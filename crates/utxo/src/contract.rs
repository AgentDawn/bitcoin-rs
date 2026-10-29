//! The chainstate-facing apply/commit/disconnect contract.
//!
//! Chainstate hands this crate one connected block at a time and gets back the
//! mutation payload, its undo record, and the value totals consensus checks
//! need; a disconnect loads the same block's undo record and rolls it back.
//! Everything the contract reads — resolved prevouts, the live set at BIP30
//! exception heights — enters through the two read traits here, so record,
//! shard, event, and codec machinery never leaves the crate.

use std::borrow::Borrow;

use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, TxOut, Txid};
use bitcoin_rs_storage::{DisconnectPhase, StorageError, UndoStore};
use hashbrown::HashSet;

use crate::set::{UtxoCoin, UtxoError, UtxoSet};
use crate::stats::{CoinStatsListener, CoinStatsRewindError};
use crate::undo_codec;

pub use crate::undo_codec::{
    UndoCodecError, decode as decode_undo_record, record_size_limit as undo_record_size_limit,
};

/// One UTXO output to add, owning a `TxOut` or borrowing it from a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoAdd<T = TxOut> {
    pub outpoint: OutPoint,
    pub txout: T,
    pub coinbase: bool,
    pub height: u32,
}

impl<T> UtxoAdd<T> {
    /// Constructs an add operation.
    #[must_use]
    pub const fn new(outpoint: OutPoint, txout: T, coinbase: bool, height: u32) -> Self {
        Self {
            outpoint,
            txout,
            coinbase,
            height,
        }
    }
}

impl<T: Borrow<TxOut>> UtxoAdd<T> {
    pub(crate) fn payload(&self) -> crate::set::BuildPayload<'_> {
        crate::set::BuildPayload {
            outpoint: &self.outpoint,
            vout: self.outpoint.vout,
            txout: self.txout.borrow(),
            coinbase: self.coinbase,
            height: self.height,
        }
    }
}

/// UTXO mutations with owned or borrowed output payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockChanges<T = TxOut> {
    adds: Vec<UtxoAdd<T>>,
    removes: Vec<OutPoint>,
}

impl<T> Default for BlockChanges<T> {
    fn default() -> Self {
        Self::with_capacity(0, 0)
    }
}

impl<T> BlockChanges<T> {
    /// Creates an empty change set with storage reserved for known operation counts.
    #[must_use]
    pub fn with_capacity(adds: usize, removes: usize) -> Self {
        Self {
            adds: Vec::with_capacity(adds),
            removes: Vec::with_capacity(removes),
        }
    }

    /// Appends an output creation.
    pub fn add(&mut self, add: UtxoAdd<T>) {
        self.adds.push(add);
    }

    /// Appends an output spend.
    pub fn remove(&mut self, outpoint: OutPoint) {
        self.removes.push(outpoint);
    }

    #[must_use]
    pub const fn add_count(&self) -> usize {
        self.adds.len()
    }

    #[must_use]
    pub const fn remove_count(&self) -> usize {
        self.removes.len()
    }

    /// Returns output creations in commit order.
    #[must_use]
    pub fn adds(&self) -> &[UtxoAdd<T>] {
        &self.adds
    }

    /// Iterates the spent outpoints in commit order (one per non-netted spend).
    #[must_use]
    pub fn spent_outpoints(&self) -> &[OutPoint] {
        &self.removes
    }
}

/// Inverse mutations needed to disconnect one block.
///
/// No public constructor: batches come from [`build_block_changes`] or the
/// undo decoder ([`load_block_undo`]), so a rollback can never be asked to
/// replay a batch the contract did not produce.
#[derive(Debug, PartialEq, Eq)]
pub struct UndoBatch {
    pub(crate) restores: Vec<UtxoAdd>,
    pub(crate) removes: Vec<OutPoint>,
}

impl UndoBatch {
    /// A batch with no inverse mutations, for the genesis skip and codec tests.
    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self {
            restores: Vec::new(),
            removes: Vec::new(),
        }
    }

    /// Outputs this batch restores, i.e. those the disconnected block spent.
    #[must_use]
    pub fn restores(&self) -> &[UtxoAdd] {
        &self.restores
    }

    /// Outputs this batch removes, i.e. those the disconnected block created.
    #[must_use]
    pub fn removes(&self) -> &[OutPoint] {
        &self.removes
    }

    /// Restores an output the disconnected block spent into this `UndoBatch`.
    pub(crate) fn restore(&mut self, add: UtxoAdd) {
        self.restores.push(add);
    }

    /// Removes an output the disconnected block created from this `UndoBatch`.
    pub(crate) fn remove(&mut self, outpoint: OutPoint) {
        self.removes.push(outpoint);
    }

    /// Rebuilds a batch from its decoded parts.
    #[must_use]
    pub(crate) const fn from_parts(restores: Vec<UtxoAdd>, removes: Vec<OutPoint>) -> Self {
        Self { restores, removes }
    }
}

/// The raw encoded undo record one block left behind.
///
/// Produced alongside its [`UndoBatch`] by [`persist_block_undo`]. It survives
/// block-level persistence so the same bytes can be stored in a durable head
/// batch instead of re-encoding them.
pub struct UndoRecord(Vec<u8>);

impl std::fmt::Debug for UndoRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UndoRecord").field(&self.0.len()).finish()
    }
}

impl UndoRecord {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the encoded record bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The outcome of rolling one block back out of the UTXO set.
#[derive(Debug)]
pub struct DisconnectReceipt {
    /// Parent transactions of the outputs restored into the live set.
    pub restored_parents: Vec<Txid>,
}

/// Lookup for the full resolved coin of a spent output, including creation
/// metadata.
///
/// Implemented by chainstate's resolved-prevout view, which resolves a
/// block's external prevouts from the committed set (or a window overlay).
pub trait SpentOutputLookup {
    /// Full resolved coin for a spent outpoint, or `None` if it is not live.
    fn entry(&self, outpoint: &OutPoint) -> Option<&UtxoCoin>;
}

/// Where a block's prevouts are read from: the committed set, or a window
/// overlay over blocks prepared but not yet committed.
pub trait OutputSource {
    /// The live coin an outpoint refers to, or `None` if unspendable here.
    fn get_entry(&self, outpoint: &OutPoint) -> Option<UtxoCoin>;
}

impl OutputSource for UtxoSet {
    fn get_entry(&self, outpoint: &OutPoint) -> Option<UtxoCoin> {
        Self::get_entry(self, outpoint)
    }
}

/// What a block pays its coinbase and what it earned in fees.
///
/// Gathered by [`build_block_changes`] because that walk already visits exactly
/// the right two sets. Outputs created and spent inside the same block are
/// skipped there, and they cancel in the fee sum — a same-block output is one
/// transaction's output and another's input — so leaving both out is exact,
/// not an approximation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockValueTotals {
    /// Total value the coinbase outputs claim.
    pub coinbase_out: u64,
    /// Input value of the block's non-coinbase transactions, same-block
    /// spends excluded.
    pub spent_in: u64,
    /// Output value of the block's non-coinbase transactions, outputs spent
    /// in the same block excluded.
    pub created_out: u64,
}

impl BlockValueTotals {
    /// Fees the block earned, or `None` if the totals are inconsistent.
    #[must_use]
    pub const fn fees(self) -> Option<u64> {
        self.spent_in.checked_sub(self.created_out)
    }
}

/// Errors produced while building UTXO connect changes for one block.
#[derive(Debug, thiserror::Error)]
pub enum BlockChangeError {
    /// Summing a block's input or output values left the satoshi range.
    #[error("block value total overflows the satoshi range")]
    BlockValueOverflow,
    /// A transaction carries more outputs than a `u32` vout can index.
    #[error("output count of transaction {txid} exceeds the vout index range")]
    VoutOverflow {
        /// Transaction id whose output count overflowed.
        txid: Txid,
    },
    /// The supplied txid slice does not cover every transaction in the block.
    #[error("block has {transactions} transactions but {txids} txids were supplied")]
    TxidCountMismatch {
        /// Transactions in the block.
        transactions: usize,
        /// Txids supplied for them.
        txids: usize,
    },
    /// A spent output had no resolved prevout, so the undo record would be
    /// unable to restore it.
    #[error("undo record cannot restore spent output {txid}:{vout}")]
    UndoPrevoutMissing {
        /// Transaction id of the unresolvable spend.
        txid: Txid,
        /// Output index of the unresolvable spend.
        vout: u32,
    },
}

/// Why a stored undo record could not be turned back into an [`UndoBatch`].
#[derive(Debug, thiserror::Error)]
#[expect(missing_docs)]
pub enum UndoLoadError {
    #[error("undo record read: {0}")]
    Read(#[source] StorageError),
    #[error("no undo record for block {hash} at height {height}")]
    Missing { hash: Hash256, height: u32 },
    #[error("undo record for block {hash} is unreadable: {source}")]
    Unreadable {
        hash: Hash256,
        #[source]
        source: UndoCodecError,
    },
}

/// Pruning availability remains owned by storage; RPC receives the same typed reasons.
pub use bitcoin_rs_storage::{BoundedReadError, pruning::HistoryUnavailable};

/// Read-only access to certified, retained block inputs. Implemented by chainstate.
pub trait BlockUndoSource: Send + Sync {
    /// Reads one complete block/input view without exposing storage mutation.
    fn block_spends(
        &self,
        hash: Hash256,
        expected_applied_hash: Hash256,
    ) -> Result<BlockSpends, BlockSpendsError>;
}

/// A verified block body and its input-ordered spent coins.
#[derive(Debug)]
pub struct BlockSpends {
    /// Body whose hash and commitments were checked by the read owner.
    pub block: Block,
    /// Complete input rows (coinbase empty), or the typed reason this body
    /// has no certified retained undo. Partial rows are never returned.
    pub spent: Result<Vec<Vec<UtxoCoin>>, HistoryUnavailable>,
}

/// A retained-history query never turns an unavailable or corrupt record into coins.
#[derive(Debug, thiserror::Error)]
pub enum BlockSpendsError {
    /// The header authority does not know this hash.
    #[error("Block not found")]
    UnknownBlock,
    /// The storage owner refused history acquisition or the row is absent.
    #[error(transparent)]
    History(#[from] HistoryUnavailable),
    /// Expected undo is missing or malformed; preserve the owning typed failure.
    #[error(transparent)]
    Undo(#[from] UndoLoadError),
    /// Reading the durable receipt failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// A bounded block-body read failed or refused the copy.
    #[error("block body read: {0}")]
    BodyRead(#[source] bitcoin_rs_storage::BoundedReadError),
    /// A bounded undo read failed or refused the record before copying it.
    #[error(transparent)]
    BoundedRead(#[from] bitcoin_rs_storage::BoundedReadError),
    /// A body, input, or undo metadata fact is inconsistent.
    #[error("inconsistent retained block/undo: {0}")]
    Corrupt(&'static str),
    /// A receipt or retention lease changed while bytes were being read.
    #[error("chain history changed during the query; retry")]
    Retry,
    /// Authoritative state is closed for recovery.
    #[error("chain history is unavailable while the node is closed for recovery")]
    Closed,
    /// Materializing this request exceeds the query's documented budget.
    #[error("block undo query exceeds its read budget")]
    ResourceLimit,
}

/// Decodes the existing undo format with allocation counts bounded by `block`.
///
/// The body's inputs bound external restores; its outputs bound BIP30
/// overwritten restores and removals. Persistence/disconnect decoding is unchanged.
pub fn decode_undo_record_for_block(
    bytes: &[u8],
    block: &Block,
) -> Result<UndoBatch, UndoCodecError> {
    let inputs = block
        .txs
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .map(|tx| tx.inputs.len())
        .sum::<usize>();
    let outputs = block.txs.iter().map(|tx| tx.outputs.len()).sum::<usize>();
    undo_codec::decode_bounded(
        bytes,
        block.block_hash().into(),
        inputs.saturating_add(outputs),
        outputs,
    )
}

/// Projects rollback facts into transaction/input order without changing their format.
///
/// Same-block outputs are absent from net undo and come from earlier transactions
/// in the authenticated body. Extra BIP30 overwritten-output restorations are
/// rollback facts, not transaction inputs, and are deliberately not emitted.
pub fn block_spent_outputs(
    block: &Block,
    height: u32,
    undo: &UndoBatch,
) -> Result<Vec<Vec<UtxoCoin>>, BlockSpendsError> {
    let restores: hashbrown::HashMap<_, _> = undo
        .restores()
        .iter()
        .map(|coin| (coin.outpoint, coin))
        .collect();
    let mut earlier: hashbrown::HashMap<Txid, (&Tx, bool)> = hashbrown::HashMap::new();
    let mut spent = Vec::with_capacity(block.txs.len());
    for tx in &block.txs {
        let coinbase = tx.is_coinbase();
        let mut inputs = Vec::with_capacity(if coinbase { 0 } else { tx.inputs.len() });
        if !coinbase {
            for input in &tx.inputs {
                let outpoint = input.previous_output;
                let txid = outpoint.txid;
                let vout = outpoint.vout;
                let coin = if let Some((parent, generated)) = earlier.get(&txid) {
                    let txout = usize::try_from(vout)
                        .ok()
                        .and_then(|vout| parent.outputs.get(vout))
                        .ok_or(BlockSpendsError::Corrupt(
                            "same-block prevout index is absent",
                        ))?;
                    UtxoCoin {
                        outpoint,
                        txout: txout.clone(),
                        coinbase: *generated,
                        height,
                    }
                } else {
                    let coin = restores
                        .get(&outpoint)
                        .ok_or(BlockSpendsError::Corrupt("input is absent from block undo"))?;
                    if coin.height >= height {
                        return Err(BlockSpendsError::Corrupt(
                            "external prevout height is not historical",
                        ));
                    }
                    UtxoCoin {
                        outpoint,
                        txout: coin.txout.clone(),
                        coinbase: coin.coinbase,
                        height: coin.height,
                    }
                };
                inputs.push(coin);
            }
        }
        spent.push(inputs);
        earlier.insert(tx.txid(), (tx, coinbase));
    }
    Ok(spent)
}

/// Only `Refused` leaves state untouched; the rest fire after the marker is
/// armed and may leave state torn for recovery to reconcile.
#[derive(Debug, thiserror::Error)]
#[expect(missing_docs)]
pub enum RollbackError {
    #[error("rollback refused: {0}")]
    Refused(#[source] StorageError),
    #[error("utxo undo: {0}")]
    Utxo(#[source] UtxoError),
    #[error("coinstats rewind: {0}")]
    CoinStats(#[source] CoinStatsRewindError),
    #[error("disconnect marker: {0}")]
    Marker(#[source] StorageError),
}

/// Applies one connected block's [`BlockChanges`] to the set.
pub fn commit_block_changes<T: Borrow<TxOut>>(
    set: &UtxoSet,
    changes: &BlockChanges<T>,
    block_hash: &Hash256,
) -> Result<(), UtxoError> {
    set.commit_block(changes, block_hash)
}

/// Builds the UTXO mutation, undo batch, and value totals for one connected
/// block.
///
/// - `block`: the block being connected.
/// - `height`: the height at which it connects.
/// - `txids`: precomputed txids for the block's transactions, in order.
/// - `same_block_spent`: outpoints spent within the same block (netted out),
///   or `None` when no same-block detection ran.
/// - `add_capacity` / `remove_capacity`: pre-reserved capacities for the
///   change sets.
/// - `resolved`: lookup for the full coins of outputs the block spends.
/// - `overwritten`: the committed set, passed only at BIP30 exception heights
///   where a coinbase reuses a still-live txid.
/// - `max_script_size`: consensus limit; outputs whose script exceeds this are
///   not added to the UTXO set.
///
/// # Errors
///
/// [`BlockChangeError::TxidCountMismatch`] when `txids` does not cover every
/// transaction, refused before iterating so no trailing transaction can be
/// silently dropped; [`BlockChangeError::VoutOverflow`] when a transaction
/// carries more outputs than a `u32` vout can index;
/// [`BlockChangeError::BlockValueOverflow`] when value totals overflow; and
/// [`BlockChangeError::UndoPrevoutMissing`] when a spend has no resolved
/// prevout. Genesis returns empty mutations.
#[expect(clippy::too_many_arguments)]
pub fn build_block_changes<'a>(
    block: &'a Block,
    height: u32,
    txids: &[Txid],
    same_block_spent: Option<&HashSet<OutPoint>>,
    add_capacity: usize,
    remove_capacity: usize,
    resolved: &impl SpentOutputLookup,
    overwritten: Option<&UtxoSet>,
    max_script_size: usize,
) -> Result<(BlockChanges<&'a TxOut>, UndoBatch, BlockValueTotals), BlockChangeError> {
    // Zipping would silently drop whichever sequence is longer, leaving
    // trailing transactions out of the changes, undo, and value totals while
    // reporting success - the window overlay refuses the same mismatch. This
    // runs before the genesis early return so a mismatched slice is refused at
    // every height, matching the documented contract.
    if block.txs.len() != txids.len() {
        return Err(BlockChangeError::TxidCountMismatch {
            transactions: block.txs.len(),
            txids: txids.len(),
        });
    }
    // Bitcoin Core indexes genesis but does not connect its transactions into
    // CoinsView; its coinbase is unspendable and absent from UTXO/MuHash state.
    if height == 0 {
        return Ok((
            BlockChanges::default(),
            UndoBatch::empty(),
            BlockValueTotals::default(),
        ));
    }

    let net_same_block_spends = same_block_spent.is_some_and(|s| !s.is_empty());
    let mut changes = BlockChanges::with_capacity(add_capacity, remove_capacity);
    let mut undo = UndoBatch::empty();
    let mut totals = BlockValueTotals::default();
    for (tx, txid) in block.txs.iter().zip(txids) {
        let txid = *txid;
        let coinbase = tx.is_coinbase();
        for (vout_idx, txout) in tx.outputs.iter().enumerate() {
            let value = txout.value.to_sat();
            let vout =
                u32::try_from(vout_idx).map_err(|_| BlockChangeError::VoutOverflow { txid })?;
            let outpoint = OutPoint::new(txid, vout);
            let same_block =
                net_same_block_spends && same_block_spent.is_some_and(|s| s.contains(&outpoint));
            if coinbase {
                totals.coinbase_out = totals
                    .coinbase_out
                    .checked_add(value)
                    .ok_or(BlockChangeError::BlockValueOverflow)?;
            } else if !same_block {
                totals.created_out = totals
                    .created_out
                    .checked_add(value)
                    .ok_or(BlockChangeError::BlockValueOverflow)?;
            }
            if same_block
                || txout.script_pubkey.first() == Some(&0x6a)
                || txout.script_pubkey.len() > max_script_size
            {
                continue;
            }
            let replaced = overwritten.and_then(|set| set.get_entry(&outpoint));
            changes.add(UtxoAdd::new(outpoint, txout, coinbase, height));
            match replaced {
                Some(previous) => undo.restore(UtxoAdd::new(
                    outpoint,
                    previous.txout,
                    previous.coinbase,
                    previous.height,
                )),
                // Disconnecting the block deletes what it created.
                None => undo.remove(outpoint),
            }
        }

        if !coinbase {
            for tx_input in &tx.inputs {
                let previous_output = tx_input.previous_output;
                if net_same_block_spends
                    && same_block_spent.is_some_and(|s| s.contains(&previous_output))
                {
                    continue;
                }
                changes.remove(previous_output);
                // ...and restores what it spent. A spend with no resolved
                // prevout would make the record unable to restore that output,
                // so refuse rather than persist an undo that silently loses it.
                let spent = resolved.entry(&tx_input.previous_output).ok_or(
                    BlockChangeError::UndoPrevoutMissing {
                        txid: previous_output.txid,
                        vout: previous_output.vout,
                    },
                )?;
                totals.spent_in = totals
                    .spent_in
                    .checked_add(spent.txout.value.to_sat())
                    .ok_or(BlockChangeError::BlockValueOverflow)?;
                undo.restore(UtxoAdd::new(
                    previous_output,
                    spent.txout.clone(),
                    spent.coinbase,
                    spent.height,
                ));
            }
        }
    }
    Ok((changes, undo, totals))
}

/// Encodes and persists a block's undo record, returning the raw record so the
/// caller can put the same row into its durable head batch.
pub fn persist_block_undo(
    store: &dyn UndoStore,
    height: u32,
    hash: Hash256,
    undo: &UndoBatch,
) -> Result<UndoRecord, StorageError> {
    let record = undo_codec::encode(undo, hash);
    store.persist_undo(height, hash, &record)?;
    Ok(UndoRecord::new(record))
}

/// Loads and decodes the record [`persist_block_undo`] wrote for a block.
///
/// # Errors
///
/// Read failure, absent record, or a record that does not decode as this
/// block's.
pub fn load_block_undo(
    store: &dyn UndoStore,
    height: u32,
    hash: Hash256,
) -> Result<UndoBatch, UndoLoadError> {
    let record = store
        .load_undo(height, hash)
        .map_err(UndoLoadError::Read)?
        .ok_or(UndoLoadError::Missing { hash, height })?;
    undo_codec::decode(&record, hash).map_err(|source| UndoLoadError::Unreadable { hash, source })
}

/// Rolls one block out of the UTXO set under a durable disconnect marker.
///
/// The marker is read before arming so a refusal cannot overwrite the
/// previous disconnect's marker: an `InFlight` marker is a torn rollback that
/// must not be armed over, while a `RolledBack` marker is owed checkpoint
/// debt that sequential disconnects carry into the next arm. On success the
/// marker stays `RolledBack` until the caller durably publishes the
/// rolled-back state. A marker that survives to the next startup no longer
/// refuses it: startup recovers automatically from the durable certified
/// head before anything serves (`docs/contracts/recovery.md`). Per-coin
/// coinstats follow the set's undo through the listener; only height and
/// transaction count are rewound here.
///
/// # Errors
///
/// [`RollbackError::Refused`] before the marker is armed; every other variant
/// after.
pub fn rollback_block(
    store: &dyn UndoStore,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    hash: Hash256,
    height: u32,
    parent_height: u32,
    tx_count_delta: u64,
    undo: &UndoBatch,
) -> Result<DisconnectReceipt, RollbackError> {
    if store
        .load_disconnect_marker()
        .map_err(RollbackError::Refused)?
        .is_some_and(|marker| marker.phase == DisconnectPhase::InFlight)
    {
        return Err(RollbackError::Refused(StorageError::InvalidOperation(
            "a disconnect is already in flight",
        )));
    }
    store
        .arm_disconnect(height, hash)
        .map_err(RollbackError::Refused)?;
    rollback_block_recovery(
        utxo,
        coin_stats,
        height,
        parent_height,
        tx_count_delta,
        undo,
    )?;
    store
        .complete_disconnect(height, hash)
        .map_err(RollbackError::Marker)?;
    Ok(DisconnectReceipt {
        restored_parents: undo
            .restores()
            .iter()
            .map(|restored| restored.outpoint.txid)
            .collect(),
    })
}

/// Recovery's rollback step: the coin rewind without the marker lifecycle.
/// Also used by an ordinary disconnect after its marker is armed.
///
/// The marker recovery carries is the evidence being reconciled — re-arming
/// would overwrite its identity and completing would fake a finished
/// rollback — so it stays `InFlight` until the checkpoint that publishes
/// the repaired state retires it. That is also what makes a crash
/// mid-rewind restartable: the same marker re-enters recovery.
///
/// # Errors
///
/// `RollbackError::Utxo` or `RollbackError::CoinStats`. Never `Refused`:
/// the arming guard does not apply to a marker recovery already owns.
pub fn rollback_block_recovery(
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    height: u32,
    parent_height: u32,
    tx_count_delta: u64,
    undo: &UndoBatch,
) -> Result<(), RollbackError> {
    // Refuse mismatched stats before the UTXO mutation: a recovery that
    // fails closed after undoing the block would retry against a partially
    // rewound set.
    coin_stats
        .check_rewind(height, tx_count_delta)
        .map_err(RollbackError::CoinStats)?;
    utxo.undo_block(undo).map_err(RollbackError::Utxo)?;
    coin_stats
        .rewind_block(height, parent_height, tx_count_delta)
        .map_err(RollbackError::CoinStats)
}

#[cfg(test)]
mod tests;
