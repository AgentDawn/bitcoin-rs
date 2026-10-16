//! Read-side store access, typed prefix-row decoding, and exact transaction/script resolution.

use super::{
    capability::IndexCapability, capability::IndexWatermark, capability::IndexWatermarks,
    capability::SCRIPT_LIVE_WATERMARK_KEY, error::IndexError,
};
use crate::{types::ScriptHashRow, types::SpendingPrefixRow, types::TxidRow};
use bitcoin_rs_primitives::{Block, OutPoint, Tx, Txid, deserialize};
use bitcoin_rs_storage::{ColumnFamily, KvStore};

/// One confirmed transaction discovered by the generic script-history resolver.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScriptHistoryEntry {
    /// Transaction identifier.
    pub txid: Txid,
    /// Confirming block height.
    pub height: u32,
}

impl ScriptHistoryEntry {
    /// Creates a confirmed script-history entry.
    pub const fn confirmed(txid: Txid, height: u32) -> Self {
        Self { txid, height }
    }
}

/// Electrs-shaped block indexer backed by a workspace [`KvStore`].
///
/// Reads and format/watermark queries live here. Durable row mutation is
/// owned exclusively by [`super::write::IndexWriter`].
pub struct Indexer<S: KvStore> {
    pub(super) store: std::sync::Arc<S>,
}

impl<S: KvStore> Indexer<S> {
    /// Creates an indexer over `store`.
    pub fn new(store: std::sync::Arc<S>) -> Self {
        Self { store }
    }

    /// Loads the exact durable `TxIndex` watermark, or `None` for an empty v2 index.
    pub(super) fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        self.capability_watermark(IndexCapability::TxLookup)
    }

    /// Loads one capability's exact durable watermark.
    pub fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        let key = capability.watermark_key();
        self.store
            .get(ColumnFamily::UtxoMeta, key)?
            .as_deref()
            .map(IndexWatermark::from_bytes)
            .transpose()
    }

    /// Loads all independently durable capability watermarks.
    pub fn watermarks(&self) -> Result<IndexWatermarks, IndexError> {
        Ok(IndexWatermarks {
            tx_lookup: self.capability_watermark(IndexCapability::TxLookup)?,
            script_history: self.capability_watermark(IndexCapability::ScriptHistory)?,
            script_live: self.capability_watermark(IndexCapability::ScriptLive)?,
            compact_filters: self.capability_watermark(IndexCapability::CompactFilters)?,
        })
    }

    /// Iterates confirmed funding rows for `scripthash`.
    ///
    /// Returns every `HashPrefixRow` in `ColumnFamily::Funding` whose 8-byte
    /// prefix matches, in store iteration order. The 4-byte height suffix is
    /// big-endian (format 5), so that order is chronological within a prefix.
    /// The prefix is lossy: callers MUST resolve heights back to full
    /// transactions via block storage to confirm scripthash identity.
    pub fn iter_funding_rows(
        &self,
        scripthash: crate::ScriptHash,
    ) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = ScriptHashRow::scan_prefix(scripthash);
        let iter = self.store.iter_prefix(ColumnFamily::Funding, &prefix)?;
        collect_prefix_rows(iter)
    }

    /// Iterates live-output rows for `scripthash`.
    ///
    /// Returns the outpoint locators currently filed under the scripthash's
    /// 8-byte scan prefix, decoded from [`ColumnFamily::ScriptLive`]. The
    /// prefix is lossy exactly like `Funding`'s: two scripts may share it, so
    /// callers MUST resolve each outpoint against authoritative UTXO state and
    /// exact-check the resolved coin's full `script_pubkey` before serving it.
    /// This scan is read-only by contract -- live deletion is always a
    /// whole-key point delete, never a prefix-range operation.
    pub fn iter_live_outpoints(
        &self,
        scripthash: crate::ScriptHash,
    ) -> Result<Vec<OutPoint>, IndexError> {
        let snapshot = self.store.snapshot()?;
        if snapshot
            .get(ColumnFamily::UtxoMeta, SCRIPT_LIVE_WATERMARK_KEY)?
            .is_none()
        {
            return Ok(Vec::new());
        }
        let prefix = ScriptHashRow::scan_prefix(scripthash);
        let iter = snapshot.iter_prefix(ColumnFamily::ScriptLive, &prefix)?;
        let mut outpoints = Vec::new();
        for row in iter {
            let (key, value) = row?;
            if !value.is_empty() {
                return Err(IndexError::InvalidLiveRowValue { len: value.len() });
            }
            let row = crate::types::ScriptLiveRow::from_db_row(&key)
                .ok_or(IndexError::InvalidPrefixRowLength { len: key.len() })?;
            outpoints.push(row.outpoint());
        }
        Ok(outpoints)
    }

    /// Iterates confirmed funding rows for `scripthash` with their row values.
    ///
    /// The value carries the transaction byte positions that let a resolver read
    /// only the matching transactions; see [`crate::types::TxPositionValue`].
    fn iter_funding_rows_with_values(
        &self,
        scripthash: crate::ScriptHash,
    ) -> Result<Vec<(crate::HashPrefixRow, Vec<u8>)>, IndexError> {
        let prefix = ScriptHashRow::scan_prefix(scripthash);
        let iter = self.store.iter_prefix(ColumnFamily::Funding, &prefix)?;
        collect_prefix_rows_with_values(iter)
    }

    /// Iterates confirmed transaction-id rows for `txid` with their row values.
    fn iter_txid_rows_with_values(
        &self,
        txid: &Txid,
    ) -> Result<Vec<(crate::HashPrefixRow, Vec<u8>)>, IndexError> {
        let prefix = TxidRow::scan_prefix(txid);
        let iter = self.store.iter_prefix(ColumnFamily::TxConfirmed, &prefix)?;
        collect_prefix_rows_with_values(iter)
    }

    /// Iterates confirmed spending rows that spent `outpoint`.
    ///
    /// Returns every `HashPrefixRow` whose 8-byte prefix matches the outpoint's
    /// spending scan prefix, decoded from `ColumnFamily::Spending`. The 8-byte
    /// prefix is lossy as above.
    ///
    /// **Height ordering:** same as [`Self::iter_funding_rows`]: the 4-byte
    /// height suffix is big-endian (format 5), so prefix-range scans arrive
    /// in chronological order.
    pub fn iter_spending_rows(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = SpendingPrefixRow::scan_prefix(outpoint);
        let iter = self.store.iter_prefix(ColumnFamily::Spending, &prefix)?;
        collect_prefix_rows(iter)
    }

    /// Resolves confirmed script-history entries for `scripthash` via `source`.
    ///
    /// Walks every funding row for the scripthash, fetches each block, and
    /// yields a `ScriptHistoryEntry::confirmed` per transaction with an output
    /// matching the full 32-byte scripthash, so the lossy 8-byte prefix is
    /// exact-resolved here. Heights the source cannot resolve are skipped.
    /// Entries are sorted by ascending height as a contract guarantee.
    pub fn resolve_script_history<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<ScriptHistoryEntry>, IndexError> {
        let rows = self.iter_funding_rows_with_values(scripthash)?;
        let mut entries = Vec::new();
        for (row, value) in &rows {
            let height = row.height();
            match positioned_history(scripthash, height, value, source) {
                Some(found) => entries.extend(found),
                None => scan_height_history(scripthash, height, source, &mut entries),
            }
        }
        entries.sort_by_key(|entry| entry.height);
        Ok(entries)
    }

    /// Resolves confirmed unspent-output candidates for `scripthash` via
    /// `source`, each carrying its funding height.
    ///
    /// Emits `(txid, vout, value_sats, funding_height)` for every output whose
    /// script hashes to the full 32-byte `scripthash`, sorted by ascending
    /// funding height. Spending checks are not performed here: callers compose
    /// with `iter_spending_rows` to filter out spent outputs.
    pub fn resolve_unspent_outputs_with_height<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<(Txid, u32, u64, u32)>, IndexError> {
        let rows = self.iter_funding_rows_with_values(scripthash)?;
        let mut outputs = Vec::new();
        for (row, value) in &rows {
            let height = row.height();
            match positioned_unspent_outputs(scripthash, height, value, source) {
                Some(found) => outputs.extend(found),
                None => scan_height_unspent_outputs(scripthash, height, source, &mut outputs),
            }
        }
        outputs.sort_by_key(|&(_, _, _, height)| height);
        Ok(outputs)
    }

    /// Resolves a transaction by txid via `source`.
    ///
    /// Scans `iter_txid_rows_with_values(txid)` for candidate `(prefix, height)` entries.
    /// For each height, fetches the block and looks for the transaction whose
    /// full computed txid matches `txid` exactly. Returns the first match, or
    /// `None` if no candidates resolve to the requested txid.
    ///
    /// The 8-byte prefix is lossy; this method exact-resolves it by comparing
    /// the full 32-byte txid before returning.
    pub fn resolve_transaction<B: BlockSource + ?Sized>(
        &self,
        txid: Txid,
        source: &B,
    ) -> Result<Option<Tx>, IndexError> {
        let rows = self.iter_txid_rows_with_values(&txid)?;
        for (row, value) in &rows {
            let height = row.height();
            if let Some(positions) = crate::types::TxPositionValue::decode(value) {
                let found = positions
                    .iter()
                    .filter_map(|position| transaction_at(height, *position, source))
                    .find(|tx| tx.txid() == txid);
                if let Some(tx) = found {
                    return Ok(Some(tx));
                }
            }
            // The positions did not produce the transaction, which is either an
            // 8-byte txid-prefix collision or a stale row. Both are rare, and
            // both are answered correctly by scanning; "not found" is never
            // reported on the strength of positions alone.
            if let Some(block) = source.block_at_height(height) {
                for tx in &block.txs {
                    if tx.txid() == txid {
                        return Ok(Some(tx.clone()));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Resolves the satoshi value of the transaction output at `outpoint` via
    /// `source`. Returns `Ok(None)` when the transaction is not indexed or the
    /// `vout` is out of range.
    ///
    /// Composes `resolve_transaction(outpoint.txid, source)` and reads the
    /// `output[vout].value.to_sat()`. Building block for real fee derivation
    /// in transaction-broadcast and prevout-value lookups.
    pub fn resolve_outpoint_value<B: BlockSource + ?Sized>(
        &self,
        outpoint: OutPoint,
        source: &B,
    ) -> Result<Option<u64>, IndexError> {
        let Some(tx) = self.resolve_transaction(outpoint.txid, source)? else {
            return Ok(None);
        };
        let Ok(vout_idx) = usize::try_from(outpoint.vout) else {
            return Ok(None);
        };
        Ok(tx.outputs.get(vout_idx).map(|output| output.value.to_sat()))
    }
}

fn collect_prefix_rows_with_values(
    iter: bitcoin_rs_storage::KvIter<'_>,
) -> Result<Vec<(crate::HashPrefixRow, Vec<u8>)>, IndexError> {
    let mut rows = Vec::new();
    for entry in iter {
        let (key, value) = entry?;
        if key.len() == crate::HASH_PREFIX_ROW_SIZE {
            rows.push((
                zerocopy::FromBytes::read_from_bytes(&key[..])
                    .map_err(|_| IndexError::InvalidHeaderLength { len: key.len() })?,
                value,
            ));
        }
    }
    Ok(rows)
}

fn collect_prefix_rows(
    iter: bitcoin_rs_storage::KvIter<'_>,
) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
    let mut rows = Vec::new();
    for entry in iter {
        let (key, _value) = entry?;
        if key.len() == crate::HASH_PREFIX_ROW_SIZE {
            rows.push(
                zerocopy::FromBytes::read_from_bytes(&key[..])
                    .map_err(|_| IndexError::InvalidHeaderLength { len: key.len() })?,
            );
        }
    }
    Ok(rows)
}

/// Reads and decodes the single transaction a position names.
///
/// Returns `None` when the source cannot serve the range, when the range is out
/// of bounds, or when the bytes are not exactly one transaction. `deserialize`
/// rejects trailing bytes, so a range covering more than one transaction fails
/// here rather than silently decoding the first.
fn transaction_at<B: BlockSource + ?Sized>(
    height: u32,
    position: crate::types::TxPosition,
    source: &B,
) -> Option<Tx> {
    let bytes = source.block_bytes_at_height(height, position.offset(), position.byte_len())?;
    deserialize::<Tx>(&bytes).ok()
}

/// Resolves one funding row's history entries from its positions.
///
/// Returns `None` — meaning "scan this height instead" — if **any** position
/// fails to resolve to a transaction funding `scripthash`. Skipping a failed
/// position and keeping the rest is what would turn a partial result into a
/// silently complete-looking one; see [`crate::types::TxPositionValue`].
fn positioned_history<B: BlockSource + ?Sized>(
    scripthash: crate::ScriptHash,
    height: u32,
    value: &[u8],
    source: &B,
) -> Option<Vec<ScriptHistoryEntry>> {
    let positions = crate::types::TxPositionValue::decode(value)?;
    let mut entries = Vec::with_capacity(positions.len());
    for position in positions {
        let tx = transaction_at(height, *position, source)?;
        if !funds_scripthash(&tx, scripthash) {
            return None;
        }
        entries.push(ScriptHistoryEntry::confirmed(tx.txid(), height));
    }
    Some(entries)
}

/// Appends the history entries a full scan of `height` produces.
fn scan_height_history<B: BlockSource + ?Sized>(
    scripthash: crate::ScriptHash,
    height: u32,
    source: &B,
    entries: &mut Vec<ScriptHistoryEntry>,
) {
    let Some(block) = source.block_at_height(height) else {
        return;
    };
    for tx in &block.txs {
        if funds_scripthash(tx, scripthash) {
            entries.push(ScriptHistoryEntry::confirmed(tx.txid(), height));
        }
    }
}

/// Resolves one funding row's unspent-output candidates from its positions.
///
/// Same all-or-scan rule as [`positioned_history`].
fn positioned_unspent_outputs<B: BlockSource + ?Sized>(
    scripthash: crate::ScriptHash,
    height: u32,
    value: &[u8],
    source: &B,
) -> Option<Vec<(Txid, u32, u64, u32)>> {
    let positions = crate::types::TxPositionValue::decode(value)?;
    let mut outputs = Vec::new();
    for position in positions {
        let tx = transaction_at(height, *position, source)?;
        let before = outputs.len();
        append_matching_outputs(&tx, scripthash, height, &mut outputs);
        if outputs.len() == before {
            return None;
        }
    }
    Some(outputs)
}

/// Appends the unspent-output candidates a full scan of `height` produces.
fn scan_height_unspent_outputs<B: BlockSource + ?Sized>(
    scripthash: crate::ScriptHash,
    height: u32,
    source: &B,
    outputs: &mut Vec<(Txid, u32, u64, u32)>,
) {
    let Some(block) = source.block_at_height(height) else {
        return;
    };
    for tx in &block.txs {
        append_matching_outputs(tx, scripthash, height, outputs);
    }
}

/// Appends `(txid, vout, value, height)` for every output of `tx` matching
/// `scripthash`, computing the txid only once a match is found.
fn append_matching_outputs(
    tx: &Tx,
    scripthash: crate::ScriptHash,
    height: u32,
    outputs: &mut Vec<(Txid, u32, u64, u32)>,
) {
    let mut computed_txid: Option<Txid> = None;
    for (vout_idx, output) in tx.outputs.iter().enumerate() {
        if crate::ScriptHash::from_script_bytes(&output.script_pubkey) != scripthash {
            continue;
        }
        let Ok(vout) = u32::try_from(vout_idx) else {
            continue;
        };
        let txid = *computed_txid.get_or_insert_with(|| tx.txid());
        outputs.push((txid, vout, output.value.to_sat(), height));
    }
}

fn funds_scripthash(tx: &Tx, scripthash: crate::ScriptHash) -> bool {
    tx.outputs
        .iter()
        .any(|output| crate::ScriptHash::from_script_bytes(&output.script_pubkey) == scripthash)
}

/// Provides block lookups for resolving lossy index prefixes to full identities.
///
/// The index column families store 8-byte prefixes of txids/scripthashes/outpoints.
/// To recover the full Bitcoin identities behind a `HashPrefixRow`, callers need
/// to fetch the block at the row's height and walk its transactions. `BlockSource`
/// is the trait that hides where blocks come from (in-memory store, raw-block KV
/// database, peer fetch).
pub trait BlockSource {
    /// Returns the Bitcoin block at `height` on the active chain, if known.
    fn block_at_height(&self, height: u32) -> Option<Block>;

    /// Returns `len` serialized bytes starting `offset` bytes into the active
    /// block at `height`, without materializing or decoding the whole body.
    ///
    /// This is what lets a resolver read only the transactions a row's
    /// [`crate::types::TxPosition`]s name instead of scanning the block.
    ///
    /// Defaults to `None`, meaning "this source cannot slice". A caller must
    /// then fall back to `block_at_height` — `None` never means the bytes are
    /// absent, and an out-of-range request yields `None` rather than a short
    /// read.
    fn block_bytes_at_height(&self, _height: u32, _offset: u32, _len: u32) -> Option<Vec<u8>> {
        None
    }
}
