//! BIP152 compact-block reconstruction.
//!
//! One [`Reconstruction`] lives per peer message loop: it owns the bounded
//! pending-reconstruction state for that connection and hands finished
//! blocks to the caller, which delivers them through the ordinary block
//! sink — the same validation and apply path as a `block` message, with no
//! bypass. Short IDs are hints only: any ambiguity, missing piece, or bound
//! miss degrades to a full-block `getdata` fallback on the same connection,
//! so a wrong guess costs round trips, never a wrong block; an entry whose
//! deadline passes is dropped silently — liveness then rests on the
//! connection's separate stall handling.
//!
//! BIP152 identity direction: a peer serializes the compact blocks it sends
//! us with the version we advertised in our own `sendcmpct`
//! ([`crate::peer::COMPACT_BLOCK_VERSION`], v2 = wtxid identity, witness-bearing
//! prefills). Conversely, we serve peers at the version they recorded with
//! us (`CompactBlockNegotiation::servable_version`, used by the chain
//! query). The two directions are independent; decoding incoming compact
//! blocks never reads their preference.
//!
//! State is released by completion, by the deadline, by a replacement, and
//! by dropping the owner at disconnect or session cancel — a chain change
//! cannot strand memory beyond the deadline.

use crate::inv::{native_block_hash, wire_block_hash};

use hashbrown::HashMap;
use std::time::{Duration, Instant};

use bitcoin::bip152::{BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn};
use bitcoin_rs_primitives::deserialize;
use bitcoin_rs_primitives::{Block, BlockHash, Header, Tx, Txid, Wtxid};

/// Compact-block protocol version this node advertises: the identity
/// profile peers use for the compact blocks they send us. Re-exported from
/// `peer` as the authority.
pub use crate::peer::COMPACT_BLOCK_VERSION;

/// Concurrent pending reconstructions per peer connection.
const MAX_PENDING_RECONSTRUCTIONS: usize = 4;
/// Approximate retained bytes across all pending entries before new
/// `cmpctblock` messages are refused in favor of the full-block fallback.
const MAX_PENDING_RETAINED_BYTES: usize = 8 * 1_024 * 1_024;
/// A pending entry older than this is dropped; a chain change cannot strand
/// memory longer than one deadline.
const PENDING_DEADLINE: Duration = Duration::from_mins(1);
/// Above this many missing transactions the `getblocktxn` round trip is
/// skipped: a full-block `getdata` is then the cheaper request.
const MAX_REQUESTED_MISSING: usize = 128;
/// Sanity bound on the transaction count a `cmpctblock` may declare.
const MAX_BLOCK_TX_COUNT: usize = 100_000;
/// Recently admitted hashes remembered per connection to avoid rescanning
/// the mempool for repeated compact announcements of one block. Sized to the
/// most block downloads one connection can own, so a peer cannot evict a
/// still-owned hash and replay it.
const MAX_RECENT_COMPACT_BLOCKS: usize = crate::download_window::PEER_INFLIGHT_BUDGET;

/// Transaction identities the mempool can offer a compact-block
/// reconstruction: an identity scan plus body lookup by either hash.
///
/// Implemented for the shared [`bitcoin_rs_mempool::MempoolGateway`]; the
/// p2p crate owns the protocol adapter, mempool owns admission state.
pub trait CompactBlockHints: Send + Sync {
    /// Invokes `f` for every resident transaction as `(txid, wtxid)`.
    fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid));

    /// Returns the transaction body for `txid`, if held.
    fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx>;

    /// Returns the transaction body for `wtxid`, if held.
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx>;
}

/// What the listener must do after one receive-side BIP152 step.
#[derive(Debug)]
pub enum Outcome {
    /// Reconstruction finished; deliver through the ordinary block sink.
    Complete(Block),
    /// Request the listed missing transaction indexes on the same connection.
    RequestMissing(GetBlockTxn),
    /// Reconstruction cannot complete from this peer's messages; request the
    /// full block instead.
    Fallback(BlockHash),
    /// Nothing to do (stale or already-fallen-back `blocktxn`).
    Idle,
}

/// Bounded per-peer pending-reconstruction state.
#[derive(Debug, Default)]
pub struct Reconstruction {
    pending: HashMap<BlockHash, Pending>,
    /// At most one reconstruction attempt per hash within its deadline.
    recent: Vec<(BlockHash, Instant)>,
}

/// One block being reconstructed.
#[derive(Debug)]
struct Pending {
    header: Header,
    filled: Vec<Option<Tx>>,
    /// Absolute slot indexes still missing, ascending.
    missing: Vec<u64>,
    /// Approximate retained bytes (prefill bodies + short IDs + filled bodies).
    retained_bytes: usize,
    deadline: Instant,
}

impl Reconstruction {
    /// Creates an empty reconstruction state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            recent: Vec::new(),
        }
    }

    /// Receive-side entry for `cmpctblock`.
    ///
    /// `identity_version` is the BIP152 version the peer used to serialize
    /// this message — our own advertised [`crate::peer::COMPACT_BLOCK_VERSION`], per the
    /// direction rule in the module docs. Prefills are placed, remaining
    /// short IDs are matched as hints against the mempool, and the outcome
    /// is [`Outcome::Complete`] (all filled), [`Outcome::RequestMissing`]
    /// (bounded missing list), or [`Outcome::Fallback`] (ambiguity,
    /// malformed indexes, or the bounded state is exhausted).
    pub fn receive_cmpctblock(
        &mut self,
        cmpct: &CmpctBlock,
        identity_version: u64,
        hints: &dyn CompactBlockHints,
        now: Instant,
    ) -> Outcome {
        self.prune(now);
        let compact = &cmpct.compact_block;
        let Some(header) = native_header(&compact.header) else {
            return Outcome::Fallback(native_block_hash(compact.header.block_hash()));
        };
        let hash = header.compute_hash();
        // Re-sending one in-flight or already completed block must never
        // trigger another mempool-wide hint walk (or another fallback).
        if self.recent.iter().any(|(seen, _)| *seen == hash) {
            return Outcome::Idle;
        }
        if self.recent.len() == MAX_RECENT_COMPACT_BLOCKS {
            self.recent.remove(0);
        }
        self.recent.push((hash, now));
        let total = compact.short_ids.len() + compact.prefilled_txs.len();
        if total > MAX_BLOCK_TX_COUNT {
            return Outcome::Fallback(hash);
        }

        let Some(mut filled) = place_prefills(compact, total) else {
            return Outcome::Fallback(hash);
        };
        let mut retained_bytes = 6 * compact.short_ids.len()
            + filled
                .iter()
                .flatten()
                .map(|tx: &Tx| tx.total_size())
                .sum::<usize>();

        // Enforce the cheap connection-level bounds before walking the
        // mempool. Keep the post-fill check as matched bodies add bytes.
        if self.pending.len() >= MAX_PENDING_RECONSTRUCTIONS
            || self.retained_bytes().saturating_add(retained_bytes) > MAX_PENDING_RETAINED_BYTES
        {
            return Outcome::Fallback(hash);
        }

        let identity_is_wtxid = identity_version == 2;
        let keys = ShortId::calculate_siphash_keys(&compact.header, compact.nonce);
        match fill_from_hints(
            &mut filled,
            compact,
            identity_is_wtxid,
            keys,
            hints,
            &mut retained_bytes,
        ) {
            Ok(()) => {}
            Err(()) => return Outcome::Fallback(hash),
        }

        if self.pending.len() >= MAX_PENDING_RECONSTRUCTIONS
            || self.retained_bytes() + retained_bytes > MAX_PENDING_RETAINED_BYTES
        {
            return Outcome::Fallback(hash);
        }
        let missing: Vec<u64> = filled
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.is_none())
            .map(|(index, _)| u64::try_from(index).unwrap_or(u64::MAX))
            .collect();
        if missing.is_empty() {
            return match complete_block(header, filled) {
                Ok(block) => Outcome::Complete(block),
                Err(()) => Outcome::Fallback(hash),
            };
        }
        if missing.len() > MAX_REQUESTED_MISSING {
            return Outcome::Fallback(hash);
        }
        self.pending.insert(
            hash,
            Pending {
                header,
                filled,
                missing: missing.clone(),
                retained_bytes,
                deadline: now + PENDING_DEADLINE,
            },
        );
        Outcome::RequestMissing(GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: wire_block_hash(hash),
                indexes: missing,
            },
        })
    }

    /// Receive-side entry for `blocktxn`.
    ///
    /// Absence is terminal: the entry is removed on entry, so any count,
    /// decode, slot, or Merkle failure releases `filled` and
    /// `retained_bytes` at once with one `Fallback`. A later `blocktxn`
    /// finds no entry and returns `Idle`.
    pub fn receive_blocktxn(&mut self, txn: &BlockTxn, now: Instant) -> Outcome {
        self.prune(now);
        let hash = native_block_hash(txn.transactions.block_hash);
        let Some(mut entry) = self.pending.remove(&hash) else {
            return Outcome::Idle;
        };
        if txn.transactions.transactions.len() != entry.missing.len() {
            return Outcome::Fallback(hash);
        }
        for (slot, tx) in entry.missing.iter().zip(&txn.transactions.transactions) {
            let Some(body) = native_tx(tx) else {
                return Outcome::Fallback(hash);
            };
            let Some(slot) = usize::try_from(*slot)
                .ok()
                .filter(|slot| *slot < entry.filled.len())
            else {
                return Outcome::Fallback(hash);
            };
            entry.filled[slot] = Some(body);
        }
        let filled = std::mem::take(&mut entry.filled);
        let Ok(block) = complete_block(entry.header, filled) else {
            return Outcome::Fallback(hash);
        };
        Outcome::Complete(block)
    }

    /// Drops pending entries whose deadline passed.
    pub fn prune(&mut self, now: Instant) {
        self.pending.retain(|_, entry| now < entry.deadline);
        self.recent
            .retain(|(_, received)| now.saturating_duration_since(*received) < PENDING_DEADLINE);
    }

    fn retained_bytes(&self) -> usize {
        self.pending
            .values()
            .map(|entry| entry.retained_bytes)
            .sum()
    }
}

/// PRE: `filled` holds the declared prefill plus one slot per declared short
/// ID for one reconstruction whose transaction request, if any, has been
/// answered.
/// POST: return a block only when every slot holds a body, the
/// transaction-ID merkle root of the assembled body equals
/// `header.merkle_root`, the transaction-ID tree is not mutated, and the body
/// is not a coinbase-less body with a 64-byte transaction; otherwise return
/// `Err`. The slot count needs no re-check here: the vector
/// is sized from the declared short IDs and prefills, `place_prefills`
/// rejects a prefill outside the declared slots, and `fill_from_hints`
/// rejects a short-ID count that does not match the unfilled slots.
/// INVARIANT: no unverified compact reconstruction reaches
/// [`Outcome::Complete`]. The root check alone cannot detect the
/// duplicate-final-transaction collision (CVE-2012-2459): `[a, b, c]` and
/// `[a, b, c, c]` hash to the same root, so the reduction also rejects a
/// mutated tree and the caller answers with the same-peer full-block
/// fallback (Core 31.1 `READ_STATUS_FAILED` before delivery,
/// `blockencodings.cpp:207-219`). A 64-byte transaction in a body without a
/// coinbase can pose as an inner tree node and reach the header's root with
/// fabricated leaves (CVE-2017-12842), so that body takes the same fallback
/// (Core `IsBlockMutated`, `validation.cpp:4035-4061`).
fn complete_block(header: Header, filled: Vec<Option<Tx>>) -> Result<Block, ()> {
    if filled.iter().any(Option::is_none) {
        return Err(());
    }
    let txs: Vec<Tx> = filled.into_iter().flatten().collect();
    let block = Block { header, txs };
    let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
    bitcoin_rs_consensus::verify_merkle_root_with_txids(&block, &txids).map_err(|_| ())?;
    if bitcoin_rs_consensus::is_sixty_four_byte_mutation(&block.txs) {
        return Err(());
    }
    Ok(block)
}

/// Matches the message's short IDs against the hint identities and fills
/// their slots. `short_ids` covers exactly the unfilled slots, in slot
/// order. Two structural faults mean the message cannot be trusted and the
/// reconstruction falls back rather than guess: fewer or more short IDs
/// than unfilled slots, and one short ID declared twice — a collapsed slot
/// map would silently misplace bodies. Two distinct hint identities that
/// collide on one short ID retire only that slot, which the `getblocktxn`
/// request then carries; a later candidate never refills it (Core 31.1
/// clears only the colliding slot, `blockencodings.cpp:116-166`).
///
/// PRE: `filled` holds one body per prefill and `None` per short-ID slot;
/// `retained_bytes` counts the short IDs and the prefilled bodies.
/// POST: every unambiguous slot holds its body and is counted once; a
/// retired slot, and one whose body the hints no longer offer, stay `None`
/// and uncounted.
/// INVARIANT: no body is looked up while the identity walk runs. The
/// mempool walk holds its pool read lock across the callback and a body
/// lookup takes that lock again, which deadlocks once a writer queues.
fn fill_from_hints(
    filled: &mut [Option<Tx>],
    compact: &HeaderAndShortIds,
    identity_is_wtxid: bool,
    keys: (u64, u64),
    hints: &dyn CompactBlockHints,
    retained_bytes: &mut usize,
) -> Result<(), ()> {
    let mut wanted: HashMap<ShortId, usize> = HashMap::new();
    let mut short_id_cursor = 0_usize;
    for (slot, slot_tx) in filled.iter().enumerate() {
        if slot_tx.is_some() {
            continue;
        }
        match compact.short_ids.get(short_id_cursor) {
            Some(short_id) => {
                wanted.insert(*short_id, slot);
                short_id_cursor += 1;
            }
            None => return Err(()),
        }
    }
    if short_id_cursor != compact.short_ids.len() || wanted.len() != compact.short_ids.len() {
        return Err(());
    }
    // Identity scan: record one claim per slot, retire a slot the first time
    // a second identity claims it.
    let mut claims: Vec<Option<(Txid, Wtxid)>> = vec![None; filled.len()];
    let mut retired = vec![false; filled.len()];
    hints.for_each_identity(&mut |txid, wtxid| {
        let identity = if identity_is_wtxid {
            wtxid.as_bytes()
        } else {
            txid.as_bytes()
        };
        let Some(&slot) = wanted.get(&ShortId::with_siphash_keys(identity, keys)) else {
            return;
        };
        if retired[slot] {
            return;
        }
        let Some((claimed_txid, claimed_wtxid)) = claims[slot] else {
            claims[slot] = Some((txid, wtxid));
            return;
        };
        if claimed_txid != txid || claimed_wtxid != wtxid {
            claims[slot] = None;
            retired[slot] = true;
        }
    });
    // Body pass: outside the walk, fetch each surviving claim once.
    for (slot, claim) in claims.into_iter().enumerate() {
        let Some((txid, wtxid)) = claim else {
            continue;
        };
        let body = if identity_is_wtxid {
            hints.get_tx_by_wtxid(wtxid)
        } else {
            hints.get_tx_by_txid(txid)
        };
        let Some(body) = body else {
            continue;
        };
        *retained_bytes += body.total_size();
        filled[slot] = Some(body);
    }
    Ok(())
}

/// Places the differentially encoded prefills into the transaction slots,
/// or `None` when an index overflows or lies outside the block.
fn place_prefills(compact: &HeaderAndShortIds, total: usize) -> Option<Vec<Option<Tx>>> {
    let mut filled: Vec<Option<Tx>> = vec![None; total];
    let mut position: usize = 0;
    for prefill in &compact.prefilled_txs {
        let slot = position.checked_add(usize::from(prefill.idx))?;
        if slot >= total {
            return None;
        }
        filled[slot] = Some(native_tx(&prefill.tx)?);
        position = slot + 1;
    }
    Some(filled)
}

/// Registry block header → primitives header.
pub(crate) fn native_header(reg: &bitcoin::blockdata::block::Header) -> Option<Header> {
    deserialize(&bitcoin::consensus::encode::serialize(reg)).ok()
}

fn native_tx(reg: &bitcoin::Transaction) -> Option<Tx> {
    deserialize(&bitcoin::consensus::encode::serialize(reg)).ok()
}

#[cfg(test)]
mod tests;
