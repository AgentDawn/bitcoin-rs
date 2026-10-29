use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Bound, RangeInclusive};

use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, TxIn, TxOut, Txid, Wtxid};

#[cfg(test)]
use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
use hashbrown::{HashMap, HashSet};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;
use thiserror::Error;

use crate::chunk_index::{ChunkIndex, ComponentState, MemberFacts, ProjectedChunks};
use crate::fee_estimator::{FeeEstimator, FeeRate};
use crate::mutation::{
    MutationChange, MutationOutcome, MutationResult, MutationSequence, RemovalReason,
};
use crate::policy::MEMPOOL_EXPIRY_SECS;
use crate::{EntryId, MempoolEntry, MempoolLimits, MempoolPolicySnapshot, PolicyError};
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
mod chunk_order_tests;
pub(crate) mod fee_policy;
pub(crate) mod package;

/// Script-index key for funding index range scans.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    bytemuck::Pod,
    bytemuck::Zeroable,
)]
#[repr(transparent)]
pub struct ScriptHash {
    /// Single SHA256 of the script bytes in consensus byte order.
    pub hash: Hash256,
}

impl ScriptHash {
    /// Hashes a script into an index key.
    #[must_use]
    pub fn from_script(script: &[u8]) -> Self {
        Self {
            hash: Hash256::from_le_bytes(&Sha256::digest(script).into()),
        }
    }

    /// Creates a script hash from the standard SHA256 digest bytes.
    #[must_use]
    pub const fn from_byte_array(bytes: [u8; 32]) -> Self {
        Self {
            hash: Hash256::from_le_bytes(&bytes),
        }
    }
}

/// Mempool insertion, mutation, and query-consistency errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MempoolError {
    /// The fee-policy graph could not be represented or validated.
    #[error(transparent)]
    FeeDiagram(#[from] crate::FeeDiagramError),
    /// A prepared mutation no longer matches membership or fee metadata.
    #[error("mempool changed during policy preparation")]
    StalePolicy,
    /// The transaction id already exists in the pool.
    #[error("transaction already exists in mempool")]
    DuplicateTransaction,
    /// The slab index can no longer fit the public `u32` entry id.
    #[error("mempool entry id space exhausted")]
    TooManyEntries,
    /// The transaction spends an output created by an entry scheduled for eviction.
    #[error("bad-txns-spends-conflicting-tx")]
    EvictedParent,
    /// The transaction violates mempool policy limits.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// The candidate would be evicted under the configured capacity bound.
    /// Its entire admission is refused before changing any pool state.
    #[error("mempool full")]
    Full,
    /// The spending index names an entry that is missing from the pool, or an
    /// entry whose transaction does not spend the indexed outpoint.
    #[error("mempool spending index is inconsistent")]
    InconsistentSpendingIndex,
}

/// Prioritisation overlay rejection reason.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PrioritiseError {
    /// Adding the delta to the signed overlay stored for a txid would leave
    /// the satoshi range. The overlay is left exactly as it was.
    #[error("fee delta would overflow the persistent overlay")]
    FeeDeltaOverflow,
}

/// One `prioritisetransaction` overlay entry, including txs not currently pooled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrioritisedTransaction {
    /// Transaction id the overlay is stored against.
    pub txid: Txid,
    /// Accumulated signed satoshi overlay.
    pub fee_delta: i64,
    /// Whether `txid` is currently in the pool.
    pub in_mempool: bool,
    /// Actual fee plus the accumulated delta, when pooled.
    pub modified_fee: Option<i128>,
}

/// Complete plan of removals for a candidate or connecting block.
///
/// One owner of block-inclusion and conflict-descendant removal semantics:
/// resident block transactions leave as `BlockInclusion` in block order,
/// their conflicts and full descendant subtrees leave as `Conflict`, each
/// resident planned at most once. `fee_deltas_cleared` counts the distinct
/// block transactions whose prioritisation overlay the block lifecycle
/// clears, so the mining generation can advance past exactly those overlays
/// and still invalidate on any concurrent `prioritise`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockRemovalPlan {
    /// Ordered entries and their exact removal reasons. Every `EntryId` is
    /// unique across the plan.
    pub removals: Vec<(EntryId, RemovalReason)>,
    /// Number of distinct block transactions with a stored fee overlay.
    pub fee_deltas_cleared: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FeeRateAggregate {
    count: u64,
    vsize: u64,
}

/// In-memory transaction pool with txid, funding, spending, and fee-priority indexes.
#[derive(Debug)]
pub struct Mempool {
    /// Entry arena. Public ids are reusable slot indices represented as `u32`.
    entries: EntryArena,
    /// Indexes and running totals derived from `entries`: the txid, wtxid,
    /// funding, and spending indexes, the component summaries, the priority
    /// index, and the vsize, fee, and fee-rate totals. One owner keeps them
    /// consistent: inserts account through [`Mempool::account_insert`], and
    /// removals reverse through [`Derived::account_remove`].
    derived: Derived,
    /// Nodes examined by graph walks since the last reset. Instrumentation for
    /// the bounded-work contract; one increment per walked entry. Atomic only
    /// because the pool must stay `Sync` behind the gateway's shared lock.
    graph_steps: AtomicU64,
    /// Active mempool policy limits.
    pub limits: MempoolLimits,

    /// Signed additive mining-only fee overlay, keyed by txid. A delta may be
    /// stored before its transaction is admitted, accumulates across calls,
    /// survives ordinary removal and replacement, and is erased only when the
    /// transaction is mined (see [`Mempool::remove_for_block`]). It adjusts
    /// modified package ordering only — never an actual fee.
    fee_deltas: HashMap<Txid, i64>,
    /// Token for metadata-only fee changes, separate from the public
    /// membership sequence. Prepared policy work captures both tokens.
    fee_delta_sequence: u64,
    /// Fee-rate history this pool owns and feeds from its own mutations.
    estimator: FeeEstimator,
    /// Mempool sequence: advanced once per emitted mutation change while the
    /// write lock is held. Reported by [`Mempool::sequence_number`], carried
    /// in ZMQ `A`/`R` event payloads, and used as the mining generation key's
    /// mempool component. Failed inserts, no-op removals, clear-on-empty, and
    /// in-pool prioritisation move nothing.
    mempool_sequence: u64,
    /// Commit-local observer capture, enabled only by the gateway's writer.
    pub(crate) accepted_capture: Option<Vec<(Txid, Arc<Tx>)>>,
    /// Core rolling minimum fee (`GetMinFee`/`trackPackageRemoved`/
    /// `removeForBlock` state). Locked after the pool lock and never held
    /// across another call: a capacity eviction or replacement trim raises
    /// the floor, every committed block connection stamps it for decay, and
    /// admission, relay, and the `getmempoolinfo` projection read it through
    /// [`Mempool::min_fee_sat_per_kvb`].
    rolling_min_fee: parking_lot::Mutex<crate::rolling_min_fee::RollingMinFee>,
    /// Revision of the rolling floor's raising transitions. Only
    /// actual raises advance it — a refused or committed trim whose rate
    /// exceeds the stored floor — never decay, reads, or block stamps. It is
    /// part of [`crate::pool::fee_policy::PolicyStamp`], so an admission that
    /// captured its facts before a concurrent floor raise fails its stamp
    /// check and retries against the newer floor instead of committing below
    /// it. Advanced only while holding the pool write guard.
    rolling_epoch: u64,
}

/// The index and total state derived from `entries`: everything a mutation
/// must keep in step with membership, and nothing else. Graph-walk
/// instrumentation (`graph_steps`) and the independent state — limits, the
/// fee-delta overlay and its sequence, the estimator, and the mempool
/// sequence — stay on [`Mempool`].
#[derive(Debug, Default)]
struct Derived {
    /// Tx id to entry id and acceptance sequence. Reach it through
    /// `contains_txid`, `entry_id_by_txid`, and `entry_by_txid`.
    by_txid: HashMap<Txid, IndexedEntry>,
    /// Funding index keyed by script hash then entry id. Reach it through
    /// `entries_funding_script`.
    funding: std::collections::BTreeSet<(ScriptHash, EntryId)>,
    /// Spending index keyed by spent outpoint then entry id. Reach it through
    /// `is_outpoint_spent` and `outpoint_spender`.
    spending: std::collections::BTreeSet<(SpendingKey, EntryId)>,
    /// Acceptance-time index: each entry's `time` then its id, oldest first.
    /// `has_expired_entries` and `expire` read it, so expiry never scans the
    /// arena. The id breaks ties and makes a recycled slot a distinct key.
    by_time: std::collections::BTreeSet<(u64, EntryId)>,
    /// Witness-id index. Reach it through `contains_wtxid` and
    /// `entry_by_wtxid`.
    by_wtxid: HashMap<Wtxid, EntryId>,
    /// Ordered index of live entries whose initial broadcast is pending.
    /// Derived from each entry's flag; key ranges bound relay retry work.
    unbroadcast: std::collections::BTreeSet<Wtxid>,
    /// Cached connected-component (cluster) summaries, indexed by component
    /// id. Maintained by `commit_insert` and `remove_entries_with_reasons`;
    /// read by the admission fast path in `check_cluster_limits`.
    components: Vec<ComponentSummary>,
    /// Recycled component ids. A component whose last member leaves frees
    /// its id here instead of growing the arena forever.
    free_components: Vec<u32>,
    /// Maintained chunk order for mining and eviction consumers: every live
    /// component's exact linearization, and the one global chunk index.
    /// Reach it through `chunks_by_feerate`.
    chunks: ChunkIndex,
    /// Running sum of `vsize` over `entries`.
    ///
    /// Maintained by the mutation methods below rather than folded on demand.
    /// `insert_entry` consults it on every accepted transaction to decide
    /// whether the pool is over its size limit, so folding it there cost `O(n)`
    /// per acceptance and made insertion quadratic in pool size on its own.
    ///
    /// Every mutation still goes through `insert_entry`, `remove_entries`,
    /// `prioritise` or `clear` — and
    /// `running_totals_track_inserts_removals_and_prioritise` holds both
    /// running sums to an independent fold of `entries` across every mutation
    /// kind.
    total_vsize: u64,
    /// Exact running sum of `fee` over `entries`. A `u32` entry id bounds the
    /// successful-entry sum below `u128::MAX`.
    total_fee: u128,
    /// Fee-rate counts and vsize sums keyed by each live
    /// `MempoolEntry.fee_rate`.
    fee_rate_aggregates: std::collections::BTreeMap<u64, FeeRateAggregate>,
}

impl Derived {
    /// Reverses one entry's accounting across the derived indexes and totals.
    /// The entry must have been accounted once. Priority-index retirement
    /// belongs to `refresh_metadata`; an untracked fee rate is an invariant error.
    fn account_remove(&mut self, id: EntryId, entry: &MempoolEntry) {
        self.total_vsize = self.total_vsize.saturating_sub(u64::from(entry.vsize));
        self.total_fee -= u128::from(entry.fee);
        match self.fee_rate_aggregates.entry(entry.fee_rate) {
            std::collections::btree_map::Entry::Occupied(mut occupied) => {
                let aggregate = occupied.get_mut();
                if aggregate.count > 1 {
                    debug_assert!(aggregate.vsize >= u64::from(entry.vsize));
                    aggregate.count -= 1;
                    aggregate.vsize -= u64::from(entry.vsize);
                } else {
                    debug_assert_eq!(aggregate.vsize, u64::from(entry.vsize));
                    occupied.remove();
                }
            }
            std::collections::btree_map::Entry::Vacant(_) => {
                debug_assert!(
                    false,
                    "fee-rate multiset drifted: removed a rate with no tracked count"
                );
            }
        }
        self.by_txid.remove(&entry.txid);
        self.by_wtxid.remove(&entry.wtxid);
        let _ = self.by_time.remove(&(entry.time, id));
        self.unbroadcast.remove(&entry.wtxid);
        for output in &entry.tx.outputs {
            let _ = self
                .funding
                .remove(&(ScriptHash::from_script(&output.script_pubkey), id));
        }
        for input in &entry.tx.inputs {
            let _ = self
                .spending
                .remove(&(SpendingKey::from(input.previous_output), id));
        }
    }
}

/// Current pool membership, retired together with the existing txid index row.
#[derive(Clone, Copy, Debug)]
struct IndexedEntry {
    id: EntryId,
    admitted_sequence: u64,
}
/// The live payload of an occupied slot.
#[derive(Debug)]
struct LiveEntry {
    /// Id of the cached component this entry belongs to.
    component: u32,
    /// Resolved parent and child links inside the pool.
    links: GraphLinks,
    entry: MempoolEntry,
}
/// Parent and child entry ids of one pooled transaction.
/// Both directions stay symmetric, sorted and deduplicated across mutations.
#[derive(Debug, Default)]
struct GraphLinks {
    parents: Vec<EntryId>,
    children: Vec<EntryId>,
}

/// Cached connected-component summary: the two numbers the admission-time
/// cluster check needs, kept exact by every mutation so the check reads
/// them instead of walking the graph.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ComponentSummary {
    member_count: u32,
    weight: u64,
}

/// Entry slots with LIFO reuse. The pool unlinks indexes and graph edges
/// before a vacated slot can acquire a new occupant.
#[derive(Debug)]
struct EntryArena {
    slots: Vec<Option<LiveEntry>>,
    /// Vacated slot indices, most recent last: the next `insert` reuses
    /// them, matching `Slab`'s vacancy stack.
    free: Vec<usize>,
    live: usize,
}

/// Slot index of an entry id, or `None` when the id cannot name a slot.
fn slot_index(id: EntryId) -> Option<usize> {
    usize::try_from(id).ok()
}

impl EntryArena {
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            live: 0,
        }
    }

    fn insert(&mut self, entry: MempoolEntry, component: u32, links: GraphLinks) -> usize {
        self.live += 1;
        let live = LiveEntry {
            component,
            links,
            entry,
        };
        if let Some(index) = self.free.pop() {
            let Some(slot) = self.slots.get_mut(index) else {
                panic!("vacancy stack names a live slot");
            };
            *slot = Some(live);
            return index;
        }
        self.slots.push(Some(live));
        self.slots.len() - 1
    }

    fn remove(&mut self, id: EntryId) -> Option<LiveEntry> {
        let index = slot_index(id)?;
        let slot = self.slots.get_mut(index)?;
        let live = slot.take()?;
        self.live -= 1;
        self.free.push(index);
        Some(live)
    }

    fn get(&self, id: EntryId) -> Option<&MempoolEntry> {
        self.slot(id).map(|live| &live.entry)
    }

    fn get_mut(&mut self, id: EntryId) -> Option<&mut MempoolEntry> {
        self.slot_mut(id).map(|live| &mut live.entry)
    }

    fn slot(&self, id: EntryId) -> Option<&LiveEntry> {
        self.slots.get(slot_index(id)?)?.as_ref()
    }

    fn slot_mut(&mut self, id: EntryId) -> Option<&mut LiveEntry> {
        self.slots.get_mut(slot_index(id)?)?.as_mut()
    }

    fn contains(&self, id: EntryId) -> bool {
        self.slot(id).is_some()
    }

    fn len(&self) -> usize {
        self.live
    }

    fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Length of the backing slot array, live and vacant alike.
    fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// The index the next `insert` will occupy.
    fn vacant_key(&self) -> usize {
        self.free.last().map_or(self.slots.len(), |&index| index)
    }

    fn clear(&mut self) {
        for slot in &mut self.slots {
            *slot = None;
        }
        self.free.clear();
        self.free.extend((0..self.slots.len()).rev());
        self.live = 0;
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (usize, &MempoolEntry)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.as_ref().map(|live| (index, &live.entry)))
    }

    fn iter_links(&self) -> impl Iterator<Item = &GraphLinks> {
        self.slots
            .iter()
            .filter_map(|slot| slot.as_ref().map(|live| &live.links))
    }
}

/// Membership bitset over entry ids that remembers insertion order.
#[derive(Debug, Default)]
struct VisitSet {
    words: Vec<u64>,
    members: Vec<EntryId>,
}

impl VisitSet {
    fn new() -> Self {
        Self::default()
    }

    fn test(&self, id: EntryId) -> bool {
        let Some(index) = slot_index(id) else {
            return false;
        };
        let Some(&word) = self.words.get(index / 64) else {
            return false;
        };
        word & (1_u64 << (index % 64)) != 0
    }

    /// Returns whether the set did not already hold `id`.
    fn insert(&mut self, id: EntryId) -> bool {
        let Some(index) = slot_index(id) else {
            return false;
        };
        if index / 64 >= self.words.len() {
            self.words.resize(index / 64 + 1, 0);
        }
        let bit = 1_u64 << (index % 64);
        if self.words[index / 64] & bit != 0 {
            return false;
        }
        self.words[index / 64] |= bit;
        self.members.push(id);
        true
    }

    fn members(&self) -> &[EntryId] {
        &self.members
    }
}

/// Membership marks a component walk records visited entries in.
trait VisitMarks {
    /// Returns whether the marks did not already hold `id`.
    fn insert(&mut self, id: EntryId) -> bool;
}

impl VisitMarks for VisitSet {
    fn insert(&mut self, id: EntryId) -> bool {
        Self::insert(self, id)
    }
}

impl VisitMarks for HashSet<EntryId> {
    fn insert(&mut self, id: EntryId) -> bool {
        Self::insert(self, id)
    }
}

/// Membership for walks confined to one connected component or one package.
/// A component holds at most the cluster-entry limit and a package at most
/// [`crate::standardness::MAX_PACKAGE_COUNT`], so a small inline list does
/// the work in time and space bounded by the visited entries, where
/// [`VisitSet`]'s bitset grows to the highest arena slot and zero-fills
/// arena-scale words on every call.
#[derive(Debug, Default)]
struct WalkSet {
    seen: SmallVec<[EntryId; 25]>,
}

impl WalkSet {
    fn new() -> Self {
        Self::default()
    }

    fn test(&self, id: EntryId) -> bool {
        self.seen.contains(&id)
    }

    fn len(&self) -> usize {
        self.seen.len()
    }
}

impl VisitMarks for WalkSet {
    fn insert(&mut self, id: EntryId) -> bool {
        if self.test(id) {
            return false;
        }
        self.seen.push(id);
        true
    }
}

pub(crate) struct PreparedInsert {
    pub(crate) entry: MempoolEntry,
}

/// The in-pool spender of one outpoint, resolved through the spending index.
#[derive(Clone, Copy, Debug)]
pub struct OutpointSpender<'a> {
    /// The entry whose transaction spends the outpoint.
    pub entry: &'a MempoolEntry,
    /// Index of the input within `entry.tx` that spends the outpoint.
    pub vin: u32,
}

/// Aggregate mempool counters surfaced through the JSON-RPC `getmempoolinfo`
/// and Esplora fee-estimate surfaces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MempoolStats {
    /// Number of transactions in the mempool.
    pub txs: u64,
    /// Sum of virtual sizes in vbytes.
    pub bytes: u64,
    /// Sum of base fees in satoshis.
    pub total_fee: u64,
}

/// One mempool entry copied into a [`MempoolMiningSnapshot`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotEntry {
    /// Tx payload, shared with the pool entry by `Arc`.
    pub tx: Arc<Tx>,
    /// Tx id.
    pub txid: Txid,
    /// Witness transaction id.
    pub wtxid: Wtxid,
    /// Policy-adjusted virtual size in vbytes.
    pub vsize: u32,
    /// BIP141 virtual size in vbytes.
    pub bip141_vsize: u32,
    /// Consensus serialization size, including witness, in bytes.
    pub size: u32,
    /// Consensus transaction weight in weight units.
    pub weight: u64,
    /// Consensus sigop cost, prevout-aware when admission supplied it.
    pub sigop_cost: u32,
    /// Actual transaction fee in satoshis. Prioritisation never changes it.
    pub fee: u64,
    /// Signed additive mining-only overlay applied to `fee` for ordering.
    pub fee_delta: i64,
    /// Mempool acceptance time in seconds.
    pub time: u64,
    /// Chain height at acceptance.
    pub height: u32,
    /// Total virtual size of this entry and all its unconfirmed ancestors.
    pub ancestor_size: u64,
    /// Total actual fee of this entry and all its unconfirmed ancestors.
    pub ancestor_fee: u64,
    /// Total signed overlay of this entry and all its unconfirmed ancestors.
    pub ancestor_fee_delta: i128,
    /// Snapshot positions of the transitive unconfirmed ancestors.
    pub ancestors: Vec<u32>,
}

/// Immutable copy of everything block-template selection needs from the pool,
/// captured by [`Mempool::mining_snapshot`] under one read.
#[derive(Clone, Debug)]
pub struct MempoolMiningSnapshot {
    /// Pool mempool sequence at capture. Every admission and removal change
    /// moves it; in-pool prioritisation does not (it emits no mutation
    /// change). Template caches key on it together with `fee_delta_sequence`.
    pub sequence: u64,
    /// Fee-delta sequence at capture, read under the same pool state as
    /// `sequence` and the transaction facts. In-pool prioritisation moves it;
    /// template caches key on it together with `sequence`.
    pub fee_delta_sequence: u64,
    /// Entries in maintained chunk order. `ancestors` positions and the
    /// order itself both refer to this vector.
    pub entries: Vec<SnapshotEntry>,
}

impl Mempool {
    /// Creates an empty mempool with the supplied limits.
    #[must_use]
    pub fn new(limits: MempoolLimits) -> Self {
        Self {
            entries: EntryArena::new(),
            derived: Derived::default(),
            graph_steps: AtomicU64::new(0),
            limits,

            fee_deltas: HashMap::new(),
            fee_delta_sequence: 0,
            estimator: FeeEstimator::new(),
            mempool_sequence: 0,
            accepted_capture: None,
            rolling_min_fee: parking_lot::Mutex::new(
                crate::rolling_min_fee::RollingMinFee::default(),
            ),
            rolling_epoch: 0,
        }
    }

    /// Removes all entries from the pool, clears every index and the
    /// persistent prioritisation overlay, and resets the fee history. Every
    /// cleared entry commits as one `Removed(Clear)` change — in entry-id
    /// order — each taking the next mempool sequence value. A clear of an
    /// already-empty pool commits nothing and moves no sequence.
    ///
    /// The fee-history reset is intentional and specific to this wholesale
    /// action: the estimator returns to the empty, insufficient-data state
    /// because every observation it held described transactions this pool no
    /// longer tracks. A reorg never routes through `clear` — disconnected
    /// transactions return through reconsideration (re-admission), which
    /// keeps the recorded confirmations and re-arms only the re-admitted
    /// entries — so chain recovery cannot silently discard fee history.
    ///
    /// This is an explicit wholesale reset for standalone pools and fixtures.
    /// Ordinary block, reorg, and snapshot paths preserve fee history.
    pub fn clear(&mut self) -> MutationResult {
        // Every entry leaves the pool here, so this is the same retire funnel
        // Core walks during a bulk clear: fire `mempool:removed` per entry
        // before the arena is emptied. The explicit-clear class reports
        // `unknown`, Core's `MemPoolRemovalReason::UNKNOWN` string.
        let mut txids = Vec::with_capacity(self.entries.len());
        for (_id, entry) in self.entries.iter() {
            bitcoin_rs_consensus::trace::removed(|| {
                (
                    entry.txid.as_bytes().as_ptr(),
                    "unknown",
                    i32::try_from(entry.vsize).unwrap_or(i32::MAX),
                    i64::try_from(entry.fee).unwrap_or(i64::MAX),
                    entry.time,
                )
            });
            txids.push(entry.txid);
        }
        self.entries.clear();
        self.derived = Derived::default();
        self.graph_steps.store(0, Ordering::Relaxed);

        if !self.fee_deltas.is_empty() {
            self.fee_delta_sequence = MutationSequence::advance(self.fee_delta_sequence);
            self.fee_deltas.clear();
        }
        self.estimator = FeeEstimator::new();
        let mut changes = Vec::with_capacity(txids.len());
        for txid in txids {
            self.push_change(
                &mut changes,
                txid,
                MutationOutcome::Removed(RemovalReason::Clear),
            );
        }
        self.finish_mutation(changes)
    }

    /// Returns the current mempool sequence: a counter advanced once per
    /// emitted mutation change. `getmempoolinfo`, `getrawmempool` sequence
    /// reporting, and the mining generation key all read this counter. Failed
    /// inserts, no-op removals, clear-on-empty, and in-pool prioritisation
    /// move nothing.
    #[must_use]
    pub const fn sequence_number(&self) -> u64 {
        self.mempool_sequence
    }

    /// Returns the current fee-delta sequence: a generation counter for
    /// fee-priority metadata. Prioritisation does not move membership.
    /// The mining generation key reads it together with
    /// [`Mempool::sequence_number`]. It advances on prioritisation
    /// (even when the stored delta nets to zero), on mined removal of a
    /// stored delta, and on clear while stored deltas remain; ordinary
    /// removal and replacement leave it alone.
    #[must_use]
    pub const fn fee_delta_sequence_number(&self) -> u64 {
        self.fee_delta_sequence
    }

    /// Returns the configured min-relay-fee rate in sat/kvB.
    #[must_use]
    pub const fn min_relay_fee_sat_per_kvb(&self) -> u64 {
        self.limits.min_relay_fee_sat_per_kvb
    }

    /// Returns the admission, relay, and eviction floor in sat/kvB: Core's
    /// rolling minimum fee, floored at the configured min-relay rate.
    ///
    /// Reading is a state transition, exactly as Core's `GetMinFee`: when a
    /// block has connected since the last bump and the clock has moved past
    /// the ten-second grace, the stored rate decays once and may reset to
    /// zero. The rolling lock is taken after the pool lock and dropped
    /// before the call returns — never held across another pool call.
    #[must_use]
    pub fn min_fee_sat_per_kvb(&self, now: u64) -> u64 {
        let incremental = crate::policy::DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB;
        let rate = {
            let mut rolling = self.rolling_min_fee.lock();
            rolling.current(
                now,
                self.total_vsize(),
                self.limits.max_total_bytes,
                incremental,
            )
        };
        rate.max(self.limits.min_relay_fee_sat_per_kvb)
    }

    /// Core `trackPackageRemoved`: raises the rolling floor to `removed`
    /// sat/kvB when it exceeds the stored rate, holding decay until the next
    /// connected block.
    ///
    /// Takes `&mut self`: every raise is a pool state transition serialized
    /// under the write guard, so a read-guard floor/stamp capture stays
    /// coherent — no floor can rise between the capture and its stamp check.
    /// The leaf rolling mutex is locked after the pool guard and released
    /// before this returns. Only an actual rise advances `rolling_epoch`;
    /// decay, reads, and block stamps never do. Callers must already hold the
    /// write guard at the state the bump was computed against;
    /// [`Mempool::commit_pool_change`] (stamp checked) and
    /// [`Mempool::track_refused_trim`] (stamp checked) are the only callers.
    pub(crate) fn track_package_removed(&mut self, removed: u64) {
        if self.rolling_min_fee.lock().track_package_removed(removed) {
            self.rolling_epoch = MutationSequence::advance(self.rolling_epoch);
        }
    }

    /// Bitcoin Core `RemovalReasonToString` mapping for `mempool:removed`.
    const fn core_removal_reason(reason: RemovalReason) -> &'static str {
        match reason {
            RemovalReason::BlockInclusion => "block",
            RemovalReason::Conflict => "conflict",
            RemovalReason::Replaced | RemovalReason::Descendant => "replaced",
            RemovalReason::PolicyEviction => "sizelimit",
            RemovalReason::Expiry => "expiry",
            RemovalReason::Reorg => "reorg",
            RemovalReason::Clear => "unknown",
        }
    }

    /// Records one committed change and assigns it the next mempool sequence
    /// value. Callers hold the write lock for the whole mutation, so
    /// assignment is total, ordered, and gap-free within a batch.
    fn push_change(
        &mut self,
        changes: &mut Vec<MutationChange>,
        txid: Txid,
        outcome: MutationOutcome,
    ) {
        self.mempool_sequence = MutationSequence::advance(self.mempool_sequence);
        changes.push(crate::mutation::change(&txid, outcome));
    }

    /// Wraps an ordered change list into a result, deriving the batch's
    /// sequence base from the counter the changes just advanced.
    pub(crate) fn finish_mutation(&self, changes: Vec<MutationChange>) -> MutationResult {
        let sequence_base = MutationSequence::base(self.mempool_sequence, changes.len());
        MutationResult {
            changes,
            sequence_base,
        }
    }

    /// Inserts trusted entry facts after preflighting cluster and capacity
    /// constraints. A refused insert leaves membership and history unchanged.
    ///
    /// Test seam: fixture staging only; production admission verifies through
    /// the gateway's `submit_transaction`/`capture_admission` path.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn insert_entry(
        &mut self,
        entry: MempoolEntry,
    ) -> Result<crate::mutation::MutationResult, MempoolError> {
        let inputs = self
            .capture_insertion(
                entry,
                crate::rbf::FeeEstimation::Estimate,
                crate::rbf::LimitEnforcement::Full,
            )
            .map_err(crate::RbfError::into_pool_error)?;
        let plan = match inputs.verify() {
            Ok(plan) => plan,
            // One `&mut` borrow spans capture and verify, so the refusal's
            // stamp is current; the stale arm is defensive only.
            Err(refusal) => {
                let (error, bump) = refusal.into_parts();
                if matches!(bump, Some(bump) if self.track_refused_trim(bump).is_err()) {
                    return Err(MempoolError::StalePolicy);
                }
                return Err(error.into_pool_error());
            }
        };
        self.commit_pool_change(plan)
            .map_err(crate::RbfError::into_pool_error)
    }

    /// Preflights one entry against the pool's structural and cluster limits.
    pub(crate) fn validate_insert(
        &self,
        entry: MempoolEntry,
        excluded: &HashSet<EntryId>,
        enforcement: crate::rbf::LimitEnforcement,
    ) -> Result<PreparedInsert, MempoolError> {
        let prepared = self.prepare_insert(entry, excluded, enforcement)?;
        self.check_cluster_limits(&prepared.entry.tx, prepared.entry.policy_weight(), excluded)?;
        if excluded.is_empty() && u32::try_from(self.entries.vacant_key()).is_err() {
            return Err(MempoolError::TooManyEntries);
        }
        Ok(prepared)
    }

    /// Shared entry validation and metadata preparation. The enclosing single
    /// or package plan must also preflight its graph and entry-id allocation.
    fn prepare_insert(
        &self,
        mut entry: MempoolEntry,
        excluded: &HashSet<EntryId>,
        enforcement: crate::rbf::LimitEnforcement,
    ) -> Result<PreparedInsert, MempoolError> {
        let txid = entry.txid;
        let min_rate = self.limits.min_relay_fee_sat_per_kvb;
        entry.fee_delta = self.fee_deltas.get(&txid).copied().unwrap_or(0);
        if entry.vsize == 0 {
            return Err(PolicyError::InvalidVirtualSize.into());
        }
        let required = crate::rbf::required_fee(min_rate, entry.vsize)
            .map_err(|_| PolicyError::FeeArithmetic)?;
        if enforcement != crate::rbf::LimitEnforcement::Deferred && entry.modified_fee() < required
        {
            let modified_rate = entry.modified_fee() * 1_000 / i128::from(entry.vsize);
            return Err(PolicyError::BelowMinRelayFee {
                tx_rate: u64::try_from(modified_rate).unwrap_or(0),
                min_rate,
            }
            .into());
        }

        if self.derived.by_txid.contains_key(&txid) {
            return Err(MempoolError::DuplicateTransaction);
        }

        if entry.tx.inputs.iter().any(|input| {
            self.derived
                .by_txid
                .get(&input.previous_output.txid)
                .is_some_and(|indexed| excluded.contains(&indexed.id))
        }) {
            return Err(MempoolError::EvictedParent);
        }

        let ancestors = self.ancestor_ids_for_tx(&entry.tx);
        let ancestor_size = ancestors.iter().fold(u64::from(entry.vsize), |total, id| {
            total.saturating_add(
                self.entry(*id)
                    .map_or(0, |ancestor| u64::from(ancestor.vsize)),
            )
        });
        let ancestor_fee = ancestors.iter().fold(entry.fee, |total, id| {
            total.saturating_add(self.entry(*id).map_or(0, |ancestor| ancestor.fee))
        });
        entry.ancestor_size = ancestor_size;
        entry.ancestor_fee = ancestor_fee;
        entry.ancestor_fee_delta = i128::from(entry.fee_delta);
        entry.descendant_size = u64::from(entry.vsize);
        entry.descendant_fee = entry.fee;
        entry.descendant_fee_delta = i128::from(entry.fee_delta);

        Ok(PreparedInsert { entry })
    }

    /// Installs one prevalidated entry. The encompassing plan owns removals,
    /// estimator updates and publication after every fallible check has passed.
    pub(crate) fn commit_insert(&mut self, prepared: PreparedInsert) -> MutationResult {
        let entry = prepared.entry;
        let txid = entry.txid;
        if let Some(capture) = &mut self.accepted_capture {
            capture.push((txid, Arc::clone(&entry.tx)));
        }
        let added_vsize = u64::from(entry.vsize);
        let added_fee = entry.fee;
        let parents = self.in_pool_parents(&entry.tx);
        let children = self.in_pool_children(txid);
        let component = self.merge_neighbour_components(&parents, &children, &entry);
        let index = self.entries.insert(entry, component, GraphLinks::default());
        let Ok(id) = EntryId::try_from(index) else {
            panic!("validate_insert accepted an entry id that does not fit u32");
        };
        for parent in &parents {
            if let Some(slot) = self.entries.slot_mut(*parent) {
                let position = slot
                    .links
                    .children
                    .binary_search(&id)
                    .unwrap_or_else(|position| position);
                slot.links.children.insert(position, id);
            }
        }
        for child in &children {
            if let Some(slot) = self.entries.slot_mut(*child) {
                let position = slot
                    .links
                    .parents
                    .binary_search(&id)
                    .unwrap_or_else(|position| position);
                slot.links.parents.insert(position, id);
            }
        }
        if let Some(slot) = self.entries.slot_mut(id) {
            slot.links = GraphLinks { parents, children };
        }

        let mut changes = Vec::new();
        self.push_change(&mut changes, txid, MutationOutcome::Accepted);
        let admitted_sequence = self.mempool_sequence;
        self.account_insert(id, admitted_sequence);
        let affected = self.metadata_closure(&[id]);
        self.refresh_metadata(&affected);
        // One relinearization for the merged cluster, seeded from the entry
        // just linked in, so no arena scan is needed to find its members.
        self.relinearize_from_seed(component, id);
        // Core fires `mempool:added` from `CTxMemPool::addUnchecked`, the
        // pool-internal install funnel, after the entry is linked into the
        // pool. `prepare` runs only while a consumer is attached.
        bitcoin_rs_consensus::trace::added(|| {
            (
                txid.as_bytes().as_ptr(),
                i32::try_from(added_vsize).unwrap_or(i32::MAX),
                i64::try_from(added_fee).unwrap_or(i64::MAX),
            )
        });
        self.finish_mutation(changes)
    }

    /// Accounts one admitted entry across the derived indexes and totals.
    fn account_insert(&mut self, id: EntryId, admitted_sequence: u64) {
        let Some(entry) = self.entry(id) else {
            debug_assert!(false, "account_insert called for a missing entry");
            return;
        };
        let tx = Arc::clone(&entry.tx);
        let txid = entry.txid;
        let wtxid = entry.wtxid;
        let time = entry.time;
        let unbroadcast = entry.unbroadcast;
        let added_vsize = u64::from(entry.vsize);
        let added_fee = entry.fee;
        let added_fee_rate = entry.fee_rate;
        self.derived.total_vsize = self.derived.total_vsize.saturating_add(added_vsize);
        self.derived.total_fee += u128::from(added_fee);
        let aggregate = self
            .derived
            .fee_rate_aggregates
            .entry(added_fee_rate)
            .or_default();
        aggregate.count += 1;
        aggregate.vsize += added_vsize;
        self.derived.by_txid.insert(
            txid,
            IndexedEntry {
                id,
                admitted_sequence,
            },
        );
        self.derived.by_wtxid.insert(wtxid, id);
        self.derived.by_time.insert((time, id));
        if unbroadcast {
            self.derived.unbroadcast.insert(wtxid);
        }
        for output in &tx.outputs {
            self.derived
                .funding
                .insert((ScriptHash::from_script(&output.script_pubkey), id));
        }
        for input in &tx.inputs {
            self.derived
                .spending
                .insert((SpendingKey::from(input.previous_output), id));
        }
    }

    /// Record arrival only after the complete mutation's capacity decision.
    pub(crate) fn record_entry_arrival(&mut self, txid: Txid) {
        if let Some((fee_rate, height)) = self
            .entry_by_txid(&txid)
            .map(|entry| (entry.fee_rate, entry.height))
        {
            self.estimator.tx_entered(txid, fee_rate, height);
        }
    }

    /// Resolved in-pool children — entries already spending an output of
    /// `txid` — sorted and deduplicated. One contiguous range of the spend
    /// index, so it also catches a child that named a vout beyond the
    /// parent's output count before the parent arrived.
    fn in_pool_children(&self, txid: Txid) -> Vec<EntryId> {
        let start = (
            SpendingKey::from(OutPoint::new(txid, u32::MIN)),
            EntryId::MIN,
        );
        let end = (
            SpendingKey::from(OutPoint::new(txid, u32::MAX)),
            EntryId::MAX,
        );
        let mut children: Vec<EntryId> = self
            .derived
            .spending
            .range(start..=end)
            .map(|(_, child)| *child)
            .collect();
        children.sort_unstable();
        children.dedup();
        children
    }
    /// Resolved in-pool parents of a not-yet-pooled transaction: sorted and
    /// deduplicated, so downstream link lists inherit that shape.
    fn in_pool_parents(&self, tx: &Tx) -> Vec<EntryId> {
        let mut parents: Vec<EntryId> = tx
            .inputs
            .iter()
            .filter_map(|input| self.entry_id_by_txid(&input.previous_output.txid))
            .collect();
        parents.sort_unstable();
        parents.dedup();
        parents
    }

    /// Joins the candidate into one component spanning every distinct
    /// component its in-pool neighbours sit in, returning the component id.
    fn merge_neighbour_components(
        &mut self,
        parents: &[EntryId],
        children: &[EntryId],
        entry: &MempoolEntry,
    ) -> u32 {
        let mut summary = ComponentSummary {
            member_count: 1,
            weight: entry.policy_weight(),
        };
        let mut base: Option<u32> = None;
        let mut merged: Vec<u32> = Vec::new();
        for neighbour in parents.iter().chain(children.iter()).copied() {
            let Some(neighbour_component) = self.component_id(neighbour) else {
                continue;
            };
            if merged.contains(&neighbour_component) {
                continue;
            }
            merged.push(neighbour_component);
            let absorbed = self
                .component_summary(neighbour_component)
                .copied()
                .unwrap_or_default();
            summary.member_count = summary.member_count.saturating_add(absorbed.member_count);
            summary.weight = summary.weight.saturating_add(absorbed.weight);
            let Some(base_component) = base else {
                base = Some(neighbour_component);
                continue;
            };
            let mut visited = WalkSet::new();
            let mut members = Vec::new();
            self.collect_component_members(neighbour, &mut visited, &mut members);
            for member in &members {
                if let Some(slot) = self.entries.slot_mut(*member) {
                    slot.component = base_component;
                }
            }
            if let Some(vacated) = self.component_summary_mut(neighbour_component) {
                *vacated = ComponentSummary::default();
            }
            self.free_component(neighbour_component);
        }
        let component = base.unwrap_or_else(|| self.alloc_component());
        if let Some(slot) = self.component_summary_mut(component) {
            *slot = summary;
        }
        component
    }

    /// Component id of a live entry, or `None` when the id is vacant.
    fn component_id(&self, id: EntryId) -> Option<u32> {
        Some(self.entries.slot(id)?.component)
    }

    /// Cached summary of one component id.
    fn component_summary(&self, component: u32) -> Option<&ComponentSummary> {
        self.derived
            .components
            .get(usize::try_from(component).ok()?)
    }

    /// Mutable variant of [`Self::component_summary`].
    fn component_summary_mut(&mut self, component: u32) -> Option<&mut ComponentSummary> {
        self.derived
            .components
            .get_mut(usize::try_from(component).ok()?)
    }

    /// Mints a component id, recycling a freed one when available.
    fn alloc_component(&mut self) -> u32 {
        self.derived.free_components.pop().unwrap_or_else(|| {
            self.derived.components.push(ComponentSummary::default());
            let id = u32::try_from(self.derived.components.len() - 1);
            match id {
                Ok(id) => id,
                Err(error) => panic!("component count exceeds the u32 entry-id space: {error}"),
            }
        })
    }

    /// Returns a component id to the free list. Its summary must be zero.
    /// Forgetting the id here, at the one owner that frees components, also
    /// drops the absorbed component's chunk keys when a merge retires it.
    fn free_component(&mut self, component: u32) {
        debug_assert!(
            self.component_summary(component)
                .is_some_and(|summary| *summary == ComponentSummary::default()),
            "freed a component that still reports members"
        );
        self.derived.chunks.forget(component);
        self.derived.free_components.push(component);
    }

    /// Collects the connected component holding `seed` with one walk over
    /// the parent/child links, recording membership in `visited` so callers
    /// can partition several seeds without re-walking.
    fn collect_component_members<M: VisitMarks>(
        &self,
        seed: EntryId,
        visited: &mut M,
        members: &mut Vec<EntryId>,
    ) {
        if !visited.insert(seed) {
            return;
        }
        members.push(seed);
        let mut frontier = vec![seed];
        while let Some(id) = frontier.pop() {
            self.graph_steps.fetch_add(1, Ordering::Relaxed);
            let Some(links) = self.links(id) else {
                continue;
            };
            for neighbour in links.parents.iter().chain(links.children.iter()).copied() {
                if visited.insert(neighbour) {
                    members.push(neighbour);
                    frontier.push(neighbour);
                }
            }
        }
    }

    /// Parent and child links of a live entry.
    fn links(&self, id: EntryId) -> Option<&GraphLinks> {
        Some(&self.entries.slot(id)?.links)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when `txid` is present in the mempool.
    #[must_use]
    pub fn contains_txid(&self, txid: &Txid) -> bool {
        self.derived.by_txid.contains_key(txid)
    }

    /// Returns a reference to the `MempoolEntry` for `txid`, or `None` if the
    /// transaction is not in the pool.
    #[must_use]
    pub fn entry_by_txid(&self, txid: &Txid) -> Option<&MempoolEntry> {
        self.entry(self.entry_id_by_txid(txid)?)
    }

    pub(crate) fn set_unbroadcast(&mut self, wtxid: bitcoin_rs_primitives::Wtxid, pending: bool) {
        if let Some(&id) = self.derived.by_wtxid.get(&wtxid)
            && let Some(entry) = self.entry_mut(id)
        {
            entry.unbroadcast = pending;
            if pending {
                self.derived.unbroadcast.insert(wtxid);
            } else {
                self.derived.unbroadcast.remove(&wtxid);
            }
        }
    }

    /// Returns a clone of the shared `Arc<Tx>` for `txid`, or `None`
    /// if the transaction is not in the pool.
    ///
    /// Cheaper than [`Self::entry_by_txid`] when only the transaction body is needed
    /// — no `MempoolEntry` indirection, just an `Arc::clone`.
    #[must_use]
    pub fn transaction_by_txid(&self, txid: &Txid) -> Option<Arc<Tx>> {
        self.entry_by_txid(txid).map(|entry| Arc::clone(&entry.tx))
    }

    /// Returns the public entry id for `txid`, or `None` when the transaction
    /// is not in the pool.
    #[must_use]
    pub fn entry_id_by_txid(&self, txid: &Txid) -> Option<EntryId> {
        self.derived.by_txid.get(txid).map(|indexed| indexed.id)
    }

    /// Returns the resident entry only when its acceptance has `sequence`.
    #[must_use]
    pub fn entry_by_txid_at_sequence(&self, txid: &Txid, sequence: u64) -> Option<&MempoolEntry> {
        let indexed = self.derived.by_txid.get(txid)?;
        if indexed.admitted_sequence != sequence {
            return None;
        }
        self.entry(indexed.id)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the txids of every entry in the pool.
    ///
    /// Order is the underlying slab iteration order, not fee-rate sorted.
    #[must_use]
    pub fn iter_txids(&self) -> Vec<Txid> {
        self.entries.iter().map(|(_id, entry)| entry.txid).collect()
    }

    /// Returns txids with explicit BIP125 sequence signaling.
    ///
    /// This reports transaction metadata. Full-RBF admission also considers
    /// replacements of entries without that signal.
    #[cfg(test)]
    #[must_use]
    fn iter_replaceable_txids(&self) -> Vec<Txid> {
        self.entries
            .iter()
            .filter(|(_id, entry)| entry.is_replaceable())
            .map(|(_id, entry)| entry.txid)
            .collect()
    }

    /// Returns the relay-policy snapshot this pool enforces, for the RPC
    /// `getmempoolinfo` projection and the transaction-admission surface.
    #[must_use]
    pub fn policy_snapshot(&self) -> MempoolPolicySnapshot {
        MempoolPolicySnapshot::from_enforced(
            self.limits,
            crate::standardness::StandardnessPolicy::default(),
        )
    }

    /// Returns the total virtual size of all entries.
    #[must_use]
    pub fn total_vsize(&self) -> u64 {
        self.derived.total_vsize
    }

    /// Evicts the lowest-fee packages until the pool's total vsize is at or
    /// below `max_bytes`. Each evicted entry — and each descendant swept with
    /// its package — commits as one `Removed(PolicyEviction)` change, in
    /// eviction commit order.
    pub fn enforce_size_limit(&mut self, max_bytes: u64) -> Result<MutationResult, MempoolError> {
        let changes = crate::evict_lowest_fee_packages(self, max_bytes)?;
        Ok(self.finish_mutation(changes))
    }

    /// Returns the sum of fees of all entries in the pool, in satoshis.
    #[must_use]
    fn aggregate_fees(&self) -> u64 {
        u64::try_from(self.derived.total_fee).unwrap_or(u64::MAX)
    }

    /// Returns aggregate counters for the current pool.
    #[must_use]
    pub fn stats(&self) -> MempoolStats {
        let txs = u64::try_from(self.entries.len()).unwrap_or(u64::MAX);
        let bytes = self.total_vsize();
        let total_fee = self.aggregate_fees();
        MempoolStats {
            txs,
            bytes,
            total_fee,
        }
    }

    /// Estimates the heap this pool occupies, in bytes.
    #[must_use]
    pub fn dynamic_memory_usage(&self) -> u64 {
        use core::mem::size_of;

        // The arena is charged at **capacity**, not at length. The slot
        // array keeps its backing allocation across removals and across
        // `clear`, so a pool that grew to a million entries and then emptied
        // still holds the arena -- and charging `len()` reported that
        // retained memory as zero, which is exactly the moment an operator
        // looks at `usage` to find out where it went. Core charges its own
        // pool the same way: `mapTx`'s allocator does not return nodes to
        // the OS either.
        //
        // Everything below stays keyed to live entries. They are payload
        // terms -- the transactions and the index keys -- and a removed
        // entry's payload really is gone.
        let arena = u64::try_from(self.entries.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<Option<LiveEntry>>()).unwrap_or(0));

        let transactions = self
            .entries
            .iter()
            .map(|(_index, entry)| transaction_heap_usage(&entry.tx))
            .fold(0_u64, u64::saturating_add);

        let by_txid = u64::try_from(self.derived.by_txid.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(Txid, IndexedEntry)>()).unwrap_or(0));
        let funding = u64::try_from(self.derived.funding.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(ScriptHash, EntryId)>()).unwrap_or(0));
        let spending = u64::try_from(self.derived.spending.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(SpendingKey, EntryId)>()).unwrap_or(0));
        let by_wtxid = u64::try_from(self.derived.by_wtxid.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(Wtxid, EntryId)>()).unwrap_or(0));
        // A `BTreeSet` exposes no capacity, so the acceptance-time index is
        // charged by length like the funding and spending maps.
        let by_time = u64::try_from(self.derived.by_time.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(u64, EntryId)>()).unwrap_or(0));
        let unbroadcast = u64::try_from(self.derived.unbroadcast.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<Wtxid>()).unwrap_or(0));
        let links = self.entries.iter_links().fold(0_u64, |total, link| {
            let payload = link
                .parents
                .capacity()
                .saturating_add(link.children.capacity());
            total.saturating_add(
                u64::try_from(payload)
                    .unwrap_or(u64::MAX)
                    .saturating_mul(u64::try_from(size_of::<EntryId>()).unwrap_or(0)),
            )
        });
        let components = u64::try_from(self.derived.components.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<ComponentSummary>()).unwrap_or(0));
        let chunks = self.derived.chunks.dynamic_memory_usage();

        arena
            .saturating_add(transactions)
            .saturating_add(by_txid)
            .saturating_add(by_wtxid)
            .saturating_add(by_time)
            .saturating_add(unbroadcast)
            .saturating_add(funding)
            .saturating_add(spending)
            .saturating_add(links)
            .saturating_add(components)
            .saturating_add(chunks)
    }
    /// Estimates the fee rate that historically confirmed within
    /// `conf_target_blocks`, from the admission and confirmation history this
    /// pool feeds itself. Returns `None` when the history is too thin to
    /// answer — an honest refusal rather than a fabricated rate.
    #[must_use]
    pub fn estimate_fee_rate(&self, conf_target_blocks: u32) -> Option<FeeRate> {
        self.estimator.estimate(conf_target_blocks)
    }

    /// Returns the estimator's last decayed height, or `None` before the first
    /// connected block. A connected block ages the estimator even when the
    /// pool is empty, so this is the observable proof that `remove_for_block`
    /// fired `block_connected`.
    /// Test seam.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn estimator_last_decayed_height(&self) -> Option<u32> {
        self.estimator.last_decayed_height()
    }

    /// Returns the estimator's encoded recoverable state for the owner-local
    /// history file (docs/policies/db-migration.md). Deterministic bytes.
    #[must_use]
    pub fn estimator_history(&self) -> Vec<u8> {
        self.estimator.to_history_bytes()
    }

    /// Publishes already decoded history so datadir loading can validate it
    /// before acquiring the mempool write lock.
    pub(crate) fn adopt_estimator_history(&mut self, history: FeeEstimator) {
        self.estimator = history;
    }

    /// Copies the pool's mining state into one immutable snapshot.
    /// Everything block-template selection needs is read in this single
    /// coherent pass — shared transaction payloads, per-entry fee, sigop,
    /// weight, and size metadata, the signed overlay, ancestor-package
    /// aggregates, ancestor topology, and both sequence counters — so
    /// the caller's read critical section ends when this returns and
    /// selection works on the owned copy with the lock released. Entries
    /// appear in maintained chunk order (the order `chunks_by_feerate`
    /// yields), and `ancestors` positions refer to this vector, so a consumer
    /// can walk packages without re-consulting the pool.
    ///
    /// Selection that only needs the top chunks should read
    /// [`Self::chunks_by_feerate`] under the guard instead: this copy exists
    /// for consumers that need every entry with the lock released
    /// (`assemble_ordered_candidate` and the RPC mining handler).
    #[must_use]
    pub fn mining_snapshot(&self) -> MempoolMiningSnapshot {
        let order: Vec<EntryId> = self
            .derived
            .chunks
            .chunks_descending(self)
            .flat_map(|chunk| chunk.members.iter().copied())
            .collect();
        debug_assert_eq!(
            order.len(),
            self.entries.len(),
            "chunk index and entry arena disagree on the pool contents"
        );
        let position: HashMap<EntryId, u32> = order
            .iter()
            .enumerate()
            .filter_map(|(index, &id)| u32::try_from(index).ok().map(|slot| (id, slot)))
            .collect();
        let entries = order
            .iter()
            .map(|&id| {
                let Some(entry) = self.entry(id) else {
                    panic!("chunk index names a missing entry");
                };
                let ancestors = self
                    .ancestor_ids_for_entry(id)
                    .into_iter()
                    .filter_map(|ancestor| position.get(&ancestor).copied())
                    .collect();
                SnapshotEntry {
                    tx: Arc::clone(&entry.tx),
                    txid: entry.txid,
                    wtxid: entry.wtxid,
                    vsize: entry.vsize,
                    bip141_vsize: entry.bip141_vsize,
                    size: entry.size,
                    weight: entry.weight,
                    sigop_cost: entry.sigop_cost,
                    fee: entry.fee,
                    fee_delta: entry.fee_delta,
                    time: entry.time,
                    height: entry.height,
                    ancestor_size: entry.ancestor_size,
                    ancestor_fee: entry.ancestor_fee,
                    ancestor_fee_delta: entry.ancestor_fee_delta,
                    ancestors,
                }
            })
            .collect();
        MempoolMiningSnapshot {
            sequence: self.sequence_number(),
            fee_delta_sequence: self.fee_delta_sequence,
            entries,
        }
    }

    /// Walks the maintained chunks from the highest feerate to the lowest.
    /// The caller holds the pool read guard; every view borrows the pool, so
    /// nothing copies. Template selection and eviction read only this; the
    /// eviction order is the same walk reversed.
    pub fn chunks_by_feerate(&self) -> impl DoubleEndedIterator<Item = crate::ChunkView<'_>> + '_ {
        self.derived.chunks.chunks_descending(self)
    }

    /// Returns the maintained chunk index. Projection merges its untouched
    /// chunks with side-linearized pieces without copying the pool.
    pub(crate) fn chunk_index(&self) -> &ChunkIndex {
        &self.derived.chunks
    }

    /// Returns an entry by public id.
    #[must_use]
    pub fn entry(&self, id: EntryId) -> Option<&MempoolEntry> {
        self.entries.get(id)
    }

    /// Returns one chunk-index member borrowed from the entry arena. The
    /// index names only live entries; a missing id is a pool invariant
    /// violation. Mining selection resolves its copies through this while
    /// the caller holds the pool read guard.
    pub fn chunk_member(&self, id: EntryId) -> &MempoolEntry {
        self.entry(id).unwrap_or_else(|| {
            panic!("chunk index names entry {id} that left the pool");
        })
    }

    /// Returns the direct in-pool parents of one live entry, or an empty
    /// slice when the id is vacant.
    pub fn parents_of(&self, id: EntryId) -> &[EntryId] {
        self.links(id).map_or(&[], |links| links.parents.as_slice())
    }

    /// Walks every live entry in slab order.
    pub fn iter_entries(&self) -> impl Iterator<Item = &MempoolEntry> + '_ {
        self.entries.iter().map(|(_id, entry)| entry)
    }

    /// Pending local initial broadcasts with their current admission epochs.
    pub fn unbroadcast_transactions(&self) -> impl Iterator<Item = (Txid, Wtxid, u64)> + '_ {
        self.unbroadcast_transactions_after(None)
    }

    /// Pending local initial broadcasts strictly after `after`, in witness-id
    /// order, with their current admission epochs. Visits only indexed pending
    /// entries, so callers can bound work with `take` without rescanning a prefix.
    pub fn unbroadcast_transactions_after(
        &self,
        after: Option<Wtxid>,
    ) -> impl Iterator<Item = (Txid, Wtxid, u64)> + '_ {
        self.derived
            .unbroadcast
            .range((
                after.map_or(Bound::Unbounded, Bound::Excluded),
                Bound::Unbounded,
            ))
            .filter_map(|wtxid| {
                let entry = self.entry_by_wtxid(wtxid)?;
                let indexed = self.derived.by_txid.get(&entry.txid)?;
                Some((entry.txid, entry.wtxid, indexed.admitted_sequence))
            })
    }

    /// Projects complete connected families, walking each live graph entry once.
    pub(crate) fn iter_clusters(&self) -> impl Iterator<Item = Vec<&MempoolEntry>> + '_ {
        let mut visited = VisitSet::new();
        self.entries.iter().filter_map(move |(id, _)| {
            let id = EntryId::try_from(id).ok()?;
            if visited.test(id) {
                return None;
            }
            let mut members = Vec::new();
            self.collect_component_members(id, &mut visited, &mut members);
            Some(
                members
                    .into_iter()
                    .filter_map(|id| self.entry(id))
                    .collect(),
            )
        })
    }

    /// Returns one ascending `(fee_rate, total_vsize)` pair per distinct
    /// actual rate.
    pub fn fee_rate_histogram(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.derived
            .fee_rate_aggregates
            .iter()
            .map(|(&rate, aggregate)| (rate, aggregate.vsize))
    }

    /// Returns every in-pool entry that funds `script_hash`.
    pub fn entries_funding_script(
        &self,
        script_hash: ScriptHash,
    ) -> impl Iterator<Item = &MempoolEntry> + '_ {
        let entries = &self.entries;
        self.derived
            .funding
            .range((
                Bound::Included((script_hash, 0)),
                Bound::Included((script_hash, u32::MAX)),
            ))
            .filter_map(move |(_, id)| entries.get(*id))
    }

    /// Returns whether any in-pool transaction has `wtxid`.
    #[must_use]
    pub(crate) fn contains_wtxid(&self, wtxid: &Wtxid) -> bool {
        self.derived.by_wtxid.contains_key(wtxid)
    }

    /// Returns the in-pool entry for `wtxid`, or `None` if none matches.
    #[must_use]
    pub(crate) fn entry_by_wtxid(&self, wtxid: &Wtxid) -> Option<&MempoolEntry> {
        let id = *self.derived.by_wtxid.get(wtxid)?;
        self.entry(id)
    }

    /// Returns mempool entry ids in order of descending `fee_rate` (sat/kvB).
    ///
    /// Walks `entries` and sorts; cost O(N log N) per call. Actual-fee-ordered
    /// traversal without going through the chunk index (which ranks on signed
    /// modified fees with dependency-closed chunk scoring).
    #[cfg(test)]
    #[must_use]
    fn iter_by_fee_rate_desc(&self) -> Vec<EntryId> {
        let mut pairs: Vec<(u64, EntryId)> = self
            .entries
            .iter()
            .filter_map(|(index, entry)| {
                let id = EntryId::try_from(index).ok()?;
                Some((entry.fee_rate, id))
            })
            .collect();
        pairs.sort_by_key(|pair| core::cmp::Reverse(pair.0));
        pairs.into_iter().map(|(_, id)| id).collect()
    }

    /// Returns mempool entry ids whose `fee_rate` >= `threshold_sat_per_kvb`.
    ///
    /// Linear scan over `entries`: a fee-rate cohort without sorting.
    #[cfg(test)]
    #[must_use]
    fn iter_above_fee_rate(&self, threshold_sat_per_kvb: u64) -> Vec<EntryId> {
        self.entries
            .iter()
            .filter(|(_index, entry)| entry.fee_rate >= threshold_sat_per_kvb)
            .filter_map(|(index, _entry)| EntryId::try_from(index).ok())
            .collect()
    }

    /// Returns whether any in-pool transaction spends `outpoint`.
    #[must_use]
    pub fn is_outpoint_spent(&self, outpoint: &OutPoint) -> bool {
        self.derived
            .spending
            .range(outpoint_range(*outpoint))
            .next()
            .is_some()
    }

    /// Returns the in-pool spender of `outpoint`: the spending entry and the
    /// exact input (`vin`) of its transaction that spends it, or `None` when
    /// nothing in the pool spends it.
    pub fn outpoint_spender(
        &self,
        outpoint: OutPoint,
    ) -> Result<Option<OutpointSpender<'_>>, MempoolError> {
        let Some(&(_, id)) = self.derived.spending.range(outpoint_range(outpoint)).next() else {
            return Ok(None);
        };
        let entry = self
            .entry(id)
            .ok_or(MempoolError::InconsistentSpendingIndex)?;
        let vin = entry
            .tx
            .inputs
            .iter()
            .position(|input| input.previous_output == outpoint)
            .ok_or(MempoolError::InconsistentSpendingIndex)?;
        Ok(Some(OutpointSpender {
            entry,
            vin: u32::try_from(vin).unwrap_or(u32::MAX),
        }))
    }

    /// Adds `fee_delta` satoshis to `txid`'s signed mining-only fee overlay.
    pub fn prioritise(&mut self, txid: Txid, fee_delta: i64) -> Result<(), PrioritiseError> {
        if fee_delta == 0 {
            return Ok(());
        }
        let accumulated = self
            .fee_deltas
            .get(&txid)
            .copied()
            .unwrap_or(0)
            .checked_add(fee_delta)
            .ok_or(PrioritiseError::FeeDeltaOverflow)?;
        self.fee_delta_sequence = MutationSequence::advance(self.fee_delta_sequence);
        if accumulated == 0 {
            self.fee_deltas.remove(&txid);
        } else {
            self.fee_deltas.insert(txid, accumulated);
        }

        let Some(id) = self.entry_id_by_txid(&txid) else {
            return Ok(());
        };
        if let Some(entry) = self.entry_mut(id) {
            entry.fee_delta = accumulated;
        }

        let affected = self.metadata_closure(&[id]);
        self.refresh_metadata(&affected);
        // The overlay changes modified fees, so the entry's cluster
        // relinearizes from the entry itself. Component ids are exact on
        // merge and split, so the seed's component is the whole closure's.
        if let Some(component) = self.component_id(id) {
            self.relinearize_from_seed(component, id);
        }
        Ok(())
    }

    /// Returns every stored fee-delta overlay, including txids not in the pool.
    #[must_use]
    pub fn prioritised_transactions(&self) -> Vec<PrioritisedTransaction> {
        self.fee_deltas()
            .map(|(txid, fee_delta)| PrioritisedTransaction {
                txid,
                fee_delta,
                in_mempool: self.derived.by_txid.contains_key(&txid),
                modified_fee: self.entry_by_txid(&txid).map(MempoolEntry::modified_fee),
            })
            .collect()
    }

    /// Borrow the overlay for bounded snapshot capture without an unbounded copy.
    pub(crate) fn fee_deltas(&self) -> impl ExactSizeIterator<Item = (Txid, i64)> + '_ {
        self.fee_deltas.iter().map(|(&txid, &delta)| (txid, delta))
    }

    /// Reason-carrying core for composite mutations that remove an entry and
    /// all descendants that spend its outputs.
    fn remove_entry_and_descendants_into(
        &mut self,
        id: EntryId,
        reason: RemovalReason,
        changes: &mut Vec<MutationChange>,
    ) {
        let mut ids = Vec::new();
        self.collect_descendants(id, &mut ids, true);
        ids.sort_unstable();
        ids.dedup();
        let removals = ids.into_iter().map(|id| (id, reason)).collect::<Vec<_>>();
        self.remove_entries_with_reasons(&removals, changes);
    }

    /// Removes the entry identified by `txid` and its descendants with the
    /// supplied reason.
    #[cfg(any(test, feature = "test-seam"))]
    fn remove_by_txid_into(
        &mut self,
        txid: &Txid,
        reason: RemovalReason,
        changes: &mut Vec<MutationChange>,
    ) {
        let Some(id) = self.entry_id_by_txid(txid) else {
            return;
        };
        self.remove_entry_and_descendants_into(id, reason, changes);
    }

    /// Pure projection of every removal `block` would commit: resident block
    /// transactions as `BlockInclusion` plus their conflicts and full
    /// descendant subtrees as `Conflict`, deduplicated so each resident is
    /// planned at most once. Does not mutate pool state, allocate slab slots,
    /// or advance sequences.
    #[must_use]
    pub fn plan_block_removals(&self, block: &Block) -> BlockRemovalPlan {
        let txids = block.txids();
        let txs: Vec<&Tx> = block.txs.iter().collect();
        self.plan_block_removals_from_txs(&txs, &txids)
    }

    /// Shared planning core behind [`Self::plan_block_removals`] and
    /// [`Self::remove_for_block`]: one owner of block-inclusion and
    /// conflict-descendant semantics over the caller's aligned slices.
    fn plan_block_removals_from_txs(
        &self,
        block_txs: &[&Tx],
        block_txids: &[Txid],
    ) -> BlockRemovalPlan {
        assert_eq!(
            block_txs.len(),
            block_txids.len(),
            "block transactions and validated txids must stay aligned"
        );
        let mut planned: HashSet<EntryId> = HashSet::new();
        let mut removals: Vec<(EntryId, RemovalReason)> = Vec::new();
        for (tx, txid) in block_txs.iter().zip(block_txids) {
            if let Some(id) = self.entry_id_by_txid(txid) {
                if planned.insert(id) {
                    removals.push((id, RemovalReason::BlockInclusion));
                }
            }
            for root in self.conflicts_for(tx) {
                if planned.contains(&root) {
                    continue;
                }
                let mut subtree = Vec::new();
                self.collect_unplanned_descendants(root, &planned, &mut subtree);
                subtree.sort_unstable();
                for id in subtree {
                    if planned.insert(id) {
                        removals.push((id, RemovalReason::Conflict));
                    }
                }
            }
        }
        let mut seen_txids: HashSet<Txid> = HashSet::new();
        let mut fee_deltas_cleared = 0_u64;
        for txid in block_txids {
            if seen_txids.insert(*txid) && self.fee_deltas.contains_key(txid) {
                fee_deltas_cleared += 1;
            }
        }
        BlockRemovalPlan {
            removals,
            fee_deltas_cleared,
        }
    }

    /// Descendants of `root` through unplanned nodes only, `root` included.
    /// Planned nodes are treated as already retired: they are neither
    /// reported nor traversed, matching the pruned links the sequential
    /// removal would walk after retiring them.
    fn collect_unplanned_descendants(
        &self,
        root: EntryId,
        planned: &HashSet<EntryId>,
        out: &mut Vec<EntryId>,
    ) {
        if planned.contains(&root) {
            return;
        }
        let mut seen: HashSet<EntryId> = HashSet::new();
        seen.insert(root);
        out.push(root);
        let mut stack = alloc::vec![root];
        while let Some(current) = stack.pop() {
            let Some(links) = self.links(current) else {
                continue;
            };
            for &child in &links.children {
                if planned.contains(&child) {
                    continue;
                }
                if seen.insert(child) {
                    out.push(child);
                    stack.push(child);
                }
            }
        }
    }

    /// Yields all chunks in descending feerate order as if `plan` had applied.
    /// Untouched components are read from the maintained index; every touched
    /// component is partitioned into its surviving connected pieces and each
    /// piece is relinearized on the side with the exact solver and its own
    /// fresh equal-feerate prefix run. The pool is borrowed, never cloned,
    /// and left unchanged.
    #[must_use]
    pub fn chunks_after(&self, plan: &BlockRemovalPlan) -> ProjectedChunks<'_> {
        let mut planned: HashSet<EntryId> = HashSet::new();
        for (id, _) in &plan.removals {
            planned.insert(*id);
        }
        let mut confirmed: HashSet<EntryId> = HashSet::new();
        for (id, reason) in &plan.removals {
            if *reason == RemovalReason::BlockInclusion {
                confirmed.insert(*id);
            }
        }
        let mut touched: HashSet<u32> = HashSet::new();
        for (id, _) in &plan.removals {
            if let Some(component) = self.component_id(*id) {
                touched.insert(component);
            }
        }
        let mut pieces: Vec<ComponentState> = Vec::new();
        let mut synthetic = u32::MAX;
        let mut touched_ordered: Vec<u32> = touched.iter().copied().collect();
        touched_ordered.sort_unstable();
        for component in touched_ordered {
            let Some(members) = self.derived.chunks.members_of(component) else {
                continue;
            };
            let surviving: Vec<EntryId> = members
                .iter()
                .copied()
                .filter(|id| !planned.contains(id))
                .collect();
            if surviving.is_empty() {
                continue;
            }
            for piece in self.connected_pieces(&surviving, &planned) {
                let facts: Vec<MemberFacts<'_>> = piece
                    .iter()
                    .filter_map(|&id| {
                        let live = self.entries.slot(id)?;
                        Some(MemberFacts {
                            id,
                            entry: &live.entry,
                            parents: live.links.parents.as_slice(),
                        })
                    })
                    .collect();
                if facts.is_empty() {
                    continue;
                }
                let state = match facts.as_slice() {
                    [only] => ComponentState::singleton(synthetic, only),
                    _ => ComponentState::linearized(synthetic, &facts),
                };
                pieces.push(state);
                synthetic = synthetic.wrapping_sub(1);
            }
        }
        ProjectedChunks::new(self, confirmed, touched, pieces)
    }

    /// Partitions `surviving` members of one touched component into connected
    /// pieces over the surviving parent/child edges. Planned nodes are never
    /// traversed, so each piece is what the real removal would leave as one
    /// connected component with its own prefix run.
    fn connected_pieces(
        &self,
        surviving: &[EntryId],
        planned: &HashSet<EntryId>,
    ) -> Vec<Vec<EntryId>> {
        let present: HashSet<EntryId> = surviving.iter().copied().collect();
        let mut visited: HashSet<EntryId> = HashSet::new();
        let mut pieces = Vec::new();
        for &seed in surviving {
            if !visited.insert(seed) {
                continue;
            }
            let mut piece = alloc::vec![seed];
            let mut stack = alloc::vec![seed];
            while let Some(current) = stack.pop() {
                let Some(links) = self.links(current) else {
                    continue;
                };
                for &neighbour in links.parents.iter().chain(links.children.iter()) {
                    if planned.contains(&neighbour) {
                        continue;
                    }
                    if !present.contains(&neighbour) {
                        continue;
                    }
                    if visited.insert(neighbour) {
                        piece.push(neighbour);
                        stack.push(neighbour);
                    }
                }
            }
            pieces.push(piece);
        }
        pieces
    }

    /// Removes the transactions a connected block confirmed, clears their
    /// prioritisation overlays, and records the confirmations in the fee
    /// history. Every removed entry commits as one `Removed(BlockInclusion)`
    /// change, in commit order: block-transaction order, each removal
    /// committing parent before descendants.
    ///
    /// Core's `removeForBlock` postamble runs for every connected block, an
    /// empty removal included: the rolling floor is stamped at `now` and may
    /// decay again after the ten-second grace.
    pub fn remove_for_block(
        &mut self,
        block_txs: &[&Tx],
        block_txids: &[Txid],
        height: u32,
        now: u64,
    ) -> MutationResult {
        assert_eq!(
            block_txs.len(),
            block_txids.len(),
            "block transactions and validated txids must stay aligned"
        );
        self.estimator.block_connected(block_txids, height);

        let plan = self.plan_block_removals_from_txs(block_txs, block_txids);
        let mut changes = Vec::with_capacity(plan.removals.len());
        self.remove_entries_with_reasons(&plan.removals, &mut changes);
        for txid in block_txids {
            if self.fee_deltas.remove(txid).is_some() {
                self.fee_delta_sequence = MutationSequence::advance(self.fee_delta_sequence);
            }
        }
        self.rolling_min_fee.lock().note_block(now);
        self.finish_mutation(changes)
    }

    /// Whether any entry is older than the expiry window at `now`: its
    /// acceptance time is strictly below `now - MEMPOOL_EXPIRY_SECS`. An
    /// entry exactly at the cutoff has not expired, and an empty pool has
    /// nothing to expire. A read of the acceptance-time index's first key.
    #[must_use]
    pub fn has_expired_entries(&self, now: u64) -> bool {
        let cutoff = now.saturating_sub(MEMPOOL_EXPIRY_SECS);
        self.derived
            .by_time
            .first()
            .is_some_and(|&(time, _)| time < cutoff)
    }

    /// Core `Expire`: removes every entry accepted strictly before
    /// `now - MEMPOOL_EXPIRY_SECS` together with all its descendants, each
    /// exactly once, as one `Removed(Expiry)` batch in entry-id order. A
    /// descendant leaves with its expired ancestor even when it is newer.
    /// Nothing expired commits nothing and moves no sequence, so a repeated
    /// call at the same `now` is a no-op.
    pub fn expire(&mut self, now: u64) -> MutationResult {
        let removals: Vec<_> = self
            .expired_entry_ids(now)
            .into_iter()
            .map(|id| (id, RemovalReason::Expiry))
            .collect();
        let mut changes = Vec::with_capacity(removals.len());
        self.remove_entries_with_reasons(&removals, &mut changes);
        self.finish_mutation(changes)
    }

    pub(crate) fn expired_entry_ids(&self, now: u64) -> Vec<EntryId> {
        let cutoff = now.saturating_sub(MEMPOOL_EXPIRY_SECS);
        // Sparse marks: expiry usually visits a thin tail, and an
        // arena-sized bitset would zero-fill to the highest slot on a pool
        // whose churn left the slot space sparse.
        let mut visited: HashSet<EntryId> = HashSet::new();
        let mut stage = Vec::new();
        for &(_, root) in self.derived.by_time.range(..(cutoff, EntryId::MIN)) {
            self.stage_with_descendants(root, &mut visited, &mut stage);
        }
        stage.sort_unstable();
        stage
    }

    /// Appends `root` and every descendant not yet in `visited` to `stage`.
    /// One visited set serves the whole expiry pass, so a descendant shared
    /// by several expired ancestors is staged once and the pass stays linear
    /// in the entries it removes.
    fn stage_with_descendants(
        &self,
        root: EntryId,
        visited: &mut impl VisitMarks,
        stage: &mut Vec<EntryId>,
    ) {
        if !visited.insert(root) {
            return;
        }
        stage.push(root);
        let mut stack = vec![root];
        while let Some(current) = stack.pop() {
            let Some(links) = self.links(current) else {
                continue;
            };
            for &child in &links.children {
                if visited.insert(child) {
                    stage.push(child);
                    stack.push(child);
                }
            }
        }
    }

    /// Removes the entries named by `txids`, each with its descendants, as
    /// `Removed(Reorg)` changes in commit order.
    pub fn remove_for_reorg(&mut self, txids: &[Txid]) -> MutationResult {
        let mut changes = Vec::new();
        for txid in txids {
            if let Some(id) = self.entry_id_by_txid(txid) {
                self.remove_entry_and_descendants_into(id, RemovalReason::Reorg, &mut changes);
            }
        }
        self.finish_mutation(changes)
    }

    /// Removes every entry whose `fee_rate` (sat/kvB) is strictly below
    /// `threshold_sat_per_kvb`. Every evicted entry — and each descendant
    /// swept with it — commits as one `Removed(PolicyEviction)` change.
    ///
    /// Use this for min-relay-fee tightening or size-bound eviction policies.
    ///
    /// Test seam: fee-history fixture door; production trimming runs through
    /// `enforce_size_limit`'s chunk-ordered eviction.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn evict_below_fee_rate(&mut self, threshold_sat_per_kvb: u64) -> MutationResult {
        let mut to_evict: Vec<Txid> = Vec::new();
        for (_id, entry) in self.entries.iter() {
            if entry.fee_rate < threshold_sat_per_kvb {
                to_evict.push(entry.txid);
            }
        }

        let mut changes = Vec::with_capacity(to_evict.len());
        for txid in to_evict {
            self.remove_by_txid_into(&txid, RemovalReason::PolicyEviction, &mut changes);
        }
        self.finish_mutation(changes)
    }

    pub(crate) fn conflicts_for(&self, tx: &Tx) -> Vec<EntryId> {
        let mut conflicts = Vec::new();
        for input in &tx.inputs {
            for (_, id) in self
                .derived
                .spending
                .range(outpoint_range(input.previous_output))
            {
                conflicts.push(*id);
            }
        }
        conflicts.sort_unstable();
        conflicts.dedup();
        conflicts
    }

    pub(crate) fn descendants_of_conflicts(&self, direct: &[EntryId]) -> Vec<EntryId> {
        let mut conflicts = direct.to_vec();
        for &id in direct {
            self.collect_descendants(id, &mut conflicts, false);
        }
        conflicts.sort_unstable();
        conflicts.dedup();
        conflicts
    }

    /// Returns all ancestor entry ids for `id`, excluding `id` itself.
    #[must_use]
    pub fn ancestor_ids_for_entry(&self, id: EntryId) -> Vec<EntryId> {
        self.collect_ancestors(
            self.links(id)
                .map(|links| links.parents.clone())
                .unwrap_or_default(),
        )
    }

    /// The resident BIP331 ancestor package of `tip`: its unconfirmed
    /// ancestors then `tip`, parents before children. `None` when `tip` is not
    /// resident or the package would exceed [`MAX_PACKAGE_COUNT`](crate::standardness::MAX_PACKAGE_COUNT)
    /// transactions. The walk stops at the first excess member, so its work is
    /// bounded by the package limit and not by the cluster size.
    #[must_use]
    pub(crate) fn ancestor_package_wtxids(&self, tip: &Wtxid) -> Option<Vec<Wtxid>> {
        let tip_id = *self.derived.by_wtxid.get(tip)?;
        // Bounded by the package limit (at most 25 visited entries), not by
        // the arena: `VisitSet` would grow its bitset to the highest slot and
        // zero-fill arena-scale words for a walk that stops at 26 members.
        let mut seen = WalkSet::new();
        seen.insert(tip_id);
        let mut order = Vec::new();
        // Iterative post-order over the cached parent links: a node is emitted
        // after every parent, so the result is topological and ends at `tip`.
        let mut stack = vec![(tip_id, 0_usize)];
        while let Some(&(id, next)) = stack.last() {
            if let Some(&parent) = self.parents_of(id).get(next) {
                if let Some(frame) = stack.last_mut() {
                    frame.1 += 1;
                }
                if seen.insert(parent) {
                    if seen.len() > crate::standardness::MAX_PACKAGE_COUNT {
                        return None;
                    }
                    stack.push((parent, 0));
                }
            } else {
                order.push(id);
                stack.pop();
            }
        }
        order
            .into_iter()
            .map(|id| self.entry(id).map(|entry| entry.wtxid))
            .collect()
    }

    /// Returns all descendant entry ids for `id`, EXCLUDING `id` itself.
    #[must_use]
    pub fn descendant_ids_for_entry(&self, id: EntryId) -> Vec<EntryId> {
        let mut ids = Vec::new();
        self.collect_descendants(id, &mut ids, false);
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    pub(crate) fn remove_entries_with_reasons(
        &mut self,
        removals: &[(EntryId, RemovalReason)],
        changes: &mut Vec<MutationChange>,
    ) {
        let ids: Vec<EntryId> = removals.iter().map(|(id, _reason)| *id).collect();
        let affected = self.metadata_closure(&ids);
        let mut dirty_components: Vec<u32> = Vec::new();
        let mut dirty_seen: HashSet<u32> = HashSet::new();
        let mut survivor_seeds: Vec<EntryId> = Vec::new();
        let mut seen_seeds = VisitSet::new();
        for (id, reason) in removals {
            if !self.entries.contains(*id) {
                continue;
            }
            let Some(retired) = self.entries.remove(*id) else {
                continue;
            };
            let entry = retired.entry;
            // Core fires `mempool:removed` from `CTxMemPool::removeUnchecked`,
            // the pool-internal retire funnel, per entry as it leaves the
            // pool. `prepare` runs only while a consumer is attached.
            bitcoin_rs_consensus::trace::removed(|| {
                (
                    entry.txid.as_bytes().as_ptr(),
                    Self::core_removal_reason(*reason),
                    i32::try_from(entry.vsize).unwrap_or(i32::MAX),
                    i64::try_from(entry.fee).unwrap_or(i64::MAX),
                    entry.time,
                )
            });
            if let Some(summary) = self.component_summary_mut(retired.component) {
                summary.member_count = summary.member_count.saturating_sub(1);
                summary.weight = summary.weight.saturating_sub(entry.policy_weight());
                if dirty_seen.insert(retired.component) {
                    dirty_components.push(retired.component);
                }
            }
            for parent in &retired.links.parents {
                if let Some(slot) = self.entries.slot_mut(*parent) {
                    slot.links.children.retain(|child| child != id);
                }
                if seen_seeds.insert(*parent) {
                    survivor_seeds.push(*parent);
                }
            }
            for child in &retired.links.children {
                if let Some(slot) = self.entries.slot_mut(*child) {
                    slot.links.parents.retain(|parent| parent != id);
                }
                if seen_seeds.insert(*child) {
                    survivor_seeds.push(*child);
                }
            }
            self.derived.account_remove(*id, &entry);
            self.push_change(changes, entry.txid, MutationOutcome::Removed(*reason));
            self.estimator.tx_left(&entry.txid);
        }
        self.recompute_dirty_components(&survivor_seeds, &dirty_components);
        self.refresh_metadata(&affected);
    }

    /// Settles the components the removals disturbed, relinearizing every
    /// surviving piece. An emptied component's id is freed, which also drops
    /// its chunk keys. Otherwise the survivor seeds name each split piece:
    /// the first keeps the id, the rest take fresh ids, and every piece
    /// relinearizes. The settle runs before the metadata refresh because
    /// relinearization reads only entry fees, weights, txids, and links,
    /// never package totals.
    fn recompute_dirty_components(&mut self, seeds: &[EntryId], dirty: &[u32]) {
        for &component in dirty {
            let Some(summary) = self.component_summary_mut(component) else {
                continue;
            };
            if summary.member_count == 0 {
                self.free_component(component);
                continue;
            }
            *summary = ComponentSummary::default();
            // Components are closed under their links, so every piece of this
            // dirty component is reachable only from its own seeds: one
            // bounded visited set per component is enough.
            let mut visited = WalkSet::new();
            let mut pieces = Vec::new();
            for &seed in seeds {
                if !self.seed_starts_piece(component, seed, &visited) {
                    continue;
                }
                let mut members = Vec::new();
                self.collect_component_members(seed, &mut visited, &mut members);
                pieces.push(members);
            }
            // The first surviving piece keeps the dirty id; every later split
            // piece takes a fresh id. Each piece relinearizes once relabelled.
            let mut pieces = pieces.into_iter();
            if let Some(first) = pieces.next() {
                self.relabel_piece(&first, component);
                self.relinearize_members(component, &first);
            }
            for rest in pieces {
                let target = self.alloc_component();
                self.relabel_piece(&rest, target);
                self.relinearize_members(target, &rest);
            }
        }
    }

    /// Returns whether a survivor seed names an unclaimed piece of a dirty
    /// component: the seed is live, still carries the component id, and no
    /// earlier walk reached it.
    fn seed_starts_piece(&self, component: u32, seed: EntryId, visited: &WalkSet) -> bool {
        self.entries.contains(seed)
            && self.component_id(seed) == Some(component)
            && !visited.test(seed)
    }

    /// Writes a split piece's component id onto its members and rebuilds the
    /// id's summary from the same member list.
    fn relabel_piece(&mut self, members: &[EntryId], target: u32) {
        for member in members {
            if let Some(slot) = self.entries.slot_mut(*member) {
                slot.component = target;
            }
        }
        let rebuilt = ComponentSummary {
            member_count: u32::try_from(members.len()).unwrap_or(u32::MAX),
            weight: members.iter().fold(0_u64, |total, member| {
                total.saturating_add(self.entry(*member).map_or(0, MempoolEntry::policy_weight))
            }),
        };
        if let Some(slot) = self.component_summary_mut(target) {
            *slot = rebuilt;
        }
    }
    /// Recomputes one entry's six package totals directly from the spend
    /// graph.
    fn recompute_entry_totals(&mut self, id: EntryId) {
        let Some(entry) = self.entry(id) else {
            return;
        };
        let own_size = u64::from(entry.vsize);
        let own_fee = entry.fee;
        let own_delta = i128::from(entry.fee_delta);

        let own = (own_size, own_fee, own_delta);
        let (ancestor_size, ancestor_fee, ancestor_fee_delta) =
            self.package_totals(self.ancestor_ids_for_entry(id), own);
        let (descendant_size, descendant_fee, descendant_fee_delta) =
            self.package_totals(self.descendant_ids_for_entry(id), own);

        if let Some(entry) = self.entry_mut(id) {
            entry.ancestor_size = ancestor_size;
            entry.ancestor_fee = ancestor_fee;
            entry.ancestor_fee_delta = ancestor_fee_delta;
            entry.descendant_size = descendant_size;
            entry.descendant_fee = descendant_fee;
            entry.descendant_fee_delta = descendant_fee_delta;
        }
    }

    /// The vsize, fee, and fee-delta sums of `own` plus every live id.
    fn package_totals(&self, ids: Vec<EntryId>, own: (u64, u64, i128)) -> (u64, u64, i128) {
        ids.into_iter()
            .filter_map(|id| self.entry(id))
            .fold(own, |(size, fee, delta), entry| {
                (
                    size.saturating_add(u64::from(entry.vsize)),
                    fee.saturating_add(entry.fee),
                    delta.saturating_add(i128::from(entry.fee_delta)),
                )
            })
    }

    /// Every entry whose totals a change at `seeds` can have altered. The
    /// returned order is deterministic (seed order, ancestors before the
    /// seed before descendants); the set alongside it keeps the membership
    /// probe constant-time when a batched removal touches many components.
    fn metadata_closure(&self, seeds: &[EntryId]) -> Vec<EntryId> {
        let mut affected = Vec::new();
        let mut seen: HashSet<EntryId> = HashSet::new();
        for seed in seeds {
            for id in self
                .ancestor_ids_for_entry(*seed)
                .into_iter()
                .chain(core::iter::once(*seed))
                .chain(self.descendant_ids_for_entry(*seed))
            {
                if seen.insert(id) {
                    affected.push(id);
                }
            }
        }
        affected
    }

    /// Recomputes package totals for `affected` only. The chunk order is not
    /// touched here: inserts relinearize from the new entry, removals settle
    /// and relinearize every split piece, and fee overlays relinearize the
    /// touched entry's cluster.
    fn refresh_metadata(&mut self, affected: &[EntryId]) {
        for id in affected {
            self.recompute_entry_totals(*id);
        }
    }

    /// Relinearizes the component holding `seed` from that entry's own walk,
    /// so member discovery touches only the cluster, never the whole arena.
    /// A one-member component's walk yields exactly the seed, so its facts
    /// are built directly with no walk and no member or fact vectors; the
    /// index content is identical. The seed is live at both call sites; a
    /// dead seed forgets, as the filtered walk would.
    fn relinearize_from_seed(&mut self, component: u32, seed: EntryId) {
        if self
            .component_summary(component)
            .is_some_and(|summary| summary.member_count == 1)
        {
            let entries = &self.entries;
            let Some(live) = entries.slot(seed) else {
                self.derived.chunks.forget(component);
                return;
            };
            let fact = MemberFacts {
                id: seed,
                entry: &live.entry,
                parents: &live.links.parents,
            };
            self.derived
                .chunks
                .relinearize(component, core::slice::from_ref(&fact));
            return;
        }
        let mut members = Vec::new();
        self.collect_component_members(seed, &mut WalkSet::new(), &mut members);
        self.relinearize_members(component, &members);
    }

    /// Stores one component's freshly walked members in the chunk index,
    /// borrowing entry facts and parent links straight from the arena. The
    /// borrow splits `entries` from `derived` up front, so the index write
    /// never aliases the facts it reads. Members that left the pool mid-walk
    /// are skipped; an empty survivor list forgets the component.
    fn relinearize_members(&mut self, component: u32, members: &[EntryId]) {
        let entries = &self.entries;
        let facts = members
            .iter()
            .filter_map(|&id| {
                let live = entries.slot(id)?;
                Some(MemberFacts {
                    id,
                    entry: &live.entry,
                    parents: &live.links.parents,
                })
            })
            .collect::<Vec<_>>();
        self.derived.chunks.relinearize(component, &facts);
    }

    /// Rebuilds every entry's package totals and the whole priority index.
    #[cfg(test)]
    fn recompute_all_metadata(&mut self) {
        let ids = self
            .entries
            .iter()
            .filter_map(|(index, _)| EntryId::try_from(index).ok())
            .collect::<Vec<_>>();
        for id in &ids {
            let ancestors = self.ancestor_ids_for_entry(*id);
            let mut ancestor_size = self.entry(*id).map_or(0, |entry| u64::from(entry.vsize));
            let mut ancestor_fee = self.entry(*id).map_or(0, |entry| entry.fee);
            let mut ancestor_fee_delta = self
                .entry(*id)
                .map_or(0, |entry| i128::from(entry.fee_delta));
            for ancestor in ancestors {
                if let Some(entry) = self.entry(ancestor) {
                    ancestor_size = ancestor_size.saturating_add(u64::from(entry.vsize));
                    ancestor_fee = ancestor_fee.saturating_add(entry.fee);
                    ancestor_fee_delta =
                        ancestor_fee_delta.saturating_add(i128::from(entry.fee_delta));
                }
            }
            if let Some(entry) = self.entry_mut(*id) {
                entry.ancestor_size = ancestor_size;
                entry.ancestor_fee = ancestor_fee;
                entry.ancestor_fee_delta = ancestor_fee_delta;
                entry.descendant_size = u64::from(entry.vsize);
                entry.descendant_fee = entry.fee;
                entry.descendant_fee_delta = i128::from(entry.fee_delta);
            }
        }

        for id in &ids {
            let Some(entry) = self.entry(*id) else {
                continue;
            };
            let size = u64::from(entry.vsize);
            let fee = entry.fee;
            let fee_delta = i128::from(entry.fee_delta);
            for ancestor in self.ancestor_ids_for_entry(*id) {
                if let Some(ancestor_entry) = self.entry_mut(ancestor) {
                    ancestor_entry.descendant_size =
                        ancestor_entry.descendant_size.saturating_add(size);
                    ancestor_entry.descendant_fee =
                        ancestor_entry.descendant_fee.saturating_add(fee);
                    ancestor_entry.descendant_fee_delta = ancestor_entry
                        .descendant_fee_delta
                        .saturating_add(fee_delta);
                }
            }
        }

        // Test oracle: rebuild the chunk index from scratch over every
        // component, so incremental maintenance has a from-scratch reference.
        // The walks finish before any index write, so the arena borrow is
        // not held across `relinearize_members`.
        self.derived.chunks = ChunkIndex::default();
        let mut components = Vec::new();
        let mut seen = VisitSet::new();
        for (index, _live) in self.entries.iter() {
            let Ok(id) = EntryId::try_from(index) else {
                continue;
            };
            // The walk inserts its seed and returns empty when an earlier
            // walk already reached it, so no separate membership test.
            let mut members = Vec::new();
            self.collect_component_members(id, &mut seen, &mut members);
            if members.is_empty() {
                continue;
            }
            if let Some(component) = self.component_id(id) {
                components.push((component, members));
            }
        }
        for (component, members) in components {
            self.relinearize_members(component, &members);
        }
    }

    /// Returns every entry reachable from `seeds` through spend edges in
    /// either direction: the union of the connected components they sit in.
    fn cluster_ids_seeded_by(
        &self,
        seeds: &[EntryId],
        excluded: &HashSet<EntryId>,
    ) -> Vec<EntryId> {
        let mut seen = VisitSet::new();
        let mut frontier: Vec<EntryId> = Vec::new();
        for seed in seeds {
            if !excluded.contains(seed) && seen.insert(*seed) {
                frontier.push(*seed);
            }
        }
        while let Some(id) = frontier.pop() {
            self.graph_steps.fetch_add(1, Ordering::Relaxed);
            let Some(links) = self.links(id) else {
                continue;
            };
            for neighbour in links.parents.iter().chain(links.children.iter()).copied() {
                if !excluded.contains(&neighbour) && seen.insert(neighbour) {
                    frontier.push(neighbour);
                }
            }
        }
        let mut cluster = seen.members().to_vec();
        cluster.sort_unstable();
        cluster
    }

    /// Refuses a transaction that would join a cluster over either limit.
    fn check_cluster_limits(
        &self,
        tx: &Tx,
        weight: u64,
        excluded: &HashSet<EntryId>,
    ) -> Result<(), PolicyError> {
        if excluded.is_empty() {
            let cached = self.check_cluster_limits_cached(tx, weight);
            debug_assert_eq!(
                self.check_cluster_limits_by_walk(tx, weight, excluded),
                cached
            );
            cached
        } else {
            self.check_cluster_limits_by_walk(tx, weight, excluded)
        }
    }

    /// The component-cache path: two numbers per joined component.
    fn check_cluster_limits_cached(&self, tx: &Tx, weight: u64) -> Result<(), PolicyError> {
        let txid = tx.txid();
        let parents = self.in_pool_parents(tx);
        let neighbours = parents.iter().copied().chain(self.in_pool_children(txid));
        let mut count = 1_u32;
        let mut total = weight;
        let mut merged: Vec<u32> = Vec::new();
        for neighbour in neighbours {
            let Some(component) = self.component_id(neighbour) else {
                continue;
            };
            if merged.contains(&component) {
                continue;
            }
            merged.push(component);
            let summary = self
                .component_summary(component)
                .copied()
                .unwrap_or_default();
            count = count.saturating_add(summary.member_count);
            total = total.saturating_add(summary.weight);
        }
        cluster_within_limits(count, total, &self.limits)
    }

    /// The walk path: authoritative when a replacement excludes entries.
    fn check_cluster_limits_by_walk(
        &self,
        tx: &Tx,
        weight: u64,
        excluded: &HashSet<EntryId>,
    ) -> Result<(), PolicyError> {
        let txid = tx.txid();
        let mut seeds = tx
            .inputs
            .iter()
            .filter_map(|input| self.entry_id_by_txid(&input.previous_output.txid))
            .collect::<Vec<_>>();
        seeds.extend(self.in_pool_children(txid));
        let cluster = self.cluster_ids_seeded_by(&seeds, excluded);
        if cluster.is_empty() {
            return cluster_within_limits(1, weight, &self.limits);
        }
        let count = u32::try_from(cluster.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let cluster_weight = cluster.iter().fold(weight, |total, id| {
            total.saturating_add(self.entry(*id).map_or(0, MempoolEntry::policy_weight))
        });
        cluster_within_limits(count, cluster_weight, &self.limits)
    }

    /// The cluster limits this pool enforces at admission.
    ///
    /// Test seam: `getmempoolinfo` reads the same `limits` through
    /// `policy_snapshot`, so these report enforced policy, not a constant.
    #[cfg(test)]
    #[must_use]
    const fn cluster_limits(&self) -> (u32, u64) {
        (self.limits.cluster_count, self.limits.cluster_size_vbytes)
    }

    fn ancestor_ids_for_tx(&self, tx: &Tx) -> Vec<EntryId> {
        // For a candidate that has no entry yet: resolve its direct parents
        // through the txid index, then walk the cached links like any entry.
        self.collect_ancestors(self.in_pool_parents(tx))
    }

    /// Transitive in-pool ancestors of `seeds`, deduplicated and in `EntryId`
    /// order. Iterative over the cached parent links, so depth follows
    /// membership, not the recursion stack.
    fn collect_ancestors(&self, seeds: Vec<EntryId>) -> Vec<EntryId> {
        let mut seen = VisitSet::new();
        let mut stack = seeds;
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(links) = self.links(id) {
                stack.extend_from_slice(&links.parents);
            }
        }
        let mut ancestors = seen.members().to_vec();
        ancestors.sort_unstable();
        ancestors
    }

    /// Descendants of `id` appended to `out`, including `id` itself when
    /// `include_root` holds, and skipping anything already in `out`.
    /// Iterative over the child links, so depth follows membership, not
    /// the recursion stack.
    fn collect_descendants(&self, id: EntryId, out: &mut Vec<EntryId>, include_root: bool) {
        let mut seen = VisitSet::new();
        for existing in out.iter() {
            seen.insert(*existing);
        }
        let fresh = seen.insert(id);
        if include_root && fresh {
            out.push(id);
        }
        let mut stack = vec![id];
        while let Some(current) = stack.pop() {
            let Some(links) = self.links(current) else {
                continue;
            };
            for child in links.children.iter().copied() {
                if seen.insert(child) {
                    out.push(child);
                    stack.push(child);
                }
            }
        }
    }

    /// Returns the txids of in-pool transactions whose inputs reference `id`,
    /// in `EntryId` order and deduplicated.
    #[must_use]
    pub fn spender_txids(&self, id: EntryId) -> Vec<Txid> {
        let Some(links) = self.links(id) else {
            return Vec::new();
        };
        links
            .children
            .iter()
            .filter_map(|child| self.entry(*child).map(|entry| entry.txid))
            .collect()
    }

    /// Returns the descendant-package count for `id` (inclusive of `id`
    /// itself), saturating at `u32::MAX`.
    #[must_use]
    pub fn descendant_count_inclusive(&self, id: EntryId) -> u32 {
        let mut descendants = Vec::new();
        self.collect_descendants(id, &mut descendants, true);
        u32::try_from(descendants.len()).unwrap_or(u32::MAX)
    }

    /// Returns the ancestor-package count for `id` (inclusive of `id` itself).
    #[must_use]
    pub fn ancestor_count_inclusive(&self, id: EntryId) -> u32 {
        let ancestors = self.ancestor_ids_for_entry(id);
        u32::try_from(ancestors.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1)
    }

    fn entry_mut(&mut self, id: EntryId) -> Option<&mut MempoolEntry> {
        self.entries.get_mut(id)
    }
}

/// Spending-index key over the raw 36-byte `OutPoint` consensus encoding.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SpendingKey([u8; 36]);

impl From<OutPoint> for SpendingKey {
    fn from(outpoint: OutPoint) -> Self {
        let mut key = [0_u8; 36];
        key[..32].copy_from_slice(outpoint.txid.as_bytes());
        key[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
        Self(key)
    }
}

/// Applies both cluster limits to a candidate cluster's count and vsize.
const fn cluster_within_limits(
    count: u32,
    weight: u64,
    limits: &MempoolLimits,
) -> Result<(), PolicyError> {
    if count > limits.cluster_count {
        return Err(PolicyError::ClusterCountLimit);
    }
    let Some(limit_weight) = limits.cluster_size_vbytes.checked_mul(4) else {
        return Err(PolicyError::ClusterSizeLimit);
    };
    if weight > limit_weight {
        return Err(PolicyError::ClusterSizeLimit);
    }
    Ok(())
}

/// Heap a single transaction owns, beyond the `Tx` struct itself.
///
/// Every byte buffer is charged at capacity, like Core's
/// `RecursiveDynamicUsage`, so reserved-but-unfilled allocation still counts
/// against the retained-memory gate.
pub(crate) fn transaction_heap_usage(tx: &Tx) -> u64 {
    use core::mem::size_of;

    let mut total = u64::try_from(size_of::<Tx>()).unwrap_or(0);
    total = total.saturating_add(
        u64::try_from(tx.inputs.capacity().saturating_mul(size_of::<TxIn>())).unwrap_or(u64::MAX),
    );
    total = total.saturating_add(
        u64::try_from(tx.outputs.capacity().saturating_mul(size_of::<TxOut>())).unwrap_or(u64::MAX),
    );
    for input in &tx.inputs {
        total =
            total.saturating_add(u64::try_from(input.script_sig.capacity()).unwrap_or(u64::MAX));
        total = total.saturating_add(
            u64::try_from(
                input
                    .witness
                    .capacity()
                    .saturating_mul(size_of::<Vec<u8>>())
                    .saturating_add(
                        input
                            .witness
                            .iter()
                            .map(std::vec::Vec::capacity)
                            .sum::<usize>(),
                    ),
            )
            .unwrap_or(u64::MAX),
        );
    }
    for output in &tx.outputs {
        total = total
            .saturating_add(u64::try_from(output.script_pubkey.capacity()).unwrap_or(u64::MAX));
    }
    total
}

/// Heap a decoded package owns.
///
/// Every member's `transaction_heap_usage` (which already charges the
/// member's own outer slot) plus the spare outer slots,
/// `txs.capacity() - txs.len()`, of the vector holding them. Wire-frame bytes
/// are never counted here.
#[must_use]
pub fn package_heap_usage(txs: &[Tx], spare_slots: usize) -> u64 {
    let spare =
        u64::try_from(spare_slots.saturating_mul(core::mem::size_of::<Tx>())).unwrap_or(u64::MAX);
    txs.iter().fold(spare, |total, tx| {
        total.saturating_add(transaction_heap_usage(tx))
    })
}

fn outpoint_range(outpoint: OutPoint) -> RangeInclusive<(SpendingKey, EntryId)> {
    let key = SpendingKey::from(outpoint);
    (key, EntryId::MIN)..=(key, EntryId::MAX)
}

#[cfg(test)]
fn txid_of(bytes: [u8; 32]) -> Txid {
    Txid::from(bitcoin_rs_primitives::Hash256::from_le_bytes(&bytes))
}
#[cfg(test)]
mod package_tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn linked(inputs: &[OutPoint], outputs: u32, tag: u64) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: inputs
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: (0..outputs)
                .map(|vout| TxOut {
                    value: Amount::from_sat(10_000 + u64::from(vout) + tag * 1_000),
                    script_pubkey: vec![0x51].into(),
                })
                .collect(),
        }
    }

    fn resident(pool: &mut Mempool, tx: &Tx) -> Result<(), MempoolError> {
        let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 10_000, 1, 7, 0);
        pool.insert_entry(entry).map(|_id| ())
    }

    #[test]
    fn ancestor_package_is_topological_ends_at_the_tip_and_holds_only_residents() -> TestResult {
        let confirmed = OutPoint::new(txid_of([3; 32]), 0);
        let root = linked(&[confirmed], 2, 1);
        let left = linked(&[OutPoint::new(root.txid(), 0)], 1, 2);
        let right = linked(&[OutPoint::new(root.txid(), 1)], 1, 3);
        let tip = linked(
            &[
                OutPoint::new(left.txid(), 0),
                OutPoint::new(right.txid(), 0),
            ],
            1,
            4,
        );
        let unrelated = linked(&[OutPoint::new(txid_of([4; 32]), 0)], 1, 5);
        let mut pool = Mempool::new(MempoolLimits::default());
        for tx in [&root, &left, &right, &tip, &unrelated] {
            resident(&mut pool, tx)?;
        }

        let package = pool
            .ancestor_package_wtxids(&tip.wtxid())
            .ok_or("the tip is resident")?;
        assert_eq!(package.len(), 4);
        assert_eq!(package.first(), Some(&root.wtxid()));
        assert_eq!(package.last(), Some(&tip.wtxid()));
        assert!(package.contains(&left.wtxid()) && package.contains(&right.wtxid()));
        assert_eq!(
            pool.ancestor_package_wtxids(&left.wtxid()),
            Some(vec![root.wtxid(), left.wtxid()])
        );
        assert_eq!(
            pool.ancestor_package_wtxids(&root.wtxid()),
            Some(vec![root.wtxid()])
        );
        assert_eq!(
            pool.ancestor_package_wtxids(&unrelated.wtxid()),
            Some(vec![unrelated.wtxid()])
        );
        let absent = linked(&[confirmed], 1, 9);
        assert_eq!(pool.ancestor_package_wtxids(&absent.wtxid()), None);
        Ok(())
    }

    #[test]
    fn ancestor_package_stops_at_the_package_count_bound() -> TestResult {
        let count = crate::standardness::MAX_PACKAGE_COUNT;
        let mut pool = Mempool::new(MempoolLimits::default());
        let mut chain: Vec<Tx> = Vec::new();
        for tag in 0..=count {
            let input = chain.last().map_or_else(
                || OutPoint::new(txid_of([5; 32]), 0),
                |previous| OutPoint::new(previous.txid(), 0),
            );
            let tx = linked(&[input], 1, u64::try_from(tag)?);
            resident(&mut pool, &tx)?;
            chain.push(tx);
        }
        assert_eq!(chain.len(), count + 1);
        let at_bound = chain.get(count - 1).ok_or("chain reaches the bound")?;
        let past_bound = chain.get(count).ok_or("chain exceeds the bound")?;
        assert_eq!(
            pool.ancestor_package_wtxids(&at_bound.wtxid())
                .map(|served| served.len()),
            Some(count)
        );
        assert_eq!(pool.ancestor_package_wtxids(&past_bound.wtxid()), None);
        Ok(())
    }

    #[test]
    fn package_walk_stays_bounded_by_visited_entries() -> TestResult {
        // The ancestor-package walk stops at the package bound, so its visited
        // set must hold at most `MAX_PACKAGE_COUNT` entries inline rather than
        // a bitset sized to the highest arena slot.
        let mut seen = WalkSet::new();
        for tag in 0..crate::standardness::MAX_PACKAGE_COUNT {
            let id = EntryId::try_from(u32::try_from(tag)?)?;
            assert!(seen.insert(id), "distinct ids insert once");
            assert!(!seen.insert(id), "reinserting is a no-op");
        }
        assert_eq!(seen.len(), crate::standardness::MAX_PACKAGE_COUNT);
        Ok(())
    }

    #[test]
    fn package_heap_usage_is_member_usage_plus_spare_outer_slots() -> TestResult {
        let first = linked(&[OutPoint::new(txid_of([6; 32]), 0)], 1, 1);
        let second = linked(&[OutPoint::new(txid_of([7; 32]), 0)], 3, 2);
        let mut txs: Vec<Tx> = Vec::with_capacity(5);
        txs.push(first);
        txs.push(second);
        let members = transaction_heap_usage(&txs[0]) + transaction_heap_usage(&txs[1]);
        let slot = u64::try_from(core::mem::size_of::<Tx>())?;
        let spare = txs.capacity() - txs.len();

        assert_eq!(package_heap_usage(&txs, 0), members);
        assert_eq!(
            package_heap_usage(&txs, spare),
            members + slot * u64::try_from(spare)?
        );
        assert_eq!(package_heap_usage(&[], 0), 0);
        assert_eq!(
            package_heap_usage(&[], usize::MAX),
            u64::try_from(usize::MAX)?
        );
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;

#[cfg(test)]
#[expect(clippy::expect_used)]
mod spend_index_tests;

#[cfg(test)]
mod dynamic_memory_usage_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut};

    use super::*;

    fn tx_with(script_len: usize, tag: u8) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: alloc::vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[tag; 32])), 0,),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: alloc::vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: alloc::vec![0x51; script_len].into(),
            }],
        }
    }

    fn pool_with(count: u8, script_len: usize) -> Mempool {
        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            ..MempoolLimits::default()
        });
        for tag in 0..count {
            let entry = MempoolEntry::new(Arc::new(tx_with(script_len, tag)), 100, 10_000, 1, 7, 0);
            let Ok(_id) = pool.insert_entry(entry) else {
                panic!("fixture insert failed");
            };
        }
        pool
    }

    #[test]
    fn usage_is_a_different_quantity_from_the_vsize_sum() {
        let pool = pool_with(4, 64);
        let stats = pool.stats();
        let usage = pool.dynamic_memory_usage();

        assert!(usage > 0);
        assert_ne!(
            usage, stats.bytes,
            "reporting `usage` as the vsize sum is the defect this replaces"
        );
        assert!(
            usage > stats.bytes,
            "holding a transaction costs more than its virtual size: {usage} vs {}",
            stats.bytes
        );
    }

    #[test]
    fn usage_grows_with_the_transactions_it_holds() {
        let small = pool_with(4, 64).dynamic_memory_usage();
        let more_entries = pool_with(8, 64).dynamic_memory_usage();
        let bigger_scripts = pool_with(4, 4_096).dynamic_memory_usage();

        assert!(more_entries > small, "{more_entries} vs {small}");
        assert!(
            bigger_scripts > small,
            "script bytes are held too: {bigger_scripts} vs {small}"
        );
    }

    /// Clearing releases the payload. It does not release the arena.
    #[test]
    fn usage_falls_when_the_pool_is_cleared() {
        let mut pool = pool_with(4, 64);
        let before = pool.dynamic_memory_usage();
        pool.clear();
        let after = pool.dynamic_memory_usage();
        assert!(after < before, "{after} vs {before}");
    }

    /// A grown-then-emptied pool still holds its arena, and still says so.
    #[test]
    fn the_arena_is_charged_after_the_pool_is_cleared() {
        use core::mem::size_of;

        let mut pool = pool_with(64, 64);
        pool.clear();

        let capacity = u64::try_from(pool.entries.capacity()).unwrap_or(0);
        assert!(
            capacity > 0,
            "the fixture must leave a grown arena behind, or this proves nothing"
        );
        let arena =
            capacity.saturating_mul(u64::try_from(size_of::<Option<LiveEntry>>()).unwrap_or(0));
        let cleared = pool.dynamic_memory_usage();
        assert_eq!(
            cleared, arena,
            "a cleared pool must report its arena and nothing else: {cleared} vs {arena}"
        );

        let fresh = Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            ..MempoolLimits::default()
        })
        .dynamic_memory_usage();
        assert_eq!(fresh, 0, "a pool that never grew holds nothing");
        assert!(
            cleared > fresh,
            "a drained pool and a fresh one must not report the same footprint"
        );
    }

    /// The chunk index is charged for its keys and component states.
    #[test]
    fn the_chunk_index_is_charged_for_what_it_holds() {
        const COUNT: u64 = 32;

        let mut pool = pool_with(u8::try_from(COUNT).unwrap_or(0), 64);
        let index = pool.derived.chunks.dynamic_memory_usage();
        assert!(index > 0, "a populated index must report a nonzero cost");

        let with_index = pool.dynamic_memory_usage();
        pool.derived.chunks = ChunkIndex::default();
        let without_index = pool.dynamic_memory_usage();
        assert_eq!(
            with_index.saturating_sub(without_index),
            index,
            "the pool must charge the index what the index says it costs"
        );
    }

    #[test]
    fn usage_accounts_the_acceptance_time_index() {
        use core::mem::size_of;

        let mut pool = pool_with(4, 64);
        let with_index = pool.dynamic_memory_usage();
        pool.derived.by_time.clear();
        let without_index = pool.dynamic_memory_usage();
        assert_eq!(
            with_index.saturating_sub(without_index),
            4_u64.saturating_mul(u64::try_from(size_of::<(u64, EntryId)>()).unwrap_or(0)),
            "the pool must charge one acceptance-time entry per pooled transaction"
        );
    }
}

#[cfg(test)]
mod entry_overhead_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_primitives::Tx;

    use super::*;

    /// A transaction that owns no heap of its own: no inputs, no outputs, so
    /// `transaction_heap_usage` is just the struct. What is left in the estimate
    /// for a pool of these is the per-entry accounting, which is what this pins.
    fn empty_tx(tag: u32) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::from_consensus(tag),
            inputs: alloc::vec::Vec::new(),
            outputs: alloc::vec::Vec::new(),
        }
    }

    #[test]
    fn usage_counts_the_entry_itself_not_only_the_transaction() {
        use core::mem::size_of;

        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            ..MempoolLimits::default()
        });
        let count = 8_u32;
        for tag in 0..count {
            let entry = MempoolEntry::new(Arc::new(empty_tx(tag)), 100, 10_000, 1, 7, 0);
            let Ok(_id) = pool.insert_entry(entry) else {
                panic!("fixture insert failed");
            };
        }

        let live = u64::from(count);
        let entry_bytes = u64::try_from(size_of::<MempoolEntry>()).unwrap_or(0);
        let tx_bytes = u64::try_from(size_of::<Tx>()).unwrap_or(0);

        assert!(
            pool.dynamic_memory_usage()
                >= live.saturating_mul(entry_bytes.saturating_add(tx_bytes)),
            "usage {} is below {live} entries of {entry_bytes} plus their transactions",
            pool.dynamic_memory_usage()
        );
    }
}

/// Fixtures for the #638 graph contracts: dependency and conflict
/// relationships stay exact across every mutation kind, component merges and
/// splits match an independent reference calculation, recycled entry ids
/// never resolve to a stale resident, cluster limits hold before a mutation
/// commits, and walk work stays local to the affected cluster.
#[cfg(test)]
#[expect(clippy::expect_used)]
mod graph_tests;
