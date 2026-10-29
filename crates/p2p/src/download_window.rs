//! Block download window, peer-assignment, stall, and scheduling policy.
//!
//! This module owns the download-side policy that decides which blocks to
//! request from which peers, how to detect and recover from stalls, and how
//! to manage the in-flight window budget. `crate::BlockStager` owns the
//! matching inbound staging set. The node sync coordinator drives these
//! types; it does not own the policy.

use std::time::{Duration, Instant};

use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use hashbrown::{HashMap, HashSet};
use smallvec::SmallVec;

use crate::BlockStager;
use crate::connection::PeerSource;

mod policy;

pub use policy::*;

#[derive(Clone, Copy, Debug)]
#[expect(missing_docs)]
pub struct SyncBudget {
    pub max_pending_blocks: usize,
    pub max_pending_bytes: usize,
    pub max_received_blocks: usize,
    pub max_received_bytes: usize,
    pub max_peer_inflight: usize,
    pub fanout_peer_inflight: usize,
    pub min_peers_for_fanout: usize,
    pub getdata_batch_limit: usize,
    /// The network's proof-of-work target spacing (Core's nPowTargetSpacing):
    /// the unit of the per-owner block-download budget,
    /// `block_spacing / 2 * (BASE + PER_PEER * other)`, where `other`
    /// counts the other owners with validated in-flight blocks, with the
    /// two Core constants expressed in half-spacing units.
    pub block_spacing: Duration,
    /// When `Some`, every owner expires at this fixed age instead of the
    /// spacing-derived per-owner budget. The slot is compiled only into
    /// test builds; production budgets never carry it.
    #[cfg(test)]
    pub(crate) pending_timeout_override: Option<Duration>,
    pub received_timeout: Duration,
    pub stall_timeout_initial: Duration,
    pub stall_timeout_max: Duration,
    pub staller_cooldown: Duration,
}

impl SyncBudget {
    /// Sets the fixed timeout used by tests; production budgets cannot carry it.
    /// INVARIANT: production never populates `pending_timeout_override`.
    #[cfg(test)]
    pub(crate) fn with_pending_timeout_override(mut self, timeout: Duration) -> Self {
        self.pending_timeout_override = Some(timeout);
        self
    }
}

/// A batch of block requests prepared for a single peer.
#[derive(Clone, Debug)]
pub(crate) struct PeerRequest {
    owner: PeerSource,
    entries: Vec<PeerRequestEntry>,
    next_request_height: u32,
}

impl PeerRequest {
    /// Returns the exact connection this request is directed to.
    pub(crate) fn owner(&self) -> PeerSource {
        self.owner
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = (u32, Hash256)> + '_ {
        self.entries.iter().map(|entry| (entry.height, entry.hash))
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Per-peer availability view for one request build.
///
/// `is_refused` names the bodies this peer answered `notfound` for; the scan
/// records the lowest such height so the batch pins the cursor there instead
/// of dropping the whole batch. Grouping the predicate with its pin keeps the
/// scan helpers to one added parameter.
pub(crate) struct RefusalFilter<'a> {
    is_refused: &'a dyn Fn(Hash256) -> bool,
    min_refused: Option<u32>,
}

impl<'a> RefusalFilter<'a> {
    pub(crate) fn new(is_refused: &'a dyn Fn(Hash256) -> bool) -> Self {
        Self {
            is_refused,
            min_refused: None,
        }
    }

    /// Whether `hash` stays in this peer's batch. A refused body is dropped
    /// and its height contends for the cursor pin.
    pub(crate) fn keep(&mut self, hash: Hash256, height: u32) -> bool {
        if (self.is_refused)(hash) {
            self.min_refused = Some(self.min_refused.map_or(height, |floor| floor.min(height)));
            false
        } else {
            true
        }
    }

    pub(crate) fn min_refused(&self) -> Option<u32> {
        self.min_refused
    }
}

#[derive(Clone, Copy, Debug)]
struct PeerRequestEntry {
    hash: Hash256,
    height: u32,
}

#[derive(Clone, Copy, Debug)]
struct RequestScan {
    height: u32,
    request_tip_height: u32,
    remaining_limit: usize,
    next_request_height: u32,
}

enum SelectedHashes {
    Inline(SmallVec<[Hash256; 4]>),
    Set(HashSet<Hash256>),
}

impl SelectedHashes {
    fn from_entries(entries: &[PeerRequestEntry]) -> Option<Self> {
        if entries.is_empty() {
            return None;
        }
        if entries.len() <= 4 {
            return Some(Self::Inline(
                entries.iter().map(|entry| entry.hash).collect(),
            ));
        }
        let mut selected_hashes = HashSet::with_capacity(entries.len());
        selected_hashes.extend(entries.iter().map(|entry| entry.hash));
        Some(Self::Set(selected_hashes))
    }

    fn len(&self) -> usize {
        match self {
            Self::Inline(hashes) => hashes.len(),
            Self::Set(hashes) => hashes.len(),
        }
    }

    fn contains(&self, hash: &Hash256) -> bool {
        match self {
            Self::Inline(hashes) => hashes.contains(hash),
            Self::Set(hashes) => hashes.contains(hash),
        }
    }
}

/// Smallest inter-front-advance interval (milliseconds) accepted as a front
/// cadence sample. The sync layer timestamps a whole inbound chunk with one
/// `Instant` (`buffer_received_block_chunk`), so an in-order run of front
/// blocks processed in the same chunk yields same-instant "advances" whose
/// 0ms samples are batching artifacts, not network cadence — left unfiltered
/// they walk the EWMA toward zero (x3/4 each) and collapse the adaptive stall
/// floor back to the static minimum. Skipping genuine sub-50ms cadence loses
/// nothing: at that speed the decay floor is clamped at
/// `stall_timeout_initial` anyway.
const EWMA_MIN_SAMPLE_MS: u64 = 50;

#[derive(Clone, Copy, Debug)]
struct PendingBlock {
    /// The exact connection that owns this request. Same-address
    /// replacement must never inherit it: liveness is checked on the pair
    /// `(owner.endpoint, owner.connection_id())`, not the address alone.
    owner: PeerSource,
    requested_at: Instant,
    height: u32,
    estimated_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
struct PendingTimeoutObservation {
    owner: PeerSource,
    hash: Hash256,
    /// Set when the owner's own timeout expiry released the observed
    /// request: the blame evidence the second tick convicts on. A
    /// delivery or a requeue releases without it and pardons.
    expired_release: bool,
}

/// A running window-blocked stall observation: the window front (`front_hash`)
/// has been in flight to `peer_addr` with the apply frontier idle and no other
/// download progress possible since `since`.
#[derive(Clone, Copy, Debug)]
struct StallEpisode {
    owner: PeerSource,
    front_hash: Hash256,
    since: Instant,
    /// Whether the one-shot episode-observability INFO line has been emitted
    /// for this episode (fires once when the episode survives
    /// [`STALL_EPISODE_LOG_AGE`]; see [`DownloadWindow::advance_stall`]).
    info_logged: bool,
}

/// Apply-side stall keyed by frontier height and hash. A brief prune/refetch
/// seam preserves the episode; a new hash or unstaged frontier starts none.
#[derive(Clone, Copy, Debug)]
struct ApplySideStuck {
    height: u32,
    frontier_hash: Hash256,
    since: Instant,
}
#[derive(Clone, Copy, Debug)]
enum ColdFrontState {
    Waiting {
        owner: PeerSource,
        hash: Hash256,
        since: Instant,
    },
    Racing {
        owner: PeerSource,
        alternate: PeerSource,
        hash: Hash256,
    },
}

/// The canonical frontier facts one blockage observation needs.
///
/// PRE: `next_apply_height` and `frontier_hash` describe the same
///      `next_required` body the scheduler requested this tick;
///      `apply_side_busy` is current for that body.
/// POST: one tick advances every observation from this one snapshot.
/// INVARIANT: a frontier without a next-expected block has `None` height
///      and `None` hash; only the pending timeout still runs there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlockedContext {
    /// The next height apply expects, or `None` at the chain tip.
    pub next_apply_height: Option<u32>,
    /// The hash of that next-expected body, or `None` at the chain tip.
    pub frontier_hash: Option<Hash256>,
    /// Whether the stager holds the next-expected body (apply lag).
    pub apply_side_busy: bool,
}

/// Why the unified blockage observation convicted an owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlameReason {
    /// The window-blocked stall predicate fired on this owner.
    Staller,
    /// This owner's pending block passed its timeout twice.
    PendingTimeout,
}

/// The single action the sync coordinator owes this tick.
///
/// PRE: apply-side state and exact pending owners are current; `now` is
///      injected by the caller.
/// POST: at most one action returns, in precedence
///      `EvictStaged` > `Blame(Staller)` > `Blame(PendingTimeout)` >
///      `HedgeColdFront` > `None`.
/// INVARIANT: a same-address replacement never inherits blame, because
///      every observation keys on the exact [`PeerSource`]; only the
///      apply-side bound can produce [`BlockedDecision::EvictStaged`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlockedDecision {
    /// Disconnect `owner`: it is stalling the window or missed its
    /// request timeout.
    Blame {
        /// The exact owning connection.
        owner: PeerSource,
        /// Which rule convicted it.
        reason: BlameReason,
    },
    /// The apply-side no-blame suppression outlived its bound: evict the
    /// staged body at `height`/`hash` for refetch. No peer is blamed.
    EvictStaged {
        /// The stuck apply-frontier height.
        height: u32,
        /// The stuck staged body's hash.
        hash: Hash256,
        /// How long the suppression had held when it fired.
        suppressed_for: Duration,
    },
    /// Send a duplicate request for the cold front from another peer.
    HedgeColdFront {
        /// The current exact owner of the front block.
        owner: PeerSource,
        /// The front block's hash.
        front_hash: Hash256,
    },
    /// Nothing to do this tick.
    None,
}
#[derive(Debug)]
struct PrefixProbe {
    owner: PeerSource,
    hashes: SmallVec<[Hash256; PREFIX_PROBE_BLOCK_LIMIT]>,
    racers: HashMap<PeerSource, u8>,
    accepted: u8,
    started_at: Instant,
}

/// Episode age at which the one-shot stall-episode observability INFO line is
/// emitted. Below the 2s conviction floor by design: the line exists to make
/// episode dynamics visible in run logs *below* the WARN fire line — which
/// clearing rule zeroed the clock, and what the front-cadence EWMA (the
/// threshold's falsifier) was while the episode ran.
const STALL_EPISODE_LOG_AGE: Duration = Duration::from_secs(1);
/// Maximum distinct cold-start front blocks hedged before the cadence EWMA
/// seeds. Two advances are sufficient to produce the first cadence sample.
const MAX_COLD_FRONT_HEDGES: usize = 2;
/// One-shot duplicate prefix used to select a responsive deep-window peer.
const PREFIX_PROBE_BLOCK_LIMIT: usize = 8;
/// A peer must deliver the first four accepted prefix blocks to win.
const PREFIX_PROBE_WIN_BLOCKS: usize = 4;
const _: () = assert!(PREFIX_PROBE_WIN_BLOCKS > 0);
const _: () = assert!(PREFIX_PROBE_WIN_BLOCKS <= PREFIX_PROBE_BLOCK_LIMIT);
const _: () = assert!(PREFIX_PROBE_BLOCK_LIMIT <= 8);
const PREFIX_PROBE_WIN_MASK: u8 = (1_u8 << PREFIX_PROBE_WIN_BLOCKS) - 1;
/// Estimated duplicate bytes per alternate during the one-shot probe.
const PREFIX_PROBE_ESTIMATED_BYTES: usize = 2 * 1024 * 1024;

/// Stall-episode clearing reasons, the counter taxonomy for
/// `node.sync.stall_episodes_cleared{reason}`. Every path that zeroes the
/// episode clock tags exactly one reason:
/// - `apply_busy`: the no-blame guard held this tick ([`DownloadWindow::observe_blocked`]).
/// - `predicate`: a [`DownloadWindow::window_blocked_on`] term went false
///   (front moved off the frontier, no staged successor, or capacity opened).
/// - `front_moved`: the predicate still holds but for a different
///   `(peer, front_hash)` — the episode re-keyed and a new one started.
/// - `peer_delivery`: the blamed peer delivered a requested block
///   ([`DownloadWindow::record_delivery_progress`]).
/// - `fired`: conviction — the episode reached the effective threshold.
fn count_stall_episode_cleared(reason: &'static str) {
    metrics::counter!("node.sync.stall_episodes_cleared", "reason" => reason).increment(1);
}

/// Block download window: tracks pending and in-flight block requests with
/// stall detection, cold-front hedging, and fan-out policy.
#[derive(Debug)]
pub(crate) struct DownloadWindow {
    budget: SyncBudget,
    pending: HashMap<Hash256, PendingBlock>,
    pending_bytes: usize,
    /// Highest `pending` population observed; feeds the high-water gauge.
    pending_blocks_high_water: usize,
    /// Highest `pending_bytes` observed; feeds the high-water gauge.
    pending_bytes_high_water: usize,
    /// Start of the current apply-idle interval: no staged work while the
    /// window still owes downloads. `None` while apply has work.
    apply_idle_since: Option<Instant>,
    /// Start of the current download-blocked-by-apply interval: blocks are
    /// staged (apply owns the frontier) while the window front stays in
    /// flight. `None` while apply is not the gate.
    download_blocked_by_apply_since: Option<Instant>,
    ewma_block_bytes: usize,
    next_request_height: u32,
    request_tip: Option<(Hash256, u32)>,
    /// Per-owner block-download queue start: the local equivalent of Core's per-peer
    /// `m_downloading_since` (`net_processing.cpp`, Core 31.1 `m_downloading_since`).
    ///
    /// Keyed by the exact `PeerSource`; an entry exists exactly while that owner has
    /// validated in-flight blocks.
    owner_downloading_since: HashMap<PeerSource, Instant>,
    /// Eligible outbound witness peers available for new block assignments.
    /// The count sizes each stripe; engagement keeps one-peer hysteresis so a
    /// transient demotion does not switch candidate classes mid-window.
    fanout_eligible_peers: usize,
    fanout_engaged: bool,
    /// Current window-blocked stall observation, if any (R8). Re-derived from
    /// the predicate every [`Self::advance_stall`] call; cleared whenever any
    /// predicate term stops holding, so a transient stall never accumulates
    /// blame across unrelated episodes.
    stall: Option<StallEpisode>,
    /// Current apply-side stuck observation, if any. Re-keyed
    /// on the apply-front `(height, hash)` every
    /// [`Self::advance_apply_side_stuck`] call; a front advance or a
    /// same-height branch replacement resets it, brief unbusy seams do not,
    /// and an idle frontier starts no clock at all.
    apply_side_stuck: Option<ApplySideStuck>,
    /// Window-wide threshold: doubles after a staller conviction and decays
    /// on front progress. Do not reset it on peer rotation; that would
    /// repeatedly blame honest slow peers.
    stall_timeout: Duration,
    /// EWMA of front-arrival cadence. Same-chunk samples are ignored so a
    /// batched delivery cannot collapse the adaptive stall floor.
    front_interval_ewma_ms: Option<u64>,
    /// When the window front last advanced (a front block arrived); the
    /// anchor for the next `front_interval_ewma_ms` sample.
    last_front_advance: Option<Instant>,
    /// Cold-start front wait or active duplicate race. Unlike `stall`, this
    /// needs no staged successors and can never disconnect a peer.
    cold_front: Option<ColdFrontState>,
    /// Distinct cold-start front hashes whose duplicate request was sent.
    cold_hedged_fronts: SmallVec<[Hash256; MAX_COLD_FRONT_HEDGES]>,
    /// Peer that proved it could deliver a blocked cold front before its
    /// tracked owner. It receives the replacement deep window.
    preferred_peer: Option<PeerSource>,
    /// One-shot same-prefix race used to select a responsive deep owner
    /// without assigning unique height holes to alternate peers.
    prefix_probe: Option<PrefixProbe>,
    /// Deep owner already tested for the current pending assignment.
    prefix_probe_attempted_owner: Option<PeerSource>,
    /// First observation of an expired front request. Conviction needs a
    /// second tick so blocks delivered during synchronous apply can drain.
    pending_timeout_observation: Option<PendingTimeoutObservation>,
    /// Peers disconnected for stalling or an expired block request, by fire
    /// time. While inside `staller_cooldown` such a peer is not fan-out
    /// eligible and receives no block requests except as the last-resort peer.
    /// This prevents immediate re-acquisition of the same block stripe.
    recent_stallers: HashMap<StallerKey, Instant>,
}

/// Identity a staller cooldown attaches to: the logical endpoint for
/// identified peers, or the connection id for unidentified (anonymous,
/// e.g. inbound Tor) sessions. Anonymous stallers are tracked per
/// connection rather than silently skipped: a `None` endpoint must never
/// collapse every anonymous session into one shared key or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum StallerKey {
    /// Identified peer, keyed by logical endpoint.
    Endpoint(crate::PeerEndpoint),
    /// Unidentified session, keyed by its connection id.
    Unidentified(crate::ConnectionId),
}

impl From<PeerSource> for StallerKey {
    fn from(source: PeerSource) -> Self {
        match source.endpoint() {
            Some(endpoint) => Self::Endpoint(endpoint),
            None => Self::Unidentified(source.connection_id()),
        }
    }
}

impl DownloadWindow {
    /// Creates a new download window with the given budget.
    pub(crate) fn new(budget: SyncBudget) -> Self {
        Self {
            budget,
            pending: HashMap::with_capacity(budget.max_pending_blocks),
            pending_bytes: 0,
            pending_blocks_high_water: 0,
            pending_bytes_high_water: 0,
            apply_idle_since: None,
            download_blocked_by_apply_since: None,
            ewma_block_bytes: 256 * 1024,
            next_request_height: 1,
            request_tip: None,
            owner_downloading_since: HashMap::with_capacity(budget.max_pending_blocks),
            fanout_eligible_peers: 0,
            fanout_engaged: false,
            stall: None,
            apply_side_stuck: None,
            stall_timeout: budget.stall_timeout_initial,
            front_interval_ewma_ms: None,
            last_front_advance: None,
            cold_front: None,
            cold_hedged_fronts: SmallVec::new(),
            preferred_peer: None,
            prefix_probe: None,
            prefix_probe_attempted_owner: None,
            pending_timeout_observation: None,
            recent_stallers: HashMap::new(),
        }
    }

    /// Records the eligible population and updates engagement with one-peer
    /// hysteresis. Dynamic stripe sizing keeps requests distributed when the count dips.
    ///
    /// Bounded prefix-race-before-fanout handoff: when the eligible count
    /// reaches the fanout threshold while a prefix probe is active and
    /// younger than `stall_timeout_initial`, defer only fanout engagement so
    /// the one-shot race (typically sub-second) can elect a preferred peer
    /// instead of being cancelled by the engagement. After the probe
    /// resolves/cancels or the fixed `stall_timeout_initial` interval
    /// expires, existing hysteresis and immediate prefix-probe cancellation
    /// behavior resume unchanged. `now` is injected (not read here) so the
    /// tick/selection path controls the clock; see [`Self::advance_stall`]
    /// for the same discipline.
    pub(crate) fn set_fanout_eligible_peers(&mut self, count: usize, now: Instant) {
        let was_engaged = self.fanout_engaged;
        self.fanout_eligible_peers = count;
        let would_engage = count >= self.budget.min_peers_for_fanout;
        // Bound the deferral: while a fresh prefix probe (age <
        // stall_timeout_initial) is racing, hold fanout disengaged so the
        // race is not cancelled mid-flight. The probe's elapsed time is
        // computed from the injected `now` against the probe's
        // `started_at` (itself an injected `Instant`), never
        // `Instant::now()`. The bound is a strict less-than: at an elapsed
        // time exactly equal to `stall_timeout_initial` the probe is no
        // longer fresh (the race had its full budget), so fanout engages at
        // the deadline — `<` rather than `<=`.
        let probe_young = self.prefix_probe.as_ref().is_some_and(|probe| {
            now.duration_since(probe.started_at) < self.budget.stall_timeout_initial
        });
        let engaging = would_engage && !probe_young;
        if engaging {
            self.fanout_engaged = true;
        } else if count.saturating_add(1) < self.budget.min_peers_for_fanout {
            self.fanout_engaged = false;
        }
        if self.fanout_engaged != was_engaged {
            tracing::info!(
                eligible = count,
                fanout_active = self.fanout_active(),
                min_peers_for_fanout = self.budget.min_peers_for_fanout,
                "fanout engagement changed"
            );
        }
        if self.fanout_engaged {
            self.prefix_probe = None;
        }
    }

    /// Whether requests use a distributed cap or the one-peer deep fallback.
    pub(crate) const fn fanout_active(&self) -> bool {
        self.fanout_engaged
    }

    /// Per-peer cap for new assignments. With multiple eligible peers, divide
    /// the global window across them but never go below Core's 16-block cap.
    /// One peer retains the deep fallback. Existing over-cap assignments drain
    /// naturally after the eligible population changes.
    fn effective_peer_inflight(&self) -> usize {
        if !self.fanout_active() {
            return self.budget.max_peer_inflight;
        }
        self.budget
            .max_pending_blocks
            .div_ceil(self.fanout_eligible_peers.max(1))
            .max(self.budget.fanout_peer_inflight)
            .min(self.budget.max_peer_inflight)
    }

    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Maximum number of blocks the download window will keep pending at once.
    pub(crate) const fn max_pending_blocks(&self) -> usize {
        self.budget.max_pending_blocks
    }

    pub(crate) const fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// Whether pending and staged capacity can absorb another estimated block.
    ///
    /// INVARIANT: staged-body counts and bytes are read from `stager`,
    ///      never from a window-local copy.
    pub(crate) fn has_request_capacity(&self, stager: &BlockStager) -> bool {
        self.pending.len() < self.budget.max_pending_blocks
            && self.pending_bytes.saturating_add(self.ewma_block_bytes)
                <= self.budget.max_pending_bytes
            && self.staged_byte_headroom(stager) >= self.ewma_block_bytes
            && self.staged_count_headroom(stager, 0) > 0
    }

    /// Whether the coupled stager has exhausted its byte budget. Refusing new
    /// requests avoids arrivals that would be dropped and requested again;
    /// applying or expiring staged blocks releases the capacity.
    fn staged_bytes_exhausted(&self, stager: &BlockStager) -> bool {
        stager.received_bytes() >= self.budget.max_received_bytes
    }

    /// Free staging bytes after accounting for pending deliveries.
    /// The coupled stager owns the received total. With no staged bytes, leave the
    /// request path open for progress; pending admission still enforces its budget.
    fn staged_byte_headroom(&self, stager: &BlockStager) -> usize {
        let staged_bytes = stager.received_bytes();
        if staged_bytes == 0 {
            return usize::MAX;
        }
        self.budget
            .max_received_bytes
            .saturating_sub(staged_bytes)
            .saturating_sub(self.pending_bytes)
    }

    /// Free staging slots after accounting for live pending deliveries.
    /// The coupled stager owns the received count. With nothing staged, leave the
    /// request path open; pending admission still enforces its own budget.
    ///
    /// Credit expired pendings so the scan can reach `next_peer_request`, which
    /// expires and re-requests them. Otherwise a full window could prevent its own
    /// timeout recovery. Hash deduplication prevents late originals from filling
    /// another slot. This clamp applies backpressure before staging eviction.
    fn staged_count_headroom(&self, stager: &BlockStager, expired_pending_blocks: usize) -> usize {
        if stager.received_len() == 0 {
            return usize::MAX;
        }
        self.budget
            .max_received_blocks
            .saturating_sub(stager.received_len())
            .saturating_sub(self.pending.len().saturating_sub(expired_pending_blocks))
    }

    /// Per-peer request bound from pending budgets and the coupled stager's
    /// byte/slot headroom. Expired pendings are credited for timeout recovery.
    pub(crate) fn request_peer_scan_limit(&self, stager: &BlockStager, now: Instant) -> usize {
        if self.staged_bytes_exhausted(stager) {
            return 0;
        }
        let per_peer = self
            .budget
            .getdata_batch_limit
            .min(self.effective_peer_inflight());
        if per_peer == 0 || self.ewma_block_bytes == 0 {
            return 0;
        }
        let (expired_blocks, expired_bytes) = self.expired_pending_capacity(now);
        let block_capacity = self
            .budget
            .max_pending_blocks
            .saturating_sub(self.pending.len().saturating_sub(expired_blocks))
            .min(self.staged_count_headroom(stager, expired_blocks));
        // Expired bytes are credited back to pending capacity (they will be
        // re-requested) but not to staging byte headroom: a late arrival of
        // the original request still stages. The count headroom does credit
        // them so a stalled front can be retried while the staging count is full.
        let byte_capacity = self
            .budget
            .max_pending_bytes
            .saturating_sub(self.pending_bytes.saturating_sub(expired_bytes))
            .min(self.staged_byte_headroom(stager))
            / self.ewma_block_bytes;
        let request_blocks = block_capacity.min(byte_capacity);
        if request_blocks == 0 {
            return 0;
        }
        request_blocks
            .div_ceil(per_peer)
            .saturating_add(self.owner_address_count())
    }

    /// Blocks and bytes whose owner's queue has aged past its budget: the
    /// capacity the request path credits back for re-request this tick.
    ///
    /// PRE: `now` is the caller's injected clock.
    /// POST: totals over `pending` entries whose owner satisfies
    ///      [`Self::owner_download_expired`] under this tick's owner count.
    /// INVARIANT: the same per-owner predicate every consumer uses; no
    ///      fixed-duration path remains.
    fn expired_pending_capacity(&self, now: Instant) -> (usize, usize) {
        let active = self.active_downloading_peers();
        self.pending
            .values()
            .fold((0_usize, 0_usize), |(blocks, bytes), pending| {
                if !self.owner_download_expired(pending.owner, active, now) {
                    return (blocks, bytes);
                }
                (
                    blocks.saturating_add(1),
                    bytes.saturating_add(pending.estimated_bytes),
                )
            })
    }

    /// Whether `source` owns a pending block past the re-request timeout —
    /// the soft-demotion signal: such a peer gets no new front-of-window
    /// requests unless it is the last-resort peer, and it does not count as
    /// fan-out-eligible (KTD6's "not currently soft-demoted" clause).
    pub(crate) fn peer_has_expired_pending(&self, source: PeerSource, now: Instant) -> bool {
        self.owner_download_expired(source, self.active_downloading_peers(), now)
    }

    /// Returns at most one action after the canonical apply drain, using injected
    /// `now`, the coupled stager, and tree-resolved heights.
    ///
    /// Evaluate intervals, apply-side bound, no-blame guard, cold-front/stall, pending
    /// timeout, then hedge. Blame always names the exact `PeerSource`, never a
    /// same-address replacement. While apply is busy only the apply-side bound may
    /// return `EvictStaged`; otherwise return the owed disconnect, unblamed eviction,
    /// hedge, or no action.
    pub(crate) fn observe_blocked(
        &mut self,
        ctx: BlockedContext,
        stager: &BlockStager,
        tree: &BlockTree,
        now: Instant,
    ) -> BlockedDecision {
        let evicted = if let Some(next_apply_height) = ctx.next_apply_height {
            self.observe_intervals(ctx.apply_side_busy, now);
            self.advance_apply_side_stuck(
                next_apply_height,
                ctx.frontier_hash,
                ctx.apply_side_busy,
                now,
            )
        } else {
            None
        };
        if ctx.apply_side_busy {
            // The no-blame guard: our own slowness is never a peer's fault.
            if self.stall.take().is_some() {
                count_stall_episode_cleared("apply_busy");
            }
            self.pending_timeout_observation = None;
            if !matches!(self.cold_front, Some(ColdFrontState::Racing { .. })) {
                self.cold_front = None;
            }
            return match (ctx.next_apply_height, evicted) {
                (Some(height), Some((hash, suppressed_for))) => BlockedDecision::EvictStaged {
                    height,
                    hash,
                    suppressed_for,
                },
                _ => BlockedDecision::None,
            };
        }
        let mut hedge = None;
        if let Some(next_apply_height) = ctx.next_apply_height {
            hedge = self.advance_cold_front(next_apply_height, now);
            if let Some(owner) = self.advance_stall(next_apply_height, stager, tree, now) {
                return BlockedDecision::Blame {
                    owner,
                    reason: BlameReason::Staller,
                };
            }
        }
        if let Some(owner) = self.advance_pending_timeout(now, self.active_downloading_peers()) {
            return BlockedDecision::Blame {
                owner,
                reason: BlameReason::PendingTimeout,
            };
        }
        hedge.map_or(BlockedDecision::None, |(owner, front_hash)| {
            BlockedDecision::HedgeColdFront { owner, front_hash }
        })
    }

    /// Convicts an expired request owner only on a second idle tick.
    ///
    /// Inbound delivery may wait behind synchronous apply: the first observation
    /// records suspicion, and delivery clears it. On the next tick the exact connection
    /// must still own the same pending hash and remain expired; otherwise clear
    /// suspicion without blame. Conviction adds its address to cooldown. Call only when
    /// the apply side is not busy.
    fn advance_pending_timeout(
        &mut self,
        now: Instant,
        active_downloading_peers: usize,
    ) -> Option<PeerSource> {
        if let Some(observation) = self.pending_timeout_observation {
            self.pending_timeout_observation = None;
            let still_owned = self
                .pending
                .get(&observation.hash)
                .is_some_and(|pending| pending.owner == observation.owner);
            if observation.expired_release
                || (still_owned
                    && self.owner_download_expired(
                        observation.owner,
                        active_downloading_peers,
                        now,
                    ))
            {
                self.mark_peer_unresponsive(observation.owner, now);
                return Some(observation.owner);
            }
            return None;
        }
        self.pending_timeout_observation = self
            .pending
            .iter()
            .filter(|(_, pending)| {
                self.owner_download_expired(pending.owner, active_downloading_peers, now)
            })
            .min_by_key(|(_, pending)| pending.height)
            .map(|(hash, pending)| PendingTimeoutObservation {
                owner: pending.owner,
                hash: *hash,
                expired_release: false,
            });
        None
    }

    /// Bounds apply-side suppression without blaming a peer for local slowness.
    ///
    /// Start the clock only after a body stages at `(height, frontier_hash)`; retain
    /// elapsed busy time across expiry/refetch seams. A frontier change or missing
    /// frontier resets it, so a late first delivery is not evicted. At twice
    /// `SyncBudget::received_timeout`, return the body and elapsed time for unblamed
    /// eviction/refetch, then re-arm. This allows one complete expiry and refetch
    /// attempt while preventing repeated arrivals from resetting recovery indefinitely.
    /// The clock accrues only while `apply_side_busy`.
    fn advance_apply_side_stuck(
        &mut self,
        next_apply_height: u32,
        frontier_hash: Option<Hash256>,
        apply_side_busy: bool,
        now: Instant,
    ) -> Option<(Hash256, Duration)> {
        let Some(frontier_hash) = frontier_hash else {
            self.apply_side_stuck = None;
            return None;
        };
        match self.apply_side_stuck {
            Some(stuck)
                if stuck.height == next_apply_height && stuck.frontier_hash == frontier_hash => {}
            _ if apply_side_busy => {
                // A new episode starts only while a body for this frontier
                // is actually staged; an idle frontier accumulates nothing.
                self.apply_side_stuck = Some(ApplySideStuck {
                    height: next_apply_height,
                    frontier_hash,
                    since: now,
                });
            }
            _ => {
                self.apply_side_stuck = None;
            }
        }
        if !apply_side_busy {
            return None;
        }
        let suppressed_for = now.duration_since(self.apply_side_stuck.as_ref()?.since);
        let bound = self.budget.received_timeout.saturating_mul(2);
        if suppressed_for < bound {
            return None;
        }
        if let Some(stuck) = self.apply_side_stuck.as_mut() {
            stuck.since = now;
        }
        Some((frontier_hash, suppressed_for))
    }

    /// Measurement only: interval bookkeeping that never feeds
    /// a blockage decision.
    ///
    /// - download-blocked-by-apply: apply owns the frontier while requests
    ///   are in flight — download progress gated by apply speed.
    /// - apply-idle: requests in flight, nothing staged — apply starved by
    ///   the network.
    ///
    /// PRE: called once per tick that has an apply frontier.
    /// POST: at most one of the two intervals is open.
    /// INVARIANT: a closed interval records its duration exactly once.
    fn observe_intervals(&mut self, apply_side_busy: bool, now: Instant) {
        if apply_side_busy {
            if self.pending.is_empty() {
                self.close_download_blocked_by_apply(now);
            } else if self.download_blocked_by_apply_since.is_none() {
                self.download_blocked_by_apply_since = Some(now);
            }
            self.close_apply_idle(now);
        } else {
            self.close_download_blocked_by_apply(now);
            if self.pending.is_empty() {
                self.close_apply_idle(now);
            } else if self.apply_idle_since.is_none() {
                self.apply_idle_since = Some(now);
            }
        }
    }

    /// Advances the blocked-window stall observation when apply is not busy.
    ///
    /// `next_apply_height` is the apply frontier. No chain-tail arm is used: ordinary
    /// tip latency and the IBD tail remain covered by pending timeouts. Cold starts use
    /// the initial floor; `stall_decay_floor` owns cadence bounds. On fire, return the
    /// exact owner to disconnect, add its address to cooldown, and double the threshold
    /// up to `stall_timeout_max`. Any failed predicate or delivery from that connection
    /// clears the episode rather than freezing it (Core's `m_stalling_since`).
    fn advance_stall(
        &mut self,
        next_apply_height: u32,
        stager: &BlockStager,
        tree: &BlockTree,
        now: Instant,
    ) -> Option<PeerSource> {
        let Some((owner, front_hash)) = self.window_blocked_on(stager, tree, next_apply_height)
        else {
            if self.stall.take().is_some() {
                count_stall_episode_cleared("predicate");
            }
            return None;
        };
        let episode = match self.stall {
            Some(episode) if episode.owner == owner && episode.front_hash == front_hash => episode,
            previous => {
                if previous.is_some() {
                    // Predicate still holds but for a different
                    // (peer, front_hash): the front advanced (or rotated
                    // owner) and the episode re-keyed.
                    count_stall_episode_cleared("front_moved");
                }
                metrics::counter!("node.sync.stall_episodes_started").increment(1);
                let episode = StallEpisode {
                    owner,
                    front_hash,
                    since: now,
                    info_logged: false,
                };
                self.stall = Some(episode);
                episode
            }
        };
        // Log a surviving episode after STALL_EPISODE_LOG_AGE.
        // The fire threshold is the stored adaptive value, never below the
        // cadence-based decay floor: on a network whose demonstrated front
        // cadence exceeds `stall_timeout_initial`, an episode younger than
        // twice that cadence is the uniform-slow steady state, not a stall.
        let effective_timeout = self.stall_timeout.max(self.stall_decay_floor());
        if !episode.info_logged && now.duration_since(episode.since) >= STALL_EPISODE_LOG_AGE {
            if let Some(stored) = self.stall.as_mut() {
                stored.info_logged = true;
            }
            tracing::info!(
                peer_addr = ?episode.owner.endpoint,
                front_hash = %episode.front_hash,
                front_height = next_apply_height,
                episode_age_ms = u64::try_from(now.duration_since(episode.since).as_millis())
                    .unwrap_or(u64::MAX),
                effective_timeout_ms = u64::try_from(effective_timeout.as_millis())
                    .unwrap_or(u64::MAX),
                front_interval_ewma_ms = ?self.front_interval_ewma_ms,
                "block sync: stall episode running"
            );
        }
        if now.duration_since(episode.since) < effective_timeout {
            return None;
        }
        count_stall_episode_cleared("fired");
        // Fire: blame is settled. Double the threshold for the next episode
        // (sudden bandwidth drops must not cascade into disconnecting every
        // peer at 2s — Core's rationale) and start the re-acquisition
        // cooldown for this peer. Doubling starts from the effective
        // threshold the fire was judged against, so a conviction at the
        // adaptive floor elevates the next episode's bar just like one at
        // the stored value.
        self.stall = None;
        self.stall_timeout = effective_timeout
            .saturating_mul(2)
            .min(self.budget.stall_timeout_max);
        self.mark_peer_unresponsive(owner, now);
        Some(owner)
    }

    /// Closes an open apply-idle interval, recording its duration.
    fn close_apply_idle(&mut self, now: Instant) {
        if let Some(since) = self.apply_idle_since.take() {
            metrics::histogram!("node.sync.apply_idle_seconds")
                .record(now.duration_since(since).as_secs_f64());
        }
    }

    /// Closes an open download-blocked-by-apply interval, recording its
    /// duration.
    fn close_download_blocked_by_apply(&mut self, now: Instant) {
        if let Some(since) = self.download_blocked_by_apply_since.take() {
            metrics::histogram!("node.sync.download_blocked_by_apply_seconds")
                .record(now.duration_since(since).as_secs_f64());
        }
    }

    /// Exposes the pending high-water marks for the metrics gauges.
    pub(crate) const fn pending_high_water(&self) -> (usize, usize) {
        (
            self.pending_blocks_high_water,
            self.pending_bytes_high_water,
        )
    }

    /// Clamps decay and conviction to twice the demonstrated front cadence, between
    /// `stall_timeout_initial` and `stall_timeout_max`.
    ///
    /// Cold starts use the initial floor. The 2x margin tolerates honest cadence
    /// jitter; same-chunk arrivals below `EWMA_MIN_SAMPLE_MS` cannot lower the EWMA.
    fn stall_decay_floor(&self) -> Duration {
        self.front_interval_ewma_ms
            .map_or(Duration::ZERO, |ewma_ms| {
                Duration::from_millis(ewma_ms.saturating_mul(2))
            })
            .max(self.budget.stall_timeout_initial)
            .min(self.budget.stall_timeout_max)
    }

    /// Identifies a single peer blocking the apply frontier: its pending block
    /// must be at `next_apply_height`, with a staged successor and at least half
    /// the staging count window occupied. An unrequested frontier gap or a
    /// generally slow download does not blame a peer.
    ///
    /// Read staged identity/count from the coupled stager and heights from `tree`;
    /// the window keeps no second copy. Tail behavior belongs to `advance_stall`.
    fn window_blocked_on(
        &self,
        stager: &BlockStager,
        tree: &BlockTree,
        next_apply_height: u32,
    ) -> Option<(PeerSource, Hash256)> {
        let (front_hash, front) = self
            .pending
            .iter()
            .min_by_key(|(_, pending)| pending.height)?;
        if front.height != next_apply_height {
            return None;
        }
        if stager.received_len() < self.budget.max_received_blocks / 2 {
            return None;
        }
        let has_staged_successor = stager.staged_hashes().any(|hash| {
            tree.height_of_hash(hash)
                .is_some_and(|height| height > front.height)
        });
        if !has_staged_successor {
            return None;
        }
        Some((front.owner, *front_hash))
    }

    /// Current stall observation, if one is running: the blamed peer and when the
    /// episode started.
    ///
    /// A peer delivering each front block just under the adaptive threshold is never
    /// disconnected (same exposure as Core) but is visible here and on the
    /// `node.sync.stall_seconds` gauge.
    pub(crate) fn stalling_peer(&self) -> Option<(Option<crate::PeerEndpoint>, Instant)> {
        self.stall
            .map(|episode| (episode.owner.endpoint, episode.since))
    }
    /// Advances the cold-start front timer independently of the strong stall
    /// predicate. Returns a duplicate request only after the same apply-front
    /// hash remains pending to one owner for the initial stall timeout.
    ///
    /// PRE: the apply side is not busy this tick (the no-blame guard in
    ///      [`Self::observe_blocked`] owns the busy case).
    /// POST: `Some((owner, hash))` names the exact owner of the waiting
    ///      front; a seeded cadence EWMA or a spent hedge budget drops the
    ///      timer.
    /// INVARIANT: a running race is never restarted from here.
    fn advance_cold_front(
        &mut self,
        next_apply_height: u32,
        now: Instant,
    ) -> Option<(PeerSource, Hash256)> {
        if matches!(self.cold_front, Some(ColdFrontState::Racing { .. })) {
            return None;
        }
        if self.front_interval_ewma_ms.is_some()
            || self.cold_hedged_fronts.len() >= MAX_COLD_FRONT_HEDGES
        {
            self.cold_front = None;
            return None;
        }
        let Some((&hash, pending)) = self
            .pending
            .iter()
            .find(|(_, pending)| pending.height == next_apply_height)
        else {
            self.cold_front = None;
            return None;
        };
        match self.cold_front {
            Some(ColdFrontState::Waiting {
                owner,
                hash: waiting_hash,
                since,
            }) if owner == pending.owner && waiting_hash == hash => {
                if now.duration_since(since) >= self.budget.stall_timeout_initial {
                    Some((owner, hash))
                } else {
                    None
                }
            }
            _ => {
                self.cold_front = Some(ColdFrontState::Waiting {
                    owner: pending.owner,
                    hash,
                    since: now,
                });
                None
            }
        }
    }

    /// Records a successfully sent cold-front duplicate request.
    pub(crate) fn confirm_cold_front_hedge(
        &mut self,
        owner: PeerSource,
        alternate: PeerSource,
        hash: Hash256,
    ) {
        if !matches!(
            self.cold_front,
            Some(ColdFrontState::Waiting {
                owner: waiting_owner,
                hash: waiting_hash,
                ..
            }) if waiting_owner == owner && waiting_hash == hash
        ) {
            return;
        }
        if !self.cold_hedged_fronts.contains(&hash) {
            if self.cold_hedged_fronts.len() >= MAX_COLD_FRONT_HEDGES {
                return;
            }
            self.cold_hedged_fronts.push(hash);
        }
        self.cold_front = Some(ColdFrontState::Racing {
            owner,
            alternate,
            hash,
        });
    }

    /// Preferred deep-window peer after winning a cold-front race.
    pub(crate) const fn preferred_peer(&self) -> Option<PeerSource> {
        self.preferred_peer
    }

    /// Number of eligible peers that activates striped fanout.
    pub(crate) const fn min_peers_for_fanout(&self) -> usize {
        self.budget.min_peers_for_fanout
    }

    /// Clears a preferred peer that is no longer serviceable.
    pub(crate) fn clear_preferred_peer(&mut self) {
        self.preferred_peer = None;
    }

    /// Whether `source` was offered `hash` as a prefix-probe racer: its
    /// `notfound` answers a question the node asked, so the scheduler
    /// remembers it even though the owner keeps the request.
    pub(crate) fn probe_offered(&self, source: PeerSource, hash: &Hash256) -> bool {
        self.prefix_probe
            .as_ref()
            .is_some_and(|probe| probe.hashes.contains(hash) && probe.racers.contains_key(&source))
    }

    /// Whether `source` is the recorded hedge alternate racing for `hash`:
    /// its `notfound` answers the duplicate request the node sent, so the
    /// scheduler remembers it even though the owner keeps the request.
    pub(crate) fn hedge_offered(&self, source: PeerSource, hash: &Hash256) -> bool {
        matches!(
            self.cold_front,
            Some(ColdFrontState::Racing {
                alternate,
                hash: front,
                owner: _,
            }) if alternate == source && front == *hash
        )
    }
    /// Builds the one-shot common-prefix probe after a deep fallback request.
    pub(crate) fn prefix_probe_plan(
        &self,
    ) -> Option<(
        PeerSource,
        SmallVec<[Hash256; PREFIX_PROBE_BLOCK_LIMIT]>,
        u32,
    )> {
        if self.preferred_peer.is_some() || self.prefix_probe.is_some() || self.fanout_active() {
            return None;
        }
        let owner = self
            .pending
            .values()
            .min_by_key(|pending| pending.height)?
            .owner;
        if self.prefix_probe_attempted_owner == Some(owner)
            || self.pending.values().any(|pending| pending.owner != owner)
        {
            return None;
        }
        let limit =
            (PREFIX_PROBE_ESTIMATED_BYTES / self.ewma_block_bytes).min(PREFIX_PROBE_BLOCK_LIMIT);
        if limit < PREFIX_PROBE_WIN_BLOCKS {
            return None;
        }
        let mut ordered: Vec<(u32, Hash256)> = self
            .pending
            .iter()
            .map(|(hash, pending)| (pending.height, *hash))
            .collect();
        ordered.sort_unstable_by_key(|(height, _)| *height);
        let mut hashes = SmallVec::new();
        let mut expected_height = ordered.first()?.0;
        for (height, hash) in ordered {
            if hashes.len() >= limit || height != expected_height {
                break;
            }
            hashes.push(hash);
            expected_height = expected_height.saturating_add(1);
        }
        (hashes.len() >= PREFIX_PROBE_WIN_BLOCKS).then_some((
            owner,
            hashes,
            expected_height.saturating_sub(1),
        ))
    }

    /// Starts the prefix race after at least one alternate accepted the probe.
    pub(crate) fn confirm_prefix_probe(
        &mut self,
        owner: PeerSource,
        hashes: SmallVec<[Hash256; PREFIX_PROBE_BLOCK_LIMIT]>,
        alternates: &[PeerSource],
        now: Instant,
    ) {
        if alternates.is_empty() {
            return;
        }
        let valid_plan =
            self.prefix_probe_plan()
                .is_some_and(|(planned_owner, planned_hashes, _)| {
                    planned_owner == owner && planned_hashes == hashes
                });
        if !valid_plan {
            return;
        }
        self.prefix_probe_attempted_owner = Some(owner);
        let mut racers = HashMap::with_capacity(alternates.len().saturating_add(1));
        racers.insert(owner, 0);
        racers.extend(alternates.iter().copied().map(|peer| (peer, 0)));
        self.prefix_probe = Some(PrefixProbe {
            owner,
            hashes,
            racers,
            accepted: 0,
            started_at: now,
        });
    }

    #[cfg(test)]
    pub(crate) const fn stall_timeout(&self) -> Duration {
        self.stall_timeout
    }

    /// Starts the re-acquisition cooldown for an unresponsive peer.
    /// Unidentified sessions cool down per connection (see
    /// [`StallerKey`]); they are never silently skipped.
    pub(crate) fn mark_peer_unresponsive(&mut self, source: PeerSource, now: Instant) {
        let cooldown = self.budget.staller_cooldown;
        self.recent_stallers
            .retain(|_, fired_at| now.duration_since(*fired_at) < cooldown);
        self.recent_stallers.insert(StallerKey::from(source), now);
    }

    /// Whether `source` is in cooldown; such peers are a last resort so a
    /// reconnecting staller cannot immediately reacquire the window front.
    pub(crate) fn peer_in_staller_cooldown(&self, source: PeerSource, now: Instant) -> bool {
        self.recent_stallers
            .get(&StallerKey::from(source))
            .is_some_and(|fired_at| now.duration_since(*fired_at) < self.budget.staller_cooldown)
    }

    pub(crate) fn contains_pending(&self, hash: &Hash256) -> bool {
        self.pending.contains_key(hash)
    }

    /// The exact connection owning the pending request for `hash`.
    pub(crate) fn pending_owner(&self, hash: &Hash256) -> Option<PeerSource> {
        self.pending.get(hash).map(|pending| pending.owner)
    }

    #[cfg(test)]
    pub(crate) fn active_prefix_probe_started_at(&self) -> Option<Instant> {
        self.prefix_probe.as_ref().map(|probe| probe.started_at)
    }

    /// Distinct exact connections owning validated in-flight blocks: the
    /// per-owner block-download budget's peer count (Core's
    /// `m_peers_downloading_from`, `net_processing.cpp`).
    ///
    /// POST: equals the population of `owner_downloading_since`.
    /// INVARIANT: announced or merely-assigned peers never count; only
    ///      ownership of at least one pending block does.
    fn active_downloading_peers(&self) -> usize {
        self.owner_downloading_since.len()
    }

    /// Whether `owner` holds one of the per-owner download slots.
    ///
    /// POST: true exactly while `owner` is in the population that
    ///   `active_downloading_peers` counts.
    /// INVARIANT: the answer is the same fact the fan-out budget reads, so a
    ///   peer counted as downloading is never retired as idle.
    #[must_use]
    pub(crate) fn is_downloading(&self, owner: PeerSource) -> bool {
        self.owner_downloading_since.contains_key(&owner)
    }

    /// The per-owner block-download budget for one tick.
    ///
    /// PRE: `active_downloading_peers` counts the owners with validated
    ///      in-flight blocks.
    /// POST: `SyncBudget::pending_timeout_override` when set; else
    ///      `block_spacing * (BLOCK_DOWNLOAD_TIMEOUT_BASE
    ///      + BLOCK_DOWNLOAD_TIMEOUT_PER_PEER * other) / 2` with `other`
    ///      the count minus one, saturating at `Duration::MAX`.
    /// INVARIANT: one tick applies this one budget to every owner; the
    ///      override is a test-only escape hatch, never production.
    fn effective_owner_timeout(&self, active_downloading_peers: usize) -> Duration {
        #[cfg(test)]
        if let Some(timeout) = self.budget.pending_timeout_override {
            return timeout;
        }
        let other = u32::try_from(active_downloading_peers.saturating_sub(1)).unwrap_or(u32::MAX);
        let raw_factor = BLOCK_DOWNLOAD_TIMEOUT_BASE
            .saturating_add(BLOCK_DOWNLOAD_TIMEOUT_PER_PEER.saturating_mul(other));
        self.budget.block_spacing.saturating_mul(raw_factor) / 2
    }

    /// Whether `owner`'s download queue has aged past its budget.
    ///
    /// PRE: `active_downloading_peers` is this tick's owner count.
    /// POST: `true` exactly while the owner has a queue start at least the
    ///      budget old; an owner with no entry never expired.
    /// INVARIANT: every expiry, eligibility, and blame decision shares this
    ///      one predicate.
    fn owner_download_expired(
        &self,
        owner: PeerSource,
        active_downloading_peers: usize,
        now: Instant,
    ) -> bool {
        self.owner_downloading_since
            .get(&owner)
            .is_some_and(|since| {
                now.duration_since(*since) >= self.effective_owner_timeout(active_downloading_peers)
            })
    }

    /// Updates one owner's queue start after removing its pending entry.
    ///
    /// Drop the clock when no entries remain. If the removed request was strictly
    /// oldest, reset to injected `now`; equal-stamped survivors adopt that stamp
    /// without regression; otherwise leave the clock unchanged. This mirrors Core 31.1
    /// `m_downloading_since` in `net_processing.cpp`: batched requests share a stamp,
    /// so non-front trickles cannot delay timeout.
    fn reset_owner_queue_start(
        &mut self,
        owner: PeerSource,
        removed_requested_at: Instant,
        now: Instant,
    ) {
        let oldest_remaining = self
            .pending
            .values()
            .filter(|pending| pending.owner == owner)
            .map(|pending| pending.requested_at)
            .min();
        match oldest_remaining {
            None => {
                self.owner_downloading_since.remove(&owner);
            }
            Some(oldest) if removed_requested_at < oldest => {
                self.owner_downloading_since.insert(owner, now);
            }
            // The removed entry shares the surviving head's stamp (entries
            // of one batched request share one `requested_at`): the head
            // keeps that stamp, so the clock stays at the batch origin
            // until the front itself is removed. The clock may already sit
            // ahead of the stamp — an earlier true-head removal moved it
            // to the removal instant — and must not regress: Core's
            // `m_downloading_since` only ever moves forward
            // (`max(since, now)`).
            Some(oldest) if removed_requested_at == oldest => {
                self.owner_downloading_since
                    .entry(owner)
                    .and_modify(|since| *since = (*since).max(oldest))
                    .or_insert(oldest);
            }
            Some(_) => {}
        }
    }

    /// Retains only ownership facts whose connection `owns` still names.
    ///
    /// PRE: `owns` is false for every connection absent from the peer
    ///   table's live set.
    /// POST: `pending` holds only entries whose owner satisfies `owns`, with
    ///   `pending_bytes`, `next_request_height`, and `owner_downloading_since`
    ///   kept in step; `cold_front` survives only while its waiting owner or
    ///   both racing participants do; `preferred_peer` and
    ///   `prefix_probe_attempted_owner` clear when their owner fails `owns`;
    ///   probe racers failing `owns` leave the race, a probe whose owner
    ///   fails `owns` is cancelled regardless of its racers, and a race left
    ///   with fewer than two racers is cancelled.
    /// INVARIANT: no fact here is compared by address alone.
    ///   `recent_stallers` is keyed by [`StallerKey`] (endpoint, or
    ///   connection id for unidentified sessions) and stays exempt;
    ///   `stall` is untouched because the conviction paths own its release.
    pub(crate) fn retain_owned_by(&mut self, owns: impl Fn(&PeerSource) -> bool) {
        let cold_front_owned = match self.cold_front {
            Some(ColdFrontState::Waiting { owner, .. }) => owns(&owner),
            Some(ColdFrontState::Racing {
                owner, alternate, ..
            }) => owns(&owner) && owns(&alternate),
            None => true,
        };
        if !cold_front_owned {
            self.cold_front = None;
        }
        if self.preferred_peer.is_some_and(|peer| !owns(&peer)) {
            self.preferred_peer = None;
        }
        if self
            .prefix_probe_attempted_owner
            .is_some_and(|owner| !owns(&owner))
        {
            self.prefix_probe_attempted_owner = None;
        }
        let cancel_probe = self.prefix_probe.as_mut().is_some_and(|probe| {
            let owner_alive = owns(&probe.owner);
            probe.racers.retain(|peer, _| owns(peer));
            !owner_alive || probe.racers.len() < 2
        });
        if cancel_probe {
            self.prefix_probe = None;
        }
        self.retain_peer_assignments(owns);
    }

    /// Retires downloads overtaken by replay from the durable archive.
    /// The chain owner supplies the first height still needing validation.
    pub(crate) fn retire_before(
        &mut self,
        stager: &mut BlockStager,
        height: u32,
        tree: &BlockTree,
        now: Instant,
    ) {
        let retired = self
            .pending
            .iter()
            .filter_map(|(hash, pending)| (pending.height < height).then_some(*hash))
            .collect::<Vec<_>>();
        for hash in retired {
            self.remove_pending(&hash, now);
        }
        let retired = stager
            .staged_hashes()
            .filter(|hash| {
                tree.lookup(*hash)
                    .and_then(|id| tree.node(id).ok())
                    .is_some_and(|node| node.height < height)
            })
            .collect::<Vec<_>>();
        for hash in retired {
            stager.discard(&hash);
        }
    }

    fn retain_peer_assignments(&mut self, retain_owner: impl Fn(&PeerSource) -> bool) {
        if self
            .pending_timeout_observation
            .is_some_and(|observation| !retain_owner(&observation.owner))
        {
            self.pending_timeout_observation = None;
        }
        let mut retry_height = self.next_request_height;
        self.pending.retain(|_hash, pending| {
            if retain_owner(&pending.owner) {
                return true;
            }
            retry_height = retry_height.min(pending.height);
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
            false
        });
        // A released owner loses every pending it had: its queue start
        // goes with them, so no phantom age survives to blame a later
        // assignment to the same connection.
        self.owner_downloading_since
            .retain(|owner, _| retain_owner(owner));
        self.next_request_height = retry_height;
    }

    /// Builds the next batch of block requests for `peer_addr`, or `None` if
    /// no blocks are available to request.
    ///
    /// PRE: `stager` is the coupled staging set; expiry has run this tick.
    /// POST: a request whose entries are unowned, on the request branch,
    ///      inside every pending/staging budget, and free of bodies
    ///      `is_refused` names for `source`; `next_request_height` covers
    ///      every height the scan offered except the lowest refused one,
    ///      which pins the cursor so another peer can plan it this tick.
    /// INVARIANT: staged membership, count, and bytes are read from `stager`.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn next_peer_request(
        &mut self,
        stager: &mut BlockStager,
        source: PeerSource,
        allow_expired_retry_from_peer: bool,
        chain_tip: &TipSnapshot,
        request_start_height: u32,
        peer_best_height: u32,
        servable_floor: u32,
        tree: &BlockTree,
        now: Instant,
        refusals: &mut RefusalFilter,
    ) -> Option<PeerRequest> {
        self.retarget_request_branch(stager, chain_tip, request_start_height, tree, now);
        if self.staged_bytes_exhausted(stager) {
            return None;
        }
        if !allow_expired_retry_from_peer
            && (self.peer_has_expired_pending(source, now)
                || self.peer_in_staller_cooldown(source, now))
        {
            return None;
        }
        let mut expired = self.expire_pending(now);
        expired.sort_by_key(|entry| entry.height);

        let owned = self.pending_count_for(source);
        let peer_capacity = self.effective_peer_inflight().saturating_sub(owned);
        // Expiry already ran above, so the count headroom needs no expired
        // credit here: `pending` reflects only live in-flight requests.
        let block_capacity = self
            .budget
            .max_pending_blocks
            .saturating_sub(self.pending.len())
            .min(self.staged_count_headroom(stager, 0));
        let mut byte_capacity = self
            .budget
            .max_pending_bytes
            .saturating_sub(self.pending_bytes)
            .min(self.staged_byte_headroom(stager));
        let batch_limit = self
            .budget
            .getdata_batch_limit
            .min(peer_capacity)
            .min(block_capacity);
        if batch_limit == 0 || byte_capacity < self.ewma_block_bytes {
            return None;
        }

        // Bodies `source` already answered `notfound` for are excluded per
        // entry, never by dropping the batch: the lowest refused height pins
        // the cursor so a peer that holds it is still planned below.
        let mut entries = self.expired_request_entries(
            stager,
            expired,
            batch_limit,
            servable_floor,
            &mut byte_capacity,
            refusals,
        );
        let selected_hashes = SelectedHashes::from_entries(&entries);

        // The current chain frontier outranks the forward-scan hint. A
        // disconnect can move it backwards without changing the header tip.
        // Rewind only an unowned frontier; retain live pending/staged work.
        if request_start_height < self.next_request_height
            && tree
                .node_at_height_from(chain_tip.tip_id, request_start_height)
                .and_then(|id| tree.node(id).ok())
                .is_some_and(|node| {
                    !self.pending.contains_key(&node.hash) && !stager.contains(&node.hash)
                })
        {
            let previous_height = self.next_request_height;
            self.next_request_height = request_start_height;
            tracing::debug!(
                previous_height,
                request_start_height,
                "block sync: rewound unowned request frontier"
            );
        }
        // `servable_floor` keeps a limited peer's batch inside its retained
        // window: `serves_requested_height` certified only the first height
        // at selection time.
        let height = request_start_height
            .max(self.next_request_height)
            .max(servable_floor);
        let mut next_request_height = self.next_request_height;
        let request_tip_height = chain_tip.height.min(peer_best_height);
        let remaining_limit = batch_limit
            .saturating_sub(entries.len())
            .min(byte_capacity / self.ewma_block_bytes);
        if height <= request_tip_height && remaining_limit > 0 {
            let scan = RequestScan {
                height,
                request_tip_height,
                remaining_limit,
                next_request_height,
            };
            if entries.is_empty()
                && let Some(request) = self
                    .clean_contiguous_peer_request(stager, source, chain_tip, tree, scan, refusals)
            {
                return Some(request);
            }

            next_request_height = self.extend_request_by_reverse_scan(
                stager,
                chain_tip,
                tree,
                scan,
                selected_hashes.as_ref(),
                &mut entries,
                refusals,
            );
        }
        if let Some(refused_height) = refusals.min_refused() {
            // The pin only holds the cursor back, never rewinds it: every
            // refused height the scan saw sits at or above where it started.
            next_request_height = next_request_height
                .min(refused_height)
                .max(self.next_request_height);
        }
        non_empty_request(source, entries, next_request_height)
    }

    pub(crate) fn retarget_request_branch(
        &mut self,
        stager: &mut BlockStager,
        chain_tip: &TipSnapshot,
        request_start_height: u32,
        tree: &BlockTree,
        now: Instant,
    ) {
        let Some((previous_hash, previous_height)) =
            self.request_tip.replace((chain_tip.hash, chain_tip.height))
        else {
            return;
        };
        let extends_request_tip = previous_height <= chain_tip.height
            && tree.lookup(previous_hash)
                == tree.node_at_height_from(chain_tip.tip_id, previous_height);
        if extends_request_tip {
            return;
        }

        let is_on_request_branch = |hash: Hash256, height: u32| {
            height >= request_start_height
                && tree.lookup(hash) == tree.node_at_height_from(chain_tip.tip_id, height)
        };
        let stale_pending: Vec<Hash256> = self
            .pending
            .iter()
            .filter_map(|(hash, pending)| {
                (!is_on_request_branch(*hash, pending.height)).then_some(*hash)
            })
            .collect();
        for hash in stale_pending {
            self.remove_pending(&hash, now);
        }
        let stale_staged: Vec<Hash256> = stager
            .staged_hashes()
            .filter(|hash| {
                let on_branch = tree
                    .lookup(*hash)
                    .and_then(|node_id| tree.node(node_id).ok())
                    .map(|node| is_on_request_branch(node.hash, node.height));
                on_branch != Some(true)
            })
            .collect();
        for hash in stale_staged {
            stager.discard(&hash);
        }

        self.next_request_height = request_start_height;
        self.stall = None;
        self.cold_front = None;
        self.cold_hedged_fronts.clear();
        self.prefix_probe = None;
        self.prefix_probe_attempted_owner = None;
        self.pending_timeout_observation = None;
    }

    fn extend_request_by_reverse_scan(
        &self,
        stager: &BlockStager,
        chain_tip: &TipSnapshot,
        tree: &BlockTree,
        scan: RequestScan,
        selected_hashes: Option<&SelectedHashes>,
        entries: &mut Vec<PeerRequestEntry>,
        refusals: &mut RefusalFilter,
    ) -> u32 {
        if scan.remaining_limit == 0 {
            return scan.next_request_height;
        }
        let mut next_request_height = scan.next_request_height;
        let skipped_hashes = self
            .pending
            .len()
            .saturating_add(stager.received_len())
            .saturating_add(selected_hashes.map_or(0, SelectedHashes::len));
        let scan_limit = scan.remaining_limit.saturating_add(skipped_hashes);
        let scan_span = u32::try_from(scan_limit.saturating_sub(1)).unwrap_or(u32::MAX);
        let request_end_height = scan
            .height
            .saturating_add(scan_span)
            .min(scan.request_tip_height);
        let Some(mut cursor) = tree.node_at_height_from(chain_tip.tip_id, request_end_height)
        else {
            return scan.next_request_height;
        };
        let mut candidates = Vec::with_capacity(scan_limit);
        while let Ok(node) = tree.node(cursor) {
            if node.height < scan.height {
                break;
            }
            if !self.pending.contains_key(&node.hash)
                && !stager.contains(&node.hash)
                && selected_hashes.is_none_or(|hashes| !hashes.contains(&node.hash))
            {
                if refusals.keep(node.hash, node.height) {
                    candidates.push(PeerRequestEntry {
                        hash: node.hash,
                        height: node.height,
                    });
                }
            }
            let Some(parent) = node.parent else {
                break;
            };
            cursor = parent;
        }
        let scanned_all_eligible = candidates.len() < scan.remaining_limit;
        let first_selected = candidates.len().saturating_sub(scan.remaining_limit);
        for entry in candidates[first_selected..].iter().rev().copied() {
            next_request_height = next_request_height.max(entry.height.saturating_add(1));
            entries.push(entry);
        }
        if scanned_all_eligible {
            next_request_height =
                next_request_height.max(scan.request_tip_height.saturating_add(1));
        }
        next_request_height
    }

    fn expired_request_entries(
        &self,
        stager: &BlockStager,
        expired: Vec<PeerRequestEntry>,
        batch_limit: usize,
        servable_floor: u32,
        byte_capacity: &mut usize,
        refusals: &mut RefusalFilter,
    ) -> Vec<PeerRequestEntry> {
        let mut entries = Vec::with_capacity(batch_limit);
        for entry in expired {
            if entries.len() >= batch_limit || *byte_capacity < self.ewma_block_bytes {
                break;
            }
            if !refusals.keep(entry.hash, entry.height) {
                continue;
            }
            if entry.height < servable_floor
                || stager.contains(&entry.hash)
                || self.pending.contains_key(&entry.hash)
            {
                continue;
            }
            *byte_capacity = byte_capacity.saturating_sub(self.ewma_block_bytes);
            entries.push(entry);
        }
        entries
    }

    fn clean_contiguous_peer_request(
        &self,
        stager: &BlockStager,
        source: PeerSource,
        chain_tip: &TipSnapshot,
        tree: &BlockTree,
        scan: RequestScan,
        refusals: &mut RefusalFilter,
    ) -> Option<PeerRequest> {
        if !self.pending.is_empty() || stager.received_len() > 0 {
            return None;
        }
        let span = u32::try_from(scan.remaining_limit.saturating_sub(1)).unwrap_or(u32::MAX);
        let request_end_height = scan
            .height
            .saturating_add(span)
            .min(scan.request_tip_height);
        let entries =
            contiguous_request_entries(tree, chain_tip.tip_id, scan.height, request_end_height)?;
        // A refused body inside the range falls through to the reverse scan,
        // which excludes it per entry and pins the cursor at its height. The
        // loop never short-circuits: every refused height contends for the
        // pin even though the range is rebuilt below.
        let mut has_refused = false;
        for entry in &entries {
            has_refused |= !refusals.keep(entry.hash, entry.height);
        }
        if has_refused {
            return None;
        }
        let next_request_height = scan
            .next_request_height
            .max(request_end_height.saturating_add(1));
        non_empty_request(source, entries, next_request_height)
    }

    fn record_prefix_probe_delivery(
        &mut self,
        hash: Hash256,
        delivery_peer: Option<PeerSource>,
        now: Instant,
    ) {
        let Some(mut probe) = self.prefix_probe.take() else {
            return;
        };
        let Some(index) = probe.hashes.iter().position(|candidate| *candidate == hash) else {
            self.prefix_probe = Some(probe);
            return;
        };
        let Ok(shift) = u32::try_from(index) else {
            self.prefix_probe = Some(probe);
            return;
        };
        let bit = 1_u8 << shift;
        probe.accepted |= bit;
        if let Some(progress) = delivery_peer.and_then(|peer| probe.racers.get_mut(&peer)) {
            *progress |= bit;
        }
        let win_mask = PREFIX_PROBE_WIN_MASK;
        let winner = probe
            .racers
            .iter()
            .find_map(|(peer, progress)| ((*progress & win_mask) == win_mask).then_some(*peer));
        let Some(winner) = winner else {
            if probe.accepted & win_mask != win_mask {
                self.prefix_probe = Some(probe);
            }
            return;
        };
        let owner = probe.owner;
        self.cold_front = None;
        self.pending_timeout_observation = None;
        self.retain_peer_assignments(|peer| *peer == winner || !probe.racers.contains_key(peer));
        if winner != owner {
            self.mark_peer_unresponsive(owner, now);
        }
        self.preferred_peer = Some(winner);
        tracing::info!(
            owner = ?owner.endpoint,
            winner = ?winner.endpoint,
            winner_is_owner = winner == owner,
            blocks = probe.hashes.len(),
            elapsed_ms = u64::try_from(now.duration_since(probe.started_at).as_millis()).unwrap_or(u64::MAX),
            "block sync: prefix probe elected winner"
        );
    }

    fn resolve_cold_front_delivery(
        &mut self,
        hash: Hash256,
        delivery_peer: Option<PeerSource>,
        now: Instant,
    ) {
        let Some(state) = self.cold_front else {
            return;
        };
        match state {
            ColdFrontState::Waiting {
                hash: waiting_hash, ..
            } if waiting_hash == hash => {
                self.cold_front = None;
            }
            ColdFrontState::Racing {
                owner,
                alternate,
                hash: racing_hash,
            } if racing_hash == hash => {
                self.cold_front = None;
                if delivery_peer != Some(alternate) {
                    return;
                }
                self.prefix_probe = None;
                self.retain_peer_assignments(|peer| *peer != owner);
                self.mark_peer_unresponsive(owner, now);
                self.preferred_peer = Some(alternate);
                tracing::info!(
                    owner = ?owner.endpoint,
                    winner = ?alternate.endpoint,
                    %hash,
                    "block sync: cold-front hedge elected alternate"
                );
            }
            _ => {}
        }
    }

    /// Records that `request` has been sent to `owner`, moving entries to
    /// pending under that exact connection's ownership.
    ///
    /// PRE: `stager` is the coupled staging set; no entry of `request` is
    ///      pending or staged.
    /// POST: every entry is pending under `owner`; the return value states
    ///      whether the window still has request capacity.
    /// INVARIANT: staged membership is read from `stager`.
    pub(crate) fn mark_requested(
        &mut self,
        stager: &BlockStager,
        request: &PeerRequest,
        owner: PeerSource,
        now: Instant,
    ) -> bool {
        if self.pending.is_empty() && !request.entries.is_empty() {
            self.prefix_probe_attempted_owner = None;
        }
        let estimated_bytes = self.ewma_block_bytes;
        for entry in &request.entries {
            debug_assert!(!self.pending.contains_key(&entry.hash));
            debug_assert!(!stager.contains(&entry.hash));
            let previous = self.pending.insert(
                entry.hash,
                PendingBlock {
                    owner,
                    requested_at: now,
                    height: entry.height,
                    estimated_bytes,
                },
            );
            debug_assert!(previous.is_none());
            self.pending_bytes = self.pending_bytes.saturating_add(estimated_bytes);
        }
        self.pending_blocks_high_water = self.pending_blocks_high_water.max(self.pending.len());
        self.pending_bytes_high_water = self.pending_bytes_high_water.max(self.pending_bytes);
        if !request.entries.is_empty() {
            self.owner_downloading_since.entry(owner).or_insert(now);
        }
        self.next_request_height = self.next_request_height.max(request.next_request_height);
        self.has_request_capacity(stager)
    }

    /// Records a delivery: pending release, source credit, EWMA byte
    /// estimate. Staging itself is the [`BlockStager`]'s job.
    ///
    /// PRE: `hash` was staged by the caller, or was never requested.
    /// POST: returns the height the pending carried at removal; `None` means
    ///   the delivery was not pending. No staged state is written.
    /// INVARIANT: the window holds no staged-body bytes or counts.
    ///
    /// The source-attributed credit runs through [`Self::credit_delivery_from`];
    /// callers proving the source's connection is still current may also call
    /// it directly after an unattributed `mark_received_from(hash, bytes, None, _)`.
    pub(crate) fn mark_received_from(
        &mut self,
        hash: Hash256,
        bytes: usize,
        source_peer: Option<PeerSource>,
        now: Instant,
    ) -> Option<u32> {
        let pending = self.remove_pending(&hash, now);
        let pending_height = pending.map(|pending| pending.height);
        if let Some(source) = source_peer {
            self.credit_delivery_from(hash, source, pending_height, now);
        }
        self.ewma_block_bytes = self
            .ewma_block_bytes
            .saturating_mul(7)
            .saturating_add(bytes)
            / 8;
        self.ewma_block_bytes = self.ewma_block_bytes.max(80);
        pending_height
    }

    /// Releases whatever the window holds for `hash` and makes it
    /// requestable again.
    ///
    /// PRE: `height`, when known, is the tree height of `hash`.
    /// POST: a pending for `hash` is released; the request cursor is lowered
    ///   to the lower of `height` and the released pending's height, when
    ///   either is known; the owner's queue start follows the removal rules
    ///   of [`Self::reset_owner_queue_start`].
    /// INVARIANT: every rewind target is a tree height (the caller's, or the
    ///   one the pending recorded at request time); a body of unknown height
    ///   with no pending never moves the cursor, so the height-0 rewind to
    ///   genesis is unrepresentable.
    pub(crate) fn requeue_for_retry(&mut self, hash: &Hash256, height: Option<u32>, now: Instant) {
        let pending_height = self.remove_pending(hash, now).map(|pending| pending.height);
        let target = match (height, pending_height) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (known, None) | (None, known) => known,
        };
        if let Some(target) = target {
            self.next_request_height = self.next_request_height.min(target);
        }
    }

    /// The request cursor: the lowest height not yet scanned or offered.
    #[cfg(test)]
    pub(crate) fn request_cursor(&self) -> u32 {
        self.next_request_height
    }

    /// The owner's live queue start, for in-crate tests that pin queue-age
    /// bookkeeping across sync seams.
    #[cfg(test)]
    pub(crate) fn owner_queue_start_for_test(&self, owner: PeerSource) -> Option<Instant> {
        self.owner_downloading_since.get(&owner).copied()
    }

    /// The source-attributed share of a staged delivery: pending-timeout,
    /// cold-front, and prefix-probe resolution plus stall-episode progress,
    /// all under the delivering connection's exact identity. `pending_height`
    /// is the height the pending carried at removal — `None` for an
    /// unsolicited delivery, which carries no progress credit.
    pub(crate) fn credit_delivery_from(
        &mut self,
        hash: Hash256,
        source: PeerSource,
        pending_height: Option<u32>,
        now: Instant,
    ) {
        if self
            .pending_timeout_observation
            .is_some_and(|observation| observation.hash == hash && observation.owner == source)
        {
            self.pending_timeout_observation = None;
        }
        self.resolve_cold_front_delivery(hash, Some(source), now);
        self.record_prefix_probe_delivery(hash, Some(source), now);
        if let Some(height) = pending_height {
            self.record_delivery_progress(source, hash, height, now);
        }
    }

    /// Credits a duplicate after the first copy was already staged.
    ///
    /// The first copy owns all byte, EWMA, cold-front and probe accounting.
    pub(crate) fn credit_duplicate_delivery(&mut self, hash: Hash256, source: PeerSource) {
        if self
            .pending_timeout_observation
            .is_some_and(|observation| observation.hash == hash && observation.owner == source)
        {
            self.pending_timeout_observation = None;
        }
    }

    /// Records delivery after removing `hash` from pending.
    ///
    /// Any requested body from the exact blamed connection clears its stall; other
    /// connections, including same-address replacements, do not. Front-only credit
    /// would falsely blame slow peers still streaming into a saturated window.
    ///
    /// A front advance samples cadence, excluding same-chunk `EWMA_MIN_SAMPLE_MS`
    /// artifacts, and decays the threshold by 0.85 toward `stall_decay_floor`.
    /// Gradual decay preserves the raised threshold across peer rotation after fire.
    fn record_delivery_progress(
        &mut self,
        source: PeerSource,
        hash: Hash256,
        height: u32,
        now: Instant,
    ) {
        if self
            .stall
            .is_some_and(|episode| episode.owner == source || episode.front_hash == hash)
        {
            self.stall = None;
            count_stall_episode_cleared("peer_delivery");
        }
        let was_front = self.pending.values().all(|pending| pending.height > height);
        if was_front {
            if let Some(previous) = self.last_front_advance {
                let sample_ms =
                    u64::try_from(now.duration_since(previous).as_millis()).unwrap_or(u64::MAX);
                // Batch artifacts are not cadence: an in-order front run
                // processed in one chunk shares the chunk's single timestamp
                // (see `EWMA_MIN_SAMPLE_MS`), so sub-threshold samples are
                // skipped entirely — never averaged in, never seeding. The
                // anchor below still moves to `now` (all batched advances
                // share it), so the next genuine sample correctly measures
                // from the batch.
                if sample_ms >= EWMA_MIN_SAMPLE_MS {
                    self.front_interval_ewma_ms = Some(match self.front_interval_ewma_ms {
                        None => sample_ms,
                        Some(ewma_ms) if sample_ms >= ewma_ms => {
                            ewma_ms.saturating_add((sample_ms - ewma_ms) / 4)
                        }
                        Some(ewma_ms) => ewma_ms - (ewma_ms - sample_ms) / 4,
                    });
                }
            }
            self.last_front_advance = Some(now);
            self.stall_timeout =
                (self.stall_timeout.saturating_mul(85) / 100).max(self.stall_decay_floor());
        }
    }

    #[cfg(test)]
    pub(crate) const fn front_interval_ewma_ms(&self) -> Option<u64> {
        self.front_interval_ewma_ms
    }

    /// Test-only cold-start disarm: installs a front-cadence estimate as if the network
    /// had demonstrated `ewma_ms` with its last front advance at `now`.
    ///
    /// Sync-layer tests whose fixtures never advance the window front use this instead
    /// of replaying two real front deliveries.
    #[cfg(test)]
    pub(crate) const fn seed_front_cadence_for_test(&mut self, ewma_ms: u64, now: Instant) {
        self.front_interval_ewma_ms = Some(ewma_ms);
        self.last_front_advance = Some(now);
    }

    /// Rejects a malformed block delivery, source-aware.
    ///
    /// When the delivering peer owns the pending request for `hash`, the
    /// pending is released so the block becomes re-requestable from a
    /// different peer. When a different peer delivers the malformed body
    /// unsolicited, the body is discarded and any existing pending request is
    /// preserved — the original owner may still supply the correct body.
    ///
    /// The malformed body was never staged, so the stager is not touched.
    pub(crate) fn reject_delivery(
        &mut self,
        hash: Hash256,
        source_peer: Option<PeerSource>,
        now: Instant,
    ) -> RejectDelivery {
        if self.pending_timeout_observation.is_some_and(|observation| {
            observation.hash == hash && Some(observation.owner) == source_peer
        }) {
            self.pending_timeout_observation = None;
        }

        // A rejected race participant cannot remain eligible to complete the
        // cold-front race. Clear the episode without electing a winner or
        // blaming either peer; a later observation may arm another hedge.
        if self.cold_front.is_some_and(|state| match state {
            ColdFrontState::Waiting {
                owner,
                hash: waiting_hash,
                ..
            } => waiting_hash == hash && Some(owner) == source_peer,
            ColdFrontState::Racing {
                owner,
                alternate,
                hash: racing_hash,
            } => {
                racing_hash == hash
                    && source_peer.is_some_and(|peer| peer == owner || peer == alternate)
            }
        }) {
            self.cold_front = None;
        }

        let is_owner = self
            .pending
            .get(&hash)
            .is_some_and(|pending| Some(pending.owner) == source_peer);
        if is_owner {
            if let Some(pending) = self.remove_pending(&hash, now) {
                self.next_request_height = self.next_request_height.min(pending.height);
            }
            RejectDelivery::ReleasedPending
        } else {
            RejectDelivery::DiscardedUnsolicited
        }
    }

    fn expire_pending(&mut self, now: Instant) -> Vec<PeerRequestEntry> {
        let timeout = self.effective_owner_timeout(self.active_downloading_peers());
        let expired_owners: HashSet<PeerSource> = self
            .owner_downloading_since
            .iter()
            .filter(|(_, since)| now.duration_since(**since) >= timeout)
            .map(|(owner, _)| *owner)
            .collect();
        if expired_owners.is_empty() {
            return Vec::new();
        }
        let mut entries = Vec::new();
        let mut removed: Vec<(PeerSource, Instant)> = Vec::new();
        let armed_observation = &mut self.pending_timeout_observation;
        {
            let pending_bytes = &mut self.pending_bytes;
            let next_request_height = &mut self.next_request_height;
            for (hash, pending) in self
                .pending
                .extract_if(|_hash, pending| expired_owners.contains(&pending.owner))
            {
                if let Some(observation) = armed_observation
                    && observation.hash == hash
                    && observation.owner == pending.owner
                {
                    observation.expired_release = true;
                }
                *pending_bytes = pending_bytes.saturating_sub(pending.estimated_bytes);
                *next_request_height = (*next_request_height).min(pending.height);
                entries.push(PeerRequestEntry {
                    hash,
                    height: pending.height,
                });
                removed.push((pending.owner, pending.requested_at));
            }
        }
        for (owner, requested_at) in removed {
            self.reset_owner_queue_start(owner, requested_at, now);
        }
        entries
    }

    /// Tracks an already-issued compact/fallback fetch without advancing the window's
    /// request frontier.
    ///
    /// Delivery resolves it; expiry/disconnect returns it to normal scheduling. Apply
    /// ordinary window/per-peer capacity bounds and refuse below-frontier heights so
    /// expiry cannot rewind over applied work. On refusal the caller retains deferred
    /// ownership, ensuring fast delivery still counts as requested.
    pub(crate) fn mark_owned_fetch(
        &mut self,
        stager: &mut BlockStager,
        owner: PeerSource,
        hash: Hash256,
        height: u32,
        now: Instant,
    ) -> bool {
        if self.pending.contains_key(&hash) {
            return true;
        }
        if stager.contains(&hash) {
            // The fetch's body is already staged: the owned fetch is its
            // request evidence, so the body counts as requested and owes
            // no unrequested-admission gate.
            stager.clear_gate_pending(&hash);
            return true;
        }
        if height < self.next_request_height
            || !self.has_request_capacity(stager)
            || self.pending_count_for(owner) >= self.effective_peer_inflight()
        {
            return false;
        }
        let request = PeerRequest {
            owner,
            entries: vec![PeerRequestEntry { hash, height }],
            next_request_height: 0,
        };
        // `mark_requested` re-enables `prefix_probe_attempted_owner` when
        // pending was empty — that re-arm is for a real post-drain request.
        // An externally owned fetch is not one: keep the marker so a
        // proven-stall owner stays ineligible for the next prefix probe.
        let attempted_owner = self.prefix_probe_attempted_owner;
        self.mark_requested(stager, &request, owner, now);
        self.prefix_probe_attempted_owner = attempted_owner;
        true
    }

    /// Releases `hash`'s pending entry without rewinding the request cursor:
    /// drop-only release for hashes that must never be re-requested
    /// (invalidated subtrees).
    pub(crate) fn release_pending(&mut self, hash: &Hash256, now: Instant) {
        let _ = self.remove_pending(hash, now);
    }

    fn remove_pending(&mut self, hash: &Hash256, now: Instant) -> Option<PendingBlock> {
        let pending = self.pending.remove(hash)?;
        self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
        self.reset_owner_queue_start(pending.owner, pending.requested_at, now);
        Some(pending)
    }

    /// Live requests owned by `source`. Derived from `pending`; the window
    /// keeps no shadow count.
    ///
    /// PRE: expiry has run this tick, so `pending` holds only live in-flight
    ///   requests.
    /// POST: returns the number of `pending` values with `owner == source`.
    /// INVARIANT: source-exact, so a same-address predecessor's share never
    ///   reduces a replacement's headroom.
    fn pending_count_for(&self, source: PeerSource) -> usize {
        self.pending
            .values()
            .filter(|pending| pending.owner == source)
            .count()
    }

    /// Distinct owner addresses holding live requests: how many peers the
    /// tick's request scan must reach in addition to fresh capacity.
    ///
    /// PRE: expiry has run this tick.
    /// POST: returns the number of distinct `pending.owner.endpoint` values.
    /// INVARIANT: each address counts once, however many requests it owns.
    fn owner_address_count(&self) -> usize {
        let mut owners: SmallVec<[Option<crate::PeerEndpoint>; 16]> = SmallVec::new();
        for pending in self.pending.values() {
            if !owners.contains(&pending.owner.endpoint) {
                owners.push(pending.owner.endpoint);
            }
        }
        owners.len()
    }
}

/// Outcome of rejecting a malformed block delivery.
///
/// The window decides whether the delivering peer owned the pending request.
/// Only the owner's malformed delivery releases the pending slot so the block
/// becomes re-requestable; an unsolicited malformed body from a different peer
/// is discarded without disturbing the in-flight request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RejectDelivery {
    /// The pending owner delivered the malformed body. Its pending request was
    /// released so the block can be re-requested from a different peer. Any
    /// matching timeout observation and cold-front race participation are
    /// cleared for a peer that demonstrably responded.
    ReleasedPending,
    /// A peer other than the pending owner delivered the malformed body
    /// (or no pending existed). The body is discarded; any existing pending
    /// request is preserved.
    DiscardedUnsolicited,
}

fn non_empty_request(
    owner: PeerSource,
    entries: Vec<PeerRequestEntry>,
    next_request_height: u32,
) -> Option<PeerRequest> {
    (!entries.is_empty()).then_some(PeerRequest {
        owner,
        entries,
        next_request_height,
    })
}

fn contiguous_request_entries(
    tree: &BlockTree,
    tip_id: bitcoin_rs_chain::NodeId,
    start_height: u32,
    end_height: u32,
) -> Option<Vec<PeerRequestEntry>> {
    let mut cursor = tree.node_at_height_from(tip_id, end_height)?;
    let capacity =
        usize::try_from(end_height.saturating_sub(start_height).saturating_add(1)).ok()?;
    let mut entries = Vec::with_capacity(capacity);
    while let Ok(node) = tree.node(cursor) {
        if node.height < start_height {
            break;
        }
        entries.push(PeerRequestEntry {
            hash: node.hash,
            height: node.height,
        });
        if node.height == start_height {
            entries.reverse();
            return Some(entries);
        }
        cursor = node.parent?;
    }
    None
}

#[cfg(test)]
mod tests;
