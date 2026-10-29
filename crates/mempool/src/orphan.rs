//! Gateway-owned peer orphan lifecycle.
//!
//! Retention, witness identity, and retry invariants are owned by `MPL-04`
//! in `docs/contracts/mempool-mutations.md`.

use crate::mutation::PeerToken;
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use bitcoin_rs_primitives::{Hash256, Tx, Txid, Wtxid};
use hashbrown::{HashMap, HashSet};

const DEFAULT_ORPHAN_QUOTA: usize = 100;
/// Aggregate BIP141 weight budget for resident orphan bodies.
const DEFAULT_MAX_ORPHAN_WEIGHT: u64 = 10_000_000;
/// Resident peer bodies are reconsidered for at most two minutes.
const DEFAULT_ORPHAN_TIMEOUT_SECS: u64 = 2 * 60;
const DEFAULT_REJECT_CAP: usize = 100_000;
/// Announcements one peer may hold before its usage score passes one.
const DEFAULT_PEER_ANNOUNCEMENTS: usize = 100;
/// Orphan weight one peer may reserve before its usage score passes one.
const DEFAULT_PEER_ANNOUNCEMENT_WEIGHT: u128 = 1_000_000;
/// Latency one peer may accumulate before its latency score passes one.
const DEFAULT_PEER_LATENCY: u128 = 1_000;

/// Whether a failure applies to the base transaction or only this witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RejectScope {
    Transaction,
    Witness,
}

/// One resident orphan body and every peer that announced it.
#[derive(Clone, Debug)]
pub(crate) struct HeldOrphan {
    pub(crate) tx: Arc<Tx>,
    /// Exact-connection tokens that announced this body. A body stays resident
    /// while at least one announcer remains live.
    pub(crate) announcers: HashSet<PeerToken>,
    /// First-seen wall-clock timestamp supplied by the admission caller.
    arrival_time: u64,
}

/// One queued reconsideration of a resident body for one selected announcer.
#[derive(Debug)]
struct OrphanRetryClaim {
    wtxid: Wtxid,
    announcer: PeerToken,
}

/// Per-peer consumption of orphan residency, charged once per announcement.
#[derive(Clone, Debug, Default)]
struct PeerUsage {
    announcements: usize,
    weight: u64,
    latency: u64,
    /// This peer's announcements in the order it made them. A body's global
    /// FIFO slot predates every later announcer, so per-peer eviction order
    /// cannot ride on shared insertion order.
    announced: VecDeque<Wtxid>,
}

/// One peer's allowance for each resource an announcement consumes. A peer at
/// or below every allowance scores at most one.
#[derive(Clone, Copy, Debug)]
struct PeerAllowance {
    announcements: u128,
    weight: u128,
    latency: u128,
}

impl PeerAllowance {
    fn new(announcements: usize, weight: u128, latency: u128) -> Self {
        Self {
            announcements: u128::try_from(announcements).unwrap_or(1).max(1),
            weight: weight.max(1),
            latency: latency.max(1),
        }
    }
}

impl PeerUsage {
    /// Core's per-peer `DoS` rank: the largest share of any allowance this peer
    /// consumes. Each share is scaled by the other two allowances so the
    /// comparison stays in exact integers.
    fn rank(&self, allowance: &PeerAllowance) -> u128 {
        let announcements = u128::try_from(self.announcements)
            .unwrap_or(u128::MAX)
            .saturating_mul(allowance.weight)
            .saturating_mul(allowance.latency);
        let weight = u128::from(self.weight)
            .saturating_mul(allowance.announcements)
            .saturating_mul(allowance.latency);
        let latency = u128::from(self.latency)
            .saturating_mul(allowance.announcements)
            .saturating_mul(allowance.weight);
        announcements.max(weight).max(latency)
    }
}

#[derive(Debug)]
pub(crate) struct OrphanPool {
    entries: HashMap<Wtxid, HeldOrphan>,
    by_parent: HashMap<Txid, HashSet<Wtxid>>,
    ready: VecDeque<OrphanRetryClaim>,
    ready_ids: HashSet<Wtxid>,
    peer_usage: HashMap<PeerToken, PeerUsage>,
    peer_allowance: PeerAllowance,
    quota: usize,
    total_weight: u64,
    max_weight: u64,
}

impl OrphanPool {
    pub(crate) fn new(quota: usize) -> Self {
        Self::with_limits(
            quota,
            DEFAULT_MAX_ORPHAN_WEIGHT,
            DEFAULT_PEER_ANNOUNCEMENTS,
            DEFAULT_PEER_ANNOUNCEMENT_WEIGHT,
            DEFAULT_PEER_LATENCY,
        )
    }

    fn with_limits(
        quota: usize,
        max_weight: u64,
        peer_announcements: usize,
        peer_weight: u128,
        peer_latency: u128,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            by_parent: HashMap::new(),
            ready: VecDeque::new(),
            ready_ids: HashSet::new(),
            peer_usage: HashMap::new(),
            peer_allowance: PeerAllowance::new(peer_announcements, peer_weight, peer_latency),
            quota,
            total_weight: 0,
            max_weight,
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Residency of one exact witness identity. A txid never identifies a
    /// resident body: two bodies can share one txid.
    pub(crate) fn get(&self, wtxid: Wtxid) -> Option<&HeldOrphan> {
        self.entries.get(&wtxid)
    }

    /// One arbitrary resident variant of a txid, for tests and retry
    /// selection only. Inventory suppression must never consult it.
    #[cfg(test)]
    fn get_by_txid(&self, txid: Txid) -> Option<&HeldOrphan> {
        self.entries.values().find(|held| held.tx.txid() == txid)
    }

    /// PRE: `claim` and `announcer` name one pair this pool issued.
    pub(crate) fn is_current(&self, claim: &HeldOrphan, announcer: &PeerToken) -> bool {
        self.entries.get(&claim.tx.wtxid()).is_some_and(|current| {
            current.announcers.contains(announcer) && Arc::ptr_eq(&current.tx, &claim.tx)
        })
    }

    /// PRE: `wtxid` may name a resident body; `announcer` is an exact
    /// connection token.
    /// POST: the pair is recorded exactly once. The body, its first-seen time,
    /// its FIFO position and the resident weight stay unchanged. False when
    /// the body is absent or the pair was already recorded.
    fn add_announcer(&mut self, wtxid: Wtxid, announcer: PeerToken) -> bool {
        let charge = {
            let Some(held) = self.entries.get_mut(&wtxid) else {
                return false;
            };
            if !held.announcers.insert(announcer) {
                return false;
            }
            (held.tx.weight(), Self::latency_score(&held.tx))
        };
        self.charge(&announcer, wtxid, charge.0, charge.1);
        true
    }

    /// Stores one peer-origin body together with the peer that announced it.
    pub(crate) fn insert(&mut self, tx: Arc<Tx>, announcer: PeerToken, time: u64) {
        let wtxid = tx.wtxid();
        if self.entries.contains_key(&wtxid) {
            self.add_announcer(wtxid, announcer);
        } else {
            for input in &tx.inputs {
                let prevout = input.previous_output;
                if !prevout.is_null() {
                    self.by_parent
                        .entry(prevout.txid)
                        .or_default()
                        .insert(wtxid);
                }
            }
            let weight = tx.weight();
            let latency = Self::latency_score(&tx);
            self.total_weight = self.total_weight.saturating_add(weight);
            self.entries.insert(
                wtxid,
                HeldOrphan {
                    tx,
                    announcers: HashSet::from([announcer]),
                    arrival_time: time,
                },
            );
            self.charge(&announcer, wtxid, weight, latency);
        }
        self.evict_to_limits();
    }

    /// Removes the body with this exact witness identity, every announcer of
    /// it, and every index entry that named it.
    pub(crate) fn remove(&mut self, wtxid: Wtxid) -> Option<HeldOrphan> {
        let entry = self.entries.remove(&wtxid)?;
        self.total_weight = self.total_weight.saturating_sub(entry.tx.weight());
        self.unindex_parents(wtxid, &entry.tx);
        let weight = entry.tx.weight();
        let latency = Self::latency_score(&entry.tx);
        for announcer in &entry.announcers {
            self.refund(announcer, weight, latency);
        }
        self.clear_ready(wtxid);
        Some(entry)
    }

    /// Removes every resident body whose txid equals `txid`.
    pub(crate) fn remove_transaction_variants(&mut self, txid: Txid) {
        let variants: Vec<Wtxid> = self
            .entries
            .iter()
            .filter(|(_, held)| held.tx.txid() == txid)
            .map(|(wtxid, _)| *wtxid)
            .collect();
        for wtxid in variants {
            self.remove(wtxid);
        }
    }

    /// PRE: `wtxid` may name a resident body; `preferred` may be one of its
    /// announcers.
    pub(crate) fn mark_ready(&mut self, wtxid: Wtxid, preferred: PeerToken) {
        let announcer = {
            let Some(held) = self.entries.get(&wtxid) else {
                return;
            };
            if held.announcers.contains(&preferred) {
                preferred
            } else {
                let Some(selected) = Self::select_announcer(&held.announcers) else {
                    return;
                };
                selected
            }
        };
        if self.ready_ids.insert(wtxid) {
            self.ready.push_back(OrphanRetryClaim { wtxid, announcer });
        }
    }

    /// Makes every resident body spending an output of `parent` eligible for
    /// reconsideration.
    pub(crate) fn parent_ready(&mut self, parent: Txid) {
        let claims: Vec<(Wtxid, PeerToken)> = self
            .by_parent
            .get(&parent)
            .map(|children| {
                children
                    .iter()
                    .filter_map(|wtxid| {
                        let held = self.entries.get(wtxid)?;
                        Some((*wtxid, Self::select_announcer(&held.announcers)?))
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (wtxid, announcer) in claims {
            self.mark_ready(wtxid, announcer);
        }
    }

    /// Schedules one reconsideration for every currently resident witness identity.
    /// Existing residency limits bound the temporary list, and `mark_ready` merges
    /// it with pending work without duplicating a body or resetting its lifetime.
    pub(crate) fn mark_all_ready(&mut self) {
        let claims: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(wtxid, held)| Some((*wtxid, Self::select_announcer(&held.announcers)?)))
            .collect();
        for (wtxid, announcer) in claims {
            self.mark_ready(wtxid, announcer);
        }
    }

    /// Claim one bounded snapshot. Bodies remain resident across transient
    /// failures.
    pub(crate) fn take_ready(&mut self) -> Vec<(HeldOrphan, PeerToken)> {
        self.ready_ids.clear();
        self.ready
            .drain(..)
            .filter_map(|claim| {
                let held = self.entries.get(&claim.wtxid)?;
                let announcer = if held.announcers.contains(&claim.announcer) {
                    claim.announcer
                } else {
                    Self::select_announcer(&held.announcers)?
                };
                Some((held.clone(), announcer))
            })
            .collect()
    }

    /// Removes expired bodies and the announcements of departed connections.
    pub(crate) fn maintain(&mut self, now: u64, live_peers: &HashSet<PeerToken>) -> usize {
        let expired: Vec<Wtxid> = self
            .entries
            .iter()
            .filter_map(|(wtxid, held)| {
                let expired = now.saturating_sub(held.arrival_time) >= DEFAULT_ORPHAN_TIMEOUT_SECS;
                expired.then_some(*wtxid)
            })
            .collect();
        let mut removed = 0;
        for wtxid in expired {
            if self.remove(wtxid).is_some() {
                removed += 1;
            }
        }
        let departed: Vec<(Wtxid, PeerToken)> = self
            .entries
            .iter()
            .flat_map(|(wtxid, held)| {
                held.announcers
                    .iter()
                    .filter(|announcer| !live_peers.contains(*announcer))
                    .map(|announcer| (*wtxid, *announcer))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (wtxid, announcer) in departed {
            if self.remove_announcer(wtxid, announcer) {
                removed += 1;
            }
        }
        removed
    }

    /// Drops one peer's announcement of one body.
    fn remove_announcer(&mut self, wtxid: Wtxid, announcer: PeerToken) -> bool {
        let charge = {
            let Some(held) = self.entries.get_mut(&wtxid) else {
                return false;
            };
            if !held.announcers.remove(&announcer) {
                return false;
            }
            (
                held.tx.weight(),
                Self::latency_score(&held.tx),
                held.announcers.is_empty(),
            )
        };
        self.refund(&announcer, charge.0, charge.1);
        if charge.2 {
            self.remove(wtxid);
            return true;
        }
        false
    }

    /// Restores both global bounds by trimming announcements of the highest
    /// scoring peer.
    fn evict_to_limits(&mut self) {
        while self.entries.len() > self.quota || self.total_weight > self.max_weight {
            let Some(victim) = self.highest_scoring_peer() else {
                break;
            };
            if !self.trim_oldest_announcement(victim) {
                break;
            }
        }
    }

    fn highest_scoring_peer(&self) -> Option<PeerToken> {
        self.peer_usage
            .iter()
            .max_by(|(left_peer, left), (right_peer, right)| {
                let rank = left
                    .rank(&self.peer_allowance)
                    .cmp(&right.rank(&self.peer_allowance));
                rank.then_with(|| {
                    (left_peer.connection_id, left_peer.endpoint)
                        .cmp(&(right_peer.connection_id, right_peer.endpoint))
                })
            })
            .map(|(peer, _)| *peer)
    }

    /// Drops the victim's oldest announcement in the order the victim made
    /// it, preferring work that is not ready for reconsideration. Entries the
    /// victim no longer announces are pruned here, so the scan stays
    /// proportional to the victim's live announcements.
    fn trim_oldest_announcement(&mut self, victim: PeerToken) -> bool {
        let target = {
            let mut ready_candidate: Option<Wtxid> = None;
            let mut found = None;
            let Some(usage) = self.peer_usage.get(&victim) else {
                return false;
            };
            for wtxid in &usage.announced {
                let Some(held) = self.entries.get(wtxid) else {
                    continue;
                };
                if !held.announcers.contains(&victim) {
                    continue;
                }
                if self.ready_ids.contains(wtxid) {
                    ready_candidate.get_or_insert(*wtxid);
                    continue;
                }
                found = Some(*wtxid);
                break;
            }
            found.or(ready_candidate)
        };
        let Some(wtxid) = target else {
            return false;
        };
        self.remove_announcer(wtxid, victim);
        if let Some(usage) = self.peer_usage.get_mut(&victim) {
            let entries = &self.entries;
            usage.announced.retain(|id| {
                entries
                    .get(id)
                    .is_some_and(|h| h.announcers.contains(&victim))
            });
        }
        true
    }

    fn charge(&mut self, announcer: &PeerToken, wtxid: Wtxid, weight: u64, latency: u64) {
        let usage = self.peer_usage.entry(*announcer).or_default();
        usage.announcements += 1;
        usage.weight = usage.weight.saturating_add(weight);
        usage.latency = usage.latency.saturating_add(latency);
        usage.announced.push_back(wtxid);
    }

    fn refund(&mut self, announcer: &PeerToken, weight: u64, latency: u64) {
        let drained = {
            let Some(usage) = self.peer_usage.get_mut(announcer) else {
                return;
            };
            usage.announcements = usage.announcements.saturating_sub(1);
            usage.weight = usage.weight.saturating_sub(weight);
            usage.latency = usage.latency.saturating_sub(latency);
            usage.announcements == 0
        };
        if drained {
            self.peer_usage.remove(announcer);
        }
    }

    /// Core's per-body latency charge: one per body plus one per ten inputs.
    fn latency_score(tx: &Tx) -> u64 {
        u64::try_from(tx.inputs.len() / 10)
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1)
    }

    /// Deterministic announcer choice: the earliest minted connection token.
    fn select_announcer(announcers: &HashSet<PeerToken>) -> Option<PeerToken> {
        announcers
            .iter()
            .copied()
            .min_by_key(|peer| (peer.connection_id, peer.endpoint))
    }

    fn unindex_parents(&mut self, wtxid: Wtxid, tx: &Tx) {
        for input in &tx.inputs {
            let parent = input.previous_output.txid;
            if let Some(children) = self.by_parent.get_mut(&parent) {
                children.remove(&wtxid);
                if children.is_empty() {
                    self.by_parent.remove(&parent);
                }
            }
        }
    }

    fn clear_ready(&mut self, wtxid: Wtxid) {
        if self.ready_ids.remove(&wtxid) {
            self.ready.retain(|claim| claim.wtxid != wtxid);
        }
    }

    #[cfg(test)]
    fn total_weight(&self) -> u64 {
        self.total_weight
    }
}

#[derive(Debug)]
pub(crate) struct AdmissionLifecycle {
    pub(crate) orphans: OrphanPool,
    rejects: HashMap<Hash256, RejectScope>,
    reject_order: VecDeque<Hash256>,
    reject_cap: usize,
}
impl Default for AdmissionLifecycle {
    fn default() -> Self {
        Self {
            orphans: OrphanPool::new(DEFAULT_ORPHAN_QUOTA),
            rejects: HashMap::new(),
            reject_order: VecDeque::new(),
            reject_cap: DEFAULT_REJECT_CAP,
        }
    }
}
impl AdmissionLifecycle {
    /// Caches one refusal and retires the resident work it covers.
    pub(crate) fn reject(&mut self, tx: &Tx, scope: RejectScope) {
        match scope {
            RejectScope::Witness => {
                self.orphans.remove(tx.wtxid());
            }
            RejectScope::Transaction => {
                self.orphans.remove_transaction_variants(tx.txid());
            }
        }
        self.cache_reject(Hash256::from(tx.wtxid()), RejectScope::Witness);
        if scope == RejectScope::Transaction {
            self.cache_reject(Hash256::from(tx.txid()), RejectScope::Transaction);
        }
        while self.reject_order.len() > self.reject_cap {
            if let Some(oldest) = self.reject_order.pop_front() {
                self.rejects.remove(&oldest);
            }
        }
    }
    fn cache_reject(&mut self, hash: Hash256, scope: RejectScope) {
        if let Some(existing) = self.rejects.get_mut(&hash) {
            if scope == RejectScope::Transaction {
                *existing = scope;
            }
        } else {
            self.rejects.insert(hash, scope);
            self.reject_order.push_back(hash);
        }
    }
    /// Base-invalid failures suppress all witnesses; other failures suppress
    /// only the body actually checked. A stripped body's wtxid may equal txid.
    pub(crate) fn rejects_transaction(&self, txid: Txid, wtxid: Wtxid) -> bool {
        self.rejects.get(&Hash256::from(txid)) == Some(&RejectScope::Transaction)
            || self.rejects.contains_key(&Hash256::from(wtxid))
    }
    pub(crate) fn rejects_inventory(&self, hash: Hash256, wtxid: bool) -> bool {
        self.rejects
            .get(&hash)
            .is_some_and(|scope| wtxid || *scope == RejectScope::Transaction)
    }
    #[cfg(any(test, feature = "test-seam"))]
    pub(crate) fn is_rejected(&self, hash: Hash256) -> bool {
        self.rejects.contains_key(&hash)
    }
    #[cfg(any(test, feature = "test-seam"))]
    pub(crate) fn rejects_len(&self) -> usize {
        self.rejects.len()
    }
    pub(crate) fn clear_rejects(&mut self) {
        self.rejects.clear();
        self.reject_order.clear();
    }
}

#[cfg(test)]
mod tests;
