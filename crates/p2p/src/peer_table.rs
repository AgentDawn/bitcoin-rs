//! Live peer-session table: the single owner of connection leases and the
//! handshake metadata published for them.
//!
//! One connection per remote address is live at a time. Registration replaces
//! and cancels any predecessor at the same address; every removal path checks
//! connection identity so a stale handle can never evict its successor. All
//! consumers (listener, connection threads, block sync, RPC) observe and
//! mutate peer sessions only through this type, so the registration,
//! replacement, and cancellation rules have exactly one implementation.

use crate::{PeerEndpoint, PeerRemote};
use std::hash::{BuildHasher, RandomState};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bitcoin::p2p::ServiceFlags;
use bitcoin_rs_primitives::{Hash256, Txid, Wtxid};
use hashbrown::HashMap;
use parking_lot::RwLock;

use crate::connection::{ConnectionId, OutboundRefusal, PeerLease, PeerSource};
use crate::counters::PeerCounters;
use crate::peer::CompactBlockNegotiation;
use crate::peer_info::PeerInfo;
#[cfg(test)]
use crate::peer_info::PeerRole;

/// One live connection joined with its handshake metadata.
#[derive(Clone, Debug)]
pub struct PeerSession {
    /// Logical peer endpoint; `None` for unidentified sessions.
    pub endpoint: Option<PeerEndpoint>,
    /// Logical remote Bitcoin endpoint.
    pub addr: PeerRemote,
    /// Control handle for the connection.
    pub lease: PeerLease,
    /// Handshake metadata, `None` while the handshake is still in progress.
    pub info: Option<PeerInfo>,
    /// Header tips this connection has delivered and the node accepted.
    pub(crate) demonstrated_tips: Vec<Hash256>,
    /// Headers tip this connection demonstrated by ending a download-twice
    /// sync with nothing past it — the cap header selection reads. `None`
    /// until a presync proves a ceiling; body eligibility keeps reading
    /// [`PeerInfo::best_known_height`], the P2P-03 credit this does not
    /// disturb.
    pub(crate) headers_horizon: Option<u32>,
    /// Whether we have currently selected this peer for high-bandwidth
    /// compact-block push — Core's `getpeerinfo.bip152_hb_to`: we asked the
    /// peer (via `sendcmpct(true)`) to announce new blocks to us as
    /// unsolicited `cmpctblock` instead of `inv`.
    pub bip152_hb_to: bool,
    /// Whether this peer has selected us for high-bandwidth compact-block
    /// push — Core's `getpeerinfo.bip152_hb_from`: the peer asked us (via
    /// its `sendcmpct(true)`) to announce new blocks to it as unsolicited
    /// `cmpctblock` instead of `inv`.
    pub bip152_hb_from: bool,
}

/// Announcement-relevant state owned by the live peer connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PeerAnnouncementState {
    pub(crate) last_announced_block: Option<Hash256>,
    pub(crate) compact_high_bandwidth: Option<bool>,
    pub(crate) compact_version: Option<u64>,
    pub(crate) useful_block_sequence: u64,
    /// Whether the announcement worker currently selects this peer for
    /// high-bandwidth push (`bip152_hb_to`). Selection authority lives in
    /// the worker; the table is the snapshot rpc reads, so promotions and
    /// demotions are written through here.
    pub(crate) selected_high_bandwidth: bool,
    /// Whether this peer negotiated BIP332 stale-tip relay, and its `prefers_blocks` flag.
    pub(crate) stale_tip_prefers_blocks: Option<bool>,
    /// The BIP331 `PKG_RELAY_*` bits the connection owner negotiated; `0`
    /// until published and whenever nothing was agreed.
    pub(crate) package_relay: u64,
}

#[derive(Debug)]
struct Entry {
    lease: PeerLease,
    info: Option<PeerInfo>,
    demonstrated_tips: Vec<Hash256>,
    headers_horizon: Option<u32>,
    announcement: PeerAnnouncementState,
    /// Core's `nKeyedNetGroup`, fixed at inbound admission; 0 for outbound.
    keyed_netgroup: u64,
    /// Recency of the last transaction from this connection the mempool
    /// accepted; 0 when there is none.
    useful_tx_sequence: u64,
    /// Service epoch for anonymous Tor inbound sessions; `None` for IP/I2P.
    #[cfg(test)]
    onion_epoch: Option<u64>,
}

impl Entry {
    fn fresh(lease: PeerLease) -> Self {
        Self {
            lease,
            info: None,
            demonstrated_tips: Vec::new(),
            headers_horizon: None,
            announcement: PeerAnnouncementState::default(),
            keyed_netgroup: 0,
            useful_tx_sequence: 0,
            #[cfg(test)]
            onion_epoch: None,
        }
    }

    fn session(&self, addr: PeerRemote) -> PeerSession {
        PeerSession {
            endpoint: addr.endpoint(),
            addr,
            lease: self.lease.clone(),
            info: self.info.clone(),
            demonstrated_tips: self.demonstrated_tips.clone(),
            headers_horizon: self.headers_horizon,
            bip152_hb_to: self.announcement.selected_high_bandwidth,
            bip152_hb_from: self.announcement.compact_high_bandwidth == Some(true),
        }
    }
}

/// The table's live entries plus the traffic accounting it retains of
/// dropped ones. Keeping both under the same lock makes removal linearizable
/// for `traffic_totals` readers: a connection's counter set is counted
/// exactly once, either in `map` or in `retired`/`settled_*`.
#[derive(Debug, Default)]
struct TableView {
    map: HashMap<PeerRemote, Entry>,
    /// Counter sets of dropped connections whose teardown may still be in
    /// flight.
    retired: Vec<Arc<PeerCounters>>,
    /// Final byte counts of fully torn-down retired connections.
    settled_recv: u64,
    settled_sent: u64,
}

impl std::ops::Deref for TableView {
    type Target = HashMap<PeerRemote, Entry>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl std::ops::DerefMut for TableView {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

fn live_sessions_of(entries: &TableView) -> Vec<PeerSource> {
    entries
        .iter()
        .filter(|(_, entry)| !entry.lease.is_cancelled())
        .map(|(key, entry)| entry.lease.source(key.endpoint()))
        .collect()
}

/// Authoritative table of live peer connections keyed by remote address.
#[derive(Debug, Default)]
pub struct PeerTable {
    entries: RwLock<TableView>,
    next_useful_block_sequence: AtomicU64,
    next_useful_tx_sequence: AtomicU64,
    /// Process-random key for inbound netgroups, so which netgroups eviction
    /// protects is unpredictable (Core `RANDOMIZER_ID_NETGROUP`).
    netgroup_key: RandomState,
    pub(crate) tx_policy: parking_lot::Mutex<crate::tx_policy::TxPolicy>,
}

impl PeerTable {
    /// Creates an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The transport owner revokes its epoch, then asks the table to wake only
    /// that epoch's leases. Connection owners retain identity-checked removal;
    /// neither a late teardown nor a replacement epoch can remove its successor.
    pub(crate) fn cancel_transport_epoch(&self, epoch: &Arc<AtomicBool>) {
        for entry in self.entries.read().values() {
            if entry.lease.belongs_to_transport_epoch(epoch) {
                entry.lease.cancel();
            }
        }
    }

    /// Registers `lease` as the live connection at `addr`, cancelling and
    /// replacing any predecessor. Returns whether a different connection was
    /// replaced; re-registering the same connection is a no-op that keeps its
    /// published metadata.
    pub fn register(&self, addr: impl Into<PeerRemote>, lease: PeerLease) -> bool {
        let addr = addr.into();
        Self::register_locked(&mut self.entries.write(), addr, Entry::fresh(lease))
    }

    /// Register an unidentified (anonymous) inbound session. Anonymous
    /// sessions coexist, are capacity-only, and never replace a known peer.
    ///
    /// Production inbound Tor reserves through `try_register_inbound` with
    /// `PeerRemote::AnonymousTor`; this helper remains for cross-crate test
    /// seams that enable `p2p/test-seam` in their development dependencies.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn register_unidentified(&self, lease: PeerLease) -> bool {
        let key = PeerRemote::AnonymousTor(lease.connection_id());
        let entry = Entry {
            keyed_netgroup: self
                .netgroup_key
                .hash_one(crate::endpoint::anonymous_netgroup(lease.connection_id())),
            ..Entry::fresh(lease)
        };
        Self::register_locked(&mut self.entries.write(), key, entry)
    }

    fn register_locked(entries: &mut TableView, addr: PeerRemote, entry: Entry) -> bool {
        match entries.get(&addr) {
            Some(current) if current.lease.same_connection(&entry.lease) => false,
            Some(_) => {
                let prior = entries.insert(addr, entry);
                if let Some(prior) = prior {
                    prior.lease.cancel();
                    Self::retain_traffic(entries, &prior);
                }
                true
            }
            None => {
                entries.insert(addr, entry);
                false
            }
        }
    }

    /// Register an outbound socket only while the service activity flag is enabled.
    /// Activity admission and connection replacement share the table write lock.
    /// Inactive admission or a cancelled lease (including a revoked transport
    /// epoch) returns `None` without changing the table.
    pub(crate) fn try_register_outbound(
        &self,
        addr: impl Into<PeerRemote>,
        lease: PeerLease,
        activity: &crate::NetworkActivity,
    ) -> Option<PeerLease> {
        let addr = addr.into();
        debug_assert!(!lease.is_inbound(), "only outbound leases register here");
        let mut entries = self.entries.write();
        if !activity.is_active() || lease.is_cancelled() {
            return None;
        }
        Self::register_locked(&mut entries, addr, Entry::fresh(lease.clone()));
        Some(lease)
    }

    /// Live inbound connections, including handshakes that have not
    /// published metadata yet.
    ///
    /// PRE: none.
    /// POST: returns the number of uncancelled leases whose identity is
    ///   inbound.
    /// INVARIANT: the count is always derived from the live entry set; no
    ///   separate inbound counter exists.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn live_inbound_count(&self) -> usize {
        Self::live_inbound_count_of(&self.entries.read())
    }

    fn live_inbound_count_of(entries: &TableView) -> usize {
        entries
            .values()
            .filter(|entry| entry.lease.is_inbound() && !entry.lease.is_cancelled())
            .count()
    }

    /// Reserves an inbound lease within the Core-derived inbound capacity,
    /// evicting an inbound connection as Core does when the capacity is
    /// full, and registers it as the live connection at `addr`.
    ///
    /// PRE: `lease.is_inbound()`, `netgroup` is the newcomer's netgroup from
    ///   [`crate::netgroup::NetGroups::group`], `max_inbound` is the resolved
    ///   automatic-connection remainder, and `best_block_depth` is
    ///   [`crate::listener::approximate_best_block_depth`].
    /// POST: inactive admission or a cancelled lease (including a revoked
    /// transport epoch) returns `None` without mutation, even for an
    ///   already registered lease. A lease at an address already holding a
    ///   LIVE inbound connection replaces and cancels it exactly as
    ///   [`Self::register`] does, which never grows the count. Any other
    ///   lease, including one over a cancelled predecessor (never counted),
    ///   grows the count: below `max_inbound` it is registered; at
    ///   `max_inbound` the connection [`crate::eviction`] selects is removed
    ///   and cancelled first. When nothing is selectable, or the address
    ///   holds a live outbound connection the newcomer would also replace,
    ///   it returns `None` and changes no table state.
    /// INVARIANT: the activity/count tests, eviction and reservation are one
    ///   `PeerTable` write operation; every reserved lease is counted until
    ///   its identity is removed.
    #[must_use]
    pub(crate) fn try_register_inbound(
        &self,
        addr: impl Into<PeerRemote>,
        lease: PeerLease,
        netgroup: &[u8],
        max_inbound: usize,
        best_block_depth: u64,
        activity: &crate::NetworkActivity,
    ) -> Option<PeerLease> {
        let addr = addr.into();
        debug_assert!(lease.is_inbound(), "only inbound leases reserve here");
        let mut entries = self.entries.write();
        if !activity.is_active() || lease.is_cancelled() {
            return None;
        }
        let key = addr;
        let grows_count = match entries.get(&key) {
            Some(current) => {
                if current.lease.same_connection(&lease) {
                    return Some(lease);
                }
                // A live inbound predecessor is displaced by this insert, so
                // the net count is unchanged. An outbound predecessor, or an
                // inbound one already cancelled (and therefore outside the
                // live count), leaves the new lease as a net addition.
                !current.lease.is_inbound() || current.lease.is_cancelled()
            }
            None => true,
        };
        if grows_count
            && Self::live_inbound_count_of(&entries) >= max_inbound
            && !Self::evict_inbound_locked(&mut entries, key, best_block_depth)
        {
            return None;
        }
        let entry = Entry {
            keyed_netgroup: self.netgroup_key.hash_one(netgroup),
            ..Entry::fresh(lease.clone())
        };
        Self::register_locked(&mut entries, key, entry);
        Some(lease)
    }

    /// Reserve an unidentified inbound session: capacity-only, coexists
    /// with known peers, never replaces by endpoint.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn try_register_inbound_unidentified(
        &self,
        lease: PeerLease,
        max_inbound: usize,
        best_block_depth: u64,
        activity: &crate::NetworkActivity,
        onion_epoch: Option<u64>,
    ) -> Option<PeerLease> {
        debug_assert!(lease.is_inbound(), "only inbound leases reserve here");
        let mut entries = self.entries.write();
        if !activity.is_active() {
            return None;
        }
        let key = PeerRemote::AnonymousTor(lease.connection_id());
        if entries
            .get(&key)
            .is_some_and(|c| c.lease.same_connection(&lease))
        {
            return Some(lease);
        }
        if Self::live_inbound_count_of(&entries) >= max_inbound
            && !Self::evict_inbound_locked(&mut entries, key, best_block_depth)
        {
            return None;
        }
        let entry = Entry {
            keyed_netgroup: self
                .netgroup_key
                .hash_one(crate::endpoint::anonymous_netgroup(lease.connection_id())),
            onion_epoch,
            ..Entry::fresh(lease.clone())
        };
        Self::register_locked(&mut entries, key, entry);
        Some(lease)
    }

    /// Makes room for an inbound newcomer at `addr` by removing the
    /// connection Core's `SelectNodeToEvict` chooses (`net.cpp:1819-1826`).
    /// Returns whether one was removed.
    fn evict_inbound_locked(
        entries: &mut TableView,
        addr: PeerRemote,
        best_block_depth: u64,
    ) -> bool {
        // The newcomer would also replace a live outbound connection at its
        // address, dropping two connections for one.
        if entries
            .get(&addr)
            .is_some_and(|current| !current.lease.is_inbound() && !current.lease.is_cancelled())
        {
            return false;
        }
        let candidates = entries
            .iter()
            .filter_map(|(addr, entry)| Self::eviction_candidate(*addr, entry, best_block_depth))
            .collect();
        let Some(victim_id) = crate::eviction::select_inbound_to_evict(candidates) else {
            return false;
        };
        // Eviction names a connection; the address key stays here.
        let Some(victim) = entries
            .iter()
            .find(|(key, _)| **key == victim_id)
            .map(|(key, _)| *key)
        else {
            return false;
        };
        if let Some(removed) = entries.remove(&victim) {
            removed.lease.cancel();
            Self::retain_traffic(entries, &removed);
        }
        tracing::debug!(peer_key = ?victim, "inbound slots full; evicted a connection for a new inbound peer");
        true
    }

    /// The eviction view of a live inbound connection without `NoBan`, the set
    /// Core's `ProtectNoBanConnections` and `ProtectOutboundConnections` leave.
    fn eviction_candidate(
        addr: PeerRemote,
        entry: &Entry,
        best_block_depth: u64,
    ) -> Option<crate::eviction::EvictionCandidate> {
        let lease = &entry.lease;
        if !lease.is_inbound() || lease.is_cancelled() || lease.is_no_ban() {
            return None;
        }
        let info = entry.info.as_ref();
        Some(crate::eviction::EvictionCandidate {
            addr,
            connected: lease.connected_at(),
            last_block: entry.announcement.useful_block_sequence,
            last_tx: entry.useful_tx_sequence,
            relevant_services: info.is_some_and(|info| {
                crate::listener::has_all_desirable_service_flags(
                    ServiceFlags::from(info.services),
                    best_block_depth,
                )
            }),
            relay_txs: info.is_some_and(|info| info.relay_transactions),
            keyed_netgroup: entry.keyed_netgroup,
            is_local: addr
                .endpoint()
                .is_some_and(|endpoint| crate::discouragement::is_local(endpoint.address())),
        })
    }

    /// Linearize the service-owned activity switch with real socket admission.
    /// Disabling cancels every lease already admitted; their owners remove them.
    /// Enabling permits fresh admission without reviving cancelled leases.
    pub(crate) fn set_network_active(&self, flag: &AtomicBool, active: bool) {
        let entries = self.entries.write();
        flag.store(active, Ordering::Release);
        if !active {
            for entry in entries.values() {
                entry.lease.cancel();
            }
        }
    }

    /// Publish info for an unidentified session (accept-only anonymous path):
    /// the anonymous key derives from the lease, so only that connection
    /// can publish or be resolved through it.
    pub fn publish_info_unidentified(&self, lease: &PeerLease, info: PeerInfo) -> bool {
        self.publish_info(PeerRemote::AnonymousTor(lease.connection_id()), lease, info)
    }

    /// Publishes handshake metadata for the connection `lease` refers to.
    pub fn publish_info(
        &self,
        addr: impl Into<PeerRemote>,
        lease: &PeerLease,
        info: PeerInfo,
    ) -> bool {
        let addr = addr.into();
        let mut entries = self.entries.write();
        match entries.get_mut(&addr) {
            Some(entry) if entry.lease.same_connection(lease) => {
                entry.info = Some(info);
                true
            }
            _ => false,
        }
    }

    /// Records that the live connection accepted `tip_hash` and raises its
    /// active-chain credit when `height` is supplied.
    pub(crate) fn note_announced_tip(
        &self,
        source: PeerSource,
        tip_hash: Hash256,
        height: Option<i32>,
    ) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        let Some(info) = entry.info.as_mut() else {
            return false;
        };
        if !entry.demonstrated_tips.contains(&tip_hash) {
            entry.demonstrated_tips.push(tip_hash);
        }
        if let Some(height) = height
            && height > info.best_known_height
        {
            info.best_known_height = height;
            return true;
        }
        true
    }

    /// Replaces the live connection's retained-tip evidence under the same
    /// identity check as `note_announced_tip`. Used by the credit refresh to
    /// drop resolved tips that can no longer raise the active-chain maximum —
    /// see P2P-03 in `docs/contracts/p2p-wire.md`.
    pub(crate) fn set_demonstrated_tips(&self, source: PeerSource, tips: Vec<Hash256>) {
        let mut entries = self.entries.write();
        if let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source))
        {
            entry.demonstrated_tips = tips;
        }
    }

    /// Raises the active-chain credit for `source`. See P2P-03 in
    /// `docs/contracts/p2p-wire.md`.
    pub(crate) fn note_announced_height(&self, source: PeerSource, height: i32) -> bool {
        let mut entries = self.entries.write();
        match entries.get_mut(&PeerRemote::from(source)) {
            Some(entry) if entry.lease.is_current(source) && !entry.lease.is_cancelled() => {
                let Some(info) = entry.info.as_mut() else {
                    return false;
                };
                if height > info.best_known_height {
                    info.best_known_height = height;
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Records `height` as the live connection's demonstrated headers
    /// horizon after its download-twice sync ended below the work floor
    /// without releasing headers — the peer proved it has nothing past that
    /// cursor, and leaving a higher handshake claim in place would keep
    /// reselecting it while starving every other peer.
    ///
    /// The cap is written to its own field, not `best_known_height`: that
    /// credit also gates block-body eligibility, and a peer with nothing
    /// left to offer headers can still legitimately serve bodies it
    /// advertised or demonstrated. Header-selection readers take
    /// `min(best_known_height, headers_horizon)`; this writer only lowers
    /// the horizon. Returns `false` for a stale, unpublished, or cancelled
    /// connection.
    pub(crate) fn note_headers_horizon(&self, source: PeerSource, height: u32) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        if entry.info.is_none() {
            return false;
        }
        entry.headers_horizon = Some(entry.headers_horizon.map_or(height, |cap| cap.min(height)));
        true
    }

    /// Lifts a terminal-page cap when the connection's download-twice sync
    /// verified headers past it: `height` is the cursor an accepted batch
    /// reached, so the earlier terminal page was not the connection's tip.
    /// Announcement credits (`note_announced_*`) never reach here — a claim
    /// alone does not undo the safeguard; only verified batches do. Returns
    /// `false` for a stale, unpublished, or cancelled connection.
    pub(crate) fn note_headers_progress(&self, source: PeerSource, height: u32) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        if entry.info.is_none() {
            return false;
        }
        if entry.headers_horizon.is_some_and(|cap| height > cap) {
            entry.headers_horizon = None;
        }
        true
    }

    /// Publishes the BIP331 `PKG_RELAY_*` bits the connection owner negotiated
    /// ([`crate::Peer::package_relay_versions`]), so other threads can tell
    /// whether `source` relays ancestor packages without owning its session.
    ///
    /// PRE: the caller is the owner of `source`'s live connection and its
    ///   handshake completed.
    /// POST: `true` and the snapshot replaces the previous one when `source`
    ///   is the current, uncancelled connection; otherwise `false` and nothing
    ///   changes, so a replacement connection never inherits another's bits.
    /// INVARIANT: the `Peer` stays the one owner of the negotiation; this is
    ///   a copy of its answer.
    pub(crate) fn note_package_relay(&self, source: PeerSource, versions: u64) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        entry.announcement.package_relay = versions;
        true
    }

    /// The `PKG_RELAY_*` bits published for the current published connection
    /// `source`, or `0` when it published none, is not live, or is not the
    /// current connection.
    pub fn package_relay_versions(&self, source: bitcoin_rs_mempool::PeerToken) -> u64 {
        self.entries
            .read()
            .iter()
            .find_map(|(key, entry)| {
                if entry.lease.is_cancelled() {
                    return None;
                }
                let current = entry.lease.source(key.endpoint());
                (current.endpoint() == source.endpoint
                    && current.connection_id().get() == source.connection_id)
                    .then_some(entry.announcement.package_relay)
            })
            .unwrap_or(0)
    }

    /// Starts an ancestor-package solicitation for a peer-token source.
    ///
    /// This resolves the token against the current lease before entering the
    /// policy critical section, so an old connection cannot solicit through
    /// its replacement. Unidentified inbound sessions are supported by the
    /// same exact-connection comparison as identified sessions.
    pub fn request_package_info_from_token(
        &self,
        source: bitcoin_rs_mempool::PeerToken,
        subject: Wtxid,
        parents: &[Txid],
    ) -> bool {
        let source = self.entries.read().iter().find_map(|(key, entry)| {
            let current = entry.lease.source(key.endpoint());
            (current.endpoint() == source.endpoint
                && current.connection_id().get() == source.connection_id
                && !entry.lease.is_cancelled())
            .then_some(current)
        });
        source.is_some_and(|source| self.request_package_info(source, subject, parents))
    }

    /// Publishes `versions` as `source`'s negotiated package-relay bits
    /// without a handshake, for cross-crate tests of the consumers of the
    /// snapshot. The listener owns the real publication.
    #[cfg(feature = "test-seam")]
    pub fn seed_package_relay(&self, source: PeerSource, versions: u64) -> bool {
        self.note_package_relay(source, versions)
    }

    /// Records that the live connection negotiated BIP332 stale-tip relay
    /// with the remote peer's `prefers_blocks` preference.
    pub(crate) fn note_stale_tip_relay(&self, source: PeerSource, prefers_blocks: bool) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        entry.announcement.stale_tip_prefers_blocks = Some(prefers_blocks);
        true
    }

    /// Raises the compact-block relay preference for `source` — its live
    /// connection accepted a post-verack `sendcmpct` with a known version.
    pub(crate) fn note_compact_relay(&self, source: PeerSource) -> bool {
        let mut entries = self.entries.write();
        match entries.get_mut(&PeerRemote::from(source)) {
            Some(entry) if entry.lease.is_current(source) && !entry.lease.is_cancelled() => {
                let Some(info) = entry.info.as_mut() else {
                    return false;
                };
                info.compact_block_relay = true;
                true
            }
            _ => false,
        }
    }

    /// Copies the connection owner's negotiated compact-announcement
    /// preference into the shared session snapshot.
    pub(crate) fn note_compact_announcement(
        &self,
        source: PeerSource,
        negotiation: &CompactBlockNegotiation,
    ) -> bool {
        let Some(preference) = negotiation.remote_preference() else {
            return false;
        };
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        entry.announcement.compact_high_bandwidth = Some(preference.send_compact);
        entry.announcement.compact_version = Some(preference.version);
        true
    }

    /// Records the last block whose possession was confirmed by an outbound
    /// headers or compact-block announcement to the current connection.
    pub(crate) fn note_announced_block(&self, source: PeerSource, hash: Hash256) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        entry.announcement.last_announced_block = Some(hash);
        true
    }

    /// Records that a block delivered by the current connection passed
    /// validation and was committed. The global sequence provides a stable
    /// recency ordering for high-bandwidth compact-relay selection.
    pub(crate) fn note_useful_block(&self, source: PeerSource) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        entry.announcement.useful_block_sequence = self
            .next_useful_block_sequence
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        true
    }

    /// Records that the mempool accepted a transaction the current connection
    /// delivered (Core `m_last_tx_time`, `net_processing.cpp:4538-4541`). The
    /// sequence orders inbound eviction protection.
    pub fn note_useful_transaction(&self, source: PeerSource) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        entry.useful_tx_sequence = self
            .next_useful_tx_sequence
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        true
    }

    /// Records whether the announcement worker currently selects the current
    /// connection for high-bandwidth compact-block push (`bip152_hb_to`).
    /// The worker keeps the authoritative set; this mirror exists so the
    /// `sessions()` snapshot rpc reads reports the live selection.
    pub(crate) fn note_high_bandwidth_selected(&self, source: PeerSource, selected: bool) {
        let mut entries = self.entries.write();
        if let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        {
            entry.announcement.selected_high_bandwidth = selected;
        }
    }

    /// Returns announcement state for the current published connection.
    pub(crate) fn announcement_state(&self, source: PeerSource) -> Option<PeerAnnouncementState> {
        let entries = self.entries.read();
        entries.get(&PeerRemote::from(source)).and_then(|entry| {
            (entry.lease.is_current(source) && entry.info.is_some()).then_some(entry.announcement)
        })
    }

    /// Reports whether the live published connection at `addr` requested
    /// compact-block relay.
    #[cfg(test)]
    pub(crate) fn compact_relay_of(&self, addr: impl Into<PeerRemote>) -> bool {
        let addr = addr.into();
        let entries = self.entries.read();
        entries.get(&addr).is_some_and(|entry| {
            entry
                .info
                .as_ref()
                .is_some_and(|info| info.compact_block_relay)
        })
    }

    /// Reports whether the live connection identified by `source` requested
    /// compact-block relay. Source-keyed so anonymous (`endpoint: None`)
    /// sessions participate identically to addressed ones.
    pub(crate) fn compact_relay_of_source(&self, source: PeerSource) -> bool {
        let entries = self.entries.read();
        entries
            .get(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
            .is_some_and(|entry| {
                entry
                    .info
                    .as_ref()
                    .is_some_and(|info| info.compact_block_relay)
            })
    }

    /// Records that the live connection at `source` negotiated BIP130 `sendheaders`.
    pub(crate) fn note_send_headers(&self, source: PeerSource) -> bool {
        let mut entries = self.entries.write();
        match entries.get_mut(&PeerRemote::from(source)) {
            Some(entry) if entry.lease.is_current(source) && !entry.lease.is_cancelled() => {
                let Some(info) = entry.info.as_mut() else {
                    return false;
                };
                info.send_headers = true;
                true
            }
            _ => false,
        }
    }

    /// Removes and cancels the connection `lease` refers to. Returns `false`
    /// when a different connection is live at `addr`, leaving it untouched.
    pub fn remove_current(&self, addr: impl Into<PeerRemote>, lease: &PeerLease) -> bool {
        let addr = addr.into();
        self.remove_if(addr, |current| current.same_connection(lease))
    }

    /// Remove an unidentified session by its lease.
    pub fn remove_unidentified(&self, lease: &PeerLease) -> bool {
        self.remove_if(PeerRemote::AnonymousTor(lease.connection_id()), |current| {
            current.same_connection(lease)
        })
    }

    /// Removes and cancels the connection that stamped `source`. Returns
    /// `false` when that connection is no longer live.
    pub(crate) fn disconnect_source(&self, source: PeerSource) -> bool {
        self.remove_if(PeerRemote::from(source), |current| {
            current.is_current(source)
        })
    }

    /// Removes and cancels whichever connection is live at `addr`.
    pub fn disconnect(&self, addr: impl Into<PeerRemote>) -> bool {
        let addr = addr.into();
        self.remove_if(addr, |_| true)
    }

    /// Removes and cancels the connection live at `addr` only when it has
    /// completed its handshake — the sessions `getpeerinfo` lists, which is
    /// what "connected nodes" means to an operator.
    pub fn disconnect_ready(&self, addr: impl Into<PeerRemote>) -> bool {
        self.remove_entry_if(addr.into(), |entry| entry.info.is_some())
    }

    /// Removes and cancels the live connection at `addr` only when its identity is `id`.
    pub(crate) fn disconnect_connection(&self, addr: PeerEndpoint, id: ConnectionId) -> bool {
        self.remove_if(addr.into(), |current| current.connection_id() == id)
    }

    /// Removes and cancels exactly the handshake-complete connection whose
    /// process-unique node id is `node_id` — [`PeerLease::node_id`], the value
    /// Core calls `nodeid` and publishes as `getpeerinfo.id`.
    ///
    /// Identity resolution and removal are one table write operation, so a
    /// same-address replacement cannot move the target in between: this can
    /// never disconnect a connection the caller did not name. Because the
    /// scan is over session keys rather than addresses, an anonymous inbound
    /// session — which has no logical endpoint at all — is selectable too.
    /// Only sessions that published metadata are selectable, the same set
    /// `getpeerinfo` reports ids for.
    ///
    /// PRE: none.
    /// POST: returns `false` and changes nothing when no handshake-complete
    ///   entry carries that node id; otherwise removes and cancels exactly
    ///   that entry and returns `true`.
    /// INVARIANT: address sessions are not consulted for identity, so the
    ///   endpoint-keyed replacement rule plays no part here.
    pub fn disconnect_ready_node_id(&self, node_id: u64) -> bool {
        let mut entries = self.entries.write();
        let Some(key) = entries
            .iter()
            .find(|(_, entry)| entry.info.is_some() && entry.lease.node_id() == node_id)
            .map(|(key, _)| *key)
        else {
            return false;
        };
        Self::remove_locked(&mut entries, key);
        true
    }

    /// Removes and cancels the handshake-complete connection at `addr` only
    /// when its process-unique node id is `node_id`.
    ///
    /// The conjunction form of [`Self::disconnect_ready_node_id`], for a
    /// caller that names both an address and an id: the address, readiness
    /// and identity checks happen under one table write, so a same-address
    /// replacement fails the identity check instead of being disconnected in
    /// the stale connection's place.
    ///
    /// PRE: none.
    /// POST: `false` with no mutation when `addr` is vacant, its session has
    ///   published no [`PeerInfo`], or it holds a connection with a different
    ///   node id.
    pub fn disconnect_ready_node_id_at(&self, addr: impl Into<PeerRemote>, node_id: u64) -> bool {
        self.remove_entry_if(addr.into(), |entry| {
            entry.info.is_some() && entry.lease.node_id() == node_id
        })
    }

    fn remove_if(&self, addr: PeerRemote, matches: impl FnOnce(&PeerLease) -> bool) -> bool {
        self.remove_entry_if(addr, |entry| matches(&entry.lease))
    }

    /// Tests `matches` against the entry at `addr` and, on a match, removes and
    /// cancels it under the same write lock.
    fn remove_entry_if(&self, addr: PeerRemote, matches: impl FnOnce(&Entry) -> bool) -> bool {
        let mut entries = self.entries.write();
        if !entries.get(&addr).is_some_and(matches) {
            return false;
        }
        Self::remove_locked(&mut entries, addr);
        true
    }

    /// Removes and cancels every connection accepted by `predicate`, returning
    /// the affected addresses.
    pub(crate) fn disconnect_matching(
        &self,
        predicate: impl Fn(&PeerRemote, &PeerLease) -> bool,
    ) -> Vec<PeerRemote> {
        let mut entries = self.entries.write();
        let targets: Vec<PeerRemote> = entries
            .iter()
            .filter(|(addr, entry)| predicate(addr, &entry.lease))
            .map(|(addr, _)| *addr)
            .collect();
        for addr in &targets {
            if let Some(removed) = entries.remove(addr) {
                removed.lease.cancel();
                Self::retire(&mut entries, &removed);
            }
        }
        Self::settle_retired(&mut entries);
        targets
    }

    /// The one removal body, for callers already holding the write lock:
    /// removes the entry at `key`, cancels its lease, and retains its traffic
    /// counters so `traffic_totals` never decreases.
    fn remove_locked(entries: &mut TableView, key: PeerRemote) {
        if let Some(removed) = entries.remove(&key) {
            removed.lease.cancel();
            Self::retain_traffic(entries, &removed);
        }
    }
    /// Removes and cancels anonymous Tor inbound connections belonging to `epoch`.
    ///
    /// Leaves IP connections, I2P connections, outbound Tor connections, and
    /// anonymous inbound connections from other epochs completely unaffected.
    #[cfg(test)]
    pub(crate) fn disconnect_onion_epoch(&self, epoch: u64) -> Vec<ConnectionId> {
        let mut entries = self.entries.write();
        let targets: Vec<(PeerRemote, ConnectionId)> = entries
            .iter()
            .filter(|(addr, entry)| {
                matches!(addr, PeerRemote::AnonymousTor(_)) && entry.onion_epoch == Some(epoch)
            })
            .map(|(addr, entry)| (*addr, entry.lease.connection_id()))
            .collect();
        for (addr, _) in &targets {
            if let Some(removed) = entries.remove(addr) {
                removed.lease.cancel();
                Self::retire(&mut entries, &removed);
            }
        }
        Self::settle_retired(&mut entries);
        targets.into_iter().map(|(_, id)| id).collect()
    }

    /// Retains a dropped connection's counter set so `traffic_totals` keeps
    /// counting it after the entry is gone; unpublished connections carry no
    /// counters to retain.
    fn retire(entries: &mut TableView, removed: &Entry) {
        if let Some(info) = removed.info.as_ref() {
            entries.retired.push(Arc::clone(&info.counters));
        }
    }

    /// Folds in the final counts of retired connections whose teardown provably
    /// finished — the table holding the last `Arc` means no writer remains, so
    /// their count is final and the list stays bounded. Runs once per removal
    /// batch so batched disconnects stay O(N + |retired|).
    fn settle_retired(entries: &mut TableView) {
        let TableView {
            retired,
            settled_recv,
            settled_sent,
            ..
        } = entries;
        retired.retain(|counters| {
            if Arc::strong_count(counters) == 1 {
                *settled_recv = settled_recv.saturating_add(counters.bytes_recv());
                *settled_sent = settled_sent.saturating_add(counters.bytes_sent());
                false
            } else {
                true
            }
        });
    }

    /// Per-removal retention for single-entry removals: retain the dropped
    /// connection's counter set, then settle retired connections whose
    /// teardown finished.
    fn retain_traffic(entries: &mut TableView, removed: &Entry) {
        Self::retire(entries, removed);
        Self::settle_retired(entries);
    }

    /// Traffic the node can account for — `(received, sent)` bytes: the live
    /// connections' counters plus the retired counters of every connection
    /// the table has dropped, so the total never decreases across disconnects.
    pub fn traffic_totals(&self) -> (u64, u64) {
        let entries = self.entries.read();
        entries
            .values()
            .filter_map(|entry| entry.info.as_ref().map(|info| &info.counters))
            .chain(entries.retired.iter())
            .fold(
                (entries.settled_recv, entries.settled_sent),
                |(recv, sent), counters| {
                    (
                        recv.saturating_add(counters.bytes_recv()),
                        sent.saturating_add(counters.bytes_sent()),
                    )
                },
            )
    }

    /// Requests teardown of every live connection without removing its entry.
    /// Connection owners remove their own session after observing the
    /// cancellation, so identity checks on the way out still succeed.
    pub fn cancel_all(&self) {
        for entry in self.entries.read().values() {
            entry.lease.cancel();
        }
    }

    /// Returns whether any connection is live at `addr`.
    #[must_use]
    pub fn is_connected(&self, addr: impl Into<PeerRemote>) -> bool {
        let addr = addr.into();
        self.entries.read().contains_key(&addr)
    }

    /// Returns whether the connection that stamped `source` is still live
    /// and uncancelled. A cancelled lease is not a schedulable peer.
    #[must_use]
    pub fn is_current(&self, source: PeerSource) -> bool {
        self.entries
            .read()
            .get(&PeerRemote::from(source))
            .is_some_and(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
    }

    /// Clones the lease of the live, uncancelled connection at `addr`.
    #[must_use]
    pub fn lease(&self, addr: impl Into<PeerRemote>) -> Option<PeerLease> {
        let addr = addr.into();
        self.entries
            .read()
            .get(&addr)
            .filter(|entry| !entry.lease.is_cancelled())
            .map(|entry| entry.lease.clone())
    }

    /// Number of live connections, including those still handshaking.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Returns whether no connection is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Identity of every live, uncancelled connection.
    ///
    /// PRE: none.
    /// POST: returns one `PeerSource` per live, uncancelled table entry.
    /// INVARIANT: every returned source passes `is_current` at snapshot time.
    #[must_use]
    pub fn live_sessions(&self) -> Vec<PeerSource> {
        live_sessions_of(&self.entries.read())
    }

    /// Runs `operation` on the live-session snapshot while the table read
    /// lock is held, so a same-address replacement cannot register between
    /// the snapshot and the ownership mutation.
    ///
    /// PRE: `operation` does not acquire the peer-table write lock and does
    ///   not read the table again (the read lock is not reentrant).
    /// POST: `operation` observed the complete live set atomically.
    /// INVARIANT: lock order is peer table, then any lock `operation` takes.
    pub(crate) fn with_live_sessions(&self, operation: impl FnOnce(&[PeerSource])) {
        let entries = self.entries.read();
        operation(&live_sessions_of(&entries));
    }

    /// Visits handshake-complete leases and their identity-bound metadata.
    /// Holds table authority through each callback, including an outbound queue
    /// operation, so replacement cannot change the target or relay preference.
    pub(crate) fn for_each_ready_lease(
        &self,
        mut f: impl FnMut(Option<PeerEndpoint>, &PeerLease, &PeerInfo),
    ) {
        for (addr, entry) in self.entries.read().iter() {
            if entry.lease.is_cancelled() {
                continue;
            }
            if let Some(info) = &entry.info {
                f(addr.endpoint(), &entry.lease, info);
            }
        }
    }

    /// Metadata of every handshake-complete connection, ordered by connection
    /// identity (connection order).
    #[must_use]
    pub fn infos(&self) -> Vec<PeerInfo> {
        let entries = self.entries.read();
        let mut infos: Vec<(ConnectionId, &PeerInfo)> = entries
            .values()
            .filter_map(|entry| {
                entry
                    .info
                    .as_ref()
                    .map(|info| (entry.lease.connection_id(), info))
            })
            .collect();
        infos.sort_unstable_by_key(|(id, _)| id.get());
        infos.into_iter().map(|(_, info)| info.clone()).collect()
    }

    /// Metadata of the one connection at `addr`, if it completed its handshake.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn info_of(&self, addr: impl Into<PeerRemote>) -> Option<PeerInfo> {
        let addr = addr.into();
        self.entries
            .read()
            .get(&addr)
            .and_then(|entry| entry.info.clone())
    }

    /// Metadata of the live connection identified by `source`, if it
    /// completed its handshake. Source-keyed so anonymous (`endpoint: None`)
    /// sessions resolve identically to addressed ones.
    #[must_use]
    pub(crate) fn info_of_source(&self, source: PeerSource) -> Option<PeerInfo> {
        self.entries
            .read()
            .get(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
            .and_then(|entry| entry.info.clone())
    }

    /// Snapshot of every live connection, ordered by connection identity.
    #[must_use]
    pub fn sessions(&self) -> Vec<PeerSession> {
        let entries = self.entries.read();
        let mut sessions: Vec<PeerSession> = entries
            .iter()
            .map(|(addr, entry)| entry.session(*addr))
            .collect();
        sessions.sort_unstable_by_key(|session| session.lease.connection_id().get());
        sessions
    }

    /// The peer-liveness snapshot every scheduler consumes: handshake-complete
    /// sessions whose leases are not cancelled, ordered by connection
    /// identity. A cancelled lease is not representable as a schedulable
    /// peer.
    #[must_use]
    pub(crate) fn usable_peers(&self) -> Vec<PeerSession> {
        let entries = self.entries.read();
        let mut sessions: Vec<PeerSession> = entries
            .iter()
            .filter(|(_, entry)| !entry.lease.is_cancelled() && entry.info.is_some())
            .map(|(addr, entry)| entry.session(*addr))
            .collect();
        sessions.sort_unstable_by_key(|session| session.lease.connection_id().get());
        sessions
    }

    /// Counts automatic outbound connections by relay role, including those
    /// still handshaking.
    ///
    /// PRE: none.
    /// POST: `(full_relay, block_relay)` counts of automatic outbound
    ///   connections; inbound connections are never counted.
    /// INVARIANT: inbound, manual, and cancelled leases hold no automatic
    ///   slot, so none can displace an automatic dial.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn outbound_role_counts(&self) -> (usize, usize) {
        let mut counts = (0_usize, 0_usize);
        for entry in self.entries.read().values() {
            if entry.lease.is_inbound() || entry.lease.is_cancelled() || entry.lease.is_manual() {
                continue;
            }
            match entry.lease.role() {
                PeerRole::FullRelay => counts.0 += 1,
                PeerRole::BlockRelayOnly => counts.1 += 1,
            }
        }
        counts
    }

    /// Returns the current connection source only when `addr` is published as
    /// ready and its lease is not cancelled. Registration clears predecessor
    /// metadata, so a handshaking replacement cannot inherit an old scheduler
    /// decision.
    #[must_use]
    pub fn ready_source(&self, addr: impl Into<PeerRemote>) -> Option<PeerSource> {
        let addr = addr.into();
        let entries = self.entries.read();
        let entry = entries.get(&addr)?;
        entry.info.as_ref()?;
        if entry.lease.is_cancelled() {
            return None;
        }
        Some(entry.lease.source(addr.endpoint()))
    }

    /// Starts `operation` only for a current, uncancelled source. The table
    /// read lock is held for the whole operation so a same-address replacement
    /// cannot register until the caller finishes.
    pub(crate) fn with_current(&self, source: PeerSource, operation: impl FnOnce()) -> bool {
        let entries = self.entries.read();
        if !entries
            .get(&PeerRemote::from(source))
            .is_some_and(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        {
            return false;
        }
        operation();
        true
    }

    /// Whether `source`'s connection published BIP144 witness relay: parent
    /// requests to it carry the witness flag, others do not.
    pub(crate) fn transaction_witness(&self, source: PeerSource) -> bool {
        let entries = self.entries.read();
        let Some(entry) = entries.get(&PeerRemote::from(source)) else {
            return false;
        };
        !entry.lease.is_cancelled()
            && entry.lease.is_current(source)
            && entry
                .info
                .as_ref()
                .is_some_and(|info| info.services & ServiceFlags::WITNESS.to_u64() != 0)
    }

    /// Clones the lease only when it is still the connection identified by
    /// `source` and has not been cancelled.
    #[must_use]
    pub(crate) fn lease_source(&self, source: PeerSource) -> Option<PeerLease> {
        self.entries
            .read()
            .get(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
            .map(|entry| entry.lease.clone())
    }

    /// Sends only to the current, uncancelled connection, holding its
    /// identity through the nonblocking enqueue. A replacement cannot
    /// register between validation and enqueue.
    ///
    /// A source that is not current maps to [`OutboundRefusal::Closed`], as
    /// does a local refusal that cancelled the lease. A node-wide aggregate
    /// refusal is [`OutboundRefusal::Saturated`]: the connection is live and
    /// the caller keeps its intent.
    #[expect(clippy::result_large_err)]
    pub fn send(&self, source: PeerSource, message: crate::Message) -> Result<(), OutboundRefusal> {
        let entries = self.entries.read();
        let Some(entry) = entries
            .get(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return Err(OutboundRefusal::Closed(message));
        };
        entry.lease.send(message)
    }

    /// Like [`Self::send`], then runs `published` while the connection's
    /// identity is still held: a same-address replacement cannot register
    /// between the enqueue and the caller stamping request ownership under
    /// that identity.
    #[expect(clippy::result_large_err)]
    pub(crate) fn send_then(
        &self,
        source: PeerSource,
        message: crate::Message,
        published: impl FnOnce(),
    ) -> Result<(), OutboundRefusal> {
        let entries = self.entries.read();
        let Some(entry) = entries
            .get(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return Err(OutboundRefusal::Closed(message));
        };
        entry.lease.send(message)?;
        published();
        Ok(())
    }

    /// Snapshots handshake-complete peers together with the connection that
    /// published them.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn ready_peers(&self) -> Vec<PeerSource> {
        self.sessions()
            .into_iter()
            .filter(|session| !session.lease.is_cancelled())
            .filter_map(|session| {
                session
                    .info
                    .is_some()
                    .then(|| session.lease.source(session.endpoint))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
