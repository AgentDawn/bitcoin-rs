//! Outbound block announcement owner: headers-first, high-bandwidth compact block,
//! and `inv` fallback.
//!
//! # Architecture
//!
//! [`BlockAnnounceQueue`] is the non-blocking producer: a one-slot wake channel
//! that coalesces notifications under backpressure. Chainstate remains the
//! authoritative owner of the committed tip.
//!
//! [`BlockAnnouncer`] is the P2P-owned decision engine:
//! - Tracks peer known-header/block state.
//! - Tracks peer `sendheaders` preference (BIP130).
//! - Maintains a bounded set of up to 3 peers promoted to BIP152 high-bandwidth mode.
//! - Selects the best announcement mechanism for each peer:
//!   1. BIP152 high-bandwidth compact block (`cmpctblock`) if selected, previous block is known, and not blocksonly.
//!   2. BIP130 `headers` sequence (up to 8 headers) if `sendheaders` was negotiated and anchored to active chain.
//!   3. Compatibility fallback `inv` (`MSG_BLOCK`) announcing the current active tip.
//! - Discards stale announcements across reorgs.
//! - Coalesces wakeups under queue saturation and rereads the committed tip from chainstate.
//! - Disconnect cleanly removes peer announcement state.

#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin_rs_primitives::{Block, BlockHash, Hash256};
use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;

use crate::PeerTable;
use crate::chain_query::{RecentBlockSlot, cmpct_message_from_native};
#[cfg(test)]
use crate::connection::PeerLease;
use crate::connection::PeerSource;
use crate::dispatch::{ChainQuery, CommittedTip};
use crate::peer::COMPACT_BLOCK_VERSION;
#[cfg(test)]
use crate::peer_info::PeerInfo;
use crate::wire::Message;

/// Core's `MAX_BLOCKS_TO_ANNOUNCE` (`net_processing.cpp:111`).
pub const MAX_BLOCKS_TO_ANNOUNCE: usize = 8;

/// Core's `MAX_PEERS_FOR_HIGH_BANDWIDTH_CMPCT` (`net_processing.cpp:142`).
pub const MAX_HIGH_BANDWIDTH_PEERS: usize = 3;

/// Drain poll interval when the block announce queue is empty.
const ANNOUNCE_POLL: Duration = Duration::from_millis(100);

/// Shared initial-block-download predicate behind the proactive P2P paths:
/// true while the node's latch reports active for its network.
pub(crate) fn ibd_active(
    ibd: Option<&(
        Arc<bitcoin_rs_chain::InitialBlockDownload>,
        bitcoin_rs_primitives::Network,
    )>,
) -> bool {
    ibd.is_some_and(|(latch, network)| {
        latch.is_active(bitcoin_rs_primitives::unix_time_secs(), *network)
    })
}

/// Configuration for block announcements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockAnnounceConfig {
    /// Whether the node operates in blocksonly/no-tx mode.
    /// In blocksonly mode, high-bandwidth compact block relay is disabled.
    pub blocksonly: bool,
}

/// Thread-safe non-blocking wake queue for committed-tip announcements.
#[derive(Clone)]
pub struct BlockAnnounceQueue {
    sender: Sender<()>,
}

/// Receiving end of the committed-tip wake queue.
pub struct BlockAnnounceReceiver {
    receiver: Receiver<()>,
}

impl BlockAnnounceQueue {
    /// Creates a one-slot wake queue. One pending token represents any number
    /// of committed-tip changes because the consumer rereads chainstate.
    #[must_use]
    pub fn new() -> (Self, BlockAnnounceReceiver) {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let queue = Self { sender };
        let rx = BlockAnnounceReceiver { receiver };
        (queue, rx)
    }

    /// Wakes the P2P consumer after a committed chain change. Never blocks
    /// chainstate; a full slot already guarantees a future reread.
    pub fn wake(&self) -> bool {
        self.sender.try_send(()).is_ok()
    }
}

impl BlockAnnounceReceiver {
    /// Receives one wake, or waits up to `timeout`, then drains redundant
    /// tokens so the caller performs one chainstate reread.
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<(), crossbeam_channel::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)?;
        while self.receiver.try_recv().is_ok() {}
        Ok(())
    }

    /// Drains all available wake tokens.
    pub fn try_recv(&self) -> bool {
        let mut woke = false;
        while self.receiver.try_recv().is_ok() {
            woke = true;
        }
        woke
    }
}

#[derive(Default)]
struct AnnounceState {
    /// Up to 3 peers we have requested high-bandwidth compact blocks from via `sendcmpct(true, 2)`.
    /// BIP152: "Nodes MUST NOT send `sendcmpct(high_bandwidth=true)` to more than 3 peers."
    high_bandwidth_requested_peers: Vec<PeerSource>,
    /// Observation cursor only; chainstate remains the authoritative tip owner.
    last_processed_tip: Option<Hash256>,
    /// Greatest height announced early. Monotonic: a second block at the
    /// same height (reorg race, duplicate connect) or a stale side branch
    /// never re-announces.
    highest_fast_announce: u32,
    /// Set when no ready peer could receive a post-commit announcement, or
    /// the node's aggregate outbound budget refused a live peer. The worker
    /// replans the committed tip on a later poll ([`BlockAnnouncer::process_tip_retry`]).
    announcement_retry: bool,
    /// Bumped by the disconnect hook under the state lock. `process_tip`
    /// compares epochs across its send window, so a disconnect between
    /// planning and the final write re-arms instead of being erased.
    announcement_epoch: u64,
}

#[derive(Clone)]
struct PlannedAnnouncement {
    source: PeerSource,
    message: Message,
    confirms_tip: bool,
}

/// Owner of block announcement selection, peer state, and high-bandwidth relay.
pub struct BlockAnnouncer {
    peers: Arc<PeerTable>,
    chain_query: Arc<dyn ChainQuery>,
    config: BlockAnnounceConfig,
    ibd: Option<(
        Arc<bitcoin_rs_chain::InitialBlockDownload>,
        bitcoin_rs_primitives::Network,
    )>,
    state: Mutex<AnnounceState>,
    recent: RecentBlockSlot,
    stale_tips: Option<Arc<crate::sync::StaleTipRetainer>>,
    block_tree: Option<bitcoin_rs_chain::BlockTreeReader>,
}

impl BlockAnnouncer {
    /// Constructs a new block announcer over the peer table and chain query.
    #[must_use]
    pub fn new(
        peers: Arc<PeerTable>,
        chain_query: Arc<dyn ChainQuery>,
        config: BlockAnnounceConfig,
    ) -> Self {
        Self {
            peers,
            chain_query,
            config,
            ibd: None,
            state: Mutex::new(AnnounceState::default()),
            recent: RecentBlockSlot::default(),
            stale_tips: None,
            block_tree: None,
        }
    }

    /// Attaches the stale-tip retainer and block tree reader so the announcer
    /// can relay recent stale tips to peers that negotiated BIP332.
    #[must_use]
    pub fn with_stale_tips(
        mut self,
        stale_tips: Arc<crate::sync::StaleTipRetainer>,
        block_tree: bitcoin_rs_chain::BlockTreeReader,
    ) -> Self {
        self.stale_tips = Some(stale_tips);
        self.block_tree = Some(block_tree);
        self
    }

    /// Attaches the early-announce body rendezvous shared with the chain
    /// query, so compact `getdata` and `getblocktxn` for the most recently
    /// announced hash answer from the held body before the store carries it.
    #[must_use]
    pub fn with_recent_block(mut self, recent: RecentBlockSlot) -> Self {
        self.recent = recent;
        self
    }

    /// Configures the IBD gate to suppress proactive block announcements during initial block download.
    #[must_use]
    pub fn with_ibd(
        mut self,
        ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
        network: bitcoin_rs_primitives::Network,
    ) -> Self {
        self.ibd = Some((ibd, network));
        self
    }

    /// Whether the node is currently in initial block download.
    #[must_use]
    pub fn in_ibd(&self) -> bool {
        ibd_active(self.ibd.as_ref())
    }

    /// Returns the current list of peers we requested high-bandwidth compact blocks from.
    #[cfg(test)]
    pub fn high_bandwidth_requested_peers(&self) -> Vec<crate::PeerEndpoint> {
        let state = self.state.lock();
        state
            .high_bandwidth_requested_peers
            .iter()
            .filter_map(|source| source.endpoint)
            .collect()
    }

    /// Returns the best block known for `addr`.
    #[cfg(test)]
    pub fn peer_known_block(&self, addr: crate::PeerEndpoint) -> Option<Hash256> {
        let source = self.peers.lease(addr)?.source(Some(addr));
        self.peers
            .announcement_state(source)
            .and_then(|state| state.last_announced_block)
    }

    /// Called when a peer handshake completes.
    pub fn on_peer_ready(&self) {
        self.reconcile_high_bandwidth_peers();
    }

    /// Called when a peer disconnects: cleans up its announcement state.
    pub fn on_peer_disconnected(&self, source: PeerSource) {
        if let Some(stale_tips) = &self.stale_tips {
            stale_tips.forget_peer(source);
        }
        let mut state = self.state.lock();
        state
            .high_bandwidth_requested_peers
            .retain(|candidate| *candidate != source);
        // An enqueued announcement dies with the session that carried it; a
        // same-address replacement starts with no announced-tip state. Arm
        // the retry so the next poll replans the committed tip onto whatever
        // sessions are live then, and bump the epoch: `process_tip` compares
        // epochs around its send window so a disconnect between planning and
        // discharge re-arms instead of being erased.
        state.announcement_retry = true;
        state.announcement_epoch += 1;
        // Keep the table's `bip152_hb_to` snapshot consistent for the window
        // where the entry outlives the worker's set membership.
        self.peers.note_high_bandwidth_selected(source, false);
    }

    /// Initial fill: offer unused high-bandwidth slots to eligible peers,
    /// proven deliverers first. Pushes the fresh promotions into `sent`.
    fn fill_high_bandwidth_slots(
        &self,
        state: &mut AnnounceState,
        eligible: &[(PeerSource, u64)],
        sent: &mut Vec<(Option<crate::PeerEndpoint>, Message)>,
    ) {
        // BIP152 asks for high-bandwidth slots to go to peers that recently
        // delivered blocks quickly. Filling strictly in session order
        // freezes the initial fill on whoever connected first — measured
        // live on testnet4, where a fresh v2/`hb=true` peer never won a
        // slot from the earliest-connected Core relayers — so prefer proven
        // deliverers here. Ties (all-zero sequences on quiet networks) keep
        // session order because the sort is stable; the rotation pass in
        // the caller still owns later upgrades.
        let mut fill_order = eligible.to_vec();
        fill_order.sort_by_key(|&(_, sequence)| std::cmp::Reverse(sequence));
        for &(source, _) in &fill_order {
            if state.high_bandwidth_requested_peers.len() >= MAX_HIGH_BANDWIDTH_PEERS {
                break;
            }
            if state.high_bandwidth_requested_peers.contains(&source) {
                continue;
            }
            let message = Message::SendCmpct(SendCmpct {
                send_compact: true,
                version: COMPACT_BLOCK_VERSION,
            });
            if self.peers.send(source, message.clone()).is_ok() {
                state.high_bandwidth_requested_peers.push(source);
                self.peers.note_high_bandwidth_selected(source, true);
                sent.push((source.endpoint, message));
            }
        }
    }

    /// Reconciles the selected high-bandwidth compact-relay peers against
    /// current ready sessions and IBD state.
    pub fn reconcile_high_bandwidth_peers(&self) -> Vec<(Option<crate::PeerEndpoint>, Message)> {
        let eligible: Vec<_> = self
            .peers
            .sessions()
            .into_iter()
            .filter_map(|session| {
                let source = session.lease.source(session.endpoint);
                let info = session.info.as_ref()?;
                let announcement = self.peers.announcement_state(source)?;
                (!session.lease.is_cancelled()
                    && info.compact_block_relay
                    && announcement.compact_version == Some(COMPACT_BLOCK_VERSION))
                .then_some((source, announcement.useful_block_sequence))
            })
            .collect();
        let selection_open = !self.config.blocksonly && !self.in_ibd();
        let mut state = self.state.lock();
        let mut sent = Vec::new();

        let selected = state.high_bandwidth_requested_peers.clone();
        for source in selected {
            if selection_open && eligible.iter().any(|(candidate, _)| *candidate == source) {
                continue;
            }
            let message = Message::SendCmpct(SendCmpct {
                send_compact: false,
                version: COMPACT_BLOCK_VERSION,
            });
            let send_succeeded = match self.peers.send(source, message.clone()) {
                Ok(()) => true,
                // The node's aggregate budget is full while the peer is live:
                // leave the selection untouched so the next reconcile retries
                // the demotion instead of forgetting it.
                Err(refusal) if refusal.is_saturated() => continue,
                Err(_) => false,
            };
            state
                .high_bandwidth_requested_peers
                .retain(|candidate| *candidate != source);
            self.peers.note_high_bandwidth_selected(source, false);
            if send_succeeded {
                sent.push((source.endpoint, message));
            }
        }

        if selection_open {
            self.fill_high_bandwidth_slots(&mut state, &eligible, &mut sent);

            while let Some(&(candidate, candidate_sequence)) = eligible
                .iter()
                .filter(|(source, sequence)| {
                    *sequence > 0 && !state.high_bandwidth_requested_peers.contains(source)
                })
                .max_by_key(|(_, sequence)| *sequence)
            {
                let Some((demote_index, demoted_sequence)) = state
                    .high_bandwidth_requested_peers
                    .iter()
                    .enumerate()
                    .filter_map(|(index, source)| {
                        eligible
                            .iter()
                            .find(|(candidate, _)| candidate == source)
                            .map(|(_, sequence)| (index, *sequence))
                    })
                    .min_by_key(|(_, sequence)| *sequence)
                else {
                    break;
                };
                if candidate_sequence <= demoted_sequence {
                    break;
                }

                let demoted = state.high_bandwidth_requested_peers.remove(demote_index);
                self.peers.note_high_bandwidth_selected(demoted, false);
                let demote = Message::SendCmpct(SendCmpct {
                    send_compact: false,
                    version: COMPACT_BLOCK_VERSION,
                });
                match self.peers.send(demoted, demote.clone()) {
                    Ok(()) => sent.push((demoted.endpoint, demote)),
                    // Aggregate budget full: the demotion did not happen, so
                    // the selection is restored as it was and the next
                    // reconcile retries the whole rotation.
                    Err(refusal) if refusal.is_saturated() => {
                        state
                            .high_bandwidth_requested_peers
                            .insert(demote_index, demoted);
                        self.peers.note_high_bandwidth_selected(demoted, true);
                        break;
                    }
                    Err(_) => {}
                }

                let promote = Message::SendCmpct(SendCmpct {
                    send_compact: true,
                    version: COMPACT_BLOCK_VERSION,
                });
                if self.peers.send(candidate, promote.clone()).is_ok() {
                    state.high_bandwidth_requested_peers.push(candidate);
                    self.peers.note_high_bandwidth_selected(candidate, true);
                    sent.push((candidate.endpoint, promote));
                } else {
                    break;
                }
            }
        }
        sent
    }

    fn ready_sessions(&self) -> Vec<crate::PeerSession> {
        self.peers
            .sessions()
            .into_iter()
            .filter(|session| session.info.is_some() && !session.lease.is_cancelled())
            .collect()
    }

    /// Why the planner fell back to a plain `inv` for one peer. Kept out of
    /// `planned_announcements` so the decision skeleton stays readable.
    fn inv_fallback_reason(
        send_headers: bool,
        known_position: Option<(Hash256, u32)>,
        tip_height: u32,
    ) -> &'static str {
        if !send_headers {
            "sendheaders not negotiated"
        } else if known_position.is_none() {
            "no demonstrated anchor"
        } else if !known_position.is_some_and(|(_, known_height)| {
            tip_height - known_height <= u32::try_from(MAX_BLOCKS_TO_ANNOUNCE).unwrap_or(u32::MAX)
        }) {
            "anchor beyond MAX_BLOCKS_TO_ANNOUNCE"
        } else {
            "headers walk unavailable"
        }
    }

    /// One ready session's announcement anchor: its source, its recorded
    /// compact preference, and its best demonstrated-or-announced position on
    /// the active chain. Shared by post-commit planning and the pre-commit
    /// early send so both read the same eligibility.
    fn peer_anchor(
        &self,
        session: &crate::PeerSession,
    ) -> (
        PeerSource,
        crate::peer_table::PeerAnnouncementState,
        Option<(Hash256, u32)>,
    ) {
        let source = session.lease.source(session.endpoint);
        let peer_state = self.peers.announcement_state(source).unwrap_or_default();
        let known_position = peer_state
            .last_announced_block
            .into_iter()
            .chain(session.demonstrated_tips.iter().copied())
            .filter_map(|hash| {
                self.chain_query
                    .active_height(BlockHash::from(hash))
                    .map(|height| (hash, height))
            })
            .max_by_key(|(_, height)| *height);
        (source, peer_state, known_position)
    }

    /// High-bandwidth compact-push candidacy for one ready session: the peer
    /// asked for high-bandwidth compact blocks, is not blocksonly-gated,
    /// knows the tip's parent, and was not already sent this header. BIP152
    /// needs no transaction-relay permission, so the peer's relay role is
    /// not consulted: negotiation plus the node blocksonly gate decide. The
    /// compact body builds lazily through `build`, so ineligible peers cost
    /// no store load and the pre-commit path builds its hand-held body once
    /// for all peers. One rule, two callers.
    fn plan_compact_push(
        &self,
        session: &crate::PeerSession,
        peer_state: crate::peer_table::PeerAnnouncementState,
        known_position: Option<(Hash256, u32)>,
        tip_height: u32,
        build: impl FnOnce() -> Option<Message>,
    ) -> Option<PlannedAnnouncement> {
        if known_position.is_some_and(|(_, height)| height >= tip_height) {
            return None;
        }
        // Peer must have explicitly requested high-bandwidth compact blocks
        // from us.
        if peer_state.compact_high_bandwidth != Some(true)
            || peer_state.compact_version != Some(COMPACT_BLOCK_VERSION)
            || self.config.blocksonly
        {
            return None;
        }
        let knows_prev =
            known_position.is_some_and(|(_, height)| height >= tip_height.saturating_sub(1));
        if !knows_prev {
            return None;
        }
        build().map(|message| PlannedAnnouncement {
            source: session.lease.source(session.endpoint),
            message,
            confirms_tip: true,
        })
    }

    /// Early compact-block announce for a PoW-valid tip child: relays the
    /// block to eligible high-bandwidth peers before connect finishes, and
    /// holds the body so compact `getdata` and `getblocktxn` answer before
    /// the store carries it. Never publishes a tip and never advances the
    /// mining generation; miners switch on the post-commit path. Skipped in
    /// initial block download and for a height at or below the greatest
    /// already announced early, so reorg races and duplicate connects send
    /// nothing more. A later connect failure is not retracted — the send
    /// stands, and the failure sends nothing further.
    pub fn announce_pow_valid(
        &self,
        block: &Block,
        hash: Hash256,
        height: u32,
    ) -> Vec<(Option<crate::PeerEndpoint>, Message)> {
        if self.in_ibd() {
            return Vec::new();
        }
        let Some(prebuilt) = cmpct_message_from_native(block, COMPACT_BLOCK_VERSION) else {
            return Vec::new();
        };
        {
            let mut state = self.state.lock();
            if height <= state.highest_fast_announce {
                return Vec::new();
            }
            state.highest_fast_announce = height;
            // The one held body: `block` is borrowed from the connect call,
            // so retaining it past this call needs exactly one copy.
            self.recent.store(hash, Arc::new(block.clone()));
        }
        let mut sent = Vec::new();
        for session in self.ready_sessions() {
            let (_, peer_state, known_position) = self.peer_anchor(&session);
            let Some(announcement) =
                self.plan_compact_push(&session, peer_state, known_position, height, || {
                    Some(prebuilt.clone())
                })
            else {
                continue;
            };
            if self
                .peers
                .send(announcement.source, announcement.message.clone())
                .is_err()
            {
                continue;
            }
            // Record the per-peer announcement: the post-commit `process_tip`
            // reads it as the peer's known position and sends no second
            // `cmpctblock` for this hash.
            self.peers.note_announced_block(announcement.source, hash);
            sent.push((announcement.source.endpoint, announcement.message));
        }
        sent
    }

    fn planned_announcements(
        &self,
        tip: CommittedTip,
        live_sessions: &[crate::PeerSession],
    ) -> Vec<PlannedAnnouncement> {
        let tip_hash = Hash256::from(tip.hash);

        let mut planned = Vec::new();

        for session in live_sessions {
            let addr = session.endpoint;
            let (source, peer_state, known_position) = self.peer_anchor(session);

            if known_position.is_some_and(|(_, height)| height >= tip.height) {
                // If this peer already knows a block at or above our active tip,
                // normal announcement is suppressed. For stale-tip relay peers,
                // however, BIP332 requires always announcing the active tip so peers
                // track our tip for fork point selection. We fall back to an `inv`.
                let stale_relay = self
                    .peers
                    .announcement_state(source)
                    .and_then(|s| s.stale_tip_prefers_blocks)
                    .is_some();
                if stale_relay {
                    let block_inv = Inventory::Block(bitcoin::BlockHash::from_byte_array(
                        tip_hash.to_le_bytes(),
                    ));
                    planned.push(PlannedAnnouncement {
                        source,
                        message: Message::Inv(vec![block_inv]),
                        confirms_tip: false,
                    });
                }
                continue;
            }

            // Option A: High-Bandwidth BIP152 Compact Block
            if let Some(announcement) =
                self.plan_compact_push(session, peer_state, known_position, tip.height, || {
                    self.chain_query
                        .compact_block_for(tip.height, tip.hash, Some(COMPACT_BLOCK_VERSION))
                        .filter(|msg| matches!(msg, Message::CmpctBlock(_)))
                })
            {
                tracing::debug!(
                    peer = ?addr,
                    tip_height = tip.height,
                    mode = "compact",
                    "block announcement planned"
                );
                planned.push(announcement);
                continue;
            }

            // Option B: Headers-First Announcement (BIP130)
            //
            // Anchoring requires a demonstrated position: a tip this
            // connection delivered and the node accepted (`demonstrated_tips`
            // from a headers-download round, or its last announced block). A
            // sendheaders peer that only listens for announcements has no
            // anchor, so it stays on the `inv` fallback — measured live on
            // testnet4 and pinned by
            // `test_sendheaders_peer_without_demonstrated_tip_gets_inv`.
            // Core additionally anchors on the peer's own announcements;
            // closing that gap is a sync-credit change, not a planner one.
            let send_headers = session.info.as_ref().is_some_and(|i| i.send_headers);
            if send_headers {
                if let Some((known_hash, known_height)) = known_position
                    && known_height < tip.height
                {
                    let distance = tip.height - known_height;
                    let max_announce = u32::try_from(MAX_BLOCKS_TO_ANNOUNCE).unwrap_or(u32::MAX);
                    if distance <= max_announce {
                        let limit = usize::try_from(distance).unwrap_or(usize::MAX);
                        let headers = self.chain_query.headers_after(
                            &[BlockHash::from(known_hash)],
                            tip.hash,
                            limit,
                        );
                        if !headers.is_empty()
                            && headers.last().map(|h| h.compute_hash().into()) == Some(tip_hash)
                        {
                            planned.push(PlannedAnnouncement {
                                source,
                                message: Message::Headers(headers),
                                confirms_tip: true,
                            });
                            tracing::debug!(
                                peer = ?addr,
                                tip_height = tip.height,
                                mode = "headers",
                                "block announcement planned"
                            );
                            continue;
                        }
                    }
                }
            }

            // Option C: `inv` Compatibility Fallback
            let reason = Self::inv_fallback_reason(send_headers, known_position, tip.height);
            let block_inv =
                Inventory::Block(bitcoin::BlockHash::from_byte_array(tip_hash.to_le_bytes()));
            planned.push(PlannedAnnouncement {
                source,
                message: Message::Inv(vec![block_inv]),
                confirms_tip: false,
            });
            tracing::debug!(
                peer = ?addr,
                tip_height = tip.height,
                mode = "inv",
                reason,
                "block announcement planned"
            );
        }

        planned
    }

    /// Rereads and processes the current committed tip.
    pub fn process_tip(&self) -> Vec<(Option<crate::PeerEndpoint>, Message)> {
        self.reconcile_high_bandwidth_peers();
        if self.in_ibd() {
            return Vec::new();
        }
        let Some(tip) = self.chain_query.committed_tip() else {
            return Vec::new();
        };
        let tip_hash = Hash256::from(tip.hash);
        let send_epoch = {
            let mut state = self.state.lock();
            // Claim the observation only on the processing path. Planning is
            // side-effect free, while this claim prevents concurrent workers
            // from sending the same committed tip twice.
            if state.last_processed_tip == Some(tip_hash) {
                return Vec::new();
            }
            state.last_processed_tip = Some(tip_hash);
            state.announcement_epoch
        };
        let live_sessions = self.ready_sessions();
        let no_ready_peers = live_sessions.is_empty();
        let planned = self.planned_announcements(tip, &live_sessions);
        let attempted = !planned.is_empty();
        let planned_sources: Vec<_> = planned.iter().map(|plan| plan.source).collect();
        let mut sent = Vec::with_capacity(planned.len());
        let mut refused_by_node_budget = false;
        for announcement in planned {
            match self
                .peers
                .send(announcement.source, announcement.message.clone())
            {
                Ok(()) => {}
                Err(refusal) => {
                    // A live peer refused only because the node's aggregate
                    // budget is full still needs its announcement: the tip is
                    // replanned on a later poll.
                    refused_by_node_budget |= refusal.is_saturated();
                    continue;
                }
            }
            if announcement.confirms_tip {
                self.peers
                    .note_announced_block(announcement.source, tip_hash);
            }
            sent.push((announcement.source.endpoint, announcement.message));
        }
        // Keep one retry intent across a disconnected interval. Each poll
        // rereads chainstate, so reconnecting peers receive the current tip
        // rather than a stored announcement from a superseded branch. A
        // poll that delivered into a stable session set discharges a stale
        // flag; refusal, an all-failed send, no ready peers, a delivered
        // source that already lost its session, or a disconnect inside the
        // send window keeps it armed. A disconnect after this write leaves
        // the hook-armed flag standing.
        let lost_delivery = planned_sources
            .iter()
            .any(|source| !self.peers.is_current(*source));
        let mut state = self.state.lock();
        let peer_lost_in_window = state.announcement_epoch != send_epoch;
        state.announcement_retry = refused_by_node_budget
            || (attempted && sent.is_empty())
            || no_ready_peers
            || lost_delivery
            || peer_lost_in_window;
        sent
    }

    /// Replans the committed tip after aggregate-budget refusal, all sends
    /// failing, or processing with no ready peers.
    ///
    /// PRE: none.
    /// POST: with a retry pending, the pending flag clears and the tip is
    /// processed again as if it had not been seen. Continued refusal or no
    /// ready peers rearms the retry. Peers that already know it are skipped
    /// by the planner, and an `inv` fallback may repeat. Without a pending
    /// retry, nothing happens.
    pub fn process_tip_retry(&self) -> Vec<(Option<crate::PeerEndpoint>, Message)> {
        // IBD suppresses announcements entirely; consuming the intent here
        // would drop a disconnect-armed retry before the first poll that can
        // act on it. Keep it armed until `process_tip` can run.
        if self.in_ibd() {
            return Vec::new();
        }
        {
            let mut state = self.state.lock();
            if !std::mem::take(&mut state.announcement_retry) {
                return Vec::new();
            }
            state.last_processed_tip = None;
        }
        self.process_tip()
    }

    /// Synchronously drains the queue, coalesces to the latest tip, and processes it.
    /// Relays recent stale tips to ready peers that negotiated BIP332.
    ///
    /// PRE: none.
    /// POST: sends at most [`crate::staletip::MAX_ADVERTISED_STALETIPS`] stale-tip announcements
    ///   per peer, respecting peer `prefers_blocks`, rate bounds, and repeat/echo
    ///   suppression. Sent tips are marked known via [`crate::sync::StaleTipRetainer::mark_known`]
    ///   only after `peers.send` returns `Ok`.
    pub fn process_stale_tips(&self) -> Vec<(Option<crate::PeerEndpoint>, Message)> {
        if self.in_ibd() {
            return Vec::new();
        }
        let (Some(stale_tips), Some(block_tree)) = (&self.stale_tips, &self.block_tree) else {
            return Vec::new();
        };

        {
            let tree = block_tree.read();
            stale_tips.prune(&tree);
        }

        let live_sessions = self.ready_sessions();
        let mut sent = Vec::new();

        for session in live_sessions {
            let source = session.lease.source(session.endpoint);
            let Some(announcement_state) = self.peers.announcement_state(source) else {
                continue;
            };
            let Some(prefers_blocks) = announcement_state.stale_tip_prefers_blocks else {
                continue;
            };
            if session.demonstrated_tips.is_empty() {
                continue;
            }

            let pending = stale_tips.pending_for(source, |tip_hash| {
                match self
                    .chain_query
                    .stale_tip_announcement(tip_hash, &session.demonstrated_tips)
                {
                    Some(crate::dispatch::StaleTipHeaders::Headers(a)) => {
                        !prefers_blocks || a.have_block
                    }
                    Some(crate::dispatch::StaleTipHeaders::TooMany) | None => false,
                }
            });

            for tip_hash in pending {
                if stale_tips.knows(source, tip_hash) {
                    continue;
                }
                let Some(crate::dispatch::StaleTipHeaders::Headers(announcement)) = self
                    .chain_query
                    .stale_tip_announcement(tip_hash, &session.demonstrated_tips)
                else {
                    continue;
                };

                let message = Message::StaleTip(announcement);
                match self.peers.send(source, message.clone()) {
                    Ok(()) => {
                        stale_tips.mark_known(source, tip_hash);
                        sent.push((session.endpoint, message));
                    }
                    Err(refusal) => {
                        if !refusal.is_saturated() {
                            stale_tips.forget_peer(source);
                        }
                        break;
                    }
                }
            }
        }

        sent
    }

    pub fn drain_queue_and_process(&self, rx: &BlockAnnounceReceiver) -> usize {
        if rx.try_recv() {
            self.process_tip();
            1
        } else {
            0
        }
    }
}

/// Dedicated background worker thread that drains `BlockAnnounceQueue` and announces new blocks.
pub fn spawn_block_announce_worker(
    announcer: Arc<BlockAnnouncer>,
    rx: BlockAnnounceReceiver,
    shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
) -> Result<std::thread::JoinHandle<()>, std::io::Error> {
    let shutdown = shutdown.into();
    std::thread::Builder::new()
        .name("bitcoin-rs-block-announce".into())
        .spawn(move || {
            while !shutdown.load() {
                match rx.recv_timeout(ANNOUNCE_POLL) {
                    Ok(()) => {
                        announcer.process_tip();
                        announcer.process_stale_tips();
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        announcer.reconcile_high_bandwidth_peers();
                        announcer.process_tip_retry();
                        announcer.process_stale_tips();
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
}

#[cfg(test)]
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::explicit_iter_loop,
    clippy::unreadable_literal,
    clippy::unwrap_used
)]
mod tests;
