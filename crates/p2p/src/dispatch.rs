use std::cell::RefCell;
use std::sync::Arc;

use bitcoin::bip152::BlockTransactionsRequest;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin_rs_primitives::{BlockHash, ConsensusEncode, Hash256, Header, Tx, Txid, Wtxid};

use crate::fsm::step;
use crate::handshake::{feature_messages, negotiated_features};
use crate::inv::{
    inventory_block_hash, inventory_tx_hash, is_within_inventory_bound, request_witness,
};
use crate::packages::{
    AncPkgInfo, GetPkgTxns, MSG_ANCPKGINFO, MSG_PKGTXNS, PKG_RELAY_ANC, PKG_RELAY_PKGTXNS, PkgTxns,
    SendPackages, combined_package_hash,
};
use crate::peer::{PackageRequest, Peer, PeerState};
use crate::wire::{MAX_HEADERS_MESSAGE_COUNT, MAX_MESSAGE_PAYLOAD, Message, PeerError};

/// Fully applied active-chain tip published by chainstate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedTip {
    /// Applied height.
    pub height: u32,
    /// Applied block hash.
    pub hash: BlockHash,
    /// Previous block hash from the applied tip's header.
    pub prev_hash: BlockHash,
}

/// Maximum block locator hashes accepted in one locator-based request.
pub(crate) use crate::wire::MAX_LOCATOR_HASHES;

/// Outcome of streamed inventory serving. Bodies pass through the serving
/// sink as they load and are never materialized as a whole.
#[derive(Debug, Default)]
pub struct InventoryServing {
    /// Inventory this node cannot serve (unknown type, stale, pruned, no
    /// body).
    pub not_found: Vec<Inventory>,
    /// True when production stopped at the headroom gate with items
    /// unexamined. A halt loads no body and reports no unserved item as
    /// served or missing: the caller keeps the unexamined items and resumes
    /// them once the gate opens (I9: no silent half-serve).
    pub halted: bool,
}

/// The single durable record of one compact-filter request across serving
/// attempts.
///
/// The first attempt carries the peer's request unchanged with no expected
/// end. When a serving pass stops after emitting a prefix of a range
/// (`getcfilters` only), the remainder is the same request narrowed to start
/// after the emitted prefix, with `expected_end` pinning the stop height the
/// emitted prefix was computed against. A later pass recomputes the range and
/// fails if the chain moved under the cursor, instead of splicing two
/// different ranges into one reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterRequest {
    /// The request still to serve: the peer's original message, or its
    /// narrowed remainder.
    pub request: Message,
    /// Height of the last filter the full range ends at, fixed by the first
    /// pass that emitted a prefix. `None` before anything was emitted.
    pub expected_end: Option<u32>,
}

impl FilterRequest {
    /// Wraps a peer's compact-filter request for its first serving attempt.
    #[must_use]
    pub const fn new(request: Message) -> Self {
        Self {
            request,
            expected_end: None,
        }
    }
}

/// Outcome of one compact-filter serving attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterServing {
    /// The whole request was answered (or there was nothing to answer).
    Done,
    /// Nothing more could be sent now: publication or send headroom is
    /// pending. The record is the exact remainder; passing it back resumes
    /// without replaying anything already sent.
    Pending(FilterRequest),
}

/// Header response for a BIP332 stale tip announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StaleTipHeaders {
    /// The stale branch headers starting immediately after `fork_point`.
    Headers(crate::staletip::StaleTipAnnouncement),
    /// The stale branch is longer than [`crate::staletip::MAX_STALETIP_HEADERS`].
    TooMany,
}

/// Read-only active-chain view used by server-side P2P responders.
pub trait ChainQuery: Send + Sync {
    /// Whether the optional filter index currently covers the applied chain.
    fn compact_filters_ready(&self) -> bool {
        false
    }

    /// Serves a bounded BIP157 request from persisted filters only.
    ///
    /// PRE: `request` is a [`FilterRequest`] built by
    /// [`FilterRequest::new`] or returned by an earlier
    /// [`FilterServing::Pending`] of this same request. `headroom` reserves
    /// (or reuses) the caller's production credit immediately before each
    /// filter is loaded and returns false when none is available.
    /// POST: `Done` when every filter in the range was sent. `Pending` with
    /// the exact remainder when publication or `headroom` stopped serving; a
    /// pending record never repeats a message already sent, and `Pending`
    /// carries the input unchanged when nothing was sent. `Err` for a range
    /// that is interrupted for good (the index stopped early, or the chain
    /// moved under a resumed cursor) and for send failures.
    /// INVARIANT: a saturated outbound gate is `Pending`, never an error.
    fn serve_compact_filters(
        &self,
        _request: &FilterRequest,
        _headroom: &dyn Fn() -> bool,
        _send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<FilterServing, PeerError> {
        Ok(FilterServing::Done)
    }
    /// Returns a bounded contiguous header response: locator-based ranges
    /// walk the applied chain, while the empty-locator single-header direct
    /// lookup stays on the header-best chain.
    fn headers_after(
        &self,
        locator_hashes: &[BlockHash],
        stop_hash: BlockHash,
        limit: usize,
    ) -> Vec<Header>;

    /// Serves block inventory one response at a time, in `items` order. For
    /// each block-typed item `headroom` is consulted EXACTLY ONCE,
    /// immediately BEFORE its body load; `false` halts production and sets
    /// `halted` (I7, I9). `headroom` reserves or reuses the caller's
    /// worst-case outbound reservation, which the following `serve` spends.
    /// Full-block items are served as
    /// [`Message::BlockPayload`]; `MSG_CMPCT_BLOCK` items as
    /// [`Message::CmpctBlock`] built at the given BIP152 version — `None`
    /// (peer never negotiated) leaves compact items in `not_found`. Each
    /// `MSG_WITNESS_BLOCK` body preserves the stored consensus payload;
    /// `MSG_BLOCK` strips witness data from the validated body (BIP144).
    /// A `serve` error aborts production and propagates. Non-block / unservable items
    /// are collected into `not_found` and never loaded.
    fn serve_inventory_blocks(
        &self,
        items: &[Inventory],
        compact_version: Option<u64>,
        headroom: &dyn Fn() -> bool,
        serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<InventoryServing, PeerError>;

    /// PRE: `request` carries decoded absolute transaction indexes for one
    /// block. `compact_version` is the peer's servable BIP152 profile.
    /// POST: return the reply to send — a `blocktxn` for a block shallow
    /// enough to reconstruct, encoded for `compact_version` (v1 strips
    /// witnesses, any other profile keeps them), or the whole
    /// witness-bearing `block` for one too deep for a useful hint set
    /// (Core 31.1 answers both instead of leaving a peer to time out);
    /// `Ok(None)` leaves the request unanswered (unknown, stale, pruned,
    /// or headless block, or a saturated `headroom` gate). `Err` reports
    /// an out-of-range transaction index — a protocol disconnect per
    /// BIP152 (Core scores misbehavior).
    /// INVARIANT: `headroom` is evaluated before any block body is loaded,
    /// so a saturated outbound gate materializes no body for this request.
    fn block_transactions(
        &self,
        request: &BlockTransactionsRequest,
        compact_version: Option<u64>,
        headroom: &dyn Fn() -> bool,
    ) -> Result<Option<Message>, PeerError>;

    /// Header time of the active tip, `None` when no active tip is known.
    ///
    /// PRE: none.
    /// POST: returns UNIX seconds of the tip header Core would read as
    ///   `m_best_block_time` (`net_processing.cpp:1445-1448`); `None` means
    ///   nothing is applied, which the outbound service policy reads as the
    ///   deepest possible local chain.
    /// INVARIANT: the only local tip-age source for peer admission; no
    ///   caller walks the block tree per handshake for it.
    fn best_block_time(&self) -> Option<u32> {
        None
    }

    /// Returns the active-chain height of `hash` if it is currently an ancestor
    /// of the active tip.
    fn active_height(&self, _hash: BlockHash) -> Option<u32> {
        None
    }

    /// Builds one `cmpctblock` message for the block at `height` and `hash`
    /// at the given BIP152 version.
    fn compact_block_for(
        &self,
        _height: u32,
        _hash: BlockHash,
        _compact_version: Option<u64>,
    ) -> Option<Message> {
        None
    }

    /// The fully applied active-chain tip, or `None` if uninitialized.
    ///
    /// This is deliberately distinct from the header-tree tip: consumers of
    /// committed block effects must never treat fresher, unapplied headers as
    /// the publication frontier.
    fn committed_tip(&self) -> Option<CommittedTip> {
        None
    }

    /// Returns the BIP332 stale-tip headers for `tip` given the peer's
    /// demonstrated tips, or `None` if the tip is unknown, not stale, or
    /// not an ancestor of any demonstrated tip. Returns `TooMany` if the
    /// branch exceeds [`crate::staletip::MAX_STALETIP_HEADERS`].
    fn stale_tip_announcement(
        &self,
        tip: Hash256,
        peer_tips: &[Hash256],
    ) -> Option<StaleTipHeaders>;
}

/// Transaction inventory view and successful-getdata acknowledgement seam,
/// used by the Inv filter and transaction responder.
///
/// Implemented here for the mempool gateway; the p2p crate owns the protocol
/// adapter while mempool owns admission, orphan, and rejection state.
/// The dispatch path consults this trait to suppress redundant `getdata`
/// requests for transactions the node already holds and to serve
/// transaction bodies in reply to `getdata`.
pub trait TxInventory: Send + Sync {
    /// Returns `true` when the node already holds the transaction identified by
    /// `hash` — in the mempool, the orphan map, or the recent-rejects cache.
    /// `hash_is_wtxid` is true for `WTx` (wtxid) and false for
    /// `Transaction`/`WitnessTransaction` (txid).
    fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool;

    /// Returns the witness transaction body for `txid`, or `None` when the
    /// node does not have it. Used to answer `getdata` for txid-typed items.
    fn get_tx(&self, txid: Txid) -> Option<Tx>;

    /// Returns the witness transaction body for `wtxid`, or `None` when the
    /// node does not have it. Used to answer BIP339 `getdata` (`WTx`) items.
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx>;

    /// Called only after a transaction body was successfully queued for getdata.
    fn transaction_sent(&self, _wtxid: Wtxid) {}

    /// The BIP331 ancestor package of `wtxid` the node can serve: its
    /// unconfirmed ancestors in topological order, then `wtxid` itself.
    ///
    /// POST: resident pool members only, never an orphan or a recent reject,
    /// and `None` when `wtxid` is not resident, the package is too large, or
    /// the provider has no resident pool. The last element is `wtxid`.
    fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>>;

    /// The bodies of `wtxids`, in request order, when every one is resident.
    ///
    /// POST: all or none, read from one view of the resident pool, as the
    /// pool's own handles; never an orphan or a recent reject, and never the
    /// general [`Self::get_tx_by_wtxid`] lookup. `None` when any member is
    /// absent or the provider has no resident pool. The caller bounds
    /// `wtxids.len()`.
    fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>>;
}

impl TxInventory for bitcoin_rs_mempool::MempoolGateway {
    fn transaction_sent(&self, wtxid: Wtxid) {
        self.mark_broadcast(wtxid);
    }

    fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>> {
        Self::ancestor_package_wtxids(self, wtxid)
    }

    fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>> {
        Self::resident_package(self, wtxids)
    }

    fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool {
        Self::have_tx(self, hash, hash_is_wtxid)
    }

    fn get_tx(&self, txid: Txid) -> Option<Tx> {
        Self::get_tx(self, txid)
    }

    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        Self::get_tx_by_wtxid(self, wtxid)
    }
}

impl crate::compact_blocks::CompactBlockHints for bitcoin_rs_mempool::MempoolGateway {
    fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
        Self::for_each_reconstruction_identity(self, f);
    }
    fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
        Self::reconstruction_tx_by_txid(self, txid)
    }

    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        Self::reconstruction_tx_by_wtxid(self, wtxid)
    }
}

/// Chainless dispatch: collects the protocol responses and returns them.
///
/// With `chain: None` responses can never contain a block body, so the batch
/// is protocol-bounded (at most [`MAX_HEADERS_MESSAGE_COUNT`] headers, or one
/// inventory-bound notfound/getdata echo) and safe to materialize whole.
/// Block announcements go to a no-op sink.
pub fn dispatch_inbound<S>(
    peer: &mut Peer<S>,
    message: &Message,
) -> Result<Vec<Message>, PeerError> {
    let responses = RefCell::new(Vec::new());
    dispatch_inbound_full(
        peer,
        message,
        None,
        None,
        &|| true,
        &|| true,
        &mut |response| {
            responses.borrow_mut().push(response);
            Ok(())
        },
        &mut |_| {},
        &mut |items| responses.borrow_mut().push(Message::GetData(items)),
    )?;
    Ok(responses.into_inner())
}

/// Dispatch with an active-chain view and a transaction-inventory filter.
///
/// Every response is emitted through `send` in the identical order the
/// former batch form produced (I8); `send` errors abort emission and
/// propagate. `headroom` gates block-body materialization (I7) and is
/// evaluated before each load. It reserves the outbound bytes of one
/// worst-case frame (or reuses a reservation already held) and returns
/// `false` when the connection or the node cannot take them; the next `send`
/// spends that reservation, so a body is loaded only while its queue space is
/// already owned.
///
/// When `tx_inventory` is `Some`, the `inv` arm suppresses `getdata` for
/// transactions the node already holds (mempool, orphan map, or
/// recent-rejects) and the `getdata` arm serves tx bodies for tx-typed
/// items the node has, reporting the rest as `notfound`. Inventory types
/// identify txids or wtxids independently of the peer's outbound preference.
///
/// `tx_relay_open` reports whether the node accepts transaction relay from
/// peers (it is not in initial block download). While it returns `false`,
/// the `inv` arm requests no transaction-typed vector and every other arm
/// is unchanged. The gate is evaluated lazily per `inv` message.
///
/// `announce_tx` receives missing transaction vectors for the shared request
/// owner; dispatch never chooses a download source.
///
/// `announce_block` receives the hash of every `MSG_BLOCK` and
/// `MSG_WITNESS_BLOCK` vector of an `inv`.
/// PRE: `announce_block` belongs to the connection that `peer` wraps.
/// POST: block inventory reaches `announce_block` and never a `getdata`.
/// INVARIANT: block bodies are requested only by header sync and the
/// download window (Core 31.1 `net_processing.cpp:4370-4410`).
#[expect(clippy::too_many_arguments, reason = "independent protocol sinks")]
pub fn dispatch_inbound_full<S>(
    peer: &mut Peer<S>,
    message: &Message,
    chain: Option<&dyn ChainQuery>,
    tx_inventory: Option<&dyn TxInventory>,
    tx_relay_open: &dyn Fn() -> bool,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    announce_block: &mut dyn FnMut(Hash256),
    announce_tx: &mut dyn FnMut(Vec<Inventory>),
) -> Result<(), PeerError> {
    match message {
        Message::Version(version) => {
            step(peer, message)?;
            reply_to_version(peer, version.version, send)?;
        }
        Message::Ping(nonce) => {
            step(peer, message)?;
            send(Message::Pong(*nonce))?;
        }
        Message::Inv(items) => {
            step(peer, message)?;
            receive_inv(
                peer,
                items,
                tx_inventory,
                tx_relay_open,
                announce_block,
                announce_tx,
            )?;
        }
        Message::GetHeaders(request) => {
            ensure_block_locator_within_bounds(
                &request.locator_hashes,
                "getheaders locator too large",
            )?;
            step(peer, message)?;
            send(headers_response(chain, request))?;
        }
        Message::GetCFilters(_) | Message::GetCFHeaders(_) | Message::GetCFCheckpt(_) => {
            step(peer, message)?;
            if peer.pending_filter_request.is_some() {
                return Err(PeerError::Io(std::io::Error::other(
                    "compact filter request already pending",
                )));
            }
            if let Some(chain) = chain
                && let FilterServing::Pending(remainder) = chain.serve_compact_filters(
                    &FilterRequest::new(message.clone()),
                    headroom,
                    send,
                )?
            {
                peer.pending_filter_request = Some(crate::peer::ParkedFilter::new(
                    remainder,
                    std::time::Instant::now(),
                ));
            }
        }
        Message::GetBlocks(request) => {
            ensure_block_locator_within_bounds(
                &request.locator_hashes,
                "getblocks locator too large",
            )?;
            step(peer, message)?;
        }
        Message::GetData(items) => {
            ensure_inventory_request_within_bounds(items)?;
            step(peer, message)?;
            ensure_getdata_package_types_negotiated(peer, items)?;
            serve_inbound_getdata(peer, chain, tx_inventory, items, headroom, send)?;
        }
        Message::AncPkgInfo(_)
        | Message::GetPkgTxns(_)
        | Message::PkgTxns(_)
        | Message::PkgTxnsPayload(_) => {
            step(peer, message)?;
            receive_package_message(peer, message, tx_inventory, tx_relay_open, headroom, send)?;
        }
        Message::GetBlockTxn(request) => {
            ensure_block_txn_indexes_valid(&request.txs_request)?;
            step(peer, message)?;
            let compact_version = peer.compact_blocks.servable_version();
            serve_block_txn(chain, &request.txs_request, compact_version, headroom, send)?;
        }
        _ => step(peer, message)?,
    }

    if peer.state == PeerState::Ready {
        tracing::trace!("peer handshake ready");
    }

    Ok(())
}

/// Answers the peer's `version` with our feature offers, the one BIP331
/// `sendpackages` offer, and `verack`.
///
/// POST: `sendpackages` is sent at most once per connection, before `verack`.
fn reply_to_version<S>(
    peer: &mut Peer<S>,
    remote_version: u32,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    for response in feature_messages() {
        send(response)?;
    }
    for announcement in negotiated_features(peer, remote_version) {
        send(Message::Feature(announcement))?;
    }
    if let Some(versions) = peer.package_relay.unsent_offer() {
        send(Message::SendPackages(SendPackages { versions }))?;
        peer.package_relay.record_advertised(versions);
    }
    send(Message::Verack)
}

/// Routes one `inv`: block vectors go to `announce_block`, and the
/// transaction vectors this node wants go to `announce_tx` as one request.
///
/// POST: an `inv` of a package-relay-only type is misbehavior. Compact,
/// unknown, and error vectors are ignored (Core `ProcessMessage(INV)`).
fn receive_inv<S>(
    peer: &Peer<S>,
    items: &[Inventory],
    tx_inventory: Option<&dyn TxInventory>,
    tx_relay_open: &dyn Fn() -> bool,
    announce_block: &mut dyn FnMut(Hash256),
    announce_tx: &mut dyn FnMut(Vec<Inventory>),
) -> Result<(), PeerError> {
    if items.iter().any(is_package_inventory) {
        return Err(PeerError::Misbehavior(
            "inv of a package-relay-only inventory type",
        ));
    }
    let relay_open = tx_relay_open();
    let mut requested = Vec::new();
    for item in items {
        if let Some(hash) = inventory_block_hash(item) {
            announce_block(hash);
            continue;
        }
        let Some(hash) = inventory_tx_hash(item) else {
            continue;
        };
        if !relay_open
            || tx_inventory.is_some_and(|inv| inv.have_tx(hash, matches!(item, Inventory::WTx(_))))
        {
            continue;
        }
        requested.push(*item);
    }
    if !requested.is_empty() {
        let witness = peer.remote_version.as_ref().is_some_and(|version| {
            version.services.to_u64() & bitcoin::p2p::ServiceFlags::WITNESS.to_u64() != 0
        });
        request_witness(&mut requested, witness);
        announce_tx(requested);
    }
    Ok(())
}

/// Applies one BIP331 package message once its sequence step passed.
///
/// POST: the message's `PKG_RELAY_*` bit was negotiated, otherwise the peer is
/// disconnected through the returned error. A `pkgtxns` frame is charged and
/// admitted by the node's ingress, which decodes it only after planning, so
/// dispatch checks the negotiation alone.
fn receive_package_message<S>(
    peer: &mut Peer<S>,
    message: &Message,
    tx_inventory: Option<&dyn TxInventory>,
    tx_relay_open: &dyn Fn() -> bool,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    match message {
        Message::AncPkgInfo(info) => {
            ensure_package_relay(
                peer,
                PKG_RELAY_ANC,
                "ancpkginfo without negotiated ancestor package relay",
            )?;
            if tx_relay_open() {
                peer.pending_package_request = package_request(tx_inventory, info);
            }
        }
        Message::GetPkgTxns(request) => {
            ensure_package_relay(
                peer,
                PKG_RELAY_PKGTXNS,
                "getpkgtxns without negotiated package transaction relay",
            )?;
            serve_getpkgtxns(tx_inventory, request, headroom, send)?;
        }
        _ => ensure_package_relay(
            peer,
            PKG_RELAY_PKGTXNS,
            "pkgtxns without negotiated package transaction relay",
        )?,
    }
    Ok(())
}

/// Whether `item` is one of the two BIP331 inventory types.
fn is_package_inventory(item: &Inventory) -> bool {
    matches!(
        item,
        Inventory::Unknown {
            inv_type: MSG_ANCPKGINFO | MSG_PKGTXNS,
            ..
        }
    )
}

/// The BIP331 `PKG_RELAY_*` bit `bit` must have been negotiated for the
/// connection before a message that rides it is accepted.
///
/// POST: otherwise the sender violated its own negotiation and no reply is
/// sent; the peer is disconnected through the returned error.
fn ensure_package_relay<S>(peer: &Peer<S>, bit: u64, error: &'static str) -> Result<(), PeerError> {
    if peer.package_relay_versions() & bit == 0 {
        return Err(PeerError::Misbehavior(error));
    }
    Ok(())
}

/// Rejects the `getdata` item types BIP331 forbids: `MSG_PKGTXNS` is a
/// `notfound`-only type, and `MSG_ANCPKGINFO` needs ancestor-package relay.
fn ensure_getdata_package_types_negotiated<S>(
    peer: &Peer<S>,
    items: &[Inventory],
) -> Result<(), PeerError> {
    for item in items {
        match item {
            Inventory::Unknown {
                inv_type: MSG_PKGTXNS,
                ..
            } => {
                return Err(PeerError::Misbehavior(
                    "getdata of a notfound-only package inventory type",
                ));
            }
            Inventory::Unknown {
                inv_type: MSG_ANCPKGINFO,
                ..
            } => ensure_package_relay(
                peer,
                PKG_RELAY_ANC,
                "getdata ancpkginfo without negotiated ancestor package relay",
            )?,
            _ => {}
        }
    }
    Ok(())
}

/// The download an `ancpkginfo` asks the request owner for.
///
/// A member counts as held only when it is resident in the pool: an orphan
/// or a recent reject is exactly what the package exists to resolve, so it
/// is requested again and admitted with its ancestors as one package.
/// POST: `None` when the subject is already resident or more than
/// `MAX_PACKAGE_COUNT` members are missing. Otherwise the non-resident
/// members in announced order, the subject last: the one sequence the
/// `getpkgtxns` is written from and the claim records.
fn package_request(
    tx_inventory: Option<&dyn TxInventory>,
    info: &AncPkgInfo,
) -> Option<PackageRequest> {
    let subject = info.subject()?;
    let resident = |wtxid: &Wtxid| {
        tx_inventory.is_some_and(|inventory| {
            inventory
                .resident_package(std::slice::from_ref(wtxid))
                .is_some()
        })
    };
    if resident(&subject) {
        return None;
    }
    let wtxids: Vec<Wtxid> = info
        .wtxids
        .iter()
        .copied()
        .filter(|wtxid| !resident(wtxid))
        .collect();
    if wtxids.len() > bitcoin_rs_mempool::standardness::MAX_PACKAGE_COUNT {
        return None;
    }
    Some(PackageRequest { subject, wtxids })
}

/// Answers one `getpkgtxns`: every requested transaction in one `pkgtxns`,
/// or one `notfound` of type `MSG_PKGTXNS` carrying the request's combined
/// hash and nothing else.
///
/// Members come from the resident pool only, read as one view, never from
/// the orphan or recent-reject sets. A package whose `pkgtxns` could not fit
/// one frame is unavailable too.
/// INVARIANT: one reply message, so one `headroom` reservation covers it and
/// no body is loaded while the gate is closed. A closed gate leaves the
/// request unanswered, like `getblocktxn`.
fn serve_getpkgtxns(
    tx_inventory: Option<&dyn TxInventory>,
    request: &GetPkgTxns,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    if !headroom() {
        return Ok(());
    }
    let package = tx_inventory.and_then(|inventory| {
        inventory
            .resident_package(&request.wtxids)
            .filter(|bodies| fits_one_frame(bodies))
            .map(|bodies| (inventory, bodies))
    });
    let Some((inventory, bodies)) = package else {
        return send(Message::NotFound(vec![Inventory::Unknown {
            inv_type: MSG_PKGTXNS,
            hash: combined_package_hash(&request.wtxids),
        }]));
    };
    send(Message::PkgTxns(PkgTxns {
        txs: bodies.iter().map(|tx| Tx::clone(tx)).collect(),
    }))?;
    for wtxid in &request.wtxids {
        inventory.transaction_sent(*wtxid);
    }
    Ok(())
}

/// Whether `bodies`, as one `pkgtxns`, fit the transport frame.
fn fits_one_frame(bodies: &[Arc<Tx>]) -> bool {
    let count = u64::try_from(bodies.len()).unwrap_or(u64::MAX);
    let mut total = bitcoin_rs_primitives::varint::encoded_len(count);
    for tx in bodies {
        total = total.saturating_add(tx.consensus_size());
        if total > MAX_MESSAGE_PAYLOAD {
            return false;
        }
    }
    true
}

/// Answers one `getdata(MSG_ANCPKGINFO)` item with the resident ancestor
/// package of its subject, or reports the item missing.
///
/// Returns `false`, having done nothing, when `headroom` is closed; `true`
/// once the `ancpkginfo` was sent or the item appended to `not_found`.
fn serve_ancpkginfo_item(
    tx_inventory: Option<&dyn TxInventory>,
    item: &Inventory,
    subject: Wtxid,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    not_found: &mut Vec<Inventory>,
) -> Result<bool, PeerError> {
    if !headroom() {
        return Ok(false);
    }
    let package = tx_inventory
        .and_then(|inventory| inventory.resident_ancestor_package(subject))
        .map(|wtxids| AncPkgInfo { wtxids })
        .filter(|info| info.subject() == Some(subject) && info.encode().is_ok());
    match package {
        Some(info) => send(Message::AncPkgInfo(info))?,
        None => not_found.push(*item),
    }
    Ok(true)
}

fn headers_response(chain: Option<&dyn ChainQuery>, request: &GetHeadersMessage) -> Message {
    let locator_hashes: Vec<BlockHash> = request
        .locator_hashes
        .iter()
        .map(|h| BlockHash(Hash256::from_le_bytes(h.as_byte_array())))
        .collect();
    let stop_hash = BlockHash(Hash256::from_le_bytes(request.stop_hash.as_byte_array()));
    let mut headers = chain.map_or_else(Vec::new, |chain| {
        chain.headers_after(&locator_hashes, stop_hash, MAX_HEADERS_MESSAGE_COUNT)
    });
    headers.truncate(MAX_HEADERS_MESSAGE_COUNT);
    Message::Headers(headers)
}

/// Serves one decoded `getdata` and parks what the production gate stops.
///
/// PRE: `items` passed the inventory bound and nothing is parked on `peer`:
/// the session reads nothing while a tail is parked, so a second request here
/// is a caller bug, and replacing or reordering the parked tail would
/// silently half-serve it.
/// POST: the tail [`serve_getdata`] returns is `peer.pending_getdata` and the
/// misses it keeps are `peer.pending_notfound`; both are empty when the whole
/// request was handled.
fn serve_inbound_getdata<S>(
    peer: &mut Peer<S>,
    chain: Option<&dyn ChainQuery>,
    tx_inventory: Option<&dyn TxInventory>,
    items: &[Inventory],
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    if peer.has_parked_getdata() {
        return Err(PeerError::Io(std::io::Error::other(
            "getdata already parked",
        )));
    }
    let compact_version = peer.compact_blocks.servable_version();
    let mut not_found = Vec::new();
    let tail = serve_getdata(
        chain,
        tx_inventory,
        compact_version,
        items,
        &mut not_found,
        headroom,
        send,
    )?;
    peer.pending_getdata = tail;
    peer.pending_notfound.extend(not_found);
    Ok(())
}

/// Serves `items` of one `getdata` through the sink, one item at a time and
/// in request order, until the outbound production gate halts it.
///
/// Block-typed and unknown items resolve through the chain query; with no
/// chain view they are reported missing. When `tx_inventory` is `Some`,
/// tx-typed items are served from the transaction inventory (the node's
/// mempool): a held tx is emitted as a `tx` message with the serialization
/// requested by its inventory type (P2P-01 / BIP144). BIP339 `WTx` items are
/// resolved by wtxid; `Transaction`/`WitnessTransaction` items by txid. With
/// `tx_inventory` `None` a tx-typed item is not a block and is reported
/// missing by the chain query.
///
/// PRE: `not_found` holds no item of `items`; `send` queues one message on
/// the connection that asked.
/// POST: every item before the returned tail was answered: served through
/// `send`, or appended to `not_found`. A non-empty return is `items` from the
/// first item the gate stopped at; nothing was sent for it. An empty return
/// means the whole request was handled: then one `notfound` carrying all of
/// `not_found` has been sent (I8), or — when the gate closed between the
/// last item and the trailing report — nothing was sent, `not_found` keeps
/// the misses, and the caller parks them like any other parked tail (I9).
/// A `send` or chain error aborts and propagates.
/// INVARIANT: `headroom` is consulted before every body load, every tx
/// lookup, and the trailing `notfound` send, so a saturated gate materializes
/// nothing and queues no message, and a halt neither sends nor disconnects.
/// The reservation `headroom` takes is held across lookups that send nothing
/// (a miss) and is spent by the next `send`, so a run of misses never takes
/// a second reservation. The caller, which owns the budget, reports the kept
/// misses once an exactly sized reply fits, and resumes the tail once it can
/// reserve production room again. At most one decoded request
/// (`MAX_INV_PER_MSG` items) is ever pending, so the tail and `not_found`
/// are bounded.
pub(crate) fn serve_getdata(
    chain: Option<&dyn ChainQuery>,
    tx_inventory: Option<&dyn TxInventory>,
    compact_version: Option<u64>,
    items: &[Inventory],
    not_found: &mut Vec<Inventory>,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<Vec<Inventory>, PeerError> {
    for (index, item) in items.iter().enumerate() {
        let tx_source = tx_inventory.filter(|_| {
            matches!(
                item,
                Inventory::Transaction(_) | Inventory::WitnessTransaction(_) | Inventory::WTx(_)
            )
        });
        let served = match (item, tx_source) {
            (
                Inventory::Unknown {
                    inv_type: MSG_ANCPKGINFO,
                    hash,
                },
                _,
            ) => {
                let subject = Wtxid::from(Hash256::from_le_bytes(hash));
                serve_ancpkginfo_item(tx_inventory, item, subject, headroom, send, not_found)?
            }
            (_, Some(inv)) => serve_tx_item(inv, item, headroom, send, not_found)?,
            (_, None) => serve_block_item(chain, compact_version, item, headroom, send, not_found)?,
        };
        if !served {
            return Ok(items[index..].to_vec());
        }
    }
    if not_found.is_empty() {
        return Ok(Vec::new());
    }
    // The trailing misses are answered behind every served item, but a gate
    // that closed while the last items were served must not turn into a
    // refused send: that cancels the lease for the session's own queue state.
    // The headroom check runs immediately before the send, so only a sender
    // that wins the slot concurrently can still refuse it. When it is closed,
    // the misses stay in `not_found` for the caller to park: they are not
    // items, and returning them as the tail would send them as `getdata`
    // answers.
    if !headroom() {
        return Ok(Vec::new());
    }
    send(Message::NotFound(std::mem::take(not_found)))?;
    Ok(Vec::new())
}

/// Answers one tx-typed `getdata` item from the transaction inventory.
///
/// Returns `false`, having done nothing, when `headroom` is closed; `true`
/// once the transaction was sent or the item appended to `not_found`.
fn serve_tx_item(
    inv: &dyn TxInventory,
    item: &Inventory,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    not_found: &mut Vec<Inventory>,
) -> Result<bool, PeerError> {
    if !headroom() {
        return Ok(false);
    }
    let found = match item {
        Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
            let native = Txid::from(Hash256::from_le_bytes(txid.as_byte_array()));
            inv.get_tx(native).map(|mut tx| {
                let wtxid = tx.wtxid();
                if matches!(item, Inventory::Transaction(_)) {
                    for input in &mut tx.inputs {
                        input.witness.clear();
                    }
                }
                (wtxid, tx)
            })
        }
        Inventory::WTx(wtxid) => {
            let native = Wtxid::from(Hash256::from_le_bytes(wtxid.as_byte_array()));
            inv.get_tx_by_wtxid(native).map(|tx| (native, tx))
        }
        _ => None,
    };
    match found {
        Some((wtxid, tx)) => {
            send(Message::Tx(tx))?;
            inv.transaction_sent(wtxid);
        }
        None => not_found.push(*item),
    }
    Ok(true)
}

/// Answers one block-typed or unknown `getdata` item through the chain
/// query, which consults `headroom` once before a body load.
///
/// Returns `false`, having sent nothing, when the chain query halted at the
/// gate; `true` once the item was served or appended to `not_found`.
fn serve_block_item(
    chain: Option<&dyn ChainQuery>,
    compact_version: Option<u64>,
    item: &Inventory,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    not_found: &mut Vec<Inventory>,
) -> Result<bool, PeerError> {
    let Some(chain) = chain else {
        not_found.push(*item);
        return Ok(true);
    };
    let outcome = chain.serve_inventory_blocks(
        std::slice::from_ref(item),
        compact_version,
        headroom,
        send,
    )?;
    if outcome.halted {
        return Ok(false);
    }
    not_found.extend(outcome.not_found);
    Ok(true)
}

/// Answers one `getblocktxn` through the chain view and sends whatever reply
/// it produces. PRE: the request's indexes are structurally valid.
/// `compact_version` is the peer's servable BIP152 profile (`None` leaves
/// witness encoding untouched). POST: a servable block gets its `blocktxn`
/// in the peer's profile encoding, a block too deep for a compact answer
/// gets the whole `block`, and an unknown, stale, headless, or
/// production-gated block — or a node with no chain view — leaves the
/// request unanswered. INVARIANT: the dispatch boundary never learns which
/// reply shape the chain chose, and a saturated `headroom` gate loads no
/// block body here.
fn serve_block_txn(
    chain: Option<&dyn ChainQuery>,
    request: &BlockTransactionsRequest,
    compact_version: Option<u64>,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    let Some(chain) = chain else {
        return Ok(());
    };
    if let Some(response) = chain.block_transactions(request, compact_version, headroom)? {
        send(response)?;
    }
    Ok(())
}

/// Enforces native decoded `getblocktxn` policy: nonempty, increasing indexes.
///
/// PRE: the request carries decoded absolute indexes. POST: a rejected list
/// returns `PeerError::Misbehavior` before any chain query, even without a chain.
/// Core 31.1 establishes increasing wire indexes during deserialization
/// (`blockencodings.h:23-54`, `net_processing.cpp:4333-4340`); the order check here
/// also defends in-process requests. Empty-list rejection is stricter native
/// policy: Core accepts an empty decoded list.
fn ensure_block_txn_indexes_valid(request: &BlockTransactionsRequest) -> Result<(), PeerError> {
    if request.indexes.is_empty() {
        return Err(PeerError::Misbehavior("getblocktxn with empty index list"));
    }
    if request.indexes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(PeerError::Misbehavior(
            "getblocktxn indexes not strictly increasing",
        ));
    }
    Ok(())
}

fn ensure_block_locator_within_bounds(
    locator_hashes: &[bitcoin::BlockHash],
    error: &'static str,
) -> Result<(), PeerError> {
    if locator_hashes.len() > MAX_LOCATOR_HASHES {
        return Err(PeerError::Misbehavior(error));
    }
    Ok(())
}

fn ensure_inventory_request_within_bounds(items: &[Inventory]) -> Result<(), PeerError> {
    if !is_within_inventory_bound(items) {
        return Err(PeerError::Misbehavior("getdata inventory too large"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
