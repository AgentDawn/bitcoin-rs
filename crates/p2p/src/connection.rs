//! Per-connection identity and cancellation.

use bitcoin_rs_primitives::PeerEndpoint;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, TrySendError};
use parking_lot::{Condvar, Mutex};
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Process-unique identity for one peer connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(u64);

impl ConnectionId {
    fn allocate() -> Self {
        let mut id = NEXT_CONNECTION_ID.load(Ordering::Relaxed);
        loop {
            let Some(next) = id.checked_add(1) else {
                std::process::abort();
            };
            match NEXT_CONNECTION_ID.compare_exchange_weak(
                id,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Self(id),
                Err(actual) => id = actual,
            }
        }
    }

    /// Returns the process-unique numeric id backing this identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Test-only identity with a chosen numeric value (eviction fixtures
    /// order candidates by it).
    #[cfg(test)]
    pub(crate) fn for_test_raw(id: u64) -> Self {
        Self(id)
    }
}

/// Remote identity of a live connection. Only destinations belong in `AddrMan`;
/// an anonymous inbound circuit is identified by its own connection lease.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PeerRemote {
    /// A routable Bitcoin peer destination.
    Endpoint(PeerEndpoint),
    /// An inbound Tor circuit whose remote destination is unknown.
    AnonymousTor(ConnectionId),
}

impl PeerRemote {
    /// Destination, when the connection reveals one.
    pub const fn endpoint(self) -> Option<PeerEndpoint> {
        match self {
            Self::Endpoint(endpoint) => Some(endpoint),
            Self::AnonymousTor(_) => None,
        }
    }

    /// Network carrying this connection, independent of proxy sockets.
    pub fn network(self) -> crate::PeerNetwork {
        match self {
            Self::Endpoint(endpoint) => endpoint.address().network(),
            Self::AnonymousTor(_) => crate::PeerNetwork::Onion,
        }
    }

    /// Mint from an optional logical endpoint and its connection.
    /// `None` (unidentified Tor inbound) becomes `AnonymousTor` and never
    /// carries the loopback forwarder/proxy socket as identity.
    #[must_use]
    pub const fn from_endpoint(
        endpoint: Option<PeerEndpoint>,
        connection_id: ConnectionId,
    ) -> Self {
        match endpoint {
            Some(endpoint) => Self::Endpoint(endpoint),
            None => Self::AnonymousTor(connection_id),
        }
    }

    /// Mint from a `PeerSource` token.
    #[must_use]
    pub fn from_source(source: PeerSource) -> Self {
        Self::from_endpoint(source.endpoint(), source.connection_id())
    }
}

impl From<PeerEndpoint> for PeerRemote {
    fn from(endpoint: PeerEndpoint) -> Self {
        Self::Endpoint(endpoint)
    }
}

impl From<std::net::SocketAddr> for PeerRemote {
    fn from(socket: std::net::SocketAddr) -> Self {
        Self::Endpoint(socket.into())
    }
}

impl<T> From<(T, u16)> for PeerRemote
where
    std::net::SocketAddr: From<(T, u16)>,
{
    fn from(value: (T, u16)) -> Self {
        Self::from(std::net::SocketAddr::from(value))
    }
}

impl std::fmt::Display for PeerRemote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Endpoint(endpoint) => endpoint.fmt(f),
            Self::AnonymousTor(id) => write!(f, "tor-inbound-{}:0", id.get()),
        }
    }
}

impl std::str::FromStr for PeerRemote {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(id) = value
            .strip_prefix("tor-inbound-")
            .and_then(|id| id.strip_suffix(":0"))
        {
            return id
                .parse()
                .map(|id| Self::AnonymousTor(ConnectionId(id)))
                .map_err(|_| "invalid anonymous Tor connection handle");
        }
        value.parse().map(Self::Endpoint)
    }
}

/// Attribution token for an event delivered by one connection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerSource {
    /// Logical peer endpoint; `None` for unidentified inbound sessions.
    pub(crate) endpoint: Option<crate::PeerEndpoint>,
    connection_id: ConnectionId,
}

impl PeerSource {
    /// Returns the connection id of the delivering peer.
    #[must_use]
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Logical endpoint of the delivering peer, if identified.
    #[must_use]
    pub fn endpoint(&self) -> Option<crate::PeerEndpoint> {
        self.endpoint
    }

    /// Remote identity for table keys: the endpoint when identified,
    /// otherwise the anonymous connection.
    #[must_use]
    pub fn remote(&self) -> PeerRemote {
        PeerRemote::from(*self)
    }

    /// Mints a source with a fresh process-unique identity for tests.
    #[cfg(test)]
    pub(crate) fn for_test(addr: impl Into<PeerRemote>) -> Self {
        Self {
            endpoint: {
                let remote: PeerRemote = addr.into();
                remote.endpoint()
            },
            connection_id: ConnectionId::allocate(),
        }
    }

    /// Mints a source for an endpoint-identified test peer.
    #[cfg(test)]
    pub(crate) fn for_test_endpoint(endpoint: crate::PeerEndpoint) -> Self {
        Self {
            endpoint: Some(endpoint),
            connection_id: ConnectionId::allocate(),
        }
    }

    /// Mints an unidentified source for tests.
    #[cfg(test)]
    pub(crate) fn for_test_unidentified() -> Self {
        Self {
            endpoint: None,
            connection_id: ConnectionId::allocate(),
        }
    }
}

impl From<PeerSource> for PeerRemote {
    fn from(source: PeerSource) -> Self {
        source
            .endpoint
            .map_or(Self::AnonymousTor(source.connection_id), Self::Endpoint)
    }
}

impl From<PeerSource> for bitcoin_rs_mempool::PeerToken {
    fn from(source: PeerSource) -> Self {
        Self {
            endpoint: source.endpoint,
            addr: PeerRemote::from(source).endpoint(),
            connection_id: source.connection_id.get(),
        }
    }
}

impl From<bitcoin_rs_mempool::PeerToken> for PeerSource {
    fn from(token: bitcoin_rs_mempool::PeerToken) -> Self {
        let connection_id = ConnectionId(token.connection_id);
        Self {
            endpoint: token.endpoint,
            connection_id,
        }
    }
}

/// Maximum queued messages for one peer connection.
const OUTBOUND_QUEUE_MAX_MESSAGES: usize = 4096;

/// Maximum queued full wire bytes for one peer connection.
const OUTBOUND_QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Aggregate queued full wire bytes shared by every connection of one node.
///
/// The per-connection [`OutboundBudget`] keeps its own message and byte
/// bounds; this budget caps the SUM of queued bytes across all of them, so
/// one stalled peer's full queue cannot multiply by the connection count
/// into gigabytes of retained memory. No tuning knob: the aggregate equals
/// one connection's maximum, the operator-visible queue bound.
///
/// The cap is strict. Every byte is charged by compare-and-swap before the
/// message that owns it exists, so the counter never exceeds the cap, not
/// even transiently, and an empty local queue gets no exemption. A refusal by
/// this budget is backpressure on the producer ([`Refusal::Shared`]); it
/// never disconnects a peer for bytes another peer queued.
pub(crate) const SHARED_OUTBOUND_QUEUE_MAX_BYTES: usize = OUTBOUND_QUEUE_MAX_BYTES;

/// Bytes of the aggregate that bulk production may never take: one maximum
/// frame, derived from the block-production reserve. Control traffic (pings,
/// replies, parked misses) keeps flowing into this margin while bulk
/// production is parked behind the lower bulk limit.
const SHARED_BULK_MARGIN_BYTES: usize = BLOCK_PRODUCTION_RESERVE_BYTES;

const _: () = assert!(
    BLOCK_PRODUCTION_RESERVE_BYTES >= crate::wire::HEADER_LEN + crate::wire::MAX_MESSAGE_PAYLOAD
);

/// Per-node shared outbound queued-byte budget, owned by the P2P service
/// (never process-global: independent services stay independent).
///
/// Byte-only: the per-connection budget keeps the message-count bound and
/// the block-production reserve, and takes this aggregate's bytes for every
/// charge it hands out. `pending_bytes` always equals the sum of the live
/// [`OutboundCredit`]s of every connection of the node.
#[derive(Debug)]
pub(crate) struct SharedOutboundBudget {
    /// Hard cap: no charge may take the counter above it.
    max_bytes: usize,
    /// Cap for bulk production reservations: `max_bytes` less the margin.
    bulk_limit: usize,
    pending_bytes: AtomicUsize,
    /// Signalled when any connection releases aggregate bytes.
    drained: Condvar,
    /// Orders aggregate updates against a waiter's predicate check; guards
    /// no data.
    drained_lock: Mutex<()>,
}

impl SharedOutboundBudget {
    /// Builds the node budget with the shared aggregate cap and the derived
    /// one-maximum-frame bulk margin.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_limits(SHARED_OUTBOUND_QUEUE_MAX_BYTES, SHARED_BULK_MARGIN_BYTES)
    }

    /// Builds a budget with an explicit cap and bulk margin (tests size both).
    #[must_use]
    pub(crate) fn with_limits(max_bytes: usize, margin: usize) -> Self {
        debug_assert!(margin <= max_bytes, "the bulk margin sits inside the cap");
        Self {
            max_bytes,
            bulk_limit: max_bytes.saturating_sub(margin),
            pending_bytes: AtomicUsize::new(0),
            drained: Condvar::new(),
            drained_lock: Mutex::new(()),
        }
    }

    /// Takes `bytes` from the aggregate when the total stays at or below
    /// `limit`; the total is never above `limit` at any instant.
    fn try_charge(&self, bytes: usize, limit: usize) -> bool {
        self.pending_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                pending.checked_add(bytes).filter(|total| *total <= limit)
            })
            .is_ok()
    }

    /// Returns `bytes` to the aggregate counter. The caller wakes the
    /// waiters with [`Self::wake_waiters`] once its own state is consistent:
    /// the counter moves first, then the lock is taken, then the waiters are
    /// notified, so no wake is lost.
    ///
    /// The subtraction is checked: a release larger than the charge would be
    /// a double release, which the debug assertion reports.
    fn release_counter(&self, bytes: usize) {
        let released =
            self.pending_bytes
                .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                    pending.checked_sub(bytes)
                });
        debug_assert!(released.is_ok(), "released more shared bytes than charged");
    }

    /// Notifies every session parked in a shared wait.
    ///
    /// PRE: the aggregate state a waiter's predicate reads was updated
    /// before the call. POST: a waiter either observed that update or is
    /// woken by this call.
    fn wake_waiters(&self) {
        drop(self.drained_lock.lock());
        self.drained.notify_all();
    }

    /// Snapshot: whether a charge of `bytes` would fit under the hard cap
    /// right now. For wait and pacing predicates only; admission is
    /// [`Self::try_charge`].
    #[must_use]
    fn may_admit(&self, bytes: usize) -> bool {
        self.pending_bytes
            .load(Ordering::Acquire)
            .checked_add(bytes)
            .is_some_and(|total| total <= self.max_bytes)
    }

    /// Snapshot: whether a bulk reservation of `bytes` would fit under the
    /// bulk limit right now. For wait and pacing predicates only.
    #[must_use]
    fn may_reserve_bulk(&self, bytes: usize) -> bool {
        self.pending_bytes
            .load(Ordering::Acquire)
            .checked_add(bytes)
            .is_some_and(|total| total <= self.bulk_limit)
    }

    /// Charged aggregate bytes awaiting release.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn pending(&self) -> usize {
        self.pending_bytes.load(Ordering::Acquire)
    }
}

/// Why a charge was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The connection's own bounds: its item cap, its byte cap, or a writer
    /// that has already returned.
    Local,
    /// The node aggregate is full. Pure backpressure: the lease stays live
    /// and the caller keeps its intent.
    Shared,
}

/// The sole owner of one outbound charge: one local message, `bytes` local
/// bytes, and `bytes` aggregate bytes.
///
/// A charge has exactly one owner at every moment: this credit, then the
/// [`QueuedFrame`] that carries it through the channel, then the writer's
/// burst. Dropping the owner releases both halves, wherever the drop happens
/// (written, refused, drained, or discarded with the channel). There is no
/// reclaim and no conversion across threads.
#[must_use]
#[derive(Debug)]
pub(crate) struct OutboundCredit {
    budget: Arc<OutboundBudget>,
    bytes: usize,
}

impl OutboundCredit {
    /// Bytes this credit still owns.
    pub(crate) const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether this credit was charged to `budget`.
    fn belongs_to(&self, budget: &Arc<OutboundBudget>) -> bool {
        Arc::ptr_eq(&self.budget, budget)
    }
}

impl Drop for OutboundCredit {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

/// One channel item: a message together with the charge that pays for it.
///
/// The writer receives frames; a frame's credit drops, and its bytes return
/// to the budgets, when the writer is done with it, when the channel discards
/// it, or when a refused enqueue returns it.
#[derive(Debug)]
pub struct QueuedFrame {
    message: crate::Message,
    credit: OutboundCredit,
}

impl QueuedFrame {
    /// The queued message.
    #[must_use]
    pub fn message(&self) -> &crate::Message {
        &self.message
    }

    /// Takes the message out, releasing the frame's charge.
    #[must_use]
    pub fn into_message(self) -> crate::Message {
        let Self { message, credit } = self;
        drop(credit);
        message
    }
}

/// Why [`PeerLease::send`] did not queue a message. The refused message is
/// returned to the caller either way.
#[derive(Debug, PartialEq, Eq)]
pub enum OutboundRefusal {
    /// The lease is cancelled, or this send cancelled it: the connection is
    /// over.
    Closed(crate::Message),
    /// The node's aggregate outbound budget is full while the lease is
    /// live. Nothing was cancelled and nothing was queued; the caller keeps
    /// its intent and retries.
    Saturated(crate::Message),
}

impl OutboundRefusal {
    /// Takes the refused message back.
    #[must_use]
    pub fn into_message(self) -> crate::Message {
        match self {
            Self::Closed(message) | Self::Saturated(message) => message,
        }
    }

    /// Whether the refusal was aggregate backpressure on a live lease.
    #[must_use]
    pub const fn is_saturated(&self) -> bool {
        matches!(self, Self::Saturated(_))
    }
}

impl std::fmt::Display for OutboundRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(_) => f.write_str("outbound queue closed"),
            Self::Saturated(_) => f.write_str("outbound queue saturated"),
        }
    }
}

impl std::error::Error for OutboundRefusal {}

/// Consensus maximum serialized block size. `peer` owns the value
/// ([`crate::peer::MAX_BLOCK_SERIALIZED_SIZE_USIZE`]); `connection` references it
/// rather than carrying an independent copy.
const BLOCK_SERIALIZED_SIZE: usize = crate::peer::MAX_BLOCK_SERIALIZED_SIZE_USIZE;

/// Full framed-wire bytes reserved before loading a worst-case block body.
const BLOCK_PRODUCTION_RESERVE_BYTES: usize = crate::wire::HEADER_LEN + BLOCK_SERIALIZED_SIZE;

const _: () = assert!(OUTBOUND_QUEUE_MAX_BYTES > 15 * BLOCK_PRODUCTION_RESERVE_BYTES);

/// Maximum unsolicited block bodies one connection may hold in the shared
/// inbound block channel at once.
///
/// The channel itself is bounded globally, so without this per-connection
/// bound one flooding peer can occupy every slot and starve the rest of the
/// swarm of block ingress. Sixteen is the per-peer in-flight budget: a
/// connection may always keep the bodies it was asked for in play, and no
/// more unsolicited ones.
pub(crate) const MAX_UNSOLICITED_BLOCK_FORWARDS: usize = 16;

/// One admitted unsolicited block forward.
///
/// Holding it is the credit; dropping it — once the forwarded body is drained
/// by sync, discarded by the stager, or rejected — releases the connection's
/// slot. A credit for a body the download window already owns releases
/// nothing, because nothing was counted.
#[derive(Debug)]
pub(crate) struct BlockForwardCredit(Option<Arc<AtomicUsize>>);

impl Drop for BlockForwardCredit {
    fn drop(&mut self) {
        if let Some(counter) = &self.0 {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Item and full-framed-wire-byte accounting for one outbound queue.
///
/// Every queued message is owned by an [`OutboundCredit`]: a charge taken
/// here, against the local bounds first and then against the node aggregate,
/// before the message is queued. A message is charged when both local
/// counters were below their high-water marks immediately before its
/// addition, which admits one oversized message to an empty local queue. The
/// credit travels with the message as a [`QueuedFrame`] and releases both
/// halves when dropped, whether the writer wrote it, the writer's error path
/// dropped it, or the channel discarded it.
///
/// # Refusal policy
///
/// A local refusal ([`Refusal::Local`]: item cap, byte cap, dead writer)
/// disconnects only this peer: [`PeerLease::send`] cancels the lease and
/// returns the refused message. An aggregate refusal ([`Refusal::Shared`])
/// never does: the lease stays live and the caller keeps its intent. Bulk
/// production reserves a worst-case frame ([`OutboundBudget::try_reserve_production`])
/// before it loads a body, so a queue that is full by item count or by bytes
/// parks the session instead of reaching a refusal.
///
/// # Waiting
///
/// A paused session sleeps on a condvar guarded by a lock that protects no
/// data. The predicate it waits for reads atomics only, and every decrease of
/// those atomics (`release`, `shrink`, `mark_writer_dead`) updates the
/// counter, then takes the lock, then notifies. A waiter therefore either
/// sees the new state in its predicate check, or is already parked when the
/// notification fires, so no wake is lost. While an aggregate is attached the
/// wait parks on the aggregate condvar, so another connection's drain wakes
/// it too.
///
/// # Lock order
///
/// Caller locks (peer table, scheduler, relay state), then this budget's
/// `drained_lock`, then the aggregate's. No path holds the two budget locks
/// at once (the aggregate is charged and released with atomics under the
/// local lock, and notified only after the local lock is dropped), and no
/// send ever blocks.
#[derive(Debug)]
pub(crate) struct OutboundBudget {
    max_messages: usize,
    max_bytes: usize,
    block_reserve: usize,
    pending_messages: AtomicUsize,
    pending_bytes: AtomicUsize,
    /// Test instrumentation: count of refused charges and reservations.
    #[cfg(test)]
    refusals: AtomicUsize,
    /// Signalled when a credit releases or the writer exits.
    drained: Condvar,
    /// Serializes this connection's admissions and releases against each
    /// other and orders updates against a waiter's predicate check; guards
    /// no data.
    drained_lock: Mutex<()>,
    /// Set once the connection writer has returned. Later charges are
    /// refused; credits still release when their owners drop.
    writer_dead: AtomicBool,
    /// Aggregate byte budget of the owning node, or `None` for standalone
    /// budgets (tests). Every charge takes the local bound first, then the
    /// aggregate; every release returns both.
    shared: Option<Arc<SharedOutboundBudget>>,
}

impl OutboundBudget {
    /// Builds a production budget with the block-production reserve.
    #[must_use]
    pub(crate) fn new(max_messages: usize, max_bytes: usize) -> Self {
        Self::with_reserve(max_messages, max_bytes, BLOCK_PRODUCTION_RESERVE_BYTES)
    }

    fn with_reserve(max_messages: usize, max_bytes: usize, block_reserve: usize) -> Self {
        Self {
            max_messages,
            max_bytes,
            block_reserve,
            pending_messages: AtomicUsize::new(0),
            pending_bytes: AtomicUsize::new(0),
            #[cfg(test)]
            refusals: AtomicUsize::new(0),
            drained: Condvar::new(),
            drained_lock: Mutex::new(()),
            writer_dead: AtomicBool::new(false),
            shared: None,
        }
    }

    #[cfg(test)]
    /// Builds a test budget with a reduced block-production reserve.
    #[must_use]
    pub(crate) fn with_block_reserve(
        max_messages: usize,
        max_bytes: usize,
        block_reserve: usize,
    ) -> Self {
        Self::with_reserve(max_messages, max_bytes, block_reserve)
    }

    /// Charges `wire_len` bytes and one message.
    ///
    /// PRE: none. POST: `Ok` carries the credit that owns the charge on both
    /// halves; `Err(Local)` means the writer is gone or a local cap is at its
    /// high-water mark; `Err(Shared)` means the aggregate cap would be
    /// exceeded. A refusal charges nothing.
    pub(crate) fn try_charge(self: &Arc<Self>, wire_len: usize) -> Result<OutboundCredit, Refusal> {
        let _guard = self.drained_lock.lock();
        if self.writer_dead.load(Ordering::Acquire) {
            #[cfg(test)]
            self.refusals.fetch_add(1, Ordering::Relaxed);
            return Err(Refusal::Local);
        }
        let messages = self.pending_messages.load(Ordering::Acquire);
        let bytes = self.pending_bytes.load(Ordering::Acquire);
        if messages >= self.max_messages || bytes >= self.max_bytes {
            #[cfg(test)]
            self.refusals.fetch_add(1, Ordering::Relaxed);
            return Err(Refusal::Local);
        }
        if let Some(shared) = &self.shared
            && !shared.try_charge(wire_len, shared.max_bytes)
        {
            #[cfg(test)]
            self.refusals.fetch_add(1, Ordering::Relaxed);
            return Err(Refusal::Shared);
        }
        Ok(self.commit_locked(wire_len))
    }

    /// Reserves one worst-case frame before a body is loaded.
    ///
    /// PRE: none. POST: `Ok` carries a credit of the block-production
    /// reserve. The local rule is the production headroom (a free item slot
    /// and room for the reserve behind everything pending, or an empty
    /// queue); the aggregate rule is that the reserve fits under the bulk
    /// limit, which keeps one maximum frame of the aggregate for control
    /// traffic. A refusal charges nothing.
    pub(crate) fn try_reserve_production(self: &Arc<Self>) -> Result<OutboundCredit, Refusal> {
        let _guard = self.drained_lock.lock();
        if self.writer_dead.load(Ordering::Acquire) || !self.local_production_headroom() {
            #[cfg(test)]
            self.refusals.fetch_add(1, Ordering::Relaxed);
            return Err(Refusal::Local);
        }
        if let Some(shared) = &self.shared
            && !shared.try_charge(self.block_reserve, shared.bulk_limit)
        {
            #[cfg(test)]
            self.refusals.fetch_add(1, Ordering::Relaxed);
            return Err(Refusal::Shared);
        }
        Ok(self.commit_locked(self.block_reserve))
    }

    /// Reserves `bound` bytes for a reply that is built only afterwards.
    ///
    /// PRE: `bound` is at least the reply's wire length. POST: as
    /// [`Self::try_charge`].
    pub(crate) fn try_reserve_reply(
        self: &Arc<Self>,
        bound: usize,
    ) -> Result<OutboundCredit, Refusal> {
        self.try_charge(bound)
    }

    /// Adds the local half of a charge whose aggregate half is already taken.
    ///
    /// PRE: the caller holds `drained_lock`.
    fn commit_locked(self: &Arc<Self>, bytes: usize) -> OutboundCredit {
        self.pending_messages.fetch_add(1, Ordering::AcqRel);
        self.pending_bytes.fetch_add(bytes, Ordering::AcqRel);
        OutboundCredit {
            budget: Arc::clone(self),
            bytes,
        }
    }

    /// Gives back the part of `credit` beyond `to` bytes, on both halves.
    ///
    /// PRE: `credit` was charged to this budget and `to <= credit.bytes()`.
    /// POST: the credit owns exactly `to` bytes and still one message.
    fn shrink(&self, credit: &mut OutboundCredit, to: usize) {
        debug_assert!(to <= credit.bytes, "a credit only shrinks");
        let excess = credit.bytes.saturating_sub(to);
        if excess == 0 {
            return;
        }
        credit.bytes -= excess;
        {
            let _guard = self.drained_lock.lock();
            self.release_bytes_locked(excess);
            if let Some(shared) = &self.shared {
                shared.release_counter(excess);
            }
        }
        self.wake_after_release();
    }

    /// Returns one credit's charge. Called only by [`OutboundCredit`]'s drop.
    fn release(&self, wire_len: usize) {
        {
            let _guard = self.drained_lock.lock();
            let messages =
                self.pending_messages
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                        pending.checked_sub(1)
                    });
            debug_assert!(messages.is_ok(), "released more messages than charged");
            self.release_bytes_locked(wire_len);
            if let Some(shared) = &self.shared {
                shared.release_counter(wire_len);
            }
        }
        self.wake_after_release();
    }

    /// Subtracts local bytes. The caller holds `drained_lock`.
    fn release_bytes_locked(&self, bytes: usize) {
        let released =
            self.pending_bytes
                .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                    pending.checked_sub(bytes)
                });
        debug_assert!(released.is_ok(), "released more bytes than charged");
    }

    /// Notifies local waiters, then aggregate waiters, after counters moved.
    fn wake_after_release(&self) {
        self.wake_waiters();
        if let Some(shared) = &self.shared {
            shared.wake_waiters();
        }
    }

    /// Notifies every session paused in [`OutboundBudget::wait_for`].
    ///
    /// PRE: the state a waiter's predicate reads was updated before the call.
    /// POST: a waiter either observed that update or is woken by this call.
    /// INVARIANT: the empty critical section orders the update before any
    /// waiter's next predicate check; it never holds the lock across the
    /// notification's effects, so a woken waiter does not contend with it.
    fn wake_waiters(&self) {
        drop(self.drained_lock.lock());
        self.drained.notify_all();
    }

    /// Records that the connection writer has returned, then wakes every
    /// waiting session. It reclaims nothing: queued frames release their own
    /// charges when they drop.
    pub(crate) fn mark_writer_dead(&self) {
        {
            // Under the admission lock, so a charge either finished before
            // the writer died (its frame is drained or discarded, and
            // releases) or sees the flag and is refused.
            let _guard = self.drained_lock.lock();
            self.writer_dead.store(true, Ordering::Release);
        }
        self.wake_after_release();
    }

    /// Returns whether the connection writer has returned.
    #[must_use]
    pub(crate) fn writer_dead(&self) -> bool {
        self.writer_dead.load(Ordering::Acquire)
    }

    /// Blocks the calling session until `ready` holds, the writer exits, or
    /// `timeout` elapses.
    ///
    /// PRE: the caller holds no lock another thread needs to release the
    /// budget (the pool, the socket), and `ready` reads atomics only.
    /// POST: returns at once when the writer is dead or `ready` already
    /// holds; otherwise returns once either holds or `timeout` has elapsed on
    /// the monotonic clock. Spurious wakeups re-enter the wait. The return
    /// promises nothing: a snapshot that held can be taken by another sender
    /// before the caller acts, so the caller retries through the admission
    /// itself and rechecks [`OutboundBudget::writer_dead`] and its own
    /// cancellation.
    ///
    /// While an aggregate budget is attached the wait parks on the aggregate
    /// condvar instead: any connection's drain can open shared room, and
    /// every release wakes here.
    pub(crate) fn wait_for(&self, timeout: Duration, ready: impl Fn() -> bool) {
        let deadline = Instant::now() + timeout;
        if let Some(shared) = &self.shared {
            let mut guard = shared.drained_lock.lock();
            while !(self.writer_dead() || ready()) {
                if shared.drained.wait_until(&mut guard, deadline).timed_out() {
                    return;
                }
            }
            return;
        }
        let mut guard = self.drained_lock.lock();
        while !(self.writer_dead() || ready()) {
            if self.drained.wait_until(&mut guard, deadline).timed_out() {
                return;
            }
        }
    }

    /// Returns the charged `(messages, full wire bytes)` awaiting release.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn pending(&self) -> (usize, usize) {
        (
            self.pending_messages.load(Ordering::Acquire),
            self.pending_bytes.load(Ordering::Acquire),
        )
    }

    /// Returns the count of charges and reservations refused on this budget.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn refusals(&self) -> usize {
        self.refusals.load(Ordering::Acquire)
    }

    /// Snapshot: whether one more worst-case frame could be reserved right
    /// now ([`Self::try_reserve_production`] would not refuse). A wait and
    /// pacing predicate only; the reservation itself is the admission.
    #[must_use]
    pub(crate) fn may_reserve_production(&self) -> bool {
        self.local_production_headroom()
            && self
                .shared
                .as_ref()
                .is_none_or(|shared| shared.may_reserve_bulk(self.block_reserve))
    }

    /// Snapshot: whether a charge of `bytes` could be taken right now
    /// ([`Self::try_charge`] would not refuse). A wait and pacing predicate
    /// only.
    #[must_use]
    pub(crate) fn may_charge(&self, bytes: usize) -> bool {
        self.local_has_room()
            && self
                .shared
                .as_ref()
                .is_none_or(|shared| shared.may_admit(bytes))
    }

    /// The per-connection half of the production gate: a free item slot and
    /// room for the reserve behind everything pending, or an empty queue
    /// (which admits one oversized message). A snapshot of this connection's
    /// own queue state only: a probe whose refusal would close the lease
    /// asks it before sending, so the connection's own saturation is never
    /// mistaken for the aggregate's.
    pub(crate) fn local_production_headroom(&self) -> bool {
        let messages = self.pending_messages.load(Ordering::Acquire);
        messages == 0
            || (messages < self.max_messages
                && self
                    .pending_bytes
                    .load(Ordering::Acquire)
                    .saturating_add(self.block_reserve)
                    <= self.max_bytes)
    }

    /// The per-connection admit condition without the reserve: both local
    /// caps are below their high-water marks and the writer is alive.
    fn local_has_room(&self) -> bool {
        !self.writer_dead()
            && self.pending_messages.load(Ordering::Acquire) < self.max_messages
            && self.pending_bytes.load(Ordering::Acquire) < self.max_bytes
    }
}

/// Cloneable handle for one live peer connection.
#[derive(Clone, Debug)]
pub struct PeerLease {
    id: ConnectionId,
    outbound: Sender<QueuedFrame>,
    cancel: Arc<AtomicBool>,
    /// Read-only reference to the transport owner's epoch marker. Local
    /// connection cancellation and provider-epoch revocation are distinct;
    /// `is_cancelled` is their single predicate for all connection consumers.
    transport_alive: Option<Arc<AtomicBool>>,
    close_tx: Sender<()>,
    close_rx: Receiver<()>,
    budget: Arc<OutboundBudget>,
    /// Live unsolicited block forwards admitted by this connection.
    unsolicited_forwards: Arc<AtomicUsize>,
    /// Instant the writer queue last admitted a message on this connection.
    last_send: Arc<Mutex<Instant>>,
    inbound: bool,
    role: crate::peer_info::PeerRole,
    /// Whether the operator pinned this dial by hand (`--connect` or
    /// `addnode`). Core: `ConnectionType::MANUAL`.
    manual: bool,
    /// Granted only when the logical remote IP matches operator configuration.
    no_ban: bool,
    /// Monotonic instant the connection was created.
    connected: Instant,
}

impl PeerLease {
    /// Creates an outbound full-relay lease with a fresh process-unique identity.
    #[must_use]
    pub fn new(outbound: Sender<QueuedFrame>) -> Self {
        Self::with_direction(
            outbound,
            false,
            crate::peer_info::PeerRole::FullRelay,
            false,
        )
    }

    /// Creates an outbound block-relay-only lease.
    ///
    /// PRE: none.
    /// POST: the lease is outbound and its role is
    ///   [`crate::peer_info::PeerRole::BlockRelayOnly`], so the connection
    ///   carries blocks and headers only, in either direction.
    /// INVARIANT: the role is fixed for the life of the lease.
    #[must_use]
    pub(crate) fn new_block_relay(outbound: Sender<QueuedFrame>) -> Self {
        Self::with_direction(
            outbound,
            false,
            crate::peer_info::PeerRole::BlockRelayOnly,
            false,
        )
    }

    /// Creates an outbound lease the operator asked for by name.
    ///
    /// PRE: none.
    /// POST: the lease is outbound, carries `role`, and is manual.
    /// INVARIANT: Core's `ConnectionType::MANUAL` is exempt from the
    ///   chain-sync timeout and the extra-peer retirement
    ///   (`net_processing.cpp:5502`, `net_processing.cpp:5558-5604`):
    ///   replacing a hand-pinned connection would undo an explicit
    ///   instruction, so the flag must outlive every policy check.
    #[must_use]
    pub(crate) fn new_manual(
        outbound: Sender<QueuedFrame>,
        role: crate::peer_info::PeerRole,
    ) -> Self {
        Self::with_direction(outbound, false, role, true)
    }

    /// Creates an inbound lease with a fresh process-unique identity.
    #[must_use]
    pub fn new_inbound(outbound: Sender<QueuedFrame>) -> Self {
        Self::with_direction(outbound, true, crate::peer_info::PeerRole::FullRelay, false)
    }

    /// Test constructor: an outbound lease already `connected_at` old, for
    /// exercising rules gated on connection age without sleeping.
    #[cfg(test)]
    pub(crate) fn new_connected_at(outbound: Sender<QueuedFrame>, connected_at: Instant) -> Self {
        let mut lease = Self::new(outbound);
        lease.backdate_for_test(connected_at);
        lease
    }

    fn with_direction(
        outbound: Sender<QueuedFrame>,
        inbound: bool,
        role: crate::peer_info::PeerRole,
        manual: bool,
    ) -> Self {
        Self::with_budget(
            outbound,
            inbound,
            role,
            manual,
            OutboundBudget::new(OUTBOUND_QUEUE_MAX_MESSAGES, OUTBOUND_QUEUE_MAX_BYTES),
        )
    }

    fn with_budget(
        outbound: Sender<QueuedFrame>,
        inbound: bool,
        role: crate::peer_info::PeerRole,
        manual: bool,
        budget: OutboundBudget,
    ) -> Self {
        let (close_tx, close_rx) = crossbeam_channel::bounded(1);
        Self {
            id: ConnectionId::allocate(),
            outbound,
            cancel: Arc::new(AtomicBool::new(false)),
            transport_alive: None,
            close_tx,
            close_rx,
            budget: Arc::new(budget),
            unsolicited_forwards: Arc::new(AtomicUsize::new(0)),
            last_send: Arc::new(Mutex::new(Instant::now())),
            inbound,
            role,
            manual,
            no_ban: false,
            connected: Instant::now(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_budget(
        outbound: Sender<QueuedFrame>,
        inbound: bool,
        budget: OutboundBudget,
    ) -> Self {
        Self::with_budget(
            outbound,
            inbound,
            crate::peer_info::PeerRole::FullRelay,
            false,
            budget,
        )
    }

    pub(crate) fn with_transport_alive(mut self, alive: Option<Arc<AtomicBool>>) -> Self {
        self.transport_alive = alive;
        self
    }

    pub(crate) fn belongs_to_transport_epoch(&self, epoch: &Arc<AtomicBool>) -> bool {
        self.transport_alive
            .as_ref()
            .is_some_and(|alive| Arc::ptr_eq(alive, epoch))
    }

    pub(crate) fn with_no_ban(mut self, no_ban: bool) -> Self {
        self.no_ban = no_ban;
        self
    }

    /// Attaches the owning node's aggregate outbound budget to this lease's
    /// fresh per-connection budget: local message and byte bounds stay
    /// per-peer, queued bytes also count against the node aggregate.
    /// Construction-time only: call before any send, while the budget `Arc`
    /// is still solely owned (no handle has escaped) and its counters are
    /// still zero.
    #[must_use]
    pub(crate) fn with_shared_budget(mut self, shared: &Arc<SharedOutboundBudget>) -> Self {
        // Sole ownership holds: the budget `Arc` was just built with this
        // lease and no handle has escaped yet.
        if let Some(budget) = Arc::get_mut(&mut self.budget) {
            debug_assert!(budget.shared.is_none());
            budget.shared = Some(Arc::clone(shared));
        } else {
            debug_assert!(false, "the aggregate attaches before the budget is shared");
        }
        self
    }

    /// Whether the operator exempted this connection from automatic punishment.
    #[must_use]
    pub const fn is_no_ban(&self) -> bool {
        self.no_ban
    }

    pub(crate) const fn is_protected(&self) -> bool {
        self.manual || self.no_ban
    }

    pub(crate) fn ignores_protocol_error(&self, error: &crate::PeerError) -> bool {
        self.is_protected() && error.recoverable_for_protected()
    }

    /// Stable process-unique node id for this connection (Core `nodeid`).
    #[must_use]
    pub const fn node_id(&self) -> u64 {
        self.id.get()
    }

    /// Process-unique identity of this connection.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.id
    }

    /// Whether this connection was accepted by the listener.
    #[must_use]
    pub const fn is_inbound(&self) -> bool {
        self.inbound
    }

    /// What this connection relays. See [`crate::peer_info::PeerRole`].
    ///
    /// PRE: none.
    /// POST: the role assigned when the lease was created.
    /// INVARIANT: never changes; a replacement connection gets its own lease
    ///   and therefore its own role.
    #[must_use]
    pub const fn role(&self) -> crate::peer_info::PeerRole {
        self.role
    }

    /// Whether the operator pinned this connection by hand.
    ///
    /// PRE: none.
    /// POST: true exactly for a dial asked for by `--connect` or `addnode`.
    /// INVARIANT: never changes, like the role: the exemption the flag
    ///   carries is Core's `ConnectionType::MANUAL`
    ///   (`net_processing.cpp:5502`), and a connection that could lose it
    ///   mid-life could be evicted by a rule that never applied to it.
    #[must_use]
    pub const fn is_manual(&self) -> bool {
        self.manual
    }

    /// When this connection was created, on the monotonic clock.
    ///
    /// PRE: none.
    /// POST: the instant never moves, and it is never in the future
    ///   relative to a later read.
    /// INVARIANT: this holds the role Core's `nTimeConnected` holds
    ///   (`net.h`): the age a connection must reach before policy may
    ///   hold its silence against it.
    #[must_use]
    pub(crate) const fn connected_at(&self) -> Instant {
        self.connected
    }

    /// Moves this lease's connection instant into the past.
    #[cfg(test)]
    pub(crate) fn backdate_for_test(&mut self, at: Instant) {
        debug_assert!(at <= Instant::now());
        self.connected = at;
    }

    /// Receiver half of the close signal raised by [`PeerLease::cancel`].
    /// The connection writer selects on it so teardown never depends on
    /// remaining sender clones. Node code never observes this channel.
    pub(crate) fn close_signal(&self) -> Receiver<()> {
        self.close_rx.clone()
    }

    /// Shared handle to this connection's outbound admission budget.
    pub(crate) fn budget_handle(&self) -> Arc<OutboundBudget> {
        Arc::clone(&self.budget)
    }

    /// Admits one inbound block body into the shared inbound channel.
    ///
    /// PRE: `source` was stamped by this lease and `requested` reports whether
    ///   the download window already owns `hash` for this connection.
    /// POST: a requested body is always admitted; an unsolicited one is
    ///   admitted only while this connection holds fewer than
    ///   [`MAX_UNSOLICITED_BLOCK_FORWARDS`] credits, and `Some` carries the
    ///   credit that releases the slot when the forwarded body is dropped.
    /// INVARIANT: no admission here waits on the channel, disconnects the
    ///   connection, or lets one source exceed its own bound. Ownership is
    ///   the connection's, so a same-address replacement starts fresh.
    pub(crate) fn admit_block_forward(
        &self,
        source: PeerSource,
        hash: bitcoin_rs_primitives::Hash256,
        requested: bool,
    ) -> Option<BlockForwardCredit> {
        if requested {
            return Some(BlockForwardCredit(None));
        }
        let counter = Arc::clone(&self.unsolicited_forwards);
        // Increment-then-compare: a credit released on the sync thread
        // concurrently can never let two admissions cross the bound.
        if counter.fetch_add(1, Ordering::AcqRel) >= MAX_UNSOLICITED_BLOCK_FORWARDS {
            counter.fetch_sub(1, Ordering::AcqRel);
            tracing::debug!(
                peer_addr = ?source.endpoint,
                %hash,
                limit = MAX_UNSOLICITED_BLOCK_FORWARDS,
                "p2p dropping unsolicited block: per-connection forward bound reached"
            );
            return None;
        }
        Some(BlockForwardCredit(Some(counter)))
    }

    /// Instant the writer queue last admitted a message on this connection.
    #[must_use]
    pub(crate) fn last_send(&self) -> Instant {
        *self.last_send.lock()
    }

    /// Stamps an inbound event with this connection's identity and endpoint.
    #[must_use]
    pub fn source(&self, endpoint: Option<crate::PeerEndpoint>) -> PeerSource {
        PeerSource {
            endpoint,
            connection_id: self.id,
        }
    }

    /// Stamps an event for a direct-IP connection at `addr`.
    #[must_use]
    pub fn source_ip(&self, addr: SocketAddr) -> PeerSource {
        self.source(Some(crate::accepted_ip_identity(addr)))
    }

    /// Queues a message for this connection's writer.
    ///
    /// PRE: none. POST: `Ok` means the message is queued with its charge.
    /// `Closed` means the lease is cancelled, or this call cancelled it for
    /// the connection's own state (an unencodable message, a local item or
    /// byte cap, a dead writer, a full or closed channel). `Saturated` means
    /// the node's aggregate budget is full: the lease is live, nothing was
    /// cancelled, and the caller keeps its intent. The refused message is
    /// returned either way.
    /// INVARIANT: never blocks.
    ///
    /// Exactness of the accounting does not depend on the channel flavor:
    /// each frame's credit drops when the frame drops, wherever that
    /// happens (after the writer wrote it, when a refused enqueue returns
    /// it, when the writer drains the channel on exit, or when the channel
    /// discards it).
    #[expect(clippy::result_large_err)]
    pub fn send(&self, message: crate::Message) -> Result<(), OutboundRefusal> {
        if self.is_cancelled() {
            return Err(OutboundRefusal::Closed(message));
        }
        // Feature advertisements belong to Peer::send's handshake window,
        // never the post-handshake queue, even when the shared budget is full.
        if matches!(message, crate::Message::Feature(_)) {
            self.cancel();
            return Err(OutboundRefusal::Closed(message));
        }
        let Ok(wire_len) = crate::wire::wire_len(&message) else {
            self.cancel();
            return Err(OutboundRefusal::Closed(message));
        };
        match self.budget.try_charge(wire_len) {
            Ok(credit) => self.enqueue(message, credit),
            Err(Refusal::Local) => {
                self.cancel();
                Err(OutboundRefusal::Closed(message))
            }
            Err(Refusal::Shared) => Err(OutboundRefusal::Saturated(message)),
        }
    }

    /// Queues a message under a reservation taken before the message existed.
    ///
    /// PRE: `credit` was charged to this lease's budget and covers the
    /// message's wire length. POST: the credit is shrunk to the exact wire
    /// length and travels with the message. A cancelled lease, an unencodable
    /// message, or a message larger than its reservation closes the lease
    /// (fail closed) and drops the credit. This never returns `Saturated`:
    /// the bytes were already taken.
    #[expect(clippy::result_large_err)]
    pub(crate) fn send_with(
        &self,
        mut credit: OutboundCredit,
        message: crate::Message,
    ) -> Result<(), OutboundRefusal> {
        debug_assert!(
            credit.belongs_to(&self.budget),
            "a credit is spent only on the lease that charged it"
        );
        if self.is_cancelled() {
            return Err(OutboundRefusal::Closed(message));
        }
        // A reserved credit is released on this local protocol refusal.
        if matches!(message, crate::Message::Feature(_)) {
            self.cancel();
            return Err(OutboundRefusal::Closed(message));
        }
        let Ok(wire_len) = crate::wire::wire_len(&message) else {
            self.cancel();
            return Err(OutboundRefusal::Closed(message));
        };
        if wire_len > credit.bytes() {
            self.cancel();
            return Err(OutboundRefusal::Closed(message));
        }
        self.budget.shrink(&mut credit, wire_len);
        self.enqueue(message, credit)
    }

    /// Hands a charged message to the writer channel.
    #[expect(clippy::result_large_err)]
    fn enqueue(
        &self,
        message: crate::Message,
        credit: OutboundCredit,
    ) -> Result<(), OutboundRefusal> {
        match self.outbound.try_send(QueuedFrame { message, credit }) {
            Ok(()) => {
                *self.last_send.lock() = Instant::now();
                Ok(())
            }
            Err(TrySendError::Full(frame) | TrySendError::Disconnected(frame)) => {
                // Taking the frame apart returns its charge.
                let message = frame.into_message();
                self.cancel();
                Err(OutboundRefusal::Closed(message))
            }
        }
    }

    /// Reserves one worst-case bulk frame before a body is loaded.
    ///
    /// PRE: none. POST: `Ok` carries the credit, spent with
    /// [`Self::send_with`] or dropped to return the bytes. Refusal charges
    /// nothing and cancels nothing; the caller decides what a local or a
    /// shared refusal means.
    pub(crate) fn try_reserve_production(&self) -> Result<OutboundCredit, Refusal> {
        self.budget.try_reserve_production()
    }

    /// Reserves `bound` bytes for a reply built only afterwards.
    ///
    /// PRE: `bound` is at least the reply's full wire length. POST: as
    /// [`Self::try_reserve_production`].
    pub(crate) fn try_reserve_reply(&self, bound: usize) -> Result<OutboundCredit, Refusal> {
        self.budget.try_reserve_reply(bound)
    }

    /// Returns whether `source` was stamped by this lease.
    #[must_use]
    pub fn is_current(&self, source: PeerSource) -> bool {
        self.id == source.connection_id
    }

    /// Returns whether both handles refer to the same connection.
    #[must_use]
    pub(crate) fn same_connection(&self, other: &Self) -> bool {
        self.id == other.id
    }

    /// Requests prompt teardown of this connection.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
        let _ = self.close_tx.try_send(());
    }

    /// Returns whether teardown has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
            || self
                .transport_alive
                .as_ref()
                .is_some_and(|alive| !alive.load(Ordering::Acquire))
    }
}

#[cfg(test)]
mod tests;
