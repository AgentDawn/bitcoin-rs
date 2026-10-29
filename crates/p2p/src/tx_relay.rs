//! Outbound transaction relay worker.
//!
//! Announces mempool-accepted transactions to connected peers as `inv`
//! messages, **excluding the peer that delivered the transaction** (by its
//! node id). Bitcoin Core never re-advertises a transaction to the peer it
//! just received it from; this worker encodes that policy.
//!
//! # Architecture
//!
//! [`TxRelayQueue`] is the producer side: a bounded crossbeam channel of
//! [`RelayRequest`]s plus drop accounting. The admission path calls
//! [`TxRelayQueue::announce`] without blocking — relay is best-effort and
//! must never stall mempool admission.
//!
//! [`PeerRelaySink`] queues identities and admission epochs in the shared
//! transaction-policy owner. Its timer drains fee-filtered, dependency-ordered
//! batches after randomized per-connection deadlines; known inventory and
//! source exclusion prevent repeats. A delayed item is checked against the
//! gateway again before enqueueing the wire message. A later removal can
//! still race the peer's eventual `getdata`, which then answers `notfound`.
//!
//! [`spawn_tx_relay_worker`] drives both request deadlines and relay timers.
//! Admission callbacks only write the bounded producer queue and never wait
//! for a peer or a timer.
//!
//! # Queue saturation
//!
//! The relay queue is bounded. When full, the newest announcement is
//! **dropped** (the producer never blocks). Later inventory exchanges may
//! advertise it again; relay stays best-effort and admission never stalls.
//! Pending local initial broadcasts also retry through this worker in bounded
//! batches until a successful getdata body response clears the live entry flag.
//! Per-peer outbound saturation follows the existing
//! p2p disconnect policy on [`crate::PeerLease::send`]: a peer whose
//! outbound queue is full is disconnected (its lease is cancelled), never
//! silently dropped while the connection remains live.
//!
//! Peer-origin accepts are announced by the ingress caller after the gateway
//! returns a committed admission. RPC and reorg accepts announce through
//! [`LocalTxRelayObserver`] on the same queue. These triggers intentionally
//! retain their separate timing. Local notifications look up the accepted
//! entry's real wtxid only while that acceptance remains resident. The
//! gateway reference is weak so its observer cannot retain the gateway.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

#[cfg(test)]
use crate::PeerLease;
#[cfg(test)]
use bitcoin_rs_mempool::BodyInterest;
use bitcoin_rs_mempool::{
    AdmissionOrigin, MempoolGateway, MempoolObserver, MutationEnvelope, MutationOutcome,
};
use bitcoin_rs_primitives::{Txid, Wtxid};
use crossbeam_channel::{Receiver, Sender, TrySendError};

/// Default maximum pending transaction announcements.
pub const DEFAULT_TX_RELAY_QUEUE_CAPACITY: usize = 1024;

/// Drain poll interval when the relay queue is empty.
const RELAY_POLL: Duration = Duration::from_millis(100);
const INITIAL_BROADCAST_RETRY: Duration = Duration::from_secs(1);
const INITIAL_BROADCAST_BATCH: usize = 1024;

/// One accepted transaction awaiting `inv` announcement.
#[derive(Clone, Copy, Debug)]
pub struct RelayRequest {
    /// Transaction id advertised in `inv` vectors.
    pub txid: Txid,
    /// Accepted transaction's witness identifier for BIP339 peers.
    pub wtxid: Wtxid,
    /// The delivering peer's node id to exclude, or `None` for local
    /// injection.
    pub source: Option<u64>,
    /// The mempool admission epoch the request was queued under, from
    /// [`bitcoin_rs_mempool::MutationResult::sequence_of`]. Removal
    /// and re-admission of the same body invalidates the epoch, so the
    /// send-time check matches the exact admission that queued the request.
    pub sequence: u64,
}

impl RelayRequest {
    /// Builds a relay request for an accepted transaction.
    #[must_use]
    pub fn new(txid: Txid, wtxid: Wtxid, source: Option<u64>, sequence: u64) -> Self {
        Self {
            txid,
            wtxid,
            source,
            sequence,
        }
    }
}

/// Bounded producer side of the relay queue.
///
/// Cloneable and cheap to share: the underlying crossbeam [`Sender`] is
/// cloneable. [`announce`](Self::announce) never blocks — on a full queue the
/// request is dropped and [`dropped`](Self::dropped) is incremented.
#[derive(Clone)]
pub struct TxRelayQueue {
    tx: Sender<RelayRequest>,
    enqueued: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl TxRelayQueue {
    /// Creates a bounded relay queue of `capacity` pending announcements and
    /// returns the queue plus the receiver the worker drains.
    #[must_use]
    pub fn new(capacity: usize) -> (Self, Receiver<RelayRequest>) {
        let (tx, rx) = crossbeam_channel::bounded(capacity);
        let queue = Self {
            tx,
            enqueued: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        };
        (queue, rx)
    }

    /// Enqueues one announcement without blocking.
    ///
    /// Returns `true` if the request was queued, `false` if the queue was
    /// full (the request is dropped) or the worker receiver has been dropped.
    /// Admission callers ignore the return value: relay is best-effort.
    pub fn announce(&self, txid: Txid, wtxid: Wtxid, source: Option<u64>, sequence: u64) -> bool {
        let request = RelayRequest::new(txid, wtxid, source, sequence);
        match self.tx.try_send(request) {
            Ok(()) => {
                self.enqueued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Total announcements successfully enqueued since construction.
    #[must_use]
    pub fn enqueued(&self) -> u64 {
        self.enqueued.load(Ordering::Relaxed)
    }

    /// Total announcements dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Announces locally-injected accepted transactions (`sendrawtransaction`,
/// Esplora `POST /tx`, reorg re-admission) to every connected peer.
///
/// Peer-origin accepts are announced by their ingress caller after admission
/// returns a committed outcome. This observer publishes RPC, Esplora and reorg
/// acceptances, which have no source peer to exclude.
pub struct LocalTxRelayObserver {
    relay: TxRelayQueue,
    gateway: Weak<MempoolGateway>,
}

impl LocalTxRelayObserver {
    /// Relays accepted local mutations through `relay`.
    #[must_use]
    pub fn new(relay: TxRelayQueue, gateway: Weak<MempoolGateway>) -> Self {
        Self { relay, gateway }
    }
}

impl MempoolObserver for LocalTxRelayObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        if !matches!(
            envelope.origin,
            AdmissionOrigin::Rpc | AdmissionOrigin::Esplora | AdmissionOrigin::Reorg
        ) {
            return;
        }
        let Some(gateway) = self.gateway.upgrade() else {
            return;
        };
        for (index, change) in envelope.result.changes.iter().enumerate() {
            if !matches!(change.outcome, MutationOutcome::Accepted) {
                continue;
            }
            let txid = Txid(change.txid);
            let Some(sequence) = envelope.result.sequence_of(index) else {
                continue;
            };
            let wtxid = gateway
                .read()
                .entry_by_txid_at_sequence(&txid, sequence)
                .map(|entry| entry.wtxid);
            if let Some(wtxid) = wtxid {
                self.relay.announce(txid, wtxid, None, sequence);
            }
        }
    }
}

/// Synchronous announcement admission reported by a [`RelaySink`].
///
/// Deferred inventory delivery occurs during `poll`; its send failures cannot
/// be reported in an earlier admission result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayOutcome {
    /// Handshake-complete peers considered for the announcement.
    pub attempted: usize,
    /// Peers skipped because they were the source of the transaction.
    pub excluded: usize,
    /// Peers whose pending announcement queue could not accept this identity
    /// because its per-peer or global budget was saturated. This counts queue
    /// admission failures; later transport failures are logged when polled.
    pub saturated: usize,
}

/// Consumer seam for the relay worker.
pub trait RelaySink: Send + Sync {
    /// Advances time-based transaction download policy.
    fn poll(&self, _gateway: &MempoolGateway) {}

    /// Queues an accepted identity and admission epoch, excluding its source.
    /// The production sink emits inventory on its next eligible timer tick.
    fn announce_inv(
        &self,
        txid: Txid,
        wtxid: Wtxid,
        exclude: Option<u64>,
        sequence: u64,
    ) -> RelayOutcome;
}

/// Production [`RelaySink`] over the shared peer table.
///
/// Borrows the shared table, so the relay worker sees peer
/// connect/disconnect/reconnect and their published BIP339 preference. A
/// handshaking lease receives no inventory: choosing before negotiation could
/// queue `MSG_TX` for a connection that later requests `MSG_WTX`. A
/// block-relay-only lease receives none either: transaction relay is
/// prohibited on such a connection, as Core restricts `RelayTransaction` to
/// full-relay peers (`net_processing.cpp:5186-5260`).
pub struct PeerRelaySink {
    peers: Arc<crate::PeerTable>,
    ibd: Option<(
        Arc<bitcoin_rs_chain::InitialBlockDownload>,
        bitcoin_rs_primitives::Network,
    )>,
}

impl PeerRelaySink {
    /// Wraps the shared peer table.
    #[must_use]
    pub fn new(peers: Arc<crate::PeerTable>) -> Self {
        Self { peers, ibd: None }
    }

    /// Shares the node's existing IBD decision for outgoing fee filters.
    #[must_use]
    pub fn with_ibd(
        mut self,
        ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
        network: bitcoin_rs_primitives::Network,
    ) -> Self {
        self.ibd = Some((ibd, network));
        self
    }
}

impl RelaySink for PeerRelaySink {
    fn poll(&self, gateway: &MempoolGateway) {
        use bitcoin::secp256k1::rand::SeedableRng as _;
        let ibd = crate::block_announce::ibd_active(self.ibd.as_ref());
        if !ibd {
            self.peers.poll_transaction_requests(gateway);
        }
        let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::from_entropy();
        self.peers
            .poll_transaction_relay(gateway, std::time::Instant::now(), ibd, &mut rng);
    }

    fn announce_inv(
        &self,
        txid: Txid,
        wtxid: Wtxid,
        exclude: Option<u64>,
        sequence: u64,
    ) -> RelayOutcome {
        use bitcoin::secp256k1::rand::SeedableRng as _;
        let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::from_entropy();
        let outcome = self.peers.queue_transaction_relay(
            RelayRequest::new(txid, wtxid, exclude, sequence),
            std::time::Instant::now(),
            &mut rng,
        );
        if outcome.saturated > 0 {
            tracing::debug!(%txid, peers = outcome.saturated, "transaction relay pending budget full");
        }
        outcome
    }
}

/// Returns whether the queued transaction is still relayable.
///
/// PRE: `gateway` is the shared gateway for the node's live mempool.
/// POST: returns true exactly when the admission that queued `request` —
/// identified by its txid at its admission epoch — is still resident in the
/// mempool read at this call. Removal and re-admission, even of byte-identical
/// bytes or a witness-mutated same-txid entry, does not satisfy the queued
/// request: `entry_by_txid_at_sequence` invalidates on the sequence, so a
/// stale request can neither announce a transaction admitted under a
/// different epoch nor advertise it back to a different source peer.
/// INVARIANT: the check does not mutate the mempool, relay queue, or
/// observer state. The read guard is released before this function
/// returns, so no caller holds it while it sends to peers.
fn transaction_is_live(gateway: &MempoolGateway, request: &RelayRequest) -> bool {
    gateway
        .read()
        .entry_by_txid_at_sequence(&request.txid, request.sequence)
        .is_some()
}

// Pending state belongs to the live mempool entries, not a second relay queue.
// Retry bounded batches so absent peers or queue saturation cannot consume the
// only announcement. The existing sink applies peer, fee and inventory rules.
fn retry_initial_broadcast(
    gateway: &MempoolGateway,
    sink: &dyn RelaySink,
    cursor: &mut Option<Wtxid>,
) {
    let requests: Vec<_> = gateway
        .read()
        .unbroadcast_transactions_after(*cursor)
        .take(INITIAL_BROADCAST_BATCH)
        .map(|(txid, wtxid, sequence)| RelayRequest::new(txid, wtxid, None, sequence))
        .collect();
    *cursor = if requests.len() < INITIAL_BROADCAST_BATCH {
        None
    } else {
        requests.last().map(|request| request.wtxid)
    };
    for request in requests {
        if transaction_is_live(gateway, &request) {
            sink.announce_inv(request.txid, request.wtxid, None, request.sequence);
        }
    }
}

/// Synchronously drains every currently-queued relay request into `sink`,
/// announcing only transactions still resident in `gateway`.
///
/// Returns the number of requests processed. Tests call it to flush the
/// queue deterministically.
///
/// PRE: `gateway` is the shared gateway for the node's live mempool; `rx`
/// is the relay queue receiver.
/// POST: every request queued at the call is consumed and counted once. A
/// request whose transaction is resident with its queued wtxid at the send
/// is announced through `sink`, excluding its source connection. A request
/// whose transaction left the mempool — or was re-admitted under a
/// different wtxid — produces no announcement.
/// INVARIANT: no mempool guard is held while `sink` sends to peers.
#[cfg(test)]
pub(crate) fn drain_relay_queue(
    rx: &Receiver<RelayRequest>,
    sink: &dyn RelaySink,
    gateway: &MempoolGateway,
) -> usize {
    let mut processed = 0;
    while let Ok(request) = rx.try_recv() {
        if transaction_is_live(gateway, &request) {
            sink.announce_inv(
                request.txid,
                request.wtxid,
                request.source,
                request.sequence,
            );
        }
        processed += 1;
    }
    processed
}

/// Spawns the single tx-relay worker thread.
///
/// The thread drains [`RelayRequest`]s from `rx` and announces each through
/// `sink`, excluding the source connection, while its transaction is still
/// in `gateway`. It exits when `shutdown` is set or the queue sender is
/// dropped.
///
/// PRE: `gateway` is a weak handle to the shared gateway for the node's live
/// mempool; it remains upgradeable while the node is running.
/// POST: each request is announced exactly when its transaction is resident
/// with its queued wtxid at the send; a request for a removed or
/// witness-mutated transaction is consumed with no announcement. The
/// thread ends on `shutdown` or queue close.
/// INVARIANT: no mempool guard is held while `sink` sends to peers. The
/// worker applies the same send-time rule as `drain_relay_queue` and never
/// retains a strong gateway reference while it waits for queue input.
pub fn spawn_tx_relay_worker<S: RelaySink + 'static>(
    sink: S,
    rx: Receiver<RelayRequest>,
    gateway: Weak<MempoolGateway>,
    shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let shutdown = shutdown.into();
    std::thread::Builder::new()
        .name("bitcoin-rs-tx-relay".to_owned())
        .spawn(move || {
            let mut next_initial = std::time::Instant::now() + INITIAL_BROADCAST_RETRY;
            let mut initial_cursor = None;
            while !shutdown.load() {
                {
                    let Some(gateway) = gateway.upgrade() else {
                        break;
                    };
                    sink.poll(&gateway);
                    if std::time::Instant::now() >= next_initial {
                        retry_initial_broadcast(&gateway, &sink, &mut initial_cursor);
                        next_initial = std::time::Instant::now() + INITIAL_BROADCAST_RETRY;
                    }
                }
                match rx.recv_timeout(RELAY_POLL) {
                    Ok(request) => {
                        let Some(gateway) = gateway.upgrade() else {
                            break;
                        };
                        if transaction_is_live(&gateway, &request) {
                            sink.announce_inv(
                                request.txid,
                                request.wtxid,
                                request.source,
                                request.sequence,
                            );
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
