//! Bitcoin Core-compatible ZMQ notification protocol and transport.
//!
//! Bitcoin Core publishes "hashblock", "hashtx", "rawblock", and "rawtx" events
//! via ZMQ for client subscribers. The node decides when committed transitions
//! are published; this module owns how those notifications are represented and
//! transported.

#[cfg(feature = "zmq")]
use anyhow::Context as _;
use anyhow::{Result, ensure};
use bitcoin_rs_primitives::{Hash256, Txid};

#[cfg(test)]
use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
#[cfg(feature = "zmq")]
use core::fmt;
#[cfg(feature = "zmq")]
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::HashSet as StdHashSet;
#[cfg(feature = "zmq")]
use std::sync::atomic::{AtomicU32, Ordering};

/// ZMQ PUB notification topic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ZmqTopic {
    HashBlock,
    HashTx,
    RawBlock,
    RawTx,
    Sequence,
}

/// Default outbound queue limit for one ZMQ PUB endpoint.
const DEFAULT_ZMQ_HWM: u32 = 1_000;

/// Configuration for one ZMQ PUB socket.
///
/// Topics sharing an endpoint necessarily share its socket-level HWM.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ZmqEndpointConfig {
    pub endpoint: String,
    pub topics: Vec<ZmqTopic>,
    /// Maximum queued outbound messages, in `1..=i32::MAX`; zero is unbounded in libzmq.
    #[serde(default)]
    pub hwm: Option<u32>,
}

impl ZmqEndpointConfig {
    /// Returns the socket HWM after applying the publisher default.
    #[must_use]
    pub fn effective_hwm(&self) -> u32 {
        self.hwm.unwrap_or(DEFAULT_ZMQ_HWM)
    }
}

/// Validates grouped ZMQ configuration before it reaches a runtime boundary.
pub fn validate_endpoint_configs(configs: &[ZmqEndpointConfig]) -> Result<()> {
    let mut endpoints = StdHashSet::new();
    for config in configs {
        ensure!(
            !config.endpoint.trim().is_empty(),
            "ZMQ endpoint must not be empty"
        );
        ensure!(
            !config.topics.is_empty(),
            "ZMQ endpoint {} must have at least one topic",
            config.endpoint
        );
        ensure!(
            endpoints.insert(&config.endpoint),
            "duplicate ZMQ endpoint: {}",
            config.endpoint
        );
        let hwm = config.effective_hwm();
        ensure!(
            hwm > 0,
            "ZMQ HWM must be positive; zero disables libzmq's queue limit"
        );
        ensure!(
            i32::try_from(hwm).is_ok(),
            "ZMQ HWM exceeds libzmq's signed SNDHWM range: {hwm}"
        );
        let mut topics = StdHashSet::new();
        for topic in &config.topics {
            ensure!(
                topics.insert(topic),
                "duplicate ZMQ topic on endpoint: {}",
                config.endpoint
            );
        }
    }
    Ok(())
}

impl ZmqTopic {
    /// Returns the Core topic string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HashBlock => "hashblock",
            Self::HashTx => "hashtx",
            Self::RawBlock => "rawblock",
            Self::RawTx => "rawtx",
            Self::Sequence => "sequence",
        }
    }

    /// Returns the Core notifier name reported by `getzmqnotifications`.
    #[must_use]
    pub const fn notifier_type(self) -> &'static str {
        match self {
            Self::HashBlock => "pubhashblock",
            Self::HashTx => "pubhashtx",
            Self::RawBlock => "pubrawblock",
            Self::RawTx => "pubrawtx",
            Self::Sequence => "pubsequence",
        }
    }

    #[cfg(feature = "zmq")]
    const fn index(self) -> usize {
        match self {
            Self::HashBlock => 0,
            Self::HashTx => 1,
            Self::RawBlock => 2,
            Self::RawTx => 3,
            Self::Sequence => 4,
        }
    }
}

/// Event published on Core's unified `sequence` topic.
#[derive(Debug, Eq, PartialEq)]
pub enum SequenceEvent {
    /// A block was connected.
    Connected(Hash256),
    /// A block was disconnected.
    Disconnected(Hash256),
    /// A transaction was admitted to the mempool, with the mempool sequence
    /// assigned to the admission.
    Added(Txid, u64),
    /// A transaction left the mempool, with the mempool sequence assigned to
    /// the removal. Block-inclusion removals never publish this event: Core
    /// suppresses `R` when the block's own `C` event already covers the
    /// departure.
    Removed(Txid, u64),
}

impl SequenceEvent {
    #[cfg(any(feature = "zmq", test))]
    const fn label(self) -> u8 {
        match self {
            Self::Connected(_) => b'C',
            Self::Disconnected(_) => b'D',
            Self::Added(..) => b'A',
            Self::Removed(..) => b'R',
        }
    }
}

/// One live bound notifier, the fact Core's `getzmqnotifications` reports per
/// active notifier.
///
/// Core enumerates `CZMQNotificationInterface::GetActiveNotifiers()` at call
/// time, each carrying its type, address, and high-water mark. The projection
/// layer owns the JSON rendering: `topic` maps to the `pub…` type string and
/// `endpoint` to the `address` key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZmqNotifier {
    pub topic: ZmqTopic,
    pub endpoint: String,
    pub hwm: u32,
}

/// Publishes block + transaction notification events.
///
/// Implementations should be best-effort — publish failures must NOT propagate
/// into the apply pipeline. Use interior mutability + atomics if state is
/// needed; the trait is `&self`-only.
pub trait ZmqPublisher: Send + Sync + core::fmt::Debug {
    /// Returns whether any ZMQ notification emitted by the apply path is observable.
    ///
    /// The default is conservative for external implementations: keep invoking
    /// publisher methods unless an implementation proves the whole publisher is
    /// a no-op.
    fn wants_notifications(&self) -> bool {
        true
    }

    /// Returns whether the publisher can consume per-transaction raw bytes.
    ///
    /// The default is conservative for external implementations: keep producing
    /// rawtx payloads unless an implementation proves they are unobservable.
    fn wants_rawtx(&self) -> bool {
        true
    }

    /// Returns whether the publisher can consume full serialized block bytes.
    ///
    /// The default is conservative for external implementations: keep producing
    /// rawblock payloads unless an implementation proves they are unobservable.
    fn wants_rawblock(&self) -> bool {
        true
    }

    /// Returns the notifiers this publisher has live-bound, enumerated at
    /// call time.
    ///
    /// The default reports none: publishers without enumerable bound
    /// endpoints (the no-op and tracing publishers) have no live notifier,
    /// matching Core's empty result when the ZMQ notification interface is
    /// absent.
    fn active_notifiers(&self) -> Vec<ZmqNotifier> {
        Vec::new()
    }

    /// Publish a `hashblock` notification (block hash big-endian display bytes).
    fn publish_hashblock(&self, hash: Hash256);

    /// Publish a `hashtx` notification (transaction id big-endian display bytes).
    fn publish_hashtx(&self, txid: Txid);

    /// Publish a `rawblock` notification with the serialized block bytes.
    fn publish_rawblock(&self, bytes: &[u8]);

    /// Publish a `rawtx` notification with the serialized transaction bytes.
    fn publish_rawtx(&self, bytes: &[u8]);

    /// Publish a block event on Core's unified `sequence` topic.
    fn publish_sequence(&self, _event: SequenceEvent) {}
}

/// Default no-op implementation. All methods discard their input silently.
///
/// Use this when ZMQ notifications are not configured.
#[derive(Debug)]
pub struct NoOpZmqPublisher;

impl ZmqPublisher for NoOpZmqPublisher {
    fn wants_notifications(&self) -> bool {
        false
    }

    fn wants_rawtx(&self) -> bool {
        false
    }

    fn wants_rawblock(&self) -> bool {
        false
    }

    fn publish_hashblock(&self, _hash: Hash256) {}

    fn publish_hashtx(&self, _txid: Txid) {}

    fn publish_rawblock(&self, _bytes: &[u8]) {}

    fn publish_rawtx(&self, _bytes: &[u8]) {}
}

/// Publish one `hashtx` notification per newly admitted transaction id.
///
/// The sole caller is [`MempoolSequenceObserver`]'s `Accepted` arm, which
/// passes each committed `Accepted` change's txid in mutation order.
/// Rejected submissions, already-known (duplicate) admissions, and removals
/// never reach this helper: duplicates and refusals commit nothing, and
/// block-inclusion removals publish nothing.
pub fn publish_admitted_hashtx(
    publisher: &dyn ZmqPublisher,
    txids: impl IntoIterator<Item = Txid>,
) {
    for txid in txids {
        publisher.publish_hashtx(txid);
    }
}

#[cfg(feature = "zmq")]
struct EndpointSocket {
    endpoint: String,
    socket: Mutex<zmq::Socket>,
}

/// Socket-backed ZMQ PUB publisher.
#[cfg(feature = "zmq")]
pub struct SocketZmqPublisher {
    _context: zmq::Context,
    endpoints: Vec<EndpointSocket>,
    hashblock_endpoints: Vec<usize>,
    hashtx_endpoints: Vec<usize>,
    rawblock_endpoints: Vec<usize>,
    rawtx_endpoints: Vec<usize>,
    sequence_endpoints: Vec<usize>,
    notifiers: Vec<ZmqNotifier>,
    counters: [AtomicU32; 5],
}

#[cfg(feature = "zmq")]
impl fmt::Debug for SocketZmqPublisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketZmqPublisher")
            .field("endpoints", &self.endpoints.len())
            .field("notifiers", &self.notifiers.len())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "zmq")]
impl SocketZmqPublisher {
    /// Binds one PUB socket per endpoint group.
    ///
    /// Duplicate endpoint groups are rejected because one endpoint identifies
    /// one owned socket and one HWM. Duplicate topics inside a group are
    /// recorded once.
    pub fn bind(endpoint_configs: &[ZmqEndpointConfig]) -> Result<Self> {
        let deduped_configs: Vec<ZmqEndpointConfig> = endpoint_configs
            .iter()
            .map(|config| {
                let mut seen = StdHashSet::new();
                ZmqEndpointConfig {
                    endpoint: config.endpoint.clone(),
                    topics: config
                        .topics
                        .iter()
                        .filter(|&&topic| seen.insert(topic))
                        .copied()
                        .collect(),
                    hwm: config.hwm,
                }
            })
            .collect();
        validate_endpoint_configs(&deduped_configs)?;
        let context = zmq::Context::new();
        let mut endpoints = Vec::new();
        let mut hashblock_endpoints = Vec::new();
        let mut hashtx_endpoints = Vec::new();
        let mut rawblock_endpoints = Vec::new();
        let mut rawtx_endpoints = Vec::new();
        let mut sequence_endpoints = Vec::new();
        let mut notifiers = Vec::new();

        for endpoint_config in &deduped_configs {
            let hwm = endpoint_config.effective_hwm();
            let socket = context.socket(zmq::PUB).context("create ZMQ PUB socket")?;
            socket
                .set_sndhwm(i32::try_from(hwm).context("ZMQ HWM exceeds i32")?)
                .with_context(|| {
                    format!("set ZMQ SNDHWM for endpoint {}", endpoint_config.endpoint)
                })?;
            socket.set_linger(0).with_context(|| {
                format!("set ZMQ LINGER for endpoint {}", endpoint_config.endpoint)
            })?;
            if is_ipv6_tcp_endpoint(&endpoint_config.endpoint) {
                socket.set_ipv6(true).with_context(|| {
                    format!("set ZMQ IPv6 for endpoint {}", endpoint_config.endpoint)
                })?;
            }
            socket
                .bind(&endpoint_config.endpoint)
                .with_context(|| format!("bind ZMQ PUB endpoint {}", endpoint_config.endpoint))?;
            let endpoint_index = endpoints.len();
            endpoints.push(EndpointSocket {
                endpoint: endpoint_config.endpoint.clone(),
                socket: Mutex::new(socket),
            });
            for &topic in &endpoint_config.topics {
                notifiers.push(ZmqNotifier {
                    topic,
                    endpoint: endpoint_config.endpoint.clone(),
                    hwm,
                });
                match topic {
                    ZmqTopic::HashBlock => hashblock_endpoints.push(endpoint_index),
                    ZmqTopic::HashTx => hashtx_endpoints.push(endpoint_index),
                    ZmqTopic::RawBlock => rawblock_endpoints.push(endpoint_index),
                    ZmqTopic::RawTx => rawtx_endpoints.push(endpoint_index),
                    ZmqTopic::Sequence => sequence_endpoints.push(endpoint_index),
                }
            }
        }

        Ok(Self {
            _context: context,
            endpoints,
            hashblock_endpoints,
            hashtx_endpoints,
            rawblock_endpoints,
            rawtx_endpoints,
            sequence_endpoints,
            notifiers,
            counters: core::array::from_fn(|_| AtomicU32::new(0)),
        })
    }

    fn publish(&self, topic: ZmqTopic, body: &[u8]) {
        let sequence_value = self.counters[topic.index()].fetch_add(1, Ordering::Relaxed);
        let sequence = sequence_body(sequence_value);
        let topic_bytes = topic.as_str().as_bytes();
        for endpoint_index in self.endpoints_for(topic) {
            let endpoint = &self.endpoints[*endpoint_index];
            let socket = endpoint.socket.lock();
            if let Err(error) =
                socket.send_multipart([topic_bytes, body, sequence.as_slice()], zmq::DONTWAIT)
            {
                tracing::debug!(
                    target: "bitcoin_rs_rpc::zmq",
                    %error,
                    endpoint = %endpoint.endpoint,
                    topic = topic.as_str(),
                    "dropping ZMQ notification"
                );
            }
        }
    }

    fn endpoints_for(&self, topic: ZmqTopic) -> &[usize] {
        match topic {
            ZmqTopic::HashBlock => &self.hashblock_endpoints,
            ZmqTopic::HashTx => &self.hashtx_endpoints,
            ZmqTopic::RawBlock => &self.rawblock_endpoints,
            ZmqTopic::RawTx => &self.rawtx_endpoints,
            ZmqTopic::Sequence => &self.sequence_endpoints,
        }
    }
}

#[cfg(feature = "zmq")]
impl ZmqPublisher for SocketZmqPublisher {
    fn wants_notifications(&self) -> bool {
        !self.endpoints.is_empty()
    }

    fn wants_rawtx(&self) -> bool {
        !self.rawtx_endpoints.is_empty()
    }

    fn wants_rawblock(&self) -> bool {
        !self.rawblock_endpoints.is_empty()
    }

    fn active_notifiers(&self) -> Vec<ZmqNotifier> {
        self.notifiers.clone()
    }

    fn publish_hashblock(&self, hash: Hash256) {
        let body = reversed_hash_body(hash.to_le_bytes());
        self.publish(ZmqTopic::HashBlock, &body);
    }

    fn publish_hashtx(&self, txid: Txid) {
        let body = reversed_hash_body(*txid.as_bytes());
        self.publish(ZmqTopic::HashTx, &body);
    }

    fn publish_rawblock(&self, bytes: &[u8]) {
        self.publish(ZmqTopic::RawBlock, bytes);
    }

    fn publish_rawtx(&self, bytes: &[u8]) {
        self.publish(ZmqTopic::RawTx, bytes);
    }

    fn publish_sequence(&self, event: SequenceEvent) {
        self.publish(ZmqTopic::Sequence, &sequence_payload(event));
    }
}

/// Body frame for a `hashblock`/`hashtx`/`sequence` event: the hash or txid's
/// natural byte order reversed for the wire.
#[cfg(any(feature = "zmq", test))]
fn reversed_hash_body(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes.reverse();
    bytes
}

/// Body frame for a `sequence` topic event: the reversed hash/txid bytes and
/// the label byte, plus — for mempool `A`/`R` events — the mempool sequence
/// as a little-endian u64. The transport's own 4-byte counter stays in its
/// separate trailing frame.
#[cfg(any(feature = "zmq", test))]
fn sequence_payload(event: SequenceEvent) -> Vec<u8> {
    match event {
        SequenceEvent::Added(txid, mempool_sequence)
        | SequenceEvent::Removed(txid, mempool_sequence) => {
            let mut body = Vec::with_capacity(41);
            body.extend_from_slice(&reversed_hash_body(*txid.as_bytes()));
            body.push(event.label());
            body.extend_from_slice(&mempool_sequence.to_le_bytes());
            body
        }
        SequenceEvent::Connected(hash) | SequenceEvent::Disconnected(hash) => {
            let mut body = Vec::with_capacity(33);
            body.extend_from_slice(&reversed_hash_body(hash.to_le_bytes()));
            body.push(event.label());
            body
        }
    }
}

#[cfg(any(feature = "zmq", test))]
pub(crate) const fn sequence_body(sequence: u32) -> [u8; 4] {
    sequence.to_le_bytes()
}

#[cfg(any(feature = "zmq", test))]
fn is_ipv6_tcp_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("tcp://[") else {
        return false;
    };
    let Some((host, tail)) = rest.split_once(']') else {
        return false;
    };
    host.contains(':') && tail.starts_with(':') && tail.len() > 1
}

/// Publishes committed admissions as `hashtx`, `rawtx`, and Core `sequence`
/// `A` events, and removals as `sequence` `R` events.
///
/// Install on the [`bitcoin_rs_mempool::MempoolGateway`] observer slot when
/// ZMQ notifications are configured. Raw bodies are retained only for `rawtx`.
pub struct MempoolSequenceObserver {
    publisher: std::sync::Arc<dyn ZmqPublisher>,
}

impl core::fmt::Debug for MempoolSequenceObserver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MempoolSequenceObserver")
            .field("publisher", &self.publisher)
            .finish()
    }
}

impl MempoolSequenceObserver {
    /// Observes on behalf of `publisher`.
    #[must_use]
    pub fn new(publisher: std::sync::Arc<dyn ZmqPublisher>) -> Self {
        Self { publisher }
    }
}

impl bitcoin_rs_mempool::MempoolObserver for MempoolSequenceObserver {
    fn on_mutation(&self, envelope: &bitcoin_rs_mempool::MutationEnvelope) {
        use bitcoin_rs_primitives::encode::consensus_bytes;
        let result = &envelope.result;
        for (offset, change) in result.changes.iter().enumerate() {
            let Some(sequence) = result.sequence_of(offset) else {
                continue;
            };
            let txid = Txid(change.txid);
            match change.outcome {
                bitcoin_rs_mempool::MutationOutcome::Accepted => {
                    // Core's `TransactionAddedToMempool` notifies `hashtx`
                    // and `rawtx` for every admission, then `sequence` `A`.
                    self.publisher.publish_hashtx(txid);
                    if self.publisher.wants_rawtx()
                        && let Some((_, tx)) = envelope
                            .accepted_transactions
                            .iter()
                            .find(|(index, _)| *index == offset)
                    {
                        self.publisher.publish_rawtx(&consensus_bytes(tx.as_ref()));
                    }
                    self.publisher
                        .publish_sequence(SequenceEvent::Added(txid, sequence));
                }
                bitcoin_rs_mempool::MutationOutcome::Removed(
                    bitcoin_rs_mempool::RemovalReason::BlockInclusion,
                ) => {}
                bitcoin_rs_mempool::MutationOutcome::Removed(_) => {
                    self.publisher
                        .publish_sequence(SequenceEvent::Removed(txid, sequence));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[expect(clippy::expect_used, clippy::as_conversions)]
mod manifest_tests;
