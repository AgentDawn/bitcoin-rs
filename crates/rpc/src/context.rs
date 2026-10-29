use alloc::sync::Arc;
#[cfg(any(test, feature = "test-seam"))]
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{
    BlockBodyReadError, BlockBodySource, BlockTreeReader, LatchReader, TipReader, TipSnapshot,
    softfork_state,
};
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_mempool::BodyInterest;
use bitcoin_rs_mempool::{AdmissionChain, ChainAdmissionSnapshot, MempoolGateway, PrevoutMeta};

#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_mempool::{Mempool, MempoolLimits, MempoolObserver};
use bitcoin_rs_mining::MiningControl;
#[cfg(feature = "pool")]
use bitcoin_rs_mining::pool::ledger as pool_ledger;
use bitcoin_rs_primitives::{
    BlockHash, CompactTarget, Hash256, Network, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    layout::ParsedBlock, unix_time_secs,
};

use crate::error::RpcError;

use crate::compressed_tx::{
    LookupError, MAX_CUMULATIVE_BODY_BYTES, MAX_CUMULATIVE_BODY_LOADS, MAX_RESOLVER_STATE_BYTES,
    MAX_RETAINED_BODIES, MAX_RETAINED_BODY_BYTES, MAX_RETAINED_BYTES_TOTAL,
    MAX_RETAINED_INDEX_BYTES, PrevoutResolver, ResolvedPrevout,
};

use bitcoin::hex::DisplayHex as _;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_consensus::ValidationEngine;
#[cfg(test)]
use bitcoin_rs_primitives::{Amount, Script};
use core::fmt;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use hashbrown::HashMap;
use parking_lot::Mutex;
#[cfg(any(test, feature = "test-seam"))]
use parking_lot::RwLock;
use std::path::PathBuf;
use std::time::Instant;

/// Core `sendrawtransaction` default `maxfeerate`: 0.1 BTC/kvB in sat/kvB.
///
/// RPC selects this default when no request override is supplied. Embedded
/// `Node::broadcast` also selects it; Esplora owns its request cap separately.
pub const DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB: u64 = 10_000_000;

/// Block and undo responses materialize a body and its projection.
/// Bound concurrent materializations independently of socket connections.
const MAX_CONCURRENT_BLOCK_RENDERS: usize = 2;

#[derive(Debug)]
struct BlockRenderBudget {
    in_flight: AtomicUsize,
}

impl BlockRenderBudget {
    const fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<BlockRenderPermit> {
        let mut in_flight = self.in_flight.load(Ordering::Acquire);
        loop {
            if in_flight >= MAX_CONCURRENT_BLOCK_RENDERS {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                in_flight,
                in_flight + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(BlockRenderPermit {
                        budget: Arc::clone(self),
                    });
                }
                Err(actual) => in_flight = actual,
            }
        }
    }
}

pub(crate) struct BlockRenderPermit {
    budget: Arc<BlockRenderBudget>,
}

impl Drop for BlockRenderPermit {
    fn drop(&mut self) {
        let previous = self.budget.in_flight.fetch_sub(1, Ordering::Release);
        debug_assert!(previous > 0, "block render permit count underflowed");
    }
}

use bitcoin_rs_index::block_log::{
    BlockLogReader, BlockRecord, record_at_height, record_at_height_hash,
};
use bitcoin_rs_index::query_api::RollbackWarningSource;

/// Typed synchronization progress behind `getblockchaininfo`.
#[derive(Debug)]
pub struct SyncProgress {
    /// Consensus network the node follows.
    pub network: Network,
    /// Blocks fully applied to chainstate.
    pub blocks: u32,
    /// Validated headers known to the node (may lead `blocks` during sync).
    pub headers: u32,
    /// Hash of the best fully applied block.
    pub best_block_hash: Hash256,
    /// Difficulty at the applied tip (Core `GetDifficulty`).
    pub difficulty: f64,
    /// Applied tip header timestamp, UNIX seconds.
    pub time: u64,
    /// Median time past of the last eleven applied blocks.
    pub median_time: u64,
    /// Core `GuessVerificationProgress` in the inclusive range `[0, 1]`.
    pub verification_progress: f64,
    /// Whether the node is still in initial block download.
    pub initial_block_download: bool,
    /// Applied chain work, big-endian hex (`"00"` before the first tip).
    pub chain_work: String,
    /// Bytes the block store occupies on disk.
    pub size_on_disk: u64,
    /// Whether pruning is enabled.
    pub pruned: bool,
    /// Prune floor height, present only on a pruned node.
    pub prune_height: Option<u32>,
}

/// Current pruning state reported by chain RPCs.
#[derive(Copy, Clone, Debug, Default)]
pub struct PruneStatus {
    /// Whether block pruning is enabled for this node.
    pub pruned: bool,
    /// Highest manual prune height completed by the backing service.
    pub pruneheight: Option<u32>,
}

/// Summary of one completed manual prune request.
#[derive(Debug, Default)]
pub struct PruneResult {
    /// Highest prune height now recorded by the service.
    pub pruneheight: u32,
}

/// Error returned by the node-owned pruning implementation.
#[derive(Debug, thiserror::Error)]
pub enum PruneServiceError {
    /// Storage or backend-specific pruning failure.
    #[error("{0}")]
    Failed(String),
}

impl PruneServiceError {
    /// Wraps a concrete backend error message without coupling RPC to a storage crate.
    #[must_use]
    pub fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }
}

/// Node-owned storage mutator used by `pruneblockchain`.
pub trait PruneService: Send + Sync {
    /// Deletes persisted block/undo data below `requested_height`.
    fn prune_to_height(&self, requested_height: u32) -> Result<PruneResult, PruneServiceError>;

    /// Reports whether pruning is enabled and the highest completed prune height.
    fn status(&self) -> PruneStatus;
}

/// Node-owned control plane for consensus-affecting chain RPCs.
pub trait ChainControl: Send + Sync {
    /// Imports a Core snapshot through the node's fenced activation boundary.
    /// Existing implementors may omit this optional capability.
    fn load_txoutset(
        &self,
        _path: &std::path::Path,
    ) -> Result<SnapshotImport, SnapshotControlError> {
        Err(SnapshotControlError::Unavailable(
            "snapshot import is not attached to this chain control".to_owned(),
        ))
    }

    /// Writes a Core v2 snapshot of the UTXO set at the applied tip to `path`.
    ///
    /// A relative `path` resolves below the node data directory. The file is
    /// created only if nothing exists at `path`; an existing entry is refused
    /// and never replaced. A request cancelled through `cancellation`, or a
    /// node that begins shutting down, answers
    /// [`SnapshotControlError::Interrupted`] and leaves no file behind.
    fn dump_txoutset(
        &self,
        path: &std::path::Path,
        cancellation: &LatchReader,
    ) -> Result<SnapshotExport, SnapshotControlError>;

    /// Reads one coherent view of the existing active and historical roles.
    /// Existing implementors may omit this optional capability.
    fn chainstates(&self) -> Result<ChainstatesInfo, SnapshotControlError> {
        Err(SnapshotControlError::Unavailable(
            "chainstate lifecycle is not attached to this chain control".to_owned(),
        ))
    }

    /// Invalidates a block and descendants and selects the best remaining chain.
    fn invalidate_block(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), ChainControlError>;

    /// Verifies the newest applied blocks for `verifychain`.
    ///
    /// `check_level` is Core's `0..=4` level and `nblocks` counts back from
    /// the applied tip, zero meaning the whole chain. The answer is true only
    /// when every block in the window was checked and passed; a window that
    /// reaches history this node does not hold, and any damaged block or
    /// undo record, answer false. A request cancelled through `cancellation`
    /// answers [`ChainControlError::Interrupted`]; a chainstate closed for
    /// recovery answers [`ChainControlError::Unavailable`].
    fn verify_chain(
        &self,
        check_level: u8,
        nblocks: u32,
        cancellation: &LatchReader,
    ) -> Result<bool, ChainControlError>;
}

/// A completed, durable Core snapshot activation.
#[derive(Debug, serde::Serialize)]
pub struct SnapshotImport {
    /// Number of unspent outputs loaded, not transaction records.
    pub coins_loaded: u64,
    /// Pinned base block hash in RPC display order.
    pub tip_hash: String,
    /// Compiled base height.
    pub base_height: u32,
    /// UTF-8 display of the absolute input path, rendered before activation.
    /// Non-UTF-8 filesystem bytes are replaced for JSON output only.
    pub path: String,
}

/// A completed, durable Core snapshot export.
#[derive(Debug, serde::Serialize)]
pub struct SnapshotExport {
    /// Number of unspent outputs written, not transaction records.
    pub coins_written: u64,
    /// Applied tip hash the snapshot is based on, in RPC display order.
    pub base_hash: String,
    /// Applied tip height the snapshot is based on.
    pub base_height: u32,
    /// UTF-8 display of the absolute output path. Non-UTF-8 filesystem bytes
    /// in a parent directory are replaced for JSON output only.
    pub path: String,
    /// `hash_serialized_3` commitment of the written coins, in RPC display order.
    pub txoutset_hash: String,
    /// Transactions in the chain up to and including the base block.
    pub nchaintx: u64,
}

/// Coherent lifecycle projection supplied by the chainstate owner.
#[derive(Debug, serde::Serialize)]
pub struct ChainstatesInfo {
    /// Best known header height.
    pub headers: u32,
    /// Historical role first, active role last.
    pub chainstates: Vec<ChainstateInfo>,
}

/// One chainstate's current lifecycle facts.
#[derive(Debug, serde::Serialize)]
pub struct ChainstateInfo {
    /// Applied block height.
    pub blocks: u32,
    /// Applied block hash in RPC display order.
    pub bestblockhash: String,
    /// Transaction-based estimate; unavailable counts are omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verificationprogress: Option<f64>,
    /// Pinned base for a snapshot-derived active role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_blockhash: Option<String>,
    /// Whether these coins have been verified from genesis.
    pub validated: bool,
}

/// Categorized error at the RPC-to-node snapshot boundary.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotControlError {
    /// Input path cannot be opened or is not a regular file.
    #[error("{0}")]
    File(String),
    /// The file or its compiled trust anchor was rejected before activation.
    #[error("{0}")]
    Invalid(String),
    /// The lifecycle cannot accept this request at present.
    #[error("{0}")]
    Unavailable(String),
    /// Activation, persistence, or post-commit consumer settlement failed.
    #[error("{0}")]
    Failed(String),
    /// The requesting caller cancelled the operation, or the node began
    /// shutting down, before it completed. Nothing was published.
    #[error("Snapshot export interrupted")]
    Interrupted,
}

/// Failure from a node-owned chain mutation.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ChainControlError {
    /// The requested block is unknown.
    #[error("unknown block")]
    UnknownBlock,
    /// Genesis cannot be invalidated.
    #[error("cannot invalidate the genesis block")]
    Genesis,
    /// The mutation failed after its request was accepted.
    #[error("{0}")]
    Failed(String),
    /// Verification stopped because the requesting caller cancelled it.
    #[error("block verification interrupted")]
    Interrupted,
    /// Verification refused because the chainstate is closed for recovery.
    #[error("chainstate is unavailable for verification")]
    Unavailable,
}

pub use bitcoin_rs_index::{
    DerivedIndexInfo, DerivedIndexQuery, ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord,
    ScriptIndexSnapshot, SpendingRecord, TxQueryError, TxUnavailableCause,
};

/// The complete description of one RPC context, grouped by node capability:
/// chain, mempool, indexes, network, and mining.
///
/// A struct-of-structs grouping, not a trait layer. [`Context::from_handles`]
/// is the single composition point: one `ContextHandles` value carries every
/// production capability, including the authoritative chain-transition
/// barrier, the durable block-body reader, and the optional surfaces (prune,
/// chain control, ZMQ publisher, debug log). The handler surface reads only
/// these capability groups — RPC consumes node capabilities and never names a
/// storage backend or backend engine type, and production wiring attaches
/// nothing to a constructed `Context` afterwards.
pub struct ContextHandles {
    /// Enable the compiled experimental keyless tweak service. No wallet state.
    pub silent_payments: bool,
    /// Enable the optional BIP337 compressed-transaction RPCs. No wallet state.
    pub compressed_transactions: bool,
    /// Chain capability: tips, block log, UTXO set, block tree, transition
    /// barrier, and the chain-owned control surfaces.
    pub chain: ChainHandles,
    /// Mempool capability: the mutation gateway in front of the pool.
    pub mempool: MempoolHandles,
    /// Index capability: transaction, script and compact-filter query adapters.
    pub indexes: IndexHandles,
    /// Network capability: peer registry, reachability, and connection control.
    pub network: NetworkHandles,
    /// Mining capability: the template coordinator, when one is attached.
    pub mining: MiningHandles,
    /// Optional node-owned pool accounting service.
    pub pool: PoolHandles,
    /// Live ZMQ notification publisher backing the notifier surface.
    pub zmq_publisher: Arc<dyn crate::zmq::ZmqPublisher>,
    /// Configured node debug-log path for `getrpcinfo`.
    pub debug_log_path: Option<PathBuf>,
}

/// Chain capability handles.
pub struct ChainHandles {
    /// Best header-chain tip. Read-only: only Chainstate publishes.
    pub chain_tip: TipReader,
    /// Best fully-applied block tip. Read-only: only Chainstate publishes.
    pub applied_tip: TipReader,
    /// Authoritative applied-tip observation, implemented by Chainstate.
    pub active_tip_wait: Option<Arc<dyn bitcoin_rs_chain::ActiveTipWait>>,
    /// Chainstate-owned synchronization progress, including the
    /// process-wide initial-block-download latch shared with P2P so both
    /// surfaces answer identically.
    pub progress: bitcoin_rs_chain::ChainProgressReader,
    /// Chain-mutation admission latch: the same fact
    /// `Chainstate::is_closed_for_recovery` publishes, exposed read-only and
    /// kept separate from the initial-block-download decision in
    /// [`Self::progress`] by that fact's invariant.
    pub closed_for_recovery: LatchReader,
    /// Applied block metadata log.
    pub blocks: BlockLogReader,
    /// Authoritative UTXO set, read-only: mutation stays with the chain
    /// owner through `utxo::contract`.
    pub utxo: bitcoin_rs_utxo::UtxoReader,
    /// Incremental UTXO statistics.
    pub coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    /// Shared block tree.
    pub block_tree: BlockTreeReader,
    /// Consensus network.
    pub chain_network: Network,
    /// Excludes authoritative chain transitions while a read runs.
    ///
    /// Production supplies the role minted alongside chainstate's mutation
    /// role. `Self::with_transition` accepts a caller-supplied role but cannot
    /// verify its provenance; callers can mint an unrelated domain through
    /// [`bitcoin_rs_chain::TransitionDomain::new`].
    pub chain_transition: bitcoin_rs_chain::StableRead,
    /// Durable block-body reader for metadata-only block records.
    pub block_body_source: Option<Arc<dyn BlockBodySource>>,
    /// Read-only certified block inputs; mutation remains with chainstate.
    pub block_undo_source: Option<Arc<dyn bitcoin_rs_utxo::contract::BlockUndoSource>>,
    /// Optional storage pruning mutator.
    pub prune_service: Option<Arc<dyn PruneService>>,
    /// Optional node-owned chain mutation service.
    pub chain_control: Option<Arc<dyn ChainControl>>,
    /// Rollback-evidence warning source for `getblockchaininfo`.
    pub rollback_warnings: Option<Arc<dyn RollbackWarningSource>>,
}

/// Borrowed provisional chain facts used by both RPC and P2P admission.
///
/// The view contains no gateway or full node/context reference. Height and MTP
/// use one applied tip; coins are read without taking the chain-transition
/// mutex. The chain owner brackets authoritative mutations with the gateway's
/// generation fence, and gateway generation/sequence revalidation discards any
/// facts collected across such a mutation before they can affect admission.
pub struct ChainAdmissionView {
    utxo: bitcoin_rs_utxo::UtxoReader,
    applied_tip: TipReader,
    block_tree: BlockTreeReader,
    network: Network,
}

impl ChainAdmissionView {
    /// Borrows the chain owner's existing handles without retaining state.
    #[must_use]
    pub const fn new(
        utxo: bitcoin_rs_utxo::UtxoReader,
        applied_tip: TipReader,
        block_tree: BlockTreeReader,
        network: Network,
    ) -> Self {
        Self {
            utxo,
            applied_tip,
            block_tree,
            network,
        }
    }
}

impl AdmissionChain for ChainAdmissionView {
    fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
        let tip = self.applied_tip.load_full();
        let height = tip.as_ref().map_or(0, |tip| tip.height);
        let tree = self.block_tree.read();
        let tip_node = tip.as_ref().and_then(|tip| tree.lookup(tip.hash));
        let locktime_cutoff = tip_node
            .and_then(|node| tree.median_time_past_at(node))
            .unwrap_or(0);
        // CSV activation at the next block gates BIP68 relative locks,
        // matching the block-connect and mining evaluation contexts. The
        // full next-block softfork state also feeds the script-execution
        // cache fill: the gateway re-verifies under exactly these flags.
        let next_softfork =
            tip_node.map(|node| softfork_state(&tree, self.network, Some(node), height + 1));
        let csv_active = next_softfork.as_ref().is_some_and(|state| state.csv_active);
        let next_block_script_flags = {
            let state = next_softfork.unwrap_or(bitcoin_rs_consensus::SoftforkState {
                csv_active: false,
                segwit_active: false,
            });
            // The next block's hash is unknowable before it is built; the
            // zero hash is never the BIP16 exception, so P2SH applies exactly
            // as connect derives it for every non-exception block.
            bitcoin_rs_consensus::verify_block::verify_flags(
                self.network,
                height + 1,
                Hash256::default(),
                state,
            )
        };
        // Confirmed coin metadata for BIP68 and coinbase maturity. Height `h`
        // uses the MTP of the block before `h`, the same derivation the
        // block-connect path applies. MTP lookups are cached per height.
        let mut mtp_cache: HashMap<u32, u32> = HashMap::new();
        let mut prevout_meta: HashMap<OutPoint, PrevoutMeta> = HashMap::new();
        let mut prevouts = Vec::new();
        for input in &tx.inputs {
            let Some(coin) = self.utxo.get_entry(&input.previous_output) else {
                continue;
            };
            let mtp = *mtp_cache.entry(coin.height).or_insert_with(|| {
                tip_node
                    .and_then(|tip| {
                        coin.height
                            .checked_sub(1)
                            .and_then(|prior| tree.node_at_height_from(tip, prior))
                    })
                    .and_then(|prior| tree.median_time_past_at(prior))
                    .unwrap_or(0)
            });
            prevout_meta.insert(
                input.previous_output,
                PrevoutMeta {
                    height: coin.height,
                    mtp,
                    coinbase: coin.coinbase,
                },
            );
            prevouts.push((input.previous_output, coin.txout));
        }
        // Live confirmed coins are positive chain evidence. The RPC lookup
        // cache may contain unconfirmed bodies and cannot supply this fact.
        // No live outputs means unknown, not proof that the tx is unconfirmed.
        let confirmed = self
            .utxo
            .has_live_outputs_for_txid(&Hash256::from(tx.txid()));
        Some(ChainAdmissionSnapshot {
            prevouts,
            prevout_meta,
            height,
            locktime_cutoff,
            csv_active,
            next_block_script_flags,
            confirmed,
        })
    }
}

/// Mempool capability handles.
pub struct MempoolHandles {
    /// The process-wide mutation gateway in front of the in-memory pool.
    pub gateway: Arc<MempoolGateway>,
}

/// Index capability handles.
#[derive(Default)]
pub struct IndexHandles {
    /// Complete transaction-index query adapter.
    pub derived_index: Option<Arc<dyn DerivedIndexQuery>>,
    /// Generic script-index query adapter.
    pub script_index: Option<Arc<dyn ScriptIndexQuery>>,
    /// Optional snapshot-gated BIP158 basic-filter index.
    pub compact_filters: Option<Arc<dyn bitcoin_rs_index::CompactFilterQuery>>,
    /// Complete transaction lookup used by Esplora output projections. It may
    /// exist without [`Self::derived_index`] because it does not advertise
    /// the Core `--txindex` contract.
    pub esplora_tx_index: Option<Arc<dyn DerivedIndexQuery>>,
    /// Live txindex status for the `getcapabilities` projection.
    pub derived_index_status: Option<Arc<dyn bitcoin_rs_index::DerivedIndexCapabilitySource>>,
}

/// Network capability handles.
pub struct NetworkHandles {
    /// Authoritative live peer sessions.
    pub peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    /// P2P service runtime owner for network mutations and state.
    pub p2p: Arc<bitcoin_rs_p2p::P2pService>,
    /// Service flags the node advertises, as resolved at P2P startup —
    /// `NETWORK` on an unpruned node, `NETWORK_LIMITED` on a pruned one.
    pub local_services: u64,
    /// Resolved overlay transport configuration, reported (configured,
    /// never probed) by `getnetworkinfo`.
    pub overlay: bitcoin_rs_p2p::overlay::OverlayConfig,
}

/// Key-free access to the node-owned durable pool ledger.
#[cfg(feature = "pool")]
pub trait PoolOperator: Send + Sync {
    /// Returns the single ledger shared with the pool runtime.
    fn ledger(&self) -> &pool_ledger::Ledger;
    /// Returns the explicitly configured payout minimum and output ceiling.
    fn payout_policy(&self) -> pool_ledger::PayoutPolicy;
}

/// Optional pool capability; absent in builds without pool support.
#[derive(Default)]
pub struct PoolHandles {
    /// Node-owned operator, absent when the pool is disabled at runtime.
    #[cfg(feature = "pool")]
    pub operator: Option<Arc<dyn PoolOperator>>,
}

/// Mining capability handles.
#[derive(Default)]
pub struct MiningHandles {
    /// Node-owned mining coordinator. `None` when mining is not wired.
    pub mining_control: Option<Arc<dyn MiningControl>>,
}

/// Shared state consumed by JSON-RPC handlers.
///
/// The subsystem graph lives behind the capability groups ([`ChainHandles`],
/// [`MempoolHandles`], [`IndexHandles`], [`NetworkHandles`], [`MiningHandles`]);
/// `Context` itself carries only those groups plus presentation-local state
/// (the ZMQ publisher surface, the debug-log path, the REST render budget,
/// and the listener bind epoch). Handlers read capabilities through the
/// groups; production wiring attaches nothing after construction.
pub struct Context {
    #[cfg(feature = "silent-payments")]
    pub(crate) silent_payments: Option<Mutex<()>>,
    /// Runtime opt-in for the BIP337 compressed-transaction RPCs.
    pub(crate) compressed_transactions: bool,
    /// Chain capability: tips, block log, UTXO set, block tree, transition
    /// barrier, and the chain-owned control surfaces.
    pub chain: ChainHandles,
    /// Mempool capability: the mutation gateway in front of the pool.
    pub mempool: MempoolHandles,
    /// Index capability: transaction, script, and Esplora query adapters.
    pub indexes: IndexHandles,
    /// Network capability: peer registry, reachability, and connection control.
    pub network: NetworkHandles,
    /// Mining capability: the template coordinator, when one is attached.
    pub mining: MiningHandles,
    /// Optional node-owned pool accounting service.
    pub pool: PoolHandles,
    /// Live ZMQ publisher, also the source of active notifier metadata.
    pub zmq_publisher: Arc<dyn crate::zmq::ZmqPublisher>,
    /// Configured node debug-log path for `getrpcinfo`.
    pub debug_log_path: Option<PathBuf>,
    /// Instant this context's RPC listener bound, set by `RpcServer::bind`
    /// and read by `uptime`. Kept per context rather than process-global so
    /// two servers in one process report their own epochs; `None` (never
    /// bound, e.g. unit tests) makes `uptime` measure from its first call.
    server_bound_at: Mutex<Option<Instant>>,
    /// Limits concurrent full-block and spent-output response materializations.
    block_render_budget: Arc<BlockRenderBudget>,
    /// Calls currently executing through `Handler::dispatch`, oldest first.
    pub(crate) active_calls: ActiveCalls,
}

/// One in-flight JSON-RPC call, tracked for `getrpcinfo`.
///
/// Registration happens in `Handler::dispatch` only after registry
/// resolution and blocking-quota acquisition, so unknown or refused
/// methods never appear. Removal is by the unique `id`, never by method
/// name, so two concurrent calls to one method settle independently.
pub(crate) struct ActiveCalls {
    entries: Mutex<Vec<ActiveCallEntry>>,
    next_id: AtomicU64,
}

struct ActiveCallEntry {
    id: u64,
    method: String,
    started: Instant,
}

/// RAII registration of one active call; dropping removes exactly its entry.
pub(crate) struct ActiveCallGuard<'a> {
    calls: &'a ActiveCalls,
    id: u64,
}

impl Drop for ActiveCallGuard<'_> {
    fn drop(&mut self) {
        self.calls
            .entries
            .lock()
            .retain(|entry| entry.id != self.id);
    }
}

impl ActiveCalls {
    fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Registers `method` as started now and returns its removal guard.
    pub(crate) fn begin(&self, method: &str) -> ActiveCallGuard<'_> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.entries.lock().push(ActiveCallEntry {
            id,
            method: method.to_owned(),
            started: Instant::now(),
        });
        ActiveCallGuard { calls: self, id }
    }

    /// `(method, elapsed_micros)` rows, oldest first.
    pub(crate) fn snapshot(&self) -> Vec<(String, u64)> {
        self.entries
            .lock()
            .iter()
            .map(|entry| {
                let micros = u64::try_from(entry.started.elapsed().as_micros()).unwrap_or(u64::MAX);
                (entry.method.clone(), micros)
            })
            .collect()
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context").finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for ChainHandles {
    /// Builds the empty synthetic chain world used by tests.
    ///
    /// The transition role here is minted from a private domain nothing else in
    /// the process shares, so a context built this way excludes no transition
    /// at all. That is correct for a fixture and wrong for a node: production
    /// wiring supplies the role from the node's transition domain when it
    /// builds `ChainHandles`. Reader capability types expose no constructor
    /// of their own; the domain is what creates each role.
    fn default() -> Self {
        Self::with_transition(bitcoin_rs_chain::TransitionDomain::new().stable_read())
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl ChainHandles {
    /// Builds the synthetic chain world over a caller-supplied transition role.
    ///
    /// This is what a test that also drives a real node uses: it passes the
    /// role composition minted for that node, so the resulting context and the
    /// chainstate it reads exclude each other's transitions. The other fields
    /// are empty publications with no owner behind them.
    #[must_use]
    fn with_transition(chain_transition: bitcoin_rs_chain::StableRead) -> Self {
        let coin_stats_listener = bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        );
        let mut utxo = bitcoin_rs_utxo::UtxoSet::new();
        utxo.track_coin_stats(coin_stats_listener.clone());
        let chain_tip = TipReader::new(Arc::new(ArcSwapOption::empty()));
        let applied_tip = TipReader::new(Arc::new(ArcSwapOption::empty()));
        let block_tree = BlockTreeReader::new(Arc::new(parking_lot::RwLock::new(
            bitcoin_rs_chain::BlockTree::new(),
        )));
        let progress = bitcoin_rs_chain::ChainProgressReader::new(
            chain_tip.clone(),
            applied_tip.clone(),
            block_tree.clone(),
            Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
                applied_tip.clone(),
                block_tree.clone(),
            )),
        );
        Self {
            chain_tip,
            applied_tip,
            active_tip_wait: None,
            progress,
            closed_for_recovery: LatchReader::new(Arc::new(core::sync::atomic::AtomicBool::new(
                false,
            ))),
            blocks: BlockLogReader::fixture_empty(),
            utxo: bitcoin_rs_utxo::UtxoReader::new(Arc::new(utxo)),
            coin_stats: Arc::new(coin_stats_listener),
            block_tree,
            chain_network: Network::Mainnet,
            chain_transition,
            block_body_source: None,
            block_undo_source: None,
            prune_service: None,
            chain_control: None,
            rollback_warnings: None,
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for MempoolHandles {
    fn default() -> Self {
        Self {
            gateway: Arc::new(MempoolGateway::new(
                Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
                None,
                ValidationEngine::Native,
                None,
            )),
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for NetworkHandles {
    fn default() -> Self {
        let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
            bitcoin_rs_p2p::P2pServiceConfig::default(),
            LatchReader::fixture_never(),
        ));
        Self {
            peer_table: p2p.table(),
            p2p,
            local_services: 0x09,
            overlay: bitcoin_rs_p2p::overlay::OverlayConfig::default(),
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for ContextHandles {
    /// Builds the empty synthetic capability set used by tests. Production
    /// wiring supplies every capability it owns.
    fn default() -> Self {
        Self {
            silent_payments: false,
            compressed_transactions: false,
            chain: ChainHandles::default(),
            mempool: MempoolHandles::default(),
            indexes: IndexHandles::default(),
            network: NetworkHandles::default(),
            mining: MiningHandles::default(),
            pool: PoolHandles::default(),
            zmq_publisher: Arc::new(crate::zmq::NoOpZmqPublisher),
            debug_log_path: None,
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    /// Builds an empty context over the default synthetic handles. Test
    /// convenience; production composes a complete [`ContextHandles`]
    /// through [`Self::from_handles`].
    #[must_use]
    #[cfg(any(test, feature = "test-seam"))]
    pub fn new() -> Self {
        Self::from_handles(ContextHandles::default())
    }

    /// Builds an empty context whose mempool gateway carries `observer`.
    ///
    /// Like [`Self::new`] but the gateway is constructed with the supplied
    /// observer instead of `None`. Test-only: production wiring constructs
    /// the gateway through `NodeState::open`.
    #[must_use]
    #[cfg(any(test, feature = "test-seam"))]
    pub fn new_with_mempool_observer(observer: Arc<dyn MempoolObserver>) -> Self {
        Self::from_handles(ContextHandles {
            mempool: MempoolHandles {
                gateway: Arc::new(MempoolGateway::new(
                    Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
                    Some((observer, BodyInterest::Metadata)),
                    ValidationEngine::Native,
                    None,
                )),
            },
            ..ContextHandles::default()
        })
    }

    /// Composes one context from a complete [`ContextHandles`] value.
    ///
    /// This is the single production composition point. PRE: `handles` names
    /// every capability the context will use, including the authoritative
    /// chain-transition barrier supplied by the chain owner. POST: the
    /// context carries that full set; the groups' `pub` fields still permit
    /// post-hoc attachment, which only test fixtures use.
    /// INVARIANT: production wiring supplies the chain owner's barrier
    /// (e.g. `chainstate.transition_barrier()`); the synthetic
    /// `ContextHandles::default` path builds a private barrier for tests.
    #[must_use]
    pub fn from_handles(handles: ContextHandles) -> Self {
        let ContextHandles {
            silent_payments,
            compressed_transactions,
            chain,
            mempool,
            indexes,
            network,
            mining,
            pool,
            zmq_publisher,
            debug_log_path,
        } = handles;
        #[cfg(not(feature = "silent-payments"))]
        let _ = silent_payments;
        Self {
            #[cfg(feature = "silent-payments")]
            silent_payments: silent_payments.then(|| Mutex::new(())),
            compressed_transactions,
            chain,
            mempool,
            indexes,
            network,
            mining,
            pool,
            zmq_publisher,
            debug_log_path,
            server_bound_at: Mutex::new(None),
            block_render_budget: Arc::new(BlockRenderBudget::new()),
            active_calls: ActiveCalls::new(),
        }
    }

    /// Marks the instant this context's RPC listener bound. A rebind
    /// overwrites the epoch so `uptime` measures the live server.
    pub(crate) fn mark_server_bound(&self) {
        *self.server_bound_at.lock() = Some(Instant::now());
    }

    /// Uptime epoch for `uptime`: the recorded bind instant, or — for a
    /// context that never binds a server — the first call's instant.
    pub(crate) fn server_start(&self) -> Instant {
        *self.server_bound_at.lock().get_or_insert_with(Instant::now)
    }

    /// Attaches the internal transaction lookup required for Esplora output
    /// projections without exposing it to Core transaction-index RPCs.
    #[must_use]
    pub fn with_esplora_derived_index(
        mut self,
        derived_index: Option<Arc<dyn DerivedIndexQuery>>,
    ) -> Self {
        self.indexes.esplora_tx_index = derived_index;
        self
    }

    /// Returns `self` with a durable block body source.
    #[must_use]
    pub fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.chain.block_body_source = Some(source);
        self
    }

    /// Attaches the node-owned mining coordinator to a context built without
    /// handles (`Context::new`). Production wiring passes the coordinator
    /// through `ContextHandles::mining` instead.
    #[must_use]
    pub fn with_mining_control(mut self, mining_control: Arc<dyn MiningControl>) -> Self {
        self.mining.mining_control = Some(mining_control);
        self
    }

    /// Attaches the node-owned chain mutation service.
    #[must_use]
    pub fn with_chain_control(mut self, chain_control: Arc<dyn ChainControl>) -> Self {
        self.chain.chain_control = Some(chain_control);
        self
    }

    /// Attaches the transition-exclusion role composition minted for this node.
    ///
    /// PRE: `chain_transition` is the read role over the same
    ///   [`bitcoin_rs_chain::TransitionDomain`] chainstate's mutation role uses.
    /// POST: exclusive chainstate reads use it; see
    ///   `ChainHandles::with_stable_chainstate`.
    /// INVARIANT: published status reads do not acquire it, so a block
    ///   transition cannot stall `getblockchaininfo` or `getchaintxstats`.
    #[must_use]
    pub fn with_chain_transition(mut self, chain_transition: bitcoin_rs_chain::StableRead) -> Self {
        self.chain.chain_transition = chain_transition;
        self
    }

    /// Acquires a bounded full-block render slot, if one is available.
    /// Full-body responses retain it through rendering. The tweak adapter drops
    /// its source first; its single-work slot still bounds derived JSON rendering.
    pub(crate) fn try_acquire_block_render(&self) -> Option<BlockRenderPermit> {
        self.block_render_budget.try_acquire()
    }

    /// Returns active ZMQ notification metadata from the live publisher.
    #[cfg(feature = "zmq")]
    #[must_use]
    pub(crate) fn zmq_notifications(&self) -> Vec<crate::zmq::ZmqNotifier> {
        self.zmq_publisher.active_notifiers()
    }
}

/// Flat-output prefix row for one transaction in a retained body.
struct FlatRow {
    txid: Txid,
    first_flat: u32,
    output_count: u32,
}

/// One retained block body: its flat-output prefix rows plus the
/// transactions materialized while building them.
///
/// The raw bytes are parsed once in [`RpcPrevoutResolver::ensure_body`]
/// and then dropped; only the materialized transactions are retained.
/// They share the body's lifetime and are dropped with it on eviction,
/// so per-input lookups never reparse and retention costs one body-sized
/// copy, not two.
struct RetainedBody {
    height: u32,
    rows: Vec<FlatRow>,
    txs: Vec<Tx>,
    index_bytes: usize,
    tx_bytes: usize,
}

/// Conservative accounting for a materialized transaction's owned
/// allocations, including one vector entry per witness item.
fn retained_tx_bytes(txs: &[Tx]) -> usize {
    txs.iter()
        .map(|tx| {
            core::mem::size_of::<Tx>()
                + tx.inputs.len() * core::mem::size_of::<TxIn>()
                + tx.outputs.len() * core::mem::size_of::<TxOut>()
                + tx.inputs
                    .iter()
                    .map(|input| {
                        input.script_sig.len()
                            + input.witness.len() * core::mem::size_of::<Vec<u8>>()
                            + input.witness.iter().map(Vec::len).sum::<usize>()
                    })
                    .sum::<usize>()
                + tx.outputs
                    .iter()
                    .map(|output| output.script_pubkey.len())
                    .sum::<usize>()
        })
        .sum()
}

/// Production [`PrevoutResolver`] for the BIP337 codec.
///
/// Consistency: snapshot isolation. Handlers construct and run the
/// resolver inside `ChainHandles::with_stable_chainstate`, so the
/// captured `applied_view()`, UTXO entries, txindex heights, and bodies
/// all come from one transition-excluded chainstate read; a tip that
/// moves mid-call cancels the call instead of mixing branches. It holds one
/// block-render permit for the whole call, retains materialized
/// transactions plus cumulative-output prefix rows per height, and parses
/// each retained body once in a scope that drops the parsed block before
/// the next body is read. Retained materialized transactions are charged
/// against the body and combined budgets and evicted with their body, so
/// the cache lifetime stays bounded. Cumulative loads and bytes bound the
/// total read/parse/materialize/txid work under the exclusion and fail
/// closed; codecs group height-known lookups so each body loads once.
/// Missing, corrupt, and unreadable bodies stay distinct ([`LookupError`])
/// because the codec degrades them differently.
pub(crate) struct RpcPrevoutResolver<'ctx> {
    ctx: &'ctx Context,
    view: AppliedView,
    /// Held for the whole call; dropping releases the render slot.
    _permit: BlockRenderPermit,
    cancellation: LatchReader,
    bodies: Vec<RetainedBody>,
    retained_tx_bytes: usize,
    retained_index_bytes: usize,
    /// Cumulative body loads performed (distinct reads; eviction reloads
    /// count again, so cycling past the retained slots cannot do unbounded
    /// parse work under the exclusion). Never decremented.
    loads: usize,
    /// Cumulative body bytes read, bounding total parse work. Never
    /// decremented.
    loaded_bytes: usize,
    memo: HashMap<OutPoint, Option<ResolvedPrevout>>,
    state_bytes: usize,
}

impl<'ctx> RpcPrevoutResolver<'ctx> {
    /// Captures the applied view and the call's single render permit.
    ///
    /// # Errors
    /// Returns retryable `Misc` (-1) when both block-render slots are
    /// busy; the caller never queues behind a render.
    pub(crate) fn new(ctx: &'ctx Context, cancellation: LatchReader) -> Result<Self, RpcError> {
        let permit = ctx
            .try_acquire_block_render()
            .ok_or_else(|| RpcError::Misc("block rendering is busy; retry".to_owned()))?;
        Ok(Self {
            ctx,
            view: ctx.chain.applied_view(),
            _permit: permit,
            cancellation,
            bodies: Vec::new(),
            retained_tx_bytes: 0,
            retained_index_bytes: 0,
            loads: 0,
            loaded_bytes: 0,
            memo: HashMap::new(),
            state_bytes: 0,
        })
    }

    /// Whether the captured view still equals the live applied view.
    #[must_use]
    pub(crate) fn view_matches_current(&self) -> bool {
        let current = self.ctx.chain.applied_view();
        match (self.view.tip(), current.tip()) {
            (None, None) => true,
            (Some(before), Some(now)) => before.height == now.height && before.hash == now.hash,
            _ => false,
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.is_triggered() || !self.view_matches_current()
    }

    /// Ensures the body at `height` is retained, evicting oldest-first.
    /// Cumulative loads and bytes fail closed before doing body I/O or
    /// parsing: without them a request cycling more heights than the
    /// retained slots could pay a full body read, parse, materialization,
    /// and txid pass per input while holding the stable-chainstate
    /// exclusion. Codecs group height-known lookups so each body loads
    /// once; this budget backstops the rest.
    fn ensure_body(&mut self, height: u32) -> Result<(), LookupError> {
        if self.bodies.iter().any(|body| body.height == height) {
            return Ok(());
        }
        if self.is_cancelled() {
            return Err(LookupError::Cancelled);
        }
        let record = self
            .ctx
            .chain
            .block_by_height_in_view(&self.view, height)
            .ok_or(LookupError::Missing)?;
        let source = self
            .ctx
            .chain
            .block_body_source
            .as_ref()
            .ok_or(LookupError::BodyMissing(height))?;
        // Fail closed before body I/O so the exclusion never pays for more
        // than a bounded number of loads.
        if self.loads >= MAX_CUMULATIVE_BODY_LOADS {
            return Err(LookupError::LimitExceeded(
                crate::compressed_tx::Limit::Loads,
            ));
        }
        let bytes = source
            .block_body(height, record.hash)
            .map_err(|error| match error {
                BlockBodyReadError::Corrupt(_) => LookupError::CorruptBody(height),
                BlockBodyReadError::Read(_) => LookupError::BodyReadFailed(height),
            })?
            .ok_or(LookupError::BodyMissing(height))?;
        if bytes.len() > MAX_RETAINED_BODY_BYTES {
            return Err(LookupError::LimitExceeded(
                crate::compressed_tx::Limit::BodyBytes,
            ));
        }
        if self.loaded_bytes.saturating_add(bytes.len()) > MAX_CUMULATIVE_BODY_BYTES {
            return Err(LookupError::LimitExceeded(
                crate::compressed_tx::Limit::LoadBytes,
            ));
        }
        self.loads += 1;
        self.loaded_bytes = self.loaded_bytes.saturating_add(bytes.len());
        // Pre-charge the transient index space this body will occupy.
        let index_bytes = bytes.len() / 60 * 40;
        if index_bytes > MAX_RETAINED_INDEX_BYTES {
            return Err(LookupError::LimitExceeded(
                crate::compressed_tx::Limit::IndexBytes,
            ));
        }
        let (rows, txs) = {
            let parsed =
                ParsedBlock::parse_exact(&bytes).map_err(|_| LookupError::CorruptBody(height))?;
            let mut rows = Vec::with_capacity(parsed.transactions().len());
            let mut txs = Vec::with_capacity(parsed.transactions().len());
            let mut flat = 0_u32;
            for parsed_tx in parsed.transactions() {
                let tx = parsed_tx.materialize();
                let output_count = u32::try_from(tx.outputs.len())
                    .map_err(|_| LookupError::CorruptBody(height))?;
                rows.push(FlatRow {
                    txid: tx.txid(),
                    first_flat: flat,
                    output_count,
                });
                flat = flat
                    .checked_add(output_count)
                    .ok_or(LookupError::CorruptBody(height))?;
                txs.push(tx);
            }
            (rows, txs)
        };
        // Charge the owned allocations, not just the wire length: a witness
        // item needs a vector entry even when its payload is one byte.
        let tx_bytes = retained_tx_bytes(&txs);
        while self.bodies.len() >= MAX_RETAINED_BODIES
            || self.retained_tx_bytes + tx_bytes > MAX_RETAINED_BODY_BYTES
            || self.retained_index_bytes + index_bytes > MAX_RETAINED_INDEX_BYTES
            || self.retained_tx_bytes + self.retained_index_bytes + tx_bytes + index_bytes
                > MAX_RETAINED_BYTES_TOTAL
        {
            let Some(evicted) = (!self.bodies.is_empty()).then(|| self.bodies.remove(0)) else {
                return Err(LookupError::LimitExceeded(
                    crate::compressed_tx::Limit::Bodies,
                ));
            };
            self.retained_tx_bytes -= evicted.tx_bytes;
            self.retained_index_bytes -= evicted.index_bytes;
        }
        self.retained_tx_bytes += tx_bytes;
        self.retained_index_bytes += index_bytes;
        self.bodies.push(RetainedBody {
            height,
            rows,
            txs,
            index_bytes,
            tx_bytes,
        });
        Ok(())
    }

    /// Borrows the transaction `txid` cached with the retained body at
    /// `height` without cloning; the body is parsed once at retain time,
    /// so this lookup scans cached transactions without reparsing.
    /// Callers clone only the requested output via [`Self::body_txout`].
    fn body_tx_ref(&mut self, height: u32, txid: &Txid) -> Result<Option<&Tx>, LookupError> {
        self.ensure_body(height)?;
        let Some(body) = self.bodies.iter().find(|body| body.height == height) else {
            return Err(LookupError::BodyMissing(height));
        };
        Ok(body
            .rows
            .iter()
            .zip(body.txs.iter())
            .find_map(|(row, tx)| (row.txid == *txid).then_some(tx)))
    }

    /// Clones only the requested output `vout` of `txid` at `height`;
    /// the retained funding transaction itself is never cloned, so
    /// per-input prevout lookups cost one `TxOut`, not one `Tx`.
    fn body_txout(
        &mut self,
        height: u32,
        txid: &Txid,
        vout: u32,
    ) -> Result<Option<TxOut>, LookupError> {
        let vout = usize::try_from(vout).map_err(|_| LookupError::Missing)?;
        let Some(tx) = self.body_tx_ref(height, txid)? else {
            return Ok(None);
        };
        Ok(tx.outputs.get(vout).cloned())
    }

    fn resolve_prevout(
        &mut self,
        outpoint: &OutPoint,
    ) -> Result<Option<ResolvedPrevout>, LookupError> {
        if let Some(coin) = self.ctx.chain.utxo.get_entry(outpoint) {
            return Ok(Some(ResolvedPrevout {
                txout: coin.txout,
                confirmed_height: Some(coin.height),
            }));
        }
        let height = match self.ctx.indexes.derived_index.as_ref() {
            Some(index) => index
                .transaction_height(&outpoint.txid)
                .map_err(|_| LookupError::Missing)?,
            None => None,
        };
        let Some(height) = height else {
            return Ok(None);
        };
        let Some(txout) = self.body_txout(height, &outpoint.txid, outpoint.vout)? else {
            return Ok(None);
        };
        Ok(Some(ResolvedPrevout {
            txout,
            confirmed_height: Some(height),
        }))
    }
}

impl PrevoutResolver for RpcPrevoutResolver<'_> {
    fn prevout(&mut self, outpoint: &OutPoint) -> Result<Option<ResolvedPrevout>, LookupError> {
        if let Some(cached) = self.memo.get(outpoint) {
            return Ok(cached.clone());
        }
        let resolved = self.resolve_prevout(outpoint)?;
        let charge = 96_usize
            + resolved
                .as_ref()
                .map_or(0, |prevout| prevout.txout.script_pubkey.len());
        let total = self
            .state_bytes
            .checked_add(charge)
            .ok_or(LookupError::LimitExceeded(
                crate::compressed_tx::Limit::State,
            ))?;
        if total > MAX_RESOLVER_STATE_BYTES {
            return Err(LookupError::LimitExceeded(
                crate::compressed_tx::Limit::State,
            ));
        }
        self.state_bytes = total;
        self.memo.insert(*outpoint, resolved.clone());
        Ok(resolved)
    }

    fn flat_output_index(
        &mut self,
        height: u32,
        txid: &Txid,
        vout: u32,
    ) -> Result<Option<u32>, LookupError> {
        match self.ensure_body(height) {
            Err(LookupError::Missing) => return Ok(None),
            Err(error) => return Err(error),
            Ok(()) => {}
        }
        let Some(body) = self.bodies.iter().find(|body| body.height == height) else {
            return Err(LookupError::BodyMissing(height));
        };
        Ok(body
            .rows
            .iter()
            .find(|row| row.txid == *txid && vout < row.output_count)
            .map(|row| row.first_flat + vout))
    }

    fn outpoint_at(
        &mut self,
        height: u32,
        flat_index: u32,
    ) -> Result<Option<(OutPoint, ResolvedPrevout)>, LookupError> {
        match self.ensure_body(height) {
            Err(LookupError::Missing) => return Ok(None),
            Err(error) => return Err(error),
            Ok(()) => {}
        }
        let located = self.bodies.iter().find_map(|body| {
            if body.height != height {
                return None;
            }
            body.rows.iter().find_map(|row| {
                (flat_index >= row.first_flat && flat_index < row.first_flat + row.output_count)
                    .then_some((row.txid, flat_index - row.first_flat))
            })
        });
        let Some((txid, vout)) = located else {
            return Ok(None);
        };
        let Some(txout) = self.body_txout(height, &txid, vout)? else {
            return Ok(None);
        };
        Ok(Some((
            OutPoint::new(txid, vout),
            ResolvedPrevout {
                txout,
                confirmed_height: Some(height),
            },
        )))
    }

    fn cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

impl ChainHandles {
    /// Runs a read with authoritative UTXO and applied-tip transitions excluded.
    ///
    /// PRE: `read` does not reacquire the transition role.
    /// POST: `read` completes before the exclusion guard is released, so its
    ///   live tip and UTXO observations describe one uninterrupted chainstate.
    /// INVARIANT: this is mutable-chainstate exclusion, not status
    ///   synchronization: published status reads answer from a retained
    ///   `AppliedView` capture and never call it.
    pub(crate) fn with_stable_chainstate<R>(&self, read: impl FnOnce() -> R) -> R {
        let _transition = self.chain_transition.lock();
        read()
    }

    /// Returns the pruning state reported by `getblockchaininfo`.
    #[must_use]
    fn prune_status(&self) -> PruneStatus {
        self.prune_service
            .as_ref()
            .map_or_else(PruneStatus::default, |service| service.status())
    }

    /// Typed synchronization progress: the `getblockchaininfo` facts without
    /// RPC JSON. Chainwork is the applied tip's when one exists.
    ///
    /// PRE: none.
    /// POST: progress projected from one applied publication captured here.
    /// INVARIANT: neither capture nor projection acquires `chain_transition`,
    ///   so a block transition in progress cannot stall this response.
    #[must_use]
    pub fn sync_progress(&self) -> SyncProgress {
        let applied = self.applied_view();
        self.sync_progress_at(&applied)
    }

    /// Synchronization progress projected from a retained applied publication.
    ///
    /// PRE: `applied` is the view this response is built from.
    /// POST: the chain facts are Chainstate's [`bitcoin_rs_chain::ChainProgress`]
    ///   at that view; this adds Core's difficulty rendering and the storage
    ///   facts. The header height is sampled separately, so best-header may
    ///   lead applied.
    /// INVARIANT: the projection never reloads the applied publication.
    #[must_use]
    pub(crate) fn sync_progress_at(&self, applied: &AppliedView) -> SyncProgress {
        let chain = self
            .progress
            .progress_at(applied.tip(), self.chain_network, unix_time_secs());
        let prune_status = self.prune_status();
        SyncProgress {
            network: self.chain_network,
            blocks: chain.blocks,
            headers: chain.headers,
            best_block_hash: chain.best_block_hash,
            difficulty: chain
                .bits
                .map_or(0.0, |bits| self.difficulty_for_bits(bits)),
            time: chain.time,
            median_time: chain.median_time,
            verification_progress: chain.verification_progress,
            initial_block_download: chain.initial_block_download,
            chain_work: chain.chain_work.map_or_else(
                || "00".to_owned(),
                |work| {
                    let bytes: [u8; 32] = work.to_be_bytes();
                    bytes.to_lower_hex_string()
                },
            ),
            size_on_disk: self
                .block_storage_disk_usage()
                .unwrap_or_else(|| self.blocks.read().size_on_disk()),
            pruned: prune_status.pruned,
            prune_height: prune_status.pruneheight,
        }
    }

    /// Returns the f64 difficulty for `bits` using Bitcoin Core's calculation.
    ///
    /// Keep the operation order here in sync with Core's `GetDifficulty`;
    /// changing the repeated 256 scaling into an equivalent exponentiation can
    /// change the final floating-point bit.
    #[must_use]
    pub fn difficulty_for_bits(&self, bits: CompactTarget) -> f64 {
        bitcoin_rs_mining::difficulty_for_bits(bits)
    }

    /// Stores a block record for block and header RPCs.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn add_block(&self, record: BlockRecord) {
        self.blocks.write().push(record);
    }

    /// Borrows the provisional chain capability shared with P2P admission.
    #[must_use]
    pub(crate) fn admission_chain(&self) -> ChainAdmissionView {
        ChainAdmissionView::new(
            self.utxo.clone(),
            self.applied_tip.clone(),
            self.block_tree.clone(),
            self.chain_network,
        )
    }

    /// Returns the current best-applied-block height (lags the header tip when
    /// headers are ahead of downloaded blocks).
    #[must_use]
    pub(crate) fn applied_height(&self) -> u32 {
        self.applied_view().height()
    }

    /// Returns the current best-applied-block hash.
    ///
    /// Before the first applied tip is published the canonical chain is the
    /// genesis-only chain, exactly as `applied_height` already reports `0` and
    /// `block_hash_at_height(0)` answers the genesis hash — callers must never
    /// see an all-zero tip for a chain that always has a height-0 block.
    #[must_use]
    pub(crate) fn applied_hash(&self) -> Hash256 {
        self.applied_view().hash(self.chain_network)
    }

    fn hash_at_height_from_tip(&self, tip: &TipSnapshot, height: u32) -> Option<Hash256> {
        if height > tip.height {
            return None;
        }
        if height == tip.height {
            return Some(tip.hash);
        }
        let tree = self.block_tree.read();
        let node_id = tree.node_at_height_from(tip.tip_id, height)?;
        Some(tree.node(node_id).ok()?.hash)
    }

    /// Returns the applied-chain hash at `height`, from the restored header index.
    #[must_use]
    pub(crate) fn active_hash_at_height(&self, height: u32) -> Option<Hash256> {
        self.active_hash_in_view(&self.applied_view(), height)
    }

    pub(crate) fn header_record(&self, hash: Hash256) -> Option<BlockRecord> {
        let tree = self.block_tree.read();
        let node = tree.node_by_hash(hash)?;
        Some(BlockRecord {
            hash: BlockHash::from(hash),
            height: node.height,
            body_size: 0,
            // The one place a header is produced. Every constructor leaves the
            // field empty, so the tree node reached here is the single source of
            // truth for what a block's header is.
            header: consensus_bytes(&node.header).try_into().ok().map(Box::new),
            tx_count: 0,
            time: node.header.time,
        })
    }

    /// Returns the block hash for an applied height.
    ///
    /// Once an applied tip exists, its ancestry is authoritative and heights
    /// above it are absent even when header sync has found a better fork.
    /// Before the first applied-tip publication, genesis and cache-only test
    /// records remain available.
    #[must_use]
    pub(crate) fn block_hash_at_height(&self, height: u32) -> Option<Hash256> {
        self.block_hash_at_height_in_view(&self.applied_view(), height)
    }

    /// Returns the applied-chain hash at `height` within a retained view.
    ///
    /// PRE: `view` is the response's retained applied publication.
    /// POST: that branch's hash at `height`; with no applied tip yet, the
    ///   genesis hash at height 0 or the block-log record's hash, which is the
    ///   cache-only fallback such contexts use.
    /// INVARIANT: reads the tree and the log as necessary but never reloads
    ///   `applied_tip`, so one response cannot straddle two applied branches.
    #[must_use]
    pub(crate) fn block_hash_at_height_in_view(
        &self,
        view: &AppliedView,
        height: u32,
    ) -> Option<Hash256> {
        if let Some(tip) = view.tip() {
            return self.hash_at_height_from_tip(tip, height);
        }
        if height == 0 {
            return Some(self.chain_network.genesis_block_hash());
        }
        record_at_height(&self.blocks.read(), height).map(|candidate| Hash256::from(candidate.hash))
    }

    /// Resolves a block record for `hash`.
    ///
    /// The restored header tree is the only identity authority. A hash it does
    /// not know resolves to `None`, even when the block log carries a record for
    /// it. For a tree-resolved `(height, hash)` pair, the log may contribute
    /// matching durable body metadata.
    #[must_use]
    pub fn block_by_hash(&self, hash: Hash256) -> Option<BlockRecord> {
        // Tree authority resolves identity first; the exact `(height, hash)`
        // record may then enrich its payload fields.
        if let Some(mut record) = self.header_record(hash) {
            // The tree already gave us the height, so this is a binary search
            // over a height-ordered log rather than a walk of every record on
            // the chain. `getblock` and `getblockheader` both land here.
            if let Some(cached) = record_at_height_hash(&self.blocks.read(), record.height, hash) {
                // The cached record supplies the payload facts — size and
                // transaction count — and the tree supplies the header, because
                // the log does not store one. Returning the cached record as it
                // stands would answer with no header at all.
                //
                // Costs no extra lock: `header_record` has already taken and
                // released the tree guard, and the header it produced outlives
                // it.
                let mut cached = cached.clone();
                cached.header = record.header.take();
                return Some(cached);
            }
            if let Some(metadata) = self
                .block_body_source
                .as_ref()
                .and_then(|source| source.block_body_metadata(record.height, BlockHash::from(hash)))
            {
                record.body_size = metadata.body_size;
                record.tx_count = metadata.tx_count;
            }
            return Some(record);
        }
        None
    }

    /// Returns the applied block at a height.
    ///
    /// Once an applied tip exists, its ancestry is authoritative. The session
    /// vector is a cache-only fallback before the first applied-tip publication.
    #[must_use]
    pub(crate) fn block_by_height(&self, height: u32) -> Option<BlockRecord> {
        self.block_by_height_in_view(&self.applied_view(), height)
    }

    /// Returns the applied block at `height` within a retained view.
    ///
    /// PRE: `view` is the response's retained applied publication.
    /// POST: that branch's record at `height`; with no applied tip yet, the
    ///   block-log record, which is the cache-only fallback such contexts use.
    /// INVARIANT: reads the log as necessary but never reloads `applied_tip`,
    ///   so one response cannot straddle two applied branches.
    #[must_use]
    pub(crate) fn block_by_height_in_view(
        &self,
        view: &AppliedView,
        height: u32,
    ) -> Option<BlockRecord> {
        if let Some(tip) = view.tip() {
            let hash = self.hash_at_height_from_tip(tip, height)?;
            return self.block_by_hash(hash);
        }
        record_at_height(&self.blocks.read(), height).cloned()
    }

    /// Returns serialized block bytes from durable body storage.
    #[must_use]
    pub fn block_body_bytes(&self, record: &BlockRecord) -> Option<Vec<u8>> {
        self.block_body_source
            .as_ref()?
            .block_body(record.height, record.hash)
            .ok()
            .flatten()
    }

    /// Bytes the node's block storage occupies on disk, when it can say.
    ///
    /// `None` when there is no durable body source, or it does not track usage.
    #[must_use]
    fn block_storage_disk_usage(&self) -> Option<u64> {
        self.block_body_source.as_ref()?.disk_usage()
    }

    /// Returns lowercase serialized block hex from durable body storage.
    #[must_use]
    pub(crate) fn block_body_hex(&self, record: &BlockRecord) -> Option<String> {
        Some(self.block_body_bytes(record)?.to_lower_hex_string())
    }

    /// Returns the median-time-past at the block with `hash`, or `None` if the
    /// block is not in the tree.
    #[must_use]
    pub(crate) fn median_time_past_for_hash(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Option<u32> {
        let tree = self.block_tree.read();
        let node_id = tree.lookup(hash)?;
        tree.median_time_past_at(node_id)
    }

    /// Returns the block height for `hash` via the in-memory `BlockTree`, or
    /// `None` if no node with that hash is known to the tree.
    ///
    /// Composes `BlockTree::height_of_hash` (chain crate commit `ef9ff41`).
    #[must_use]
    pub(crate) fn height_for_hash(&self, hash: bitcoin_rs_primitives::Hash256) -> Option<u32> {
        self.block_tree.read().height_of_hash(hash)
    }

    /// Returns the 64-char lowercase hex chainwork at the block with `hash`.
    #[must_use]
    pub(crate) fn chain_work_hex_for_hash(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Option<String> {
        let tree = self.block_tree.read();
        let node = tree.node_by_hash(hash)?;
        let bytes: [u8; 32] = node.chainwork.to_be_bytes();
        Some(bytes.to_lower_hex_string())
    }
}

/// One retained applied-tip publication.
///
/// A response that reports several applied facts builds them from a single
/// value of this type, so height, hash, work, and count cannot come from
/// different blocks.
///
/// PRE: the publisher stores complete immutable [`TipSnapshot`] values.
/// POST: the view retains the result of exactly one `applied_tip` load; no
///   transition exclusion, tree lock, UTXO lock, count-register read, or retry
///   loop occurs in capture.
/// INVARIANT: the facts projected from this view describe the same
///   publication even if the publisher advances afterward.
pub(crate) struct AppliedView {
    tip: Option<Arc<TipSnapshot>>,
}

impl ChainHandles {
    /// Captures the applied publication the response is built from.
    ///
    /// PRE: none; this reads the published tip cell.
    /// POST: a view holding exactly one `applied_tip` load result, empty
    ///   before the first publication.
    /// INVARIANT: capture never acquires `chain_transition`, so a response
    ///   that reports only applied facts does not wait on a block transition.
    #[must_use]
    pub(crate) fn applied_view(&self) -> AppliedView {
        AppliedView {
            tip: self.applied_tip.load_full(),
        }
    }

    /// Returns the applied-chain hash at `height` within a retained view.
    ///
    /// PRE: `view` is the response's retained applied publication.
    /// POST: that tip's ancestor hash at `height`, or `None` for no tip, a
    ///   height above the tip, or missing ancestry.
    /// INVARIANT: reads the block tree as necessary but never reloads
    ///   `applied_tip`, so the answer cannot describe a newer branch.
    #[must_use]
    pub(crate) fn active_hash_in_view(&self, view: &AppliedView, height: u32) -> Option<Hash256> {
        let tip = view.tip()?;
        self.hash_at_height_from_tip(tip, height)
    }
}

impl AppliedView {
    /// The captured snapshot, or `None` before the first publication.
    ///
    /// PRE: use a captured view.
    /// POST: the retained snapshot.
    /// INVARIANT: does not reload a publisher.
    #[must_use]
    pub(crate) fn tip(&self) -> Option<&TipSnapshot> {
        self.tip.as_deref()
    }

    /// The applied height, `0` with no tip.
    ///
    /// PRE: use a captured view.
    /// POST: the captured tip's height, or the empty-tip default `0`.
    /// INVARIANT: does not reload a publisher.
    #[must_use]
    pub(crate) fn height(&self) -> u32 {
        self.tip.as_ref().map_or(0, |tip| tip.height)
    }

    /// The applied block hash, genesis with no tip.
    ///
    /// PRE: use a captured view and the network the response describes.
    /// POST: the captured tip's hash, or that network's genesis hash when the
    ///   view is empty.
    /// INVARIANT: does not reload a publisher.
    #[must_use]
    pub(crate) fn hash(&self, network: Network) -> Hash256 {
        self.tip
            .as_ref()
            .map_or_else(|| network.genesis_block_hash(), |tip| tip.hash)
    }

    /// The applied-chain transaction count, `None` when unknown.
    ///
    /// PRE: use a captured view.
    /// POST: the captured tip's count, or `None` for an empty view or a tip
    ///   whose count is not yet known. A present tip with an unknown count is
    ///   not guessed as zero.
    /// INVARIANT: does not reload a publisher or read a count register.
    #[must_use]
    pub(crate) fn chain_tx_count(&self) -> Option<u64> {
        self.tip.as_ref().and_then(|tip| tip.chain_tx_count.get())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;

#[cfg(test)]
mod admission_chain_tests;

#[cfg(test)]
pub(crate) struct BlockBodies {
    pub(crate) bodies: Vec<(u32, BlockHash, Vec<u8>)>,
}

#[cfg(test)]
impl BlockBodySource for BlockBodies {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        Ok(self
            .bodies
            .iter()
            .find(|(candidate_height, candidate_hash, _)| {
                *candidate_height == height && *candidate_hash == hash
            })
            .map(|(_, _, body)| body.clone()))
    }
}
