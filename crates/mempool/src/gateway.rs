//! The single mutation gateway in front of the mempool.
//!
//! Every production mempool mutation routes through [`MempoolGateway`]: it
//! owns the pool's write lock, commits the mutation, and then enqueues the
//! ordered [`MutationEnvelope`] for the optional [`MempoolObserver`] — always
//! in commit order, by construction. Publication is eventual: a nested or
//! concurrent mutation call may return before its callback runs, and the
//! elected drainer completes every queued callback exactly once, in
//! sequence order, with no gateway lock held. After this, no production
//! code outside the gateway takes the mempool write lock — lookups go
//! through the [`MempoolGateway::read`] passthrough. The composition root
//! constructs one gateway per pool and passes clones of that handle to every
//! mutation route, so they share one publish queue and one observer slot.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::entry::MempoolEntry;
use crate::pool::{Mempool, transaction_heap_usage};
use bitcoin_rs_consensus::{
    ConsensusError, ScriptExecutionCache, UtxoView, ValidationEngine, transaction_sigop_cost,
    verify_transaction,
};
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid, Wtxid};
use bitcoin_rs_script::VerifyFlags;
use bitcoin_rs_script::{is_p2sh, is_witness_program};
use hashbrown::{HashMap, HashSet};
use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Adapter that lets the consensus verifier look up prevouts from a resolved
/// `(OutPoint, TxOut)` slice, layered under the mempool by `MempoolUtxoView`.
struct PrevoutMap<'a>(&'a [(OutPoint, TxOut)]);

impl UtxoView for PrevoutMap<'_> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.0
            .iter()
            .find(|(op, _)| op == outpoint)
            .map(|(_, txout)| txout.clone())
    }
}

/// Chain UTXO set with the mempool's unconfirmed outputs layered on top.
struct MempoolUtxoView<'a, V> {
    pool: &'a Mempool,
    chain: &'a V,
}

impl<'a, V> MempoolUtxoView<'a, V> {
    /// Layers `pool`'s unconfirmed outputs over `chain`.
    #[must_use]
    const fn new(pool: &'a Mempool, chain: &'a V) -> Self {
        Self { pool, chain }
    }
}

impl<V> UtxoView for MempoolUtxoView<'_, V>
where
    V: UtxoView,
{
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        if let Some(entry) = self.pool.entry_by_txid(&outpoint.txid) {
            let vout = usize::try_from(outpoint.vout).ok()?;
            return entry.tx.outputs.get(vout).cloned();
        }
        self.chain.lookup(outpoint)
    }
}

/// Why a chain-change reservation or finish failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ChainChangeError {
    /// A chain change is already active (the current generation is odd).
    #[error("a chain change is already active")]
    AlreadyActive,
    /// The reserved odd or even value would overflow `u64`.
    #[error("chain generation overflow")]
    Overflow,
    /// The compare-exchange from the odd value to the reserved even value
    /// failed because the generation moved underneath the guard.
    #[error("chain generation changed before finish")]
    GenerationMoved,
    /// The guard was issued by a different gateway.
    #[error("chain change guard belongs to another gateway")]
    ForeignGuard,
}

// ---------------------------------------------------------------------------
// Atomic admission — one generation-revalidated gateway operation.
// ---------------------------------------------------------------------------

/// Resolved context and exact state tokens for one admission attempt.
pub struct AdmissionRequest {
    /// The transaction to admit.
    pub tx: Arc<Tx>,
    /// Resolved per-transaction context (fee, vsize, sigop cost, missing
    /// inputs) from the mempool and UTXO set.
    pub context: crate::standardness::PackageTxContext,
    /// Resolved prevouts for consensus verification. Empty when the caller
    /// has not resolved them (e.g., missing inputs); the admission path
    /// rejects the transaction outright rather than admitting it unverified.
    pub prevouts: Vec<(
        bitcoin_rs_primitives::OutPoint,
        bitcoin_rs_primitives::TxOut,
    )>,
    /// Confirmed-chain metadata for each resolved prevout. Unconfirmed
    /// mempool/package parents are derived by the gateway; confirmed entries
    /// come from the chain snapshot. Absent entries carry no lock or maturity
    /// constraint.
    pub prevout_meta: hashbrown::HashMap<OutPoint, crate::PrevoutMeta>,
    /// Median-time-past of the applied chain tip for BIP113 finality checks.
    /// Zero disables the locktime cutoff (pre-genesis).
    pub locktime_cutoff: u32,
    /// Whether CSV (BIP68/112/113) is active for the next block.
    pub csv_active: bool,
    /// Script flags the next block will verify under. The script stage
    /// re-verifies the transaction under these flags after the `STANDARD`
    /// pass to fill the script-execution cache.
    pub next_block_script_flags: VerifyFlags,
    /// Caller-supplied maximum fee rate in sat/kvB; `None` means no cap.
    pub max_feerate_sat_per_kvb: Option<u64>,
    /// Wall-clock seconds for the mempool entry timestamp.
    pub time: u64,
    /// Current applied block height for the mempool entry. Finality is
    /// evaluated at the next block height (`height + 1`), matching Core's
    /// `CheckFinalTxAtTip`, while the stored entry keeps this applied tip
    /// height.
    pub height: u32,
    /// How the transaction entered the node.
    pub origin: AdmissionOrigin,
    /// Exact chain generation the caller captured before admission.
    /// Ordinary submitters only ever hold an even value obtained from
    /// [`MempoolGateway::stable_generation`]; requests prepared under a
    /// [`ChainChangeGuard`] carry its odd value. The token alone grants no
    /// authority — `check_admission_state` accepts it only under the
    /// matching `AdmissionFence`.
    pub expected_generation: u64,
    /// Exact mempool sequence the caller captured before admission.
    pub expected_sequence: u64,
}

/// The outcome of one admission attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmitOutcome {
    /// The transaction was committed to the pool. The result carries every
    /// `Removed` change in commit order followed by exactly one `Accepted`.
    Committed(crate::mutation::MutationResult),
    /// The exact transaction was already present. No envelope, sequence, or
    /// publication was produced — the caller returns normal txid success.
    AlreadyKnown,
}

/// Why an admission attempt did not commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdmitError {
    /// The chain generation changed between capture and the write-lock
    /// check. The caller must retry with a fresh stable generation.
    #[error("chain generation changed before admission")]
    GenerationChanged,
    /// The mempool sequence changed between capture and the write-lock
    /// check. The caller must retry with fresh facts.
    #[error("mempool sequence changed before admission")]
    MempoolChanged,
    /// The transaction was rejected by policy. The reason is mempool-owned.
    #[error(transparent)]
    Policy(#[from] crate::standardness::AcceptanceRejectReason),
    /// The transaction failed consensus verification (finality, duplicate
    /// inputs, overspend, sigop limits) or failed its input scripts under
    /// Core's policy flags (`STANDARD_SCRIPT_VERIFY_FLAGS`, validation.cpp
    /// `PolicyScriptChecks`).
    #[error("consensus verification failed")]
    Consensus,
}

/// Immutable input facts and a provisional verdict. It carries no pool borrow:
/// script execution must finish before the writer reservation is acquired.
pub(crate) struct PreparedAdmission {
    pub(crate) fact: crate::standardness::TxAcceptanceFact,
    prevouts: Vec<(OutPoint, TxOut)>,
    pub(crate) rejection: Option<(AdmitError, RejectScope)>,
    pub(crate) stamp: crate::pool::fee_policy::PolicyStamp,
    /// Floor bump a refused size trim earned, applied only in the stamped
    /// commit closure. The reported rejection is unchanged.
    pub(crate) refused_bump: Option<crate::rbf::TrimBump>,
    replacement: ReplacementStage,
    /// Engine for this attempt's script checks; set by the gateway that
    /// prepared it, so the deferred `verify` phase cannot run under another.
    engine: ValidationEngine,
    /// Validated script-cache key from the second verification pass. Set only
    /// when that pass succeeds with no rejection pending; the commit outcome
    /// below decides whether it is inserted, so rejected admissions and
    /// failed packages never fill.
    pub(crate) script_cache_key: Option<(Wtxid, VerifyFlags)>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AdmissionMode {
    Single,
    SingleSubmit,
    PackageTest,
    PackageSubmit,
    PackageRpcSubmit(Option<u64>),
}

#[allow(
    clippy::large_enum_variant,
    reason = "Admission stages keep their owned facts inline without an additional heap allocation."
)]
enum ReplacementStage {
    Rejected,
    Package,
    Captured(crate::rbf::ReplacementInputs),
    Verified(crate::rbf::PreparedPoolChange),
}

impl PreparedAdmission {
    pub(crate) fn check_package_max_feerate(&mut self, maximum: Option<u64>) {
        if self.rejection.is_none()
            && self.fact.vsize != 0
            && maximum.is_some_and(|max| {
                self.fact.modified_fee.is_some_and(|fee| {
                    // Core 31.1 compares CFeeRate ratios, not GetFee or the
                    // displayed integer rate. Divide the nonnegative limit
                    // instead of multiplying the signed fee. u64 * u32 fits
                    // i128, and negative or very large fee deltas stay exact.
                    fee > i128::from(max) * i128::from(self.fact.vsize) / 1_000
                })
            })
        {
            self.reject(
                AdmitError::Policy(crate::standardness::AcceptanceRejectReason::MaxFeeExceeded),
                RejectScope::Transaction,
            );
        }
    }

    fn reject(&mut self, error: AdmitError, scope: RejectScope) {
        self.replacement = ReplacementStage::Rejected;
        self.fact.allowed = Some(false);
        self.fact.reject_reason = Some(match error {
            AdmitError::Policy(reason) => reason,
            _ => crate::standardness::AcceptanceRejectReason::ScriptVerify,
        });
        self.rejection = Some((error, scope));
    }

    /// Both preview and submission execute precisely this verification over
    /// the copied input outputs, never over a changing pool or chain reader.
    /// A successful script stage records the cache key; the commit outcome
    /// decides insertion. Previews pass `None` and stay dry.
    pub(crate) fn verify(
        &mut self,
        request: &AdmissionRequest,
        script_cache: Option<&ScriptExecutionCache>,
    ) {
        self.verify_policy(request);
        self.verify_scripts(request, script_cache);
    }

    pub(crate) fn verify_policy(&mut self, request: &AdmissionRequest) {
        use crate::standardness::AcceptanceRejectReason;
        if matches!(self.rejection, Some((AdmitError::Consensus, _))) {
            return;
        }
        if matches!(
            self.fact.reject_reason,
            Some(
                AcceptanceRejectReason::NonStandard(_)
                    | AcceptanceRejectReason::MissingInputs
                    | AcceptanceRejectReason::AlreadyInMempool
                    | AcceptanceRejectReason::TooManySigops
            )
        ) {
            return;
        }
        let default_scope = rejection_scope(&request.tx);
        let Some(height) = request.height.checked_add(1) else {
            self.reject(AdmitError::Consensus, default_scope);
            return;
        };
        // Core package prechecks must reject value/finality errors before
        // any row is reported script-valid. Reuse the consensus owner over
        // copied outputs; this phase executes no scripts and holds no lock.
        if bitcoin_rs_consensus::verify_tx::verify_transaction_non_script(
            &request.tx,
            &PrevoutMap(&self.prevouts),
            height,
            request.locktime_cutoff,
            VerifyFlags::STANDARD,
        )
        .is_err()
        {
            self.reject(AdmitError::Consensus, default_scope);
            return;
        }
        for input in &request.tx.inputs {
            if let Some(meta) = request.prevout_meta.get(&input.previous_output)
                && bitcoin_rs_consensus::check_coinbase_maturity(meta.coinbase, meta.height, height)
                    .is_err()
            {
                self.reject(AdmitError::Consensus, default_scope);
                return;
            }
        }
        if self.rejection.is_some() {
            return;
        }
        let replacement = std::mem::replace(&mut self.replacement, ReplacementStage::Rejected);
        if let ReplacementStage::Captured(inputs) = replacement {
            match inputs.verify() {
                Ok(plan) => self.replacement = ReplacementStage::Verified(plan),
                Err(refusal) => {
                    let (error, bump) = refusal.into_parts();
                    self.refused_bump = bump;
                    self.reject(replacement_rejection(error), default_scope);
                }
            }
        } else if matches!(replacement, ReplacementStage::Package) {
            self.replacement = ReplacementStage::Package;
        } else {
            self.reject(AdmitError::MempoolChanged, default_scope);
        }
    }

    /// Runs the `STANDARD` script pass, then re-verifies under the request's
    /// next-block flags. A successful second pass with no rejection pending
    /// records the cache key for the commit outcome to insert; a failed
    /// second pass after a `STANDARD` pass is logged and records nothing, and
    /// a rejected transaction never fills.
    ///
    /// A size-trim refusal (`refused_bump`) still runs the `STANDARD` pass
    /// and the caller's max-feerate check: Core trims only script-valid,
    /// under-cap transactions, so an invalid script or a breached cap
    /// clears the bump while the reported `Full` rejection is kept either
    /// way. The next-block pass and the cache fill are skipped on this
    /// path — a refused transaction never fills.
    pub(crate) fn verify_scripts(
        &mut self,
        request: &AdmissionRequest,
        script_cache: Option<&ScriptExecutionCache>,
    ) {
        // A refused trim earns its floor bump only with valid scripts, but
        // the refusal itself is reported before scripts ever run.
        let verifying_refusal = self.refused_bump.is_some();
        if self.rejection.is_some() && !verifying_refusal {
            return;
        }
        let Some(height) = request.height.checked_add(1) else {
            self.refused_bump = None;
            return;
        };
        let default_scope = rejection_scope(&request.tx);
        let signature_cache = bitcoin_rs_script::SignatureCache::new();
        if let Err(error) = verify_transaction(
            &request.tx,
            &PrevoutMap(&self.prevouts),
            height,
            request.locktime_cutoff,
            VerifyFlags::STANDARD,
            self.engine,
            Some(&signature_cache),
        ) {
            if verifying_refusal {
                self.refused_bump = None;
                return;
            }
            let possibly_stripped = witness_strippable_failure(&error, &self.prevouts);
            self.reject(
                AdmitError::Consensus,
                if possibly_stripped {
                    RejectScope::Witness
                } else {
                    default_scope
                },
            );
            return;
        }
        // The caller's cap gates the bump like scripts do — Core applies
        // `client_maxfeerate` in PreChecks, before any trim can touch the
        // floor. The gate uses the transaction's actual base fee: a policy
        // discount or surcharge must not change the client fee-limit result.
        // A capped candidate keeps its Full report but earns nothing.
        let fee_for_max = self.fact.base_fee.unwrap_or(0);
        if crate::standardness::exceeds_max_feerate(
            fee_for_max,
            self.fact.vsize,
            request.max_feerate_sat_per_kvb,
        ) {
            self.refused_bump = None;
            if verifying_refusal {
                return;
            }
            self.reject(
                AdmitError::Policy(crate::standardness::AcceptanceRejectReason::MaxFeeExceeded),
                default_scope,
            );
        }
        if verifying_refusal {
            return;
        }
        if self.rejection.is_some() {
            return;
        }
        let Some(_) = script_cache.filter(|_| self.engine == ValidationEngine::Native) else {
            return;
        };
        let flags = request.next_block_script_flags;
        if let Err(error) = verify_transaction(
            &request.tx,
            &PrevoutMap(&self.prevouts),
            height,
            request.locktime_cutoff,
            flags,
            self.engine,
            Some(&signature_cache),
        ) {
            tracing::warn!(
                txid = %request.tx.txid(),
                flags = flags.bits(),
                error = %error,
                "script cache second pass failed after a STANDARD pass; not caching",
            );
            return;
        }
        self.script_cache_key = Some((request.tx.wtxid(), flags));
    }
}

fn replacement_rejection(error: RbfError) -> AdmitError {
    match error {
        RbfError::StalePlan => AdmitError::MempoolChanged,
        RbfError::Truc(error) => {
            AdmitError::Policy(crate::standardness::AcceptanceRejectReason::Truc(error))
        }
        RbfError::Mempool(crate::pool::MempoolError::Policy(policy)) => AdmitError::Policy(
            crate::standardness::AcceptanceRejectReason::PackageLimit(policy),
        ),
        other => AdmitError::Policy(crate::standardness::AcceptanceRejectReason::Replacement(
            other,
        )),
    }
}

fn rejection_scope(tx: &Tx) -> RejectScope {
    if tx.has_witness() {
        RejectScope::Witness
    } else {
        RejectScope::Transaction
    }
}

/// Whether a script-verification failure may be witness-strippable, i.e. a
/// different witness body of the same txid must still be allowed past the
/// rejection cache.
fn witness_strippable_failure(error: &ConsensusError, prevouts: &[(OutPoint, TxOut)]) -> bool {
    matches!(error, ConsensusError::Script { .. })
        && prevouts.iter().any(|(_, output)| {
            is_witness_program(&output.script_pubkey) || is_p2sh(&output.script_pubkey)
        })
}

use crate::mutation::{AdmissionOrigin, MutationEnvelope, MutationResult};
use crate::orphan::RejectScope;
use crate::pool::{MempoolError, PrioritiseError, PrioritisedTransaction};
#[cfg(any(test, feature = "test-seam"))]
use crate::rbf::ReplacementCandidate;
use crate::rbf::{LimitEnforcement, RbfError};

/// Receives every committed mempool mutation, exactly once, in sequence
/// order.
///
/// Callbacks run without gateway locks and may re-enter the gateway. Nested
/// commits enqueue behind the current callback and may return before publication.
/// Observer panics are contained after the pool mutation has committed.
///
/// Whether an observer wants accepted transaction bodies is a
/// registration-time fact ([`BodyInterest`]), never a callback: `commit`
/// loads the composite's atomic before taking the pool write lock, so no
/// observer code ever runs under any gateway lock.
pub trait MempoolObserver: Send + Sync {
    /// Called once per committed, non-empty [`MutationEnvelope`].
    fn on_mutation(&self, envelope: &MutationEnvelope);
}

/// Body-retention interest declared when a leg registers.
///
/// Bodies are captured under the pool write lock because they must match
/// the commit, not a later state, and are delivered in the ordered
/// envelope. Metadata-only legs skip retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyInterest {
    /// Retain accepted transaction bodies until ordered publication.
    Bodies,
    /// Envelope metadata only; no body retention.
    Metadata,
}

/// Fans one committed mutation out to several named observers.
#[derive(Default)]
pub struct CompositeObserver {
    /// Guarded because a subsystem may attach its leg after the gateway is
    /// constructed. Publication clones the list under this lock and releases it
    /// before calling any leg, so a leg re-entering the gateway cannot
    /// deadlock against an attach.
    legs: Mutex<Vec<(&'static str, Arc<dyn MempoolObserver>)>>,
    /// Registration-time OR of every leg's [`BodyInterest`]: true once any
    /// leg registers [`BodyInterest::Bodies`]. `commit` loads it before
    /// taking the pool write lock, so interest never executes observer code
    /// under any gateway lock. Legs are append-only, so the OR only ever
    /// gains `true` and needs no recomputation.
    bodies_wanted: AtomicBool,
}

impl CompositeObserver {
    /// An empty composite; attach legs with [`Self::add_leg`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            legs: Mutex::new(alloc::vec::Vec::new()),
            bodies_wanted: AtomicBool::new(false),
        }
    }

    /// Appends a named leg. Names identify the leg in failure logs only; the
    /// operator failure counter is intentionally aggregate. Order is
    /// publication order. Legs are append-only: once a [`BodyInterest::Bodies`]
    /// leg registers, body retention stays on.
    pub fn add_leg(
        &self,
        name: &'static str,
        leg: Arc<dyn MempoolObserver>,
        interest: BodyInterest,
    ) {
        self.legs.lock().push((name, leg));
        if interest == BodyInterest::Bodies {
            self.bodies_wanted.store(true, Ordering::Release);
        }
    }

    /// Whether any registered leg wants accepted transaction bodies.
    ///
    /// Loads the registration-time atomic; it calls no observer code and
    /// holds no gateway lock, so `commit` reads it before taking the pool
    /// write lock.
    #[must_use]
    pub fn wants_bodies(&self) -> bool {
        self.bodies_wanted.load(Ordering::Acquire)
    }
}

fn panic_message_and_dispose(panic_payload: Box<dyn core::any::Any + Send>) -> (String, bool) {
    let message = panic_payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            panic_payload
                .downcast_ref::<&str>()
                .map(|message| (*message).to_string())
        })
        .unwrap_or_else(|| "non-string panic payload".to_owned());
    let disposal_panicked = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        drop(panic_payload);
    }))
    .map_or_else(
        |nested_payload| {
            let _nested_payload = core::mem::ManuallyDrop::new(nested_payload);
            true
        },
        |()| false,
    );
    (message, disposal_panicked)
}

impl MempoolObserver for CompositeObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let legs = self.legs.lock().clone();
        for (name, leg) in &legs {
            let outcome = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
                leg.on_mutation(envelope);
            }));
            if let Err(panic_payload) = outcome {
                metrics::counter!("node.mempool.observer_failures_total").increment(1);
                let (message, payload_disposal_panicked) = panic_message_and_dispose(panic_payload);
                tracing::warn!(
                    leg = *name,
                    message = %message,
                    payload_disposal_panicked,
                    "mempool observer leg panicked; later legs continue"
                );
            }
        }
    }
}

/// Transactions kept beyond pool residency for BIP152 reconstruction: Core's
/// `DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN` (`net_processing.h:47-48`).
pub(crate) const BLOCK_RECONSTRUCTION_EXTRA_TXN: usize = 100;
/// A policy-rejected transaction whose retained heap reaches this bound is
/// not kept for reconstruction; Core's `RecursiveDynamicUsage(*ptx) < 100000`
/// gate (`net_processing.cpp:3139`), measured here with the pool's own
/// `transaction_heap_usage` accounting rather than the consensus
/// serialization.
pub(crate) const EXTRA_TXN_MAX_MEMORY_BYTES: usize = 100_000;

/// One retained body with the identities its reconstruction match needs.
struct ExtraTxn {
    txid: Txid,
    wtxid: Wtxid,
    tx: Arc<Tx>,
}

/// Bounded FIFO of transactions a compact block may still name after the pool
/// dropped or never admitted them: replaced bodies, peer orphans and peer
/// policy rejects (Core's `vExtraTxnForCompact`).
///
/// Identity is the witness hash, so two witness variants of one txid are two
/// entries. Re-inserting a resident wtxid changes nothing: the entry keeps its
/// place, so a repeated body can neither grow the ring nor postpone its own
/// eviction. A coinbase is never retained. Entry count is bounded by
/// [`BLOCK_RECONSTRUCTION_EXTRA_TXN`]. Bodies that reached the ring through
/// the pool or the orphan pool are already bounded by the standardness rules
/// that admitted them there; a policy reject is additionally bounded by the
/// [`EXTRA_TXN_MAX_MEMORY_BYTES`] retained-memory gate.
///
/// The ring is reconstruction-hint state only. It is never consulted for
/// inventory, `getdata`, relay, admission or any pool query.
#[derive(Default)]
pub(crate) struct ExtraTxnRing {
    entries: VecDeque<ExtraTxn>,
}

impl ExtraTxnRing {
    fn insert(&mut self, txid: Txid, wtxid: Wtxid, tx: &Arc<Tx>) {
        if tx.is_coinbase() || self.entries.iter().any(|held| held.wtxid == wtxid) {
            return;
        }
        if self.entries.len() == BLOCK_RECONSTRUCTION_EXTRA_TXN {
            self.entries.pop_front();
        }
        self.entries.push_back(ExtraTxn {
            txid,
            wtxid,
            tx: Arc::clone(tx),
        });
    }

    fn by_txid(&self, txid: Txid) -> Option<&Arc<Tx>> {
        self.entries
            .iter()
            .find(|held| held.txid == txid)
            .map(|held| &held.tx)
    }

    fn by_wtxid(&self, wtxid: Wtxid) -> Option<&Arc<Tx>> {
        self.entries
            .iter()
            .find(|held| held.wtxid == wtxid)
            .map(|held| &held.tx)
    }
}

/// Whether a peer-origin refusal is a policy verdict whose body a block may
/// still contain: only the typed policy class, below the retained-memory gate,
/// and not a transaction that spends a null or out-of-range outpoint (which no
/// block can carry). Consensus failures and stale-state retries are never
/// retained.
fn retains_rejected_body(pool: &Mempool, tx: &Tx, error: AdmitError) -> bool {
    let AdmitError::Policy(reason) = error else {
        return false;
    };
    transaction_heap_usage(tx) < u64::try_from(EXTRA_TXN_MAX_MEMORY_BYTES).unwrap_or(u64::MAX)
        && !(matches!(
            reason,
            crate::standardness::AcceptanceRejectReason::MissingInputs
        ) && crate::admission::has_unspendable_input(pool, tx))
}

/// The mutation publication queue state, protected by the `publish` mutex.
struct PublishState {
    /// Committed, non-empty envelopes awaiting their observer callback, in
    /// commit order.
    queue: VecDeque<MutationEnvelope>,
    /// Whether exactly one caller is draining the queue.
    draining: bool,
}

/// Owns the mempool's write lock and publishes ordered mutation events.
///
/// # Ordering invariant
///
/// Every mutating method flows through exactly one path, `Self::commit`,
/// which runs, in this exact order:
///
/// 1. take the commit-ordering lock, then the pool write lock,
/// 2. mutate and assign per-change mempool sequences,
/// 3. release the write lock, join accepted bodies to the committed changes,
///    then enqueue the non-empty envelope on the publish state's FIFO queue
///    and elect a drainer if none exists,
/// 4. release the ordering lock and the publish-state lock,
/// 5. the elected drainer pops batches one at a time — releasing the
///    publish-state lock before every observer call — and returns the
///    publish state to idle only once the queue is empty.
///
/// Commits serialize under the ordering lock and step 3 enqueues under that
/// same ownership, so the queue order is the commit order and the sequence
/// order: every committed, non-empty batch is published exactly once, in
/// order, even across nested and concurrent callers. Publication is
/// eventual, not synchronous: a nested or concurrent mutation enqueues
/// and returns while a drainer exists, and its callback may run after
/// that call has returned. No gateway lock is ever held across an
/// observer call, so observers may re-enter the gateway freely. An
/// observer panic is caught and recorded; the drainer continues with
/// the remaining queue and only then returns to idle. Empty results and
/// an absent observer enqueue nothing, allocate nothing, and spawn no
/// thread.
pub struct MempoolGateway {
    pub(crate) pool: Arc<RwLock<Mempool>>,
    /// Pool guards precede this lock. Never held during observer calls,
    /// script verification, or chain/transport access.
    pub(crate) lifecycle: Mutex<crate::orphan::AdmissionLifecycle>,
    /// The one observer slot, held as the composite so a second subsystem
    /// can attach its own named leg after construction. An absent composite
    /// means nobody is listening and the publish path stays allocation-free.
    observer: Option<Arc<CompositeObserver>>,
    /// Serializes commit-to-enqueue so the publish queue order is the commit
    /// order. Taken before the pool write lock and released after the
    /// publish enqueue; the pool guard itself drops before the body join so
    /// admission-lock time stays out of the join. Lock order is
    /// commit-order, pool, publish, and it is never held across an observer
    /// call.
    commit_order: Mutex<()>,
    publish: Mutex<PublishState>,
    /// BIP152 reconstruction extras: replaced bodies, peer orphans and peer
    /// policy rejects. A leaf lock: pool guards precede it, and nothing else
    /// is acquired while it is held. Written only under the pool write lock,
    /// so a walk under the pool read guard sees pool and ring at one instant.
    pub(crate) extra_txn: Mutex<ExtraTxnRing>,
    /// Even means stable; odd means a chain change is active or a failed
    /// chain change has closed admission. Initialized to `0` (even/stable)
    /// in [`Self::new`]. Compare only for exact equality — never order or
    /// subtract wrapping counters.
    chain_generation: AtomicU64,
    /// The one script-verification engine this gateway's admission path runs,
    /// resolved once from node configuration (`validation.engine`). The
    /// admission pipeline is shared; only the script backend dispatches on it.
    engine: ValidationEngine,
    /// Native-only script-execution cache filled after admission and
    /// consulted by block connect. `None` without a node composition that
    /// installed one (including every kernel-engine node, so the kernel
    /// oracle stays authoritative).
    script_cache: Option<Arc<ScriptExecutionCache>>,
}

impl core::fmt::Debug for MempoolGateway {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MempoolGateway")
            .field("pool", &self.pool)
            .field("observer", &self.observer.as_ref().map(|_| "installed"))
            .finish_non_exhaustive()
    }
}

impl MempoolGateway {
    /// Wraps `pool` and optionally installs `observer`.
    ///
    /// The composition root must construct exactly one gateway for a pool and
    /// pass clones of that handle to every mutation route.
    ///
    /// Pass `None` — or use the node's no-op publisher behind its observer —
    /// when no `--zmq-pub-sequence` endpoint is configured.
    ///
    /// `script_cache` is the node-owned script-execution cache this gateway
    /// fills after admission; the node passes `Some` only when the validation
    /// engine is native, `None` otherwise (including every test seam that
    /// does not exercise the fill).
    #[must_use]
    pub fn new(
        pool: Arc<RwLock<Mempool>>,
        observer: Option<(Arc<dyn MempoolObserver>, BodyInterest)>,
        engine: ValidationEngine,
        script_cache: Option<Arc<ScriptExecutionCache>>,
    ) -> Self {
        let composite = observer.map(|(observer, interest)| {
            let composite = CompositeObserver::new();
            composite.add_leg("primary", observer, interest);
            Arc::new(composite)
        });
        Self {
            pool,
            lifecycle: Mutex::new(crate::orphan::AdmissionLifecycle::default()),
            observer: composite,
            commit_order: Mutex::new(()),
            publish: Mutex::new(PublishState {
                queue: VecDeque::new(),
                draining: false,
            }),
            extra_txn: Mutex::new(ExtraTxnRing::default()),
            chain_generation: AtomicU64::new(0),
            engine,
            script_cache,
        }
    }

    /// The resolved script-verification engine this gateway verifies with.
    #[must_use]
    pub const fn engine(&self) -> ValidationEngine {
        self.engine
    }

    /// The node-owned script-execution cache this gateway fills, if any.
    #[must_use]
    pub(crate) fn script_cache(&self) -> Option<&ScriptExecutionCache> {
        self.script_cache.as_deref()
    }

    /// Attaches another named leg to this gateway's observer slot.
    pub fn attach_observer_leg(
        &self,
        name: &'static str,
        leg: Arc<dyn MempoolObserver>,
        interest: BodyInterest,
    ) -> Result<(), &'static str> {
        let Some(composite) = self.observer.as_ref() else {
            return Err("gateway has no observer slot to extend");
        };
        composite.add_leg(name, leg, interest);
        Ok(())
    }

    /// Returns `true` when the gateway was constructed with an observer.
    ///
    /// Test seam: lifecycle assertions only.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn has_observer(&self) -> bool {
        self.observer.is_some()
    }

    /// Returns a cloneable read-only capability over the pool.
    #[must_use]
    pub fn reader(&self) -> crate::MempoolReader {
        crate::MempoolReader::new(Arc::clone(&self.pool))
    }

    /// Raw pool access for test fixture staging and read-side composition
    /// only. The raw-site audit's production pattern matches
    /// `.pool().write()` too; production mutations must go through the
    /// gateway so observers stay in the loop.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn pool(&self) -> &Arc<RwLock<Mempool>> {
        &self.pool
    }

    /// Read passthrough for lookup callers. Never mutate through this guard:
    /// mutations must go through the gateway so observers stay in the loop.
    pub fn read(&self) -> RwLockReadGuard<'_, Mempool> {
        self.pool.read()
    }

    /// Returns the exact even chain generation, or `None` when a chain change
    /// is active (odd) or a failed chain change has closed admission.
    #[must_use]
    pub fn stable_generation(&self) -> Option<u64> {
        let value = self.chain_generation.load(Ordering::Acquire);
        value.is_multiple_of(2).then_some(value)
    }

    /// The raw generation value, even or odd, for same-crate fence checks.
    /// Callers compare only for exact equality — never order or subtract.
    pub(crate) fn chain_generation(&self) -> u64 {
        self.chain_generation.load(Ordering::Acquire)
    }

    /// Reserves the next chain-change generation and returns a guard that owns
    /// the exact odd value and the reserved next even value.
    pub fn begin_chain_change(self: &Arc<Self>) -> Result<ChainChangeGuard, ChainChangeError> {
        let pool_guard = self.pool.write();
        let current = self.chain_generation.load(Ordering::Relaxed);
        if !current.is_multiple_of(2) {
            return Err(ChainChangeError::AlreadyActive);
        }
        let odd = current.checked_add(1).ok_or(ChainChangeError::Overflow)?;
        let even = odd.checked_add(1).ok_or(ChainChangeError::Overflow)?;
        self.chain_generation.store(odd, Ordering::Release);
        drop(pool_guard);
        Ok(ChainChangeGuard {
            gateway: Arc::clone(self),
            odd,
            even,
        })
    }

    /// Cross-crate test seam: prepares insertion outside the writer and
    /// publishes one atomic result. No production caller; fixtures use it to
    /// stage entries without resolving a chain snapshot.
    #[cfg(any(test, feature = "test-seam"))]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the consuming mutation API retains the entry across bounded optimistic attempts"
    )]
    pub fn insert_entry(
        &self,
        origin: AdmissionOrigin,
        entry: MempoolEntry,
    ) -> Result<MutationResult, MempoolError> {
        for _ in 0..crate::admission::MAX_ADMISSION_RETRIES {
            let inputs = self
                .pool
                .read()
                .capture_insertion(
                    entry.clone(),
                    crate::rbf::FeeEstimation::Estimate,
                    crate::rbf::LimitEnforcement::Full,
                )
                .map_err(RbfError::into_pool_error)?;
            let plan = match inputs.verify() {
                Ok(plan) => plan,
                Err(refusal) => {
                    // Raises serialize under the write guard with every other
                    // pool transition, so the floor cannot move between a
                    // read-guard capture and its stamp check.
                    let mut pool = self.pool.write();
                    let (error, bump) = refusal.into_parts();
                    let error = match bump {
                        Some(bump) if pool.track_refused_trim(bump).is_err() => {
                            MempoolError::StalePolicy
                        }
                        _ => error.into_pool_error(),
                    };
                    if matches!(error, MempoolError::StalePolicy) {
                        continue;
                    }
                    return Err(error);
                }
            };
            let result = self.commit(
                origin,
                move |pool| {
                    pool.commit_pool_change(plan)
                        .map_err(RbfError::into_pool_error)
                },
                |result| Some(result),
            );
            if !matches!(result, Err(MempoolError::StalePolicy)) {
                return result;
            }
        }
        Err(MempoolError::StalePolicy)
    }

    /// Verifies replacement outside the writer, then commits and publishes
    /// only while the captured pool and fee state is still current.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn replace_transaction(
        &self,
        origin: AdmissionOrigin,
        candidate: &ReplacementCandidate,
        time: u64,
        height: u32,
    ) -> Result<crate::mutation::MutationResult, RbfError> {
        for _ in 0..crate::admission::MAX_ADMISSION_RETRIES {
            let inputs = self.pool.read().capture_replacement(
                candidate,
                time,
                height,
                crate::rbf::FeeEstimation::Estimate,
            )?;
            let plan = match inputs.verify() {
                Ok(plan) => plan,
                Err(refusal) => {
                    // See above: raises take the write guard.
                    let mut pool = self.pool.write();
                    let (error, bump) = refusal.into_parts();
                    let error = match bump {
                        Some(bump) if pool.track_refused_trim(bump).is_err() => RbfError::StalePlan,
                        _ => error,
                    };
                    if matches!(error, RbfError::StalePlan) {
                        continue;
                    }
                    return Err(error);
                }
            };
            let result = self.commit(
                origin,
                move |pool| pool.commit_pool_change(plan),
                |result| Some(result),
            );
            if !matches!(result, Err(RbfError::StalePlan)) {
                return result;
            }
        }
        Err(RbfError::StalePlan)
    }

    /// Evaluates policy and copies input outputs under a pool read, then
    /// verifies scripts without a pool lock. The writer rechecks the captured
    /// chain generation, pool sequence and policy before any lifecycle change
    /// or mutation. Exact duplicates retain their idempotent submission result.
    /// Committed changes use the existing ordered publication seam, including
    /// the capacity evictions verified before insertion.
    // The public atomic API consumes its prepared request; the private path
    // borrows it so the shared retry owner can recover the Arc after a mismatch.
    #[expect(clippy::needless_pass_by_value)]
    /// Test seam: the pre-claimed single-shot door; production submissions
    /// run through `submit_transaction`'s bounded claimed path.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn admit_transaction(&self, request: AdmissionRequest) -> Result<AdmitOutcome, AdmitError> {
        self.admit_transaction_claimed(&request, None, crate::admission::AdmissionFence::Stable)
    }

    /// A private resident-body claim joins generation/sequence validation.
    /// Evicted or refreshed retry bodies may not mutate pool or lifecycle.
    // Keep token checks, mutation, lifecycle finalization and FIFO publication
    // in one auditable write-lock interval instead of splitting the commit.
    pub(crate) fn admit_transaction_claimed(
        &self,
        request: &AdmissionRequest,
        claim: Option<(&crate::orphan::HeldOrphan, &crate::PeerToken)>,
        fence: crate::admission::AdmissionFence,
    ) -> Result<AdmitOutcome, AdmitError> {
        let mut prepared = {
            let pool = self.pool.read();
            self.check_admission_state(
                &pool,
                request.expected_generation,
                request.expected_sequence,
                fence,
                None,
            )?;
            Self::prepare_admission(
                &pool,
                request,
                AdmissionMode::SingleSubmit,
                fence,
                self.engine(),
            )
        };
        prepared.verify(request, self.script_cache());

        #[cfg(any(test, feature = "test-seam"))]
        ordering_gate::park_if_armed(std::ptr::from_ref(self).expose_provenance());

        // The validated key is copied out before the writer runs; the commit
        // outcome below decides whether it is inserted, outside the pool
        // write lock, with no re-verification and no cloning.
        let cache_key = prepared.script_cache_key;

        let outcome = self.commit(
            request.origin,
            |pool| {
                self.check_admission_state(
                    pool,
                    request.expected_generation,
                    request.expected_sequence,
                    fence,
                    Some(prepared.stamp),
                )?;
                if claim.is_some_and(|(claim, announcer)| {
                    !self.lifecycle.lock().orphans.is_current(claim, announcer)
                }) {
                    return Ok(AdmitOutcome::AlreadyKnown);
                }
                let txid = request.tx.txid();
                if pool.contains_txid(&txid) {
                    self.lifecycle
                        .lock()
                        .orphans
                        .remove_transaction_variants(txid);
                    return Ok(AdmitOutcome::AlreadyKnown);
                }
                if let Some((error, scope)) = prepared.rejection {
                    if let Some(bump) = prepared.refused_bump {
                        if pool.track_refused_trim(bump).is_err() {
                            return Err(AdmitError::MempoolChanged);
                        }
                    }
                    self.record_peer_failure(pool, request, error, scope);
                    return Err(error);
                }
                let default_reject_scope = rejection_scope(&request.tx);

                // The writer consumes the already verified graph plan. It checks
                // the stamp again but never reruns the solver or script verifier.
                let ReplacementStage::Verified(plan) = prepared.replacement else {
                    return Err(AdmitError::MempoolChanged);
                };
                // Replaced bodies leave the pool in the commit below, so they
                // are captured first and retained in the same writer interval:
                // a reader never sees them gone from both pool and ring.
                let replaced: Vec<_> = plan
                    .replaced_entries(pool)
                    .map(|entry| (entry.txid, entry.wtxid, Arc::clone(&entry.tx)))
                    .collect();
                pool.commit_pool_change(plan)
                    .map(|result| {
                        self.retain_replaced(&replaced);
                        AdmitOutcome::Committed(result)
                    })
                    .map_err(|error| {
                        let error = replacement_rejection(error);
                        self.record_peer_failure(pool, request, error, default_reject_scope);
                        error
                    })
            },
            |outcome| match outcome {
                AdmitOutcome::AlreadyKnown => None,
                AdmitOutcome::Committed(result) => Some(result),
            },
        )?;
        // Only an accepted mutation fills, after the commit released the
        // pool write lock. Rejections, holds, and already-known outcomes
        // record nothing.
        if matches!(outcome, AdmitOutcome::Committed(_)) {
            if let (Some((wtxid, flags)), Some(cache)) = (cache_key, self.script_cache()) {
                cache.insert(wtxid, flags);
            }
        }
        Ok(outcome)
    }

    /// Rejects an attempt whose captured admittance facts no longer hold.
    pub(crate) fn check_admission_state(
        &self,
        pool: &Mempool,
        expected_generation: u64,
        expected_sequence: u64,
        fence: crate::admission::AdmissionFence,
        stamp: Option<crate::pool::fee_policy::PolicyStamp>,
    ) -> Result<(), AdmitError> {
        if fence.current(self) != Some(expected_generation) {
            return Err(AdmitError::GenerationChanged);
        }
        if pool.sequence_number() != expected_sequence {
            return Err(AdmitError::MempoolChanged);
        }
        if stamp.is_some_and(|stamp| !stamp.matches(pool)) {
            return Err(AdmitError::MempoolChanged);
        }
        Ok(())
    }

    /// The shared policy evaluator. Pool-dependent work ends at this boundary;
    /// the returned job owns every previous output its script checks may read.
    #[expect(
        clippy::too_many_lines,
        reason = "keep policy precedence and the captured preparation stamp in one owner"
    )]
    pub(crate) fn prepare_admission(
        pool: &Mempool,
        request: &AdmissionRequest,
        mode: AdmissionMode,
        fence: crate::admission::AdmissionFence,
        engine: ValidationEngine,
    ) -> PreparedAdmission {
        let policy = pool.policy_snapshot();
        let chain = PrevoutMap(&request.prevouts);
        let view = MempoolUtxoView::new(pool, &chain);
        let standard =
            crate::standardness::is_standard_tx(&request.tx, &policy.standardness).is_ok();
        let prevouts: Vec<_> = if standard && !pool.contains_txid(&request.tx.txid()) {
            request
                .tx
                .inputs
                .iter()
                .filter_map(|input| {
                    view.lookup(&input.previous_output)
                        .map(|output| (input.previous_output, output))
                })
                .collect()
        } else {
            Vec::new()
        };
        let mut context = request.context;
        if standard {
            context.sigop_cost =
                transaction_sigop_cost(&request.tx, &prevouts, VerifyFlags::STANDARD);
            context.vsize = context.vsize.max(crate::accounting::policy_vsize(
                &request.tx,
                context.sigop_cost,
            ));
        }
        // Core re-admits a disconnected transaction with `bypassLimits = true`
        // on `AcceptToMemoryPool` (validation.cpp), which skips the
        // `GetMinFee()` floor and the mempool size limit while ancestor
        // topology, TRUC, and ephemeral-spend checks still run. `Deferred` is
        // that bypass: the fee floor is skipped here and the per-acceptance
        // size trim downstream, with one size trim at settlement instead.
        // It derives from the chain-change fence, not the caller-declared
        // origin: `AdmissionOrigin::Reorg` is public metadata, so only a
        // submission that actually runs under `AdmissionFence::ChainChange`
        // may defer — anything else enforces in full.
        let enforcement = match (request.origin, fence) {
            (AdmissionOrigin::Reorg, crate::admission::AdmissionFence::ChainChange(_)) => {
                LimitEnforcement::Deferred
            }
            (_, crate::admission::AdmissionFence::Stable)
                if mode == AdmissionMode::SingleSubmit
                    && !matches!(request.origin, AdmissionOrigin::Reorg) =>
            {
                LimitEnforcement::ExpireBeforeTrim(request.time)
            }
            _ => LimitEnforcement::Full,
        };
        let deferred = enforcement == LimitEnforcement::Deferred;
        let floor = if deferred
            || matches!(
                mode,
                AdmissionMode::PackageSubmit | AdmissionMode::PackageRpcSubmit(_)
            ) {
            None
        } else {
            Some(pool.min_fee_sat_per_kvb(bitcoin_rs_primitives::unix_time_secs()))
        };
        // BIP68 is evaluated at the next block. A resolved input that is not
        // present in the confirmed metadata is an unconfirmed (mempool/package)
        // parent and is encoded as the next block.
        let next_height = request.height.saturating_add(1);
        let resolved_prevouts: HashSet<OutPoint> =
            request.prevouts.iter().map(|(op, _)| *op).collect();
        let finality = crate::standardness::Bip68Admission {
            csv_active: request.csv_active,
            next_height,
            next_mtp: request.locktime_cutoff,
            prevout_meta: Some(&request.prevout_meta),
            resolved_prevouts: Some(&resolved_prevouts),
        };
        let fact = crate::standardness::evaluate_one(
            pool,
            &policy.standardness,
            &request.tx,
            context,
            None,
            floor,
            &finality,
        );
        let rejection = fact
            .reject_reason
            .map(|reason| (AdmitError::Policy(reason), rejection_scope(&request.tx)));
        let mut prepared = PreparedAdmission {
            fact,
            prevouts,
            rejection,
            stamp: pool.policy_stamp(),
            refused_bump: None,
            replacement: ReplacementStage::Rejected,
            engine,
            script_cache_key: None,
        };
        if !pool.contains_txid(&request.tx.txid()) {
            if standard
                && bitcoin_rs_consensus::verify_tx::verify_transaction_input_outpoints(&request.tx)
                    .is_err()
            {
                prepared.reject(AdmitError::Consensus, RejectScope::Transaction);
            } else if crate::admission::has_invalid_mempool_outpoint(pool, &request.tx) {
                prepared.reject(
                    AdmitError::Policy(crate::standardness::AcceptanceRejectReason::MissingInputs),
                    RejectScope::Transaction,
                );
            }
        }
        if matches!(
            mode,
            AdmissionMode::PackageTest
                | AdmissionMode::PackageSubmit
                | AdmissionMode::PackageRpcSubmit(_)
        ) {
            // Package previews and native submissions forbid replacement;
            // an already resident tx retains its duplicate result here.
            if !pool.contains_txid(&request.tx.txid())
                && !pool.conflicts_for(&request.tx).is_empty()
            {
                prepared.reject(
                    AdmitError::Policy(
                        crate::standardness::AcceptanceRejectReason::MempoolConflict,
                    ),
                    rejection_scope(&request.tx),
                );
            }
            if prepared.rejection.is_none() {
                match pool.truc_conflicts(&request.tx, prepared.fact.vsize, false) {
                    Ok(_) => prepared.replacement = ReplacementStage::Package,
                    Err(error) => {
                        prepared.reject(replacement_rejection(error), rejection_scope(&request.tx));
                    }
                }
            }
        } else if prepared.rejection.is_none() {
            let fee_estimation = crate::rbf::FeeEstimation::from_origin(&request.origin);
            // Core's `bypassLimits` re-acceptance still runs
            // `SingleTRUCChecks` (validation.cpp): the pool the disconnect
            // changed decides the topology now, so the TRUC conflict walk —
            // which also returns the direct conflicts the BIP125 fee rules
            // need — applies under Deferred exactly as under Full.
            let conflict_set = pool.truc_conflicts(&request.tx, prepared.fact.vsize, true);
            let captured = conflict_set.and_then(|(conflicts, sibling_eviction)| {
                let entry = MempoolEntry::new(
                    Arc::clone(&request.tx),
                    prepared.fact.vsize,
                    prepared.fact.base_fee.unwrap_or(0),
                    request.time,
                    request.height,
                    prepared.fact.sigop_cost,
                );
                if conflicts.is_empty() {
                    pool.capture_insertion(entry, fee_estimation, enforcement)
                } else {
                    pool.capture_admission(
                        entry,
                        conflicts,
                        policy.incremental_relay_fee_sat_per_kvb,
                        sibling_eviction,
                        fee_estimation,
                        enforcement,
                    )
                }
            });
            match captured {
                Ok(inputs) => prepared.replacement = ReplacementStage::Captured(inputs),
                Err(error) => {
                    prepared.reject(replacement_rejection(error), rejection_scope(&request.tx));
                }
            }
            if prepared.rejection.is_none()
                && crate::package::missing_ephemeral_spends(
                    pool,
                    core::slice::from_ref(request.tx.as_ref()),
                    policy.standardness.dust_relay_fee,
                )
                .is_some()
            {
                prepared.reject(
                    AdmitError::Policy(
                        crate::standardness::AcceptanceRejectReason::MissingEphemeralSpends,
                    ),
                    rejection_scope(&request.tx),
                );
            }
        }
        prepared
    }

    /// Removes resident entries the current chain no longer supports after a
    /// disconnect: an input that is neither a live coin nor a resident parent,
    /// an immature coinbase input, or locktime/BIP68 no longer final at the
    /// next block. Descendants leave with `RemovalReason::Reorg`.
    pub fn remove_for_reorg(
        &self,
        change: &ChainChangeGuard,
        chain: &dyn crate::admission::AdmissionChain,
    ) -> Result<MutationResult, ChainChangeError> {
        if !change.owns(self) {
            return Err(ChainChangeError::ForeignGuard);
        }
        let residents: Vec<Arc<Tx>> = {
            let pool = self.pool.read();
            pool.iter_entries()
                .map(|entry| Arc::clone(&entry.tx))
                .collect()
        };
        let mut failing = Vec::new();
        for tx in residents {
            let Some(snapshot) = chain.snapshot(&tx) else {
                continue;
            };
            let next_height = snapshot.height.saturating_add(1);
            let fails = {
                let pool = self.pool.read();
                let missing_input = tx.inputs.iter().any(|input| {
                    !pool.contains_txid(&input.previous_output.txid)
                        && !snapshot
                            .prevouts
                            .iter()
                            .any(|(outpoint, _)| *outpoint == input.previous_output)
                });
                let nonfinal = !bitcoin_rs_consensus::verify_tx::is_final_tx(
                    &tx,
                    next_height,
                    snapshot.locktime_cutoff,
                );
                let immature = tx.inputs.iter().any(|input| {
                    snapshot
                        .prevout_meta
                        .get(&input.previous_output)
                        .is_some_and(|meta| {
                            bitcoin_rs_consensus::check_coinbase_maturity(
                                meta.coinbase,
                                meta.height,
                                next_height,
                            )
                            .is_err()
                        })
                });
                let bip68 = !crate::standardness::bip68_final(
                    &pool,
                    &tx,
                    &crate::standardness::Bip68Admission {
                        csv_active: snapshot.csv_active,
                        next_height,
                        next_mtp: snapshot.locktime_cutoff,
                        prevout_meta: Some(&snapshot.prevout_meta),
                        resolved_prevouts: None,
                    },
                );
                missing_input || nonfinal || immature || bip68
            };
            if fails {
                failing.push(tx.txid());
            }
        }
        self.commit(
            AdmissionOrigin::Reorg,
            |pool| {
                let fence = crate::admission::AdmissionFence::ChainChange(change.odd_generation());
                if fence.current(self) != Some(change.odd_generation()) {
                    return Err(ChainChangeError::GenerationMoved);
                }
                Ok(pool.remove_for_reorg(&failing))
            },
            |result| Some(result),
        )
    }

    /// Commits `pool.remove_for_block` and publishes its result. `now` stamps
    /// the rolling floor for decay, even when the block removes nothing.
    pub fn remove_for_block(
        &self,
        origin: AdmissionOrigin,
        block_txs: &[&Tx],
        block_txids: &[Txid],
        height: u32,
        now: u64,
    ) -> MutationResult {
        self.commit_infallible(origin, |pool| {
            pool.remove_for_block(block_txs, block_txids, height, now)
        })
    }

    /// Commits `pool.expire` when the acceptance-time index shows stale
    /// entries, and publishes its result. Returns `None` without taking the
    /// write lock when nothing is stale.
    pub fn expire(&self, origin: AdmissionOrigin, now: u64) -> Option<MutationResult> {
        if !self.pool.read().has_expired_entries(now) {
            return None;
        }
        Some(self.commit_infallible(origin, |pool| pool.expire(now)))
    }

    /// Commits `pool.evict_below_fee_rate` and publishes its result.
    ///
    /// Test seam: fee-history fixture door; production trimming runs through
    /// `enforce_size_limit`'s chunk-ordered eviction.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn evict_below_fee_rate(
        &self,
        origin: AdmissionOrigin,
        threshold_sat_per_kvb: u64,
    ) -> MutationResult {
        self.commit_infallible(origin, |pool| {
            pool.evict_below_fee_rate(threshold_sat_per_kvb)
        })
    }

    /// The configured total-size ceiling of the underlying pool, in vbytes.
    #[must_use]
    pub fn max_total_bytes(&self) -> u64 {
        self.pool.read().limits.max_total_bytes
    }

    /// Commits `pool.enforce_size_limit` and publishes its result.
    pub fn enforce_size_limit(
        &self,
        origin: AdmissionOrigin,
        max_bytes: u64,
    ) -> Result<MutationResult, MempoolError> {
        let inputs = self.pool.read().capture_eviction(max_bytes)?;
        let plan = inputs.verify();
        self.commit(
            origin,
            move |pool| {
                pool.commit_pool_change(plan)
                    .map_err(RbfError::into_pool_error)
            },
            |result| Some(result),
        )
    }

    /// Commits `pool.clear` and publishes its result.
    ///
    /// Test seam: wholesale fixture reset without a chain-change reservation.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn clear(&self, origin: AdmissionOrigin) -> MutationResult {
        self.commit_infallible(origin, Mempool::clear)
    }

    /// Commits `pool.prioritise`. Never publishes: prioritisation emits no
    /// mutation change, so there is nothing to order.
    pub fn prioritise(&self, txid: Txid, fee_delta: i64) -> Result<(), PrioritiseError> {
        let mut pool = self.pool.write();
        self.apply_prioritise(&mut pool, txid, fee_delta)
    }

    /// A successful P2P getdata response completes initial broadcast of this
    /// exact witness body. Membership and its public sequence do not change.
    pub fn mark_broadcast(&self, wtxid: bitcoin_rs_primitives::Wtxid) {
        self.pool.write().set_unbroadcast(wtxid, false);
    }

    pub(crate) fn restore_unbroadcast(&self, wtxid: bitcoin_rs_primitives::Wtxid) {
        self.pool.write().set_unbroadcast(wtxid, true);
    }

    /// Atomically rejects pooled dust before applying a fee overlay.
    pub fn prioritise_if_not_dust(
        &self,
        txid: Txid,
        fee_delta: i64,
        dust_relay_fee: u64,
    ) -> Result<bool, PrioritiseError> {
        let mut pool = self.pool.write();
        if let Some(entry) = pool.entry_by_txid(&txid)
            && crate::standardness::tx_has_dust_outputs(&entry.tx, dust_relay_fee)
        {
            return Ok(false);
        }
        self.apply_prioritise(&mut pool, txid, fee_delta)?;
        Ok(true)
    }

    /// Applies the overlay and clears peer-reject evidence the new fee
    /// ordering may have invalidated.
    fn apply_prioritise(
        &self,
        pool: &mut Mempool,
        txid: Txid,
        fee_delta: i64,
    ) -> Result<(), PrioritiseError> {
        pool.prioritise(txid, fee_delta)?;
        if fee_delta != 0 {
            self.lifecycle.lock().clear_rejects();
        }
        Ok(())
    }

    /// Reads the stored fee-delta overlay map.
    #[must_use]
    pub fn prioritised_transactions(&self) -> Vec<PrioritisedTransaction> {
        self.read().prioritised_transactions()
    }

    /// The single commit-and-publish path every publishing mutation flows
    /// through. A failed `mutate` returns before the publish mutex is taken
    /// and means nothing was committed. A successful mutation publishes
    /// every accepted/removed change from its prevalidated plan.
    /// Successful mutations acquire the publish mutex before releasing the
    /// pool guard, then call observers only after releasing the pool guard.
    pub(crate) fn commit<T, E>(
        &self,
        origin: AdmissionOrigin,
        mutate: impl FnOnce(&mut Mempool) -> Result<T, E>,
        mutation: impl FnOnce(&T) -> Option<&MutationResult>,
    ) -> Result<T, E> {
        // Registration-time fact, read before the pool write lock: no
        // observer code runs here or under the write lock below. Linearizable
        // capture at this load decides one commit's retention; a leg that
        // attaches concurrently takes effect on a later commit.
        let bodies_wanted = self
            .observer
            .as_ref()
            .is_some_and(|observer| observer.wants_bodies());
        // Linearizable commit-to-enqueue: held from the pool mutation through
        // the publish enqueue so the queue order is the commit order even
        // though the join no longer runs under the pool write lock. Dropped
        // before the drain so observer re-entry never blocks on it.
        let order = self.commit_order.lock();
        let mut elected = false;
        // Publication decided under the write lock; the index/body join below
        // runs after the pool guard drops so large packages do not burn
        // admission-lock time on a quadratic scan.
        let mut pending = None;
        let outcome = {
            let mut pool = self.pool.write();
            pool.accepted_capture = bodies_wanted.then(Vec::new);
            let outcome = mutate(&mut pool);
            let captured = pool.accepted_capture.take().unwrap_or_default();
            let outcome = outcome?;
            if let Some(result) = mutation(&outcome) {
                if matches!(origin, AdmissionOrigin::Rpc | AdmissionOrigin::Esplora) {
                    for change in &result.changes {
                        if matches!(change.outcome, crate::MutationOutcome::Accepted)
                            && let Some(wtxid) = pool
                                .entry_by_txid(&Txid(change.txid))
                                .map(|entry| entry.wtxid)
                        {
                            pool.set_unbroadcast(wtxid, true);
                        }
                    }
                }
                self.update_admission_lifecycle(&pool, result);
                if !result.changes.is_empty() && self.observer.is_some() {
                    pending = Some((result.clone(), captured));
                }
            }
            outcome
        };
        if let Some((result, captured)) = pending {
            let transactions = Self::join_accepted_bodies(&result, captured, bodies_wanted);
            let mut publish = self.publish.lock();
            publish.queue.push_back(MutationEnvelope {
                origin,
                result,
                accepted_transactions: transactions,
            });
            elected = !publish.draining;
            publish.draining = true;
        }
        drop(order);
        if elected {
            self.drain();
        }
        Ok(outcome)
    }

    /// Joins committed `Accepted` changes to their captured bodies.
    ///
    /// Capture runs under the pool write lock so bodies match the commit; the
    /// index/body join itself needs no pool state and runs after the guard
    /// drops. A missing body with capture enabled means an accept path
    /// bypassed the capture and is logged instead of silently dropped;
    /// without capture the envelope simply carries no bodies.
    fn join_accepted_bodies(
        result: &MutationResult,
        captured: Vec<(Txid, Arc<Tx>)>,
        bodies_wanted: bool,
    ) -> Vec<(usize, Arc<Tx>)> {
        let mut bodies = HashMap::with_capacity(captured.len());
        for (txid, body) in captured {
            bodies.insert(txid, body);
        }
        result
            .changes
            .iter()
            .enumerate()
            .filter_map(|(index, change)| {
                if !matches!(change.outcome, crate::MutationOutcome::Accepted) {
                    return None;
                }
                let Some(body) = bodies.remove(&Txid(change.txid)) else {
                    if bodies_wanted {
                        tracing::warn!(
                            txid = ?change.txid,
                            "accepted transaction has no captured body; envelope omits it",
                        );
                    }
                    debug_assert!(
                        !bodies_wanted,
                        "capture was enabled but an Accepted change has no body",
                    );
                    return None;
                };
                Some((index, body))
            })
            .collect()
    }

    /// Finalizes peer-only holding/rejection while the exact admission state
    /// remains locked. Thus a parent commit or chain reset cannot pass between
    /// the verdict and registration of its lifecycle consequences.
    fn record_peer_failure(
        &self,
        pool: &Mempool,
        request: &AdmissionRequest,
        error: AdmitError,
        scope: RejectScope,
    ) {
        let AdmissionOrigin::Peer(source) = request.origin else {
            return;
        };
        let hold = error
            == AdmitError::Policy(crate::standardness::AcceptanceRejectReason::MissingInputs)
            && crate::admission::can_hold_orphan(
                pool,
                &request.tx,
                &pool.policy_snapshot().standardness,
            );
        let mut lifecycle = self.lifecycle.lock();
        if hold {
            lifecycle
                .orphans
                .insert(Arc::clone(&request.tx), source, request.time);
            self.retain_for_reconstruction(&request.tx);
        } else {
            lifecycle.reject(&request.tx, scope);
            if retains_rejected_body(pool, &request.tx, error) {
                self.retain_for_reconstruction(&request.tx);
            }
        }
    }

    /// Hands each individually refused member of a refused package, in package
    /// (dependency) order, to the peer lifecycle exactly as a refused single
    /// transaction would be. Members with no individual refusal, such as those
    /// caught only by an aggregate fee, topology or cluster check, are not
    /// recorded. `requests` and `prepared` are the same-length batch the
    /// refusal was decided on, and a non-peer origin records nothing. PRE: the
    /// caller holds the pool write lock with the stamped state revalidated.
    pub(crate) fn record_peer_package_refusal(
        &self,
        pool: &Mempool,
        requests: &[AdmissionRequest],
        prepared: &[PreparedAdmission],
    ) {
        for (request, job) in requests.iter().zip(prepared) {
            if let Some((error, scope)) = job.rejection {
                self.record_peer_failure(pool, request, error, scope);
            }
        }
    }

    /// Retains `tx` in the reconstruction ring. PRE: the caller holds the pool
    /// write lock, which is what makes the ring consistent with the pool.
    fn retain_for_reconstruction(&self, tx: &Arc<Tx>) {
        let (txid, wtxid) = (tx.txid(), tx.wtxid());
        self.extra_txn.lock().insert(txid, wtxid, tx);
    }

    /// Retains the bodies one committed replacement removed, with the
    /// identities the pool already computed. PRE: the caller holds the pool
    /// write lock.
    fn retain_replaced(&self, replaced: &[(Txid, Wtxid, Arc<Tx>)]) {
        if replaced.is_empty() {
            return;
        }
        let mut ring = self.extra_txn.lock();
        for (txid, wtxid, tx) in replaced {
            ring.insert(*txid, *wtxid, tx);
        }
    }

    /// Invokes `f` for every transaction a BIP152 reconstruction may match:
    /// each pool entry, then each retained extra not already in the pool.
    ///
    /// Hint-only: the extras are never admitted, relayed, served as inventory,
    /// or visible to [`Self::get_tx`], [`Self::get_tx_by_wtxid`] or
    /// [`Self::have_tx`]. Pool read guard, then the ring's leaf lock, are held
    /// across `f`, so `f` must not call back into this gateway; fetch bodies
    /// with [`Self::reconstruction_tx_by_txid`] or
    /// [`Self::reconstruction_tx_by_wtxid`] after the walk returns. The orphan
    /// lock is never taken.
    pub fn for_each_reconstruction_identity(&self, mut f: impl FnMut(Txid, Wtxid)) {
        let pool = self.pool.read();
        for entry in pool.iter_entries() {
            f(entry.txid, entry.wtxid);
        }
        let ring = self.extra_txn.lock();
        for held in &ring.entries {
            if !pool.contains_wtxid(&held.wtxid) {
                f(held.txid, held.wtxid);
            }
        }
    }

    /// The pool body for `txid`, else a retained reconstruction extra. Hint
    /// use only; see [`Self::for_each_reconstruction_identity`].
    #[must_use]
    pub fn reconstruction_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
        let pool = self.pool.read();
        if let Some(tx) = pool.transaction_by_txid(&txid) {
            return Some((*tx).clone());
        }
        self.extra_txn.lock().by_txid(txid).map(|tx| (**tx).clone())
    }

    /// The pool body for `wtxid`, else a retained reconstruction extra. Hint
    /// use only; see [`Self::for_each_reconstruction_identity`].
    #[must_use]
    pub fn reconstruction_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        let pool = self.pool.read();
        if let Some(entry) = pool.entry_by_wtxid(&wtxid) {
            return Some((*entry.tx).clone());
        }
        self.extra_txn
            .lock()
            .by_wtxid(wtxid)
            .map(|tx| (**tx).clone())
    }

    /// Required internal lifecycle work is independent of fallible observers.
    /// A ready marker authorizes re-preparation only, never admission itself.
    fn update_admission_lifecycle(&self, pool: &Mempool, result: &MutationResult) {
        if result.changes.is_empty() {
            return;
        }
        let mut lifecycle = self.lifecycle.lock();
        for change in &result.changes {
            if matches!(change.outcome, crate::mutation::MutationOutcome::Accepted) {
                let txid = Txid::from(change.txid);
                lifecycle.orphans.remove_transaction_variants(txid);
                if pool.contains_txid(&txid) {
                    lifecycle.orphans.parent_ready(txid);
                }
            }
        }
    }

    /// The same path for pool methods that cannot fail.
    fn commit_infallible(
        &self,
        origin: AdmissionOrigin,
        mutate: impl FnOnce(&mut Mempool) -> MutationResult,
    ) -> MutationResult {
        let Ok(result) = self.commit(
            origin,
            |pool| Ok::<_, core::convert::Infallible>(mutate(pool)),
            |result| Some(result),
        );
        result
    }

    /// Publishes queued batches until the queue is empty, then returns
    /// the publish state to idle. Exactly one drainer runs at a time: the
    /// election in [`Self::commit`] is the only place `draining` turns
    /// true, and the idle transition happens under the same mutex only
    /// when the queue is empty, so no enqueue is lost. No gateway lock is
    /// held across an observer call: a nested or concurrent mutation
    /// commits, enqueues, and returns while this loop runs. A panicking
    /// observer is contained per batch — the mutation already committed,
    /// and the panic must not take the caller down with it. The default
    /// panic hook still prints the panic before it is caught here.
    fn drain(&self) {
        loop {
            let envelope = {
                let mut publish = self.publish.lock();
                if let Some(envelope) = publish.queue.pop_front() {
                    envelope
                } else {
                    publish.draining = false;
                    return;
                }
            };
            let Some(observer) = self.observer.as_ref() else {
                continue;
            };
            let outcome = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
                observer.on_mutation(&envelope);
            }));
            if let Err(panic_payload) = outcome {
                let (message, payload_disposal_panicked) = panic_message_and_dispose(panic_payload);
                tracing::warn!(
                    message = %message,
                    payload_disposal_panicked,
                    "mempool observer panicked; the committed mutation stands"
                );
            }
        }
    }

    /// Cross-crate test seam: stores `value` into `chain_generation` with
    /// `Release` ordering, simulating an external generation move between
    /// reservation and settlement so `ChainChangeGuard::finish` fails its
    /// compare-exchange. No production caller.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn force_chain_generation(&self, value: u64) {
        self.chain_generation.store(value, Ordering::Release);
    }
}

/// Owns an active chain-change reservation: the exact odd generation and the
/// reserved next even value.
///
/// No `Drop` path reopens admission: early return or unwinding leaves the
/// gateway odd. Only a successful [`Self::finish`] restores the reserved even
/// generation; a failed finish does not release the reservation.
/// One guard covers one coherent connect, disconnect, apply window, or reorg.
#[derive(Debug)]
pub struct ChainChangeGuard {
    gateway: Arc<MempoolGateway>,
    odd: u64,
    even: u64,
}

impl ChainChangeGuard {
    /// Returns the exact odd generation this guard reserved.
    #[must_use]
    pub(crate) fn odd_generation(&self) -> u64 {
        self.odd
    }

    /// Returns the reserved even value `finish` will store on success.
    #[cfg(test)]
    #[must_use]
    fn reserved_even(&self) -> u64 {
        self.even
    }

    /// Whether this guard was issued by `gateway` itself.
    pub(crate) fn owns(&self, gateway: &MempoolGateway) -> bool {
        core::ptr::eq(Arc::as_ptr(&self.gateway), gateway)
    }

    /// Compare-exchanges the exact odd value to the reserved even value.
    pub fn finish(self) -> Result<(), ChainChangeError> {
        let prev = self.gateway.chain_generation.compare_exchange(
            self.odd,
            self.even,
            Ordering::Release,
            Ordering::Relaxed,
        );
        if prev.is_ok() {
            Ok(())
        } else {
            Err(ChainChangeError::GenerationMoved)
        }
    }
}

/// Test-only causal gate after admission verification, before writer recheck.
#[cfg(any(test, feature = "test-seam"))]
mod ordering_gate {
    use parking_lot::Mutex;
    use std::sync::mpsc::{Receiver, Sender};

    struct Gate {
        armed: Option<(usize, Sender<()>, Receiver<()>)>,
    }

    static GATE: Mutex<Gate> = Mutex::new(Gate { armed: None });

    /// Arms the gate with the test's signaling channels.
    pub(super) fn arm(target: usize, parked_tx: Sender<()>, release_rx: Receiver<()>) {
        let mut gate = GATE.lock();
        assert!(gate.armed.is_none(), "ordering gate armed twice");
        gate.armed = Some((target, parked_tx, release_rx));
    }

    /// Restores the disarmed state; called by tests that may have failed
    /// between arming and the one-shot park.
    pub(super) fn reset() {
        GATE.lock().armed = None;
    }

    pub(super) fn park_if_armed(target: usize) {
        let Some((parked_tx, release_rx)) = ({
            let mut gate = GATE.lock();
            match gate.armed.take() {
                Some((armed_target, parked_tx, release_rx)) if armed_target == target => {
                    Some((parked_tx, release_rx))
                }
                Some(armed) => {
                    gate.armed = Some(armed);
                    None
                }
                None => None,
            }
        }) else {
            return;
        };
        let _ = parked_tx.send(());
        let _ = release_rx.recv();
    }
}

/// Cross-crate test seam: arms the admission park gate so the next
/// `admit_transaction` on the gateway at `target` blocks before the write
/// lock, signalling `parked_tx` and waiting on `release_rx`.
#[cfg(any(test, feature = "test-seam"))]
pub fn arm_admission_park(
    target: usize,
    parked_tx: std::sync::mpsc::Sender<()>,
    release_rx: std::sync::mpsc::Receiver<()>,
) {
    ordering_gate::arm(target, parked_tx, release_rx);
}

/// Cross-crate test seam: disarms the admission park gate.
#[cfg(any(test, feature = "test-seam"))]
pub fn reset_admission_park() {
    ordering_gate::reset();
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
