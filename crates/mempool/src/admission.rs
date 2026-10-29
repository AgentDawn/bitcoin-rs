//! Shared preparation and bounded admission retry for RPC and peer producers.
//!
//! Chain facts are collected without gateway locks. The existing atomic gateway
//! operation validates exact generation/sequence tokens before either a pool
//! commit or a peer orphan/reject transition.

use alloc::{sync::Arc, vec::Vec};
#[cfg(test)]
use bitcoin_rs_primitives::unix_time_secs;
use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxOut, Txid, Wtxid};
use hashbrown::{HashMap, HashSet};

use crate::standardness::{AcceptanceRejectReason, StandardnessPolicy, is_standard_tx};
use crate::{
    AdmissionOrigin, AdmissionRequest, AdmitError, AdmitOutcome, LocalOrigin, MempoolGateway,
    MutationResult, PeerToken,
};

pub(crate) const MAX_ADMISSION_RETRIES: usize = 4;

/// Which chain-generation a submission attempt must observe.
/// Ordinary attempts require a stable even generation; re-admission uses the
/// guard's reserved odd generation. Both compare the same live generation.
#[derive(Clone, Copy)]
pub(crate) enum AdmissionFence {
    /// The even value returned by `stable_generation`.
    Stable,
    /// The exact odd value held by an active `ChainChangeGuard`.
    ChainChange(u64),
}

impl AdmissionFence {
    /// The generation this fence currently admits under, or `None` when
    /// the chain moved (odd fence mismatched, or stable fence saw odd).
    pub(crate) fn current(self, gateway: &MempoolGateway) -> Option<u64> {
        match self {
            Self::Stable => gateway.stable_generation(),
            Self::ChainChange(odd) => (gateway.chain_generation() == odd).then_some(odd),
        }
    }
}

/// Provisional applied-chain facts collected during one submission attempt.
/// Height and MTP identify one sampled applied tip.
/// The gateway must revalidate the captured generation before using these facts.
#[derive(Clone, Debug, Default)]
pub struct ChainAdmissionSnapshot {
    /// Confirmed input outputs; unavailable inputs are absent.
    pub prevouts: Vec<(OutPoint, TxOut)>,
    /// Per-confirmed-output chain metadata needed for BIP68 and coinbase
    /// maturity checks. Pool parents are not included here.
    pub prevout_meta: HashMap<OutPoint, PrevoutMeta>,
    /// Applied tip height; finality is checked at the next height.
    pub height: u32,
    /// Applied tip's median time past (zero before genesis).
    pub locktime_cutoff: u32,
    /// Whether CSV (BIP68/112/113) is active for the next block.
    pub csv_active: bool,
    /// Script flags the next block will verify under, derived from the tip's
    /// softfork state. The gateway re-verifies an admitted transaction under
    /// these flags to fill the script-execution cache.
    pub next_block_script_flags: bitcoin_rs_script::VerifyFlags,
    /// Positive live-coin evidence used for peer duplicate suppression and
    /// native package deduplication. RPC cache membership is not admission.
    pub confirmed: bool,
}

/// Chain-origin metadata for one confirmed input.
///
/// Used to evaluate BIP68 relative locks and coinbase maturity at admission.
/// The `MTP` value is the median-time-past of the block *before* the one that
/// created the output, matching `bip68_prevout_mtp` in the block-connect path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrevoutMeta {
    /// Height the spent output was created at.
    pub height: u32,
    /// Median-time-past of the block before the one at `height`.
    pub mtp: u32,
    /// Whether the spent output came from a coinbase transaction.
    pub coinbase: bool,
}

/// Narrow chain read capability.
///
/// Read fresh applied-tip facts without pool or lifecycle locks on each attempt.
/// Height and MTP must identify one sampled applied tip.
/// The chain owner brackets fact-changing mutations with a gateway chain-change
/// reservation. The gateway revalidates the generation and pool sequence;
/// snapshots may overlap transitions. `None` means facts are unavailable.
pub trait AdmissionChain: Send + Sync {
    /// Reads the chain inputs and applied-tip context needed by `tx`.
    fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot>;
}

/// Surface-independent outcome. Peer-only holding is not a mempool mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmitOutcome {
    /// Atomic admission committed these ordered changes.
    Committed(MutationResult),
    /// Current mempool membership, or a suppressed recent peer rejection.
    AlreadyKnown,
    /// A peer transaction was already confirmed.
    AlreadyConfirmed,
    /// A standard peer transaction is missing inputs. Its body is retained
    /// subject to the orphan quota; P2P owns requesting these parent txids.
    Held {
        /// Missing parent transaction identifiers, without duplicates.
        missing_parents: Vec<Txid>,
    },
}

/// Failure after the common preparation/retry operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubmitError {
    /// Policy refused the transaction.
    #[error(transparent)]
    Policy(#[from] AcceptanceRejectReason),
    /// Consensus or policy script verification refused the transaction.
    #[error("consensus-verification-failed")]
    Consensus,
    /// Every attempt observed changing or unavailable state.
    #[error("admission retry exhausted: chain or mempool changed during submission")]
    RetryExhausted,
}

/// One resident orphan's bounded retry result and the announcer selected for
/// that retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanRetry {
    /// Transaction identifier for relay.
    pub txid: Txid,
    /// Witness identifier of the exact body offered for re-admission.
    pub wtxid: Wtxid,
    /// The announcer this retry was submitted as; never a socket or
    /// connection handle. Other announcers of the same body stay recorded.
    pub source: PeerToken,
    /// The same result a fresh submission receives.
    pub result: Result<SubmitOutcome, SubmitError>,
}

pub(crate) fn can_hold_orphan(pool: &crate::Mempool, tx: &Tx, policy: &StandardnessPolicy) -> bool {
    !has_unspendable_input(pool, tx) && is_standard_tx(tx, policy).is_ok()
}

/// A null input or an output index no known parent can ever supply: no
/// parent arrival can repair it, so no block can carry the transaction.
pub(crate) fn has_unspendable_input(pool: &crate::Mempool, tx: &Tx) -> bool {
    tx.inputs
        .iter()
        .any(|input| input.previous_output.is_null())
        || has_invalid_mempool_outpoint(pool, tx)
}

/// A known parent cannot later acquire an output without changing its txid.
pub(crate) fn has_invalid_mempool_outpoint(pool: &crate::Mempool, tx: &Tx) -> bool {
    tx.inputs.iter().any(|input| {
        let outpoint = input.previous_output;
        pool.transaction_by_txid(&outpoint.txid)
            .is_some_and(|parent| {
                usize::try_from(outpoint.vout)
                    .ok()
                    .and_then(|index| parent.outputs.get(index))
                    .is_none()
            })
    })
}

pub(crate) fn resolve_mempool_inputs(
    pool: &crate::Mempool,
    tx: &Tx,
) -> Option<HashMap<OutPoint, TxOut>> {
    let mut prevouts = HashMap::new();
    for input in &tx.inputs {
        let outpoint = input.previous_output;
        if outpoint.is_null() {
            continue;
        }
        if let Some(parent) = pool.transaction_by_txid(&outpoint.txid) {
            let output = parent.outputs.get(usize::try_from(outpoint.vout).ok()?)?;
            prevouts.insert(outpoint, output.clone());
        }
    }
    Some(prevouts)
}

fn combine_input_facts(
    tx: &Tx,
    mempool_prevouts: &HashMap<OutPoint, TxOut>,
    confirmed: &HashMap<OutPoint, TxOut>,
) -> (Vec<(OutPoint, TxOut)>, Vec<Txid>) {
    let mut prevouts = Vec::with_capacity(tx.inputs.len());
    let mut missing_parents = Vec::new();
    let mut seen_missing = HashSet::new();
    for input in &tx.inputs {
        let outpoint = input.previous_output;
        if outpoint.is_null() {
            continue;
        }
        if let Some(output) = mempool_prevouts
            .get(&outpoint)
            .or_else(|| confirmed.get(&outpoint))
        {
            prevouts.push((outpoint, output.clone()));
        } else if seen_missing.insert(outpoint.txid) {
            missing_parents.push(outpoint.txid);
        }
    }
    (prevouts, missing_parents)
}

/// Builds the one admission request for an attempt from the resolved chain
/// facts, returning it with the txids of still-missing parents. Without
/// chain facts, the empty/missing context and zero tip fields cannot
/// authorize a commit: the gate checks the same generation and sequence
/// first, then rejects the still-known invalid outpoint before policy or
/// finality. Changed tokens rebuild a normal attempt, including chain
/// lookup if the parent disappeared.
fn build_admission_request(
    tx: Arc<Tx>,
    mempool_prevouts: Option<HashMap<OutPoint, TxOut>>,
    snapshot: Option<ChainAdmissionSnapshot>,
    max_feerate_sat_per_kvb: Option<u64>,
    time: u64,
    origin: AdmissionOrigin,
    generation: u64,
    sequence: u64,
) -> (AdmissionRequest, Vec<Txid>) {
    let (confirmed, height, locktime_cutoff, prevout_meta, csv_active, next_block_script_flags) =
        snapshot.map_or_else(
            || {
                (
                    HashMap::new(),
                    0,
                    0,
                    HashMap::new(),
                    false,
                    bitcoin_rs_script::VerifyFlags::NONE,
                )
            },
            |snapshot| {
                (
                    snapshot.prevouts.into_iter().collect::<HashMap<_, _>>(),
                    snapshot.height,
                    snapshot.locktime_cutoff,
                    snapshot.prevout_meta,
                    snapshot.csv_active,
                    snapshot.next_block_script_flags,
                )
            },
        );
    let mempool_prevouts = mempool_prevouts.unwrap_or_default();
    let (prevouts, missing_parents) = combine_input_facts(&tx, &mempool_prevouts, &confirmed);
    let missing_inputs = prevouts.len() != tx.inputs.len();
    let context = crate::accounting::prepared_context(&tx, &prevouts, missing_inputs);
    let request = AdmissionRequest {
        tx,
        context,
        prevouts,
        prevout_meta,
        csv_active,
        next_block_script_flags,
        locktime_cutoff,
        max_feerate_sat_per_kvb,
        time,
        height,
        origin,
        expected_generation: generation,
        expected_sequence: sequence,
    };
    (request, missing_parents)
}

pub(crate) fn batch_requests(
    txs: &[Tx],
    mempool_inputs: Vec<Option<HashMap<OutPoint, TxOut>>>,
    chain: &dyn AdmissionChain,
    max_feerate_sat_per_kvb: Option<u64>,
    time: u64,
    origin: AdmissionOrigin,
    (generation, sequence): (u64, u64),
    mode: crate::gateway::AdmissionMode,
) -> Option<Vec<AdmissionRequest>> {
    let mut package_outputs = HashMap::new();
    let mut requests = Vec::with_capacity(txs.len());
    for (tx, mempool_inputs) in txs.iter().zip(mempool_inputs) {
        let snapshot = if mempool_inputs.is_some() {
            chain.snapshot(tx)?
        } else {
            ChainAdmissionSnapshot::default()
        };
        if mode == crate::gateway::AdmissionMode::PackageSubmit && snapshot.confirmed {
            continue;
        }
        let mut available = snapshot.prevouts.into_iter().collect::<HashMap<_, _>>();
        available.extend(mempool_inputs.unwrap_or_default());
        available.extend(
            package_outputs
                .iter()
                .map(|(outpoint, output): (&OutPoint, &TxOut)| (*outpoint, output.clone())),
        );
        let (prevouts, _) = combine_input_facts(tx, &available, &HashMap::new());
        let context =
            crate::accounting::prepared_context(tx, &prevouts, prevouts.len() != tx.inputs.len());
        requests.push(AdmissionRequest {
            tx: Arc::new(tx.clone()),
            context,
            prevouts,
            prevout_meta: snapshot.prevout_meta,
            csv_active: snapshot.csv_active,
            next_block_script_flags: snapshot.next_block_script_flags,
            locktime_cutoff: snapshot.locktime_cutoff,
            max_feerate_sat_per_kvb,
            time,
            height: snapshot.height,
            origin,
            expected_generation: generation,
            expected_sequence: sequence,
        });
        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            if let Ok(vout) = u32::try_from(vout) {
                package_outputs.insert(OutPoint::new(txid, vout), output.clone());
            }
        }
    }
    Some(requests)
}

impl MempoolGateway {
    /// Evaluates a bounded batch through the submission evaluator without
    /// changing membership, sequence, fee history, orphan state or observers.
    #[expect(
        clippy::too_many_lines,
        reason = "keep batch capture, verification and retry fencing in one auditable owner"
    )]
    pub fn preview_transactions(
        &self,
        txs: &[Tx],
        max_feerate_sat_per_kvb: Option<u64>,
        chain: &dyn AdmissionChain,
    ) -> Result<crate::standardness::PackageAcceptanceFacts, SubmitError> {
        use crate::gateway::AdmissionMode;
        use crate::standardness::PackageAcceptanceFacts;
        if let Err(reason) = crate::package::check_structure(txs) {
            return Ok(PackageAcceptanceFacts {
                package_error: Some(reason),
                results: if reason == AcceptanceRejectReason::PackageCount {
                    Vec::new()
                } else {
                    txs.iter().map(crate::package::unfinished).collect()
                },
            });
        }
        let mode = if txs.len() == 1 {
            AdmissionMode::Single
        } else {
            AdmissionMode::PackageTest
        };
        'attempt: for _ in 0..MAX_ADMISSION_RETRIES {
            let Some(generation) = self.stable_generation() else {
                continue;
            };
            let (sequence, stamp, mempool_inputs) = {
                let pool = self.pool.read();
                let sequence = pool.sequence_number();
                if self
                    .check_admission_state(
                        &pool,
                        generation,
                        sequence,
                        AdmissionFence::Stable,
                        None,
                    )
                    .is_err()
                {
                    continue;
                }
                let stamp = pool.policy_stamp();
                (
                    sequence,
                    stamp,
                    txs.iter()
                        .map(|tx| resolve_mempool_inputs(&pool, tx))
                        .collect::<Vec<_>>(),
                )
            };
            let Some(requests) = batch_requests(
                txs,
                mempool_inputs,
                chain,
                max_feerate_sat_per_kvb,
                0,
                AdmissionOrigin::Rpc,
                (generation, sequence),
                mode,
            ) else {
                continue 'attempt;
            };
            let (mut prepared, package_checks) = {
                let pool = self.pool.read();
                if self
                    .check_admission_state(
                        &pool,
                        generation,
                        sequence,
                        AdmissionFence::Stable,
                        Some(stamp),
                    )
                    .is_err()
                {
                    continue;
                }
                let prepared = requests
                    .iter()
                    .map(|request| {
                        Self::prepare_admission(
                            &pool,
                            request,
                            mode,
                            AdmissionFence::Stable,
                            self.engine(),
                        )
                    })
                    .collect::<Vec<_>>();
                let checks = (mode == AdmissionMode::PackageTest
                    && prepared.iter().all(|job| job.fact.reject_reason.is_none()))
                .then(|| {
                    let entries = crate::package::package_entries(&requests, &prepared);
                    crate::package::capture_package_checks(&pool, txs, &entries)
                });
                (prepared, checks)
            };
            let facts =
                crate::package::finish_preview(txs, &requests, &mut prepared, package_checks);
            let pool = self.pool.read();
            if self
                .check_admission_state(&pool, generation, sequence, AdmissionFence::Stable, None)
                .is_err()
            {
                continue;
            }
            for row in &prepared {
                if self
                    .check_admission_state(
                        &pool,
                        generation,
                        sequence,
                        AdmissionFence::Stable,
                        Some(row.stamp),
                    )
                    .is_err()
                {
                    continue 'attempt;
                }
            }
            return Ok(facts);
        }
        Err(SubmitError::RetryExhausted)
    }

    /// Prepares and submits one transaction, rebuilding all facts after a
    /// transient token mismatch. Only peer-origin failures affect relay caches.
    pub fn submit_transaction(
        &self,
        tx: Arc<Tx>,
        origin: AdmissionOrigin,
        max_feerate_sat_per_kvb: Option<u64>,
        time: u64,
        chain: &dyn AdmissionChain,
    ) -> Result<SubmitOutcome, SubmitError> {
        self.submit_transaction_claimed(
            tx,
            origin,
            max_feerate_sat_per_kvb,
            time,
            chain,
            None,
            AdmissionFence::Stable,
        )
    }

    /// Submits one locally originated transaction: RPC `sendrawtransaction`,
    /// an Esplora broadcast, or the embedded `Node::broadcast`.
    ///
    /// Runs [`Self::submit_transaction`]. Holding an orphan and reporting a
    /// confirmed transaction are peer-only outcomes, so a local submission
    /// answers current membership as success with no changes and keeps a
    /// missing input a refusal.
    ///
    /// # Errors
    ///
    /// Returns the gateway's refusal; nothing is inserted when this fails.
    pub fn submit_local_transaction(
        &self,
        tx: Arc<Tx>,
        origin: LocalOrigin,
        max_feerate_sat_per_kvb: Option<u64>,
        time: u64,
        chain: &dyn AdmissionChain,
    ) -> Result<MutationResult, SubmitError> {
        match self.submit_transaction(tx, origin.into(), max_feerate_sat_per_kvb, time, chain)? {
            SubmitOutcome::Committed(result) => Ok(result),
            SubmitOutcome::AlreadyKnown => Ok(MutationResult::empty()),
            SubmitOutcome::AlreadyConfirmed | SubmitOutcome::Held { .. } => {
                Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
            }
        }
    }

    /// Re-admits transactions displaced by disconnected blocks through the
    /// shared admission evaluator while `change` holds the chain fence.
    /// `txs` must arrive parents before children. A refused candidate, and any
    /// later candidate spending it or spending a txid an earlier commit
    /// removed, is withheld so a refused parent never leaves a partial family.
    /// A guard issued by a different gateway admits nothing and returns an
    /// empty result: the odd value alone is not authority.
    ///
    /// Every candidate is admitted with `LimitEnforcement::Deferred`,
    /// the equivalent of Core passing `bypassLimits = true` to
    /// `AcceptToMemoryPool` from its disconnect walk — derived from the held
    /// `ChainChangeGuard`, not the caller-declared origin. The mempool fee
    /// floor and the per-acceptance size trim are therefore not applied here:
    /// a disconnected transaction satisfied them on the way in, and trimming
    /// per admission would shed a parent before the child that spends it is
    /// re-admitted. Consensus and script verification, duplicate and
    /// evicted-parent rejection, ancestry accounting, the replacement fee
    /// rules, and the topology gates Core still runs under `bypassLimits` —
    /// cluster limits, TRUC, and ephemeral-spend checks — all still apply.
    ///
    /// POST: the pool may exceed its `max_total_bytes` ceiling when this
    /// returns. The caller owns the one size trim over the settled pool; see
    /// [`MempoolGateway::enforce_size_limit`] and `settle_node_reorg` in the
    /// node crate.
    pub fn reconsider_disconnected(
        &self,
        change: &crate::gateway::ChainChangeGuard,
        chain: &dyn AdmissionChain,
        time: u64,
        txs: impl IntoIterator<Item = Arc<Tx>>,
    ) -> Vec<MutationResult> {
        if !change.owns(self) {
            return Vec::new();
        }
        let fence = AdmissionFence::ChainChange(change.odd_generation());
        let mut refused: HashSet<Txid> = HashSet::new();
        let mut committed = Vec::new();
        for tx in txs {
            let txid = tx.txid();
            let spends_refused = tx
                .inputs
                .iter()
                .any(|input| refused.contains(&input.previous_output.txid));
            if spends_refused {
                refused.insert(txid);
                continue;
            }
            match self.submit_transaction_claimed(
                tx,
                AdmissionOrigin::Reorg,
                None,
                time,
                chain,
                None,
                fence,
            ) {
                Ok(SubmitOutcome::Committed(result)) => {
                    for removed in result.removed_txids() {
                        refused.insert(removed);
                    }
                    committed.push(result);
                }
                Ok(SubmitOutcome::AlreadyKnown | SubmitOutcome::AlreadyConfirmed) => {}
                Ok(SubmitOutcome::Held { .. }) | Err(_) => {
                    refused.insert(txid);
                }
            }
        }
        committed
    }

    fn submit_transaction_claimed(
        &self,
        mut tx: Arc<Tx>,
        origin: AdmissionOrigin,
        max_feerate_sat_per_kvb: Option<u64>,
        time: u64,
        chain: &dyn AdmissionChain,
        claim: Option<(&crate::orphan::HeldOrphan, &PeerToken)>,
        fence: AdmissionFence,
    ) -> Result<SubmitOutcome, SubmitError> {
        let txid = tx.txid();
        let peer = matches!(origin, AdmissionOrigin::Peer(_));
        for _ in 0..MAX_ADMISSION_RETRIES {
            let Some(generation) = fence.current(self) else {
                continue;
            };
            let (sequence, mempool_prevouts, holdable) = {
                let pool = self.pool.read();
                let sequence = pool.sequence_number();
                if self
                    .check_admission_state(&pool, generation, sequence, fence, None)
                    .is_err()
                {
                    continue;
                }
                if pool.contains_txid(&txid) {
                    return Ok(SubmitOutcome::AlreadyKnown);
                }
                if peer && self.lifecycle.lock().rejects_transaction(txid, tx.wtxid()) {
                    return Ok(SubmitOutcome::AlreadyKnown);
                }
                if claim.is_some_and(|(claim, announcer)| {
                    !self.lifecycle.lock().orphans.is_current(claim, announcer)
                }) {
                    return Ok(SubmitOutcome::AlreadyKnown);
                }
                let prevouts = resolve_mempool_inputs(&pool, &tx);
                (
                    sequence,
                    prevouts,
                    peer && can_hold_orphan(&pool, &tx, &pool.policy_snapshot().standardness),
                )
            };
            let snapshot = if mempool_prevouts.is_some() {
                let Some(snapshot) = chain.snapshot(&tx) else {
                    continue;
                };
                Some(snapshot)
            } else {
                None
            };
            if peer && snapshot.as_ref().is_some_and(|snapshot| snapshot.confirmed) {
                let pool = self.pool.read();
                if self
                    .check_admission_state(&pool, generation, sequence, fence, None)
                    .is_err()
                {
                    continue;
                }
                let mut lifecycle = self.lifecycle.lock();
                if claim.is_some_and(|(claim, announcer)| {
                    !lifecycle.orphans.is_current(claim, announcer)
                }) {
                    return Ok(SubmitOutcome::AlreadyKnown);
                }
                lifecycle.orphans.remove_transaction_variants(txid);
                return Ok(SubmitOutcome::AlreadyConfirmed);
            }
            let (request, missing_parents) = build_admission_request(
                tx,
                mempool_prevouts,
                snapshot,
                max_feerate_sat_per_kvb,
                time,
                origin,
                generation,
                sequence,
            );
            match self.admit_transaction_claimed(&request, claim, fence) {
                Ok(AdmitOutcome::Committed(result)) => {
                    self.check_admitted_residency(origin, fence, &[txid])?;
                    return Ok(SubmitOutcome::Committed(result));
                }
                Ok(AdmitOutcome::AlreadyKnown) => return Ok(SubmitOutcome::AlreadyKnown),
                Err(AdmitError::GenerationChanged | AdmitError::MempoolChanged) => {
                    tx = request.tx;
                }
                Err(AdmitError::Policy(AcceptanceRejectReason::MissingInputs)) if holdable => {
                    return Ok(SubmitOutcome::Held { missing_parents });
                }
                Err(AdmitError::Policy(reason)) => return Err(SubmitError::Policy(reason)),
                Err(AdmitError::Consensus) => return Err(SubmitError::Consensus),
            }
        }
        Err(SubmitError::RetryExhausted)
    }

    /// Reports a post-admission full refusal if an admitted member is no longer
    /// resident (e.g. removed by expiry or concurrent capacity trim). Admission plans
    /// publish acceptance before expiry in one atomic commit, with capacity
    /// computed after expiry. Reorg bypass is unchanged.
    pub(crate) fn check_admitted_residency(
        &self,
        origin: AdmissionOrigin,
        fence: AdmissionFence,
        admitted: &[Txid],
    ) -> Result<(), SubmitError> {
        let readmission = matches!(origin, AdmissionOrigin::Reorg)
            || matches!(fence, AdmissionFence::ChainChange(_));
        if readmission {
            return Ok(());
        }
        let pool = self.pool.read();
        if admitted.iter().any(|txid| !pool.contains_txid(txid)) {
            return Err(SubmitError::Policy(crate::MempoolError::Full.into()));
        }
        Ok(())
    }

    /// Processes the current bounded ready set once. Work remains resident
    /// when generation changes, and no call immediately consumes its own retry
    /// again.
    pub fn retry_orphans(&self, chain: &dyn AdmissionChain, time: u64) -> Vec<OrphanRetry> {
        let ready = {
            let _pool = self.pool.read();
            if self.stable_generation().is_none() {
                return Vec::new();
            }
            self.lifecycle.lock().orphans.take_ready()
        };
        let mut results = Vec::with_capacity(ready.len());
        for (held, announcer) in ready {
            let txid = held.tx.txid();
            let wtxid = held.tx.wtxid();
            if !self.lifecycle.lock().orphans.is_current(&held, &announcer) {
                let mut lifecycle = self.lifecycle.lock();
                if lifecycle.orphans.get(wtxid).is_some() {
                    lifecycle.orphans.mark_ready(wtxid, announcer);
                }
                continue;
            }
            let result = self.submit_transaction_claimed(
                Arc::clone(&held.tx),
                AdmissionOrigin::Peer(announcer),
                None,
                time,
                chain,
                Some((&held, &announcer)),
                AdmissionFence::Stable,
            );
            if matches!(result, Err(SubmitError::RetryExhausted)) {
                let mut lifecycle = self.lifecycle.lock();
                if lifecycle.orphans.is_current(&held, &announcer) {
                    lifecycle.orphans.mark_ready(wtxid, announcer);
                }
            }
            results.push(OrphanRetry {
                txid,
                wtxid,
                source: announcer,
                result,
            });
        }
        results
    }

    /// Applies the orphan retention policy to one snapshot of live
    /// connections.
    pub fn maintain_orphans(
        &self,
        time: u64,
        live_peers: impl IntoIterator<Item = PeerToken>,
    ) -> usize {
        let live_peers: hashbrown::HashSet<PeerToken> = live_peers.into_iter().collect();
        self.lifecycle.lock().orphans.maintain(time, &live_peers)
    }

    /// Called for committed connect/disconnect, including ones with no pool
    /// mutation. The caller keeps the chain-change generation fenced until
    /// consumers settle.
    pub fn chain_changed(&self, available_parents: &[Txid]) {
        let _pool = self.pool.read();
        let mut lifecycle = self.lifecycle.lock();
        lifecycle.clear_rejects();
        for parent in available_parents {
            lifecycle.orphans.parent_ready(*parent);
        }
    }

    /// Records a committed snapshot replacement while admission remains fenced.
    /// A snapshot can supply inputs for any resident orphan. Schedule one bounded
    /// reconsideration through the existing ready set; normal retries validate and
    /// admit only after the chain-change guard settles. This is native snapshot
    /// policy, not Bitcoin Core's reject-cache-only active-tip notification.
    pub fn snapshot_changed(&self) {
        let _pool = self.pool.read();
        let mut lifecycle = self.lifecycle.lock();
        lifecycle.clear_rejects();
        lifecycle.orphans.mark_all_ready();
    }

    /// Inventory membership includes resident orphans and recent peer rejects.
    #[must_use]
    pub fn have_tx(&self, hash: Hash256, wtxid: bool) -> bool {
        let pool = self.pool.read();
        let in_pool = if wtxid {
            pool.contains_wtxid(&Wtxid::from(hash))
        } else {
            pool.contains_txid(&Txid::from(hash))
        };
        if in_pool {
            return true;
        }
        let lifecycle = self.lifecycle.lock();
        lifecycle.rejects_inventory(hash, wtxid)
            || (wtxid && lifecycle.orphans.get(Wtxid::from(hash)).is_some())
    }

    /// Returns an accepted mempool transaction body by txid.
    #[must_use]
    pub fn get_tx(&self, txid: Txid) -> Option<Tx> {
        let pool = self.pool.read();
        pool.transaction_by_txid(&txid).map(|tx| (*tx).clone())
    }

    /// Returns an accepted or resident orphan transaction body by witness txid.
    #[must_use]
    pub fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        let pool = self.pool.read();
        if let Some(entry) = pool.entry_by_wtxid(&wtxid) {
            return Some((*entry.tx).clone());
        }
        self.lifecycle
            .lock()
            .orphans
            .get(wtxid)
            .map(|held| (*held.tx).clone())
    }

    /// Number of resident orphan transaction bodies.
    ///
    /// Test seam: peer-eviction assertions in this crate's and the node's
    /// suites read it; production inventory suppression goes through
    /// `have_tx`/`rejects_inventory`, never a count.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.lifecycle.lock().orphans.len()
    }

    /// Number of retained rejection hashes with transaction or witness scope.
    ///
    /// Test seam: reject-cache assertions only.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn recent_rejects_count(&self) -> usize {
        self.lifecycle.lock().rejects_len()
    }

    /// Whether a hash belongs to the bounded recent peer rejection cache.
    ///
    /// Test seam: reject-cache assertions only; production checks
    /// `rejects_inventory`/`rejects_transaction` for scope.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn is_rejected(&self, hash: Hash256) -> bool {
        self.lifecycle.lock().is_rejected(hash)
    }
}

#[cfg(test)]
mod tests;
