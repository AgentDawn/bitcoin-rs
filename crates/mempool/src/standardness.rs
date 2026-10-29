//! Bitcoin Core `IsStandardTx` / `IsStandard` policy checks.
//!
//! These are mempool/relay policy checks, not consensus rules. A transaction
//! that fails these checks may still be valid; it simply will not be accepted
//! to the mempool or relayed by default.

use alloc::vec::Vec;

use hashbrown::{HashMap, HashSet};

use bitcoin_rs_consensus::bip68;
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid, Wtxid};

#[cfg(test)]
use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
use bitcoin_rs_script::{
    is_op_return, is_p2a, is_p2pk, is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh, is_p2wsh, is_push_only,
    minimal_non_dust, multisig_key_count,
};
use thiserror::Error;

use crate::{Mempool, PolicyError, PrevoutMeta, RbfError};

/// Maximum weight of a standard transaction (400 000 weight units).
const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

/// Maximum length of a standard `scriptSig` in bytes.
const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 1_650;

/// Standard relay policy values that are configurable by the node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardnessPolicy {
    /// Fee rate used to classify outputs as dust, in sat/kvB.
    pub dust_relay_fee: u64,
    /// Maximum aggregate serialized nulldata script bytes, or `None` to disable nulldata.
    pub max_datacarrier_bytes: Option<usize>,
}

impl Default for StandardnessPolicy {
    /// The enforced defaults: Core's dust-relay rate (3 000 sat/kvB) and an
    /// 83-byte aggregate nulldata budget. Admission consumes these through
    /// [`crate::Mempool::policy_snapshot`]; `getmempoolinfo` projects them.
    fn default() -> Self {
        Self {
            dust_relay_fee: 3_000,
            max_datacarrier_bytes: Some(83),
        }
    }
}

/// Minimum transaction version considered standard.
const TX_VERSION_MIN: u32 = 1;

/// Version 3 is accepted with BIP431 admission checks.
const TX_VERSION_MAX: u32 = 3;

/// Standardness policy rejection reason for a single transaction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StandardnessError {
    /// Transaction version is outside the standard range (1 through 3).
    #[error("non-standard transaction version")]
    Version,
    /// Transaction weight exceeds `MAX_STANDARD_TX_WEIGHT` (400 000).
    #[error("transaction weight exceeds maximum standard weight")]
    Weight,
    /// A `scriptSig` contains non-push opcodes.
    #[error("scriptSig is not push-only")]
    ScriptSigNotPushOnly,
    /// A `scriptSig` exceeds 1650 bytes.
    #[error("scriptSig exceeds maximum standard size")]
    ScriptSigTooLarge,
    /// An output script is not a recognized standard type.
    #[error("non-standard output script")]
    NonStandardOutput,
    /// Nulldata outputs are disabled by policy.
    #[error("nulldata outputs are disabled")]
    DataCarrierDisabled,
    /// Aggregate serialized nulldata script bytes exceed the policy limit.
    #[error("aggregate nulldata script bytes exceed the policy limit")]
    DataCarrierBytesExceeded,
    /// Aggregate serialized nulldata script length overflowed.
    #[error("aggregate nulldata script length overflowed")]
    DataCarrierSizeOverflow,
    /// Non-witness serialization is below the relay minimum.
    #[error("transaction non-witness size is below the relay minimum")]
    TransactionTooSmall,
    /// Ephemeral dust violates the output-count or zero-fee requirement.
    #[error("dust")]
    DustOutput,
}

/// Checks whether a transaction satisfies Bitcoin Core's standardness policy.
pub fn is_standard_tx(tx: &Tx, policy: &StandardnessPolicy) -> Result<(), StandardnessError> {
    check_version(tx)?;
    check_weight(tx)?;
    check_script_sigs(tx)?;
    check_outputs(tx, policy)?;
    check_min_size(tx)?;
    Ok(())
}

/// Bitcoin Core `MAX_PACKAGE_COUNT` for package acceptance / `testmempoolaccept`.
pub const MAX_PACKAGE_COUNT: usize = 25;

/// Bitcoin Core `MAX_PACKAGE_WEIGHT`: the aggregate weight-unit bound of a
/// multi-transaction package.
pub const MAX_PACKAGE_WEIGHT: u64 = 404_000;

/// Caller-resolved fee and prevout context for one package transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageTxContext {
    /// Actual fee in satoshis.
    pub fee: u64,
    /// Policy virtual size in vbytes.
    pub vsize: u32,
    /// Prevout-aware sigop cost.
    pub sigop_cost: u32,
    /// At least one input is neither confirmed nor satisfied by the mempool /
    /// earlier package transactions.
    pub missing_inputs: bool,
}

/// Per-transaction package acceptance fact for RPC / admission consumers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxAcceptanceFact {
    /// Transaction id.
    pub txid: Txid,
    /// Witness transaction id.
    pub wtxid: Wtxid,
    /// Whether the transaction was accepted or rejected. `None` means package
    /// evaluation stopped before this row was validated.
    pub allowed: Option<bool>,
    /// Policy virtual size in vbytes.
    pub vsize: u32,
    /// Consensus weight.
    pub weight: u64,
    /// Prevout-aware sigop cost supplied by the caller.
    pub sigop_cost: u32,
    /// Base fee when acceptance accounting succeeded far enough to know it.
    pub base_fee: Option<u64>,
    /// Modified fee in satoshis when prioritisation is applied.
    pub modified_fee: Option<i128>,
    /// Modified fee rate in sat/kvB from the captured policy state.
    pub effective_fee_rate: Option<u64>,
    /// Rejection reason when `allowed` is false.
    pub reject_reason: Option<AcceptanceRejectReason>,
}

/// Package-level acceptance facts: optional package error plus per-tx rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageAcceptanceFacts {
    /// Package-wide failure (for example package count bounds).
    pub package_error: Option<AcceptanceRejectReason>,
    /// One row per submitted transaction, in input order.
    pub results: Vec<TxAcceptanceFact>,
}
/// Next-block BIP68 sequence-lock context for one admission evaluation.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Bip68Admission<'a> {
    /// Whether CSV (BIP68/112/113) is active for the next block.
    pub csv_active: bool,
    /// Height of the block that would include `tx` (applied tip + 1).
    pub next_height: u32,
    /// Median-time-past of the applied tip; also the assumed time context
    /// of any unconfirmed (mempool/package) parent input.
    pub next_mtp: u32,
    /// Confirmed-chain metadata per resolved input. Mempool/package parents
    /// are derived at `next_height` / `next_mtp` when not present here.
    pub prevout_meta: Option<&'a HashMap<OutPoint, PrevoutMeta>>,
    /// Set of inputs this evaluation actually resolved, including mempool and
    /// package parents. Used to treat unconfirmed parents consistently.
    pub resolved_prevouts: Option<&'a HashSet<OutPoint>>,
}

/// Per-transaction relay sigop limit: one fifth of the block limit,
/// matching Core v31.1's `MAX_STANDARD_TX_SIGOPS_COST`.
pub const MAX_STANDARD_TX_SIGOPS_COST: u32 = 16_000;

/// Policy rejection reason for dry-run package acceptance.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcceptanceRejectReason {
    /// Package length is outside `1..=MAX_PACKAGE_COUNT`.
    #[error("package-too-many-transactions")]
    PackageCount,
    /// Multiple transactions exceed 404,000 aggregate wire weight units.
    #[error("package-too-large")]
    PackageTooLarge,
    /// Repeated txids, including differing witness bodies.
    #[error("package-contains-duplicates")]
    PackageDuplicates,
    /// A parent follows its child in the offered package.
    #[error("package-not-sorted")]
    PackageOrder,
    /// Native submission requires a child and its independent direct parents.
    #[error("package-not-child-with-parents")]
    PackageTopology,
    /// Public package submission currently supports singletons and 1p1c only.
    #[error("package submission supports at most one parent and one child")]
    PackageUnsupported,
    /// Two package transactions spend the same outpoint.
    #[error("conflict-in-package")]
    PackageConflict,
    /// Multi-transaction testmempoolaccept cannot replace a resident member.
    #[error("bip125-replacement-disallowed")]
    MempoolConflict,
    /// Combined package additions exceed a cluster bound.
    #[error("too-large-cluster")]
    PackageCluster,
    /// Version-3 ancestry or size violates BIP431.
    #[error(transparent)]
    Truc(#[from] crate::TrucError),
    /// A child leaves a dust output of its unconfirmed parent unspent.
    #[error("missing-ephemeral-spends")]
    MissingEphemeralSpends,
    /// Transaction is already present in the mempool.
    #[error("txn-already-in-mempool")]
    AlreadyInMempool,
    /// One or more inputs are unavailable.
    #[error("missing-inputs")]
    MissingInputs,
    /// Fee rate is below the live min-relay / mempool-min floor.
    #[error("min relay fee not met")]
    MinRelayFeeNotMet,
    /// Fee rate exceeds the caller-supplied maximum.
    #[error("max-fee-exceeded")]
    MaxFeeExceeded,
    /// Transaction fails standardness policy.
    #[error(transparent)]
    NonStandard(#[from] StandardnessError),
    /// Conflicting replacement fails BIP125.
    #[error(transparent)]
    Replacement(#[from] RbfError),
    /// Native admission cannot insert into the pool or represent its graph.
    #[error(transparent)]
    Mempool(#[from] crate::MempoolError),
    /// Transaction exceeds ancestor or descendant package limits.
    #[error(transparent)]
    PackageLimit(#[from] PolicyError),
    /// Prevout-aware sigop cost exceeds the per-transaction relay limit.
    #[error("too-many-sigops")]
    TooManySigops,
    /// Next-block BIP68 relative sequence locks are unmet.
    #[error("non-BIP68-final")]
    NonBip68Final,
    /// Consensus script verification failed.
    #[error("script-verify-flag-failed")]
    ScriptVerify,
}

/// Caller fee guard shared by policy-only evaluation and verified admission.
pub(crate) fn exceeds_max_feerate(fee: u64, vsize: u32, maximum: Option<u64>) -> bool {
    maximum.is_some_and(|max| {
        crate::rbf::required_fee(max, vsize)
            .is_ok_and(|limit| limit != 0 && i128::from(fee) > limit)
    })
}
/// Returns true when `tx`'s BIP68 sequence locks are satisfied at the next
/// block.
///
/// Callers must reject missing inputs first; this check skips unresolved inputs.
pub(crate) fn bip68_final(pool: &Mempool, tx: &Tx, finality: &Bip68Admission<'_>) -> bool {
    if !finality.csv_active || tx.version < 2 {
        return true;
    }
    let empty_meta = HashMap::new();
    let empty_set = HashSet::new();
    let prevout_meta = finality.prevout_meta.unwrap_or(&empty_meta);
    let resolved = finality.resolved_prevouts.unwrap_or(&empty_set);
    for input in &tx.inputs {
        let sequence = input.sequence.to_consensus();
        if sequence & bip68::SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            continue;
        }
        let (prevout_height, prevout_mtp) =
            if let Some(meta) = prevout_meta.get(&input.previous_output) {
                (meta.height, meta.mtp)
            } else if resolved.contains(&input.previous_output)
                || pool.contains_txid(&input.previous_output.txid)
            {
                (finality.next_height, finality.next_mtp)
            } else {
                continue;
            };
        if !bip68::sequence_lock_satisfied(
            tx.version,
            sequence,
            prevout_height,
            prevout_mtp,
            finality.next_height,
            finality.next_mtp,
        ) {
            return false;
        }
    }
    true
}

pub(crate) fn evaluate_one(
    pool: &Mempool,
    policy: &StandardnessPolicy,
    tx: &Tx,
    context: PackageTxContext,
    max_feerate_sat_per_kvb: Option<u64>,
    mempool_min_fee_sat_per_kvb: Option<u64>,
    finality: &Bip68Admission<'_>,
) -> TxAcceptanceFact {
    let txid = tx.txid();
    let wtxid = tx.wtxid();
    let weight = tx.weight();
    let vsize = context.vsize;
    // `None` omits the floor comparison entirely (Core `bypassLimits`):
    // a zero floor still rejects a tx whose prioritisation delta drags
    // its modified fee negative, which bypassing must not do.
    let modified_fee_res = pool.modified_fee_for(txid, context.fee);
    let modified_fee = modified_fee_res.as_ref().ok().copied();
    // The caller's cap gates on the transaction's actual base fee, exactly
    // like submission: a policy discount or surcharge must not change the
    // client fee-limit result, so preview and submit agree on the same cap.
    let fee_for_max = context.fee;

    let fee_rejection = match mempool_min_fee_sat_per_kvb {
        None => None,
        Some(floor) => match (modified_fee_res, crate::rbf::required_fee(floor, vsize)) {
            (Ok(fee), Ok(required)) => {
                (fee < required).then_some(AcceptanceRejectReason::MinRelayFeeNotMet)
            }
            _ => Some(AcceptanceRejectReason::Replacement(
                RbfError::ArithmeticOverflow,
            )),
        },
    };

    let reject = if pool.contains_txid(&txid) {
        Some(AcceptanceRejectReason::AlreadyInMempool)
    } else if tx.is_coinbase() || context.missing_inputs {
        Some(AcceptanceRejectReason::MissingInputs)
    } else if let Err(err) = is_standard_tx(tx, policy) {
        Some(AcceptanceRejectReason::NonStandard(err))
    } else if tx_has_dust_outputs(tx, policy.dust_relay_fee)
        && (context.fee != 0 || pool.modified_fee_for(txid, context.fee) != Ok(0))
    {
        Some(AcceptanceRejectReason::NonStandard(
            StandardnessError::DustOutput,
        ))
    } else if context.sigop_cost > MAX_STANDARD_TX_SIGOPS_COST {
        Some(AcceptanceRejectReason::TooManySigops)
    } else if let Some(reason) = fee_rejection {
        Some(reason)
    } else if exceeds_max_feerate(fee_for_max, vsize, max_feerate_sat_per_kvb) {
        Some(AcceptanceRejectReason::MaxFeeExceeded)
    } else if !bip68_final(pool, tx, finality) {
        Some(AcceptanceRejectReason::NonBip68Final)
    } else {
        None
    };

    let effective_fee_rate = modified_fee.and_then(|fee| {
        let clamped = fee.max(0);
        (vsize != 0)
            .then(|| {
                clamped
                    .checked_mul(1_000)
                    .map(|prod| prod / i128::from(vsize))
            })
            .flatten()
            .and_then(|rate| u64::try_from(rate).ok())
    });

    TxAcceptanceFact {
        txid,
        wtxid,
        allowed: Some(reject.is_none()),
        vsize,
        weight,
        sigop_cost: context.sigop_cost,
        base_fee: Some(context.fee),
        modified_fee,
        effective_fee_rate,
        reject_reason: reject,
    }
}

/// Minimum non-witness serialization Core relays, `tx-size-small`.
const MIN_NON_WITNESS_TX_SIZE: usize = 65;

fn check_min_size(tx: &Tx) -> Result<(), StandardnessError> {
    if tx.base_size() < MIN_NON_WITNESS_TX_SIZE {
        return Err(StandardnessError::TransactionTooSmall);
    }
    Ok(())
}

fn check_version(tx: &Tx) -> Result<(), StandardnessError> {
    if (TX_VERSION_MIN..=TX_VERSION_MAX).contains(&tx.version) {
        Ok(())
    } else {
        Err(StandardnessError::Version)
    }
}

fn check_weight(tx: &Tx) -> Result<(), StandardnessError> {
    if tx.weight() > MAX_STANDARD_TX_WEIGHT {
        Err(StandardnessError::Weight)
    } else {
        Ok(())
    }
}

fn check_script_sigs(tx: &Tx) -> Result<(), StandardnessError> {
    for input in &tx.inputs {
        let script_sig = &input.script_sig;
        if !is_push_only(script_sig) {
            return Err(StandardnessError::ScriptSigNotPushOnly);
        }
        if script_sig.len() > MAX_STANDARD_SCRIPTSIG_SIZE {
            return Err(StandardnessError::ScriptSigTooLarge);
        }
    }
    Ok(())
}

fn check_outputs(tx: &Tx, policy: &StandardnessPolicy) -> Result<(), StandardnessError> {
    let mut datacarrier_bytes = 0_usize;
    let mut dust_outputs = 0_usize;
    for output in &tx.outputs {
        let script = &output.script_pubkey;
        if is_op_return(script) {
            if !is_push_only(&script[1..]) {
                return Err(StandardnessError::NonStandardOutput);
            }
            let Some(limit) = policy.max_datacarrier_bytes else {
                return Err(StandardnessError::DataCarrierDisabled);
            };
            let serialized_script_bytes = bitcoin_rs_primitives::varint::encoded_len(
                u64::try_from(script.len()).unwrap_or(u64::MAX),
            )
            .checked_add(script.len())
            .ok_or(StandardnessError::DataCarrierSizeOverflow)?;
            datacarrier_bytes = datacarrier_bytes
                .checked_add(serialized_script_bytes)
                .ok_or(StandardnessError::DataCarrierSizeOverflow)?;
            if datacarrier_bytes > limit {
                return Err(StandardnessError::DataCarrierBytesExceeded);
            }
            continue;
        }
        if !is_standard_output_script(script) {
            return Err(StandardnessError::NonStandardOutput);
        }
        dust_outputs += usize::from(is_dust(output, policy.dust_relay_fee));
    }
    if dust_outputs > 1 {
        return Err(StandardnessError::DustOutput);
    }
    Ok(())
}

/// Returns `true` if `script` is one of the standard output script types.
fn is_standard_output_script(script: &[u8]) -> bool {
    is_p2pkh(script)
        || is_p2sh(script)
        || is_p2pk(script)
        || is_p2wpkh(script)
        || is_p2wsh(script)
        || is_p2tr(script)
        || is_p2a(script)
        || is_standard_multisig(script)
}

/// Returns `true` if `script` is a bare multisig with at most 3 pubkeys.
fn is_standard_multisig(script: &[u8]) -> bool {
    multisig_key_count(script).is_some_and(|n| n <= 3)
}

/// Returns `true` if a non-`OP_RETURN` output is dust.
pub(crate) fn is_dust(output: &TxOut, dust_relay_fee: u64) -> bool {
    output.value.to_sat() < minimal_non_dust(&output.script_pubkey, dust_relay_fee)
}

/// Core `GetDust`: whether any output is below the dust-relay threshold.
#[must_use]
pub(crate) fn tx_has_dust_outputs(tx: &Tx, dust_relay_fee: u64) -> bool {
    tx.outputs
        .iter()
        .any(|output| is_dust(output, dust_relay_fee))
}

#[cfg(test)]
mod tests;
