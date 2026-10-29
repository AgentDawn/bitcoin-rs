//! History-based fee-rate estimator modelled on Bitcoin Core's
//! `CBlockPolicyEstimator` but simplified.
//!
//! Maintains exponentially-spaced fee-rate buckets and records, per bucket,
//! how many blocks transactions waited before confirmation.
//! [`FeeEstimator::estimate`] returns the lowest fee rate whose historical
//! confirmation success rate clears a threshold, or [`None`] when there is
//! insufficient data.

use alloc::vec::Vec;

use bitcoin_rs_primitives::Txid;
use hashbrown::HashMap;

/// Bucket fee-rate growth numerator: each bucket's lower bound is 5% above
/// the previous (`lower * 105 / 100`).
const BUCKET_GROWTH_NUM: u64 = 105;
/// Bucket fee-rate growth denominator.
const BUCKET_GROWTH_DEN: u64 = 100;
/// Minimum tracked fee rate: 1 sat/vB = 1 000 sat/kvB.
const MIN_FEE_RATE_SAT_PER_KVB: u64 = 1_000;
/// Maximum tracked fee rate: 1 000 sat/vB = 1 000 000 sat/kvB.
const MAX_FEE_RATE_SAT_PER_KVB: u64 = 1_000_000;
/// Maximum confirmation-target horizon in blocks.
const MAX_CONF_TARGET: usize = 25;
/// A bucket is suggested when >= 85% of historical transactions at or above
/// its fee rate confirmed within the target.
const SUCCESS_THRESHOLD: f64 = 0.85;
/// Per-block decay factor applied to all bucket counts.
const DECAY_FACTOR: f64 = 0.998;
/// Minimum decayed observation count required before producing an estimate.
const MIN_OBSERVATIONS: f64 = 1.0;
/// Maximum number of pending (unconfirmed) transaction entries tracked.
const MAX_PENDING_ENTRIES: usize = 10_000;

/// Fee rate in satoshis per kilo-virtual-byte (sat/kvB).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FeeRate(u64);

impl FeeRate {
    /// Returns the fee rate in sat/kvB.
    #[must_use]
    pub const fn as_sat_per_kvb(self) -> u64 {
        self.0
    }
}

/// Rejection reason when a persisted fee estimator history payload is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryReject {
    /// Leading magic bytes are not the estimator's.
    BadMagic,
    /// The format version is not one this build reads.
    UnknownVersion(u32),
    /// Truncated, carries trailing bytes, or disagrees with the layout this
    /// build computes: drifted bucket bounds, non-finite or negative
    /// counts, out-of-range indexes, or impossible entry counts.
    Corrupt,
}

/// Per-bucket confirmation statistics.
#[derive(Debug)]
struct Bucket {
    /// Lower-bound fee rate for this bucket (sat/kvB).
    fee_rate_sat_per_kvb: u64,
    /// Decayed count of transactions confirmed within N blocks
    /// (index 0 = 1 block, index 24 = 25 blocks).
    confirmed_within: [f64; MAX_CONF_TARGET],
    /// Decayed count of transactions RESOLVED for each target: confirmed
    /// within it, or still unconfirmed once it expired.
    resolved_within: [f64; MAX_CONF_TARGET],
}

impl Bucket {
    /// Creates a zeroed bucket at the given fee-rate lower bound.
    const fn new(fee_rate_sat_per_kvb: u64) -> Self {
        Self {
            fee_rate_sat_per_kvb,
            confirmed_within: [0.0; MAX_CONF_TARGET],
            resolved_within: [0.0; MAX_CONF_TARGET],
        }
    }
}

/// Metadata for a pending (unconfirmed) transaction.
#[derive(Debug)]
struct PendingEntry {
    /// Index into `buckets`.
    bucket_index: usize,
    /// Block height at which the transaction entered the mempool.
    entry_height: u32,
    /// Highest target already sampled for this transaction, 0 for none.
    resolved_through: usize,
}

/// History-based fee estimator with exponential buckets and per-block decay.
#[derive(Debug)]
pub struct FeeEstimator {
    buckets: Vec<Bucket>,
    /// Height whose decay has already been applied, so a repeated
    /// notification for it does not age the history a second time.
    last_decayed_height: Option<u32>,
    pending: HashMap<Txid, PendingEntry>,
    /// Heights at which tracked txids were recorded as confirmed.
    confirmed_at: HashMap<Txid, u32>,
}

impl FeeEstimator {
    /// Creates a new estimator with precomputed fee-rate buckets and no data.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: build_buckets(),
            pending: HashMap::new(),
            last_decayed_height: None,
            confirmed_at: HashMap::new(),
        }
    }

    /// Records that a transaction entered the mempool.
    pub fn tx_entered(&mut self, txid: Txid, fee_rate_sat_per_kvb: u64, height: u32) {
        if self.pending.contains_key(&txid) {
            return;
        }
        if self.pending.len() >= MAX_PENDING_ENTRIES {
            return;
        }
        let bucket_index = self.bucket_index_for_rate(fee_rate_sat_per_kvb);
        self.pending.insert(
            txid,
            PendingEntry {
                bucket_index,
                entry_height: height,
                resolved_through: 0,
            },
        );
    }

    /// Records that a transaction left the mempool without confirming.
    pub fn tx_left(&mut self, txid: &Txid) {
        self.pending.remove(txid);
    }

    /// Records confirmations from a connected block and applies decay.
    pub fn block_connected(&mut self, confirmed_txids: &[Txid], block_height: u32) {
        let advances_height = match self.last_decayed_height {
            Some(last_height) => block_height > last_height,
            None => true,
        };

        if let Some(last_height) = self.last_decayed_height
            && advances_height
        {
            for skipped_height in last_height.saturating_add(1)..block_height {
                self.advance_height(skipped_height);
            }
        }
        for txid in confirmed_txids {
            if self.confirmed_at.get(txid) == Some(&block_height) {
                self.pending.remove(txid);
                continue;
            }
            if let Some(entry) = self.pending.remove(txid) {
                self.confirmed_at.insert(*txid, block_height);
                let blocks_waited = block_height.saturating_sub(entry.entry_height).max(1);
                self.record_confirmation(&entry, blocks_waited);
            }
        }

        if advances_height {
            self.advance_height(block_height);
        }
    }

    /// Expires targets and decays observations for one newly reached height.
    fn advance_height(&mut self, block_height: u32) {
        self.expire_targets(block_height);
        self.last_decayed_height = Some(block_height);
        self.apply_decay();
        let prune_window = u32::try_from(MAX_CONF_TARGET).unwrap_or(u32::MAX);
        self.confirmed_at.retain(|_, confirmed_height| {
            block_height.saturating_sub(*confirmed_height) <= prune_window
        });
    }

    /// Samples a failure for every target that expired on this block.
    fn expire_targets(&mut self, block_height: u32) {
        let mut outlived = Vec::new();
        for (txid, entry) in &mut self.pending {
            let waited = usize::try_from(block_height.saturating_sub(entry.entry_height))
                .unwrap_or(usize::MAX)
                .min(MAX_CONF_TARGET);
            while entry.resolved_through < waited {
                self.buckets[entry.bucket_index].resolved_within[entry.resolved_through] += 1.0;
                entry.resolved_through += 1;
            }
            if entry.resolved_through == MAX_CONF_TARGET {
                outlived.push(*txid);
            }
        }
        for txid in outlived {
            self.pending.remove(&txid);
        }
    }

    /// Estimates the minimum fee rate for confirmation within
    /// `conf_target_blocks`.
    #[must_use]
    pub fn estimate(&self, conf_target_blocks: u32) -> Option<FeeRate> {
        let target = usize::try_from(conf_target_blocks)
            .unwrap_or(0)
            .min(MAX_CONF_TARGET);
        if target == 0 {
            return None;
        }
        let target_idx = target - 1;
        let mut cumulative_confirmed = 0.0_f64;
        let mut cumulative_total = 0.0_f64;
        let mut result = None;
        for bucket in self.buckets.iter().rev() {
            cumulative_confirmed += bucket.confirmed_within[target_idx];
            cumulative_total += bucket.resolved_within[target_idx];
            if cumulative_total >= MIN_OBSERVATIONS {
                let success_rate = cumulative_confirmed / cumulative_total;
                if success_rate >= SUCCESS_THRESHOLD {
                    result = Some(FeeRate(bucket.fee_rate_sat_per_kvb));
                }
            }
        }
        result
    }

    /// Returns the last height whose decay was applied, or `None` before the
    /// first `block_connected` call. A connected block ages the estimator even
    /// when it confirms nothing the pool tracked, so this is the observable
    /// proof that `block_connected` fired.
    #[must_use]
    #[cfg(any(test, feature = "test-seam"))]
    pub(crate) fn last_decayed_height(&self) -> Option<u32> {
        self.last_decayed_height
    }

    /// Returns the bucket index for a fee rate: the highest bucket whose
    /// lower bound is <= the given rate. Rates below the first bucket clamp
    /// to index 0.
    fn bucket_index_for_rate(&self, fee_rate_sat_per_kvb: u64) -> usize {
        let idx = self
            .buckets
            .partition_point(|b| b.fee_rate_sat_per_kvb <= fee_rate_sat_per_kvb);
        idx.saturating_sub(1)
    }

    /// Records a confirmation, incrementing all targets >= `blocks_waited`.
    fn record_confirmation(&mut self, entry: &PendingEntry, blocks_waited: u32) {
        let bucket_index = entry.bucket_index;
        let waited = usize::try_from(blocks_waited).unwrap_or(0);
        if waited == 0 {
            return;
        }
        let bucket = &mut self.buckets[bucket_index];
        if waited > MAX_CONF_TARGET {
            for target in entry.resolved_through..MAX_CONF_TARGET {
                bucket.resolved_within[target] += 1.0;
            }
            return;
        }
        for target in entry.resolved_through.saturating_add(1)..waited {
            bucket.resolved_within[target - 1] += 1.0;
        }
        for target in waited..=MAX_CONF_TARGET {
            bucket.confirmed_within[target - 1] += 1.0;
            if target > entry.resolved_through {
                bucket.resolved_within[target - 1] += 1.0;
            }
        }
    }

    /// Applies the per-block decay factor to all bucket counts.
    fn apply_decay(&mut self) {
        for bucket in &mut self.buckets {
            for count in &mut bucket.confirmed_within {
                *count *= DECAY_FACTOR;
            }
            for count in &mut bucket.resolved_within {
                *count *= DECAY_FACTOR;
            }
        }
    }

    /// Encodes the estimator's recoverable state for the owner-local
    /// history file. Deterministic: the same state produces the same bytes.
    #[must_use]
    pub fn to_history_bytes(&self) -> Vec<u8> {
        history_codec::encode(self)
    }

    /// Decodes a history payload written by [`Self::to_history_bytes`].
    pub(crate) fn from_history_bytes(bytes: &[u8]) -> Result<Self, HistoryReject> {
        history_codec::decode(bytes)
    }
}
impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// Owner-local persistence of the estimator's recoverable state.
mod history_codec {
    use super::{
        Bucket, FeeEstimator, HistoryReject, MAX_CONF_TARGET, MAX_PENDING_ENTRIES, PendingEntry,
        build_buckets,
    };
    use alloc::vec::Vec;
    use bitcoin_rs_primitives::Txid;
    use hashbrown::HashMap;

    /// Magic prefix of every version-1 history payload.
    pub(super) const HISTORY_MAGIC: [u8; 8] = *b"BRSEFEES";
    /// Estimator-owned format version; bumped only for a format change.
    pub(super) const HISTORY_VERSION: u32 = 1;
    /// Decode-side bound on confirmation records. Runtime state is bounded
    /// by the prune window; this gate only stops a hostile payload from
    /// naming billions of entries before any work is believed.
    const MAX_CONFIRMED_RECORDS: usize = 1_000_000;

    /// Sequential little-endian reader over a trusted-length byte slice.
    struct Reader<'a> {
        bytes: &'a [u8],
    }

    impl<'a> Reader<'a> {
        fn take(&mut self, len: usize) -> Result<&'a [u8], HistoryReject> {
            if self.bytes.len() < len {
                return Err(HistoryReject::Corrupt);
            }
            let (head, tail) = self.bytes.split_at(len);
            self.bytes = tail;
            Ok(head)
        }

        fn u8(&mut self) -> Result<u8, HistoryReject> {
            Ok(self.take(1)?[0])
        }

        fn u32_le(&mut self) -> Result<u32, HistoryReject> {
            let raw: [u8; 4] = self
                .take(4)?
                .try_into()
                .map_err(|_| HistoryReject::Corrupt)?;
            Ok(u32::from_le_bytes(raw))
        }

        fn u64_le(&mut self) -> Result<u64, HistoryReject> {
            let raw: [u8; 8] = self
                .take(8)?
                .try_into()
                .map_err(|_| HistoryReject::Corrupt)?;
            Ok(u64::from_le_bytes(raw))
        }

        fn counts<const N: usize>(&mut self) -> Result<[f64; N], HistoryReject> {
            let raw = self.take(N * 8)?;
            let (chunks, remainder) = raw.as_chunks::<8>();
            if !remainder.is_empty() {
                return Err(HistoryReject::Corrupt);
            }
            let mut out = [0.0_f64; N];
            for (slot, chunk) in out.iter_mut().zip(chunks) {
                let value = f64::from_le_bytes(*chunk);
                if !value.is_finite() || value < 0.0 {
                    return Err(HistoryReject::Corrupt);
                }
                *slot = value;
            }
            Ok(out)
        }

        fn txid(&mut self) -> Result<Txid, HistoryReject> {
            let raw: [u8; 32] = self
                .take(32)?
                .try_into()
                .map_err(|_| HistoryReject::Corrupt)?;
            Ok(Txid(bitcoin_rs_primitives::Hash256::from_le_bytes(&raw)))
        }

        fn finish(&self) -> Result<(), HistoryReject> {
            if self.bytes.is_empty() {
                Ok(())
            } else {
                Err(HistoryReject::Corrupt)
            }
        }
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_counts<const N: usize>(out: &mut Vec<u8>, counts: &[f64; N]) {
        for count in counts {
            out.extend_from_slice(&count.to_le_bytes());
        }
    }

    /// Encodes the estimator state with txids in sorted order, so the same
    /// state always produces the same bytes.
    pub(super) fn encode(est: &FeeEstimator) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&HISTORY_MAGIC);
        push_u32(&mut out, HISTORY_VERSION);
        match est.last_decayed_height {
            Some(height) => {
                out.push(1);
                out.extend_from_slice(&height.to_le_bytes());
            }
            None => out.push(0),
        }
        push_u32(
            &mut out,
            u32::try_from(est.buckets.len()).unwrap_or(u32::MAX),
        );
        for bucket in &est.buckets {
            out.extend_from_slice(&bucket.fee_rate_sat_per_kvb.to_le_bytes());
            push_counts(&mut out, &bucket.confirmed_within);
            push_counts(&mut out, &bucket.resolved_within);
        }
        let mut pending: Vec<_> = est.pending.iter().collect();
        pending.sort_unstable_by_key(|(txid, _)| **txid);
        push_u32(&mut out, u32::try_from(pending.len()).unwrap_or(u32::MAX));
        for (txid, entry) in pending {
            out.extend_from_slice(txid.as_bytes());
            push_u32(
                &mut out,
                u32::try_from(entry.bucket_index).unwrap_or(u32::MAX),
            );
            out.extend_from_slice(&entry.entry_height.to_le_bytes());
            push_u32(
                &mut out,
                u32::try_from(entry.resolved_through).unwrap_or(u32::MAX),
            );
        }
        let mut confirmed: Vec<_> = est.confirmed_at.iter().collect();
        confirmed.sort_unstable_by_key(|(txid, _)| **txid);
        push_u32(&mut out, u32::try_from(confirmed.len()).unwrap_or(u32::MAX));
        for (txid, height) in confirmed {
            out.extend_from_slice(txid.as_bytes());
            out.extend_from_slice(&height.to_le_bytes());
        }
        out
    }

    /// Decodes a version-1 payload, rejecting anything this build cannot
    /// interpret exactly.
    pub(super) fn decode(bytes: &[u8]) -> Result<FeeEstimator, HistoryReject> {
        let mut reader = Reader { bytes };
        if reader.take(HISTORY_MAGIC.len())? != HISTORY_MAGIC {
            return Err(HistoryReject::BadMagic);
        }
        let version = reader.u32_le()?;
        if version != HISTORY_VERSION {
            return Err(HistoryReject::UnknownVersion(version));
        }
        let last_decayed_height = match reader.u8()? {
            0 => None,
            1 => Some(reader.u32_le()?),
            _ => return Err(HistoryReject::Corrupt),
        };
        let bucket_count = reader.u32_le()?.try_into().unwrap_or(usize::MAX);
        let mut buckets = Vec::new();
        for _ in 0..bucket_count {
            let fee_rate_sat_per_kvb = reader.u64_le()?;
            let confirmed_within = reader.counts::<MAX_CONF_TARGET>()?;
            let resolved_within = reader.counts::<MAX_CONF_TARGET>()?;
            buckets.push(Bucket {
                fee_rate_sat_per_kvb,
                confirmed_within,
                resolved_within,
            });
        }
        let expected = build_buckets();
        if buckets.len() != expected.len()
            || buckets
                .iter()
                .zip(expected.iter())
                .any(|(bucket, expected_bucket)| {
                    bucket.fee_rate_sat_per_kvb != expected_bucket.fee_rate_sat_per_kvb
                })
        {
            return Err(HistoryReject::Corrupt);
        }
        let pending_count = reader.u32_le()?.try_into().unwrap_or(usize::MAX);
        if pending_count > MAX_PENDING_ENTRIES {
            return Err(HistoryReject::Corrupt);
        }
        let mut pending = HashMap::new();
        for _ in 0..pending_count {
            let txid = reader.txid()?;
            let bucket_index = reader.u32_le()?.try_into().unwrap_or(usize::MAX);
            let entry_height = reader.u32_le()?;
            let resolved_through = reader.u32_le()?.try_into().unwrap_or(usize::MAX);
            if bucket_index >= buckets.len() || resolved_through > MAX_CONF_TARGET {
                return Err(HistoryReject::Corrupt);
            }
            pending.insert(
                txid,
                PendingEntry {
                    bucket_index,
                    entry_height,
                    resolved_through,
                },
            );
        }
        let confirmed_count = reader.u32_le()?.try_into().unwrap_or(usize::MAX);
        if confirmed_count > MAX_CONFIRMED_RECORDS {
            return Err(HistoryReject::Corrupt);
        }
        let mut confirmed_at = HashMap::new();
        for _ in 0..confirmed_count {
            let txid = reader.txid()?;
            let height = reader.u32_le()?;
            confirmed_at.insert(txid, height);
        }
        reader.finish()?;
        Ok(FeeEstimator {
            buckets,
            last_decayed_height,
            pending,
            confirmed_at,
        })
    }
}

/// Builds the exponentially-spaced fee-rate buckets.
fn build_buckets() -> Vec<Bucket> {
    let mut buckets = Vec::new();
    let mut lower = MIN_FEE_RATE_SAT_PER_KVB;
    while lower <= MAX_FEE_RATE_SAT_PER_KVB {
        buckets.push(Bucket::new(lower));
        let next = lower.saturating_mul(BUCKET_GROWTH_NUM) / BUCKET_GROWTH_DEN;
        if next <= lower {
            break;
        }
        lower = next;
    }
    buckets
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
