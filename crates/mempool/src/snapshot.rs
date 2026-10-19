//! Optional restart candidates, independent of Chainstate and estimator history.
//!
//! Persist only canonical transactions, admission times and operator fee deltas.
//! Graphs, fees, admission stamps and sequences are reconstructed by the gateway.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use bitcoin_rs_primitives::{
    ConsensusEncode, Hash256, Network, Tx, Txid, consensus_bytes, deserialize,
};
use hashbrown::HashMap;
use sha2::{Digest, Sha256};

use crate::{AdmissionChain, AdmissionOrigin, LocalOrigin, MempoolGateway};

/// This artifact is optional and never participates in authoritative recovery.
const FILE_NAME: &str = "mempool-snapshot.dat";
const MAGIC: &[u8; 8] = b"BRSMPOOL";
const VERSION: u32 = 1;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;
const MAX_TX_BYTES: usize = 400_000;
/// Candidates older than fourteen days are not reconsidered at startup.
const MAX_AGE: u64 = 14 * 24 * 60 * 60;

struct SavedTransaction {
    tx: Arc<Tx>,
    txid: Txid,
    time: u64,
}

struct Snapshot {
    transactions: Vec<SavedTransaction>,
    deltas: Vec<(Txid, i64)>,
}

/// Startup outcome after revalidation, including resource-budget exhaustion.
#[derive(Debug)]
pub struct RestoreReport {
    /// Number of saved candidate transactions.
    pub candidates: usize,
    /// Candidates still present after all admission/eviction decisions.
    pub restored: usize,
    /// Candidates not present, including expired, confirmed and rejected entries.
    pub skipped: usize,
    /// The cooperative startup deadline stopped further admissions.
    pub timed_out: bool,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "mempool snapshot deadline exceeded",
        ))
    } else {
        Ok(())
    }
}

fn read_file(path: &Path, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
    check_deadline(deadline)?;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err(invalid("snapshot is not an ordinary bounded file"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BYTES {
        return Err(invalid("snapshot exceeds its size limit"));
    }
    check_deadline(deadline)?;
    Ok(Some(bytes))
}

fn take<const N: usize>(input: &mut &[u8]) -> io::Result<[u8; N]> {
    let (value, rest) = input
        .split_at_checked(N)
        .ok_or_else(|| invalid("truncated snapshot"))?;
    *input = rest;
    value.try_into().map_err(|_| invalid("truncated snapshot"))
}

impl Snapshot {
    fn capture(
        gateway: &MempoolGateway,
        deadline: Instant,
        max_bytes: u64,
        max_records: usize,
    ) -> io::Result<Self> {
        let pool = gateway
            .pool
            .try_read_for(deadline.saturating_duration_since(Instant::now()))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "mempool snapshot read lock busy")
            })?;
        // Preserve every operator overlay before allocating the remaining budget
        // to optional transaction candidates. Never silently truncate priorities.
        let deltas = pool.fee_deltas();
        if deltas.len() > MAX_RECORDS
            || 84_u64.saturating_add(
                u64::try_from(deltas.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(40),
            ) > max_bytes
        {
            return Err(invalid("too many mempool snapshot fee deltas"));
        }
        let mut deltas: Vec<_> = deltas.collect();
        let mut bytes = 84 + u64::try_from(deltas.len()).unwrap_or(u64::MAX) * 40;
        let mut transactions = Vec::with_capacity(pool.len().min(max_records));
        for cluster in pool.iter_clusters() {
            check_deadline(deadline)?;
            // Keep complete connected families: a parent-only prefix could
            // discard its paying CPFP child and make the saved parent useless.
            let cluster_bytes: u64 = cluster.iter().map(|row| u64::from(row.size) + 12).sum();
            if transactions.len() + cluster.len() > max_records
                || bytes.saturating_add(cluster_bytes) > max_bytes
                || cluster
                    .iter()
                    .any(|row| usize::try_from(row.size).unwrap_or(usize::MAX) > MAX_TX_BYTES)
            {
                break;
            }
            bytes += cluster_bytes;
            for entry in cluster {
                transactions.push(SavedTransaction {
                    tx: Arc::clone(&entry.tx),
                    txid: entry.txid,
                    time: entry.time,
                });
            }
        }
        if transactions.len() < pool.len() {
            tracing::warn!(
                saved = transactions.len(),
                omitted = pool.len() - transactions.len(),
                "mempool snapshot capacity reached; saving complete families within the budget"
            );
        }
        drop(pool);
        transactions.sort_unstable_by_key(|row| row.txid);
        deltas.sort_unstable_by_key(|row| row.0);
        Ok(Self {
            transactions,
            deltas,
        })
    }

    fn encode(&self, network: Network, deadline: Instant) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&network.genesis_block_hash().to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.transactions.len())
                .map_err(|_| invalid("too many transactions"))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.deltas.len())
                .map_err(|_| invalid("too many fee deltas"))?
                .to_le_bytes(),
        );
        for row in &self.transactions {
            check_deadline(deadline)?;
            bytes.extend_from_slice(&row.time.to_le_bytes());
            bytes.extend_from_slice(
                &u32::try_from(row.tx.consensus_size())
                    .map_err(|_| invalid("transaction too large"))?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&consensus_bytes(row.tx.as_ref()));
        }
        for (txid, delta) in &self.deltas {
            check_deadline(deadline)?;
            bytes.extend_from_slice(txid.as_bytes());
            bytes.extend_from_slice(&delta.to_le_bytes());
        }
        bytes.extend_from_slice(&Sha256::digest(&bytes));
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BYTES {
            return Err(invalid("snapshot exceeds its size limit"));
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8], network: Network, deadline: Instant) -> io::Result<Self> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BYTES || bytes.len() < 84 {
            return Err(invalid("invalid snapshot size"));
        }
        let (payload, checksum) = bytes.split_at(bytes.len() - 32);
        if Sha256::digest(payload).as_slice() != checksum {
            return Err(invalid("snapshot checksum mismatch"));
        }
        let mut input = payload;
        if &take::<8>(&mut input)? != MAGIC {
            return Err(invalid("invalid snapshot magic"));
        }
        if u32::from_le_bytes(take(&mut input)?) != VERSION {
            return Err(invalid("unsupported mempool snapshot version"));
        }
        if take::<32>(&mut input)? != network.genesis_block_hash().to_le_bytes() {
            return Err(invalid("mempool snapshot belongs to another network"));
        }
        let count = usize::try_from(u32::from_le_bytes(take(&mut input)?))
            .map_err(|_| invalid("transaction count overflow"))?;
        let delta_count = usize::try_from(u32::from_le_bytes(take(&mut input)?))
            .map_err(|_| invalid("fee delta count overflow"))?;
        if count > MAX_RECORDS || delta_count > MAX_RECORDS {
            return Err(invalid("snapshot record count exceeds its bound"));
        }
        let mut transactions = Vec::new();
        let mut ids = hashbrown::HashSet::new();
        for _ in 0..count {
            check_deadline(deadline)?;
            let time = u64::from_le_bytes(take(&mut input)?);
            let len = usize::try_from(u32::from_le_bytes(take(&mut input)?))
                .map_err(|_| invalid("transaction size overflow"))?;
            if len == 0 || len > MAX_TX_BYTES {
                return Err(invalid("snapshot transaction exceeds its size bound"));
            }
            let (raw, rest) = input
                .split_at_checked(len)
                .ok_or_else(|| invalid("truncated transaction"))?;
            input = rest;
            let tx: Tx = deserialize(raw).map_err(|_| invalid("invalid snapshot transaction"))?;
            if consensus_bytes(&tx) != raw {
                return Err(invalid("noncanonical snapshot transaction"));
            }
            let txid = tx.txid();
            if !ids.insert(txid) {
                return Err(invalid("duplicate snapshot transaction"));
            }
            transactions.push(SavedTransaction {
                tx: Arc::new(tx),
                txid,
                time,
            });
        }
        let mut deltas = Vec::new();
        let mut ids = hashbrown::HashSet::new();
        for _ in 0..delta_count {
            check_deadline(deadline)?;
            let txid = Txid(Hash256::from_le_bytes(&take(&mut input)?));
            let delta = i64::from_le_bytes(take(&mut input)?);
            if !ids.insert(txid) {
                return Err(invalid("duplicate snapshot fee delta"));
            }
            deltas.push((txid, delta));
        }
        if !input.is_empty() {
            return Err(invalid("trailing snapshot bytes"));
        }
        transactions.sort_unstable_by_key(|row| row.txid);
        Ok(Self {
            transactions,
            deltas,
        })
    }

    fn order(&self) -> io::Result<Vec<usize>> {
        let positions: HashMap<_, _> = self
            .transactions
            .iter()
            .enumerate()
            .map(|(i, row)| (row.txid, i))
            .collect();
        let parents: Vec<Vec<usize>> = self
            .transactions
            .iter()
            .map(|row| {
                row.tx
                    .inputs
                    .iter()
                    .filter_map(|input| positions.get(&input.previous_output.txid).copied())
                    .collect()
            })
            .collect();
        crate::fee_diagram::topological(&parents, &(0..self.transactions.len()).collect::<Vec<_>>())
            .map_err(|_| invalid("cyclic snapshot dependencies"))
    }
}

/// A synced staging file. Dropping it abandons the save without publishing.
pub struct PreparedSnapshot {
    file: tempfile::NamedTempFile,
    network: Network,
    deadline: Instant,
}

impl PreparedSnapshot {
    /// Publishes on the caller's thread. OS rename/fsync may exceed the
    /// cooperative deadline, so this call must complete before teardown returns.
    pub fn publish(self) -> io::Result<()> {
        check_deadline(self.deadline)?;
        let data_dir = self
            .file
            .path()
            .parent()
            .ok_or_else(|| invalid("missing staging directory"))?
            .to_path_buf();
        let live = data_dir.join(FILE_NAME);
        let validation = read_file(&live, self.deadline).and_then(|bytes| {
            bytes
                .map(|bytes| Snapshot::decode(&bytes, self.network, self.deadline))
                .transpose()
        });
        match validation {
            Ok(_) => {}
            Err(error)
                if error.kind() == io::ErrorKind::InvalidData
                    && std::fs::symlink_metadata(&live)?.is_file() =>
            {
                check_deadline(self.deadline)?;
                // A fresh directory gives rename an unused destination without
                // overwriting an earlier rejected artifact or copying a huge file.
                let rejected = tempfile::Builder::new()
                    .prefix("mempool-snapshot-rejected-")
                    .tempdir_in(&data_dir)?;
                std::fs::rename(&live, rejected.path().join(FILE_NAME))?;
                let path = rejected.keep();
                tracing::warn!(%error, path = %path.display(), "quarantined rejected mempool snapshot");
            }
            Err(error) => return Err(error),
        }
        check_deadline(self.deadline)?;
        self.file.persist(&live).map_err(|error| error.error)?;
        if let Ok(directory) = std::fs::File::open(&data_dir) {
            if let Err(error) = directory.sync_all() {
                tracing::warn!(%error, "mempool snapshot published but directory sync failed; crash durability is uncertain");
            }
        }
        Ok(())
    }
}

/// Captures and syncs a bounded snapshot without touching the live artifact.
/// A background worker may call this, but publication belongs to its caller.
pub fn prepare(
    data_dir: &Path,
    gateway: &MempoolGateway,
    network: Network,
    deadline: Instant,
) -> io::Result<PreparedSnapshot> {
    let started = Instant::now();
    let snapshot = Snapshot::capture(gateway, deadline, MAX_BYTES, MAX_RECORDS)?;
    let bytes = snapshot.encode(network, deadline)?;
    // Each writer owns a distinct staging inode. A concurrent save must never
    // rename another writer's unfinished file into the live pathname.
    let mut file = tempfile::Builder::new()
        .prefix("mempool-snapshot-")
        .suffix(".tmp")
        .tempfile_in(data_dir)?;
    for chunk in bytes.chunks(64 * 1024) {
        check_deadline(deadline)?;
        file.write_all(chunk)?;
    }
    file.as_file().sync_all()?;
    check_deadline(deadline)?;
    tracing::info!(
        transactions = snapshot.transactions.len(),
        bytes = bytes.len(),
        elapsed_ms = started.elapsed().as_millis(),
        "prepared mempool snapshot"
    );
    Ok(PreparedSnapshot {
        file,
        network,
        deadline,
    })
}

/// Saves on the calling thread; rejected ordinary files are quarantined intact.
pub fn save(
    data_dir: &Path,
    gateway: &MempoolGateway,
    network: Network,
    deadline: Instant,
) -> io::Result<()> {
    prepare(data_dir, gateway, network, deadline)?.publish()
}

/// Revalidates candidates before services become ready.
///
/// No saved membership, base fee, height or admission token is trusted. A malformed artifact changes
/// nothing; a budget-limited restore retains only successfully re-admitted rows.
#[expect(
    clippy::too_many_lines,
    reason = "keep restore validation, bounded dependency retries and gateway publication together"
)]
pub fn restore(
    data_dir: &Path,
    gateway: &MempoolGateway,
    network: Network,
    chain: &dyn AdmissionChain,
    now: u64,
    deadline: Instant,
) -> io::Result<Option<RestoreReport>> {
    {
        let pool = gateway.read();
        if !pool.is_empty() || pool.fee_deltas().len() != 0 {
            return Err(invalid("snapshot restore requires a fresh mempool"));
        }
    }
    let Some(bytes) = read_file(&data_dir.join(FILE_NAME), deadline)? else {
        return Ok(None);
    };
    let snapshot = Snapshot::decode(&bytes, network, deadline)?;
    drop(bytes);
    let order = snapshot.order()?;
    let positions: HashMap<_, _> = snapshot
        .transactions
        .iter()
        .map(|row| (row.txid, row))
        .collect();
    let eligible = |row: &SavedTransaction| row.time <= now && now - row.time <= MAX_AGE;
    let mut timed_out = false;
    for (txid, delta) in &snapshot.deltas {
        if check_deadline(deadline).is_err() {
            timed_out = true;
            break;
        }
        gateway
            .prioritise(*txid, *delta)
            .map_err(|_| invalid("snapshot fee delta overflow"))?;
    }
    let mut ready = VecDeque::from(order);
    let mut queued = vec![true; snapshot.transactions.len()];
    let mut waiting: HashMap<Txid, hashbrown::HashSet<usize>> = HashMap::new();
    let mut announced = hashbrown::HashSet::new();
    while let Some(index) = ready.pop_front() {
        queued[index] = false;
        if timed_out || check_deadline(deadline).is_err() {
            timed_out = true;
            break;
        }
        let row = &snapshot.transactions[index];
        if !eligible(row) || gateway.read().contains_txid(&row.txid) {
            continue;
        }
        let mut result = gateway
            .submit_transaction(
                Arc::clone(&row.tx),
                AdmissionOrigin::Snapshot,
                None,
                row.time,
                chain,
            )
            .map(|outcome| match outcome {
                crate::SubmitOutcome::Committed(result) => result,
                _ => crate::MutationResult::empty(),
            });
        // A native CPFP/ephemeral-dust package may have a parent that cannot
        // enter alone. Reuse the existing child-with-independent-parents owner;
        // it enforces package limits, scripts and current aggregate fee floors.
        let mut package = Vec::new();
        let mut missing = hashbrown::HashSet::new();
        if result.is_err() {
            for input in &row.tx.inputs {
                if gateway.read().contains_txid(&input.previous_output.txid) {
                    continue;
                }
                if let Some(parent) = positions.get(&input.previous_output.txid)
                    && eligible(parent)
                    && missing.insert(parent.txid)
                {
                    if package.len() < crate::standardness::MAX_PACKAGE_COUNT {
                        package.push(parent.tx.as_ref().clone());
                    }
                }
            }
        }
        if !package.is_empty() && package.len() < crate::standardness::MAX_PACKAGE_COUNT {
            if check_deadline(deadline).is_err() {
                timed_out = true;
                break;
            }
            package.push(row.tx.as_ref().clone());
            result = gateway.submit_package_with_times(
                package,
                LocalOrigin::Snapshot,
                None,
                |tx| positions[&tx.txid()].time,
                chain,
            );
        }
        if let Ok(result) = result {
            for change in result.changes {
                let id = Txid(change.txid);
                if gateway.read().contains_txid(&id)
                    && announced.insert(id)
                    && let Some(children) = waiting.remove(&id)
                {
                    let mut children: Vec<_> = children.into_iter().collect();
                    children.sort_unstable();
                    for child in children {
                        if !queued[child] {
                            queued[child] = true;
                            ready.push_back(child);
                        }
                    }
                }
            }
        } else {
            // Each restored parent wakes its failed dependents at most once.
            // No progress means no retries; total wakes are bounded by saved
            // dependency edges, in addition to the cooperative time budget.
            for parent in missing {
                waiting.entry(parent).or_default().insert(index);
            }
        }
    }
    timed_out |= check_deadline(deadline).is_err();
    let restored = gateway.read().len();
    Ok(Some(RestoreReport {
        candidates: snapshot.transactions.len(),
        restored,
        skipped: snapshot.transactions.len().saturating_sub(restored),
        timed_out,
    }))
}

#[cfg(test)]
mod tests;
