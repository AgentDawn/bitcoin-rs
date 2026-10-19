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
const VERSION: u32 = 2;
/// Default byte budget; operators may raise it for full large-pool preservation.
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TX_BYTES: usize = 400_000;
/// Candidates older than fourteen days are not reconsidered at startup.
const MAX_AGE: u64 = 14 * 24 * 60 * 60;

struct SavedTransaction {
    tx: Arc<Tx>,
    txid: Txid,
    time: u64,
    unbroadcast: bool,
    sigop_cost: u32,
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

fn read_file(path: &Path, max_bytes: u64, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
    check_deadline(deadline)?;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(invalid("snapshot is not an ordinary bounded file"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
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
        if 84_u64.saturating_add(
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
            let cluster_bytes: u64 = cluster.iter().map(|row| u64::from(row.size) + 17).sum();
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
                    unbroadcast: entry.unbroadcast,
                    sigop_cost: entry.sigop_cost,
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

    fn encode(&self, network: Network, max_bytes: u64, deadline: Instant) -> io::Result<Vec<u8>> {
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
            bytes.push(u8::from(row.unbroadcast));
            bytes.extend_from_slice(&row.sigop_cost.to_le_bytes());
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
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
            return Err(invalid("snapshot exceeds its size limit"));
        }
        Ok(bytes)
    }

    fn decode(
        bytes: &[u8],
        network: Network,
        max_bytes: u64,
        deadline: Instant,
    ) -> io::Result<Self> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes || bytes.len() < 84 {
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
        if count > bytes.len() / 17 || delta_count > bytes.len() / 40 {
            return Err(invalid("snapshot record count exceeds its bound"));
        }
        let mut transactions = Vec::new();
        let mut ids = hashbrown::HashSet::new();
        for _ in 0..count {
            check_deadline(deadline)?;
            let time = u64::from_le_bytes(take(&mut input)?);
            let unbroadcast = match take::<1>(&mut input)? {
                [0] => false,
                [1] => true,
                _ => return Err(invalid("invalid initial broadcast flag")),
            };
            let sigop_cost = u32::from_le_bytes(take(&mut input)?);
            if sigop_cost > crate::standardness::MAX_STANDARD_TX_SIGOPS_COST {
                return Err(invalid("snapshot transaction exceeds standard sigop cost"));
            }
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
                unbroadcast,
                sigop_cost,
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
    max_bytes: u64,
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
        let validation = read_file(&live, self.max_bytes, self.deadline).and_then(|bytes| {
            bytes
                .map(|bytes| Snapshot::decode(&bytes, self.network, self.max_bytes, self.deadline))
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
    max_bytes: u64,
    deadline: Instant,
) -> io::Result<PreparedSnapshot> {
    let started = Instant::now();
    let snapshot = Snapshot::capture(
        gateway,
        deadline,
        max_bytes,
        usize::try_from(u32::MAX).unwrap_or(usize::MAX),
    )?;
    let bytes = snapshot.encode(network, max_bytes, deadline)?;
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
        max_bytes,
    })
}

/// Saves on the calling thread; rejected ordinary files are quarantined intact.
pub fn save(
    data_dir: &Path,
    gateway: &MempoolGateway,
    network: Network,
    max_bytes: u64,
    deadline: Instant,
) -> io::Result<()> {
    prepare(data_dir, gateway, network, max_bytes, deadline)?.publish()
}

/// Revalidates candidates before services become ready.
///
/// No saved membership, base fee, height or admission token is trusted. A malformed artifact changes
/// nothing; a budget-limited restore retains only successfully re-admitted rows.
pub fn restore(
    data_dir: &Path,
    gateway: &MempoolGateway,
    network: Network,
    chain: &dyn AdmissionChain,
    now: u64,
    max_bytes: u64,
    deadline: Instant,
) -> io::Result<Option<RestoreReport>> {
    {
        let pool = gateway.read();
        if !pool.is_empty() || pool.fee_deltas().len() != 0 {
            return Err(invalid("snapshot restore requires a fresh mempool"));
        }
    }
    let Some(bytes) = read_file(&data_dir.join(FILE_NAME), max_bytes, deadline)? else {
        return Ok(None);
    };
    let snapshot = Snapshot::decode(&bytes, network, max_bytes, deadline)?;
    drop(bytes);
    restore_candidates(&snapshot, gateway, chain, now, deadline).map(Some)
}

// With children, collect a family before standalone admission consumes its
// shared fee budget. Without them, collect only missing ancestors for retry.
// Both traversals stop as soon as the package cannot fit the existing limit.
fn collect_saved_dependencies(
    tx: &Tx,
    gateway: &MempoolGateway,
    chain: &dyn AdmissionChain,
    positions: &HashMap<Txid, &SavedTransaction>,
    children: Option<&HashMap<Txid, Vec<Txid>>>,
    eligible: impl Fn(&SavedTransaction) -> bool,
    deadline: Instant,
) -> io::Result<hashbrown::HashSet<Txid>> {
    let mut missing = hashbrown::HashSet::new();
    if children.is_some() {
        missing.insert(tx.txid());
    }
    let limit = crate::standardness::MAX_PACKAGE_COUNT + usize::from(children.is_some());
    let mut stack = vec![tx];
    while let Some(tx) = stack.pop() {
        check_deadline(deadline)?;
        let confirmed_inputs = chain.snapshot(tx).map(|view| view.prevouts);
        for input in &tx.inputs {
            check_deadline(deadline)?;
            let point = input.previous_output;
            // Follow only unavailable inputs. A saved parent can now
            // be confirmed, with fully spent ancestors behind it.
            if gateway.read().contains_txid(&point.txid)
                || confirmed_inputs
                    .as_ref()
                    .is_some_and(|coins| coins.iter().any(|(confirmed, _)| *confirmed == point))
            {
                continue;
            }
            if let Some(ancestor) = positions.get(&point.txid)
                && eligible(ancestor)
                && missing.insert(point.txid)
            {
                if missing.len() >= limit {
                    return Ok(missing);
                }
                stack.push(ancestor.tx.as_ref());
            }
        }
        if let Some(descendants) = children.and_then(|children| children.get(&tx.txid())) {
            for id in descendants {
                check_deadline(deadline)?;
                if !gateway.read().contains_txid(id)
                    && let Some(child) = positions.get(id)
                    && eligible(child)
                    && missing.insert(*id)
                {
                    if missing.len() >= limit {
                        return Ok(missing);
                    }
                    stack.push(child.tx.as_ref());
                }
            }
        }
    }
    Ok(missing)
}

#[expect(
    clippy::too_many_lines,
    reason = "keep bounded dependency retries and gateway publication together"
)]
fn restore_candidates(
    snapshot: &Snapshot,
    gateway: &MempoolGateway,
    chain: &dyn AdmissionChain,
    now: u64,
    deadline: Instant,
) -> io::Result<RestoreReport> {
    let order = snapshot.order()?;
    let topo_order: HashMap<Txid, usize> = order
        .iter()
        .enumerate()
        .map(|(topo, &idx)| (snapshot.transactions[idx].txid, topo))
        .collect();
    let positions: HashMap<_, _> = snapshot
        .transactions
        .iter()
        .map(|row| (row.txid, row))
        .collect();
    let eligible = |row: &SavedTransaction| {
        row.time <= now
            && now - row.time <= MAX_AGE
            && row.sigop_cost <= crate::standardness::MAX_STANDARD_TX_SIGOPS_COST
    };
    // The decoded overlay is operator state, not optional admission work.
    // Finish it even if the cooperative transaction budget has expired, so
    // the next save cannot replace the file with only a prefix of priorities.
    // Decode rejects duplicate txids and startup requires an empty overlay.
    for (txid, delta) in &snapshot.deltas {
        gateway
            .prioritise(*txid, *delta)
            .map_err(|_| invalid("snapshot fee delta overflow"))?;
    }
    let mut timed_out = false;
    let mut children: HashMap<Txid, Vec<Txid>> = HashMap::new();
    'dependencies: for row in &snapshot.transactions {
        for input in &row.tx.inputs {
            if check_deadline(deadline).is_err() {
                timed_out = true;
                break 'dependencies;
            }
            if positions.contains_key(&input.previous_output.txid) {
                children
                    .entry(input.previous_output.txid)
                    .or_default()
                    .push(row.txid);
            }
        }
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
        let Ok(family) = collect_saved_dependencies(
            &row.tx,
            gateway,
            chain,
            &positions,
            Some(&children),
            eligible,
            deadline,
        ) else {
            timed_out = true;
            break;
        };
        let mut family: Vec<_> =
            if (2..=crate::standardness::MAX_PACKAGE_COUNT).contains(&family.len()) {
                family.into_iter().collect()
            } else {
                Vec::new()
            };
        family.sort_unstable_by_key(|id| topo_order[id]);
        let family: Vec<_> = family
            .iter()
            .map(|id| positions[id].tx.as_ref().clone())
            .collect();
        if check_deadline(deadline).is_err() {
            timed_out = true;
            break;
        }
        let restored_family = if family.is_empty() {
            None
        } else {
            gateway
                .submit_package_with_times(
                    &family,
                    LocalOrigin::Snapshot,
                    None,
                    |tx| positions[&tx.txid()].time,
                    chain,
                )
                .ok()
        };
        if restored_family.is_none() && check_deadline(deadline).is_err() {
            timed_out = true;
            break;
        }
        let mut result = if let Some(result) = restored_family {
            Ok(result)
        } else {
            gateway
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
                })
        };
        // A native CPFP/ephemeral-dust package may have parents and ancestors
        // that cannot enter alone. Recursively collect unconfirmed in-snapshot
        // ancestors in topological order; package validation enforces limits,
        // scripts and current aggregate fee floors.
        let mut package = Vec::new();
        let mut missing = hashbrown::HashSet::new();
        if result.is_err() {
            let Ok(ancestors) = collect_saved_dependencies(
                &row.tx, gateway, chain, &positions, None, eligible, deadline,
            ) else {
                timed_out = true;
                break;
            };
            missing = ancestors;
            if !missing.is_empty() && missing.len() < crate::standardness::MAX_PACKAGE_COUNT {
                let mut ancestor_ids: Vec<_> = missing.iter().copied().collect();
                ancestor_ids.sort_by_key(|id| topo_order.get(id).copied().unwrap_or(usize::MAX));
                for id in ancestor_ids {
                    package.push(positions[&id].tx.as_ref().clone());
                }
                package.push(row.tx.as_ref().clone());
            }
        }
        if !package.is_empty() {
            if check_deadline(deadline).is_err() {
                timed_out = true;
                break;
            }
            result = gateway.submit_package_with_times(
                &package,
                LocalOrigin::Snapshot,
                None,
                |tx| positions[&tx.txid()].time,
                chain,
            );
        }
        if let Ok(result) = result {
            for change in result.changes {
                let id = Txid(change.txid);
                if let Some(saved) = positions.get(&id)
                    && saved.unbroadcast
                {
                    gateway.restore_unbroadcast(saved.tx.wtxid());
                }
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
    Ok(RestoreReport {
        candidates: snapshot.transactions.len(),
        restored,
        skipped: snapshot.transactions.len().saturating_sub(restored),
        timed_out,
    })
}

#[cfg(test)]
mod tests;
