use super::*;
use crate::{ChainAdmissionSnapshot, Mempool, MempoolLimits, PrevoutMeta};
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_primitives::{Amount, LockTime, OutPoint, Script, Sequence, TxIn, TxOut, Witness};
use parking_lot::{Mutex, RwLock};
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const NOW: u64 = 2_000_000;
const INTERRUPTED_STAGE: &str = "mempool-snapshot-interrupted.tmp";

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

struct Coins {
    outputs: Vec<(OutPoint, TxOut)>,
    height: u32,
    coinbase: bool,
}
impl AdmissionChain for Coins {
    fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
        Some(ChainAdmissionSnapshot {
            prevouts: self.outputs.clone(),
            height: self.height,
            prevout_meta: self
                .outputs
                .iter()
                .map(|(point, _)| {
                    (
                        *point,
                        PrevoutMeta {
                            height: 1,
                            mtp: 0,
                            coinbase: self.coinbase,
                        },
                    )
                })
                .collect(),
            ..Default::default()
        })
    }
}

#[derive(Default)]
struct Seen(Mutex<Vec<crate::MutationEnvelope>>);
impl crate::MempoolObserver for Seen {
    fn on_mutation(&self, batch: &crate::MutationEnvelope) {
        self.0.lock().push(batch.clone());
    }
}

fn gateway(limits: MempoolLimits, seen: Option<Arc<Seen>>) -> MempoolGateway {
    MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(limits))),
        seen.map(|observer| -> Arc<dyn crate::MempoolObserver> { observer }),
        ValidationEngine::Native,
    )
}

fn output(value: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: Script::from_bytes([vec![0, 32], Sha256::digest([0x51]).to_vec()].concat()),
    }
}

fn spend(point: OutPoint, value: u64) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: point,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0x51]]),
        }],
        outputs: vec![output(value)],
    }
}

fn family() -> (Coins, Tx, Tx) {
    let point = OutPoint::new(Txid(Hash256::from_le_bytes(&[7; 32])), 0);
    let parent = spend(point, 99_000);
    let child = spend(OutPoint::new(parent.txid(), 0), 98_000);
    (
        Coins {
            outputs: vec![(point, output(100_000))],
            height: 100,
            coinbase: true,
        },
        parent,
        child,
    )
}

fn admit(gateway: &MempoolGateway, tx: &Tx, chain: &dyn AdmissionChain) -> TestResult {
    gateway.submit_transaction(
        Arc::new(tx.clone()),
        AdmissionOrigin::Rpc,
        None,
        NOW - 10,
        chain,
    )?;
    Ok(())
}

// MPL-01/POL-02: restoration publishes actual gateway commits once, in parent
// order, and does not adopt saved fees, graph links or membership sequences.
#[test]
fn restores_dependencies_priorities_and_gateway_publication() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, child) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    admit(&source, &child, &chain)?;
    source.prioritise(parent.txid(), 500)?;
    let absent = Txid(Hash256::from_le_bytes(&[8; 32]));
    source.prioritise(absent, i64::MIN)?;
    let before_history = source.read().estimator_history();
    save(dir.path(), &source, Network::Regtest, deadline())?;
    let seen = Arc::new(Seen::default());
    let restored = gateway(MempoolLimits::default(), Some(Arc::clone(&seen)));
    crate::fee_history::save(dir.path(), &before_history);
    crate::fee_history::load(dir.path(), &restored.pool);
    let report = restore(
        dir.path(),
        &restored,
        Network::Regtest,
        &chain,
        NOW,
        deadline(),
    )?
    .ok_or("missing snapshot")?;
    assert_eq!(
        (
            report.candidates,
            report.restored,
            report.skipped,
            report.timed_out
        ),
        (2, 2, 0, false)
    );
    let pool = restored.read();
    let entry = pool.entry_by_txid(&child.txid()).ok_or("missing child")?;
    assert_eq!(
        (
            entry.ancestor_fee,
            entry.ancestor_fee_delta,
            entry.time,
            entry.height
        ),
        (2_000, 500, NOW - 10, 100)
    );
    assert_eq!(
        pool.entry_by_txid(&parent.txid())
            .ok_or("missing parent")?
            .fee_delta,
        500
    );
    assert!(
        pool.prioritised_transactions()
            .iter()
            .any(|row| row.txid == absent && row.fee_delta == i64::MIN)
    );
    assert!(
        pool.estimator_history() == before_history,
        "snapshot restore must not rewrite estimator state"
    );
    assert_eq!(
        Sha256::digest(std::fs::read(dir.path().join("fee-estimator-history.dat"))?),
        Sha256::digest(&before_history)
    );
    drop(pool);
    let batches = seen.0.lock();
    assert_eq!(batches.len(), 2);
    assert_eq!(
        batches[0].result.changes[0].txid,
        Hash256::from(parent.txid())
    );
    assert_eq!(
        batches[1].result.changes[0].txid,
        Hash256::from(child.txid())
    );
    assert!(
        batches
            .iter()
            .all(|batch| batch.origin == AdmissionOrigin::Snapshot)
    );
    assert_eq!(restored.orphan_count(), 0);
    assert_eq!(restored.recent_rejects_count(), 0);
    Ok(())
}

#[test]
fn rechecks_spent_coins_maturity_fee_floor_capacity_and_expiry() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, child) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    admit(&source, &child, &chain)?;
    save(dir.path(), &source, Network::Regtest, deadline())?;
    for (chain, limits, now) in [
        (
            Coins {
                outputs: vec![],
                height: 100,
                coinbase: false,
            },
            MempoolLimits::default(),
            NOW,
        ),
        (
            Coins {
                outputs: chain.outputs.clone(),
                height: 1,
                coinbase: true,
            },
            MempoolLimits::default(),
            NOW,
        ),
        (
            Coins {
                outputs: chain.outputs.clone(),
                height: 100,
                coinbase: true,
            },
            MempoolLimits {
                min_relay_fee_sat_per_kvb: 1_000_000,
                ..Default::default()
            },
            NOW,
        ),
        (
            Coins {
                outputs: chain.outputs.clone(),
                height: 100,
                coinbase: true,
            },
            MempoolLimits {
                max_total_bytes: 1,
                ..Default::default()
            },
            NOW,
        ),
        (
            Coins {
                outputs: chain.outputs,
                height: 100,
                coinbase: true,
            },
            MempoolLimits::default(),
            NOW + MAX_AGE + 1,
        ),
    ] {
        let pool = gateway(limits, None);
        let report = restore(dir.path(), &pool, Network::Regtest, &chain, now, deadline())?
            .ok_or("missing snapshot")?;
        assert_eq!(report.restored, 0);
        assert!(pool.read().is_empty());
        assert_eq!(pool.orphan_count(), 0);
    }
    // A confirmed parent no longer enters, while its child can use the live coin.
    let confirmed = Coins {
        outputs: vec![(OutPoint::new(parent.txid(), 0), parent.outputs[0].clone())],
        height: 101,
        coinbase: false,
    };
    let pool = gateway(MempoolLimits::default(), None);
    let report = restore(
        dir.path(),
        &pool,
        Network::Regtest,
        &confirmed,
        NOW,
        deadline(),
    )?
    .ok_or("missing snapshot")?;
    assert_eq!(report.restored, 1);
    assert!(!pool.read().contains_txid(&parent.txid()));
    assert!(pool.read().contains_txid(&child.txid()));
    Ok(())
}

#[test]
fn restores_cpfp_and_ephemeral_dust_through_atomic_package_admission() -> TestResult {
    for ephemeral in [false, true] {
        let dir = tempfile::tempdir()?;
        let (chain, mut parent, _) = family();
        parent.version = 3;
        parent.outputs[0].value = Amount::from_sat(100_000);
        if ephemeral {
            parent.outputs.push(output(0));
        }
        let mut child = spend(OutPoint::new(parent.txid(), 0), 98_000);
        child.version = 3;
        if ephemeral {
            let mut input = child.inputs[0].clone();
            input.previous_output.vout = 1;
            child.inputs.push(input);
        }
        let source = gateway(MempoolLimits::default(), None);
        source.submit_local_package(
            vec![child.clone(), parent.clone()],
            LocalOrigin::Rpc,
            None,
            NOW - 10,
            &chain,
        )?;
        save(dir.path(), &source, Network::Regtest, deadline())?;
        let seen = Arc::new(Seen::default());
        let target = gateway(MempoolLimits::default(), Some(Arc::clone(&seen)));
        let report = restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            deadline(),
        )?
        .ok_or("missing snapshot")?;
        assert_eq!(report.restored, 2);
        let batches = seen.0.lock();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].result.changes.len(), 2);
    }
    Ok(())
}

fn reseal(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let digest = Sha256::digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&digest);
}

#[test]
fn rejects_bad_artifacts_without_mutation_or_overwriting_operator_data() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, _) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    let valid = Snapshot::capture(&source, deadline())?.encode(Network::Regtest, deadline())?;
    let mut version = valid.clone();
    version[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    reseal(&mut version);
    let mut network = valid.clone();
    network[12] ^= 1;
    reseal(&mut network);
    let mut count = valid.clone();
    count[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
    reseal(&mut count);
    let mut length = valid.clone();
    length[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
    reseal(&mut length);
    let mut checksum = valid.clone();
    checksum[65] ^= 1;
    let mut trailing = valid.clone();
    trailing.insert(trailing.len() - 32, 0);
    reseal(&mut trailing);
    for bytes in [
        version,
        network,
        count,
        length,
        checksum,
        trailing,
        valid[..valid.len() - 1].to_vec(),
    ] {
        std::fs::write(dir.path().join(FILE_NAME), &bytes)?;
        let pool = gateway(MempoolLimits::default(), None);
        assert!(restore(dir.path(), &pool, Network::Regtest, &chain, NOW, deadline()).is_err());
        assert!(pool.read().is_empty());
        assert!(save(dir.path(), &source, Network::Regtest, deadline()).is_err());
        assert_eq!(std::fs::read(dir.path().join(FILE_NAME))?, bytes);
    }
    Ok(())
}

#[test]
fn interrupted_or_failed_save_preserves_the_complete_live_snapshot() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, _) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    save(dir.path(), &source, Network::Regtest, deadline())?;
    let before = std::fs::read(dir.path().join(FILE_NAME))?;
    let guard = source.pool.write();
    assert!(
        save(
            dir.path(),
            &source,
            Network::Regtest,
            Instant::now() + Duration::from_millis(2)
        )
        .is_err()
    );
    drop(guard);
    assert_eq!(std::fs::read(dir.path().join(FILE_NAME))?, before);
    std::fs::write(dir.path().join(INTERRUPTED_STAGE), b"interrupted write")?;
    let target = gateway(MempoolLimits::default(), None);
    assert_eq!(
        restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            deadline()
        )?
        .ok_or("missing")?
        .restored,
        1
    );
    // Unknown staging entries belong to the operator; only the writer's own
    // unique temporary file is ever cleaned up.
    std::fs::remove_file(dir.path().join(INTERRUPTED_STAGE))?;
    std::fs::create_dir(dir.path().join(INTERRUPTED_STAGE))?;
    let marker = dir.path().join(INTERRUPTED_STAGE).join("operator-data");
    std::fs::write(&marker, b"preserve")?;
    save(dir.path(), &source, Network::Regtest, deadline())?;
    assert_eq!(std::fs::read(dir.path().join(FILE_NAME))?, before);
    assert_eq!(std::fs::read(marker)?, b"preserve");
    assert!(save(dir.path(), &source, Network::Regtest, Instant::now()).is_err());
    assert_eq!(std::fs::read(dir.path().join(FILE_NAME))?, before);
    Ok(())
}

#[cfg(windows)]
#[test]
fn failed_atomic_replacement_keeps_the_previous_snapshot() -> TestResult {
    use std::os::windows::fs::OpenOptionsExt as _;
    let dir = tempfile::tempdir()?;
    let (chain, parent, child) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    save(dir.path(), &source, Network::Regtest, deadline())?;
    let path = dir.path().join(FILE_NAME);
    let before = std::fs::read(&path)?;
    // Permit reads but deny deletion/rename while the staging file is written.
    let guard = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&path)?;
    admit(&source, &child, &chain)?;
    assert!(save(dir.path(), &source, Network::Regtest, deadline()).is_err());
    drop(guard);
    assert_eq!(std::fs::read(&path)?, before);
    assert_eq!(std::fs::read_dir(dir.path())?.count(), 1);
    Ok(())
}

#[test]
fn missing_oversized_and_non_file_snapshots_fail_safely() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, _, _) = family();
    let pool = gateway(MempoolLimits::default(), None);
    assert!(restore(dir.path(), &pool, Network::Regtest, &chain, NOW, deadline())?.is_none());
    let path = dir.path().join(FILE_NAME);
    let file = std::fs::File::create(&path)?;
    file.set_len(MAX_BYTES + 1)?;
    drop(file);
    assert!(restore(dir.path(), &pool, Network::Regtest, &chain, NOW, deadline()).is_err());
    assert!(save(dir.path(), &pool, Network::Regtest, deadline()).is_err());
    assert_eq!(std::fs::metadata(&path)?.len(), MAX_BYTES + 1);
    std::fs::remove_file(&path)?;
    std::fs::create_dir(&path)?;
    std::fs::write(path.join("operator-data"), b"preserve")?;
    assert!(restore(dir.path(), &pool, Network::Regtest, &chain, NOW, deadline()).is_err());
    assert!(save(dir.path(), &pool, Network::Regtest, deadline()).is_err());
    assert_eq!(std::fs::read(path.join("operator-data"))?, b"preserve");
    Ok(())
}

#[test]
fn revalidates_witness_standardness_finality_and_only_saves_live_rbf_members() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, child) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    admit(&source, &child, &chain)?;
    let mut replacement = parent.clone();
    replacement.outputs[0].value = Amount::from_sat(90_000);
    admit(&source, &replacement, &chain)?;
    save(dir.path(), &source, Network::Regtest, deadline())?;
    let target = gateway(MempoolLimits::default(), None);
    let report = restore(
        dir.path(),
        &target,
        Network::Regtest,
        &chain,
        NOW,
        deadline(),
    )?
    .ok_or("missing")?;
    assert_eq!((report.candidates, report.restored), (1, 1));
    assert!(target.read().contains_txid(&replacement.txid()));
    assert!(!target.read().contains_txid(&parent.txid()));
    assert!(!target.read().contains_txid(&child.txid()));

    let mut invalid_witness = parent.clone();
    invalid_witness.inputs[0].witness = Witness::from_stack(vec![vec![0x00]]);
    let mut nonstandard = parent.clone();
    nonstandard.outputs[0].script_pubkey = Script::from_bytes(vec![0x51]);
    let mut nonfinal = parent;
    nonfinal.lock_time = LockTime::from_consensus(200);
    nonfinal.inputs[0].sequence = Sequence::from_consensus(0xffff_fffe);
    for tx in [invalid_witness, nonstandard, nonfinal] {
        let snapshot = Snapshot {
            transactions: vec![SavedTransaction {
                txid: tx.txid(),
                tx: Arc::new(tx),
                time: NOW - 10,
            }],
            deltas: vec![],
        };
        std::fs::write(
            dir.path().join(FILE_NAME),
            snapshot.encode(Network::Regtest, deadline())?,
        )?;
        let target = gateway(MempoolLimits::default(), None);
        let report = restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            deadline(),
        )?
        .ok_or("missing")?;
        assert_eq!((report.restored, report.skipped), (0, 1));
        assert_eq!(target.read().sequence_number(), 0);
    }
    Ok(())
}

#[test]
fn concurrent_admission_and_save_capture_a_coherent_candidate_set() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, child) = family();
    let source = Arc::new(gateway(MempoolLimits::default(), None));
    admit(&source, &parent, &chain)?;
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let writer = {
        let source = Arc::clone(&source);
        let barrier = Arc::clone(&barrier);
        let data_dir = dir.path().to_path_buf();
        std::thread::spawn(move || {
            barrier.wait();
            source
                .submit_transaction(
                    Arc::new(child),
                    AdmissionOrigin::Rpc,
                    None,
                    NOW - 10,
                    &chain,
                )
                .map_err(io::Error::other)?;
            save(&data_dir, &source, Network::Regtest, deadline())
        })
    };
    barrier.wait();
    let first = save(dir.path(), &source, Network::Regtest, deadline());
    let second = writer.join().map_err(|_| "admission thread panicked")?;
    assert!(first.is_ok() || second.is_ok());
    // Windows can refuse one overlapping replacement while the other writer's
    // file handle is closing. Refusal must still leave a complete live file.
    for result in [first, second] {
        #[cfg(windows)]
        if let Err(error) = result {
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
        #[cfg(not(windows))]
        result?;
    }
    let (chain, _, _) = family();
    let target = gateway(MempoolLimits::default(), None);
    let report = restore(
        dir.path(),
        &target,
        Network::Regtest,
        &chain,
        NOW,
        deadline(),
    )?
    .ok_or("missing")?;
    assert!((1..=2).contains(&report.candidates));
    assert_eq!(report.restored, report.candidates);
    assert!(target.read().contains_txid(&parent.txid()));
    Ok(())
}
