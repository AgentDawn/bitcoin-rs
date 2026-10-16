use std::str::FromStr as _;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use bitcoin_rs_mining::{MempoolSequenceWake, MiningControl, MiningControlError};
use bitcoin_rs_node::{
    MiningCoordinator, MiningOverrides, Network, NetworkSelection, UserConfig, resolve,
    state::NodeState,
};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use compact_str::CompactString;
use crossbeam_channel::bounded;
use parking_lot::Mutex;

use super::support::{
    advance_mempool_sequence, coordinator, expect_template, mined_child, open_at_genesis,
    regtest_mining, template_request, to_lower_hex,
};

#[test]
fn cache_reuses_candidate_for_identical_generation_key() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();

    let first = expect_template(mining.get_block_template(template_request(None))?);
    let second = expect_template(mining.get_block_template(template_request(None))?);
    assert_eq!(
        first.candidate.template_id.as_str(),
        second.candidate.template_id.as_str()
    );
    assert!(
        Arc::ptr_eq(&first.candidate, &second.candidate),
        "identical generation must reuse the cached candidate arc"
    );
    Ok(())
}

#[test]
fn watch_only_payout_lands_in_candidate_coinbase() -> Result<()> {
    const ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let dir = tempfile::tempdir()?;
    let layer = UserConfig {
        network: Some(NetworkSelection::Regtest),
        mining: MiningOverrides {
            payout_address: Some(ADDRESS.to_owned()),
        },
        ..Default::default()
    };
    let mut config = resolve(&[&layer])?;
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    std::mem::forget(dir);
    let state = NodeState::open(config, None)?;
    let _ = state.apply_block(&Network::Regtest.genesis_block())?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let template = expect_template(mining.get_block_template(template_request(None))?);
    let expected = bitcoin::Address::from_str(ADDRESS)?
        .require_network(bitcoin::Network::Regtest)?
        .script_pubkey()
        .as_bytes()
        .to_vec();
    assert_eq!(
        template.candidate.coinbase.outputs[0].script_pubkey, expected,
        "configured watch-only payout must be the candidate coinbase script"
    );
    Ok(())
}

#[test]
fn network_hash_ps_answers_on_the_applied_tip() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let genesis_rate = mining.network_hash_ps(120, -1)?;
    assert!(
        genesis_rate.abs() < f64::EPSILON,
        "genesis has no lookback window, got {genesis_rate}"
    );
    let genesis_height_rate = mining.network_hash_ps(120, 0)?;
    assert!(
        genesis_height_rate.abs() < f64::EPSILON,
        "Core reports 0 at the genesis height, got {genesis_height_rate}"
    );
    Ok(())
}

#[test]
// CONTRACT: docs/contracts/external-api.md#API-06
fn network_hash_ps_rejects_core_invalid_windows() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    match mining.network_hash_ps(0, -1) {
        Err(MiningControlError::InvalidRequest(message)) => {
            assert_eq!(
                message.as_str(),
                "Invalid nblocks. Must be a positive number or -1."
            );
        }
        other => panic!("nblocks 0 must be invalid, got {other:?}"),
    }
    match mining.network_hash_ps(-2, -1) {
        Err(MiningControlError::InvalidRequest(message)) => {
            assert_eq!(
                message.as_str(),
                "Invalid nblocks. Must be a positive number or -1."
            );
        }
        other => panic!("nblocks -2 must be invalid, got {other:?}"),
    }
    match mining.network_hash_ps(120, -10) {
        Err(MiningControlError::InvalidRequest(message)) => {
            assert_eq!(message.as_str(), "Block does not exist at specified height");
        }
        other => panic!("height -10 must be invalid, got {other:?}"),
    }
    match mining.network_hash_ps(120, 1) {
        Err(MiningControlError::InvalidRequest(message)) => {
            assert_eq!(message.as_str(), "Block does not exist at specified height");
        }
        other => panic!("height above the tip must be invalid, got {other:?}"),
    }
    Ok(())
}

#[test]
fn key_invalidation_rebuilds_after_mempool_sequence_change() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let first = expect_template(mining.get_block_template(template_request(None))?);

    advance_mempool_sequence(&state)?;
    mining.publish_generation();
    let second = expect_template(mining.get_block_template(template_request(None))?);
    assert_ne!(
        first.candidate.template_id.as_str(),
        second.candidate.template_id.as_str(),
        "mempool sequence change must invalidate the generation key"
    );
    assert!(!Arc::ptr_eq(&first.candidate, &second.candidate));
    Ok(())
}

#[test]
fn concurrent_requests_share_single_flight_assembly() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let mining = Arc::new(mining);
    mining.publish_generation();

    let barrier = Arc::new(std::sync::Barrier::new(8));
    let candidates = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let mining = Arc::clone(&mining);
        let barrier = Arc::clone(&barrier);
        let candidates = Arc::clone(&candidates);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let template = expect_template(
                mining
                    .get_block_template(template_request(None))
                    .unwrap_or_else(|error| panic!("template failed: {error}")),
            );
            candidates.lock().push(Arc::clone(&template.candidate));
        }));
    }
    for handle in handles {
        handle.join().unwrap_or_else(|_| panic!("worker panicked"));
    }
    let candidates = candidates.lock();
    let first = &candidates[0];
    assert!(
        candidates
            .iter()
            .all(|candidate| Arc::ptr_eq(candidate, first)),
        "all concurrent waiters must observe the same single-flight candidate"
    );
    Ok(())
}

#[test]
fn long_poll_wakes_on_tip_change() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    let mining = Arc::new(mining);
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
    let (started_tx, started_rx) = bounded::<()>(1);
    let mining_wait = Arc::clone(&mining);
    let waiter = thread::spawn(move || {
        started_tx
            .send(())
            .unwrap_or_else(|error| panic!("start signal failed: {error}"));
        mining_wait.get_block_template(template_request(Some(long_poll_id)))
    });
    started_rx.recv_timeout(Duration::from_secs(2))?;
    thread::sleep(Duration::from_millis(50));
    let genesis = Network::Regtest.genesis_block();
    let child = mined_child(genesis.block_hash())?;
    let _ = state.apply_block(&child)?;
    mining.publish_generation();
    let result = waiter
        .join()
        .unwrap_or_else(|_| panic!("long-poll waiter panicked"))
        .unwrap_or_else(|error| panic!("long poll failed: {error}"));
    let template = expect_template(result);
    assert_ne!(
        template.candidate.template_id.as_str(),
        current.candidate.template_id.as_str()
    );
    let child_hash = Hash256::from_le_bytes(child.block_hash().as_bytes());
    assert_eq!(template.candidate.previous_block_hash, child_hash);
    assert_eq!(template.submit_old, Some(false));
    assert_eq!(
        template.rules.iter().any(|rule| rule.as_str() == "csv"),
        template.candidate.csv_active
    );
    assert_eq!(
        template.rules.iter().any(|rule| rule.as_str() == "segwit"),
        template.candidate.segwit_active
    );
    Ok(())
}

#[test]
fn long_poll_wakes_on_mempool_sequence_change() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    let mining = Arc::new(mining);
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
    let (started_tx, started_rx) = bounded::<()>(1);
    let mining_wait = Arc::clone(&mining);
    let waiter = thread::spawn(move || {
        started_tx
            .send(())
            .unwrap_or_else(|error| panic!("start signal failed: {error}"));
        mining_wait.get_block_template(template_request(Some(long_poll_id)))
    });
    started_rx.recv_timeout(Duration::from_secs(2))?;
    thread::sleep(Duration::from_millis(50));
    advance_mempool_sequence(&state)?;
    mining.publish_generation();
    let result = waiter
        .join()
        .unwrap_or_else(|_| panic!("mempool long-poll waiter panicked"))
        .unwrap_or_else(|error| panic!("mempool long poll failed: {error}"));
    let template = expect_template(result);
    assert_ne!(
        template.candidate.mempool_sequence,
        current.candidate.mempool_sequence
    );
    assert_eq!(
        template.candidate.previous_block_hash,
        current.candidate.previous_block_hash
    );
    assert_eq!(template.submit_old, Some(true));
    Ok(())
}

#[test]
fn shutdown_ends_long_poll_without_wake() -> Result<()> {
    let state = open_at_genesis(Network::Regtest)?;
    let shutdown = state.shutdown();
    let mining = Arc::new(MiningCoordinator::new(
        state.mempool_reader(),
        state.chainstate(),
        state.stable_read(),
        state.chain_followers(),
        state.config().mining.payout_script.clone(),
    ));
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
    let mining_wait = Arc::clone(&mining);
    let waiter =
        thread::spawn(move || mining_wait.get_block_template(template_request(Some(long_poll_id))));
    thread::sleep(Duration::from_millis(50));
    // Bounded wait slices must observe the flag even without a direct wake:
    // correctness does not depend on a wake notification, so the coordinator
    // carries none.
    shutdown.store(true, Ordering::Release);
    let outcome = waiter
        .join()
        .unwrap_or_else(|_| panic!("shutdown waiter panicked"));
    let Err(err) = outcome else {
        panic!("shutdown wait unexpectedly succeeded");
    };
    assert!(matches!(err, MiningControlError::Unavailable(_)));
    Ok(())
}

#[test]
fn mining_info_reports_default_signet_challenge() -> Result<()> {
    let state = open_at_genesis(Network::Signet)?;
    let mining = coordinator(&state);
    let info = mining.mining_info()?;
    let Some(signet) = info.signet.as_ref() else {
        panic!("default Signet did not expose challenge metadata");
    };
    assert_eq!(
        to_lower_hex(&signet.challenge),
        concat!(
            "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430",
            "210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae",
        )
    );
    Ok(())
}

#[test]
fn mining_info_omits_signet_on_regtest() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let info = mining.mining_info()?;
    assert!(info.signet.is_none());
    Ok(())
}

#[test]
fn mining_info_reports_network_hashps_after_genesis() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let info = mining.mining_info()?;
    assert_eq!(info.blocks, 0);
    assert!(
        info.network_hashes_per_second.is_finite(),
        "hashps must be a finite projection"
    );
    Ok(())
}

#[test]
fn last_candidate_counts_include_the_coinbase() -> Result<()> {
    use bitcoin_rs_mempool::MempoolEntry;

    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let empty = expect_template(mining.get_block_template(template_request(None))?);
    let empty_info = mining.mining_info()?;
    assert!(empty.candidate.transactions.is_empty());
    assert_eq!(
        empty_info.last_candidate.map(|info| info.transactions),
        Some(1)
    );

    let tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x42; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    };
    {
        let mempool = state.mempool();
        let mut guard = mempool.write();
        guard.insert_entry(MempoolEntry::new(Arc::new(tx), 120, 10_000, 1, 1, 0))?;
    }
    mining.publish_generation();
    let one = expect_template(mining.get_block_template(template_request(None))?);
    let one_info = mining.mining_info()?;
    assert_eq!(one.candidate.transactions.len(), 1);
    assert_eq!(
        one_info.last_candidate.map(|info| info.transactions),
        Some(2)
    );
    Ok(())
}

/// Two threads looping `publish_generation` (tip path) and
/// `publish_generation_from` (mempool path) must not deadlock within a 200 ms
/// watchdog.
#[test]
fn concurrent_publish_generation_paths_do_not_deadlock() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let mining = Arc::new(mining);

    let stop = Arc::new(AtomicBool::new(false));

    let (tip_done_tx, tip_done_rx) = bounded::<()>(1);
    let mining_tip = Arc::clone(&mining);
    let stop_tip = Arc::clone(&stop);
    let tip_thread = thread::spawn(move || {
        while !stop_tip.load(Ordering::Relaxed) {
            mining_tip.publish_generation();
        }
        let _ = tip_done_tx.send(());
    });

    let (seq_done_tx, seq_done_rx) = bounded::<()>(1);
    let mining_seq = Arc::clone(&mining);
    let stop_seq = Arc::clone(&stop);
    let seq_thread = thread::spawn(move || {
        let mut seq = 1_u64;
        while !stop_seq.load(Ordering::Relaxed) {
            mining_seq.publish_generation_from(seq);
            seq = seq.wrapping_add(1);
        }
        let _ = seq_done_tx.send(());
    });

    // 200 ms watchdog — if either thread is stuck, the joins below time out.
    thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);

    tip_done_rx
        .recv_timeout(Duration::from_millis(500))
        .map_err(|_| anyhow::anyhow!("tip publish_generation thread deadlocked"))?;
    seq_done_rx
        .recv_timeout(Duration::from_millis(500))
        .map_err(|_| anyhow::anyhow!("sequence publish_generation_from thread deadlocked"))?;

    tip_thread
        .join()
        .unwrap_or_else(|_| panic!("tip publish_generation thread panicked"));
    seq_thread
        .join()
        .unwrap_or_else(|_| panic!("sequence publish_generation_from thread panicked"));
    Ok(())
}

/// `publish_generation_from` must not take the mempool read lock: holding the
/// pool write lock and calling it must return immediately, not deadlock.
#[test]
fn publish_generation_from_does_not_take_mempool_lock() -> Result<()> {
    let (state, mining) = regtest_mining()?;

    // Hold the mempool write lock for the duration of the call — a reentrant
    // read would deadlock (parking_lot RwLock is not reentrant).
    let mempool = state.mempool();
    let _write_guard = mempool.write();

    let (done_tx, done_rx) = bounded::<()>(1);
    let handle = thread::spawn(move || {
        mining.publish_generation_from(1);
        let _ = done_tx.send(());
    });

    done_rx
        .recv_timeout(Duration::from_millis(200))
        .map_err(|_| {
            anyhow::anyhow!(
                "publish_generation_from deadlocked under the mempool write lock \
                 — it must not take the mempool read lock"
            )
        })?;
    handle
        .join()
        .unwrap_or_else(|_| panic!("publish_generation_from thread panicked"));
    Ok(())
}

/// A long-poll waiter must return in well under 1 s after a mempool-sequence
/// wake, even when `mempool_update_wait` is non-zero. The waiter returns as
/// soon as the published generation key differs from the waited key — no
/// `LONG_POLL_SLICE` (1 s) recheck delay.
#[test]
fn long_poll_returns_quickly_on_mempool_sequence_wake() -> Result<()> {
    let state = open_at_genesis(Network::Regtest)?;

    // Non-zero cooldown: the old code would wait up to `mempool_update_wait`
    // before returning on a mempool-only change. The fix returns immediately.
    let mining = Arc::new(MiningCoordinator::new(
        state.mempool_reader(),
        state.chainstate(),
        state.stable_read(),
        state.chain_followers(),
        state.config().mining.payout_script.clone(),
    ));
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let long_poll_id = CompactString::from(current.candidate.template_id.as_str());

    let (started_tx, started_rx) = bounded::<()>(1);
    let (done_tx, done_rx) = bounded(1);
    let mining_wait = Arc::clone(&mining);
    let waiter = thread::spawn(move || {
        started_tx
            .send(())
            .unwrap_or_else(|error| panic!("start signal failed: {error}"));
        let result = mining_wait.get_block_template(template_request(Some(long_poll_id)));
        let _ = done_tx.send(result);
    });

    started_rx.recv_timeout(Duration::from_secs(2))?;
    // Scheduling aid only: the start signal does not prove entry into the wait.
    thread::sleep(Duration::from_millis(50));

    // Advance the mempool sequence and wake via the lock-free path.
    advance_mempool_sequence(&state)?;
    let seq = state.mempool().read().sequence_number();
    let wake_start = std::time::Instant::now();
    mining.publish_generation_from(seq);

    let result = done_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|error| anyhow::anyhow!("mempool long-poll waiter did not complete: {error}"))?;
    let elapsed = wake_start.elapsed();
    waiter
        .join()
        .unwrap_or_else(|_| panic!("mempool long-poll waiter panicked"));
    let result = result.unwrap_or_else(|error| panic!("mempool long poll failed: {error}"));

    assert!(
        elapsed < Duration::from_millis(800),
        "long-poll waiter returned in {elapsed:?}, expected well under 1 s"
    );
    let template = expect_template(result);
    assert_ne!(
        template.candidate.mempool_sequence,
        current.candidate.mempool_sequence
    );
    assert_eq!(
        template.candidate.previous_block_hash,
        current.candidate.previous_block_hash
    );
    assert_eq!(template.submit_old, Some(true));
    Ok(())
}

/// CONTRACT: API-06 — getmininginfo's networkhashps mirrors the default
/// getnetworkhashps window.
#[test]
fn network_hash_ps_matches_mining_info_default_window() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let info = mining.mining_info()?;
    let rate = mining.network_hash_ps(120, -1)?;
    assert!(
        (rate - info.network_hashes_per_second).abs() < f64::EPSILON,
        "default-window hash rate must match mining info: {rate} vs {}",
        info.network_hashes_per_second
    );
    Ok(())
}
