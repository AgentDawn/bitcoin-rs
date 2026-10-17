//! Public verification outcomes over real mined bodies and explicit read failures.
#![expect(clippy::expect_used, clippy::unwrap_used)]

use super::*;
use crate::handlers::Handler;
use bitcoin_rs_chain::{BlockBodyReadError, BlockBodySource, regtest_fixture};
use bitcoin_rs_primitives::{OutPoint, Tx, Txid};
use parking_lot::Mutex;

type BodyRead = Result<Option<Vec<u8>>, BlockBodyReadError>;

// The signal comes from a failed timed lock attempt, on this worker only.
// No hook or additional synchronization state exists in production builds.
std::thread_local! {
    static LOCK_WAIT: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> =
        const { std::cell::RefCell::new(None) };
}

pub(super) fn notify_lock_wait() {
    LOCK_WAIT.with(|slot| {
        if let Some(signal) = slot.borrow_mut().take() {
            signal.send(()).expect("test must observe lock contention");
        }
    });
}

struct Source {
    bodies: Mutex<Vec<(BlockHash, BodyRead)>>,
    during_read: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl BlockBodySource for Source {
    fn block_body(&self, height: u32, hash: BlockHash) -> BodyRead {
        let action = self.during_read.lock().take();
        if let Some(action) = action {
            action();
        }
        let bodies = self.bodies.lock();
        let (expected, bytes) = bodies
            .get(usize::try_from(height).unwrap())
            .expect("verification must not read above the fixture's applied height");
        assert_eq!(
            hash, *expected,
            "verification must follow the captured ancestry"
        );
        bytes.clone()
    }
}

fn fixture() -> (Arc<Context>, Arc<Source>) {
    fixture_with_tip(vec![regtest_fixture::coinbase(3)])
}

fn fixture_with_tip(txs: Vec<Tx>) -> (Arc<Context>, Arc<Source>) {
    let mut ctx = Context::new();
    ctx.chain.chain_network = Network::Regtest;
    let mut blocks = vec![Network::Regtest.genesis_block()];
    for height in 1..=2 {
        blocks.push(
            regtest_fixture::mined_regtest_child_at(blocks.last().unwrap().block_hash(), height)
                .unwrap(),
        );
    }
    blocks.push(
        regtest_fixture::mined_block_with_prev_hash(blocks.last().unwrap().block_hash(), 3, txs)
            .unwrap(),
    );
    let source = Arc::new(Source {
        bodies: Mutex::new(
            blocks
                .iter()
                .map(|block| (block.block_hash(), Ok(Some(consensus_bytes(block)))))
                .collect(),
        ),
        during_read: Mutex::new(None),
    });
    let mut parent = None;
    for (height, block) in blocks.iter().enumerate() {
        parent = Some(
            ctx.chain
                .block_tree
                .write()
                .insert_node(parent, block.header, NodeStatus::Active)
                .unwrap(),
        );
        ctx.chain.add_block(BlockRecord::from_block(
            u32::try_from(height).unwrap(),
            block,
        ));
    }
    ctx.chain
        .applied_tip
        .store(ctx.chain.block_tree.read().tip());
    ctx.chain.block_body_source = Some(source.clone());
    (Arc::new(ctx), source)
}

#[test]
fn level_one_checks_transaction_rules_after_header_and_merkle_authentication() {
    let mut short_coinbase = regtest_fixture::coinbase(3);
    short_coinbase.inputs[0].script_sig = Script::from_bytes(vec![0]);
    let mut overflowing = regtest_fixture::coinbase(3);
    overflowing.outputs[0].value = Amount::from_sat(Amount::MAX_MONEY.to_sat() + 1);
    let mut duplicate = regtest_fixture::coinbase(3);
    duplicate.inputs[0].previous_output = OutPoint::new(Txid(Hash256::from_le_bytes(&[1; 32])), 0);
    duplicate.inputs.push(duplicate.inputs[0].clone());
    let mut sigops = regtest_fixture::coinbase(3);
    sigops.outputs[0].script_pubkey =
        Script::from_bytes(vec![bitcoin_rs_script::opcode::OP_CHECKSIG; 20_001]);
    for txs in [
        vec![short_coinbase],
        vec![overflowing],
        vec![regtest_fixture::coinbase(3), duplicate],
        vec![sigops],
    ] {
        let (ctx, source) = fixture_with_tip(txs);
        let tip = ctx.chain.applied_tip.load_full().unwrap();
        let before = source.bodies.lock().clone();
        let handler = Handler::new(ctx.clone());
        assert_eq!(
            handler.dispatch("verifychain", &json!([0, 1])).unwrap(),
            json!(true)
        );
        for level in 1..=4 {
            assert_eq!(
                handler.dispatch("verifychain", &json!([level, 1])).unwrap(),
                json!(false)
            );
        }
        assert!(Arc::ptr_eq(
            &tip,
            &ctx.chain.applied_tip.load_full().unwrap()
        ));
        for (original, after) in before.iter().zip(source.bodies.lock().iter()) {
            assert_eq!(original.0, after.0);
            assert_eq!(original.1.as_ref().unwrap(), after.1.as_ref().unwrap());
        }
    }
}

#[test]
fn complete_window_and_level_zero_require_real_readable_blocks() {
    let (ctx, source) = fixture();
    let handler = Handler::new(ctx);
    for params in [
        json!([]),
        json!([0, 1]),
        json!([2, 0]),
        json!([4, -1]),
        json!([-1, 100]),
    ] {
        assert_eq!(
            handler.dispatch("verifychain", &params).unwrap(),
            json!(true)
        );
    }
    // Corruption below the requested one-block suffix is not part of that
    // verification. Zero/negative depth and oversized windows must find it.
    source.bodies.lock()[1].1 = Ok(Some(vec![1, 2, 3]));
    assert_eq!(
        handler.dispatch("verifychain", &json!([2, 1])).unwrap(),
        json!(true)
    );
    for level in 0..=4 {
        for depth in [0, -1, 3, 100] {
            assert_eq!(
                handler
                    .dispatch("verifychain", &json!([level, depth]))
                    .unwrap(),
                json!(false)
            );
        }
    }
}

#[test]
fn merkle_and_stored_header_corruption_cannot_pass() {
    let (ctx, source) = fixture();
    let handler = Handler::new(ctx);
    let bytes = source.bodies.lock()[3].1.clone().unwrap().unwrap();
    let mut block: Block = deserialize(&bytes).unwrap();
    block.txs[0].outputs[0].value = Amount::from_sat(1);
    source.bodies.lock()[3].1 = Ok(Some(consensus_bytes(&block)));
    // Level zero authenticates the serialized header, not the Merkle tree.
    assert_eq!(
        handler.dispatch("verifychain", &json!([0, 1])).unwrap(),
        json!(true)
    );
    for level in 1..=4 {
        assert_eq!(
            handler.dispatch("verifychain", &json!([level, 1])).unwrap(),
            json!(false)
        );
    }
    block.header.time += 1;
    source.bodies.lock()[3].1 = Ok(Some(consensus_bytes(&block)));
    assert_eq!(
        handler.dispatch("verifychain", &json!([0, 1])).unwrap(),
        json!(false)
    );
}

#[test]
fn corrupt_stored_frame_is_false_at_every_level() {
    let (ctx, source) = fixture();
    let handler = Handler::new(ctx);
    source.bodies.lock()[1].1 = Err(BlockBodyReadError::Corrupt("truncated frame".to_owned()));
    for level in 0..=4 {
        assert_eq!(
            handler.dispatch("verifychain", &json!([level, 1])).unwrap(),
            json!(true)
        );
        assert_eq!(
            handler.dispatch("verifychain", &json!([level, 0])).unwrap(),
            json!(false)
        );
    }
}

#[test]
fn unavailable_history_and_io_failure_are_explicit_incomplete_results() {
    let (ctx, source) = fixture();
    let handler = Handler::new(ctx);
    // None can mean pruned or not-yet-imported snapshot history. It proves
    // neither corruption nor completion, even after a valid suffix was read.
    source.bodies.lock()[1].1 = Ok(None);
    assert_eq!(
        handler.dispatch("verifychain", &json!([2, 2])).unwrap(),
        json!(true)
    );
    let error = handler.dispatch("verifychain", &json!([0, 0])).unwrap_err();
    assert_eq!(error.code(), -1);
    assert!(
        error
            .to_string()
            .contains("Block data unavailable at height 1")
    );
    source.bodies.lock()[1].1 = Err(BlockBodyReadError::Read("injected I/O failure".to_owned()));
    let error = handler.dispatch("verifychain", &json!([2, 0])).unwrap_err();
    assert_eq!(error.code(), -1);
    assert!(
        error
            .to_string()
            .contains("Unable to read block at height 1: injected I/O failure")
    );
}

#[test]
fn genesis_only_is_empty_but_snapshot_ancestry_is_not() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(ctx.clone());
    assert_eq!(
        handler.dispatch("verifychain", &json!([0, 0])).unwrap(),
        json!(true)
    );
    // A snapshot publication without its ancestry must not look like genesis.
    ctx.chain
        .applied_tip
        .store(Some(Arc::new(bitcoin_rs_chain::TipSnapshot {
            tip_id: bitcoin_rs_chain::NodeId::new(500),
            height: 500,
            chainwork: bitcoin_rs_chain::ChainWork::ZERO,
            hash: Hash256::default(),
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
        })));
    let error = handler.dispatch("verifychain", &json!([0, 0])).unwrap_err();
    assert_eq!(error.code(), -1);
    assert!(error.to_string().contains("ancestry unavailable"));

    let (mut ctx, _) = fixture();
    Arc::get_mut(&mut ctx).unwrap().chain.block_body_source = None;
    let error = Handler::new(ctx)
        .dispatch("verifychain", &json!([0, 0]))
        .unwrap_err();
    assert_eq!(error.code(), -1);
    assert!(error.to_string().contains("reader unavailable"));
}

#[test]
fn shutdown_and_changed_tip_cannot_report_completion() {
    for change in 0..3 {
        let (ctx, source) = fixture();
        let handler = Arc::new(Handler::new(ctx.clone()));
        let weak_handler = Arc::downgrade(&handler);
        *source.during_read.lock() = Some(Box::new(move || {
            let handler = weak_handler.upgrade().unwrap();
            if change == 0 {
                handler.stop();
            } else {
                let mut tip = (*handler.context().chain.applied_tip.load_full().unwrap()).clone();
                // Same-height replacement and advancement both invalidate the
                // captured publication. This also exercises the final-body race.
                if change == 2 {
                    tip.height += 1;
                }
                tip.hash = Hash256::from_le_bytes(&[42; 32]);
                handler
                    .context()
                    .chain
                    .applied_tip
                    .store(Some(Arc::new(tip)));
            }
        }));
        let error = handler.dispatch("verifychain", &json!([0, 1])).unwrap_err();
        assert_eq!(error.code(), -1);
        assert!(error.to_string().contains(if change == 0 {
            "interrupted"
        } else {
            "chain changed"
        }));
    }
}

#[test]
#[expect(
    clippy::redundant_closure_for_method_calls,
    reason = "the method item cannot satisfy with_stable_view's higher-ranked lifetime"
)]
fn failure_and_cancellation_leave_chain_and_coins_untouched() {
    let (ctx, source) = fixture();
    let handler = Arc::new(Handler::new(ctx.clone()));
    let tip = ctx.chain.applied_tip.load_full();
    let coins = ctx
        .chain
        .utxo
        .with_stable_view(|view| view.hash_serialized_3())
        .unwrap();
    source.bodies.lock()[3].1 = Ok(Some(vec![1, 2, 3]));
    assert_eq!(
        handler.dispatch("verifychain", &json!([0, 1])).unwrap(),
        json!(false)
    );
    handler.stop();
    assert_eq!(
        handler
            .dispatch("verifychain", &json!([0, 1]))
            .unwrap_err()
            .code(),
        -1
    );
    assert_eq!(ctx.chain.applied_tip.load_full(), tip);
    assert_eq!(
        ctx.chain
            .utxo
            .with_stable_view(|view| view.hash_serialized_3())
            .unwrap(),
        coins
    );
    assert_eq!(
        source.bodies.lock()[3].1.as_ref().unwrap().as_deref(),
        Some(&[1, 2, 3][..])
    );
}

#[test]
fn parameters_use_signed_core_ranges_without_silent_defaults() {
    let handler = Handler::new(Arc::new(Context::new()));
    for params in [
        json!([]),
        json!([null, null]),
        json!([-1, -1]),
        json!([5, 0]),
    ] {
        assert_eq!(
            handler.dispatch("verifychain", &params).unwrap(),
            json!(true)
        );
    }
    for params in [json!(["0"]), json!([0, false])] {
        assert_eq!(
            handler.dispatch("verifychain", &params).unwrap_err().code(),
            -3
        );
    }
    for params in [
        json!([2_147_483_648_i64]),
        json!([0, -2_147_483_649_i64]),
        json!([0, 0.5]),
    ] {
        assert_eq!(
            handler.dispatch("verifychain", &params).unwrap_err().code(),
            -1
        );
    }
    assert_eq!(
        handler
            .dispatch("verifychain", &json!([0, 0, 0]))
            .unwrap_err()
            .code(),
        -32602
    );
}

#[test]
fn shutdown_does_not_wait_for_a_chain_transition_or_tree_writer() {
    for block_tree in [false, true] {
        let (mut ctx, _) = fixture();
        let domain = bitcoin_rs_chain::TransitionDomain::new();
        Arc::get_mut(&mut ctx).unwrap().chain.chain_transition = domain.stable_read();
        let authority = domain.authority();
        let _transition = (!block_tree).then(|| authority.lock());
        let _tree = block_tree.then(|| ctx.chain.block_tree.write());
        let handler = Arc::new(Handler::new(ctx.clone()));
        let worker = handler.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let (waiting, observed_wait) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            LOCK_WAIT.with(|slot| *slot.borrow_mut() = Some(waiting));
            send.send(worker.dispatch("verifychain", &json!([0, 0])))
                .unwrap();
        });
        observed_wait
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("worker must reach the contended lock before shutdown");
        handler.stop();
        let error = receive
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("shutdown must not wait for the writer to release")
            .unwrap_err();
        assert_eq!(error.to_string(), "Block verification interrupted");
        task.join().unwrap();
    }
}

#[test]
fn applied_window_ignores_a_higher_header_tip_and_recovery_refuses_reads() {
    let (mut ctx, source) = fixture();
    let closed = Arc::new(core::sync::atomic::AtomicBool::new(false));
    Arc::get_mut(&mut ctx).unwrap().chain.closed_for_recovery = closed.clone().into();
    let mut applied = (*ctx.chain.applied_tip.load_full().unwrap()).clone();
    ctx.chain.chain_tip.store(Some(Arc::new(applied.clone())));
    {
        let tree = ctx.chain.block_tree.read();
        let node = tree
            .node(tree.node(applied.tip_id).unwrap().parent.unwrap())
            .unwrap();
        applied.tip_id = tree.lookup(node.hash).unwrap();
        applied.height = node.height;
        applied.hash = node.hash;
    }
    ctx.chain.applied_tip.store(Some(Arc::new(applied)));
    source.bodies.lock()[3].1 = Ok(Some(vec![1, 2, 3]));
    let handler = Handler::new(ctx);
    assert_eq!(
        handler.dispatch("verifychain", &json!([2, 0])).unwrap(),
        json!(true)
    );
    closed.store(true, core::sync::atomic::Ordering::Release);
    let error = handler.dispatch("verifychain", &json!([0, 0])).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Chainstate is unavailable for verification"
    );
}
