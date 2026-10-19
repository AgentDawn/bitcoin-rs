//! `verifychain` parameter boundaries and pre-delegation outcomes.
//!
//! The handler validates Core's signed parameters, honors handler shutdown,
//! and answers a tip without a verifier as unverified. The node-owned
//! verifier's answers, including the applied-genesis window, are proven
//! against the real verifier in `node` (`lifecycle` tests) and in
//! `chainstate::verify`; no stand-in verifier lives here.
#![expect(clippy::unwrap_used)]

use alloc::sync::Arc;

use super::*;
use crate::handlers::Handler;

/// A context whose applied tip is genesis, with no chain control attached.
fn tipped() -> Arc<Context> {
    let ctx = Context::new();
    let genesis = Network::Regtest.genesis_block();
    ctx.chain
        .block_tree
        .write()
        .insert_node(None, genesis.header, NodeStatus::Active)
        .unwrap();
    ctx.chain
        .applied_tip
        .store(ctx.chain.block_tree.read().tip());
    assert!(
        ctx.chain.applied_tip.load_full().is_some(),
        "the fixture must apply its tip"
    );
    Arc::new(ctx)
}

#[test]
fn parameters_follow_core_signed_ranges() {
    let handler = Handler::new(Arc::new(Context::new()));
    // No applied tip: nothing to verify, whatever the window.
    for params in [
        json!([]),
        json!([3, 6]),
        json!([0, 6]),
        json!([4, 0]),
        json!([-1, -1]),
        json!([null, null]),
        json!([5, 0]),
        json!([3, 2_147_483_647]),
    ] {
        let result = handler
            .dispatch("verifychain", &params)
            .unwrap_or_else(|err| panic!("verifychain{params:?} failed: {err}"));
        assert_eq!(result.as_bool(), Some(true), "{params:?}");
    }

    // Core reads both parameters with `getInt`: a non-number is a type
    // error, anything outside the signed 32-bit range is out of range.
    for params in [json!(["0"]), json!([0, false])] {
        assert_eq!(
            handler.dispatch("verifychain", &params).unwrap_err().code(),
            -3,
            "{params:?}"
        );
    }
    for params in [
        json!([2_147_483_648_i64]),
        json!([3, 2_147_483_648_i64]),
        json!([9, i64::MIN]),
        json!([0, -2_147_483_649_i64]),
        json!([0, 0.5]),
        json!([3, u64::from(u32::MAX) + 1]),
        json!([3, u64::MAX]),
    ] {
        assert_eq!(
            handler.dispatch("verifychain", &params).unwrap_err().code(),
            -1,
            "{params:?}"
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
fn cancelled_requests_report_interruption() {
    let handler = Handler::new(tipped());
    // The same request over the same applied tip answers `false` while the
    // handler runs (no verifier attached), so the error below is the
    // handler's own pre-dispatch interruption, not a verifier outcome.
    assert_eq!(
        handler.dispatch("verifychain", &json!([0, 0])).unwrap(),
        json!(false)
    );
    handler.stop();
    let error = handler.dispatch("verifychain", &json!([0, 0])).unwrap_err();
    assert_eq!(error.code(), -1);
    assert_eq!(error.to_string(), "Block verification interrupted");
}

#[test]
fn tip_without_control_is_not_verified() {
    let handler = Handler::new(tipped());
    for level in 0..=4 {
        assert_eq!(
            handler.dispatch("verifychain", &json!([level, 6])).unwrap(),
            json!(false),
            "level {level} without a verifier"
        );
    }
}
