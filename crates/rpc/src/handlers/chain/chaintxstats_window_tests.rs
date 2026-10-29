use alloc::sync::Arc;

use bitcoin_rs_chain::NodeStatus;
use sonic_rs::{JsonValueTrait, json};

use super::*;

const REGTEST_BITS: u32 = 0x207f_ffff;

/// Timestamps that are not in order, because block times are not.
///
/// A miner only has to beat the median of the previous eleven blocks, so a
/// header may be stamped earlier than its parent. These dip twice, which is
/// what separates a median-time window from a raw-timestamp one.
const TIMES: [u32; 13] = [
    1_000_000, 1_000_600, 1_001_200, 1_000_900, 1_002_400, 1_003_000, 1_002_100, 1_004_200,
    1_004_800, 1_005_400, 1_006_000, 1_005_100, 1_007_200,
];

/// Bitcoin Core's `GetMedianTimePast`, written out rather than borrowed.
///
/// The median of the block and its ten ancestors. A reference that called the
/// block tree could not disagree with the block tree.
fn median_time_past(times: &[u32], height: usize) -> u32 {
    let start = height.saturating_sub(10);
    let mut window = times[start..=height].to_vec();
    window.sort_unstable();
    window[window.len() / 2]
}

fn header(previous: BlockHash, time: u32, nonce: u32) -> Header {
    Header {
        version: 1,
        prev_blockhash: previous,
        merkle_root: Hash256::default(),
        time,
        bits: CompactTarget::from_consensus(REGTEST_BITS),
        nonce,
    }
}

/// A node whose active chain carries `times`, in both the tree and the log.
///
/// Each block is given `height + 1` transactions, so a window sum is a
/// number the test can state in closed form.
fn chain_ctx(times: &[u32]) -> Arc<Context> {
    chain_ctx_with_counter(times, None)
}

/// [`chain_ctx`], with the node's durable cumulative counter set.
///
/// The counter tracks the applied tip and nothing else, so a fixture that
/// leaves it unset cannot tell "the shortcut is restricted to the tip" from
/// "there is no shortcut to take".
fn chain_ctx_with_counter(times: &[u32], chain_tx_count: Option<u64>) -> Arc<Context> {
    let ctx = Arc::new(Context::new());
    let mut previous = BlockHash::default();
    let mut parent = None;
    let mut tip = None;
    for (index, &time) in times.iter().enumerate() {
        let height = u32::try_from(index).unwrap_or(u32::MAX);
        let candidate = header(previous, time, height);
        previous = candidate.compute_hash();
        let hash = previous;
        let id = {
            let mut tree = ctx.chain.block_tree.write();
            tree.insert_node(parent, candidate, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("insert_node failed: {err}"))
        };
        parent = Some(id);
        tip = Some((id, hash, height));
        ctx.chain.add_block(BlockRecord {
            hash,
            height,
            body_size: 0,
            header: None,
            tx_count: usize::try_from(height).unwrap_or(0) + 1,
            time,
        });
    }
    let Some((tip_id, hash, height)) = tip else {
        panic!("a chain fixture needs at least one block");
    };
    ctx.chain
        .applied_tip
        .store(Some(Arc::new(bitcoin_rs_chain::TipSnapshot {
            tip_id,
            height,
            chainwork: bitcoin_rs_chain::ChainWork::ZERO,
            hash: hash.into(),
            chain_tx_count: chain_tx_count.map_or(
                bitcoin_rs_chain::ChainTxCount::UNKNOWN,
                bitcoin_rs_chain::ChainTxCount::established,
            ),
        })));
    ctx
}

fn stats(ctx: &Arc<Context>, params: &sonic_rs::Value) -> sonic_rs::Value {
    getchaintxstats(ctx, params).unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"))
}

fn field(value: &sonic_rs::Value, key: &str) -> Option<i64> {
    value.get(key).and_then(JsonValueTrait::as_i64)
}

#[test]
fn window_interval_is_the_difference_of_two_median_times() {
    let ctx = chain_ctx(&TIMES);
    let blocks = 4_i64;
    let final_height = TIMES.len() - 1;
    let past_height = final_height - usize::try_from(blocks).unwrap_or(0);

    let expected = i64::from(median_time_past(&TIMES, final_height))
        - i64::from(median_time_past(&TIMES, past_height));
    let raw = i64::from(TIMES[final_height]) - i64::from(TIMES[past_height]);
    assert_ne!(
        expected, raw,
        "the fixture must separate the two definitions, or it proves nothing"
    );

    assert_eq!(
        field(&stats(&ctx, &json!([blocks])), "window_interval"),
        Some(expected)
    );
}

/// The rate follows the interval, so it follows the median times too.
#[test]
fn txrate_is_the_window_count_over_the_median_time_interval() {
    let ctx = chain_ctx(&TIMES);
    let blocks = 4_usize;
    let final_height = TIMES.len() - 1;
    let past_height = final_height - blocks;

    // Heights `past_height + 1 ..= final_height`, each with height + 1 txs.
    let count: i64 = (past_height + 1..=final_height)
        .map(|height| i64::try_from(height).unwrap_or(0) + 1)
        .sum();
    let interval = i64::from(median_time_past(&TIMES, final_height))
        - i64::from(median_time_past(&TIMES, past_height));

    let result = stats(&ctx, &json!([blocks]));
    assert_eq!(field(&result, "window_tx_count"), Some(count));
    let Some(txrate) = result.get("txrate").and_then(JsonValueTrait::as_f64) else {
        panic!("txrate missing: {result:?}");
    };
    let expected = bitcoin_rs_primitives::u64_to_f64(u64::try_from(count).unwrap_or(0))
        / bitcoin_rs_primitives::u64_to_f64(u64::try_from(interval).unwrap_or(0));
    assert!(
        (txrate - expected).abs() < f64::EPSILON,
        "got {txrate}, expected {expected}"
    );
}

/// A rate must keep the full window count, not the low 32 bits.
///
/// Capping through `u32::try_from` locks `txrate` once the window's
/// transactions pass `4_294_967_295`. Bitcoin Core divides the 64-bit
/// count by the 64-bit interval; so does [`bitcoin_rs_primitives::u64_to_f64`].
#[test]
fn txrate_keeps_counts_above_u32_max() {
    const PAST: u64 = 3;
    // `u32::MAX + 100`. Written as a literal because `u64::from` is not
    // const-stable here; the inequality below is what keeps it honest.
    const END: u64 = 4_294_967_395;
    let ctx = Context::new();
    // Four blocks so a one-block window is legal and the two MTP
    // boundaries differ (three or fewer keep the same median).
    let tip = super::chaintxstats_durability_tests::insert_counted_chain(
        &ctx,
        &[1_000, 2_000, 3_000, 4_000],
        &[1, 2, PAST, END],
    );
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    let ctx = Arc::new(ctx);
    assert!(
        END > u64::from(u32::MAX),
        "END must sit above the old 32-bit cap"
    );

    let result = stats(&ctx, &json!([1]));
    let count = END - PAST;
    assert_eq!(
        result
            .get("window_tx_count")
            .and_then(JsonValueTrait::as_u64),
        Some(count)
    );
    let Some(interval) = result
        .get("window_interval")
        .and_then(JsonValueTrait::as_u64)
    else {
        panic!("window_interval missing: {result:?}");
    };
    let Some(txrate) = result.get("txrate").and_then(JsonValueTrait::as_f64) else {
        panic!("txrate missing: {result:?}");
    };
    let expected =
        bitcoin_rs_primitives::u64_to_f64(count) / bitcoin_rs_primitives::u64_to_f64(interval);
    let capped = f64::from(u32::MAX) / bitcoin_rs_primitives::u64_to_f64(interval);
    assert_ne!(
        expected.to_bits(),
        capped.to_bits(),
        "the fixture must sit above the old 32-bit cap"
    );
    assert!(
        (txrate - expected).abs() < f64::EPSILON,
        "got {txrate}, expected {expected}"
    );
}

#[test]
fn a_zero_block_window_reports_no_window_fields() {
    let result = stats(&chain_ctx(&TIMES), &json!([0]));
    assert_eq!(field(&result, "window_block_count"), Some(0));
    assert!(result.get("window_interval").is_none(), "{result:?}");
    assert!(result.get("window_tx_count").is_none(), "{result:?}");
    assert!(result.get("txrate").is_none(), "{result:?}");
}

#[test]
fn txrate_is_omitted_when_the_window_does_not_advance() {
    // Eleven identical times, so every median time in the chain is equal
    // and any window between them is zero seconds long.
    let flat = [1_500_000_u32; 12];
    let result = stats(&chain_ctx(&flat), &json!([3]));
    assert_eq!(field(&result, "window_interval"), Some(0));
    assert!(result.get("window_tx_count").is_some(), "{result:?}");
    assert!(result.get("txrate").is_none(), "{result:?}");
}

/// An explicit count that reaches past genesis is refused, not clamped.
#[test]
fn a_block_count_past_the_chain_is_refused() {
    let ctx = chain_ctx(&TIMES);
    let height = i64::try_from(TIMES.len()).unwrap_or(0) - 1;
    for requested in [height, height + 1, 10_000] {
        let error = getchaintxstats(&ctx, &json!([requested]))
            .err()
            .unwrap_or_else(|| panic!("a {requested}-block window must be refused"));
        assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER, "{error:?}");
    }
    // One below the height is the largest window that fits.
    assert!(getchaintxstats(&ctx, &json!([height - 1])).is_ok());
}

/// A negative count is refused rather than read as an unsigned number.
#[test]
fn a_negative_block_count_is_refused() {
    let error = getchaintxstats(&chain_ctx(&TIMES), &json!([-1]))
        .err()
        .unwrap_or_else(|| panic!("a negative window must be refused"));
    assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
}

#[test]
fn the_default_window_is_clamped_to_the_chain() {
    let result = stats(&chain_ctx(&TIMES), &json!([]));
    let height = i64::try_from(TIMES.len()).unwrap_or(0) - 1;
    assert_eq!(field(&result, "window_block_count"), Some(height - 1));
}

/// The window ends where `blockhash` says, not always at the tip.
#[test]
fn a_blockhash_selects_the_block_the_window_ends_at() {
    let ctx = chain_ctx(&TIMES);
    let chosen_height = 8_usize;
    let hash = {
        let tree = ctx.chain.block_tree.read();
        let Some(node) = tree.active_node_at_height(u32::try_from(chosen_height).unwrap_or(0))
        else {
            panic!("the fixture has a block at that height");
        };
        node.hash
    };

    let result = stats(&ctx, &json!([2, hash.to_string_be()]));

    assert_eq!(
        field(&result, "window_final_block_height"),
        Some(i64::try_from(chosen_height).unwrap_or(0))
    );
    assert_eq!(
        result
            .get("window_final_block_hash")
            .and_then(JsonValueTrait::as_str),
        Some(hash.to_string_be().as_str())
    );
    assert_eq!(
        field(&result, "time"),
        Some(i64::from(TIMES[chosen_height]))
    );
    let expected = i64::from(median_time_past(&TIMES, chosen_height))
        - i64::from(median_time_past(&TIMES, chosen_height - 2));
    assert_eq!(field(&result, "window_interval"), Some(expected));
    // The count is the cumulative one *through the chosen block*, not the
    // tip's total. The durable counter tracks the tip alone, so this can
    // only come from a log prefix that reaches genesis -- which this
    // fixture has, and which a restarted node would not.
    //
    // The fixture gives block `h` exactly `h + 1` transactions, so the
    // cumulative count through height 8 is 1 + 2 + ... + 9.
    let expected_txcount = (1..=i64::try_from(chosen_height).unwrap_or(0) + 1).sum::<i64>();
    assert_eq!(
        field(&result, "txcount"),
        Some(expected_txcount),
        "a historical block on the applied chain has a knowable count: {result:?}"
    );
    assert_ne!(
        field(&result, "txcount"),
        field(&stats(&ctx, &json!([2])), "txcount"),
        "reporting the tip's total against another block would pass the check above \
             only by coincidence; these must differ"
    );
}

/// A block whose body this node has not applied is not the end of a window.
///
/// Membership used to be decided against the header tree's own best chain.
/// Headers run ahead of validation for most of a sync, so that accepts a
/// block this node has never verified -- and answers about it with the same
/// confidence as one it has. Resolved from the applied tip, it is refused.
#[test]
fn a_header_only_block_above_the_applied_tip_is_refused() {
    let ctx = chain_ctx(&TIMES);
    let Some(tip) = ctx.chain.applied_tip.load_full() else {
        panic!("the fixture has an applied tip");
    };
    // One more header on the same chain, with no record and no application.
    let ahead = {
        let mut tree = ctx.chain.block_tree.write();
        let Ok(tip_node) = tree.node(tip.tip_id) else {
            panic!("the applied tip must be in the tree");
        };
        let candidate = header(tip_node.header.compute_hash(), 1_008_000, 99);
        let hash = Hash256::from_le_bytes(candidate.compute_hash().as_bytes());
        let _id = tree
            .insert_node(Some(tip.tip_id), candidate, NodeStatus::Active)
            .unwrap_or_else(|err| panic!("insert_node failed: {err}"));
        hash
    };

    let error = getchaintxstats(&ctx, &json!([2, ahead.to_string_be()]))
        .err()
        .unwrap_or_else(|| panic!("a header-only block must be refused"));
    assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
}

/// A restarted node cannot name a count it never counted.
///
/// The log is rebuilt empty on every open, so a prefix that does not reach
/// genesis sums to a number that is not a chain total. Omitting is Core's
/// own signal for an unknown count; under-reporting would read as a quiet
/// chain and a fee estimator would believe it.
#[test]
fn a_log_that_does_not_reach_genesis_reports_no_count() {
    let ctx = chain_ctx(&TIMES);
    {
        // Drop the genesis record, leaving the rest of the log intact.
        let mut blocks = ctx.chain.blocks.write();
        let kept: Vec<BlockRecord> = blocks.iter().skip(1).cloned().collect();
        blocks.clear();
        for record in kept {
            blocks.push(record);
        }
    }
    let chosen = TIMES.len() - 5;
    let hash = {
        let tree = ctx.chain.block_tree.read();
        let Some(node) = tree.active_node_at_height(u32::try_from(chosen).unwrap_or(0)) else {
            panic!("the fixture has a block at that height");
        };
        node.hash
    };
    let result = stats(&ctx, &json!([2, hash.to_string_be()]));
    assert!(result.get("txcount").is_none(), "{result:?}");
}

/// The durable counter answers for the applied tip, and for nothing else.
///
/// It carries one number, the total through the tip. Handing that number
/// back for a block six deep reports the whole chain's transactions as
/// though they had all arrived by then -- an over-count that grows with the
/// distance, and reads as a confident measurement.
///
/// The log is what knows the rest, and it knows them exactly: the fixture
/// gives block `h` exactly `h + 1` transactions, so the count through `h`
/// is `(h + 1)(h + 2) / 2` however the counter is set.
#[test]
fn the_durable_counter_does_not_answer_for_a_historical_block() {
    const TIP_TOTAL: u64 = 999_999;

    let ctx = chain_ctx_with_counter(&TIMES, Some(TIP_TOTAL));
    let chosen = TIMES.len() - 5;
    let hash = {
        let tree = ctx.chain.block_tree.read();
        let Some(node) = tree.active_node_at_height(u32::try_from(chosen).unwrap_or(0)) else {
            panic!("the fixture has a block at that height");
        };
        node.hash
    };

    // The tip still answers from the counter, which is what makes the
    // historical answer below a restriction rather than a removal.
    assert_eq!(
        field(&stats(&ctx, &json!([2])), "txcount"),
        Some(i64::try_from(TIP_TOTAL).unwrap_or(0)),
        "the applied tip is exactly what the durable counter is for"
    );

    let historical = i64::try_from(chosen).unwrap_or(0);
    assert_eq!(
        field(&stats(&ctx, &json!([2, hash.to_string_be()])), "txcount"),
        Some((historical + 1) * (historical + 2) / 2),
        "a historical block is counted through the log, not handed the tip's total"
    );
}

/// A known durable tip total must not suppress a window the log can count.
///
/// The counter is one number, the total through the tip. Subtracting a
/// log prefix from that number is only right when the two agree. The
/// fixture sets them apart on purpose: mixing them would report
/// `TIP_TOTAL - log_start` instead of the window the log actually holds.
#[test]
fn a_durable_tip_total_does_not_block_a_complete_log_window() {
    const TIP_TOTAL: u64 = 999_999;
    let ctx = chain_ctx_with_counter(&TIMES, Some(TIP_TOTAL));
    let blocks = 4_i64;
    let final_height = TIMES.len() - 1;
    let past_height = final_height - usize::try_from(blocks).unwrap_or(0);
    let expected: i64 = (past_height + 1..=final_height)
        .map(|height| i64::try_from(height).unwrap_or(0) + 1)
        .sum();
    let mixed = i64::try_from(TIP_TOTAL).unwrap_or(0)
        - (0..=past_height)
            .map(|height| i64::try_from(height).unwrap_or(0) + 1)
            .sum::<i64>();
    assert_ne!(
        expected, mixed,
        "the fixture must separate the two sources, or it proves nothing"
    );

    let result = stats(&ctx, &json!([blocks]));
    assert_eq!(
        field(&result, "txcount"),
        Some(i64::try_from(TIP_TOTAL).unwrap_or(0)),
        "the applied tip still answers from the durable counter"
    );
    assert_eq!(
        field(&result, "window_tx_count"),
        Some(expected),
        "the window must come from the log, not durable_tip - log_start: {result:?}"
    );
}

/// A hash the node has never seen is not found.
#[test]
fn an_unknown_blockhash_is_not_found() {
    let unknown = Hash256::from_le_bytes(&[0x5c; 32]).to_string_be();
    let error = getchaintxstats(&chain_ctx(&TIMES), &json!([2, unknown]))
        .err()
        .unwrap_or_else(|| panic!("an unknown block must be refused"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
}

/// A block the node knows but has reorged away from ends no window.
///
/// It keeps its height, so a check that only compared heights would accept
/// it and then measure a window through a chain that does not exist.
#[test]
fn a_blockhash_off_the_active_chain_is_refused() {
    let ctx = chain_ctx(&TIMES);
    let stale = {
        let mut tree = ctx.chain.block_tree.write();
        let Some(parent) = tree.active_node_at_height(3).map(|node| node.hash) else {
            panic!("the fixture has a block at height 3");
        };
        let Some(parent_id) = tree.lookup(parent) else {
            panic!("a node the tree returned must be findable");
        };
        let sibling = header(
            BlockHash::from(Hash256::from_le_bytes(&parent.to_le_bytes())),
            1_002_000,
            9_999,
        );
        let hash = Hash256::from_le_bytes(sibling.compute_hash().as_bytes());
        let _id = tree
            .insert_node(Some(parent_id), sibling, NodeStatus::Stale)
            .unwrap_or_else(|err| panic!("insert_node failed: {err}"));
        hash
    };

    let error = getchaintxstats(&ctx, &json!([2, stale.to_string_be()]))
        .err()
        .unwrap_or_else(|| panic!("a stale block must be refused"));
    assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
}

/// A window the record log does not cover reports no count.
///
/// The log is rebuilt empty on every open, so after a restart the sum over
/// a window is a fraction of it. Reporting that fraction would read as a
/// quiet chain, which is what a fee estimator would then believe.
#[test]
fn window_tx_count_is_omitted_when_the_log_does_not_cover_the_window() {
    let ctx = chain_ctx(&TIMES);
    ctx.chain.blocks.write().clear();

    let result = stats(&ctx, &json!([4]));

    assert!(result.get("window_interval").is_some(), "{result:?}");
    assert!(result.get("window_tx_count").is_none(), "{result:?}");
    assert!(result.get("txrate").is_none(), "{result:?}");
}
