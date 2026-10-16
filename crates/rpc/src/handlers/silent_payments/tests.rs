use super::*;
use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
use bitcoin_rs_index::silent_payments::{TaprootCandidate, TransactionTweak};
use bitcoin_rs_primitives::{Block, Network};
use bitcoin_rs_utxo::contract::{BlockSpends, BlockUndoSource, HistoryUnavailable};
use sonic_rs::JsonContainerTrait as _;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Source<F>(F);
impl<F> BlockUndoSource for Source<F>
where
    F: Fn(Hash256, Hash256) -> std::result::Result<BlockSpends, BlockSpendsError> + Send + Sync,
{
    fn block_spends(
        &self,
        hash: Hash256,
        tip: Hash256,
    ) -> std::result::Result<BlockSpends, BlockSpendsError> {
        (self.0)(hash, tip)
    }
}

fn fixture() -> Result<(Context, Block)> {
    let mut ctx = Context::from_handles(crate::context::ContextHandles {
        silent_payments: true,
        ..crate::context::ContextHandles::default()
    });
    ctx.chain.chain_network = Network::Regtest;
    let mut block = Network::Regtest.genesis_block();
    // Synthetic source: chainstate authentication is tested by its owning suite.
    block.header.time = u32::try_from(bitcoin_rs_primitives::unix_time_secs())?;
    let tip = {
        let mut tree = ctx.chain.block_tree.write();
        let id = tree.insert_node(None, block.header, NodeStatus::Active)?;
        let node = tree.node(id)?;
        TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        }
    };
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    let body = block.clone();
    ctx.chain.block_undo_source = Some(Arc::new(Source(move |hash, expected| {
        assert_eq!(hash, Hash256::from(body.block_hash()));
        assert_eq!(expected, hash);
        Ok(BlockSpends {
            block: body.clone(),
            spent: Ok(vec![vec![]]),
        })
    })));
    Ok((ctx, block))
}

#[test]
fn height_and_named_hash_return_exact_identity_and_empty_success() -> Result {
    for named in [false, true] {
        let (ctx, block) = fixture()?;
        let params = if named {
            json!({"block": block.block_hash().to_string()})
        } else {
            json!([0])
        };
        let result = crate::Handler::new(Arc::new(ctx)).dispatch("getblocktweaks", &params)?;
        assert_eq!(result["height"].as_u64(), Some(0));
        assert_eq!(
            result["hash"].as_str(),
            Some(block.block_hash().to_string().as_str())
        );
        assert_eq!(result["tip_hash"], result["hash"]);
        assert_eq!(result["taproot_active"].as_bool(), Some(true));
        assert!(
            result["transactions"]
                .as_array()
                .ok_or("transactions")?
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn eligible_transactions_keep_complete_candidate_indices() -> Result {
    use bitcoin::hex::FromHex as _;
    use bitcoin_rs_primitives::{OutPoint, Script, Tx, TxIn, TxOut, Witness};
    use bitcoin_rs_utxo::UtxoCoin;

    // Public generator key; the source boundary is synthetic, as in fixture().
    // Cryptographic expectations remain owned by the index's pinned vectors.
    let key = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let script: Script = [vec![0x51, 0x20], Vec::from_hex(key)?].concat().into();
    let (mut ctx, mut block) = fixture()?;
    let outpoint = OutPoint::new(block.txs[0].txid(), 0);
    let mut tx = Tx::default();
    tx.inputs.push(TxIn {
        previous_output: outpoint,
        witness: Witness::from(vec![vec![0; 64]]),
        ..TxIn::default()
    });
    let coin = UtxoCoin {
        outpoint,
        txout: TxOut { script_pubkey: script.clone(), ..TxOut::default() },
        height: 1,
        coinbase: false,
    };
    tx.outputs.push(TxOut::default());
    tx.outputs.push(TxOut {
        script_pubkey: script,
        ..TxOut::default()
    });
    tx.outputs.push(tx.outputs[1].clone());
    let txid = tx.txid().to_string();
    block.txs.push(tx);
    ctx.chain.block_undo_source = Some(Arc::new(Source(move |_, _| {
        Ok(BlockSpends {
            block: block.clone(),
            spent: Ok(vec![vec![], vec![coin.clone()]]),
        })
    })));
    let result = getblocktweaks(&Arc::new(ctx), &json!([0]))?;
    let transaction = &result["transactions"][0];
    assert_eq!(transaction["txid"].as_str(), Some(txid.as_str()));
    assert_eq!(transaction["tweak"].as_str().ok_or("tweak")?.len(), 66);
    assert_eq!(transaction["outputs"].as_array().ok_or("outputs")?.len(), 2);
    assert_eq!(transaction["outputs"][0]["vout"].as_u64(), Some(1));
    assert_eq!(transaction["outputs"][1]["vout"].as_u64(), Some(2));
    assert_eq!(transaction["outputs"][0]["output_key"].as_str(), Some(key));
    Ok(())
}

#[test]
fn malformed_range_secret_and_header_only_selectors_are_rejected() -> Result {
    for params in [
        json!([]),
        json!([-1]),
        json!([1]),
        json!([1.5]),
        json!([true]),
        json!([[0, 1]]),
        json!([0, 1]),
        json!({"scan_sk": "secret"}),
        json!(["bad"]),
    ] {
        let (ctx, _) = fixture()?;
        assert!(
            getblocktweaks(&Arc::new(ctx), &params).is_err(),
            "{params:?}"
        );
    }
    let (ctx, block) = fixture()?;
    let mut header = block.header;
    header.prev_blockhash = block.block_hash();
    header.nonce ^= 1;
    let hash = Hash256::from(header.compute_hash());
    {
        let mut tree = ctx.chain.block_tree.write();
        let parent = tree.lookup(block.block_hash().into());
        tree.insert_node(parent, header, NodeStatus::Active)?;
    }
    assert!(getblocktweaks(&Arc::new(ctx), &json!([hash.to_string_be()])).is_err());
    Ok(())
}

#[test]
fn deep_unindexed_ancestry_is_refused_before_body_io() -> Result {
    let (ctx, block) = fixture()?;
    let tip = {
        let mut tree = ctx.chain.block_tree.write();
        let root = tree.lookup(block.block_hash().into()).ok_or("root")?;
        let mut parent = root;
        for nonce in 1..=u32::try_from(MAX_SELECTION_HOPS + 1)? {
            let mut header = block.header;
            header.prev_blockhash = tree.node(parent)?.header.compute_hash();
            header.nonce = nonce;
            parent = tree.insert_node(Some(parent), header, NodeStatus::Active)?;
        }
        let node = tree.node(parent)?;
        let tip = TipSnapshot {
            tip_id: parent,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        };
        // The seam invalidates the height index even without altering a node.
        let _unindexed = tree.node_mut(root)?;
        tip
    };
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    // fixture's source would assert if reached with this new expected tip.
    let error = getblocktweaks(&Arc::new(ctx), &json!([0]))
        .err()
        .ok_or("budget")?;
    assert!(error.to_string().contains("hop budget"));
    Ok(())
}

#[test]
fn unavailable_history_never_becomes_empty_success() -> Result {
    for reason in [
        HistoryUnavailable::Missing,
        HistoryUnavailable::Pruned { below: 1 },
        HistoryUnavailable::Reserved { below: 1 },
        HistoryUnavailable::Shutdown,
    ] {
        let (mut ctx, block) = fixture()?;
        ctx.chain.block_undo_source = Some(Arc::new(Source(move |_, _| {
            Ok(BlockSpends {
                block: block.clone(),
                spent: Err(reason),
            })
        })));
        let error = getblocktweaks(&Arc::new(ctx), &json!([0]))
            .err()
            .ok_or("unavailable")?;
        assert_eq!(error.code(), -1);
        assert!(error.to_string().contains(&reason.to_string()));
    }
    Ok(())
}

#[test]
fn moved_tip_and_recovery_after_source_read_refuse_publication() -> Result {
    for close in [false, true] {
        let (mut ctx, block) = fixture()?;
        let applied = ctx.chain.applied_tip.clone();
        let closed = Arc::new(core::sync::atomic::AtomicBool::new(false));
        ctx.chain.closed_for_recovery = bitcoin_rs_chain::LatchReader::new(closed.clone());
        ctx.chain.block_undo_source = Some(Arc::new(Source(move |_, _| {
            if close {
                closed.store(true, core::sync::atomic::Ordering::Release);
            } else {
                let mut tip = applied
                    .load_full()
                    .ok_or(BlockSpendsError::Retry)?
                    .as_ref()
                    .clone();
                tip.hash = Hash256::default();
                applied.store(Some(Arc::new(tip)));
            }
            Ok(BlockSpends {
                block: block.clone(),
                spent: Ok(vec![vec![]]),
            })
        })));
        let error = getblocktweaks(&Arc::new(ctx), &json!([0]))
            .err()
            .ok_or("must refuse")?;
        assert!(
            error
                .to_string()
                .contains(if close { "recovery" } else { "changed" })
        );
    }
    Ok(())
}

#[test]
fn wrong_body_and_source_retry_are_errors() -> Result {
    for retry in [false, true] {
        let (mut ctx, mut block) = fixture()?;
        block.header.nonce ^= 1;
        ctx.chain.block_undo_source = Some(Arc::new(Source(move |_, _| {
            if retry {
                return Err(BlockSpendsError::Retry);
            }
            Ok(BlockSpends {
                block: block.clone(),
                spent: Ok(vec![vec![]]),
            })
        })));
        let error = getblocktweaks(&Arc::new(ctx), &json!([0]))
            .err()
            .ok_or("must refuse")?;
        assert_eq!(
            error.code(),
            if retry { -1 } else { RpcError::INTERNAL_ERROR }
        );
    }
    Ok(())
}

#[test]
fn admission_is_nonblocking_rate_limited_and_releases_the_slot() -> Result {
    let admission = Admission::new();
    let now = Instant::now();
    let held = admission.acquire(now)?;
    assert!(admission.acquire(now + ADMISSION_INTERVAL).is_err());
    drop(held);
    assert!(
        admission
            .acquire(now + ADMISSION_INTERVAL.saturating_sub(Duration::from_nanos(1)))
            .is_err()
    );
    drop(admission.acquire(now + ADMISSION_INTERVAL)?);
    Ok(())
}

#[test]
fn shared_materialization_budget_and_transition_never_queue_tweak_work() -> Result {
    let (ctx, _) = fixture()?;
    let ctx = Arc::new(ctx);
    let first = ctx.try_acquire_block_render().ok_or("permit")?;
    let second = ctx.try_acquire_block_render().ok_or("permit")?;
    let error = getblocktweaks(&ctx, &json!([0]))
        .err()
        .ok_or("must refuse")?;
    assert!(error.to_string().contains("full-block read limit"));
    drop((first, second));

    let (ctx, _) = fixture()?;
    let ctx = Arc::new(ctx);
    let held = ctx.chain.chain_transition.lock();
    let error = getblocktweaks(&ctx, &json!([0]))
        .err()
        .ok_or("must refuse")?;
    assert!(error.to_string().contains("transition in progress"));
    drop(held);
    Ok(())
}

#[test]
fn ibd_and_missing_applied_tip_are_not_empty_success() -> Result {
    let (ctx, _) = fixture()?;
    let ctx = Arc::new(ctx);
    // Mainnet's minimum work is not met by this synthetic regtest root.
    let (mut ibd, _) = fixture()?;
    ibd.chain.chain_network = Network::Mainnet;
    assert!(matches!(
        getblocktweaks(&Arc::new(ibd), &json!([0])),
        Err(RpcError::ClientInInitialDownload(_))
    ));
    ctx.chain.applied_tip.store(None);
    assert!(getblocktweaks(&ctx, &json!([0])).is_err());
    Ok(())
}

#[test]
fn historical_activation_uses_requested_height_not_the_captured_tip_height() -> Result {
    let (mut ctx, _) = fixture()?;
    // Latch this synthetic world out of IBD before testing mainnet's boundary.
    assert!(
        !ctx.chain
            .progress
            .initial_block_download(bitcoin_rs_primitives::unix_time_secs(), Network::Regtest,)
    );
    ctx.chain.chain_network = Network::Mainnet;
    let mut tip = ctx
        .chain
        .applied_tip
        .load_full()
        .ok_or("tip")?
        .as_ref()
        .clone();
    // A synthetic high publication keeps the requested root at height zero.
    tip.height = Network::Mainnet.taproot_activation_height();
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    let result = getblocktweaks(&Arc::new(ctx), &json!([0]))?;
    assert_eq!(result["taproot_active"].as_bool(), Some(false));
    assert_eq!(
        result["tip_height"].as_u64(),
        Some(u64::from(Network::Mainnet.taproot_activation_height()))
    );
    Ok(())
}

#[test]
fn result_budget_keeps_complete_candidates_and_refuses_excess() -> Result {
    let (ctx, block) = fixture()?;
    let tx = TransactionTweak {
        txid: block.txs[0].txid(),
        input_public_key_sum: [2; 33],
        input_hash: [1; 32],
        tweak: [3; 33],
        outputs: vec![TaprootCandidate {
            vout: u32::MAX,
            output_key: [4; 32],
        }],
    };
    let mut material = BlockTweaks {
        hash: block.block_hash(),
        transactions: vec![tx],
    };
    let result = render(&material, u32::MAX, &ctx.chain.applied_view(), true)?;
    assert_eq!(
        result["transactions"][0]["outputs"][0]["vout"].as_u64(),
        Some(u64::from(u32::MAX))
    );
    assert_eq!(
        result["transactions"][0]["tweak"].as_str(),
        Some(
            material.transactions[0]
                .tweak
                .to_lower_hex_string()
                .as_str()
        )
    );
    material.transactions[0].outputs =
        vec![material.transactions[0].outputs[0].clone(); (MAX_RESULT_BYTES - 512 - 256) / 128];
    check_result_budget(&material)?;
    let value = render(&material, u32::MAX, &ctx.chain.applied_view(), true)?;
    assert!(sonic_rs::to_vec(&value)?.len() <= MAX_RESULT_BYTES);
    material.transactions[0].outputs.push(TaprootCandidate {
        vout: 0,
        output_key: [0; 32],
    });
    assert!(render(&material, 0, &ctx.chain.applied_view(), true).is_err());
    Ok(())
}
