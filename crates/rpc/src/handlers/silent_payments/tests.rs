use super::*;
use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::{Block, Network};
use bitcoin_rs_utxo::contract::{BlockSpends, BlockUndoSource, HistoryUnavailable};

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
fn header_only_selector_is_rejected_before_body_io() -> Result {
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
    for wrap in [BlockSpendsError::BodyRead, BlockSpendsError::BoundedRead] {
        let disk = std::io::Error::other("private/path: disk read failed").into();
        let error = read_error(&wrap(BoundedReadError::Storage(disk)));
        assert_eq!(error.code(), RpcError::INTERNAL_ERROR);
        assert_eq!(
            error.to_string(),
            "internal error: Unable to read silent payment block inputs"
        );
        for refusal in [
            BoundedReadError::Unsupported,
            BoundedReadError::Limit { size: 2, limit: 1 },
        ] {
            assert_eq!(read_error(&wrap(refusal)).code(), -1);
        }
    }
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
fn shared_materialization_budget_and_transition_never_queue_tweak_work() -> Result {
    let (ctx, _) = fixture()?;
    let ctx = Arc::new(ctx);
    let held = ctx.silent_payments.as_ref().ok_or("service")?.lock();
    assert!(getblocktweaks(&ctx, &json!([0])).is_err());
    drop(held);
    // Consecutive requests need no timer once the previous work releases its slot.
    getblocktweaks(&ctx, &json!([0]))?;
    getblocktweaks(&ctx, &json!([0]))?;
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
