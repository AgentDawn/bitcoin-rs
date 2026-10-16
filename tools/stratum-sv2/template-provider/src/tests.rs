//! Production public-Node consumer: no RPC client, test seam, or fake coordinator.
use super::*;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_mining::{BlockValidationResult, GenerateRequest, GenerateSelection, solve_block};
use bitcoin_rs_primitives::{
    Amount, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness, consensus_bytes,
};
use std::time::Duration;
use stratum_apps::stratum_core::{bitcoin, template_distribution_sv2::SubmitSolutionOwned};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn candidate(node: &Node) -> Arc<bitcoin_rs_mining::Candidate> {
    let result = node
        .mining_control()
        .unwrap()
        .get_block_template(BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: vec![],
            rules: vec![],
            long_poll_id: None,
        })
        .unwrap();
    let BlockTemplateResult::Template(template) = result else {
        panic!("template");
    };
    template.candidate
}

async fn next(rx: &mut watch::Receiver<Option<Arc<TemplateState>>>) -> Arc<TemplateState> {
    tokio::time::timeout(Duration::from_secs(5), rx.changed())
        .await
        .unwrap()
        .unwrap();
    rx.borrow_and_update().clone().unwrap()
}

#[tokio::test]
async fn embedded_templates_preserve_wire_data_commit_and_cancel_on_shutdown() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.rpc.bind = "127.0.0.1:0".parse()?;
    config.p2p.listen.clear();
    config.p2p.dns_seeds_enabled = false;
    config.storage.dbcache_mb = 16;
    let witness_hash = bitcoin::hashes::sha256::Hash::hash(&[0x51]);
    config.mining.payout_script = [vec![0, 32], witness_hash.to_byte_array().to_vec()].concat();
    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
    let node = Arc::new(
        tokio::task::spawn_blocking(move || {
            block_on(Node::start(
                config,
                RuntimeInputs::default().with_shutdown(shutdown_rx),
            ))
        })
        .await??,
    );
    let hub = Hub::new();
    let mut updates = hub.subscribe();
    let worker_node = Arc::clone(&node);
    let worker_hub = hub.clone();
    let worker = std::thread::spawn(move || template_loop(worker_node, worker_hub));
    let first = next(&mut updates).await;
    let c = Arc::clone(&first.candidate);
    let wire = first.new_template_msg()?;
    assert_eq!(wire.coinbase_tx_value_remaining, c.coinbase_value);
    assert_eq!(
        wire.coinbase_prefix.as_ref(),
        c.coinbase.inputs[0].script_sig.as_bytes()
    );
    assert_eq!(
        wire.coinbase_tx_outputs.as_ref(),
        c.coinbase
            .outputs
            .iter()
            .skip(1)
            .flat_map(consensus_bytes)
            .collect::<Vec<_>>()
    );
    assert!(first.fits_constraints(1000, 100));
    assert!(!first.fits_constraints(u32::MAX, u32::MAX));
    let mut solved = c.into_unsolved_block()?;
    solve_block(&mut solved, 1_000_000)?;
    let solution = SubmitSolutionOwned {
        template_id: first.id,
        version: solved.header.version as u32,
        header_timestamp: solved.header.time,
        header_nonce: solved.header.nonce,
        coinbase_tx: consensus_bytes(&solved.txs[0]).try_into().unwrap(),
    };
    let assembled = first.assemble_block(&solution)?;
    let reference: bitcoin::Block = bitcoin::consensus::deserialize(&consensus_bytes(&assembled))?;
    assert_eq!(
        reference.header.merkle_root,
        reference.compute_merkle_root().unwrap()
    );
    assert_eq!(consensus_bytes(&assembled), consensus_bytes(&solved));
    let submission_node = Arc::clone(&node);
    assert_eq!(
        tokio::task::spawn_blocking(move || submission_node
            .mining_control()
            .unwrap()
            .submit_block(assembled))
        .await??,
        BlockValidationResult::Accepted
    );
    let second = next(&mut updates).await;
    assert_ne!(second.candidate.template_id, c.template_id);
    assert!(Arc::ptr_eq(&hub.lookup(first.id).unwrap(), &first));
    assert_eq!(
        node.mining_control()?
            .submit_block(first.assemble_block(&solution)?)?,
        BlockValidationResult::Duplicate
    );
    let funding = solved.txs[0].clone();
    let generating = Arc::clone(&node);
    let payout = funding.outputs[0].script_pubkey.as_bytes().to_vec();
    tokio::task::spawn_blocking(move || {
        generating
            .mining_control()
            .unwrap()
            .generate(GenerateRequest {
                payout,
                count: 100,
                max_tries: 1_000_000,
                selection: GenerateSelection::Mempool,
                submit: true,
            })
    })
    .await??;
    let tx = Tx {
        version: 2,
        lock_time: bitcoin_rs_primitives::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(funding.txid(), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0x51]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(c.coinbase_value - 2000),
            script_pubkey: funding.outputs[0].script_pubkey.clone(),
        }],
    };
    let txid = tx.txid();
    let expected_tx = consensus_bytes(&tx);
    let before = candidate(&node);
    let broadcasting = Arc::clone(&node);
    tokio::task::spawn_blocking(move || block_on(broadcasting.broadcast(tx))).await??;
    let after = candidate(&node);
    assert_eq!(before.previous_block_hash, after.previous_block_hash);
    assert_ne!(before.template_id, after.template_id);
    let with_tx = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let latest = updates.borrow_and_update().clone();
            if let Some(state) = latest
                && state
                    .candidate
                    .transactions
                    .iter()
                    .any(|entry| entry.txid == txid)
            {
                break state;
            }
            updates.changed().await.unwrap();
        }
    })
    .await?;
    assert_eq!(with_tx.candidate.template_id, after.template_id);
    assert_eq!(with_tx.candidate.transactions[0].txid, txid);
    let data = with_tx.transaction_data()?.into_inner();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0].as_ref(), expected_tx);
    let reference_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(data[0].as_ref())?;
    assert_eq!(
        reference_tx.compute_txid().to_byte_array(),
        *txid.as_bytes()
    );
    let mut solved_with_tx = with_tx.candidate.into_unsolved_block()?;
    solve_block(&mut solved_with_tx, 1_000_000)?;
    let with_tx_solution = SubmitSolutionOwned {
        template_id: with_tx.id,
        version: solved_with_tx.header.version as u32,
        header_timestamp: solved_with_tx.header.time,
        header_nonce: solved_with_tx.header.nonce,
        coinbase_tx: consensus_bytes(&solved_with_tx.txs[0]).try_into().unwrap(),
    };
    let projected = with_tx.assemble_block(&with_tx_solution)?;
    let reference: bitcoin::Block = bitcoin::consensus::deserialize(&consensus_bytes(&projected))?;
    assert_eq!(
        reference.header.merkle_root,
        reference.compute_merkle_root().unwrap()
    );
    assert_eq!(
        consensus_bytes(&projected),
        consensus_bytes(&solved_with_tx)
    );
    // The superseded same-tip empty job is still valid after mempool admission.
    let mut old_job = before.into_unsolved_block()?;
    solve_block(&mut old_job, 1_000_000)?;
    assert_eq!(
        node.mining_control()?.submit_block(old_job)?,
        BlockValidationResult::Accepted
    );
    // Its competitor must now be rejected by normal chainstate admission.
    assert!(matches!(
        node.mining_control()?.submit_block(projected)?,
        BlockValidationResult::Rejected(_)
    ));

    for _ in 0..RETAINED_TEMPLATES + 1 {
        hub.publish(Arc::clone(&c));
    }
    assert!(hub.lookup(first.id).is_none());
    assert_eq!(hub.issued.lock().unwrap().len(), RETAINED_TEMPLATES);
    shutdown_tx.send(())?;
    let ended = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || worker.join()),
    )
    .await??
    .unwrap();
    assert!(ended.is_err());
    let node = Arc::try_unwrap(node).map_err(|_| "live node borrower")?;
    tokio::task::spawn_blocking(move || block_on(node.shutdown())).await??;
    Ok(())
}
