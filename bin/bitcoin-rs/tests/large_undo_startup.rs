//! Manual consensus-valid undo/restart boundary evidence against pinned Core.
#![cfg(feature = "fjall")]

use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions};
use bitcoin_rs_storage::{FjallStore, KvUndoStore, UndoStore};
use serde_json::json;

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn coinbase(height: u32, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn { previous_output: OutPoint::null(),
            script_sig: bitcoin::script::Builder::new().push_int(i64::from(height)).push_int(0).into_script(),
            sequence: Sequence::MAX, witness: Witness::new() }],
        output: outputs,
    }
}

fn block(prev: BlockHash, height: u32, time: u32, txdata: Vec<Transaction>) -> Result<Block> {
    let mut block = Block {
        header: bitcoin::block::Header { version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: prev, merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time, bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff), nonce: 0 },
        txdata,
    };
    block.header.merkle_root = block.compute_merkle_root().ok_or("empty block")?;
    while block.header.validate_pow(block.header.target()).is_err() {
        block.header.nonce = block.header.nonce.checked_add(1).ok_or("nonce")?;
    }
    let _ = height;
    Ok(block)
}

fn submit(node: &mut ProcessNode, block: &Block) -> Result {
    // Bulk fixture bodies would exceed the process journal's 64 MiB bound.
    // Keep process custody and the common RPC transport; journal compact
    // block identities here instead of copying 140 MiB of generated hex.
    let result = bitcoin_rs_e2e::rpc::Connection::new(node.rpc_addr).rpc(
        &json!({"jsonrpc":"2.0","id":1,"method":"submitblock","params":[bitcoin::consensus::encode::serialize_hex(block)]}),
        ("parity", "parity"), Instant::now() + Duration::from_secs(60),
    )?;
    if result.get("error").is_some_and(|error| !error.is_null()) { return Err(format!("RPC: {result}").into()); }
    let result = &result["result"];
    if !result.is_null() { return Err(format!("submitblock: {result}").into()); }
    Ok(())
}

#[test]
#[ignore = "manual pinned-Core reproduction: writes 70 MiB of real spent scripts"]
fn valid_large_undo_reopens_and_verifies() -> Result {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let options = SpawnOptions { binary: Some(std::path::Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))), ..SpawnOptions::default() };
    let mut native = ProcessNode::spawn_with(Kind::BitcoinRs, &options)?;
    println!("D native_pid={} evidence={} core_evidence={}", native.pid(), native.evidence.display(), core.evidence.display());
    let mut script = vec![0x00, 0x63]; // OP_FALSE OP_IF
    for _ in 0..19 { script.extend_from_slice(&[0x4d, 0x08, 0x02]); script.extend_from_slice(&[0; 520]); }
    script.push(58); script.extend_from_slice(&[0; 58]);
    script.extend_from_slice(&[0x68, 0x51]); // OP_ENDIF OP_TRUE
    assert_eq!(script.len(), 10_000);
    let funding = TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::from_bytes(script) };
    let simple = || TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) };
    let mut previous = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
    let time = u32::try_from(bitcoin_rs_e2e::node::mock_time())?;
    println!("D fixture_time={time}");
    let mut inputs = Vec::new();
    let started = Instant::now();
    // 88 blocks fund 7,040 outputs; 100 more blocks mature even the last.
    for height in 1..=188 {
        let outputs = if height <= 88 { vec![funding.clone(); 80] } else { vec![simple()] };
        let cb = coinbase(height, outputs);
        if height <= 88 {
            for vout in 0..80 {
                if inputs.len() < 7_000 { inputs.push(TxIn { previous_output: OutPoint::new(cb.compute_txid(), vout),
                    script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }); }
            }
        }
        let candidate = block(previous, height, time + height, vec![cb])?;
        submit(&mut core, &candidate)?;
        submit(&mut native, &candidate)?;
        previous = candidate.block_hash();
    }
    let spend = Transaction { version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO, input: inputs,
        output: vec![TxOut { value: Amount::from_sat(6_999_000), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) }] };
    let candidate = block(previous, 189, time + 189, vec![coinbase(189, vec![simple()]), spend])?;
    println!("D funding_ms={} inputs=7000 previous_script_bytes=10000 block_bytes={} weight={}", started.elapsed().as_millis(), bitcoin::consensus::serialize(&candidate).len(), candidate.weight().to_wu());
    submit(&mut core, &candidate)?;
    submit(&mut native, &candidate)?;
    println!("D native_accepted={} core_accepted={}", native.rpc("getblockcount", &json!([]))?, core.rpc("getblockcount", &json!([]))?);
    let started = Instant::now();
    println!("D core_verify={:?} elapsed_ms={}", core.rpc("verifychain", &json!([2, 1])), started.elapsed().as_millis());
    let started = Instant::now();
    println!("D native_verify={:?} elapsed_ms={}", native.rpc("verifychain", &json!([2, 1])), started.elapsed().as_millis());
    let directory = native.stop_keep_datadir()?;
    {
        let store = Arc::new(FjallStore::open(directory.path().join("node/chainstate"))?);
        let undo = KvUndoStore::new(store);
        let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&candidate.block_hash().to_byte_array());
        let started = Instant::now();
        let record = undo.load_undo(189, hash)?.ok_or("node-written undo")?;
        println!("D node_written_undo_bytes={} read_ms={}", record.len(), started.elapsed().as_millis());
        assert!(record.len() > 64 * 1024 * 1024);
    }
    let started = Instant::now();
    let restarted = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions { timeout: Some(Duration::from_secs(90)), ..options }, directory);
    println!("D native_restart={:?} elapsed_ms={}", restarted.as_ref().map(|node| node.pid()), started.elapsed().as_millis());
    if let Ok(mut node) = restarted {
        assert_eq!(node.rpc("verifychain", &json!([2, 1]))?, json!(true));
        node.stop()?;
    }
    let directory = core.stop_keep_datadir()?;
    let mut restarted = ProcessNode::spawn_in_datadir(Kind::Core, &SpawnOptions::default(), directory)?;
    assert_eq!(restarted.rpc("verifychain", &json!([2, 1]))?, json!(true));
    restarted.stop()?;
    Ok(())
}
