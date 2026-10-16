//! Signed, consensus-validated spend -> retained undo -> BIP352 -> authenticated HTTP.
#![cfg(feature = "silent-payments")]

use std::path::Path;

use anyhow::{Context as _, Result};
use bitcoin::Block;
use bitcoin::consensus::deserialize;
use bitcoin::hex::FromHex as _;
use bitcoin_rs_e2e::helpers::tx_hex;
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions};
use serde_json::json;

mod support {
    pub(crate) mod silent_payment_spend;
}
use support::silent_payment_spend::{OUTPUT_KEY, mine_candidates};

const OUTPUT_COUNT: usize = 11_000;

#[test]
fn signed_dense_block_survives_reorg_and_restart() -> Result<()> {
    let options = SpawnOptions {
        binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
        extra_args: &["--silent-payments"],
        ..SpawnOptions::default()
    };
    let mut node = ProcessNode::spawn_with(Kind::BitcoinRs, &options)?;
    let request = json!({"jsonrpc":"2.0","id":1,"method":"getblocktweaks","params":[101]});
    assert_eq!(
        node.http("POST", "/", &serde_json::to_vec(&request)?, false)?
            .status,
        401
    );
    let (tx, hash, expected) = mine_candidates(&mut node, OUTPUT_COUNT)?;
    let outpoint = tx.input[0].previous_output;
    let raw = node.rpc("getblock", &json!([hash, 0]))?;
    let block: Block = deserialize(&Vec::from_hex(raw.as_str().context("block hex")?)?)?;
    assert!(block.weight().to_wu() > 1_890_000);
    assert!(block.weight().to_wu() <= 4_000_000);
    assert!(
        node.rpc(
            "gettxout",
            &json!([outpoint.txid.to_string(), outpoint.vout, false])
        )?
        .is_null()
    );

    let result = node.rpc("getblocktweaks", &json!([101]))?;
    assert_eq!(result["height"], 101);
    assert_eq!(result["hash"], hash);
    assert_eq!(result["tip_hash"], hash);
    assert_eq!(result["taproot_active"], true);
    let transactions = result["transactions"].as_array().context("transactions")?;
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0]["txid"], tx.compute_txid().to_string());
    assert_eq!(transactions[0]["tweak"], expected);
    let outputs = transactions[0]["outputs"].as_array().context("outputs")?;
    assert_eq!(outputs.len(), OUTPUT_COUNT);
    for (vout, output) in outputs.iter().enumerate() {
        assert_eq!(output, &json!({"vout":vout,"output_key":OUTPUT_KEY}));
    }
    eprintln!(
        "validated block: {} WU; {} candidates",
        block.weight().to_wu(),
        outputs.len()
    );

    node.rpc("invalidateblock", &json!([hash]))?;
    let stale =
        node.rpc_raw(&json!({"jsonrpc":"2.0","id":1,"method":"getblocktweaks","params":[hash]}))?;
    assert_eq!(stale["error"]["code"], -8);
    let replacement = node.rpc("generateblock", &json!(["raw(52)", [tx_hex(&tx)]]))?;
    let replacement_hash = replacement["hash"].as_str().context("replacement hash")?;
    assert_ne!(replacement_hash, hash);
    let replaced = node.rpc("getblocktweaks", &json!({"block":replacement_hash}))?;
    assert_eq!(replaced["hash"], replacement_hash);
    assert_eq!(replaced["tip_hash"], replacement_hash);
    assert_eq!(replaced["transactions"], result["transactions"]);

    let datadir = node.stop_keep_datadir()?;
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options, datadir)?;
    assert_eq!(node.rpc("getblocktweaks", &json!([101]))?, replaced);
    let datadir = node.stop_keep_datadir()?;
    let mut node = ProcessNode::spawn_in_datadir(
        Kind::BitcoinRs,
        &SpawnOptions {
            extra_args: &[],
            ..options
        },
        datadir,
    )?;
    assert_eq!(node.rpc_raw(&request)?["error"]["code"], -32603);
    node.stop()?;
    Ok(())
}
