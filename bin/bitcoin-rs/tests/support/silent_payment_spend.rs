//! A signed mature P2PKH spend and independent single-input BIP352 expectation.
use anyhow::{Context as _, Result};
use bitcoin::consensus::serialize;
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::secp256k1::{Scalar, Secp256k1};
use bitcoin::{Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxOut};
use bitcoin_rs_e2e::ProcessNode;
use bitcoin_rs_e2e::helpers::{
    COINBASE_MATURITY, coinbase_at, funding_address, funding_output, mine_blocks_to, raw_spend_to,
    sign_p2pkh_inputs, submit_genesis, tx_hex,
};
use serde_json::json;

pub(crate) const OUTPUT_KEY: &str =
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// Independent single-input BIP352 oracle: the fixture's known public key,
// serialized funding outpoint and tagged SHA256, without the node/index codec.
fn expected_tweak(outpoint: OutPoint, prevout: &TxOut) -> Result<String> {
    let key: PublicKey =
        "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f".parse()?;
    assert_eq!(
        prevout.script_pubkey,
        ScriptBuf::new_p2pkh(&key.pubkey_hash())
    );
    let tag = sha256::Hash::hash(b"BIP0352/Inputs");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(tag.as_byte_array());
    bytes.extend_from_slice(tag.as_byte_array());
    bytes.extend_from_slice(&serialize(&outpoint));
    bytes.extend_from_slice(&key.inner.serialize());
    let scalar = Scalar::from_be_bytes(sha256::Hash::hash(&bytes).to_byte_array())?;
    Ok(key
        .inner
        .mul_tweak(&Secp256k1::verification_only(), &scalar)?
        .serialize()
        .to_lower_hex_string())
}

pub(crate) fn mine_candidates(
    node: &mut ProcessNode,
    output_count: usize,
) -> Result<(Transaction, String, String)> {
    submit_genesis(node)?;
    let _ = mine_blocks_to(
        node,
        COINBASE_MATURITY,
        &format!("addr({})", funding_address()?),
    )?;
    let (outpoint, prevout) = funding_output(&coinbase_at(node, 1)?)?;
    let expected = expected_tweak(outpoint, &prevout)?;
    let script = ScriptBuf::from_bytes(Vec::from_hex(&format!("5120{OUTPUT_KEY}"))?);
    let mut tx = raw_spend_to(outpoint, &prevout, 10_000, Sequence::MAX, &script);
    // Keep duplicates and dust: candidate completeness is independent of policy.
    tx.output.resize(
        output_count,
        TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        },
    );
    sign_p2pkh_inputs(&mut tx, &[prevout])?;
    let mined = node.rpc("generateblock", &json!(["raw(51)", [tx_hex(&tx)]]))?;
    let hash = mined["hash"].as_str().context("mined hash")?.to_owned();
    Ok((tx, hash, expected))
}
