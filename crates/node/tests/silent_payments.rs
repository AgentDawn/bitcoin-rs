//! The optional service through production startup, authenticated HTTP, reorg and restart.
#![cfg(feature = "silent-payments")]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_chain::regtest_fixture::{
    mine_block_to_declared_target, mined_regtest_child_at_time,
};
use bitcoin_rs_node::{Auth, Network, Node, NodeConfig, RuntimeInputs, state::NodeState};
use bitcoin_rs_primitives::{consensus_bytes, unix_time_secs};
use serde_json::{Value, json};

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn rpc(address: SocketAddr, method: &str, params: &Value, authenticated: bool) -> Result<Value> {
    for _ in 0..20 {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let auth = if authenticated {
            "Authorization: Basic dGVzdDpzZWNyZXQ=\r\n"
        } else {
            ""
        };
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: {address}\r\n{auth}Connection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )?;
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes)?;
        let text = std::str::from_utf8(&bytes)?;
        if !authenticated {
            assert!(text.starts_with("HTTP/1.1 401"), "{text}");
            return Ok(Value::Null);
        }
        let (_, body) = text.split_once("\r\n\r\n").context("HTTP response")?;
        let value: Value = serde_json::from_str(body)?;
        if value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("rate limit"))
        {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        return Ok(value);
    }
    bail!("tweak service remained rate limited")
}

#[test]
fn authenticated_tweaks_follow_reorg_and_survive_clean_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.p2p.connect.clear();
    config.p2p.dns_seeds_enabled = false;
    config.rpc.auth = Auth::basic("test", "secret");
    config.rpc.silent_payments = true;
    let reservation = TcpListener::bind("127.0.0.1:0")?;
    let address = reservation.local_addr()?;
    config.rpc.bind = address;

    let genesis = Network::Regtest.genesis_block();
    let now = u32::try_from(unix_time_secs())?;
    let first = mined_regtest_child_at_time(genesis.block_hash(), now - 3, 1)?;
    let second = mined_regtest_child_at_time(first.block_hash(), now - 2, 2)?;
    {
        let state = NodeState::open(config.clone(), None)?;
        state.apply_block(&genesis)?;
        state.apply_block(&first)?;
        state.apply_block(&second)?;
        state.publish_checkpoint()?;
    }
    drop(reservation);
    let node = block_on(Node::start(config.clone(), RuntimeInputs::default()))?;
    rpc(address, "getblocktweaks", &json!([1]), false)?;
    let original = rpc(address, "getblocktweaks", &json!([2]), true)?;
    assert_eq!(original["result"]["hash"], second.block_hash().to_string());
    assert_eq!(original["result"]["transactions"], json!([]));
    let invalidated = rpc(
        address,
        "invalidateblock",
        &json!([second.block_hash().to_string()]),
        true,
    )?;
    assert!(invalidated["error"].is_null(), "{invalidated}");
    let above = rpc(address, "getblocktweaks", &json!([2]), true)?;
    assert_eq!(above["error"]["code"], -8);
    let stale = rpc(
        address,
        "getblocktweaks",
        &json!([second.block_hash().to_string()]),
        true,
    )?;
    assert_eq!(stale["error"]["code"], -8);

    let mut replacement = second;
    replacement.header.time = now - 1;
    replacement.header.nonce = 0;
    mine_block_to_declared_target(&mut replacement)?;
    let submitted = rpc(
        address,
        "submitblock",
        &json!([consensus_bytes(&replacement).to_lower_hex_string()]),
        true,
    )?;
    assert!(
        submitted["error"].is_null() && submitted["result"].is_null(),
        "{submitted}"
    );
    let replaced = rpc(address, "getblocktweaks", &json!({"block": 2}), true)?;
    assert_eq!(
        replaced["result"]["hash"],
        replacement.block_hash().to_string()
    );
    assert_eq!(
        replaced["result"]["tip_hash"],
        replacement.block_hash().to_string()
    );
    let historical = rpc(
        address,
        "getblocktweaks",
        &json!([first.block_hash().to_string()]),
        true,
    )?;
    assert_eq!(historical["result"]["height"], 1);
    assert_eq!(historical["result"]["hash"], first.block_hash().to_string());
    block_on(node.shutdown())?;

    let node = block_on(Node::start(config.clone(), RuntimeInputs::default()))?;
    let restored = rpc(address, "getblocktweaks", &json!([2]), true)?;
    assert_eq!(restored["result"], replaced["result"]);
    block_on(node.shutdown())?;

    config.rpc.silent_payments = false;
    let node = block_on(Node::start(config, RuntimeInputs::default()))?;
    let disabled = rpc(address, "getblocktweaks", &json!([2]), true)?;
    assert_eq!(disabled["error"]["code"], -32603);
    assert!(
        disabled["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("disabled"))
    );
    block_on(node.shutdown())?;
    Ok(())
}
