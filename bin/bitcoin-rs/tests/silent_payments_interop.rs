//! Explicit pinned `BlindBit` interoperability evidence for the existing L1 REST path.

use std::path::Path;

use anyhow::{Context as _, Result};
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions};
use serde_json::json;

mod support {
    pub(crate) mod silent_payment_spend;
}
use support::silent_payment_spend::mine_candidates;

/// Build the unmodified Oracle at the pin in docs/silent-payments.md first.
#[test]
#[ignore = "requires BLINDBIT_ORACLE pointing to the pinned upstream binary"]
fn blindbit_indexes_existing_rest_without_the_tweak_service() -> Result<()> {
    use std::fs::File;
    use std::net::TcpListener;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use bitcoin_rs_e2e::rpc::Connection;

    let oracle = std::env::var_os("BLINDBIT_ORACLE").context("BLINDBIT_ORACLE is required")?;
    let mut node = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
            extra_args: &["--rest=true"],
            ..SpawnOptions::default()
        },
    )?;
    let (_, hash, expected) = mine_candidates(&mut node, 1)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let config = node.evidence.join("blindbit.toml");
    std::fs::write(
        &config,
        format!(
            "chain = \"regtest\"\ncore_rest_endpoint = \"http://{}\"\nhttp_host = \"{address}\"\ngrpc_host = \"\"\nsync_start_height = 101\nmax_parallel_requests = 1\nmax_parallel_tweak_computations = 1\nmax_cpu_cores = 1\ntweaks_only = true\ntweaks_full_basic = true\ntweaks_full_with_dust_filter = false\ntweaks_cut_through_with_dust_filter = false\nlog_level = \"debug\"\n",
            node.rpc_addr,
        ),
    )?;
    let log = File::create(node.evidence.join("blindbit.log"))?;
    drop(listener);
    let mut child = Command::new(oracle)
        .args(["run", "--skip-precheck", "--datadir"])
        .arg(node.evidence.join("blindbit"))
        .arg("--config")
        .arg(&config)
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .context("start BLINDBIT_ORACLE")?;
    // Reap the external process before propagating probe errors.
    let outcome = (|| -> Result<()> {
        let mut connection = Connection::new(address);
        let response = node.wait_for(
            "BlindBit positive REST index",
            Duration::from_secs(30),
            |_| {
                let response = connection.http(
                    "GET",
                    "/tweaks/101",
                    &[],
                    None,
                    Instant::now() + Duration::from_secs(2),
                )?;
                if response.status != 200 {
                    return Ok(None);
                }
                let response = response.json()?;
                Ok((response["block_identifier"]["block_hash"] == hash).then_some(response))
            },
        )?;
        std::fs::write(
            node.evidence.join("blindbit-tweaks.json"),
            serde_json::to_vec_pretty(&response)?,
        )?;
        anyhow::ensure!(
            response["index"] == json!([expected]),
            "Oracle positive tweak differs"
        );
        Ok(())
    })();
    let _ = child.kill();
    child.wait()?;
    outcome?;
    node.stop()?;
    Ok(())
}
