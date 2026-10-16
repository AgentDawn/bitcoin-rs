use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::{Result, bail};
use bitcoin::hex::FromHex;
use bitcoin_rs_chain::regtest_fixture::{self, REGTEST_BITS};
use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry, SubmitOutcome};
use bitcoin_rs_mining::{
    BlockTemplate, BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult,
    BlockValidationResult, MiningControl, solve_block,
};
use bitcoin_rs_node::{MiningCoordinator, Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness, deserialize as native_deserialize,
};
use bitcoin_rs_rpc::{
    Handler,
    context::{
        ChainAdmissionView, ChainHandles, Context, ContextHandles, IndexHandles, MempoolHandles,
        MiningHandles, NetworkHandles,
    },
};
use bitcoin_rs_script::push_int;
use bitcoin_rs_utxo::UtxoSet;
use compact_str::CompactString;
use sonic_rs::JsonValueTrait as _;

pub(crate) const SEED_BLOCKS: u32 = 100;
pub(crate) const SEED_BASE_TIME: u32 = 1_296_688_603;
pub(crate) const SEED_BLOCK_INTERVAL: u32 = 600;
pub(crate) const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
pub(crate) const MEMPOOL_TX_FEE_SATS: u64 = 10_000;
pub(crate) const WITNESS_RESERVED: [u8; 32] = [0_u8; 32];
pub(crate) const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

pub(crate) fn open_network(network: Network) -> Result<NodeState> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(network);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    // NodeState retains open files under data_dir for the test duration.
    std::mem::forget(dir);
    NodeState::open(config, None)
}

pub(crate) fn open_at_genesis(network: Network) -> Result<NodeState> {
    let state = open_network(network)?;
    let _ = state.apply_block(&network.genesis_block())?;
    Ok(state)
}

/// Regtest node at its applied genesis tip plus the coordinator over it.
pub(crate) fn regtest_mining() -> Result<(NodeState, MiningCoordinator)> {
    let state = open_at_genesis(Network::Regtest)?;
    let mining = coordinator(&state);
    Ok((state, mining))
}

pub(crate) fn coordinator(state: &NodeState) -> MiningCoordinator {
    // Empty template coinbase script matches transport-only GBT wiring.
    MiningCoordinator::new(
        state.mempool_reader(),
        state.chainstate(),
        state.stable_read(),
        state.chain_followers(),
        state.config().mining.payout_script.clone(),
    )
}

pub(crate) fn advance_mempool_sequence(state: &NodeState) -> Result<()> {
    let mempool = state.mempool();
    let mut guard = mempool.write();
    guard
        .insert_entry(MempoolEntry::new(
            Arc::new(mempool_sequence_tx()),
            100,
            10_000,
            1,
            7,
            0,
        ))
        .map_err(|error| anyhow::anyhow!("seed insert failed: {error}"))?;
    guard.clear();
    Ok(())
}

pub(crate) fn template_request(long_poll_id: Option<CompactString>) -> BlockTemplateRequest {
    BlockTemplateRequest {
        mode: BlockTemplateMode::Template,
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id,
    }
}

pub(crate) fn expect_template(result: BlockTemplateResult) -> BlockTemplate {
    match result {
        BlockTemplateResult::Template(template) => template,
        other @ BlockTemplateResult::Proposal(_) => {
            panic!("expected template, got {other:?}")
        }
    }
}

pub(crate) fn to_lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub(crate) fn is_witness_commitment(script_pubkey: &[u8]) -> bool {
    script_pubkey.len() >= 38 && script_pubkey.starts_with(&WITNESS_COMMITMENT_PREFIX)
}

pub(crate) fn solved_template_block(mining: &MiningCoordinator) -> Result<Block> {
    let template = expect_template(mining.get_block_template(template_request(None))?);
    let mut block = template
        .candidate
        .into_unsolved_block()
        .map_err(|error| anyhow::anyhow!("assemble template candidate: {error}"))?;
    solve_block(&mut block, 1_000_000)
        .map_err(|error| anyhow::anyhow!("solve template candidate: {error}"))?;
    Ok(block)
}

pub(crate) fn mined_child(prev: BlockHash) -> Result<Block> {
    mined_child_labeled(prev, 1)
}

pub(crate) fn mined_child_labeled(prev: BlockHash, label: i64) -> Result<Block> {
    let script_opcode = u8::try_from(label + 0x50)?;
    let coinbase = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![script_opcode, 0x51]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50 * 100_000_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    };
    let mut block = Block {
        header: Header {
            version: 0x2000_0000,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time: 1_296_688_603 + 600,
            bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    block.header.merkle_root = block.txs[0].txid().into();
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

pub(crate) fn mined_regtest_header(prev: BlockHash, time: u32, version: i32) -> Header {
    let mut header = Header {
        version,
        prev_blockhash: prev,
        merkle_root: Hash256::default(),
        time,
        bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
        nonce: 0,
    };
    regtest_fixture::mine_header_to_declared_target(&mut header)
        .unwrap_or_else(|error| panic!("regtest fixture header: {error}"));
    header
}

pub(crate) fn excess_coinbase_child(prev: BlockHash) -> Result<Block> {
    let mut block = mined_child(prev)?;
    let Some(output) = block.txs.first_mut().and_then(|tx| tx.outputs.first_mut()) else {
        panic!("coinbase has no output");
    };
    output.value = output.value.saturating_add(Amount::from_sat(1));
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("test block has no merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

pub(crate) fn mempool_sequence_tx() -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x42; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    }
}

pub(crate) fn propose_block(
    mining: &MiningCoordinator,
    block: Block,
) -> Result<BlockValidationResult> {
    match mining.get_block_template(BlockTemplateRequest {
        mode: BlockTemplateMode::Proposal(block),
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id: None,
    })? {
        BlockTemplateResult::Proposal(result) => Ok(result),
        other @ BlockTemplateResult::Template(_) => {
            panic!("expected a proposal result, got {other:?}")
        }
    }
}

pub(crate) fn disconnect_applied(state: &NodeState, block: &Block) -> Result<()> {
    use bitcoin_rs_primitives::consensus_bytes;
    let genesis = Network::Regtest.genesis_block();
    let target = state
        .chainstate()
        .block_tree_reader()
        .read()
        .lookup(Hash256::from(genesis.block_hash()))
        .ok_or_else(|| anyhow::anyhow!("missing genesis node"))?;
    let block_hash = Hash256::from(block.block_hash());
    let body = block.clone();
    bitcoin_rs_node::reorg::switch_to_branch(
        &state.chainstate(),
        &state.chain_followers(),
        target,
        |hash| (hash == block_hash).then(|| (body.clone(), consensus_bytes(&body).into())),
        |_| {},
    )
    .map_err(|error| anyhow::anyhow!("{error}"))
}

pub(crate) fn open_regtest() -> Result<(NodeState, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    Ok((state, dir))
}

pub(crate) fn apply_genesis(state: &NodeState) -> Result<()> {
    let genesis = Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    Ok(())
}

pub(crate) fn seed_chain(state: &NodeState, count: u32) -> Result<Hash256> {
    let mut tip = current_tip(state)?;
    for height in 1..=count {
        let coinbase = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes([push_int(i64::from(height)), push_int(0)].concat()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::ZERO,
        };
        let mut block = Block {
            header: Header {
                version: 0x2000_0000,
                prev_blockhash: BlockHash::from(tip.hash),
                merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                bits: CompactTarget::from_consensus(REGTEST_BITS),
                nonce: 0,
            },
            txs: vec![coinbase],
        };
        block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
            .ok_or_else(|| anyhow::anyhow!("seed block must have a merkle root"))?;
        regtest_fixture::mine_block_to_declared_target(&mut block)?;
        state.apply_block(&block)?;
        tip = current_tip(state)?;
        assert_eq!(tip.height, height, "seed block must become the tip");
    }
    Ok(tip.hash)
}

pub(crate) fn current_tip(state: &NodeState) -> Result<bitcoin_rs_chain::TipSnapshot> {
    let Some(tip) = state.chainstate().applied_tip_snapshot() else {
        bail!("applied tip must exist");
    };
    Ok((*tip).clone())
}

pub(crate) fn assemble_from_template(
    template: &sonic_rs::Value,
    template_txs: &[sonic_rs::Value],
) -> Result<Block> {
    let prev_hex = required_str(template, "previousblockhash")?;
    let height = required_u64(template, "height")?;
    let coinbase_value = required_u64(template, "coinbasevalue")?;
    let bits = u32::from_str_radix(&required_str(template, "bits")?, 16)?;
    let curtime = u32::try_from(required_u64(template, "curtime")?).unwrap_or(u32::MAX);
    let version = i32::try_from(required_u64(template, "version")?).unwrap_or(0);
    let commitment_script =
        Vec::<u8>::from_hex(&required_str(template, "default_witness_commitment")?)?;
    assert!(
        commitment_script.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
        "default_witness_commitment must be the BIP141 commitment script"
    );

    let mut txs = Vec::with_capacity(template_txs.len());
    for entry in template_txs {
        let data = entry
            .get("data")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("template transaction missing data hex"))?;
        txs.push(native_deserialize::<Tx>(&Vec::<u8>::from_hex(data)?)?);
    }

    assemble_block(
        prev_hex.as_str(),
        u32::try_from(height).unwrap_or(u32::MAX),
        version,
        bits,
        curtime,
        coinbase_value,
        commitment_script,
        txs,
    )
}

pub(crate) fn seed_coinbase_spend() -> Tx {
    seed_coinbase_spend_with_fee(MEMPOOL_TX_FEE_SATS)
}

pub(crate) fn seed_coinbase_spend_with_fee(fee_sats: u64) -> Tx {
    let seed_coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes([push_int(1), push_int(0)].concat()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    };
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(seed_coinbase.txid(), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - fee_sats),
            script_pubkey: p2sh_true_output(),
        }],
        lock_time: LockTime::ZERO,
    }
}

pub(crate) fn p2sh_true_output() -> Script {
    let redeem = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    Script::from_bytes(redeem.to_p2sh().into_bytes())
}

pub(crate) fn p2sh_true_spend_script_sig() -> Script {
    Script::from_bytes(vec![0x01, 0x51])
}

pub(crate) fn assemble_regtest_block(prev: Hash256, height: u32, txs: Vec<Tx>) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes([push_int(i64::from(height)), push_int(0)].concat()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    };
    let mut block = Block {
        header: Header {
            version: 0x2000_0000,
            prev_blockhash: BlockHash::from(prev),
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        },
        txs: std::iter::once(coinbase).chain(txs).collect(),
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("regtest block must have a merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

#[expect(clippy::unnecessary_wraps)]
pub(crate) fn admit_to_mempool(state: &NodeState, tx: &Tx) -> Result<()> {
    let utxo = state.chainstate().utxo_reader();
    let applied_tip = state.chainstate().applied_tip_reader();
    let block_tree = state.chainstate().block_tree_reader();
    let view = ChainAdmissionView::new(utxo, applied_tip, block_tree, Network::Regtest);
    let outcome = state.mempool_gateway().submit_transaction(
        Arc::new(tx.clone()),
        AdmissionOrigin::Rpc,
        None,
        bitcoin_rs_primitives::unix_time_secs(),
        &view,
    );
    assert!(
        matches!(outcome, Ok(SubmitOutcome::Committed(_))),
        "gateway admission must commit the spend, got: {outcome:?}"
    );
    Ok(())
}

pub(crate) fn mine_regtest_block(
    state: &NodeState,
    prev: Hash256,
    height: u32,
    txs: Vec<Tx>,
) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes([push_int(i64::from(height)), push_int(0)].concat()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    };
    let mut block = Block {
        header: Header {
            version: 0x2000_0000,
            prev_blockhash: BlockHash::from(prev),
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        },
        txs: std::iter::once(coinbase).chain(txs).collect(),
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("mined block must have a merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    state.apply_block(&block)?;
    Ok(block)
}

pub(crate) fn mining_handler(state: &NodeState) -> Handler {
    let coordinator = MiningCoordinator::new(
        state.mempool_reader(),
        state.chainstate(),
        state.stable_read(),
        state.chain_followers(),
        state.config().mining.payout_script.clone(),
    );
    let mining_control: Arc<dyn MiningControl> = Arc::new(coordinator);
    let ctx = Context::from_handles(ContextHandles {
        chain: ChainHandles {
            chain_tip: state.chainstate().header_tip_reader(),
            applied_tip: state.chainstate().applied_tip_reader(),
            active_tip_wait: Some(state.chainstate()),
            progress: state.chainstate().chain_progress_reader(),
            blocks: state.block_log_reader(),
            utxo: bitcoin_rs_utxo::UtxoReader::new(Arc::new(UtxoSet::new())),
            coin_stats: state.chainstate().coin_stats_handle(),
            block_tree: state.chainstate().block_tree_reader(),
            chain_network: state.config().network,
            chain_transition: state.stable_read(),
            closed_for_recovery: state.chainstate().closed_for_recovery_reader(),
            ..ChainHandles::default()
        },
        mempool: MempoolHandles {
            gateway: state.mempool_gateway(),
        },
        indexes: IndexHandles::default(),
        network: NetworkHandles {
            peer_table: state.peer_table(),
            p2p: state.p2p(),
            local_services: state.p2p().local_services().to_u64(),
        },
        mining: MiningHandles {
            mining_control: Some(mining_control),
        },
        ..ContextHandles::default()
    })
    .with_chain_transition(state.stable_read());
    Handler::new(Arc::new(ctx))
}

pub(crate) fn assemble_block(
    prev_hex: &str,
    height: u32,
    version: i32,
    bits: u32,
    curtime: u32,
    coinbase_value: u64,
    commitment_script: Vec<u8>,
    txs: Vec<Tx>,
) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(push_int(i64::from(height))),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![WITNESS_RESERVED.to_vec()]),
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(coinbase_value),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: Script::from_bytes(commitment_script),
            },
        ],
        lock_time: LockTime::ZERO,
    };

    let mut block_txs = Vec::with_capacity(txs.len() + 1);
    block_txs.push(coinbase);
    block_txs.extend(txs);

    let mut block = Block {
        header: Header {
            version,
            prev_blockhash: prev_hex
                .parse::<BlockHash>()
                .map_err(|err| anyhow::anyhow!("invalid previousblockhash: {err}"))?,
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time: curtime,
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        },
        txs: block_txs,
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("block must have a merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

pub(crate) fn required_str(value: &sonic_rs::Value, key: &str) -> Result<String> {
    let text = value
        .get(key)
        .and_then(|text| text.as_str())
        .ok_or_else(|| anyhow::anyhow!("template field {key} missing or not a string"))?;
    Ok(text.to_owned())
}

pub(crate) fn required_u64(value: &sonic_rs::Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(sonic_rs::JsonValueTrait::as_i64)
        .and_then(|number| u64::try_from(number).ok())
        .ok_or_else(|| anyhow::anyhow!("template field {key} missing or not a number"))
}
