use super::*;

use crate::{EXAMPLE_PRIVATE_KEY_HEX, Network, NodeConfig, RuntimeInputs};
use bitcoin_rs_mempool::{AdmissionOrigin, MempoolObserver, MutationEnvelope};
use bitcoin_rs_mining::{
    BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult, GenerateRequest,
    GenerateSelection, solve_block,
};
use bitcoin_rs_primitives::{
    Amount, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness, consensus_bytes,
};
use futures_executor::block_on;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use stratum_apps::{
    network_helpers::{
        connect_with_noise,
        noise_stream::{NoiseTcpReadHalf, NoiseTcpStream},
    },
    stratum_core::{
        bitcoin::{self, hashes::Hash as _},
        codec_sv2::ENCRYPTED_SV2_FRAME_HEADER_SIZE,
        common_messages_sv2::SetupConnectionOwned,
        template_distribution_sv2::{
            CoinbaseOutputConstraintsOwned, RequestTransactionDataOwned, SubmitSolutionOwned,
        },
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    task::JoinHandle,
};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(5);

#[tokio::test]
async fn transient_accept_error_waits_before_retrying() {
    let (_stop, mut cancel) = watch::channel(false);
    for error in [
        std::io::Error::from(std::io::ErrorKind::ConnectionAborted),
        std::io::Error::other("temporary resource exhaustion"),
    ] {
        let started = Instant::now();
        wait_after_accept_error(error, &mut cancel).await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(100));
    }
}

#[tokio::test]
async fn accept_error_backoff_can_be_cancelled_by_shutdown() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    let (stop, mut cancel) = watch::channel(false);
    let wait = wait_after_accept_error(
        std::io::Error::other("temporary resource exhaustion"),
        &mut cancel,
    );
    tokio::pin!(wait);
    let mut context = Context::from_waker(Waker::noop());
    assert!(wait.as_mut().poll(&mut context).is_pending());
    stop.send_replace(true);
    assert!(matches!(
        wait.as_mut().poll(&mut context),
        Poll::Ready(Ok(()))
    ));
}

#[tokio::test]
async fn permanent_accept_error_remains_fatal() {
    let (_stop, mut cancel) = watch::channel(false);
    let result = wait_after_accept_error(
        std::io::Error::from(std::io::ErrorKind::InvalidInput),
        &mut cancel,
    )
    .await;
    assert!(result.is_err());
}

struct EmbeddedNode {
    node: Arc<Node>,
    shutdown: crossbeam_channel::Sender<()>,
    _dir: tempfile::TempDir,
}

impl EmbeddedNode {
    async fn start(observer: Option<Arc<dyn MempoolObserver>>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.rpc.bind = "127.0.0.1:0".parse().unwrap();
        config.p2p.listen.clear();
        config.p2p.dns_seeds_enabled = false;
        config.storage.dbcache_mb = 16;
        config.mining.payout_script = [
            vec![0, 32],
            bitcoin::hashes::sha256::Hash::hash(&[0x51])
                .to_byte_array()
                .to_vec(),
        ]
        .concat();
        let (shutdown, rx) = crossbeam_channel::bounded(1);
        let node = tokio::task::spawn_blocking(move || {
            block_on(Node::start(
                config,
                RuntimeInputs {
                    shutdown: Some(rx),
                    mempool_observer: observer,
                },
            ))
        })
        .await
        .unwrap()
        .unwrap();
        Self {
            _dir: dir,
            node: Arc::new(node),
            shutdown,
        }
    }

    fn candidate(&self) -> Arc<bitcoin_rs_mining::Candidate> {
        let BlockTemplateResult::Template(template) = self
            .node
            .mining_control()
            .unwrap()
            .get_block_template(BlockTemplateRequest {
                mode: BlockTemplateMode::Template,
                capabilities: vec![],
                rules: vec![],
                long_poll_id: None,
            })
            .unwrap()
        else {
            panic!("template")
        };
        template.candidate
    }

    async fn shutdown(self) {
        self.shutdown.send(()).unwrap();
        let node = Arc::try_unwrap(self.node).unwrap_or_else(|_| panic!("session retained Node"));
        tokio::task::spawn_blocking(move || block_on(node.shutdown()))
            .await
            .unwrap()
            .unwrap();
    }
}

async fn start_session(
    node: Arc<Node>,
    hub: Hub,
) -> (
    std::net::SocketAddr,
    watch::Sender<bool>,
    JoinHandle<Result<(), String>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let secret = Secp256k1SecretKey(
        secp256k1::SecretKey::from_slice(&hex::decode(EXAMPLE_PRIVATE_KEY_HEX).unwrap()).unwrap(),
    );
    let (stop, cancel) = watch::channel(false);
    let session = Session {
        hub,
        node,
        stop: cancel,
        keys: (Secp256k1PublicKey::from(secret), secret),
        cert_validity_secs: 3600,
    };
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        session.serve(stream).await
    });
    (address, stop, task)
}

async fn connect(address: std::net::SocketAddr) -> NoiseTcpStream {
    let secret = Secp256k1SecretKey(
        secp256k1::SecretKey::from_slice(&hex::decode(EXAMPLE_PRIVATE_KEY_HEX).unwrap()).unwrap(),
    );
    tokio::time::timeout(
        DEADLINE,
        connect_with_noise(
            TcpStream::connect(address).await.unwrap(),
            Some(Secp256k1PublicKey::from(secret)),
        ),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn setup(reader: &mut NoiseTcpReadHalf, writer: &mut NoiseTcpWriteHalf) {
    send(
        writer,
        AnyMessageOwned::Common(CommonMessagesOwned::SetupConnection(SetupConnectionOwned {
            protocol: Protocol::TemplateDistributionProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: "localhost".try_into().unwrap(),
            endpoint_port: 0,
            vendor: "test".try_into().unwrap(),
            hardware_version: "".try_into().unwrap(),
            firmware: "".try_into().unwrap(),
            device_id: "".try_into().unwrap(),
        })),
    )
    .await
    .unwrap();
    let mut frame = tokio::time::timeout(DEADLINE, reader.read_frame())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        parse_common(&mut frame),
        Some(CommonMessagesOwned::SetupConnectionSuccess(_))
    ));
    send(
        writer,
        AnyMessageOwned::TemplateDistribution(
            TemplateDistributionOwned::CoinbaseOutputConstraints(CoinbaseOutputConstraintsOwned {
                coinbase_output_max_additional_size: 1000,
                coinbase_output_max_additional_sigops: 1,
            }),
        ),
    )
    .await
    .unwrap();
}

async fn receive(reader: &mut NoiseTcpReadHalf) -> TemplateDistributionOwned {
    let mut frame = tokio::time::timeout(DEADLINE, reader.read_frame())
        .await
        .unwrap()
        .unwrap();
    TemplateDistribution::try_from((frame.header().msg_type(), frame.payload()))
        .unwrap()
        .into_owned()
}

async fn receive_job(reader: &mut NoiseTcpReadHalf, id: u64) {
    assert!(
        matches!(receive(reader).await, TemplateDistributionOwned::NewTemplate(t) if t.template_id == id)
    );
    assert!(
        matches!(receive(reader).await, TemplateDistributionOwned::SetNewPrevHash(t) if t.template_id == id)
    );
}

#[tokio::test]
async fn partial_noise_frame_survives_refresh_and_tight_candidate_closes_session() -> TestResult {
    let embedded = EmbeddedNode::start(None).await;
    let hub = Hub::new();
    hub.publish(embedded.candidate());
    let (address, stop, session) = start_session(Arc::clone(&embedded.node), hub.clone()).await;
    // A byte-transparent TCP proxy gates the remainder of one encrypted frame.
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy_listener.local_addr()?;
    let (arm, arm_rx) = oneshot::channel();
    let (armed, armed_rx) = oneshot::channel();
    let (partial, partial_rx) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let proxy = tokio::spawn(async move {
        let (client, _) = proxy_listener.accept().await.unwrap();
        let upstream = TcpStream::connect(address).await.unwrap();
        let (mut from_client, mut to_client) = client.into_split();
        let (mut from_server, mut to_server) = upstream.into_split();
        let forward = async move {
            let mut arm_rx = arm_rx;
            let mut buf = [0; 4096];
            loop {
                tokio::select! {
                    _ = &mut arm_rx => break,
                    count = from_client.read(&mut buf) => {
                        let count = count.unwrap();
                        assert_ne!(count, 0);
                        to_server.write_all(&buf[..count]).await.unwrap();
                    }
                }
            }
            armed.send(()).unwrap();
            let mut prefix = [0; ENCRYPTED_SV2_FRAME_HEADER_SIZE + 1];
            from_client.read_exact(&mut prefix).await.unwrap();
            to_server.write_all(&prefix).await.unwrap();
            partial.send(()).unwrap();
            release_rx.await.unwrap();
            tokio::io::copy(&mut from_client, &mut to_server).await
        };
        let backward = async {
            let result = tokio::io::copy(&mut from_server, &mut to_client).await;
            to_client.shutdown().await.unwrap();
            result
        };
        tokio::join!(forward, backward)
    });
    let (mut reader, mut writer) = connect(proxy_address).await.into_split();
    setup(&mut reader, &mut writer).await;
    receive_job(&mut reader, 1).await;
    arm.send(()).unwrap();
    tokio::time::timeout(DEADLINE, armed_rx).await??;
    send(
        &mut writer,
        AnyMessageOwned::TemplateDistribution(TemplateDistributionOwned::RequestTransactionData(
            RequestTransactionDataOwned { template_id: 1 },
        )),
    )
    .await?;
    tokio::time::timeout(DEADLINE, partial_rx).await??;
    tokio::task::yield_now().await;
    hub.publish(embedded.candidate());
    // Observe refresh while the client frame is still incomplete.
    receive_job(&mut reader, 2).await;
    release.send(()).unwrap();
    assert!(
        matches!(receive(&mut reader).await, TemplateDistributionOwned::RequestTransactionDataSuccess(t) if t.template_id == 1)
    );
    // A subsequent complete record also decodes, checking continued alignment.
    send(
        &mut writer,
        AnyMessageOwned::TemplateDistribution(TemplateDistributionOwned::RequestTransactionData(
            RequestTransactionDataOwned { template_id: 2 },
        )),
    )
    .await?;
    assert!(
        matches!(receive(&mut reader).await, TemplateDistributionOwned::RequestTransactionDataSuccess(t) if t.template_id == 2)
    );
    let mut tight = crate::tests::empty_candidate();
    tight.max_weight = tight.weight + (1000 + 109) * 4 - 1;
    hub.publish(Arc::new(tight));
    assert_eq!(
        tokio::time::timeout(DEADLINE, session).await??,
        Err("coinbase constraints exceed candidate headroom".into())
    );
    assert!(
        tokio::time::timeout(DEADLINE, reader.read_frame())
            .await?
            .is_err()
    );
    stop.send_replace(true);
    proxy.abort();
    let _ = proxy.await;
    embedded.shutdown().await;
    Ok(())
}

struct SubmissionGate {
    entered: Mutex<Option<oneshot::Sender<()>>>,
    release: crossbeam_channel::Receiver<()>,
    released: AtomicBool,
}

impl MempoolObserver for SubmissionGate {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        if envelope.origin == AdmissionOrigin::Block {
            self.entered
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            self.released.store(
                self.release.recv_timeout(DEADLINE).is_ok(),
                Ordering::SeqCst,
            );
        }
    }
}

#[tokio::test]
async fn session_shutdown_drains_a_running_native_submission() -> TestResult {
    let (entered, entered_rx) = oneshot::channel();
    let (release, release_rx) = crossbeam_channel::bounded(1);
    let gate = Arc::new(SubmissionGate {
        entered: Mutex::new(Some(entered)),
        release: release_rx,
        released: AtomicBool::new(false),
    });
    let embedded = EmbeddedNode::start(Some(gate.clone())).await;
    let payout = embedded.candidate().coinbase.outputs[0]
        .script_pubkey
        .as_bytes()
        .to_vec();
    let node = Arc::clone(&embedded.node);
    let generated = tokio::task::spawn_blocking(move || {
        node.mining_control().unwrap().generate(GenerateRequest {
            payout,
            count: 101,
            max_tries: 1_000_000,
            selection: GenerateSelection::Mempool,
            submit: true,
        })
    })
    .await??;
    let funding = embedded
        .node
        .block_by_hash(generated[0].hash)
        .await?
        .unwrap()
        .txs[0]
        .clone();
    let spend = Tx {
        version: 2,
        lock_time: bitcoin_rs_primitives::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(funding.txid(), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0x51]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(funding.outputs[0].value.to_sat() - 2000),
            script_pubkey: funding.outputs[0].script_pubkey.clone(),
        }],
    };
    let node = Arc::clone(&embedded.node);
    tokio::task::spawn_blocking(move || block_on(node.broadcast(spend))).await??;
    let candidate = embedded.candidate();
    assert_eq!(candidate.transactions.len(), 1);
    let mut block = candidate.into_unsolved_block()?;
    solve_block(&mut block, 1_000_000)?;
    let hash = block.block_hash();
    let solution = SubmitSolutionOwned {
        template_id: 1,
        version: block.header.version as u32,
        header_timestamp: block.header.time,
        header_nonce: block.header.nonce,
        coinbase_tx: consensus_bytes(&block.txs[0]).try_into().unwrap(),
    };
    let hub = Hub::new();
    hub.publish(candidate);
    let (address, stop, mut session) = start_session(Arc::clone(&embedded.node), hub).await;
    let (mut reader, mut writer) = connect(address).await.into_split();
    setup(&mut reader, &mut writer).await;
    receive_job(&mut reader, 1).await;
    send(
        &mut writer,
        AnyMessageOwned::TemplateDistribution(TemplateDistributionOwned::SubmitSolution(solution)),
    )
    .await?;
    // This observer runs inside canonical block submission after mempool removal.
    tokio::time::timeout(DEADLINE, entered_rx).await??;
    stop.send_replace(true);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut session)
            .await
            .is_err(),
        "session exited with its native submission still blocked"
    );
    release.send(())?;
    tokio::time::timeout(DEADLINE, session).await???;
    assert!(gate.released.load(Ordering::SeqCst));
    assert_eq!(embedded.node.snapshot().tip_height, 102);
    assert_eq!(
        embedded
            .node
            .block_by_hash(hash)
            .await?
            .unwrap()
            .block_hash(),
        hash
    );
    embedded.shutdown().await;
    Ok(())
}
