//! Bounded Noise/TDP sessions over an embedded Node. No internal RPC transport.
use crate::{Config, Hub, template::TemplateState};
use bitcoin_rs_node::Node;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use stratum_apps::network_helpers::{accept_noise_connection, noise_stream::NoiseTcpWriteHalf};
use stratum_apps::stratum_core::common_messages_sv2::{
    Protocol, SetupConnectionErrorOwned, SetupConnectionSuccessOwned,
};
use stratum_apps::stratum_core::parsers_sv2::{
    AnyMessageOwned, CommonMessagesOwned, TemplateDistribution, TemplateDistributionOwned,
};
use stratum_apps::stratum_core::template_distribution_sv2::{
    RequestTransactionDataErrorOwned, RequestTransactionDataSuccessOwned,
};
use stratum_apps::utils::types::{InboundFrame, OutboundFrame};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
};
use tracing::{debug, info, warn};

const MAX_SESSIONS: usize = 8;

pub async fn run(
    config: Config,
    hub: Hub,
    node: Arc<Node>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), String> {
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| e.to_string())?;
    info!(listen = %listener.local_addr().map_err(|e| e.to_string())?, "TDP server listening");
    let mut sessions = JoinSet::new();
    let (session_stop, session_cancel) = watch::channel(false);
    let outcome = loop {
        if *stop.borrow() {
            break Ok(());
        }
        tokio::select! {
            _ = stop.changed() => break Ok(()),
            _ = sessions.join_next(), if !sessions.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, peer) = match accepted { Ok(value) => value, Err(error) => break Err(error.to_string()) };
                if sessions.len() >= MAX_SESSIONS { drop(stream); continue; }
                let session = Session {
                    hub: hub.clone(), node: Arc::clone(&node), stop: session_cancel.clone(),
                    keys: (Secp256k1PublicKey::from(config.secret_key), config.secret_key),
                    cert_validity_secs: config.cert_validity_secs,
                };
                sessions.spawn(async move {
                    if let Err(error) = session.serve(stream).await { warn!(%peer, %error, "pool connection ended"); }
                });
            }
        }
    };
    session_stop.send_replace(true);
    // Sessions cancel incomplete reads by closing the connection, but finish
    // awaited blocking submissions before dropping their Node borrows.
    while sessions.join_next().await.is_some() {}
    outcome
}

struct Session {
    hub: Hub,
    node: Arc<Node>,
    stop: watch::Receiver<bool>,
    keys: (Secp256k1PublicKey, Secp256k1SecretKey),
    cert_validity_secs: u64,
}

impl Session {
    async fn serve(mut self, stream: TcpStream) -> Result<(), String> {
        let (public, secret) = self.keys;
        let noise = tokio::select! {
            _ = self.stop.changed() => return Ok(()),
            result = tokio::time::timeout(Duration::from_secs(10), accept_noise_connection(stream, public, secret, self.cert_validity_secs)) => {
                result.map_err(|_| "noise deadline")?.map_err(|e| e.to_string())?
            }
        };
        let (mut reader, mut writer) = noise.into_split();
        let mut frame = tokio::select! {
            _ = self.stop.changed() => return Ok(()),
            result = tokio::time::timeout(Duration::from_secs(10), reader.read_frame()) => {
                result.map_err(|_| "setup deadline")?.map_err(|e| e.to_string())?
            }
        };
        match parse_common(&mut frame) {
            Some(CommonMessagesOwned::SetupConnection(setup))
                if setup.protocol == Protocol::TemplateDistributionProtocol
                    && setup.min_version <= 2
                    && setup.max_version >= 2 => {}
            Some(CommonMessagesOwned::SetupConnection(setup))
                if setup.protocol == Protocol::TemplateDistributionProtocol =>
            {
                send_error(&mut writer, "protocol-version-mismatch").await?;
                return Err("unsupported version".into());
            }
            _ => {
                send_error(&mut writer, "unsupported-protocol").await?;
                return Err("unsupported setup".into());
            }
        }
        send(
            &mut writer,
            AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionSuccess(
                SetupConnectionSuccessOwned {
                    used_version: 2,
                    flags: 0,
                },
            )),
        )
        .await?;
        info!("pool setup connection completed");
        let mut templates = self.hub.subscribe();
        let mut constraints = None;
        loop {
            if *self.stop.borrow() {
                return Ok(());
            }
            // Keep this exact future alive across template refreshes. The SRI
            // Noise reader is NOT cancellation-safe after a partial record.
            let read = reader.read_frame();
            tokio::pin!(read);
            let message = loop {
                tokio::select! {
                    _ = self.stop.changed() => return Ok(()),
                    changed = templates.changed() => {
                        changed.map_err(|e| e.to_string())?;
                        let state = templates.borrow_and_update().clone();
                        if let (Some(state), Some((bytes, sigops))) = (state, constraints) {
                            push_template(&mut writer, &state, bytes, sigops).await?;
                        }
                    }
                    frame = &mut read => {
                        let mut frame = frame.map_err(|e| e.to_string())?;
                        break TemplateDistribution::try_from((frame.header().msg_type(), frame.payload()))
                            .map_err(|e| format!("TDP decode: {e}"))?.into_owned();
                    }
                }
            };
            match message {
                TemplateDistributionOwned::CoinbaseOutputConstraints(c) => {
                    let bytes = c.coinbase_output_max_additional_size;
                    let sigops = u32::from(c.coinbase_output_max_additional_sigops);
                    constraints = Some((bytes, sigops));
                    let state = templates.borrow_and_update().clone();
                    if let Some(state) = state {
                        push_template(&mut writer, &state, bytes, sigops).await?;
                    }
                }
                TemplateDistributionOwned::RequestTransactionData(request) => {
                    match self.hub.lookup(request.template_id) {
                        Some(template) => {
                            let list =
                                tokio::task::spawn_blocking(move || template.transaction_data())
                                    .await
                                    .map_err(|e| e.to_string())??;
                            send(
                                &mut writer,
                                AnyMessageOwned::TemplateDistribution(
                                    TemplateDistributionOwned::RequestTransactionDataSuccess(
                                        RequestTransactionDataSuccessOwned {
                                            template_id: request.template_id,
                                            excess_data: Vec::new().try_into().unwrap(),
                                            transaction_list: list,
                                        },
                                    ),
                                ),
                            )
                            .await?;
                            debug!(
                                template_id = request.template_id,
                                "served RequestTransactionData"
                            );
                        }
                        None => {
                            send_error_tdp(&mut writer, request.template_id, "template-not-found")
                                .await?
                        }
                    }
                }
                TemplateDistributionOwned::SubmitSolution(solution) => {
                    let Some(template) = self.hub.lookup(solution.template_id) else {
                        continue;
                    };
                    let node = Arc::clone(&self.node);
                    let id = solution.template_id;
                    let started = Instant::now();
                    let result = tokio::task::spawn_blocking(move || {
                        let block = template.assemble_block(&solution)?;
                        node.mining_control()
                            .map_err(|e| e.to_string())?
                            .submit_block(block)
                            .map_err(|e| e.to_string())
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                    info!(
                        template_id = id,
                        ?result,
                        submit_us = started.elapsed().as_micros(),
                        height = self.node.snapshot().tip_height,
                        "typed solution submitted"
                    );
                }
                other => debug!(?other, "ignoring TDP message"),
            }
        }
    }
}

async fn push_template(
    writer: &mut NoiseTcpWriteHalf,
    state: &TemplateState,
    bytes: u32,
    sigops: u32,
) -> Result<(), String> {
    if !state.fits_constraints(bytes, sigops) {
        return Err("coinbase constraints exceed candidate headroom".into());
    }
    let started = Instant::now();
    send(
        writer,
        AnyMessageOwned::TemplateDistribution(TemplateDistributionOwned::NewTemplate(
            state.new_template_msg()?,
        )),
    )
    .await?;
    send(
        writer,
        AnyMessageOwned::TemplateDistribution(TemplateDistributionOwned::SetNewPrevHash(
            state.set_new_prev_hash_msg(),
        )),
    )
    .await?;
    info!(
        template_id = state.id,
        job_us = started.elapsed().as_micros(),
        "pushed template to pool"
    );
    Ok(())
}

/// Decodes a frame as an owned common message, `None` on failure.
fn parse_common(frame: &mut InboundFrame) -> Option<CommonMessagesOwned> {
    stratum_apps::stratum_core::parsers_sv2::CommonMessages::try_from((
        frame.header().msg_type(),
        frame.payload(),
    ))
    .ok()
    .map(|m| m.into_owned())
}

/// Encodes and writes one SV2 message.
async fn send(writer: &mut NoiseTcpWriteHalf, message: AnyMessageOwned) -> Result<(), String> {
    let frame = OutboundFrame::from_message(message).map_err(|e| format!("frame encode: {e}"))?;
    tokio::time::timeout(Duration::from_secs(10), writer.write_frame(frame))
        .await
        .map_err(|_| "write deadline".to_owned())?
        .map_err(|e| format!("write: {e}"))
}

async fn send_error(writer: &mut NoiseTcpWriteHalf, code: &'static str) -> Result<(), String> {
    send(
        writer,
        AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionError(
            SetupConnectionErrorOwned {
                flags: 0,
                error_code: code.try_into().expect("ascii fits"),
            },
        )),
    )
    .await
}

async fn send_error_tdp(
    writer: &mut NoiseTcpWriteHalf,
    template_id: u64,
    code: &'static str,
) -> Result<(), String> {
    send(
        writer,
        AnyMessageOwned::TemplateDistribution(
            TemplateDistributionOwned::RequestTransactionDataError(
                RequestTransactionDataErrorOwned {
                    template_id,
                    error_code: code.try_into().expect("ascii fits"),
                },
            ),
        ),
    )
    .await
}
