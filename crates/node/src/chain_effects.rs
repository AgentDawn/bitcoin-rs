//! Derived consumers of committed chain transitions.
//!
//! Ownership and ordering rules are defined by `ARCH-07` in
//! [`docs/contracts/architecture.md`](../../docs/contracts/architecture.md). Apply
//! does not import these consumer types.

use std::sync::Arc;

use bitcoin_rs_index::block_log::{BlockLog, BlockRecord};
use bitcoin_rs_primitives::{Block, BlockHash, BlockPayload, Hash256};
use parking_lot::RwLock;

use bitcoin_rs_chainstate::{ConnectOutcome, DisconnectOutcome};
use bitcoin_rs_index::runtime::DerivedIndexRuntime;
use bitcoin_rs_mempool::AdmissionOrigin;
use bitcoin_rs_mempool::ChainChangeGuard;
use bitcoin_rs_mempool::MempoolGateway;
use bitcoin_rs_mempool::MutationResult;
use bitcoin_rs_rpc::zmq::{SequenceEvent, ZmqPublisher};

/// Failure of a node-owned single-block connect.
///
/// The authoritative chainstate failure and a failure after a successful
/// commit are deliberately different variants. Callers must not retry the
/// latter as though the block had been refused.
#[derive(Debug, thiserror::Error)]
pub enum ConnectMutationError {
    /// No complete authoritative commit was returned.
    #[error("connect did not produce a committed outcome: {0}")]
    NotCommitted(#[source] bitcoin_rs_chainstate::ApplyError),
    /// Chainstate committed, but the node-owned mempool fence did not settle.
    #[error("authoritative connect committed, but node settlement failed: {source}")]
    CommittedButSettlementFailed {
        /// The authoritative outcome, retained so no caller has to infer it
        /// by rereading mutable global state.
        outcome: Box<ConnectOutcome>,
        /// Failure that forced the node into recovery-required shutdown.
        #[source]
        source: bitcoin_rs_chainstate::ApplyError,
    },
}

/// Node-owned derived work that follows a committed chain event.
///
/// `Chainstate` does not hold this. The composition root dispatches after
/// each committed connect or disconnect, and this type is the one owner of
/// that dispatch: the RPC block log, hash/raw ZMQ, the derived-index wake,
/// the sequence `C`/`D` events, the mining-generation wake, and mempool
/// admission all run from here, in the order `ARCH-07` fixes.
///
/// INVARIANT: consumer failure is ignored. A full ZMQ socket or a lagged
/// index cannot invalidate chainstate.
#[derive(Clone)]
pub struct ChainFollowers {
    blocks: Arc<RwLock<BlockLog>>,
    zmq: Arc<dyn ZmqPublisher>,
    derived_index: Option<Arc<DerivedIndexRuntime>>,
    mining: Arc<crate::mining::MiningGenerationSignal>,
    mempool: Option<Arc<MempoolGateway>>,
    block_announcer: Option<bitcoin_rs_p2p::BlockAnnounceQueue>,
}

impl ChainFollowers {
    /// Builds the follower set over its consumers.
    ///
    /// `mempool` is `None` only for a node without an admission gate. Effects
    /// run through [`Self::on_connect`] and [`Self::on_disconnect`].
    #[must_use]
    pub(crate) fn new(
        blocks: Arc<RwLock<BlockLog>>,
        zmq: Arc<dyn ZmqPublisher>,
        derived_index: Option<Arc<DerivedIndexRuntime>>,
        mining: Arc<crate::mining::MiningGenerationSignal>,
        mempool: Option<Arc<MempoolGateway>>,
    ) -> Self {
        Self {
            blocks,
            zmq,
            derived_index,
            mining,
            mempool,
            block_announcer: None,
        }
    }

    /// Empty RPC log, no-op ZMQ, no index, no admission, a fresh mining signal.
    ///
    /// Test and planner handles use this.
    #[must_use]
    pub fn noop() -> Self {
        Self::new(
            Arc::new(RwLock::new(BlockLog::new())),
            Arc::new(crate::NoOpZmqPublisher),
            None,
            Arc::new(crate::mining::MiningGenerationSignal::new()),
            None,
        )
    }

    /// Returns `self` with `zmq` swapped to `publisher`.
    #[cfg(test)]
    #[must_use]
    pub fn with_zmq_publisher(mut self, publisher: Arc<dyn ZmqPublisher>) -> Self {
        self.zmq = publisher;
        self
    }

    /// Returns `self` with the `TxIndex` wake handle swapped.
    #[must_use]
    pub fn with_tx_index(mut self, derived_index: Option<Arc<DerivedIndexRuntime>>) -> Self {
        self.derived_index = derived_index;
        self
    }

    /// Returns `self` with the block announcement queue swapped.
    #[must_use]
    pub fn with_block_announcer(
        mut self,
        block_announcer: Option<bitcoin_rs_p2p::BlockAnnounceQueue>,
    ) -> Self {
        self.block_announcer = block_announcer;
        self
    }

    /// Whether apply should capture per-transaction wire bytes for `rawtx`.
    #[must_use]
    pub fn needs_rawtx(&self) -> bool {
        self.zmq.wants_rawtx()
    }

    /// Whether apply should serialize the full block for a derived consumer.
    #[must_use]
    pub fn needs_block_bytes(&self) -> bool {
        self.derived_index.is_some() || self.zmq.wants_rawblock()
    }

    /// Returns a read-only capability to observe the applied-block log.
    #[must_use]
    pub fn block_log_reader(&self) -> bitcoin_rs_index::BlockLogReader {
        bitcoin_rs_index::BlockLogReader::new(Arc::clone(&self.blocks))
    }

    /// Shared RPC block log owned by this committed-effect dispatcher.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn block_log(&self) -> &Arc<RwLock<BlockLog>> {
        &self.blocks
    }

    /// Publisher used by committed chain effects and RPC notifier discovery.
    #[must_use]
    pub(crate) fn zmq_publisher(&self) -> Arc<dyn ZmqPublisher> {
        Arc::clone(&self.zmq)
    }

    /// `TxIndex` runtime, when one is wired.
    #[cfg(test)]
    #[must_use]
    pub fn derived_index(&self) -> Option<&Arc<DerivedIndexRuntime>> {
        self.derived_index.as_ref()
    }

    /// Mining generation signal.
    #[must_use]
    pub(crate) fn mining(&self) -> &Arc<crate::mining::MiningGenerationSignal> {
        &self.mining
    }

    #[must_use]
    pub(crate) fn mempool_gateway(&self) -> Option<&Arc<MempoolGateway>> {
        self.mempool.as_ref()
    }

    pub(crate) fn begin_mempool_change(
        &self,
    ) -> core::result::Result<Option<ChainChangeGuard>, bitcoin_rs_chainstate::ApplyError> {
        self.mempool
            .as_ref()
            .map(|gateway| {
                gateway.begin_chain_change().map_err(|error| match error {
                    bitcoin_rs_mempool::ChainChangeError::AlreadyActive
                    | bitcoin_rs_mempool::ChainChangeError::GenerationMoved
                    | bitcoin_rs_mempool::ChainChangeError::ForeignGuard => {
                        bitcoin_rs_chainstate::ApplyError::ConcurrentChainChange
                    }
                    bitcoin_rs_mempool::ChainChangeError::Overflow => {
                        bitcoin_rs_chainstate::ApplyError::ChainChangeGenerationOverflow
                    }
                })
            })
            .transpose()
    }

    pub(crate) fn finish_transition(
        handles: &bitcoin_rs_chainstate::Chainstate,
        transition: bitcoin_rs_chainstate::ChainTransition<'_>,
        mempool_change: Option<ChainChangeGuard>,
    ) -> core::result::Result<(), bitcoin_rs_chainstate::ApplyError> {
        if let Some(change) = mempool_change
            && change.finish().is_err()
        {
            handles.fail_closed_for_recovery();
            return Err(bitcoin_rs_chainstate::ApplyError::Shutdown);
        }
        drop(transition);
        Ok(())
    }

    /// Dispatches a committed connect: RPC log, ZMQ, index wake, sequence `C`,
    /// mining wake, and orphan re-evaluation, in that order.
    ///
    /// PRE: `outcome` is committed and the mempool fence, when present, is
    /// held.
    ///
    /// POST: block-log record, hash/raw ZMQ, derived-index wake plus sequence
    /// `C`, mining wake, and mempool orphan re-evaluation run once in that
    /// order. The block-inclusion removals are committed before sequence
    /// `C`; a `sequence` subscriber sees no `R` event for them, because the
    /// block event already covers the departures. The committed removal
    /// receipt travels with the mining wake so a staged preparation can
    /// install against exactly these removals.
    ///
    /// INVARIANT: consumer failure cannot invalidate chainstate.
    pub(crate) fn on_connect(&self, block: &Block, outcome: &ConnectOutcome) {
        // Step-21 block-to-template baseline: debug-only on-connect span, same
        // mechanism as the chainstate publish profile; no behavior change.
        let on_connect_started = quanta::Instant::now();
        // A follower set without an admission gate removed nothing, so its
        // receipt is truthfully empty: every committed connect publishes one,
        // and a foreground joined on a prepared candidate always sees its
        // tip's receipt arrive.
        let block_removals = if let Some(gateway) = &self.mempool {
            let block_txs: Vec<&bitcoin_rs_primitives::Tx> = block.txs.iter().collect();
            gateway.remove_for_block(
                AdmissionOrigin::Block,
                &block_txs,
                &outcome.txids,
                outcome.height,
                bitcoin_rs_primitives::unix_time_secs(),
            )
        } else {
            MutationResult::empty()
        };
        self.blocks
            .write()
            .push(BlockRecord::from_block(outcome.height, block));
        self.publish_block(outcome);
        self.wake_index();
        if self.zmq.wants_notifications() {
            self.zmq
                .publish_sequence(SequenceEvent::Connected(outcome.hash));
        }
        self.mining
            .publish_block_generation(outcome.hash, &block_removals);
        if let Some(admission) = &self.mempool {
            admission.chain_changed(&outcome.txids);
        }
        if let Some(announcer) = &self.block_announcer {
            announcer.wake();
        }
        tracing::debug!(
            height = outcome.height,
            tip_hash = %outcome.hash,
            on_connect_us = on_connect_started.elapsed().as_micros(),
            "chain_effects: on_connect profile"
        );
    }

    /// Dispatches a committed disconnect: log pop, index wake, and sequence
    /// `D`, then the mining wake and orphan re-evaluation.
    ///
    /// PRE: `outcome` is a committed production disconnect.
    ///
    /// POST: the matching-tail log pop, derived-index wake, and gated
    /// sequence `D` run once in that order; the mining wake and
    /// `restored_parents` re-evaluation then run.
    ///
    /// INVARIANT: a non-matching tail is not popped, and no consumer
    /// failure changes the chainstate result.
    pub(crate) fn on_disconnect(&self, outcome: &DisconnectOutcome) {
        self.pop_matching_tail(outcome.hash);
        self.wake_index();
        if self.zmq.wants_notifications() {
            self.zmq
                .publish_sequence(SequenceEvent::Disconnected(outcome.hash));
        }
        self.mining.publish_generation();
        if let Some(admission) = &self.mempool {
            admission.chain_changed(&outcome.restored_parents);
        }
    }

    /// Emits hash/raw ZMQ topics for a committed block. See `ARCH-07` for
    /// effect ordering.
    fn publish_block(&self, outcome: &ConnectOutcome) {
        if !self.zmq.wants_notifications() {
            return;
        }
        self.zmq.publish_hashblock(outcome.hash);
        if self.zmq.wants_rawblock() {
            self.zmq.publish_rawblock(&outcome.block_bytes);
        }
        if let Some(raw_txs) = &outcome.raw_txs {
            for (txid, rawtx_bytes) in outcome.txids.iter().zip(raw_txs) {
                self.zmq.publish_hashtx(*txid);
                self.zmq.publish_rawtx(rawtx_bytes);
            }
        } else {
            for txid in &outcome.txids {
                self.zmq.publish_hashtx(*txid);
            }
        }
    }

    /// Pops the RPC cache if the tail hash matches this block. See `ARCH-07`.
    ///
    /// The log starts empty on boot and pruning may drop the tail. Matching
    /// the hash stops a pop of a record that is not this block.
    fn pop_matching_tail(&self, hash: Hash256) {
        let mut blocks = self.blocks.write();
        if blocks
            .last()
            .is_some_and(|record| record.hash == BlockHash::from(hash))
        {
            blocks.pop();
        }
    }

    /// Reconciles derived consumers after an atomic snapshot-tip replacement.
    /// The caller has verified an empty mempool under the held generation fence.
    /// No per-block notifications are fabricated for the skipped history.
    pub(crate) fn on_snapshot(&self) {
        if let Some(gateway) = &self.mempool {
            gateway.snapshot_changed();
        }
        self.blocks.write().clear();
        self.wake_index();
        self.mining.publish_generation();
    }

    fn wake_index(&self) {
        if let Some(runtime) = &self.derived_index {
            runtime.wake();
        }
    }

    /// Connects `block` and dispatches this set before the transition ends.
    ///
    /// See `ARCH-07`: production single-block paths must not finish the
    /// [`bitcoin_rs_chainstate::ChainTransition`] and then dispatch, or a later
    /// connect or disconnect can publish derived effects first.
    ///
    /// PRE: no transition or fence is held.
    ///
    /// POST: `Ok` means the block committed and settlement completed;
    /// [`ConnectMutationError::CommittedButSettlementFailed`] retains the
    /// committed outcome when only settlement failed; on refusal nothing is
    /// dispatched and settlement is attempted.
    ///
    /// INVARIANT: fatal errors drop guards without settlement; operational
    /// refusal attempts settlement.
    pub(crate) fn apply_connect(
        &self,
        handles: &bitcoin_rs_chainstate::Chainstate,
        payload: &BlockPayload,
    ) -> core::result::Result<ConnectOutcome, ConnectMutationError> {
        let transition = handles
            .begin_transition()
            .map_err(ConnectMutationError::NotCommitted)?;
        let mempool_change = self
            .begin_mempool_change()
            .map_err(ConnectMutationError::NotCommitted)?;
        self.apply_connect_in_transition(handles, transition, mempool_change, payload)
    }

    pub(crate) fn apply_connect_in_transition(
        &self,
        handles: &bitcoin_rs_chainstate::Chainstate,
        transition: bitcoin_rs_chainstate::ChainTransition<'_>,
        mempool_change: Option<ChainChangeGuard>,
        payload: &BlockPayload,
    ) -> core::result::Result<ConnectOutcome, ConnectMutationError> {
        match transition.connect(payload) {
            Ok(outcome) => {
                self.on_connect(payload.block(), &outcome);
                match Self::finish_transition(handles, transition, mempool_change) {
                    Ok(()) => Ok(outcome),
                    Err(source) => Err(ConnectMutationError::CommittedButSettlementFailed {
                        outcome: Box::new(outcome),
                        source,
                    }),
                }
            }
            Err(error) => {
                if bitcoin_rs_chainstate::classify_apply_error(&error)
                    == bitcoin_rs_chainstate::WindowApplyDisposition::Fatal
                {
                    drop(mempool_change);
                    drop(transition);
                    return Err(ConnectMutationError::NotCommitted(error));
                }
                if let Err(settlement) =
                    Self::finish_transition(handles, transition, mempool_change)
                {
                    tracing::error!(
                        original = %error,
                        finish = %settlement,
                        "chain transition could not be settled after connect refusal"
                    );
                    return Err(ConnectMutationError::NotCommitted(settlement));
                }
                Err(ConnectMutationError::NotCommitted(error))
            }
        }
    }
}

/// Applies genesis when the applied-tip slot is still empty and publishes
/// the header tip from its outcome.
///
/// A fresh chainstate has no applied tip until genesis commits; every
/// caller that can outrun the sync loop's first tick (startup before the
/// RPC listener binds, the sync tick itself) funnels through this one
/// owner. Idempotent — a populated applied tip returns immediately.
///
/// Either connect failure is returned so startup can abort instead of
/// binding RPC onto a chainstate that cannot serve an applied tip. Only a
/// refused connect leaves the slot empty for the sync tick to retry; a
/// failed settlement publishes its tip but has already closed chain
/// admission and requested shutdown, so there is nothing to retry.
pub(crate) fn bootstrap_genesis(
    handles: &bitcoin_rs_chainstate::Chainstate,
    followers: &ChainFollowers,
) -> Result<(), ConnectMutationError> {
    if handles.applied_tip_snapshot().is_some() {
        return Ok(());
    }
    let genesis = handles.network().genesis_block();
    let payload = BlockPayload::from_local(genesis);
    match followers.apply_connect(handles, &payload) {
        // The header-tip cell is the chainstate's to publish — including on
        // a committed-but-unsettled connect, which owns its outcome.
        Ok(outcome) => handles.publish_genesis_tip(outcome.tip),
        Err(error) => {
            if let ConnectMutationError::CommittedButSettlementFailed { outcome, .. } = &error {
                handles.publish_genesis_tip(outcome.tip.clone());
            }
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
