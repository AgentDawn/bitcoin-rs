//! Bounded ingress for BIP331 `pkgtxns` bodies, contained in the transaction
//! policy owner.
//!
//! A `pkgtxns` body is accepted for admission in one fixed order, and every
//! step before the last allocates nothing a peer controls:
//!
//! 1. [`plan_package_charge`] scans the still-encoded payload without
//!    allocating. It rejects a count above the mempool's package bound from
//!    the `CompactSize` prefix, accumulates each member's exact
//!    [`Tx::weight`] against the package weight bound, and yields the member
//!    wtxids and the decoded-heap lower bound in the same pass.
//! 2. [`PeerTable::begin_package_resolution`] compares the plan against the
//!    sent `getpkgtxns` claim of the exact [`PeerSource`].
//! 3. [`PackageCapacity`] reserves the frame bytes and the planned decoded
//!    bytes with one compare-and-add against a process-wide cap.
//! 4. The still-encoded frame is queued on the node's one bounded ingress
//!    channel as [`InboundBody::Package`].
//!
//! The single ingress consumer then takes the package by value and
//! [`InboundPackage::open`] re-plans the frame (plan equality is exact),
//! decodes it with `try_reserve_exact` at the planned sizes as the one
//! decode-or-admit window, and reconciles the measured heap against the
//! plan. The consumer ends in exactly one of
//! [`PeerTable::package_response_rejected`] (the package never reached
//! admission) or [`PeerTable::package_response_completed`] (the gateway
//! answered, `Ok` or `Err`); each returns the capacity and releases the
//! request claim through the one claim owner.
//!
//! The charge is a lower bound of the heap a decoded package owns, taken at
//! the exact capacities the decoder requests. It is not a physical heap
//! ceiling: allocator rounding is outside it, and no process allocator is
//! made to refuse.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin_rs_mempool::package_heap_usage;
use bitcoin_rs_mempool::standardness::{MAX_PACKAGE_COUNT, MAX_PACKAGE_WEIGHT};
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness, Wtxid,
    varint,
};
use hashbrown::HashSet;
use parking_lot::Mutex;

use crate::packages::{MAX_GETPKGTXNS, combined_package_hash};
use crate::{InboundTx, PeerSource, PeerTable, TxInventory};

/// Decoded packages one connection may hold between acceptance and the end
/// of admission.
pub const MAX_DECODED_PACKAGES_PER_PEER: usize = 1;

/// Smallest serialized input: outpoint, empty script length, sequence.
const MIN_INPUT_LEN: u64 = 41;
/// Smallest serialized output: value and empty script length.
const MIN_OUTPUT_LEN: u64 = 9;
/// Serialized outpoint length.
const OUTPOINT_LEN: usize = 36;

/// Widens a length; slice lengths always fit.
fn wide(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// `size_of::<T>()` as a heap-accounting quantity.
fn slot<T>() -> u64 {
    wide(core::mem::size_of::<T>())
}

/// Why a `pkgtxns` body was not accepted, or not admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PackageRefusal {
    /// The payload is not one well-formed package encoding.
    #[error("pkgtxns payload is malformed")]
    Malformed,
    /// The payload carries no transaction.
    #[error("pkgtxns carries no transaction")]
    Empty,
    /// The package has more members than mempool admission accepts.
    #[error("package exceeds the member bound")]
    OverCount,
    /// The package exceeds the aggregate weight bound.
    #[error("package exceeds the weight bound")]
    OverWeight,
    /// No awaiting request of this exact connection matches the body: it is
    /// unsolicited, foreign, a duplicate, reordered, a different set, or late.
    #[error("package does not match an outstanding request")]
    Unsolicited,
    /// The global package capacity cannot take the charge.
    #[error("package capacity exhausted")]
    Budget,
    /// The connection already holds its one package.
    #[error("connection already holds a package")]
    PeerHeld,
    /// The re-plan at the consumer differs from the accepted plan.
    #[error("package no longer matches its plan")]
    PlanMismatch,
    /// The decoder could not obtain the planned allocation.
    #[error("package allocation refused")]
    Allocation,
}

impl PackageRefusal {
    /// Whether the sender broke the protocol, as opposed to a body this node
    /// merely declines to hold. Only a peer fault ends the connection.
    #[must_use]
    pub const fn is_peer_fault(self) -> bool {
        matches!(self, Self::Malformed | Self::Empty)
    }
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct CapacityState {
    cap: u64,
    /// Bytes charged by live [`PackageCharge`]s. Rises only through
    /// [`Self::try_add`], so it never exceeds `cap`.
    used: AtomicU64,
    /// Connections holding a package; one slot per exact [`PeerSource`].
    held: Mutex<HashSet<PeerSource>>,
}

impl CapacityState {
    /// Compare-and-add: takes `bytes` only while the total stays within `cap`.
    fn try_add(&self, bytes: u64) -> bool {
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.cap)
            })
            .is_ok()
    }

    fn release(&self, bytes: u64) {
        let released = self
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_sub(bytes)
            });
        debug_assert!(released.is_ok(), "released more package bytes than charged");
    }
}

/// The process-wide ledger of retained package bytes.
///
/// INVARIANT: `reserved() <= cap()` at every instant; each byte is owned by
/// exactly one [`PackageCharge`], which returns it when dropped.
#[derive(Clone, Debug)]
pub struct PackageCapacity {
    state: Arc<CapacityState>,
}

impl PackageCapacity {
    /// A ledger that never lets more than `cap` bytes be charged.
    #[must_use]
    pub fn new(cap: u64) -> Self {
        Self {
            state: Arc::new(CapacityState {
                cap,
                used: AtomicU64::new(0),
                held: Mutex::new(HashSet::new()),
            }),
        }
    }

    /// The hard cap.
    #[must_use]
    pub fn cap(&self) -> u64 {
        self.state.cap
    }

    /// Bytes currently charged.
    #[must_use]
    pub fn reserved(&self) -> u64 {
        self.state.used.load(Ordering::Acquire)
    }

    /// Connections currently holding a package.
    #[must_use]
    pub fn held(&self) -> usize {
        self.state.held.lock().len()
    }

    /// Takes the frame and decoded charges of one package for `source` with a
    /// single compare-and-add, and claims `source`'s one package slot.
    ///
    /// POST: `Ok` holds both parts and the slot; any refusal charges nothing
    /// and holds nothing.
    fn charge(
        &self,
        source: PeerSource,
        frame: u64,
        decoded: u64,
    ) -> Result<(PackageCharge, PackageCharge), PackageRefusal> {
        let total = frame.checked_add(decoded).ok_or(PackageRefusal::Budget)?;
        let mut held = self.state.held.lock();
        if held.contains(&source) {
            return Err(PackageRefusal::PeerHeld);
        }
        if !self.state.try_add(total) {
            return Err(PackageRefusal::Budget);
        }
        held.insert(source);
        drop(held);
        Ok((
            PackageCharge {
                state: Arc::clone(&self.state),
                bytes: frame,
                slot: None,
            },
            PackageCharge {
                state: Arc::clone(&self.state),
                bytes: decoded,
                slot: Some(source),
            },
        ))
    }

    /// A charge of nothing, for a refusal that still ends in the one release.
    fn nothing(&self) -> PackageCharge {
        PackageCharge {
            state: Arc::clone(&self.state),
            bytes: 0,
            slot: None,
        }
    }
}

/// The sole owner of `bytes` of [`PackageCapacity`], and of one connection's
/// package slot when it is the decoded part of a package.
///
/// Dropping returns both: there is no other release, so an error, a full
/// channel, a cancelled session or a dropped channel reclaims them.
#[derive(Debug)]
pub struct PackageCharge {
    state: Arc<CapacityState>,
    bytes: u64,
    slot: Option<PeerSource>,
}

impl PackageCharge {
    /// Bytes this part owns.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Takes `extra` more bytes by compare-and-add. `false` charges nothing.
    fn top_up(&mut self, extra: u64) -> bool {
        if !self.state.try_add(extra) {
            return false;
        }
        // The addition succeeded under the cap, so it cannot overflow.
        self.bytes = self.bytes.saturating_add(extra);
        true
    }
}

impl Drop for PackageCharge {
    fn drop(&mut self) {
        if let Some(source) = self.slot.take() {
            self.state.held.lock().remove(&source);
        }
        self.state.release(self.bytes);
    }
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// The outcome of [`plan_package_charge`]: everything the charge and the
/// claim comparison need, for the frame it was computed from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackagePlan {
    count: usize,
    wtxids: [Wtxid; MAX_PACKAGE_COUNT],
    weight: u64,
    decoded_bytes: u64,
}

impl PackagePlan {
    /// The member wtxids in wire order.
    #[must_use]
    pub fn wtxids(&self) -> &[Wtxid] {
        self.wtxids.get(..self.count).unwrap_or(&[])
    }

    /// The request subject: the last member.
    #[must_use]
    pub fn subject(&self) -> Wtxid {
        self.wtxids().last().copied().unwrap_or_default()
    }

    /// Total consensus weight of the members.
    #[must_use]
    pub const fn weight(&self) -> u64 {
        self.weight
    }

    /// Lower bound of the heap the decoded package owns, at the exact
    /// capacities the decoder requests.
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
}

/// A forward cursor over one immutable payload.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn take_len(&mut self, len: usize) -> Result<&'a [u8], PackageRefusal> {
        let (head, tail) = self
            .rest
            .split_at_checked(len)
            .ok_or(PackageRefusal::Malformed)?;
        self.rest = tail;
        Ok(head)
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8], PackageRefusal> {
        self.take_len(usize::try_from(len).map_err(|_| PackageRefusal::Malformed)?)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PackageRefusal> {
        <[u8; N]>::try_from(self.take_len(N)?).map_err(|_| PackageRefusal::Malformed)
    }

    /// A minimal `CompactSize`.
    fn compact(&mut self) -> Result<u64, PackageRefusal> {
        let (value, used) = varint::decode(self.rest).map_err(|_| PackageRefusal::Malformed)?;
        self.rest = self.rest.get(used..).ok_or(PackageRefusal::Malformed)?;
        Ok(value)
    }

    /// Rejects a count whose minimal footprint exceeds what remains, before
    /// any per-record work.
    fn require_count(&self, count: u64, minimum: u64) -> Result<(), PackageRefusal> {
        if count.saturating_mul(minimum) > wide(self.rest.len()) {
            return Err(PackageRefusal::Malformed);
        }
        Ok(())
    }

    const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
}

fn varint_len(value: u64) -> u64 {
    wide(varint::encoded_len(value))
}

/// What the plan keeps of one scanned transaction.
struct TxScan {
    weight: u64,
    heap: u64,
    wtxid: Wtxid,
}

/// Scans one transaction in the shapes `Tx::consensus_decode` accepts,
/// without allocating.
fn scan_tx(reader: &mut Reader<'_>) -> Result<TxScan, PackageRefusal> {
    let image = reader.rest;
    reader.take_len(4)?;
    let mut inputs = reader.compact()?;
    let mut segwit = false;
    let mut legacy_empty = false;
    if inputs == 0 {
        // Core reads a zero flag as the legacy empty-input form and `0x01` as
        // the BIP144 marker; anything else is rejected.
        match reader.array::<1>()? {
            [0] => legacy_empty = true,
            [1] => {
                segwit = true;
                inputs = reader.compact()?;
            }
            _ => return Err(PackageRefusal::Malformed),
        }
    }
    reader.require_count(inputs, MIN_INPUT_LEN)?;

    // version + lock time, then every counted part below.
    let mut base = 8_u64.saturating_add(varint_len(inputs));
    let mut heap = 0_u64;
    for _ in 0..inputs {
        reader.take_len(OUTPOINT_LEN)?;
        let script = reader.compact()?;
        reader.take(script)?;
        reader.take_len(4)?;
        base = base
            .saturating_add(36 + 4)
            .saturating_add(varint_len(script))
            .saturating_add(script);
        heap = heap.saturating_add(script);
    }

    let outputs = if legacy_empty { 0 } else { reader.compact()? };
    reader.require_count(outputs, MIN_OUTPUT_LEN)?;
    base = base.saturating_add(varint_len(outputs));
    for _ in 0..outputs {
        reader.take_len(8)?;
        let script = reader.compact()?;
        reader.take(script)?;
        base = base
            .saturating_add(8)
            .saturating_add(varint_len(script))
            .saturating_add(script);
        heap = heap.saturating_add(script);
    }

    let mut witness = 0_u64;
    if segwit {
        // Marker and flag, then one stack per input.
        witness = 2;
        let mut any_item = false;
        for _ in 0..inputs {
            let items = reader.compact()?;
            reader.require_count(items, 1)?;
            witness = witness.saturating_add(varint_len(items));
            heap = heap.saturating_add(items.saturating_mul(slot::<Vec<u8>>()));
            for _ in 0..items {
                let len = reader.compact()?;
                reader.take(len)?;
                witness = witness.saturating_add(varint_len(len)).saturating_add(len);
                heap = heap.saturating_add(len);
            }
            any_item |= items > 0;
        }
        // The marker exists only to carry witness data (BIP144).
        if !any_item {
            return Err(PackageRefusal::Malformed);
        }
    }
    reader.take_len(4)?;

    let consumed = image
        .len()
        .checked_sub(reader.rest.len())
        .and_then(|consumed| image.get(..consumed))
        .ok_or(PackageRefusal::Malformed)?;
    let heap = heap
        .saturating_add(slot::<Tx>())
        .saturating_add(inputs.saturating_mul(slot::<TxIn>()))
        .saturating_add(outputs.saturating_mul(slot::<TxOut>()));
    Ok(TxScan {
        // `Tx::weight`: `base * 3 + (base + witness)`.
        weight: base.saturating_mul(4).saturating_add(witness),
        heap,
        wtxid: Wtxid(double_sha256(consumed)),
    })
}

/// Plans the charge of one encoded `pkgtxns` payload.
///
/// PRE: `payload` is the frame exactly as received.
/// POST: `Ok` means the payload is one exactly-consumed list of at most
///   [`MAX_PACKAGE_COUNT`] well-formed transactions whose weights sum to at
///   most [`MAX_PACKAGE_WEIGHT`]; the plan carries their wtxids and the heap
///   their decoded form owns. Any other payload is a typed refusal.
/// INVARIANT: allocates nothing and reserves nothing; work is bounded by
///   the payload length.
pub fn plan_package_charge(payload: &[u8]) -> Result<PackagePlan, PackageRefusal> {
    let mut reader = Reader::new(payload);
    let count = reader.compact()?;
    if count == 0 {
        return Err(PackageRefusal::Empty);
    }
    // The codec's wire bound; beyond it the message is malformed, not merely
    // too big for admission.
    if count > wide(MAX_GETPKGTXNS) {
        return Err(PackageRefusal::Malformed);
    }
    let count = usize::try_from(count).map_err(|_| PackageRefusal::Malformed)?;
    if count > MAX_PACKAGE_COUNT {
        return Err(PackageRefusal::OverCount);
    }
    let mut plan = PackagePlan {
        count,
        wtxids: [Wtxid::default(); MAX_PACKAGE_COUNT],
        weight: 0,
        decoded_bytes: 0,
    };
    for index in 0..count {
        let scan = scan_tx(&mut reader)?;
        plan.weight = plan.weight.saturating_add(scan.weight);
        if count > 1 && plan.weight > MAX_PACKAGE_WEIGHT {
            return Err(PackageRefusal::OverWeight);
        }
        plan.decoded_bytes = plan.decoded_bytes.saturating_add(scan.heap);
        *plan
            .wtxids
            .get_mut(index)
            .ok_or(PackageRefusal::OverCount)? = scan.wtxid;
    }
    if !reader.is_empty() {
        return Err(PackageRefusal::Malformed);
    }
    Ok(plan)
}

/// The subject of an oversized `pkgtxns` body, for claim retirement: the last
/// member's wtxid when the payload is a well-formed list of `1..=MAX_GETPKGTXNS`
/// transactions, even when the count or weight exceeds admission. `None` for
/// any malformed payload, which has no attributable claim to retire. Work is
/// bounded by the payload length and allocates nothing.
fn oversized_subject(payload: &[u8]) -> Option<Wtxid> {
    let mut reader = Reader::new(payload);
    let count = reader.compact().ok()?;
    if count == 0 || count > wide(MAX_GETPKGTXNS) {
        return None;
    }
    let count = usize::try_from(count).ok()?;
    let mut last = None;
    for _ in 0..count {
        last = Some(scan_tx(&mut reader).ok()?.wtxid);
    }
    if !reader.is_empty() {
        return None;
    }
    last
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

fn reserve_exact<T>(len: usize) -> Result<Vec<T>, PackageRefusal> {
    let mut vec = Vec::new();
    vec.try_reserve_exact(len)
        .map_err(|_| PackageRefusal::Allocation)?;
    Ok(vec)
}

/// A length-prefixed byte string in a buffer of exactly its length.
fn read_bytes(reader: &mut Reader<'_>) -> Result<Vec<u8>, PackageRefusal> {
    let len = reader.compact()?;
    let bytes = reader.take(len)?;
    let mut buffer = reserve_exact(bytes.len())?;
    buffer.extend_from_slice(bytes);
    Ok(buffer)
}

fn read_u32(reader: &mut Reader<'_>) -> Result<u32, PackageRefusal> {
    Ok(u32::from_le_bytes(reader.array::<4>()?))
}

fn decode_tx(reader: &mut Reader<'_>) -> Result<Tx, PackageRefusal> {
    let version = read_u32(reader)?;
    let mut input_count = reader.compact()?;
    let mut segwit = false;
    let mut legacy_empty = false;
    if input_count == 0 {
        match reader.array::<1>()? {
            [0] => legacy_empty = true,
            [1] => {
                segwit = true;
                input_count = reader.compact()?;
            }
            _ => return Err(PackageRefusal::PlanMismatch),
        }
    }
    let mut inputs = reserve_exact::<TxIn>(
        usize::try_from(input_count).map_err(|_| PackageRefusal::PlanMismatch)?,
    )?;
    for _ in 0..input_count {
        let txid = reader.array::<32>()?;
        let vout = read_u32(reader)?;
        let script_sig = read_bytes(reader)?;
        let sequence = read_u32(reader)?;
        inputs.push(TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&txid)), vout),
            script_sig: Script::from_bytes(script_sig),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        });
    }
    let output_count = if legacy_empty { 0 } else { reader.compact()? };
    let mut outputs = reserve_exact::<TxOut>(
        usize::try_from(output_count).map_err(|_| PackageRefusal::PlanMismatch)?,
    )?;
    for _ in 0..output_count {
        let value = u64::from_le_bytes(reader.array::<8>()?);
        outputs.push(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(read_bytes(reader)?),
        });
    }
    if segwit {
        for input in &mut inputs {
            let items = reader.compact()?;
            let mut stack = reserve_exact::<Vec<u8>>(
                usize::try_from(items).map_err(|_| PackageRefusal::PlanMismatch)?,
            )?;
            for _ in 0..items {
                stack.push(read_bytes(reader)?);
            }
            input.witness = Witness::from_stack(stack);
        }
    }
    Ok(Tx {
        version,
        inputs,
        outputs,
        lock_time: LockTime::from_consensus(read_u32(reader)?),
    })
}

/// Decodes a payload `plan` was computed from, requesting exactly the planned
/// capacity for every buffer.
fn decode_package(payload: &[u8], plan: &PackagePlan) -> Result<Vec<Tx>, PackageRefusal> {
    let mut reader = Reader::new(payload);
    if usize::try_from(reader.compact()?) != Ok(plan.count) {
        return Err(PackageRefusal::PlanMismatch);
    }
    let mut txs = reserve_exact::<Tx>(plan.count)?;
    for _ in 0..plan.count {
        // Within the reserved capacity: no reallocation.
        txs.push(decode_tx(&mut reader)?);
    }
    if !reader.is_empty() {
        return Err(PackageRefusal::PlanMismatch);
    }
    Ok(txs)
}

// ---------------------------------------------------------------------------
// Package lifecycle
// ---------------------------------------------------------------------------

/// The frame's own bytes and the charge that pays for them. The charge is
/// returned when the frame drops, and not before.
#[derive(Debug)]
struct RawFrame {
    payload: bytes::Bytes,
    _charge: PackageCharge,
}

/// The identity of one accepted body and the decoded part of its charge.
///
/// A token obliges its holder to end in exactly one of
/// [`PeerTable::package_response_rejected`] and
/// [`PeerTable::package_response_completed`]; neither can be skipped without
/// leaving the request claim held until the hash becomes known.
#[derive(Debug)]
#[must_use = "a package token must end in package_response_rejected or package_response_completed"]
pub struct PackageToken {
    source: PeerSource,
    subject: Wtxid,
    decoded: PackageCharge,
}

impl PackageToken {
    /// The connection that delivered the body.
    #[must_use]
    pub const fn source(&self) -> PeerSource {
        self.source
    }

    /// The request subject the body answers.
    #[must_use]
    pub const fn subject(&self) -> Wtxid {
        self.subject
    }
}

/// A `pkgtxns` frame accepted for admission: still encoded, charged, and
/// bound to its request. Exactly one exists per connection at a time.
#[derive(Debug)]
pub struct InboundPackage {
    token: PackageToken,
    frame: RawFrame,
    plan: PackagePlan,
}

impl InboundPackage {
    /// The connection that delivered the body.
    #[must_use]
    pub const fn source(&self) -> PeerSource {
        self.token.source
    }

    /// The request subject the body answers.
    #[must_use]
    pub const fn subject(&self) -> Wtxid {
        self.token.subject
    }

    /// The plan the body was accepted under.
    #[must_use]
    pub const fn plan(&self) -> &PackagePlan {
        &self.plan
    }

    /// Gives the frame back and keeps the token, for a body that never
    /// reached the consumer.
    pub fn into_token(self) -> PackageToken {
        self.token
    }

    /// Re-plans, decodes and reconciles the body: the sole decode-or-admit
    /// window, run by the single ingress consumer.
    ///
    /// PRE: `self` came from [`PeerTable::admit_package`].
    /// POST: `Opened` owns the decoded transactions at exactly the planned
    ///   capacities and the decoded charge; the frame charge is already
    ///   returned. `Refused` returns the token for
    ///   [`PeerTable::package_response_rejected`] with nothing decoded kept.
    /// INVARIANT: measured heap is compared with the plan as a lower bound,
    ///   never as an equality. An excess is topped up by compare-and-add and
    ///   reported in [`OpenedPackage::overrun`]; a refused top-up refuses the
    ///   package. The charge only ever rises through the cap check.
    pub fn open(self) -> PackageOpening {
        let Self {
            mut token,
            frame,
            plan,
        } = self;
        match plan_package_charge(&frame.payload) {
            Ok(replanned) if replanned == plan => {}
            _ => {
                return PackageOpening::Refused(PackageRejection {
                    token,
                    refusal: PackageRefusal::PlanMismatch,
                });
            }
        }
        let txs = match decode_package(&frame.payload, &plan) {
            Ok(txs) => txs,
            Err(refusal) => return PackageOpening::Refused(PackageRejection { token, refusal }),
        };
        drop(frame);
        let spare = txs.capacity().saturating_sub(txs.len());
        let overrun = package_heap_usage(&txs, spare).saturating_sub(plan.decoded_bytes);
        if overrun > 0 && !token.decoded.top_up(overrun) {
            return PackageOpening::Refused(PackageRejection {
                token,
                refusal: PackageRefusal::Budget,
            });
        }
        PackageOpening::Opened(OpenedPackage {
            token,
            txs,
            overrun,
        })
    }
}

/// What [`InboundPackage::open`] produced.
#[derive(Debug)]
pub enum PackageOpening {
    /// The body decoded at its planned size.
    Opened(OpenedPackage),
    /// The body was refused; release its token as rejected.
    Refused(PackageRejection),
}

/// A refused body's token and the reason.
#[derive(Debug)]
pub struct PackageRejection {
    /// The token to release with [`PeerTable::package_response_rejected`].
    pub token: PackageToken,
    /// Why the body was refused.
    pub refusal: PackageRefusal,
}

/// A decoded package in its one admission window.
#[derive(Debug)]
pub struct OpenedPackage {
    token: PackageToken,
    txs: Vec<Tx>,
    overrun: u64,
}

impl OpenedPackage {
    /// Bytes the measured heap exceeded the plan by, after the top-up.
    #[must_use]
    pub const fn overrun(&self) -> u64 {
        self.overrun
    }

    /// The connection that delivered the body.
    #[must_use]
    pub const fn source(&self) -> PeerSource {
        self.token.source
    }

    /// The decoded members, in the peer-supplied order.
    #[must_use]
    pub fn txs(&self) -> &[Tx] {
        &self.txs
    }

    /// Hands the members to admission and keeps the token, which still owns
    /// the decoded charge until [`PeerTable::package_response_completed`].
    pub fn into_parts(self) -> (PackageToken, Vec<Tx>) {
        (self.token, self.txs)
    }
}

/// One item of the node's bounded peer-body ingress channel.
pub enum InboundBody {
    /// A decoded `tx` body.
    Tx(InboundTx),
    /// An encoded, charged `pkgtxns` body.
    Package(Box<InboundPackage>),
}

impl core::fmt::Debug for InboundBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tx(tx) => f
                .debug_struct("InboundBody::Tx")
                .field("source", &tx.source)
                .field("txid", &tx.tx.txid())
                .finish(),
            Self::Package(package) => f
                .debug_tuple("InboundBody::Package")
                .field(package)
                .finish(),
        }
    }
}

impl From<InboundTx> for InboundBody {
    fn from(tx: InboundTx) -> Self {
        Self::Tx(tx)
    }
}

impl From<InboundPackage> for InboundBody {
    fn from(package: InboundPackage) -> Self {
        Self::Package(Box::new(package))
    }
}

/// What [`PeerTable::clear_package_claims`] found at teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageTeardown {
    /// Package claims still recorded and now cleared.
    pub claims_cleared: usize,
    /// Bytes still charged. Zero once every token has been dropped.
    pub bytes_reserved: u64,
    /// Connections still holding a package. Zero with `bytes_reserved`.
    pub held: usize,
}

impl PeerTable {
    /// Accepts one `pkgtxns` payload for admission: plan, compare, reserve.
    ///
    /// PRE: `payload` is the frame exactly as read from `source`; the caller
    ///   has checked package negotiation and that transaction relay is open.
    /// POST: `Ok` holds one claim in `Enqueued`, the frame and decoded charges
    ///   and `source`'s package slot; the caller must queue the package and
    ///   end in one release. A refusal holds nothing and mutates nothing,
    ///   except that a body already compared and then refused for capacity
    ///   releases its claim through [`Self::package_response_rejected`],
    ///   and an oversized body retires `source`'s solicited claim so an
    ///   alternate source is offered the request without waiting for expiry.
    /// INVARIANT: nothing is decoded and nothing is reserved before the
    ///   claim comparison succeeds.
    pub fn admit_package(
        &self,
        capacity: &PackageCapacity,
        inventory: &dyn TxInventory,
        source: PeerSource,
        payload: bytes::Bytes,
    ) -> Result<InboundPackage, PackageRefusal> {
        let plan = match plan_package_charge(&payload) {
            Ok(plan) => plan,
            Err(refusal @ (PackageRefusal::OverCount | PackageRefusal::OverWeight)) => {
                Self::retire_oversized_solicitation(self, source, &payload);
                return Err(refusal);
            }
            Err(other) => return Err(other),
        };
        let subject = plan.subject();
        let combined = combined_package_hash(plan.wtxids());
        if !self.begin_package_resolution(source, subject, combined, plan.wtxids()) {
            return Err(PackageRefusal::Unsolicited);
        }
        match capacity.charge(source, wide(payload.len()), plan.decoded_bytes()) {
            Ok((frame, decoded)) => Ok(InboundPackage {
                token: PackageToken {
                    source,
                    subject,
                    decoded,
                },
                frame: RawFrame {
                    payload,
                    _charge: frame,
                },
                plan,
            }),
            Err(refusal) => {
                self.package_response_rejected(
                    PackageToken {
                        source,
                        subject,
                        decoded: capacity.nothing(),
                    },
                    inventory,
                );
                Err(refusal)
            }
        }
    }

    /// Retires `source`'s solicited claim when its `pkgtxns` body is
    /// oversized for admission. The body cannot be admitted, but leaving the
    /// `Awaiting` claim until expiry would hold the request's in-flight slot
    /// and block alternates; retiring offers the request promptly like any
    /// other failure. Malformed bodies have no attributable subject and
    /// retire nothing; a source without an `Awaiting` claim is a no-op.
    fn retire_oversized_solicitation(&self, source: PeerSource, payload: &[u8]) {
        let Some(subject) = oversized_subject(payload) else {
            return;
        };
        let key = super::Identity::Wtxid(subject.0);
        let now = std::time::Instant::now();
        let mut policy = self.tx_policy.lock();
        // Only an `Awaiting` package claim owned by this source may retire
        // here. An ordinary WTXID download for the same hash, another source's
        // claim, or an already-`Enqueued` body must keep its owner and retry
        // path; a forged oversized body must not release them.
        let awaiting = policy.requests.get(&key).is_some_and(|request| {
            request
                .package
                .as_ref()
                .is_some_and(|claim| claim.state == super::PackagePhase::Awaiting)
                && request.owner.is_some_and(|(owner, _)| owner == source)
        });
        if !awaiting {
            return;
        }
        // The claim's riding orphan parents fall back to `source`.
        let keys = policy.failed_with_parents(key, source, now);
        drop(policy);
        self.send_transaction_requests(now, None, Some(&keys), std::time::Instant::now);
    }

    /// The sole pre-admission release: the body never reached the gateway
    /// (capacity refusal, full or closed channel, cancellation, send failure,
    /// decode refusal).
    pub fn package_response_rejected(&self, token: PackageToken, inventory: &dyn TxInventory) {
        self.release_token(token, inventory);
    }

    /// The sole post-admission release: the gateway answered, `Ok` or `Err`.
    pub fn package_response_completed(&self, token: PackageToken, inventory: &dyn TxInventory) {
        self.release_token(token, inventory);
    }

    /// Returns the decoded charge and the connection's slot, then retires the
    /// `Enqueued` claim through its one owner. A claim already retired (the
    /// hash became known meanwhile) makes the second step a no-op.
    fn release_token(&self, token: PackageToken, inventory: &dyn TxInventory) {
        let PackageToken {
            source,
            subject,
            decoded,
        } = token;
        drop(decoded);
        self.release_package_claim(source, subject, inventory);
    }

    /// Clears every package claim still recorded and reports what the
    /// capacity still holds. Called last in node teardown, after the ingress
    /// consumer has stopped and its channel has been dropped.
    pub fn clear_package_claims(&self, capacity: &PackageCapacity) -> PackageTeardown {
        let claims_cleared = self
            .tx_policy
            .lock()
            .teardown_package_claims(std::time::Instant::now());
        PackageTeardown {
            claims_cleared,
            bytes_reserved: capacity.reserved(),
            held: capacity.held(),
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
