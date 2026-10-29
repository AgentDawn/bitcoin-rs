use bitcoin_rs_primitives::encode::ConsensusEncode;

use super::*;
use crate::tx_policy::tests::{CountingInventory, registered_source, source};

fn sample_tx(version: u32, prev_vout: u32, sat: u64) -> Tx {
    let prev_byte = u8::try_from(prev_vout).expect("fixture vout fits u8");
    Tx {
        version,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                Txid(Hash256::from_le_bytes(&[prev_byte; 32])),
                prev_vout,
            ),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xFFFF_FFFF),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(sat),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn sample_segwit_tx(version: u32, prev_vout: u32, sat: u64, item: Vec<u8>) -> Tx {
    let prev_byte = u8::try_from(prev_vout).expect("fixture vout fits u8");
    Tx {
        version,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                Txid(Hash256::from_le_bytes(&[prev_byte; 32])),
                prev_vout,
            ),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xFFFF_FFFF),
            witness: Witness::from_stack(vec![item]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(sat),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn make_payload(txs: &[Tx]) -> bytes::Bytes {
    let mut buf = Vec::new();
    let count = u64::try_from(txs.len()).expect("fixture tx count fits u64");
    buf.extend_from_slice(&varint::encode(count));
    for tx in txs {
        tx.consensus_encode(&mut buf);
    }
    bytes::Bytes::from(buf)
}

#[test]
fn plan_charge_computes_exact_weights_and_reconciles_on_open() {
    let parent = sample_segwit_tx(2, 1, 50_000, vec![1, 2, 3]);
    let child = sample_tx(2, 2, 40_000);
    let txs = vec![parent.clone(), child.clone()];
    let payload = make_payload(&txs);

    let plan = plan_package_charge(&payload).expect("plan must succeed");
    assert_eq!(plan.count, 2);
    assert_eq!(plan.wtxids(), &[parent.wtxid(), child.wtxid()]);
    assert_eq!(plan.subject(), child.wtxid());
    assert_eq!(plan.weight(), parent.weight() + child.weight());
    assert!(plan.decoded_bytes() > 0);

    let decoded = decode_package(&payload, &plan).expect("decode must succeed");
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].wtxid(), parent.wtxid());
    assert_eq!(decoded[1].wtxid(), child.wtxid());
}

#[test]
fn plan_refuses_empty_malformed_and_out_of_bounds_payloads() {
    assert_eq!(plan_package_charge(&[]), Err(PackageRefusal::Malformed));
    assert_eq!(plan_package_charge(&[0x00]), Err(PackageRefusal::Empty));

    // Overcount: 26 txs.
    let txs: Vec<Tx> = (0..26).map(|i| sample_tx(1, i, 1_000)).collect();
    let payload = make_payload(&txs);
    assert_eq!(
        plan_package_charge(&payload),
        Err(PackageRefusal::OverCount)
    );

    // Over 100 txs is a wire malformation.
    let over_wire = varint::encode(101);
    assert_eq!(
        plan_package_charge(&over_wire),
        Err(PackageRefusal::Malformed)
    );

    // Superfluous segwit marker without witness data.
    let mut superfluous = vec![1]; // count = 1
    superfluous.extend_from_slice(&1_u32.to_le_bytes()); // version = 1
    superfluous.push(0); // input_count = 0 -> check flag
    superfluous.push(1); // flag = 1 -> segwit
    superfluous.push(1); // real input count = 1
    superfluous.extend_from_slice(&[0; 36]); // outpoint
    superfluous.push(0); // script_sig len = 0
    superfluous.extend_from_slice(&[0xFF; 4]); // sequence
    superfluous.push(0); // output count = 0
    superfluous.push(0); // witness items = 0 -> any_item is false!
    superfluous.extend_from_slice(&0_u32.to_le_bytes()); // lock_time
    assert_eq!(
        plan_package_charge(&superfluous),
        Err(PackageRefusal::Malformed)
    );

    // Trailing bytes.
    let mut trailing = make_payload(&[sample_tx(1, 1, 1_000)]).to_vec();
    trailing.push(0xFF);
    assert_eq!(
        plan_package_charge(&trailing),
        Err(PackageRefusal::Malformed)
    );
}

#[test]
fn plan_refuses_overweight_package() {
    // Two individually standard transactions (each ~210_000 WU) whose sum
    // exceeds MAX_PACKAGE_WEIGHT (404_000 WU).
    let tx1 = sample_segwit_tx(2, 1, 1_000, vec![0; 210_000]);
    let tx2 = sample_segwit_tx(2, 2, 1_000, vec![0; 210_000]);
    assert!(tx1.weight() <= 400_000 && tx2.weight() <= 400_000);
    assert!(tx1.weight() + tx2.weight() > MAX_PACKAGE_WEIGHT);
    let payload = make_payload(&[tx1, tx2]);
    assert_eq!(
        plan_package_charge(&payload),
        Err(PackageRefusal::OverWeight)
    );
}

#[test]
fn capacity_bounds_memory_and_enforces_one_package_per_peer() {
    let cap = 1_000;
    let capacity = PackageCapacity::new(cap);
    let peer_a = source(1);
    let peer_b = source(2);

    // peer_a charges 400 frame + 200 decoded = 600 total.
    let (frame_a, decoded_a) = capacity.charge(peer_a, 400, 200).expect("charge succeeds");
    assert_eq!(capacity.reserved(), 600);
    assert_eq!(capacity.held(), 1);

    // peer_a cannot hold a second package concurrently.
    assert!(matches!(
        capacity.charge(peer_a, 50, 50),
        Err(PackageRefusal::PeerHeld)
    ));

    // peer_b requests 300 frame + 200 decoded = 500 total, which would exceed cap 1000.
    assert!(matches!(
        capacity.charge(peer_b, 300, 200),
        Err(PackageRefusal::Budget)
    ));
    assert_eq!(capacity.reserved(), 600);

    // Dropping frame_a releases frame bytes immediately.
    drop(frame_a);
    assert_eq!(capacity.reserved(), 200);
    assert_eq!(capacity.held(), 1);

    // peer_b can now take 500 bytes.
    let (frame_b, decoded_b) = capacity.charge(peer_b, 300, 200).expect("charge succeeds");
    assert_eq!(capacity.reserved(), 700);
    assert_eq!(capacity.held(), 2);

    // Dropping decoded_a releases the slot and bytes for peer_a.
    drop(decoded_a);
    assert_eq!(capacity.reserved(), 500);
    assert_eq!(capacity.held(), 1);

    // peer_a can now take a new package.
    let (frame_a2, decoded_a2) = capacity
        .charge(peer_a, 100, 100)
        .expect("recharge succeeds");
    assert_eq!(capacity.reserved(), 700);
    assert_eq!(capacity.held(), 2);
    drop(frame_a2);
    drop(decoded_a2);
    drop(decoded_b);
    assert_eq!(capacity.reserved(), 300, "peer_b's frame is still held");
    assert_eq!(capacity.held(), 0);
    drop(frame_b);
    assert_eq!(capacity.reserved(), 0);
    assert_eq!(capacity.held(), 0);
}

#[test]
fn foreign_and_unsolicited_bodies_are_refused_without_holding_capacity() {
    let table = PeerTable::new();
    let capacity = PackageCapacity::new(100_000);
    let inventory = CountingInventory::default();
    let peer = source(1);

    let tx = sample_tx(1, 1, 10_000);
    let payload = make_payload(&[tx]);

    // Peer has no awaiting request.
    let result = table.admit_package(&capacity, &inventory, peer, payload);
    assert_eq!(result.err(), Some(PackageRefusal::Unsolicited));
    assert_eq!(capacity.reserved(), 0);
    assert_eq!(capacity.held(), 0);
}

#[test]
fn reordered_and_mismatched_sequence_is_refused_and_claim_stays_awaiting() {
    let table = PeerTable::new();
    let (peer, _rx) = registered_source(&table, 8333);
    let capacity = PackageCapacity::new(100_000);
    let inventory = CountingInventory::default();

    let parent = sample_tx(1, 1, 50_000);
    let child = sample_tx(1, 2, 40_000);
    let subject = child.wtxid();

    // The solicited `ancpkginfo` names parent then child (subject).
    assert!(table.request_package_info(peer, subject, &[]));
    assert!(table.request_package_transactions(peer, subject, vec![parent.wtxid(), subject]));

    // Peer replies with reordered sequence [child, parent].
    let reordered_payload = make_payload(&[child.clone(), parent.clone()]);
    let err = table.admit_package(&capacity, &inventory, peer, reordered_payload);
    assert_eq!(err.err(), Some(PackageRefusal::Unsolicited));
    assert_eq!(capacity.reserved(), 0);
    assert_eq!(capacity.held(), 0);

    // Original claim is still Awaiting; foreign peer cannot adopt it.
    let foreign = source(2);
    let matching_payload = make_payload(&[parent.clone(), child.clone()]);
    let foreign_err = table.admit_package(&capacity, &inventory, foreign, matching_payload.clone());
    assert_eq!(foreign_err.err(), Some(PackageRefusal::Unsolicited));

    // Matching payload from rightful peer succeeds.
    let admitted = table
        .admit_package(&capacity, &inventory, peer, matching_payload)
        .expect("admit succeeds");
    assert_eq!(capacity.held(), 1);
    assert!(capacity.reserved() > 0);

    // Once enqueued, a duplicate send is refused.
    let duplicate_err =
        table.admit_package(&capacity, &inventory, peer, make_payload(&[parent, child]));
    assert!(matches!(
        duplicate_err.err(),
        Some(PackageRefusal::Unsolicited | PackageRefusal::PeerHeld)
    ));

    // Release rejected returns the capacity and clears the claim.
    table.package_response_rejected(admitted.into_token(), &inventory);
    assert_eq!(capacity.reserved(), 0);
    assert_eq!(capacity.held(), 0);
    assert!(
        !table.release_package_claim(peer, subject, &inventory),
        "the claim was released exactly once"
    );
}

#[test]
fn queued_package_survives_disconnect_and_releases_exactly_once() {
    let table = PeerTable::new();
    let (peer, _rx) = registered_source(&table, 8333);
    let capacity = PackageCapacity::new(100_000);
    let inventory = CountingInventory::default();

    let tx = sample_tx(1, 1, 10_000);
    let subject = tx.wtxid();

    assert!(table.request_package_info(peer, subject, &[]));
    assert!(table.request_package_transactions(peer, subject, vec![subject]));

    let payload = make_payload(std::slice::from_ref(&tx));
    let inbound = table
        .admit_package(&capacity, &inventory, peer, payload)
        .expect("admission succeeds");
    assert_eq!(capacity.held(), 1);

    // Peer disconnects: enqueued body stays queued and held.
    table.transaction_peer_disconnected(peer, &inventory);
    assert_eq!(capacity.held(), 1);

    // A replacement connection cannot adopt the claim.
    let replacement = PeerSource::for_test(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
    let rep_payload = make_payload(&[tx]);
    let rep_err = table.admit_package(&capacity, &inventory, replacement, rep_payload);
    assert_eq!(rep_err.err(), Some(PackageRefusal::Unsolicited));
    assert!(
        !table.release_package_claim(replacement, subject, &inventory),
        "a replacement connection cannot release the queued claim"
    );

    // Consumer opens and completes the package.
    let opening = inbound.open();
    let opened = match opening {
        PackageOpening::Opened(opened) => opened,
        PackageOpening::Refused(_) => panic!("opening must succeed"),
    };
    let (token, txs) = opened.into_parts();
    assert_eq!(txs.len(), 1);
    table.package_response_completed(token, &inventory);

    // Released: capacity is 0, held is 0.
    assert_eq!(capacity.reserved(), 0);
    assert_eq!(capacity.held(), 0);
    assert!(
        !table.release_package_claim(peer, subject, &inventory),
        "the claim was released exactly once"
    );

    // Teardown reports zero claims and zero residual bytes.
    let teardown = table.clear_package_claims(&capacity);
    assert_eq!(teardown.claims_cleared, 0);
    assert_eq!(teardown.bytes_reserved, 0);
    assert_eq!(teardown.held, 0);
}

#[test]
fn teardown_clears_stranded_claims_and_reports_unreturned_bytes() {
    let table = PeerTable::new();
    let (peer, _rx) = registered_source(&table, 8333);
    let capacity = PackageCapacity::new(100_000);
    let inventory = CountingInventory::default();

    let stranded = sample_tx(1, 1, 10_000);
    let stranded_subject = stranded.wtxid();
    assert!(table.request_package_info(peer, stranded_subject, &[]));
    assert!(table.request_package_transactions(peer, stranded_subject, vec![stranded_subject]));

    // Claim is Awaiting. Teardown clears it.
    let teardown = table.clear_package_claims(&capacity);
    assert_eq!(teardown.claims_cleared, 1);
    assert_eq!(teardown.bytes_reserved, 0);
    assert_eq!(teardown.held, 0);

    let queued = sample_tx(1, 2, 20_000);
    let queued_subject = queued.wtxid();
    assert!(table.request_package_info(peer, queued_subject, &[]));
    assert!(table.request_package_transactions(peer, queued_subject, vec![queued_subject]));
    let inbound = table
        .admit_package(&capacity, &inventory, peer, make_payload(&[queued]))
        .expect("admission succeeds");
    let charged = capacity.reserved();
    assert!(charged > 0);

    // A body the consumer never released: teardown clears its claim and
    // reports the bytes and the connection slot it still holds.
    let teardown = table.clear_package_claims(&capacity);
    assert_eq!(teardown.claims_cleared, 1);
    assert_eq!(teardown.bytes_reserved, charged);
    assert_eq!(teardown.held, 1);
    assert!(
        !table.release_package_claim(peer, queued_subject, &inventory),
        "a cleared claim has nothing left to release"
    );

    drop(inbound);
    assert_eq!(capacity.reserved(), 0);
    assert_eq!(capacity.held(), 0);
}

#[test]
fn capacity_refusal_after_the_claim_comparison_releases_the_claim_once() {
    let table = PeerTable::new();
    let (peer, _rx) = registered_source(&table, 8333);
    let starved = PackageCapacity::new(1);
    let ample = PackageCapacity::new(100_000);
    let inventory = CountingInventory::default();

    let tx = sample_tx(1, 1, 10_000);
    let subject = tx.wtxid();
    assert!(table.request_package_info(peer, subject, &[]));
    assert!(table.request_package_transactions(peer, subject, vec![subject]));

    let refused = table.admit_package(
        &starved,
        &inventory,
        peer,
        make_payload(std::slice::from_ref(&tx)),
    );
    assert_eq!(refused.err(), Some(PackageRefusal::Budget));
    assert_eq!(starved.reserved(), 0);
    assert_eq!(starved.held(), 0);

    assert!(
        !table.release_package_claim(peer, subject, &inventory),
        "the refusal already released the claim"
    );
    let replay = table.admit_package(
        &ample,
        &inventory,
        peer,
        make_payload(std::slice::from_ref(&tx)),
    );
    assert_eq!(replay.err(), Some(PackageRefusal::Unsolicited));
    assert_eq!(ample.reserved(), 0);
    assert_eq!(ample.held(), 0);

    assert!(
        table.request_package_info(peer, subject, &[]),
        "the retired solicitation frees its hash and in-flight slot"
    );
}

#[test]
fn oversized_body_retires_awaiting_claim_but_not_ordinary_requests() {
    let table = PeerTable::new();
    let capacity = PackageCapacity::new(10_000_000);
    let inventory = CountingInventory::default();
    let (owner, _rx) = registered_source(&table, 8333);
    let (stranger, _) = registered_source(&table, 8334);

    let parent = sample_tx(1, 1, 50_000);
    let child = sample_tx(1, 2, 40_000);
    let subject = child.wtxid();
    assert!(table.request_package_info(owner, subject, &[]));
    assert!(table.request_package_transactions(owner, subject, vec![parent.wtxid(), subject]));

    // 26 members ending at the solicited subject: oversized for admission.
    let mut oversized: Vec<Tx> = (0..25u32).map(|i| sample_tx(3, i, 1_000)).collect();
    oversized.push(child.clone());
    let oversized_payload = make_payload(&oversized);
    assert_eq!(
        table
            .admit_package(&capacity, &inventory, owner, oversized_payload.clone())
            .err(),
        Some(PackageRefusal::OverCount)
    );
    // The `Awaiting` claim retired: the right-sized body is now unsolicited.
    let right_sized = make_payload(&[parent.clone(), child.clone()]);
    assert_eq!(
        table
            .admit_package(&capacity, &inventory, owner, right_sized)
            .err(),
        Some(PackageRefusal::Unsolicited)
    );

    // A forged oversized body from a stranger must not release an ordinary
    // owner: solicit again, then send oversized from the stranger.
    assert!(table.request_package_info(owner, subject, &[]));
    assert!(table.request_package_transactions(owner, subject, vec![parent.wtxid(), subject]));
    assert_eq!(
        table
            .admit_package(&capacity, &inventory, stranger, oversized_payload)
            .err(),
        Some(PackageRefusal::OverCount)
    );
    // The owner's claim survives the stranger's forgery.
    let admitted = table
        .admit_package(&capacity, &inventory, owner, make_payload(&[parent, child]))
        .expect("owner claim survives a stranger oversized body");
    table.package_response_rejected(admitted.into_token(), &inventory);
}
