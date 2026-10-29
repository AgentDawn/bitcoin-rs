use alloc::sync::Arc;
use std::io::{Read as _, Write as _};
use std::net::SocketAddr;

use bitcoin_rs_p2p::{CountingStream, PeerCounters, PeerInfo, PeerLease, PeerTable};
use crossbeam_channel::unbounded;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

use super::{getnetworkinfo, getpeerinfo};
use crate::context::Context;

fn peer(addr: &str, bind: &str, time_offset: i64, counters: Arc<PeerCounters>) -> PeerInfo {
    directed_peer(addr, bind, time_offset, counters, true)
}

/// A peer whose direction the test chooses.
///
/// The clock offset is sampled from outbound peers only, so a fixture that
/// cannot make one cannot exercise the median at all.
fn directed_peer(
    addr: &str,
    bind: &str,
    time_offset: i64,
    counters: Arc<PeerCounters>,
    inbound: bool,
) -> PeerInfo {
    let parse = |text: &str| -> SocketAddr {
        text.parse()
            .unwrap_or_else(|_| panic!("test address {text} must parse"))
    };
    PeerInfo {
        wtxid_relay: false,
        relay_transactions: true,
        compact_block_relay: false,
        send_headers: false,
        endpoint: Some(bitcoin_rs_p2p::PeerEndpoint::Ip(parse(addr))),
        network: bitcoin_rs_p2p::PeerEndpoint::Ip(parse(addr)).net(),
        addr: parse(addr).into(),
        version: 70_016,
        services: 0,
        user_agent: "/test/".to_owned(),
        start_height: 0,
        best_known_height: 0,
        conn_time: 0,
        inbound,
        addr_bind: bitcoin_rs_p2p::TransportRemote::new(parse(bind)),
        time_offset,
        counters,
        transport: bitcoin_rs_p2p::TransportProtocol::V1,
    }
}

/// `count` outbound peers, each declaring the offset `offsets` gives it.
fn outbound_peers(offsets: &[i64]) -> Vec<PeerInfo> {
    offsets
        .iter()
        .enumerate()
        .map(|(index, offset)| {
            directed_peer(
                &format!("127.0.0.1:{}", index + 1),
                &format!("127.0.0.1:{}", 1000 + index),
                *offset,
                Arc::new(PeerCounters::default()),
                false,
            )
        })
        .collect()
}

fn context_with(peers: Vec<PeerInfo>) -> Arc<Context> {
    let peer_table = PeerTable::new();
    for info in peers {
        let (tx, _rx) = unbounded();
        let lease = PeerLease::new(tx);
        let Some(endpoint) = info.endpoint else {
            panic!("identified test peer missing endpoint");
        };
        peer_table.register(endpoint, lease.clone());
        peer_table.publish_info(endpoint, &lease, info);
    }
    let mut ctx = Context::new();
    ctx.network.peer_table = Arc::new(peer_table);
    Arc::new(ctx)
}

fn first_peer(ctx: &Arc<Context>) -> sonic_rs::Value {
    let result =
        getpeerinfo(ctx, &json!(null)).unwrap_or_else(|err| panic!("getpeerinfo failed: {err}"));
    let Some(entry) = result.as_array().and_then(|array| array.first()) else {
        panic!("getpeerinfo returned no peers: {result:?}");
    };
    entry.clone()
}

/// The byte counts are the connection's own, not a placeholder.
///
/// The traffic is put through a `CountingStream`, the way a real connection
/// does it, so this covers the wiring and not just the rendering.
#[test]
fn getpeerinfo_reports_what_the_connection_actually_moved() {
    let counters = Arc::new(PeerCounters::default());
    {
        let mut sent = CountingStream::new(Vec::new(), Arc::clone(&counters));
        let _written = sent
            .write(&[0_u8; 42])
            .unwrap_or_else(|error| panic!("write failed: {error}"));
        let mut received =
            CountingStream::new(std::io::Cursor::new(vec![1_u8; 7]), Arc::clone(&counters));
        let mut buffer = [0_u8; 7];
        let _read = received
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("read failed: {error}"));
    }

    let ctx = context_with(vec![peer(
        "127.0.0.1:8333",
        "10.0.0.2:51234",
        0,
        Arc::clone(&counters),
    )]);
    let entry = first_peer(&ctx);

    assert_eq!(
        entry.get("bytessent").and_then(JsonValueTrait::as_u64),
        Some(42)
    );
    assert_eq!(
        entry.get("bytesrecv").and_then(JsonValueTrait::as_u64),
        Some(7)
    );
    assert_ne!(
        entry.get("lastsend").and_then(JsonValueTrait::as_u64),
        Some(0),
        "a connection that sent something has a last-send time"
    );
    assert_ne!(
        entry.get("lastrecv").and_then(JsonValueTrait::as_u64),
        Some(0)
    );
}

/// `addrbind` is this node's end of the connection.
///
/// It used to repeat `addr`, which told an operator listening on several
/// interfaces nothing at all about which one carried the peer.
#[test]
fn getpeerinfo_reports_the_bind_address_not_the_peer_address() {
    let ctx = context_with(vec![peer(
        "203.0.113.7:8333",
        "10.0.0.2:51234",
        0,
        Arc::new(PeerCounters::default()),
    )]);
    let entry = first_peer(&ctx);

    assert_eq!(
        entry.get("addr").and_then(JsonValueTrait::as_str),
        Some("203.0.113.7:8333")
    );
    assert_eq!(
        entry.get("addrbind").and_then(JsonValueTrait::as_str),
        Some("10.0.0.2:51234")
    );
}

/// A peer's clock offset is reported with its sign.
#[test]
fn getpeerinfo_reports_the_peers_clock_offset() {
    for offset in [-90_i64, 0, 120] {
        let ctx = context_with(vec![peer(
            "127.0.0.1:8333",
            "127.0.0.1:1234",
            offset,
            Arc::new(PeerCounters::default()),
        )]);
        assert_eq!(
            first_peer(&ctx)
                .get("timeoffset")
                .and_then(JsonValueTrait::as_i64),
            Some(offset)
        );
    }
}

/// The negotiated transport is reported as Core does: `v2` with the
/// BIP324 session id in byte order, or `v1` with an empty id.
#[test]
fn getpeerinfo_reports_the_negotiated_transport() {
    let mut session_id = [0_u8; 32];
    session_id[0] = 0xab;
    session_id[31] = 0x01;
    for (transport, kind, id) in [
        (bitcoin_rs_p2p::TransportProtocol::V1, "v1", String::new()),
        (
            bitcoin_rs_p2p::TransportProtocol::V2 { session_id },
            "v2",
            format!("ab{}01", "00".repeat(30)),
        ),
    ] {
        let mut info = peer(
            "127.0.0.1:8333",
            "127.0.0.1:1234",
            0,
            Arc::new(PeerCounters::default()),
        );
        info.transport = transport;
        let ctx = context_with(vec![info]);
        let row = first_peer(&ctx);
        assert_eq!(
            row.get("transport_protocol_type")
                .and_then(JsonValueTrait::as_str),
            Some(kind)
        );
        assert_eq!(
            row.get("session_id").and_then(JsonValueTrait::as_str),
            Some(id.as_str())
        );
    }
}

/// The node's own offset is the median, so one peer cannot move it.
///
/// The figure exists to tell an operator their clock is wrong. A single
/// peer claiming an absurd time must not be able to raise that alarm, which
/// is exactly what a mean would let it do.
#[test]
fn getnetworkinfo_timeoffset_is_the_median_of_its_peers() {
    let ctx = context_with(outbound_peers(&[10, 20, 30, 40, 100_000]));

    let result = getnetworkinfo(&ctx, &json!(null))
        .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));

    assert_eq!(
        result.get("timeoffset").and_then(JsonValueTrait::as_i64),
        Some(30),
        "the outlier must not move the median"
    );
}

/// An inbound peer cannot move the node's reported clock offset.
///
/// Core takes samples from outbound peers only, and says why at the call
/// site: "Don't use timedata samples from inbound peers to make it harder
/// for others to create false warnings about our clock being out of sync."
/// Anyone can open an inbound connection and declare any time they like, so
/// medianing over every peer hands whoever does that the operator's belief
/// about whether this machine's clock is wrong.
///
/// Five outbound peers agreeing on ten seconds, and a crowd of inbound ones
/// declaring an hour. The inbound peers outnumber the outbound ones, so a
/// median over all of them lands on the inbound value and this fails.
#[test]
fn getnetworkinfo_timeoffset_ignores_inbound_peers() {
    let mut peers = outbound_peers(&[10, 10, 10, 10, 10]);
    for index in 0..9 {
        peers.push(directed_peer(
            &format!("127.0.0.2:{}", index + 1),
            &format!("127.0.0.1:{}", 2000 + index),
            3_600,
            Arc::new(PeerCounters::default()),
            true,
        ));
    }
    let ctx = context_with(peers);

    let result = getnetworkinfo(&ctx, &json!(null))
        .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));

    assert_eq!(
        result.get("timeoffset").and_then(JsonValueTrait::as_i64),
        Some(10),
        "inbound peers must not be sampled, however many of them there are"
    );
}

/// Too few samples is not a measurement, and is reported as none.
///
/// `TimeOffsets::Median` returns zero below five offsets: "Only calculate
/// the median if we have 5 or more offsets". Four peers all an hour ahead
/// used to be reported as an hour, which reads as a confident finding about
/// the local clock drawn from four strangers.
#[test]
fn getnetworkinfo_timeoffset_needs_five_samples() {
    let four = context_with(outbound_peers(&[3_600, 3_600, 3_600, 3_600]));
    assert_eq!(
        getnetworkinfo(&four, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"))
            .get("timeoffset")
            .and_then(JsonValueTrait::as_i64),
        Some(0),
        "four samples is below Core's floor, so there is no offset to report"
    );

    // The paired case, so the zero above is the floor and not an inability
    // to report anything at all.
    let five = context_with(outbound_peers(&[3_600, 3_600, 3_600, 3_600, 3_600]));
    assert_eq!(
        getnetworkinfo(&five, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"))
            .get("timeoffset")
            .and_then(JsonValueTrait::as_i64),
        Some(3_600),
        "one more sample crosses the floor and the offset is reported"
    );
}

/// Offsets at the extremes of `i64` are reported, not halved.
///
/// The even-count branch used to average the two middle samples as
/// `lower.saturating_add(upper) / 2`. With both near `i64::MAX` the sum
/// saturates *before* the division, so the answer comes back at roughly
/// half the magnitude -- and these are values a peer can simply put in its
/// version message, so an attacker controlling two outbound peers could
/// pick what the node reported about its own clock.
///
/// There is no averaging any more: Core indexes `sorted[size / 2]` and so
/// does this, which removes the arithmetic rather than making it
/// overflow-safe. This test is what says the class is gone rather than
/// relocated -- an extreme value must arrive at the output unchanged, at
/// both ends of the range.
#[test]
fn extreme_offsets_are_reported_at_their_own_magnitude() {
    for extreme in [i64::MAX, i64::MIN, i64::MAX - 1, i64::MIN + 1] {
        // Six samples, so the even-count path is the one taken, with both
        // middle values at the extreme.
        let ctx = context_with(outbound_peers(&[
            i64::MIN,
            i64::MIN,
            extreme,
            extreme,
            i64::MAX,
            i64::MAX,
        ]));
        let reported = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"))
            .get("timeoffset")
            .and_then(JsonValueTrait::as_i64);

        // Sorted, `[MIN, MIN, extreme, extreme, MAX, MAX]` puts an extreme
        // at index 3 whichever way `extreme` sorts, except when it *is* an
        // endpoint -- in which case the value at index 3 is that endpoint
        // too. Either way the answer is a sample, never a computed number.
        let Some(reported) = reported else {
            panic!("time_offset missing for {extreme}");
        };
        assert!(
            [i64::MIN, i64::MAX, extreme].contains(&reported),
            "{reported} is not one of the offsets any peer reported"
        );
        assert_ne!(
            reported,
            extreme / 2,
            "an extreme offset must not come back halved"
        );
    }
}

/// An even sample count takes the upper middle, as Core does.
///
/// Core indexes `sorted[size / 2]` whatever the parity, and says why it
/// does not interpolate: "approximate median is good enough, keep it
/// simple". Averaging the two middle values answers a number no peer
/// reported and differs from Core on every even count -- here 40 against
/// the 35 an average of the two middle samples would give.
#[test]
fn getnetworkinfo_timeoffset_does_not_interpolate() {
    let ctx = context_with(outbound_peers(&[10, 20, 30, 40, 50, 60]));

    assert_eq!(
        getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"))
            .get("timeoffset")
            .and_then(JsonValueTrait::as_i64),
        Some(40),
        "the upper of the two middle values, not their average"
    );
}

/// A round trip that was never measured is not reported as zero.
///
/// Core omits `pingtime` and `minping` until it has a measurement. These
/// used to be `0.0`, which is not merely wrong but flattering: zero is the
/// best latency a peer could possibly have.
#[test]
fn getpeerinfo_omits_ping_times_it_has_never_measured() {
    let ctx = context_with(vec![peer(
        "127.0.0.1:8333",
        "127.0.0.1:1234",
        0,
        Arc::new(PeerCounters::default()),
    )]);
    let entry = first_peer(&ctx);

    assert!(entry.get("pingtime").is_none(), "{entry:?}");
    assert!(entry.get("minping").is_none(), "{entry:?}");
    assert!(entry.get("pingwait").is_none(), "{entry:?}");
}

/// The reported client version follows the release, not a constant.
///
/// The expected number is derived here from the package version rather than
/// read back from the function under test, which could not disagree with
/// itself.
#[test]
fn getnetworkinfo_version_tracks_the_release() {
    let mut expected = 0_i64;
    for (field, scale) in bitcoin_rs_primitives::PKG_VERSION
        .split('.')
        .zip([10_000_i64, 100, 1])
    {
        let digits: String = field.chars().take_while(char::is_ascii_digit).collect();
        expected += digits.parse::<i64>().unwrap_or(0) * scale;
    }
    assert_ne!(
        expected, 10_000,
        "the fixture must not match the old constant"
    );

    let result = getnetworkinfo(&Arc::new(Context::new()), &json!(null))
        .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));

    assert_eq!(
        result.get("version").and_then(JsonValueTrait::as_i64),
        Some(expected)
    );
}

/// With no peers there is nothing to compare against.
#[test]
fn getnetworkinfo_timeoffset_is_zero_without_peers() {
    let result = getnetworkinfo(&Arc::new(Context::new()), &json!(null))
        .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
    assert_eq!(
        result.get("timeoffset").and_then(JsonValueTrait::as_i64),
        Some(0)
    );
}
