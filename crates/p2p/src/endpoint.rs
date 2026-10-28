//! P2P-owned endpoint parsing, formatting, and BIP155 conversion.
//!
//! Every caller treats [`PeerEndpoint`] as opaque identity; the single
//! transport dial lives on [`crate::overlay::OverlayTransport`].

use std::net::SocketAddr;

use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin_rs_primitives::endpoint::{base32_decode, tor_v3_key_from_payload};
use bitcoin_rs_primitives::{EndpointHost, PeerEndpoint};
use sha2::{Digest, Sha256};

/// Socket that actually carried a connection. This is socket accounting
/// (`addrbind`, local/remote socket) only; it is never peer identity and
/// has no conversion to [`PeerEndpoint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransportRemote(SocketAddr);

impl TransportRemote {
    /// Wrap the socket a connection was accepted on / dialed to.
    #[must_use]
    pub const fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }

    /// The underlying socket, for `addrbind` reporting and socket accounting.
    #[must_use]
    pub const fn socket_addr(self) -> SocketAddr {
        self.0
    }
}

impl std::fmt::Display for TransportRemote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identity assigned to a direct-IP inbound accept: the remote socket is
/// the logical peer for IP transport.
#[must_use]
pub fn accepted_ip_identity(remote: SocketAddr) -> PeerEndpoint {
    PeerEndpoint::Ip(remote)
}

/// Result of classifying a textual peer target for dialing and DNS policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassifiedEndpoint {
    /// Valid typed endpoint (direct IP, Tor v3, or I2P).
    Valid(PeerEndpoint),
    /// Reserved overlay target (`.onion` or `.i2p`) that failed validation.
    ///
    /// Malformed overlay targets MUST fail locally and MUST NOT fall through
    /// to system DNS resolution.
    InvalidOverlay,
    /// Non-overlay endpoint candidate that requires standard host:port DNS resolution.
    NonOverlay,
}

/// Whether a hostname candidate refers to a reserved overlay namespace (`.onion` or `.i2p`),
/// independently of case, trailing dots, or payload validity.
///
/// Preserves ordinary single-label LAN names (`onion`, `i2p`) when they do not have
/// a trailing dot, while treating absolute root forms (`onion.`, `i2p.`) as reserved overlay.
#[must_use]
pub(crate) fn is_reserved_overlay_host(host: &str) -> bool {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let had_trailing_dot = unbracketed.ends_with('.');
    let trimmed = unbracketed.trim_end_matches('.');
    let label = match trimmed.rsplit_once('.') {
        Some((_, last_label)) => last_label,
        None if had_trailing_dot => trimmed,
        None => return false,
    };
    label.eq_ignore_ascii_case("onion") || label.eq_ignore_ascii_case("i2p")
}

/// Classify a textual endpoint: direct IP, valid overlay, invalid overlay, or DNS candidate.
///
/// Overlay names (`.onion` and `.i2p`) are validated locally and MUST NEVER fall through
/// to DNS resolution. All names ending in `.i2p` must fail locally if they are not
/// supported canonical `<52>.b32.i2p` targets.
#[must_use]
pub fn classify_endpoint(text: &str) -> ClassifiedEndpoint {
    if let Ok(socket) = text.parse::<SocketAddr>() {
        if socket.port() == 0 {
            return ClassifiedEndpoint::NonOverlay;
        }
        return ClassifiedEndpoint::Valid(PeerEndpoint::Ip(socket));
    }

    let (host, port_text) = text
        .rsplit_once(':')
        .map_or((text, None), |(h, p)| (h, Some(p)));

    let first_host = text.split_once(':').map_or(text, |(h, _)| h);
    let is_overlay = is_reserved_overlay_host(host)
        || is_reserved_overlay_host(first_host)
        || is_reserved_overlay_host(text);

    if !is_overlay {
        return ClassifiedEndpoint::NonOverlay;
    }

    let Some(port_str) = port_text else {
        return ClassifiedEndpoint::InvalidOverlay;
    };
    let Ok(port) = port_str.parse::<u16>() else {
        return ClassifiedEndpoint::InvalidOverlay;
    };

    if let Some(onion) = host.strip_suffix(".onion") {
        if port == 0 {
            return ClassifiedEndpoint::InvalidOverlay;
        }
        if onion.len() != 56 {
            return ClassifiedEndpoint::InvalidOverlay;
        }
        let Some(payload) = base32_decode(onion) else {
            return ClassifiedEndpoint::InvalidOverlay;
        };
        let Some(key) = tor_v3_key_from_payload(&payload) else {
            return ClassifiedEndpoint::InvalidOverlay;
        };
        return ClassifiedEndpoint::Valid(PeerEndpoint::TorV3 { key, port });
    }

    if let Some(b32) = host.strip_suffix(".b32.i2p") {
        if b32.len() != 52 {
            return ClassifiedEndpoint::InvalidOverlay;
        }
        let Some(payload) = base32_decode(b32) else {
            return ClassifiedEndpoint::InvalidOverlay;
        };
        if payload.len() != 32 {
            return ClassifiedEndpoint::InvalidOverlay;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload);
        return ClassifiedEndpoint::Valid(PeerEndpoint::I2p { hash, port });
    }

    ClassifiedEndpoint::InvalidOverlay
}

/// Parse a textual endpoint: `host:port` for IP, `<56>.onion:port` for
/// Tor v3, or `<52>.b32.i2p:port` for I2P. Overlay names are validated
/// locally and never resolved through system DNS.
#[must_use]
pub fn parse_endpoint(text: &str) -> Option<PeerEndpoint> {
    match classify_endpoint(text) {
        ClassifiedEndpoint::Valid(endpoint) => Some(endpoint),
        ClassifiedEndpoint::InvalidOverlay | ClassifiedEndpoint::NonOverlay => None,
    }
}

/// Log/report form of an optional endpoint: the endpoint or `unknown`.
#[must_use]
pub fn display_endpoint(endpoint: Option<PeerEndpoint>) -> String {
    endpoint.map_or_else(|| "unknown".to_owned(), |endpoint| endpoint.to_string())
}

/// Canonical textual form of an endpoint (inverse of [`parse_endpoint`]).
#[must_use]
pub fn format_endpoint(endpoint: PeerEndpoint) -> String {
    endpoint.to_string()
}

/// Convert a BIP155 `addrv2` row to a typed endpoint.
///
/// BIP155 ids 1/2 (IP) and 4/5 (`TorV3`/`I2P`) are accepted; `TorV2`,
/// CJDNS, and unknown networks are rejected.
#[must_use]
pub fn endpoint_from_addrv2(message: &AddrV2Message) -> Option<PeerEndpoint> {
    let port = message.port;
    // I2P SAM accepts port 0 (unspecified/default service port); every
    // other network still requires a nonzero port.
    if port == 0 && !matches!(message.addr, AddrV2::I2p(_)) {
        return None;
    }
    match message.addr {
        AddrV2::Ipv4(ip) => Some(PeerEndpoint::Ip(SocketAddr::new(ip.into(), port))),
        AddrV2::Ipv6(ip) => Some(PeerEndpoint::Ip(SocketAddr::new(ip.into(), port))),
        AddrV2::TorV3(key) => Some(PeerEndpoint::TorV3 { key, port }),
        AddrV2::I2p(hash) => Some(PeerEndpoint::I2p { hash, port }),
        _ => None,
    }
}

/// Convert a typed endpoint to a BIP155 `addrv2` row.
#[must_use]
pub fn endpoint_to_addrv2(
    endpoint: PeerEndpoint,
    time: u32,
    services: ServiceFlags,
) -> AddrV2Message {
    let (addr, port) = match endpoint {
        PeerEndpoint::Ip(SocketAddr::V4(socket)) => (AddrV2::Ipv4(*socket.ip()), socket.port()),
        PeerEndpoint::Ip(SocketAddr::V6(socket)) => (AddrV2::Ipv6(*socket.ip()), socket.port()),
        PeerEndpoint::TorV3 { key, port } => (AddrV2::TorV3(key), port),
        PeerEndpoint::I2p { hash, port } => (AddrV2::I2p(hash), port),
    };
    AddrV2Message {
        time,
        services,
        addr,
        port,
    }
}

/// Whether gossip may carry this endpoint on `addrv2`: IP always; Tor
/// only when a Tor route is configured; I2P only when a SAM bridge is
/// configured (legacy `addr` remains IP-only by construction).
#[must_use]
pub const fn addrv2_gossip_enabled(
    endpoint: PeerEndpoint,
    tor_enabled: bool,
    i2p_enabled: bool,
) -> bool {
    match endpoint {
        PeerEndpoint::Ip(_) => true,
        PeerEndpoint::TorV3 { .. } => tor_enabled,
        PeerEndpoint::I2p { .. } => i2p_enabled,
    }
}

/// Canonical `AddrMan` netgroup for an endpoint host (not the BIP155 tag).
///
/// IP uses the existing prefix/ASMap grouping via
/// [`crate::netgroup::NetGroups`] at call sites; overlay groups are
/// `[4, key[0]|0x0f]` / `[5, hash[0]|0x0f]` with `nBits = 4`, matching the
/// canonical v1 schema that PR #1684 must adopt before its merge.
#[must_use]
pub fn overlay_netgroup(host: EndpointHost) -> Option<Vec<u8>> {
    match host {
        EndpointHost::TorV3 { key } => Some(vec![4, key[0] | 0x0f]),
        EndpointHost::I2p { hash } => Some(vec![5, hash[0] | 0x0f]),
        EndpointHost::Ip(_) => None,
    }
}

/// Eviction netgroup for an unidentified (anonymous) session:
/// `vec![3] ++ SHA256(connection_id.to_le_bytes())[..2]`.
#[must_use]
pub fn anonymous_netgroup(connection_id: crate::ConnectionId) -> Vec<u8> {
    let digest = Sha256::digest(connection_id.get().to_le_bytes());
    vec![3, digest[0], digest[1]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_primitives::endpoint::tor_v3_payload;
    use std::net::{IpAddr, Ipv4Addr};

    fn tor_endpoint() -> PeerEndpoint {
        PeerEndpoint::TorV3 {
            key: [3u8; 32],
            port: 8333,
        }
    }

    #[test]
    fn parse_format_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        for endpoint in [
            PeerEndpoint::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333)),
            PeerEndpoint::Ip("[::1]:8333".parse::<SocketAddr>()?),
            tor_endpoint(),
            PeerEndpoint::I2p {
                hash: [5u8; 32],
                port: 7656,
            },
        ] {
            let text = format_endpoint(endpoint);
            assert_eq!(parse_endpoint(&text), Some(endpoint), "{text}");
        }
        Ok(())
    }

    #[test]
    fn parse_rejects_bad_tor_checksum_and_payload() {
        let mut payload = tor_v3_payload(&[3u8; 32]);
        payload[32] ^= 1;
        let bad = format!(
            "{}.onion:8333",
            bitcoin_rs_primitives::endpoint::base32_encode(&payload)
        );
        assert_eq!(parse_endpoint(&bad), None);
        // Short onion, uppercase, zero port, unknown suffix.
        assert_eq!(parse_endpoint("abc.onion:8333"), None);
        let good = format_endpoint(tor_endpoint());
        assert_eq!(parse_endpoint(&good.replace("8333", "0")), None);
        assert_eq!(parse_endpoint(&good.to_uppercase()), None);
        // I2P payload of wrong decoded length (51 chars is invalid length class).
        assert_eq!(
            parse_endpoint(&format!("{}.b32.i2p:8333", "a".repeat(51))),
            None
        );
        assert_eq!(
            parse_endpoint(&format!("{}.b32.i2p:8333", "a".repeat(53))),
            None
        );
        // Valid I2P: 52 chars of 'a' decode to 32 zero bytes.
        assert_eq!(
            parse_endpoint(&format!("{}.b32.i2p:8333", "a".repeat(52))),
            Some(PeerEndpoint::I2p {
                hash: [0u8; 32],
                port: 8333
            })
        );
    }

    #[test]
    fn classification_matrix_valid_cases() {
        let good_tor = format_endpoint(tor_endpoint());
        let good_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));

        assert!(matches!(
            classify_endpoint(&good_tor),
            ClassifiedEndpoint::Valid(PeerEndpoint::TorV3 { port: 8333, .. })
        ));
        assert_eq!(
            classify_endpoint(&good_i2p),
            ClassifiedEndpoint::Valid(PeerEndpoint::I2p {
                hash: [0u8; 32],
                port: 8333
            })
        );
        assert_eq!(
            classify_endpoint("127.0.0.1:8333"),
            ClassifiedEndpoint::Valid(PeerEndpoint::Ip(SocketAddr::from(([127, 0, 0, 1], 8333))))
        );
    }

    #[test]
    fn classification_matrix_invalid_overlay_cases() {
        let good_tor = format_endpoint(tor_endpoint());
        let good_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));

        let mut bad_payload = tor_v3_payload(&[3u8; 32]);
        bad_payload[32] ^= 1;
        let bad_checksum_onion = format!(
            "{}.onion:8333",
            bitcoin_rs_primitives::endpoint::base32_encode(&bad_payload)
        );

        let wrong_len_i2p_51 = format!("{}.b32.i2p:8333", "a".repeat(51));
        let wrong_len_i2p_53 = format!("{}.b32.i2p:8333", "a".repeat(53));
        let missing_port_onion = format!(
            "{}.onion",
            bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
        );
        let missing_port_i2p = format!("{}.b32.i2p", "a".repeat(52));
        let malformed_port_onion = format!(
            "{}.onion:notaport",
            bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
        );
        let zero_port_onion = good_tor.replace("8333", "0");
        let overflow_port_onion = format!(
            "{}.onion:99999",
            bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
        );

        let uppercase_onion = good_tor.to_uppercase();
        let mixedcase_onion = format!(
            "{}.ONION:8333",
            bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
        );
        let uppercase_i2p = good_i2p.to_uppercase();
        let mixedcase_i2p = format!("{}.B32.I2P:8333", "a".repeat(52));
        let trailing_dot_onion = format!(
            "{}.onion.:8333",
            bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
        );
        let trailing_dot_no_port = format!(
            "{}.onion.",
            bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
        );
        let trailing_dot_i2p = format!("{}.b32.i2p.:8333", "a".repeat(52));
        let trailing_dot_i2p_no_port = format!("{}.b32.i2p.", "a".repeat(52));

        let invalid_targets = [
            bad_checksum_onion.as_str(),
            "abc.onion:8333",
            wrong_len_i2p_51.as_str(),
            wrong_len_i2p_53.as_str(),
            missing_port_onion.as_str(),
            missing_port_i2p.as_str(),
            malformed_port_onion.as_str(),
            zero_port_onion.as_str(),
            overflow_port_onion.as_str(),
            uppercase_onion.as_str(),
            mixedcase_onion.as_str(),
            uppercase_i2p.as_str(),
            mixedcase_i2p.as_str(),
            trailing_dot_onion.as_str(),
            trailing_dot_no_port.as_str(),
            trailing_dot_i2p.as_str(),
            trailing_dot_i2p_no_port.as_str(),
            "foo.i2p:8333",
            "foo.i2p",
            "FOO.I2P:8333",
            "foo.i2p.:8333",
            "foo.i2p.",
            "b32.i2p:8333",
            "b32.i2p",
            "B32.I2P:8333",
            "b32.i2p.:8333",
            "onion.:8333",
            "onion.",
            "ONION.:8333",
            "i2p.:8333",
            "i2p.",
            "I2P.:8333",
        ];

        for rejected in invalid_targets {
            assert_eq!(
                classify_endpoint(rejected),
                ClassifiedEndpoint::InvalidOverlay,
                "invalid overlay target must classify as InvalidOverlay: {rejected}"
            );
            assert_eq!(parse_endpoint(rejected), None);
        }
    }

    #[test]
    fn classification_matrix_ordinary_hostnames() {
        for ordinary in [
            "seed.bitcoin.sipa.be:8333",
            "node.example.com:8333",
            "onion.com:8333",
            "fakeb32.i2p.org:8333",
            "onion:8333",
            "onion",
            "i2p:8333",
            "i2p",
        ] {
            assert_eq!(
                classify_endpoint(ordinary),
                ClassifiedEndpoint::NonOverlay,
                "ordinary hostname must classify as NonOverlay: {ordinary}"
            );
            assert_eq!(parse_endpoint(ordinary), None);
        }
    }

    #[test]
    fn i2p_port_zero_is_valid_but_tor_and_ip_are_not() {
        // I2P SAM accepts port 0 (unspecified/default service port).
        let i2p_zero = format!("{}.b32.i2p:0", "a".repeat(52));
        assert_eq!(
            classify_endpoint(&i2p_zero),
            ClassifiedEndpoint::Valid(PeerEndpoint::I2p {
                hash: [0u8; 32],
                port: 0
            })
        );
        assert_eq!(
            parse_endpoint(&i2p_zero),
            Some(PeerEndpoint::I2p {
                hash: [0u8; 32],
                port: 0
            })
        );

        // Tor v3 and IP still require a nonzero port.
        let tor_zero = format_endpoint(tor_endpoint()).replace("8333", "0");
        assert_eq!(
            classify_endpoint(&tor_zero),
            ClassifiedEndpoint::InvalidOverlay
        );
        assert_eq!(parse_endpoint(&tor_zero), None);
        assert_eq!(parse_endpoint("127.0.0.1:0"), None);
    }

    #[test]
    fn addrv2_accepts_i2p_port_zero_only() {
        let i2p_zero = AddrV2Message {
            time: 1,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::I2p([7u8; 32]),
            port: 0,
        };
        assert_eq!(
            endpoint_from_addrv2(&i2p_zero),
            Some(PeerEndpoint::I2p {
                hash: [7u8; 32],
                port: 0
            })
        );
        // Every other network with port 0 is still rejected.
        for addr in [AddrV2::Ipv4(Ipv4Addr::LOCALHOST), AddrV2::TorV3([3u8; 32])] {
            assert_eq!(
                endpoint_from_addrv2(&AddrV2Message {
                    time: 1,
                    services: ServiceFlags::NETWORK,
                    addr,
                    port: 0,
                }),
                None
            );
        }
    }

    #[test]
    fn addrv2_round_trip_and_rejections() {
        for endpoint in [
            PeerEndpoint::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333)),
            tor_endpoint(),
            PeerEndpoint::I2p {
                hash: [5u8; 32],
                port: 7656,
            },
        ] {
            let row = endpoint_to_addrv2(endpoint, 1, ServiceFlags::NETWORK);
            assert_eq!(endpoint_from_addrv2(&row), Some(endpoint));
        }
        let torv2 = AddrV2Message {
            time: 1,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::TorV2([0u8; 10]),
            port: 8333,
        };
        assert_eq!(endpoint_from_addrv2(&torv2), None);
        let unknown = AddrV2Message {
            time: 1,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Unknown(99, vec![1, 2, 3]),
            port: 8333,
        };
        assert_eq!(endpoint_from_addrv2(&unknown), None);
    }

    #[test]
    fn overlay_netgroup_vectors() {
        assert_eq!(
            overlay_netgroup(EndpointHost::TorV3 { key: [0x21u8; 32] }),
            Some(vec![4, 0x2f])
        );
        assert_eq!(
            overlay_netgroup(EndpointHost::I2p { hash: [0x30u8; 32] }),
            Some(vec![5, 0x3f])
        );
        assert_eq!(
            overlay_netgroup(EndpointHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            None
        );
    }

}
