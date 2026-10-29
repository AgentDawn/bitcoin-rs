//! P2P-owned endpoint parsing, formatting, BIP155 conversion, and dialing.
//!
//! Only [`connect_peer_stream`] matches on transport variants. Every other
//! caller treats [`PeerEndpoint`] as opaque identity.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin_rs_primitives::endpoint::{base32_decode, tor_v3_key_from_payload, tor_v3_payload};
use bitcoin_rs_primitives::{EndpointHost, NetworkLabel, PeerEndpoint};
use sha2::{Digest, Sha256};

use crate::sam::SamSession;
use crate::socks::{SocksTarget, socks_connect};

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

/// Identity assigned to a dialed IP endpoint.
#[must_use]
pub fn dialed_ip_identity(addr: SocketAddr) -> PeerEndpoint {
    PeerEndpoint::Ip(addr)
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

/// Routing configuration for dials: which SOCKS proxy carries IP and
/// onion traffic and which SAM session carries I2P traffic.
#[derive(Clone, Debug, Default)]
pub struct DialRoutes {
    /// General SOCKS5 proxy for IP dials (and onion when `onion` unset).
    pub proxy: Option<SocketAddr>,
    /// SOCKS5 proxy for onion dials.
    pub onion: Option<SocketAddr>,
    /// Per-dial credential randomization on the general proxy.
    pub proxy_randomize_credentials: bool,
    /// Established persistent SAM session for I2P dials.
    pub sam_session: Option<Arc<SamSession>>,
    /// Dial restriction; empty allows every network.
    pub onlynet: Vec<NetworkLabel>,
}

impl DialRoutes {
    /// Whether Tor dials can be routed.
    #[must_use]
    pub fn tor_enabled(&self) -> bool {
        self.onion.is_some() || self.proxy.is_some()
    }

    /// Whether I2P dials can be routed.
    #[must_use]
    pub fn i2p_enabled(&self) -> bool {
        self.sam_session.is_some()
    }
}

/// Why this node cannot route a dial to an endpoint. Pure configuration
/// fact: no I/O, derivable before any socket is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDenial {
    /// The endpoint's network is outside the configured `onlynet` set.
    NotInOnlynet,
    /// A Tor endpoint with no onion proxy route configured.
    NoOnionRoute,
    /// An I2P endpoint with no SAM session established.
    NoI2pRoute,
}

/// Static reachability predicate over one node's local routes.
///
/// Selection applies [`RouteTable::denial`] before any worker, thread, or
/// address-book claim is spent; the dial-time gate in [`connect_peer_stream`]
/// stays as defense in depth for fixed peers and races.
#[derive(Clone, Debug, Default)]
pub struct RouteTable {
    /// Dial restriction; empty allows every network.
    pub onlynet: Vec<NetworkLabel>,
    /// SOCKS5 proxy for onion dials (or the general proxy as fallback).
    pub proxy: Option<SocketAddr>,
    /// SOCKS5 proxy dedicated to onion dials.
    pub onion: Option<SocketAddr>,
    /// Established persistent SAM session for I2P dials.
    pub sam_session: Option<Arc<SamSession>>,
}

impl RouteTable {
    /// Build the predicate from the live dial routes. The snapshot is taken
    /// after overlay startup, so an established SAM session is included.
    #[must_use]
    pub fn from_routes(routes: &DialRoutes) -> Self {
        Self {
            onlynet: routes.onlynet.clone(),
            proxy: routes.proxy,
            onion: routes.onion,
            sam_session: routes.sam_session.clone(),
        }
    }

    /// Pure reachability check. `None` means dialable by this node.
    #[must_use]
    pub fn denial(&self, endpoint: &PeerEndpoint) -> Option<RouteDenial> {
        if !self.onlynet.is_empty() && !self.onlynet.contains(&endpoint.net()) {
            return Some(RouteDenial::NotInOnlynet);
        }
        match endpoint {
            PeerEndpoint::Ip(_) => None,
            PeerEndpoint::TorV3 { .. } => {
                if self.onion.is_some() || self.proxy.is_some() {
                    None
                } else {
                    Some(RouteDenial::NoOnionRoute)
                }
            }
            PeerEndpoint::I2p { .. } => {
                if self.sam_session.is_some() {
                    None
                } else {
                    Some(RouteDenial::NoI2pRoute)
                }
            }
        }
    }
}

/// Typed dial outcome at the transport seam.
///
/// `Transport` covers every local failure: dead or refusing proxy, SOCKS
/// authentication/protocol failure, dead SAM bridge, SAM negotiation or
/// naming failure, local policy (`onlynet`), and missing routes. None of
/// these is evidence about the peer and none may move addrman failure
/// accounting. `PeerUnreachable` is reserved for outcomes reported past
/// a working transport (direct TCP refusal, SOCKS peer-unreachable reply
/// codes, SAM `CANT_REACH_PEER`/`TIMEOUT`).
#[derive(Debug)]
pub enum DialFailure {
    /// Local transport failure; never peer evidence.
    Transport(io::Error),
    /// The transport worked and reported the peer unreachable.
    PeerUnreachable(io::Error),
}

impl DialFailure {
    /// Whether this outcome may count as a peer failure in addrman.
    #[must_use]
    pub const fn counts_as_peer_failure(&self) -> bool {
        matches!(self, Self::PeerUnreachable(_))
    }

    /// The underlying I/O error kind.
    #[must_use]
    pub fn kind(&self) -> io::ErrorKind {
        match self {
            Self::Transport(error) | Self::PeerUnreachable(error) => error.kind(),
        }
    }

    /// Flatten back to the I/O error callers report.
    #[must_use]
    pub fn into_io(self) -> io::Error {
        match self {
            Self::Transport(error) | Self::PeerUnreachable(error) => error,
        }
    }
}

impl std::fmt::Display for DialFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "transport failure: {error}"),
            Self::PeerUnreachable(error) => write!(f, "peer unreachable: {error}"),
        }
    }
}

impl std::error::Error for DialFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) | Self::PeerUnreachable(error) => Some(error),
        }
    }
}

impl From<io::Error> for DialFailure {
    fn from(error: io::Error) -> Self {
        // Bare I/O failures inside a transport exchange are local.
        Self::Transport(error)
    }
}

/// The single transport-match dial function.
///
/// `Ip` dials direct TCP exactly as before, or through the configured
/// general SOCKS proxy. `TorV3` dials through SOCKS with the onion name
/// as a domain target. `I2p` dials through the SAM session. Overlay
/// names never reach the system resolver and no failure falls back to
/// direct TCP; a missing route is a typed transport error.
pub fn connect_peer_stream(
    endpoint: PeerEndpoint,
    routes: &DialRoutes,
    timeout: Duration,
) -> Result<TcpStream, DialFailure> {
    if !routes.onlynet.is_empty() && !routes.onlynet.contains(&endpoint.net()) {
        return Err(DialFailure::Transport(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "dial refused: endpoint network is not in onlynet",
        )));
    }
    match endpoint {
        PeerEndpoint::Ip(addr) => match routes.proxy {
            Some(proxy) => socks_connect(
                proxy,
                &SocksTarget::Ip(addr),
                routes.proxy_randomize_credentials,
                timeout,
            ),
            None => match TcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => Ok(stream),
                Err(error) => Err(match error.kind() {
                    io::ErrorKind::ConnectionRefused => DialFailure::PeerUnreachable(error),
                    _ => DialFailure::Transport(error),
                }),
            },
        },
        PeerEndpoint::TorV3 { key, port } => {
            let Some(proxy) = routes.onion.or(routes.proxy) else {
                return Err(DialFailure::Transport(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "overlay transport unavailable: no onion proxy route is configured",
                )));
            };
            // Full `<56-char base32>.onion` name: exactly 62 bytes, the
            // SOCKS domain-length byte 0x3e asserted by transcript tests.
            let host = format!(
                "{}.onion",
                bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&key))
            );
            debug_assert_eq!(host.len(), 62);
            socks_connect(proxy, &SocksTarget::Domain(host, port), true, timeout)
        }
        PeerEndpoint::I2p { hash, port } => {
            let Some(session) = &routes.sam_session else {
                return Err(DialFailure::Transport(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "overlay transport unavailable: no I2P SAM session is configured",
                )));
            };
            session.connect(hash, port)
        }
    }
}

#[cfg(test)]
mod tests;
