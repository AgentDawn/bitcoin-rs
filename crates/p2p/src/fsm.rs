use crate::feature::{FEATURE_VERSION, FeatureAnnouncement};
use crate::packages::SendPackages;
use crate::peer::{Peer, PeerState};
use crate::wire::{Message, PeerError};

/// Advance a peer by one inbound message.
pub(crate) fn step<S>(peer: &mut Peer<S>, message: &Message) -> Result<(), PeerError> {
    match message {
        Message::Version(version) => receive_version(peer, version.clone()),
        Message::Verack => receive_verack(peer),
        Message::Feature(announcement) => receive_feature(peer, announcement),
        Message::SendPackages(send_packages) => receive_send_packages(peer, *send_packages),
        Message::SendHeaders => {
            ensure_negotiating_or_ready(peer)?;
            peer.capabilities.send_headers = true;
            Ok(())
        }
        Message::SendAddrV2 => {
            ensure_negotiating_or_ready(peer)?;
            peer.capabilities.addr_v2 = true;
            Ok(())
        }
        Message::WtxidRelay => {
            ensure_negotiating_or_ready(peer)?;
            // BIP339 requires negotiation before verack. Once Ready, keep
            // the published per-connection relay preference unchanged.
            if peer.state == PeerState::Ready {
                return Ok(());
            }
            peer.wtxid_relay.mark_peer_supported();
            Ok(())
        }
        Message::SendCmpct(send_cmpct) => {
            ensure_negotiating_or_ready(peer)?;
            peer.compact_blocks.record_remote_preference(send_cmpct);
            Ok(())
        }
        _ => {
            if peer.state == PeerState::Ready {
                Ok(())
            } else {
                Err(PeerError::Misbehavior(
                    "message received before handshake completed",
                ))
            }
        }
    }
}

fn receive_version<S>(
    peer: &mut Peer<S>,
    version: bitcoin::p2p::message_network::VersionMessage,
) -> Result<(), PeerError> {
    if peer.remote_version.is_some() {
        return Err(PeerError::Misbehavior("duplicate version message"));
    }
    match peer.state {
        PeerState::Disconnected | PeerState::VersionExchange | PeerState::Verack => {
            peer.remote_version = Some(version);
            if peer.received_verack {
                peer.state = PeerState::Ready;
            } else {
                peer.state = PeerState::Verack;
            }
            Ok(())
        }
        PeerState::Ready | PeerState::Disconnecting => {
            Err(PeerError::Misbehavior("duplicate version message"))
        }
    }
}

/// Record one BIP434 `feature` announcement.
///
/// PRE: `announcement` decoded within the codec bounds.
/// POST: the peer sent it after its `version`, at protocol version
///   [`FEATURE_VERSION`] or above, and before its `verack`; otherwise the
///   result is a protocol violation and the peer is unchanged. Unknown
///   identifiers (printable or not) and invalid payloads for a recognised
///   identifier are ignored, not punished. The first valid payload of a
///   recognised identifier is retained and later ones are ignored.
/// INVARIANT: `Peer::remote_features` only ever holds
///   [`FeatureAnnouncement::is_supported`] announcements, one per identifier.
fn receive_feature<S>(
    peer: &mut Peer<S>,
    announcement: &FeatureAnnouncement,
) -> Result<(), PeerError> {
    if ensure_version_to_verack_window(peer)? < FEATURE_VERSION {
        return Err(PeerError::Misbehavior(
            "feature received from a peer below the feature protocol version",
        ));
    }
    if announcement.is_supported() {
        peer.remote_features
            .entry(announcement.id.clone())
            .or_insert_with(|| announcement.data.clone());
    }
    Ok(())
}

/// Record one BIP331 `sendpackages`.
///
/// PRE: `send_packages` decoded; any `versions` value is well formed.
/// POST: the peer sent it after its `version` and before its `verack`;
///   otherwise the result is a protocol violation and the peer is unchanged.
///   Only the known `PKG_RELAY_*` bits of the first message are kept: `0`,
///   unknown bits and later messages are ignored, not punished. BIP331 has no
///   protocol-version floor and no BIP434 mapping.
/// INVARIANT: this records the peer's offer only. [`Peer::package_relay_versions`]
///   is the one place that combines it with `verack`, `wtxidrelay`, `fRelay`
///   and our own `sendpackages`.
fn receive_send_packages<S>(
    peer: &mut Peer<S>,
    send_packages: SendPackages,
) -> Result<(), PeerError> {
    ensure_version_to_verack_window(peer)?;
    peer.package_relay.record_remote(send_packages.versions);
    Ok(())
}

/// The peer's protocol version, when it is inside its own pre-`verack`
/// negotiation window: after its `version`, before its `verack`.
///
/// The window is the peer's `verack`, not our [`PeerState`]: the inbound
/// handshake resets the state to `VersionExchange` after accepting `version`.
fn ensure_version_to_verack_window<S>(peer: &Peer<S>) -> Result<u32, PeerError> {
    let Some(remote_version) = peer.remote_version.as_ref() else {
        return Err(PeerError::Misbehavior(
            "negotiation message received before version",
        ));
    };
    if peer.received_verack || !matches!(peer.state, PeerState::VersionExchange | PeerState::Verack)
    {
        return Err(PeerError::Misbehavior(
            "negotiation message received outside the version-to-verack window",
        ));
    }
    Ok(remote_version.version)
}

const fn receive_verack<S>(peer: &mut Peer<S>) -> Result<(), PeerError> {
    if peer.remote_version.is_none() {
        return Err(PeerError::Misbehavior("verack received before version"));
    }
    peer.received_verack = true;
    peer.refresh_ready_state();
    Ok(())
}

const fn ensure_negotiating_or_ready<S>(peer: &Peer<S>) -> Result<(), PeerError> {
    match peer.state {
        PeerState::VersionExchange | PeerState::Verack | PeerState::Ready => Ok(()),
        PeerState::Disconnected | PeerState::Disconnecting => Err(PeerError::Misbehavior(
            "feature negotiation outside handshake",
        )),
    }
}

#[cfg(test)]
mod tests;
