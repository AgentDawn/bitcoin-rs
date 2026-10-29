//! BIP331 ancestor package relay: message codec and combined package hash.
//!
//! BIP331 adds four messages, all negotiated before `verack` through
//! `sendpackages`:
//!
//! | command        | payload                                                      |
//! |----------------|--------------------------------------------------------------|
//! | `sendpackages` | `versions`: one little-endian `u64` bit field                |
//! | `ancpkginfo`   | `CompactSize` count, then that many 32-byte wtxids, subject last |
//! | `getpkgtxns`   | `CompactSize` count, then that many 32-byte wtxids           |
//! | `pkgtxns`      | `CompactSize` count, then that many witness-serialized `tx`s |
//!
//! Two inventory types ride the existing messages: `getdata(MSG_ANCPKGINFO)`
//! requests an `ancpkginfo`, and `notfound(MSG_PKGTXNS)` carries a
//! [`combined_package_hash`] answering one `getpkgtxns`. `inv(MSG_ANCPKGINFO)`,
//! `inv(MSG_PKGTXNS)` and `getdata(MSG_PKGTXNS)` are never valid.
//!
//! Every decoder consumes its payload exactly and reads `CompactSize` minimally.
//! A list's count is checked against [`MAX_GETPKGTXNS`] from the prefix alone,
//! before the body is inspected or any vector is reserved, so the largest list a
//! peer can make us allocate for is fixed. [`PkgTxns`] additionally bounds the
//! payload by the transport frame ([`crate::wire::MAX_MESSAGE_PAYLOAD`]) and
//! delegates each transaction to the node's single [`Tx`] decoder, so
//! transaction bytes, witness handling, and per-transaction allocation bounds
//! are the ones the `tx` message already has.
//!
//! The wire bound is the protocol maximum, not mempool admission policy: mempool
//! package acceptance is stricter (`MAX_PACKAGE_COUNT`) and is applied by the
//! caller before it reserves any budget for a decoded package.
//!
//! Sources: BIP331 at bitcoin/bips `c0c5aea41e6a334d34db4ca87ae53bbfd7f268d1` and
//! Bitcoin Core's merged `GetPackageHash` at `092c978a42e8f4a02291b994713505ba8aac8b28`.
//! BIP331 publishes no test-vector section.

use bitcoin_rs_primitives::{
    ConsensusDecode, ConsensusEncode, DecodeError, Hash256, Tx, Wtxid, varint,
};
use sha2::{Digest, Sha256};

use crate::wire::MAX_MESSAGE_PAYLOAD;

/// `sendpackages` version bit for batched transaction download
/// (`getpkgtxns`, `pkgtxns`, `MSG_PKGTXNS`).
pub const PKG_RELAY_PKGTXNS: u64 = 1 << 0;

/// `sendpackages` version bit for ancestor package information
/// (`ancpkginfo`, `MSG_ANCPKGINFO`).
pub const PKG_RELAY_ANC: u64 = 1 << 1;

/// Largest list any BIP331 list message carries on the wire.
///
/// BIP331 bounds `getpkgtxns` at 100 wtxids; `ancpkginfo` feeds `getpkgtxns`
/// and `pkgtxns` answers it, so all three share the bound.
pub const MAX_GETPKGTXNS: usize = 100;

/// Inventory type of `getdata` requests for an `ancpkginfo`. Never valid in `inv`.
pub const MSG_ANCPKGINFO: u32 = 0x7;

/// Inventory type of the `notfound` that answers an unservable `getpkgtxns`.
/// Never valid in `inv` or `getdata`.
pub const MSG_PKGTXNS: u32 = 0x6;

const WTXID_LEN: usize = 32;

/// Errors from encoding or decoding a BIP331 message payload.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackageError {
    /// The payload ended before the message was complete.
    #[error("truncated package payload")]
    Truncated,
    /// A `CompactSize` used a wider encoding than its value needs.
    #[error("non-canonical compact size")]
    NonCanonical,
    /// A list message carried no entries.
    #[error("package list is empty")]
    Empty,
    /// A list message declared or held more entries than the wire bound.
    #[error("package list count {count} exceeds bound {max}")]
    TooMany {
        /// The declared (decode) or supplied (encode) entry count.
        count: u64,
        /// The bound, [`MAX_GETPKGTXNS`].
        max: usize,
    },
    /// An `ancpkginfo` repeated a wtxid, which BIP331 defines as malformed.
    #[error("ancpkginfo repeats a wtxid")]
    DuplicateWtxid,
    /// Bytes remained after the message was complete.
    #[error("trailing {0} bytes after package payload")]
    Trailing(usize),
    /// The payload exceeds the transport frame bound.
    #[error("package payload length {0} exceeds the frame bound")]
    PayloadTooLarge(usize),
    /// A transaction inside `pkgtxns` failed the node's transaction decoder.
    #[error("package transaction: {0}")]
    Transaction(#[from] DecodeError),
}

/// `sendpackages`: the package relay versions the sender supports.
///
/// The codec carries the bit field verbatim, including `0` and bits this node
/// does not know; negotiation ignores those, the codec does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendPackages {
    /// Bit field of supported versions; see [`PKG_RELAY_PKGTXNS`] and [`PKG_RELAY_ANC`].
    pub versions: u64,
}

impl SendPackages {
    /// The payload: `versions` as a little-endian `u64`.
    #[must_use]
    pub const fn encode(self) -> [u8; 8] {
        self.versions.to_le_bytes()
    }

    /// Decodes a payload of exactly eight bytes.
    pub fn decode(payload: &[u8]) -> Result<Self, PackageError> {
        let (versions, rest) = payload
            .split_first_chunk::<8>()
            .ok_or(PackageError::Truncated)?;
        if !rest.is_empty() {
            return Err(PackageError::Trailing(rest.len()));
        }
        Ok(Self {
            versions: u64::from_le_bytes(*versions),
        })
    }
}

/// `ancpkginfo`: the unconfirmed ancestor package of one transaction.
///
/// The last wtxid is the subject the message answers; the others are its
/// ancestors in no enforced order. An empty list has no subject and is malformed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AncPkgInfo {
    /// The package's wtxids, subject last, without repeats.
    pub wtxids: Vec<Wtxid>,
}

impl AncPkgInfo {
    /// The wtxid this message describes: the last entry.
    #[must_use]
    pub fn subject(&self) -> Option<Wtxid> {
        self.wtxids.last().copied()
    }

    /// Encodes the list; rejects an empty, oversized, or repeating list.
    pub fn encode(&self) -> Result<Vec<u8>, PackageError> {
        check_count(len_u64(self.wtxids.len()))?;
        if has_duplicates(&self.wtxids) {
            return Err(PackageError::DuplicateWtxid);
        }
        Ok(write_wtxids(&self.wtxids))
    }

    /// Decodes a list, rejecting an empty, oversized, repeating, truncated, or
    /// over-long payload.
    pub fn decode(payload: &[u8]) -> Result<Self, PackageError> {
        let wtxids = read_wtxids(payload)?;
        if has_duplicates(&wtxids) {
            return Err(PackageError::DuplicateWtxid);
        }
        Ok(Self { wtxids })
    }
}

/// `getpkgtxns`: a request for all of the listed transactions or none.
///
/// The sequence is the request identity: a reply must list the same wtxids in
/// the same order, and the `notfound` answer names [`combined_package_hash`] of
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetPkgTxns {
    /// The requested wtxids, in request order.
    pub wtxids: Vec<Wtxid>,
}

impl GetPkgTxns {
    /// Encodes the list; rejects an empty or oversized list.
    pub fn encode(&self) -> Result<Vec<u8>, PackageError> {
        check_count(len_u64(self.wtxids.len()))?;
        Ok(write_wtxids(&self.wtxids))
    }

    /// Decodes a list, rejecting an empty, oversized, truncated, or over-long payload.
    pub fn decode(payload: &[u8]) -> Result<Self, PackageError> {
        Ok(Self {
            wtxids: read_wtxids(payload)?,
        })
    }
}

/// `pkgtxns`: the transactions of one `getpkgtxns`, in request order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PkgTxns {
    /// The transactions, in the order the request listed their wtxids.
    pub txs: Vec<Tx>,
}

impl PkgTxns {
    /// Encodes the list with each transaction in the `tx` message's serialization.
    ///
    /// Rejects an empty or oversized list and a payload above the frame bound,
    /// computed before anything is serialized.
    pub fn encode(&self) -> Result<Vec<u8>, PackageError> {
        let count = len_u64(self.txs.len());
        check_count(count)?;
        let mut total = varint::encoded_len(count);
        for tx in &self.txs {
            total = total.saturating_add(tx.consensus_size());
            if total > MAX_MESSAGE_PAYLOAD {
                return Err(PackageError::PayloadTooLarge(total));
            }
        }
        let mut payload = Vec::with_capacity(total);
        payload.extend_from_slice(&varint::encode(count));
        for tx in &self.txs {
            tx.consensus_encode(&mut payload);
        }
        Ok(payload)
    }

    /// Decodes a list of transactions, rejecting an empty, oversized, or
    /// over-long payload and any transaction the `tx` decoder rejects.
    pub fn decode(payload: &[u8]) -> Result<Self, PackageError> {
        if payload.len() > MAX_MESSAGE_PAYLOAD {
            return Err(PackageError::PayloadTooLarge(payload.len()));
        }
        let (count, mut reader) = read_count(payload)?;
        let mut txs = Vec::with_capacity(count);
        for _ in 0..count {
            txs.push(Tx::consensus_decode(&mut reader)?);
        }
        if !reader.is_empty() {
            return Err(PackageError::Trailing(reader.len()));
        }
        Ok(Self { txs })
    }
}

/// The canonical identifier of a package: a single SHA-256 over its wtxids.
///
/// The wtxids are sorted by their conventional displayed hex, which is
/// lexicographic order over the bytes read in reverse, then each wtxid's 32
/// internal bytes are concatenated without a count prefix and hashed once.
/// The result is independent of input order and keeps repeated wtxids. This is
/// Bitcoin Core's `GetPackageHash`; neither `Wtxid`'s derived `Ord` (internal
/// byte order), a tagged hash, nor a count prefix produces it.
#[must_use]
pub fn combined_package_hash(wtxids: &[Wtxid]) -> [u8; 32] {
    let mut ordered: Vec<&[u8; WTXID_LEN]> = wtxids.iter().map(Wtxid::as_bytes).collect();
    ordered.sort_unstable_by(|a, b| a.iter().rev().cmp(b.iter().rev()));
    let mut engine = Sha256::new();
    for wtxid in ordered {
        engine.update(wtxid);
    }
    engine.finalize().into()
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Validates a list count: `1..=MAX_GETPKGTXNS`.
fn check_count(count: u64) -> Result<usize, PackageError> {
    if count == 0 {
        return Err(PackageError::Empty);
    }
    match usize::try_from(count) {
        Ok(count) if count <= MAX_GETPKGTXNS => Ok(count),
        _ => Err(PackageError::TooMany {
            count,
            max: MAX_GETPKGTXNS,
        }),
    }
}

/// Reads and bounds a list message's leading `CompactSize` count, returning the
/// count and the bytes after the prefix.
///
/// The one reader for every BIP331 list payload: minimal encoding and a count
/// from `1` through [`MAX_GETPKGTXNS`] are decided here from the prefix alone.
/// Callers that inspect a `pkgtxns` frame before decoding it (the ingress
/// charge plan) use it so the prefix rules are not restated.
pub fn read_count(payload: &[u8]) -> Result<(usize, &[u8]), PackageError> {
    let (count, consumed) = varint::decode(payload).map_err(|err| match err {
        varint::VarintError::Truncated { .. } => PackageError::Truncated,
        varint::VarintError::NonCanonical { .. } => PackageError::NonCanonical,
    })?;
    Ok((check_count(count)?, &payload[consumed..]))
}

/// Decodes a count-prefixed wtxid list that fills the payload exactly.
fn read_wtxids(payload: &[u8]) -> Result<Vec<Wtxid>, PackageError> {
    let (count, body) = read_count(payload)?;
    let needed = count * WTXID_LEN;
    if body.len() < needed {
        return Err(PackageError::Truncated);
    }
    if body.len() > needed {
        return Err(PackageError::Trailing(body.len() - needed));
    }
    let (wtxids, _) = body.as_chunks::<WTXID_LEN>();
    Ok(wtxids
        .iter()
        .map(|bytes| Wtxid(Hash256::from_le_bytes(bytes)))
        .collect())
}

/// Serializes a wtxid list already known to satisfy [`check_count`].
fn write_wtxids(wtxids: &[Wtxid]) -> Vec<u8> {
    let count = len_u64(wtxids.len());
    let mut payload = Vec::with_capacity(varint::encoded_len(count) + wtxids.len() * WTXID_LEN);
    payload.extend_from_slice(&varint::encode(count));
    for wtxid in wtxids {
        payload.extend_from_slice(wtxid.as_bytes());
    }
    payload
}

/// Whether any wtxid appears twice; allocation-free over a list of at most
/// [`MAX_GETPKGTXNS`] entries.
fn has_duplicates(wtxids: &[Wtxid]) -> bool {
    wtxids
        .iter()
        .enumerate()
        .any(|(index, wtxid)| wtxids[index + 1..].contains(wtxid))
}

#[cfg(test)]
mod tests;
