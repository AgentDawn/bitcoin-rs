//! BIP332 `staletip` message codec.
//!
//! A `staletip` announces one stale branch: the `fork_point` hash the receiver
//! already knows, up to [`MAX_STALETIP_HEADERS`] [`CompressedHeader`]s that
//! follow it in chain order, and whether the sender will serve the tip block.
//! Payload layout (BIP332, draft):
//!
//! | bytes | field |
//! | --- | --- |
//! | 32 | `fork_point`, consensus little-endian |
//! | 1, 3, 5 or 9 | minimal `CompactSize` header count, `1..=20` |
//! | 48 × count | compressed headers: header minus its previous-block hash |
//! | 1 | `have_block`, `0x00` or `0x01` |
//!
//! This module owns only the byte format. It neither validates proof of work
//! nor consults chain state; reconstructed headers enter the node through the
//! ordinary header-admission path.
//!
//! No BIP324 short message ID is reserved for `staletip`: the command travels
//! as its twelve-byte ASCII name on both transports.

use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Header, varint};

/// P2P command string for stale-tip announcements.
pub const STALETIP_COMMAND: &str = "staletip";

/// Serialized size of one [`CompressedHeader`]: `version`, `merkle_root`,
/// `time`, `bits`, `nonce`.
pub const COMPRESSED_HEADER_LEN: usize = 48;

/// Recommended and enforced maximum header count of one announcement
/// (BIP332 `MAX_STALETIP_HEADERS`).
pub const MAX_STALETIP_HEADERS: usize = 20;
/// Recommended maximum distance in blocks from the receiver's active tip
/// (BIP332 `STALETIP_RECENT_WINDOW`).
pub const STALETIP_RECENT_WINDOW: u32 = 1000;

/// Recommended maximum number of previously known stale tips advertised to a peer
/// (BIP332 `MAX_ADVERTISED_STALETIPS`).
pub const MAX_ADVERTISED_STALETIPS: usize = 10;

/// Largest valid payload: 32-byte fork point, one-byte count, twenty
/// compressed headers, one-byte `have_block`.
pub const MAX_PAYLOAD_LEN: usize =
    FORK_POINT_LEN + 1 + MAX_STALETIP_HEADERS * COMPRESSED_HEADER_LEN + 1;

const FORK_POINT_LEN: usize = 32;

/// A block header without its previous-block hash.
///
/// The previous hash is the hash of the preceding header, or the announcement's
/// `fork_point` for the first one, so it is redundant on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressedHeader {
    /// Block version.
    pub version: i32,
    /// Merkle root of the block's transactions.
    pub merkle_root: Hash256,
    /// Unix epoch seconds.
    pub time: u32,
    /// Compact proof-of-work target.
    pub bits: CompactTarget,
    /// Proof-of-work nonce.
    pub nonce: u32,
}

impl CompressedHeader {
    /// Drops the previous-block hash of `header`.
    #[must_use]
    pub fn from_header(header: &Header) -> Self {
        Self {
            version: header.version,
            merkle_root: header.merkle_root,
            time: header.time,
            bits: header.bits,
            nonce: header.nonce,
        }
    }

    /// Restores the full header that follows the block hashed `prev`.
    #[must_use]
    pub fn with_prev(self, prev: Hash256) -> Header {
        Header {
            version: self.version,
            prev_blockhash: BlockHash::from(prev),
            merkle_root: self.merkle_root,
            time: self.time,
            bits: self.bits,
            nonce: self.nonce,
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(self.merkle_root.as_byte_array());
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&self.bits.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
    }

    fn read(chunk: &[u8; COMPRESSED_HEADER_LEN]) -> Option<Self> {
        let mut cursor = chunk.as_slice();
        Some(Self {
            version: i32::from_le_bytes(take(&mut cursor)?),
            merkle_root: Hash256::from_le_bytes(&take(&mut cursor)?),
            time: u32::from_le_bytes(take(&mut cursor)?),
            bits: CompactTarget::from_consensus(u32::from_le_bytes(take(&mut cursor)?)),
            nonce: u32::from_le_bytes(take(&mut cursor)?),
        })
    }
}

/// Splits `N` bytes off the front of `cursor`.
fn take<const N: usize>(cursor: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = cursor.split_first_chunk::<N>()?;
    *cursor = tail;
    Some(*head)
}

/// One `staletip` announcement.
///
/// Field validity (`1..=MAX_STALETIP_HEADERS` headers) is enforced by
/// [`encode`] and [`decode`], not by construction, so a value is a plain
/// record both for the sender's planner and the receiver's decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleTipAnnouncement {
    /// Hash the first header follows; the receiver must already know it.
    pub fork_point: Hash256,
    /// The stale branch after `fork_point`, in chain order; the last entry is
    /// the stale tip.
    pub headers: Vec<CompressedHeader>,
    /// Whether the sender will serve the stale tip's block.
    pub have_block: bool,
}

impl StaleTipAnnouncement {
    /// Rebuilds the linear headers: header `i` extends the hash of header
    /// `i - 1`, and the first extends `fork_point`.
    ///
    /// POST: the result has `headers.len()` entries in chain order; its last
    /// header's hash is the stale tip's hash. No validation is performed.
    #[must_use]
    pub fn reconstruct(&self) -> Vec<Header> {
        let mut prev = self.fork_point;
        self.headers
            .iter()
            .map(|compressed| {
                let header = compressed.with_prev(prev);
                prev = Hash256::from(header.compute_hash());
                header
            })
            .collect()
    }
}

/// Reasons a `staletip` payload does not encode or decode.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StaleTipError {
    /// The payload ended before the announcement was complete.
    #[error("truncated staletip payload")]
    Truncated,
    /// The header count used a non-minimal `CompactSize` encoding.
    #[error("non-canonical compact size")]
    NonCanonical,
    /// The announcement carries no headers.
    #[error("staletip has no headers")]
    NoHeaders,
    /// The announcement carries more than [`MAX_STALETIP_HEADERS`] headers.
    #[error("staletip header count {0} exceeds bound 20")]
    TooManyHeaders(usize),
    /// `have_block` was neither `0x00` nor `0x01`.
    #[error("invalid have_block byte {0:#04x}")]
    InvalidBool(u8),
    /// Bytes were left after the announcement.
    #[error("trailing {0} bytes after staletip payload")]
    Trailing(usize),
}

impl StaleTipError {
    /// Whether the input exceeded a local resource limit rather than being
    /// malformed.
    ///
    /// BIP332 says a peer SHOULD NOT be punished solely because one
    /// announcement exceeds local policy limits, so callers ignore such a
    /// message; every other variant is a malformed payload.
    #[must_use]
    pub const fn is_policy_limit(&self) -> bool {
        matches!(self, Self::TooManyHeaders(_))
    }
}

/// Encodes `announcement` into its wire payload.
///
/// Rejects an empty or over-limit header list before allocating; on success
/// the payload is at most [`MAX_PAYLOAD_LEN`] bytes.
pub fn encode(announcement: &StaleTipAnnouncement) -> Result<Vec<u8>, StaleTipError> {
    let count = announcement.headers.len();
    if count == 0 {
        return Err(StaleTipError::NoHeaders);
    }
    if count > MAX_STALETIP_HEADERS {
        return Err(StaleTipError::TooManyHeaders(count));
    }
    let count_bytes =
        varint::encode(u64::try_from(count).map_err(|_| StaleTipError::TooManyHeaders(count))?);
    let mut out =
        Vec::with_capacity(FORK_POINT_LEN + count_bytes.len() + count * COMPRESSED_HEADER_LEN + 1);
    out.extend_from_slice(announcement.fork_point.as_byte_array());
    out.extend_from_slice(&count_bytes);
    for header in &announcement.headers {
        header.write(&mut out);
    }
    out.push(u8::from(announcement.have_block));
    Ok(out)
}

/// Decodes a `staletip` payload.
///
/// Strict: requires 1 to [`MAX_STALETIP_HEADERS`] headers, a minimal
/// `CompactSize` count, a `0x00`/`0x01` `have_block`, and exact consumption.
/// The count is checked against the limit before any header storage is
/// reserved, so an attacker-chosen count never sizes an allocation; an
/// over-limit count is reported as soon as it is read, whatever follows it.
pub fn decode(bytes: &[u8]) -> Result<StaleTipAnnouncement, StaleTipError> {
    let (fork_point, rest) = bytes
        .split_first_chunk::<FORK_POINT_LEN>()
        .ok_or(StaleTipError::Truncated)?;
    let (count, count_len) = varint::decode(rest).map_err(|err| match err {
        varint::VarintError::Truncated { .. } => StaleTipError::Truncated,
        varint::VarintError::NonCanonical { .. } => StaleTipError::NonCanonical,
    })?;
    let count = usize::try_from(count).unwrap_or(usize::MAX);
    if count == 0 {
        return Err(StaleTipError::NoHeaders);
    }
    if count > MAX_STALETIP_HEADERS {
        return Err(StaleTipError::TooManyHeaders(count));
    }

    let body = &rest[count_len..];
    let headers_len = count * COMPRESSED_HEADER_LEN;
    let needed = headers_len + 1;
    if body.len() < needed {
        return Err(StaleTipError::Truncated);
    }
    if body.len() > needed {
        return Err(StaleTipError::Trailing(body.len() - needed));
    }

    let (header_bytes, flag) = body.split_at(headers_len);
    let have_block = match flag {
        [0] => false,
        [1] => true,
        [other] => return Err(StaleTipError::InvalidBool(*other)),
        _ => return Err(StaleTipError::Truncated),
    };
    let (chunks, _) = header_bytes.as_chunks::<COMPRESSED_HEADER_LEN>();
    let mut headers = Vec::with_capacity(count);
    for chunk in chunks {
        headers.push(CompressedHeader::read(chunk).ok_or(StaleTipError::Truncated)?);
    }
    Ok(StaleTipAnnouncement {
        fork_point: Hash256::from_le_bytes(fork_point),
        headers,
        have_block,
    })
}

#[cfg(test)]
mod tests;
