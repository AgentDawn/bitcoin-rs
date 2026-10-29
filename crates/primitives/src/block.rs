//! Native block type and block-level hashing helpers.

use bytes::Bytes;

use crate::{
    BlockHash, Header, Tx, Txid,
    encode::{ConsensusDecode, ConsensusEncode, DecodeError, consensus_bytes, deserialize},
};

/// A Bitcoin block in native owned form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Block {
    /// The block header.
    pub header: Header,
    /// Transactions in consensus order; the first entry is the coinbase.
    pub txs: Vec<Tx>,
}

impl Block {
    /// Computes the block hash from the block header.
    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        self.header.compute_hash()
    }

    /// Computes all transaction ids in block order.
    #[must_use]
    pub fn txids(&self) -> Vec<Txid> {
        self.txs.iter().map(Tx::txid).collect()
    }

    /// Full consensus serialization length, including BIP144 witness sections.
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.consensus_size()
    }

    /// Consensus serialization length without BIP144 witness sections.
    ///
    /// Matches Core's `GetSerializeSize(TX_NO_WITNESS(*this))`: the header,
    /// the transaction-count compact size, and each transaction's base
    /// (txid-layout) size.
    #[must_use]
    pub fn stripped_size(&self) -> usize {
        Header::LEN
            .saturating_add(crate::varint::encoded_len(crate::encode::compact_len(
                self.txs.len(),
            )))
            .saturating_add(self.txs.iter().map(Tx::base_size).sum())
    }

    /// BIP141 block weight: `stripped_size * 3 + total_size` weight units.
    ///
    /// Matches Core's `GetBlockWeight`. Both sizes include the header and the
    /// transaction-count compact size; they are not a sum of per-transaction
    /// weights.
    #[must_use]
    pub fn weight(&self) -> u64 {
        u64::try_from(self.stripped_size())
            .unwrap_or(u64::MAX)
            .saturating_mul(3)
            .saturating_add(u64::try_from(self.total_size()).unwrap_or(u64::MAX))
    }

    /// Returns the total heap bytes allocated for this block's transaction vector,
    /// transactions, inputs, outputs, scripts, and witness stacks, including spare capacity.
    ///
    /// Excludes the inline `Block` struct itself, any separate serialized raw byte buffer,
    /// and allocator metadata or size-class rounding.
    #[must_use]
    pub fn retained_heap_bytes(&self) -> usize {
        let mut total = self
            .txs
            .capacity()
            .saturating_mul(core::mem::size_of::<Tx>());
        for tx in &self.txs {
            total = total.saturating_add(tx.retained_heap_bytes());
        }
        total
    }
}

/// Exact wire/storage block payload: one decoded [`Block`] plus the exact bytes it carries.
///
/// `BlockPayload` owns one decoded [`Block`] plus the exact bytes it carries. Raw ingress
/// claims decode once via [`BlockPayload::from_raw`]; locally assembled blocks encode once
/// via [`BlockPayload::from_local`]; the Core-compatible RPC submit path keeps its
/// ignore-trailing-bytes semantics via [`BlockPayload::from_prefix`]. It introduces no
/// unchecked pair constructor, no generic buffer, no new parser, and no shared-pointer
/// wrapper. Cloning is by value: the `Block` is cloned and the `Bytes` handle is shared
/// by reference count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPayload {
    block: Block,
    bytes: Bytes,
}

impl BlockPayload {
    /// Decodes `raw` once through the existing consensus decode and retains the input bytes.
    ///
    /// Trailing bytes are rejected with [`DecodeError::TrailingBytes`]. No re-encode
    /// comparison is performed; canonicality is inherited from the existing
    /// `ParsedBlock`/`deserialize` contract as it stands today.
    pub fn from_raw(raw: Bytes) -> Result<Self, DecodeError> {
        let block = deserialize::<Block>(&raw)?;
        Ok(Self { block, bytes: raw })
    }

    /// Encodes `block` once through the existing consensus encoder and retains that encoding.
    pub fn from_local(block: Block) -> Self {
        let bytes = Bytes::from(consensus_bytes(&block));
        Self { block, bytes }
    }

    /// Decodes one block from the front of `raw`, retaining only the consumed prefix bytes.
    ///
    /// Runs the one existing decode shared with [`BlockPayload::from_raw`] through a
    /// borrow of `raw`, copies the consumed prefix into an exact-sized buffer, and
    /// returns the consumed length. The ignored `submitblock` suffix allocation is
    /// released rather than retained behind the prefix, and nothing is
    /// re-encoded. This exists only for the Core-compatible RPC `submitblock` boundary,
    /// which ignores
    /// bytes after the block; every other boundary uses [`BlockPayload::from_raw`] or
    /// [`BlockPayload::from_local`].
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Owning raw releases the ignored submitblock suffix after copying the consumed prefix"
    )]
    pub fn from_prefix(raw: Bytes) -> Result<(Self, usize), DecodeError> {
        let mut reader: &[u8] = &raw;
        let block = Block::consensus_decode(&mut reader)?;
        let consumed = raw.len() - reader.len();
        let bytes = Bytes::copy_from_slice(&raw[..consumed]);
        Ok((Self { block, bytes }, consumed))
    }

    /// Borrows the decoded block.
    #[must_use]
    pub fn block(&self) -> &Block {
        &self.block
    }

    /// Borrows the exact retained bytes.
    #[must_use]
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Consumes the payload, returning the decoded block and discarding the retained bytes.
    ///
    /// Exists for the block-template proposal path, which dry-validates the decoded block
    /// and never persists bytes.
    #[must_use]
    pub fn into_block(self) -> Block {
        self.block
    }
}

/// Block payload facts available without materializing a full block body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockBodyMetadata {
    /// Serialized block byte length.
    pub body_size: usize,
    /// Number of transactions encoded in the block.
    pub tx_count: usize,
}

#[cfg(test)]
mod tests;
