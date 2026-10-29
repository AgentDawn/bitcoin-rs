use std::sync::LazyLock;

use bitcoin_rs_primitives::Hash256;
use secp256k1::{Parity, Scalar, XOnlyPublicKey};
use sha2::{Digest, Sha256};

/// BIP341 annex tag prefix (Core `ANNEX_TAG`).
pub(crate) const ANNEX_TAG: u8 = 0x50;

/// Control block base size: 1 leaf-version/parity byte + 32-byte x-only internal key.
pub(crate) const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
pub(crate) const TAPROOT_CONTROL_NODE_SIZE: usize = 32;

/// Maximum number of merkle-path nodes in a control block (BIP341).
pub(crate) const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
pub(crate) const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

pub(crate) const TAPROOT_LEAF_MASK: u8 = 0xfe;
pub(crate) const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;

// BIP340 "Tagged Hashes": the doubled tag digest is exactly one SHA256
// block. Keep only these two fixed public prefixes, never request data.
static TAPBRANCH_ENGINE: LazyLock<Sha256> = LazyLock::new(|| tagged_hash_engine(b"TapBranch"));
static TAPTWEAK_ENGINE: LazyLock<Sha256> = LazyLock::new(|| tagged_hash_engine(b"TapTweak"));

/// Initializes SHA256 after `SHA256(tag) || SHA256(tag)`, before any message.
fn tagged_hash_engine(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut engine = Sha256::new();
    Digest::update(&mut engine, tag_hash);
    Digest::update(&mut engine, tag_hash);
    engine
}

/// BIP341 `TapBranch`: raw-byte lexicographic ordering, not display order.
fn compute_tapbranch_hash(prefix: &Sha256, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let mut engine = prefix.clone();
    Digest::update(&mut engine, first);
    Digest::update(&mut engine, second);
    engine.finalize().into()
}

/// Walks the merkle path from `tapleaf_hash` through the control block's
/// nodes, returning the computed merkle root.
///
/// Mirrors Core's `ComputeTaprootMerkleRoot`. The caller must have already
/// validated the control block size.
#[must_use]
pub(crate) fn compute_taproot_merkle_root(control: &[u8], tapleaf_hash: &Hash256) -> Hash256 {
    let mut k = *tapleaf_hash.as_byte_array();
    let path = control.get(TAPROOT_CONTROL_BASE_SIZE..).unwrap_or(&[]);
    let nodes = path.as_chunks::<TAPROOT_CONTROL_NODE_SIZE>().0;
    if nodes.is_empty() {
        return *tapleaf_hash;
    }
    // Resolve lazy initialization once per path, not once per Merkle node.
    let prefix = LazyLock::force(&TAPBRANCH_ENGINE);
    for node in nodes {
        k = compute_tapbranch_hash(prefix, &k, node);
    }
    Hash256::from_le_bytes(&k)
}

/// Verifies the taproot commitment: that the output pubkey (`program`) equals
/// the internal pubkey tweaked by the merkle root.
///
/// Mirrors Core's `VerifyTaprootCommitment` / `XOnlyPubKey::CheckTapTweak`.
/// Returns `false` (not an error) when the internal pubkey is invalid or the
/// tweak check fails, matching Core's behavior.
#[must_use]
pub(crate) fn verify_taproot_commitment(
    control: &[u8],
    program: &[u8],
    tapleaf_hash: &Hash256,
) -> bool {
    let Some(internal_bytes) = control.get(1..TAPROOT_CONTROL_BASE_SIZE) else {
        return false;
    };
    let Ok(internal) = XOnlyPublicKey::from_slice(internal_bytes) else {
        return false;
    };
    let Ok(output) = XOnlyPublicKey::from_slice(program) else {
        return false;
    };
    let merkle_root = compute_taproot_merkle_root(control, tapleaf_hash);
    // TapTweak hash: TaggedHash("TapTweak", internal_pubkey || merkle_root).
    // The internal pubkey is serialized in big-endian (standard x-only form);
    // the merkle root is serialized in little-endian (matching Core's uint256
    // memory layout).
    let mut engine = LazyLock::force(&TAPTWEAK_ENGINE).clone();
    Digest::update(&mut engine, internal.serialize());
    Digest::update(&mut engine, merkle_root.as_byte_array());
    let tweak_bytes = engine.finalize().into();
    let Ok(tweak) = Scalar::from_be_bytes(tweak_bytes) else {
        return false;
    };
    let parity = if control[0] & 1 == 0 {
        Parity::Even
    } else {
        Parity::Odd
    };
    internal.tweak_add_check(secp256k1::SECP256K1, &output, parity, tweak)
}

#[cfg(test)]
mod tests;
