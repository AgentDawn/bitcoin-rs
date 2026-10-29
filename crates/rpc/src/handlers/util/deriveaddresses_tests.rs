use alloc::sync::Arc;

use super::*;

const ADDRESS: &str = "1111111111111111111114oLvT2";

/// `descriptor#checksum`, because this call requires one.
///
/// These tests are about derivation, not about the checksum, so they append
/// the computed one rather than hard-coding eight characters per fixture.
/// The checksum's own correctness is pinned against the BIP380 vector in
/// `descriptor_checksum_tests`, and its enforcement by the refusals there.
fn checksummed(descriptor: &str) -> String {
    let Some(checksum) = descriptor_checksum(descriptor) else {
        panic!("the fixture descriptor `{descriptor}` must have a checksum");
    };
    format!("{descriptor}#{checksum}")
}

/// An `addr()` descriptor derives the address it names.
#[test]
fn an_address_descriptor_derives_its_own_address() {
    let ctx = Arc::new(Context::new());
    let result = deriveaddresses(&ctx, &json!([checksummed(&format!("addr({ADDRESS})"))]))
        .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));

    assert_eq!(result, json!([ADDRESS]));
}

/// A range Core would refuse never starts deriving.
///
/// `ParseDescriptorRange` in `rpc/util.cpp` refuses `high >= low + 1000000`
/// and any `high` with its top bit set. Without those, `[0, 4294967295]` is
/// a legal request that derives four billion addresses and holds every one
/// of them before answering -- one JSON object turning into an
/// out-of-memory kill. The refusal has to land before the work starts,
/// which is why it lives in the parser.
///
/// The test asserts it is *fast* as well as refused: a bound checked inside
/// the loop would also return an error, eventually, having done the damage.
#[test]
fn a_range_too_large_to_serve_is_refused_before_any_work() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let descriptor = checksummed(&format!("wpkh({xpub}/0/*)"));

    let started = std::time::Instant::now();
    for (range, expected) in [
        // Top bit set: not a large request but an impossible index.
        (json!([0, 4_294_967_295_u64]), "End of range is too high"),
        (json!([0, 2_147_483_648_u64]), "End of range is too high"),
        // `2^31 - 1` is the largest legal *index*, so it clears the check
        // above and trips the size limit instead -- which is the order Core
        // applies them in, and the reason both messages exist.
        (json!([0, 2_147_483_647_u64]), "Range is too large"),
        (json!([0, 1_000_000]), "Range is too large"),
        (json!(1_000_000), "Range is too large"),
    ] {
        let error = deriveaddresses(&ctx, &json!([descriptor.clone(), range.clone()]))
            .err()
            .unwrap_or_else(|| panic!("{range:?} must be refused"));
        assert_eq!(
            error.code(),
            RpcError::CORE_INVALID_PARAMETER,
            "for {range:?}"
        );
        assert!(
            error.to_string().contains(expected),
            "for {range:?}: {error}"
        );
    }
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the refusals must happen before the derivation, not after it"
    );

    // One below the ceiling is served, so the bound is a ceiling and not a
    // blanket refusal. Kept small: this is about the boundary being in the
    // right place, and 999,999 derivations would prove it slowly.
    let ok = deriveaddresses(&ctx, &json!([descriptor, [10, 12]]))
        .unwrap_or_else(|err| panic!("a modest range must still work: {err}"));
    assert_eq!(ok.as_array().map(sonic_rs::Array::len), Some(3));
}

/// A key from another network does not derive addresses for this one.
///
/// Bitcoin Core never reaches this: `DecodeExtPubKey` resolves the version
/// bytes against the running chain's Base58 prefix, so a `tpub` on mainnet
/// fails to decode and the descriptor never parses. rust-bitcoin decodes
/// both prefixes into one type and keeps the network as a field, so the
/// descriptor parses and the mismatch survives to derivation -- where
/// `address(network)` re-encodes the key with *this* network's prefix and
/// hands back a `bc1...` address for a testnet key.
///
/// That address is well-formed and nobody holds its private key. Someone
/// checking the descriptor by eye sees mainnet addresses and cannot tell.
#[test]
fn a_testnet_key_does_not_derive_mainnet_addresses() {
    // A mainnet context, which is `Context::new()`'s default.
    let ctx = Arc::new(Context::new());
    let tpub = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp";
    let descriptor = checksummed(&format!("wpkh({tpub}/0/*)"));

    let error = deriveaddresses(&ctx, &json!([descriptor, [0, 1]]))
        .err()
        .unwrap_or_else(|| panic!("a testnet key must not derive mainnet addresses"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert!(
        error.to_string().contains("test network"),
        "the refusal must say which network the key is for: {error}"
    );
}

#[test]
fn deriveaddresses_requires_a_checksum() {
    let ctx = Arc::new(Context::new());

    let error = deriveaddresses(&ctx, &json!([format!("addr({ADDRESS})")]))
        .err()
        .unwrap_or_else(|| panic!("a descriptor with no checksum must be refused"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert!(
        error.to_string().contains("Missing checksum"),
        "got {error}"
    );

    // The paired acceptance, so the refusal is the missing checksum and not
    // something else about the descriptor.
    let accepted = deriveaddresses(&ctx, &json!([checksummed(&format!("addr({ADDRESS})"))]))
        .unwrap_or_else(|err| panic!("the same descriptor with a checksum: {err}"));
    assert_eq!(accepted, json!([ADDRESS]));
}

/// A key descriptor derives a real address, where this used to answer `[]`.
///
/// Every descriptor but `addr()` returned an empty array -- not an error,
/// an empty answer, which reads as "this descriptor describes no
/// addresses" rather than "this node did not look".
#[test]
fn a_key_descriptor_derives_an_address() {
    let ctx = Arc::new(Context::new());
    let descriptor =
        checksummed("wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)");
    let result = deriveaddresses(&ctx, &json!([descriptor]))
        .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));

    let Some(addresses) = result.as_array() else {
        panic!("expected an array: {result:?}");
    };
    assert_eq!(addresses.len(), 1);
    let Some(address) = addresses.first().and_then(JsonValueTrait::as_str) else {
        panic!("expected a string: {result:?}");
    };
    assert!(
        address.starts_with("bc1q"),
        "a mainnet v0 segwit address: {address}"
    );
}

/// A ranged descriptor derives one address per index, inclusive at both ends.
#[test]
fn a_ranged_descriptor_derives_one_address_per_index() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let descriptor = checksummed(&format!("wpkh({xpub}/0/*)"));
    let result = deriveaddresses(&ctx, &json!([descriptor, [0, 2]]))
        .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));

    let Some(addresses) = result.as_array() else {
        panic!("expected an array: {result:?}");
    };
    assert_eq!(addresses.len(), 3, "0, 1 and 2: {result:?}");
    let distinct: std::collections::BTreeSet<&str> = addresses
        .iter()
        .filter_map(JsonValueTrait::as_str)
        .collect();
    assert_eq!(
        distinct.len(),
        3,
        "each index is its own address: {result:?}"
    );
}

/// A range is required for a ranged descriptor, and refused for a fixed one.
#[test]
fn the_range_argument_must_match_the_descriptor() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    let missing = deriveaddresses(&ctx, &json!([checksummed(&format!("wpkh({xpub}/0/*)"))]))
        .err()
        .unwrap_or_else(|| panic!("a ranged descriptor needs a range"));
    assert_eq!(missing.code(), RpcError::CORE_INVALID_PARAMETER);

    // Both kinds of fixed descriptor: one miniscript parses, and one it
    // does not model at all. They take separate paths to the same refusal.
    let fixed_key =
        checksummed("wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)");
    for fixed in [fixed_key, checksummed(&format!("addr({ADDRESS})"))] {
        let unwanted = deriveaddresses(&ctx, &json!([fixed.clone(), [0, 2]]))
            .err()
            .unwrap_or_else(|| panic!("a fixed descriptor takes no range: {fixed}"));
        assert_eq!(
            unwanted.code(),
            RpcError::CORE_INVALID_PARAMETER,
            "for {fixed}"
        );
    }
}

/// Bitcoin Core `test/functional/rpc_deriveaddresses.py`: `combo(tprv…/1/1/0)`
/// on regtest yields P2PKH, P2WPKH, and P2SH-P2WPKH. Bare P2PK is skipped.
#[test]
fn combo_derives_core_regtest_addresses() {
    let mut ctx = Context::new();
    ctx.chain.chain_network = bitcoin_rs_primitives::Network::Regtest;
    let ctx = Arc::new(ctx);
    // Bitcoin Core `rpc_deriveaddresses.py`.
    let tprv = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK";
    let result = deriveaddresses(&ctx, &json!([checksummed(&format!("combo({tprv}/1/1/0)"))]))
        .unwrap_or_else(|err| panic!("combo must derive: {err}"));
    assert_eq!(
        result,
        json!([
            "mtfUoUax9L4tzXARpw1oTGxWyoogp52KhJ",
            "bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5",
            "2NDvEwGfpEqJWfybzpKPHF2XH3jwoQV3D7x"
        ])
    );
}

/// BIP 384: an uncompressed key is only `pk` + `pkh`, so derivation is the
/// P2PKH address — the same address `pkh(KEY)` produces.
#[test]
fn combo_uncompressed_derives_only_p2pkh() {
    let ctx = Arc::new(Context::new());
    let key = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    let combo = deriveaddresses(&ctx, &json!([checksummed(&format!("combo({key})"))]))
        .unwrap_or_else(|err| panic!("uncompressed combo must derive: {err}"));
    let pkh = deriveaddresses(&ctx, &json!([checksummed(&format!("pkh({key})"))]))
        .unwrap_or_else(|err| panic!("pkh of the same key: {err}"));
    assert_eq!(combo, pkh);
    assert_eq!(combo.as_array().map(sonic_rs::Array::len), Some(1));
}

/// A compressed combo is the flat BIP 384 set: `pkh`, `wpkh`, `sh(wpkh)`.
#[test]
fn combo_compressed_derives_the_bip384_address_set() {
    let ctx = Arc::new(Context::new());
    let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let combo = deriveaddresses(&ctx, &json!([checksummed(&format!("combo({key})"))]))
        .unwrap_or_else(|err| panic!("compressed combo must derive: {err}"));
    let pkh = deriveaddresses(&ctx, &json!([checksummed(&format!("pkh({key})"))]))
        .unwrap_or_else(|err| panic!("pkh: {err}"));
    let wpkh = deriveaddresses(&ctx, &json!([checksummed(&format!("wpkh({key})"))]))
        .unwrap_or_else(|err| panic!("wpkh: {err}"));
    let sh_wpkh = deriveaddresses(&ctx, &json!([checksummed(&format!("sh(wpkh({key}))"))]))
        .unwrap_or_else(|err| panic!("sh(wpkh): {err}"));
    let expected = json!([
        pkh.as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .unwrap_or_else(|| panic!("pkh address")),
        wpkh.as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .unwrap_or_else(|| panic!("wpkh address")),
        sh_wpkh
            .as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .unwrap_or_else(|| panic!("sh(wpkh) address")),
    ]);
    assert_eq!(combo, expected);
}

/// Ranged combo uses the same range contract as every other descriptor, and
/// each index contributes the BIP 384 address set.
#[test]
fn combo_range_must_match_and_derives_one_set_per_index() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let ranged = checksummed(&format!("combo({xpub}/0/*)"));
    let missing = deriveaddresses(&ctx, &json!([ranged]))
        .err()
        .unwrap_or_else(|| panic!("a ranged combo needs a range"));
    assert_eq!(missing.code(), RpcError::CORE_INVALID_PARAMETER);

    let fixed =
        checksummed("combo(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)");
    let unwanted = deriveaddresses(&ctx, &json!([fixed, [0, 1]]))
        .err()
        .unwrap_or_else(|| panic!("a fixed combo takes no range"));
    assert_eq!(unwanted.code(), RpcError::CORE_INVALID_PARAMETER);

    let derived = deriveaddresses(&ctx, &json!([ranged, [0, 1]]))
        .unwrap_or_else(|err| panic!("ranged combo must derive: {err}"));
    let Some(addresses) = derived.as_array() else {
        panic!("expected a flat array: {derived:?}");
    };
    assert_eq!(addresses.len(), 6, "3 addresses × 2 indices: {derived:?}");
    let distinct: std::collections::BTreeSet<&str> = addresses
        .iter()
        .filter_map(JsonValueTrait::as_str)
        .collect();
    assert_eq!(
        distinct.len(),
        6,
        "each script and index is distinct: {derived:?}"
    );
}

/// A testnet WIF combo is refused on mainnet during derivation too.
#[test]
fn combo_does_not_derive_from_a_testnet_wif_on_mainnet() {
    let ctx = Arc::new(Context::new());
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
    .unwrap_or_else(|err| panic!("secret 1 is valid: {err}"));
    let wif = bitcoin::PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Test,
        inner: secret,
    }
    .to_string();
    let error = deriveaddresses(&ctx, &json!([checksummed(&format!("combo({wif})"))]))
        .err()
        .unwrap_or_else(|| panic!("a testnet WIF must not derive on mainnet"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert!(error.to_string().contains("test network"), "got {error}");
}
