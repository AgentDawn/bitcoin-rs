use alloc::sync::Arc;

use super::*;

const ADDRESS: &str = "1111111111111111111114oLvT2";

#[test]
fn getdescriptorinfo_emits_8_char_bech32_checksum() {
    let ctx = Arc::new(Context::new());
    let result = getdescriptorinfo(&ctx, &json!(["addr(1111111111111111111114oLvT2)"]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
    let Some(checksum) = result.get("checksum").and_then(|v| v.as_str()) else {
        panic!("checksum missing: {result:?}");
    };
    assert_eq!(checksum.len(), 8, "checksum must be 8 chars: {checksum}");
    // All chars should be in the bech32 charset.
    for ch in checksum.chars() {
        assert!(
            BIP380_CHECKSUM_CHARSET.iter().any(|b| char::from(*b) == ch),
            "checksum char {ch} not in bech32 charset"
        );
    }
}

/// The BIP380 vector, so the checksum is not certified by its own output.
///
/// Every other test here compares this implementation against itself. This
/// one compares it against the specification: the descriptor and checksum
/// are the worked example in BIP380, and Core answers the same eight
/// characters for it.
#[test]
fn the_checksum_matches_the_bip380_vector() {
    const DESCRIPTOR: &str = "raw(deadbeef)";
    const CHECKSUM: &str = "89f8spxm";

    let ctx = Arc::new(Context::new());
    let result = getdescriptorinfo(&ctx, &json!([DESCRIPTOR]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
    assert_eq!(
        result.get("checksum").and_then(JsonValueTrait::as_str),
        Some(CHECKSUM)
    );

    // And the same descriptor with its checksum attached is accepted.
    let with_checksum = getdescriptorinfo(&ctx, &json!([format!("{DESCRIPTOR}#{CHECKSUM}")]))
        .unwrap_or_else(|err| panic!("a correct checksum must be accepted: {err}"));
    assert_eq!(
        with_checksum
            .get("checksum")
            .and_then(JsonValueTrait::as_str),
        Some(CHECKSUM)
    );
}

/// A checksum that does not match is refused, not replaced.
///
/// This used to split the text on its last `#`, throw the supplied checksum
/// away, and answer with a freshly computed one -- so a caller who mistyped
/// a descriptor was told it was fine and handed a different descriptor than
/// the one they meant. Catching that typo is the checksum's entire purpose.
///
/// Core's three refusals, from `CheckChecksum` in `script/descriptor.cpp`,
/// each with the message Core gives.
#[test]
fn a_checksum_that_does_not_match_is_refused() {
    let ctx = Arc::new(Context::new());

    for (input, expected) in [
        // Right length, wrong value.
        (format!("addr({ADDRESS})#qqqqqqqq"), "does not match"),
        // Present but not eight characters.
        (
            format!("addr({ADDRESS})#short"),
            "Expected 8 character checksum",
        ),
        // More than one `#` is a malformed descriptor, not an odd checksum.
        (
            format!("addr({ADDRESS})#aaaaaaaa#bbbbbbbb"),
            "Multiple '#' symbols",
        ),
    ] {
        let error = getdescriptorinfo(&ctx, &json!([input.clone()]))
            .err()
            .unwrap_or_else(|| panic!("`{input}` must be refused"));
        assert_eq!(error.code(), RpcError::CORE_NOT_FOUND, "for `{input}`");
        assert!(
            error.to_string().contains(expected),
            "`{input}` must say why: got {error}"
        );
    }
}

/// A descriptor with no checksum is still analysed.
///
/// Core calls `Parse` without `require_checksum` here, so the field is
/// optional -- unlike `deriveaddresses`, where it is not. The two call
/// sites differ on purpose and this pins that they still do.
#[test]
fn getdescriptorinfo_does_not_require_a_checksum() {
    let ctx = Arc::new(Context::new());
    let result = getdescriptorinfo(&ctx, &json!([format!("addr({ADDRESS})")]))
        .unwrap_or_else(|err| panic!("a bare descriptor must be analysed: {err}"));
    let Some(canonical) = result.get("descriptor").and_then(JsonValueTrait::as_str) else {
        panic!("descriptor missing: {result:?}");
    };
    assert!(
        canonical.starts_with(&format!("addr({ADDRESS})#")),
        "the canonical form carries its own checksum: {canonical}"
    );
}

/// The canonical descriptor carries a checksum, as Core's does.
///
/// `DescriptorImpl::ToString` ends in `return AddChecksum(ret)`, so every
/// descriptor Core hands back is ready to be pasted into the next call.
/// This returned the bare form, so a caller copying it out got something
/// `deriveaddresses` then refuses for having no checksum.
///
/// The checksum on the canonical form is of the *canonical* string, and the
/// separate `checksum` field is of the *input*. They differ whenever the
/// parse rewrites anything, which is what the second half checks.
#[test]
fn the_canonical_descriptor_carries_its_own_checksum() {
    let ctx = Arc::new(Context::new());
    let result = getdescriptorinfo(&ctx, &json!([format!("addr({ADDRESS})")]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));

    let Some(canonical) = result.get("descriptor").and_then(JsonValueTrait::as_str) else {
        panic!("descriptor missing: {result:?}");
    };
    let Some((body, sum)) = canonical.rsplit_once('#') else {
        panic!("the canonical form must carry a checksum: {canonical}");
    };
    assert_eq!(body, format!("addr({ADDRESS})"));
    assert_eq!(sum.len(), 8);

    // Round trip: what comes out must be accepted by the call that demands
    // a checksum, which is the whole point of putting one there.
    let derived = deriveaddresses(&ctx, &json!([canonical]))
        .unwrap_or_else(|err| panic!("the canonical form must be usable as-is: {err}"));
    assert_eq!(derived, json!([ADDRESS]));
}

/// A descriptor that names an output cannot produce a spend for it.
#[test]
fn an_address_descriptor_is_not_solvable() {
    let ctx = Arc::new(Context::new());
    let result = getdescriptorinfo(&ctx, &json!([format!("addr({ADDRESS})")]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));

    assert_eq!(
        result.get("issolvable").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        result.get("isrange").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
}

#[test]
fn a_key_descriptor_is_solvable() {
    let ctx = Arc::new(Context::new());
    let descriptor = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
    let result = getdescriptorinfo(&ctx, &json!([descriptor]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));

    assert_eq!(
        result.get("issolvable").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        result
            .get("hasprivatekeys")
            .and_then(JsonValueTrait::as_bool),
        Some(false),
        "a public key is not a private one"
    );
}

#[test]
fn a_private_key_is_reported_and_not_echoed_back() {
    let ctx = Arc::new(Context::new());
    // BIP32 test vector 1, master private key.
    let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    let with_key = format!("wpkh({xprv}/0/0)");
    let result = getdescriptorinfo(&ctx, &json!([with_key]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));

    assert_eq!(
        result
            .get("hasprivatekeys")
            .and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    let Some(canonical) = result.get("descriptor").and_then(JsonValueTrait::as_str) else {
        panic!("descriptor missing: {result:?}");
    };
    assert!(
        !canonical.contains(xprv),
        "the private key must not come back out: {canonical}"
    );
    assert!(
        canonical.contains("xpub"),
        "the canonical form carries the public key: {canonical}"
    );
}

/// Text that is not a descriptor is refused with Core's code.
#[test]
fn a_descriptor_that_does_not_parse_is_refused() {
    let ctx = Arc::new(Context::new());
    let error = getdescriptorinfo(&ctx, &json!(["addr(x)"]))
        .err()
        .unwrap_or_else(|| panic!("addr(x) is not an address"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND, "{error:?}");
}

/// BIP 384 / Core `doc/descriptors.md`: `combo(KEY)` is the top-level
/// collection of `pk`/`pkh` (and, for a compressed key, `wpkh`/`sh(wpkh)`).
///
/// A single-path combo must omit `multipathexpansion`. A private key is
/// reported and replaced by its public form, same as Core's
/// `provider.keys.size() > 0` plus `DescriptorImpl::ToString`.
#[test]
fn combo_is_canonicalized_and_private_keys_are_redacted() {
    let ctx = Arc::new(Context::new());
    let key = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    let result = getdescriptorinfo(&ctx, &json!([format!("combo({key})")]))
        .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
    assert!(
        result
            .get("descriptor")
            .and_then(JsonValueTrait::as_str)
            .is_some_and(|descriptor| descriptor.starts_with(&format!("combo({key})#")))
    );
    assert_eq!(
        result
            .get("hasprivatekeys")
            .and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        result.get("issolvable").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        result.get("isrange").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert!(
        result.get("multipath_expansion").is_none(),
        "single-path combo must omit multipath_expansion: {result:?}"
    );

    // BIP32 test vector 1 master private key, so the redaction is against
    // a published vector rather than this function's own output.
    let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let private = getdescriptorinfo(&ctx, &json!([format!("combo({xprv}/0/0)")]))
        .unwrap_or_else(|err| panic!("combo with an xprv must parse: {err}"));
    assert_eq!(
        private
            .get("hasprivatekeys")
            .and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    let Some(canonical) = private.get("descriptor").and_then(JsonValueTrait::as_str) else {
        panic!("descriptor missing: {private:?}");
    };
    assert!(
        !canonical.contains(xprv),
        "the private key must not come back out: {canonical}"
    );
    assert!(
        canonical.starts_with(&format!("combo({xpub}/0/0)#")),
        "the canonical form is the public combo: {canonical}"
    );
}

/// A supplied checksum is verified, then the body is analysed. `combo` is
/// not miniscript, so the parser must see `combo(KEY)` and not `combo(KEY)#sum`.
#[test]
fn checksummed_combo_is_analysed() {
    let ctx = Arc::new(Context::new());
    let key = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    let bare = format!("combo({key})");
    let checksum =
        descriptor_checksum(&bare).unwrap_or_else(|| panic!("{bare} must have a checksum"));

    let with = getdescriptorinfo(&ctx, &json!([format!("{bare}#{checksum}")]))
        .unwrap_or_else(|err| panic!("checksummed combo must analyse: {err}"));
    let without = getdescriptorinfo(&ctx, &json!([bare]))
        .unwrap_or_else(|err| panic!("bare combo must analyse: {err}"));
    assert_eq!(without, with);
}

/// Core's `getdescriptorinfo` expands a multipath descriptor into one
/// entry per path and returns the first as `descriptor`.
#[test]
fn combo_multipath_is_expanded() {
    let ctx = Arc::new(Context::new());
    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let result = getdescriptorinfo(&ctx, &json!([format!("combo({xpub}/<0;1>/*)")]))
        .unwrap_or_else(|err| panic!("multipath combo must parse: {err}"));
    let Some(canonical) = result.get("descriptor").and_then(JsonValueTrait::as_str) else {
        panic!("descriptor missing: {result:?}");
    };
    assert!(
        canonical.starts_with(&format!("combo({xpub}/0/*)#")),
        "the first expansion is canonical: {canonical}"
    );
    let Some(expansions) = result.get("multipath_expansion").and_then(Value::as_array) else {
        panic!("multipath combo must report expansions: {result:?}");
    };
    assert_eq!(expansions.len(), 2, "{result:?}");
    let Some(first) = expansions.first().and_then(JsonValueTrait::as_str) else {
        panic!("first expansion missing: {result:?}");
    };
    let Some(second) = expansions.get(1).and_then(JsonValueTrait::as_str) else {
        panic!("second expansion missing: {result:?}");
    };
    assert_eq!(first, canonical);
    assert!(
        second.starts_with(&format!("combo({xpub}/1/*)#")),
        "second path in specifier order: {second}"
    );
    assert_eq!(
        result.get("isrange").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
}

/// rust-bitcoin decodes both WIF prefixes; Core refuses a WIF whose
/// version byte is not this chain's. The network lives on the secret in
/// the keymap, not on the public `Single` key.
#[test]
fn combo_rejects_a_wif_from_another_network() {
    let ctx = Arc::new(Context::new());
    let wif = testnet_compressed_wif();
    let error = getdescriptorinfo(&ctx, &json!([format!("combo({wif})")]))
        .err()
        .unwrap_or_else(|| panic!("a testnet WIF must not analyse on mainnet"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert!(
        error.to_string().contains("test network"),
        "the refusal must say which network the key is for: {error}"
    );
}

/// Same network check as derivation: a testnet extended key is not valid
/// descriptor info on a mainnet node.
#[test]
fn combo_rejects_a_testnet_extended_key_on_mainnet() {
    let ctx = Arc::new(Context::new());
    let tpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B";
    let error = getdescriptorinfo(&ctx, &json!([format!("combo({tpub}/0/*)")]))
        .err()
        .unwrap_or_else(|| panic!("a testnet xpub must not analyse on mainnet"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert!(error.to_string().contains("test network"), "got {error}");
}

fn testnet_compressed_wif() -> String {
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
    .unwrap_or_else(|err| panic!("secret 1 is valid: {err}"));
    bitcoin::PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Test,
        inner: secret,
    }
    .to_string()
}
