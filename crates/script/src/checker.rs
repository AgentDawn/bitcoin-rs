//! Transaction signature checker: ECDSA, Schnorr, locktime, and sequence verification.
//!
//! Implements the signature-checking layer the script evaluator calls. Every digest
//! is routed through the existing [`SighashCache`] engine; ECDSA through `secp256k1`,
//! Schnorr through `secp256k1`'s Schnorr API. Encoding enforcement (strict DER, low-S,
//! hashtype validity, pubkey encoding, `NULLFAIL`) is driven by [`VerifyFlags`].
//!
//! Behavioral authority: `.references/bitcoin/src/script/interpreter.cpp`
//! (`CheckSignatureEncoding`, `CheckPubKeyEncoding`, `IsLowDERSignature`,
//! `CheckLockTime`, `CheckSequence`).

use bitcoin_rs_primitives::{Amount, Hash256, Sighash, SighashCache, Tx, TxOut};
use secp256k1::{Message, PublicKey, XOnlyPublicKey, ecdsa::Signature as EcdsaSig};

use crate::eval::{OP_CODESEPARATOR, remove_all};
use crate::interpreter::{ScriptErrCode, ScriptError, VerifyFlags};
use crate::signature_cache::SignatureCache;

/// Signature version context: which sighash algorithm and encoding rules apply.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum SigVersion {
    /// Pre-segwit legacy signatures (double-SHA256 legacy sighash).
    Base,
    /// Segwit v0 signatures (BIP143).
    WitnessV0,
    /// Taproot script-path signatures (BIP342).
    Tapscript,
}

/// BIP65 locktime threshold: values below this are block heights, values at or
/// above are Unix timestamps (median-time-past).
const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// BIP112 sequence-type flag: bit 22 of the sequence field.
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// BIP112 sequence lock-time mask: the low 16 bits carry the relative lock value.
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;

/// BIP112 disable flag: bit 31 of the sequence field disables relative locktime.
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// The sequence value that marks an input as finalized (disables locktime checks).
const SEQUENCE_FINAL: u32 = 0xffff_ffff;

/// `SIGHASH_ANYONECANPAY` bit mask for legacy hashtype validation.
const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// Transaction signature checker that holds a transaction, input index, amount,
/// prevouts, and a lazily-initialized sighash cache.
pub(crate) struct TxSignatureChecker<'a> {
    tx: &'a Tx,
    input_index: usize,
    amount: Amount,
    prevouts: &'a [TxOut],
    cache: &'a SighashCache<'a>,
    /// Admission-local positive signature-result cache. `None` outside admission.
    /// Carried for the duration of one verification call only; every encoding,
    /// parsing, sighash, and script check still runs on a hit.
    sig_cache: Option<&'a SignatureCache>,
    /// Raw taproot annex bytes, when present (BIP341). Used by
    /// `check_schnorr_signature` to commit the annex to the sighash.
    annex: Option<Vec<u8>>,
}

impl<'a> TxSignatureChecker<'a> {
    /// Builds a checker for one input of `tx`, with `prevouts` covering every
    /// input so taproot sighashes can commit to all spent outputs.
    ///
    /// `sig_cache` is the admission-local positive result cache for this call
    /// only; pass `None` outside admission. It is never stored beyond the call.
    #[must_use]
    pub(crate) fn new(
        tx: &'a Tx,
        input_index: usize,
        amount: Amount,
        prevouts: &'a [TxOut],
        cache: &'a SighashCache<'a>,
        sig_cache: Option<&'a SignatureCache>,
    ) -> Self {
        Self {
            tx,
            input_index,
            amount,
            prevouts,
            cache,
            sig_cache,
            annex: None,
        }
    }

    /// Sets the taproot annex for BIP341 sighash commitment.
    ///
    /// The driver calls this after stripping an annex from the witness stack
    /// so that subsequent Schnorr signature checks commit to the annex.
    pub(crate) fn set_annex(&mut self, annex: Option<Vec<u8>>) {
        self.annex = annex;
    }

    /// Verifies an ECDSA signature against the appropriate sighash.
    ///
    /// Enforces strict DER (`DERSIG`), low-S (`LOW_S`), hashtype validity and
    /// pubkey encoding (`STRICTENC`), compressed-only pubkeys in segwit
    /// (`WITNESS_PUBKEYTYPE`). `NULLFAIL` is enforced by the callers
    /// (`eval_checksig` / `check_multisig` cleanup), not here.
    ///
    /// Returns `Ok(true)` when the signature is valid, `Ok(false)` when it is
    /// empty (clean failure), and `Err` when encoding or verification fails
    /// under the active flags.
    pub(crate) fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sigversion: SigVersion,
        flags: VerifyFlags,
    ) -> Result<bool, ScriptError> {
        // Core checks both encodings before signature verification. An empty
        // signature is permitted, but does not waive public-key encoding rules.
        check_signature_encoding(sig, flags)?;
        check_pubkey_encoding(pubkey, flags, sigversion)?;

        if sig.is_empty() {
            return Ok(false);
        }

        // Parse the pubkey; an invalid pubkey is a clean false (not an error)
        // matching Core's `CPubKey::IsValid()` returning false.
        let Ok(secp_pubkey) = PublicKey::from_slice(pubkey) else {
            return Ok(false);
        };

        let Some((hashtype_byte, der_sig)) = sig.split_last() else {
            return Ok(false);
        };

        // Parse the DER portion using lax DER parsing (Core's
        // `ecdsa_signature_parse_der_lax`), then normalize to low-S before
        // verification (Core's `secp256k1_ecdsa_signature_normalize`). Strict
        // DER enforcement is handled separately by `check_signature_encoding`
        // under the DERSIG flag; the verification path itself always uses lax
        // parsing so pre-BIP66 signatures still verify. Invalid DER is a
        // clean false.
        let Ok(mut ecdsa_sig) = EcdsaSig::from_der_lax(der_sig) else {
            return Ok(false);
        };
        ecdsa_sig.normalize_s();

        // Core's CTransactionSignatureSerializer::SerializeScriptCode removes
        // OP_CODESEPARATOR (0xab) opcode bytes from the scriptCode before
        // hashing. Segwit v0 uses BIP143 which does not have this step.
        let sighash = match sigversion {
            SigVersion::Base => {
                let raw_hashtype = u32::from(*hashtype_byte);
                let cleaned = remove_all(script_code, &[OP_CODESEPARATOR]).0;
                self.cache
                    .legacy_signature_hash(self.input_index, &cleaned, raw_hashtype)
                    .map_err(|e| ScriptError::Verification(e.to_string()))?
            }
            SigVersion::WitnessV0 => {
                // STRICTENC alone restricts ECDSA hashtypes. BIP143 must
                // classify, but still commit to, the original signature byte.
                self.cache
                    .segwit_v0_signature_hash_raw(
                        self.input_index,
                        script_code,
                        self.amount,
                        u32::from(*hashtype_byte),
                    )
                    .map_err(|e| ScriptError::Verification(e.to_string()))?
            }
            SigVersion::Tapscript => {
                // ECDSA is not used in tapscript; this is a caller error.
                return Err(ScriptError::Verification(
                    "ECDSA signature check requested for tapscript".to_owned(),
                ));
            }
        };

        let message = Message::from_digest(*sighash.as_byte_array());
        if let Some(sig_cache) = self.sig_cache {
            let key = SignatureCache::ecdsa_key(sighash.as_byte_array(), sig, pubkey);
            if sig_cache.contains(&key) {
                return Ok(true);
            }
            // One process-wide context: constructing `verification_only()` per
            // signature rebuilds secp256k1's verification tables on every CHECKSIG.
            let verified = secp256k1::SECP256K1
                .verify_ecdsa(&message, &ecdsa_sig, &secp_pubkey)
                .is_ok();
            if verified {
                sig_cache.insert(key);
            }
            return Ok(verified);
        }
        // One process-wide context: constructing `verification_only()` per
        // signature rebuilds secp256k1's verification tables on every CHECKSIG.
        let verified = secp256k1::SECP256K1
            .verify_ecdsa(&message, &ecdsa_sig, &secp_pubkey)
            .is_ok();

        // NULLFAIL is enforced by the callers (eval_checksig for CHECKSIG,
        // check_multisig cleanup for CHECKMULTISIG), matching Core where
        // CheckECDSASignature returns false without inspecting NULLFAIL.
        // A sig that fails against one pubkey may succeed against another in
        // multisig; an internal NULLFAIL check would fire prematurely.

        Ok(verified)
    }

    /// Verifies a Schnorr signature against the BIP341/BIP342 sighash.
    /// Key-path and tapscript checks share signature-size and hashtype rules.
    ///
    /// `leaf_hash` is absent for key-path spends, or the tapscript leaf hash.
    /// `codesep_pos` is the position of the last `OP_CODESEPARATOR` (or
    /// `CODESEPARATOR_POSITION` when none executed).
    ///
    /// Returns `Ok(true)` when valid, `Ok(false)` when the signature is empty
    /// (tapscript empty-sig convention), and `Err` for size/hashtype/verification
    /// failures.
    pub(crate) fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        leaf_hash: Option<&Hash256>,
        codesep_pos: u32,
    ) -> Result<bool, ScriptError> {
        // Empty signature: a clean false in tapscript (invalid but not an error).
        if sig.is_empty() {
            return Ok(false);
        }

        if sig.len() != 64 && sig.len() != 65 {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSigSize,
            });
        }

        let (schnorr_sig_bytes, hashtype_byte) = if sig.len() == 65 {
            (&sig[..64], sig[64])
        } else {
            (sig, 0x00) // SIGHASH_DEFAULT (64-byte sig)
        };

        if sig.len() == 65 && hashtype_byte == 0x00 {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSigHashtype,
            });
        }

        let sighash_type =
            Sighash::from_consensus_u8(hashtype_byte).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSigHashtype,
            })?;

        if pubkey.len() != 32 {
            return Err(ScriptError::Verification(
                "Schnorr public key must be 32 bytes".to_owned(),
            ));
        }

        let xonly_pubkey = XOnlyPublicKey::from_slice(pubkey)
            .map_err(|e| ScriptError::Verification(format!("invalid Schnorr public key: {e}")))?;

        let schnorr_sig =
            secp256k1::schnorr::Signature::from_slice(schnorr_sig_bytes).map_err(|_| {
                ScriptError::Invalid {
                    code: ScriptErrCode::SchnorrSig,
                }
            })?;

        // Compute the BIP341/BIP342 sighash.
        let leaf_codesep = leaf_hash.map(|lh| (*lh, codesep_pos));
        let sighash = self
            .cache
            .taproot_signature_hash(
                self.input_index,
                self.prevouts,
                self.annex.as_deref(),
                leaf_codesep,
                sighash_type,
            )
            .map_err(|e| ScriptError::Verification(e.to_string()))?;

        let message = Message::from_digest(*sighash.as_byte_array());
        if let Some(sig_cache) = self.sig_cache {
            let key = SignatureCache::schnorr_key(sighash.as_byte_array(), sig, pubkey);
            if sig_cache.contains(&key) {
                return Ok(true);
            }
            return match secp256k1::SECP256K1.verify_schnorr(&schnorr_sig, &message, &xonly_pubkey)
            {
                Ok(()) => {
                    sig_cache.insert(key);
                    Ok(true)
                }
                Err(_) => Err(ScriptError::Invalid {
                    code: ScriptErrCode::SchnorrSig,
                }),
            };
        }
        secp256k1::SECP256K1
            .verify_schnorr(&schnorr_sig, &message, &xonly_pubkey)
            .map(|()| true)
            .map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSig,
            })
    }

    /// BIP65 `OP_CHECKLOCKTIMEVERIFY`: compares `locktime` against the
    /// transaction's nLockTime.
    ///
    /// Returns `true` when the locktime is satisfied: the types match
    /// (both block-height or both timestamp), `locktime <= tx.lock_time`,
    /// and the input's sequence is not `SEQUENCE_FINAL`.
    #[must_use]
    pub(crate) fn check_locktime(&self, locktime: i64) -> bool {
        let tx_locktime = i64::from(self.tx.lock_time.to_consensus());

        let same_type = (tx_locktime < i64::from(LOCKTIME_THRESHOLD))
            == (locktime < i64::from(LOCKTIME_THRESHOLD));
        if !same_type {
            return false;
        }

        if locktime > tx_locktime {
            return false;
        }

        let input = match self.tx.inputs.get(self.input_index) {
            Some(inp) => inp,
            None => return false,
        };
        if input.sequence.to_consensus() == SEQUENCE_FINAL {
            return false;
        }

        true
    }

    /// BIP112 `OP_CHECKSEQUENCEVERIFY`: compares `sequence` against the
    /// input's own nSequence.
    ///
    /// Returns `true` when the relative locktime is satisfied: the transaction
    /// version is >= 2, the input's sequence disable bit is not set, the types
    /// match (both block-height or both time-based), and the masked `sequence`
    /// is <= the masked input sequence.
    #[must_use]
    pub(crate) fn check_sequence(&self, sequence: i64) -> bool {
        let input = match self.tx.inputs.get(self.input_index) {
            Some(inp) => inp,
            None => return false,
        };
        let tx_sequence = i64::from(input.sequence.to_consensus());

        // Transaction version must be >= 2 for BIP68 rules. The version is
        // stored unsigned (the wire value), matching Core's uint32_t.
        if self.tx.version < 2 {
            return false;
        }

        if (input.sequence.to_consensus() & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0 {
            return false;
        }

        let mask = i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK);
        let tx_masked = tx_sequence & mask;
        let seq_masked = sequence & mask;

        let same_type = (tx_masked < i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG))
            == (seq_masked < i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG));
        if !same_type {
            return false;
        }

        if seq_masked > tx_masked {
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Encoding checks (mirrors Core's CheckSignatureEncoding / CheckPubKeyEncoding)
// ---------------------------------------------------------------------------

/// Checks signature encoding per Core's `CheckSignatureEncoding`.
///
/// Empty signatures are allowed (clean false). Under `DERSIG`, `LOW_S`, or
/// `STRICTENC`, the signature must be valid DER. Under `LOW_S`, the S value
/// must be low. Under `STRICTENC`, the hashtype must be defined.
///
/// # Errors
/// Returns the typed DER, high-S, or undefined-hashtype failure selected by `flags`.
pub fn check_signature_encoding(sig: &[u8], flags: VerifyFlags) -> Result<(), ScriptError> {
    // Empty signature is always allowed (not strictly DER, but valid for
    // CHECK(MULTI)SIG dummy / null-fail purposes).
    if sig.is_empty() {
        return Ok(());
    }

    let needs_der = flags.contains(VerifyFlags::DERSIG)
        || flags.contains(VerifyFlags::LOW_S)
        || flags.contains(VerifyFlags::STRICTENC);

    if needs_der && !is_valid_der_encoding(sig) {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::SigDer,
        });
    }

    if flags.contains(VerifyFlags::LOW_S) && !is_low_der_signature(sig) {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::SigHighS,
        });
    }

    if flags.contains(VerifyFlags::STRICTENC) && !is_defined_hashtype(sig) {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::SigHashtype,
        });
    }

    Ok(())
}

/// Checks public key encoding per Core's `CheckPubKeyEncoding`.
fn check_pubkey_encoding(
    pubkey: &[u8],
    flags: VerifyFlags,
    sigversion: SigVersion,
) -> Result<(), ScriptError> {
    if flags.contains(VerifyFlags::STRICTENC) && !is_compressed_or_uncompressed_pubkey(pubkey) {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::PubkeyType,
        });
    }

    // Only compressed keys are accepted in segwit v0.
    if flags.contains(VerifyFlags::WITNESS_PUBKEYTYPE)
        && sigversion == SigVersion::WitnessV0
        && !is_compressed_pubkey(pubkey)
    {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::WitnessPubkeyType,
        });
    }

    Ok(())
}

/// Core's `IsValidSignatureEncoding`: validates the DER structure of a
/// signature including the trailing hashtype byte.
fn is_valid_der_encoding(sig: &[u8]) -> bool {
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }

    if sig[0] != 0x30 {
        return false;
    }

    if usize::from(sig[1]) != sig.len() - 3 {
        return false;
    }

    let len_r = usize::from(sig[3]);
    if 5 + len_r >= sig.len() {
        return false;
    }

    let len_s = usize::from(sig[5 + len_r]);
    if len_r + len_s + 7 != sig.len() {
        return false;
    }

    if sig[2] != 0x02 {
        return false;
    }
    if len_r == 0 {
        return false;
    }
    if sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    }

    if sig[len_r + 4] != 0x02 {
        return false;
    }
    if len_s == 0 {
        return false;
    }
    if sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }

    true
}

/// Core's `IsLowDERSignature`: checks that the S value is at most half the
/// group order.
fn is_low_der_signature(sig: &[u8]) -> bool {
    // secp256k1's group order / 2 in big-endian:
    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    // n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];

    if !is_valid_der_encoding(sig) {
        return false;
    }

    let Some((_, der)) = sig.split_last() else {
        return false;
    };

    let len_r = usize::from(der[3]);
    let s_start = 6 + len_r;
    let s_bytes = &der[s_start..];

    let s_stripped = s_bytes
        .iter()
        .copied()
        .skip_while(|&b| b == 0x00)
        .collect::<Vec<_>>();

    if s_stripped.is_empty() {
        return true;
    }

    if s_stripped.len() > 32 {
        return false;
    }
    if s_stripped.len() < 32 {
        return true;
    }

    s_stripped.as_slice() <= HALF_ORDER.as_slice()
}

/// Core's `IsDefinedHashtypeSignature`: checks that the hashtype byte
/// (ignoring `ANYONECANPAY`) is in the range `SIGHASH_ALL..=SIGHASH_SINGLE`.
fn is_defined_hashtype(sig: &[u8]) -> bool {
    let &hashtype = sig.last().unwrap_or(&0xff);
    let masked = hashtype & (!SIGHASH_ANYONECANPAY);
    (0x01..=0x03).contains(&masked)
}

fn is_compressed_or_uncompressed_pubkey(pubkey: &[u8]) -> bool {
    is_compressed_pubkey(pubkey) || (pubkey.len() == 65 && pubkey[0] == 0x04)
}

fn is_compressed_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03)
}

#[cfg(test)]
mod tests;
