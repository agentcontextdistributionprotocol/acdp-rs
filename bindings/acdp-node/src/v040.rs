//! Pure-Rust core of the ACDP 0.4 binding surface — transparency-log
//! **witness cosignatures** (RFC-ACDP-0015).
//!
//! This module is FFI-framework-free and byte-identical between the
//! Python (PyO3) and Node (NAPI-rs) bindings: all inputs are parsed
//! `serde_json::Value`s / plain strings, all outputs are JSON strings.
//! The thin per-framework wrappers in `verifier.rs` only parse argument
//! strings and map raised errors — keeping the protocol-critical logic
//! in exactly one shape per binding, wrapping the same `acdp` core types.
//!
//! Three roles are exposed (JSON in, JSON out):
//!
//! * **Witness mint** — [`build_witness_cosignature_core`] mints a
//!   signed `log_cosignature` over an observed checkpoint with the
//!   witness's OWN key (the `WitnessSigner::new` + `mint` path). This is
//!   the MINT surface a host-language witness service uses; it is the
//!   *raw* mint (RFC-ACDP-0015 §5) — the §7 obligation (checkpoint
//!   signature + consistency) is the host's / registry's job.
//! * **Consumer verify** — [`verify_witness_cosignature_verdict`] runs
//!   the RFC-ACDP-0015 §8 steps 1–5 for one cosignature against a
//!   checkpoint the consumer has itself verified, offline (the witness
//!   DID document is supplied by the caller — the same
//!   resolution-in-the-host stance as the 0.3 verdict surface).
//! * **Consumer quorum** — [`evaluate_witness_quorum_report`] computes
//!   the §8 N-witnessed count over a set of cosignatures under a
//!   [`WitnessPolicyParsed`].
//!
//! ## Verdict convention (unchanged from 0.3)
//!
//! The verdict/report functions never fail for a *verification* reason —
//! they return a JSON string. A cosignature that fails a §8 step is a
//! result to report (`{"valid": false, "code":
//! "invalid_witness_cosignature", "error": ...}`), never a host
//! programming error. Only malformed host input is raised by the
//! wrappers.

use std::collections::BTreeSet;

use acdp::did::DidDocument;
use acdp::error::AcdpError;
use acdp::types::cosignature::{LogCosignature, WitnessSigner, WitnessedCheckpoint};
use acdp::types::log::{LogCheckpoint, LOG_CHECKPOINT_VERSION};
use acdp::types::Signature;
use chrono::{DateTime, Duration, Utc};

/// RFC-ACDP-0015 §8 step 5 RECOMMENDED forward clock-skew allowance
/// (the RFC-ACDP-0011 §7 step 6 allowance).
pub(crate) const DEFAULT_WITNESS_MAX_CLOCK_SKEW_SECS: i64 = 120;
/// RFC-ACDP-0015 §8.1 RECOMMENDED maximum cosignature age for
/// current-ness-sensitive decisions.
pub(crate) const DEFAULT_WITNESS_MAX_AGE_SECS: i64 = 300;

/// The wire-code taxonomy string for an [`AcdpError`], used in failure
/// verdicts so hosts can branch without parsing messages. A witness
/// cosignature failure is `invalid_witness_cosignature` (RFC-ACDP-0015
/// §10) — deliberately distinct from `invalid_log_proof`: it indicts a
/// witness's attestation, never the registry's log.
fn error_code(e: &AcdpError) -> &'static str {
    match e {
        AcdpError::InvalidWitnessCosignature(_) => "invalid_witness_cosignature",
        AcdpError::InvalidLogProof(_) => "invalid_log_proof",
        AcdpError::InvalidReceipt(_) => "invalid_receipt",
        AcdpError::InvalidSignature(_) => "invalid_signature",
        AcdpError::KeyNotAuthorized(_) => "key_not_authorized",
        AcdpError::KeyRevoked(_) => "key_not_authorized",
        // Not a wire code: discovery could not establish revocation status.
        AcdpError::RevocationUnknown { .. } => "revocation_unknown",
        AcdpError::KeyResolution(_) => "key_resolution",
        AcdpError::UnsupportedAlgorithm(_) => "unsupported_algorithm",
        AcdpError::SchemaViolation(_) => "schema_violation",
        _ => "acdp_error",
    }
}

fn failure(e: &AcdpError) -> serde_json::Value {
    serde_json::json!({
        "valid": false,
        "code": error_code(e),
        "error": e.to_string(),
    })
}

// ── Witness mint (RFC-ACDP-0015 §5) ──────────────────────────────────────────

/// Mint a signed `log_cosignature` over an observed checkpoint's
/// identity-bearing subset (`{log_id, tree_size, root_hash,
/// timestamp}`), keyed by the witness's OWN Ed25519 key derived from
/// `seed`. Wraps `WitnessSigner::new` + `mint` (RFC-ACDP-0015 §5).
///
/// The witness signing-key DID URL is derived as
/// `"<witness_id>#witness-key-1"` — the RFC-ACDP-0015 §5 / §9 witness
/// key convention (and the wit-001 golden `signature.key_id`). The
/// resulting `signature` uses the RFC-ACDP-0010 §5 construction verbatim
/// (the witness signs the ASCII bytes of the `"sha256:<hex>"`
/// cosignature-hash string), so a fixed `seed` + input reproduces the
/// signature byte-for-byte across bindings.
///
/// This is the RAW mint: it performs no §7 witness obligation (the
/// checkpoint's own signature / consistency against a retained head).
/// Production witnesses run those checks first (the Rust
/// `client::mint_cosignature_checked`, which needs HTTP, lives host-side
/// / native).
pub(crate) fn build_witness_cosignature_core(
    witnessed_checkpoint: &serde_json::Value,
    witness_id: &str,
    seed: &[u8; 32],
    witnessed_at: DateTime<Utc>,
) -> Result<String, AcdpError> {
    // Parse the identity-bearing subset the witness observed (closed
    // schema: an unknown member is rejected here).
    let wc: WitnessedCheckpoint =
        serde_json::from_value(witnessed_checkpoint.clone()).map_err(|e| {
            AcdpError::SchemaViolation(format!(
                "invalid witnessed_checkpoint (expected {{log_id, tree_size, root_hash, \
                 timestamp}}): {e}"
            ))
        })?;

    // Reconstitute the minimal LogCheckpoint the mint copies from — only
    // {log_id, tree_size, root_hash, timestamp} are read into the
    // cosignature, so the placeholder version/signature never surface.
    let checkpoint = LogCheckpoint {
        checkpoint_version: LOG_CHECKPOINT_VERSION.to_string(),
        log_id: wc.log_id,
        tree_size: wc.tree_size,
        root_hash: wc.root_hash,
        timestamp: wc.timestamp,
        signature: Signature {
            algorithm: "ed25519".to_string(),
            key_id: format!("{witness_id}#witness-key-1"),
            value: String::new(),
        },
    };

    let signer = WitnessSigner::new(
        acdp::crypto::SigningKey::from_bytes(seed),
        witness_id,
        format!("{witness_id}#witness-key-1"),
    )?;
    let cosig = signer.mint(&checkpoint, witnessed_at)?;
    serde_json::to_string(&cosig).map_err(AcdpError::from)
}

// ── Consumer verify (RFC-ACDP-0015 §8) ───────────────────────────────────────

/// The RFC-ACDP-0015 §8 procedure for one cosignature against an
/// already-verified checkpoint — the pure mirror of the Rust
/// `client::verify_witness_cosignature_value` (the witness DID document
/// is supplied by the caller; DID resolution stays in the host):
///
/// 1. schema-closed parse + §4/§5 invariants + step 3 structural witness
///    binding (`signature.key_id` DID = `witness_id`);
/// 2. §8 step 4 checkpoint binding (`{log_id, tree_size, root_hash}`);
/// 3. §8 step 3 witness binding (DID document `id` = `witness_id`);
/// 4. §8 step 2 signature verify over the RAW wire preimage against the
///    key resolved from the witness DID document (RFC-ACDP-0015 §9:
///    looked up in `verificationMethod`, retired keys stay verifiable);
/// 5. §8 step 5 `witnessed_at` well-formedness + forward skew.
///
/// Every failure maps to [`AcdpError::InvalidWitnessCosignature`], matching
/// the core.
fn verify_witness_cosignature(
    cosig_value: &serde_json::Value,
    witness_did_doc: &serde_json::Value,
    expected: &LogCheckpoint,
    now: DateTime<Utc>,
    max_clock_skew_secs: i64,
) -> Result<LogCosignature, AcdpError> {
    // §8 step 1: closed parse + §4/§5 invariants + step 3 structural
    // witness binding (key_id DID == witness_id).
    let cosig = LogCosignature::from_value(cosig_value)?;

    // §8 step 4: checkpoint binding against the independently-held,
    // independently-verified checkpoint.
    cosig.cross_check_against_checkpoint(expected)?;

    // §8 step 3: the resolving witness DID document's id MUST equal
    // witness_id.
    let doc: DidDocument = serde_json::from_value(witness_did_doc.clone()).map_err(|e| {
        AcdpError::InvalidWitnessCosignature(format!("witness DID document does not parse: {e}"))
    })?;
    if doc.id != cosig.witness_id {
        return Err(AcdpError::InvalidWitnessCosignature(format!(
            "witness DID document id '{}' ≠ cosignature witness_id '{}' \
             (RFC-ACDP-0015 §8 step 3)",
            doc.id, cosig.witness_id
        )));
    }

    // §8 step 2: resolve signature.key_id in the witness DID document and
    // verify over the RAW wire preimage (re-serializing the parsed struct
    // could normalize byte details and falsely reject an honest
    // cosignature — the mistake wit-004 exists to catch).
    let key_id = &cosig.signature.key_id;
    let (_did_part, fragment) = key_id.split_once('#').ok_or_else(|| {
        AcdpError::InvalidWitnessCosignature(format!(
            "witness cosignature signature.key_id '{key_id}' has no fragment"
        ))
    })?;
    let method = doc.find_by_fragment(fragment).ok_or_else(|| {
        AcdpError::InvalidWitnessCosignature(format!(
            "witness DID document has no verification method '#{fragment}' — witness keys \
             (including retired ones) must remain in verificationMethod (RFC-ACDP-0015 §9)"
        ))
    })?;
    let raw_hash = LogCosignature::preimage_hash_of_value(cosig_value)?;
    match cosig.signature.algorithm.as_str() {
        "ed25519" => {
            let key = method.ed25519_public_key_bytes().map_err(|e| {
                AcdpError::InvalidWitnessCosignature(format!("witness key extraction: {e}"))
            })?;
            cosig.verify_signature_against_hash(&raw_hash, Some(&key), None)?;
        }
        "ecdsa-p256" => {
            let key = method.ecdsa_p256_public_key_sec1().map_err(|e| {
                AcdpError::InvalidWitnessCosignature(format!("witness key extraction: {e}"))
            })?;
            cosig.verify_signature_against_hash(&raw_hash, None, Some(&key))?;
        }
        other => {
            return Err(AcdpError::InvalidWitnessCosignature(format!(
                "witness cosignature signature algorithm '{other}' is not supported"
            )));
        }
    }

    // §8 step 5: witnessed_at well-formedness + forward-skew.
    cosig.check_witnessed_at_skew(now, Duration::seconds(max_clock_skew_secs))?;
    Ok(cosig)
}

/// Consumer §8 verdict for one cosignature (steps 1–5), plus the §8.1
/// freshness split (`stale` / `age_secs`). Staleness is policy, never a
/// verification failure — an old-but-honest cosignature is
/// `valid: true, stale: true` (for anti-backdating it never expires).
pub(crate) fn verify_witness_cosignature_verdict(
    cosig_value: &serde_json::Value,
    witness_did_doc: &serde_json::Value,
    expected_checkpoint: &serde_json::Value,
    now: DateTime<Utc>,
    max_clock_skew_secs: i64,
    max_age_secs: i64,
) -> String {
    let run = || -> Result<(LogCosignature, i64), AcdpError> {
        // The checkpoint MUST parse (the caller passes the one it has
        // itself verified); a malformed one is an InvalidLogProof verdict.
        let checkpoint = LogCheckpoint::from_value(expected_checkpoint)?;
        let cosig = verify_witness_cosignature(
            cosig_value,
            witness_did_doc,
            &checkpoint,
            now,
            max_clock_skew_secs,
        )?;
        let age = cosig.age_at(now).num_seconds();
        Ok((cosig, age))
    };
    match run() {
        Ok((cosig, age_secs)) => serde_json::json!({
            "valid": true,
            "witness_id": cosig.witness_id,
            "age_secs": age_secs,
            "stale": age_secs > max_age_secs,
        })
        .to_string(),
        Err(e) => failure(&e).to_string(),
    }
}

// ── Consumer quorum (RFC-ACDP-0015 §8, N-witnessed) ──────────────────────────

/// The parsed [`WitnessPolicy`](acdp::client::WitnessPolicy) equivalent
/// (a plain struct — the bindings never expose the Rust type).
pub(crate) struct WitnessPolicyParsed {
    pub min_witnesses: u32,
    /// `None` disables the §8.1 freshness split (fresh == verified).
    pub max_age_secs: Option<i64>,
    pub max_clock_skew_secs: i64,
}

/// Parse `policy_json` (`{min_witnesses?, max_age_secs?,
/// max_clock_skew_secs?}`) into a [`WitnessPolicyParsed`]. Defaults
/// mirror the Rust `WitnessPolicy::default()`: `min_witnesses = 1`,
/// `max_age_secs = Some(300)`, `max_clock_skew_secs = 120`. An explicit
/// JSON `null` for `max_age_secs` disables the freshness split. Errors
/// are HOST-input problems and are raised by the wrappers.
pub(crate) fn parse_witness_policy(policy_json: &str) -> Result<WitnessPolicyParsed, String> {
    let value: serde_json::Value =
        serde_json::from_str(policy_json).map_err(|e| format!("invalid policy JSON: {e}"))?;
    let obj = value.as_object().ok_or("policy must be a JSON object")?;

    let min_witnesses = match obj.get("min_witnesses") {
        None => 1,
        Some(v) => v
            .as_u64()
            .filter(|v| *v >= 1 && *v <= u64::from(u32::MAX))
            .ok_or("policy.min_witnesses must be an integer >= 1")? as u32,
    };
    // Absent → default 300; explicit null → None (disable); number → Some.
    let max_age_secs = match obj.get("max_age_secs") {
        None => Some(DEFAULT_WITNESS_MAX_AGE_SECS),
        Some(serde_json::Value::Null) => None,
        Some(v) => Some(
            v.as_i64()
                .filter(|v| *v >= 0)
                .ok_or("policy.max_age_secs must be a non-negative integer or null")?,
        ),
    };
    let max_clock_skew_secs = match obj.get("max_clock_skew_secs") {
        None => DEFAULT_WITNESS_MAX_CLOCK_SKEW_SECS,
        Some(v) => v
            .as_i64()
            .filter(|v| *v >= 0)
            .ok_or("policy.max_clock_skew_secs must be a non-negative integer")?,
    };
    Ok(WitnessPolicyParsed {
        min_witnesses,
        max_age_secs,
        max_clock_skew_secs,
    })
}

/// Compute the RFC-ACDP-0015 §8 N-witnessed report for a checkpoint the
/// consumer has itself verified — the pure mirror of the Rust
/// `client::evaluate_witness_quorum`.
///
/// A cosignature counts toward N iff it (a) names a trusted witness, (b)
/// covers the same `(log_id, tree_size, root_hash)` tuple as
/// `expected_checkpoint`, and (c) passes every §8 step. DISTINCT
/// `witness_id` values are counted; repeats from one witness count once.
/// A cosignature that fails a step does not fail the checkpoint — it is
/// recorded in `failures` and simply does not count.
///
/// `witness_did_docs` is a JSON object keyed by `witness_id`; each value
/// is that witness's resolved DID document. Returns the report as a JSON
/// string; the `Err` arm is a malformed `expected_checkpoint` (host
/// input), raised by the wrappers.
pub(crate) fn evaluate_witness_quorum_report(
    cosignatures: &[serde_json::Value],
    expected_checkpoint: &serde_json::Value,
    trusted_witnesses: &[String],
    witness_did_docs: &serde_json::Map<String, serde_json::Value>,
    policy: &WitnessPolicyParsed,
    now: DateTime<Utc>,
) -> Result<String, AcdpError> {
    let checkpoint = LogCheckpoint::from_value(expected_checkpoint)?;
    let expected_tuple = (
        checkpoint.log_id.as_str(),
        checkpoint.tree_size,
        checkpoint.root_hash.as_str(),
    );

    let mut verified: BTreeSet<String> = BTreeSet::new();
    let mut fresh: BTreeSet<String> = BTreeSet::new();
    let mut failures: Vec<serde_json::Value> = Vec::new();

    for value in cosignatures {
        // Peek at the tuple + witness_id via the closed parse. A malformed
        // cosignature can't be attributed to a tuple/witness, so it is
        // skipped here rather than blamed on this checkpoint.
        let Ok(peek) = LogCosignature::from_value(value) else {
            continue;
        };
        if peek.checkpoint_tuple() != expected_tuple {
            continue; // evidence about a different checkpoint (§8 step 4)
        }
        if !trusted_witnesses.iter().any(|w| w == &peek.witness_id) {
            continue; // untrusted — cannot count toward N (§8 step 3)
        }
        // A trusted witness over our tuple: it MUST verify to count.
        let Some(doc) = witness_did_docs.get(&peek.witness_id) else {
            failures.push(failure(&AcdpError::InvalidWitnessCosignature(format!(
                "no DID document supplied for trusted witness '{}' — cannot verify its \
                 cosignature (RFC-ACDP-0015 §8 step 2)",
                peek.witness_id
            ))));
            continue;
        };
        match verify_witness_cosignature(value, doc, &checkpoint, now, policy.max_clock_skew_secs) {
            Ok(cosig) => {
                let within_age = policy
                    .max_age_secs
                    .is_none_or(|max| cosig.age_at(now) <= Duration::seconds(max));
                if within_age {
                    fresh.insert(cosig.witness_id.clone());
                }
                verified.insert(cosig.witness_id);
            }
            Err(e) => failures.push(failure(&e)),
        }
    }

    let witnessed_count = verified.len();
    let fresh_witnessed_count = fresh.len();
    let min = policy.min_witnesses as usize;
    Ok(serde_json::json!({
        "witnessed_count": witnessed_count,
        "witnesses": verified.into_iter().collect::<Vec<_>>(),
        "meets_quorum": witnessed_count >= min,
        "fresh_witnessed_count": fresh_witnessed_count,
        "meets_fresh_quorum": fresh_witnessed_count >= min,
        "failures": failures,
    })
    .to_string())
}
