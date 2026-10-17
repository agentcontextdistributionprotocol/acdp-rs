//! Pure-Rust core of the ACDP WebAssembly verifier surface.
//!
//! FFI-framework-free: every function takes JSON strings (and plain
//! scalar strings) and returns JSON strings — either a **verdict object**
//! (`{"valid": true, ...}` / `{"valid": false, "code"?, "error"}`) for
//! verification outcomes, or a plain result string for constructors and
//! resolvers. Malformed HOST input (bad JSON, bad base64) is returned as
//! `Err(String)`; the thin `wasm-bindgen` layer in `lib.rs` maps that to
//! a thrown `JsError`, exactly as the PyO3 wrappers raise `ValueError`.
//!
//! This mirrors the `bindings/acdp-py` / `bindings/acdp-node`
//! `AcdpVerifier` design: crypto in Rust, JSON across the boundary, HTTP
//! (and `did:web` resolution) in the JS host. The 0.3/0.4 verdict logic
//! is reused **verbatim** from the byte-identical shared cores
//! [`crate::v030`] / [`crate::v040`] — no crypto is reimplemented here.
//!
//! A failed *verification* is a result to report, not an error: those
//! functions return `Ok(verdict_json)` with `"valid": false`. Only
//! malformed host input yields `Err`.
//!
//! `verify_ctx_id_binding_json` is the one place this line gets subtle:
//! `expected_ctx_id` is host input (pre-parsed with `CtxId::parse`, so a
//! malformed value is `Err`), but a malformed *served* `ctx_id` — i.e.
//! one embedded in `body_json` — is a fail verdict, because it describes
//! the thing being verified, not a caller mistake. See
//! `bindings/acdp-wasm/README.md` for why the binding exists at all
//! (RFC-ACDP-0006 §4.1 step 7).

use acdp::crypto::{
    canonical_preimage, explain_hash_mismatch, fingerprint_ed25519, verify_body_value_offline,
    verify_content_hash, verify_ecdsa_p256, verify_ed25519,
    verify_publish_request_signature_offline,
};
use acdp::did::{resolve_did_key, DidKeyMaterial};
use acdp::types::revocation::KeyRevocation;
use acdp::types::{Body, ContentHash, CtxId, PublishRequest, RegistryReceipt};
use acdp::verify::verify_ctx_id_binding;
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};

use crate::{v030, v040};

// ── shared helpers ───────────────────────────────────────────────────

/// Parse a required JSON argument, tagging the error with the argument
/// name (a malformed host input, surfaced as `Err`).
fn parse_json(arg: &str, what: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(arg).map_err(|e| format!("invalid {what} JSON: {e}"))
}

/// Parse an optional RFC 3339 `now`, defaulting to the system clock. The
/// fixture-friendly escape hatch: golden vectors pin their clock.
fn parse_now(now_rfc3339: Option<&str>) -> Result<DateTime<Utc>, String> {
    match now_rfc3339 {
        None => Ok(Utc::now()),
        Some(raw) => DateTime::parse_from_rfc3339(raw)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|e| format!("invalid now_rfc3339 '{raw}': {e}")),
    }
}

/// Parse a REQUIRED RFC 3339 timestamp argument.
fn parse_rfc3339_required(raw: &str, what: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| format!("invalid {what} '{raw}': {e}"))
}

/// Decode a standard-base64 raw 32-byte Ed25519 public key.
fn decode_ed25519_b64(public_key_b64: &str) -> Result<[u8; 32], String> {
    let bytes: Vec<u8> = STANDARD
        .decode(public_key_b64)
        .map_err(|e| format!("invalid public_key_b64: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "public key must decode to 32 bytes".to_string())
}

/// Decode a hex-encoded 32-byte witness signing seed.
fn decode_witness_seed_hex(seed_hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(seed_hex).map_err(|e| format!("invalid witness_seed_hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "witness_seed_hex must decode to 32 bytes".to_string())
}

/// A `{"valid": true}` verdict.
fn verdict_ok() -> String {
    "{\"valid\":true}".to_string()
}

/// A `{"valid": false, "error": ...}` verdict — the crypto-primitive
/// failure shape (byte-level checks carry no RFC-0007 wire code of their
/// own; the v030/v040 verdicts that DO have codes build them themselves).
fn verdict_fail(err: impl std::fmt::Display) -> String {
    serde_json::json!({ "valid": false, "error": err.to_string() }).to_string()
}

// ── content_hash + producer signature (the full-context path) ────────

/// Recompute `sha256(JCS(producer_content))` over the RAW body JSON and
/// compare against the supplied `expected_hash`. Returns a verdict.
/// `Err` only on malformed JSON / a malformed `expected_hash` envelope.
pub fn verify_content_hash_json(body_json: &str, expected_hash: &str) -> Result<String, String> {
    let body: serde_json::Value = parse_json(body_json, "body")?;
    let stored =
        ContentHash::parse(expected_hash).map_err(|e| format!("invalid content_hash: {e}"))?;
    Ok(match verify_content_hash(&body, &stored) {
        Ok(()) => verdict_ok(),
        Err(e) => verdict_fail(e),
    })
}

/// Verify that a body's *served* `ctx_id` matches the `ctx_id` the
/// caller *expected* (RFC-ACDP-0006 §4.1 step 7, NORMATIVE) — the
/// context-identity binding check for the receipt-less retrieval path,
/// since `ctx_id` is registry-assigned and outside
/// `content_hash`/signature coverage.
///
/// Argument order is `(body_json, expected_ctx_id)`: the body's own
/// `ctx_id` is the *served* identity, `expected_ctx_id` is what the
/// caller requested — the same `(served, expected)` order as
/// `verify_ctx_id_binding` and `RegistryReceipt::cross_check`.
///
/// `expected_ctx_id` is host input, so a malformed value is pre-parsed
/// and `Err`s (throws), mirroring `verify_content_hash_json`'s
/// `expected_hash` and `verify_receipt_json`'s `expected_ctx_id`. The
/// *served* side is registry data: a malformed served `ctx_id`, or a
/// served/expected mismatch, stays a verification outcome
/// (`{"valid": false, ...}`) via `verify_ctx_id_binding`. `Err`
/// otherwise only on malformed body JSON.
pub fn verify_ctx_id_binding_json(
    body_json: &str,
    expected_ctx_id: &str,
) -> Result<String, String> {
    let body: Body =
        serde_json::from_str(body_json).map_err(|e| format!("invalid body JSON: {e}"))?;
    let expected =
        CtxId::parse(expected_ctx_id).map_err(|e| format!("invalid expected_ctx_id: {e}"))?;
    Ok(
        match verify_ctx_id_binding(body.ctx_id.as_str(), expected.as_str()) {
            Ok(()) => verdict_ok(),
            Err(e) => verdict_fail(e),
        },
    )
}

/// Verify an Ed25519 signature over the ASCII `"sha256:<hex>"` string
/// (RFC-ACDP-0001 §5.8 — NOT the raw digest). `pub_key_b64` is the raw
/// 32-byte key, base64. Returns a verdict.
pub fn verify_signature_ed25519(
    pub_key_b64: &str,
    sig_b64: &str,
    content_hash: &str,
) -> Result<String, String> {
    let key = decode_ed25519_b64(pub_key_b64)?;
    Ok(match verify_ed25519(&key, sig_b64, content_hash) {
        Ok(()) => verdict_ok(),
        Err(e) => verdict_fail(e),
    })
}

/// Verify an ECDSA-P256 signature (IEEE-1363 `r‖s`, base64) over the
/// ASCII `"sha256:<hex>"` string. `pub_key_sec1_b64` is the 65-byte
/// SEC1-uncompressed key, base64. Returns a verdict.
pub fn verify_signature_p256(
    pub_key_sec1_b64: &str,
    sig_b64: &str,
    content_hash: &str,
) -> Result<String, String> {
    let key: Vec<u8> = STANDARD
        .decode(pub_key_sec1_b64)
        .map_err(|e| format!("invalid pub_key_sec1_b64: {e}"))?;
    Ok(match verify_ecdsa_p256(&key, sig_b64, content_hash) {
        Ok(()) => verdict_ok(),
        Err(e) => verdict_fail(e),
    })
}

/// Fully verify a `did:key` body offline (ACDP 0.2): structural
/// validation, `content_hash` recomputation, key_id/agent_id
/// consistency, and signature verification against the key embedded in
/// the DID. No resolution, no network, no key argument. Returns a
/// verdict (a non-`did:key` producer fails — `did:web` needs host-side
/// resolution).
pub fn verify_body_offline_json(body_json: &str) -> Result<String, String> {
    // Raw wire value, not a typed re-serialization: the hash is
    // recomputed over the bytes the producer signed (RFC-ACDP-0001 §5.7).
    let raw: serde_json::Value =
        serde_json::from_str(body_json).map_err(|e| format!("invalid body JSON: {e}"))?;
    let _: Body =
        serde_json::from_value(raw.clone()).map_err(|e| format!("invalid body JSON: {e}"))?;
    Ok(match verify_body_value_offline(&raw) {
        Ok(_) => verdict_ok(),
        Err(e) => verdict_fail(e),
    })
}

/// Fully verify a `did:key` PublishRequest offline (ACDP 0.2): recompute
/// and check `content_hash` over the RAW wire object, then verify the
/// signature against the key embedded in the `did:key` DID. Returns a
/// verdict.
pub fn verify_publish_request_offline_json(request_json: &str) -> Result<String, String> {
    let req: PublishRequest =
        serde_json::from_str(request_json).map_err(|e| format!("invalid request JSON: {e}"))?;
    let value: serde_json::Value = parse_json(request_json, "request")?;
    if let Err(e) = verify_content_hash(&value, &req.content_hash) {
        return Ok(verdict_fail(format!("content_hash mismatch: {e}")));
    }
    Ok(match verify_publish_request_signature_offline(&req) {
        Ok(()) => verdict_ok(),
        Err(e) => verdict_fail(e),
    })
}

// ── diagnostics ──────────────────────────────────────────────────────

/// The exact JCS canonical preimage hashed for `content_hash`, as a
/// string (canonical bytes are always valid UTF-8). Diff two SDKs'
/// preimages to localize a hash divergence.
pub fn canonical_preimage_json(body_json: &str) -> Result<String, String> {
    let body: serde_json::Value = parse_json(body_json, "body")?;
    let (bytes, _hash) = canonical_preimage(&body).map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| format!("canonical bytes not UTF-8: {e}"))
}

/// Diagnose a `content_hash` mismatch by probing known divergence
/// patterns (WS-D2). Human-readable report; never a verdict.
pub fn explain_hash_mismatch_json(body_json: &str, expected_hash: &str) -> Result<String, String> {
    let body: serde_json::Value = parse_json(body_json, "body")?;
    let expected =
        ContentHash::parse(expected_hash).map_err(|e| format!("invalid content_hash: {e}"))?;
    explain_hash_mismatch(&body, &expected).map_err(|e| e.to_string())
}

// ── registry receipts (RFC-ACDP-0010) ────────────────────────────────

/// Fingerprint a raw Ed25519 public key for receipt cross-checks:
/// `"sha256:" + hex(SHA-256(raw 32-byte key))`.
pub fn fingerprint_ed25519_b64(public_key_b64: &str) -> Result<String, String> {
    let key = decode_ed25519_b64(public_key_b64)?;
    Ok(fingerprint_ed25519(&key))
}

/// Verify a registry receipt (RFC-ACDP-0010): reject non-canonical
/// `created_at` byte forms, run the offline cross-checks against the
/// consumer's own recomputed body hash / expected ctx_id / producer key
/// fingerprint, bind the receipt's `lineage_id` / `origin_registry` /
/// `created_at` to the accompanying `body_json` (§8 step 3), then verify
/// the registry's Ed25519 signature over the preimage hashed from the
/// RAW wire JSON (never a re-serialized struct).
///
/// `body_json` must parse into a full `Body` — a malformed value is a
/// host-input error (`Err`), distinct from a `cross_check_body`
/// mismatch, which is a `{"valid": false, ...}` verdict like any other
/// receipt cross-check failure.
///
/// Two checks remain the HOST/caller's obligation — this binding makes
/// no HTTP calls, so it cannot perform them (see the py binding docs
/// for the full rationale):
///
/// 1. Serving-authority binding — `receipt.registry_did` MUST equal
///    `"did:web:" + <authority>` where `<authority>` is the authority
///    the response was *actually fetched from*, not whatever the
///    receipt claims.
/// 2. Recompute, don't trust, the body hash — `recomputed_body_hash`
///    MUST be the body hash independently recomputed (e.g. via
///    `verify_content_hash_json`), never the body's echoed
///    `content_hash` field taken on faith.
///
/// This returns a verdict.
pub fn verify_receipt_json(
    receipt_json: &str,
    body_json: &str,
    registry_public_key_b64: &str,
    expected_ctx_id: &str,
    recomputed_body_hash: &str,
    producer_key_fingerprint: &str,
) -> Result<String, String> {
    let value: serde_json::Value = parse_json(receipt_json, "receipt")?;
    let body: Body =
        serde_json::from_str(body_json).map_err(|e| format!("invalid body JSON: {e}"))?;
    let registry_key = decode_ed25519_b64(registry_public_key_b64)?;
    let recomputed = ContentHash::parse(recomputed_body_hash)
        .map_err(|e| format!("invalid recomputed_body_hash: {e}"))?;
    let expected_ctx =
        CtxId::parse(expected_ctx_id).map_err(|e| format!("invalid expected_ctx_id: {e}"))?;

    // §8 step 6: reject non-canonical created_at byte forms first — a
    // parsed struct would silently normalize them. This is a
    // verification outcome, not a host error.
    if let Err(e) = RegistryReceipt::validate_created_at_form(&value) {
        return Ok(verdict_fail(e));
    }
    let receipt = match RegistryReceipt::from_value(&value) {
        Ok(r) => r,
        Err(e) => return Ok(verdict_fail(e)),
    };
    if let Err(e) = receipt.cross_check(&expected_ctx, &recomputed, producer_key_fingerprint) {
        return Ok(verdict_fail(e));
    }
    // §8 step 3 body bindings: lineage_id / origin_registry / created_at
    // must equal the accompanying body's fields. A mismatch is a
    // verification outcome, not a host error — the body itself parsed
    // fine.
    if let Err(e) = receipt.cross_check_body(&body) {
        return Ok(verdict_fail(e));
    }
    let raw_hash = match RegistryReceipt::preimage_hash_of_value(&value) {
        Ok(h) => h,
        Err(e) => return Ok(verdict_fail(e)),
    };
    Ok(
        match receipt.verify_signature_against_hash(&raw_hash, Some(&registry_key), None) {
            Ok(()) => verdict_ok(),
            Err(e) => verdict_fail(e),
        },
    )
}

// ── lineage-head receipts (RFC-ACDP-0011) ─────────────────────────────

/// Verify a lineage-head receipt offline (RFC-ACDP-0011 §7). Delegates
/// verbatim to the shared [`crate::v030`] verdict core. Returns a JSON
/// verdict `{"valid", "stale", "age_secs", "historical"}` /
/// `{"valid": false, "code", "error"}`.
#[allow(clippy::too_many_arguments)]
pub fn verify_lineage_head_receipt_json(
    receipt_json: &str,
    expected_json: &str,
    registry_did_doc_json: &str,
    now_rfc3339: Option<&str>,
    max_skew_secs: Option<i64>,
    max_age_secs: Option<i64>,
) -> Result<String, String> {
    let value = parse_json(receipt_json, "receipt")?;
    let expected = v030::parse_expected_head(expected_json)?;
    let now = parse_now(now_rfc3339)?;
    Ok(v030::lineage_head_receipt_verdict(
        &value,
        &expected,
        registry_did_doc_json,
        now,
        max_skew_secs.unwrap_or(v030::DEFAULT_MAX_SKEW_SECS),
        max_age_secs.unwrap_or(v030::DEFAULT_MAX_AGE_SECS),
    ))
}

// ── transparency log (RFC-ACDP-0012) ─────────────────────────────────

/// Verify a transparency-log checkpoint (signed tree head) offline
/// (RFC-ACDP-0012 §9.3). Returns a JSON verdict.
pub fn verify_log_checkpoint_json(
    checkpoint_json: &str,
    registry_did_doc_json: &str,
    expected_log_id: Option<&str>,
    now_rfc3339: Option<&str>,
    max_skew_secs: Option<i64>,
) -> Result<String, String> {
    let value = parse_json(checkpoint_json, "checkpoint")?;
    let now = parse_now(now_rfc3339)?;
    Ok(v030::log_checkpoint_verdict(
        &value,
        registry_did_doc_json,
        expected_log_id,
        now,
        max_skew_secs.unwrap_or(v030::DEFAULT_MAX_SKEW_SECS),
    ))
}

/// Verify a transparency-log inclusion proof offline (RFC-ACDP-0012
/// §9.1). `reconstructed_leaf_json` MUST be a leaf the verifier built
/// from verified material (see [`build_log_leaf_json`]), never a
/// registry-echoed leaf. Returns a JSON verdict.
pub fn verify_log_inclusion_json(
    inclusion_json: &str,
    checkpoint_json: &str,
    reconstructed_leaf_json: &str,
) -> Result<String, String> {
    let inclusion = parse_json(inclusion_json, "inclusion")?;
    let checkpoint = parse_json(checkpoint_json, "checkpoint")?;
    let leaf = parse_json(reconstructed_leaf_json, "leaf")?;
    Ok(v030::log_inclusion_verdict(&inclusion, &checkpoint, &leaf))
}

/// Verify a transparency-log consistency proof offline (RFC-ACDP-0012
/// §9.2) — the history-rewrite detector. Returns a JSON verdict.
pub fn verify_log_consistency_json(
    consistency_json: &str,
    checkpoint_json: &str,
    first_root_hash: &str,
) -> Result<String, String> {
    let consistency = parse_json(consistency_json, "consistency proof")?;
    let checkpoint = parse_json(checkpoint_json, "checkpoint")?;
    Ok(v030::log_consistency_verdict(
        &consistency,
        &checkpoint,
        first_root_hash,
    ))
}

/// Build the canonical RFC-ACDP-0012 §4 log leaf from a VERIFIED
/// RFC-ACDP-0010 receipt (§9.1 step 1). Returns the leaf JSON string.
/// `Err` on a malformed receipt.
pub fn build_log_leaf_json(receipt_json: &str) -> Result<String, String> {
    let value = parse_json(receipt_json, "receipt")?;
    v030::build_log_leaf_core(&value).map_err(|e| e.to_string())
}

// ── lifecycle events (RFC-ACDP-0013) ─────────────────────────────────

/// Verify one `registry_state.lifecycle_events` entry offline
/// (RFC-ACDP-0013 §5). `actor_did_doc_json` is `None` for a `did:key`
/// actor. Returns a JSON verdict.
pub fn verify_lifecycle_event_json(
    event_json: &str,
    actor_did_doc_json: Option<&str>,
    expected_ctx_id: &str,
) -> Result<String, String> {
    let value = parse_json(event_json, "event")?;
    Ok(v030::lifecycle_event_verdict(
        &value,
        actor_did_doc_json,
        expected_ctx_id,
    ))
}

// ── key revocation (RFC-ACDP-0014) ───────────────────────────────────

/// Parse and shape-validate a `key-revocation` context body
/// (RFC-ACDP-0014 §4) and derive its trust class. Returns the typed
/// revocation as JSON. `Err` on §4 shape violations / a self-signed
/// revocation. Parsing does NOT verify the body.
pub fn parse_key_revocation_json(
    body_json: &str,
    signer_fingerprint: Option<&str>,
) -> Result<String, String> {
    let body: Body =
        serde_json::from_str(body_json).map_err(|e| format!("invalid body JSON: {e}"))?;
    v030::parse_key_revocation_core(&body, signer_fingerprint).map_err(|e| e.to_string())
}

/// Apply the RFC-ACDP-0014 §7 compromise-boundary rule (fail-closed).
/// `revocations_json` is a JSON array of VERIFIED revocations.
/// `receipt_created_at_rfc3339` MUST come from a VERIFIED receipt, never
/// the bare body `created_at`. Returns a JSON authorization report.
pub fn classify_under_revocation_json(
    revocations_json: &str,
    signer_fingerprint: &str,
    receipt_created_at_rfc3339: Option<&str>,
) -> Result<String, String> {
    let revocations: Vec<KeyRevocation> = serde_json::from_str(revocations_json)
        .map_err(|e| format!("invalid revocations JSON (array): {e}"))?;
    let created_at = match receipt_created_at_rfc3339 {
        None => None,
        Some(raw) => Some(parse_rfc3339_required(raw, "receipt_created_at_rfc3339")?),
    };
    Ok(v030::classify_under_revocation_core(
        &revocations,
        signer_fingerprint,
        created_at,
    ))
}

// ── Merkle tree arithmetic (RFC-ACDP-0012 §5) ────────────────────────

/// §5.1 leaf hash `SHA-256(0x00 ‖ JCS(leaf))` → `"sha256:<hex>"`.
pub fn merkle_leaf_hash_json(leaf_json: &str) -> Result<String, String> {
    let value = parse_json(leaf_json, "leaf")?;
    v030::merkle_leaf_hash(&value).map_err(|e| e.to_string())
}

/// §5.1 interior-node hash `SHA-256(0x01 ‖ left ‖ right)` over the two
/// wire-form (`"sha256:<hex>"`) child digests.
pub fn merkle_node_hash_str(left_hash: &str, right_hash: &str) -> Result<String, String> {
    v030::merkle_node_hash(left_hash, right_hash).map_err(|e| e.to_string())
}

/// §5.2 RFC 6962 Merkle tree hash `MTH(D[n])` over an ordered JSON array
/// of wire-form leaf hashes. An empty array yields `SHA-256("")`.
pub fn merkle_root_hash_json(leaf_hashes_json: &str) -> Result<String, String> {
    let hashes: Vec<String> = serde_json::from_str(leaf_hashes_json)
        .map_err(|e| format!("invalid leaf_hashes JSON (array of strings): {e}"))?;
    v030::merkle_root_hash(&hashes).map_err(|e| e.to_string())
}

// ── witness cosignatures (RFC-ACDP-0015) ─────────────────────────────

/// Mint a signed transparency-log witness cosignature (RFC-ACDP-0015
/// §5). Deterministic (Ed25519) — draws no randomness. Returns the
/// signed `log_cosignature` JSON. `Err` on malformed input.
pub fn build_witness_cosignature_json(
    witnessed_checkpoint_json: &str,
    witness_did: &str,
    witness_seed_hex: &str,
    witnessed_at_rfc3339: &str,
) -> Result<String, String> {
    let witnessed_checkpoint = parse_json(witnessed_checkpoint_json, "witnessed_checkpoint")?;
    let seed = decode_witness_seed_hex(witness_seed_hex)?;
    let witnessed_at = parse_rfc3339_required(witnessed_at_rfc3339, "witnessed_at_rfc3339")?;
    v040::build_witness_cosignature_core(&witnessed_checkpoint, witness_did, &seed, witnessed_at)
        .map_err(|e| e.to_string())
}

/// Verify one witness cosignature against a checkpoint the consumer has
/// itself verified (RFC-ACDP-0015 §8, steps 1–5). Returns a JSON verdict
/// `{"valid", "witness_id", "age_secs", "stale"}` /
/// `{"valid": false, "code", "error"}`.
pub fn verify_witness_cosignature_json(
    cosig_json: &str,
    witness_did_doc_json: &str,
    expected_checkpoint_json: &str,
    now_rfc3339: Option<&str>,
    max_clock_skew_secs: Option<i64>,
) -> Result<String, String> {
    let cosig = parse_json(cosig_json, "cosignature")?;
    let doc = parse_json(witness_did_doc_json, "witness DID document")?;
    let checkpoint = parse_json(expected_checkpoint_json, "checkpoint")?;
    let now = parse_now(now_rfc3339)?;
    Ok(v040::verify_witness_cosignature_verdict(
        &cosig,
        &doc,
        &checkpoint,
        now,
        max_clock_skew_secs.unwrap_or(v040::DEFAULT_WITNESS_MAX_CLOCK_SKEW_SECS),
        v040::DEFAULT_WITNESS_MAX_AGE_SECS,
    ))
}

/// Compute the RFC-ACDP-0015 §8 N-witnessed report over a set of
/// cosignatures for a verified checkpoint. Returns a JSON report. `Err`
/// only on malformed host input.
pub fn evaluate_witness_quorum_json(
    cosignatures_json: &str,
    expected_checkpoint_json: &str,
    trusted_witness_dids_json: &str,
    witness_did_docs_json: &str,
    policy_json: &str,
    now_rfc3339: Option<&str>,
) -> Result<String, String> {
    let cosignatures: Vec<serde_json::Value> = serde_json::from_str(cosignatures_json)
        .map_err(|e| format!("invalid cosignatures JSON (array): {e}"))?;
    let checkpoint = parse_json(expected_checkpoint_json, "checkpoint")?;
    let trusted: Vec<String> = serde_json::from_str(trusted_witness_dids_json)
        .map_err(|e| format!("invalid trusted_witness_dids JSON (array): {e}"))?;
    let docs_value = parse_json(witness_did_docs_json, "witness DID docs")?;
    let docs = docs_value
        .as_object()
        .ok_or_else(|| {
            "witness_did_docs_json must be a JSON object keyed by witness_id".to_string()
        })?
        .clone();
    let policy = v040::parse_witness_policy(policy_json)?;
    let now = parse_now(now_rfc3339)?;
    v040::evaluate_witness_quorum_report(&cosignatures, &checkpoint, &trusted, &docs, &policy, now)
        .map_err(|e| e.to_string())
}

// ── did:key resolution (offline) ─────────────────────────────────────

/// Resolve a `did:key:z…` DID to its public key material — pure, offline
/// (no network, no document). Returns
/// `{"algorithm": "ed25519", "public_key_b64": ...}` or
/// `{"algorithm": "ecdsa-p256", "public_key_sec1_b64": ...}` (the SEC1
/// point re-encoded uncompressed is NOT done here — did:key carries the
/// 33-byte compressed point; we return it base64 as `public_key_b64`
/// tagged by algorithm). `Err` on a malformed did:key.
pub fn resolve_did_key_json(did: &str) -> Result<String, String> {
    let material = resolve_did_key(did).map_err(|e| e.to_string())?;
    let value = match material {
        DidKeyMaterial::Ed25519(key) => serde_json::json!({
            "algorithm": "ed25519",
            "public_key_b64": STANDARD.encode(key),
        }),
        DidKeyMaterial::EcdsaP256(point) => serde_json::json!({
            "algorithm": "ecdsa-p256",
            // did:key carries the SEC1-*compressed* 33-byte point.
            "public_key_compressed_b64": STANDARD.encode(point),
        }),
    };
    Ok(value.to_string())
}
