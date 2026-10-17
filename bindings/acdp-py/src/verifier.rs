//! `AcdpVerifier` — consumer-side content_hash and signature verification.
//!
//! All methods are static. DID resolution is intentionally NOT done here
//! — that requires async HTTP and belongs in the host language (or the
//! Rust `client` feature called from native code). This binding exposes
//! the pure-crypto checks every consumer needs:
//!
//! * `verify_content_hash` — recompute `sha256(JCS(producer_content))`
//!   and compare against the body's stored `content_hash`.
//! * `verify_signature` — Ed25519 verify against an already-known
//!   public key, useful once the host has resolved the producer's DID.
//! * `verify_ctx_id_binding` — bind the served `ctx_id` (from the body)
//!   to the `ctx_id` the caller requested (RFC-ACDP-0006 §4.1 step 7,
//!   NORMATIVE). `ctx_id` is registry-assigned and outside both
//!   `content_hash` and the producer signature (RFC-ACDP-0001 §5.7), so
//!   this explicit comparison is the only binding available on the
//!   receipt-less path.
//! * `verify_body_offline` / `verify_publish_request_offline` — full
//!   verification for `did:key` producers (ACDP 0.2), where the key is
//!   the identity and no resolution is needed at all.
//! * `canonical_preimage` / `explain_hash_mismatch` — hash-divergence
//!   diagnostics (WS-D2).
//! * `fingerprint_ed25519_b64` / `verify_receipt` — registry-receipt
//!   verification (ACDP 0.2, RFC-ACDP-0010).
//!
//! ACDP 0.3 adds the offline verdict surface (documents supplied by
//! the caller, never fetched here):
//!
//! * `verify_lineage_head_receipt` — RFC-ACDP-0011 §7.
//! * `verify_log_checkpoint` / `verify_log_inclusion` /
//!   `verify_log_consistency` / `build_log_leaf` — RFC-ACDP-0012
//!   §9.1–§9.3 (tree arithmetic itself: [`crate::merkle`]).
//! * `verify_lifecycle_event` — RFC-ACDP-0013 §5.
//! * `parse_key_revocation` / `classify_under_revocation` —
//!   RFC-ACDP-0014 §4–§7.
//!
//! The `verify_*` 0.3 methods return JSON **verdict strings**
//! (`{"valid": true, ...}` / `{"valid": false, "code": ..., "error":
//! ...}`) instead of raising on verification failure — a failed
//! verification is a result to report, not a host programming error.
//! Only malformed host input raises.

use acdp::crypto::{
    canonical_preimage, explain_hash_mismatch, fingerprint_ed25519, verify_body_value_offline,
    verify_content_hash, verify_ecdsa_p256, verify_ed25519,
    verify_publish_request_signature_offline,
};
use acdp::types::revocation::KeyRevocation;
use acdp::types::{Body, ContentHash, CtxId, PublishRequest, RegistryReceipt};
use acdp::verify::verify_ctx_id_binding;
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use crate::errors::map_acdp_error;
use crate::{v030, v040};

/// Parse an optional RFC 3339 `now` argument, defaulting to the system
/// clock (the fixture-friendly escape hatch: golden vectors pin their
/// timestamps, so tests pass an explicit consumer clock).
fn parse_now(now_rfc3339: Option<&str>) -> PyResult<DateTime<Utc>> {
    match now_rfc3339 {
        None => Ok(Utc::now()),
        Some(raw) => DateTime::parse_from_rfc3339(raw)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|e| PyValueError::new_err(format!("invalid now_rfc3339 '{raw}': {e}"))),
    }
}

/// Parse a required JSON-object argument, raising `ValueError` with the
/// argument's name on malformed input.
fn parse_json(arg: &str, what: &str) -> PyResult<serde_json::Value> {
    serde_json::from_str(arg)
        .map_err(|e| PyValueError::new_err(format!("invalid {what} JSON: {e}")))
}

/// Parse a REQUIRED RFC 3339 timestamp argument, raising `ValueError`
/// with the argument's name on malformed input.
fn parse_rfc3339_required(raw: &str, what: &str) -> PyResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| PyValueError::new_err(format!("invalid {what} '{raw}': {e}")))
}

/// Decode a hex-encoded 32-byte witness signing seed.
fn decode_witness_seed_hex(seed_hex: &str) -> PyResult<[u8; 32]> {
    let bytes = hex::decode(seed_hex)
        .map_err(|e| PyValueError::new_err(format!("invalid witness_seed_hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("witness_seed_hex must decode to 32 bytes"))
}

/// Decode a standard-base64 raw 32-byte Ed25519 public key.
fn decode_ed25519_b64(public_key_b64: &str) -> PyResult<[u8; 32]> {
    let bytes: Vec<u8> = STANDARD
        .decode(public_key_b64)
        .map_err(|e| PyValueError::new_err(format!("invalid public_key_b64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("public key must decode to 32 bytes"))
}

/// Consumer-side verification utilities. All methods are static.
#[pyclass(name = "AcdpVerifier")]
pub struct PyAcdpVerifier;

#[pymethods]
impl PyAcdpVerifier {
    /// Verify that a body's `content_hash` matches the SHA-256 over its
    /// JCS-canonicalized producer-controlled fields.
    ///
    /// * `body_json` — the `body` object from a `FullContext` retrieval
    ///   (or the `PublishRequest` itself — both share the §5.7 layout).
    /// * `expected_hash` — the `body.content_hash` string
    ///   (`"sha256:<64-hex>"`).
    ///
    /// Returns `True` on success. Raises `RuntimeError` on mismatch or
    /// `ValueError` on malformed JSON.
    #[staticmethod]
    fn verify_content_hash(body_json: &str, expected_hash: &str) -> PyResult<bool> {
        let body: serde_json::Value = serde_json::from_str(body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;
        // Validate the hash envelope up-front so a malformed
        // `expected_hash` (wrong prefix, wrong length, uppercase hex)
        // produces a clear ValueError instead of being treated as a
        // recomputation mismatch.
        let stored = ContentHash::parse(expected_hash)
            .map_err(|e| PyValueError::new_err(format!("invalid content_hash: {e}")))?;
        verify_content_hash(&body, &stored)
            .map(|_| true)
            .map_err(|e| PyRuntimeError::new_err(format!("content_hash mismatch: {e}")))
    }

    /// Verify that a body's *served* `ctx_id` matches the `ctx_id` the
    /// caller *expected* (RFC-ACDP-0006 §4.1 step 7, NORMATIVE) — the
    /// context-identity binding check for the receipt-less retrieval
    /// path, since `ctx_id` is registry-assigned and outside
    /// `content_hash`/signature coverage.
    ///
    /// Argument order is `(body_json, expected_ctx_id)`: the body's own
    /// `ctx_id` is the *served* identity, `expected_ctx_id` is what the
    /// caller requested — the same `(served, expected)` order as
    /// `verify_ctx_id_binding` and `RegistryReceipt::cross_check`.
    ///
    /// * `body_json` — the `body` object from a `FullContext` retrieval.
    /// * `expected_ctx_id` — the `ctx_id` the caller requested.
    ///
    /// Returns `True` on success. Raises `ValueError` on malformed JSON
    /// or a malformed `ctx_id` on either side, or `RuntimeError` on
    /// mismatch.
    #[staticmethod]
    fn verify_ctx_id_binding(body_json: &str, expected_ctx_id: &str) -> PyResult<bool> {
        let body: Body = serde_json::from_str(body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;
        verify_ctx_id_binding(body.ctx_id.as_str(), expected_ctx_id)
            .map(|_| true)
            .map_err(map_acdp_error)
    }

    /// Verify an Ed25519 signature over a `content_hash` string.
    ///
    /// The signing input per RFC-ACDP-0001 §5.8 is the ASCII bytes of
    /// the full `"sha256:<hex>"` string — NOT the raw 32-byte digest.
    /// This wrapper forwards exactly the same bytes
    /// `acdp::crypto::verify_ed25519` expects.
    ///
    /// * `pub_key_b64` — standard base64 (padded) of the 32-byte raw
    ///   Ed25519 public key (same format as
    ///   `AcdpProducer.public_key_b64`).
    /// * `sig_b64` — the `body.signature.value` field from the wire
    ///   format.
    /// * `content_hash` — the `body.content_hash` string.
    ///
    /// Returns `True` on success. Raises `ValueError` on malformed
    /// base64 input or `RuntimeError` on a verification failure.
    #[staticmethod]
    fn verify_signature(pub_key_b64: &str, sig_b64: &str, content_hash: &str) -> PyResult<bool> {
        let pub_bytes: Vec<u8> = STANDARD
            .decode(pub_key_b64)
            .map_err(|e| PyValueError::new_err(format!("invalid pub_key_b64: {e}")))?;
        let arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("public key must decode to 32 bytes"))?;
        verify_ed25519(&arr, sig_b64, content_hash)
            .map(|_| true)
            .map_err(|e| PyRuntimeError::new_err(format!("signature invalid: {e}")))
    }

    /// Verify an ECDSA-P256 signature over a `content_hash` string.
    ///
    /// The counterpart to [`AcdpP256Producer`] signing. The signing input
    /// per RFC-ACDP-0001 §5.8 is the ASCII bytes of the full
    /// `"sha256:<hex>"` string — NOT the raw 32-byte digest. The wire
    /// signature is IEEE 1363 `r‖s` (64 bytes, base64), NOT DER.
    ///
    /// * `pub_key_sec1_b64` — standard base64 of the 65-byte
    ///   SEC1-uncompressed public key (`0x04 || x || y`), the same format
    ///   as `AcdpP256Producer.public_key_sec1_b64`.
    /// * `sig_b64` — the `body.signature.value` field from the wire
    ///   format (88-char base64 of the 64-byte `r‖s`).
    /// * `content_hash` — the `body.content_hash` string.
    ///
    /// Returns `True` on success. Raises `ValueError` on malformed
    /// base64 input or `RuntimeError` on a verification failure.
    ///
    /// [`AcdpP256Producer`]: crate::producer::PyAcdpP256Producer
    #[staticmethod]
    fn verify_signature_p256(
        pub_key_sec1_b64: &str,
        sig_b64: &str,
        content_hash: &str,
    ) -> PyResult<bool> {
        let pub_bytes: Vec<u8> = STANDARD
            .decode(pub_key_sec1_b64)
            .map_err(|e| PyValueError::new_err(format!("invalid pub_key_sec1_b64: {e}")))?;
        verify_ecdsa_p256(&pub_bytes, sig_b64, content_hash)
            .map(|_| true)
            .map_err(|e| PyRuntimeError::new_err(format!("signature invalid: {e}")))
    }

    /// Fully verify a `did:key` body offline (ACDP 0.2) — structural
    /// validation, `content_hash` recomputation, key_id/agent_id
    /// consistency, and signature verification against the key embedded
    /// in the DID itself. No resolution, no network, no key argument.
    ///
    /// * `body_json` — the `body` object from a `FullContext` retrieval.
    ///
    /// Returns `True` on success. Raises `ValueError` on malformed JSON
    /// or `RuntimeError` on any verification failure (including a
    /// non-`did:key` producer — `did:web` bodies need DID resolution,
    /// which stays in the host language by design).
    #[staticmethod]
    fn verify_body_offline(body_json: &str) -> PyResult<bool> {
        // Raw wire value, not a typed re-serialization: the hash is
        // recomputed over the bytes the producer signed (RFC-ACDP-0001
        // §5.7). Parsing it as a `Body` first keeps the error class.
        let raw: serde_json::Value = serde_json::from_str(body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;
        let _: Body = serde_json::from_value(raw.clone())
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;
        verify_body_value_offline(&raw)
            .map(|_| true)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Fully verify a `did:key` PublishRequest offline (ACDP 0.2):
    /// recompute and check `content_hash`, then verify the signature
    /// against the key embedded in the producer's `did:key` DID.
    ///
    /// * `request_json` — the wire PublishRequest JSON (e.g. the output
    ///   of `AcdpProducer.build_publish_request` on a did:key producer).
    ///
    /// Returns `True` on success. Raises `ValueError` on malformed JSON
    /// or `RuntimeError` on hash mismatch, key/agent inconsistency, a
    /// non-`did:key` producer, or a bad signature.
    #[staticmethod]
    fn verify_publish_request_offline(request_json: &str) -> PyResult<bool> {
        let req: PublishRequest = serde_json::from_str(request_json)
            .map_err(|e| PyValueError::new_err(format!("invalid request JSON: {e}")))?;
        // The offline signature check assumes the content_hash was
        // independently recomputed — do that first, over the raw wire
        // object (so unknown fields participate, mirroring the core).
        let value: serde_json::Value = serde_json::from_str(request_json)
            .map_err(|e| PyValueError::new_err(format!("invalid request JSON: {e}")))?;
        verify_content_hash(&value, &req.content_hash)
            .map_err(|e| PyRuntimeError::new_err(format!("content_hash mismatch: {e}")))?;
        verify_publish_request_signature_offline(&req)
            .map(|_| true)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Diagnose a `content_hash` mismatch by probing the known
    /// divergence patterns (`acdp_version` omitted vs explicit,
    /// null-vs-absent optionals, sub-millisecond timestamps — WS-D2).
    /// Returns a human-readable report; this is tooling for chasing
    /// "the hash that won't reproduce", never a verification verdict.
    ///
    /// * `body_json` — the body (or PublishRequest) JSON object.
    /// * `expected_hash` — the hash the counterparty computed
    ///   (`"sha256:<64-hex>"`).
    #[staticmethod]
    fn explain_hash_mismatch(body_json: &str, expected_hash: &str) -> PyResult<String> {
        let body: serde_json::Value = serde_json::from_str(body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;
        let expected = ContentHash::parse(expected_hash)
            .map_err(|e| PyValueError::new_err(format!("invalid content_hash: {e}")))?;
        explain_hash_mismatch(&body, &expected).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// The exact JCS canonical preimage hashed for `content_hash`,
    /// returned as a string (the canonical bytes are always valid UTF-8
    /// JSON). When two SDKs disagree on a hash, diff their preimages —
    /// that localizes the divergence in a way two opaque digests never
    /// can. See also [`explain_hash_mismatch`] for an automated first
    /// pass.
    ///
    /// [`explain_hash_mismatch`]: Self::explain_hash_mismatch
    #[staticmethod]
    fn canonical_preimage(body_json: &str) -> PyResult<String> {
        let body: serde_json::Value = serde_json::from_str(body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;
        let (bytes, _hash) =
            canonical_preimage(&body).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        String::from_utf8(bytes)
            .map_err(|e| PyRuntimeError::new_err(format!("canonical bytes not UTF-8: {e}")))
    }

    /// Fingerprint a raw Ed25519 public key for receipt cross-checks
    /// (ACDP 0.2, RFC-ACDP-0010):
    /// `"sha256:" + lowercase_hex(SHA-256(raw 32-byte key))`.
    ///
    /// * `public_key_b64` — standard base64 (padded) of the 32-byte raw
    ///   key, the same format as `AcdpProducer.public_key_b64`.
    #[staticmethod]
    fn fingerprint_ed25519_b64(public_key_b64: &str) -> PyResult<String> {
        let key = decode_ed25519_b64(public_key_b64)?;
        Ok(fingerprint_ed25519(&key))
    }

    /// Verify a registry receipt (ACDP 0.2, RFC-ACDP-0010): validate the
    /// canonical millisecond byte form of `created_at`, run the offline
    /// cross-checks, then verify the registry's Ed25519 signature over
    /// the preimage hash computed from the RAW wire JSON exactly as
    /// received (never a re-serialized struct — re-serialization can
    /// normalize byte details and falsely fail an honest receipt).
    ///
    /// Resolving the registry's DID document to obtain
    /// `registry_public_key_b64` stays in the host language by design
    /// (it needs HTTP) — pair `AcdpDid.web_to_url` + `httpx` +
    /// `AcdpDidDocument.key_for_algorithm`, then pass the key here.
    ///
    /// **Two RFC-ACDP-0010 checks remain the HOST's obligation** —
    /// this binding makes no HTTP calls, so it cannot perform them:
    ///
    /// 1. **Serving-authority binding** — `receipt.registry_did` MUST
    ///    equal `"did:web:" + <authority>` where `<authority>` is the
    ///    authority the response was *actually fetched from*. Compare
    ///    it against your HTTP client's request URL, not against any
    ///    field inside the response.
    /// 2. **Recompute, don't trust, the body hash** —
    ///    `recomputed_body_hash` MUST be the body hash you
    ///    independently RECOMPUTED (run `AcdpVerifier.verify_content_hash`
    ///    on the body first and pass that verified hash) — never the
    ///    body's echoed `content_hash` field taken on faith.
    ///
    /// * `receipt_json` — the `registry_receipt` object from a
    ///   `FullContext` retrieval, exactly as received on the wire.
    /// * `body_json` — the accompanying `body` object from the same
    ///   `FullContext` retrieval, used for the §8 step 3 body bindings
    ///   (`lineage_id` / `origin_registry` / `created_at`).
    /// * `registry_public_key_b64` — standard base64 of the registry's
    ///   raw 32-byte Ed25519 receipt key.
    /// * `expected_ctx_id` — the ctx_id the consumer requested.
    /// * `recomputed_body_hash` — the body hash the consumer recomputed
    ///   itself (`"sha256:<64-hex>"` — never the body's echoed field).
    /// * `producer_key_fingerprint` — fingerprint of the resolved
    ///   producer key (see `fingerprint_ed25519_b64`).
    ///
    /// Returns `True` on success. Raises `ValueError` on malformed
    /// input or `RuntimeError` (carrying the core error message) on any
    /// failed cross-check or a bad signature.
    #[staticmethod]
    fn verify_receipt(
        receipt_json: &str,
        body_json: &str,
        registry_public_key_b64: &str,
        expected_ctx_id: &str,
        recomputed_body_hash: &str,
        producer_key_fingerprint: &str,
    ) -> PyResult<bool> {
        let value: serde_json::Value = serde_json::from_str(receipt_json)
            .map_err(|e| PyValueError::new_err(format!("invalid receipt JSON: {e}")))?;
        let body: Body = serde_json::from_str(body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;
        // §8 step 6: reject non-canonical created_at byte forms before
        // anything else — a parsed struct would silently normalize them.
        RegistryReceipt::validate_created_at_form(&value)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let receipt = RegistryReceipt::from_value(&value)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let registry_key = decode_ed25519_b64(registry_public_key_b64)?;
        let recomputed = ContentHash::parse(recomputed_body_hash)
            .map_err(|e| PyValueError::new_err(format!("invalid content_hash: {e}")))?;
        let expected_ctx = CtxId::parse(expected_ctx_id)
            .map_err(|e| PyValueError::new_err(format!("invalid expected_ctx_id: {e}")))?;
        receipt
            .cross_check(&expected_ctx, &recomputed, producer_key_fingerprint)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        // §8 step 3 body bindings: lineage_id / origin_registry /
        // created_at must equal the accompanying body's fields.
        receipt
            .cross_check_body(&body)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        // Normative raw-JSON rule: hash the receipt exactly as received
        // (minus `signature`), not a re-serialization of the parsed
        // struct — mirrors the Rust client's verification path.
        let raw_hash = RegistryReceipt::preimage_hash_of_value(&value)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        receipt
            .verify_signature_against_hash(&raw_hash, Some(&registry_key), None)
            .map(|_| true)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    // ── ACDP 0.3 — lineage-head receipts (RFC-ACDP-0011) ─────────────

    /// Verify a lineage-head receipt offline per RFC-ACDP-0011 §7:
    /// closed parse, registry/lineage/head bindings, `as_of` clock
    /// skew, and the registry signature over the RAW wire preimage —
    /// against the registry key extracted from the caller-supplied DID
    /// document (RFC-ACDP-0010 §9 receipt-key lifecycle: retired keys
    /// verify with `historical: true`; fully removed keys fail closed).
    ///
    /// * `receipt_json` — the `lineage_head_receipt` object as
    ///   received on the wire.
    /// * `expected_json` — the consumer's own expectations:
    ///   `{"authority" and/or "registry_did", "lineage_id",
    ///   "head_ctx_id", "head_version", "head_status",
    ///   "on_current_endpoint"?}`. `authority` is the authority the
    ///   response was *actually fetched from* (compare your HTTP
    ///   client's URL, not any response field); `registry_did` is
    ///   `capabilities.registry_did`; either derives the other.
    ///   `on_current_endpoint` defaults to `True` (`GET /current` —
    ///   §7 step 5 byte-match); pass `False` for a full retrieval,
    ///   where the §7 step 5b stale-consistency rule applies.
    /// * `registry_did_doc_json` — the registry's resolved DID
    ///   document (resolution stays in the host: `AcdpDid.web_to_url`
    ///   + `httpx`).
    /// * `now_rfc3339` — the consumer clock (defaults to now).
    /// * `max_skew_secs` — §7 step 6 allowance (default 120).
    /// * `max_age_secs` — §6 freshness policy (default 300).
    ///
    /// Returns a JSON verdict: `{"valid": true, "stale": bool,
    /// "age_secs": int, "historical": bool}` — staleness is policy,
    /// not verification failure — or `{"valid": false, "code":
    /// "invalid_receipt"|..., "error": ...}`. Raises `ValueError` only
    /// on malformed host input.
    #[staticmethod]
    #[pyo3(signature = (receipt_json, expected_json, registry_did_doc_json, now_rfc3339=None, max_skew_secs=None, max_age_secs=None))]
    fn verify_lineage_head_receipt(
        receipt_json: &str,
        expected_json: &str,
        registry_did_doc_json: &str,
        now_rfc3339: Option<&str>,
        max_skew_secs: Option<i64>,
        max_age_secs: Option<i64>,
    ) -> PyResult<String> {
        let value = parse_json(receipt_json, "receipt")?;
        let expected = v030::parse_expected_head(expected_json).map_err(PyValueError::new_err)?;
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

    // ── ACDP 0.3 — transparency log (RFC-ACDP-0012) ──────────────────

    /// Verify a transparency-log checkpoint (signed tree head) offline
    /// per RFC-ACDP-0012 §9.3: closed parse, optional `log_id` pin
    /// (§7.4 — a new `log_id` is an explicit history reset), timestamp
    /// form + clock skew, and the registry signature over the RAW wire
    /// preimage against the receipt key from the caller-supplied DID
    /// document (retired keys verify with `historical: true`).
    ///
    /// The HOST still owns the §9.3 step 3 serving-authority half:
    /// confirm the `log_id`'s registry DID matches the authority the
    /// checkpoint was actually fetched from and
    /// `capabilities.registry_did`.
    ///
    /// Returns `{"valid": true, "log_id", "tree_size", "root_hash",
    /// "age_secs", "historical"}` (retain `tree_size`/`root_hash` for
    /// future §9.2 consistency checks) or `{"valid": false, "code":
    /// "invalid_log_proof", "error": ...}`.
    #[staticmethod]
    #[pyo3(signature = (checkpoint_json, registry_did_doc_json, expected_log_id=None, now_rfc3339=None, max_skew_secs=None))]
    fn verify_log_checkpoint(
        checkpoint_json: &str,
        registry_did_doc_json: &str,
        expected_log_id: Option<&str>,
        now_rfc3339: Option<&str>,
        max_skew_secs: Option<i64>,
    ) -> PyResult<String> {
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

    /// Verify a transparency-log inclusion proof offline —
    /// RFC-ACDP-0012 §9.1 steps 2 and 4–6: hash the RECONSTRUCTED
    /// leaf, check the proof ↔ checkpoint bindings, fold the audit
    /// path, compare against the checkpoint root.
    ///
    /// * `inclusion_json` — the proof (`log_id`, `leaf_index`,
    ///   `tree_size`, `inclusion_path`, optionally an embedded
    ///   `log_checkpoint`).
    /// * `checkpoint_json` — the checkpoint the proof verifies
    ///   against. Inserted when the proof carries none; when the proof
    ///   embeds one, the two MUST be byte-equal (a proof quietly
    ///   carrying a different checkpoint is the substitution §9.1
    ///   step 3 exists to stop). Verify its signature separately with
    ///   `verify_log_checkpoint` — the verdicts are independent.
    /// * `reconstructed_leaf_json` — the leaf built from *verified*
    ///   body + receipt material via `build_log_leaf` (§9.1 step 1).
    ///   NEVER pass a leaf echoed by the registry — the whole point is
    ///   that the verifier vouches for the leaf bytes itself.
    ///
    /// Returns `{"valid": true, "leaf_hash": "sha256:..."}` or
    /// `{"valid": false, "code": "invalid_log_proof", "error": ...}`.
    #[staticmethod]
    fn verify_log_inclusion(
        inclusion_json: &str,
        checkpoint_json: &str,
        reconstructed_leaf_json: &str,
    ) -> PyResult<String> {
        let inclusion = parse_json(inclusion_json, "inclusion")?;
        let checkpoint = parse_json(checkpoint_json, "checkpoint")?;
        let leaf = parse_json(reconstructed_leaf_json, "leaf")?;
        Ok(v030::log_inclusion_verdict(&inclusion, &checkpoint, &leaf))
    }

    /// Verify a transparency-log consistency proof offline —
    /// RFC-ACDP-0012 §9.2, the history-rewrite detector: prove the
    /// tree the verifier RETAINED a root for (`first_root_hash`, at
    /// `first_tree_size`) is a prefix of the checkpointed later tree.
    ///
    /// * `consistency_json` — the proof (`log_id`, `first_tree_size`,
    ///   `second_tree_size`, `consistency_path`, optionally an
    ///   embedded `log_checkpoint`).
    /// * `checkpoint_json` — the later checkpoint (merged/byte-checked
    ///   exactly as in `verify_log_inclusion`; verify its signature
    ///   separately with `verify_log_checkpoint`).
    /// * `first_root_hash` — the verifier's own retained root
    ///   (`"sha256:<hex>"`) — retaining it is the whole point.
    ///
    /// Returns `{"valid": true}` or `{"valid": false, "code":
    /// "invalid_log_proof", "error": ...}`. A fold failure between two
    /// signature-valid checkpoints of one `log_id` is cryptographic
    /// evidence of a logged-history rewrite — retain both checkpoints
    /// and the failing path (§9.2, §15).
    #[staticmethod]
    fn verify_log_consistency(
        consistency_json: &str,
        checkpoint_json: &str,
        first_root_hash: &str,
    ) -> PyResult<String> {
        let consistency = parse_json(consistency_json, "consistency proof")?;
        let checkpoint = parse_json(checkpoint_json, "checkpoint")?;
        Ok(v030::log_consistency_verdict(
            &consistency,
            &checkpoint,
            first_root_hash,
        ))
    }

    /// Build the canonical RFC-ACDP-0012 §4 log leaf from a VERIFIED
    /// RFC-ACDP-0010 receipt (§9.1 step 1) — every leaf field other
    /// than `receipt_hash` duplicates a receipt field, and
    /// `receipt_hash` is the receipt's §5 preimage hash, computed here
    /// over the RAW wire JSON as received. Returns the leaf as a JSON
    /// string, ready for `verify_log_inclusion` /
    /// `AcdpMerkle.leaf_hash`.
    ///
    /// Run `verify_receipt` on the receipt FIRST: a leaf reconstructed
    /// from an unverified receipt proves membership of a claim nobody
    /// has checked. Raises on a malformed receipt.
    #[staticmethod]
    fn build_log_leaf(receipt_json: &str) -> PyResult<String> {
        let value = parse_json(receipt_json, "receipt")?;
        v030::build_log_leaf_core(&value).map_err(map_acdp_error)
    }

    // ── ACDP 0.3 — lifecycle events (RFC-ACDP-0013) ──────────────────

    /// Verify one `registry_state.lifecycle_events` entry offline per
    /// RFC-ACDP-0013 §5: closed §4 parse, binding to `expected_ctx_id`
    /// (a signed event cannot be replayed against another context),
    /// the §5 actor binding (`signature.key_id` DID = `actor`), and
    /// the signature over the RAW wire preimage.
    ///
    /// * `event_json` — the event object as received.
    /// * `actor_did_doc_json` — the ACTOR's resolved DID document, or
    ///   `None` for a `did:key` actor (self-certifying — verified
    ///   natively with no document). For `did:web` actors the key must
    ///   pass the `assertionMethod` gate, like a body signature.
    /// * `expected_ctx_id` — the ctx_id of the context whose registry
    ///   state carries the event.
    ///
    /// The HOST still owns the §4/§12 authorization check that `actor`
    /// equals the context's `body.agent_id` (producer-initiated) or
    /// the registry's `capabilities.registry_did` (registry-initiated)
    /// — this binding sees neither document. Retraction state itself
    /// is derived from array order, last `retracted`/`republished`
    /// event wins; unknown event types are inert (§7.1, §7.3).
    ///
    /// Returns `{"valid": true, "event_id", "event_type", "actor"}` or
    /// `{"valid": false, "code": ..., "error": ...}` (an unsigned
    /// event fails — producer-initiated events MUST be signed).
    #[staticmethod]
    #[pyo3(signature = (event_json, actor_did_doc_json, expected_ctx_id))]
    fn verify_lifecycle_event(
        event_json: &str,
        actor_did_doc_json: Option<&str>,
        expected_ctx_id: &str,
    ) -> PyResult<String> {
        let value = parse_json(event_json, "event")?;
        Ok(v030::lifecycle_event_verdict(
            &value,
            actor_did_doc_json,
            expected_ctx_id,
        ))
    }

    // ── ACDP 0.3 — key revocation (RFC-ACDP-0014) ────────────────────

    /// Parse and shape-validate a `key-revocation` context body
    /// (RFC-ACDP-0014 §4) and derive its §5/§6 trust class. Returns
    /// the typed revocation as JSON: `{"revoked_key_fingerprint",
    /// "compromised_since", "reason"?, "revoked_key_id"?,
    /// "revoked_key_controller", "publisher", "trust_class":
    /// "producer_signed"|"registry_attested"}`. The fingerprint is
    /// authoritative; `compromised_since` is the compromise boundary T.
    /// Never collapse the two trust classes when reporting (§6).
    ///
    /// * `body_json` — the retrieved context `body` (the §5.7 layout
    ///   including registry-assigned fields).
    /// * `signer_fingerprint` — the RFC-ACDP-0010 §6 fingerprint of
    ///   the RESOLVED key that signed the body, for the §5 step 2
    ///   not-self-signed rule. For `did:key` signers the check runs
    ///   natively from the body itself; for `did:web` signers resolve
    ///   the key in the host (`AcdpDidDocument.key_for_algorithm` +
    ///   `fingerprint_ed25519_b64`) and pass its fingerprint here — a
    ///   revocation signed by the very key it revokes proves only
    ///   possession of the attacker-held key and raises.
    ///
    /// Parsing does NOT verify the body: run the ordinary hash +
    /// signature pipeline (`verify_content_hash` + `verify_signature`,
    /// or `verify_body_offline` for did:key) before trusting the
    /// result. Raises `ValueError` on §4 shape violations and
    /// `RuntimeError` on a self-signed revocation.
    #[staticmethod]
    #[pyo3(signature = (body_json, signer_fingerprint=None))]
    fn parse_key_revocation(body_json: &str, signer_fingerprint: Option<&str>) -> PyResult<String> {
        let body: Body = serde_json::from_str(body_json)
            .map_err(|e| PyValueError::new_err(format!("invalid body JSON: {e}")))?;
        v030::parse_key_revocation_core(&body, signer_fingerprint).map_err(map_acdp_error)
    }

    /// Apply the RFC-ACDP-0014 §7 compromise-boundary rule — the
    /// fail-closed classification the Rust client uses, over the
    /// earliest `compromised_since` among the supplied revocations
    /// naming the key (§4 monotonicity: a superseding revocation can
    /// widen, never quietly shrink, the window — feed the whole
    /// lineage through, superseded revocations included).
    ///
    /// * `revocations_json` — JSON array of VERIFIED revocations (the
    ///   shapes `parse_key_revocation` returns). Which trust classes
    ///   to act on is the caller's §6 policy.
    /// * `signer_fingerprint` — fingerprint of the key that signed the
    ///   context under verification.
    /// * `receipt_created_at_rfc3339` — `created_at` from a registry
    ///   receipt VERIFIED per RFC-ACDP-0010 §8, or `None` when there
    ///   is no verified receipt. NEVER the bare body `created_at` —
    ///   it is registry-assigned, producer-unsigned, and
    ///   attacker-backdatable (§7 step 1).
    ///
    /// Returns `{"authorization": "none"}` (no revocation names the
    /// key — ordinary rules apply), `{"authorization":
    /// "historically_authorized_pre_compromise", "boundary": ...}`
    /// (§7 step 2 — still verify the signature itself, under the
    /// RFC-ACDP-0010 §10 historical rule), or `{"authorization":
    /// "none", "boundary": ..., "error": ...}` — fail closed (§7
    /// steps 3–4).
    #[staticmethod]
    #[pyo3(signature = (revocations_json, signer_fingerprint, receipt_created_at_rfc3339=None))]
    fn classify_under_revocation(
        revocations_json: &str,
        signer_fingerprint: &str,
        receipt_created_at_rfc3339: Option<&str>,
    ) -> PyResult<String> {
        let revocations: Vec<KeyRevocation> = serde_json::from_str(revocations_json)
            .map_err(|e| PyValueError::new_err(format!("invalid revocations JSON (array): {e}")))?;
        let created_at = match receipt_created_at_rfc3339 {
            None => None,
            Some(raw) => Some(
                DateTime::parse_from_rfc3339(raw)
                    .map(|t| t.with_timezone(&Utc))
                    .map_err(|e| {
                        PyValueError::new_err(format!(
                            "invalid receipt_created_at_rfc3339 '{raw}': {e}"
                        ))
                    })?,
            ),
        };
        Ok(v030::classify_under_revocation_core(
            &revocations,
            signer_fingerprint,
            created_at,
        ))
    }

    // ── ACDP 0.4 — witness cosignatures (RFC-ACDP-0015) ──────────────

    /// Mint a signed transparency-log witness cosignature
    /// (RFC-ACDP-0015 §5) — the MINT surface a host-language witness
    /// service uses. The witness observes a checkpoint and cosigns it
    /// with its OWN Ed25519 key (a witness key, distinct from the
    /// registry receipt key); the returned `log_cosignature` uses the
    /// RFC-ACDP-0010 §5 construction verbatim (the witness signs the
    /// ASCII bytes of the `"sha256:<hex>"` cosignature-hash string).
    ///
    /// * `witnessed_checkpoint_json` — the identity-bearing subset of
    ///   the checkpoint the witness observed, copied verbatim from the
    ///   verified checkpoint: `{"log_id", "tree_size", "root_hash",
    ///   "timestamp"}` (closed schema — an unknown member raises).
    /// * `witness_did` — the witness's own DID (`did:web` or `did:key`).
    ///   The signing-key DID URL is derived as
    ///   `"<witness_did>#witness-key-1"` (the §5/§9 witness-key
    ///   convention).
    /// * `witness_seed_hex` — the witness Ed25519 signing seed, hex-
    ///   encoded (64 hex chars → 32 bytes). The same seed produces
    ///   byte-identical cosignatures across bindings.
    /// * `witnessed_at_rfc3339` — the witness-clock observation time
    ///   (canonical millisecond RFC 3339 UTC; truncated to ms).
    ///
    /// Returns the signed `log_cosignature` as a JSON string. This is
    /// the RAW mint (no §7 obligation — the checkpoint's own signature
    /// and consistency against a retained head are the host's job).
    /// Raises `ValueError` on malformed input (bad seed, bad
    /// timestamp, malformed witness DID / witnessed_checkpoint).
    #[staticmethod]
    fn build_witness_cosignature(
        witnessed_checkpoint_json: &str,
        witness_did: &str,
        witness_seed_hex: &str,
        witnessed_at_rfc3339: &str,
    ) -> PyResult<String> {
        let witnessed_checkpoint = parse_json(witnessed_checkpoint_json, "witnessed_checkpoint")?;
        let seed = decode_witness_seed_hex(witness_seed_hex)?;
        let witnessed_at = parse_rfc3339_required(witnessed_at_rfc3339, "witnessed_at_rfc3339")?;
        v040::build_witness_cosignature_core(
            &witnessed_checkpoint,
            witness_did,
            &seed,
            witnessed_at,
        )
        .map_err(map_acdp_error)
    }

    /// Verify one witness cosignature against a checkpoint the consumer
    /// has itself verified, offline per RFC-ACDP-0015 §8 (steps 1–5):
    /// closed parse + witness binding, checkpoint binding, the witness
    /// signature over the RAW wire preimage against the key resolved
    /// from the caller-supplied witness DID document (§9: looked up in
    /// `verificationMethod`, retired keys stay verifiable), and the
    /// `witnessed_at` well-formedness + forward-skew check.
    ///
    /// * `cosig_json` — the `log_cosignature` object as received.
    /// * `witness_did_doc_json` — the WITNESS's resolved DID document
    ///   (resolution stays in the host). Its `id` MUST equal the
    ///   cosignature's `witness_id`.
    /// * `expected_checkpoint_json` — the RFC-ACDP-0012 checkpoint the
    ///   consumer independently holds and verified; the cosignature's
    ///   `{log_id, tree_size, root_hash}` MUST match it (§8 step 4).
    /// * `now_rfc3339` — the consumer clock (defaults to now).
    /// * `max_clock_skew_secs` — §8 step 5 forward allowance
    ///   (default 120).
    ///
    /// Returns a JSON verdict: `{"valid": true, "witness_id": ...,
    /// "age_secs": int, "stale": bool}` — staleness (§8.1) is policy,
    /// not a verification failure; an old cosignature is stronger
    /// anti-backdating evidence — or `{"valid": false, "code":
    /// "invalid_witness_cosignature"|..., "error": ...}`. Raises
    /// `ValueError` only on malformed host input.
    #[staticmethod]
    #[pyo3(signature = (cosig_json, witness_did_doc_json, expected_checkpoint_json, now_rfc3339=None, max_clock_skew_secs=None))]
    fn verify_witness_cosignature(
        cosig_json: &str,
        witness_did_doc_json: &str,
        expected_checkpoint_json: &str,
        now_rfc3339: Option<&str>,
        max_clock_skew_secs: Option<i64>,
    ) -> PyResult<String> {
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
    /// cosignatures for a checkpoint the consumer has itself verified.
    /// A cosignature counts toward N iff it names a TRUSTED witness,
    /// covers the checkpoint's `(log_id, tree_size, root_hash)` tuple,
    /// and passes every §8 step; DISTINCT `witness_id` values are
    /// counted (repeats from one witness count once). A cosignature
    /// that fails a step does not fail the checkpoint — it is recorded
    /// in `failures` and simply does not count.
    ///
    /// * `cosignatures_json` — a JSON array of `log_cosignature`
    ///   objects (e.g. a checkpoint response's `witness_signatures`).
    /// * `expected_checkpoint_json` — the verified checkpoint the
    ///   quorum is over.
    /// * `trusted_witness_dids_json` — a JSON array of the witness DIDs
    ///   the consumer trusts; only these can count.
    /// * `witness_did_docs_json` — a JSON object mapping each
    ///   `witness_id` to its resolved DID document.
    /// * `policy_json` — `{"min_witnesses"?, "max_age_secs"?,
    ///   "max_clock_skew_secs"?}`. Defaults mirror the Rust
    ///   `WitnessPolicy`: `min_witnesses=1`, `max_age_secs=300` (an
    ///   explicit `null` disables the freshness split),
    ///   `max_clock_skew_secs=120`.
    /// * `now_rfc3339` — the consumer clock (defaults to now).
    ///
    /// Returns a JSON report: `{"witnessed_count", "witnesses",
    /// "meets_quorum", "fresh_witnessed_count", "meets_fresh_quorum",
    /// "failures"}`. Raises `ValueError` on malformed host input.
    #[staticmethod]
    #[pyo3(signature = (cosignatures_json, expected_checkpoint_json, trusted_witness_dids_json, witness_did_docs_json, policy_json, now_rfc3339=None))]
    fn evaluate_witness_quorum(
        cosignatures_json: &str,
        expected_checkpoint_json: &str,
        trusted_witness_dids_json: &str,
        witness_did_docs_json: &str,
        policy_json: &str,
        now_rfc3339: Option<&str>,
    ) -> PyResult<String> {
        let cosignatures: Vec<serde_json::Value> = serde_json::from_str(cosignatures_json)
            .map_err(|e| {
                PyValueError::new_err(format!("invalid cosignatures JSON (array): {e}"))
            })?;
        let checkpoint = parse_json(expected_checkpoint_json, "checkpoint")?;
        let trusted: Vec<String> =
            serde_json::from_str(trusted_witness_dids_json).map_err(|e| {
                PyValueError::new_err(format!("invalid trusted_witness_dids JSON (array): {e}"))
            })?;
        let docs_value = parse_json(witness_did_docs_json, "witness DID docs")?;
        let docs = docs_value
            .as_object()
            .ok_or_else(|| {
                PyValueError::new_err(
                    "witness_did_docs_json must be a JSON object keyed by witness_id",
                )
            })?
            .clone();
        let policy = v040::parse_witness_policy(policy_json).map_err(PyValueError::new_err)?;
        let now = parse_now(now_rfc3339)?;
        v040::evaluate_witness_quorum_report(
            &cosignatures,
            &checkpoint,
            &trusted,
            &docs,
            &policy,
            now,
        )
        .map_err(map_acdp_error)
    }
}
