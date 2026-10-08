//! `acdp-wasm` — the WebAssembly member of the ACDP binding family.
//!
//! A pure, **offline** cryptographic verifier for the browser (the
//! console) and edge hosts: it lets a consumer render an ACDP
//! context and independently reach a real verification VERDICT — the
//! producer signature, the `content_hash`, the `ctx_id` binding
//! (RFC-ACDP-0006 §4.1 step 7 — see `verifyCtxIdBinding`), a registry
//! receipt (RFC-ACDP-0010), a lineage-head receipt (RFC-ACDP-0011), a
//! transparency-log checkpoint / inclusion / consistency proof
//! (RFC-ACDP-0012), a lifecycle event (RFC-ACDP-0013), a key revocation
//! (RFC-ACDP-0014), and witness cosignatures + quorum (RFC-ACDP-0015) —
//! **without trusting any server to have done it**.
//!
//! ## Design (mirrors `bindings/acdp-py`, `bindings/acdp-node`)
//!
//! * **JSON across the boundary.** Every export takes JSON strings and
//!   returns a JSON string — a verdict object for verification outcomes,
//!   a result string for constructors/resolvers. Malformed *host* input
//!   throws a `JsError`; a failed *verification* is `{"valid": false,
//!   ...}`, never a throw.
//! * **Crypto in Rust, HTTP in the host.** No network calls. `did:web`
//!   resolution and all transport stay in JS (`fetch`); pass the fetched
//!   DID document / receipt / body JSON in. `did:key` verification is
//!   fully offline and needs no host help — the highest-value browser
//!   path.
//! * **No crypto reimplemented.** Every check delegates to the same
//!   `acdp` core the native library, Python, and Node bindings use; the
//!   0.3/0.4 verdict logic is the byte-identical shared [`v030`] /
//!   [`v040`] cores lifted verbatim from the other bindings.
//!
//! ## Randomness
//!
//! The default build is **verify-first and RNG-free at runtime**: no
//! exported verification (or the deterministic witness mint) draws
//! randomness. A getrandom *backend* is still wired at build time only
//! because the core crates pull `rand_core`/`OsRng` and `uuid` v4
//! unconditionally (see this crate's README and
//! `docs/research/wasm-target.md`); it is never invoked on the verify
//! path.

pub mod core;
mod v030;
mod v040;

use wasm_bindgen::prelude::*;

/// Map the pure core's `Result<String, String>` to the wasm ABI: `Ok`
/// passes the JSON string through; `Err` (malformed host input) becomes a
/// thrown `JsError`.
fn out(r: Result<String, String>) -> Result<String, JsError> {
    r.map_err(|e| JsError::new(&e))
}

// ── content_hash + producer signature (the full-context path) ────────

/// Recompute `content_hash` over the body and compare to `expectedHash`.
/// Returns a verdict JSON string. Throws on malformed input.
#[wasm_bindgen(js_name = verifyContentHash)]
pub fn verify_content_hash(body_json: &str, expected_hash: &str) -> Result<String, JsError> {
    out(core::verify_content_hash_json(body_json, expected_hash))
}

/// Verify that a body's *served* `ctx_id` matches the `ctx_id` the
/// caller *expected* (RFC-ACDP-0006 §4.1 step 7, NORMATIVE). Argument
/// order is `(bodyJson, expectedCtxId)`: the body's own `ctx_id` is the
/// *served* identity, `expectedCtxId` is what the caller requested.
/// Returns a verdict for the served side (a malformed served `ctx_id`,
/// or a served/expected mismatch, is a fail verdict). Throws on
/// malformed body JSON or a malformed `expectedCtxId` — that value is
/// host input, mirroring `verifyContentHash`'s `expectedHash`.
#[wasm_bindgen(js_name = verifyCtxIdBinding)]
pub fn verify_ctx_id_binding(body_json: &str, expected_ctx_id: &str) -> Result<String, JsError> {
    out(core::verify_ctx_id_binding_json(body_json, expected_ctx_id))
}

/// Verify an Ed25519 signature over the ASCII `"sha256:<hex>"` string.
/// `pubKeyB64` is the raw 32-byte key, base64. Returns a verdict.
#[wasm_bindgen(js_name = verifySignatureEd25519)]
pub fn verify_signature_ed25519(
    pub_key_b64: &str,
    sig_b64: &str,
    content_hash: &str,
) -> Result<String, JsError> {
    out(core::verify_signature_ed25519(
        pub_key_b64,
        sig_b64,
        content_hash,
    ))
}

/// Verify an ECDSA-P256 signature (IEEE-1363 `r‖s`, base64) over the
/// ASCII `"sha256:<hex>"` string. `pubKeySec1B64` is the 65-byte
/// SEC1-uncompressed key, base64. Returns a verdict.
#[wasm_bindgen(js_name = verifySignatureP256)]
pub fn verify_signature_p256(
    pub_key_sec1_b64: &str,
    sig_b64: &str,
    content_hash: &str,
) -> Result<String, JsError> {
    out(core::verify_signature_p256(
        pub_key_sec1_b64,
        sig_b64,
        content_hash,
    ))
}

/// Fully verify a `did:key` body offline (ACDP 0.2). Returns a verdict.
#[wasm_bindgen(js_name = verifyBodyOffline)]
pub fn verify_body_offline(body_json: &str) -> Result<String, JsError> {
    out(core::verify_body_offline_json(body_json))
}

/// Fully verify a `did:key` PublishRequest offline (ACDP 0.2). Returns a
/// verdict.
#[wasm_bindgen(js_name = verifyPublishRequestOffline)]
pub fn verify_publish_request_offline(request_json: &str) -> Result<String, JsError> {
    out(core::verify_publish_request_offline_json(request_json))
}

// ── diagnostics ──────────────────────────────────────────────────────

/// The exact JCS canonical preimage hashed for `content_hash`.
#[wasm_bindgen(js_name = canonicalPreimage)]
pub fn canonical_preimage(body_json: &str) -> Result<String, JsError> {
    out(core::canonical_preimage_json(body_json))
}

/// Diagnose a `content_hash` mismatch (human-readable, never a verdict).
#[wasm_bindgen(js_name = explainHashMismatch)]
pub fn explain_hash_mismatch(body_json: &str, expected_hash: &str) -> Result<String, JsError> {
    out(core::explain_hash_mismatch_json(body_json, expected_hash))
}

// ── registry receipts (RFC-ACDP-0010) ────────────────────────────────

/// `"sha256:" + hex(SHA-256(raw 32-byte key))`.
#[wasm_bindgen(js_name = fingerprintEd25519)]
pub fn fingerprint_ed25519(public_key_b64: &str) -> Result<String, JsError> {
    out(core::fingerprint_ed25519_b64(public_key_b64))
}

/// Verify a registry receipt (RFC-ACDP-0010) against the consumer's own
/// recomputed body hash / expected ctx_id / producer key fingerprint,
/// and bind it to the accompanying `body_json` (§8 step 3). Returns a
/// verdict.
#[wasm_bindgen(js_name = verifyReceipt)]
pub fn verify_receipt(
    receipt_json: &str,
    body_json: &str,
    registry_public_key_b64: &str,
    expected_ctx_id: &str,
    recomputed_body_hash: &str,
    producer_key_fingerprint: &str,
) -> Result<String, JsError> {
    out(core::verify_receipt_json(
        receipt_json,
        body_json,
        registry_public_key_b64,
        expected_ctx_id,
        recomputed_body_hash,
        producer_key_fingerprint,
    ))
}

// ── lineage-head receipts (RFC-ACDP-0011) ─────────────────────────────

/// Verify a lineage-head receipt offline (RFC-ACDP-0011 §7). Returns a
/// verdict.
#[wasm_bindgen(js_name = verifyLineageHeadReceipt)]
pub fn verify_lineage_head_receipt(
    receipt_json: &str,
    expected_json: &str,
    registry_did_doc_json: &str,
    now_rfc3339: Option<String>,
    max_skew_secs: Option<i64>,
    max_age_secs: Option<i64>,
) -> Result<String, JsError> {
    out(core::verify_lineage_head_receipt_json(
        receipt_json,
        expected_json,
        registry_did_doc_json,
        now_rfc3339.as_deref(),
        max_skew_secs,
        max_age_secs,
    ))
}

// ── transparency log (RFC-ACDP-0012) ─────────────────────────────────

/// Verify a transparency-log checkpoint offline (RFC-ACDP-0012 §9.3).
#[wasm_bindgen(js_name = verifyLogCheckpoint)]
pub fn verify_log_checkpoint(
    checkpoint_json: &str,
    registry_did_doc_json: &str,
    expected_log_id: Option<String>,
    now_rfc3339: Option<String>,
    max_skew_secs: Option<i64>,
) -> Result<String, JsError> {
    out(core::verify_log_checkpoint_json(
        checkpoint_json,
        registry_did_doc_json,
        expected_log_id.as_deref(),
        now_rfc3339.as_deref(),
        max_skew_secs,
    ))
}

/// Verify a transparency-log inclusion proof offline (RFC-ACDP-0012
/// §9.1).
#[wasm_bindgen(js_name = verifyLogInclusion)]
pub fn verify_log_inclusion(
    inclusion_json: &str,
    checkpoint_json: &str,
    reconstructed_leaf_json: &str,
) -> Result<String, JsError> {
    out(core::verify_log_inclusion_json(
        inclusion_json,
        checkpoint_json,
        reconstructed_leaf_json,
    ))
}

/// Verify a transparency-log consistency proof offline (RFC-ACDP-0012
/// §9.2).
#[wasm_bindgen(js_name = verifyLogConsistency)]
pub fn verify_log_consistency(
    consistency_json: &str,
    checkpoint_json: &str,
    first_root_hash: &str,
) -> Result<String, JsError> {
    out(core::verify_log_consistency_json(
        consistency_json,
        checkpoint_json,
        first_root_hash,
    ))
}

/// Build the canonical §4 log leaf from a VERIFIED receipt (§9.1 step 1).
#[wasm_bindgen(js_name = buildLogLeaf)]
pub fn build_log_leaf(receipt_json: &str) -> Result<String, JsError> {
    out(core::build_log_leaf_json(receipt_json))
}

/// §5.1 leaf hash `SHA-256(0x00 ‖ JCS(leaf))`.
#[wasm_bindgen(js_name = merkleLeafHash)]
pub fn merkle_leaf_hash(leaf_json: &str) -> Result<String, JsError> {
    out(core::merkle_leaf_hash_json(leaf_json))
}

/// §5.1 interior-node hash `SHA-256(0x01 ‖ left ‖ right)`.
#[wasm_bindgen(js_name = merkleNodeHash)]
pub fn merkle_node_hash(left_hash: &str, right_hash: &str) -> Result<String, JsError> {
    out(core::merkle_node_hash_str(left_hash, right_hash))
}

/// §5.2 RFC 6962 Merkle tree hash over an ordered array of leaf hashes.
#[wasm_bindgen(js_name = merkleRootHash)]
pub fn merkle_root_hash(leaf_hashes_json: &str) -> Result<String, JsError> {
    out(core::merkle_root_hash_json(leaf_hashes_json))
}

// ── lifecycle events (RFC-ACDP-0013) ─────────────────────────────────

/// Verify one lifecycle event offline (RFC-ACDP-0013 §5).
/// `actorDidDocJson` is `null`/`undefined` for a `did:key` actor.
#[wasm_bindgen(js_name = verifyLifecycleEvent)]
pub fn verify_lifecycle_event(
    event_json: &str,
    actor_did_doc_json: Option<String>,
    expected_ctx_id: &str,
) -> Result<String, JsError> {
    out(core::verify_lifecycle_event_json(
        event_json,
        actor_did_doc_json.as_deref(),
        expected_ctx_id,
    ))
}

// ── key revocation (RFC-ACDP-0014) ───────────────────────────────────

/// Parse + shape-validate a `key-revocation` body (RFC-ACDP-0014 §4).
#[wasm_bindgen(js_name = parseKeyRevocation)]
pub fn parse_key_revocation(
    body_json: &str,
    signer_fingerprint: Option<String>,
) -> Result<String, JsError> {
    out(core::parse_key_revocation_json(
        body_json,
        signer_fingerprint.as_deref(),
    ))
}

/// Apply the RFC-ACDP-0014 §7 compromise-boundary rule (fail-closed).
#[wasm_bindgen(js_name = classifyUnderRevocation)]
pub fn classify_under_revocation(
    revocations_json: &str,
    signer_fingerprint: &str,
    receipt_created_at_rfc3339: Option<String>,
) -> Result<String, JsError> {
    out(core::classify_under_revocation_json(
        revocations_json,
        signer_fingerprint,
        receipt_created_at_rfc3339.as_deref(),
    ))
}

// ── witness cosignatures (RFC-ACDP-0015) ─────────────────────────────

/// Mint a signed witness cosignature (RFC-ACDP-0015 §5). Deterministic.
#[wasm_bindgen(js_name = buildWitnessCosignature)]
pub fn build_witness_cosignature(
    witnessed_checkpoint_json: &str,
    witness_did: &str,
    witness_seed_hex: &str,
    witnessed_at_rfc3339: &str,
) -> Result<String, JsError> {
    out(core::build_witness_cosignature_json(
        witnessed_checkpoint_json,
        witness_did,
        witness_seed_hex,
        witnessed_at_rfc3339,
    ))
}

/// Verify one witness cosignature offline (RFC-ACDP-0015 §8). Returns a
/// verdict.
#[wasm_bindgen(js_name = verifyWitnessCosignature)]
pub fn verify_witness_cosignature(
    cosig_json: &str,
    witness_did_doc_json: &str,
    expected_checkpoint_json: &str,
    now_rfc3339: Option<String>,
    max_clock_skew_secs: Option<i64>,
) -> Result<String, JsError> {
    out(core::verify_witness_cosignature_json(
        cosig_json,
        witness_did_doc_json,
        expected_checkpoint_json,
        now_rfc3339.as_deref(),
        max_clock_skew_secs,
    ))
}

/// Compute the RFC-ACDP-0015 §8 N-witnessed quorum report. Returns a
/// report JSON.
#[wasm_bindgen(js_name = evaluateWitnessQuorum)]
pub fn evaluate_witness_quorum(
    cosignatures_json: &str,
    expected_checkpoint_json: &str,
    trusted_witness_dids_json: &str,
    witness_did_docs_json: &str,
    policy_json: &str,
    now_rfc3339: Option<String>,
) -> Result<String, JsError> {
    out(core::evaluate_witness_quorum_json(
        cosignatures_json,
        expected_checkpoint_json,
        trusted_witness_dids_json,
        witness_did_docs_json,
        policy_json,
        now_rfc3339.as_deref(),
    ))
}

// ── did:key resolution (offline) ─────────────────────────────────────

/// Resolve a `did:key:z…` DID to its public key material — offline.
#[wasm_bindgen(js_name = resolveDidKey)]
pub fn resolve_did_key(did: &str) -> Result<String, JsError> {
    out(core::resolve_did_key_json(did))
}
