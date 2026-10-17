//! Pure-Rust core of the ACDP 0.3.0 binding surface — transparency-log
//! verification (RFC-ACDP-0012), lineage-head receipts (RFC-ACDP-0011),
//! lifecycle events (RFC-ACDP-0013), and key revocation
//! (RFC-ACDP-0014).
//!
//! This module is FFI-framework-free and byte-identical between the
//! Python (PyO3) and Node (NAPI-rs) bindings: all inputs are parsed
//! `serde_json::Value`s / plain strings, all outputs are JSON strings.
//! The thin per-framework wrappers in `verifier.rs` / `merkle.rs` only
//! parse argument strings and map raised errors — keeping the
//! protocol-critical logic in exactly one shape per binding, wrapping
//! the same `acdp` core types.
//!
//! ## Verdict convention
//!
//! The `*_verdict` functions never fail for a *verification* reason —
//! they return a JSON verdict string:
//!
//! * success: `{"valid": true, ...}` (plus documented extras such as
//!   `stale`, `age_secs`, `historical`);
//! * failure: `{"valid": false, "code": "<wire-code>", "error": "..."}`
//!   where `code` is the RFC-ACDP-0007 §5 wire-code taxonomy
//!   (`invalid_receipt`, `invalid_log_proof`, ...).
//!
//! Only malformed *host input* (an argument that is not JSON at all, a
//! missing required expected-field) is raised by the wrappers.

use acdp::did::DidDocument;
use acdp::error::AcdpError;
use acdp::types::lifecycle::LifecycleEvent;
use acdp::types::log::{
    decode_sha256_hex, encode_sha256_hex, LogCheckpoint, LogConsistencyProof, LogInclusion,
    LogLeaf, LOG_LEAF_VERSION,
};
use acdp::types::receipt::LineageHeadReceipt;
use acdp::types::revocation::{effective_boundary, KeyRevocation, RevocationTrustClass};
use acdp::types::{CtxId, LineageId, RegistryReceipt, Status};
use chrono::{DateTime, Duration, Utc};

/// RFC-ACDP-0011 §7 step 6 / RFC-ACDP-0012 §9.3 step 4 RECOMMENDED
/// clock-skew allowance.
pub(crate) const DEFAULT_MAX_SKEW_SECS: i64 = 120;
/// RFC-ACDP-0011 §6 / RFC-ACDP-0012 §7.2 RECOMMENDED freshness maximum.
pub(crate) const DEFAULT_MAX_AGE_SECS: i64 = 300;

const MS_FMT: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";

/// The wire-code taxonomy string for an [`AcdpError`], used in failure
/// verdicts so hosts can branch without parsing messages.
fn error_code(e: &AcdpError) -> &'static str {
    match e {
        AcdpError::InvalidReceipt(_) => "invalid_receipt",
        AcdpError::InvalidLogProof(_) => "invalid_log_proof",
        AcdpError::ImmutableField(_) => "immutable_field",
        AcdpError::InvalidLifecycleTransition(_) => "invalid_lifecycle_transition",
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

fn failure(e: &AcdpError) -> String {
    serde_json::json!({
        "valid": false,
        "code": error_code(e),
        "error": e.to_string(),
    })
    .to_string()
}

// ── DID-document key extraction (offline receipt/actor keys) ────────────────

pub(crate) struct ResolvedDocKey {
    pub ed25519: Option<[u8; 32]>,
    pub p256_sec1: Option<Vec<u8>>,
    /// `true` when the key is retained in `verificationMethod` but no
    /// longer referenced by `assertionMethod` (RFC-ACDP-0010 §9).
    pub historical: bool,
}

/// Resolve `key_id` from a caller-supplied DID document, offline.
///
/// * `require_assertion = false` — the RFC-ACDP-0010 §9 receipt-key
///   lifecycle: retired receipt keys stay verifiable (`historical`),
///   full removal from `verificationMethod` fails closed. Used for
///   registry receipt/checkpoint keys.
/// * `require_assertion = true` — the producer/actor gate: the key
///   must be in `assertionMethod` (RFC-ACDP-0001 §5.11). Used for
///   lifecycle-event actor keys.
///
/// Always applies the algorithm-downgrade defense (RFC-ACDP-0008 §3.9).
pub(crate) fn doc_key_for(
    doc_json: &str,
    expected_did: &str,
    key_id: &str,
    algorithm: &str,
    require_assertion: bool,
) -> Result<ResolvedDocKey, AcdpError> {
    let doc: DidDocument = serde_json::from_str(doc_json)
        .map_err(|e| AcdpError::KeyResolution(format!("DID document parse: {e}")))?;
    if doc.id != expected_did {
        return Err(AcdpError::KeyResolution(format!(
            "DID document id '{}' ≠ expected DID '{expected_did}'",
            doc.id
        )));
    }
    let fragment = key_id
        .rsplit_once('#')
        .map(|(_, f)| f)
        .filter(|f| !f.is_empty())
        .ok_or_else(|| {
            AcdpError::KeyResolution(format!("signature key_id '{key_id}' has no fragment"))
        })?;
    let vm = doc.find_by_fragment(fragment).ok_or_else(|| {
        AcdpError::KeyResolution(format!(
            "DID document has no verificationMethod '#{fragment}' — retired receipt keys \
             must remain in verificationMethod indefinitely (RFC-ACDP-0010 §9); full \
             removal is the compromise-revocation signal, fail closed"
        ))
    })?;
    if let Some(declared) = vm.declared_algorithm() {
        if declared != algorithm {
            return Err(AcdpError::UnsupportedAlgorithm(format!(
                "signature declares '{algorithm}' but verificationMethod '{}' is '{declared}' \
                 (RFC-ACDP-0008 §3.9 algorithm-downgrade defense)",
                vm.id
            )));
        }
    }
    let historical = !doc.is_assertion_method(key_id);
    if require_assertion && historical {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "verificationMethod '{key_id}' is not referenced by assertionMethod \
             (RFC-ACDP-0001 §5.11)"
        )));
    }
    match algorithm {
        "ed25519" => Ok(ResolvedDocKey {
            ed25519: Some(
                vm.ed25519_public_key_bytes()
                    .map_err(|e| AcdpError::KeyResolution(format!("key extraction: {e}")))?,
            ),
            p256_sec1: None,
            historical,
        }),
        "ecdsa-p256" => Ok(ResolvedDocKey {
            ed25519: None,
            p256_sec1: Some(
                vm.ecdsa_p256_public_key_sec1()
                    .map_err(|e| AcdpError::KeyResolution(format!("key extraction: {e}")))?,
            ),
            historical,
        }),
        other => Err(AcdpError::UnsupportedAlgorithm(format!(
            "unsupported signature algorithm '{other}'"
        ))),
    }
}

// ── Lineage-head receipts (RFC-ACDP-0011) ───────────────────────────────────

/// The consumer-side expectations a head receipt is verified against
/// (RFC-ACDP-0011 §7 steps 3–5). Parsed from the host's `expected`
/// JSON object.
pub(crate) struct ExpectedHead {
    pub authority: String,
    pub registry_did: String,
    pub lineage_id: LineageId,
    pub head_ctx_id: CtxId,
    pub head_version: u32,
    pub head_status: Status,
    pub on_current_endpoint: bool,
}

/// Parse the `expected` object. Errors here are HOST-input problems
/// (the caller knows its own request) and are raised by the wrappers,
/// not folded into the verdict.
pub(crate) fn parse_expected_head(json: &str) -> Result<ExpectedHead, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid expected JSON: {e}"))?;
    let obj = value.as_object().ok_or("expected must be a JSON object")?;
    let get_str = |key: &str| obj.get(key).and_then(|v| v.as_str()).map(str::to_owned);

    // Serving authority and capabilities registry_did: either may be
    // given; each derives the other (did:web:<authority> ⇄ authority).
    let (authority, registry_did) = match (get_str("authority"), get_str("registry_did")) {
        (Some(a), Some(d)) => (a, d),
        (Some(a), None) => {
            let d = acdp::did::authority_to_did_web(&a);
            (a, d)
        }
        (None, Some(d)) => {
            let a = acdp::did::did_web_to_authority(&d)
                .ok_or_else(|| format!("expected.registry_did '{d}' is not a did:web DID"))?;
            (a, d)
        }
        (None, None) => {
            return Err(
                "expected must carry 'authority' (the serving authority the response was \
                 fetched from) and/or 'registry_did' (capabilities.registry_did)"
                    .into(),
            );
        }
    };

    let lineage_id =
        LineageId::parse(get_str("lineage_id").ok_or("expected.lineage_id is required")?)
            .map_err(|e| format!("expected.lineage_id: {e}"))?;
    let head_ctx_id =
        CtxId::parse(get_str("head_ctx_id").ok_or("expected.head_ctx_id is required")?)
            .map_err(|e| format!("expected.head_ctx_id: {e}"))?;
    let head_version = obj
        .get("head_version")
        .and_then(|v| v.as_u64())
        .filter(|v| *v <= u64::from(u32::MAX))
        .ok_or("expected.head_version is required and must be an unsigned integer")?
        as u32;
    let head_status =
        Status::parse(&get_str("head_status").ok_or("expected.head_status is required")?)
            .map_err(|e| format!("expected.head_status: {e}"))?;
    let on_current_endpoint = obj
        .get("on_current_endpoint")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    Ok(ExpectedHead {
        authority,
        registry_did,
        lineage_id,
        head_ctx_id,
        head_version,
        head_status,
        on_current_endpoint,
    })
}

/// RFC-ACDP-0011 §7 verification of a lineage-head receipt, offline:
/// step 1 closed parse, step 2 signature over the RAW wire preimage
/// against the registry key from the caller-supplied DID document
/// (receipt-key lifecycle, RFC-ACDP-0010 §9), step 3 registry binding,
/// step 4 lineage binding, step 5/5b head binding, step 6 `as_of`
/// clock-skew. Staleness (§6) is reported separately in the verdict —
/// an old-but-honest receipt is `valid: true, stale: true`.
pub(crate) fn lineage_head_receipt_verdict(
    value: &serde_json::Value,
    expected: &ExpectedHead,
    registry_did_doc_json: &str,
    now: DateTime<Utc>,
    max_skew_secs: i64,
    max_age_secs: i64,
) -> String {
    let run = || -> Result<(LineageHeadReceipt, bool), AcdpError> {
        // §7 step 1: closed parse + §4 semantic invariants + raw as_of
        // byte form.
        let receipt = LineageHeadReceipt::from_value(value)?;
        // §7 step 3: serving-authority + capabilities + key_id + single-
        // registry bindings (pure).
        receipt.cross_check_registry_binding(&expected.authority, &expected.registry_did)?;
        // §7 step 4: requested-lineage binding.
        receipt.cross_check_lineage(&expected.lineage_id)?;
        // §7 step 5 / 5b: head binding against the served response.
        receipt.cross_check_head(
            &expected.head_ctx_id,
            expected.head_version,
            &expected.head_status,
            expected.on_current_endpoint,
        )?;
        // §7 step 6: as_of form + clock skew (forged-freshness defense).
        receipt.check_as_of_skew(now, Duration::seconds(max_skew_secs))?;
        // §7 step 2: signature over the preimage hash of the RAW wire
        // JSON (never a re-serialization), registry key per the
        // RFC-ACDP-0010 §9 receipt-key lifecycle.
        let key = doc_key_for(
            registry_did_doc_json,
            &receipt.registry_did,
            &receipt.signature.key_id,
            &receipt.signature.algorithm,
            false,
        )?;
        let hash = LineageHeadReceipt::preimage_hash_of_value(value)?;
        receipt.verify_signature_against_hash(
            &hash,
            key.ed25519.as_ref(),
            key.p256_sec1.as_deref(),
        )?;
        Ok((receipt, key.historical))
    };
    match run() {
        Ok((receipt, historical)) => {
            let age_secs = receipt.age_at(now).num_seconds();
            serde_json::json!({
                "valid": true,
                "stale": age_secs > max_age_secs,
                "age_secs": age_secs,
                "historical": historical,
            })
            .to_string()
        }
        Err(e) => failure(&e),
    }
}

// ── Transparency log (RFC-ACDP-0012) ────────────────────────────────────────

/// RFC-ACDP-0012 §9.3 checkpoint verification, offline: step 1 closed
/// parse (+ optional `expected_log_id` pin, §7.4), step 2 signature
/// over the RAW wire preimage against the registry receipt key from
/// the caller-supplied DID document, step 4 timestamp form + skew.
///
/// The §9.3 step 3 serving-authority half is implicit: the checkpoint's
/// `log_id` embeds the registry DID, `signature.key_id` is checked to
/// live under it at parse time, and the DID document's `id` must equal
/// it — the HOST still owns confirming that DID matches the authority
/// it actually fetched from and `capabilities.registry_did`.
pub(crate) fn log_checkpoint_verdict(
    value: &serde_json::Value,
    registry_did_doc_json: &str,
    expected_log_id: Option<&str>,
    now: DateTime<Utc>,
    max_skew_secs: i64,
) -> String {
    let run = || -> Result<(LogCheckpoint, bool), AcdpError> {
        let checkpoint = LogCheckpoint::from_value(value)?;
        if let Some(expected) = expected_log_id {
            if checkpoint.log_id != expected {
                return Err(AcdpError::InvalidLogProof(format!(
                    "log_checkpoint log_id '{}' ≠ expected '{expected}' — a new log_id is an \
                     explicit, detectable history reset (RFC-ACDP-0012 §7.4)",
                    checkpoint.log_id
                )));
            }
        }
        let registry_did = checkpoint.registry_did()?.to_string();
        checkpoint.check_timestamp_skew(now, Duration::seconds(max_skew_secs))?;
        let key = doc_key_for(
            registry_did_doc_json,
            &registry_did,
            &checkpoint.signature.key_id,
            &checkpoint.signature.algorithm,
            false,
        )?;
        let hash = LogCheckpoint::preimage_hash_of_value(value)?;
        checkpoint.verify_signature_against_hash(
            &hash,
            key.ed25519.as_ref(),
            key.p256_sec1.as_deref(),
        )?;
        Ok((checkpoint, key.historical))
    };
    match run() {
        Ok((checkpoint, historical)) => serde_json::json!({
            "valid": true,
            "log_id": checkpoint.log_id,
            "tree_size": checkpoint.tree_size,
            "root_hash": checkpoint.root_hash,
            "age_secs": checkpoint.age_at(now).num_seconds(),
            "historical": historical,
        })
        .to_string(),
        Err(e) => failure(&e),
    }
}

/// Insert `checkpoint` as the proof's `log_checkpoint` member when the
/// proof was served without one (the `GET /log/proof` response shape);
/// when both are present they must be byte-equal — a proof quietly
/// carrying a *different* checkpoint than the one the caller verified
/// is exactly the substitution §9.1 step 3 exists to stop.
fn with_checkpoint(
    proof: &serde_json::Value,
    checkpoint: &serde_json::Value,
    what: &str,
) -> Result<serde_json::Value, AcdpError> {
    let mut merged = proof.clone();
    let obj = merged
        .as_object_mut()
        .ok_or_else(|| AcdpError::InvalidLogProof(format!("{what} must be a JSON object")))?;
    match obj.get("log_checkpoint") {
        None => {
            obj.insert("log_checkpoint".into(), checkpoint.clone());
        }
        Some(embedded) if embedded != checkpoint => {
            return Err(AcdpError::InvalidLogProof(format!(
                "{what} embeds a log_checkpoint that differs from the supplied (verified) \
                 checkpoint (RFC-ACDP-0012 §9.1 step 3)"
            )));
        }
        Some(_) => {}
    }
    Ok(merged)
}

/// RFC-ACDP-0012 §9.1 steps 2 + 4–6, offline: hash the *reconstructed*
/// leaf (never an echoed one — build it with `build_log_leaf` from
/// verified body + receipt material, §9.1 step 1), check the proof ↔
/// checkpoint bindings, fold the audit path, compare against the
/// checkpoint's root. The checkpoint's own signature (§9.3, step 3
/// here) is verified separately via `verify_log_checkpoint` — the two
/// verdicts are independent.
pub(crate) fn log_inclusion_verdict(
    inclusion: &serde_json::Value,
    checkpoint: &serde_json::Value,
    leaf: &serde_json::Value,
) -> String {
    let run = || -> Result<String, AcdpError> {
        let merged = with_checkpoint(inclusion, checkpoint, "log_inclusion")?;
        let inclusion = LogInclusion::from_value(&merged)?;
        let leaf = LogLeaf::from_value(leaf)?;
        inclusion.verify_reconstructed_leaf(&leaf)?;
        leaf.leaf_hash_hex()
    };
    match run() {
        Ok(leaf_hash) => serde_json::json!({"valid": true, "leaf_hash": leaf_hash}).to_string(),
        Err(e) => failure(&e),
    }
}

/// RFC-ACDP-0012 §9.2, offline: verify a consistency proof between the
/// verifier's *retained* earlier root (`first_root_hash`) and the
/// supplied later checkpoint. The checkpoint's signature (§9.3) is
/// verified separately via `verify_log_checkpoint`.
///
/// A `valid: false` fold failure between two signature-valid
/// checkpoints of one `log_id` is cryptographic evidence that the
/// registry rewrote logged history — retain both checkpoints and the
/// failing path (RFC-ACDP-0012 §9.2, §15).
pub(crate) fn log_consistency_verdict(
    consistency: &serde_json::Value,
    checkpoint: &serde_json::Value,
    first_root_hash: &str,
) -> String {
    let run = || -> Result<(), AcdpError> {
        let merged = with_checkpoint(consistency, checkpoint, "consistency proof")?;
        let proof = LogConsistencyProof::from_value(&merged)?;
        proof.verify_against_first_root(first_root_hash)
    };
    match run() {
        Ok(()) => serde_json::json!({"valid": true}).to_string(),
        Err(e) => failure(&e),
    }
}

/// Build the canonical RFC-ACDP-0012 §4 log leaf from a **verified**
/// RFC-ACDP-0010 receipt (§9.1 step 1) — every leaf field other than
/// `receipt_hash` duplicates a receipt field, and `receipt_hash` is
/// the §5 preimage hash of the receipt itself, computed here over the
/// RAW wire JSON. Returns the leaf as a JSON string.
///
/// The caller MUST have verified the receipt first (`verify_receipt`):
/// a leaf reconstructed from an unverified receipt proves membership
/// of a claim nobody has checked.
pub(crate) fn build_log_leaf_core(value: &serde_json::Value) -> Result<String, AcdpError> {
    RegistryReceipt::validate_created_at_form(value)?;
    let receipt = RegistryReceipt::from_value(value)?;
    let receipt_hash = RegistryReceipt::preimage_hash_of_value(value)?;
    let leaf = LogLeaf {
        leaf_version: LOG_LEAF_VERSION.to_string(),
        ctx_id: receipt.ctx_id.clone(),
        lineage_id: receipt.lineage_id.clone(),
        origin_registry: receipt.origin_registry.clone(),
        created_at: receipt.created_at,
        content_hash: receipt.content_hash.clone(),
        key_fingerprint: receipt.key_fingerprint.clone(),
        receipt_hash: receipt_hash.as_str().to_string(),
    };
    serde_json::to_string(&leaf).map_err(AcdpError::from)
}

// ── Merkle arithmetic (RFC-ACDP-0012 §5) ────────────────────────────────────

/// §5.1 leaf hash of a closed leaf object: `SHA-256(0x00 ‖ JCS(leaf))`,
/// wire form. The leaf is shape-validated first — hashing a malformed
/// leaf would mint a digest of bytes no conformant log ever committed.
pub(crate) fn merkle_leaf_hash(leaf: &serde_json::Value) -> Result<String, AcdpError> {
    LogLeaf::from_value(leaf)?.leaf_hash_hex()
}

/// §5.1 interior-node hash: `SHA-256(0x01 ‖ left ‖ right)` over the raw
/// digests the two wire-form (`"sha256:<hex>"`) arguments encode.
pub(crate) fn merkle_node_hash(left: &str, right: &str) -> Result<String, AcdpError> {
    let left = decode_sha256_hex(left)?;
    let right = decode_sha256_hex(right)?;
    Ok(encode_sha256_hex(&acdp::crypto::merkle::node_hash(
        &left, &right,
    )))
}

/// §5.2 RFC 6962 Merkle tree hash `MTH(D[n])` over an ordered list of
/// wire-form leaf hashes; the empty list yields `SHA-256("")`.
pub(crate) fn merkle_root_hash(leaf_hashes: &[String]) -> Result<String, AcdpError> {
    let hashes = leaf_hashes
        .iter()
        .map(|h| decode_sha256_hex(h))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(encode_sha256_hex(&acdp::crypto::merkle_tree_hash(&hashes)))
}

// ── Lifecycle events (RFC-ACDP-0013) ────────────────────────────────────────

/// RFC-ACDP-0013 §5 verification of one lifecycle event, offline:
/// closed §4 parse, `ctx_id` binding to the context the caller is
/// evaluating, the §5 actor binding (`signature.key_id` DID = `actor`),
/// and the signature over the RAW wire preimage. `did:key` actors
/// verify natively; `did:web` actors verify against the caller-supplied
/// actor DID document with the `assertionMethod` gate — the same
/// envelope rules as a body signature.
///
/// The HOST still owns the §4/§12 authorization check that `actor` is
/// either the context's `body.agent_id` or the serving registry's
/// `capabilities.registry_did` — this binding sees neither.
pub(crate) fn lifecycle_event_verdict(
    value: &serde_json::Value,
    actor_did_doc_json: Option<&str>,
    expected_ctx_id: &str,
) -> String {
    let run = || -> Result<LifecycleEvent, AcdpError> {
        let event = LifecycleEvent::from_value(value)?;
        if event.ctx_id.as_str() != expected_ctx_id {
            return Err(AcdpError::SchemaViolation(format!(
                "lifecycle event ctx_id '{}' ≠ expected ctx_id '{expected_ctx_id}' \
                 (RFC-ACDP-0013 §4: a signed event binds to exactly one context and \
                 cannot be replayed against another)",
                event.ctx_id
            )));
        }
        let signature = event.actor_bound_signature()?.clone();
        // Raw-JSON rule: hash the event exactly as received.
        let hash = LifecycleEvent::preimage_hash_of_value(value)?;
        if event.actor.as_str().starts_with("did:key:") {
            // Self-certifying actor: key material comes from the DID
            // itself — no document, no network.
            acdp::crypto::verify_did_key_envelope(&signature, &hash)?;
        } else {
            let doc_json = actor_did_doc_json.ok_or_else(|| {
                AcdpError::KeyResolution(format!(
                    "actor '{}' is not did:key — supply the actor's resolved DID document \
                     (actor_did_doc_json); DID resolution stays in the host language",
                    event.actor
                ))
            })?;
            let key = doc_key_for(
                doc_json,
                event.actor.as_str(),
                &signature.key_id,
                &signature.algorithm,
                true,
            )?;
            event.verify_signature_against_hash(
                &hash,
                key.ed25519.as_ref(),
                key.p256_sec1.as_deref(),
            )?;
        }
        Ok(event)
    };
    match run() {
        Ok(event) => serde_json::json!({
            "valid": true,
            "event_id": event.event_id,
            "event_type": event.event_type.as_str(),
            "actor": event.actor.as_str(),
        })
        .to_string(),
        Err(e) => failure(&e),
    }
}

// ── Key revocation (RFC-ACDP-0014) ──────────────────────────────────────────

/// Parse + shape-validate a `key-revocation` context body (§4) and
/// derive its §5/§6 trust class; returns the typed revocation as a
/// JSON string. Enforces the §5 step 2 not-self-signed rule natively
/// for `did:key` signers (inside `KeyRevocation::from_body`) and, when
/// `signer_fingerprint` is supplied (the resolved `did:web` signing
/// key's RFC-ACDP-0010 §6 fingerprint), for resolved signers too.
///
/// Parsing does NOT verify the body: run the ordinary hash + signature
/// pipeline (`verify_content_hash` + `verify_signature`, or
/// `verify_body_offline` for did:key) before trusting the result.
pub(crate) fn parse_key_revocation_core(
    body: &acdp::types::Body,
    signer_fingerprint: Option<&str>,
) -> Result<String, AcdpError> {
    let revocation = KeyRevocation::from_body(body)?;
    if let Some(fingerprint) = signer_fingerprint {
        revocation.check_not_self_signed(fingerprint)?;
    }
    let mut out = serde_json::Map::new();
    out.insert(
        "revoked_key_fingerprint".into(),
        revocation.revoked_key_fingerprint.clone().into(),
    );
    out.insert(
        "compromised_since".into(),
        revocation
            .compromised_since
            .format(MS_FMT)
            .to_string()
            .into(),
    );
    // Absent-not-null convention (RFC-ACDP-0005 §2.2.1).
    if let Some(reason) = &revocation.reason {
        out.insert("reason".into(), reason.clone().into());
    }
    if let Some(key_id) = &revocation.revoked_key_id {
        out.insert("revoked_key_id".into(), key_id.clone().into());
    }
    out.insert(
        "revoked_key_controller".into(),
        revocation.revoked_key_controller.as_str().into(),
    );
    out.insert("publisher".into(), revocation.publisher.as_str().into());
    out.insert(
        "trust_class".into(),
        match revocation.trust_class {
            RevocationTrustClass::ProducerSigned => "producer_signed",
            RevocationTrustClass::RegistryAttested => "registry_attested",
        }
        .into(),
    );
    Ok(serde_json::Value::Object(out).to_string())
}

/// The RFC-ACDP-0014 §7 compromise-boundary rule over a set of
/// **verified** revocations (the JSON shapes `parse_key_revocation`
/// emits), mirroring the Rust client's fail-closed semantics:
///
/// * no supplied revocation names the fingerprint →
///   `{"authorization": "none"}` (no error: ordinary rules apply);
/// * receipt-attested publish time strictly before the earliest
///   boundary (§4 monotonicity, §7 step 2) →
///   `{"authorization": "historically_authorized_pre_compromise", "boundary": ...}`
///   — the caller still verifies the signature itself under the
///   RFC-ACDP-0010 §10 historical rule;
/// * publish time at/after the boundary (§7 step 3) or no verifiable
///   publish time at all (§7 step 4) → `{"authorization": "none",
///   "boundary": ..., "error": ...}` — **fail closed**.
///
/// `receipt_created_at` MUST come from a receipt verified per
/// RFC-ACDP-0010 §8 — never the bare body `created_at`, which is
/// registry-assigned, unsigned by the producer, and attacker-
/// backdatable (§7 step 1).
pub(crate) fn classify_under_revocation_core(
    revocations: &[KeyRevocation],
    signing_key_fingerprint: &str,
    receipt_created_at: Option<DateTime<Utc>>,
) -> String {
    let Some(boundary) = effective_boundary(revocations, signing_key_fingerprint) else {
        return serde_json::json!({"authorization": "none"}).to_string();
    };
    let boundary_str = boundary.format(MS_FMT).to_string();
    match receipt_created_at {
        Some(created_at) if created_at < boundary => serde_json::json!({
            "authorization": "historically_authorized_pre_compromise",
            "boundary": boundary_str,
        })
        .to_string(),
        Some(created_at) => serde_json::json!({
            "authorization": "none",
            "boundary": boundary_str,
            "error": format!(
                "signing key {signing_key_fingerprint} is revoked with compromise boundary \
                 {boundary_str}; the receipt-attested publish time {} is at/after the \
                 boundary, so the signature is not attributable to the producer — fail \
                 closed regardless of DID-document state or receipt validity \
                 (RFC-ACDP-0014 §7 step 3)",
                created_at.format(MS_FMT),
            ),
        })
        .to_string(),
        None => serde_json::json!({
            "authorization": "none",
            "boundary": boundary_str,
            "error": format!(
                "signing key {signing_key_fingerprint} is revoked (compromise boundary \
                 {boundary_str}) and the context has no verified registry receipt, so its \
                 publish time cannot be placed relative to the boundary — fail closed \
                 (RFC-ACDP-0014 §7 step 4)",
            ),
        })
        .to_string(),
    }
}
