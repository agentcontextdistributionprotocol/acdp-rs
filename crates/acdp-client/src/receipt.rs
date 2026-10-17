//! Client-side registry-receipt verification (ACDP 0.2, RFC-ACDP-0010).
//!
//! Runs the full cross-check set. The cross-checks — not the signature
//! alone — are the security value: a receipt that verifies
//! cryptographically but binds a different `ctx_id`, a different body
//! hash, a different producer key, or a foreign registry is an attack,
//! not a receipt.

use acdp_did::web::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_types::primitives::{ContentHash, CtxId, LineageId};
use acdp_types::receipt::{LineageHeadReceipt, ReceiptKeyStatus, RegistryReceipt};

/// Resolve the registry DID document holding receipt key `#fragment`,
/// re-fetching a stale cached copy once (RFC-ACDP-0001 §5.11 "Caching").
async fn resolve_receipt_key_doc(
    did: &str,
    fragment: &str,
    resolver: &WebResolver,
    since: std::time::Instant,
) -> Result<acdp_did::DidDocument, AcdpError> {
    resolver
        .resolve_with_fragment(did, fragment, since)
        .await
        .map_err(|e| match e {
            AcdpError::KeyResolution(_) => AcdpError::InvalidReceipt(format!(
                "registry DID document has no verification method '#{fragment}' — \
                 receipt keys (including retired ones) must remain in verificationMethod"
            )),
            other => other,
        })
}

/// Resolve the registry DID document for receipt key `#fragment` and
/// report its RFC-ACDP-0010 §8 step 1 status. A cached copy on which the
/// key is absent or merely *historical* is re-fetched once (the status
/// is an adverse input to RFC-ACDP-0014 §7 placement, so it is subject
/// to the same RFC-ACDP-0001 §5.11 refresh rule as a step-5 verdict).
/// Under the forced-refresh rate limit the stale copy is used: a key it
/// lacks is [`AcdpError::KeyResolutionUnreachable`] (transient), a key
/// it holds outside `assertionMethod` is reported `Historical`.
async fn resolve_receipt_key_with_status(
    did: &str,
    fragment: &str,
    resolver: &WebResolver,
    since: std::time::Instant,
) -> Result<(acdp_did::DidDocument, ReceiptKeyStatus), AcdpError> {
    let res = resolver
        .resolve_until(did, since, |doc| {
            doc.find_by_fragment(fragment)
                .is_some_and(|m| doc.is_assertion_method(&m.id))
        })
        .await
        .map_err(|e| match e {
            AcdpError::KeyResolution(why) => {
                AcdpError::InvalidReceipt(format!("registry DID document: {why}"))
            }
            other => other,
        })?;
    let doc = res.document;
    let status = match doc.find_by_fragment(fragment) {
        Some(m) if doc.is_assertion_method(&m.id) => ReceiptKeyStatus::Current,
        Some(_) => ReceiptKeyStatus::Historical,
        None if res.fresh => {
            return Err(AcdpError::InvalidReceipt(format!(
                "registry DID document has no verification method '#{fragment}' — \
                 receipt keys (including retired ones) must remain in verificationMethod"
            )))
        }
        None => {
            return Err(AcdpError::KeyResolutionUnreachable(format!(
                "receipt key '#{fragment}' is absent from a stale cached copy of {did} \
                 and the re-fetch is rate-limited (RFC-ACDP-0001 §5.11)"
            )))
        }
    };
    Ok((doc, status))
}

/// Verify a `registry_receipt` value end-to-end:
///
/// 1. Parse. The receipt schema is CLOSED (RFC-ACDP-0010 §4): an
///    unknown member fails parsing with `invalid_receipt`.
/// 2. `registry_did` equals `did:web:<serving_authority>` — the
///    authority the context was actually fetched from, not whatever
///    the receipt claims.
/// 3. Pure cross-checks: `ctx_id`, `content_hash` (against the
///    *recomputed* body hash), `key_fingerprint` (against the resolved
///    producer key), millisecond `created_at`, internal
///    `registry_did`/`origin_registry` consistency.
/// 4. Resolve the registry's DID document and verify the receipt
///    signature. The receipt key is looked up in `verificationMethod`
///    WITHOUT requiring `assertionMethod` membership: retired receipt
///    keys remain in `verificationMethod` indefinitely (RFC-ACDP-0010
///    key lifecycle), keeping old receipts verifiable after rotation.
///
/// All failures map to [`AcdpError::InvalidReceipt`] except transport-
/// level DID-resolution failures, which keep their transient/permanent
/// classification so retry logic still works.
pub async fn verify_receipt_value(
    value: &serde_json::Value,
    expected_ctx_id: &CtxId,
    body: &acdp_types::body::Body,
    recomputed_body_hash: &ContentHash,
    producer_key_fingerprint: &str,
    serving_authority: &str,
    resolver: &WebResolver,
) -> Result<RegistryReceipt, AcdpError> {
    verify_receipt_value_since(
        value,
        expected_ctx_id,
        body,
        recomputed_body_hash,
        producer_key_fingerprint,
        serving_authority,
        resolver,
        std::time::Instant::now(),
    )
    .await
}

/// [`verify_receipt_value`] with an explicit DID-document freshness
/// scope (RFC-ACDP-0001 §5.11 "Caching"): a registry DID document fetched
/// at or after `since` is fresh for this check; an older cached copy that
/// lacks the receipt key is re-fetched once before the receipt is
/// rejected. A key still absent after that re-fetch is
/// [`AcdpError::InvalidReceipt`]; a key absent from a stale copy whose
/// re-fetch was rate-limited is [`AcdpError::KeyResolutionUnreachable`]
/// (transient).
#[allow(clippy::too_many_arguments)]
pub async fn verify_receipt_value_since(
    value: &serde_json::Value,
    expected_ctx_id: &CtxId,
    body: &acdp_types::body::Body,
    recomputed_body_hash: &ContentHash,
    producer_key_fingerprint: &str,
    serving_authority: &str,
    resolver: &WebResolver,
    since: std::time::Instant,
) -> Result<RegistryReceipt, AcdpError> {
    verify_receipt_value_with_status_since(
        value,
        expected_ctx_id,
        body,
        recomputed_body_hash,
        producer_key_fingerprint,
        serving_authority,
        resolver,
        since,
    )
    .await
    .map(|(receipt, _)| receipt)
}

/// [`verify_receipt_value_since`] that also reports the receipt-key
/// status (RFC-ACDP-0010 §8 step 1, 0.5.0): [`ReceiptKeyStatus::Current`]
/// when the receipt key is in the registry DID document's
/// `assertionMethod`, [`ReceiptKeyStatus::Historical`] when it is in
/// `verificationMethod` only. Both verify; a historical status MUST be
/// reported as such and, under the strict profile, cannot place a
/// revoked-key context before its compromise boundary
/// (RFC-ACDP-0014 §7 step 1).
#[allow(clippy::too_many_arguments)]
pub async fn verify_receipt_value_with_status_since(
    value: &serde_json::Value,
    expected_ctx_id: &CtxId,
    body: &acdp_types::body::Body,
    recomputed_body_hash: &ContentHash,
    producer_key_fingerprint: &str,
    serving_authority: &str,
    resolver: &WebResolver,
    since: std::time::Instant,
) -> Result<(RegistryReceipt, ReceiptKeyStatus), AcdpError> {
    let receipt = RegistryReceipt::from_value(value)?;

    // §8 step 6: canonical millisecond byte form, checked on the RAW
    // wire string before any parsing normalization.
    RegistryReceipt::validate_created_at_form(value)?;

    // Serving-authority binding (the client-side half of cross-check 2;
    // the receipt-internal half lives in `RegistryReceipt::cross_check`).
    let expected_did = acdp_did::web::authority_to_did_web(serving_authority);
    if receipt.registry_did != expected_did {
        return Err(AcdpError::InvalidReceipt(format!(
            "receipt registry_did '{}' ≠ serving authority's DID '{expected_did}'",
            receipt.registry_did
        )));
    }

    receipt.cross_check(
        expected_ctx_id,
        recomputed_body_hash,
        producer_key_fingerprint,
    )?;
    // §8 step 3 body bindings: lineage_id / origin_registry /
    // created_at must equal the accompanying body's fields.
    receipt.cross_check_body(body)?;

    // Resolve the registry's receipt key and verify the signature.
    let key_id = &receipt.signature.key_id;
    let (did_part, fragment) = key_id.split_once('#').ok_or_else(|| {
        AcdpError::InvalidReceipt(format!(
            "receipt signature.key_id '{key_id}' has no fragment"
        ))
    })?;
    if did_part != receipt.registry_did {
        return Err(AcdpError::InvalidReceipt(format!(
            "receipt signature.key_id DID '{did_part}' ≠ registry_did '{}'",
            receipt.registry_did
        )));
    }
    let (doc, key_status) =
        resolve_receipt_key_with_status(did_part, fragment, resolver, since).await?;
    let method = doc
        .find_by_fragment(fragment)
        .expect("resolve_receipt_key_with_status guarantees the fragment");

    // §5 / RFC-ACDP-0001 §6 raw-JSON rule: hash the receipt exactly as
    // received — re-serializing the parsed struct could normalize byte
    // details and falsely reject an honest receipt.
    let raw_hash = RegistryReceipt::preimage_hash_of_value(value)?;
    match receipt.signature.algorithm.as_str() {
        "ed25519" => {
            let key = method
                .ed25519_public_key_bytes()
                .map_err(|e| AcdpError::InvalidReceipt(format!("receipt key extraction: {e}")))?;
            receipt.verify_signature_against_hash(&raw_hash, Some(&key), None)?;
        }
        "ecdsa-p256" => {
            let key = method
                .ecdsa_p256_public_key_sec1()
                .map_err(|e| AcdpError::InvalidReceipt(format!("receipt key extraction: {e}")))?;
            receipt.verify_signature_against_hash(&raw_hash, None, Some(&key))?;
        }
        other => {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt signature algorithm '{other}' is not supported"
            )));
        }
    }

    Ok((receipt, key_status))
}

/// Verify a `lineage_head_receipt` value end-to-end per the
/// RFC-ACDP-0011 §7 procedure (ACDP 0.3):
///
/// 1. **Closed parse** — the schema is CLOSED and `receipt_version`
///    MUST be exactly `"acdp-lhr/1"`; unknown or missing members fail
///    with `invalid_receipt`. The raw `as_of` byte form is checked
///    before any parsing normalization.
/// 2. **Registry binding** — `registry_did` equals
///    `did:web:<serving_authority>` (the authority the response was
///    actually fetched from) AND equals `capabilities.registry_did`;
///    `signature.key_id` is a DID URL under `registry_did`; the
///    `head_ctx_id` authority equals the registry's (fixture `lhr-003`).
/// 3. **Lineage binding** — `lineage_id` equals the lineage the
///    consumer requested (byte-for-byte).
/// 4. **Head binding** — the receipt's head fields byte-match the
///    accompanying response (`on_current_endpoint = true` for
///    `/current`, where the receipt MUST describe the very head being
///    served; fixture `lhr-002`). On full retrieval of a non-head
///    version the §7 step 5b consistency rule applies.
/// 5. **Signature** — JCS-recompute the preimage from the RAW wire
///    JSON, resolve `signature.key_id` from the registry's DID document
///    and verify. Like RFC-ACDP-0010 receipts, the key is looked up in
///    `verificationMethod` WITHOUT requiring `assertionMethod`
///    membership (retired receipt keys keep persisted head receipts
///    verifiable, RFC-ACDP-0011 §8).
/// 6. **`as_of` skew** — not in the future beyond `max_clock_skew`
///    (RFC recommends 120 s; fixture `lhr-004`).
///
/// Staleness (an old but honest `as_of`) is deliberately NOT checked
/// here — it is consumer freshness policy (§6), evaluated separately
/// via [`LineageHeadReceipt::age_at`] and reported distinctly from
/// these verification failures.
///
/// All failures map to [`AcdpError::InvalidReceipt`] except transport-
/// level DID-resolution failures, which keep their transient/permanent
/// classification so retry logic still works.
#[allow(clippy::too_many_arguments)]
pub async fn verify_lineage_head_receipt_value(
    value: &serde_json::Value,
    requested_lineage: &LineageId,
    served_ctx_id: &CtxId,
    served_version: u32,
    served_status: &acdp_types::primitives::Status,
    on_current_endpoint: bool,
    serving_authority: &str,
    capabilities_registry_did: &str,
    max_clock_skew: chrono::Duration,
    resolver: &WebResolver,
) -> Result<LineageHeadReceipt, AcdpError> {
    // §7 step 1: closed parse + semantic invariants + raw as_of form.
    let receipt = LineageHeadReceipt::from_value(value)?;

    // §7 steps 3–5 cross-checks (pure) — the security value; run before
    // the network round-trip for the signature, exactly like
    // `verify_receipt_value`.
    receipt.cross_check_registry_binding(serving_authority, capabilities_registry_did)?;
    receipt.cross_check_lineage(requested_lineage)?;
    receipt.cross_check_head(
        served_ctx_id,
        served_version,
        served_status,
        on_current_endpoint,
    )?;

    // §7 step 2: resolve the registry's receipt key and verify the
    // signature over the RAW wire preimage (re-serializing the parsed
    // struct could normalize byte details and falsely reject an honest
    // receipt).
    let key_id = &receipt.signature.key_id;
    let (did_part, fragment) = key_id.split_once('#').ok_or_else(|| {
        AcdpError::InvalidReceipt(format!(
            "lineage_head_receipt signature.key_id '{key_id}' has no fragment"
        ))
    })?;
    let doc =
        resolve_receipt_key_doc(did_part, fragment, resolver, std::time::Instant::now()).await?;
    let method = doc
        .find_by_fragment(fragment)
        .expect("resolve_receipt_key_doc guarantees the fragment");
    let raw_hash = LineageHeadReceipt::preimage_hash_of_value(value)?;
    match receipt.signature.algorithm.as_str() {
        "ed25519" => {
            let key = method
                .ed25519_public_key_bytes()
                .map_err(|e| AcdpError::InvalidReceipt(format!("receipt key extraction: {e}")))?;
            receipt.verify_signature_against_hash(&raw_hash, Some(&key), None)?;
        }
        "ecdsa-p256" => {
            let key = method
                .ecdsa_p256_public_key_sec1()
                .map_err(|e| AcdpError::InvalidReceipt(format!("receipt key extraction: {e}")))?;
            receipt.verify_signature_against_hash(&raw_hash, None, Some(&key))?;
        }
        other => {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt signature algorithm '{other}' is not supported"
            )));
        }
    }

    // §7 step 6: forged-freshness rejection against the consumer clock.
    receipt.check_as_of_skew(chrono::Utc::now(), max_clock_skew)?;

    Ok(receipt)
}
