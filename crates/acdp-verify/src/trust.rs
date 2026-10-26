//! RFC-ACDP-0020 §5.2 for a list carried out of band (§7): verify a
//! `did:key`-issued trust-list body offline and turn it into a
//! [`ListVersion`].
//!
//! The pure selection and evaluation logic is in
//! [`acdp_types::trust_list`]; a `did:web` issuer needs the
//! resolver-backed path in `acdp_client::trust`, and lists carried in an
//! RFC-ACDP-0017 bundle are verified by `acdp_chain`.

use acdp_types::lifecycle::{retraction_state, LifecycleEvent};
use acdp_types::trust_list::{
    validate_list_version, IssuerPin, ListRejected, ListVersion, VerifiedListBody,
};
use acdp_types::PublishRequest;
use serde_json::Value;

/// Verify a trust-list body offline and validate it for `pin` (§5.2).
///
/// `raw` is either a retrieved body (with `ctx_id`) or, out of band, the
/// signed publish-request form (§7): both verify identically. The issuer
/// MUST be a `did:key`.
///
/// `retractions` are the issuer-signed lifecycle events supplied with an
/// out-of-band list (§5.3), in order. Each must bind to the body's
/// `ctx_id` and verify under the issuer key; others are ignored, so a
/// registry-actor retraction never withdraws a list. A publish-request
/// body has no `ctx_id` for an event to bind to, so it is never
/// retracted. `issuer_key_revoked` is the caller's RFC-ACDP-0014 §7
/// verdict for the issuer key (§5.2 step 5).
pub fn verify_list_offline(
    raw: &Value,
    pin: &IssuerPin,
    retractions: &[Value],
    issuer_key_revoked: bool,
) -> Result<ListVersion, ListRejected> {
    let step1 = |e: acdp_primitives::error::AcdpError| ListRejected {
        step: 1,
        reason: e.to_string(),
    };
    let (agent_id, context_type, metadata, content_hash, ctx_id, key_id) =
        if raw.get("ctx_id").is_some() {
            let body = crate::verify_body_value_offline(raw).map_err(step1)?;
            (
                body.agent_id,
                body.context_type,
                body.metadata,
                body.content_hash,
                Some(body.ctx_id),
                body.signature.key_id,
            )
        } else {
            let req: PublishRequest = serde_json::from_value(raw.clone()).map_err(|e| {
                step1(acdp_primitives::error::AcdpError::SchemaViolation(format!(
                    "publish request does not parse: {e}"
                )))
            })?;
            acdp_validation::validate_publish_request(&req).map_err(step1)?;
            if !req.agent_id.as_str().starts_with("did:key:") {
                return Err(step1(acdp_primitives::error::AcdpError::KeyResolution(
                    "offline trust-list verification supports did:key issuers only".into(),
                )));
            }
            acdp_crypto::verify_content_hash(raw, &req.content_hash).map_err(step1)?;
            crate::verify_publish_request_signature_offline(&req).map_err(step1)?;
            (
                req.agent_id,
                req.context_type,
                req.metadata,
                req.content_hash,
                None,
                req.signature.key_id,
            )
        };
    let fingerprint = acdp_did::key::resolve_did_key_url(&key_id)
        .and_then(|m| acdp_crypto::fingerprint::fingerprint_did_key_material(&m))
        .map_err(step1)?;

    let retracted = ctx_id.as_ref().is_some_and(|ctx| {
        let events: Vec<LifecycleEvent> = retractions
            .iter()
            .filter_map(|ev| crate::verify_lifecycle_event_offline(ev, ctx, &agent_id, None).ok())
            .filter(|ev| ev.actor == agent_id)
            .collect();
        retraction_state(&events)
    });
    let context_type = serde_json::to_value(&context_type)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    validate_list_version(
        pin,
        &VerifiedListBody {
            agent_id: agent_id.as_str(),
            context_type: &context_type,
            metadata: metadata.as_ref(),
            content_hash: content_hash.as_str(),
            ctx_id: ctx_id.as_ref().map(|c| c.as_str()),
            issuer_key_fingerprint: Some(&fingerprint),
            issuer_key_revoked,
            retracted,
        },
    )
}
