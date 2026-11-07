//! The link in `Artifact.metadata["io.agentcontextdistributionprotocol/provenance"]` (RFC-ACDP-0022
//! §6–§6.2). The value is exactly RFC-ACDP-0019 §6's, except that under
//! this RFC `salt` is always present (§5.2).

use acdp::{
    types::{primitives::ContentHash, CtxId},
    AcdpError,
};
use serde_json::{json, Map, Value};

use crate::hash::Salt;

/// The `Artifact.metadata` key carrying the link (RFC-ACDP-0019's key).
pub const LINK_KEY: &str = "io.agentcontextdistributionprotocol/provenance";

/// `Idempotency-Key` for a body: `acdp-a2a-<64 hex of content_hash>` (§6).
pub fn idempotency_key(content_hash: &ContentHash) -> String {
    format!(
        "acdp-a2a-{}",
        content_hash.as_str().trim_start_matches("sha256:")
    )
}

/// §6 published value `{ctx_id, content_hash, registry, salt}`.
/// `registry` is the `ctx_id` authority, which is the body's
/// `origin_registry`.
pub fn published(ctx_id: &CtxId, content_hash: &ContentHash, salt: &Salt) -> Value {
    json!({
        "ctx_id": ctx_id.as_str(),
        "content_hash": content_hash.as_str(),
        "registry": ctx_id.authority(),
        "salt": salt.to_base64url(),
    })
}

/// §6.2 fail-open value `{failed: true, error?}`. `error` is the
/// registry's `error.code` when the registry answered with an ACDP error.
pub fn failed(error: Option<&str>) -> Value {
    match error {
        Some(code) => json!({ "failed": true, "error": code }),
        None => json!({ "failed": true }),
    }
}

/// Set `link` on an A2A `Artifact` object's `metadata`, creating the
/// object when absent. Every other member and metadata key is kept
/// (§6); `Artifact.extensions` is never touched (§6.1). Returns `false`
/// (and changes nothing) when `artifact` is not an object or its
/// `metadata` is not an object.
pub fn attach(artifact: &mut Value, link: Value) -> bool {
    let Some(a) = artifact.as_object_mut() else {
        return false;
    };
    let meta = a
        .entry("metadata")
        .or_insert_with(|| Value::Object(Map::new()));
    if meta.is_null() {
        *meta = Value::Object(Map::new());
    }
    let Value::Object(meta) = meta else {
        return false;
    };
    meta.insert(LINK_KEY.into(), link);
    true
}

/// The link on a held A2A `Artifact`, if any.
pub fn link_of(artifact: &Value) -> Option<&Value> {
    artifact.get("metadata")?.get(LINK_KEY)
}

/// The registry's `error.code` when the registry answered the publish
/// with an ACDP error; `None` for transport failures (refused, timed
/// out, SSRF-refused) and unreadable responses (§6.2).
pub fn registry_error_code(e: &AcdpError) -> Option<String> {
    use AcdpError as E;
    let code = match e {
        E::Registry(w) => {
            return (w.error.code != "unknown").then(|| w.error.code.clone());
        }
        E::SchemaViolation(m)
            if e.is_ssrf_policy_refusal() || m.starts_with("malformed registry response") =>
        {
            return None;
        }
        E::InvalidSignature(_) => "invalid_signature",
        E::RemoteHashMismatch(_) => "hash_mismatch",
        E::DataRefHashMismatch(_) => "data_ref_hash_mismatch",
        E::SchemaViolation(_) => "schema_violation",
        E::NotAuthorized(_) => "not_authorized",
        E::NotFound(_) => "not_found",
        E::RateLimited { .. } => "rate_limited",
        E::PayloadTooLarge(_) => "payload_too_large",
        E::EmbeddedTooLarge(_) => "embedded_too_large",
        E::KeyResolution(_) => "key_resolution_failed",
        E::KeyResolutionUnreachable(_) => "key_resolution_unreachable",
        E::KeyNotAuthorized(_) => "key_not_authorized",
        E::UnsupportedAlgorithm(_) => "unsupported_algorithm",
        E::UnsupportedMediaType(_) => "unsupported_media_type",
        E::NotImplemented(_) => "not_implemented",
        E::CursorExpired => "cursor_expired",
        E::InvalidCursor(_) => "invalid_cursor",
        E::DuplicatePublish(_) => "duplicate_publish",
        E::CrossRegistryResolutionFailed(_) => "cross_registry_resolution_failed",
        E::InvalidReceipt(_) => "invalid_receipt",
        E::InvalidLogProof(_) => "invalid_log_proof",
        E::InvalidWitnessCosignature(_) => "invalid_witness_cosignature",
        E::ImmutableField(_) => "immutable_field",
        E::InvalidLifecycleTransition(_) => "invalid_lifecycle_transition",
        E::RegistryInternal(_) => "internal_error",
        E::SupersededTarget { .. } => "superseded_target",
        _ => return None,
    };
    Some(code.to_owned())
}
