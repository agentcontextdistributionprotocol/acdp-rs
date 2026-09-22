//! Runtime validation against the ACDP schemas.
//!
//! The JSON schemas are the single source of truth for wire-shape constraints,
//! but JSON Schema cannot express every invariant in the ACDP RFCs. This
//! module implements the runtime checks the schema delegates to producers
//! and registries:
//!
//! - String length / array uniqueness / array size limits
//! - `data_period.start <= end`
//! - `DataRef` oneOf (location XOR embedded), URI credential rejection,
//!   structured-locator scheme pattern, embedded size cap, embedded
//!   `content` typing per encoding
//! - `metadata` runtime depth / JCS-size / property-count caps
//! - `agent_id` DID pattern + `did:web` enforcement (v0.1.0)
//! - Signature value length per algorithm
//! - Embedded `content_hash` computation and verification
//! - Identifier pattern validation (`ctx_id`, `lineage_id`, `content_hash`)
//!
//! Each function is independently usable; [`validate_publish_request`] and
//! [`validate_body`] aggregate everything for end-to-end validation.

use acdp_crypto::try_canonicalize_value;
use acdp_primitives::error::AcdpError;
use acdp_types::anchor::AnchorEntry;
use acdp_types::body::Body;
use acdp_types::data_ref::{DataRef, EmbeddedContent, EmbeddedEncoding, Location};
use acdp_types::primitives::{
    AgentDid, ContentHash, ContextType, CtxId, LineageId, Status, Visibility,
};
use acdp_types::publish::PublishRequest;
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

// ── Constants from the schemas ────────────────────────────────────────────────

const MAX_TITLE_LEN: usize = 500;
const MAX_DESCRIPTION_LEN: usize = 5000;
const MAX_SUMMARY_LEN: usize = 1000;
const MAX_DOMAIN_LEN: usize = 200;
const MAX_DATA_REF_DESCRIPTION_LEN: usize = 1000;
const MAX_TAG_LEN: usize = 100;
const MAX_CONTRIBUTORS: usize = 100;
const MAX_TAGS: usize = 200;
const MAX_DERIVED_FROM: usize = 1000;
const MAX_AUDIENCE: usize = 1000;
const MAX_METADATA_PROPERTIES: usize = 100;
const MAX_METADATA_DEPTH: usize = 8;
const MAX_METADATA_JCS_BYTES: usize = 65_536;
const MAX_URI_LEN: usize = 4096;
const MAX_ANCHORS: usize = 100;
const MAX_EMBEDDED_BYTES: usize = 65_536;
const ED25519_SIG_B64_LEN: usize = 88;
const ECDSA_P256_SIG_B64_LEN: usize = 88;

// ── Capabilities ─────────────────────────────────────────────────────────────

/// True when a `major.minor.patch` version string is >= the given
/// major.minor (version-conditional capability checks; malformed
/// versions are rejected by `validate_semver_pattern` first).
fn version_at_least(v: &str, major: u64, minor: u64) -> bool {
    let mut it = v.split('.').filter_map(|p| p.parse::<u64>().ok());
    match (it.next(), it.next()) {
        (Some(ma), Some(mi)) => ma > major || (ma == major && mi >= minor),
        _ => false,
    }
}

/// Validate a [`acdp_types::CapabilitiesDocument`] against the
/// runtime constraints listed in RFC-ACDP-0007 §3.
///
/// The JSON schema enforces *types*; this validator enforces the
/// constraints the schema cannot express:
///
/// 1. `acdp_version` matches `^\d+\.\d+\.\d+$`.
/// 2. `registry_did` is a v0.1.0 `did:web` DID.
/// 3. `supported_signature_algorithms` MUST contain `"ed25519"`.
/// 4. `supported_did_methods` MUST contain `"did:web"`.
/// 5. `profiles` MUST contain `"acdp-registry-core"`.
/// 6. `limits.max_embedded_bytes` MUST equal exactly 65536.
/// 7. If `supports_idempotency_key` is `true`,
///    `limits.idempotency_key_ttl_seconds` MUST be present and in
///    `86400..=604800`.
/// 8. `limits.max_payload_bytes` MUST be at least 1024 bytes.
///
/// Wired into `acdp::client::RegistryClient::capabilities` and
/// `acdp::client::CrossRegistryResolver::resolve`.
pub fn validate_capabilities(caps: &acdp_types::CapabilitiesDocument) -> Result<(), AcdpError> {
    validate_semver_pattern("acdp_version", &caps.acdp_version)?;

    // §3.5 item 11 *(0.3.0)*: limits.max_publish_per_minute, when
    // present, MUST be an integer >= 1 (schema minimum).
    if let Some(mppm) = caps.limits.max_publish_per_minute {
        if mppm < 1 {
            return Err(AcdpError::SchemaViolation(
                "capabilities.limits.max_publish_per_minute MUST be >= 1 \
                 (RFC-ACDP-0007 \u{a7}3.5 item 11)"
                    .into(),
            ));
        }
    }

    // §3.5 item 10 *(0.3.0)* / RFC-ACDP-0003 §6.4: a registry
    // advertising acdp_version >= 0.3.0 MUST support Idempotency-Key;
    // supports_idempotency_key absent-or-false alongside such a version
    // makes the document self-contradictory (fixture idem-007).
    if version_at_least(&caps.acdp_version, 0, 3) && !caps.supports_idempotency_key {
        return Err(AcdpError::SchemaViolation(
            "capabilities advertising acdp_version >= 0.3.0 MUST set \
             supports_idempotency_key: true (RFC-ACDP-0003 \u{a7}6.4, \
             RFC-ACDP-0007 \u{a7}3.5 item 10)"
                .into(),
        ));
    }

    AgentDid::parse_web(caps.registry_did.as_str()).map_err(|e| {
        AcdpError::SchemaViolation(format!(
            "capabilities.registry_did must be did:web for v0.1.0: {e}"
        ))
    })?;

    if !caps
        .supported_signature_algorithms
        .iter()
        .any(|a| a == "ed25519")
    {
        return Err(AcdpError::SchemaViolation(
            "capabilities.supported_signature_algorithms MUST contain 'ed25519' \
             (RFC-ACDP-0001 §5.10)"
                .into(),
        ));
    }

    if !caps.supported_did_methods.iter().any(|m| m == "did:web") {
        return Err(AcdpError::SchemaViolation(
            "capabilities.supported_did_methods MUST contain 'did:web' \
             (RFC-ACDP-0001 §5.4)"
                .into(),
        ));
    }

    if !caps.profiles.iter().any(|p| p == "acdp-registry-core") {
        return Err(AcdpError::SchemaViolation(
            "capabilities.profiles MUST contain 'acdp-registry-core' \
             (RFC-ACDP-0001 §9.1)"
                .into(),
        ));
    }

    if caps.limits.max_embedded_bytes != 65_536 {
        return Err(AcdpError::SchemaViolation(format!(
            "capabilities.limits.max_embedded_bytes must be 65536 (fixed by \
             RFC-ACDP-0007 §3.1), got {}",
            caps.limits.max_embedded_bytes
        )));
    }

    if caps.limits.max_payload_bytes < 1024 {
        return Err(AcdpError::SchemaViolation(format!(
            "capabilities.limits.max_payload_bytes must be ≥ 1024, got {}",
            caps.limits.max_payload_bytes
        )));
    }

    if caps.supports_idempotency_key {
        let ttl = caps.limits.idempotency_key_ttl_seconds.ok_or_else(|| {
            AcdpError::SchemaViolation(
                "limits.idempotency_key_ttl_seconds is required when \
                 supports_idempotency_key is true (RFC-ACDP-0007 §3.2)"
                    .into(),
            )
        })?;
        if !(86_400..=604_800).contains(&ttl) {
            return Err(AcdpError::SchemaViolation(format!(
                "limits.idempotency_key_ttl_seconds must be in 86400..=604800, got {ttl}"
            )));
        }
    }

    Ok(())
}

// ── Top-level entry points ───────────────────────────────────────────────────

/// Validate a complete [`PublishRequest`] against every schema constraint
/// and runtime invariant.
pub fn validate_publish_request(req: &PublishRequest) -> Result<(), AcdpError> {
    validate_title(&req.title)?;
    validate_optional_string(
        req.description.as_deref(),
        "description",
        MAX_DESCRIPTION_LEN,
    )?;
    validate_optional_string(req.summary.as_deref(), "summary", MAX_SUMMARY_LEN)?;
    validate_optional_string(req.domain.as_deref(), "domain", MAX_DOMAIN_LEN)?;

    validate_agent_did(&req.agent_id)?;
    for c in &req.contributors {
        validate_loose_did(c)?;
    }
    validate_unique_array("contributors", &req.contributors, MAX_CONTRIBUTORS)?;
    validate_unique_array("derived_from", &req.derived_from, MAX_DERIVED_FROM)?;

    if let Some(tags) = &req.tags {
        validate_tags(tags)?;
    }
    if let Some(audience) = &req.audience {
        validate_unique_array("audience", audience, MAX_AUDIENCE)?;
        for did in audience {
            validate_loose_did(did)?;
        }
    }

    validate_visibility_audience(&req.visibility, req.audience.as_deref())?;

    if let Some(dp) = &req.data_period {
        if dp.start > dp.end {
            return Err(AcdpError::SchemaViolation(
                "data_period.start must not be after data_period.end".into(),
            ));
        }
    }

    if let Some(ct) = &req.context_type.namespaced_form() {
        validate_namespaced_context_type(ct)?;
    }

    if let Some(meta) = &req.metadata {
        validate_metadata(meta)?;
    }

    for dr in &req.data_refs {
        validate_data_ref(dr)?;
    }

    if let Some(anchors) = &req.anchors {
        validate_anchors(anchors)?;
    }

    validate_signature_length(&req.signature.algorithm, &req.signature.value)?;
    validate_did_key_key_id_form(&req.signature.key_id)?;
    ContentHash::parse(req.content_hash.as_str())?;

    // Identifier patterns on every supplied ctx_id
    if let Some(prev) = &req.supersedes {
        CtxId::parse(prev.as_str())?;
    }
    for ancestor in &req.derived_from {
        CtxId::parse(ancestor.as_str())?;
    }
    if let Some(lineage) = &req.lineage_id {
        acdp_types::primitives::LineageId::parse(lineage.as_str())?;
    }

    // acdp_version pattern (semver `^\d+\.\d+\.\d+$`)
    if let Some(v) = &req.acdp_version {
        validate_semver_pattern("acdp_version", v)?;
    }

    // Version coherence (also enforced by the builder)
    match (&req.supersedes, req.version) {
        (None, 1) => {}
        (None, v) => {
            return Err(AcdpError::SchemaViolation(format!(
                "first-version publish requires version=1, got {v}"
            )));
        }
        (Some(_), v) if v >= 2 => {}
        (Some(_), v) => {
            return Err(AcdpError::SchemaViolation(format!(
                "supersession publish requires version >= 2, got {v}"
            )));
        }
    }

    // RFC-ACDP-0003 §2.2 / `acdp-publish-request.schema.json` allOf:
    // v1 publications MUST NOT include lineage_id (the value would
    // necessarily be wrong because the formula depends on the
    // registry-assigned ctx_id). The builder enforces this too, but
    // applying it here lets the validator stand alone for callers that
    // do not go through `RequestBuilder` (e.g. the conformance harness,
    // server-side validators).
    if req.version == 1 && req.lineage_id.is_some() {
        return Err(AcdpError::SchemaViolation(
            "lineage_id MUST NOT be set on v1 publish requests (RFC-ACDP-0003 §2.2)".into(),
        ));
    }

    Ok(())
}

/// Validate a stored [`Body`] (retrieval-side check).
pub fn validate_body(body: &Body) -> Result<(), AcdpError> {
    validate_body_inner(body, /* check_embedded_hashes = */ true)
}

/// Same as [`validate_body`] but skips the embedded-`content_hash` recomputation.
///
/// Used by `acdp::client::VerifiedContext::fetch_report` so per-`DataRef`
/// embedded-hash outcomes can be recorded individually rather than
/// short-circuiting the whole verification. Callers that want the
/// embedded-hash check MUST run [`verify_embedded_hash`] themselves —
/// `fetch_report`'s recording loop is one such caller.
///
/// Production code that doesn't need partial-failure reporting should
/// prefer [`validate_body`].
pub fn validate_body_structural(body: &Body) -> Result<(), AcdpError> {
    validate_body_inner(body, /* check_embedded_hashes = */ false)
}

fn validate_body_inner(body: &Body, check_embedded_hashes: bool) -> Result<(), AcdpError> {
    validate_title(&body.title)?;
    validate_optional_string(
        body.description.as_deref(),
        "description",
        MAX_DESCRIPTION_LEN,
    )?;
    validate_optional_string(body.summary.as_deref(), "summary", MAX_SUMMARY_LEN)?;
    validate_optional_string(body.domain.as_deref(), "domain", MAX_DOMAIN_LEN)?;

    validate_agent_did(&body.agent_id)?;
    for c in &body.contributors {
        validate_loose_did(c)?;
    }
    validate_unique_array("contributors", &body.contributors, MAX_CONTRIBUTORS)?;
    validate_unique_array("derived_from", &body.derived_from, MAX_DERIVED_FROM)?;

    if let Some(tags) = &body.tags {
        validate_tags(tags)?;
    }
    if let Some(audience) = &body.audience {
        validate_unique_array("audience", audience, MAX_AUDIENCE)?;
        for did in audience {
            validate_loose_did(did)?;
        }
    }
    validate_visibility_audience(&body.visibility, body.audience.as_deref())?;

    if let Some(dp) = &body.data_period {
        if dp.start > dp.end {
            return Err(AcdpError::SchemaViolation(
                "data_period.start must not be after data_period.end".into(),
            ));
        }
    }

    if let Some(meta) = &body.metadata {
        validate_metadata(meta)?;
    }

    // Forward-compat `extensions` (`#[serde(flatten)]`) are producer-
    // controlled and flow into JCS + content_hash; cap them like metadata
    // so they cannot bypass the §3.3 size/count/depth limits (P1-3).
    validate_extensions(&body.extensions)?;

    for dr in &body.data_refs {
        if check_embedded_hashes {
            validate_data_ref(dr)?;
        } else {
            validate_data_ref_structural(dr)?;
        }
    }

    if let Some(anchors) = &body.anchors {
        validate_anchors(anchors)?;
    }

    validate_signature_length(&body.signature.algorithm, &body.signature.value)?;
    validate_did_key_key_id_form(&body.signature.key_id)?;
    validate_identifiers(&body.ctx_id, &body.lineage_id, &body.content_hash)?;

    // Every entry in supersedes / derived_from MUST be a valid ctx_id.
    if let Some(prev) = &body.supersedes {
        CtxId::parse(prev.as_str())?;
    }
    for ancestor in &body.derived_from {
        CtxId::parse(ancestor.as_str())?;
    }

    if let Some(v) = &body.acdp_version {
        validate_semver_pattern("acdp_version", v)?;
    }

    let _ = &body.created_at; // schema-derived; serde already enforces RFC 3339
    validate_origin_registry(&body.origin_registry)?;

    // Avoid unused-import warnings on Status / Visibility
    let _ = std::any::type_name::<Status>();
    let _: &Visibility = &body.visibility;

    Ok(())
}

/// Validate an identifier triple — convenient for retrieval-side use.
pub fn validate_identifiers(
    ctx_id: &CtxId,
    lineage_id: &LineageId,
    content_hash: &ContentHash,
) -> Result<(), AcdpError> {
    CtxId::parse(ctx_id.as_str())?;
    LineageId::parse(lineage_id.as_str())?;
    ContentHash::parse(content_hash.as_str())?;
    Ok(())
}

// ── DataRef ──────────────────────────────────────────────────────────────────

/// Validate a single [`DataRef`] against `acdp-data-ref.schema.json` and the
/// runtime invariants the schema delegates.
pub fn validate_data_ref(dr: &DataRef) -> Result<(), AcdpError> {
    validate_data_ref_structural(dr)?;
    // BUG-02: verify the declared content_hash against the decoded bytes
    // (RFC-ACDP-0002 §6.6 #8). A producer-supplied wrong hash is a
    // signed commitment to a misleading integrity claim, so we catch
    // it at validate time, not just inside `PublishValidator`.
    if dr.embedded.is_some() {
        verify_embedded_hash(dr)?;
    }
    Ok(())
}

/// Same as [`validate_data_ref`] but skips the embedded-`content_hash`
/// recomputation. Callers that want to report per-`DataRef` hash failures
/// (e.g. `acdp::client::VerifiedContext::fetch_report`) run the
/// structural checks via this helper, then call [`verify_embedded_hash`]
/// themselves and record the outcome instead of short-circuiting.
pub fn validate_data_ref_structural(dr: &DataRef) -> Result<(), AcdpError> {
    // oneOf: exactly one of location / embedded
    match (&dr.location, &dr.embedded) {
        (None, None) => {
            return Err(AcdpError::SchemaViolation(
                "DataRef requires exactly one of 'location' or 'embedded' (got neither)".into(),
            ));
        }
        (Some(_), Some(_)) => {
            return Err(AcdpError::SchemaViolation(
                "DataRef requires exactly one of 'location' or 'embedded' (got both)".into(),
            ));
        }
        _ => {}
    }

    if let Some(desc) = &dr.description {
        if desc.len() > MAX_DATA_REF_DESCRIPTION_LEN {
            return Err(AcdpError::SchemaViolation(format!(
                "DataRef.description {} chars exceeds {} limit",
                desc.len(),
                MAX_DATA_REF_DESCRIPTION_LEN
            )));
        }
    }

    if let Some(loc) = &dr.location {
        validate_location(loc)?;
    }
    if let Some(emb) = &dr.embedded {
        validate_embedded(emb)?;
    }

    Ok(())
}

fn validate_location(loc: &Location) -> Result<(), AcdpError> {
    match loc {
        Location::Uri(uri) => validate_uri_location(uri),
        Location::Structured(map) => validate_structured_locator(map),
    }
}

fn validate_uri_location(uri: &str) -> Result<(), AcdpError> {
    if uri.len() < 3 || uri.len() > MAX_URI_LEN {
        return Err(AcdpError::SchemaViolation(format!(
            "DataRef.location URI length {} not in 3..={}",
            uri.len(),
            MAX_URI_LEN
        )));
    }
    // Scheme: ^[a-z][a-z0-9+.-]*:
    let (scheme, rest) = uri
        .split_once(':')
        .ok_or_else(|| AcdpError::SchemaViolation(format!("URI missing scheme: {uri}")))?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-'))
    {
        return Err(AcdpError::SchemaViolation(format!(
            "URI scheme '{scheme}' invalid; must match [a-z][a-z0-9+.-]*"
        )));
    }
    // userinfo rejection: ^[a-z][a-z0-9+.-]*://[^/?#@]+@
    if let Some(after_slashes) = rest.strip_prefix("//") {
        if let Some(authority_end) = after_slashes.find(['/', '?', '#']) {
            let authority = &after_slashes[..authority_end];
            if authority.contains('@') {
                return Err(AcdpError::SchemaViolation(format!(
                    "URI MUST NOT contain credentials in userinfo: {uri}"
                )));
            }
        } else if after_slashes.contains('@') {
            return Err(AcdpError::SchemaViolation(format!(
                "URI MUST NOT contain credentials in userinfo: {uri}"
            )));
        }
    }
    Ok(())
}

fn validate_structured_locator(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AcdpError> {
    let scheme = map.get("scheme").and_then(|v| v.as_str()).ok_or_else(|| {
        AcdpError::SchemaViolation("structured locator missing required 'scheme'".into())
    })?;
    if !is_dotted_namespace_scheme(scheme) {
        return Err(AcdpError::SchemaViolation(format!(
            "structured locator scheme '{scheme}' must match ^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$"
        )));
    }
    Ok(())
}

fn is_dotted_namespace_scheme(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    parts.iter().all(|part| {
        !part.is_empty()
            && part.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

/// Validate `Body::anchors` / `PublishRequest::anchors`
/// (RFC-ACDP-0016 §4). Called only when the field is `Some` — an
/// absent field needs no validation, and the caller is responsible for
/// the absent-vs-null distinction (`de_present` on the field itself).
fn validate_anchors(anchors: &[AnchorEntry]) -> Result<(), AcdpError> {
    if anchors.is_empty() {
        return Err(AcdpError::SchemaViolation(
            "anchors MUST be omitted entirely (never sent as an empty array) when there is \
             nothing to anchor — the absent-when-empty convention (RFC-ACDP-0016 \u{a7}4)"
                .into(),
        ));
    }
    validate_unique_array("anchors", anchors, MAX_ANCHORS)?;
    for anchor in anchors {
        if !is_dotted_namespace_scheme(&anchor.scheme) {
            return Err(AcdpError::SchemaViolation(format!(
                "anchor scheme '{}' must match ^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$ \
                 (RFC-ACDP-0016 \u{a7}4)",
                anchor.scheme
            )));
        }
        ContentHash::parse(anchor.content_hash.as_str())?;
    }
    Ok(())
}

fn validate_embedded(emb: &EmbeddedContent) -> Result<(), AcdpError> {
    // utf8 / base64: content MUST be a JSON string
    match emb.encoding {
        EmbeddedEncoding::Utf8 | EmbeddedEncoding::Base64 => {
            if !emb.content.is_string() {
                return Err(AcdpError::SchemaViolation(format!(
                    "embedded {:?} content MUST be a JSON string",
                    emb.encoding
                )));
            }
        }
        EmbeddedEncoding::Json => {}
    }
    // Decoded size cap
    let decoded = embedded_decoded_bytes(emb)?;
    if decoded.len() > MAX_EMBEDDED_BYTES {
        return Err(AcdpError::EmbeddedTooLarge(format!(
            "embedded decoded size {} bytes exceeds {} limit",
            decoded.len(),
            MAX_EMBEDDED_BYTES
        )));
    }
    Ok(())
}

/// Decode an [`EmbeddedContent`] to its canonical byte form per
/// `acdp-data-ref.schema.json` `content_hash` semantics:
/// - `json`   → JCS-canonicalized bytes
/// - `utf8`   → raw UTF-8 bytes of the string
/// - `base64` → base64-decoded bytes of the string
pub fn embedded_decoded_bytes(emb: &EmbeddedContent) -> Result<Vec<u8>, AcdpError> {
    Ok(match emb.encoding {
        EmbeddedEncoding::Json => try_canonicalize_value(&emb.content)?,
        EmbeddedEncoding::Utf8 => {
            let s = emb.content.as_str().ok_or_else(|| {
                AcdpError::SchemaViolation("utf8 embedded content must be a JSON string".into())
            })?;
            s.as_bytes().to_vec()
        }
        EmbeddedEncoding::Base64 => {
            let s = emb.content.as_str().ok_or_else(|| {
                AcdpError::SchemaViolation("base64 embedded content must be a JSON string".into())
            })?;
            STANDARD
                .decode(s)
                .map_err(|e| AcdpError::SchemaViolation(format!("base64 decode failed: {e}")))?
        }
    })
}

/// Compute the SHA-256 [`ContentHash`] of decoded embedded content.
pub fn compute_embedded_hash(emb: &EmbeddedContent) -> Result<ContentHash, AcdpError> {
    let bytes = embedded_decoded_bytes(emb)?;
    let digest = Sha256::digest(&bytes);
    Ok(ContentHash(format!("sha256:{}", hex::encode(digest))))
}

/// Verify a [`DataRef`]'s declared content hash(es) against its embedded
/// payload. Does nothing if the ref has no `embedded`.
///
/// RFC-ACDP-0002 §6.6 ("Check 8") scopes the publish-time integrity
/// obligation to `embedded.content_hash`: when present, it MUST match the
/// SHA-256 of the decoded `embedded.content` bytes. The DataRef-root
/// `content_hash` (§6.1) carries no obligation for embedded refs — a
/// registry "MAY additionally verify" it, but MUST NOT reject a publish
/// merely because both fields are present. This function checks **both
/// fields when both are present**: that satisfies §6.6's two hard
/// requirements (verify `embedded.content_hash`; don't reject on
/// co-presence alone) while also preserving the pre-existing root-hash
/// check that consumer-side `location`-form fetch verification
/// (`acdp-client`) depends on — dropping the root check for embedded refs
/// would silently regress that coverage. A mismatch on *either* field is a
/// *data-reference-level* integrity failure ([`AcdpError::DataRefHashMismatch`],
/// wire code `data_ref_hash_mismatch`) — the embedded bytes diverged from a
/// producer-declared hash, but the body's own `content_hash` / signature are
/// unaffected. It is NOT the body-level [`AcdpError::HashMismatch`]
/// (RFC-ACDP-0007 §5, data-ref-007).
pub fn verify_embedded_hash(dr: &DataRef) -> Result<(), AcdpError> {
    let Some(emb) = &dr.embedded else {
        return Ok(());
    };
    if dr.content_hash.is_none() && emb.content_hash.is_none() {
        return Ok(());
    }
    let recomputed = compute_embedded_hash(emb)?;
    if let Some(embedded_hash) = &emb.content_hash {
        if &recomputed != embedded_hash {
            return Err(AcdpError::DataRefHashMismatch(format!(
                "embedded.content_hash mismatch: declared {}, computed {}",
                embedded_hash.as_str(),
                recomputed.as_str()
            )));
        }
    }
    if let Some(root_hash) = &dr.content_hash {
        if &recomputed != root_hash {
            return Err(AcdpError::DataRefHashMismatch(format!(
                "content_hash mismatch: declared {}, computed {}",
                root_hash.as_str(),
                recomputed.as_str()
            )));
        }
    }
    Ok(())
}

// ── Metadata ─────────────────────────────────────────────────────────────────

/// Validate `metadata`'s runtime invariants per RFC-ACDP-0002 §3.3:
/// max 100 top-level properties, max 8 nesting levels, max 64 KB JCS size.
pub fn validate_metadata(value: &serde_json::Value) -> Result<(), AcdpError> {
    validate_json_object_limits(value, "metadata")
}

/// Shared object-limit check for any producer-controlled free-form JSON
/// object (`metadata` and the flattened `extensions`): max 100 top-level
/// properties, max 8 nesting levels, max 64 KB JCS size. Without this,
/// `extensions` (P1-3) would carry unbounded keys/values into JCS+SHA-256.
fn validate_json_object_limits(value: &serde_json::Value, field: &str) -> Result<(), AcdpError> {
    let obj = value
        .as_object()
        .ok_or_else(|| AcdpError::SchemaViolation(format!("{field} must be a JSON object")))?;
    if obj.len() > MAX_METADATA_PROPERTIES {
        return Err(AcdpError::SchemaViolation(format!(
            "{field} has {} top-level properties, exceeds {} limit",
            obj.len(),
            MAX_METADATA_PROPERTIES
        )));
    }
    let depth = json_depth(value);
    if depth > MAX_METADATA_DEPTH {
        return Err(AcdpError::SchemaViolation(format!(
            "{field} nesting depth {depth} exceeds {MAX_METADATA_DEPTH}"
        )));
    }
    let canonical_size = try_canonicalize_value(value)?.len();
    if canonical_size > MAX_METADATA_JCS_BYTES {
        return Err(AcdpError::SchemaViolation(format!(
            "{field} JCS-canonical size {canonical_size} bytes exceeds {MAX_METADATA_JCS_BYTES}"
        )));
    }
    Ok(())
}

/// Validate the flattened forward-compatibility `extensions` object with
/// the same property-count / depth / JCS-size caps as `metadata`.
pub fn validate_extensions(
    extensions: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AcdpError> {
    if extensions.is_empty() {
        return Ok(());
    }
    // Wrap in a `Value::Object` (clones the map) so the shared
    // object-limit walker can scan it; `extensions` is small and capped,
    // so the clone is negligible.
    let value = serde_json::Value::Object(extensions.clone());
    validate_json_object_limits(&value, "extensions")
}

/// Depth measured per RFC-ACDP-0002 §3.3: nested-object/array count,
/// not counting leaf scalars. The cap of 8 is inclusive (`≤ 8`).
/// `meta-003` pins this boundary.
///
/// Recursion is bounded by `MAX_JSON_DEPTH_SCAN` (well above the §3.3 cap
/// of 8 and serde_json's 128-level parse limit) so a pathologically deep
/// programmatically-built `Value` cannot blow the stack here. Any value
/// that reaches the budget already exceeds `MAX_METADATA_DEPTH`, so the
/// caller rejects it regardless of the exact (clamped) count.
fn json_depth(v: &serde_json::Value) -> usize {
    /// Above §3.3's cap of 8 and serde's 128 parse limit; bounds stack use.
    const MAX_JSON_DEPTH_SCAN: usize = 256;
    fn go(v: &serde_json::Value, budget: usize) -> usize {
        if budget == 0 {
            return 1; // stop descending; already far over MAX_METADATA_DEPTH
        }
        match v {
            serde_json::Value::Object(map) => {
                1 + map.values().map(|x| go(x, budget - 1)).max().unwrap_or(0)
            }
            serde_json::Value::Array(arr) => {
                1 + arr.iter().map(|x| go(x, budget - 1)).max().unwrap_or(0)
            }
            _ => 0,
        }
    }
    go(v, MAX_JSON_DEPTH_SCAN)
}

// ── Visibility ───────────────────────────────────────────────────────────────

fn validate_visibility_audience(
    vis: &Visibility,
    audience: Option<&[AgentDid]>,
) -> Result<(), AcdpError> {
    match vis {
        Visibility::Restricted => {
            if audience.is_none_or(|a| a.is_empty()) {
                return Err(AcdpError::SchemaViolation(
                    "visibility:restricted requires a non-empty audience".into(),
                ));
            }
        }
        Visibility::Public => {
            if audience.is_some_and(|a| !a.is_empty()) {
                return Err(AcdpError::SchemaViolation(
                    "visibility:public MUST NOT include audience".into(),
                ));
            }
        }
        Visibility::Private => {}
    }
    Ok(())
}

// ── Strings & arrays ─────────────────────────────────────────────────────────

fn validate_title(title: &str) -> Result<(), AcdpError> {
    if title.is_empty() || title.chars().count() > MAX_TITLE_LEN {
        return Err(AcdpError::SchemaViolation(format!(
            "title length {} not in 1..={}",
            title.chars().count(),
            MAX_TITLE_LEN
        )));
    }
    Ok(())
}

fn validate_optional_string(s: Option<&str>, name: &str, max_len: usize) -> Result<(), AcdpError> {
    if let Some(value) = s {
        if value.chars().count() > max_len {
            return Err(AcdpError::SchemaViolation(format!(
                "{name} length {} exceeds {max_len}",
                value.chars().count()
            )));
        }
    }
    Ok(())
}

fn validate_unique_array<T: PartialEq + std::fmt::Debug>(
    name: &str,
    items: &[T],
    max: usize,
) -> Result<(), AcdpError> {
    if items.len() > max {
        return Err(AcdpError::SchemaViolation(format!(
            "{name} has {} items, exceeds {max}",
            items.len()
        )));
    }
    for (i, item) in items.iter().enumerate() {
        if items[i + 1..].iter().any(|other| other == item) {
            return Err(AcdpError::SchemaViolation(format!(
                "{name} contains duplicate entry: {item:?}"
            )));
        }
    }
    Ok(())
}

fn validate_tags(tags: &[String]) -> Result<(), AcdpError> {
    if tags.len() > MAX_TAGS {
        return Err(AcdpError::SchemaViolation(format!(
            "tags has {} entries, exceeds {}",
            tags.len(),
            MAX_TAGS
        )));
    }
    for tag in tags {
        validate_tag(tag)?;
    }
    // Uniqueness
    for (i, tag) in tags.iter().enumerate() {
        if tags[i + 1..].iter().any(|t| t == tag) {
            return Err(AcdpError::SchemaViolation(format!(
                "tags contains duplicate entry: {tag}"
            )));
        }
    }
    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), AcdpError> {
    if tag.is_empty() || tag.len() > MAX_TAG_LEN {
        return Err(AcdpError::SchemaViolation(format!(
            "tag '{tag}' length not in 1..={MAX_TAG_LEN}"
        )));
    }
    let mut chars = tag.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err(AcdpError::SchemaViolation(format!(
            "tag '{tag}' first char must be alphanumeric"
        )));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')) {
        return Err(AcdpError::SchemaViolation(format!(
            "tag '{tag}' must match [A-Za-z0-9][A-Za-z0-9_.-]*"
        )));
    }
    Ok(())
}

// ── DID / agent_id ───────────────────────────────────────────────────────────

/// Validate a DID used as `agent_id`.
///
/// Producers MUST use a resolvable method: `did:web` (RFC-ACDP-0001
/// §5.4, the v0.1.0 baseline) or `did:key` (ACDP 0.2 — pure offline
/// resolution; the DID is the key). For did:key the embedded key
/// material is decoded here so a garbage identifier fails at schema
/// validation rather than at signature verification. Whether a given
/// *registry* accepts did:key producers is a capabilities decision
/// (`supported_did_methods`), enforced by
/// `registry::PublishValidator` — this function checks protocol-level
/// well-formedness only.
/// Validate the `signature.key_id` form when it is a `did:key` URL
/// (ACDP 0.2). The only verification method a did:key document has is
/// the key itself, so the fragment MUST equal the method-specific
/// identifier and the key material MUST decode. No-op for other
/// methods — their key_id resolves against a DID document at
/// verification time.
fn validate_did_key_key_id_form(key_id: &str) -> Result<(), AcdpError> {
    if !key_id.starts_with("did:key:") {
        return Ok(());
    }
    // RFC-ACDP-0001 §5.11.1: any did:key resolver fault (steps 1-4) is
    // REQUIRED to surface as `key_resolution_failed`. `schema_violation` is
    // only a spec-tolerated MAY-level alternative for a registry's own
    // stricter grammar on steps 1-2 (dk-002's own
    // `expected.alternative_applies_to_cases: [1, 2]` proves the tolerance
    // is narrower than "all did:key resolver faults") — never a
    // requirement, so propagating the resolver's own `AcdpError::KeyResolution`
    // unconditionally is conformant for all did:key fixtures and needs no
    // step-level distinction the resolver doesn't expose anyway.
    acdp_did::key::resolve_did_key_url(key_id)?;
    Ok(())
}

fn validate_agent_did(did: &AgentDid) -> Result<(), AcdpError> {
    if did.as_str().starts_with("did:key:") {
        AgentDid::parse(did.as_str())?;
        // See validate_did_key_key_id_form above: propagate the resolver's
        // own AcdpError::KeyResolution rather than downgrading to
        // SchemaViolation.
        acdp_did::key::resolve_did_key(did.as_str())?;
        return Ok(());
    }
    AgentDid::parse_web(did.as_str())?;
    Ok(())
}

/// Validate `body.origin_registry` per `acdp-context-body.schema.json`
/// (RFC-ACDP-0002 §3.1, fixture body-001/body-002).
///
/// MUST be a bare DNS hostname — NOT a `did:web:` URI, NOT a URL.
/// `capabilities.registry_did` carries the `did:web` encoding; the
/// stored body carries the hostname encoding. Storing either form in
/// the other field is a conformance violation.
fn validate_origin_registry(s: &str) -> Result<(), AcdpError> {
    if s.is_empty() {
        return Err(AcdpError::SchemaViolation(
            "origin_registry must be a non-empty DNS hostname".into(),
        ));
    }
    if s.starts_with("did:") {
        return Err(AcdpError::SchemaViolation(format!(
            "origin_registry must be a DNS hostname, not a DID URI (got '{s}'); \
             use the bare authority — capabilities.registry_did carries the did:web form"
        )));
    }
    if s.contains("://") {
        return Err(AcdpError::SchemaViolation(format!(
            "origin_registry must be a DNS hostname, not a URL (got '{s}')"
        )));
    }
    if s.ends_with('.') || s.starts_with('.') {
        return Err(AcdpError::SchemaViolation(format!(
            "origin_registry must be a syntactically valid DNS hostname (got '{s}')"
        )));
    }
    // BUG-02: delegate the full hostname grammar to the same validator
    // `CtxId::parse` uses for its authority. Enforces lowercase-only,
    // no underscore, no port, and valid label structure — values like
    // `REGISTRY.EXAMPLE.COM`, `registry_example.com`, or `registry-.com`
    // pass the coarse checks above but are not schema-valid hostnames.
    if !acdp_types::primitives::is_valid_dns_authority(s) {
        return Err(AcdpError::SchemaViolation(format!(
            "origin_registry '{s}' is not a valid DNS hostname (must be lowercase \
             labels of [a-z0-9-] separated by dots, e.g. 'registry.example.com')"
        )));
    }
    Ok(())
}

/// Validate a DID used in `contributors[]` or `audience[]`.
///
/// Per the spec plan's RFC-FIX-11 method-scope table:
/// - contributors[] SHOULD be `did:web` (attribution; no key resolution),
/// - audience[] MAY be any DID method (authorization list; not resolved
///   in v0.1.0).
///
/// This helper enforces only the loose `did:` syntax (no method
/// constraint) so other-method contributors are accepted.
fn validate_loose_did(did: &AgentDid) -> Result<(), AcdpError> {
    AgentDid::parse(did.as_str())?;
    Ok(())
}

// ── Context type ─────────────────────────────────────────────────────────────

fn validate_namespaced_context_type(value: &str) -> Result<(), AcdpError> {
    // Schema pattern: ^[a-z][a-z0-9_]*:[a-z][a-z0-9_-]*$
    let (ns, name) = value.split_once(':').ok_or_else(|| {
        AcdpError::SchemaViolation(format!(
            "context_type '{value}' missing namespace separator"
        ))
    })?;
    if ns.is_empty()
        || !ns.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        || !ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(AcdpError::SchemaViolation(format!(
            "context_type namespace '{ns}' must match [a-z][a-z0-9_]*"
        )));
    }
    if name.is_empty()
        || !name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
    {
        return Err(AcdpError::SchemaViolation(format!(
            "context_type name '{name}' must match [a-z][a-z0-9_-]*"
        )));
    }
    Ok(())
}

trait ContextTypeExt {
    fn namespaced_form(&self) -> Option<&str>;
}

impl ContextTypeExt for ContextType {
    fn namespaced_form(&self) -> Option<&str> {
        match self {
            ContextType::Custom(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

// ── Signatures ───────────────────────────────────────────────────────────────

fn validate_semver_pattern(name: &str, value: &str) -> Result<(), AcdpError> {
    let parts: Vec<&str> = value.split('.').collect();
    let ok = parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    if !ok {
        return Err(AcdpError::SchemaViolation(format!(
            "{name} '{value}' must match the semver pattern ^\\d+\\.\\d+\\.\\d+$"
        )));
    }
    Ok(())
}

fn validate_signature_length(algorithm: &str, value_b64: &str) -> Result<(), AcdpError> {
    let expected = match algorithm {
        "ed25519" => Some(ED25519_SIG_B64_LEN),
        "ecdsa-p256" => Some(ECDSA_P256_SIG_B64_LEN),
        _ => None,
    };
    if let Some(n) = expected {
        if value_b64.len() != n {
            return Err(AcdpError::InvalidSignature(format!(
                "signature.value for '{algorithm}' must be {n} base64 chars, got {}",
                value_b64.len()
            )));
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_types::data_ref::DataRefType;
    use serde_json::json;

    fn embedded_json(v: serde_json::Value) -> EmbeddedContent {
        EmbeddedContent {
            encoding: EmbeddedEncoding::Json,
            content: v,
            content_hash: None,
        }
    }

    fn embedded_json_with_hash(v: serde_json::Value, hash: ContentHash) -> EmbeddedContent {
        EmbeddedContent {
            encoding: EmbeddedEncoding::Json,
            content: v,
            content_hash: Some(hash),
        }
    }

    // ── origin_registry (BUG-02) ─────────────────────────────────────────────

    #[test]
    fn origin_registry_accepts_valid_hostname() {
        validate_origin_registry("registry.example.com").unwrap();
        validate_origin_registry("reg.example").unwrap();
        validate_origin_registry("a-b-c.io").unwrap();
    }

    #[test]
    fn origin_registry_rejects_uppercase() {
        assert!(matches!(
            validate_origin_registry("REGISTRY.EXAMPLE.COM"),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn origin_registry_rejects_underscore() {
        assert!(matches!(
            validate_origin_registry("registry_example.com"),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn origin_registry_rejects_hyphen_label_edges() {
        assert!(matches!(
            validate_origin_registry("registry-.com"),
            Err(AcdpError::SchemaViolation(_))
        ));
        assert!(matches!(
            validate_origin_registry("-registry.example.com"),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    // ── DataRef.oneOf ────────────────────────────────────────────────────────

    #[test]
    fn data_ref_neither_location_nor_embedded_rejected() {
        let dr = DataRef {
            ref_type: DataRefType::PrimaryResult,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: None,
            embedded: None,
            extensions: serde_json::Map::new(),
        };
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn data_ref_both_location_and_embedded_rejected() {
        let dr = DataRef {
            ref_type: DataRefType::PrimaryResult,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: Some(Location::Uri("https://x/y".into())),
            embedded: Some(embedded_json(json!({"a": 1}))),
            extensions: serde_json::Map::new(),
        };
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    // ── DataRef.location URI ─────────────────────────────────────────────────

    #[test]
    fn uri_credentials_rejected() {
        let dr = DataRef::uri(DataRefType::RawData, "https://user:pass@example.com/data");
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn uri_without_scheme_rejected() {
        let dr = DataRef::uri(DataRefType::RawData, "no-scheme");
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn uri_too_long_rejected() {
        let long_uri = format!("https://x.com/{}", "a".repeat(MAX_URI_LEN));
        let dr = DataRef::uri(DataRefType::RawData, long_uri);
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    // ── DataRef.location structured ──────────────────────────────────────────

    #[test]
    fn structured_locator_missing_scheme_rejected() {
        let mut map = serde_json::Map::new();
        map.insert("offset".into(), json!(42));
        let dr = DataRef {
            ref_type: DataRefType::RawData,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: Some(Location::Structured(map)),
            embedded: None,
            extensions: serde_json::Map::new(),
        };
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn structured_locator_bad_scheme_rejected() {
        // try_structured rejects at construction time; structured() panics
        // in debug builds. The validate_data_ref guard catches anyone who
        // assembles a `DataRef` literal with a bad scheme directly.
        let err =
            DataRef::try_structured(DataRefType::RawData, "not_dotted", serde_json::Map::new())
                .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));

        // Direct literal construction (skipping the constructor): must
        // also be caught by validate_data_ref.
        let mut bad = serde_json::Map::new();
        bad.insert(
            "scheme".into(),
            serde_json::Value::String("not_dotted".into()),
        );
        let dr = DataRef {
            ref_type: DataRefType::RawData,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: Some(Location::Structured(bad)),
            embedded: None,
            extensions: serde_json::Map::new(),
        };
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn structured_locator_valid() {
        let mut extra = serde_json::Map::new();
        extra.insert("topic".into(), json!("events"));
        let dr = DataRef::structured(DataRefType::RawData, "kafka.offset", extra);
        validate_data_ref(&dr).unwrap();
    }

    // ── DataRef.embedded ─────────────────────────────────────────────────────

    #[test]
    fn embedded_utf8_must_be_string() {
        let dr = DataRef {
            ref_type: DataRefType::PrimaryResult,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: None,
            location: None,
            embedded: Some(EmbeddedContent {
                encoding: EmbeddedEncoding::Utf8,
                content: json!(42),
                content_hash: None,
            }),
            extensions: serde_json::Map::new(),
        };
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn embedded_too_large_rejected() {
        // 70 KB of UTF-8 content
        let big = "a".repeat(70 * 1024);
        let dr = DataRef::embedded_utf8(DataRefType::PrimaryResult, big);
        assert!(matches!(
            validate_data_ref(&dr),
            Err(AcdpError::EmbeddedTooLarge(_))
        ));
    }

    // ── Embedded hash ────────────────────────────────────────────────────────

    #[test]
    fn embedded_hash_json_round_trip() {
        let emb = embedded_json(json!({"b": 2, "a": 1}));
        let h = compute_embedded_hash(&emb).unwrap();
        // JCS sorts keys → {"a":1,"b":2}, hash is deterministic
        let expected = {
            let bytes = b"{\"a\":1,\"b\":2}";
            format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
        };
        assert_eq!(h.as_str(), expected);
    }

    #[test]
    fn embedded_hash_utf8() {
        let emb = EmbeddedContent {
            encoding: EmbeddedEncoding::Utf8,
            content: json!("hello"),
            content_hash: None,
        };
        let h = compute_embedded_hash(&emb).unwrap();
        let expected = format!("sha256:{}", hex::encode(Sha256::digest(b"hello")));
        assert_eq!(h.as_str(), expected);
    }

    #[test]
    fn embedded_hash_base64() {
        let raw = b"binary data";
        let b64 = STANDARD.encode(raw);
        let emb = EmbeddedContent {
            encoding: EmbeddedEncoding::Base64,
            content: json!(b64),
            content_hash: None,
        };
        let h = compute_embedded_hash(&emb).unwrap();
        let expected = format!("sha256:{}", hex::encode(Sha256::digest(raw)));
        assert_eq!(h.as_str(), expected);
    }

    #[test]
    fn verify_embedded_hash_mismatch_detected() {
        let emb = embedded_json(json!({"x": 1}));
        let dr = DataRef {
            ref_type: DataRefType::PrimaryResult,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: Some(ContentHash("sha256:0000".into())),
            location: None,
            embedded: Some(emb),
            extensions: serde_json::Map::new(),
        };
        assert!(matches!(
            verify_embedded_hash(&dr),
            Err(AcdpError::DataRefHashMismatch(_))
        ));
    }

    // ── Metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn metadata_too_many_properties_rejected() {
        let mut obj = serde_json::Map::new();
        for i in 0..101 {
            obj.insert(format!("k{i}"), json!(i));
        }
        assert!(matches!(
            validate_metadata(&serde_json::Value::Object(obj)),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn metadata_too_deep_rejected() {
        // Build an object nested 10 levels deep
        let mut v = json!("leaf");
        for _ in 0..10 {
            let mut o = serde_json::Map::new();
            o.insert("a".into(), v);
            v = serde_json::Value::Object(o);
        }
        assert!(matches!(
            validate_metadata(&v),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn metadata_too_large_rejected() {
        let big = "a".repeat(70 * 1024);
        let v = json!({"big": big});
        assert!(matches!(
            validate_metadata(&v),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn metadata_must_be_object() {
        assert!(matches!(
            validate_metadata(&json!([1, 2, 3])),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    // ── Visibility / audience ────────────────────────────────────────────────

    #[test]
    fn public_with_audience_rejected() {
        let aud = vec![AgentDid::new("did:web:x")];
        assert!(matches!(
            validate_visibility_audience(&Visibility::Public, Some(&aud)),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn public_with_empty_audience_ok() {
        validate_visibility_audience(&Visibility::Public, Some(&[])).unwrap();
        validate_visibility_audience(&Visibility::Public, None).unwrap();
    }

    #[test]
    fn restricted_without_audience_rejected() {
        assert!(matches!(
            validate_visibility_audience(&Visibility::Restricted, None),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    // ── data_period ──────────────────────────────────────────────────────────

    #[test]
    fn data_period_start_after_end_rejected_via_builder() {
        use acdp_crypto::SigningKey;
        use acdp_producer::Producer;
        use acdp_types::body::DataPeriod;
        use chrono::TimeZone;

        let p = Producer::new(
            SigningKey::from_bytes(&[0u8; 32]),
            AgentDid::new("did:web:agents.example.com:test"),
            "did:web:agents.example.com:test#key-1",
        );
        let err = p
            .publish_request()
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .data_period(DataPeriod {
                start: chrono::Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap(),
                end: chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            })
            .build()
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    // ── Tags ─────────────────────────────────────────────────────────────────

    #[test]
    fn tag_pattern_validation() {
        validate_tag("hello").unwrap();
        validate_tag("Q1-2026").unwrap();
        validate_tag("a_b.c").unwrap();
        // Cannot start with non-alphanumeric
        assert!(validate_tag("-bad").is_err());
        // Disallowed chars
        assert!(validate_tag("space here").is_err());
        // Empty
        assert!(validate_tag("").is_err());
    }

    #[test]
    fn duplicate_tags_rejected() {
        let tags = vec!["a".to_string(), "b".to_string(), "a".to_string()];
        assert!(validate_tags(&tags).is_err());
    }

    // ── Signature length ─────────────────────────────────────────────────────

    #[test]
    fn ed25519_sig_must_be_88_chars() {
        assert!(validate_signature_length("ed25519", "AAAA").is_err());
        validate_signature_length("ed25519", &"A".repeat(88)).unwrap();
        // Unknown algorithm: skipped
        validate_signature_length("future-alg", "any").unwrap();
    }

    // ── context_type custom ──────────────────────────────────────────────────

    #[test]
    fn namespaced_context_type_pattern() {
        validate_namespaced_context_type("finance:portfolio_snapshot").unwrap();
        assert!(validate_namespaced_context_type("Finance:portfolio").is_err());
        assert!(validate_namespaced_context_type("finance:Portfolio").is_err());
        assert!(validate_namespaced_context_type("no-colon").is_err());
    }

    // ── R2 audit test-coverage matrix ────────────────────────────────────────

    /// T8 — `acdp_version` semver pattern is enforced.
    #[test]
    fn acdp_version_pattern_rejects_non_semver() {
        validate_semver_pattern("acdp_version", "0.1.0").unwrap();
        validate_semver_pattern("acdp_version", "10.20.30").unwrap();
        assert!(validate_semver_pattern("acdp_version", "0.1.0-rc.1").is_err());
        assert!(validate_semver_pattern("acdp_version", "0.0").is_err());
        assert!(validate_semver_pattern("acdp_version", "vee.zero.zero").is_err());
    }

    /// T7 — `derived_from` containing a malformed ctx_id is rejected by
    /// `validate_publish_request`.
    #[test]
    fn derived_from_malformed_ctx_id_rejected() {
        use acdp_crypto::SigningKey;
        use acdp_producer::Producer;

        let p = Producer::new(
            SigningKey::from_bytes(&[0u8; 32]),
            AgentDid::new("did:web:agents.example.com:test"),
            "did:web:agents.example.com:test#key-1",
        );
        let err = p
            .publish_request()
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .derived_from(vec![CtxId("not-a-ctx-id".into())])
            .build()
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    /// T2 — Embedded `content_hash` mismatch caught by
    /// `verify_embedded_hash`.
    #[test]
    fn embedded_content_hash_mismatch_caught() {
        use acdp_types::data_ref::DataRefType;
        let dr = DataRef {
            ref_type: DataRefType::PrimaryResult,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: Some(ContentHash("sha256:0000".into())),
            location: None,
            embedded: Some(EmbeddedContent {
                encoding: EmbeddedEncoding::Json,
                content: json!({"x": 1}),
                content_hash: None,
            }),
            extensions: serde_json::Map::new(),
        };
        assert!(matches!(
            verify_embedded_hash(&dr),
            Err(AcdpError::DataRefHashMismatch(_))
        ));
    }

    /// RFC-ACDP-0002 §6.6: a DataRef carrying both root `content_hash` and
    /// `embedded.content_hash` over the same, *consistent* decoded bytes
    /// MUST be accepted.
    #[test]
    fn both_content_hashes_consistent_accepted() {
        use acdp_types::data_ref::DataRefType;
        let emb = embedded_json(json!({"a": 1, "b": 2}));
        let hash = compute_embedded_hash(&emb).unwrap();
        let dr = DataRef {
            ref_type: DataRefType::PrimaryResult,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: Some(hash.clone()),
            location: None,
            embedded: Some(embedded_json_with_hash(json!({"a": 1, "b": 2}), hash)),
            extensions: serde_json::Map::new(),
        };
        verify_embedded_hash(&dr).unwrap();
    }

    /// RFC-ACDP-0002 §6.6: when root `content_hash` and
    /// `embedded.content_hash` disagree, the ref MUST be rejected with
    /// `DataRefHashMismatch` — checking both fields is the natural
    /// consequence of Check 8, not a new rule.
    #[test]
    fn both_content_hashes_disagree_rejected() {
        use acdp_types::data_ref::DataRefType;
        let emb = embedded_json(json!({"a": 1, "b": 2}));
        let correct_hash = compute_embedded_hash(&emb).unwrap();
        let wrong_hash = ContentHash(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        );
        // embedded.content_hash is correct, root content_hash disagrees with the
        // actual decoded bytes — Check 8 passes, but the (still-checked) root
        // comparison catches the disagreement.
        let dr = DataRef {
            ref_type: DataRefType::PrimaryResult,
            description: None,
            size_bytes: None,
            format: None,
            schema_version: None,
            content_hash: Some(wrong_hash),
            location: None,
            embedded: Some(embedded_json_with_hash(
                json!({"a": 1, "b": 2}),
                correct_hash,
            )),
            extensions: serde_json::Map::new(),
        };
        assert!(matches!(
            verify_embedded_hash(&dr),
            Err(AcdpError::DataRefHashMismatch(_))
        ));
    }

    /// T14 — duplicate audience entries rejected (uniqueItems: true).
    #[test]
    fn audience_uniqueness_rejected() {
        let dup = vec![
            AgentDid::new("did:web:a.example.com"),
            AgentDid::new("did:web:a.example.com"),
        ];
        let err = validate_unique_array("audience", &dup, MAX_AUDIENCE).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    // ── P1-3: extensions caps + bounded walkers ──────────────────────────────

    #[test]
    fn extensions_empty_ok() {
        validate_extensions(&serde_json::Map::new()).unwrap();
    }

    #[test]
    fn extensions_small_forward_compat_accepted() {
        // The can-008/can-009 shape: a couple of unknown producer fields.
        let mut ext = serde_json::Map::new();
        ext.insert("priority".into(), json!("high"));
        ext.insert("custom".into(), json!({"k": [1, 2, 3]}));
        validate_extensions(&ext).unwrap();
    }

    #[test]
    fn extensions_too_many_properties_rejected() {
        let mut ext = serde_json::Map::new();
        for i in 0..(MAX_METADATA_PROPERTIES + 1) {
            ext.insert(format!("k{i}"), json!(i));
        }
        let err = validate_extensions(&ext).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn extensions_oversized_jcs_rejected() {
        let mut ext = serde_json::Map::new();
        ext.insert("blob".into(), json!("x".repeat(MAX_METADATA_JCS_BYTES + 1)));
        let err = validate_extensions(&ext).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn extensions_too_deep_rejected() {
        // Build a value nested past MAX_METADATA_DEPTH.
        let mut v = json!(0);
        for _ in 0..(MAX_METADATA_DEPTH + 2) {
            v = json!({ "n": v });
        }
        let mut ext = serde_json::Map::new();
        ext.insert("deep".into(), v);
        let err = validate_extensions(&ext).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn json_depth_clamps_past_scan_budget() {
        // Deeper than the 256-frame scan budget but shallow enough that
        // building/dropping the Value is itself safe. `json_depth` must
        // bound its own recursion and still report a value over the §3.3
        // cap, and the canonicalizer must refuse it rather than overflow.
        let mut v = json!(0);
        for _ in 0..400 {
            v = json!([v]);
        }
        assert!(json_depth(&v) > MAX_METADATA_DEPTH);
        assert!(acdp_crypto::try_canonicalize_value(&v).is_err());
    }
}

#[cfg(test)]
mod capabilities_0_3_0_tests {
    use super::*;
    use acdp_types::capabilities::{CapabilitiesDocument, Limits};

    fn caps(version: &str, supports_idem: bool, mppm: Option<u64>) -> CapabilitiesDocument {
        CapabilitiesDocument {
            acdp_version: version.into(),
            registry_did: "did:web:registry.example.com".into(),
            supported_signature_algorithms: vec!["ed25519".into()],
            supported_did_methods: vec!["did:web".into()],
            profiles: vec!["acdp-registry-core".into()],
            limits: Limits {
                max_payload_bytes: 1_048_576,
                max_embedded_bytes: 65_536,
                idempotency_key_ttl_seconds: if supports_idem { Some(86_400) } else { None },
                max_publish_per_minute: mppm,
            },
            read_authentication_methods: vec![],
            anonymous_public_reads: false,
            supports_idempotency_key: supports_idem,
            extensions: Default::default(),
        }
    }

    /// RFC-ACDP-0007 §3.5 item 11 *(0.3.0)* — caps-007's reject variants:
    /// zero is rejected at validation; the ≥1 accept case passes.
    #[test]
    fn max_publish_per_minute_bounds() {
        assert!(validate_capabilities(&caps("0.1.0", false, Some(600))).is_ok());
        let err = validate_capabilities(&caps("0.1.0", false, Some(0)))
            .expect_err("zero MUST be rejected");
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    /// RFC-ACDP-0003 §6.4 / RFC-ACDP-0007 §3.5 item 10 *(0.3.0)* — the
    /// idem-007 rule: acdp_version ≥ 0.3.0 without idempotency support
    /// is self-contradictory and MUST be rejected; 0.1.0/0.2.0 without
    /// support stay valid; 0.3.0 with support is valid.
    #[test]
    fn idempotency_required_at_0_3_0() {
        assert!(validate_capabilities(&caps("0.1.0", false, None)).is_ok());
        assert!(validate_capabilities(&caps("0.2.0", false, None)).is_ok());
        assert!(validate_capabilities(&caps("0.3.0", true, None)).is_ok());
        assert!(validate_capabilities(&caps("0.4.0", true, None)).is_ok());
        for v in ["0.3.0", "0.4.0", "1.0.0"] {
            let err = validate_capabilities(&caps(v, false, None))
                .expect_err("version >= 0.3.0 without idempotency MUST be rejected");
            assert!(matches!(err, AcdpError::SchemaViolation(_)), "{v}: {err:?}");
        }
    }
}
