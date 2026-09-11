//! High-level body / publish-request verification — RFC-ACDP-0001 §5.11
//! (7-step algorithm).
//!
//! This layer sits above `validation`, `types`, `crypto`, and `did`: it
//! recomputes the `content_hash`, runs structural validation, resolves
//! the producer DID, and verifies the signature envelope. The byte-level
//! primitives ([`acdp_crypto::verify_ed25519`] /
//! [`acdp_crypto::verify_ecdsa_p256`]) live in `crypto`.

use acdp_crypto::{verify_content_hash, verify_ecdsa_p256, verify_ed25519};
use acdp_primitives::error::AcdpError;
use acdp_types::body::{Body, Signature};
use acdp_types::lifecycle::LifecycleEvent;
use acdp_types::primitives::{AgentDid, ContentHash, CtxId};
use acdp_types::publish::PublishRequest;

#[cfg(feature = "client")]
use acdp_did::web::WebResolver;

/// Stateless verifier.  Requires a DID resolver to fetch producer keys.
#[cfg(feature = "client")]
pub struct Verifier<'a> {
    resolver: &'a WebResolver,
}

#[cfg(feature = "client")]
impl<'a> Verifier<'a> {
    pub fn new(resolver: &'a WebResolver) -> Self {
        Self { resolver }
    }

    /// Full end-to-end verification per RFC-ACDP-0001 §5.11.
    ///
    /// Steps:
    ///  1. (Implicit) Check `key_id` has a `#fragment`.
    ///  2. Verify `key_id` DID portion equals `body.agent_id`.
    ///  3. Resolve the DID document.
    ///  4. Find the verification method by fragment.
    ///  5. Check `assertionMethod` authorization.
    ///  6. Extract the Ed25519 public key.
    ///  7. Verify the signature over the content_hash ASCII bytes.
    ///
    ///  (Hash recomputation is step 0, performed first.)
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(
            name = "acdp.verify_body",
            skip_all,
            fields(ctx_id = %body.ctx_id.0, agent_id = body.agent_id.as_str()),
            err(Display)
        )
    )]
    pub async fn verify_body(&self, body: &Body) -> Result<(), AcdpError> {
        // Step -1 (BUG-04): structural / runtime validation. A body may be
        // cryptographically correct but protocol-invalid (non-did:web
        // producer, inverted data_period, oversize metadata). Catch those
        // before paying the SHA-256 + DID resolution cost.
        acdp_validation::validate_body(body)?;

        self.verify_body_signed(body).await
    }

    /// Verify only the hash recomputation + DID resolution + signature
    /// envelope, assuming structural validation has already been done by
    /// the caller. Use when you want to separate structural failures
    /// from cryptographic ones — e.g. [`Self::verify_body`] itself runs
    /// `acdp_validation::validate_body` first and then delegates the
    /// hash + signature phases to this method, so the two concerns stay
    /// independently testable.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(
            name = "acdp.verify_body_signed",
            skip_all,
            fields(ctx_id = %body.ctx_id.0),
            err(Display)
        )
    )]
    pub async fn verify_body_signed(&self, body: &Body) -> Result<(), AcdpError> {
        self.verify_body_hash(body)?;
        #[cfg(feature = "tracing")]
        tracing::debug!(
            stage = "content_hash",
            "content hash recomputed and matched"
        );
        self.verify_body_signature(body).await?;
        #[cfg(feature = "tracing")]
        tracing::debug!(stage = "signature", "producer signature verified");
        Ok(())
    }

    /// Step 0 only — recompute the `content_hash` over ProducerContent
    /// and compare against `body.content_hash`. Lets diagnostic
    /// callers record hash-pass/fail independently of the signature
    /// stage (FEAT-05).
    pub fn verify_body_hash(&self, body: &Body) -> Result<(), AcdpError> {
        let body_val = serde_json::to_value(body)?;
        verify_content_hash(&body_val, &body.content_hash)
    }

    /// Steps 1–7 only — resolve the producer's DID, find the signing
    /// key, verify the signature over the (already-stored)
    /// `body.content_hash`. Assumes [`Self::verify_body_hash`] (or an
    /// equivalent check) has already run.
    pub async fn verify_body_signature(&self, body: &Body) -> Result<(), AcdpError> {
        verify_signature_envelope(
            &body.agent_id,
            &body.signature,
            &body.content_hash,
            self.resolver,
        )
        .await
    }
}

/// Verify the producer signature on a [`PublishRequest`] per RFC-ACDP-0003
/// §2.1 steps 7–8.
///
/// Assumes structural validation and `content_hash` recomputation have
/// already been performed (e.g. by `acdp::registry::PublishValidator::validate_post_schema`).
/// Executes only the DID resolution + signature verification steps shared
/// with [`Verifier::verify_body`].
///
/// Used by `acdp::registry::RegistryServer::publish_verified` to fulfill
/// the §2.1 publish algorithm before persistence; consumers wanting end-to-end
/// verification on retrieval should prefer
/// `acdp::client::VerifiedContext::fetch` which calls [`Verifier::verify_body`].
#[cfg(feature = "client")]
#[cfg_attr(
    feature = "tracing",
    tracing::instrument(
        name = "acdp.verify_publish_request_signature",
        skip_all,
        fields(agent_id = req.agent_id.as_str(), key_id = %req.signature.key_id),
        err(Display)
    )
)]
pub async fn verify_publish_request_signature(
    req: &PublishRequest,
    resolver: &WebResolver,
) -> Result<(), AcdpError> {
    verify_signature_envelope(&req.agent_id, &req.signature, &req.content_hash, resolver).await
}

/// Steps 1–7 of RFC-ACDP-0001 §5.11 — the part of body verification that
/// operates only on the signature envelope and is identical for stored
/// `Body` values and incoming `PublishRequest` values. Caller is responsible
/// for hash recomputation (step 0).
#[cfg(feature = "client")]
async fn verify_signature_envelope(
    agent_id: &AgentDid,
    signature: &Signature,
    content_hash: &ContentHash,
    resolver: &WebResolver,
) -> Result<(), AcdpError> {
    // Step 1: parse key_id — must contain a non-empty '#' fragment
    // (RFC-ACDP-0001 §5.11 step 1). An empty fragment (`did:web:x#`) is
    // rejected rather than used as a lookup key (#22).
    let key_id = &signature.key_id;
    let (did_part, fragment) = key_id.split_once('#').ok_or_else(|| {
        AcdpError::KeyResolution(format!("signature.key_id '{key_id}' has no '#fragment'"))
    })?;
    if fragment.is_empty() {
        return Err(AcdpError::KeyResolution(format!(
            "signature.key_id '{key_id}' has an empty '#fragment'"
        )));
    }

    // Step 2: DID portion MUST equal agent_id
    if did_part != agent_id.as_str() {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "key_id DID '{did_part}' ≠ agent_id '{agent_id}'"
        )));
    }

    // Step 1.5: method dispatch. `did:key` resolves purely (the DID is
    // the key — no document fetch, no assertionMethod check); `did:web`
    // takes the HTTPS resolver path below. Any other method has no
    // resolver in this version.
    if did_part.starts_with("did:key:") {
        return verify_did_key_envelope(signature, content_hash);
    }
    if !did_part.starts_with("did:web:") {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "signatures require a did:web or did:key key_id; got '{did_part}'"
        )));
    }

    // Step 3: resolve DID document
    let doc = resolver.resolve(did_part).await?;

    // Step 4: find verification method by fragment
    let method = doc.find_by_fragment(fragment).ok_or_else(|| {
        AcdpError::KeyResolution(format!(
            "no verification method with fragment '#{fragment}'"
        ))
    })?;

    // Step 5: assertionMethod authorization
    if !doc.is_assertion_method(&method.id) {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "'{}' is not in assertionMethod",
            method.id
        )));
    }

    // Step 5.5: algorithm-downgrade rejection (RFC-ACDP-0008 §3.9 +
    // RFC-ACDP-0001 §5.11 step 6). When the verification method declares
    // an algorithm via its `type` (or `publicKeyJwk` params), it MUST equal
    // `signature.algorithm`. Otherwise an attacker could route an Ed25519
    // key through a verifier that thinks it's checking some other algorithm.
    if let Some(declared) = method.declared_algorithm() {
        if declared != signature.algorithm {
            return Err(AcdpError::InvalidSignature(format!(
                "signature.algorithm '{}' does not match verification method type \
                 (resolved key declares '{declared}')",
                signature.algorithm
            )));
        }
    }

    // Steps 6 + 7: dispatch by algorithm.
    match signature.algorithm.as_str() {
        "ed25519" => {
            let pub_bytes = method.ed25519_public_key_bytes()?;
            verify_ed25519(&pub_bytes, &signature.value, content_hash.as_str())
        }
        "ecdsa-p256" => {
            let pub_sec1 = method.ecdsa_p256_public_key_sec1()?;
            verify_ecdsa_p256(&pub_sec1, &signature.value, content_hash.as_str())
        }
        other => Err(AcdpError::UnsupportedAlgorithm(format!(
            "verifier does not support signature algorithm '{other}'"
        ))),
    }
}

/// Verify a signature envelope whose key is a `did:key` — a pure
/// function available without the `client` feature (no resolver, no
/// network, no async).
///
/// Performs:
/// 1. `key_id` form check (`did:key:z<mb>#z<mb>`, fragment = key).
/// 2. Pure key resolution from the DID itself.
/// 3. Algorithm-downgrade rejection: `signature.algorithm` MUST equal
///    the algorithm implied by the key's multicodec prefix
///    (RFC-ACDP-0008 §3.9).
/// 4. Signature verification over the ASCII bytes of `content_hash`.
///
/// The caller is responsible for the `key_id`-DID-equals-`agent_id`
/// binding check and for `content_hash` recomputation (use
/// [`verify_body_offline`] for the full pipeline).
pub fn verify_did_key_envelope(
    signature: &Signature,
    content_hash: &ContentHash,
) -> Result<(), AcdpError> {
    let material = acdp_did::key::resolve_did_key_url(&signature.key_id)?;

    if material.algorithm() != signature.algorithm {
        return Err(AcdpError::InvalidSignature(format!(
            "signature.algorithm '{}' does not match the did:key multicodec \
             (key implies '{}')",
            signature.algorithm,
            material.algorithm()
        )));
    }

    match material {
        acdp_did::key::DidKeyMaterial::Ed25519(pub_bytes) => {
            verify_ed25519(&pub_bytes, &signature.value, content_hash.as_str())
        }
        acdp_did::key::DidKeyMaterial::EcdsaP256(sec1_compressed) => {
            verify_ecdsa_p256(&sec1_compressed, &signature.value, content_hash.as_str())
        }
    }
}

/// Full offline body verification for `did:key` producers — works with
/// `--no-default-features` (no HTTP stack, no resolver, no async).
///
/// Pipeline (mirrors [`Verifier::verify_body`] minus DID-document
/// resolution, which did:key does not have):
/// 1. Structural validation ([`acdp_validation::validate_body`]).
/// 2. `content_hash` recomputation over ProducerContent (§5.7).
/// 3. `key_id` DID portion equals `agent_id`.
/// 4. Pure did:key envelope verification (algorithm + signature).
///
/// Returns [`AcdpError::KeyResolution`] for a `did:web` (or other
/// method) body — those require the resolver-backed
/// [`Verifier::verify_body`] under the `client` feature.
pub fn verify_body_offline(body: &Body) -> Result<(), AcdpError> {
    acdp_validation::validate_body(body)?;

    if !body.agent_id.as_str().starts_with("did:key:") {
        return Err(AcdpError::KeyResolution(format!(
            "verify_body_offline supports did:key producers only; '{}' requires \
             the resolver-backed Verifier (client feature)",
            body.agent_id
        )));
    }

    let body_val = serde_json::to_value(body)?;
    verify_content_hash(&body_val, &body.content_hash)?;

    let did_part = body
        .signature
        .key_id
        .split_once('#')
        .map(|(d, _)| d)
        .unwrap_or(body.signature.key_id.as_str());
    if did_part != body.agent_id.as_str() {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "key_id DID '{did_part}' ≠ agent_id '{}'",
            body.agent_id
        )));
    }

    verify_did_key_envelope(&body.signature, &body.content_hash)
}

/// Offline counterpart of [`verify_publish_request_signature`] for
/// `did:key` producers — used by registries (and the bindings) to verify
/// a publish request without the `client` feature. Assumes structural
/// validation and `content_hash` recomputation have already run
/// (e.g. via `PublishValidator::validate_post_schema`).
pub fn verify_publish_request_signature_offline(req: &PublishRequest) -> Result<(), AcdpError> {
    let key_id = req.signature.key_id.as_str();
    let did_part = key_id.split_once('#').map(|(d, _)| d).unwrap_or(key_id);
    if did_part != req.agent_id.as_str() {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "key_id DID '{did_part}' ≠ agent_id '{}'",
            req.agent_id
        )));
    }
    if !did_part.starts_with("did:key:") {
        return Err(AcdpError::KeyResolution(format!(
            "offline verification supports did:key only; got '{did_part}'"
        )));
    }
    verify_did_key_envelope(&req.signature, &req.content_hash)
}

/// Historical-key body-signature verification (ACDP 0.2, WS-B).
///
/// Identical to the standard envelope verification EXCEPT that the
/// `assertionMethod` membership check is skipped: a rotated-out key
/// that the producer retained in `verificationMethod` (per the
/// RFC-ACDP-0010 key-retention rule) still verifies. Callers MUST
/// gate this on a **verified registry receipt** whose
/// `key_fingerprint` matches this key — without that attestation,
/// accepting a non-assertion key is exactly the bypass the
/// `assertionMethod` check exists to prevent. did:key bodies never
/// take this path (the key cannot rotate).
#[cfg(feature = "client")]
pub async fn verify_body_signature_historical(
    body: &Body,
    resolver: &WebResolver,
) -> Result<(), AcdpError> {
    let key_id = &body.signature.key_id;
    let (did_part, fragment) = key_id.split_once('#').ok_or_else(|| {
        AcdpError::KeyResolution(format!("signature.key_id '{key_id}' has no '#fragment'"))
    })?;
    if did_part != body.agent_id.as_str() {
        return Err(AcdpError::KeyNotAuthorized(format!(
            "key_id DID '{did_part}' ≠ agent_id '{}'",
            body.agent_id
        )));
    }
    if !did_part.starts_with("did:web:") {
        return Err(AcdpError::KeyResolution(format!(
            "historical-key verification applies to did:web only; got '{did_part}'"
        )));
    }
    let doc = resolver.resolve(did_part).await?;
    // Key fully removed from the DID document → fail closed. The
    // producer's obligation is to RETAIN rotated keys in
    // verificationMethod (RFC-ACDP-0010); a deleted key is
    // unverifiable by design.
    let method = doc.find_by_fragment(fragment).ok_or_else(|| {
        AcdpError::KeyResolution(format!(
            "no verification method with fragment '#{fragment}' — the key was \
             removed from the DID document, not just rotated out of assertionMethod"
        ))
    })?;
    if let Some(declared) = method.declared_algorithm() {
        if declared != body.signature.algorithm {
            return Err(AcdpError::InvalidSignature(format!(
                "signature.algorithm '{}' does not match verification method type \
                 (resolved key declares '{declared}')",
                body.signature.algorithm
            )));
        }
    }
    match body.signature.algorithm.as_str() {
        "ed25519" => verify_ed25519(
            &method.ed25519_public_key_bytes()?,
            &body.signature.value,
            body.content_hash.as_str(),
        ),
        "ecdsa-p256" => verify_ecdsa_p256(
            &method.ecdsa_p256_public_key_sec1()?,
            &body.signature.value,
            body.content_hash.as_str(),
        ),
        other => Err(AcdpError::UnsupportedAlgorithm(format!(
            "verifier does not support signature algorithm '{other}'"
        ))),
    }
}

// ── Context-identity binding (RFC-ACDP-0006 §4.1 step 7) ─────────────────────

/// Verify that a served body's `ctx_id` is the one the caller actually
/// requested — RFC-ACDP-0006 §4.1 step 7 (NORMATIVE, "Bind the resolved
/// identity").
///
/// `ctx_id` is registry-assigned and sits in the RFC-ACDP-0001 §5.7
/// exclusion set, so it is stripped from `ProducerContent` before hashing:
/// neither `content_hash` recomputation nor the producer signature covers
/// it. Without this explicit comparison a registry can serve any other
/// validly-signed body from the same producer under the requested
/// context's URL, and every other check still passes (RFC-ACDP-0008 §9.1).
/// This is the only binding available on the receipt-less path, since
/// `ctx_id` is assigned by the registry rather than the producer.
///
/// Fails closed: both `served_ctx_id` and `expected_ctx_id` are parsed with
/// [`CtxId::parse`] before comparison, so a malformed id on *either* side
/// is rejected with [`AcdpError::SchemaViolation`] rather than silently
/// passing or silently failing to match. `CtxId::parse` mandates a unique
/// canonical text form (`acdp://` prefix, lowercase DNS authority,
/// lowercase v4 UUID), so byte equality and parsed equality coincide for
/// every value that clears parsing.
///
/// This is deliberately **stricter** than conformance fixture
/// `fed-011-ctx-id-binding.json`'s `uri_encoding_and_path_style_equivalence`
/// case, which asks that percent-encoded and path-style forms compare
/// *equal* to the canonical form. Requiring canonical form on both sides
/// instead produces false refusals for such alternate encodings, never
/// false acceptances — a safe deviation from that one fixture case.
///
/// On mismatch, returns the existing [`AcdpError::ContextIdMismatch`]
/// (shipped in 0.9.0 for the Rust client's equivalent check) rather than a
/// new variant, so the two enforcement points share one typed error.
pub fn verify_ctx_id_binding(served_ctx_id: &str, expected_ctx_id: &str) -> Result<(), AcdpError> {
    let served = CtxId::parse(served_ctx_id)?;
    let expected = CtxId::parse(expected_ctx_id)?;
    if served != expected {
        return Err(AcdpError::ContextIdMismatch {
            requested: expected.as_str().to_string(),
            served: served.as_str().to_string(),
        });
    }
    Ok(())
}

// ── Lifecycle events (ACDP 0.3, RFC-ACDP-0013 §5) ────────────────────────────

/// The pure (offline) prefix of RFC-ACDP-0013 §5 lifecycle-event
/// verification, shared by the resolver-backed and did:key paths:
///
/// 1. Recompute the preimage hash over the RAW wire JSON (minus
///    `signature` — verifiers MUST NOT re-serialize a parsed struct).
/// 2. Parse the closed event schema (§4 — an unknown member is
///    malformed registry state).
/// 3. **`ctx_id` binding**: the event's `ctx_id` MUST equal the
///    retrieved context's — a signed event cannot be replayed against
///    another context.
/// 4. **Actor rule**: producer-initiated events carry
///    `actor == body.agent_id`; registry-initiated events carry
///    `actor == capabilities.registry_did`. Any other actor is refused
///    — there is no third-party retraction (§12).
/// 5. **Actor binding**: `signature.key_id`'s DID portion MUST equal
///    `actor`, and the signature MUST be present (producer events MUST
///    be signed; an unsigned registry event is attributable only as far
///    as transport and cannot be *verified* — callers that tolerate it
///    check `event.is_signed()` before calling here).
fn lifecycle_event_prechecks(
    raw_event: &serde_json::Value,
    expected_ctx_id: &CtxId,
    producer_did: &AgentDid,
    registry_did: Option<&str>,
) -> Result<(LifecycleEvent, ContentHash), AcdpError> {
    let hash = LifecycleEvent::preimage_hash_of_value(raw_event)?;
    let event = LifecycleEvent::from_value(raw_event)?;
    if &event.ctx_id != expected_ctx_id {
        return Err(AcdpError::SchemaViolation(format!(
            "lifecycle event ctx_id '{}' ≠ the context's ctx_id '{expected_ctx_id}' \
             (RFC-ACDP-0013 §4: an event binds to exactly one context)",
            event.ctx_id
        )));
    }
    let is_producer = event.actor.as_str() == producer_did.as_str();
    let is_registry = registry_did.is_some_and(|did| event.actor.as_str() == did);
    if !is_producer && !is_registry {
        return Err(AcdpError::NotAuthorized(format!(
            "lifecycle event actor '{}' is neither the producer '{producer_did}' nor the \
             registry DID — only the producer and the serving registry can record \
             lifecycle events (RFC-ACDP-0013 §4, §12)",
            event.actor
        )));
    }
    // Presence + §5 actor binding (key_id DID portion == actor).
    event.actor_bound_signature()?;
    Ok((event, hash))
}

/// Verify a lifecycle event per RFC-ACDP-0013 §5 — the helper both
/// registries (at `/retract`/`/republish` submission time, §6 step 3)
/// and consumers (before treating an event as attributable evidence)
/// use.
///
/// **Producer-actor events** (`actor == producer_did`, i.e.
/// `body.agent_id`) verify against the producer's DID through the full
/// RFC-ACDP-0001 §5.11 pipeline — the same resolution, `assertionMethod`
/// authorization, algorithm-downgrade rejection, and SSRF protections
/// as a publish. **Registry-actor events** (`actor == registry_did`,
/// i.e. `capabilities.registry_did`) verify against the registry's DID
/// document through the same envelope path (RFC-ACDP-0010 §8 step 1
/// resolution). In both cases the signature is over the ASCII bytes of
/// the event hash recomputed from `raw_event` exactly as received.
///
/// Pass `registry_did: None` when validating a producer-initiated
/// endpoint submission (only the producer may use the §6 endpoints).
/// Returns the parsed event on success.
#[cfg(feature = "client")]
pub async fn verify_lifecycle_event(
    raw_event: &serde_json::Value,
    expected_ctx_id: &CtxId,
    producer_did: &AgentDid,
    registry_did: Option<&str>,
    resolver: &WebResolver,
) -> Result<LifecycleEvent, AcdpError> {
    let (event, hash) =
        lifecycle_event_prechecks(raw_event, expected_ctx_id, producer_did, registry_did)?;
    // The envelope path re-checks key_id-DID == actor, resolves the
    // actor's DID (did:web via the resolver; did:key purely), enforces
    // assertionMethod + algorithm binding, and verifies over the ASCII
    // bytes of the event hash — identical framing to a body signature.
    let signature = event.actor_bound_signature()?.clone();
    verify_signature_envelope(&event.actor, &signature, &hash, resolver).await?;
    Ok(event)
}

/// Offline counterpart of [`verify_lifecycle_event`] for `did:key`
/// actors — no resolver, no network, works with
/// `--no-default-features`. A `did:web` actor is refused with
/// [`AcdpError::KeyResolution`]; use the resolver-backed helper.
pub fn verify_lifecycle_event_offline(
    raw_event: &serde_json::Value,
    expected_ctx_id: &CtxId,
    producer_did: &AgentDid,
    registry_did: Option<&str>,
) -> Result<LifecycleEvent, AcdpError> {
    let (event, hash) =
        lifecycle_event_prechecks(raw_event, expected_ctx_id, producer_did, registry_did)?;
    if !event.actor.as_str().starts_with("did:key:") {
        return Err(AcdpError::KeyResolution(format!(
            "offline lifecycle-event verification supports did:key actors only; '{}' \
             requires the resolver-backed verify_lifecycle_event (client feature)",
            event.actor
        )));
    }
    let signature = event.actor_bound_signature()?;
    verify_did_key_envelope(signature, &hash)?;
    Ok(event)
}

// ── Offline verification tests ───────────────────────────────────────────────
//
// These exercise the resolver-free surface (did:key envelope, offline
// body / publish-request / lifecycle-event verification) and compile
// without the `client` feature. The resolver-backed 7-step algorithm is
// covered by `tests/verify_algorithm.rs` at the workspace root, which
// reuses the TLS DID-document harness.
#[cfg(test)]
mod offline_tests {
    use super::*;
    use acdp_crypto::{P256SigningKey, SigningKey};
    use acdp_producer::Producer;
    use acdp_types::body::{Body, DataPeriod};
    use acdp_types::lifecycle::{LifecycleEvent, LifecycleEventType};
    use acdp_types::{AgentDid, ContextType, CtxId, LineageId, Visibility};

    const CTX: &str = "acdp://registry.example.com/00000000-0000-4000-8000-000000000000";
    const LIN: &str = "lin:sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const EVENT_ID: &str = "00000000-0000-4000-8000-0000000000aa";

    fn ts() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn body_of(producer: &Producer) -> Body {
        let req = producer
            .publish_request()
            .title("offline verify test")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .expect("valid request");
        Body::from_publish_request(
            &req,
            CtxId(CTX.into()),
            LineageId(LIN.into()),
            "registry.example.com",
            ts(),
        )
    }

    fn ed25519_body() -> Body {
        body_of(&Producer::new_did_key(SigningKey::from_bytes(&[1u8; 32])))
    }

    fn p256_body() -> Body {
        let key = P256SigningKey::from_bytes(&[2u8; 32]).expect("valid p256 scalar");
        body_of(&Producer::new_did_key_p256(key).expect("did:key p256 producer"))
    }

    fn didweb_body() -> Body {
        body_of(&Producer::new(
            SigningKey::from_bytes(&[3u8; 32]),
            AgentDid::new("did:web:agents.example.com:p"),
            "did:web:agents.example.com:p#key-1",
        ))
    }

    // ── verify_did_key_envelope ──────────────────────────────────────────

    #[test]
    fn did_key_envelope_ed25519_and_p256_happy() {
        let b = ed25519_body();
        assert!(verify_did_key_envelope(&b.signature, &b.content_hash).is_ok());
        let p = p256_body();
        assert!(verify_did_key_envelope(&p.signature, &p.content_hash).is_ok());
    }

    #[test]
    fn did_key_envelope_algorithm_downgrade_rejected() {
        // An Ed25519 key whose signature claims ecdsa-p256 must not verify
        // (RFC-ACDP-0008 §3.9 downgrade rejection).
        let b = ed25519_body();
        let mut sig = b.signature.clone();
        sig.algorithm = "ecdsa-p256".into();
        assert!(matches!(
            verify_did_key_envelope(&sig, &b.content_hash),
            Err(AcdpError::InvalidSignature(_))
        ));
    }

    #[test]
    fn did_key_envelope_malformed_key_id_errors() {
        let b = ed25519_body();
        let mut sig = b.signature.clone();
        // Strip the "#<multibase>" fragment: no key to resolve.
        sig.key_id = sig.key_id.split('#').next().unwrap().to_string();
        assert!(verify_did_key_envelope(&sig, &b.content_hash).is_err());
    }

    #[test]
    fn did_key_envelope_tampered_signature_rejected() {
        // Substitute a *different* key's valid Ed25519 signature: correct
        // length and base64, but not a signature by this key over this
        // hash → InvalidSignature (not a decode/length error).
        let b = ed25519_body();
        let other = body_of(&Producer::new_did_key(SigningKey::from_bytes(&[9u8; 32])));
        let mut sig = b.signature.clone();
        sig.value = other.signature.value.clone();
        assert!(matches!(
            verify_did_key_envelope(&sig, &b.content_hash),
            Err(AcdpError::InvalidSignature(_))
        ));
    }

    // ── verify_body_offline ──────────────────────────────────────────────

    #[test]
    fn body_offline_happy_ed25519_and_p256() {
        assert!(verify_body_offline(&ed25519_body()).is_ok());
        assert!(verify_body_offline(&p256_body()).is_ok());
    }

    #[test]
    fn body_offline_structural_failure_precedes_hash() {
        // An inverted data_period is a structural error. It must be caught
        // by validate_body BEFORE the content_hash is recomputed — proven
        // by leaving content_hash intact yet still failing on structure.
        let mut b = ed25519_body();
        b.data_period = Some(DataPeriod {
            start: ts(),
            end: ts() - chrono::Duration::days(1),
        });
        assert!(matches!(
            verify_body_offline(&b),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn body_offline_rejects_did_web_producer() {
        assert!(matches!(
            verify_body_offline(&didweb_body()),
            Err(AcdpError::KeyResolution(_))
        ));
    }

    #[test]
    fn body_offline_tampered_field_fails_hash() {
        // Mutating a ProducerContent field (not in the §5.7 exclusion set)
        // changes the recomputed hash but not the stored content_hash.
        let mut b = ed25519_body();
        b.title = "tampered title".into();
        assert!(verify_body_offline(&b).is_err());
    }

    #[test]
    fn body_offline_key_id_did_must_equal_agent_id() {
        // signature/key_id are in the exclusion set, so swapping key_id to
        // a different did:key leaves content_hash valid but fails the
        // agent-binding check.
        let mut b = ed25519_body();
        let other = p256_body();
        b.signature.key_id = other.signature.key_id.clone();
        assert!(matches!(
            verify_body_offline(&b),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
    }

    #[test]
    fn body_offline_fragmentless_key_id_reaches_envelope_error() {
        // A key_id with no '#fragment' passes the DID-equality check via
        // the `unwrap_or` fallback, then fails in resolve_did_key_url
        // (which needs the fragment to recover the key).
        let mut b = ed25519_body();
        b.signature.key_id = b.agent_id.as_str().to_string();
        assert!(verify_body_offline(&b).is_err());
    }

    // ── verify_publish_request_signature_offline ─────────────────────────

    #[test]
    fn publish_request_offline_happy() {
        let producer = Producer::new_did_key(SigningKey::from_bytes(&[4u8; 32]));
        let req = producer
            .publish_request()
            .title("pr offline")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .expect("valid request");
        assert!(verify_publish_request_signature_offline(&req).is_ok());
    }

    #[test]
    fn publish_request_offline_did_mismatch_and_did_web() {
        let producer = Producer::new_did_key(SigningKey::from_bytes(&[4u8; 32]));
        let mut req = producer
            .publish_request()
            .title("pr offline")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .expect("valid request");
        let orig = req.signature.key_id.clone();
        // DID portion no longer matches agent_id → KeyNotAuthorized.
        req.signature.key_id = p256_body().signature.key_id.clone();
        assert!(matches!(
            verify_publish_request_signature_offline(&req),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
        // A did:web key_id (matching a did:web agent) → KeyResolution.
        req.agent_id = AgentDid::new("did:web:agents.example.com:p");
        req.signature.key_id = "did:web:agents.example.com:p#key-1".into();
        let _ = orig;
        assert!(matches!(
            verify_publish_request_signature_offline(&req),
            Err(AcdpError::KeyResolution(_))
        ));
    }

    // ── verify_lifecycle_event_offline ───────────────────────────────────

    fn identity(seed: &[u8; 32]) -> (AgentDid, String) {
        let key = SigningKey::from_bytes(seed);
        let did = acdp_did::key::did_key_from_ed25519(&key.verifying_key_bytes());
        let key_id = acdp_did::key::did_key_url(&did).expect("did:key url");
        (AgentDid::new(did), key_id)
    }

    fn signed_event(seed: &[u8; 32], actor: AgentDid, key_id: String) -> serde_json::Value {
        let event = LifecycleEvent::new(
            EVENT_ID,
            CtxId(CTX.into()),
            LifecycleEventType::Retracted,
            ts(),
            actor,
            Some("superseded".into()),
        )
        .expect("valid event")
        .sign_with(SigningKey::from_bytes(seed), key_id)
        .expect("signed event");
        serde_json::to_value(&event).expect("event serializes")
    }

    #[test]
    fn lifecycle_offline_happy_producer_actor() {
        let (actor, key_id) = identity(&[5u8; 32]);
        let raw = signed_event(&[5u8; 32], actor.clone(), key_id);
        let out = verify_lifecycle_event_offline(&raw, &CtxId(CTX.into()), &actor, None);
        assert!(out.is_ok());
    }

    #[test]
    fn lifecycle_offline_registry_actor_accepted() {
        let (actor, key_id) = identity(&[6u8; 32]);
        let raw = signed_event(&[6u8; 32], actor.clone(), key_id);
        // Actor is the registry DID, not the producer.
        let producer = AgentDid::new("did:key:z6MkOtherProducerDidThatIsNotTheActor");
        let out = verify_lifecycle_event_offline(
            &raw,
            &CtxId(CTX.into()),
            &producer,
            Some(actor.as_str()),
        );
        assert!(out.is_ok());
    }

    #[test]
    fn lifecycle_offline_unknown_member_rejected() {
        let (actor, key_id) = identity(&[5u8; 32]);
        let mut raw = signed_event(&[5u8; 32], actor.clone(), key_id);
        raw.as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::json!(1));
        assert!(matches!(
            verify_lifecycle_event_offline(&raw, &CtxId(CTX.into()), &actor, None),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn lifecycle_offline_ctx_id_mismatch_rejected() {
        let (actor, key_id) = identity(&[5u8; 32]);
        let raw = signed_event(&[5u8; 32], actor.clone(), key_id);
        let other =
            CtxId("acdp://registry.example.com/11111111-1111-4111-8111-111111111111".into());
        assert!(matches!(
            verify_lifecycle_event_offline(&raw, &other, &actor, None),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn lifecycle_offline_unauthorized_actor_rejected() {
        let (actor, key_id) = identity(&[5u8; 32]);
        let raw = signed_event(&[5u8; 32], actor, key_id);
        let stranger = AgentDid::new("did:key:z6MkStrangerNeitherProducerNorRegistry");
        // Neither producer nor (absent) registry.
        assert!(matches!(
            verify_lifecycle_event_offline(&raw, &CtxId(CTX.into()), &stranger, None),
            Err(AcdpError::NotAuthorized(_))
        ));
        // Still unauthorized when a *different* registry DID is supplied.
        assert!(matches!(
            verify_lifecycle_event_offline(
                &raw,
                &CtxId(CTX.into()),
                &stranger,
                Some("did:key:z6MkSomeOtherRegistry")
            ),
            Err(AcdpError::NotAuthorized(_))
        ));
    }

    #[test]
    fn lifecycle_offline_unsigned_event_rejected() {
        let (actor, _key_id) = identity(&[5u8; 32]);
        let event = LifecycleEvent::new(
            EVENT_ID,
            CtxId(CTX.into()),
            LifecycleEventType::Retracted,
            ts(),
            actor.clone(),
            Some("superseded".into()),
        )
        .expect("valid event");
        let raw = serde_json::to_value(&event).expect("serializes");
        assert!(verify_lifecycle_event_offline(&raw, &CtxId(CTX.into()), &actor, None).is_err());
    }

    #[test]
    fn lifecycle_offline_did_web_actor_rejected() {
        let actor = AgentDid::new("did:web:agents.example.com:p");
        let key_id = "did:web:agents.example.com:p#key-1".to_string();
        let raw = signed_event(&[7u8; 32], actor.clone(), key_id);
        assert!(matches!(
            verify_lifecycle_event_offline(&raw, &CtxId(CTX.into()), &actor, None),
            Err(AcdpError::KeyResolution(_))
        ));
    }

    #[test]
    fn lifecycle_offline_mutated_raw_json_fails_signature() {
        // The preimage is hashed from the RAW wire JSON, so mutating a
        // non-signature field after signing invalidates the signature.
        let (actor, key_id) = identity(&[5u8; 32]);
        let mut raw = signed_event(&[5u8; 32], actor.clone(), key_id);
        raw.as_object_mut()
            .unwrap()
            .insert("reason".into(), serde_json::json!("changed after signing"));
        assert!(matches!(
            verify_lifecycle_event_offline(&raw, &CtxId(CTX.into()), &actor, None),
            Err(AcdpError::InvalidSignature(_))
        ));
    }

    // ── verify_ctx_id_binding ─────────────────────────────────────────────

    const OTHER_CTX: &str = "acdp://registry.example.com/11111111-1111-4111-8111-111111111111";

    #[test]
    fn ctx_id_binding_matching_ids_ok() {
        // Positive control for every failure case below.
        assert!(verify_ctx_id_binding(CTX, CTX).is_ok());
    }

    #[test]
    fn ctx_id_binding_mismatch_rejected_with_both_fields() {
        match verify_ctx_id_binding(OTHER_CTX, CTX) {
            Err(AcdpError::ContextIdMismatch { requested, served }) => {
                assert_eq!(requested, CTX);
                assert_eq!(served, OTHER_CTX);
            }
            other => panic!("expected ContextIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn ctx_id_binding_non_canonical_expected_is_schema_violation_not_silent_pass() {
        // Positive control: CTX vs CTX matches (see
        // `ctx_id_binding_matching_ids_ok`); an uppercase-authority variant
        // of the *expected* side must fail parsing, not silently pass and
        // not be reported as a `ContextIdMismatch`.
        let uppercase_authority =
            "acdp://Registry.example.com/00000000-0000-4000-8000-000000000000";
        assert!(matches!(
            verify_ctx_id_binding(CTX, uppercase_authority),
            Err(AcdpError::SchemaViolation(_))
        ));

        let uppercase_uuid = "acdp://registry.example.com/00000000-0000-4000-8000-000000000AAA";
        assert!(matches!(
            verify_ctx_id_binding(CTX, uppercase_uuid),
            Err(AcdpError::SchemaViolation(_))
        ));

        let missing_prefix = "registry.example.com/00000000-0000-4000-8000-000000000000";
        assert!(matches!(
            verify_ctx_id_binding(CTX, missing_prefix),
            Err(AcdpError::SchemaViolation(_))
        ));

        let malformed_uuid = "acdp://registry.example.com/not-a-uuid";
        assert!(matches!(
            verify_ctx_id_binding(CTX, malformed_uuid),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn ctx_id_binding_non_canonical_served_is_schema_violation() {
        let uppercase_authority =
            "acdp://Registry.example.com/00000000-0000-4000-8000-000000000000";
        assert!(matches!(
            verify_ctx_id_binding(uppercase_authority, CTX),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn ctx_id_binding_both_non_canonical_errors_without_panic() {
        let bad_served = "acdp://Registry.example.com/00000000-0000-4000-8000-000000000000";
        let bad_expected = "not-acdp-at-all";
        assert!(matches!(
            verify_ctx_id_binding(bad_served, bad_expected),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn ctx_id_binding_empty_string_either_side_errors_without_panic() {
        assert!(matches!(
            verify_ctx_id_binding("", CTX),
            Err(AcdpError::SchemaViolation(_))
        ));
        assert!(matches!(
            verify_ctx_id_binding(CTX, ""),
            Err(AcdpError::SchemaViolation(_))
        ));
        assert!(matches!(
            verify_ctx_id_binding("", ""),
            Err(AcdpError::SchemaViolation(_))
        ));
    }
}
