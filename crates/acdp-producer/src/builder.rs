//! Producer-side API for building and signing publish requests.

use acdp_crypto::sign::{AcdpSigningKey, P256SigningKey};
use acdp_crypto::{compute_content_hash, SigningKey};
use acdp_primitives::error::AcdpError;
use acdp_types::anchor::AnchorEntry;
use acdp_types::body::{Body, DataPeriod, Signature};
use acdp_types::data_ref::DataRef;
use acdp_types::primitives::*;
use acdp_types::publish::PublishRequest;
use chrono::{DateTime, Utc};

// ── Producer ─────────────────────────────────────────────────────────────────

/// A context producer. Wraps a signing key and identity.
///
/// The signing key may be Ed25519 (the mandatory baseline) or
/// ECDSA-P256 (interop). Construct with [`Producer::new`] /
/// [`Producer::new_ed25519`] for Ed25519 keys, or [`Producer::new_p256`]
/// for P-256 keys; the builder emits the matching `signature.algorithm`
/// string and the corresponding wire-form signature.
pub struct Producer {
    signing_key: AcdpSigningKey,
    agent_id: AgentDid,
    /// DID URL of the signing key, e.g. `did:web:example.com#key-1`.
    key_id: String,
    /// The key attestation every request carries when the key is a
    /// keyless key (RFC-ACDP-0021 §6.2); see `Producer::keyless`.
    key_attestation: Option<acdp_types::keyless::KeyAttestationRef>,
}

impl Producer {
    /// Create a new producer with an Ed25519 signing key.
    ///
    /// `key_id` MUST be a DID URL whose DID portion equals `agent_id`.
    /// Equivalent to [`Producer::new_ed25519`] — retained as the
    /// historically-stable name.
    pub fn new(signing_key: SigningKey, agent_id: AgentDid, key_id: impl Into<String>) -> Self {
        Self::new_ed25519(signing_key, agent_id, key_id)
    }

    /// Create a new producer with an Ed25519 signing key (explicit).
    ///
    /// `key_id` MUST be a DID URL whose DID portion equals `agent_id`.
    pub fn new_ed25519(
        signing_key: SigningKey,
        agent_id: AgentDid,
        key_id: impl Into<String>,
    ) -> Self {
        Self {
            signing_key: AcdpSigningKey::Ed25519(signing_key),
            agent_id,
            key_id: key_id.into(),
            key_attestation: None,
        }
    }

    /// Create a new producer with an ECDSA-P256 signing key.
    ///
    /// `key_id` MUST be a DID URL whose DID portion equals `agent_id`,
    /// and the corresponding DID document verification method MUST
    /// declare the P-256 algorithm so that consumers don't reject the
    /// signature on algorithm-downgrade grounds (RFC-ACDP-0008 §3.9).
    pub fn new_p256(
        signing_key: P256SigningKey,
        agent_id: AgentDid,
        key_id: impl Into<String>,
    ) -> Self {
        Self {
            signing_key: AcdpSigningKey::P256(signing_key),
            agent_id,
            key_id: key_id.into(),
            key_attestation: None,
        }
    }

    /// Create a producer whose identity **is** its Ed25519 key
    /// (`did:key`, ACDP 0.2).
    ///
    /// The `agent_id` and `key_id` are derived from the public key — no
    /// domain, no DID-document hosting, no manual DID string. Consumers
    /// verify did:key contexts offline
    /// (`acdp::verify::verify_body_offline`), with no
    /// dependency on the producer's infrastructure remaining online.
    ///
    /// Tradeoff: did:key cannot rotate. A new key is a new identity,
    /// and `supersedes` requires the same `agent_id`, so lineage
    /// continuity ends with the key. Use `did:web` for long-lived
    /// organizational anchors; use did:key for ephemeral or
    /// archival-critical producers.
    pub fn new_did_key(signing_key: SigningKey) -> Self {
        let did = acdp_did::key::did_key_from_ed25519(&signing_key.verifying_key_bytes());
        let key_id = acdp_did::key::did_key_url(&did)
            .expect("did_key_from_ed25519 always yields a did:key DID");
        Self {
            signing_key: AcdpSigningKey::Ed25519(signing_key),
            agent_id: AgentDid::new(did),
            key_id,
            key_attestation: None,
        }
    }

    /// Create a producer whose identity **is** its ECDSA-P256 key
    /// (`did:key`, ACDP 0.2). See [`Producer::new_did_key`] for the
    /// rotation tradeoff. Fails only if the key's SEC1 point is
    /// malformed (cannot happen for a key produced by this crate).
    pub fn new_did_key_p256(signing_key: P256SigningKey) -> Result<Self, AcdpError> {
        let did = acdp_did::key::did_key_from_p256_sec1(&signing_key.verifying_key_sec1())?;
        let key_id = acdp_did::key::did_key_url(&did)?;
        Ok(Self {
            signing_key: AcdpSigningKey::P256(signing_key),
            agent_id: AgentDid::new(did),
            key_id,
            key_attestation: None,
        })
    }

    /// Create a producer that signs with a keyless key (RFC-ACDP-0021,
    /// 0.5.0 Draft): an ephemeral key a registry attested for the
    /// controller. `attestation` is the attestation's metadata and
    /// `reference` names it; the attestation is usually obtained with
    /// [`crate::keyless::EphemeralKey`] and the client's
    /// `request_key_attestation`.
    ///
    /// The producer's `agent_id` is the attestation's `controller` and its
    /// key id the attested `<controller>#acdp-kl-<hex>`; every request it
    /// builds carries `key_attestation`. Fails when `signing_key` is not
    /// the attested key or its algorithm differs.
    ///
    /// The window is short (at most an hour): requests built after
    /// `not_after` are refused by the registry (`outside_attestation_window`).
    #[cfg(feature = "keyless")]
    pub fn keyless(
        signing_key: AcdpSigningKey,
        attestation: &acdp_types::keyless::KeyAttestation,
        reference: acdp_types::keyless::KeyAttestationRef,
    ) -> Result<Self, AcdpError> {
        let key = crate::keyless::EphemeralKey::from_key(signing_key);
        if key.fingerprint()? != attestation.key_fingerprint
            || key.algorithm() != attestation.algorithm
        {
            return Err(AcdpError::SchemaViolation(
                "the signing key is not the key the attestation attests".into(),
            ));
        }
        Ok(Self {
            signing_key: key.into_inner(),
            agent_id: AgentDid::new(attestation.controller.clone()),
            key_id: attestation.key_id.clone(),
            key_attestation: Some(reference),
        })
    }

    /// The signing key id.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Start building a new first-version publish request.
    pub fn publish_request(&self) -> RequestBuilder<'_> {
        RequestBuilder::new(self)
    }

    /// Start building a superseding publish request from a previous version's
    /// `ctx_id`. The caller MUST also call `.version(N)` with the correct next
    /// version number before `.build()`. Prefer `supersede_body` when the full
    /// previous Body is available — it propagates the version automatically.
    pub fn supersede(&self, previous: CtxId) -> RequestBuilder<'_> {
        let mut b = RequestBuilder::new(self);
        b.supersedes = Some(previous);
        b
    }

    /// Start building a superseding publish request from a retrieved Body.
    ///
    /// Propagates `previous.version + 1` so that the resulting request has the
    /// correct version number per RFC-ACDP-0003 §3.1 step 5. The previous
    /// context's `ctx_id` is used as `supersedes`. This is the recommended
    /// supersession entry point.
    pub fn supersede_body(&self, previous: &Body) -> RequestBuilder<'_> {
        let mut b = RequestBuilder::new(self);
        b.supersedes = Some(previous.ctx_id.clone());
        b.version = Some(previous.version + 1);
        b.expected_lineage_id = Some(previous.lineage_id.clone());
        b
    }

    /// Start building a new version that carries every producer-controlled
    /// field over from `previous`, then lets the caller override what
    /// changed. Inverts [`Self::supersede_body`]'s "blank slate" approach
    /// for workflows where most fields stay the same and only the data /
    /// summary / metadata move.
    ///
    /// Pre-fills supersedes / version / expected_lineage_id (same as
    /// `supersede_body`) plus title, context_type, contributors,
    /// data_refs, anchors, derived_from, visibility, audience,
    /// description, summary, tags, domain, expires_at, data_period,
    /// metadata, schema_uri, and acdp_version.
    pub fn new_version_from(&self, previous: &Body) -> RequestBuilder<'_> {
        let mut b = self.supersede_body(previous);
        b.title = Some(previous.title.clone());
        b.context_type = Some(previous.context_type.clone());
        b.contributors = previous.contributors.clone();
        b.data_refs = previous.data_refs.clone();
        b.anchors = previous.anchors.clone();
        b.derived_from = previous.derived_from.clone();
        b.visibility = previous.visibility.clone();
        b.audience = previous.audience.clone();
        b.description = previous.description.clone();
        b.summary = previous.summary.clone();
        b.tags = previous.tags.clone();
        b.domain = previous.domain.clone();
        b.expires_at = previous.expires_at;
        b.data_period = previous.data_period.clone();
        b.metadata = previous.metadata.clone();
        b.schema_uri = previous.schema_uri.clone();
        b.acdp_version = previous.acdp_version.clone();
        b
    }
}

// ── RequestBuilder ────────────────────────────────────────────────────────────

/// Builder for a [`PublishRequest`].
///
/// Call `.build()` when all required fields are set.  This will:
///  1. Assemble the ProducerContent JSON (producer-controlled fields only).
///  2. Compute `content_hash` via JCS + SHA-256 (§5.7).
///  3. Sign the `content_hash` string with the producer's Ed25519 key (§5.8).
///  4. Return a wire-ready `PublishRequest`.
pub struct RequestBuilder<'a> {
    producer: &'a Producer,

    // Required
    title: Option<String>,
    context_type: Option<ContextType>,

    // With defaults
    supersedes: Option<CtxId>,
    visibility: Visibility,
    contributors: Vec<AgentDid>,
    data_refs: Vec<DataRef>,
    derived_from: Vec<CtxId>,

    /// Explicit version override. Required for v2+ supersession; rejected for v1.
    version: Option<u32>,

    /// Optional `lineage_id` self-verification on supersession (v2+ only).
    /// Schema requires that v1 publications MUST NOT include this field.
    expected_lineage_id: Option<LineageId>,

    // Optional producer fields
    audience: Option<Vec<AgentDid>>,
    description: Option<String>,
    summary: Option<String>,
    tags: Option<Vec<String>>,
    domain: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    data_period: Option<DataPeriod>,
    metadata: Option<serde_json::Value>,
    schema_uri: Option<String>,
    acdp_version: Option<String>,
    anchors: Option<Vec<AnchorEntry>>,
}

use acdp_primitives::time::trunc_ms;

impl<'a> RequestBuilder<'a> {
    fn new(producer: &'a Producer) -> Self {
        Self {
            producer,
            title: None,
            context_type: None,
            supersedes: None,
            visibility: Visibility::Public,
            contributors: vec![],
            data_refs: vec![],
            derived_from: vec![],
            version: None,
            expected_lineage_id: None,
            audience: None,
            description: None,
            summary: None,
            tags: None,
            domain: None,
            expires_at: None,
            data_period: None,
            metadata: None,
            schema_uri: None,
            anchors: None,
            // ACDP 0.2 (trust & hardening, WS-D1): emit the protocol
            // version explicitly by default. An absent `acdp_version`
            // and an explicit one produce different content_hash values
            // (the JCS preimages differ); defaulting to explicit
            // emission removes the omitted-vs-explicit ambiguity for
            // everything built going forward. Use
            // [`RequestBuilder::omit_acdp_version`] to reproduce the
            // 0.1.x omitted form (e.g. the sig-001 golden vector).
            acdp_version: Some(acdp_primitives::ACDP_VERSION.to_string()),
        }
    }

    /// Title (1..=500 chars).
    pub fn title(mut self, t: impl Into<String>) -> Self {
        self.title = Some(t.into());
        self
    }

    /// Context type (closed enum or namespaced custom).
    pub fn context_type(mut self, t: ContextType) -> Self {
        self.context_type = Some(t);
        self
    }

    /// Visibility (`public`, `restricted`, `private`).
    pub fn visibility(mut self, v: Visibility) -> Self {
        self.visibility = v;
        self
    }

    /// Audience for `restricted` visibility (≥ 1 DID required when restricted).
    pub fn audience(mut self, a: Vec<AgentDid>) -> Self {
        self.audience = Some(a);
        self
    }

    /// Contributors (DIDs, ≤ 100 unique).
    pub fn contributors(mut self, c: Vec<AgentDid>) -> Self {
        self.contributors = c;
        self
    }

    /// Data references (each MUST satisfy `acdp-data-ref.schema.json`).
    pub fn data_refs(mut self, d: Vec<DataRef>) -> Self {
        self.data_refs = d;
        self
    }

    /// Lineage of contexts this body was derived from (≤ 1000 unique ctx_ids).
    pub fn derived_from(mut self, d: Vec<CtxId>) -> Self {
        self.derived_from = d;
        self
    }

    /// Long human-readable description (≤ 5000 chars).
    pub fn description(mut self, s: impl Into<String>) -> Self {
        self.description = Some(s.into());
        self
    }

    /// Producer-supplied summary for search results (≤ 1000 chars).
    /// Part of ProducerContent — included in the content_hash preimage.
    pub fn summary(mut self, s: impl Into<String>) -> Self {
        self.summary = Some(s.into());
        self
    }

    /// Free-form tags (each: `^[A-Za-z0-9][A-Za-z0-9_.-]*$`, ≤ 100 chars).
    pub fn tags(mut self, t: Vec<impl Into<String>>) -> Self {
        self.tags = Some(t.into_iter().map(Into::into).collect());
        self
    }

    /// Subject-domain identifier (≤ 200 chars).
    pub fn domain(mut self, d: impl Into<String>) -> Self {
        self.domain = Some(d.into());
        self
    }

    /// When the conclusions in this body should no longer be relied upon.
    /// Truncated to millisecond precision per RFC-ACDP-0001 §5.3.
    pub fn expires_at(mut self, e: DateTime<Utc>) -> Self {
        self.expires_at = Some(trunc_ms(e));
        self
    }

    /// Time window the data covers. Both fields are required by schema and
    /// truncated to millisecond precision per RFC-ACDP-0001 §5.3.
    pub fn data_period(mut self, dp: DataPeriod) -> Self {
        self.data_period = Some(DataPeriod {
            start: trunc_ms(dp.start),
            end: trunc_ms(dp.end),
        });
        self
    }

    /// Producer-specific structured metadata payload.
    pub fn metadata(mut self, m: serde_json::Value) -> Self {
        self.metadata = Some(m);
        self
    }

    /// JSON Schema URI describing the metadata shape.
    pub fn schema_uri(mut self, u: impl Into<String>) -> Self {
        self.schema_uri = Some(u.into());
        self
    }

    /// Typed external anchors (RFC-ACDP-0016, 0.5.0): content-addressed
    /// references to non-ACDP artifacts this body genesis-links to.
    /// Per the absent-when-empty convention, an empty `Vec` here is
    /// rejected at [`Self::build`] time (`schema_violation`) rather
    /// than silently omitted — call this only when there is at least
    /// one anchor to send.
    pub fn anchors(mut self, a: Vec<AnchorEntry>) -> Self {
        self.anchors = Some(a);
        self
    }

    /// Unset `anchors` entirely (the field is omitted from the wire).
    ///
    /// Needed specifically on the [`Producer::new_version_from`] path:
    /// that constructor carries the previous version's `anchors`
    /// forward by default (matching every other producer-controlled
    /// field), so a version that genuinely has none of its own has no
    /// other way to say so — `.anchors(vec![])` is rejected at
    /// [`Self::build`] time by the same absent-when-empty rule that
    /// makes an *empty* anchors array meaningless on the wire. Takes
    /// precedence over a prior `.anchors(...)` call in the same chain.
    pub fn clear_anchors(mut self) -> Self {
        self.anchors = None;
        self
    }

    /// Explicit version number. Required for v2+ supersession when not set
    /// via `Producer::supersede_body`. Rejected for first-version requests.
    pub fn version(mut self, v: u32) -> Self {
        self.version = Some(v);
        self
    }

    /// Self-verifying `lineage_id` for supersession publish.
    ///
    /// v2+ producers MAY include this so the registry can verify it matches
    /// the deterministically-derived value (RFC-ACDP-0003 §2.2). v1
    /// publications MUST NOT include it.
    pub fn expected_lineage_id(mut self, l: LineageId) -> Self {
        self.expected_lineage_id = Some(l);
        self
    }

    /// Set the ACDP protocol version string explicitly (e.g.
    /// [`acdp_primitives::ACDP_VERSION`]).
    ///
    /// **SDK default (since 0.2): emitted explicitly** as
    /// [`acdp_primitives::ACDP_VERSION`]. Per RFC-ACDP-0001 §6 a conformant
    /// consumer treats an absent `acdp_version` as `"0.1.0"`, but an
    /// absent field and an explicit one are *different JCS preimages*
    /// and therefore produce *different `content_hash` values* — the
    /// single most common source of cross-implementation hash
    /// divergence after timestamp precision. Explicit emission removes
    /// the ambiguity for everything built going forward.
    ///
    /// **Distinct preimage warning.** Pick one form and sign over
    /// exactly what you emit; do not switch mid-lineage. To reproduce a
    /// hash signed under the 0.1.x omitted form (e.g. the `sig-001`
    /// golden vector), call [`Self::omit_acdp_version`].
    pub fn acdp_version(mut self, v: impl Into<String>) -> Self {
        self.acdp_version = Some(v.into());
        self
    }

    /// Omit `acdp_version` from the publish request (the 0.1.x SDK
    /// default form). Consumers treat the absent field as `"0.1.0"`
    /// (RFC-ACDP-0001 §6); the omitted and explicit forms hash
    /// differently. Use this only to reproduce hashes signed under the
    /// omitted form — new lineages should keep the explicit default.
    pub fn omit_acdp_version(mut self) -> Self {
        self.acdp_version = None;
        self
    }

    /// Compute content_hash, sign, and return a wire-ready publish request.
    pub fn build(self) -> Result<PublishRequest, AcdpError> {
        let title = self.title.ok_or(AcdpError::MissingField("title"))?;
        let context_type = self
            .context_type
            .ok_or(AcdpError::MissingField("context_type"))?;

        // Resolve version per RFC-ACDP-0003 §3.1:
        //   - First version: `supersedes` MUST be null, version MUST be 1
        //   - Superseding: version MUST equal previous.version + 1
        let version: u32 = match (&self.supersedes, self.version) {
            (None, None) | (None, Some(1)) => 1,
            (None, Some(v)) => {
                return Err(AcdpError::SchemaViolation(format!(
                    "first-version publish requires version=1, got {v}"
                )));
            }
            (Some(_), None) => return Err(AcdpError::MissingField("version")),
            (Some(_), Some(v)) if v < 2 => {
                return Err(AcdpError::SchemaViolation(format!(
                    "supersession publish requires version >= 2, got {v}"
                )));
            }
            (Some(_), Some(v)) => v,
        };

        // RFC-ACDP-0003 §2.2: v1 publications MUST NOT include lineage_id.
        if version == 1 && self.expected_lineage_id.is_some() {
            return Err(AcdpError::SchemaViolation(
                "lineage_id MUST NOT be set on v1 publish requests".into(),
            ));
        }

        // Validate: restricted visibility requires a non-empty audience
        if matches!(self.visibility, Visibility::Restricted)
            && self.audience.as_ref().is_none_or(|v| v.is_empty())
        {
            return Err(AcdpError::SchemaViolation(
                "visibility:restricted requires a non-empty audience".into(),
            ));
        }

        // Build the ProducerContent JSON object (fields covered by the signature).
        //
        // Required fields are always present. `supersedes` is required-with-null
        // (always present, value may be JSON null). Optional fields are omitted
        // entirely when None — matches the wire format produced by serde with
        // `skip_serializing_if = "Option::is_none"` on PublishRequest.
        use serde_json::{json, Map, Value};
        let mut pc: Map<String, Value> = Map::new();
        pc.insert("version".into(), json!(version));
        pc.insert("supersedes".into(), json!(self.supersedes));
        pc.insert("agent_id".into(), json!(self.producer.agent_id));
        pc.insert("contributors".into(), json!(self.contributors));
        pc.insert("title".into(), json!(title));
        pc.insert("type".into(), json!(context_type));
        pc.insert("data_refs".into(), json!(self.data_refs));
        pc.insert("derived_from".into(), json!(self.derived_from));
        pc.insert("visibility".into(), json!(self.visibility));

        if let Some(v) = &self.audience {
            pc.insert("audience".into(), json!(v));
        }
        if let Some(v) = &self.acdp_version {
            pc.insert("acdp_version".into(), json!(v));
        }
        if let Some(v) = &self.description {
            pc.insert("description".into(), json!(v));
        }
        if let Some(v) = &self.summary {
            pc.insert("summary".into(), json!(v));
        }
        if let Some(v) = &self.tags {
            pc.insert("tags".into(), json!(v));
        }
        if let Some(v) = &self.domain {
            pc.insert("domain".into(), json!(v));
        }
        if let Some(v) = &self.expires_at {
            // §5.3 canonical `.mmmZ` — the same spelling the wire
            // `PublishRequest.expires_at` serializer emits, so the hash
            // matches the bytes a consumer receives.
            pc.insert(
                "expires_at".into(),
                json!(acdp_primitives::time::fmt_rfc3339_canonical(*v)),
            );
        }
        if let Some(v) = &self.data_period {
            pc.insert("data_period".into(), json!(v));
        }
        if let Some(v) = &self.metadata {
            pc.insert("metadata".into(), json!(v));
        }
        if let Some(v) = &self.schema_uri {
            pc.insert("schema_uri".into(), json!(v));
        }
        if let Some(v) = &self.anchors {
            pc.insert("anchors".into(), json!(v));
        }
        if let Some(v) = &self.producer.key_attestation {
            pc.insert("key_attestation".into(), json!(v));
        }

        let producer_content_value = Value::Object(pc);

        // compute_content_hash strips the §5.7 exclusion set automatically
        // (none of the excluded keys appear in producer_content_value above)
        let content_hash = compute_content_hash(&producer_content_value)?;

        // Sign the ASCII bytes of the full "sha256:<hex>" string. The
        // `AcdpSigningKey` enum reports the matching algorithm string so
        // the Signature envelope stays in sync with the key variant.
        let (algorithm, sig_value) = self.producer.signing_key.sign_content_hash(&content_hash);

        let req = PublishRequest {
            version,
            supersedes: self.supersedes,
            agent_id: self.producer.agent_id.clone(),
            contributors: self.contributors,
            title,
            context_type,
            data_refs: self.data_refs,
            derived_from: self.derived_from,
            visibility: self.visibility,
            content_hash,
            signature: Signature {
                algorithm: algorithm.into(),
                key_id: self.producer.key_id.clone(),
                value: sig_value,
            },
            audience: self.audience,
            acdp_version: self.acdp_version,
            description: self.description,
            summary: self.summary,
            tags: self.tags,
            domain: self.domain,
            expires_at: self.expires_at,
            data_period: self.data_period,
            metadata: self.metadata,
            schema_uri: self.schema_uri,
            anchors: self.anchors,
            key_attestation: self.producer.key_attestation.clone(),
            lineage_id: self.expected_lineage_id,
        };
        // Final schema-conformance check before emission.
        acdp_validation::validate_publish_request(&req)?;
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_producer() -> Producer {
        let key = SigningKey::from_bytes(&[0u8; 32]);
        Producer::new(
            key,
            AgentDid::new("did:web:agents.example.com:test-producer"),
            "did:web:agents.example.com:test-producer#key-1",
        )
    }

    #[test]
    fn missing_title_returns_error() {
        let p = test_producer();
        let err = p
            .publish_request()
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap_err();
        assert!(matches!(err, AcdpError::MissingField("title")));
    }

    #[test]
    fn missing_type_returns_error() {
        let p = test_producer();
        let err = p.publish_request().title("t").build().unwrap_err();
        assert!(matches!(err, AcdpError::MissingField("context_type")));
    }

    #[test]
    fn restricted_visibility_requires_audience() {
        let p = test_producer();
        let err = p
            .publish_request()
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .build()
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn restricted_visibility_with_empty_audience_rejected() {
        let p = test_producer();
        let err = p
            .publish_request()
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![])
            .build()
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn restricted_visibility_with_audience_succeeds() {
        let p = test_producer();
        let req = p
            .publish_request()
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![AgentDid::new("did:web:other.example.com:agent")])
            .build()
            .unwrap();
        assert_eq!(req.version, 1);
        assert!(req.audience.is_some());
    }

    #[test]
    fn supersede_requires_explicit_version() {
        let p = test_producer();
        let prev = CtxId("acdp://r.example.com/12345678-1234-4321-8123-123456781234".into());
        let err = p
            .supersede(prev)
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap_err();
        assert!(matches!(err, AcdpError::MissingField("version")));
    }

    #[test]
    fn supersede_with_explicit_version() {
        let p = test_producer();
        let prev = CtxId("acdp://r.example.com/12345678-1234-4321-8123-123456781234".into());
        let req = p
            .supersede(prev.clone())
            .version(2)
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap();
        assert_eq!(req.version, 2);
        assert_eq!(req.supersedes.as_ref().unwrap(), &prev);
    }

    #[test]
    fn supersede_v3_chain() {
        let p = test_producer();
        let v2 = CtxId("acdp://r.example.com/12345678-1234-4321-8123-1234567812aa".into());
        let req = p
            .supersede(v2.clone())
            .version(3)
            .title("v3")
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap();
        assert_eq!(req.version, 3);
    }

    #[test]
    fn supersede_with_version_below_2_rejected() {
        let p = test_producer();
        let prev = CtxId("acdp://r.example.com/12345678-1234-4321-8123-123456781234".into());
        let err = p
            .supersede(prev)
            .version(1)
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn first_version_with_explicit_version_other_than_1_rejected() {
        let p = test_producer();
        let err = p
            .publish_request()
            .version(2)
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn unset_optional_fields_are_omitted_from_hash_preimage() {
        // Regression test: unset Options must NOT serialize as JSON null in
        // the canonical form, otherwise the golden vector hash diverges.
        // sig-001 was signed under the 0.1.x omitted-`acdp_version` form,
        // reproduced here via the explicit opt-out.
        let p = test_producer();
        let req = p
            .publish_request()
            .omit_acdp_version()
            .title("Golden test vector — minimal first version")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        // From sig-001-ed25519-golden.json
        assert_eq!(
            req.content_hash.as_str(),
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5"
        );
    }

    /// WS-D1 — the 0.2 builder emits `acdp_version` explicitly by
    /// default; the default form hashes identically to an explicit
    /// `.acdp_version(ACDP_VERSION)` call and differently from the
    /// omitted form (distinct JCS preimages).
    #[test]
    fn default_emits_acdp_version_explicitly() {
        let p = test_producer();
        let build = |b: RequestBuilder<'_>| {
            b.title("t")
                .context_type(ContextType::DataSnapshot)
                .build()
                .unwrap()
        };
        let default_form = build(p.publish_request());
        let explicit_form = build(
            p.publish_request()
                .acdp_version(acdp_primitives::ACDP_VERSION),
        );
        let omitted_form = build(p.publish_request().omit_acdp_version());

        assert_eq!(
            default_form.acdp_version.as_deref(),
            Some(acdp_primitives::ACDP_VERSION)
        );
        assert_eq!(default_form.content_hash, explicit_form.content_hash);
        assert_ne!(
            default_form.content_hash, omitted_form.content_hash,
            "omitted and explicit acdp_version are distinct JCS preimages"
        );
    }

    #[test]
    fn summary_changes_content_hash() {
        let p = test_producer();
        let without = p
            .publish_request()
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap();
        let with = p
            .publish_request()
            .title("t")
            .summary("hello")
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap();
        assert_ne!(
            without.content_hash, with.content_hash,
            "summary must be in the hash preimage"
        );
    }

    #[test]
    fn v1_with_expected_lineage_id_rejected() {
        let p = test_producer();
        let err = p
            .publish_request()
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .expected_lineage_id(LineageId(
                "lin:sha256:b14ccd2a8b34530309255db68c151a10689b6a82feb30aff9222d54fdd871720"
                    .into(),
            ))
            .build()
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn supersede_body_propagates_version_and_lineage_id() {
        use acdp_types::body::{Body, RegistryState, Signature};
        use chrono::TimeZone;
        let prev = Body {
            ctx_id: CtxId(
                "acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into(),
            ),
            lineage_id: LineageId(
                "lin:sha256:b14ccd2a8b34530309255db68c151a10689b6a82feb30aff9222d54fdd871720"
                    .into(),
            ),
            origin_registry: "registry.example.com".into(),
            created_at: chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            content_hash: ContentHash("sha256:abcd".repeat(8) + "abcd"),
            signature: Signature {
                algorithm: "ed25519".into(),
                key_id: "did:web:agents.example.com:test-producer#key-1".into(),
                value: "A".repeat(88),
            },
            version: 2,
            supersedes: None,
            agent_id: AgentDid::new("did:web:agents.example.com:test-producer"),
            contributors: vec![],
            title: "v2".into(),
            context_type: ContextType::DataSnapshot,
            data_refs: vec![],
            derived_from: vec![],
            visibility: Visibility::Public,
            audience: None,
            acdp_version: None,
            description: None,
            summary: None,
            tags: None,
            domain: None,
            expires_at: None,
            data_period: None,
            metadata: None,
            schema_uri: None,
            anchors: None,
            extensions: Default::default(),
        };
        let _state = RegistryState {
            status: Status::Active,
            lifecycle_events: None,
            event_receipts: None,
            extensions: Default::default(),
        };

        let p = test_producer();
        let req = p
            .supersede_body(&prev)
            .title("v3")
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap();
        assert_eq!(req.version, 3);
        assert_eq!(req.supersedes.as_ref().unwrap(), &prev.ctx_id);
        assert_eq!(req.lineage_id.as_ref(), Some(&prev.lineage_id));
    }

    /// `new_version_from` (unlike `supersede_body`'s blank slate) MUST
    /// carry every producer-controlled field from `previous` forward,
    /// including `anchors` — a field added after this function was
    /// written (RFC-ACDP-0016) that was silently missing from the
    /// carry-over list until this test.
    #[test]
    fn new_version_from_carries_anchors_forward() {
        use acdp_types::body::{Body, RegistryState, Signature};
        use chrono::TimeZone;
        let anchor = AnchorEntry {
            scheme: "macp.commitment".into(),
            content_hash: ContentHash(
                "sha256:fa8fe6b9143b469866d31de09b81928cc44d226ed935162cd346ae80d14fd200".into(),
            ),
            uri: None,
            extensions: Default::default(),
        };
        let prev = Body {
            ctx_id: CtxId(
                "acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into(),
            ),
            lineage_id: LineageId(
                "lin:sha256:b14ccd2a8b34530309255db68c151a10689b6a82feb30aff9222d54fdd871720"
                    .into(),
            ),
            origin_registry: "registry.example.com".into(),
            created_at: chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            content_hash: ContentHash("sha256:abcd".repeat(8) + "abcd"),
            signature: Signature {
                algorithm: "ed25519".into(),
                key_id: "did:web:agents.example.com:test-producer#key-1".into(),
                value: "A".repeat(88),
            },
            version: 1,
            supersedes: None,
            agent_id: AgentDid::new("did:web:agents.example.com:test-producer"),
            contributors: vec![],
            title: "v1".into(),
            context_type: ContextType::DataSnapshot,
            data_refs: vec![],
            derived_from: vec![],
            visibility: Visibility::Public,
            audience: None,
            acdp_version: None,
            description: None,
            summary: None,
            tags: None,
            domain: None,
            expires_at: None,
            data_period: None,
            metadata: None,
            schema_uri: None,
            anchors: Some(vec![anchor.clone()]),
            extensions: Default::default(),
        };
        let _state = RegistryState {
            status: Status::Active,
            lifecycle_events: None,
            event_receipts: None,
            extensions: Default::default(),
        };

        let p = test_producer();
        // No explicit .anchors(...) override — relying entirely on the
        // carry-over.
        let req = p.new_version_from(&prev).build().unwrap();
        assert_eq!(req.anchors, Some(vec![anchor]));
    }

    /// `clear_anchors()` is the only way to produce a version with NO
    /// anchors after `new_version_from` has carried a previous version's
    /// anchors forward — `.anchors(vec![])` is rejected by the
    /// absent-when-empty rule, so a dedicated unset method is required.
    #[test]
    fn clear_anchors_unsets_a_carried_over_value() {
        use acdp_types::body::{Body, RegistryState, Signature};
        use chrono::TimeZone;
        let anchor = AnchorEntry {
            scheme: "macp.commitment".into(),
            content_hash: ContentHash(
                "sha256:fa8fe6b9143b469866d31de09b81928cc44d226ed935162cd346ae80d14fd200".into(),
            ),
            uri: None,
            extensions: Default::default(),
        };
        let prev = Body {
            ctx_id: CtxId(
                "acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into(),
            ),
            lineage_id: LineageId(
                "lin:sha256:b14ccd2a8b34530309255db68c151a10689b6a82feb30aff9222d54fdd871720"
                    .into(),
            ),
            origin_registry: "registry.example.com".into(),
            created_at: chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            content_hash: ContentHash("sha256:abcd".repeat(8) + "abcd"),
            signature: Signature {
                algorithm: "ed25519".into(),
                key_id: "did:web:agents.example.com:test-producer#key-1".into(),
                value: "A".repeat(88),
            },
            version: 1,
            supersedes: None,
            agent_id: AgentDid::new("did:web:agents.example.com:test-producer"),
            contributors: vec![],
            title: "v1".into(),
            context_type: ContextType::DataSnapshot,
            data_refs: vec![],
            derived_from: vec![],
            visibility: Visibility::Public,
            audience: None,
            acdp_version: None,
            description: None,
            summary: None,
            tags: None,
            domain: None,
            expires_at: None,
            data_period: None,
            metadata: None,
            schema_uri: None,
            anchors: Some(vec![anchor]),
            extensions: Default::default(),
        };
        let _state = RegistryState {
            status: Status::Active,
            lifecycle_events: None,
            event_receipts: None,
            extensions: Default::default(),
        };

        let p = test_producer();
        let req = p.new_version_from(&prev).clear_anchors().build().unwrap();
        assert_eq!(req.anchors, None);
    }

    #[test]
    fn timestamps_truncated_to_millis() {
        // Construct a timestamp with sub-millisecond precision; expect the
        // builder to drop everything below ms.
        let dt = DateTime::from_timestamp_nanos(1_700_000_000_123_456_789);
        let p = test_producer();
        let req = p
            .publish_request()
            .title("t")
            .context_type(ContextType::DataSnapshot)
            .expires_at(dt)
            .build()
            .unwrap();
        let truncated = req.expires_at.unwrap();
        assert_eq!(truncated.timestamp_subsec_nanos() % 1_000_000, 0);
    }
}
