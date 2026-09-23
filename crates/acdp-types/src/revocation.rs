//! Producer key-revocation signal (ACDP 0.3, RFC-ACDP-0014).
//!
//! A revocation is not a new wire object: it is an ordinary signed,
//! permanent, content-addressed [`Body`] of type `key-revocation`
//! (interim pre-0.3.0 form: `acdp:key-revocation`) whose metadata
//! declares a key compromised **as of a stated time**. This module is
//! the typed view over that metadata: [`KeyRevocation::from_body`]
//! enforces the §4 shape rules and derives the §5/§6 trust class, and
//! [`effective_boundary`] applies the §4 earliest-`compromised_since`
//! rule across a set of revocations.
//!
//! Parsing a revocation does NOT verify it. A **verified revocation**
//! additionally requires the strict RFC-ACDP-0001 §5.11 body pipeline
//! plus the §5 not-self-signed check
//! ([`KeyRevocation::check_not_self_signed`]) against the *resolved*
//! signing key's fingerprint — `acdp-client` wires the full pipeline.

use crate::body::Body;
use crate::publish::PublishRequest;
use acdp_primitives::error::AcdpError;
use acdp_primitives::primitives::{AgentDid, ContextType, Visibility};
use acdp_primitives::time::fmt_rfc3339_ms;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum length of `metadata.reason` (RFC-ACDP-0014 §4).
pub const MAX_REASON_CHARS: usize = 1024;

/// The two trust classes of RFC-ACDP-0014 §5–§6. They carry different
/// authority and MUST be reported distinguishably — never collapsed
/// (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationTrustClass {
    /// Signed by the producer's own current, non-revoked key (§5): the
    /// stronger class, backed by the same trust anchor as every ACDP
    /// body. Consumers act on it without further judgment (§7).
    ProducerSigned,
    /// Published under the registry's identity on the producer's
    /// behalf after an out-of-band identity check (§6): the weaker,
    /// lost-everything fallback. It imports registry trust — a hostile
    /// or deceived registry can fabricate one. Strict-profile default:
    /// apply §7 only for contexts served by or receipted by that same
    /// registry; seek corroboration before applying it globally.
    RegistryAttested,
}

/// Typed, shape-validated view of a `key-revocation` context body
/// (RFC-ACDP-0014 §4).
///
/// Obtain via [`KeyRevocation::from_body`]. Field semantics:
///
/// - The **fingerprint is authoritative**; `revoked_key_id` is human
///   traceability only (§4).
/// - `compromised_since` is the compromise boundary **T**: signatures
///   made strictly before T are attributable to the producer; at or
///   after T they are not (§7). Across a superseding revocation
///   lineage the *earliest* T is effective (§4, [`effective_boundary`]).
/// - A revocation is permanent — there is no un-revoking. Consumers
///   SHOULD cache verified revocations indefinitely (§7); the type is
///   serde-serializable for exactly that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRevocation {
    /// RFC-ACDP-0010 §6 fingerprint of the revoked public key
    /// (`sha256:` + 64 lowercase hex), byte-for-byte the encoding
    /// receipts record. Authoritative over `revoked_key_id`.
    pub revoked_key_fingerprint: String,
    /// The compromise boundary T (canonical millisecond RFC 3339 UTC
    /// on the wire).
    pub compromised_since: DateTime<Utc>,
    /// Optional human-readable circumstances (≤ 1024 chars).
    /// Informational only — apply output hygiene before display
    /// (RFC-ACDP-0014 §13).
    pub reason: Option<String>,
    /// Optional DID URL of the revoked verification method. On any
    /// disagreement with the fingerprint, the fingerprint governs.
    pub revoked_key_id: Option<String>,
    /// The producer DID that controls the revoked key. Defaults to the
    /// body's `agent_id` when the metadata field is absent
    /// (producer-signed form); on registry-attested revocations it
    /// names the affected producer while `agent_id` is the registry.
    pub revoked_key_controller: AgentDid,
    /// The body's `agent_id` — the identity the revocation was
    /// published under (the producer for [`RevocationTrustClass::ProducerSigned`],
    /// the registry for [`RevocationTrustClass::RegistryAttested`]).
    pub publisher: AgentDid,
    /// §5/§6 trust class, derived from the controller binding:
    /// `revoked_key_controller` absent or equal to `agent_id` ⇒
    /// producer-signed; different ⇒ registry-attested. MUST NOT be
    /// collapsed when reporting (§6). For a registry-attested claim the
    /// caller still owns confirming that `publisher` really is the DID
    /// of a registry it talks to — see
    /// [`Self::cross_check_registry_binding`].
    pub trust_class: RevocationTrustClass,
}

impl KeyRevocation {
    /// Parse and shape-validate a `key-revocation` context body per
    /// RFC-ACDP-0014 §4.
    ///
    /// Enforced here (violations are [`AcdpError::SchemaViolation`], the
    /// code a 0.3.0 registry rejects them with at publish):
    ///
    /// - `type` is `key-revocation` (or the §10 interim
    ///   `acdp:key-revocation`).
    /// - `visibility` is `public` — an audience-restricted revocation
    ///   protects nobody outside the audience.
    /// - `metadata.revoked_key_fingerprint` present, in the
    ///   RFC-ACDP-0010 §6 form `sha256:` + 64 lowercase hex.
    /// - `metadata.compromised_since` present, canonical
    ///   millisecond-precision RFC 3339 UTC (RFC-ACDP-0001 §5.3).
    /// - `metadata.reason`, when present, ≤ 1024 characters.
    /// - `metadata.revoked_key_controller`, when present, a valid DID.
    ///
    /// Additionally, when the signing key's fingerprint is derivable
    /// *purely* from the body (a `did:key` signer), the §5 step 2
    /// not-self-signed rule is enforced here too. For `did:web` signers
    /// the fingerprint requires DID resolution: callers MUST follow up
    /// with [`Self::check_not_self_signed`] against the resolved
    /// fingerprint (`acdp-client`'s revocation pipeline does).
    ///
    /// This does NOT verify the body's hash or signature — a parsed
    /// revocation is untrusted until the strict §5.11 pipeline passes.
    pub fn from_body(body: &Body) -> Result<Self, AcdpError> {
        Self::from_parts(
            &body.context_type,
            &body.visibility,
            body.metadata.as_ref(),
            &body.agent_id,
            &body.signature.key_id,
        )
    }

    /// Parse and shape-validate a `key-revocation` context carried as a
    /// producer-submitted [`PublishRequest`] — i.e. *before* the registry
    /// has assigned `ctx_id`/`lineage_id`/`origin_registry`/`created_at`.
    /// Enforces exactly the same RFC-ACDP-0014 §4 shape table as
    /// [`Self::from_body`] (see its doc comment for the itemized list),
    /// because none of those checks touch a registry-assigned field.
    ///
    /// This is the entry point a `PublishValidator` — which sees a
    /// `PublishRequest`, never a `Body` — uses to run the §4 checks at
    /// publish time.
    pub fn from_publish_request(req: &PublishRequest) -> Result<Self, AcdpError> {
        Self::from_parts(
            &req.context_type,
            &req.visibility,
            req.metadata.as_ref(),
            &req.agent_id,
            &req.signature.key_id,
        )
    }

    /// Shared RFC-ACDP-0014 §4 shape-validation core over the five fields
    /// the constraint table actually touches. Identical on `Body` and
    /// `PublishRequest`, which is why [`Self::from_body`] and
    /// [`Self::from_publish_request`] both delegate here instead of each
    /// carrying their own copy — see [`Self::from_body`]'s doc comment
    /// for the itemized list of what is enforced.
    fn from_parts(
        context_type: &ContextType,
        visibility: &Visibility,
        metadata: Option<&serde_json::Value>,
        agent_id: &AgentDid,
        signing_key_id: &str,
    ) -> Result<Self, AcdpError> {
        if !context_type.is_key_revocation() {
            return Err(AcdpError::SchemaViolation(format!(
                "not a key-revocation context: type is '{}' (RFC-ACDP-0014 §4 requires \
                 'key-revocation', or 'acdp:key-revocation' in the pre-0.3.0 interim form)",
                serde_json::to_value(context_type)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
            )));
        }
        if *visibility != Visibility::Public {
            return Err(AcdpError::SchemaViolation(
                "a key-revocation context MUST be visibility 'public' — it is a safety \
                 broadcast; an audience-restricted revocation protects nobody outside the \
                 audience (RFC-ACDP-0014 §4)"
                    .into(),
            ));
        }

        let meta = metadata.and_then(|m| m.as_object()).ok_or_else(|| {
            AcdpError::SchemaViolation(
                "key-revocation body has no metadata object; \
                 metadata.revoked_key_fingerprint and metadata.compromised_since are \
                 REQUIRED (RFC-ACDP-0014 §4)"
                    .into(),
            )
        })?;

        let fingerprint = required_str(meta, "revoked_key_fingerprint")?;
        if !is_sha256_fingerprint(fingerprint) {
            return Err(AcdpError::SchemaViolation(format!(
                "metadata.revoked_key_fingerprint '{fingerprint}' is not in the \
                 RFC-ACDP-0010 §6 form 'sha256:' + 64 lowercase hex (RFC-ACDP-0014 §4)"
            )));
        }

        let since_raw = required_str(meta, "compromised_since")?;
        let compromised_since = parse_canonical_ms(since_raw).ok_or_else(|| {
            AcdpError::SchemaViolation(format!(
                "metadata.compromised_since '{since_raw}' is not canonical \
                 millisecond-precision RFC 3339 UTC (RFC-ACDP-0001 §5.3, RFC-ACDP-0014 §4)"
            ))
        })?;

        let reason = optional_str(meta, "reason")?;
        if let Some(r) = &reason {
            if r.chars().count() > MAX_REASON_CHARS {
                return Err(AcdpError::SchemaViolation(format!(
                    "metadata.reason exceeds {MAX_REASON_CHARS} characters (RFC-ACDP-0014 §4)"
                )));
            }
        }
        let revoked_key_id = optional_str(meta, "revoked_key_id")?;

        let (revoked_key_controller, trust_class) =
            match optional_str(meta, "revoked_key_controller")? {
                None => (agent_id.clone(), RevocationTrustClass::ProducerSigned),
                Some(c) => {
                    let controller = AgentDid::parse(&c)?;
                    if controller == *agent_id {
                        // §5 rule 3: present-and-equal is the explicit
                        // producer-signed controller binding.
                        (controller, RevocationTrustClass::ProducerSigned)
                    } else {
                        // §6: published under another identity (the
                        // registry's) on the controller's behalf.
                        (controller, RevocationTrustClass::RegistryAttested)
                    }
                }
            };

        let revocation = KeyRevocation {
            revoked_key_fingerprint: fingerprint.to_string(),
            compromised_since,
            reason,
            revoked_key_id,
            revoked_key_controller,
            publisher: agent_id.clone(),
            trust_class,
        };

        // §5 step 2, pure sub-case: a did:key signer's fingerprint is
        // derivable from the key_id itself with no resolution. A
        // malformed did:key key_id is left for signature verification
        // to reject — this check is best-effort by design.
        if signing_key_id.starts_with("did:key:") {
            if let Ok(material) = acdp_did::key::resolve_did_key_url(signing_key_id) {
                if let Ok(fp) = acdp_crypto::fingerprint::fingerprint_did_key_material(&material) {
                    revocation.check_not_self_signed(&fp)?;
                }
            }
        }

        Ok(revocation)
    }

    /// RFC-ACDP-0014 §5 step 2 — the revocation MUST NOT be signed by
    /// the very key it revokes: such a statement proves only possession
    /// of the (by hypothesis, attacker-held) key. Registries at ≥ 0.3.0
    /// reject the publish with `key_not_authorized`; consumers MUST
    /// treat one as **unverified** (at most a hint to seek a real
    /// signal).
    ///
    /// `signing_key_fingerprint` is the RFC-ACDP-0010 §6 fingerprint of
    /// the *resolved* key that signed the revocation body (see
    /// `acdp_crypto::fingerprint`).
    pub fn check_not_self_signed(&self, signing_key_fingerprint: &str) -> Result<(), AcdpError> {
        if signing_key_fingerprint == self.revoked_key_fingerprint {
            return Err(AcdpError::KeyNotAuthorized(format!(
                "revocation of key {} is signed by that same key — a key is not \
                 authorized to attest its own compromise; treat as unverified \
                 (RFC-ACDP-0014 §5 step 2)",
                self.revoked_key_fingerprint
            )));
        }
        Ok(())
    }

    /// True when this revocation applies to the given signing-key
    /// fingerprint (RFC-ACDP-0010 §6 encoding, exact match).
    pub fn revokes(&self, key_fingerprint: &str) -> bool {
        self.revoked_key_fingerprint == key_fingerprint
    }

    /// RFC-ACDP-0014 §5 step 2, decoupled from full §4 shape validation
    /// (contrast [`Self::check_not_self_signed`], which needs an already
    /// shape-validated [`KeyRevocation`]). §10's interim-form carve-out
    /// is scoped explicitly to "§4 shape validation" — it says nothing
    /// about §5, whose own MUST-reject text is gated on `acdp_version`
    /// alone, not on which spelling of the context type was used. So a
    /// registry on `[0.3.0, 0.5.0)` that must NOT §4-validate the
    /// interim `acdp:key-revocation` form still MUST enforce this check
    /// against it — this is the primitive that lets it do so without
    /// pulling in the rest of §4.
    ///
    /// Tolerant by design: a missing or non-string
    /// `metadata.revoked_key_fingerprint` can't be evaluated, so this
    /// returns `Ok(())` rather than rejecting on shape grounds — full §4
    /// validation (standard type) or §5.11 signature verification is
    /// what catches those cases instead. `signing_key_fingerprint` is
    /// the RFC-ACDP-0010 §6 fingerprint of the *resolved* signing key.
    pub fn check_not_self_signed_lenient(
        req: &PublishRequest,
        signing_key_fingerprint: &str,
    ) -> Result<(), AcdpError> {
        let Some(fingerprint) = req
            .metadata
            .as_ref()
            .and_then(|m| m.as_object())
            .and_then(|m| m.get("revoked_key_fingerprint"))
            .and_then(|v| v.as_str())
        else {
            return Ok(());
        };
        if fingerprint == signing_key_fingerprint {
            return Err(AcdpError::KeyNotAuthorized(format!(
                "revocation of key {fingerprint} is signed by that same key — a key is not \
                 authorized to attest its own compromise; treat as unverified \
                 (RFC-ACDP-0014 §5 step 2)"
            )));
        }
        Ok(())
    }

    /// [`Self::check_not_self_signed_lenient`]'s did:key sub-case: the
    /// signing key's fingerprint is derivable from `signature.key_id`
    /// alone, with no DID resolution — the same synchronous check
    /// `from_parts` used to run unconditionally as a side effect of full
    /// §4 parsing (before the interim form was carved out of that), now
    /// exposed standalone so a caller (like `PublishValidator`) can run
    /// it on a body it deliberately is NOT §4-shape-validating.
    ///
    /// Tolerant by design: a non-did:key signer, an unresolvable
    /// did:key `key_id`, or a fingerprint that fails to derive all leave
    /// this a no-op — see [`Self::check_not_self_signed_lenient`] for
    /// why that's the right default.
    pub fn check_not_self_signed_did_key_lenient(req: &PublishRequest) -> Result<(), AcdpError> {
        if !req.signature.key_id.starts_with("did:key:") {
            return Ok(());
        }
        let Ok(material) = acdp_did::key::resolve_did_key_url(&req.signature.key_id) else {
            return Ok(());
        };
        let Ok(signer_fingerprint) =
            acdp_crypto::fingerprint::fingerprint_did_key_material(&material)
        else {
            return Ok(());
        };
        Self::check_not_self_signed_lenient(req, &signer_fingerprint)
    }

    /// Registry-attestation binding (pure): `publisher` — the identity
    /// this revocation was actually published under — MUST equal both
    /// `did:web:<serving_authority>` (the authority the context was
    /// actually fetched from, not whatever the body claims) AND the
    /// serving registry's advertised `capabilities.registry_did`. The
    /// two halves have different citations: the `registry_did` half is
    /// RFC-ACDP-0014 §6 step 2; the `serving_authority` half is not a
    /// §6 step at all — it is the ACDP-wide `registry_did`↔authority
    /// invariant of RFC-ACDP-0011 §7 step 3 / RFC-ACDP-0012 §9.3 step 3
    /// (the two house-pattern siblings), applied here to key
    /// revocations.
    ///
    /// A [`RevocationTrustClass::RegistryAttested`] revocation imports
    /// its authority entirely from *who published it* — §5 body
    /// verification alone only proves the body is genuinely signed by
    /// `publisher`'s current key, not that `publisher` is the specific
    /// registry a caller actually talks to. Without this check a
    /// consumer could apply a registry-attested revocation on the say-so
    /// of any producer willing to name someone else as
    /// `revoked_key_controller`; this pins `publisher` to the one
    /// registry both the transport (`serving_authority`) and the
    /// registry's own self-description (`capabilities_registry_did`)
    /// agree on.
    ///
    /// Pure — no DID resolution or network I/O — so it stays exposable
    /// from the language bindings.
    pub fn cross_check_registry_binding(
        &self,
        serving_authority: &str,
        capabilities_registry_did: &str,
    ) -> Result<(), AcdpError> {
        let expected_did = acdp_did::web::authority_to_did_web(serving_authority);
        if self.publisher.as_str() != expected_did {
            return Err(AcdpError::KeyNotAuthorized(format!(
                "key-revocation publisher '{}' ≠ serving authority's DID '{expected_did}' \
                 (RFC-ACDP-0014 §6 steps 2–3)",
                self.publisher
            )));
        }
        if self.publisher.as_str() != capabilities_registry_did {
            return Err(AcdpError::KeyNotAuthorized(format!(
                "key-revocation publisher '{}' ≠ capabilities.registry_did \
                 '{capabilities_registry_did}' (RFC-ACDP-0014 §6 steps 2–3)",
                self.publisher
            )));
        }
        Ok(())
    }
}

/// The effective compromise boundary for `key_fingerprint` across a set
/// of (verified) revocations: the **earliest** `compromised_since`
/// among those that name the fingerprint, or `None` when none does.
///
/// This is the RFC-ACDP-0014 §4 monotonicity rule: a superseding
/// revocation may widen — never narrow — the compromise window, so a
/// supersession can never quietly shrink it. Feed every revocation of a
/// lineage (including superseded ones) through this, not just the head.
pub fn effective_boundary<'a>(
    revocations: impl IntoIterator<Item = &'a KeyRevocation>,
    key_fingerprint: &str,
) -> Option<DateTime<Utc>> {
    revocations
        .into_iter()
        .filter(|r| r.revokes(key_fingerprint))
        .map(|r| r.compromised_since)
        .min()
}

fn required_str<'m>(
    meta: &'m serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'m str, AcdpError> {
    meta.get(key).and_then(|v| v.as_str()).ok_or_else(|| {
        AcdpError::SchemaViolation(format!(
            "key-revocation metadata.{key} is REQUIRED and must be a string \
             (RFC-ACDP-0014 §4)"
        ))
    })
}

fn optional_str(
    meta: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<String>, AcdpError> {
    match meta.get(key) {
        None => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(AcdpError::SchemaViolation(format!(
            "key-revocation metadata.{key} must be a string when present (RFC-ACDP-0014 §4)"
        ))),
    }
}

/// `sha256:` + exactly 64 lowercase hex digits (RFC-ACDP-0010 §6).
fn is_sha256_fingerprint(s: &str) -> bool {
    match s.strip_prefix("sha256:") {
        Some(hex) => {
            hex.len() == 64
                && hex
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        }
        None => false,
    }
}

/// Parse a timestamp REQUIRING the canonical millisecond RFC 3339 UTC
/// form `YYYY-MM-DDTHH:MM:SS.mmmZ` (RFC-ACDP-0001 §5.3): the string
/// must round-trip byte-identically through the canonical formatter.
fn parse_canonical_ms(raw: &str) -> Option<DateTime<Utc>> {
    let parsed = DateTime::parse_from_rfc3339(raw).ok()?.with_timezone(&Utc);
    (fmt_rfc3339_ms(parsed) == raw).then_some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::Signature;
    use acdp_primitives::primitives::{ContentHash, CtxId, LineageId};

    // ── from_publish_request: mirrors the from_body shape-violation
    // coverage above, over the PublishRequest-shaped entry point Phase 5
    // adds (RFC-ACDP-0014 §4). ──────────────────────────────────────────

    const PR_PRODUCER_DID: &str = "did:web:agents.example.com:pr-test-producer";
    const PR_COMPROMISED_SINCE: &str = "2026-05-01T00:00:00.000Z";

    fn pr_valid_metadata() -> serde_json::Value {
        serde_json::json!({
            "revoked_key_fingerprint": format!("sha256:{}", "a".repeat(64)),
            "compromised_since": PR_COMPROMISED_SINCE,
        })
    }

    fn publish_request_with_metadata(metadata: Option<serde_json::Value>) -> PublishRequest {
        PublishRequest {
            version: 1,
            supersedes: None,
            agent_id: AgentDid::new(PR_PRODUCER_DID),
            contributors: vec![],
            title: "Key revocation — key-1 compromised".into(),
            context_type: ContextType::KeyRevocation,
            data_refs: vec![],
            derived_from: vec![],
            visibility: Visibility::Public,
            content_hash: ContentHash("sha256:0".into()),
            signature: Signature {
                algorithm: "ed25519".into(),
                key_id: format!("{PR_PRODUCER_DID}#key-1"),
                value: "A".repeat(88),
            },
            audience: None,
            acdp_version: Some("0.3.0".into()),
            description: None,
            summary: None,
            lineage_id: None,
            tags: None,
            domain: None,
            expires_at: None,
            data_period: None,
            metadata,
            schema_uri: None,
            anchors: None,
        }
    }

    /// Positive control: a shape-conformant request is accepted, and
    /// classifies as producer-signed — proving the rejection tests below
    /// aren't passing vacuously.
    #[test]
    fn from_publish_request_valid_case_is_accepted() {
        let req = publish_request_with_metadata(Some(pr_valid_metadata()));
        let rev =
            KeyRevocation::from_publish_request(&req).expect("shape-conformant request must parse");
        assert_eq!(rev.trust_class, RevocationTrustClass::ProducerSigned);
        assert_eq!(rev.publisher.as_str(), PR_PRODUCER_DID);
        assert_eq!(rev.revoked_key_controller.as_str(), PR_PRODUCER_DID);
    }

    #[test]
    fn from_publish_request_wrong_context_type_rejected() {
        let mut req = publish_request_with_metadata(Some(pr_valid_metadata()));
        req.context_type = ContextType::Analysis;
        assert!(matches!(
            KeyRevocation::from_publish_request(&req),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn from_publish_request_non_public_visibility_rejected() {
        let mut req = publish_request_with_metadata(Some(pr_valid_metadata()));
        req.visibility = Visibility::Restricted;
        assert!(matches!(
            KeyRevocation::from_publish_request(&req),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn from_publish_request_missing_metadata_rejected() {
        let req = publish_request_with_metadata(None);
        assert!(matches!(
            KeyRevocation::from_publish_request(&req),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn from_publish_request_missing_fingerprint_rejected() {
        let mut meta = pr_valid_metadata();
        meta.as_object_mut()
            .unwrap()
            .remove("revoked_key_fingerprint");
        let req = publish_request_with_metadata(Some(meta));
        assert!(matches!(
            KeyRevocation::from_publish_request(&req),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn from_publish_request_malformed_fingerprint_rejected() {
        let mut meta = pr_valid_metadata();
        meta["revoked_key_fingerprint"] = serde_json::json!("not-a-fingerprint");
        let req = publish_request_with_metadata(Some(meta));
        assert!(matches!(
            KeyRevocation::from_publish_request(&req),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn from_publish_request_missing_compromised_since_rejected() {
        let mut meta = pr_valid_metadata();
        meta.as_object_mut().unwrap().remove("compromised_since");
        let req = publish_request_with_metadata(Some(meta));
        assert!(matches!(
            KeyRevocation::from_publish_request(&req),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn from_publish_request_non_canonical_compromised_since_rejected() {
        let mut meta = pr_valid_metadata();
        // No fractional-seconds component — RFC 3339-valid but not the
        // canonical millisecond form RFC-ACDP-0001 §5.3 requires.
        meta["compromised_since"] = serde_json::json!("2026-05-01T00:00:00Z");
        let req = publish_request_with_metadata(Some(meta));
        assert!(matches!(
            KeyRevocation::from_publish_request(&req),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn from_publish_request_reason_over_limit_rejected() {
        let mut meta = pr_valid_metadata();
        meta["reason"] = serde_json::json!("x".repeat(MAX_REASON_CHARS + 1));
        let req = publish_request_with_metadata(Some(meta));
        assert!(matches!(
            KeyRevocation::from_publish_request(&req),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    /// `from_body` and `from_publish_request` share `from_parts`: over
    /// the five fields the §4 table touches, equivalent input must
    /// produce an identical parsed `KeyRevocation`, not merely the same
    /// pass/fail verdict.
    #[test]
    fn from_body_and_from_publish_request_agree_on_equivalent_input() {
        let metadata = Some(pr_valid_metadata());
        let req = publish_request_with_metadata(metadata.clone());
        let body = body_from_pr_request(&req);

        assert_eq!(
            KeyRevocation::from_publish_request(&req).unwrap(),
            KeyRevocation::from_body(&body).unwrap()
        );
    }

    /// Builds the `Body` a registry would derive from `req`, mirroring
    /// `from_body_and_from_publish_request_agree_on_equivalent_input`'s
    /// fixture so error-path equivalence tests can reuse it verbatim.
    fn body_from_pr_request(req: &PublishRequest) -> Body {
        Body::from_publish_request(
            req,
            CtxId("acdp://registry.example.com/00000000-0000-4000-8000-000000000000".into()),
            LineageId(format!("lin:sha256:{}", "0".repeat(64))),
            "registry.example.com",
            DateTime::parse_from_rfc3339("2026-05-02T08:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        )
    }

    /// Gap E: agreement must hold on the ERROR path too, and not merely
    /// at the variant level — every §4 shape violation returns
    /// `SchemaViolation`, so comparing variants alone would pass even if
    /// `from_body` and `from_publish_request` disagreed on the message.
    /// Covers two distinct violations: non-public visibility (a
    /// top-level-field check) and a malformed fingerprint (a
    /// metadata-field check).
    #[test]
    fn from_body_and_from_publish_request_agree_on_error_message() {
        // Violation 1: non-public visibility.
        let mut req = publish_request_with_metadata(Some(pr_valid_metadata()));
        req.visibility = Visibility::Restricted;
        let body = body_from_pr_request(&req);
        let pr_err = KeyRevocation::from_publish_request(&req).unwrap_err();
        let body_err = KeyRevocation::from_body(&body).unwrap_err();
        assert!(matches!(pr_err, AcdpError::SchemaViolation(_)));
        assert_eq!(pr_err.to_string(), body_err.to_string());

        // Violation 2: malformed fingerprint.
        let mut meta = pr_valid_metadata();
        meta["revoked_key_fingerprint"] = serde_json::json!("not-a-fingerprint");
        let req = publish_request_with_metadata(Some(meta));
        let body = body_from_pr_request(&req);
        let pr_err = KeyRevocation::from_publish_request(&req).unwrap_err();
        let body_err = KeyRevocation::from_body(&body).unwrap_err();
        assert!(matches!(pr_err, AcdpError::SchemaViolation(_)));
        assert_eq!(pr_err.to_string(), body_err.to_string());
    }

    // ── from_publish_request: revoked_key_controller classification ────

    /// Controller present and equal to `agent_id` is the explicit form
    /// of the producer-signed binding (distinct from the
    /// controller-absent case `from_publish_request_valid_case_is_accepted`
    /// already covers).
    #[test]
    fn from_publish_request_controller_equal_to_agent_id_is_producer_signed() {
        let mut meta = pr_valid_metadata();
        meta["revoked_key_controller"] = serde_json::json!(PR_PRODUCER_DID);
        let req = publish_request_with_metadata(Some(meta));
        let rev = KeyRevocation::from_publish_request(&req).unwrap();
        assert_eq!(rev.trust_class, RevocationTrustClass::ProducerSigned);
        assert_eq!(rev.revoked_key_controller.as_str(), PR_PRODUCER_DID);
    }

    /// Controller present and different from `agent_id` classifies as
    /// registry-attested. Classification only — Phase 6 owns enforcing
    /// that the publisher really is a trusted registry.
    #[test]
    fn from_publish_request_controller_different_from_agent_id_is_registry_attested() {
        const OTHER_PRODUCER: &str = "did:web:agents.example.com:other-producer";
        let mut meta = pr_valid_metadata();
        meta["revoked_key_controller"] = serde_json::json!(OTHER_PRODUCER);
        let req = publish_request_with_metadata(Some(meta));
        let rev = KeyRevocation::from_publish_request(&req).unwrap();
        assert_eq!(rev.trust_class, RevocationTrustClass::RegistryAttested);
        assert_eq!(rev.revoked_key_controller.as_str(), OTHER_PRODUCER);
        assert_eq!(rev.publisher.as_str(), PR_PRODUCER_DID);
    }

    #[test]
    fn from_publish_request_controller_not_a_string_rejected() {
        let mut meta = pr_valid_metadata();
        meta["revoked_key_controller"] = serde_json::json!(42);
        let req = publish_request_with_metadata(Some(meta));
        assert!(matches!(
            KeyRevocation::from_publish_request(&req),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn from_publish_request_controller_invalid_did_rejected() {
        let mut meta = pr_valid_metadata();
        meta["revoked_key_controller"] = serde_json::json!("not-a-did");
        let req = publish_request_with_metadata(Some(meta));
        assert!(matches!(
            KeyRevocation::from_publish_request(&req),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    // ── from_publish_request: §5 step 2 did:key self-sign tail ─────────
    // All tests above use a did:web key_id, leaving `from_parts`' pure
    // did:key self-sign check (revocation.rs ~252-258) dead in every one
    // of them. These drive it explicitly through `from_publish_request`,
    // reusing the fixture approach of
    // `tests/key_revocation.rs::rev_001_did_key_self_revocation_rejected_at_parse`
    // but built from primitives already in acdp-types's dependency graph
    // (acdp-crypto and acdp-did are ordinary, non-dev dependencies —
    // `from_parts` itself already calls into them) rather than
    // `acdp-producer`'s `Producer`, which sits above acdp-types in the
    // crate stack and is unavailable here.

    /// Builds a did:key `signature.key_id` and its RFC-ACDP-0010 §6
    /// fingerprint from an Ed25519 seed, mirroring
    /// `rev_001_did_key_self_revocation_rejected_at_parse`'s fixture.
    fn did_key_fixture(seed: [u8; 32]) -> (String, String) {
        let signing_key = acdp_crypto::SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key_bytes();
        let did = acdp_did::key::did_key_from_ed25519(&public_key);
        let key_id = acdp_did::key::did_key_url(&did).unwrap();
        let fingerprint = acdp_crypto::fingerprint::fingerprint_ed25519(&public_key);
        (key_id, fingerprint)
    }

    /// Negative: `signature.key_id` is a did:key URL whose derived
    /// fingerprint EQUALS `metadata.revoked_key_fingerprint` — the
    /// revocation is signed by the very key it revokes (RFC-ACDP-0014 §5
    /// step 2) — rejected even though the request never goes through
    /// `from_body`.
    #[test]
    fn from_publish_request_did_key_self_revocation_rejected() {
        let (key_id, fingerprint) = did_key_fixture([1u8; 32]);
        let mut meta = pr_valid_metadata();
        meta["revoked_key_fingerprint"] = serde_json::json!(fingerprint);
        let mut req = publish_request_with_metadata(Some(meta));
        req.signature.key_id = key_id;
        assert!(matches!(
            KeyRevocation::from_publish_request(&req),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
    }

    /// Positive control for the test above: same did:key shape, but the
    /// signing key's fingerprint DIFFERS from `revoked_key_fingerprint`
    /// — accepted. Without this, the negative test could be passing for
    /// an unrelated reason (e.g. a bug that always rejects did:key
    /// signers).
    #[test]
    fn from_publish_request_did_key_different_key_accepted() {
        let (key_id, _fingerprint) = did_key_fixture([2u8; 32]);
        let meta = pr_valid_metadata(); // fingerprint is all-'a', unrelated to key [2u8; 32]
        let mut req = publish_request_with_metadata(Some(meta));
        req.signature.key_id = key_id;
        let rev = KeyRevocation::from_publish_request(&req)
            .expect("did:key signer whose fingerprint differs from the revoked key must pass");
        assert_eq!(rev.trust_class, RevocationTrustClass::ProducerSigned);
    }

    /// A malformed did:key `signature.key_id` (fragment does not match
    /// the method-specific identifier) makes fingerprint derivation fail
    /// `Ok(...)`-checked inside `from_parts`, which by design leaves the
    /// self-sign check unrun rather than rejecting here — signature
    /// verification is expected to reject the body instead. Pinning this
    /// deliberate leniency so a future change to it is visible.
    #[test]
    fn from_publish_request_malformed_did_key_key_id_not_rejected_here() {
        let (key_id, fingerprint) = did_key_fixture([3u8; 32]);
        let malformed_key_id = format!("{}-not-the-msi", key_id); // breaks the #fragment == msi rule
        let mut meta = pr_valid_metadata();
        meta["revoked_key_fingerprint"] = serde_json::json!(fingerprint);
        let mut req = publish_request_with_metadata(Some(meta));
        req.signature.key_id = malformed_key_id;
        let rev = KeyRevocation::from_publish_request(&req).expect(
            "malformed did:key key_id is left for signature verification, not rejected here",
        );
        assert_eq!(rev.trust_class, RevocationTrustClass::ProducerSigned);
    }

    fn registry_attested_rev(publisher: &str) -> KeyRevocation {
        KeyRevocation {
            revoked_key_fingerprint: format!("sha256:{}", "a1".repeat(32)),
            compromised_since: parse_canonical_ms("2026-05-01T00:00:00.000Z").unwrap(),
            reason: None,
            revoked_key_id: None,
            revoked_key_controller: AgentDid::new("did:web:agents.example.com:producer"),
            publisher: AgentDid::new(publisher),
            trust_class: RevocationTrustClass::RegistryAttested,
        }
    }

    /// RFC-ACDP-0014 §6 steps 2–3: `publisher` must equal both the
    /// serving authority's DID and `capabilities.registry_did`. All
    /// aligned ⇒ `Ok`; either mismatch ⇒ `Err(KeyNotAuthorized)`.
    #[test]
    fn cross_check_registry_binding_success_and_both_failure_directions() {
        let rev = registry_attested_rev("did:web:registry.example.com");

        rev.cross_check_registry_binding("registry.example.com", "did:web:registry.example.com")
            .expect("serving authority and capabilities.registry_did both match publisher");

        // Wrong serving authority.
        assert!(matches!(
            rev.cross_check_registry_binding("hostile.example", "did:web:registry.example.com"),
            Err(AcdpError::KeyNotAuthorized(_))
        ));

        // Wrong capabilities.registry_did.
        assert!(matches!(
            rev.cross_check_registry_binding("registry.example.com", "did:web:other.example"),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
    }

    /// `did:web:localhost%3A8443` — the percent-encoded-port form
    /// `authority_to_did_web` produces for a `host:port` authority
    /// (RFC-ACDP-0014 §6 steps 2–3; live in this codebase's own test
    /// harness, which binds ephemeral ports, not merely hypothetical).
    #[test]
    fn cross_check_registry_binding_percent_encoded_port_authority() {
        let rev = registry_attested_rev("did:web:localhost%3A8443");

        rev.cross_check_registry_binding("localhost:8443", "did:web:localhost%3A8443")
            .expect("host:port authority round-trips through authority_to_did_web");

        // A bare-hostname serving authority (no port) must NOT match a
        // publisher bound to the port-bearing form.
        assert!(matches!(
            rev.cross_check_registry_binding("localhost", "did:web:localhost%3A8443"),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
    }

    #[test]
    fn fingerprint_form_edges() {
        assert!(is_sha256_fingerprint(&format!(
            "sha256:{}",
            "a1".repeat(32)
        )));
        assert!(!is_sha256_fingerprint(&format!(
            "sha256:{}",
            "A1".repeat(32)
        ))); // uppercase
        assert!(!is_sha256_fingerprint(&format!(
            "sha512:{}",
            "a1".repeat(32)
        ))); // wrong alg
        assert!(!is_sha256_fingerprint(&format!(
            "sha256:{}",
            "a1".repeat(31)
        ))); // short
        assert!(!is_sha256_fingerprint("sha256:")); // empty hex
        assert!(!is_sha256_fingerprint(&"a1".repeat(32))); // no prefix
    }

    #[test]
    fn canonical_ms_timestamp_edges() {
        assert!(parse_canonical_ms("2026-05-01T00:00:00.000Z").is_some());
        // Non-canonical forms MUST be rejected even when RFC 3339-valid.
        for bad in [
            "2026-05-01T00:00:00Z",          // no fractional part
            "2026-05-01T00:00:00.0Z",        // 1 digit
            "2026-05-01T00:00:00.000000Z",   // microseconds
            "2026-05-01T00:00:00.000+00:00", // offset spelling
            "2026-05-01 00:00:00.000Z",      // space separator
            "not-a-time",
        ] {
            assert!(
                parse_canonical_ms(bad).is_none(),
                "{bad:?} must be rejected"
            );
        }
    }

    // ── effective_boundary: issue #226 Phase 5 — zero direct unit tests
    // existed for this fold before this block; `rev_002_earliest_boundary_across_lineage`
    // (tests/key_revocation.rs) and `earliest_boundary_wins`
    // (crates/acdp-client/src/revocation.rs) exercise it only indirectly,
    // through `classify_under_revocation`. ─────────────────────────────

    const EB_FP: &str = "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070";
    const EB_OTHER_FP: &str =
        "sha256:3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f";

    fn eb_rev(fp: &str, t: &str) -> KeyRevocation {
        KeyRevocation {
            revoked_key_fingerprint: fp.into(),
            compromised_since: DateTime::parse_from_rfc3339(t).unwrap().with_timezone(&Utc),
            reason: None,
            revoked_key_id: None,
            revoked_key_controller: AgentDid::new("did:web:agents.example.com:p"),
            publisher: AgentDid::new("did:web:agents.example.com:p"),
            trust_class: RevocationTrustClass::ProducerSigned,
        }
    }

    #[test]
    fn effective_boundary_empty_slice_is_none() {
        let revs: [KeyRevocation; 0] = [];
        assert_eq!(effective_boundary(&revs, EB_FP), None);
    }

    #[test]
    fn effective_boundary_single_match() {
        let revs = [eb_rev(EB_FP, "2026-05-01T00:00:00.000Z")];
        assert_eq!(
            effective_boundary(&revs, EB_FP),
            Some(
                DateTime::parse_from_rfc3339("2026-05-01T00:00:00.000Z")
                    .unwrap()
                    .with_timezone(&Utc)
            )
        );
    }

    /// The §4 monotonicity rule: the EARLIEST `compromised_since` among
    /// several entries naming the same fingerprint wins, regardless of
    /// input order or which one is the lineage head.
    #[test]
    fn effective_boundary_min_folds_across_multiple_entries_same_fingerprint() {
        let revs = [
            eb_rev(EB_FP, "2026-06-01T00:00:00.000Z"),
            eb_rev(EB_FP, "2026-04-01T00:00:00.000Z"), // earliest
            eb_rev(EB_FP, "2026-05-01T00:00:00.000Z"),
        ];
        assert_eq!(
            effective_boundary(&revs, EB_FP),
            Some(
                DateTime::parse_from_rfc3339("2026-04-01T00:00:00.000Z")
                    .unwrap()
                    .with_timezone(&Utc)
            )
        );
    }

    /// An entry naming a different fingerprint is inert: it neither
    /// contributes to nor blocks the fold for the fingerprint under
    /// test.
    #[test]
    fn effective_boundary_ignores_non_matching_fingerprints() {
        let revs = [
            eb_rev(EB_OTHER_FP, "2026-01-01T00:00:00.000Z"),
            eb_rev(EB_FP, "2026-05-01T00:00:00.000Z"),
            eb_rev(EB_OTHER_FP, "2026-02-01T00:00:00.000Z"),
        ];
        assert_eq!(
            effective_boundary(&revs, EB_FP),
            Some(
                DateTime::parse_from_rfc3339("2026-05-01T00:00:00.000Z")
                    .unwrap()
                    .with_timezone(&Utc)
            )
        );
        // And the converse: querying a fingerprint no entry names at
        // all is None, not a false match against the non-matching
        // entries present.
        const UNRELATED_FP: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(effective_boundary(&revs, UNRELATED_FP), None);
    }
}
