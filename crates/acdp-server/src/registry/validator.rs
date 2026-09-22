//! Server-side publish validation pipeline — RFC-ACDP-0003 §2.1 (feature = "server").
//!
//! Runs steps 1–8 (validation) before any persistence occurs.

use acdp_crypto::hash::{compute_content_hash, derive_lineage_id};
use acdp_primitives::error::AcdpError;
use acdp_types::{
    body::Body,
    capabilities::CapabilitiesDocument,
    primitives::{ContentHash, ContextType, CtxId, LineageId},
    publish::PublishRequest,
    revocation::KeyRevocation,
};

/// Outcome of a successful validation — the registry can now assign
/// identifiers and persist.
#[derive(Debug)]
pub struct ValidatedPublish {
    /// The hash recomputed by the validator over ProducerContent.
    pub recomputed_hash: ContentHash,
}

/// Stateless publish request validator.
///
/// Runs §2.1 steps 1–8 (structural and cryptographic checks).
/// Steps 9+ (identifier assignment, lineage, supersession, persistence)
/// are registry-implementation concerns.
pub struct PublishValidator<'a> {
    caps: &'a CapabilitiesDocument,
    own_authority: Option<&'a str>,
}

impl<'a> PublishValidator<'a> {
    /// Create a validator without same-registry supersession enforcement.
    pub fn new(caps: &'a CapabilitiesDocument) -> Self {
        Self {
            caps,
            own_authority: None,
        }
    }

    /// Create a validator that rejects cross-registry supersession.
    ///
    /// `own_authority` is the registry's DNS authority (e.g.
    /// `registry.example.com`). When set, a publish request whose
    /// `supersedes` ctx_id has a different authority will be rejected with
    /// [`AcdpError::SupersededTarget`] / `CrossRegistrySupersessionUnsupported`
    /// (RFC-ACDP-0006 — v0.1.0 only allows same-registry supersession).
    pub fn for_authority(caps: &'a CapabilitiesDocument, own_authority: &'a str) -> Self {
        Self {
            caps,
            own_authority: Some(own_authority),
        }
    }

    /// Validate a publish request through the structural / cryptographic
    /// steps of RFC-ACDP-0003 §2.1, plus the cross-registry-supersession
    /// guard if the validator was built with [`Self::for_authority`].
    ///
    /// Mapped steps from RFC-ACDP-0003 §2.1:
    /// - **Step 1** (schema validation) — assumed performed upstream
    ///   (e.g. by `validate_publish_request`).
    /// - **Step 2** (payload size vs `limits.max_payload_bytes`).
    /// - **Step 3** (embedded size vs `limits.max_embedded_bytes`).
    /// - **Step 4** (hash recomputation over ProducerContent).
    /// - **Step 5** (signature algorithm vs
    ///   `supported_signature_algorithms`).
    /// - **Step 6** (key_id DID portion equals `agent_id`).
    /// - **Step 7–8** (DID resolution + signature verification) — async,
    ///   handled separately by `acdp_verify::Verifier::verify_body`.
    /// - Cross-registry supersession check (RFC-ACDP-0006): when an
    ///   own-authority is configured, rejects supersedes targets on a
    ///   different authority.
    pub fn validate_post_schema(
        &self,
        req: &PublishRequest,
        raw_body_bytes: usize,
    ) -> Result<ValidatedPublish, AcdpError> {
        // Run the full schema-aligned validation (string lengths, array
        // uniqueness, DataRef oneOf + URI rules, metadata depth/size,
        // visibility/audience invariants, did:web check, signature length,
        // identifier patterns, version coherence) on top of the raw
        // structural / cryptographic steps below. This makes
        // `validate_post_schema` a complete RFC-ACDP-0003 §2.1
        // implementation regardless of whether the producer side ran
        // [`acdp_validation::validate_publish_request`] first.
        acdp_validation::validate_publish_request(req)?;
        self.validate_registry_limits_and_crypto(req, raw_body_bytes)
    }

    /// Deprecated alias — now routes through [`Self::validate_post_schema`].
    ///
    /// The previous implementation skipped the schema-level validation
    /// (title length, metadata depth, DataRef integrity, did:web check,
    /// version coherence, …). Callers using `validate_structural`
    /// directly were silently bypassing those checks. The deprecated
    /// alias now runs the full pipeline so existing call sites remain
    /// safe; new code should call `validate_post_schema` explicitly.
    #[deprecated(
        since = "0.1.0",
        note = "Use validate_post_schema; this alias no longer skips runtime validation"
    )]
    pub fn validate_structural(
        &self,
        req: &PublishRequest,
        raw_body_bytes: usize,
    ) -> Result<ValidatedPublish, AcdpError> {
        self.validate_post_schema(req, raw_body_bytes)
    }

    /// Internal: registry-limit + cryptographic step list (no schema
    /// validation). Keep private — bypassing the schema validation is
    /// not a publishable surface.
    fn validate_registry_limits_and_crypto(
        &self,
        req: &PublishRequest,
        raw_body_bytes: usize,
    ) -> Result<ValidatedPublish, AcdpError> {
        // Step 2: payload size
        if raw_body_bytes as u64 > self.caps.limits.max_payload_bytes {
            return Err(AcdpError::SchemaViolation(format!(
                "payload {} bytes exceeds limit {}",
                raw_body_bytes, self.caps.limits.max_payload_bytes
            )));
        }

        // Step 3: embedded size + optional embedded content_hash check
        // (RFC-ACDP-0003 §2.1 step 3 last sentence; RFC-ACDP-0002 §6.6 #8).
        for dr in &req.data_refs {
            if let Some(emb) = &dr.embedded {
                let decoded = acdp_validation::embedded_decoded_bytes(emb)?;
                if decoded.len() as u64 > self.caps.limits.max_embedded_bytes {
                    return Err(AcdpError::EmbeddedTooLarge(format!(
                        "embedded data reference {} bytes exceeds {} limit",
                        decoded.len(),
                        self.caps.limits.max_embedded_bytes
                    )));
                }
                // If the producer declared an embedded content_hash, recompute
                // and verify per §2.1 step 3.
                acdp_validation::verify_embedded_hash(dr)?;
            }
        }

        // Step 4: hash recomputation over ProducerContent
        let body_val = serde_json::to_value(req)?;
        let recomputed = compute_content_hash(&body_val)?;
        if recomputed != req.content_hash {
            return Err(AcdpError::HashMismatch {
                stored: req.content_hash.clone(),
                recomputed: recomputed.clone(),
            });
        }

        // Step 5: algorithm check
        if !self
            .caps
            .supported_signature_algorithms
            .iter()
            .any(|a| a == &req.signature.algorithm)
        {
            return Err(AcdpError::SchemaViolation(format!(
                "unsupported algorithm '{}'; registry supports {:?}",
                req.signature.algorithm, self.caps.supported_signature_algorithms,
            )));
        }

        // Step 5.5: DID-method gate — the producer's method must be one
        // this registry advertises in `supported_did_methods` (ACDP 0.2:
        // did:key acceptance is a per-registry capabilities decision;
        // did:web is mandatory for every registry). Maps to
        // `key_resolution_failed` (permanent): the registry has no
        // resolver for the method, and no retry will grow one.
        let agent_method = req
            .agent_id
            .as_str()
            .splitn(3, ':')
            .take(2)
            .collect::<Vec<_>>()
            .join(":");
        if !self.caps.supports_did_method(&agent_method) {
            return Err(AcdpError::KeyResolution(format!(
                "agent_id method '{agent_method}' is not in this registry's \
                 supported_did_methods {:?}",
                self.caps.supported_did_methods
            )));
        }

        // Step 6: key-id binding — DID portion must equal agent_id
        let key_id = &req.signature.key_id;
        let did_part = key_id.split_once('#').map(|(d, _)| d).ok_or_else(|| {
            AcdpError::KeyResolution(format!("key_id '{key_id}' has no '#fragment'"))
        })?;

        if did_part != req.agent_id.as_str() {
            return Err(AcdpError::KeyNotAuthorized(format!(
                "key_id DID '{did_part}' ≠ agent_id '{}'",
                req.agent_id
            )));
        }

        // Cross-registry supersession check — v0.1.0 only allows same-registry.
        if let (Some(own), Some(target)) = (self.own_authority, &req.supersedes) {
            let target_authority = target.authority();
            if target_authority != own {
                return Err(AcdpError::SupersededTarget {
                    reason: acdp_primitives::error::SupersessionReason::CrossRegistrySupersessionUnsupported,
                    message: format!(
                        "supersedes target on '{target_authority}' rejected by '{own}'; \
                         v0.1.0 only allows same-registry supersession"
                    ),
                });
            }
        }

        // RFC-ACDP-0014 §10: a registry advertising acdp_version >= 0.5.0
        // MUST reject any *new* publish typed as the interim
        // `acdp:key-revocation` form outright — unconditionally, whatever
        // `supersedes` carries or what its target's type is. The interim
        // form is retired at 0.5.0 in favor of the standard
        // `key-revocation` context_type; this check must run before the
        // §4 gate below, since `is_key_revocation()` still treats the
        // interim form as revocation-equivalent and would otherwise
        // accept it.
        if is_interim_key_revocation_form(&req.context_type)
            && key_revocation_retirement_gate_applies(&self.caps.acdp_version)
        {
            return Err(AcdpError::SchemaViolation(format!(
                "context_type '{}' (the interim key-revocation form) is retired for \
                 registries advertising acdp_version >= 0.5.0 (RFC-ACDP-0014 §10); \
                 publish using the standard 'key-revocation' context_type instead",
                ContextType::KEY_REVOCATION_INTERIM
            )));
        }

        // RFC-ACDP-0014 §4 publish-time gate: registries advertising
        // acdp_version >= 0.3.0 MUST reject malformed key-revocation
        // bodies with schema_violation. See `key_revocation_gate_applies`
        // for the fail-closed polarity on a malformed acdp_version.
        if req.context_type.is_key_revocation()
            && key_revocation_gate_applies(&self.caps.acdp_version)
        {
            let revocation = KeyRevocation::from_publish_request(req)?;
            self.check_revocation_controller(req, &revocation)?;
        }

        // Steps 7–8 (key resolution + signature verification) require async
        // DID resolution; the caller should invoke Verifier::verify_body for those.
        Ok(ValidatedPublish {
            recomputed_hash: recomputed,
        })
    }

    /// RFC-ACDP-0014 §4/§6 controller-class rule — the one clause
    /// `KeyRevocation::from_publish_request` cannot enforce on its own
    /// because it needs the registry's own identity
    /// (`caps.registry_did`), which lives only here.
    ///
    /// Five arms (§4 makes the controller OPTIONAL — defaulting to
    /// `agent_id` — on producer-signed revocations; §6 makes it REQUIRED
    /// and different on registry-attested ones):
    ///
    /// 1. absent, `agent_id != registry_did` ⇒ OK (producer-signed, defaulted).
    /// 2. present, `== agent_id` ⇒ OK (producer-signed, explicit).
    /// 3. present, `!= agent_id`, `agent_id == registry_did` ⇒ OK (§6 registry-attested).
    /// 4. present, `!= agent_id`, `agent_id != registry_did` ⇒ `SchemaViolation`.
    /// 5. absent, `agent_id == registry_did` ⇒ `SchemaViolation` — §4 and §6 step 2
    ///    both make the controller REQUIRED on registry-attested revocations; without
    ///    this arm a registry publishing under its own DID with no controller would be
    ///    silently classified `ProducerSigned` by `from_parts`, i.e. treated as revoking
    ///    its own key.
    ///
    /// Arm 5 is indistinguishable from arm 2 by inspecting the returned
    /// `KeyRevocation` alone — `from_parts` collapses an absent controller
    /// to `(agent_id.clone(), ProducerSigned)`, exactly what arm 2
    /// produces. So presence is read directly off `req.metadata` here,
    /// not inferred from the parsed struct.
    fn check_revocation_controller(
        &self,
        req: &PublishRequest,
        revocation: &KeyRevocation,
    ) -> Result<(), AcdpError> {
        let controller_present = req
            .metadata
            .as_ref()
            .and_then(|m| m.as_object())
            .is_some_and(|m| m.contains_key("revoked_key_controller"));

        let agent_is_registry = req.agent_id.as_str() == self.caps.registry_did;
        let controller_differs = revocation.revoked_key_controller != req.agent_id;

        if controller_present && controller_differs && !agent_is_registry {
            // Arm 4.
            return Err(AcdpError::SchemaViolation(format!(
                "metadata.revoked_key_controller '{}' differs from agent_id '{}', but \
                 agent_id is not this registry's own DID ('{}'); a controller different \
                 from agent_id is only valid on a §6 registry-attested revocation \
                 (RFC-ACDP-0014 §4, §6)",
                revocation.revoked_key_controller, req.agent_id, self.caps.registry_did
            )));
        }

        if !controller_present && agent_is_registry {
            // Arm 5.
            return Err(AcdpError::SchemaViolation(format!(
                "key-revocation published under this registry's own DID ('{}') has no \
                 metadata.revoked_key_controller; a registry-attested revocation MUST \
                 name the affected producer's DID as the controller (RFC-ACDP-0014 §4, §6)",
                self.caps.registry_did
            )));
        }

        Ok(())
    }
}

/// True when `v` is a well-formed `major.minor.patch` version string:
/// exactly three non-empty, all-ASCII-digit, dot-separated parts. Mirrors
/// `acdp_validation::validate_semver_pattern`'s notion of well-formedness
/// (kept as a private, local copy here rather than a shared export, since
/// this gate's fail-closed polarity on malformed input is specific to an
/// admission check and should not be exposed as a general-purpose helper).
fn is_well_formed_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// RFC-ACDP-0014 §4 version gate, fail-closed.
///
/// A malformed `acdp_version` must turn the gate ON, never OFF. This
/// checks well-formedness first (exactly three non-empty, all-digit,
/// dot-separated parts — same criteria as
/// `acdp_validation::validate_semver_pattern`) before doing any numeric
/// comparison. Merely counting how many dot-separated parts parse as a
/// number *anywhere* in the string is not enough: `"0.3x.0"` and
/// `"0. 3.0"` both contain two parseable numeric parts (`0` and `0`) and
/// would be silently misread as version `0.0`, and `"0.2.0 "` /
/// `"0.2.0;"` would be misread as `0.2` — all turning the gate OFF when
/// it must stay ON for anything that isn't a clean `major.minor.patch`.
///
/// `pub` (not merely `pub(crate)`): `RegistryServer::publish_verified_in_tenant`
/// (server.rs) reuses this exact predicate to gate the §5 step 2
/// did:web self-sign check on the same version boundary as the §4
/// shape gate above — a second, independent version-comparison helper
/// would risk drifting from this one's fail-closed polarity. It is
/// also the version predicate an external registry implementer needs
/// to decide whether [`check_revocation_supersession`] applies to a
/// given publish — the two are promoted to `pub` together so a rule
/// is never reachable without the gate that decides when to call it.
pub fn key_revocation_gate_applies(acdp_version: &str) -> bool {
    if !is_well_formed_version(acdp_version) {
        return true;
    }
    let mut parts = acdp_version.split('.');
    let major: u64 = match parts.next().and_then(|p| p.parse().ok()) {
        Some(m) => m,
        None => return true,
    };
    let minor: u64 = match parts.next().and_then(|p| p.parse().ok()) {
        Some(m) => m,
        None => return true,
    };
    major > 0 || minor >= 3
}

/// True only for the *interim* `acdp:key-revocation` custom `context_type`
/// — unlike [`ContextType::is_key_revocation`], this excludes the standard
/// `ContextType::KeyRevocation` form. RFC-ACDP-0014 §10 retires only the
/// interim spelling at 0.5.0, not the `key-revocation` type itself.
fn is_interim_key_revocation_form(ct: &ContextType) -> bool {
    matches!(ct, ContextType::Custom(s) if s == ContextType::KEY_REVOCATION_INTERIM)
}

/// RFC-ACDP-0014 §10 version gate (interim-form retirement), fail-closed
/// on the same well-formedness rule as [`key_revocation_gate_applies`] —
/// see that function's doc comment for why malformed input must turn the
/// gate ON, never OFF. Threshold is `>= 0.5.0` instead of `>= 0.3.0`.
///
/// **Not** reused for §4 Arm 3's error-code selection — see
/// [`advertises_0_5_0_or_higher`], which answers a related but distinct
/// question with the opposite polarity on malformed input.
fn key_revocation_retirement_gate_applies(acdp_version: &str) -> bool {
    if !is_well_formed_version(acdp_version) {
        return true;
    }
    let mut parts = acdp_version.split('.');
    let major: u64 = match parts.next().and_then(|p| p.parse().ok()) {
        Some(m) => m,
        None => return true,
    };
    let minor: u64 = match parts.next().and_then(|p| p.parse().ok()) {
        Some(m) => m,
        None => return true,
    };
    major > 0 || minor >= 5
}

/// Strictly "is this a well-formed `acdp_version` string that parses to
/// `>= 0.5.0`" — used only to gate Arm 3's error-code choice in
/// [`check_revocation_supersession`], and deliberately does **not** fail
/// closed toward `true` on malformed input the way
/// [`key_revocation_retirement_gate_applies`] does.
///
/// The two functions answer different questions. §10's gate decides
/// whether to *reject at all*, where fail-closed-toward-rejecting is the
/// safe direction. This function instead decides which of two rejection
/// codes to emit — Arm 3 rejects unconditionally either way — and
/// `registries/error-codes.md` states `revocation_type_mismatch` "MUST
/// NOT be emitted by implementations declaring `acdp_version < 0.5.0`". A
/// malformed version string is not a legitimate `>= 0.5.0` declaration, so
/// this returns `false` on malformed input (falling back to the
/// long-established `schema_violation` code) rather than `true` — the
/// conservative choice is the one that can't violate that MUST NOT.
fn advertises_0_5_0_or_higher(acdp_version: &str) -> bool {
    if !is_well_formed_version(acdp_version) {
        return false;
    }
    let mut parts = acdp_version.split('.');
    let major: u64 = match parts.next().and_then(|p| p.parse().ok()) {
        Some(m) => m,
        None => return false,
    };
    let minor: u64 = match parts.next().and_then(|p| p.parse().ok()) {
        Some(m) => m,
        None => return false,
    };
    major > 0 || minor >= 5
}

/// RFC-ACDP-0014 §4 `supersedes` row for `key-revocation` contexts.
///
/// Verbatim (§4): "A revocation context MAY be superseded only by
/// another `key-revocation` context from the same signer class (e.g.
/// to widen — never narrow — the compromise window by moving T
/// earlier). Consumers MUST treat the earliest `compromised_since`
/// across a revocation lineage as effective."
///
/// This function enforces exactly the *type* and *signer-class*
/// halves of that sentence — nothing else. It does NOT compare
/// `compromised_since` in either direction: the RFC's "widen, never
/// narrow" clause is illustrative of *why* a producer would supersede
/// a revocation, not an additional publish-time constraint — per §4:58
/// the monotonicity protection belongs on the consumer side, as the
/// earliest-T rule. [`acdp_types::revocation::effective_boundary`]
/// implements that fold correctly, and — as of issue #226 — assembling
/// its input from a registry is wired end-to-end on the consumer side:
/// `acdp_client::revocation::{find_revocations, find_registry_attested_revocations,
/// find_revocations_in_lineage}` each walk a candidate's full lineage
/// (via `GET /lineages/{id}`, including superseded and retracted
/// members) rather than trusting a single search-visible one, so a
/// consumer that feeds `effective_boundary`'s input from one of those
/// helpers gets the earliest-T guarantee genuinely, not merely
/// aspirationally. Nothing about that consumer-side guarantee changes
/// this function's own scope, which stays deliberately narrow: gating
/// the *publish-time* direction too (rejecting a narrowing
/// `compromised_since` here) would let an attacker who has learned a
/// key is compromised deny its legitimate producer the ability to
/// publish a corrected, earlier-T revocation superseding a prior one
/// that understated the window — RFC-ACDP-0014 §4:58's normative verb
/// ("Consumers MUST …") already places the monotonicity obligation on
/// the consumer side, not the publish path.
///
/// "Signer class" is [`acdp_types::revocation::RevocationTrustClass`]
/// (`ProducerSigned` vs. `RegistryAttested`) — **not** same-DID; RFC-ACDP-0014
/// §13 explicitly blesses cross-producer registry-attested revocations
/// superseding one another.
///
/// Caller contract (this function does NOT re-derive these on its
/// own):
/// - `prev` is the current, non-superseded version of the lineage the
///   incoming request's `supersedes` names — the store has already
///   confirmed the target exists, belongs to the same tenant, is
///   owned by the requester, and is not already superseded (§4's "arm
///   5" concerns, entirely outside this function's scope).
/// - Call this only when [`key_revocation_gate_applies`] returns
///   `true` for the registry's advertised `acdp_version` — pre-0.3.0
///   registries have no `key-revocation` vocabulary to enforce this
///   against.
/// - `acdp_version` is the registry's own advertised version (i.e. the
///   same string passed to [`key_revocation_gate_applies`] above) — used
///   only to pick Arm 3's error code, per RFC-ACDP-0014 §10.
///
/// Arms (see the Phase 5 plan for the full table):
///
/// **Arm 1** — `prev` key-revocation, `req` key-revocation, same class
/// ⇒ `Ok` (regardless of `compromised_since` direction — arm 6 is just
/// a special case of this).
///
/// **Arm 2** — `prev` key-revocation, `req` key-revocation, different
/// class ⇒ `SchemaViolation`.
///
/// **Arm 3** — `prev` key-revocation, `req` NOT a key-revocation ⇒
/// `SupersededTarget`/`RevocationTypeMismatch` at `acdp_version >= 0.5.0`,
/// `SchemaViolation` below it (RFC-ACDP-0014 §10) — the security payload:
/// without this, the holder of a compromised key could re-point the
/// lineage head away from the revocation with an ordinary body, since
/// #207's §5 step 2 not-self-signed check only fires for
/// `is_key_revocation()` bodies.
///
/// **Arm 4** — `prev` NOT a key-revocation ⇒ `Ok` unconditionally —
/// out of scope for this §4 row; whatever `req` is, nothing here
/// constrains it.
///
/// **Arm 6b** — `prev` is (interim-form) a key-revocation but
/// `KeyRevocation::from_body(prev)` fails to parse (a malformed
/// pre-0.3.0-stored body) ⇒ arm 3's type rule still applies (`req`
/// must be a key-revocation), but the signer-class comparison is
/// skipped since there is no parsed `prev` class to compare against —
/// allow. This arm is unreachable on a ≥ 0.3.0 registry: every publish
/// path routes through `validate_post_schema`, which runs
/// `KeyRevocation::from_publish_request(req)?` when
/// [`key_revocation_gate_applies`] is true, and `Body::from_publish_request`
/// (`acdp_types::body`) copies verbatim the exact five fields
/// `KeyRevocation::from_parts` reads — so a `Body` stored through that
/// path always has `from_body(stored) ≡ from_publish_request(req)`,
/// meaning `from_body` cannot fail there either. A future normalizing
/// change to `Body` that broke that equivalence would turn this arm
/// into a live escape hatch — see the inline comment at the match arm
/// below.
pub fn check_revocation_supersession(
    prev: &Body,
    req: &PublishRequest,
    acdp_version: &str,
) -> Result<(), AcdpError> {
    if !prev.context_type.is_key_revocation() {
        // Arm 4: whatever `prev` is, this §4 row does not constrain
        // its supersession.
        return Ok(());
    }

    if !req.context_type.is_key_revocation() {
        // Arm 3: the security payload. `prev` is a safety broadcast;
        // only another key-revocation may take over its lineage head.
        //
        // RFC-ACDP-0014 §10 (0.5.0 registry amendments): a registry
        // advertising acdp_version >= 0.5.0 MUST reject this case with
        // SupersededTarget/revocation_type_mismatch instead of the
        // historical schema_violation. The rejection itself is
        // deliberately unconditional on the version — only the wire
        // code changes below 0.5.0 (see this plan's Open Questions for
        // why weakening the rejection itself below 0.5.0 would be a
        // security regression, not spec compliance). Uses
        // `advertises_0_5_0_or_higher`, NOT the §10 gate above — a
        // malformed `acdp_version` must still reject (fail-closed) but
        // must NOT claim the new, more specific error code.
        if advertises_0_5_0_or_higher(acdp_version) {
            return Err(AcdpError::SupersededTarget {
                reason: acdp_primitives::error::SupersessionReason::RevocationTypeMismatch,
                message: format!(
                    "ctx_id '{}' is a key-revocation context and MAY only be superseded by \
                     another key-revocation context (RFC-ACDP-0014 §4); the incoming publish \
                     from agent_id '{}' has type '{}'",
                    prev.ctx_id,
                    req.agent_id,
                    context_type_label(&req.context_type),
                ),
            });
        }
        return Err(AcdpError::SchemaViolation(format!(
            "ctx_id '{}' is a key-revocation context and MAY only be superseded by \
             another key-revocation context (RFC-ACDP-0014 §4); the incoming publish \
             from agent_id '{}' has type '{}'",
            prev.ctx_id,
            req.agent_id,
            context_type_label(&req.context_type),
        )));
    }

    // Both PREV and IN are key-revocations. Arms 1/2/6/6b turn on the
    // signer class, which requires parsing PREV's metadata.
    let prev_revocation = match KeyRevocation::from_body(prev) {
        Ok(r) => r,
        Err(_) => {
            // Arm 6b: PREV was stored as a key-revocation (by type) but
            // does not shape-validate today — most plausibly a
            // pre-0.3.0 body admitted before this rule existed. Arm 3's
            // type rule already passed above; there is no parsed class
            // to compare IN against, so allow rather than fail closed
            // on a predecessor this function did not admit.
            //
            // Load-bearing equivalence: on ≥ 0.3.0 this branch is
            // unreachable, because `from_body(stored) ≡
            // from_publish_request(req)` — `Body::from_publish_request`
            // copies verbatim the same five fields
            // `KeyRevocation::from_parts` reads, and the publish gate
            // already required `from_publish_request` to succeed. If a
            // future change to `Body::from_publish_request` ever stops
            // copying one of those fields verbatim, this arm silently
            // becomes reachable again as an allow-anything escape
            // hatch for a well-formed stored revocation.
            return Ok(());
        }
    };

    let incoming_revocation = KeyRevocation::from_publish_request(req)?;

    if prev_revocation.trust_class == incoming_revocation.trust_class {
        // Arms 1 and 6: same signer class, any `compromised_since`
        // direction.
        Ok(())
    } else {
        // Arm 2: signer class changed across the supersession.
        Err(AcdpError::SchemaViolation(format!(
            "ctx_id '{}' is a key-revocation with signer class {:?}; the incoming \
             supersession from agent_id '{}' is a key-revocation with signer class {:?} \
             — a revocation MAY only be superseded by another key-revocation from the \
             same signer class (RFC-ACDP-0014 §4)",
            prev.ctx_id, prev_revocation.trust_class, req.agent_id, incoming_revocation.trust_class,
        )))
    }
}

/// Human-readable label for a [`acdp_types::primitives::ContextType`]
/// for use in error messages only (mirrors the `serde_json` round-trip
/// `acdp_types::revocation` already uses for the same purpose).
fn context_type_label(context_type: &acdp_types::primitives::ContextType) -> String {
    serde_json::to_value(context_type)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<unrepresentable>".into())
}

/// Assign registry identifiers after successful validation per
/// RFC-ACDP-0001 §5.6.
///
/// For first-version publications (`supersedes == None`,
/// `first_version_ctx_id == None`), `lineage_id` is derived from the newly
/// assigned `ctx_id`. For supersession (`supersedes == Some(_)`), the
/// caller MUST supply the v1 `ctx_id` of the lineage so `lineage_id` is
/// derived from it — using the new ctx_id would orphan the supersession
/// from its lineage.
///
/// Returns `SchemaViolation` if `supersedes` is set but
/// `first_version_ctx_id` is not.
pub fn assign_identifiers(
    authority: &str,
    supersedes: &Option<CtxId>,
    first_version_ctx_id: Option<&CtxId>,
    _validated: &ValidatedPublish,
) -> Result<(CtxId, LineageId), AcdpError> {
    let uuid = uuid::Uuid::new_v4();
    let ctx_id = CtxId(format!("acdp://{authority}/{uuid}"));
    let lineage_source: &CtxId = match (supersedes, first_version_ctx_id) {
        (None, _) => &ctx_id,
        (Some(_), Some(v1)) => v1,
        (Some(_), None) => {
            return Err(AcdpError::SchemaViolation(
                "supersession assignment requires the v1 ctx_id to derive lineage_id".into(),
            ));
        }
    };
    let lineage_id = derive_lineage_id(lineage_source);
    Ok((ctx_id, lineage_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_crypto::SigningKey;
    use acdp_producer::Producer;
    use acdp_types::{
        capabilities::Limits,
        primitives::{AgentDid, ContextType, Visibility},
        revocation::RevocationTrustClass,
    };

    fn test_caps() -> CapabilitiesDocument {
        CapabilitiesDocument {
            acdp_version: "0.1.0".into(),
            registry_did: "did:web:registry.example.com".into(),
            supported_signature_algorithms: vec!["ed25519".into()],
            supported_did_methods: vec!["did:web".into()],
            profiles: vec!["acdp-registry-core".into()],
            limits: Limits {
                max_payload_bytes: 1_048_576,
                max_embedded_bytes: 65_536,
                idempotency_key_ttl_seconds: None,
                max_publish_per_minute: None,
            },
            read_authentication_methods: vec![],
            anonymous_public_reads: true,
            supports_idempotency_key: false,
            extensions: Default::default(),
        }
    }

    fn test_request() -> PublishRequest {
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new("did:web:agents.example.com:test-producer"),
            "did:web:agents.example.com:test-producer#key-1",
        );
        p.publish_request()
            .title("Golden test vector — minimal first version")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap()
    }

    #[test]
    fn happy_path_validates() {
        let caps = test_caps();
        let v = PublishValidator::new(&caps);
        let req = test_request();
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    #[test]
    fn payload_too_large_rejected() {
        let mut caps = test_caps();
        caps.limits.max_payload_bytes = 10;
        let v = PublishValidator::new(&caps);
        let req = test_request();
        let err = v.validate_post_schema(&req, 1024).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn unsupported_algorithm_rejected() {
        let mut caps = test_caps();
        caps.supported_signature_algorithms = vec!["secp256k1".into()];
        let v = PublishValidator::new(&caps);
        let req = test_request();
        let err = v.validate_post_schema(&req, 1024).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn key_id_without_fragment_rejected() {
        let caps = test_caps();
        let v = PublishValidator::new(&caps);
        let mut req = test_request();
        req.signature.key_id = "did:web:agents.example.com:test-producer".into();
        let err = v.validate_post_schema(&req, 1024).unwrap_err();
        assert!(matches!(err, AcdpError::KeyResolution(_)));
    }

    #[test]
    fn key_id_did_must_match_agent_id() {
        let caps = test_caps();
        let v = PublishValidator::new(&caps);
        let mut req = test_request();
        req.signature.key_id = "did:web:other.example.com:attacker#key-1".into();
        let err = v.validate_post_schema(&req, 1024).unwrap_err();
        assert!(matches!(err, AcdpError::KeyNotAuthorized(_)));
    }

    #[test]
    fn tampered_hash_detected() {
        let caps = test_caps();
        let v = PublishValidator::new(&caps);
        let mut req = test_request();
        req.title = "tampered title".into();
        let err = v.validate_post_schema(&req, 1024).unwrap_err();
        assert!(matches!(err, AcdpError::HashMismatch { .. }));
    }

    #[test]
    fn assign_identifiers_first_version_derives_lineage_from_new_id() {
        let v = ValidatedPublish {
            recomputed_hash: ContentHash("sha256:abcd".into()),
        };
        let (ctx_id, lineage_id) =
            assign_identifiers("registry.example.com", &None, None, &v).unwrap();
        let expected = derive_lineage_id(&ctx_id);
        assert_eq!(lineage_id, expected);
    }

    #[test]
    fn assign_identifiers_supersession_uses_v1_ctx_id() {
        let v = ValidatedPublish {
            recomputed_hash: ContentHash("sha256:abcd".into()),
        };
        let v1 = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
        let supersedes = Some(CtxId(
            "acdp://registry.example.com/12345678-1234-4321-8123-123456781299".into(),
        ));
        let (_new_id, lineage_id) =
            assign_identifiers("registry.example.com", &supersedes, Some(&v1), &v).unwrap();
        assert_eq!(lineage_id, derive_lineage_id(&v1));
    }

    #[test]
    fn cross_registry_supersession_rejected() {
        let caps = test_caps();
        let v = PublishValidator::for_authority(&caps, "registry.example.com");
        // Build a v2 request that supersedes a context on a different registry
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new("did:web:agents.example.com:test-producer"),
            "did:web:agents.example.com:test-producer#key-1",
        );
        let other_reg =
            CtxId("acdp://other.example.com/12345678-1234-4321-8123-123456781234".into());
        let req = p
            .supersede(other_reg)
            .version(2)
            .title("v2")
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap();
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        match err {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(
                    reason,
                    acdp_primitives::error::SupersessionReason::CrossRegistrySupersessionUnsupported
                );
            }
            other => panic!("expected SupersededTarget, got {other:?}"),
        }
    }

    #[test]
    fn same_registry_supersession_passes_authority_check() {
        let caps = test_caps();
        let v = PublishValidator::for_authority(&caps, "registry.example.com");
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new("did:web:agents.example.com:test-producer"),
            "did:web:agents.example.com:test-producer#key-1",
        );
        let same = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
        let req = p
            .supersede(same)
            .version(2)
            .title("v2")
            .context_type(ContextType::DataSnapshot)
            .build()
            .unwrap();
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    #[test]
    fn assign_identifiers_supersession_without_v1_id_rejected() {
        let v = ValidatedPublish {
            recomputed_hash: ContentHash("sha256:abcd".into()),
        };
        let supersedes = Some(CtxId("acdp://x/y".into()));
        let err = assign_identifiers("registry.example.com", &supersedes, None, &v).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    // ── Phase 6: RFC-ACDP-0014 §4 key-revocation publish-time gate ─────

    fn test_caps_v030() -> CapabilitiesDocument {
        CapabilitiesDocument {
            acdp_version: "0.3.0".into(),
            ..test_caps()
        }
    }

    fn test_caps_v020() -> CapabilitiesDocument {
        CapabilitiesDocument {
            acdp_version: "0.2.0".into(),
            ..test_caps()
        }
    }

    fn test_caps_v050() -> CapabilitiesDocument {
        CapabilitiesDocument {
            acdp_version: "0.5.0".into(),
            ..test_caps()
        }
    }

    const REVOCATION_PRODUCER_DID: &str = "did:web:agents.example.com:test-producer";
    const REVOCATION_OTHER_PRODUCER_DID: &str = "did:web:agents.example.com:other-producer";
    const REVOCATION_FP: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REVOCATION_SINCE: &str = "2026-05-01T00:00:00.000Z";

    fn valid_revocation_metadata() -> serde_json::Value {
        serde_json::json!({
            "revoked_key_fingerprint": REVOCATION_FP,
            "compromised_since": REVOCATION_SINCE,
        })
    }

    /// Builds a signed `key-revocation` `PublishRequest` published under
    /// `agent_did`, with the given `metadata` and wire `acdp_version`
    /// field (independent of the *registry's* `caps.acdp_version` under
    /// test).
    fn build_revocation_request(
        agent_did: &str,
        metadata: serde_json::Value,
        acdp_version: &str,
    ) -> PublishRequest {
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(key, AgentDid::new(agent_did), format!("{agent_did}#key-1"));
        p.publish_request()
            .title("Key revocation test")
            .context_type(ContextType::KeyRevocation)
            .visibility(Visibility::Public)
            .acdp_version(acdp_version)
            .metadata(metadata)
            .build()
            .unwrap()
    }

    // Arm 1: controller absent, agent_id != registry_did ⇒ OK
    // (producer-signed, defaulted).
    #[test]
    fn revocation_arm1_absent_controller_accepted_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let req = build_revocation_request(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(),
            "0.3.0",
        );
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    // Arm 2: controller present and == agent_id ⇒ OK (producer-signed,
    // explicit).
    #[test]
    fn revocation_arm2_explicit_matching_controller_accepted_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta["revoked_key_controller"] = serde_json::json!(REVOCATION_PRODUCER_DID);
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    // Arm 3: controller present, != agent_id, agent_id == registry_did ⇒
    // OK (§6 registry-attested).
    #[test]
    fn revocation_arm3_registry_attested_accepted_at_0_3_0() {
        let caps = test_caps_v030();
        let registry_did = caps.registry_did.clone();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta["revoked_key_controller"] = serde_json::json!(REVOCATION_PRODUCER_DID);
        let req = build_revocation_request(&registry_did, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    // Arm 4: controller present, != agent_id, agent_id != registry_did ⇒
    // SchemaViolation.
    #[test]
    fn revocation_arm4_mismatched_controller_rejected_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta["revoked_key_controller"] = serde_json::json!(REVOCATION_OTHER_PRODUCER_DID);
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn revocation_arm4_accepted_at_0_2_0_positive_control() {
        let caps = test_caps_v020();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta["revoked_key_controller"] = serde_json::json!(REVOCATION_OTHER_PRODUCER_DID);
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    // Arm 5 — the one everyone misses: controller absent, agent_id ==
    // registry_did ⇒ SchemaViolation. Indistinguishable from arm 1/2 by
    // inspecting the returned `KeyRevocation` alone (`from_parts`
    // collapses an absent controller to `(agent_id.clone(),
    // ProducerSigned)`), so the gate must read presence off
    // `req.metadata` directly.
    #[test]
    fn revocation_arm5_absent_controller_under_registry_did_rejected_at_0_3_0() {
        let caps = test_caps_v030();
        let registry_did = caps.registry_did.clone();
        let v = PublishValidator::new(&caps);
        let req = build_revocation_request(&registry_did, valid_revocation_metadata(), "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn revocation_arm5_accepted_at_0_2_0_positive_control() {
        let caps = test_caps_v020();
        let registry_did = caps.registry_did.clone();
        let v = PublishValidator::new(&caps);
        let req = build_revocation_request(&registry_did, valid_revocation_metadata(), "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    #[test]
    fn revocation_non_public_visibility_rejected_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new(REVOCATION_PRODUCER_DID),
            format!("{REVOCATION_PRODUCER_DID}#key-1"),
        );
        let req = p
            .publish_request()
            .title("Key revocation test")
            .context_type(ContextType::KeyRevocation)
            .visibility(Visibility::Restricted)
            .audience(vec![AgentDid::new(REVOCATION_PRODUCER_DID)])
            .acdp_version("0.3.0")
            .metadata(valid_revocation_metadata())
            .build()
            .unwrap();
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn revocation_non_public_visibility_accepted_at_0_2_0_positive_control() {
        let caps = test_caps_v020();
        let v = PublishValidator::new(&caps);
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new(REVOCATION_PRODUCER_DID),
            format!("{REVOCATION_PRODUCER_DID}#key-1"),
        );
        let req = p
            .publish_request()
            .title("Key revocation test")
            .context_type(ContextType::KeyRevocation)
            .visibility(Visibility::Restricted)
            .audience(vec![AgentDid::new(REVOCATION_PRODUCER_DID)])
            .acdp_version("0.3.0")
            .metadata(valid_revocation_metadata())
            .build()
            .unwrap();
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    #[test]
    fn revocation_missing_fingerprint_rejected_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta.as_object_mut()
            .unwrap()
            .remove("revoked_key_fingerprint");
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn revocation_missing_fingerprint_accepted_at_0_2_0_positive_control() {
        let caps = test_caps_v020();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta.as_object_mut()
            .unwrap()
            .remove("revoked_key_fingerprint");
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    #[test]
    fn revocation_missing_compromised_since_rejected_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta.as_object_mut().unwrap().remove("compromised_since");
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn revocation_missing_compromised_since_accepted_at_0_2_0_positive_control() {
        let caps = test_caps_v020();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta.as_object_mut().unwrap().remove("compromised_since");
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    #[test]
    fn revocation_malformed_fingerprint_rejected_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta["revoked_key_fingerprint"] = serde_json::json!("not-a-fingerprint");
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn revocation_malformed_fingerprint_accepted_at_0_2_0_positive_control() {
        let caps = test_caps_v020();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta["revoked_key_fingerprint"] = serde_json::json!("not-a-fingerprint");
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    #[test]
    fn revocation_non_canonical_compromised_since_rejected_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta["compromised_since"] = serde_json::json!("2026-05-01T00:00:00Z");
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn revocation_non_canonical_compromised_since_accepted_at_0_2_0_positive_control() {
        let caps = test_caps_v020();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta["compromised_since"] = serde_json::json!("2026-05-01T00:00:00Z");
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    #[test]
    fn revocation_reason_over_limit_rejected_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta["reason"] =
            serde_json::json!("x".repeat(acdp_types::revocation::MAX_REASON_CHARS + 1));
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn revocation_reason_over_limit_accepted_at_0_2_0_positive_control() {
        let caps = test_caps_v020();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta["reason"] =
            serde_json::json!("x".repeat(acdp_types::revocation::MAX_REASON_CHARS + 1));
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    // rev-003 scenario N: the bound is INCLUSIVE — a reason of EXACTLY
    // `MAX_REASON_CHARS` MUST be accepted at 0.3.0. Paired with the
    // rejection test above (which uses `MAX_REASON_CHARS + 1`); without
    // this positive control a registry using `>= MAX_REASON_CHARS`
    // instead of `>` would pass the rejection test above while wrongly
    // rejecting exactly this length — the off-by-one this pair exists
    // to catch.
    #[test]
    fn revocation_reason_at_exactly_the_limit_accepted_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta["reason"] = serde_json::json!("x".repeat(acdp_types::revocation::MAX_REASON_CHARS));
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len)
            .expect("a reason of exactly MAX_REASON_CHARS must be accepted, not rejected");
    }

    // Malformed `acdp_version` must turn the gate ON (fail closed), not
    // off — `key_revocation_gate_applies` treats anything that is not a
    // well-formed `major.minor.patch` string as malformed rather than
    // reinterpreting it as some other version.
    #[test]
    fn revocation_gate_fails_closed_on_unparseable_acdp_version() {
        let mut caps = test_caps_v030();
        caps.acdp_version = "not-a-version".into();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta.as_object_mut()
            .unwrap()
            .remove("revoked_key_fingerprint");
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    #[test]
    fn revocation_gate_fails_closed_on_empty_acdp_version() {
        let mut caps = test_caps_v030();
        caps.acdp_version = "".into();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta.as_object_mut()
            .unwrap()
            .remove("revoked_key_fingerprint");
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    // Non-key-revocation bodies are entirely unaffected by the gate,
    // even under a 0.3.0 registry.
    #[test]
    fn non_key_revocation_body_unaffected_by_gate_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let req = test_request();
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    // `key_revocation_gate_applies` well-formedness truth table.
    //
    // The gate must NOT silently reinterpret a malformed `acdp_version`
    // string as whatever version its first two parseable numeric
    // fragments happen to spell — that reinterpretation is exactly the
    // bug being fixed here. Every entry left of `=>` is malformed (or,
    // for the last three rows, well-formed-and-comparable) and the
    // right-hand side is the required gate outcome.
    #[test]
    fn key_revocation_gate_truth_table() {
        let cases: &[(&str, bool)] = &[
            // Malformed: a typo'd patch segment must not be silently
            // read as "0.3" truncated down to "0.0".
            ("0.3x.0", true),
            // Malformed: an embedded space breaks the numeric parse of
            // that segment, and must not be read as "0.0".
            ("0. 3.0", true),
            // Malformed: trailing whitespace/punctuation after a
            // perfectly-formed "0.2.0" must not let the first two
            // fragments ("0", "2") stand in for the whole string.
            ("0.2.0 ", true),
            ("0.2.0;", true),
            // Malformed: a non-numeric minor segment.
            ("0.x.1", true),
            // Malformed: a unicode digit (ARABIC-INDIC THREE, U+0663)
            // fails `char::is_ascii_digit`, so this segment is not
            // ASCII-digit-only and the whole string is not well-formed.
            ("0.\u{0663}.0", true),
            // Already-covered malformed cases, kept here too so the
            // whole table lives in one place.
            ("not-a-version", true),
            ("", true),
            // Well-formed and >= 0.3.0 ⇒ gate ON.
            ("0.3.0", true),
            ("0.4.0", true),
            ("1.0.0", true),
            // Well-formed and < 0.3.0 ⇒ gate OFF.
            ("0.2.9", false),
            ("0.2.0", false),
        ];
        for (input, expected) in cases {
            assert_eq!(
                key_revocation_gate_applies(input),
                *expected,
                "input {input:?} should gate {}",
                if *expected { "ON" } else { "OFF" }
            );
        }
    }

    /// Like `build_revocation_request`, but lets the test pick the
    /// `ContextType` — used to publish the RFC-ACDP-0014 §10 interim
    /// `acdp:key-revocation` custom form through the gate, since
    /// `build_revocation_request` always uses the standard
    /// `ContextType::KeyRevocation`.
    fn build_revocation_request_with_type(
        agent_did: &str,
        metadata: serde_json::Value,
        acdp_version: &str,
        context_type: ContextType,
    ) -> PublishRequest {
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(key, AgentDid::new(agent_did), format!("{agent_did}#key-1"));
        p.publish_request()
            .title("Key revocation test (interim §10 type)")
            .context_type(context_type)
            .visibility(Visibility::Public)
            .acdp_version(acdp_version)
            .metadata(metadata)
            .build()
            .unwrap()
    }

    // §10: a >= 0.3.0 registry ACCEPTS the interim `acdp:key-revocation`
    // custom type — not just the standard `key-revocation` type — and
    // applies the same §4 shape validation to it, since
    // `ContextType::is_key_revocation()` treats both forms as
    // equivalent and the gate is keyed off that predicate.
    #[test]
    fn revocation_interim_custom_type_valid_body_accepted_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let req = build_revocation_request_with_type(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(),
            "0.3.0",
            ContextType::Custom(ContextType::KEY_REVOCATION_INTERIM.into()),
        );
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).unwrap();
    }

    #[test]
    fn revocation_interim_custom_type_violation_rejected_at_0_3_0() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let mut meta = valid_revocation_metadata();
        meta.as_object_mut()
            .unwrap()
            .remove("revoked_key_fingerprint");
        let req = build_revocation_request_with_type(
            REVOCATION_PRODUCER_DID,
            meta,
            "0.3.0",
            ContextType::Custom(ContextType::KEY_REVOCATION_INTERIM.into()),
        );
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    // ── Phase 4 (#279+RFC-0014-wave): RFC-ACDP-0014 §10 — interim-form
    // retirement at acdp_version >= 0.5.0. ───────────────────────────────

    // §10: a >= 0.5.0 registry rejects a *new* publish typed as the
    // interim `acdp:key-revocation` form outright, even though the body
    // is otherwise perfectly valid (same fixture that's accepted at 0.3.0
    // above) and carries no `supersedes` at all (acceptance criterion 4).
    #[test]
    fn revocation_interim_custom_type_rejected_unconditionally_at_0_5_0() {
        let caps = test_caps_v050();
        let v = PublishValidator::new(&caps);
        let req = build_revocation_request_with_type(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(),
            "0.5.0",
            ContextType::Custom(ContextType::KEY_REVOCATION_INTERIM.into()),
        );
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(
            matches!(err, AcdpError::SchemaViolation(_)),
            "the interim form must be rejected unconditionally at >= 0.5.0, got {err:?}"
        );
    }

    // §10, the other half of acceptance criterion 4: the interim form is
    // rejected unconditionally regardless of whether the publish carries a
    // `supersedes` target — unlike Arm 3, this is a flat retirement of the
    // *type*, not a supersession rule, so it must reject even a v2
    // interim-form publish superseding a v1 interim-form context.
    #[test]
    fn revocation_interim_custom_type_rejected_with_supersedes_at_0_5_0() {
        let caps = test_caps_v050();
        let v = PublishValidator::new(&caps);
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new(REVOCATION_PRODUCER_DID),
            format!("{REVOCATION_PRODUCER_DID}#key-1"),
        );
        let target =
            CtxId("acdp://registry.example.com/00000000-0000-4000-8000-000000000002".into());
        let req = p
            .supersede(target)
            .version(2)
            .title("Key revocation test (interim §10 type, v2 supersedes)")
            .context_type(ContextType::Custom(
                ContextType::KEY_REVOCATION_INTERIM.into(),
            ))
            .visibility(Visibility::Public)
            .acdp_version("0.5.0")
            .metadata(valid_revocation_metadata())
            .build()
            .unwrap();
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        let err = v.validate_post_schema(&req, raw_len).unwrap_err();
        assert!(
            matches!(err, AcdpError::SchemaViolation(_)),
            "the interim form must be rejected even when it carries a supersedes target, got {err:?}"
        );
    }

    // §10 does not over-reject: the *standard* `key-revocation`
    // context_type (not the interim custom spelling) must still be
    // accepted at acdp_version >= 0.5.0 — only the interim spelling is
    // retired (acceptance criterion 5, standard-form half).
    #[test]
    fn revocation_standard_type_still_accepted_at_0_5_0() {
        let caps = test_caps_v050();
        let v = PublishValidator::new(&caps);
        let req = build_revocation_request(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(),
            "0.5.0",
        );
        let raw_len = serde_json::to_vec(&req).unwrap().len();
        v.validate_post_schema(&req, raw_len).expect(
            "the standard key-revocation type is not retired by §10, only the interim spelling is",
        );
    }

    // ── Phase 5 (#216a): RFC-ACDP-0014 §4 `supersedes` rule —
    // `check_revocation_supersession`. Dead code until Phase 6 wires it
    // in; these tests exercise it directly. ─────────────────────────────

    /// Materializes the `Body` a registry would have stored from `req`,
    /// so `check_revocation_supersession`'s `prev: &Body` parameter can
    /// be exercised without a real store.
    fn body_from_request(req: &PublishRequest) -> Body {
        Body::from_publish_request(
            req,
            CtxId("acdp://registry.example.com/00000000-0000-4000-8000-000000000001".into()),
            LineageId(format!("lin:sha256:{}", "0".repeat(64))),
            "registry.example.com",
            chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
    }

    // Arm 1: PREV key-revocation, IN key-revocation, SAME signer class
    // ⇒ allow, regardless of `compromised_since` direction — here IN's
    // T is EARLIER than PREV's.
    #[test]
    fn revocation_supersession_same_class_allowed_t_earlier() {
        let prev_req = build_revocation_request(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(), // T = 2026-05-01
            "0.3.0",
        );
        let prev = body_from_request(&prev_req);

        let mut meta = valid_revocation_metadata();
        meta["compromised_since"] = serde_json::json!("2026-04-01T00:00:00.000Z"); // earlier
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");

        check_revocation_supersession(&prev, &req, "0.3.0")
            .expect("same signer class supersession must be allowed regardless of T direction");
    }

    // Arm 2: PREV key-revocation, IN key-revocation, DIFFERENT signer
    // class (producer-signed → registry-attested) ⇒ reject
    // SchemaViolation.
    #[test]
    fn revocation_supersession_different_class_rejected() {
        let prev_req = build_revocation_request(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(), // no controller ⇒ ProducerSigned
            "0.3.0",
        );
        let prev = body_from_request(&prev_req);

        let registry_did = test_caps().registry_did;
        let mut meta = valid_revocation_metadata();
        meta["revoked_key_controller"] = serde_json::json!(REVOCATION_PRODUCER_DID);
        let req = build_revocation_request(&registry_did, meta, "0.3.0"); // RegistryAttested

        let err = check_revocation_supersession(&prev, &req, "0.3.0").unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    // Arm 3: PREV key-revocation, IN NOT a key-revocation ⇒ reject
    // SchemaViolation. The security payload: without this, the holder
    // of the compromised key could re-point the lineage head away from
    // its own revocation with an ordinary body.
    #[test]
    fn revocation_superseded_by_non_revocation_rejected() {
        let prev_req = build_revocation_request(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(),
            "0.3.0",
        );
        let prev = body_from_request(&prev_req);
        let req = test_request(); // ordinary DataSnapshot body

        let err = check_revocation_supersession(&prev, &req, "0.3.0").unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    // Arm 3, RFC-ACDP-0014 §10: identical fixture to the test above, but at
    // a registry advertising acdp_version >= 0.5.0 — the wire code changes
    // to SupersededTarget/RevocationTypeMismatch, the rejection itself
    // unchanged (Phase 4 acceptance criterion 2).
    #[test]
    fn revocation_superseded_by_non_revocation_rejected_as_revocation_type_mismatch_at_0_5_0() {
        let prev_req = build_revocation_request(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(),
            "0.3.0",
        );
        let prev = body_from_request(&prev_req);
        let req = test_request(); // ordinary DataSnapshot body

        let err = check_revocation_supersession(&prev, &req, "0.5.0").unwrap_err();
        assert!(
            matches!(
                err,
                AcdpError::SupersededTarget {
                    reason: acdp_primitives::error::SupersessionReason::RevocationTypeMismatch,
                    ..
                }
            ),
            "expected SupersededTarget/RevocationTypeMismatch at acdp_version >= 0.5.0, got {err:?}"
        );
    }

    // Same fixture again, one version short of the 0.5.0 boundary — pins
    // the exact threshold (Phase 4 acceptance criterion 3: unchanged below
    // 0.5.0).
    #[test]
    fn revocation_superseded_by_non_revocation_still_schema_violation_below_0_5_0() {
        let prev_req = build_revocation_request(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(),
            "0.3.0",
        );
        let prev = body_from_request(&prev_req);
        let req = test_request(); // ordinary DataSnapshot body

        let err = check_revocation_supersession(&prev, &req, "0.4.9").unwrap_err();
        assert!(
            matches!(err, AcdpError::SchemaViolation(_)),
            "0.4.9 is below the 0.5.0 boundary; expected the unchanged SchemaViolation, got {err:?}"
        );
    }

    // rev-003 scenario P: identical to O above, except PREV is published
    // under the RFC-ACDP-0014 §10 INTERIM `acdp:key-revocation` form
    // rather than the standard type. `check_revocation_supersession`'s
    // Arm 3 gate is `prev.context_type.is_key_revocation()`, which
    // treats both forms as equivalent triggering predecessor types — an
    // implementation that special-cases the standard type string and
    // misses the interim one would pass O while failing here.
    #[test]
    fn revocation_superseded_by_non_revocation_rejected_as_revocation_type_mismatch_interim_predecessor_at_0_5_0(
    ) {
        let prev_req = build_revocation_request_with_type(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(),
            "0.3.0",
            ContextType::Custom(ContextType::KEY_REVOCATION_INTERIM.into()),
        );
        let prev = body_from_request(&prev_req);
        let req = test_request(); // ordinary DataSnapshot body

        let err = check_revocation_supersession(&prev, &req, "0.5.0").unwrap_err();
        assert!(
            matches!(
                err,
                AcdpError::SupersededTarget {
                    reason: acdp_primitives::error::SupersessionReason::RevocationTypeMismatch,
                    ..
                }
            ),
            "an interim-typed predecessor must trigger the same rejection as a \
             standard-typed one, got {err:?}"
        );
    }

    // rev-003 scenario R: the positive control pinning that the (0.5.0)
    // predecessor-keyed rule does not over-reject the legitimate case —
    // a key-revocation properly superseding a key-revocation, widening
    // the boundary — specifically AT the 0.5.0 boundary itself.
    // `revocation_supersession_same_class_allowed_t_earlier` above pins
    // the identical shape but only at 0.3.0; without a dedicated 0.5.0
    // test, a registry that (incorrectly) rejected every supersession of
    // a key-revocation target once acdp_version >= 0.5.0 — not only
    // non-revocation ones — would pass O/P for the wrong reason
    // (over-rejection) and nothing here would catch it.
    #[test]
    fn revocation_supersession_same_class_allowed_at_0_5_0() {
        let prev_req = build_revocation_request(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(), // T = 2026-05-01
            "0.5.0",
        );
        let prev = body_from_request(&prev_req);

        let mut meta = valid_revocation_metadata();
        meta["compromised_since"] = serde_json::json!("2026-04-01T00:00:00.000Z"); // earlier, widening
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.5.0");

        check_revocation_supersession(&prev, &req, "0.5.0").expect(
            "a same-class key-revocation supersession must still be allowed at 0.5.0 — \
             the (0.5.0) rule targets non-revocation successors only",
        );
    }

    // Arm 4: PREV NOT a key-revocation ⇒ allow unconditionally,
    // whatever IN is — out of scope for this §4 row (RFC §4 constrains
    // only what may supersede a revocation, not what a revocation may
    // supersede).
    #[test]
    fn non_revocation_predecessor_superseded_by_revocation_allowed() {
        let prev_req = test_request();
        let prev = body_from_request(&prev_req);
        let req = build_revocation_request(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(),
            "0.3.0",
        );

        check_revocation_supersession(&prev, &req, "0.3.0")
            .expect("a non-revocation predecessor is out of scope for this §4 row");
    }

    // Arm 6: same code path as arm 1, but exercising the genuinely
    // distinct direction — NARROWING the compromise window by moving T
    // LATER (arm 1 already covers "same class, T earlier"; a test that
    // also moves T earlier would just be arm 1 again). This is the arm
    // carrying the intentional residual risk: `check_revocation_supersession`
    // does not compare `compromised_since` direction at all, so a
    // narrowing supersession is allowed at publish. That is
    // spec-correct per §4:58 (the monotonicity protection belongs on
    // the consumer side via `effective_boundary`) and, as of issue
    // #226, that consumer-side guarantee is now wired end-to-end —
    // `acdp_client::revocation::find_revocations` /
    // `find_registry_attested_revocations` / `find_revocations_in_lineage`
    // walk the full lineage (superseded and retracted members
    // included) rather than trusting a single search-visible member —
    // see the doc comment above `check_revocation_supersession`.
    #[test]
    fn revocation_supersession_same_class_narrowing_t_allowed_at_publish() {
        let mut prev_meta = valid_revocation_metadata();
        prev_meta["compromised_since"] = serde_json::json!("2026-05-01T00:00:00.000Z");
        let prev_req = build_revocation_request(REVOCATION_PRODUCER_DID, prev_meta, "0.3.0");
        let prev = body_from_request(&prev_req);

        let mut meta = valid_revocation_metadata();
        meta["compromised_since"] = serde_json::json!("2026-06-01T00:00:00.000Z"); // later — narrows
        let req = build_revocation_request(REVOCATION_PRODUCER_DID, meta, "0.3.0");

        check_revocation_supersession(&prev, &req, "0.3.0").expect(
            "narrowing the compromise window (T moved later) is allowed at publish time; \
             this function enforces only type + signer class, not compromised_since \
             direction (RFC-ACDP-0014 §4:58)",
        );
    }

    // Arm 6b: PREV is a key-revocation by type but its stored body
    // fails `KeyRevocation::from_body` (malformed pre-0.3.0 body with
    // no metadata object at all) ⇒ arm 3's type rule still applies (IN
    // must be a key-revocation) but the signer-class comparison is
    // skipped since there is no parsed PREV class to compare.
    #[test]
    fn revocation_supersession_malformed_predecessor_skips_class_comparison() {
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new(REVOCATION_PRODUCER_DID),
            format!("{REVOCATION_PRODUCER_DID}#key-1"),
        );
        let prev_req = p
            .publish_request()
            .title("Malformed pre-0.3.0 key-revocation (no metadata)")
            .context_type(ContextType::KeyRevocation)
            .visibility(Visibility::Public)
            .acdp_version("0.2.0")
            .build()
            .unwrap();
        let prev = body_from_request(&prev_req);
        assert!(
            KeyRevocation::from_body(&prev).is_err(),
            "fixture must actually fail from_body, or this test proves nothing"
        );

        let req = build_revocation_request(
            REVOCATION_OTHER_PRODUCER_DID,
            valid_revocation_metadata(),
            "0.3.0",
        );

        check_revocation_supersession(&prev, &req, "0.3.0").expect(
            "arm 6b: a malformed predecessor skips the class comparison but a \
             well-formed key-revocation successor is still allowed",
        );
    }

    // Arm 6b + arm 3: the other half of arm 6b's criterion. The test
    // above only proves the signer-class comparison is skipped for a
    // malformed predecessor; it does NOT prove arm 3's type rule still
    // applies to one. This is the half that carries the security
    // weight: an unparseable stored revocation must still not be
    // supersedable by an ordinary (non-key-revocation) context.
    #[test]
    fn revocation_supersession_malformed_predecessor_still_blocks_non_revocation_successor() {
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new(REVOCATION_PRODUCER_DID),
            format!("{REVOCATION_PRODUCER_DID}#key-1"),
        );
        let prev_req = p
            .publish_request()
            .title("Malformed pre-0.3.0 key-revocation (no metadata)")
            .context_type(ContextType::KeyRevocation)
            .visibility(Visibility::Public)
            .acdp_version("0.2.0")
            .build()
            .unwrap();
        let prev = body_from_request(&prev_req);
        assert!(
            KeyRevocation::from_body(&prev).is_err(),
            "fixture must actually fail from_body, or this test proves nothing"
        );

        let req = test_request(); // ordinary DataSnapshot body, not a key-revocation

        let err = check_revocation_supersession(&prev, &req, "0.3.0").unwrap_err();
        assert!(
            matches!(err, AcdpError::SchemaViolation(_)),
            "arm 3's type rule must still reject a non-revocation successor even when the \
             predecessor is malformed and the class comparison is skipped"
        );
    }

    // Arm 2, isolating CLASS from DID (part 1 of 2): same-DID class
    // flip → reject. PREV and IN are published under the exact same
    // agent_id (the registry's own DID), so a same-DID criterion would
    // treat this as no change and allow it — but the controller field
    // differs, flipping the class from ProducerSigned (controller ==
    // agent_id, explicit — RFC-ACDP-0014 §5 rule 3) to RegistryAttested
    // (controller != agent_id — §6). Both fixtures independently pass
    // `check_revocation_controller` (verified below against
    // `KeyRevocation::from_parts`'s §5/§6 classification), so this is a
    // legitimately admissible pair, not merely abstractly constructible.
    #[test]
    fn revocation_supersession_same_did_class_flip_rejected() {
        let caps = test_caps_v030();
        let v = PublishValidator::new(&caps);
        let registry_did = caps.registry_did.clone();

        let mut prev_meta = valid_revocation_metadata();
        prev_meta["revoked_key_controller"] = serde_json::json!(registry_did);
        let prev_req = build_revocation_request(&registry_did, prev_meta, "0.3.0"); // ProducerSigned (controller == agent_id)
        let prev_revocation = KeyRevocation::from_publish_request(&prev_req).unwrap();
        assert_eq!(
            prev_revocation.trust_class,
            RevocationTrustClass::ProducerSigned
        );
        v.check_revocation_controller(&prev_req, &prev_revocation)
            .expect("PREV fixture must be a legitimately publishable revocation");
        let prev = body_from_request(&prev_req);

        let mut meta = valid_revocation_metadata();
        meta["revoked_key_controller"] = serde_json::json!(REVOCATION_PRODUCER_DID);
        let req = build_revocation_request(&registry_did, meta, "0.3.0"); // RegistryAttested (controller != agent_id)
        let in_revocation = KeyRevocation::from_publish_request(&req).unwrap();
        assert_eq!(
            in_revocation.trust_class,
            RevocationTrustClass::RegistryAttested
        );
        v.check_revocation_controller(&req, &in_revocation)
            .expect("IN fixture must be a legitimately publishable revocation");

        let err = check_revocation_supersession(&prev, &req, "0.3.0").unwrap_err();
        assert!(
            matches!(err, AcdpError::SchemaViolation(_)),
            "same agent_id on both sides must NOT be enough to allow this supersession — \
             the criterion is signer class, not DID"
        );
    }

    // Arm 2, isolating CLASS from DID (part 2 of 2): cross-DID, same
    // class → allow. This is RFC-ACDP-0014 §13's cross-producer case,
    // currently verified nowhere else: PREV and IN are published under
    // different agent_id values (cross-DID) but classify to the same
    // signer class (both ProducerSigned, controller absent/defaulted),
    // so the supersession must be allowed. Together with the test
    // above, this pins the criterion to trust class, not identity.
    #[test]
    fn revocation_supersession_cross_did_same_class_allowed() {
        let prev_req = build_revocation_request(
            REVOCATION_PRODUCER_DID,
            valid_revocation_metadata(), // no controller ⇒ ProducerSigned
            "0.3.0",
        );
        let prev = body_from_request(&prev_req);

        let req = build_revocation_request(
            REVOCATION_OTHER_PRODUCER_DID, // different agent_id ⇒ cross-DID
            valid_revocation_metadata(),   // no controller ⇒ ProducerSigned
            "0.3.0",
        );

        check_revocation_supersession(&prev, &req, "0.3.0").expect(
            "cross-DID, same signer class (ProducerSigned) must be allowed — \
             RFC-ACDP-0014 §13 blesses cross-producer supersession; the criterion is \
             class, not DID",
        );
    }
}
