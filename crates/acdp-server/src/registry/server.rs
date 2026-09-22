//! Logical registry handler (feature = "server").
//!
//! Wires [`PublishValidator`] together with a [`RegistryStore`] backend
//! to provide the seven core registry operations enumerated in
//! RFC-ACDP-0003 §2.1 and RFC-ACDP-0005:
//!
//! - capabilities — return the [`CapabilitiesDocument`].
//! - publish — validate, verify signature, assign identifiers, persist.
//! - retrieve — fetch a stored body + registry_state (visibility-filtered).
//! - retrieve_body — fetch just the body (visibility-filtered).
//! - lineage / current — lineage graph queries.
//! - search — keyword + filter projection (visibility-filtered).
//!
//! This is the building block an HTTP-binding layer can sit on top of;
//! the integration tests in this crate exercise it directly without
//! mocking.
//!
//! # Conformant publish
//!
//! [`RegistryServer::publish_verified`] runs the full RFC-ACDP-0003 §2.1
//! algorithm — structural validation, hash recomputation, DID resolution,
//! signature verification — before persistence. It requires the `client`
//! feature for [`acdp_did::WebResolver`].
//!
//! [`RegistryServer::publish_unverified_for_tests`] (and its
//! idempotency/tenant-capable sibling
//! [`RegistryServer::publish_unverified_in_tenant_for_tests`]) perform
//! only steps 1–6 (skipping DID resolution + signature verification)
//! and are intentionally **not** RFC-conformant; use only in tests
//! where DID resolution would require a live network or mock server.

use crate::registry::rate_limit::{NoopRateLimiter, RateLimiter};
use crate::registry::store::RegistryStore;
use crate::registry::validator::{
    check_revocation_supersession, key_revocation_gate_applies, PublishValidator,
};
use acdp_primitives::error::AcdpError;
use acdp_types::{
    body::{Body, FullContext},
    capabilities::CapabilitiesDocument,
    primitives::{AgentDid, ContentHash, CtxId, LineageId, Status, Visibility},
    publish::{PublishRequest, PublishResponse},
    revocation::KeyRevocation,
    search::{SearchParams, SearchResponse},
};

/// Logical registry handler over an arbitrary [`RegistryStore`].
///
/// `L` is the rate-limiting policy (RFC-ACDP-0008 §4.3). The default
/// [`NoopRateLimiter`] accepts every publish; operators that need a
/// real limiter construct via [`Self::with_rate_limiter`].
pub struct RegistryServer<S: RegistryStore, L: RateLimiter = NoopRateLimiter> {
    store: S,
    caps: CapabilitiesDocument,
    authority: String,
    rate_limiter: L,
    /// Receipt minting identity (ACDP 0.2, RFC-ACDP-0010). `None` =
    /// 0.1.0-mode registry (no receipts). Set via
    /// [`Self::with_receipt_signer`], which also advertises the
    /// `acdp-registry-receipts` profile.
    receipt_signer: Option<acdp_types::receipt::ReceiptSigner>,
    /// Lineage-head receipt minting (ACDP 0.3, RFC-ACDP-0011). Enabled
    /// via [`Self::with_lineage_head_receipts`], which also advertises
    /// the `acdp-registry-head-receipts` profile. When enabled,
    /// [`Self::current`] mints a fresh head receipt per response with
    /// the RFC-ACDP-0010 receipt signing key. Never true without
    /// `receipt_signer` (the profile's prerequisite).
    mint_head_receipts: bool,
    /// Lifecycle events & retraction (ACDP 0.3, RFC-ACDP-0013). Enabled
    /// via [`Self::with_lifecycle`], which also advertises the
    /// `acdp-registry-lifecycle` profile. When disabled, the lifecycle
    /// operations return [`AcdpError::NotImplemented`] (the §6 rule for
    /// non-advertising registries: HTTP 501) and the registry never
    /// emits `lifecycle_events` or the `retracted` status.
    lifecycle_enabled: bool,
}

/// Proof that a [`PublishRequest`]'s identity has been established —
/// RFC-ACDP-0003 §2.1 steps 1–8 (schema/hash validation, DID resolution,
/// signature verification) plus the RFC-ACDP-0014 §5 step 2 self-revocation
/// check, whichever of those the request's `context_type` and the
/// registry's `acdp_version` require — but nothing has been persisted yet.
///
/// Produced only by a successful [`RegistryServer::prove_publish_identity`] /
/// [`RegistryServer::prove_publish_identity_did_key`] /
/// [`RegistryServer::prove_publish_identity_pinned`] call — there is no
/// public constructor, so a caller cannot manufacture one from an
/// unverified request. Not [`Clone`]: a `Proven` that outlived its single
/// intended [`RegistryServer::commit_proven`] call risks being committed
/// twice against different tenants/idempotency keys, so this is a
/// move-only, "prove once, commit once" value.
///
/// Borrows `req` rather than owning a clone — the did:web caller already
/// holds an owned request across its `.await`, and the did:key caller
/// already clones into its blocking closure, so an owned `Proven` would
/// force a needless clone on the async path for no benefit on the sync
/// one.
#[derive(Debug)]
pub struct Proven<'a> {
    req: &'a PublishRequest,
    fingerprint: Option<String>,
    /// The `content_hash` recomputed over `req`'s `ProducerContent` during
    /// proving (RFC-ACDP-0003 §2.1 step 4) — not exposed publicly, since
    /// it is provably always equal to `req.content_hash` by the time a
    /// `Proven` exists (a mismatch fails `prove_publish_identity*` with
    /// [`AcdpError::HashMismatch`] first, and `req` — with its own `pub
    /// content_hash` — is already reachable via [`Self::request`]).
    /// [`RegistryServer::commit_proven`] asserts that invariant against it
    /// in debug builds.
    recomputed_hash: ContentHash,
    authority: String,
}

impl<'a> Proven<'a> {
    /// The request this proof was established for.
    pub fn request(&self) -> &PublishRequest {
        self.req
    }

    /// The producer's agent DID.
    pub fn agent_id(&self) -> &AgentDid {
        &self.req.agent_id
    }

    /// The verified producer key's fingerprint, when one was computed.
    ///
    /// Computed only when the registry has a receipt signer configured
    /// (RFC-ACDP-0010) or `req` is a key-revocation subject to the
    /// RFC-ACDP-0014 §5 step 2 self-sign check — `None` otherwise, exactly
    /// mirroring the conditions the pre-`Proven` publish pipeline already
    /// used to decide whether fingerprinting was worth its cost.
    pub fn key_fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
}

impl<S: RegistryStore> RegistryServer<S, NoopRateLimiter> {
    /// Unchecked constructor. Skips capabilities and DID-authority binding
    /// validation; prefer [`Self::try_new`] in production. Retained for
    /// tests that build a server from known-good fixtures.
    #[doc(hidden)]
    pub fn new(store: S, caps: CapabilitiesDocument, authority: impl Into<String>) -> Self {
        Self {
            store,
            caps,
            authority: authority.into(),
            rate_limiter: NoopRateLimiter,
            receipt_signer: None,
            mint_head_receipts: false,
            lifecycle_enabled: false,
        }
    }

    /// Production constructor.
    ///
    /// Validates that `authority` is a bare lowercase DNS hostname,
    /// validates capabilities against RFC-ACDP-0007 §3, and enforces that
    /// `caps.registry_did` equals `did:web:<authority>` (per
    /// RFC-ACDP-0006 §4.1 step 3 — the registry's DID document binds it
    /// to the authority it claims).
    ///
    /// A `host:port`, scheme-prefixed, or uppercase authority is rejected:
    /// the server uses `authority` to mint `ctx_id` (`acdp://<authority>/…`)
    /// and `origin_registry`, and a colon or slash there violates the
    /// `acdp://` URI authority rule (RFC-ACDP-0002 §3.1). For `host:port`
    /// test setups use [`Self::try_new_for_test_authority`].
    pub fn try_new(
        store: S,
        caps: CapabilitiesDocument,
        authority: impl Into<String>,
    ) -> Result<Self, AcdpError> {
        let authority = authority.into();
        // Production authority MUST be a bare lowercase DNS hostname — no
        // port, no scheme, no DID prefix (RFC-ACDP-0002 §3.1).
        if !acdp_types::primitives::is_valid_dns_authority(&authority) {
            return Err(AcdpError::SchemaViolation(format!(
                "registry authority '{authority}' is not a valid DNS hostname \
                 (must be lowercase labels, e.g. 'registry.example.com'); \
                 use RegistryServer::try_new_for_test_authority for host:port test setups"
            )));
        }
        acdp_validation::validate_capabilities(&caps)?;
        // BUG-06: percent-encode `:` in `host:port` authorities — the
        // colon is a structural separator in did:web.
        let expected_did = acdp_did::authority_to_did_web(&authority);
        if caps.registry_did != expected_did {
            return Err(AcdpError::SchemaViolation(format!(
                "capabilities.registry_did '{}' does not match expected '{expected_did}' \
                 for authority '{authority}'",
                caps.registry_did
            )));
        }
        Ok(Self {
            store,
            caps,
            authority,
            rate_limiter: NoopRateLimiter,
            receipt_signer: None,
            mint_head_receipts: false,
            lifecycle_enabled: false,
        })
    }

    /// Test-only constructor that accepts a `host:port` authority such as
    /// `"localhost:8443"`. The authority is **not** validated as a DNS
    /// hostname; capabilities and the DID binding are still checked.
    ///
    /// **Non-production only.** A server built with this constructor will
    /// mint `ctx_id` and `origin_registry` values that do not conform to
    /// the `acdp://` URI syntax rules (a colon in the authority segment).
    /// Use [`Self::try_new`] for production registries.
    #[doc(hidden)]
    pub fn try_new_for_test_authority(
        store: S,
        caps: CapabilitiesDocument,
        authority: impl Into<String>,
    ) -> Result<Self, AcdpError> {
        let authority = authority.into();
        acdp_validation::validate_capabilities(&caps)?;
        let expected_did = acdp_did::authority_to_did_web(&authority);
        if caps.registry_did != expected_did {
            return Err(AcdpError::SchemaViolation(format!(
                "capabilities.registry_did '{}' does not match expected '{expected_did}' \
                 for authority '{authority}'",
                caps.registry_did
            )));
        }
        Ok(Self {
            store,
            caps,
            authority,
            rate_limiter: NoopRateLimiter,
            receipt_signer: None,
            mint_head_receipts: false,
            lifecycle_enabled: false,
        })
    }
}

impl<S: RegistryStore, L: RateLimiter> RegistryServer<S, L> {
    /// Replace the rate-limiting policy (RFC-ACDP-0008 §4.3).
    pub fn with_rate_limiter<L2: RateLimiter>(self, limiter: L2) -> RegistryServer<S, L2> {
        RegistryServer {
            store: self.store,
            caps: self.caps,
            authority: self.authority,
            rate_limiter: limiter,
            receipt_signer: self.receipt_signer,
            mint_head_receipts: self.mint_head_receipts,
            lifecycle_enabled: self.lifecycle_enabled,
        }
    }

    /// Configure receipt minting (ACDP 0.2, RFC-ACDP-0010). Every
    /// subsequent verified publish mints a registry-signed receipt
    /// atomically with persistence, returns it in the publish response,
    /// and serves it on retrieval.
    ///
    /// Also advertises the `acdp-registry-receipts` profile — a
    /// registry without a signing key MUST NOT advertise it, so the
    /// profile is bound to this call rather than to raw capabilities
    /// input. Fails if the signer's `registry_did` does not match
    /// `caps.registry_did` (a receipt minted under a foreign DID would
    /// fail every consumer's serving-authority cross-check).
    ///
    /// Note: [`Self::publish_unverified_for_tests`] and
    /// [`Self::publish_unverified_in_tenant_for_tests`] never mint — the
    /// producer key is not resolved on either path, so a fingerprint
    /// attestation would be false.
    pub fn with_receipt_signer(
        mut self,
        signer: acdp_types::receipt::ReceiptSigner,
    ) -> Result<Self, AcdpError> {
        if signer.registry_did() != self.caps.registry_did {
            return Err(AcdpError::SchemaViolation(format!(
                "receipt signer registry_did '{}' ≠ capabilities.registry_did '{}'",
                signer.registry_did(),
                self.caps.registry_did
            )));
        }
        // RFC-ACDP-0010 §11: registries advertising the receipts
        // profile MUST advertise acdp_version >= 0.2.0.
        self.require_min_acdp_version((0, 2, 0), "acdp-registry-receipts")?;
        let profile = acdp_types::profile::Profile::RegistryReceipts.as_str();
        if !self.caps.profiles.iter().any(|p| p == profile) {
            self.caps.profiles.push(profile.to_string());
        }
        self.receipt_signer = Some(signer);
        Ok(self)
    }

    /// Enable lineage-head receipt minting (ACDP 0.3, RFC-ACDP-0011).
    /// Every subsequent [`Self::current`] response carries a freshly
    /// minted head receipt (`as_of` = the registry clock at response
    /// time, ms-truncated), signed with the RFC-ACDP-0010 receipt
    /// signing key — head receipts introduce no new key role (§5, §8).
    ///
    /// Also advertises the `acdp-registry-head-receipts` profile. The
    /// profile's prerequisite is `acdp-registry-receipts` (§9): this
    /// method fails unless [`Self::with_receipt_signer`] was configured
    /// first — a registry with no receipt key has nothing to sign head
    /// receipts with, and MUST NOT advertise the profile (§6: no
    /// degraded mode on `/current`). Registries advertising the profile
    /// MUST advertise `acdp_version` >= 0.3.0 (§9).
    pub fn with_lineage_head_receipts(mut self) -> Result<Self, AcdpError> {
        if self.receipt_signer.is_none() {
            return Err(AcdpError::SchemaViolation(
                "acdp-registry-head-receipts requires the acdp-registry-receipts profile \
                 (RFC-ACDP-0011 §9): call with_receipt_signer first"
                    .into(),
            ));
        }
        self.require_min_acdp_version((0, 3, 0), "acdp-registry-head-receipts")?;
        let profile = acdp_types::profile::Profile::RegistryHeadReceipts.as_str();
        if !self.caps.profiles.iter().any(|p| p == profile) {
            self.caps.profiles.push(profile.to_string());
        }
        self.mint_head_receipts = true;
        Ok(self)
    }

    /// Enable lifecycle events & retraction (ACDP 0.3, RFC-ACDP-0013).
    /// Advertises the `acdp-registry-lifecycle` profile (prerequisite:
    /// `acdp-registry-core`) and activates the
    /// [`Self::retract_verified`] / [`Self::republish_verified`]
    /// operation surface, the §7 status derivation (`retracted`
    /// dominating `superseded` and `expired`), the §8.2 default-search
    /// exclusion, and the §8.3 `/current` head exclusion.
    ///
    /// Registries advertising the profile MUST advertise `acdp_version`
    /// ≥ 0.3.0 (§10). The paired [`RegistryStore`] must implement
    /// [`RegistryStore::commit_lifecycle_event`] — the default trait
    /// impl fails with `not_implemented`, so a mispaired backend fails
    /// loudly on the first lifecycle write rather than silently
    /// dropping a retraction.
    pub fn with_lifecycle(mut self) -> Result<Self, AcdpError> {
        self.require_min_acdp_version((0, 3, 0), "acdp-registry-lifecycle")?;
        let profile = acdp_types::profile::Profile::RegistryLifecycle.as_str();
        if !self.caps.profiles.iter().any(|p| p == profile) {
            self.caps.profiles.push(profile.to_string());
        }
        self.lifecycle_enabled = true;
        Ok(self)
    }

    /// Profile version gate: `capabilities.acdp_version` must be a plain
    /// `MAJOR.MINOR.PATCH` version (the capabilities schema's
    /// `^\d+\.\d+\.\d+$` form — malformed input is an error, never
    /// coerced) and at least `min`.
    fn require_min_acdp_version(&self, min: (u64, u64, u64), what: &str) -> Result<(), AcdpError> {
        let parts: Vec<u64> = self
            .caps
            .acdp_version
            .split('.')
            .map(|p| p.parse::<u64>())
            .collect::<Result<_, _>>()
            .map_err(|_| {
                AcdpError::SchemaViolation(format!(
                    "capabilities.acdp_version '{}' is not a plain MAJOR.MINOR.PATCH version",
                    self.caps.acdp_version
                ))
            })?;
        let [major, minor, patch] = parts.as_slice() else {
            return Err(AcdpError::SchemaViolation(format!(
                "capabilities.acdp_version '{}' is not a plain MAJOR.MINOR.PATCH version",
                self.caps.acdp_version
            )));
        };
        if (*major, *minor, *patch) < min {
            return Err(AcdpError::SchemaViolation(format!(
                "{what} requires capabilities.acdp_version >= {}.{}.{}, got '{}'",
                min.0, min.1, min.2, self.caps.acdp_version
            )));
        }
        Ok(())
    }

    /// Borrow the underlying store. Useful for tests that want to
    /// inspect side-effects directly.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// `GET /.well-known/acdp.json`.
    pub fn capabilities(&self) -> &CapabilitiesDocument {
        &self.caps
    }

    /// **RFC-conformant publish.**
    ///
    /// Runs RFC-ACDP-0003 §2.1 steps 1–11:
    ///
    /// - **1–6.** [`PublishValidator::validate_post_schema`] — schema,
    ///   payload + embedded size, hash recomputation, algorithm /
    ///   key_id binding.
    /// - **7–8.** [`acdp_verify::verify_publish_request_signature`] —
    ///   DID resolution + signature verification.
    /// - **9.** Identifier assignment (`ctx_id`, `lineage_id`).
    /// - **10.** Lineage coherence on supersession.
    /// - **11.** Persistence and predecessor supersession.
    ///
    /// Steps 7–8 require a [`acdp_did::WebResolver`], so this method
    /// is gated on the `client` feature.
    #[cfg(feature = "client")]
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(
            name = "acdp.publish_verified",
            skip_all,
            fields(
                agent_id = req.agent_id.as_str(),
                version = req.version,
                idempotency_key = idempotency_key.is_some(),
            ),
            err(Display)
        )
    )]
    pub async fn publish_verified(
        &self,
        req: &PublishRequest,
        idempotency_key: Option<&str>,
        resolver: &acdp_did::WebResolver,
    ) -> Result<PublishResponse, AcdpError> {
        self.publish_verified_in_tenant(req, idempotency_key, resolver, None)
            .await
    }

    /// Like [`Self::publish_verified`] but binds the publish to a tenant so a
    /// multi-tenant store persists `tenant_id` atomically with the context row
    /// (rather than via a separate, non-transactional stamping UPDATE that a
    /// crash could leave stranded in the default bucket).
    ///
    /// `tenant = None` behaves identically to [`Self::publish_verified`] —
    /// but note this method returns the commit OUTCOME, not a bare
    /// `PublishResponse`, so it is not a drop-in for it. The bare-response
    /// equivalent is [`Self::publish_verified_in_tenant`].
    ///
    /// Which entry points have an outcome twin, and why the rest do not:
    /// the three `*_in_tenant` publish forms do (this one, `did_key`, and
    /// `pinned`), because those are the paths a registry front-end answers a
    /// real `POST /contexts` through. The non-tenant forms do not — each is a
    /// `(…, None)` delegate to its `_in_tenant` twin, so a caller wanting the
    /// outcome passes `tenant = None`. `publish_unverified_in_tenant_for_tests`
    /// does not either, deliberately: it skips DID resolution and signature
    /// verification, is not an RFC-conformant publish path, and no registry
    /// serves production traffic through it.
    #[cfg(feature = "client")]
    pub async fn publish_verified_in_tenant_with_outcome(
        &self,
        req: &PublishRequest,
        idempotency_key: Option<&str>,
        resolver: &acdp_did::WebResolver,
        tenant: Option<&str>,
    ) -> Result<crate::registry::store::PublishCommitOutcome, AcdpError> {
        // FEAT-01: hand the rest of the pipeline to the store as a
        // single atomic commit. Idempotency lookup, predecessor
        // verification, body insertion, predecessor supersession
        // marking, and idempotency record writing all happen under one
        // critical section. Two concurrent publishes against the same
        // `supersedes` (or the same `Idempotency-Key`) can no longer
        // both succeed.
        let proven = self.prove_publish_identity(req, resolver).await?;
        self.commit_proven(proven, idempotency_key, tenant)
    }

    /// **Prove** a did:web producer's identity for `req` — RFC-ACDP-0003
    /// §2.1 steps 1–8 (schema/hash validation, DID resolution, signature
    /// verification) plus the RFC-ACDP-0014 §5 step 2 self-revocation
    /// check — without persisting anything. Pair with
    /// [`Self::commit_proven`] to complete the publish; the two together
    /// are exactly what [`Self::publish_verified_in_tenant_with_outcome`]
    /// composes.
    #[cfg(feature = "client")]
    pub async fn prove_publish_identity<'a>(
        &self,
        req: &'a PublishRequest,
        resolver: &acdp_did::WebResolver,
    ) -> Result<Proven<'a>, AcdpError> {
        // Rate-limit gate runs before any expensive work — RFC-ACDP-0008 §4.3.
        self.check_publish_rate_limit(&req.agent_id)?;

        let raw_bytes = serde_json::to_vec(req)?.len();
        let validator = PublishValidator::for_authority(&self.caps, &self.authority);
        let validated = validator.validate_post_schema(req, raw_bytes)?;

        // Steps 7–8: DID resolution + signature verification.
        acdp_verify::verify_publish_request_signature(req, resolver).await?;

        // RFC-ACDP-0014 §5 step 2 on the did:web publish path: a
        // revocation MUST NOT be signed by the very key it revokes.
        // `PublishValidator::validate_post_schema` (above) already
        // enforces this for a did:key signer offline, purely from the
        // body (`KeyRevocation::from_parts`'s did:key sub-case) — but a
        // did:web signer's fingerprint is not derivable without
        // resolving its DID document. That resolution already happened
        // unconditionally just above, to verify the signature
        // (RFC-ACDP-0003 steps 7–8) — so this is NOT a new resolution.
        // `producer_key_fingerprint` dispatches by method
        // internally, so a did:key signer reaching this line would be a
        // harmless, resolver-free recheck of what was already enforced
        // above; a did:web signer instead gets a second, cache-hit
        // resolve of the same DID (via `WebResolver`'s LRU cache)
        // purely to derive a fingerprint from the key that already
        // verified — no new I/O, no new failure mode. Scoped to
        // key-revocation bodies at `acdp_version >= 0.3.0` so no other
        // publish pays even that cached-lookup cost.
        let revocation_check_needed = req.context_type.is_key_revocation()
            && key_revocation_gate_applies(&self.caps.acdp_version);

        // RFC-ACDP-0010: fingerprint the key that was just resolved and
        // verified, for the receipt's `key_fingerprint` binding. Also
        // needed (and computed here, not a second time) when the §5
        // step 2 check above applies, so a key-revocation publish never
        // triggers two DID resolutions for one fingerprint.
        let fingerprint = if self.receipt_signer.is_some() || revocation_check_needed {
            Some(producer_key_fingerprint(req, resolver).await?)
        } else {
            None
        };

        if revocation_check_needed {
            // `fingerprint` is `Some` here because `revocation_check_needed`
            // was one of the two disjuncts in the `if` just above that
            // decided whether to compute it — but that's a non-local
            // invariant spanning several lines, so treat a `None` as a
            // recoverable internal-state error rather than panicking the
            // publish path (this crate is `forbid(unsafe_code)` and ships
            // to crates.io; see `AcdpError::RegistryInternal`'s other use
            // in this file for the same "impossible state" idiom).
            let fp = fingerprint.as_deref().ok_or_else(|| {
                AcdpError::RegistryInternal(
                    "key-revocation fingerprint missing despite revocation_check_needed \
                     — this is an internal invariant violation, not a caller error"
                        .into(),
                )
            })?;
            KeyRevocation::from_publish_request(req)?.check_not_self_signed(fp)?;
        }

        Ok(Proven {
            req,
            fingerprint,
            recomputed_hash: validated.recomputed_hash,
            authority: self.authority.clone(),
        })
    }

    /// [`Self::publish_verified_in_tenant_with_outcome`] with the insert/replay
    /// distinction discarded — see that method for the full contract, which is
    /// otherwise identical. This form is a one-line delegate to it, so the two
    /// cannot drift.
    ///
    /// Answering `POST /contexts` needs the twin: RFC-ACDP-0003 requires
    /// `201 Created` + `Location` on a fresh publish and `200 OK` on a same-hash
    /// retry (idem-002 says NOT 201), and this signature cannot express which
    /// one happened.
    #[cfg(feature = "client")]
    pub async fn publish_verified_in_tenant(
        &self,
        req: &PublishRequest,
        idempotency_key: Option<&str>,
        resolver: &acdp_did::WebResolver,
        tenant: Option<&str>,
    ) -> Result<PublishResponse, AcdpError> {
        self.publish_verified_in_tenant_with_outcome(req, idempotency_key, resolver, tenant)
            .await
            .map(|o| o.into_response())
    }

    /// **RFC-conformant publish for `did:key` producers — no resolver.**
    ///
    /// Runs the same RFC-ACDP-0003 §2.1 pipeline as
    /// [`Self::publish_verified`], but performs steps 7–8 via the pure
    /// did:key verifier
    /// ([`acdp_verify::verify_publish_request_signature_offline`]),
    /// so it is available without the `client` feature. Rejects
    /// `did:web` (and any other method) producers with
    /// `key_resolution_failed` — those need the resolver-backed
    /// [`Self::publish_verified`].
    ///
    /// The capabilities gate still applies: the request is refused
    /// unless `supported_did_methods` includes `"did:key"`.
    pub fn publish_verified_did_key(
        &self,
        req: &PublishRequest,
        idempotency_key: Option<&str>,
    ) -> Result<PublishResponse, AcdpError> {
        self.publish_verified_did_key_in_tenant(req, idempotency_key, None)
    }

    /// Like [`Self::publish_verified_did_key`] but binds the publish to a
    /// tenant so a multi-tenant store persists `tenant_id` atomically with
    /// the context row — the same contract as
    /// [`Self::publish_verified_in_tenant`].
    ///
    /// `tenant = None` behaves identically to
    /// [`Self::publish_verified_did_key`] — but note this method returns the
    /// commit OUTCOME, not a bare `PublishResponse`, so it is not a drop-in
    /// for it. The bare-response equivalent is
    /// [`Self::publish_verified_did_key_in_tenant`].
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(
            name = "acdp.publish_verified_did_key",
            skip_all,
            fields(
                agent_id = req.agent_id.as_str(),
                version = req.version,
                idempotency_key = idempotency_key.is_some(),
            ),
            err(Display)
        )
    )]
    pub fn publish_verified_did_key_in_tenant_with_outcome(
        &self,
        req: &PublishRequest,
        idempotency_key: Option<&str>,
        tenant: Option<&str>,
    ) -> Result<crate::registry::store::PublishCommitOutcome, AcdpError> {
        let proven = self.prove_publish_identity_did_key(req)?;
        self.commit_proven(proven, idempotency_key, tenant)
    }

    /// **Prove** a did:key producer's identity for `req` — RFC-ACDP-0003
    /// §2.1 steps 1–8, pure (no resolver, no network) — without
    /// persisting anything. Pair with [`Self::commit_proven`] to complete
    /// the publish; the two together are exactly what
    /// [`Self::publish_verified_did_key_in_tenant_with_outcome`] composes.
    pub fn prove_publish_identity_did_key<'a>(
        &self,
        req: &'a PublishRequest,
    ) -> Result<Proven<'a>, AcdpError> {
        self.check_publish_rate_limit(&req.agent_id)?;

        let raw_bytes = serde_json::to_vec(req)?.len();
        let validator = PublishValidator::for_authority(&self.caps, &self.authority);
        let validated = validator.validate_post_schema(req, raw_bytes)?;

        // Steps 7–8, pure: did:key resolution + signature verification.
        acdp_verify::verify_publish_request_signature_offline(req)?;

        // did:key fingerprints are derivable from the DID itself — no
        // resolver needed for the receipt binding.
        let fingerprint = if self.receipt_signer.is_some() {
            let material = acdp_did::key::resolve_did_key(req.agent_id.as_str())?;
            Some(acdp_crypto::fingerprint::fingerprint_did_key_material(
                &material,
            )?)
        } else {
            None
        };

        Ok(Proven {
            req,
            fingerprint,
            recomputed_hash: validated.recomputed_hash,
            authority: self.authority.clone(),
        })
    }

    /// [`Self::publish_verified_did_key_in_tenant_with_outcome`] with the insert/replay
    /// distinction discarded — see that method for the full contract, which is
    /// otherwise identical. This form is a one-line delegate to it, so the two
    /// cannot drift.
    ///
    /// Answering `POST /contexts` needs the twin: RFC-ACDP-0003 requires
    /// `201 Created` + `Location` on a fresh publish and `200 OK` on a same-hash
    /// retry (idem-002 says NOT 201), and this signature cannot express which
    /// one happened.
    pub fn publish_verified_did_key_in_tenant(
        &self,
        req: &PublishRequest,
        idempotency_key: Option<&str>,
        tenant: Option<&str>,
    ) -> Result<PublishResponse, AcdpError> {
        self.publish_verified_did_key_in_tenant_with_outcome(req, idempotency_key, tenant)
            .map(|o| o.into_response())
    }

    /// **NOT RFC-conformant.** Skips DID resolution and signature
    /// verification (RFC-ACDP-0003 §2.1 steps 7–8).
    ///
    /// Intended for integration tests where DID resolution would require
    /// a live network or mock server. Production callers MUST use
    /// [`Self::publish_verified`].
    ///
    /// Delegates to [`Self::publish_unverified_in_tenant_for_tests`] with
    /// no idempotency key and no tenant; use that method directly for an
    /// idempotent-replay or tenant-stamped test publish.
    #[doc(hidden)]
    pub fn publish_unverified_for_tests(
        &self,
        req: &PublishRequest,
    ) -> Result<PublishResponse, AcdpError> {
        self.publish_unverified_in_tenant_for_tests(req, None, None)
    }

    /// Like [`Self::publish_unverified_for_tests`] but additionally
    /// accepts an idempotency key and a tenant, so tests can exercise the
    /// idempotent-replay and tenant-stamping behavior of
    /// [`Self::commit_via_store`] without resorting to store-level
    /// workarounds. `(None, None)` is identical to
    /// [`Self::publish_unverified_for_tests`].
    ///
    /// **NOT RFC-conformant** — same caveats as
    /// [`Self::publish_unverified_for_tests`]: skips RFC-ACDP-0003 §2.1
    /// steps 7–8 (DID resolution + signature verification). Production
    /// callers MUST use [`Self::publish_verified_in_tenant`].
    ///
    /// Passing an idempotency key to a registry whose capabilities don't
    /// advertise `supports_idempotency_key` is a silent no-op — mirrors
    /// [`Self::publish_verified_in_tenant`]'s contract via the shared
    /// [`Self::commit_via_store`] gate.
    #[doc(hidden)]
    pub fn publish_unverified_in_tenant_for_tests(
        &self,
        req: &PublishRequest,
        idempotency_key: Option<&str>,
        tenant: Option<&str>,
    ) -> Result<PublishResponse, AcdpError> {
        // Rate-limit gate fires here too — the limiter is intentionally
        // wired BEFORE validation so it works as a defensive cap even
        // when the test path is used.
        self.check_publish_rate_limit(&req.agent_id)?;

        // RFC-ACDP-0010 §7: a receipts-advertising registry has no
        // degraded mode — every persisted context must carry a receipt,
        // and minting here would attest a `key_fingerprint` that was
        // never resolved. Refuse outright rather than persist a
        // receipt-less context — from either unverified test entry
        // point, since neither resolves a producer key.
        if self.receipt_signer.is_some() {
            return Err(AcdpError::SchemaViolation(
                "publish_unverified_for_tests / publish_unverified_in_tenant_for_tests are \
                 unavailable on a receipts-advertising registry (RFC-ACDP-0010 §7: no \
                 degraded mode); use publish_verified or publish_verified_did_key"
                    .into(),
            ));
        }
        // RFC-ACDP-0014 §5 step 2 is deliberately NOT extended here for
        // a did:web signer: this method's entire contract (see its doc
        // comment above) is to skip DID resolution + signature
        // verification, so there is no resolved key — and no
        // resolver — to fingerprint. `validate_post_schema` below still
        // enforces the did:key sub-case offline (`KeyRevocation::from_parts`),
        // since that needs no resolution either; a did:web self-revocation
        // published through this test-only bypass is not caught until a
        // conformant path re-verifies it.
        let raw_bytes = serde_json::to_vec(req)?.len();
        let validator = PublishValidator::for_authority(&self.caps, &self.authority);
        let _validated = validator.validate_post_schema(req, raw_bytes)?;
        self.commit_via_store(req, idempotency_key, tenant, None)
            .map(|o| o.into_response())
    }

    /// **Publish already verified by the caller against an
    /// operator-pinned key** (e.g. a demo/playground registry's
    /// out-of-band pinned-key allowlist — a config-supplied public key
    /// checked instead of a live-resolved DID document).
    ///
    /// Unlike [`Self::publish_unverified_for_tests`], this is safe to call
    /// on a receipts-advertising registry: the caller has ALREADY
    /// cryptographically verified `req`'s signature against
    /// `verified_public_key_b64` before calling this method (steps 7–8 are
    /// the caller's responsibility, not this method's — there is no DID
    /// document or did:key to resolve for a pinned key, so this crate has
    /// nothing further to verify), so the fingerprint of that key can be
    /// attested in the minted receipt (RFC-ACDP-0010 §7: no degraded mode,
    /// every persisted context must carry a receipt with a genuinely
    /// resolved key_fingerprint).
    ///
    /// `verified_algorithm` MUST be `"ed25519"` or `"ecdsa-p256"` and MUST
    /// be the algorithm the caller actually verified `verified_public_key_b64`
    /// against — this method trusts the caller completely for verification;
    /// it does not re-verify the signature itself, only recomputes the
    /// fingerprint of the key the caller names.
    pub fn publish_pinned_verified_in_tenant_with_outcome(
        &self,
        req: &PublishRequest,
        idempotency_key: Option<&str>,
        tenant: Option<&str>,
        verified_public_key_b64: &str,
        verified_algorithm: &str,
    ) -> Result<crate::registry::store::PublishCommitOutcome, AcdpError> {
        let proven =
            self.prove_publish_identity_pinned(req, verified_public_key_b64, verified_algorithm)?;
        self.commit_proven(proven, idempotency_key, tenant)
    }

    /// **Prove** an operator-pinned-key producer's identity for `req` —
    /// RFC-ACDP-0003 §2.1 steps 1–6 plus the RFC-ACDP-0014 §5 step 2
    /// self-revocation check (steps 7–8 are the CALLER's responsibility —
    /// see the doc comment on
    /// [`Self::publish_pinned_verified_in_tenant_with_outcome`]) — without
    /// persisting anything. Pair with [`Self::commit_proven`] to complete
    /// the publish; the two together are exactly what
    /// [`Self::publish_pinned_verified_in_tenant_with_outcome`] composes.
    pub fn prove_publish_identity_pinned<'a>(
        &self,
        req: &'a PublishRequest,
        verified_public_key_b64: &str,
        verified_algorithm: &str,
    ) -> Result<Proven<'a>, AcdpError> {
        self.check_publish_rate_limit(&req.agent_id)?;

        let raw_bytes = serde_json::to_vec(req)?.len();
        let validator = PublishValidator::for_authority(&self.caps, &self.authority);
        let validated = validator.validate_post_schema(req, raw_bytes)?;

        // RFC-ACDP-0014 §5 step 2 applies here too, and at no extra
        // resolution cost: `verified_public_key_b64` is the key the
        // *caller* already verified the signature against — there is
        // no DID document to fetch, so fingerprinting it is a pure,
        // local computation regardless of receipt minting. Unlike the
        // did:web hook in `prove_publish_identity`, this adds no new I/O.
        let revocation_check_needed = req.context_type.is_key_revocation()
            && key_revocation_gate_applies(&self.caps.acdp_version);

        let fingerprint = if self.receipt_signer.is_some() || revocation_check_needed {
            Some(fingerprint_pinned_key(
                verified_public_key_b64,
                verified_algorithm,
            )?)
        } else {
            None
        };

        if revocation_check_needed {
            // See the identical guard in `prove_publish_identity` for why
            // this is `ok_or_else` rather than `expect`: the `Some`-ness
            // of `fingerprint` here depends on the `if` a few lines above
            // matching this same `revocation_check_needed`, a non-local
            // invariant that shouldn't panic the publish path if it's
            // ever broken by a future edit.
            let fp = fingerprint.as_deref().ok_or_else(|| {
                AcdpError::RegistryInternal(
                    "key-revocation fingerprint missing despite revocation_check_needed \
                     — this is an internal invariant violation, not a caller error"
                        .into(),
                )
            })?;
            KeyRevocation::from_publish_request(req)?.check_not_self_signed(fp)?;
        }

        Ok(Proven {
            req,
            fingerprint,
            recomputed_hash: validated.recomputed_hash,
            authority: self.authority.clone(),
        })
    }

    /// [`Self::publish_pinned_verified_in_tenant_with_outcome`] with the insert/replay
    /// distinction discarded — see that method for the full contract, which is
    /// otherwise identical. This form is a one-line delegate to it, so the two
    /// cannot drift.
    ///
    /// `#[doc(hidden)]`, as it was before the twin was split out — splitting a
    /// method must not quietly publish a deliberately hidden one. Its twin is
    /// NOT hidden, and that asymmetry is deliberate: a registry front-end has
    /// to call the twin to answer `201` vs `200` correctly, so it needs to be
    /// discoverable in rustdoc and tracked by `cargo semver-checks`.
    ///
    /// Answering `POST /contexts` needs the twin: RFC-ACDP-0003 requires
    /// `201 Created` + `Location` on a fresh publish and `200 OK` on a same-hash
    /// retry (idem-002 says NOT 201), and this signature cannot express which
    /// one happened.
    #[doc(hidden)]
    pub fn publish_pinned_verified_in_tenant(
        &self,
        req: &PublishRequest,
        idempotency_key: Option<&str>,
        tenant: Option<&str>,
        verified_public_key_b64: &str,
        verified_algorithm: &str,
    ) -> Result<PublishResponse, AcdpError> {
        self.publish_pinned_verified_in_tenant_with_outcome(
            req,
            idempotency_key,
            tenant,
            verified_public_key_b64,
            verified_algorithm,
        )
        .map(|o| o.into_response())
    }

    /// Rate-limit gate shared by every publish path (RFC-ACDP-0008 §4.3).
    /// Under the `tracing` feature a rejection emits a structured warn
    /// event so operators can see limiter hits per agent.
    fn check_publish_rate_limit(
        &self,
        agent_id: &acdp_types::primitives::AgentDid,
    ) -> Result<(), AcdpError> {
        match self.rate_limiter.check_publish(agent_id) {
            Ok(()) => Ok(()),
            Err(e) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    agent_id = agent_id.as_str(),
                    "publish rejected by rate limiter"
                );
                Err(e)
            }
        }
    }

    /// Drive `RegistryStore::commit_publish` from a validated request.
    ///
    /// Returns the `PublishCommitOutcome` **whole**. It used to unwrap both
    /// variants to the same `PublishResponse` here, on the grounds that the
    /// distinction "only matters internally for logging/tracing" — that was
    /// wrong. A registry front-end needs it to answer `201 Created` on a
    /// fresh publish and `200 OK` on an idempotent replay, and flattening it
    /// at this layer made that undecidable for every caller: three of the
    /// four publish paths in `acdp-registry-rs` had no way to tell a replay
    /// from an insert and would have answered `201` to both.
    ///
    /// Callers that genuinely do not care unwrap with
    /// [`PublishCommitOutcome::into_response`].
    fn commit_via_store(
        &self,
        req: &PublishRequest,
        idempotency_key: Option<&str>,
        tenant: Option<&str>,
        producer_key_fingerprint: Option<String>,
    ) -> Result<crate::registry::store::PublishCommitOutcome, AcdpError> {
        let idempotency = if self.caps.supports_idempotency_key {
            idempotency_key.map(|key| crate::registry::store::PendingIdempotencyCommit {
                key,
                ttl: chrono::Duration::seconds(
                    self.caps
                        .limits
                        .idempotency_key_ttl_seconds
                        .unwrap_or(86_400) as i64,
                ),
            })
        } else {
            None
        };
        // RFC-ACDP-0010 minting hook — runs inside the store's critical
        // section so the receipt persists atomically with the context.
        #[allow(clippy::type_complexity)]
        let minter: Option<
            Box<dyn Fn(&Body) -> Result<serde_json::Value, AcdpError> + Send + Sync>,
        > = match (&self.receipt_signer, producer_key_fingerprint) {
            (Some(signer), Some(fp)) => Some(Box::new(move |body: &Body| {
                let receipt = signer.mint(
                    &body.ctx_id,
                    &body.lineage_id,
                    &body.origin_registry,
                    body.created_at,
                    &body.content_hash,
                    &fp,
                )?;
                serde_json::to_value(receipt).map_err(AcdpError::from)
            })),
            _ => None,
        };
        let minted_expected = minter.is_some();

        // RFC-ACDP-0014 §4 `supersedes`-row admission hook. `Some` iff
        // the version gate is on AND this request actually carries a
        // `supersedes` — the mandatory carry-forward from Phase 5:
        // `check_revocation_supersession` has no internal version
        // guard, so calling it unconditionally would reject a
        // key-revocation-shaped body at e.g. acdp_version 0.2.0, where
        // RFC §4:60 reserves that rejection for ≥0.3.0 registries.
        //
        // Captures `req` by reference (not `move`-owned data like
        // `receipt_minter` above) so it can call
        // `check_revocation_supersession(prev, req, acdp_version)` — the
        // closure's hidden lifetime is exactly `req`'s, which the store
        // threads through the same call as `PublishCommit::req`, so the
        // two `'a`-tied fields agree. `acdp_version` is threaded through
        // too (RFC-ACDP-0014 §10) so Arm 3 can pick its error code —
        // `self.caps.acdp_version` outlives the closure via `self`.
        let admission_closure =
            if key_revocation_gate_applies(&self.caps.acdp_version) && req.supersedes.is_some() {
                Some(move |prev: &Body| {
                    check_revocation_supersession(prev, req, &self.caps.acdp_version)
                })
            } else {
                None
            };
        #[allow(clippy::type_complexity)]
        let predecessor_admission: Option<
            &(dyn Fn(&Body) -> Result<(), AcdpError> + Send + Sync),
        > = admission_closure
            .as_ref()
            .map(|f| f as &(dyn Fn(&Body) -> Result<(), AcdpError> + Send + Sync));

        let outcome = self
            .store
            .commit_publish(crate::registry::store::PublishCommit {
                req,
                authority: &self.authority,
                idempotency,
                tenant,
                receipt_minter: minter.as_deref(),
                predecessor_admission,
            })?;
        // Borrow rather than move: the tracing fields and the RFC-ACDP-0010
        // §7 check below both only read, and `outcome` is returned whole.
        let (response, replayed) = match &outcome {
            crate::registry::store::PublishCommitOutcome::Inserted(r) => (r, false),
            crate::registry::store::PublishCommitOutcome::IdempotentReplay(r) => (r, true),
        };
        #[cfg(feature = "tracing")]
        tracing::debug!(
            ctx_id = %response.ctx_id.0,
            lineage_id = %response.lineage_id.0,
            version = response.version,
            replayed,
            "publish committed"
        );
        // RFC-ACDP-0010 §7 belt-and-braces: a receipts-advertising
        // registry has no degraded mode. A store implementation that
        // ignores `receipt_minter` (e.g. compiled against the older
        // trait shape) must fail loudly here, not silently persist a
        // receipt-less context.
        //
        // Scoped to NEWLY INSERTED contexts only: an idempotent replay
        // returns the ORIGINAL publish response verbatim, and that
        // original may legitimately predate receipts (a record minted
        // before the registry enabled its signer, still inside the
        // idempotency TTL). Failing such a replay would turn a correct
        // producer retry into a 500 across the upgrade boundary — §7
        // attests what was persisted at publish time, not re-mint time.
        if minted_expected && !replayed && response.registry_receipt.is_none() {
            return Err(AcdpError::RegistryInternal(
                "receipt signer is configured but the store returned no receipt — \
                 the RegistryStore implementation must invoke PublishCommit::receipt_minter \
                 inside its commit (RFC-ACDP-0010 §7: no degraded mode)"
                    .into(),
            ));
        }
        Ok(outcome)
    }

    /// **Commit** a [`Proven`] publish — the second half of the
    /// `prove → commit` split (`prove_publish_identity*` /
    /// `commit_proven`, #273). Everything through RFC-ACDP-0003 §2.1
    /// steps 1–8 (and the RFC-ACDP-0014 §5 step 2 self-revocation check,
    /// where applicable) already passed to produce `proven` — this call
    /// runs the same atomic store commit
    /// (idempotency lookup, predecessor verification, insertion,
    /// predecessor-supersession marking) that
    /// [`Self::publish_verified_in_tenant_with_outcome`] and its siblings
    /// have always run, just reachable without re-deriving identity.
    ///
    /// Rejects a `proven` minted for a different registry authority with
    /// [`AcdpError::RegistryInternal`] rather than silently committing
    /// under the wrong one — a `Proven` carries the authority it was
    /// proved against specifically so this cross-registry mismatch is
    /// cheap to catch here, before persistence.
    pub fn commit_proven(
        &self,
        proven: Proven<'_>,
        idempotency_key: Option<&str>,
        tenant: Option<&str>,
    ) -> Result<crate::registry::store::PublishCommitOutcome, AcdpError> {
        if proven.authority != self.authority {
            return Err(AcdpError::RegistryInternal(format!(
                "commit_proven: Proven was established against authority '{}', but this \
                 registry's authority is '{}' — refusing to commit a proof against the \
                 wrong registry",
                proven.authority, self.authority
            )));
        }
        debug_assert_eq!(
            proven.recomputed_hash, proven.req.content_hash,
            "Proven's recomputed_hash must always equal its request's content_hash by \
             construction — prove_publish_identity* fails closed with HashMismatch before \
             a Proven can exist otherwise"
        );
        self.commit_via_store(proven.req, idempotency_key, tenant, proven.fingerprint)
    }

    /// `GET /contexts/{ctx_id}`.
    ///
    /// Applies the RFC-ACDP-0008 §4.5 disclosure rules:
    ///
    /// | Visibility   | Authorized requester for retrieval                  |
    /// |--------------|-----------------------------------------------------|
    /// | `public`     | anyone (when `caps.anonymous_public_reads` is true) |
    /// | `restricted` | producer (`agent_id`) **or** any DID in `audience`  |
    /// | `private`    | producer (`agent_id`) **or** any DID in `audience`  |
    ///
    /// Returns `Ok(None)` (not `Err`) for unauthorized callers — prevents
    /// existence leakage via error codes.
    pub fn retrieve(
        &self,
        ctx_id: &CtxId,
        requester: Option<&AgentDid>,
    ) -> Result<Option<FullContext>, AcdpError> {
        let Some(ctx) = self.store.get(ctx_id)? else {
            return Ok(None);
        };
        if !can_retrieve(&ctx.body, requester, &self.caps) {
            return Ok(None);
        }
        Ok(Some(ctx))
    }

    /// `GET /contexts/{ctx_id}/body`. See [`Self::retrieve`] for visibility rules.
    pub fn retrieve_body(
        &self,
        ctx_id: &CtxId,
        requester: Option<&AgentDid>,
    ) -> Result<Option<Body>, AcdpError> {
        Ok(self.retrieve(ctx_id, requester)?.map(|c| c.body))
    }

    /// `GET /lineages/{lineage_id}`.
    ///
    /// BUG-03: applies the same visibility filter as `retrieve`. A
    /// caller who knows or guesses a `lineage_id` must not be able to
    /// surface restricted or private bodies through the lineage
    /// endpoint when `retrieve(ctx_id, requester)` would deny them.
    pub fn lineage(
        &self,
        lineage_id: &LineageId,
        requester: Option<&AgentDid>,
    ) -> Result<Vec<FullContext>, AcdpError> {
        let all = self.store.lineage(lineage_id)?;
        Ok(all
            .into_iter()
            .filter(|ctx| can_retrieve(&ctx.body, requester, &self.caps))
            .collect())
    }

    /// `GET /lineages/{lineage_id}/current`.
    ///
    /// BUG-03 + BUG-04: returns the newest version visible to the
    /// requester that is neither `Superseded` nor `Retracted` (a
    /// retracted version is NEVER a head — RFC-ACDP-0013 §8.3, fixture
    /// `lc-003`; contrast `Expired`, which remains a servable head).
    /// `None` when the lineage is unknown, when every version is
    /// superseded or retracted (RFC-ACDP-0004 §5 as amended), or when
    /// no visible version exists. Because head selection excludes
    /// retracted versions, a lineage-head receipt can never name a
    /// retracted head (RFC-ACDP-0011 §4 as amended; the signer's mint
    /// refusal is the backstop).
    ///
    /// When the registry advertises `acdp-registry-head-receipts`
    /// ([`Self::with_lineage_head_receipts`]), the response carries a
    /// freshly minted lineage-head receipt (RFC-ACDP-0011 §6 rule 1:
    /// REQUIRED on `/current`, no degraded mode). Because the head is
    /// resolved *after* visibility filtering, the receipt attests the
    /// head as visible to this requester (§4: never an existence leak).
    pub fn current(
        &self,
        lineage_id: &LineageId,
        requester: Option<&AgentDid>,
    ) -> Result<Option<FullContext>, AcdpError> {
        let all = self.store.lineage(lineage_id)?;
        // `lineage` returns versions ordered from v1 → vN; iterate in
        // reverse to find the newest non-superseded version. `Active`
        // and `Expired` both qualify as valid current heads (a body
        // that expired without being superseded is still the latest
        // and the consumer needs to see it to know it has lapsed).
        for mut ctx in all.into_iter().rev() {
            if !matches!(
                ctx.registry_state.status,
                Status::Superseded | Status::Retracted
            ) && can_retrieve(&ctx.body, requester, &self.caps)
            {
                if self.mint_head_receipts {
                    // RFC-ACDP-0011 §6: as_of is the registry's clock at
                    // response time (ms-truncated by the signer); the
                    // head fields are exactly the served response's, so
                    // the §7 step 5 byte-match holds by construction.
                    let signer = self.receipt_signer.as_ref().ok_or_else(|| {
                        AcdpError::RegistryInternal(
                            "head-receipt minting enabled without a receipt signer \
                             (RFC-ACDP-0011 §9 prerequisite violated)"
                                .into(),
                        )
                    })?;
                    let receipt = signer.mint_lineage_head(
                        lineage_id,
                        &ctx.body.ctx_id,
                        ctx.body.version,
                        &ctx.registry_state.status,
                        chrono::Utc::now(),
                    )?;
                    ctx.lineage_head_receipt = Some(serde_json::to_value(receipt)?);
                }
                return Ok(Some(ctx));
            }
        }
        Ok(None)
    }

    /// `GET /contexts/search`.
    ///
    /// Applies the RFC-ACDP-0008 §4.5 search disclosure rules (note the
    /// asymmetry vs retrieval): private contexts surface in search only
    /// to their producer (audience members must already know the ctx_id).
    ///
    /// When `caps.anonymous_public_reads` is `false`, an anonymous search
    /// request is rejected outright with [`AcdpError::NotAuthorized`]
    /// (HTTP 403) rather than returning an empty `200`. An empty result
    /// set would still leak the registry's existence and confirm that
    /// the keyword query ran; the required response is `not_authorized`
    /// (RFC-ACDP-0005 §2.5.5, RFC-ACDP-0008 §6.3, fixture `vis-009`).
    pub fn search(
        &self,
        params: &SearchParams,
        requester: Option<&AgentDid>,
    ) -> Result<SearchResponse, AcdpError> {
        // BUG-01 + vis-009: reject anonymous search when the registry
        // does not allow anonymous reads. An empty 200 would still leak
        // the registry's existence (and that the query executed); the
        // normative response is 403 not_authorized.
        if requester.is_none() && !self.caps.anonymous_public_reads {
            return Err(AcdpError::NotAuthorized(
                "anonymous search requires authentication \
                 (registry caps: anonymous_public_reads=false)"
                    .into(),
            ));
        }
        // BUG-02: pass `anonymous_public_reads` to the store so search
        // and retrieve agree. A registry advertising the flag as false
        // MUST suppress public contexts for anonymous callers in BOTH
        // endpoints (RFC-ACDP-0008 §4.5).
        self.store
            .search(params, requester, self.caps.anonymous_public_reads)
    }

    // ── Lifecycle events & retraction (ACDP 0.3, RFC-ACDP-0013 §6) ──────
    //
    // The logical handlers behind `POST /contexts/{ctx_id}/retract` and
    // `POST /contexts/{ctx_id}/republish`. An HTTP binding layer should
    // first run the raw request body through
    // [`crate::registry::lifecycle::parse_lifecycle_request`] (the
    // closed-envelope / `immutable_field` check of §6 step 2, fixture
    // `lc-002`), then hand the parsed event here. The typed
    // [`acdp_types::lifecycle::LifecycleEvent`] round-trips
    // byte-identically, so signature verification over its
    // re-serialization equals verification over the received bytes.

    /// §6 steps 1–3, shared by both endpoints and all verification
    /// modes (signature *verification* itself is the caller's step —
    /// it differs by DID method):
    ///
    /// 1. **Visibility first** (RFC-ACDP-0008 §4.5): a context the
    ///    requester could not retrieve yields `not_found` — lifecycle
    ///    endpoints never leak existence, and error ordering never lets
    ///    an unauthorized caller distinguish "exists but not yours".
    /// 2. **Event validation**: closed §4 semantics, the
    ///    endpoint-binding rule (`retracted` on `/retract`,
    ///    `republished` on `/republish` — which also excludes every
    ///    unregistered `event_type`, §7.3), and the future-`occurred_at`
    ///    rejection (120 s skew allowance, §4).
    /// 3. **Actor authentication**: `actor` MUST equal `body.agent_id`
    ///    (`not_authorized` — the supersession rule of RFC-ACDP-0003
    ///    §3.1 step 3; delegation remains out of scope) and the event
    ///    MUST be signed (`schema_violation` when missing, §5).
    ///
    /// Returns the resolved context for the caller's verification step.
    fn lifecycle_precheck(
        &self,
        event: &acdp_types::lifecycle::LifecycleEvent,
        expected_type: &acdp_types::lifecycle::LifecycleEventType,
        requester: Option<&AgentDid>,
    ) -> Result<FullContext, AcdpError> {
        if !self.lifecycle_enabled {
            return Err(AcdpError::NotImplemented(
                "this registry does not advertise acdp-registry-lifecycle \
                 (RFC-ACDP-0013 §6: lifecycle endpoints are not implemented)"
                    .into(),
            ));
        }
        // Step 1 — resolve + visibility before ANY other check.
        let ctx = self
            .retrieve(&event.ctx_id, requester)?
            .ok_or_else(|| AcdpError::NotFound(format!("context '{}' not found", event.ctx_id)))?;
        // Step 2 — event validation.
        event.validate()?;
        if &event.event_type != expected_type {
            return Err(AcdpError::SchemaViolation(format!(
                "event_type '{}' does not match this endpoint (expected '{}', \
                 RFC-ACDP-0013 §6 step 2)",
                event.event_type, expected_type
            )));
        }
        let now = chrono::Utc::now();
        if event.occurred_at > now + chrono::Duration::seconds(120) {
            return Err(AcdpError::SchemaViolation(format!(
                "event occurred_at '{}' is in the future beyond the 120s skew allowance \
                 (RFC-ACDP-0013 §4)",
                event.occurred_at.format("%Y-%m-%dT%H:%M:%S%.3fZ")
            )));
        }
        // Step 3 — actor authentication.
        if event.actor != ctx.body.agent_id {
            return Err(AcdpError::NotAuthorized(format!(
                "event actor '{}' is not the context's producer — only the producer \
                 (agent_id) may use the lifecycle endpoints (RFC-ACDP-0013 §6 step 3)",
                event.actor
            )));
        }
        // Producer-initiated events MUST be signed (§5); presence and
        // the key_id-DID == actor binding are checked here, the
        // cryptographic verification by the caller.
        event.actor_bound_signature()?;
        Ok(ctx)
    }

    /// §6 steps 4–5: atomic transition + append via the store, mapping
    /// both outcomes (fresh append, byte-identical idempotent retry) to
    /// the post-transition full-retrieval envelope.
    fn lifecycle_commit(
        &self,
        event: &acdp_types::lifecycle::LifecycleEvent,
    ) -> Result<FullContext, AcdpError> {
        Ok(self.store.commit_lifecycle_event(event)?.into_context())
    }

    /// Shared verified pipeline for both endpoints (resolver-backed).
    #[cfg(feature = "client")]
    async fn lifecycle_transition_verified(
        &self,
        event: &acdp_types::lifecycle::LifecycleEvent,
        expected_type: acdp_types::lifecycle::LifecycleEventType,
        requester: Option<&AgentDid>,
        resolver: &acdp_did::WebResolver,
    ) -> Result<FullContext, AcdpError> {
        let ctx = self.lifecycle_precheck(event, &expected_type, requester)?;
        // Full RFC-ACDP-0001 §5.11 pipeline over the event hash
        // (RFC-ACDP-0013 §5): resolution, assertionMethod, algorithm
        // binding, SSRF protections — the same pipeline as a publish.
        acdp_verify::verify_lifecycle_event(
            &serde_json::to_value(event)?,
            &event.ctx_id,
            &ctx.body.agent_id,
            None, // producer-only: registry events do not use the endpoints
            resolver,
        )
        .await?;
        self.lifecycle_commit(event)
    }

    /// Shared verified pipeline for did:key producers — no resolver.
    fn lifecycle_transition_verified_did_key(
        &self,
        event: &acdp_types::lifecycle::LifecycleEvent,
        expected_type: acdp_types::lifecycle::LifecycleEventType,
        requester: Option<&AgentDid>,
    ) -> Result<FullContext, AcdpError> {
        let ctx = self.lifecycle_precheck(event, &expected_type, requester)?;
        acdp_verify::verify_lifecycle_event_offline(
            &serde_json::to_value(event)?,
            &event.ctx_id,
            &ctx.body.agent_id,
            None,
        )?;
        self.lifecycle_commit(event)
    }

    /// **RFC-conformant retraction** — `POST /contexts/{ctx_id}/retract`
    /// (RFC-ACDP-0013 §6). Runs the full §6 pipeline: visibility, event
    /// validation (`retracted` on this endpoint), actor authentication,
    /// signature verification through the RFC-ACDP-0001 §5.11 resolver
    /// pipeline, strict-alternation transition validation, and the
    /// atomic append. Returns the post-transition full-retrieval
    /// envelope (`status: retracted`, event appended) — or the current
    /// state unchanged on a byte-identical `event_id` retry.
    ///
    /// Retraction is **mark-not-delete**: the body remains retrievable
    /// (§8.1), falls out of default searches (§8.2), and is never
    /// served from `/current` (§8.3).
    #[cfg(feature = "client")]
    pub async fn retract_verified(
        &self,
        event: &acdp_types::lifecycle::LifecycleEvent,
        requester: Option<&AgentDid>,
        resolver: &acdp_did::WebResolver,
    ) -> Result<FullContext, AcdpError> {
        self.lifecycle_transition_verified(
            event,
            acdp_types::lifecycle::LifecycleEventType::Retracted,
            requester,
            resolver,
        )
        .await
    }

    /// **RFC-conformant republication** — `POST
    /// /contexts/{ctx_id}/republish` (RFC-ACDP-0013 §6): reverses a
    /// prior retraction. `status` re-derives per RFC-ACDP-0004 §4 as
    /// though the retraction had not occurred; both events remain in
    /// the append-only history. Same pipeline as
    /// [`Self::retract_verified`].
    #[cfg(feature = "client")]
    pub async fn republish_verified(
        &self,
        event: &acdp_types::lifecycle::LifecycleEvent,
        requester: Option<&AgentDid>,
        resolver: &acdp_did::WebResolver,
    ) -> Result<FullContext, AcdpError> {
        self.lifecycle_transition_verified(
            event,
            acdp_types::lifecycle::LifecycleEventType::Republished,
            requester,
            resolver,
        )
        .await
    }

    /// [`Self::retract_verified`] for `did:key` producers — the §5
    /// signature verification is pure (the DID is the key), so this is
    /// available without the `client` feature. Rejects `did:web` (and
    /// any other method) actors with `key_resolution_failed`.
    pub fn retract_verified_did_key(
        &self,
        event: &acdp_types::lifecycle::LifecycleEvent,
        requester: Option<&AgentDid>,
    ) -> Result<FullContext, AcdpError> {
        self.lifecycle_transition_verified_did_key(
            event,
            acdp_types::lifecycle::LifecycleEventType::Retracted,
            requester,
        )
    }

    /// [`Self::republish_verified`] for `did:key` producers.
    pub fn republish_verified_did_key(
        &self,
        event: &acdp_types::lifecycle::LifecycleEvent,
        requester: Option<&AgentDid>,
    ) -> Result<FullContext, AcdpError> {
        self.lifecycle_transition_verified_did_key(
            event,
            acdp_types::lifecycle::LifecycleEventType::Republished,
            requester,
        )
    }

    /// **NOT RFC-conformant.** Skips signature verification (the §6
    /// step 3 cryptographic half; presence and actor binding are still
    /// enforced). Test-only, mirroring
    /// [`Self::publish_unverified_for_tests`].
    #[doc(hidden)]
    pub fn retract_unverified_for_tests(
        &self,
        event: &acdp_types::lifecycle::LifecycleEvent,
        requester: Option<&AgentDid>,
    ) -> Result<FullContext, AcdpError> {
        self.lifecycle_precheck(
            event,
            &acdp_types::lifecycle::LifecycleEventType::Retracted,
            requester,
        )?;
        self.lifecycle_commit(event)
    }

    /// **NOT RFC-conformant.** See [`Self::retract_unverified_for_tests`].
    #[doc(hidden)]
    pub fn republish_unverified_for_tests(
        &self,
        event: &acdp_types::lifecycle::LifecycleEvent,
        requester: Option<&AgentDid>,
    ) -> Result<FullContext, AcdpError> {
        self.lifecycle_precheck(
            event,
            &acdp_types::lifecycle::LifecycleEventType::Republished,
            requester,
        )?;
        self.lifecycle_commit(event)
    }

    /// Record a **registry-initiated** lifecycle event (RFC-ACDP-0013
    /// §6: deployment policy, legal compulsion). Does NOT use the
    /// producer endpoints or their actor rule: `actor` MUST equal the
    /// registry's own DID (`capabilities.registry_did`). Subject to the
    /// same append-only, uniqueness, transition, and shape rules; the
    /// event SHOULD be signed under a key in the registry's DID
    /// document (a registry advertising `acdp-registry-receipts` MUST
    /// sign — enforced here when a receipt signer is configured, per
    /// the §5 same-key precedent). This is the protocol-visible form of
    /// "removed by policy": the body stays served, the withdrawal is
    /// explicit and attributed.
    pub fn record_registry_lifecycle_event(
        &self,
        event: &acdp_types::lifecycle::LifecycleEvent,
    ) -> Result<FullContext, AcdpError> {
        if !self.lifecycle_enabled {
            return Err(AcdpError::NotImplemented(
                "this registry does not advertise acdp-registry-lifecycle \
                 (RFC-ACDP-0013 §6)"
                    .into(),
            ));
        }
        event.validate()?;
        if !event.event_type.is_registered() {
            return Err(AcdpError::SchemaViolation(format!(
                "event_type '{}' is not registered for acceptance in 0.3.0 \
                 (RFC-ACDP-0013 §7.3)",
                event.event_type
            )));
        }
        if event.actor.as_str() != self.caps.registry_did {
            return Err(AcdpError::NotAuthorized(format!(
                "registry-initiated event actor '{}' ≠ this registry's DID '{}' \
                 (RFC-ACDP-0013 §6)",
                event.actor, self.caps.registry_did
            )));
        }
        if self.receipt_signer.is_some() && !event.is_signed() {
            return Err(AcdpError::SchemaViolation(
                "a registry advertising acdp-registry-receipts MUST sign its lifecycle \
                 events (RFC-ACDP-0013 §5)"
                    .into(),
            ));
        }
        if event.is_signed() {
            // §5 actor binding for the registry key.
            event.actor_bound_signature()?;
        }
        self.lifecycle_commit(event)
    }
}

/// RFC-ACDP-0008 §4.5 retrieval disclosure rule.
pub(crate) fn can_retrieve(
    body: &Body,
    requester: Option<&AgentDid>,
    caps: &CapabilitiesDocument,
) -> bool {
    match body.visibility {
        Visibility::Public => caps.anonymous_public_reads || requester.is_some(),
        Visibility::Restricted | Visibility::Private => match requester {
            None => false,
            Some(r) => {
                r == &body.agent_id
                    || body
                        .audience
                        .as_deref()
                        .is_some_and(|a| a.iter().any(|d| d == r))
            }
        },
    }
}

/// Resolve and fingerprint the producer key named by
/// `signature.key_id` — the binding recorded in a receipt's
/// `key_fingerprint` (RFC-ACDP-0010), and (as of RFC-ACDP-0014 §5 step 2)
/// also checked against a did:web key-revocation's own
/// `revoked_key_fingerprint` in [`RegistryServer::publish_verified_in_tenant`].
/// Delegates to the same
/// [`acdp_crypto::fingerprint::fingerprint_for_key_id`] the consumer
/// cross-check uses, so mint-time and verify-time fingerprints cannot
/// drift. Callers MUST invoke this only after
/// `verify_publish_request_signature` succeeded, so the fingerprinted
/// key is the one that actually verified (the resolver's cache makes a
/// second resolution — receipt minting and/or the §5 step 2 check on
/// the same request — cheap, and `publish_verified_in_tenant` computes
/// it at most once per publish either way).
#[cfg(feature = "client")]
async fn producer_key_fingerprint(
    req: &PublishRequest,
    resolver: &acdp_did::WebResolver,
) -> Result<String, AcdpError> {
    acdp_crypto::fingerprint::fingerprint_for_key_id(
        &req.signature.key_id,
        &req.signature.algorithm,
        resolver,
    )
    .await
}

/// Fingerprint a base64 public key the caller has already verified a
/// signature against (an operator-pinned key, not a resolved DID
/// document) — no resolution involved, just decode + dispatch by
/// algorithm. Used by [`RegistryServer::publish_pinned_verified_in_tenant`].
fn fingerprint_pinned_key(public_key_b64: &str, algorithm: &str) -> Result<String, AcdpError> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let raw = STANDARD
        .decode(public_key_b64)
        .map_err(|e| AcdpError::KeyResolution(format!("pinned key is not valid base64: {e}")))?;
    match algorithm {
        "ed25519" => {
            let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                AcdpError::KeyResolution(format!(
                    "pinned ed25519 key must be 32 bytes, got {}",
                    raw.len()
                ))
            })?;
            Ok(acdp_crypto::fingerprint::fingerprint_ed25519(&arr))
        }
        "ecdsa-p256" => acdp_crypto::fingerprint::fingerprint_p256_sec1(&raw),
        other => Err(AcdpError::UnsupportedAlgorithm(format!(
            "cannot fingerprint a pinned key for algorithm '{other}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::store::{InMemoryStore, PublishCommitOutcome};
    use acdp_crypto::SigningKey;
    use acdp_producer::Producer;
    use acdp_types::capabilities::Limits;
    use acdp_types::primitives::{AgentDid, ContextType, Visibility};

    fn caps() -> CapabilitiesDocument {
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

    fn producer() -> Producer {
        Producer::new(
            SigningKey::from_bytes(&[1u8; 32]),
            AgentDid::new("did:web:agents.example.com:test"),
            "did:web:agents.example.com:test#key-1",
        )
    }

    #[test]
    fn publish_v1_then_retrieve() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();
        assert_eq!(resp.version, 1);
        let ctx = server.retrieve(&resp.ctx_id, None).unwrap().unwrap();
        assert_eq!(ctx.body.title, "v1");
        // Lineage round-trip
        let lineage = server.lineage(&resp.lineage_id, None).unwrap();
        assert_eq!(lineage.len(), 1);
        // Current points at the same record
        let cur = server.current(&resp.lineage_id, None).unwrap().unwrap();
        assert_eq!(cur.body.ctx_id, resp.ctx_id);
    }

    #[test]
    fn supersession_marks_predecessor_and_returns_v2() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let v1_req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v1 = server.publish_unverified_for_tests(&v1_req).unwrap();

        let v2_req = p
            .supersede(v1.ctx_id.clone())
            .version(2)
            .title("v2")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v2 = server.publish_unverified_for_tests(&v2_req).unwrap();
        assert_eq!(v2.version, 2);
        // v1 was marked superseded
        let v1_ctx = server.retrieve(&v1.ctx_id, None).unwrap().unwrap();
        assert!(matches!(
            v1_ctx.registry_state.status,
            acdp_types::Status::Superseded
        ));
        // Same lineage
        assert_eq!(v1.lineage_id, v2.lineage_id);
        // Current resolves to v2
        let cur = server.current(&v1.lineage_id, None).unwrap().unwrap();
        assert_eq!(cur.body.ctx_id, v2.ctx_id);
    }

    /// FEAT-01: two concurrent publishes that both supersede the same
    /// v1 MUST resolve to exactly one success + one
    /// `SupersededTarget { AlreadySuperseded }`. The race was possible
    /// when the supersedes check, body insert, and predecessor mark
    /// lived in separate mutex acquisitions; `commit_publish` puts
    /// them under one critical section so only one of two contenders
    /// wins (RFC-ACDP-0003 §6).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_supersession_exactly_one_succeeds() {
        use std::sync::Arc;
        let server = Arc::new(RegistryServer::new(
            InMemoryStore::new(),
            caps(),
            "registry.example.com",
        ));
        let p = producer();
        let v1_req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v1 = server.publish_unverified_for_tests(&v1_req).unwrap();

        // Pre-build BOTH v2 requests up front, then fire them in
        // parallel on a multi-threaded runtime. With the prior
        // non-atomic sequence the test would fail intermittently;
        // with `commit_publish` it's deterministic.
        let v2a_req = p
            .supersede(v1.ctx_id.clone())
            .version(2)
            .title("v2-A")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v2b_req = p
            .supersede(v1.ctx_id.clone())
            .version(2)
            .title("v2-B")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();

        let s1 = Arc::clone(&server);
        let s2 = Arc::clone(&server);
        let h1 = tokio::task::spawn_blocking(move || s1.publish_unverified_for_tests(&v2a_req));
        let h2 = tokio::task::spawn_blocking(move || s2.publish_unverified_for_tests(&v2b_req));
        let (r1, r2) = (h1.await.unwrap(), h2.await.unwrap());

        let outcomes = [r1, r2];
        let successes = outcomes.iter().filter(|r| r.is_ok()).count();
        let failures = outcomes.iter().filter(|r| r.is_err()).count();
        assert_eq!(
            successes, 1,
            "exactly one concurrent supersession MUST succeed; got {successes} successes / {failures} failures"
        );
        assert_eq!(failures, 1);
        // The loser MUST get AlreadySuperseded — the predecessor was
        // marked under the same lock the winner used.
        for r in &outcomes {
            if let Err(e) = r {
                match e {
                    AcdpError::SupersededTarget { reason, .. } => assert_eq!(
                        *reason,
                        acdp_primitives::error::SupersessionReason::AlreadySuperseded,
                        "concurrent loser MUST be AlreadySuperseded"
                    ),
                    other => panic!("concurrent loser had wrong error: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn hostile_supersession_by_non_owner_rejected_predecessor_unchanged() {
        // P0-2: an attacker controlling their own DID must not be able to
        // supersede a victim's context. Without the producer-continuity
        // check this marks the victim's context `Superseded` and re-points
        // `current(lineage)` at the attacker's body — a lineage takeover.
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let victim = producer_for(7, "did:web:agents.example.com:victim");
        let v1_req = victim
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v1 = server.publish_unverified_for_tests(&v1_req).unwrap();

        // Attacker signs their own valid v2, omitting lineage_id (the only
        // self-declared coherence arm), supersedes = victim's v1.
        let attacker = producer_for(9, "did:web:evil.example.com:attacker");
        let v2_req = attacker
            .supersede(v1.ctx_id.clone())
            .version(2)
            .title("hijacked")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let err = server.publish_unverified_for_tests(&v2_req).unwrap_err();
        // Uniform with not-found: no existence / version / status oracle.
        match err {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(reason, acdp_primitives::error::SupersessionReason::NotFound);
            }
            other => panic!("expected uniform SupersededTarget::NotFound, got {other:?}"),
        }
        // Predecessor MUST be untouched: still current, not superseded.
        let cur = server.current(&v1.lineage_id, None).unwrap().unwrap();
        assert_eq!(cur.body.ctx_id, v1.ctx_id);
        assert_eq!(cur.body.title, "v1");
        assert_eq!(
            cur.registry_state.status,
            acdp_types::primitives::Status::Active
        );
    }

    #[test]
    fn owner_supersession_still_succeeds_after_ownership_check() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let v1_req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v1 = server.publish_unverified_for_tests(&v1_req).unwrap();
        let v2_req = p
            .supersede(v1.ctx_id.clone())
            .version(2)
            .title("v2")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v2 = server.publish_unverified_for_tests(&v2_req).unwrap();
        assert_eq!(v2.version, 2);
        let cur = server.current(&v1.lineage_id, None).unwrap().unwrap();
        assert_eq!(cur.body.ctx_id, v2.ctx_id);
    }

    #[test]
    fn supersession_with_unknown_target_rejected_as_not_found() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let phantom =
            CtxId("acdp://registry.example.com/12345678-1234-4321-8123-deadbeefcafe".into());
        let req = p
            .supersede(phantom)
            .version(2)
            .title("v2-orphan")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let err = server.publish_unverified_for_tests(&req).unwrap_err();
        match err {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(reason, acdp_primitives::error::SupersessionReason::NotFound);
            }
            other => panic!("expected SupersededTarget::NotFound, got {other:?}"),
        }
    }

    #[test]
    fn version_mismatch_rejected() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let v1_req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let v1 = server.publish_unverified_for_tests(&v1_req).unwrap();
        // Build a v3 (wrong) supersession
        let v3_req = p
            .supersede(v1.ctx_id.clone())
            .version(3)
            .title("v3-skipped")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let err = server.publish_unverified_for_tests(&v3_req).unwrap_err();
        match err {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(
                    reason,
                    acdp_primitives::error::SupersessionReason::VersionMismatch
                );
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn search_finds_published_context() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("Q1 portfolio risk")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        server.publish_unverified_for_tests(&req).unwrap();
        let resp = server
            .search(
                &SearchParams {
                    q: Some("portfolio".into()),
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        assert_eq!(resp.matches.len(), 1);
        assert_eq!(resp.matches[0].title, "Q1 portfolio risk");
    }

    // ── BUG-03 — lineage/current visibility filtering ──────────────────

    /// BUG-03: a stranger calling `lineage()` MUST NOT see restricted
    /// bodies they aren't on the audience for. The retrieval predicate
    /// is now mirrored here.
    #[test]
    fn lineage_filters_restricted_for_stranger() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let audience = AgentDid::new("did:web:audience.example.com:reader");
        let req = p
            .publish_request()
            .title("restricted v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![audience.clone()])
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();

        let stranger = AgentDid::new("did:web:other.example.com:reader");
        let stranger_view = server.lineage(&resp.lineage_id, Some(&stranger)).unwrap();
        assert!(
            stranger_view.is_empty(),
            "stranger MUST NOT see restricted bodies via lineage(); got {} entries",
            stranger_view.len()
        );

        let audience_view = server.lineage(&resp.lineage_id, Some(&audience)).unwrap();
        assert_eq!(
            audience_view.len(),
            1,
            "audience member MUST see the restricted body via lineage()"
        );
    }

    /// BUG-03: `current()` also filters by requester visibility.
    /// A stranger gets `None` for a private lineage.
    #[test]
    fn current_filters_private_for_stranger() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("private v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Private)
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();

        let stranger = AgentDid::new("did:web:other.example.com:reader");
        assert!(
            server
                .current(&resp.lineage_id, Some(&stranger))
                .unwrap()
                .is_none(),
            "stranger MUST NOT see private contexts via current()"
        );

        let producer_did = AgentDid::new("did:web:agents.example.com:test");
        assert!(
            server
                .current(&resp.lineage_id, Some(&producer_did))
                .unwrap()
                .is_some(),
            "producer MUST see private contexts via current()"
        );
    }

    // ── BUG-04 — current() superseded fallback ─────────────────────────

    /// BUG-04: when every version of a lineage is `Superseded`,
    /// `current()` MUST return `None`. Previously the fallback returned
    /// the last entry projected, which is a protocol violation
    /// (RFC-ACDP-0004 §5: "If no such version exists, returns not_found").
    ///
    /// Constructing an all-superseded lineage requires a direct store
    /// mark — there's no publish path that produces this state today,
    /// but the registry's `current()` MUST not implicitly fall through.
    #[test]
    fn current_returns_none_when_all_superseded() {
        use crate::registry::store::RegistryStore;
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();
        // Force the only version into Superseded directly.
        server.store().mark_superseded(&resp.ctx_id).unwrap();

        let cur = server.current(&resp.lineage_id, None).unwrap();
        assert!(
            cur.is_none(),
            "all-superseded lineage MUST resolve to None per RFC-ACDP-0004 §5; got {cur:?}"
        );
    }

    // ── BUG-01 / vis-009 — anonymous search honors anonymous_public_reads ──

    /// BUG-01 + vis-009: a registry advertising `anonymous_public_reads:
    /// false` MUST reject an anonymous search with `not_authorized`
    /// (HTTP 403) — not an empty `200`, which would still leak the
    /// registry's existence. The same context surfaces with a `200`
    /// once the requester authenticates.
    #[test]
    fn search_suppresses_public_when_anonymous_public_reads_false() {
        let mut c = caps();
        c.anonymous_public_reads = false;
        let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("public-but-flag-off")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        server.publish_unverified_for_tests(&req).unwrap();

        // Anonymous: MUST be rejected with NotAuthorized (vis-009 s1).
        let err = server
            .search(
                &SearchParams {
                    q: Some("public-but-flag-off".into()),
                    ..Default::default()
                },
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, AcdpError::NotAuthorized(_)),
            "vis-009: anonymous search MUST be NotAuthorized when \
             anonymous_public_reads=false; got {err:?}"
        );

        // Authenticated requester (any DID — public is universally visible
        // once authenticated): MUST see the context.
        let stranger = AgentDid::new("did:web:other.example.com:reader");
        let authed = server
            .search(
                &SearchParams {
                    q: Some("public-but-flag-off".into()),
                    ..Default::default()
                },
                Some(&stranger),
            )
            .unwrap();
        assert_eq!(
            authed.matches.len(),
            1,
            "authenticated search MUST see public contexts regardless of anonymous_public_reads"
        );
    }

    // ── try_new validation tests ────────────────────────────────────────

    #[test]
    fn try_new_rejects_did_authority_mismatch() {
        let mut c = caps();
        c.registry_did = "did:web:other.example.com".into(); // wrong authority
        let res = RegistryServer::try_new(InMemoryStore::new(), c, "registry.example.com");
        match res {
            Err(AcdpError::SchemaViolation(msg)) => {
                assert!(msg.contains("does not match expected"))
            }
            Err(other) => panic!("expected SchemaViolation, got {other:?}"),
            Ok(_) => panic!("expected Err"),
        }
    }

    #[test]
    fn try_new_rejects_caps_missing_ed25519() {
        let mut c = caps();
        c.supported_signature_algorithms = vec!["ecdsa-p256".into()]; // missing ed25519
        let res = RegistryServer::try_new(InMemoryStore::new(), c, "registry.example.com");
        assert!(matches!(res, Err(AcdpError::SchemaViolation(_))));
    }

    #[test]
    fn try_new_accepts_valid_caps() {
        RegistryServer::try_new(InMemoryStore::new(), caps(), "registry.example.com").unwrap();
    }

    // ── WIRE-04 — try_new authority-format validation ───────────────────

    #[test]
    fn try_new_accepts_valid_dns_authority() {
        RegistryServer::try_new(InMemoryStore::new(), caps(), "registry.example.com").unwrap();
    }

    #[test]
    fn try_new_rejects_host_port_authority() {
        // A `host:port` authority would mint `acdp://localhost:8443/<uuid>`
        // ctx_ids — a colon violates the acdp:// authority rule.
        let res = RegistryServer::try_new(InMemoryStore::new(), caps(), "localhost:8443");
        assert!(matches!(res, Err(AcdpError::SchemaViolation(_))));
    }

    #[test]
    fn try_new_rejects_uppercase_authority() {
        let res = RegistryServer::try_new(InMemoryStore::new(), caps(), "Registry.Example.Com");
        assert!(matches!(res, Err(AcdpError::SchemaViolation(_))));
    }

    #[test]
    fn try_new_rejects_url_form_authority() {
        let res =
            RegistryServer::try_new(InMemoryStore::new(), caps(), "https://registry.example.com");
        assert!(matches!(res, Err(AcdpError::SchemaViolation(_))));
    }

    #[test]
    fn try_new_for_test_accepts_host_port() {
        // The test constructor skips the DNS-authority check; it still
        // enforces the DID binding, so the caps DID must match.
        let mut c = caps();
        c.registry_did = acdp_did::authority_to_did_web("localhost:8443");
        RegistryServer::try_new_for_test_authority(InMemoryStore::new(), c, "localhost:8443")
            .unwrap();
    }

    // ── Visibility-enforcement tests (RFC-ACDP-0008 §4.5) ───────────────

    fn producer_for(seed: u8, did: &str) -> Producer {
        Producer::new(
            SigningKey::from_bytes(&[seed; 32]),
            AgentDid::new(did),
            format!("{did}#key-1"),
        )
    }

    #[test]
    fn retrieve_restricted_blocks_stranger_returns_none() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let owner = AgentDid::new("did:web:agents.example.com:owner");
        let audience_member = AgentDid::new("did:web:agents.example.com:friend");
        let p = producer_for(2, owner.as_str());
        let req = p
            .publish_request()
            .title("restricted")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![audience_member.clone()])
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();
        let stranger = AgentDid::new("did:web:agents.example.com:stranger");

        assert!(server.retrieve(&resp.ctx_id, None).unwrap().is_none());
        assert!(server
            .retrieve(&resp.ctx_id, Some(&stranger))
            .unwrap()
            .is_none());
        assert!(server
            .retrieve(&resp.ctx_id, Some(&owner))
            .unwrap()
            .is_some());
        assert!(server
            .retrieve(&resp.ctx_id, Some(&audience_member))
            .unwrap()
            .is_some());
    }

    #[test]
    fn search_restricted_filters_strangers() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let owner = AgentDid::new("did:web:agents.example.com:owner");
        let p = producer_for(3, owner.as_str());
        let req = p
            .publish_request()
            .title("hush hush")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![AgentDid::new("did:web:agents.example.com:friend")])
            .build()
            .unwrap();
        server.publish_unverified_for_tests(&req).unwrap();

        let stranger = AgentDid::new("did:web:agents.example.com:stranger");
        let r_anon = server.search(&SearchParams::default(), None).unwrap();
        assert!(
            r_anon.matches.is_empty(),
            "anonymous must not see restricted"
        );
        let r_stranger = server
            .search(&SearchParams::default(), Some(&stranger))
            .unwrap();
        assert!(r_stranger.matches.is_empty());
        let r_owner = server
            .search(&SearchParams::default(), Some(&owner))
            .unwrap();
        assert_eq!(r_owner.matches.len(), 1);
    }

    /// RFC-ACDP-0008 §4.5 asymmetry: a private context surfaces in search
    /// only to its producer — audience members can retrieve by id but can't
    /// discover via search.
    #[test]
    fn search_private_visible_only_to_producer() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let owner = AgentDid::new("did:web:agents.example.com:owner");
        let audience_member = AgentDid::new("did:web:agents.example.com:friend");
        let p = producer_for(4, owner.as_str());
        let req = p
            .publish_request()
            .title("private note")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Private)
            .audience(vec![audience_member.clone()])
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();

        let r_audience = server
            .search(&SearchParams::default(), Some(&audience_member))
            .unwrap();
        assert!(
            r_audience.matches.is_empty(),
            "audience must NOT see private in search"
        );
        let r_owner = server
            .search(&SearchParams::default(), Some(&owner))
            .unwrap();
        assert_eq!(
            r_owner.matches.len(),
            1,
            "owner sees their own private context"
        );

        // Audience CAN retrieve directly by id.
        assert!(server
            .retrieve(&resp.ctx_id, Some(&audience_member))
            .unwrap()
            .is_some());
    }

    // ── publish_verified offline-rejection tests ────────────────────────
    //
    // Full end-to-end `publish_verified` requires a TLS-mocked DID
    // document (because `WebResolver` is HTTPS-only). These tests cover
    // the rejection paths that fire BEFORE the resolver call so they
    // don't need a network: malformed key_id, non-did:web key_id,
    // agent_id ≠ key_id DID portion. Together with the existing
    // `verify_signature_envelope` algorithm-downgrade unit test, they
    // pin the entry checks of RFC-ACDP-0003 §2.1 steps 7–8 without
    // requiring a TLS mock harness.

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn publish_verified_rejects_non_did_web_key_id() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let mut req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        // Mutate post-build — validation already ran and accepted did:web.
        // Re-sign isn't necessary: the verifier rejects before signature
        // check. Use a *well-formed* did:key URL (a malformed one is
        // caught earlier by schema validation as of ACDP 0.2): the
        // key_id DID portion no longer matches the did:web agent_id, so
        // the binding check refuses it.
        let did_key = acdp_did::key::did_key_from_ed25519(
            &SigningKey::from_bytes(&[9u8; 32]).verifying_key_bytes(),
        );
        req.signature.key_id = acdp_did::key::did_key_url(&did_key).unwrap();
        let resolver = acdp_did::WebResolver::new();
        let err = server
            .publish_verified(&req, None, &resolver)
            .await
            .unwrap_err();
        match err {
            AcdpError::KeyNotAuthorized(msg) => assert!(msg.contains("did:web")),
            other => panic!("expected KeyNotAuthorized for non-did:web, got {other:?}"),
        }
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn publish_verified_rejects_agent_id_keyid_mismatch() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let mut req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        req.signature.key_id = "did:web:other.example.com:agent#key-1".into();
        let resolver = acdp_did::WebResolver::new();
        let err = server
            .publish_verified(&req, None, &resolver)
            .await
            .unwrap_err();
        match err {
            AcdpError::KeyNotAuthorized(msg) => assert!(msg.contains("agent_id")),
            other => panic!("expected KeyNotAuthorized for agent_id mismatch, got {other:?}"),
        }
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn publish_verified_rejects_keyid_without_fragment() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let mut req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        req.signature.key_id = "did:web:agents.example.com:test".into(); // no '#'
        let resolver = acdp_did::WebResolver::new();
        let err = server
            .publish_verified(&req, None, &resolver)
            .await
            .unwrap_err();
        // Schema validation (step 1) catches missing-fragment before
        // step 7 fires, so the surface error is SchemaViolation.
        assert!(
            matches!(
                err,
                AcdpError::SchemaViolation(_) | AcdpError::KeyResolution(_)
            ),
            "expected fragment-rejection error, got {err:?}"
        );
    }

    // ── FEAT-04 idempotency tests ──────────────────────────────────────

    fn caps_with_idempotency() -> CapabilitiesDocument {
        let mut c = caps();
        c.supports_idempotency_key = true;
        c.limits.idempotency_key_ttl_seconds = Some(86_400);
        c
    }

    #[test]
    fn idempotency_same_hash_returns_original_response() {
        let server = RegistryServer::new(
            InMemoryStore::new(),
            caps_with_idempotency(),
            "registry.example.com",
        );
        let p = producer();
        let req = p
            .publish_request()
            .title("once")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        // Publish twice through the same idempotency key via the real
        // path — `publish_unverified_in_tenant_for_tests` can pass an
        // idempotency key straight through to `commit_via_store`, so
        // there is no more need to fake the store-level entry.
        let first = server
            .publish_unverified_in_tenant_for_tests(&req, Some("k-001"), None)
            .unwrap();
        let replayed = server
            .publish_unverified_in_tenant_for_tests(&req, Some("k-001"), None)
            .unwrap();
        assert_eq!(replayed.ctx_id, first.ctx_id);
        assert_eq!(replayed.lineage_id, first.lineage_id);
        assert_eq!(replayed.created_at, first.created_at);
        // And only one context was actually persisted.
        let resp = server.search(&SearchParams::default(), None).unwrap();
        assert_eq!(
            resp.matches.len(),
            1,
            "idempotent replay must not persist a second context"
        );
    }

    #[test]
    fn idempotency_evicts_after_ttl() {
        let store = InMemoryStore::new();
        let agent = AgentDid::new("did:web:agents.example.com:test");
        let resp = PublishResponse {
            registry_receipt: None,
            ctx_id: acdp_types::CtxId("acdp://r/12345678-1234-4321-8123-000000000099".into()),
            lineage_id: acdp_types::LineageId(
                "lin:sha256:9999999999999999999999999999999999999999999999999999999999999999"
                    .into(),
            ),
            version: 1,
            created_at: chrono::Utc::now(),
            status: Status::Active,
        };
        // Already-past expiration.
        let past = chrono::Utc::now() - chrono::Duration::seconds(1);
        store
            .idempotency_record(
                &agent,
                "expired",
                &acdp_types::ContentHash("sha256:0".into()),
                &resp,
                past,
            )
            .unwrap();
        // Lookup runs lazy eviction; the expired record MUST be gone.
        let prior = store.idempotency_lookup(&agent, "expired").unwrap();
        assert!(
            prior.is_none(),
            "lazy TTL eviction should drop expired record"
        );
    }

    /// A receipts-advertising registry must refuse
    /// `publish_unverified_in_tenant_for_tests` identically to
    /// `publish_unverified_for_tests` (RFC-ACDP-0010 §7: no degraded
    /// mode) — the refusal is inherited by construction since the old
    /// method's body moved wholesale into the new one, but this proves
    /// it from the new name specifically.
    #[test]
    fn publish_unverified_in_tenant_for_tests_refuses_receipts_registry() {
        let mut c = caps();
        c.acdp_version = "0.2.0".into();
        let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com")
            .with_receipt_signer(
                acdp_types::receipt::ReceiptSigner::new(
                    SigningKey::from_bytes(&[0x33u8; 32]),
                    "did:web:registry.example.com",
                    "did:web:registry.example.com#receipt-key-1",
                )
                .unwrap(),
            )
            .unwrap();
        let p = producer();
        let req = p
            .publish_request()
            .title("should be refused")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let err = server
            .publish_unverified_in_tenant_for_tests(&req, None, None)
            .unwrap_err();
        assert!(
            matches!(err, AcdpError::SchemaViolation(_)),
            "expected SchemaViolation refusal on a receipts-advertising registry, got {err:?}"
        );
    }

    // ── Tenancy-recording test store ────────────────────────────────────
    //
    // `InMemoryStore::commit_publish` deliberately discards `tenant`
    // (store.rs:676-678: "InMemoryStore does not model tenancy") since
    // it is a single-tenant reference/test backend — so testing tenancy
    // plumbing against it directly would prove nothing. `RecordingStore`
    // wraps an `InMemoryStore` for all real behavior and additionally
    // captures the `tenant` argument each `commit_publish` call receives.

    /// Delegates every [`RegistryStore`] method to an inner
    /// [`InMemoryStore`], additionally recording `commit.tenant` from
    /// each [`RegistryStore::commit_publish`] call.
    struct RecordingStore {
        inner: InMemoryStore,
        tenants: std::sync::Mutex<Vec<Option<String>>>,
    }

    impl RecordingStore {
        fn new() -> Self {
            Self {
                inner: InMemoryStore::new(),
                tenants: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl RegistryStore for RecordingStore {
        fn put(&self, body: Body) -> Result<(), AcdpError> {
            self.inner.put(body)
        }

        fn get(&self, ctx_id: &CtxId) -> Result<Option<FullContext>, AcdpError> {
            self.inner.get(ctx_id)
        }

        fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError> {
            self.inner.lineage(lineage_id)
        }

        fn current(&self, lineage_id: &LineageId) -> Result<Option<FullContext>, AcdpError> {
            self.inner.current(lineage_id)
        }

        fn mark_superseded(&self, ctx_id: &CtxId) -> Result<(), AcdpError> {
            self.inner.mark_superseded(ctx_id)
        }

        fn first_version_ctx_id(&self, lineage_id: &LineageId) -> Result<Option<CtxId>, AcdpError> {
            self.inner.first_version_ctx_id(lineage_id)
        }

        fn search(
            &self,
            params: &SearchParams,
            requester: Option<&AgentDid>,
            anonymous_public_reads: bool,
        ) -> Result<SearchResponse, AcdpError> {
            self.inner.search(params, requester, anonymous_public_reads)
        }

        fn idempotency_lookup(
            &self,
            agent_id: &AgentDid,
            key: &str,
        ) -> Result<Option<crate::registry::store::IdempotencyRecord>, AcdpError> {
            self.inner.idempotency_lookup(agent_id, key)
        }

        fn idempotency_record(
            &self,
            agent_id: &AgentDid,
            key: &str,
            hash: &acdp_types::primitives::ContentHash,
            response: &PublishResponse,
            expires_at: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), AcdpError> {
            self.inner
                .idempotency_record(agent_id, key, hash, response, expires_at)
        }

        fn idempotency_evict_expired(
            &self,
            now: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), AcdpError> {
            self.inner.idempotency_evict_expired(now)
        }

        fn commit_publish(
            &self,
            commit: crate::registry::store::PublishCommit<'_>,
        ) -> Result<crate::registry::store::PublishCommitOutcome, AcdpError> {
            self.tenants
                .lock()
                .unwrap()
                .push(commit.tenant.map(String::from));
            self.inner.commit_publish(commit)
        }

        fn commit_lifecycle_event(
            &self,
            event: &acdp_types::lifecycle::LifecycleEvent,
        ) -> Result<crate::registry::store::LifecycleCommitOutcome, AcdpError> {
            self.inner.commit_lifecycle_event(event)
        }
    }

    /// Proves `tenant` reaches `PublishCommit.tenant` verbatim from
    /// `publish_unverified_in_tenant_for_tests`, in call order.
    ///
    /// What this does NOT prove: tenant *isolation* (that two tenants'
    /// data cannot leak into each other's reads) — that is the durable
    /// backends' contract (`store.rs:274-279`), entirely out of scope
    /// for `InMemoryStore`/`RecordingStore`, which is why this test only
    /// asserts on the recorded argument, not on any read-side behavior.
    #[test]
    fn tenant_reaches_publish_commit_verbatim() {
        let server = RegistryServer::new(RecordingStore::new(), caps(), "registry.example.com");
        let p = producer();

        let req_a = p
            .publish_request()
            .title("tenant a")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        server
            .publish_unverified_in_tenant_for_tests(&req_a, None, Some("tenant-a"))
            .unwrap();

        let req_b = p
            .publish_request()
            .title("tenant none")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        server
            .publish_unverified_in_tenant_for_tests(&req_b, None, None)
            .unwrap();

        let recorded = server.store().tenants.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec![Some("tenant-a".to_string()), None],
            "tenant must reach PublishCommit.tenant verbatim, in call order"
        );
    }

    // ── FEAT-05 rate limiter tests ─────────────────────────────────────

    struct AlwaysDeny;
    impl crate::registry::RateLimiter for AlwaysDeny {
        fn check_publish(&self, agent_id: &AgentDid) -> Result<(), AcdpError> {
            Err(AcdpError::RateLimited(format!("blocked: {agent_id}")))
        }
    }

    #[test]
    fn rate_limiter_blocks_publish_before_persist() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com")
            .with_rate_limiter(AlwaysDeny);
        let p = producer();
        let req = p
            .publish_request()
            .title("blocked")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let err = server.publish_unverified_for_tests(&req).unwrap_err();
        assert!(matches!(err, AcdpError::RateLimited(_)));
        // And the store is empty — the limiter MUST short-circuit before persist.
        let resp = server.search(&SearchParams::default(), None).unwrap();
        assert!(
            resp.matches.is_empty(),
            "rate-limited publish must not persist"
        );
    }

    #[test]
    fn created_at_is_ms_truncated() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("ms")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let resp = server.publish_unverified_for_tests(&req).unwrap();
        // Nanosecond component of a ms-truncated timestamp is always a multiple of 1_000_000.
        assert_eq!(
            resp.created_at.timestamp_subsec_nanos() % 1_000_000,
            0,
            "created_at must be millisecond-truncated per RFC-ACDP-0001 §5.3"
        );
    }

    // ── did:key publish (ACDP 0.2) ───────────────────────────────────────

    fn did_key_request() -> acdp_types::publish::PublishRequest {
        let p = Producer::new_did_key(SigningKey::from_bytes(&[7u8; 32]));
        p.publish_request()
            .title("did:key publish")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap()
    }

    /// A registry that does NOT advertise `did:key` in
    /// `supported_did_methods` refuses a did:key publish with
    /// `key_resolution_failed` (permanent) — the anchor-plan decision.
    #[test]
    fn did_key_publish_rejected_when_not_advertised() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let err = server
            .publish_verified_did_key(&did_key_request(), None)
            .unwrap_err();
        assert!(
            matches!(err, AcdpError::KeyResolution(ref m) if m.contains("supported_did_methods")),
            "got {err:?}"
        );
    }

    /// With `did:key` advertised, the offline pipeline runs end-to-end:
    /// schema → hash → pure key resolution → signature → persistence.
    /// No resolver, no network — works in a `server`-only build.
    #[test]
    fn did_key_publish_verified_end_to_end() {
        let mut c = caps();
        c.supported_did_methods.push("did:key".into());
        let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com");
        let req = did_key_request();
        let resp = server.publish_verified_did_key(&req, None).unwrap();
        assert_eq!(resp.ctx_id.authority(), "registry.example.com");

        // Tampered title → hash mismatch caught before signature.
        let mut tampered = did_key_request();
        tampered.title = "tampered".into();
        let err = server
            .publish_verified_did_key(&tampered, None)
            .unwrap_err();
        assert!(matches!(err, AcdpError::HashMismatch { .. }), "got {err:?}");
    }

    /// Upgrade boundary: a registry that enables receipts must still
    /// honor idempotent replays of records minted BEFORE the signer
    /// existed. The §7 no-degraded-mode check applies to newly inserted
    /// contexts only — a replayed pre-receipts response (no
    /// `registry_receipt`) is returned verbatim, not failed as a 500.
    #[test]
    fn receiptless_idempotent_replay_survives_enabling_receipts() {
        let mut c = caps();
        c.acdp_version = "0.2.0".into();
        c.supported_did_methods.push("did:key".into());
        c.supports_idempotency_key = true;
        c.limits.idempotency_key_ttl_seconds = Some(86_400);
        let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com")
            .with_receipt_signer(
                acdp_types::receipt::ReceiptSigner::new(
                    SigningKey::from_bytes(&[0x11u8; 32]),
                    "did:web:registry.example.com",
                    "did:web:registry.example.com#receipt-key-1",
                )
                .unwrap(),
            )
            .unwrap();

        // Simulate a record persisted before receipts were enabled: the
        // stored response carries no `registry_receipt`.
        let req = did_key_request();
        let pre_receipts_response = acdp_types::publish::PublishResponse {
            ctx_id: CtxId(format!(
                "acdp://registry.example.com/{}",
                uuid::Uuid::new_v4()
            )),
            lineage_id: acdp_crypto::derive_lineage_id(&CtxId(
                "acdp://registry.example.com/v1".into(),
            )),
            version: 1,
            created_at: acdp_primitives::time::trunc_ms(chrono::Utc::now()),
            status: Status::Active,
            registry_receipt: None,
        };
        server
            .store()
            .idempotency_record(
                &req.agent_id,
                "pre-receipts-key",
                &req.content_hash,
                &pre_receipts_response,
                chrono::Utc::now() + chrono::Duration::hours(1),
            )
            .unwrap();

        // Same agent + key + content_hash → the replay must return the
        // original receipt-less response, not RegistryInternal.
        let resp = server
            .publish_verified_did_key(&req, Some("pre-receipts-key"))
            .expect("replay of a pre-receipts record must succeed");
        assert_eq!(resp.ctx_id, pre_receipts_response.ctx_id);
        assert!(
            resp.registry_receipt.is_none(),
            "replay returns the original response verbatim"
        );

        // A FRESH publish on the same server still enforces minting.
        let p2 = Producer::new_did_key(SigningKey::from_bytes(&[8u8; 32]));
        let fresh = p2
            .publish_request()
            .title("fresh after enabling receipts")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let fresh_resp = server.publish_verified_did_key(&fresh, None).unwrap();
        assert!(
            fresh_resp.registry_receipt.is_some(),
            "new inserts on a receipts registry must mint"
        );
    }

    /// A pinned-key publish (the caller already verified the signature
    /// against an operator-pinned key, e.g. a demo registry's
    /// `playground.pinned_keys` allowlist) mints a receipt whose
    /// `key_fingerprint` matches the pinned key — proving
    /// `publish_pinned_verified_in_tenant` is safe on a
    /// receipts-advertising registry, unlike `publish_unverified_for_tests`.
    #[test]
    fn pinned_verified_publish_mints_receipt_with_correct_fingerprint() {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let key = SigningKey::from_bytes(&[3u8; 32]);
        let verifying_key_bytes = key.verifying_key_bytes();
        let pub_b64 = STANDARD.encode(verifying_key_bytes);
        let did = "did:web:agents.example.com:pinned-agent";
        let p = Producer::new(key, AgentDid::new(did), format!("{did}#key-1"));
        let req = p
            .publish_request()
            .title("pinned publish")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();

        let mut c = caps();
        c.acdp_version = "0.2.0".into();
        let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com")
            .with_receipt_signer(
                acdp_types::receipt::ReceiptSigner::new(
                    SigningKey::from_bytes(&[0x22u8; 32]),
                    "did:web:registry.example.com",
                    "did:web:registry.example.com#receipt-key-1",
                )
                .unwrap(),
            )
            .unwrap();

        let resp = server
            .publish_pinned_verified_in_tenant(&req, None, None, &pub_b64, "ed25519")
            .expect("pinned-verified publish must succeed on a receipts registry");
        let receipt = resp
            .registry_receipt
            .expect("a receipts-advertising registry must mint a receipt");
        assert_eq!(
            receipt["key_fingerprint"].as_str().unwrap(),
            acdp_crypto::fingerprint::fingerprint_ed25519(&verifying_key_bytes)
        );
    }

    /// Without a receipt signer configured, `publish_pinned_verified_in_tenant`
    /// still succeeds — it just mints no receipt (the fingerprint is only
    /// ever needed for the receipt binding).
    #[test]
    fn pinned_verified_publish_without_receipt_signer_succeeds_with_no_receipt() {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let key = SigningKey::from_bytes(&[4u8; 32]);
        let pub_b64 = STANDARD.encode(key.verifying_key_bytes());
        let did = "did:web:agents.example.com:pinned-agent-2";
        let p = Producer::new(key, AgentDid::new(did), format!("{did}#key-1"));
        let req = p
            .publish_request()
            .title("pinned publish, no receipts")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();

        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let resp = server
            .publish_pinned_verified_in_tenant(&req, None, None, &pub_b64, "ed25519")
            .unwrap();
        assert!(resp.registry_receipt.is_none());
    }

    /// `publish_verified_did_key` refuses did:web producers — they need
    /// the resolver-backed `publish_verified`.
    #[test]
    fn did_key_publish_path_refuses_did_web() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let req = p
            .publish_request()
            .title("did:web on the offline path")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let err = server.publish_verified_did_key(&req, None).unwrap_err();
        assert!(
            matches!(err, AcdpError::KeyResolution(_)),
            "did:web on the offline path must be refused, got {err:?}"
        );
    }

    // ── Phase 8: prove/commit split (#273) ────────────────────────────

    /// `prove_publish_identity_did_key` + `commit_proven` must succeed and
    /// persist exactly like the composed
    /// `publish_verified_did_key_in_tenant_with_outcome` they replace the
    /// body of — proving the split is a genuine decomposition of the
    /// existing pipeline, not a different one.
    #[test]
    fn prove_then_commit_did_key_round_trip_matches_direct_publish() {
        let mut c = caps();
        c.supported_did_methods.push("did:key".into());
        let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com");
        let req = did_key_request();

        let proven = server
            .prove_publish_identity_did_key(&req)
            .expect("prove must succeed for a validly signed did:key request");
        assert_eq!(proven.agent_id(), &req.agent_id);
        assert_eq!(proven.request().content_hash, req.content_hash);

        // `commit_proven` below debug_asserts recomputed_hash == request().content_hash
        // internally — this round trip is what exercises that invariant.
        let outcome = server
            .commit_proven(proven, None, None)
            .expect("commit_proven must persist a proven publish");
        let resp = outcome.into_response();
        assert_eq!(resp.ctx_id.authority(), "registry.example.com");
        assert_eq!(resp.version, 1);

        let ctx = server.retrieve(&resp.ctx_id, None).unwrap().unwrap();
        assert_eq!(ctx.body.content_hash, req.content_hash);
    }

    /// The pinned-key `prove`/`commit` split must still thread the
    /// fingerprint through to receipt minting exactly like
    /// `publish_pinned_verified_in_tenant_with_outcome` does directly.
    #[test]
    fn prove_then_commit_pinned_round_trip_mints_receipt_with_correct_fingerprint() {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let key = SigningKey::from_bytes(&[5u8; 32]);
        let verifying_key_bytes = key.verifying_key_bytes();
        let pub_b64 = STANDARD.encode(verifying_key_bytes);
        let did = "did:web:agents.example.com:pinned-proven-agent";
        let p = Producer::new(key, AgentDid::new(did), format!("{did}#key-1"));
        let req = p
            .publish_request()
            .title("pinned publish via prove/commit")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();

        let mut c = caps();
        c.acdp_version = "0.2.0".into();
        let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com")
            .with_receipt_signer(
                acdp_types::receipt::ReceiptSigner::new(
                    SigningKey::from_bytes(&[0x33u8; 32]),
                    "did:web:registry.example.com",
                    "did:web:registry.example.com#receipt-key-1",
                )
                .unwrap(),
            )
            .unwrap();

        let proven = server
            .prove_publish_identity_pinned(&req, &pub_b64, "ed25519")
            .expect("prove must succeed for a validly pinned request");
        let expected_fp = acdp_crypto::fingerprint::fingerprint_ed25519(&verifying_key_bytes);
        assert_eq!(proven.key_fingerprint(), Some(expected_fp.as_str()));

        let outcome = server
            .commit_proven(proven, None, None)
            .expect("commit_proven must persist and mint a receipt");
        let resp = outcome.into_response();
        let receipt = resp
            .registry_receipt
            .expect("a receipts-advertising registry must mint a receipt");
        assert_eq!(receipt["key_fingerprint"].as_str().unwrap(), expected_fp);
    }

    /// `prove_publish_identity` (the did:web variant) runs the same
    /// pre-resolution rejections as `publish_verified` — proving the
    /// async prove entry point exists and is wired into the same
    /// validation pipeline, without needing a live/mocked resolver.
    #[cfg(feature = "client")]
    #[tokio::test]
    async fn prove_publish_identity_rejects_non_did_web_key_id_before_producing_proven() {
        let server = RegistryServer::new(InMemoryStore::new(), caps(), "registry.example.com");
        let p = producer();
        let mut req = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let did_key = acdp_did::key::did_key_from_ed25519(
            &SigningKey::from_bytes(&[10u8; 32]).verifying_key_bytes(),
        );
        req.signature.key_id = acdp_did::key::did_key_url(&did_key).unwrap();
        let resolver = acdp_did::WebResolver::new();
        let err = server
            .prove_publish_identity(&req, &resolver)
            .await
            .unwrap_err();
        match err {
            AcdpError::KeyNotAuthorized(msg) => assert!(msg.contains("did:web")),
            other => panic!("expected KeyNotAuthorized for non-did:web, got {other:?}"),
        }
    }

    /// `commit_proven` must refuse a `Proven` established against a
    /// different registry authority rather than silently persisting it —
    /// the "prove against server A, commit on server B" footgun the
    /// authority check exists to close.
    #[test]
    fn commit_proven_rejects_proven_from_different_authority() {
        let mut c1 = caps();
        c1.supported_did_methods.push("did:key".into());
        let mut c2 = caps();
        c2.supported_did_methods.push("did:key".into());
        let server_a = RegistryServer::new(InMemoryStore::new(), c1, "registry-a.example.com");
        let server_b = RegistryServer::new(InMemoryStore::new(), c2, "registry-b.example.com");

        let req = did_key_request();
        let proven = server_a
            .prove_publish_identity_did_key(&req)
            .expect("prove must succeed against server A");

        let err = server_b
            .commit_proven(proven, None, None)
            .expect_err("commit_proven must refuse a Proven minted for a different authority");
        match err {
            AcdpError::RegistryInternal(msg) => {
                assert!(
                    msg.contains("registry-a.example.com")
                        && msg.contains("registry-b.example.com"),
                    "error should name both authorities, got: {msg}"
                );
            }
            other => panic!("expected RegistryInternal authority-mismatch, got {other:?}"),
        }
    }

    /// The `prove → commit` split's core invariant: `commit_proven` is
    /// only reachable via a `Proven`, and the only way to mint one is a
    /// successful `prove_publish_identity*` call — a request that fails
    /// RFC-ACDP-0003 §2.1 verification (here: a tampered body, caught by
    /// the hash-mismatch check) produces no `Proven` at all, so there is
    /// no path from a bare `PublishRequest` to `commit_proven` for it.
    #[test]
    fn prove_publish_identity_did_key_produces_no_proven_for_a_tampered_request() {
        let mut c = caps();
        c.supported_did_methods.push("did:key".into());
        let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com");

        let mut tampered = did_key_request();
        tampered.title = "tampered".into();
        let err = server
            .prove_publish_identity_did_key(&tampered)
            .expect_err("prove must fail for a request whose hash no longer matches its body");
        assert!(matches!(err, AcdpError::HashMismatch { .. }), "got {err:?}");
        // No `Proven` was produced for `tampered` — structurally, nothing
        // else in this crate's public API could have manufactured one
        // either, since `Proven` has no public constructor.
    }

    // ── the insert/replay distinction, per entry point ───────────────────
    //
    // These are the tests that did not exist anywhere before U-564. The
    // consuming registry's own idem-001..004 chain looks like it covers this
    // and does not: it builds its harness with the playground enabled and no
    // pinned keys, so every publish in that chain takes the one branch that
    // re-queries `idempotency_lookup` by hand.
    //
    // Stated precisely, because a looser earlier version of this comment was
    // simply false: what was missing on the three branches that go through
    // `commit_via_store` is coverage of the insert/replay DISTINCTION, not
    // replay coverage as such. `receiptless_idempotent_replay_survives_enabling_receipts`
    // predates this work and does drive a did:key replay — and it, not
    // anything added here, is what first caught a delegate that dropped the
    // receipt. What nothing asserted was WHICH of the two a publish was, which
    // is the only thing a front-end can use to choose 201 over 200, and that is
    // why flattening the outcome went unnoticed.

    /// Caps that advertise `did:key` AND idempotency. `supports_idempotency_key`
    /// is the gate `commit_via_store` reads before it passes a key to the store
    /// at all — with the default `false` from [`caps`], a second publish with
    /// the same key is a second INSERT and no replay is reachable.
    ///
    /// Measured, because the first version of this note claimed the opposite
    /// and was wrong: dropping `supports_idempotency_key = true` — from here
    /// and from the inline `caps()` in the pinned test — makes these tests
    /// FAIL (117 passed, 3 failed), it does not make them pass vacuously.
    /// Three distinct tests fail with three distinct messages, not one
    /// assertion three times. The cap is load-bearing for reachability, and
    /// its absence is loud rather than silent.
    fn caps_idempotent_did_key() -> CapabilitiesDocument {
        let mut c = caps();
        c.supported_did_methods.push("did:key".into());
        c.supports_idempotency_key = true;
        c.limits.idempotency_key_ttl_seconds = Some(86_400);
        c
    }

    /// did:key branch: first publish inserts, the same request with the same
    /// `Idempotency-Key` replays.
    ///
    /// A registry front-end reads exactly this to choose `201 Created` +
    /// `Location` vs `200 OK`; RFC-ACDP-0003's idem-002 requires 200 on the
    /// second call and says explicitly NOT 201.
    #[test]
    fn did_key_publish_reports_inserted_then_idempotent_replay() {
        let server = RegistryServer::new(
            InMemoryStore::new(),
            caps_idempotent_did_key(),
            "registry.example.com",
        );
        let req = did_key_request();

        let first = server
            .publish_verified_did_key_in_tenant_with_outcome(&req, Some("k-did-key"), None)
            .expect("first publish must succeed");
        assert!(
            !first.is_replay(),
            "a first publish is an insert, not a replay"
        );
        assert!(matches!(first, PublishCommitOutcome::Inserted(_)));

        let second = server
            .publish_verified_did_key_in_tenant_with_outcome(&req, Some("k-did-key"), None)
            .expect("same-hash retry with the same key must succeed");
        assert!(
            second.is_replay(),
            "a same-key same-hash retry is a replay — answering 201 here violates idem-002"
        );
        assert!(matches!(second, PublishCommitOutcome::IdempotentReplay(_)));

        // idem-002 also requires the replay to return the ORIGINAL response,
        // so assert identity rather than merely "it replayed".
        assert_eq!(
            first.response().ctx_id,
            second.response().ctx_id,
            "a replay must return the original response verbatim"
        );
    }

    /// Pinned branch: same property, reached through a different entry point.
    ///
    /// Worth its own test rather than trusting that it shares
    /// `commit_via_store` with the did:key path: what is under test is each
    /// PUBLIC entry point's contract, and a delegate that dropped the outcome
    /// would be invisible to a test of the other one.
    #[test]
    fn pinned_publish_reports_inserted_then_idempotent_replay() {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let key = SigningKey::from_bytes(&[4u8; 32]);
        let pub_b64 = STANDARD.encode(key.verifying_key_bytes());
        let did = "did:web:agents.example.com:pinned-idem";
        let p = Producer::new(key, AgentDid::new(did), format!("{did}#key-1"));
        let req = p
            .publish_request()
            .title("pinned publish, idempotent retry")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();

        let mut c = caps();
        c.supports_idempotency_key = true;
        c.limits.idempotency_key_ttl_seconds = Some(86_400);
        let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com");

        let first = server
            .publish_pinned_verified_in_tenant_with_outcome(
                &req,
                Some("k-pinned"),
                None,
                &pub_b64,
                "ed25519",
            )
            .expect("first pinned publish must succeed");
        assert!(!first.is_replay(), "a first publish is an insert");

        let second = server
            .publish_pinned_verified_in_tenant_with_outcome(
                &req,
                Some("k-pinned"),
                None,
                &pub_b64,
                "ed25519",
            )
            .expect("pinned same-hash retry must succeed");
        assert!(
            second.is_replay(),
            "a same-key same-hash pinned retry is a replay"
        );
        assert_eq!(first.response().ctx_id, second.response().ctx_id);
    }

    /// The bare-response entry points must keep returning exactly what they
    /// returned before U-564 — they are now one-line delegates, and this pins
    /// that the delegation is lossless rather than assuming it.
    ///
    /// Compared across a REPLAY, on one server, deliberately. Two independent
    /// inserts can never be compared field-for-field: the store assigns a
    /// fresh `ctx_id` per insert and `lineage_id` is derived from it, so an
    /// insert-vs-insert test can only assert the handful of fields the request
    /// determines — which is exactly the kind of weakened assertion that
    /// passes while the interesting field differs. Replaying the first publish
    /// through the bare entry point makes the two responses the SAME record,
    /// so full equality is meaningful.
    #[test]
    fn bare_entry_point_matches_its_outcome_twin() {
        // A receipt signer is attached DELIBERATELY. Without one,
        // `registry_receipt` is `None` on both sides and the "receipt
        // included" half of the assertion below is unbacked — a delegate that
        // dropped the receipt would sail through. With one, `minted_expected`
        // is true (it is `minter.is_some()`, and the minter needs both a
        // signer and a producer fingerprint), so the insert carries a real
        // receipt and the replay must return it verbatim.
        let mut c = caps_idempotent_did_key();
        c.acdp_version = "0.2.0".into();
        let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com")
            .with_receipt_signer(
                acdp_types::receipt::ReceiptSigner::new(
                    SigningKey::from_bytes(&[0x21u8; 32]),
                    "did:web:registry.example.com",
                    "did:web:registry.example.com#receipt-key-1",
                )
                .unwrap(),
            )
            .unwrap();
        let req = did_key_request();

        let inserted = server
            .publish_verified_did_key_in_tenant_with_outcome(&req, Some("k-a"), None)
            .unwrap();
        assert!(
            inserted.response().registry_receipt.is_some(),
            "fixture precondition: the insert must actually mint a receipt, or \
             the receipt half of this test proves nothing"
        );
        assert!(!inserted.is_replay());
        let via_twin = inserted.into_response();

        let via_bare = server
            .publish_verified_did_key_in_tenant(&req, Some("k-a"), None)
            .unwrap();

        // `PublishResponse` has no `PartialEq`, and comparing a chosen subset
        // of fields is how a delegate that drops one goes unnoticed. Compare
        // the serialized form instead: it is the whole wire surface, which is
        // also the surface this contract is actually about.
        assert_eq!(
            serde_json::to_value(&via_twin).unwrap(),
            serde_json::to_value(&via_bare).unwrap(),
            "the bare entry point must return the replayed record verbatim — \
             it is a delegate to the twin and must lose nothing, receipt included"
        );
    }
}
