//! VerifiedContext: retrieve + verify in one call.

use super::data_ref::{fetch_and_verify_data_ref, DataRefFetcher};
use super::registry::RegistryClient;
use acdp_did::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_types::{body::FullContext, primitives::CtxId};
use acdp_verify::Verifier;

/// Consumer-tunable strictness for [`VerifiedContext::fetch_with_policy`],
/// [`VerifiedContext::fetch_current_with_policy`], and the
/// `fetch_report*` family ([`VerifiedContext::fetch_report`],
/// [`VerifiedContext::fetch_report_with_fetcher`],
/// [`VerifiedContext::fetch_report_diagnose`]). All three surfaces
/// consult the same policy fields through the same `verify_retrieved`
/// spine — but they do not always *agree*, because
/// [`VerifiedContext::fetch_report_diagnose`] differs in more than just
/// how a failure surfaces:
///
/// - [`VerifiedContext::fetch_report`] and
///   [`VerifiedContext::fetch_report_with_fetcher`] run
///   `verify_retrieved` directly once their own top-level probes pass,
///   and surface a phase failure as `Err`.
/// - [`VerifiedContext::fetch_report_diagnose`] runs its own
///   independent, strict, assertionMethod-only signature *probe* first
///   (recorded as `VerificationReport::signature_ok`). That probe has
///   no historical-key fallback and runs *before* `verify_retrieved` is
///   ever invoked. If it fails, `diagnose` withholds the
///   [`VerifiedContext`] handle with `policy_phase_error: None` — the
///   spine never ran, so there is no phase error to record — even in
///   cases where `verify_retrieved` itself, as run by `fetch_report`,
///   would have accepted the key historically under the default
///   `historical_keys: HistoricalKeyPolicy::AcceptWithReceipt` plus a
///   verified receipt. Concretely: for a key rotated out of
///   `assertionMethod` with a valid receipt, `fetch_report` returns
///   `Ok` with [`KeyAuthorization::HistoricallyAuthorized`], while
///   `diagnose` returns no handle at all for the same input and policy.
///   Only once `diagnose`'s own probes all pass does it fall through to
///   `verify_retrieved` and, from that point on, withhold the handle /
///   record [`VerificationReport::policy_phase_error`] instead of
///   returning `Err` — that part of the behavior *is* shared with the
///   other two.
///
/// For ACDP v0.1.0 the verification profile is **always strict**:
///
/// - `did:web` is required for every producer identity — enforced
///   unconditionally by `verify_signature_envelope`
///   (RFC-ACDP-0001 §5.4), regardless of any policy field.
/// - Embedded `DataRef` hashes are verified by
///   [`acdp_validation::validate_body`] whenever `validate_body_schema`
///   is set.
///
/// Only the fields below have real effect in this version; there are no
/// relaxed-mode `did:web` or embedded-hash knobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationPolicy {
    /// If true, run [`acdp_validation::validate_body`] (structural
    /// schema checks plus embedded-`DataRef` hash verification) before
    /// any cryptographic check. Default `true`. Set `false` only in
    /// diagnostic paths that want to attempt signature verification
    /// despite a body known to fail structural checks.
    ///
    /// The `fetch_report*` family forces this field off unconditionally
    /// on the internal policy it derives from the caller's — they run
    /// `validate_body_structural` (schema only) themselves and record
    /// per-`DataRef` embedded-hash outcomes in
    /// [`VerificationReport::data_ref_embedded`] instead of treating a
    /// mismatch as fatal. This field's value as set by the caller is
    /// otherwise irrelevant to the report family.
    pub validate_body_schema: bool,

    /// If true, accept `Status::Other` values (degrade to active per
    /// RFC-ACDP-0004 §4.1). When false, reject unknown statuses.
    /// Default `true`.
    pub allow_unknown_status: bool,

    /// Registry-receipt handling (ACDP 0.2, RFC-ACDP-0010).
    /// Default [`ReceiptPolicy::VerifyIfPresent`].
    pub receipts: ReceiptPolicy,

    /// Historical-key handling (ACDP 0.2, WS-B). Default
    /// [`HistoricalKeyPolicy::AcceptWithReceipt`].
    pub historical_keys: HistoricalKeyPolicy,

    /// Lineage-head receipt handling on `/current` fetches (ACDP 0.3,
    /// RFC-ACDP-0011). Only consulted by
    /// [`VerifiedContext::fetch_current_with_policy`]; plain retrieval
    /// preserves any `lineage_head_receipt` verbatim without verifying
    /// it. Default [`LineageHeadPolicy::default`]. This is the ONE
    /// field on this struct with restricted scope — `allow_unknown_status`,
    /// `receipts`, `historical_keys`, and `revocations` above and below
    /// are each honored by every entry point that accepts a
    /// [`VerificationPolicy`], including the `fetch_report*` family.
    pub lineage_head: LineageHeadPolicy,

    /// Key-revocation handling (ACDP 0.3, RFC-ACDP-0014 §7). Default:
    /// no known revocations — the phase is inert.
    pub revocations: RevocationPolicy,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            validate_body_schema: true,
            allow_unknown_status: true,
            receipts: ReceiptPolicy::VerifyIfPresent,
            historical_keys: HistoricalKeyPolicy::AcceptWithReceipt,
            lineage_head: LineageHeadPolicy::default(),
            revocations: RevocationPolicy::default(),
        }
    }
}

/// Consumer-held key revocations to enforce during verification
/// (ACDP 0.3, RFC-ACDP-0014 §7).
///
/// The revocation signal is **pull-based**: the pipeline does not go
/// looking for revocations on its own — the caller supplies the
/// **verified** revocations it holds (from
/// [`find_revocations`](crate::revocation::find_revocations),
/// [`find_registry_attested_revocations`](crate::revocation::find_registry_attested_revocations),
/// an out-of-band channel, or its own indefinite cache — the statement
/// is permanent, cache accordingly). When `known` is empty the phase
/// is inert and verification behaves exactly as before RFC-ACDP-0014.
///
/// When the body's signing key matches a supplied revocation, §7
/// applies: a receipt-attested publish time strictly before the
/// (earliest, §4) `compromised_since` boundary verifies as
/// [`KeyAuthorization::HistoricallyAuthorizedPreCompromise`]; at/after
/// the boundary, or with no verified receipt to place the context at
/// all, verification **fails closed** with `key_not_authorized` —
/// regardless of DID-document state and regardless of the receipt's
/// own validity. Note the interaction with [`ReceiptPolicy::Ignore`]:
/// an unverified receipt provides no publish time, so a revoked key's
/// contexts all fail closed under it.
///
/// This applies uniformly to every entry point that accepts a
/// [`VerificationPolicy`] — [`VerifiedContext::fetch_with_policy`],
/// [`VerifiedContext::fetch_current_with_policy`], and the
/// `fetch_report*` family — since they all reach this phase through the
/// same internal pipeline. On [`VerifiedContext::fetch_report_diagnose`]
/// specifically, "fails closed" means the returned [`VerifiedContext`]
/// handle is withheld and the cause is recorded in
/// `VerificationReport::policy_phase_error`, rather than the call
/// returning `Err` — that method never short-circuits on a policy-phase
/// failure by design.
///
/// Only put revocations here that you have verified (strict body
/// pipeline + the §5 not-self-signed rule) and, per §6, that you have
/// decided to act on: producer-signed ones unconditionally;
/// registry-attested ones ([`RevocationTrustClass::RegistryAttested`](acdp_types::revocation::RevocationTrustClass))
/// by default only for contexts served by or receipted by that same
/// registry, with corroboration before global application.
///
/// [`find_revocations`](crate::revocation::find_revocations) itself
/// pre-filters its output to [`RevocationTrustClass::ProducerSigned`](acdp_types::revocation::RevocationTrustClass)
/// entries actually published by the queried producer, so §6
/// registry-attested attestations never arrive through it — obtain
/// those from
/// [`find_registry_attested_revocations`](crate::revocation::find_registry_attested_revocations)
/// instead.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RevocationPolicy {
    /// Verified revocations to enforce, matched against the signing
    /// key's RFC-ACDP-0010 §6 fingerprint. The §4 earliest-
    /// `compromised_since` rule is applied across entries naming the
    /// same fingerprint, so include *every* revocation of a lineage,
    /// superseded (and retracted) ones too — a later member can only
    /// widen the compromise window, never narrow it, and dropping an
    /// earlier one is exactly how that window gets quietly (and
    /// wrongly) shrunk. This is no longer an unassisted obligation:
    /// [`find_revocations`](crate::revocation::find_revocations) and
    /// [`find_registry_attested_revocations`](crate::revocation::find_registry_attested_revocations)
    /// each walk the full lineage of every candidate they find
    /// (search-visible or not, including all-retracted lineages) and
    /// already return the complete set for their respective trust
    /// class; [`find_revocations_in_lineage`](crate::revocation::find_revocations_in_lineage)
    /// does the same directly from a known `lineage_id`, with no
    /// producer/trust-class scope filter. Populate `known` from one of
    /// these rather than hand-assembling a lineage.
    pub known: Vec<acdp_types::revocation::KeyRevocation>,
}

/// How to treat the optional `registry_receipt` on retrieval
/// (RFC-ACDP-0010).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReceiptPolicy {
    /// Skip receipt verification entirely (0.1.0 behavior). The
    /// receipt value is still preserved verbatim on the context.
    Ignore,
    /// Verify the receipt when one is present; absence is not an
    /// error (the registry may simply be a 0.1.0 registry). Default.
    #[default]
    VerifyIfPresent,
    /// Fail closed unless a receipt is present AND verifies. Use when
    /// the deployment requires audit-grade provenance — registry
    /// claims (`ctx_id`, `created_at`, `origin_registry`) are
    /// assertions, not proofs, without a receipt.
    ///
    /// Honored identically by every entry point that accepts a
    /// [`VerificationPolicy`] — `fetch_with_policy`,
    /// `fetch_current_with_policy` (via [`LineageHeadPolicy::receipts`]),
    /// and the `fetch_report*` family. On
    /// [`VerifiedContext::fetch_report_diagnose`] the failure surfaces as
    /// a withheld handle plus `VerificationReport::policy_phase_error`,
    /// not an `Err` — see that method's doc.
    Require,
}

/// How to treat the optional `lineage_head_receipt` on
/// `GET /lineages/{id}/current` responses (ACDP 0.3, RFC-ACDP-0011).
///
/// The presence handling reuses the [`ReceiptPolicy`] vocabulary; the
/// two numeric knobs are the RFC's consumer-side parameters:
///
/// - `max_clock_skew_seconds` — §7 step 6's forward-skew allowance. A
///   receipt whose `as_of` is further in the future **fails
///   verification** (`invalid_receipt`, fixture `lhr-004`). RFC
///   RECOMMENDED: 120.
/// - `max_age_seconds` — §6's freshness policy. A receipt older than
///   this is still *verified* (it may be perfectly genuine — merely
///   old); it is reported distinctly via
///   [`VerifiedContext::head_receipt_stale`], never as a verification
///   failure. RFC RECOMMENDED default: 300. `None` disables the
///   staleness verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineageHeadPolicy {
    /// Presence handling: `Ignore` (skip verification, preserve
    /// verbatim), `VerifyIfPresent` (default), or `Require` (fail
    /// closed unless present AND verified — appropriate when the
    /// registry advertises `acdp-registry-head-receipts`, under which
    /// a head receipt on `/current` is REQUIRED, RFC-ACDP-0011 §6).
    pub receipts: ReceiptPolicy,
    /// RFC-ACDP-0011 §7 step 6 clock-skew allowance (default 120 s).
    pub max_clock_skew_seconds: u32,
    /// RFC-ACDP-0011 §6 maximum acceptable receipt age for the
    /// staleness verdict (default `Some(300)`).
    pub max_age_seconds: Option<u32>,
}

impl Default for LineageHeadPolicy {
    fn default() -> Self {
        Self {
            receipts: ReceiptPolicy::VerifyIfPresent,
            max_clock_skew_seconds: 120,
            max_age_seconds: Some(300),
        }
    }
}

/// How to treat a producer key that is present in the DID document's
/// `verificationMethod` but no longer in `assertionMethod` — i.e. a
/// key the producer rotated out but retained per the RFC-ACDP-0010
/// key-retention rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HistoricalKeyPolicy {
    /// Strict 0.1.0 behavior: only `assertionMethod` keys verify.
    /// Every context signed by a rotated-out key fails.
    Reject,
    /// Accept a retained key **only** when a verified registry receipt
    /// attests (via `key_fingerprint`) that this exact key was the
    /// authorized one at publish time. Without a verified receipt the
    /// historical path never activates — fail closed. Default.
    #[default]
    AcceptWithReceipt,
}

/// How the producer key that verified the body relates to the
/// producer's *current* DID document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAuthorization {
    /// The signing key is currently listed in `assertionMethod`.
    CurrentlyAuthorized,
    /// The signing key was rotated out of `assertionMethod` but is
    /// retained in `verificationMethod`, and a verified registry
    /// receipt attests it was the authorized key at publish time
    /// (RFC-ACDP-0010). Weigh accordingly: valid history, not a
    /// current endorsement.
    HistoricallyAuthorized,
    /// The signing key is **revoked** (a verified RFC-ACDP-0014
    /// revocation names its fingerprint), but a verified registry
    /// receipt attests the context was published strictly *before* the
    /// compromise boundary `compromised_since` — it was signed while
    /// the key was still the producer's, and verified under the
    /// RFC-ACDP-0010 §10 historical rule (RFC-ACDP-0014 §7 step 2).
    ///
    /// Deliberately distinguishable from BOTH
    /// [`Self::CurrentlyAuthorized`] and the no-revocation
    /// [`Self::HistoricallyAuthorized`]: the revocation and its
    /// boundary MUST be visible in the verdict — even a key still
    /// listed in `assertionMethod` MUST NOT be reported as fully
    /// current once revoked. This holds for every entry point that
    /// accepts a [`VerificationPolicy`], including the `fetch_report*`
    /// family: they derive `key_status` from the same `verify_retrieved`
    /// phase `fetch_with_policy` uses, so a revoked key cannot silently
    /// surface as [`Self::CurrentlyAuthorized`] on any of them. Contexts
    /// by the same key at/after the boundary — or with no verifiable
    /// publish time — never reach a status at all: they fail closed
    /// with `key_not_authorized` (§7 steps 3–4).
    HistoricallyAuthorizedPreCompromise,
}

impl VerificationPolicy {
    /// The v0.1.0 strict verification profile (RFC-ACDP-0001 §5.11, §9.2).
    ///
    /// Runs the full §5.11 pipeline: body schema validation, `content_hash`
    /// recomputation, `did:web` key resolution, signature verification, and
    /// embedded `data_ref.content_hash` checks. Returns on the first failure.
    ///
    /// This is the **only** mode covered by the `acdp-consumer` conformance
    /// profile. Relaxed modes (`Diagnostic`, `UnsafeForTests`) are NOT
    /// available in this crate in v0.1.0 — they would be separately-named
    /// opt-ins per §9.2, and are not currently implemented.
    ///
    /// NOT identical to [`Default::default()`] as of 0.2: the default
    /// policy is receipt-aware (`VerifyIfPresent` + `AcceptWithReceipt`),
    /// while this named profile preserves the exact v0.1.0 semantics —
    /// receipts inert ([`ReceiptPolicy::Ignore`]) and only
    /// `assertionMethod` keys accepted
    /// ([`HistoricalKeyPolicy::Reject`]). Callers pinned to this
    /// constructor keep v0.1.0 behavior across the 0.2 upgrade.
    pub fn strict_v0_1_0() -> Self {
        Self {
            validate_body_schema: true,
            allow_unknown_status: true,
            receipts: ReceiptPolicy::Ignore,
            historical_keys: HistoricalKeyPolicy::Reject,
            lineage_head: LineageHeadPolicy {
                receipts: ReceiptPolicy::Ignore,
                ..LineageHeadPolicy::default()
            },
            // A 0.1.0-pinned consumer predates RFC-ACDP-0014 and is
            // unaffected by it (§10): no revocations enforced.
            revocations: RevocationPolicy::default(),
        }
    }

    /// The policy the report family (`fetch_report`,
    /// `fetch_report_with_fetcher`, `fetch_report_diagnose`) passes to
    /// [`VerifiedContext::verify_retrieved`].
    ///
    /// `validate_body_schema` is forced `false` unconditionally,
    /// independent of the caller: P1 (schema) is always handled by the
    /// report path itself — `validate_body_structural` plus per-`DataRef`
    /// non-fatal recording of embedded-hash outcomes into
    /// `VerificationReport::data_ref_embedded` — so the spine must always
    /// skip its own full `validate_body` (structural + fatal embedded-hash
    /// check) here. Every other field passes through verbatim. Do **not**
    /// pass the caller's policy directly to `verify_retrieved` from a
    /// report entry point; doing so reinstates the fatal embedded-hash
    /// check the report path deliberately downgrades to non-fatal (see
    /// `tests/tls_conformance.rs`'s
    /// `fetch_report_records_embedded_hash_failure`).
    fn derived_for_report(&self) -> Self {
        Self {
            validate_body_schema: false,
            ..self.clone()
        }
    }
}

/// A retrieved context that has been cryptographically verified.
///
/// Every value of this type is the output of one of the
/// `VerifiedContext::fetch*` pipelines, each of which independently
/// recomputes `content_hash` (RFC-ACDP-0001 §5.11) and verifies the
/// producer signature before the value is constructed. The fields are
/// **private** precisely so this "cryptographically verified" invariant
/// cannot be forged: there is no way to construct a `VerifiedContext`
/// around an unverified [`FullContext`]. Downstream code can therefore
/// trust the accessors below without re-deriving anything.
#[derive(Debug)]
pub struct VerifiedContext {
    inner: FullContext,
    /// Whether the body verified against a currently authorized key or
    /// a receipt-attested historical one (ACDP 0.2, WS-B).
    key_status: KeyAuthorization,
    /// The verified registry receipt, when one was present and the
    /// policy verified it (RFC-ACDP-0010). `None` under
    /// [`ReceiptPolicy::Ignore`] or when the registry minted none.
    verified_receipt: Option<acdp_types::receipt::RegistryReceipt>,
    /// The verified lineage-head receipt (ACDP 0.3, RFC-ACDP-0011),
    /// when one was present and the policy verified it. Only populated
    /// by [`Self::fetch_current`] / [`Self::fetch_current_with_policy`]
    /// — plain retrieval preserves the raw value verbatim without
    /// verification. Per §7 this verdict is independent of the body
    /// verdict and the RFC-ACDP-0010 receipt verdict.
    verified_head_receipt: Option<acdp_types::receipt::LineageHeadReceipt>,
    /// RFC-ACDP-0011 §6 freshness verdict for the verified head
    /// receipt, reported distinctly from verification: `Some(true)`
    /// when the (genuine, verified) receipt's `as_of` is older than
    /// [`LineageHeadPolicy::max_age_seconds`]; `Some(false)` when
    /// within policy; `None` when there is no verified head receipt or
    /// the max-age knob is disabled.
    head_receipt_stale: Option<bool>,
}

impl VerifiedContext {
    /// Retrieve a context and verify its signature using the strict
    /// default [`VerificationPolicy`].
    pub async fn fetch(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
    ) -> Result<Self, AcdpError> {
        Self::fetch_with_policy(client, resolver, ctx_id, &VerificationPolicy::default()).await
    }

    /// Retrieve a context and verify its signature with caller-controlled
    /// strictness.
    ///
    /// 1. Fetches `body + registry_state` from the registry.
    /// 2. Refuses a served body whose `ctx_id` differs from the one
    ///    requested (`AcdpError::ContextIdMismatch`) — this implements
    ///    RFC-ACDP-0006 §4.1 step 7 (NORMATIVE, "Bind the resolved
    ///    identity"): neither the signature check (step 5) nor the
    ///    `content_hash` recomputation (step 6) can supply this binding,
    ///    because `ctx_id` sits in the RFC-ACDP-0001 §5.7 registry-assigned
    ///    exclusion set and is therefore stripped from ProducerContent
    ///    before hashing. See RFC-ACDP-0008 §9.1 for the threat this
    ///    closes: without it, a registry can serve any other
    ///    validly-signed body by the same producer under the requested
    ///    context's URL, and both preceding checks still pass. Step 7
    ///    permits a consumer to surface "an equivalent typed error" in
    ///    place of the registry-side `cross_registry_resolution_failed`
    ///    wire code — `ContextIdMismatch` is that typed error. This
    ///    generalizes the receipt-path analogue at RFC-ACDP-0010 §8 step 3
    ///    to the receipt-less core-profile path, where it is the only
    ///    binding available. It does **not** close §9.1 in full: a
    ///    registry that genuinely republishes the same content under a
    ///    new `ctx_id` still passes; only serve-time substitution — a
    ///    different id claimed to be the one requested — is caught.
    /// 3. Optionally runs `validate_body` — structural schema checks
    ///    plus embedded-`DataRef` hash verification (policy-controlled).
    /// 4. Recomputes `content_hash` over ProducerContent.
    /// 5. Resolves the producer's DID document. `did:web` is required
    ///    unconditionally for v0.1.0 (RFC-ACDP-0001 §5.4).
    /// 6. Verifies the Ed25519 signature (or other supported algorithm).
    /// 7. Optionally verifies the `registry_receipt` placeholder.
    /// 8. Optionally rejects unknown statuses.
    pub async fn fetch_with_policy(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
        policy: &VerificationPolicy,
    ) -> Result<Self, AcdpError> {
        let ctx = client.retrieve(ctx_id).await?;
        let (key_status, verified_receipt) =
            Self::verify_retrieved(client, resolver, &ctx, ctx_id, policy).await?;
        Ok(Self {
            inner: ctx,
            key_status,
            verified_receipt,
            verified_head_receipt: None,
            head_receipt_stale: None,
        })
    }

    /// Retrieve the current head of a lineage
    /// (`GET /lineages/{lineage_id}/current`) and verify it with the
    /// strict default [`VerificationPolicy`] — including the
    /// lineage-head receipt when the registry minted one (ACDP 0.3,
    /// RFC-ACDP-0011).
    pub async fn fetch_current(
        client: &RegistryClient,
        resolver: &WebResolver,
        lineage_id: &acdp_types::primitives::LineageId,
    ) -> Result<Self, AcdpError> {
        Self::fetch_current_with_policy(
            client,
            resolver,
            lineage_id,
            &VerificationPolicy::default(),
        )
        .await
    }

    /// Retrieve + verify the current head of a lineage with
    /// caller-controlled strictness.
    ///
    /// Runs the same pipeline as [`Self::fetch_with_policy`] against
    /// the `/current` response (the expected `ctx_id` is the served
    /// body's own — there is no requested identifier on this endpoint;
    /// the head receipt's §7 step 5 byte-match is what binds it), then
    /// applies `policy.lineage_head` to the response's
    /// `lineage_head_receipt` per RFC-ACDP-0011 §7:
    ///
    /// - [`ReceiptPolicy::Ignore`] — the raw value is preserved
    ///   verbatim, unverified.
    /// - [`ReceiptPolicy::VerifyIfPresent`] — verified when present
    ///   (absence is fine: the registry may not advertise
    ///   `acdp-registry-head-receipts`).
    /// - [`ReceiptPolicy::Require`] — fail closed with
    ///   `invalid_receipt` unless present AND verified.
    ///
    /// Verification fetches the registry's capabilities document for
    /// the §7 step 3 `capabilities.registry_did` binding. Staleness
    /// beyond `policy.lineage_head.max_age_seconds` is a *freshness*
    /// verdict reported via [`Self::head_receipt_stale`], never a
    /// verification failure (§6).
    ///
    /// [`Self::fetch_with_policy`] now additionally refuses a served body
    /// whose `ctx_id` is not the one requested (RFC-ACDP-0008 §9.1). This
    /// endpoint has no requested identifier to compare against — the
    /// served head's `ctx_id` is trivially "the one requested" — so on a
    /// receipt-less registry the served head's identity rests entirely on
    /// registry honesty (RFC-ACDP-0008 §9.1). Use [`ReceiptPolicy::Require`]
    /// where that matters.
    pub async fn fetch_current_with_policy(
        client: &RegistryClient,
        resolver: &WebResolver,
        lineage_id: &acdp_types::primitives::LineageId,
        policy: &VerificationPolicy,
    ) -> Result<Self, AcdpError> {
        let ctx = client.current(lineage_id).await?;
        let served_ctx_id = ctx.body.ctx_id.clone();
        let (key_status, verified_receipt) =
            Self::verify_retrieved(client, resolver, &ctx, &served_ctx_id, policy).await?;

        // ── Lineage-head receipt phase (RFC-ACDP-0011) ──────────────
        let (verified_head_receipt, head_receipt_stale) =
            match (policy.lineage_head.receipts, &ctx.lineage_head_receipt) {
                (ReceiptPolicy::Ignore, _) | (ReceiptPolicy::VerifyIfPresent, None) => (None, None),
                (ReceiptPolicy::Require, None) => {
                    return Err(AcdpError::InvalidReceipt(
                        "policy requires a lineage-head receipt but the /current response \
                         carries none (registry without the acdp-registry-head-receipts \
                         profile?)"
                            .into(),
                    ));
                }
                (_, Some(value)) => {
                    let serving_authority = client
                        .authority()
                        .unwrap_or_else(|| served_ctx_id.authority().to_string());
                    // §7 step 3 needs capabilities.registry_did — fetched
                    // from the same authority the context came from.
                    let caps = client.capabilities().await?;
                    let receipt = super::receipt::verify_lineage_head_receipt_value(
                        value,
                        lineage_id,
                        &served_ctx_id,
                        ctx.body.version,
                        &ctx.registry_state.status,
                        true, // /current always serves the attested head
                        &serving_authority,
                        &caps.registry_did,
                        chrono::Duration::seconds(
                            policy.lineage_head.max_clock_skew_seconds as i64,
                        ),
                        resolver,
                    )
                    .await?;
                    let stale = policy.lineage_head.max_age_seconds.map(|max| {
                        receipt.age_at(chrono::Utc::now()) > chrono::Duration::seconds(max as i64)
                    });
                    (Some(receipt), stale)
                }
            };

        Ok(Self {
            inner: ctx,
            key_status,
            verified_receipt,
            verified_head_receipt,
            head_receipt_stale,
        })
    }

    /// The shared retrieve-side verification pipeline: body schema,
    /// hash recomputation, RFC-ACDP-0010 receipt phase, signature
    /// phase (with the receipt-gated historical-key fallback), and the
    /// unknown-status policy check.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(
            name = "acdp.verify_retrieved",
            skip_all,
            fields(ctx_id = %expected_ctx_id),
            err(Display)
        )
    )]
    async fn verify_retrieved(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx: &FullContext,
        expected_ctx_id: &CtxId,
        policy: &VerificationPolicy,
    ) -> Result<
        (
            KeyAuthorization,
            Option<acdp_types::receipt::RegistryReceipt>,
        ),
        AcdpError,
    > {
        // Identifier binding — RFC-ACDP-0006 §4.1 step 7 (NORMATIVE, "Bind
        // the resolved identity"): refuse a served body whose `ctx_id`
        // differs from the one requested, before any crypto or network
        // work. `ctx_id` is registry-assigned and outside both the
        // `content_hash` and signature coverage (RFC-ACDP-0001 §5.7's
        // exclusion set), so this equality check is the only binding
        // available when no receipt is served. See RFC-ACDP-0008 §9.1 for
        // the threat this closes; it does not close §9.1 in full (a
        // genuine republish under a new `ctx_id` still passes — only
        // serve-time substitution is caught). Step 7 permits a
        // consumer-side "equivalent typed error" in place of the
        // registry-side `cross_registry_resolution_failed` wire code —
        // `ContextIdMismatch` is that typed error.
        if ctx.body.ctx_id != *expected_ctx_id {
            return Err(AcdpError::ContextIdMismatch {
                requested: expected_ctx_id.as_str().to_string(),
                served: ctx.body.ctx_id.as_str().to_string(),
            });
        }

        if policy.validate_body_schema {
            acdp_validation::validate_body(&ctx.body)?;
        }

        // Hash recomputation first: from here on `ctx.body.content_hash`
        // IS the independently recomputed value, which the receipt
        // cross-check below relies on.
        let verifier = Verifier::new(resolver);
        verifier.verify_body_hash(&ctx.body)?;

        // ── Receipt phase (RFC-ACDP-0010) ───────────────────────────
        // Verified BEFORE the signature phase because the historical-
        // key path is gated on a verified receipt.
        let serving_authority = client
            .authority()
            .unwrap_or_else(|| expected_ctx_id.authority().to_string());
        let verified_receipt = match (policy.receipts, &ctx.registry_receipt) {
            (ReceiptPolicy::Ignore, _) | (ReceiptPolicy::VerifyIfPresent, None) => None,
            (ReceiptPolicy::Require, None) => {
                return Err(AcdpError::InvalidReceipt(
                    "policy requires a registry receipt but the response carries none \
                     (registry without the acdp-registry-receipts profile, or a \
                     pre-receipts context)"
                        .into(),
                ));
            }
            (_, Some(value)) => {
                let fingerprint = acdp_crypto::fingerprint::fingerprint_for_key_id(
                    &ctx.body.signature.key_id,
                    &ctx.body.signature.algorithm,
                    resolver,
                )
                .await?;
                Some(
                    super::receipt::verify_receipt_value(
                        value,
                        expected_ctx_id,
                        &ctx.body,
                        &ctx.body.content_hash,
                        &fingerprint,
                        &serving_authority,
                        resolver,
                    )
                    .await?,
                )
            }
        };

        // ── Revocation phase (RFC-ACDP-0014 §7) ─────────────────────
        // Runs after the receipt phase because the boundary comparison
        // accepts ONLY a receipt-attested publish time (§7 step 1 —
        // the bare body created_at is registry-assigned and MUST NOT
        // be used). The verified receipt's key_fingerprint was already
        // cross-checked against the body's signing key above (§8 step
        // 5), so `verified_receipt.created_at` genuinely places THIS
        // key's signature in time.
        let revocation_verdict = if policy.revocations.known.is_empty() {
            None
        } else {
            let fingerprint = acdp_crypto::fingerprint::fingerprint_for_key_id(
                &ctx.body.signature.key_id,
                &ctx.body.signature.algorithm,
                resolver,
            )
            .await?;
            super::revocation::classify_under_revocation(
                &policy.revocations.known,
                &fingerprint,
                verified_receipt.as_ref().map(|r| r.created_at),
            )?
        };

        // ── Signature phase ──────────────────────────────────────────
        // Standard path enforces assertionMethod membership. A
        // KeyNotAuthorized failure falls back to the historical path
        // only under AcceptWithReceipt AND a verified receipt — the
        // receipt's key_fingerprint (already cross-checked against this
        // exact key above) is what attests publish-time authorization.
        let key_status = match revocation_verdict {
            // Pre-compromise (§7 step 2): the signature is verified
            // under the RFC-ACDP-0010 §10 historical rule — the key may
            // legitimately have left assertionMethod (and SHOULD, §9),
            // and even a key still in assertionMethod MUST NOT be
            // reported as fully current once revoked. did:key material
            // cannot rotate, so it takes the plain envelope path.
            Some(pre_compromise) => {
                if ctx.body.agent_id.as_str().starts_with("did:key:") {
                    verifier.verify_body_signature(&ctx.body).await?;
                } else {
                    acdp_verify::verify_body_signature_historical(&ctx.body, resolver).await?;
                }
                pre_compromise
            }
            None => match verifier.verify_body_signature(&ctx.body).await {
                Ok(()) => KeyAuthorization::CurrentlyAuthorized,
                Err(AcdpError::KeyNotAuthorized(_))
                    if policy.historical_keys == HistoricalKeyPolicy::AcceptWithReceipt
                        && verified_receipt.is_some() =>
                {
                    acdp_verify::verify_body_signature_historical(&ctx.body, resolver).await?;
                    KeyAuthorization::HistoricallyAuthorized
                }
                Err(e) => return Err(e),
            },
        };

        if !policy.allow_unknown_status {
            if let Some(other) = ctx.registry_state.status.as_other() {
                return Err(AcdpError::SchemaViolation(format!(
                    "policy.allow_unknown_status=false; registry returned '{other}'"
                )));
            }
        }

        Ok((key_status, verified_receipt))
    }

    /// Retrieve + verify, returning a structured [`VerificationReport`]
    /// alongside the verified context. Does NOT attempt external
    /// `DataRef` fetches — use [`Self::fetch_report_with_fetcher`] for
    /// that. Each `data_ref_external` slot in the returned report is
    /// `None`.
    ///
    /// Unlike [`Self::fetch_with_policy`], per-`DataRef` embedded-hash
    /// failures are recorded in the report instead of aborting the
    /// verification. The top-level checks (schema, body hash,
    /// signature) remain hard-fail: if any of them fails, the method
    /// returns an `AcdpError` and produces no report.
    ///
    /// For diagnostic callers that want a populated report even when
    /// a top-level check fails (e.g. an audit walker that needs to
    /// distinguish "wrong hash" from "wrong signature"), use
    /// [`Self::fetch_report_diagnose`] instead.
    pub async fn fetch_report(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
        policy: &VerificationPolicy,
    ) -> Result<(Self, VerificationReport), AcdpError> {
        Self::fetch_report_inner::<NoFetcher>(client, resolver, ctx_id, policy, None).await
    }

    /// Diagnostic variant of [`Self::fetch_report`] that never
    /// short-circuits on a top-level failure — schema, body-hash, and
    /// signature outcomes are each recorded individually in the
    /// returned [`VerificationReport`]. Returns `Ok((None, report))`
    /// when any top-level probe failed (the report shows which one);
    /// `Ok((Some(verified), report))` only when every check passed
    /// (FEAT-05) — and "every check" now genuinely means every
    /// authorization phase (receipt, revocation, signature/
    /// historical-key, unknown-status), not just the top-level probes:
    /// once the probes pass, this method additionally runs the same
    /// `verify_retrieved` phase `fetch_with_policy` does, and withholds
    /// the handle — recording the cause in
    /// [`VerificationReport::policy_phase_error`] — if that phase fails
    /// too. Either way the method still returns `Ok`; it never converts
    /// a policy-phase failure into an `Err`.
    ///
    /// Use cases:
    /// - Audit walkers that need to classify failures by stage.
    /// - Admin tooling that wants to distinguish "hash mismatch"
    ///   (probable tampering / encoding drift) from "signature
    ///   verification failed" (key compromise / DID resolution
    ///   problem).
    ///
    /// Network errors from the initial retrieval still propagate as
    /// `Err` — there's no body to inspect when the registry is
    /// unreachable. But network/DID-resolution errors that occur
    /// *inside* the `verify_retrieved` phase (e.g. resolving the
    /// fingerprint for a receipt cross-check, or the historical-key
    /// fallback) are caught there and land in
    /// [`VerificationReport::policy_phase_error`] instead of `Err`,
    /// same as any other phase failure — this method never
    /// short-circuits once retrieval has succeeded. That means a
    /// transient network flake at that stage can read as a policy
    /// rejection (`Ok((None, report))`) rather than an `Err`. A caller
    /// that needs to tell a flake from a genuine rejection should
    /// inspect `policy_phase_error`'s [`AcdpError::is_transient`].
    pub async fn fetch_report_diagnose(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
        policy: &VerificationPolicy,
    ) -> Result<(Option<Self>, VerificationReport), AcdpError> {
        let ctx = client.retrieve(ctx_id).await?;
        let mut report = VerificationReport {
            body_hash_ok: false,
            signature_ok: false,
            schema_ok: false,
            data_ref_embedded: Vec::with_capacity(ctx.body.data_refs.len()),
            data_ref_external: Vec::with_capacity(ctx.body.data_refs.len()),
            ctx_id_ok: ctx.body.ctx_id == *ctx_id,
            key_status: None,
            policy_phase_error: None,
        };

        // Schema (structural) — record pass/fail.
        if policy.validate_body_schema {
            match acdp_validation::validate_body_structural(&ctx.body) {
                Ok(()) => report.schema_ok = true,
                Err(_) => { /* keep schema_ok=false; continue collecting */ }
            }
        } else {
            report.schema_ok = true;
        }

        // Per-DataRef embedded hashes — same as fetch_report_inner.
        for dr in &ctx.body.data_refs {
            if let (Some(emb), Some(_)) = (&dr.embedded, &dr.content_hash) {
                let outcome = acdp_validation::verify_embedded_hash(dr)
                    .and_then(|()| acdp_validation::embedded_decoded_bytes(emb).map(|b| b.len()));
                report.data_ref_embedded.push(outcome);
            } else {
                report.data_ref_embedded.push(Ok(0));
            }
        }

        // Hash + signature recorded independently (FEAT-05).
        let verifier = Verifier::new(resolver);
        report.body_hash_ok = verifier.verify_body_hash(&ctx.body).is_ok();
        report.signature_ok = verifier.verify_body_signature(&ctx.body).await.is_ok();

        // External fetches were not attempted (this method has no
        // fetcher param — diagnostic callers can wire their own).
        for _ in &ctx.body.data_refs {
            report.data_ref_external.push(None);
        }

        // Decide whether to surface the verified handle. The probes above
        // are diagnostic — their whole value is continuing past failure —
        // but the handle is a trust assertion (`VerifiedContext`'s
        // invariant: "the accessors below can be trusted without
        // re-deriving anything"), so it is only ever issued once the real
        // authorization phases (receipt, revocation, signature/historical,
        // unknown-status) have actually run and passed through
        // `verify_retrieved` — never on the probes alone.
        let all_top_level_pass =
            report.schema_ok && report.body_hash_ok && report.signature_ok && report.ctx_id_ok;
        let verified = if all_top_level_pass {
            // The call MUST be hoisted out of the `match` scrutinee: in a
            // match, scrutinee temporaries live to the end of the match,
            // so the awaited future would still be holding `&ctx` inside
            // the arms and `Self { inner: ctx, .. }` below would fail
            // borrowck (E0505).
            let outcome = Self::verify_retrieved(
                client,
                resolver,
                &ctx,
                ctx_id,
                &policy.derived_for_report(),
            )
            .await; // borrow of `ctx` ends here
            match outcome {
                Ok((key_status, verified_receipt)) => {
                    report.key_status = Some(key_status);
                    Some(Self {
                        inner: ctx,
                        key_status,
                        verified_receipt,
                        verified_head_receipt: None,
                        head_receipt_stale: None,
                    })
                }
                Err(e) => {
                    // Reports; never short-circuits — `fetch_report_diagnose`
                    // still returns `Ok` in every case it does today.
                    report.policy_phase_error = Some(e);
                    None
                }
            }
        } else {
            None
        };
        Ok((verified, report))
    }

    /// Retrieve + verify like [`Self::fetch_report`], and additionally
    /// fetch every `DataRef` whose `location` resolves through `fetcher`.
    /// Each external fetch outcome is recorded in `report.data_ref_external`.
    pub async fn fetch_report_with_fetcher<F: DataRefFetcher>(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
        policy: &VerificationPolicy,
        fetcher: &F,
    ) -> Result<(Self, VerificationReport), AcdpError> {
        Self::fetch_report_inner(client, resolver, ctx_id, policy, Some(fetcher)).await
    }

    async fn fetch_report_inner<F: DataRefFetcher>(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
        policy: &VerificationPolicy,
        fetcher: Option<&F>,
    ) -> Result<(Self, VerificationReport), AcdpError> {
        let ctx = client.retrieve(ctx_id).await?;

        // Identifier binding — RFC-ACDP-0006 §4.1 step 7 (NORMATIVE, "Bind
        // the resolved identity"). Same check as `verify_retrieved`,
        // applied here (in addition to `verify_retrieved`'s own re-check
        // below) so this fails before schema validation too — the early
        // copy preserves fail-before-schema ordering that
        // `tests/receipts.rs` depends on.
        if ctx.body.ctx_id != *ctx_id {
            return Err(AcdpError::ContextIdMismatch {
                requested: ctx_id.as_str().to_string(),
                served: ctx.body.ctx_id.as_str().to_string(),
            });
        }

        let mut report = VerificationReport {
            body_hash_ok: false,
            signature_ok: false,
            schema_ok: false,
            data_ref_embedded: Vec::with_capacity(ctx.body.data_refs.len()),
            data_ref_external: Vec::with_capacity(ctx.body.data_refs.len()),
            ctx_id_ok: true,
            key_status: None,
            policy_phase_error: None,
        };

        // Structural-only schema validation — embedded-hash checks are
        // intentionally skipped here so per-DataRef hash failures land
        // in the report (below) instead of short-circuiting the whole
        // verification. That's the diagnostic shape `fetch_report`
        // promises in its docstring.
        if policy.validate_body_schema {
            acdp_validation::validate_body_structural(&ctx.body)?;
        }
        report.schema_ok = true;

        // Per-DataRef embedded-hash outcomes — recorded individually.
        for dr in &ctx.body.data_refs {
            if let (Some(emb), Some(_)) = (&dr.embedded, &dr.content_hash) {
                let outcome = acdp_validation::verify_embedded_hash(dr)
                    .and_then(|()| acdp_validation::embedded_decoded_bytes(emb).map(|b| b.len()));
                report.data_ref_embedded.push(outcome);
            } else {
                report.data_ref_embedded.push(Ok(0));
            }
        }

        // Delegate the remaining phases — content_hash recomputation,
        // RFC-ACDP-0010 receipt, RFC-ACDP-0014 revocation, signature (with
        // the historical-key fallback), and the unknown-status check — to
        // `verify_retrieved`, the sole reader of those policy fields. The
        // derived policy forces `validate_body_schema` off (P1 was already
        // handled, structurally-only, above) and passes everything else
        // through verbatim — see `VerificationPolicy::derived_for_report`.
        let (key_status, verified_receipt) =
            Self::verify_retrieved(client, resolver, &ctx, ctx_id, &policy.derived_for_report())
                .await?;
        report.body_hash_ok = true;
        report.signature_ok = true;
        report.key_status = Some(key_status);

        // External fetches — record per-ref outcomes when a fetcher is
        // supplied; otherwise leave each slot as `None` so callers can
        // distinguish "skipped" from "failed".
        for dr in &ctx.body.data_refs {
            let slot: Option<Result<usize, AcdpError>> = match (fetcher, &dr.location) {
                (Some(f), Some(_)) => Some(fetch_and_verify_data_ref(dr, f).await.map(|b| b.len())),
                _ => None,
            };
            report.data_ref_external.push(slot);
        }

        Ok((
            Self {
                inner: ctx,
                key_status,
                verified_receipt,
                verified_head_receipt: None,
                head_receipt_stale: None,
            },
            report,
        ))
    }

    pub fn body(&self) -> &acdp_types::body::Body {
        &self.inner.body
    }

    pub fn registry_state(&self) -> &acdp_types::body::RegistryState {
        &self.inner.registry_state
    }

    /// The verified [`FullContext`] (body + registry state + any
    /// receipts) in its retrieval shape. Every field was reached only
    /// after this context's hash + signature were verified.
    pub fn full_context(&self) -> &FullContext {
        &self.inner
    }

    /// Whether the body verified against a currently authorized key, a
    /// receipt-attested historical one, or a receipt-attested
    /// pre-compromise one (ACDP 0.2 WS-B / RFC-ACDP-0014 §7). This is
    /// the real verdict regardless of which `fetch*`/`fetch_report*`
    /// entry point produced this `VerifiedContext` — every construction
    /// path runs the same `verify_retrieved` phase to derive it.
    pub fn key_status(&self) -> KeyAuthorization {
        self.key_status
    }

    /// The verified registry receipt (RFC-ACDP-0010), when one was
    /// present and the policy verified it. `None` under
    /// [`ReceiptPolicy::Ignore`] or when the registry minted none — this
    /// is exhaustive; there is no additional "or you used a report path"
    /// carve-out, since `fetch_report`/`fetch_report_with_fetcher`/
    /// `fetch_report_diagnose` verify the receipt exactly like
    /// `fetch_with_policy` does. For the raw on-wire value see
    /// [`Self::receipt`].
    pub fn verified_receipt(&self) -> Option<&acdp_types::receipt::RegistryReceipt> {
        self.verified_receipt.as_ref()
    }

    /// The verified lineage-head receipt (ACDP 0.3, RFC-ACDP-0011),
    /// populated only by [`Self::fetch_current`] /
    /// [`Self::fetch_current_with_policy`] when one was present and the
    /// policy verified it. For the raw on-wire value see
    /// [`Self::lineage_head_receipt`].
    pub fn verified_head_receipt(&self) -> Option<&acdp_types::receipt::LineageHeadReceipt> {
        self.verified_head_receipt.as_ref()
    }

    /// RFC-ACDP-0011 §6 freshness verdict for the verified head
    /// receipt: `Some(true)` when the (genuine, verified) receipt's
    /// `as_of` is older than [`LineageHeadPolicy::max_age_seconds`];
    /// `Some(false)` when within policy; `None` when there is no
    /// verified head receipt or the max-age knob is disabled.
    pub fn head_receipt_stale(&self) -> Option<bool> {
        self.head_receipt_stale
    }

    /// Raw registry receipt value as served on the wire
    /// (RFC-ACDP-0010), preserved verbatim. For the verified, typed
    /// form see [`Self::verified_receipt`].
    pub fn receipt(&self) -> Option<&serde_json::Value> {
        self.inner.registry_receipt.as_ref()
    }

    /// Raw lineage-head receipt value as served on the wire
    /// (RFC-ACDP-0011), preserved verbatim. For the verified, typed
    /// form see [`Self::verified_head_receipt`].
    pub fn lineage_head_receipt(&self) -> Option<&serde_json::Value> {
        self.inner.lineage_head_receipt.as_ref()
    }

    /// Verify the registry receipt, when one is present
    /// (RFC-ACDP-0010).
    ///
    /// Standalone variant for contexts obtained via the report paths;
    /// `fetch_with_policy` already does this under
    /// [`ReceiptPolicy::VerifyIfPresent`]/`Require`. The serving
    /// authority is taken from the context's own `ctx_id` — this method
    /// performs no requested-id binding of its own (it has no requested
    /// id to compare against; it only ever sees `self.inner.body.ctx_id`),
    /// so deriving the serving authority this way is sound only for a
    /// `VerifiedContext` obtained through a pipeline that already bound
    /// the served `ctx_id` to the one requested. Every construction path
    /// does: `fetch_with_policy` and `CrossRegistryResolver::resolve`
    /// check it directly; `fetch_current_with_policy` does too,
    /// tautologically, since `/current` has no requested id to diverge
    /// from; `fetch_report`/`fetch_report_with_fetcher` check it and
    /// return `ContextIdMismatch` on failure; and `fetch_report_diagnose`
    /// folds it into its `all_top_level_pass` gate, so it only ever
    /// hands back `Some(VerifiedContext)` when `ctx_id_ok` held. All of
    /// these implement RFC-ACDP-0006 §4.1 step 7, so the type invariant
    /// — every `VerifiedContext` was bound to its requested `ctx_id` —
    /// holds unconditionally.
    ///
    /// Returns `Ok(None)` when no receipt is present, `Ok(Some(_))`
    /// with the verified receipt otherwise.
    ///
    /// The receipt cross-check (RFC-ACDP-0010 §8 step 4) relies on
    /// `body.content_hash` being the independently recomputed value.
    /// That is guaranteed by the type invariant — every
    /// `VerifiedContext` is built only after its constructing pipeline
    /// verified the body hash (`Verifier::verify_body_hash` /
    /// `verify_body_signed`), and the fields are private so no caller
    /// can substitute an unverified body — so no re-derivation is
    /// needed here.
    pub async fn verify_receipt(
        &self,
        resolver: &WebResolver,
    ) -> Result<Option<acdp_types::receipt::RegistryReceipt>, AcdpError> {
        let Some(value) = &self.inner.registry_receipt else {
            return Ok(None);
        };
        let fingerprint = acdp_crypto::fingerprint::fingerprint_for_key_id(
            &self.inner.body.signature.key_id,
            &self.inner.body.signature.algorithm,
            resolver,
        )
        .await?;
        let receipt = super::receipt::verify_receipt_value(
            value,
            &self.inner.body.ctx_id,
            &self.inner.body,
            &self.inner.body.content_hash,
            &fingerprint,
            self.inner.body.ctx_id.authority(),
            resolver,
        )
        .await?;
        Ok(Some(receipt))
    }
}

/// Structured diagnostic outcome from [`VerifiedContext::fetch_report`].
///
/// Top-level booleans report the per-stage outcome of the verification
/// pipeline. Per-`DataRef` slots track outcomes for each entry in
/// `body.data_refs`, in declaration order:
///
/// - `data_ref_embedded[i]` — `Ok(decoded_size_bytes)` when the embedded
///   payload's `content_hash` matched; `Err` when it didn't (or the
///   embedded was malformed). Refs without an embedded payload or
///   without a declared `content_hash` produce `Ok(0)`.
/// - `data_ref_external[i]` — `None` when no external fetch was
///   attempted (either no `location` or no `fetcher` was provided);
///   `Some(Ok(bytes_len))` when the fetch + hash succeeded;
///   `Some(Err(_))` on any failure (SSRF rejection, hash mismatch,
///   timeout, …).
///
/// `AcdpError` doesn't implement `Clone`, so the report is move-only.
///
/// `#[non_exhaustive]`: this struct has already gained a field once as a
/// non-optional consequence of a security fix (the RFC-ACDP-0006 §4.1
/// context-identity binding), and it is output-only — constructed solely
/// inside this crate (`verified.rs`) — so downstream loses nothing by
/// being unable to construct it directly. Same rationale as `SsrfReason`
/// in `crates/acdp-safe-http/src/lib.rs` ("future spec revisions may add
/// ranges"): future fields stop being breaking changes for callers that
/// only read this report.
#[derive(Debug)]
#[non_exhaustive]
pub struct VerificationReport {
    /// `content_hash` recomputed from the body matches the declared one.
    pub body_hash_ok: bool,
    /// The producer signature verified against the resolved DID key.
    pub signature_ok: bool,
    /// `validate_body` passed (or was disabled by policy).
    pub schema_ok: bool,
    /// Per-`DataRef` embedded-hash outcome, in `body.data_refs` order.
    pub data_ref_embedded: Vec<Result<usize, AcdpError>>,
    /// Per-`DataRef` external-fetch outcome, in `body.data_refs` order.
    /// `None` indicates "not attempted" (no fetcher provided or no
    /// `location` to fetch from).
    pub data_ref_external: Vec<Option<Result<usize, AcdpError>>>,
    /// The served body's `ctx_id` equals the one requested
    /// (RFC-ACDP-0006 §4.1 step 7, NORMATIVE — "Bind the resolved
    /// identity"). `false` means the registry served a different,
    /// validly-signed body under the requested id (context
    /// substitution); see `VerifiedContext::verify_retrieved`'s doc for
    /// the full rationale. This flag gates whether
    /// [`VerifiedContext::fetch_report_diagnose`] hands back a
    /// `Some(VerifiedContext)` — appended last so any positional
    /// construction fails loudly rather than silently binding the wrong
    /// field.
    pub ctx_id_ok: bool,
    /// The real P3-P6 verdict from `verify_retrieved`'s authorization
    /// phases (receipt, revocation, signature/historical, unknown-status),
    /// when they ran and all passed. `None` means either "not reached"
    /// (a top-level probe — schema, body hash, signature, ctx_id — failed
    /// first, so `verify_retrieved` was never invoked) or "the phase ran
    /// and failed" (see [`Self::policy_phase_error`] for which one).
    pub key_status: Option<KeyAuthorization>,
    /// Which of `verify_retrieved`'s policy-governed phases (receipt,
    /// revocation, signature/historical-key, unknown-status) failed, when
    /// one did. `None` when every phase passed, or when `verify_retrieved`
    /// was never invoked because a top-level probe failed first.
    /// `AcdpError` is not `Clone`, so — like `data_ref_embedded` above —
    /// this field is populated by moving the error in, and asserting on it
    /// requires `matches!` rather than `==`/`assert_eq!` (`AcdpError`
    /// derives only `Debug, Error`).
    pub policy_phase_error: Option<AcdpError>,
}

/// Sentinel `DataRefFetcher` used as the type parameter for
/// `fetch_report_inner` when no fetcher is supplied. `fetch` is never
/// actually called — the option is matched out before that — but
/// providing a real impl lets the generic monomorphize cleanly without
/// requiring `fetch_report`'s callers to name a type.
struct NoFetcher;

impl DataRefFetcher for NoFetcher {
    async fn fetch(
        &self,
        _location: &acdp_types::data_ref::Location,
    ) -> Result<Vec<u8>, AcdpError> {
        Err(AcdpError::NotImplemented(
            "NoFetcher should never be called — this is a fetch_report sentinel".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{HistoricalKeyPolicy, ReceiptPolicy, VerificationPolicy};

    /// The RFC-ACDP-0001 §9.2 named constructor preserves exact v0.1.0
    /// semantics: receipts inert, assertionMethod-only keys. It is
    /// deliberately NOT the 0.2 default (which is receipt-aware).
    #[test]
    fn strict_v0_1_0_preserves_v0_1_0_semantics() {
        let strict = VerificationPolicy::strict_v0_1_0();
        assert!(strict.validate_body_schema);
        assert!(strict.allow_unknown_status);
        assert_eq!(strict.receipts, ReceiptPolicy::Ignore);
        assert_eq!(strict.historical_keys, HistoricalKeyPolicy::Reject);
        assert!(
            strict.revocations.known.is_empty(),
            "a 0.1.0-pinned consumer is unaffected by RFC-ACDP-0014"
        );
        assert_ne!(
            strict,
            VerificationPolicy::default(),
            "the 0.2 default is receipt-aware; the v0.1.0 profile is not"
        );
    }

    /// Phase 2 acceptance criterion 6 — the spine lock.
    ///
    /// `verify_retrieved` must be the SOLE reader of the four
    /// authorization-policy fields (`receipts`, `revocations`,
    /// `historical_keys`, `allow_unknown_status`) anywhere in this file.
    /// Every public entry point (the four `fetch*` forms plus the three
    /// report forms) reaches every authorization phase through that one
    /// function, so a future RFC phase added anywhere else — instead of
    /// inside `verify_retrieved` — trips this test instead of silently
    /// reintroducing the exact divergence this phase fixed.
    ///
    /// Implemented as a plain `str` scan (no `regex` — it is not a
    /// dependency of `acdp-client`) over this file's own source, read via
    /// `include_str!`. `verify_retrieved`'s body span is located by
    /// brace-counting from its own opening brace (its signature has no
    /// braces of its own — only angle brackets in the return type — so
    /// the first `{` after the `fn` keyword IS the body's opening brace),
    /// not by hard-coded line numbers, so the check survives any diff.
    /// Lines whose trimmed start is `//` (covers `///` too), and matches
    /// that fall inside a string literal (detected by an odd count of
    /// unescaped `"` before the match on its line — this file's one
    /// in-string occurrence, the `allow_unknown_status=false` error
    /// message, already lives inside `verify_retrieved` regardless), are
    /// excluded.
    ///
    /// The four search patterns are built by runtime concatenation
    /// (`policy.` + each field name) rather than written as contiguous
    /// `"policy.receipts"`-style literals, so this test's own source —
    /// included verbatim via `include_str!` — does not self-match its
    /// own patterns.
    #[test]
    fn verify_retrieved_is_sole_reader_of_authorization_policy_fields() {
        const SRC: &str = include_str!("verified.rs");

        let policy_prefix = "policy.";
        let fields = [
            "receipts",
            "revocations",
            "historical_keys",
            "allow_unknown_status",
        ];
        let patterns: Vec<String> = fields
            .iter()
            .map(|f| format!("{policy_prefix}{f}"))
            .collect();

        // Locate `verify_retrieved`'s body span.
        let fn_start = SRC
            .find("async fn verify_retrieved(")
            .expect("verify_retrieved must exist in verified.rs");
        let body_open = fn_start
            + SRC[fn_start..]
                .find('{')
                .expect("verify_retrieved must have a body");
        let mut depth = 0i32;
        let mut body_close = None;
        for (i, ch) in SRC[body_open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        body_close = Some(body_open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let body_close =
            body_close.expect("verify_retrieved's matching closing brace must be found");
        assert!(
            body_close > body_open,
            "sanity: verify_retrieved's body must be non-empty"
        );

        // Scan the whole file, tracking byte offsets so each match's
        // position can be tested against the body span.
        let mut offset = 0usize;
        let mut checked_any = false;
        for line in SRC.split_inclusive('\n') {
            let trimmed = line.trim_start();
            let is_comment_line = trimmed.starts_with("//");
            if !is_comment_line {
                for pattern in &patterns {
                    let mut search_from = 0usize;
                    while let Some(rel) = line[search_from..].find(pattern.as_str()) {
                        let match_col = search_from + rel;
                        let match_start = offset + match_col;
                        let before = &line[..match_col];
                        let in_string_literal = before.matches('"').count() % 2 == 1;
                        if !in_string_literal {
                            checked_any = true;
                            assert!(
                                match_start >= body_open && match_start < body_close,
                                "found `{pattern}` outside verify_retrieved's body \
                                 (byte offset {match_start}, line: {line:?}) — every \
                                 authorization-policy-field read must live inside \
                                 verify_retrieved, the sole reader"
                            );
                        }
                        search_from = match_col + pattern.len();
                    }
                }
            }
            offset += line.len();
        }
        assert!(
            checked_any,
            "sanity: the scan must find at least one non-comment, non-string-literal \
             match for at least one pattern (verify_retrieved itself reads these \
             fields) — zero hits would mean the patterns are miscomputed, not that \
             the invariant holds"
        );
    }
}
