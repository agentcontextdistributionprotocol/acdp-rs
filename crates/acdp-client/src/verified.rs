//! VerifiedContext: retrieve + verify in one call.

use super::data_ref::{fetch_and_verify_data_ref, DataRefFetcher};
use super::registry::RegistryClient;
use acdp_did::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_types::{body::FullContext, primitives::CtxId};
use acdp_verify::Verifier;
use std::time::Duration;

use super::revocation_verdict::{RevocationAssessment, RevocationVerdict, SourcedRevocation};
use super::transparency::{LogInclusionPolicy, TransparencyVerdicts, WitnessQuorumPolicy};
use super::witness::WitnessQuorumReport;

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
/// The verification profile is **always strict**:
///
/// - Every producer identity must be `did:web` or `did:key` — enforced
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

    /// RFC-ACDP-0001 §5.11 v0.1.0 strict profile, item 1 (NORMATIVE for
    /// `acdp-consumer`): when `body.acdp_version` is absent or `"0.1.0"`,
    /// `body.agent_id` and the DID portion of `signature.key_id` MUST be
    /// `did:web`; any other method fails with `schema_violation`.
    /// Default `true` (and `true` in [`Self::strict_v0_1_0`]).
    ///
    /// `did:key` was introduced in 0.2.0, whose producers MUST emit
    /// `acdp_version`, so a conformant body never trips this. Setting it
    /// `false` is a relaxed mode that is **non-conformant with v0.1.0**
    /// and outside the `acdp-consumer` conformance profile (§5.11).
    pub require_did_web_for_v0_1_0: bool,

    /// Transparency-log inclusion handling (ACDP 0.4, RFC-ACDP-0012 §9).
    /// Default [`LogInclusionPolicy::Ignore`]. The verdict is reported
    /// separately, through [`VerifiedContext::log_inclusion_verdict`] and
    /// [`VerificationReport::log_inclusion_verdict`]. A failure fails
    /// verification only under [`LogInclusionPolicy::Require`] (§9.3).
    pub log_inclusion: LogInclusionPolicy,

    /// Witness-quorum corroboration of the log checkpoint (ACDP 0.4,
    /// RFC-ACDP-0015 §8). Default `None`, which means not evaluated. When
    /// set, the `log_inclusion` checkpoint is verified even under
    /// [`LogInclusionPolicy::Ignore`], because cosignatures can only be
    /// checked against a checkpoint the consumer verified itself.
    pub witness_quorum: Option<WitnessQuorumPolicy>,
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
            require_did_web_for_v0_1_0: true,
            log_inclusion: LogInclusionPolicy::Ignore,
            witness_quorum: None,
        }
    }
}

/// Consumer-held key revocations to enforce during verification
/// (ACDP 0.3, RFC-ACDP-0014 §7).
///
/// [`Self::known`] is **pull-based**: the pipeline does not go looking
/// for those revocations on its own — the caller supplies the
/// **verified** revocations it holds (from
/// [`find_revocations`](crate::revocation::find_revocations),
/// [`find_registry_attested_revocations`](crate::revocation::find_registry_attested_revocations),
/// an out-of-band channel, or its own indefinite cache — the statement
/// is permanent, cache accordingly). [`Self::discover`] (RFC-ACDP-0014
/// §8) is the opt-in complement: when set, `verify_retrieved` itself
/// runs those same two lookups and unions their result with `known`
/// (see [`RevocationDiscovery`]). When `known` is empty, `discover` is
/// `None`, AND no [`crate::RevocationCache`] is attached to the client,
/// the phase is inert and verification behaves exactly as before
/// RFC-ACDP-0014.
///
/// Issue #257 gives `discover`'s own caching a first-class home:
/// [`crate::RevocationCache`], attached to the [`crate::RegistryClient`]
/// passed to `verify_retrieved` via
/// [`crate::RegistryClient::with_revocation_cache`], persists exactly the
/// "own indefinite cache" a caller would otherwise have to hand-roll
/// around `known` — verified revocations discovered on one call are
/// unioned into every later call against the same client, unconditionally
/// and indefinitely, independent of [`RevocationDiscovery::freshness`], and
/// **regardless of whether that later call itself sets `discover`** —
/// attaching a cache is itself the opt-in (MATERIAL-3, fresh-Opus review
/// of Phase 2): a call made with `discover: None` still seeds
/// producer-signed facts from the cache (never registry-attested ones —
/// see below), which is what extends this anti-rollback protection to
/// [`VerifiedContext::fetch`]/[`VerifiedContext::fetch_current`] (LIM-2),
/// the two entry points that can never set `discover` at all. A
/// registry-attested fact, by contrast, is additionally scoped to the
/// vantage that minted it (BLOCKER-1, RFC-ACDP-0014 §6): reading it back
/// through a client talking to a different authority never applies it,
/// even under [`RevocationDiscovery::include_registry_attested`]. See
/// that field's doc and `crate::revocation_cache` for the full model,
/// including the separate, opt-in, TTL-bounded marker that can additionally
/// skip a repeat lookup.
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
/// This applies uniformly to every entry point that *accepts* a
/// [`VerificationPolicy`] — [`VerifiedContext::fetch_with_policy`],
/// [`VerifiedContext::fetch_current_with_policy`], and the
/// `fetch_report*` family (five entry points in total) — since they all
/// reach this phase through the same internal pipeline. On
/// [`VerifiedContext::fetch_report_diagnose`] specifically, "fails
/// closed" means the returned [`VerifiedContext`] handle is withheld
/// and the cause is recorded in `VerificationReport::policy_phase_error`,
/// rather than the call returning `Err` — that method never
/// short-circuits on a policy-phase failure by design.
///
/// "Uniformly" has one remaining carve-out, structural rather than a
/// policy choice: [`VerifiedContext::fetch`] and
/// [`VerifiedContext::fetch_current`] hardcode
/// [`VerificationPolicy::default`] and so can never carry a non-empty
/// `known` or a `discover`; callers wanting either use the
/// `_with_policy` forms instead. This is recorded as a known limitation
/// (issue #248 LIM-2) rather than silently true. Phase 2's cache still
/// extends anti-rollback protection to these two entry points — see
/// [`Self::discover`]'s doc — but they can never *configure* discovery
/// themselves.
///
/// **Issue #260 closed the sibling limitation, LIM-1.**
/// [`crate::CrossRegistryResolver::with_revocation_policy`] now injects a
/// [`RevocationPolicy`] into every node a cross-registry walk verifies,
/// and [`crate::CrossRegistryResolver::with_revocation_cache`] shares one
/// [`crate::RevocationCache`] across the walk (walk-scoped by default —
/// see that method's doc). The resolver derives `receipts` itself, per
/// node, from that node's advertised capabilities, so it takes a
/// [`RevocationPolicy`], never a caller-supplied [`VerificationPolicy`] —
/// see `CrossRegistryResolver::with_revocation_policy`'s doc for why.
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
///
/// `#[non_exhaustive]`: this struct grew a second field
/// ([`Self::discover`], RFC-ACDP-0014 §8 auto-discovery) after having
/// shipped with exactly one, and a caller constructing this with a
/// bare struct literal would otherwise break on every future field the
/// same way. Construct with [`Self::new`] (equivalent to today's
/// `RevocationPolicy { known }`) and, when opting into discovery,
/// [`Self::with_discovery`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
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

    /// RFC-ACDP-0014 §8 auto-discovery configuration. `None` (the
    /// default) is exactly today's behavior: the caller supplies
    /// everything via [`Self::known`] and this phase does no network
    /// I/O of its own. `Some` opts into running
    /// [`find_revocations`](crate::revocation::find_revocations) and,
    /// depending on [`RevocationDiscovery::include_registry_attested`],
    /// [`find_registry_attested_revocations`](crate::revocation::find_registry_attested_revocations)
    /// as part of verification, merging their results with
    /// [`Self::known`].
    pub discover: Option<RevocationDiscovery>,

    /// Non-strict placement mode (RFC-ACDP-0014 §7 step 1, 0.5.0).
    /// Under the strict profile (the default, `false`), a receipt
    /// verified under a *historical* receipt key
    /// ([`ReceiptKeyStatus::Historical`](acdp_types::receipt::ReceiptKeyStatus))
    /// cannot place a revoked-key context before its compromise
    /// boundary: the context is unplaceable (§7 step 4) and fails
    /// closed. `true` also accepts a historical receipt key as a
    /// placement — a deployment choice that is **non-conformant with the
    /// strict profile**, reported per RFC-ACDP-0001 §5.11 like the step 4
    /// pragmatic mode. Set it with
    /// [`Self::accept_historical_receipt_key_for_pre_t`]. Ordinary
    /// rotation with no revocation is unaffected either way.
    pub accept_historical_receipt_key_for_pre_t: bool,
}

impl RevocationPolicy {
    /// Construct a policy from a caller-supplied revocation set with
    /// discovery left off (`discover: None`) — the same shape as the
    /// bare `RevocationPolicy { known }` literal this struct's
    /// `#[non_exhaustive]` retires.
    #[must_use]
    pub fn new(known: Vec<acdp_types::revocation::KeyRevocation>) -> Self {
        Self {
            known,
            discover: None,
            accept_historical_receipt_key_for_pre_t: false,
        }
    }

    /// Opt into the non-strict placement mode: a receipt verified under
    /// a historical receipt key may place a revoked-key context before
    /// its compromise boundary. See
    /// [`Self::accept_historical_receipt_key_for_pre_t`](field@Self::accept_historical_receipt_key_for_pre_t).
    #[must_use]
    pub fn accept_historical_receipt_key_for_pre_t(mut self) -> Self {
        self.accept_historical_receipt_key_for_pre_t = true;
        self
    }

    /// Opt into RFC-ACDP-0014 §8 auto-discovery on top of any
    /// caller-supplied [`Self::known`] revocations. See
    /// [`RevocationDiscovery`] for cost and the required explicit
    /// trust-class choice.
    #[must_use]
    pub fn with_discovery(mut self, discovery: RevocationDiscovery) -> Self {
        self.discover = Some(discovery);
        self
    }
}

/// RFC-ACDP-0014 §8 revocation auto-discovery configuration.
///
/// When set on [`RevocationPolicy::discover`], this instructs
/// verification to look up revocations itself — via
/// [`find_revocations`](crate::revocation::find_revocations) and,
/// when [`Self::include_registry_attested`] is `true`, additionally
/// [`find_registry_attested_revocations`](crate::revocation::find_registry_attested_revocations)
/// — instead of relying solely on [`RevocationPolicy::known`].
///
/// # Cost
///
/// Discovery is expensive, and every request it issues is **serial**.
/// `MAX_SEARCH_PAGES = 10` (`crate::revocation`) bounds search
/// round-trips *per `(type_form, status)` pair*, and there are **6**
/// such pairs (2 type forms × 3 statuses) — so up to 60 search
/// requests, each of which can name up to 100 per-candidate context
/// retrieves (`GET /contexts/{id}`, capped at 1 MB apiece), for up to
/// **6,000 + 60 + 100 = 6,160 requests / ~6.1 GB** in the worst case
/// for *one* of the two discovery functions. The retrieve fan-out is
/// **not** bounded by `MAX_LINEAGE_WALKS = 100` — that cap is only
/// checked *after* the retrieves have already gone out. With
/// [`Self::include_registry_attested`] set, both functions run:
/// **≈12,321 requests / ~12.2 GB** worst case for the pair (the extra
/// 1 is the unconditional `client.capabilities()` fetch
/// `find_registry_attested_revocations` makes).
///
/// [`Self::total_timeout`] is an **availability bound, not a bytes or
/// memory bound**: it stops verification from hanging forever against
/// a slow or hostile registry, but a hostile registry on a fast link
/// can still serve gigabytes of legitimate-looking traffic inside the
/// window — the 1 MB cap applies per request, not in aggregate, and
/// verified revocations accumulate in a `Vec` for the call's duration.
/// [`Self::max_requests`] and [`Self::max_bytes`] (issue #258) close
/// that gap: set either (or both) to bound the two lookups **combined**
/// — enabling [`Self::include_registry_attested`] does not double the
/// ceiling — checked **before** each request is issued, so a would-be
/// request that would exceed the budget is never sent. Exhaustion
/// raises `AcdpError::RevocationDiscoveryBudgetExceeded` through the
/// same [`Self::on_failure`] path as `AcdpError::SearchTruncated` — it
/// is permanent for the same request shape and is never transient.
/// Both knobs bound **registry** traffic only: DID-document fetches
/// issued via `WebResolver` are not counted. [`Self::max_bytes`] counts
/// only **successfully-parsed response bodies** — an error-envelope
/// read on a non-success response is not charged. [`Self::max_requests`]
/// has no such exemption: the request slot is reserved *before* the
/// request is issued, so a 503, a parse failure, or a `PayloadTooLarge`
/// still consumes it. Leaving both `None` (as both
/// [`Self::producer_signed_only`] and [`Self::all_trust_classes`] do)
/// preserves pre-#258 behavior exactly: unbounded requests and bytes,
/// bounded only by [`Self::total_timeout`].
///
/// Issue #257 adds an opt-in cache ([`crate::RevocationCache`], attached
/// to the [`crate::RegistryClient`] passed in via
/// [`crate::RegistryClient::with_revocation_cache`]) — but attaching one
/// does NOT, by itself, turn "re-discovers from scratch" into "sometimes
/// skips discovery." It is two independent things: verified revocations
/// ("facts") are always unioned into classification, indefinitely,
/// regardless of [`Self::freshness`] — a caller verifying many contexts
/// against the same producer benefits from this immediately, with zero
/// extra configuration, simply by attaching a cache and reusing the
/// client. Whether a repeat lookup is skipped entirely (saving requests)
/// is governed separately by [`Self::freshness`], which defaults to
/// 300 s (RFC-ACDP-0014 §8's RECOMMENDED bound on a cached negative). See [`Self::freshness`]'s own doc and
/// `crate::revocation_cache` for the full model. Without a cache attached
/// at all, this crate behaves exactly as before #257: every call
/// re-discovers from scratch, budgeted or not. A caller that does not
/// want to manage a `RevocationCache` can still discover once itself and
/// pass the results via [`RevocationPolicy::known`] instead of setting
/// `discover` on every call — the same hoisting guidance
/// `crate::revocation`'s `find_registry_attested_revocations` doc already
/// gives callers of that function directly (see its "Cost note for
/// callers verifying many contexts").
///
/// # Reentrancy
///
/// Discovery calls back into verification, and that reentrancy has two
/// consequences worth stating explicitly rather than leaving implicit:
///
/// 1. Each candidate body [`find_revocations`](crate::revocation::find_revocations)
///    turns up is verified via `Verifier::new(resolver).verify_body` —
///    **not** `verify_retrieved` — so discovered revocation bodies are
///    themselves checked *without* revocation checking of their own.
///    That is defensible under RFC-ACDP-0014 §5 step 1's "currently
///    authorized key," but it is an assumption this type is making on
///    the caller's behalf, not an accident.
/// 2. Verifying a `key-revocation` context now *also* triggers
///    discovery against the same producer, so the revocation-fetch path
///    itself becomes fragile under [`DiscoveryFailurePolicy::FailClosed`]:
///    a producer whose revocation search is briefly unreachable can no
///    longer be verified as revoked, either.
///
/// # No `Default`
///
/// This type deliberately has **no [`Default`] impl** — construct it
/// via [`Self::producer_signed_only`] or [`Self::all_trust_classes`].
/// RFC-ACDP-0014 §6's "lost-everything" fallback means a producer that
/// has lost every key it could sign a revocation with can *only* be
/// revoked registry-attested — so the catastrophic case is exactly the
/// one a silently-defaulted-off trust class would skip. A quiet
/// `Default::default()` that leaves `include_registry_attested: false`
/// would make that skip invisible at every call site; forcing a named
/// constructor puts the choice at the type level instead, where a
/// reviewer (and `git grep`) can see it. Callers protecting against
/// key loss, or otherwise unwilling to assume a producer always
/// retains signing capacity, MUST use [`Self::all_trust_classes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RevocationDiscovery {
    /// Whether to also run
    /// [`find_registry_attested_revocations`](crate::revocation::find_registry_attested_revocations)
    /// (the §6 registry-attested trust class), in addition to the
    /// producer-signed search every discovery configuration runs.
    /// Requires the registry to serve `/.well-known/acdp.json`; under
    /// [`DiscoveryFailurePolicy::FailClosed`] a registry that serves no
    /// capabilities document fails verification when this is `true`.
    pub include_registry_attested: bool,
    /// What to do when discovery itself fails (a transient transport
    /// error from either search, or the search-safety-cap error
    /// `AcdpError::SearchTruncated`). Default [`DiscoveryFailurePolicy::FailClosed`].
    ///
    /// **`SearchTruncated` and a transport error (e.g. a 503) are NOT
    /// equivalent, even though both take this same `on_failure` path.**
    /// `SearchTruncated` means "this producer has more revocations than
    /// we will page through" (`MAX_SEARCH_PAGES`) — an
    /// **attacker-inducible security downgrade**, since a hostile
    /// producer or registry can pad the result set specifically to
    /// exhaust the page cap and hide a real revocation from discovery.
    /// A 503 is an ordinary availability blip. **A third case is
    /// attacker-inducible the same way `SearchTruncated` is (issue
    /// #258):** `AcdpError::RevocationDiscoveryBudgetExceeded`, raised
    /// when [`Self::max_requests`] or [`Self::max_bytes`] is exhausted —
    /// a hostile registry that learns a caller's budget can pad
    /// harmless-looking traffic specifically to exhaust it before a
    /// real revocation is found, just as padding the result set exhausts
    /// `MAX_SEARCH_PAGES`. Under [`DiscoveryFailurePolicy::ProceedWithKnown`]
    /// all three are treated the same way (proceed on
    /// [`RevocationPolicy::known`] alone, record the failure) — choose
    /// `ProceedWithKnown` knowing it also waives truncation and budget
    /// exhaustion, not just transient unavailability.
    pub on_failure: DiscoveryFailurePolicy,
    /// Wall-clock budget for the whole discovery step (both searches,
    /// if [`Self::include_registry_attested`] is set). An **availability**
    /// bound only — see the type-level cost section above. Matches this
    /// crate's existing `ResolverOptions::total_timeout` precedent
    /// (`crate::cross_registry`), defaulting to the same 30 s rather
    /// than exceeding it on the core verify path.
    ///
    /// Enforced via [`tokio::time::timeout`], which requires the
    /// executing Tokio runtime to have its **time driver enabled**
    /// (`#[tokio::main]` and `#[tokio::test]` enable it by default;
    /// a hand-built `Builder::new_current_thread()` runtime does
    /// **not** unless `.enable_time()` or `.enable_all()` is called).
    /// Calling `verify_retrieved` with `discover: Some(..)` from a
    /// runtime without the time driver **panics** — it does not
    /// return `Err` — the same requirement `ResolverOptions::total_timeout`
    /// (`crate::cross_registry`) already carries on its opt-in walk,
    /// but here it sits on the core verify path whenever discovery is
    /// configured, not just on an explicit cross-registry walk.
    pub total_timeout: Duration,
    /// Issue #258: cap on the total number of registry requests the
    /// discovery step may issue, **combined across both lookups** (the
    /// producer-signed search always, plus the registry-attested search
    /// when [`Self::include_registry_attested`] is set) — not a ceiling
    /// per lookup, so turning on the second trust class does not double
    /// the allowance. `None` (the default from both named constructors)
    /// is unbounded, matching every version before #258. Checked
    /// **before** each request is issued (`RegistryClient::capabilities`,
    /// `::retrieve`, `::lineage`, `::search`); exceeding it raises
    /// `AcdpError::RevocationDiscoveryBudgetExceeded` through
    /// [`Self::on_failure`], the same path `AcdpError::SearchTruncated`
    /// already takes. Counts registry requests only — DID-document
    /// fetches via `WebResolver` are not counted.
    pub max_requests: Option<std::num::NonZeroUsize>,
    /// Issue #258: cap on the cumulative bytes of *successfully-parsed*
    /// response bodies the discovery step may read, **combined across
    /// both lookups**, same combination rule as [`Self::max_requests`].
    /// `None` (the default from both named constructors) is unbounded,
    /// matching every version before #258. Checked **before** each
    /// request is issued, using the running total from requests that
    /// already completed — the size of an in-flight request cannot be
    /// known (and therefore reserved) in advance, so **up to two**
    /// requests can push the total past `max_bytes` before the next
    /// check observes the overrun: the two trust-class lookups run
    /// concurrently under `tokio::try_join!`, and both can pass a
    /// not-yet-updated check before either's response is recorded — see
    /// [`Self::max_requests`]'s doc for the same race on the request
    /// count, where it is closed by an atomic reservation; there is no
    /// equivalent reservation for bytes, since a response's size is not
    /// known until after it is read. Counts a non-success response's
    /// error-envelope read *not at all* — only bytes read on the
    /// success path are charged.
    ///
    /// `Some(0)` is representable (unlike [`Self::max_requests`], which
    /// is guarded by `NonZeroUsize`) and is not special-cased: it trips
    /// the `>=` check on the very first request of either lookup,
    /// before that request is ever issued, so discovery fails
    /// immediately with zero registry traffic. This is a deliberate
    /// consequence of keeping this field a plain `u64` (matching the
    /// wave plan's chosen types) rather than a reason to reach for
    /// `NonZeroU64`.
    pub max_bytes: Option<u64>,
    /// Issue #257: how long a discovery-freshness marker stays valid on
    /// a [`crate::RevocationCache`] attached to the [`crate::RegistryClient`]
    /// passed to `verify_retrieved` (via
    /// [`crate::RegistryClient::with_revocation_cache`]). A marker records
    /// "vantage V completed a full, untruncated discovery for this
    /// producer/trust-class at time T"; while one is within `freshness` of
    /// T, that lookup is skipped entirely (zero registry requests) rather
    /// than merely supplemented.
    ///
    /// Default [`RECOMMENDED_NEGATIVE_FRESHNESS`](crate::RECOMMENDED_NEGATIVE_FRESHNESS)
    /// (300 s) from both named constructors — RFC-ACDP-0014 §8 "Caching"
    /// (0.5.0) RECOMMENDS bounding a cached negative this way (it was
    /// `Duration::ZERO` before 0.15.0). A cached absence is per vantage,
    /// per trust class, and minted only by a complete, untruncated lookup;
    /// an `unknown` outcome is never cached. A verdict answered from one
    /// reports when the absence was observed
    /// ([`RevocationVerdict::NotRevoked`]'s `observed_at`). Set
    /// `Duration::ZERO` to never suppress a lookup. No cache attached makes
    /// this field inert regardless of its value.
    ///
    /// Distinct from — and orthogonal to — caching verified revocations
    /// themselves ("facts"), which a [`crate::RevocationCache`] does
    /// **unconditionally** and **indefinitely** whenever one is attached,
    /// independent of this field: facts are always unioned into
    /// classification (never gated behind `freshness`), because a
    /// revocation is monotone (more revocations ⇒ an earlier effective
    /// boundary ⇒ strictly more fail-closed verdicts), so seeding from
    /// them can only tighten a verdict, never loosen one. `freshness`
    /// governs only whether a lookup that would otherwise re-confirm "no
    /// NEW revocation" is skipped. See `crate::revocation_cache` for the
    /// full two-object model.
    ///
    /// That "unconditionally" is exact for a producer-signed fact (§8:
    /// self-contained, applies at any vantage) but is scoped for a
    /// registry-attested one (§6): the cache additionally filters those to
    /// the vantage that minted them, so attaching one cache to clients for
    /// two different registries does not let registry A's attestation
    /// apply to a context served by registry B.
    ///
    /// A recommended ceiling, not enforced: RFC-ACDP-0006 §4.2 caps
    /// `WebResolver`'s own DID-document cache TTL at 3600 s, and that is a
    /// reasonable order-of-magnitude anchor for this field too — this
    /// crate already accepts bounded key-material staleness at that
    /// order. Left unenforced deliberately: a hard cap on a knob whose
    /// safe default is `ZERO` would add a failure mode without adding
    /// safety.
    pub freshness: Duration,
}

impl RevocationDiscovery {
    /// Discover producer-signed revocations only
    /// (`include_registry_attested: false`). Cheapest of the two
    /// constructors, and the default choice for callers that are not
    /// specifically defending against a producer that has lost every
    /// signing key — see the "No `Default`" section above for who must
    /// NOT stop here.
    #[must_use]
    pub fn producer_signed_only() -> Self {
        Self {
            include_registry_attested: false,
            on_failure: DiscoveryFailurePolicy::FailClosed,
            total_timeout: Duration::from_secs(30),
            max_requests: None,
            max_bytes: None,
            freshness: super::revocation_verdict::RECOMMENDED_NEGATIVE_FRESHNESS,
        }
    }

    /// Discover both trust classes: producer-signed AND registry-attested
    /// (`include_registry_attested: true`). Required to catch RFC-ACDP-0014
    /// §6's "lost-everything" fallback, where a producer with no signing
    /// key left can only be revoked registry-attested. Requires the
    /// registry to serve a capabilities document.
    #[must_use]
    pub fn all_trust_classes() -> Self {
        Self {
            include_registry_attested: true,
            on_failure: DiscoveryFailurePolicy::FailClosed,
            total_timeout: Duration::from_secs(30),
            max_requests: None,
            max_bytes: None,
            freshness: super::revocation_verdict::RECOMMENDED_NEGATIVE_FRESHNESS,
        }
    }
}

/// What to do when RFC-ACDP-0014 §8 auto-discovery itself fails (a
/// transient search/lookup error, or the discovery search functions'
/// own safety-cap error).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DiscoveryFailurePolicy {
    /// Treat an `unknown` discovery outcome as a verification failure
    /// (`AcdpError::RevocationUnknown`). Default — matches this
    /// crate's existing bias (§7's own lineage-walk and
    /// verification-failure paths already fail closed; see
    /// `crate::revocation`'s doc for the parallel reasoning) that an
    /// authorization phase which could not run is not the same thing
    /// as one that ran and found nothing.
    #[default]
    FailClosed,
    /// Proceed using only [`RevocationPolicy::known`] and cached facts when
    /// discovery is `unknown`; the verified context then carries
    /// [`RevocationVerdict::Unknown`] (never not-revoked) and the
    /// `AcdpError::RevocationUnknown` in
    /// [`VerifiedContext::revocation_discovery_failure`].
    /// Use only when availability matters more than catching a
    /// revocation that discovery would otherwise have found.
    ProceedWithKnown,
}

/// What RFC-ACDP-0014 §8 auto-discovery actually did, distinguishing
/// "this trust class was not queried" from "it was queried and found
/// nothing" — the same distinction
/// [`RevocationDiscovery`]'s no-`Default` design protects at the
/// config level, carried through to the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiscoveryOutcome {
    /// Count of producer-signed revocations discovery found.
    pub producer_signed: usize,
    /// Count of registry-attested revocations discovery found, or
    /// `None` if [`RevocationDiscovery::include_registry_attested`]
    /// was `false` and that trust class was never queried.
    pub registry_attested: Option<usize>,
}

/// How to treat the optional `registry_receipt` on retrieval
/// (RFC-ACDP-0010).
///
/// `#[non_exhaustive]` since 0.15.0 ([`Self::VerifyAndReport`] was added).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
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
    /// Verify the receipt when one is present and report its verdict
    /// separately from the body verdict (RFC-ACDP-0010 §8, 0.5.0 — the
    /// `acdp-consumer` "receipt verdict reported separately" rule). A
    /// failing receipt does not fail retrieval: it is recorded in
    /// [`VerifiedContext::receipt_verdict`] /
    /// [`VerificationReport::receipt_verdict`] and then treated exactly
    /// as an absent one by every rule that consumes receipt-attested
    /// facts — the RFC-ACDP-0010 §10 historical-key rule does not apply,
    /// an RFC-ACDP-0014 §7 revoked-key context is unplaceable (fails
    /// closed), and `lineage_id` is reported
    /// [`LineageBinding::Unbound`](acdp_verify::LineageBinding). The
    /// body is never presented as receipt-attested
    /// ([`VerifiedContext::verified_receipt`] is `None`).
    ///
    /// On `/current` the same applies to the lineage-head receipt under
    /// [`LineageHeadPolicy::receipts`]
    /// ([`VerifiedContext::head_receipt_verdict`]).
    VerifyAndReport,
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

/// RFC-ACDP-0001 §5.11 v0.1.0 strict profile item 1: a body with
/// `acdp_version` absent or `"0.1.0"` MUST be signed by a `did:web`
/// producer (`agent_id` and the DID portion of `signature.key_id`).
fn require_did_web_for_v0_1_0(body: &acdp_types::body::Body) -> Result<(), AcdpError> {
    if !matches!(body.acdp_version.as_deref(), None | Some("0.1.0")) {
        return Ok(());
    }
    let key_did = body
        .signature
        .key_id
        .split_once('#')
        .map_or(body.signature.key_id.as_str(), |(d, _)| d);
    for (field, did) in [
        ("agent_id", body.agent_id.as_str()),
        ("signature.key_id", key_did),
    ] {
        if !did.starts_with("did:web:") {
            return Err(AcdpError::SchemaViolation(format!(
                "v0.1.0 context (acdp_version {}) requires a did:web {field}; got '{did}' \
                 (RFC-ACDP-0001 §5.11 strict profile)",
                body.acdp_version.as_deref().unwrap_or("absent"),
            )));
        }
    }
    Ok(())
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
            require_did_web_for_v0_1_0: true,
            // Likewise RFC-ACDP-0012/0015 (0.4.0): transparency inert.
            log_inclusion: LogInclusionPolicy::Ignore,
            witness_quorum: None,
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
    /// RFC-ACDP-0010 §8 step 1 status of the key that signed
    /// `verified_receipt` (0.5.0). `None` exactly when `verified_receipt`
    /// is `None`.
    receipt_key_status: Option<acdp_types::receipt::ReceiptKeyStatus>,
    /// The receipt verdict, reported separately from the body verdict
    /// (RFC-ACDP-0010 §8, 0.5.0). `None` when no receipt was evaluated.
    receipt_verdict: Option<Result<(), AcdpError>>,
    /// How `body.lineage_id` is bound (RFC-ACDP-0004 §2.1, 0.5.0).
    lineage_binding: acdp_verify::LineageBinding,
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
    /// The lineage-head receipt verdict (RFC-ACDP-0011 §7), reported
    /// separately: `None` when none was evaluated.
    head_receipt_verdict: Option<Result<(), AcdpError>>,
    /// RFC-ACDP-0014 §8 auto-discovery failure, when
    /// `policy.revocations.discover` was `Some`, discovery failed, and
    /// [`DiscoveryFailurePolicy::ProceedWithKnown`] let verification
    /// proceed on [`RevocationPolicy::known`] alone anyway. `None` when
    /// discovery was off, succeeded, or was never attempted because
    /// [`DiscoveryFailurePolicy::FailClosed`] turned the failure into
    /// this call's `Err` instead (so no `VerifiedContext` was ever
    /// constructed to carry it). Exposed so `ProceedWithKnown` is never
    /// silent on the plain `fetch*` paths — see
    /// [`Self::revocation_discovery_failure`].
    revocation_discovery_failure: Option<AcdpError>,
    /// The typed revocation verdict (RFC-ACDP-0014 §7/§8, 0.5.0).
    revocation_verdict: RevocationVerdict,
    /// Verified revocations outside the producer's scope — hints only.
    revocation_hints: Vec<SourcedRevocation>,
    /// RFC-ACDP-0012 §9 / RFC-ACDP-0015 §8 verdicts.
    transparency: TransparencyVerdicts,
}

/// `verify_retrieved`'s verdicts — private and free to shape.
struct Retrieved {
    key_status: KeyAuthorization,
    verified_receipt: Option<acdp_types::receipt::RegistryReceipt>,
    receipt_key_status: Option<acdp_types::receipt::ReceiptKeyStatus>,
    receipt_verdict: Option<Result<(), AcdpError>>,
    lineage_binding: acdp_verify::LineageBinding,
    revocation: RevocationAssessment,
    transparency: TransparencyVerdicts,
}

type VerifyRetrievedResult = Result<Retrieved, AcdpError>;

impl Retrieved {
    /// Copy the verdicts onto a report.
    fn record(&self, report: &mut VerificationReport) {
        report.key_status = Some(self.key_status);
        report.receipt_key_status = self.receipt_key_status;
        report.receipt_verdict = self.receipt_verdict.clone();
        report.lineage_binding = Some(self.lineage_binding);
        report.revocation_discovery = self.revocation.discovery.clone();
        report.revocation_verdict = Some(self.revocation.verdict.clone());
        report.revocation_hints = self.revocation.hints.clone();
        report.log_inclusion_verdict = self.transparency.log_verdict();
        report.witness_quorum = self.transparency.witness.clone();
    }

    fn into_context(self, inner: FullContext) -> VerifiedContext {
        let RevocationAssessment {
            verdict,
            hints,
            discovery,
            ..
        } = self.revocation;
        let revocation_discovery_failure = match discovery {
            Some(Err(e)) => Some(e),
            _ => None,
        };
        VerifiedContext {
            inner,
            key_status: self.key_status,
            verified_receipt: self.verified_receipt,
            receipt_key_status: self.receipt_key_status,
            receipt_verdict: self.receipt_verdict,
            lineage_binding: self.lineage_binding,
            verified_head_receipt: None,
            head_receipt_stale: None,
            head_receipt_verdict: None,
            revocation_discovery_failure,
            revocation_verdict: verdict,
            revocation_hints: hints,
            transparency: self.transparency,
        }
    }
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
        let retrieved = Self::verify_retrieved(client, resolver, &ctx, ctx_id, policy).await?;
        Ok(retrieved.into_context(ctx))
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
        let retrieved =
            Self::verify_retrieved(client, resolver, &ctx, &served_ctx_id, policy).await?;

        // ── Lineage-head receipt phase (RFC-ACDP-0011) ──────────────
        let head_policy = policy.lineage_head.receipts;
        let head = match (head_policy, &ctx.lineage_head_receipt) {
            (ReceiptPolicy::Ignore, _)
            | (ReceiptPolicy::VerifyIfPresent | ReceiptPolicy::VerifyAndReport, None) => None,
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
                let verdict = super::receipt::verify_lineage_head_receipt_value(
                    value,
                    lineage_id,
                    &served_ctx_id,
                    ctx.body.version,
                    &ctx.registry_state.status,
                    true, // /current always serves the attested head
                    &serving_authority,
                    &caps.registry_did,
                    chrono::Duration::seconds(policy.lineage_head.max_clock_skew_seconds as i64),
                    resolver,
                )
                .await;
                match verdict {
                    Ok(receipt) => Some(Ok(receipt)),
                    Err(e) if head_policy == ReceiptPolicy::VerifyAndReport => Some(Err(e)),
                    Err(e) => return Err(e),
                }
            }
        };
        let (verified_head_receipt, head_receipt_verdict) = match head {
            None => (None, None),
            Some(Ok(receipt)) => (Some(receipt), Some(Ok(()))),
            Some(Err(e)) => (None, Some(Err(e))),
        };
        let head_receipt_stale = verified_head_receipt.as_ref().and_then(
            |receipt: &acdp_types::receipt::LineageHeadReceipt| {
                policy.lineage_head.max_age_seconds.map(|max| {
                    receipt.age_at(chrono::Utc::now()) > chrono::Duration::seconds(max as i64)
                })
            },
        );

        let mut verified = retrieved.into_context(ctx);
        verified.verified_head_receipt = verified_head_receipt;
        verified.head_receipt_stale = head_receipt_stale;
        verified.head_receipt_verdict = head_receipt_verdict;
        Ok(verified)
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
    ) -> VerifyRetrievedResult {
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

        // Registry-assigned lineage/origin binding — RFC-ACDP-0004 §2.1
        // (0.5.0): `lineage_id` and `origin_registry` are outside
        // `content_hash`/signature coverage like `ctx_id`, so a first
        // version's derivation and the origin authority are checked here,
        // offline, before any crypto or network work.
        acdp_verify::verify_registry_assigned_bindings(&ctx.body)?;

        if policy.validate_body_schema {
            acdp_validation::validate_body(&ctx.body)?;
        }
        if policy.require_did_web_for_v0_1_0 {
            require_did_web_for_v0_1_0(&ctx.body)?;
        }

        // Hash recomputation first: from here on `ctx.body.content_hash`
        // IS the independently recomputed value, which the receipt
        // cross-check below relies on.
        // One DID-freshness scope for every lookup this verification makes
        // (RFC-ACDP-0001 §5.11 "Caching"): a document fetched at or after
        // `since` is fresh, so a forced re-fetch done for the receipt key
        // also serves the signature phase.
        let since = std::time::Instant::now();
        let verifier = Verifier::new(resolver).fresh_since(since);
        verifier.verify_context_hash(ctx)?;

        // ── Receipt phase (RFC-ACDP-0010) ───────────────────────────
        // Verified BEFORE the signature phase because the historical-
        // key path is gated on a verified receipt.
        let serving_authority = client
            .authority()
            .unwrap_or_else(|| expected_ctx_id.authority().to_string());
        let receipt_outcome = match (policy.receipts, &ctx.registry_receipt) {
            (ReceiptPolicy::Ignore, _)
            | (ReceiptPolicy::VerifyIfPresent | ReceiptPolicy::VerifyAndReport, None) => None,
            (ReceiptPolicy::Require, None) => {
                return Err(AcdpError::InvalidReceipt(
                    "policy requires a registry receipt but the response carries none \
                     (registry without the acdp-registry-receipts profile, or a \
                     pre-receipts context)"
                        .into(),
                ));
            }
            (_, Some(value)) => {
                let fingerprint = acdp_crypto::fingerprint::fingerprint_for_key_id_since(
                    &ctx.body.signature.key_id,
                    &ctx.body.signature.algorithm,
                    resolver,
                    since,
                )
                .await?;
                let verdict = super::receipt::verify_receipt_value_with_status_since(
                    value,
                    expected_ctx_id,
                    &ctx.body,
                    &ctx.body.content_hash,
                    &fingerprint,
                    &serving_authority,
                    resolver,
                    since,
                )
                .await;
                match verdict {
                    Ok(placed) => Some(Ok(placed)),
                    // RFC-ACDP-0010 §8 (0.5.0): reported separately, then
                    // treated exactly as an absent receipt below.
                    Err(e) if policy.receipts == ReceiptPolicy::VerifyAndReport => Some(Err(e)),
                    Err(e) => return Err(e),
                }
            }
        };
        let (verified_receipt, receipt_key_status, receipt_verdict) = match receipt_outcome {
            None => (None, None, None),
            Some(Ok((receipt, status))) => (Some(receipt), Some(status), Some(Ok(()))),
            Some(Err(e)) => (None, None, Some(Err(e))),
        };

        // ── Revocation phase (RFC-ACDP-0014 §7/§8) ──────────────────
        // `crate::revocation_verdict` gathers `known` + cached facts +
        // (when configured) §8 discovery, scopes them to this producer
        // (0.5.0 "Producer scope"), and decides the verdict. Cached facts
        // are read before discovery runs, so they survive any failure an
        // attacker can induce on this call (anti-rollback). Runs after the
        // receipt phase because §7 step 1 accepts ONLY a receipt-attested
        // publish time — and under the strict profile only one from a
        // *current* receipt key. Discovered revocation bodies are verified
        // with `Verifier::verify_body`, never `verify_retrieved`, so this
        // does not recurse.
        //
        // Discovery puts a Tokio time-driver requirement on this path
        // (`total_timeout`), gated behind `discover: Some`.
        let gathered = super::revocation_verdict::gather(
            client,
            resolver,
            &ctx.body.agent_id,
            &policy.revocations,
        )
        .await;
        let fingerprint = if gathered.has_in_scope() {
            Some(
                acdp_crypto::fingerprint::fingerprint_for_key_id_since(
                    &ctx.body.signature.key_id,
                    &ctx.body.signature.algorithm,
                    resolver,
                    since,
                )
                .await?,
            )
        } else {
            None
        };
        let revocation = super::revocation_verdict::decide(
            gathered,
            fingerprint.as_deref(),
            verified_receipt
                .as_ref()
                .zip(receipt_key_status)
                .map(|(r, status)| (r.created_at, status)),
            policy.revocations.accept_historical_receipt_key_for_pre_t,
        )
        .enforce()?;

        // ── Signature phase ──────────────────────────────────────────
        // Standard path enforces assertionMethod membership. A
        // KeyNotAuthorized failure falls back to the historical path
        // only under AcceptWithReceipt AND a verified receipt — the
        // receipt's key_fingerprint (already cross-checked against this
        // exact key above) is what attests publish-time authorization.
        let key_status = match revocation.pre_compromise() {
            // Pre-compromise (§7 step 2): the signature is verified
            // under the RFC-ACDP-0010 §10 historical rule — the key may
            // legitimately have left assertionMethod (and SHOULD, §9),
            // and even a key still in assertionMethod MUST NOT be
            // reported as fully current once revoked. did:key material
            // cannot rotate, so it takes the plain envelope path.
            true => {
                if ctx.body.agent_id.as_str().starts_with("did:key:") {
                    verifier.verify_body_signature(&ctx.body).await?;
                } else {
                    verifier.verify_body_signature_historical(&ctx.body).await?;
                }
                KeyAuthorization::HistoricallyAuthorizedPreCompromise
            }
            false => match verifier.verify_body_signature(&ctx.body).await {
                Ok(()) => KeyAuthorization::CurrentlyAuthorized,
                Err(AcdpError::KeyNotAuthorized(_))
                    if policy.historical_keys == HistoricalKeyPolicy::AcceptWithReceipt
                        && verified_receipt.is_some() =>
                {
                    verifier.verify_body_signature_historical(&ctx.body).await?;
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

        // ── Transparency phase (RFC-ACDP-0012 §9, RFC-ACDP-0015 §8) ──
        // Runs last: the leaf is rebuilt only from material verified
        // above (recomputed content_hash, verified receipt). Its verdicts
        // are independent of the ones above (§9.3), and under the default
        // policies they never fail verification.
        let material = match (&verified_receipt, &ctx.registry_receipt) {
            (Some(receipt), Some(receipt_value)) => Some(super::transparency::LeafMaterial {
                receipt,
                receipt_value,
            }),
            _ => None,
        };
        let transparency = super::transparency::evaluate(
            client,
            ctx,
            material,
            &serving_authority,
            policy.log_inclusion,
            policy.witness_quorum.as_ref(),
            resolver,
        )
        .await?;

        let lineage_binding = acdp_verify::lineage_binding(&ctx.body, verified_receipt.is_some());
        Ok(Retrieved {
            key_status,
            verified_receipt,
            receipt_key_status,
            receipt_verdict,
            lineage_binding,
            revocation,
            transparency,
        })
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
    ///
    /// Stage-classification caveat: `verify_retrieved` (and therefore the
    /// receipt/revocation/signature/historical-key phases it runs) is only
    /// attempted once ALL top-level probes pass, `ctx_id_ok` included — see
    /// `all_top_level_pass` below. So when `ctx_id_ok` is `false`,
    /// `policy_phase_error` stays `None` even if the served body also
    /// carries a receipt that would independently fail its own cross-check
    /// (e.g. a receipt genuinely bound to the *served*, substituted body —
    /// RFC-ACDP-0010 §8 step 3 — rather than the requested one). A caller
    /// classifying a `ctx_id_ok: false` report should not read a `None`
    /// `policy_phase_error` as "the receipt/signature phases passed" — they
    /// were never attempted.
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
            revocation_discovery: None,
            receipt_key_status: None,
            receipt_verdict: None,
            lineage_binding: None,
            revocation_verdict: None,
            revocation_hints: Vec::new(),
            log_inclusion_verdict: None,
            witness_quorum: None,
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
            if let Some(emb) = &dr.embedded {
                if dr.content_hash.is_some() || emb.content_hash.is_some() {
                    let outcome = acdp_validation::verify_embedded_hash(dr).and_then(|()| {
                        acdp_validation::embedded_decoded_bytes(emb).map(|b| b.len())
                    });
                    report.data_ref_embedded.push(outcome);
                } else {
                    report.data_ref_embedded.push(Ok(0));
                }
            } else {
                report.data_ref_embedded.push(Ok(0));
            }
        }

        // Hash + signature recorded independently (FEAT-05).
        let verifier = Verifier::new(resolver);
        report.body_hash_ok = verifier.verify_context_hash(&ctx).is_ok();
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
                Ok(retrieved) => {
                    retrieved.record(&mut report);
                    Some(retrieved.into_context(ctx))
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
            revocation_discovery: None,
            receipt_key_status: None,
            receipt_verdict: None,
            lineage_binding: None,
            revocation_verdict: None,
            revocation_hints: Vec::new(),
            log_inclusion_verdict: None,
            witness_quorum: None,
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
            if let Some(emb) = &dr.embedded {
                if dr.content_hash.is_some() || emb.content_hash.is_some() {
                    let outcome = acdp_validation::verify_embedded_hash(dr).and_then(|()| {
                        acdp_validation::embedded_decoded_bytes(emb).map(|b| b.len())
                    });
                    report.data_ref_embedded.push(outcome);
                } else {
                    report.data_ref_embedded.push(Ok(0));
                }
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
        let retrieved =
            Self::verify_retrieved(client, resolver, &ctx, ctx_id, &policy.derived_for_report())
                .await?;
        report.body_hash_ok = true;
        report.signature_ok = true;
        retrieved.record(&mut report);

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

        Ok((retrieved.into_context(ctx), report))
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

    /// RFC-ACDP-0010 §8 step 1 status of the key that signed the
    /// verified receipt (0.5.0): [`ReceiptKeyStatus::Current`] when it is
    /// in the registry DID document's `assertionMethod`,
    /// [`ReceiptKeyStatus::Historical`] when it is in `verificationMethod`
    /// only. A historical receipt is not a currently-authorized registry
    /// attestation and, under the strict profile, cannot place a
    /// revoked-key context before its boundary. `None` exactly when
    /// [`Self::verified_receipt`] is `None`.
    ///
    /// [`ReceiptKeyStatus::Current`]: acdp_types::receipt::ReceiptKeyStatus::Current
    /// [`ReceiptKeyStatus::Historical`]: acdp_types::receipt::ReceiptKeyStatus::Historical
    pub fn receipt_key_status(&self) -> Option<acdp_types::receipt::ReceiptKeyStatus> {
        self.receipt_key_status
    }

    /// The registry-receipt verdict, reported separately from the body
    /// verdict (RFC-ACDP-0010 §8, 0.5.0). `None` when no receipt was
    /// evaluated (none served, or [`ReceiptPolicy::Ignore`]);
    /// `Some(Ok(()))` when it verified; `Some(Err(_))` only under
    /// [`ReceiptPolicy::VerifyAndReport`] — the other policies turn a
    /// failing receipt into the call's `Err`.
    pub fn receipt_verdict(&self) -> Option<&Result<(), AcdpError>> {
        self.receipt_verdict.as_ref()
    }

    /// How `body.lineage_id` is bound (RFC-ACDP-0004 §2.1, 0.5.0):
    /// derived offline for a first version, attested by the verified
    /// receipt for a later one, or registry-asserted only (`Unbound`).
    pub fn lineage_binding(&self) -> acdp_verify::LineageBinding {
        self.lineage_binding
    }

    /// The lineage-head receipt verdict (RFC-ACDP-0011 §7), reported
    /// separately; `Some(Err(_))` only under
    /// [`ReceiptPolicy::VerifyAndReport`] on [`LineageHeadPolicy::receipts`].
    pub fn head_receipt_verdict(&self) -> Option<&Result<(), AcdpError>> {
        self.head_receipt_verdict.as_ref()
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

    /// RFC-ACDP-0014 §8 auto-discovery failure that
    /// [`DiscoveryFailurePolicy::ProceedWithKnown`] swallowed to let
    /// this `VerifiedContext` exist at all. `None` when discovery was
    /// off ([`RevocationPolicy::discover`] is `None`), succeeded, or
    /// was never attempted — a [`DiscoveryFailurePolicy::FailClosed`]
    /// failure turns into this call's `Err` instead, so there is no
    /// `VerifiedContext` to carry it in that case. See
    /// [`VerificationReport::revocation_discovery`] for the twin
    /// surface on the report family, populated from the same event on
    /// the `fetch_report*` paths.
    pub fn revocation_discovery_failure(&self) -> Option<&AcdpError> {
        self.revocation_discovery_failure.as_ref()
    }

    /// The typed revocation verdict for this context's signing key
    /// (RFC-ACDP-0014 §7/§8, 0.5.0): [`RevocationVerdict::Revoked`] with
    /// [`RevocationEffect::PreCompromise`](crate::RevocationEffect::PreCompromise)
    /// (a refusal never yields a `VerifiedContext` — it is
    /// [`AcdpError::KeyRevoked`]), [`RevocationVerdict::NotRevoked`], or —
    /// only under [`DiscoveryFailurePolicy::ProceedWithKnown`] —
    /// [`RevocationVerdict::Unknown`].
    pub fn revocation_verdict(&self) -> &RevocationVerdict {
        &self.revocation_verdict
    }

    /// Verified revocations that do not speak for this context's producer
    /// (RFC-ACDP-0014 §7 "Producer scope", 0.5.0) — reported as hints,
    /// never applied to the verdict.
    pub fn revocation_hints(&self) -> &[SourcedRevocation] {
        &self.revocation_hints
    }

    /// The RFC-ACDP-0012 §9 transparency-log inclusion verdict, reported
    /// separately from the body, receipt and revocation verdicts (§9.3:
    /// log-proof failure "invalidates nothing else").
    ///
    /// - `None`: not evaluated. Either the policy is
    ///   [`LogInclusionPolicy::Ignore`] with no witness policy, or the
    ///   response carried no `log_inclusion`.
    /// - `Some(Ok(()))`: the proof verified. The context is included in
    ///   the log the registry committed to; see
    ///   [`Self::verified_log_inclusion`].
    /// - `Some(Err(_))`: the proof was present and failed (wire code
    ///   `invalid_log_proof`). Under the default policy the context still
    ///   verified.
    #[must_use]
    pub fn log_inclusion_verdict(&self) -> Option<Result<(), AcdpError>> {
        self.transparency.log_verdict()
    }

    /// The verified inclusion proof, including the signed checkpoint, when
    /// [`Self::log_inclusion_verdict`] is `Some(Ok(()))`. Keep the
    /// checkpoint to check consistency with later ones (RFC-ACDP-0012 §9.2).
    #[must_use]
    pub fn verified_log_inclusion(&self) -> Option<&acdp_types::log::LogInclusion> {
        match &self.transparency.log {
            Some(Ok(inclusion)) => Some(inclusion),
            _ => None,
        }
    }

    /// The RFC-ACDP-0015 §8 witness-quorum verdict over the verified
    /// checkpoint.
    /// - `None`: [`VerificationPolicy::witness_quorum`] was unset.
    /// - `Some(Err(_))`: there was no verified checkpoint to corroborate.
    /// - `Some(Ok(report))`: the quorum was evaluated.
    ///
    /// Read the quorum from the report:
    /// - [`WitnessQuorumReport::meets_quorum`] is the split-view and
    ///   anti-rewrite quorum;
    /// - [`WitnessQuorumReport::meets_fresh_quorum`] is the quorum for
    ///   decisions that need a current checkpoint.
    #[must_use]
    pub fn witness_quorum(&self) -> Option<&Result<WitnessQuorumReport, AcdpError>> {
        self.transparency.witness.as_ref()
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

    /// Re-assess this context's revocation status under `policy` without
    /// refetching the context (RFC-ACDP-0014 §7/§8) — for a long-lived
    /// holder of a `VerifiedContext` that must notice a revocation
    /// published after it verified.
    ///
    /// Derives the two inputs of
    /// [`find_revocations_verdict`](crate::find_revocations_verdict) from
    /// this context: the signing key's RFC-ACDP-0010 §6 fingerprint
    /// (resolved through `resolver`, normally a DID-cache hit) and the
    /// placement fixed at verification time
    /// ([`Self::verified_receipt`]'s `created_at` with
    /// [`Self::receipt_key_status`]). Never fails on a verdict; call
    /// [`RevocationAssessment::enforce`](crate::RevocationAssessment::enforce)
    /// to turn a refusal or a fail-closed `unknown` into an error. `Err`
    /// only when the signing key can no longer be resolved.
    pub async fn recheck_revocation(
        &self,
        client: &RegistryClient,
        resolver: &WebResolver,
        policy: &RevocationPolicy,
    ) -> Result<crate::RevocationAssessment, AcdpError> {
        let fingerprint = acdp_crypto::fingerprint::fingerprint_for_key_id(
            &self.inner.body.signature.key_id,
            &self.inner.body.signature.algorithm,
            resolver,
        )
        .await?;
        let placement = self
            .verified_receipt
            .as_ref()
            .zip(self.receipt_key_status)
            .map(|(r, status)| (r.created_at, status));
        crate::find_revocations_verdict(
            client,
            resolver,
            &self.inner.body.agent_id,
            &fingerprint,
            placement,
            policy,
        )
        .await
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
/// `AcdpError` implements `Clone` (see its doc), which is what lets
/// [`Self::revocation_discovery`]'s failure also be independently owned
/// by [`VerifiedContext::revocation_discovery_failure`] from the same
/// `fetch_report*` call; `AcdpError` still has no `PartialEq`, so
/// asserting on any `AcdpError`-carrying field here wants `matches!`.
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
    /// `AcdpError` derives `Clone` (see its doc — added for this field's
    /// and [`VerifiedContext::revocation_discovery_failure`]'s sake), but
    /// asserting on it still wants `matches!` over `==`/`assert_eq!`:
    /// `AcdpError` has no `PartialEq`.
    pub policy_phase_error: Option<AcdpError>,
    /// What RFC-ACDP-0014 §8 auto-discovery did, when
    /// `policy.revocations.discover` was `Some` and `verify_retrieved`
    /// was reached (a top-level probe failure or a
    /// [`DiscoveryFailurePolicy::FailClosed`] discovery failure both
    /// leave this `None` — the latter surfaces via
    /// [`Self::policy_phase_error`] instead, since `verify_retrieved`
    /// returned `Err` before there was any outcome to record). `Some(Ok(_))`
    /// on success; `Some(Err(_))` when
    /// [`DiscoveryFailurePolicy::ProceedWithKnown`] swallowed a
    /// discovery failure and verification proceeded on
    /// [`RevocationPolicy::known`] alone — see
    /// [`VerifiedContext::revocation_discovery_failure`] for the twin
    /// surface on the verified handle itself, populated from the same
    /// event. The counts inside [`DiscoveryOutcome`] are discovery
    /// output only, never `known` — appended last, after
    /// `policy_phase_error`, for the same "fail loudly on stale
    /// positional construction" reason that field was.
    pub revocation_discovery: Option<Result<DiscoveryOutcome, AcdpError>>,
    /// RFC-ACDP-0010 §8 step 1 receipt-key status (0.5.0); see
    /// [`VerifiedContext::receipt_key_status`]. `None` when no receipt
    /// verified or the authorization phases were not reached.
    pub receipt_key_status: Option<acdp_types::receipt::ReceiptKeyStatus>,
    /// The receipt verdict, reported separately from the body verdict
    /// (RFC-ACDP-0010 §8, 0.5.0); see [`VerifiedContext::receipt_verdict`].
    pub receipt_verdict: Option<Result<(), AcdpError>>,
    /// How `body.lineage_id` is bound (RFC-ACDP-0004 §2.1, 0.5.0);
    /// `None` when the authorization phases were not reached.
    pub lineage_binding: Option<acdp_verify::LineageBinding>,
    /// The typed revocation verdict (RFC-ACDP-0014 §7/§8, 0.5.0); see
    /// [`VerifiedContext::revocation_verdict`]. `None` when the
    /// authorization phases were not reached.
    pub revocation_verdict: Option<RevocationVerdict>,
    /// Verified revocations outside the producer's scope (RFC-ACDP-0014 §7
    /// "Producer scope", 0.5.0) — reported, never applied.
    pub revocation_hints: Vec<SourcedRevocation>,
    /// The RFC-ACDP-0012 §9 log-inclusion verdict (0.4.0), reported
    /// separately from every verdict above; see
    /// [`VerifiedContext::log_inclusion_verdict`]. `None` when not
    /// evaluated or when the authorization phases were not reached.
    pub log_inclusion_verdict: Option<Result<(), AcdpError>>,
    /// The RFC-ACDP-0015 §8 witness-quorum verdict (0.4.0); see
    /// [`VerifiedContext::witness_quorum`]. `None` when
    /// [`VerificationPolicy::witness_quorum`] is unset or when the
    /// authorization phases were not reached.
    pub witness_quorum: Option<Result<WitnessQuorumReport, AcdpError>>,
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
    use super::{
        DiscoveryFailurePolicy, HistoricalKeyPolicy, ReceiptPolicy, RevocationDiscovery,
        RevocationPolicy, VerificationPolicy,
    };
    use acdp_primitives::error::AcdpError;
    use std::time::Duration;

    /// The RFC-ACDP-0001 §9.2 named constructor preserves exact v0.1.0
    /// semantics: receipts inert, assertionMethod-only keys. It is
    /// deliberately NOT the 0.2 default (which is receipt-aware).
    /// RFC-ACDP-0001 §5.11 strict profile item 1 (acdp-rs#385 item 8).
    #[test]
    fn v0_1_0_bodies_require_did_web() {
        use acdp_types::Body;

        const DK: &str = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
        const WEB: &str = "did:web:agents.example.com:p";
        let body_for = |agent: &str, version: Option<&str>| -> Body {
            let mut v = serde_json::json!({
                "ctx_id": "acdp://registry.example.com/9f1e2d3c-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
                "lineage_id": "lin:sha256:6af6229c1c6a4a119695c77e47f6554941aebce3d25ba8567e2ae6ffbb6059cb",
                "origin_registry": "registry.example.com",
                "created_at": "2026-05-02T08:00:00.000Z",
                "version": 1,
                "supersedes": null,
                "agent_id": agent,
                "contributors": [],
                "content_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "signature": {"algorithm": "ed25519", "key_id": format!("{agent}#key-1"), "value": "AA=="},
                "title": "strict v0.1.0",
                "type": "data_snapshot",
                "data_refs": [],
                "derived_from": [],
                "visibility": "public",
            });
            if let Some(ver) = version {
                v["acdp_version"] = serde_json::json!(ver);
            }
            serde_json::from_value(v).unwrap()
        };

        for v in [None, Some("0.1.0")] {
            let err = crate::verified::require_did_web_for_v0_1_0(&body_for(DK, v)).unwrap_err();
            assert!(
                matches!(err, AcdpError::SchemaViolation(_)),
                "{v:?}: {err:?}"
            );
            crate::verified::require_did_web_for_v0_1_0(&body_for(WEB, v)).unwrap();
        }
        for v in ["0.2.0", "0.4.0"] {
            crate::verified::require_did_web_for_v0_1_0(&body_for(DK, Some(v))).unwrap();
        }

        // A did:web agent_id with a did:key signing key on a v0.1.0 body
        // is rejected too (the key_id DID portion is checked separately).
        let mut mixed = body_for(WEB, None);
        mixed.signature.key_id = format!("{DK}#k");
        assert!(matches!(
            crate::verified::require_did_web_for_v0_1_0(&mixed),
            Err(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn strict_v0_1_0_preserves_v0_1_0_semantics() {
        let strict = VerificationPolicy::strict_v0_1_0();
        assert!(strict.validate_body_schema);
        assert!(strict.allow_unknown_status);
        assert_eq!(strict.receipts, ReceiptPolicy::Ignore);
        assert_eq!(strict.historical_keys, HistoricalKeyPolicy::Reject);
        assert!(strict.require_did_web_for_v0_1_0);
        assert!(
            VerificationPolicy::default().require_did_web_for_v0_1_0,
            "RFC-ACDP-0001 §5.11: a relaxed mode MUST NOT be the default"
        );
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
    /// `verify_retrieved` must be the SOLE reader of the
    /// authorization-policy fields (`receipts`, `revocations`,
    /// `historical_keys`, `allow_unknown_status`,
    /// `require_did_web_for_v0_1_0`) anywhere in this file.
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
            "require_did_web_for_v0_1_0",
            "log_inclusion",
            "witness_quorum",
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

        // Second pass — whitespace-normalized, to catch a read rustfmt
        // has wrapped across lines (e.g. a `policy` / `.revocations` /
        // `.known` chain on three separate lines), which the
        // line-by-line pass above cannot see since the pattern never
        // sits contiguously on any single line. Build a copy of `SRC`
        // with whitespace immediately touching a `.` removed — folding
        // any such wrapped chain back to its unwrapped spelling — while
        // recording, for every byte kept, the byte offset it came from
        // in the original `SRC`. Every match here is re-validated
        // against its ORIGINAL line for the same comment / string
        // exclusions the first pass applies, so this pass only adds
        // coverage; it does not relax anything the first pass enforces.
        let mut normalized = String::with_capacity(SRC.len());
        let mut orig_offsets: Vec<usize> = Vec::with_capacity(SRC.len());
        let mut after_dot = false;
        for (i, ch) in SRC.char_indices() {
            if ch == '.' {
                while let Some(last) = normalized.chars().last() {
                    if !last.is_whitespace() {
                        break;
                    }
                    normalized.pop();
                    let new_len = orig_offsets.len() - last.len_utf8();
                    orig_offsets.truncate(new_len);
                }
                normalized.push(ch);
                orig_offsets.push(i);
                after_dot = true;
                continue;
            }
            if after_dot && ch.is_whitespace() {
                continue; // swallow whitespace immediately after a dot
            }
            after_dot = false;
            normalized.push(ch);
            for _ in 0..ch.len_utf8() {
                orig_offsets.push(i);
            }
        }
        debug_assert_eq!(normalized.len(), orig_offsets.len());

        let is_comment_line_at = |pos: usize| -> bool {
            let line_start = SRC[..pos].rfind('\n').map_or(0, |i| i + 1);
            let line_end = SRC[pos..].find('\n').map_or(SRC.len(), |i| pos + i);
            SRC[line_start..line_end].trim_start().starts_with("//")
        };
        let in_string_literal_at = |pos: usize| -> bool {
            let line_start = SRC[..pos].rfind('\n').map_or(0, |i| i + 1);
            SRC[line_start..pos].matches('"').count() % 2 == 1
        };

        for pattern in &patterns {
            let mut search_from = 0usize;
            while let Some(rel) = normalized[search_from..].find(pattern.as_str()) {
                let match_col = search_from + rel;
                let orig_start = orig_offsets[match_col];
                if !is_comment_line_at(orig_start) && !in_string_literal_at(orig_start) {
                    checked_any = true;
                    assert!(
                        orig_start >= body_open && orig_start < body_close,
                        "found `{pattern}` (whitespace-normalized) outside \
                         verify_retrieved's body (original byte offset {orig_start}) \
                         — every authorization-policy-field read must live inside \
                         verify_retrieved, the sole reader, even when rustfmt has \
                         wrapped the field-access chain across multiple lines"
                    );
                }
                search_from = match_col + pattern.len();
            }
        }

        assert!(
            checked_any,
            "sanity: the scan must find at least one non-comment, non-string-literal \
             match for at least one pattern (verify_retrieved itself reads these \
             fields) — zero hits would mean the patterns are miscomputed, not that \
             the invariant holds"
        );
    }

    /// issue #248 Phase 2, acceptance criterion 1 — `RevocationPolicy::default()`
    /// stays behaviorally identical to the pre-Phase-2 shape: no known
    /// revocations, discovery off.
    #[test]
    fn revocation_policy_default_is_unchanged() {
        let policy = RevocationPolicy::default();
        assert!(policy.known.is_empty());
        assert!(policy.discover.is_none());
    }

    /// issue #248 Phase 2, acceptance criterion 1 (continued) — `::new`
    /// produces the same shape as the old bare-literal `RevocationPolicy { known }`
    /// this struct's `#[non_exhaustive]` retires.
    #[test]
    fn revocation_policy_new_leaves_discovery_off() {
        let policy = RevocationPolicy::new(vec![]);
        assert!(policy.known.is_empty());
        assert!(policy.discover.is_none());
    }

    /// issue #248 Phase 2, acceptance criterion 3.
    #[test]
    fn discovery_failure_policy_defaults_to_fail_closed() {
        assert_eq!(
            DiscoveryFailurePolicy::default(),
            DiscoveryFailurePolicy::FailClosed
        );
    }

    /// issue #248 Phase 2, acceptance criterion 3.
    #[test]
    fn revocation_discovery_constructors_set_the_right_trust_classes() {
        let producer_only = RevocationDiscovery::producer_signed_only();
        assert!(!producer_only.include_registry_attested);
        assert_eq!(producer_only.on_failure, DiscoveryFailurePolicy::FailClosed);
        assert_eq!(producer_only.total_timeout, Duration::from_secs(30));
        assert_eq!(
            producer_only.freshness,
            Duration::from_secs(300),
            "RFC-ACDP-0014 §8 (0.5.0): negative freshness defaults to the RECOMMENDED 300 s"
        );

        let all = RevocationDiscovery::all_trust_classes();
        assert!(all.include_registry_attested);
        assert_eq!(all.on_failure, DiscoveryFailurePolicy::FailClosed);
        assert_eq!(all.total_timeout, Duration::from_secs(30));
        assert_eq!(all.freshness, Duration::from_secs(300));
    }

    /// issue #248 Phase 2, acceptance criterion 3 (continued) — D6:
    /// `RevocationDiscovery` has no `Default` impl. This is a
    /// compile-time property, not something a runtime assertion can
    /// check; the doc comment on `RevocationDiscovery` records why.
    /// This test exists to make that guarantee discoverable from the
    /// test suite: if a future change adds `Default`, this comment is
    /// the tripwire a reviewer reads, since nothing here would fail.
    /// (An attempted `RevocationDiscovery::default()` call would be a
    /// compile error today — that IS the enforcement.)
    #[test]
    fn revocation_discovery_has_no_default_by_design() {
        // Deliberately empty: the guarantee is enforced by the type
        // system (no `Default` impl exists), not by this test body.
    }

    /// RFC-ACDP-0014 §8 (0.5.0): `RevocationUnknown` is transient exactly
    /// when its reason is `transient`.
    #[test]
    fn revocation_unknown_is_transient_only_for_transient_reason() {
        let unknown = |source: AcdpError| {
            let reason = source.unknown_reason();
            AcdpError::RevocationUnknown {
                reason,
                source: Box::new(source),
                detail: String::new(),
            }
        };
        let transient = unknown(AcdpError::KeyResolutionUnreachable("x".into()));
        assert!(transient.is_transient());
        for permanent in [
            AcdpError::InvalidSignature("x".into()),
            AcdpError::SearchTruncated("x".into()),
            AcdpError::NotAuthorized("x".into()),
            AcdpError::RevocationCandidateUnverifiable("x".into()),
        ] {
            assert!(!unknown(permanent).is_transient());
        }
    }
}
