//! Consumer-side key-revocation semantics (ACDP 0.3, RFC-ACDP-0014).
//!
//! Three layers:
//!
//! - [`classify_under_revocation`] — the pure §7 boundary rule: given
//!   verified revocations and a (receipt-attested) publish time,
//!   decide *historically authorized (pre-compromise, receipt-attested)*
//!   vs fail-closed. This is what
//!   [`VerificationPolicy::revocations`](crate::VerificationPolicy)
//!   drives inside the fetch pipeline.
//! - [`verify_revocation_body`] — the §5 verification pipeline for a
//!   revocation context itself: strict RFC-ACDP-0001 §5.11 body
//!   verification, §4 shape parse, and the §5 step 2 not-self-signed
//!   check against the resolved signing key's fingerprint.
//! - [`find_revocations`] — the §8 discovery SHOULD: search a registry
//!   for a producer's revocation contexts and return the ones that
//!   verify.

use acdp_crypto::fingerprint::fingerprint_for_key_id;
use acdp_did::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_types::body::Body;
use acdp_types::primitives::{AgentDid, CtxId, LineageId};
use acdp_types::revocation::{effective_boundary, KeyRevocation, RevocationTrustClass};
use acdp_types::search::SearchParamsBuilder;
use acdp_verify::Verifier;
use chrono::{DateTime, Utc};

use super::registry::RegistryClient;
use super::verified::KeyAuthorization;

/// Pagination safety cap for [`find_revocations`] — a hostile registry
/// must not be able to hold the helper in an endless cursor loop.
const MAX_SEARCH_PAGES: usize = 10;

/// Lineage-walk safety cap for [`find_revocations`] and
/// [`find_registry_attested_revocations`] — a hostile registry must not
/// be able to name an unbounded number of distinct `lineage_id`s across
/// a `MAX_SEARCH_PAGES`-bounded search (3 statuses × 2 type-forms × 10
/// pages × limit 100 = up to ~6000 candidates) and force one
/// `GET /lineages/{id}` fetch each (each capped at 1 MB by the client —
/// ~6 GB of forced fetches with no cap at all). 100 is generous for any
/// legitimate producer's revocation history and bounded against a
/// hostile one; exceeding it is treated exactly like exhausting
/// `MAX_SEARCH_PAGES` — a hard [`AcdpError::SearchTruncated`], never a
/// silently partial set (issue #226 Phase 4).
const MAX_LINEAGE_WALKS: usize = 100;

/// Apply the RFC-ACDP-0014 §7 compromise-boundary rule.
///
/// Inputs:
///
/// - `revocations` — **verified** revocations the consumer has decided
///   to act on (see [`RevocationPolicy`](crate::RevocationPolicy) for
///   the §6 trust-class guidance). The §4 earliest-`compromised_since`
///   rule is applied across every entry naming the fingerprint.
/// - `signing_key_fingerprint` — the RFC-ACDP-0010 §6 fingerprint of
///   the key that signed the context under verification.
/// - `receipt_attested_created_at` — `created_at` from a registry
///   receipt **verified per RFC-ACDP-0010 §8** (whose step 5 confirms
///   the receipt attests this same fingerprint), or `None` when there
///   is no verified receipt. The bare body `created_at` MUST NOT be
///   passed here — it is registry-assigned, unsigned by the producer,
///   and attacker-backdatable (§7 step 1).
///
/// Verdicts:
///
/// - `Ok(None)` — no supplied revocation names this key; the ordinary
///   verification rules apply unchanged.
/// - `Ok(Some(`[`KeyAuthorization::HistoricallyAuthorizedPreCompromise`]`))`
///   — publish time strictly before the boundary (§7 step 2). The
///   caller must still verify the signature itself, under the
///   RFC-ACDP-0010 §10 historical rule.
/// - `Err(`[`AcdpError::KeyNotAuthorized`]`)` — fail closed: publish
///   time at/after the boundary (§7 step 3), or no verifiable publish
///   time at all (§7 step 4). Per RFC-ACDP-0014 §10 this is a
///   verification verdict, not a wire condition — there is no new wire
///   error code; the key is simply not authorized to speak for the
///   producer in (or without placement relative to) the compromise
///   window.
pub fn classify_under_revocation(
    revocations: &[KeyRevocation],
    signing_key_fingerprint: &str,
    receipt_attested_created_at: Option<DateTime<Utc>>,
) -> Result<Option<KeyAuthorization>, AcdpError> {
    let Some(boundary) = effective_boundary(revocations, signing_key_fingerprint) else {
        return Ok(None);
    };
    match receipt_attested_created_at {
        Some(created_at) if created_at < boundary => {
            Ok(Some(KeyAuthorization::HistoricallyAuthorizedPreCompromise))
        }
        Some(created_at) => Err(AcdpError::KeyNotAuthorized(format!(
            "signing key {signing_key_fingerprint} is revoked with compromise boundary \
             {}; the receipt-attested publish time {} is at/after the boundary, so the \
             signature is not attributable to the producer — fail closed regardless of \
             DID-document state or receipt validity (RFC-ACDP-0014 §7 step 3)",
            boundary.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            created_at.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        ))),
        None => Err(AcdpError::KeyNotAuthorized(format!(
            "signing key {signing_key_fingerprint} is revoked (compromise boundary {}) \
             and the context has no verified registry receipt, so its publish time \
             cannot be placed relative to the boundary — an unplaceable revoked-key \
             signature is exactly the artifact an attacker mints freely; the strict \
             profile fails closed (RFC-ACDP-0014 §7 step 4)",
            boundary.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        ))),
    }
}

/// Verify a `key-revocation` context body per RFC-ACDP-0014 §5 and
/// return its typed, trust-classified form.
///
/// Pipeline:
///
/// 1. Strict RFC-ACDP-0001 §5.11 body verification (schema, hash
///    recomputation, DID resolution, `assertionMethod` authorization,
///    signature) — §5 step 1's "signed by a currently authorized key".
/// 2. §4 shape parse + §5/§6 trust-class derivation
///    ([`KeyRevocation::from_body`]).
/// 3. §5 step 2 — the resolved signing key's fingerprint MUST NOT
///    equal `revoked_key_fingerprint`
///    ([`KeyRevocation::check_not_self_signed`]).
///
/// Note the §5 step 1 nuance this strict form does not cover: a
/// revocation whose own signing key was later rotated out *cleanly*
/// remains acceptable via the RFC-ACDP-0010 §10 receipt-attested
/// historical rule — fetch it through
/// [`VerifiedContext::fetch_with_policy`](crate::VerifiedContext::fetch_with_policy)
/// (default policy) and parse the body afterwards for that case.
///
/// The returned trust class MUST be honored per §6: act on
/// producer-signed revocations unconditionally; treat registry-attested
/// ones as the weaker class (confirm `publisher` is in fact the DID of
/// the registry involved via
/// [`KeyRevocation::cross_check_registry_binding`], and corroborate
/// before global use).
pub async fn verify_revocation_body(
    body: &Body,
    resolver: &WebResolver,
) -> Result<KeyRevocation, AcdpError> {
    Verifier::new(resolver).verify_body(body).await?;
    let revocation = KeyRevocation::from_body(body)?;
    let signer_fingerprint =
        fingerprint_for_key_id(&body.signature.key_id, &body.signature.algorithm, resolver).await?;
    revocation.check_not_self_signed(&signer_fingerprint)?;
    Ok(revocation)
}

/// Walk every member of a revocation lineage and return the ones that
/// verify per §5 — **regardless of `registry_state.status`** and with
/// **no trust-class or publisher scope filter**.
///
/// **Why walk a lineage at all, when [`find_revocations`] already
/// re-queries `status=superseded`:** a merely-superseded member is
/// already visible to a `status=superseded` search pass — the walk buys
/// nothing there. What the walk buys is robustness to any lineage whose
/// members carry a *mixed* set of statuses a search pass does not (or
/// cannot) enumerate: `expired` members, a future [`acdp_types::primitives::Status::Other`]
/// value (`Status` is an open enum — RFC-ACDP-0004 §4), or a member a
/// search pass has been made structurally blind to. RFC-ACDP-0013
/// §8.1 makes `GET /lineages/{id}` an **obligation** to include the
/// full lineage including retracted versions — so one lineage member
/// that IS visible to search exposes every other member through this
/// endpoint, independent of what search itself would ever return for
/// them. A registry excluding a retracted context from `status=superseded`
/// search results (RFC-ACDP-0013 §8.2 — normative) is exactly the seed
/// case this closes; the complementary case — where **every** member of
/// a lineage is invisible to search (e.g. the lineage head itself was
/// retracted) — has no live search match to discover the lineage id
/// from in the first place, and is closed separately by an explicit
/// `status=retracted` search pass, not by this walk.
///
/// Fetches `client.lineage(lineage_id)` (RFC-ACDP-0004 §5.1 defines no
/// pagination for this endpoint, so a pathological lineage fails loudly
/// at the client's `MAX_CONTEXT_BYTES` cap rather than truncating) and
/// verifies every returned member via [`verify_revocation_body`],
/// pairing each verified member with its `ctx_id` — read from
/// `ctx.body.ctx_id`, since the lineage linkage travels via the
/// [`acdp_types::body::FullContext`]/[`Body`] shape, never via a new
/// [`KeyRevocation`] field (`KeyRevocation` carries no `ctx_id` and
/// derives no `Hash`, so its public return shape alone cannot feed a
/// `ctx_id`-keyed dedupe set).
///
/// A member is only skipped when its §5 verification failure is
/// **permanent** (`AcdpError::is_transient() == false` — a broken
/// signature, a hash mismatch, a schema violation, a DID that resolves
/// but denies the key) — attacker-injected garbage in a lineage must
/// not poison the set — logged via `tracing::warn!` when the `tracing`
/// feature is enabled. Note the asymmetry with the two fail-closed
/// cases below: a cryptographic-verification failure *inside* an
/// otherwise well-formed, correctly-membered lineage is actually a
/// **stronger** signal of registry (or upstream producer) misbehavior
/// than an empty or mismatched lineage response is — a well-behaved
/// registry simply does not have a signature-broken member to serve in
/// the first place — yet it is the empty/mismatched cases that fail
/// loudly here, not this one. That is a deliberate, asymmetric choice,
/// not an oversight: treating every verification failure as fatal
/// would let one injected garbage member suppress every other genuine
/// revocation in the lineage (the same "one bad apple poisons
/// discovery" DoS this whole function exists to avoid), whereas
/// dropping a **permanently** un-verifiable member and continuing
/// costs nothing an attacker can turn into a false *authorization* —
/// such a member was never going to contribute a valid
/// `compromised_since` to [`effective_boundary`]'s fold, dropped or
/// not. It is currently invisible without the `tracing` feature; a
/// future caller auditing registry health should not assume "no
/// revocations found" means "no suspicious members were seen."
///
/// **A transient failure (`is_transient() == true` — the DID host is
/// unreachable, rate-limited, or otherwise could not be asked, as
/// opposed to having answered and denied) is a different case and is
/// NOT dropped: it propagates as `Err` instead (issue #248 Phase 1,
/// "D5").** An earlier revision of this doc claimed a dropped member
/// is "simply absent from the result, never wrongly present" — true
/// only of the permanent case above, and false in general: a dropped
/// member that *would* have named an earlier `compromised_since` than
/// any survivor moves [`effective_boundary`]'s `.min()` fold **later**
/// (`acdp_types::revocation::effective_boundary`), which silently
/// authorizes activity that should have been inside the compromise
/// window — a genuine false authorization, not a mere omission. A
/// transient failure gives no information about what that member would
/// have said, so silently continuing past it could produce exactly
/// that outcome. Propagating instead tells the caller "this set is
/// incomplete, do not trust it," which — per D5 — adds no new denial-
/// of-service lever: this function already aborts unconditionally on
/// `client.lineage` failing outright, so a hostile or merely-unlucky
/// network path already had an abort lever before this change; this
/// closes the one case that used to bypass it by masquerading as a
/// clean, complete result.
///
/// **Fails closed, rather than silently continuing, in two cases:**
///
/// 1. The lineage has no members at all. The reference registry returns
///    `Ok(vec![])` for an unrecognized `lineage_id`
///    (`crates/acdp-server/src/registry/store.rs`), so an empty response
///    for a `lineage_id` a live search match just named is never an
///    honest "nothing here."
/// 2. `expect_member` is `Some` and is not among the **pre-verification**
///    members the registry served (see the parameter doc below) — the
///    registry answered the lineage-walk request, but not with the
///    lineage the search match actually pointed at.
///
/// Both cases return [`AcdpError::IncompleteLineage`]. A genuine 404 or
/// transport error from `client.lineage` propagates unchanged (a
/// different variant, not this one) — all the way out to
/// [`find_revocations`] and [`find_registry_attested_revocations`],
/// neither of which catches an `Err` from this function.
///
/// **This does not contradict RFC-ACDP-0004 §5.4** ("if the lineage
/// exists but the requester is authorized to see zero versions, the
/// response MUST be an empty array `[]`, not `not_found`" — corroborated
/// by fixture `vis-008`): that rule is about visibility scoping hiding
/// versions from a requester who is not authorized to see them, and it
/// is real for ordinary lineages. It cannot legitimately fire *here*,
/// specifically, because RFC-ACDP-0014 §4 requires every revocation
/// context to be published `visibility: public` — there is no
/// authorized-to-see-zero-versions state a public-only lineage can be
/// in. An empty response to a revocation-lineage walk therefore means
/// the registry is inconsistent (eventually-consistent lag) or hostile,
/// not that §5.4 visibility scoping legitimately applied — reword from
/// an earlier draft that called this "the realistic hostile shape,"
/// which conflated a hostile registry with a benign eventual-consistency
/// race; both are covered by the same fail-closed response here, but
/// only because both are equally unexplainable for a lineage that MUST
/// be all-public. Callers relying on this function for a
/// **non**-revocation, mixed-visibility lineage would need a different
/// rule.
///
/// **Round-trip cost.** Every distinct `lineage_id` a search match names
/// (deduped by the callers below) costs one `client.lineage` fetch
/// (RFC-ACDP-0004 §5.1 defines no pagination for this endpoint, so a
/// pathological lineage fails loudly at `MAX_CONTEXT_BYTES` rather than
/// truncating) plus one DID resolution per member returned — including
/// members belonging to producers other than the one a caller queried
/// for, since a lineage walk has no producer filter. Worst case this
/// roughly doubles the per-call work a hostile registry can impose,
/// against the already-existing per-search-match `retrieve` cost — not a
/// new exposure *class*, since [`acdp_did::WebResolver`]'s
/// [`acdp_safe_http::SsrfPolicy`] still bounds which hosts any of those
/// DID fetches can reach, but real added work per call.
///
/// This is the neutral building block: no trust-class or publisher
/// filter is applied here. [`find_revocations_in_lineage`] is a thin
/// wrapper for a caller that wants every verified member regardless of
/// scope; [`find_revocations`] and [`find_registry_attested_revocations`]
/// each apply their own (different) scope filter to the members this
/// returns, and each propagates a failure from this function via `?`,
/// aborting the whole discovery call rather than scoping the failure to
/// one lineage — see their docs.
///
/// `expect_member`, when `Some`, is the `ctx_id` a live search match
/// named for `lineage_id` — checked against the lineage's
/// **pre-verification** member list, not the post-verification
/// survivors. The two differ whenever a member fails §5 verification,
/// and the choice matters: checking survivors instead would let a
/// hostile registry serve a corrupted (signature-broken) copy of the
/// named member specifically to manufacture this same failure, making
/// "fails §5" and "isn't the lineage that was searched" indistinguishable.
/// The question this check answers is "did the registry serve the
/// lineage it claimed to," which is answerable from the raw member list
/// alone, before any per-member verification is attempted.
async fn walk_revocation_lineage(
    client: &RegistryClient,
    resolver: &WebResolver,
    lineage_id: &LineageId,
    expect_member: Option<&CtxId>,
) -> Result<Vec<(CtxId, KeyRevocation)>, AcdpError> {
    let members = client.lineage(lineage_id).await?;
    if members.is_empty() {
        return Err(AcdpError::IncompleteLineage {
            lineage_id: lineage_id.as_str().to_string(),
            ctx_id: expect_member.map(|c| c.as_str().to_string()),
        });
    }
    // GAP-A (issue #226 Phase 3): confirm the registry actually served
    // the lineage a live search match named, checked against the
    // PRE-verification member list — see the parameter doc above for
    // why pre- rather than post-verification.
    if let Some(expected) = expect_member {
        if !members.iter().any(|ctx| &ctx.body.ctx_id == expected) {
            return Err(AcdpError::IncompleteLineage {
                lineage_id: lineage_id.as_str().to_string(),
                ctx_id: Some(expected.as_str().to_string()),
            });
        }
    }
    let mut out = Vec::with_capacity(members.len());
    for ctx in members {
        match verify_revocation_body(&ctx.body, resolver).await {
            Ok(rev) => out.push((ctx.body.ctx_id.clone(), rev)),
            // D5 (issue #248 Phase 1): a transient failure means "could
            // not check this member," not "this member is bad" — propagate
            // it rather than silently treating it as if it had never
            // existed. See the rustdoc block above for why the permanent
            // case still drops and warns.
            Err(e) if e.is_transient() => return Err(e),
            Err(_e) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    lineage_id = %lineage_id.as_str(),
                    ctx_id = %ctx.body.ctx_id.as_str(),
                    error = %_e,
                    "walk_revocation_lineage: dropped lineage member failing §5 verification"
                );
            }
        }
    }
    Ok(out)
}

/// Discover every verified member of a revocation lineage
/// (RFC-ACDP-0014 §4, RFC-ACDP-0013 §8.1), regardless of
/// `registry_state.status` and with no trust-class or publisher scope
/// filter applied.
///
/// A thin wrapper over the crate-private lineage walk
/// (`walk_revocation_lineage`) — see the walk-vs-search rationale
/// below (in short: `GET /lineages/{id}` is normatively obliged to
/// include every member, including ones a `status=`-scoped search pass
/// cannot or does not enumerate, so one search-visible member exposes
/// the whole lineage through this call). [`find_revocations`] and
/// [`find_registry_attested_revocations`] both call this internally
/// (via the same private walk) to widen their own search-driven
/// discovery; call this function directly when a caller already has a
/// `lineage_id` in hand (e.g. from a [`acdp_types::search::SearchResult`]
/// or a previously-verified [`Body`]) and wants every verified member
/// without those functions' scope filters.
pub async fn find_revocations_in_lineage(
    client: &RegistryClient,
    resolver: &WebResolver,
    lineage_id: &LineageId,
) -> Result<Vec<KeyRevocation>, AcdpError> {
    Ok(walk_revocation_lineage(client, resolver, lineage_id, None)
        .await?
        .into_iter()
        .map(|(_, rev)| rev)
        .collect())
}

/// The data-only differences between [`find_revocations`] and
/// [`find_registry_attested_revocations`] that [`discover_revocations`]
/// needs but cannot compute itself (issue #264: "five parameters, not
/// three" — this struct is three of the five; `keep` and `on_drop` below
/// are the other two).
struct DiscoveryParams<'a> {
    /// Value passed to `SearchParamsBuilder::agent_id` for every search
    /// pass — the producer's own DID for [`find_revocations`], the
    /// registry's own DID (`capabilities.registry_did`) for the attested
    /// form (registry-attested revocations are published under the
    /// *registry's* `agent_id`, never the producer's).
    search_agent_id: &'a str,
    /// Diagnostic prefix shared by both `AcdpError::SearchTruncated`
    /// messages this engine can raise — `"find_revocations"` or
    /// `"find_registry_attested_revocations"`.
    fn_name: &'a str,
    /// Identity label used in the `MAX_LINEAGE_WALKS` message —
    /// `"agent_id"` or `"controller"`. Genuinely different from a mere
    /// value substitution: the label itself differs, not only what fills
    /// it (issue #264 point 5).
    identity_label: &'a str,
    /// Identity value formatted after `identity_label` in the same
    /// message — `agent_id.as_str()` or `controller.as_str()`.
    identity_value: &'a str,
}

/// The discovery engine shared by [`find_revocations`] and
/// [`find_registry_attested_revocations`]: the type-form × status ×
/// page search loop, the `MAX_LINEAGE_WALKS` bound, and the lineage-walk
/// loop that follows it (issue #264). Everything upstream of the search
/// loop — DID parsing, the revocation-cache marker check/record, and
/// (for the attested form) the one-time `client.capabilities()` fetch —
/// stays in the two public callers: the marker check must run before
/// `capabilities()` in the attested form, and `record_success` must fire
/// only once this engine returns `Ok`, so neither belongs inside a
/// shared loop body.
///
/// `params.search_agent_id` scopes every `SearchParamsBuilder` pass.
/// `keep` re-checks the verified body against the caller's own scope
/// invariants (publisher + trust class for the producer-signed form;
/// controller + registry-binding for the attested form) — a candidate
/// `keep` rejects is dropped, never surfaced as an error, exactly as
/// before. `on_drop` is called for every candidate `keep` rejects, with
/// the third argument `true` when the candidate came from the
/// lineage-walk loop rather than the search loop (the two forms differ
/// in `tracing::warn!` payload shape — `trust_class`/computed `filter`
/// vs `publisher`/`controller` — which a single `&dyn Fn(..) -> bool`
/// predicate cannot carry).
///
/// Every other behavior — the transient-propagate/permanent-drop split
/// (issue #248 Phase 1), `MAX_SEARCH_PAGES` being fresh per
/// `(type_form, status)` pair, the `MAX_LINEAGE_WALKS` check running
/// after the retrieves for that pass have already gone out, and the
/// `SearchTruncated` fail-closed contract — is unchanged from the two
/// functions' original bodies; see their docs for the full rationale.
async fn discover_revocations(
    client: &RegistryClient,
    resolver: &WebResolver,
    params: DiscoveryParams<'_>,
    keep: &dyn Fn(&KeyRevocation) -> bool,
    on_drop: &dyn Fn(&KeyRevocation, &CtxId, bool),
) -> Result<Vec<KeyRevocation>, AcdpError> {
    let DiscoveryParams {
        search_agent_id,
        fn_name,
        identity_label,
        identity_value,
    } = params;

    let mut revocations = Vec::new();
    let mut seen = std::collections::HashSet::new();
    // Discovery-order list of distinct lineage ids (walked below) plus
    // a plain `HashSet<String>` for the dedupe check — `LineageId`
    // derives `Hash` but not `Ord`, so a `BTreeSet` is not an option
    // without a wider change than GAP-B needs. Iterating a `Vec` here
    // (rather than a `HashSet<LineageId>`) keeps output order — and
    // which lineage's walk failure surfaces first — deterministic
    // across runs, matching the pre-existing search-order determinism.
    let mut lineage_order: Vec<LineageId> = Vec::new();
    let mut lineage_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    // First search match naming each lineage_id — threaded into the
    // walk below as the expected member (GAP-A). First match wins: once
    // a lineage_id has been seen, later matches naming the same lineage
    // do not overwrite the recorded ctx_id.
    let mut lineage_expect: std::collections::HashMap<String, CtxId> =
        std::collections::HashMap::new();

    for type_form in ["key-revocation", "acdp:key-revocation"] {
        // Revocations are permanent but supersedable; the registry
        // defaults search to status=active, so ask for the other
        // statuses explicitly too. `retracted` closes the seed hole
        // Phase 3's lineage walk cannot reach on its own: if every
        // member of a lineage is retracted, no `active`/`superseded`
        // pass returns anything to walk from in the first place
        // (RFC-ACDP-0013 §8.2, issue #226 Phase 4).
        for status in ["active", "superseded", "retracted"] {
            let mut search_params = SearchParamsBuilder::new()
                .context_type(type_form)
                .agent_id(search_agent_id)
                .status(status)
                .limit(100)
                .build();
            // Set only when the loop exhausts `MAX_SEARCH_PAGES` while a
            // cursor still remains — i.e. genuine truncation, not
            // completion. See the boundary note on `AcdpError::SearchTruncated`.
            let mut truncated = false;
            for _page in 0..MAX_SEARCH_PAGES {
                let resp = client.search(&search_params).await?;
                for m in &resp.matches {
                    // Free — no extra round trip: every match names its
                    // own lineage, walked below regardless of whether
                    // this particular ctx_id turns out to be new.
                    let lid_key = m.lineage_id.as_str().to_string();
                    if lineage_seen.insert(lid_key.clone()) {
                        lineage_order.push(m.lineage_id.clone());
                        lineage_expect.insert(lid_key, m.ctx_id.clone());
                    }
                    if !seen.insert(m.ctx_id.as_str().to_string()) {
                        continue;
                    }
                    let ctx = client.retrieve(&m.ctx_id).await?;
                    match verify_revocation_body(&ctx.body, resolver).await {
                        Ok(rev) => {
                            if keep(&rev) {
                                revocations.push(rev);
                            } else {
                                on_drop(&rev, &m.ctx_id, false);
                            }
                        }
                        // D5 (issue #248 Phase 1): transient means "could
                        // not look," not "clean" — propagate rather than
                        // let the candidate vanish into an empty Vec that
                        // `classify_under_revocation` reads as "proceed."
                        Err(e) if e.is_transient() => return Err(e),
                        Err(_e) => {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                ctx_id = %m.ctx_id,
                                error = %_e,
                                "{fn_name}: dropped candidate failing §5 verification"
                            );
                        }
                    }
                }
                match resp.next_cursor {
                    Some(cursor) => {
                        search_params.cursor = Some(cursor);
                        truncated = true;
                    }
                    None => {
                        truncated = false;
                        break;
                    }
                }
            }
            if truncated {
                return Err(AcdpError::SearchTruncated(format!(
                    "{fn_name}: exhausted MAX_SEARCH_PAGES={MAX_SEARCH_PAGES} pages \
                     for (type_form={type_form}, status={status}) with results still \
                     remaining on the registry (next_cursor was still Some) — refusing to \
                     return a silently partial revocation set"
                )));
            }
        }
    }

    // Bound the lineage walk the same way the search pages are bounded:
    // a hostile registry must not be able to name more distinct
    // lineage ids than this client is willing to fetch one-by-one via
    // `GET /lineages/{id}` (issue #226 Phase 4).
    if lineage_order.len() > MAX_LINEAGE_WALKS {
        return Err(AcdpError::SearchTruncated(format!(
            "{fn_name}: {} candidate lineage ids for {identity_label}={identity_value} exceed \
             MAX_LINEAGE_WALKS={MAX_LINEAGE_WALKS} — refusing to fetch a partial set",
            lineage_order.len(),
        )));
    }

    // The lineage walk: recovers members a search pass cannot or does
    // not enumerate. Each candidate lineage is fetched at most once
    // (deduped above), in discovery order (GAP-B). A walk failure for
    // one lineage — empty response, or a served member set missing the
    // search-named `ctx_id` (GAP-A) — aborts this whole call via `?`:
    // a partial `Vec` here is indistinguishable from a complete one to
    // the caller, and feeds `effective_boundary`'s `.min()` over
    // `compromised_since` (RFC-ACDP-0014 §4), so silently dropping a
    // lineage could only ever move the effective compromise boundary
    // later (or, if the whole set is dropped, make enforcement inert) —
    // never safer to omit than to fail closed on. A member failing §5
    // verification transiently (issue #248 Phase 1, "D5") also aborts
    // the walk this way, rather than being skipped like a permanent
    // failure.
    for lineage_id in &lineage_order {
        let expect = lineage_expect.get(lineage_id.as_str());
        let walked = walk_revocation_lineage(client, resolver, lineage_id, expect).await?;
        for (ctx_id, rev) in walked {
            if !seen.insert(ctx_id.as_str().to_string()) {
                continue;
            }
            if keep(&rev) {
                revocations.push(rev);
            } else {
                on_drop(&rev, &ctx_id, true);
            }
        }
    }

    Ok(revocations)
}

/// Discover a producer's key revocations on a registry
/// (RFC-ACDP-0014 §8): search `type=key-revocation` (and the §10
/// interim `acdp:key-revocation`) with `agent_id=<producer>`, retrieve
/// each match, and return the ones that verify per §5
/// ([`verify_revocation_body`]) **and** that satisfy two additional
/// invariants enforced client-side, neither of which the registry can
/// be trusted to have applied:
///
/// 1. `KeyRevocation::publisher == agent_id` (exact byte match — see
///    below) — the query's own scope. `resp.matches` is registry-
///    supplied and is re-checked here rather than trusted: a hostile
///    registry could otherwise return a context belonging to a
///    different producer entirely, and it would verify (§5 covers
///    signature validity, not query relevance). This is a genuine
///    cryptographic binding, not merely a registry-trusted one:
///    `Body.agent_id` is a producer-controlled field, not part of the
///    RFC-ACDP-0001 §5.7 exclusion set, so it sits inside
///    ProducerContent — covered by `content_hash` and the producer's
///    signature. Because [`verify_revocation_body`] runs the full
///    §5.11 pipeline first, `rev.publisher` read here has already been
///    verified against that signature, so a hostile registry cannot
///    forge it — stronger than the Phase 1 `ctx_id` check, which binds
///    only a registry-assigned field.
/// 2. `trust_class == RevocationTrustClass::ProducerSigned` — with (1)
///    enforced, a `RegistryAttested` result here would mean a producer
///    published a revocation *claiming to speak as the registry*
///    (`agent_id == publisher == <the queried producer>` while
///    `revoked_key_controller` differs). RFC-ACDP-0014 §4 makes
///    `revoked_key_controller` REQUIRED on registry-attested
///    revocations and, when present, requires it equal `body.agent_id`
///    on producer-signed ones — so this shape (`agent_id` fixed as the
///    queried producer, `revoked_key_controller` differing) is illegal
///    only in the producer-signed case; it is the *mandatory* shape
///    when `body.agent_id` is genuinely a registry. RFC-ACDP-0014 §13
///    documents this exact cross-producer forgery and endorses
///    consumer-local, operational mitigations generally — this
///    implementation's choice is client-local filtering; §13's own
///    first-named suggestion is surfacing which DID issued each
///    acted-upon revocation, which the `tracing` diagnostics below
///    partially adopt.
///
/// Both are required together: (1) alone still admits a producer's own
/// spec-illegal self-published "registry attestation" (`agent_id` and
/// `publisher` are the same field, so that check alone can't tell honest
/// producer-signed apart from self-claimed registry-attested); (2) alone
/// still admits *another* producer's genuine revocation served by a
/// hostile or buggy registry that ignored the `agent_id` search filter.
///
/// Candidates dropped by either check, or that fail §5 verification
/// outright with a **permanent** error (`AcdpError::is_transient() ==
/// false`) — including self-signed "revocations", which are at most a
/// hint (§5 step 2) — are omitted from the return value: returning a
/// typed error for one bad or off-scope body would let anyone poison
/// the whole discovery result for every caller — a cheap DoS on the
/// very helper meant to defend against DoS. Dropped candidates are not
/// silent, though: with the `tracing` feature enabled, each one is
/// surfaced via a `tracing::warn!` recording the publisher, trust
/// class, and `ctx_id` of the dropped candidate and which filter
/// dropped it — RFC-ACDP-0014 §13's first-named mitigation,
/// "surfacing which DID issued each acted-upon revocation." A caller
/// wanting them in-band, or building without `tracing`, has the
/// composable primitives directly:
/// [`RegistryClient::search`](crate::RegistryClient::search),
/// [`verify_revocation_body`], and [`KeyRevocation::from_body`].
///
/// Superseded revocations are queried too: the §4 earliest-boundary
/// rule needs the whole lineage. **Retracted revocations are queried as
/// a third status pass** (RFC-ACDP-0013 §8.2 makes `status=retracted`
/// available for exactly this): if every member of a revocation lineage
/// has been retracted, no `active`/`superseded` search pass returns
/// anything to seed the lineage walk from at all — the `retracted` pass
/// is the only way to discover the `lineage_id` in that case (issue
/// #226 Phase 4). **A retracted revocation is not merely a seed for
/// finding the rest of the lineage**: once verified it is pushed into
/// the returned `Vec` exactly like any other member, so it still
/// permanently constrains [`effective_boundary`]'s earliest-`T` fold.
/// This is deliberate, fail-closed behavior, not an oversight — a
/// registry cannot erase a revocation's effect merely by retracting it
/// — and it matches the private lineage walk underneath, which never
/// filtered on `registry_state.status` in the first place.
///
/// **Error contract.** In addition to the errors documented per-step
/// above, this function returns
/// [`AcdpError::SearchTruncated`] in two cases, both hard fail-closed —
/// never a silently partial `Vec`: (1) any one `(type_form, status)`
/// search pass exhausts `MAX_SEARCH_PAGES` while a `next_cursor` still
/// remains, or (2) the total number of distinct candidate
/// `lineage_id`s discovered across every search pass exceeds
/// `MAX_LINEAGE_WALKS` before the lineage walk begins. Exactly
/// `MAX_SEARCH_PAGES` full pages whose last page's `next_cursor` is
/// `None` is a *complete* result, not truncated, and returns `Ok`
/// normally.
///
/// **`agent_id` is matched by exact bytes, not normalized.**
/// [`AgentDid`] derives `PartialEq` as plain string equality, and
/// [`AgentDid::parse`] allows uppercase in the method-specific id —
/// only the DID *method* is constrained to lowercase (a mismatched
/// case there is rejected with `SchemaViolation`, not normalized) — so
/// `did:web:Agents.example.com` and `did:web:agents.example.com` are
/// both schema-valid and unequal here.
/// Passing an `agent_id` that differs only in case from the one a body
/// was actually published under means every candidate is dropped by
/// filter (1) and this function returns `Ok(vec![])` — a silent "no
/// revocations found", indistinguishable from the honest empty case.
/// Pass the exact DID bytes the producer publishes under (e.g. from a
/// verified body's `agent_id`, not a hand-typed or config-sourced
/// variant). `agent_id` is schema-parsed at entry so a malformed DID
/// fails loudly instead of silently returning empty.
///
/// **The honest caveat (§8), unchanged by the above:** search is served
/// by the registry, and a malicious registry can hide a revocation
/// exactly as it can hide any context — an empty result is *not*
/// evidence of absence, and a registry colluding with a key thief can
/// serve the stolen key's contexts while suppressing this signal.
/// Within the protocol the systemic mitigation is the RFC-ACDP-0009
/// §2.11 append-only transparency log (RFC-ACDP-0012); until it is
/// deployed, query more than one vantage where the stakes warrant it,
/// and remember that revocations are self-contained signed contexts —
/// out-of-band delivery verifies identically and is the one channel a
/// registry cannot suppress.
///
/// **No independent binding of the returned `ctx_id`.** Each result is
/// retrieved by the `ctx_id` the search response named; nothing here
/// re-derives or independently confirms that id. The publisher filter
/// above catches a registry substituting a *different producer's*
/// revocation, but a registry that returns `agent_id`'s own *wrong*
/// revocation body for a listed `ctx_id` is not detected by this
/// function. That is benign today only because the §4 earliest-`T`
/// rule makes any genuine revocation of `agent_id` conservative to
/// apply regardless of which one is returned — a future reader must
/// not assume the id-to-body binding is actually checked.
///
/// Registry-attested revocations (§6) are published under the
/// *registry's* DID, not the producer's, so this producer-scoped query
/// never returns them (filter 2 above, in addition to the search scope
/// itself) — call [`find_registry_attested_revocations`] for those.
///
/// **Beyond the search passes above, every distinct `lineage_id` named
/// by a search match is also walked** via the private lineage-walking
/// helper behind [`find_revocations_in_lineage`] — see that function's
/// doc for the full rationale. This recovers a lineage member a
/// `status=`-scoped search pass cannot or does not enumerate (mixed
/// `expired`/`Other` statuses, or a member a search pass has been made
/// structurally blind to) as long as at least one member of the same
/// lineage is still visible to search. Walked members are deduped
/// against search-found ones by `ctx_id` and pass through the same
/// publisher/trust-class filter as above.
///
/// **A failure walking any one lineage aborts the whole call.** If
/// `walk_revocation_lineage` errors for a given `lineage_id` — empty
/// response, or (per issue #226 Phase 3) a registry-served member set
/// that does not include the `ctx_id` a search match actually named
/// for it — that error propagates via `?` and this function returns
/// `Err` rather than a partial `Vec`. A caller cannot distinguish a
/// `Vec` that omits a compromise window from one that is complete, and
/// that `Vec` feeds straight into [`effective_boundary`]'s `.min()`
/// over `compromised_since` (RFC-ACDP-0014 §4): silently dropping a
/// member with an earlier boundary would move the effective boundary
/// later, and dropping an entire lineage would make revocation
/// enforcement inert for it — exactly the "quietly shrink a compromise
/// window" outcome §4 forbids, and exactly what a hostile registry
/// gets for free by failing one lineage walk if this were scoped
/// instead of fatal. This is not a new abort lever either: the same
/// call already aborts unconditionally on `client.search` and
/// `client.retrieve` a few lines above, so failing closed here adds no
/// availability exposure this function does not already have.
///
/// **Extended by issue #248 Phase 1 ("D5") to the per-candidate
/// verification calls this function makes directly**, not only to
/// `walk_revocation_lineage`'s own errors above: a *transient*
/// [`verify_revocation_body`] failure (the candidate's DID host is
/// unreachable, rate-limited, or otherwise could not be asked) now
/// propagates via the same reasoning — an unresolved candidate could
/// have named an earlier `compromised_since` than anything already
/// found, so silently continuing is the same "quietly shrink a
/// compromise window" outcome this paragraph already rejects for a
/// failed lineage walk. Only a *permanent* verification failure (bad
/// signature, hash mismatch, schema violation, or a DID that resolves
/// but denies the key) is still dropped with a `tracing::warn!` — see
/// `walk_revocation_lineage`'s doc above for the full DoS argument for
/// why that narrower case remains safe to drop.
pub async fn find_revocations(
    client: &RegistryClient,
    resolver: &WebResolver,
    agent_id: &AgentDid,
) -> Result<Vec<KeyRevocation>, AcdpError> {
    // Schema-validate the caller's DID before it is promoted from an
    // opaque search-filter string into an equality operand (filter 1
    // below) — see the exact-byte-match caveat in the doc above. This
    // does not normalize case; it only rejects a malformed DID loudly
    // instead of silently yielding an empty result.
    let agent_id = AgentDid::parse(agent_id.as_str())?;

    // Issue #257: a per-vantage freshness marker, when a cache is attached
    // AND still fresh, skips this entire lookup — zero requests issued.
    // Keyed by `(vantage, agent_id, ProducerSigned)`, never by anything
    // registry-specific: this function's scope is the producer itself.
    // `marker_fresh` is a plain-bool fast path when no cache is attached or
    // `freshness == Duration::ZERO` (the default from both
    // `RevocationDiscovery` named constructors), so this costs nothing in
    // the common case. Facts are handled separately, downstream, at
    // `verify_retrieved`'s `effective` merge — never folded in here (see
    // the wave plan's B1: this function's own failure paths below set
    // nothing but `Err`, and if facts rode in this return value they would
    // vanish on exactly the failure an attacker can induce).
    let vantage = client.authority();
    // N7 (fresh-Opus review of Phase 2): both the marker check and the
    // fact record below are gated on `Some(vantage)`, so a client whose
    // base URL has no resolvable host (`authority()` returns `None`)
    // silently makes caching a no-op for this call — unreachable in
    // practice (`RegistryClient` is always built from a parsed URL), but
    // worth signaling rather than leaving unsignalled.
    #[cfg(feature = "tracing")]
    if vantage.is_none() && client.revocation_cache().is_some() {
        tracing::warn!(
            "find_revocations: a RevocationCache is attached but client.authority() is None \
             — caching is silently inert for this call"
        );
    }
    if let (Some((cache, freshness)), Some(vantage)) =
        (client.revocation_cache(), vantage.as_deref())
    {
        if cache.marker_fresh(
            vantage,
            agent_id.as_str(),
            RevocationTrustClass::ProducerSigned,
            freshness,
        ) {
            return Ok(Vec::new());
        }
    }

    let keep = |rev: &KeyRevocation| {
        // Re-check query scope and trust class on the verified body — do
        // not trust `resp.matches`, and do not accept a producer claiming
        // to be a registry (RFC-ACDP-0014 §4, §13).
        rev.publisher == agent_id && rev.trust_class == RevocationTrustClass::ProducerSigned
    };
    let on_drop = |_rev: &KeyRevocation, _ctx_id: &CtxId, _from_lineage_walk: bool| {
        #[cfg(feature = "tracing")]
        if _from_lineage_walk {
            tracing::warn!(
                publisher = %_rev.publisher,
                trust_class = ?_rev.trust_class,
                ctx_id = %_ctx_id,
                filter = if _rev.publisher != agent_id {
                    "publisher_scope"
                } else {
                    "trust_class"
                },
                "find_revocations: dropped lineage-walk candidate outside query scope/trust class"
            );
        } else {
            tracing::warn!(
                publisher = %_rev.publisher,
                trust_class = ?_rev.trust_class,
                ctx_id = %_ctx_id,
                filter = if _rev.publisher != agent_id {
                    "publisher_scope"
                } else {
                    "trust_class"
                },
                "find_revocations: dropped candidate outside query scope/trust class"
            );
        }
    };

    let revocations = discover_revocations(
        client,
        resolver,
        DiscoveryParams {
            search_agent_id: agent_id.as_str(),
            fn_name: "find_revocations",
            identity_label: "agent_id",
            identity_value: agent_id.as_str(),
        },
        &keep,
        &on_drop,
    )
    .await?;

    // Issue #257: this point is reached only on a fully successful,
    // untruncated discovery (every early-return above is an `Err`), so
    // recording here is exactly "mint a marker only on full success" by
    // construction. `record_success` dedups `revocations` into the cached
    // fact set via `KeyRevocation`'s `Eq` and caps growth per entry — see
    // `crate::revocation_cache`.
    if let (Some((cache, _freshness)), Some(vantage)) =
        (client.revocation_cache(), vantage.as_deref())
    {
        cache.record_success(
            vantage,
            agent_id.as_str(),
            RevocationTrustClass::ProducerSigned,
            &revocations,
        );
    }
    Ok(revocations)
}

/// Discover a producer's **registry-attested** (§6) key revocations —
/// the RFC-ACDP-0014 §8 second query that [`find_revocations`]'s own
/// doc points callers at, since a producer-scoped search structurally
/// cannot return them (they are published under the *registry's*
/// `agent_id`, not the producer's).
///
/// Fetches the registry's own capabilities document (**exactly once**,
/// before the search loop — [`RegistryClient::capabilities`] issues a
/// fresh network round-trip on every call, so hoisting it above the
/// type-form × status loop bounds total cost to one capabilities fetch,
/// plus up to `6 * MAX_SEARCH_PAGES` search round-trips (three statuses
/// — `active`, `superseded`, `retracted` — × two type-forms = six
/// distinct `(type_form, status)` pairs, each independently bounded by
/// its own `MAX_SEARCH_PAGES` page cap), plus up to
/// `MAX_LINEAGE_WALKS` lineage fetches from the walk below, each capped
/// at 1 MB — rather than one capabilities fetch per candidate), then searches
/// `agent_id=<capabilities.registry_did>` for `key-revocation` (and the
/// §10 interim `acdp:key-revocation`) contexts, retrieves each match,
/// and keeps the ones that:
///
/// 1. Verify per §5 ([`verify_revocation_body`]) — schema, hash
///    recomputation, DID resolution, signature, and the §5 step 2
///    not-self-signed check;
/// 2. Name `controller` in `revoked_key_controller` (exact
///    [`AgentDid`] equality — see [`find_revocations`]'s exact-byte-match
///    caveat, which applies here identically); and
/// 3. Pass [`KeyRevocation::cross_check_registry_binding`] against the
///    authority this client actually talks to and the capabilities
///    document just fetched — RFC-ACDP-0014 §6 step 2 (`publisher`
///    must equal `capabilities.registry_did`) plus the RFC-ACDP-0011
///    §7 step 3 / RFC-ACDP-0012 §9.3 step 3 house binding (`publisher`
///    must equal `did:web:<serving_authority>`), confirming that
///    `publisher` really is the specific registry this client is
///    talking to, not merely *some* identity that appears in the
///    search response claiming registry standing over `controller`'s
///    key.
///
///    This function is what closes the *discovery* gap
///    [`find_revocations`]'s trust-class filter opened: that filter
///    excludes registry-attested revocations from its results
///    entirely (by design — a producer-scoped search cannot
///    distinguish a genuine one from a forgery), so without a
///    dedicated registry-scoped query a caller would never see a
///    genuine one at all. Filter (3) here then narrows *this*
///    function's own results — and narrows a different thing than it
///    might look like: it does **not** stop a producer forging a
///    registry attestation of its own key by setting `agent_id` to the
///    registry's DID. That forgery is already impossible one step
///    earlier — [`verify_revocation_body`] runs `Verifier::verify_body`,
///    which resolves `body.agent_id`'s DID document and verifies the
///    signature against it, so a body claiming `agent_id = <registry
///    DID>` cannot exist unless the registry's own key actually signed
///    it. What filter (3) actually rejects is a **genuinely signed
///    body published under some third DID** — another registry, or a
///    producer emitting the §4-illegal `agent_id=Q,
///    revoked_key_controller=P` shape — that a hostile or compromised
///    registry lists in the `agent_id=<registry_did>` search response
///    it serves to this client. That is the exact analog of
///    [`find_revocations`]'s filter 1, and it is real and load-bearing:
///    without it, this function would trust `publisher` merely because
///    *some* validly-signed body appeared among the search results,
///    rather than confirming it is signed by the one registry this
///    client actually talks to.
///
/// As with [`find_revocations`], candidates dropped by (2) or (3), or
/// that fail §5 outright with a **permanent** error
/// (`AcdpError::is_transient() == false`), are omitted rather than
/// surfaced as errors — a single bad or off-scope body must not poison
/// the whole discovery result. With the `tracing` feature enabled,
/// each drop is logged via `tracing::warn!` naming the publisher,
/// controller, and `ctx_id`.
///
/// **Propagates, rather than swallows, a `capabilities()` error.**
/// `CapabilitiesDocument.registry_did` is a required, non-`Option`
/// `String` with no `#[serde(default)]`
/// (`crates/acdp-types/src/capabilities.rs`), and
/// [`RegistryClient::capabilities`] runs
/// `acdp_validation::validate_capabilities` — which parses it with
/// [`acdp_types::primitives::AgentDid::parse_web`] — before returning.
/// A registry that omits `registry_did` fails deserialization; one
/// sending `""` or a non-`did:web` value fails `parse_web`. Either way
/// `capabilities()` already returns `Err`, so there is no "missing
/// `registry_did`" state for this function to special-case — it simply
/// propagates whatever `capabilities()` returns via `?`, rather than
/// mapping a failure into a silent empty vec.
///
/// **The same §8 honest caveat as [`find_revocations`] applies**: search
/// is registry-served, so an empty result is not evidence of absence.
///
/// **Retracted revocations are queried as a third status pass**, and
/// **the same [`AcdpError::SearchTruncated`] error contract applies**,
/// as [`find_revocations`] — see that function's doc for the exact
/// truncation and completeness boundary (issue #226 Phase 4). As with
/// [`find_revocations`], a retracted revocation is not seed-only: once
/// verified it is pushed into the returned `Vec` like any other member
/// and still permanently constrains [`effective_boundary`]'s
/// earliest-`T` fold — a registry cannot erase its effect by retracting
/// it.
///
/// **Beyond the search passes above, every distinct `lineage_id` named
/// by a search match is also walked** via the private lineage-walking
/// helper behind [`find_revocations_in_lineage`] — see that function's
/// doc for the full rationale. Walked members are deduped against
/// search-found ones by `ctx_id` and pass through the same
/// controller/registry-binding filter as above.
///
/// **Cost note for callers verifying many contexts.** The single
/// capabilities fetch above is hoisted *within* one call, but
/// [`RegistryClient::capabilities`] issues a fresh network round-trip
/// on every call to *this* function too — nothing here caches it across
/// calls. A caller verifying many contexts against the same registry in
/// a loop should hoist its own call to this function (or to
/// `capabilities()` directly) above that loop rather than calling it
/// once per context. An overload taking a pre-fetched capabilities
/// document can be added additively later if that turns out to matter
/// in practice.
///
/// **A failure walking any one lineage aborts the whole call** — see
/// [`find_revocations`]'s doc for the identical rationale (issue #226
/// Phase 3): a partial `Vec` is indistinguishable from a complete one
/// to the caller, and feeds the same `effective_boundary` `.min()` this
/// crate uses to enforce RFC-ACDP-0014 §4, so a dropped lineage must
/// fail the call rather than silently narrow the result. The same doc's
/// issue #248 Phase 1 ("D5") extension applies here identically: a
/// *transient* per-candidate [`verify_revocation_body`] failure in the
/// search loop below also propagates as `Err` rather than being
/// silently dropped — only a *permanent* one is dropped with a
/// `tracing::warn!`.
pub async fn find_registry_attested_revocations(
    client: &RegistryClient,
    resolver: &WebResolver,
    controller: &AgentDid,
) -> Result<Vec<KeyRevocation>, AcdpError> {
    let controller = AgentDid::parse(controller.as_str())?;

    // Issue #257: the marker check MUST precede `client.capabilities()`
    // below — that fetch is unconditional and otherwise costs one request
    // on every "suppressed" call. Keyed by `(vantage, controller,
    // RegistryAttested)` — `controller` is the producer/controller DID
    // this call was asked about, deliberately NEVER the registry's own DID
    // (`capabilities.registry_did`, not yet even fetched at this point):
    // keying by the search identity instead would let one marker suppress
    // discovery for every producer at this registry, not just this one.
    // See `find_revocations` above for the shared rationale (fast path
    // when unattached or `freshness == Duration::ZERO`; facts are handled
    // downstream in `verify_retrieved`, never folded into this return
    // value).
    let vantage = client.authority();
    // N7 (fresh-Opus review of Phase 2): see `find_revocations`'s identical
    // note — both the marker check and the fact record below are gated on
    // `Some(vantage)`, so a client with no resolvable authority silently
    // makes caching a no-op for this call.
    #[cfg(feature = "tracing")]
    if vantage.is_none() && client.revocation_cache().is_some() {
        tracing::warn!(
            "find_registry_attested_revocations: a RevocationCache is attached but \
             client.authority() is None — caching is silently inert for this call"
        );
    }
    if let (Some((cache, freshness)), Some(vantage)) =
        (client.revocation_cache(), vantage.as_deref())
    {
        if cache.marker_fresh(
            vantage,
            controller.as_str(),
            RevocationTrustClass::RegistryAttested,
            freshness,
        ) {
            return Ok(Vec::new());
        }
    }

    // Fetched exactly once, outside the type-form × status loop below —
    // see the doc above for why hoisting this is required, not
    // stylistic.
    let caps = client.capabilities().await?;
    let registry_agent_id = AgentDid::parse(caps.registry_did.as_str())?;
    let serving_authority = client
        .authority()
        .ok_or_else(|| AcdpError::SchemaViolation("registry client base URL has no host".into()))?;

    let keep = |rev: &KeyRevocation| {
        rev.revoked_key_controller == controller
            && rev
                .cross_check_registry_binding(&serving_authority, &caps.registry_did)
                .is_ok()
    };
    let on_drop = |_rev: &KeyRevocation, _ctx_id: &CtxId, _from_lineage_walk: bool| {
        #[cfg(feature = "tracing")]
        if _from_lineage_walk {
            tracing::warn!(
                publisher = %_rev.publisher,
                controller = %_rev.revoked_key_controller,
                ctx_id = %_ctx_id,
                "find_registry_attested_revocations: dropped lineage-walk \
                 candidate outside controller scope or failing \
                 registry-binding check"
            );
        } else {
            tracing::warn!(
                publisher = %_rev.publisher,
                controller = %_rev.revoked_key_controller,
                ctx_id = %_ctx_id,
                "find_registry_attested_revocations: dropped candidate \
                 outside controller scope or failing registry-binding check"
            );
        }
    };

    let revocations = discover_revocations(
        client,
        resolver,
        DiscoveryParams {
            search_agent_id: registry_agent_id.as_str(),
            fn_name: "find_registry_attested_revocations",
            identity_label: "controller",
            identity_value: controller.as_str(),
        },
        &keep,
        &on_drop,
    )
    .await?;

    // Issue #257: reached only on full, untruncated success — see
    // `find_revocations`'s identical note above. Keyed by `controller`,
    // matching the marker check at the top of this function.
    if let (Some((cache, _freshness)), Some(vantage)) =
        (client.revocation_cache(), vantage.as_deref())
    {
        cache.record_success(
            vantage,
            controller.as_str(),
            RevocationTrustClass::RegistryAttested,
            &revocations,
        );
    }
    Ok(revocations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_types::revocation::RevocationTrustClass;
    use chrono::TimeZone;

    fn rev(fp: &str, t: DateTime<Utc>) -> KeyRevocation {
        KeyRevocation {
            revoked_key_fingerprint: fp.into(),
            compromised_since: t,
            reason: None,
            revoked_key_id: None,
            revoked_key_controller: AgentDid::new("did:web:agents.example.com:p"),
            publisher: AgentDid::new("did:web:agents.example.com:p"),
            trust_class: RevocationTrustClass::ProducerSigned,
        }
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    const F: &str = "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070";

    /// §7 step 2: strictly-before-T verifies with the distinguishable
    /// pre-compromise status; §7 step 3: equal-to-T already fails.
    #[test]
    fn boundary_is_strict() {
        let t = at("2026-05-01T00:00:00.000Z");
        let revs = [rev(F, t)];
        assert_eq!(
            classify_under_revocation(&revs, F, Some(at("2026-04-30T23:59:59.999Z"))).unwrap(),
            Some(KeyAuthorization::HistoricallyAuthorizedPreCompromise)
        );
        assert!(matches!(
            classify_under_revocation(&revs, F, Some(t)),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
    }

    /// §7 step 4: no receipt-attested time → fail closed.
    #[test]
    fn no_receipt_fails_closed() {
        let revs = [rev(F, at("2026-05-01T00:00:00.000Z"))];
        assert!(matches!(
            classify_under_revocation(&revs, F, None),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
    }

    /// A revocation of some OTHER key changes nothing.
    #[test]
    fn unrelated_fingerprint_is_inert() {
        let revs = [rev(F, at("2026-05-01T00:00:00.000Z"))];
        let other = "sha256:3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f";
        assert_eq!(classify_under_revocation(&revs, other, None).unwrap(), None);
        assert_eq!(
            classify_under_revocation(&[], F, None).unwrap(),
            None,
            "no known revocations ⇒ inert"
        );
    }

    /// §4 monotonicity: the earliest T across a revocation lineage is
    /// effective — a later supersession cannot quietly shrink the
    /// window.
    #[test]
    fn earliest_boundary_wins() {
        let early = at("2026-04-01T00:00:00.000Z");
        let late = at("2026-05-01T00:00:00.000Z");
        let revs = [rev(F, late), rev(F, early)];
        // Between the two boundaries: inside the (earliest-T) window.
        assert!(matches!(
            classify_under_revocation(&revs, F, Some(at("2026-04-15T00:00:00.000Z"))),
            Err(AcdpError::KeyNotAuthorized(_))
        ));
        // Before both: pre-compromise.
        assert_eq!(
            classify_under_revocation(&revs, F, Some(at("2026-03-01T00:00:00.000Z"))).unwrap(),
            Some(KeyAuthorization::HistoricallyAuthorizedPreCompromise)
        );
    }

    #[test]
    fn pre_compromise_uses_millis() {
        // Sub-second boundaries compare at millisecond precision — the
        // canonical wire precision (RFC-ACDP-0001 §5.3).
        let t = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap()
            + chrono::Duration::milliseconds(500);
        let revs = [rev(F, t)];
        let just_before = t - chrono::Duration::milliseconds(1);
        assert_eq!(
            classify_under_revocation(&revs, F, Some(just_before)).unwrap(),
            Some(KeyAuthorization::HistoricallyAuthorizedPreCompromise)
        );
    }
}
