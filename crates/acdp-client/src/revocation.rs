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
/// A member that fails §5 verification is skipped exactly as in the
/// existing search-driven loop — attacker-injected garbage in a lineage
/// must not poison the set — logged via `tracing::warn!` when the
/// `tracing` feature is enabled.
///
/// **Fails closed, rather than returning an empty vec, when the
/// lineage itself has no members at all.** The reference registry
/// returns `Ok(vec![])` for an unrecognized `lineage_id`
/// (`crates/acdp-server/src/registry/store.rs`), so an empty response
/// here for a `lineage_id` a live search match just named is the
/// realistic hostile-or-eventually-consistent shape, not an honest
/// "nothing here" — the caller must not silently continue with a
/// partial revocation set. A genuine 404 or transport error from
/// `client.lineage` propagates unchanged.
///
/// This is the neutral building block: no trust-class or publisher
/// filter is applied here. [`find_revocations_in_lineage`] is a thin
/// wrapper for a caller that wants every verified member regardless of
/// scope; [`find_revocations`] and [`find_registry_attested_revocations`]
/// each apply their own (different) scope filter to the members this
/// returns.
async fn walk_revocation_lineage(
    client: &RegistryClient,
    resolver: &WebResolver,
    lineage_id: &LineageId,
) -> Result<Vec<(CtxId, KeyRevocation)>, AcdpError> {
    let members = client.lineage(lineage_id).await?;
    if members.is_empty() {
        return Err(AcdpError::NotFound(format!(
            "lineage {} named by a search match has no members on this registry \
             (unknown or empty lineage) — an empty response for a lineage a live \
             search match just named is treated as a discovery failure, not an \
             honest \"nothing here\": never silently continue with a partial \
             revocation set",
            lineage_id.as_str(),
        )));
    }
    let mut out = Vec::with_capacity(members.len());
    for ctx in members {
        match verify_revocation_body(&ctx.body, resolver).await {
            Ok(rev) => out.push((ctx.body.ctx_id.clone(), rev)),
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
    Ok(walk_revocation_lineage(client, resolver, lineage_id)
        .await?
        .into_iter()
        .map(|(_, rev)| rev)
        .collect())
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
/// outright — including self-signed "revocations", which are at most a
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
/// rule needs the whole lineage.
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

    let mut revocations = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut lineage_ids = std::collections::HashSet::new();

    for type_form in ["key-revocation", "acdp:key-revocation"] {
        // Revocations are permanent but supersedable; the registry
        // defaults search to status=active, so ask for both explicitly.
        for status in ["active", "superseded"] {
            let mut params = SearchParamsBuilder::new()
                .context_type(type_form)
                .agent_id(agent_id.as_str())
                .status(status)
                .limit(100)
                .build();
            for _page in 0..MAX_SEARCH_PAGES {
                let resp = client.search(&params).await?;
                for m in &resp.matches {
                    // Free — no extra round trip: every match names its
                    // own lineage, walked below regardless of whether
                    // this particular ctx_id turns out to be new.
                    lineage_ids.insert(m.lineage_id.clone());
                    if !seen.insert(m.ctx_id.as_str().to_string()) {
                        continue;
                    }
                    let ctx = client.retrieve(&m.ctx_id).await?;
                    if let Ok(rev) = verify_revocation_body(&ctx.body, resolver).await {
                        // Re-check query scope and trust class on the
                        // verified body — do not trust `resp.matches`,
                        // and do not accept a producer claiming to be
                        // a registry (RFC-ACDP-0014 §4, §13).
                        if rev.publisher == agent_id
                            && rev.trust_class == RevocationTrustClass::ProducerSigned
                        {
                            revocations.push(rev);
                        } else {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                publisher = %rev.publisher,
                                trust_class = ?rev.trust_class,
                                ctx_id = %m.ctx_id,
                                filter = if rev.publisher != agent_id {
                                    "publisher_scope"
                                } else {
                                    "trust_class"
                                },
                                "find_revocations: dropped candidate outside query scope/trust class"
                            );
                        }
                    }
                }
                match resp.next_cursor {
                    Some(cursor) => params.cursor = Some(cursor),
                    None => break,
                }
            }
        }
    }

    // The lineage walk: recovers members a search pass cannot or does
    // not enumerate. Each candidate lineage is fetched at most once
    // (deduped above); an error from the walk (including the
    // empty/unknown-lineage fail-closed case) propagates and aborts
    // this whole call — never continue with a partial revocation set.
    for lineage_id in lineage_ids {
        let walked = walk_revocation_lineage(client, resolver, &lineage_id).await?;
        for (ctx_id, rev) in walked {
            if !seen.insert(ctx_id.as_str().to_string()) {
                continue;
            }
            if rev.publisher == agent_id && rev.trust_class == RevocationTrustClass::ProducerSigned
            {
                revocations.push(rev);
            } else {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    publisher = %rev.publisher,
                    trust_class = ?rev.trust_class,
                    ctx_id = %ctx_id.as_str(),
                    filter = if rev.publisher != agent_id {
                        "publisher_scope"
                    } else {
                        "trust_class"
                    },
                    "find_revocations: dropped lineage-walk candidate outside query scope/trust class"
                );
            }
        }
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
/// type-form × status loop bounds total cost to one capabilities fetch
/// plus up to `2 * MAX_SEARCH_PAGES` search round-trips rather than
/// one capabilities fetch per candidate), then searches
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
/// that fail §5 outright, are omitted rather than surfaced as errors —
/// a single bad or off-scope body must not poison the whole discovery
/// result. With the `tracing` feature enabled, each drop is logged via
/// `tracing::warn!` naming the publisher, controller, and `ctx_id`.
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
pub async fn find_registry_attested_revocations(
    client: &RegistryClient,
    resolver: &WebResolver,
    controller: &AgentDid,
) -> Result<Vec<KeyRevocation>, AcdpError> {
    let controller = AgentDid::parse(controller.as_str())?;

    // Fetched exactly once, outside the type-form × status loop below —
    // see the doc above for why hoisting this is required, not
    // stylistic.
    let caps = client.capabilities().await?;
    let registry_agent_id = AgentDid::parse(caps.registry_did.as_str())?;
    let serving_authority = client
        .authority()
        .ok_or_else(|| AcdpError::SchemaViolation("registry client base URL has no host".into()))?;

    let mut revocations = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut lineage_ids = std::collections::HashSet::new();

    for type_form in ["key-revocation", "acdp:key-revocation"] {
        // Revocations are permanent but supersedable; the registry
        // defaults search to status=active, so ask for both explicitly.
        for status in ["active", "superseded"] {
            let mut params = SearchParamsBuilder::new()
                .context_type(type_form)
                .agent_id(registry_agent_id.as_str())
                .status(status)
                .limit(100)
                .build();
            for _page in 0..MAX_SEARCH_PAGES {
                let resp = client.search(&params).await?;
                for m in &resp.matches {
                    // Free — no extra round trip: every match names its
                    // own lineage, walked below regardless of whether
                    // this particular ctx_id turns out to be new.
                    lineage_ids.insert(m.lineage_id.clone());
                    if !seen.insert(m.ctx_id.as_str().to_string()) {
                        continue;
                    }
                    let ctx = client.retrieve(&m.ctx_id).await?;
                    if let Ok(rev) = verify_revocation_body(&ctx.body, resolver).await {
                        if rev.revoked_key_controller == controller
                            && rev
                                .cross_check_registry_binding(
                                    &serving_authority,
                                    &caps.registry_did,
                                )
                                .is_ok()
                        {
                            revocations.push(rev);
                        } else {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                publisher = %rev.publisher,
                                controller = %rev.revoked_key_controller,
                                ctx_id = %m.ctx_id,
                                "find_registry_attested_revocations: dropped candidate \
                                 outside controller scope or failing registry-binding check"
                            );
                        }
                    }
                }
                match resp.next_cursor {
                    Some(cursor) => params.cursor = Some(cursor),
                    None => break,
                }
            }
        }
    }

    // The lineage walk: recovers members a search pass cannot or does
    // not enumerate — see `find_revocations_in_lineage`'s doc for the
    // full rationale. Each candidate lineage is fetched at most once
    // (deduped above); a walk error (including the empty/unknown-lineage
    // fail-closed case) propagates and aborts this whole call — never
    // continue with a partial revocation set.
    for lineage_id in lineage_ids {
        let walked = walk_revocation_lineage(client, resolver, &lineage_id).await?;
        for (ctx_id, rev) in walked {
            if !seen.insert(ctx_id.as_str().to_string()) {
                continue;
            }
            if rev.revoked_key_controller == controller
                && rev
                    .cross_check_registry_binding(&serving_authority, &caps.registry_did)
                    .is_ok()
            {
                revocations.push(rev);
            } else {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    publisher = %rev.publisher,
                    controller = %rev.revoked_key_controller,
                    ctx_id = %ctx_id.as_str(),
                    "find_registry_attested_revocations: dropped lineage-walk candidate \
                     outside controller scope or failing registry-binding check"
                );
            }
        }
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
