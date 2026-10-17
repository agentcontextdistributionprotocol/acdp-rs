//! Typed, attributable revocation verdicts (RFC-ACDP-0014 §7/§8, 0.5.0
//! "Attribution", "Producer scope", "Discovery outcome classes",
//! "Caching") — rev-002 I/J, rev-005 F–K, rev-006 A/B, and the
//! `find_revocations_verdict` re-check entry point.
//!
//! Every revocation discovered here is a real, signed, receipt-bearing
//! context served by the shared in-process world; caller-supplied
//! (`known`) revocations are typed literals so producer scope can be
//! exercised against issuers the world does not host.

mod common;
mod world;

use std::time::Duration;

use acdp::client::{
    find_revocations_verdict, DiscoveryFailurePolicy, KeyAuthorization, RevocationCache,
    RevocationDiscovery, RevocationEffect, RevocationPolicy, RevocationSource, RevocationVerdict,
    UnknownReason, VerificationPolicy, VerifiedContext,
};
use acdp::error::AcdpError;
use acdp::types::revocation::{KeyRevocation, RevocationTrustClass};
use acdp::types::{AgentDid, ContextType, FullContext};
use chrono::{DateTime, Utc};
use serde_json::json;
use world::*;

const PAST: &str = "2026-05-01T00:00:00.000Z";
const FUTURE: &str = "2099-01-01T00:00:00.000Z";
const MALLORY: &str = "did:web:localhost:mallory";

fn both_keys() -> serde_json::Value {
    producer_doc(&[("key-1", K1), ("key-2", K2)], &["key-1", "key-2"])
}

fn ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

/// A world with one K1-signed analysis context (published first, so the
/// publish gate never sees a revocation).
async fn world() -> (World, FullContext) {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    (w, ctx)
}

/// Publish a K2-signed revocation of K1 with boundary `t`; discovery
/// finds it through search.
async fn publish_revocation(w: &World, t: &str) -> FullContext {
    w.publish(
        "key-2",
        K2,
        ContextType::KeyRevocation,
        Some(json!({
            "revoked_key_fingerprint": K1_FP,
            "compromised_since": t,
            "reason": "test compromise",
        })),
    )
    .await
}

fn literal(issuer: &str, controller: &str, class: RevocationTrustClass, t: &str) -> KeyRevocation {
    KeyRevocation {
        revoked_key_fingerprint: K1_FP.to_string(),
        compromised_since: ts(t),
        reason: None,
        revoked_key_id: None,
        revoked_key_controller: AgentDid::new(controller),
        publisher: AgentDid::new(issuer),
        trust_class: class,
        ctx_id: None,
    }
}

fn discovering(on_failure: DiscoveryFailurePolicy) -> RevocationDiscovery {
    let mut d = RevocationDiscovery::producer_signed_only();
    d.on_failure = on_failure;
    d
}

fn policy(revocations: RevocationPolicy) -> VerificationPolicy {
    VerificationPolicy {
        revocations,
        ..VerificationPolicy::default()
    }
}

async fn fetch(
    w: &World,
    client: &acdp::client::RegistryClient,
    ctx: &FullContext,
    policy: &VerificationPolicy,
) -> Result<VerifiedContext, AcdpError> {
    VerifiedContext::fetch_with_policy(client, &w.resolver(), &ctx.body.ctx_id, policy).await
}

fn expect_unknown(err: &AcdpError, want: UnknownReason) {
    match err {
        AcdpError::RevocationUnknown { reason, .. } => assert_eq!(*reason, want, "{err}"),
        other => panic!("expected RevocationUnknown({want}), got {other:?}"),
    }
    assert_eq!(err.unknown_reason(), want);
    assert_eq!(err.is_transient(), want == UnknownReason::Transient);
    assert!(err.to_string().contains(want.as_str()), "{err}");
}

// ── rev-005 F–H: unknown is typed, never not-revoked ─────────────────

/// Drive one discovery failure under both failure policies: `FailClosed`
/// surfaces `RevocationUnknown{reason}`; `ProceedWithKnown` yields a
/// context whose verdict is `Unknown{reason}` — never `NotRevoked`.
async fn assert_unknown_both_policies(mode: SearchMode, want: UnknownReason) {
    let (w, ctx) = world().await;
    w.set_search_mode(mode);
    let client = w.client();

    let closed = policy(
        RevocationPolicy::default().with_discovery(discovering(DiscoveryFailurePolicy::FailClosed)),
    );
    let err = fetch(&w, &client, &ctx, &closed).await.unwrap_err();
    expect_unknown(&err, want);

    let open = policy(
        RevocationPolicy::default()
            .with_discovery(discovering(DiscoveryFailurePolicy::ProceedWithKnown)),
    );
    let v = fetch(&w, &client, &ctx, &open).await.expect("proceeds");
    assert_eq!(v.revocation_verdict().unknown_reason(), Some(want));
    assert!(!matches!(
        v.revocation_verdict(),
        RevocationVerdict::NotRevoked { .. }
    ));
    expect_unknown(v.revocation_discovery_failure().expect("carried"), want);

    // The report family carries the same verdict.
    let (_, report) =
        VerifiedContext::fetch_report(&client, &w.resolver(), &ctx.body.ctx_id, &open)
            .await
            .unwrap();
    assert_eq!(
        report.revocation_verdict.and_then(|v| v.unknown_reason()),
        Some(want)
    );
}

/// F: a page cap hit while `next_cursor` remains is truncation, not
/// completeness.
#[tokio::test]
async fn rev_005_f_page_cap_is_truncated() {
    assert_unknown_both_policies(SearchMode::Paginate, UnknownReason::Truncated).await;
}

/// G: a vantage refusing anonymous reads (403 `not_authorized`) is
/// unanswerable.
#[tokio::test]
async fn rev_005_g_not_authorized_is_unanswerable() {
    assert_unknown_both_policies(SearchMode::Status(403), UnknownReason::Unanswerable).await;
}

/// H: a vantage without search (501 `not_implemented`) is unanswerable.
#[tokio::test]
async fn rev_005_h_not_implemented_is_unanswerable() {
    assert_unknown_both_policies(SearchMode::Status(501), UnknownReason::Unanswerable).await;
}

/// A registry-side failure is transient — and only that reason is.
#[tokio::test]
async fn rev_005_registry_failure_is_transient() {
    assert_unknown_both_policies(SearchMode::Status(503), UnknownReason::Transient).await;
}

/// The discovery deadline is transient.
#[tokio::test]
async fn rev_005_deadline_is_transient() {
    let (w, ctx) = world().await;
    let mut d = discovering(DiscoveryFailurePolicy::FailClosed);
    d.total_timeout = Duration::from_nanos(1);
    let err = fetch(
        &w,
        &w.client(),
        &ctx,
        &policy(RevocationPolicy::default().with_discovery(d)),
    )
    .await
    .unwrap_err();
    expect_unknown(&err, UnknownReason::Transient);
}

/// A complete discovery with nothing found is `NotRevoked { complete }`.
#[tokio::test]
async fn rev_005_complete_absence_is_not_revoked_complete() {
    let (w, ctx) = world().await;
    let v = fetch(
        &w,
        &w.client(),
        &ctx,
        &policy(
            RevocationPolicy::default().with_discovery(RevocationDiscovery::producer_signed_only()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        v.revocation_verdict(),
        &RevocationVerdict::NotRevoked {
            complete: true,
            registry_attested_checked: false,
            observed_at: None,
        }
    );

    // Without discovery, absence is reported as incomplete.
    let v = fetch(&w, &w.client(), &ctx, &VerificationPolicy::default())
        .await
        .unwrap();
    assert!(matches!(
        v.revocation_verdict(),
        RevocationVerdict::NotRevoked {
            complete: false,
            ..
        }
    ));
}

// ── rev-002 I/J: attributed refusals ──────────────────────────────────

/// I: a discovered, in-scope revocation with the context placed at/after
/// T refuses with `KeyRevoked`, attributed end to end.
#[tokio::test]
async fn rev_002_i_key_revoked_is_attributed() {
    let (w, ctx) = world().await;
    let rev = publish_revocation(&w, PAST).await;
    let err = fetch(
        &w,
        &w.client(),
        &ctx,
        &policy(
            RevocationPolicy::default().with_discovery(RevocationDiscovery::producer_signed_only()),
        ),
    )
    .await
    .unwrap_err();
    assert!(err.is_key_not_authorized());
    assert!(!err.is_transient());
    let r = err.revocation_refusal().expect("attributed");
    assert_eq!(r.effect, RevocationEffect::Revoked);
    assert_eq!(r.signing_key_fingerprint, K1_FP);
    assert_eq!(r.boundary, ts(PAST));
    assert!(r.placement.expect("receipt placed it") >= r.boundary);
    assert_eq!(r.revocation.issuer, agent());
    assert_eq!(
        r.revocation.trust_class,
        RevocationTrustClass::ProducerSigned
    );
    assert_eq!(r.revocation.ctx_id.as_ref(), Some(&rev.body.ctx_id));
    assert_eq!(
        r.revocation.source,
        RevocationSource::Discovered {
            authority: REGISTRY_AUTHORITY.to_string()
        }
    );
    let shown = err.to_string();
    assert!(
        shown.contains("revoked") && shown.contains(AGENT),
        "{shown}"
    );
}

/// J: without a receipt there is no placement — `Unplaceable`, distinct
/// from `Revoked`.
#[tokio::test]
async fn rev_002_j_no_receipt_is_unplaceable_not_revoked() {
    let (w, ctx) = world().await;
    w.strip_receipts
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let err = fetch(
        &w,
        &w.client(),
        &ctx,
        &policy(RevocationPolicy::new(vec![literal(
            AGENT,
            AGENT,
            RevocationTrustClass::ProducerSigned,
            FUTURE,
        )])),
    )
    .await
    .unwrap_err();
    let r = err.revocation_refusal().expect("attributed");
    assert_eq!(r.effect, RevocationEffect::Unplaceable);
    assert_eq!(r.placement, None);
    assert_eq!(r.revocation.source, RevocationSource::Known);
}

/// Placed before T: accepted, reported as pre-compromise.
#[tokio::test]
async fn rev_002_pre_compromise_is_reported() {
    let (w, ctx) = world().await;
    publish_revocation(&w, FUTURE).await;
    let v = fetch(
        &w,
        &w.client(),
        &ctx,
        &policy(
            RevocationPolicy::default().with_discovery(RevocationDiscovery::producer_signed_only()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        v.key_status(),
        KeyAuthorization::HistoricallyAuthorizedPreCompromise
    );
    match v.revocation_verdict() {
        RevocationVerdict::Revoked {
            effect: RevocationEffect::PreCompromise,
            boundary,
            ..
        } => assert_eq!(*boundary, ts(FUTURE)),
        other => panic!("expected pre-compromise, got {other:?}"),
    }
}

/// The earliest in-scope boundary fixes T (§4).
#[tokio::test]
async fn rev_002_earliest_in_scope_boundary_wins() {
    let (w, ctx) = world().await;
    let err = fetch(
        &w,
        &w.client(),
        &ctx,
        &policy(RevocationPolicy::new(vec![
            literal(AGENT, AGENT, RevocationTrustClass::ProducerSigned, FUTURE),
            literal(AGENT, AGENT, RevocationTrustClass::ProducerSigned, PAST),
        ])),
    )
    .await
    .unwrap_err();
    let r = err.revocation_refusal().expect("attributed");
    assert_eq!(r.boundary, ts(PAST));
    assert_eq!(r.revocation.compromised_since, ts(PAST));
}

/// A definitive refusal outranks an unfinished discovery: a known
/// revocation refuses even when discovery is `unknown`.
#[tokio::test]
async fn refusal_outranks_unknown() {
    let (w, ctx) = world().await;
    w.set_search_mode(SearchMode::Status(503));
    let err = fetch(
        &w,
        &w.client(),
        &ctx,
        &policy(
            RevocationPolicy::new(vec![literal(
                AGENT,
                AGENT,
                RevocationTrustClass::ProducerSigned,
                PAST,
            )])
            .with_discovery(discovering(DiscoveryFailurePolicy::FailClosed)),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AcdpError::KeyRevoked(_)), "{err:?}");
}

/// An acceptance does not outrank `unknown`: an unfinished discovery could
/// hide an earlier boundary. Under `ProceedWithKnown` the context still
/// verifies under the historical rule, with an `Unknown` verdict.
#[tokio::test]
async fn unknown_outranks_pre_compromise() {
    let (w, ctx) = world().await;
    w.set_search_mode(SearchMode::Status(403));
    let known = || {
        RevocationPolicy::new(vec![literal(
            AGENT,
            AGENT,
            RevocationTrustClass::ProducerSigned,
            FUTURE,
        )])
    };
    let err = fetch(
        &w,
        &w.client(),
        &ctx,
        &policy(known().with_discovery(discovering(DiscoveryFailurePolicy::FailClosed))),
    )
    .await
    .unwrap_err();
    expect_unknown(&err, UnknownReason::Unanswerable);

    let v = fetch(
        &w,
        &w.client(),
        &ctx,
        &policy(known().with_discovery(discovering(DiscoveryFailurePolicy::ProceedWithKnown))),
    )
    .await
    .unwrap();
    assert_eq!(
        v.revocation_verdict().unknown_reason(),
        Some(UnknownReason::Unanswerable)
    );
    assert_eq!(
        v.key_status(),
        KeyAuthorization::HistoricallyAuthorizedPreCompromise
    );
}

// ── rev-006: producer scope ───────────────────────────────────────────

/// A: revocations that do not speak for the producer never change its
/// verdict; they are reported as hints.
#[tokio::test]
async fn rev_006_a_out_of_scope_revocations_are_hints_only() {
    let (w, ctx) = world().await;
    let foreign_signed = literal(MALLORY, MALLORY, RevocationTrustClass::ProducerSigned, PAST);
    let foreign_attested = literal(
        REGISTRY_DID,
        MALLORY,
        RevocationTrustClass::RegistryAttested,
        PAST,
    );
    let pol = policy(RevocationPolicy::new(vec![
        foreign_signed.clone(),
        foreign_attested.clone(),
    ]));
    let v = fetch(&w, &w.client(), &ctx, &pol)
        .await
        .expect("out-of-scope revocations MUST NOT refuse");
    assert_eq!(v.key_status(), KeyAuthorization::CurrentlyAuthorized);
    assert!(matches!(
        v.revocation_verdict(),
        RevocationVerdict::NotRevoked { .. }
    ));
    assert_eq!(
        v.revocation_hints(),
        &[
            foreign_signed.sourced(RevocationSource::Known),
            foreign_attested.sourced(RevocationSource::Known),
        ]
    );

    let (_, report) =
        VerifiedContext::fetch_report(&w.client(), &w.resolver(), &ctx.body.ctx_id, &pol)
            .await
            .unwrap();
    assert_eq!(report.revocation_hints.len(), 2);
}

/// B: a registry attestation whose controller is the producer applies,
/// and is attributed to its class.
#[tokio::test]
async fn rev_006_b_in_scope_registry_attestation_applies() {
    let (w, ctx) = world().await;
    let err = fetch(
        &w,
        &w.client(),
        &ctx,
        &policy(RevocationPolicy::new(vec![literal(
            REGISTRY_DID,
            AGENT,
            RevocationTrustClass::RegistryAttested,
            PAST,
        )])),
    )
    .await
    .unwrap_err();
    let r = err.revocation_refusal().expect("attributed");
    assert_eq!(
        r.revocation.trust_class,
        RevocationTrustClass::RegistryAttested
    );
    assert_eq!(r.revocation.issuer.as_str(), REGISTRY_DID);
    assert_eq!(r.revocation.revoked_key_controller, agent());
}

// ── rev-005 I–K: caching ──────────────────────────────────────────────

/// I: `unknown` is never cached — a repeat lookup after an unknown runs
/// again; a complete absence is cached and reports when it was observed.
#[tokio::test]
async fn rev_005_i_unknown_is_never_cached() {
    let (w, ctx) = world().await;
    let client = w.client().with_revocation_cache(RevocationCache::new());
    let pol = policy(
        RevocationPolicy::default()
            .with_discovery(discovering(DiscoveryFailurePolicy::ProceedWithKnown)),
    );

    w.set_search_mode(SearchMode::Status(503));
    let v = fetch(&w, &client, &ctx, &pol).await.unwrap();
    assert!(v.revocation_verdict().is_unknown());
    let after_unknown = w.search_hits();

    w.set_search_mode(SearchMode::Normal);
    let v = fetch(&w, &client, &ctx, &pol).await.unwrap();
    assert!(
        w.search_hits() > after_unknown,
        "an unknown outcome minted no marker: the next call searched"
    );
    assert_eq!(
        v.revocation_verdict(),
        &RevocationVerdict::NotRevoked {
            complete: true,
            registry_attested_checked: false,
            observed_at: None,
        }
    );
    let after_live = w.search_hits();

    // J: the complete absence is now cached for the default 300 s.
    let v = fetch(&w, &client, &ctx, &pol).await.unwrap();
    assert_eq!(w.search_hits(), after_live, "fresh marker suppresses");
    assert!(matches!(
        v.revocation_verdict(),
        RevocationVerdict::NotRevoked {
            complete: true,
            observed_at: Some(_),
            ..
        }
    ));
}

/// K: a verified revocation is a fact — it survives a registry that
/// stops serving it and fails every lookup, and is attributed to the
/// cache and the vantage that first verified it.
#[tokio::test]
async fn rev_005_k_verified_revocations_are_never_evicted() {
    let (w, ctx) = world().await;
    publish_revocation(&w, PAST).await;
    let client = w.client().with_revocation_cache(RevocationCache::new());
    let mut d = discovering(DiscoveryFailurePolicy::ProceedWithKnown);
    d.freshness = Duration::ZERO;
    let pol = policy(RevocationPolicy::default().with_discovery(d));

    let first = fetch(&w, &client, &ctx, &pol).await.unwrap_err();
    assert!(matches!(
        first.revocation_refusal().unwrap().revocation.source,
        RevocationSource::Discovered { .. }
    ));

    w.matches.write().unwrap().clear();
    w.lineages.write().unwrap().clear();
    w.set_search_mode(SearchMode::Status(503));
    let err = fetch(&w, &client, &ctx, &pol).await.unwrap_err();
    let r = err.revocation_refusal().expect("the fact still refuses");
    assert_eq!(
        r.revocation.source,
        RevocationSource::Cached {
            origin: REGISTRY_AUTHORITY.to_string()
        }
    );
}

// ── find_revocations_verdict: re-check without refetching ────────────

#[tokio::test]
async fn find_revocations_verdict_rechecks_without_refetching_the_context() {
    let (w, ctx) = world().await;
    let client = w.client();
    let resolver = w.resolver();
    let v = fetch(&w, &client, &ctx, &VerificationPolicy::default())
        .await
        .unwrap();
    let placement = v
        .verified_receipt()
        .map(|r| r.created_at)
        .zip(v.receipt_key_status());
    let pol =
        RevocationPolicy::default().with_discovery(RevocationDiscovery::producer_signed_only());

    let before = w.retrievals_of(ctx.body.ctx_id.as_str());
    assert!(before >= 1, "the initial fetch retrieved it");
    let clean = find_revocations_verdict(&client, &resolver, &agent(), K1_FP, placement, &pol)
        .await
        .unwrap();
    assert!(matches!(
        clean.verdict,
        RevocationVerdict::NotRevoked { complete: true, .. }
    ));
    assert!(clean.enforce().is_ok());

    publish_revocation(&w, PAST).await;
    let revoked = find_revocations_verdict(&client, &resolver, &agent(), K1_FP, placement, &pol)
        .await
        .unwrap();
    assert!(revoked.verdict.is_refusal());
    let err = revoked.enforce().unwrap_err();
    assert_eq!(
        err.revocation_refusal().unwrap().effect,
        RevocationEffect::Revoked
    );
    assert_eq!(
        w.retrievals_of(ctx.body.ctx_id.as_str()),
        before,
        "the re-check never refetched the context"
    );

    // Another key of the same producer is untouched by the revocation.
    let other =
        find_revocations_verdict(&client, &resolver, &agent(), "sha256:00", placement, &pol)
            .await
            .unwrap();
    assert!(matches!(
        other.verdict,
        RevocationVerdict::NotRevoked { .. }
    ));
}

/// `VerifiedContext::recheck_revocation` derives the signing-key
/// fingerprint and receipt placement from the verified context itself, so
/// a long-lived holder (Seam) re-checks without hand-assembling either and
/// without refetching the context.
#[tokio::test]
async fn recheck_revocation_uses_the_contexts_own_key_and_placement() {
    let (w, ctx) = world().await;
    let client = w.client();
    let resolver = w.resolver();
    let v = fetch(&w, &client, &ctx, &VerificationPolicy::default())
        .await
        .unwrap();
    let pol =
        RevocationPolicy::default().with_discovery(RevocationDiscovery::producer_signed_only());
    let before = w.retrievals_of(ctx.body.ctx_id.as_str());

    let clean = v
        .recheck_revocation(&client, &resolver, &pol)
        .await
        .unwrap();
    assert!(matches!(
        clean.verdict,
        RevocationVerdict::NotRevoked { complete: true, .. }
    ));

    // A boundary before the receipt's publish time: refused.
    publish_revocation(&w, PAST).await;
    let revoked = v
        .recheck_revocation(&client, &resolver, &pol)
        .await
        .unwrap();
    match &revoked.verdict {
        RevocationVerdict::Revoked {
            effect,
            revocation,
            placement,
            ..
        } => {
            assert_eq!(effect, &RevocationEffect::Revoked);
            assert_eq!(revocation.revoked_key_fingerprint, K1_FP);
            assert_eq!(
                placement.as_ref().copied(),
                v.verified_receipt().map(|r| r.created_at),
                "placement is the context's own verified receipt time"
            );
        }
        other => panic!("expected Revoked, got {other:?}"),
    }
    assert_eq!(w.retrievals_of(ctx.body.ctx_id.as_str()), before);
}

/// A boundary after the receipt's publish time places the context before
/// T: pre-compromise, accepted.
#[tokio::test]
async fn recheck_revocation_places_a_receipted_context_before_a_future_boundary() {
    let (w, ctx) = world().await;
    let client = w.client();
    let resolver = w.resolver();
    let v = fetch(&w, &client, &ctx, &VerificationPolicy::default())
        .await
        .unwrap();
    publish_revocation(&w, FUTURE).await;
    let pol =
        RevocationPolicy::default().with_discovery(RevocationDiscovery::producer_signed_only());
    let a = v
        .recheck_revocation(&client, &resolver, &pol)
        .await
        .unwrap();
    assert!(a.pre_compromise());
    assert!(matches!(
        a.verdict,
        RevocationVerdict::Revoked {
            effect: RevocationEffect::PreCompromise,
            ..
        }
    ));
    assert!(a.enforce().is_ok());
}
