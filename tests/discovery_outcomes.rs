//! RFC-ACDP-0014 §8 "Discovery outcome classes" and RFC-ACDP-0001 §5.11
//! "Caching" (0.5.0) — the rev-005 A–E, rot-002 and did-001 D scenarios.
//!
//! One in-process TLS registry serves the registry DID document, a
//! *mutable* producer DID document (so a test can rotate keys after the
//! consumer cached the old document), a mutable DID-host HTTP status,
//! search, retrieve and lineage. Every revocation is a real, signed,
//! receipt-bearing context published through `RegistryServer`.

mod common;

mod world;

use std::sync::atomic::Ordering;
use std::time::Duration;

use acdp::client::find_revocations;
use acdp::error::AcdpError;
use acdp::types::{Body, ContextType};
use acdp::verify::Verifier;
use serde_json::json;
use world::*;

// ── rot-002 / did-001 D: refresh-then-retry on a stale cache ──────────

/// rot-002: the consumer cached a document holding only K1; P adds K2
/// and publishes a K2-signed context. Verification succeeds after
/// exactly one forced re-fetch.
#[tokio::test]
async fn rot_002_new_key_verifies_after_one_forced_refetch() {
    let w = World::start(producer_doc(&[("key-1", K1)], &["key-1"])).await;
    let resolver = w.resolver();
    resolver.resolve(AGENT).await.expect("prime cache");
    let primed = w.did_hits();

    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ));
    let ctx = w.publish("key-2", K2, ContextType::Analysis, None).await;

    let before = w.did_hits();
    assert_eq!(before, primed + 1, "publish-side resolver fetched once");
    Verifier::new(&resolver)
        .verify_context(&ctx)
        .await
        .expect("K2 verifies after refresh");
    assert_eq!(w.did_hits(), before + 1, "exactly one forced re-fetch");

    // The refreshed document is cached: a second verification is free.
    Verifier::new(&resolver).verify_context(&ctx).await.unwrap();
    assert_eq!(w.did_hits(), before + 1);
}

/// rot-002 (step 5): a key present but not yet in `assertionMethod` in
/// the cached document is re-checked against a fresh copy too.
#[tokio::test]
async fn rot_002_assertion_added_after_caching_verifies() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    let ctx = w.publish("key-2", K2, ContextType::Analysis, None).await;

    let resolver = w.resolver();
    w.set_doc(producer_doc(&[("key-1", K1), ("key-2", K2)], &["key-1"]));
    resolver
        .resolve(AGENT)
        .await
        .expect("cache the not-yet-authorized doc");
    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ));

    Verifier::new(&resolver)
        .verify_context(&ctx)
        .await
        .expect("assertionMethod re-checked on a fresh copy");
}

/// did-001 D: the key is absent even after the forced re-fetch — a
/// permanent `key_resolution_failed`, after exactly one re-fetch.
#[tokio::test]
async fn did_001_d_key_absent_after_refetch_is_permanent() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    let ctx = w.publish("key-2", K2, ContextType::Analysis, None).await;
    w.set_doc(producer_doc(&[("key-1", K1)], &["key-1"]));
    let resolver = w.resolver();
    resolver.resolve(AGENT).await.unwrap();
    let before = w.did_hits();

    let err = Verifier::new(&resolver)
        .verify_context(&ctx)
        .await
        .unwrap_err();
    assert!(matches!(err, AcdpError::KeyResolution(_)), "{err:?}");
    assert!(!err.is_transient());
    assert_eq!(w.did_hits(), before + 1, "one forced re-fetch, no more");
}

/// The per-DID rate limit: once a forced re-fetch was spent, a key
/// absent from the (now stale) cached copy is NOT reported as absent —
/// it is transient (`key_resolution_unreachable`). This is the
/// attacker-burns-the-refresh-slot case: a permanent verdict here would
/// let discovery silently drop a revocation signed by a just-added key.
#[tokio::test]
async fn rate_limited_refetch_reports_absent_key_as_transient() {
    let w = World::start(producer_doc(&[("key-1", K1)], &["key-1"])).await;
    let resolver = w.resolver();
    resolver.resolve(AGENT).await.unwrap();

    // Attacker spends the forced-refresh slot with a bogus fragment.
    let bogus = resolver
        .resolve_with_fragment(AGENT, "bogus", std::time::Instant::now())
        .await
        .unwrap_err();
    assert!(matches!(bogus, AcdpError::KeyResolution(_)), "{bogus:?}");

    // Producer adds K2 and publishes; the consumer's copy is stale and
    // the slot is spent.
    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ));
    let ctx = w.publish("key-2", K2, ContextType::Analysis, None).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    let before = w.did_hits();
    let err = Verifier::new(&resolver)
        .verify_context(&ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AcdpError::KeyResolutionUnreachable(_)),
        "absence on a stale copy must be transient, got {err:?}"
    );
    assert!(err.is_transient());
    assert_eq!(w.did_hits(), before, "rate limit honored — no fetch");

    // With the limit disabled the same verification succeeds.
    let unlimited = w.resolver().with_forced_refresh_interval(Duration::ZERO);
    unlimited.resolve(AGENT).await.unwrap();
    Verifier::new(&unlimited)
        .verify_context(&ctx)
        .await
        .unwrap();
}

#[test]
fn forced_refresh_interval_defaults_to_one_hour() {
    assert_eq!(
        acdp::did::DEFAULT_FORCED_REFRESH_INTERVAL,
        Duration::from_secs(3600)
    );
}

// ── rev-005 A–E: discovery outcome classes ───────────────────────────

/// rev-005 A: the revocation is signed by K2, which P has since rotated
/// out of `assertionMethod` (still in `verificationMethod`). Its valid
/// registry receipt places the signature → revoked. The lineage-walk
/// copy carries no receipt, so the walk re-retrieves it by `ctx_id`
/// (D-4) instead of dropping or failing.
#[tokio::test]
async fn rev_005_a_rotated_out_signer_with_receipt_is_revoked() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    w.publish_revocation_of_k1("key-2", K2).await;
    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2), ("key-3", K3)],
        &["key-3"],
    ));

    let before = w.retrieve_hits.load(Ordering::SeqCst);
    let revs = find_revocations(&w.client(), &w.resolver(), &agent())
        .await
        .expect("historical arm verifies");
    assert_eq!(revs.len(), 1);
    assert_eq!(revs[0].revoked_key_fingerprint, K1_FP);
    assert!(
        w.retrieve_hits.load(Ordering::SeqCst) >= before + 2,
        "search retrieve + lineage-walk re-retrieve for the receipt"
    );
}

/// rev-005 B: same rotated-out signer, no receipt anywhere → the
/// candidate is unverifiable → discovery fails (unknown), never "not
/// revoked".
#[tokio::test]
async fn rev_005_b_rotated_out_signer_without_receipt_is_unknown() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    w.publish_revocation_of_k1("key-2", K2).await;
    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2), ("key-3", K3)],
        &["key-3"],
    ));
    w.strip_receipts.store(true, Ordering::SeqCst);

    let err = find_revocations(&w.client(), &w.resolver(), &agent())
        .await
        .expect_err("must not fold into not-revoked");
    assert!(is_unverifiable(&err), "{err:?}");
}

/// rev-005 B′: a receipt that does not verify is no better than none.
#[tokio::test]
async fn rev_005_b_tampered_receipt_is_unknown() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    let ctx = w.publish_revocation_of_k1("key-2", K2).await;
    {
        let mut contexts = w.contexts.write().unwrap();
        let v = contexts.get_mut(ctx.body.ctx_id.as_str()).unwrap();
        let sig = &mut v["registry_receipt"]["signature"]["value"];
        let s = sig.as_str().unwrap().to_string();
        let flipped = if s.starts_with('A') { "B" } else { "A" };
        *sig = json!(format!("{flipped}{}", &s[1..]));
    }
    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2), ("key-3", K3)],
        &["key-3"],
    ));
    let err = find_revocations(&w.client(), &w.resolver(), &agent())
        .await
        .expect_err("bad receipt → unknown");
    assert!(is_unverifiable(&err), "{err:?}");
}

/// rev-005 C: the producer's DID host answers 503 / 404 → the candidate
/// could not be checked → transient, unknown.
#[tokio::test]
async fn rev_005_c_did_host_failure_is_transient() {
    for code in [503u16, 404] {
        let w = World::start(producer_doc(
            &[("key-1", K1), ("key-2", K2)],
            &["key-1", "key-2"],
        ))
        .await;
        w.publish_revocation_of_k1("key-2", K2).await;
        w.did_status.store(code, Ordering::SeqCst);
        let err = find_revocations(&w.client(), &w.resolver(), &agent())
            .await
            .expect_err("DID host down → unknown");
        assert!(err.is_transient(), "HTTP {code}: {err:?}");
    }
}

/// rev-005 D: the consumer cached P's document before P added K3; the
/// K3-signed revocation verifies after one forced re-fetch → revoked.
#[tokio::test]
async fn rev_005_d_key_added_after_caching_is_revoked() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    let resolver = w.resolver();
    resolver.resolve(AGENT).await.unwrap();

    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2), ("key-3", K3)],
        &["key-2", "key-3"],
    ));
    w.publish_revocation_of_k1("key-3", K3).await;

    let revs = find_revocations(&w.client(), &resolver, &agent())
        .await
        .expect("refetch finds K3");
    assert_eq!(revs.len(), 1);
}

/// rev-005 E: K2 is absent from P's document even after a fresh fetch →
/// the candidate is permanently invalid and dropped → not revoked
/// (complete).
#[tokio::test]
async fn rev_005_e_signer_absent_after_fresh_fetch_is_dropped() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    let resolver = w.resolver();
    w.publish_revocation_of_k1("key-2", K2).await;
    w.set_doc(producer_doc(&[("key-1", K1), ("key-3", K3)], &["key-3"]));
    resolver.resolve(AGENT).await.unwrap(); // cached copy lacks K2
    let before = w.did_hits();

    let revs = find_revocations(&w.client(), &resolver, &agent())
        .await
        .expect("permanently invalid candidate is dropped, not unknown");
    assert!(revs.is_empty());
    assert_eq!(
        w.did_hits(),
        before + 1,
        "absence confirmed by exactly one forced re-fetch for the whole run \
         (search candidate + lineage-walk member share it)"
    );
}

/// Bodies the tests above publish are the shape `find_revocations`
/// sees; guard against the harness silently serving a different body.
#[tokio::test]
async fn harness_serves_published_body() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    let ctx = w.publish_revocation_of_k1("key-2", K2).await;
    let got = w.client().retrieve(&ctx.body.ctx_id).await.unwrap();
    let a: &Body = &got.body;
    assert_eq!(a.content_hash, ctx.body.content_hash);
    assert!(got.registry_receipt.is_some());
}
