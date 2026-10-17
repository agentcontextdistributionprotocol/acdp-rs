//! Receipt-key status, the separate receipt verdict, and the consumer
//! lineage/origin binding (0.5.0 consumer clarifications P5–P7):
//! `rcpt-005` A–D, `rcpt-006`, `ret-003` A–D and `body-003`.

mod common;
mod world;

use std::sync::atomic::Ordering;

use acdp::client::{
    verify_revocation_context, KeyAuthorization, ReceiptPolicy, RevocationEffect, RevocationPolicy,
    VerificationPolicy, VerifiedContext,
};
use acdp::error::AcdpError;
use acdp::types::receipt::ReceiptKeyStatus;
use acdp::types::{ContextType, CtxId, FullContext};
use acdp::verify::LineageBinding;
use serde_json::json;
use world::*;

fn id(ctx: &FullContext) -> CtxId {
    ctx.body.ctx_id.clone()
}

fn both_keys() -> serde_json::Value {
    producer_doc(&[("key-1", K1), ("key-2", K2)], &["key-1", "key-2"])
}

async fn fetch(
    w: &World,
    ctx: &FullContext,
    policy: &VerificationPolicy,
) -> Result<VerifiedContext, AcdpError> {
    VerifiedContext::fetch_with_policy(&w.client(), &w.resolver(), &id(ctx), policy).await
}

/// A K2-signed revocation of K1 with the given boundary, verified.
async fn revoke_k1(w: &World, compromised_since: &str) -> acdp::types::revocation::KeyRevocation {
    let rev = w
        .publish(
            "key-2",
            K2,
            ContextType::KeyRevocation,
            Some(json!({
                "revoked_key_fingerprint": K1_FP,
                "compromised_since": compromised_since,
                "reason": "test compromise",
            })),
        )
        .await;
    verify_revocation_context(&rev, &w.resolver())
        .await
        .expect("revocation verifies")
}

// ── rcpt-005: receipt-key status ─────────────────────────────────────

/// A: receipt key in `verificationMethod` and `assertionMethod`.
#[tokio::test]
async fn rcpt_005_a_current_receipt_key() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let v = fetch(&w, &ctx, &VerificationPolicy::default())
        .await
        .unwrap();
    assert_eq!(v.receipt_key_status(), Some(ReceiptKeyStatus::Current));
    assert!(matches!(v.receipt_verdict(), Some(Ok(()))));
}

/// B: receipt key in `verificationMethod` only → valid, historical.
#[tokio::test]
async fn rcpt_005_b_historical_receipt_key() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    w.set_receipt_key(ReceiptKey::Historical);
    let v = fetch(&w, &ctx, &VerificationPolicy::default())
        .await
        .unwrap();
    assert!(v.verified_receipt().is_some());
    assert_eq!(v.receipt_key_status(), Some(ReceiptKeyStatus::Historical));
}

/// C: receipt key absent from `verificationMethod` → `invalid_receipt`.
#[tokio::test]
async fn rcpt_005_c_absent_receipt_key_is_invalid_receipt() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    w.set_receipt_key(ReceiptKey::Absent);
    let err = fetch(&w, &ctx, &VerificationPolicy::default())
        .await
        .unwrap_err();
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "{err:?}");
}

/// A historical status read from a stale cached registry document is
/// re-checked against a fresh copy once (RFC-ACDP-0001 §5.11).
#[tokio::test]
async fn rcpt_005_stale_historical_status_is_refreshed() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    w.set_receipt_key(ReceiptKey::Historical);
    let resolver = w.resolver();
    resolver.resolve(REGISTRY_DID).await.expect("prime");
    w.set_receipt_key(ReceiptKey::Current);
    let before = w.registry_did_hits.load(Ordering::SeqCst);
    let v = VerifiedContext::fetch_with_policy(
        &w.client(),
        &resolver,
        &id(&ctx),
        &VerificationPolicy::default(),
    )
    .await
    .unwrap();
    assert_eq!(v.receipt_key_status(), Some(ReceiptKeyStatus::Current));
    assert_eq!(w.registry_did_hits.load(Ordering::SeqCst), before + 1);
}

/// D: a K1-signed context placed before T only by a *historical*
/// receipt key fails closed (unplaceable) under the strict default; a
/// current receipt key places it; the named opt-in restores placement.
#[tokio::test]
async fn rcpt_005_d_historical_receipt_key_cannot_place_pre_t() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let revocation = revoke_k1(&w, "2099-01-01T00:00:00.000Z").await;
    let strict = VerificationPolicy {
        revocations: RevocationPolicy::new(vec![revocation.clone()]),
        ..VerificationPolicy::default()
    };

    // Current receipt key → pre-compromise.
    let v = fetch(&w, &ctx, &strict).await.unwrap();
    assert_eq!(
        v.key_status(),
        KeyAuthorization::HistoricallyAuthorizedPreCompromise
    );

    // Historical receipt key → unplaceable, fail closed.
    w.set_receipt_key(ReceiptKey::Historical);
    let err = fetch(&w, &ctx, &strict).await.unwrap_err();
    match &err {
        AcdpError::KeyRevoked(r) => {
            assert_eq!(r.effect, RevocationEffect::Unplaceable, "{err:?}");
            assert!(r.placement.is_some(), "placed, but by a historical key");
            assert!(r.detail.contains("historical receipt key"), "{err:?}");
        }
        other => panic!("expected an unplaceable KeyRevoked, got {other:?}"),
    }
    assert!(err.is_key_not_authorized());

    // The explicitly named non-strict mode accepts it.
    let relaxed = VerificationPolicy {
        revocations: RevocationPolicy::new(vec![revocation])
            .accept_historical_receipt_key_for_pre_t(),
        ..VerificationPolicy::default()
    };
    let v = fetch(&w, &ctx, &relaxed).await.unwrap();
    assert_eq!(
        v.key_status(),
        KeyAuthorization::HistoricallyAuthorizedPreCompromise
    );
    assert_eq!(v.receipt_key_status(), Some(ReceiptKeyStatus::Historical));
}

/// D (no revocation): a historical receipt key still supports the
/// RFC-ACDP-0010 §10 historical-key rule for ordinary rotation.
#[tokio::test]
async fn rcpt_005_d_historical_receipt_key_supports_plain_rotation() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    w.set_doc(producer_doc(&[("key-1", K1), ("key-2", K2)], &["key-2"]));
    w.set_receipt_key(ReceiptKey::Historical);
    let v = fetch(&w, &ctx, &VerificationPolicy::default())
        .await
        .unwrap();
    assert_eq!(v.key_status(), KeyAuthorization::HistoricallyAuthorized);
    assert_eq!(v.receipt_key_status(), Some(ReceiptKeyStatus::Historical));
}

// ── rcpt-006: the receipt verdict is reported separately ─────────────

fn mismatch_receipt_ctx_id(v: &mut serde_json::Value) {
    v["registry_receipt"]["ctx_id"] =
        json!("acdp://localhost/00000000-0000-4000-8000-000000000000");
}

/// Body valid, receipt invalid: `VerifyAndReport` returns both verdicts.
#[tokio::test]
async fn rcpt_006_body_valid_receipt_invalid_reported_separately() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    w.tamper(ctx.body.ctx_id.as_str(), mismatch_receipt_ctx_id);

    let policy = VerificationPolicy {
        receipts: ReceiptPolicy::VerifyAndReport,
        ..VerificationPolicy::default()
    };
    let v = fetch(&w, &ctx, &policy).await.expect("body verdict valid");
    assert_eq!(v.key_status(), KeyAuthorization::CurrentlyAuthorized);
    assert!(
        v.verified_receipt().is_none(),
        "never presented as attested"
    );
    assert_eq!(v.receipt_key_status(), None);
    assert!(matches!(
        v.receipt_verdict(),
        Some(Err(AcdpError::InvalidReceipt(_)))
    ));

    // The report carries the same split.
    let (_, report) = VerifiedContext::fetch_report(&w.client(), &w.resolver(), &id(&ctx), &policy)
        .await
        .unwrap();
    assert!(report.signature_ok);
    assert!(matches!(
        report.receipt_verdict,
        Some(Err(AcdpError::InvalidReceipt(_)))
    ));

    // Regression: VerifyIfPresent and Require still fail closed.
    for receipts in [ReceiptPolicy::VerifyIfPresent, ReceiptPolicy::Require] {
        let policy = VerificationPolicy {
            receipts,
            ..VerificationPolicy::default()
        };
        assert!(matches!(
            fetch(&w, &ctx, &policy).await,
            Err(AcdpError::InvalidReceipt(_))
        ));
    }
}

/// A failed receipt is treated as absent: with the signer rotated out,
/// the historical-key rule is unavailable and verification fails closed.
#[tokio::test]
async fn rcpt_006_failed_receipt_disables_historical_rule() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    w.tamper(ctx.body.ctx_id.as_str(), mismatch_receipt_ctx_id);
    w.set_doc(producer_doc(&[("key-1", K1), ("key-2", K2)], &["key-2"]));
    let policy = VerificationPolicy {
        receipts: ReceiptPolicy::VerifyAndReport,
        ..VerificationPolicy::default()
    };
    let err = fetch(&w, &ctx, &policy).await.unwrap_err();
    assert!(err.is_key_not_authorized(), "{err:?}");
}

/// A failed receipt cannot place a revoked-key context either.
#[tokio::test]
async fn rcpt_006_failed_receipt_is_unplaceable() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let revocation = revoke_k1(&w, "2099-01-01T00:00:00.000Z").await;
    w.tamper(ctx.body.ctx_id.as_str(), mismatch_receipt_ctx_id);
    let policy = VerificationPolicy {
        receipts: ReceiptPolicy::VerifyAndReport,
        revocations: RevocationPolicy::new(vec![revocation]),
        ..VerificationPolicy::default()
    };
    let err = fetch(&w, &ctx, &policy).await.unwrap_err();
    match &err {
        AcdpError::KeyRevoked(r) => {
            assert_eq!(r.effect, RevocationEffect::Unplaceable, "{err:?}");
            assert_eq!(r.placement, None, "a failed receipt places nothing");
        }
        other => panic!("expected an unplaceable KeyRevoked, got {other:?}"),
    }
}

// ── ret-003 / body-003: registry-assigned bindings ───────────────────

/// A: a first version with the correct derivation is accepted.
#[tokio::test]
async fn ret_003_a_v1_derived_lineage_accepted() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let v = fetch(&w, &ctx, &VerificationPolicy::default())
        .await
        .unwrap();
    assert_eq!(v.lineage_binding(), LineageBinding::Derived);
}

/// B: a first version whose `lineage_id` derives from another `ctx_id`
/// is `schema_violation`, receipt or not.
#[tokio::test]
async fn ret_003_b_v1_wrong_lineage_rejected() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let other = w.publish("key-1", K1, ContextType::Analysis, None).await;
    w.strip_receipts.store(true, Ordering::SeqCst);
    w.tamper(ctx.body.ctx_id.as_str(), |v| {
        v["body"]["lineage_id"] = json!(other.body.lineage_id.as_str());
    });
    for receipts in [ReceiptPolicy::VerifyIfPresent, ReceiptPolicy::Ignore] {
        let policy = VerificationPolicy {
            receipts,
            ..VerificationPolicy::default()
        };
        let err = fetch(&w, &ctx, &policy).await.unwrap_err();
        assert!(
            matches!(&err, AcdpError::SchemaViolation(m) if m.contains("lineage_id")),
            "{err:?}"
        );
    }
}

/// C: a later version without a receipt is accepted with `lineage_id`
/// reported unbound; with a verified receipt it is receipt-attested.
#[tokio::test]
async fn ret_003_c_v2_lineage_binding_reported() {
    let w = World::start(both_keys()).await;
    let v1 = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let v2 = w.publish_next(&v1, "key-1", K1).await;
    assert_eq!(v2.body.version, 2);

    let v = fetch(&w, &v2, &VerificationPolicy::default())
        .await
        .unwrap();
    assert_eq!(v.lineage_binding(), LineageBinding::ReceiptAttested);

    w.strip_receipts.store(true, Ordering::SeqCst);
    let v = fetch(&w, &v2, &VerificationPolicy::default())
        .await
        .unwrap();
    assert_eq!(v.lineage_binding(), LineageBinding::Unbound);

    let (_, report) = VerifiedContext::fetch_report(
        &w.client(),
        &w.resolver(),
        &id(&v2),
        &VerificationPolicy::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.lineage_binding, Some(LineageBinding::Unbound));
}

/// D: a later version whose receipt fails RFC-ACDP-0010 §8 is treated as
/// receipt-less — accepted with `lineage_id` unbound, never attested.
#[tokio::test]
async fn ret_003_d_v2_failed_receipt_is_unbound() {
    let w = World::start(both_keys()).await;
    let v1 = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let v2 = w.publish_next(&v1, "key-1", K1).await;
    w.tamper(v2.body.ctx_id.as_str(), mismatch_receipt_ctx_id);

    let policy = VerificationPolicy {
        receipts: ReceiptPolicy::VerifyAndReport,
        ..VerificationPolicy::default()
    };
    let v = fetch(&w, &v2, &policy).await.expect("body verdict valid");
    assert_eq!(v.lineage_binding(), LineageBinding::Unbound);
    assert!(matches!(
        v.receipt_verdict(),
        Some(Err(AcdpError::InvalidReceipt(_)))
    ));
}

/// body-003: `origin_registry` ≠ the `ctx_id` authority → rejected.
#[tokio::test]
async fn body_003_origin_registry_mismatch_rejected() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    w.strip_receipts.store(true, Ordering::SeqCst);
    w.tamper(ctx.body.ctx_id.as_str(), |v| {
        v["body"]["origin_registry"] = json!("evil.example.com");
    });
    let err = fetch(&w, &ctx, &VerificationPolicy::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AcdpError::SchemaViolation(m) if m.contains("origin_registry")),
        "{err:?}"
    );
}
