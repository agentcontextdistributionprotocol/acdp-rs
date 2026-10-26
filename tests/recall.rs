//! Retraction recall, consumer side (ACDP 0.5.0 Draft, RFC-ACDP-0018,
//! profile `acdp-consumer-recall`) — behavioral bindings for `rec-006`
//! (§7 consumer verification, scenarios A–H) and `rec-007` D–E (§8.2
//! hint receiver), against the in-process TLS registry world.
//!
//! The registry-side fixtures (`rec-001..005`, `rec-007` A–C/F–H,
//! `rec-008`) bind the `acdp-registry-changes` / `-events` profiles and
//! are a registry implementation's to run.

mod common;
mod world;

use acdp::client::recall::{
    verify_change, ChangeEffect, ChangeFeed, ChangeVerdict, HeldContext, LifecycleSource,
    SeenChanges, Since,
};
use acdp::client::VerificationPolicy;
use acdp::crypto::SigningKey;
use acdp::error::AcdpError;
use acdp::types::change::{
    sign_hint, verify_hint_signature, Change, ChangeHint, ChangeKind, WatchFilter,
};
use acdp::types::lifecycle::{LifecycleEvent, LifecycleEventType};
use acdp::types::receipt::{ReceiptSigner, RegistryReceipt};
use acdp::types::{AgentDid, ContextType, EventReceipt, FullContext};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use world::*;

const RELIER_SEQ: u64 = 1042;

async fn world() -> World {
    World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await
}

fn signer() -> ReceiptSigner {
    ReceiptSigner::new(
        SigningKey::from_bytes(&RECEIPT_SEED),
        REGISTRY_DID,
        format!("{REGISTRY_DID}#receipt-key-1"),
    )
    .unwrap()
}

/// A producer-signed lifecycle event of `ctx`, `n` ms after its creation.
fn event(ctx: &FullContext, ty: LifecycleEventType, n: u8) -> Value {
    let e = LifecycleEvent::new(
        format!("00000000-0000-4000-8000-0000000000{n:02x}"),
        ctx.body.ctx_id.clone(),
        ty,
        at(ctx, n),
        agent(),
        None,
    )
    .unwrap()
    .sign_with(SigningKey::from_bytes(&K1), format!("{AGENT}#key-1"))
    .unwrap();
    serde_json::to_value(e).unwrap()
}

fn at(ctx: &FullContext, n: u8) -> DateTime<Utc> {
    ctx.body.created_at + Duration::milliseconds(i64::from(n) + 1)
}

fn event_receipt(ctx: &FullContext, raw: &Value, index: u64, n: u8) -> EventReceipt {
    signer()
        .mint_event_receipt(&ctx.body.ctx_id, raw, index, at(ctx, n))
        .unwrap()
}

/// Serve `events` (with their receipts) as `ctx`'s lifecycle state.
fn serve_events(w: &World, ctx: &FullContext, events: &[(Value, EventReceipt)]) {
    let raw: Vec<Value> = events.iter().map(|(e, _)| e.clone()).collect();
    let receipts: Vec<Value> = events
        .iter()
        .map(|(_, r)| serde_json::to_value(r).unwrap())
        .collect();
    w.tamper(ctx.body.ctx_id.as_str(), |v| {
        v["registry_state"]["lifecycle_events"] = json!(raw);
        v["registry_state"]["event_receipts"] = json!(receipts);
    });
}

fn lifecycle_change(ctx: &FullContext, raw: &Value, r: &EventReceipt) -> Change {
    Change::lifecycle(
        RELIER_SEQ,
        ctx.body.lineage_id.clone(),
        agent(),
        raw.clone(),
        r,
    )
    .unwrap()
}

fn receipt_of(ctx: &FullContext) -> RegistryReceipt {
    RegistryReceipt::from_value(ctx.registry_receipt.as_ref().expect("receipt")).unwrap()
}

async fn verify(w: &World, change: &Change, held: Option<HeldContext<'_>>) -> ChangeVerdict {
    verify_change(
        &w.client(),
        &w.resolver(),
        change,
        held,
        &VerificationPolicy::default(),
    )
    .await
    .expect("decided")
}

fn rejected(v: &ChangeVerdict) -> &AcdpError {
    v.rejection()
        .unwrap_or_else(|| panic!("expected a rejection, got {v:?}"))
}

/// The golden retraction: event 0 of the relied-on context, served.
async fn retracted_world() -> (World, FullContext, Value, EventReceipt) {
    let w = world().await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let e0 = event(&ctx, LifecycleEventType::Retracted, 0);
    let r0 = event_receipt(&ctx, &e0, 0, 0);
    serve_events(&w, &ctx, &[(e0.clone(), r0.clone())]);
    (w, ctx, e0, r0)
}

// ── rec-006: §7 consumer verification ────────────────────────────────────────

#[tokio::test]
async fn rec_006_a_valid_retraction_verifies() {
    let (w, ctx, e0, r0) = retracted_world().await;
    let change = lifecycle_change(&ctx, &e0, &r0);

    // Re-retrieval path.
    match verify(&w, &change, None).await {
        ChangeVerdict::Verified(ChangeEffect::Lifecycle {
            event,
            retracted,
            source,
        }) => {
            assert_eq!(event.event_type, LifecycleEventType::Retracted);
            assert!(retracted);
            assert_eq!(source, LifecycleSource::Retrieved);
        }
        other => panic!("expected a verified lifecycle effect, got {other:?}"),
    }
    assert_eq!(w.retrievals_of(ctx.body.ctx_id.as_str()), 1);

    // Held path: index 0 needs no earlier events, so no retrieval.
    let held = HeldContext {
        body: &ctx.body,
        events: &[],
    };
    match verify(&w, &change, Some(held)).await {
        ChangeVerdict::Verified(ChangeEffect::Lifecycle {
            retracted, source, ..
        }) => {
            assert!(retracted);
            assert_eq!(source, LifecycleSource::Held);
        }
        other => panic!("expected a verified lifecycle effect, got {other:?}"),
    }
    assert_eq!(w.retrievals_of(ctx.body.ctx_id.as_str()), 1);
}

#[tokio::test]
async fn rec_006_b_bad_event_signature_changes_nothing() {
    let (w, ctx, e0, r0) = retracted_world().await;
    let mut wire = serde_json::to_value(lifecycle_change(&ctx, &e0, &r0)).unwrap();
    let sig = wire["event"]["signature"]["value"]
        .as_str()
        .unwrap()
        .to_owned();
    let flipped = if sig.starts_with('A') { "B" } else { "A" };
    wire["event"]["signature"]["value"] = json!(format!("{flipped}{}", &sig[1..]));
    let change = Change::from_value(&wire).unwrap();
    let held = HeldContext {
        body: &ctx.body,
        events: &[],
    };
    rejected(&verify(&w, &change, Some(held)).await);
    rejected(&verify(&w, &change, None).await);
}

#[tokio::test]
async fn rec_006_c_failing_event_receipt_is_absent() {
    let (w, ctx, e0, _) = retracted_world().await;
    // The receipt claims index 1 for the event at position 0.
    let wrong = event_receipt(&ctx, &e0, 1, 0);
    let change = lifecycle_change(&ctx, &e0, &wrong);
    change.check_consistency().unwrap();
    rejected(&verify(&w, &change, None).await);
    let held = HeldContext {
        body: &ctx.body,
        events: &[],
    };
    rejected(&verify(&w, &change, Some(held)).await);

    // A receipt by another registry key over the right binding.
    let mut wire =
        serde_json::to_value(lifecycle_change(&ctx, &e0, &event_receipt(&ctx, &e0, 0, 0))).unwrap();
    wire["event_receipt"]["signature"]["value"] = serde_json::to_value(
        ReceiptSigner::new(
            SigningKey::from_bytes(&[0x77; 32]),
            REGISTRY_DID,
            format!("{REGISTRY_DID}#receipt-key-1"),
        )
        .unwrap()
        .mint_event_receipt(&ctx.body.ctx_id, &e0, 0, at(&ctx, 0))
        .unwrap()
        .signature
        .value,
    )
    .unwrap();
    let forged = Change::from_value(&wire).unwrap();
    assert!(matches!(
        rejected(&verify(&w, &forged, None).await),
        AcdpError::InvalidReceipt(_) | AcdpError::InvalidSignature(_)
    ));
}

#[tokio::test]
async fn rec_006_d_partial_event_list_forces_retrieval() {
    let w = world().await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let e0 = event(&ctx, LifecycleEventType::Retracted, 0);
    let r0 = event_receipt(&ctx, &e0, 0, 0);
    let e1 = event(&ctx, LifecycleEventType::Republished, 1);
    let r1 = event_receipt(&ctx, &e1, 1, 1);
    serve_events(&w, &ctx, &[(e0.clone(), r0), (e1.clone(), r1.clone())]);
    let change = lifecycle_change(&ctx, &e1, &r1);

    // Index 1, index 0 not held: the full list is re-retrieved.
    let held = HeldContext {
        body: &ctx.body,
        events: &[],
    };
    match verify(&w, &change, Some(held)).await {
        ChangeVerdict::Verified(ChangeEffect::Lifecycle {
            retracted, source, ..
        }) => {
            assert!(!retracted, "republished after retracted");
            assert_eq!(source, LifecycleSource::Retrieved);
        }
        other => panic!("expected a verified lifecycle effect, got {other:?}"),
    }
    assert_eq!(w.retrievals_of(ctx.body.ctx_id.as_str()), 1);

    // Index 0 held: applied directly.
    let held_events = [e0.clone()];
    let held = HeldContext {
        body: &ctx.body,
        events: &held_events,
    };
    match verify(&w, &change, Some(held)).await {
        ChangeVerdict::Verified(ChangeEffect::Lifecycle {
            retracted, source, ..
        }) => {
            assert!(!retracted);
            assert_eq!(source, LifecycleSource::Held);
        }
        other => panic!("expected a verified lifecycle effect, got {other:?}"),
    }
    assert_eq!(w.retrievals_of(ctx.body.ctx_id.as_str()), 1);

    // A registry whose served list disagrees with the entry is rejected.
    serve_events(&w, &ctx, &[(e0.clone(), event_receipt(&ctx, &e0, 0, 0))]);
    rejected(&verify(&w, &change, None).await);
}

#[tokio::test]
async fn rec_006_e_bogus_supersession_changes_nothing() {
    let w = world().await;
    let v1 = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let v2 = w.publish_next(&v1, "key-1", K1).await;

    let good = Change::superseded(1050, v1.body.ctx_id.clone(), agent(), &receipt_of(&v2)).unwrap();
    match verify(&w, &good, None).await {
        ChangeVerdict::Verified(ChangeEffect::Superseded { new_version }) => {
            assert_eq!(new_version.body().ctx_id, v2.body.ctx_id);
        }
        other => panic!("expected a verified supersession, got {other:?}"),
    }

    // superseded_by does not supersede ctx_id: an unrelated context.
    let unrelated = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let bogus = Change::superseded(
        1051,
        v1.body.ctx_id.clone(),
        agent(),
        &receipt_of(&unrelated),
    )
    .unwrap();
    bogus.check_consistency().unwrap();
    rejected(&verify(&w, &bogus, None).await);

    // A different lineage: the envelope disagrees with the receipt.
    let mut wire = serde_json::to_value(&good).unwrap();
    wire["lineage_id"] = json!(unrelated.body.lineage_id.as_str());
    rejected(&verify(&w, &Change::from_value(&wire).unwrap(), None).await);

    // Another producer named on the entry (§7 step 2, agent_id).
    let mut wire = serde_json::to_value(&good).unwrap();
    wire["agent_id"] = json!("did:web:other.example.com");
    rejected(&verify(&w, &Change::from_value(&wire).unwrap(), None).await);
}

#[tokio::test]
async fn rec_006_e_supersession_from_another_origin_is_rejected() {
    // RFC-ACDP-0018 §7 origin binding: the new version must originate at
    // the registry serving the feed. Same server, reached under another
    // authority name, so its origin differs from the serving authority.
    let w = world().await;
    let v1 = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let v2 = w.publish_next(&v1, "key-1", K1).await;
    let change =
        Change::superseded(1052, v1.body.ctx_id.clone(), agent(), &receipt_of(&v2)).unwrap();
    let mirror = acdp::client::RegistryClient::with_test_endpoint(
        "https://localhost.",
        w.tls.addr,
        &w.tls.root_cert_pem,
    )
    .expect("client");
    assert_eq!(mirror.authority().as_deref(), Some("localhost."));
    let verdict = verify_change(
        &mirror,
        &w.resolver(),
        &change,
        None,
        &VerificationPolicy::default(),
    )
    .await
    .expect("decided");
    // The receipt binding (registry_did vs the serving authority) fires
    // before the explicit origin check; either way the entry is rejected.
    let e = rejected(&verdict);
    assert!(
        e.to_string().contains("serving authority") || e.to_string().contains("originates at"),
        "{e}"
    );
}

#[tokio::test]
async fn rec_006_f_out_of_scope_revocation_changes_nothing() {
    let w = world().await;
    let rev = w.publish_revocation_of_k1("key-2", K2).await;
    let receipt = receipt_of(&rev);

    let in_scope = Change::key_revocation(1057, agent(), &receipt).unwrap();
    match verify(&w, &in_scope, None).await {
        ChangeVerdict::Verified(ChangeEffect::KeyRevocation { revocation }) => {
            assert!(revocation.speaks_for(&agent()));
            assert_eq!(revocation.revoked_key_fingerprint, K1_FP);
        }
        other => panic!("expected a verified revocation, got {other:?}"),
    }

    // Served and entry receipts agree under JCS but the signature is
    // forged: the served receipt must itself verify (RFC-ACDP-0010 §8).
    let mut forged = serde_json::to_value(&receipt).unwrap();
    let sig = forged["signature"]["value"].as_str().unwrap().to_owned();
    let flipped = if sig.starts_with('A') { "B" } else { "A" };
    forged["signature"]["value"] = json!(format!("{flipped}{}", &sig[1..]));
    w.tamper(rev.body.ctx_id.as_str(), |v| {
        v["registry_receipt"] = forged.clone()
    });
    let mut wire = serde_json::to_value(&in_scope).unwrap();
    wire["registry_receipt"] = forged;
    assert!(matches!(
        rejected(&verify(&w, &Change::from_value(&wire).unwrap(), None).await),
        AcdpError::InvalidReceipt(_)
    ));
    w.tamper(rev.body.ctx_id.as_str(), |v| {
        v["registry_receipt"] = serde_json::to_value(&receipt).unwrap()
    });

    // The entry claims the revocation affects another producer.
    let other = AgentDid::new("did:web:other.example.com");
    let out_of_scope = Change::key_revocation(1058, other, &receipt).unwrap();
    rejected(&verify(&w, &out_of_scope, None).await);
}

#[tokio::test]
async fn rec_006_g_duplicate_is_processed_once() {
    let (w, ctx, e0, r0) = retracted_world().await;
    let change = serde_json::to_value(lifecycle_change(&ctx, &e0, &r0)).unwrap();
    let page = json!({ "changes": [change], "next_cursor": "c1", "has_more": false });
    // At-least-once: the same page is delivered twice (a re-read after a
    // crash before the cursor was persisted).
    w.queue_changes(200, page.clone());
    w.queue_changes(200, page);

    let client = w.client();
    let authority = client.authority().unwrap();
    let feed = ChangeFeed::new(&client, WatchFilter::new().ctx_id(ctx.body.ctx_id.clone()));
    let mut seen = SeenChanges::new();
    let mut processed = 0;
    for _ in 0..2 {
        let page = feed.fetch().await.unwrap();
        for change in &page.changes {
            if !seen.is_new(&authority, change.seq()) {
                continue;
            }
            assert!(verify(&w, change, None).await.effect().is_some());
            seen.mark(&authority, change.seq());
            processed += 1;
        }
    }
    assert_eq!(processed, 1);
    assert_eq!(w.retrievals_of(ctx.body.ctx_id.as_str()), 1);
}

#[tokio::test]
async fn rec_006_h_cursor_expired_resyncs_from_head() {
    let w = world().await;
    w.queue_changes(
        400,
        json!({ "error": { "code": "cursor_expired", "message": "too old" } }),
    );
    w.queue_changes(
        200,
        json!({ "changes": [], "next_cursor": "head-cursor", "has_more": false }),
    );
    let client = w.client();
    let filter = WatchFilter::new().kind(ChangeKind::Lifecycle);
    let mut feed = ChangeFeed::new(&client, filter).since(Since::Cursor("stale".into()));

    assert!(matches!(feed.fetch().await, Err(AcdpError::CursorExpired)));
    // The consumer re-verifies every watched context directly here, then:
    feed.reset_to_head();
    let page = feed.fetch().await.unwrap();
    assert!(page.changes.is_empty());
    feed.advance(&page);
    assert_eq!(feed.position(), &Since::Cursor("head-cursor".into()));

    let q = w.changes_queries();
    assert_eq!(q.len(), 2);
    assert!(
        q[0].contains("since=stale") && q[0].contains("kind=lifecycle"),
        "{q:?}"
    );
    assert!(
        q[1].contains("since=head") && q[1].contains("kind=lifecycle"),
        "{q:?}"
    );
}

#[tokio::test]
async fn rec_006_envelope_mismatch_is_rejected_before_any_fetch() {
    let (w, ctx, e0, r0) = retracted_world().await;
    let mut wire = serde_json::to_value(lifecycle_change(&ctx, &e0, &r0)).unwrap();
    wire["recorded_at"] = json!("2020-01-01T00:00:00.000Z");
    rejected(&verify(&w, &Change::from_value(&wire).unwrap(), None).await);
    assert_eq!(w.retrievals_of(ctx.body.ctx_id.as_str()), 0);
}

// ── rec-007 D–E: §8.2 hint receiver ──────────────────────────────────────────

const SECRET: &str = "q4C3i0gxkC8b7mSx2F5fW1dTnYp9Z0eLrJvH6uK3oAM=";

#[test]
fn rec_007_d_receiver_rejects_wrong_mac_and_skew() {
    let body = br#"{"hint_version":"acdp-change-hint/1"}"#;
    let t = 1_790_985_602;
    let now = DateTime::from_timestamp(t, 0).unwrap();
    let header = sign_hint(SECRET, t, body);
    verify_hint_signature(SECRET, &header, body, now).unwrap();

    let wrong = sign_hint("another-secret-of-the-required-length-xxxxxxx=", t, body);
    assert!(matches!(
        verify_hint_signature(SECRET, &wrong, body, now),
        Err(AcdpError::NotAuthorized(_))
    ));
    for skew in [301, -301] {
        assert!(matches!(
            verify_hint_signature(SECRET, &header, body, now + Duration::seconds(skew)),
            Err(AcdpError::NotAuthorized(_))
        ));
    }
}

#[tokio::test]
async fn rec_007_e_receiver_pulls_its_own_cursor() {
    let w = world().await;
    let client = w.client();
    let filter = WatchFilter::new().lineage_id(
        acdp::types::LineageId::parse(
            "lin:sha256:a3cb6a87c1601b9f6dddd8d54709b01df3e05f1095b43e6d58e3a862bf9906fa",
        )
        .unwrap(),
    );
    let feed = ChangeFeed::new(&client, filter).since(Since::Cursor("mine".into()));
    let hint = ChangeHint::new(
        "6f1c2a9e-3b4d-4e5f-8a6b-7c8d9e0f1a2b",
        REGISTRY_AUTHORITY,
        "theirs",
    );
    feed.on_hint(&hint).await.unwrap();
    let q = w.changes_queries();
    assert_eq!(q.len(), 1);
    assert!(q[0].contains("since=mine"), "{q:?}");
    assert!(!q[0].contains("theirs"), "{q:?}");
    assert!(q[0].contains("lineage_id="), "{q:?}");

    // A hint for another registry is not acted on.
    let foreign = ChangeHint::new(
        "6f1c2a9e-3b4d-4e5f-8a6b-7c8d9e0f1a2b",
        "elsewhere.example.com",
        "x",
    );
    assert!(feed.on_hint(&foreign).await.is_err());
    assert_eq!(w.changes_queries().len(), 1);
}
