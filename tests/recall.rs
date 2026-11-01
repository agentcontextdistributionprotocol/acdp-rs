//! Retraction recall, consumer side (ACDP 0.5.0 Draft, RFC-ACDP-0018,
//! profile `acdp-consumer-recall`) — behavioral bindings for `rec-006`
//! (§7 consumer verification, scenarios A–K, M and N), `rec-007` D–E
//! (§8.2 hint receiver) and `rec-010` G–I (§6.1 bucket filters), against
//! the in-process TLS registry world, plus `rec-009`'s and `rec-010`'s
//! executed known answers.
//!
//! `rec-006` L (feed silence is not non-revocation) is a duty of the
//! RFC-ACDP-0014 §8 discovery schedule, not of the feed: it is exercised
//! by the revocation auto-discovery tests in `tests/key_revocation.rs`.
//!
//! The registry-side fixtures (`rec-001..005`, `rec-007` A–C/F–H,
//! `rec-008`, `rec-010` A–F) bind the `acdp-registry-changes` / `-events`
//! profiles and are a registry implementation's to run (this repo's
//! `acdp-server` has no `GET /changes`, so `rec-001` G's limit clamp and H's
//! page bound are not bound here).

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
    bucket, sign_hint, verify_hint_signature, Change, ChangeHint, ChangeKind, EnvelopeReason,
    WatchFilter,
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
async fn rec_006_i_invalid_cursor_on_a_persisted_cursor_resyncs() {
    let w = world().await;
    w.queue_changes(
        400,
        json!({ "error": { "code": "invalid_cursor", "message": "unknown cursor" } }),
    );
    w.queue_changes(
        200,
        json!({ "changes": [], "next_cursor": "head-cursor", "has_more": false }),
    );
    let client = w.client();
    let authority = client.authority().unwrap();
    let mut feed = ChangeFeed::new(&client, WatchFilter::new().kind(ChangeKind::Lifecycle))
        .since(Since::Cursor("persisted".into()));
    let mut seen = SeenChanges::new();
    seen.mark(&authority, RELIER_SEQ);

    let err = feed.fetch().await.unwrap_err();
    assert!(matches!(err, AcdpError::InvalidCursor(_)), "{err:?}");
    // A persisted cursor refused as invalid is treated as cursor_expired.
    assert!(feed.needs_resync(&err));
    assert!(feed.needs_resync(&AcdpError::CursorExpired));
    // The consumer re-verifies every watched context directly here, then:
    feed.resync(&mut seen);
    assert_eq!(feed.position(), &Since::Head);
    assert!(seen.is_new(&authority, RELIER_SEQ), "dedup state survived");
    // Not retried forever: the next request starts from the head.
    let page = feed.fetch().await.unwrap();
    feed.advance(&page);
    assert_eq!(feed.position(), &Since::Cursor("head-cursor".into()));
    let q = w.changes_queries();
    assert_eq!(q.len(), 2, "{q:?}");
    assert!(q[0].contains("since=persisted"), "{q:?}");
    assert!(q[1].contains("since=head"), "{q:?}");

    // invalid_cursor on a request that sent no persisted cursor is a real
    // error, not a resync trigger.
    let head = ChangeFeed::new(&client, WatchFilter::new()).since(Since::Head);
    assert!(!head.needs_resync(&AcdpError::InvalidCursor("x".into())));
    assert!(!feed.needs_resync(&AcdpError::RateLimited {
        message: "slow".into(),
        retry_after: None
    }));
}

#[tokio::test]
async fn rec_006_j_seq_reused_after_a_resync_is_new() {
    let (w, ctx, e0, r0) = retracted_world().await;
    // A second relied-on context, retracted, whose entry the restored
    // feed serves at the SAME seq.
    let ctx2 = w.publish("key-1", K1, ContextType::Analysis, None).await;
    assert_ne!(ctx.body.ctx_id, ctx2.body.ctx_id);
    let e2 = event(&ctx2, LifecycleEventType::Retracted, 0);
    let r2 = event_receipt(&ctx2, &e2, 0, 0);
    serve_events(&w, &ctx2, &[(e2.clone(), r2.clone())]);
    let first = serde_json::to_value(lifecycle_change(&ctx, &e0, &r0)).unwrap();
    let reused = serde_json::to_value(lifecycle_change(&ctx2, &e2, &r2)).unwrap();

    w.queue_changes(
        200,
        json!({ "changes": [first], "next_cursor": "c1", "has_more": false }),
    );
    w.queue_changes(
        400,
        json!({ "error": { "code": "cursor_expired", "message": "sequence reset" } }),
    );
    w.queue_changes(
        200,
        json!({ "changes": [], "next_cursor": "h1", "has_more": false }),
    );
    w.queue_changes(
        200,
        json!({ "changes": [reused], "next_cursor": "h2", "has_more": false }),
    );

    let client = w.client();
    let authority = client.authority().unwrap();
    let mut feed = ChangeFeed::new(&client, WatchFilter::new()).since(Since::Cursor("c0".into()));
    let mut seen = SeenChanges::new();
    let mut processed = Vec::new();
    for _ in 0..4 {
        let page = match feed.fetch().await {
            Err(e) if feed.needs_resync(&e) => {
                feed.resync(&mut seen);
                continue;
            }
            other => other.unwrap(),
        };
        for change in &page.changes {
            if !seen.is_new(&authority, change.seq()) {
                continue;
            }
            assert!(verify(&w, change, None).await.effect().is_some());
            seen.mark(&authority, change.seq());
            processed.push(change.ctx_id().clone());
        }
        feed.advance(&page);
    }
    assert_eq!(processed, vec![ctx.body.ctx_id, ctx2.body.ctx_id]);
}

#[tokio::test]
async fn rec_006_k_revocation_matches_by_the_retrieved_fingerprint() {
    use acdp::crypto::fingerprint::fingerprint_ed25519;

    let w = world().await;
    // Two relied-on contexts by the same controller, signed by K1 and K2.
    let by_k1 = fingerprint_ed25519(&SigningKey::from_bytes(&K1).verifying_key_bytes());
    let by_k2 = fingerprint_ed25519(&SigningKey::from_bytes(&K2).verifying_key_bytes());
    assert_ne!(by_k1, by_k2);
    let rev = w.publish_revocation_of_k1("key-2", K2).await;
    let change = Change::key_revocation(1057, agent(), &receipt_of(&rev)).unwrap();
    // The entry carries no fingerprint: its closed schema has no member
    // for one, so matching can only use the retrieved, verified body.
    let wire = serde_json::to_value(&change).unwrap();
    assert!(wire.get("revoked_key_fingerprint").is_none());
    let mut smuggled = wire.clone();
    smuggled["revoked_key_fingerprint"] = json!(by_k2);
    assert!(Change::from_value(&smuggled).is_err());

    match verify(&w, &change, None).await {
        ChangeVerdict::Verified(ChangeEffect::KeyRevocation { revocation }) => {
            assert_eq!(revocation.revoked_key_fingerprint, by_k1);
            // Only the context signed by the revoked key is affected.
            assert!(revocation.revoked_key_fingerprint == by_k1);
            assert!(revocation.revoked_key_fingerprint != by_k2);
        }
        other => panic!("expected a verified revocation, got {other:?}"),
    }
}

#[tokio::test]
async fn rec_006_m_a_short_page_is_not_the_head() {
    let (w, ctx, e0, r0) = retracted_world().await;
    let change = serde_json::to_value(lifecycle_change(&ctx, &e0, &r0)).unwrap();
    // limit=500 asked, the registry clamps (or filters) to a short page
    // that still says has_more.
    w.queue_changes(
        200,
        json!({ "changes": [change], "next_cursor": "c1", "has_more": true }),
    );
    w.queue_changes(
        200,
        json!({ "changes": [], "next_cursor": "c2", "has_more": false }),
    );
    let client = w.client();
    let mut feed = ChangeFeed::new(&client, WatchFilter::new()).limit(500);
    let mut pages = 0;
    loop {
        let page = feed.fetch().await.unwrap();
        pages += 1;
        feed.advance(&page);
        // Only has_more: false says the head is reached.
        if !page.has_more {
            break;
        }
    }
    assert_eq!(pages, 2);
    assert_eq!(feed.position(), &Since::Cursor("c2".into()));
    let q = w.changes_queries();
    assert!(q[0].contains("limit=500"), "{q:?}");
    assert!(q[1].contains("since=c1"), "{q:?}");
}

// ── rec-006 N and §5.2: page size and compression ────────────────────────────

const MIB: usize = 1_048_576;

/// The value of `name` in a raw query string.
fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

/// A registry allowing 1000-entry pages over `total` lifecycle entries, as
/// the real ones are served: entries are large enough that a full page goes
/// over 1 MiB, and `coding` compresses every answer when set.
fn serve_big_feed(w: &World, template: &Change, total: u64, coding: Option<&'static str>) -> usize {
    let wire = serde_json::to_value(template).unwrap();
    let padding = "x".repeat(200);
    let entry_at = move |seq: u64| {
        let mut e = wire.clone();
        e["seq"] = json!(seq);
        // Evidence is verbatim and open: this parses, and sizes the entry
        // like a real one (RFC-ACDP-0018 §5.2, about 1–1.5 KB).
        e["event"]["reason"] = json!(padding.clone());
        e
    };
    let entry_bytes = serde_json::to_vec(&entry_at(1)).unwrap().len();
    w.respond_to_changes(move |query| {
        let after: u64 = query_param(query, "since")
            .and_then(|c| c.strip_prefix('c'))
            .map_or(0, |c| c.parse().unwrap());
        let limit: u64 = query_param(query, "limit").map_or(100, |l| l.parse().unwrap());
        let last = (after + limit.min(1000)).min(total);
        let changes: Vec<Value> = (after + 1..=last).map(&entry_at).collect();
        let body = serde_json::to_vec(&json!({
            "changes": changes,
            "next_cursor": format!("c{last}"),
            "has_more": last < total,
        }))
        .unwrap();
        match coding {
            Some(c) => (200, Some(c), gzip(&body)),
            None => (200, None, body),
        }
    });
    entry_bytes
}

/// The Seam shape: a consumer driving `RegistryClient::changes` directly,
/// with `limit=1000`, against pages of about 1.4 MB. Before this rule it
/// backed off on the unchanged request forever.
#[tokio::test]
async fn rec_006_n_an_oversized_page_is_retried_smaller() {
    let (w, ctx, e0, r0) = retracted_world().await;
    let entry_bytes = serve_big_feed(&w, &lifecycle_change(&ctx, &e0, &r0), 1_800, None);
    assert!(entry_bytes * 1000 > MIB, "entry is {entry_bytes} bytes");
    assert!(entry_bytes * 500 < MIB, "entry is {entry_bytes} bytes");

    let client = w.client();
    let filter = WatchFilter::new();
    let mut since = Since::Cursor("c0".into());
    let mut seqs = Vec::new();
    loop {
        let page = client.changes(&since, &filter, Some(1000)).await.unwrap();
        seqs.extend(page.changes.iter().map(Change::seq));
        since = Since::Cursor(page.next_cursor.clone());
        if !page.has_more {
            break;
        }
    }
    // Nothing skipped or repeated, and the walk reached the head.
    assert_eq!(seqs, (1..=1_800).collect::<Vec<u64>>());

    let q = w.changes_queries();
    assert!(q[0].contains("limit=1000"), "{q:?}");
    assert!(q[1].contains("limit=500"), "{q:?}");
    assert_eq!(
        query_param(&q[0], "since"),
        query_param(&q[1], "since"),
        "the retry is of the same page: {q:?}"
    );
    assert_eq!(query_param(&q[2], "since"), Some("c500"), "{q:?}");
    // One oversized read per page, plus the fitting one: bounded.
    assert!(q.len() <= 8, "{q:?}");
}

/// The same through `ChangeFeed`, whose cursor only moves on `advance`.
#[tokio::test]
async fn rec_006_n_a_feed_keeps_its_position() {
    let (w, ctx, e0, r0) = retracted_world().await;
    serve_big_feed(&w, &lifecycle_change(&ctx, &e0, &r0), 1_000, None);
    let client = w.client();
    let mut feed = ChangeFeed::new(&client, WatchFilter::new())
        .since(Since::Cursor("c0".into()))
        .limit(1000);
    let page = feed.fetch().await.unwrap();
    assert_eq!(page.changes.len(), 500);
    assert!(page.has_more, "a shrunk page is not the head");
    assert_eq!(feed.position(), &Since::Cursor("c0".into()));
    feed.advance(&page);
    assert_eq!(feed.position(), &Since::Cursor("c500".into()));
}

/// A `limit` left to the registry is halved from its default, 100.
#[tokio::test]
async fn rec_006_n_default_limit_is_halved_from_100() {
    let w = world().await;
    w.respond_to_changes(|query| {
        if query_param(query, "limit") == Some("50") {
            let page = json!({ "changes": [], "next_cursor": "c1", "has_more": false });
            (200, None, serde_json::to_vec(&page).unwrap())
        } else {
            (200, None, vec![b' '; MIB + 1])
        }
    });
    let page = w
        .client()
        .changes(&Since::Head, &WatchFilter::new(), None)
        .await
        .unwrap();
    assert_eq!(page.next_cursor, "c1");
    let q = w.changes_queries();
    assert_eq!(q.len(), 2, "{q:?}");
    assert_eq!(query_param(&q[0], "limit"), None, "{q:?}");
    assert_eq!(query_param(&q[1], "limit"), Some("50"), "{q:?}");
}

/// "A consumer MUST accept a response body of up to 1 MiB": exactly at the
/// bound is one request; one byte over is the retry.
#[tokio::test]
async fn rec_006_n_one_mib_is_accepted_and_one_byte_more_is_not() {
    let w = world().await;
    let page = serde_json::to_vec(&json!({ "changes": [], "next_cursor": "c", "has_more": false }))
        .unwrap();
    let padded = |n: usize| {
        let mut b = page.clone();
        b.resize(n, b' ');
        b
    };
    let exact = padded(MIB);
    w.respond_to_changes(move |_| (200, None, exact.clone()));
    let client = w.client();
    client
        .changes(&Since::Head, &WatchFilter::new(), Some(8))
        .await
        .unwrap();
    assert_eq!(w.changes_queries().len(), 1);

    let over = padded(MIB + 1);
    w.respond_to_changes(move |_| (200, None, over.clone()));
    let err = client
        .changes(&Since::Head, &WatchFilter::new(), Some(8))
        .await
        .unwrap_err();
    assert!(matches!(err, AcdpError::PayloadTooLarge(_)), "{err:?}");
    assert!(!err.is_transient(), "{err:?}");
    // 8, 4, 2, 1, then the error: never an unbounded loop. This is the one
    // entry over the bound that §5.2 says a registry still serves alone.
    assert_eq!(w.changes_queries().len(), 1 + 4);
    assert!(err.to_string().contains("limit=1"), "{err}");
}

/// Only a size failure shrinks the request: a 429 goes back to the caller
/// with its delay, on the first request.
#[tokio::test]
async fn rec_006_n_other_errors_do_not_shrink_the_limit() {
    let w = world().await;
    w.queue_changes(
        429,
        json!({ "error": { "code": "rate_limited", "message": "slow down" } }),
    );
    let err = w
        .client()
        .changes(&Since::Head, &WatchFilter::new(), Some(1000))
        .await
        .unwrap_err();
    assert!(matches!(err, AcdpError::RateLimited { .. }), "{err:?}");
    assert_eq!(w.changes_queries().len(), 1);
}

/// §5.2: gzip is requested on `/changes` and only there, and is decoded.
#[tokio::test]
async fn rec_006_n_changes_requests_and_decodes_gzip() {
    let (w, ctx, e0, r0) = retracted_world().await;
    serve_big_feed(&w, &lifecycle_change(&ctx, &e0, &r0), 3, Some("gzip"));
    let client = w.client();
    let page = client
        .changes(&Since::Cursor("c0".into()), &WatchFilter::new(), Some(10))
        .await
        .unwrap();
    assert_eq!(page.changes.len(), 3);
    assert_eq!(
        w.accept_encodings_of("/changes"),
        vec![Some("gzip".to_string())]
    );

    client.retrieve(&ctx.body.ctx_id).await.unwrap();
    let path = format!(
        "/contexts/{}",
        urlencoding::encode(ctx.body.ctx_id.as_str())
    );
    let seen = w.accept_encodings_of(&path);
    assert!(!seen.is_empty(), "{path}");
    assert!(seen.iter().all(Option::is_none), "{seen:?}");
}

/// The 1 MiB bound is on the DECODED body: a small compressed bomb costs
/// the client at most the bound per request, never its expansion.
#[tokio::test]
async fn rec_006_n_a_compressed_bomb_is_bounded_by_its_decoded_size() {
    let w = world().await;
    let bomb = gzip(&vec![b' '; 64 * MIB]);
    assert!(bomb.len() < MIB, "the wire size alone would pass the bound");
    w.respond_to_changes(move |_| (200, Some("gzip"), bomb.clone()));
    let err = w
        .client()
        .changes(&Since::Head, &WatchFilter::new(), Some(2))
        .await
        .unwrap_err();
    assert!(matches!(err, AcdpError::PayloadTooLarge(_)), "{err:?}");
    assert_eq!(w.changes_queries().len(), 2);
}

/// A page small on the wire but over the bound once decoded is retried like
/// any other oversized page.
#[tokio::test]
async fn rec_006_n_gzip_page_over_the_decoded_bound_is_retried_smaller() {
    let (w, ctx, e0, r0) = retracted_world().await;
    serve_big_feed(&w, &lifecycle_change(&ctx, &e0, &r0), 1_000, Some("gzip"));
    let page = w
        .client()
        .changes(&Since::Cursor("c0".into()), &WatchFilter::new(), Some(1000))
        .await
        .unwrap();
    assert_eq!(page.changes.len(), 500);
    assert_eq!(w.changes_queries().len(), 2);
}

// ── rec-010: bucket filters, consumer side ───────────────────────────────────

/// `rec-010` G: the fixture's bucket-derivation vectors, every length, and
/// the wrong readings it pins.
#[test]
fn rec_010_g_bucket_derivation_known_answers() {
    let Some(root) = spec_root() else {
        eprintln!("ACDP spec not found; skipping rec-010");
        return;
    };
    let path = root.join("schemas/conformance/rec-010-bucket-filters.json");
    if !path.exists() {
        assert!(
            std::env::var("ACDP_REQUIRE_CONFORMANCE").is_err(),
            "ACDP_REQUIRE_CONFORMANCE is set but {} is missing",
            path.display()
        );
        return;
    }
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let vectors = fixture["vectors"].as_array().expect("rec-010 vectors[]");
    assert_eq!(vectors.len(), 5, "rec-010 vectors changed");
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let value = v["bucket_of"].as_str().unwrap();
        assert_eq!(
            bucket(value, 64),
            v["sha256_hex"].as_str().unwrap(),
            "{name}"
        );
        for (n, want) in v["expected"].as_object().unwrap() {
            let n: usize = n.parse().unwrap();
            assert_eq!(bucket(value, n), want.as_str().unwrap(), "{name} n={n}");
        }
        if let Some(wrong) = v["not_bucket_4"].as_str() {
            assert_ne!(bucket(value, 4), wrong, "{name}");
        }
    }
}

/// `rec-010` H: a bucket response is a candidate set. The consumer keeps
/// the entry it watches, drops the neighbour sharing its bucket, and a
/// `ctx_id` watch keeps its producer's key revocation.
#[tokio::test]
async fn rec_010_h_consumer_filters_a_bucket_response_locally() {
    let (w, x, e0, r0) = retracted_world().await;
    *w.bucket_limit.write().unwrap() = Some(8);
    let lx = x.body.lineage_id.clone();
    let producer = agent();
    let n = 1;
    let wire = WatchFilter::new()
        .lineage_bucket(bucket(lx.as_str(), n))
        .agent_bucket(bucket(producer.as_str(), n));

    // Another producer's context in the same 1-digit bucket as X.
    let change_x = lifecycle_change(&x, &e0, &r0);
    let mut neighbour = serde_json::to_value(&change_x).unwrap();
    neighbour["seq"] = json!(RELIER_SEQ + 1);
    neighbour["lineage_id"] =
        json!("lin:sha256:9eb5e0ee5d9a110edc81f7e1fdafca3e3f521650fb58b8bb09c53f29bec58592");
    neighbour["agent_id"] = json!("did:web:other.example.com");
    neighbour["ctx_id"] = json!("acdp://localhost/dddddddd-dddd-4ddd-8ddd-dddddddddddd");
    let revocation = json!({
        "change_version": "acdp-change/1",
        "seq": RELIER_SEQ + 2,
        "kind": "key_revocation",
        "ctx_id": "acdp://localhost/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "lineage_id": "lin:sha256:a3cb6a87c1601b9f6dddd8d54709b01df3e05f1095b43e6d58e3a862bf9906fa",
        "agent_id": AGENT,
        "recorded_at": "2026-10-03T00:00:01.000Z",
        "registry_receipt": serde_json::to_value(receipt_of(&x)).unwrap(),
    });
    w.queue_changes(
        200,
        json!({
            "changes": [serde_json::to_value(&change_x).unwrap(), neighbour, revocation],
            "next_cursor": "c9",
            "has_more": false,
        }),
    );
    let client = w.client();
    let mut feed = ChangeFeed::new(&client, wire).since(Since::Cursor("c0".into()));
    let page = feed.fetch().await.unwrap();
    assert_eq!(page.changes.len(), 3, "the registry returned the bucket");

    // Watching lineage Lx only: X's retraction, nothing else.
    let by_lineage = WatchFilter::new().lineage_id(lx);
    let none = |_: &acdp::types::CtxId| None;
    let kept: Vec<u64> = page
        .changes
        .iter()
        .filter(|c| by_lineage.matches_exact(c, none))
        .map(Change::seq)
        .collect();
    assert_eq!(kept, vec![RELIER_SEQ]);

    // Watching context X: also its producer's key revocation.
    let by_ctx = WatchFilter::new().ctx_id(x.body.ctx_id.clone());
    let producer_of = |c: &acdp::types::CtxId| (c == &x.body.ctx_id).then(|| producer.clone());
    let kept: Vec<u64> = page
        .changes
        .iter()
        .filter(|c| by_ctx.matches_exact(c, producer_of))
        .map(Change::seq)
        .collect();
    assert_eq!(kept, vec![RELIER_SEQ, RELIER_SEQ + 2]);

    // The bucket-only wire filter names nothing exactly, so it keeps
    // nothing rather than everything; the cursor moves regardless.
    assert!(!page
        .changes
        .iter()
        .any(|c| feed.filter().matches_exact(c, none)));
    feed.advance(&page);
    assert_eq!(feed.position(), &Since::Cursor("c9".into()));
}

/// `rec-010` I: no bucket parameter reaches a registry that does not
/// advertise the limit, nor one longer than it advertises. An exact filter
/// reads no capabilities at all.
#[tokio::test]
async fn rec_010_i_no_buckets_without_the_limit() {
    let w = world().await;
    let client = w.client();
    let buckets = WatchFilter::new().lineage_bucket("1f54");

    let err = client
        .changes(&Since::Head, &buckets, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "{err:?}");
    assert!(
        err.to_string().contains("max_change_bucket_length"),
        "{err}"
    );
    assert!(w.changes_queries().is_empty());

    // Unfiltered and exact polls still work, without a capabilities read.
    let hits = w.caps_hits.load(std::sync::atomic::Ordering::SeqCst);
    client
        .changes(&Since::Head, &WatchFilter::new(), None)
        .await
        .unwrap();
    assert_eq!(w.changes_queries().len(), 1);
    assert_eq!(w.caps_hits.load(std::sync::atomic::Ordering::SeqCst), hits);
}

#[tokio::test]
async fn rec_010_i_bucket_within_the_advertised_limit_is_sent() {
    let w = world().await;
    *w.bucket_limit.write().unwrap() = Some(4);
    let client = w.client();

    let too_long = WatchFilter::new().agent_bucket("ad90e");
    let err = client
        .changes(&Since::Head, &too_long, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "{err:?}");
    assert!(w.changes_queries().is_empty());

    // A malformed value is refused locally too (rec-010 E is what a registry
    // would answer).
    for bad in ["", "AD90", "zz"] {
        let f = WatchFilter::new().lineage_bucket(bad);
        assert!(
            client.changes(&Since::Head, &f, None).await.is_err(),
            "{bad:?}"
        );
    }
    assert!(w.changes_queries().is_empty());

    let fits = WatchFilter::new()
        .lineage_bucket("1f54")
        .agent_bucket("ad90")
        .kind(ChangeKind::KeyRevocation);
    client.changes(&Since::Head, &fits, None).await.unwrap();
    client.changes(&Since::Head, &fits, None).await.unwrap();
    let q = w.changes_queries();
    assert_eq!(q.len(), 2);
    assert!(q[0].contains("lineage_bucket=1f54"), "{q:?}");
    assert!(q[0].contains("agent_bucket=ad90"), "{q:?}");
    assert!(q[0].contains("kind=key_revocation"), "{q:?}");
}

/// The limit is cached for the capabilities TTL, not read on every poll, and
/// a registry refusing a filter forces a fresh read.
#[tokio::test]
async fn rec_010_i_a_refused_filter_rereads_the_limit() {
    let w = world().await;
    *w.bucket_limit.write().unwrap() = Some(4);
    let client = w.client();
    let f = WatchFilter::new().lineage_bucket("1f54");
    let hits = || w.caps_hits.load(std::sync::atomic::Ordering::SeqCst);

    client.changes(&Since::Head, &f, None).await.unwrap();
    client.changes(&Since::Head, &f, None).await.unwrap();
    assert_eq!(hits(), 1, "cached between polls");

    // The registry stopped supporting buckets.
    *w.bucket_limit.write().unwrap() = None;
    w.queue_changes(
        400,
        json!({ "error": { "code": "schema_violation", "message": "unknown parameter" } }),
    );
    let refused = client.changes(&Since::Head, &f, None).await.unwrap_err();
    assert!(
        matches!(refused, AcdpError::SchemaViolation(_)),
        "{refused:?}"
    );
    let sent = w.changes_queries().len();

    let err = client.changes(&Since::Head, &f, None).await.unwrap_err();
    assert!(
        err.to_string().contains("max_change_bucket_length"),
        "{err}"
    );
    assert_eq!(hits(), 2);
    assert_eq!(w.changes_queries().len(), sent, "nothing more was sent");
}

/// `limits.max_change_bucket_length` keeps its schema range (4 to 16).
#[tokio::test]
async fn rec_010_i_an_out_of_range_limit_is_a_bad_document() {
    let w = world().await;
    for bad in [3, 17] {
        *w.bucket_limit.write().unwrap() = Some(bad);
        let err = w.client().capabilities().await.unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)), "{err:?}");
    }
    for ok in [4, 16] {
        *w.bucket_limit.write().unwrap() = Some(ok);
        let caps = w.client().capabilities().await.unwrap();
        assert_eq!(caps.limits.max_change_bucket_length, Some(ok));
    }
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

// ── acdp::client::blocking: the sync facade over the same paths ──────────────

#[cfg(feature = "blocking")]
mod blocking {
    use super::*;
    use acdp::client::blocking::BlockingClient;
    use std::time::{Duration as StdDuration, Instant};

    fn assert_send_sync<T: Send + Sync + 'static>() {}

    #[test]
    fn facade_types_are_send_sync() {
        assert_send_sync::<BlockingClient>();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_needs_a_cross_registry_resolver() {
        let (w, ctx, ..) = retracted_world().await;
        let err = facade(&w).resolve(&ctx.body.ctx_id, soon()).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)), "{err:?}");
        assert_eq!(w.retrievals_of(ctx.body.ctx_id.as_str()), 0);
    }

    fn facade(w: &World) -> BlockingClient {
        BlockingClient::new(w.client(), w.resolver()).expect("facade")
    }

    fn soon() -> Instant {
        Instant::now() + StdDuration::from_secs(10)
    }

    /// Retrieve, verify and verify_change through the facade.
    fn exercise(c: &BlockingClient, ctx: &FullContext, change: &Change) {
        let id = &ctx.body.ctx_id;
        assert_eq!(c.retrieve(id, soon()).unwrap().body.ctx_id, *id);
        let verified = c
            .fetch_verified(id, &VerificationPolicy::default(), soon())
            .unwrap();
        assert_eq!(verified.body().ctx_id, *id);
        let held = HeldContext {
            body: &ctx.body,
            events: &[],
        };
        for held in [None, Some(held)] {
            match c
                .verify_change(change, held, &VerificationPolicy::default(), soon())
                .unwrap()
            {
                ChangeVerdict::Verified(ChangeEffect::Lifecycle { retracted, .. }) => {
                    assert!(retracted)
                }
                other => panic!("expected a verified lifecycle effect, got {other:?}"),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn from_a_plain_thread() {
        let (w, ctx, e0, r0) = retracted_world().await;
        let change = lifecycle_change(&ctx, &e0, &r0);
        let c = facade(&w);
        tokio::task::spawn_blocking(move || exercise(&c, &ctx, &change))
            .await
            .unwrap();
    }

    /// Called directly on a multi-threaded runtime's worker: no panic, and
    /// dropping the last clone there does not drop the facade's runtime
    /// in async context.
    #[tokio::test(flavor = "multi_thread")]
    async fn inside_a_multi_thread_runtime() {
        let (w, ctx, e0, r0) = retracted_world().await;
        let change = lifecycle_change(&ctx, &e0, &r0);
        let c = facade(&w);
        exercise(&c, &ctx, &change);
        drop(c);
    }

    /// Called from inside a current-thread runtime (where
    /// `block_in_place` is unavailable): no panic.
    #[tokio::test(flavor = "multi_thread")]
    async fn inside_a_current_thread_runtime() {
        let (w, ctx, e0, r0) = retracted_world().await;
        let change = lifecycle_change(&ctx, &e0, &r0);
        let c = facade(&w);
        tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                exercise(&c, &ctx, &change);
                drop(c);
            });
        })
        .await
        .unwrap();
    }

    /// A registry that accepts the connection and never answers: the call
    /// fails closed at the deadline, not at the client's 30 s timeout.
    #[tokio::test(flavor = "multi_thread")]
    async fn deadline_fails_closed() {
        let (w, ctx, ..) = retracted_world().await;
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = silent.local_addr().unwrap();
        let hung = acdp::client::RegistryClient::with_test_endpoint(
            &format!("https://{REGISTRY_AUTHORITY}"),
            addr,
            &w.tls.root_cert_pem,
        )
        .unwrap();
        let c = BlockingClient::new(hung, w.resolver()).unwrap();
        let id = ctx.body.ctx_id.clone();
        let (err, took) = tokio::task::spawn_blocking(move || {
            let start = Instant::now();
            let err = c
                .fetch_verified(
                    &id,
                    &VerificationPolicy::default(),
                    start + StdDuration::from_millis(300),
                )
                .unwrap_err();
            (err, start.elapsed())
        })
        .await
        .unwrap();
        drop(silent);
        assert!(matches!(err, AcdpError::DeadlineExceeded(_)), "{err:?}");
        assert!(err.is_transient());
        assert!(took < StdDuration::from_secs(3), "took {took:?}");

        // A deadline already past fails before any request is made.
        let c = facade(&w);
        let before = w.retrievals_of(ctx.body.ctx_id.as_str());
        let past = Instant::now() - StdDuration::from_millis(1);
        let err = c.retrieve(&ctx.body.ctx_id, past).unwrap_err();
        assert!(matches!(err, AcdpError::DeadlineExceeded(_)), "{err:?}");
        assert_eq!(w.retrievals_of(ctx.body.ctx_id.as_str()), before);
    }
}

// ── rec-009: executed envelope known answers ─────────────────────────────────

fn spec_root() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    let require = std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok();
    if let Ok(env) = std::env::var("ACDP_SPEC_DIR") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
        assert!(!require, "ACDP_SPEC_DIR '{}' does not exist", p.display());
    }
    let sibling = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("agentcontextdistributionprotocol"));
    if let Some(s) = sibling.filter(|s| s.exists()) {
        return Some(s);
    }
    assert!(
        !require,
        "ACDP_REQUIRE_CONFORMANCE is set but no ACDP spec checkout could be located"
    );
    None
}

/// `rec-009`: every vector reaches the fixture's verdict, and a rejection
/// reports the first failing check in `check_order`. The served evidence
/// is compared under JCS, so a reordered copy is accepted. The checks
/// that need no served copy also reject in `verify_change` before any
/// fetch.
#[tokio::test]
async fn rec_009_entry_envelope_known_answers() {
    let Some(root) = spec_root() else {
        eprintln!("ACDP spec not found; skipping rec-009");
        return;
    };
    let path = root.join("schemas/conformance/rec-009-entry-envelope.json");
    if !path.exists() {
        assert!(
            std::env::var("ACDP_REQUIRE_CONFORMANCE").is_err(),
            "ACDP_REQUIRE_CONFORMANCE is set but {} is missing",
            path.display()
        );
        return;
    }
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        fixture["check_order"].as_array().map(Vec::len),
        Some(5),
        "rec-009 check_order changed; revisit Change::check_envelope"
    );
    let vectors = fixture["vectors"].as_array().expect("rec-009 vectors[]");
    assert!(!vectors.is_empty());
    let w = world().await;
    for v in vectors {
        let name = v["name"].as_str().unwrap_or("?");
        let change = Change::from_value(&v["entry"])
            .unwrap_or_else(|e| panic!("{name}: entry does not parse: {e}"));
        let served = &v["served"];
        let served = served
            .get("lifecycle_event")
            .or_else(|| served.get("registry_receipt"))
            .unwrap_or_else(|| panic!("{name}: no served evidence"));
        let got = change.check_envelope(Some(served));
        match v["expected"]["verdict"].as_str() {
            Some("accept") => {
                got.unwrap_or_else(|f| panic!("{name}: expected accept, got {f}"));
                change
                    .check_consistency()
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
            }
            Some("reject") => {
                let want = v["expected"]["reason"].as_str().unwrap();
                let fault = got.expect_err(name);
                assert_eq!(fault.reason.as_str(), want, "{name}: {fault}");
                if fault.reason != EnvelopeReason::EvidenceMismatch {
                    assert!(change.check_consistency().is_err(), "{name}");
                    rejected(&verify(&w, &change, None).await);
                }
            }
            other => panic!("{name}: unknown verdict {other:?}"),
        }
    }
    assert_eq!(w.changes_queries().len(), 0);
}
