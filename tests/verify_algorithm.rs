//! Resolver-backed verification of the RFC-ACDP-0001 §5.11 seven-step
//! algorithm — the per-step error branches of `acdp-verify`'s
//! `Verifier` / `verify_signature_envelope`, driven through the shared
//! in-process TLS DID-document harness (`tests/common`).
//!
//! Scope split: the happy paths and the forged-signature / not-in-
//! assertionMethod branches are already pinned by `tls_conformance.rs`
//! (pub-001/006) and the conformance golden vectors. This file covers
//! the remaining step branches — malformed/empty fragment, DID mismatch,
//! unsupported method, resolver failure, missing fragment in the doc,
//! algorithm-downgrade, the ordering guarantee (structural failure MUST
//! precede any DID fetch), historical-key verification, and one
//! resolver-backed lifecycle-event path. Synthetic keys only — no golden
//! constants are re-pinned here.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::{response::Json, routing::get, Router};
use serde_json::Value;

use acdp::crypto::sign::SigningKey;
use acdp::did::WebResolver;
use acdp::producer::Producer;
use acdp::safe_http::SsrfPolicy;
use acdp::types::body::{Body, DataPeriod};
use acdp::types::lifecycle::{LifecycleEvent, LifecycleEventType};
use acdp::types::primitives::{AgentDid, ContextType, CtxId, LineageId, Visibility};
use acdp::verify::{verify_body_signature_historical, verify_lifecycle_event, Verifier};
use acdp::AcdpError;

use common::{did_doc_router, ed25519_did_doc, ed25519_did_doc_without_assertion, TlsTestServer};

const CTX: &str = "acdp://localhost/00000000-0000-4000-8000-000000000000";
const LIN: &str = "lin:sha256:0000000000000000000000000000000000000000000000000000000000000000";
const EVENT_ID: &str = "00000000-0000-4000-8000-0000000000aa";

fn test_resolver(root_cert_pem: &[u8]) -> WebResolver {
    WebResolver::with_root_cert_pem(root_cert_pem)
        .expect("resolver")
        .with_ssrf_policy(SsrfPolicy::allow_test_loopback())
}

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap()
}

/// Materialize a `Body` from a producer, assigning registry fields. The
/// signature is over ProducerContent (which excludes the registry
/// fields), so the assigned ctx_id/lineage_id do not affect validity.
fn body_of(producer: &Producer) -> Body {
    let req = producer
        .publish_request()
        .title("verify-algorithm body")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("valid request");
    Body::from_publish_request(
        &req,
        CtxId(CTX.into()),
        LineageId(LIN.into()),
        "localhost",
        ts(),
    )
}

/// A did_doc router that counts how many times the DID document is
/// fetched — lets a test assert that a structural failure short-circuits
/// before any network resolution.
fn counting_router(did_doc: Value, counter: Arc<AtomicUsize>) -> Router {
    let doc = Arc::new(did_doc);
    Router::new().route(
        "/.well-known/did.json",
        get(move || {
            let doc = doc.clone();
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Json((*doc).clone())
            }
        }),
    )
}

// ── happy path (body pipeline) ───────────────────────────────────────────────

#[tokio::test]
async fn verify_body_happy_ed25519() {
    let key = SigningKey::generate();
    let pub_bytes = key.verifying_key_bytes();
    let server = TlsTestServer::start_with(|port| {
        let did = format!("did:web:localhost%3A{port}");
        did_doc_router(ed25519_did_doc(&did, "key-1", &pub_bytes))
    })
    .await;
    let did = server.did();
    let producer = Producer::new(key, AgentDid::new(did.clone()), format!("{did}#key-1"));
    let body = body_of(&producer);
    let resolver = test_resolver(&server.root_cert_pem);
    Verifier::new(&resolver)
        .verify_body(&body)
        .await
        .expect("honest body MUST verify end-to-end");
}

// ── step 1 — key_id fragment form ────────────────────────────────────────────

#[tokio::test]
async fn key_id_without_fragment_rejected() {
    let (body, resolver) = body_and_resolver().await;
    let mut body = body;
    body.signature.key_id = body.agent_id.as_str().to_string(); // no '#'
    let err = Verifier::new(&resolver)
        .verify_body_signature(&body)
        .await
        .expect_err("key_id without a fragment MUST be rejected");
    assert!(matches!(err, AcdpError::KeyResolution(_)), "got {err:?}");
}

#[tokio::test]
async fn key_id_empty_fragment_rejected() {
    // Regression for issue #22: an empty fragment must not be used as a
    // lookup key.
    let (body, resolver) = body_and_resolver().await;
    let mut body = body;
    body.signature.key_id = format!("{}#", body.agent_id.as_str());
    let err = Verifier::new(&resolver)
        .verify_body_signature(&body)
        .await
        .expect_err("empty fragment MUST be rejected");
    assert!(matches!(err, AcdpError::KeyResolution(_)), "got {err:?}");
}

// ── step 2 — key_id DID must equal agent_id ──────────────────────────────────

#[tokio::test]
async fn key_id_did_mismatch_rejected() {
    let (body, resolver) = body_and_resolver().await;
    let mut body = body;
    body.signature.key_id = "did:web:elsewhere.example.com#key-1".into();
    let err = Verifier::new(&resolver)
        .verify_body_signature(&body)
        .await
        .expect_err("key_id DID ≠ agent_id MUST be rejected");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

// ── step 1.5 — method dispatch ───────────────────────────────────────────────

#[tokio::test]
async fn unsupported_did_method_rejected() {
    // A key_id/agent_id under an unsupported DID method reaches neither
    // the did:key nor the did:web path. The producer builder refuses to
    // emit a did:example agent, so we mutate an honest body's envelope
    // (agent_id + key_id) — verify_body_signature skips structural
    // validation, so step 2 (DID equality) passes and step 1.5 rejects.
    let (mut body, resolver) = body_and_resolver().await;
    body.agent_id = AgentDid::new("did:example:1234");
    body.signature.key_id = "did:example:1234#key-1".into();
    let err = Verifier::new(&resolver)
        .verify_body_signature(&body)
        .await
        .expect_err("unsupported DID method MUST be rejected");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

// ── step 3 — DID document resolution ─────────────────────────────────────────

#[tokio::test]
async fn resolver_failure_is_key_resolution_unreachable() {
    // Server serves no /.well-known/did.json → 404 → resolution fails.
    // Since 0.15.0 a non-2xx DID-document fetch is transient
    // (`key_resolution_unreachable`, RFC-ACDP-0001 §5.11 step 3, did-001 A).
    let key = SigningKey::generate();
    let server = TlsTestServer::start(Router::new()).await;
    let did = server.did();
    let producer = Producer::new(key, AgentDid::new(did.clone()), format!("{did}#key-1"));
    let body = body_of(&producer);
    let resolver = test_resolver(&server.root_cert_pem);
    let err = Verifier::new(&resolver)
        .verify_body_signature(&body)
        .await
        .expect_err("unresolvable DID MUST fail");
    assert!(
        matches!(err, AcdpError::KeyResolutionUnreachable(_)),
        "got {err:?}"
    );
    assert!(err.is_transient());
}

// ── step 4 — fragment present in the DID document ────────────────────────────

#[tokio::test]
async fn fragment_absent_from_doc_rejected() {
    // Doc publishes key-1; the body signs with key_id #key-2.
    let key = SigningKey::generate();
    let pub_bytes = key.verifying_key_bytes();
    let server = TlsTestServer::start_with(move |port| {
        let did = format!("did:web:localhost%3A{port}");
        did_doc_router(ed25519_did_doc(&did, "key-1", &pub_bytes))
    })
    .await;
    let did = server.did();
    let producer = Producer::new(key, AgentDid::new(did.clone()), format!("{did}#key-2"));
    let body = body_of(&producer);
    let resolver = test_resolver(&server.root_cert_pem);
    let err = Verifier::new(&resolver)
        .verify_body_signature(&body)
        .await
        .expect_err("missing fragment in DID doc MUST fail");
    assert!(matches!(err, AcdpError::KeyResolution(_)), "got {err:?}");
}

// ── step 5.5 — algorithm-downgrade rejection ─────────────────────────────────

#[tokio::test]
async fn algorithm_downgrade_rejected() {
    // The DID doc declares an Ed25519 key; the signature envelope claims
    // ecdsa-p256. The declared-vs-declared mismatch MUST be rejected
    // before any signature math (RFC-ACDP-0008 §3.9).
    let key = SigningKey::generate();
    let pub_bytes = key.verifying_key_bytes();
    let server = TlsTestServer::start_with(move |port| {
        let did = format!("did:web:localhost%3A{port}");
        did_doc_router(ed25519_did_doc(&did, "key-1", &pub_bytes))
    })
    .await;
    let did = server.did();
    let producer = Producer::new(key, AgentDid::new(did.clone()), format!("{did}#key-1"));
    let mut body = body_of(&producer);
    body.signature.algorithm = "ecdsa-p256".into();
    let resolver = test_resolver(&server.root_cert_pem);
    let err = Verifier::new(&resolver)
        .verify_body_signature(&body)
        .await
        .expect_err("algorithm downgrade MUST be rejected");
    assert!(matches!(err, AcdpError::InvalidSignature(_)), "got {err:?}");
}

// ── step 0 ordering — structural failure precedes DID fetch ──────────────────

#[tokio::test]
async fn structural_failure_precedes_did_fetch() {
    let key = SigningKey::generate();
    let pub_bytes = key.verifying_key_bytes();
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_router = counter.clone();
    let server = TlsTestServer::start_with(move |port| {
        let did = format!("did:web:localhost%3A{port}");
        counting_router(
            ed25519_did_doc(&did, "key-1", &pub_bytes),
            counter_for_router,
        )
    })
    .await;
    let did = server.did();
    let producer = Producer::new(key, AgentDid::new(did.clone()), format!("{did}#key-1"));
    let mut body = body_of(&producer);
    // Inverted data_period → structural failure.
    body.data_period = Some(DataPeriod {
        start: ts(),
        end: ts() - chrono::Duration::days(1),
    });
    let resolver = test_resolver(&server.root_cert_pem);
    let err = Verifier::new(&resolver)
        .verify_body(&body)
        .await
        .expect_err("structurally invalid body MUST fail");
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "verify_body MUST NOT resolve the DID document when structural validation fails"
    );
}

// ── historical-key verification (ACDP 0.2, WS-B) ─────────────────────────────

#[tokio::test]
async fn historical_key_rotated_out_of_assertion_still_verifies() {
    // A key retained in verificationMethod but dropped from
    // assertionMethod (rotated out) MUST still verify under the
    // historical path.
    let key = SigningKey::generate();
    let pub_bytes = key.verifying_key_bytes();
    let server = TlsTestServer::start_with(move |port| {
        let did = format!("did:web:localhost%3A{port}");
        did_doc_router(ed25519_did_doc_without_assertion(&did, "key-1", &pub_bytes))
    })
    .await;
    let did = server.did();
    let producer = Producer::new(key, AgentDid::new(did.clone()), format!("{did}#key-1"));
    let body = body_of(&producer);
    let resolver = test_resolver(&server.root_cert_pem);
    // Standard path rejects it (not in assertionMethod)…
    let err = Verifier::new(&resolver)
        .verify_body_signature(&body)
        .await
        .expect_err("standard path requires assertionMethod");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
    // …the historical path accepts it.
    verify_body_signature_historical(&body, &resolver)
        .await
        .expect("rotated-out key MUST verify under the historical path");
}

#[tokio::test]
async fn historical_key_fully_removed_fails_closed() {
    // The signing key is not in the served DID document at all → the
    // historical path fails closed.
    let key = SigningKey::generate();
    let other_pub = SigningKey::generate().verifying_key_bytes();
    let server = TlsTestServer::start_with(move |port| {
        let did = format!("did:web:localhost%3A{port}");
        // Doc publishes a *different* key under key-1.
        did_doc_router(ed25519_did_doc(&did, "key-1", &other_pub))
    })
    .await;
    let did = server.did();
    let producer = Producer::new(key, AgentDid::new(did.clone()), format!("{did}#key-2"));
    let body = body_of(&producer);
    let resolver = test_resolver(&server.root_cert_pem);
    let err = verify_body_signature_historical(&body, &resolver)
        .await
        .expect_err("a removed key MUST fail closed");
    assert!(matches!(err, AcdpError::KeyResolution(_)), "got {err:?}");
}

// ── resolver-backed lifecycle event (RFC-ACDP-0013 §5) ───────────────────────

#[tokio::test]
async fn lifecycle_event_registry_actor_did_web_verifies() {
    let key = SigningKey::generate();
    let pub_bytes = key.verifying_key_bytes();
    let server = TlsTestServer::start_with(move |port| {
        let did = format!("did:web:localhost%3A{port}");
        did_doc_router(ed25519_did_doc(&did, "key-1", &pub_bytes))
    })
    .await;
    let did = server.did();
    let actor = AgentDid::new(did.clone());
    let event = LifecycleEvent::new(
        EVENT_ID,
        CtxId(CTX.into()),
        LifecycleEventType::Retracted,
        ts(),
        actor.clone(),
        Some("superseded".into()),
    )
    .expect("valid event")
    .sign_with(key, format!("{did}#key-1"))
    .expect("signed event");
    let raw = serde_json::to_value(&event).expect("serializes");
    let resolver = test_resolver(&server.root_cert_pem);
    // Producer is someone else; the registry DID is the actor.
    let producer = AgentDid::new("did:web:producer.example.com");
    let out = verify_lifecycle_event(
        &raw,
        &CtxId(CTX.into()),
        &producer,
        Some(did.as_str()),
        &resolver,
    )
    .await;
    assert!(
        out.is_ok(),
        "registry-actor did:web event MUST verify: {out:?}"
    );
}

// Shared setup: an honest did:web body plus a resolver that trusts the
// harness. The individual tests then mutate the body's signature to
// isolate a single step's failure.
async fn body_and_resolver() -> (Body, WebResolver) {
    let key = SigningKey::generate();
    let pub_bytes = key.verifying_key_bytes();
    let server = TlsTestServer::start_with(move |port| {
        let did = format!("did:web:localhost%3A{port}");
        did_doc_router(ed25519_did_doc(&did, "key-1", &pub_bytes))
    })
    .await;
    let did = server.did();
    let producer = Producer::new(key, AgentDid::new(did.clone()), format!("{did}#key-1"));
    let body = body_of(&producer);
    let resolver = test_resolver(&server.root_cert_pem);
    (body, resolver)
}
