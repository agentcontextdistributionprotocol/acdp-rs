//! Strict Ed25519 verification at every public verification entry point
//! (RFC-ACDP-0001 §5.10, conformance vector `sig-004`, acdp-rs#342).
//!
//! The forgery: public key `A` = identity, nonce `R` = identity, `s = 0`.
//! The cofactorless equation `[s]B = R + [k]A` then holds for EVERY
//! message, so a non-strict verifier accepts it as a signature by the
//! (small-order) key over anything. Each test below takes an object that
//! the entry point would otherwise accept, binds it to the identity key,
//! substitutes the forged signature, and asserts the entry point's
//! signature-failure verdict. Every entry point funnels into
//! `acdp_crypto::verify::verify_ed25519`, so these tests fail together if
//! that one call site ever regresses to non-strict `verify`.

mod common;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};

use acdp::crypto::sign::SigningKey;
use acdp::did::WebResolver;
use acdp::producer::Producer;
use acdp::safe_http::SsrfPolicy;
use acdp::types::body::Body;
use acdp::types::cosignature::WitnessSigner;
use acdp::types::lifecycle::{LifecycleEvent, LifecycleEventType};
use acdp::types::primitives::{AgentDid, ContentHash, ContextType, CtxId, LineageId, Visibility};
use acdp::types::receipt::ReceiptSigner;
use acdp::verify::{
    verify_body_signature_historical, verify_did_key_envelope, verify_lifecycle_event_offline,
    verify_publish_request_signature, verify_publish_request_signature_offline, Verifier,
};
use acdp::AcdpError;

use common::{did_doc_router, ed25519_did_doc, ed25519_did_doc_without_assertion, TlsTestServer};

const CTX: &str = "acdp://localhost/00000000-0000-4000-8000-000000000000";
const LIN: &str = "lin:sha256:0000000000000000000000000000000000000000000000000000000000000000";
const REGISTRY_DID: &str = "did:web:registry.example.com";
const LOG_ID: &str = "did:web:registry.example.com/log/1";

/// The Edwards25519 identity point (order 1), the first sig-004 encoding.
fn identity() -> [u8; 32] {
    let mut p = [0u8; 32];
    p[0] = 1;
    p
}

/// sig-004 `signature_value_hex`: `R` = identity, `s` = 0.
fn forged_sig_b64() -> String {
    let mut sig = [0u8; 64];
    sig[0] = 1;
    STANDARD.encode(sig)
}

fn ts() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).unwrap()
}

fn test_resolver(root_cert_pem: &[u8]) -> WebResolver {
    WebResolver::with_root_cert_pem(root_cert_pem)
        .expect("resolver")
        .with_ssrf_policy(SsrfPolicy::allow_test_loopback())
}

fn identity_did_key() -> (AgentDid, String) {
    let did = acdp::did::key::did_key_from_ed25519(&identity());
    let key_id = acdp::did::key::did_key_url(&did).expect("did:key url");
    (AgentDid::new(did), key_id)
}

fn request_of(producer: &Producer) -> acdp::types::publish::PublishRequest {
    producer
        .publish_request()
        .title("strict ed25519")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("valid request")
}

fn body_of(producer: &Producer) -> Body {
    Body::from_publish_request(
        &request_of(producer),
        CtxId(CTX.into()),
        LineageId(LIN.into()),
        "localhost",
        ts(),
    )
}

/// A did:web producer whose DID document publishes the identity point
/// under `#key-1`, plus a resolver trusting the harness. `in_assertion`
/// selects the standard vs. rotated-out (historical) document shape.
async fn small_order_did_web(in_assertion: bool) -> (TlsTestServer, Producer, WebResolver) {
    let server = TlsTestServer::start_with(move |port| {
        let did = format!("did:web:localhost%3A{port}");
        let doc = if in_assertion {
            ed25519_did_doc(&did, "key-1", &identity())
        } else {
            ed25519_did_doc_without_assertion(&did, "key-1", &identity())
        };
        did_doc_router(doc)
    })
    .await;
    let did = server.did();
    // The signing key is irrelevant: the signature is replaced below.
    let producer = Producer::new(
        SigningKey::generate(),
        AgentDid::new(did.clone()),
        format!("{did}#key-1"),
    );
    let resolver = test_resolver(&server.root_cert_pem);
    (server, producer, resolver)
}

// ── publish (resolver-backed and offline) ───────────────────────────────────

#[tokio::test]
async fn publish_did_web_small_order_key_rejected() {
    let (_server, producer, resolver) = small_order_did_web(true).await;
    let mut req = request_of(&producer);
    req.signature.value = forged_sig_b64();
    let err = verify_publish_request_signature(&req, &resolver)
        .await
        .expect_err("sig-004 forgery MUST be rejected on publish");
    assert!(matches!(err, AcdpError::InvalidSignature(_)), "got {err:?}");

    // Same body pipeline: Verifier::verify_body_signature.
    let mut body = body_of(&producer);
    body.signature.value = forged_sig_b64();
    let err = Verifier::new(&resolver)
        .verify_body_signature(&body)
        .await
        .expect_err("sig-004 forgery MUST be rejected on retrieval");
    assert!(matches!(err, AcdpError::InvalidSignature(_)), "got {err:?}");
}

#[test]
fn publish_offline_did_key_small_order_key_rejected() {
    let (did, key_id) = identity_did_key();
    let mut req = request_of(&Producer::new_did_key(SigningKey::from_bytes(&[4u8; 32])));
    req.agent_id = did;
    req.signature.key_id = key_id;
    req.signature.value = forged_sig_b64();
    let err = verify_publish_request_signature_offline(&req)
        .expect_err("sig-004 forgery MUST be rejected offline");
    assert!(matches!(err, AcdpError::InvalidSignature(_)), "got {err:?}");
}

// ── did:key envelope ─────────────────────────────────────────────────────────

#[test]
fn did_key_envelope_small_order_key_rejected() {
    let (_did, key_id) = identity_did_key();
    let mut sig = request_of(&Producer::new_did_key(SigningKey::from_bytes(&[4u8; 32])))
        .signature
        .clone();
    sig.key_id = key_id;
    sig.value = forged_sig_b64();
    let hash = ContentHash(
        "sha256:ccd2641662848a5168095e629c2c90336441bc0d61464e3d8066ea3c147fbaea".into(),
    );
    let err = verify_did_key_envelope(&sig, &hash).expect_err("did:key forgery MUST be rejected");
    assert!(matches!(err, AcdpError::InvalidSignature(_)), "got {err:?}");
}

// ── historical-key path ──────────────────────────────────────────────────────

#[tokio::test]
async fn historical_small_order_key_rejected() {
    let (_server, producer, resolver) = small_order_did_web(false).await;
    let mut body = body_of(&producer);
    body.signature.value = forged_sig_b64();
    let err = verify_body_signature_historical(&body, &resolver)
        .await
        .expect_err("sig-004 forgery MUST be rejected on the historical path");
    assert!(matches!(err, AcdpError::InvalidSignature(_)), "got {err:?}");
}

// ── lifecycle event ──────────────────────────────────────────────────────────

#[test]
fn lifecycle_small_order_key_rejected() {
    let (actor, key_id) = identity_did_key();
    let event = LifecycleEvent::new(
        "00000000-0000-4000-8000-0000000000aa",
        CtxId(CTX.into()),
        LifecycleEventType::Retracted,
        ts(),
        actor.clone(),
        Some("superseded".into()),
    )
    .expect("valid event")
    .sign_with(SigningKey::from_bytes(&[5u8; 32]), key_id)
    .expect("signed event");
    let mut raw = serde_json::to_value(&event).unwrap();
    raw["signature"]["value"] = serde_json::json!(forged_sig_b64());
    let err = verify_lifecycle_event_offline(&raw, &CtxId(CTX.into()), &actor, None)
        .expect_err("sig-004 forgery MUST be rejected on a lifecycle event");
    assert!(matches!(err, AcdpError::InvalidSignature(_)), "got {err:?}");
}

// ── registry receipt, log checkpoint, witness cosignature ───────────────────

fn receipt_signer() -> ReceiptSigner {
    ReceiptSigner::new(
        SigningKey::from_bytes(&[0x11u8; 32]),
        REGISTRY_DID,
        format!("{REGISTRY_DID}#receipt-key-1"),
    )
    .unwrap()
}

#[test]
fn receipt_small_order_key_rejected() {
    let mut receipt = receipt_signer()
        .mint(
            &CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into()),
            &LineageId(format!("lin:sha256:{}", "a".repeat(64))),
            "registry.example.com",
            ts(),
            &ContentHash(format!("sha256:{}", "b".repeat(64))),
            &format!("sha256:{}", "c".repeat(64)),
        )
        .unwrap();
    receipt.signature.value = forged_sig_b64();
    let err = receipt
        .verify_signature_with_key(Some(&identity()), None)
        .expect_err("sig-004 forgery MUST be rejected on a receipt");
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");
}

fn checkpoint() -> acdp::types::log::LogCheckpoint {
    let root = acdp::types::log::encode_sha256_hex(&acdp::crypto::merkle_tree_hash(&[]));
    receipt_signer()
        .mint_log_checkpoint(LOG_ID, 0, &root, ts())
        .unwrap()
}

#[test]
fn checkpoint_small_order_key_rejected() {
    let mut cp = checkpoint();
    cp.signature.value = forged_sig_b64();
    let err = cp
        .verify_signature_with_key(Some(&identity()), None)
        .expect_err("sig-004 forgery MUST be rejected on a log checkpoint");
    assert!(matches!(err, AcdpError::InvalidLogProof(_)), "got {err:?}");
}

#[test]
fn cosignature_small_order_key_rejected() {
    let witness = "did:web:witness.example.org";
    let mut cosig = WitnessSigner::new(
        SigningKey::from_bytes(&[0x33u8; 32]),
        witness,
        format!("{witness}#witness-key-1"),
    )
    .unwrap()
    .mint(&checkpoint(), ts())
    .unwrap();
    cosig.signature.value = forged_sig_b64();
    let err = cosig
        .verify_signature_with_key(Some(&identity()), None)
        .expect_err("sig-004 forgery MUST be rejected on a witness cosignature");
    assert!(
        matches!(err, AcdpError::InvalidWitnessCosignature(_)),
        "got {err:?}"
    );
}
