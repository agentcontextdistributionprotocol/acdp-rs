//! RFC-ACDP-0021 §8 consumer verification of keyless-signed bodies over
//! an in-process TLS registry: `kl-005`, `kl-006`, the consumer side of
//! `kl-007` and `kl-009`.
//!
//! The registry here is a static fixture server: it serves the
//! attestation and the keyless-signed body exactly as a keyless registry
//! would store them (bodies built with the producer API, receipts minted
//! with `ReceiptSigner`), so each scenario can change one input.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use acdp::client::{
    KeyAuthorization, KeylessPolicy, RegistryClient, RevocationPolicy, VerificationPolicy,
    VerifiedContext,
};
use acdp::crypto::fingerprint::fingerprint_ed25519;
use acdp::crypto::{derive_lineage_id, SigningKey};
use acdp::did::WebResolver;
use acdp::error::AcdpError;
use acdp::producer::keyless::EphemeralKey;
use acdp::producer::Producer;
use acdp::types::keyless::{
    IdentityDescriptor, KeyAttestation, KeylessReason, WorkloadIdentity, ATTESTATION_VERSION,
    KEY_ATTESTATION_SCHEMA_URI, KEY_ATTESTATION_TYPE,
};
use acdp::types::receipt::ReceiptSigner;
use acdp::types::revocation::{KeyRevocation, RevocationTrustClass};
use acdp::types::{AgentDid, Body, ContextType, CtxId, PublishRequest};
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use common::{ed25519_did_doc, TlsTestServer};
use serde_json::{json, Value};

const AUTHORITY: &str = "localhost";
const REGISTRY_DID: &str = "did:web:localhost";
const OTHER_REGISTRY_DID: &str = "did:web:localhost:other";
const CONTROLLER: &str = "did:web:localhost:agent";
const REGISTRY_SEED: [u8; 32] = [0x11; 32];
const CONTROLLER_SEED: [u8; 32] = [0x22; 32];
const EPHEMERAL_SEED: [u8; 32] = [0x66; 32];
const ISSUER: &str = "https://token.actions.githubusercontent.com";
const SUBJECT: &str = "repo:example/pipeline:ref:refs/heads/main";
const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.TEST-ONLY-NOT-A-REAL-TOKEN.kl";

fn identity() -> WorkloadIdentity {
    WorkloadIdentity::Oidc {
        issuer: ISSUER.into(),
        subject: SUBJECT.into(),
    }
}

fn controller_doc(listed: bool) -> Value {
    let mut doc = ed25519_did_doc(
        CONTROLLER,
        "key-1",
        &SigningKey::from_bytes(&CONTROLLER_SEED).verifying_key_bytes(),
    );
    let identities = if listed {
        json!([{"type": "oidc", "issuer": ISSUER, "subject": SUBJECT}])
    } else {
        json!([])
    };
    doc["service"] = json!([{
        "id": format!("{CONTROLLER}#acdp-keyless"),
        "type": "AcdpKeylessSigning",
        "serviceEndpoint": {"identities": identities}
    }]);
    doc
}

struct Harness {
    tls: TlsTestServer,
    contexts: Arc<RwLock<HashMap<String, Value>>>,
    controller: Arc<RwLock<Value>>,
    resolver: WebResolver,
}

async fn harness() -> Harness {
    let registry_doc = ed25519_did_doc(
        REGISTRY_DID,
        "receipt-key-1",
        &SigningKey::from_bytes(&REGISTRY_SEED).verifying_key_bytes(),
    );
    let contexts: Arc<RwLock<HashMap<String, Value>>> = Arc::default();
    let controller = Arc::new(RwLock::new(controller_doc(true)));
    let router = Router::new()
        .route(
            "/.well-known/did.json",
            get(move || {
                let doc = registry_doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/agent/did.json",
            get({
                let doc = controller.clone();
                move || {
                    let doc = doc.clone();
                    async move { Json(doc.read().unwrap().clone()) }
                }
            }),
        )
        .route(
            "/contexts/{id}",
            get({
                let contexts = contexts.clone();
                move |Path(id): Path<String>| {
                    let contexts = contexts.clone();
                    async move {
                        match contexts.read().unwrap().get(&id) {
                            Some(v) => Json(v.clone()).into_response(),
                            None => (
                                StatusCode::NOT_FOUND,
                                Json(json!({"error": {"code": "not_found", "message": "no such context"}})),
                            )
                                .into_response(),
                        }
                    }
                }
            }),
        )
        .route(
            "/contexts/search",
            get({
                let contexts = contexts.clone();
                move |Query(q): Query<HashMap<String, String>>| {
                    let contexts = contexts.clone();
                    async move {
                        let matches: Vec<Value> = contexts
                            .read()
                            .unwrap()
                            .values()
                            .filter(|c| {
                                Some(&c["body"]["type"]) == q.get("type").map(|t| json!(t)).as_ref()
                                    && Some(&c["body"]["agent_id"])
                                        == q.get("agent_id").map(|a| json!(a)).as_ref()
                                    && Some(&c["registry_state"]["status"])
                                        == q.get("status").map(|s| json!(s)).as_ref()
                            })
                            .map(|c| {
                                let b = &c["body"];
                                json!({
                                    "ctx_id": b["ctx_id"],
                                    "lineage_id": b["lineage_id"],
                                    "agent_id": b["agent_id"],
                                    "title": b["title"],
                                    "type": b["type"],
                                    "created_at": b["created_at"],
                                    "status": c["registry_state"]["status"],
                                    "visibility": b["visibility"],
                                })
                            })
                            .collect();
                        Json(json!({"matches": matches}))
                    }
                }
            }),
        )
        .route(
            "/lineages/{id}",
            get({
                let contexts = contexts.clone();
                move |Path(id): Path<String>| {
                    let contexts = contexts.clone();
                    async move {
                        let members: Vec<Value> = contexts
                            .read()
                            .unwrap()
                            .values()
                            .filter(|c| c["body"]["lineage_id"] == json!(id))
                            .cloned()
                            .collect();
                        Json(json!(members))
                    }
                }
            }),
        )
        .route(
            "/key-attestations",
            get({
                let contexts = contexts.clone();
                move || {
                    let contexts = contexts.clone();
                    async move {
                        let items: Vec<Value> = contexts
                            .read()
                            .unwrap()
                            .values()
                            .filter(|c| c["body"]["type"] == KEY_ATTESTATION_TYPE)
                            .map(|c| {
                                json!({
                                    "ctx_id": c["body"]["ctx_id"],
                                    "content_hash": c["body"]["content_hash"],
                                    "metadata": c["body"]["metadata"],
                                })
                            })
                            .collect();
                        Json(json!({"items": items, "next_cursor": null}))
                    }
                }
            })
            .post({
                let contexts = contexts.clone();
                move || {
                    let contexts = contexts.clone();
                    async move {
                        let att = contexts
                            .read()
                            .unwrap()
                            .values()
                            .find(|c| c["body"]["type"] == KEY_ATTESTATION_TYPE)
                            .cloned()
                            .unwrap();
                        (StatusCode::CREATED, Json(att))
                    }
                }
            }),
        );
    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, AUTHORITY, tls.addr)
        .expect("pinned resolver");
    Harness {
        tls,
        contexts,
        controller,
        resolver,
    }
}

impl Harness {
    fn client(&self) -> RegistryClient {
        RegistryClient::with_test_endpoint(
            &format!("https://{AUTHORITY}"),
            self.tls.addr,
            &self.tls.root_cert_pem,
        )
        .expect("pinned client")
    }

    fn serve(&self, ctx: &Value) {
        let id = ctx["body"]["ctx_id"].as_str().unwrap().to_owned();
        self.contexts.write().unwrap().insert(id, ctx.clone());
    }

    fn list_identity(&self, listed: bool) {
        *self.controller.write().unwrap() = controller_doc(listed);
        self.resolver.invalidate(CONTROLLER);
    }
}

fn new_ctx_id() -> CtxId {
    CtxId::parse(format!("acdp://{AUTHORITY}/{}", uuid::Uuid::new_v4())).unwrap()
}

fn signer(registry_did: &str) -> ReceiptSigner {
    ReceiptSigner::new(
        SigningKey::from_bytes(&REGISTRY_SEED),
        registry_did,
        format!("{registry_did}#receipt-key-1"),
    )
    .unwrap()
}

/// Store `req` as the registry would: the body, `status`, and (when
/// `receipt_by` is set) a receipt naming `fingerprint`.
fn stored(
    req: &PublishRequest,
    created_at: DateTime<Utc>,
    receipt_by: Option<&ReceiptSigner>,
    fingerprint: &str,
    status: &str,
) -> (Body, Value) {
    let ctx_id = new_ctx_id();
    let lineage = derive_lineage_id(&ctx_id);
    let body =
        Body::from_publish_request(req, ctx_id.clone(), lineage.clone(), AUTHORITY, created_at);
    let mut ctx = json!({
        "body": body,
        "registry_state": {"status": status},
    });
    if let Some(signer) = receipt_by {
        let receipt = signer
            .mint(
                &ctx_id,
                &lineage,
                AUTHORITY,
                body.created_at,
                &body.content_hash,
                fingerprint,
            )
            .unwrap();
        ctx["registry_receipt"] = serde_json::to_value(receipt).unwrap();
    }
    (body, ctx)
}

struct Fixture {
    attestation: Body,
    attestation_ctx: Value,
    body_req: PublishRequest,
    fingerprint: String,
    created_at: DateTime<Utc>,
}

/// An attestation for the ephemeral key, window [now-60s, now+540s),
/// and a keyless body signed under it.
fn fixture(attestation_status: &str) -> Fixture {
    fixture_with(attestation_status, REGISTRY_DID)
}

fn fixture_with(attestation_status: &str, attestation_agent: &str) -> Fixture {
    fixture_full(attestation_status, attestation_agent, false)
}

fn fixture_full(attestation_status: &str, attestation_agent: &str, org_wide: bool) -> Fixture {
    let now = acdp::time::trunc_ms(Utc::now());
    let key = EphemeralKey::from_key(SigningKey::from_bytes(&EPHEMERAL_SEED).into());
    let fingerprint = key.fingerprint().unwrap();
    let metadata = KeyAttestation {
        attestation_version: ATTESTATION_VERSION.into(),
        controller: CONTROLLER.into(),
        identity: identity(),
        org_wide,
        key_id: key.key_id(CONTROLLER).unwrap(),
        algorithm: "ed25519".into(),
        public_key_jwk: key.jwk().unwrap(),
        key_fingerprint: fingerprint.clone(),
        not_before: now - Duration::seconds(60),
        not_after: now + Duration::seconds(540),
        token_hash: acdp::types::keyless::token_hash(TOKEN),
    };
    let registry = Producer::new(
        SigningKey::from_bytes(&REGISTRY_SEED),
        AgentDid::new(attestation_agent),
        format!("{REGISTRY_DID}#receipt-key-1"),
    );
    let registry = if attestation_agent == REGISTRY_DID {
        registry
    } else {
        Producer::new(
            SigningKey::from_bytes(&CONTROLLER_SEED),
            AgentDid::new(attestation_agent),
            format!("{attestation_agent}#key-1"),
        )
    };
    let att_req = registry
        .publish_request()
        .title("Key attestation")
        .context_type(ContextType::Custom(KEY_ATTESTATION_TYPE.into()))
        .metadata(serde_json::to_value(&metadata).unwrap())
        .schema_uri(KEY_ATTESTATION_SCHEMA_URI)
        .acdp_version("0.5.0")
        .build()
        .unwrap();
    let registry_fp =
        fingerprint_ed25519(&SigningKey::from_bytes(&REGISTRY_SEED).verifying_key_bytes());
    let (attestation, attestation_ctx) = stored(
        &att_req,
        now - Duration::seconds(60),
        Some(&signer(REGISTRY_DID)),
        &registry_fp,
        attestation_status,
    );

    // Build the body through the producer API (the attestation as the
    // producer would see it, before any test mutation).
    let ok_attestation = if attestation_agent == REGISTRY_DID {
        attestation.clone()
    } else {
        let mut b = attestation.clone();
        b.agent_id = AgentDid::new(REGISTRY_DID);
        b
    };
    let producer = EphemeralKey::from_key(SigningKey::from_bytes(&EPHEMERAL_SEED).into())
        .into_producer(&ok_attestation)
        .unwrap();
    let body_req = producer
        .publish_request()
        .title("Nightly evaluation summary")
        .context_type(ContextType::Analysis)
        .acdp_version("0.5.0")
        .build()
        .unwrap();
    Fixture {
        attestation,
        attestation_ctx,
        body_req,
        fingerprint,
        created_at: now,
    }
}

fn accepting() -> VerificationPolicy {
    VerificationPolicy {
        keyless: KeylessPolicy::attesters([REGISTRY_DID]),
        ..VerificationPolicy::default()
    }
}

async fn verify(
    h: &Harness,
    ctx: &Value,
    policy: &VerificationPolicy,
) -> Result<VerifiedContext, AcdpError> {
    h.serve(ctx);
    let ctx_id = CtxId::parse(ctx["body"]["ctx_id"].as_str().unwrap()).unwrap();
    VerifiedContext::fetch_with_policy(&h.client(), &h.resolver, &ctx_id, policy).await
}

/// Serve the fixture and verify its keyless body under `policy`.
async fn run(
    h: &Harness,
    fx: &Fixture,
    policy: &VerificationPolicy,
) -> Result<VerifiedContext, AcdpError> {
    h.serve(&fx.attestation_ctx);
    let (_, ctx) = stored(
        &fx.body_req,
        fx.created_at,
        Some(&signer(REGISTRY_DID)),
        &fx.fingerprint,
        "active",
    );
    verify(h, &ctx, policy).await
}

fn reason(r: Result<VerifiedContext, AcdpError>) -> KeylessReason {
    let e = r.expect_err("must fail closed");
    KeylessReason::of(&e).unwrap_or_else(|| panic!("no keyless reason on {e:?}"))
}

fn revocation(compromised_since: DateTime<Utc>, fingerprint: &str) -> KeyRevocation {
    KeyRevocation {
        revoked_key_fingerprint: fingerprint.into(),
        compromised_since,
        reason: None,
        revoked_key_id: None,
        revoked_key_controller: AgentDid::new(CONTROLLER),
        publisher: AgentDid::new(CONTROLLER),
        trust_class: RevocationTrustClass::ProducerSigned,
        ctx_id: None,
    }
}

// ── kl-005 ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn kl_005_a_currently_authorized() {
    let h = harness().await;
    let fx = fixture("active");
    let v = run(&h, &fx, &accepting()).await.expect("verifies");
    assert_eq!(v.key_status(), KeyAuthorization::CurrentlyAuthorized);
    assert!(v.verified_receipt().is_some());
    assert_eq!(
        v.body().key_attestation().unwrap().unwrap().ctx_id,
        fx.attestation.ctx_id
    );
}

/// kl-005 B and kl-009 A: removing the identity does not reach back.
#[tokio::test]
async fn kl_005_b_kl_009_a_identity_removed_is_historical() {
    let h = harness().await;
    h.list_identity(false);
    let fx = fixture("active");
    let v = run(&h, &fx, &accepting()).await.expect("verifies");
    assert_eq!(v.key_status(), KeyAuthorization::HistoricallyAuthorized);
}

/// kl-005 C/D and kl-009 D: a revocation of the attested fingerprint,
/// placed by the receipt.
#[tokio::test]
async fn kl_005_c_d_kl_009_d_revocation_placed_by_receipt() {
    let h = harness().await;
    let fx = fixture("active");

    let mut policy = accepting();
    policy.revocations = RevocationPolicy::new(vec![revocation(
        fx.created_at + Duration::seconds(1),
        &fx.fingerprint,
    )]);
    // Pre-compromise needs no current document: make it unreachable.
    *h.controller.write().unwrap() = json!({"not": "a did document"});
    h.resolver.invalidate(CONTROLLER);
    let v = run(&h, &fx, &policy)
        .await
        .expect("pre-compromise verifies");
    assert_eq!(
        v.key_status(),
        KeyAuthorization::HistoricallyAuthorizedPreCompromise
    );

    // D: receipt at T is revoked.
    policy.revocations = RevocationPolicy::new(vec![revocation(fx.created_at, &fx.fingerprint)]);
    let err = run(&h, &fx, &policy).await.unwrap_err();
    assert!(matches!(err, AcdpError::KeyRevoked(_)), "{err:?}");
    assert_eq!(KeylessReason::of(&err), Some(KeylessReason::Revoked));
}

/// kl-005 E and kl-009 E: a retracted attestation withdraws the key.
#[tokio::test]
async fn kl_005_e_kl_009_e_retracted_attestation() {
    let h = harness().await;
    let fx = fixture("retracted");
    assert_eq!(
        reason(run(&h, &fx, &accepting()).await),
        KeylessReason::AttestationWithdrawn
    );
}

/// kl-005 F: no receipt, or a receipt from another registry.
#[tokio::test]
async fn kl_005_f_unplaceable() {
    let h = harness().await;
    let fx = fixture("active");
    h.serve(&fx.attestation_ctx);

    let (_, no_receipt) = stored(&fx.body_req, fx.created_at, None, &fx.fingerprint, "active");
    assert_eq!(
        reason(verify(&h, &no_receipt, &accepting()).await),
        KeylessReason::Unplaceable
    );

    let (_, foreign) = stored(
        &fx.body_req,
        fx.created_at,
        Some(&signer(OTHER_REGISTRY_DID)),
        &fx.fingerprint,
        "active",
    );
    assert_eq!(
        reason(verify(&h, &foreign, &accepting()).await),
        KeylessReason::Unplaceable
    );

    // A receipt naming another key.
    let (_, other_key) = stored(
        &fx.body_req,
        fx.created_at,
        Some(&signer(REGISTRY_DID)),
        &format!("sha256:{}", "0".repeat(64)),
        "active",
    );
    assert_eq!(
        reason(verify(&h, &other_key, &accepting()).await),
        KeylessReason::Unplaceable
    );
}

/// The window is checked against the receipt's `created_at` only.
#[tokio::test]
async fn kl_005_receipt_outside_the_window() {
    let h = harness().await;
    let fx = fixture("active");
    h.serve(&fx.attestation_ctx);
    let (_, late) = stored(
        &fx.body_req,
        fx.created_at + Duration::seconds(540),
        Some(&signer(REGISTRY_DID)),
        &fx.fingerprint,
        "active",
    );
    assert_eq!(
        reason(verify(&h, &late, &accepting()).await),
        KeylessReason::OutsideAttestationWindow
    );
}

/// The signature must verify under the attested key.
#[tokio::test]
async fn kl_005_bad_signature() {
    let h = harness().await;
    let mut fx = fixture("active");
    fx.body_req.signature.value =
        SigningKey::from_bytes(&[0x77; 32]).sign_string(fx.body_req.content_hash.as_str());
    assert_eq!(
        reason(run(&h, &fx, &accepting()).await),
        KeylessReason::InvalidSignature
    );
}

/// The attestation must be the one the body pins.
#[tokio::test]
async fn kl_005_attestation_hash_pinned() {
    let h = harness().await;
    let fx = fixture("active");
    h.serve(&fx.attestation_ctx);
    let mut ctx = stored(
        &fx.body_req,
        fx.created_at,
        Some(&signer(REGISTRY_DID)),
        &fx.fingerprint,
        "active",
    )
    .1;
    // Re-point the (signed) body at a different hash: the hash check
    // on the body itself catches the edit first.
    ctx["body"]["key_attestation"]["content_hash"] = json!(format!("sha256:{}", "a".repeat(64)));
    assert!(verify(&h, &ctx, &accepting()).await.is_err());
}

// ── kl-006 ─────────────────────────────────────────────────────────────────

/// kl-006 A: the default accepts no attester.
#[tokio::test]
async fn kl_006_a_default_accepts_no_attester() {
    let h = harness().await;
    let fx = fixture("active");
    assert_eq!(
        reason(run(&h, &fx, &VerificationPolicy::default()).await),
        KeylessReason::UntrustedAttester
    );
    // Accepting another registry does not help.
    let other = VerificationPolicy {
        keyless: KeylessPolicy::attesters(["did:web:registry.example.com"]),
        ..VerificationPolicy::default()
    };
    assert_eq!(
        reason(run(&h, &fx, &other).await),
        KeylessReason::UntrustedAttester
    );
}

/// kl-006 B: an attester in local configuration.
#[tokio::test]
async fn kl_006_b_configured_attester() {
    let h = harness().await;
    let fx = fixture("active");
    run(&h, &fx, &accepting()).await.expect("verifies");
}

/// kl-006 E: an attestation whose agent_id is not the registry of its
/// ctx_id is attestation_invalid.
#[tokio::test]
async fn kl_006_e_attestation_from_another_authority() {
    let h = harness().await;
    let fx = fixture_with("active", CONTROLLER);
    assert_eq!(
        reason(run(&h, &fx, &accepting()).await),
        KeylessReason::AttestationInvalid
    );
}

// ── kl-007 ─────────────────────────────────────────────────────────────────

/// kl-007 A/D: the DID-document path never resolves a keyless key id,
/// with or without the `keyless` feature.
#[tokio::test]
async fn kl_007_a_d_did_document_path_fails_closed() {
    let h = harness().await;
    let fx = fixture("active");
    let (body, _) = stored(
        &fx.body_req,
        fx.created_at,
        Some(&signer(REGISTRY_DID)),
        &fx.fingerprint,
        "active",
    );
    let err = acdp::verify::Verifier::new(&h.resolver)
        .verify_body_signature(&body)
        .await
        .unwrap_err();
    assert!(matches!(err, AcdpError::KeyResolution(_)), "{err:?}");
    let err = acdp::verify::verify_body_signature_historical(&body, &h.resolver)
        .await
        .unwrap_err();
    assert!(matches!(err, AcdpError::KeyResolution(_)), "{err:?}");
}

// ── kl-009 ─────────────────────────────────────────────────────────────────

/// kl-009 C and §5.1: the client side of `/key-attestations`.
#[tokio::test]
async fn kl_009_c_key_attestation_endpoints() {
    let h = harness().await;
    let fx = fixture("active");
    h.serve(&fx.attestation_ctx);
    let client = h.client();

    let list = client
        .list_key_attestations(CONTROLLER, Some(&identity()), None)
        .await
        .unwrap();
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].ctx_id, fx.attestation.ctx_id);
    let att = KeyAttestation::from_metadata(&list.items[0].metadata).unwrap();
    assert_eq!(att.key_fingerprint, fx.fingerprint);
    assert!(list.next_cursor.is_none());

    let key = EphemeralKey::from_key(SigningKey::from_bytes(&EPHEMERAL_SEED).into());
    let req = key
        .attestation_request(
            CONTROLLER,
            REGISTRY_DID,
            IdentityDescriptor::oidc(ISSUER, SUBJECT, TOKEN),
            None,
        )
        .unwrap();
    let minted = client.request_key_attestation(&req).await.unwrap();
    let producer = key.into_producer(&minted.body).unwrap();
    assert!(producer.key_id().contains("#acdp-kl-"));
}

// ── kl-006 C/D: RFC-ACDP-0020 trust-list acceptance ────────────────────────

/// A trust list issued by a did:key, trusting this test registry with
/// `entry_extra` merged into its one entry.
fn trust_lists(entry_extra: Value) -> acdp::client::trust::TrustLists {
    use acdp::types::trust_list::{IssuerPin, TRUST_LIST_SCHEMA_URI, TRUST_LIST_TYPE};
    let now = Utc::now();
    let ms = |t: DateTime<Utc>| acdp::time::fmt_rfc3339_ms(t);
    let registry_fp =
        fingerprint_ed25519(&SigningKey::from_bytes(&REGISTRY_SEED).verifying_key_bytes());
    let mut entry = json!({
        "registry_did": REGISTRY_DID,
        "origin": AUTHORITY,
        "receipt_key_fingerprints": [registry_fp],
    });
    for (k, v) in entry_extra.as_object().unwrap() {
        entry[k] = v.clone();
    }
    let issuer = Producer::new_did_key(SigningKey::from_bytes(&[0x42; 32]));
    let req = issuer
        .publish_request()
        .title("Trust list")
        .context_type(ContextType::Custom(TRUST_LIST_TYPE.into()))
        .schema_uri(TRUST_LIST_SCHEMA_URI)
        .metadata(json!({
            "trust_list_version": "acdp-trust-list/1",
            "list_id": "tenant.keyless",
            "serial": 1,
            "issued_at": ms(now - Duration::hours(1)),
            "valid_from": ms(now - Duration::days(1)),
            "valid_until": ms(now + Duration::days(1)),
            "entries": [entry],
        }))
        .acdp_version("0.5.0")
        .build()
        .unwrap();
    let mut lists = acdp::client::trust::TrustLists::new(vec![IssuerPin::new(
        issuer.key_id().split_once('#').unwrap().0,
        "tenant.keyless",
    )]);
    lists
        .add_offline(&serde_json::to_value(req).unwrap(), &[], false)
        .expect("list held");
    lists
}

fn trusting(lists: &acdp::client::trust::TrustLists) -> VerificationPolicy {
    VerificationPolicy {
        keyless: KeylessPolicy::default().with_trust_lists(acdp::client::KeylessTrust::at(
            lists,
            Utc::now(),
            None,
        )),
        ..VerificationPolicy::default()
    }
}

/// kl-006 C: the keyless body evaluates `trusted` at the attester.
#[tokio::test]
async fn kl_006_c_trust_list_accepts_the_attester() {
    let h = harness().await;
    let fx = fixture("active");
    let v = run(&h, &fx, &trusting(&trust_lists(json!({}))))
        .await
        .expect("trusted attester");
    assert_eq!(v.key_status(), KeyAuthorization::CurrentlyAuthorized);
}

/// kl-006 D: out of scope, or expired, refuses as untrusted_attester.
#[tokio::test]
async fn kl_006_d_trust_list_outcome_other_than_trusted() {
    let h = harness().await;
    let fx = fixture("active");
    let out_of_scope = trust_lists(json!({"scope": {"agent_ids": ["did:web:elsewhere.example"]}}));
    assert_eq!(
        reason(run(&h, &fx, &trusting(&out_of_scope)).await),
        KeylessReason::UntrustedAttester
    );
    let expired = trust_lists(json!({
        "valid_until": acdp::time::fmt_rfc3339_ms(Utc::now() - Duration::hours(2))
    }));
    assert_eq!(
        reason(run(&h, &fx, &trusting(&expired)).await),
        KeylessReason::UntrustedAttester
    );
    // A registry the list does not name.
    let other = trust_lists(json!({
        "registry_did": "did:web:registry.example.com",
        "origin": "registry.example.com"
    }));
    assert_eq!(
        reason(run(&h, &fx, &trusting(&other)).await),
        KeylessReason::UntrustedAttester
    );
}

// ── §9.3: keyless-signed revocations, client and chain agreeing ────────────

/// A body signed by the controller's DID-document key `key-1`, and a
/// revocation of `key-1` signed by the ephemeral keyless key under an
/// attestation (`org_wide` as given), compromised before the body.
struct KeylessRevocationCase {
    fx: Fixture,
    body: Body,
    body_ctx: Value,
    revocation: Body,
    revocation_ctx: Value,
}

fn keyless_revocation_case(org_wide: bool) -> KeylessRevocationCase {
    let fx = fixture_full("active", REGISTRY_DID, org_wide);
    let key1_fp =
        fingerprint_ed25519(&SigningKey::from_bytes(&CONTROLLER_SEED).verifying_key_bytes());
    let req = EphemeralKey::from_key(SigningKey::from_bytes(&EPHEMERAL_SEED).into())
        .into_producer(&fx.attestation)
        .unwrap()
        .publish_request()
        .title("Key revocation")
        .context_type(ContextType::KeyRevocation)
        .visibility(acdp::types::Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": key1_fp,
            "compromised_since": acdp::time::fmt_rfc3339_ms(fx.created_at - Duration::hours(1)),
        }))
        .acdp_version("0.5.0")
        .build()
        .unwrap();
    let (revocation, revocation_ctx) = stored(
        &req,
        fx.created_at,
        Some(&signer(REGISTRY_DID)),
        &fx.fingerprint,
        "active",
    );
    let req = Producer::new(
        SigningKey::from_bytes(&CONTROLLER_SEED),
        AgentDid::new(CONTROLLER),
        format!("{CONTROLLER}#key-1"),
    )
    .publish_request()
    .title("Signed by key-1")
    .context_type(ContextType::Analysis)
    .build()
    .unwrap();
    let (body, body_ctx) = stored(
        &req,
        fx.created_at,
        Some(&signer(REGISTRY_DID)),
        &key1_fp,
        "active",
    );
    KeylessRevocationCase {
        fx,
        body,
        body_ctx,
        revocation,
        revocation_ctx,
    }
}

/// The three outcomes both verifiers must agree on.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Revoked,
    NotRevoked,
    Unknown,
}

async fn client_outcome(case: &KeylessRevocationCase, keyless: KeylessPolicy) -> Outcome {
    let h = harness().await;
    h.serve(&case.fx.attestation_ctx);
    h.serve(&case.revocation_ctx);
    let policy = VerificationPolicy {
        keyless,
        revocations: RevocationPolicy::new(vec![])
            .with_discovery(acdp::client::RevocationDiscovery::producer_signed_only()),
        ..VerificationPolicy::default()
    };
    match verify(&h, &case.body_ctx, &policy).await {
        Ok(v) => {
            assert_eq!(v.key_status(), KeyAuthorization::CurrentlyAuthorized);
            Outcome::NotRevoked
        }
        Err(AcdpError::KeyRevoked(_)) => Outcome::Revoked,
        Err(AcdpError::RevocationUnknown { reason, .. }) => {
            assert_eq!(reason, acdp::client::UnknownReason::UnverifiableCandidate);
            Outcome::Unknown
        }
        Err(e) => panic!("unexpected {e:?}"),
    }
}

fn chain_outcome(case: &KeylessRevocationCase, attesters: &[&str]) -> (Outcome, Option<String>) {
    use acdp::chain::*;
    let observed = acdp::time::fmt_rfc3339_ms(case.fx.created_at - Duration::hours(2));
    let doc = |v: Value| v.as_object().unwrap().clone();
    let mut e = Evidence::new();
    e.did_documents = Some(
        [
            (
                REGISTRY_DID.to_string(),
                vec![DidSnapshot::new(
                    doc(ed25519_did_doc(
                        REGISTRY_DID,
                        "receipt-key-1",
                        &SigningKey::from_bytes(&REGISTRY_SEED).verifying_key_bytes(),
                    )),
                    &observed,
                )],
            ),
            (
                CONTROLLER.to_string(),
                vec![DidSnapshot::new(doc(controller_doc(true)), &observed)],
            ),
        ]
        .into(),
    );
    for ctx in [
        &case.fx.attestation_ctx,
        &case.revocation_ctx,
        &case.body_ctx,
    ] {
        let mut ce = ContextEvidence::new(ctx["body"].clone());
        ce.registry_receipt = Some(ctx["registry_receipt"].clone());
        e.contexts
            .insert(ctx["body"]["ctx_id"].as_str().unwrap().to_owned(), ce);
    }
    e.revocation_discovery = Some(
        [(
            CONTROLLER.to_string(),
            vec![DiscoveryRecord::new(
                AUTHORITY,
                DiscoveryOutcome::NotRevokedComplete,
                acdp::time::fmt_rfc3339_ms(case.fx.created_at + Duration::seconds(1)),
            )],
        )]
        .into(),
    );
    let e = Evidence::from_slice(&serde_json::to_vec(&e).unwrap()).unwrap();
    let id = case.body.ctx_id.as_str().to_owned();
    let v = verify_chain(
        std::slice::from_ref(&id),
        &e,
        &Options::default().with_keyless_attesters(attesters.iter().copied()),
    )
    .unwrap();
    let node = v.nodes.iter().find(|n| n.ctx_id == id).unwrap();
    let kr = node.latest.stages.key_revocation.as_ref().unwrap();
    let outcome = match kr.value {
        KeyRevocationValue::Revoked => Outcome::Revoked,
        KeyRevocationValue::NotRevoked => Outcome::NotRevoked,
        KeyRevocationValue::Unknown => Outcome::Unknown,
        other => panic!("unexpected {other:?}"),
    };
    (outcome, kr.revocation_ctx_id.clone())
}

/// §9.3: an org-wide keyless key's revocation is producer-signed and
/// applies in both verifiers.
#[tokio::test]
async fn kl_009_org_wide_keyless_revocation_applies() {
    let case = keyless_revocation_case(true);
    assert_eq!(
        client_outcome(&case, KeylessPolicy::attesters([REGISTRY_DID])).await,
        Outcome::Revoked
    );
    let (chain, ctx_id) = chain_outcome(&case, &[REGISTRY_DID]);
    assert_eq!(chain, Outcome::Revoked);
    assert_eq!(ctx_id.as_deref(), Some(case.revocation.ctx_id.as_str()));
}

/// kl-005 G: a non-org-wide keyless key's revocation is not applied; the
/// client reports it as a hint.
#[tokio::test]
async fn kl_005_g_non_org_wide_keyless_revocation_is_a_hint() {
    let case = keyless_revocation_case(false);
    let h = harness().await;
    h.serve(&case.fx.attestation_ctx);
    h.serve(&case.revocation_ctx);
    let policy = VerificationPolicy {
        keyless: KeylessPolicy::attesters([REGISTRY_DID]),
        revocations: RevocationPolicy::new(vec![])
            .with_discovery(acdp::client::RevocationDiscovery::producer_signed_only()),
        ..VerificationPolicy::default()
    };
    let v = verify(&h, &case.body_ctx, &policy)
        .await
        .expect("not revoked");
    assert_eq!(v.revocation_hints().len(), 1);
    assert_eq!(chain_outcome(&case, &[REGISTRY_DID]).0, Outcome::NotRevoked);
}

/// A keyless-signed revocation that cannot be evaluated (the attester
/// is not accepted) makes the key's status unknown, never not-revoked,
/// in both verifiers (RFC-ACDP-0014 §7 precedence).
#[tokio::test]
async fn kl_009_unevaluable_keyless_revocation_is_unknown() {
    let case = keyless_revocation_case(true);
    assert_eq!(
        client_outcome(&case, KeylessPolicy::default()).await,
        Outcome::Unknown
    );
    let (chain, ctx_id) = chain_outcome(&case, &[]);
    assert_eq!(chain, Outcome::Unknown);
    assert_eq!(ctx_id.as_deref(), Some(case.revocation.ctx_id.as_str()));
}
