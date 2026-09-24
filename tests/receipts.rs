//! Registry receipts (ACDP 0.2, RFC-ACDP-0010) — end-to-end tests.
//!
//! Covers the rcpt-001..004 fixture behaviors plus the WS-B
//! historical-key path (rot-001): publish over an in-process TLS
//! registry with a receipt signer, retrieve + verify through the full
//! client pipeline, rotate the producer key, and confirm the receipt
//! is what keeps history verifiable — and that everything fails closed
//! without it.

mod common;

use std::sync::{Arc, RwLock};

use acdp::client::{
    HistoricalKeyPolicy, HttpsDataRefFetcher, KeyAuthorization, ReceiptPolicy, RegistryClient,
    VerificationPolicy, VerifiedContext,
};
use acdp::crypto::SigningKey;
use acdp::did::WebResolver;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::registry::{InMemoryStore, RegistryServer, RegistryStore as _};
use acdp::types::receipt::{ReceiptSigner, RegistryReceipt};
use acdp::types::{AgentDid, CapabilitiesDocument, ContextType, CtxId, LineageId, Visibility};
use axum::{routing::get, Json, Router};
use common::{ed25519_did_doc, ed25519_did_doc_without_assertion, TlsTestServer};

const REGISTRY_AUTHORITY: &str = "localhost";
const REGISTRY_DID: &str = "did:web:localhost";
const PRODUCER_DID: &str = "did:web:localhost:agent";

fn caps() -> CapabilitiesDocument {
    use acdp::types::capabilities::Limits;
    CapabilitiesDocument {
        acdp_version: "0.2.0".into(),
        registry_did: REGISTRY_DID.into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into(), "did:key".into()],
        profiles: vec!["acdp-registry-core".into()],
        limits: Limits {
            max_payload_bytes: 1_048_576,
            max_embedded_bytes: 65_536,
            idempotency_key_ttl_seconds: None,
            max_publish_per_minute: None,
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        supports_idempotency_key: false,
        extensions: Default::default(),
    }
}

/// Shared-state harness: one TLS server hosting the registry DID
/// document, a mutable producer DID document, and a mutable retrieval
/// endpoint for the published context.
struct Harness {
    tls: TlsTestServer,
    producer_doc: Arc<RwLock<serde_json::Value>>,
    context_json: Arc<RwLock<Option<serde_json::Value>>>,
    capabilities_json: Arc<RwLock<serde_json::Value>>,
    resolver: WebResolver,
}
async fn start_harness(registry_receipt_pub: &[u8; 32], producer_pub: &[u8; 32]) -> Harness {
    let registry_doc = ed25519_did_doc(REGISTRY_DID, "receipt-key-1", registry_receipt_pub);
    let producer_doc = Arc::new(RwLock::new(ed25519_did_doc(
        PRODUCER_DID,
        "key-1",
        producer_pub,
    )));
    let context_json: Arc<RwLock<Option<serde_json::Value>>> = Arc::new(RwLock::new(None));
    let capabilities_json = Arc::new(RwLock::new(serde_json::to_value(caps()).unwrap()));

    let router = Router::new()
        .route(
            "/.well-known/acdp.json",
            get({
                let caps = capabilities_json.clone();
                move || {
                    let caps = caps.clone();
                    async move { Json(caps.read().unwrap().clone()) }
                }
            }),
        )
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
                let doc = producer_doc.clone();
                move || {
                    let doc = doc.clone();
                    async move { Json(doc.read().unwrap().clone()) }
                }
            }),
        )
        .route(
            "/contexts/{id}",
            get({
                let ctx = context_json.clone();
                move || {
                    let ctx = ctx.clone();
                    async move {
                        Json(
                            ctx.read()
                                .unwrap()
                                .clone()
                                .expect("context not yet published"),
                        )
                    }
                }
            }),
        );

    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    Harness {
        tls,
        producer_doc,
        context_json,
        capabilities_json,
        resolver,
    }
}

impl Harness {
    fn client(&self) -> RegistryClient {
        RegistryClient::with_test_endpoint(
            &format!("https://{REGISTRY_AUTHORITY}"),
            self.tls.addr,
            &self.tls.root_cert_pem,
        )
        .expect("pinned client")
    }

    fn rotate_producer_key_out(&self, old_pub: &[u8; 32]) {
        // Rotation per the RFC-ACDP-0010 retention rule: the old key
        // stays in verificationMethod, leaves assertionMethod.
        *self.producer_doc.write().unwrap() =
            ed25519_did_doc_without_assertion(PRODUCER_DID, "key-1", old_pub);
        self.resolver.invalidate(PRODUCER_DID);
    }

    fn serve_context(&self, value: serde_json::Value) {
        *self.context_json.write().unwrap() = Some(value);
    }

    fn advertise_profiles(&self, profiles: &[&str]) {
        self.capabilities_json.write().unwrap()["profiles"] = serde_json::json!(profiles);
    }
}

/// Publish through the receipt-minting server and return
/// `(ctx_id, full_context_json, response_receipt)`.
async fn publish_with_receipts(
    h: &Harness,
    producer_key: SigningKey,
) -> (CtxId, serde_json::Value, serde_json::Value) {
    publish_with_receipts_titled(h, producer_key, "receipted context").await
}

/// Same as [`publish_with_receipts`] but with a caller-chosen title — used
/// when a test publishes twice and wants the two (otherwise-identical)
/// contexts distinguishable by eye in assertions and failure messages.
/// `ctx_id` distinctness itself does not depend on the title: the registry
/// mints `ctx_id` as `acdp://{authority}/{Uuid::new_v4()}`
/// (`crates/acdp-server/src/registry/validator.rs`), so distinctness comes
/// from UUIDv4 randomness, guarded at runtime by `assert_ne!` at the call
/// site.
async fn publish_with_receipts_titled(
    h: &Harness,
    producer_key: SigningKey,
    title: &str,
) -> (CtxId, serde_json::Value, serde_json::Value) {
    let server = RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY)
        .expect("server")
        .with_receipt_signer(
            ReceiptSigner::new(
                SigningKey::from_bytes(&[0x11u8; 32]),
                REGISTRY_DID,
                format!("{REGISTRY_DID}#receipt-key-1"),
            )
            .expect("signer"),
        )
        .expect("receipt signer accepted");

    let producer = Producer::new(
        producer_key,
        AgentDid::new(PRODUCER_DID),
        format!("{PRODUCER_DID}#key-1"),
    );
    let req = producer
        .publish_request()
        .title(title)
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("build");

    let resp = server
        .publish_verified(&req, None, &h.resolver)
        .await
        .expect("publish with receipt minting");
    let receipt = resp
        .registry_receipt
        .clone()
        .expect("response must carry a receipt");

    let full = server
        .store()
        .get(&resp.ctx_id)
        .expect("store get")
        .expect("present");
    assert!(
        full.registry_receipt.is_some(),
        "persisted context must carry the receipt atomically"
    );
    let ctx_json = serde_json::to_value(&full).expect("serialize");
    (resp.ctx_id, ctx_json, receipt)
}

// ── Happy path: publish → receipt → fetch + verify ──────────────────────────

#[tokio::test]
async fn receipt_minted_verified_end_to_end() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json, response_receipt) = publish_with_receipts(&h, producer_key).await;

    // The response receipt parses, cross-checks, and verifies against
    // the registry key directly (pure path).
    let typed = RegistryReceipt::from_value(&response_receipt).expect("typed receipt");
    assert_eq!(typed.registry_did, REGISTRY_DID);
    assert_eq!(typed.ctx_id, ctx_id);
    typed
        .verify_signature_with_key(Some(&registry_key_pub), None)
        .expect("receipt signature");

    // Full client pipeline, default policy (VerifyIfPresent).
    h.serve_context(ctx_json);
    let client = h.client();
    let verified = VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect("fetch + verify with receipt");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
    let vr = verified.verified_receipt().expect("receipt verified");
    assert_eq!(vr.ctx_id, ctx_id);
    assert_eq!(vr.content_hash, verified.body().content_hash);

    // Require policy also passes when the receipt is present.
    let strict = VerificationPolicy {
        receipts: ReceiptPolicy::Require,
        ..Default::default()
    };
    VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &strict)
        .await
        .expect("Require passes with a verified receipt");
}

// ── Require fails closed without a receipt ──────────────────────────────────

#[tokio::test]
async fn require_policy_fails_without_receipt() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, mut ctx_json, _) = publish_with_receipts(&h, producer_key).await;

    // Strip the receipt — a 0.1.0-mode response.
    ctx_json.as_object_mut().unwrap().remove("registry_receipt");
    h.serve_context(ctx_json);

    let client = h.client();
    // Default (VerifyIfPresent): absence is fine.
    VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect("VerifyIfPresent tolerates absence");

    // Require: fail closed.
    let strict = VerificationPolicy {
        receipts: ReceiptPolicy::Require,
        ..Default::default()
    };
    let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &strict)
        .await
        .expect_err("Require must fail without a receipt");
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");
}

// ── rcpt-002: tampered receipt rejected ──────────────────────────────────────

#[tokio::test]
async fn tampered_receipt_rejected() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, mut ctx_json, _) = publish_with_receipts(&h, producer_key).await;

    // Backdate created_at inside the served receipt — the signature
    // no longer covers the mutated bytes.
    ctx_json["registry_receipt"]["created_at"] = serde_json::json!("2020-01-01T00:00:00.000Z");
    h.serve_context(ctx_json);

    let client = h.client();
    let err = VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect_err("tampered receipt must be rejected");
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");
}

// ── rot-001: historical key accepted via receipt, fails closed without ──────

#[tokio::test]
async fn rotated_key_verifies_historically_via_receipt() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json, _) = publish_with_receipts(&h, producer_key).await;
    h.serve_context(ctx_json.clone());

    // Rotate: key-1 leaves assertionMethod, stays in verificationMethod.
    h.rotate_producer_key_out(&producer_pub);

    let client = h.client();

    // Default policy: receipt attests the fingerprint → historically
    // authorized.
    let verified = VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect("receipt-attested historical key must verify");
    assert_eq!(
        verified.key_status(),
        KeyAuthorization::HistoricallyAuthorized
    );
    assert!(verified.verified_receipt().is_some());

    // Strict policy: historical keys rejected outright.
    let strict = VerificationPolicy {
        historical_keys: HistoricalKeyPolicy::Reject,
        ..Default::default()
    };
    let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &strict)
        .await
        .expect_err("Reject policy must refuse rotated-out keys");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    // No receipt → the historical path never activates (fail closed).
    let mut stripped = ctx_json;
    stripped.as_object_mut().unwrap().remove("registry_receipt");
    h.serve_context(stripped);
    let err = VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect_err("historical acceptance without a receipt must fail closed");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

// ── did:key producers get receipts too (offline server path) ────────────────

#[test]
fn did_key_publish_mints_receipt_offline() {
    let mut c = caps();
    c.registry_did = "did:web:registry.example.com".into();
    let server = RegistryServer::new(InMemoryStore::new(), c, "registry.example.com")
        .with_receipt_signer(
            ReceiptSigner::new(
                SigningKey::from_bytes(&[0x11u8; 32]),
                "did:web:registry.example.com",
                "did:web:registry.example.com#receipt-key-1",
            )
            .unwrap(),
        )
        .unwrap();

    let producer = Producer::new_did_key(SigningKey::from_bytes(&[9u8; 32]));
    let expected_fp = acdp::crypto::fingerprint_ed25519(
        &SigningKey::from_bytes(&[9u8; 32]).verifying_key_bytes(),
    );
    let req = producer
        .publish_request()
        .title("did:key + receipt")
        .context_type(ContextType::DataSnapshot)
        .build()
        .unwrap();

    let resp = server.publish_verified_did_key(&req, None).unwrap();
    let receipt =
        RegistryReceipt::from_value(&resp.registry_receipt.expect("receipt minted")).unwrap();
    assert_eq!(
        receipt.key_fingerprint, expected_fp,
        "did:key receipt fingerprint must derive from the DID's own key"
    );
    receipt
        .verify_signature_with_key(
            Some(&SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes()),
            None,
        )
        .unwrap();
    receipt
        .cross_check(&resp.ctx_id, &req.content_hash, &expected_fp)
        .unwrap();
}

// ── rcpt-001 golden vector (deterministic mint) ──────────────────────────────

/// Pins the canonical `rcpt-001-receipt-golden.json` spec fixture:
/// registry seed 0x11×32, the sig-001 producer key fingerprint, and
/// the spec's fixed identifiers/timestamp. If the signature or
/// preimage hash drifts, the receipt wire format is broken.
#[test]
fn rcpt_001_golden_vector() {
    let signer = ReceiptSigner::new(
        SigningKey::from_bytes(&[0x11u8; 32]),
        "did:web:registry.example.com",
        "did:web:registry.example.com#receipt-key-1",
    )
    .unwrap();
    let receipt = signer
        .mint(
            &CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into()),
            &LineageId(
                "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a"
                    .into(),
            ),
            "registry.example.com",
            chrono::DateTime::parse_from_rfc3339("2026-04-16T10:30:15.123Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            &acdp::types::ContentHash(
                "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5".into(),
            ),
            "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
        )
        .unwrap();

    assert_eq!(
        receipt.preimage_hash().unwrap().as_str(),
        RCPT_001_PREIMAGE_HASH
    );
    assert_eq!(receipt.signature.value, RCPT_001_SIGNATURE);

    let registry_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();
    receipt
        .verify_signature_with_key(Some(&registry_pub), None)
        .unwrap();
}

const RCPT_001_PREIMAGE_HASH: &str =
    "sha256:9deaa52778ad3b6be27a96d607c3017e9e11442905891a8972f34d8c2dbca9cf";
const RCPT_001_SIGNATURE: &str =
    "vBgQKmn17pHXXY95C07BBeconmjDIdYIvxN5B+YXrQ7tIzFsDNsh1TglzgxOyPUp8lwTz7zwMNiK+Sn5whveDg==";

// ── fed-009 — federated resolution vs receipts-advertising upstreams ────────

/// fed-009: a `CrossRegistryResolver` resolving from an upstream that
/// advertises `acdp-registry-receipts` MUST treat a missing receipt as
/// `invalid_receipt` (RFC-ACDP-0010 §7: no degraded mode); a present
/// receipt is verified against the REMOTE authority; an upstream that
/// does not advertise the profile resolves receipt-lessly under the
/// v0.1.0 trust model.
#[tokio::test]
async fn fed_009_missing_receipt_from_advertising_upstream_fails() {
    use acdp::client::CrossRegistryResolver;

    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json, _) = publish_with_receipts(&h, producer_key).await;

    let make_resolver = || {
        let r = CrossRegistryResolver::new().with_did_resolver(
            WebResolver::with_test_endpoint(&h.tls.root_cert_pem, "localhost", h.tls.addr).unwrap(),
        );
        r.seed_client(REGISTRY_AUTHORITY, h.client());
        r
    };

    // Case 1: advertising upstream + receipt present → success, receipt
    // verified against the remote authority.
    h.advertise_profiles(&["acdp-registry-core", "acdp-registry-receipts"]);
    h.serve_context(ctx_json.clone());
    let verified = make_resolver()
        .resolve(&ctx_id)
        .await
        .expect("advertising upstream with a valid receipt must resolve");
    assert!(verified.verified_receipt().is_some());

    // Case 2: advertising upstream + NO receipt → invalid_receipt
    // (registry fault, not degraded mode).
    let mut stripped = ctx_json.clone();
    stripped.as_object_mut().unwrap().remove("registry_receipt");
    h.serve_context(stripped.clone());
    let err = make_resolver()
        .resolve(&ctx_id)
        .await
        .expect_err("missing receipt from an advertising upstream is a fault");
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");

    // Case 3: non-advertising upstream + no receipt → success under the
    // v0.1.0 trust model.
    h.advertise_profiles(&["acdp-registry-core"]);
    h.serve_context(stripped);
    let verified = make_resolver()
        .resolve(&ctx_id)
        .await
        .expect("receipt-less upstream without the profile must resolve");
    assert!(verified.verified_receipt().is_none());
}

// ── issue #189 — context substitution refused ────────────────────────────────

/// #189: `fetch_with_policy` must refuse a body whose `ctx_id` differs
/// from the one requested. The harness's `/contexts/{id}` route ignores
/// the path parameter and always serves whatever `serve_context` last
/// stored, which is the substitution scenario verbatim — a registry (or
/// an on-path attacker) that serves context B in response to a request
/// for context A.
///
/// Exercises the conformance fixture `fed-011-ctx-id-binding.json`
/// (RFC-ACDP-0006 §4.1 step 7, NORMATIVE), specifically its base scenario
/// plus the `no_receipt_served` `additional_test_cases` entry — the
/// receipt-less path is the only one `fetch_with_policy` (a receipt-less
/// core-profile client) can exercise. The `receipt_served_but_attests_returned_body`
/// case (a receipt present but bound to the wrong body) is covered separately
/// by `receipt_present_but_attests_wrong_body_still_refused_on_ctx_id` below.
/// This test does **not** cover the fixture's third additional case,
/// `uri_encoding_and_path_style_equivalence` (percent-encoding / path-style
/// request forms that must compare equal and NOT trip this check).
///
/// Reproduced under the exact gap this defence closes: default
/// `ReceiptPolicy::VerifyIfPresent` with `registry_receipt: None` (no
/// `acdp-registry-receipts` profile advertised), so no other binding —
/// cryptographic or receipt-based — is available to catch it.
#[tokio::test]
async fn context_substitution_is_refused() {
    // Same seed, two instances: `SigningKey` is not `Clone` and
    // `publish_with_receipts_titled` takes it by value.
    let producer_key_a = SigningKey::from_bytes(&[7u8; 32]);
    let producer_key_b = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key_a.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    // Explicit restatement of `caps()`'s default (`["acdp-registry-core"]`)
    // for readability — this call is a no-op, but spelling it out here
    // documents that `acdp-registry-receipts` is deliberately NOT
    // advertised: VerifyIfPresent tolerates the missing receipt below
    // rather than failing closed on that axis, isolating the ctx_id check
    // as the only thing in play.
    h.advertise_profiles(&["acdp-registry-core"]);

    // Distinct titles are for telling the two contexts apart by eye below;
    // ctx_id distinctness comes from the registry's UUIDv4 mint
    // (title-independent), guarded by the assert_ne! just below.
    let (ctx_id_a, mut ctx_json_a, _) =
        publish_with_receipts_titled(&h, producer_key_a, "context A").await;
    let (ctx_id_b, mut ctx_json_b, _) =
        publish_with_receipts_titled(&h, producer_key_b, "context B").await;
    assert_ne!(
        ctx_id_a, ctx_id_b,
        "the two publishes must mint distinct ctx_ids"
    );

    // Strip receipts from both — the VerifyIfPresent + None gap.
    ctx_json_a
        .as_object_mut()
        .unwrap()
        .remove("registry_receipt");
    ctx_json_b
        .as_object_mut()
        .unwrap()
        .remove("registry_receipt");

    let client = h.client();

    // Positive control: A requested, A served — must still succeed.
    // Guards against the new check being trivially always-true.
    h.serve_context(ctx_json_a.clone());
    VerifiedContext::fetch_with_policy(
        &client,
        &h.resolver,
        &ctx_id_a,
        &VerificationPolicy::default(),
    )
    .await
    .expect("A requested, A served must still succeed");

    // Substitution: A requested, registry serves B.
    h.serve_context(ctx_json_b);
    let err = VerifiedContext::fetch_with_policy(
        &client,
        &h.resolver,
        &ctx_id_a,
        &VerificationPolicy::default(),
    )
    .await
    .expect_err("A requested, B served must be refused");
    assert!(
        matches!(err, AcdpError::ContextIdMismatch { .. }),
        "got {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains(ctx_id_a.as_str()),
        "message must name the requested id: {msg}"
    );
    assert!(
        msg.contains(ctx_id_b.as_str()),
        "message must name the served id: {msg}"
    );
}

/// `receipt_served_but_attests_returned_body` — the `additional_test_cases`
/// entry of `fed-011-ctx-id-binding.json` that `context_substitution_is_refused`
/// above deliberately does not cover. Unlike that test, receipts are NOT
/// stripped here: context B is served (in response to a request for A)
/// carrying B's own receipt — a receipt that is internally, cryptographically
/// valid because it genuinely attests to the body it's shipped with.
///
/// The fixture requires BOTH checks to independently refuse this: RFC-ACDP-0010
/// §8 step 3 (`receipt.ctx_id` must equal the *requested* ctx_id, which B's
/// receipt fails since it legitimately names B) and RFC-ACDP-0006 §4.1 step 7
/// (the unconditional body/requested ctx_id binding). "A consumer MUST NOT
/// treat receipt verification success as a substitute for the unconditional
/// step-7 check" — so this test's real purpose is to guard against a
/// regression where a *validly-signed, internally self-consistent* receipt
/// gets treated as sufficient proof of identity and the step-7 comparison is
/// skipped or short-circuited in its favor. A receipt this convincing is
/// exactly the case a weaker implementation could be fooled by.
#[tokio::test]
async fn receipt_present_but_attests_wrong_body_still_refused_on_ctx_id() {
    let producer_key_a = SigningKey::from_bytes(&[7u8; 32]);
    let producer_key_b = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key_a.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;

    let (ctx_id_a, ctx_json_a, _) =
        publish_with_receipts_titled(&h, producer_key_a, "receipt context A").await;
    let (ctx_id_b, ctx_json_b, receipt_b) =
        publish_with_receipts_titled(&h, producer_key_b, "receipt context B").await;
    assert_ne!(
        ctx_id_a, ctx_id_b,
        "the two publishes must mint distinct ctx_ids"
    );

    // Premise: B's own receipt is internally valid and genuinely attests to
    // B, not to A — so if the ctx_id-binding check were ever skipped in
    // favor of "the receipt verified", this substitution would sail through.
    let typed_receipt_b = RegistryReceipt::from_value(&receipt_b).expect("B's receipt parses");
    assert_eq!(
        typed_receipt_b.ctx_id, ctx_id_b,
        "premise: B's receipt attests to B, not A — this is what makes it a \
         convincing (not just present) receipt for the substituted body"
    );

    let client = h.client();

    // Positive control: A requested, A served (with A's own receipt) —
    // must still succeed. Guards against the ctx_id check alone being
    // enough to explain a failure below for the wrong reason.
    h.serve_context(ctx_json_a);
    VerifiedContext::fetch_with_policy(
        &client,
        &h.resolver,
        &ctx_id_a,
        &VerificationPolicy::default(),
    )
    .await
    .expect("A requested, A served (receipted) must still succeed");

    // Substitution: A requested, registry serves B — complete with B's own
    // valid receipt. Must still be refused via ContextIdMismatch: the
    // unconditional step-7 check runs first and is not superseded by the
    // receipt's own internal validity.
    h.serve_context(ctx_json_b);
    let err = VerifiedContext::fetch_with_policy(
        &client,
        &h.resolver,
        &ctx_id_a,
        &VerificationPolicy::default(),
    )
    .await
    .expect_err("A requested, B served (with B's valid receipt) must still be refused");
    assert!(
        matches!(err, AcdpError::ContextIdMismatch { .. }),
        "receipt validity must not substitute for the step-7 binding check, got {err:?}"
    );
}

// ── issue #189 — substitution refused through CrossRegistryResolver ─────────

/// #189 (`CrossRegistryResolver` variant): the ctx_id-binding defence must
/// also hold when reached through `CrossRegistryResolver::resolve`, not
/// only through the direct `VerifiedContext::fetch_with_policy` path
/// covered by `context_substitution_is_refused` above. This matters
/// because `CrossRegistryResolver`'s `derived_from` DAG walk
/// (`walk_derived_from`) resolves every entry via `resolve` and pushes
/// each into the returned evidence set; if `resolve` failed to enforce
/// the binding, a single substituting upstream would silently corrupt
/// the whole walk's evidence chain rather than surfacing one failed
/// retrieval. Reuses the fed-009 harness (`start_harness`,
/// `Harness::client`/`advertise_profiles`/`serve_context`) and, like
/// `context_substitution_is_refused`, exercises the base scenario of
/// conformance fixture `fed-011-ctx-id-binding.json` (RFC-ACDP-0006 §4.1
/// step 7, NORMATIVE) — through the cross-registry entry point instead
/// of the direct one.
#[tokio::test]
async fn cross_registry_resolver_refuses_context_substitution() {
    use acdp::client::CrossRegistryResolver;

    let producer_key_a = SigningKey::from_bytes(&[7u8; 32]);
    let producer_key_b = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key_a.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    // No `acdp-registry-receipts` profile advertised — isolates the
    // ctx_id check as the only binding in play, same as the direct-path
    // test above.
    h.advertise_profiles(&["acdp-registry-core"]);

    let (ctx_id_a, mut ctx_json_a, _) =
        publish_with_receipts_titled(&h, producer_key_a, "resolver context A").await;
    let (ctx_id_b, mut ctx_json_b, _) =
        publish_with_receipts_titled(&h, producer_key_b, "resolver context B").await;
    assert_ne!(
        ctx_id_a, ctx_id_b,
        "the two publishes must mint distinct ctx_ids"
    );

    // Strip receipts from both — the VerifyIfPresent + None gap, as above.
    ctx_json_a
        .as_object_mut()
        .unwrap()
        .remove("registry_receipt");
    ctx_json_b
        .as_object_mut()
        .unwrap()
        .remove("registry_receipt");

    let make_resolver = || {
        let r = CrossRegistryResolver::new().with_did_resolver(
            WebResolver::with_test_endpoint(&h.tls.root_cert_pem, "localhost", h.tls.addr).unwrap(),
        );
        r.seed_client(REGISTRY_AUTHORITY, h.client());
        r
    };

    // Positive control: A requested, A served — resolve() must still
    // succeed. Guards against the check being trivially always-true.
    h.serve_context(ctx_json_a.clone());
    make_resolver()
        .resolve(&ctx_id_a)
        .await
        .expect("A requested, A served must still resolve");

    // Substitution: A requested, registry serves B. `resolve` must fail
    // rather than returning a `VerifiedContext` for B under A's identity
    // (which a `derived_from` walk would then graft into its evidence set).
    h.serve_context(ctx_json_b);
    let err = make_resolver()
        .resolve(&ctx_id_a)
        .await
        .expect_err("A requested, B served must be refused, not silently corrupt the DAG");
    assert!(
        matches!(err, AcdpError::ContextIdMismatch { .. }),
        "got {err:?}"
    );
}

// ── Phase 2 — substitution refused on the report paths ──────────────────────
//
// `fetch_report` / `fetch_report_with_fetcher` delegate their receipt,
// revocation, and signature/historical-key phases to `verify_retrieved`
// (via `fetch_report_inner`), but the ctx_id binding is still checked
// eagerly, inline, before that delegation — so the substitution below is
// still caught early, ahead of schema/hash/signature work. This section
// reproduces `context_substitution_is_refused`'s exact scenario (same
// harness pattern, same receipt-stripping, same `VerifyIfPresent` + `None`
// gap) against each of the three report-path entry points.

/// Shared setup for the Phase 2 report-path substitution tests: two
/// contexts (A, B) published by the same producer key, receipts stripped
/// (the `VerifyIfPresent` + `None` gap), registry currently serving A.
/// Returns `(harness, client, ctx_id_a, ctx_json_b)` — callers request A
/// and then call `h.serve_context(ctx_json_b)` to trigger substitution.
async fn setup_report_substitution() -> (Harness, RegistryClient, CtxId, serde_json::Value) {
    let producer_key_a = SigningKey::from_bytes(&[7u8; 32]);
    let producer_key_b = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key_a.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    h.advertise_profiles(&["acdp-registry-core"]);

    let (ctx_id_a, mut ctx_json_a, _) =
        publish_with_receipts_titled(&h, producer_key_a, "report context A").await;
    let (ctx_id_b, mut ctx_json_b, _) =
        publish_with_receipts_titled(&h, producer_key_b, "report context B").await;
    assert_ne!(
        ctx_id_a, ctx_id_b,
        "the two publishes must mint distinct ctx_ids"
    );

    ctx_json_a
        .as_object_mut()
        .unwrap()
        .remove("registry_receipt");
    ctx_json_b
        .as_object_mut()
        .unwrap()
        .remove("registry_receipt");

    let client = h.client();
    h.serve_context(ctx_json_a);
    (h, client, ctx_id_a, ctx_json_b)
}

/// `fetch_report` against a registry substituting B for requested A must
/// hard-fail with `ContextIdMismatch` — the same as `fetch_with_policy`,
/// since `fetch_report_inner` gets the identical check.
#[tokio::test]
async fn fetch_report_refuses_context_substitution() {
    let (h, client, ctx_id_a, ctx_json_b) = setup_report_substitution().await;

    // Substitution: A requested, registry serves B.
    h.serve_context(ctx_json_b);
    let err = VerifiedContext::fetch_report(
        &client,
        &h.resolver,
        &ctx_id_a,
        &VerificationPolicy::default(),
    )
    .await
    .expect_err("A requested, B served must be refused");
    assert!(
        matches!(err, AcdpError::ContextIdMismatch { .. }),
        "got {err:?}"
    );
}

/// `fetch_report_with_fetcher` is a separate public entry point from
/// `fetch_report` (both back onto `fetch_report_inner`, but each is named
/// individually in the plan's acceptance criteria) — must independently
/// refuse the same substitution.
#[tokio::test]
async fn fetch_report_with_fetcher_refuses_context_substitution() {
    let (h, client, ctx_id_a, ctx_json_b) = setup_report_substitution().await;

    h.serve_context(ctx_json_b);
    let fetcher = HttpsDataRefFetcher::new();
    let err = VerifiedContext::fetch_report_with_fetcher(
        &client,
        &h.resolver,
        &ctx_id_a,
        &VerificationPolicy::default(),
        &fetcher,
    )
    .await
    .expect_err("A requested, B served must be refused");
    assert!(
        matches!(err, AcdpError::ContextIdMismatch { .. }),
        "got {err:?}"
    );
}

/// `fetch_report_diagnose` is diagnostic by contract and must NOT
/// short-circuit: it returns `Ok((None, report))` rather than an `Err`,
/// with `report.ctx_id_ok == false` and every other top-level check still
/// recorded as having passed — proving the substituted body genuinely
/// cleared schema/hash/signature and only the id binding caught it, and
/// that the gate at `all_top_level_pass` refuses to hand back a
/// `VerifiedContext` over that substituted content.
#[tokio::test]
async fn fetch_report_diagnose_refuses_verified_handle_on_context_substitution() {
    let (h, client, ctx_id_a, ctx_json_b) = setup_report_substitution().await;

    h.serve_context(ctx_json_b);
    let (verified, report) = VerifiedContext::fetch_report_diagnose(
        &client,
        &h.resolver,
        &ctx_id_a,
        &VerificationPolicy::default(),
    )
    .await
    .expect("fetch_report_diagnose must not error — it reports, not short-circuits");

    assert!(
        verified.is_none(),
        "a VerifiedContext must NOT be handed back over a substituted body"
    );
    assert!(
        !report.ctx_id_ok,
        "report must record the id-binding failure"
    );
    assert!(
        report.signature_ok,
        "the substituted body's own signature is genuinely valid — must still be reported true"
    );
    assert!(
        report.body_hash_ok,
        "the substituted body's own hash genuinely recomputes — must still be reported true"
    );
    assert!(
        report.schema_ok,
        "the substituted body is genuinely schema-valid — must still be reported true"
    );
}

/// Positive control: `fetch_report_diagnose` on a correctly-served context
/// (A requested, A served) returns `Some(_)` with `ctx_id_ok == true`.
/// Guards against the new field being trivially always-false.
#[tokio::test]
async fn fetch_report_diagnose_positive_control() {
    let (_h, client, ctx_id_a, _ctx_json_b) = setup_report_substitution().await;

    let (verified, report) = VerifiedContext::fetch_report_diagnose(
        &client,
        &_h.resolver,
        &ctx_id_a,
        &VerificationPolicy::default(),
    )
    .await
    .expect("fetch_report_diagnose must not error on a correctly served context");

    assert!(
        verified.is_some(),
        "A requested, A served must still yield a VerifiedContext"
    );
    assert!(
        report.ctx_id_ok,
        "correctly served context must report ctx_id_ok == true"
    );
    assert!(report.signature_ok);
    assert!(report.body_hash_ok);
    assert!(report.schema_ok);
}

// ── Phase 2 — the report family honors the caller's VerificationPolicy ─────
//
// `fetch_report` / `fetch_report_with_fetcher` / `fetch_report_diagnose` now
// delegate their receipt, revocation, and signature/historical-key phases
// to `verify_retrieved` (via `fetch_report_inner` /
// `fetch_report_diagnose`'s own gated call), instead of hardcoding
// `key_status: CurrentlyAuthorized` and `verified_receipt: None`. These
// tests cover T2/T3/T5/T6/T7 of the Phase 2 plan's test matrix (T1 and T4
// live in `tests/key_revocation.rs`, which has the richer revocation
// harness).

/// Phase 2 T2 — `fetch_report` (and, folded in per `receipts.rs:786`-ish,
/// `fetch_report_with_fetcher`) must honor `ReceiptPolicy::Require`: fail
/// closed with `Err(InvalidReceipt)` when the receipt is stripped, and
/// succeed with `verified_receipt()` populated when a valid receipt is
/// present.
///
/// Falsifiability: pinning `receipts: ReceiptPolicy::Ignore` inside
/// `VerificationPolicy::derived_for_report` reddens BOTH halves — the
/// stripped-receipt case wrongly returns `Ok` (no longer failing closed),
/// and the present-receipt case's `verified_receipt().is_some()` assertion
/// fails (receipts are inert under `Ignore`, so nothing gets verified).
#[tokio::test]
async fn report_requires_receipt() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json, _) = publish_with_receipts(&h, producer_key).await;
    let client = h.client();

    let require = VerificationPolicy {
        receipts: ReceiptPolicy::Require,
        ..Default::default()
    };

    // Receipt stripped: fail closed.
    let mut stripped = ctx_json.clone();
    stripped.as_object_mut().unwrap().remove("registry_receipt");
    h.serve_context(stripped);
    let err = VerifiedContext::fetch_report(&client, &h.resolver, &ctx_id, &require)
        .await
        .expect_err("Require must fail closed without a receipt");
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");

    // Receipt present: succeeds, and the receipt is genuinely verified
    // (not just echoed).
    h.serve_context(ctx_json);
    let (verified, _report) =
        VerifiedContext::fetch_report(&client, &h.resolver, &ctx_id, &require)
            .await
            .expect("Require passes with a verified receipt");
    assert!(
        verified.verified_receipt().is_some(),
        "fetch_report must actually verify the receipt under Require"
    );

    // `fetch_report_with_fetcher` is a separate public entry point from
    // `fetch_report` (both back onto `fetch_report_inner`) — cover it too.
    let fetcher = HttpsDataRefFetcher::new();
    let (verified, _report) = VerifiedContext::fetch_report_with_fetcher(
        &client,
        &h.resolver,
        &ctx_id,
        &require,
        &fetcher,
    )
    .await
    .expect("fetch_report_with_fetcher must also honor Require");
    assert!(verified.verified_receipt().is_some());
}

/// Phase 2 T3 — clone of `rotated_key_verifies_historically_via_receipt`
/// via `fetch_report`: locks row 5 of the semver table, the deliberate
/// LOOSENING under the default policy (a rotated-out key with a verified
/// receipt now verifies via `fetch_report`, where it used to hard-fail
/// because the old pipeline ran only the strict assertionMethod check).
///
/// Falsifiability: restoring the old `Verifier::new(resolver)
/// .verify_body_signed(&ctx.body).await?` call in `fetch_report_inner` (in
/// place of the `verify_retrieved` delegation) reddens this test — that
/// call enforces `assertionMethod` membership only, with no
/// historical-key fallback, so a rotated-out key fails even under the
/// default (`AcceptWithReceipt`) policy.
#[tokio::test]
async fn report_accepts_rotated_key_via_receipt() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json, _) = publish_with_receipts(&h, producer_key).await;
    h.serve_context(ctx_json.clone());

    h.rotate_producer_key_out(&producer_pub);

    let client = h.client();

    // Default policy: receipt attests the fingerprint → historically
    // authorized, and the report's new `key_status` field mirrors it.
    let (verified, report) = VerifiedContext::fetch_report(
        &client,
        &h.resolver,
        &ctx_id,
        &VerificationPolicy::default(),
    )
    .await
    .expect("receipt-attested historical key must verify via fetch_report");
    assert_eq!(
        verified.key_status(),
        KeyAuthorization::HistoricallyAuthorized
    );
    assert!(verified.verified_receipt().is_some());
    assert_eq!(
        report.key_status,
        Some(KeyAuthorization::HistoricallyAuthorized)
    );

    // Reject policy: rotated-out keys refused outright.
    let strict = VerificationPolicy {
        historical_keys: HistoricalKeyPolicy::Reject,
        ..Default::default()
    };
    let err = VerifiedContext::fetch_report(&client, &h.resolver, &ctx_id, &strict)
        .await
        .expect_err("Reject policy must refuse rotated-out keys via fetch_report");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    // No receipt → historical path never activates (fail closed).
    let mut stripped = ctx_json;
    stripped.as_object_mut().unwrap().remove("registry_receipt");
    h.serve_context(stripped);
    let err = VerifiedContext::fetch_report(
        &client,
        &h.resolver,
        &ctx_id,
        &VerificationPolicy::default(),
    )
    .await
    .expect_err("historical acceptance without a receipt must fail closed via fetch_report");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// Phase 2 T5 — `fetch_report_diagnose` must honor
/// `allow_unknown_status: false`: withhold the verified handle and record
/// `policy_phase_error` as `SchemaViolation` when the registry serves an
/// unrecognized status string. Before this phase `fetch_report_diagnose`
/// had no P6 phase at all (the third missing phase, absent even from
/// `fetch_report_inner`'s pre-fix pipeline) and handed back
/// `Some(VerifiedContext)` regardless of `allow_unknown_status`.
#[tokio::test]
async fn report_diagnose_honors_allow_unknown_status() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, mut ctx_json, _) = publish_with_receipts(&h, producer_key).await;
    ctx_json["registry_state"]["status"] = serde_json::json!("quarantined");
    h.serve_context(ctx_json);

    let client = h.client();
    let strict_status = VerificationPolicy {
        allow_unknown_status: false,
        ..Default::default()
    };

    let (verified, report) =
        VerifiedContext::fetch_report_diagnose(&client, &h.resolver, &ctx_id, &strict_status)
            .await
            .expect("fetch_report_diagnose must not error — it reports, not short-circuits");
    assert!(
        verified.is_none(),
        "handle must be withheld when the unknown-status policy phase fails"
    );
    assert!(
        matches!(
            report.policy_phase_error,
            Some(AcdpError::SchemaViolation(_))
        ),
        "got {:?}",
        report.policy_phase_error
    );

    // Positive control: `fetch_report` (the hard-fail entry point) rejects
    // outright under the same policy.
    let err = VerifiedContext::fetch_report(&client, &h.resolver, &ctx_id, &strict_status)
        .await
        .expect_err(
            "fetch_report must hard-fail on an unknown status under allow_unknown_status=false",
        );
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");
}

/// Phase 2 T6 — proves row 7 of the semver table: `strict_v0_1_0()`
/// callers of `fetch_report` see byte-identical behavior before and after
/// this phase. Receipts stay inert (`Ignore`) even against a
/// receipts-minting registry.
///
/// Falsifiability: forcing `VerifyIfPresent` inside
/// `VerificationPolicy::derived_for_report` (instead of passing
/// `receipts` through verbatim) reddens the `verified_receipt().is_none()`
/// assertion — the receipt would get verified and populated even under
/// the v0.1.0-pinned profile.
#[tokio::test]
async fn report_strict_v0_1_0_unchanged() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json, _) = publish_with_receipts(&h, producer_key).await;
    h.serve_context(ctx_json);

    let client = h.client();
    let (verified, _report) = VerifiedContext::fetch_report(
        &client,
        &h.resolver,
        &ctx_id,
        &VerificationPolicy::strict_v0_1_0(),
    )
    .await
    .expect("strict_v0_1_0 must still succeed via fetch_report");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
    assert!(
        verified.verified_receipt().is_none(),
        "strict_v0_1_0 ignores receipts even when the registry mints one"
    );
}

/// Phase 2 T7 — covers row 1 of the semver table, the most important row:
/// under `VerificationPolicy::default()` (`VerifyIfPresent`, no caller
/// opt-in at all — the entire 0.2+ line against a receipts-profile
/// registry), a TAMPERED receipt must be rejected by `fetch_report`, not
/// silently accepted the way the pre-fix hardcoded pipeline did. Clones
/// `tampered_receipt_rejected`'s tampering technique.
///
/// Falsifiability: pinning `receipts: ReceiptPolicy::Ignore` inside
/// `VerificationPolicy::derived_for_report` reddens this test — the call
/// returns `Ok` (receipts inert), so the `Err(InvalidReceipt)` assertion
/// fails.
#[tokio::test]
async fn report_rejects_invalid_receipt_under_default_policy() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, mut ctx_json, _) = publish_with_receipts(&h, producer_key).await;

    // Backdate created_at inside the served receipt — the signature no
    // longer covers the mutated bytes (same technique as
    // tampered_receipt_rejected above).
    ctx_json["registry_receipt"]["created_at"] = serde_json::json!("2020-01-01T00:00:00.000Z");
    h.serve_context(ctx_json);

    let client = h.client();
    let err = VerifiedContext::fetch_report(
        &client,
        &h.resolver,
        &ctx_id,
        &VerificationPolicy::default(),
    )
    .await
    .expect_err("fetch_report must reject a tampered receipt under the default policy");
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");
}
