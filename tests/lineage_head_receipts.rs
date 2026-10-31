//! Lineage-head receipts (ACDP 0.3, RFC-ACDP-0011) — end-to-end tests.
//!
//! Covers the lhr-001..004 fixture behaviors through the live server +
//! client stack (the arithmetic fixture bindings live in
//! `tests/conformance.rs`): publish v1 + v2 on a receipts +
//! head-receipts registry, serve `/current` over in-process TLS, verify
//! the minted head receipt with the full RFC-ACDP-0011 §7 verifier, and
//! confirm every §6/§9 issuance invariant fails closed.

mod common;

use std::sync::{Arc, RwLock};

use acdp::client::{
    LineageHeadPolicy, ReceiptPolicy, RegistryClient, VerificationPolicy, VerifiedContext,
};
use acdp::crypto::SigningKey;
use acdp::did::WebResolver;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::registry::{InMemoryStore, RegistryServer, RegistryStore as _};
use acdp::types::receipt::{LineageHeadReceipt, ReceiptSigner};
use acdp::types::{CapabilitiesDocument, ContextType, Visibility};
use axum::{extract::Path, routing::get, Json, Router};
use common::{ed25519_did_doc, TlsTestServer};

const REGISTRY_AUTHORITY: &str = "localhost";
const REGISTRY_DID: &str = "did:web:localhost";
const RECEIPT_SEED: [u8; 32] = [0x11u8; 32];

fn caps() -> CapabilitiesDocument {
    use acdp::types::capabilities::Limits;
    CapabilitiesDocument {
        acdp_version: "0.3.0".into(),
        registry_did: REGISTRY_DID.into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into(), "did:key".into()],
        profiles: vec!["acdp-registry-core".into()],
        limits: Limits {
            max_payload_bytes: 1_048_576,
            max_embedded_bytes: 65_536,
            idempotency_key_ttl_seconds: Some(86_400),
            max_publish_per_minute: None,
            change_retention_seconds: None,
            max_change_filters: None,
            max_changes_page: None,
            max_subscriptions_per_requester: None,
            max_reads_per_minute: None,
            max_anonymous_reads_per_minute: None,
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        // Required at acdp_version >= 0.3.0 (RFC-ACDP-0003 §6.4,
        // fixture idem-007).
        supports_idempotency_key: true,
        extensions: Default::default(),
    }
}

/// A receipts + head-receipts registry over an in-memory store
/// (RFC-ACDP-0011 §9: head receipts require the receipts profile).
fn head_receipts_server() -> RegistryServer<InMemoryStore> {
    RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY)
        .expect("server")
        .with_receipt_signer(
            ReceiptSigner::new(
                SigningKey::from_bytes(&RECEIPT_SEED),
                REGISTRY_DID,
                format!("{REGISTRY_DID}#receipt-key-1"),
            )
            .expect("signer"),
        )
        .expect("receipt signer accepted")
        .with_lineage_head_receipts()
        .expect("head receipts enabled")
}

/// Publish v1 + v2 of a did:key lineage through the RFC-conformant
/// offline path and return `(server, lineage_id, v2_current_context)`.
fn publish_two_versions() -> (
    RegistryServer<InMemoryStore>,
    acdp::types::LineageId,
    acdp::types::body::FullContext,
) {
    let server = head_receipts_server();
    let producer = Producer::new_did_key(SigningKey::from_bytes(&[9u8; 32]));

    let v1 = producer
        .publish_request()
        .title("head receipts v1")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("v1 build");
    let resp1 = server
        .publish_verified_did_key(&v1, None)
        .expect("v1 publish");

    // Supersede from the stored v1 body (propagates version + lineage).
    let stored_v1 = server
        .store()
        .get(&resp1.ctx_id)
        .expect("store get")
        .expect("v1 present");
    let v2 = producer
        .supersede_body(&stored_v1.body)
        .title("head receipts v2")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("v2 build");
    let resp2 = server
        .publish_verified_did_key(&v2, None)
        .expect("v2 publish");
    assert_eq!(resp2.lineage_id, resp1.lineage_id);
    assert_eq!(resp2.version, 2);

    let current = server
        .current(&resp2.lineage_id, None)
        .expect("current query")
        .expect("head visible");
    (server, resp2.lineage_id, current)
}

/// TLS harness hosting the registry's DID document (for receipt-key
/// resolution) and a live `/lineages/:id/current` endpoint.
struct Harness {
    tls: TlsTestServer,
    current_json: Arc<RwLock<Option<serde_json::Value>>>,
    resolver: WebResolver,
}
async fn start_harness(caps_json: serde_json::Value) -> Harness {
    let registry_pub = SigningKey::from_bytes(&RECEIPT_SEED).verifying_key_bytes();
    let registry_doc = ed25519_did_doc(REGISTRY_DID, "receipt-key-1", &registry_pub);
    let current_json: Arc<RwLock<Option<serde_json::Value>>> = Arc::new(RwLock::new(None));

    let router = Router::new()
        .route(
            "/.well-known/acdp.json",
            get(move || async move { Json(caps_json) }),
        )
        .route(
            "/.well-known/did.json",
            get(move || async move { Json(registry_doc) }),
        )
        .route(
            "/lineages/{lineage_id}/current",
            get({
                let current = current_json.clone();
                move |Path(_lineage_id): Path<String>| {
                    let current = current.clone();
                    async move {
                        Json(
                            current
                                .read()
                                .unwrap()
                                .clone()
                                .expect("current not yet published"),
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
        current_json,
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

    fn serve_current(&self, value: serde_json::Value) {
        *self.current_json.write().unwrap() = Some(value);
    }
}

// ── Deliverable: v1 + v2 → /current → §7 verification end-to-end ────────────

/// Publish v1 + v2 via `publish_verified_did_key` on a receipts +
/// head-receipts server, call `current()`, and verify the minted head
/// receipt end-to-end with `verify_lineage_head_receipt_value`
/// (registry key resolved through a live TLS `did:web` document).
#[tokio::test]
async fn head_receipt_minted_on_current_and_verifies_end_to_end() {
    let (server, lineage_id, current) = publish_two_versions();

    // §9: the profile chain is advertised.
    let profiles = &server.capabilities().profiles;
    assert!(profiles.iter().any(|p| p == "acdp-registry-receipts"));
    assert!(profiles.iter().any(|p| p == "acdp-registry-head-receipts"));

    // §6 rule 1: /current MUST carry a head receipt describing the very
    // head being served.
    let value = current
        .lineage_head_receipt
        .clone()
        .expect("advertising registry must mint on /current");
    let typed = LineageHeadReceipt::from_value(&value).expect("closed parse");
    assert_eq!(typed.receipt_version, "acdp-lhr/1");
    assert_eq!(typed.registry_did, REGISTRY_DID);
    assert_eq!(typed.lineage_id, lineage_id);
    assert_eq!(typed.head_ctx_id, current.body.ctx_id);
    assert_eq!(typed.head_version, 2);
    assert_eq!(typed.head_status, "active");

    // Pure signature check against the known registry key.
    let registry_pub = SigningKey::from_bytes(&RECEIPT_SEED).verifying_key_bytes();
    typed
        .verify_signature_with_key(Some(&registry_pub), None)
        .expect("freshly minted head receipt must verify");

    // Full RFC-ACDP-0011 §7 verifier, registry key resolved via did:web
    // over TLS.
    let h = start_harness(serde_json::to_value(server.capabilities()).unwrap()).await;
    let verified = acdp::client::verify_lineage_head_receipt_value(
        &value,
        &lineage_id,
        &current.body.ctx_id,
        current.body.version,
        &current.registry_state.status,
        true, // /current
        REGISTRY_AUTHORITY,
        REGISTRY_DID,
        chrono::Duration::seconds(120),
        &h.resolver,
    )
    .await
    .expect("end-to-end §7 verification");
    assert_eq!(verified.head_version, 2);
    assert!(
        verified.age_at(chrono::Utc::now()) < chrono::Duration::seconds(300),
        "freshly minted as_of must be well within the §6 recommended max age"
    );

    // The superseded v1 can never be attested as head: current() only
    // ever names the non-superseded head, and the signer refuses a
    // superseded status outright (RFC-ACDP-0011 §4).
    let signer = ReceiptSigner::new(
        SigningKey::from_bytes(&RECEIPT_SEED),
        REGISTRY_DID,
        format!("{REGISTRY_DID}#receipt-key-1"),
    )
    .unwrap();
    let err = signer
        .mint_lineage_head(
            &lineage_id,
            &current.body.ctx_id,
            1,
            &acdp::types::Status::Superseded,
            chrono::Utc::now(),
        )
        .expect_err("minting a superseded head must be refused");
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");
}

// ── Full client pipeline: fetch_current + LineageHeadPolicy ─────────────────

/// `VerifiedContext::fetch_current_with_policy` verifies body,
/// RFC-ACDP-0010 receipt, and RFC-ACDP-0011 head receipt in one call;
/// `Require` fails closed when the receipt is stripped; a stale (v1)
/// head receipt served with a v2 body fails the §7 step 5 byte-match
/// (lhr-002 behavior).
#[tokio::test]
async fn fetch_current_policy_end_to_end() {
    let (server, lineage_id, _) = publish_two_versions();

    // Capture a genuine-but-stale head receipt: re-serve current()
    // BEFORE v3 exists... simpler: mint a v1-attesting receipt with the
    // real key (the lhr-002 scenario: previously valid, now stale).
    let v1_ctx = {
        let all = server.lineage(&lineage_id, None).expect("lineage");
        all.into_iter().find(|c| c.body.version == 1).unwrap()
    };
    let stale_receipt = ReceiptSigner::new(
        SigningKey::from_bytes(&RECEIPT_SEED),
        REGISTRY_DID,
        format!("{REGISTRY_DID}#receipt-key-1"),
    )
    .unwrap()
    .mint_lineage_head(
        &lineage_id,
        &v1_ctx.body.ctx_id,
        1,
        &acdp::types::Status::Active,
        chrono::Utc::now(),
    )
    .unwrap();

    let current = server
        .current(&lineage_id, None)
        .expect("current query")
        .expect("head visible");
    let current_json = serde_json::to_value(&current).expect("serialize");

    let h = start_harness(serde_json::to_value(server.capabilities()).unwrap()).await;
    let client = h.client();
    let require = VerificationPolicy {
        lineage_head: LineageHeadPolicy {
            receipts: ReceiptPolicy::Require,
            ..Default::default()
        },
        ..Default::default()
    };

    // Happy path: default policy (VerifyIfPresent) and Require both
    // verify the served head receipt; freshness verdict is "not stale".
    h.serve_current(current_json.clone());
    let verified = VerifiedContext::fetch_current(&client, &h.resolver, &lineage_id)
        .await
        .expect("fetch_current with default policy");
    let head = verified
        .verified_head_receipt()
        .expect("head receipt verified");
    assert_eq!(head.head_version, 2);
    assert_eq!(head.head_ctx_id, verified.body().ctx_id);
    assert_eq!(verified.head_receipt_stale(), Some(false));
    // The RFC-ACDP-0010 publish receipt rides the same response and is
    // verified independently (§7: three independent verdicts).
    assert!(verified.verified_receipt().is_some());

    VerifiedContext::fetch_current_with_policy(&client, &h.resolver, &lineage_id, &require)
        .await
        .expect("Require passes with a verified head receipt");

    // Require fails closed when the registry omits the receipt.
    let mut stripped = current_json.clone();
    stripped
        .as_object_mut()
        .unwrap()
        .remove("lineage_head_receipt");
    h.serve_current(stripped.clone());
    let err =
        VerifiedContext::fetch_current_with_policy(&client, &h.resolver, &lineage_id, &require)
            .await
            .expect_err("Require must fail without a head receipt");
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");
    // VerifyIfPresent tolerates absence (a 0.1.0/0.2.0 registry).
    let verified = VerifiedContext::fetch_current(&client, &h.resolver, &lineage_id)
        .await
        .expect("VerifyIfPresent tolerates absence");
    assert!(verified.verified_head_receipt().is_none());
    assert_eq!(verified.head_receipt_stale(), None);

    // lhr-002 behavior: v2 body served with the (genuinely signed)
    // v1-attesting receipt → §7 step 5 byte-match fails.
    let mut stale = current_json.clone();
    stale["lineage_head_receipt"] = serde_json::to_value(&stale_receipt).unwrap();
    h.serve_current(stale);
    let err = VerifiedContext::fetch_current(&client, &h.resolver, &lineage_id)
        .await
        .expect_err("stale head receipt must be rejected");
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");

    // Tampered receipt (mutated as_of) → signature no longer covers the
    // bytes → invalid_receipt.
    let mut tampered = current_json.clone();
    tampered["lineage_head_receipt"]["as_of"] = serde_json::json!("2020-01-01T00:00:00.000Z");
    h.serve_current(tampered);
    let err = VerifiedContext::fetch_current(&client, &h.resolver, &lineage_id)
        .await
        .expect_err("tampered head receipt must be rejected");
    assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");

    // Ignore policy: receipt preserved verbatim, unverified — even a
    // tampered one doesn't fail the fetch (v0.2.0 behavior).
    let ignore = VerificationPolicy {
        lineage_head: LineageHeadPolicy {
            receipts: ReceiptPolicy::Ignore,
            ..Default::default()
        },
        ..Default::default()
    };
    let verified =
        VerifiedContext::fetch_current_with_policy(&client, &h.resolver, &lineage_id, &ignore)
            .await
            .expect("Ignore policy skips head-receipt verification");
    assert!(verified.verified_head_receipt().is_none());
    assert!(verified.lineage_head_receipt().is_some());
}

// ── §6 / §9 issuance invariants ──────────────────────────────────────────────

/// A registry that does not advertise the profile MUST NOT emit
/// lineage-head receipts; the profile cannot be enabled without its
/// `acdp-registry-receipts` prerequisite or below 0.3.0 (RFC-ACDP-0011
/// §9); body-only retrieval never carries any receipt (§6 rule 3).
#[test]
fn issuance_invariants() {
    // Non-advertising registry (receipts only): no head receipt.
    let receipts_only = RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY)
        .unwrap()
        .with_receipt_signer(
            ReceiptSigner::new(
                SigningKey::from_bytes(&RECEIPT_SEED),
                REGISTRY_DID,
                format!("{REGISTRY_DID}#receipt-key-1"),
            )
            .unwrap(),
        )
        .unwrap();
    let producer = Producer::new_did_key(SigningKey::from_bytes(&[9u8; 32]));
    let req = producer
        .publish_request()
        .title("no head receipts here")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let resp = receipts_only.publish_verified_did_key(&req, None).unwrap();
    let current = receipts_only
        .current(&resp.lineage_id, None)
        .unwrap()
        .expect("head visible");
    assert!(
        current.lineage_head_receipt.is_none(),
        "non-advertising registries MUST NOT emit lineage_head_receipt (RFC-ACDP-0011 §10)"
    );
    assert!(!receipts_only
        .capabilities()
        .profiles
        .iter()
        .any(|p| p == "acdp-registry-head-receipts"));

    // Prerequisite gate: head receipts without a receipt signer.
    let Err(err) = RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY)
        .unwrap()
        .with_lineage_head_receipts()
    else {
        panic!("head receipts require the receipts profile (RFC-ACDP-0011 §9)");
    };
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");

    // Version gate: profile requires acdp_version >= 0.3.0.
    let mut old_caps = caps();
    old_caps.acdp_version = "0.2.0".into();
    let Err(err) = RegistryServer::try_new(InMemoryStore::new(), old_caps, REGISTRY_AUTHORITY)
        .unwrap()
        .with_receipt_signer(
            ReceiptSigner::new(
                SigningKey::from_bytes(&RECEIPT_SEED),
                REGISTRY_DID,
                format!("{REGISTRY_DID}#receipt-key-1"),
            )
            .unwrap(),
        )
        .unwrap()
        .with_lineage_head_receipts()
    else {
        panic!("head receipts require acdp_version >= 0.3.0 (RFC-ACDP-0011 §9)");
    };
    assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");

    // §6 rule 3: body-only retrieval carries no receipt of any kind —
    // Body has no receipt members at all, so serialize and assert.
    let (server, lineage_id, _) = publish_two_versions();
    let current = server.current(&lineage_id, None).unwrap().unwrap();
    let body = server
        .retrieve_body(&current.body.ctx_id, None)
        .unwrap()
        .expect("body visible");
    let body_json = serde_json::to_value(&body).unwrap();
    assert!(body_json.get("lineage_head_receipt").is_none());
    assert!(body_json.get("registry_receipt").is_none());
}

// ── Ephemerality: fresh as_of per response ───────────────────────────────────

/// Head receipts are ephemeral (RFC-ACDP-0011 §4): each `/current`
/// response is signed over its own response-time `as_of`, ms-truncated.
#[test]
fn each_current_response_mints_fresh_as_of() {
    let (server, lineage_id, first) = publish_two_versions();
    let r1 = LineageHeadReceipt::from_value(first.lineage_head_receipt.as_ref().unwrap()).unwrap();
    assert_eq!(
        r1.as_of.timestamp_subsec_nanos() % 1_000_000,
        0,
        "as_of must be ms-truncated (RFC-ACDP-0001 §5.3)"
    );

    std::thread::sleep(std::time::Duration::from_millis(5));
    let second = server.current(&lineage_id, None).unwrap().unwrap();
    let r2 = LineageHeadReceipt::from_value(second.lineage_head_receipt.as_ref().unwrap()).unwrap();
    assert!(
        r2.as_of > r1.as_of,
        "a later /current response must carry a fresh as_of ({} vs {})",
        r1.as_of,
        r2.as_of
    );
    // Same head, same claim — only the evaluation instant moved.
    assert_eq!(r1.head_ctx_id, r2.head_ctx_id);
    assert_eq!(r1.head_version, r2.head_version);
}
