//! Live cross-implementation tests: this crate's client against a REAL
//! `acdp-registry-rs` server (not wiremock, not the in-process `tests/world`
//! router).
//!
//! Every other publish test in this repo drives `RegistryClient::publish`
//! against wiremock or calls `RegistryServer::publish_verified` in process,
//! so nothing proves the bytes this SDK emits are accepted, stored, served
//! back and re-verified by the production registry. A drift in canonical
//! form, `Option` skip-serialization, the signature preimage or error-code
//! mapping would pass the whole suite and only break downstream (Seam, the
//! registry's own consumers). These tests close that boundary.
//!
//! # Gating
//!
//! Skipped (with a message) unless `ACDP_LIVE_REGISTRY_URL` is set, so plain
//! `cargo test` and CI never need a network or a running registry. Set
//! `ACDP_REQUIRE_LIVE_REGISTRY=1` to turn a missing URL into a failure.
//! The URL MUST be loopback HTTP (the test transport permits only that, by
//! design); never point it at a shared or production registry.
//!
//! # Running locally
//!
//! ```bash
//! # in ../acdp-registry-rs/docker (postgres + registry, TLS off, :8443)
//! docker compose -p livetest-acdp -f docker-compose.yml up -d --build --wait
//! ACDP_LIVE_REGISTRY_URL=http://127.0.0.1:8443 \
//!   cargo test --features client,test-transport --test live_registry
//! docker compose -p livetest-acdp -f docker-compose.yml down -v --remove-orphans
//! ```
//!
//! Producers are `did:key` so the registry verifies them offline: no DID
//! document hosting is needed on either side.

use acdp::{
    client::{RegistryClient, VerifiedContext},
    crypto::SigningKey,
    did::WebResolver,
    error::AcdpError,
    producer::Producer,
    types::{
        primitives::{ContextType, CtxId, Visibility},
        publish::PublishRequest,
        search::SearchParams,
        DataRef, DataRefType,
    },
    verify::{verify_body_offline, verify_context_hash},
};

/// Returns the live registry base URL, or `None` (after printing why) when
/// the suite should skip.
fn live_url() -> Option<String> {
    match std::env::var("ACDP_LIVE_REGISTRY_URL") {
        Ok(u) if !u.trim().is_empty() => {
            let u = u.trim().trim_end_matches('/').to_string();
            assert!(
                u.starts_with("http://127.0.0.1:") || u.starts_with("http://localhost:"),
                "ACDP_LIVE_REGISTRY_URL must be a loopback http:// URL (got a non-local \
                 target); these tests must never run against a shared registry"
            );
            Some(u)
        }
        _ => {
            if std::env::var("ACDP_REQUIRE_LIVE_REGISTRY").as_deref() == Ok("1") {
                panic!("ACDP_REQUIRE_LIVE_REGISTRY=1 but ACDP_LIVE_REGISTRY_URL is unset");
            }
            eprintln!("SKIP live_registry: ACDP_LIVE_REGISTRY_URL not set");
            None
        }
    }
}

fn client(url: &str) -> RegistryClient {
    RegistryClient::with_test_transport(url).expect("build test-transport client")
}

/// A client for a registry that accepts `did:key` producers. The registry's
/// shipped `docker/config.docker.toml` advertises only `did:web`
/// (`[auth] did_methods`), and such a registry correctly refuses a did:key
/// publish with `key_resolution_failed` (dk-003); the live run needs
/// `did_methods = ["did:web", "did:key"]` in its config.
async fn did_key_client(url: &str) -> RegistryClient {
    let c = client(url);
    let caps = c.capabilities().await.expect("capabilities");
    assert!(
        caps.supported_did_methods.iter().any(|m| m == "did:key"),
        "live registry must advertise did:key in supported_did_methods (set \
         [auth] did_methods = [\"did:web\", \"did:key\"] in its config); got {:?}",
        caps.supported_did_methods
    );
    c
}

fn producer() -> Producer {
    Producer::new_did_key(SigningKey::generate())
}

fn request(p: &Producer, title: &str) -> PublishRequest {
    p.publish_request()
        .title(title)
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .description("acdp-rs live cross-implementation test")
        .tags(vec!["acdp-rs-live"])
        .domain("testing")
        .data_refs(vec![DataRef::uri(
            DataRefType::PrimaryResult,
            "https://data.example.com/live/result.json",
        )])
        .summary("live test context")
        .metadata(serde_json::json!({ "suite": "live_registry", "n": 1, "neg_zero": -0.0 }))
        .build()
        .expect("build publish request")
}

#[tokio::test]
async fn live_capabilities_document_parses() {
    let Some(url) = live_url() else { return };
    let caps = client(&url).capabilities().await.expect("capabilities");
    assert!(
        !caps.profiles.is_empty(),
        "registry advertises no profiles: {caps:?}"
    );
}

/// The core boundary: SDK-built request → real registry → served back →
/// re-verified by the SDK through every consumer path.
#[tokio::test]
async fn live_publish_retrieve_verify_round_trip() {
    let Some(url) = live_url() else { return };
    let c = did_key_client(&url).await;
    let p = producer();
    let req = request(&p, "live round trip");

    let resp = c
        .publish(&req)
        .await
        .expect("real registry accepts SDK publish");
    assert_eq!(resp.version, 1);

    let ctx = c.retrieve(&resp.ctx_id).await.expect("retrieve");
    assert_eq!(ctx.body.ctx_id, resp.ctx_id);
    assert_eq!(ctx.body.lineage_id, resp.lineage_id);
    assert_eq!(
        ctx.body.content_hash, req.content_hash,
        "registry must serve the producer's content_hash unchanged"
    );
    assert_eq!(ctx.body.signature.value, req.signature.value);
    assert_eq!(ctx.body.agent_id, req.agent_id);

    // Hash over the raw served body (RFC-ACDP-0001 §5.7) and offline did:key
    // signature verification.
    verify_context_hash(&ctx).expect("raw served body re-hashes to content_hash");
    verify_body_offline(&ctx.body).expect("served body verifies offline");

    // Full consumer pipeline: fetch + ctx_id binding + hash + signature.
    let verified = VerifiedContext::fetch(&c, &WebResolver::new(), &resp.ctx_id)
        .await
        .expect("VerifiedContext::fetch against the real registry");
    assert_eq!(verified.full_context().body.ctx_id, resp.ctx_id);

    let body = c.retrieve_body(&resp.ctx_id).await.expect("retrieve_body");
    assert_eq!(body.content_hash, req.content_hash);
}

#[tokio::test]
async fn live_idempotent_replay_returns_same_context() {
    let Some(url) = live_url() else { return };
    let c = did_key_client(&url).await;
    let p = producer();
    let req = request(&p, "live idempotency");
    let key = format!("acdp-rs-live-{}", uuid_like());

    let first = c
        .publish_idempotent(&req, &key)
        .await
        .expect("first publish");
    let replay = c.publish_idempotent(&req, &key).await.expect("replay");
    assert_eq!(
        first.ctx_id, replay.ctx_id,
        "replay must not mint a second context"
    );
}

/// The real registry must refuse a forged signature and a forged hash, and
/// the SDK must map each refusal to its typed error, never `Ok`.
#[tokio::test]
async fn live_registry_rejects_tampered_requests_with_typed_errors() {
    let Some(url) = live_url() else { return };
    let c = did_key_client(&url).await;
    let p = producer();

    // Signature from a different key over the same content.
    let mut forged = request(&p, "live forged signature");
    let other = request(&producer(), "live forged signature");
    forged.signature.value = other.signature.value;
    match c.publish(&forged).await {
        Err(AcdpError::InvalidSignature(_)) => {}
        other => panic!("forged signature: expected InvalidSignature, got {other:?}"),
    }

    // Body changed after signing: the registry recomputes a different hash
    // and answers `hash_mismatch`, which maps to RemoteHashMismatch.
    let mut tampered = request(&p, "live tampered body");
    tampered.title = "changed after signing".into();
    match c.publish(&tampered).await {
        Err(AcdpError::RemoteHashMismatch(_)) => {}
        other => panic!("tampered body: expected RemoteHashMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn live_supersession_advances_lineage_current() {
    let Some(url) = live_url() else { return };
    let c = did_key_client(&url).await;
    let p = producer();

    let v1 = c
        .publish(&request(&p, "live lineage v1"))
        .await
        .expect("v1");
    let v1_body = c.retrieve_body(&v1.ctx_id).await.expect("v1 body");
    let v2_req = p
        .new_version_from(&v1_body)
        .title("live lineage v2")
        .build()
        .expect("build v2");
    let v2 = c.publish(&v2_req).await.expect("v2 accepted");
    assert_eq!(v2.version, 2);
    assert_eq!(v2.lineage_id, v1.lineage_id);

    let current = c.current(&v1.lineage_id).await.expect("current");
    assert_eq!(current.body.ctx_id, v2.ctx_id, "current must be v2");
    verify_body_offline(&current.body).expect("v2 verifies offline");

    let lineage = c.lineage(&v1.lineage_id).await.expect("lineage");
    let ids: Vec<&CtxId> = lineage.iter().map(|x| &x.body.ctx_id).collect();
    assert!(
        ids.contains(&&v1.ctx_id) && ids.contains(&&v2.ctx_id),
        "{ids:?}"
    );
}

#[tokio::test]
async fn live_search_finds_published_context_by_agent() {
    let Some(url) = live_url() else { return };
    let c = did_key_client(&url).await;
    let p = producer();
    let req = request(&p, "live search");
    let req_agent = req.agent_id.as_str().to_string();
    let resp = c.publish(&req).await.expect("publish");

    let params = SearchParams {
        agent_id: Some(req_agent.clone()),
        ..Default::default()
    };
    let found = c.search(&params).await.expect("search");
    assert!(
        found.matches.iter().any(|m| m.ctx_id == resp.ctx_id),
        "search by agent_id did not return the published context"
    );
}

#[tokio::test]
async fn live_unknown_context_is_not_found() {
    let Some(url) = live_url() else { return };
    let c = did_key_client(&url).await;
    let p = producer();
    // Publish once to learn the registry's ctx_id shape, then ask for a
    // sibling id that was never minted.
    let resp = c
        .publish(&request(&p, "live not-found probe"))
        .await
        .expect("publish");
    let mut s = resp.ctx_id.0.clone();
    let last = s.pop().expect("non-empty ctx_id");
    s.push(if last == '0' { '1' } else { '0' });
    match c.retrieve(&CtxId(s)).await {
        Err(AcdpError::NotFound(_)) => {}
        other => panic!("unknown ctx_id: expected NotFound, got {other:?}"),
    }
}

fn uuid_like() -> String {
    let k = SigningKey::generate();
    k.verifying_key_bytes()[..12]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
