//! HTTP-level tests for `RegistryClient` against a mocked registry.
//!
//! Uses `wiremock` over plain HTTP (reqwest's rustls-tls backend handles HTTP
//! and HTTPS; only the TLS path requires TLS).

#![cfg(feature = "client")]

use acdp::{
    client::RegistryClient,
    error::AcdpError,
    types::{
        body::Signature,
        primitives::{AgentDid, ContentHash, ContextType, CtxId, LineageId, Visibility},
        publish::PublishRequest,
        search::SearchParams,
    },
};
use serde_json::json;
use wiremock::{
    matchers::{header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn sample_publish_request() -> PublishRequest {
    PublishRequest {
        version: 1,
        supersedes: None,
        agent_id: AgentDid::new("did:web:agents.example.com:test"),
        contributors: vec![],
        title: "test".into(),
        context_type: ContextType::DataSnapshot,
        data_refs: vec![],
        derived_from: vec![],
        visibility: Visibility::Public,
        content_hash: ContentHash("sha256:0000".into()),
        signature: Signature {
            algorithm: "ed25519".into(),
            key_id: "did:web:agents.example.com:test#key-1".into(),
            value: "AAAA".into(),
        },
        audience: None,
        acdp_version: None,
        description: None,
        summary: None,
        tags: None,
        domain: None,
        expires_at: None,
        data_period: None,
        metadata: None,
        schema_uri: None,
        anchors: None,
        lineage_id: None,
    }
}

fn sample_body_json(ctx_id: &str) -> serde_json::Value {
    json!({
        "ctx_id": ctx_id,
        "lineage_id": "lin:sha256:aabb",
        "origin_registry": "registry.example.com",
        "created_at": "2026-04-16T10:30:15.123Z",
        "content_hash": "sha256:0000",
        "signature": {
            "algorithm": "ed25519",
            "key_id": "did:web:agents.example.com:test#key-1",
            "value": "AAAA"
        },
        "version": 1,
        "supersedes": null,
        "agent_id": "did:web:agents.example.com:test",
        "contributors": [],
        "title": "test",
        "type": "data_snapshot",
        "data_refs": [],
        "derived_from": [],
        "visibility": "public"
    })
}

// ── Capabilities ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn capabilities_happy_path() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/acdp.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "acdp_version": "0.1.0",
            "registry_did": "did:web:registry.example.com",
            "supported_signature_algorithms": ["ed25519"],
            "supported_did_methods": ["did:web"],
            "profiles": ["acdp-registry-core", "acdp-registry-discovery"],
            "limits": {
                "max_payload_bytes": 1048576,
                "max_embedded_bytes": 65536
            },
            "anonymous_public_reads": true,
            "supports_idempotency_key": false
        })))
        .mount(&server)
        .await;

    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let caps = client.capabilities().await.expect("capabilities call");

    assert_eq!(caps.acdp_version, "0.1.0");
    assert!(caps.supports_discovery());
    assert!(!caps.supports_federation());
    assert_eq!(caps.limits.max_embedded_bytes, 65536);
}

// ── Publish ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn publish_returns_assigned_ids() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/contexts"))
        .and(header("Content-Type", "application/acdp+json"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "ctx_id": "acdp://registry.example.com/uuid-1",
            "lineage_id": "lin:sha256:aabb",
            "version": 1,
            "created_at": "2026-04-16T10:30:15.123Z",
            "status": "active"
        })))
        .mount(&server)
        .await;

    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let resp = client.publish(&sample_publish_request()).await.unwrap();

    assert_eq!(resp.ctx_id.as_str(), "acdp://registry.example.com/uuid-1");
    assert_eq!(resp.version, 1);
    assert!(resp.status.is_active());
}

#[tokio::test]
async fn publish_idempotent_sends_header() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/contexts"))
        .and(header("Idempotency-Key", "key-123"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "ctx_id": "acdp://registry.example.com/uuid-2",
            "lineage_id": "lin:sha256:aabb",
            "version": 1,
            "created_at": "2026-04-16T10:30:15.123Z",
            "status": "active"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    client
        .publish_idempotent(&sample_publish_request(), "key-123")
        .await
        .unwrap();
    // wiremock asserts the .expect(1) on drop
}

#[tokio::test]
async fn publish_error_surfaces_wire_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/contexts"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": {
                "code": "lineage_conflict",
                "message": "another version already exists for this lineage"
            }
        })))
        .mount(&server)
        .await;

    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let err = client.publish(&sample_publish_request()).await.unwrap_err();

    match err {
        AcdpError::Registry(wire) => {
            assert_eq!(wire.error.code, "lineage_conflict");
        }
        other => panic!("expected Registry error, got {other:?}"),
    }
}

#[tokio::test]
async fn publish_unknown_error_body_falls_back_to_unknown_code() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/contexts"))
        .respond_with(ResponseTemplate::new(500).set_body_string("not json"))
        .mount(&server)
        .await;

    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let err = client.publish(&sample_publish_request()).await.unwrap_err();
    match err {
        AcdpError::Registry(w) => assert_eq!(w.error.code, "unknown"),
        other => panic!("expected Registry error, got {other:?}"),
    }
}

// ── Retrieval ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn retrieve_full_context() {
    let server = MockServer::start().await;
    let ctx_id = "acdp://registry.example.com/uuid-1";

    Mock::given(method("GET"))
        // urlencoded ':' = %3A, '/' = %2F
        .and(path(format!(
            "/contexts/{}",
            urlencoding::encode(ctx_id)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "body": sample_body_json(ctx_id),
            "registry_state": { "status": "active" }
        })))
        .mount(&server)
        .await;

    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let ctx = client.retrieve(&CtxId(ctx_id.into())).await.unwrap();
    assert_eq!(ctx.body.title, "test");
    assert_eq!(
        ctx.body.ctx_id.as_str(),
        "acdp://registry.example.com/uuid-1"
    );
}

#[tokio::test]
async fn retrieve_body_only() {
    let server = MockServer::start().await;
    let ctx_id = "acdp://registry.example.com/uuid-1";

    Mock::given(method("GET"))
        .and(path(format!(
            "/contexts/{}/body",
            urlencoding::encode(ctx_id)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_body_json(ctx_id)))
        .mount(&server)
        .await;

    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let body = client.retrieve_body(&CtxId(ctx_id.into())).await.unwrap();
    assert_eq!(body.version, 1);
}

#[tokio::test]
async fn retrieve_not_found_maps_to_registry_error() {
    let server = MockServer::start().await;
    let ctx_id = "acdp://registry.example.com/missing";

    Mock::given(method("GET"))
        .and(path(format!("/contexts/{}", urlencoding::encode(ctx_id))))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": { "code": "not_found", "message": "no such context" }
        })))
        .mount(&server)
        .await;

    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let err = client.retrieve(&CtxId(ctx_id.into())).await.unwrap_err();
    match err {
        AcdpError::NotFound(_) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn rate_limited_maps_to_typed_variant() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/contexts"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "error": { "code": "rate_limited", "message": "slow down" }
        })))
        .mount(&server)
        .await;
    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let err = client.publish(&sample_publish_request()).await.unwrap_err();
    assert!(matches!(err, AcdpError::RateLimited(_)));
}

#[tokio::test]
async fn superseded_target_maps_with_reason() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/contexts"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": {
                "code": "superseded_target",
                "message": "target already superseded",
                "details": { "reason": "already_superseded" }
            }
        })))
        .mount(&server)
        .await;
    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let err = client.publish(&sample_publish_request()).await.unwrap_err();
    match err {
        AcdpError::SupersededTarget { reason, .. } => {
            assert_eq!(reason, acdp::SupersessionReason::AlreadySuperseded);
        }
        other => panic!("got {other:?}"),
    }
}

// ── Lineage ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn lineage_current_returns_latest() {
    let server = MockServer::start().await;
    let lineage = "lin:sha256:aabb";
    let ctx_id = "acdp://registry.example.com/uuid-1";

    Mock::given(method("GET"))
        .and(path(format!(
            "/lineages/{}/current",
            urlencoding::encode(lineage)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "body": sample_body_json(ctx_id),
            "registry_state": { "status": "active" }
        })))
        .mount(&server)
        .await;

    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let ctx = client.current(&LineageId(lineage.into())).await.unwrap();
    assert_eq!(ctx.body.title, "test");
}

// ── Search ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn search_passes_query_string() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/contexts/search"))
        .and(query_param("q", "revenue"))
        .and(query_param("type", "data_snapshot"))
        .and(query_param("limit", "10"))
        // A registry with no further pages MUST omit `next_cursor`, not
        // emit `next_cursor: null` (schema-005 absent-vs-null convention).
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "matches": [],
            "total_estimate": 0
        })))
        .mount(&server)
        .await;

    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let params = SearchParams {
        q: Some("revenue".into()),
        context_type: Some("data_snapshot".into()),
        limit: Some(10),
        ..Default::default()
    };
    let resp = client.search(&params).await.unwrap();
    assert_eq!(resp.matches.len(), 0);
    assert_eq!(resp.results().len(), 0); // back-compat accessor
}

#[tokio::test]
async fn search_response_with_results_key_rejected() {
    // Conformance vis-003: a registry that emits `results` is non-conformant.
    // The schema is additionalProperties: false; the deserializer rejects it
    // because `matches` is required.
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/contexts/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [],
            "total_estimate": 0
        })))
        .mount(&server)
        .await;

    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let err = client.search(&SearchParams::default()).await.unwrap_err();
    match err {
        AcdpError::Serialization(_) => {}
        other => panic!("expected Serialization error, got {other:?}"),
    }
}

#[tokio::test]
async fn search_response_with_matches_and_full_summary() {
    // A match_summary with the full optional set deserializes correctly.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/contexts/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "matches": [
                {
                    "ctx_id": "acdp://registry.example.com/550e8400-e29b-41d4-a716-446655440000",
                    "lineage_id": "lin:sha256:b14ccd2a8b34530309255db68c151a10689b6a82feb30aff9222d54fdd871720",
                    "agent_id": "did:web:agents.example.com:test",
                    "title": "Sample",
                    "summary": "Quarterly snapshot",
                    "type": "data_snapshot",
                    "domain": "finance",
                    "created_at": "2026-04-16T10:15:00.000Z",
                    "status": "active"
                }
            ]
        })))
        .mount(&server)
        .await;
    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let resp = client.search(&SearchParams::default()).await.unwrap();
    assert_eq!(resp.matches.len(), 1);
    assert_eq!(
        resp.matches[0].summary.as_deref(),
        Some("Quarterly snapshot")
    );
}

// ── URL trimming ─────────────────────────────────────────────────────────────

/// T5 — Cross-authority redirect MUST be rejected (RFC-ACDP-0006 §7.5).
#[tokio::test]
async fn cross_authority_redirect_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/acdp.json"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", "https://attacker.example.com/y"),
        )
        .mount(&server)
        .await;
    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let err = client.capabilities().await.unwrap_err();
    // Reqwest surfaces the policy rejection as an Http error.
    assert!(matches!(err, AcdpError::Http(_)));
}

/// T6 — Oversize body MUST be aborted before parse (§7.3 cap, ~1 MB).
#[tokio::test]
async fn oversize_response_body_aborted() {
    let server = MockServer::start().await;
    // 2 MB of JSON-shaped padding — well over the MAX_CONTEXT_BYTES cap.
    let big = "x".repeat(2 * 1024 * 1024);
    let payload = format!("{{\"junk\":\"{big}\"}}");
    Mock::given(method("GET"))
        .and(path("/contexts/search"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/acdp+json")
                .set_body_raw(payload, "application/acdp+json"),
        )
        .mount(&server)
        .await;
    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let err = client.search(&SearchParams::default()).await.unwrap_err();
    assert!(matches!(err, AcdpError::PayloadTooLarge(_)));
}

#[tokio::test]
async fn trailing_slash_is_normalized() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/acdp.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "acdp_version": "0.1.0",
            "registry_did": "did:web:registry.example.com",
            "supported_signature_algorithms": ["ed25519"],
            "supported_did_methods": ["did:web"],
            "profiles": ["acdp-registry-core"],
            "limits": { "max_payload_bytes": 1024, "max_embedded_bytes": 65536 }
        })))
        .mount(&server)
        .await;

    let with_slash = format!("{}/", server.uri());
    let client = RegistryClient::with_test_transport(&with_slash).unwrap();
    client.capabilities().await.unwrap();
}

/// BUG-09 — `capabilities_with_ttl` parses `Cache-Control: max-age=N`
/// and uses it as the cache TTL. A registry serving max-age=60 means
/// the resolver MUST honor that hint and refetch after 60s.
#[tokio::test]
async fn capabilities_ttl_reflects_cache_control_max_age() {
    let server = MockServer::start().await;
    let caps_body = json!({
        "acdp_version": "0.1.0",
        "registry_did": "did:web:registry.example.com",
        "supported_signature_algorithms": ["ed25519"],
        "supported_did_methods": ["did:web"],
        "profiles": ["acdp-registry-core"],
        "limits": { "max_payload_bytes": 1024, "max_embedded_bytes": 65536 }
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/acdp.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Cache-Control", "max-age=60")
                .set_body_json(caps_body),
        )
        .mount(&server)
        .await;

    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let (_caps, ttl) = client.capabilities_with_ttl().await.unwrap();
    assert_eq!(
        ttl,
        std::time::Duration::from_secs(60),
        "TTL MUST be the parsed max-age value (BUG-09 regression)"
    );
}

/// BUG-09 — absurdly large `max-age` is clamped to the 3600s ceiling
/// per RFC-ACDP-0006 §4.2.
#[tokio::test]
async fn capabilities_ttl_clamps_to_3600_ceiling() {
    let server = MockServer::start().await;
    let caps_body = json!({
        "acdp_version": "0.1.0",
        "registry_did": "did:web:registry.example.com",
        "supported_signature_algorithms": ["ed25519"],
        "supported_did_methods": ["did:web"],
        "profiles": ["acdp-registry-core"],
        "limits": { "max_payload_bytes": 1024, "max_embedded_bytes": 65536 }
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/acdp.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Cache-Control", "max-age=999999")
                .set_body_json(caps_body),
        )
        .mount(&server)
        .await;
    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let (_caps, ttl) = client.capabilities_with_ttl().await.unwrap();
    assert_eq!(ttl, std::time::Duration::from_secs(3600));
}

/// BUG-09 — no `Cache-Control` header falls back to the 300s default
/// (matches the prior resolver-wide TTL so behavior is unchanged on
/// silent registries).
#[tokio::test]
async fn capabilities_ttl_default_when_cache_control_absent() {
    let server = MockServer::start().await;
    let caps_body = json!({
        "acdp_version": "0.1.0",
        "registry_did": "did:web:registry.example.com",
        "supported_signature_algorithms": ["ed25519"],
        "supported_did_methods": ["did:web"],
        "profiles": ["acdp-registry-core"],
        "limits": { "max_payload_bytes": 1024, "max_embedded_bytes": 65536 }
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/acdp.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(caps_body))
        .mount(&server)
        .await;
    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    let (_caps, ttl) = client.capabilities_with_ttl().await.unwrap();
    assert_eq!(ttl, std::time::Duration::from_secs(300));
}

// ── P0-1: RegistryClient enforces SSRF / HTTPS-only / DNS-rebinding ──────────
//
// `RegistryClient::new` is the entire `acdp-consumer` transport surface and
// MUST apply the documented "applied automatically" posture (RFC-ACDP-0006
// §7 / RFC-ACDP-0008 §4.8–4.9). These constructor-time checks mirror the
// `did_ssrf_*` / `data_ref_ssrf_*` harness.

#[test]
fn new_rejects_plaintext_http() {
    match RegistryClient::new("http://registry.example.com") {
        Err(AcdpError::SchemaViolation(_)) => {}
        Err(other) => panic!("expected SchemaViolation, got {other:?}"),
        Ok(_) => panic!("plaintext http MUST be rejected"),
    }
}

#[test]
fn new_rejects_ip_literal_loopback() {
    assert!(RegistryClient::new("https://127.0.0.1").is_err());
    assert!(RegistryClient::new("https://[::1]").is_err());
}

#[test]
fn new_rejects_imds_and_private_ip_literals() {
    // AWS/GCP metadata endpoint and RFC 1918.
    assert!(RegistryClient::new("https://169.254.169.254").is_err());
    assert!(RegistryClient::new("https://10.0.0.1").is_err());
    assert!(RegistryClient::new("https://192.168.1.1").is_err());
}

#[test]
fn new_accepts_https_hostname() {
    // A plausible public hostname passes the constructor-time URL check
    // (DNS-time filtering still applies at connect).
    assert!(RegistryClient::new("https://registry.example.com").is_ok());
}

/// DNS-rebinding: a hostname whose DNS answer is a forbidden internal IP
/// MUST be refused at DNS time, before any connect. `localhost` resolves to
/// loopback, which the default policy forbids.
#[tokio::test]
async fn new_refuses_hostname_resolving_to_loopback_at_dns_time() {
    // Use a real mock server (binds loopback) but address it via the
    // `localhost` *hostname* so resolution — not an IP literal — is what the
    // SafeDnsResolver filters.
    let server = MockServer::start().await;
    let port = server.address().port();
    let url = format!("https://localhost:{port}");
    // Constructor succeeds (hostname is syntactically fine)...
    let client = RegistryClient::new(&url).unwrap();
    // ...but the request fails: localhost → 127.0.0.1 is filtered at DNS time.
    let err = client.capabilities().await.unwrap_err();
    // A bare `is_err()` here would pass even if DNS-time SSRF filtering were
    // completely disabled: `MockServer` only ever serves plain HTTP, so an
    // `https://` request against it fails the TLS handshake regardless of
    // which IP it resolved to. Assert on the SSRF rejection text itself
    // (surfaced via the `reqwest::Error` source chain — see
    // `AcdpError::from(reqwest::Error)`) so this test can only pass when the
    // DNS-time filter is what actually fired.
    let AcdpError::Http(msg) = &err else {
        panic!("expected AcdpError::Http, got {err:?}");
    };
    assert!(
        msg.contains("SSRF policy") && msg.contains("forbidden"),
        "expected the DNS-time SSRF rejection to be visible in the error, got: {msg}"
    );
}
