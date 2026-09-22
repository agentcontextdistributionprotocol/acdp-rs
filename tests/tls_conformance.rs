//! TLS-backed fixture-bound conformance tests.
//!
//! Each test spins up an in-process self-signed HTTPS server via the
//! shared [`common::TlsTestServer`] helper and configures a `WebResolver`
//! / `RegistryClient` to trust it. This unblocks the conformance
//! fixtures that need a live `did:web` HTTPS endpoint or a live foreign
//! registry — previously deferred behind a "needs TLS mock" note in
//! `plans/defered/defered.md`.

mod common;

use acdp::crypto::sign::SigningKey;
use acdp::crypto::verify_publish_request_signature;
use acdp::did::WebResolver;
use acdp::producer::Producer;
use acdp::safe_http::SsrfPolicy;
use acdp::types::primitives::{AgentDid, ContextType, Visibility};
use acdp::AcdpError;

/// Test-only resolver constructor: trusts the harness's self-signed
/// root and opts the SsrfPolicy into loopback so `did:web:localhost…`
/// resolves against `127.0.0.1`. Default policy still rejects every
/// other forbidden range — only loopback is permitted.
fn test_resolver(root_cert_pem: &[u8]) -> WebResolver {
    WebResolver::with_root_cert_pem(root_cert_pem)
        .expect("resolver")
        .with_ssrf_policy(SsrfPolicy::allow_test_loopback())
}

use common::{did_doc_router, ed25519_did_doc, ed25519_did_doc_without_assertion, TlsTestServer};

// ── pub-001 — forged signature rejected ──────────────────────────────────────

/// pub-001 — a PublishRequest whose signature value was produced by a
/// key that is NOT the one published in the DID document MUST be
/// rejected at signature verification (RFC-ACDP-0003 §2.1 step 8).
///
/// Construction:
///   1. honest_key — published in the DID document
///   2. attacker_key — different keypair, used to sign the publish request
///   3. ProducerContent / content_hash are correctly computed for the
///      forged request — only the signature is from the wrong key.
///   4. Verifier MUST fail with `AcdpError::InvalidSignature(_)`.
#[tokio::test]
async fn pub_001_forged_signature_rejected() {
    let honest_key = SigningKey::generate();
    let attacker_key = SigningKey::generate();
    let honest_pub = honest_key.verifying_key_bytes();

    let server = TlsTestServer::start_with(|port| {
        let did = format!("did:web:localhost%3A{port}");
        let doc = ed25519_did_doc(&did, "key-1", &honest_pub);
        did_doc_router(doc)
    })
    .await;

    let did = server.did();
    let key_id = format!("{did}#key-1");

    let resolver = test_resolver(&server.root_cert_pem);

    // Forged: signer is attacker_key, but the publish references the
    // honest DID + its key_id. content_hash is correct; only the
    // signature value differs from what the resolver-fetched key would
    // verify.
    let producer = Producer::new(attacker_key, AgentDid::new(did.clone()), key_id);
    let req = producer
        .publish_request()
        .title("pub-001: forged signature")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("forged request builds");

    let err = verify_publish_request_signature(&req, &resolver)
        .await
        .expect_err("forged signature MUST be rejected");
    assert!(
        matches!(err, AcdpError::InvalidSignature(_)),
        "pub-001 MUST surface InvalidSignature, got {err:?}"
    );
}

// ── pub-006 — key not in assertionMethod ────────────────────────────────────

/// pub-006 — the verification method is present in the DID document
/// and the signature would otherwise verify, but the key is NOT listed
/// in `assertionMethod`. The verifier MUST reject with
/// `KeyNotAuthorized` (RFC-ACDP-0001 §5.11 step 5).
#[tokio::test]
async fn pub_006_key_not_in_assertion_method() {
    let key = SigningKey::generate();
    let pub_bytes = key.verifying_key_bytes();

    let server = TlsTestServer::start_with(|port| {
        let did = format!("did:web:localhost%3A{port}");
        did_doc_router(ed25519_did_doc_without_assertion(&did, "key-1", &pub_bytes))
    })
    .await;

    let did = server.did();
    let key_id = format!("{did}#key-1");

    let resolver = test_resolver(&server.root_cert_pem);

    let producer = Producer::new(key, AgentDid::new(did.clone()), key_id);
    let req = producer
        .publish_request()
        .title("pub-006: key not in assertionMethod")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("valid signed request");

    let err = verify_publish_request_signature(&req, &resolver)
        .await
        .expect_err("missing assertionMethod authorization MUST be rejected");
    assert!(
        matches!(err, AcdpError::KeyNotAuthorized(_)),
        "pub-006 MUST surface KeyNotAuthorized, got {err:?}"
    );
}

// ── happy-path sanity — resolver + TLS server work end-to-end ───────────────

/// Smoke test that the TLS helper + `WebResolver::with_root_cert_pem`
/// actually round-trip: an honest publish request from a key
/// authorized in `assertionMethod` MUST verify.
#[tokio::test]
async fn tls_resolver_happy_path() {
    let key = SigningKey::generate();
    let pub_bytes = key.verifying_key_bytes();

    let server = TlsTestServer::start_with(|port| {
        let did = format!("did:web:localhost%3A{port}");
        did_doc_router(ed25519_did_doc(&did, "key-1", &pub_bytes))
    })
    .await;

    let did = server.did();
    let key_id = format!("{did}#key-1");
    let resolver = test_resolver(&server.root_cert_pem);

    let producer = Producer::new(key, AgentDid::new(did.clone()), key_id);
    let req = producer
        .publish_request()
        .title("happy path")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("build");

    verify_publish_request_signature(&req, &resolver)
        .await
        .expect("honest signature MUST verify against TLS-served DID");
}

// ── pub-003 — supersession lineage mismatch ─────────────────────────────────

/// pub-003 — a v2+ publish that declares a `lineage_id` not matching the
/// predecessor's MUST be rejected with
/// `SupersededTarget { reason: LineageMismatch }` (RFC-ACDP-0003 §3.1
/// step 4 + RFC-ACDP-0007 §5 mapping).
///
/// The fixture's body uses a placeholder signature and a non-did:web
/// agent_id; the binding here exercises the same lineage-mismatch
/// condition with a real signing flow and a real registry-assigned v1.
/// The error surface is what pub-003 normatively requires.
#[cfg(feature = "server")]
#[test]
fn pub_003_supersession_lineage_mismatch() {
    use acdp::registry::{InMemoryStore, RegistryServer};
    use acdp::types::primitives::LineageId;
    use acdp::types::{CapabilitiesDocument, Limits};

    let caps = CapabilitiesDocument {
        acdp_version: "0.1.0".into(),
        registry_did: "did:web:registry.example.com".into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into()],
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
    };
    let server = RegistryServer::new(InMemoryStore::new(), caps, "registry.example.com");

    let key = SigningKey::generate();
    let agent = AgentDid::new("did:web:agents.example.com:test");
    let producer = Producer::new(key, agent.clone(), "did:web:agents.example.com:test#key-1");

    let v1_req = producer
        .publish_request()
        .title("v1")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("v1 builds");
    let v1 = server
        .publish_unverified_for_tests(&v1_req)
        .expect("v1 persists");

    // Build v2 superseding v1, but override the declared lineage_id to a
    // value that differs from v1.lineage_id. The builder accepts this
    // (it's a producer-supplied self-verifying value); the registry's
    // step 10 lineage coherence check is what MUST reject it.
    let wrong_lineage = LineageId(
        "lin:sha256:9999999999999999999999999999999999999999999999999999999999999999".into(),
    );
    let v2_req = producer
        .supersede(v1.ctx_id.clone())
        .version(2)
        .expected_lineage_id(wrong_lineage)
        .title("v2 with mismatched lineage")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("v2 with wrong lineage_id still builds");

    let err = server
        .publish_unverified_for_tests(&v2_req)
        .expect_err("lineage_mismatch MUST be rejected");
    match err {
        AcdpError::SupersededTarget { reason, .. } => {
            assert_eq!(
                reason,
                acdp::error::SupersessionReason::LineageMismatch,
                "pub-003: details.reason MUST be 'lineage_mismatch'"
            );
        }
        other => panic!("pub-003: expected SupersededTarget::LineageMismatch, got {other:?}"),
    }
}

// ── fed-001..005 — SSRF policy bindings (offline) ────────────────────────────

mod fed_001_005_offline {
    use acdp::safe_http::SsrfPolicy;
    use acdp::AcdpError;

    /// fed-001 — HTTPS-only. `http://`, `ftp://`, `file://`, `ws://` all
    /// MUST be rejected with the same outcome before any socket activity.
    #[test]
    fn fed_001_https_only() {
        let p = SsrfPolicy::default();
        for forbidden in [
            "http://insecure.example.com",
            "ftp://ftp.example.com",
            "file:///etc/passwd",
            "ws://ws.example.com",
        ] {
            let err = p
                .check_url(forbidden)
                .expect_err(&format!("fed-001: '{forbidden}' MUST be rejected"));
            assert!(
                matches!(err, AcdpError::SchemaViolation(_)),
                "fed-001: '{forbidden}' rejection MUST surface SchemaViolation, got {err:?}"
            );
        }
        // Positive: https:// passes the same policy.
        p.check_url("https://registry.example.com")
            .expect("fed-001: https:// MUST pass");
    }

    /// fed-002 — RFC 1918 private IPv4 ranges rejected.
    #[test]
    fn fed_002_private_ip_ranges() {
        let p = SsrfPolicy::default();
        for ip in ["10.0.0.1", "172.16.5.5", "172.31.255.254", "192.168.1.1"] {
            let parsed: std::net::IpAddr = ip.parse().unwrap();
            p.check_resolved_ip(parsed)
                .expect_err(&format!("fed-002: '{ip}' MUST be rejected"));
        }
        // Positive: public IP passes.
        p.check_resolved_ip("8.8.8.8".parse().unwrap())
            .expect("fed-002: public IP MUST pass");
    }

    /// fed-003 — loopback (127.0.0.0/8 + ::1) rejected.
    #[test]
    fn fed_003_loopback() {
        let p = SsrfPolicy::default();
        for ip in ["127.0.0.1", "127.99.99.99"] {
            p.check_resolved_ip(ip.parse().unwrap())
                .expect_err(&format!("fed-003: '{ip}' MUST be rejected"));
        }
        let v6_loopback: std::net::IpAddr = "::1".parse().unwrap();
        p.check_resolved_ip(v6_loopback)
            .expect_err("fed-003: ::1 MUST be rejected");
    }

    /// fed-004 — link-local + IMDS (169.254.0.0/16, fe80::/10) rejected.
    #[test]
    fn fed_004_link_local_and_imds() {
        let p = SsrfPolicy::default();
        // AWS / GCP / Azure metadata service.
        p.check_resolved_ip("169.254.169.254".parse().unwrap())
            .expect_err("fed-004: IMDS MUST be rejected");
        // RFC 3927 link-local.
        p.check_resolved_ip("169.254.5.5".parse().unwrap())
            .expect_err("fed-004: link-local MUST be rejected");
        // IPv6 link-local.
        p.check_resolved_ip("fe80::1".parse().unwrap())
            .expect_err("fed-004: IPv6 link-local MUST be rejected");
    }

    /// fed-005 — cross-authority redirects rejected.
    #[test]
    fn fed_005_cross_authority_redirect() {
        let p = SsrfPolicy::default();
        let orig = url::Url::parse("https://registry.example.com/a").unwrap();
        let err = p
            .check_redirect_authority(&orig, "https://attacker.com/x")
            .expect_err("fed-005: cross-authority redirect MUST be rejected");
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
        // Same authority OK.
        p.check_redirect_authority(&orig, "https://registry.example.com/y")
            .expect("fed-005: same-authority redirect MUST pass");
    }
}

// ── fed-006 — registry DID mismatch (TLS-backed) ─────────────────────────────

/// fed-006 — when a foreign registry's capabilities document declares a
/// `registry_did` that does not match `did:web:<authority>`, the
/// resolver MUST reject with `CrossRegistryResolutionFailed`. Catches a
/// registry impersonating a different authority via its DID claim.
///
/// The `acdp://` reference uses authority `localhost` (a valid
/// lowercase DNS label that satisfies the `CtxId` parser). The seeded
/// `RegistryClient` is pinned to the test server's actual
/// `127.0.0.1:<port>` via `with_test_endpoint`, so the resolver hits the
/// in-process mock instead of a real network endpoint.
#[tokio::test]
async fn fed_006_registry_did_mismatch() {
    use acdp::client::{CrossRegistryResolver, RegistryClient};
    use acdp::types::primitives::CtxId;

    let server = TlsTestServer::start_with(|_port| {
        // Capabilities advertise `did:web:other-registry.example.com`,
        // but the resolver expects `did:web:localhost` to match the URL
        // authority — pinning the divergence pub-006 normatively
        // requires the resolver to detect.
        common::capabilities_router(common::minimal_capabilities(
            "did:web:other-registry.example.com",
        ))
    })
    .await;

    let authority = "localhost";
    let base = format!("https://{authority}");
    let target: std::net::SocketAddr = server.addr;
    let client =
        RegistryClient::with_test_endpoint(&base, target, &server.root_cert_pem).expect("client");

    let resolver = CrossRegistryResolver::new();
    resolver.seed_client(authority, client);

    let ctx_id = CtxId(format!(
        "acdp://{authority}/12345678-1234-4321-8123-123456781234"
    ));
    let err = match resolver.resolve(&ctx_id).await {
        Ok(_) => panic!("fed-006: mismatched registry_did MUST be rejected"),
        Err(e) => e,
    };
    match err {
        AcdpError::CrossRegistryResolutionFailed(msg) => {
            assert!(
                msg.contains("registry DID") && msg.contains("other-registry.example.com"),
                "fed-006: error MUST surface the DID mismatch, got {msg:?}"
            );
        }
        other => panic!("fed-006: expected CrossRegistryResolutionFailed, got {other:?}"),
    }
}

// ── SEC-01 — CrossRegistryResolver pins authority DNS ────────────────────────

/// SEC-01 — `CrossRegistryResolver` builds its per-authority
/// `RegistryClient` via `RegistryClient::builder(base).pinned(true)`,
/// which resolves the authority's DNS up-front and refuses any answer
/// in a forbidden range.
///
/// `check_url` alone only validates URL *syntax* — a hostile `ctx_id`
/// authority that is a syntactically valid public hostname but resolves
/// to a private / loopback address would slip past it. `localhost`
/// stands in for such a hostname: it parses as a valid `CtxId`
/// authority and clears `check_url`, but resolves to a loopback address
/// that the pinned constructor MUST reject before any connection.
#[tokio::test]
async fn sec_01_cross_registry_pins_authority_dns() {
    use acdp::client::CrossRegistryResolver;
    use acdp::types::primitives::CtxId;

    let resolver = CrossRegistryResolver::new();
    let ctx_id = CtxId("acdp://localhost/12345678-1234-4321-8123-123456781234".into());
    let err = match resolver.resolve(&ctx_id).await {
        Ok(_) => panic!("SEC-01: authority resolving to loopback MUST be refused"),
        Err(e) => e,
    };
    // The pinned builder → `pin_resolved_ip` rejects the loopback answer
    // with `SchemaViolation` ("forbidden range"); it propagates unwrapped
    // from `client_for`.
    assert!(
        matches!(err, AcdpError::SchemaViolation(_)),
        "SEC-01: expected SchemaViolation from the pinned DNS check, got {err:?}"
    );
}

// ── VerificationReport (FEAT-06) — structured diagnostic outcome ────────────

/// FEAT-06 — `VerifiedContext::fetch_report` returns a structured
/// outcome alongside the verified context. All top-level booleans
/// must be `true` on the happy path; per-DataRef slots reflect the
/// declared refs (empty here because the test body has no data_refs).
#[tokio::test]
async fn fetch_report_happy_path() {
    use acdp::client::{RegistryClient, VerificationPolicy, VerifiedContext};
    use acdp::types::body::{Body, FullContext, RegistryState, Signature};
    use acdp::types::primitives::{CtxId, Status};
    use chrono::{TimeZone, Utc};
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let key = SigningKey::generate();
    let pub_bytes = key.verifying_key_bytes();

    // TLS DID server — answers GET /.well-known/did.json for the
    // honest key.
    let tls = TlsTestServer::start_with(|port| {
        let did = format!("did:web:localhost%3A{port}");
        did_doc_router(ed25519_did_doc(&did, "key-1", &pub_bytes))
    })
    .await;
    let did = tls.did();
    let key_id = format!("{did}#key-1");

    // Build a publish request → use its content_hash + signature to
    // synthesize a stored FullContext that the verifier will check.
    let producer = Producer::new(key, AgentDid::new(did.clone()), key_id.clone());
    let req = producer
        .publish_request()
        .title("fetch_report happy")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("build");

    let ctx_id = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
    let lineage_id = acdp::crypto::derive_lineage_id(&ctx_id);
    let body = Body {
        ctx_id: ctx_id.clone(),
        lineage_id,
        origin_registry: "registry.example.com".into(),
        created_at: Utc.with_ymd_and_hms(2026, 5, 10, 0, 0, 0).unwrap(),
        content_hash: req.content_hash.clone(),
        signature: Signature {
            algorithm: req.signature.algorithm.clone(),
            key_id: req.signature.key_id.clone(),
            value: req.signature.value.clone(),
        },
        version: req.version,
        supersedes: req.supersedes.clone(),
        agent_id: req.agent_id.clone(),
        contributors: req.contributors.clone(),
        title: req.title.clone(),
        context_type: req.context_type.clone(),
        data_refs: req.data_refs.clone(),
        derived_from: req.derived_from.clone(),
        visibility: req.visibility.clone(),
        audience: req.audience.clone(),
        acdp_version: req.acdp_version.clone(),
        description: req.description.clone(),
        summary: req.summary.clone(),
        tags: req.tags.clone(),
        domain: req.domain.clone(),
        expires_at: req.expires_at,
        data_period: req.data_period.clone(),
        metadata: req.metadata.clone(),
        schema_uri: req.schema_uri.clone(),
        anchors: req.anchors.clone(),
        extensions: Default::default(),
    };
    let full = FullContext {
        body,
        registry_state: RegistryState {
            status: Status::Active,
            lifecycle_events: None,
            extensions: Default::default(),
        },
        registry_receipt: None,
        lineage_head_receipt: None,
        log_inclusion: None,
        extensions: Default::default(),
    };
    let full_value = serde_json::to_value(&full).expect("FullContext serializes");

    // Wiremock registry — answers any `GET /contexts/...` with the
    // FullContext above. Plain HTTP is fine; reqwest's rustls backend
    // accepts both schemes.
    let registry = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/contexts/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(full_value))
        .mount(&registry)
        .await;

    let client = RegistryClient::with_test_transport(&registry.uri()).expect("client");
    let resolver = test_resolver(&tls.root_cert_pem);

    let (_verified, report) =
        VerifiedContext::fetch_report(&client, &resolver, &ctx_id, &VerificationPolicy::default())
            .await
            .expect("fetch_report MUST succeed");

    assert!(
        report.body_hash_ok,
        "body_hash_ok MUST be true on happy path"
    );
    assert!(
        report.signature_ok,
        "signature_ok MUST be true on happy path"
    );
    assert!(report.schema_ok, "schema_ok MUST be true on happy path");
    assert!(
        report.data_ref_embedded.is_empty(),
        "no data_refs in this body — embedded slot vec MUST be empty"
    );
    assert!(
        report.data_ref_external.is_empty(),
        "no data_refs in this body — external slot vec MUST be empty"
    );
}

/// BUG-05 — `VerificationPolicy::validate_body_schema = false` MUST
/// actually skip the structural validator. Previously `verify_body`
/// re-ran `validate_body` unconditionally so the knob was a no-op.
///
/// Construction: a body whose `summary` exceeds the 1000-char cap is
/// structurally invalid but cryptographically sound. With the policy
/// flag off, `fetch_with_policy` MUST succeed; with it on (the
/// default), the same body MUST fail with `SchemaViolation`.
#[tokio::test]
async fn verification_policy_validate_body_schema_off_skips_structural_check() {
    use acdp::client::{RegistryClient, VerificationPolicy, VerifiedContext};
    use acdp::crypto::{compute_content_hash, derive_lineage_id};
    use acdp::types::body::{Body, FullContext, RegistryState, Signature};
    use acdp::types::primitives::{CtxId, Status};
    use chrono::{TimeZone, Utc};
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let key = SigningKey::generate();
    let pub_bytes = key.verifying_key_bytes();
    let tls = TlsTestServer::start_with(|port| {
        let did = format!("did:web:localhost%3A{port}");
        did_doc_router(ed25519_did_doc(&did, "key-1", &pub_bytes))
    })
    .await;
    let did = tls.did();
    let key_id = format!("{did}#key-1");

    let ctx_id = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
    let lineage_id = derive_lineage_id(&ctx_id);
    let created_at = Utc.with_ymd_and_hms(2026, 5, 18, 0, 0, 0).unwrap();

    // Oversize summary: 1001 chars > MAX_SUMMARY_LEN. The body still
    // hashes and signs correctly — the offense is purely structural.
    let oversize_summary = "x".repeat(1001);
    let mut body = Body {
        ctx_id: ctx_id.clone(),
        lineage_id,
        origin_registry: "registry.example.com".into(),
        created_at,
        content_hash: acdp::types::ContentHash(String::new()),
        signature: Signature {
            algorithm: "ed25519".into(),
            key_id: key_id.clone(),
            value: String::new(),
        },
        version: 1,
        supersedes: None,
        agent_id: AgentDid::new(did.clone()),
        contributors: vec![],
        title: "BUG-05 fixture".into(),
        context_type: ContextType::DataSnapshot,
        data_refs: vec![],
        derived_from: vec![],
        visibility: Visibility::Public,
        audience: None,
        acdp_version: None,
        description: None,
        summary: Some(oversize_summary),
        tags: None,
        domain: None,
        expires_at: None,
        data_period: None,
        metadata: None,
        schema_uri: None,
        anchors: None,
        extensions: Default::default(),
    };
    let body_value = serde_json::to_value(&body).unwrap();
    body.content_hash = compute_content_hash(&body_value).unwrap();
    body.signature.value = key.sign_content_hash(&body.content_hash);

    let full_value = serde_json::to_value(FullContext {
        body,
        registry_state: RegistryState {
            status: Status::Active,
            lifecycle_events: None,
            extensions: Default::default(),
        },
        registry_receipt: None,
        lineage_head_receipt: None,
        log_inclusion: None,
        extensions: Default::default(),
    })
    .unwrap();

    let registry = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/contexts/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(full_value))
        .mount(&registry)
        .await;
    let client = RegistryClient::with_test_transport(&registry.uri()).unwrap();
    let resolver = test_resolver(&tls.root_cert_pem);

    // Default policy: structural validation enabled → MUST fail.
    match VerifiedContext::fetch_with_policy(
        &client,
        &resolver,
        &ctx_id,
        &VerificationPolicy::default(),
    )
    .await
    {
        Ok(_) => panic!("default policy MUST reject oversize summary"),
        Err(AcdpError::SchemaViolation(_)) => {}
        Err(other) => panic!("default policy MUST surface SchemaViolation, got {other:?}"),
    }

    // Schema off: structural check skipped → MUST succeed (the
    // signature and hash still verify).
    let relaxed = VerificationPolicy {
        validate_body_schema: false,
        ..VerificationPolicy::default()
    };
    VerifiedContext::fetch_with_policy(&client, &resolver, &ctx_id, &relaxed)
        .await
        .expect(
            "policy.validate_body_schema=false MUST skip structural validation \
             (BUG-05 regression)",
        );
}

/// FEAT-06 follow-up — when an embedded `DataRef`'s declared
/// `content_hash` does NOT match the embedded payload, the report
/// MUST record the mismatch in `data_ref_embedded[i]` instead of
/// aborting the entire `fetch_report` call. The top-level checks
/// (`schema_ok`, `body_hash_ok`, `signature_ok`) MUST still pass —
/// they describe the body envelope, not per-DataRef integrity.
///
/// This is the key behavioral promise of `fetch_report` that the
/// happy-path test alone doesn't exercise.
#[tokio::test]
async fn fetch_report_records_embedded_hash_failure() {
    use acdp::client::{RegistryClient, VerificationPolicy, VerifiedContext};
    use acdp::crypto::{compute_content_hash, derive_lineage_id};
    use acdp::types::body::{Body, FullContext, RegistryState, Signature};
    use acdp::types::data_ref::{DataRef, DataRefType, EmbeddedContent, EmbeddedEncoding};
    use acdp::types::primitives::{CtxId, Status};
    use acdp::types::ContentHash;
    use chrono::{TimeZone, Utc};
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let key = SigningKey::generate();
    let pub_bytes = key.verifying_key_bytes();

    let tls = TlsTestServer::start_with(|port| {
        let did = format!("did:web:localhost%3A{port}");
        did_doc_router(ed25519_did_doc(&did, "key-1", &pub_bytes))
    })
    .await;
    let did = tls.did();
    let key_id = format!("{did}#key-1");

    // Bad embedded ref: the producer claims `content_hash = sha256:0000…`
    // but the actual UTF-8 payload is "hello" (which has a different
    // SHA-256). The DataRef itself is structurally valid (one of
    // location/embedded, embedded.content is a string for utf8
    // encoding) — only the declared hash is wrong.
    let bad_data_ref = DataRef {
        ref_type: DataRefType::PrimaryResult,
        description: None,
        size_bytes: None,
        format: None,
        schema_version: None,
        content_hash: Some(ContentHash(format!("sha256:{}", "0".repeat(64)))),
        location: None,
        embedded: Some(EmbeddedContent {
            encoding: EmbeddedEncoding::Utf8,
            content: serde_json::Value::String("hello".into()),
            content_hash: None,
        }),
        extensions: serde_json::Map::new(),
    };

    let ctx_id = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
    let lineage_id = derive_lineage_id(&ctx_id);
    let created_at = Utc.with_ymd_and_hms(2026, 5, 11, 0, 0, 0).unwrap();

    // Build the body with the bad DataRef. Producer cannot use
    // `RequestBuilder` here because builder runs `validate_data_ref`
    // which would reject the bad embedded hash at build time.
    let mut body = Body {
        ctx_id: ctx_id.clone(),
        lineage_id,
        origin_registry: "registry.example.com".into(),
        created_at,
        // placeholder — recomputed below
        content_hash: ContentHash(String::new()),
        signature: Signature {
            algorithm: "ed25519".into(),
            key_id: key_id.clone(),
            value: String::new(),
        },
        version: 1,
        supersedes: None,
        agent_id: AgentDid::new(did.clone()),
        contributors: vec![],
        title: "embedded-hash-mismatch fixture".into(),
        context_type: ContextType::DataSnapshot,
        data_refs: vec![bad_data_ref],
        derived_from: vec![],
        visibility: Visibility::Public,
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
        extensions: Default::default(),
    };

    // Compute the body-level content_hash over ProducerContent (with
    // the bad DataRef included) and sign it.
    let body_value = serde_json::to_value(&body).expect("serialize body for hashing");
    let computed = compute_content_hash(&body_value).expect("compute body hash");
    body.content_hash = computed.clone();
    body.signature.value = key.sign_content_hash(&computed);

    let full_value = serde_json::to_value(FullContext {
        body,
        registry_state: RegistryState {
            status: Status::Active,
            lifecycle_events: None,
            extensions: Default::default(),
        },
        registry_receipt: None,
        lineage_head_receipt: None,
        log_inclusion: None,
        extensions: Default::default(),
    })
    .expect("serialize full context");

    let registry = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/contexts/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(full_value))
        .mount(&registry)
        .await;
    let client = RegistryClient::with_test_transport(&registry.uri()).expect("client");
    let resolver = test_resolver(&tls.root_cert_pem);

    let (_verified, report) =
        VerifiedContext::fetch_report(&client, &resolver, &ctx_id, &VerificationPolicy::default())
            .await
            .expect("fetch_report MUST succeed despite the bad DataRef hash");

    // Top-level: envelope is sound.
    assert!(report.schema_ok, "structural schema MUST still pass");
    assert!(
        report.body_hash_ok,
        "body-level content_hash MUST still verify (it was computed over the bad-DataRef body)"
    );
    assert!(report.signature_ok, "producer signature MUST still verify");

    // Per-DataRef: the embedded hash mismatch is recorded, not raised.
    assert_eq!(
        report.data_ref_embedded.len(),
        1,
        "report MUST have one slot per declared DataRef"
    );
    assert!(
        report.data_ref_embedded[0].is_err(),
        "embedded hash mismatch MUST surface as Err in data_ref_embedded[0]; got {:?}",
        report.data_ref_embedded[0]
    );

    // External fetches were not attempted (no fetcher was passed).
    assert_eq!(report.data_ref_external.len(), 1);
    assert!(
        report.data_ref_external[0].is_none(),
        "no fetcher supplied — external slot MUST be None, got {:?}",
        report.data_ref_external[0]
    );
}

/// FEAT-05 — `fetch_report_diagnose` populates the report even when a
/// top-level check fails. A forged signature (signer key ≠ DID-resolved
/// key) MUST surface as `(None, report)` with `body_hash_ok = true`,
/// `signature_ok = false`, `schema_ok = true`. The default
/// `fetch_report` would have returned `Err(InvalidSignature)` with no
/// report.
#[tokio::test]
async fn fetch_report_diagnose_records_forged_signature() {
    use acdp::client::{RegistryClient, VerificationPolicy, VerifiedContext};
    use acdp::crypto::{compute_content_hash, derive_lineage_id};
    use acdp::types::body::{Body, FullContext, RegistryState, Signature};
    use acdp::types::primitives::{CtxId, Status};
    use chrono::{TimeZone, Utc};
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let honest_key = SigningKey::generate();
    let attacker_key = SigningKey::generate();
    let honest_pub = honest_key.verifying_key_bytes();

    // TLS DID server hosts the honest key.
    let tls = TlsTestServer::start_with(|port| {
        let did = format!("did:web:localhost%3A{port}");
        did_doc_router(ed25519_did_doc(&did, "key-1", &honest_pub))
    })
    .await;
    let did = tls.did();
    let key_id = format!("{did}#key-1");

    // Compute the hash over a well-formed ProducerContent, then sign
    // with the ATTACKER key. Hash will verify; signature won't.
    let ctx_id = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
    let lineage_id = derive_lineage_id(&ctx_id);
    let mut body = Body {
        ctx_id: ctx_id.clone(),
        lineage_id,
        origin_registry: "registry.example.com".into(),
        created_at: Utc.with_ymd_and_hms(2026, 5, 18, 0, 0, 0).unwrap(),
        content_hash: acdp::types::ContentHash(String::new()),
        signature: Signature {
            algorithm: "ed25519".into(),
            key_id: key_id.clone(),
            value: String::new(),
        },
        version: 1,
        supersedes: None,
        agent_id: AgentDid::new(did.clone()),
        contributors: vec![],
        title: "FEAT-05 diagnose forged sig".into(),
        context_type: ContextType::DataSnapshot,
        data_refs: vec![],
        derived_from: vec![],
        visibility: Visibility::Public,
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
        extensions: Default::default(),
    };
    let body_value = serde_json::to_value(&body).unwrap();
    body.content_hash = compute_content_hash(&body_value).unwrap();
    body.signature.value = attacker_key.sign_content_hash(&body.content_hash);

    let full_value = serde_json::to_value(FullContext {
        body,
        registry_state: RegistryState {
            status: Status::Active,
            lifecycle_events: None,
            extensions: Default::default(),
        },
        registry_receipt: None,
        lineage_head_receipt: None,
        log_inclusion: None,
        extensions: Default::default(),
    })
    .unwrap();

    let registry = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/contexts/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(full_value))
        .mount(&registry)
        .await;
    let client = RegistryClient::with_test_transport(&registry.uri()).unwrap();
    let resolver = test_resolver(&tls.root_cert_pem);

    // Diagnose: MUST succeed with a populated report.
    let (verified, report) = VerifiedContext::fetch_report_diagnose(
        &client,
        &resolver,
        &ctx_id,
        &VerificationPolicy::default(),
    )
    .await
    .expect("fetch_report_diagnose MUST surface the report rather than erroring");

    assert!(
        verified.is_none(),
        "top-level failure MUST yield None for the verified context"
    );
    assert!(report.schema_ok, "schema check MUST still pass");
    assert!(
        report.body_hash_ok,
        "hash recomputation MUST pass — the attacker computed content_hash correctly"
    );
    assert!(
        !report.signature_ok,
        "signature MUST be recorded as failed — attacker_key ≠ honest key in DID doc"
    );

    // The default `fetch_report` MUST still hard-fail for the same input.
    match VerifiedContext::fetch_report(&client, &resolver, &ctx_id, &VerificationPolicy::default())
        .await
    {
        Ok(_) => panic!("default fetch_report MUST reject forged signature"),
        Err(AcdpError::InvalidSignature(_)) => {}
        Err(other) => panic!("default fetch_report MUST surface InvalidSignature, got {other:?}"),
    }
}

// ── fixture presence checks ──────────────────────────────────────────────────

/// Assert each Phase-12 fixture exists in the bundled spec checkout.
/// If the spec isn't co-located the harness skips (matches the rest of
/// `tests/conformance.rs`), so this is a one-line guard against the
/// fixture set being renamed out from under us.
#[test]
fn phase12_fixtures_present_in_spec() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    for name in &[
        "pub-001-invalid-signature.json",
        "pub-003-superseded-target-mismatch.json",
        "pub-006-key-not-authorized.json",
        "fed-001-https-only.json",
        "fed-002-private-ip.json",
        "fed-003-loopback.json",
        "fed-004-link-local-imds.json",
        "fed-005-cross-authority-redirect.json",
        "fed-006-registry-did-mismatch.json",
    ] {
        let path = dir.join(name);
        assert!(path.exists(), "spec fixture '{name}' must exist");
    }
}

fn spec_root() -> Option<std::path::PathBuf> {
    let require = std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok();

    if let Ok(env) = std::env::var("ACDP_SPEC_DIR") {
        let p = std::path::PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
        assert!(
            !require,
            "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR '{}' does not exist",
            p.display()
        );
    } else {
        assert!(
            !require,
            "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR is not"
        );
    }

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(sibling) = manifest_dir
        .parent()
        .map(|p| p.join("agentcontextdistributionprotocol"))
    {
        if sibling.exists() {
            return Some(sibling);
        }
    }
    assert!(
        !require,
        "ACDP_REQUIRE_CONFORMANCE is set but no ACDP spec checkout could be located"
    );
    None
}
