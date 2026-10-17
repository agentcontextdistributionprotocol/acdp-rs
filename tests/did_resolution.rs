//! `did-001-fetch-failure-classification` (RFC-ACDP-0001 §5.11 step 3;
//! 0.5.0 consumer-revocation proposal, spec PR #77).
//!
//! The fixture is not yet in the spec checkout, so the scenarios are
//! bound here directly against the in-process TLS DID-document harness:
//!
//! | Scenario | DID host response                       | Expected                               |
//! |----------|-----------------------------------------|----------------------------------------|
//! | A        | 404, 410, 500 or 503                    | `key_resolution_unreachable` (transient) |
//! | B        | connection refused / TLS failure        | `key_resolution_unreachable` (transient) |
//! | C        | 200 with a body that is not JSON        | `key_resolution_failed` (permanent)    |
//!
//! Scenario D (no matching `verificationMethod` after one forced
//! re-fetch) lives with the forced-refresh tests in `tests/key_revocation.rs`.

mod common;

use acdp::did::WebResolver;
use acdp::error::AcdpError;
use acdp::registry::safe_http::SsrfPolicy;
use axum::{http::StatusCode, routing::get, Router};
use common::TlsTestServer;

fn resolver(pem: &[u8]) -> WebResolver {
    WebResolver::with_root_cert_pem(pem)
        .expect("resolver")
        .with_ssrf_policy(SsrfPolicy::allow_test_loopback())
}

async fn serve_status(status: StatusCode) -> TlsTestServer {
    TlsTestServer::start(Router::new().route(
        "/.well-known/did.json",
        get(move || async move { (status, "{\"error\":\"nope\"}") }),
    ))
    .await
}

#[tokio::test]
async fn did_001_a_non_2xx_is_transient_unreachable() {
    for status in [
        StatusCode::NOT_FOUND,
        StatusCode::GONE,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let server = serve_status(status).await;
        let err = resolver(&server.root_cert_pem)
            .resolve(&server.did())
            .await
            .expect_err("non-2xx must not resolve");
        assert!(
            matches!(err, AcdpError::KeyResolutionUnreachable(_)),
            "HTTP {status}: expected KeyResolutionUnreachable, got {err:?}"
        );
        assert!(err.is_transient(), "HTTP {status} must be transient");
    }
}

#[tokio::test]
async fn did_001_b_connection_refused_is_transient_unreachable() {
    let server = serve_status(StatusCode::OK).await;
    let did = server.did();
    let pem = server.root_cert_pem.clone();
    server.shutdown().await;
    let err = resolver(&pem).resolve(&did).await.expect_err("dead host");
    assert!(
        matches!(err, AcdpError::KeyResolutionUnreachable(_)),
        "connection refused: expected KeyResolutionUnreachable, got {err:?}"
    );
    assert!(err.is_transient());
}

#[tokio::test]
async fn did_001_b_tls_failure_is_transient_unreachable() {
    // The resolver does NOT trust the harness's self-signed root, so the
    // handshake fails.
    let server = serve_status(StatusCode::OK).await;
    let r = WebResolver::new().with_ssrf_policy(SsrfPolicy::allow_test_loopback());
    let err = r.resolve(&server.did()).await.expect_err("untrusted cert");
    assert!(
        matches!(err, AcdpError::KeyResolutionUnreachable(_)),
        "TLS failure: expected KeyResolutionUnreachable, got {err:?}"
    );
    assert!(err.is_transient());
}

#[tokio::test]
async fn did_001_c_non_json_200_is_permanent_failure() {
    let server = TlsTestServer::start(Router::new().route(
        "/.well-known/did.json",
        get(|| async { "<html>definitely not a DID document</html>" }),
    ))
    .await;
    let err = resolver(&server.root_cert_pem)
        .resolve(&server.did())
        .await
        .expect_err("non-JSON must not resolve");
    assert!(
        matches!(err, AcdpError::KeyResolution(_)),
        "non-JSON 200: expected KeyResolution, got {err:?}"
    );
    assert!(!err.is_transient());
}
