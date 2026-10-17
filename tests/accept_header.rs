//! Every `RegistryClient` request advertises the ACDP media type in
//! `Accept` (RFC-ACDP-0001 §5.1, `registries/media-types.md`;
//! acdp-rs#385 item 10) — on both the DNS-hook and the pinned client.

mod common;

use std::sync::{Arc, Mutex};

use acdp::client::{RegistryClient, ACDP_ACCEPT};
use acdp::registry::safe_http::SsrfPolicy;
use acdp::types::{CtxId, LineageId, SearchParams};
use axum::{
    extract::Request,
    http::{header, StatusCode},
    response::IntoResponse,
    Router,
};
use common::TlsTestServer;

type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// Records `(path, Accept)` for every request, then answers with an
/// ACDP error envelope (the client calls fail; only headers matter).
async fn recording_server() -> (TlsTestServer, Seen) {
    let seen: Seen = Arc::default();
    let s = seen.clone();
    let router = Router::new().fallback(move |req: Request| {
        let s = s.clone();
        async move {
            let accept = req
                .headers()
                .get(header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            s.lock()
                .unwrap()
                .push((req.uri().path().to_string(), accept));
            (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/acdp+json")],
                r#"{"error":{"code":"not_found","message":"recorded"}}"#,
            )
                .into_response()
        }
    });
    (TlsTestServer::start(router).await, seen)
}

async fn exercise(client: &RegistryClient) {
    let ctx = CtxId("acdp://localhost/9f1e2d3c-5a6b-4c7d-8e9f-0a1b2c3d4e5f".into());
    let lin = LineageId(
        "lin:sha256:6af6229c1c6a4a119695c77e47f6554941aebce3d25ba8567e2ae6ffbb6059cb".into(),
    );
    let _ = client.capabilities().await;
    let _ = client.retrieve(&ctx).await;
    let _ = client.retrieve_body(&ctx).await;
    let _ = client.lineage(&lin).await;
    let _ = client.current(&lin).await;
    let _ = client.search(&SearchParams::default()).await;
}

fn assert_all_accept(seen: &Seen) {
    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 6, "expected six reads, saw {seen:?}");
    for (path, accept) in seen.iter() {
        assert_eq!(accept.as_deref(), Some(ACDP_ACCEPT), "{path}");
    }
}

#[tokio::test]
async fn default_client_sends_acdp_accept_on_every_read() {
    let (server, seen) = recording_server().await;
    let client = RegistryClient::with_root_cert_pem(&server.base_url(), &server.root_cert_pem)
        .expect("client");
    exercise(&client).await;
    assert_all_accept(&seen);
}

#[tokio::test]
async fn pinned_client_sends_acdp_accept_on_every_read() {
    let (server, seen) = recording_server().await;
    let client = RegistryClient::builder(&server.base_url())
        .pinned(true)
        .ssrf_policy(SsrfPolicy::allow_test_loopback())
        .root_cert_pem(server.root_cert_pem.clone())
        .build()
        .await
        .expect("pinned client");
    exercise(&client).await;
    assert_all_accept(&seen);
}

#[test]
fn accept_prefers_the_canonical_media_type() {
    assert!(ACDP_ACCEPT.starts_with("application/acdp+json"));
}
