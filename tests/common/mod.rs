//! Test-only helpers shared across integration test crates.
//!
//! Each file under `tests/` compiles as its own integration test crate;
//! shared modules live in `tests/common/` and are included via
//! `mod common;` from any file that needs them. (Anything compiled as a
//! standalone test crate must live directly under `tests/`; subdirectories
//! are intentionally exempt.)
//!
//! The TLS DID server here unblocks the conformance fixtures
//! `pub-001 / pub-003 / pub-006` and `fed-001..006` — all of which need
//! a real HTTPS endpoint serving a self-signed certificate that the
//! consumer is configured to trust.

#![allow(dead_code)] // each consumer uses a subset of these helpers

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{response::Json, routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use tokio::task::JoinHandle;

// ── TLS server ────────────────────────────────────────────────────────────────

/// In-process HTTPS server backed by an auto-generated self-signed cert.
///
/// The cert covers `localhost` only — the server binds to `127.0.0.1:0`
/// (kernel-assigned port) and the cert's SAN list contains exactly
/// `localhost`, so any URL of the form `https://localhost:<port>/…`
/// validates under TLS when the consumer's HTTP client trusts the
/// returned `root_cert_pem`.
pub struct TlsTestServer {
    pub addr: SocketAddr,
    pub root_cert_pem: Vec<u8>,
    _handle: JoinHandle<()>,
}

impl TlsTestServer {
    /// Start a TLS server serving the given router. Runs on the current
    /// Tokio runtime; spawns a background task that holds the server.
    pub async fn start(router: Router) -> Self {
        Self::start_with(|_port| router).await
    }

    /// Start a TLS server, binding to a kernel-assigned port and giving
    /// the bound port to `build_router` so it can construct documents
    /// (e.g. a `did:web:localhost%3A<port>` DID document) that reference
    /// the actual address. The router is consumed after the port is
    /// known but before the server begins serving.
    pub async fn start_with<F>(build_router: F) -> Self
    where
        F: FnOnce(u16) -> Router,
    {
        // rustls 0.23 requires a crypto provider to be installed
        // process-wide before the first TLS handshake. Install once
        // per process — subsequent attempts return Err which we ignore.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let cert_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed cert");
        let cert_pem = cert_key.cert.pem().into_bytes();
        // rcgen 0.14 renamed the field back to `signing_key` (it was
        // `key_pair` in 0.13, `signing_key` in 0.12). Both APIs return
        // the PEM-encoded private key.
        let key_pem = cert_key.signing_key.serialize_pem().into_bytes();
        let config = RustlsConfig::from_pem(cert_pem.clone(), key_pem)
            .await
            .expect("rustls config");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind random port");
        // Tokio now refuses to register a blocking socket from inside
        // an async context (tokio-rs/tokio#7172); axum-server 0.8's
        // `from_tcp_rustls` converts this std listener into a Tokio one
        // inside the spawned task below, so it must already be
        // non-blocking before we hand it off.
        listener
            .set_nonblocking(true)
            .expect("set listener non-blocking");
        let addr = listener.local_addr().expect("local_addr");
        let router = build_router(addr.port());

        let handle = tokio::spawn(async move {
            // axum-server 0.8 made `from_tcp_rustls` fallible (it now
            // configures the rustls acceptor eagerly instead of lazily).
            let server =
                axum_server::from_tcp_rustls(listener, config).expect("configure rustls acceptor");
            let _ = server.serve(router.into_make_service()).await;
        });

        // Wait until the kernel actually accepts a TCP connection on
        // the bound port. `axum-server` does not expose a ready signal,
        // so a tight loop with a hard ceiling is the most robust way
        // to avoid timing flakes in CI. Replaces an earlier
        // `sleep(50ms)` that was just-barely-enough on a fast laptop.
        Self::wait_until_ready(addr, std::time::Duration::from_secs(5)).await;

        Self {
            addr,
            root_cert_pem: cert_pem,
            _handle: handle,
        }
    }

    /// Poll the bound address with `TcpStream::connect` until it
    /// accepts a connection, or `timeout` elapses. Panics on timeout —
    /// in test context, that's the correct loud-fail behavior.
    async fn wait_until_ready(addr: SocketAddr, timeout: std::time::Duration) {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            // `tokio::net::TcpStream::connect` returns Ok as soon as the
            // listener accepts — no TLS handshake, just the raw socket
            // accept. That's exactly the signal we need: the listener
            // task has been scheduled and is in `accept()`.
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!("TlsTestServer at {addr} did not accept connections within {timeout:?}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// Abort the background task serving this endpoint and wait until
    /// the port genuinely stops accepting connections.
    ///
    /// Used to simulate a `did:web` host going from reachable (at
    /// publish time) to truly unreachable (at query time) — a real
    /// connection refusal (`AcdpError::KeyResolutionUnreachable`,
    /// transient), as opposed to a 404 (host reachable, route just
    /// missing — `AcdpError::KeyResolution`, permanent). Issue #248
    /// Phase 1's discovery tests need that distinction, which a merely-
    /// unregistered route cannot produce on its own since the rest of
    /// the harness (search/retrieve/lineage) is served by a different,
    /// still-live `TlsTestServer`.
    ///
    /// # Panics
    ///
    /// Panics if the port is still accepting connections 5s after
    /// `abort()` — in test context, that is the correct loud-fail
    /// behavior rather than a false pass on a still-live server.
    pub async fn shutdown(self) {
        self._handle.abort();
        // `abort()` only requests cancellation; the task (and the
        // listener it owns) is actually dropped at its next await
        // point, asynchronously. Poll rather than assume a fixed delay
        // is long enough — mirrors `wait_until_ready`'s style, inverted.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if tokio::net::TcpStream::connect(self.addr).await.is_err() {
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!(
                    "TlsTestServer at {} did not stop accepting connections within 5s of shutdown()",
                    self.addr
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// `localhost:<port>` — host portion only.
    pub fn host(&self) -> String {
        format!("localhost:{}", self.addr.port())
    }

    /// `did:web:localhost%3A<port>` — for use as agent_id / DID URL prefix.
    ///
    /// The colon between host and port MUST be percent-encoded in a
    /// `did:web` identifier per the spec; otherwise the DID parser
    /// reads `:<port>` as a path component.
    pub fn did(&self) -> String {
        format!("did:web:localhost%3A{}", self.addr.port())
    }

    /// `https://localhost:<port>` — base URL for a `RegistryClient`.
    pub fn base_url(&self) -> String {
        format!("https://localhost:{}", self.addr.port())
    }
}

// ── DID document helpers ──────────────────────────────────────────────────────

/// Build a DID document containing a single Ed25519 verification method
/// authorized in `assertionMethod`.
///
/// The returned JSON object can be plugged directly into
/// [`did_doc_router`] to serve at `/.well-known/did.json`.
pub fn ed25519_did_doc(did: &str, key_fragment: &str, pub_key: &[u8; 32]) -> Value {
    let jwk_x = URL_SAFE_NO_PAD.encode(pub_key);
    let vm_id = format!("{did}#{key_fragment}");
    json!({
        "id": did,
        "verificationMethod": [{
            "id": vm_id,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": jwk_x,
            }
        }],
        "assertionMethod": [vm_id],
    })
}

/// Like [`ed25519_did_doc`] but the verification method is NOT listed
/// in `assertionMethod`. Used for pub-006: key is resolvable but not
/// authorized to sign.
pub fn ed25519_did_doc_without_assertion(
    did: &str,
    key_fragment: &str,
    pub_key: &[u8; 32],
) -> Value {
    let jwk_x = URL_SAFE_NO_PAD.encode(pub_key);
    let vm_id = format!("{did}#{key_fragment}");
    json!({
        "id": did,
        "verificationMethod": [{
            "id": vm_id,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": jwk_x,
            }
        }],
        "assertionMethod": [],
    })
}

/// Build a router that serves `did_doc` at the well-known DID-document
/// path. The TLS server forwards the path back to `WebResolver`'s
/// computed URL: `did:web:localhost%3A<port>` ⇒
/// `https://localhost:<port>/.well-known/did.json`.
pub fn did_doc_router(did_doc: Value) -> Router {
    let doc = Arc::new(did_doc);
    Router::new().route(
        "/.well-known/did.json",
        get(move || {
            let doc = doc.clone();
            async move { Json((*doc).clone()) }
        }),
    )
}

/// Build a minimal capabilities document with the given `registry_did`.
/// All other fields are the v0.1.0 mandatory minimum.
pub fn minimal_capabilities(registry_did: &str) -> Value {
    json!({
        "acdp_version": "0.1.0",
        "registry_did": registry_did,
        "supported_signature_algorithms": ["ed25519"],
        "supported_did_methods": ["did:web"],
        "profiles": ["acdp-registry-core"],
        "limits": {
            "max_payload_bytes": 1_048_576,
            "max_embedded_bytes": 65_536,
        },
        "read_authentication_methods": [],
        "anonymous_public_reads": true,
        "supports_idempotency_key": false,
    })
}

/// Router that serves a JSON capabilities document at
/// `/.well-known/acdp.json` — the path a `RegistryClient` queries first.
pub fn capabilities_router(capabilities: Value) -> Router {
    let caps = Arc::new(capabilities);
    Router::new().route(
        "/.well-known/acdp.json",
        get(move || {
            let caps = caps.clone();
            async move { Json((*caps).clone()) }
        }),
    )
}
