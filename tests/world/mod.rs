//! Shared in-process registry world for the 0.15.0 consumer-verification
//! suites (`discovery_outcomes.rs`, `receipt_bindings.rs`).
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use crate::common::TlsTestServer;
use acdp::client::RegistryClient;
use acdp::crypto::SigningKey;
use acdp::did::WebResolver;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::registry::{InMemoryStore, RegistryServer, RegistryStore as _};
use acdp::types::receipt::ReceiptSigner;
use acdp::types::{AgentDid, ContextType, FullContext, Visibility};
use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};

pub const REGISTRY_AUTHORITY: &str = "localhost";
pub const REGISTRY_DID: &str = "did:web:localhost";
pub const RECEIPT_SEED: [u8; 32] = [0x11u8; 32];
pub const AGENT: &str = "did:web:localhost:agent";

pub const K1: [u8; 32] = [0u8; 32];
pub const K1_FP: &str = "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070";
pub const K2: [u8; 32] = [0x42u8; 32];
pub const K3: [u8; 32] = [0x33u8; 32];

pub fn caps() -> acdp::types::CapabilitiesDocument {
    use acdp::types::capabilities::Limits;
    acdp::types::CapabilitiesDocument {
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
            change_retention_seconds: None,
            max_change_filters: None,
            max_changes_page: None,
            max_subscriptions_per_requester: None,
            max_reads_per_minute: None,
            max_anonymous_reads_per_minute: None,
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        supports_idempotency_key: false,
        extensions: Default::default(),
    }
}

/// Status of the registry's receipt key in its DID document.
#[derive(Clone, Copy)]
pub enum ReceiptKey {
    /// In `verificationMethod` and `assertionMethod`.
    Current,
    /// In `verificationMethod` only.
    Historical,
    /// Absent from `verificationMethod`.
    Absent,
}

/// The registry DID document with `#receipt-key-1` in `status`.
pub fn registry_doc(status: ReceiptKey) -> Value {
    let vm = json!({
        "id": format!("{REGISTRY_DID}#receipt-key-1"),
        "type": "JsonWebKey2020",
        "controller": REGISTRY_DID,
        "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&RECEIPT_SEED).verifying_key_bytes()),
        }
    });
    let (vms, am) = match status {
        ReceiptKey::Current => (vec![vm], vec![format!("{REGISTRY_DID}#receipt-key-1")]),
        ReceiptKey::Historical => (vec![vm], vec![]),
        ReceiptKey::Absent => (vec![], vec![]),
    };
    json!({ "id": REGISTRY_DID, "verificationMethod": vms, "assertionMethod": am })
}

/// Producer DID document with `keys` in `verificationMethod` and the
/// `assertion` subset in `assertionMethod`.
pub fn producer_doc(keys: &[(&str, [u8; 32])], assertion: &[&str]) -> Value {
    let vms: Vec<Value> = keys
        .iter()
        .map(|(frag, seed)| {
            json!({
                "id": format!("{AGENT}#{frag}"),
                "type": "JsonWebKey2020",
                "controller": AGENT,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(seed).verifying_key_bytes()),
                }
            })
        })
        .collect();
    let am: Vec<String> = assertion.iter().map(|f| format!("{AGENT}#{f}")).collect();
    json!({ "id": AGENT, "verificationMethod": vms, "assertionMethod": am })
}

/// Every request's path and `Authorization` header, in arrival order.
pub type AuthLog = Arc<RwLock<Vec<(String, Option<String>)>>>;

pub struct World {
    pub tls: TlsTestServer,
    pub server: RegistryServer<InMemoryStore>,
    pub producer_doc: Arc<RwLock<Value>>,
    /// The registry DID document (receipt key status is mutable).
    pub registry_doc: Arc<RwLock<Value>>,
    pub registry_did_hits: Arc<AtomicUsize>,
    /// HTTP status the producer DID host answers with (200 = serve doc).
    pub did_status: Arc<AtomicU16>,
    pub did_hits: Arc<AtomicUsize>,
    pub retrieve_hits: Arc<AtomicUsize>,
    pub contexts: Arc<RwLock<HashMap<String, Value>>>,
    pub matches: Arc<RwLock<Vec<Value>>>,
    pub lineages: Arc<RwLock<HashMap<String, Value>>>,
    /// When set, `/contexts/{id}` serves contexts without `registry_receipt`.
    pub strip_receipts: Arc<std::sync::atomic::AtomicBool>,
    /// How `/contexts/search` answers.
    pub search_mode: Arc<RwLock<SearchMode>>,
    pub search_hits: Arc<AtomicUsize>,
    /// Every `/contexts/{id}` id served, in order.
    pub retrieved: Arc<RwLock<Vec<String>>>,
    /// When set, `/contexts*` and `/lineages*` answer 403 `not_authorized`
    /// unless the request carries `Authorization: Bearer <this>`
    /// (RFC-ACDP-0008 §6.2, `anonymous_public_reads: false`).
    pub required_bearer: Arc<RwLock<Option<String>>>,
    /// `(path, Authorization header)` of every request, in order.
    pub auth_seen: AuthLog,
    /// Queued `GET /changes` answers `(status, body)`, served in order;
    /// when empty, an empty page at cursor `end`.
    pub changes_queue: Arc<RwLock<std::collections::VecDeque<(u16, Value)>>>,
    /// The raw query string of every `GET /changes`, in order.
    pub changes_queries: Arc<RwLock<Vec<String>>>,
}

/// How the world's `/contexts/search` route answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchMode {
    /// Serve the published revocations, one page.
    Normal,
    /// Answer every search with this HTTP status and an ACDP error body.
    Status(u16),
    /// Serve the matches with a `next_cursor` on every page, forever —
    /// drives the page cap (truncation).
    Paginate,
}

impl World {
    pub async fn start(initial_doc: Value) -> Self {
        let producer_doc = Arc::new(RwLock::new(initial_doc));
        let did_status = Arc::new(AtomicU16::new(200));
        let did_hits = Arc::new(AtomicUsize::new(0));
        let retrieve_hits = Arc::new(AtomicUsize::new(0));
        let contexts: Arc<RwLock<HashMap<String, Value>>> = Arc::default();
        let matches: Arc<RwLock<Vec<Value>>> = Arc::default();
        let lineages: Arc<RwLock<HashMap<String, Value>>> = Arc::default();
        let strip_receipts = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let registry_doc = Arc::new(RwLock::new(registry_doc(ReceiptKey::Current)));
        let registry_did_hits = Arc::new(AtomicUsize::new(0));
        let search_mode = Arc::new(RwLock::new(SearchMode::Normal));
        let search_hits = Arc::new(AtomicUsize::new(0));
        let retrieved: Arc<RwLock<Vec<String>>> = Arc::default();
        let required_bearer: Arc<RwLock<Option<String>>> = Arc::default();
        let auth_seen: AuthLog = Arc::default();
        let changes_queue: Arc<RwLock<std::collections::VecDeque<(u16, Value)>>> = Arc::default();
        let changes_queries: Arc<RwLock<Vec<String>>> = Arc::default();

        let router = Router::new()
            .route(
                "/.well-known/did.json",
                get({
                    let (doc, hits) = (registry_doc.clone(), registry_did_hits.clone());
                    move || {
                        let (doc, hits) = (doc.clone(), hits.clone());
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            Json(doc.read().unwrap().clone())
                        }
                    }
                }),
            )
            .route(
                "/agent/did.json",
                get({
                    let (doc, status, hits) =
                        (producer_doc.clone(), did_status.clone(), did_hits.clone());
                    move || {
                        let (doc, status, hits) = (doc.clone(), status.clone(), hits.clone());
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            let code = status.load(Ordering::SeqCst);
                            if code == 200 {
                                Json(doc.read().unwrap().clone()).into_response()
                            } else {
                                StatusCode::from_u16(code).unwrap().into_response()
                            }
                        }
                    }
                }),
            )
            .route("/.well-known/acdp.json", get(|| async { Json(caps()) }))
            // Publish endpoint: only the `Authorization` log matters, so it
            // always refuses.
            .route(
                "/contexts",
                post(|| async {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": { "code": "internal_error", "message": "test" } })),
                    )
                }),
            )
            .route(
                "/contexts/search",
                get({
                    let (matches, mode, hits) =
                        (matches.clone(), search_mode.clone(), search_hits.clone());
                    move || {
                        let (matches, mode, hits) = (matches.clone(), mode.clone(), hits.clone());
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            let matches = matches.read().unwrap().clone();
                            let mode = *mode.read().unwrap();
                            match mode {
                                SearchMode::Normal => {
                                    Json(json!({ "matches": matches })).into_response()
                                }
                                SearchMode::Paginate => Json(json!({
                                    "matches": matches,
                                    "next_cursor": "more",
                                }))
                                .into_response(),
                                SearchMode::Status(code) => {
                                    let wire = match code {
                                        403 => "not_authorized",
                                        501 => "not_implemented",
                                        _ => "internal_error",
                                    };
                                    (
                                        StatusCode::from_u16(code).unwrap(),
                                        Json(
                                            json!({ "error": { "code": wire, "message": "test" } }),
                                        ),
                                    )
                                        .into_response()
                                }
                            }
                        }
                    }
                }),
            )
            .route(
                "/contexts/{id}",
                get({
                    let (contexts, hits, strip, log) = (
                        contexts.clone(),
                        retrieve_hits.clone(),
                        strip_receipts.clone(),
                        retrieved.clone(),
                    );
                    move |axum::extract::Path(id): axum::extract::Path<String>| {
                        let (contexts, hits, strip, log) =
                            (contexts.clone(), hits.clone(), strip.clone(), log.clone());
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            log.write().unwrap().push(id.clone());
                            let mut v = contexts.read().unwrap().get(&id).cloned().expect("known");
                            if strip.load(Ordering::SeqCst) {
                                v.as_object_mut().unwrap().remove("registry_receipt");
                            }
                            Json(v)
                        }
                    }
                }),
            )
            .route(
                "/changes",
                get({
                    let (queue, queries) = (changes_queue.clone(), changes_queries.clone());
                    move |uri: axum::http::Uri| {
                        let (queue, queries) = (queue.clone(), queries.clone());
                        async move {
                            queries
                                .write()
                                .unwrap()
                                .push(uri.query().unwrap_or("").to_string());
                            let (code, body) = queue.write().unwrap().pop_front().unwrap_or((
                                200,
                                json!({ "changes": [], "next_cursor": "end", "has_more": false }),
                            ));
                            (StatusCode::from_u16(code).unwrap(), Json(body)).into_response()
                        }
                    }
                }),
            )
            .route(
                "/lineages/{id}",
                get({
                    let lineages = lineages.clone();
                    move |axum::extract::Path(id): axum::extract::Path<String>| {
                        let lineages = lineages.clone();
                        async move {
                            Json(
                                lineages
                                    .read()
                                    .unwrap()
                                    .get(&id)
                                    .cloned()
                                    .unwrap_or(json!([])),
                            )
                        }
                    }
                }),
            )
            .layer(axum::middleware::from_fn({
                let (required, seen) = (required_bearer.clone(), auth_seen.clone());
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    let (required, seen) = (required.clone(), seen.clone());
                    async move {
                        let path = req.uri().path().to_string();
                        let auth = req
                            .headers()
                            .get(axum::http::header::AUTHORIZATION)
                            .map(|v| v.to_str().unwrap().to_string());
                        seen.write().unwrap().push((path.clone(), auth.clone()));
                        let gated = path.starts_with("/contexts") || path.starts_with("/lineages");
                        let want = required.read().unwrap().clone();
                        match want {
                            Some(token)
                                if gated && auth.as_deref() != Some(&format!("Bearer {token}")) =>
                            {
                                (
                                    StatusCode::FORBIDDEN,
                                    Json(json!({ "error": {
                                        "code": "not_authorized",
                                        "message": "bearer required",
                                    }})),
                                )
                                    .into_response()
                            }
                            _ => next.run(req).await,
                        }
                    }
                }
            }));
        let tls = TlsTestServer::start(router).await;

        let server = RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY)
            .expect("server")
            .with_receipt_signer(
                ReceiptSigner::new(
                    SigningKey::from_bytes(&RECEIPT_SEED),
                    REGISTRY_DID,
                    format!("{REGISTRY_DID}#receipt-key-1"),
                )
                .expect("signer"),
            )
            .expect("receipt signer accepted");

        World {
            tls,
            server,
            producer_doc,
            registry_doc,
            registry_did_hits,
            did_status,
            did_hits,
            retrieve_hits,
            contexts,
            matches,
            lineages,
            strip_receipts,
            search_mode,
            search_hits,
            retrieved,
            required_bearer,
            auth_seen,
            changes_queue,
            changes_queries,
        }
    }

    /// Queue a `GET /changes` answer.
    pub fn queue_changes(&self, status: u16, body: Value) {
        self.changes_queue
            .write()
            .unwrap()
            .push_back((status, body));
    }

    /// The query strings `GET /changes` was called with.
    pub fn changes_queries(&self) -> Vec<String> {
        self.changes_queries.read().unwrap().clone()
    }

    /// Gate reads behind `Authorization: Bearer <token>` (`None` = open).
    pub fn require_bearer(&self, token: Option<&str>) {
        *self.required_bearer.write().unwrap() = token.map(str::to_string);
    }

    /// The `Authorization` headers seen on requests whose path starts
    /// with `prefix`.
    pub fn auth_headers_for(&self, prefix: &str) -> Vec<Option<String>> {
        self.auth_seen
            .read()
            .unwrap()
            .iter()
            .filter(|(p, _)| p.starts_with(prefix))
            .map(|(_, a)| a.clone())
            .collect()
    }

    pub fn set_search_mode(&self, mode: SearchMode) {
        *self.search_mode.write().unwrap() = mode;
    }

    /// How many times `/contexts/{ctx_id}` was served.
    pub fn retrievals_of(&self, ctx_id: &str) -> usize {
        self.retrieved
            .read()
            .unwrap()
            .iter()
            .filter(|id| id.as_str() == ctx_id || ctx_id.ends_with(&format!("/{id}")))
            .count()
    }

    pub fn search_hits(&self) -> usize {
        self.search_hits.load(Ordering::SeqCst)
    }

    pub fn set_doc(&self, doc: Value) {
        *self.producer_doc.write().unwrap() = doc;
    }

    pub fn set_receipt_key(&self, status: ReceiptKey) {
        *self.registry_doc.write().unwrap() = registry_doc(status);
    }

    /// Mutate the context served at `/contexts/{ctx_id}`.
    pub fn tamper(&self, ctx_id: &str, f: impl FnOnce(&mut Value)) {
        f(self
            .contexts
            .write()
            .unwrap()
            .get_mut(ctx_id)
            .expect("known"));
    }

    pub fn resolver(&self) -> WebResolver {
        WebResolver::with_test_endpoint(&self.tls.root_cert_pem, "localhost", self.tls.addr)
            .expect("resolver")
    }

    pub fn client(&self) -> RegistryClient {
        RegistryClient::with_test_endpoint(
            &format!("https://{REGISTRY_AUTHORITY}"),
            self.tls.addr,
            &self.tls.root_cert_pem,
        )
        .expect("client")
    }

    /// Publish (with receipt) a context signed by `frag`/`seed`; the
    /// current producer document must authorize it. Revocations are
    /// listed in search and served from `/lineages/{id}` WITHOUT their
    /// receipt (as lineage listings may be).
    pub async fn publish(
        &self,
        frag: &str,
        seed: [u8; 32],
        context_type: ContextType,
        metadata: Option<Value>,
    ) -> FullContext {
        let producer = Producer::new(
            SigningKey::from_bytes(&seed),
            AgentDid::new(AGENT),
            format!("{AGENT}#{frag}"),
        );
        let mut b = producer
            .publish_request()
            .acdp_version("0.3.0")
            .title(format!("signed by {frag}"))
            .context_type(context_type.clone())
            .visibility(Visibility::Public);
        if let Some(m) = metadata {
            b = b.metadata(m);
        }
        let req = b.build().expect("build");
        let resp = self
            .server
            .publish_verified(&req, None, &self.resolver())
            .await
            .expect("publish");
        let full = self
            .server
            .store()
            .get(&resp.ctx_id)
            .expect("get")
            .expect("present");
        let v = serde_json::to_value(&full).unwrap();
        assert!(v.get("registry_receipt").is_some(), "receipt minted");
        self.contexts
            .write()
            .unwrap()
            .insert(full.body.ctx_id.as_str().to_string(), v.clone());
        if context_type == ContextType::KeyRevocation {
            self.matches.write().unwrap().push(json!({
                "ctx_id": full.body.ctx_id.as_str(),
                "lineage_id": full.body.lineage_id.as_str(),
                "agent_id": AGENT,
                "title": full.body.title,
                "type": "key-revocation",
                "created_at": "2026-05-02T08:00:00.000Z",
                "status": "active",
                "visibility": "public",
            }));
            let mut member = v.clone();
            member.as_object_mut().unwrap().remove("registry_receipt");
            self.lineages
                .write()
                .unwrap()
                .insert(full.body.lineage_id.as_str().to_string(), json!([member]));
        }
        serde_json::from_value(v).unwrap()
    }

    /// Publish (with receipt) version `previous.version + 1` of
    /// `previous`'s lineage, signed by `frag`/`seed`.
    pub async fn publish_next(
        &self,
        previous: &FullContext,
        frag: &str,
        seed: [u8; 32],
    ) -> FullContext {
        let producer = Producer::new(
            SigningKey::from_bytes(&seed),
            AgentDid::new(AGENT),
            format!("{AGENT}#{frag}"),
        );
        let req = producer
            .supersede_body(&previous.body)
            .acdp_version("0.3.0")
            .title(format!("v{} signed by {frag}", previous.body.version + 1))
            .context_type(previous.body.context_type.clone())
            .visibility(Visibility::Public)
            .build()
            .expect("build");
        let resp = self
            .server
            .publish_verified(&req, None, &self.resolver())
            .await
            .expect("publish");
        let full = self
            .server
            .store()
            .get(&resp.ctx_id)
            .expect("get")
            .expect("present");
        let v = serde_json::to_value(&full).unwrap();
        self.contexts
            .write()
            .unwrap()
            .insert(full.body.ctx_id.as_str().to_string(), v.clone());
        serde_json::from_value(v).unwrap()
    }

    pub async fn publish_revocation_of_k1(&self, frag: &str, seed: [u8; 32]) -> FullContext {
        self.publish(
            frag,
            seed,
            ContextType::KeyRevocation,
            Some(json!({
                "revoked_key_fingerprint": K1_FP,
                "compromised_since": "2026-05-01T00:00:00.000Z",
                "reason": "test compromise",
            })),
        )
        .await
    }

    pub fn did_hits(&self) -> usize {
        self.did_hits.load(Ordering::SeqCst)
    }
}

pub fn agent() -> AgentDid {
    AgentDid::new(AGENT)
}

pub fn is_unverifiable(e: &AcdpError) -> bool {
    match e {
        AcdpError::RevocationCandidateUnverifiable(_) => true,
        AcdpError::RevocationUnknown { source, .. } => is_unverifiable(source),
        _ => false,
    }
}
