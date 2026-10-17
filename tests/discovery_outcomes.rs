//! RFC-ACDP-0014 §8 "Discovery outcome classes" and RFC-ACDP-0001 §5.11
//! "Caching" (0.5.0) — the rev-005 A–E, rot-002 and did-001 D scenarios.
//!
//! One in-process TLS registry serves the registry DID document, a
//! *mutable* producer DID document (so a test can rotate keys after the
//! consumer cached the old document), a mutable DID-host HTTP status,
//! search, retrieve and lineage. Every revocation is a real, signed,
//! receipt-bearing context published through `RegistryServer`.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use acdp::client::{find_revocations, RegistryClient};
use acdp::crypto::SigningKey;
use acdp::did::WebResolver;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::registry::{InMemoryStore, RegistryServer, RegistryStore as _};
use acdp::types::receipt::ReceiptSigner;
use acdp::types::{AgentDid, Body, ContextType, FullContext, Visibility};
use acdp::verify::Verifier;
use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use common::{ed25519_did_doc, TlsTestServer};
use serde_json::{json, Value};

const REGISTRY_AUTHORITY: &str = "localhost";
const REGISTRY_DID: &str = "did:web:localhost";
const RECEIPT_SEED: [u8; 32] = [0x11u8; 32];
const AGENT: &str = "did:web:localhost:agent";

const K1: [u8; 32] = [0u8; 32];
const K1_FP: &str = "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070";
const K2: [u8; 32] = [0x42u8; 32];
const K3: [u8; 32] = [0x33u8; 32];

fn caps() -> acdp::types::CapabilitiesDocument {
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
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        supports_idempotency_key: false,
        extensions: Default::default(),
    }
}

/// Producer DID document with `keys` in `verificationMethod` and the
/// `assertion` subset in `assertionMethod`.
fn producer_doc(keys: &[(&str, [u8; 32])], assertion: &[&str]) -> Value {
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

struct World {
    tls: TlsTestServer,
    server: RegistryServer<InMemoryStore>,
    producer_doc: Arc<RwLock<Value>>,
    /// HTTP status the producer DID host answers with (200 = serve doc).
    did_status: Arc<AtomicU16>,
    did_hits: Arc<AtomicUsize>,
    retrieve_hits: Arc<AtomicUsize>,
    contexts: Arc<RwLock<HashMap<String, Value>>>,
    matches: Arc<RwLock<Vec<Value>>>,
    lineages: Arc<RwLock<HashMap<String, Value>>>,
    /// When set, `/contexts/{id}` serves contexts without `registry_receipt`.
    strip_receipts: Arc<std::sync::atomic::AtomicBool>,
}

impl World {
    async fn start(initial_doc: Value) -> Self {
        let producer_doc = Arc::new(RwLock::new(initial_doc));
        let did_status = Arc::new(AtomicU16::new(200));
        let did_hits = Arc::new(AtomicUsize::new(0));
        let retrieve_hits = Arc::new(AtomicUsize::new(0));
        let contexts: Arc<RwLock<HashMap<String, Value>>> = Arc::default();
        let matches: Arc<RwLock<Vec<Value>>> = Arc::default();
        let lineages: Arc<RwLock<HashMap<String, Value>>> = Arc::default();
        let strip_receipts = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let registry_doc = ed25519_did_doc(
            REGISTRY_DID,
            "receipt-key-1",
            &SigningKey::from_bytes(&RECEIPT_SEED).verifying_key_bytes(),
        );

        let router = Router::new()
            .route(
                "/.well-known/did.json",
                get(move || {
                    let d = registry_doc.clone();
                    async move { Json(d) }
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
            .route(
                "/contexts/search",
                get({
                    let matches = matches.clone();
                    move || {
                        let matches = matches.clone();
                        async move { Json(json!({ "matches": matches.read().unwrap().clone() })) }
                    }
                }),
            )
            .route(
                "/contexts/{id}",
                get({
                    let (contexts, hits, strip) = (
                        contexts.clone(),
                        retrieve_hits.clone(),
                        strip_receipts.clone(),
                    );
                    move |axum::extract::Path(id): axum::extract::Path<String>| {
                        let (contexts, hits, strip) =
                            (contexts.clone(), hits.clone(), strip.clone());
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
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
            );
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
            did_status,
            did_hits,
            retrieve_hits,
            contexts,
            matches,
            lineages,
            strip_receipts,
        }
    }

    fn set_doc(&self, doc: Value) {
        *self.producer_doc.write().unwrap() = doc;
    }

    fn resolver(&self) -> WebResolver {
        WebResolver::with_test_endpoint(&self.tls.root_cert_pem, "localhost", self.tls.addr)
            .expect("resolver")
    }

    fn client(&self) -> RegistryClient {
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
    async fn publish(
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

    async fn publish_revocation_of_k1(&self, frag: &str, seed: [u8; 32]) -> FullContext {
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

    fn did_hits(&self) -> usize {
        self.did_hits.load(Ordering::SeqCst)
    }
}

fn agent() -> AgentDid {
    AgentDid::new(AGENT)
}

fn is_unverifiable(e: &AcdpError) -> bool {
    match e {
        AcdpError::RevocationCandidateUnverifiable(_) => true,
        AcdpError::RevocationDiscoveryFailed { source } => is_unverifiable(source),
        _ => false,
    }
}

// ── rot-002 / did-001 D: refresh-then-retry on a stale cache ──────────

/// rot-002: the consumer cached a document holding only K1; P adds K2
/// and publishes a K2-signed context. Verification succeeds after
/// exactly one forced re-fetch.
#[tokio::test]
async fn rot_002_new_key_verifies_after_one_forced_refetch() {
    let w = World::start(producer_doc(&[("key-1", K1)], &["key-1"])).await;
    let resolver = w.resolver();
    resolver.resolve(AGENT).await.expect("prime cache");
    let primed = w.did_hits();

    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ));
    let ctx = w.publish("key-2", K2, ContextType::Analysis, None).await;

    let before = w.did_hits();
    assert_eq!(before, primed + 1, "publish-side resolver fetched once");
    Verifier::new(&resolver)
        .verify_context(&ctx)
        .await
        .expect("K2 verifies after refresh");
    assert_eq!(w.did_hits(), before + 1, "exactly one forced re-fetch");

    // The refreshed document is cached: a second verification is free.
    Verifier::new(&resolver).verify_context(&ctx).await.unwrap();
    assert_eq!(w.did_hits(), before + 1);
}

/// rot-002 (step 5): a key present but not yet in `assertionMethod` in
/// the cached document is re-checked against a fresh copy too.
#[tokio::test]
async fn rot_002_assertion_added_after_caching_verifies() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    let ctx = w.publish("key-2", K2, ContextType::Analysis, None).await;

    let resolver = w.resolver();
    w.set_doc(producer_doc(&[("key-1", K1), ("key-2", K2)], &["key-1"]));
    resolver
        .resolve(AGENT)
        .await
        .expect("cache the not-yet-authorized doc");
    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ));

    Verifier::new(&resolver)
        .verify_context(&ctx)
        .await
        .expect("assertionMethod re-checked on a fresh copy");
}

/// did-001 D: the key is absent even after the forced re-fetch — a
/// permanent `key_resolution_failed`, after exactly one re-fetch.
#[tokio::test]
async fn did_001_d_key_absent_after_refetch_is_permanent() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    let ctx = w.publish("key-2", K2, ContextType::Analysis, None).await;
    w.set_doc(producer_doc(&[("key-1", K1)], &["key-1"]));
    let resolver = w.resolver();
    resolver.resolve(AGENT).await.unwrap();
    let before = w.did_hits();

    let err = Verifier::new(&resolver)
        .verify_context(&ctx)
        .await
        .unwrap_err();
    assert!(matches!(err, AcdpError::KeyResolution(_)), "{err:?}");
    assert!(!err.is_transient());
    assert_eq!(w.did_hits(), before + 1, "one forced re-fetch, no more");
}

/// The per-DID rate limit: once a forced re-fetch was spent, a key
/// absent from the (now stale) cached copy is NOT reported as absent —
/// it is transient (`key_resolution_unreachable`). This is the
/// attacker-burns-the-refresh-slot case: a permanent verdict here would
/// let discovery silently drop a revocation signed by a just-added key.
#[tokio::test]
async fn rate_limited_refetch_reports_absent_key_as_transient() {
    let w = World::start(producer_doc(&[("key-1", K1)], &["key-1"])).await;
    let resolver = w.resolver();
    resolver.resolve(AGENT).await.unwrap();

    // Attacker spends the forced-refresh slot with a bogus fragment.
    let bogus = resolver
        .resolve_with_fragment(AGENT, "bogus", std::time::Instant::now())
        .await
        .unwrap_err();
    assert!(matches!(bogus, AcdpError::KeyResolution(_)), "{bogus:?}");

    // Producer adds K2 and publishes; the consumer's copy is stale and
    // the slot is spent.
    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ));
    let ctx = w.publish("key-2", K2, ContextType::Analysis, None).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    let before = w.did_hits();
    let err = Verifier::new(&resolver)
        .verify_context(&ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AcdpError::KeyResolutionUnreachable(_)),
        "absence on a stale copy must be transient, got {err:?}"
    );
    assert!(err.is_transient());
    assert_eq!(w.did_hits(), before, "rate limit honored — no fetch");

    // With the limit disabled the same verification succeeds.
    let unlimited = w.resolver().with_forced_refresh_interval(Duration::ZERO);
    unlimited.resolve(AGENT).await.unwrap();
    Verifier::new(&unlimited)
        .verify_context(&ctx)
        .await
        .unwrap();
}

#[test]
fn forced_refresh_interval_defaults_to_one_hour() {
    assert_eq!(
        acdp::did::DEFAULT_FORCED_REFRESH_INTERVAL,
        Duration::from_secs(3600)
    );
}

// ── rev-005 A–E: discovery outcome classes ───────────────────────────

/// rev-005 A: the revocation is signed by K2, which P has since rotated
/// out of `assertionMethod` (still in `verificationMethod`). Its valid
/// registry receipt places the signature → revoked. The lineage-walk
/// copy carries no receipt, so the walk re-retrieves it by `ctx_id`
/// (D-4) instead of dropping or failing.
#[tokio::test]
async fn rev_005_a_rotated_out_signer_with_receipt_is_revoked() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    w.publish_revocation_of_k1("key-2", K2).await;
    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2), ("key-3", K3)],
        &["key-3"],
    ));

    let before = w.retrieve_hits.load(Ordering::SeqCst);
    let revs = find_revocations(&w.client(), &w.resolver(), &agent())
        .await
        .expect("historical arm verifies");
    assert_eq!(revs.len(), 1);
    assert_eq!(revs[0].revoked_key_fingerprint, K1_FP);
    assert!(
        w.retrieve_hits.load(Ordering::SeqCst) >= before + 2,
        "search retrieve + lineage-walk re-retrieve for the receipt"
    );
}

/// rev-005 B: same rotated-out signer, no receipt anywhere → the
/// candidate is unverifiable → discovery fails (unknown), never "not
/// revoked".
#[tokio::test]
async fn rev_005_b_rotated_out_signer_without_receipt_is_unknown() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    w.publish_revocation_of_k1("key-2", K2).await;
    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2), ("key-3", K3)],
        &["key-3"],
    ));
    w.strip_receipts.store(true, Ordering::SeqCst);

    let err = find_revocations(&w.client(), &w.resolver(), &agent())
        .await
        .expect_err("must not fold into not-revoked");
    assert!(is_unverifiable(&err), "{err:?}");
}

/// rev-005 B′: a receipt that does not verify is no better than none.
#[tokio::test]
async fn rev_005_b_tampered_receipt_is_unknown() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    let ctx = w.publish_revocation_of_k1("key-2", K2).await;
    {
        let mut contexts = w.contexts.write().unwrap();
        let v = contexts.get_mut(ctx.body.ctx_id.as_str()).unwrap();
        let sig = &mut v["registry_receipt"]["signature"]["value"];
        let s = sig.as_str().unwrap().to_string();
        let flipped = if s.starts_with('A') { "B" } else { "A" };
        *sig = json!(format!("{flipped}{}", &s[1..]));
    }
    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2), ("key-3", K3)],
        &["key-3"],
    ));
    let err = find_revocations(&w.client(), &w.resolver(), &agent())
        .await
        .expect_err("bad receipt → unknown");
    assert!(is_unverifiable(&err), "{err:?}");
}

/// rev-005 C: the producer's DID host answers 503 / 404 → the candidate
/// could not be checked → transient, unknown.
#[tokio::test]
async fn rev_005_c_did_host_failure_is_transient() {
    for code in [503u16, 404] {
        let w = World::start(producer_doc(
            &[("key-1", K1), ("key-2", K2)],
            &["key-1", "key-2"],
        ))
        .await;
        w.publish_revocation_of_k1("key-2", K2).await;
        w.did_status.store(code, Ordering::SeqCst);
        let err = find_revocations(&w.client(), &w.resolver(), &agent())
            .await
            .expect_err("DID host down → unknown");
        assert!(err.is_transient(), "HTTP {code}: {err:?}");
    }
}

/// rev-005 D: the consumer cached P's document before P added K3; the
/// K3-signed revocation verifies after one forced re-fetch → revoked.
#[tokio::test]
async fn rev_005_d_key_added_after_caching_is_revoked() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    let resolver = w.resolver();
    resolver.resolve(AGENT).await.unwrap();

    w.set_doc(producer_doc(
        &[("key-1", K1), ("key-2", K2), ("key-3", K3)],
        &["key-2", "key-3"],
    ));
    w.publish_revocation_of_k1("key-3", K3).await;

    let revs = find_revocations(&w.client(), &resolver, &agent())
        .await
        .expect("refetch finds K3");
    assert_eq!(revs.len(), 1);
}

/// rev-005 E: K2 is absent from P's document even after a fresh fetch →
/// the candidate is permanently invalid and dropped → not revoked
/// (complete).
#[tokio::test]
async fn rev_005_e_signer_absent_after_fresh_fetch_is_dropped() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    let resolver = w.resolver();
    w.publish_revocation_of_k1("key-2", K2).await;
    w.set_doc(producer_doc(&[("key-1", K1), ("key-3", K3)], &["key-3"]));
    resolver.resolve(AGENT).await.unwrap(); // cached copy lacks K2
    let before = w.did_hits();

    let revs = find_revocations(&w.client(), &resolver, &agent())
        .await
        .expect("permanently invalid candidate is dropped, not unknown");
    assert!(revs.is_empty());
    assert_eq!(
        w.did_hits(),
        before + 1,
        "absence confirmed by exactly one forced re-fetch for the whole run \
         (search candidate + lineage-walk member share it)"
    );
}

/// Bodies the tests above publish are the shape `find_revocations`
/// sees; guard against the harness silently serving a different body.
#[tokio::test]
async fn harness_serves_published_body() {
    let w = World::start(producer_doc(
        &[("key-1", K1), ("key-2", K2)],
        &["key-1", "key-2"],
    ))
    .await;
    let ctx = w.publish_revocation_of_k1("key-2", K2).await;
    let got = w.client().retrieve(&ctx.body.ctx_id).await.unwrap();
    let a: &Body = &got.body;
    assert_eq!(a.content_hash, ctx.body.content_hash);
    assert!(got.registry_receipt.is_some());
}
