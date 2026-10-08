//! Example: the full publish → retrieve → verify loop against a registry.
//!
//! Run with: `cargo run --example end_to_end --features client,test-transport`
//!
//! `examples/consumer.rs` shows the recommended network path as a
//! *commented* sketch (because it has no registry to talk to). This
//! example makes that path *runnable* by standing up an in-process mock
//! registry with `wiremock`, so you can watch the real `RegistryClient`
//! calls execute end to end:
//!
//!   1. A producer builds + signs a `PublishRequest`.
//!   2. `RegistryClient::publish` POSTs it; the registry assigns a
//!      `ctx_id` / `lineage_id` and returns a `PublishResponse`.
//!   3. `RegistryClient::retrieve` GETs the stored `FullContext`.
//!   4. The consumer re-derives `content_hash` and checks the Ed25519
//!      signature — proving the body was not tampered with in transit.
//!
//! Step 4 here verifies against the producer's *known* public key. In
//! production the key is instead resolved from the producer's `did:web`
//! document and the whole of steps 3–4 collapse into a single
//! `VerifiedContext::fetch_report` call (see `examples/consumer.rs`).

use acdp::{
    client::RegistryClient,
    crypto::{compute_content_hash, verify_ed25519, SigningKey},
    producer::Producer,
    types::{AgentDid, ContentHash, ContextType, CtxId, DataRef, DataRefType, Visibility},
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── 1. Build and sign a publish request ─────────────────────────────────
    let key = SigningKey::generate();
    let producer_pub = key.verifying_key_bytes(); // capture before `key` moves
    let agent_id = AgentDid::new("did:web:agents.example.com:my-agent");
    let key_id = "did:web:agents.example.com:my-agent#key-1";
    let producer = Producer::new(key, agent_id, key_id);

    let request = producer
        .publish_request()
        .title("Q1 2026 revenue snapshot")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .summary("Quarterly revenue snapshot for Q1 2026.")
        .data_refs(vec![DataRef::uri(
            DataRefType::PrimaryResult,
            "https://data.example.com/revenue/q1-2026.parquet",
        )])
        .build()?;

    // ── 2. Stand up a mock registry ─────────────────────────────────────────
    // The ctx_id / lineage_id below are what a real registry would mint.
    // Registry-assigned fields are in the §5.7 exclusion set, so attaching
    // them to the returned body does NOT change `content_hash`.
    let ctx_id = "acdp://registry.example.com/11111111-1111-4111-8111-111111111111";
    let lineage_id = "lin:sha256:4c63394418b2e784aef68f5a091535c557453c21231f5905f21a38c02913cd86";

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/contexts"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "ctx_id": ctx_id,
            "lineage_id": lineage_id,
            "version": 1,
            "created_at": "2026-04-16T10:30:15.123Z",
            "status": "active"
        })))
        .mount(&server)
        .await;

    // Reflect the producer's request back as the stored body, plus the
    // registry-assigned identity fields — exactly what `GET /contexts/{id}`
    // returns. `content_hash` and `signature` are the producer's originals.
    let mut body = serde_json::to_value(&request)?;
    let obj = body.as_object_mut().unwrap();
    obj.insert("ctx_id".into(), json!(ctx_id));
    obj.insert("lineage_id".into(), json!(lineage_id));
    obj.insert("origin_registry".into(), json!("registry.example.com"));
    obj.insert("created_at".into(), json!("2026-04-16T10:30:15.123Z"));

    Mock::given(method("GET"))
        .and(path(format!("/contexts/{}", urlencoding::encode(ctx_id))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "body": body,
            "registry_state": { "status": "active" }
        })))
        .mount(&server)
        .await;

    // `with_test_transport` relaxes the SSRF policy so the client will talk
    // to a plain-HTTP loopback mock. Production code uses
    // `RegistryClient::new("https://registry.example.com")` instead.
    let client = RegistryClient::with_test_transport(&server.uri())?;

    // ── 3. Publish ──────────────────────────────────────────────────────────
    let resp = client.publish(&request).await?;
    println!("✓ Published");
    println!("  ctx_id:     {}", resp.ctx_id.as_str());
    println!("  lineage_id: {}", resp.lineage_id.as_str());
    println!("  version:    {}", resp.version);

    // ── 4. Retrieve ─────────────────────────────────────────────────────────
    let full = client.retrieve(&CtxId::parse(ctx_id)?).await?;
    println!("✓ Retrieved \"{}\"", full.body.title);

    // ── 5. Verify integrity ─────────────────────────────────────────────────
    let body_value = serde_json::to_value(&full.body)?;
    let recomputed = compute_content_hash(&body_value)?;
    let stored = ContentHash(full.body.content_hash.as_str().to_string());
    anyhow::ensure!(
        recomputed == stored,
        "content_hash mismatch — body tampered!"
    );
    println!("✓ content_hash matches: {recomputed}");

    verify_ed25519(&producer_pub, &full.body.signature.value, stored.as_str())
        .map_err(|e| anyhow::anyhow!("signature verification failed: {e}"))?;
    println!("✓ Ed25519 signature verified — body is authentic");

    Ok(())
}
