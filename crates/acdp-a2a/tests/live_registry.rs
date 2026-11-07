//! Live RFC-ACDP-0022 round trip: the A2A [`Agent`] publishes an artifact
//! to a REAL `acdp-registry-rs` server and the holder verifies it with
//! [`fetch_and_verify`], which no other test calls (`behavior.rs` uses a
//! wiremock registry that never serves a body; `conformance.rs` is offline).
//!
//! Skipped unless `ACDP_LIVE_REGISTRY_URL` is set (loopback `http://` only),
//! so plain `cargo test` and CI need no network. `ACDP_REQUIRE_LIVE_REGISTRY=1`
//! turns a missing URL into a failure. The registry must advertise `did:key`
//! (`[auth] did_methods = ["did:web", "did:key"]`). See the root crate's
//! `tests/live_registry.rs` for the docker compose recipe.

use std::time::Duration;

use acdp::{
    client::{RegistryClient, VerificationPolicy},
    crypto::SigningKey,
    did::WebResolver,
    producer::Producer,
    types::primitives::{AgentDid, ContextType, Visibility},
};
use acdp_a2a::{
    link::LINK_KEY,
    record::BodyTemplate,
    verify::{fetch_and_verify, HeldArtifact, HolderPolicy, TrustedAgents},
    Agent, ArtifactPolicy, ChunkOutput, FailureKind, TaskSession,
};
use serde_json::{json, Value};

fn live_url() -> Option<String> {
    match std::env::var("ACDP_LIVE_REGISTRY_URL") {
        Ok(u) if !u.trim().is_empty() => {
            let u = u.trim().trim_end_matches('/').to_string();
            assert!(
                u.starts_with("http://127.0.0.1:") || u.starts_with("http://localhost:"),
                "ACDP_LIVE_REGISTRY_URL must be a loopback http:// URL"
            );
            Some(u)
        }
        _ => {
            if std::env::var("ACDP_REQUIRE_LIVE_REGISTRY").as_deref() == Ok("1") {
                panic!("ACDP_REQUIRE_LIVE_REGISTRY=1 but ACDP_LIVE_REGISTRY_URL is unset");
            }
            eprintln!("SKIP a2a live_registry: ACDP_LIVE_REGISTRY_URL not set");
            None
        }
    }
}

fn template() -> BodyTemplate {
    let mut t =
        BodyTemplate::new(serde_json::from_value::<ContextType>(json!("analysis")).unwrap());
    t.domain = Some("payments.fraud".into());
    // The template defaults to `private`, which an anonymous holder cannot
    // read (the registry answers a non-disclosing 404). Public keeps the
    // live run auth-free; ids and parts stay salted (RFC-ACDP-0022 §5.2).
    t.visibility = Visibility::Public;
    t
}

fn rand_hex() -> String {
    SigningKey::generate().verifying_key_bytes()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Publishes one completed artifact through the agent; returns the emitted
/// (linked) artifact, the agent's DID and the task ids.
async fn publish_artifact(url: &str) -> (RegistryClient, Value, AgentDid, String, String) {
    let client = RegistryClient::with_test_transport(url).unwrap();
    let producer = Producer::new_did_key(SigningKey::generate());
    let did = AgentDid::new(producer.key_id().split('#').next().unwrap());
    let agent = Agent::new(
        producer,
        client.clone(),
        "1.0",
        ArtifactPolicy::new(template()),
    )
    .with_publish_timeout(Duration::from_secs(10))
    .with_max_attempts(1);

    let (task, ctx) = (
        format!("task-{}", rand_hex()),
        format!("ctx-{}", rand_hex()),
    );
    let mut session = TaskSession::new(task.clone(), ctx.clone());
    let chunk = json!({
        "taskId": task, "contextId": ctx, "append": false, "lastChunk": true,
        "artifact": { "artifactId": "live-1", "parts": [{ "text": "fraud score 0.93" }] }
    });
    let out = match agent.on_chunk(&mut session, chunk).await.expect("on_chunk") {
        ChunkOutput::Emit(c) => c,
        ChunkOutput::Withhold { artifact_id, .. } => panic!("withheld {artifact_id}"),
    };
    let artifact = out["artifact"].clone();
    assert!(
        artifact["metadata"][LINK_KEY]["ctx_id"].is_string(),
        "emitted artifact carries no link: {artifact}"
    );
    (client, artifact, did, task, ctx)
}

#[tokio::test]
async fn live_a2a_publish_then_fetch_and_verify() {
    let Some(url) = live_url() else { return };
    let (client, artifact, did, task, ctx) = publish_artifact(&url).await;

    let verdict = fetch_and_verify(
        &client,
        &WebResolver::new(),
        &VerificationPolicy::default(),
        &HeldArtifact {
            artifact: &artifact,
            task_id: Some(&task),
            context_id: Some(&ctx),
        },
        &HolderPolicy {
            trusted: TrustedAgents::Only(vec![did.clone()]),
            card: None,
        },
    )
    .await
    .expect("holder verifies the artifact against the real registry");
    assert_eq!(verdict.agent_id, did);
    assert!(verdict.task_checked && verdict.context_checked);
    assert_eq!(
        verdict.ctx_id.0,
        artifact["metadata"][LINK_KEY]["ctx_id"].as_str().unwrap()
    );
}

/// Over the real registry, a holder must refuse altered parts, a different
/// task, and an agent it does not trust.
#[tokio::test]
async fn live_a2a_holder_refusals() {
    let Some(url) = live_url() else { return };
    let (client, artifact, did, task, ctx) = publish_artifact(&url).await;
    let trusted = HolderPolicy {
        trusted: TrustedAgents::Only(vec![did]),
        card: None,
    };
    let run = |a: Value, t: String, p: HolderPolicy| {
        let client = client.clone();
        let ctx = ctx.clone();
        async move {
            fetch_and_verify(
                &client,
                &WebResolver::new(),
                &VerificationPolicy::default(),
                &HeldArtifact {
                    artifact: &a,
                    task_id: Some(&t),
                    context_id: Some(&ctx),
                },
                &p,
            )
            .await
            .map(|_| ())
            .map_err(|e| e.kind)
        }
    };

    let mut altered = artifact.clone();
    altered["parts"] = json!([{ "text": "fraud score 0.01" }]);
    assert_eq!(
        run(altered, task.clone(), trusted.clone()).await,
        Err(FailureKind::PartsMismatch)
    );
    assert_eq!(
        run(artifact.clone(), "other-task".into(), trusted.clone()).await,
        Err(FailureKind::TaskMismatch)
    );
    let stranger = HolderPolicy {
        trusted: TrustedAgents::Only(vec![AgentDid::new(
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        )]),
        card: None,
    };
    assert_eq!(
        run(artifact, task, stranger).await,
        Err(FailureKind::UntrustedAgent)
    );
}
