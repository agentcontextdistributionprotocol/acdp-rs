//! Compile-only regression test for issue #279.
//!
//! 0.13.2 accidentally made every public async entry point that goes
//! through `discover_revocations` (`crates/acdp-client/src/revocation.rs`)
//! `!Send`, because its two `&dyn Fn(..)` closure parameters were held
//! across an `.await` point with no `Sync` bound — `&dyn Fn` is `Send`
//! only when the trait object itself is `Sync`. That broke
//! `axum::handler::Handler` compatibility for any handler doing
//! cross-registry resolution.
//!
//! This file asserts `Send` at compile time for every affected entry
//! point. It is never executed — `assert_send` never calls the futures
//! it's handed, so no live registry is needed; a regression here shows up
//! as a compile error, not a runtime failure.

#![cfg(feature = "client")]

fn assert_send<T: Send>(_: T) {}

#[test]
fn revocation_discovery_futures_are_send() {
    use acdp::client::{
        find_registry_attested_revocations, find_revocations, CrossRegistryResolver,
        RegistryClient, VerificationPolicy, VerifiedContext,
    };
    use acdp::did::WebResolver;
    use acdp::types::{primitives::LineageId, AgentDid, CtxId};

    let client = RegistryClient::new("https://registry.example.com").unwrap();
    let resolver = WebResolver::new();
    let agent_id = AgentDid::new("did:web:agents.example.com:test");
    let ctx_id = CtxId("acdp://registry.example.com/00000000-0000-4000-8000-000000000000".into());
    let lineage_id = LineageId(
        "lin:sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
    );
    let policy = VerificationPolicy::default();
    let cross = CrossRegistryResolver::new();
    let body = acdp::types::Body {
        ctx_id: ctx_id.clone(),
        lineage_id: lineage_id.clone(),
        version: 1,
        supersedes: None,
        agent_id: agent_id.clone(),
        contributors: vec![],
        origin_registry: "registry.example.com".into(),
        created_at: chrono::Utc::now(),
        content_hash: acdp::types::primitives::ContentHash(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        ),
        signature: acdp::types::Signature {
            algorithm: "ed25519".into(),
            key_id: "did:web:agents.example.com:test#key-1".into(),
            value: "A".repeat(86),
        },
        title: "t".into(),
        context_type: acdp::types::ContextType::DataSnapshot,
        data_refs: vec![],
        derived_from: vec![],
        visibility: acdp::types::Visibility::Public,
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

    assert_send(find_revocations(&client, &resolver, &agent_id));
    assert_send(find_registry_attested_revocations(
        &client, &resolver, &agent_id,
    ));
    assert_send(VerifiedContext::fetch(&client, &resolver, &ctx_id));
    assert_send(VerifiedContext::fetch_with_policy(
        &client, &resolver, &ctx_id, &policy,
    ));
    assert_send(VerifiedContext::fetch_current(
        &client,
        &resolver,
        &lineage_id,
    ));
    assert_send(VerifiedContext::fetch_current_with_policy(
        &client,
        &resolver,
        &lineage_id,
        &policy,
    ));
    assert_send(VerifiedContext::fetch_report(
        &client, &resolver, &ctx_id, &policy,
    ));
    assert_send(cross.resolve(&ctx_id));
    assert_send(cross.walk_derived_from(&body));
}
