//! Compile-time auto-trait guard for the public API (COMPATIBILITY.md).
//!
//! `cargo semver-checks` compares named types, so it catches a public
//! struct losing `Send` or `Sync`. It cannot see the anonymous future an
//! `async fn` returns, and that is how 0.13.2 shipped `!Send` futures with
//! a clean semver report (#279). This file closes that gap: every public
//! `async fn` in the umbrella crate's surface is wrapped in a function
//! whose return type is `impl Future + Send`, so a `!Send` regression is a
//! compile error here rather than a downstream surprise.
//!
//! Nothing is executed: the wrappers are only type-checked, never called,
//! so no runtime or live registry is needed. `tests/send_futures.rs` holds
//! the original #279 regression guard; this file is the exhaustive one.
//!
//! Futures are promised `Send`, not `Sync` (a future is polled through
//! `&mut`, and `tokio::spawn` / axum handlers need only `Send + 'static`).
//! Public types are promised `Send + Sync + 'static`.
//!
//! The file runs under the default feature set (`client`), which is how
//! downstream consumers such as Seam build the crate; CI also runs it in
//! that configuration on its own. Server-side futures are checked when
//! `server` is enabled as well.
//!
//! When adding a public `async fn`, add a wrapper here.

#![cfg(feature = "client")]
#![allow(dead_code, clippy::too_many_arguments)]

use std::future::Future;
use std::time::Instant;

use acdp::client::registry::RegistrySearch;
use acdp::client::{
    DataRefFetcher, HttpsDataRefFetcher, RegistryClient, RegistryClientBuilder, RevocationPolicy,
    VerificationPolicy, VerifiedContext, WitnessConsistencyCheck,
};
use acdp::did::{DidDocument, WebResolver};
use acdp::safe_http::SsrfPolicy;
use acdp::types::receipt::ReceiptKeyStatus;
use acdp::types::{
    AgentDid, Body, ContentHash, CtxId, DataRef, FullContext, LineageId, LogLeaf, PublishRequest,
    SearchParams, Status, WitnessSigner,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

fn assert_send_sync<T: Send + Sync + 'static + ?Sized>() {}
fn assert_spawnable<F: Future + Send + 'static>(_: F) {}

// ---------------------------------------------------------------------------
// acdp::client::RegistryClient / builders
// ---------------------------------------------------------------------------

mod registry_client {
    use super::*;

    #[allow(deprecated)]
    fn new_pinned<'a>(url: &'a str, p: &'a SsrfPolicy) -> impl Future + Send + 'a {
        RegistryClient::new_pinned(url, p)
    }
    fn capabilities(c: &RegistryClient) -> impl Future + Send + '_ {
        c.capabilities()
    }
    fn capabilities_with_ttl(c: &RegistryClient) -> impl Future + Send + '_ {
        c.capabilities_with_ttl()
    }
    fn publish<'a>(c: &'a RegistryClient, r: &'a PublishRequest) -> impl Future + Send + 'a {
        c.publish(r)
    }
    fn publish_idempotent<'a>(
        c: &'a RegistryClient,
        r: &'a PublishRequest,
        k: &'a str,
    ) -> impl Future + Send + 'a {
        c.publish_idempotent(r, k)
    }
    fn publish_with_retry<'a>(
        c: &'a RegistryClient,
        r: &'a PublishRequest,
        k: &'a str,
    ) -> impl Future + Send + 'a {
        c.publish_with_retry(r, k, 3)
    }
    fn retrieve<'a>(c: &'a RegistryClient, id: &'a CtxId) -> impl Future + Send + 'a {
        c.retrieve(id)
    }
    fn retrieve_with_metadata<'a>(c: &'a RegistryClient, id: &'a CtxId) -> impl Future + Send + 'a {
        c.retrieve_with_metadata(id)
    }
    fn retrieve_if_none_match<'a>(
        c: &'a RegistryClient,
        id: &'a CtxId,
        etag: &'a str,
    ) -> impl Future + Send + 'a {
        c.retrieve_if_none_match(id, etag)
    }
    fn retrieve_body<'a>(c: &'a RegistryClient, id: &'a CtxId) -> impl Future + Send + 'a {
        c.retrieve_body(id)
    }
    fn lineage<'a>(c: &'a RegistryClient, l: &'a LineageId) -> impl Future + Send + 'a {
        c.lineage(l)
    }
    fn current<'a>(c: &'a RegistryClient, l: &'a LineageId) -> impl Future + Send + 'a {
        c.current(l)
    }
    fn search<'a>(c: &'a RegistryClient, p: &'a SearchParams) -> impl Future + Send + 'a {
        c.search(p)
    }
    fn builder_build(b: RegistryClientBuilder) -> impl Future + Send + 'static {
        b.build()
    }
    fn search_send(s: RegistrySearch<'_>) -> impl Future + Send + '_ {
        s.send()
    }
}

// ---------------------------------------------------------------------------
// acdp::client::VerifiedContext
// ---------------------------------------------------------------------------

mod verified_context {
    use super::*;

    fn fetch<'a>(
        c: &'a RegistryClient,
        r: &'a WebResolver,
        id: &'a CtxId,
    ) -> impl Future + Send + 'a {
        VerifiedContext::fetch(c, r, id)
    }
    fn fetch_with_policy<'a>(
        c: &'a RegistryClient,
        r: &'a WebResolver,
        id: &'a CtxId,
        p: &'a VerificationPolicy,
    ) -> impl Future + Send + 'a {
        VerifiedContext::fetch_with_policy(c, r, id, p)
    }
    fn fetch_current<'a>(
        c: &'a RegistryClient,
        r: &'a WebResolver,
        l: &'a LineageId,
    ) -> impl Future + Send + 'a {
        VerifiedContext::fetch_current(c, r, l)
    }
    fn fetch_current_with_policy<'a>(
        c: &'a RegistryClient,
        r: &'a WebResolver,
        l: &'a LineageId,
        p: &'a VerificationPolicy,
    ) -> impl Future + Send + 'a {
        VerifiedContext::fetch_current_with_policy(c, r, l, p)
    }
    fn fetch_report<'a>(
        c: &'a RegistryClient,
        r: &'a WebResolver,
        id: &'a CtxId,
        p: &'a VerificationPolicy,
    ) -> impl Future + Send + 'a {
        VerifiedContext::fetch_report(c, r, id, p)
    }
    fn fetch_report_diagnose<'a>(
        c: &'a RegistryClient,
        r: &'a WebResolver,
        id: &'a CtxId,
        p: &'a VerificationPolicy,
    ) -> impl Future + Send + 'a {
        VerifiedContext::fetch_report_diagnose(c, r, id, p)
    }
    fn fetch_report_with_fetcher<'a>(
        c: &'a RegistryClient,
        r: &'a WebResolver,
        id: &'a CtxId,
        p: &'a VerificationPolicy,
        f: &'a HttpsDataRefFetcher,
    ) -> impl Future + Send + 'a {
        VerifiedContext::fetch_report_with_fetcher(c, r, id, p, f)
    }
    // Generic over any fetcher: `DataRefFetcher: Send + Sync` and its
    // `fetch` future is `Send`, so the outer future must be `Send` too.
    fn fetch_report_with_any_fetcher<'a, F: DataRefFetcher>(
        c: &'a RegistryClient,
        r: &'a WebResolver,
        id: &'a CtxId,
        p: &'a VerificationPolicy,
        f: &'a F,
    ) -> impl Future + Send + 'a {
        VerifiedContext::fetch_report_with_fetcher(c, r, id, p, f)
    }
    fn verify_receipt<'a>(v: &'a VerifiedContext, r: &'a WebResolver) -> impl Future + Send + 'a {
        v.verify_receipt(r)
    }
    fn recheck_revocation<'a>(
        v: &'a VerifiedContext,
        c: &'a RegistryClient,
        r: &'a WebResolver,
        p: &'a RevocationPolicy,
    ) -> impl Future + Send + 'a {
        v.recheck_revocation(c, r, p)
    }
}

// ---------------------------------------------------------------------------
// acdp::client::CrossRegistryResolver
// ---------------------------------------------------------------------------

mod cross_registry {
    use super::*;
    use acdp::client::CrossRegistryResolver;

    fn resolve<'a>(x: &'a CrossRegistryResolver, id: &'a CtxId) -> impl Future + Send + 'a {
        x.resolve(id)
    }
    fn walk_derived_from<'a>(x: &'a CrossRegistryResolver, b: &'a Body) -> impl Future + Send + 'a {
        x.walk_derived_from(b)
    }
}

// ---------------------------------------------------------------------------
// acdp::client revocation (RFC-ACDP-0014)
// ---------------------------------------------------------------------------

mod revocation {
    use super::*;
    use acdp::client::{
        find_registry_attested_revocations, find_revocations, find_revocations_in_lineage,
        find_revocations_verdict, verify_revocation_body, verify_revocation_candidate,
        verify_revocation_context,
    };

    fn body<'a>(b: &'a Body, r: &'a WebResolver) -> impl Future + Send + 'a {
        verify_revocation_body(b, r)
    }
    fn context<'a>(x: &'a FullContext, r: &'a WebResolver) -> impl Future + Send + 'a {
        verify_revocation_context(x, r)
    }
    fn candidate<'a>(
        x: &'a FullContext,
        c: &'a RegistryClient,
        r: &'a WebResolver,
        since: Instant,
    ) -> impl Future + Send + 'a {
        verify_revocation_candidate(x, c, r, since)
    }
    fn in_lineage<'a>(
        c: &'a RegistryClient,
        r: &'a WebResolver,
        l: &'a LineageId,
    ) -> impl Future + Send + 'a {
        find_revocations_in_lineage(c, r, l)
    }
    fn find<'a>(
        c: &'a RegistryClient,
        r: &'a WebResolver,
        a: &'a AgentDid,
    ) -> impl Future + Send + 'a {
        find_revocations(c, r, a)
    }
    fn registry_attested<'a>(
        c: &'a RegistryClient,
        r: &'a WebResolver,
        a: &'a AgentDid,
    ) -> impl Future + Send + 'a {
        find_registry_attested_revocations(c, r, a)
    }
    fn verdict<'a>(
        c: &'a RegistryClient,
        r: &'a WebResolver,
        a: &'a AgentDid,
        fp: &'a str,
        placement: Option<(DateTime<Utc>, ReceiptKeyStatus)>,
        p: &'a RevocationPolicy,
    ) -> impl Future + Send + 'a {
        find_revocations_verdict(c, r, a, fp, placement, p)
    }
}

// ---------------------------------------------------------------------------
// acdp::client receipts, transparency log, witnesses, data refs
// ---------------------------------------------------------------------------

mod receipts_and_log {
    use super::*;
    use acdp::client::{
        fetch_and_verify_data_ref, mint_cosignature_checked, verify_lineage_head_receipt_value,
        verify_log_checkpoint_value, verify_log_inclusion_value, verify_receipt_value,
        verify_receipt_value_since, verify_receipt_value_with_status_since,
    };

    fn receipt<'a>(
        v: &'a Value,
        id: &'a CtxId,
        b: &'a Body,
        h: &'a ContentHash,
        fp: &'a str,
        auth: &'a str,
        r: &'a WebResolver,
    ) -> impl Future + Send + 'a {
        verify_receipt_value(v, id, b, h, fp, auth, r)
    }
    fn receipt_since<'a>(
        v: &'a Value,
        id: &'a CtxId,
        b: &'a Body,
        h: &'a ContentHash,
        fp: &'a str,
        auth: &'a str,
        r: &'a WebResolver,
        since: Instant,
    ) -> impl Future + Send + 'a {
        verify_receipt_value_since(v, id, b, h, fp, auth, r, since)
    }
    fn receipt_with_status_since<'a>(
        v: &'a Value,
        id: &'a CtxId,
        b: &'a Body,
        h: &'a ContentHash,
        fp: &'a str,
        auth: &'a str,
        r: &'a WebResolver,
        since: Instant,
    ) -> impl Future + Send + 'a {
        verify_receipt_value_with_status_since(v, id, b, h, fp, auth, r, since)
    }
    fn lineage_head_receipt<'a>(
        v: &'a Value,
        l: &'a LineageId,
        id: &'a CtxId,
        s: &'a Status,
        auth: &'a str,
        reg: &'a str,
        r: &'a WebResolver,
    ) -> impl Future + Send + 'a {
        verify_lineage_head_receipt_value(
            v,
            l,
            id,
            1,
            s,
            true,
            auth,
            reg,
            chrono::Duration::zero(),
            r,
        )
    }
    fn log_checkpoint<'a>(
        v: &'a Value,
        auth: &'a str,
        reg: &'a str,
        r: &'a WebResolver,
    ) -> impl Future + Send + 'a {
        verify_log_checkpoint_value(v, auth, reg, chrono::Duration::zero(), r)
    }
    fn log_inclusion<'a>(
        v: &'a Value,
        leaf: &'a LogLeaf,
        auth: &'a str,
        reg: &'a str,
        r: &'a WebResolver,
    ) -> impl Future + Send + 'a {
        verify_log_inclusion_value(v, leaf, auth, reg, chrono::Duration::zero(), r)
    }
    fn mint_cosignature<'a>(
        s: &'a WitnessSigner,
        v: &'a Value,
        auth: &'a str,
        reg: &'a str,
        consistency: Option<WitnessConsistencyCheck<'a>>,
        r: &'a WebResolver,
    ) -> impl Future + Send + 'a {
        mint_cosignature_checked(
            s,
            v,
            auth,
            reg,
            consistency,
            Utc::now(),
            chrono::Duration::zero(),
            r,
        )
    }
    fn data_ref<'a, F: DataRefFetcher>(d: &'a DataRef, f: &'a F) -> impl Future + Send + 'a {
        fetch_and_verify_data_ref(d, f)
    }
}

// ---------------------------------------------------------------------------
// acdp::did / acdp::crypto / acdp::safe_http / acdp::verify
// ---------------------------------------------------------------------------

mod did_crypto_verify {
    use super::*;
    use acdp::crypto::fingerprint::{fingerprint_for_key_id, fingerprint_for_key_id_since};
    use acdp::verify::{
        verify_body_signature_historical, verify_body_signature_historical_since,
        verify_lifecycle_event, verify_publish_request_signature, Verifier,
    };

    fn resolve<'a>(r: &'a WebResolver, did: &'a str) -> impl Future + Send + 'a {
        r.resolve(did)
    }
    fn resolve_tracked<'a>(r: &'a WebResolver, did: &'a str) -> impl Future + Send + 'a {
        r.resolve_tracked(did)
    }
    fn resolve_fresh<'a>(r: &'a WebResolver, did: &'a str) -> impl Future + Send + 'a {
        r.resolve_fresh(did)
    }
    fn resolve_until<'a, F>(
        r: &'a WebResolver,
        did: &'a str,
        since: Instant,
        accept: F,
    ) -> impl Future + Send + 'a
    where
        F: Fn(&DidDocument) -> bool + Send + 'a,
    {
        r.resolve_until(did, since, accept)
    }
    fn resolve_with_fragment<'a>(
        r: &'a WebResolver,
        did: &'a str,
        frag: &'a str,
        since: Instant,
    ) -> impl Future + Send + 'a {
        r.resolve_with_fragment(did, frag, since)
    }
    fn pin_resolved_ip<'a>(p: &'a SsrfPolicy, host: &'a str) -> impl Future + Send + 'a {
        p.pin_resolved_ip(host, 443)
    }
    fn fingerprint<'a>(k: &'a str, alg: &'a str, r: &'a WebResolver) -> impl Future + Send + 'a {
        fingerprint_for_key_id(k, alg, r)
    }
    fn fingerprint_since<'a>(
        k: &'a str,
        alg: &'a str,
        r: &'a WebResolver,
        since: Instant,
    ) -> impl Future + Send + 'a {
        fingerprint_for_key_id_since(k, alg, r, since)
    }
    fn verifier_verify_body<'a>(v: &'a Verifier<'a>, b: &'a Body) -> impl Future + Send + 'a {
        v.verify_body(b)
    }
    fn verifier_verify_body_signed<'a>(
        v: &'a Verifier<'a>,
        b: &'a Body,
    ) -> impl Future + Send + 'a {
        v.verify_body_signed(b)
    }
    fn verifier_verify_context<'a>(
        v: &'a Verifier<'a>,
        x: &'a FullContext,
    ) -> impl Future + Send + 'a {
        v.verify_context(x)
    }
    fn verifier_verify_body_signature<'a>(
        v: &'a Verifier<'a>,
        b: &'a Body,
    ) -> impl Future + Send + 'a {
        v.verify_body_signature(b)
    }
    fn verifier_verify_body_signature_historical<'a>(
        v: &'a Verifier<'a>,
        b: &'a Body,
    ) -> impl Future + Send + 'a {
        v.verify_body_signature_historical(b)
    }
    fn publish_request_signature<'a>(
        req: &'a PublishRequest,
        r: &'a WebResolver,
    ) -> impl Future + Send + 'a {
        verify_publish_request_signature(req, r)
    }
    fn historical<'a>(b: &'a Body, r: &'a WebResolver) -> impl Future + Send + 'a {
        verify_body_signature_historical(b, r)
    }
    fn historical_since<'a>(
        b: &'a Body,
        r: &'a WebResolver,
        since: Instant,
    ) -> impl Future + Send + 'a {
        verify_body_signature_historical_since(b, r, since)
    }
    fn lifecycle_event<'a>(
        v: &'a Value,
        id: &'a CtxId,
        did: &'a AgentDid,
        reg: Option<&'a str>,
        r: &'a WebResolver,
    ) -> impl Future + Send + 'a {
        verify_lifecycle_event(v, id, did, reg, r)
    }
}

// ---------------------------------------------------------------------------
// acdp::registry (server + client)
// ---------------------------------------------------------------------------

#[cfg(feature = "server")]
mod server {
    use super::*;
    use acdp::registry::{InMemoryStore, LifecycleEndpoint, RegistryServer};
    use acdp::types::LifecycleEvent;

    type Server = RegistryServer<InMemoryStore>;

    fn publish_verified<'a>(
        s: &'a Server,
        req: &'a PublishRequest,
        key: Option<&'a str>,
        r: &'a WebResolver,
    ) -> impl Future + Send + 'a {
        s.publish_verified(req, key, r)
    }
    fn publish_verified_in_tenant<'a>(
        s: &'a Server,
        req: &'a PublishRequest,
        key: Option<&'a str>,
        r: &'a WebResolver,
        tenant: Option<&'a str>,
    ) -> impl Future + Send + 'a {
        s.publish_verified_in_tenant(req, key, r, tenant)
    }
    fn publish_verified_in_tenant_with_outcome<'a>(
        s: &'a Server,
        req: &'a PublishRequest,
        key: Option<&'a str>,
        r: &'a WebResolver,
        tenant: Option<&'a str>,
    ) -> impl Future + Send + 'a {
        s.publish_verified_in_tenant_with_outcome(req, key, r, tenant)
    }
    fn prove_publish_identity<'a>(
        s: &'a Server,
        req: &'a PublishRequest,
        r: &'a WebResolver,
    ) -> impl Future + Send + 'a {
        s.prove_publish_identity(req, r)
    }
    fn prove_lifecycle_identity<'a>(
        s: &'a Server,
        e: &'a LifecycleEvent,
        ep: LifecycleEndpoint,
        who: Option<&'a AgentDid>,
        r: &'a WebResolver,
    ) -> impl Future + Send + 'a {
        s.prove_lifecycle_identity(e, ep, who, r)
    }
    fn retract_verified<'a>(
        s: &'a Server,
        e: &'a LifecycleEvent,
        who: Option<&'a AgentDid>,
        r: &'a WebResolver,
    ) -> impl Future + Send + 'a {
        s.retract_verified(e, who, r)
    }
    fn republish_verified<'a>(
        s: &'a Server,
        e: &'a LifecycleEvent,
        who: Option<&'a AgentDid>,
        r: &'a WebResolver,
    ) -> impl Future + Send + 'a {
        s.republish_verified(e, who, r)
    }

    #[test]
    fn server_types_are_send_sync() {
        use acdp::registry::{MerkleLog, NoopRateLimiter, PublishValidator};
        assert_send_sync::<Server>();
        assert_send_sync::<InMemoryStore>();
        assert_send_sync::<NoopRateLimiter>();
        assert_send_sync::<MerkleLog>();
        assert_send_sync::<PublishValidator<'static>>();
    }
}

// ---------------------------------------------------------------------------
// 'static: the shapes a consumer actually spawns
// ---------------------------------------------------------------------------

/// `tokio::spawn` and axum handlers need `Send + 'static`. The library's
/// futures borrow their arguments, so the supported pattern is an
/// `async move` block that owns (or `Arc`-shares) the client, resolver and
/// policy. That block must be spawnable.
#[test]
fn owned_futures_are_spawnable() {
    use acdp::client::{CrossRegistryResolver, RevocationCache};
    use std::sync::Arc;

    let client = Arc::new(RegistryClient::new("https://registry.example.com").unwrap());
    let resolver = Arc::new(WebResolver::new());
    let policy = Arc::new(VerificationPolicy::default());
    let cross = Arc::new(CrossRegistryResolver::new());
    let cache = Arc::new(RevocationCache::new());
    let ctx_id = CtxId("acdp://registry.example.com/00000000-0000-4000-8000-000000000000".into());

    {
        let (client, resolver, policy, ctx_id) = (
            client.clone(),
            resolver.clone(),
            policy.clone(),
            ctx_id.clone(),
        );
        assert_spawnable(async move {
            VerifiedContext::fetch_with_policy(&client, &resolver, &ctx_id, &policy).await
        });
    }
    {
        let (client, ctx_id) = (client.clone(), ctx_id.clone());
        assert_spawnable(async move { client.retrieve(&ctx_id).await });
    }
    {
        let (cross, ctx_id) = (cross.clone(), ctx_id.clone());
        assert_spawnable(async move { cross.resolve(&ctx_id).await });
    }
    {
        let resolver = resolver.clone();
        assert_spawnable(async move { resolver.resolve("did:web:example.com").await });
    }
    assert_spawnable(async move {
        let _keep = cache;
        RegistryClient::builder("https://registry.example.com")
            .build()
            .await
    });
}

// ---------------------------------------------------------------------------
// Public types: Send + Sync + 'static
// ---------------------------------------------------------------------------

#[test]
fn client_types_are_send_sync() {
    use acdp::client::registry::RetrievalMetadata;
    use acdp::client::*;

    assert_send_sync::<RegistryClient>();
    assert_send_sync::<RegistryClientBuilder>();
    assert_send_sync::<RegistrySearch<'static>>();
    assert_send_sync::<RetrievalMetadata>();
    assert_send_sync::<CrossRegistryResolver>();
    assert_send_sync::<ResolverOptions>();
    assert_send_sync::<VerifiedContext>();
    assert_send_sync::<VerificationPolicy>();
    assert_send_sync::<VerificationReport>();
    assert_send_sync::<RevocationPolicy>();
    assert_send_sync::<RevocationDiscovery>();
    assert_send_sync::<DiscoveryFailurePolicy>();
    assert_send_sync::<DiscoveryOutcome>();
    assert_send_sync::<ReceiptPolicy>();
    assert_send_sync::<LineageHeadPolicy>();
    assert_send_sync::<HistoricalKeyPolicy>();
    assert_send_sync::<KeyAuthorization>();
    assert_send_sync::<RevocationCache>();
    assert_send_sync::<RevocationVerdict>();
    assert_send_sync::<RevocationAssessment>();
    assert_send_sync::<RevocationEffect>();
    assert_send_sync::<RevocationRefusal>();
    assert_send_sync::<RevocationSource>();
    assert_send_sync::<SourcedRevocation>();
    assert_send_sync::<UnknownReason>();
    assert_send_sync::<HttpsDataRefFetcher>();
    assert_send_sync::<dyn AuthProvider>();
    assert_send_sync::<BearerToken>();
    assert_send_sync::<StaticBearerToken>();
    assert_send_sync::<PerAuthorityTokens>();
    assert_send_sync::<LogInclusionPolicy>();
    assert_send_sync::<LogInclusionVerdict>();
    assert_send_sync::<CannotVerifyReason>();
    assert_send_sync::<WitnessEnforcement>();
    assert_send_sync::<WitnessQuorumPolicy>();
    assert_send_sync::<WitnessPolicy>();
    assert_send_sync::<WitnessQuorumReport>();
    assert_send_sync::<WitnessConsistencyCheck<'static>>();
}

/// RFC-ACDP-0017: the offline chain verifier's public types.
#[test]
fn chain_types_are_send_sync() {
    use acdp::chain::*;

    assert_send_sync::<ChainError>();
    assert_send_sync::<Evidence>();
    assert_send_sync::<ContextEvidence>();
    assert_send_sync::<DidSnapshot>();
    assert_send_sync::<DiscoveryRecord>();
    assert_send_sync::<CheckpointEvidence>();
    assert_send_sync::<Omitted>();
    assert_send_sync::<Options>();
    assert_send_sync::<Limits>();
    assert_send_sync::<Pinned>();
    assert_send_sync::<PinnedSnapshot>();
    assert_send_sync::<ChainVerdict>();
    assert_send_sync::<Node>();
    assert_send_sync::<Pass>();
    assert_send_sync::<Stages>();
    assert_send_sync::<Drift>();
}

#[test]
fn core_types_are_send_sync() {
    use acdp::crypto::{AcdpSigningKey, P256SigningKey, SigningKey};
    use acdp::did::{FreshResolution, ResolvedDidDocument};
    use acdp::producer::{Producer, RequestBuilder};
    use acdp::safe_http::SafeDnsResolver;
    use acdp::types::*;
    use acdp::verify::Verifier;

    assert_send_sync::<acdp::AcdpError>();
    assert_send_sync::<WebResolver>();
    assert_send_sync::<DidDocument>();
    assert_send_sync::<ResolvedDidDocument>();
    assert_send_sync::<FreshResolution>();
    assert_send_sync::<SsrfPolicy>();
    assert_send_sync::<SafeDnsResolver>();
    assert_send_sync::<Verifier<'static>>();
    assert_send_sync::<SigningKey>();
    assert_send_sync::<P256SigningKey>();
    assert_send_sync::<AcdpSigningKey>();
    assert_send_sync::<Producer>();
    assert_send_sync::<RequestBuilder<'static>>();
    assert_send_sync::<Body>();
    assert_send_sync::<FullContext>();
    assert_send_sync::<RegistryState>();
    assert_send_sync::<PublishRequest>();
    assert_send_sync::<PublishResponse>();
    assert_send_sync::<CapabilitiesDocument>();
    assert_send_sync::<SearchParams>();
    assert_send_sync::<SearchResponse>();
    assert_send_sync::<DataRef>();
    assert_send_sync::<AnchorEntry>();
    assert_send_sync::<RegistryReceipt>();
    assert_send_sync::<ReceiptKeyStatus>();
    assert_send_sync::<KeyRevocation>();
    assert_send_sync::<LifecycleEvent>();
    assert_send_sync::<LogCheckpoint>();
    assert_send_sync::<LogInclusion>();
    assert_send_sync::<LogCosignature>();
    assert_send_sync::<WireError>();
}
