//! Read authentication (RFC-ACDP-0008 §6.2, 0.5.0 `bearer_jwt`;
//! acdp-rs#385 item 11): an `AuthProvider` makes a registry with
//! `anonymous_public_reads: false` answerable — including revocation
//! discovery, which is otherwise `unknown (unanswerable)` — and its tokens
//! are scoped per authority, read-only, and never leaked.

mod common;
mod world;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use acdp::client::{
    find_revocations_verdict, AuthFuture, AuthProvider, BearerToken, CrossRegistryResolver,
    PerAuthorityTokens, RevocationDiscovery, RevocationEffect, RevocationPolicy, RevocationVerdict,
    StaticBearerToken, UnknownReason, VerificationPolicy, VerifiedContext,
};
use acdp::error::AcdpError;
use acdp::types::ContextType;
use world::*;

const TOKEN: &str = "eyJhbGciOiJFZERTQSJ9.eyJhdWQiOiJkaWQ6d2ViOmxvY2FsaG9zdCJ9.c2ln";

fn token(s: &str) -> BearerToken {
    BearerToken::new(s).unwrap()
}

fn both_keys() -> serde_json::Value {
    producer_doc(&[("key-1", K1), ("key-2", K2)], &["key-1", "key-2"])
}

fn discovery_policy() -> RevocationPolicy {
    RevocationPolicy::default().with_discovery(RevocationDiscovery::producer_signed_only())
}

/// A provider that counts `token_rejected` calls.
struct Counting {
    inner: StaticBearerToken,
    rejected: AtomicUsize,
}

impl AuthProvider for Counting {
    fn bearer_token<'a>(&'a self, authority: &'a str) -> AuthFuture<'a> {
        self.inner.bearer_token(authority)
    }
    fn token_rejected(&self, authority: &str) {
        assert_eq!(authority, REGISTRY_AUTHORITY);
        self.rejected.fetch_add(1, Ordering::SeqCst);
    }
}

/// Acceptance: a 403 registry becomes answerable when a token is
/// configured — for retrieval and for revocation discovery.
#[tokio::test]
async fn bearer_token_makes_a_403_registry_answerable() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    w.publish_revocation_of_k1("key-2", K2).await;
    w.require_bearer(Some(TOKEN));
    let resolver = w.resolver();

    // Anonymous: retrieval is refused, discovery is unknown(unanswerable).
    let anon = w.client();
    let err = anon.retrieve(&ctx.body.ctx_id).await.unwrap_err();
    assert!(matches!(err, AcdpError::NotAuthorized(_)), "{err:?}");
    let a = find_revocations_verdict(&anon, &resolver, &agent(), K1_FP, None, &discovery_policy())
        .await
        .unwrap();
    assert_eq!(
        a.verdict.unknown_reason(),
        Some(UnknownReason::Unanswerable),
        "{:?}",
        a.verdict
    );

    // With the registry's token: both answer, and the revocation applies.
    let authed = w
        .client()
        .with_auth_provider(Arc::new(StaticBearerToken::new(
            REGISTRY_AUTHORITY,
            token(TOKEN),
        )));
    assert!(authed.has_auth_provider());
    let policy = VerificationPolicy {
        revocations: discovery_policy(),
        ..VerificationPolicy::default()
    };
    let err = VerifiedContext::fetch_with_policy(&authed, &resolver, &ctx.body.ctx_id, &policy)
        .await
        .expect_err("K1 is revoked as of a boundary before this context's receipt");
    assert_eq!(
        err.revocation_refusal().expect("KeyRevoked").effect,
        RevocationEffect::Revoked,
        "{err}"
    );
    let b = find_revocations_verdict(
        &authed,
        &resolver,
        &agent(),
        K1_FP,
        None,
        &discovery_policy(),
    )
    .await
    .unwrap();
    assert!(
        !matches!(b.verdict, RevocationVerdict::Unknown { .. }),
        "discovery answered: {:?}",
        b.verdict
    );

    let sent = w.auth_headers_for("/contexts");
    assert!(sent.contains(&Some(format!("Bearer {TOKEN}"))));
}

/// A token is presented only to the authority it was issued for: a
/// provider holding a token for another registry sends nothing here.
#[tokio::test]
async fn token_is_never_sent_to_another_authority() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let client = w.client().with_auth_provider(Arc::new(
        PerAuthorityTokens::new().with("other.example", token("secret-for-other")),
    ));
    client.retrieve(&ctx.body.ctx_id).await.unwrap();
    let seen = w.auth_headers_for("/contexts");
    assert!(!seen.is_empty());
    assert!(seen.iter().all(Option::is_none), "{seen:?}");
}

/// Tokens are read-only credentials: the capabilities fetch (public) and
/// DID documents never carry one.
#[tokio::test]
async fn token_is_not_sent_on_capabilities_or_did_fetches() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let client = w
        .client()
        .with_auth_provider(Arc::new(StaticBearerToken::new(
            REGISTRY_AUTHORITY,
            token(TOKEN),
        )));
    client.capabilities().await.unwrap();
    VerifiedContext::fetch(&client, &w.resolver(), &ctx.body.ctx_id)
        .await
        .unwrap();
    for prefix in ["/.well-known/acdp.json", "/.well-known/did.json", "/agent"] {
        let seen = w.auth_headers_for(prefix);
        assert!(seen.iter().all(Option::is_none), "{prefix}: {seen:?}");
    }
    assert!(w
        .auth_headers_for("/contexts")
        .iter()
        .all(|a| a.as_deref() == Some(&*format!("Bearer {TOKEN}"))));
}

/// A rejected token is reported back to the provider so it can refresh;
/// the read itself fails `not_authorized` and is not retried.
#[tokio::test]
async fn rejected_token_is_reported_to_the_provider() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    w.require_bearer(Some(TOKEN));
    let provider = Arc::new(Counting {
        inner: StaticBearerToken::new(REGISTRY_AUTHORITY, token("expired")),
        rejected: AtomicUsize::new(0),
    });
    let client = w.client().with_auth_provider(provider.clone());
    let err = client.retrieve(&ctx.body.ctx_id).await.unwrap_err();
    assert!(matches!(err, AcdpError::NotAuthorized(_)), "{err:?}");
    assert_eq!(provider.rejected.load(Ordering::SeqCst), 1);
    assert_eq!(w.auth_headers_for("/contexts").len(), 1, "not retried");
}

/// An anonymous read through a provider that holds no token never calls
/// `token_rejected` (there was no token to reject).
#[tokio::test]
async fn anonymous_refusal_does_not_report_a_rejection() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    w.require_bearer(Some(TOKEN));
    let provider = Arc::new(Counting {
        inner: StaticBearerToken::new("other.example", token(TOKEN)),
        rejected: AtomicUsize::new(0),
    });
    let client = w.client().with_auth_provider(provider.clone());
    client.retrieve(&ctx.body.ctx_id).await.unwrap_err();
    assert_eq!(provider.rejected.load(Ordering::SeqCst), 0);
}

/// A provider error aborts the read and surfaces unchanged.
#[tokio::test]
async fn provider_error_aborts_the_read() {
    struct Failing;
    impl AuthProvider for Failing {
        fn bearer_token<'a>(&'a self, _: &'a str) -> AuthFuture<'a> {
            Box::pin(async { Err(AcdpError::Http("token service down".into())) })
        }
    }
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let client = w.client().with_auth_provider(Arc::new(Failing));
    let err = client.retrieve(&ctx.body.ctx_id).await.unwrap_err();
    assert!(
        matches!(err, AcdpError::Http(ref m) if m.contains("token service")),
        "{err:?}"
    );
    assert!(w.auth_headers_for("/contexts").is_empty(), "nothing sent");
}

/// Cross-registry: the resolver's provider is consulted per hop
/// authority and attached to a seeded client that has none; a seeded
/// client that carries its own provider keeps it.
#[tokio::test]
async fn cross_registry_resolver_presents_per_authority_tokens() {
    let w = World::start(both_keys()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    w.require_bearer(Some(TOKEN));

    let anon = CrossRegistryResolver::new().with_did_resolver(w.resolver());
    anon.seed_client(REGISTRY_AUTHORITY, w.client());
    anon.resolve(&ctx.body.ctx_id)
        .await
        .expect_err("anonymous walk is refused");

    let tokens = PerAuthorityTokens::new()
        .with(REGISTRY_AUTHORITY, token(TOKEN))
        .with("other.example", token("secret-for-other"));
    let authed = CrossRegistryResolver::new()
        .with_did_resolver(w.resolver())
        .with_auth_provider(Arc::new(tokens));
    authed.seed_client(REGISTRY_AUTHORITY, w.client());
    let v = authed.resolve(&ctx.body.ctx_id).await.expect("answerable");
    assert_eq!(v.body().ctx_id, ctx.body.ctx_id);
    assert!(!w
        .auth_headers_for("/contexts")
        .contains(&Some("Bearer secret-for-other".into())));

    // A seeded client's own provider wins (fill-if-absent).
    let own = CrossRegistryResolver::new()
        .with_did_resolver(w.resolver())
        .with_auth_provider(Arc::new(PerAuthorityTokens::new()));
    own.seed_client(
        REGISTRY_AUTHORITY,
        w.client()
            .with_auth_provider(Arc::new(StaticBearerToken::new(
                REGISTRY_AUTHORITY,
                token(TOKEN),
            ))),
    );
    own.resolve(&ctx.body.ctx_id)
        .await
        .expect("own provider kept");
}
