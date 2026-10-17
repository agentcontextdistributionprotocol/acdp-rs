//! Read authentication (RFC-ACDP-0008 §6.2, 0.5.0 `bearer_jwt`).
//!
//! A registry that serves non-public contexts, or that sets
//! `anonymous_public_reads: false`, answers an unauthenticated read with
//! `not_authorized`. Revocation discovery against such a vantage is then
//! `unknown` (`unanswerable`), never not-revoked. An [`AuthProvider`]
//! attached to a [`RegistryClient`](crate::RegistryClient) or a
//! [`CrossRegistryResolver`](crate::CrossRegistryResolver) makes those reads
//! answerable by presenting `Authorization: Bearer <token>` (RFC 6750).
//!
//! The provider is asked for a token **per request, by authority** — the
//! host (plus non-default port) of the registry being read. A
//! `bearer_jwt` token's `aud` is the registry that minted it, and that
//! registry MUST reject any other audience; asking by authority keeps one
//! registry's token from ever being presented to another, including on a
//! cross-registry walk. Minting the token (the signed-challenge exchange)
//! is deployment-defined and outside the protocol, so it is the provider's
//! job; this crate only presents what the provider returns.
//!
//! Tokens are attached only to **read** requests (retrieve, lineage,
//! current, search), only over `https`, and never on a redirect to another
//! authority (the client follows same-authority redirects only). A bearer
//! token never substitutes for a producer signature on a write
//! (RFC-ACDP-0008 §6.2), so `publish*` never sends one, and neither does
//! the public capabilities fetch.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use acdp_primitives::AcdpError;

/// The boxed future an [`AuthProvider`] returns. Boxed because the trait
/// is used as `dyn AuthProvider` and the MSRV (1.86) has no `async fn` in
/// object-safe traits.
pub type AuthFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<BearerToken>, AcdpError>> + Send + 'a>>;

/// A bearer token. `Debug` and `Display` never print it.
#[derive(Clone, PartialEq, Eq)]
pub struct BearerToken(Arc<str>);

impl BearerToken {
    /// Wrap a token string (the compact JWT, without the `Bearer ` prefix).
    ///
    /// # Errors
    /// [`AcdpError::SchemaViolation`] when the token is empty or contains a
    /// character that is not valid in an RFC 6750 `b64token` (so it can
    /// never inject a header line).
    pub fn new(token: impl Into<String>) -> Result<Self, AcdpError> {
        let token = token.into();
        // b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
        let core = token.trim_end_matches('=');
        let valid = !core.is_empty()
            && core.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
            });
        if !valid {
            return Err(AcdpError::SchemaViolation(
                "bearer token must be a non-empty RFC 6750 b64token".into(),
            ));
        }
        Ok(Self(token.into()))
    }

    /// The token string. Handle with care: whoever holds it can replay it
    /// until it expires.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

/// Supplies read credentials per registry authority (RFC-ACDP-0008 §6.2).
///
/// Implement this to plug in a token source that refreshes before `exp`
/// (registries SHOULD keep `bearer_jwt` lifetimes short). Return
/// `Ok(None)` for an authority you hold no credential for: the read goes
/// out anonymously. An `Err` aborts the read and is returned to the caller
/// unchanged; during revocation discovery it becomes `unknown` with the
/// reason its error class maps to.
pub trait AuthProvider: Send + Sync {
    /// The token to present to `authority` (host, plus port when
    /// non-default — the same value as
    /// [`RegistryClient::authority`](crate::RegistryClient::authority)).
    fn bearer_token<'a>(&'a self, authority: &'a str) -> AuthFuture<'a>;

    /// Called when `authority` answered a read that carried this
    /// provider's token with HTTP 401 or 403 — the token may have expired
    /// or been revoked. Drop any cached token for `authority` here so the
    /// next read fetches a fresh one. The rejected read itself is not
    /// retried. Default: no-op.
    fn token_rejected(&self, authority: &str) {
        let _ = authority;
    }
}

impl fmt::Debug for dyn AuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dyn AuthProvider")
    }
}

/// One token for exactly one authority. Use on a [`RegistryClient`] that
/// talks to a single registry.
///
/// [`RegistryClient`]: crate::RegistryClient
#[derive(Debug, Clone)]
pub struct StaticBearerToken {
    authority: String,
    token: BearerToken,
}

impl StaticBearerToken {
    /// Present `token` to `authority` and to no other.
    #[must_use]
    pub fn new(authority: impl Into<String>, token: BearerToken) -> Self {
        Self {
            authority: authority.into().to_ascii_lowercase(),
            token,
        }
    }
}

impl AuthProvider for StaticBearerToken {
    fn bearer_token<'a>(&'a self, authority: &'a str) -> AuthFuture<'a> {
        let token = authority
            .eq_ignore_ascii_case(&self.authority)
            .then(|| self.token.clone());
        Box::pin(async move { Ok(token) })
    }
}

/// A token per authority, replaceable at runtime — the shape a
/// [`CrossRegistryResolver`](crate::CrossRegistryResolver) walk across
/// several registries needs. Cheap to clone (an `Arc` handle); a clone
/// shares the table, so a background task can refresh tokens with
/// [`Self::set`] while readers use them.
#[derive(Debug, Clone, Default)]
pub struct PerAuthorityTokens {
    tokens: Arc<RwLock<HashMap<String, BearerToken>>>,
}

impl PerAuthorityTokens {
    /// An empty table: every read goes out anonymously until [`Self::set`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Present `token` to `authority`, replacing any previous token.
    #[must_use]
    pub fn with(self, authority: impl Into<String>, token: BearerToken) -> Self {
        self.set(authority, token);
        self
    }

    /// Present `token` to `authority`, replacing any previous token.
    pub fn set(&self, authority: impl Into<String>, token: BearerToken) {
        self.tokens
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(authority.into().to_ascii_lowercase(), token);
    }

    /// Stop presenting a token to `authority`.
    pub fn remove(&self, authority: &str) {
        self.tokens
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&authority.to_ascii_lowercase());
    }
}

impl AuthProvider for PerAuthorityTokens {
    fn bearer_token<'a>(&'a self, authority: &'a str) -> AuthFuture<'a> {
        let token = self
            .tokens
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&authority.to_ascii_lowercase())
            .cloned();
        Box::pin(async move { Ok(token) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(s: &str) -> BearerToken {
        BearerToken::new(s).unwrap()
    }

    #[test]
    fn token_debug_is_redacted() {
        let t = tok("eyJhbGciOiJFZERTQSJ9.e30.c2ln");
        assert_eq!(format!("{t:?}"), "BearerToken(<redacted>)");
        let p = StaticBearerToken::new("r.example", t);
        assert!(!format!("{p:?}").contains("eyJ"));
    }

    #[test]
    fn token_rejects_header_injection_and_empty() {
        assert!(BearerToken::new("").is_err());
        assert!(BearerToken::new("abc\r\nX-Evil: 1").is_err());
        assert!(BearerToken::new("a b").is_err());
        assert!(
            BearerToken::new("a=b").is_err(),
            "'=' only as trailing padding"
        );
        assert!(BearerToken::new("abc==").is_ok());
        assert!(BearerToken::new("a-b.c_d~e+f/g").is_ok());
    }

    #[tokio::test]
    async fn static_token_is_scoped_to_its_authority() {
        let p = StaticBearerToken::new("Registry.Example", tok("t1"));
        assert_eq!(
            p.bearer_token("registry.example").await.unwrap(),
            Some(tok("t1"))
        );
        assert_eq!(p.bearer_token("other.example").await.unwrap(), None);
        assert_eq!(
            p.bearer_token("registry.example:8443").await.unwrap(),
            None,
            "a different port is a different authority"
        );
    }

    #[tokio::test]
    async fn per_authority_tokens_are_shared_and_replaceable() {
        let p = PerAuthorityTokens::new().with("a.example", tok("ta"));
        let reader = p.clone();
        assert_eq!(
            reader.bearer_token("a.example").await.unwrap(),
            Some(tok("ta"))
        );
        assert_eq!(reader.bearer_token("b.example").await.unwrap(), None);
        p.set("A.example", tok("ta2"));
        assert_eq!(
            reader.bearer_token("a.example").await.unwrap(),
            Some(tok("ta2"))
        );
        p.remove("a.example");
        assert_eq!(reader.bearer_token("a.example").await.unwrap(), None);
    }
}
