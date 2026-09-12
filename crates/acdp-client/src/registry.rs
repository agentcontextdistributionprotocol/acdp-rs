//! HTTP client for ACDP registries (feature = "client").

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use acdp_primitives::error::AcdpError;
use acdp_primitives::limits::{
    CONNECT_TIMEOUT, MAX_CONTEXT_BYTES, MAX_METADATA_BYTES, MAX_REDIRECTS, REQUEST_TIMEOUT,
};
use acdp_safe_http::SsrfPolicy;
use acdp_types::{
    body::FullContext,
    capabilities::CapabilitiesDocument,
    primitives::{CtxId, LineageId},
    publish::{PublishRequest, PublishResponse, WireError},
    search::{SearchParams, SearchResponse},
};
use chrono::{DateTime, Utc};
use reqwest::{redirect, Client};

use crate::revocation_cache::RevocationCache;

/// HTTP client for a single ACDP registry.
///
/// `reqwest::Client` clones cheaply (it's an `Arc` internally), so this
/// struct is `Clone` to enable per-authority caching in
/// [`crate::CrossRegistryResolver`] without re-wiring HTTP+TLS
/// state on every hop. The same is true of `budget` (issue #258): it is
/// an `Option<DiscoveryBudget>`, and `DiscoveryBudget` is itself an
/// `Arc` handle, so cloning a client that carries a budget shares the
/// counters rather than resetting them — the shape
/// [`RevocationDiscovery`](crate::verified::RevocationDiscovery)
/// depends on: `verify_retrieved` attaches one `DiscoveryBudget` to a
/// single client clone and hands that SAME clone to both trust-class
/// lookups.
///
/// `revocation_cache` (issue #257) is the same shape again: an
/// `Option<RevocationCache>`, itself an `Arc` handle, so cloning a client
/// that carries a cache shares the underlying store rather than resetting
/// it. Unlike `budget`, it is caller-injectable via
/// [`Self::with_revocation_cache`] on ANY client, not only the
/// discovery-scoped clone `verify_retrieved` builds internally — a caller
/// verifying many contexts against the same producer attaches one cache up
/// front and every subsequent discovery benefits. `revocation_freshness`
/// travels alongside it: `verify_retrieved` overrides it per call from
/// `RevocationDiscovery::freshness` (crate-private
/// `with_revocation_freshness`, crate-private), while a cache attached directly
/// via `with_revocation_cache` defaults to `Duration::ZERO` — pure seeding,
/// no marker ever suppresses a lookup, until the caller explicitly opts in
/// through a discovery configuration's `freshness` field.
#[derive(Clone)]
pub struct RegistryClient {
    base: String,
    http: Client,
    budget: Option<DiscoveryBudget>,
    revocation_cache: Option<RevocationCache>,
    revocation_freshness: Duration,
}

/// Combined request-count and cumulative-byte budget for RFC-ACDP-0014
/// §8 revocation auto-discovery (issue #258, decision D-B).
///
/// Attached to a [`RegistryClient`] clone created once per discovery
/// call (`acdp_client::verified::verify_retrieved`) via
/// [`RegistryClient::with_discovery_budget`], and shared — via this
/// type's own internal `Arc` — by both trust-class lookups running
/// concurrently under `tokio::try_join!`, so the two lookups draw down
/// ONE combined ceiling rather than a ceiling each.
///
/// `pub(crate)`: `verify_retrieved` is the only intended caller. There
/// is deliberately no public `find_revocations_with_budget` or similar
/// — a public budget type would be a permanent commitment to a shape
/// nothing outside this crate needs (see the wave plan's D-B).
///
/// Bounds **registry** traffic only: DID-document fetches issued via
/// `WebResolver` (inside `verify_revocation_body`) do not pass through
/// `RegistryClient` and are not counted. Bounds **successfully-parsed
/// response bodies** only: `parse_success`'s non-success branch reads
/// up to 64 KB of an error envelope, and that read is never charged to
/// the byte budget.
#[derive(Clone)]
pub(crate) struct DiscoveryBudget {
    inner: Arc<DiscoveryBudgetInner>,
}

struct DiscoveryBudgetInner {
    max_requests: Option<NonZeroUsize>,
    max_bytes: Option<u64>,
    requests_used: AtomicUsize,
    bytes_used: AtomicU64,
}

impl DiscoveryBudget {
    /// Build a budget from `RevocationDiscovery`'s two knobs. `None`
    /// for either means that dimension is unbounded — passing `None`
    /// for both makes every check a no-op, preserving pre-#258
    /// behavior exactly.
    pub(crate) fn new(max_requests: Option<NonZeroUsize>, max_bytes: Option<u64>) -> Self {
        Self {
            inner: Arc::new(DiscoveryBudgetInner {
                max_requests,
                max_bytes,
                requests_used: AtomicUsize::new(0),
                bytes_used: AtomicU64::new(0),
            }),
        }
    }

    /// Check-and-reserve, called at the top of each of
    /// `RegistryClient`'s four discovery-reachable request methods
    /// (`capabilities`/`capabilities_with_ttl`, `retrieve`, `lineage`,
    /// `search`) — BEFORE the request is issued. This is what makes
    /// check-before-issue structural rather than a discipline: a
    /// budget error returned here can never be issued as a wasted
    /// request the way `MAX_LINEAGE_WALKS`'s after-the-fact check can.
    ///
    /// The byte check runs first and is a plain load with no side
    /// effect, so a budget that is already byte-exhausted never
    /// consumes a request-count reservation it will not use.
    ///
    /// The request-count check is an atomic `fetch_update`
    /// compare-exchange loop, not load-then-store: two lookups racing
    /// under `try_join!` against the same remaining count can never
    /// both observe room for the last slot.
    fn check_before_request(&self) -> Result<(), AcdpError> {
        if let Some(max_bytes) = self.inner.max_bytes {
            if self.inner.bytes_used.load(Ordering::SeqCst) >= max_bytes {
                return Err(AcdpError::RevocationDiscoveryBudgetExceeded(format!(
                    "revocation discovery exceeded max_bytes={max_bytes}"
                )));
            }
        }
        if let Some(max_requests) = self.inner.max_requests {
            let max_requests = max_requests.get();
            let reserved =
                self.inner
                    .requests_used
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                        if used < max_requests {
                            Some(used + 1)
                        } else {
                            None
                        }
                    });
            if reserved.is_err() {
                return Err(AcdpError::RevocationDiscoveryBudgetExceeded(format!(
                    "revocation discovery exceeded max_requests={max_requests}"
                )));
            }
        }
        Ok(())
    }

    /// Add the bytes of a just-completed successful response to the
    /// running total. Not a check — overrun is only observed by the
    /// NEXT [`Self::check_before_request`] call, since the size of an
    /// in-flight request cannot be known (and therefore reserved) in
    /// advance.
    fn record_bytes(&self, n: usize) {
        self.inner.bytes_used.fetch_add(n as u64, Ordering::SeqCst);
    }
}

/// Cache and integrity headers returned alongside a retrieved body.
///
/// `etag` is the body's `content_hash` (immutable; ideal cache key).
/// `cache_control` and `last_modified` are reported verbatim from the
/// upstream registry.
#[derive(Debug, Clone, Default)]
pub struct RetrievalMetadata {
    /// Strong validator for conditional retrieval (`If-None-Match`).
    pub etag: Option<String>,
    /// Raw `Cache-Control` header value, if any.
    pub cache_control: Option<String>,
    /// Parsed `Last-Modified` header, if any.
    pub last_modified: Option<DateTime<Utc>>,
}

impl RegistryClient {
    /// The authority (host, plus port when non-default) of the registry
    /// this client talks to — the value a receipt's `registry_did`
    /// must match (RFC-ACDP-0010 serving-authority cross-check).
    pub fn authority(&self) -> Option<String> {
        url::Url::parse(&self.base).ok().and_then(|u| {
            let host = u.host_str()?.to_string();
            Some(match u.port() {
                Some(p) => format!("{host}:{p}"),
                None => host,
            })
        })
    }

    /// Return a clone of this client with `budget` attached, replacing
    /// any budget the original carried. Issue #258: `verify_retrieved`
    /// calls this exactly once per discovery, on a client clone it then
    /// hands to BOTH trust-class lookups, so the two lookups share one
    /// combined counter rather than getting one each. The original
    /// client (and any other clone of it) is unaffected — traffic
    /// issued through it is never charged to this budget.
    pub(crate) fn with_discovery_budget(&self, budget: DiscoveryBudget) -> Self {
        Self {
            base: self.base.clone(),
            http: self.http.clone(),
            budget: Some(budget),
            revocation_cache: self.revocation_cache.clone(),
            revocation_freshness: self.revocation_freshness,
        }
    }

    /// Check-and-reserve against this client's attached budget, if any.
    /// A no-op `Ok(())` when no budget is attached (the common case —
    /// budgets exist only on discovery-scoped clones).
    fn check_discovery_budget(&self) -> Result<(), AcdpError> {
        match &self.budget {
            Some(budget) => budget.check_before_request(),
            None => Ok(()),
        }
    }

    /// Record a successful response's byte count against this client's
    /// attached budget, if any.
    fn record_discovery_bytes(&self, n: usize) {
        if let Some(budget) = &self.budget {
            budget.record_bytes(n);
        }
    }

    /// Return a clone of this client with `cache` attached (issue #257),
    /// replacing any cache the original carried, and resetting
    /// `revocation_freshness` to `Duration::ZERO` — pure seeding by
    /// default, following [`crate::verified::RevocationDiscovery`]'s own
    /// zero default. Attach a cache once and reuse the returned client
    /// across many `VerifiedContext::fetch*` calls against the same
    /// producer(s) to amortize RFC-ACDP-0014 §8 discovery: facts persist
    /// (indefinitely, per §7:114) across calls regardless of `freshness`;
    /// setting a discovery configuration's `freshness` above zero
    /// additionally lets a fresh marker skip a repeat lookup entirely — see
    /// `crate::revocation_cache` for the two-object model.
    pub fn with_revocation_cache(&self, cache: RevocationCache) -> Self {
        Self {
            base: self.base.clone(),
            http: self.http.clone(),
            budget: self.budget.clone(),
            revocation_cache: Some(cache),
            revocation_freshness: Duration::ZERO,
        }
    }

    /// Return a clone of this client with `freshness` overriding whatever
    /// `revocation_freshness` it carried, leaving `revocation_cache`
    /// (attached or not) unchanged. `verify_retrieved` calls this on the
    /// same discovery-scoped clone it already built via
    /// [`Self::with_discovery_budget`], threading through
    /// `RevocationDiscovery::freshness` — never a caller-facing knob on its
    /// own, since freshness is a per-discovery-call policy, not a
    /// per-client one.
    pub(crate) fn with_revocation_freshness(&self, freshness: Duration) -> Self {
        Self {
            base: self.base.clone(),
            http: self.http.clone(),
            budget: self.budget.clone(),
            revocation_cache: self.revocation_cache.clone(),
            revocation_freshness: freshness,
        }
    }

    /// This client's attached revocation cache and its current freshness
    /// setting, if a cache is attached. `crate::revocation`'s two discovery
    /// functions read this — never `&VerificationPolicy` — to check/mint
    /// freshness markers and to record newly-discovered facts.
    pub(crate) fn revocation_cache(&self) -> Option<(&RevocationCache, Duration)> {
        self.revocation_cache
            .as_ref()
            .map(|cache| (cache, self.revocation_freshness))
    }

    /// Connect to a registry at `base_url` (e.g. `https://registry.example.com`).
    ///
    /// Uses `rustls` for TLS; does not use the system OpenSSL. Applies
    /// the RFC-ACDP-0006 §7.4 default timeouts (5s connect, 30s total)
    /// and §7.5 redirect policy (max 3 follows, same authority only).
    ///
    /// # DNS-rebinding posture (default)
    ///
    /// This constructor installs the **`SafeDnsResolver` DNS hook**
    /// (RFC-ACDP-0006 §7.6): every hostname lookup — the first connect,
    /// each redirect, and every reconnect the pool makes over the
    /// client's lifetime — is filtered through the [`SsrfPolicy`] *at
    /// DNS time, before any TCP connect*. This is **strictly stronger
    /// than pin-once resolution** ([`Self::new_pinned`]): a pinned
    /// client validates a single answer and reuses that address, so a
    /// hostile authoritative DNS server that only later flips a name
    /// into a forbidden range is still caught here but not there. The
    /// DNS-hook posture is therefore the default for all callers; reach
    /// for [`Self::builder`] only when you need a non-default knob (a
    /// private root cert, a custom [`SsrfPolicy`], timeout overrides, or
    /// the legacy pinned mode).
    pub fn new(base_url: &str) -> Result<Self, AcdpError> {
        Self::build(base_url, None, None, SsrfPolicy::default())
    }

    /// Start a [`RegistryClientBuilder`] for the non-default connection
    /// postures — a private root certificate, a custom [`SsrfPolicy`],
    /// timeout overrides, and the legacy pinned-resolution mode.
    ///
    /// The builder's *default* is identical to [`Self::new`]: the
    /// stronger `SafeDnsResolver` DNS-hook posture with the default
    /// SSRF policy and the RFC-ACDP-0006 §7.4 timeouts. Opt into
    /// pin-once resolution with [`RegistryClientBuilder::pinned`].
    pub fn builder(base_url: &str) -> RegistryClientBuilder {
        RegistryClientBuilder::new(base_url)
    }

    /// Connect to a registry that trusts the given PEM-encoded root
    /// certificate in addition to the system roots.
    ///
    /// Primary use is the in-process self-signed HTTPS server in the
    /// crate's `tests/helpers/tls_did_server.rs` harness so the spec
    /// fixtures `fed-001..006` can drive `CrossRegistryResolver`
    /// end-to-end without going over the network.
    #[cfg(feature = "test-transport")]
    pub fn with_root_cert_pem(base_url: &str, pem: &[u8]) -> Result<Self, AcdpError> {
        // Drives an in-process HTTPS server on loopback, so the SSRF
        // policy must permit a loopback-resolved answer. All other
        // forbidden ranges (RFC 1918, IMDS, …) still apply.
        Self::build(base_url, Some(pem), None, SsrfPolicy::allow_test_loopback())
    }

    /// Test-only permissive transport: allows `http://`, IP-literal hosts,
    /// and loopback so the crate's in-process mock HTTP servers (e.g.
    /// `wiremock`, which binds `http://127.0.0.1:<port>`) can be driven.
    ///
    /// Production MUST use [`Self::new`], which applies the full
    /// RFC-ACDP-0006 §7 / RFC-ACDP-0008 SSRF + HTTPS-only + DNS-rebinding
    /// posture. This constructor exists solely to keep the test harness on
    /// loopback HTTP.
    #[doc(hidden)]
    #[cfg(feature = "test-transport")]
    pub fn with_test_transport(base_url: &str) -> Result<Self, AcdpError> {
        let policy = SsrfPolicy {
            reject_ip_literals: false,
            allow_http: true,
            allow_loopback_resolved: true,
        };
        Self::build(base_url, None, None, policy)
    }

    /// Connect to a registry whose `<authority>` in `base_url` is routed
    /// to a fixed socket address. Trusts the given PEM-encoded root
    /// certificate in addition to the system roots.
    ///
    /// Use only in tests: a `CrossRegistryResolver` test that wants to
    /// drive `acdp://<host>/<uuid>` references requires `<host>` to be
    /// a valid lowercase DNS label (per `is_valid_dns_authority` in
    /// `types::primitives`), which precludes embedding the port in the
    /// `ctx_id`. This factory accepts a logical hostname (e.g.
    /// `localhost`) and pins it to the test server's actual
    /// `127.0.0.1:<port>` via reqwest's `.resolve()` hook.
    #[doc(hidden)]
    #[cfg(feature = "test-transport")]
    pub fn with_test_endpoint(
        base_url: &str,
        target: std::net::SocketAddr,
        pem: &[u8],
    ) -> Result<Self, AcdpError> {
        // Pins a logical hostname to a loopback test endpoint; permit the
        // loopback answer while keeping every other forbidden range live.
        Self::build(
            base_url,
            Some(pem),
            Some(target),
            SsrfPolicy::allow_test_loopback(),
        )
    }

    fn build(
        base_url: &str,
        extra_root_pem: Option<&[u8]>,
        resolve_target: Option<std::net::SocketAddr>,
        policy_ssrf: SsrfPolicy,
    ) -> Result<Self, AcdpError> {
        RegistryClientBuilder {
            base_url: base_url.to_string(),
            pinned: false,
            ssrf_policy: policy_ssrf,
            root_cert_pem: extra_root_pem.map(<[u8]>::to_vec),
            resolve_target,
            connect_timeout: CONNECT_TIMEOUT,
            request_timeout: REQUEST_TIMEOUT,
        }
        .build_blocking()
    }

    /// Connect to a registry with pin-once DNS-rebinding protection
    /// (RFC-ACDP-0006 §7.6).
    ///
    /// Resolves the hostname once, validates the resolved IP against
    /// `policy`, then pins that IP into the HTTP client.
    ///
    /// **Deprecated:** the default [`Self::new`] posture installs the
    /// `SafeDnsResolver` DNS hook, which validates the resolved IP on
    /// *every* connection (including reconnects) rather than just once —
    /// strictly stronger protection. For the rare case that still wants
    /// pin-once semantics with a custom policy, use
    /// `RegistryClient::builder(base_url).pinned(true).ssrf_policy(policy).build().await`.
    #[deprecated(
        since = "0.4.0",
        note = "prefer `RegistryClient::new` (SafeDnsResolver DNS hook — validates every \
                connection, strictly stronger than pin-once) or, for explicit pin-once mode, \
                `RegistryClient::builder(base_url).pinned(true).ssrf_policy(policy).build().await`"
    )]
    pub async fn new_pinned(base_url: &str, policy: &SsrfPolicy) -> Result<Self, AcdpError> {
        Self::builder(base_url)
            .pinned(true)
            .ssrf_policy(policy.clone())
            .build()
            .await
    }

    // ── Capabilities ────────────────────────────────────────────────────────

    /// Fetch the registry's capabilities document and run the
    /// RFC-ACDP-0007 §3 runtime validation
    /// ([`acdp_validation::validate_capabilities`]).
    ///
    /// Body capped at 64 KB per RFC-ACDP-0006 §7.3.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn capabilities(&self) -> Result<CapabilitiesDocument, AcdpError> {
        Ok(self.capabilities_with_ttl().await?.0)
    }

    /// Like [`Self::capabilities`] but also returns the cache TTL
    /// derived from the response's `Cache-Control: max-age=N` header.
    ///
    /// Per RFC-ACDP-0006 §4.2, consumers SHOULD cache the capabilities
    /// document for `min(max-age, 3600s)` seconds. When no
    /// `Cache-Control` (or no parseable `max-age`) is returned, the
    /// fallback is `300s` — a conservative middle-ground that matches
    /// [`crate::ResolverOptions::capabilities_ttl`]'s default.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn capabilities_with_ttl(
        &self,
    ) -> Result<(CapabilitiesDocument, std::time::Duration), AcdpError> {
        self.check_discovery_budget()?;
        let url = format!("{}/.well-known/acdp.json", self.base);
        let resp = self.http.get(&url).send().await?;
        let ttl = cache_ttl_from_response(&resp);
        let (caps, nbytes): (CapabilitiesDocument, usize) =
            self.parse_success(resp, MAX_METADATA_BYTES).await?;
        self.record_discovery_bytes(nbytes);
        acdp_validation::validate_capabilities(&caps)?;
        Ok((caps, ttl))
    }

    // ── Publish ─────────────────────────────────────────────────────────────

    /// Publish a context.  Returns the registry-assigned identifiers.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, req)))]
    pub async fn publish(&self, req: &PublishRequest) -> Result<PublishResponse, AcdpError> {
        let url = format!("{}/contexts", self.base);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/acdp+json")
            .json(req)
            .send()
            .await?;
        self.parse_success(resp, MAX_METADATA_BYTES)
            .await
            .map(|(v, _)| v)
    }

    /// Publish with an idempotency key for safe retries.
    pub async fn publish_idempotent(
        &self,
        req: &PublishRequest,
        idempotency_key: &str,
    ) -> Result<PublishResponse, AcdpError> {
        let url = format!("{}/contexts", self.base);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/acdp+json")
            .header("Idempotency-Key", idempotency_key)
            .json(req)
            .send()
            .await?;
        self.parse_success(resp, MAX_METADATA_BYTES)
            .await
            .map(|(v, _)| v)
    }

    /// Publish with bounded retry for transient failures.
    ///
    /// Reuses `idempotency_key` across attempts so the registry can
    /// dedupe (RFC-ACDP-0003 §6). Retries only when the error is
    /// transient per [`AcdpError::is_transient`]. Bounded backoff:
    /// 250 ms, 500 ms, 1 s, 2 s.
    pub async fn publish_with_retry(
        &self,
        req: &PublishRequest,
        idempotency_key: &str,
        max_attempts: u32,
    ) -> Result<PublishResponse, AcdpError> {
        let attempts = max_attempts.max(1);
        let mut last_err: Option<AcdpError> = None;
        for attempt in 0..attempts {
            match self.publish_idempotent(req, idempotency_key).await {
                Ok(resp) => return Ok(resp),
                Err(e) if e.is_transient() && attempt + 1 < attempts => {
                    let backoff_ms = 250u64 * (1 << attempt.min(3));
                    last_err = Some(e);
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        attempt = attempt + 1,
                        backoff_ms,
                        "publish transient failure; retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err
            .unwrap_or_else(|| AcdpError::Http("publish_with_retry exhausted attempts".into())))
    }

    // ── Retrieval ────────────────────────────────────────────────────────────

    /// Retrieve a full context (body + registry_state) by ctx_id.
    ///
    /// Body capped at 1 MB per RFC-ACDP-0006 §7.3.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), fields(ctx_id = %ctx_id)))]
    pub async fn retrieve(&self, ctx_id: &CtxId) -> Result<FullContext, AcdpError> {
        self.check_discovery_budget()?;
        let encoded = urlencoding::encode(ctx_id.as_str());
        let url = format!("{}/contexts/{}", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        let (body, nbytes) = self.parse_success(resp, MAX_CONTEXT_BYTES).await?;
        self.record_discovery_bytes(nbytes);
        Ok(body)
    }

    /// Retrieve a full context plus cache / integrity headers.
    pub async fn retrieve_with_metadata(
        &self,
        ctx_id: &CtxId,
    ) -> Result<(FullContext, RetrievalMetadata), AcdpError> {
        let encoded = urlencoding::encode(ctx_id.as_str());
        let url = format!("{}/contexts/{}", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        let metadata = parse_retrieval_metadata(&resp);
        let (body, _) = self.parse_success(resp, MAX_CONTEXT_BYTES).await?;
        Ok((body, metadata))
    }

    /// Conditional retrieval using `If-None-Match`.
    ///
    /// Returns `Ok(None)` when the registry responds 304 Not Modified.
    /// Returns `Ok(Some((body, metadata)))` for a fresh retrieval.
    pub async fn retrieve_if_none_match(
        &self,
        ctx_id: &CtxId,
        etag: &str,
    ) -> Result<Option<(FullContext, RetrievalMetadata)>, AcdpError> {
        let encoded = urlencoding::encode(ctx_id.as_str());
        let url = format!("{}/contexts/{}", self.base, encoded);
        let resp = self
            .http
            .get(&url)
            .header("If-None-Match", etag)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(None);
        }
        let metadata = parse_retrieval_metadata(&resp);
        let (body, _) = self.parse_success(resp, MAX_CONTEXT_BYTES).await?;
        Ok(Some((body, metadata)))
    }

    /// Retrieve just the body (immutable, highly cacheable).
    pub async fn retrieve_body(&self, ctx_id: &CtxId) -> Result<acdp_types::body::Body, AcdpError> {
        let encoded = urlencoding::encode(ctx_id.as_str());
        let url = format!("{}/contexts/{}/body", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        self.parse_success(resp, MAX_CONTEXT_BYTES)
            .await
            .map(|(v, _)| v)
    }

    // ── Lineage ──────────────────────────────────────────────────────────────

    /// Retrieve all contexts in a lineage (oldest to newest).
    pub async fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError> {
        self.check_discovery_budget()?;
        let encoded = urlencoding::encode(lineage_id.as_str());
        let url = format!("{}/lineages/{}", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        let (value, nbytes) = self
            .parse_success::<serde_json::Value>(resp, MAX_CONTEXT_BYTES)
            .await?;
        self.record_discovery_bytes(nbytes);
        serde_json::from_value(value).map_err(|e| AcdpError::Serialization(e.to_string()))
    }

    /// Retrieve the current (latest) context in a lineage.
    pub async fn current(&self, lineage_id: &LineageId) -> Result<FullContext, AcdpError> {
        let encoded = urlencoding::encode(lineage_id.as_str());
        let url = format!("{}/lineages/{}/current", self.base, encoded);
        let resp = self.http.get(&url).send().await?;
        self.parse_success(resp, MAX_CONTEXT_BYTES)
            .await
            .map(|(v, _)| v)
    }

    // ── Discovery ────────────────────────────────────────────────────────────

    /// Keyword search across the registry.
    ///
    /// Body capped at 64 KB (search responses are projection-summaries —
    /// IMP-03: not the 1 MB context cap).
    pub async fn search(&self, params: &SearchParams) -> Result<SearchResponse, AcdpError> {
        self.check_discovery_budget()?;
        let url = format!("{}/contexts/search", self.base);
        let resp = self.http.get(&url).query(params).send().await?;
        let (result, nbytes) = self.parse_success(resp, MAX_METADATA_BYTES).await?;
        self.record_discovery_bytes(nbytes);
        Ok(result)
    }

    /// Begin a fluent search via [`RegistrySearch`]. Chains parameters
    /// with strong typing, then `.send().await` issues the request.
    ///
    /// ```no_run
    /// # async fn ex(client: &acdp_client::RegistryClient) -> Result<(), acdp_primitives::AcdpError> {
    /// let resp = client
    ///     .search_builder()
    ///     .q("market risk")
    ///     .tag("risk")
    ///     .tag("portfolio")
    ///     .limit(50)
    ///     .send()
    ///     .await?;
    /// # let _ = resp; Ok(()) }
    /// ```
    pub fn search_builder(&self) -> RegistrySearch<'_> {
        RegistrySearch::new(self)
    }
}

/// Same-authority + redirect-cap policy shared by every
/// [`RegistryClient`] HTTP client (RFC-ACDP-0006 §7.5 / RFC-ACDP-0008
/// §4.8): at most [`MAX_REDIRECTS`] follows, and each follow must stay
/// on the original request's scheme + host + port.
fn redirect_policy() -> redirect::Policy {
    redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error(format!(
                "exceeded {MAX_REDIRECTS} redirects per RFC-ACDP-0006 §7.5"
            ));
        }
        // Same-authority enforcement (scheme + host + port) against the
        // original request URL. RFC-ACDP-0008 §4.8.
        let cross = attempt
            .previous()
            .first()
            .filter(|orig| !acdp_safe_http::same_fetch_authority(orig, attempt.url()))
            .map(|orig| (orig.to_string(), attempt.url().to_string()));
        if let Some((from, to)) = cross {
            return attempt.error(format!(
                "cross-authority redirect rejected ({from} -> {to})"
            ));
        }
        attempt.follow()
    })
}

/// Builder for the non-default [`RegistryClient`] connection postures.
///
/// Start from [`RegistryClient::builder`]. The defaults match
/// [`RegistryClient::new`] exactly — the stronger `SafeDnsResolver`
/// DNS-hook posture (RFC-ACDP-0006 §7.6), the default [`SsrfPolicy`],
/// and the RFC-ACDP-0006 §7.4 timeouts (5s connect, 30s total) — so a
/// bare `builder(url).build().await` is equivalent to `new(url)`. Each
/// setter changes exactly one knob:
///
/// - [`Self::pinned`] — pin-once resolution instead of the DNS hook.
/// - [`Self::ssrf_policy`] — a custom SSRF policy (e.g. a test policy).
/// - [`Self::root_cert_pem`] — trust an extra PEM root (private CA).
/// - [`Self::connect_timeout`] / [`Self::request_timeout`] — override
///   the RFC default timeouts.
pub struct RegistryClientBuilder {
    base_url: String,
    pinned: bool,
    ssrf_policy: SsrfPolicy,
    root_cert_pem: Option<Vec<u8>>,
    /// Test-only: pin `<authority>` to a fixed socket via reqwest's
    /// `.resolve()`. Only set through the private `RegistryClient::build`
    /// shim (never via the public `builder()` surface).
    resolve_target: Option<std::net::SocketAddr>,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl RegistryClientBuilder {
    fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            pinned: false,
            ssrf_policy: SsrfPolicy::default(),
            root_cert_pem: None,
            resolve_target: None,
            connect_timeout: CONNECT_TIMEOUT,
            request_timeout: REQUEST_TIMEOUT,
        }
    }

    /// Select **pin-once** resolution (RFC-ACDP-0006 §7.6): resolve the
    /// authority's DNS a single time, validate that answer against the
    /// SSRF policy, and pin the connection to it. Weaker than the
    /// default DNS-hook posture (which re-validates every connection) —
    /// prefer the default unless you specifically need pin-once.
    pub fn pinned(mut self, pinned: bool) -> Self {
        self.pinned = pinned;
        self
    }

    /// Override the [`SsrfPolicy`] applied to the base URL and to every
    /// resolved IP. Defaults to [`SsrfPolicy::default`].
    pub fn ssrf_policy(mut self, policy: SsrfPolicy) -> Self {
        self.ssrf_policy = policy;
        self
    }

    /// Trust an additional PEM-encoded root certificate in addition to
    /// the system roots (e.g. a private/corporate CA).
    pub fn root_cert_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.root_cert_pem = Some(pem.into());
        self
    }

    /// Override the connect timeout (default: RFC-ACDP-0006 §7.4, 5s).
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Override the total request timeout (default: RFC-ACDP-0006 §7.4,
    /// 30s).
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Build the [`RegistryClient`].
    ///
    /// Async because [`Self::pinned`] mode resolves DNS up front. The
    /// default (DNS-hook) mode does no async work — it is constructed
    /// synchronously internally.
    pub async fn build(self) -> Result<RegistryClient, AcdpError> {
        if !self.pinned {
            return self.build_blocking();
        }

        // ── Pin-once mode (RFC-ACDP-0006 §7.6) ──────────────────────
        let base = self.base_url.trim_end_matches('/').to_string();
        let parsed = url::Url::parse(&base)
            .map_err(|e| AcdpError::SchemaViolation(format!("invalid base URL: {e}")))?;
        // Pre-flight: scheme + host range checks via the same policy.
        self.ssrf_policy.check_url(&base)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| AcdpError::SchemaViolation(format!("base URL has no host: {base}")))?
            .to_string();
        let port = parsed
            .port_or_known_default()
            .unwrap_or(if parsed.scheme() == "http" { 80 } else { 443 });
        let pinned = self.ssrf_policy.pin_resolved_ip(&host, port).await?;

        let mut builder = Client::builder()
            .use_rustls_tls()
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .redirect(redirect_policy())
            .resolve(&host, pinned);
        builder = Self::apply_root_cert(builder, self.root_cert_pem.as_deref())?;

        let http = builder
            .build()
            .map_err(|e| AcdpError::Http(e.to_string()))?;
        Ok(RegistryClient {
            base,
            http,
            budget: None,
            revocation_cache: None,
            revocation_freshness: Duration::ZERO,
        })
    }

    /// Synchronous build for the default DNS-hook posture (no pinning).
    /// The public sync constructors ([`RegistryClient::new`] and the
    /// test-transport factories) route through here.
    fn build_blocking(self) -> Result<RegistryClient, AcdpError> {
        debug_assert!(
            !self.pinned,
            "build_blocking is DNS-hook only; pinned mode must use the async build()"
        );
        let base = self.base_url.trim_end_matches('/').to_string();
        // RFC-ACDP-0006 §7 / RFC-ACDP-0008 §4.8–4.9: reject non-HTTPS,
        // IP-literal, and malformed base URLs up front, then filter every
        // resolved IP at DNS time (below) so DNS-rebinding answers in
        // forbidden ranges are refused before connect.
        self.ssrf_policy.check_url(&base)?;
        let original_authority = url::Url::parse(&base)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string));

        let mut builder = Client::builder()
            .use_rustls_tls()
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .redirect(redirect_policy())
            // DNS-time SSRF filtering for every connection (incl. redirects
            // and reconnects), defeating DNS rebinding — RFC-ACDP-0006 §7.6.
            // Mirrors `WebResolver::build_http_client` / `HttpsDataRefFetcher`.
            .dns_resolver(acdp_safe_http::SafeDnsResolver::arc(self.ssrf_policy));
        builder = Self::apply_root_cert(builder, self.root_cert_pem.as_deref())?;

        if let (Some(target), Some(host)) = (self.resolve_target, original_authority) {
            builder = builder.resolve(&host, target);
        }

        let http = builder
            .build()
            .map_err(|e| AcdpError::Http(e.to_string()))?;
        Ok(RegistryClient {
            base,
            http,
            budget: None,
            revocation_cache: None,
            revocation_freshness: Duration::ZERO,
        })
    }

    fn apply_root_cert(
        builder: reqwest::ClientBuilder,
        pem: Option<&[u8]>,
    ) -> Result<reqwest::ClientBuilder, AcdpError> {
        let Some(pem) = pem else {
            return Ok(builder);
        };
        let cert = reqwest::Certificate::from_pem(pem)
            .map_err(|e| AcdpError::Http(format!("invalid root cert PEM: {e}")))?;
        Ok(builder.add_root_certificate(cert))
    }
}

/// Fluent search builder bound to a [`RegistryClient`]. See
/// [`RegistryClient::search_builder`].
pub struct RegistrySearch<'a> {
    client: &'a RegistryClient,
    inner: acdp_types::search::SearchParamsBuilder,
}

impl<'a> RegistrySearch<'a> {
    fn new(client: &'a RegistryClient) -> Self {
        Self {
            client,
            inner: acdp_types::search::SearchParamsBuilder::new(),
        }
    }

    /// Issue the search.
    pub async fn send(self) -> Result<SearchResponse, AcdpError> {
        let params = self.inner.build();
        self.client.search(&params).await
    }
    /// Full-text query.
    pub fn q(mut self, q: impl Into<String>) -> Self {
        self.inner = self.inner.q(q);
        self
    }
    /// Filter on `type`.
    pub fn context_type(mut self, t: impl Into<String>) -> Self {
        self.inner = self.inner.context_type(t);
        self
    }
    /// Filter on `domain`.
    pub fn domain(mut self, d: impl Into<String>) -> Self {
        self.inner = self.inner.domain(d);
        self
    }
    /// Accumulate a tag.
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.inner = self.inner.tag(t);
        self
    }
    /// Filter on `agent_id`.
    pub fn agent_id(mut self, a: impl Into<String>) -> Self {
        self.inner = self.inner.agent_id(a);
        self
    }
    /// Filter on `derived_from` (strongly typed).
    pub fn derived_from(mut self, c: &acdp_types::CtxId) -> Self {
        self.inner = self.inner.derived_from_ctx_id(c);
        self
    }
    /// Lower bound on `created_at`.
    pub fn created_after(mut self, dt: chrono::DateTime<chrono::Utc>) -> Self {
        self.inner = self.inner.created_after(dt);
        self
    }
    /// Upper bound on `created_at`.
    pub fn created_before(mut self, dt: chrono::DateTime<chrono::Utc>) -> Self {
        self.inner = self.inner.created_before(dt);
        self
    }
    /// Status filter.
    pub fn status(mut self, s: impl Into<String>) -> Self {
        self.inner = self.inner.status(s);
        self
    }
    /// Result page size cap.
    pub fn limit(mut self, l: u32) -> Self {
        self.inner = self.inner.limit(l);
        self
    }
    /// Pagination cursor.
    pub fn cursor(mut self, c: impl Into<String>) -> Self {
        self.inner = self.inner.cursor(c);
        self
    }
}

// ── Internal helpers on RegistryClient ───────────────────────────────────────

impl RegistryClient {
    /// Returns the parsed value alongside the exact byte count read
    /// from a *successful* response body (issue #258: this is what
    /// lets `RegistryClient`'s discovery-reachable methods charge the
    /// caller-configured byte budget the exact count `read_body_capped`
    /// already computes, instead of discarding it). The non-success
    /// branch's error-envelope read is never counted — see
    /// `DiscoveryBudget`'s doc.
    async fn parse_success<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
        max_bytes: usize,
    ) -> Result<(T, usize), AcdpError> {
        if resp.status().is_success() {
            let bytes = read_body_capped(resp, max_bytes).await?;
            let value = serde_json::from_slice(&bytes)
                .map_err(|e| AcdpError::Serialization(e.to_string()))?;
            Ok((value, bytes.len()))
        } else {
            // Error envelopes are tiny — apply the metadata cap so a
            // hostile registry can't exhaust memory via the error path.
            let bytes = match read_body_capped(resp, MAX_METADATA_BYTES).await {
                Ok(b) => b,
                Err(_) => {
                    return Err(AcdpError::from_wire_error(WireError {
                        error: acdp_types::publish::WireErrorBody {
                            code: "unknown".into(),
                            message: "could not read registry error response".into(),
                            details: None,
                        },
                    }));
                }
            };
            let wire: WireError = serde_json::from_slice(&bytes).unwrap_or_else(|_| WireError {
                error: acdp_types::publish::WireErrorBody {
                    code: "unknown".into(),
                    message: "could not parse registry error response".into(),
                    details: None,
                },
            });
            Err(AcdpError::from_wire_error(wire))
        }
    }
}

/// Extract the cache TTL for a capabilities response per
/// RFC-ACDP-0006 §4.2 — `min(Cache-Control: max-age=N, 3600s)`.
///
/// Falls back to a conservative 300s when no parseable `max-age`
/// directive is present (matches [`crate::ResolverOptions::capabilities_ttl`]'s
/// default so behavior is identical to the pre-BUG-09 code path on
/// silent registries).
fn cache_ttl_from_response(resp: &reqwest::Response) -> std::time::Duration {
    const MAX_CAPS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3600);
    const DEFAULT_CAPS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

    let Some(cc) = resp
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    else {
        return DEFAULT_CAPS_CACHE_TTL;
    };
    for directive in cc.split(',') {
        let directive = directive.trim();
        if let Some(value) = directive
            .strip_prefix("max-age=")
            .or_else(|| directive.strip_prefix("s-maxage="))
        {
            if let Ok(secs) = value.parse::<u64>() {
                return std::time::Duration::from_secs(secs).min(MAX_CAPS_CACHE_TTL);
            }
        }
    }
    DEFAULT_CAPS_CACHE_TTL
}

fn parse_retrieval_metadata(resp: &reqwest::Response) -> RetrievalMetadata {
    let headers = resp.headers();
    let etag = headers
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let cache_control = headers
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let last_modified = headers
        .get(reqwest::header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            DateTime::parse_from_rfc2822(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        });
    RetrievalMetadata {
        etag,
        cache_control,
        last_modified,
    }
}

/// Read the response body, aborting if the running total exceeds
/// `max_bytes`. Returns [`AcdpError::PayloadTooLarge`] on overflow.
async fn read_body_capped(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, AcdpError> {
    if let Some(len) = resp.content_length() {
        if len as usize > max_bytes {
            return Err(AcdpError::PayloadTooLarge(format!(
                "response Content-Length {len} exceeds cap {max_bytes}"
            )));
        }
    }
    let mut buf = Vec::with_capacity(8 * 1024);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| AcdpError::Http(e.to_string()))?
    {
        if buf.len() + chunk.len() > max_bytes {
            return Err(AcdpError::PayloadTooLarge(format!(
                "response body exceeded {max_bytes} bytes"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}
