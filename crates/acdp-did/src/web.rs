//! `did:web` resolver — RFC-ACDP-0001 §5.11, step 3.

use acdp_primitives::error::AcdpError;

#[cfg(feature = "client")]
use {
    super::document::DidDocument,
    acdp_primitives::limits::{
        CONNECT_TIMEOUT, MAX_METADATA_BYTES, MAX_REDIRECTS, REQUEST_TIMEOUT,
    },
    acdp_safe_http::SsrfPolicy,
    lru::LruCache,
    reqwest::redirect,
    std::num::NonZeroUsize,
    std::sync::{Arc, Mutex},
    std::time::{Duration, Instant},
};

#[cfg(feature = "client")]
const CACHE_MAX: Duration = Duration::from_secs(24 * 3600); // 24 hours
#[cfg(feature = "client")]
const DEFAULT_CACHE_CAPACITY: usize = 1000;

/// Default minimum interval between two *forced* (cache-bypassing)
/// re-fetches of the same DID document — one hour.
///
/// RFC-ACDP-0001 §5.11 "Caching" *(0.5.0)* requires a verifier holding a
/// cached document to re-fetch it once before reporting "no
/// `verificationMethod` matches" (step 4) or `key_not_authorized`
/// (step 5), and lets it rate-limit those forced re-fetches per DID.
/// The bound stops a stream of bodies naming unknown fragments from
/// turning the verifier into a request amplifier against a DID host.
/// Override with [`WebResolver::with_forced_refresh_interval`].
#[cfg(feature = "client")]
pub const DEFAULT_FORCED_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

#[cfg(feature = "client")]
struct CacheEntry {
    doc: DidDocument,
    cached_at: Instant,
}

/// A resolved DID document together with when it was fetched from the
/// network (a cache hit reports the original fetch time).
#[cfg(feature = "client")]
#[derive(Debug, Clone)]
pub struct ResolvedDidDocument {
    /// The document.
    pub document: DidDocument,
    /// When this document was fetched over HTTPS.
    pub fetched_at: Instant,
}

/// Result of [`WebResolver::resolve_until`]: the best document the
/// resolver could obtain, and whether it is *fresh* for the operation
/// (fetched from the network at or after the operation's start).
#[cfg(feature = "client")]
#[derive(Debug, Clone)]
pub struct FreshResolution {
    /// The document the caller should evaluate.
    pub document: DidDocument,
    /// `true` when `document` was fetched at or after the caller's
    /// `since` instant — i.e. a verdict against it is final per
    /// RFC-ACDP-0001 §5.11 "Caching". `false` only when the document is
    /// an older cached copy that the caller's predicate rejected and a
    /// forced re-fetch was refused by the per-DID rate limit.
    pub fresh: bool,
}

/// Resolves `did:web:…` DIDs to DID documents via HTTPS.
///
/// Caches resolved documents for 5–24 hours per §5.11 guidance, evicting
/// the least-recently-used entry once the cache reaches the configured
/// capacity (default 1000).
///
/// Every resolution URL passes the [`SsrfPolicy`] gate before any socket
/// activity: a producer-controlled `did:web` authority is an SSRF vector
/// identical to a cross-registry reference (RFC-ACDP-0008 §4.8). The
/// default policy refuses IP-literal authorities and non-HTTPS schemes,
/// so `did:web:127.0.0.1` / `did:web:169.254.169.254` cannot turn a
/// registry verifying a publish — or a consumer verifying a retrieved
/// context — into an SSRF proxy against process-internal listeners.
#[cfg(feature = "client")]
pub struct WebResolver {
    http: reqwest::Client,
    cache: Arc<Mutex<LruCache<String, CacheEntry>>>,
    /// Last forced (cache-bypassing) fetch per DID — the §5.11 refresh
    /// rate limit. Bounded like the document cache.
    forced: Arc<Mutex<LruCache<String, Instant>>>,
    forced_refresh_interval: Duration,
    ssrf_policy: SsrfPolicy,
    // Stored verbatim so [`Self::with_ssrf_policy`] can rebuild the
    // HTTP client (the DNS resolver is wired in at builder time, so a
    // policy swap requires rebuilding).
    root_cert_pem: Option<Vec<u8>>,
}

#[cfg(feature = "client")]
impl WebResolver {
    /// Build a resolver with the default LRU capacity (1000 entries).
    ///
    /// # Panics
    ///
    /// Panics if the underlying HTTP client cannot be built (e.g. the
    /// TLS backend fails to initialize). Use [`Self::try_new`] to
    /// handle that failure as a `Result` instead.
    pub fn new() -> Self {
        Self::try_new().expect("failed to build HTTP client for DID resolver")
    }

    /// Fallible variant of [`Self::new`]: builds a resolver with the
    /// default LRU capacity (1000 entries), returning an error instead
    /// of panicking if the underlying HTTP client cannot be built.
    pub fn try_new() -> Result<Self, AcdpError> {
        Self::try_with_capacity(DEFAULT_CACHE_CAPACITY)
    }

    /// Build a resolver with a custom LRU capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity == 0` — use a positive capacity; the LRU
    /// model has no semantically valid empty configuration — or if the
    /// underlying HTTP client cannot be built. Use
    /// [`Self::try_with_capacity`] to handle the HTTP-client failure
    /// as a `Result` instead.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::try_with_capacity(capacity).expect("failed to build HTTP client for DID resolver")
    }

    /// Fallible variant of [`Self::with_capacity`]: returns an error
    /// instead of panicking if the underlying HTTP client cannot be
    /// built.
    ///
    /// # Panics
    ///
    /// Still panics if `capacity == 0`; that is a programmer error, not
    /// a runtime condition.
    pub fn try_with_capacity(capacity: usize) -> Result<Self, AcdpError> {
        Self::from_parts(capacity, SsrfPolicy::default(), None)
    }

    /// Build a resolver that trusts the given PEM-encoded root certificate
    /// in addition to the system roots.
    ///
    /// Primary use is the in-process self-signed HTTPS server in the
    /// crate's `tests/helpers/tls_did_server.rs` harness, so the spec
    /// fixtures `pub-001` / `pub-006` / `fed-001..006` can drive the
    /// resolver end-to-end without going over the network. Production
    /// callers on corporate intranets MAY also use this to trust a
    /// private CA.
    pub fn with_root_cert_pem(pem: &[u8]) -> Result<Self, AcdpError> {
        Self::from_parts(
            DEFAULT_CACHE_CAPACITY,
            SsrfPolicy::default(),
            Some(pem.to_vec()),
        )
    }

    /// Build a resolver with a custom LRU capacity AND a custom root cert.
    pub fn with_capacity_and_root_cert_pem(capacity: usize, pem: &[u8]) -> Result<Self, AcdpError> {
        Self::from_parts(capacity, SsrfPolicy::default(), Some(pem.to_vec()))
    }

    /// Resolver pinned to a fixed socket address for a logical hostname,
    /// trusting the given root certificate — the resolver-side analogue
    /// of [`crate::client::RegistryClient::with_test_endpoint`]. Lets a
    /// test resolve `did:web:localhost` (and path DIDs under it) against
    /// an in-process TLS server bound to `127.0.0.1:<port>` without the
    /// port appearing in the DID. Uses the loopback-permitting SSRF
    /// policy. Use only in tests.
    #[doc(hidden)]
    #[cfg(feature = "test-transport")]
    pub fn with_test_endpoint(
        pem: &[u8],
        host: &str,
        target: std::net::SocketAddr,
    ) -> Result<Self, AcdpError> {
        let cap = NonZeroUsize::new(DEFAULT_CACHE_CAPACITY).expect("capacity > 0");
        let policy = SsrfPolicy::allow_test_loopback();
        let http = build_http_client_pinned(Some(pem), &policy, Some((host, target)))?;
        Ok(Self {
            http,
            cache: Arc::new(Mutex::new(LruCache::new(cap))),
            forced: Arc::new(Mutex::new(LruCache::new(cap))),
            forced_refresh_interval: DEFAULT_FORCED_REFRESH_INTERVAL,
            ssrf_policy: policy,
            root_cert_pem: Some(pem.to_vec()),
        })
    }

    fn from_parts(
        capacity: usize,
        ssrf_policy: SsrfPolicy,
        root_cert_pem: Option<Vec<u8>>,
    ) -> Result<Self, AcdpError> {
        let cap = NonZeroUsize::new(capacity).expect("WebResolver capacity must be > 0");
        let http = build_http_client(root_cert_pem.as_deref(), &ssrf_policy)?;
        Ok(Self {
            http,
            cache: Arc::new(Mutex::new(LruCache::new(cap))),
            forced: Arc::new(Mutex::new(LruCache::new(cap))),
            forced_refresh_interval: DEFAULT_FORCED_REFRESH_INTERVAL,
            ssrf_policy,
            root_cert_pem,
        })
    }

    /// Override the [`SsrfPolicy`] applied to `did:web` resolution.
    ///
    /// The policy gates both the URL stage (refusing IP-literal
    /// authorities and non-HTTPS schemes — fixtures did-ssrf-001/002/003)
    /// **and** the DNS resolution stage (filtering hostnames that resolve
    /// into forbidden ranges — RFC-ACDP-0008 §4.8 DNS-rebinding
    /// protection). Calling this rebuilds the underlying HTTP client so
    /// the DNS resolver hook reflects the new policy.
    ///
    /// Relax the policy **only** in a test harness that resolves
    /// `did:web:localhost…` against an in-process loopback server.
    /// Production callers MUST keep the default.
    ///
    /// # Panics
    ///
    /// Panics if the underlying HTTP client cannot be rebuilt. Use
    /// [`Self::try_with_ssrf_policy`] to handle that failure as a
    /// `Result` instead.
    pub fn with_ssrf_policy(self, policy: SsrfPolicy) -> Self {
        self.try_with_ssrf_policy(policy)
            .expect("rebuild HTTP client for DID resolver")
    }

    /// Fallible variant of [`Self::with_ssrf_policy`]: returns an error
    /// instead of panicking if the underlying HTTP client cannot be
    /// rebuilt.
    pub fn try_with_ssrf_policy(mut self, policy: SsrfPolicy) -> Result<Self, AcdpError> {
        // Rebuild the HTTP client so the DNS resolver hook carries the
        // new policy. `build_http_client` is fallible only on bad cert
        // PEM input; we already validated it at construction time.
        let http = build_http_client(self.root_cert_pem.as_deref(), &policy)?;
        self.http = http;
        self.ssrf_policy = policy;
        Ok(self)
    }

    /// Set the minimum interval between two forced re-fetches of the
    /// same DID (default [`DEFAULT_FORCED_REFRESH_INTERVAL`], one hour).
    /// `Duration::ZERO` disables the rate limit.
    pub fn with_forced_refresh_interval(mut self, interval: Duration) -> Self {
        self.forced_refresh_interval = interval;
        self
    }

    /// The configured forced-refresh interval.
    pub fn forced_refresh_interval(&self) -> Duration {
        self.forced_refresh_interval
    }

    /// Resolve a `did:web:…` DID to a DID document.
    ///
    /// Hits the cache on repeated calls for the same DID. Verifiers that
    /// need the RFC-ACDP-0001 §5.11 "refresh on plausible rotation"
    /// behavior use [`Self::resolve_until`].
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), fields(did = did)))]
    pub async fn resolve(&self, did: &str) -> Result<DidDocument, AcdpError> {
        Ok(self.resolve_tracked(did).await?.document)
    }

    /// [`Self::resolve`], also reporting when the document was fetched.
    pub async fn resolve_tracked(&self, did: &str) -> Result<ResolvedDidDocument, AcdpError> {
        // Check cache (mutates LRU recency on hit)
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(did) {
                if entry.cached_at.elapsed() < CACHE_MAX {
                    return Ok(ResolvedDidDocument {
                        document: entry.doc.clone(),
                        fetched_at: entry.cached_at,
                    });
                }
            }
        }
        self.fetch_and_store(did).await
    }

    /// Forced re-fetch: bypass the cache, fetch the document over HTTPS
    /// and repopulate the cache (RFC-ACDP-0001 §5.11 "Caching").
    ///
    /// Rate-limited per DID to one forced fetch per
    /// [`Self::forced_refresh_interval`]. A refused forced fetch returns
    /// [`AcdpError::KeyResolutionUnreachable`] (transient): the caller
    /// could not obtain a fresh document, which is not evidence about
    /// the key.
    pub async fn resolve_fresh(&self, did: &str) -> Result<DidDocument, AcdpError> {
        if !self.try_claim_forced(did) {
            return Err(AcdpError::KeyResolutionUnreachable(format!(
                "forced re-fetch of {did} refused by the per-DID rate limit ({:?})",
                self.forced_refresh_interval
            )));
        }
        Ok(self.fetch_and_store(did).await?.document)
    }

    /// Resolve `did` for an operation that started at `since`, accepting
    /// the first document for which `accept` returns `true`.
    ///
    /// This is the RFC-ACDP-0001 §5.11 "Caching" *(0.5.0)* rule made
    /// mechanical:
    ///
    /// 1. Resolve normally (cache allowed). If `accept` passes, done.
    /// 2. If the document was fetched at or after `since`, it is already
    ///    fresh for this operation: return it, `fresh = true` (the
    ///    verdict against it is final).
    /// 3. If another task re-fetched the document after `since`, use
    ///    that copy (`fresh = true`) — concurrent verifications share one
    ///    forced fetch.
    /// 4. Otherwise force one re-fetch, subject to the per-DID rate
    ///    limit, and return the fresh document (`fresh = true`). When the
    ///    rate limit refuses, the cached copy is returned with
    ///    `fresh = false`; the caller decides whether that is final
    ///    (for example, a key present but not in `assertionMethod`) or
    ///    must be reported as transient (a key absent from the cached
    ///    document).
    pub async fn resolve_until<F>(
        &self,
        did: &str,
        since: Instant,
        accept: F,
    ) -> Result<FreshResolution, AcdpError>
    where
        F: Fn(&DidDocument) -> bool,
    {
        let first = self.resolve_tracked(did).await?;
        if accept(&first.document) || first.fetched_at >= since {
            return Ok(FreshResolution {
                document: first.document,
                fresh: first.fetched_at >= since,
            });
        }
        // Someone else already refreshed after `since`?
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(did) {
                if entry.cached_at >= since && entry.cached_at > first.fetched_at {
                    return Ok(FreshResolution {
                        document: entry.doc.clone(),
                        fresh: true,
                    });
                }
            }
        }
        if !self.try_claim_forced(did) {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                did,
                "forced DID re-fetch refused by rate limit; evaluating cached copy"
            );
            return Ok(FreshResolution {
                document: first.document,
                fresh: false,
            });
        }
        let fresh = self.fetch_and_store(did).await?;
        Ok(FreshResolution {
            document: fresh.document,
            fresh: true,
        })
    }

    /// Resolve `did` and return a document that contains a
    /// `verificationMethod` with `#fragment`, re-fetching once (per
    /// [`Self::resolve_until`]) when the cached copy lacks it.
    ///
    /// Errors when the key is still absent:
    ///
    /// - [`AcdpError::KeyResolution`] (permanent) — absent from a
    ///   document fetched at or after `since`: the RFC-ACDP-0001 §5.11
    ///   step 4 verdict, final per "Caching".
    /// - [`AcdpError::KeyResolutionUnreachable`] (transient) — absent
    ///   from an older cached copy whose forced re-fetch the rate limit
    ///   refused. No fresh document was seen, so absence is not proven.
    pub async fn resolve_with_fragment(
        &self,
        did: &str,
        fragment: &str,
        since: Instant,
    ) -> Result<DidDocument, AcdpError> {
        let res = self
            .resolve_until(did, since, |doc| doc.find_by_fragment(fragment).is_some())
            .await?;
        if res.document.find_by_fragment(fragment).is_some() {
            return Ok(res.document);
        }
        if res.fresh {
            Err(AcdpError::KeyResolution(format!(
                "no verification method with fragment '#{fragment}' in {did} \
                 (checked against a freshly fetched DID document)"
            )))
        } else {
            Err(AcdpError::KeyResolutionUnreachable(format!(
                "no verification method with fragment '#{fragment}' in the cached DID \
                 document for {did}, and the forced re-fetch was refused by the per-DID \
                 rate limit — absence is not proven"
            )))
        }
    }

    /// Record a forced fetch for `did` if the rate limit allows one now.
    fn try_claim_forced(&self, did: &str) -> bool {
        let mut forced = self.forced.lock().unwrap();
        let now = Instant::now();
        if let Some(last) = forced.get(did) {
            if now.duration_since(*last) < self.forced_refresh_interval {
                return false;
            }
        }
        forced.put(did.to_string(), now);
        true
    }

    async fn fetch_and_store(&self, did: &str) -> Result<ResolvedDidDocument, AcdpError> {
        let url = did_web_to_url(did)?;

        // RFC-ACDP-0008 §4.8: a producer-controlled did:web authority is
        // an SSRF vector. Refuse loopback / link-local / IMDS / private-
        // range targets before issuing any request. The refusal is
        // policy-driven and producer-caused, so it maps to
        // `key_resolution_failed` (HTTP 400, permanent) — NOT
        // `key_resolution_unreachable` (HTTP 502, retryable). See
        // fixtures did-ssrf-001 / did-ssrf-002 / did-ssrf-003.
        self.ssrf_policy.check_url(&url).map_err(|e| {
            AcdpError::KeyResolution(format!("SSRF policy blocked did:web resolution: {e}"))
        })?;

        let mut resp = self
            .http
            .get(&url)
            .header("Accept", "application/did+json, application/json")
            .send()
            .await
            .map_err(|e| classify_reqwest_error(&e))?;

        // RFC-ACDP-0001 §5.11 step 3 (did-001 A): ANY non-2xx DID-document
        // response — 404 and 410 included — is `key_resolution_unreachable`
        // (transient). A briefly-misconfigured or unavailable DID host is not
        // evidence that the key does not exist, and a permanent verdict here
        // is exactly what lets revocation discovery drop a real revocation
        // candidate (RFC-ACDP-0014 §8, 0.5.0 discovery outcome classes).
        if !resp.status().is_success() {
            return Err(AcdpError::KeyResolutionUnreachable(format!(
                "DID document fetch returned HTTP {}",
                resp.status()
            )));
        }

        // Cap body size at 64 KB per RFC-ACDP-0006 §7.3.
        if let Some(len) = resp.content_length() {
            if len as usize > MAX_METADATA_BYTES {
                return Err(AcdpError::KeyResolution(format!(
                    "DID document Content-Length {len} exceeds {MAX_METADATA_BYTES}-byte cap"
                )));
            }
        }
        let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| AcdpError::KeyResolutionUnreachable(e.to_string()))?
        {
            if buf.len() + chunk.len() > MAX_METADATA_BYTES {
                return Err(AcdpError::KeyResolution(format!(
                    "DID document body exceeded {MAX_METADATA_BYTES}-byte cap"
                )));
            }
            buf.extend_from_slice(&chunk);
        }
        let doc: DidDocument = serde_json::from_slice(&buf)
            .map_err(|e| AcdpError::KeyResolution(format!("DID document parse: {e}")))?;

        // Store in cache (evicts LRU on overflow)
        let fetched_at = Instant::now();
        {
            let mut cache = self.cache.lock().unwrap();
            cache.put(
                did.to_string(),
                CacheEntry {
                    doc: doc.clone(),
                    cached_at: fetched_at,
                },
            );
        }

        Ok(ResolvedDidDocument {
            document: doc,
            fetched_at,
        })
    }

    /// Invalidate a specific DID's cache entry, forcing a fresh fetch.
    pub fn invalidate(&self, did: &str) {
        self.cache.lock().unwrap().pop(did);
    }
}

#[cfg(feature = "client")]
impl Default for WebResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the `reqwest::Client` used by `WebResolver`, optionally trusting
/// an additional PEM-encoded root certificate.
///
/// Encapsulates the redirect policy, timeouts, and the DNS-rebinding
/// filter so the no-cert and with-cert constructors stay byte-for-byte
/// identical on TLS posture.
///
/// `ssrf_policy` is plumbed into reqwest's `dns_resolver` hook via
/// [`acdp_safe_http::SafeDnsResolver`]: every resolved IP is filtered
/// against the policy before reqwest connects, so a hostname whose DNS
/// answers fall in forbidden ranges (loopback, RFC 1918, link-local,
/// IMDS, ULA, …) is refused at connect time, defeating DNS rebinding
/// (RFC-ACDP-0008 §4.8).
#[cfg(feature = "client")]
fn build_http_client(
    extra_root_pem: Option<&[u8]>,
    ssrf_policy: &SsrfPolicy,
) -> Result<reqwest::Client, AcdpError> {
    build_http_client_pinned(extra_root_pem, ssrf_policy, None)
}

/// Like [`build_http_client`] but optionally pins `host` to a fixed
/// socket address via reqwest's `.resolve()` hook (test endpoints).
#[cfg(feature = "client")]
fn build_http_client_pinned(
    extra_root_pem: Option<&[u8]>,
    ssrf_policy: &SsrfPolicy,
    pin: Option<(&str, std::net::SocketAddr)>,
) -> Result<reqwest::Client, AcdpError> {
    let policy = redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error(format!("DID resolver: exceeded {MAX_REDIRECTS} redirects"));
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
                "DID resolver: cross-authority redirect rejected ({from} -> {to})"
            ));
        }
        attempt.follow()
    });

    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(policy)
        .dns_resolver(acdp_safe_http::SafeDnsResolver::arc(ssrf_policy.clone()));

    if let Some(pem) = extra_root_pem {
        let cert = reqwest::Certificate::from_pem(pem)
            .map_err(|e| AcdpError::Http(format!("invalid root cert PEM: {e}")))?;
        builder = builder.add_root_certificate(cert);
    }

    if let Some((host, target)) = pin {
        builder = builder.resolve(host, target);
    }

    builder
        .build()
        .map_err(|e| AcdpError::Http(format!("DID resolver client build: {e}")))
}

/// Translate a `reqwest::Error` into the right [`AcdpError`] variant.
///
/// Walks the error's `source()` chain so the `SafeDnsResolver`'s refusal
/// (the typed `acdp_primitives::error::SsrfDnsRefusal` marker, detected by
/// the shared `is_ssrf_refusal`) survives reqwest's wrapping. An
/// SSRF-refused DNS lookup is policy-driven and
/// permanent — it maps to `key_resolution_failed` (HTTP 400), NOT
/// `key_resolution_unreachable` (502, retryable) that
/// `reqwest::Error::is_connect()` would suggest by default
/// (RFC-ACDP-0008 §4.8, fixtures did-ssrf-001/002/003).
#[cfg(feature = "client")]
fn classify_reqwest_error(e: &reqwest::Error) -> AcdpError {
    // Shared detection with `From<reqwest::Error> for AcdpError` and
    // `HttpsDataRefFetcher` (issue #321); only the target variants differ.
    let chain = acdp_primitives::error::error_chain_message(e);
    if acdp_primitives::error::is_ssrf_refusal(e) {
        return AcdpError::KeyResolution(chain);
    }
    if e.is_timeout() || e.is_connect() {
        AcdpError::KeyResolutionUnreachable(chain)
    } else {
        AcdpError::KeyResolution(chain)
    }
}

/// Convert a `did:web:…` DID to its HTTPS URL per the `did:web` spec.
///
/// `did:web:example.com` → `https://example.com/.well-known/did.json`
/// `did:web:example.com:users:alice` → `https://example.com/users/alice/did.json`
pub fn did_web_to_url(did: &str) -> Result<String, AcdpError> {
    let rest = did
        .strip_prefix("did:web:")
        .ok_or_else(|| AcdpError::KeyResolution(format!("not a did:web DID: {did}")))?;

    let parts: Vec<&str> = rest.split(':').collect();
    let authority = urlencoding::decode(parts[0])
        .map_err(|e| AcdpError::KeyResolution(format!("authority decode: {e}")))?;

    if parts.len() == 1 {
        Ok(format!("https://{}/.well-known/did.json", authority))
    } else {
        let path = parts[1..].join("/");
        Ok(format!("https://{}/{}/did.json", authority, path))
    }
}

/// Convert a registry authority (DNS hostname, optionally with a port)
/// to its `did:web` form per the did:web method spec.
///
/// The `:` between host and port is a structural delimiter in did:web
/// — it splits the DID into colon-separated path components — so a
/// `host:port` authority must percent-encode the colon as `%3A` to
/// keep the port in the authority segment.
///
/// Examples:
/// - `"registry.example.com"`  → `"did:web:registry.example.com"`
/// - `"localhost:8443"`        → `"did:web:localhost%3A8443"`
pub fn authority_to_did_web(authority: &str) -> String {
    let encoded = authority.replace(':', "%3A");
    format!("did:web:{encoded}")
}

/// Reverse of [`authority_to_did_web`]: strip the `did:web:` prefix
/// and decode `%3A` back to `:`. Returns `None` for non-`did:web` input.
///
/// Used in `RegistryServer::try_new` and `CrossRegistryResolver::resolve`
/// to compare a capabilities-advertised DID against the authority the
/// consumer connected to. Round-trips with `authority_to_did_web`.
pub fn did_web_to_authority(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:web:")?;
    // Only the first segment carries the authority; further segments
    // are path components and don't get colon-decoded.
    let mut parts = rest.splitn(2, ':');
    let authority = parts.next()?;
    Some(authority.replace("%3A", ":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_authority() {
        let url = did_web_to_url("did:web:example.com").unwrap();
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn path_authority() {
        let url = did_web_to_url("did:web:example.com:users:alice").unwrap();
        assert_eq!(url, "https://example.com/users/alice/did.json");
    }

    /// BUG-06: bare DNS hostname maps to the plain did:web form.
    #[test]
    fn authority_to_did_web_bare_hostname() {
        assert_eq!(
            authority_to_did_web("registry.example.com"),
            "did:web:registry.example.com"
        );
    }

    /// BUG-06: `host:port` authority percent-encodes the colon.
    #[test]
    fn authority_to_did_web_with_port() {
        assert_eq!(
            authority_to_did_web("localhost:8443"),
            "did:web:localhost%3A8443"
        );
    }

    /// BUG-06: reverse helper strips prefix and decodes the colon.
    #[test]
    fn did_web_to_authority_round_trips() {
        for authority in ["registry.example.com", "localhost:8443", "127.0.0.1:9000"] {
            let did = authority_to_did_web(authority);
            let back = did_web_to_authority(&did)
                .unwrap_or_else(|| panic!("did_web_to_authority returned None for '{did}'"));
            assert_eq!(back, authority, "round-trip for '{authority}' failed");
        }
    }

    /// `did_web_to_url` already URL-decodes the authority — confirm
    /// that `authority_to_did_web("localhost:8443")` produces a DID
    /// that resolves to `https://localhost:8443/.well-known/did.json`.
    #[test]
    fn authority_to_did_web_then_to_url_keeps_port() {
        let did = authority_to_did_web("localhost:8443");
        let url = did_web_to_url(&did).unwrap();
        assert_eq!(url, "https://localhost:8443/.well-known/did.json");
    }

    // ── BUG-04 — WebResolver SSRF policy (did-ssrf-001/002/003) ─────────

    /// did-ssrf-001 — a `did:web` authority that is a loopback IP literal
    /// is refused by the default resolver before any socket activity.
    /// The error is `key_resolution_failed` (permanent), not
    /// `key_resolution_unreachable` (retryable).
    #[cfg(feature = "client")]
    #[tokio::test]
    async fn did_resolver_rejects_loopback_did() {
        let resolver = WebResolver::new();
        let err = resolver.resolve("did:web:127.0.0.1").await.unwrap_err();
        assert!(
            matches!(err, AcdpError::KeyResolution(_)),
            "did-ssrf-001: loopback did:web MUST be blocked by SSRF policy, got {err:?}"
        );
    }

    /// did-ssrf-002 — a `did:web` authority pointing at the cloud-metadata
    /// endpoint (169.254.169.254) is refused.
    #[cfg(feature = "client")]
    #[tokio::test]
    async fn did_resolver_rejects_imds_did() {
        let resolver = WebResolver::new();
        let err = resolver
            .resolve("did:web:169.254.169.254")
            .await
            .unwrap_err();
        assert!(
            matches!(err, AcdpError::KeyResolution(_)),
            "did-ssrf-002: IMDS did:web MUST be blocked by SSRF policy, got {err:?}"
        );
    }

    /// did-ssrf-003 — a `did:web` authority in an RFC 1918 private range
    /// is refused.
    #[cfg(feature = "client")]
    #[tokio::test]
    async fn did_resolver_rejects_private_range_did() {
        let resolver = WebResolver::new();
        for did in [
            "did:web:192.168.1.1",
            "did:web:10.0.0.1",
            "did:web:172.16.0.1",
        ] {
            let err = resolver.resolve(did).await.unwrap_err();
            assert!(
                matches!(err, AcdpError::KeyResolution(_)),
                "did-ssrf-003: private-range did:web '{did}' MUST be blocked, got {err:?}"
            );
        }
    }

    /// RFC-ACDP-0008 §4.8 DNS-rebinding protection — a hostname whose
    /// DNS answers fall in forbidden ranges is refused at the DNS step,
    /// before any TCP connect. `localhost` is a perfectly valid DNS
    /// name (it passes `check_url`), but it resolves to `127.0.0.1` —
    /// which the default policy MUST refuse via the `SafeDnsResolver`
    /// hook on reqwest's `dns_resolver`. The error message MUST
    /// identify the SSRF policy so operators can tell the refusal
    /// apart from a generic connection failure.
    #[cfg(feature = "client")]
    #[tokio::test]
    async fn did_resolver_rejects_hostname_resolving_to_loopback() {
        let resolver = WebResolver::new();
        let err = resolver
            .resolve("did:web:localhost%3A12345")
            .await
            .expect_err("DNS-rebinding protection MUST refuse localhost under default policy");
        let msg = format!("{err}");
        // SSRF-refused DNS is policy-driven and permanent — it maps to
        // `KeyResolution` (HTTP 400), NOT `KeyResolutionUnreachable`
        // (HTTP 502, retryable). The retry-aware client MUST NOT retry.
        assert!(
            matches!(err, AcdpError::KeyResolution(_)),
            "DNS-rebinding refusal MUST be permanent KeyResolution, got {err:?}"
        );
        assert!(
            msg.contains("SSRF policy"),
            "DNS-rebinding refusal MUST identify the SSRF policy in its message; got: {msg}"
        );
        // And `is_transient` MUST return false so retry loops don't loop.
        assert!(!err.is_transient(), "SSRF refusal MUST NOT be transient");
    }
}
