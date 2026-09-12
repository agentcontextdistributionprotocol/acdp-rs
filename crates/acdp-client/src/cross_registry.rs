//! Cross-registry resolution per RFC-ACDP-0006 (feature = "client").
//!
//! Resolves a `ctx_id` whose authority differs from the registry the
//! consumer is currently talking to. Walks the lineage of `derived_from`
//! references with cycle detection, configurable depth / node / fanout
//! caps, and per-authority caching of the `RegistryClient` and
//! capabilities document.
//!
//! See RFC-ACDP-0006 §4.1 for the seven-step algorithm:
//!   1. Parse URI → authority
//!   2. Fetch the foreign registry's capabilities
//!   3. Verify the registry DID matches `did:web:<authority>`
//!   4. Retrieve the full context
//!   5. Verify content_hash
//!   6. Verify signature via DID resolution
//!   7. Walk `derived_from` references (with cycle/depth/node/fanout/timeout limits)

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{
    ReceiptPolicy, RegistryClient, RevocationCache, RevocationPolicy, VerificationPolicy,
    VerifiedContext,
};
use acdp_did::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_safe_http::SsrfPolicy;
use acdp_types::body::Body;
use acdp_types::primitives::CtxId;
use acdp_types::CapabilitiesDocument;

/// Per-walk and per-resolve safety options.
///
/// Defaults are tuned for RFC-ACDP-0006 §7.4 / §7.5 — they bound a walk
/// even when the producer fabricates `derived_from` lists pointing into a
/// foreign registry's pathological lineage graph.
#[derive(Debug, Clone)]
pub struct ResolverOptions {
    /// Per-edge maximum depth (default 10).
    pub max_depth: usize,
    /// Total number of contexts the walk may verify (default 100). Acts
    /// as a hard ceiling even when individual hops respect `max_depth`.
    pub max_nodes: usize,
    /// Maximum `derived_from` count permitted on any single context the
    /// walker visits (default 32). A context that lists more parents is
    /// either malformed or hostile — short-circuit before fanning out.
    pub max_fanout: usize,
    /// Wall-clock budget for the entire walk (default 30 s). Wraps
    /// [`CrossRegistryResolver::walk_derived_from`] in `tokio::time::timeout`.
    pub total_timeout: Duration,
    /// How long to cache a foreign registry's capabilities document
    /// before re-fetching (default 5 min). Avoids hammering the foreign
    /// `/.well-known/acdp.json` on every hop.
    pub capabilities_ttl: Duration,
}

impl Default for ResolverOptions {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_nodes: 100,
            max_fanout: 32,
            total_timeout: Duration::from_secs(30),
            capabilities_ttl: Duration::from_secs(300),
        }
    }
}

/// Resolver for cross-registry references.
///
/// Holds a [`WebResolver`] for DID lookups and caches a [`RegistryClient`]
/// + capabilities document per authority for the lifetime of the resolver.
///
/// The [`SsrfPolicy`] is consulted on every URL the resolver constructs
/// (RFC-ACDP-0006 §7.1, §7.2).
///
/// # Revocation discovery (issue #260)
///
/// [`Self::with_revocation_policy`] injects a [`RevocationPolicy`] into
/// every node this resolver verifies, closing the LIM-1 gap recorded in
/// `crate::verified`'s `RevocationPolicy` rustdoc: before this, neither a
/// caller-supplied `known` set nor `discover` could reach a
/// cross-registry walk at all. [`Self::with_revocation_cache`] additionally
/// shares one [`RevocationCache`] handle across every per-authority
/// client the resolver builds (or is seeded with) — see
/// [`Self::walk_derived_from`]'s doc for the walk-scoped default this
/// replaces.
pub struct CrossRegistryResolver {
    did_resolver: WebResolver,
    options: ResolverOptions,
    allowlist: Option<HashSet<String>>,
    ssrf_policy: SsrfPolicy,
    // Per-authority caches. Mutex-guarded for interior mutability across
    // the immutable `&self` API surface; contention is low since
    // authorities are few per walk.
    client_cache: Mutex<HashMap<String, RegistryClient>>,
    /// Per-authority capabilities cache. The `Duration` is the
    /// per-response TTL parsed from `Cache-Control: max-age=N` (capped
    /// at 3600s per RFC-ACDP-0006 §4.2). Replaces an earlier shape
    /// that used the resolver-wide `capabilities_ttl` for every entry,
    /// ignoring the registry's own cache hint (BUG-09).
    caps_cache: Mutex<HashMap<String, (CapabilitiesDocument, Instant, Duration)>>,
    /// Injected via [`Self::with_revocation_policy`]. Default
    /// [`RevocationPolicy::default`] (empty `known`, `discover: None`) is
    /// inert, so a resolver built without calling this setter behaves
    /// byte-identically to before this field existed (issue #260 AC7).
    /// Deliberately `RevocationPolicy`, never `VerificationPolicy` — see
    /// [`Self::with_revocation_policy`]'s doc for why `receipts` is the
    /// one field this injection point can never carry.
    revocation_policy: RevocationPolicy,
    /// Injected via [`Self::with_revocation_cache`]. `None` (the default)
    /// means [`Self::walk_derived_from`] creates a fresh, walk-scoped
    /// cache for each call instead of reusing one across walks — see
    /// that method's doc.
    revocation_cache: Option<RevocationCache>,
}

impl Default for CrossRegistryResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossRegistryResolver {
    /// Build a resolver with default settings: no allowlist, depth 10,
    /// HTTPS-only / no IP literals SSRF policy.
    pub fn new() -> Self {
        Self {
            did_resolver: WebResolver::new(),
            options: ResolverOptions::default(),
            allowlist: None,
            ssrf_policy: SsrfPolicy::default(),
            client_cache: Mutex::new(HashMap::new()),
            caps_cache: Mutex::new(HashMap::new()),
            revocation_policy: RevocationPolicy::default(),
            revocation_cache: None,
        }
    }

    /// Override the [`SsrfPolicy`] applied to outbound URLs.
    ///
    /// Useful for test environments that need to allow `http://` or
    /// IP-literal hosts. Production deployments SHOULD keep the default.
    pub fn with_ssrf_policy(mut self, policy: SsrfPolicy) -> Self {
        self.ssrf_policy = policy;
        self
    }

    /// Cap the number of `derived_from` hops walked in a single
    /// [`Self::walk_derived_from`] call.
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.options.max_depth = depth;
        self
    }

    /// Replace the complete options struct (overrides every individual
    /// `with_*` setter that wasn't already applied).
    pub fn with_options(mut self, options: ResolverOptions) -> Self {
        self.options = options;
        self
    }

    /// Borrow the active options. Useful for tests + telemetry.
    pub fn options(&self) -> &ResolverOptions {
        &self.options
    }

    /// Inject a [`RevocationPolicy`] into every node this resolver
    /// verifies (issue #260, closing LIM-1). Default
    /// [`RevocationPolicy::default`] (empty `known`, `discover: None`) is
    /// inert — this method is the opt-in.
    ///
    /// Deliberately `RevocationPolicy`, never `VerificationPolicy`: this
    /// resolver derives [`VerificationPolicy::receipts`] per node from
    /// that node's upstream-advertised capabilities (`Require` iff the
    /// upstream claims `acdp-registry-receipts`) — a capability-dependent
    /// escalation a caller cannot express statically, since a walk can
    /// visit authorities it does not know in advance. Accepting a full
    /// `VerificationPolicy` here would have no coherent semantics:
    /// honoring it verbatim would let a caller unknowingly strip
    /// `Require` on a receipts-capable upstream (a downgrade primitive),
    /// while silently overriding it would violate the "uniform policy"
    /// contract every other policy-taking entry point upholds. `known`
    /// travels with this policy, so a caller can enforce a
    /// pre-discovered revocation set across a whole walk without
    /// enabling live discovery at all.
    ///
    /// Not consulted by [`Self::resolve`]/[`Self::walk_derived_from`]'s
    /// safety limits ([`ResolverOptions`]) — see that struct's doc for
    /// why revocation configuration does not live there either.
    pub fn with_revocation_policy(mut self, policy: RevocationPolicy) -> Self {
        self.revocation_policy = policy;
        self
    }

    /// Inject a [`RevocationCache`] to share across every per-authority
    /// client this resolver builds or is seeded with (issue #260),
    /// instead of the fresh, walk-scoped cache
    /// [`Self::walk_derived_from`] otherwise creates for each call. Use
    /// this when discovery should stay warm ACROSS separate walks
    /// against long-lived resolver, at the cost of cached absence
    /// (a freshness marker) potentially outliving any single walk — see
    /// [`Self::walk_derived_from`]'s doc for the default this replaces
    /// and the exposure it carries.
    pub fn with_revocation_cache(mut self, cache: RevocationCache) -> Self {
        self.revocation_cache = Some(cache);
        self
    }

    /// Borrow the active revocation policy. Useful for tests + telemetry.
    pub fn revocation_policy(&self) -> &RevocationPolicy {
        &self.revocation_policy
    }

    /// Override the [`WebResolver`] used for DID document lookups.
    ///
    /// Primary use is supplying a `WebResolver::with_root_cert_pem`
    /// instance in tests so a self-signed mock can answer DID-document
    /// requests for `did:web:localhost%3A<port>`. Production callers do
    /// not need this — the default resolver trusts the system CA bundle.
    pub fn with_did_resolver(mut self, resolver: WebResolver) -> Self {
        self.did_resolver = resolver;
        self
    }

    /// Pre-populate the per-authority [`RegistryClient`] cache.
    ///
    /// Primary use is the conformance harness: tests supply a client
    /// whose HTTP layer trusts the in-process TLS server's self-signed
    /// root certificate (via [`RegistryClient::with_root_cert_pem`]), so
    /// the resolver hits the mock instead of attempting a real network
    /// call. The seeded client wins over the lazy pin-once
    /// `RegistryClient::builder(..).pinned(true)` client that
    /// [`Self::resolve`] would otherwise build on first access.
    pub fn seed_client(&self, authority: impl Into<String>, client: RegistryClient) {
        self.client_cache
            .lock()
            .unwrap()
            .insert(authority.into(), client);
    }

    /// Restrict cross-registry resolution to a fixed set of authorities
    /// (lowercase DNS hostnames). When set, any reference outside the
    /// allowlist is rejected with [`AcdpError::CrossRegistryResolutionFailed`].
    pub fn with_allowlist<I, S>(mut self, authorities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowlist = Some(authorities.into_iter().map(Into::into).collect());
        self
    }

    /// Resolve a single cross-registry [`CtxId`] end-to-end.
    ///
    /// Steps 1–7 of RFC-ACDP-0006 §4.1: parse, fetch capabilities,
    /// verify the registry DID *and* its DID document's web binding,
    /// retrieve, recompute hash, verify signature, and (step 7,
    /// NORMATIVE) bind the resolved identity — reached through
    /// `fetch_with_policy`, which refuses a served body whose `ctx_id`
    /// is not the one requested. The [`SsrfPolicy`] is checked first so
    /// a hostile authority cannot drive an internal-network request.
    ///
    /// Applies [`Self::revocation_policy`] (issue #260). If a
    /// [`RevocationCache`] was injected via [`Self::with_revocation_cache`],
    /// it is attached to the per-authority client used here,
    /// fill-if-absent: a client that already carries its own cache (e.g.
    /// via [`Self::seed_client`]) keeps it. Called directly, outside a
    /// [`Self::walk_derived_from`] call, there is no walk-scoped cache to
    /// fall back on — a bare `resolve()` gets seeding/suppression only
    /// when [`Self::with_revocation_cache`] was called explicitly. It is
    /// also bounded only by `RevocationDiscovery::total_timeout`
    /// (`crate::RevocationDiscovery`) when `discover` is set —
    /// [`ResolverOptions::total_timeout`] wraps [`Self::walk_derived_from`],
    /// not this method.
    pub async fn resolve(&self, ctx_id: &CtxId) -> Result<VerifiedContext, AcdpError> {
        self.resolve_inner(ctx_id, self.revocation_cache.as_ref())
            .await
    }

    /// Shared implementation behind [`Self::resolve`] and the per-node
    /// calls [`Self::walk_derived_from_inner`] makes. `cache` is either
    /// the resolver-wide handle ([`Self::with_revocation_cache`]) or a
    /// fresh, walk-scoped one built once per [`Self::walk_derived_from`]
    /// call — see that method's doc.
    async fn resolve_inner(
        &self,
        ctx_id: &CtxId,
        cache: Option<&RevocationCache>,
    ) -> Result<VerifiedContext, AcdpError> {
        let parsed = CtxId::parse(ctx_id.as_str())?;
        let authority = parsed.authority().to_string();
        self.check_allowlist(&authority)?;

        // RFC-ACDP-0006 §7: SSRF policy on the outbound base URL.
        let base = format!("https://{authority}");
        self.ssrf_policy
            .check_url(&base)
            .map_err(|e| AcdpError::CrossRegistryResolutionFailed(format!("SSRF policy: {e}")))?;

        // Cached client (and capabilities) per authority.
        let registry = self.client_for(&authority, &base).await?;
        // Issue #260: fill-if-absent. A client returned by `client_for`
        // (built, cached, or seeded via `Self::seed_client`) that carries
        // no `RevocationCache` of its own gets this call's `cache`
        // attached; one that already carries a cache (a caller-seeded
        // client wiring its own) keeps it unchanged. Precedence:
        // explicit-on-client > explicit-on-resolver/walk > none. This is
        // what makes vantage binding fall out for free: each authority's
        // client is attached (or already carries) a cache independently,
        // matching `RevocationCache`'s own per-origin scoping
        // (RFC-ACDP-0014 §6).
        let registry = match cache {
            Some(cache) if registry.revocation_cache().is_none() => {
                registry.with_revocation_cache(cache.clone())
            }
            _ => registry,
        };
        let caps = self.capabilities_for(&authority, &registry).await?;

        // Step 3a: capabilities.registry_did MUST be `did:web:<authority>`.
        // BUG-06: percent-encode `:` for host:port authorities so the
        // expected DID round-trips with `authority_to_did_web`.
        let expected_did = acdp_did::authority_to_did_web(&authority);
        if caps.registry_did != expected_did {
            return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                "registry DID '{}' does not match expected '{expected_did}'",
                caps.registry_did
            )));
        }

        // Step 3b (RFC-ACDP-0006 §4.1 step 3): resolve the registry's
        // DID document and confirm the web binding matches `<authority>`.
        let registry_doc = self
            .did_resolver
            .resolve(&caps.registry_did)
            .await
            .map_err(|e| {
                AcdpError::CrossRegistryResolutionFailed(format!(
                    "could not resolve registry DID document for '{}': {e}",
                    caps.registry_did
                ))
            })?;
        if registry_doc.id != caps.registry_did {
            return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                "registry DID document `id` '{}' does not match capabilities.registry_did '{}'",
                registry_doc.id, caps.registry_did
            )));
        }

        // Steps 4–6: retrieve + verify. fed-009 / RFC-ACDP-0010 §7+§11:
        // an upstream advertising `acdp-registry-receipts` MUST always
        // serve a receipt — absence is a registry fault (`invalid_receipt`),
        // not a degraded mode — so the policy escalates to `Require` for
        // such upstreams. Receipt-less upstreams proceed under the
        // v0.1.0 trust model (receipt verified only if one is present).
        //
        // Issue #260: `revocations` is injected from `self.revocation_policy`
        // — never a caller-supplied `VerificationPolicy` (no injection
        // point accepts one; see `Self::with_revocation_policy`'s doc for
        // why `receipts`, derived per-node just below, is the one field
        // that stays off-limits).
        let mut policy = VerificationPolicy {
            revocations: self.revocation_policy.clone(),
            ..VerificationPolicy::default()
        };
        if caps.claims_profile(acdp_types::profile::Profile::RegistryReceipts) {
            policy.receipts = ReceiptPolicy::Require;
        }
        VerifiedContext::fetch_with_policy(&registry, &self.did_resolver, &parsed, &policy).await
    }

    /// Walk the `derived_from` graph rooted at `body` with cycle detection,
    /// a per-edge depth cap of [`ResolverOptions::max_depth`], a total-
    /// nodes cap of `max_nodes`, a per-context fanout cap of `max_fanout`,
    /// and a wall-clock `total_timeout`. Returns each verified ancestor
    /// (excluding the root). Breadth-first; closer ancestors are returned
    /// first.
    ///
    /// # Revocation discovery is walk-scoped by default (issue #260)
    ///
    /// When [`Self::revocation_policy`] has `discover` set and no
    /// [`RevocationCache`] was injected via [`Self::with_revocation_cache`],
    /// this call creates a **fresh cache for this call only** and shares
    /// it across every node the walk visits — so discovery for a given
    /// `(authority, trust class)` runs at most once per walk regardless
    /// of `max_nodes`, rather than once per node. No cached absence
    /// outlives the call, so suppression is safe on default
    /// configuration without the caller needing to set a nonzero
    /// `RevocationDiscovery::freshness`. A caller who explicitly wants
    /// discovery to stay warm ACROSS separate walks (at the cost of a
    /// marker that can outlive any one of them) opts in via
    /// [`Self::with_revocation_cache`], which is then reused here
    /// instead of a fresh per-call cache.
    ///
    /// **The 30 s / 30 s default collision.** `RevocationDiscovery`'s
    /// `total_timeout` defaults to 30 s, matching
    /// [`ResolverOptions::total_timeout`]'s own default — but the two are
    /// nested: this method wraps the whole walk in
    /// `ResolverOptions::total_timeout`, and revocation discovery for
    /// EACH node re-applies its own `total_timeout` inside that. On an
    /// all-defaults configuration, one slow-but-not-yet-failed node's
    /// discovery can consume the entire walk's budget. This fails
    /// closed (the walk simply times out), so it is safe, but it is
    /// surprising — set `discovery.total_timeout` well below
    /// `ResolverOptions::total_timeout`, or raise the latter, if you
    /// enable discovery here. The walk-scoped cache substantially
    /// mitigates this in practice, since a repeat node at the same
    /// authority/class no longer re-runs discovery at all.
    pub async fn walk_derived_from(&self, body: &Body) -> Result<Vec<VerifiedContext>, AcdpError> {
        let total_timeout = self.options.total_timeout;
        // Issue #260: walk-scoped by default. `self.revocation_cache` is
        // the caller's explicit opt-in to cross-walk sharing
        // (`Self::with_revocation_cache`); absent that, build one fresh
        // `RevocationCache` here, alive only for this call, and thread it
        // into every node this walk resolves.
        let walk_cache = self.revocation_cache.clone().unwrap_or_default();
        let fut = self.walk_derived_from_inner(body, &walk_cache);
        match tokio::time::timeout(total_timeout, fut).await {
            Ok(res) => res,
            Err(_) => Err(AcdpError::CrossRegistryResolutionFailed(format!(
                "derived_from walk exceeded total_timeout={:?}",
                total_timeout
            ))),
        }
    }

    async fn walk_derived_from_inner(
        &self,
        body: &Body,
        cache: &RevocationCache,
    ) -> Result<Vec<VerifiedContext>, AcdpError> {
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(body.ctx_id.0.clone());

        if body.derived_from.len() > self.options.max_fanout {
            return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                "root context {} has derived_from fanout {} > max_fanout={}",
                body.ctx_id.0,
                body.derived_from.len(),
                self.options.max_fanout
            )));
        }

        let mut results: Vec<VerifiedContext> = Vec::new();
        let mut frontier: VecDeque<(CtxId, usize)> = body
            .derived_from
            .iter()
            .map(|c| (c.clone(), 1usize))
            .collect();

        while let Some((next, depth)) = frontier.pop_front() {
            if !seen.insert(next.0.clone()) {
                continue; // cycle
            }
            if depth > self.options.max_depth {
                return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                    "derived_from walk exceeded max_depth={} at {}",
                    self.options.max_depth, next.0
                )));
            }
            if results.len() >= self.options.max_nodes {
                return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                    "derived_from walk exceeded max_nodes={} (last attempted: {})",
                    self.options.max_nodes, next.0
                )));
            }
            let verified = self.resolve_inner(&next, Some(cache)).await?;
            let parents = &verified.body().derived_from;
            if parents.len() > self.options.max_fanout {
                return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                    "context {} has derived_from fanout {} > max_fanout={}",
                    next.0,
                    parents.len(),
                    self.options.max_fanout
                )));
            }
            for parent in parents {
                if !seen.contains(parent.as_str()) {
                    frontier.push_back((parent.clone(), depth + 1));
                }
            }
            results.push(verified);
        }
        Ok(results)
    }

    fn check_allowlist(&self, authority: &str) -> Result<(), AcdpError> {
        if let Some(list) = &self.allowlist {
            if !list.contains(authority) {
                return Err(AcdpError::CrossRegistryResolutionFailed(format!(
                    "authority '{authority}' is not on the resolver allowlist"
                )));
            }
        }
        Ok(())
    }

    /// Return a cached `RegistryClient` for the authority, building one
    /// on first use. Reuse across hops avoids per-hop reqwest
    /// connection-pool churn.
    ///
    /// SEC-01: the client is built via
    /// `RegistryClient::builder(base).pinned(true)`, which resolves the
    /// authority's DNS up-front, filters every resolved IP through the
    /// resolver's [`SsrfPolicy`], and pins the connection to that
    /// address. Without pinning a hostile `ctx_id`
    /// authority (e.g. `internal-host.example.com` resolving to
    /// `10.0.0.1` or `169.254.169.254`) would slip past the URL-syntax
    /// `check_url` gate and reach an internal target. The seeded test
    /// path ([`Self::seed_client`]) bypasses this constructor.
    async fn client_for(&self, authority: &str, base: &str) -> Result<RegistryClient, AcdpError> {
        {
            let cache = self.client_cache.lock().unwrap();
            if let Some(c) = cache.get(authority) {
                return Ok(c.clone());
            }
        }
        // Build with pin-once DNS resolution before taking the cache
        // lock — the builder's `.build()` is async (it resolves the
        // authority up front) and the cache mutex must not be held
        // across the await.
        let client = RegistryClient::builder(base)
            .pinned(true)
            .ssrf_policy(self.ssrf_policy.clone())
            .build()
            .await?;
        let mut cache = self.client_cache.lock().unwrap();
        Ok(cache.entry(authority.to_string()).or_insert(client).clone())
    }

    /// Return the cached capabilities for `authority`, fetching when
    /// the entry is missing or its per-response TTL has elapsed.
    ///
    /// BUG-09: TTL comes from the response's `Cache-Control: max-age=N`
    /// (clamped to `[1s, ResolverOptions::capabilities_ttl]` so the
    /// resolver-wide ceiling still applies) rather than a fixed value.
    /// A registry serving `Cache-Control: max-age=60` is honored; one
    /// serving no `Cache-Control` falls back to the
    /// [`RegistryClient::capabilities_with_ttl`] default (300s).
    async fn capabilities_for(
        &self,
        authority: &str,
        registry: &RegistryClient,
    ) -> Result<CapabilitiesDocument, AcdpError> {
        // Fast path: cache hit + within per-response TTL.
        {
            let cache = self.caps_cache.lock().unwrap();
            if let Some((caps, fetched_at, ttl)) = cache.get(authority) {
                if fetched_at.elapsed() < *ttl {
                    return Ok(caps.clone());
                }
            }
        }
        let (caps, response_ttl) = registry
            .capabilities_with_ttl()
            .await
            .map_err(|e| match e {
                AcdpError::Http(_) | AcdpError::KeyResolutionUnreachable(_) => {
                    AcdpError::CrossRegistryResolutionFailed(format!(
                        "could not reach registry '{authority}': {e}"
                    ))
                }
                other => other,
            })?;
        // Clamp to the resolver-wide ceiling so a registry advertising
        // an absurd `max-age` can't pin a stale doc indefinitely.
        let ttl = response_ttl.min(self.options.capabilities_ttl);
        let mut cache = self.caps_cache.lock().unwrap();
        cache.insert(authority.to_string(), (caps.clone(), Instant::now(), ttl));
        Ok(caps)
    }

    /// Return the capabilities document already cached for `authority`
    /// from a prior walk, without fetching.
    ///
    /// `resolve`/`walk_derived_from` fetch and cache a foreign registry's
    /// capabilities internally (via the private `capabilities_for`) but
    /// never exposed the result, so a caller that also needs that document
    /// (e.g. to check a profile the resolver itself didn't need) had no
    /// way to read it back and had to issue a second, duplicate fetch.
    /// Returns `None` if the resolver has never cached an entry for this
    /// authority, or if the cached entry's per-response TTL has elapsed —
    /// this is a cache peek, not a fetch-or-refresh, so a stale entry is
    /// reported as absent rather than silently returned.
    pub fn cached_capabilities(&self, authority: &str) -> Option<CapabilitiesDocument> {
        let cache = self.caps_cache.lock().unwrap();
        cache
            .get(authority)
            .and_then(|(caps, fetched_at, ttl)| (fetched_at.elapsed() < *ttl).then(|| caps.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_caps() -> CapabilitiesDocument {
        serde_json::from_value(serde_json::json!({
            "acdp_version": "0.4.0",
            "registry_did": "did:web:registry.example.com",
            "supported_signature_algorithms": ["ed25519"],
            "supported_did_methods": ["did:web"],
            "profiles": ["acdp-registry-core"],
            "limits": {"max_payload_bytes": 1_048_576, "max_embedded_bytes": 65536},
        }))
        .unwrap()
    }

    #[test]
    fn cached_capabilities_returns_none_when_never_fetched() {
        let resolver = CrossRegistryResolver::new();
        assert!(resolver
            .cached_capabilities("registry.example.com")
            .is_none());
    }

    #[test]
    fn cached_capabilities_returns_fresh_entry_without_fetching() {
        let resolver = CrossRegistryResolver::new();
        resolver.caps_cache.lock().unwrap().insert(
            "registry.example.com".to_string(),
            (test_caps(), Instant::now(), Duration::from_secs(300)),
        );
        let caps = resolver
            .cached_capabilities("registry.example.com")
            .expect("entry was just seeded fresh");
        assert_eq!(caps.registry_did, "did:web:registry.example.com");
    }

    #[test]
    fn cached_capabilities_reports_expired_entry_as_absent() {
        let resolver = CrossRegistryResolver::new();
        // `checked_sub` avoids a debug-mode underflow panic if the test
        // runs within 60s of process start.
        let long_ago = Instant::now()
            .checked_sub(Duration::from_secs(60))
            .expect("test host uptime exceeds 60s");
        resolver.caps_cache.lock().unwrap().insert(
            "registry.example.com".to_string(),
            (test_caps(), long_ago, Duration::from_secs(1)),
        );
        assert!(resolver
            .cached_capabilities("registry.example.com")
            .is_none());
    }

    #[test]
    fn allowlist_rejects_outside_authorities() {
        let resolver =
            CrossRegistryResolver::new().with_allowlist(["registry.example.com".to_string()]);
        let err = resolver.check_allowlist("evil.com").unwrap_err();
        assert!(matches!(err, AcdpError::CrossRegistryResolutionFailed(_)));
        resolver.check_allowlist("registry.example.com").unwrap();
    }

    #[test]
    fn options_default_values_match_doc() {
        let o = ResolverOptions::default();
        assert_eq!(o.max_depth, 10);
        assert_eq!(o.max_nodes, 100);
        assert_eq!(o.max_fanout, 32);
        assert_eq!(o.total_timeout, Duration::from_secs(30));
        assert_eq!(o.capabilities_ttl, Duration::from_secs(300));
    }

    #[test]
    fn with_options_replaces_full_struct() {
        let r = CrossRegistryResolver::new().with_options(ResolverOptions {
            max_depth: 3,
            max_nodes: 7,
            max_fanout: 2,
            total_timeout: Duration::from_secs(5),
            capabilities_ttl: Duration::from_secs(60),
        });
        assert_eq!(r.options().max_depth, 3);
        assert_eq!(r.options().max_nodes, 7);
        assert_eq!(r.options().max_fanout, 2);
    }

    #[test]
    fn cycle_detection_short_circuits() {
        let _resolver = CrossRegistryResolver::new();
        let mut seen: HashSet<String> = HashSet::new();
        let id = "acdp://r/12345678-1234-4321-8123-123456781234".to_string();
        assert!(seen.insert(id.clone()));
        assert!(!seen.insert(id));
    }
}
