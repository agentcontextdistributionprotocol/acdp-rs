//! SSRF defenses for server-side cross-registry resolution
//! (RFC-ACDP-0006 §7).
//!
//! ## Single source of SSRF policy
//!
//! This module is the **single source of truth** for ACDP's SSRF policy
//! across both the `client` and `server` features. The server-scoped
//! path (`crate::registry::safe_http`) does not reimplement any of this
//! — it only *re-exports* [`SsrfPolicy`] from here (see
//! `src/registry/safe_http.rs`). Any change to blocked IP ranges, the
//! HTTPS-only rule, redirect limits, or DNS-rebinding handling therefore
//! applies to client and server alike; there is no second copy to keep
//! in sync. Do not add a divergent implementation under `registry/`.
//!
//! When a registry resolves a foreign `acdp://` reference on behalf of a
//! consumer, it must defend against attacker-supplied URIs that target the
//! registry's own internal network. This module implements the policy
//! decisions enumerated by §7:
//!
//! - **§7.1** Reject loopback, RFC 1918 / 4193 private ranges, link-local,
//!   multicast, the AWS / GCP metadata endpoint (`169.254.169.254`), and
//!   the IPv6 equivalents.
//! - **§7.2** HTTPS-only.
//! - **§7.3** Response-size caps.
//! - **§7.5** Maximum redirects, same-authority only.
//! - **§7.6** DNS rebinding protection. [`SsrfPolicy::pin_resolved_ip`]
//!   resolves a hostname once, validates **every** returned IP, and
//!   returns a [`SocketAddr`] that the caller pins into
//!   `reqwest::Client::builder().resolve(host, addr)` — so the filter
//!   and the connection use the same IP, defeating a hostile DNS server
//!   flipping the answer between the two. Per §7.1 the resolution is
//!   rejected outright if **any** returned IP is forbidden — a public
//!   answer cannot mask a private one.

#[cfg(feature = "client")]
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use acdp_primitives::AcdpError;

#[cfg(feature = "client")]
use std::sync::Arc;

// Re-exported from `acdp_primitives::limits` for back-compat.
pub use acdp_primitives::limits::{MAX_CONTEXT_BYTES, MAX_METADATA_BYTES, MAX_REDIRECTS};

/// Stable, machine-readable reason an SSRF check rejected a target.
///
/// Surfaced by the [`SsrfPolicy::classify_url`] / [`SsrfPolicy::classify_ip`]
/// / [`SsrfPolicy::classify_redirect`] family so callers can react
/// programmatically — and so language bindings can map a rejection to a
/// typed exception — instead of string-matching the free-form detail
/// message. Maps to RFC-ACDP-0006 §7 / RFC-ACDP-0008 §4.8.
///
/// `#[non_exhaustive]`: future spec revisions may add ranges; match with a
/// wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SsrfReason {
    /// URL scheme is not `https` (and `allow_http` is off).
    NonHttps,
    /// URL embeds an IP literal; a hostname (forcing DNS) is required.
    IpLiteral,
    /// URL could not be parsed, has no host, or has an invalid hostname.
    InvalidUrl,
    /// Loopback range — IPv4 `127.0.0.0/8` or IPv6 `::1`.
    Loopback,
    /// Private range — RFC 1918 (`10/8`, `172.16/12`, `192.168/16`),
    /// CGNAT `100.64/10`, or IPv6 ULA `fc00::/7`.
    Private,
    /// Link-local / cloud instance-metadata reach — IPv4 `169.254.0.0/16`
    /// (incl. `169.254.169.254`), IPv6 `fe80::/10`, and the NAT64
    /// well-known prefix `64:ff9b::/96` (which can translate to IMDS).
    Imds,
    /// Multicast or otherwise reserved/unusable range (`0.0.0.0/8`,
    /// `192.0.0.0/24`, `198.18.0.0/15`, `224.0.0.0/4`, `240.0.0.0/4`,
    /// IPv6 multicast / unspecified).
    MulticastOrReserved,
    /// A redirect target whose scheme, host, or effective port differs
    /// from the originating request's authority (RFC-ACDP-0006 §7.5).
    CrossAuthority,
}

impl SsrfReason {
    /// The stable snake_case identifier for this reason — the contract
    /// language bindings expose to host code.
    pub fn as_str(&self) -> &'static str {
        match self {
            SsrfReason::NonHttps => "non_https",
            SsrfReason::IpLiteral => "ip_literal",
            SsrfReason::InvalidUrl => "invalid_url",
            SsrfReason::Loopback => "loopback",
            SsrfReason::Private => "private",
            SsrfReason::Imds => "imds",
            SsrfReason::MulticastOrReserved => "multicast_or_reserved",
            SsrfReason::CrossAuthority => "cross_authority",
        }
    }
}

impl std::fmt::Display for SsrfReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rejection produced by the `classify_*` SSRF checks: a stable
/// [`SsrfReason`] discriminant plus a human-readable detail.
///
/// Converts to [`AcdpError::SchemaViolation`] (carrying `detail`) via
/// `From`, so the back-compat `check_*` wrappers preserve their existing
/// error shape exactly.
#[derive(Debug, Clone)]
pub struct SsrfRejection {
    /// Stable machine-readable reason code.
    pub reason: SsrfReason,
    /// Human-readable explanation (the message the legacy `check_*`
    /// methods surfaced).
    pub detail: String,
}

impl std::fmt::Display for SsrfRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}]", self.detail, self.reason)
    }
}

impl From<SsrfRejection> for AcdpError {
    fn from(r: SsrfRejection) -> Self {
        AcdpError::SchemaViolation(r.detail)
    }
}

/// SSRF policy applied to outbound HTTP requests.
#[derive(Debug, Clone)]
pub struct SsrfPolicy {
    /// If true, reject IP literals in the URL (forces DNS resolution).
    pub reject_ip_literals: bool,
    /// If false, only `https://` URLs are accepted. Default `false`.
    pub allow_http: bool,
    /// When true, permit IPv4 `127.0.0.0/8` and IPv6 `::1` (loopback)
    /// across [`Self::check_ip`] / [`Self::check_resolved_ip`] /
    /// [`Self::pin_resolved_ip`]. All other forbidden ranges
    /// (RFC 1918, link-local / IMDS, ULA, CGNAT, multicast, …) still
    /// apply. Default `false`.
    ///
    /// Intended for test harnesses that resolve `did:web:localhost…`
    /// against a self-signed in-process HTTPS server bound to
    /// `127.0.0.1`. Production callers MUST keep this `false` — opening
    /// loopback turns the resolver into an SSRF vector against
    /// process-internal listeners (RFC-ACDP-0008 §4.8).
    pub allow_loopback_resolved: bool,
}

impl Default for SsrfPolicy {
    fn default() -> Self {
        Self {
            reject_ip_literals: true,
            allow_http: false,
            allow_loopback_resolved: false,
        }
    }
}

impl SsrfPolicy {
    /// A test-only policy: defaults + `allow_loopback_resolved = true`.
    ///
    /// `#[doc(hidden)]` because production must never use this — see
    /// [`Self::allow_loopback_resolved`].
    #[doc(hidden)]
    #[cfg(feature = "test-transport")]
    pub fn allow_test_loopback() -> Self {
        Self {
            allow_loopback_resolved: true,
            ..Self::default()
        }
    }
}

impl SsrfPolicy {
    /// Validate a URL string (scheme + host) before issuing a request.
    ///
    /// Back-compat wrapper over [`Self::classify_url`]: a rejection maps
    /// to [`AcdpError::SchemaViolation`] with the same detail message
    /// callers have always seen.
    pub fn check_url(&self, url: &str) -> Result<(), AcdpError> {
        self.classify_url(url).map_err(AcdpError::from)
    }

    /// Validate a URL string, returning a stable [`SsrfRejection`]
    /// (reason code + detail) on failure.
    ///
    /// Checks scheme (HTTPS-only unless `allow_http`), IP-literal
    /// rejection, per-IP range filtering for literal hosts, and hostname
    /// length. Prefer this over [`Self::check_url`] when the caller needs
    /// to branch on *why* the URL was rejected (e.g. a language binding
    /// mapping to a typed exception).
    pub fn classify_url(&self, url: &str) -> Result<(), SsrfRejection> {
        let parsed = url::Url::parse(url).map_err(|e| SsrfRejection {
            reason: SsrfReason::InvalidUrl,
            detail: format!("invalid URL: {e}"),
        })?;

        if !self.allow_http && parsed.scheme() != "https" {
            return Err(SsrfRejection {
                reason: SsrfReason::NonHttps,
                detail: format!(
                    "SSRF policy: scheme '{}' not permitted; only https",
                    parsed.scheme()
                ),
            });
        }

        let host = parsed.host().ok_or_else(|| SsrfRejection {
            reason: SsrfReason::InvalidUrl,
            detail: format!("URL has no host: {url}"),
        })?;

        match host {
            url::Host::Ipv4(v4) => {
                if self.reject_ip_literals {
                    return Err(SsrfRejection {
                        reason: SsrfReason::IpLiteral,
                        detail: format!(
                            "SSRF policy: IPv4 literal '{v4}' not permitted; use a hostname"
                        ),
                    });
                }
                self.classify_ip(IpAddr::V4(v4))?;
            }
            url::Host::Ipv6(v6) => {
                if self.reject_ip_literals {
                    return Err(SsrfRejection {
                        reason: SsrfReason::IpLiteral,
                        detail: format!(
                            "SSRF policy: IPv6 literal '{v6}' not permitted; use a hostname"
                        ),
                    });
                }
                self.classify_ip(IpAddr::V6(v6))?;
            }
            url::Host::Domain(name) => {
                if name.is_empty() || name.len() > 253 {
                    return Err(SsrfRejection {
                        reason: SsrfReason::InvalidUrl,
                        detail: format!("SSRF policy: invalid hostname length: {name}"),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validate an already-resolved [`IpAddr`] — useful when DNS resolution
    /// is performed externally and the caller wants to filter pre-connect.
    /// Respects [`Self::allow_loopback_resolved`].
    pub fn check_resolved_ip(&self, ip: IpAddr) -> Result<(), AcdpError> {
        self.check_ip(ip)
    }

    /// Range filter for a single [`IpAddr`], respecting the policy's
    /// [`Self::allow_loopback_resolved`] flag.
    ///
    /// Back-compat wrapper over [`Self::classify_ip`].
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), AcdpError> {
        self.classify_ip(ip).map_err(AcdpError::from)
    }

    /// Range filter for a single [`IpAddr`], returning a stable
    /// [`SsrfRejection`] (reason code + detail) when the address falls in
    /// a forbidden range. Respects [`Self::allow_loopback_resolved`].
    pub fn classify_ip(&self, ip: IpAddr) -> Result<(), SsrfRejection> {
        let reason = match ip {
            IpAddr::V4(v4) => {
                if self.allow_loopback_resolved && v4.is_loopback() {
                    None
                } else {
                    classify_unsafe_v4(v4)
                }
            }
            IpAddr::V6(v6) => {
                if self.allow_loopback_resolved && v6.is_loopback() {
                    None
                } else {
                    classify_unsafe_v6(v6)
                }
            }
        };
        match reason {
            Some(reason) => Err(SsrfRejection {
                reason,
                detail: format!("SSRF policy: IP address '{ip}' is in a forbidden range"),
            }),
            None => Ok(()),
        }
    }

    /// DNS rebinding protection per RFC-ACDP-0006 §7.6.
    ///
    /// Resolves `host:port`, validates **every** returned address, and
    /// returns one [`SocketAddr`] to pin. The caller MUST pin this exact
    /// address into the HTTP client via
    /// `reqwest::Client::builder().resolve(host, addr)` — otherwise a
    /// hostile authoritative DNS could flip the answer between the filter
    /// check and the connect, bypassing §7.1.
    ///
    /// RFC-ACDP-0006 §7.1 / RFC-ACDP-0008 §4.8: if **any** resolved
    /// address is in a forbidden range, the **entire** resolution is
    /// rejected — an attacker MUST NOT be able to bypass the filter by
    /// mixing one public and one private answer in a single DNS response.
    ///
    /// Returns [`AcdpError::Http`] when DNS returns no answers and
    /// [`AcdpError::SchemaViolation`] when any answer is in a forbidden
    /// range.
    #[cfg(feature = "client")]
    pub async fn pin_resolved_ip(&self, host: &str, port: u16) -> Result<SocketAddr, AcdpError> {
        let target = format!("{host}:{port}");
        let candidates: Vec<SocketAddr> = tokio::net::lookup_host(&target)
            .await
            .map_err(|e| AcdpError::Http(format!("DNS lookup for '{host}' failed: {e}")))?
            .collect();
        if candidates.is_empty() {
            return Err(AcdpError::Http(format!(
                "DNS lookup for '{host}' returned no addresses"
            )));
        }
        // Validate EVERY resolved address before pinning one. Any failure
        // aborts the whole resolution (no silent filtering).
        reject_if_any_forbidden(self, host, &candidates)?;
        // All candidates passed — pin the first (IPv4-preferred).
        let pinned = candidates
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| candidates.first())
            .copied()
            .expect("candidates is non-empty");
        Ok(pinned)
    }

    /// Per §7.5: a redirect is permitted only if it stays within the same
    /// fetch authority as the originating request — identical scheme,
    /// host, and effective port (RFC-ACDP-0008 §4.8: "host + port").
    pub fn check_redirect_authority(
        &self,
        original_url: &url::Url,
        redirect_url: &str,
    ) -> Result<(), AcdpError> {
        self.classify_redirect_authority(original_url, redirect_url)
            .map_err(AcdpError::from)
    }

    /// Same-authority redirect check returning a stable [`SsrfRejection`].
    /// See [`Self::check_redirect_authority`].
    pub fn classify_redirect_authority(
        &self,
        original_url: &url::Url,
        redirect_url: &str,
    ) -> Result<(), SsrfRejection> {
        let redirect = url::Url::parse(redirect_url).map_err(|e| SsrfRejection {
            reason: SsrfReason::InvalidUrl,
            detail: format!("invalid redirect URL: {e}"),
        })?;
        if !same_fetch_authority(original_url, &redirect) {
            return Err(SsrfRejection {
                reason: SsrfReason::CrossAuthority,
                detail: format!(
                    "SSRF policy: cross-authority redirect rejected: {original_url} → {redirect}"
                ),
            });
        }
        Ok(())
    }

    /// String-in/string-in convenience over [`Self::classify_redirect_authority`]
    /// for FFI callers that hold both endpoints as strings (no `url::Url`
    /// on the boundary). Parses `from_url` as the origin authority, then
    /// applies the same scheme + host + effective-port equality.
    pub fn classify_redirect(&self, from_url: &str, to_url: &str) -> Result<(), SsrfRejection> {
        let original = url::Url::parse(from_url).map_err(|e| SsrfRejection {
            reason: SsrfReason::InvalidUrl,
            detail: format!("invalid origin URL: {e}"),
        })?;
        self.classify_redirect_authority(&original, to_url)
    }
}

/// Returns `true` when `a` and `b` share the same fetch authority:
/// identical scheme, identical host, and identical effective port
/// (the scheme default applies — 443 for `https`, 80 for `http`).
///
/// RFC-ACDP-0006 §7.5 and RFC-ACDP-0008 §4.8: a "same authority"
/// redirect must match host **and** port; this also pins the scheme so
/// an `https → http` downgrade can never be treated as same-authority.
#[doc(hidden)]
pub fn same_fetch_authority(a: &url::Url, b: &url::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Strict-default range filter (no loopback allowance). Retained as a
/// test-only helper that pins the legacy `check_safe_ip` semantics —
/// production callers should use the policy-aware
/// [`SsrfPolicy::check_ip`] instead.
#[cfg(test)]
fn check_safe_ip(ip: IpAddr) -> Result<(), AcdpError> {
    let bad = match ip {
        IpAddr::V4(v4) => classify_unsafe_v4(v4).is_some(),
        IpAddr::V6(v6) => classify_unsafe_v6(v6).is_some(),
    };
    if bad {
        return Err(AcdpError::SchemaViolation(format!(
            "SSRF policy: IP address '{ip}' is in a forbidden range"
        )));
    }
    Ok(())
}

// ── DNS-rebinding protection (RFC-ACDP-0006 §7.6 / RFC-ACDP-0008 §4.8) ──────
//
// Plumb [`SsrfPolicy::check_ip`] into reqwest's DNS resolver hook so the
// filter and the actual TCP connect see the SAME resolved IP. A hostile
// authoritative DNS server can no longer flip the answer between a
// pre-connect `pin_resolved_ip` check and the real connect: reqwest
// passes the addresses we return straight to the connector.

/// Reject the **entire** resolution if ANY candidate address is in a
/// forbidden range (RFC-ACDP-0006 §7.1 / RFC-ACDP-0008 §4.8). Shared by
/// [`SsrfPolicy::pin_resolved_ip`] and [`SafeDnsResolver`]'s resolve hook so
/// both apply identical reject-all semantics — never silent filtering.
///
/// Public because it is the canonical enforcement point the
/// mixed-answer conformance fixtures pin (`did-ssrf-004`,
/// `data-ref-ssrf-004`, `fed-007`), and so implementations that resolve
/// DNS themselves can reuse the reject-all rule instead of
/// re-implementing it (filter-and-proceed is explicitly non-conformant).
#[cfg(feature = "client")]
pub fn reject_if_any_forbidden(
    policy: &SsrfPolicy,
    host: &str,
    candidates: &[SocketAddr],
) -> Result<(), AcdpError> {
    for addr in candidates {
        if let Err(e) = policy.check_ip(addr.ip()) {
            return Err(AcdpError::SchemaViolation(format!(
                "SSRF policy: DNS answer for '{host}' contains a forbidden address \
                 ({} is disallowed); rejecting the entire resolution. {e}",
                addr.ip()
            )));
        }
    }
    Ok(())
}

/// `reqwest::dns::Resolve` implementation that validates every resolved
/// IP through an [`SsrfPolicy`] before handing them to the connector.
#[cfg(feature = "client")]
#[doc(hidden)]
pub struct SafeDnsResolver {
    policy: SsrfPolicy,
}

#[cfg(feature = "client")]
impl SafeDnsResolver {
    #[doc(hidden)]
    pub fn arc(policy: SsrfPolicy) -> Arc<Self> {
        Arc::new(Self { policy })
    }
}

/// Build a `reqwest::Client` hardened against SSRF for outbound POSTs to
/// operator-configured endpoints (webhook delivery, federation feeds).
///
/// Every resolved IP is filtered through `policy` at DNS time via
/// `SafeDnsResolver` — defeating DNS rebinding (RFC-ACDP-0008 §4.8) — and
/// redirects are refused outright: such an endpoint must respond directly, not
/// bounce the registry to an internal host (e.g. cloud IMDS). `connect` and
/// request timeouts are bounded. Use [`SsrfPolicy::default`] in production and
/// [`SsrfPolicy::allow_test_loopback`] in tests that POST to a local listener.
#[cfg(feature = "client")]
pub fn safe_client(
    policy: &SsrfPolicy,
    timeout: std::time::Duration,
) -> Result<reqwest::Client, AcdpError> {
    reqwest::Client::builder()
        .use_rustls_tls()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        // Each outbound POST to an operator endpoint is independent; a fresh
        // connection per request avoids reusing a pooled connection to an
        // endpoint that has since gone away (and re-runs the SafeDnsResolver
        // check every time rather than pinning a once-resolved IP).
        .pool_max_idle_per_host(0)
        .dns_resolver(SafeDnsResolver::arc(policy.clone()))
        .build()
        .map_err(|e| AcdpError::Http(e.to_string()))
}

#[cfg(feature = "client")]
impl reqwest::dns::Resolve for SafeDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.policy.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port 0 — reqwest replaces it with the URL's port (or the
            // scheme default) before connecting. We only care about the
            // IPs returned.
            let target = format!("{host}:0");
            let candidates: Vec<SocketAddr> = tokio::net::lookup_host(&target)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();

            if candidates.is_empty() {
                let msg: String = format!("DNS lookup for '{host}' returned no addresses");
                return Err(msg.into());
            }

            // RFC-ACDP-0006 §7.1 / RFC-ACDP-0008 §4.8: validate EVERY
            // resolved address. If any answer is in a forbidden range the
            // ENTIRE resolution is rejected — never silently filter, or an
            // attacker bypasses the filter by mixing one public and one
            // private answer in a single DNS response. reqwest bubbles
            // this up as a transport error; returning the typed
            // `SsrfDnsRefusal` marker lets every caller's error mapper
            // (`From<reqwest::Error>`, `WebResolver`) recognize it via
            // `acdp_primitives::error::is_ssrf_refusal` and classify it as
            // permanent rather than as a retryable transport error.
            if let Err(e) = reject_if_any_forbidden(&policy, &host, &candidates) {
                let msg = match e {
                    AcdpError::SchemaViolation(m) => m,
                    other => other.to_string(),
                };
                let refusal: Box<dyn std::error::Error + Send + Sync> =
                    Box::new(acdp_primitives::error::SsrfDnsRefusal::new(msg));
                return Err(refusal);
            }

            let addrs: reqwest::dns::Addrs = Box::new(candidates.into_iter());
            Ok(addrs)
        })
    }
}

/// Classify an IPv4 address against the forbidden ranges, returning the
/// stable [`SsrfReason`] for the first range it falls in (or `None` when
/// the address is safe to connect to). The set of rejected addresses is
/// identical to the historical `is_unsafe_v4` predicate — only the reason
/// granularity is new.
fn classify_unsafe_v4(ip: Ipv4Addr) -> Option<SsrfReason> {
    let o = ip.octets();
    if o[0] == 0 {
        // 0.0.0.0/8 — current network
        Some(SsrfReason::MulticastOrReserved)
    } else if o[0] == 10 {
        // 10.0.0.0/8 — private
        Some(SsrfReason::Private)
    } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
        // 100.64.0.0/10 — CGNAT
        Some(SsrfReason::Private)
    } else if o[0] == 127 {
        // 127.0.0.0/8 — loopback
        Some(SsrfReason::Loopback)
    } else if o[0] == 169 && o[1] == 254 {
        // 169.254.0.0/16 — link-local + AWS/GCP IMDS
        Some(SsrfReason::Imds)
    } else if o[0] == 172 && (o[1] & 0xf0) == 16 {
        // 172.16.0.0/12 — private
        Some(SsrfReason::Private)
    } else if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        // 192.0.0.0/24 — IETF protocol
        Some(SsrfReason::MulticastOrReserved)
    } else if o[0] == 192 && o[1] == 168 {
        // 192.168.0.0/16 — private
        Some(SsrfReason::Private)
    } else if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        // 198.18.0.0/15 — benchmarking
        Some(SsrfReason::MulticastOrReserved)
    } else if o[0] >= 224 && o[0] <= 239 {
        // 224.0.0.0/4 — multicast
        Some(SsrfReason::MulticastOrReserved)
    } else if o[0] >= 240 {
        // 240.0.0.0/4 — reserved
        Some(SsrfReason::MulticastOrReserved)
    } else {
        None
    }
}

/// Classify an IPv6 address against the forbidden ranges. Mirrors
/// [`classify_unsafe_v4`]; the rejected set matches the historical
/// `is_unsafe_v6` predicate exactly.
fn classify_unsafe_v6(ip: Ipv6Addr) -> Option<SsrfReason> {
    if ip.is_loopback() {
        return Some(SsrfReason::Loopback);
    }
    if ip.is_unspecified() || ip.is_multicast() {
        return Some(SsrfReason::MulticastOrReserved);
    }
    let segments = ip.segments();
    // Embedded-IPv4 forms — both IPv4-mapped (`::ffff:a.b.c.d`) and the
    // deprecated IPv4-compatible (`::a.b.c.d`, RFC 4291) carry an IPv4
    // address in the low 32 bits with the high 80 bits zero. Decode it
    // and re-run the v4 filter so e.g. `::127.0.0.1` / `::ffff:10.0.0.1`
    // are caught. The non-zero guard keeps `::` (unspecified, already
    // handled above) and `::1` (loopback) from being misclassified.
    if segments[0..5] == [0, 0, 0, 0, 0] && (segments[5] == 0 || segments[5] == 0xffff) {
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        if !v4.is_unspecified() {
            return classify_unsafe_v4(v4);
        }
    }
    // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052) and the local-use
    // 64:ff9b:1::/48 prefix (RFC 8215): a hostile AAAA answer such as
    // `64:ff9b::a9fe:a9fe` translates to IMDS `169.254.169.254` through a
    // NAT64/DNS64 gateway, which is routable in IPv6-only / cloud networks.
    if segments[0] == 0x0064 && segments[1] == 0xff9b {
        return Some(SsrfReason::Imds);
    }
    // fc00::/7 — unique local
    if (segments[0] & 0xfe00) == 0xfc00 {
        return Some(SsrfReason::Private);
    }
    // fe80::/10 — link-local
    if (segments[0] & 0xffc0) == 0xfe80 {
        return Some(SsrfReason::Imds);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// safe_client built with the default policy refuses a loopback target at
    /// DNS time — the SafeDnsResolver rejects 127.0.0.1 before any connect, so
    /// the request errors. This is the SSRF guard the webhook delivery client
    /// relies on (#6).
    #[cfg(feature = "client")]
    #[tokio::test]
    async fn safe_client_default_refuses_loopback() {
        let client =
            safe_client(&SsrfPolicy::default(), std::time::Duration::from_secs(2)).unwrap();
        let result = client.get("http://127.0.0.1:9/").send().await;
        assert!(
            result.is_err(),
            "default policy must refuse a loopback target"
        );
    }

    /// Issue #321: the refusal reaches the caller with the typed
    /// `SsrfDnsRefusal` marker still downcastable somewhere in the
    /// `reqwest::Error` source chain — so classification does not depend
    /// on the message-text fallback.
    #[cfg(feature = "client")]
    #[tokio::test]
    async fn dns_refusal_carries_typed_marker_through_reqwest() {
        let client =
            safe_client(&SsrfPolicy::default(), std::time::Duration::from_secs(2)).unwrap();
        let err = client
            .get("https://localhost:9/")
            .send()
            .await
            .expect_err("default policy must refuse localhost");
        let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        let mut found = false;
        while let Some(e) = cur {
            if let Some(r) = e.downcast_ref::<acdp_primitives::error::SsrfDnsRefusal>() {
                assert!(r.message().contains("SSRF policy"), "{}", r.message());
                found = true;
                break;
            }
            cur = e.source();
        }
        assert!(found, "typed SsrfDnsRefusal missing from chain: {err:?}");
        assert!(acdp_primitives::error::is_ssrf_refusal(&err));
    }

    /// allow_test_loopback permits loopback so tests can POST to a local
    /// listener.
    #[cfg(all(feature = "client", feature = "test-transport"))]
    #[test]
    fn safe_client_builds_with_loopback_policy() {
        assert!(safe_client(
            &SsrfPolicy::allow_test_loopback(),
            std::time::Duration::from_secs(2)
        )
        .is_ok());
    }

    #[test]
    fn https_only_by_default() {
        let p = SsrfPolicy::default();
        assert!(p.check_url("https://registry.example.com").is_ok());
        assert!(p.check_url("http://registry.example.com").is_err());
        assert!(p.check_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn rejects_ip_literals_by_default() {
        let p = SsrfPolicy::default();
        assert!(p.check_url("https://192.168.1.1").is_err());
        assert!(p.check_url("https://[::1]").is_err());
    }

    #[test]
    fn private_v4_ranges_rejected() {
        // RFC 1918
        assert!(check_safe_ip("10.0.0.1".parse().unwrap()).is_err());
        assert!(check_safe_ip("172.16.5.5".parse().unwrap()).is_err());
        assert!(check_safe_ip("192.168.1.1".parse().unwrap()).is_err());
        // Loopback
        assert!(check_safe_ip("127.0.0.1".parse().unwrap()).is_err());
        // Link-local + AWS IMDS
        assert!(check_safe_ip("169.254.169.254".parse().unwrap()).is_err());
        // Multicast
        assert!(check_safe_ip("239.0.0.1".parse().unwrap()).is_err());
        // Public
        assert!(check_safe_ip("8.8.8.8".parse().unwrap()).is_ok());
        assert!(check_safe_ip("203.0.113.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn unsafe_v6_rejected() {
        assert!(check_safe_ip("::1".parse().unwrap()).is_err());
        assert!(check_safe_ip("fc00::1".parse().unwrap()).is_err());
        assert!(check_safe_ip("fe80::1".parse().unwrap()).is_err());
        // IPv4-mapped private
        assert!(check_safe_ip("::ffff:10.0.0.1".parse().unwrap()).is_err());
        // IPv4-compatible (deprecated `::a.b.c.d`) decoding to loopback / IMDS
        assert!(check_safe_ip("::127.0.0.1".parse().unwrap()).is_err());
        assert!(check_safe_ip("::7f00:1".parse().unwrap()).is_err());
        assert!(check_safe_ip("::169.254.169.254".parse().unwrap()).is_err());
        // NAT64 well-known prefix translating to IMDS 169.254.169.254
        assert!(check_safe_ip("64:ff9b::a9fe:a9fe".parse().unwrap()).is_err());
        assert!(check_safe_ip("64:ff9b::169.254.169.254".parse().unwrap()).is_err());
        // Public v6
        assert!(check_safe_ip("2001:db8::1".parse().unwrap()).is_ok());
        // IPv4-compatible decoding to a *public* v4 stays allowed
        assert!(check_safe_ip("::93.184.216.34".parse().unwrap()).is_ok());
    }

    #[test]
    fn cross_authority_redirect_rejected() {
        let p = SsrfPolicy::default();
        let orig = url::Url::parse("https://registry.example.com/a").unwrap();
        let err = p
            .check_redirect_authority(&orig, "https://attacker.com/x")
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
        // Same authority OK
        p.check_redirect_authority(&orig, "https://registry.example.com/y")
            .unwrap();
    }

    // ── SEC-02 — same_fetch_authority (scheme + host + port) ────────────
    fn u(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn same_host_same_implicit_port_allowed() {
        assert!(same_fetch_authority(
            &u("https://a.example/x"),
            &u("https://a.example/y")
        ));
    }

    #[test]
    fn same_host_explicit_443_same_as_implicit_allowed() {
        // Explicit :443 must compare equal to the implicit https default.
        assert!(same_fetch_authority(
            &u("https://a.example/x"),
            &u("https://a.example:443/y")
        ));
    }

    #[test]
    fn same_host_different_port_rejected() {
        assert!(!same_fetch_authority(
            &u("https://a.example/x"),
            &u("https://a.example:8443/y")
        ));
    }

    #[test]
    fn https_to_http_same_host_rejected() {
        // Scheme downgrade is never same-authority.
        assert!(!same_fetch_authority(
            &u("https://a.example/x"),
            &u("http://a.example/y")
        ));
    }

    #[test]
    fn different_host_rejected() {
        assert!(!same_fetch_authority(
            &u("https://a.example/x"),
            &u("https://b.example/y")
        ));
    }

    #[test]
    fn check_redirect_authority_rejects_port_change() {
        let p = SsrfPolicy::default();
        let orig = u("https://registry.example.com/a");
        let err = p
            .check_redirect_authority(&orig, "https://registry.example.com:8443/b")
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    // ── SEC-01 — reject the ENTIRE resolution on any forbidden IP ───────
    #[cfg(feature = "client")]
    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[cfg(feature = "client")]
    #[test]
    fn mixed_public_private_dns_rejected_entirely() {
        let p = SsrfPolicy::default();
        let candidates = [sock("203.0.113.10:443"), sock("10.0.0.1:443")];
        assert!(reject_if_any_forbidden(&p, "evil.example", &candidates).is_err());
    }

    #[cfg(feature = "client")]
    #[test]
    fn mixed_public_loopback_rejected() {
        let p = SsrfPolicy::default();
        let candidates = [sock("198.51.100.1:443"), sock("127.0.0.1:443")];
        assert!(reject_if_any_forbidden(&p, "evil.example", &candidates).is_err());
    }

    #[cfg(feature = "client")]
    #[test]
    fn mixed_public_imds_rejected() {
        let p = SsrfPolicy::default();
        let candidates = [sock("198.51.100.1:443"), sock("169.254.169.254:443")];
        assert!(reject_if_any_forbidden(&p, "evil.example", &candidates).is_err());
    }

    #[cfg(feature = "client")]
    #[test]
    fn single_public_ip_allowed() {
        let p = SsrfPolicy::default();
        let candidates = [sock("203.0.113.10:443")];
        assert!(reject_if_any_forbidden(&p, "ok.example", &candidates).is_ok());
    }

    #[cfg(feature = "client")]
    #[test]
    fn all_public_ips_allowed() {
        let p = SsrfPolicy::default();
        let candidates = [sock("203.0.113.10:443"), sock("198.51.100.1:443")];
        assert!(reject_if_any_forbidden(&p, "ok.example", &candidates).is_ok());
    }

    #[test]
    fn allow_http_can_be_opted_into() {
        let p = SsrfPolicy {
            allow_http: true,
            ..SsrfPolicy::default()
        };
        assert!(p.check_url("http://registry.example.com").is_ok());
    }

    // ── SsrfReason taxonomy (D1) ────────────────────────────────────────
    fn reason_for_ip(s: &str) -> SsrfReason {
        SsrfPolicy::default()
            .classify_ip(s.parse().unwrap())
            .unwrap_err()
            .reason
    }

    #[test]
    fn classify_ip_maps_stable_reasons() {
        assert_eq!(reason_for_ip("127.0.0.1"), SsrfReason::Loopback);
        assert_eq!(reason_for_ip("10.0.0.1"), SsrfReason::Private);
        assert_eq!(reason_for_ip("172.16.5.5"), SsrfReason::Private);
        assert_eq!(reason_for_ip("192.168.1.1"), SsrfReason::Private);
        assert_eq!(reason_for_ip("100.64.0.1"), SsrfReason::Private);
        assert_eq!(reason_for_ip("169.254.169.254"), SsrfReason::Imds);
        assert_eq!(reason_for_ip("239.0.0.1"), SsrfReason::MulticastOrReserved);
        assert_eq!(reason_for_ip("0.0.0.1"), SsrfReason::MulticastOrReserved);
        assert_eq!(reason_for_ip("240.0.0.1"), SsrfReason::MulticastOrReserved);
        // IPv6
        assert_eq!(reason_for_ip("::1"), SsrfReason::Loopback);
        assert_eq!(reason_for_ip("fc00::1"), SsrfReason::Private);
        assert_eq!(reason_for_ip("fe80::1"), SsrfReason::Imds);
        // NAT64 well-known prefix → IMDS reach.
        assert_eq!(reason_for_ip("64:ff9b::a9fe:a9fe"), SsrfReason::Imds);
        // IPv4-mapped private decodes through to the v4 reason.
        assert_eq!(reason_for_ip("::ffff:10.0.0.1"), SsrfReason::Private);
        // Public addresses classify clean.
        assert!(SsrfPolicy::default()
            .classify_ip("8.8.8.8".parse().unwrap())
            .is_ok());
        assert!(SsrfPolicy::default()
            .classify_ip("2001:db8::1".parse().unwrap())
            .is_ok());
    }

    #[test]
    fn classify_reason_as_str_is_stable() {
        assert_eq!(SsrfReason::NonHttps.as_str(), "non_https");
        assert_eq!(SsrfReason::IpLiteral.as_str(), "ip_literal");
        assert_eq!(SsrfReason::InvalidUrl.as_str(), "invalid_url");
        assert_eq!(SsrfReason::Loopback.as_str(), "loopback");
        assert_eq!(SsrfReason::Private.as_str(), "private");
        assert_eq!(SsrfReason::Imds.as_str(), "imds");
        assert_eq!(
            SsrfReason::MulticastOrReserved.as_str(),
            "multicast_or_reserved"
        );
        assert_eq!(SsrfReason::CrossAuthority.as_str(), "cross_authority");
    }

    #[test]
    fn classify_url_maps_stable_reasons() {
        let p = SsrfPolicy::default();
        assert_eq!(
            p.classify_url("http://registry.example.com")
                .unwrap_err()
                .reason,
            SsrfReason::NonHttps
        );
        assert_eq!(
            p.classify_url("https://192.168.1.1").unwrap_err().reason,
            SsrfReason::IpLiteral
        );
        assert_eq!(
            p.classify_url("https://[::1]").unwrap_err().reason,
            SsrfReason::IpLiteral
        );
        assert_eq!(
            p.classify_url("not a url").unwrap_err().reason,
            SsrfReason::InvalidUrl
        );
        assert!(p.classify_url("https://registry.example.com").is_ok());
    }

    #[test]
    fn classify_redirect_reasons_and_port_parity() {
        let p = SsrfPolicy::default();
        // Cross-host → cross_authority.
        assert_eq!(
            p.classify_redirect("https://a.example/x", "https://b.example/y")
                .unwrap_err()
                .reason,
            SsrfReason::CrossAuthority
        );
        // Port change → cross_authority.
        assert_eq!(
            p.classify_redirect("https://a.example/x", "https://a.example:8443/y")
                .unwrap_err()
                .reason,
            SsrfReason::CrossAuthority
        );
        // Scheme downgrade → cross_authority.
        assert_eq!(
            p.classify_redirect("https://a.example/x", "http://a.example/y")
                .unwrap_err()
                .reason,
            SsrfReason::CrossAuthority
        );
        // D2: explicit :443 is equal to the implicit https default.
        assert!(p
            .classify_redirect("https://a.example/x", "https://a.example:443/y")
            .is_ok());
        // Same authority is allowed.
        assert!(p
            .classify_redirect("https://a.example/x", "https://a.example/y")
            .is_ok());
        // Unparseable origin → invalid_url.
        assert_eq!(
            p.classify_redirect("::not-a-url", "https://a.example/y")
                .unwrap_err()
                .reason,
            SsrfReason::InvalidUrl
        );
    }

    #[test]
    fn check_wrappers_preserve_schema_violation() {
        // The back-compat surface still produces SchemaViolation with the
        // same detail string, so existing callers are unaffected.
        let p = SsrfPolicy::default();
        let err = p.check_url("http://registry.example.com").unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
        let err = p.check_ip("10.0.0.1".parse().unwrap()).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    /// FEAT-07 — `pin_resolved_ip` resolves localhost (which always maps
    /// to a forbidden range) and rejects it. This proves the §7.6 path
    /// runs the same range filter as `check_safe_ip`, so an attacker
    /// cannot use a hostname that only resolves to private IPs to slip
    /// past the URL-time check by hostname.
    #[cfg(feature = "client")]
    #[tokio::test]
    async fn pin_resolved_ip_rejects_loopback_hostname() {
        let p = SsrfPolicy::default();
        let err = p.pin_resolved_ip("localhost", 443).await.unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }
}
