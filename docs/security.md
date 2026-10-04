# Security Model

This page documents the security defenses the crate applies **automatically**
and how to (carefully) relax them for tests. The threat model and the normative
requirements are specified in
[RFC-ACDP-0008 (Security & Threat Model)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0008-security.md)
and the cross-registry SSRF rules in
[RFC-ACDP-0006 §7](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0006-cross-registry.md).
This crate does not invent policy — it enforces what those RFCs require, by
default, on every public client API.

## The trust boundary

ACDP is a zero-trust substrate. **A registry is not a trusted party.** The only
thing you trust is the producer's signature, verified against a key resolved
from the producer's own `did:web` document. Everything the
[verification pipeline](consuming.md#verifiedcontext--the-verification-pipeline)
does follows from that: recompute the hash yourself, resolve the key yourself,
verify the signature yourself.

The second trust concern is **outbound requests**. The library makes outbound
HTTPS calls in three places, and each is SSRF-guarded identically:

1. **Producer DID resolution** — `WebResolver` fetching `did.json`.
2. **Cross-registry resolution** — `CrossRegistryResolver` fetching foreign
   contexts and capabilities.
3. **Data-ref fetching** — `HttpsDataRefFetcher` fetching referenced data.

## Defenses applied by default

Every public client API (`RegistryClient`, `WebResolver`,
`CrossRegistryResolver`, `HttpsDataRefFetcher`) applies these out of the box —
you do not opt in:

| Defense | What it does | Spec |
|---|---|---|
| **HTTPS-only** | `http://` URLs are rejected. | RFC-ACDP-0008 |
| **IP-literal rejection** | `https://1.2.3.4/…` is rejected — forces a DNS lookup so the resolved IP can be filtered. | RFC-ACDP-0006 §7 |
| **Private/loopback/link-local/multicast/IMDS blocking** | Resolved IPs in RFC 1918, loopback, link-local, CGNAT, multicast, ULA (`fc00::/7`), `fe80::/10`, and the metadata endpoint (`169.254.169.254`) are refused — IPv4 **and** IPv6, including IPv4-mapped. | RFC-ACDP-0008 §4.8/§4.9 |
| **DNS-rebinding pin** | IPs are filtered **at DNS-resolution time, before any TCP connect** — a hostname whose answers fall in a forbidden range is refused. See below. | RFC-ACDP-0008 §7.6 |
| **Body-size caps** | 1 MB for context retrievals; 64 KB for capabilities and DID documents. | RFC-ACDP-0006 §7 |
| **Redirect cap** | Max 3 redirects, **same-authority only**. | RFC-ACDP-0006 §7 |
| **Timeouts** | 5 s connect, 30 s total. | RFC-ACDP-0006 §7.4 |
| **Algorithm-downgrade rejection** | The signature algorithm must match the algorithm of the resolved DID verification method. | RFC-ACDP-0001 §5.10 |
| **Ed25519 mandatory** | Ed25519 is always supported; downgrade attacks are rejected. | RFC-ACDP-0001 §5.10 |
| **Context-identity binding** | The served body's `ctx_id` must equal the one requested; mismatch is treated as a failed resolution (fail-closed). This is the only binding available on the receipt-less path, since `ctx_id` is registry-assigned and outside `content_hash`/signature coverage. `RegistryClient`/`VerifiedContext` enforce it automatically; the Python, Node, and WASM bindings expose the same check explicitly as `verify_ctx_id_binding` / `verifyCtxIdBinding` for callers building their own pipeline (see [`docs/bindings.md`](bindings.md)). | RFC-ACDP-0006 §4.1 step 7 (NORMATIVE) |

> The size, redirect, and timeout constants are exposed as
> `acdp::registry::{MAX_CONTEXT_BYTES, MAX_METADATA_BYTES, MAX_REDIRECTS}` and
> in `src/limits.rs`.

## DNS-rebinding protection is active

DNS-rebinding (RFC-ACDP-0008 §7.6) is **on**. `crate::safe_http::SafeDnsResolver`
is wired into reqwest's `dns_resolver` hook by every HTTP client the crate
builds (`WebResolver`, `RegistryClient`, `HttpsDataRefFetcher`,
`CrossRegistryResolver`). Each resolved IP is filtered through the active
`SsrfPolicy` *at DNS time, before the socket is opened*, so a host that
DNS-rebinds to a forbidden range can never be connected to.

A host whose answers fall in a forbidden range is refused before any connect.
How that refusal surfaces depends on the client:

| Path | Error | `is_transient()` |
|---|---|---|
| `WebResolver` (resolving a `did:web` document) | `AcdpError::KeyResolution` (wire `key_resolution_failed`, HTTP 400) | `false` |
| `RegistryClient` (and any other path through `From<reqwest::Error>`) | `AcdpError::Http("connection failed: … SSRF policy … forbidden …")` | `true` |
| `HttpsDataRefFetcher` | `AcdpError::Http(…)` carrying only reqwest's outer message | `true` |

On the `RegistryClient` path the refusal is visible only because
`From<reqwest::Error>` appends the error's `source()` chain to the message. Because `Http` is
transient, `RegistryClient::publish_with_retry` retries such a refusal until
`max_attempts` runs out. If you need to stop early, check the message for
`SSRF policy`.

## SsrfPolicy

`SsrfPolicy` is the knob behind all of this. Its default is the secure posture;
you rarely construct it directly.

| Field | Default | Meaning |
|---|---|---|
| `reject_ip_literals` | `true` | refuse URLs with a literal IP host |
| `allow_http` | `false` | HTTPS-only |
| `allow_loopback_resolved` | `false` | refuse hosts that resolve to loopback |

`policy.check_url(url)` validates a URL up front; `classify_url` returns a
structured `SsrfRejection { reason, detail }` for diagnostics.

## Testing against localhost

Because loopback is blocked by default, tests that POST to a local listener
need to opt in explicitly. The intended seams:

- **`SsrfPolicy::allow_test_loopback()`** — the default policy with
  `allow_loopback_resolved = true`. Pass it to a fetcher/resolver that accepts
  a custom policy (e.g. `HttpsDataRefFetcher::with_ssrf_policy(...)`,
  `CrossRegistryResolver::with_ssrf_policy(...)`).
- **`RegistryClient::with_test_transport(base_url)`** — a client that permits
  HTTP and loopback for in-process test servers.
- **`RegistryClient::with_test_endpoint(...)`** / **`new_pinned(...)`** — pin a
  DNS answer / custom CA so a TLS test server on `127.0.0.1` is reachable while
  the production path stays locked down.

> These are **test-only**. Never construct a loopback-permitting policy in
> production code — it reopens the SSRF surface the defaults close. The TLS
> conformance suite (`tests/tls_conformance.rs`) uses exactly these seams to
> drive the `fed-001..006` and `pub-001/003/006` fixtures against an in-process
> server (the `did-ssrf-*` fixtures run in `tests/conformance.rs`).

## What the crate does *not* do

Per RFC-ACDP-0008, some responsibilities sit with the registry or the operator,
not this client library:

- **Rate limiting** (RFC-ACDP-0008 §4.3) — a registry concern. The `server`
  feature exposes a `RateLimiter` trait; see [Implementing a registry](registry.md).
- **Authentication / authorization of cross-registry calls** — out of scope for
  v0.1.0 (RFC-ACDP-0006). Cross-registry resolution is unauthenticated.
- **Visibility enforcement at rest** — the registry enforces visibility on
  retrieval; the consumer applies visibility rules client-side but cannot see
  what a registry refuses to serve.

For the full threat enumeration (replay, Sybil/spam, existence-leak,
supersession races), read RFC-ACDP-0008 directly — these docs do not duplicate
it.
