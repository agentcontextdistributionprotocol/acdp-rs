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
from the producer's own DID (a `did:web` document, or a self-describing
`did:key`). Everything the
[verification pipeline](consuming.md#verifiedcontext--the-verification-pipeline)
does follows from that: recompute the hash yourself, resolve the key yourself,
verify the signature yourself.

The second trust concern is **outbound requests**. The library makes outbound
HTTPS calls in four places, and each is SSRF-guarded identically:

1. **Registry calls** — `RegistryClient` publishing, retrieving, searching,
   and fetching capabilities from the registry you point it at.
2. **Producer DID resolution** — `WebResolver` fetching `did.json`
   (`did:key` resolves offline and makes no request).
3. **Cross-registry resolution** — `CrossRegistryResolver` fetching foreign
   contexts and capabilities.
4. **Data-ref fetching** — `HttpsDataRefFetcher` fetching referenced data.

## Defenses applied by default

Every public client API (`RegistryClient`, `WebResolver`,
`CrossRegistryResolver`, `HttpsDataRefFetcher`) applies these out of the box —
you do not opt in:

| Defense | What it does | Spec |
|---|---|---|
| **HTTPS-only** | `http://` URLs are rejected. | RFC-ACDP-0008 |
| **IP-literal rejection** | `https://1.2.3.4/…` is rejected — forces a DNS lookup so the resolved IP can be filtered. | RFC-ACDP-0006 §7 |
| **Private/loopback/link-local/multicast/IMDS blocking** | Resolved IPs in RFC 1918, loopback, link-local, CGNAT, multicast, ULA (`fc00::/7`), `fe80::/10`, and the metadata endpoint (`169.254.169.254`) are refused — IPv4 **and** IPv6, including IPv4-mapped. | RFC-ACDP-0008 §4.8/§4.9 |
| **DNS-rebinding pin** | IPs are filtered **at DNS-resolution time, before any TCP connect** — a hostname whose answers fall in a forbidden range is refused. See below. | RFC-ACDP-0006 §7.6 |
| **Body-size caps** | 1 MB for context retrievals; 64 KB for capabilities and DID documents. | RFC-ACDP-0006 §7 |
| **Redirect cap** | Max 3 redirects, **same-authority only**. | RFC-ACDP-0006 §7 |
| **Timeouts** | 5 s connect, 30 s total. | RFC-ACDP-0006 §7.4 |
| **Algorithm-downgrade rejection** | The signature algorithm must match the algorithm of the resolved DID verification method. | RFC-ACDP-0001 §5.10 |
| **Ed25519 mandatory** | Ed25519 is always supported; downgrade attacks are rejected. | RFC-ACDP-0001 §5.10 |
| **Strict Ed25519 verification** | Every Ed25519 check (producer signatures at publish and retrieval, did:key, historical-key, lifecycle events, registry and head receipts, log checkpoints, witness cosignatures) uses ed25519-dalek `verify_strict`: a non-canonical `s` and a small-order public key `A` or nonce point `R` are rejected with `invalid_signature`. Without this, identity `A`, identity `R`, `s = 0` verifies for every message (conformance vector `sig-004`). Honest keys are never small-order, so no honest signature is affected. This lives in the core, so the offline APIs and the Python, Node, and WASM bindings get it too. | RFC-ACDP-0001 §5.10 |
| **Context-identity binding** | The served body's `ctx_id` must equal the one requested; mismatch is treated as a failed resolution (fail-closed). This is the only binding available on the receipt-less path, since `ctx_id` is registry-assigned and outside `content_hash`/signature coverage. `RegistryClient`/`VerifiedContext` enforce it automatically; the Python, Node, and WASM bindings expose the same check explicitly as `verify_ctx_id_binding` / `verifyCtxIdBinding` for callers building their own pipeline (see [`docs/bindings.md`](bindings.md)). | RFC-ACDP-0006 §4.1 step 7 (NORMATIVE) |

> The size, redirect, and timeout constants are exposed as
> `acdp::registry::{MAX_CONTEXT_BYTES, MAX_METADATA_BYTES, MAX_REDIRECTS}` and
> `acdp::limits` (the `limits` module of the `acdp-primitives` crate).

## ECDSA-P256 signatures: low-S on emit, high-S accepted

ECDSA signatures are not unique: anyone can turn a valid `(r, s)` into a
second valid signature without the private key. The normative rules are in the
spec's [`ecdsa-p256` signature non-uniqueness](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/registries/signature-algorithms.md#ecdsa-p256-signature-non-uniqueness-normative)
section; this is how the crate applies them:

- **Emit:** every P-256 signature this crate produces
  (`P256SigningKey::sign_content_hash` / `sign_string`, and so every
  `ecdsa-p256` publish request, lifecycle event, and auth challenge) is
  normalized to low-S (`s <= n/2`). RFC 6979 keeps it deterministic, so the
  same key and input always give the same bytes. The `sig-002` golden vector
  is already low-S and is unchanged.
- **Verify:** `verify_ecdsa_p256` still **accepts** high-S signatures. Other
  producers may not normalize, and the spec does not require consumers to
  reject them.
- **Signature bytes are not identities.** Never key deduplication, caching,
  or idempotency on `signature.value`. Publish idempotency is keyed on
  `content_hash`. The lifecycle retry check (RFC-ACDP-0013 §6) compares whole
  events, signature included, by spec decision: only a **byte-identical**
  retry is an `IdempotentReplay`. A flipped-S twin of an applied event is
  rejected as `schema_violation` with nothing appended (see
  `p256_flipped_s_lifecycle_retry_is_not_idempotent` in `tests/lifecycle.rs`).
  Retry with the exact bytes you sent the first time.

## DNS-rebinding protection is active

DNS-rebinding protection ([RFC-ACDP-0006 §7.6](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0006-cross-registry.md#76-dns-rebinding-protection)) is **on**. `crate::safe_http::SafeDnsResolver`
is wired into reqwest's `dns_resolver` hook by every HTTP client the crate
builds (`WebResolver`, `RegistryClient`, `HttpsDataRefFetcher`,
`CrossRegistryResolver`). Each resolved IP is filtered through the active
`SsrfPolicy` *at DNS time, before the socket is opened*, so a host that
DNS-rebinds to a forbidden range can never be connected to.

A host whose answers fall in a forbidden range is refused before any connect.
The resolver returns a typed `acdp::error::SsrfDnsRefusal` marker, and every
path recognizes it through one shared check (`acdp::error::is_ssrf_refusal`).
Which variant you get depends on the path:

| Path | Error | `is_transient()` |
|---|---|---|
| `WebResolver` (resolving a `did:web` document) | `AcdpError::KeyResolution` (wire `key_resolution_failed`, HTTP 400) | `false` |
| `RegistryClient`, `HttpsDataRefFetcher`, and any other path through `From<reqwest::Error>` | `AcdpError::SchemaViolation("SSRF policy: …")`, the same shape as the URL-time `SsrfPolicy::check_url` refusal; test it with `AcdpError::is_ssrf_policy_refusal()` | `false` |
| `CrossRegistryResolver` (any hop: pin-once DNS, capabilities, retrieval) | `AcdpError::CrossRegistryResolutionFailed` (wire `cross_registry_resolution_failed`, HTTP 502), as RFC-ACDP-0007 §5 and fixture `fed-007` require | `true` |

So `RegistryClient::publish_with_retry` returns an SSRF refusal on the first
attempt. In every case the message carries the whole `source()` chain, so the
SSRF detail is visible. See [errors.md](errors.md#retryability) for the retry
predicate.

Redirect-policy refusals (a cross-authority redirect, or more than 3
redirects) are not SSRF refusals in this sense. On `RegistryClient` and
`HttpsDataRefFetcher` they still surface as the transient `AcdpError::Http`;
`CrossRegistryResolver` reports them as `CrossRegistryResolutionFailed` when
they occur during the capabilities fetch; during retrieval the `Http` error
passes through unchanged.

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

## Read authentication

The client side of read authentication is **not implemented**. `RegistryClient`
reads anonymously: it sends no `Authorization` header on any request, so it
sees only what a registry serves to anonymous callers. In particular the
registered `bearer_jwt` method
([RFC-ACDP-0008 §6.2](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0008-security.md#62-read-authentication),
[`registries/auth-methods.md`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/registries/auth-methods.md))
is **not implemented client-side**. What the crate does provide:

- `CapabilitiesDocument::read_authentication_methods` — the methods a
  registry advertises, as opaque strings (no typed handling).
- `SigningKey::sign_string` / `P256SigningKey::sign_string` — the producer's
  half of a challenge-response flow (signing an arbitrary ASCII input with
  the producer key). Obtaining the challenge, exchanging the signature for a
  token, and presenting it are up to the host.

For the flow `acdp-registry-rs` runs, including the exact signing input, see
its [challenge-response flow](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/AUTHENTICATION.md#challenge-response-flow)
and [`bearer_jwt` conformance](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/AUTHENTICATION.md#spec-conformance-bearer_jwt)
notes.

## What the crate does *not* do

Per RFC-ACDP-0008, some responsibilities sit with the registry or the operator,
not this client library:

- **Rate limiting** (RFC-ACDP-0008 §4.3) — a registry concern. The `server`
  feature exposes a `RateLimiter` trait; see [Implementing a registry](registry.md).
- **Authenticated reads** — every client request is anonymous, including
  cross-registry resolution (see [Read authentication](#read-authentication)).
- **Visibility enforcement** — the registry enforces visibility on retrieval
  and search; a consumer only sees what the registry chooses to serve.

For the full threat enumeration (replay, Sybil/spam, existence-leak,
supersession races), read RFC-ACDP-0008 directly — these docs do not duplicate
it.
