# Architecture

This page explains how the crate is organized internally and why. The
protocol-level rationale for the three-layer split lives in
[RFC-ACDP-0001 §5](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0001-core.md)
(identifiers, canonicalization, hashing, signatures) and
[RFC-ACDP-0002](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0002-context-body.md)
(the body structure). This page maps that structure onto Rust modules and
explains the one rule you must never break: **a field's layer determines
whether it is hashed, signed, or mutable.**

## The three layers

```
PublishRequest                               crates/acdp-types/src/publish.rs
  │
  ├── Body                  ← immutable, JCS-canonicalized   crates/acdp-types/src/body.rs
  │     │
  │     └── ProducerContent ← Body minus the §5.7 exclusion set
  │           │                (producer-controlled fields only)
  │           ├── content_hash  = sha256(JCS(ProducerContent))    crates/acdp-crypto/src/hash.rs
  │           └── signature     = Ed25519( ASCII "sha256:<hex>" ) crates/acdp-crypto/src/sign.rs
  │                                            ▲
  │                                            └─ ⚠️ the ASCII string, NOT the 32-byte digest
  │
  ├── content_hash          ← echoed in the request for transport
  └── signature             ← the producer's Ed25519 signature

FullContext = Body + RegistryState                     ← retrieval shape
                     │
                     └── status, receipt, … (mutable/registry-derived)  crates/acdp-types/src/body.rs
```

Three operations are protocol-critical and the crate implements them exactly:

| Operation | Spec | Implementation |
|---|---|---|
| JCS canonicalization | RFC 8785 | `crates/acdp-jcs/src/lib.rs` — **in-house**, handles `-0.0` |
| `content_hash` | RFC-ACDP-0001 §5.7 | `crates/acdp-crypto/src/hash.rs` — `sha256(JCS(ProducerContent))` |
| Ed25519 / P-256 sign/verify | RFC-ACDP-0001 §5.8/§5.11 | `crates/acdp-crypto/src/{sign,verify}.rs` |

### Three things that trip people up

1. **The signature preimage is the ASCII string `"sha256:<hex>"`** — the 71-byte
   text — not the raw 32-byte digest. This is the single most common
   implementation mistake. See `crates/acdp-crypto/src/sign.rs`.
2. **`Option::is_none` fields are skipped, not emitted as `null`.** Emitting
   `null` for an unset field changes the JCS bytes and therefore the
   `content_hash`. This is load-bearing for the `sig-001` golden vector.
3. **`Body` and `RegistryState` are split deliberately.** `status` is *not* a
   body field — it's registry-derived and lives in `RegistryState`. Merging
   them would let mutable state into the signed preimage.

## Workspace crate map

The umbrella `acdp` crate (`src/lib.rs`) is a thin facade that re-exports a
fine-grained set of crates under `crates/`, preserving the historical
`acdp::{types, crypto, did, validation, verify, producer, client, registry, …}`
paths. The crates form a strict bottom→top dependency DAG:

| Crate | Role |
|---|---|
| `acdp-primitives` | Leaf types (`AgentDid`, `CtxId`, …), `AcdpError`, `ACDP_VERSION`, limits/time/serde helpers. |
| `acdp-jcs` | RFC 8785 JCS — **in-house**, handles `-0.0`. |
| `acdp-safe-http` | `SsrfPolicy`, the HTTPS guard, and `SafeDnsResolver` (the DNS-time IP filter). |
| `acdp-did` | `WebResolver` for `did:web` (LRU-cached, SSRF-gated) and offline `did:key` resolution (Ed25519 + P-256). |
| `acdp-crypto` | `hash` (`content_hash` + `lineage_id`), `sign`/`verify` (Ed25519 + ECDSA-P256), fingerprint, Merkle. |
| `acdp-types` | Wire types: `body`, `publish`, `search`, `data_ref`, `capabilities`, `anchor`, `receipt`, `lifecycle`, `log`, `cosignature`, `revocation`, `primitives`. `Body`/`RegistryState` are kept apart; `Status`/`ContextType`/`Visibility` are **open enums**. |
| `acdp-validation` | One-stop schema validator: `validate_publish_request`, `validate_body`, `validate_data_ref`, `validate_metadata`, `compute_embedded_hash`. |
| `acdp-verify` | High-level verification: resolver-backed `Verifier` (RFC-ACDP-0001 §5.11) plus offline `did:key` body/request/lifecycle verification. |
| `acdp-producer` | `Producer` + `RequestBuilder`. Enforces v1-vs-v2+ rules, ms-truncates timestamps, validates, computes `content_hash`, then signs. |
| `acdp-client` *(feature `client`)* | `RegistryClient`, `VerifiedContext`, `VerificationPolicy`/`Report`, `CrossRegistryResolver`. Implements the **`acdp-consumer`** profile. |
| `acdp-server` *(feature `server`)* | `RegistryServer`, `PublishValidator`, `InMemoryStore`. Building blocks for separate `acdp-registry-*` crates. |
| `acdp-cli` | The `acdp` binary (`cargo run -p acdp-cli`). Uses `std::env::args` directly — **no `clap`** by design. |

`did→crypto` and `validation→producer` are **test-only** (dev-dependency)
cycles; `acdp-verify` also takes `acdp-producer` as a dev-dependency to build
signed fixtures.

## Feature gating

Features on the umbrella crate add layers outward from a pure core:

```
              ┌─────────────────────────────────────────────┐
 (own crate)  │ acdp-cli  (the `acdp` binary)               │
              ├─────────────────────────────────────────────┤
 client ───►  │ client::{RegistryClient, VerifiedContext,   │
              │   CrossRegistryResolver}  ·  did::WebResolver│
              ├─────────────────────────────────────────────┤
 server ───►  │ registry::{RegistryServer, PublishValidator,│
              │   InMemoryStore}                             │
              ├─────────────────────────────────────────────┤
  core   ───► │ types · crypto · validation · verify ·      │  ← always present,
 (no feat)    │ producer · error · profile · safe_http · did │    no HTTP stack
              └─────────────────────────────────────────────┘
```

- **`client` and `server` are independent, with one coupling.** A consumer
  pulls `client`; a registry pulls `server`, and neither requires the other.
  But when both are enabled, `client` also turns on `acdp-server/client`
  (`acdp-server?/client` in the root `Cargo.toml`), which is what gates the
  resolver-backed (`did:web`) async `RegistryServer::publish_verified` path.
  A `server`-only build keeps the offline `did:key` publish path.
- **The core has no async runtime and no HTTP.** `reqwest`/`tokio`/`rustls`
  only arrive with `client`. Offline `did:key` verification and the receipt
  types work with `--no-default-features`. This is what lets the
  [bindings](bindings.md) ship a thin wheel/`.node`/`.wasm` — crypto in Rust,
  HTTP in the host language.

## Where the work happens

Most behavior changes land in **`crates/acdp-validation/src/lib.rs`** (~70 KB).
It is the single source of structural truth: the builder calls it before
signing, the `server` feature calls it during publish, and `VerifiedContext`
calls it during retrieval. If you're changing what counts as a valid context,
that's the file.

The crypto layer is intentionally small and rarely changes — and when it does,
it must keep passing the `sig-001` / `can-001` golden vectors (see
[Conformance & testing](conformance.md)).

## Design rules (repo conventions)

These are enforced and will fail CI or review if broken:

- **No `unsafe`** — `unsafe_code = "forbid"` at the crate root.
- **JCS is in-house** — do not swap `crates/acdp-jcs/src/lib.rs` for an external
  crate; the `-0.0` handling is pinned by `proptest_jcs.rs`,
  `crates/acdp-jcs/tests/differential_numbers.rs`, and `can-001`.
- **No `clap`** in the CLI — manual arg parsing keeps the dep graph identical to
  the library.
- **`Option::is_none` skip-serialization** is load-bearing — never emit `null`
  for unset fields.
- **Producer timestamps are ms-truncated** (`time::trunc_ms`) per
  RFC-ACDP-0001 §5.3.
- **Conventional Commits** — `release-plz` derives versions from
  `feat:`/`fix:`/`docs:`/… prefixes.
