# Research memo: WebAssembly target for the pure-crypto core

> **Historical — shipped as [`bindings/acdp-wasm`](../../bindings/acdp-wasm/README.md)**
> (npm `@agentcontextdistributionprotocol/acdp-wasm`). This memo is the
> pre-implementation evaluation, kept for its rationale; it is not updated to
> match the shipped package. Where they differ, the package README wins — notably
> on `getrandom` (needed at compile time on `wasm32-unknown-unknown`) and on
> WASI (not built or tested; only `wasm32-unknown-unknown` ships).

**Status:** historical (shipped)
**Scope:** make the no-HTTP core (types, crypto, JCS, `did:key`, offline verification) run in browsers, edge runtimes, and WASI.
**Effort:** **M** (medium) for the browser/WASI verifier surface; **S** if scoped to a build-check-only "it compiles to `wasm32`" milestone.

---

## 1. Goal and why it matters

Today the umbrella `acdp` crate can build with `--no-default-features` down to a
pure types + crypto core (no `reqwest`, `tokio`, or `rustls`). A WebAssembly
target would let that core run **client-side** — in a browser tab, a Cloudflare
Worker / Deno / edge function, or a WASI host — so a consumer can verify a
producer signature, a `content_hash`, a lineage chain, a registry receipt
(RFC-ACDP-0010), or a transparency-log inclusion/consistency proof
(RFC-ACDP-0012) **without trusting any server to have done it**. That is the same
zero-server-trust posture the whole 0.2.0/0.3.0/0.4.0 trust-hardening arc pushes
toward (receipts, key-revocation, witness cosigning): the last mile is putting
the verifier where the untrusted data is rendered. It also directly complements
the existing JSON-over-FFI bindings (`bindings/acdp-py`, `bindings/acdp-node`) —
a `wasm-bindgen` surface is the browser member of that same family.

---

## 2. Which crates are WASM-eligible today

The workspace is layered bottom→top (see `CLAUDE.md`). The dependency facts
below are from the actual `Cargo.toml`s and `Cargo.lock` in this repo.

| Crate | WASM-eligible? | Why |
|---|---|---|
| `acdp-primitives` | **Yes** (types only) | `serde`, `serde_json`, `chrono`, `uuid` (v4), `thiserror`. `reqwest` is behind an **optional** `reqwest` feature (off in the core). `uuid` v4 needs randomness — see §4. |
| `acdp-jcs` | **Yes** | `serde` + `serde_json` only. In-house RFC 8785 canonicalizer, no platform deps. |
| `acdp-crypto` | **Yes, with one caveat** | `sha2`, `ed25519-dalek` 2, `p256` (`default-features = false`), `base64`, `bs58`, `zeroize`, `rand_core` 0.6 (`OsRng`). All pure-Rust — **no `ring`**. The caveat is `getrandom` via `rand_core`/`OsRng` (§4). |
| `acdp-types` | **Yes** | `acdp-{primitives,jcs,crypto,did}` + `serde`/`chrono`/`base64`/`hex`/`sha2`. |
| `acdp-did` — `did:key` path (`key.rs`) | **Yes** | Pure offline resolution: multibase/multicodec decode (`bs58`), `p256` for the compressed-point path. No network. |
| `acdp-did` — `did:web` path (`web.rs`, `WebResolver`) | **No** | Gated behind the `client` feature which pulls `reqwest` + `lru`; also wires `acdp-safe-http`'s DNS resolver. Network + `tokio`. |
| `acdp-validation` | **Yes** | Schema/structural validation over the pure types; `serde`/`chrono`/`base64`/`hex`/`sha2`. |
| `acdp-verify` — offline path | **Yes** | `verify_body_offline` / `did:key` envelope verification and `verify_content_hash` dispatch on `acdp-crypto` primitives only. No resolver, no I/O. |
| `acdp-verify` — resolver-backed `Verifier` | **No** (for the network half) | The `Verifier` that fetches a `did:web` document needs the `WebResolver` → `reqwest`. |
| `acdp-producer` | **Yes** (offline build), signing works | `RequestBuilder` computes `content_hash` and signs; ed25519 signing is deterministic and p256 uses RFC 6979 — **no RNG needed to sign**. Only *key generation* needs the RNG (§4). |
| `acdp-safe-http` | **No** | `SsrfPolicy` + `SafeDnsResolver` are inherently about `tokio::net` DNS + `reqwest`. Nothing to run in a browser (the host does the fetch). |
| `acdp-client` | **No** | `reqwest` + `tokio` + `rustls` — the whole point is HTTP. Host language / JS `fetch` owns transport in a WASM deployment. |
| `acdp-server` | **No** (out of scope) | Registry-side. |

**Bottom line:** the entire consumer *verification* surface and the producer
*signing* surface are pure-Rust and WASM-clean. The only two things that do not
cross the boundary are (a) network I/O (`did:web` resolution, `RegistryClient`)
— which in a WASM deployment is delegated to the host's `fetch`, exactly as the
Python/Node bindings delegate HTTP today — and (b) OS randomness for fresh key
generation, which needs a target-specific backend (§4).

### Surprising codebase fact: the core is already `ring`-free

`ring` **is** in `Cargo.lock`, but `cargo tree -i ring` shows it enters
**only** via (1) `rcgen` (a dev-dependency for the TLS test harness), (2)
`axum-server` / `rustls` (dev-dependencies), and (3) `reqwest`'s `rustls-tls`
(the `client` feature's TLS). A `--no-default-features` build of the workspace
core pulls **no `ring`, no `reqwest`, no `tokio`, no `hyper`** (verified with
`cargo tree --no-default-features -e no-dev`). `ring` is historically the single
biggest WASM blocker in the Rust crypto ecosystem (it ships C/asm and its
wasm32 support is partial). ACDP dodges it entirely because `acdp-crypto` uses
the **RustCrypto** stack (`ed25519-dalek`, `p256`, `sha2`) and RustCrypto is
pure-Rust and `no_std`-friendly. This is the fact that makes a WASM target
cheap rather than a rewrite.

---

## 3. `wasm32-unknown-unknown` vs `wasm32-wasi`

Both are worth supporting; they unlock different deployments and differ mainly
in how randomness is sourced.

| Target | Deployment | Randomness story |
|---|---|---|
| `wasm32-unknown-unknown` | Browser (via `wasm-bindgen`), some edge runtimes | `getrandom` has **no default backend**; you must opt into the JS backend (browser `crypto.getRandomValues`) or register a custom source. See §4. |
| `wasm32-wasip1` (formerly `wasm32-wasi`) | WASI hosts (Wasmtime, Wasmer, Fastly, Spin) | `getrandom` 0.2 has a **native WASI backend** — randomness works out of the box, no JS shim. This is the lower-friction target. |

A verifier-only build (no key generation) needs **no randomness at all** on
either target — see §4. That makes a *consumer-only* WASM artifact the easiest
possible first deliverable.

---

## 4. The `getrandom` question (the one real sharp edge)

`Cargo.lock` currently resolves three `getrandom` majors: `0.2.17`, `0.3.4`,
`0.4.2`. The one on the **crypto path** is `getrandom 0.2.17`, pulled by
`rand_core 0.6.4`, which is a direct dependency of `acdp-crypto` (for
`rand_core::OsRng`) and is also pulled transitively by
`p256` → `ecdsa`/`elliptic-curve` → `crypto-bigint`.

Two facts that shape the whole plan:

1. **Verification and signing do not draw randomness.**
   - Ed25519 signatures are deterministic (RFC 8032); `SigningKey::sign_content_hash` calls `ed25519_dalek::Signer::sign` with no RNG.
   - ECDSA-P256 signing here is **RFC 6979 deterministic** (`acdp-crypto/src/sign.rs`, `P256SigningKey::sign_content_hash`) — no RNG.
   - All verification (`verify_ed25519`, `verify_ecdsa_p256`, `verify_content_hash`) is RNG-free.
   The **only** callers of `OsRng` in the crate are `SigningKey::generate()` and
   `P256SigningKey::generate()` — fresh keypair creation.

2. **`getrandom 0.2` fails to *compile* on `wasm32-unknown-unknown` unless a
   backend is chosen.** It is not a runtime panic; it is a build-time error
   ("the wasm32-unknown-unknown target is not supported by default"). Options:
   - Enable the `js` feature on `getrandom` (`getrandom = { version = "0.2", features = ["js"] }`) → browser `crypto.getRandomValues` via `wasm-bindgen`. Only valid in a JS host.
   - Register a custom source (`getrandom::register_custom_getrandom!`) for non-JS edge runtimes.
   - On `wasm32-wasi`, do nothing — the WASI backend is built in.

**Design consequence.** Split the WASM surface by whether it needs
`generate()`:

- **Verifier / consumer build** — no `generate()`, no `uuid` v4, therefore **no
  `getrandom` backend needed** on any wasm target. Ships the smallest, most
  portable artifact and covers the highest-value use case (client-side
  receipt/lineage/signature verification).
- **Producer build** — needs `generate()` (and `uuid` v4 for any client-side
  `ctx_id`-adjacent tooling). Gate the JS `getrandom` backend behind a Cargo
  feature so it is only pulled for `wasm32-unknown-unknown` + browser. On WASI
  it works without the feature. Note the RFC-ACDP-0001 §5.10 key-generation
  mandate: on the browser, `crypto.getRandomValues` **is** the compliant CSPRNG
  the spec names ("`crypto.getRandomValues` … in JS"), so the JS backend is
  spec-blessed — but it must be wired deliberately, never left to a non-crypto
  fallback.

> `uuid`'s v4 generator also reaches for `getrandom`; a verifier build that never
> mints UUIDs sidesteps this. If a producer build needs it in-browser, the same
> `js` backend covers `uuid`.

---

## 5. Proposed plan

### 5.1 Shape: a dedicated `acdp-wasm` crate mirroring the FFI philosophy

Follow the established binding design rules (`CLAUDE.md` → "Design rules for
bindings"): **JSON across the boundary, crypto in Rust, HTTP in the host.** A
new **standalone** package `bindings/acdp-wasm` (its own `[workspace]`, like
`acdp-py` / `acdp-node`) that:

- Depends on `acdp` with `default-features = false` (pure core only — no
  `reqwest`/`tokio`/`rustls`, identical to how the Python/Node bindings pull it).
- Exposes a `wasm-bindgen` surface whose methods take and return **JSON
  strings** — e.g. `verify_offline(body_json) -> report_json`,
  `verify_receipt(receipt_json, body_json, registry_public_key_b64,
  expected_ctx_id, recomputed_body_hash, producer_key_fingerprint) ->
  report_json`,
  `content_hash(producer_content_json) -> "sha256:…"`,
  `sign_content_hash(seed_bytes, hash_string) -> sig_b64`. This mirrors the
  `AcdpProducer` seed-storage pattern (`SigningKey::seed_bytes()` /
  `sign_string()` in `acdp-crypto/src/sign.rs`) exactly.
- Does **no** network calls. `did:web` resolution stays in the JS host (`fetch`
  the DID document, pass the JSON in). `did:key` verification is fully offline
  and needs no host help — the highest-value browser path.
- For non-`wasm-bindgen` edge/WASI hosts, additionally offer a plain
  `cdylib`/component export of the same JSON entrypoints (WASI Preview 2
  component, or plain exported functions) so the crate is not JS-only.

### 5.2 `getrandom` configuration

- Verifier-only feature (default for the wasm crate): no `getrandom` backend,
  no `uuid`. Builds on all three wasm targets unmodified.
- `producer` feature: adds `getrandom = { version = "0.2", features = ["js"] }`
  (only meaningful on `wasm32-unknown-unknown`) and enables `generate()`. On
  `wasm32-wasi` the feature is a no-op (native backend).

### 5.3 CI job (the S-sized milestone worth doing regardless)

Add a `wasm` job to `.github/workflows/ci.yml` that guards against regression —
i.e. someone adding a `tokio`/`reqwest`/`ring`-flavoured dependency to a core
crate. Minimum viable:

```bash
rustup target add wasm32-unknown-unknown wasm32-wasip1
# Core must build for wasm with no HTTP features:
cargo build -p acdp --no-default-features --target wasm32-wasip1
cargo build -p acdp --no-default-features --target wasm32-unknown-unknown \
  || echo "expected: needs a getrandom backend — see §4"
```

For `wasm32-unknown-unknown`, build the **verifier-only** wasm crate (no
`getrandom` needed) so the job is green without a JS shim; add a `wasm-pack
test --headless` step once `bindings/acdp-wasm` exists to actually exercise a
signature verification in a real browser engine.

### 5.4 What it unlocks

- **Client-side, zero-server-trust verification** in a browser or edge worker:
  a rendered ACDP context, its producer signature, its `content_hash`, its
  lineage ancestors, and any accompanying RFC-ACDP-0010 receipt or
  RFC-ACDP-0012 proof can all be checked in the viewer, closing the loop on the
  trust-hardening program (the server can no longer be the sole vantage — the
  verifier is at the edge).
- A browser member of the binding family with **byte-identical** golden-vector
  behavior (the `sig-001` / `sig-002` constants must hold on wasm exactly as
  they do for `acdp-py` / `acdp-node`; the interop suite gains a wasm arm).

---

## 6. Sharp edges / risks

- **`getrandom` backend selection is the one thing that can silently go wrong.**
  A misconfigured producer build could fall back to a non-crypto source; the RFC
  §5.10 prohibitions (no default PRNG, no low-entropy seeds) apply on wasm too.
  Keep key generation gated and documented; default the wasm crate to
  verify-only.
- **`getrandom` 0.3/0.4 vs 0.2 config drift.** The config mechanism changed
  between majors (0.2 uses the `js` *feature*; 0.3+ uses
  `--cfg getrandom_backend="wasm_js"` RUSTFLAGS). The crypto path is pinned to
  0.2 via `rand_core 0.6`; if `rand_core`/`ed25519-dalek` later bump to
  `rand_core 0.9`+ (getrandom 0.3), the wasm build config must move to the
  RUSTFLAGS form. Flag this in the CI job so a dependency bump can't break wasm
  silently.
- **`chrono` on wasm.** `chrono` can pull `wasm-bindgen`/`js-sys` for
  "now"-style calls; ACDP only *parses/formats* RFC 3339 timestamps (producer
  timestamps are ms-truncated, `time::trunc_ms`), so the `clock`/`now` surface
  should not be needed — verify `chrono` is used without `default-features`'
  wall-clock path, or the browser build inflates.
- **Zeroization on wasm.** `ZeroizeOnDrop` still runs, but linear-memory
  guarantees differ from native; document that a browser tab is not an HSM (the
  RFC §5.10 key-storage guidance already says the browser holds a handle, not a
  vault — but on wasm the seed *is* in linear memory during a call).
- **Not a full client.** `CrossRegistryResolver`, `RegistryClient`, and
  `did:web` resolution do **not** move to wasm; the host owns HTTP and SSRF
  policy. This is a feature (keeps the SSRF defenses of RFC-ACDP-0006 §7 /
  RFC-ACDP-0008 on a real host), not a gap — but consumers must understand the
  wasm artifact is a *verifier*, not a *fetcher*.

---

## 7. Recommendation

Ship in two steps. **(S)** Add the `wasm32` build-check CI job now — it is
nearly free and permanently protects the "core stays pure" invariant that makes
this possible. **(M)** Then build `bindings/acdp-wasm` as a verify-first
`wasm-bindgen` + WASI crate following the JSON-over-FFI rules, adding the gated
`producer`/`getrandom-js` feature only once the verifier surface and its
golden-vector parity are proven. No spec change is required — this is a pure
implementation/packaging effort on the existing wire-frozen core.
