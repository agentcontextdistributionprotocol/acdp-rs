# acdp-wasm — ACDP WebAssembly verification core

The **browser / edge / WASI** member of the ACDP binding family
(`bindings/acdp-py`, `bindings/acdp-node`). A pure, **offline**
cryptographic verifier: it lets a consumer render an ACDP context and
independently reach a real verification **verdict** — the producer
signature, the `content_hash`, a registry receipt (RFC-ACDP-0010), a
lineage-head receipt (RFC-ACDP-0011), a transparency-log checkpoint /
inclusion / consistency proof (RFC-ACDP-0012), a lifecycle event
(RFC-ACDP-0013), a key revocation (RFC-ACDP-0014), and witness
cosignatures + quorum (RFC-ACDP-0015) — **without trusting any server to
have done it**. This is the client-side verification core the console's
verdicts consume.

It is a standalone Cargo package (its own `[workspace]`) that depends on
the umbrella `acdp` crate with `default-features = false`, so
`reqwest` / `tokio` / `rustls` never enter the `.wasm` binary. See
`docs/research/wasm-target.md` for the design rationale.

## Design (same rules as the Python / Node bindings)

- **JSON across the boundary.** Every export takes JSON strings and
  returns a JSON string — a **verdict object** (`{"valid": true, ...}` /
  `{"valid": false, "code"?, "error"}`) for verification outcomes, or a
  result string for constructors/resolvers. Malformed *host* input
  throws a `JsError`; a failed *verification* is `{"valid": false}`,
  never a throw.
- **Crypto in Rust, HTTP in the host.** No network calls. `did:web`
  resolution and all transport stay in JS (`fetch` the DID document /
  receipt / body, pass the JSON in). `did:key` verification is fully
  offline and needs no host help — the highest-value browser path.
- **No crypto reimplemented.** Every check delegates to the same `acdp`
  core the native library, Python, and Node bindings use. The 0.3/0.4
  verdict logic (`src/v030.rs`, `src/v040.rs`) is lifted **verbatim,
  byte-identical** from the other bindings.

## Exported surface

wasm-bindgen exports (camelCase in JS/TypeScript):

| Export | RFC | Purpose |
|---|---|---|
| `verifyContentHash` | 0001 §5.7 | recompute `sha256(JCS(producer_content))` |
| `verifySignatureEd25519` / `verifySignatureP256` | 0001 §5.8 | signature over the ASCII `"sha256:<hex>"` string |
| `verifyCtxIdBinding` | 0006 §4.1 step 7 | bind the served `ctx_id` to the one requested — see [Verifying a retrieved body](#verifying-a-retrieved-body) |
| `verifyBodyOffline` / `verifyPublishRequestOffline` | 0002 | full `did:key` context verify (no resolution) |
| `fingerprintEd25519` / `verifyReceipt(receiptJson, bodyJson, registryPublicKeyB64, expectedCtxId, recomputedBodyHash, producerKeyFingerprint)` | 0010 | registry-receipt verification — see [Verifying a registry receipt](#verifying-a-registry-receipt) below |
| `verifyLineageHeadReceipt` | 0011 | lineage-head receipt |
| `verifyLogCheckpoint` / `verifyLogInclusion` / `verifyLogConsistency` / `buildLogLeaf` / `merkleLeafHash` / `merkleNodeHash` / `merkleRootHash` | 0012 | transparency log |
| `verifyLifecycleEvent` | 0013 | lifecycle event |
| `parseKeyRevocation` / `classifyUnderRevocation` | 0014 | key revocation |
| `buildWitnessCosignature` / `verifyWitnessCosignature` / `evaluateWitnessQuorum` | 0015 | witness cosignatures + quorum |
| `resolveDidKey` | — | offline `did:key` → public key |
| `canonicalPreimage` / `explainHashMismatch` | — | hash-divergence diagnostics |

## Install

Published to npm as **`@agentcontextdistributionprotocol/acdp-wasm`** (a
public scoped package, provenance-signed on GitHub Actions), so the console
and other consumers depend on it without a sibling checkout:

```bash
npm install @agentcontextdistributionprotocol/acdp-wasm
```

```js
import init, { verifyContentHash, verifySignatureEd25519, verifyCtxIdBinding }
  from "@agentcontextdistributionprotocol/acdp-wasm";
await init();
const verdict = JSON.parse(verifyContentHash(bodyJson, body.content_hash));
if (verdict.valid) { /* the hash the consumer recomputed itself checks out */ }

// Bind the served ctx_id to the one requested (RFC-ACDP-0006 §4.1 step 7).
// See "Verifying a retrieved body" below for why this is a separate call.
const binding = JSON.parse(verifyCtxIdBinding(bodyJson, requestedCtxId));
if (binding.valid) { /* the ctx_id you got back is the one you asked for */ }
```

### Verifying a retrieved body

`ctx_id` is registry-assigned and sits in the RFC-ACDP-0001 §5.7 exclusion
set, so it is stripped before `content_hash` is computed — neither the hash
recompute above nor the producer's signature covers it. Without an
explicit comparison, a registry could serve any other validly-signed body
from the same producer under the `ctx_id` URL you asked for, and every
check above would still pass. `verifyCtxIdBinding(bodyJson, expectedCtxId)`
closes that gap: `bodyJson` carries the *served* identity, `expectedCtxId`
is what you requested. Like `verifyContentHash`, a malformed *served*
`ctx_id` is a `{"valid": false, ...}` verdict, not a throw — only a
malformed `expectedCtxId` argument throws a `JsError`.

### Verifying a registry receipt

`verifyReceipt` (RFC-ACDP-0010 §8) takes the accompanying `bodyJson` as a
**required** second argument — it binds the receipt's `lineage_id`,
`origin_registry`, and `created_at` to the served body's own fields (§8
step 3):

```js
const verdict = JSON.parse(verifyReceipt(
  receiptJson, bodyJson, registryPublicKeyB64,
  expectedCtxId, recomputedBodyHash, producerKeyFingerprint,
));
```

A malformed `bodyJson` throws a `JsError` (host input); a body/receipt
mismatch is a `{"valid": false, ...}` verdict (verification outcome), not
a throw — same convention as `verifyContentHash` / `verifyCtxIdBinding`.
Two checks still stay the HOST's obligation, because neither needs the
body: the serving-authority binding (`receipt.registry_did` must equal
the authority you actually fetched from) and recomputing (never
trusting) the body hash you pass in.

The package is built with `wasm-pack --target web`: an ESM module you
initialize once with `await init()`. This is the target the crate is
designed and CI-tested around, and it loads cleanly in browsers and in
Next.js client components (webpack 5 resolves the `new URL(..., import.meta.url)`
wasm asset the `web` target emits — no `experiments.asyncWebAssembly`
webpack override, which the `bundler` target would require).

## Build

```bash
rustup target add wasm32-unknown-unknown

# Raw wasm (regression build-check):
cargo build --target wasm32-unknown-unknown            # verify-only default

# Browser package (.js / .wasm / .d.ts) with wasm-pack. `--scope` makes
# wasm-pack emit the package name `@agentcontextdistributionprotocol/acdp-wasm`
# (the same rename the release workflow performs):
wasm-pack build --target web --out-dir pkg --scope agentcontextdistributionprotocol
```

Import from a browser (local, unpublished build):

```js
import init, { verifyContentHash, verifySignatureEd25519, verifyCtxIdBinding } from "./pkg/acdp_wasm.js";
await init();
const verdict = JSON.parse(verifyContentHash(bodyJson, body.content_hash));
if (verdict.valid) { /* the hash the consumer recomputed itself checks out */ }
const binding = JSON.parse(verifyCtxIdBinding(bodyJson, requestedCtxId));
if (binding.valid) { /* the ctx_id you got back is the one you asked for */ }
```

## Golden-vector parity

`tests/golden.rs` is a **native** `cargo test` that runs the canonical
`sig-001` (content hash + Ed25519 signature) and `wit-001` (witness
cosignature mint + verify) spec fixtures through the same pure `core`
functions the wasm exports wrap, asserting byte-for-byte reproduction of
the pinned golden values — the same constants the `acdp-py` / `acdp-node`
suites pin. It locates fixtures via `ACDP_SPEC_DIR` and skips gracefully
when absent:

```bash
ACDP_SPEC_DIR=../../../agentcontextdistributionprotocol cargo test
```

`tests/wasm.rs` is a `wasm-bindgen-test` real-engine smoke test of the
exported wrappers (inline sig-001 constants, no fixtures needed):

```bash
wasm-pack test --node
```

## Randomness — a correction to the research memo

`docs/research/wasm-target.md` §4 predicted a **verify-only** build would
need **no `getrandom` backend** on any wasm target. That holds at
*runtime* — no exported verification (nor the deterministic Ed25519
witness mint) draws randomness. It does **not** hold at *compile time*
for `wasm32-unknown-unknown`: the core crates pull **`getrandom 0.4`**
**unconditionally**, from two places, and it emits a hard
`compile_error!` on that target unless a backend is wired:

- `acdp-crypto` key generation (`getrandom::SysRng`, used with
  `rand_core` 0.10, which has no `OsRng`); and
- **`uuid` v4** (a non-optional dependency of `acdp-primitives`).

The backend is the getrandom **`wasm_js` feature** (on the
`getrandom_wasm` alias in `Cargo.toml`), plus
`--cfg getrandom_backend="wasm_js"` in `.cargo/config.toml`, which is
inert at 0.4.3 and kept for forward compatibility. `uuid` additionally
needs its own **`js` feature** for its v4 RNG shim. (An older direct
`getrandom 0.2` dependency with the `js` feature, for the former
`rand_core 0.6` / `OsRng` path, was removed in #363; nothing in this
binding's graph uses 0.2 any more.)

Both are wired here, **target-gated to `wasm32` only** (see
`Cargo.toml` and `.cargo/config.toml`), so a native `cargo test` is
untouched. `crypto.getRandomValues` (the `wasm_js` backend) is the CSPRNG
RFC-ACDP-0001 §5.10 names for the browser, so the choice is spec-blessed
— but it is never invoked on the verify path; it is present only to link.

A future `producer` feature (reserved, not yet wired) would expose fresh
key generation (`SigningKey::generate`, the only `SysRng` caller) and is
where a runtime randomness draw would actually occur.

## Security notes

- This artifact is a **verifier, not a fetcher**. `RegistryClient`,
  `CrossRegistryResolver`, and `did:web` resolution do NOT move to wasm;
  the host owns HTTP and the RFC-ACDP-0006 §7 / RFC-ACDP-0008 SSRF
  defenses. Pass fetched documents in as JSON.
- A browser tab is not an HSM. Verification holds no secrets, but a
  future `producer`/keygen surface would place the signing seed in wasm
  linear memory during a call (RFC-ACDP-0001 §5.10).
