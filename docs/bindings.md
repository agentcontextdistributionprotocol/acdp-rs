# Language Bindings

The crate ships three SDKs that reuse the Rust crypto core:

- **`bindings/acdp-py`** — Python, via [PyO3](https://pyo3.rs) / maturin
  (published to PyPI as `acdp`).
- **`bindings/acdp-node`** — Node.js, via [NAPI-rs](https://napi.rs)
  (published to npm as `@agentcontextdistributionprotocol/acdp`).
- **`bindings/acdp-wasm`** — a browser/edge WebAssembly **verifier core**, via
  `wasm-bindgen` / wasm-pack (published to npm as
  `@agentcontextdistributionprotocol/acdp-wasm`). Verification-only — no
  producer/signing surface.

All implement the same protocol primitives as the Rust crate, so a context
signed in Python verifies in Node, in the browser, and in Rust. Each binding is
released at the same version as the `acdp` crate (the release cascade stamps
it at publish time) and carries the same protocol
surface; which protocol lines each SDK version implements is recorded in the
spec's
[`docs/version-matrix.md`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/docs/version-matrix.md).

## Design: crypto in Rust, HTTP in the host

The single most important design decision: **the bindings never make network
calls.** They expose the deterministic, security-critical operations — building,
hashing, signing, verifying — and leave transport to the host language's HTTP
stack (`httpx`, `fetch`, …).

This is why all three bindings depend on `acdp` with `default-features = false`:
`reqwest` / `tokio` / `rustls` never enter the Python wheel, the `.node`
binary, or the `.wasm` module. They only need the pure-types/crypto core (see
[Architecture → feature gating](architecture.md#feature-gating)).

### JSON across the FFI boundary

Every binding method accepts and returns **JSON strings** — the same HTTP
request/response bodies you'd send on the wire. No Rust types cross the
boundary, so the API stays small and stable across language updates.

```
host language  ──(JSON string)──►  binding (Rust crypto)  ──(JSON string)──►  host language
     │                                                                              │
     └──────────────────── HTTP (httpx / fetch) ──────────────────────────────────┘
```

### Key handling

`AcdpProducer` stores a **32-byte seed**, not a live `SigningKey`. `SigningKey`
is `ZeroizeOnDrop` and not `Clone`, so the binding rebuilds it from the seed for
each call. The seams that make this work are `SigningKey::seed_bytes()` and
`SigningKey::sign_string()` in `crates/acdp-crypto/src/sign.rs` — they exist
specifically to support the binding surface.

## Python (`acdp-py`)

```bash
cd bindings/acdp-py && maturin develop      # or: make sdk-py
```

```python
import json, httpx
from acdp import AcdpProducer, AcdpVerifier

# Build + sign — returns a JSON publish request
producer = AcdpProducer.generate("did:web:agents.example.com:my-agent",
                                 "did:web:agents.example.com:my-agent#key-1")
req = producer.build_publish_request(title="Q1 snapshot", context_type="data_snapshot")

# Transport is yours:
httpx.post("https://registry.example.com/contexts",
           content=req, headers={"Content-Type": "application/acdp+json"})

# Optional RFC-ACDP-0016 external anchors: a JSON-encoded array of
# {scheme, content_hash, uri?} objects, part of the content_hash preimage.
# (Schemes: registries/anchor-schemes.md in the spec repo.)
req = producer.build_publish_request(
    title="Q1 snapshot", context_type="data_snapshot",
    anchors=json.dumps([{"scheme": "macp.commitment",
                         "content_hash": "sha256:" + "ab" * 32}]))

# Verify a retrieved body (raises on mismatch)
AcdpVerifier.verify_content_hash(body_json, stored_hash)
AcdpVerifier.verify_signature(pub_key_b64, sig_b64, content_hash)

# Bind the served identity to the one you requested (RFC-ACDP-0006 §4.1
# step 7, NORMATIVE). `ctx_id` is registry-assigned and in the §5.7
# exclusion set, so neither content_hash nor the signature covers it —
# without this call a registry could serve any other validly-signed body
# from the same producer under the URL you asked for.
AcdpVerifier.verify_ctx_id_binding(body_json=body_json, expected_ctx_id=requested_ctx_id)
```

All `AcdpVerifier` methods that return a plain bool follow the same
convention: they return `True`/`true` on success and raise/throw on
failure — never `False`/`false`. Writing `if AcdpVerifier.verify_...(...)`
guards a branch that can't be reached.

## Node.js (`acdp-node`)

```bash
cd bindings/acdp-node && npm run build:debug   # or: make sdk-node
```

```js
const { AcdpProducer, AcdpVerifier } = require('@agentcontextdistributionprotocol/acdp');

const producer = AcdpProducer.generate(
  'did:web:agents.example.com:my-agent',
  'did:web:agents.example.com:my-agent#key-1');
const req = producer.buildPublishRequest({ title: 'Q1 snapshot', contextType: 'data_snapshot' });

await fetch('https://registry.example.com/contexts', {
  method: 'POST',
  headers: { 'Content-Type': 'application/acdp+json' },
  body: req,
});

AcdpVerifier.verifyContentHash(bodyJson, storedHash);  // throws on mismatch
AcdpVerifier.verifySignature(pubKeyB64, sigB64, contentHash);

// Bind the served identity to the one you requested (RFC-ACDP-0006 §4.1
// step 7, NORMATIVE) — argument order is (bodyJson, expectedCtxId): the
// body carries the *served* ctx_id, the second argument is what you
// requested. ctx_id is registry-assigned and outside content_hash /
// signature coverage, so this explicit check is the only binding
// available on the receipt-less path.
AcdpVerifier.verifyCtxIdBinding(bodyJson, requestedCtxId);  // throws on mismatch
```

The Node API is the same surface in camelCase; external anchors are the
same JSON-encoded string, passed as the `anchors` option of
`buildPublishRequest` / `buildSupersedeRequest`. Known `scheme` identifiers are
tracked in the spec's [anchor-schemes registry](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/registries/anchor-schemes.md).

## Verifying a registry receipt

`verify_receipt` / `verifyReceipt` (RFC-ACDP-0010 §8) checks a registry
receipt against the body it accompanies. `body_json` is a **required**
second argument (not optional) — it binds the receipt's `lineage_id`,
`origin_registry`, and `created_at` to the served body's own fields (§8
step 3), the sibling check to `verify_ctx_id_binding` on the
receipt-bearing path.

```python
# Python
AcdpVerifier.verify_receipt(
    receipt_json,            # the `registry_receipt` object, as received
    body_json,                # the accompanying `body`, from the same retrieval
    registry_public_key_b64,  # resolved via AcdpDid.web_to_url + httpx
    expected_ctx_id,          # the ctx_id you actually requested
    recomputed_body_hash,     # YOUR OWN verify_content_hash result — never
                               # the body's echoed content_hash field
    producer_key_fingerprint, # fingerprint of the resolved producer key
)
```

```js
// Node.js
AcdpVerifier.verifyReceipt(
  receiptJson,
  bodyJson,
  registryPublicKeyB64,
  expectedCtxId,
  recomputedBodyHash,
  producerKeyFingerprint,
);
```

Two checks stay the HOST's obligation on every binding, because neither
needs the body — they need things this binding never sees:

1. **Serving-authority binding** — `receipt.registry_did` must equal
   `"did:web:" + <authority>` for the authority the response was
   *actually fetched from*, compared against your HTTP client's request
   URL, not any field inside the response.
2. **Recompute, don't trust, the body hash** — `recomputed_body_hash`
   must be a hash *you* independently recomputed (run
   `verify_content_hash` on the body first), never the body's echoed
   `content_hash` field taken on faith.

## WebAssembly (`acdp-wasm`)

A verification-only core for browsers and edge runtimes. It exposes the
consumer-side checks (`verifyContentHash`, `verifySignatureEd25519`,
`verifyCtxIdBinding`, `verifyBodyOffline`, receipt/log/lifecycle/witness
verification) but no producer/signing surface — signing keys should not
live in a browser.

```bash
cd bindings/acdp-wasm && wasm-pack build --target web
```

```js
import init, { verifyContentHash, verifyCtxIdBinding, verifyReceipt } from '@agentcontextdistributionprotocol/acdp-wasm';
await init();
const verdict = JSON.parse(verifyContentHash(bodyJson, storedHash));

// Bind the served ctx_id to the one requested (RFC-ACDP-0006 §4.1 step 7).
// Like verifyContentHash, a malformed *served* ctx_id is
// reported as a `{"valid": false, ...}` verdict, not a throw — only a
// malformed `expectedCtxId` argument throws.
const binding = JSON.parse(verifyCtxIdBinding(bodyJson, requestedCtxId));
if (binding.valid) { /* served ctx_id matches what was requested */ }

// verifyReceipt takes bodyJson as its required 2nd argument (RFC-ACDP-0010
// §8 step 3 body binding). A malformed bodyJson throws (host input); a
// body/receipt mismatch is a `{"valid": false, ...}` verdict, like any
// other cross-check failure.
const rcpt = JSON.parse(verifyReceipt(
  receiptJson, bodyJson, registryPublicKeyB64,
  expectedCtxId, recomputedBodyHash, producerKeyFingerprint,
));
```

See `bindings/acdp-wasm/README.md` for the full exported surface.

## Golden-vector parity

All three binding test suites pin the **same** constants from the `sig-001`
golden vector:

```
content_hash    = "sha256:f170150d…"
signature.value = "ErkbV+FU…"
```

The `bindings/interop/` suite cross-builds the identical request in the Python
and Node bindings and asserts byte equality. If any of those constants drift,
the protocol is broken — that's the tripwire.

`bindings/interop/test_parity.py` also guards against API drift, using
`bindings/interop/expected_surface.json` as the single source of truth:

- **API-surface parity** — Python and Node must expose the same classes and
  methods (names normalized to snake_case) as the manifest.
- **Arity guard** — the manifest's `arity` block pins each method's required
  and total parameter count, checked against Python, the Node `.d.ts`, and the
  WASM `.d.ts`.
- **WASM surface parity** — the manifest's `wasm` block pins the flat
  `acdp-wasm` export surface, including its permanent aliases. These checks
  skip when `bindings/acdp-wasm/pkg/` is not built, unless
  `ACDP_REQUIRE_WASM_PARITY=1` (set in CI).
- **Version parity** — all binding manifests carry the same version.

```bash
cd bindings/interop && pytest        # or: make interop (build wasm first with make sdk-wasm)
```

For an independent, non-Rust second implementation used as the
cross-implementation interop gate, see `acdp-verifier-py`'s
[Cross-implementation interop](https://github.com/agentcontextdistributionprotocol/acdp-verifier-py#cross-implementation-interop-rfc-acdp-0015-witness-cosigning)
section.

## Build details

Each binding is a **standalone Cargo package** (its own `[workspace]` table)
that references the parent crate via `path = "../.."`. They are **not** part of
`cargo test` on the root crate — build each independently with maturin / napi /
wasm-pack. The top-level `Makefile` wraps the common targets: `make sdk-py`,
`make sdk-node`, `make sdk-wasm`, `make interop`, `make audit-bindings`
(`cargo deny` advisories for all three bindings; `npm audit` for `acdp-node`
only), and `make ci-bindings`. `make ci-bindings` is a **local subset** of
`.github/workflows/bindings.yml`: it runs the root tests, the Python and Node
SDK suites, interop, and the advisory audits, but not `bindings-fmt`, the
`acdp-wasm` job (native golden parity, `wasm32` builds, `wasm-pack test`), the
`v030.rs`/`v040.rs` copy-parity guard, or the Python/Node version matrices —
and `make interop` skips the wasm parity checks unless `make sdk-wasm` was run
first.

### Pinned binding toolchain

The binding builds pin their toolchains so a release is reproducible:

| Tool | Pin | Where |
|---|---|---|
| `maturin`, `pytest` | `maturin==1.15.0`, `pytest==8.4.2` | `.github/workflows/bindings.yml` |
| `@napi-rs/cli` | `3.8.6`, exact | `bindings/acdp-node/package.json`; asserted in `bindings.yml` and `bindings-release.yml` |
| `rustc` for the wasm release | `1.98.0` | `.github/workflows/acdp-wasm-release.yml` |
| `wasm-pack` | `0.15.0` | `bindings.yml`, `acdp-wasm-release.yml` (via `taiki-e/install-action`) |
| Cargo / npm lockfiles | `bindings/{acdp-py,acdp-node,acdp-wasm}/Cargo.lock` and `bindings/acdp-node/package-lock.json` are committed; Cargo builds run `--locked`, and CI installs the npm graph with `npm ci` (rationale at `.github/workflows/bindings.yml:124`) | `.gitignore` (rationale), the binding workflows |
