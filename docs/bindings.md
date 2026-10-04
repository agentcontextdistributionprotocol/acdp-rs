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
signed in Python verifies in Node, in the browser, and in Rust. The protocol
contract they implement is the same RFC set (0001 through 0016) — see
[RFC-ACDP-0001](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0001-core.md).

## Design: crypto in Rust, HTTP in the host

The single most important design decision: **the bindings never make network
calls.** They expose the deterministic, security-critical operations — building,
hashing, signing, verifying — and leave transport to the host language's HTTP
stack (`httpx`, `fetch`, …).

This is why both bindings depend on `acdp` with `default-features = false`:
`reqwest` / `tokio` / `rustls` never enter the Python wheel or the `.node`
binary. They only need the pure-types/crypto core (see
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

The Node API is the same surface in camelCase.

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

Both binding test suites pin the **same** constants from the `sig-001` golden
vector:

```
content_hash    = "sha256:f170150d…"
signature.value = "ErkbV+FU…"
```

The `bindings/interop/` suite cross-builds the identical request in *both*
bindings and asserts byte equality. If any of those constants drift, the
protocol is broken — that's the tripwire.

```bash
cd bindings/interop && pytest        # or: make interop
```

## Build details

Each binding is a **standalone Cargo package** (its own `[workspace]` table)
that references the parent crate via `path = "../.."`. They are **not** part of
`cargo test` on the root crate — build each independently with maturin / napi /
wasm-pack. The top-level `Makefile` wraps the common targets: `make sdk-py`,
`make sdk-node`, `make interop`.
