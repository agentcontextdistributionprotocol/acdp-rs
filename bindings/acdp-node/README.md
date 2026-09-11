# acdp — Node.js SDK

Thin NAPI-rs binding over the [`acdp`](https://crates.io/crates/acdp)
Rust library. Implements the producer- and consumer-side crypto for the
Agent Context Distribution Protocol — v0.1.0 core plus the v0.2.0 Trust &
Hardening surface (RFC-ACDP-0001 through 0015). HTTP is intentionally left
to the caller — pair this with `fetch` / `undici` for transport.

Package version tracks the binding release line (currently **0.8.0**).

## Install

```bash
npm install @agentcontextdistributionprotocol/acdp
```

Prebuilt native binaries are published for macOS (x64/arm64) and Linux
(x64/arm64-gnu); the loader package selects the right one at install time.

## Install (development)

`package-lock.json` is committed, so `npm install` here resolves the pinned
dependency graph (including an exact `@napi-rs/cli` version) rather than
re-resolving fresh.

```bash
npm install                  # installs @napi-rs/cli
npm run build:debug          # produces index.js + acdp.<platform>.node
node --test tests/*.mjs      # in-process unit tests, no HTTP
```

## Build a release binary

```bash
npm run build                # release mode (LTO + strip)
```

## Quickstart

```javascript
import { AcdpProducer, AcdpVerifier } from '@agentcontextdistributionprotocol/acdp';

const producer = AcdpProducer.generate(
  'did:web:agents.example.com:my-agent',
  'did:web:agents.example.com:my-agent#key-1',
);

const raw = producer.buildPublishRequest({
  title: 'Q1 snapshot',
  contextType: 'data_snapshot',
  summary: 'Quarter-end inventory',
});

// POST `raw` (the JSON string) to your registry. On retrieve:
const body = (await response.json()).body;
AcdpVerifier.verifyContentHash(JSON.stringify(body), body.content_hash);
AcdpVerifier.verifySignature(
  pubKeyB64,                  // resolved from the producer's did:web doc
  body.signature.value,
  body.content_hash,
);
```

### Verifying a retrieved body

`ctx_id` is registry-assigned and sits in the RFC-ACDP-0001 §5.7 exclusion
set, so it is stripped before `content_hash` is computed — neither the hash
recompute above nor the producer's signature covers it. Without an
explicit comparison, a registry could serve any other validly-signed body
from the same producer under the `ctx_id` URL you asked for, and every
check above would still pass. Call `verifyCtxIdBinding` to close that gap
(RFC-ACDP-0006 §4.1 step 7, NORMATIVE):

```javascript
// Argument order matters: `bodyJson` carries the *served* ctx_id,
// `expectedCtxId` is the one you requested.
AcdpVerifier.verifyCtxIdBinding(JSON.stringify(body), requestedCtxId);
```

Like the rest of the `AcdpVerifier` bool surface, this returns `true` on
success and throws on failure — never `false` — so
`if (AcdpVerifier.verifyCtxIdBinding(...))` guards a branch that can't be
reached.

### Verifying a registry receipt

`verifyReceipt` (RFC-ACDP-0010 §8) takes the accompanying `bodyJson` as a
**required** second argument — it binds the receipt's `lineage_id`,
`origin_registry`, and `created_at` to the served body's own fields (§8
step 3):

```javascript
AcdpVerifier.verifyReceipt(
  receiptJson,            // the `registry_receipt` object, as received
  bodyJson,                // the accompanying `body`, same retrieval
  registryPublicKeyB64,    // resolved via AcdpDid.webToUrl + fetch
  expectedCtxId,           // the ctx_id you actually requested
  recomputedBodyHash,      // YOUR OWN verifyContentHash result — never
                            // the body's echoed content_hash field
  producerKeyFingerprint,  // fingerprint of the resolved producer key
);
```

Throws on a malformed `bodyJson` (host input) or a body/receipt mismatch
(verification failure) alike — never `false`. Two checks still stay the
HOST's obligation, because neither needs the body: the serving-authority
binding (`receipt.registry_did` must equal the authority you actually
fetched from) and recomputing (never trusting) the body hash you pass in.

## Verification surface

`AcdpVerifier` covers the full 0.2.0 surface in addition to the basics
above: identity binding (`verifyCtxIdBinding`, see
[Verifying a retrieved body](#verifying-a-retrieved-body) above),
offline `did:key` verification (`verifyBodyOffline`,
`verifyPublishRequestOffline`), registry receipts
(`verifyReceipt(receiptJson, bodyJson, registryPublicKeyB64, expectedCtxId, recomputedBodyHash, producerKeyFingerprint)`,
see [Verifying a registry receipt](#verifying-a-registry-receipt) above;
`verifyLineageHeadReceipt`), the transparency log (`verifyLogCheckpoint`,
`verifyLogInclusion`, `verifyLogConsistency`), lifecycle events
(`verifyLifecycleEvent`), key revocation (`parseKeyRevocation`,
`classifyUnderRevocation`), and witness cosigning
(`buildWitnessCosignature`, `verifyWitnessCosignature`,
`evaluateWitnessQuorum`). `AcdpP256Producer`, `AcdpDid`,
`AcdpDidDocument`, `AcdpCanonicalizer`, `AcdpMerkle`, and `AcdpSsrfPolicy`
are also exported.

## Design rules

* **JSON across the FFI boundary.** Every method accepts and returns
  JSON strings — never a Rust type, never a JS class instance you'd
  have to serialize before sending. The binary stays at ~500 lines of
  glue.
* **Crypto in Rust, HTTP in JS.** Key generation, JCS + SHA-256 hashing,
  Ed25519 signing, and signature verification happen in the underlying
  `acdp` crate. Transport, retries, and observability are yours.
* **`AcdpProducer` stores a 32-byte seed.** The Rust `SigningKey` is
  `ZeroizeOnDrop` and not `Clone`, so the binding rebuilds the signing
  key from the seed on each call.
* **Golden vector parity.** `golden content_hash + signature match
  sig-001` pins the JS-side `content_hash` and `signature.value`
  against the spec's `sig-001` fixture — the same constants the Rust
  suite asserts. A drift on either side is a protocol break.

## Layout

```
bindings/acdp-node/
├── Cargo.toml         # standalone [workspace]; depends on `acdp` via path
├── build.rs           # napi-build setup
├── package.json
├── README.md          # this file
├── index.js           # generated by `napi build`
├── index.d.ts         # generated by `napi build`
├── acdp.<platform>.node  # native binary
├── src/
│   ├── lib.rs         # module entry — re-exports the napi classes
│   ├── producer.rs    # AcdpProducer: build/sign publish requests
│   ├── verifier.rs    # AcdpVerifier: content_hash + signature verify
│   └── helpers.rs     # visibility / contextType parsers
└── tests/
    └── test.mjs
```
