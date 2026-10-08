# acdp — Python SDK

Thin PyO3 binding over the [`acdp`](https://crates.io/crates/acdp) Rust
library. Implements the producer- and consumer-side crypto for the Agent
Context Distribution Protocol — the 0.1.0–0.4.0 Final lines plus RFC-ACDP-0016
external anchors; see the spec's
[version matrix](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/docs/version-matrix.md) for exactly
which protocol lines each release implements. HTTP is intentionally left to
the caller — pair this with `httpx` / `requests` for transport.

The package is released at the same version as the
[`acdp`](https://crates.io/crates/acdp) crate.

## Install

```bash
pip install acdp               # from PyPI
```

## Install (development)

```bash
pip install 'maturin==1.15.0' 'pytest==8.4.2'   # the versions CI pins
maturin develop                # editable install into the active venv
pytest tests/                  # in-process unit tests, no HTTP
```

The pinned tool versions are listed in
[Pinned binding toolchain](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/bindings.md#pinned-binding-toolchain);
that table is the source of truth if the line above drifts.

## Build a wheel

```bash
maturin build --release        # produces target/wheels/acdp-*.whl
pip install target/wheels/acdp-*.whl
```

## Verification surface

Beyond `build_publish_request` / `build_supersede_request` (Ed25519 and
P-256 producers) and the `verify_content_hash` / `verify_signature`
basics, `AcdpVerifier` exposes the full verification surface:

- `verify_ctx_id_binding` — bind the served `ctx_id` to the one you
  requested (RFC-ACDP-0006 §4.1 step 7, NORMATIVE); see
  [Verifying a retrieved body](#verifying-a-retrieved-body) below for why
  this is a separate call.
- `verify_body_offline` / `verify_publish_request_offline` — offline
  `did:key` verification (no network).
- `verify_receipt(receipt_json, body_json, registry_public_key_b64, expected_ctx_id, recomputed_body_hash, producer_key_fingerprint)`
  / `verify_lineage_head_receipt` — registry receipts (RFC-ACDP-0010/0011);
  see [Verifying a registry receipt](#verifying-a-registry-receipt) below.
- `verify_log_checkpoint` / `verify_log_inclusion` /
  `verify_log_consistency` — transparency log (RFC-ACDP-0012).
- `verify_lifecycle_event` — lifecycle/retraction (RFC-ACDP-0013).
- `parse_key_revocation` / `classify_under_revocation` — key revocation
  (RFC-ACDP-0014).
- `build_witness_cosignature` / `verify_witness_cosignature` /
  `evaluate_witness_quorum` — witness cosigning (RFC-ACDP-0015).

`AcdpDid`, `AcdpDidDocument`, `AcdpCanonicalizer`, `AcdpMerkle`, and
`AcdpSsrfPolicy` are also exported.

## Quickstart

```python
import json, acdp

producer = acdp.AcdpProducer.generate(
    "did:web:agents.example.com:my-agent",
    "did:web:agents.example.com:my-agent#key-1",
)

raw = producer.build_publish_request(
    title="Q1 snapshot",
    context_type="data_snapshot",
    summary="Quarter-end inventory",
)
request = json.loads(raw)

# POST `raw` (the JSON string) to the registry's /contexts endpoint
# with your HTTP client of choice. On retrieve, validate the response:
body = ...  # response.json()["body"]
acdp.AcdpVerifier.verify_content_hash(json.dumps(body), body["content_hash"])
acdp.AcdpVerifier.verify_signature(
    pub_key_b64,                  # resolved from the producer's did:web doc
    body["signature"]["value"],
    body["content_hash"],
)
```

### Verifying a retrieved body

`ctx_id` is registry-assigned and sits in the RFC-ACDP-0001 §5.7 exclusion
set, so it is stripped before `content_hash` is computed — neither the hash
recompute above nor the producer's signature covers it. Without an
explicit comparison, a registry could serve any other validly-signed body
from the same producer under the `ctx_id` URL you asked for, and every
check above would still pass. Call `verify_ctx_id_binding` to close that
gap (RFC-ACDP-0006 §4.1 step 7, NORMATIVE):

```python
# Argument order matters: `body_json` carries the *served* ctx_id,
# `expected_ctx_id` is the one you requested. Using keyword args makes a
# transposed call impossible to typo silently.
acdp.AcdpVerifier.verify_ctx_id_binding(
    body_json=json.dumps(body),
    expected_ctx_id=requested_ctx_id,
)
```

Like the rest of the `AcdpVerifier` bool surface, this returns `True` on
success and raises on failure (`ValueError` for a malformed `ctx_id` on
either side, `RuntimeError` for a mismatch) — it never returns `False`, so
`if acdp.AcdpVerifier.verify_ctx_id_binding(...):` guards a branch that
can't be reached.

### Verifying a registry receipt

`verify_receipt` (RFC-ACDP-0010 §8) takes the accompanying `body_json` as
a **required** second argument — it binds the receipt's `lineage_id`,
`origin_registry`, and `created_at` to the served body's own fields (§8
step 3):

```python
acdp.AcdpVerifier.verify_receipt(
    receipt_json,             # the `registry_receipt` object, as received
    body_json,                 # the accompanying `body`, same retrieval
    registry_public_key_b64,   # resolved via AcdpDid.web_to_url + httpx
    expected_ctx_id,           # the ctx_id you actually requested
    recomputed_body_hash,      # YOUR OWN verify_content_hash result —
                                # never the body's echoed content_hash
    producer_key_fingerprint,  # fingerprint of the resolved producer key
)
```

A malformed `body_json` raises `ValueError` (host input); a body/receipt
mismatch raises `RuntimeError` (verification failure) — the two are
distinguishable by exception type. Two checks still stay the HOST's
obligation, because neither needs the body: the serving-authority binding
(`receipt.registry_did` must equal the authority you actually fetched
from) and recomputing (never trusting) the body hash you pass in.

## Design rules

* **JSON across the FFI boundary.** Every method accepts and returns
  JSON strings — never a Rust type, never a Python dataclass.
* **Crypto in Rust, HTTP in Python.** Key generation, JCS + SHA-256
  hashing, Ed25519 signing, and signature verification all happen in
  the underlying `acdp` crate. The Python side handles transport,
  retries, and observability.
* **`AcdpProducer` stores a 32-byte seed.** The Rust `SigningKey` is
  `ZeroizeOnDrop` and not `Clone`, so the binding rebuilds the signing
  key from the seed on each call.
* **Golden vector parity.** `test_golden_content_hash` pins the
  Python-side `content_hash` and `signature.value` against the spec's
  `sig-001` fixture — the same constants the Rust suite asserts. A
  drift on either side is a protocol break.

## Public surface

The canonical list of exported classes and methods (and their arity) is
[`bindings/interop/expected_surface.json`](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/bindings/interop/expected_surface.json),
enforced against this package by the interop parity tests.
