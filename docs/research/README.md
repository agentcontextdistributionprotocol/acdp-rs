# Research track

Forward-looking technical evaluation memos for roadmap items. Except where the
status column says otherwise, they are **not yet scheduled**. Each memo is a rigorous, implementer-actionable assessment grounded
in this codebase (the workspace crates under `crates/`) and the normative RFC set
(`agentcontextdistributionprotocol/agentcontextdistributionprotocol/rfcs`). They
are **evaluations, not commitments**, and none changes any wire-frozen
semantic of a Final protocol line.

These sit apart from the [library documentation](../README.md), which describes
the crate *as it exists*. This directory describes things the crate *could grow*.

| Memo | One-line summary | Status |
|---|---|---|
| [WebAssembly target](wasm-target.md) | Ship the pure types/crypto/JCS/`did:key`/offline-verify core to browsers and edge runtimes for client-side zero-server-trust verification; the core is already `ring`-free, so `getrandom` on `wasm32` is the only real sharp edge. | **historical** — shipped as [`bindings/acdp-wasm`](../../bindings/acdp-wasm/README.md) (npm `@agentcontextdistributionprotocol/acdp-wasm`; WASI untested); memo retained for its rationale |
| [`did:webvh` evaluation](did-webvh.md) | Add `did:web` + Verifiable History as a second resolvable producer DID method to close the historical-key-validity gap (RFC-ACDP-0008 §9.3) and the domain-lapse problem independently of receipts; additive and capability-gated like `did:key` was. | evaluation / not scheduled |
| [Post-quantum signatures (ML-DSA)](post-quantum.md) | Add ML-DSA (FIPS 204) via the existing algorithm-agility machinery (the `ml-dsa-*` identifiers are already reserved); an additive, maturity-gated change whose only hard parts are crate readiness and KB-scale signature/key sizes. | evaluation / not scheduled |

## Cross-cutting theme

All three advance the same **trust-hardening arc** the 0.2.0–0.4.0 RFC line
pursues (receipts, key-revocation, transparency logs, witness cosigning):

- **WASM** puts the verifier at the edge, where untrusted data is rendered — the
  last mile of "don't trust the server."
- **`did:webvh`** gives producers a self-certifying, offline-verifiable key
  history that `did:web` architecturally cannot, complementing registry
  receipts.
- **ML-DSA** future-proofs the signature primitive itself against a quantum
  adversary, without touching the wire format.

Two of the three note a **shared witness abstraction** opportunity with
[RFC-ACDP-0015](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0015-witness-cosigning.md)
(`did:webvh` witnesses ≈ transparency-log witnesses), which argues for
sequencing the `did:webvh` work with that RFC line.
