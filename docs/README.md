# acdp — Library Documentation

**Crate**: `acdp` &nbsp;|&nbsp; **Protocol**: ACDP v0.1.0 Final through v0.4.0 (`ACDP_VERSION` = `0.4.0`) &nbsp;|&nbsp; **Language**: Rust (MSRV 1.86)

This is the reference Rust implementation of the **Agent Context Distribution
Protocol**. ACDP lets agents publish immutable, producer-signed context
descriptors, retrieve and verify them locally, discover them by keyword, and
follow signed `acdp://` references across registries.

These docs are **additive to the specification**. They cover *how to use this
crate* — the public types, the verification pipeline, the security defaults,
and the conformance harness. They do **not** restate the wire format or the
normative protocol rules. For those, each page links to the relevant RFC.

> **Specification.** The normative source of truth is the RFC set in
> [`agentcontextdistributionprotocol/agentcontextdistributionprotocol`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/tree/main/rfcs).
> Throughout these docs, citations like *RFC-ACDP-0001 §5.7* point at a specific
> normative section. When the spec and this crate disagree, the spec wins and
> the crate has a bug — please report it.

---

## Start here

| If you want to… | Read |
|---|---|
| Install the crate and run your first publish/verify | [Getting Started](getting-started.md) |
| Understand how the crate is layered (what gets hashed/signed/stored) | [Architecture](architecture.md) |

## Building blocks

| Doc | Covers |
|---|---|
| [Producing contexts](producing.md) | `Producer`, `RequestBuilder`, supersession, lineage, data refs — building and signing a `PublishRequest`. |
| [Consuming & verifying](consuming.md) | `RegistryClient`, `VerifiedContext`, the verification pipeline, `VerificationReport`, `CrossRegistryResolver`, data-ref fetching. |
| [Errors & retries](errors.md) | `AcdpError`, the RFC-ACDP-0007 wire-code mapping, and `is_transient` retry guidance. |
| [Security model](security.md) | The SSRF defenses and HTTPS/size/redirect caps the client applies automatically, and how they map to RFC-ACDP-0006 §7 / RFC-ACDP-0008. |

## For registry implementers

| Doc | Covers |
|---|---|
| [Implementing a registry](registry.md) | The `server` feature: `RegistryServer`, `PublishValidator`, `RegistryStore`, and the publish pipeline you MUST follow (RFC-ACDP-0003 §2.1). |

## Tooling & ecosystem

| Doc | Covers |
|---|---|
| [CLI reference](cli.md) | The `acdp` binary (`cli` feature) — 11 subcommands for capabilities, retrieve, publish, validate, hash, sign, resolve. |
| [Language bindings](bindings.md) | The Python (`acdp-py`) and Node (`acdp-node`) SDKs and the JSON-across-FFI design. |
| [Release runbook](release-runbook.md) | Tagging/publishing the crate family and the three language bindings, and the tag-triggered-workflow hazard (H11) to mind when tagging retroactively. |
| [Conformance & testing](conformance.md) | Running the spec golden vectors and the conformance fixture suite via `ACDP_SPEC_DIR`. |
| [Supply-chain security](supply-chain.md) | Build provenance (npm/PyPI/GitHub attestations), the Action-pinning policy, the `cargo vet` contributor workflow, and the `cargo deny` posture. |

## Research track

Forward-looking evaluation memos for roadmap items that are **not yet scheduled** —
WebAssembly targeting, `did:webvh`, and post-quantum (ML-DSA) signatures. See
[research/README.md](research/README.md).

---

## The 30-second model

ACDP separates three things that the crate keeps strictly apart. Misplacing a
field across these layers breaks the protocol:

- **ProducerContent** — the producer-controlled fields. Its JCS-canonicalized
  SHA-256 is the `content_hash`, and the `content_hash` string is what the
  producer signs.
- **Body** — ProducerContent plus the registry-assigned fields (`ctx_id`,
  `lineage_id`, `origin_registry`, `created_at`) and the integrity fields
  (`content_hash`, `signature`). Immutable once published.
- **RegistryState** — the mutable, registry-derived state (`status`, and in
  0.2.0 the optional registry receipt) returned alongside the Body on retrieval.

```
PublishRequest                 ← what a producer POSTs
  ├── (Body fields)
  ├── content_hash  = sha256(JCS(ProducerContent))
  └── signature     = Ed25519 over the ASCII "sha256:<hex>" string

FullContext = Body + RegistryState   ← what a registry returns on retrieval
```

See [Architecture](architecture.md) for the full breakdown and the module map.

## Rustdoc

These guides complement — they don't replace — the API reference. Build the
full rustdoc locally:

```bash
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --all-features --no-deps --open
```

or read it on [docs.rs/acdp](https://docs.rs/acdp).
