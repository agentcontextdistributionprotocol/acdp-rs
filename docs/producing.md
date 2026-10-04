# Producing Contexts

This page covers building and signing a `PublishRequest` with `Producer` and
`RequestBuilder`. For what the fields *mean* and the publish wire contract, see
[RFC-ACDP-0002 (Context Body)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0002-context-body.md)
and [RFC-ACDP-0003 (Publish & Supersession)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0003-publish.md).

Available in the **default (core) build** — no feature flags, no HTTP. The
producer only *builds and signs*; transport is your responsibility (use the
[`client`](consuming.md) feature, the [CLI](cli.md), or your own HTTP).

## The producer

A `Producer` binds a signing key to a producer identity and a key id. For a
`did:web` producer the key id is the verification-method id in the producer's
`did:web` document. For a `did:key` producer (ACDP 0.2) both the identity and
the key id are derived from the public key itself.

```rust
use acdp::{crypto::SigningKey, producer::Producer, types::AgentDid};

let key = SigningKey::from_bytes(&seed);          // or SigningKey::generate()
let producer = Producer::new(
    key,
    AgentDid::new("did:web:agents.example.com:my-agent"),
    "did:web:agents.example.com:my-agent#key-1",
);
```

| Constructor | Algorithm | Notes |
|---|---|---|
| `Producer::new(key, agent_id, key_id)` | Ed25519 | The common case. |
| `Producer::new_ed25519(...)` | Ed25519 | Explicit alias of `new`. |
| `Producer::new_p256(key, ...)` | ECDSA-P256 | Interop only. **Ed25519 is mandatory** (RFC-ACDP-0001 §5.10); P256 is optional and some registries may not accept it. |
| `Producer::new_did_key(key)` | Ed25519 | `did:key` identity derived from the key: no domain or DID-document hosting, and consumers verify offline. A `did:key` cannot rotate, so a new key is a new identity and ends the lineage. |
| `Producer::new_did_key_p256(p256_key)` | ECDSA-P256 | As above, for P-256. Returns `Result` (fails only on a malformed SEC1 point). |

`SigningKey` is `ZeroizeOnDrop` and not `Clone` — it erases its seed on drop.
Load the 32-byte seed from secure storage in production rather than calling
`generate()` (which uses OS entropy and gives you a fresh, unrecoverable key).

## Building a first version

```rust
use acdp::types::{ContextType, Visibility};

let req = producer
    .publish_request()
    .title("Q1 2026 revenue snapshot")          // required, 1..=500 chars
    .context_type(ContextType::DataSnapshot)     // required
    .visibility(Visibility::Public)              // defaults to Public
    .description("Quarterly revenue figures aggregated by region.")
    .tags(vec!["finance", "revenue"])
    .domain("finance")
    .summary("Q1 2026 revenue snapshot.")
    .metadata(serde_json::json!({ "currency": "USD" }))
    .build()?;
```

`.build()` performs four steps in order (`crates/acdp-producer/src/builder.rs`):

1. Assemble **ProducerContent** (producer-controlled fields only).
2. Compute `content_hash` = `sha256(JCS(ProducerContent))`.
3. Sign the `content_hash` **string** with the producer's key.
4. Return a wire-ready `PublishRequest` (with `content_hash` + `signature`
   attached).

Before step 2 it runs `validation::validate_publish_request`, so a bad request
fails *locally* with a typed `AcdpError` rather than at the registry. Timestamps
you pass (`expires_at`, `data_period`) are **truncated to milliseconds**
(RFC-ACDP-0001 §5.3) so the canonical form is stable.

### Builder methods

| Method | Field | Required? |
|---|---|---|
| `.title(s)` | title | **yes** (1..=500 chars) |
| `.context_type(t)` | type | **yes** |
| `.visibility(v)` | visibility | defaults to `Public` |
| `.description(s)` / `.summary(s)` | description / summary | optional |
| `.tags(vec)` / `.domain(s)` | tags / domain | optional |
| `.data_refs(vec)` | data_refs | optional — see below |
| `.contributors(vec)` / `.audience(vec)` | contributors / audience | optional |
| `.derived_from(vec)` | derived_from (lineage) | optional |
| `.metadata(json)` | metadata | optional (depth/size capped) |
| `.schema_uri(s)` | schema_uri | optional |
| `.expires_at(dt)` / `.data_period(dp)` | expiry / period | optional |
| `.version(n)` / `.expected_lineage_id(l)` | version / lineage check | **v2+ only** (see [Supersession](#supersession)) |
| `.anchors(vec)` / `.clear_anchors()` | anchors (RFC-ACDP-0016 typed external anchors, 0.5.0 Draft) | optional — an empty `Vec` fails `build()` with `SchemaViolation`, so call `.anchors` only with at least one `AnchorEntry` |
| `.acdp_version(v)` / `.omit_acdp_version()` | acdp_version | emitted as `ACDP_VERSION` by default (see [below](#the-acdp_version-field)) |

## Data references

`DataRef` describes where a context's underlying data lives — by URI, by
embedded blob, or by structured locator. Use the constructors rather than
building the struct by hand; they set the encoding and shape correctly.

```rust
use acdp::types::{DataRef, DataRefType};

// By URI (most common)
DataRef::uri(DataRefType::PrimaryResult, "https://data.example.com/q1.parquet");

// By URI with a pre-known content hash (verified on fetch)
DataRef::uri_verified(DataRefType::PrimaryResult, "https://…", content_hash);

// Embedded inline — pick the encoding that matches your payload
DataRef::embedded_json(DataRefType::PrimaryResult, serde_json::json!({ "rows": 42 }));
DataRef::embedded_utf8(DataRefType::Metadata, "free-form text");
DataRef::embedded_base64(DataRefType::SecondaryData, "SGVsbG8=");
```

Convenience shorthands exist too: `DataRef::primary_result_uri(uri)`,
`raw_data_uri`, `supporting_info_uri`, `derived_data_uri`,
`primary_result_json`, `derived_data_json`.

> **Embedded size cap.** Embedded content is bounded (64 KB — RFC-ACDP-0007
> `limits.max_embedded_bytes`). Oversize embeds fail `build()` with
> `AcdpError::EmbeddedTooLarge`. For large data, reference by URI and set the
> `DataRef`'s `content_hash` (as `uri_verified` does) so a consumer can verify
> the fetched bytes.

### Data-reference hashes

A `DataRef` can carry two hashes, checked in different places:

| Field | Applies to | Checked |
|---|---|---|
| `DataRef.content_hash` (root, RFC-ACDP-0002 §6.1) | `location` (URI) refs | by the consumer after fetching, in `fetch_and_verify_data_ref` |
| `EmbeddedContent.content_hash` (`embedded.content_hash`, RFC-ACDP-0002 §6.3/§6.6) | `embedded` refs: SHA-256 of the decoded `embedded.content` bytes | at validation and publish time by `validation::verify_embedded_hash`, which `build()`, `PublishValidator`, and `VerifiedContext` all run |

A mismatch on either is `AcdpError::DataRefHashMismatch` (wire
`data_ref_hash_mismatch`), not the body-level `HashMismatch`. For an embedded
ref, a root `content_hash` carries no verification obligation and is **not**
checked; the embedded integrity check is `embedded.content_hash` only.
`EmbeddedContent.content_hash` was added in 0.14.0, a breaking change for code
that builds `EmbeddedContent` with a struct literal.

## Supersession

A new version of an existing context *supersedes* the previous one. The
preferred entry point is `supersede_body`, which propagates the version number
and lineage id from the retrieved previous `Body` (RFC-ACDP-0003 §3.1):

```rust
// `previous` is the Body you retrieved for the current version.
let v2 = producer
    .supersede_body(&previous)        // sets supersedes, version+1, expected_lineage_id
    .title(previous.title.clone())
    .context_type(previous.context_type.clone())
    .summary("Updated with corrected April figures.")
    .build()?;
```

| Method | Use when |
|---|---|
| `supersede_body(&prev)` | You have the full previous `Body`. **Recommended** — auto-sets `version`, `supersedes`, and `expected_lineage_id`. |
| `new_version_from(&prev)` | Most fields stay the same; you only change data/summary/metadata. Carries *every* producer field over from `prev`, then you override what changed. |
| `supersede(prev_ctx_id)` | You only have the previous `ctx_id`. You **must** also call `.version(n)` yourself. |

> **v1 vs v2+ rule.** `expected_lineage_id` MUST NOT appear on a v1 publish and
> is required for v2+ self-verification. The builder enforces this — calling
> `.expected_lineage_id(...)` on a v1 request (or omitting `.version()` on a
> manual `supersede`) fails `build()`. Use `supersede_body` and you won't hit
> this.

## Lineage vs. derived-from

Two different relationships, easy to confuse:

- **Lineage** (`supersedes` / `lineage_id`) — *successive versions of the same
  work*. A `lineage_id` is derived from the v1 `ctx_id` and is stable across
  versions.
- **Derived-from** (`.derived_from(vec)`) — *this context was built using those
  other contexts as inputs*. A provenance edge, not a version bump. The
  [`CrossRegistryResolver`](consuming.md#cross-registry-resolution) walks these.

## The `acdp_version` field

Since 0.2.0 the builder **emits `acdp_version` explicitly by default**, set to
`acdp::ACDP_VERSION` (currently `"0.4.0"`). Use `.acdp_version(v)` to pin a
different line. Conformant consumers treat an absent field as `"0.1.0"`
(RFC-ACDP-0001 §6). To reproduce the 0.1.x omitted form, which is what the
`sig-001` golden vector was signed with, opt out:

```rust
builder.omit_acdp_version()   // drops the field, matching the 0.1.x wire form
```

> ⚠️ **The absent and explicit forms produce different `content_hash`
> values** — the JCS byte sequences differ. Pick one convention and keep it
> consistent within a lineage, or supersession self-verification and
> round-trip tests will surprise you. New lineages should keep the explicit
> default.

## What you get back

`build()` returns a `PublishRequest` with `content_hash` and `signature`
populated. Serialize it and POST it:

```rust
let json = serde_json::to_string_pretty(&req)?;   // the publish body
println!("{}", req.content_hash);                 // sha256:<hex>
println!("{} / {}", req.signature.algorithm, req.signature.key_id);
```

To actually publish over HTTP, see
[Consuming & verifying → publishing](consuming.md#publishing-from-the-client) or
the [`acdp publish`](cli.md#publish) CLI command.
