//! # acdp — Rust library for the Agent Context Distribution Protocol
//!
//! Reference implementation of **ACDP v0.1.0 Final** (promoted 2026-05-19),
//! the **v0.2.0 Trust & Hardening** layer, **v0.3.0**, and **v0.4.0**
//! ([`ACDP_VERSION`] is `0.4.0`) — all wire-frozen Final lines. Covers
//! RFC-ACDP-0001 through 0015 (0009 reserved): the core protocol,
//! registry receipts (0010), lineage-head receipts (0011), the
//! transparency log (0012), lifecycle/retraction (0013), key revocation
//! (0014), and witness cosigning (0015, promoted to Final 2026-08).
//!
//! ACDP lets agents publish immutable, producer-signed context descriptors,
//! retrieve and verify them locally, discover them by keyword, and follow
//! signed references across registries. This crate is the facade over a
//! workspace of fine-grained crates under `crates/`; see the repository
//! README for the layout.
//!
//! ## Quick start — producer
//!
//! ```rust,no_run
//! # use acdp::{producer::Producer, crypto::SigningKey,
//! #            types::{AgentDid, ContextType, Visibility}};
//! // In production, load from secure storage; `generate` uses OsRng.
//! let key  = SigningKey::generate();
//! let prod = Producer::new(
//!     key,
//!     AgentDid::new("did:web:agents.example.com:my-agent"),
//!     "did:web:agents.example.com:my-agent#key-1",
//! );
//!
//! let req = prod.publish_request()
//!     .title("Q1 snapshot")
//!     .context_type(ContextType::DataSnapshot)
//!     .visibility(Visibility::Public)
//!     .build()
//!     .unwrap();
//!
//! println!("content_hash: {}", req.content_hash);
//! ```
//!
//! ## Quick start — consumer (feature = "client")
//!
//! ```rust,no_run
//! # #[cfg(feature = "client")]
//! # async fn example() -> Result<(), acdp::error::AcdpError> {
//! use acdp::{client::{RegistryClient, VerifiedContext}, did::WebResolver, types::CtxId};
//!
//! let client   = RegistryClient::new("https://registry.example.com")?;
//! let resolver = WebResolver::new();
//! let ctx_id   = CtxId::parse("acdp://registry.example.com/a1b2c3d4-e5f6-4789-8abc-def012345678")?;
//! let ctx      = VerifiedContext::fetch(&client, &resolver, &ctx_id).await?;
//! println!("title: {}", ctx.body().title);
//! # Ok(())
//! # }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

// Wire types and the profile vocabulary now live in the `acdp-types`
// crate; re-export under the historical `acdp::types` / `acdp::profile`
// paths.
pub use acdp_types as types;
pub use acdp_types::profile;

// Validation, high-level verification, and the producer builder are now
// their own crates; re-export under their historical module paths.
pub use acdp_producer as producer;
pub use acdp_validation as validation;
pub use acdp_verify as verify;

/// Cryptographic primitives — re-exports the `acdp-crypto` crate plus the
/// high-level verification helpers (which live in [`crate::verify`], one
/// layer up) under their historical `crate::crypto::*` paths.
pub mod crypto {
    pub use acdp_crypto::*;

    /// Preserves the historical `acdp::crypto::verify` module path, merging
    /// the byte-level verifiers (`acdp-crypto`) with the high-level,
    /// resolver-backed pipeline (`acdp-verify`). Shadows the byte-level
    /// `verify` module brought in by the glob above.
    pub mod verify {
        pub use acdp_crypto::verify::*;
        pub use acdp_verify::*;
    }

    #[cfg(feature = "client")]
    pub use crate::verify::verify_publish_request_signature;
    pub use crate::verify::{
        verify_body_offline, verify_did_key_envelope, verify_publish_request_signature_offline,
    };
}

// DID resolution now lives in the `acdp-did` crate.
pub use acdp_did as did;

// Foundational layer now lives in the `acdp-primitives` crate; re-export
// it under the historical module paths so `acdp::error`, `acdp::limits`,
// and `acdp::time` are unchanged for downstream users.
pub use acdp_primitives::{error, limits, time};

// SSRF defenses moved to the `acdp-safe-http` crate; re-export under the
// historical `acdp::safe_http` path.
pub use acdp_safe_http as safe_http;

// Consumer client and registry/server building blocks are their own
// crates; re-export under the historical `acdp::client` / `acdp::registry`
// / `acdp::pagination` paths.
#[cfg(feature = "client")]
pub use acdp_client as client;

#[cfg(feature = "server")]
pub use acdp_server::{pagination, registry};

// ── Protocol version ──────────────────────────────────────────────────────────
// Defined in `acdp-primitives`; re-exported here for the historical paths.
pub use acdp_primitives::{ACDP_SCHEMA_NAMESPACE, ACDP_VERSION};

// ── Convenience re-exports ────────────────────────────────────────────────────
pub use error::{AcdpError, SupersessionReason};
pub use types::{
    AgentDid, AnchorEntry, Body, CapabilitiesDocument, ContentHash, ContextType, CtxId, DataRef,
    DataRefType, FullContext, KeyRevocation, LifecycleEvent, LifecycleEventType, LineageId,
    Location, LogCheckpoint, LogConsistencyProof, LogCosignature, LogInclusion, LogLeaf,
    PublishRequest, PublishResponse, RegistryState, RevocationTrustClass, SearchParams,
    SearchResponse, Status, Visibility, WireError, WitnessSigner, WitnessedCheckpoint,
};

// ── Guide doctests ────────────────────────────────────────────────────────────
// Compiles (and, unless fenced `no_run`/`ignore`, runs) the Rust snippets in
// README.md and docs/*.md under `cargo test --doc`, so guide examples cannot
// silently rot (issue #324). Only built for doctests; never public API.
// A guide that is wholly about one feature is gated on it here; mixed
// guides gate individual snippets with a hidden `# #[cfg(feature = ...)]`.
#[cfg(doctest)]
mod doc_guides {
    #[doc = include_str!("../README.md")]
    struct Readme;
    #[doc = include_str!("../docs/getting-started.md")]
    struct GettingStarted;
    #[doc = include_str!("../docs/producing.md")]
    struct Producing;
    #[cfg(feature = "client")]
    #[doc = include_str!("../docs/consuming.md")]
    struct Consuming;
    #[doc = include_str!("../docs/registry.md")]
    struct Registry;
    #[doc = include_str!("../docs/errors.md")]
    struct Errors;
}
