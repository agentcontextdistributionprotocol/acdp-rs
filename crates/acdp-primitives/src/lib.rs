//! # acdp-primitives — foundational types for the Agent Context Distribution Protocol
//!
//! The bottom layer of the `acdp` crate family: the typed error
//! vocabulary ([`error::AcdpError`]), the opaque identifier/enum
//! primitives ([`primitives`]), the wire error envelope (`WireError`,
//! whose canonical public path is `acdp::types::WireError`), and small
//! shared utilities (`limits`, `time`, `serde_helpers`). It has no
//! cryptography and makes no network calls.
//!
//! Most users should depend on the umbrella [`acdp`](https://docs.rs/acdp)
//! crate, which re-exports everything here.

pub mod error;
pub mod limits;
pub mod primitives;
pub mod revocation;
pub mod serde_helpers;
pub mod time;
// The `WireError` envelope is *defined* here (down in `acdp-primitives`
// to break the historical error↔types dependency cycle), but its
// canonical public path is `acdp::types::WireError` / `WireErrorBody`.
// The module and the direct re-export below stay `pub` only for
// intra-workspace back-compat (`acdp-types` re-exports from here); they
// are `#[doc(hidden)]` so downstream users are steered to the single
// canonical path.
#[doc(hidden)]
pub mod wire_error;

pub use error::{AcdpError, SupersessionReason};
pub use primitives::{AgentDid, ContentHash, ContextType, CtxId, LineageId, Status, Visibility};
#[doc(hidden)]
pub use revocation::{
    RevocationEffect, RevocationRefusal, RevocationSource, RevocationTrustClass, SourcedRevocation,
    UnknownReason,
};
pub use wire_error::{WireError, WireErrorBody};

// ── Protocol version ──────────────────────────────────────────────────────────

/// The ACDP protocol version this library implements by default.
///
/// This is the newest **Final** wire-format line: 0.2.0 (Trust &
/// Hardening — registry receipts, RFC-ACDP-0010), 0.3.0 (lineage-head
/// receipts, transparency log, lifecycle/retraction, key revocation —
/// RFC-ACDP-0011..0014), and 0.4.0 (witness cosigning, RFC-ACDP-0015,
/// promoted to Final 2026-08). Every v0.1.0 body, signature, and
/// `content_hash` remains valid — bumping this constant only changes
/// what a producer stamps by *default* going forward; it is not a
/// breaking change to anything already published. An absent
/// `acdp_version` field on a publish request is interpreted as `0.1.0`
/// by the protocol; 0.2.0+ builders MUST emit the field explicitly
/// (RFC-ACDP-0001 §6). Callers that need an older explicit line (e.g. to
/// stay under a registry that hasn't adopted 0.4.0 yet) should set it
/// explicitly via `RequestBuilder::acdp_version` (in `acdp-producer`)
/// rather than relying on the default.
pub const ACDP_VERSION: &str = "0.4.0";

/// The JSON Schema namespace (`$id` prefix) for this protocol version,
/// e.g. `<ACDP_SCHEMA_NAMESPACE>/acdp-error.schema.json`.
pub const ACDP_SCHEMA_NAMESPACE: &str = "https://schemas.acdp.io/v0.1.0";
