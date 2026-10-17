//! The shared `AcdpError` → JS error mapping for the ACDP 0.3.0
//! surface.
//!
//! Mirrors the `AcdpSsrfPolicy` / `AcdpDidDocument` convention: thrown
//! errors carry a stable snake_case reason on the JS `.code` property,
//! so host code can branch on the *kind* of failure without parsing
//! message strings. The three 0.3.0 wire codes get their own codes —
//! `invalid_log_proof`, `immutable_field`,
//! `invalid_lifecycle_transition` — the same taxonomy the Python
//! binding exposes as the typed `InvalidLogProof` / `ImmutableField` /
//! `InvalidLifecycleTransition` exception classes.

use acdp::error::AcdpError;
use napi::bindgen_prelude::*;

/// Map a core [`AcdpError`] to a JS `Error` whose `.code` is the
/// RFC-ACDP-0007 §5 wire-code taxonomy string.
pub(crate) fn map_acdp_err(e: AcdpError) -> Error<String> {
    let code = match &e {
        AcdpError::InvalidLogProof(_) => "invalid_log_proof",
        AcdpError::InvalidWitnessCosignature(_) => "invalid_witness_cosignature",
        AcdpError::ImmutableField(_) => "immutable_field",
        AcdpError::InvalidLifecycleTransition(_) => "invalid_lifecycle_transition",
        AcdpError::InvalidReceipt(_) => "invalid_receipt",
        AcdpError::InvalidSignature(_) => "invalid_signature",
        AcdpError::KeyNotAuthorized(_) => "key_not_authorized",
        AcdpError::KeyRevoked(_) => "key_not_authorized",
        // Not a wire code: discovery could not establish revocation status.
        AcdpError::RevocationUnknown { .. } => "revocation_unknown",
        AcdpError::KeyResolution(_) => "key_resolution",
        AcdpError::UnsupportedAlgorithm(_) => "unsupported_algorithm",
        AcdpError::SchemaViolation(_) => "schema_violation",
        _ => "acdp_error",
    };
    Error::new(code.to_string(), e.to_string())
}

/// A plain input-shape error (bad JSON argument, missing required
/// expected-field) with the stable `invalid_input` code.
pub(crate) fn input_err(detail: impl Into<String>) -> Error<String> {
    Error::new("invalid_input".to_string(), detail.into())
}
