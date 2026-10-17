//! Consumer binding of the registry-assigned `lineage_id` and
//! `origin_registry` (RFC-ACDP-0004 §2.1 / RFC-ACDP-0002 §4.2, 0.5.0).
//!
//! Both fields sit in the RFC-ACDP-0001 §5.7 exclusion set, so neither
//! the producer signature nor `content_hash` covers them. Without a
//! receipt, nothing else binds them — the same gap the `ctx_id`
//! identity binding (RFC-ACDP-0006 §4.1 step 7) closes for `ctx_id`.

use acdp_crypto::hash::derive_lineage_id;
use acdp_primitives::error::AcdpError;
use acdp_types::body::Body;
use serde::{Deserialize, Serialize};

/// How a verified body's `lineage_id` is bound to its lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LineageBinding {
    /// First version (`supersedes: null`): `lineage_id` equals the
    /// RFC-ACDP-0001 §5.6 derivation from `ctx_id`, checked offline.
    Derived,
    /// Later version whose `lineage_id` is attested by a verified
    /// registry receipt (RFC-ACDP-0010 §8 step 3).
    ReceiptAttested,
    /// Later version with no verified receipt: `lineage_id` is
    /// registry-asserted only.
    Unbound,
}

/// Enforce the offline registry-assigned bindings on a retrieved body:
///
/// 1. For a first version (`supersedes: null`), `lineage_id` MUST equal
///    the RFC-ACDP-0001 §5.6 derivation from `ctx_id`.
/// 2. `origin_registry` MUST equal the `ctx_id` authority (the RFC's
///    SHOULD for consumers that rely on `origin_registry`; this crate
///    exposes the field, so it always checks).
///
/// Either mismatch is [`AcdpError::SchemaViolation`].
pub fn verify_registry_assigned_bindings(body: &Body) -> Result<(), AcdpError> {
    if body.supersedes.is_none() {
        let derived = derive_lineage_id(&body.ctx_id);
        if body.lineage_id != derived {
            return Err(AcdpError::SchemaViolation(format!(
                "lineage_id '{}' is not the RFC-ACDP-0001 §5.6 derivation '{}' of first-version \
                 ctx_id '{}' (RFC-ACDP-0004 §2.1)",
                body.lineage_id.as_str(),
                derived.as_str(),
                body.ctx_id.as_str(),
            )));
        }
    }
    let authority = body.ctx_id.authority();
    if body.origin_registry != authority {
        return Err(AcdpError::SchemaViolation(format!(
            "origin_registry '{}' does not equal the ctx_id authority '{authority}' \
             (RFC-ACDP-0004 §2.1)",
            body.origin_registry
        )));
    }
    Ok(())
}

/// Classify how `body.lineage_id` is bound, given whether a receipt
/// for it was verified. Call after [`verify_registry_assigned_bindings`].
pub fn lineage_binding(body: &Body, receipt_verified: bool) -> LineageBinding {
    if body.supersedes.is_none() {
        LineageBinding::Derived
    } else if receipt_verified {
        LineageBinding::ReceiptAttested
    } else {
        LineageBinding::Unbound
    }
}
