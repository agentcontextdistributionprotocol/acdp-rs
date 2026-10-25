//! The one error type: inputs `verify_chain` refuses to judge.
//!
//! A verdict is never an error. Failed checks inside a well-formed
//! bundle are reported as stage values in the verdict; only a malformed
//! bundle (RFC-ACDP-0017 §4.1) or out-of-range options (§6.1(4), §6.3)
//! stop the run, and then no partial verdict is emitted.

/// Why `verify_chain` emitted no verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// The bundle fails `acdp-evidence.schema.json` and is rejected
    /// whole (RFC-ACDP-0017 §4.1). Examples: an unknown top-level member
    /// not starting with `_`, a `did:key` DID in `did_documents`, a
    /// malformed receipt, a non-canonical timestamp.
    #[error("invalid evidence bundle: {0}")]
    InvalidEvidence(String),
    /// The options are out of range: a limit above its RFC-ACDP-0006
    /// default or below the schema minimum (§6.1(4)), a `pinned` object
    /// failing `#/$defs/pinned` (§6.3), a non-millisecond `as_of`, or no
    /// roots.
    #[error("invalid verify_chain options: {0}")]
    InvalidOptions(String),
}

pub(crate) fn evidence(msg: impl Into<String>) -> ChainError {
    ChainError::InvalidEvidence(msg.into())
}

pub(crate) fn options(msg: impl Into<String>) -> ChainError {
    ChainError::InvalidOptions(msg.into())
}
