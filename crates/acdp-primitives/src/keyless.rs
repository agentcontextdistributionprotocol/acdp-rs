//! Keyless-signing reason tokens (RFC-ACDP-0021 §13.3, Final at 0.5.0).
//!
//! RFC-ACDP-0021 adds no wire error code and this library adds no
//! [`AcdpError`] variant for it. A refusal reuses the variant of an
//! existing code, and the reason travels in the message as a stable
//! `keyless:<token>: ` prefix that [`KeylessReason::of`] reads back:
//!
//! - registry refusals: [`AcdpError::from_wire_error`] adds the prefix
//!   when `details.reason` is one of the registry tokens of
//!   `registries/error-codes.md` ("Keyless-signing reason tokens");
//! - consumer refusals (§8.1): the keyless verifier builds its errors
//!   with [`KeylessReason::error`].

use crate::error::AcdpError;
use serde::{Deserialize, Serialize};

/// The prefix that marks a keyless reason in an [`AcdpError`] message.
const PREFIX: &str = "keyless:";

/// Why a keyless step refused: the registry `details.reason` tokens
/// (§5.2, §6.3, §7) and the consumer verification results (§8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KeylessReason {
    /// §5.2 step 2: the token's issuer (or SPIFFE trust domain) is not
    /// accepted by the registry.
    IssuerNotAccepted,
    /// §5.2 step 3: the token fails verification.
    TokenInvalid,
    /// §5.2 step 3: the token's `aud` lacks the registry's DID.
    AudienceMismatch,
    /// §5.2 step 3: `cnf.jkt` is not the presented key's thumbprint.
    ConfirmationMismatch,
    /// §5.2 step 3: the token was already used.
    TokenReplayed,
    /// §5.2 step 6, §6.3 step 7: the controller does not list the
    /// identity.
    IdentityNotAuthorized,
    /// §5.2 step 4: the proof of possession does not verify.
    PopInvalid,
    /// §6.3 step 1: a keyless key id with no `key_attestation`.
    AttestationMissing,
    /// §6.3 step 2: the attestation is on another registry.
    AttestationForeign,
    /// §6.3 step 3: no attestation at `key_attestation.ctx_id`.
    AttestationNotFound,
    /// §6.3 steps 3–4, §8.1 step 3: the attestation's bytes or bindings
    /// differ.
    AttestationMismatch,
    /// §6.3 step 5, §8.1 step 7: the attestation was retracted.
    AttestationWithdrawn,
    /// §6.3 step 6, §8.1 step 5: the placing time is outside the window.
    OutsideAttestationWindow,
    /// §7: the successor's identity may not supersede the predecessor.
    KeylessIdentityMismatch,
    /// §8.1 step 1: the attestation does not verify or breaks §5.3.
    AttestationInvalid,
    /// §8.1 step 2: the consumer does not accept the attesting registry.
    UntrustedAttester,
    /// §8.1 step 4: no receipt by the attester places the signature.
    Unplaceable,
    /// §8.1 step 6: the signature does not verify under the attested key.
    InvalidSignature,
    /// §8.1 step 8: a revocation of the attested key applies.
    Revoked,
    /// §8.1 step 9: the controller's DID document could not be fetched.
    ControllerUnreachable,
    // New tokens go last, so existing discriminants never move.
    /// §5.2 step 3: the issuer's published keys (OIDC JWKS or SPIFFE
    /// bundle) could not be fetched. Transient: the wire code is
    /// `key_resolution_unreachable`, so the client may retry.
    IssuerUnreachable,
    /// §6.3: a lifecycle event signed with a keyless key id; keyless
    /// keys do not sign events in this version.
    KeylessEventUnsupported,
}

impl KeylessReason {
    /// Every reason, in declaration order. A slice, so a new spec token
    /// is an additive change.
    pub const ALL: &'static [KeylessReason] = &[
        Self::IssuerNotAccepted,
        Self::TokenInvalid,
        Self::AudienceMismatch,
        Self::ConfirmationMismatch,
        Self::TokenReplayed,
        Self::IdentityNotAuthorized,
        Self::PopInvalid,
        Self::AttestationMissing,
        Self::AttestationForeign,
        Self::AttestationNotFound,
        Self::AttestationMismatch,
        Self::AttestationWithdrawn,
        Self::OutsideAttestationWindow,
        Self::KeylessIdentityMismatch,
        Self::AttestationInvalid,
        Self::UntrustedAttester,
        Self::Unplaceable,
        Self::InvalidSignature,
        Self::Revoked,
        Self::ControllerUnreachable,
        Self::IssuerUnreachable,
        Self::KeylessEventUnsupported,
    ];

    /// The token as written on the wire and in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IssuerNotAccepted => "issuer_not_accepted",
            Self::TokenInvalid => "token_invalid",
            Self::IssuerUnreachable => "issuer_unreachable",
            Self::AudienceMismatch => "audience_mismatch",
            Self::ConfirmationMismatch => "confirmation_mismatch",
            Self::TokenReplayed => "token_replayed",
            Self::IdentityNotAuthorized => "identity_not_authorized",
            Self::PopInvalid => "pop_invalid",
            Self::AttestationMissing => "attestation_missing",
            Self::KeylessEventUnsupported => "keyless_event_unsupported",
            Self::AttestationForeign => "attestation_foreign",
            Self::AttestationNotFound => "attestation_not_found",
            Self::AttestationMismatch => "attestation_mismatch",
            Self::AttestationWithdrawn => "attestation_withdrawn",
            Self::OutsideAttestationWindow => "outside_attestation_window",
            Self::KeylessIdentityMismatch => "keyless_identity_mismatch",
            Self::AttestationInvalid => "attestation_invalid",
            Self::UntrustedAttester => "untrusted_attester",
            Self::Unplaceable => "unplaceable",
            Self::InvalidSignature => "invalid_signature",
            Self::Revoked => "revoked",
            Self::ControllerUnreachable => "controller_unreachable",
        }
    }

    /// Parse a token.
    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|r| r.as_str() == token)
    }

    /// True for the tokens `registries/error-codes.md` lists as registry
    /// `details.reason` values (the rest are consumer results, §13.3).
    pub fn is_registry_token(self) -> bool {
        !matches!(
            self,
            Self::AttestationInvalid
                | Self::UntrustedAttester
                | Self::Unplaceable
                | Self::InvalidSignature
                | Self::Revoked
                | Self::ControllerUnreachable
        )
    }

    /// `message` with this reason's prefix.
    pub fn tag(self, message: impl std::fmt::Display) -> String {
        format!("{PREFIX}{}: {message}", self.as_str())
    }

    /// The consumer-side error for this reason (§8.1, §8.2): the
    /// existing variant whose meaning fits, with the reason prefix.
    /// `controller_unreachable` and `issuer_unreachable` are the
    /// transient refusals.
    pub fn error(self, message: impl std::fmt::Display) -> AcdpError {
        let msg = self.tag(message);
        match self {
            Self::InvalidSignature | Self::PopInvalid => AcdpError::InvalidSignature(msg),
            Self::ControllerUnreachable | Self::IssuerUnreachable => {
                AcdpError::KeyResolutionUnreachable(msg)
            }
            Self::AttestationInvalid
            | Self::AttestationMissing
            | Self::KeylessEventUnsupported
            | Self::AttestationForeign
            | Self::AttestationNotFound => AcdpError::KeyResolution(msg),
            Self::KeylessIdentityMismatch => AcdpError::NotAuthorized(msg),
            _ => AcdpError::KeyNotAuthorized(msg),
        }
    }

    /// The keyless reason an error carries, if any. A
    /// [`AcdpError::KeyRevoked`] reads as [`Self::Revoked`]: keyless
    /// verification refuses a revoked key with that typed error.
    pub fn of(error: &AcdpError) -> Option<Self> {
        let msg = match error {
            // §8.1 step 8 keeps the typed revocation refusal.
            AcdpError::KeyRevoked(_) => return Some(Self::Revoked),
            AcdpError::InvalidSignature(m)
            | AcdpError::KeyResolution(m)
            | AcdpError::KeyResolutionUnreachable(m)
            | AcdpError::KeyNotAuthorized(m)
            | AcdpError::NotAuthorized(m)
            | AcdpError::SchemaViolation(m) => m,
            _ => return None,
        };
        let (token, _) = msg.strip_prefix(PREFIX)?.split_once(": ")?;
        Self::parse(token)
    }
}

impl std::fmt::Display for KeylessReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_round_trip_and_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for &r in KeylessReason::ALL {
            assert!(seen.insert(r.as_str()), "duplicate token {r}");
            assert_eq!(KeylessReason::parse(r.as_str()), Some(r));
            let json = serde_json::to_value(r).unwrap();
            assert_eq!(json, r.as_str());
            assert_eq!(KeylessReason::of(&r.error("x")), Some(r));
        }
    }

    #[test]
    fn untagged_errors_carry_no_reason() {
        assert_eq!(
            KeylessReason::of(&AcdpError::KeyNotAuthorized("plain".into())),
            None
        );
        assert_eq!(
            KeylessReason::of(&AcdpError::KeyNotAuthorized("keyless:nope: x".into())),
            None
        );
    }
}
