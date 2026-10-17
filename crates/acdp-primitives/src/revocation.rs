//! Attributable revocation verdict vocabulary (RFC-ACDP-0014 §7/§8,
//! 0.5.0 "Attribution" and "Discovery outcome classes").
//!
//! These types live at the bottom of the workspace because
//! [`AcdpError::KeyRevoked`](crate::AcdpError::KeyRevoked) and
//! [`AcdpError::RevocationUnknown`](crate::AcdpError::RevocationUnknown)
//! carry them. `acdp-types` re-exports [`RevocationTrustClass`] from its
//! historical `acdp::types::revocation` path; `acdp-client` builds the
//! rest from verified `KeyRevocation`s.

use crate::primitives::{AgentDid, CtxId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The two trust classes of RFC-ACDP-0014 §5–§6. They carry different
/// authority and MUST be reported distinguishably — never collapsed
/// (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationTrustClass {
    /// Signed by the producer's own current, non-revoked key (§5): the
    /// stronger class, backed by the same trust anchor as every ACDP
    /// body. Consumers act on it without further judgment (§7).
    ProducerSigned,
    /// Published under the registry's identity on the producer's
    /// behalf after an out-of-band identity check (§6): the weaker,
    /// lost-everything fallback. It imports registry trust — a hostile
    /// or deceived registry can fabricate one. Strict-profile default:
    /// apply §7 only for contexts served by or receipted by that same
    /// registry; seek corroboration before applying it globally.
    RegistryAttested,
}

/// Where a consumer obtained a revocation it acted on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RevocationSource {
    /// Supplied by the caller (`RevocationPolicy::known`) — the §8
    /// "out of band" source.
    Known,
    /// Found by this call's §8 discovery at registry `authority`.
    Discovered {
        /// The registry authority discovery queried.
        authority: String,
    },
    /// Read from a `RevocationCache`; first verified at `origin`.
    Cached {
        /// The registry authority whose discovery first verified it.
        origin: String,
    },
}

/// A verified revocation, attributed (RFC-ACDP-0014 §7 "Attribution",
/// 0.5.0): which context it is, who signed it, its trust class, which
/// producer's key it names, and where the consumer got it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SourcedRevocation {
    /// RFC-ACDP-0010 §6 fingerprint of the revoked key.
    pub revoked_key_fingerprint: String,
    /// This revocation's compromise boundary T (the *effective* boundary
    /// across a lineage is [`RevocationRefusal::boundary`]).
    pub compromised_since: DateTime<Utc>,
    /// The revocation context's `ctx_id`, when known. `None` only for a
    /// caller-supplied revocation built from a publish request.
    /// Registry-assigned — identifies, does not authenticate.
    pub ctx_id: Option<CtxId>,
    /// The revocation's signer (`body.agent_id`): the producer for the
    /// producer-signed class, the registry for the registry-attested one.
    pub issuer: AgentDid,
    /// `metadata.revoked_key_controller` (defaults to `issuer`).
    pub revoked_key_controller: AgentDid,
    /// §5/§6 trust class.
    pub trust_class: RevocationTrustClass,
    /// Where the consumer obtained it.
    pub source: RevocationSource,
}

impl SourcedRevocation {
    /// Assemble an attributed revocation. `acdp-client` builds these from
    /// verified `KeyRevocation`s; there is no other sound source.
    #[must_use]
    pub fn new(
        revoked_key_fingerprint: String,
        compromised_since: DateTime<Utc>,
        ctx_id: Option<CtxId>,
        issuer: AgentDid,
        revoked_key_controller: AgentDid,
        trust_class: RevocationTrustClass,
        source: RevocationSource,
    ) -> Self {
        Self {
            revoked_key_fingerprint,
            compromised_since,
            ctx_id,
            issuer,
            revoked_key_controller,
            trust_class,
            source,
        }
    }

    /// Whether this revocation speaks for `producer` (RFC-ACDP-0014 §7
    /// "Producer scope", 0.5.0): producer-signed ⇒ `issuer == producer`;
    /// registry-attested ⇒ `revoked_key_controller == producer` (§6
    /// vantage scoping is applied separately). A revocation outside this
    /// scope MUST NOT change the producer's verdict; it is a hint only.
    #[must_use]
    pub fn speaks_for(&self, producer: &AgentDid) -> bool {
        match self.trust_class {
            RevocationTrustClass::ProducerSigned => self.issuer == *producer,
            RevocationTrustClass::RegistryAttested => self.revoked_key_controller == *producer,
        }
    }
}

/// Which RFC-ACDP-0014 §7 step a revocation verdict came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RevocationEffect {
    /// §7 step 2: placed strictly before T — the context stays
    /// attributable (accepted under the historical rule).
    PreCompromise,
    /// §7 step 3: placed at or after T — final.
    Revoked,
    /// §7 step 4: no verifiable publish time (no verified receipt, or a
    /// receipt under a historical receipt key in the strict profile) —
    /// curable by a receipt.
    Unplaceable,
}

/// The attributed refusal carried by
/// [`AcdpError::KeyRevoked`](crate::AcdpError::KeyRevoked): a verified,
/// in-scope revocation made the context's signing key not authorized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RevocationRefusal {
    /// [`RevocationEffect::Revoked`] or [`RevocationEffect::Unplaceable`].
    pub effect: RevocationEffect,
    /// Fingerprint of the context's signing key.
    pub signing_key_fingerprint: String,
    /// Effective boundary T: the earliest `compromised_since` across
    /// every in-scope revocation naming the key (§4).
    pub boundary: DateTime<Utc>,
    /// The revocation that fixes `boundary`.
    pub revocation: SourcedRevocation,
    /// The receipt-attested publish time compared against `boundary`, if
    /// any.
    pub placement: Option<DateTime<Utc>>,
    /// Human-readable explanation.
    pub detail: String,
}

impl RevocationRefusal {
    /// Assemble a refusal.
    #[must_use]
    pub fn new(
        effect: RevocationEffect,
        signing_key_fingerprint: String,
        boundary: DateTime<Utc>,
        revocation: SourcedRevocation,
        placement: Option<DateTime<Utc>>,
        detail: String,
    ) -> Self {
        Self {
            effect,
            signing_key_fingerprint,
            boundary,
            revocation,
            placement,
            detail,
        }
    }
}

impl std::fmt::Display for RevocationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let effect = match self.effect {
            RevocationEffect::PreCompromise => "pre-compromise",
            RevocationEffect::Revoked => "revoked",
            RevocationEffect::Unplaceable => "unplaceable",
        };
        write!(
            f,
            "{effect}: key {} revoked as of {} by {} ({:?}",
            self.signing_key_fingerprint,
            crate::time::fmt_rfc3339_ms(self.boundary),
            self.revocation.issuer,
            self.revocation.trust_class,
        )?;
        if let Some(ctx) = &self.revocation.ctx_id {
            write!(f, ", {ctx}")?;
        }
        write!(f, "): {}", self.detail)
    }
}

/// Why a revocation-discovery outcome is `unknown` (RFC-ACDP-0014 §8,
/// 0.5.0). `unknown` is never folded into not-revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UnknownReason {
    /// A search or lineage walk was cut short by a page, walk, or budget
    /// cap (§8 "Truncation is not completeness").
    Truncated,
    /// The vantage cannot answer: `not_authorized` (e.g.
    /// `anonymous_public_reads: false`), `not_implemented`, or a
    /// malformed discovery response.
    Unanswerable,
    /// A lookup failed transiently (DID host, registry, transport, or the
    /// discovery deadline).
    Transient,
    /// A candidate could be neither verified nor proven invalid (the §5
    /// step 1 historical arm had no usable receipt).
    UnverifiableCandidate,
}

impl UnknownReason {
    /// The report token (`truncated`, `unanswerable`, `transient`,
    /// `unverifiable_candidate`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            UnknownReason::Truncated => "truncated",
            UnknownReason::Unanswerable => "unanswerable",
            UnknownReason::Transient => "transient",
            UnknownReason::UnverifiableCandidate => "unverifiable_candidate",
        }
    }
}

impl std::fmt::Display for UnknownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
