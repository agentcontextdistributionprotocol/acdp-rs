//! The verdict object, `acdp-chain-verdict/1` (RFC-ACDP-0017 §9).
//!
//! Closed at every level, as `acdp-chain-verdict.schema.json` is: the
//! types emit exactly the schema's members, members that do not apply
//! are omitted rather than `null`, and the verdict's JCS bytes are what
//! the two digests cover (§9.2, §9.3).

use serde::{Deserialize, Serialize};

use crate::options::Limits;

/// The `verdict_version` literal.
pub const VERDICT_VERSION: &str = "acdp-chain-verdict/1";

/// A node or chain verdict, ordered worst-last: `Ok < OkWithCaveats <
/// Unknown < Refused` (§8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every stage passed with no caveat.
    Ok,
    /// Passed, with the listed caveats.
    OkWithCaveats,
    /// Something could not be established.
    Unknown,
    /// Something failed.
    Refused,
}

/// What a stage result rests on, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    /// Arithmetic over the bundle itself (hashes, did:key).
    #[serde(rename = "self")]
    SelfEvident,
    /// Vouched for by the caller (§6.3).
    Pinned,
    /// Signed by a registry.
    Registry,
    /// Asserted by whoever built the bundle.
    Observed,
}

/// A §8.1 caveat token. Declared in byte order, so the derived `Ord`
/// sorts as §8.1 requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Caveat {
    /// `key: historical_receipt_attested`.
    HistoricalKey,
    /// `registry_receipt.key_status: historical`.
    HistoricalReceiptKey,
    /// `identity: unbound`.
    IdentityUnbound,
    /// `log: cannot_verify`.
    LogCannotVerify,
    /// A stage rests on basis `observed`.
    ObservedBasis,
    /// `key_revocation: pre-compromise`.
    PreCompromise,
    /// `retraction: retracted`.
    Retracted,
    /// Present as of T with no evidence time.
    Undated,
}

/// The `limits` echo.
pub type VerdictLimits = Limits;

/// The walk control that fired first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Control {
    /// `max_depth`.
    MaxDepth,
    /// `max_nodes`.
    MaxNodes,
    /// `max_fanout`.
    MaxFanout,
    /// The caller's time budget (exempt from determinism, §6.1(5)).
    Timeout,
}

/// An `acdp-chain-verdict/1` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ChainVerdict {
    /// Always [`VERDICT_VERSION`].
    pub verdict_version: String,
    /// Sorted, deduplicated.
    pub roots: Vec<String>,
    /// T, or `null`.
    pub as_of: Option<String>,
    /// The greatest evidence time in the bundle (§5.4), or `null`.
    pub horizon: Option<String>,
    /// The limits the walk ran under.
    pub limits: Limits,
    /// §6.4.
    pub require_attested_events: bool,
    /// Digest of the normalized `pinned`, or `null`.
    pub options_digest: Option<String>,
    /// Digest of the bundle.
    pub evidence_digest: String,
    /// False when a control fired.
    pub complete: bool,
    /// The first control that fired.
    pub control: Option<Control>,
    /// Referenced but not admitted, sorted.
    pub frontier: Vec<String>,
    /// Sorted by `ctx_id`.
    pub nodes: Vec<Node>,
    /// Chain verdicts.
    pub chain: ChainVerdicts,
    /// Tainted paths per pass.
    pub tainted_paths: TaintedPaths,
    /// Sorted by `ctx_id`, then `kind`.
    pub drift: Vec<Drift>,
    /// The value to seal at T, or `null`.
    pub as_of_digest: Option<String>,
    /// Digest of the whole verdict.
    pub verdict_digest: String,
}

impl ChainVerdict {
    /// The verdict as JSON.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("verdict serializes")
    }

    /// The verdict's JCS bytes, the form §9.3 requires to be identical
    /// across implementations.
    pub fn to_jcs(&self) -> Vec<u8> {
        acdp_jcs::canonicalize(self).expect("verdict canonicalizes")
    }
}

/// One node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Node {
    /// The node.
    pub ctx_id: String,
    /// Shortest distance from a root.
    pub depth: u32,
    /// As in the body, in body order; omitted when the node is not
    /// present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<Vec<String>>,
    /// The as-of pass, or `null`.
    pub as_of: Option<Pass>,
    /// The latest pass.
    pub latest: Pass,
}

/// One pass over one node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Pass {
    /// §8.1.
    pub verdict: Verdict,
    /// Sorted.
    pub caveats: Vec<Caveat>,
    /// §7, in stage order.
    pub stages: Stages,
}

/// The §7 stages. Only `presence` is always present; the others are
/// omitted for a node that is not present.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Stages {
    /// §7.1.
    pub presence: Presence,
    /// §7.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    /// §7.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<ContentHashStage>,
    /// §7.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureStage>,
    /// §7.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_receipt: Option<ReceiptStage>,
    /// §7.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyStage>,
    /// §7.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<LogStage>,
    /// §7.8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retraction: Option<RetractionStage>,
    /// §7.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_revocation: Option<KeyRevocationStage>,
}

macro_rules! value_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $variant:ident = $wire:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub enum $name {
            $($(#[$vm])* #[serde(rename = $wire)] $variant),+
        }
    };
}

value_enum!(
    /// §7.1 values.
    PresenceValue {
        /// Carried by the bundle and in existence at T (or undated).
        Present = "present",
        /// Left out by the exporter's policy.
        Withheld = "withheld",
        /// The exporter could not fetch it.
        Unresolved = "unresolved",
        /// Neither carried nor listed in `omitted`.
        Absent = "absent",
        /// Reserved by the schema.
        Truncated = "truncated",
        /// On a `derived_from` cycle.
        Cycle = "cycle",
        /// Receipted after T.
        NotYetPublished = "not_yet_published",
    }
);

value_enum!(
    /// §7.2 values.
    IdentityValue { Ok = "ok", Unbound = "unbound", Mismatch = "mismatch" }
);

value_enum!(
    /// §7.3 values.
    ContentHashValue { Ok = "ok", Mismatch = "mismatch" }
);

value_enum!(
    /// §7.4 values.
    SignatureValue { Ok = "ok", Invalid = "invalid", Unresolvable = "unresolvable" }
);

value_enum!(
    /// §7.5 values.
    ReceiptValue { Absent = "absent", Ok = "ok", Invalid = "invalid" }
);

value_enum!(
    /// §7.5 `key_status`.
    KeyStatus { Current = "current", Historical = "historical" }
);

value_enum!(
    /// §7.6 values.
    KeyValue {
        Current = "current",
        HistoricalReceiptAttested = "historical_receipt_attested",
        Revoked = "revoked",
        Unplaceable = "unplaceable",
        Unresolvable = "unresolvable",
        Unknown = "unknown",
    }
);

value_enum!(
    /// §7.7 values.
    LogValue {
        Absent = "absent",
        Included = "included",
        CannotVerify = "cannot_verify",
        Invalid = "invalid",
    }
);

value_enum!(
    /// §7.8 values.
    RetractionValue {
        NotRetracted = "not_retracted",
        Retracted = "retracted",
        Invalid = "invalid",
        Unknown = "unknown",
    }
);

value_enum!(
    /// §7.9 values.
    KeyRevocationValue {
        NotRevoked = "not-revoked",
        PreCompromise = "pre-compromise",
        Revoked = "revoked",
        Unplaceable = "unplaceable",
        Unknown = "unknown",
    }
);

/// The one `reason` token this implementation emits (§6.2, §7.6).
pub const REASON_NO_EVIDENCE_AT_AS_OF: &str = "no_evidence_at_as_of";

/// §7.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Presence {
    /// The value.
    pub value: PresenceValue,
    /// The receipt's `created_at`, when one verifies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_time: Option<String>,
    /// The receipt's basis, when one verifies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<Basis>,
}

impl Default for Presence {
    fn default() -> Self {
        Self {
            value: PresenceValue::Absent,
            evidence_time: None,
            basis: None,
        }
    }
}

/// §7.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Identity {
    /// The value.
    pub value: IdentityValue,
    /// The basis of a bound identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<Basis>,
    /// A reason token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// §7.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ContentHashStage {
    /// The value.
    pub value: ContentHashValue,
    /// Always `self`.
    pub basis: Basis,
}

/// §7.4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SignatureStage {
    /// The value.
    pub value: SignatureValue,
    /// The basis of the key it was checked under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<Basis>,
}

/// §7.5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ReceiptStage {
    /// The value.
    pub value: ReceiptValue,
    /// On `ok`: whether the receipt key is in `assertionMethod`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_status: Option<KeyStatus>,
    /// On `ok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<Basis>,
    /// On `ok`: `created_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_time: Option<String>,
    /// A reason token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// §7.6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct KeyStage {
    /// The value.
    pub value: KeyValue,
    /// What the key decision rests on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<Basis>,
    /// The deciding evidence's time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_time: Option<String>,
    /// A reason token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// §7.7.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct LogStage {
    /// The value.
    pub value: LogValue,
    /// On `included`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_size: Option<u64>,
    /// On `included`: the checkpoint's `timestamp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_time: Option<String>,
    /// On `included`: distinct pinned witnesses whose cosignatures verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witnesses: Option<u64>,
    /// On `included`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<Basis>,
    /// A reason token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// §7.8.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RetractionStage {
    /// The value.
    pub value: RetractionValue,
    /// The length of the admitted prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_admitted: Option<u64>,
    /// The weakest basis among admitted events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<Basis>,
    /// The greatest `accepted_at` among admitted receipted events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_time: Option<String>,
    /// A reason token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// §7.9.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct KeyRevocationStage {
    /// The value.
    pub value: KeyRevocationValue,
    /// The revocation that decided it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_ctx_id: Option<String>,
    /// `registry` (a revocation decided) or `observed`/`pinned` (a
    /// discovery record decided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<Basis>,
    /// The deciding evidence's time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_time: Option<String>,
    /// A reason token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `chain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ChainVerdicts {
    /// The as-of chain verdict, or `null`.
    pub as_of: Option<Verdict>,
    /// The latest chain verdict.
    pub latest: Verdict,
}

/// `tainted_paths`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TaintedPaths {
    /// As-of paths, or `null`.
    pub as_of: Option<Vec<Vec<String>>>,
    /// Latest paths.
    pub latest: Vec<Vec<String>>,
}

/// A §8.4 drift kind, declared in byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    /// A stage was unknown as of T for want of evidence, decided latest.
    AsOfUnprovable,
    /// An event occurred ≤ T but was accepted > T.
    BackdatedEvent,
    /// Receipted after T.
    PublishedAfterAsOf,
    /// Republished only in the latest pass.
    RepublishedAfterAsOf,
    /// Retracted only in the latest pass.
    RetractedAfterAsOf,
    /// Revoked or unplaceable only in the latest pass.
    RevokedAfterAsOf,
    /// The verdict changed and no other kind holds.
    VerdictChanged,
}

/// A drift entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Drift {
    /// The node.
    pub ctx_id: String,
    /// What changed.
    pub kind: DriftKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_orders_match_wire_byte_order() {
        let caveats = [
            Caveat::HistoricalKey,
            Caveat::HistoricalReceiptKey,
            Caveat::IdentityUnbound,
            Caveat::LogCannotVerify,
            Caveat::ObservedBasis,
            Caveat::PreCompromise,
            Caveat::Retracted,
            Caveat::Undated,
        ];
        let wire: Vec<String> = caveats
            .iter()
            .map(|c| {
                serde_json::to_value(c)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        let mut sorted = wire.clone();
        sorted.sort();
        assert_eq!(wire, sorted);

        let kinds = [
            DriftKind::AsOfUnprovable,
            DriftKind::BackdatedEvent,
            DriftKind::PublishedAfterAsOf,
            DriftKind::RepublishedAfterAsOf,
            DriftKind::RetractedAfterAsOf,
            DriftKind::RevokedAfterAsOf,
            DriftKind::VerdictChanged,
        ];
        let wire: Vec<String> = kinds
            .iter()
            .map(|c| {
                serde_json::to_value(c)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        let mut sorted = wire.clone();
        sorted.sort();
        assert_eq!(wire, sorted);
    }
}
