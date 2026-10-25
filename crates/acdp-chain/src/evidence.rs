//! The evidence bundle, `acdp-evidence/1` (RFC-ACDP-0017 §4).
//!
//! The bundle is unsigned and untrusted. These types only carry it:
//! nothing in a bundle is believed because it is present, and every
//! stage re-derives its result from content. Signed sub-objects (bodies,
//! receipts, events, checkpoints) are held as raw JSON so that hashes
//! and signatures are always recomputed over the bytes as received.
//!
//! Parsing is closed at every level. [`Evidence::from_value`] rejects the
//! whole bundle on any schema failure (§4.1); there is no partial parse.

use std::collections::BTreeMap;

use acdp_types::body::Body;
use acdp_types::cosignature::LogCosignature;
use acdp_types::event_receipt::EventReceipt;
use acdp_types::lifecycle::LifecycleEvent;
use acdp_types::log::{LogCheckpoint, LogInclusion};
use acdp_types::receipt::RegistryReceipt;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{evidence, ChainError};
use crate::syntax::{is_ctx_id, is_did, is_digest, is_hostname, jcs_digest, parse_ts};

/// The `evidence_version` literal.
pub const EVIDENCE_VERSION: &str = "acdp-evidence/1";

/// An `acdp-evidence/1` bundle.
///
/// Construct one with [`Evidence::new`] and fill the members, or parse
/// one with [`Evidence::from_value`] / [`Evidence::from_slice`]. Optional
/// members are `Option` so that absent and empty stay distinct: the
/// bundle round-trips byte-for-byte under JCS, which `evidence_digest`
/// depends on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Evidence {
    /// Always [`EVIDENCE_VERSION`].
    pub evidence_version: String,
    /// Informational: the roots the exporter walked from (§4.2). The
    /// verifier takes its roots from the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roots: Option<Vec<String>>,
    /// Informational; plays no part in either pass (§4.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exported_at: Option<String>,
    /// Keyed by `ctx_id`. The key is a claim, checked by the identity
    /// stage (§7.2).
    pub contexts: BTreeMap<String, ContextEvidence>,
    /// Snapshot history per DID: producers, registries and witnesses.
    /// `did:key` DIDs MUST NOT appear (§4.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_documents: Option<BTreeMap<String, Vec<DidSnapshot>>>,
    /// Observed RFC-ACDP-0014 §8 discovery records per producer DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_discovery: Option<BTreeMap<String, Vec<DiscoveryRecord>>>,
    /// RFC-ACDP-0012 checkpoints with RFC-ACDP-0015 cosignatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoints: Option<Vec<CheckpointEvidence>>,
    /// RFC-ACDP-0012 §9.2 consistency proofs between carried checkpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_proofs: Option<Vec<ConsistencyProofEvidence>>,
    /// The exporter's list of contexts it deliberately left out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omitted: Option<Vec<Omitted>>,
    /// Annotation members (`^_`): ignored by verification, but part of
    /// the bundle and so of `evidence_digest`. Any other unknown member
    /// rejects the bundle.
    #[serde(flatten)]
    pub annotations: BTreeMap<String, Value>,
}

/// One context's evidence (`#/$defs/context_evidence`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ContextEvidence {
    /// The context body, exactly as retrieved.
    pub body: Value,
    /// The RFC-ACDP-0010 registry receipt, as retrieved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_receipt: Option<Value>,
    /// RFC-ACDP-0013 lifecycle events, in registry order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_events: Option<Vec<Value>>,
    /// RFC-ACDP-0017 §10 event receipts, parallel to `lifecycle_events`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_receipts: Option<Vec<Value>>,
    /// The RFC-ACDP-0012 inclusion proof, as retrieved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_inclusion: Option<Value>,
}

impl ContextEvidence {
    /// Evidence carrying only a body.
    pub fn new(body: Value) -> Self {
        Self {
            body,
            registry_receipt: None,
            lifecycle_events: None,
            event_receipts: None,
            log_inclusion: None,
        }
    }
}

/// A DID-document snapshot (`#/$defs/did_snapshot`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DidSnapshot {
    /// The DID document as fetched, verbatim.
    pub document: Map<String, Value>,
    /// When the observer fetched it: an assertion, basis `observed`.
    pub observed_at: String,
    /// Who observed it (≤ 256 characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_by: Option<String>,
    /// Where it was fetched from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl DidSnapshot {
    /// A snapshot with no `observed_by` or `source`.
    pub fn new(document: Map<String, Value>, observed_at: impl Into<String>) -> Self {
        Self {
            document,
            observed_at: observed_at.into(),
            observed_by: None,
            source: None,
        }
    }
}

/// An RFC-ACDP-0014 §8 discovery outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryOutcome {
    /// Discovery found a revocation.
    #[serde(rename = "revoked")]
    Revoked,
    /// Every lookup completed and found none.
    #[serde(rename = "not-revoked-complete")]
    NotRevokedComplete,
    /// Discovery could not finish.
    #[serde(rename = "unknown")]
    Unknown,
}

/// An observed discovery record (`#/$defs/discovery_record`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DiscoveryRecord {
    /// The registry authority queried.
    pub vantage: String,
    /// What discovery concluded.
    pub outcome: DiscoveryOutcome,
    /// When discovery finished.
    pub completed_at: String,
}

impl DiscoveryRecord {
    /// A record.
    pub fn new(
        vantage: impl Into<String>,
        outcome: DiscoveryOutcome,
        completed_at: impl Into<String>,
    ) -> Self {
        Self {
            vantage: vantage.into(),
            outcome,
            completed_at: completed_at.into(),
        }
    }
}

/// A checkpoint with its cosignatures.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CheckpointEvidence {
    /// The RFC-ACDP-0012 checkpoint, as retrieved.
    pub checkpoint: Value,
    /// RFC-ACDP-0015 cosignatures over it, as retrieved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cosignatures: Option<Vec<Value>>,
}

/// An RFC-ACDP-0012 §9.2 consistency proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ConsistencyProofEvidence {
    /// The log.
    pub log_id: String,
    /// The older tree size.
    pub first_tree_size: u64,
    /// The newer tree size.
    pub second_tree_size: u64,
    /// The proof path.
    pub consistency_path: Vec<String>,
}

/// Why the exporter left a context out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmittedReason {
    /// Left out by policy (e.g. visibility): presence `withheld`.
    Withheld,
    /// The fetch failed: presence `unresolved`.
    NotRetrievable,
    /// An export budget fired: presence `unresolved`.
    Limit,
}

/// An `omitted` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Omitted {
    /// The context left out.
    pub ctx_id: String,
    /// Why.
    pub reason: OmittedReason,
}

impl Omitted {
    /// An entry.
    pub fn new(ctx_id: impl Into<String>, reason: OmittedReason) -> Self {
        Self {
            ctx_id: ctx_id.into(),
            reason,
        }
    }
}

impl Default for Evidence {
    fn default() -> Self {
        Self::new()
    }
}

impl Evidence {
    /// An empty bundle (`evidence_version` set, no contexts).
    pub fn new() -> Self {
        Self {
            evidence_version: EVIDENCE_VERSION.to_string(),
            roots: None,
            exported_at: None,
            contexts: BTreeMap::new(),
            did_documents: None,
            revocation_discovery: None,
            checkpoints: None,
            consistency_proofs: None,
            omitted: None,
            annotations: BTreeMap::new(),
        }
    }

    /// Parse and schema-check a bundle. Any failure rejects the whole
    /// bundle (§4.1).
    pub fn from_value(value: &Value) -> Result<Self, ChainError> {
        if !value.is_object() {
            return Err(evidence("the bundle must be a JSON object"));
        }
        let parsed: Evidence = serde_json::from_value(value.clone())
            .map_err(|e| evidence(format!("does not parse: {e}")))?;
        // The typed form must round-trip to the same JSON: this rejects
        // `null` for optional members (which the schema forbids and
        // serde would silently drop) and keeps `evidence_digest` equal
        // over the raw and the typed form.
        let round_trip = serde_json::to_value(&parsed)
            .map_err(|e| evidence(format!("does not serialize: {e}")))?;
        if &round_trip != value {
            return Err(evidence(
                "a member does not round-trip (e.g. an optional member set to null)",
            ));
        }
        parsed.check()?;
        Ok(parsed)
    }

    /// [`Self::from_value`] over JSON bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ChainError> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|e| evidence(format!("not JSON: {e}")))?;
        Self::from_value(&value)
    }

    /// The bundle as JSON.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("evidence serializes")
    }

    /// `evidence_digest`: `sha256:` + hex(SHA-256(JCS(bundle))) (§9.1).
    pub fn digest(&self) -> String {
        jcs_digest(&self.to_value())
    }

    /// Run the whole schema check without keeping the parsed parts.
    pub fn check(&self) -> Result<(), ChainError> {
        self.parse().map(|_| ())
    }

    /// The schema check, keeping the parsed sub-objects for the passes.
    pub(crate) fn parse(&self) -> Result<Parsed<'_>, ChainError> {
        if self.evidence_version != EVIDENCE_VERSION {
            return Err(evidence(format!(
                "evidence_version '{}' ≠ '{EVIDENCE_VERSION}'",
                self.evidence_version
            )));
        }
        for key in self.annotations.keys() {
            if !key.starts_with('_') {
                return Err(evidence(format!(
                    "unknown member '{key}' (only '_'-prefixed annotations are allowed)"
                )));
            }
        }
        if let Some(roots) = &self.roots {
            for r in roots {
                if !is_ctx_id(r) {
                    return Err(evidence(format!("roots entry '{r}' is not a ctx_id")));
                }
            }
        }
        if let Some(t) = &self.exported_at {
            ts(t, "exported_at")?;
        }

        let mut contexts = BTreeMap::new();
        for (key, ce) in &self.contexts {
            if !is_ctx_id(key) {
                return Err(evidence(format!("contexts key '{key}' is not a ctx_id")));
            }
            contexts.insert(key.as_str(), parse_context(key, ce)?);
        }

        let mut snapshots = BTreeMap::new();
        for (did, list) in self.did_documents.iter().flatten() {
            if !is_did(did) || did.starts_with("did:key:") {
                return Err(evidence(format!(
                    "did_documents key '{did}' is not a non-did:key DID (did:key resolves \
                     arithmetically, RFC-ACDP-0017 §4.2)"
                )));
            }
            if list.is_empty() {
                return Err(evidence(format!("did_documents['{did}'] is empty")));
            }
            let mut parsed = Vec::with_capacity(list.len());
            for s in list {
                if s.observed_by
                    .as_ref()
                    .is_some_and(|o| o.chars().count() > 256)
                {
                    return Err(evidence("did_snapshot.observed_by exceeds 256 characters"));
                }
                if s.source.as_ref().is_some_and(|u| !looks_like_uri(u)) {
                    return Err(evidence("did_snapshot.source is not a URI"));
                }
                parsed.push((ts(&s.observed_at, "observed_at")?, &s.document));
            }
            snapshots.insert(did.as_str(), parsed);
        }

        let mut discovery = BTreeMap::new();
        for (did, list) in self.revocation_discovery.iter().flatten() {
            if !is_did(did) {
                return Err(evidence(format!(
                    "revocation_discovery key '{did}' is not a DID"
                )));
            }
            if list.is_empty() {
                return Err(evidence(format!("revocation_discovery['{did}'] is empty")));
            }
            let mut parsed = Vec::with_capacity(list.len());
            for r in list {
                if !is_hostname(&r.vantage) {
                    return Err(evidence(format!(
                        "discovery vantage '{}' is not a hostname",
                        r.vantage
                    )));
                }
                parsed.push(ParsedDiscovery {
                    vantage: &r.vantage,
                    outcome: r.outcome,
                    completed_at: ts(&r.completed_at, "completed_at")?,
                });
            }
            discovery.insert(did.as_str(), parsed);
        }

        let mut checkpoints = Vec::new();
        for c in self.checkpoints.iter().flatten() {
            let checkpoint = LogCheckpoint::from_value(&c.checkpoint)
                .map_err(|e| evidence(format!("checkpoint: {e}")))?;
            let mut cosignatures = Vec::new();
            for cv in c.cosignatures.iter().flatten() {
                let cosig = LogCosignature::from_value(cv)
                    .map_err(|e| evidence(format!("cosignature: {e}")))?;
                cosignatures.push((cosig, cv));
            }
            checkpoints.push(ParsedCheckpoint {
                checkpoint,
                raw: &c.checkpoint,
                cosignatures,
            });
        }

        for p in self.consistency_proofs.iter().flatten() {
            if p.log_id.is_empty() || !p.consistency_path.iter().all(|h| is_digest(h)) {
                return Err(evidence("malformed consistency proof"));
            }
        }

        let mut omitted = BTreeMap::new();
        for o in self.omitted.iter().flatten() {
            if !is_ctx_id(&o.ctx_id) {
                return Err(evidence(format!(
                    "omitted ctx_id '{}' is not a ctx_id",
                    o.ctx_id
                )));
            }
            // Several entries for one ctx_id: the first one is the
            // exporter's statement.
            omitted.entry(o.ctx_id.as_str()).or_insert(o.reason);
        }

        Ok(Parsed {
            contexts,
            snapshots,
            discovery,
            checkpoints,
            omitted,
        })
    }
}

fn ts(raw: &str, what: &str) -> Result<DateTime<Utc>, ChainError> {
    parse_ts(raw).ok_or_else(|| {
        evidence(format!(
            "{what} '{raw}' is not a canonical millisecond RFC 3339 UTC timestamp"
        ))
    })
}

/// `format: uri`, checked to the extent JSON Schema validators do by
/// default: a scheme followed by `:`.
fn looks_like_uri(s: &str) -> bool {
    s.split_once(':').is_some_and(|(scheme, _)| {
        let b = scheme.as_bytes();
        !b.is_empty()
            && b[0].is_ascii_alphabetic()
            && b.iter()
                .all(|c| c.is_ascii_alphanumeric() || b"+-.".contains(c))
    })
}

fn parse_context<'a>(
    key: &'a str,
    ce: &'a ContextEvidence,
) -> Result<ParsedContext<'a>, ChainError> {
    let body: Body = serde_json::from_value(ce.body.clone())
        .map_err(|e| evidence(format!("contexts['{key}'].body does not parse: {e}")))?;
    acdp_validation::validate_body(&body)
        .map_err(|e| evidence(format!("contexts['{key}'].body: {e}")))?;

    let receipt = match &ce.registry_receipt {
        Some(v) => {
            let r = RegistryReceipt::from_value(v)
                .and_then(|r| RegistryReceipt::validate_created_at_form(v).map(|_| r))
                .map_err(|e| evidence(format!("contexts['{key}'].registry_receipt: {e}")))?;
            Some((r, v))
        }
        None => None,
    };

    let mut events = Vec::new();
    if let Some(list) = &ce.lifecycle_events {
        if list.is_empty() {
            return Err(evidence(format!(
                "contexts['{key}'].lifecycle_events is empty"
            )));
        }
        for v in list {
            let e = LifecycleEvent::from_value(v)
                .map_err(|e| evidence(format!("contexts['{key}'].lifecycle_events: {e}")))?;
            events.push((e, v));
        }
    }

    let mut event_receipts = Vec::new();
    if let Some(list) = &ce.event_receipts {
        if ce.lifecycle_events.is_none() {
            return Err(evidence(format!(
                "contexts['{key}'].event_receipts requires lifecycle_events"
            )));
        }
        if list.is_empty() {
            return Err(evidence(format!(
                "contexts['{key}'].event_receipts is empty"
            )));
        }
        for v in list {
            let r = EventReceipt::from_value(v)
                .map_err(|e| evidence(format!("contexts['{key}'].event_receipts: {e}")))?;
            event_receipts.push((r, v));
        }
    }

    let log_inclusion = match &ce.log_inclusion {
        Some(v) => Some((
            LogInclusion::from_value(v)
                .map_err(|e| evidence(format!("contexts['{key}'].log_inclusion: {e}")))?,
            v,
        )),
        None => None,
    };

    Ok(ParsedContext {
        raw_body: &ce.body,
        body,
        receipt,
        events,
        event_receipts,
        log_inclusion,
    })
}

/// A snapshot's `observed_at` and document.
pub(crate) type Snapshot<'a> = (DateTime<Utc>, &'a Map<String, Value>);

/// The schema-checked bundle, borrowed.
pub(crate) struct Parsed<'a> {
    pub contexts: BTreeMap<&'a str, ParsedContext<'a>>,
    pub snapshots: BTreeMap<&'a str, Vec<Snapshot<'a>>>,
    pub discovery: BTreeMap<&'a str, Vec<ParsedDiscovery<'a>>>,
    pub checkpoints: Vec<ParsedCheckpoint<'a>>,
    pub omitted: BTreeMap<&'a str, OmittedReason>,
}

pub(crate) struct ParsedContext<'a> {
    pub raw_body: &'a Value,
    pub body: Body,
    pub receipt: Option<(RegistryReceipt, &'a Value)>,
    pub events: Vec<(LifecycleEvent, &'a Value)>,
    pub event_receipts: Vec<(EventReceipt, &'a Value)>,
    pub log_inclusion: Option<(LogInclusion, &'a Value)>,
}

pub(crate) struct ParsedDiscovery<'a> {
    pub vantage: &'a str,
    pub outcome: DiscoveryOutcome,
    pub completed_at: DateTime<Utc>,
}

pub(crate) struct ParsedCheckpoint<'a> {
    pub checkpoint: LogCheckpoint,
    pub raw: &'a Value,
    pub cosignatures: Vec<(LogCosignature, &'a Value)>,
}
