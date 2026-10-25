//! Retraction recall wire types (ACDP 0.5.0 Draft, RFC-ACDP-0018).
//!
//! - [`Change`] — one `acdp-change/1` entry of a registry's `GET /changes`
//!   feed (§4). Its evidence is a per-kind enum ([`ChangeEvidence`]), so
//!   a `lifecycle` entry carrying a `registry_receipt` (or any other
//!   cross-kind mix) cannot be built or parsed.
//! - [`ChangesResponse`] — the `GET /changes` response body (§5.2).
//! - [`WatchFilter`] — the stateless §6 filter, with the registry-side
//!   matching rule ([`WatchFilter::matches`]).
//! - [`SubscriptionRequest`], [`Subscription`], [`ChangeHint`] — the §8
//!   change-hint webhook objects, plus [`sign_hint`] /
//!   [`verify_hint_signature`] for the `ACDP-Signature` header.
//!
//! A change entry is **evidence, not a verdict** (§4): parsing one proves
//! only its shape. The signed objects it carries are kept as the raw wire
//! JSON, because their signatures cover the bytes as served; consumers
//! verify them per §7 (`acdp-client`'s `recall` module) before changing
//! any reliance decision.

use crate::lifecycle::LifecycleEvent;
use crate::receipt::{is_canonical_ms_utc, RegistryReceipt};
use crate::serde_helpers::de_present;
use crate::EventReceipt;
use acdp_primitives::error::AcdpError;
use acdp_primitives::primitives::{is_valid_dns_authority, AgentDid, CtxId, LineageId};
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

/// The `change_version` literal of a change entry.
pub const CHANGE_VERSION: &str = "acdp-change/1";
/// The `hint_version` literal of a change hint.
pub const CHANGE_HINT_VERSION: &str = "acdp-change-hint/1";
/// The header carrying a change hint's HMAC (RFC-ACDP-0018 §8.2).
pub const SIGNATURE_HEADER: &str = "ACDP-Signature";
/// A receiver rejects a hint whose `t` is further than this from its
/// clock, in seconds (RFC-ACDP-0018 §8.2).
pub const HINT_MAX_SKEW_SECONDS: i64 = 300;
/// Feed cursors are opaque strings of 1 to this many characters.
pub const MAX_CURSOR_LEN: usize = 2048;
/// The minimum `limits.change_retention_seconds` (30 days, §5.4).
pub const MIN_CHANGE_RETENTION_SECONDS: u64 = 2_592_000;

fn bad(msg: impl Into<String>) -> AcdpError {
    AcdpError::SchemaViolation(msg.into())
}

// ── Change kinds and evidence ────────────────────────────────────────────────

/// What a change entry records (RFC-ACDP-0018 §3). Closed in
/// `acdp-change/1`: a new kind needs `acdp-change/2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// A lifecycle event was appended to the affected context.
    Lifecycle,
    /// A newer version superseding the affected context was accepted.
    Superseded,
    /// A `key-revocation` context (the affected context) was accepted.
    KeyRevocation,
}

impl ChangeKind {
    /// Every kind, in wire order.
    pub const ALL: [ChangeKind; 3] = [
        ChangeKind::Lifecycle,
        ChangeKind::Superseded,
        ChangeKind::KeyRevocation,
    ];

    /// The wire form: `lifecycle`, `superseded` or `key_revocation`.
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Lifecycle => "lifecycle",
            ChangeKind::Superseded => "superseded",
            ChangeKind::KeyRevocation => "key_revocation",
        }
    }

    /// Parse the wire form. An unknown kind is a
    /// [`AcdpError::SchemaViolation`], as §5.1 requires of a registry.
    pub fn parse(s: &str) -> Result<Self, AcdpError> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| bad(format!("unknown change kind '{s}' (RFC-ACDP-0018 §3)")))
    }
}

impl std::fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A change entry's evidence, by kind (RFC-ACDP-0018 §4). The signed
/// objects are the raw wire JSON exactly as served.
#[derive(Debug, Clone, PartialEq)]
pub enum ChangeEvidence {
    /// `kind: lifecycle`.
    Lifecycle {
        /// The stored lifecycle event, byte-for-byte as served in
        /// `lifecycle_events`.
        event: Value,
        /// Its `acdp-event-receipt/1` (RFC-ACDP-0017 §10).
        event_receipt: Value,
    },
    /// `kind: superseded`.
    Superseded {
        /// The new version's `ctx_id`.
        superseded_by: CtxId,
        /// The new version's registry receipt (RFC-ACDP-0010).
        registry_receipt: Value,
    },
    /// `kind: key_revocation`.
    KeyRevocation {
        /// The revocation context's registry receipt.
        registry_receipt: Value,
    },
}

impl ChangeEvidence {
    /// The kind this evidence belongs to.
    pub fn kind(&self) -> ChangeKind {
        match self {
            ChangeEvidence::Lifecycle { .. } => ChangeKind::Lifecycle,
            ChangeEvidence::Superseded { .. } => ChangeKind::Superseded,
            ChangeEvidence::KeyRevocation { .. } => ChangeKind::KeyRevocation,
        }
    }
}

// ── The change entry ─────────────────────────────────────────────────────────

/// One `acdp-change/1` entry (RFC-ACDP-0018 §4), CLOSED.
///
/// Built only through [`Self::from_value`] / `Deserialize` (which enforce
/// the schema, including each carried object's own closed schema) or the
/// registry-side constructors [`Self::lifecycle`], [`Self::superseded`]
/// and [`Self::key_revocation`] (which derive `recorded_at` and the ids
/// from the evidence, so they cannot disagree with it).
///
/// Parsing does not verify anything: see [`Self::check_consistency`] for
/// the pure cross-checks, and `acdp-client`'s `verify_change` for §7.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ChangeWire", into = "ChangeWire")]
pub struct Change {
    seq: u64,
    ctx_id: CtxId,
    lineage_id: LineageId,
    agent_id: AgentDid,
    recorded_at: DateTime<Utc>,
    evidence: ChangeEvidence,
}

impl Change {
    /// Parse a change entry from wire JSON, enforcing the closed schema.
    /// Failures are [`AcdpError::SchemaViolation`].
    pub fn from_value(value: &Value) -> Result<Self, AcdpError> {
        Self::deserialize(value).map_err(|e| bad(format!("change entry does not parse: {e}")))
    }

    /// A `lifecycle` entry for the event at `event_receipt.index` of the
    /// receipt's context. `raw_event` is the stored event, verbatim;
    /// `recorded_at` is the receipt's `accepted_at`.
    pub fn lifecycle(
        seq: u64,
        lineage_id: LineageId,
        agent_id: AgentDid,
        raw_event: Value,
        event_receipt: &EventReceipt,
    ) -> Result<Self, AcdpError> {
        let change = Self {
            seq,
            ctx_id: event_receipt.ctx_id.clone(),
            lineage_id,
            agent_id,
            recorded_at: event_receipt.accepted_at,
            evidence: ChangeEvidence::Lifecycle {
                event: raw_event,
                event_receipt: serde_json::to_value(event_receipt)?,
            },
        };
        change.validate()?;
        Ok(change)
    }

    /// A `superseded` entry: `ctx_id` was superseded by the version
    /// `registry_receipt` was minted for. The lineage is the receipt's;
    /// `agent_id` is the superseded context's producer.
    pub fn superseded(
        seq: u64,
        ctx_id: CtxId,
        agent_id: AgentDid,
        registry_receipt: &RegistryReceipt,
    ) -> Result<Self, AcdpError> {
        let change = Self {
            seq,
            ctx_id,
            lineage_id: registry_receipt.lineage_id.clone(),
            agent_id,
            recorded_at: registry_receipt.created_at,
            evidence: ChangeEvidence::Superseded {
                superseded_by: registry_receipt.ctx_id.clone(),
                registry_receipt: serde_json::to_value(registry_receipt)?,
            },
        };
        change.validate()?;
        Ok(change)
    }

    /// A `key_revocation` entry for the revocation context
    /// `registry_receipt` was minted for. `agent_id` is the revoked key's
    /// controller: `metadata.revoked_key_controller` when present, else
    /// the revocation body's `agent_id` (RFC-ACDP-0018 §4).
    pub fn key_revocation(
        seq: u64,
        agent_id: AgentDid,
        registry_receipt: &RegistryReceipt,
    ) -> Result<Self, AcdpError> {
        let change = Self {
            seq,
            ctx_id: registry_receipt.ctx_id.clone(),
            lineage_id: registry_receipt.lineage_id.clone(),
            agent_id,
            recorded_at: registry_receipt.created_at,
            evidence: ChangeEvidence::KeyRevocation {
                registry_receipt: serde_json::to_value(registry_receipt)?,
            },
        };
        change.validate()?;
        Ok(change)
    }

    /// The entry's sequence number (§5.3).
    pub fn seq(&self) -> u64 {
        self.seq
    }
    /// The entry's kind.
    pub fn kind(&self) -> ChangeKind {
        self.evidence.kind()
    }
    /// The affected context.
    pub fn ctx_id(&self) -> &CtxId {
        &self.ctx_id
    }
    /// The affected context's lineage.
    pub fn lineage_id(&self) -> &LineageId {
        &self.lineage_id
    }
    /// The producer whose reliance the change touches (§4).
    pub fn agent_id(&self) -> &AgentDid {
        &self.agent_id
    }
    /// The registry's clock at commit.
    pub fn recorded_at(&self) -> DateTime<Utc> {
        self.recorded_at
    }
    /// The evidence, by kind.
    pub fn evidence(&self) -> &ChangeEvidence {
        &self.evidence
    }

    /// The schema invariants serde does not enforce: the ids' grammars,
    /// and each carried object's own closed schema.
    fn validate(&self) -> Result<(), AcdpError> {
        CtxId::parse(self.ctx_id.as_str())?;
        LineageId::parse(self.lineage_id.as_str())?;
        AgentDid::parse(self.agent_id.as_str())?;
        match &self.evidence {
            ChangeEvidence::Lifecycle {
                event,
                event_receipt,
            } => {
                LifecycleEvent::from_value(event)?;
                EventReceipt::from_value(event_receipt)?;
            }
            ChangeEvidence::Superseded {
                superseded_by,
                registry_receipt,
            } => {
                CtxId::parse(superseded_by.as_str())?;
                RegistryReceipt::from_value(registry_receipt)?;
            }
            ChangeEvidence::KeyRevocation { registry_receipt } => {
                RegistryReceipt::from_value(registry_receipt)?;
            }
        }
        Ok(())
    }

    /// The pure cross-checks between an entry's envelope and its
    /// evidence (RFC-ACDP-0018 §4), run before any network round-trip:
    ///
    /// - `lifecycle`: the event's and the receipt's `ctx_id` are the
    ///   entry's; `recorded_at` equals `event_receipt.accepted_at`.
    /// - `superseded`: the receipt is for `superseded_by` (not the
    ///   entry's own context) in the entry's lineage; `recorded_at`
    ///   equals `registry_receipt.created_at`.
    /// - `key_revocation`: the receipt is for the entry's context and
    ///   lineage; `recorded_at` equals `registry_receipt.created_at`.
    ///
    /// Signatures and the receipt's binding to the event are NOT checked
    /// here. Failures are [`AcdpError::SchemaViolation`].
    pub fn check_consistency(&self) -> Result<(), AcdpError> {
        let recorded = |at: DateTime<Utc>, what: &str| {
            if at == self.recorded_at {
                Ok(())
            } else {
                Err(bad(format!(
                    "change {} recorded_at {} ≠ {what} {} (RFC-ACDP-0018 §4)",
                    self.seq,
                    fmt_ms(self.recorded_at),
                    fmt_ms(at)
                )))
            }
        };
        match &self.evidence {
            ChangeEvidence::Lifecycle {
                event,
                event_receipt,
            } => {
                let e = LifecycleEvent::from_value(event)?;
                let r = EventReceipt::from_value(event_receipt)?;
                if e.ctx_id != self.ctx_id || r.ctx_id != self.ctx_id {
                    return Err(bad(format!(
                        "change {} names ctx_id {} but its event or event receipt names another \
                         context",
                        self.seq, self.ctx_id
                    )));
                }
                recorded(r.accepted_at, "event_receipt.accepted_at")
            }
            ChangeEvidence::Superseded {
                superseded_by,
                registry_receipt,
            } => {
                let r = RegistryReceipt::from_value(registry_receipt)?;
                if superseded_by == &self.ctx_id {
                    return Err(bad(format!(
                        "change {}: a context cannot supersede itself",
                        self.seq
                    )));
                }
                if &r.ctx_id != superseded_by || r.lineage_id != self.lineage_id {
                    return Err(bad(format!(
                        "change {}: registry_receipt is not for superseded_by {superseded_by} in \
                         lineage {}",
                        self.seq, self.lineage_id
                    )));
                }
                recorded(r.created_at, "registry_receipt.created_at")
            }
            ChangeEvidence::KeyRevocation { registry_receipt } => {
                let r = RegistryReceipt::from_value(registry_receipt)?;
                if r.ctx_id != self.ctx_id || r.lineage_id != self.lineage_id {
                    return Err(bad(format!(
                        "change {}: registry_receipt is not for the revocation context {} in \
                         lineage {}",
                        self.seq, self.ctx_id, self.lineage_id
                    )));
                }
                recorded(r.created_at, "registry_receipt.created_at")
            }
        }
    }
}

fn fmt_ms(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn parse_ms(raw: &str, what: &str) -> Result<DateTime<Utc>, AcdpError> {
    if !is_canonical_ms_utc(raw) {
        return Err(bad(format!(
            "{what} '{raw}' is not canonical millisecond-precision RFC 3339 UTC"
        )));
    }
    Ok(DateTime::parse_from_rfc3339(raw)
        .expect("is_canonical_ms_utc parsed it")
        .with_timezone(&Utc))
}

/// The flat wire form of [`Change`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeWire {
    change_version: String,
    seq: u64,
    kind: ChangeKind,
    ctx_id: CtxId,
    lineage_id: LineageId,
    agent_id: AgentDid,
    recorded_at: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_present"
    )]
    event: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_present"
    )]
    event_receipt: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_present"
    )]
    superseded_by: Option<CtxId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_present"
    )]
    registry_receipt: Option<Value>,
}

impl TryFrom<ChangeWire> for Change {
    type Error = AcdpError;

    fn try_from(w: ChangeWire) -> Result<Self, AcdpError> {
        if w.change_version != CHANGE_VERSION {
            return Err(bad(format!(
                "change_version '{}' ≠ '{CHANGE_VERSION}'",
                w.change_version
            )));
        }
        let recorded_at = parse_ms(&w.recorded_at, "recorded_at")?;
        let mismatch = |extra: &str| {
            bad(format!(
                "a '{}' change entry must not carry '{extra}' (RFC-ACDP-0018 §4)",
                w.kind
            ))
        };
        let missing = |member: &str| {
            bad(format!(
                "a '{}' change entry requires '{member}' (RFC-ACDP-0018 §4)",
                w.kind
            ))
        };
        let evidence = match w.kind {
            ChangeKind::Lifecycle => {
                if w.superseded_by.is_some() {
                    return Err(mismatch("superseded_by"));
                }
                if w.registry_receipt.is_some() {
                    return Err(mismatch("registry_receipt"));
                }
                ChangeEvidence::Lifecycle {
                    event: w.event.ok_or_else(|| missing("event"))?,
                    event_receipt: w.event_receipt.ok_or_else(|| missing("event_receipt"))?,
                }
            }
            ChangeKind::Superseded => {
                if w.event.is_some() {
                    return Err(mismatch("event"));
                }
                if w.event_receipt.is_some() {
                    return Err(mismatch("event_receipt"));
                }
                ChangeEvidence::Superseded {
                    superseded_by: w.superseded_by.ok_or_else(|| missing("superseded_by"))?,
                    registry_receipt: w
                        .registry_receipt
                        .ok_or_else(|| missing("registry_receipt"))?,
                }
            }
            ChangeKind::KeyRevocation => {
                for (present, name) in [
                    (w.event.is_some(), "event"),
                    (w.event_receipt.is_some(), "event_receipt"),
                    (w.superseded_by.is_some(), "superseded_by"),
                ] {
                    if present {
                        return Err(mismatch(name));
                    }
                }
                ChangeEvidence::KeyRevocation {
                    registry_receipt: w
                        .registry_receipt
                        .ok_or_else(|| missing("registry_receipt"))?,
                }
            }
        };
        let change = Change {
            seq: w.seq,
            ctx_id: w.ctx_id,
            lineage_id: w.lineage_id,
            agent_id: w.agent_id,
            recorded_at,
            evidence,
        };
        change.validate()?;
        Ok(change)
    }
}

impl From<Change> for ChangeWire {
    fn from(c: Change) -> Self {
        let mut w = ChangeWire {
            change_version: CHANGE_VERSION.into(),
            seq: c.seq,
            kind: c.evidence.kind(),
            ctx_id: c.ctx_id,
            lineage_id: c.lineage_id,
            agent_id: c.agent_id,
            recorded_at: fmt_ms(c.recorded_at),
            event: None,
            event_receipt: None,
            superseded_by: None,
            registry_receipt: None,
        };
        match c.evidence {
            ChangeEvidence::Lifecycle {
                event,
                event_receipt,
            } => {
                w.event = Some(event);
                w.event_receipt = Some(event_receipt);
            }
            ChangeEvidence::Superseded {
                superseded_by,
                registry_receipt,
            } => {
                w.superseded_by = Some(superseded_by);
                w.registry_receipt = Some(registry_receipt);
            }
            ChangeEvidence::KeyRevocation { registry_receipt } => {
                w.registry_receipt = Some(registry_receipt);
            }
        }
        w
    }
}

// ── The feed response ────────────────────────────────────────────────────────

/// The `GET /changes` response body (RFC-ACDP-0018 §5.2), CLOSED.
///
/// `next_cursor` is always present: the feed is a tail, so a consumer at
/// the head keeps polling with it. `has_more` means entries past
/// `next_cursor` were already committed; an empty `changes` with
/// `has_more: true` is not the end of the feed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangesResponse {
    /// Matching, visible entries after `since`, ascending `seq`.
    pub changes: Vec<Change>,
    /// Opaque, durable cursor naming the position after the last entry
    /// scanned (§5.4).
    pub next_cursor: String,
    /// Entries past `next_cursor` were committed when the response was
    /// built; request again at once.
    pub has_more: bool,
}

impl ChangesResponse {
    /// Parse a response, enforcing the closed schema, the cursor length
    /// bounds and strictly ascending `seq`. Failures are
    /// [`AcdpError::SchemaViolation`].
    pub fn from_value(value: &Value) -> Result<Self, AcdpError> {
        let r = Self::deserialize(value)
            .map_err(|e| bad(format!("changes response does not parse: {e}")))?;
        r.validate()?;
        Ok(r)
    }

    /// The invariants serde does not enforce.
    pub fn validate(&self) -> Result<(), AcdpError> {
        check_cursor(&self.next_cursor, "next_cursor")?;
        if self.changes.windows(2).any(|w| w[0].seq >= w[1].seq) {
            return Err(bad(
                "changes are not in strictly ascending seq order (RFC-ACDP-0018 §5.2, §5.3)",
            ));
        }
        Ok(())
    }
}

fn check_cursor(c: &str, what: &str) -> Result<(), AcdpError> {
    if c.is_empty() || c.chars().count() > MAX_CURSOR_LEN {
        return Err(bad(format!(
            "{what} must be 1 to {MAX_CURSOR_LEN} characters (RFC-ACDP-0018 §5.4)"
        )));
    }
    Ok(())
}

// ── Watch filters ────────────────────────────────────────────────────────────

/// A §6 watch filter: the `ctx_id`, `lineage_id`, `agent_id` and `kind`
/// values of a `GET /changes` request or a subscription.
///
/// Values within a member are OR'd; `ctx_id`, `lineage_id` and
/// `agent_id` are OR'd with each other; `kind` is AND'd with the result.
/// With no id value at all, every visible entry matches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchFilter {
    /// Watched contexts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ctx_id: Vec<CtxId>,
    /// Watched lineages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lineage_id: Vec<LineageId>,
    /// Watched producers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_id: Vec<AgentDid>,
    /// Restrict to these kinds; empty means every kind.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kind: Vec<ChangeKind>,
}

impl WatchFilter {
    /// The empty filter: every visible entry.
    pub fn new() -> Self {
        Self::default()
    }
    /// Also watch context `c`.
    pub fn ctx_id(mut self, c: CtxId) -> Self {
        self.ctx_id.push(c);
        self
    }
    /// Also watch lineage `l`.
    pub fn lineage_id(mut self, l: LineageId) -> Self {
        self.lineage_id.push(l);
        self
    }
    /// Also watch producer `a`.
    pub fn agent_id(mut self, a: AgentDid) -> Self {
        self.agent_id.push(a);
        self
    }
    /// Also accept kind `k`.
    pub fn kind(mut self, k: ChangeKind) -> Self {
        self.kind.push(k);
        self
    }

    /// True when no member has a value.
    pub fn is_empty(&self) -> bool {
        self.total_values() == 0
    }

    /// The total number of values, which `limits.max_change_filters`
    /// bounds (§5.1).
    pub fn total_values(&self) -> usize {
        self.ctx_id.len() + self.lineage_id.len() + self.agent_id.len() + self.kind.len()
    }

    /// Check the ids' grammars and, when given, the
    /// `limits.max_change_filters` bound. Failures are
    /// [`AcdpError::SchemaViolation`], as §5.1 requires of a registry.
    pub fn validate(&self, max_change_filters: Option<u64>) -> Result<(), AcdpError> {
        for c in &self.ctx_id {
            CtxId::parse(c.as_str())?;
        }
        for l in &self.lineage_id {
            LineageId::parse(l.as_str())?;
        }
        for a in &self.agent_id {
            AgentDid::parse(a.as_str())?;
        }
        if let Some(max) = max_change_filters {
            if self.total_values() as u64 > max {
                return Err(bad(format!(
                    "{} filter values exceed limits.max_change_filters {max} (RFC-ACDP-0018 §5.1)",
                    self.total_values()
                )));
            }
        }
        Ok(())
    }

    /// The stricter form a subscription filter takes (§8.1): at least one
    /// value, and no member repeating a value.
    pub fn validate_for_subscription(
        &self,
        max_change_filters: Option<u64>,
    ) -> Result<(), AcdpError> {
        self.validate(max_change_filters)?;
        if self.is_empty() {
            return Err(bad("a subscription filter needs at least one value"));
        }
        fn unique<T: Ord>(v: &[T]) -> bool {
            let mut seen = std::collections::BTreeSet::new();
            v.iter().all(|x| seen.insert(x))
        }
        if !unique(&self.ctx_id.iter().map(CtxId::as_str).collect::<Vec<_>>())
            || !unique(
                &self
                    .lineage_id
                    .iter()
                    .map(LineageId::as_str)
                    .collect::<Vec<_>>(),
            )
            || !unique(
                &self
                    .agent_id
                    .iter()
                    .map(AgentDid::as_str)
                    .collect::<Vec<_>>(),
            )
            || !unique(&self.kind)
        {
            return Err(bad("a subscription filter member repeats a value"));
        }
        Ok(())
    }

    /// The repeatable `GET /changes` query parameters (§5.1), in member
    /// order.
    pub fn query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut q = Vec::with_capacity(self.total_values());
        q.extend(
            self.ctx_id
                .iter()
                .map(|c| ("ctx_id", c.as_str().to_owned())),
        );
        q.extend(
            self.lineage_id
                .iter()
                .map(|l| ("lineage_id", l.as_str().to_owned())),
        );
        q.extend(
            self.agent_id
                .iter()
                .map(|a| ("agent_id", a.as_str().to_owned())),
        );
        q.extend(self.kind.iter().map(|k| ("kind", k.as_str().to_owned())));
        q
    }

    /// Whether `change` matches (§6). `producer_of` returns the
    /// `agent_id` of a context the registry holds: a `ctx_id=X` watch
    /// also matches a `key_revocation` entry for X's producer.
    pub fn matches(
        &self,
        change: &Change,
        producer_of: impl Fn(&CtxId) -> Option<AgentDid>,
    ) -> bool {
        if !self.kind.is_empty() && !self.kind.contains(&change.kind()) {
            return false;
        }
        if self.ctx_id.is_empty() && self.lineage_id.is_empty() && self.agent_id.is_empty() {
            return true;
        }
        self.ctx_id.contains(&change.ctx_id)
            || self.lineage_id.contains(&change.lineage_id)
            || self.agent_id.contains(&change.agent_id)
            || (change.kind() == ChangeKind::KeyRevocation
                && self
                    .ctx_id
                    .iter()
                    .any(|c| producer_of(c).as_ref() == Some(&change.agent_id)))
    }
}

/// Reject a filter member given as `[]` on the wire (`minItems: 1`).
fn check_filter_arrays(filter: Option<&Value>) -> Result<(), AcdpError> {
    if let Some(obj) = filter.and_then(Value::as_object) {
        for (k, v) in obj {
            if v.as_array().is_some_and(Vec::is_empty) {
                return Err(bad(format!("filter.{k} is empty (minItems 1)")));
            }
        }
    }
    Ok(())
}

fn check_callback_url(url: &str) -> Result<(), AcdpError> {
    let host = url.strip_prefix("https://").map(|r| {
        r.split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .rsplit('@')
            .next()
            .unwrap_or("")
    });
    if url.len() > 2048
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
        || host.is_none_or(str::is_empty)
    {
        return Err(bad(format!(
            "callback_url '{url}' is not an https URL of at most 2048 characters \
             (RFC-ACDP-0018 §8.1)"
        )));
    }
    Ok(())
}

// ── Subscriptions ────────────────────────────────────────────────────────────

/// The `POST /subscriptions` body (RFC-ACDP-0018 §8.1), CLOSED.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionRequest {
    /// The §6 filter hints are sent for.
    pub filter: WatchFilter,
    /// Where hints are POSTed: `https` only. The registry applies the
    /// §8.3 SSRF rules at creation and at every delivery.
    pub callback_url: String,
}

impl SubscriptionRequest {
    /// A request for `filter`, delivered to `callback_url`.
    pub fn new(filter: WatchFilter, callback_url: impl Into<String>) -> Self {
        Self {
            filter,
            callback_url: callback_url.into(),
        }
    }

    /// Parse and validate a request (the schema; not the §8.3 network
    /// rules, which need DNS). Failures are [`AcdpError::SchemaViolation`].
    pub fn from_value(value: &Value) -> Result<Self, AcdpError> {
        check_filter_arrays(value.get("filter"))?;
        let r = Self::deserialize(value)
            .map_err(|e| bad(format!("subscription request does not parse: {e}")))?;
        r.validate(None)?;
        Ok(r)
    }

    /// The schema invariants serde does not enforce, plus the
    /// `limits.max_change_filters` bound when given.
    pub fn validate(&self, max_change_filters: Option<u64>) -> Result<(), AcdpError> {
        self.filter.validate_for_subscription(max_change_filters)?;
        check_callback_url(&self.callback_url)
    }
}

/// A subscription's delivery state (§8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    /// Hints are delivered.
    Active,
    /// Disabled after sustained delivery failure.
    Disabled,
}

/// A change-hint subscription (RFC-ACDP-0018 §8.1), CLOSED. Owned by the
/// requester DID that created it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subscription {
    /// Canonical lowercase v4 UUID.
    pub subscription_id: String,
    /// The §6 filter hints are sent for.
    pub filter: WatchFilter,
    /// Where hints are POSTed.
    pub callback_url: String,
    /// When the subscription was created (canonical millisecond UTC).
    #[serde(with = "crate::receipt::ms_rfc3339")]
    pub created_at: DateTime<Utc>,
    /// Delivery state.
    pub status: SubscriptionStatus,
    /// Base64 of at least 32 random bytes: the `ACDP-Signature` HMAC key.
    /// Present ONLY in the `201` creation response; never served again.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_present"
    )]
    pub secret: Option<String>,
}

impl Subscription {
    /// Parse and validate a subscription object. Failures are
    /// [`AcdpError::SchemaViolation`].
    pub fn from_value(value: &Value) -> Result<Self, AcdpError> {
        check_filter_arrays(value.get("filter"))?;
        if let Some(raw) = value.get("created_at").and_then(Value::as_str) {
            parse_ms(raw, "created_at")?;
        }
        let s = Self::deserialize(value)
            .map_err(|e| bad(format!("subscription does not parse: {e}")))?;
        s.validate()?;
        Ok(s)
    }

    /// The schema invariants serde does not enforce.
    pub fn validate(&self) -> Result<(), AcdpError> {
        if !is_uuid_v4(&self.subscription_id) {
            return Err(bad(format!(
                "subscription_id '{}' is not a canonical lowercase v4 UUID",
                self.subscription_id
            )));
        }
        self.filter.validate_for_subscription(None)?;
        check_callback_url(&self.callback_url)?;
        if let Some(secret) = &self.secret {
            if !is_secret_form(secret) {
                return Err(bad(
                    "subscription secret is not base64 of at least 32 bytes (RFC-ACDP-0018 §8.1)",
                ));
            }
        }
        Ok(())
    }

    /// This subscription as `GET /subscriptions/{id}` serves it: without
    /// `secret`.
    pub fn without_secret(&self) -> Self {
        Self {
            secret: None,
            ..self.clone()
        }
    }
}

/// `^[A-Za-z0-9+/]{43,}={0,2}$`: base64 of at least 32 bytes.
fn is_secret_form(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    s.len() - body.len() <= 2
        && body.len() >= 43
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`.
fn is_uuid_v4(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            14 => c == b'4',
            19 => matches!(c, b'8' | b'9' | b'a' | b'b'),
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

// ── Change hints ─────────────────────────────────────────────────────────────

/// An `acdp-change-hint/1` webhook body (RFC-ACDP-0018 §8.2), CLOSED.
///
/// It carries no change content. The receiver pulls `GET /changes` from
/// its OWN persisted cursor; `head_cursor` is informational, and jumping
/// to it skips entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeHint {
    /// Always [`CHANGE_HINT_VERSION`].
    pub hint_version: String,
    /// The subscription the hint is for.
    pub subscription_id: String,
    /// The registry's authority (hostname).
    pub registry_authority: String,
    /// The feed head when the hint was built. Informational only.
    pub head_cursor: String,
}

impl ChangeHint {
    /// A hint for `subscription_id` from `registry_authority`.
    pub fn new(
        subscription_id: impl Into<String>,
        registry_authority: impl Into<String>,
        head_cursor: impl Into<String>,
    ) -> Self {
        Self {
            hint_version: CHANGE_HINT_VERSION.into(),
            subscription_id: subscription_id.into(),
            registry_authority: registry_authority.into(),
            head_cursor: head_cursor.into(),
        }
    }

    /// Parse and validate a hint body. Verify its `ACDP-Signature` over
    /// the raw bytes first ([`verify_hint_signature`]). Failures are
    /// [`AcdpError::SchemaViolation`].
    pub fn from_value(value: &Value) -> Result<Self, AcdpError> {
        let h = Self::deserialize(value)
            .map_err(|e| bad(format!("change hint does not parse: {e}")))?;
        h.validate()?;
        Ok(h)
    }

    /// The schema invariants serde does not enforce.
    pub fn validate(&self) -> Result<(), AcdpError> {
        if self.hint_version != CHANGE_HINT_VERSION {
            return Err(bad(format!(
                "hint_version '{}' ≠ '{CHANGE_HINT_VERSION}'",
                self.hint_version
            )));
        }
        if !is_uuid_v4(&self.subscription_id) {
            return Err(bad(format!(
                "subscription_id '{}' is not a canonical lowercase v4 UUID",
                self.subscription_id
            )));
        }
        if !is_valid_dns_authority(&self.registry_authority) {
            return Err(bad(format!(
                "registry_authority '{}' is not a hostname",
                self.registry_authority
            )));
        }
        check_cursor(&self.head_cursor, "head_cursor")
    }
}

// ── ACDP-Signature (HMAC-SHA-256) ────────────────────────────────────────────

/// The HMAC key for a subscription `secret`: the UTF-8 bytes of the
/// base64 string exactly as the creation response served it (not the
/// decoded random bytes).
fn hint_key(secret: &str) -> &[u8] {
    secret.as_bytes()
}

fn hint_mac(secret: &str, t: i64, body: &[u8]) -> Hmac<Sha256> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(hint_key(secret)).expect("HMAC accepts any key length");
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac
}

/// The `ACDP-Signature` header value for a hint body, registry side:
/// `t=<t>,v1=<hex HMAC-SHA-256(secret, "<t>." + body)>` (RFC-ACDP-0018
/// §8.2). `body` is the exact bytes that will be POSTed; `t` is unix
/// seconds.
pub fn sign_hint(secret: &str, t: i64, body: &[u8]) -> String {
    let tag = hint_mac(secret, t, body).finalize().into_bytes();
    format!("t={t},v1={}", hex::encode(tag))
}

/// Verify a hint's `ACDP-Signature` header, receiver side (RFC-ACDP-0018
/// §8.2, fixture `rec-007` D).
///
/// `header` is the header value, `body` the raw request body bytes
/// exactly as received (never a re-serialization), `now` the receiver's
/// clock. Passes when `t` is within [`HINT_MAX_SKEW_SECONDS`] of `now`
/// and any `v1` equals the HMAC, compared in constant time. Members
/// other than `t` and `v1` are ignored, so a later `v2` does not break
/// receivers.
///
/// A pass authenticates the hint to its subscriber and nothing more: it
/// is not evidence for any change, and the receiver still pulls the feed
/// from its own cursor. Failures are [`AcdpError::NotAuthorized`].
pub fn verify_hint_signature(
    secret: &str,
    header: &str,
    body: &[u8],
    now: DateTime<Utc>,
) -> Result<(), AcdpError> {
    let reject = |why: &str| {
        AcdpError::NotAuthorized(format!(
            "ACDP-Signature rejected: {why} (RFC-ACDP-0018 §8.2)"
        ))
    };
    let mut t: Option<i64> = None;
    let mut v1: Vec<Vec<u8>> = Vec::new();
    for part in header.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else {
            return Err(reject("malformed header"));
        };
        match k {
            "t" => {
                if t.is_some() || v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(reject("t is missing, repeated or not unix seconds"));
                }
                t = Some(v.parse().map_err(|_| reject("t is out of range"))?);
            }
            "v1" => v1.push(hex::decode(v).map_err(|_| reject("v1 is not hex"))?),
            _ => {}
        }
    }
    let t = t.ok_or_else(|| reject("no t"))?;
    if v1.is_empty() {
        return Err(reject("no v1"));
    }
    if (now.timestamp() - t).abs() > HINT_MAX_SKEW_SECONDS {
        return Err(reject(
            "t is more than 300 seconds from the receiver's clock",
        ));
    }
    let mac = hint_mac(secret, t, body);
    if v1.iter().any(|tag| mac.clone().verify_slice(tag).is_ok()) {
        Ok(())
    } else {
        Err(reject("v1 does not match"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::ReceiptSigner;
    use acdp_crypto::SigningKey;
    use serde_json::json;

    const CTX: &str = "acdp://registry.example.com/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const NEW: &str = "acdp://registry.example.com/cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const LIN: &str = "lin:sha256:a3cb6a87c1601b9f6dddd8d54709b01df3e05f1095b43e6d58e3a862bf9906fa";
    const AGENT: &str = "did:web:agents.example.com:test-producer";
    const FP: &str = "sha256:6a3803d5f059902a1c6dafbc9ba4729212f7caac08634cc3ae76b27529f03827";

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn registry() -> ReceiptSigner {
        ReceiptSigner::new(
            SigningKey::from_bytes(&[0x11; 32]),
            "did:web:registry.example.com",
            "did:web:registry.example.com#receipt-key-1",
        )
        .unwrap()
    }

    fn event() -> Value {
        let e = LifecycleEvent::new(
            "00000000-0000-4000-8000-000000000098",
            CtxId::parse(CTX).unwrap(),
            crate::lifecycle::LifecycleEventType::Retracted,
            at("2026-10-03T00:00:00.000Z"),
            AgentDid::new(AGENT),
            None,
        )
        .unwrap()
        .sign_with(SigningKey::from_bytes(&[0; 32]), format!("{AGENT}#key-1"))
        .unwrap();
        serde_json::to_value(e).unwrap()
    }

    fn lifecycle_change() -> Change {
        let r = registry()
            .mint_event_receipt(
                &CtxId::parse(CTX).unwrap(),
                &event(),
                0,
                at("2026-10-03T00:00:01.000Z"),
            )
            .unwrap();
        Change::lifecycle(
            1042,
            LineageId::parse(LIN).unwrap(),
            AgentDid::new(AGENT),
            event(),
            &r,
        )
        .unwrap()
    }

    fn receipt_for(ctx: &str, created: &str) -> RegistryReceipt {
        registry()
            .mint(
                &CtxId::parse(ctx).unwrap(),
                &LineageId::parse(LIN).unwrap(),
                "registry.example.com",
                at(created),
                &acdp_primitives::primitives::ContentHash::parse(
                    "sha256:1e5ec1be1bb3dc4ee2c9ec6eb4c6cc6422b4ee4a862b6e947aee8de772b6e879",
                )
                .unwrap(),
                FP,
            )
            .unwrap()
    }

    #[test]
    fn constructors_round_trip_and_are_consistent() {
        let l = lifecycle_change();
        let s = Change::superseded(
            1050,
            CtxId::parse(CTX).unwrap(),
            AgentDid::new(AGENT),
            &receipt_for(NEW, "2026-10-04T00:00:00.000Z"),
        )
        .unwrap();
        let k = Change::key_revocation(
            1057,
            AgentDid::new(AGENT),
            &receipt_for(NEW, "2026-10-05T00:00:00.000Z"),
        )
        .unwrap();
        for c in [&l, &s, &k] {
            c.check_consistency().unwrap();
            let wire = serde_json::to_value(c).unwrap();
            assert_eq!(wire["change_version"], CHANGE_VERSION);
            assert_eq!(wire["kind"], c.kind().as_str());
            assert_eq!(&Change::from_value(&wire).unwrap(), c);
        }
        assert_eq!(l.recorded_at(), at("2026-10-03T00:00:01.000Z"));
        assert_eq!(
            serde_json::to_value(&s).unwrap()["superseded_by"],
            json!(NEW)
        );
    }

    #[test]
    fn cross_kind_members_are_rejected() {
        let wire = serde_json::to_value(lifecycle_change()).unwrap();
        let receipt = serde_json::to_value(receipt_for(NEW, "2026-10-04T00:00:00.000Z")).unwrap();
        type Mutate = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(&str, Mutate)> = vec![
            ("lifecycle + registry_receipt", {
                let r = receipt.clone();
                Box::new(move |v: &mut Value| v["registry_receipt"] = r.clone())
            }),
            (
                "lifecycle + superseded_by",
                Box::new(|v: &mut Value| v["superseded_by"] = json!(NEW)),
            ),
            (
                "lifecycle without event_receipt",
                Box::new(|v: &mut Value| {
                    v.as_object_mut().unwrap().remove("event_receipt");
                }),
            ),
            (
                "superseded carrying event",
                Box::new(|v: &mut Value| v["kind"] = json!("superseded")),
            ),
            (
                "key_revocation carrying event",
                Box::new(|v: &mut Value| v["kind"] = json!("key_revocation")),
            ),
            (
                "unknown kind",
                Box::new(|v: &mut Value| v["kind"] = json!("deleted")),
            ),
            (
                "unknown member",
                Box::new(|v: &mut Value| v["x"] = json!(1)),
            ),
            (
                "wrong version",
                Box::new(|v: &mut Value| v["change_version"] = json!("acdp-change/2")),
            ),
            (
                "non-canonical recorded_at",
                Box::new(|v: &mut Value| v["recorded_at"] = json!("2026-10-03T00:00:01Z")),
            ),
            (
                "explicit null",
                Box::new(|v: &mut Value| v["superseded_by"] = Value::Null),
            ),
            (
                "event receipt with an unknown member",
                Box::new(|v: &mut Value| v["event_receipt"]["x"] = json!(1)),
            ),
        ];
        for (name, f) in cases {
            let mut v = wire.clone();
            f(&mut v);
            assert!(Change::from_value(&v).is_err(), "{name} parsed");
        }
    }

    #[test]
    fn consistency_catches_envelope_disagreeing_with_evidence() {
        let mut v = serde_json::to_value(lifecycle_change()).unwrap();
        v["recorded_at"] = json!("2026-10-03T00:00:02.000Z");
        assert!(Change::from_value(&v).unwrap().check_consistency().is_err());

        let mut v = serde_json::to_value(lifecycle_change()).unwrap();
        v["ctx_id"] = json!(NEW);
        assert!(Change::from_value(&v).unwrap().check_consistency().is_err());

        // A superseded entry whose receipt is the superseded context's own.
        let s = Change::superseded(
            1,
            CtxId::parse(CTX).unwrap(),
            AgentDid::new(AGENT),
            &receipt_for(CTX, "2026-10-04T00:00:00.000Z"),
        )
        .unwrap();
        assert!(s.check_consistency().is_err());
    }

    #[test]
    fn changes_response_needs_cursor_and_ascending_seq() {
        let c = serde_json::to_value(lifecycle_change()).unwrap();
        let ok = json!({"changes": [c], "next_cursor": "c2VxOjEwNDI", "has_more": false});
        ChangesResponse::from_value(&ok).unwrap();
        for bad in [
            json!({"changes": [], "has_more": false}),
            json!({"changes": [], "next_cursor": "", "has_more": false}),
            json!({"changes": [], "next_cursor": "x".repeat(2049), "has_more": false}),
            json!({"changes": [c, c], "next_cursor": "c", "has_more": false}),
            json!({"changes": [], "next_cursor": "c", "has_more": false, "x": 1}),
        ] {
            assert!(ChangesResponse::from_value(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn watch_filter_semantics() {
        let l = lifecycle_change();
        let k = Change::key_revocation(
            1057,
            AgentDid::new(AGENT),
            &receipt_for(NEW, "2026-10-05T00:00:00.000Z"),
        )
        .unwrap();
        let none = |_: &CtxId| None;
        assert!(WatchFilter::new().matches(&l, none));
        // OR across members, AND with kind.
        let f = WatchFilter::new()
            .ctx_id(CtxId::parse(NEW).unwrap())
            .lineage_id(LineageId::parse(LIN).unwrap());
        assert!(f.matches(&l, none));
        assert!(!f.clone().kind(ChangeKind::Superseded).matches(&l, none));
        assert!(WatchFilter::new()
            .agent_id(AgentDid::new(AGENT))
            .matches(&l, none));
        // A ctx_id watch hears its producer's key revocation...
        let other_ctx = "acdp://registry.example.com/dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        let watch = WatchFilter::new().ctx_id(CtxId::parse(other_ctx).unwrap());
        assert!(watch.matches(&k, |_| Some(AgentDid::new(AGENT))));
        assert!(!watch.matches(&k, |_| Some(AgentDid::new("did:web:other.example.com"))));
        // ...but not its producer's other lifecycle events.
        assert!(!watch.matches(&l, |_| Some(AgentDid::new(AGENT))));
        assert_eq!(
            f.query_pairs(),
            vec![("ctx_id", NEW.to_string()), ("lineage_id", LIN.to_string())]
        );
        assert!(WatchFilter::new()
            .kind(ChangeKind::Lifecycle)
            .kind(ChangeKind::Superseded)
            .validate(Some(1))
            .is_err());
    }

    #[test]
    fn subscription_objects_validate() {
        let req = json!({
            "filter": {"lineage_id": [LIN], "kind": ["lifecycle", "key_revocation"]},
            "callback_url": "https://consumer.example.com/acdp/hints"
        });
        let r = SubscriptionRequest::from_value(&req).unwrap();
        assert_eq!(serde_json::to_value(&r).unwrap(), req);
        for bad in [
            json!({"filter": {}, "callback_url": "https://c.example.com/"}),
            json!({"filter": {"kind": []}, "callback_url": "https://c.example.com/"}),
            json!({"filter": {"kind": ["lifecycle", "lifecycle"]}, "callback_url": "https://c.example.com/"}),
            json!({"filter": {"kind": ["lifecycle"]}, "callback_url": "http://c.example.com/"}),
            json!({"filter": {"kind": ["lifecycle"]}, "callback_url": "https:///path"}),
            json!({"filter": {"x": ["y"]}, "callback_url": "https://c.example.com/"}),
        ] {
            assert!(SubscriptionRequest::from_value(&bad).is_err(), "{bad}");
        }

        let created = json!({
            "subscription_id": "6f1c2a9e-3b4d-4e5f-8a6b-7c8d9e0f1a2b",
            "filter": {"lineage_id": [LIN]},
            "callback_url": "https://consumer.example.com/acdp/hints",
            "created_at": "2026-10-01T00:00:00.000Z",
            "status": "active",
            "secret": "q4C3i0gxkC8b7mSx2F5fW1dTnYp9Z0eLrJvH6uK3oAM="
        });
        let s = Subscription::from_value(&created).unwrap();
        assert_eq!(serde_json::to_value(&s).unwrap(), created);
        let served = serde_json::to_value(s.without_secret()).unwrap();
        assert!(served.get("secret").is_none());
        let mut short = created.clone();
        short["secret"] = json!("c2hvcnQ=");
        assert!(Subscription::from_value(&short).is_err());
        let mut upper = created.clone();
        upper["subscription_id"] = json!("6F1C2A9E-3B4D-4E5F-8A6B-7C8D9E0F1A2B");
        assert!(Subscription::from_value(&upper).is_err());
    }

    #[test]
    fn hint_parses() {
        let h = json!({
            "hint_version": "acdp-change-hint/1",
            "subscription_id": "6f1c2a9e-3b4d-4e5f-8a6b-7c8d9e0f1a2b",
            "registry_authority": "registry.example.com",
            "head_cursor": "c2VxOjEwNTc"
        });
        let parsed = ChangeHint::from_value(&h).unwrap();
        assert_eq!(
            parsed,
            ChangeHint::new(
                "6f1c2a9e-3b4d-4e5f-8a6b-7c8d9e0f1a2b",
                "registry.example.com",
                "c2VxOjEwNTc"
            )
        );
        let mut content = h.clone();
        content["changes"] = json!([]);
        assert!(ChangeHint::from_value(&content).is_err());
    }

    /// The HMAC-SHA-256 primitive against RFC 4231 test case 2.
    #[test]
    fn hmac_primitive_matches_rfc_4231() {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac.finalize().into_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// Spec KAT `hint-hmac-001` (rec-007 `vectors[0]`): the key is the
    /// secret string's UTF-8 bytes; the decoded-key MAC must not verify.
    #[test]
    fn hint_hmac_001() {
        let secret = "q4C3i0gxkC8b7mSx2F5fW1dTnYp9Z0eLrJvH6uK3oAM=";
        let body = br#"{"head_cursor":"c2VxOjEwNTc","hint_version":"acdp-change-hint/1","registry_authority":"registry.example.com","subscription_id":"6f1c2a9e-3b4d-4e5f-8a6b-7c8d9e0f1a2b"}"#;
        let t = 1_790_985_602;
        let expected =
            "t=1790985602,v1=a000c589a805e6a5ed4eeb7835a9e8051a879d067c17c86c3de28862f9e489de";
        let not =
            "t=1790985602,v1=3b096f13ceb0ff06e1f51542614551007d2a8547f8df1a6f5f38daa26d5f0aed";
        assert_eq!(sign_hint(secret, t, body), expected);
        let now = DateTime::from_timestamp(t, 0).unwrap();
        verify_hint_signature(secret, expected, body, now).unwrap();
        assert!(verify_hint_signature(secret, not, body, now).is_err());
    }

    #[test]
    fn hint_signature_round_trip_and_rejections() {
        let secret = "q4C3i0gxkC8b7mSx2F5fW1dTnYp9Z0eLrJvH6uK3oAM=";
        let body = br#"{"hint_version":"acdp-change-hint/1"}"#;
        let t = 1_790_000_000_i64;
        let now = DateTime::from_timestamp(t, 0).unwrap();
        let header = sign_hint(secret, t, body);
        assert!(header.starts_with(&format!("t={t},v1=")));
        verify_hint_signature(secret, &header, body, now).unwrap();
        // Order-insensitive, extra members ignored, any v1 may match.
        let v1 = header.split_once(",v1=").unwrap().1;
        verify_hint_signature(secret, &format!("v1={v1}, t={t},v2=zz"), body, now).unwrap();
        verify_hint_signature(
            secret,
            &format!("t={t},v1={},v1={v1}", "00".repeat(32)),
            body,
            now,
        )
        .unwrap();
        // Skew: 300 s passes, 301 s fails, both directions.
        for (d, ok) in [(300, true), (-300, true), (301, false), (-301, false)] {
            let r =
                verify_hint_signature(secret, &header, body, now + chrono::Duration::seconds(d));
            assert_eq!(r.is_ok(), ok, "skew {d}");
        }
        // Wrong v1, wrong secret, changed body, malformed headers.
        let mut flipped = header.clone();
        let last = flipped.pop().unwrap();
        flipped.push(if last == '0' { '1' } else { '0' });
        for (s, h, b) in [
            (secret, flipped.as_str(), &body[..]),
            (
                "another-secret-another-secret-another-secret",
                header.as_str(),
                &body[..],
            ),
            (secret, header.as_str(), &b"{}"[..]),
            (secret, "v1=00", &body[..]),
            (secret, &format!("t={t}"), &body[..]),
            (secret, &format!("t=-{t},v1={v1}"), &body[..]),
            (secret, &format!("t={t},t={t},v1={v1}"), &body[..]),
            (secret, "garbage", &body[..]),
        ] {
            assert!(
                matches!(
                    verify_hint_signature(s, h, b, now),
                    Err(AcdpError::NotAuthorized(_))
                ),
                "{h} accepted"
            );
        }
    }
}
