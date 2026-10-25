//! `verify_chain` options (RFC-ACDP-0017 §6): the as-of instant, walk
//! limits, pinned trust and `require_attested_events`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{options, ChainError};
use crate::syntax::{fmt_ts, is_did, is_hostname, jcs_digest, parse_ts};

/// The RFC-ACDP-0006 §4.1 walk controls (§6.1(4)). Each one truncates the
/// walk; none aborts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// A node at this depth is verified but not expanded. `0..=10`.
    pub max_depth: u32,
    /// No node is admitted beyond this many. `1..=500`.
    pub max_nodes: u32,
    /// Only the first this-many distinct `derived_from` entries of a node
    /// are admitted. `0..=100`.
    pub max_fanout: u32,
}

impl Limits {
    /// The defaults, which are also the maxima: 10 / 500 / 100.
    pub const DEFAULT: Limits = Limits {
        max_depth: 10,
        max_nodes: 500,
        max_fanout: 100,
    };

    /// Reject a limit above its default or below the schema minimum.
    pub fn check(&self) -> Result<(), ChainError> {
        if self.max_depth > Self::DEFAULT.max_depth {
            return Err(options(format!(
                "max_depth {} exceeds the default {} (RFC-ACDP-0017 §6.1(4))",
                self.max_depth,
                Self::DEFAULT.max_depth
            )));
        }
        if self.max_nodes == 0 || self.max_nodes > Self::DEFAULT.max_nodes {
            return Err(options(format!(
                "max_nodes {} is outside 1..={} (RFC-ACDP-0017 §6.1(4))",
                self.max_nodes,
                Self::DEFAULT.max_nodes
            )));
        }
        if self.max_fanout > Self::DEFAULT.max_fanout {
            return Err(options(format!(
                "max_fanout {} exceeds the default {} (RFC-ACDP-0017 §6.1(4))",
                self.max_fanout,
                Self::DEFAULT.max_fanout
            )));
        }
        Ok(())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A caller-vouched DID-document snapshot (§6.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PinnedSnapshot {
    /// The DID (never `did:key`).
    pub did: String,
    /// The DID document the caller vouches for.
    pub document: Map<String, Value>,
    /// The instant at which the caller vouches for it; it takes part in
    /// §6.2 selection as an `observed_at` would.
    pub instant: String,
}

impl PinnedSnapshot {
    /// A pinned snapshot.
    pub fn new(
        did: impl Into<String>,
        document: Map<String, Value>,
        instant: impl Into<String>,
    ) -> Self {
        Self {
            did: did.into(),
            document,
            instant: instant.into(),
        }
    }
}

/// Pinned trust (§6.3), `acdp-evidence.schema.json#/$defs/pinned`.
///
/// Members may be given in any order and with duplicates; the verifier
/// normalizes before use and before computing `options_digest`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Pinned {
    /// Caller-vouched snapshots: basis `pinned`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snapshots: Vec<PinnedSnapshot>,
    /// Registry DIDs whose receipt keys the caller trusts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registries: Vec<String>,
    /// Trusted witness DIDs; only these count toward `log.witnesses`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witnesses: Vec<String>,
    /// Discovery vantages whose records the caller vouches for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vantages: Vec<String>,
}

impl Pinned {
    /// Parse the JSON form, closed (§6.3); `null` is the empty pin set.
    /// An empty array member is
    /// rejected here, as the schema's `minItems: 1` requires; build the
    /// struct directly to have empties dropped instead.
    pub fn from_value(value: &Value) -> Result<Self, ChainError> {
        // `pinned: null` is equivalent to absent or `{}` (§6.3).
        if value.is_null() {
            return Ok(Pinned::default());
        }
        let obj = value
            .as_object()
            .ok_or_else(|| options("pinned must be a JSON object"))?;
        for (k, v) in obj {
            if v.as_array().is_some_and(|a| a.is_empty()) {
                return Err(options(format!("pinned.{k} is empty (minItems 1)")));
            }
        }
        let pinned: Pinned = serde_json::from_value(value.clone())
            .map_err(|e| options(format!("pinned does not parse: {e}")))?;
        for (k, list) in [
            ("registries", &pinned.registries),
            ("witnesses", &pinned.witnesses),
            ("vantages", &pinned.vantages),
        ] {
            let mut seen = std::collections::BTreeSet::new();
            if !list.iter().all(|s| seen.insert(s)) {
                return Err(options(format!("pinned.{k} has duplicates (uniqueItems)")));
            }
        }
        pinned.check()?;
        Ok(pinned)
    }

    /// Check every member's form.
    pub fn check(&self) -> Result<(), ChainError> {
        // One DID pinned twice at one instant must carry one document;
        // two different documents leave §6.2 selection undefined.
        let mut at: std::collections::BTreeMap<(&str, &str), &Map<String, Value>> =
            std::collections::BTreeMap::new();
        for s in &self.snapshots {
            if let Some(prev) = at.insert((&s.did, &s.instant), &s.document) {
                if prev != &s.document {
                    return Err(options(format!(
                        "pinned snapshots for '{}' at {} carry different documents \
                         (RFC-ACDP-0017 §6.3)",
                        s.did, s.instant
                    )));
                }
            }
        }
        for s in &self.snapshots {
            if !is_did(&s.did) || s.did.starts_with("did:key:") {
                return Err(options(format!(
                    "pinned snapshot did '{}' is not a non-did:key DID (RFC-ACDP-0017 §6.3)",
                    s.did
                )));
            }
            if parse_ts(&s.instant).is_none() {
                return Err(options(format!(
                    "pinned snapshot instant '{}' is not a canonical millisecond timestamp",
                    s.instant
                )));
            }
        }
        for d in self.registries.iter().chain(&self.witnesses) {
            if !is_did(d) {
                return Err(options(format!("pinned DID '{d}' is not a DID")));
            }
        }
        for h in &self.vantages {
            if !is_hostname(h) {
                return Err(options(format!("pinned vantage '{h}' is not a hostname")));
            }
        }
        Ok(())
    }

    /// The §6.3 normal form: arrays byte-sorted and deduplicated,
    /// snapshots sorted by `did` then `instant` and deduplicated.
    pub fn normalized(&self) -> Pinned {
        fn sorted(v: &[String]) -> Vec<String> {
            let mut v = v.to_vec();
            v.sort();
            v.dedup();
            v
        }
        let mut snapshots = self.snapshots.clone();
        // `check` rejects one DID pinned at one instant with two
        // documents, so (did, instant) orders totally.
        snapshots.sort_by(|a, b| (&a.did, &a.instant).cmp(&(&b.did, &b.instant)));
        snapshots.dedup();
        Pinned {
            snapshots,
            registries: sorted(&self.registries),
            witnesses: sorted(&self.witnesses),
            vantages: sorted(&self.vantages),
        }
    }

    /// True when nothing is pinned (absent and `{}` are equivalent).
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
            && self.registries.is_empty()
            && self.witnesses.is_empty()
            && self.vantages.is_empty()
    }

    /// `options_digest` (§9.1): `sha256:` + hex(SHA-256(JCS(normalized))),
    /// or `None` when nothing is pinned.
    pub fn digest(&self) -> Option<String> {
        if self.is_empty() {
            None
        } else {
            Some(jcs_digest(&self.normalized()))
        }
    }
}

/// The options for one `verify_chain` run.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Options {
    /// T. `None` runs the latest pass only. Must be millisecond-aligned.
    pub as_of: Option<DateTime<Utc>>,
    /// The walk controls.
    pub limits: Limits,
    /// Pinned trust; `None` and an empty [`Pinned`] are equivalent.
    pub pinned: Option<Pinned>,
    /// §6.4. Defaults to `true`.
    pub require_attested_events: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            as_of: None,
            limits: Limits::DEFAULT,
            pinned: None,
            require_attested_events: true,
        }
    }
}

impl Options {
    /// Default options with T set.
    pub fn as_of(t: DateTime<Utc>) -> Self {
        Self {
            as_of: Some(t),
            ..Self::default()
        }
    }

    /// Set the limits.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Set pinned trust.
    pub fn with_pinned(mut self, pinned: Pinned) -> Self {
        self.pinned = Some(pinned);
        self
    }

    /// Set `require_attested_events`.
    pub fn with_require_attested_events(mut self, require: bool) -> Self {
        self.require_attested_events = require;
        self
    }

    pub(crate) fn check(&self) -> Result<(), ChainError> {
        self.limits.check()?;
        if let Some(t) = self.as_of {
            if parse_ts(&fmt_ts(t)) != Some(t) {
                return Err(options(
                    "as_of is not millisecond-aligned (RFC-ACDP-0001 §5.3)",
                ));
            }
        }
        if let Some(p) = &self.pinned {
            p.check()?;
        }
        Ok(())
    }
}
