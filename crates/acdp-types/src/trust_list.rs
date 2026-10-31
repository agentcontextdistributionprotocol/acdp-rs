//! Registry trust lists — RFC-ACDP-0020 (Final at 0.5.0).
//!
//! A trust list is an ordinary body of type `acdp:trust-list` whose
//! `metadata` is an `acdp-trust-list/1` object ([`TrustList`]). This
//! module holds the pure, offline part of the consumer profile
//! `acdp-consumer-trust-list`:
//!
//! - [`TrustList::from_metadata`]: the closed §4.2 object plus the §5.2
//!   step 4 runtime checks;
//! - [`select_version`]: §5.3–§5.4 series state (floor, rollback,
//!   equivocation, retraction, list window) for one [`IssuerPin`];
//! - [`evaluate`]: §6.2 for one verified body;
//! - [`TrustReport`]: the deterministic §8 `acdp-trust-report/1` object.
//!
//! Verifying a candidate list body (§5.2 steps 1, 3 and 5) needs the
//! producer-signature pipeline and lives in `acdp_verify::trust`; the
//! bundle-wide trust step lives in `acdp_chain`, and fetching with a
//! persisted floor in `acdp_client::trust`.

use std::collections::BTreeSet;

use acdp_primitives::error::AcdpError;
use acdp_primitives::time::fmt_rfc3339_ms;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::receipt::is_canonical_ms_utc;

/// The body `type` of a trust list (§4.1).
pub const TRUST_LIST_TYPE: &str = "acdp:trust-list";
/// `trust_list_version` (§4.2).
pub const TRUST_LIST_VERSION: &str = "acdp-trust-list/1";
/// The RECOMMENDED `schema_uri` of a trust list (§4.1).
pub const TRUST_LIST_SCHEMA_URI: &str =
    "https://schemas.acdp.io/v0.1.0/acdp-trust-list.schema.json";
/// `trust_report_version` (§8).
pub const TRUST_REPORT_VERSION: &str = "acdp-trust-report/1";
/// The profile name that, in `required_profiles`, also requires a
/// verified receipt (§4.2, §6.2 step 2.3).
pub const RECEIPTS_PROFILE: &str = "acdp-registry-receipts";
/// Maximum `entries` (§4.2).
pub const MAX_ENTRIES: usize = 1000;

// ── §4.2 the acdp-trust-list/1 object ──────────────────────────────────────

/// The `acdp-trust-list/1` metadata of a trust list (§4.2). Closed at
/// every level; build it with [`TrustList::from_metadata`], which also
/// runs the §5.2 step 4 checks the schema cannot express.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustList {
    /// Always [`TRUST_LIST_VERSION`].
    pub trust_list_version: String,
    /// The issuer-chosen series name, `^[a-z0-9][a-z0-9._-]{0,127}$`.
    pub list_id: String,
    /// Strictly increasing within the series (≥ 1).
    pub serial: u64,
    /// When the issuer signed this version (§5.4 as-of selection).
    #[serde(with = "ms")]
    pub issued_at: DateTime<Utc>,
    /// Start of the list window (inclusive).
    #[serde(with = "ms")]
    pub valid_from: DateTime<Utc>,
    /// End of the list window (exclusive). Mandatory, so a list that
    /// stops being refreshed stops working.
    #[serde(with = "ms")]
    pub valid_until: DateTime<Utc>,
    /// The trusted registries (0–1000). Empty trusts nothing.
    pub entries: Vec<TrustListEntry>,
}

/// One trusted registry (§4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustListEntry {
    /// `did:web:` + [`Self::origin`].
    pub registry_did: String,
    /// The registry authority as bodies name it: a lowercase hostname,
    /// no port (§4.3).
    pub origin: String,
    /// Pins the registry's receipt-signing keys (RFC-ACDP-0010 §6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_key_fingerprints: Option<Vec<String>>,
    /// Profiles the registry must advertise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_profiles: Option<Vec<String>>,
    /// Which bodies from this registry are trusted. Absent: all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<TrustScope>,
    /// Narrows the list window for this entry (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "ms_opt")]
    pub valid_from: Option<DateTime<Utc>>,
    /// Narrows the list window for this entry (exclusive).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "ms_opt")]
    pub valid_until: Option<DateTime<Utc>>,
}

/// An entry's scope (§4.2). Every present member is a constraint;
/// `agent_ids` and `agent_id_prefixes` together form one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustScope {
    /// Exact producer DIDs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_ids: Option<Vec<String>>,
    /// String prefixes of `agent_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id_prefixes: Option<Vec<String>>,
    /// DID methods, e.g. `did:web`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_methods: Option<Vec<String>>,
    /// Exact body `type` values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
}

pub(crate) mod ms {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&acdp_primitives::time::fmt_rfc3339_ms(*t))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(d)?;
        super::parse_ms(&raw).map_err(serde::de::Error::custom)
    }
}

mod ms_opt {
    use chrono::{DateTime, Utc};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => super::ms::serialize(t, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
        super::ms::deserialize(d).map(Some)
    }
}

fn parse_ms(raw: &str) -> Result<DateTime<Utc>, String> {
    if !is_canonical_ms_utc(raw) {
        return Err(format!(
            "'{raw}' is not a canonical millisecond RFC 3339 UTC timestamp"
        ));
    }
    DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| e.to_string())
}

fn fail(msg: impl std::fmt::Display) -> AcdpError {
    AcdpError::SchemaViolation(format!("trust list: {msg}"))
}

/// `^[a-z0-9][a-z0-9._-]{0,127}$`.
pub fn is_list_id(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=128).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// `acdp-common.schema.json#/$defs/hostname`.
fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            let b = label.as_bytes();
            !b.is_empty()
                && b.iter()
                    .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
        })
}

/// `acdp-common.schema.json#/$defs/did`.
fn is_did(s: &str) -> bool {
    let Some((method, id)) = s.strip_prefix("did:").and_then(|r| r.split_once(':')) else {
        return false;
    };
    (7..=2048).contains(&s.len())
        && is_method_name(method)
        && !id.is_empty()
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'%' | b'-'))
}

fn is_method_name(m: &str) -> bool {
    !m.is_empty()
        && m.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// `acdp-common.schema.json#/$defs/context_type`.
fn is_context_type(s: &str) -> bool {
    if matches!(
        s,
        "data_snapshot" | "analysis" | "prediction" | "alert" | "key-revocation"
    ) {
        return true;
    }
    let ident = |p: &str, extra: &[u8]| {
        let b = p.as_bytes();
        !b.is_empty()
            && b[0].is_ascii_lowercase()
            && b.iter().all(|&c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || extra.contains(&c)
            })
    };
    s.split_once(':')
        .is_some_and(|(ns, name)| ident(ns, b"") && ident(name, b"-"))
}

fn is_sha256(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

fn is_profile(s: &str) -> bool {
    s.len() <= 64
        && s.strip_prefix("acdp-").is_some_and(|r| {
            let b = r.as_bytes();
            !b.is_empty()
                && b[0].is_ascii_lowercase()
                && b.iter()
                    .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

fn string_array(
    items: &[String],
    what: &str,
    max: usize,
    ok: impl Fn(&str) -> bool,
) -> Result<(), AcdpError> {
    if items.is_empty() || items.len() > max {
        return Err(fail(format!("{what} must have 1..={max} items")));
    }
    if let Some(bad) = items.iter().find(|s| !ok(s)) {
        return Err(fail(format!("{what} item '{bad}' is malformed")));
    }
    if items.iter().collect::<BTreeSet<_>>().len() != items.len() {
        return Err(fail(format!("{what} items must be unique")));
    }
    Ok(())
}

impl TrustList {
    /// Parse and validate a list body's `metadata` (§4.2, §5.2 step 4):
    /// the closed schema, `valid_from < valid_until`, and every entry's
    /// `registry_did` equal to `did:web:` + its `origin`.
    pub fn from_metadata(metadata: &Value) -> Result<Self, AcdpError> {
        let list = Self::deserialize(metadata).map_err(fail)?;
        list.validate()?;
        Ok(list)
    }

    fn validate(&self) -> Result<(), AcdpError> {
        if self.trust_list_version != TRUST_LIST_VERSION {
            return Err(fail(format!(
                "trust_list_version '{}' is not '{TRUST_LIST_VERSION}'",
                self.trust_list_version
            )));
        }
        if !is_list_id(&self.list_id) {
            return Err(fail(format!("list_id '{}' is malformed", self.list_id)));
        }
        if self.serial < 1 {
            return Err(fail("serial must be ≥ 1"));
        }
        if self.valid_from >= self.valid_until {
            return Err(fail("valid_from must be before valid_until"));
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(fail(format!("entries holds more than {MAX_ENTRIES}")));
        }
        for (i, e) in self.entries.iter().enumerate() {
            e.validate()
                .map_err(|err| fail(format!("entries[{i}]: {err}")))?;
        }
        Ok(())
    }
}

impl TrustListEntry {
    fn validate(&self) -> Result<(), String> {
        if !is_hostname(&self.origin) {
            return Err(format!(
                "origin '{}' is not a lowercase hostname without a port (§4.3)",
                self.origin
            ));
        }
        let did_ok = self
            .registry_did
            .strip_prefix("did:web:")
            .is_some_and(is_hostname);
        if !did_ok {
            return Err(format!(
                "registry_did '{}' is not a did:web DID",
                self.registry_did
            ));
        }
        if self.registry_did != format!("did:web:{}", self.origin) {
            return Err(format!(
                "registry_did '{}' is not did:web: + origin '{}' (§4.2)",
                self.registry_did, self.origin
            ));
        }
        let check = |r: Result<(), AcdpError>| r.map_err(|e| e.to_string());
        if let Some(fps) = &self.receipt_key_fingerprints {
            check(string_array(fps, "receipt_key_fingerprints", 16, is_sha256))?;
        }
        if let Some(p) = &self.required_profiles {
            check(string_array(p, "required_profiles", 32, is_profile))?;
        }
        if let Some(s) = &self.scope {
            if s == &TrustScope::default() {
                return Err("scope must have at least one member".into());
            }
            if let Some(v) = &s.agent_ids {
                check(string_array(v, "scope.agent_ids", 1000, is_did))?;
            }
            if let Some(v) = &s.agent_id_prefixes {
                let prefix = |p: &str| {
                    p.len() <= 512
                        && p.strip_prefix("did:")
                            .and_then(|r| r.split_once(':'))
                            .is_some_and(|(m, _)| is_method_name(m))
                };
                check(string_array(v, "scope.agent_id_prefixes", 100, prefix))?;
            }
            if let Some(v) = &s.did_methods {
                let method = |m: &str| m.strip_prefix("did:").is_some_and(is_method_name);
                check(string_array(v, "scope.did_methods", 16, method))?;
            }
            if let Some(v) = &s.types {
                check(string_array(v, "scope.types", 100, is_context_type))?;
            }
        }
        Ok(())
    }

    fn requires_receipt(&self) -> bool {
        self.receipt_key_fingerprints.is_some()
            || self
                .required_profiles
                .as_ref()
                .is_some_and(|p| p.iter().any(|n| n == RECEIPTS_PROFILE))
    }
}

// ── §5 pins, versions and selection ────────────────────────────────────────

/// An issuer pin (§5.1): the root of trust. It comes from configuration
/// only — never from a list, a registry, a capabilities document or an
/// evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IssuerPin {
    /// The issuer DID (`body.agent_id` of its lists).
    pub issuer: String,
    /// The pinned series.
    pub list_id: String,
    /// When set, only these issuer keys (RFC-ACDP-0010 §6 fingerprints)
    /// may sign the list (§5.2 step 3).
    pub issuer_key_fingerprints: Option<BTreeSet<String>>,
}

impl IssuerPin {
    /// A pin on `issuer`'s `list_id` series, any issuer key.
    pub fn new(issuer: impl Into<String>, list_id: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            list_id: list_id.into(),
            issuer_key_fingerprints: None,
        }
    }

    /// Restrict the issuer keys that may sign the list (§5.2 step 3).
    pub fn with_issuer_key_fingerprints<I, S>(mut self, fingerprints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.issuer_key_fingerprints = Some(fingerprints.into_iter().map(Into::into).collect());
        self
    }

    /// `(issuer, list_id)`: the series key, and the pin order of §6.2
    /// step 4 and §8 (by code point).
    pub fn series(&self) -> (&str, &str) {
        (&self.issuer, &self.list_id)
    }
}

/// One list version that passed §5.2 for its pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListVersion {
    /// The verified metadata.
    pub list: TrustList,
    /// The recomputed `content_hash`.
    pub content_hash: String,
    /// The `ctx_id`, when the version was retrieved from a registry
    /// (absent for an out-of-band publish-request body, §7).
    pub ctx_id: Option<String>,
    /// Withdrawn by an admitted, issuer-signed `retracted` event (§5.3).
    pub retracted: bool,
}

/// A candidate's failure of §5.2: the version is ignored, as if absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRejected {
    /// The §5.2 step (1–5).
    pub step: u8,
    /// What failed.
    pub reason: String,
}

impl std::fmt::Display for ListRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "trust list version ignored (§5.2 step {}): {}",
            self.step, self.reason
        )
    }
}

impl std::error::Error for ListRejected {}

/// What the producer-signature pipeline established about a candidate
/// list body (§5.2 steps 1, 3 and 5), from whichever pipeline verified
/// it: `acdp_verify::trust` offline, `acdp_client::trust` online, or the
/// RFC-ACDP-0017 engine for a bundle.
#[derive(Debug, Clone)]
pub struct VerifiedListBody<'a> {
    /// `body.agent_id`.
    pub agent_id: &'a str,
    /// `body.type`.
    pub context_type: &'a str,
    /// `body.metadata`, raw.
    pub metadata: Option<&'a Value>,
    /// The recomputed `content_hash`.
    pub content_hash: &'a str,
    /// `body.ctx_id`, if the body has one.
    pub ctx_id: Option<&'a str>,
    /// The RFC-ACDP-0010 §6 fingerprint of the issuer key that verified
    /// the signature.
    pub issuer_key_fingerprint: Option<&'a str>,
    /// RFC-ACDP-0014 §7 refused the issuer key for this body (step 5).
    pub issuer_key_revoked: bool,
    /// Withdrawn by an admitted, issuer-signed `retracted` event (§5.3).
    pub retracted: bool,
}

/// §5.2 steps 2–5 over a body whose step 1 already passed.
pub fn validate_list_version(
    pin: &IssuerPin,
    body: &VerifiedListBody<'_>,
) -> Result<ListVersion, ListRejected> {
    let reject = |step: u8, reason: String| ListRejected { step, reason };
    if body.agent_id != pin.issuer {
        return Err(reject(
            2,
            format!("agent_id '{}' is not the pinned issuer", body.agent_id),
        ));
    }
    if body.context_type != TRUST_LIST_TYPE {
        return Err(reject(
            2,
            format!("type '{}' is not '{TRUST_LIST_TYPE}'", body.context_type),
        ));
    }
    let metadata = body
        .metadata
        .ok_or_else(|| reject(2, "no metadata".into()))?;
    if metadata.get("list_id").and_then(Value::as_str) != Some(pin.list_id.as_str()) {
        return Err(reject(
            2,
            "metadata.list_id is not the pinned list_id".into(),
        ));
    }
    if let Some(allowed) = &pin.issuer_key_fingerprints {
        if !body
            .issuer_key_fingerprint
            .is_some_and(|fp| allowed.contains(fp))
        {
            return Err(reject(
                3,
                "the verifying key is not a pinned issuer key".into(),
            ));
        }
    }
    let list = TrustList::from_metadata(metadata).map_err(|e| reject(4, e.to_string()))?;
    if body.issuer_key_revoked {
        return Err(reject(
            5,
            "the issuer key is revoked for this version".into(),
        ));
    }
    Ok(ListVersion {
        list,
        content_hash: body.content_hash.to_string(),
        ctx_id: body.ctx_id.map(str::to_string),
        retracted: body.retracted,
    })
}

/// Which RFC-ACDP-0017 pass an evaluation belongs to (§5.4, §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustPass {
    /// T is now; the consumer's persisted floor applies.
    Latest,
    /// T is the as-of instant; only versions issued by T count, and the
    /// floor is derived from them.
    AsOf,
}

/// A pin's status in a report (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListStatus {
    /// A selected, in-window version: its entries decide.
    Used,
    /// The selected version's window does not cover T (`list_window`).
    Expired,
    /// No usable version (`no_valid_version`, `rollback`,
    /// `equivocation`, `retracted`).
    Invalid,
}

/// §6 outcome. `Ord` is the §6.2 precedence: `Trusted` is best.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustOutcome {
    /// Reliance permitted. The only such outcome.
    Trusted,
    /// A window (list or entry) does not cover T.
    Expired,
    /// The registry is trusted, but not for this body.
    OutOfScope,
    /// The registry is not trusted for this body.
    UntrustedRegistry,
    /// No usable list version.
    ListInvalid,
}

/// The reason accompanying a non-`trusted` outcome or a non-`used` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustReason {
    /// `ctx_id` authority ≠ `origin_registry` (§6.2 step 1).
    OriginMismatch,
    /// The verified receipt names another registry DID.
    RegistryMismatch,
    /// A verified receipt is required and absent.
    ReceiptRequired,
    /// The receipt's registry key is not pinned.
    ReceiptKeyUnpinned,
    /// The capabilities lack a required profile.
    ProfileMissing,
    /// The entry window does not cover T.
    EntryWindow,
    /// `agent_id` fails the agent constraint.
    ScopeAgent,
    /// The `agent_id` DID method fails `did_methods`.
    ScopeDidMethod,
    /// `type` fails `types`.
    ScopeType,
    /// No entry names the body's registry.
    NoEntry,
    /// The selected version's window does not cover T.
    ListWindow,
    /// No valid version (or no pins at all).
    NoValidVersion,
    /// Every held version is below the floor.
    Rollback,
    /// Two valid versions share the top serial with different hashes.
    Equivocation,
    /// The top version is retracted by its issuer.
    Retracted,
}

/// §5.4's result for one pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinState {
    /// The pin.
    pub pin: IssuerPin,
    /// `used`, `expired` or `invalid`.
    pub status: ListStatus,
    /// The selected version, for `used` and `expired`.
    pub version: Option<ListVersion>,
    /// Why the pin is not `used`.
    pub reason: Option<TrustReason>,
}

/// The floor to persist after holding `versions` as valid (§5.3): the
/// highest serial among them, retracted ones included, and never lower
/// than `floor`.
pub fn advance_floor<'a>(
    floor: Option<u64>,
    versions: impl IntoIterator<Item = &'a ListVersion>,
) -> Option<u64> {
    versions
        .into_iter()
        .map(|v| v.list.serial)
        .chain(floor)
        .max()
}

/// Select `pin`'s version for T (§5.4) from its §5.2-valid `versions`.
///
/// In the latest pass `floor` is the consumer's persisted floor. In an
/// as-of pass `floor` is ignored: only versions issued by T are held,
/// and the caller marks as `retracted` only the retractions it admits
/// as of T. The checks run in the fixed §5.4 order: no valid version,
/// rollback, equivocation, retracted, list window.
pub fn select_version(
    pin: &IssuerPin,
    versions: &[ListVersion],
    t: DateTime<Utc>,
    pass: TrustPass,
    floor: Option<u64>,
) -> PinState {
    let state = |status, version: Option<&ListVersion>, reason| PinState {
        pin: pin.clone(),
        status,
        version: version.cloned(),
        reason,
    };
    let held: Vec<&ListVersion> = versions
        .iter()
        .filter(|v| pass == TrustPass::Latest || v.list.issued_at <= t)
        .collect();
    let Some(top) = held.iter().map(|v| v.list.serial).max() else {
        return state(ListStatus::Invalid, None, Some(TrustReason::NoValidVersion));
    };
    if pass == TrustPass::Latest && floor.is_some_and(|f| top < f) {
        return state(ListStatus::Invalid, None, Some(TrustReason::Rollback));
    }
    let at_top: Vec<&ListVersion> = held.into_iter().filter(|v| v.list.serial == top).collect();
    if at_top
        .iter()
        .map(|v| v.content_hash.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        > 1
    {
        return state(ListStatus::Invalid, None, Some(TrustReason::Equivocation));
    }
    // One content_hash at the top; the same bytes from several registries
    // are one version, retracted if any copy's admitted events retract it.
    if at_top.iter().any(|v| v.retracted) {
        return state(ListStatus::Invalid, None, Some(TrustReason::Retracted));
    }
    let selected = at_top
        .iter()
        .find(|v| v.ctx_id.is_some())
        .unwrap_or(&at_top[0]);
    if !(selected.list.valid_from <= t && t < selected.list.valid_until) {
        return state(
            ListStatus::Expired,
            Some(selected),
            Some(TrustReason::ListWindow),
        );
    }
    state(ListStatus::Used, Some(selected), None)
}

// ── §6 evaluating a body ───────────────────────────────────────────────────

/// The fields of B that §6.2 reads, from a body that already passed
/// RFC-ACDP-0001 §5.11.
#[derive(Debug, Clone, Copy)]
pub struct TrustSubject<'a> {
    /// `ctx_id`.
    pub ctx_id: &'a str,
    /// `origin_registry`.
    pub origin_registry: &'a str,
    /// `agent_id`.
    pub agent_id: &'a str,
    /// `type`.
    pub context_type: &'a str,
}

impl<'a> TrustSubject<'a> {
    /// The subject fields of a verified body.
    pub fn of(body: &'a crate::body::Body, context_type: &'a str) -> Self {
        Self {
            ctx_id: body.ctx_id.as_str(),
            origin_registry: &body.origin_registry,
            agent_id: body.agent_id.as_str(),
            context_type,
        }
    }
}

/// R of §6.1: B's registry receipt, present only when it verified under
/// RFC-ACDP-0010 §8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptInput {
    /// The receipt's `registry_did`.
    pub registry_did: String,
    /// The RFC-ACDP-0010 §6 fingerprint of the registry key that signed
    /// the receipt — not the receipt's `key_fingerprint` member, which
    /// names the producer's key.
    pub registry_key_fingerprint: String,
}

/// One evaluated body: a `nodes` element of the §8 report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeTrust {
    /// The body's `ctx_id`.
    pub ctx_id: String,
    /// The §6 outcome.
    pub outcome: TrustOutcome,
    /// Absent for `trusted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<TrustReason>,
    /// Whether C (the capabilities profiles) was supplied (§6.3).
    pub profiles_checked: bool,
    /// The deciding pin's issuer, when an entry decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The deciding pin's `list_id`, when an entry decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_id: Option<String>,
    /// The deciding entry, when an entry decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_index: Option<u64>,
}

impl NodeTrust {
    /// Whether reliance is permitted (§6.2: only `trusted`).
    pub fn is_trusted(&self) -> bool {
        self.outcome == TrustOutcome::Trusted
    }
}

fn in_window(from: Option<DateTime<Utc>>, until: Option<DateTime<Utc>>, t: DateTime<Utc>) -> bool {
    from.is_none_or(|f| f <= t) && until.is_none_or(|u| t < u)
}

fn entry_outcome(
    e: &TrustListEntry,
    b: &TrustSubject<'_>,
    origin: &str,
    receipt: Option<&ReceiptInput>,
    capabilities: Option<&[String]>,
    t: DateTime<Utc>,
) -> Option<(TrustOutcome, Option<TrustReason>)> {
    use TrustOutcome::*;
    use TrustReason::*;
    if e.origin != origin {
        return None;
    }
    let refuse = |o, r| Some((o, Some(r)));
    if receipt.is_some_and(|r| r.registry_did != e.registry_did) {
        return refuse(UntrustedRegistry, RegistryMismatch);
    }
    if e.requires_receipt() && receipt.is_none() {
        return refuse(UntrustedRegistry, ReceiptRequired);
    }
    if let (Some(pinned), Some(r)) = (&e.receipt_key_fingerprints, receipt) {
        if !pinned.contains(&r.registry_key_fingerprint) {
            return refuse(UntrustedRegistry, ReceiptKeyUnpinned);
        }
    }
    if let (Some(caps), Some(required)) = (capabilities, &e.required_profiles) {
        if required.iter().any(|p| !caps.contains(p)) {
            return refuse(UntrustedRegistry, ProfileMissing);
        }
    }
    if !in_window(e.valid_from, e.valid_until, t) {
        return refuse(Expired, EntryWindow);
    }
    if let Some(s) = &e.scope {
        if s.agent_ids.is_some() || s.agent_id_prefixes.is_some() {
            let listed = s
                .agent_ids
                .as_ref()
                .is_some_and(|ids| ids.iter().any(|d| d == b.agent_id));
            let prefixed = s
                .agent_id_prefixes
                .as_ref()
                .is_some_and(|ps| ps.iter().any(|p| b.agent_id.starts_with(p.as_str())));
            if !listed && !prefixed {
                return refuse(OutOfScope, ScopeAgent);
            }
        }
        if let Some(methods) = &s.did_methods {
            let method = b
                .agent_id
                .match_indices(':')
                .nth(1)
                .map_or(b.agent_id, |(i, _)| &b.agent_id[..i]);
            if !methods.iter().any(|m| m == method) {
                return refuse(OutOfScope, ScopeDidMethod);
            }
        }
        if let Some(types) = &s.types {
            if !types.iter().any(|ty| ty == b.context_type) {
                return refuse(OutOfScope, ScopeType);
            }
        }
    }
    Some((Trusted, None))
}

/// §6.2: evaluate verified body `b` against the pins' §5.4 states.
///
/// `receipt` is R (only a receipt that verified); `capabilities` is C,
/// the profiles the body's registry advertises, when the consumer
/// fetched its capabilities document. Only [`TrustOutcome::Trusted`]
/// permits reliance.
pub fn evaluate(
    b: &TrustSubject<'_>,
    pins: &[PinState],
    t: DateTime<Utc>,
    receipt: Option<&ReceiptInput>,
    capabilities: Option<&[String]>,
) -> NodeTrust {
    let node = |outcome, reason, decided: Option<(&IssuerPin, usize)>| NodeTrust {
        ctx_id: b.ctx_id.to_string(),
        outcome,
        reason,
        profiles_checked: capabilities.is_some(),
        issuer: decided.map(|(p, _)| p.issuer.clone()),
        list_id: decided.map(|(p, _)| p.list_id.clone()),
        entry_index: decided.map(|(_, i)| i as u64),
    };
    // Step 1, before any case fold of the entries: a body whose identity
    // claims two registries is trusted through neither.
    let authority = b
        .ctx_id
        .strip_prefix("acdp://")
        .unwrap_or(b.ctx_id)
        .split('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let origin = b.origin_registry.to_ascii_lowercase();
    if authority != origin {
        return node(
            TrustOutcome::UntrustedRegistry,
            Some(TrustReason::OriginMismatch),
            None,
        );
    }
    let mut ordered: Vec<&PinState> = pins.iter().collect();
    ordered.sort_by(|a, b| a.pin.series().cmp(&b.pin.series()));
    let mut best: Option<NodeTrust> = None;
    for state in ordered {
        let candidate = match (&state.status, &state.version) {
            (ListStatus::Used, Some(v)) => {
                let mut list_best: Option<NodeTrust> = None;
                for (i, e) in v.list.entries.iter().enumerate() {
                    let Some((o, r)) = entry_outcome(e, b, &origin, receipt, capabilities, t)
                    else {
                        continue;
                    };
                    // Ties keep the lowest index (§6.2 step 3).
                    if list_best.as_ref().is_none_or(|lb| o < lb.outcome) {
                        list_best = Some(node(o, r, Some((&state.pin, i))));
                    }
                }
                list_best.unwrap_or_else(|| {
                    node(
                        TrustOutcome::UntrustedRegistry,
                        Some(TrustReason::NoEntry),
                        None,
                    )
                })
            }
            (ListStatus::Expired, _) => node(TrustOutcome::Expired, state.reason, None),
            _ => node(TrustOutcome::ListInvalid, state.reason, None),
        };
        // Ties keep the earlier pin (§6.2 step 4).
        if best
            .as_ref()
            .is_none_or(|bt| candidate.outcome < bt.outcome)
        {
            best = Some(candidate);
        }
    }
    best.unwrap_or_else(|| {
        node(
            TrustOutcome::ListInvalid,
            Some(TrustReason::NoValidVersion),
            None,
        )
    })
}

// ── §8 the trust report ────────────────────────────────────────────────────

/// One `lists` element of the §8 report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportList {
    /// The pin's issuer.
    pub issuer: String,
    /// The pin's `list_id`.
    pub list_id: String,
    /// `used`, `expired` or `invalid`.
    pub status: ListStatus,
    /// The selected version's serial, for `used` and `expired` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<u64>,
    /// The selected version's `content_hash`, for `used` and `expired`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// The selected version's `ctx_id`, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctx_id: Option<String>,
    /// Why the pin is not `used`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<TrustReason>,
}

impl From<&PinState> for ReportList {
    fn from(s: &PinState) -> Self {
        let version = s
            .version
            .as_ref()
            .filter(|_| matches!(s.status, ListStatus::Used | ListStatus::Expired));
        Self {
            issuer: s.pin.issuer.clone(),
            list_id: s.pin.list_id.clone(),
            status: s.status,
            serial: version.map(|v| v.list.serial),
            content_hash: version.map(|v| v.content_hash.clone()),
            ctx_id: version.and_then(|v| v.ctx_id.clone()),
            reason: s.reason,
        }
    }
}

/// The `acdp-trust-report/1` object (§8). JCS-canonical and
/// deterministic; build it with [`TrustReport::new`], which sorts and
/// seals it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustReport {
    /// Always [`TRUST_REPORT_VERSION`].
    pub trust_report_version: String,
    /// The RFC-ACDP-0017 pass it applies to.
    pub pass: TrustPass,
    /// T, canonical millisecond form.
    pub evaluated_at: String,
    /// The bound RFC-ACDP-0017 verdict's `verdict_digest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_digest: Option<String>,
    /// The bundle digest, when the lists came from a bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
    /// One element per pin, sorted by (`issuer`, `list_id`).
    pub lists: Vec<ReportList>,
    /// One element per evaluated body, sorted by `ctx_id`.
    pub nodes: Vec<NodeTrust>,
    /// `sha256:` + hex(SHA-256(JCS(report without `report_digest`))).
    pub report_digest: String,
}

impl TrustReport {
    /// Assemble and seal a report.
    pub fn new(
        pass: TrustPass,
        t: DateTime<Utc>,
        pins: &[PinState],
        mut nodes: Vec<NodeTrust>,
        verdict_digest: Option<String>,
        evidence_digest: Option<String>,
    ) -> Self {
        let mut lists: Vec<ReportList> = pins.iter().map(ReportList::from).collect();
        lists.sort_by(|a, b| (&a.issuer, &a.list_id).cmp(&(&b.issuer, &b.list_id)));
        nodes.sort_by(|a, b| a.ctx_id.cmp(&b.ctx_id));
        let mut report = Self {
            trust_report_version: TRUST_REPORT_VERSION.to_string(),
            pass,
            evaluated_at: fmt_rfc3339_ms(t),
            verdict_digest,
            evidence_digest,
            lists,
            nodes,
            report_digest: String::new(),
        };
        report.report_digest = report.compute_digest();
        report
    }

    /// The JSON value, `report_digest` included.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("a trust report always serializes")
    }

    /// The JCS bytes of the report.
    pub fn to_jcs(&self) -> Vec<u8> {
        acdp_jcs::canonicalize_value(&self.to_value())
    }

    /// Recompute `report_digest` over the report without it.
    pub fn compute_digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut v = self.to_value();
        if let Value::Object(m) = &mut v {
            m.remove("report_digest");
        }
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(acdp_jcs::canonicalize_value(&v)))
        )
    }

    /// Whether every node is `trusted` — one possible consumer policy
    /// for refusing a chain (§8: combining is the consumer's choice).
    pub fn all_trusted(&self) -> bool {
        self.nodes.iter().all(NodeTrust::is_trusted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    fn list(serial: u64, issued: &str, from: &str, until: &str) -> Value {
        json!({
            "trust_list_version": TRUST_LIST_VERSION,
            "list_id": "tenant-acme.production",
            "serial": serial,
            "issued_at": issued,
            "valid_from": from,
            "valid_until": until,
            "entries": [{"registry_did": "did:web:registry.example.com", "origin": "registry.example.com"}]
        })
    }

    fn version(serial: u64, hash: char, retracted: bool) -> ListVersion {
        ListVersion {
            list: TrustList::from_metadata(&list(
                serial,
                "2026-10-26T00:00:00.000Z",
                "2026-10-01T00:00:00.000Z",
                "2027-04-01T00:00:00.000Z",
            ))
            .unwrap(),
            content_hash: format!("sha256:{}", hash.to_string().repeat(64)),
            ctx_id: None,
            retracted,
        }
    }

    #[test]
    fn metadata_is_closed_and_checked() {
        let ok = list(
            7,
            "2026-10-26T00:00:00.000Z",
            "2026-10-01T00:00:00.000Z",
            "2027-04-01T00:00:00.000Z",
        );
        TrustList::from_metadata(&ok).unwrap();
        let bad = |f: &dyn Fn(&mut Value)| {
            let mut v = ok.clone();
            f(&mut v);
            assert!(TrustList::from_metadata(&v).is_err(), "{v}");
        };
        bad(&|v| v["extra"] = json!(1));
        bad(&|v| v["entries"][0]["extra"] = json!(1));
        bad(&|v| v["entries"][0]["origin"] = json!("registry.example.com:8443"));
        bad(&|v| v["entries"][0]["registry_did"] = json!("did:web:evil.example.com"));
        bad(&|v| v["valid_from"] = json!("2027-05-01T00:00:00.000Z"));
        bad(&|v| v["valid_from"] = json!("2026-10-01T00:00:00Z"));
        bad(&|v| v["serial"] = json!(0));
        bad(&|v| v["serial"] = json!(7.5));
        bad(&|v| v["list_id"] = json!("Tenant"));
        bad(&|v| v["entries"][0]["scope"] = json!({}));
        bad(&|v| v["entries"][0]["scope"] = json!({"types": []}));
        bad(&|v| v["entries"][0]["scope"] = json!({"types": ["Bad"]}));
        bad(&|v| v["entries"][0]["receipt_key_fingerprints"] = json!(["sha256:AB"]));
    }

    #[test]
    fn selection_order() {
        let pin = IssuerPin::new("did:key:z6Mk", "tenant-acme.production");
        let t = at("2026-10-27T00:00:00.000Z");
        let pick =
            |vs: &[ListVersion], floor| select_version(&pin, vs, t, TrustPass::Latest, floor);
        assert_eq!(pick(&[], None).reason, Some(TrustReason::NoValidVersion));
        assert_eq!(
            pick(&[version(5, 'a', false)], Some(7)).reason,
            Some(TrustReason::Rollback)
        );
        let eq = [version(8, 'a', false), version(8, 'b', true)];
        assert_eq!(pick(&eq, Some(7)).reason, Some(TrustReason::Equivocation));
        let same = [version(8, 'a', false), version(8, 'a', false)];
        assert_eq!(pick(&same, Some(8)).status, ListStatus::Used);
        let retracted = [version(6, 'c', false), version(7, 'a', true)];
        assert_eq!(
            pick(&retracted, Some(7)).reason,
            Some(TrustReason::Retracted)
        );
        assert_eq!(advance_floor(Some(6), &retracted), Some(7));
        let late = select_version(
            &pin,
            &[version(7, 'a', false)],
            at("2027-05-01T00:00:00.000Z"),
            TrustPass::Latest,
            None,
        );
        assert_eq!(
            (late.status, late.reason),
            (ListStatus::Expired, Some(TrustReason::ListWindow))
        );
    }
}
