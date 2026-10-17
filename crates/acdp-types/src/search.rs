use crate::serde_helpers::de_present;
use acdp_primitives::primitives::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Keyword search ────────────────────────────────────────────────────────────

/// Query parameters for `GET /contexts/search`.
///
/// All fields are optional; unset fields are omitted from the query string.
/// The registry defaults `status` to `active` when not supplied.
#[derive(Debug, Default, Serialize, Clone)]
pub struct SearchParams {
    /// Full-text search across title, description, domain, tags, agent_id, type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,

    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub context_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    /// Comma-separated tag list.  All listed tags must be present (AND).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_uri: Option<String>,

    /// Filter for contexts whose `derived_from` includes this `ctx_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<String>,

    /// RFC 3339 lower bound on `created_at`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_after: Option<String>,

    /// RFC 3339 upper bound on `created_at`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_before: Option<String>,

    /// RFC 3339 lower bound on `data_period.start`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_period_start_after: Option<String>,

    /// RFC 3339 upper bound on `data_period.end`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_period_end_before: Option<String>,

    /// RFC 3339 lower bound on `expires_at`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_after: Option<String>,

    /// RFC 3339 upper bound on `expires_at`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_before: Option<String>,

    /// Filter by lifecycle status.  Defaults to `active`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// Maximum results per page (registry-capped, typically ≤ 100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Pagination cursor from a previous response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Response from `GET /contexts/search`.
///
/// Per `acdp-search-response.schema.json` (additionalProperties: false), the
/// wrapping array MUST be named `matches`. Conformant consumers MUST reject
/// responses that emit `results` or any other alternative spelling
/// (RFC-ACDP-0005 §2.2, fixture vis-003).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchResponse {
    /// Lightweight projections of matching contexts.
    pub matches: Vec<SearchResult>,
    /// Estimated total — may be approximate. Omitted (never serialized
    /// as `null`) when the registry supplies no estimate.
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub total_estimate: Option<u64>,
    /// Opaque pagination cursor; absent when there are no more results.
    ///
    /// `acdp-search-response.schema.json` types `next_cursor` as a bare
    /// `string` (not `["string","null"]`): a missing cursor MUST be
    /// expressed by omitting the key, never by serializing `null`. The
    /// field is omitted on serialize and an explicit `null` is rejected
    /// on deserialize (RFC-ACDP-0005 §2.2.1, fixture schema-005).
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

impl SearchResponse {
    /// Back-compat accessor; new code should prefer `.matches`.
    pub fn results(&self) -> &[SearchResult] {
        &self.matches
    }
}

/// A single search result — `match_summary` projection per
/// `acdp-common.schema.json#/$defs/match_summary`.
///
/// Required fields: ctx_id, lineage_id, type, agent_id, title, created_at,
/// status. Optional: summary, domain, visibility. The full description,
/// tags, etc. are NOT in this projection — fetch the full Body via the
/// registry's retrieval endpoint to access them.
///
/// `match_summary` is `additionalProperties: false`; deserialization
/// rejects unknown fields to keep the projection aligned with the schema.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchResult {
    /// Context identifier.
    pub ctx_id: CtxId,
    /// Lineage this version belongs to.
    pub lineage_id: LineageId,
    /// Producer's signing DID.
    pub agent_id: AgentDid,
    /// Short human-readable title.
    pub title: String,
    /// Producer-supplied search-summary (≤ 1000 chars). Omitted (never
    /// `null`) when the context has no summary — `match_summary` types
    /// it as a bare string; an explicit `null` is rejected (schema-006).
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub summary: Option<String>,
    /// Standard or namespaced custom context type.
    #[serde(rename = "type")]
    pub context_type: ContextType,
    /// Subject-domain identifier. Omitted (never `null`) when absent —
    /// `match_summary` types it as a bare string; an explicit `null` is
    /// rejected (schema-007).
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub domain: Option<String>,
    /// Registry-assigned acceptance time.
    #[serde(with = "acdp_primitives::time::canonical_rfc3339")]
    pub created_at: DateTime<Utc>,
    /// Lifecycle status.
    pub status: Status,
    /// Visibility level per RFC-ACDP-0005 §2.2 / RFC-ACDP-0008 §4.5
    /// disclosure rules. Registries SHOULD include `Public` for public
    /// results; for `Restricted` / `Private` results the field MUST only
    /// be present when the requester is authorized. Absence MUST NOT be
    /// interpreted as `Public`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
}

// ── Typed builder ────────────────────────────────────────────────────────────

/// Typed builder for [`SearchParams`] that accepts `DateTime<Utc>` for date
/// filters and ensures they're emitted in RFC 3339 millisecond form.
#[derive(Default)]
pub struct SearchParamsBuilder {
    inner: SearchParams,
}

use acdp_primitives::time::fmt_rfc3339_ms;

impl SearchParamsBuilder {
    /// Start an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Full-text query.
    pub fn q(mut self, q: impl Into<String>) -> Self {
        self.inner.q = Some(q.into());
        self
    }

    /// Filter on `type`.
    pub fn context_type(mut self, t: impl Into<String>) -> Self {
        self.inner.context_type = Some(t.into());
        self
    }

    /// Filter on `domain`.
    pub fn domain(mut self, d: impl Into<String>) -> Self {
        self.inner.domain = Some(d.into());
        self
    }

    /// Filter on tags (comma-separated).
    pub fn tags(mut self, t: impl Into<String>) -> Self {
        self.inner.tags = Some(t.into());
        self
    }

    /// Filter on `agent_id`.
    pub fn agent_id(mut self, a: impl Into<String>) -> Self {
        self.inner.agent_id = Some(a.into());
        self
    }

    /// Filter to contexts whose `derived_from` includes this `ctx_id`.
    pub fn derived_from(mut self, c: impl Into<String>) -> Self {
        self.inner.derived_from = Some(c.into());
        self
    }

    /// Typed alternative to [`Self::derived_from`] — accepts a strongly
    /// typed [`CtxId`] so callers don't pass arbitrary strings.
    pub fn derived_from_ctx_id(mut self, c: &CtxId) -> Self {
        self.inner.derived_from = Some(c.as_str().to_string());
        self
    }

    /// Accumulate a tag. Multiple calls are joined with `,` for the
    /// AND-semantics matcher per RFC-ACDP-0005 §2.1.
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        let t: String = t.into();
        match self.inner.tags.as_mut() {
            Some(existing) if !existing.is_empty() => {
                existing.push(',');
                existing.push_str(&t);
            }
            _ => self.inner.tags = Some(t),
        }
        self
    }

    /// Lower bound on `created_at`.
    pub fn created_after(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.created_after = Some(fmt_rfc3339_ms(dt));
        self
    }

    /// Upper bound on `created_at`.
    pub fn created_before(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.created_before = Some(fmt_rfc3339_ms(dt));
        self
    }

    /// Lower bound on `data_period.start`.
    pub fn data_period_start_after(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.data_period_start_after = Some(fmt_rfc3339_ms(dt));
        self
    }

    /// Upper bound on `data_period.end`.
    pub fn data_period_end_before(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.data_period_end_before = Some(fmt_rfc3339_ms(dt));
        self
    }

    /// Lower bound on `expires_at`.
    pub fn expires_after(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.expires_after = Some(fmt_rfc3339_ms(dt));
        self
    }

    /// Upper bound on `expires_at`.
    pub fn expires_before(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.expires_before = Some(fmt_rfc3339_ms(dt));
        self
    }

    /// Status filter.
    pub fn status(mut self, s: impl Into<String>) -> Self {
        self.inner.status = Some(s.into());
        self
    }

    /// Result page size cap.
    pub fn limit(mut self, l: u32) -> Self {
        self.inner.limit = Some(l);
        self
    }

    /// Pagination cursor.
    pub fn cursor(mut self, c: impl Into<String>) -> Self {
        self.inner.cursor = Some(c.into());
        self
    }

    /// Finalize.
    pub fn build(self) -> SearchParams {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal conformant `match_summary` value. Optional bare-string
    /// fields (`summary`, `domain`) are *omitted*, not set to `null` —
    /// emitting `null` for them is schema-invalid (schema-006/007).
    fn base_result() -> serde_json::Value {
        serde_json::json!({
            "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
            "lineage_id": "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "agent_id": "did:web:agents.example.com:test",
            "title": "x",
            "type": "data_snapshot",
            "created_at": "2026-01-01T00:00:00.000Z",
            "status": "active",
        })
    }

    /// BUG-03 — `SearchResult` carries the `visibility` projection field.
    /// `match_summary` schema marks it optional; a registry SHOULD emit
    /// it for public results and MUST omit it for restricted/private
    /// results when the requester is unauthorized.
    #[test]
    fn deserializes_with_visibility() {
        let mut v = base_result();
        v["visibility"] = serde_json::json!("public");
        let r: SearchResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.visibility, Some(Visibility::Public));
    }

    #[test]
    fn deserializes_without_visibility() {
        let r: SearchResult = serde_json::from_value(base_result()).unwrap();
        assert_eq!(r.visibility, None, "absence must NOT be coerced to Public");
    }

    /// `match_summary` is `additionalProperties: false` — extra fields
    /// must be rejected so the projection stays aligned with the schema.
    #[test]
    fn rejects_unknown_field() {
        let mut v = base_result();
        v["surprise"] = serde_json::json!("rejected");
        let r: Result<SearchResult, _> = serde_json::from_value(v);
        assert!(r.is_err(), "unknown field must trigger deny_unknown_fields");
    }

    /// Round-trip preserves visibility.
    #[test]
    fn round_trip_with_visibility_public() {
        let mut v = base_result();
        v["visibility"] = serde_json::json!("restricted");
        let r: SearchResult = serde_json::from_value(v).unwrap();
        let back = serde_json::to_value(&r).unwrap();
        assert_eq!(back["visibility"], serde_json::json!("restricted"));
    }

    // ── BUG-03 — absent-vs-null wire convention ────────────────────────

    /// BUG-03: a `SearchResponse` with no `total_estimate` / `next_cursor`
    /// MUST omit those keys, never serialize them as `null`
    /// (`acdp-search-response.schema.json` is `additionalProperties:
    /// false` and types both as non-nullable).
    #[test]
    fn search_response_omits_none_fields() {
        let r = SearchResponse {
            matches: vec![],
            total_estimate: None,
            next_cursor: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            !obj.contains_key("total_estimate"),
            "total_estimate: None MUST be omitted, not null"
        );
        assert!(
            !obj.contains_key("next_cursor"),
            "next_cursor: None MUST be omitted, not null"
        );
    }

    /// BUG-03: a `SearchResult` with no `summary` / `domain` MUST omit
    /// those keys (`match_summary` types both as bare strings).
    #[test]
    fn search_result_omits_none_summary_and_domain() {
        let r: SearchResult = serde_json::from_value(base_result()).unwrap();
        assert_eq!(r.summary, None);
        assert_eq!(r.domain, None);
        let v = serde_json::to_value(&r).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            !obj.contains_key("summary"),
            "summary: None MUST be omitted"
        );
        assert!(!obj.contains_key("domain"), "domain: None MUST be omitted");
    }

    /// schema-005: `next_cursor: null` is schema-invalid — `next_cursor`
    /// is typed as a bare string, so a strict consumer MUST reject it
    /// rather than coerce `null` to absent.
    #[test]
    fn search_response_rejects_null_next_cursor() {
        let raw = r#"{"matches":[],"total_estimate":0,"next_cursor":null}"#;
        let parsed: Result<SearchResponse, _> = serde_json::from_str(raw);
        assert!(
            parsed.is_err(),
            "schema-005: next_cursor:null MUST be rejected, got {parsed:?}"
        );
    }

    /// schema-006: `summary: null` inside a match_summary is rejected.
    #[test]
    fn search_result_rejects_null_summary() {
        let mut v = base_result();
        v["summary"] = serde_json::Value::Null;
        let parsed: Result<SearchResult, _> = serde_json::from_value(v);
        assert!(
            parsed.is_err(),
            "schema-006: summary:null MUST be rejected, got {parsed:?}"
        );
    }

    /// schema-007: `domain: null` inside a match_summary is rejected.
    #[test]
    fn search_result_rejects_null_domain() {
        let mut v = base_result();
        v["domain"] = serde_json::Value::Null;
        let parsed: Result<SearchResult, _> = serde_json::from_value(v);
        assert!(
            parsed.is_err(),
            "schema-007: domain:null MUST be rejected, got {parsed:?}"
        );
    }

    /// Absent optional fields deserialize cleanly to `None`.
    #[test]
    fn search_response_accepts_omitted_optionals() {
        let r: SearchResponse = serde_json::from_str(r#"{"matches":[]}"#).unwrap();
        assert_eq!(r.total_estimate, None);
        assert_eq!(r.next_cursor, None);
    }

    /// Back-compat `results()` accessor returns the same slice as `matches`.
    #[test]
    fn results_accessor_aliases_matches() {
        let r: SearchResponse = serde_json::from_value(serde_json::json!({
            "matches": [base_result()],
        }))
        .unwrap();
        assert_eq!(r.results().len(), 1);
        assert_eq!(r.results().len(), r.matches.len());
        assert_eq!(r.results()[0].ctx_id.as_str(), r.matches[0].ctx_id.as_str());
    }

    // ── SearchParamsBuilder ────────────────────────────────────────────────

    /// An empty builder yields an all-`None` `SearchParams`, which
    /// serializes to an empty object (every field is
    /// `skip_serializing_if = "Option::is_none"`).
    #[test]
    fn builder_empty_serializes_to_empty_object() {
        let params = SearchParamsBuilder::new().build();
        let v = serde_json::to_value(&params).unwrap();
        assert_eq!(v, serde_json::json!({}), "no field set ⇒ empty query");
    }

    /// `new()` and `default()` produce the same empty builder.
    #[test]
    fn builder_new_equals_default() {
        let a = serde_json::to_value(SearchParamsBuilder::new().build()).unwrap();
        let b = serde_json::to_value(SearchParamsBuilder::default().build()).unwrap();
        assert_eq!(a, b);
    }

    /// Scalar setters populate the matching query-string keys, and
    /// `context_type` is renamed to `type` per `SearchParams`.
    #[test]
    fn builder_sets_scalar_fields_with_wire_names() {
        let params = SearchParamsBuilder::new()
            .q("rainfall")
            .context_type("data_snapshot")
            .domain("weather")
            .agent_id("did:web:agents.example.com:test")
            .derived_from("acdp://r.example.com/abc")
            .status("active")
            .limit(25)
            .cursor("opaque-cursor")
            .build();
        let v = serde_json::to_value(&params).unwrap();
        assert_eq!(v["q"], "rainfall");
        assert_eq!(v["type"], "data_snapshot", "context_type renames to `type`");
        assert_eq!(v["domain"], "weather");
        assert_eq!(v["agent_id"], "did:web:agents.example.com:test");
        assert_eq!(v["derived_from"], "acdp://r.example.com/abc");
        assert_eq!(v["status"], "active");
        assert_eq!(v["limit"], 25);
        assert_eq!(v["cursor"], "opaque-cursor");
    }

    /// `tag()` accumulates into a single comma-joined string for the
    /// AND-semantics matcher (RFC-ACDP-0005 §2.1); a lone call leaves no
    /// leading/trailing comma.
    #[test]
    fn builder_tag_accumulates_comma_joined() {
        let one = SearchParamsBuilder::new().tag("alpha").build();
        assert_eq!(one.tags.as_deref(), Some("alpha"));

        let many = SearchParamsBuilder::new()
            .tag("alpha")
            .tag("beta")
            .tag("gamma")
            .build();
        assert_eq!(many.tags.as_deref(), Some("alpha,beta,gamma"));
    }

    /// A prior `tags()` (bulk) value is extended by a later `tag()` call.
    #[test]
    fn builder_tag_extends_existing_bulk_tags() {
        let params = SearchParamsBuilder::new().tags("a,b").tag("c").build();
        assert_eq!(params.tags.as_deref(), Some("a,b,c"));
    }

    /// `tag()` after an explicitly empty `tags("")` replaces rather than
    /// prefixing a stray comma (the `!existing.is_empty()` guard).
    #[test]
    fn builder_tag_after_empty_replaces_without_leading_comma() {
        let params = SearchParamsBuilder::new().tags("").tag("c").build();
        assert_eq!(params.tags.as_deref(), Some("c"));
    }

    /// `derived_from_ctx_id` accepts a typed `CtxId` and stores its string.
    #[test]
    fn builder_derived_from_ctx_id_uses_string_form() {
        let id = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
        let params = SearchParamsBuilder::new().derived_from_ctx_id(&id).build();
        assert_eq!(params.derived_from.as_deref(), Some(id.as_str()));
    }

    /// Every date-bound setter emits RFC 3339 millisecond form (the
    /// `fmt_rfc3339_ms` contract), and lands in the right query key.
    #[test]
    fn builder_date_filters_emit_rfc3339_ms() {
        use chrono::TimeZone;
        // A sub-millisecond instant proves truncation to ms precision.
        let dt = Utc.timestamp_opt(1_700_000_000, 123_456_789).unwrap();
        let params = SearchParamsBuilder::new()
            .created_after(dt)
            .created_before(dt)
            .data_period_start_after(dt)
            .data_period_end_before(dt)
            .expires_after(dt)
            .expires_before(dt)
            .build();
        let expected = fmt_rfc3339_ms(dt);
        assert!(expected.ends_with(".123Z"), "ms-truncated form: {expected}");
        assert_eq!(params.created_after.as_deref(), Some(expected.as_str()));
        assert_eq!(params.created_before.as_deref(), Some(expected.as_str()));
        assert_eq!(
            params.data_period_start_after.as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(
            params.data_period_end_before.as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(params.expires_after.as_deref(), Some(expected.as_str()));
        assert_eq!(params.expires_before.as_deref(), Some(expected.as_str()));
    }
}
