//! The `acdp-a2a-artifact/1` record and the signed body (RFC-ACDP-0022
//! §4–§5, §10). Pure: no I/O, no clock.

use std::collections::HashMap;

use acdp::{
    crypto::canonicalize_value,
    producer::Producer,
    types::{
        anchor::AnchorEntry,
        data_ref::{DataRef, DataRefType, EmbeddedContent, EmbeddedEncoding},
        primitives::{AgentDid, ContentHash, ContextType, LineageId, Visibility},
        CtxId, PublishRequest,
    },
    AcdpError,
};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use crate::{assembly::AssembledArtifact, hash, hash::Salt, link};

/// `metadata` member carrying the record (§4.5).
pub const RECORD_KEY: &str = "acdp:a2a";
/// `record_version` this crate emits.
pub const RECORD_VERSION: &str = "acdp-a2a-artifact/1";
/// Minimum `acdp_version` for a body under this RFC (§4.1).
pub const ACDP_VERSION: &str = "0.5.0";
/// The `a2a.artifact` anchor scheme (§10).
pub const ANCHOR_SCHEME: &str = "a2a.artifact";
/// RFC-ACDP-0002 §6.3 embedded cap, measured over JCS(parts).
pub const MAX_EMBEDDED_BYTES: usize = 65_536;
/// Title when the agent sets none and the artifact has no `name` (§4.1).
pub const DEFAULT_TITLE: &str = "A2A artifact";
/// Types whose `metadata` is itself an ACDP-defined record (§4.1).
pub const FORBIDDEN_TYPES: [&str; 5] = [
    "acdp:mcp-tool-result",
    "acdp:trust-list",
    "acdp:key-attestation",
    "key-revocation",
    "acdp:key-revocation",
];

const MAX_TITLE_CHARS: usize = 500;
const MAX_NAME: usize = 256;
const MAX_DESCRIPTION: usize = 1024;
const MAX_PROTOCOL_VERSION: usize = 64;

/// Truncate to `max` Unicode scalar values (§4.4).
pub fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// A record label (`name` or `description`) as the record carries it:
/// truncated to its schema limit, `None` when empty.
pub fn record_label(value: Option<&str>, max: usize) -> Option<String> {
    value.filter(|s| !s.is_empty()).map(|s| truncate(s, max))
}

/// `name` as the record carries it (256 scalar values).
pub fn record_name(name: Option<&str>) -> Option<String> {
    record_label(name, MAX_NAME)
}

/// `description` as the record carries it (1024 scalar values).
pub fn record_description(description: Option<&str>) -> Option<String> {
    record_label(description, MAX_DESCRIPTION)
}

/// The agent's own body fields (§4.1): everything not part of the
/// binding. The record, `data_refs`, `derived_from`, `version` and
/// `supersedes` are filled in by [`prepare`].
#[derive(Debug, Clone)]
pub struct BodyTemplate {
    /// The agent's own domain type; never one of [`FORBIDDEN_TYPES`].
    pub context_type: ContextType,
    /// Explicit title; else the artifact `name`, else [`DEFAULT_TITLE`].
    pub title: Option<String>,
    /// The agent's own `metadata` members; must not carry [`RECORD_KEY`].
    pub metadata: Map<String, Value>,
    /// The agent's own schema for its `metadata` (must allow `acdp:a2a`).
    pub schema_uri: Option<String>,
    /// `private` by default (§13.3). Published exactly as configured.
    pub visibility: Visibility,
    /// Required when `visibility` is `restricted`.
    pub audience: Vec<AgentDid>,
    /// DIDs the agent chooses to credit.
    pub contributors: Vec<AgentDid>,
    /// Optional body `description`.
    pub description: Option<String>,
    /// Optional body `domain`.
    pub domain: Option<String>,
    /// Optional body `tags`.
    pub tags: Vec<String>,
    /// Optional body `summary`.
    pub summary: Option<String>,
    /// Record the artifact's `name` in the record (§4.4, §13.2).
    pub record_name: bool,
    /// Record the artifact's `description` in the record (§4.4, §13.2).
    pub record_description: bool,
}

impl BodyTemplate {
    /// A template for the agent's own `context_type`, every other field
    /// at its default.
    pub fn new(context_type: ContextType) -> Self {
        Self {
            context_type,
            title: None,
            metadata: Map::new(),
            schema_uri: None,
            visibility: Visibility::Private,
            audience: Vec::new(),
            contributors: Vec::new(),
            description: None,
            domain: None,
            tags: Vec::new(),
            summary: None,
            record_name: true,
            record_description: true,
        }
    }
}

/// Whether the parts may be published (§5.3).
#[derive(Debug, Clone, Default)]
pub enum Embedding {
    /// Not allowlisted: `embedded` false, `parts_hash` salted (default).
    #[default]
    Never,
    /// Allowlisted: inline within the 64 KB cap; above it an external
    /// location `<base>/<content-hash hex>.json` when a base is
    /// configured, else unembedded and salted.
    Allowlisted {
        /// `https` URL prefix the agent serves over-cap parts from.
        external_base: Option<String>,
    },
}

/// What the agent knows about the bytes behind a `url` part (§5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlContent {
    /// `H(bytes)`.
    pub content_hash: ContentHash,
    /// Byte length.
    pub size_bytes: u64,
}

impl UrlContent {
    /// From the bytes the agent served at the URL.
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            content_hash: ContentHash(hash::sha256_tagged(bytes)),
            size_bytes: bytes.len() as u64,
        }
    }
}

/// The agent's published body for a key, which a re-emission supersedes
/// (§4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousBody {
    /// Its `ctx_id`.
    pub ctx_id: CtxId,
    /// Its `lineage_id`.
    pub lineage_id: LineageId,
    /// Its `version`.
    pub version: u32,
}

/// One completed artifact and everything the body binds it to.
#[derive(Debug, Clone)]
pub struct Completion<'a> {
    /// `protocolVersion` of the `AgentInterface` the request arrived on.
    pub a2a_protocol_version: &'a str,
    /// The task's `id`.
    pub task_id: &'a str,
    /// The task's `contextId`.
    pub context_id: &'a str,
    /// The completed artifact (§4.2).
    pub artifact: &'a AssembledArtifact,
    /// Time of completion; emitted as canonical millisecond UTC.
    pub completed_at: DateTime<Utc>,
    /// §7 `derived_from`, already filtered and ordered.
    pub derived_from: Vec<CtxId>,
    /// The body this one supersedes, for a re-emission (§4.3).
    pub previous: Option<&'a PreviousBody>,
    /// Map `url` parts to `data_refs` (§5.4, SHOULD; default true).
    pub map_url_parts: bool,
    /// Known contents behind `url` parts, by URL.
    pub url_contents: &'a HashMap<String, UrlContent>,
    /// The A2A #1140 hash of this artifact, for the `a2a.artifact` anchor.
    pub a2a_artifact_hash: Option<ContentHash>,
}

/// Over-cap parts the agent must serve at `location` before publishing
/// (§5.3: exactly the bytes JCS(parts)).
#[derive(Debug, Clone)]
pub struct ExternalPayload {
    /// The DataRef `location`.
    pub location: String,
    /// The hex digest naming the payload (`<hex>.json`).
    pub hex: String,
    /// `JCS(parts)`.
    pub bytes: Vec<u8>,
}

/// A signed publish request plus what the agent needs afterwards.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// The wire-ready signed request.
    pub request: PublishRequest,
    /// The body's salt, revealed only in the link.
    pub salt: Salt,
    /// `acdp-a2a-<content_hash hex>` (§6).
    pub idempotency_key: String,
    /// Present when the parts go to an external location (§5.3).
    pub external: Option<ExternalPayload>,
}

impl Prepared {
    /// The §6 link once the registry assigned `ctx_id`.
    pub fn link(&self, ctx_id: &CtxId) -> Value {
        link::published(ctx_id, &self.request.content_hash, &self.salt)
    }
}

fn schema(m: impl Into<String>) -> AcdpError {
    AcdpError::SchemaViolation(m.into())
}

/// §5.4: a `url` part's URL is mapped only when it is plain `https` with
/// no userinfo, query or fragment. A query or fragment may hold a token,
/// signature or expiry; when in doubt the DataRef is omitted.
pub fn mappable_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    if rest.contains(['?', '#']) {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or("");
    !authority.is_empty() && !authority.contains('@')
}

/// The record (§4.4) for `c`, salted with `salt` (the ids always;
/// `parts_hash` when `salt_parts`).
pub fn build_record(
    c: &Completion<'_>,
    template: &BodyTemplate,
    salt: &Salt,
    salt_parts: bool,
    embedded: bool,
) -> Value {
    let parts = Value::Array(c.artifact.parts.clone());
    let mut r = Map::new();
    r.insert("record_version".into(), RECORD_VERSION.into());
    r.insert(
        "a2a_protocol_version".into(),
        truncate(c.a2a_protocol_version, MAX_PROTOCOL_VERSION).into(),
    );
    r.insert(
        "artifact_id_hash".into(),
        hash::id_hash(&c.artifact.artifact_id, salt).into(),
    );
    if let Some(role) = c.artifact.record_role() {
        r.insert("role".into(), role.into());
    }
    r.insert("task_id_hash".into(), hash::id_hash(c.task_id, salt).into());
    r.insert(
        "context_id_hash".into(),
        hash::id_hash(c.context_id, salt).into(),
    );
    r.insert(
        "parts_hash".into(),
        hash::parts_hash(&parts, salt_parts.then_some(salt)).into(),
    );
    r.insert("salted".into(), salt_parts.into());
    r.insert("embedded".into(), embedded.into());
    if template.record_name {
        if let Some(n) = record_name(c.artifact.name.as_deref()) {
            r.insert("name".into(), n.into());
        }
    }
    if template.record_description {
        if let Some(d) = record_description(c.artifact.description.as_deref()) {
            r.insert("description".into(), d.into());
        }
    }
    r.insert(
        "completed_at".into(),
        acdp::time::fmt_rfc3339_ms(acdp::time::trunc_ms(c.completed_at)).into(),
    );
    Value::Object(r)
}

/// Build and sign the body for one completed artifact (§4–§5, §10).
/// `fresh_salt` supplies the per-body salt, so known-answer tests can
/// inject it.
pub fn prepare(
    producer: &Producer,
    c: &Completion<'_>,
    template: &BodyTemplate,
    embedding: &Embedding,
    fresh_salt: impl FnOnce() -> Result<Salt, AcdpError>,
) -> Result<Prepared, AcdpError> {
    let ty = serde_json::to_value(&template.context_type)?;
    if ty.as_str().is_some_and(|t| FORBIDDEN_TYPES.contains(&t)) {
        return Err(schema(format!(
            "type {ty} carries an ACDP-defined record and cannot carry acdp:a2a (RFC-ACDP-0022 §4.1)"
        )));
    }
    if template.metadata.contains_key(RECORD_KEY) {
        return Err(schema(format!(
            "metadata member {RECORD_KEY} is reserved for the record (RFC-ACDP-0022 §4.5)"
        )));
    }
    if c.artifact.is_client_written() {
        return Err(schema(
            "a ROLE_USER artifact is client-written and is never published (RFC-ACDP-0022 §4.2)",
        ));
    }

    let parts = Value::Array(c.artifact.parts.clone());
    let mut data_refs = Vec::new();
    let mut external = None;
    if let Embedding::Allowlisted { external_base } = embedding {
        let bytes = canonicalize_value(&parts);
        if bytes.len() <= MAX_EMBEDDED_BYTES {
            let mut r = DataRef::primary_result_json(Value::Null);
            r.format = Some("json".into());
            r.embedded = Some(EmbeddedContent {
                encoding: EmbeddedEncoding::Json,
                content: parts.clone(),
                content_hash: None,
            });
            data_refs.push(r);
        } else if let Some(base) = external_base {
            let h = ContentHash(hash::sha256_tagged(&bytes));
            let hex = h.as_str().trim_start_matches("sha256:").to_owned();
            let location = format!("{}/{hex}.json", base.trim_end_matches('/'));
            let mut r = DataRef::uri_verified(DataRefType::PrimaryResult, location.clone(), h);
            r.format = Some("json".into());
            r.size_bytes = Some(bytes.len() as u64);
            data_refs.push(r);
            external = Some(ExternalPayload {
                location,
                hex,
                bytes,
            });
        }
    }
    let embedded = !data_refs.is_empty();

    if c.map_url_parts {
        for p in &c.artifact.parts {
            let Some(url) = p.get("url").and_then(Value::as_str) else {
                continue;
            };
            if !mappable_url(url) {
                continue;
            }
            let mut r = match c.url_contents.get(url) {
                Some(k) => {
                    let mut r = DataRef::uri_verified(
                        DataRefType::PrimaryResult,
                        url,
                        k.content_hash.clone(),
                    );
                    r.size_bytes = Some(k.size_bytes);
                    r
                }
                None => DataRef::uri(DataRefType::PrimaryResult, url),
            };
            r.format = p
                .get("mediaType")
                .and_then(Value::as_str)
                .map(str::to_owned);
            data_refs.push(r);
        }
    }

    // §5.2: the ids are always salted; parts_hash whenever not embedded.
    let salt = fresh_salt()?;
    let salt_parts = !embedded;
    if c.a2a_artifact_hash.is_some() && salt_parts && template.visibility == Visibility::Public {
        return Err(schema(
            "the a2a.artifact anchor undoes the salt and is not allowed on a public body \
             with salted parts (RFC-ACDP-0022 §10)",
        ));
    }
    let record = build_record(c, template, &salt, salt_parts, embedded);
    let mut metadata = template.metadata.clone();
    metadata.insert(RECORD_KEY.into(), record);

    let title = template
        .title
        .clone()
        .or_else(|| c.artifact.name.clone().filter(|n| !n.is_empty()))
        .unwrap_or_else(|| DEFAULT_TITLE.to_owned());
    let mut b = match c.previous {
        Some(p) => producer
            .supersede(p.ctx_id.clone())
            .version(p.version + 1)
            .expected_lineage_id(p.lineage_id.clone()),
        None => producer.publish_request(),
    };
    b = b
        .title(truncate(&title, MAX_TITLE_CHARS))
        .context_type(template.context_type.clone())
        .data_refs(data_refs)
        .derived_from(c.derived_from.clone())
        .visibility(template.visibility.clone())
        .metadata(Value::Object(metadata))
        .acdp_version(ACDP_VERSION);
    if !template.contributors.is_empty() {
        b = b.contributors(template.contributors.clone());
    }
    if !template.audience.is_empty() {
        b = b.audience(template.audience.clone());
    }
    if let Some(s) = &template.schema_uri {
        b = b.schema_uri(s.clone());
    }
    if let Some(d) = &template.description {
        b = b.description(d.clone());
    }
    if let Some(d) = &template.domain {
        b = b.domain(d.clone());
    }
    if !template.tags.is_empty() {
        b = b.tags(template.tags.clone());
    }
    if let Some(s) = &template.summary {
        b = b.summary(s.clone());
    }
    if let Some(h) = &c.a2a_artifact_hash {
        b = b.anchors(vec![AnchorEntry {
            scheme: ANCHOR_SCHEME.into(),
            content_hash: h.clone(),
            uri: None,
            extensions: Map::new(),
        }]);
    }
    let request = b.build()?;
    let idempotency_key = link::idempotency_key(&request.content_hash);
    Ok(Prepared {
        request,
        salt,
        idempotency_key,
        external,
    })
}
