//! The `acdp:mcp-tool-result` body (RFC-ACDP-0019 §4–§5): call hashes,
//! the salt, `derived_from` extraction, embedding, and the signed
//! publish request. Pure — no I/O, no clock.

use acdp::{
    crypto::{canonicalize_value, compute_content_hash},
    producer::Producer,
    types::{
        data_ref::{DataRef, DataRefType, EmbeddedContent, EmbeddedEncoding},
        primitives::{AgentDid, ContextType, Visibility},
        CtxId, PublishRequest,
    },
    AcdpError,
};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// `type` of every body the proxy publishes.
pub const CONTEXT_TYPE: &str = "acdp:mcp-tool-result";
/// `schema_uri` of every body the proxy publishes.
pub const SCHEMA_URI: &str = "https://schemas.acdp.io/v0.1.0/acdp-mcp-tool-result.schema.json";
/// `metadata.record_version` this crate emits.
pub const RECORD_VERSION: &str = "acdp-mcp-tool-result/1";
/// Minimum `acdp_version` for the record (RFC-ACDP-0019 §4.1).
pub const ACDP_VERSION: &str = "0.5.0";
/// RFC-ACDP-0002 `derived_from` maximum, the §4.4 extraction cap.
pub const MAX_DERIVED_FROM: usize = 1000;
/// RFC-ACDP-0002 §6.3 embedded cap, measured over the JCS bytes.
pub const MAX_EMBEDDED_BYTES: usize = 65_536;
/// Placeholder that replaces a credential-bearing launch argument
/// before `endpoint_hash` is computed (§4.2).
pub const REDACTED_ARG: &str = "<redacted>";

const TITLE_PREFIX: &str = "MCP tool result: ";
const MAX_TITLE_CHARS: usize = 500;
// Record string bounds from `acdp-mcp-tool-result.schema.json`.
const MAX_SERVER_NAME: usize = 256;
const MAX_SERVER_VERSION: usize = 128;
const MAX_PROTOCOL_VERSION: usize = 64;
const MAX_TOOL: usize = 256;

/// The 32-byte per-body salt (§4.3).
#[derive(Clone, PartialEq, Eq)]
pub struct Salt([u8; 32]);

impl Salt {
    /// Fresh salt from the operating system's CSPRNG.
    pub fn random() -> Result<Self, AcdpError> {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b)
            .map_err(|e| AcdpError::Serialization(format!("salt CSPRNG unavailable: {e}")))?;
        Ok(Self(b))
    }

    /// Wrap known bytes (known-answer tests).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Strict decode of the `_meta` form: base64url, unpadded, exactly
    /// 32 bytes (§4.3 verification step 3).
    pub fn from_base64url(s: &str) -> Result<Self, AcdpError> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| AcdpError::SchemaViolation(format!("salt is not base64url: {e}")))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
            AcdpError::SchemaViolation(format!("salt must be 32 bytes, got {}", b.len()))
        })?;
        Ok(Self(arr))
    }

    /// The `_meta` form: base64url without padding (43 characters).
    pub fn to_base64url(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Salt(..)")
    }
}

/// §4.3 call hash: `H(salt ‖ JCS(value))` when salted, else `H(JCS(value))`.
pub fn call_hash(value: &Value, salt: Option<&Salt>) -> String {
    let mut h = Sha256::new();
    if let Some(s) = salt {
        h.update(s.as_bytes());
    }
    h.update(canonicalize_value(value));
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// The hashed result (§4.3): the result restricted to whichever of
/// `content`, `structuredContent` and `isError` are present, values
/// unchanged. An absent `isError` stays absent.
pub fn hashed_result(result: &Map<String, Value>) -> Value {
    let mut out = Map::new();
    for k in ["content", "structuredContent", "isError"] {
        if let Some(v) = result.get(k) {
            out.insert(k.to_owned(), v.clone());
        }
    }
    Value::Object(out)
}

/// The upstream transport (`server.transport`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    /// Child process over stdin/stdout.
    Stdio,
    /// MCP streamable HTTP.
    StreamableHttp,
    /// Legacy HTTP+SSE.
    Sse,
}

/// §4.2 stdio endpoint descriptor `{"command", "args"}`, with each
/// argument index in `redact` replaced by [`REDACTED_ARG`]. The
/// environment never enters it.
pub fn stdio_descriptor(command: &str, args: &[String], redact: &[usize]) -> Value {
    let args: Vec<&str> = args
        .iter()
        .enumerate()
        .map(|(i, a)| {
            if redact.contains(&i) {
                REDACTED_ARG
            } else {
                a.as_str()
            }
        })
        .collect();
    json!({ "command": command, "args": args })
}

/// §4.2 HTTP endpoint descriptor `{"url"}`: userinfo, query and
/// fragment removed. Headers never enter it.
pub fn http_descriptor(url: &str) -> Result<Value, AcdpError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| AcdpError::SchemaViolation(format!("not an absolute URL: {url}")))?;
    let rest = rest.split(['#', '?']).next().unwrap_or("");
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    Ok(json!({ "url": format!("{scheme}://{host}{path}") }))
}

/// `server.endpoint_hash`: `H(JCS(descriptor))`, unsalted on purpose.
pub fn endpoint_hash(descriptor: &Value) -> String {
    call_hash(descriptor, None)
}

/// §4.4 `derived_from`: every string value (never a key) that is a
/// whole `ctx_id`, in JCS preorder, first occurrence kept, at most
/// [`MAX_DERIVED_FROM`].
pub fn derived_from(arguments: &Value) -> Vec<CtxId> {
    fn walk(v: &Value, out: &mut Vec<CtxId>) {
        if out.len() >= MAX_DERIVED_FROM {
            return;
        }
        match v {
            Value::String(s) => {
                if let Ok(id) = CtxId::parse(s.as_str()) {
                    if !out.contains(&id) {
                        out.push(id);
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|e| walk(e, out)),
            Value::Object(m) => {
                // RFC 8785 §3.2.3: keys ordered by UTF-16 code units.
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
                keys.into_iter().for_each(|k| walk(&m[k], out));
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(arguments, &mut out);
    out
}

/// The upstream server as learned at `initialize`.
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    /// `serverInfo.name`.
    pub name: String,
    /// `serverInfo.version`, if reported.
    pub version: Option<String>,
    /// Negotiated `protocolVersion`.
    pub protocol_version: String,
    /// How the proxy reaches the server.
    pub transport: Transport,
    /// [`endpoint_hash`] of the server's descriptor.
    pub endpoint_hash: String,
}

/// One observed `tools/call` exchange.
#[derive(Debug, Clone)]
pub struct ToolCall {
    /// `params.name`.
    pub tool: String,
    /// `params.arguments` (`{}` when the request carried none).
    pub arguments: Value,
    /// The JSON-RPC request `id`.
    pub request_id: Option<Value>,
    /// The `CallToolResult` as the server returned it.
    pub result: Map<String, Value>,
    /// When the request was forwarded upstream.
    pub started_at: DateTime<Utc>,
    /// When the result came back.
    pub completed_at: DateTime<Utc>,
}

/// Whether the result itself may be published (§5).
#[derive(Debug, Clone, Default)]
pub enum Embedding {
    /// Not allowlisted: `data_refs: []`, salted (the default).
    #[default]
    Never,
    /// Allowlisted. Inline within the 64 KB cap; above it, an external
    /// location DataRef `<base>/<content-hash hex>.json` when a base is
    /// configured, else unembedded and salted.
    Allowlisted {
        /// URL prefix the operator serves external results from.
        external_base: Option<String>,
    },
}

/// Body-level options the operator configures.
#[derive(Debug, Clone)]
pub struct BodyOptions {
    /// §8.3: `private` by default.
    pub visibility: Visibility,
    /// Required when `visibility` is `restricted`.
    pub audience: Vec<AgentDid>,
    /// §5 embedding for this tool.
    pub embedding: Embedding,
}

impl Default for BodyOptions {
    fn default() -> Self {
        Self {
            visibility: Visibility::Private,
            audience: Vec::new(),
            embedding: Embedding::Never,
        }
    }
}

/// A result the operator must make available at `location` before the
/// external DataRef that points to it resolves.
#[derive(Debug, Clone)]
pub struct ExternalPayload {
    /// The DataRef `location`.
    pub location: String,
    /// The hex digest naming the payload (`<hex>.json`).
    pub hex: String,
    /// `JCS(hashed result)` — the bytes the DataRef `content_hash` covers.
    pub bytes: Vec<u8>,
}

/// A signed publish request plus what the proxy needs after publishing.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// The wire-ready signed request.
    pub request: PublishRequest,
    /// The salt, when the record is salted.
    pub salt: Option<Salt>,
    /// `acdp-mcp-<content_hash hex>` (§7).
    pub idempotency_key: String,
    /// Present when the result goes to an external location (§5).
    pub external: Option<ExternalPayload>,
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Build and sign the body for one call (§4–§5). `fresh_salt` is
/// called only when the record is salted, so known-answer tests can
/// inject the salt.
pub fn prepare(
    producer: &Producer,
    server: &ServerIdentity,
    call: &ToolCall,
    opts: &BodyOptions,
    fresh_salt: impl FnOnce() -> Result<Salt, AcdpError>,
) -> Result<Prepared, AcdpError> {
    let hashed = hashed_result(&call.result);
    let mut data_refs = Vec::new();
    let mut external = None;
    if let Embedding::Allowlisted { external_base } = &opts.embedding {
        let bytes = canonicalize_value(&hashed);
        if bytes.len() <= MAX_EMBEDDED_BYTES {
            let mut r = DataRef::primary_result_json(Value::Null);
            r.format = Some("json".into());
            r.embedded = Some(EmbeddedContent {
                encoding: EmbeddedEncoding::Json,
                content: hashed.clone(),
                content_hash: None,
            });
            data_refs.push(r);
        } else if let Some(base) = external_base {
            let hash = compute_content_hash(&hashed)?;
            let hex = hash.as_str().trim_start_matches("sha256:").to_owned();
            let location = format!("{}/{hex}.json", base.trim_end_matches('/'));
            let mut r = DataRef::uri_verified(DataRefType::PrimaryResult, location.clone(), hash);
            r.format = Some("json".into());
            data_refs.push(r);
            external = Some(ExternalPayload {
                location,
                hex,
                bytes,
            });
        }
    }
    let embedded = !data_refs.is_empty();
    // §4.3: MUST salt when not embedded; an embedded record is left
    // unsalted since the result is already published.
    let salt = if embedded { None } else { Some(fresh_salt()?) };

    let mut server_obj = Map::new();
    server_obj.insert(
        "name".into(),
        truncate(&server.name, MAX_SERVER_NAME).into(),
    );
    if let Some(v) = &server.version {
        server_obj.insert("version".into(), truncate(v, MAX_SERVER_VERSION).into());
    }
    server_obj.insert("transport".into(), serde_json::to_value(server.transport)?);
    server_obj.insert("endpoint_hash".into(), server.endpoint_hash.clone().into());

    let tool = truncate(&call.tool, MAX_TOOL);
    let mut record = Map::new();
    record.insert("record_version".into(), RECORD_VERSION.into());
    record.insert(
        "mcp_protocol_version".into(),
        truncate(&server.protocol_version, MAX_PROTOCOL_VERSION).into(),
    );
    record.insert("server".into(), Value::Object(server_obj));
    record.insert("tool".into(), tool.clone().into());
    record.insert(
        "arguments_hash".into(),
        call_hash(&call.arguments, salt.as_ref()).into(),
    );
    record.insert(
        "result_hash".into(),
        call_hash(&hashed, salt.as_ref()).into(),
    );
    if let Some(id) = &call.request_id {
        record.insert(
            "request_id_hash".into(),
            call_hash(id, salt.as_ref()).into(),
        );
    }
    let is_error = call
        .result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    record.insert("is_error".into(), is_error.into());
    record.insert("salted".into(), salt.is_some().into());
    record.insert("embedded".into(), embedded.into());
    record.insert(
        "started_at".into(),
        acdp::time::fmt_rfc3339_ms(acdp::time::trunc_ms(call.started_at)).into(),
    );
    record.insert(
        "completed_at".into(),
        acdp::time::fmt_rfc3339_ms(acdp::time::trunc_ms(call.completed_at)).into(),
    );

    let title = truncate(
        &format!("{TITLE_PREFIX}{}/{}", server.name, call.tool),
        MAX_TITLE_CHARS,
    );
    let mut b = producer
        .publish_request()
        .title(title)
        .context_type(ContextType::Custom(CONTEXT_TYPE.into()))
        .schema_uri(SCHEMA_URI)
        .data_refs(data_refs)
        .derived_from(derived_from(&call.arguments))
        .visibility(opts.visibility.clone())
        .metadata(Value::Object(record))
        .acdp_version(ACDP_VERSION);
    if !opts.audience.is_empty() {
        b = b.audience(opts.audience.clone());
    }
    let request = b.build()?;
    let idempotency_key = format!(
        "acdp-mcp-{}",
        request.content_hash.as_str().trim_start_matches("sha256:")
    );
    Ok(Prepared {
        request,
        salt,
        idempotency_key,
        external,
    })
}
