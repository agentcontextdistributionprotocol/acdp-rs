//! The holder's check of an `io.acdp/provenance` link (RFC-ACDP-0019
//! §4.3 "Verification").
//!
//! [`verify_link`] runs steps 1–5 against a body the caller has already
//! retrieved **and verified** (RFC-ACDP-0001 §5.11: `content_hash` and
//! the producer signature — `acdp::crypto::verify_body_offline` for a
//! `did:key` proxy, the resolver-backed `Verifier` for `did:web`). It
//! never fetches anything.

use acdp::types::{primitives::AgentDid, Body};
use serde_json::{Map, Value};

use crate::record::{self, Salt};

/// Which half of §4.3 failed: the record is not one to rely on
/// (steps 1–2), or it is not a record of the held call (steps 3–5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// Steps 1–2: wrong body, untrusted proxy, or not a valid record.
    Unrecognised {
        /// The §4.3 step (1 or 2).
        step: u8,
        /// What failed.
        reason: String,
    },
    /// Steps 3–5: the record does not match the result or call held.
    Mismatch {
        /// The §4.3 step (3, 4 or 5).
        step: u8,
        /// What failed.
        reason: String,
    },
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unrecognised { step, reason } => {
                write!(f, "provenance record unrecognised (step {step}): {reason}")
            }
            Self::Mismatch { step, reason } => {
                write!(
                    f,
                    "provenance record does not match the call (step {step}): {reason}"
                )
            }
        }
    }
}

impl std::error::Error for LinkError {}

/// The call as the holder knows it.
#[derive(Debug, Clone)]
pub struct HeldCall<'a> {
    /// The `params.name` the holder called.
    pub tool: &'a str,
    /// The result as received, `_meta` included or not.
    pub result: &'a Map<String, Value>,
    /// `params.arguments` as sent (`{}` if omitted), to check
    /// `arguments_hash`; `None` skips that optional check.
    pub arguments: Option<&'a Value>,
    /// The JSON-RPC request `id` as sent, to check `request_id_hash`;
    /// `None` skips it. An absent `request_id_hash` is never a mismatch.
    pub request_id: Option<&'a Value>,
}

fn unrecognised(step: u8, reason: impl Into<String>) -> LinkError {
    LinkError::Unrecognised {
        step,
        reason: reason.into(),
    }
}

fn mismatch(step: u8, reason: impl Into<String>) -> LinkError {
    LinkError::Mismatch {
        step,
        reason: reason.into(),
    }
}

/// Verify `link` (the `io.acdp/provenance` value) against `body` and the
/// held call. `body` MUST already have passed RFC-ACDP-0001 §5.11.
pub fn verify_link(
    body: &Body,
    link: &Value,
    trusted_proxies: &[AgentDid],
    held: &HeldCall<'_>,
) -> Result<(), LinkError> {
    // Step 1 — bind the retrieved body to the link.
    let link = link
        .as_object()
        .ok_or_else(|| unrecognised(1, "link is not an object"))?;
    if link.contains_key("failed") {
        return Err(unrecognised(1, "link records a failed publish"));
    }
    let field = |k: &str| link.get(k).and_then(Value::as_str);
    if field("ctx_id") != Some(body.ctx_id.as_str()) {
        return Err(unrecognised(1, "body ctx_id differs from the link's"));
    }
    if field("registry") != Some(body.origin_registry.as_str()) {
        return Err(unrecognised(
            1,
            "body origin_registry differs from the link's registry",
        ));
    }
    if field("content_hash") != Some(body.content_hash.as_str()) {
        return Err(unrecognised(1, "body content_hash differs from the link's"));
    }

    // Step 2 — a trusted proxy's closed record.
    if !trusted_proxies.contains(&body.agent_id) {
        return Err(unrecognised(
            2,
            format!("{} is not a trusted proxy", body.agent_id.as_str()),
        ));
    }
    let ty = serde_json::to_value(&body.context_type).unwrap_or(Value::Null);
    if ty != record::CONTEXT_TYPE {
        return Err(unrecognised(
            2,
            format!("type is {ty}, not {}", record::CONTEXT_TYPE),
        ));
    }
    let rec = body
        .metadata
        .as_ref()
        .ok_or_else(|| unrecognised(2, "no metadata"))?;
    check_record(rec).map_err(|r| unrecognised(2, r))?;
    let rec = rec.as_object().expect("checked");
    let salted = rec["salted"] == true;

    // Step 3 — the salt, canonical encoding only.
    let salt = match (salted, field("salt")) {
        (true, Some(s)) => Some(Salt::from_base64url(s).map_err(|e| mismatch(3, e.to_string()))?),
        (true, None) => return Err(mismatch(3, "record is salted but the link has no salt")),
        (false, Some(_)) => return Err(mismatch(3, "record is unsalted but the link has a salt")),
        (false, None) => None,
    };
    if link.contains_key("salt") && field("salt").is_none() {
        return Err(mismatch(3, "salt is not a string"));
    }

    // Step 4 — the held result, tool and isError.
    let hashed = record::hashed_result(held.result);
    if rec["result_hash"] != record::call_hash(&hashed, salt.as_ref()) {
        return Err(mismatch(4, "result_hash does not match the held result"));
    }
    if rec["tool"] != held.tool {
        return Err(mismatch(4, "tool differs from the params.name called"));
    }
    let is_error = held
        .result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if rec["is_error"] != is_error {
        return Err(mismatch(4, "is_error differs from the held isError"));
    }

    // Step 5 — optional request checks.
    if let Some(args) = held.arguments {
        if rec["arguments_hash"] != record::call_hash(args, salt.as_ref()) {
            return Err(mismatch(
                5,
                "arguments_hash does not match the arguments sent",
            ));
        }
    }
    if let (Some(id), Some(h)) = (held.request_id, rec.get("request_id_hash")) {
        if *h != record::call_hash(id, salt.as_ref()) {
            return Err(mismatch(
                5,
                "request_id_hash does not match the request id sent",
            ));
        }
    }
    Ok(())
}

const RECORD_KEYS: &[&str] = &[
    "record_version",
    "mcp_protocol_version",
    "server",
    "tool",
    "arguments_hash",
    "result_hash",
    "request_id_hash",
    "is_error",
    "salted",
    "embedded",
    "started_at",
    "completed_at",
];
const SERVER_KEYS: &[&str] = &["name", "version", "transport", "endpoint_hash"];

fn is_hash(v: &Value) -> bool {
    v.as_str()
        .and_then(|s| s.strip_prefix("sha256:"))
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
}

fn is_timestamp(v: &Value) -> bool {
    // ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$
    let Some(s) = v.as_str() else { return false };
    let b = s.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    let head = b.len() >= 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19);
    head && match &b[19..] {
        [b'Z'] => true,
        [b'.', rest @ .., b'Z'] => !rest.is_empty() && rest.iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

fn bounded_str(v: Option<&Value>, max: usize) -> bool {
    v.and_then(Value::as_str)
        .is_some_and(|s| (1..=max).contains(&s.chars().count()))
}

/// `acdp-mcp-tool-result.schema.json#/$defs/record`, closed.
pub fn check_record(rec: &Value) -> Result<(), String> {
    let m = rec.as_object().ok_or("record is not an object")?;
    if let Some(k) = m.keys().find(|k| !RECORD_KEYS.contains(&k.as_str())) {
        return Err(format!("unknown record member '{k}'"));
    }
    if m.get("record_version").and_then(Value::as_str) != Some(record::RECORD_VERSION) {
        return Err(format!("record_version is not {}", record::RECORD_VERSION));
    }
    if !bounded_str(m.get("mcp_protocol_version"), 64) {
        return Err("bad mcp_protocol_version".into());
    }
    if !bounded_str(m.get("tool"), 256) {
        return Err("bad tool".into());
    }
    for k in ["arguments_hash", "result_hash"] {
        if !m.get(k).is_some_and(is_hash) {
            return Err(format!("bad {k}"));
        }
    }
    if m.get("request_id_hash").is_some_and(|v| !is_hash(v)) {
        return Err("bad request_id_hash".into());
    }
    for k in ["is_error", "salted", "embedded"] {
        if !m.get(k).is_some_and(Value::is_boolean) {
            return Err(format!("bad {k}"));
        }
    }
    for k in ["started_at", "completed_at"] {
        if !m.get(k).is_some_and(is_timestamp) {
            return Err(format!("bad {k}"));
        }
    }
    let s = m
        .get("server")
        .and_then(Value::as_object)
        .ok_or("server is not an object")?;
    if let Some(k) = s.keys().find(|k| !SERVER_KEYS.contains(&k.as_str())) {
        return Err(format!("unknown server member '{k}'"));
    }
    if !bounded_str(s.get("name"), 256) {
        return Err("bad server.name".into());
    }
    if s.contains_key("version") && !bounded_str(s.get("version"), 128) {
        return Err("bad server.version".into());
    }
    if !matches!(
        s.get("transport").and_then(Value::as_str),
        Some("stdio" | "streamable-http" | "sse")
    ) {
        return Err("bad server.transport".into());
    }
    if !s.get("endpoint_hash").is_some_and(is_hash) {
        return Err("bad server.endpoint_hash".into());
    }
    Ok(())
}
