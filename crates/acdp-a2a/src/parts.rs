//! The parts in A2A JSON (RFC-ACDP-0022 §5.1).
//!
//! `parts_hash` covers the `parts` array, in order, each Part in this
//! form:
//!
//! - exactly one content member, `text`, `raw`, `url` or `data`, present
//!   even when its value is empty;
//! - `metadata` present exactly when the Part's metadata is set;
//! - `filename` and `mediaType` present exactly when they are non-empty
//!   strings;
//! - no other member.
//!
//! [`normalize_part`] rebuilds a received Part into that form: it drops
//! `null` members (ProtoJSON reads them as unset), drops empty
//! `filename`/`mediaType`, and re-encodes `raw` as RFC 4648 §4 standard
//! padded base64. The agent and the holder both hash the output, so the
//! hash does not depend on the encoder.

use base64::{
    alphabet,
    engine::{general_purpose::STANDARD, DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    Engine as _,
};
use serde_json::{Map, Value};

/// The content members of a Part; exactly one is present.
pub const CONTENT_MEMBERS: [&str; 4] = ["text", "raw", "url", "data"];

/// Lenient decoder for received `raw`: padding optional, trailing bits
/// ignored (what ProtoJSON parsers accept). The URL-safe alphabet is
/// mapped onto the standard one before decoding.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Why a Part could not be put in A2A JSON form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartError(pub String);

impl std::fmt::Display for PartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid A2A Part: {}", self.0)
    }
}

impl std::error::Error for PartError {}

fn err<T>(m: impl Into<String>) -> Result<T, PartError> {
    Err(PartError(m.into()))
}

/// Re-encode a received `raw` string (standard or URL-safe alphabet,
/// padded or not) as standard padded base64 (§5.1 "`raw` parts").
pub fn canonical_raw(s: &str) -> Result<String, PartError> {
    let mapped: String = s
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let bytes = LENIENT
        .decode(mapped.as_bytes())
        .map_err(|e| PartError(format!("raw is not base64: {e}")))?;
    Ok(STANDARD.encode(bytes))
}

/// One Part in its §5.1 A2A JSON form.
pub fn normalize_part(part: &Value) -> Result<Value, PartError> {
    let Some(obj) = part.as_object() else {
        return err("a Part is not an object");
    };
    let mut out = Map::new();
    let mut content = 0usize;
    for (k, v) in obj {
        if v.is_null() {
            continue;
        }
        match k.as_str() {
            "text" | "url" => {
                if !v.is_string() {
                    return err(format!("{k} is not a string"));
                }
                content += 1;
                out.insert(k.clone(), v.clone());
            }
            "raw" => {
                let Some(s) = v.as_str() else {
                    return err("raw is not a string");
                };
                content += 1;
                out.insert(k.clone(), canonical_raw(s)?.into());
            }
            "data" => {
                content += 1;
                out.insert(k.clone(), v.clone());
            }
            "metadata" => {
                if !v.is_object() {
                    return err("metadata is not an object");
                }
                out.insert(k.clone(), v.clone());
            }
            "filename" | "mediaType" => {
                let Some(s) = v.as_str() else {
                    return err(format!("{k} is not a string"));
                };
                if !s.is_empty() {
                    out.insert(k.clone(), v.clone());
                }
            }
            other => return err(format!("unknown Part member '{other}'")),
        }
    }
    if content != 1 {
        return err(format!(
            "a Part carries exactly one of text, raw, url, data; this one carries {content}"
        ));
    }
    Ok(Value::Object(out))
}

/// The `parts` array in §5.1 form, order kept.
pub fn normalize_parts(parts: &[Value]) -> Result<Vec<Value>, PartError> {
    parts.iter().map(normalize_part).collect()
}
