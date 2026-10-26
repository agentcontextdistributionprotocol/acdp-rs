//! Spec checkout discovery, fixture loading, and a minimal JSON Schema
//! checker for `acdp-mcp-tool-result.schema.json` (record and
//! provenance), modelled on `acdp-chain`'s test helper.
#![allow(dead_code)]

use std::path::PathBuf;

use acdp::types::{primitives::is_valid_dns_authority, CtxId};
use serde_json::Value;

/// The spec checkout: `ACDP_SPEC_DIR`, else the sibling directory.
/// `None` (skip) unless `ACDP_REQUIRE_CONFORMANCE` is set, which makes a
/// missing checkout a failure.
pub fn spec_dir() -> Option<PathBuf> {
    let candidates = [
        std::env::var("ACDP_SPEC_DIR").ok().map(PathBuf::from),
        Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../agentcontextdistributionprotocol"),
        ),
    ];
    let found = candidates.into_iter().flatten().find(|p| {
        p.join("schemas/json/acdp-mcp-tool-result.schema.json")
            .exists()
    });
    if found.is_none() && std::env::var_os("ACDP_REQUIRE_CONFORMANCE").is_some() {
        panic!(
            "ACDP_REQUIRE_CONFORMANCE is set but no spec checkout with the mcp fixtures was found"
        );
    }
    found
}

/// A conformance fixture by file name.
pub fn fixture(dir: &std::path::Path, name: &str) -> Value {
    let p = dir.join("schemas/conformance").join(name);
    serde_json::from_slice(&std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())))
        .unwrap()
}

pub struct Schemas {
    mcp: Value,
    common: Value,
}

impl Schemas {
    pub fn load(dir: &std::path::Path) -> Self {
        let read = |f: &str| -> Value {
            serde_json::from_slice(&std::fs::read(dir.join("schemas/json").join(f)).unwrap())
                .unwrap()
        };
        Self {
            mcp: read("acdp-mcp-tool-result.schema.json"),
            common: read("acdp-common.schema.json"),
        }
    }

    /// Validate against `$defs/<name>` (`record` or `provenance`).
    pub fn validate(&self, def: &str, value: &Value) -> Result<(), String> {
        let schema = &self.mcp["$defs"][def];
        self.check(&self.mcp, schema, value, "$")
    }

    fn resolve<'s>(&'s self, root: &'s Value, r: &str) -> (&'s Value, &'s Value) {
        let (doc, ptr) = match r.split_once('#') {
            Some(("", p)) => (root, p),
            Some((uri, p)) if uri.ends_with("acdp-common.schema.json") => (&self.common, p),
            Some((uri, p)) if uri.ends_with("acdp-mcp-tool-result.schema.json") => (&self.mcp, p),
            _ => panic!("unsupported $ref {r}"),
        };
        (
            doc,
            doc.pointer(ptr)
                .unwrap_or_else(|| panic!("dangling $ref {r}")),
        )
    }

    fn check(&self, root: &Value, schema: &Value, v: &Value, path: &str) -> Result<(), String> {
        let err = |m: &str| Err(format!("{path}: {m}"));
        if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
            let (doc, target) = self.resolve(root, r);
            self.check(doc, target, v, path)?;
        }
        if let Some(c) = schema.get("const") {
            if c != v {
                return err(&format!("≠ const {c}"));
            }
        }
        if let Some(e) = schema.get("enum").and_then(Value::as_array) {
            if !e.contains(v) {
                return err(&format!("{v} not in enum"));
            }
        }
        if let Some(alts) = schema.get("oneOf").and_then(Value::as_array) {
            let n = alts
                .iter()
                .filter(|s| self.check(root, s, v, path).is_ok())
                .count();
            if n != 1 {
                return err(&format!("matches {n} oneOf branches"));
            }
        }
        if let Some(not) = schema.get("not") {
            if self.check(root, not, v, path).is_ok() {
                return err("matches `not`");
            }
        }
        match schema.get("type").and_then(Value::as_str) {
            Some("object") if !v.is_object() => return err("not an object"),
            Some("array") if !v.is_array() => return err("not an array"),
            Some("string") if !v.is_string() => return err("not a string"),
            Some("boolean") if !v.is_boolean() => return err("not a boolean"),
            Some("null") if !v.is_null() => return err("not null"),
            Some("integer") if !(v.is_u64() || v.is_i64()) => return err("not an integer"),
            _ => {}
        }
        if let Some(min) = schema.get("minimum").and_then(Value::as_i64) {
            if v.as_i64().is_some_and(|x| x < min) {
                return err("below minimum");
            }
        }
        if let Some(max) = schema.get("maximum").and_then(Value::as_i64) {
            if v.as_i64().is_some_and(|x| x > max) {
                return err("above maximum");
            }
        }
        if let Some(s) = v.as_str() {
            let n = s.chars().count() as u64;
            if schema
                .get("minLength")
                .and_then(Value::as_u64)
                .is_some_and(|m| n < m)
            {
                return err("too short");
            }
            if schema
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|m| n > m)
            {
                return err("too long");
            }
        }
        if let (Some(p), Some(s)) = (schema.get("pattern").and_then(Value::as_str), v.as_str()) {
            if !pattern_ok(p, s) {
                return err(&format!("'{s}' fails pattern {p}"));
            }
        }
        if let Some(obj) = v.as_object() {
            let props = schema.get("properties").and_then(Value::as_object);
            for req in schema
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if !obj.contains_key(req.as_str().unwrap()) {
                    return err(&format!("missing required '{req}'"));
                }
            }
            for (k, val) in obj {
                match props.and_then(|p| p.get(k)) {
                    Some(s) => self.check(root, s, val, &format!("{path}.{k}"))?,
                    None if schema.get("additionalProperties") == Some(&Value::Bool(false)) => {
                        return err(&format!("unknown member '{k}'"));
                    }
                    None => {}
                }
            }
        }
        if let Some(arr) = v.as_array() {
            if let Some(min) = schema.get("minItems").and_then(Value::as_u64) {
                if (arr.len() as u64) < min {
                    return err("too few items");
                }
            }
            if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
                for (i, a) in arr.iter().enumerate() {
                    if arr[..i].contains(a) {
                        return err("duplicate items");
                    }
                }
            }
            if let Some(items) = schema.get("items") {
                for (i, a) in arr.iter().enumerate() {
                    self.check(root, items, a, &format!("{path}[{i}]"))?;
                }
            }
        }
        Ok(())
    }
}

/// The handful of patterns the verdict schema uses, checked by shape.
fn pattern_ok(pattern: &str, s: &str) -> bool {
    match pattern {
        p if p.starts_with("^sha256:") => s.strip_prefix("sha256:").is_some_and(|h| {
            h.len() == 64
                && h.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        }),
        // Emission is always the canonical millisecond form.
        p if p.starts_with("^\\d{4}") => {
            s.len() == 24 && s.ends_with('Z') && s.as_bytes()[19] == b'.'
        }
        p if p.starts_with("^acdp://") => CtxId::parse(s).is_ok(),
        p if p.starts_with("^[a-z0-9](?:") => is_valid_dns_authority(s),
        "^[A-Za-z0-9_-]{43}$" => {
            s.len() == 43
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        }
        "^[a-z][a-z0-9_]*$" => {
            s.bytes().next().is_some_and(|c| c.is_ascii_lowercase())
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        }
        other => panic!("pattern not modelled: {other}"),
    }
}
