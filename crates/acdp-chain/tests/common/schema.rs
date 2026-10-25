//! A minimal validator for the subset of JSON Schema 2020-12 that
//! `acdp-chain-verdict.schema.json` uses (object/required/properties/
//! additionalProperties:false, enum, const, oneOf, array items/minItems/
//! uniqueItems, integer min/max, string pattern via shape checks, local
//! and acdp-common `$ref`s). Runs only when the spec checkout is found.
#![allow(dead_code)]

use std::path::PathBuf;

use serde_json::Value;

pub fn spec_dir() -> Option<PathBuf> {
    let candidates = [
        std::env::var("ACDP_SPEC_DIR").ok().map(PathBuf::from),
        Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../agentcontextdistributionprotocol"),
        ),
    ];
    candidates.into_iter().flatten().find(|p| {
        p.join("schemas/json/acdp-chain-verdict.schema.json")
            .exists()
    })
}

pub struct Schemas {
    verdict: Value,
    common: Value,
}

impl Schemas {
    pub fn load() -> Option<Self> {
        let dir = spec_dir()?.join("schemas/json");
        let read = |f: &str| -> Value {
            serde_json::from_slice(&std::fs::read(dir.join(f)).unwrap()).unwrap()
        };
        Some(Self {
            verdict: read("acdp-chain-verdict.schema.json"),
            common: read("acdp-common.schema.json"),
        })
    }

    /// Validate `value` against the verdict schema; returns the first
    /// violation's path.
    pub fn validate_verdict(&self, value: &Value) -> Result<(), String> {
        self.check(&self.verdict, &self.verdict, value, "$")
    }

    fn resolve<'s>(&'s self, root: &'s Value, r: &str) -> (&'s Value, &'s Value) {
        let (doc, ptr) = match r.split_once('#') {
            Some(("", p)) => (root, p),
            Some((uri, p)) if uri.ends_with("acdp-common.schema.json") => (&self.common, p),
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
        p if p.starts_with("^\\d{4}") => {
            s.len() == 24 && s.ends_with('Z') && s.as_bytes()[19] == b'.'
        }
        p if p.starts_with("^acdp://") => acdp_types::primitives::CtxId::parse(s).is_ok(),
        "^[a-z][a-z0-9_]*$" => {
            s.bytes().next().is_some_and(|c| c.is_ascii_lowercase())
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        }
        other => panic!("pattern not modelled: {other}"),
    }
}
