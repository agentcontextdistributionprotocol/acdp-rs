//! content_hash and lineage_id computation per RFC-ACDP-0001 §5.7 / §5.6.

use super::jcs::try_canonicalize_value;
use acdp_primitives::error::AcdpError;
use acdp_primitives::primitives::{ContentHash, CtxId, LineageId};
use sha2::{Digest, Sha256};

/// Fields excluded from ProducerContent (the hash/signature preimage).
///
/// RFC-ACDP-0001 §5.7: these fields are not known to the producer at signing
/// time, or cannot be part of their own hash/signature inputs.
const EXCLUDE: &[&str] = &[
    "content_hash",    // cannot contain its own hash
    "signature",       // over the hash, not in the hash
    "ctx_id",          // registry-assigned
    "lineage_id",      // registry-assigned
    "origin_registry", // registry-assigned
    "created_at",      // registry-assigned
];

/// Compute `content_hash` over a JSON representation of a body.
///
/// Strips the §5.7 exclusion set, JCS-canonicalizes, SHA-256 hashes,
/// and returns the result as `"sha256:<64-lowercase-hex>"`.
///
/// The input may be a `PublishRequest`, a stored `Body`, or any JSON object
/// that contains the producer-controlled fields.
pub fn compute_content_hash(body_value: &serde_json::Value) -> Result<ContentHash, AcdpError> {
    Ok(canonical_preimage(body_value)?.1)
}

/// Return the exact JCS canonical bytes hashed for `content_hash`,
/// alongside the hash itself (WS-D2 divergence diagnostics).
///
/// This is the byte sequence other implementations must reproduce.
/// When two SDKs disagree on a hash, diffing their canonical preimages
/// localizes the divergence (timestamp precision, `acdp_version`
/// omitted-vs-explicit, null-vs-absent, unknown-field drops, …) in a
/// way two opaque digests never can. See also
/// [`explain_hash_mismatch`] for an automated first pass.
pub fn canonical_preimage(
    body_value: &serde_json::Value,
) -> Result<(Vec<u8>, ContentHash), AcdpError> {
    let mut map = body_value
        .as_object()
        .ok_or_else(|| AcdpError::InvalidBody("expected a JSON object".into()))?
        .clone();

    for key in EXCLUDE {
        map.remove(*key);
    }

    let canonical = try_canonicalize_value(&serde_json::Value::Object(map))?;
    let digest = Sha256::digest(&canonical);
    let hash = ContentHash(format!("sha256:{}", hex::encode(digest)));
    Ok((canonical, hash))
}

/// Diagnose a `content_hash` mismatch by testing the known divergence
/// patterns (WS-D2). Returns a human-readable report; never fails the
/// caller's verification decision — this is tooling for producers and
/// SDK authors chasing "the hash that won't reproduce".
///
/// Patterns probed, mirroring the spec's divergence corpus:
/// 1. `acdp_version` omitted vs explicit `"0.1.0"` (distinct JCS
///    preimages, RFC-ACDP-0001 §6).
/// 2. Optional fields serialized as `null` instead of omitted
///    (RFC-ACDP-0005 §2.2.1 — `supersedes` is the one legitimately
///    nullable field).
/// 3. Timestamps with sub-millisecond precision (RFC-ACDP-0001 §5.3 —
///    "the most common source of cross-implementation hash
///    divergence").
///
/// If a single pattern (or all of them combined) reproduces `expected`,
/// the report names it; otherwise it reports the recomputed hash and
/// preimage so the caller can diff canonical bytes across
/// implementations via [`canonical_preimage`].
pub fn explain_hash_mismatch(
    body_value: &serde_json::Value,
    expected: &ContentHash,
) -> Result<String, AcdpError> {
    let recomputed = compute_content_hash(body_value)?;
    if &recomputed == expected {
        return Ok("content_hash matches the canonical preimage; no divergence".into());
    }

    let mut report =
        format!("content_hash mismatch:\n  expected:   {expected}\n  recomputed: {recomputed}\n");

    let mut hypotheses: Vec<(&str, serde_json::Value)> = Vec::new();
    if let Some(obj) = body_value.as_object() {
        // 1. acdp_version omitted ↔ explicit ↔ other version. The
        //    can-012 corpus pins the omitted, "0.1.0", and "0.2.0"
        //    forms as three distinct preimages.
        if obj.contains_key("acdp_version") {
            let mut removed = obj.clone();
            removed.remove("acdp_version");
            hypotheses.push((
                "the expected hash was computed WITHOUT acdp_version — the \
                 counterparty omits the field while this body emits it",
                serde_json::Value::Object(removed),
            ));
        }
        for version in ["0.1.0", "0.2.0"] {
            if obj.get("acdp_version").and_then(|v| v.as_str()) == Some(version) {
                continue; // already this body's form
            }
            let mut with_v = obj.clone();
            with_v.insert("acdp_version".into(), serde_json::json!(version));
            let desc: &'static str = if version == "0.1.0" {
                "the expected hash was computed WITH acdp_version \"0.1.0\" — \
                 the counterparty emits a different acdp_version form than this body"
            } else {
                "the expected hash was computed WITH acdp_version \"0.2.0\" — \
                 the counterparty emits a different acdp_version form than this body"
            };
            hypotheses.push((desc, serde_json::Value::Object(with_v)));
        }

        // 2. Present-but-null optionals (other than `supersedes`) that
        //    should have been omitted.
        let mut stripped = obj.clone();
        stripped.retain(|k, v| k == "supersedes" || !v.is_null());
        if stripped.len() != obj.len() {
            hypotheses.push((
                "the expected hash was computed with null-valued optional fields \
                 OMITTED — this body serializes null instead of omitting \
                 (RFC-ACDP-0005 §2.2.1)",
                serde_json::Value::Object(stripped),
            ));
        }

        // 3. Sub-millisecond timestamp precision.
        let truncated = truncate_sub_ms_strings(body_value);
        if &truncated != body_value {
            hypotheses.push((
                "the expected hash was computed over millisecond-truncated \
                 timestamps — this body carries sub-ms precision \
                 (RFC-ACDP-0001 §5.3: truncate BEFORE signing)",
                truncated,
            ));
        }
    }

    // Combined patterns: strip nulls + truncate timestamps with the
    // body's own acdp_version form preserved, and additionally with
    // each version-form variant — so multi-cause divergences (e.g.
    // nulls AND sub-ms timestamps) are still identified.
    if let Some(obj) = body_value.as_object() {
        let mut base = obj.clone();
        base.retain(|k, v| k == "supersedes" || !v.is_null());
        let base = match truncate_sub_ms_strings(&serde_json::Value::Object(base)) {
            serde_json::Value::Object(m) => m,
            _ => unreachable!("object in, object out"),
        };
        if serde_json::Value::Object(base.clone()) != *body_value {
            hypotheses.push((
                "multiple divergence patterns combined (null-stripping + ms \
                 truncation; acdp_version form unchanged)",
                serde_json::Value::Object(base.clone()),
            ));
        }
        let mut removed = base.clone();
        removed.remove("acdp_version");
        hypotheses.push((
            "multiple divergence patterns combined (null-stripping + ms \
             truncation + acdp_version omitted)",
            serde_json::Value::Object(removed),
        ));
        for version in ["0.1.0", "0.2.0"] {
            let mut with_v = base.clone();
            with_v.insert("acdp_version".into(), serde_json::json!(version));
            hypotheses.push((
                "multiple divergence patterns combined (null-stripping + ms \
                 truncation + acdp_version form change)",
                serde_json::Value::Object(with_v),
            ));
        }
    }

    for (desc, variant) in &hypotheses {
        if &compute_content_hash(variant)? == expected {
            report.push_str(&format!("  likely cause: {desc}\n"));
            return Ok(report);
        }
    }

    let (preimage, _) = canonical_preimage(body_value)?;
    report.push_str(&format!(
        "  no known divergence pattern reproduces the expected hash.\n  \
         canonical preimage ({} bytes) — diff this against the counterparty's \
         canonical_preimage() output:\n  {}\n",
        preimage.len(),
        String::from_utf8_lossy(&preimage)
    ));
    Ok(report)
}

/// Recursively truncate every RFC 3339 timestamp string with
/// sub-millisecond precision to the canonical millisecond form
/// (`…T…SS.mmmZ`). Non-timestamp strings pass through unchanged.
fn truncate_sub_ms_strings(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::String(s) => {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                let utc = dt.with_timezone(&chrono::Utc);
                if !utc.timestamp_subsec_nanos().is_multiple_of(1_000_000) {
                    return Value::String(
                        acdp_primitives::time::trunc_ms(utc)
                            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                            .to_string(),
                    );
                }
            }
            v.clone()
        }
        Value::Array(items) => Value::Array(items.iter().map(truncate_sub_ms_strings).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, val)| (k.clone(), truncate_sub_ms_strings(val)))
                .collect(),
        ),
        _ => v.clone(),
    }
}

/// Derive the `lineage_id` from the first version's `ctx_id`.
///
/// Formula (RFC-ACDP-0001 §5.6):
/// `lineage_id = "lin:sha256:" + lowercase_hex(SHA-256(utf8(ctx_id)))`
pub fn derive_lineage_id(first_ctx_id: &CtxId) -> LineageId {
    let digest = Sha256::digest(first_ctx_id.as_str().as_bytes());
    LineageId(format!("lin:sha256:{}", hex::encode(digest)))
}

/// Verify that a stored `content_hash` matches the recomputed value.
///
/// Returns `Ok(())` if they match, `Err(AcdpError::HashMismatch)` otherwise.
pub fn verify_content_hash(
    body_value: &serde_json::Value,
    stored: &ContentHash,
) -> Result<(), AcdpError> {
    let recomputed = compute_content_hash(body_value)?;
    if &recomputed != stored {
        return Err(AcdpError::HashMismatch {
            stored: stored.clone(),
            recomputed,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn golden_content_hash() {
        // Matches sig-001-ed25519-golden.json expected.content_hash
        let body = json!({
            "version": 1,
            "supersedes": null,
            "agent_id": "did:web:agents.example.com:test-producer",
            "contributors": [],
            "title": "Golden test vector — minimal first version",
            "type": "data_snapshot",
            "data_refs": [],
            "derived_from": [],
            "visibility": "public"
        });
        let h = compute_content_hash(&body).unwrap();
        assert_eq!(
            h.as_str(),
            "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5"
        );
    }

    #[test]
    fn exclusion_set_applied() {
        let base = json!({
            "version": 1, "supersedes": null,
            "agent_id": "did:web:x", "contributors": [],
            "title": "T", "type": "data_snapshot",
            "data_refs": [], "derived_from": [], "visibility": "public"
        });
        // Adding excluded fields should NOT change the hash
        let mut with_excluded = base.as_object().unwrap().clone();
        with_excluded.insert("ctx_id".into(), json!("acdp://x/y"));
        with_excluded.insert("created_at".into(), json!("2026-01-01T00:00:00.000Z"));
        with_excluded.insert("content_hash".into(), json!("sha256:aabb"));
        with_excluded.insert(
            "signature".into(),
            json!({"algorithm":"ed25519","key_id":"k","value":"v"}),
        );

        let h1 = compute_content_hash(&base).unwrap();
        let h2 = compute_content_hash(&serde_json::Value::Object(with_excluded)).unwrap();
        assert_eq!(h1, h2, "excluded fields must not affect content_hash");
    }

    #[test]
    fn lineage_id_golden() {
        let ctx = CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into());
        let lid = derive_lineage_id(&ctx);
        assert_eq!(
            lid.as_str(),
            "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a"
        );
    }
    // ── WS-D2 — explain_hash_mismatch diagnostics ───────────────────────

    #[test]
    fn explain_detects_acdp_version_toggle() {
        let mut without = golden_body();
        let h_without = compute_content_hash(&without).unwrap();
        without
            .as_object_mut()
            .unwrap()
            .insert("acdp_version".into(), json!("0.1.0"));
        // Body emits the field; expected hash came from the omitted form.
        let report = explain_hash_mismatch(&without, &h_without).unwrap();
        assert!(
            report.contains("WITHOUT acdp_version"),
            "report must name the omitted-vs-explicit divergence:\n{report}"
        );

        // And the mirror image: body omits, expected hash included it.
        let with_field = without; // has acdp_version now
        let h_with = compute_content_hash(&with_field).unwrap();
        let omitted = golden_body();
        let report = explain_hash_mismatch(&omitted, &h_with).unwrap();
        assert!(
            report.contains("WITH acdp_version"),
            "report must name the explicit-vs-omitted divergence:\n{report}"
        );
    }

    #[test]
    fn explain_detects_sub_ms_timestamp() {
        let mut truncated = golden_body();
        truncated
            .as_object_mut()
            .unwrap()
            .insert("expires_at".into(), json!("2026-06-12T10:30:15.123Z"));
        let expected = compute_content_hash(&truncated).unwrap();

        let mut sub_ms = golden_body();
        sub_ms
            .as_object_mut()
            .unwrap()
            .insert("expires_at".into(), json!("2026-06-12T10:30:15.123456Z"));
        let report = explain_hash_mismatch(&sub_ms, &expected).unwrap();
        assert!(
            report.contains("millisecond-truncated"),
            "report must name the §5.3 truncation divergence:\n{report}"
        );
    }

    #[test]
    fn explain_detects_null_instead_of_omitted() {
        let expected = compute_content_hash(&golden_body()).unwrap();
        let mut with_null = golden_body();
        with_null
            .as_object_mut()
            .unwrap()
            .insert("summary".into(), serde_json::Value::Null);
        let report = explain_hash_mismatch(&with_null, &expected).unwrap();
        assert!(
            report.contains("null-valued optional fields"),
            "report must name the null-vs-absent divergence:\n{report}"
        );
    }

    #[test]
    fn explain_reports_match_and_unknown() {
        let body = golden_body();
        let h = compute_content_hash(&body).unwrap();
        let report = explain_hash_mismatch(&body, &h).unwrap();
        assert!(report.contains("matches"));

        // A completely different expected hash matches no pattern; the
        // report must carry the canonical preimage for manual diffing.
        let bogus = ContentHash(format!("sha256:{}", "0".repeat(64)));
        let report = explain_hash_mismatch(&body, &bogus).unwrap();
        assert!(report.contains("no known divergence pattern"));
        assert!(report.contains("canonical preimage"));
    }

    #[test]
    fn canonical_preimage_round_trips_hash() {
        let body = golden_body();
        let (bytes, hash) = canonical_preimage(&body).unwrap();
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(&bytes);
        assert_eq!(hash.as_str(), format!("sha256:{}", hex::encode(digest)));
    }

    fn golden_body() -> serde_json::Value {
        json!({
            "version": 1,
            "supersedes": null,
            "agent_id": "did:web:agents.example.com:test-producer",
            "contributors": [],
            "title": "Golden test vector — minimal first version",
            "type": "data_snapshot",
            "data_refs": [],
            "derived_from": [],
            "visibility": "public"
        })
    }
}
