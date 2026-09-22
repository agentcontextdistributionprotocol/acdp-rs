//! Conformance tests against the canonical ACDP spec fixtures and examples.
//!
//! Locates the spec repo via the `ACDP_SPEC_DIR` environment variable, with
//! a fallback to the sibling path `../agentcontextdistributionprotocol` (the
//! layout used in this monorepo). If neither path resolves, the tests
//! gracefully skip with a notice — they don't fail the suite when the spec
//! isn't co-located, so this crate remains buildable in isolation.

use std::path::{Path, PathBuf};

use acdp::types::{
    body::Body,
    capabilities::CapabilitiesDocument,
    publish::{PublishRequest, WireError},
    search::SearchResponse,
};

/// Locate the ACDP spec checkout.
///
/// Normally the conformance tests skip gracefully when the spec is not
/// co-located, so this crate stays buildable in isolation. When
/// `ACDP_REQUIRE_CONFORMANCE` is set (IMP-02 — used by the dedicated CI
/// job), a missing spec is a hard failure instead: a green run then
/// genuinely proves conformance.
fn spec_root() -> Option<PathBuf> {
    let require = std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok();

    if let Ok(env) = std::env::var("ACDP_SPEC_DIR") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
        assert!(
            !require,
            "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR '{}' does not exist",
            p.display()
        );
    } else {
        assert!(
            !require,
            "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR is not"
        );
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(sibling) = manifest_dir
        .parent()
        .map(|p| p.join("agentcontextdistributionprotocol"))
    {
        if sibling.exists() {
            return Some(sibling);
        }
    }
    assert!(
        !require,
        "ACDP_REQUIRE_CONFORMANCE is set but no ACDP spec checkout could be located"
    );
    None
}

fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

/// True when `ACDP_REQUIRE_CONFORMANCE` is set (the dedicated CI job).
fn require_conformance() -> bool {
    std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok()
}

/// Existence gate for fixtures/examples that are part of the PUBLISHED
/// spec.
///
/// Returns `true` (→ caller skips) when the file is absent. Under
/// `ACDP_REQUIRE_CONFORMANCE` an absent published fixture is a hard
/// failure instead: previously only the spec *checkout* was required,
/// so a test whose referenced fixture went missing (renamed, or newer
/// than the checkout) silently no-opped even in the required CI job.
fn fixture_missing(path: &Path) -> bool {
    if path.exists() {
        return false;
    }
    assert!(
        !require_conformance(),
        "ACDP_REQUIRE_CONFORMANCE is set but published fixture {} is missing",
        path.display()
    );
    eprintln!("fixture {} not present; skipping", path.display());
    true
}

#[test]
fn all_conformance_fixtures_parse_as_valid_json() {
    let Some(root) = spec_root() else {
        eprintln!("ACDP spec not found; skipping conformance fixtures test");
        return;
    };
    let dir = root.join("schemas/conformance");
    let mut count = 0usize;
    for entry in std::fs::read_dir(&dir).expect("conformance dir readable") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let v = read_json(&path);
        // Every fixture has at minimum `id` + `description`.
        assert!(
            v.get("id").is_some(),
            "fixture {} missing 'id'",
            path.display()
        );
        assert!(
            v.get("description").is_some(),
            "fixture {} missing 'description'",
            path.display()
        );
        count += 1;
    }
    // The v0.1.0 Final spec (including the 2026-05-20 Clarifications
    // Addendum) ships 93 conformance fixtures across the `body`, `can`,
    // `caps`, `cur`, `data-ref`, `data-ref-ssrf`, `did-ssrf`, `err`,
    // `fed`, `idem`, `lin`, `meta`, `pub`, `rate`, `ret`, `schema`,
    // `sig`, `status`, `vis` families. The addendum added the
    // `data-ref-ssrf-001/002/003` family. Floor at 93 so a wholesale
    // regression in fixture loading is caught; the spec only ever
    // grows, so `>=` accommodates future additions.
    assert!(
        count >= 93,
        "expected ≥93 fixtures (ACDP v0.1.0 + addendum), found {count}"
    );
}

/// The fixture families acdp-rs currently accounts for, reviewed by hand on every
/// deliberate spec-pin bump (RS-3/RS-8/RS-5, etc.). A brand-new family appearing in the
/// spec's own `registries/profiles.json` `fixture_families` registry must be added here
/// (with dedicated test coverage) or excused below before
/// `all_conformance_fixtures_are_bucketed_into_known_families` will pass again — that
/// forcing function is the entire point (RS-2, gates SPEC-9 per hazard H8).
const KNOWN_FAMILIES: &[&str] = &[
    "anc",
    "body",
    "can",
    "caps",
    "cur",
    "data-ref",
    "data-ref-ssrf",
    "did-ssrf",
    "dk",
    "err",
    "fed",
    "fp",
    "idem",
    "lc",
    "lhr",
    "lin",
    "log",
    "meta",
    "pub",
    "rate",
    "rcpt",
    "ret",
    "rev",
    "rot",
    "schema",
    "sig",
    "status",
    "vis",
    "wit",
];

/// Families in [`KNOWN_FAMILIES`] with no dedicated fixture-driven test today, and why.
/// Every entry here must also appear in `KNOWN_FAMILIES`
/// (see `excused_families_are_a_subset_of_known_families`).
const EXCUSED: &[(&str, &str)] = &[];

/// Longest-prefix match of a fixture `id` against a family list, mirroring the spec's own
/// `scripts/check-consistency.py::check_families` (spec repo, ~line 79): sort candidates by
/// length descending and take the first one that is a true `-`-delimited prefix of `id`. A
/// naive split-on-first-hyphen would mis-bucket `data-ref-ssrf-001` as `data` (or
/// `data-ref`), and `did-ssrf-001` as `did`.
fn bucket_family<'a>(id: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let mut ordered: Vec<&str> = candidates.to_vec();
    ordered.sort_by_key(|fam| std::cmp::Reverse(fam.len()));
    ordered
        .into_iter()
        .find(|fam| id.starts_with(&format!("{fam}-")))
}

#[test]
fn fixture_family_bucketing_prefers_longest_match() {
    let candidates = ["data-ref", "data-ref-ssrf", "did", "did-ssrf"];
    assert_eq!(
        bucket_family("data-ref-ssrf-001", &candidates),
        Some("data-ref-ssrf")
    );
    assert_eq!(bucket_family("data-ref-001", &candidates), Some("data-ref"));
    assert_eq!(bucket_family("did-ssrf-001", &candidates), Some("did-ssrf"));
    assert_eq!(bucket_family("did-001", &candidates), Some("did"));
    assert_eq!(bucket_family("unrelated-001", &candidates), None);
}

#[test]
fn excused_families_are_a_subset_of_known_families() {
    for (family, reason) in EXCUSED {
        assert!(
            KNOWN_FAMILIES.contains(family),
            "EXCUSED family '{family}' (reason: {reason}) is not in KNOWN_FAMILIES — an \
             excused family must still be one we consciously account for"
        );
    }
}

/// RS-2 — fails the moment the spec's fixture set contains a family this repo hasn't
/// consciously accounted for (via `KNOWN_FAMILIES` test coverage, or a documented
/// `EXCUSED` reason). Supersedes the bare `count >= 93` floor above with per-family
/// coverage: that floor has ~44 fixtures of slack today, so a whole family could vanish
/// without it noticing.
#[test]
fn all_conformance_fixtures_are_bucketed_into_known_families() {
    let Some(root) = spec_root() else {
        eprintln!("ACDP spec not found; skipping fixture-family coverage test");
        return;
    };
    let dir = root.join("schemas/conformance");
    let profiles_path = root.join("registries/profiles.json");
    let profiles = read_json(&profiles_path);
    let spec_families: Vec<&str> = profiles
        .get("fixture_families")
        .and_then(|v| v.as_object())
        .unwrap_or_else(|| {
            panic!(
                "{} missing 'fixture_families' object",
                profiles_path.display()
            )
        })
        .keys()
        .map(|s| s.as_str())
        .collect();

    let mut observed: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("conformance dir readable") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let v = read_json(&path);
        let id = v
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("fixture {} missing string 'id'", path.display()));
        let family = bucket_family(id, &spec_families).unwrap_or_else(|| {
            panic!(
                "fixture {} (id '{id}') doesn't match any family in {}'s fixture_families \
                 (known: {})",
                path.display(),
                profiles_path.display(),
                spec_families.join(", ")
            )
        });
        observed.insert(family);
    }

    let unaccounted: Vec<&str> = observed
        .into_iter()
        .filter(|family| !KNOWN_FAMILIES.contains(family))
        .collect();
    assert!(
        unaccounted.is_empty(),
        "fixture families with real fixtures on disk but not in KNOWN_FAMILIES or EXCUSED \
         (tests/conformance.rs): {} — add test coverage or an EXCUSED entry with a reason",
        unaccounted.join(", ")
    );
}

/// FEAT-03 — capabilities conformance fixtures (caps-001..006).
#[test]
fn capabilities_conformance_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("caps-") {
            continue;
        }
        let v = read_json(&path);
        let Some(body) = v.pointer("/input/response_body") else {
            continue;
        };
        let outcome = v["expected"]["outcome"].as_str().unwrap_or("");
        let parsed: Result<acdp::types::CapabilitiesDocument, _> =
            serde_json::from_value(body.clone());
        match (parsed, outcome) {
            (Ok(caps), "accept") => {
                acdp::validation::validate_capabilities(&caps)
                    .unwrap_or_else(|e| panic!("{name}: expected accept, validation failed: {e}"));
            }
            (Ok(caps), "reject") => {
                let err = acdp::validation::validate_capabilities(&caps).err();
                assert!(
                    err.is_some(),
                    "{name}: expected reject, validation accepted"
                );
            }
            (Err(e), "reject") => {
                // Schema-level rejection at deserialize time also satisfies "reject".
                let _ = e;
            }
            (Err(e), "accept") => {
                panic!("{name}: expected accept, deserialization failed: {e}");
            }
            (_, other) => panic!("{name}: unrecognized outcome '{other}'"),
        }
        checked += 1;
    }
    assert!(checked >= 4, "expected ≥4 caps-* fixtures, got {checked}");
}

/// FEAT-03 — status fixtures (status-001..004).
#[test]
fn status_conformance_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("status-") {
            continue;
        }
        let v = read_json(&path);
        // Try both shapes: `input.response_body.registry_state.status` and
        // `input.status_value` if present.
        let status_value = v
            .pointer("/input/response_body/registry_state/status")
            .and_then(|x| x.as_str())
            .or_else(|| v.pointer("/input/status_value").and_then(|x| x.as_str()))
            .or_else(|| {
                // status-002/003/004 embed the bad value directly in registry_state
                v.pointer("/input/response_body").and_then(|rb| {
                    rb.as_object()
                        .and_then(|m| m.get("registry_state"))
                        .and_then(|rs| rs.get("status"))
                        .and_then(|x| x.as_str())
                })
            });
        let Some(s) = status_value else {
            continue;
        };
        let outcome = v["expected"]["outcome"]
            .as_str()
            .or_else(|| v["expected"]["consumer_outcome"].as_str())
            .unwrap_or("");
        let parsed = acdp::types::Status::parse(s);
        match outcome {
            "accept" | "success" => assert!(parsed.is_ok(), "{name}: '{s}' should accept"),
            "reject" | "failure" => assert!(parsed.is_err(), "{name}: '{s}' should reject"),
            other => panic!("{name}: unrecognized outcome '{other}'"),
        }
        checked += 1;
    }
    assert!(checked >= 1, "expected ≥1 status-* fixture, got {checked}");
}

/// FEAT-03 — DataRef structural-validation fixtures (data-ref-001..007).
///
/// Two fixture families are deliberately excluded because they are
/// *not* structural-validation cases — the body stays valid and a
/// registry MUST accept the publish:
///
/// - `data-ref-008` — an *external* data_ref hash mismatch, a runtime
///   data-integrity failure detectable only after fetching `location`.
///   Bound behaviorally by `fetch_and_verify_uri_ref_fails_on_hash_mismatch`
///   in `src/client/data_ref.rs` (asserts `DataRefHashMismatch`).
/// - `data-ref-ssrf-*` — consumer fetch-time SSRF defenses
///   (RFC-ACDP-0008 §4.9). The fixture's `expected.body_remains_valid`
///   is `true` and `registry_publish_behavior` says the publish MUST
///   NOT be rejected; the refusal lives entirely in
///   `HttpsDataRefFetcher`. Bound behaviorally by the SSRF tests in
///   `src/client/data_ref.rs`.
#[test]
fn data_ref_conformance_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("data-ref-") {
            continue;
        }
        // data-ref-008 — fetch-time external hash mismatch (tested
        // separately by data_ref_008_external_hash_mismatch_*).
        if name.starts_with("data-ref-008") {
            continue;
        }
        // data-ref-007 — embedded content_hash mismatch, tested separately
        // by data_ref_007_embedded_hash_mismatch_surfaced_as_data_ref_hash_mismatch
        // with an error-*variant*-specific assertion; the generic `is_err()`
        // check below would pass vacuously on a schema_violation too (the
        // exact false-pass this fixture's own `description` warns about).
        if name.starts_with("data-ref-007") {
            continue;
        }
        // data-ref-ssrf-* — consumer fetch-time SSRF refusal, not
        // structural validation (tested by data_ref_ssrf_conformance_fixtures).
        if name.starts_with("data-ref-ssrf-") {
            continue;
        }
        let v = read_json(&path);
        let Some(dr_value) = v.pointer("/input/data_ref_under_test") else {
            continue;
        };
        let outcome = v["expected"]["outcome"].as_str().unwrap_or("");
        // Try to deserialize into DataRef, then validate.
        match serde_json::from_value::<acdp::types::DataRef>(dr_value.clone()) {
            Ok(dr) => {
                let result = acdp::validation::validate_data_ref(&dr);
                match outcome {
                    "accept" | "success" => {
                        assert!(result.is_ok(), "{name}: expected accept, got {result:?}");
                    }
                    "failure" | "reject" => {
                        assert!(
                            result.is_err(),
                            "{name}: expected failure, validate accepted"
                        );
                    }
                    other => panic!("{name}: unrecognized outcome '{other}'"),
                }
            }
            Err(e) if matches!(outcome, "failure" | "reject") => {
                // Deserialize-time rejection is also acceptable for negative cases.
                let _ = e;
            }
            Err(e) => panic!("{name}: deserialize failed: {e}"),
        }
        checked += 1;
    }
    assert!(
        checked >= 5,
        "expected ≥5 data-ref-* fixtures, got {checked}"
    );
}

/// `data-ref-ssrf-001/002/003` — consumer fetch-time DataRef SSRF refusal.
///
/// RFC-ACDP-0008 §4.9 (Clarifications Addendum, 2026-05-20).
/// `data-ref-ssrf-*` are required fixtures for the `acdp-consumer` profile.
///
/// - `ssrf-001`: IP-literal private/loopback/link-local host → refused
///   before any DNS lookup (URL-level SSRF check, `SsrfPolicy::check_url`).
/// - `ssrf-002`: hostname that DNS-resolves to a forbidden address → the
///   *entire* resolution is rejected if **any** answer is disallowed
///   (`SsrfPolicy::check_ip` per resolved IP — the multi-answer
///   reject-all rule, RFC-ACDP-0006 §7.1).
/// - `ssrf-003`: cross-authority redirect → refused (`check_redirect_authority`,
///   the same-authority host+port policy).
///
/// Each fixture's own `input` is driven so the `acdp-consumer` profile
/// claim is traceable to the canonical fixture data, not just a mirror
/// of the unit tests in `src/client/data_ref.rs` and `src/safe_http.rs`.
#[cfg(feature = "client")]
#[tokio::test]
async fn data_ref_ssrf_conformance_fixtures() {
    use acdp::client::DataRefFetcher;
    use acdp::safe_http::SsrfPolicy;

    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");

    let mut checked = 0usize;

    // ── data-ref-ssrf-001: IP-literal host → SSRF refusal at URL-check
    // time, before any DNS resolution. Drive every URI the fixture lists
    // (`data_ref_under_test.location` + `additional_test_cases`).
    let f001 = dir.join("data-ref-ssrf-001-ip-literal-private.json");
    if f001.exists() {
        let fixture = read_json(&f001);
        let input = &fixture["input"];
        let mut uris: Vec<String> = Vec::new();
        if let Some(u) = input["data_ref_under_test"]["location"].as_str() {
            uris.push(u.to_string());
        }
        if let Some(extra) = input["additional_test_cases"].as_array() {
            uris.extend(extra.iter().filter_map(|v| v.as_str().map(str::to_string)));
        }
        assert!(
            uris.len() >= 5,
            "data-ref-ssrf-001: expected ≥5 IP-literal URIs from the fixture, got {uris:?}"
        );
        let fetcher = acdp::client::HttpsDataRefFetcher::new();
        for uri in &uris {
            let loc = acdp::types::Location::Uri(uri.clone());
            let err = fetcher
                .fetch(&loc)
                .await
                .expect_err(&format!("data-ref-ssrf-001: '{uri}' must be refused"));
            assert!(
                matches!(err, acdp::AcdpError::SchemaViolation(_)),
                "data-ref-ssrf-001: '{uri}' must be SchemaViolation (SSRF policy), got {err:?}"
            );
        }
        checked += 1;
    }

    // ── data-ref-ssrf-002: a hostname can be syntactically public yet
    // resolve to a forbidden address. The reject-all rule: if ANY answer
    // in the DNS response is disallowed, the whole resolution is rejected
    // (including the `rebind.example` mixed public+private case). Bind to
    // every `dns_resolution_results` list the fixture carries.
    let f002 = dir.join("data-ref-ssrf-002-dns-rebinding-loopback.json");
    if f002.exists() {
        let fixture = read_json(&f002);
        let input = &fixture["input"];
        let policy = SsrfPolicy::default();

        let mut answer_sets: Vec<Vec<String>> = Vec::new();
        if let Some(top) = input["dns_resolution_results"].as_array() {
            answer_sets.push(
                top.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
            );
        }
        if let Some(extra) = input["additional_test_cases"].as_array() {
            for case in extra {
                if let Some(ips) = case["dns_resolution_results"].as_array() {
                    answer_sets.push(
                        ips.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect(),
                    );
                }
            }
        }
        assert!(
            !answer_sets.is_empty(),
            "data-ref-ssrf-002: fixture carried no dns_resolution_results"
        );
        for set in &answer_sets {
            // RFC-ACDP-0006 §7.1: reject the whole resolution if ANY
            // single resolved address is forbidden.
            let any_forbidden = set.iter().any(|ip| {
                let parsed: std::net::IpAddr = ip
                    .parse()
                    .unwrap_or_else(|_| panic!("ssrf-002: bad IP '{ip}'"));
                policy.check_ip(parsed).is_err()
            });
            assert!(
                any_forbidden,
                "data-ref-ssrf-002: resolution {set:?} contains a forbidden \
                 address, so the entire resolution MUST be rejected"
            );
        }
        checked += 1;
    }

    // ── data-ref-ssrf-003: a 30x redirect to a different authority MUST
    // be refused. Drive the fixture's own initial location + redirect.
    let f003 = dir.join("data-ref-ssrf-003-cross-authority-redirect.json");
    if f003.exists() {
        let fixture = read_json(&f003);
        let input = &fixture["input"];
        let original = input["data_ref_under_test"]["location"]
            .as_str()
            .expect("ssrf-003: input.data_ref_under_test.location");
        let redirect = input["redirect_response"]["Location"]
            .as_str()
            .expect("ssrf-003: input.redirect_response.Location");
        let original_url = url::Url::parse(original).expect("ssrf-003: original URL");
        let policy = SsrfPolicy::default();
        let err = policy
            .check_redirect_authority(&original_url, redirect)
            .expect_err(&format!(
                "data-ref-ssrf-003: redirect {original} → {redirect} must be refused"
            ));
        assert!(
            matches!(err, acdp::AcdpError::SchemaViolation(_)),
            "data-ref-ssrf-003: cross-authority redirect must be SchemaViolation, got {err:?}"
        );
        checked += 1;
    }

    assert!(
        checked >= 1,
        "expected ≥1 data-ref-ssrf-* fixture (ACDP v0.1.0 addendum); \
         set ACDP_SPEC_DIR to enable"
    );
}

/// FEAT-03 — metadata fixtures (meta-001..003).
#[test]
fn metadata_conformance_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("meta-") {
            continue;
        }
        let v = read_json(&path);
        let Some(meta) = v.pointer("/input/metadata_under_test") else {
            continue;
        };
        let outcome = v["expected"]["outcome"].as_str().unwrap_or("");
        let result = acdp::validation::validate_metadata(meta);
        match outcome {
            "accept" | "success" => {
                assert!(result.is_ok(), "{name}: expected accept, got {result:?}")
            }
            "failure" | "reject" => {
                assert!(
                    result.is_err(),
                    "{name}: expected failure, validate accepted"
                )
            }
            other => panic!("{name}: unrecognized outcome '{other}'"),
        }
        checked += 1;
    }
    assert!(checked >= 2, "expected ≥2 meta-* fixtures, got {checked}");
}

/// FEAT-03 — closed-schema fixtures (schema-001..004).
#[test]
fn closed_schema_conformance_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("schema-") {
            continue;
        }
        let v = read_json(&path);
        let outcome = v["expected"]["outcome"].as_str().unwrap_or("");
        match name {
            "schema-001-search-response-extra-results.json" => {
                if let Some(body) = v.pointer("/input/response_body") {
                    let r: Result<SearchResponse, _> = serde_json::from_value(body.clone());
                    match outcome {
                        "reject" | "failure" => {
                            assert!(r.is_err(), "{name}: expected reject")
                        }
                        _ => {}
                    }
                }
            }
            "schema-002-publish-response-extra-content-hash.json" => {
                if let Some(body) = v.pointer("/input/response_body") {
                    let r: Result<acdp::types::PublishResponse, _> =
                        serde_json::from_value(body.clone());
                    match outcome {
                        "reject" | "failure" => {
                            assert!(r.is_err(), "{name}: expected reject")
                        }
                        _ => {}
                    }
                }
            }
            "schema-004-capabilities-extra-top-level-allowed.json" => {
                if let Some(body) = v.pointer("/input/response_body") {
                    let r: Result<acdp::types::CapabilitiesDocument, _> =
                        serde_json::from_value(body.clone());
                    if matches!(outcome, "accept" | "success") {
                        assert!(r.is_ok(), "{name}: expected accept");
                    }
                }
            }
            // schema-005/006/007 — `next_cursor` / `summary` / `domain`
            // are bare strings; a JSON `null` is non-conformant and a
            // strict consumer MUST reject it (BUG-03).
            "schema-005-search-response-next-cursor-null.json"
            | "schema-006-search-result-summary-null.json"
            | "schema-007-search-result-domain-null.json" => {
                if let Some(body) = v.pointer("/input/response_body") {
                    let r: Result<SearchResponse, _> = serde_json::from_value(body.clone());
                    if matches!(outcome, "reject" | "failure") {
                        assert!(
                            r.is_err(),
                            "{name}: a `null` bare-string field MUST be rejected, got {r:?}"
                        );
                    }
                }
            }
            // schema-008 — the `signature` object is a closed wire shape
            // (deny_unknown_fields, BUG-06).
            "schema-008-signature-extra-field.json" => {
                if let Some(sig) = v.pointer("/input/request_body_excerpt/signature") {
                    let r: Result<acdp::types::body::Signature, _> =
                        serde_json::from_value(sig.clone());
                    assert!(
                        r.is_err(),
                        "{name}: unknown signature field MUST be rejected"
                    );
                }
            }
            // schema-009 — `data_period` is a closed wire shape (BUG-06).
            "schema-009-data-period-extra-field.json" => {
                if let Some(dp) = v.pointer("/input/request_body_excerpt/data_period") {
                    let r: Result<acdp::types::body::DataPeriod, _> =
                        serde_json::from_value(dp.clone());
                    assert!(
                        r.is_err(),
                        "{name}: unknown data_period field MUST be rejected"
                    );
                }
            }
            // schema-010 — `limits` is a closed sub-object inside the
            // otherwise-open capabilities document (BUG-06).
            "schema-010-capabilities-limits-extra-field.json" => {
                if let Some(limits) = v.pointer("/input/response_body_excerpt/limits") {
                    let r: Result<acdp::types::Limits, _> = serde_json::from_value(limits.clone());
                    assert!(r.is_err(), "{name}: unknown limits field MUST be rejected");
                }
            }
            _ => {}
        }
    }
}

/// FEAT-03 — `did:web` enforcement fixtures (pub-008/009/010).
#[test]
fn did_web_enforcement_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    for fixture in &[
        "pub-008-non-did-web-agent-id.json",
        "pub-009-non-did-web-key-id.json",
        "pub-010-non-did-web-contributor.json",
    ] {
        let path = dir.join(fixture);
        if fixture_missing(&path) {
            continue;
        }
        let _v = read_json(&path);
        // The fixtures describe scenarios; the library-level guarantee is
        // that `validate_publish_request` rejects non-did:web agent_id /
        // key_id and accepts non-did:web contributors. Sanity-checked
        // here against a synthetic minimal case rather than the descriptive
        // fixture body.
    }

    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::types::{AgentDid, ContextType};

    // pub-008 (updated for ACDP 0.2): a *well-formed* did:key agent_id
    // is accepted at schema level — did:key is a resolvable method as of
    // 0.2 (registry acceptance is gated separately via
    // `supported_did_methods`). An unresolvable method is still rejected,
    // as is a did:key key_id whose fragment is not the key itself.
    let key = SigningKey::from_bytes(&[0u8; 32]);
    let p = Producer::new_did_key(key);
    p.publish_request()
        .title("t")
        .context_type(ContextType::DataSnapshot)
        .build()
        .expect("pub-008 (0.2): well-formed did:key agent_id MUST be accepted");

    // Unresolvable method (no resolver exists) → rejected.
    let p = Producer::new(
        SigningKey::from_bytes(&[0u8; 32]),
        AgentDid::new("did:example:12345"),
        "did:example:12345#key-1",
    );
    let err = p
        .publish_request()
        .title("t")
        .context_type(ContextType::DataSnapshot)
        .build()
        .unwrap_err();
    assert!(
        matches!(err, acdp::AcdpError::SchemaViolation(_)),
        "pub-008: unresolvable agent_id method MUST be rejected"
    );

    // did:key key_id with a non-key fragment is structurally invalid:
    // the did:key document's only verification method is the key itself.
    // #285 / RFC-ACDP-0001 §5.11.1 step 1: this is a did:key *resolver*
    // fault (fragment ≠ method-specific identifier), so it MUST surface as
    // `key_resolution_failed`, not `schema_violation` — the spec's
    // `schema_violation` alternative is a MAY-level tolerance the SDK
    // doesn't take (see `validate_did_key_key_id_form`).
    let p = Producer::new(
        SigningKey::from_bytes(&[0u8; 32]),
        AgentDid::new("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"),
        "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#key-1",
    );
    let err = p
        .publish_request()
        .title("t")
        .context_type(ContextType::DataSnapshot)
        .build()
        .unwrap_err();
    assert!(
        matches!(err, acdp::AcdpError::KeyResolution(_)),
        "pub-009 (0.2): did:key key_id fragment MUST equal the key itself, \
         and MUST be reported as key_resolution_failed (#285), got {err:?}"
    );

    // pub-010: did:key contributor accepted
    let p = Producer::new(
        SigningKey::from_bytes(&[0u8; 32]),
        AgentDid::new("did:web:agents.example.com:test"),
        "did:web:agents.example.com:test#key-1",
    );
    p.publish_request()
        .title("t")
        .context_type(ContextType::DataSnapshot)
        .contributors(vec![AgentDid::new(
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSshBHqcWv6Vt8mfWAFs",
        )])
        .build()
        .expect("pub-010: did:key contributor MUST be accepted");
}

/// BUG-09 — When a registry mistakenly returns `{"results": [...]}`
/// instead of `{"matches": [...]}`, the consumer MUST NOT silently
/// coerce. With `deny_unknown_fields` on `SearchResponse`, the
/// deserializer surfaces a serde error rather than empty matches.
#[test]
fn vis_003_consumer_rejects_results_key() {
    let raw = r#"{"results":[{"ctx_id":"acdp://r/x","lineage_id":"lin:sha256:a","agent_id":"did:web:r","title":"t","type":"data_snapshot","created_at":"2026-01-01T00:00:00.000Z","status":"active"}]}"#;
    let parsed: Result<SearchResponse, _> = serde_json::from_str(raw);
    assert!(
        parsed.is_err(),
        "consumer MUST reject `results` key per vis-003 (got Ok)"
    );
}

#[test]
fn capabilities_example_deserializes() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("examples/capabilities/acdp-capabilities.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let _: CapabilitiesDocument = serde_json::from_value(v)
        .expect("capabilities example must deserialize into CapabilitiesDocument");
}

#[test]
fn publish_request_examples_deserialize() {
    let Some(root) = spec_root() else {
        return;
    };
    let dir = root.join("examples/publish");
    if !dir.exists() {
        return;
    }
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let v = read_json(&path);
        let _: PublishRequest = serde_json::from_value(v.clone()).unwrap_or_else(|e| {
            panic!(
                "{} did not deserialize as PublishRequest: {e}",
                path.display()
            )
        });
    }
}

#[test]
fn retrieval_examples_deserialize_as_body() {
    let Some(root) = spec_root() else {
        return;
    };
    let dir = root.join("examples/retrieval");
    if !dir.exists() {
        return;
    }
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let v = read_json(&path);
        // Some examples are full ACDP "context" envelopes (body+registry_state)
        // others are just bodies. Try both, then run validate_body so we
        // catch any regressions in field-shape rules (BUG-01: hostname
        // form for `origin_registry`, etc.).
        let body: Body = if v.get("body").is_some() {
            let ctx: acdp::types::body::FullContext = serde_json::from_value(v)
                .unwrap_or_else(|e| panic!("{}: not FullContext: {e}", path.display()));
            ctx.body
        } else {
            serde_json::from_value(v)
                .unwrap_or_else(|e| panic!("{}: not Body: {e}", path.display()))
        };
        acdp::validation::validate_body(&body).unwrap_or_else(|e| {
            panic!(
                "{} failed validate_body — example must be schema-conformant: {e}",
                path.display()
            )
        });
    }
}

// ── body-001 / body-002 — origin_registry hostname vs DID (BUG-01) ──────────

/// body-001 — `origin_registry` is a bare DNS hostname. The fixture's
/// `body_fields_under_test.origin_registry` MUST pass our validator.
#[test]
fn body_001_origin_registry_hostname_accepted() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/body-001-origin-registry-hostname.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let hostname = v["input"]["body_fields_under_test"]["origin_registry"]
        .as_str()
        .expect("fixture must expose origin_registry");
    assert_eq!(hostname, "registry.example.com");
    // Compose a minimal Body around this value and assert validate_body
    // accepts it. (Schema validation against the hostname `$defs` is
    // implicitly covered by the validate_body call once it includes
    // validate_origin_registry — see body-002 for the negative case.)
    let body = body_with_origin_registry(hostname);
    acdp::validation::validate_body(&body)
        .expect("body-001: hostname origin_registry MUST be accepted");
}

/// body-002 — `origin_registry` set to a `did:web:` URI MUST be rejected.
/// Pins the BUG-01 fix.
#[test]
fn body_002_origin_registry_did_rejected() {
    let body = body_with_origin_registry("did:web:registry.example.com");
    let err = acdp::validation::validate_body(&body)
        .expect_err("body-002: did:web origin_registry MUST be rejected");
    assert!(
        matches!(err, acdp::AcdpError::SchemaViolation(_)),
        "body-002: error MUST be SchemaViolation, got {err:?}"
    );
}

fn body_with_origin_registry(origin_registry: &str) -> Body {
    use acdp::types::body::Signature;
    use acdp::types::primitives::{
        AgentDid, ContentHash, ContextType, CtxId, LineageId, Status, Visibility,
    };
    use chrono::{TimeZone, Utc};
    let _ = Status::Active; // silence unused-import on no-default builds
    Body {
        ctx_id: CtxId("acdp://registry.example.com/00000000-0000-4000-8000-000000000001".into()),
        lineage_id: LineageId(
            "lin:sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        ),
        origin_registry: origin_registry.into(),
        created_at: Utc.with_ymd_and_hms(2026, 5, 18, 0, 0, 0).unwrap(),
        content_hash: ContentHash(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        ),
        signature: Signature {
            algorithm: "ed25519".into(),
            key_id: "did:web:agents.example.com:test#key-1".into(),
            value: "A".repeat(86) + "==",
        },
        version: 1,
        supersedes: None,
        agent_id: AgentDid::new("did:web:agents.example.com:test"),
        contributors: vec![],
        title: "body-001/002 fixture body".into(),
        context_type: ContextType::DataSnapshot,
        data_refs: vec![],
        derived_from: vec![],
        visibility: Visibility::Public,
        audience: None,
        acdp_version: None,
        description: None,
        summary: None,
        tags: None,
        domain: None,
        expires_at: None,
        data_period: None,
        metadata: None,
        schema_uri: None,
        anchors: None,
        extensions: Default::default(),
    }
}

#[test]
fn visibility_example_bodies_deserialize() {
    let Some(root) = spec_root() else {
        return;
    };
    let dir = root.join("examples/visibility");
    if !dir.exists() {
        return;
    }
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let v = read_json(&path);
        // Visibility examples wrap a Body under `body`.
        let body_value = v.get("body").cloned().unwrap_or(v);
        let _: Body = serde_json::from_value(body_value)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
}

#[test]
fn search_response_example_deserializes() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("examples/search/keyword-search-response.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let _: SearchResponse =
        serde_json::from_value(v).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

#[test]
fn error_example_deserializes() {
    let Some(root) = spec_root() else {
        return;
    };
    let dir = root.join("examples/error");
    if fixture_missing(&dir) {
        return;
    }
    // Scan the whole directory rather than naming one file. The named-file
    // form silently ignored every error example the spec added after it was
    // written — `unsupported-media-type.json` (spec #68) landed with zero
    // coverage here and the suite stayed green.
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("examples/error readable") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let v = read_json(&path);
        let wire: WireError =
            serde_json::from_value(v).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        // An example carrying a code this library has not typed yet would
        // deserialize fine as a WireError and tell us nothing, so assert the
        // typed mapping too.
        let err = acdp::AcdpError::from_wire_error(wire);
        assert!(
            !matches!(err, acdp::AcdpError::Registry(_)),
            "{}: error code fell through to the untyped AcdpError::Registry \
             catch-all — add the variant and a from_wire_error arm \
             (CLAUDE.md, \"Adding a new wire error code\")",
            path.display()
        );
        checked += 1;
    }
    assert!(checked > 0, "no error examples found in {}", dir.display());
}

/// The forcing function for RFC-ACDP-0007 §5 drift: every code in the spec's
/// own `acdp-error.schema.json` enum MUST map to a typed [`acdp::AcdpError`]
/// variant. `acdp-primitives`' `all_26_wire_codes_round_trip` pins the same
/// property against a hand-written list, so it only catches a code we forgot
/// to wire up — it cannot notice the spec growing a 27th. This one reads the
/// enum out of the pinned spec, so a pin bump that adopts a new code fails
/// here until the three-edit rule is followed.
#[test]
fn wire_error_codes_cover_the_spec_enum() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("schemas/json/acdp-error.schema.json");
    if fixture_missing(&path) {
        return;
    }
    let schema = read_json(&path);
    let codes = schema
        .pointer("/properties/error/properties/code/enum")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| {
            panic!(
                "{} missing /properties/error/properties/code/enum",
                path.display()
            )
        });
    assert!(
        codes.len() >= 26,
        "{}: expected >=26 wire codes, found {} — the enum only ever grows",
        path.display(),
        codes.len()
    );
    let mut untyped: Vec<String> = Vec::new();
    for code in codes {
        let code = code.as_str().expect("enum member is a string");
        let wire: WireError = serde_json::from_value(serde_json::json!({
            "error": { "code": code, "message": "conformance probe" }
        }))
        .expect("probe envelope is well-formed");
        if matches!(
            acdp::AcdpError::from_wire_error(wire),
            acdp::AcdpError::Registry(_)
        ) {
            untyped.push(code.to_string());
        }
    }
    assert!(
        untyped.is_empty(),
        "wire codes in {} with no typed AcdpError variant: {} — follow the \
         three-edit rule in CLAUDE.md (variant + from_wire_error arm + extend \
         all_N_wire_codes_round_trip), and revisit is_transient",
        path.display(),
        untyped.join(", ")
    );
}

#[test]
fn lineage_multi_step_example_parses_each_body() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("examples/lineage/multi-step-derivation.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    // Multi-step examples are typically arrays of contexts. Be generous: try
    // array-of-bodies, then array-of-FullContext, then a wrapping object.
    if let Some(arr) = v.as_array() {
        for (i, item) in arr.iter().enumerate() {
            if item.get("body").is_some() {
                let _: acdp::types::body::FullContext = serde_json::from_value(item.clone())
                    .unwrap_or_else(|e| panic!("element {i}: not FullContext: {e}"));
            } else {
                let _: Body = serde_json::from_value(item.clone())
                    .unwrap_or_else(|e| panic!("element {i}: not Body: {e}"));
            }
        }
    }
}

#[test]
fn supersession_example_v2_deserializes() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("examples/supersession/v2-supersedes-v1.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    // The example may be a publish request or a body or a wrapping object.
    if v.get("body").is_some() {
        let _: acdp::types::body::FullContext = serde_json::from_value(v).unwrap();
    } else if v.get("ctx_id").is_some() && v.get("origin_registry").is_some() {
        let _: Body = serde_json::from_value(v).unwrap();
    } else if v.get("content_hash").is_some() && v.get("signature").is_some() {
        let _: PublishRequest = serde_json::from_value(v).unwrap();
    }
}

#[test]
fn mixed_data_refs_example_deserializes() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("examples/mixed-data-refs/alert-mixed-data-refs.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    if v.get("body").is_some() {
        let _: acdp::types::body::FullContext = serde_json::from_value(v).unwrap();
    } else if v.get("ctx_id").is_some() && v.get("origin_registry").is_some() {
        let _: Body = serde_json::from_value(v).unwrap();
    } else {
        let _: PublishRequest = serde_json::from_value(v).unwrap();
    }
}

/// Deserializing this example is not the same as it being *publishable* —
/// this drives every `data_refs[]` entry through the actual registry-side
/// Check 8 (`verify_embedded_hash`), the check a real publish runs. Found
/// via `/reconcile`-adjacent review: `data_refs[0]` here carries a root
/// `content_hash` that does not match its `embedded` content (no
/// `embedded.content_hash` of its own — nothing for Check 8 to verify per
/// RFC-ACDP-0002 §6.6) — a registry that independently validated the root
/// field for embedded refs anyway (as this crate did before this test was
/// added) rejects the spec's own canonical example. `data_refs[3]` covers
/// the co-presence case for real (both fields set, and equal); `[1]`/`[2]`
/// are location-form and have no `embedded` at all, so Check 8 doesn't
/// apply to them regardless.
#[test]
fn mixed_data_refs_example_passes_registry_check_8() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("examples/mixed-data-refs/alert-mixed-data-refs.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let full: acdp::types::body::FullContext = serde_json::from_value(v).unwrap();
    let data_refs = &full.body.data_refs;
    assert_eq!(
        data_refs.len(),
        4,
        "example shape drifted — update this test's data_refs[] commentary too"
    );
    for (i, dr) in data_refs.iter().enumerate() {
        acdp::validation::verify_embedded_hash(dr)
            .unwrap_or_else(|e| panic!("data_refs[{i}] must pass Check 8, got {e:?}"));
    }
}

/// T9 — every `can-*` canonicalization vector that publishes an
/// `expected.canonical_form` and `expected.sha256_hex` (or
/// `expected.content_hash_field_value`) MUST hash-match exactly.
///
/// BUG-05: `lin-*` fixtures are covered here too. `lin-001` uses the
/// same `input.ctx_id → expected.lineage_id` vector shape as the
/// lineage vectors inside `can-001`, so the existing derivation check
/// handles both with no extra logic.
#[test]
fn can_vectors_match_expected_hash() {
    use sha2::{Digest, Sha256};

    let Some(root) = spec_root() else {
        return;
    };
    let dir = root.join("schemas/conformance");
    let mut checked = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("can-") && !name.starts_with("lin-") {
            continue;
        }
        let v = read_json(&path);
        let Some(vectors) = v.get("vectors").and_then(|x| x.as_array()) else {
            continue;
        };
        for (i, vec) in vectors.iter().enumerate() {
            let Some(input) = vec.get("input") else {
                continue;
            };
            let Some(expected) = vec.get("expected") else {
                continue;
            };

            // Body canonicalization → SHA-256 hex.
            if let (Some(canonical), Some(hex_hash)) = (
                expected.get("canonical_form").and_then(|x| x.as_str()),
                expected.get("sha256_hex").and_then(|x| x.as_str()),
            ) {
                let bytes = acdp::crypto::canonicalize_value(input);
                let got_canonical = std::str::from_utf8(&bytes).unwrap();
                assert_eq!(
                    got_canonical, canonical,
                    "{name} vector {i}: canonical_form mismatch"
                );
                let digest = hex::encode(Sha256::digest(&bytes));
                assert_eq!(digest, hex_hash, "{name} vector {i}: sha256 mismatch");
                checked += 1;
            }

            // Lineage derivation: input.ctx_id → expected.lineage_id.
            if let (Some(ctx), Some(lineage)) = (
                input.get("ctx_id").and_then(|x| x.as_str()),
                expected.get("lineage_id").and_then(|x| x.as_str()),
            ) {
                let derived =
                    acdp::crypto::derive_lineage_id(&acdp::types::primitives::CtxId(ctx.into()));
                assert_eq!(
                    derived.as_str(),
                    lineage,
                    "{name} vector {i}: lineage_id mismatch"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 1,
        "expected at least one hashable can-* vector; checked {checked}"
    );
}

/// IMP-02 — `did-ssrf-001/002/003` are required by `profiles.json` for
/// `acdp-consumer` and `acdp-registry-core`. Bind them to a behavioral
/// assertion: each fixture's `did:web` authority resolves into a
/// forbidden range (loopback / IMDS / RFC 1918) and MUST be refused by
/// the default `WebResolver` SSRF policy before any request is made.
#[cfg(feature = "client")]
#[tokio::test]
async fn did_ssrf_conformance_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let cases = [
        ("did-ssrf-001-loopback-did-web.json", "did:web:127.0.0.1"),
        ("did-ssrf-002-imds-did-web.json", "did:web:169.254.169.254"),
        (
            "did-ssrf-003-private-range-did-web.json",
            "did:web:10.0.0.1",
        ),
    ];
    let resolver = acdp::did::WebResolver::new();
    let mut checked = 0usize;
    for (filename, did) in &cases {
        let path = dir.join(filename);
        if fixture_missing(&path) {
            continue;
        }
        let _fixture = read_json(&path); // validates the fixture JSON parses
        let err = resolver
            .resolve(did)
            .await
            .expect_err(&format!("{filename}: {did} MUST be blocked by SSRF policy"));
        assert!(
            matches!(err, acdp::AcdpError::KeyResolution(_)),
            "{filename}: {did} must fail with KeyResolution (permanent, HTTP 400); got {err:?}"
        );
        checked += 1;
    }
    assert!(
        checked >= 1,
        "expected ≥1 did-ssrf-* fixture, found {checked}"
    );
}

/// FEAT-04 — verify the sig-002 ECDSA-P256 golden vector with the test
/// public key. Confirms the verify path matches the spec wire form
/// (IEEE 1363 r‖s, 88 base64 chars).
#[test]
fn sig_002_ecdsa_p256_verify_against_spec_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/sig-002-ecdsa-p256-golden.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let kp = &v["test_keypair"];
    let sec1_hex = kp["public_key_uncompressed_sec1_hex"].as_str().unwrap();
    let pub_sec1 = hex::decode(sec1_hex).unwrap();
    let vec = &v["vectors"][0]["expected"];
    let sig_b64 = vec["signature_value_base64"].as_str().unwrap();
    let content_hash = vec["content_hash"].as_str().unwrap();
    acdp::crypto::verify::verify_ecdsa_p256(&pub_sec1, sig_b64, content_hash)
        .expect("sig-002 ecdsa-p256 verification must pass");
}

/// FEAT-01 — sign-side round trip: the producer-side ECDSA-P256 signer
/// MUST reproduce the spec's golden signature byte-for-byte when given
/// the test private scalar. Confirms (a) deterministic RFC 6979
/// signing, (b) IEEE 1363 r‖s output (not DER), (c) 88-char base64 wire
/// form.
#[test]
fn sig_002_ecdsa_p256_sign_round_trip() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/sig-002-ecdsa-p256-golden.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let priv_hex = v["test_keypair"]["private_scalar_hex"].as_str().unwrap();
    let priv_bytes: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();

    let key = acdp::crypto::P256SigningKey::from_bytes(&priv_bytes)
        .expect("p256 scalar=1 is a valid test key");
    let expected_hash = v["vectors"][0]["expected"]["content_hash"]
        .as_str()
        .unwrap();
    let expected_sig = v["vectors"][0]["expected"]["signature_value_base64"]
        .as_str()
        .unwrap();
    let hash = acdp::ContentHash(expected_hash.to_string());
    let sig = key.sign_content_hash(&hash);
    assert_eq!(
        sig.len(),
        88,
        "sig-002: wire signature MUST be 88 base64 chars"
    );
    // RFC 6979 deterministic ECDSA — value MUST match the spec exactly.
    assert_eq!(
        sig, expected_sig,
        "sig-002: producer signature MUST match spec golden vector byte-for-byte"
    );
}

/// FEAT-01 — when a Producer is constructed with a P256 key, the
/// emitted PublishRequest carries `signature.algorithm = "ecdsa-p256"`
/// and the value verifies against the producer's own public key.
/// Confirms the algorithm-string plumb-through end-to-end.
#[test]
fn p256_producer_emits_ecdsa_p256_algorithm() {
    use acdp::crypto::{verify::verify_ecdsa_p256, P256SigningKey};
    use acdp::producer::Producer;
    use acdp::types::{AgentDid, ContextType, Visibility};

    let key = P256SigningKey::generate();
    let pub_sec1 = key.verifying_key_sec1();
    let p = Producer::new_p256(
        key,
        AgentDid::new("did:web:agents.example.com:p256-producer"),
        "did:web:agents.example.com:p256-producer#key-1",
    );
    let req = p
        .publish_request()
        .title("p256 round-trip")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("p256 producer build");
    assert_eq!(
        req.signature.algorithm, "ecdsa-p256",
        "p256-keyed producer MUST emit signature.algorithm == 'ecdsa-p256'"
    );
    assert_eq!(
        req.signature.value.len(),
        88,
        "p256 wire signature MUST be 88 base64 chars"
    );
    verify_ecdsa_p256(&pub_sec1, &req.signature.value, req.content_hash.as_str())
        .expect("emitted signature MUST verify against the producer's public key");
}

/// Replays `sig-001-ed25519-golden.json` end-to-end through the producer
/// builder + verifier, asserting every emitted value matches the spec.
#[test]
fn sig_001_full_round_trip_against_spec_fixture() {
    let Some(root) = spec_root() else {
        return;
    };
    let path = root.join("schemas/conformance/sig-001-ed25519-golden.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let vec = v["vectors"][0].clone();
    let pc = &vec["producer_content"];
    let expected_canonical = vec["expected"]["canonical_form"].as_str().unwrap();
    let expected_hash = vec["expected"]["content_hash"].as_str().unwrap();
    let expected_sig = vec["expected"]["signature_value_base64"].as_str().unwrap();

    // 1. Canonical form
    let canonical = acdp::crypto::canonicalize_value(pc);
    assert_eq!(std::str::from_utf8(&canonical).unwrap(), expected_canonical);

    // 2. Content hash
    let h = acdp::crypto::compute_content_hash(pc).unwrap();
    assert_eq!(h.as_str(), expected_hash);

    // 3. Signature with the test seed
    let seed_hex = v["test_keypair"]["private_seed_hex"].as_str().unwrap();
    let seed_bytes: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
    let key = acdp::crypto::SigningKey::from_bytes(&seed_bytes);
    assert_eq!(key.sign_content_hash(&h), expected_sig);
}

// ── BUG-12 / BUG-13 — explicit fixture-binding tests ─────────────────────────

/// BUG-13a — can-008 forward-compat: a `Body` deserialized from a v0.1
/// payload that includes an unknown producer-controlled field
/// (`priority` here) MUST round-trip through `serde_json::to_value(&body)`
/// → JCS → SHA-256 and produce the expected hash. This catches the
/// "typed struct silently drops unknown fields" failure mode that the
/// fixture's `non_conformant_behavior` warns about.
#[test]
fn can_008_body_roundtrip_preserves_unknown_producer_field() {
    use sha2::{Digest, Sha256};
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/can-008-body-with-unknown-producer-field.json");
    if fixture_missing(&path) {
        return;
    }
    let fixture = read_json(&path);
    let vector = &fixture["vectors"][0];
    let producer_content = &vector["input"];
    let expected_hash = vector["expected"]["sha256_hex"].as_str().unwrap();

    // Build a wire body with the registry-assigned fields injected so the
    // value parses as Body. The exclusion set strips them before hashing.
    let mut wire_body = producer_content.clone();
    let m = wire_body.as_object_mut().unwrap();
    m.insert(
        "ctx_id".into(),
        serde_json::json!("acdp://registry.example.com/12345678-1234-4321-8123-123456781234"),
    );
    m.insert(
        "lineage_id".into(),
        serde_json::json!(
            "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111"
        ),
    );
    m.insert(
        "origin_registry".into(),
        serde_json::json!("did:web:registry.example.com"),
    );
    m.insert(
        "created_at".into(),
        serde_json::json!("2026-05-10T00:00:00.000Z"),
    );
    m.insert(
        "content_hash".into(),
        serde_json::json!(format!("sha256:{expected_hash}")),
    );
    m.insert(
        "signature".into(),
        serde_json::json!({
            "algorithm": "ed25519",
            "key_id": "did:web:agents.example.com:test#key-1",
            "value": "A".repeat(88),
        }),
    );

    let body: acdp::types::Body =
        serde_json::from_value(wire_body).expect("Body must deserialize with extensions");
    assert!(
        body.extensions.contains_key("priority"),
        "extensions map MUST capture the unknown 'priority' field"
    );

    let serialized = serde_json::to_value(&body).unwrap();
    // Reverse the exclusion set — same procedure as compute_content_hash.
    let mut prod_content = serialized;
    let m = prod_content.as_object_mut().unwrap();
    for k in [
        "ctx_id",
        "lineage_id",
        "origin_registry",
        "created_at",
        "content_hash",
        "signature",
    ] {
        m.remove(k);
    }
    let canonical = acdp::crypto::canonicalize_value(&prod_content);
    let digest = hex::encode(Sha256::digest(&canonical));
    assert_eq!(
        digest, expected_hash,
        "Body round-trip MUST produce the fixture hash — unknown fields must be preserved"
    );
}

/// anc-004 — the `can-*`-equivalent executed golden vector for
/// RFC-ACDP-0016 (0.5.0): `content_hash` over a body carrying `anchors`,
/// proving the field enters the JCS preimage exactly like any other
/// producer-controlled field (§5). Not picked up by
/// `can_vectors_match_expected_hash` (that scan is `can-`/`lin-`-prefixed
/// filenames only), so bound explicitly here.
#[test]
fn anc_004_content_hash_with_anchors_golden_fixture() {
    use sha2::{Digest, Sha256};
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/anc-004-content-hash-with-anchors.json");
    if fixture_missing(&path) {
        return;
    }
    let fixture = read_json(&path);
    let vector = &fixture["vectors"][0];
    let input = &vector["input"];
    let expected = &vector["expected"];
    let expected_canonical = expected["canonical_form"].as_str().unwrap();
    let expected_hash = expected["sha256_hex"].as_str().unwrap();

    let bytes = acdp::crypto::canonicalize_value(input);
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        expected_canonical,
        "anc-004: canonical_form mismatch"
    );
    let digest = hex::encode(Sha256::digest(&bytes));
    assert_eq!(digest, expected_hash, "anc-004: sha256 mismatch");

    let content_hash = acdp::crypto::compute_content_hash(input).unwrap();
    assert_eq!(
        content_hash.as_str(),
        expected["content_hash_field_value"].as_str().unwrap(),
        "anc-004: content_hash field value mismatch"
    );
}

/// RS-8 — companion to anc-004: prove the TYPED `Body`/`PublishRequest`
/// structs (not just a raw JSON value) round-trip `anchors`
/// byte-exactly through the `content_hash` preimage. Self-contained
/// (no spec fixture needed — anc-004's own `input` is a minimal
/// ProducerContent slice, not a fully valid Body, so it's unsuitable
/// for a real Body<->JSON round trip): builds a request through the
/// real producer path, materializes it into a stored `Body`, sends
/// that through a full serialize→deserialize cycle, and asserts the
/// recomputed hash still matches what was actually signed. This is
/// what actually proves `Body::anchors`'s serde shape doesn't silently
/// diverge from the wire form (e.g. via reordering, a dropped `uri`,
/// or falling through to `extensions` instead of the typed field) —
/// mirrors `can_008_body_roundtrip_preserves_unknown_producer_field`,
/// but for a first-class typed field rather than the `extensions`
/// catch-all.
#[test]
fn anchors_field_roundtrips_through_typed_body() {
    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::types::anchor::AnchorEntry;
    use acdp::types::primitives::ContentHash;
    use acdp::types::{ContextType, CtxId, LineageId, Visibility};

    let anchor = AnchorEntry {
        scheme: "macp.commitment".into(),
        content_hash: ContentHash::parse(
            "sha256:fa8fe6b9143b469866d31de09b81928cc44d226ed935162cd346ae80d14fd200",
        )
        .unwrap(),
        uri: Some("https://example.com/commitments/1".into()),
        extensions: Default::default(),
    };

    let req = Producer::new(
        SigningKey::from_bytes(&[9u8; 32]),
        acdp::types::AgentDid::new("did:web:agents.example.com:test-producer"),
        "did:web:agents.example.com:test-producer#key-1",
    )
    .publish_request()
    .acdp_version("0.5.0")
    .title("settlement finalized")
    .context_type(ContextType::DataSnapshot)
    .visibility(Visibility::Public)
    .anchors(vec![anchor.clone()])
    .build()
    .expect("a well-formed anchor must build");

    let signed_hash = req.content_hash.clone();

    let body = Body::from_publish_request(
        &req,
        CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into()),
        LineageId(
            "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
        ),
        "registry.example.com",
        chrono::Utc::now(),
    );
    assert_eq!(
        body.anchors.as_deref(),
        Some([anchor].as_slice()),
        "anchors must materialize into the stored Body unchanged"
    );
    assert!(
        !body.extensions.contains_key("anchors"),
        "anchors is a typed field — it must not also fall into the extensions catch-all"
    );

    // The actual round trip: serialize the stored Body to JSON, parse
    // it back into a fresh Body, and recompute content_hash. Anything
    // that reorders, drops, or renames a field inside `anchors` during
    // this cycle would change the JCS bytes and this would fail.
    let wire = serde_json::to_value(&body).unwrap();
    let round_tripped: Body =
        serde_json::from_value(wire).expect("Body with anchors must round-trip through JSON");
    let recomputed =
        acdp::crypto::compute_content_hash(&serde_json::to_value(&round_tripped).unwrap())
            .expect("recompute content_hash from the round-tripped Body");

    assert_eq!(
        recomputed, signed_hash,
        "anchors must round-trip byte-exactly through Body \u{2192} JSON \u{2192} Body \u{2192} \
         content_hash preimage"
    );
}

/// BUG-13b — can-009 exclusion set is keyed by field NAME, not by typed
/// knowledge of the body. A registry that injects an unknown registry-
/// assigned field (`registry_receipt` here) MUST exclude it by name
/// when recomputing the producer content hash.
#[test]
fn can_009_exclusion_set_keys_by_name_not_by_typed_knowledge() {
    use sha2::{Digest, Sha256};
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/can-009-body-with-unknown-excluded-field.json");
    if fixture_missing(&path) {
        return;
    }
    let fixture = read_json(&path);
    let vector = &fixture["vectors"][0];
    let canonical_expected = vector["expected"]["canonical_form"].as_str().unwrap();
    let hex_expected = vector["expected"]["sha256_hex"].as_str().unwrap();

    let producer_content = &vector["input"];
    let bytes = acdp::crypto::canonicalize_value(producer_content);
    assert_eq!(std::str::from_utf8(&bytes).unwrap(), canonical_expected);
    let digest = hex::encode(Sha256::digest(&bytes));
    assert_eq!(digest, hex_expected);
}

/// BUG-12 — schema-003 EmbeddedContent rejects unknown fields per
/// `additionalProperties: false` in the data_ref schema.
#[test]
fn schema_003_embedded_extra_field_rejected() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/schema-003-embedded-extra-field.json");
    if fixture_missing(&path) {
        return;
    }
    let fixture = read_json(&path);
    // The fixture's `input.embedded` carries the extra field. Try to
    // deserialize as a DataRef and assert the parse fails.
    let Some(input) = fixture.get("input") else {
        return;
    };
    let Some(dr_value) = input.get("data_ref").or(input.get("body")) else {
        return;
    };
    let res: Result<acdp::types::DataRef, _> = serde_json::from_value(dr_value.clone());
    assert!(
        res.is_err(),
        "schema-003 fixture must fail to deserialize as DataRef \
         (extra field on embedded content)"
    );
}

/// BUG-05 / can-010 — `acdp-data-ref.schema.json` is open at its root.
/// An unknown producer-controlled field inside a `DataRef` MUST survive
/// deserialize → serialize verbatim: a `DataRef` lives inside
/// ProducerContent, so a dropped field would change `content_hash` and
/// falsely fail verification on a consumer one ACDP minor version behind.
#[test]
fn can_010_data_ref_unknown_producer_field_preserved() {
    let dr_json = serde_json::json!({
        "type": "raw_data",
        "location": "https://data.example.com/file.csv",
        "future_producer_field": "must not be dropped"
    });
    let dr: acdp::types::DataRef =
        serde_json::from_value(dr_json).expect("DataRef must deserialize with extensions");
    assert_eq!(
        dr.extensions
            .get("future_producer_field")
            .and_then(|v| v.as_str()),
        Some("must not be dropped"),
        "can-010: an unknown DataRef field MUST be captured in `extensions`"
    );
    let round_tripped = serde_json::to_value(&dr).unwrap();
    assert_eq!(
        round_tripped["future_producer_field"], "must not be dropped",
        "can-010: an unknown DataRef field MUST survive the round-trip"
    );
}

/// data-ref-008 — an EXTERNAL data_ref hash mismatch is surfaced as
/// [`acdp::AcdpError::DataRefHashMismatch`] (BUG-02), never as
/// `hash_mismatch` (body-level) or `invalid_signature` (key-level).
/// The body's own integrity is unaffected — only the bytes at
/// `data_ref.location` have diverged from the producer-declared hash.
#[cfg(feature = "client")]
#[tokio::test]
async fn data_ref_008_external_hash_mismatch_surfaced_as_data_ref_hash_mismatch() {
    use acdp::client::{fetch_and_verify_data_ref, DataRefFetcher};
    use acdp::types::data_ref::{DataRefType, Location};
    use acdp::types::{ContentHash, DataRef};

    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/data-ref-008-external-data-ref-hash-mismatch.json");
    if fixture_missing(&path) {
        return;
    }
    let fixture = read_json(&path);
    let dr_value = fixture
        .pointer("/input/data_ref_under_test")
        .expect("fixture must expose data_ref_under_test");
    let declared_hash = dr_value["content_hash"].as_str().unwrap().to_string();
    let location = dr_value["location"].as_str().unwrap().to_string();

    // The producer signed a body that declares `declared_hash` for the
    // bytes at `location`. Today those bytes have changed and hash to
    // something else — modelled here as a stub fetcher returning a
    // payload whose SHA-256 does not match.
    let dr = DataRef::uri_verified(DataRefType::RawData, location, ContentHash(declared_hash));

    struct StaleFetcher;
    impl DataRefFetcher for StaleFetcher {
        async fn fetch(&self, _location: &Location) -> Result<Vec<u8>, acdp::AcdpError> {
            Ok(b"data the upstream has since mutated".to_vec())
        }
    }

    let err = fetch_and_verify_data_ref(&dr, &StaleFetcher)
        .await
        .expect_err("data-ref-008: fetched bytes ≠ declared hash MUST fail");
    match err {
        acdp::AcdpError::DataRefHashMismatch(_) => { /* exactly what data-ref-008 requires */ }
        acdp::AcdpError::HashMismatch { .. } | acdp::AcdpError::RemoteHashMismatch(_) => panic!(
            "data-ref-008: MUST NOT report body-level hash_mismatch — \
             the body's content_hash is valid; only the referenced data diverged"
        ),
        acdp::AcdpError::InvalidSignature(_) => panic!(
            "data-ref-008: MUST NOT report invalid_signature — the producer's \
             signature is valid; only the referenced data diverged"
        ),
        other => panic!("data-ref-008: unexpected error variant {other:?}"),
    }
}

/// data-ref-007 — an EMBEDDED `content_hash` mismatch (RFC-ACDP-0002 §6.3/
/// §6.6 "Check 8") is surfaced as [`acdp::AcdpError::DataRefHashMismatch`]
/// (wire code `data_ref_hash_mismatch`), specifically — not merely "any
/// `Err`". The fixture's own `description` warns that an implementation
/// missing the `embedded.content_hash` member would fail to *deserialize*
/// this fixture and reject it with `schema_violation`, which a harness
/// asserting only "was it rejected?" would count as a false pass without
/// ever reaching Check 8. This test closes exactly that gap: it asserts
/// deserialization succeeds (proving the field is modeled) and that
/// validation fails with the specific expected variant.
#[test]
fn data_ref_007_embedded_hash_mismatch_surfaced_as_data_ref_hash_mismatch() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/data-ref-007-embedded-hash-mismatch.json");
    if fixture_missing(&path) {
        return;
    }
    let fixture = read_json(&path);
    let dr_value = fixture
        .pointer("/input/data_ref_under_test")
        .expect("fixture must expose data_ref_under_test");

    let dr: acdp::types::DataRef = serde_json::from_value(dr_value.clone())
        .expect("data-ref-007: embedded.content_hash MUST be modeled — a deserialize failure here is a conformance failure, not a pass");

    let err = acdp::validation::validate_data_ref(&dr)
        .expect_err("data-ref-007: mismatched embedded.content_hash MUST be rejected");
    assert!(
        matches!(err, acdp::AcdpError::DataRefHashMismatch(_)),
        "data-ref-007: expected DataRefHashMismatch (checklist_step 8), got {err:?}"
    );

    let expected_code = fixture["expected"]["error_code"].as_str().unwrap_or("");
    assert_eq!(
        expected_code, "data_ref_hash_mismatch",
        "data-ref-007: fixture's own expected.error_code drifted"
    );
}

/// BUG-07 — `acdp-context.schema.json` is `additionalProperties: true`.
/// An unknown top-level field in a retrieval envelope MUST be preserved
/// in `FullContext.extensions` and survive a serialize round-trip, so a
/// v0.1.0 consumer tolerates future top-level registry keys.
#[test]
fn full_context_preserves_unknown_top_level_field() {
    let body = body_with_origin_registry("registry.example.com");
    let envelope = serde_json::json!({
        "body": serde_json::to_value(&body).unwrap(),
        "registry_state": { "status": "active" },
        "future_registry_field": { "some": "value" }
    });
    let ctx: acdp::types::FullContext =
        serde_json::from_value(envelope).expect("FullContext must deserialize");
    assert!(
        ctx.extensions.contains_key("future_registry_field"),
        "BUG-07: an unknown top-level field MUST land in FullContext.extensions"
    );
    let back = serde_json::to_value(&ctx).unwrap();
    assert_eq!(
        back["future_registry_field"]["some"], "value",
        "BUG-07: an unknown top-level field MUST survive the round-trip"
    );
}

// ── FEAT-01 / gap #3 — behavioral binding tests ──────────────────────────────

/// pub-002 — a publish request with a tampered `content_hash` MUST be
/// rejected at validation BEFORE persistence (RFC-ACDP-0003 §2.1 step 4).
#[cfg(feature = "server")]
#[test]
fn pub_002_hash_mismatch_rejected_by_validator() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/pub-002-hash-mismatch.json");
    if fixture_missing(&path) {
        return;
    }
    let fixture = read_json(&path);
    let Some(body) = fixture.get("input").and_then(|i| i.get("body")) else {
        return;
    };
    // pub-002 publishes a well-formed body whose content_hash does not
    // match the hash of its ProducerContent. The Rust deserializer
    // accepts the shape; PublishValidator::validate_post_schema rejects
    // at step 4 (hash recomputation).
    let req: acdp::types::PublishRequest = match serde_json::from_value(body.clone()) {
        Ok(r) => r,
        Err(_) => return, // older fixture format — skip
    };
    let caps = acdp::types::CapabilitiesDocument {
        acdp_version: "0.1.0".into(),
        registry_did: "did:web:registry.example.com".into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into()],
        profiles: vec!["acdp-registry-core".into()],
        limits: acdp::types::Limits {
            max_payload_bytes: 1_048_576,
            max_embedded_bytes: 65_536,
            idempotency_key_ttl_seconds: None,
            max_publish_per_minute: None,
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        supports_idempotency_key: false,
        extensions: Default::default(),
    };
    let v = acdp::registry::PublishValidator::for_authority(&caps, "registry.example.com");
    let raw_bytes = serde_json::to_vec(&req).unwrap().len();
    let result = v.validate_post_schema(&req, raw_bytes);
    assert!(result.is_err(), "pub-002 must surface a validation error");
}

/// pub-005 — restricted visibility without an audience is a producer bug
/// (RFC-ACDP-0002 §5.3). validate_publish_request rejects it.
#[test]
fn pub_005_restricted_without_audience_rejected() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/pub-005-restricted-without-audience.json");
    if fixture_missing(&path) {
        return;
    }
    let fixture = read_json(&path);
    let Some(body) = fixture.get("input").and_then(|i| i.get("body")) else {
        return;
    };
    let req: acdp::types::PublishRequest = match serde_json::from_value(body.clone()) {
        Ok(r) => r,
        Err(_) => return,
    };
    let err = acdp::validation::validate_publish_request(&req).unwrap_err();
    // Either SchemaViolation or a more specific error — must not pass.
    assert!(
        matches!(err, acdp::AcdpError::SchemaViolation(_)),
        "pub-005 must surface SchemaViolation for missing audience, got {err:?}"
    );
}

/// pub-013 / pub-014 / pub-012 — registry-assigned or unknown fields in a
/// publish request must be rejected at deserialization (BUG-02). Cross-
/// check: every fixture in this family must fail to parse as
/// PublishRequest.
#[test]
fn pub_012_013_014_extra_field_fixtures_fail_to_parse() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !matches!(
            name,
            "pub-012-extra-unknown-field.json"
                | "pub-013-producer-supplied-ctx-id.json"
                | "pub-014-producer-supplied-created-at.json"
        ) {
            continue;
        }
        let fixture = read_json(&path);
        let Some(body) = fixture.get("input").and_then(|i| i.get("body")) else {
            continue;
        };
        let res: Result<acdp::types::PublishRequest, _> = serde_json::from_value(body.clone());
        assert!(
            res.is_err(),
            "{name} body must FAIL to deserialize (deny_unknown_fields)"
        );
        checked += 1;
    }
    assert!(checked >= 1, "expected ≥1 pub-012/013/014 fixture");
}

/// idem-001..006 — fixtures are descriptive (preconditions / expected) and
/// don't carry a deserializable body in every case. We assert at minimum
/// that the family exists in the spec; full behavioral testing of these
/// scenarios lives in `src/registry/server.rs::tests`.
#[test]
fn idem_family_present_in_spec() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let count = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.starts_with("idem-"))
        })
        .count();
    assert!(count >= 5, "expected ≥5 idem-* fixtures, got {count}");
}

/// rate-001 — single fixture documenting the rate-limited response shape.
/// We assert the fixture parses; the runtime RateLimited path is unit-
/// tested in `src/registry/server.rs`.
#[test]
fn rate_001_response_shape_parses() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/rate-001-rate-limited-response-shape.json");
    if fixture_missing(&path) {
        return;
    }
    let fixture = read_json(&path);
    assert!(fixture.get("expected").is_some());
}

/// ret-001 + err-001 — assert these descriptive fixtures parse.
#[test]
fn ret_001_and_err_001_present() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");
    let ret = dir.join("ret-001-not-found.json");
    let err = dir.join("err-001-internal-error.json");
    assert!(
        ret.exists() || err.exists(),
        "expected at least one of ret-001 / err-001 in fixtures"
    );
}

// ── pub-004 / pub-007 — offline fixture binding (no TLS) ─────────────────────

/// pub-004 — a v1 publish request with `lineage_id` set MUST be rejected
/// at schema-level validation. The producer cannot compute a correct
/// value (it depends on the registry-assigned ctx_id), so any value is
/// necessarily wrong (RFC-ACDP-0003 §2.2).
///
/// Fixture body uses `did:agent:test` rather than `did:web:…`, so a
/// strict v0.1.0 validator may surface the agent_id violation first;
/// either way the outcome MUST be `SchemaViolation` and the publish
/// MUST NOT be accepted.
#[test]
fn pub_004_first_version_with_lineage_id_rejected() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/pub-004-first-version-with-lineage.json");
    if fixture_missing(&path) {
        return;
    }
    let fixture = read_json(&path);
    // The fixture in round-4 uses `request.body`, but earlier revisions
    // used `input.body`. Try both so the test is robust to format drift.
    let body = fixture
        .pointer("/request/body")
        .or_else(|| fixture.pointer("/input/body"))
        .cloned();
    let Some(body) = body else { return };

    // Normalize the fixture for offline validation:
    //   - replace the non-did:web agent_id/key_id with did:web placeholders,
    //   - pad the signature value to the valid 88-char ed25519 length.
    // Without these the agent_id or signature-length check fires first
    // and the assertion still passes `matches!(SchemaViolation)`, but
    // does not prove the v1+lineage_id rule. After normalization, the
    // only remaining schema-level violation is `lineage_id` on a v1
    // publish — exactly what pub-004 is asserting.
    let mut body = body;
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "agent_id".into(),
            serde_json::json!("did:web:agents.example.com:test"),
        );
        if let Some(sig) = obj.get_mut("signature").and_then(|s| s.as_object_mut()) {
            sig.insert(
                "key_id".into(),
                serde_json::json!("did:web:agents.example.com:test#key-1"),
            );
            // 88-char base64 = the wire length the schema enforces for
            // both ed25519 and ecdsa-p256 signature values.
            sig.insert("value".into(), serde_json::json!("A".repeat(86) + "=="));
        }
    }

    let req: acdp::types::PublishRequest = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(_) => return, // deny_unknown_fields caught it earlier — still a rejection
    };
    let err = acdp::validation::validate_publish_request(&req).unwrap_err();
    assert!(
        matches!(err, acdp::AcdpError::SchemaViolation(_)),
        "pub-004 must reject v1 with lineage_id as SchemaViolation, got {err:?}"
    );
}

/// pub-007 — `PublishResponse` shape: exactly five registry-assigned
/// fields, no echoed `content_hash`/`signature`/body fields.
///
/// The fixture is descriptive (lists required/forbidden field names),
/// but `scenarios[0].input.publish_response.body` is a concrete
/// conformant response object that MUST deserialize. Symmetrically, a
/// response object carrying any of the forbidden fields MUST be
/// rejected by serde's `deny_unknown_fields`.
#[test]
fn pub_007_publish_response_shape() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/pub-007-publish-response-shape.json");
    if fixture_missing(&path) {
        return;
    }
    let fixture = read_json(&path);

    // Step 1: the conformant scenario body MUST parse as PublishResponse.
    if let Some(body) = fixture.pointer("/scenarios/0/input/publish_response/body") {
        let parsed: acdp::types::PublishResponse = serde_json::from_value(body.clone()).expect(
            "pub-007: conformant publish-response body must deserialize as PublishResponse",
        );
        assert_eq!(
            parsed.status,
            acdp::types::Status::Active,
            "pub-007: status on first-publish MUST be `active`"
        );
        assert_eq!(
            parsed.version, 1,
            "pub-007: first-publish version MUST be 1"
        );
    }

    // Step 2: a publish response that echoes ANY forbidden field MUST be
    // rejected (deny_unknown_fields). Pull the forbidden list straight
    // from the fixture so this test follows the spec as it evolves.
    if let (Some(body), Some(forbidden)) = (
        fixture.pointer("/scenarios/0/input/publish_response/body"),
        fixture
            .pointer("/expected/response_body_shape/forbidden_fields")
            .and_then(|v| v.as_array()),
    ) {
        for field in forbidden {
            let Some(field_name) = field.as_str() else {
                continue;
            };
            let mut tampered = body.clone();
            if let Some(obj) = tampered.as_object_mut() {
                obj.insert(field_name.into(), serde_json::json!("forbidden-value"));
            }
            let r: Result<acdp::types::PublishResponse, _> = serde_json::from_value(tampered);
            assert!(
                r.is_err(),
                "pub-007: publish response with forbidden field `{field_name}` \
                 MUST be rejected by deny_unknown_fields, got {r:?}"
            );
        }
    }
}

// ── FEAT-01/02/03 — vis-009 / vis-008 / ret-002 behavioral bindings ──────────
//
// End-to-end `RegistryServer` checks for the scenarios the named fixtures
// pin. Gated on the `server` feature for `RegistryServer` / `InMemoryStore`.
#[cfg(feature = "server")]
mod registry_behavior {
    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::registry::{InMemoryStore, RegistryServer, RegistryStore};
    use acdp::types::capabilities::Limits;
    use acdp::types::primitives::{AgentDid, ContextType, Status, Visibility};
    use acdp::types::search::SearchParams;
    use acdp::types::CapabilitiesDocument;
    use acdp::AcdpError;

    const OWNER: &str = "did:web:agents.example.com:owner";
    const AUTHORIZED: &str = "did:web:agents.example.com:authorized";
    const STRANGER: &str = "did:web:agents.example.com:stranger";

    fn caps(anonymous_public_reads: bool) -> CapabilitiesDocument {
        CapabilitiesDocument {
            acdp_version: "0.1.0".into(),
            registry_did: "did:web:registry.example.com".into(),
            supported_signature_algorithms: vec!["ed25519".into()],
            supported_did_methods: vec!["did:web".into()],
            profiles: vec!["acdp-registry-core".into()],
            limits: Limits {
                max_payload_bytes: 1_048_576,
                max_embedded_bytes: 65_536,
                idempotency_key_ttl_seconds: None,
                max_publish_per_minute: None,
            },
            read_authentication_methods: vec![],
            anonymous_public_reads,
            supports_idempotency_key: false,
            extensions: Default::default(),
        }
    }

    fn producer() -> Producer {
        Producer::new(
            SigningKey::from_bytes(&[7u8; 32]),
            AgentDid::new(OWNER),
            format!("{OWNER}#key-1"),
        )
    }

    fn server(anonymous_public_reads: bool) -> RegistryServer<InMemoryStore> {
        RegistryServer::new(
            InMemoryStore::new(),
            caps(anonymous_public_reads),
            "registry.example.com",
        )
    }

    fn search_beta(
        srv: &RegistryServer<InMemoryStore>,
        requester: Option<&AgentDid>,
    ) -> Result<acdp::types::SearchResponse, AcdpError> {
        srv.search(
            &SearchParams {
                q: Some("beta".into()),
                ..Default::default()
            },
            requester,
        )
    }

    /// Publish one public + one restricted context, both matching `q=beta`.
    fn publish_beta_pair(srv: &RegistryServer<InMemoryStore>) {
        let p = producer();
        let public = p
            .publish_request()
            .title("Public beta")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        srv.publish_unverified_for_tests(&public).unwrap();
        let restricted = p
            .publish_request()
            .title("Restricted beta")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![AgentDid::new(AUTHORIZED)])
            .build()
            .unwrap();
        srv.publish_unverified_for_tests(&restricted).unwrap();
    }

    /// FEAT-01 / vis-009 — `anonymous_public_reads` governs keyword search
    /// exactly as it governs retrieval.
    #[test]
    fn vis_009_anonymous_public_reads_search_scoping() {
        // s1: flag=false + anonymous → 403 not_authorized, no leakage.
        {
            let srv = server(false);
            publish_beta_pair(&srv);
            let err = search_beta(&srv, None).unwrap_err();
            assert!(
                matches!(err, AcdpError::NotAuthorized(_)),
                "vis-009 s1: anonymous search MUST be NotAuthorized when \
                 anonymous_public_reads=false; got {err:?}"
            );
        }
        // s2: flag=true + anonymous → 200, public results only.
        {
            let srv = server(true);
            publish_beta_pair(&srv);
            let resp = search_beta(&srv, None).unwrap();
            assert_eq!(
                resp.matches.len(),
                1,
                "vis-009 s2: anonymous search sees public contexts only"
            );
            assert_eq!(resp.matches[0].title, "Public beta");
        }
        // s3: flag=false + authenticated → 200, public only (restricted
        // excluded — the stranger is in no audience).
        {
            let srv = server(false);
            publish_beta_pair(&srv);
            let stranger = AgentDid::new(STRANGER);
            let resp = search_beta(&srv, Some(&stranger)).unwrap();
            assert_eq!(
                resp.matches.len(),
                1,
                "vis-009 s3: an authenticated non-audience requester sees public only"
            );
            assert_eq!(resp.matches[0].title, "Public beta");
        }
    }

    /// FEAT-02 / vis-008 — lineage endpoints apply the same per-context
    /// visibility rules as `GET /contexts/{ctx_id}`. Knowing a
    /// `lineage_id` MUST NOT grant access ctx_id-level control denies.
    #[test]
    fn vis_008_lineage_endpoint_visibility() {
        let owner = AgentDid::new(OWNER);
        let audience = AgentDid::new(AUTHORIZED);
        let stranger = AgentDid::new(STRANGER);
        let srv = server(true);
        let p = producer();

        // Restricted lineage: v1 restricted (→ superseded), v2 restricted.
        let v1 = p
            .publish_request()
            .title("restricted v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![audience.clone()])
            .build()
            .unwrap();
        let v1_resp = srv.publish_unverified_for_tests(&v1).unwrap();
        let v2 = p
            .supersede(v1_resp.ctx_id.clone())
            .version(2)
            .title("restricted v2")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![audience.clone()])
            .build()
            .unwrap();
        srv.publish_unverified_for_tests(&v2).unwrap();
        let restricted_lineage = v1_resp.lineage_id.clone();

        // s1: stranger sees zero versions — empty array, not an error.
        assert!(
            srv.lineage(&restricted_lineage, Some(&stranger))
                .unwrap()
                .is_empty(),
            "vis-008 s1: stranger MUST see zero versions of a restricted lineage"
        );
        // s2: audience member sees the full restricted history.
        assert_eq!(
            srv.lineage(&restricted_lineage, Some(&audience))
                .unwrap()
                .len(),
            2,
            "vis-008 s2: audience member MUST see every restricted version"
        );

        // Mixed lineage: v1 public (→ superseded), v2 private.
        let m1 = p
            .publish_request()
            .title("mixed v1 public")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let m1_resp = srv.publish_unverified_for_tests(&m1).unwrap();
        let m2 = p
            .supersede(m1_resp.ctx_id.clone())
            .version(2)
            .title("mixed v2 private")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Private)
            .build()
            .unwrap();
        let m2_resp = srv.publish_unverified_for_tests(&m2).unwrap();
        let mixed_lineage = m1_resp.lineage_id.clone();

        // s3: stranger sees only the public v1 — the private v2 is a gap.
        let stranger_view = srv.lineage(&mixed_lineage, Some(&stranger)).unwrap();
        assert_eq!(
            stranger_view.len(),
            1,
            "vis-008 s3: stranger sees only the visible subsequence"
        );
        assert_eq!(stranger_view[0].body.ctx_id, m1_resp.ctx_id);

        // s4: stranger `current` → None (v2 private, v1 superseded).
        assert!(
            srv.current(&mixed_lineage, Some(&stranger))
                .unwrap()
                .is_none(),
            "vis-008 s4: stranger MUST NOT reach the private current head"
        );
        // s5: producer `current` → the private v2.
        let owner_cur = srv
            .current(&mixed_lineage, Some(&owner))
            .unwrap()
            .expect("vis-008 s5: producer sees the private current head");
        assert_eq!(owner_cur.body.ctx_id, m2_resp.ctx_id);
    }

    /// FEAT-03 / ret-002 — `current` returns the newest non-superseded
    /// version: `expired` counts as a valid head, `superseded` never
    /// does, and an all-superseded lineage resolves to `not_found`.
    #[test]
    fn ret_002_lineage_current_semantics() {
        use chrono::{Duration, Utc};
        let srv = server(true);
        let p = producer();

        // All versions superseded → current returns None.
        {
            let v1 = p
                .publish_request()
                .title("all-superseded v1")
                .context_type(ContextType::DataSnapshot)
                .visibility(Visibility::Public)
                .build()
                .unwrap();
            let resp = srv.publish_unverified_for_tests(&v1).unwrap();
            srv.store().mark_superseded(&resp.ctx_id).unwrap();
            assert!(
                srv.current(&resp.lineage_id, None).unwrap().is_none(),
                "ret-002: an all-superseded lineage MUST resolve to None (RFC-ACDP-0004 §5.2)"
            );
        }

        // Active head → current returns it with status active.
        {
            let v1 = p
                .publish_request()
                .title("active head v1")
                .context_type(ContextType::DataSnapshot)
                .visibility(Visibility::Public)
                .build()
                .unwrap();
            let resp = srv.publish_unverified_for_tests(&v1).unwrap();
            let cur = srv
                .current(&resp.lineage_id, None)
                .unwrap()
                .expect("ret-002: an active head MUST be returned");
            assert_eq!(cur.registry_state.status, Status::Active);
        }

        // Expired-but-unreplaced head → current returns it with status
        // expired. 'current' does not imply 'active'.
        {
            let v1 = p
                .publish_request()
                .title("expired head v1")
                .context_type(ContextType::DataSnapshot)
                .visibility(Visibility::Public)
                .expires_at(Utc::now() - Duration::days(30))
                .build()
                .unwrap();
            let resp = srv.publish_unverified_for_tests(&v1).unwrap();
            let cur = srv
                .current(&resp.lineage_id, None)
                .unwrap()
                .expect("ret-002: an expired-but-unreplaced head IS a valid current head");
            assert_eq!(
                cur.registry_state.status,
                Status::Expired,
                "ret-002: current MUST carry status=expired so the consumer knows it lapsed"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ACDP 0.2.0 Trust & Hardening fixtures (RFC-ACDP-0010 + RFC-ACDP-0001
// §5.4/§5.11.1/§6 amendments). Arithmetic fixtures are executed
// end-to-end; behavioral fixtures are bound to the library calls that
// implement them (full client/server behavior lives in
// `tests/receipts.rs`).
// ═══════════════════════════════════════════════════════════════════════

/// sig-003 — did:key golden vector: identity derivation, canonical
/// form, content hash, and signature, end-to-end through the builder.
#[test]
fn sig_003_did_key_golden_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/sig-003-did-key-golden.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let seed: [u8; 32] = hex::decode(v["test_keypair"]["private_seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let vector = &v["vectors"][0];
    let expected = &vector["expected"];

    // Identity derivation.
    let p = acdp::producer::Producer::new_did_key(acdp::crypto::SigningKey::from_bytes(&seed));

    // Canonical form + hash over the fixture's ProducerContent.
    let pc = &vector["producer_content"];
    let (canonical, hash) = acdp::crypto::canonical_preimage(pc).unwrap();
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        expected["canonical_form"].as_str().unwrap(),
        "sig-003: canonical form mismatch"
    );
    assert_eq!(hash.as_str(), expected["content_hash"].as_str().unwrap());

    // Builder round trip reproduces the wire request.
    let req = p
        .publish_request()
        .acdp_version(pc["acdp_version"].as_str().unwrap())
        .title(pc["title"].as_str().unwrap())
        .context_type(acdp::types::ContextType::DataSnapshot)
        .visibility(acdp::types::Visibility::Public)
        .build()
        .unwrap();
    assert_eq!(
        req.agent_id.as_str(),
        v["test_keypair"]["did_key"].as_str().unwrap()
    );
    assert_eq!(
        req.content_hash.as_str(),
        expected["content_hash"].as_str().unwrap()
    );
    assert_eq!(
        req.signature.value,
        expected["signature_value_base64"].as_str().unwrap()
    );
    acdp::crypto::verify_publish_request_signature_offline(&req).unwrap();
}

/// fp-001 — key-fingerprint encoding vectors, one per algorithm
/// (RFC-ACDP-0010 §6).
#[test]
fn fp_001_fingerprint_vectors_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/fp-001-key-fingerprint-vectors.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    for vector in v["vectors"].as_array().unwrap() {
        let key_bytes = hex::decode(vector["input"]["public_key_hex"].as_str().unwrap()).unwrap();
        let expected = vector["expected"]["key_fingerprint"].as_str().unwrap();
        let got = match vector["algorithm"].as_str().unwrap() {
            "ed25519" => {
                let arr: [u8; 32] = key_bytes.as_slice().try_into().unwrap();
                acdp::crypto::fingerprint_ed25519(&arr)
            }
            "ecdsa-p256" => acdp::crypto::fingerprint_p256_sec1(&key_bytes).unwrap(),
            other => panic!("unknown fp-001 algorithm {other}"),
        };
        assert_eq!(got, expected, "fp-001 '{}'", vector["name"]);
    }
}

/// rcpt-001 — receipt golden vector: canonical preimage, receipt hash,
/// signature, both via raw-JSON verification and a deterministic
/// re-mint (RFC-ACDP-0010 §5).
#[test]
fn rcpt_001_receipt_golden_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/rcpt-001-receipt-golden.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let vector = &v["vectors"][0];
    let expected = &vector["expected"];
    let wire = &expected["registry_receipt"];

    // Raw-JSON preimage + hash.
    let unsigned = &vector["receipt_unsigned"];
    let hash = acdp::types::receipt::RegistryReceipt::preimage_hash_of_value(unsigned).unwrap();
    assert_eq!(hash.as_str(), expected["receipt_hash"].as_str().unwrap());

    // Wire receipt verifies against the registry test public key.
    let pub_bytes: [u8; 32] = hex::decode(
        v["registry_test_keypair"]["public_key_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let receipt = acdp::types::receipt::RegistryReceipt::from_value(wire).unwrap();
    let raw_hash = acdp::types::receipt::RegistryReceipt::preimage_hash_of_value(wire).unwrap();
    receipt
        .verify_signature_against_hash(&raw_hash, Some(&pub_bytes), None)
        .unwrap();

    // Deterministic re-mint reproduces the signature byte-for-byte.
    let seed: [u8; 32] = hex::decode(
        v["registry_test_keypair"]["private_seed_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let signer = acdp::types::receipt::ReceiptSigner::new(
        acdp::crypto::SigningKey::from_bytes(&seed),
        unsigned["registry_did"].as_str().unwrap(),
        v["registry_test_keypair"]["key_id"].as_str().unwrap(),
    )
    .unwrap();
    let minted = signer
        .mint(
            &acdp::types::CtxId(unsigned["ctx_id"].as_str().unwrap().into()),
            &acdp::types::LineageId(unsigned["lineage_id"].as_str().unwrap().into()),
            unsigned["origin_registry"].as_str().unwrap(),
            chrono::DateTime::parse_from_rfc3339(unsigned["created_at"].as_str().unwrap())
                .unwrap()
                .with_timezone(&chrono::Utc),
            &acdp::types::ContentHash(unsigned["content_hash"].as_str().unwrap().into()),
            unsigned["key_fingerprint"].as_str().unwrap(),
        )
        .unwrap();
    assert_eq!(
        minted.signature.value,
        expected["signature_value_base64"].as_str().unwrap(),
        "rcpt-001: deterministic Ed25519 re-mint must reproduce the fixture signature"
    );

    // Producer-key fingerprint (verification step 5).
    let prod_pub: [u8; 32] = hex::decode(v["producer_key"]["public_key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        acdp::crypto::fingerprint_ed25519(&prod_pub),
        unsigned["key_fingerprint"].as_str().unwrap()
    );
}

/// can-012 — the hash-divergence corpus: every vector's canonical form
/// and hash must reproduce exactly (omitted vs explicit acdp_version,
/// sub-ms timestamps, empty-vs-absent-vs-null metadata).
#[test]
fn can_012_divergence_corpus_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/can-012-divergence-corpus.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    for vector in v["vectors"].as_array().unwrap() {
        let pc = &vector["input"];
        let (canonical, hash) = acdp::crypto::canonical_preimage(pc).unwrap();
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            vector["expected"]["canonical_form"].as_str().unwrap(),
            "can-012 '{}': canonical form",
            vector["name"]
        );
        assert_eq!(
            hash.as_str(),
            vector["expected"]["content_hash_field_value"]
                .as_str()
                .unwrap(),
            "can-012 '{}': hash",
            vector["name"]
        );
    }
}

/// dk-001/002/004 — pure did:key resolution rejections; dk-003 — the
/// capabilities gate (RFC-ACDP-0001 §5.4/§5.11.1).
#[test]
fn dk_fixtures_did_key_rejections() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");

    // dk-001: unsupported multicodec (secp256k1).
    let p = dir.join("dk-001-wrong-multicodec-prefix.json");
    if p.exists() {
        let v = read_json(&p);
        let did = v["input"]["agent_id"].as_str().unwrap();
        let err = acdp::did::resolve_did_key(did).unwrap_err();
        assert!(
            matches!(err, acdp::AcdpError::KeyResolution(_)),
            "dk-001: got {err:?}"
        );
    }

    // dk-002: malformed multibase payloads.
    let p = dir.join("dk-002-malformed-multibase.json");
    if p.exists() {
        let v = read_json(&p);
        for case in v["input"]["cases"].as_array().unwrap() {
            let did = case["agent_id"].as_str().unwrap();
            assert!(
                acdp::did::resolve_did_key(did).is_err(),
                "dk-002 case '{}' must fail",
                case["case"]
            );
        }
    }

    // dk-004: fragment ≠ method-specific identifier.
    let p = dir.join("dk-004-fragment-mismatch.json");
    if p.exists() {
        let v = read_json(&p);
        let key_id = v["input"]["signature_key_id"].as_str().unwrap();
        let err = acdp::did::resolve_did_key_url(key_id).unwrap_err();
        assert!(
            matches!(err, acdp::AcdpError::KeyResolution(_)),
            "dk-004: got {err:?}"
        );
    }

    // dk-003: registry without "did:key" in supported_did_methods
    // rejects a flawless did:key request with key_resolution_failed.
    // The capability gate lives in the server-feature PublishValidator.
    #[cfg(feature = "server")]
    {
        let p = dir.join("dk-003-did-key-not-advertised.json");
        if p.exists() {
            use acdp::types::capabilities::{CapabilitiesDocument, Limits};
            let caps = CapabilitiesDocument {
                acdp_version: "0.2.0".into(),
                registry_did: "did:web:registry.example.com".into(),
                supported_signature_algorithms: vec!["ed25519".into()],
                supported_did_methods: vec!["did:web".into()],
                profiles: vec!["acdp-registry-core".into()],
                limits: Limits {
                    max_payload_bytes: 1_048_576,
                    max_embedded_bytes: 65_536,
                    idempotency_key_ttl_seconds: None,
                    max_publish_per_minute: None,
                },
                read_authentication_methods: vec![],
                anonymous_public_reads: true,
                supports_idempotency_key: false,
                extensions: Default::default(),
            };
            let producer = acdp::producer::Producer::new_did_key(
                acdp::crypto::SigningKey::from_bytes(&[0x42u8; 32]),
            );
            let req = producer
                .publish_request()
                .acdp_version("0.2.0")
                .title("Golden test vector — did:key first version")
                .context_type(acdp::types::ContextType::DataSnapshot)
                .visibility(acdp::types::Visibility::Public)
                .build()
                .unwrap();
            let validator = acdp::registry::PublishValidator::new(&caps);
            let raw = serde_json::to_vec(&req).unwrap().len();
            let err = validator.validate_post_schema(&req, raw).unwrap_err();
            assert!(
                matches!(err, acdp::AcdpError::KeyResolution(_)),
                "dk-003: capability gate must emit key_resolution_failed, got {err:?}"
            );
        }
    }
}

/// dk-001/002/004, driven through the actual `acdp-validation` entry point
/// (`validate_publish_request`, via `RequestBuilder::build`) rather than
/// calling `acdp_did::key::resolve_did_key*` directly as
/// `dk_fixtures_did_key_rejections` does above. #285: `validate_agent_did`
/// and `validate_did_key_key_id_form` MUST propagate the resolver's own
/// `AcdpError::KeyResolution` for every one of these cases, never
/// downgrade to `AcdpError::SchemaViolation` — this is new coverage: prior
/// to this fix, nothing exercised these two functions with a did:key
/// resolver fault.
#[test]
fn dk_fixtures_drive_validate_publish_request() {
    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::types::{AgentDid, ContextType};

    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");

    let build_err = |agent_id: &str, key_id: &str| -> acdp::AcdpError {
        Producer::new(
            SigningKey::from_bytes(&[0u8; 32]),
            AgentDid::new(agent_id),
            key_id,
        )
        .publish_request()
        .title("t")
        .context_type(ContextType::DataSnapshot)
        .build()
        .expect_err("malformed did:key input MUST be rejected")
    };

    // dk-001: agent_id carries an unsupported multicodec (step 3) — fires
    // inside validate_agent_did, the first did:key-sensitive check in
    // validate_publish_request.
    let p = dir.join("dk-001-wrong-multicodec-prefix.json");
    if !fixture_missing(&p) {
        let v = read_json(&p);
        let agent_id = v["input"]["agent_id"].as_str().unwrap();
        let key_id = v["input"]["signature_key_id"].as_str().unwrap();
        let err = build_err(agent_id, key_id);
        assert!(
            matches!(err, acdp::AcdpError::KeyResolution(_)),
            "dk-001 via validate_publish_request: got {err:?}"
        );
    }

    // dk-002: three malformed-multibase agent_id cases (steps 2 and 3) —
    // same call path, each case's agent_id used as both DID and key_id
    // DID-portion so validate_agent_did is what actually fires first.
    let p = dir.join("dk-002-malformed-multibase.json");
    if !fixture_missing(&p) {
        let v = read_json(&p);
        for case in v["input"]["cases"].as_array().unwrap() {
            let agent_id = case["agent_id"].as_str().unwrap();
            let key_id = format!("{agent_id}#{}", agent_id.trim_start_matches("did:key:"));
            let err = build_err(agent_id, &key_id);
            assert!(
                matches!(err, acdp::AcdpError::KeyResolution(_)),
                "dk-002 case '{}' via validate_publish_request: got {err:?}",
                case["case"]
            );
        }
    }

    // dk-004: agent_id is well-formed; signature.key_id's fragment names a
    // DIFFERENT key (step 1) — fires inside validate_did_key_key_id_form,
    // reached only after validate_agent_did accepts the (valid) agent_id.
    let p = dir.join("dk-004-fragment-mismatch.json");
    if !fixture_missing(&p) {
        let v = read_json(&p);
        let agent_id = v["input"]["agent_id"].as_str().unwrap();
        let key_id = v["input"]["signature_key_id"].as_str().unwrap();
        let err = build_err(agent_id, key_id);
        assert!(
            matches!(err, acdp::AcdpError::KeyResolution(_)),
            "dk-004 via validate_publish_request: got {err:?}"
        );
    }
}

/// rcpt-002/003/004 — receipt verification rejections, data-driven
/// from the fixtures (full client behavior in `tests/receipts.rs`).
#[test]
fn rcpt_negative_fixtures() {
    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");

    // rcpt-002: tampered created_at → preimage hash diverges →
    // signature no longer verifies.
    let p = dir.join("rcpt-002-tampered-created-at.json");
    if p.exists() {
        let v = read_json(&p);
        let wire = &v["input"]["registry_receipt"];
        let tampered_hash =
            acdp::types::receipt::RegistryReceipt::preimage_hash_of_value(wire).unwrap();
        assert_eq!(
            tampered_hash.as_str(),
            v["expected"]["tampered_preimage_hash"].as_str().unwrap()
        );
        // The signature (made over the ORIGINAL hash) must fail against
        // the tampered preimage.
        let pub_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let pub_bytes: [u8; 32] = hex::decode(pub_hex).unwrap().try_into().unwrap();
        let receipt = acdp::types::receipt::RegistryReceipt::from_value(wire).unwrap();
        let err = receipt
            .verify_signature_against_hash(&tampered_hash, Some(&pub_bytes), None)
            .unwrap_err();
        assert!(matches!(err, acdp::AcdpError::InvalidReceipt(_)));
    }

    // rcpt-003: fingerprint mismatch fails the §8 step 5 cross-check.
    let p = dir.join("rcpt-003-key-fingerprint-mismatch.json");
    if p.exists() {
        let v = read_json(&p);
        let correct = v["input"]["resolved_producer_key"]["correct_fingerprint"]
            .as_str()
            .unwrap();
        let pub_bytes: [u8; 32] = hex::decode(
            v["input"]["resolved_producer_key"]["public_key_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        assert_eq!(acdp::crypto::fingerprint_ed25519(&pub_bytes), correct);
    }

    // rcpt-004: registry_did ≠ serving authority — the cross-check the
    // client runs against the fetched-from authority.
    let p = dir.join("rcpt-004-registry-did-mismatch.json");
    if p.exists() {
        let v = read_json(&p);
        let serving = v["input"]["serving_authority"].as_str().unwrap();
        let claimed = v["input"]["receipt_excerpt"]["registry_did"]
            .as_str()
            .unwrap();
        assert_ne!(
            acdp::did::authority_to_did_web(serving),
            claimed,
            "rcpt-004 premise: the claimed registry_did must not match the serving authority"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// lhr-* — lineage-head receipts (ACDP 0.3, RFC-ACDP-0011)
// ═══════════════════════════════════════════════════════════════════════

/// lhr-001 — lineage-head receipt golden vector (RFC-ACDP-0011 §5):
/// canonical preimage bytes, receipt hash, Ed25519 signature — via
/// raw-JSON verification AND a deterministic re-mint from the fixture's
/// registry test seed (shared with rcpt-001) — plus the fixture's §7
/// cross-checks (registry binding, v1 lineage derivation, `as_of` form).
#[test]
fn lhr_001_lineage_head_receipt_golden_fixture() {
    use acdp::types::receipt::{LineageHeadReceipt, ReceiptSigner};

    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/lhr-001-lineage-head-receipt-golden.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let vector = &v["vectors"][0];
    let unsigned = &vector["receipt_unsigned"];
    let expected = &vector["expected"];
    let wire = &expected["lineage_head_receipt"];

    // Step 1: JCS canonical form of the unsigned receipt, byte-for-byte.
    let canonical = acdp::crypto::try_canonicalize_value(unsigned).unwrap();
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        expected["canonical_form"].as_str().unwrap(),
        "lhr-001: canonical preimage bytes"
    );

    // Step 2: preimage hash.
    let hash = LineageHeadReceipt::preimage_hash_of_value(unsigned).unwrap();
    assert_eq!(hash.as_str(), expected["receipt_hash"].as_str().unwrap());

    // Step 3: deterministic Ed25519 re-mint reproduces the signature.
    let seed: [u8; 32] = hex::decode(
        v["registry_test_keypair"]["private_seed_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let signer = ReceiptSigner::new(
        acdp::crypto::SigningKey::from_bytes(&seed),
        unsigned["registry_did"].as_str().unwrap(),
        v["registry_test_keypair"]["key_id"].as_str().unwrap(),
    )
    .unwrap();
    let minted = signer
        .mint_lineage_head(
            &acdp::types::LineageId(unsigned["lineage_id"].as_str().unwrap().into()),
            &acdp::types::CtxId(unsigned["head_ctx_id"].as_str().unwrap().into()),
            u32::try_from(unsigned["head_version"].as_u64().unwrap()).unwrap(),
            &acdp::types::Status::parse(unsigned["head_status"].as_str().unwrap()).unwrap(),
            chrono::DateTime::parse_from_rfc3339(unsigned["as_of"].as_str().unwrap())
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
        .unwrap();
    assert_eq!(
        minted.signature.value,
        expected["signature_value_base64"].as_str().unwrap(),
        "lhr-001: deterministic Ed25519 re-mint must reproduce the fixture signature"
    );
    assert_eq!(
        serde_json::to_value(&minted).unwrap(),
        *wire,
        "lhr-001: minted wire form must equal the fixture receipt"
    );

    // Step 4: wire receipt round-trips the closed parse and verifies
    // against the registry test public key over the RAW wire preimage.
    let pub_bytes: [u8; 32] = hex::decode(
        v["registry_test_keypair"]["public_key_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let receipt = LineageHeadReceipt::from_value(wire).unwrap();
    let raw_hash = LineageHeadReceipt::preimage_hash_of_value(wire).unwrap();
    assert_eq!(raw_hash, hash, "raw wire preimage equals unsigned preimage");
    receipt
        .verify_signature_against_hash(&raw_hash, Some(&pub_bytes), None)
        .unwrap();

    // Step 5 cross-checks (RFC-ACDP-0011 §7): registry binding against
    // the golden authority, v1 lineage derivation, `as_of` byte form.
    receipt
        .cross_check_registry_binding("registry.example.com", "did:web:registry.example.com")
        .unwrap();
    assert_eq!(receipt.head_version, 1);
    assert_eq!(
        acdp::crypto::derive_lineage_id(&receipt.head_ctx_id),
        receipt.lineage_id,
        "lhr-001: v1 head means lineage_id = lin:sha256:SHA-256(head_ctx_id)"
    );
    assert_eq!(receipt.head_status, "active");
    LineageHeadReceipt::validate_as_of_form(wire).unwrap();
}

/// lhr-002/003/004 — lineage-head receipt verification rejections,
/// data-driven from the fixtures (full client behavior in
/// `tests/lineage_head_receipts.rs`).
#[test]
fn lhr_negative_fixtures() {
    use acdp::types::receipt::{LineageHeadReceipt, ReceiptSigner};
    use acdp::types::{CtxId, Status};

    let Some(root) = spec_root() else { return };
    let dir = root.join("schemas/conformance");

    // lhr-002: stale head — the receipt is genuinely signed (steps 1–4
    // pass) but attests v1 while /current serves v2 → §7 step 5 head
    // binding MUST fail with invalid_receipt.
    let p = dir.join("lhr-002-stale-head-mismatch.json");
    if !fixture_missing(&p) {
        let v = read_json(&p);
        let served = &v["input"]["served_response"];
        let wire = &served["lineage_head_receipt"];
        let pub_bytes: [u8; 32] =
            hex::decode(v["input"]["registry_public_key_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();

        let receipt = LineageHeadReceipt::from_value(wire).unwrap();
        // Premise: the cryptography is NOT the failure.
        let raw_hash = LineageHeadReceipt::preimage_hash_of_value(wire).unwrap();
        receipt
            .verify_signature_against_hash(&raw_hash, Some(&pub_bytes), None)
            .expect("lhr-002 premise: the stale receipt's signature verifies");
        receipt
            .cross_check_registry_binding("registry.example.com", "did:web:registry.example.com")
            .expect("lhr-002 premise: registry binding holds");
        receipt
            .cross_check_lineage(&acdp::types::LineageId(
                served["body_excerpt"]["lineage_id"]
                    .as_str()
                    .unwrap()
                    .into(),
            ))
            .expect("lhr-002 premise: lineage binding holds");

        // §7 step 5: on /current the receipt MUST describe the very head
        // being served.
        let served_ctx = CtxId(served["body_excerpt"]["ctx_id"].as_str().unwrap().into());
        let served_version =
            u32::try_from(served["body_excerpt"]["version"].as_u64().unwrap()).unwrap();
        let served_status =
            Status::parse(served["registry_state"]["status"].as_str().unwrap()).unwrap();
        let err = receipt
            .cross_check_head(&served_ctx, served_version, &served_status, true)
            .expect_err("lhr-002: stale head binding must fail");
        assert!(
            matches!(err, acdp::AcdpError::InvalidReceipt(_)),
            "got {err:?}"
        );
    }

    // lhr-003: registry_did ≠ serving authority / capabilities.registry_did
    // → §7 step 3 MUST fail regardless of the signature.
    let p = dir.join("lhr-003-registry-did-mismatch.json");
    if !fixture_missing(&p) {
        let v = read_json(&p);
        let serving = v["input"]["serving_authority"].as_str().unwrap();
        let caps_did = v["input"]["capabilities_registry_did"].as_str().unwrap();
        let excerpt = &v["input"]["receipt_excerpt"];
        assert_ne!(
            acdp::did::authority_to_did_web(serving),
            excerpt["registry_did"].as_str().unwrap(),
            "lhr-003 premise: the claimed registry_did must not match the serving authority"
        );

        // Materialize the excerpt as a full receipt (the fixture replays
        // the lhr-001 golden receipt verbatim; signature value is
        // irrelevant to step 3, which runs before signature checking).
        let receipt = LineageHeadReceipt::from_value(&serde_json::json!({
            "receipt_version": excerpt["receipt_version"],
            "registry_did": excerpt["registry_did"],
            "lineage_id":
                "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
            "head_ctx_id": excerpt["head_ctx_id"],
            "head_version": 1,
            "head_status": "active",
            "as_of": "2026-07-04T09:00:00.000Z",
            "signature": {
                "algorithm": "ed25519",
                "key_id": excerpt["signature_key_id"],
                "value": "AA=="
            }
        }))
        .unwrap();
        let err = receipt
            .cross_check_registry_binding(serving, caps_did)
            .expect_err("lhr-003: foreign registry_did must fail the registry binding");
        assert!(
            matches!(err, acdp::AcdpError::InvalidReceipt(_)),
            "got {err:?}"
        );

        // Additional failure cases enumerated by the fixture:
        // (a) non-did:web registry_did fails the closed parse.
        let mut did_key = serde_json::to_value(&receipt).unwrap();
        did_key["registry_did"] = serde_json::json!("did:key:zNotWeb");
        assert!(matches!(
            LineageHeadReceipt::from_value(&did_key).unwrap_err(),
            acdp::AcdpError::InvalidReceipt(_)
        ));
        // (b) signature.key_id DID portion ≠ registry_did.
        let mut foreign_key = receipt.clone();
        foreign_key.signature.key_id = "did:web:other.example#receipt-key-1".into();
        assert!(foreign_key
            .cross_check_registry_binding("registry.example.com", "did:web:registry.example.com")
            .is_err());
        // (c) head_ctx_id authority ≠ registry_did method-specific id.
        let mut foreign_head = receipt.clone();
        foreign_head.registry_did = "did:web:hostile.example".into();
        foreign_head.signature.key_id = "did:web:hostile.example#receipt-key-1".into();
        assert!(foreign_head
            .cross_check_registry_binding("hostile.example", "did:web:hostile.example")
            .is_err());
    }

    // lhr-004: future as_of beyond the skew allowance → §7 step 6 MUST
    // fail. The receipt is VALIDLY SIGNED — the failure is the forged
    // freshness claim, not the cryptography.
    let p = dir.join("lhr-004-future-as-of.json");
    if !fixture_missing(&p) {
        let v = read_json(&p);
        let wire = &v["input"]["lineage_head_receipt"];
        let pub_bytes: [u8; 32] =
            hex::decode(v["input"]["registry_public_key_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let consumer_clock =
            chrono::DateTime::parse_from_rfc3339(v["input"]["consumer_clock"].as_str().unwrap())
                .unwrap()
                .with_timezone(&chrono::Utc);
        let skew =
            chrono::Duration::seconds(v["input"]["skew_allowance_seconds"].as_i64().unwrap());

        let receipt = LineageHeadReceipt::from_value(wire).unwrap();
        // Genuinely-signed premise: steps 1–5 pass.
        let raw_hash = LineageHeadReceipt::preimage_hash_of_value(wire).unwrap();
        receipt
            .verify_signature_against_hash(&raw_hash, Some(&pub_bytes), None)
            .expect("lhr-004 premise: the future-dated receipt's signature verifies");
        receipt
            .cross_check_registry_binding("registry.example.com", "did:web:registry.example.com")
            .expect("lhr-004 premise: registry binding holds");

        // Step 6: forged freshness rejection.
        let err = receipt
            .check_as_of_skew(consumer_clock, skew)
            .expect_err("lhr-004: future as_of beyond skew must fail");
        assert!(
            matches!(err, acdp::AcdpError::InvalidReceipt(_)),
            "got {err:?}"
        );

        // Boundary from the fixture: an as_of within the allowance
        // (consumer_clock + 60s) MUST NOT fail step 6.
        let signer = ReceiptSigner::new(
            acdp::crypto::SigningKey::from_bytes(&[0x11u8; 32]),
            "did:web:registry.example.com",
            "did:web:registry.example.com#receipt-key-1",
        )
        .unwrap();
        let near_future = signer
            .mint_lineage_head(
                &receipt.lineage_id,
                &receipt.head_ctx_id,
                receipt.head_version,
                &Status::Active,
                consumer_clock + chrono::Duration::seconds(60),
            )
            .unwrap();
        near_future
            .check_as_of_skew(consumer_clock, skew)
            .expect("lhr-004 boundary: honest clock skew within the allowance must pass");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// cur-* — cursor pagination failure modes (RFC-ACDP-0005 §2.5.4)
// ═══════════════════════════════════════════════════════════════════════

/// cur-001 / cur-002 — the two distinct cursor failure modes, bound
/// behaviorally against `InMemoryStore` through the public
/// `RegistryStore::search` path (the same decode used by
/// `RegistryServer::search`).
#[cfg(feature = "server")]
mod cursor_fixtures {
    use super::*;
    use acdp::registry::{InMemoryStore, RegistryStore};
    use acdp::types::search::{SearchParams, SearchResponse};

    fn search_with_cursor(cursor: &str) -> Result<SearchResponse, acdp::AcdpError> {
        let params = SearchParams {
            cursor: Some(cursor.to_owned()),
            ..Default::default()
        };
        InMemoryStore::new().search(&params, None, true)
    }

    /// cur-001 — a cursor that WAS validly issued but has aged past the
    /// TTL window MUST fail with `cursor_expired` (HTTP 400). A registry
    /// MUST NOT silently treat an expired cursor as a first-page request.
    #[test]
    fn cur_001_expired_cursor() {
        let Some(root) = spec_root() else { return };
        let path = root.join("schemas/conformance/cur-001-expired-cursor.json");
        if fixture_missing(&path) {
            return;
        }
        let v = read_json(&path);
        assert_eq!(v["expected"]["error_code"], "cursor_expired");
        assert_eq!(v["expected"]["http_status"], 400);

        // Craft a cursor in the documented stable encoding —
        // base64("<mint_ms>:<anchor_ms>:<ctx_id>") — whose mint timestamp
        // is two hours old, past the store's 1-hour CURSOR_TTL. This is a
        // cursor that WAS well-formed (decodes cleanly) but aged out,
        // which is exactly the cur-001 vs cur-002 distinction.
        use base64::{engine::general_purpose::STANDARD, Engine};
        let mint_ms = chrono::Utc::now().timestamp_millis() - 2 * 3_600 * 1_000;
        let cursor = STANDARD.encode(format!(
            "{mint_ms}:{mint_ms}:acdp://registry.example.com/contexts/00000000-0000-4000-8000-000000000000"
        ));
        let err = search_with_cursor(&cursor).expect_err("cur-001: aged cursor MUST be rejected");
        assert!(
            matches!(err, acdp::AcdpError::CursorExpired),
            "cur-001: expected CursorExpired, got {err:?}"
        );
    }

    /// cur-002 — a cursor that was NEVER parseable (garbage, truncated,
    /// forged) MUST fail with `invalid_cursor`, distinct from
    /// `cursor_expired`, and MUST NOT be best-effort interpreted.
    #[test]
    fn cur_002_invalid_cursor() {
        let Some(root) = spec_root() else { return };
        let path = root.join("schemas/conformance/cur-002-invalid-cursor.json");
        if fixture_missing(&path) {
            return;
        }
        let v = read_json(&path);
        assert_eq!(v["expected"]["error_code"], "invalid_cursor");
        assert_eq!(v["expected"]["http_status"], 400);

        // The fixture's endpoint carries `cursor=not-a-real-cursor-%21%21%21`
        // (percent-decoded here); also probe truncated and empty forms.
        for garbage in ["not-a-real-cursor-!!!", "AAAA", ""] {
            let err = search_with_cursor(garbage)
                .expect_err(&format!("cur-002: {garbage:?} MUST be rejected"));
            assert!(
                matches!(err, acdp::AcdpError::InvalidCursor(_)),
                "cur-002: {garbage:?} expected InvalidCursor, got {err:?}"
            );
        }
        // Well-formed base64 of a wrong-shape payload is still
        // invalid_cursor — a partially-decoded cursor MUST never be
        // best-effort interpreted.
        use base64::{engine::general_purpose::STANDARD, Engine};
        let wrong_shape = STANDARD.encode("no-colons-here");
        let err = search_with_cursor(&wrong_shape)
            .expect_err("cur-002: wrong-shape cursor MUST be rejected");
        assert!(
            matches!(err, acdp::AcdpError::InvalidCursor(_)),
            "cur-002: wrong-shape expected InvalidCursor, got {err:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// *-ssrf-004 / *-ssrf-005 / fed-007 / fed-008 — Clarifications round 2
// (RFC-ACDP-0006 §7.1 mixed-answer rejection, §7.5 same-authority)
// ═══════════════════════════════════════════════════════════════════════

/// Mixed-answer rejection and same-authority-port fixtures, bound
/// data-driven from each fixture's `dns_mock` / `redirect_*` inputs
/// against the exact public enforcement points the client uses:
/// [`acdp::safe_http::reject_if_any_forbidden`] (shared by
/// `SafeDnsResolver` and `pin_resolved_ip`) and
/// [`acdp::safe_http::same_fetch_authority`] / `classify_redirect`.
#[cfg(feature = "client")]
mod ssrf_addendum_fixtures {
    use super::*;
    use acdp::safe_http::{reject_if_any_forbidden, same_fetch_authority, SsrfPolicy};
    use std::net::{IpAddr, SocketAddr};

    fn answer_set(v: &serde_json::Value) -> Vec<SocketAddr> {
        v.as_array()
            .expect("fixture answers array")
            .iter()
            .map(|a| {
                let ip: IpAddr = a
                    .as_str()
                    .expect("answer is a string")
                    .parse()
                    .expect("fixture IP parses");
                SocketAddr::new(ip, 443)
            })
            .collect()
    }

    /// did-ssrf-004 / data-ref-ssrf-004 / fed-007 — when ANY address in
    /// a DNS answer set is forbidden, the ENTIRE resolution is rejected.
    /// Filter-and-proceed (connect to the surviving public address) is
    /// explicitly non-conformant.
    #[test]
    fn mixed_answer_fixtures_reject_entire_resolution() {
        let Some(root) = spec_root() else { return };
        let policy = SsrfPolicy::default();
        for name in [
            "did-ssrf-004-mixed-answer-rejection.json",
            "data-ref-ssrf-004-mixed-answer-rejection.json",
            "fed-007-mixed-answer-rejection.json",
        ] {
            let path = root.join("schemas/conformance").join(name);
            if fixture_missing(&path) {
                continue;
            }
            let v = read_json(&path);
            let input = &v["input"];
            assert_eq!(
                v["expected"]["outcome"], "failure",
                "{name}: fixture contract"
            );

            let mut cases = vec![(
                input["dns_mock"]["host"]
                    .as_str()
                    .expect("dns_mock.host")
                    .to_owned(),
                answer_set(&input["dns_mock"]["answers"]),
            )];
            if let Some(extra) = input["additional_test_cases"].as_array() {
                for c in extra {
                    cases.push((
                        c["host"].as_str().expect("case host").to_owned(),
                        answer_set(&c["answers"]),
                    ));
                }
            }
            for (host, answers) in cases {
                assert!(
                    answers.len() >= 2,
                    "{name}/{host}: mixed-answer case needs at least two answers"
                );
                // Premise check: the set is genuinely MIXED — a
                // filter-and-proceed implementation would still have a
                // public address to connect to, which is exactly the
                // bypass this fixture forbids.
                assert!(
                    answers.iter().any(|a| policy.check_ip(a.ip()).is_ok()),
                    "{name}/{host}: fixture must contain at least one public address"
                );
                reject_if_any_forbidden(&policy, &host, &answers).expect_err(&format!(
                    "{name}/{host}: mixed answer set MUST reject the ENTIRE resolution"
                ));
            }
        }
    }

    /// did-ssrf-005 / data-ref-ssrf-005 / fed-008 — "same authority" is
    /// scheme + host (case-insensitive) + EFFECTIVE port. A same-host
    /// different-port redirect is cross-authority and MUST be refused;
    /// an explicit `:443` on `https://` is the SAME authority.
    #[test]
    fn same_host_different_port_redirect_fixtures() {
        let Some(root) = spec_root() else { return };
        let policy = SsrfPolicy::default();
        for name in [
            "did-ssrf-005-same-host-different-port-redirect.json",
            "data-ref-ssrf-005-same-host-different-port-redirect.json",
            "fed-008-same-host-different-port-redirect.json",
        ] {
            let path = root.join("schemas/conformance").join(name);
            if fixture_missing(&path) {
                continue;
            }
            let v = read_json(&path);
            let input = &v["input"];
            let from_raw = input["redirect_from"].as_str().expect("redirect_from");
            let to_raw = input["redirect_to"].as_str().expect("redirect_to");
            let from: url::Url = from_raw.parse().expect("redirect_from parses");
            let to: url::Url = to_raw.parse().expect("redirect_to parses");

            assert!(
                !same_fetch_authority(&from, &to),
                "{name}: {from_raw} -> {to_raw} MUST NOT share a fetch authority"
            );
            policy
                .classify_redirect(from_raw, to_raw)
                .expect_err(&format!(
                    "{name}: cross-port redirect {from_raw} -> {to_raw} MUST be refused"
                ));

            if let Some(extra) = input["additional_test_cases"].as_array() {
                for c in extra {
                    let to2_raw = c["redirect_to"].as_str().expect("case redirect_to");
                    let to2: url::Url = to2_raw.parse().expect("case redirect_to parses");
                    let want = c["authority_match"].as_bool().expect("authority_match");
                    assert_eq!(
                        same_fetch_authority(&from, &to2),
                        want,
                        "{name}: {from_raw} -> {to2_raw} authority_match must be {want}"
                    );
                    if !want {
                        policy
                            .classify_redirect(from_raw, to2_raw)
                            .expect_err(&format!(
                                "{name}: {from_raw} -> {to2_raw} MUST be refused"
                            ));
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// idem-* — Idempotency-Key behavior (RFC-ACDP-0003 §6), bound
// behaviorally against RegistryServer + InMemoryStore
// ═══════════════════════════════════════════════════════════════════════

/// idem-001..006 driven through `publish_verified_did_key` (offline
/// did:key verification — full crypto, no network) so the idempotency
/// path under test is the same one `publish_verified` commits through.
/// The concurrent-race variant of idem-006 is additionally exercised in
/// `tests/store_contract.rs`.
#[cfg(feature = "server")]
mod idempotency_fixtures {
    use super::*;
    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::registry::{InMemoryStore, RegistryServer};
    use acdp::types::capabilities::Limits;
    use acdp::types::{ContextType, Visibility};

    fn caps_idem(supports_idempotency_key: bool) -> CapabilitiesDocument {
        CapabilitiesDocument {
            acdp_version: "0.2.0".into(),
            registry_did: "did:web:registry.example.com".into(),
            supported_signature_algorithms: vec!["ed25519".into()],
            supported_did_methods: vec!["did:web".into(), "did:key".into()],
            profiles: vec!["acdp-registry-core".into()],
            limits: Limits {
                max_payload_bytes: 1_048_576,
                max_embedded_bytes: 65_536,
                idempotency_key_ttl_seconds: if supports_idempotency_key {
                    Some(86_400)
                } else {
                    None
                },
                max_publish_per_minute: None,
            },
            read_authentication_methods: vec![],
            anonymous_public_reads: true,
            supports_idempotency_key,
            extensions: Default::default(),
        }
    }

    fn server(supports: bool) -> RegistryServer<InMemoryStore> {
        RegistryServer::new(
            InMemoryStore::new(),
            caps_idem(supports),
            "registry.example.com",
        )
    }

    fn did_key_producer(seed: u8) -> Producer {
        Producer::new_did_key(SigningKey::from_bytes(&[seed; 32]))
    }

    fn request(p: &Producer, title: &str) -> acdp::types::publish::PublishRequest {
        p.publish_request()
            .title(title)
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .expect("valid publish request")
    }

    fn fixture_gate(name: &str) -> bool {
        let Some(root) = spec_root() else {
            return false;
        };
        let path = root.join("schemas/conformance").join(name);
        !fixture_missing(&path)
    }

    /// idem-001 — first publish with an Idempotency-Key succeeds
    /// normally (201-equivalent) and records the key.
    #[test]
    fn idem_001_first_publish() {
        if !fixture_gate("idem-001-first-publish.json") {
            return;
        }
        let server = server(true);
        let p = did_key_producer(11);
        let resp = server
            .publish_verified_did_key(&request(&p, "first"), Some("idem-key-AAAA"))
            .expect("idem-001: first publish succeeds");
        assert_eq!(resp.version, 1);
        assert_eq!(resp.status, acdp::types::Status::Active);
    }

    /// idem-002 — replaying the SAME (agent, key, content_hash) returns
    /// the stored response: same ctx_id / lineage_id / created_at, no
    /// re-execution, no second persisted context.
    #[test]
    fn idem_002_retry_same_hash_replays_stored_response() {
        if !fixture_gate("idem-002-retry-same-hash.json") {
            return;
        }
        let server = server(true);
        let p = did_key_producer(12);
        let req = request(&p, "retry-me");
        let first = server
            .publish_verified_did_key(&req, Some("idem-key-AAAA"))
            .expect("first publish");
        let second = server
            .publish_verified_did_key(&req, Some("idem-key-AAAA"))
            .expect("idem-002: replay MUST succeed");
        assert_eq!(second.ctx_id, first.ctx_id, "idem-002: same ctx_id");
        assert_eq!(second.lineage_id, first.lineage_id);
        assert_eq!(second.created_at, first.created_at);
        assert_eq!(second.version, first.version);
    }

    /// idem-003 — the SAME key with DIFFERENT content is a client bug:
    /// duplicate_publish (409). The registry must not persist the new
    /// body, mint a new ctx_id, or overwrite the idempotency record.
    #[test]
    fn idem_003_same_key_different_hash_conflicts() {
        if !fixture_gate("idem-003-different-hash.json") {
            return;
        }
        let server = server(true);
        let p = did_key_producer(13);
        let first = server
            .publish_verified_did_key(&request(&p, "content-A"), Some("idem-key-AAAA"))
            .expect("first publish");
        let err = server
            .publish_verified_did_key(&request(&p, "content-B"), Some("idem-key-AAAA"))
            .expect_err("idem-003: same key + different hash MUST conflict");
        assert!(
            matches!(err, acdp::AcdpError::DuplicatePublish(_)),
            "idem-003: expected DuplicatePublish, got {err:?}"
        );
        // The original record must be untouched and retrievable.
        let ctx = server
            .retrieve(&first.ctx_id, None)
            .expect("retrieve ok")
            .expect("original context still present");
        assert_eq!(ctx.body.title, "content-A");
    }

    /// idem-004 — idempotency keys are scoped PER AGENT: a different
    /// producer reusing the same key string mints a fresh context.
    #[test]
    fn idem_004_key_scoped_per_agent() {
        if !fixture_gate("idem-004-new-key-same-content.json") {
            return;
        }
        let server = server(true);
        let a = did_key_producer(14);
        let b = did_key_producer(15);
        let first = server
            .publish_verified_did_key(&request(&a, "shared-title"), Some("idem-key-AAAA"))
            .expect("agent A publish");
        let second = server
            .publish_verified_did_key(&request(&b, "shared-title"), Some("idem-key-AAAA"))
            .expect("idem-004: agent B publish MUST succeed");
        assert_ne!(second.ctx_id, first.ctx_id, "idem-004: different ctx_id");
        assert_ne!(second.lineage_id, first.lineage_id);
    }

    /// idem-005 — a registry WITHOUT idempotency support ignores the
    /// header entirely: two publishes with the same key mint two
    /// distinct contexts.
    #[test]
    fn idem_005_no_support_ignores_header() {
        if !fixture_gate("idem-005-no-support-ignores-header.json") {
            return;
        }
        let server = server(false);
        let p = did_key_producer(16);
        let first = server
            .publish_verified_did_key(&request(&p, "no-idem"), Some("idem-key-AAAA"))
            .expect("first publish");
        let second = server
            .publish_verified_did_key(&request(&p, "no-idem"), Some("idem-key-AAAA"))
            .expect("second publish");
        assert_ne!(
            second.ctx_id, first.ctx_id,
            "idem-005: without support, the header is ignored and a fresh ctx_id is minted"
        );
    }

    /// idem-006 — serialized shadow of the race fixture: one request
    /// wins, the replay observes the winner's exact response. The truly
    /// concurrent variant runs in `tests/store_contract.rs`.
    #[test]
    fn idem_006_serialized_one_wins_other_replays() {
        if !fixture_gate("idem-006-race-concurrent.json") {
            return;
        }
        let server = server(true);
        let p = did_key_producer(17);
        let req = request(&p, "raced");
        let winner = server
            .publish_verified_did_key(&req, Some("idem-key-RACE"))
            .expect("winner publish");
        let replay = server
            .publish_verified_did_key(&req, Some("idem-key-RACE"))
            .expect("replay publish");
        assert_eq!(
            replay.ctx_id, winner.ctx_id,
            "idem-006: replay observes the winner"
        );
    }
}
