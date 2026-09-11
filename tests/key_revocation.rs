//! Producer key-revocation signal (ACDP 0.3, RFC-ACDP-0014) —
//! rev-001/rev-002 fixture bindings.
//!
//! rev-001 is EXECUTED: the golden producer-signed `key-revocation`
//! context (producer revokes K1 — the sig-001 key — signing with its
//! current key K2, the 0x42-seed) is rebuilt from the test keypair and
//! byte-compared against the pinned canonical form, `content_hash`,
//! and Ed25519 signature; the §4 shape rules and the §5 step 2
//! not-self-signed rule are asserted both positively and negatively.
//!
//! rev-002 is the §7 boundary matrix: receipt-attested publish time
//! strictly before T → *historically authorized (pre-compromise,
//! receipt-attested)*; at/after T → fail closed despite a valid
//! receipt; no verifiable publish time → fail closed under strict; and
//! the two trust classes stay distinguishable. The classification is
//! exercised both as the pure rule and end-to-end through
//! `VerifiedContext::fetch_with_policy` over the in-process TLS
//! registry harness (no external network).

mod common;

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use acdp::client::{
    classify_under_revocation, verify_revocation_body, DiscoveryFailurePolicy, HttpsDataRefFetcher,
    KeyAuthorization, ReceiptPolicy, RegistryClient, RevocationDiscovery, RevocationPolicy,
    VerificationPolicy, VerifiedContext,
};
use acdp::crypto::{
    canonicalize_value, compute_content_hash, derive_lineage_id, fingerprint_ed25519,
    verify_ed25519, SigningKey,
};
use acdp::did::WebResolver;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::registry::{InMemoryStore, RegistryServer, RegistryStore as _};
use acdp::types::receipt::ReceiptSigner;
use acdp::types::revocation::{KeyRevocation, RevocationTrustClass};
use acdp::types::{AgentDid, Body, ContentHash, ContextType, CtxId, LineageId, Visibility};
use axum::{response::IntoResponse, routing::get, Json, Router};
use chrono::{DateTime, Utc};
use common::{did_doc_router, ed25519_did_doc, TlsTestServer};
use serde_json::json;

// ── rev-001 pinned values ────────────────────────────────────────────────────

/// K2 — the producer's CURRENT key (the sig-003 test seed, rot-001's K2).
const K2_SEED: [u8; 32] = [0x42u8; 32];
const K2_PUB_HEX: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
const K2_FP: &str = "sha256:3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f";

/// K1 — the revoked key (the sig-001 all-zero test seed).
const K1_SEED: [u8; 32] = [0u8; 32];
const K1_PUB_HEX: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
const K1_FP: &str = "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070";

const PRODUCER_DID: &str = "did:web:agents.example.com:test-producer";
const TITLE: &str = "Key revocation — key-1 compromised";
const SUMMARY: &str = "Revocation of the Ed25519 key \
    did:web:agents.example.com:test-producer#key-1, compromised since 2026-05-01T00:00:00.000Z.";
const REASON: &str = "laptop theft; private key material presumed exfiltrated";
/// The compromise boundary T.
const T: &str = "2026-05-01T00:00:00.000Z";

const EXPECTED_CANONICAL: &str = "{\"acdp_version\":\"0.3.0\",\"agent_id\":\"did:web:agents.example.com:test-producer\",\"contributors\":[],\"data_refs\":[],\"derived_from\":[],\"metadata\":{\"compromised_since\":\"2026-05-01T00:00:00.000Z\",\"reason\":\"laptop theft; private key material presumed exfiltrated\",\"revoked_key_fingerprint\":\"sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070\"},\"summary\":\"Revocation of the Ed25519 key did:web:agents.example.com:test-producer#key-1, compromised since 2026-05-01T00:00:00.000Z.\",\"supersedes\":null,\"title\":\"Key revocation — key-1 compromised\",\"type\":\"key-revocation\",\"version\":1,\"visibility\":\"public\"}";
const EXPECTED_CONTENT_HASH: &str =
    "sha256:210bb03ec4bd39de893eb7d39ee992913cda80f767b135a02992a71491bf57ca";
const EXPECTED_SIGNATURE_B64: &str =
    "Lf7P+ZifUGPXIkR2i9Vy4LByaTb6ktsakKcjm4ZFUlcgTs2r9/3eyjDJDNWfT+qAseNYecvYggTIGnT7EZiPAw==";
const EXPECTED_SIGNATURE_HEX: &str =
    "2dfecff9989f5063d72244768bd572e0b0726936fa92db1a90a7239b86455257204ecdabf7fddeca30c90cd59f4fea80b1e35879cbd88204c81a74fb11988f03";

const REGISTRY_ASSIGNED_CTX_ID: &str =
    "acdp://registry.example.com/9f1e2d3c-5a6b-4c7d-8e9f-0a1b2c3d4e5f";
const REGISTRY_ASSIGNED_LINEAGE: &str =
    "lin:sha256:6af6229c1c6a4a119695c77e47f6554941aebce3d25ba8567e2ae6ffbb6059cb";

fn at(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

fn revocation_metadata() -> serde_json::Value {
    json!({
        "revoked_key_fingerprint": K1_FP,
        "compromised_since": T,
        "reason": REASON,
    })
}

/// The fixture's producer_content, verbatim.
fn golden_producer_content() -> serde_json::Value {
    json!({
        "version": 1,
        "supersedes": null,
        "agent_id": PRODUCER_DID,
        "contributors": [],
        "title": TITLE,
        "summary": SUMMARY,
        "type": "key-revocation",
        "data_refs": [],
        "derived_from": [],
        "visibility": "public",
        "metadata": revocation_metadata(),
        "acdp_version": "0.3.0",
    })
}

/// Rebuild the golden publish request through the real producer path:
/// K2 signs the revocation of K1.
fn golden_publish_request() -> acdp::types::PublishRequest {
    Producer::new(
        SigningKey::from_bytes(&K2_SEED),
        AgentDid::new(PRODUCER_DID),
        format!("{PRODUCER_DID}#key-2"),
    )
    .publish_request()
    .acdp_version("0.3.0")
    .title(TITLE)
    .summary(SUMMARY)
    .context_type(ContextType::KeyRevocation)
    .visibility(Visibility::Public)
    .metadata(revocation_metadata())
    .build()
    .expect("the golden revocation request must pass builder validation")
}

/// Materialize the golden stored Body with the fixture's
/// registry-assigned identity fields.
fn golden_body() -> Body {
    Body::from_publish_request(
        &golden_publish_request(),
        CtxId(REGISTRY_ASSIGNED_CTX_ID.into()),
        LineageId(REGISTRY_ASSIGNED_LINEAGE.into()),
        "registry.example.com",
        at("2026-05-02T08:00:00.000Z"),
    )
}

// ── rev-001: executed golden vector ──────────────────────────────────────────

#[test]
fn rev_001_keypair_constants_are_consistent() {
    let k2 = SigningKey::from_bytes(&K2_SEED);
    assert_eq!(hex::encode(k2.verifying_key_bytes()), K2_PUB_HEX);
    assert_eq!(fingerprint_ed25519(&k2.verifying_key_bytes()), K2_FP);

    let k1 = SigningKey::from_bytes(&K1_SEED);
    assert_eq!(hex::encode(k1.verifying_key_bytes()), K1_PUB_HEX);
    assert_eq!(fingerprint_ed25519(&k1.verifying_key_bytes()), K1_FP);
}

#[test]
fn rev_001_canonical_form_matches() {
    let canonical = canonicalize_value(&golden_producer_content());
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        EXPECTED_CANONICAL,
        "JCS canonical form mismatch"
    );
}

#[test]
fn rev_001_content_hash_matches() {
    let hash = compute_content_hash(&golden_producer_content()).unwrap();
    assert_eq!(hash.as_str(), EXPECTED_CONTENT_HASH);
}

#[test]
fn rev_001_signature_matches_and_verifies() {
    // Sign the ASCII bytes of the content_hash string with K2.
    let sig = SigningKey::from_bytes(&K2_SEED)
        .sign_content_hash(&ContentHash(EXPECTED_CONTENT_HASH.into()));
    assert_eq!(sig, EXPECTED_SIGNATURE_B64);
    assert_eq!(
        hex::encode(base64_decode(&sig)),
        EXPECTED_SIGNATURE_HEX,
        "raw signature bytes drifted"
    );

    let pub_bytes: [u8; 32] = hex::decode(K2_PUB_HEX).unwrap().try_into().unwrap();
    verify_ed25519(&pub_bytes, EXPECTED_SIGNATURE_B64, EXPECTED_CONTENT_HASH).unwrap();
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// The full producer path (builder validation → hash → signature)
/// reproduces the golden vector byte-for-byte.
#[test]
fn rev_001_full_producer_round_trip() {
    let req = golden_publish_request();
    assert_eq!(req.content_hash.as_str(), EXPECTED_CONTENT_HASH);
    assert_eq!(req.signature.value, EXPECTED_SIGNATURE_B64);
    assert_eq!(req.signature.algorithm, "ed25519");
    assert_eq!(req.signature.key_id, format!("{PRODUCER_DID}#key-2"));
}

#[test]
fn rev_001_lineage_id_derivation() {
    let lid = derive_lineage_id(&CtxId(REGISTRY_ASSIGNED_CTX_ID.into()));
    assert_eq!(lid.as_str(), REGISTRY_ASSIGNED_LINEAGE);
}

/// KeyRevocation::from_body parses the golden body into the typed §4
/// view with the producer-signed trust class.
#[test]
fn rev_001_parses_as_producer_signed_revocation() {
    let rev = KeyRevocation::from_body(&golden_body()).expect("golden body must parse");
    assert_eq!(rev.revoked_key_fingerprint, K1_FP);
    assert_eq!(rev.compromised_since, at(T));
    assert_eq!(rev.reason.as_deref(), Some(REASON));
    assert_eq!(rev.revoked_key_id, None);
    assert_eq!(rev.trust_class, RevocationTrustClass::ProducerSigned);
    assert_eq!(rev.revoked_key_controller.as_str(), PRODUCER_DID);
    assert_eq!(rev.publisher.as_str(), PRODUCER_DID);
    assert!(rev.revokes(K1_FP));
    assert!(!rev.revokes(K2_FP));

    // §5 step 2 against the resolved signer fingerprints: K2 signed it
    // (fine); had K1 signed it, it would be self-signed (rejected).
    rev.check_not_self_signed(K2_FP)
        .expect("K2-signed revocation of K1 is not self-signed");
    let err = rev.check_not_self_signed(K1_FP).unwrap_err();
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// §10 interim form: the identical §4 metadata under the custom type
/// `acdp:key-revocation` MUST be treated as equivalent.
#[test]
fn rev_001_interim_custom_form_is_equivalent() {
    let mut body = golden_body();
    body.context_type = ContextType::Custom("acdp:key-revocation".into());
    assert!(body.context_type.is_key_revocation());
    let rev = KeyRevocation::from_body(&body).expect("interim form must parse");
    assert_eq!(rev.revoked_key_fingerprint, K1_FP);
    assert_eq!(rev.trust_class, RevocationTrustClass::ProducerSigned);
}

/// §5 step 2, pure did:key sub-case: a did:key producer "revoking" its
/// own key is rejected at parse time — the fingerprint is derivable
/// without resolution.
#[test]
fn rev_001_did_key_self_revocation_rejected_at_parse() {
    // The all-zero seed IS K1: this did:key's fingerprint equals the
    // revoked fingerprint.
    let producer = Producer::new_did_key(SigningKey::from_bytes(&K1_SEED));
    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title(TITLE)
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(revocation_metadata())
        .build()
        .expect("builder does not resolve keys; the publish shape itself is valid");
    let body = Body::from_publish_request(
        &req,
        CtxId(REGISTRY_ASSIGNED_CTX_ID.into()),
        LineageId(REGISTRY_ASSIGNED_LINEAGE.into()),
        "registry.example.com",
        at("2026-05-02T08:00:00.000Z"),
    );
    let err = KeyRevocation::from_body(&body).unwrap_err();
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// §4 shape violations → schema_violation, matching what a 0.3.0
/// registry must reject at publish.
#[test]
fn rev_001_shape_violations_rejected() {
    // Wrong context type.
    let mut body = golden_body();
    body.context_type = ContextType::Analysis;
    assert!(matches!(
        KeyRevocation::from_body(&body),
        Err(AcdpError::SchemaViolation(_))
    ));

    // Non-public visibility protects nobody.
    let mut body = golden_body();
    body.visibility = acdp::types::Visibility::Restricted;
    assert!(matches!(
        KeyRevocation::from_body(&body),
        Err(AcdpError::SchemaViolation(_))
    ));

    // Missing metadata entirely.
    let mut body = golden_body();
    body.metadata = None;
    assert!(matches!(
        KeyRevocation::from_body(&body),
        Err(AcdpError::SchemaViolation(_))
    ));

    // Fingerprint not in RFC-ACDP-0010 §6 form.
    for bad_fp in [
        json!("139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070"), // no prefix
        json!("sha256:139E3940E64B5491722088D9A0D741628FC826E09475D341A780ACDE3C4B8070"), // uppercase
        json!("sha256:139e39"),                                                           // short
        json!(42), // not a string
    ] {
        let mut body = golden_body();
        body.metadata.as_mut().unwrap()["revoked_key_fingerprint"] = bad_fp.clone();
        assert!(
            matches!(
                KeyRevocation::from_body(&body),
                Err(AcdpError::SchemaViolation(_))
            ),
            "fingerprint {bad_fp} must be rejected"
        );
    }

    // compromised_since must be canonical millisecond RFC 3339 UTC.
    for bad_t in [
        json!("2026-05-01T00:00:00Z"),          // no millis
        json!("2026-05-01T00:00:00.000+00:00"), // offset spelling
        json!("2026-05-01"),                    // date only
        json!(1_777_000_000),                   // epoch number
    ] {
        let mut body = golden_body();
        body.metadata.as_mut().unwrap()["compromised_since"] = bad_t.clone();
        assert!(
            matches!(
                KeyRevocation::from_body(&body),
                Err(AcdpError::SchemaViolation(_))
            ),
            "compromised_since {bad_t} must be rejected"
        );
    }

    // reason capped at 1024 characters.
    let mut body = golden_body();
    body.metadata.as_mut().unwrap()["reason"] = json!("x".repeat(1025));
    assert!(matches!(
        KeyRevocation::from_body(&body),
        Err(AcdpError::SchemaViolation(_))
    ));

    // revoked_key_controller present-and-equal is the explicit
    // producer-signed binding (§5 rule 3) — accepted.
    let mut body = golden_body();
    body.metadata.as_mut().unwrap()["revoked_key_controller"] = json!(PRODUCER_DID);
    let rev = KeyRevocation::from_body(&body).unwrap();
    assert_eq!(rev.trust_class, RevocationTrustClass::ProducerSigned);
}

/// Cross-check the inline constants against the canonical spec fixture
/// and execute the fixture's own vector end-to-end. Skips when the spec
/// checkout is absent; hard-fails under ACDP_REQUIRE_CONFORMANCE.
#[test]
fn rev_001_fixture_file_cross_check() {
    let require = std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok();
    let Some(root) = spec_root() else {
        assert!(!require, "ACDP_REQUIRE_CONFORMANCE set but spec not found");
        eprintln!("ACDP spec not found; skipping rev-001 fixture cross-check");
        return;
    };
    let path = root.join("schemas/conformance/rev-001-revocation-context-golden.json");
    if !path.exists() {
        assert!(
            !require,
            "ACDP_REQUIRE_CONFORMANCE set but {} is missing",
            path.display()
        );
        eprintln!("rev-001 fixture not present; skipping");
        return;
    }
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

    // Keypair constants.
    assert_eq!(v["test_keypair"]["private_seed_hex"], hex::encode(K2_SEED));
    assert_eq!(v["test_keypair"]["public_key_hex"], K2_PUB_HEX);
    assert_eq!(v["test_keypair"]["key_fingerprint"], K2_FP);
    assert_eq!(v["revoked_key"]["public_key_hex"], K1_PUB_HEX);
    assert_eq!(v["revoked_key"]["key_fingerprint"], K1_FP);

    let vector = &v["vectors"][0];

    // Execute the vector from the fixture's own producer_content.
    let pc = &vector["producer_content"];
    let canonical = canonicalize_value(pc);
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        vector["expected"]["canonical_form"].as_str().unwrap()
    );
    let hash = compute_content_hash(pc).unwrap();
    assert_eq!(
        hash.as_str(),
        vector["expected"]["content_hash"].as_str().unwrap()
    );
    let sig = SigningKey::from_bytes(&K2_SEED).sign_content_hash(&hash);
    assert_eq!(
        sig,
        vector["expected"]["signature_value_base64"]
            .as_str()
            .unwrap()
    );

    // The fixture's expected values equal our inline pins.
    assert_eq!(vector["expected"]["canonical_form"], EXPECTED_CANONICAL);
    assert_eq!(vector["expected"]["content_hash"], EXPECTED_CONTENT_HASH);
    assert_eq!(
        vector["expected"]["signature_value_base64"],
        EXPECTED_SIGNATURE_B64
    );
    assert_eq!(
        vector["expected"]["signature_value_hex"],
        EXPECTED_SIGNATURE_HEX
    );

    // The fixture's full publish_request_body round-trips through the
    // typed PublishRequest (this requires ContextType to accept the
    // standard `key-revocation` value).
    let req: acdp::types::PublishRequest =
        serde_json::from_value(vector["expected"]["publish_request_body"].clone()).unwrap();
    assert_eq!(req.context_type, ContextType::KeyRevocation);
    assert_eq!(req.content_hash.as_str(), EXPECTED_CONTENT_HASH);
}

fn spec_root() -> Option<PathBuf> {
    if let Ok(env) = std::env::var("ACDP_SPEC_DIR") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
    }
    let sibling = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .join("agentcontextdistributionprotocol");
    sibling.exists().then_some(sibling)
}

// ── rev-002: §7 boundary matrix (pure classification) ───────────────────────
//
// RS-5: driven from `rev-002-before-after-boundary.json`'s `input` matrix
// rather than hand-copied constants — see `rev_002_fixture()` /
// `rev_002_revocation_from_fixture()` below. Editing the fixture's
// `revocation.revoked_key_fingerprint`, `revocation.compromised_since`, or
// `registry_receipt.created_at_by_scenario.{A,B}` changes what these tests
// actually exercise, because both the signed revocation body AND the
// classifier inputs are built from those parsed values, not from module
// constants that merely happen to match.

/// Load the rev-002 fixture, honoring the require-mode gate — mirrors
/// the inline pattern in `rev_001_fixture_file_cross_check` above (this
/// file has no shared `require_conformance()` helper the way
/// `tests/conformance.rs` does).
fn rev_002_fixture() -> Option<serde_json::Value> {
    let require = std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok();
    let Some(root) = spec_root() else {
        assert!(!require, "ACDP_REQUIRE_CONFORMANCE set but spec not found");
        eprintln!("ACDP spec not found; skipping rev-002 fixture-driven scenario tests");
        return None;
    };
    let path = root.join("schemas/conformance/rev-002-before-after-boundary.json");
    if !path.exists() {
        assert!(
            !require,
            "ACDP_REQUIRE_CONFORMANCE set but {} is missing",
            path.display()
        );
        eprintln!("rev-002 fixture not present; skipping");
        return None;
    }
    Some(serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap())
}

/// Look up a required string field by JSON path, panicking with the
/// path on any shape drift — loud failure beats a silent `None`
/// mis-driving a scenario test.
fn json_str<'a>(v: &'a serde_json::Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for key in path {
        cur = cur
            .get(key)
            .unwrap_or_else(|| panic!("rev-002 fixture missing {path:?} (stopped at '{key}')"));
    }
    cur.as_str()
        .unwrap_or_else(|| panic!("rev-002 fixture {path:?} is not a string"))
}

/// Build a producer-signed revocation from the fixture's own
/// `input.revocation` values (fingerprint + compromise boundary),
/// rather than the module-level `K1_FP`/`T` constants — this is what
/// makes the scenario tests below actually depend on the fixture's
/// content, not just its presence.
fn rev_002_revocation_from_fixture(fixture: &serde_json::Value) -> KeyRevocation {
    let revoked_fp = json_str(fixture, &["input", "revocation", "revoked_key_fingerprint"]);
    let compromised_since = json_str(fixture, &["input", "revocation", "compromised_since"]);
    let metadata = json!({
        "revoked_key_fingerprint": revoked_fp,
        "compromised_since": compromised_since,
        "reason": REASON,
    });
    let req = Producer::new(
        SigningKey::from_bytes(&K2_SEED),
        AgentDid::new(PRODUCER_DID),
        format!("{PRODUCER_DID}#key-2"),
    )
    .publish_request()
    .acdp_version("0.3.0")
    .title(TITLE)
    .summary(SUMMARY)
    .context_type(ContextType::KeyRevocation)
    .visibility(Visibility::Public)
    .metadata(metadata)
    .build()
    .expect("the rev-002-driven revocation request must pass builder validation");
    let body = Body::from_publish_request(
        &req,
        CtxId(REGISTRY_ASSIGNED_CTX_ID.into()),
        LineageId(REGISTRY_ASSIGNED_LINEAGE.into()),
        "registry.example.com",
        at("2026-05-02T08:00:00.000Z"),
    );
    KeyRevocation::from_body(&body).unwrap()
}

/// Scenario A — receipt-attested publish time strictly before T:
/// historically authorized (pre-compromise, receipt-attested), and the
/// status is distinguishable from every other verdict.
#[test]
fn rev_002_a_before_t_is_pre_compromise_historical() {
    let Some(fixture) = rev_002_fixture() else {
        return;
    };
    let revoked_fp = json_str(
        &fixture,
        &["input", "body_under_test", "signer_key_fingerprint"],
    );
    let before_t = json_str(
        &fixture,
        &["input", "registry_receipt", "created_at_by_scenario", "A"],
    );
    let revocation = rev_002_revocation_from_fixture(&fixture);

    let verdict = classify_under_revocation(&[revocation], revoked_fp, Some(at(before_t)))
        .unwrap()
        .expect("the revocation names K1 — it must produce a verdict");
    assert_eq!(
        verdict,
        KeyAuthorization::HistoricallyAuthorizedPreCompromise
    );
    // MUST NOT be reported as fully current, and MUST NOT be reported
    // identically to the no-revocation rot-001 A status.
    assert_ne!(verdict, KeyAuthorization::CurrentlyAuthorized);
    assert_ne!(verdict, KeyAuthorization::HistoricallyAuthorized);
}

/// Scenario B — at or after T: fail closed despite the valid receipt.
#[test]
fn rev_002_b_at_or_after_t_fails_closed() {
    let Some(fixture) = rev_002_fixture() else {
        return;
    };
    let revoked_fp = json_str(
        &fixture,
        &["input", "body_under_test", "signer_key_fingerprint"],
    );
    let compromised_since = json_str(&fixture, &["input", "revocation", "compromised_since"]);
    let after_t = json_str(
        &fixture,
        &["input", "registry_receipt", "created_at_by_scenario", "B"],
    );
    let revocation = rev_002_revocation_from_fixture(&fixture);

    for when in [after_t, compromised_since] {
        let err = classify_under_revocation(
            std::slice::from_ref(&revocation),
            revoked_fp,
            Some(at(when)),
        )
        .expect_err("at/after the boundary must fail closed");
        assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
    }
}

/// Scenario C — no receipt: the publish time is unverifiable and the
/// strict profile fails closed (the bare body created_at MUST NOT be
/// used — there is no parameter through which to pass it).
#[test]
fn rev_002_c_unverifiable_time_fails_closed() {
    let Some(fixture) = rev_002_fixture() else {
        return;
    };
    let revoked_fp = json_str(
        &fixture,
        &["input", "body_under_test", "signer_key_fingerprint"],
    );
    let revocation = rev_002_revocation_from_fixture(&fixture);

    let err = classify_under_revocation(&[revocation], revoked_fp, None)
        .expect_err("receipt-less revoked-key context must fail closed under strict");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// Scenario D — trust classes are distinguishable: the same statement
/// arriving as a registry-attested context is classified
/// registry-attested, never collapsed into producer-signed; and a
/// K1-self-signed "revocation" is unverified, triggering none of §7.
#[test]
fn rev_002_d_trust_classes_distinguishable() {
    let Some(fixture) = rev_002_fixture() else {
        return;
    };
    let revoked_fp = json_str(
        &fixture,
        &["input", "body_under_test", "signer_key_fingerprint"],
    );

    // Registry-attested form: agent_id is the registry,
    // revoked_key_controller (REQUIRED here) names the producer.
    let mut body = golden_body();
    body.agent_id = AgentDid::new("did:web:registry.example.com");
    body.signature.key_id = "did:web:registry.example.com#receipt-key-1".into();
    body.metadata.as_mut().unwrap()["revoked_key_controller"] = json!(PRODUCER_DID);
    let registry_attested = KeyRevocation::from_body(&body).unwrap();
    assert_eq!(
        registry_attested.trust_class,
        RevocationTrustClass::RegistryAttested
    );
    assert_eq!(
        registry_attested.revoked_key_controller.as_str(),
        PRODUCER_DID
    );
    assert_eq!(
        registry_attested.publisher.as_str(),
        "did:web:registry.example.com"
    );

    let producer_signed = rev_002_revocation_from_fixture(&fixture);
    assert_eq!(
        producer_signed.trust_class,
        RevocationTrustClass::ProducerSigned
    );
    assert_ne!(
        producer_signed.trust_class, registry_attested.trust_class,
        "the classes MUST NOT be collapsed (RFC-ACDP-0014 §6)"
    );

    // A "revocation" signed by K1 itself: §5 step 2 rejects it before
    // it can ever enter the §7 classifier.
    let err = producer_signed
        .check_not_self_signed(revoked_fp)
        .unwrap_err();
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// §4 earliest-T monotonicity across a revocation lineage: a
/// supersession can widen but never quietly shrink the window. Not one
/// of rev-002's own A/B/C/D scenarios, but driven from the same
/// fixture-sourced fingerprint/boundary for consistency.
#[test]
fn rev_002_earliest_boundary_across_lineage() {
    let Some(fixture) = rev_002_fixture() else {
        return;
    };
    let revoked_fp = json_str(
        &fixture,
        &["input", "body_under_test", "signer_key_fingerprint"],
    );
    let before_t = json_str(
        &fixture,
        &["input", "registry_receipt", "created_at_by_scenario", "A"],
    );

    let head = rev_002_revocation_from_fixture(&fixture);
    // A superseding revocation that moved T EARLIER (widening).
    let mut widened = head.clone();
    widened.compromised_since = at("2026-04-01T00:00:00.000Z");
    let lineage = [head, widened];

    // A publish time before the head's T but after the widened T is
    // inside the effective window.
    let err = classify_under_revocation(&lineage, revoked_fp, Some(at(before_t)))
        .expect_err("the earliest compromised_since across the lineage is effective");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    // Strictly before both boundaries still verifies.
    assert_eq!(
        classify_under_revocation(&lineage, revoked_fp, Some(at("2026-03-01T00:00:00.000Z")))
            .unwrap(),
        Some(KeyAuthorization::HistoricallyAuthorizedPreCompromise)
    );
}

/// **Issue #226 Phase 5 — the pinning test.** `rev_002_earliest_boundary_across_lineage`
/// above folds a HAND-BUILT two-element array through `classify_under_revocation`
/// directly — it proves `effective_boundary`'s fold is correct, and
/// nothing at all about whether real discovery ever *assembles* that
/// array in the first place. This test drives the real registry
/// end-to-end: R1 (T=early) → superseded by R2 (T=later) → R1 is
/// retracted. It asserts all three things RFC-ACDP-0014 §4:62's
/// end-to-end guarantee actually requires:
///
/// 1. A **search-only reconstruction** — the historical pre-Phase-3/4
///    algorithm: `active` + `superseded` search passes only, no
///    `retracted` pass, no lineage walk — MISSES R1 entirely. Once R1
///    is retracted, the registry's *served* status for it is
///    `retracted`, not `superseded` — `project_status` in
///    `crates/acdp-server/src/registry/store.rs` makes retraction take
///    precedence over the stored supersession fact — so neither
///    pre-fix search pass ever names it again. This pins the
///    historical blind spot as a documented, executable property
///    rather than free-text prose.
/// 2. `find_revocations` (post Phase 3 lineage walk + Phase 4 retracted
///    pass) returns BOTH R1 and R2.
/// 3. `effective_boundary` over that output resolves to R1's (earlier)
///    T — the RFC-ACDP-0014 §4 monotonicity rule, now proven against
///    real assembly rather than a hand-built input.
///
/// Runs against `LineageServerHarness` (a REAL `RegistryServer`), not a
/// hand-built mock: every hand-built mock elsewhere in this file
/// ignores the `status` query parameter and reports every match as
/// `"status": "active"` regardless of what actually happened to it,
/// which would make assertion 1 pass vacuously.
#[tokio::test]
async fn find_revocations_recovers_retracted_predecessor_across_lineage_supersession() {
    use acdp::client::find_revocations;
    use acdp::types::lifecycle::{LifecycleEvent, LifecycleEventType};
    use acdp::types::revocation::effective_boundary;

    let h = LineageServerHarness::start(lifecycle_caps(), true).await;

    let seed = [0x91u8; 32];
    let producer = Producer::new_did_key(SigningKey::from_bytes(&seed));
    let did =
        acdp::did::key::did_key_from_ed25519(&SigningKey::from_bytes(&seed).verifying_key_bytes());
    let key_id = acdp::did::key::did_key_url(&did).expect("did:key URL");
    let agent_id = AgentDid::new(did);

    let early_t = at("2026-04-01T00:00:00.000Z");
    let later_t = at("2026-05-01T00:00:00.000Z");

    // R1: T = early.
    let r1_req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("R1: early compromise boundary, later retracted")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": K1_FP,
            "compromised_since": "2026-04-01T00:00:00.000Z",
        }))
        .build()
        .expect("r1 build");
    let r1_resp = h
        .server
        .publish_verified_did_key(&r1_req, None)
        .expect("r1 publish");
    let r1_stored = h
        .server
        .store()
        .get(&r1_resp.ctx_id)
        .expect("get")
        .expect("r1 present");

    // R2: supersedes R1, T = later. `check_revocation_supersession`
    // does not gate on the direction `compromised_since` moves at
    // publish time — RFC-ACDP-0014 §4:62 places the monotonicity
    // guarantee on the consumer side, via `effective_boundary` — so
    // this publishes without issue regardless of which way T moved.
    let r2_req = producer
        .supersede_body(&r1_stored.body)
        .acdp_version("0.3.0")
        .title("R2: supersedes R1, later boundary")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": K1_FP,
            "compromised_since": "2026-05-01T00:00:00.000Z",
        }))
        .build()
        .expect("r2 build");
    let r2_resp = h
        .server
        .publish_verified_did_key(&r2_req, None)
        .expect("r2 publish");
    assert_eq!(r2_resp.lineage_id, r1_resp.lineage_id);

    // R1 is now genuinely superseded — the real registry deriving that,
    // not a hand-synthesized status.
    let r1_after_supersede = h.server.store().get(&r1_resp.ctx_id).unwrap().unwrap();
    assert_eq!(r1_after_supersede.registry_state.status, Status::Superseded);

    // Retract R1. `retract_unverified_for_tests` skips only the §6
    // step 3 cryptographic half; actor presence/binding is still
    // enforced, so the event still needs a bound signature.
    let event = LifecycleEvent::new(
        "018f6d0a-00f4-4c4d-9e1f-3a5b7c9d1e30",
        r1_resp.ctx_id.clone(),
        LifecycleEventType::Retracted,
        chrono::Utc::now(),
        agent_id.clone(),
        Some("R1 retracted after being superseded by R2".into()),
    )
    .expect("valid event")
    .sign_with(SigningKey::from_bytes(&seed), key_id)
    .expect("signed event");
    h.server
        .retract_unverified_for_tests(&event, None)
        .expect("retract");

    // Real-registry projection: retraction takes precedence over the
    // stored "superseded" fact (`project_status`,
    // `crates/acdp-server/src/registry/store.rs`) — R1's SERVED status
    // is now `retracted`, NOT `superseded`. This is exactly what makes
    // assertion 1 below non-vacuous: a `status=superseded` search pass
    // genuinely no longer names R1.
    let r1_after_retract = h.server.store().get(&r1_resp.ctx_id).unwrap().unwrap();
    assert_eq!(r1_after_retract.registry_state.status, Status::Retracted);

    let client = h.client();

    // ── Assertion 1: a search-only reconstruction (the pre-fix
    // algorithm — `active` + `superseded` passes, NO `retracted` pass,
    // NO lineage walk) MISSES R1. ────────────────────────────────────
    let mut search_only = Vec::new();
    for status in ["active", "superseded"] {
        let params = acdp::types::SearchParamsBuilder::new()
            .context_type("key-revocation")
            .agent_id(agent_id.as_str())
            .status(status)
            .limit(100)
            .build();
        let resp = client.search(&params).await.expect("search");
        for m in &resp.matches {
            let ctx = client.retrieve(&m.ctx_id).await.expect("retrieve");
            if let Ok(rev) = verify_revocation_body(&ctx.body, &h.resolver).await {
                search_only.push(rev);
            }
        }
    }
    assert_eq!(
        search_only.len(),
        1,
        "the pre-fix search-only reconstruction must see only R2 — R1 is now \
         retracted, invisible to both the active and superseded passes"
    );
    assert_eq!(search_only[0].compromised_since, later_t);
    assert!(
        !search_only.iter().any(|r| r.compromised_since == early_t),
        "R1 (the retracted, earlier-boundary member) must be MISSING from the \
         pre-fix search-only reconstruction — this is the historical blind \
         spot issue #226 exists to close"
    );

    // ── Assertion 2: `find_revocations` (post Phase 3 lineage walk +
    // Phase 4 retracted pass) returns BOTH R1 and R2. ────────────────
    let mut revs = find_revocations(&client, &h.resolver, &agent_id)
        .await
        .expect("find_revocations must recover the full lineage");
    assert_eq!(
        revs.len(),
        2,
        "find_revocations must return both R1 (retracted) and R2 (active)"
    );
    revs.sort_by_key(|r| r.compromised_since);
    assert_eq!(revs[0].compromised_since, early_t);
    assert_eq!(revs[1].compromised_since, later_t);
    for r in &revs {
        assert_eq!(r.revoked_key_fingerprint, K1_FP);
        assert_eq!(r.trust_class, RevocationTrustClass::ProducerSigned);
    }

    // ── Assertion 3: `effective_boundary` over that output resolves
    // to R1's (earlier) T. ────────────────────────────────────────────
    assert_eq!(
        effective_boundary(&revs, K1_FP),
        Some(early_t),
        "RFC-ACDP-0014 §4: the earliest compromised_since across the lineage \
         is effective, regardless of retraction"
    );
}

// ── §5 pipeline: verify_revocation_body over an offline did:key body ────────

/// A did:key producer CAN issue a producer-signed revocation for some
/// *other* key's fingerprint; the full §5 pipeline verifies it with no
/// network (pure did:key resolution).
#[tokio::test]
async fn verify_revocation_body_did_key_offline() {
    let producer = Producer::new_did_key(SigningKey::from_bytes(&[9u8; 32]));
    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title(TITLE)
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(revocation_metadata()) // revokes K1's fingerprint
        .build()
        .unwrap();
    let body = Body::from_publish_request(
        &req,
        CtxId(REGISTRY_ASSIGNED_CTX_ID.into()),
        LineageId(REGISTRY_ASSIGNED_LINEAGE.into()),
        "registry.example.com",
        at("2026-05-02T08:00:00.000Z"),
    );

    let resolver = WebResolver::new();
    let rev = verify_revocation_body(&body, &resolver)
        .await
        .expect("did:key revocation of a different key must verify offline");
    assert_eq!(rev.revoked_key_fingerprint, K1_FP);
    assert_eq!(rev.trust_class, RevocationTrustClass::ProducerSigned);

    // Tampering with the boundary breaks the content hash → the §5
    // pipeline rejects before the shape is ever consulted.
    let mut tampered = body;
    tampered.metadata.as_mut().unwrap()["compromised_since"] = json!("2026-06-01T00:00:00.000Z");
    assert!(verify_revocation_body(&tampered, &resolver).await.is_err());
}

// ── rev-002 end-to-end: the fetch pipeline honors RevocationPolicy ──────────

const REGISTRY_AUTHORITY: &str = "localhost";
const REGISTRY_DID: &str = "did:web:localhost";
const LOCAL_PRODUCER_DID: &str = "did:web:localhost:agent";
/// A second, distinct producer identity — used only by the §191
/// query-scope tests below to prove that a body genuinely published
/// under a *different* producer, but listed in `LOCAL_PRODUCER_DID`'s
/// search results by a hostile or buggy registry, is dropped rather
/// than returned.
const OTHER_PRODUCER_DID: &str = "did:web:localhost:other-agent";

fn caps() -> acdp::types::CapabilitiesDocument {
    use acdp::types::capabilities::Limits;
    acdp::types::CapabilitiesDocument {
        acdp_version: "0.2.0".into(),
        registry_did: REGISTRY_DID.into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into(), "did:key".into()],
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
    }
}

struct Harness {
    tls: TlsTestServer,
    context_json: Arc<RwLock<Option<serde_json::Value>>>,
    resolver: WebResolver,
}
async fn start_harness(registry_receipt_pub: &[u8; 32], producer_pub: &[u8; 32]) -> Harness {
    let registry_doc = ed25519_did_doc(REGISTRY_DID, "receipt-key-1", registry_receipt_pub);
    let producer_doc = ed25519_did_doc(LOCAL_PRODUCER_DID, "key-1", producer_pub);
    let context_json: Arc<RwLock<Option<serde_json::Value>>> = Arc::new(RwLock::new(None));

    let router = Router::new()
        .route(
            "/.well-known/did.json",
            get(move || {
                let doc = registry_doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/agent/did.json",
            get(move || {
                let doc = producer_doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/contexts/{id}",
            get({
                let ctx = context_json.clone();
                move || {
                    let ctx = ctx.clone();
                    async move {
                        Json(
                            ctx.read()
                                .unwrap()
                                .clone()
                                .expect("context not yet published"),
                        )
                    }
                }
            }),
        );

    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    Harness {
        tls,
        context_json,
        resolver,
    }
}

impl Harness {
    fn client(&self) -> RegistryClient {
        RegistryClient::with_test_endpoint(
            &format!("https://{REGISTRY_AUTHORITY}"),
            self.tls.addr,
            &self.tls.root_cert_pem,
        )
        .expect("pinned client")
    }
}

/// Publish through a receipt-minting in-process registry; the receipt's
/// `created_at` (mint time = now) is the receipt-attested publish time
/// the §7 boundary is compared against.
async fn publish_with_receipt(h: &Harness, producer_key: SigningKey) -> (CtxId, serde_json::Value) {
    let server = RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY)
        .expect("server")
        .with_receipt_signer(
            ReceiptSigner::new(
                SigningKey::from_bytes(&[0x11u8; 32]),
                REGISTRY_DID,
                format!("{REGISTRY_DID}#receipt-key-1"),
            )
            .expect("signer"),
        )
        .expect("receipt signer accepted");

    let producer = Producer::new(
        producer_key,
        AgentDid::new(LOCAL_PRODUCER_DID),
        format!("{LOCAL_PRODUCER_DID}#key-1"),
    );
    let req = producer
        .publish_request()
        .title("context signed by the soon-to-be-revoked key")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("build");

    let resp = server
        .publish_verified(&req, None, &h.resolver)
        .await
        .expect("publish with receipt minting");
    let full = server
        .store()
        .get(&resp.ctx_id)
        .expect("get")
        .expect("present");
    (resp.ctx_id, serde_json::to_value(&full).expect("serialize"))
}

/// A verified producer-signed revocation of the harness producer key,
/// with boundary T.
fn local_revocation(producer_fp: &str, t: DateTime<Utc>) -> KeyRevocation {
    KeyRevocation {
        revoked_key_fingerprint: producer_fp.into(),
        compromised_since: acdp::time::trunc_ms(t),
        reason: Some("test compromise".into()),
        revoked_key_id: Some(format!("{LOCAL_PRODUCER_DID}#key-1")),
        revoked_key_controller: AgentDid::new(LOCAL_PRODUCER_DID),
        publisher: AgentDid::new(LOCAL_PRODUCER_DID),
        trust_class: RevocationTrustClass::ProducerSigned,
    }
}

/// rev-002 through the real retrieval pipeline: pre-T receipt →
/// pre-compromise historical; post/at-T → fail closed; no verified
/// receipt → fail closed. `key_status` stays `CurrentlyAuthorized`
/// when no supplied revocation names the key.
#[tokio::test]
async fn rev_002_fetch_pipeline_boundary_matrix() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let producer_fp = fingerprint_ed25519(&producer_pub);
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json) = publish_with_receipt(&h, producer_key).await;
    *h.context_json.write().unwrap() = Some(ctx_json.clone());
    let client = h.client();

    let policy_with = |revs: Vec<KeyRevocation>, receipts: ReceiptPolicy| VerificationPolicy {
        receipts,
        revocations: RevocationPolicy::new(revs),
        ..Default::default()
    };

    // No revocation supplied: unchanged 0.2 behavior.
    let verified = VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect("baseline fetch");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
    let receipt_time = verified.verified_receipt().expect("receipt").created_at;

    // A: boundary strictly after the receipt-attested publish time →
    // historically authorized (pre-compromise, receipt-attested), even
    // though the key is still in assertionMethod.
    let pre = policy_with(
        vec![local_revocation(
            &producer_fp,
            receipt_time + chrono::Duration::days(1),
        )],
        ReceiptPolicy::VerifyIfPresent,
    );
    let verified = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &pre)
        .await
        .expect("pre-compromise context must verify");
    assert_eq!(
        verified.key_status(),
        KeyAuthorization::HistoricallyAuthorizedPreCompromise
    );

    // B: boundary at/before the receipt-attested publish time → fail
    // closed despite the valid receipt.
    for boundary in [receipt_time, receipt_time - chrono::Duration::days(1)] {
        let post = policy_with(
            vec![local_revocation(&producer_fp, boundary)],
            ReceiptPolicy::VerifyIfPresent,
        );
        let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &post)
            .await
            .expect_err("inside the compromise window must fail closed");
        assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
    }

    // C: no verified receipt → publish time unverifiable → fail closed,
    // whether the receipt is absent…
    let mut stripped = ctx_json.clone();
    stripped.as_object_mut().unwrap().remove("registry_receipt");
    *h.context_json.write().unwrap() = Some(stripped);
    let future_boundary = policy_with(
        vec![local_revocation(
            &producer_fp,
            receipt_time + chrono::Duration::days(1),
        )],
        ReceiptPolicy::VerifyIfPresent,
    );
    let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &future_boundary)
        .await
        .expect_err("receipt-less revoked-key context must fail closed");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    // …or present but unverified because policy ignores receipts.
    *h.context_json.write().unwrap() = Some(ctx_json.clone());
    let ignoring = policy_with(
        vec![local_revocation(
            &producer_fp,
            receipt_time + chrono::Duration::days(1),
        )],
        ReceiptPolicy::Ignore,
    );
    let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &ignoring)
        .await
        .expect_err("an unverified receipt provides no publish time");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    // A revocation of some OTHER key leaves this context fully current.
    let unrelated = policy_with(
        vec![local_revocation(
            K1_FP,
            receipt_time - chrono::Duration::days(30),
        )],
        ReceiptPolicy::VerifyIfPresent,
    );
    let verified = VerifiedContext::fetch_with_policy(&client, &h.resolver, &ctx_id, &unrelated)
        .await
        .expect("unrelated revocation is inert");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
}

/// Phase 2 T1 — `fetch_report` must reach every authorization phase
/// (receipt, revocation, signature/historical-key) exactly like
/// `fetch_with_policy`, since both now delegate to `verify_retrieved`.
/// Runs each of the `rev_002` matrix cases through BOTH entry points and
/// asserts identical Ok/Err verdicts and, when both `Ok`, identical
/// `key_status`.
///
/// Falsifiability: restoring the `key_status: KeyAuthorization::
/// CurrentlyAuthorized` hardcode in `fetch_report_inner` reddens case A
/// (the pre-compromise verdict silently downgrades to `CurrentlyAuthorized`
/// while `fetch_with_policy` correctly reports
/// `HistoricallyAuthorizedPreCompromise`); deleting the `verify_retrieved`
/// delegation (so the report path never runs the revocation phase at all)
/// reddens cases B and C (an `Ok` from `fetch_report` where
/// `fetch_with_policy` returns `Err(KeyNotAuthorized)`).
#[tokio::test]
async fn report_parity_matrix() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let producer_fp = fingerprint_ed25519(&producer_pub);
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json) = publish_with_receipt(&h, producer_key).await;
    *h.context_json.write().unwrap() = Some(ctx_json.clone());
    let client = h.client();

    let policy_with = |revs: Vec<KeyRevocation>, receipts: ReceiptPolicy| VerificationPolicy {
        receipts,
        revocations: RevocationPolicy::new(revs),
        ..Default::default()
    };

    /// Run both `fetch_with_policy` and `fetch_report` against the same
    /// context under the same policy; assert they agree on Ok/Err and,
    /// when both `Ok`, on `key_status`.
    async fn assert_parity(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx_id: &CtxId,
        policy: &VerificationPolicy,
        case: &str,
    ) {
        let via_policy = VerifiedContext::fetch_with_policy(client, resolver, ctx_id, policy).await;
        let via_report = VerifiedContext::fetch_report(client, resolver, ctx_id, policy).await;
        match (via_policy, via_report) {
            (Ok(a), Ok((b, _report))) => {
                assert_eq!(
                    a.key_status(),
                    b.key_status(),
                    "{case}: fetch_with_policy and fetch_report must agree on key_status"
                );
            }
            (Err(ea), Err(eb)) => {
                // `AcdpError` has no `PartialEq`; comparing discriminants
                // is sufficient to prove "the same kind of failure".
                assert_eq!(
                    std::mem::discriminant(&ea),
                    std::mem::discriminant(&eb),
                    "{case}: fetch_with_policy err {ea:?} vs fetch_report err {eb:?}"
                );
            }
            (a, b) => panic!(
                "{case}: fetch_with_policy and fetch_report disagree on Ok/Err: \
                 {a:?} / is_ok={}",
                b.is_ok()
            ),
        }
    }

    // Baseline: no revocation supplied.
    assert_parity(
        &client,
        &h.resolver,
        &ctx_id,
        &VerificationPolicy::default(),
        "baseline",
    )
    .await;

    let baseline = VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect("baseline fetch for receipt_time");
    let receipt_time = baseline.verified_receipt().expect("receipt").created_at;

    // A: pre-compromise (boundary strictly after the receipt-attested
    // publish time) — both must verify as
    // HistoricallyAuthorizedPreCompromise.
    let pre = policy_with(
        vec![local_revocation(
            &producer_fp,
            receipt_time + chrono::Duration::days(1),
        )],
        ReceiptPolicy::VerifyIfPresent,
    );
    assert_parity(&client, &h.resolver, &ctx_id, &pre, "A (pre-compromise)").await;

    // B: boundary at/before the receipt-attested publish time — both
    // must fail closed.
    for (i, boundary) in [receipt_time, receipt_time - chrono::Duration::days(1)]
        .into_iter()
        .enumerate()
    {
        let post = policy_with(
            vec![local_revocation(&producer_fp, boundary)],
            ReceiptPolicy::VerifyIfPresent,
        );
        assert_parity(
            &client,
            &h.resolver,
            &ctx_id,
            &post,
            &format!("B[{i}] (boundary)"),
        )
        .await;
    }

    // C: no verified publish time — receipt absent — both fail closed.
    let mut stripped = ctx_json.clone();
    stripped.as_object_mut().unwrap().remove("registry_receipt");
    *h.context_json.write().unwrap() = Some(stripped);
    let future_boundary = policy_with(
        vec![local_revocation(
            &producer_fp,
            receipt_time + chrono::Duration::days(1),
        )],
        ReceiptPolicy::VerifyIfPresent,
    );
    assert_parity(
        &client,
        &h.resolver,
        &ctx_id,
        &future_boundary,
        "C (receipt absent)",
    )
    .await;

    // C': present but unverified because policy ignores receipts — both
    // fail closed.
    *h.context_json.write().unwrap() = Some(ctx_json.clone());
    let ignoring = policy_with(
        vec![local_revocation(
            &producer_fp,
            receipt_time + chrono::Duration::days(1),
        )],
        ReceiptPolicy::Ignore,
    );
    assert_parity(
        &client,
        &h.resolver,
        &ctx_id,
        &ignoring,
        "C' (receipts ignored)",
    )
    .await;

    // Unrelated-key revocation is inert on both paths.
    let unrelated = policy_with(
        vec![local_revocation(
            K1_FP,
            receipt_time - chrono::Duration::days(30),
        )],
        ReceiptPolicy::VerifyIfPresent,
    );
    assert_parity(&client, &h.resolver, &ctx_id, &unrelated, "unrelated key").await;
}

/// Phase 2 T4 — `fetch_report_diagnose` must REPORT a revocation-phase
/// failure rather than silently ignoring it (the pre-fix hardcoded
/// pipeline never ran the revocation phase at all) — but must never
/// convert it into a hard `Err`; that is this method's whole diagnostic
/// contract ("never short-circuits on a top-level failure").
///
/// Two falsifiability probes, both required:
/// (i) the pre-fix code (hardcoded `key_status: CurrentlyAuthorized`,
/// `verified_receipt: None`, no `verify_retrieved` call at all) reddens
/// this test: the revocation phase never runs, so
/// `report.policy_phase_error` stays `None` instead of
/// `Some(KeyNotAuthorized)`.
/// (ii) the over-fix guard: replacing `match outcome { .. }` in
/// `fetch_report_diagnose` with `outcome?` reddens this test too, because
/// the method would then return `Err` instead of `Ok` — exactly the
/// regression this test exists to catch, since a diagnostic that
/// hard-fails on a policy-phase error is no longer diagnostic.
#[tokio::test]
async fn report_diagnose_reports_revocation_without_erroring() {
    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let producer_fp = fingerprint_ed25519(&producer_pub);
    let registry_key_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();

    let h = start_harness(&registry_key_pub, &producer_pub).await;
    let (ctx_id, ctx_json) = publish_with_receipt(&h, producer_key).await;
    *h.context_json.write().unwrap() = Some(ctx_json.clone());
    let client = h.client();

    let baseline = VerifiedContext::fetch(&client, &h.resolver, &ctx_id)
        .await
        .expect("baseline fetch for receipt_time");
    let receipt_time = baseline.verified_receipt().expect("receipt").created_at;

    // Post-boundary: the revocation boundary is at the receipt-attested
    // publish time itself — inside the compromise window, must fail
    // closed (rev-002 case B).
    let post = VerificationPolicy {
        revocations: RevocationPolicy::new(vec![local_revocation(&producer_fp, receipt_time)]),
        ..Default::default()
    };

    let (verified, report) =
        VerifiedContext::fetch_report_diagnose(&client, &h.resolver, &ctx_id, &post)
            .await
            .expect("fetch_report_diagnose must return Ok even when the revocation phase fails");

    assert!(
        verified.is_none(),
        "the handle must be withheld once the revocation phase fails"
    );
    assert!(
        report.signature_ok,
        "the probes must still have run: the body's own signature is genuinely valid"
    );
    assert_eq!(
        report.key_status, None,
        "the phase failed, so no real key_status verdict was produced"
    );
    assert!(
        matches!(
            report.policy_phase_error,
            Some(AcdpError::KeyNotAuthorized(_))
        ),
        "got {:?}",
        report.policy_phase_error
    );
}

// ── §8 discovery: find_revocations over a searchable harness ────────────────

/// `find_revocations` returns the producer's verified revocations and
/// silently skips candidates that fail §5 with a permanent error
/// (`AcdpError::is_transient() == false`) — here a "revocation" signed
/// by the very key it revokes, which is at most a hint (§5 step 2).
#[tokio::test]
async fn find_revocations_returns_only_verified() {
    use acdp::client::find_revocations;
    use std::collections::HashMap;

    let producer_key = SigningKey::from_bytes(&[7u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let producer_fp = fingerprint_ed25519(&producer_pub);
    let producer_doc = ed25519_did_doc(LOCAL_PRODUCER_DID, "key-1", &producer_pub);

    // Stand up DID hosting first — publish-side verification resolves
    // the producer document through it.
    let did_router = Router::new().route(
        "/agent/did.json",
        get(move || {
            let doc = producer_doc.clone();
            async move { Json(doc) }
        }),
    );

    // Publish both candidates through the real registry server so the
    // served bodies are genuine (hash + signature valid for BOTH — the
    // self-signed one is cryptographically fine; §5 is what rejects it).
    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY).expect("server");
    let make_producer = |seed: [u8; 32]| {
        Producer::new(
            SigningKey::from_bytes(&seed),
            AgentDid::new(LOCAL_PRODUCER_DID),
            format!("{LOCAL_PRODUCER_DID}#key-1"),
        )
    };
    let good_req = make_producer([7u8; 32])
        .publish_request()
        .acdp_version("0.3.0")
        .title("revocation of the old key")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(revocation_metadata()) // revokes K1's fingerprint
        .build()
        .unwrap();
    let self_signed_req = make_producer([7u8; 32])
        .publish_request()
        .acdp_version("0.3.0")
        .title("self-signed non-revocation")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            // Revokes the very key that signs it: §5 step 2.
            "revoked_key_fingerprint": producer_fp,
            "compromised_since": T,
        }))
        .build()
        .unwrap();

    let tls_did = TlsTestServer::start(did_router).await;
    let resolver =
        WebResolver::with_test_endpoint(&tls_did.root_cert_pem, "localhost", tls_did.addr)
            .expect("pinned resolver");

    let mut contexts: HashMap<String, serde_json::Value> = HashMap::new();
    // Both candidates here are independent fresh v1s, so each one's own
    // lineage contains only itself — this just gives `find_revocations`'s
    // (now unconditional) lineage walk a real `/lineages/{id}` route to
    // call instead of 404ing; it is not what this test is pinning.
    let mut lineages: HashMap<String, serde_json::Value> = HashMap::new();
    let mut matches = Vec::new();
    for req in [&good_req, &self_signed_req] {
        let resp = server
            .publish_verified(req, None, &resolver)
            .await
            .expect("publish");
        let full = server
            .store()
            .get(&resp.ctx_id)
            .expect("get")
            .expect("present");
        matches.push(json!({
            "ctx_id": full.body.ctx_id.as_str(),
            "lineage_id": full.body.lineage_id.as_str(),
            "agent_id": LOCAL_PRODUCER_DID,
            "title": full.body.title,
            "type": "key-revocation",
            "created_at": "2026-05-02T08:00:00.000Z",
            "status": "active",
            "visibility": "public",
        }));
        contexts.insert(
            full.body.ctx_id.as_str().to_string(),
            serde_json::to_value(&full).unwrap(),
        );
        lineages.insert(
            full.body.lineage_id.as_str().to_string(),
            json!([serde_json::to_value(&full).unwrap()]),
        );
    }

    // Serve search + retrieval + DID hosting from one harness.
    let search_body = json!({ "matches": matches });
    let contexts = Arc::new(contexts);
    let lineages = Arc::new(lineages);
    let full_router = Router::new()
        .route(
            "/agent/did.json",
            get({
                let doc = ed25519_did_doc(LOCAL_PRODUCER_DID, "key-1", &producer_pub);
                move || {
                    let doc = doc.clone();
                    async move { Json(doc) }
                }
            }),
        )
        .route(
            "/contexts/search",
            get(move || {
                let body = search_body.clone();
                async move { Json(body) }
            }),
        )
        .route(
            "/contexts/{id}",
            get({
                let contexts = contexts.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let contexts = contexts.clone();
                    async move { Json(contexts.get(&id).cloned().expect("known ctx_id")) }
                }
            }),
        )
        .route(
            "/lineages/{id}",
            get({
                let lineages = lineages.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let lineages = lineages.clone();
                    async move { Json(lineages.get(&id).cloned().unwrap_or(json!([]))) }
                }
            }),
        );
    let tls = TlsTestServer::start(full_router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    let revs = find_revocations(&client, &resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
        .await
        .expect("discovery");
    assert_eq!(
        revs.len(),
        1,
        "exactly the verified revocation; the self-signed candidate is skipped, \
         and the four search passes (type forms × statuses) dedupe by ctx_id"
    );
    assert_eq!(revs[0].revoked_key_fingerprint, K1_FP);
    assert_eq!(revs[0].trust_class, RevocationTrustClass::ProducerSigned);
    assert_eq!(revs[0].publisher.as_str(), LOCAL_PRODUCER_DID);
}

// ── §191: query-scope + trust-class invariants in `find_revocations` ───────
//
// Three cases pinning that `find_revocations` enforces, on top of §5
// body verification: (1) the returned revocation's `publisher` really
// is the queried `agent_id`, and (2) its `trust_class` really is
// `ProducerSigned`. Neither check alone suffices — see the doc rewrite
// on `find_revocations` for why both are required together.

/// One `key-revocation` body to publish for [`discover_with_candidates`]:
/// which producer identity signs it and is served under, and the
/// body's own metadata.
struct Candidate {
    /// DID path segment: for every non-empty path, the body publishes
    /// under, and its DID document is served at,
    /// `did:web:localhost:<path>`. The empty path is the one exception
    /// (see [`candidate_did`] / [`candidate_did_route`]): it resolves
    /// instead to [`REGISTRY_DID`], served at `/.well-known/did.json`.
    path: &'static str,
    /// The producer's Ed25519 signing-key seed for that path.
    seed: [u8; 32],
    title: &'static str,
    metadata: serde_json::Value,
}

/// DID a `candidate.path` publishes under: the empty path is the
/// registry's own bare DID ([`REGISTRY_DID`], no path component) — used
/// by the §6/§8 registry-attested-discovery tests, which need a
/// candidate published under the registry's own identity rather than
/// under `did:web:localhost:<path>`.
fn candidate_did(path: &str) -> String {
    if path.is_empty() {
        REGISTRY_DID.to_string()
    } else {
        format!("did:web:localhost:{path}")
    }
}

/// The DID-document route path for `candidate_did(path)`: the bare
/// registry DID resolves at the well-known path; every other candidate
/// at its own path segment.
fn candidate_did_route(path: &str) -> String {
    if path.is_empty() {
        "/.well-known/did.json".to_string()
    } else {
        format!("/{path}/did.json")
    }
}

/// Shared harness for the `find_revocations` / `find_registry_attested_revocations`
/// query-scope tests (extracted so the six cases below don't each clone
/// the ~130-line registry + DID + search setup
/// `find_revocations_returns_only_verified` uses inline).
///
/// Publishes every `candidate` as a genuine, real-hash, real-signature
/// `key-revocation` body — so §5 verification is the thing under test,
/// never a shortcut in the fixture — serves every distinct producer
/// path's DID document, and synthesizes a search response, as if
/// returned for a search scoped to `search_agent_id`, listing ALL of
/// them regardless of which producer they were actually published
/// under. That mismatch is deliberate: it is exactly the "trust
/// `resp.matches`" hole filter 1 of `find_revocations` closes. Returns
/// a client + resolver wired against the harness.
async fn discover_with_candidates(
    search_agent_id: &str,
    candidates: &[Candidate],
) -> (
    RegistryClient,
    WebResolver,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Distinct producer identities among the candidates — same path
    // MUST mean same seed here (single-producer contexts multi-published
    // under it), so a DID document route is registered exactly once per
    // path (axum panics on a duplicate route registration).
    let mut producers: HashMap<&str, [u8; 32]> = HashMap::new();
    for c in candidates {
        match producers.insert(c.path, c.seed) {
            Some(prior) if prior != c.seed => panic!(
                "candidate path '{}' reused with a different signing seed",
                c.path
            ),
            _ => {}
        }
    }

    // DID-hosting-only router first: publish-time verification (inside
    // `publish_verified`) needs every candidate producer's document to
    // resolve.
    let mut did_router = Router::new();
    for (&path, seed) in &producers {
        let pub_key = SigningKey::from_bytes(seed).verifying_key_bytes();
        let doc = ed25519_did_doc(&candidate_did(path), "key-1", &pub_key);
        did_router = did_router.route(
            &candidate_did_route(path),
            get(move || {
                let doc = doc.clone();
                async move { Json(doc) }
            }),
        );
    }
    let tls_did = TlsTestServer::start(did_router).await;
    let publish_resolver =
        WebResolver::with_test_endpoint(&tls_did.root_cert_pem, "localhost", tls_did.addr)
            .expect("pinned resolver");

    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY).expect("server");

    let mut matches = Vec::new();
    let mut contexts: HashMap<String, serde_json::Value> = HashMap::new();
    // Each candidate here is an independent fresh v1 (no `supersedes`),
    // so its own lineage always contains exactly itself — this is not
    // the Phase 3 lineage-walking behavior under test (that lives in
    // `lineage_walk_recovers_search_blind_member` and the
    // `LineageServerHarness` tests); it exists purely so `find_revocations`
    // / `find_registry_attested_revocations`'s own (now unconditional)
    // lineage walk has a real `/lineages/{id}` route to call instead of
    // 404ing.
    let mut lineages: HashMap<String, serde_json::Value> = HashMap::new();
    for c in candidates {
        let producer_did = candidate_did(c.path);
        let producer = Producer::new(
            SigningKey::from_bytes(&c.seed),
            AgentDid::new(&producer_did),
            format!("{producer_did}#key-1"),
        );
        let req = producer
            .publish_request()
            .acdp_version("0.3.0")
            .title(c.title)
            .context_type(ContextType::KeyRevocation)
            .visibility(Visibility::Public)
            .metadata(c.metadata.clone())
            .build()
            .expect("build");
        let resp = server
            .publish_verified(&req, None, &publish_resolver)
            .await
            .expect("publish");
        let full = server
            .store()
            .get(&resp.ctx_id)
            .expect("get")
            .expect("present");
        matches.push(json!({
            "ctx_id": full.body.ctx_id.as_str(),
            "lineage_id": full.body.lineage_id.as_str(),
            // Deliberately the *queried* agent_id, not the body's own —
            // simulating a registry search response that names a
            // context under whatever scope it was asked about,
            // independent of what the retrieved body actually says.
            "agent_id": search_agent_id,
            "title": full.body.title,
            "type": "key-revocation",
            "created_at": "2026-05-02T08:00:00.000Z",
            "status": "active",
            "visibility": "public",
        }));
        contexts.insert(
            full.body.ctx_id.as_str().to_string(),
            serde_json::to_value(&full).unwrap(),
        );
        lineages.insert(
            full.body.lineage_id.as_str().to_string(),
            json!([serde_json::to_value(&full).unwrap()]),
        );
    }

    // Paginate the synthesized search response one match per page (via
    // an index-encoded `cursor`) rather than returning everything in
    // one shot — so a candidate list of 2+ actually exercises
    // `find_revocations` / `find_registry_attested_revocations`'s
    // cursor-following loop, not just its single-page path.
    const PAGE_SIZE: usize = 1;
    let matches = Arc::new(matches);
    let contexts = Arc::new(contexts);
    let lineages = Arc::new(lineages);
    let caps_hits = Arc::new(AtomicUsize::new(0));

    let mut full_router = Router::new()
        .route(
            "/contexts/search",
            get({
                let matches = matches.clone();
                move |axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>| {
                    let matches = matches.clone();
                    async move {
                        let offset: usize =
                            q.get("cursor").and_then(|c| c.parse().ok()).unwrap_or(0);
                        let end = (offset + PAGE_SIZE).min(matches.len());
                        let page: Vec<serde_json::Value> = matches
                            .get(offset..end)
                            .map(<[_]>::to_vec)
                            .unwrap_or_default();
                        let mut body = serde_json::Map::new();
                        body.insert("matches".to_string(), json!(page));
                        if end < matches.len() {
                            body.insert("next_cursor".to_string(), json!(end.to_string()));
                        }
                        Json(serde_json::Value::Object(body))
                    }
                }
            }),
        )
        .route(
            "/contexts/{id}",
            get({
                let contexts = contexts.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let contexts = contexts.clone();
                    async move { Json(contexts.get(&id).cloned().expect("known ctx_id")) }
                }
            }),
        )
        .route(
            "/lineages/{id}",
            get({
                let lineages = lineages.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let lineages = lineages.clone();
                    async move { Json(lineages.get(&id).cloned().unwrap_or(json!([]))) }
                }
            }),
        )
        // `find_registry_attested_revocations` fetches this exactly
        // once before the search loop, regardless of how many search
        // pages the loop below ends up following — `caps_hits` is how
        // callers assert that.
        .route(
            "/.well-known/acdp.json",
            get({
                let caps_hits = caps_hits.clone();
                move || {
                    let caps_hits = caps_hits.clone();
                    async move {
                        caps_hits.fetch_add(1, Ordering::SeqCst);
                        Json(caps())
                    }
                }
            }),
        );
    for (&path, seed) in &producers {
        let pub_key = SigningKey::from_bytes(seed).verifying_key_bytes();
        let doc = ed25519_did_doc(&candidate_did(path), "key-1", &pub_key);
        full_router = full_router.route(
            &candidate_did_route(path),
            get(move || {
                let doc = doc.clone();
                async move { Json(doc) }
            }),
        );
    }

    let tls = TlsTestServer::start(full_router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    (client, resolver, caps_hits)
}

/// Case A (issue #191): a producer publishes `agent_id` = itself but
/// `metadata.revoked_key_controller` naming a DIFFERENT DID — a
/// self-claimed "registry attestation" that §5 body verification
/// accepts today, since nothing in §5 checks who the publisher claims
/// to be attesting for. Alongside it, publish a genuine
/// producer-signed revocation. `find_revocations` MUST return only the
/// latter: the trust-class filter drops the forged `RegistryAttested`
/// entry even though its `publisher == agent_id` and it verifies.
#[tokio::test]
async fn find_revocations_drops_self_claimed_registry_attestation() {
    use acdp::client::find_revocations;

    let candidates = [
        Candidate {
            path: "agent",
            seed: [7u8; 32],
            title: "legitimate producer-signed revocation",
            metadata: revocation_metadata(),
        },
        Candidate {
            path: "agent",
            seed: [7u8; 32],
            title: "forged self-claimed registry attestation",
            metadata: json!({
                "revoked_key_fingerprint": K2_FP,
                "compromised_since": T,
                // Present and DIFFERENT from agent_id (both bodies
                // publish under LOCAL_PRODUCER_DID) — this is exactly
                // what `KeyRevocation::from_body` classifies as
                // RegistryAttested (RFC-ACDP-0014 §5 rule 3 / §6),
                // even though the publisher is a plain producer with
                // no registry standing at all.
                "revoked_key_controller": "did:web:localhost:victim-agent",
            }),
        },
    ];
    let (client, resolver, _caps_hits) =
        discover_with_candidates(LOCAL_PRODUCER_DID, &candidates).await;

    let revs = find_revocations(&client, &resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
        .await
        .expect("discovery");
    assert_eq!(
        revs.len(),
        1,
        "both candidates verify per §5 and both name agent_id == \
         LOCAL_PRODUCER_DID, but the forged RegistryAttested one MUST \
         be dropped by the trust-class filter — 1 result, not 2"
    );
    assert_eq!(revs[0].revoked_key_fingerprint, K1_FP);
    assert_eq!(revs[0].trust_class, RevocationTrustClass::ProducerSigned);
    assert_eq!(revs[0].publisher.as_str(), LOCAL_PRODUCER_DID);
}

/// Case B (issue #191, the larger unreported hole): a body genuinely
/// published — and signed — under a SECOND producer's DID
/// (`OTHER_PRODUCER_DID`) is listed in a search response scoped to
/// `LOCAL_PRODUCER_DID`, as if the registry ignored its own `agent_id`
/// filter (or was actively hostile). The body verifies per §5 — its
/// own signature is genuine — but
/// `find_revocations(.., LOCAL_PRODUCER_DID)` MUST NOT return it: the
/// publisher-scope filter catches the misattribution that trusting
/// `resp.matches` alone cannot rule out.
#[tokio::test]
async fn find_revocations_drops_cross_producer_substitution() {
    use acdp::client::find_revocations;

    let other_path = OTHER_PRODUCER_DID
        .strip_prefix("did:web:localhost:")
        .expect("OTHER_PRODUCER_DID is a did:web:localhost:<path> DID");
    let candidates = [
        Candidate {
            path: "agent",
            seed: [7u8; 32],
            title: "P's own legitimate revocation",
            metadata: revocation_metadata(),
        },
        Candidate {
            path: other_path,
            seed: [9u8; 32],
            title: "Q's own revocation, falsely listed under P's search",
            metadata: json!({
                "revoked_key_fingerprint": K2_FP,
                "compromised_since": T,
            }),
        },
    ];
    let (client, resolver, _caps_hits) =
        discover_with_candidates(LOCAL_PRODUCER_DID, &candidates).await;

    let revs = find_revocations(&client, &resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
        .await
        .expect("discovery");
    assert_eq!(
        revs.len(),
        1,
        "Q's genuinely-signed, genuinely-verifying revocation was \
         listed under P's search scope but published under a different \
         DID — the publisher-scope filter must drop it: 1 result, not 2"
    );
    assert_eq!(revs[0].revoked_key_fingerprint, K1_FP);
    assert_eq!(revs[0].publisher.as_str(), LOCAL_PRODUCER_DID);
}

/// Case C (issue #191 AC 4): the documented, intended false-negative.
/// `agent_id` is matched by exact bytes, not normalized — passing a
/// case-variant of the DID a body actually published under drops every
/// candidate and yields `Ok(vec![])`, indistinguishable from "no
/// revocations." Pinned deliberately, per the exact-byte-match caveat
/// in `find_revocations`'s doc, so this stays intended behaviour rather
/// than an accident nobody notices regressing.
#[tokio::test]
async fn find_revocations_case_variant_agent_id_is_a_false_negative_by_design() {
    use acdp::client::find_revocations;

    let candidates = [Candidate {
        path: "agent",
        seed: [7u8; 32],
        title: "legitimate producer-signed revocation",
        metadata: revocation_metadata(),
    }];
    let (client, resolver, _caps_hits) =
        discover_with_candidates(LOCAL_PRODUCER_DID, &candidates).await;

    // Same DID, method-specific id differs only in case — schema-valid
    // per `AgentDid::parse` (only the DID *method* is case-folded), and
    // unequal to `LOCAL_PRODUCER_DID` under derived `PartialEq`.
    let case_variant = LOCAL_PRODUCER_DID.replace("agent", "Agent");
    assert_ne!(case_variant, LOCAL_PRODUCER_DID);
    AgentDid::parse(&case_variant).expect("case-variant DID is still schema-valid");

    let revs = find_revocations(&client, &resolver, &AgentDid::new(&case_variant))
        .await
        .expect("a schema-valid DID must not error, even though it matches nothing");
    assert_eq!(
        revs,
        Vec::new(),
        "case-variant agent_id must silently yield no results — the \
         exact-byte-match contract, not a bug"
    );

    // Sanity: the exact byte value DOES find the revocation, so the
    // empty result above is provably the case-sensitivity filter, not
    // some other harness mistake.
    let revs = find_revocations(&client, &resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
        .await
        .expect("discovery");
    assert_eq!(revs.len(), 1);
}

// ── Phase 5 (#191 G1 fix): `find_registry_attested_revocations` ─────────────
//
// `find_revocations`'s trust-class filter (Phase 4) deliberately drops
// every `RegistryAttested` candidate — including a genuine RFC-ACDP-0014
// §6 attestation published under the registry's own DID. That is
// correct for `find_revocations` (a producer-scoped query structurally
// cannot vouch for a registry-scoped claim), but it means the doc
// instruction that used to read "search the registry's own `agent_id`
// and match `revoked_key_controller` client-side" needs a real function
// behind it — this is that function, and the tests below are the
// round-trip proof that the gap Phase 4 opened is closed again.

/// A genuine §6 registry-attested revocation: published under
/// [`REGISTRY_DID`] itself (`candidate.path == ""`), naming
/// [`LOCAL_PRODUCER_DID`] as `revoked_key_controller` — the shape
/// `KeyRevocation::from_body` classifies as
/// [`RevocationTrustClass::RegistryAttested`] since `revoked_key_controller`
/// is present and differs from `agent_id`.
fn registry_attested_candidate() -> Candidate {
    Candidate {
        path: "",
        seed: [0x11u8; 32],
        title: "registry-attested revocation of the producer's key",
        metadata: json!({
            "revoked_key_fingerprint": K2_FP,
            "compromised_since": T,
            "revoked_key_controller": LOCAL_PRODUCER_DID,
        }),
    }
}

/// `find_registry_attested_revocations` returns every genuine §6
/// attestation: published under the registry's own DID, naming the
/// queried controller, and passing the registry-binding check against
/// the live capabilities document and serving authority.
///
/// Two attestations (not one) are published here — the harness pages
/// its synthesized search response one match per page, so with two
/// matches this actually drives the function's cursor-following loop
/// across a real `next_cursor`, rather than only ever taking the
/// single-page path. That is also what makes the `caps_hits` assertion
/// below meaningful: it pins the plan's "exactly one capabilities
/// fetch regardless of page count" acceptance criterion against a call
/// that genuinely spans more than one page.
#[tokio::test]
async fn find_registry_attested_revocations_returns_genuine_attestation() {
    use acdp::client::find_registry_attested_revocations;

    let second = Candidate {
        path: "",
        seed: [0x11u8; 32],
        title: "a second registry-attested revocation of the producer's key",
        metadata: json!({
            "revoked_key_fingerprint": K1_FP,
            "compromised_since": T,
            "revoked_key_controller": LOCAL_PRODUCER_DID,
        }),
    };
    let candidates = [registry_attested_candidate(), second];
    let (client, resolver, caps_hits) = discover_with_candidates(REGISTRY_DID, &candidates).await;

    let mut revs =
        find_registry_attested_revocations(&client, &resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
            .await
            .expect("discovery");
    assert_eq!(revs.len(), 2, "both genuine §6 attestations must be found");
    revs.sort_by(|a, b| a.revoked_key_fingerprint.cmp(&b.revoked_key_fingerprint));
    assert_eq!(revs[0].revoked_key_fingerprint, K1_FP);
    assert_eq!(revs[1].revoked_key_fingerprint, K2_FP);
    for rev in &revs {
        assert_eq!(rev.publisher.as_str(), REGISTRY_DID);
        assert_eq!(rev.revoked_key_controller.as_str(), LOCAL_PRODUCER_DID);
        assert_eq!(rev.trust_class, RevocationTrustClass::RegistryAttested);
    }
    assert_eq!(
        caps_hits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "capabilities() must be fetched exactly once regardless of how many \
         search pages the two-match, one-per-page response above required"
    );
}

/// **The G1 regression guard.** Before Phase 5, `RevocationPolicy`'s
/// doc (and `find_revocations`'s own closing sentence) told a caller to
/// obtain a §6 registry attestation by calling
/// `find_revocations(client, resolver, &registry_did)`: `publisher ==
/// registry_did == agent_id` passes the query-scope filter, then the
/// trust-class filter silently drops it — `Ok(vec![])`, indistinguishable
/// from "no revocations." This test pins both halves of the round trip:
/// `find_revocations` queried with the registry's own DID still finds
/// nothing (proving the hole Phase 4 opened stays closed off from that
/// path), and `find_registry_attested_revocations` finds the very same
/// registry-published attestation (proving the doc's replacement
/// instruction is actually true).
#[tokio::test]
async fn find_registry_attested_revocations_recovers_what_find_revocations_now_drops() {
    use acdp::client::{find_registry_attested_revocations, find_revocations};

    let candidates = [registry_attested_candidate()];
    let (client, resolver, _caps_hits) = discover_with_candidates(REGISTRY_DID, &candidates).await;

    // The old (now-corrected) doc instruction: query `find_revocations`
    // with the registry's own DID. It verifies per §5 (genuine
    // signature) and passes the publisher-scope filter (`publisher ==
    // agent_id == registry_did`) — but the trust-class filter (§6
    // `RegistryAttested`) drops it. This is Phase 4's intended
    // behavior for `find_revocations` specifically, not a bug — the
    // point of this test is that the *replacement* function recovers
    // it.
    let dropped = find_revocations(&client, &resolver, &AgentDid::new(REGISTRY_DID))
        .await
        .expect("discovery");
    assert_eq!(
        dropped,
        Vec::new(),
        "find_revocations correctly excludes RegistryAttested entries even when \
         queried with the registry's own DID"
    );

    // The corrected instruction: `find_registry_attested_revocations`
    // finds the very same attestation.
    let recovered =
        find_registry_attested_revocations(&client, &resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
            .await
            .expect("discovery");
    assert_eq!(
        recovered.len(),
        1,
        "the registry-attested revocation find_revocations dropped MUST be \
         reachable through find_registry_attested_revocations — this is the \
         G1 fix"
    );
    assert_eq!(recovered[0].revoked_key_fingerprint, K2_FP);
    assert_eq!(
        recovered[0].trust_class,
        RevocationTrustClass::RegistryAttested
    );
}

/// `find_registry_attested_revocations` propagates a `capabilities()`
/// failure rather than swallowing it into an empty vec. Simulated here
/// by a registry that serves no `/.well-known/acdp.json` at all (a
/// stand-in for any capabilities failure mode — malformed document,
/// non-`did:web` `registry_did`, transport error, ...): the point under
/// test is only that the finder's `?` on `client.capabilities()`
/// actually propagates, not any specific failure shape.
#[tokio::test]
async fn find_registry_attested_revocations_propagates_capabilities_error() {
    use acdp::client::find_registry_attested_revocations;

    let router = Router::new(); // no `/.well-known/acdp.json` route
    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    let result =
        find_registry_attested_revocations(&client, &resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
            .await;
    assert!(
        result.is_err(),
        "a registry that can't even serve capabilities must surface an error, \
         not look like an honest \"no revocations\" empty vec"
    );
}

/// Issue #226 Phase 5, N2 — `find_registry_attested_revocations` gets
/// its own page-cap-exhaustion regression, mirroring
/// `find_revocations_errors_on_page_cap_exhaustion_with_cursor_remaining`
/// exactly: before this test, the retracted seed pass, the page-cap
/// error, and the walk-cap error were duplicated verbatim from
/// `find_revocations` into this function's implementation but
/// exercised by nothing. A registry that never stops offering a
/// `next_cursor` must abort with `AcdpError::SearchTruncated` rather
/// than return whatever it collected across `MAX_SEARCH_PAGES` pages.
#[tokio::test]
async fn find_registry_attested_revocations_errors_on_page_cap_exhaustion_with_cursor_remaining() {
    use acdp::client::find_registry_attested_revocations;
    use std::collections::HashMap;

    let router = Router::new()
        .route(
            "/.well-known/acdp.json",
            get(move || {
                let c = caps();
                async move { Json(c) }
            }),
        )
        .route(
            "/contexts/search",
            get(
                |_: axum::extract::Query<HashMap<String, String>>| async move {
                    // Empty matches, but a cursor that never runs out —
                    // a hostile (or pathologically paginated) registry
                    // holding the caller in an endless cursor loop.
                    Json(json!({"matches": [], "next_cursor": "stuck"}))
                },
            ),
        );
    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    let err =
        find_registry_attested_revocations(&client, &resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
            .await
            .expect_err("page-cap exhaustion with a cursor remaining must be a hard error");
    assert!(
        matches!(err, AcdpError::SearchTruncated(_)),
        "expected SearchTruncated, got {err:?}"
    );
}

// ── Phase 3 (#226 part 1): lineage-walking revocation discovery ────────────
//
// `find_revocations` / `find_registry_attested_revocations`'s own search
// passes cannot see a lineage member a search pass is structurally blind
// to (or has been made blind to by a hostile/eventually-consistent
// registry). RFC-ACDP-0013 §8.1 obliges `GET /lineages/{id}` to include
// every member, so walking the lineage id any visible member names
// recovers it. The tests below pin that the walk is actually wired in
// (test A, the falsifiability-probe target), that it works end-to-end
// against a genuine `RegistryServer` lineage endpoint (test B), and that
// a member failing §5 verification is dropped rather than erroring
// (test C).

use acdp::client::find_revocations_in_lineage;
use acdp::types::body::FullContext;
use acdp::types::search::SearchResult;
use acdp::types::{CapabilitiesDocument, Status};

/// Build a genuine, verifiable `key-revocation` `Body` without a live
/// registry: `Producer::publish_request` / `supersede_body` compute the
/// real hash + signature, and `Body::from_publish_request` assigns
/// whatever `ctx_id` / `lineage_id` the test wants — the registry-
/// assigned identity fields sit outside `content_hash` coverage
/// (RFC-ACDP-0001 §5.7), so choosing them by hand here does not affect
/// verification.
fn revocation_body(
    producer: &Producer,
    metadata: serde_json::Value,
    ctx_id: &str,
    lineage_id: &LineageId,
    supersedes: Option<&Body>,
    created_at: DateTime<Utc>,
) -> Body {
    let builder = match supersedes {
        Some(prev) => producer.supersede_body(prev),
        None => producer.publish_request(),
    };
    let req = builder
        .acdp_version("0.3.0")
        .title("lineage-walk test revocation")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(metadata)
        .build()
        .expect("build");
    Body::from_publish_request(
        &req,
        CtxId::parse(ctx_id).expect("valid ctx_id"),
        lineage_id.clone(),
        REGISTRY_AUTHORITY,
        created_at,
    )
}

/// Wrap a `Body` in the minimal `FullContext` envelope `client.lineage`
/// deserializes into — status is irrelevant to the walk (it verifies
/// every member regardless of `registry_state.status`), so a plain
/// `Active` is fine everywhere it's used below.
fn full_context(body: Body) -> FullContext {
    FullContext {
        body,
        registry_state: acdp::types::body::RegistryState {
            status: Status::Active,
            lifecycle_events: None,
            extensions: Default::default(),
        },
        registry_receipt: None,
        lineage_head_receipt: None,
        log_inclusion: None,
        extensions: Default::default(),
    }
}

/// A `match_summary`-shaped search result naming `ctx_id`/`lineage_id`
/// for the hand-built search mock below.
fn search_result(
    ctx_id: &str,
    lineage_id: &LineageId,
    agent_id: &str,
    created_at: &str,
) -> SearchResult {
    SearchResult {
        ctx_id: CtxId::parse(ctx_id).expect("valid ctx_id"),
        lineage_id: lineage_id.clone(),
        agent_id: AgentDid::new(agent_id),
        title: "lineage-walk test revocation".into(),
        summary: None,
        context_type: ContextType::KeyRevocation,
        domain: None,
        created_at: at(created_at),
        status: Status::Active,
        visibility: Some(Visibility::Public),
    }
}

fn lineage_p() -> LineageId {
    LineageId::parse(format!("lin:sha256:{}", "1".repeat(64))).unwrap()
}
fn lineage_r() -> LineageId {
    LineageId::parse(format!("lin:sha256:{}", "2".repeat(64))).unwrap()
}

/// **Test A — criterion 6's falsifiability probe target.** A hand-built
/// mock whose `/contexts/search` never lists R1 (of either lineage), on
/// any page, while `/lineages/{id}` (also hand-built) includes it —
/// search is structurally blind to R1; only the lineage walk can find
/// it. Both `find_revocations` (producer-scoped, a did:key identity —
/// no DID hosting needed) and `find_registry_attested_revocations`
/// (registry-scoped, a did:web identity hosted at
/// `/.well-known/did.json`) are exercised against ONE combined mock, so
/// this single test pins the walk for both wired call sites.
#[tokio::test]
async fn lineage_walk_recovers_search_blind_member() {
    use acdp::client::{find_registry_attested_revocations, find_revocations};
    use std::collections::HashMap;

    let producer = Producer::new_did_key(SigningKey::from_bytes(&[0x21u8; 32]));
    let registry_seed = [0x33u8; 32];
    let registry_pub = SigningKey::from_bytes(&registry_seed).verifying_key_bytes();
    let registry = Producer::new(
        SigningKey::from_bytes(&registry_seed),
        AgentDid::new(REGISTRY_DID),
        format!("{REGISTRY_DID}#key-1"),
    );
    let controller = "did:web:localhost:some-affected-producer";

    // R1/R2: producer-signed, same lineage, R2 supersedes R1.
    let r1_p = revocation_body(
        &producer,
        json!({"revoked_key_fingerprint": K1_FP, "compromised_since": "2026-04-01T00:00:00.000Z"}),
        "acdp://localhost/00000000-0000-4000-8000-000000000001",
        &lineage_p(),
        None,
        at("2026-04-02T00:00:00.000Z"),
    );
    let producer_did = r1_p.agent_id.as_str().to_string();
    let r2_p = revocation_body(
        &producer,
        json!({"revoked_key_fingerprint": K1_FP, "compromised_since": "2026-05-01T00:00:00.000Z"}),
        "acdp://localhost/00000000-0000-4000-8000-000000000002",
        &lineage_p(),
        Some(&r1_p),
        at("2026-05-02T00:00:00.000Z"),
    );

    // R1'/R2': registry-attested, same (different) lineage, R2'
    // supersedes R1'.
    let r1_r = revocation_body(
        &registry,
        json!({
            "revoked_key_fingerprint": K2_FP,
            "compromised_since": "2026-04-03T00:00:00.000Z",
            "revoked_key_controller": controller,
        }),
        "acdp://localhost/00000000-0000-4000-8000-000000000003",
        &lineage_r(),
        None,
        at("2026-04-04T00:00:00.000Z"),
    );
    let r2_r = revocation_body(
        &registry,
        json!({
            "revoked_key_fingerprint": K2_FP,
            "compromised_since": "2026-05-03T00:00:00.000Z",
            "revoked_key_controller": controller,
        }),
        "acdp://localhost/00000000-0000-4000-8000-000000000004",
        &lineage_r(),
        Some(&r1_r),
        at("2026-05-04T00:00:00.000Z"),
    );

    // The search mock: ONLY R2/R2' ever appear, on every page. R1/R1'
    // are named exclusively by `/lineages/{id}`.
    let search_response = json!({
        "matches": [
            search_result(r2_p.ctx_id.as_str(), &lineage_p(), &producer_did, "2026-05-02T00:00:00.000Z"),
            search_result(r2_r.ctx_id.as_str(), &lineage_r(), REGISTRY_DID, "2026-05-04T00:00:00.000Z"),
        ],
    });
    let mut contexts: HashMap<String, serde_json::Value> = HashMap::new();
    contexts.insert(
        r2_p.ctx_id.as_str().to_string(),
        serde_json::to_value(full_context(r2_p.clone())).unwrap(),
    );
    contexts.insert(
        r2_r.ctx_id.as_str().to_string(),
        serde_json::to_value(full_context(r2_r.clone())).unwrap(),
    );
    let mut lineages: HashMap<String, serde_json::Value> = HashMap::new();
    lineages.insert(
        lineage_p().as_str().to_string(),
        serde_json::to_value(vec![full_context(r1_p.clone()), full_context(r2_p.clone())]).unwrap(),
    );
    lineages.insert(
        lineage_r().as_str().to_string(),
        serde_json::to_value(vec![full_context(r1_r.clone()), full_context(r2_r.clone())]).unwrap(),
    );
    let contexts = Arc::new(contexts);
    let lineages = Arc::new(lineages);

    let registry_doc = ed25519_did_doc(REGISTRY_DID, "key-1", &registry_pub);
    let router = Router::new()
        .route(
            "/.well-known/did.json",
            get(move || {
                let doc = registry_doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/.well-known/acdp.json",
            get(move || {
                let c = caps();
                async move { Json(c) }
            }),
        )
        .route(
            "/contexts/search",
            get(move |_: axum::extract::Query<HashMap<String, String>>| {
                let resp = search_response.clone();
                async move { Json(resp) }
            }),
        )
        .route(
            "/contexts/{id}",
            get({
                let contexts = contexts.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let contexts = contexts.clone();
                    async move { Json(contexts.get(&id).cloned().expect("known ctx_id")) }
                }
            }),
        )
        .route(
            "/lineages/{id}",
            get({
                let lineages = lineages.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let lineages = lineages.clone();
                    async move { Json(lineages.get(&id).cloned().unwrap_or(json!([]))) }
                }
            }),
        );

    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    // `find_revocations`: search alone would only ever see R2 (the
    // fingerprint asserted below on the early-boundary member is the
    // walk's, not search's, contribution).
    let mut producer_revs = find_revocations(&client, &resolver, &AgentDid::new(&producer_did))
        .await
        .expect("producer-scoped discovery");
    assert_eq!(
        producer_revs.len(),
        2,
        "search alone finds only R2 — the walk must add R1"
    );
    producer_revs.sort_by_key(|r| r.compromised_since);
    assert_eq!(
        producer_revs[0].compromised_since,
        at("2026-04-01T00:00:00.000Z"),
        "R1's early boundary must be present — it is invisible to search entirely"
    );
    assert_eq!(
        producer_revs[1].compromised_since,
        at("2026-05-01T00:00:00.000Z")
    );
    for r in &producer_revs {
        assert_eq!(r.revoked_key_fingerprint, K1_FP);
        assert_eq!(r.trust_class, RevocationTrustClass::ProducerSigned);
    }

    // `find_registry_attested_revocations`: same story, the registry-
    // attested lineage.
    let mut registry_revs =
        find_registry_attested_revocations(&client, &resolver, &AgentDid::new(controller))
            .await
            .expect("registry-scoped discovery");
    assert_eq!(
        registry_revs.len(),
        2,
        "search alone finds only R2' — the walk must add R1'"
    );
    registry_revs.sort_by_key(|r| r.compromised_since);
    assert_eq!(
        registry_revs[0].compromised_since,
        at("2026-04-03T00:00:00.000Z"),
        "R1's early boundary must be present — it is invisible to search entirely"
    );
    assert_eq!(
        registry_revs[1].compromised_since,
        at("2026-05-03T00:00:00.000Z")
    );
    for r in &registry_revs {
        assert_eq!(r.revoked_key_fingerprint, K2_FP);
        assert_eq!(r.trust_class, RevocationTrustClass::RegistryAttested);
        assert_eq!(r.revoked_key_controller.as_str(), controller);
    }
}

/// **GAP-A regression.** A search match names ctx_id `X` under
/// `lineage_p()`, but `/lineages/{id}` for that same lineage_id serves a
/// DIFFERENT member `Y` that does not include `X` at all — the registry
/// answered the lineage-walk request, but not with the lineage the
/// search match actually pointed at. The walk must reject this
/// (`AcdpError::IncompleteLineage`, checked against the pre-verification
/// member list) — and, per the Phase 3 round-2 fix, that rejection must
/// abort the whole `find_revocations` call rather than being scoped to
/// this one lineage: a partial result is indistinguishable from a
/// complete one to the caller, and silently incorporating `X` alone
/// (dropping the mismatched lineage) would be exactly the "quietly
/// shrink a compromise window" outcome RFC-ACDP-0014 §4 forbids.
#[tokio::test]
async fn lineage_walk_rejects_member_mismatch_by_aborting_the_whole_call() {
    use acdp::client::find_revocations;
    use std::collections::HashMap;

    let producer = Producer::new_did_key(SigningKey::from_bytes(&[0x66u8; 32]));

    // X: the genuine revocation the search match names.
    let x = revocation_body(
        &producer,
        json!({"revoked_key_fingerprint": K1_FP, "compromised_since": "2026-04-05T00:00:00.000Z"}),
        "acdp://localhost/00000000-0000-4000-8000-0000000000b1",
        &lineage_p(),
        None,
        at("2026-04-06T00:00:00.000Z"),
    );
    let producer_did = x.agent_id.as_str().to_string();

    // Y: a DIFFERENT, unrelated ctx_id served under X's lineage_id when
    // the lineage endpoint is queried — the registry is not honestly
    // answering for the lineage X's own search match named.
    let y = revocation_body(
        &producer,
        json!({"revoked_key_fingerprint": K2_FP, "compromised_since": "2026-04-07T00:00:00.000Z"}),
        "acdp://localhost/00000000-0000-4000-8000-0000000000b2",
        &lineage_p(),
        None,
        at("2026-04-08T00:00:00.000Z"),
    );

    let search_response = json!({
        "matches": [
            search_result(x.ctx_id.as_str(), &lineage_p(), &producer_did, "2026-04-06T00:00:00.000Z"),
        ],
    });
    let mut contexts: HashMap<String, serde_json::Value> = HashMap::new();
    contexts.insert(
        x.ctx_id.as_str().to_string(),
        serde_json::to_value(full_context(x.clone())).unwrap(),
    );
    let mut lineages: HashMap<String, serde_json::Value> = HashMap::new();
    // The lineage endpoint serves Y only — NOT X — under the same
    // lineage_id the search match named for X.
    lineages.insert(
        lineage_p().as_str().to_string(),
        serde_json::to_value(vec![full_context(y.clone())]).unwrap(),
    );
    let contexts = Arc::new(contexts);
    let lineages = Arc::new(lineages);

    let router = Router::new()
        .route(
            "/contexts/search",
            get(move |_: axum::extract::Query<HashMap<String, String>>| {
                let resp = search_response.clone();
                async move { Json(resp) }
            }),
        )
        .route(
            "/contexts/{id}",
            get({
                let contexts = contexts.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let contexts = contexts.clone();
                    async move { Json(contexts.get(&id).cloned().expect("known ctx_id")) }
                }
            }),
        )
        .route(
            "/lineages/{id}",
            get({
                let lineages = lineages.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let lineages = lineages.clone();
                    async move { Json(lineages.get(&id).cloned().unwrap_or(json!([]))) }
                }
            }),
        );

    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    let err = find_revocations(&client, &resolver, &AgentDid::new(&producer_did))
        .await
        .expect_err("a mismatched lineage walk must abort the whole call, not be dropped");
    assert!(
        matches!(err, AcdpError::IncompleteLineage { .. }),
        "expected IncompleteLineage, got {err:?}"
    );
}

/// **Empty-lineage fail-closed rule, untested until now.** A search
/// match names ctx_id `X` under `lineage_p()`, but `/lineages/{id}` for
/// that same `lineage_id` serves an empty array — the reference
/// registry's documented shape for an *unrecognized* `lineage_id`
/// (`crates/acdp-server/src/registry/store.rs`), never an honest answer
/// for a `lineage_id` a live search match just named. `walk_revocation_lineage`
/// must fail closed with `AcdpError::IncompleteLineage` on `members.is_empty()`,
/// and `find_revocations` must propagate that `Err` rather than treat it
/// as "nothing more to add."
#[tokio::test]
async fn find_revocations_fails_closed_on_empty_lineage_response() {
    use acdp::client::find_revocations;
    use std::collections::HashMap;

    let producer = Producer::new_did_key(SigningKey::from_bytes(&[0x77u8; 32]));

    let x = revocation_body(
        &producer,
        json!({"revoked_key_fingerprint": K1_FP, "compromised_since": "2026-04-05T00:00:00.000Z"}),
        "acdp://localhost/00000000-0000-4000-8000-0000000000c1",
        &lineage_p(),
        None,
        at("2026-04-06T00:00:00.000Z"),
    );
    let producer_did = x.agent_id.as_str().to_string();

    let search_response = json!({
        "matches": [
            search_result(x.ctx_id.as_str(), &lineage_p(), &producer_did, "2026-04-06T00:00:00.000Z"),
        ],
    });
    let mut contexts: HashMap<String, serde_json::Value> = HashMap::new();
    contexts.insert(
        x.ctx_id.as_str().to_string(),
        serde_json::to_value(full_context(x.clone())).unwrap(),
    );
    let contexts = Arc::new(contexts);
    // No entry for `lineage_p()` in the lineages map at all — the
    // `/lineages/{id}` route below falls back to `json!([])`, exactly
    // the "unrecognized lineage_id" shape this test is pinning.
    let lineages: Arc<HashMap<String, serde_json::Value>> = Arc::new(HashMap::new());

    let router = Router::new()
        .route(
            "/contexts/search",
            get(move |_: axum::extract::Query<HashMap<String, String>>| {
                let resp = search_response.clone();
                async move { Json(resp) }
            }),
        )
        .route(
            "/contexts/{id}",
            get({
                let contexts = contexts.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let contexts = contexts.clone();
                    async move { Json(contexts.get(&id).cloned().expect("known ctx_id")) }
                }
            }),
        )
        .route(
            "/lineages/{id}",
            get({
                let lineages = lineages.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let lineages = lineages.clone();
                    async move { Json(lineages.get(&id).cloned().unwrap_or(json!([]))) }
                }
            }),
        );

    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    let err = find_revocations(&client, &resolver, &AgentDid::new(&producer_did))
        .await
        .expect_err("an empty lineage response for a search-named lineage_id must fail closed");
    assert!(
        matches!(err, AcdpError::IncompleteLineage { .. }),
        "expected IncompleteLineage, got {err:?}"
    );
}

/// **`find_registry_attested_revocations`'s own walk-failure arm,
/// untested until now** — its `Err` arm is duplicated from
/// `find_revocations`'s, not shared, and its success-path scope filter
/// (controller + registry-binding, not publisher/trust-class) genuinely
/// differs, so this function needs its own regression rather than
/// relying on `find_revocations`'s. Mirrors the GAP-A mismatch shape
/// above: a search match names ctx_id `X` under `lineage_r()`, but
/// `/lineages/{id}` serves a different member `Y` that does not include
/// `X` — the walk must fail with `IncompleteLineage` and that failure
/// must abort the whole call.
#[tokio::test]
async fn find_registry_attested_revocations_fails_closed_on_lineage_mismatch() {
    use acdp::client::find_registry_attested_revocations;
    use std::collections::HashMap;

    let registry_seed = [0x88u8; 32];
    let registry_pub = SigningKey::from_bytes(&registry_seed).verifying_key_bytes();
    let registry = Producer::new(
        SigningKey::from_bytes(&registry_seed),
        AgentDid::new(REGISTRY_DID),
        format!("{REGISTRY_DID}#key-1"),
    );
    let controller = "did:web:localhost:some-other-affected-producer";

    // X: the genuine registry-attested revocation the search match names.
    let x = revocation_body(
        &registry,
        json!({
            "revoked_key_fingerprint": K2_FP,
            "compromised_since": "2026-04-05T00:00:00.000Z",
            "revoked_key_controller": controller,
        }),
        "acdp://localhost/00000000-0000-4000-8000-0000000000d1",
        &lineage_r(),
        None,
        at("2026-04-06T00:00:00.000Z"),
    );

    // Y: a DIFFERENT, unrelated ctx_id served under X's lineage_id when
    // the lineage endpoint is queried.
    let y = revocation_body(
        &registry,
        json!({
            "revoked_key_fingerprint": K2_FP,
            "compromised_since": "2026-04-07T00:00:00.000Z",
            "revoked_key_controller": controller,
        }),
        "acdp://localhost/00000000-0000-4000-8000-0000000000d2",
        &lineage_r(),
        None,
        at("2026-04-08T00:00:00.000Z"),
    );

    let search_response = json!({
        "matches": [
            search_result(x.ctx_id.as_str(), &lineage_r(), REGISTRY_DID, "2026-04-06T00:00:00.000Z"),
        ],
    });
    let mut contexts: HashMap<String, serde_json::Value> = HashMap::new();
    contexts.insert(
        x.ctx_id.as_str().to_string(),
        serde_json::to_value(full_context(x.clone())).unwrap(),
    );
    let mut lineages: HashMap<String, serde_json::Value> = HashMap::new();
    // The lineage endpoint serves Y only — NOT X — under the same
    // lineage_id the search match named for X.
    lineages.insert(
        lineage_r().as_str().to_string(),
        serde_json::to_value(vec![full_context(y.clone())]).unwrap(),
    );
    let contexts = Arc::new(contexts);
    let lineages = Arc::new(lineages);

    let registry_doc = ed25519_did_doc(REGISTRY_DID, "key-1", &registry_pub);
    let router = Router::new()
        .route(
            "/.well-known/did.json",
            get(move || {
                let doc = registry_doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/.well-known/acdp.json",
            get(move || {
                let c = caps();
                async move { Json(c) }
            }),
        )
        .route(
            "/contexts/search",
            get(move |_: axum::extract::Query<HashMap<String, String>>| {
                let resp = search_response.clone();
                async move { Json(resp) }
            }),
        )
        .route(
            "/contexts/{id}",
            get({
                let contexts = contexts.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let contexts = contexts.clone();
                    async move { Json(contexts.get(&id).cloned().expect("known ctx_id")) }
                }
            }),
        )
        .route(
            "/lineages/{id}",
            get({
                let lineages = lineages.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let lineages = lineages.clone();
                    async move { Json(lineages.get(&id).cloned().unwrap_or(json!([]))) }
                }
            }),
        );

    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    let err = find_registry_attested_revocations(&client, &resolver, &AgentDid::new(controller))
        .await
        .expect_err("a mismatched lineage walk must abort the whole call, not be dropped");
    assert!(
        matches!(err, AcdpError::IncompleteLineage { .. }),
        "expected IncompleteLineage, got {err:?}"
    );
}

/// `lifecycle_caps()` — mirrors `tests/lifecycle.rs:110-115`: idem-007
/// (`acdp_version` ≥ 0.3.0 requires `supports_idempotency_key: true`)
/// plus a TTL in the `86_400..=604_800` range `validate_capabilities`
/// hard-requires whenever idempotency is on
/// (`crates/acdp-validation/src/lib.rs:164-178`). Deliberately NOT the
/// shared `caps()` above (0.2.0, no TTL) — a partial flip of that one
/// fails `RegistryServer::try_new` outright.
fn lifecycle_caps() -> CapabilitiesDocument {
    use acdp::types::capabilities::Limits;
    CapabilitiesDocument {
        acdp_version: "0.3.0".into(),
        registry_did: REGISTRY_DID.into(),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into(), "did:key".into()],
        // `LineageServerHarness` also serves `/contexts/search`, which
        // requires `acdp-registry-discovery` (RFC-ACDP-0001-core.md
        // §545-551) — `acdp-registry-core` alone would be an inaccurate
        // profile claim for what this harness actually serves.
        profiles: vec![
            "acdp-registry-core".into(),
            "acdp-registry-discovery".into(),
        ],
        limits: Limits {
            max_payload_bytes: 1_048_576,
            max_embedded_bytes: 65_536,
            idempotency_key_ttl_seconds: Some(86_400),
            max_publish_per_minute: None,
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        supports_idempotency_key: true,
        extensions: Default::default(),
    }
}

/// A harness routing `/contexts/search`, `/contexts/{id}`, and
/// `/lineages/{id}` through a REAL `RegistryServer<InMemoryStore>` —
/// statuses, query filtering, and lineage membership are all genuine,
/// not hand-synthesized. Parameterized over the capabilities document
/// and a `lifecycle` flag (rather than hardcoding `caps()`/always
/// calling `with_lifecycle()`) so Phase 4/5 additions can reuse this
/// harness with lifecycle enabled without reopening this constructor.
///
/// **issue #248 Phase 3 — why this harness, extended, and not a
/// fourth type.** Phase 4's headline assertion needs, simultaneously:
/// a receipt-bearing target context (RFC-ACDP-0014 §7 fails closed
/// without a receipt-attested publish time), real `/contexts/search`
/// and `/lineages/{id}`, producer + registry DID hosting, an optional
/// `/.well-known/acdp.json` (`find_registry_attested_revocations`
/// fetches capabilities unconditionally), and injectable error
/// statuses / delays / hit counts. Neither pre-existing harness in
/// this file could do all of that:
///
/// - `Harness` (`start_harness`/`publish_with_receipt`, above) has DID
///   routes and a receipt signer, but its `/contexts/{id}` route
///   serves one static `Arc<RwLock<Option<Value>>>` blob regardless of
///   the requested id, has no `/contexts/search` or `/lineages/{id}`
///   route at all, and its `RegistryServer` is a throwaway created and
///   dropped inside `publish_with_receipt` — nothing persists across
///   calls.
/// - `LineageServerHarness` itself, pre-Phase-3, had a real persisted
///   `RegistryServer<InMemoryStore>` behind genuine search/retrieve/
///   lineage handlers, but no DID routes (its 3 existing tests use
///   `Producer::new_did_key`, resolved offline), no receipt signer, no
///   well-known routes, and no error/delay/hit-count injection — so
///   nothing verified through it could satisfy `ReceiptPolicy::Require`
///   and no test could simulate a registry that is failing or slow.
///
/// So it is extended in place rather than forked a third time: the
/// hard part (a real persisted registry with genuine status/query
/// projection) was already here. `LineageServerHarnessBuilder` below
/// adds DID hosting, an optional receipt signer, an optional
/// `/.well-known/acdp.json`, and a uniform per-route hit-counter /
/// error-injection / delay layer (`RouteState`) — while
/// `LineageServerHarness::start` (the two-arg constructor the 3
/// pre-Phase-3 tests call) keeps its exact prior signature and
/// behavior unchanged, as a thin call into the builder with every new
/// knob left off. Assertions about *what discovery finds* must still
/// run against this real server, never a hand-built mock — the mocks
/// elsewhere in this file hardcode `"status": "active"` on every
/// match regardless of reality (see `discover_with_candidates`),
/// which would make a search-only assertion pass spuriously.
///
/// If a *fifth* harness is ever tempted, read this comment first.
struct LineageServerHarness {
    tls: TlsTestServer,
    server: Arc<RegistryServer<InMemoryStore>>,
    resolver: WebResolver,
    /// Per-route hit-counter / error-injection / delay state, keyed by
    /// route name: `"search"`, `"context"`, `"lineage"`, `"current"`
    /// (`/lineages/{id}/current` — added for issue #248 Phase 4's
    /// `fetch_current_with_policy` coverage; `LineageServerHarness`
    /// pre-Phase-4 had no route for it at all) always present;
    /// `"registry_did"` and `"acdp_json"` present when the builder's
    /// corresponding `with_*` was called; a producer's own path string
    /// (e.g. `"agent"`) present once per
    /// [`LineageServerHarnessBuilder::with_producer_did`] /
    /// [`LineageServerHarnessBuilder::with_producer_did_document`] call.
    routes: std::collections::HashMap<String, Arc<RouteState>>,
}

/// One harness route's runtime-injectable behavior: a hit counter, an
/// optional HTTP status to return instead of normal handling, and an
/// optional delay applied before responding either way. Precedent for
/// each piece existed separately in this file before Phase 3 —
/// `caps_hits` (`:1761`, a hit counter) and `counting_router`
/// (`tests/verify_algorithm.rs:73`) — but nothing combined them or
/// added error injection (this file had no `StatusCode`/404/500/503
/// construct anywhere pre-Phase-3); this generalizes the idiom so
/// every route on the Phase-4-capable harness gets all three
/// uniformly.
#[derive(Default)]
struct RouteState {
    hits: std::sync::atomic::AtomicUsize,
    /// 0 = no injected error; otherwise a valid HTTP status code.
    error_status: std::sync::atomic::AtomicU16,
    /// 0 = no delay.
    delay_ms: std::sync::atomic::AtomicU64,
}

impl RouteState {
    /// Count this hit, apply any configured delay, then either produce
    /// an injected-error response (short-circuiting the caller, which
    /// must return it as-is) or signal "proceed normally" with `None`.
    async fn intercept(&self) -> Option<axum::response::Response> {
        use std::sync::atomic::Ordering;

        self.hits.fetch_add(1, Ordering::SeqCst);
        let delay_ms = self.delay_ms.load(Ordering::SeqCst);
        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        let status = self.error_status.load(Ordering::SeqCst);
        if status == 0 {
            return None;
        }
        let code = axum::http::StatusCode::from_u16(status)
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        // Wire code `internal_error` → `AcdpError::RegistryInternal`,
        // which `is_transient() == true` — a reasonable single choice
        // for "this route is currently failing" regardless of which
        // HTTP status a test injects; this harness does not attempt to
        // model every wire-code/status pairing, only "currently down."
        Some(
            (
                code,
                Json(json!({
                    "error": {
                        "code": "internal_error",
                        "message": "harness: injected test error"
                    }
                })),
            )
                .into_response(),
        )
    }
}

/// Builds a [`LineageServerHarness`]. Every capability beyond the base
/// search/retrieve/lineage trio is opt-in, so
/// `LineageServerHarness::start(caps, lifecycle)` — unchanged, still
/// called by the 3 pre-Phase-3 tests — is exactly
/// `LineageServerHarness::builder(caps).lifecycle(lifecycle).build()`.
struct LineageServerHarnessBuilder {
    caps: CapabilitiesDocument,
    lifecycle: bool,
    receipt_signer: Option<ReceiptSigner>,
    registry_did_doc: Option<serde_json::Value>,
    producer_dids: Vec<(String, serde_json::Value)>,
    well_known_acdp: bool,
}

/// Route names reserved by the harness itself — a producer path
/// registered via [`LineageServerHarnessBuilder::with_producer_did`]
/// must not collide with one of these in the shared `routes` map.
const RESERVED_ROUTE_NAMES: [&str; 6] = [
    "search",
    "context",
    "lineage",
    "current",
    "registry_did",
    "acdp_json",
];

impl LineageServerHarnessBuilder {
    fn new(caps: CapabilitiesDocument) -> Self {
        Self {
            caps,
            lifecycle: false,
            receipt_signer: None,
            registry_did_doc: None,
            producer_dids: Vec::new(),
            well_known_acdp: false,
        }
    }

    fn lifecycle(mut self, on: bool) -> Self {
        self.lifecycle = on;
        self
    }

    /// Mint a registry receipt for every subsequent verified publish
    /// (`server.publish_verified`/`publish_verified_did_key`), and host
    /// the registry's own `did:web:localhost` document at
    /// `/.well-known/did.json` (mirroring `start_harness`'s registry
    /// DID hosting) so `WebResolver` can resolve the receipt signing
    /// key. `key_fragment` becomes both the DID document's
    /// verification-method id and the receipt signer's `key_id`
    /// fragment. Required for AC3 — a context verified through the
    /// resulting harness satisfies `ReceiptPolicy::Require`.
    fn with_receipt_signer(mut self, signer_key: SigningKey, key_fragment: &str) -> Self {
        let pub_key = signer_key.verifying_key_bytes();
        self.registry_did_doc = Some(ed25519_did_doc(REGISTRY_DID, key_fragment, &pub_key));
        self.receipt_signer = Some(
            ReceiptSigner::new(
                signer_key,
                REGISTRY_DID,
                format!("{REGISTRY_DID}#{key_fragment}"),
            )
            .expect("receipt signer"),
        );
        self
    }

    /// Host a `did:web` producer document at `did:web:localhost:{path}`
    /// (served at `/{path}/did.json`, via the same `candidate_did` /
    /// `candidate_did_route` convention `discover_with_candidates`
    /// uses), so a did:web-signed context published through this
    /// harness resolves without any external network. Panics if `path`
    /// is empty, reserved, or registered twice.
    fn with_producer_did(mut self, path: &str, key_fragment: &str, pub_key: &[u8; 32]) -> Self {
        assert!(
            !path.is_empty(),
            "producer DID path must be non-empty (empty is reserved for the registry)"
        );
        assert!(
            !RESERVED_ROUTE_NAMES.contains(&path),
            "producer DID path '{path}' collides with a reserved harness route name"
        );
        assert!(
            self.producer_dids.iter().all(|(p, _)| p != path),
            "producer DID path '{path}' registered twice"
        );
        let did = candidate_did(path);
        self.producer_dids.push((
            path.to_string(),
            ed25519_did_doc(&did, key_fragment, pub_key),
        ));
        self
    }

    /// Like [`Self::with_producer_did`], but hosts a caller-supplied DID
    /// document instead of building a single-key one via
    /// [`ed25519_did_doc`] — added for issue #248 Phase 4's key-rotation
    /// tests, which need a producer with TWO independently-resolvable
    /// keys: one that signed the target context (later revoked), a
    /// different one that signs the revocation itself (RFC-ACDP-0014 §5
    /// step 2 forbids a key revoking itself, so `seed_revocations`
    /// against a single-key producer identity always fails
    /// `check_not_self_signed`). Panics under the same conditions as
    /// [`Self::with_producer_did`].
    fn with_producer_did_document(mut self, path: &str, doc: serde_json::Value) -> Self {
        assert!(
            !path.is_empty(),
            "producer DID path must be non-empty (empty is reserved for the registry)"
        );
        assert!(
            !RESERVED_ROUTE_NAMES.contains(&path),
            "producer DID path '{path}' collides with a reserved harness route name"
        );
        assert!(
            self.producer_dids.iter().all(|(p, _)| p != path),
            "producer DID path '{path}' registered twice"
        );
        self.producer_dids.push((path.to_string(), doc));
        self
    }

    /// Serve `server.capabilities()` at `/.well-known/acdp.json` —
    /// needed by `find_registry_attested_revocations`, which fetches
    /// capabilities unconditionally before its search loop.
    fn with_well_known_acdp(mut self) -> Self {
        self.well_known_acdp = true;
        self
    }

    async fn build(self) -> LineageServerHarness {
        use std::collections::HashMap;

        let mut server =
            RegistryServer::try_new(InMemoryStore::new(), self.caps, REGISTRY_AUTHORITY)
                .expect("server");
        if self.lifecycle {
            server = server.with_lifecycle().expect("lifecycle enabled");
        }
        if let Some(signer) = self.receipt_signer {
            server = server
                .with_receipt_signer(signer)
                .expect("receipt signer accepted");
        }
        let server = Arc::new(server);

        let mut routes: HashMap<String, Arc<RouteState>> = HashMap::new();
        routes.insert("search".into(), Arc::new(RouteState::default()));
        routes.insert("context".into(), Arc::new(RouteState::default()));
        routes.insert("lineage".into(), Arc::new(RouteState::default()));
        routes.insert("current".into(), Arc::new(RouteState::default()));

        let mut router = Router::new()
            .route(
                "/contexts/search",
                get({
                    let server = server.clone();
                    let state = routes["search"].clone();
                    move |axum::extract::Query(raw): axum::extract::Query<
                        HashMap<String, String>,
                    >| {
                        let server = server.clone();
                        let state = state.clone();
                        async move {
                            if let Some(resp) = state.intercept().await {
                                return resp;
                            }
                            let params = acdp::types::SearchParams {
                                q: raw.get("q").cloned(),
                                context_type: raw.get("type").cloned(),
                                domain: raw.get("domain").cloned(),
                                tags: raw.get("tags").cloned(),
                                agent_id: raw.get("agent_id").cloned(),
                                schema_uri: raw.get("schema_uri").cloned(),
                                derived_from: raw.get("derived_from").cloned(),
                                created_after: raw.get("created_after").cloned(),
                                created_before: raw.get("created_before").cloned(),
                                data_period_start_after: raw
                                    .get("data_period_start_after")
                                    .cloned(),
                                data_period_end_before: raw.get("data_period_end_before").cloned(),
                                expires_after: raw.get("expires_after").cloned(),
                                expires_before: raw.get("expires_before").cloned(),
                                status: raw.get("status").cloned(),
                                limit: raw.get("limit").and_then(|v| v.parse().ok()),
                                cursor: raw.get("cursor").cloned(),
                            };
                            let resp = server.search(&params, None).expect("search");
                            Json(resp).into_response()
                        }
                    }
                }),
            )
            .route(
                "/contexts/{id}",
                get({
                    let server = server.clone();
                    let state = routes["context"].clone();
                    move |axum::extract::Path(id): axum::extract::Path<String>| {
                        let server = server.clone();
                        let state = state.clone();
                        async move {
                            if let Some(resp) = state.intercept().await {
                                return resp;
                            }
                            let ctx_id = CtxId(id);
                            let full = server
                                .retrieve(&ctx_id, None)
                                .expect("retrieve")
                                .expect("found");
                            Json(full).into_response()
                        }
                    }
                }),
            )
            .route(
                "/lineages/{id}",
                get({
                    let server = server.clone();
                    let state = routes["lineage"].clone();
                    move |axum::extract::Path(id): axum::extract::Path<String>| {
                        let server = server.clone();
                        let state = state.clone();
                        async move {
                            if let Some(resp) = state.intercept().await {
                                return resp;
                            }
                            let lineage_id = LineageId(id);
                            let all = server.lineage(&lineage_id, None).expect("lineage");
                            Json(all).into_response()
                        }
                    }
                }),
            )
            .route(
                "/lineages/{id}/current",
                get({
                    let server = server.clone();
                    let state = routes["current"].clone();
                    move |axum::extract::Path(id): axum::extract::Path<String>| {
                        let server = server.clone();
                        let state = state.clone();
                        async move {
                            if let Some(resp) = state.intercept().await {
                                return resp;
                            }
                            let lineage_id = LineageId(id);
                            let full = server
                                .current(&lineage_id, None)
                                .expect("current")
                                .expect("lineage has a head");
                            Json(full).into_response()
                        }
                    }
                }),
            );

        if let Some(doc) = self.registry_did_doc {
            let state = Arc::new(RouteState::default());
            routes.insert("registry_did".into(), state.clone());
            let doc = Arc::new(doc);
            router = router.route(
                "/.well-known/did.json",
                get(move || {
                    let doc = doc.clone();
                    let state = state.clone();
                    async move {
                        if let Some(resp) = state.intercept().await {
                            return resp;
                        }
                        Json((*doc).clone()).into_response()
                    }
                }),
            );
        }

        for (path, doc) in self.producer_dids {
            let state = Arc::new(RouteState::default());
            routes.insert(path.clone(), state.clone());
            let doc = Arc::new(doc);
            router = router.route(
                &candidate_did_route(&path),
                get(move || {
                    let doc = doc.clone();
                    let state = state.clone();
                    async move {
                        if let Some(resp) = state.intercept().await {
                            return resp;
                        }
                        Json((*doc).clone()).into_response()
                    }
                }),
            );
        }

        if self.well_known_acdp {
            let state = Arc::new(RouteState::default());
            routes.insert("acdp_json".into(), state.clone());
            let server = server.clone();
            router = router.route(
                "/.well-known/acdp.json",
                get(move || {
                    let server = server.clone();
                    let state = state.clone();
                    async move {
                        if let Some(resp) = state.intercept().await {
                            return resp;
                        }
                        Json(server.capabilities().clone()).into_response()
                    }
                }),
            );
        }
        let tls = TlsTestServer::start(router).await;
        let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
            .expect("pinned resolver");
        LineageServerHarness {
            tls,
            server,
            resolver,
            routes,
        }
    }
}

/// One producer-signed `key-revocation` context seeded by
/// [`LineageServerHarness::seed_revocations`].
struct SeededRevocation {
    ctx_id: CtxId,
    lineage_id: LineageId,
    revocation: KeyRevocation,
}

impl LineageServerHarness {
    async fn start(caps: CapabilitiesDocument, lifecycle: bool) -> Self {
        Self::builder(caps).lifecycle(lifecycle).build().await
    }

    fn builder(caps: CapabilitiesDocument) -> LineageServerHarnessBuilder {
        LineageServerHarnessBuilder::new(caps)
    }

    fn client(&self) -> RegistryClient {
        RegistryClient::with_test_endpoint(
            &format!("https://{REGISTRY_AUTHORITY}"),
            self.tls.addr,
            &self.tls.root_cert_pem,
        )
        .expect("pinned client")
    }

    fn route_state(&self, route: &str) -> &Arc<RouteState> {
        self.routes.get(route).unwrap_or_else(|| {
            let known: Vec<&String> = self.routes.keys().collect();
            panic!("harness: no such route '{route}' (registered: {known:?})")
        })
    }

    /// Requests served so far for `route` (see [`LineageServerHarness::routes`]
    /// for valid names). AC4.
    fn hits(&self, route: &str) -> usize {
        self.route_state(route)
            .hits
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// From the next request onward, `route` returns `status` instead
    /// of its normal handling. AC2 — e.g.
    /// `set_error("search", axum::http::StatusCode::SERVICE_UNAVAILABLE)`.
    fn set_error(&self, route: &str, status: axum::http::StatusCode) {
        self.route_state(route)
            .error_status
            .store(status.as_u16(), std::sync::atomic::Ordering::SeqCst);
    }

    /// Undo [`Self::set_error`].
    fn clear_error(&self, route: &str) {
        self.route_state(route)
            .error_status
            .store(0, std::sync::atomic::Ordering::SeqCst);
    }

    /// From the next request onward, `route` sleeps `delay` before
    /// responding (whether or not an error is also injected). AC5.
    fn set_delay(&self, route: &str, delay: std::time::Duration) {
        self.route_state(route).delay_ms.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    /// Undo [`Self::set_delay`].
    fn clear_delay(&self, route: &str) {
        self.route_state(route)
            .delay_ms
            .store(0, std::sync::atomic::Ordering::SeqCst);
    }

    /// Seed `boundaries.len()` distinct producer-signed
    /// `key-revocation` contexts, all published under `producer`'s own
    /// identity (so a later `find_revocations(client, resolver,
    /// producer_agent_id)` call can discover them) and all naming
    /// `revoked_key_fingerprint`. Each boundary becomes its own fresh
    /// v1 — its own lineage — so `boundaries.len() == 1` gives exactly
    /// the "≥1 lineage" floor and `> 1` gives that many distinct
    /// lineages. AC6: Phase 4's `known`-vs-discovered split (e.g. R1
    /// held back, R2 left for `discover` to find) is just the caller's
    /// choice of which returned `SeededRevocation`s to place in
    /// `RevocationPolicy::new(known)`. A caller wanting a supersession
    /// *chain* within one lineage instead can call
    /// `Producer::supersede_body` /
    /// `server.publish_verified_did_key` directly, exactly as
    /// `find_revocations_in_lineage_returns_superseded_and_current_member`
    /// (above) already does — this helper deliberately covers only the
    /// simpler, sufficient shape.
    ///
    /// Uses `server.publish_verified` (not the did:key-only
    /// `publish_verified_did_key` shortcut), so it works uniformly
    /// whether `producer` is did:key (resolved offline) or a did:web
    /// identity hosted by this same harness via
    /// [`LineageServerHarnessBuilder::with_producer_did`]. Each seeded
    /// body is round-tripped through `verify_revocation_body` against
    /// the harness's own resolver before being returned, so callers get
    /// back exactly the `KeyRevocation` shape `find_revocations` would
    /// produce.
    async fn seed_revocations(
        &self,
        producer: &Producer,
        revoked_key_fingerprint: &str,
        boundaries: &[DateTime<Utc>],
    ) -> Vec<SeededRevocation> {
        let mut out = Vec::with_capacity(boundaries.len());
        for (i, &t) in boundaries.iter().enumerate() {
            let req = producer
                .publish_request()
                .acdp_version("0.3.0")
                .title(format!("seeded revocation #{i}"))
                .context_type(ContextType::KeyRevocation)
                .visibility(Visibility::Public)
                .metadata(json!({
                    "revoked_key_fingerprint": revoked_key_fingerprint,
                    "compromised_since": acdp::time::trunc_ms(t)
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                }))
                .build()
                .expect("seeded revocation build");
            let resp = self
                .server
                .publish_verified(&req, None, &self.resolver)
                .await
                .expect("seeded revocation publish");
            let full = self
                .server
                .store()
                .get(&resp.ctx_id)
                .expect("get")
                .expect("seeded revocation present");
            let revocation = verify_revocation_body(&full.body, &self.resolver)
                .await
                .expect("seeded revocation must itself verify");
            out.push(SeededRevocation {
                ctx_id: resp.ctx_id,
                lineage_id: resp.lineage_id,
                revocation,
            });
        }
        out
    }
}

/// **Test B — the genuine lineage endpoint, end-to-end.** R1 (early
/// boundary) superseded by R2 (later boundary) on a real
/// `RegistryServer`; `find_revocations_in_lineage` must return both,
/// exercising the real `/lineages/{id}` handler rather than a
/// hand-built stand-in.
#[tokio::test]
async fn find_revocations_in_lineage_returns_superseded_and_current_member() {
    let h = LineageServerHarness::start(lifecycle_caps(), false).await;

    let producer = Producer::new_did_key(SigningKey::from_bytes(&[0x44u8; 32]));
    let v1 = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("lineage-walk v1: early boundary")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": K1_FP,
            "compromised_since": "2026-04-01T00:00:00.000Z",
        }))
        .build()
        .expect("v1 build");
    let resp1 = h
        .server
        .publish_verified_did_key(&v1, None)
        .expect("v1 publish");
    let stored_v1 = h
        .server
        .store()
        .get(&resp1.ctx_id)
        .expect("get")
        .expect("v1 present");

    let v2 = producer
        .supersede_body(&stored_v1.body)
        .acdp_version("0.3.0")
        .title("lineage-walk v2: later boundary")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": K1_FP,
            "compromised_since": "2026-05-01T00:00:00.000Z",
        }))
        .build()
        .expect("v2 build");
    let resp2 = h
        .server
        .publish_verified_did_key(&v2, None)
        .expect("v2 publish");
    assert_eq!(resp2.lineage_id, resp1.lineage_id);

    // v1 is now genuinely superseded — this is the real registry
    // deriving that status, not a hand-synthesized one.
    let stored_v1_after = h.server.store().get(&resp1.ctx_id).unwrap().unwrap();
    assert_eq!(stored_v1_after.registry_state.status, Status::Superseded);

    let client = h.client();
    let mut revs = find_revocations_in_lineage(&client, &h.resolver, &resp2.lineage_id)
        .await
        .expect("lineage walk");
    assert_eq!(
        revs.len(),
        2,
        "both the superseded and current member must be returned"
    );
    revs.sort_by_key(|r| r.compromised_since);
    assert_eq!(revs[0].compromised_since, at("2026-04-01T00:00:00.000Z"));
    assert_eq!(revs[1].compromised_since, at("2026-05-01T00:00:00.000Z"));
    for r in &revs {
        assert_eq!(r.revoked_key_fingerprint, K1_FP);
        assert_eq!(r.trust_class, RevocationTrustClass::ProducerSigned);
    }
}

/// **Negative test.** A lineage member whose signature is broken is
/// excluded from `find_revocations_in_lineage`'s output — dropped
/// exactly as the existing search-driven loop drops a permanently
/// unverifiable candidate — rather than surfaced as (or turned into)
/// an error.
#[tokio::test]
async fn find_revocations_in_lineage_drops_broken_signature_member() {
    use std::collections::HashMap;

    let producer = Producer::new_did_key(SigningKey::from_bytes(&[0x55u8; 32]));
    let lineage = LineageId::parse(format!("lin:sha256:{}", "3".repeat(64))).unwrap();

    let good = revocation_body(
        &producer,
        json!({"revoked_key_fingerprint": K1_FP, "compromised_since": T}),
        "acdp://localhost/00000000-0000-4000-8000-0000000000a1",
        &lineage,
        None,
        at("2026-05-02T00:00:00.000Z"),
    );
    let mut broken = revocation_body(
        &producer,
        json!({"revoked_key_fingerprint": K2_FP, "compromised_since": T}),
        "acdp://localhost/00000000-0000-4000-8000-0000000000a2",
        &lineage,
        None,
        at("2026-05-03T00:00:00.000Z"),
    );
    // Corrupt the signature. `content_hash` still matches (the
    // signature is not part of ProducerContent), so this fails
    // specifically at Ed25519 verification, not earlier at hash
    // recomputation.
    broken.signature.value = "A".repeat(88);

    let mut lineages: HashMap<String, serde_json::Value> = HashMap::new();
    lineages.insert(
        lineage.as_str().to_string(),
        serde_json::to_value(vec![full_context(good.clone()), full_context(broken)]).unwrap(),
    );
    let lineages = Arc::new(lineages);

    let router = Router::new().route(
        "/lineages/{id}",
        get({
            let lineages = lineages.clone();
            move |axum::extract::Path(id): axum::extract::Path<String>| {
                let lineages = lineages.clone();
                async move { Json(lineages.get(&id).cloned().unwrap_or(json!([]))) }
            }
        }),
    );
    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    let revs = find_revocations_in_lineage(&client, &resolver, &lineage)
        .await
        .expect("lineage walk must not error on a dropped candidate");
    assert_eq!(
        revs.len(),
        1,
        "the broken-signature member must be dropped, not error, and not \
         poison the genuine member"
    );
    assert_eq!(revs[0].revoked_key_fingerprint, K1_FP);
}

// ── Issue #226 Phase 4: retracted seed pass + loud page/walk caps ───────────

/// **Retracted-only lineage.** The sole member of this revocation
/// lineage is retracted on a REAL `RegistryServer` — no `active` or
/// `superseded` search pass can ever return it, so before Phase 4 the
/// consumer would never learn the `lineage_id` to walk in the first
/// place. RFC-ACDP-0013 §8.2 makes `status=retracted` available
/// specifically to close this hole; `find_revocations`'s new third
/// status pass discovers the seed match, and the (single-member)
/// lineage walk trivially confirms it. The hand-built mocks used
/// elsewhere in this file cannot express this case at all — they
/// ignore the `status` query parameter entirely — which is why this
/// test uses `LineageServerHarness` with `lifecycle_caps()` and
/// lifecycle enabled instead.
#[tokio::test]
async fn find_revocations_recovers_all_retracted_lineage_via_retracted_search_pass() {
    use acdp::client::find_revocations;
    use acdp::types::lifecycle::{LifecycleEvent, LifecycleEventType};

    let h = LineageServerHarness::start(lifecycle_caps(), true).await;

    let seed = [0x71u8; 32];
    let producer = Producer::new_did_key(SigningKey::from_bytes(&seed));
    let did =
        acdp::did::key::did_key_from_ed25519(&SigningKey::from_bytes(&seed).verifying_key_bytes());
    let key_id = acdp::did::key::did_key_url(&did).expect("did:key URL");
    let actor = AgentDid::new(did);

    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("retracted-only lineage revocation")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": K1_FP,
            "compromised_since": "2026-04-01T00:00:00.000Z",
        }))
        .build()
        .expect("build");
    let resp = h
        .server
        .publish_verified_did_key(&req, None)
        .expect("publish");

    // Retract the sole member. `retract_unverified_for_tests` skips only
    // the §6 step 3 cryptographic half — actor presence/binding is still
    // enforced, so the event still needs a bound signature.
    let event = LifecycleEvent::new(
        "018f6d0a-00f4-4c4d-9e1f-3a5b7c9d1e2f",
        resp.ctx_id.clone(),
        LifecycleEventType::Retracted,
        chrono::Utc::now(),
        actor,
        Some("compromise confirmed; retracting the only lineage member".into()),
    )
    .expect("valid event")
    .sign_with(SigningKey::from_bytes(&seed), key_id)
    .expect("signed event");
    h.server
        .retract_unverified_for_tests(&event, None)
        .expect("retract");

    let stored = h.server.store().get(&resp.ctx_id).unwrap().unwrap();
    assert_eq!(
        stored.registry_state.status,
        Status::Retracted,
        "the store must genuinely reflect the retraction, not a hand-synthesized status"
    );

    let client = h.client();
    let revs = find_revocations(&client, &h.resolver, &req.agent_id)
        .await
        .expect("an all-retracted lineage must still be discoverable via the retracted pass");
    assert_eq!(
        revs.len(),
        1,
        "only the retracted status pass can find this revocation"
    );
    assert_eq!(revs[0].revoked_key_fingerprint, K1_FP);
}

/// Issue #226 Phase 4 — page-cap exhaustion becomes a hard, loud error
/// instead of a silent partial return. A hand-built mock that never
/// stops offering a `next_cursor`, on every page, for every
/// `(type_form, status)` pair `find_revocations` tries: it must abort
/// with `AcdpError::SearchTruncated` rather than return whatever it
/// collected (nothing, here) across `MAX_SEARCH_PAGES` pages.
#[tokio::test]
async fn find_revocations_errors_on_page_cap_exhaustion_with_cursor_remaining() {
    use acdp::client::find_revocations;
    use std::collections::HashMap;

    let router = Router::new().route(
        "/contexts/search",
        get(
            |_: axum::extract::Query<HashMap<String, String>>| async move {
                // Empty matches, but a cursor that never runs out — a
                // hostile (or pathologically paginated) registry holding
                // the caller in an endless cursor loop.
                Json(json!({"matches": [], "next_cursor": "stuck"}))
            },
        ),
    );
    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    let err = find_revocations(&client, &resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
        .await
        .expect_err("page-cap exhaustion with a cursor remaining must be a hard error");
    assert!(
        matches!(err, AcdpError::SearchTruncated(_)),
        "expected SearchTruncated, got {err:?}"
    );
}

/// **Boundary — completion, not truncation.** Exactly `MAX_SEARCH_PAGES`
/// (10) full pages whose LAST page's `next_cursor` is absent is a
/// *complete* result: `find_revocations` must return `Ok`, never
/// `SearchTruncated`, in this case. The mock encodes the page index in
/// the cursor itself (`"0"..="9"`) so every `(type_form, status)` pass
/// independently walks the same exact-boundary sequence.
#[tokio::test]
async fn find_revocations_exactly_at_page_cap_with_no_trailing_cursor_is_ok() {
    use acdp::client::find_revocations;
    use std::collections::HashMap;

    let router = Router::new().route(
        "/contexts/search",
        get(
            |axum::extract::Query(raw): axum::extract::Query<HashMap<String, String>>| async move {
                let n: usize = raw.get("cursor").and_then(|c| c.parse().ok()).unwrap_or(0);
                let next = n + 1;
                // MAX_SEARCH_PAGES = 10 (kept in lockstep with
                // `crates/acdp-client/src/revocation.rs`; not itself
                // exported for tests to reference).
                if next < 10 {
                    Json(json!({"matches": [], "next_cursor": next.to_string()}))
                } else {
                    Json(json!({"matches": []}))
                }
            },
        ),
    );
    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    let revs = find_revocations(&client, &resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
        .await
        .expect("exactly-at-cap with no trailing cursor is complete, not truncated");
    assert!(revs.is_empty());
}

/// Issue #226 Phase 4 — the lineage walk is bounded exactly like the
/// search pages: a search response naming more distinct candidate
/// `lineage_id`s than `MAX_LINEAGE_WALKS` (100) must abort with the
/// same `AcdpError::SearchTruncated`, never silently walk only the
/// first `MAX_LINEAGE_WALKS` and drop the rest. All 101 matches share
/// one `ctx_id` (dedup is by `ctx_id`, not `lineage_id`), so exactly
/// one `retrieve` call happens and the test stays cheap.
#[tokio::test]
async fn find_revocations_errors_when_candidate_lineages_exceed_walk_cap() {
    use acdp::client::find_revocations;
    use std::collections::HashMap;

    let producer = Producer::new_did_key(SigningKey::from_bytes(&[0x72u8; 32]));
    let ctx_id = "acdp://localhost/00000000-0000-4000-8000-0000000000c1";
    let body = revocation_body(
        &producer,
        json!({"revoked_key_fingerprint": K1_FP, "compromised_since": "2026-04-01T00:00:00.000Z"}),
        ctx_id,
        &lineage_p(),
        None,
        at("2026-04-02T00:00:00.000Z"),
    );
    let producer_did = body.agent_id.as_str().to_string();

    // MAX_LINEAGE_WALKS (100) + 1 distinct candidate lineage ids.
    let matches: Vec<serde_json::Value> = (0..101u32)
        .map(|i| {
            let lineage = LineageId::parse(format!("lin:sha256:{i:064x}")).unwrap();
            serde_json::to_value(search_result(
                ctx_id,
                &lineage,
                &producer_did,
                "2026-04-02T00:00:00.000Z",
            ))
            .unwrap()
        })
        .collect();
    let search_response = json!({ "matches": matches });
    let expected_ctx_id = ctx_id.to_string();
    let context_json = serde_json::to_value(full_context(body)).unwrap();

    let router = Router::new()
        .route(
            "/contexts/search",
            get(move |_: axum::extract::Query<HashMap<String, String>>| {
                let resp = search_response.clone();
                async move { Json(resp) }
            }),
        )
        .route(
            "/contexts/{id}",
            get(
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let context_json = context_json.clone();
                    let expected_ctx_id = expected_ctx_id.clone();
                    async move {
                        assert_eq!(
                            id, expected_ctx_id,
                            "only the single shared ctx_id should ever be retrieved"
                        );
                        Json(context_json)
                    }
                },
            ),
        );

    let tls = TlsTestServer::start(router).await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    let err = find_revocations(&client, &resolver, &AgentDid::new(&producer_did))
        .await
        .expect_err("more candidate lineage ids than MAX_LINEAGE_WALKS must be a hard error");
    assert!(
        matches!(err, AcdpError::SearchTruncated(_)),
        "expected SearchTruncated, got {err:?}"
    );
}

// ── issue #248 Phase 1 (D5): transient verification failures propagate ─────
//
// `find_revocations`, `find_registry_attested_revocations`, and
// `find_revocations_in_lineage` must turn a *transient*
// `verify_revocation_body` failure — the candidate's `did:web` host is
// unreachable, not merely answering with something that fails §5 — into
// `Err`, not a silently empty/short `Vec`. `classify_under_revocation(&[],
// …)` reads an empty set as "proceed" (`revocation.rs:86-88`), so an
// unreachable DID host must never be allowed to look identical to "no
// revocations exist."

/// Publishes exactly one `key-revocation` candidate under a `did:web`
/// host that is reachable at publish time and then shut down — a real
/// connection refusal at query time
/// ([`common::TlsTestServer::shutdown`]), not a 404. A 404 means the
/// host answered and the route was missing, which maps to the
/// *permanent* `AcdpError::KeyResolution` and is exactly what the two
/// "must stay green, unchanged" tests already cover
/// (`find_revocations_returns_only_verified`,
/// `find_revocations_in_lineage_drops_broken_signature_member`). This
/// harness instead reproduces the plan's actual motivating scenario —
/// "a producer's `did:web` host being unreachable" — which is a
/// *transient* `AcdpError::KeyResolutionUnreachable`.
///
/// Search, retrieve, and lineage all succeed normally against a
/// separate, still-live `TlsTestServer` — only DID resolution fails, so
/// the resulting `Err` is attributable specifically to the D5 split
/// under test, not to some other already-covered abort lever (hostile
/// `client.search` / `client.retrieve` / `client.lineage` failures).
///
/// `include_lineage_member` controls the `/lineages/{id}` response:
///
/// - `true` — returns the one candidate as the lineage's sole member.
///   Needed by the `find_revocations_in_lineage` test, which walks the
///   lineage directly.
/// - `false` — returns an empty array. **Required** to isolate the
///   `find_revocations` / `find_registry_attested_revocations` tests:
///   both functions unconditionally walk every search match's lineage
///   *in addition to* verifying the match inline, so with `true` here,
///   reverting *only* the inline-verify site under test would still go
///   `Err` — via the still-correct lineage walk hitting the very same
///   unreachable DID — and the falsifiability probe would (wrongly)
///   read green. An empty lineage makes that walk fail with the
///   unrelated, permanent `IncompleteLineage` the moment it is
///   reached, which only happens *after* the inline-verify site has
///   already had its chance to return — so with the code correctly
///   fixed, the inline site's `Err(KeyResolutionUnreachable)` returns
///   first and the walk (and the empty response) is never reached at
///   all.
///
/// Returns a client/resolver pair pinned against the live server, plus
/// the candidate's own `agent_id` and `lineage_id`.
async fn discover_with_unreachable_did(
    include_lineage_member: bool,
) -> (RegistryClient, WebResolver, AgentDid, LineageId) {
    use std::collections::HashMap;

    let seed = [0x99u8; 32];
    let pub_key = SigningKey::from_bytes(&seed).verifying_key_bytes();

    // DID-only server: reachable during publish, shut down below before
    // the caller runs discovery. `start_with` hands back the
    // kernel-assigned port so the DID document (and the producer's own
    // `agent_id`) can embed it via the percent-encoded `did:web:
    // localhost%3A<port>` form (`TlsTestServer::did`'s doc explains the
    // encoding).
    let tls_did = TlsTestServer::start_with(|port| {
        let did = format!("did:web:localhost%3A{port}");
        let doc = ed25519_did_doc(&did, "key-1", &pub_key);
        did_doc_router(doc)
    })
    .await;
    let producer_did = tls_did.did();

    let server =
        RegistryServer::try_new(InMemoryStore::new(), caps(), REGISTRY_AUTHORITY).expect("server");
    let producer = Producer::new(
        SigningKey::from_bytes(&seed),
        AgentDid::new(&producer_did),
        format!("{producer_did}#key-1"),
    );
    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("candidate behind a DID host that goes unreachable")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": K1_FP,
            "compromised_since": T,
        }))
        .build()
        .expect("build");

    let publish_resolver =
        WebResolver::with_test_endpoint(&tls_did.root_cert_pem, "localhost", tls_did.addr)
            .expect("pinned resolver");
    let resp = server
        .publish_verified(&req, None, &publish_resolver)
        .await
        .expect("publish");
    let full = server
        .store()
        .get(&resp.ctx_id)
        .expect("get")
        .expect("present");
    let lineage_id = full.body.lineage_id.clone();
    let full_value = serde_json::to_value(&full).unwrap();

    // The host the candidate's DID resolves to is now taken down —
    // permanently, for the rest of this harness's life. Any later
    // attempt to connect to `tls_did.addr` gets a genuine connection
    // refusal, not a 404.
    tls_did.shutdown().await;

    // A second, independent server backs search/retrieve/lineage and
    // stays live for the whole discovery call — proving the failure
    // this test asserts on comes from DID resolution alone.
    let matches = vec![json!({
        "ctx_id": full.body.ctx_id.as_str(),
        "lineage_id": full.body.lineage_id.as_str(),
        "agent_id": producer_did,
        "title": full.body.title,
        "type": "key-revocation",
        "created_at": "2026-05-02T08:00:00.000Z",
        "status": "active",
        "visibility": "public",
    })];
    let router = Router::new()
        .route(
            "/contexts/search",
            get({
                let matches = matches.clone();
                move |axum::extract::Query(_): axum::extract::Query<HashMap<String, String>>| {
                    let matches = matches.clone();
                    async move { Json(json!({ "matches": matches })) }
                }
            }),
        )
        .route(
            "/contexts/{id}",
            get({
                let full_value = full_value.clone();
                move |axum::extract::Path(_): axum::extract::Path<String>| {
                    let full_value = full_value.clone();
                    async move { Json(full_value) }
                }
            }),
        )
        .route(
            "/lineages/{id}",
            get({
                let lineage_body = if include_lineage_member {
                    json!([full_value])
                } else {
                    json!([])
                };
                move |axum::extract::Path(_): axum::extract::Path<String>| {
                    let lineage_body = lineage_body.clone();
                    async move { Json(lineage_body) }
                }
            }),
        )
        .route(
            "/.well-known/acdp.json",
            get(move || async move { Json(caps()) }),
        );

    let tls = TlsTestServer::start(router).await;
    // The PEM used here is irrelevant to whether DID resolution
    // succeeds: the candidate's `did:web` URL carries its own explicit
    // (now-dead) port, so that connection is refused at the TCP layer,
    // long before TLS certificate validation would matter.
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let client = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls.addr,
        &tls.root_cert_pem,
    )
    .expect("pinned client");

    (client, resolver, AgentDid::new(&producer_did), lineage_id)
}

/// Falsifiability target for `find_revocations`'s D5 split
/// (`revocation.rs` — the search-driven candidate loop): reverting the
/// `match … Err(e) if e.is_transient() => return Err(e) …` back to
/// `if let Ok(rev) = …` must turn this red.
#[tokio::test]
async fn find_revocations_propagates_transient_resolution_failure() {
    use acdp::client::find_revocations;

    let (client, resolver, agent_id, _lineage_id) = discover_with_unreachable_did(false).await;

    let err = find_revocations(&client, &resolver, &agent_id)
        .await
        .expect_err(
            "a candidate behind an unreachable DID host must not read as a clean \
             \"no revocations found\" — D5, issue #248 Phase 1",
        );
    assert!(
        err.is_transient(),
        "expected a transient error, got {err:?}"
    );
    assert!(
        matches!(err, AcdpError::KeyResolutionUnreachable(_)),
        "expected KeyResolutionUnreachable specifically, got {err:?}"
    );
}

/// Falsifiability target for `find_registry_attested_revocations`'s D5
/// split (the same shape, in its own search-driven candidate loop).
/// The `controller` passed here never matters: verification — and the
/// transient failure under test — happens before the controller/
/// registry-binding checks are ever reached.
#[tokio::test]
async fn find_registry_attested_revocations_propagates_transient_resolution_failure() {
    use acdp::client::find_registry_attested_revocations;

    let (client, resolver, _agent_id, _lineage_id) = discover_with_unreachable_did(false).await;

    let err =
        find_registry_attested_revocations(&client, &resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
            .await
            .expect_err(
                "a candidate behind an unreachable DID host must not read as a clean \
             \"no revocations found\" — D5, issue #248 Phase 1",
            );
    assert!(
        err.is_transient(),
        "expected a transient error, got {err:?}"
    );
    assert!(
        matches!(err, AcdpError::KeyResolutionUnreachable(_)),
        "expected KeyResolutionUnreachable specifically, got {err:?}"
    );
}

/// Falsifiability target for `walk_revocation_lineage`'s D5 split (the
/// member loop `find_revocations_in_lineage` wraps): reverting
/// `Err(e) if e.is_transient() => return Err(e)` back to a bare
/// `Err(_e) => { warn!(...) }` (dropping the new arm entirely) must
/// turn this red.
#[tokio::test]
async fn find_revocations_in_lineage_propagates_transient_resolution_failure() {
    use acdp::client::find_revocations_in_lineage;

    let (client, resolver, _agent_id, lineage_id) = discover_with_unreachable_did(true).await;

    let err = find_revocations_in_lineage(&client, &resolver, &lineage_id)
        .await
        .expect_err(
            "a lineage member behind an unreachable DID host must not read as a clean \
             \"no revocations found\" — D5, issue #248 Phase 1",
        );
    assert!(
        err.is_transient(),
        "expected a transient error, got {err:?}"
    );
    assert!(
        matches!(err, AcdpError::KeyResolutionUnreachable(_)),
        "expected KeyResolutionUnreachable specifically, got {err:?}"
    );
}

// ── issue #248 Phase 3: self-tests for the extended LineageServerHarness ────
//
// These exercise `LineageServerHarnessBuilder`'s new capabilities in
// isolation. Phase 4 (a separate PR) is the actual consumer of this
// harness for the discovery-in-`verify_retrieved` assertions; nothing
// here reads `policy.revocations.discover`.

/// AC1 (all six routes from one instance) + AC3 (receipt minting
/// satisfies `ReceiptPolicy::Require`) + AC7 (portability proof): this
/// reproduces the pre-compromise-historical and fail-closed-at-boundary
/// outcomes of `rev_002_fetch_pipeline_boundary_matrix`'s cases A and B
/// — same intent, same assertions — through `LineageServerHarness`
/// instead of the older `Harness`/`start_harness`/`publish_with_receipt`
/// trio, proving the merged harness can replace what that one did.
#[tokio::test]
async fn discovery_harness_serves_all_six_routes_and_satisfies_receipt_require() {
    let registry_signer_key = SigningKey::from_bytes(&[0xB1u8; 32]);
    let producer_key = SigningKey::from_bytes(&[0xB2u8; 32]);
    let producer_pub = producer_key.verifying_key_bytes();
    let producer_fp = fingerprint_ed25519(&producer_pub);
    let producer_path = "harness-agent";
    let producer_did = candidate_did(producer_path);

    let h = LineageServerHarness::builder(lifecycle_caps())
        .with_receipt_signer(registry_signer_key, "receipt-key-1")
        .with_producer_did(producer_path, "key-1", &producer_pub)
        .with_well_known_acdp()
        .build()
        .await;

    let producer = Producer::new(
        producer_key,
        AgentDid::new(producer_did.as_str()),
        format!("{producer_did}#key-1"),
    );
    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("harness-hosted receipt-bearing target context")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("build");
    let resp = h
        .server
        .publish_verified(&req, None, &h.resolver)
        .await
        .expect("publish with receipt minting");

    // Publish-time verification already hit the producer's DID route
    // to check the signature (minting itself needs no network — the
    // registry signs with its own locally-held `ReceiptSigner` key;
    // the registry's DID route is instead hit below, when a consumer
    // resolves that key to *verify* the receipt).
    assert!(
        h.hits(producer_path) > 0,
        "producer DID route must have been hit resolving the publish-time signature"
    );
    // Receipts are minted with the registry's own locally-held
    // `ReceiptSigner` key (a pure local signing operation — see
    // `crates/acdp-types/src/receipt.rs`), so publish never resolves
    // the registry's own DID over the network. The registry DID route
    // is hit only consumer-side, inside `verify_receipt_value`
    // (`crates/acdp-client/src/receipt.rs`), when a consumer verifies
    // the receipt below.
    assert_eq!(
        h.hits("registry_did"),
        0,
        "registry DID route must not be hit at publish time — receipts are minted with a \
         locally-held key, not a resolved one"
    );

    let client = h.client();

    // ── AC1: search, retrieve, lineage, and capabilities — all from
    // this one instance. ────────────────────────────────────────────
    let search_params = acdp::types::SearchParamsBuilder::new()
        .agent_id(producer_did.as_str())
        .limit(10)
        .build();
    let via_search = client.search(&search_params).await.expect("search");
    assert_eq!(
        via_search.matches.len(),
        1,
        "search must find the published context"
    );

    let via_retrieve = client.retrieve(&resp.ctx_id).await.expect("retrieve");
    assert_eq!(via_retrieve.body.ctx_id, resp.ctx_id);

    let via_lineage = client.lineage(&resp.lineage_id).await.expect("lineage");
    assert_eq!(via_lineage.len(), 1);

    let via_caps = client.capabilities().await.expect("capabilities");
    assert_eq!(via_caps.registry_did, REGISTRY_DID);
    assert!(h.hits("acdp_json") > 0);

    // ── AC3: the context verified through this harness satisfies
    // `ReceiptPolicy::Require`. ─────────────────────────────────────
    let require_policy = VerificationPolicy {
        receipts: ReceiptPolicy::Require,
        ..Default::default()
    };
    let verified =
        VerifiedContext::fetch_with_policy(&client, &h.resolver, &resp.ctx_id, &require_policy)
            .await
            .expect("a context verified through this harness must satisfy ReceiptPolicy::Require");
    let receipt_time = verified
        .verified_receipt()
        .expect("receipt must be present and verified")
        .created_at;
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
    assert!(
        h.hits("registry_did") > 0,
        "registry DID route must have been hit resolving the receipt signing key to verify it"
    );

    // ── AC7 port of rev-002 case A: boundary strictly after the
    // receipt-attested publish time → historically authorized
    // (pre-compromise, receipt-attested). ───────────────────────────
    let revocation_at = |t: DateTime<Utc>| KeyRevocation {
        revoked_key_fingerprint: producer_fp.clone(),
        compromised_since: acdp::time::trunc_ms(t),
        reason: Some("ported from rev_002_fetch_pipeline_boundary_matrix".into()),
        revoked_key_id: Some(format!("{producer_did}#key-1")),
        revoked_key_controller: AgentDid::new(producer_did.as_str()),
        publisher: AgentDid::new(producer_did.as_str()),
        trust_class: RevocationTrustClass::ProducerSigned,
    };
    let pre = VerificationPolicy {
        receipts: ReceiptPolicy::VerifyIfPresent,
        revocations: RevocationPolicy::new(vec![revocation_at(
            receipt_time + chrono::Duration::days(1),
        )]),
        ..Default::default()
    };
    let verified = VerifiedContext::fetch_with_policy(&client, &h.resolver, &resp.ctx_id, &pre)
        .await
        .expect("pre-compromise context must verify");
    assert_eq!(
        verified.key_status(),
        KeyAuthorization::HistoricallyAuthorizedPreCompromise
    );

    // ── AC7 port of rev-002 case B: boundary at/before the
    // receipt-attested publish time → fail closed despite the valid
    // receipt. ───────────────────────────────────────────────────────
    let post = VerificationPolicy {
        receipts: ReceiptPolicy::VerifyIfPresent,
        revocations: RevocationPolicy::new(vec![revocation_at(receipt_time)]),
        ..Default::default()
    };
    let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &resp.ctx_id, &post)
        .await
        .expect_err("inside the compromise window must fail closed");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// AC2: a named route can be made to return an explicit error status —
/// specifically 503 on `/contexts/search`, which is exactly what Phase
/// 4 AC4 consumes — while `/contexts/{id}` on the same instance keeps
/// working normally, and clearing the injection restores it.
#[tokio::test]
async fn discovery_harness_injects_503_on_contexts_search() {
    let h = LineageServerHarness::start(lifecycle_caps(), false).await;
    let producer = Producer::new_did_key(SigningKey::from_bytes(&[0xB3u8; 32]));
    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("AC2 target")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("build");
    let resp = h
        .server
        .publish_verified_did_key(&req, None)
        .expect("publish");
    let client = h.client();

    h.set_error("search", axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let params = acdp::types::SearchParamsBuilder::new().limit(10).build();
    let err = client
        .search(&params)
        .await
        .expect_err("search must fail while the injected 503 is active");
    assert!(
        err.is_transient(),
        "expected a transient error, got {err:?}"
    );
    assert!(matches!(err, AcdpError::RegistryInternal(_)), "got {err:?}");

    // Per-route, not global: `/contexts/{id}` is unaffected.
    let via_retrieve = client
        .retrieve(&resp.ctx_id)
        .await
        .expect("retrieve must still work while search is failing");
    assert_eq!(via_retrieve.body.ctx_id, resp.ctx_id);

    h.clear_error("search");
    let ok = client
        .search(&params)
        .await
        .expect("search must succeed once the injected error is cleared");
    assert_eq!(ok.matches.len(), 1);
}

/// AC4: a per-route hit counter, independent per route — precedent
/// `caps_hits` (`:1761`) generalized to every route on this harness.
#[tokio::test]
async fn discovery_harness_counts_hits_per_route() {
    let h = LineageServerHarness::start(lifecycle_caps(), false).await;
    let producer = Producer::new_did_key(SigningKey::from_bytes(&[0xB4u8; 32]));
    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("AC4 target")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("build");
    let resp = h
        .server
        .publish_verified_did_key(&req, None)
        .expect("publish");
    let client = h.client();

    assert_eq!(h.hits("search"), 0);
    assert_eq!(h.hits("context"), 0);
    assert_eq!(h.hits("lineage"), 0);

    let params = acdp::types::SearchParamsBuilder::new().limit(10).build();
    client.search(&params).await.expect("search 1");
    client.search(&params).await.expect("search 2");
    client.retrieve(&resp.ctx_id).await.expect("retrieve");

    assert_eq!(h.hits("search"), 2, "search hit exactly twice");
    assert_eq!(h.hits("context"), 1, "context hit exactly once");
    assert_eq!(
        h.hits("lineage"),
        0,
        "lineage route never called — request counts are unchanged when unused, \
         exactly the shape Phase 4 AC1 needs for discover: None"
    );
}

/// AC5: a configurable per-route delay, enough to prove a short
/// client-side timeout elapses. Phase 4 AC7 uses this shape with a 2s
/// timeout against a 30s-delayed route.
///
/// The delay/timeout pair here (2s / 100ms) is deliberately wide, not
/// merely fast: a cold process pays a one-time cost (rustls-provider
/// install, first TLS handshake) that has been measured at roughly
/// 20ms, so a delay/timeout pair close to that order can be satisfied
/// by init cost alone even with `set_delay` never taking effect — a
/// spurious pass that only shows up running this test solo (in the
/// full suite the harness is already warm). A warm-up request through
/// this same harness before `set_delay` pays that cost up front, and
/// the 20x margin between the 100ms timeout and the 2s delay means
/// the assertion can only be satisfied by the injected delay actually
/// applying. The test still returns quickly because `timeout` fires
/// at 100ms, not at the 2s delay.
#[tokio::test]
async fn discovery_harness_delay_elapses_a_short_timeout() {
    let h = LineageServerHarness::start(lifecycle_caps(), false).await;
    let client = h.client();
    let params = acdp::types::SearchParamsBuilder::new().limit(10).build();

    // Warm-up: pay one-time TLS/crypto init cost before the timed
    // call, so the timed assertion below measures the injected delay,
    // not process startup.
    client.search(&params).await.expect("warm-up search");

    h.set_delay("search", std::time::Duration::from_secs(2));
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        client.search(&params),
    )
    .await;
    assert!(
        result.is_err(),
        "a 100ms client timeout must elapse against a 2s-delayed route"
    );

    h.clear_delay("search");
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(5), client.search(&params)).await;
    assert!(
        result.is_ok(),
        "search must complete promptly once the delay is cleared"
    );
}

/// AC6: a seeding helper placing N distinct revocations across ≥1
/// lineage, in a shape directly usable for Phase 4 AC6's "hold R1 in
/// `known`, discover R2" split — demonstrated here by holding the
/// first seeded revocation aside and recovering both only through
/// `find_revocations`.
#[tokio::test]
async fn discovery_harness_seed_revocations_places_n_across_lineages() {
    use acdp::client::find_revocations;

    let h = LineageServerHarness::start(lifecycle_caps(), true).await;
    let seed = [0xB5u8; 32];
    let producer = Producer::new_did_key(SigningKey::from_bytes(&seed));
    let did =
        acdp::did::key::did_key_from_ed25519(&SigningKey::from_bytes(&seed).verifying_key_bytes());
    let agent_id = AgentDid::new(did);

    let seeded = h
        .seed_revocations(
            &producer,
            K1_FP,
            &[
                at("2026-04-01T00:00:00.000Z"),
                at("2026-05-01T00:00:00.000Z"),
            ],
        )
        .await;
    assert_eq!(seeded.len(), 2);
    assert_ne!(seeded[0].ctx_id, seeded[1].ctx_id);
    assert_ne!(
        seeded[0].lineage_id, seeded[1].lineage_id,
        "each boundary is seeded as its own fresh v1 — its own lineage"
    );
    for s in &seeded {
        assert_eq!(s.revocation.revoked_key_fingerprint, K1_FP);
        assert_eq!(s.revocation.publisher, agent_id);
        assert_eq!(
            s.revocation.trust_class,
            RevocationTrustClass::ProducerSigned
        );
    }

    // Phase 4 AC6's shape: `known` would carry only `seeded[0]`;
    // discovery must still recover `seeded[1]` (and, redundantly,
    // `seeded[0]` too — this harness makes no attempt to hide already-
    // known revocations from search).
    let known_boundary = seeded[0].revocation.compromised_since;
    let client = h.client();
    let mut discovered = find_revocations(&client, &h.resolver, &agent_id)
        .await
        .expect("find_revocations must recover both seeded lineages");
    discovered.sort_by_key(|r| r.compromised_since);
    assert_eq!(discovered.len(), 2);
    assert_eq!(discovered[0].compromised_since, known_boundary);
    assert_eq!(
        discovered[1].compromised_since,
        seeded[1].revocation.compromised_since
    );
}

// ── issue #248 Phase 4 — discovery executed inside `verify_retrieved` ──────
//
// Every test below runs against the real `LineageServerHarness` (Phase 3),
// never a hand-built mock — the mocks elsewhere in this file hardcode
// `"status": "active"` on every match regardless of reality, which would
// make a discovery assertion pass spuriously (see the harness's own doc).

/// A DID document exposing TWO independently-resolvable Ed25519
/// verification methods under one `did:web` identity, both in
/// `assertionMethod`. [`discovery_rig`] needs this rather than
/// [`ed25519_did_doc`]'s single-key shape: `key-1` signs the target
/// context (later revoked), `key-2` signs the revocation itself.
/// RFC-ACDP-0014 §5 step 2 forbids a key revoking itself
/// (`check_not_self_signed`), so seeding a discoverable revocation
/// against a single-key producer identity always fails that check.
fn two_key_ed25519_did_doc(
    did: &str,
    frag1: &str,
    pub1: &[u8; 32],
    frag2: &str,
    pub2: &[u8; 32],
) -> serde_json::Value {
    use base64::Engine as _;
    let encode = |pk: &[u8; 32]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk);
    let vm1 = format!("{did}#{frag1}");
    let vm2 = format!("{did}#{frag2}");
    json!({
        "id": did,
        "verificationMethod": [
            {
                "id": vm1,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": encode(pub1) }
            },
            {
                "id": vm2,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": encode(pub2) }
            }
        ],
        "assertionMethod": [vm1, vm2],
    })
}

/// Shared rig for the Phase 4 tests: a receipt-minting harness with a
/// did:web-hosted producer identity and `/.well-known/acdp.json` (so both
/// `producer_signed_only()` and `all_trust_classes()` scenarios can reuse
/// it), plus one receipt-bearing target context already published under
/// that identity's `key-1` — `receipt_time` is that publish's
/// receipt-attested `created_at`, the boundary every test below positions
/// its seeded revocations relative to. `producer` signs with the
/// identity's OTHER key (`key-2`), so `h.seed_revocations(&rig.producer,
/// &rig.producer_fp, ..)` produces a genuine rotated-key revocation of
/// `key-1` rather than tripping `check_not_self_signed`.
struct DiscoveryRig {
    h: LineageServerHarness,
    client: RegistryClient,
    /// Signs with `key-2` — used to seed revocations of `key-1`.
    producer: Producer,
    producer_did: String,
    /// Fingerprint of `key-1`, the key that signed `target_ctx_id` — the
    /// key every seeded revocation in these tests names.
    producer_fp: String,
    target_ctx_id: CtxId,
    target_lineage_id: LineageId,
    receipt_time: DateTime<Utc>,
}

impl DiscoveryRig {
    fn agent_id(&self) -> AgentDid {
        AgentDid::new(self.producer_did.as_str())
    }
}

async fn discovery_rig(seed: u8) -> DiscoveryRig {
    let registry_signer_key = SigningKey::from_bytes(&[seed; 32]);
    let target_key = SigningKey::from_bytes(&[seed.wrapping_add(1); 32]);
    let target_pub = target_key.verifying_key_bytes();
    let target_fp = fingerprint_ed25519(&target_pub);
    let revoker_key = SigningKey::from_bytes(&[seed.wrapping_add(2); 32]);
    let revoker_pub = revoker_key.verifying_key_bytes();
    let producer_path = format!("phase4-agent-{seed:02x}");
    let producer_did = candidate_did(&producer_path);
    let did_doc =
        two_key_ed25519_did_doc(&producer_did, "key-1", &target_pub, "key-2", &revoker_pub);

    let h = LineageServerHarness::builder(lifecycle_caps())
        .with_receipt_signer(registry_signer_key, "receipt-key-1")
        .with_producer_did_document(&producer_path, did_doc)
        .with_well_known_acdp()
        .build()
        .await;

    let target_producer = Producer::new(
        target_key,
        AgentDid::new(producer_did.as_str()),
        format!("{producer_did}#key-1"),
    );
    let req = target_producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("phase-4 discovery target")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("build");
    let resp = h
        .server
        .publish_verified(&req, None, &h.resolver)
        .await
        .expect("publish with receipt minting");

    let client = h.client();
    let verified = VerifiedContext::fetch_with_policy(
        &client,
        &h.resolver,
        &resp.ctx_id,
        &VerificationPolicy::default(),
    )
    .await
    .expect("target must verify cleanly before any revocation exists");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
    let receipt_time = verified
        .verified_receipt()
        .expect("receipt must be present and verified")
        .created_at;

    let revoker = Producer::new(
        revoker_key,
        AgentDid::new(producer_did.as_str()),
        format!("{producer_did}#key-2"),
    );

    DiscoveryRig {
        h,
        client,
        producer: revoker,
        producer_did,
        producer_fp: target_fp,
        target_ctx_id: resp.ctx_id,
        target_lineage_id: resp.lineage_id,
        receipt_time,
    }
}

/// AC1: with `discover: None`, behavior and request count are unchanged —
/// the discovery phase must never call `/contexts/search` or
/// `/lineages/{id}` at all.
#[tokio::test]
async fn phase4_ac1_discover_none_leaves_behavior_and_request_count_unchanged() {
    let rig = discovery_rig(0xC1).await;
    assert_eq!(rig.h.hits("search"), 0);
    assert_eq!(rig.h.hits("lineage"), 0);

    let policy = VerificationPolicy::default();
    let verified = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect("must verify exactly as before discovery existed");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
    assert!(verified.revocation_discovery_failure().is_none());

    assert_eq!(
        rig.h.hits("search"),
        0,
        "discover: None must never call /contexts/search"
    );
    assert_eq!(
        rig.h.hits("lineage"),
        0,
        "discover: None must never call /lineages/{{id}}"
    );
}

/// AC2: `discover: Some(..)` plus a revocation reachable ONLY by
/// discovery (never placed in `known`) makes a previously-successful
/// verification fail `KeyNotAuthorized`.
#[tokio::test]
async fn phase4_ac2_discovery_only_revocation_flips_success_to_key_not_authorized() {
    let rig = discovery_rig(0xC2).await;

    // Confirmed clean beforehand, with no revocations known and no discovery.
    let baseline = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &VerificationPolicy::default(),
    )
    .await
    .expect("must succeed before any revocation exists");
    assert_eq!(baseline.key_status(), KeyAuthorization::CurrentlyAuthorized);

    // Seed a revocation reachable only by discovery — never placed in `known`.
    // Boundary AT the receipt time: RFC-ACDP-0014 §7 fails closed at/after
    // the boundary regardless of receipt validity.
    rig.h
        .seed_revocations(&rig.producer, &rig.producer_fp, &[rig.receipt_time])
        .await;

    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default()
            .with_discovery(RevocationDiscovery::producer_signed_only()),
        ..Default::default()
    };
    let err = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect_err("a revocation reachable only by discovery must now fail verification");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
    assert!(rig.h.hits("search") > 0, "discovery must have searched");
}

/// AC3: all FIVE policy-taking entry points honor `discover` —
/// `fetch_with_policy`, `fetch_current_with_policy`, `fetch_report`,
/// `fetch_report_diagnose`, `fetch_report_with_fetcher`. (`fetch` /
/// `fetch_current` hardcode the default policy and `CrossRegistryResolver`
/// has no policy-injection point — LIM-1/LIM-2, out of scope by design.)
///
/// Split into five independent `#[tokio::test]` functions (one per entry
/// point, each with its own `discovery_rig` seed) rather than one test
/// running all five sequentially: a regression in one entry point (e.g.
/// `fetch_with_policy`) used to `panic!`/`expect_err` out of the shared
/// test function and mask whether the other four still honored `discover`
/// at all. Each function below is a decomposition of the original body —
/// same setup shape, same assertions per entry point — not a rewrite.
#[tokio::test]
async fn phase4_ac3_fetch_with_policy_honors_discover() {
    let rig = discovery_rig(0xD0).await;
    rig.h
        .seed_revocations(&rig.producer, &rig.producer_fp, &[rig.receipt_time])
        .await;
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default()
            .with_discovery(RevocationDiscovery::producer_signed_only()),
        ..Default::default()
    };

    let err = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect_err("fetch_with_policy must honor discover");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

#[tokio::test]
async fn phase4_ac3_fetch_current_with_policy_honors_discover() {
    let rig = discovery_rig(0xD1).await;
    rig.h
        .seed_revocations(&rig.producer, &rig.producer_fp, &[rig.receipt_time])
        .await;
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default()
            .with_discovery(RevocationDiscovery::producer_signed_only()),
        ..Default::default()
    };

    let err = VerifiedContext::fetch_current_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_lineage_id,
        &policy,
    )
    .await
    .expect_err("fetch_current_with_policy must honor discover");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

#[tokio::test]
async fn phase4_ac3_fetch_report_honors_discover() {
    let rig = discovery_rig(0xD2).await;
    rig.h
        .seed_revocations(&rig.producer, &rig.producer_fp, &[rig.receipt_time])
        .await;
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default()
            .with_discovery(RevocationDiscovery::producer_signed_only()),
        ..Default::default()
    };

    let err =
        VerifiedContext::fetch_report(&rig.client, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect_err("fetch_report must honor discover");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

#[tokio::test]
async fn phase4_ac3_fetch_report_with_fetcher_honors_discover() {
    let rig = discovery_rig(0xD3).await;
    rig.h
        .seed_revocations(&rig.producer, &rig.producer_fp, &[rig.receipt_time])
        .await;
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default()
            .with_discovery(RevocationDiscovery::producer_signed_only()),
        ..Default::default()
    };

    let fetcher = HttpsDataRefFetcher::new();
    let err = VerifiedContext::fetch_report_with_fetcher(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
        &fetcher,
    )
    .await
    .expect_err("fetch_report_with_fetcher must honor discover");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

#[tokio::test]
async fn phase4_ac3_fetch_report_diagnose_honors_discover() {
    let rig = discovery_rig(0xD4).await;
    rig.h
        .seed_revocations(&rig.producer, &rig.producer_fp, &[rig.receipt_time])
        .await;
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default()
            .with_discovery(RevocationDiscovery::producer_signed_only()),
        ..Default::default()
    };

    let (verified, report) = VerifiedContext::fetch_report_diagnose(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect("fetch_report_diagnose never returns Err for a policy-phase failure");
    assert!(
        verified.is_none(),
        "the handle must be withheld when the policy phase fails"
    );
    assert!(
        matches!(
            report.policy_phase_error,
            Some(AcdpError::KeyNotAuthorized(_))
        ),
        "got {:?}",
        report.policy_phase_error
    );
}

/// AC4: under `FailClosed`, a 503 from `/contexts/search` yields
/// `Err(RevocationDiscoveryFailed)` from the four `Err`-propagating entry
/// points, and `VerificationReport::policy_phase_error` from
/// `fetch_report_diagnose`. The harness maps every injected status to
/// wire code `internal_error` → `AcdpError::RegistryInternal`, which is
/// transient — assert transience, not a status-specific variant.
#[tokio::test]
async fn phase4_ac4_fail_closed_503_propagates_as_revocation_discovery_failed() {
    let rig = discovery_rig(0xC4).await;
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default()
            .with_discovery(RevocationDiscovery::producer_signed_only()),
        ..Default::default()
    };
    rig.h
        .set_error("search", axum::http::StatusCode::SERVICE_UNAVAILABLE);

    let err = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect_err("FailClosed must propagate a discovery failure");
    assert!(
        matches!(err, AcdpError::RevocationDiscoveryFailed { .. }),
        "got {err:?}"
    );
    assert!(err.is_transient(), "got {err:?}");

    let err = VerifiedContext::fetch_current_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_lineage_id,
        &policy,
    )
    .await
    .expect_err("fetch_current_with_policy must also propagate");
    assert!(matches!(err, AcdpError::RevocationDiscoveryFailed { .. }));
    assert!(err.is_transient());

    let err =
        VerifiedContext::fetch_report(&rig.client, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect_err("fetch_report must also propagate");
    assert!(matches!(err, AcdpError::RevocationDiscoveryFailed { .. }));
    assert!(err.is_transient());

    let fetcher = HttpsDataRefFetcher::new();
    let err = VerifiedContext::fetch_report_with_fetcher(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
        &fetcher,
    )
    .await
    .expect_err("fetch_report_with_fetcher must also propagate");
    assert!(matches!(err, AcdpError::RevocationDiscoveryFailed { .. }));
    assert!(err.is_transient());

    let (verified, report) = VerifiedContext::fetch_report_diagnose(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect("fetch_report_diagnose never returns Err");
    assert!(verified.is_none());
    match &report.policy_phase_error {
        Some(e @ AcdpError::RevocationDiscoveryFailed { .. }) => assert!(e.is_transient()),
        other => panic!("expected Some(RevocationDiscoveryFailed), got {other:?}"),
    }

    rig.h.clear_error("search");
}

/// AC5: under `ProceedWithKnown`, the same 503 yields `Ok`, verification
/// proceeds on `known` alone, and the failure is retrievable via BOTH
/// `VerifiedContext::revocation_discovery_failure()` and
/// `VerificationReport::revocation_discovery` — never silent.
#[tokio::test]
async fn phase4_ac5_proceed_with_known_surfaces_failure_without_erroring() {
    let rig = discovery_rig(0xC5).await;
    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.on_failure = DiscoveryFailurePolicy::ProceedWithKnown;
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    rig.h
        .set_error("search", axum::http::StatusCode::SERVICE_UNAVAILABLE);

    let verified = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect("ProceedWithKnown must let verification succeed on `known` alone");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
    assert!(
        verified.revocation_discovery_failure().is_some(),
        "the swallowed failure must still be observable on the plain fetch path"
    );

    let (verified2, report) =
        VerifiedContext::fetch_report(&rig.client, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect("ProceedWithKnown must let fetch_report succeed too");
    assert!(verified2.revocation_discovery_failure().is_some());
    match &report.revocation_discovery {
        Some(Err(e)) => assert!(matches!(e, AcdpError::RevocationDiscoveryFailed { .. })),
        other => panic!("expected Some(Err(RevocationDiscoveryFailed)), got {other:?}"),
    }

    rig.h.clear_error("search");
}

/// AC6: union proven. `known` holds an entry irrelevant to the signing
/// key (mirrors `revocation::tests::unrelated_fingerprint_is_inert` —
/// alone it changes nothing), discovery finds the one that actually
/// matches; the merged set is what classification acts on, and
/// `VerificationReport::revocation_discovery` reports `Ok(1)` — discovery
/// output only, never `known`'s count. (A scenario where BOTH entries
/// match and jointly tighten the boundary can only be demonstrated by
/// pushing the union into `KeyNotAuthorized`, which discards the report
/// via the same "no partial state past a failing phase" rule that already
/// applies to every other `verify_retrieved` phase — e.g. `key_status`
/// stays `None` if the signature phase fails after the receipt phase
/// passed. The min-fold itself is already proven directly at the pure-
/// function level by `revocation::tests::earliest_boundary_wins`.)
#[tokio::test]
async fn phase4_ac6_union_of_known_and_discovered_is_merged_before_classification() {
    let rig = discovery_rig(0xC6).await;

    let r1 = KeyRevocation {
        revoked_key_fingerprint: K1_FP.to_string(),
        compromised_since: acdp::time::trunc_ms(rig.receipt_time - chrono::Duration::days(1)),
        reason: Some("AC6: known, deliberately unrelated fingerprint".into()),
        revoked_key_id: Some(format!("{}#unrelated-key", rig.producer_did)),
        revoked_key_controller: rig.agent_id(),
        publisher: rig.agent_id(),
        trust_class: RevocationTrustClass::ProducerSigned,
    };

    // Baseline: `known = [R1]` alone, no discovery — R1's fingerprint
    // doesn't match the signing key at all, so it must be completely inert.
    let known_only = VerificationPolicy {
        revocations: RevocationPolicy::new(vec![r1.clone()]),
        ..Default::default()
    };
    let baseline = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &known_only,
    )
    .await
    .expect("R1 alone must not affect an unrelated signing key");
    assert_eq!(baseline.key_status(), KeyAuthorization::CurrentlyAuthorized);

    // R2 — reachable only via discovery, matches the producer's actual
    // signing key, boundary strictly after the receipt-attested publish
    // time (safe/pre-compromise on its own).
    rig.h
        .seed_revocations(
            &rig.producer,
            &rig.producer_fp,
            &[rig.receipt_time + chrono::Duration::days(5)],
        )
        .await;

    let union_policy = VerificationPolicy {
        revocations: RevocationPolicy::new(vec![r1])
            .with_discovery(RevocationDiscovery::producer_signed_only()),
        ..Default::default()
    };
    let (verified, report) = VerifiedContext::fetch_report(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &union_policy,
    )
    .await
    .expect("union of an inert known entry plus a real discovered one must still verify");
    assert_eq!(
        verified.key_status(),
        KeyAuthorization::HistoricallyAuthorizedPreCompromise,
        "the discovered R2 must have been merged in and applied — the verdict changed \
         from the R1-only baseline above"
    );
    match report.revocation_discovery {
        Some(Ok(outcome)) => {
            assert_eq!(
                outcome.producer_signed, 1,
                "count is discovery output only — must not include `known`'s R1"
            );
            assert_eq!(
                outcome.registry_attested, None,
                "producer_signed_only must never query the registry-attested class"
            );
        }
        other => panic!(
            "expected Some(Ok(DiscoveryOutcome {{ producer_signed: 1, .. }})), got {other:?}"
        ),
    }

    // Second half: prove the merge is a genuine UNION, not "whichever
    // side is non-empty wins". `known` now holds a REVOCATION THAT
    // MATCHES the signing key with a boundary BEFORE the receipt time
    // (alone it would already fail closed); discovery finds R2 again
    // (boundary AFTER the receipt time, individually safe). Only a true
    // union's min-fold correctly fails closed here — a "discovered
    // replaces known" merge would drop R3 and wrongly let this verify,
    // since R2 alone is safe.
    let r3 = KeyRevocation {
        revoked_key_fingerprint: rig.producer_fp.clone(),
        compromised_since: acdp::time::trunc_ms(rig.receipt_time - chrono::Duration::days(1)),
        reason: Some("AC6: known, relevant, earlier boundary than the discovered R2".into()),
        revoked_key_id: Some(format!("{}#key-1", rig.producer_did)),
        revoked_key_controller: rig.agent_id(),
        publisher: rig.agent_id(),
        trust_class: RevocationTrustClass::ProducerSigned,
    };
    let union_with_relevant_known_policy = VerificationPolicy {
        revocations: RevocationPolicy::new(vec![r3])
            .with_discovery(RevocationDiscovery::producer_signed_only()),
        ..Default::default()
    };
    let err = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &union_with_relevant_known_policy,
    )
    .await
    .expect_err(
        "known's earlier boundary must still apply even though discovery also found a \
         later, individually-safe revocation — proves the merge is a union, not a \
         replacement",
    );
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// AC7: `total_timeout` proven two-sided against a `/contexts/search`
/// route sleeping 30s with a 2s `total_timeout`: (i) elapsed >= 2s, (ii)
/// elapsed < 10s — which fails if the per-request `RegistryClient` cap
/// (30s) fired instead — and (iii) the error is `RevocationDiscoveryFailed`
/// whose source names the timeout, not a transport error.
#[tokio::test]
async fn phase4_ac7_total_timeout_bounds_wall_clock_and_names_the_timeout() {
    let rig = discovery_rig(0xC7).await;
    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.total_timeout = std::time::Duration::from_secs(2);
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    rig.h
        .set_delay("search", std::time::Duration::from_secs(30));

    let start = std::time::Instant::now();
    let err = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect_err("discovery must time out against a 30s-delayed search route");
    let elapsed = start.elapsed();

    assert!(
        elapsed >= std::time::Duration::from_secs(2),
        "elapsed = {elapsed:?}, must be at least the 2s total_timeout"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "elapsed = {elapsed:?} — must be well under the per-request RegistryClient cap (30s); \
         a value near 30s means that cap fired instead of total_timeout"
    );
    match &err {
        AcdpError::RevocationDiscoveryFailed { source } => {
            let msg = source.to_string();
            assert!(
                matches!(**source, AcdpError::CrossRegistryResolutionFailed(_))
                    && msg.contains("total_timeout"),
                "source must name the timeout, not a transport error; got {source:?}"
            );
        }
        other => panic!("expected RevocationDiscoveryFailed, got {other:?}"),
    }

    rig.h.clear_delay("search");
}
