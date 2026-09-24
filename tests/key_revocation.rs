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

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use acdp::client::{
    classify_under_revocation, verify_revocation_body, DiscoveryFailurePolicy, HttpsDataRefFetcher,
    KeyAuthorization, ReceiptPolicy, RegistryClient, RevocationCache, RevocationDiscovery,
    RevocationPolicy, VerificationPolicy, VerifiedContext,
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

// ── rev-002 scenarios E/F/G/H: lineage-shaped §7 boundary matrix ────────────
//
// Issue-273/279/284/285 + RFC-ACDP-0014 wave, Phase 5. The plan's own
// text claimed `rev_002_earliest_boundary_across_lineage` "essentially
// already covers" E and `find_revocations_recovers_retracted_predecessor_across_lineage_supersession`
// "essentially already covers" F; direct inspection during
// implementation found both claims too generous — the former exercises
// a structurally different (widening, not narrowing) lineage with
// non-fixture timestamps, and the latter proves discovery/boundary
// correctness but never drives a `classify_under_revocation` verdict —
// so the four tests below are new, dedicated, fixture-driven coverage
// rather than reuses. Both existing tests are left untouched; they
// remain valid, independently useful regression tests of adjacent
// properties.

/// Look up a lineage member's `compromised_since` by its `label`
/// (e.g. "R1", "X", "Y") within `input.revocation_lineage.<lineage>.members`
/// — an array, so it can't be reached by `json_str`'s object-path walk.
/// Reading these live (rather than hand-copying the values into the
/// test bodies below) means a fixture edit to L1/L2/L3's timestamps
/// changes what these tests exercise, matching `rev_002_revocation_from_fixture`'s
/// own rationale.
fn lineage_member_compromised_since<'a>(
    fixture: &'a serde_json::Value,
    lineage: &str,
    label: &str,
) -> &'a str {
    fixture["input"]["revocation_lineage"][lineage]["members"]
        .as_array()
        .unwrap_or_else(|| panic!("rev-002 fixture missing revocation_lineage.{lineage}.members"))
        .iter()
        .find(|m| m["label"] == label)
        .unwrap_or_else(|| panic!("rev-002 fixture {lineage} has no member labeled '{label}'"))
        ["compromised_since"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("rev-002 fixture {lineage}.{label}.compromised_since is not a string")
        })
}

/// Scenario E (RFC-ACDP-0014 §7): lineage L1 — R1 (T1 = 2026-05-01,
/// `key-revocation`) superseded by R2 (T2 = 2026-06-15, also
/// `key-revocation`, same signer class — a NARROWING supersession —
/// `check_revocation_supersession` does not gate on direction, only
/// the consumer-side fold does). A receipt-attested publish at
/// `created_at_by_scenario.E` (>= T1 but < T2) MUST still fail closed,
/// because R2's later boundary never narrows the effective window
/// below T1.
#[tokio::test]
async fn rev_002_e_narrowing_supersession_effective_boundary_stays_t1() {
    use acdp::client::find_revocations;

    let Some(fixture) = rev_002_fixture() else {
        return;
    };
    let revoked_fp = json_str(
        &fixture,
        &["input", "body_under_test", "signer_key_fingerprint"],
    );
    let receipt_time = json_str(
        &fixture,
        &["input", "registry_receipt", "created_at_by_scenario", "E"],
    );
    let t1 = lineage_member_compromised_since(&fixture, "L1", "R1");
    let t2 = lineage_member_compromised_since(&fixture, "L1", "R2");

    let h = LineageServerHarness::start(lifecycle_caps(), false).await;

    let seed = [0xa1u8; 32];
    let producer = Producer::new_did_key(SigningKey::from_bytes(&seed));
    let did =
        acdp::did::key::did_key_from_ed25519(&SigningKey::from_bytes(&seed).verifying_key_bytes());
    let agent_id = AgentDid::new(did);

    let r1_req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("R1: rev-002 scenario E, T1")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": revoked_fp,
            "compromised_since": t1,
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

    // R2: same signer class, later (narrower) boundary T2 — permitted
    // at publish time (RFC-ACDP-0014 §4's supersedes row); the
    // consumer-side monotonicity fold is what actually matters here.
    let r2_req = producer
        .supersede_body(&r1_stored.body)
        .acdp_version("0.3.0")
        .title("R2: supersedes R1, narrows to T2")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": revoked_fp,
            "compromised_since": t2,
        }))
        .build()
        .expect("r2 build");
    h.server
        .publish_verified_did_key(&r2_req, None)
        .expect("r2 publish");

    let client = h.client();
    let mut revs = find_revocations(&client, &h.resolver, &agent_id)
        .await
        .expect("find_revocations");
    assert_eq!(revs.len(), 2);
    revs.sort_by_key(|r| r.compromised_since);
    assert_eq!(revs[0].compromised_since, at(t1));
    assert_eq!(revs[1].compromised_since, at(t2));

    let err = classify_under_revocation(&revs, revoked_fp, Some(at(receipt_time)))
        .expect_err("scenario E: R2's narrower T2 must not shrink the effective window below T1");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// Scenario F (RFC-ACDP-0014 §7): identical to scenario E's lineage
/// L1, but R1 is additionally retracted after R2 supersedes it
/// (`retraction_for_scenario_F`). Builds on the discovery-recovery
/// property `find_revocations_recovers_retracted_predecessor_across_lineage_supersession`
/// already proves (real registry, real retraction, `effective_boundary`
/// resolves to the earlier T) by driving the fixture's own T1/T2/receipt
/// values through to a concrete `classify_under_revocation` verdict — a
/// consumer MUST NOT drop R1 from the fold just because the registry's
/// *served* status for it is now `retracted` rather than `superseded`.
#[tokio::test]
async fn rev_002_f_retracted_predecessor_still_governs_verdict() {
    use acdp::client::find_revocations;
    use acdp::types::lifecycle::{LifecycleEvent, LifecycleEventType};

    let Some(fixture) = rev_002_fixture() else {
        return;
    };
    let revoked_fp = json_str(
        &fixture,
        &["input", "body_under_test", "signer_key_fingerprint"],
    );
    let receipt_time = json_str(
        &fixture,
        &["input", "registry_receipt", "created_at_by_scenario", "F"],
    );
    let t1 = lineage_member_compromised_since(&fixture, "L1", "R1");
    let t2 = lineage_member_compromised_since(&fixture, "L1", "R2");

    let h = LineageServerHarness::start(lifecycle_caps(), true).await;

    let seed = [0xa2u8; 32];
    let producer = Producer::new_did_key(SigningKey::from_bytes(&seed));
    let did =
        acdp::did::key::did_key_from_ed25519(&SigningKey::from_bytes(&seed).verifying_key_bytes());
    let key_id = acdp::did::key::did_key_url(&did).expect("did:key URL");
    let agent_id = AgentDid::new(did);

    let r1_req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("R1: rev-002 scenario F, T1, later retracted")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": revoked_fp,
            "compromised_since": t1,
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

    let r2_req = producer
        .supersede_body(&r1_stored.body)
        .acdp_version("0.3.0")
        .title("R2: supersedes R1, narrows to T2")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": revoked_fp,
            "compromised_since": t2,
        }))
        .build()
        .expect("r2 build");
    h.server
        .publish_verified_did_key(&r2_req, None)
        .expect("r2 publish");

    let event = LifecycleEvent::new(
        "018f6d0a-00f4-4c4d-9e1f-3a5b7c9d1e31",
        r1_resp.ctx_id.clone(),
        LifecycleEventType::Retracted,
        chrono::Utc::now(),
        agent_id.clone(),
        Some("R1 retracted after being superseded by R2 (rev-002 scenario F)".into()),
    )
    .expect("valid event")
    .sign_with(SigningKey::from_bytes(&seed), key_id)
    .expect("signed event");
    h.server
        .retract_unverified_for_tests(&event, None)
        .expect("retract");

    // If retraction regressed to a no-op, R1 would still be visible via
    // the `superseded` search pass and this test would keep passing
    // vacuously — assert the served status actually flipped.
    let r1_after_retract = h.server.store().get(&r1_resp.ctx_id).unwrap().unwrap();
    assert_eq!(r1_after_retract.registry_state.status, Status::Retracted);

    let client = h.client();
    let mut revs = find_revocations(&client, &h.resolver, &agent_id)
        .await
        .expect("find_revocations must recover the retracted predecessor");
    assert_eq!(revs.len(), 2);
    revs.sort_by_key(|r| r.compromised_since);
    assert_eq!(revs[0].compromised_since, at(t1));
    assert_eq!(revs[1].compromised_since, at(t2));

    let err = classify_under_revocation(&revs, revoked_fp, Some(at(receipt_time))).expect_err(
        "scenario F: retraction of R1 must not remove it from the fold — the effective \
         boundary stays T1",
    );
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// Scenario G (RFC-ACDP-0014 §7): lineage L2 — R1-prime (T1,
/// `key-revocation`) "superseded" by X, a NON-revocation (`analysis`)
/// context under the same `agent_id`. This repo's own registry
/// already rejects such a publish unconditionally at every
/// `acdp_version` (`check_revocation_supersession` Arm 3, above) — a
/// protection the fixture itself notes only some registries implement
/// ("every registry below acdp_version 0.5.0 accepts this publish").
/// Scenario G exists precisely because RFC-ACDP-0014 §7's consumer-side
/// defence MUST NOT assume that protection exists on every registry a
/// context might be discovered through — so this test constructs the
/// otherwise-unpublishable lineage directly against the store
/// (`RegistryStore::put`/`mark_superseded`, bypassing
/// `check_revocation_supersession` entirely) to model a registry that
/// never closed this gap, then proves real client-side discovery and
/// the fold still fail closed against it.
#[tokio::test]
async fn rev_002_g_non_revocation_supersession_does_not_disarm() {
    use acdp::client::find_revocations;

    let Some(fixture) = rev_002_fixture() else {
        return;
    };
    let revoked_fp = json_str(
        &fixture,
        &["input", "body_under_test", "signer_key_fingerprint"],
    );
    let receipt_time = json_str(
        &fixture,
        &["input", "registry_receipt", "created_at_by_scenario", "G"],
    );

    let h = LineageServerHarness::start(lifecycle_caps(), false).await;

    let seed = [0xa3u8; 32];
    let producer = Producer::new_did_key(SigningKey::from_bytes(&seed));
    let did =
        acdp::did::key::did_key_from_ed25519(&SigningKey::from_bytes(&seed).verifying_key_bytes());
    let agent_id = AgentDid::new(did);

    let r1_prime_ctx_id =
        CtxId("acdp://registry.example.com/9f1e2d3c-5a6b-4c7d-8e9f-0a1b2c3d4e60".into());
    let lineage_id = derive_lineage_id(&r1_prime_ctx_id);

    let r1_prime_req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("R1-prime: rev-002 scenario G, T1")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": revoked_fp,
            "compromised_since": "2026-05-01T00:00:00.000Z",
        }))
        .build()
        .expect("r1-prime build");
    let r1_prime_body = Body::from_publish_request(
        &r1_prime_req,
        r1_prime_ctx_id.clone(),
        lineage_id.clone(),
        "registry.example.com",
        at("2026-05-02T08:00:00.000Z"),
    );

    let x_ctx_id = CtxId("acdp://registry.example.com/9f1e2d3c-5a6b-4c7d-8e9f-0a1b2c3d4e61".into());
    let x_req = producer
        .supersede_body(&r1_prime_body)
        .acdp_version("0.3.0")
        .title("X: a non-revocation superseding R1-prime")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("x build");
    let x_body = Body::from_publish_request(
        &x_req,
        x_ctx_id,
        lineage_id,
        "registry.example.com",
        at("2026-05-10T00:00:00.000Z"),
    );

    h.server
        .store()
        .put(r1_prime_body)
        .expect("put r1-prime (bypassing check_revocation_supersession)");
    h.server
        .store()
        .put(x_body)
        .expect("put x (bypassing check_revocation_supersession)");
    h.server
        .store()
        .mark_superseded(&r1_prime_ctx_id)
        .expect("mark r1-prime superseded");

    let client = h.client();
    let revs = find_revocations(&client, &h.resolver, &agent_id)
        .await
        .expect("find_revocations must recover R1-prime, dropping X");
    assert_eq!(
        revs.len(),
        1,
        "X is not a key-revocation — it must be dropped by verify_revocation_body's type \
         check, not silently trusted as a disarming successor"
    );
    assert_eq!(revs[0].compromised_since, at("2026-05-01T00:00:00.000Z"));
    assert_eq!(revs[0].revoked_key_fingerprint, revoked_fp);

    let err = classify_under_revocation(&revs, revoked_fp, Some(at(receipt_time))).expect_err(
        "scenario G: a non-revocation supersession must not disarm the revocation still \
         governing the lineage",
    );
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// Scenario H (RFC-ACDP-0014 §7): lineage L3 — R1-triple-prime (T1,
/// `key-revocation`) superseded by Y, a WIDENING revocation (T4 =
/// 2026-04-01, earlier than T1) published under the §10 INTERIM form
/// `acdp:key-revocation`. Unlike scenario G's X, Y IS itself a
/// revocation — just spelled the pre-0.3.0 way — so
/// `check_revocation_supersession` Arm 3 does not reject it
/// (`is_key_revocation()` treats both forms as equivalent); this
/// publishes normally, through the real registry, with no store
/// bypass. The point of this scenario is that the §7 fold MUST count
/// Y's T4, not disregard it as if it were a disarming non-revocation:
/// a receipt-attested publish at `created_at_by_scenario.H` (>= T4 but
/// < T1) MUST fail closed.
#[tokio::test]
async fn rev_002_h_interim_form_widening_successor_is_counted() {
    use acdp::client::find_revocations;
    use acdp::types::revocation::effective_boundary;

    let Some(fixture) = rev_002_fixture() else {
        return;
    };
    let revoked_fp = json_str(
        &fixture,
        &["input", "body_under_test", "signer_key_fingerprint"],
    );
    let receipt_time = json_str(
        &fixture,
        &["input", "registry_receipt", "created_at_by_scenario", "H"],
    );

    let h = LineageServerHarness::start(lifecycle_caps(), false).await;

    let seed = [0xa4u8; 32];
    let producer = Producer::new_did_key(SigningKey::from_bytes(&seed));
    let did =
        acdp::did::key::did_key_from_ed25519(&SigningKey::from_bytes(&seed).verifying_key_bytes());
    let agent_id = AgentDid::new(did);

    let r1_req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("R1-triple-prime: rev-002 scenario H, T1")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": revoked_fp,
            "compromised_since": "2026-05-01T00:00:00.000Z",
        }))
        .build()
        .expect("r1-triple-prime build");
    let r1_resp = h
        .server
        .publish_verified_did_key(&r1_req, None)
        .expect("r1-triple-prime publish");
    let r1_stored = h
        .server
        .store()
        .get(&r1_resp.ctx_id)
        .expect("get")
        .expect("r1-triple-prime present");

    // Y: the §10 interim form, widening the boundary to T4. Arm 3 does
    // not fire — `is_key_revocation()` treats this custom type as
    // equivalent to the standard one — so this is a normal, accepted
    // publish (same signer class as R1-triple-prime).
    let y_req = producer
        .supersede_body(&r1_stored.body)
        .acdp_version("0.3.0")
        .title("Y: interim-form widening successor")
        .context_type(ContextType::Custom(
            ContextType::KEY_REVOCATION_INTERIM.into(),
        ))
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": revoked_fp,
            "compromised_since": "2026-04-01T00:00:00.000Z",
        }))
        .build()
        .expect("y build");
    h.server
        .publish_verified_did_key(&y_req, None)
        .expect("y publish");

    let client = h.client();
    let revs = find_revocations(&client, &h.resolver, &agent_id)
        .await
        .expect("find_revocations must recover both members, interim form included");
    assert_eq!(revs.len(), 2);
    assert_eq!(
        effective_boundary(&revs, revoked_fp),
        Some(at("2026-04-01T00:00:00.000Z")),
        "scenario H: Y's interim-typed widening successor must set the effective boundary"
    );

    let err = classify_under_revocation(&revs, revoked_fp, Some(at(receipt_time))).expect_err(
        "scenario H: the interim-typed widening successor is itself a revocation and MUST \
         be counted, not disregarded as a disarming non-revocation",
    );
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

// ── rev-004: interim-form retrieval unaffected by the (0.5.0) retirement
// rule (Phase 6) ─────────────────────────────────────────────────────────
//
// RFC-ACDP-0014 §10's (0.5.0) rule binds PUBLISH time only ("MUST reject a
// NEW publication... though it continues serving bodies already published
// under it") and creates no retroactive retrieval-time obligation. rev-003
// Q (`tests/key_revocation_publish_gate.rs`) pins the publish-time half;
// these three tests pin the other, easily-overlooked half — that nothing
// about adopting the >= 0.5.0 rejection licenses a registry to filter or
// alter retrieval of a body that already exists on the record, across
// direct GET, search, and lineage walk.

/// Seeds the rev-004 fixture's `existing_context` — an interim-typed
/// (`acdp:key-revocation`) body, `acdp_version: "0.2.0"` (what the
/// producer's registry advertised at ORIGINAL publish time, pre-0.3.0),
/// inserted directly into the store rather than published through this
/// 0.5.0-advertising server: a fresh publish of this shape would itself
/// be rejected by the §10 retirement gate (rev-003 Q), which is exactly
/// the point — this body predates that gate, and retrieval must not
/// retroactively apply it.
async fn rev_004_seed_interim_body() -> (LineageServerHarness, CtxId, LineageId, AgentDid, Body) {
    let caps = CapabilitiesDocument {
        acdp_version: "0.5.0".into(),
        ..lifecycle_caps()
    };
    let h = LineageServerHarness::start(caps, false).await;

    let seed = [0xb1u8; 32];
    let producer = Producer::new_did_key(SigningKey::from_bytes(&seed));
    let did =
        acdp::did::key::did_key_from_ed25519(&SigningKey::from_bytes(&seed).verifying_key_bytes());
    let agent_id = AgentDid::new(did);

    let fp = fingerprint_ed25519(&SigningKey::from_bytes(&seed).verifying_key_bytes());
    let req = producer
        .publish_request()
        .acdp_version("0.2.0")
        .title("Key revocation — interim form, published pre-0.3.0")
        .context_type(ContextType::Custom(
            ContextType::KEY_REVOCATION_INTERIM.into(),
        ))
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": fp,
            "compromised_since": "2026-01-15T00:00:00.000Z",
        }))
        .build()
        .expect("valid interim-form request at 0.2.0");

    let ctx_id = CtxId("acdp://registry.example.com/9f1e2d3c-5a6b-4c7d-8e9f-0a1b2c3d4e80".into());
    let lineage_id = derive_lineage_id(&ctx_id);
    let body = Body::from_publish_request(
        &req,
        ctx_id.clone(),
        lineage_id.clone(),
        "registry.example.com",
        at("2026-01-15T00:05:00.000Z"),
    );
    h.server
        .store()
        .put(body.clone())
        .expect("seed the pre-existing interim-form body");

    (h, ctx_id, lineage_id, agent_id, body)
}

/// rev-004 A: direct retrieval succeeds, unchanged — same type
/// (`acdp:key-revocation`, not rewritten or rejected), same content_hash,
/// same signature, and `acdp_version` still `0.2.0` (what the producer's
/// registry advertised at ORIGINAL publish time — the fixture's own
/// point is that this field is never rewritten on registry upgrade).
#[tokio::test]
async fn rev_004_a_direct_retrieval_succeeds_unchanged() {
    let (h, ctx_id, _lineage_id, _agent_id, seeded) = rev_004_seed_interim_body().await;
    let client = h.client();

    let ctx = client
        .retrieve(&ctx_id)
        .await
        .expect("GET must still succeed for a pre-existing interim-form body");
    assert_eq!(
        ctx.body.context_type,
        ContextType::Custom(ContextType::KEY_REVOCATION_INTERIM.into()),
        "the stored type must not be rewritten to the standard form"
    );
    assert_eq!(ctx.body.ctx_id, ctx_id);
    assert_eq!(ctx.body.content_hash, seeded.content_hash);
    assert_eq!(ctx.body.signature, seeded.signature);
    assert_eq!(
        ctx.body.acdp_version.as_deref(),
        Some("0.2.0"),
        "the body's own acdp_version field must stay what it was published under, \
         regardless of what the serving registry advertises today"
    );
}

/// rev-004 B: discoverable via search on its actual type string, not
/// filtered. This registry advertises `acdp-registry-discovery`
/// (`lifecycle_caps()`), so the endpoint is live and must not hide the
/// body merely because that type string is no longer accepted for new
/// publications.
#[tokio::test]
async fn rev_004_b_discoverable_via_search_on_its_actual_type() {
    let (h, ctx_id, _lineage_id, agent_id, _seeded) = rev_004_seed_interim_body().await;
    let client = h.client();

    let params = acdp::types::SearchParamsBuilder::new()
        .context_type(ContextType::KEY_REVOCATION_INTERIM)
        .agent_id(agent_id.as_str())
        .limit(100)
        .build();
    let resp = client.search(&params).await.expect("search");
    assert!(
        resp.matches.iter().any(|m| m.ctx_id == ctx_id),
        "search on the body's actual (interim) type string must still find it"
    );
}

/// rev-004 C: included in a lineage walk, not skipped — the property
/// rev-002 scenario H's fold depends on: a consumer can only count an
/// interim-typed member's `compromised_since` if the registry's lineage
/// walk actually returns that member in the first place.
#[tokio::test]
async fn rev_004_c_included_in_lineage_walk() {
    let (h, ctx_id, lineage_id, _agent_id, _seeded) = rev_004_seed_interim_body().await;
    let client = h.client();

    let members = client
        .lineage(&lineage_id)
        .await
        .expect("GET /lineages/{id} must still succeed");
    assert!(
        members.iter().any(|m| m.body.ctx_id == ctx_id
            && m.body.context_type
                == ContextType::Custom(ContextType::KEY_REVOCATION_INTERIM.into())),
        "the lineage walk must include the interim-typed member, unfiltered"
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
    /// Issue #265: remaining number of responses for which the
    /// `"search"` route should fabricate a non-null `next_cursor`
    /// (with empty `matches`) instead of delegating to the real
    /// server, decremented on each such response. 0 (the `Default`
    /// value, same as the other three fields) means "fabricate
    /// nothing" — every existing test, which never calls
    /// [`LineageServerHarness::set_pages`], is unaffected by
    /// construction. Meaningful only for the `"search"` route; other
    /// routes' handlers never read it.
    fabricated_pages: std::sync::atomic::AtomicUsize,
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

    /// Host a REGISTRY DID document at `/.well-known/did.json` WITHOUT
    /// enabling a receipt signer — for issue #260's `CrossRegistryResolver`
    /// tests, which need `resolve()`'s step 3b (registry DID → DID
    /// document resolution) to succeed but must NOT have every publish
    /// carry a registry receipt: a receipt's `registry_did` is minted
    /// once and cross-checked against the SERVING client's
    /// `.authority()` (RFC-ACDP-0010's serving-authority binding), which
    /// a vantage-binding test deliberately varies across calls (see
    /// `cache_ac8_marker_is_per_vantage`'s own doc for the same
    /// precedent). [`Self::with_receipt_signer`] is the right choice
    /// when a test actually wants receipts; this is the right choice
    /// when it only needs the registry DID document served.
    fn with_registry_did_document(mut self, doc: serde_json::Value) -> Self {
        self.registry_did_doc = Some(doc);
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
                            // Issue #265: applied AFTER `intercept()`'s hit
                            // count, so a fabricated page still counts as a
                            // request. Guarded `fetch_update` decrement
                            // (not load-then-store): this route is hit
                            // concurrently by `tokio::try_join!`'d lookups
                            // (`acdp-client::verified`'s discovery block).
                            let fabricated = state.fabricated_pages.fetch_update(
                                std::sync::atomic::Ordering::SeqCst,
                                std::sync::atomic::Ordering::SeqCst,
                                |n| if n > 0 { Some(n - 1) } else { None },
                            );
                            if fabricated.is_ok() {
                                // Shaped like a genuine `SearchResponse`
                                // minus the matches: `find_revocations`
                                // only needs a valid body with a non-null
                                // `next_cursor` to keep paging.
                                let resp = acdp::types::SearchResponse {
                                    matches: Vec::new(),
                                    total_estimate: None,
                                    next_cursor: Some("harness-fabricated-page".to_string()),
                                };
                                return Json(resp).into_response();
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

    /// From the next request onward, the `"search"` route fabricates a
    /// non-null `next_cursor` (with empty `matches`) for the next `n`
    /// responses — each still counted as a hit — before the
    /// `(n+1)`-th request delegates to the real server exactly as
    /// today. Issue #265: lets `MAX_SEARCH_PAGES` page-cap exhaustion
    /// be reached through this harness's real, persisted
    /// `RegistryServer<InMemoryStore>` instead of a hand-built mock
    /// router.
    fn set_pages(&self, route: &str, n: usize) {
        self.route_state(route)
            .fabricated_pages
            .store(n, std::sync::atomic::Ordering::SeqCst);
    }

    /// Undo [`Self::set_pages`].
    fn clear_pages(&self, route: &str) {
        self.route_state(route)
            .fabricated_pages
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

/// Issue #265 — `LineageServerHarness::set_pages("search", n)` makes
/// exactly the next `n` `/contexts/search` responses fabricate a
/// non-null `next_cursor` with empty `matches`, each still counted as
/// a hit (AC1, AC2), and the `(n+1)`-th request delegates to the real,
/// persisted `RegistryServer<InMemoryStore>` exactly as it did before
/// this field existed (AC5: no seeded data here, so the real page is
/// an empty, cursor-less result, matching what this route has always
/// returned for an empty store).
#[tokio::test]
async fn harness_set_pages_fabricates_exact_page_count_and_counts_hits() {
    let h = LineageServerHarness::start(caps(), false).await;
    let client = h.client();
    let params = acdp::types::SearchParams::default();

    h.set_pages("search", 3);
    for i in 0..3 {
        let resp = client
            .search(&params)
            .await
            .unwrap_or_else(|e| panic!("fabricated page #{i}: {e:?}"));
        assert!(
            resp.matches.is_empty(),
            "fabricated page #{i} must carry no matches"
        );
        assert!(
            resp.next_cursor.is_some(),
            "fabricated page #{i} must carry a non-null next_cursor"
        );
    }

    // The 4th request must NOT fabricate again — it delegates to the
    // real (empty) store.
    let resp = client.search(&params).await.expect("real page");
    assert!(resp.matches.is_empty());
    assert!(
        resp.next_cursor.is_none(),
        "the (n+1)-th request must delegate to the real server, not fabricate again"
    );

    assert_eq!(
        h.hits("search"),
        4,
        "the 3 fabricated pages plus the 1 real delegated page must all count as hits (AC2)"
    );

    // `clear_pages` undoes a still-outstanding counter; harmless here
    // (already at 0) but exercises the accessor pair symmetrically
    // with `clear_error`/`clear_delay`.
    h.clear_pages("search");
    let resp = client.search(&params).await.expect("real page after clear");
    assert!(resp.next_cursor.is_none());
    assert_eq!(h.hits("search"), 5);
}

/// Issue #265 — `find_revocations`'s `MAX_SEARCH_PAGES` (10) page-cap
/// exhaustion, reached through the REAL harness (a genuine, persisted
/// `RegistryServer<InMemoryStore>`) rather than one of the hand-built
/// mock routers above (`find_revocations_errors_on_page_cap_exhaustion_with_cursor_remaining`,
/// `find_revocations_exactly_at_page_cap_with_no_trailing_cursor_is_ok`).
/// `set_pages("search", 10)` fabricates a `next_cursor` for the first
/// 10 requests the (type_form="key-revocation", status="active") pass
/// makes — `find_revocations` tries 6 `(type_form, status)` pairs in a
/// fixed order and this is the first, so all 10 fabricated pages are
/// consumed by it alone, with a cursor still remaining on the 10th —
/// genuine truncation, not completion.
#[tokio::test]
async fn find_revocations_page_cap_exhaustion_through_real_harness() {
    use acdp::client::find_revocations;

    let h = LineageServerHarness::start(caps(), false).await;
    // MAX_SEARCH_PAGES = 10 (kept in lockstep with
    // crates/acdp-client/src/revocation.rs; not itself exported for
    // tests to reference).
    h.set_pages("search", 10);
    let client = h.client();

    let err = find_revocations(&client, &h.resolver, &AgentDid::new(LOCAL_PRODUCER_DID))
        .await
        .expect_err("page-cap exhaustion through the real harness must be a hard error");
    assert!(
        matches!(err, AcdpError::SearchTruncated(_)),
        "expected SearchTruncated, got {err:?}"
    );
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
/// `fetch_current` hardcode the default policy — LIM-2, out of scope by
/// design. LIM-1, `CrossRegistryResolver` having no policy-injection
/// point, was closed by issue #260 — see the `resolver_ac*` tests below.)
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

// ── issue #258 — combined revocation-discovery request/byte budget ────────
//
// All tests below reuse `discovery_rig` with NO revocations seeded, so
// every discovery run is a "zero-match" search: `find_revocations` issues
// exactly 6 `/contexts/search` requests (2 type_forms x 3 statuses, no
// candidates, no retrieves, no lineage walks) and
// `find_registry_attested_revocations` issues exactly 1 `/.well-known/
// acdp.json` fetch plus 6 more searches — verified empirically against
// this harness before these numbers were hardcoded below. `hits("context")`
// also ticks up by 1 per `fetch_with_policy` call, but that single hit is
// `VerifiedContext::fetch_with_policy`'s OWN top-level retrieve of the
// target context through the CALLER's client, never the budget-scoped
// clone `verify_retrieved` builds for discovery — so it is deliberately
// excluded from every budgeted-total assertion below (folding it in would
// make the "combined ceiling" assertions off-by-one and, worse, wrongly
// imply retrieval of the target itself is charged to the discovery
// budget).

/// AC1: `RevocationDiscovery` is still `Copy` after adding the two budget
/// fields — both are `Copy` types, so this is a compile-time proof, not a
/// runtime one. (`#[non_exhaustive]` and "no `Default` impl" are also
/// unchanged, but those are load-bearing on the *absence* of code — the
/// type still has no `Default` impl and the module still compiles with
/// only the two named constructors building it — rather than something a
/// runtime assertion can exercise.)
#[test]
fn budget_ac1_revocation_discovery_still_copy() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<RevocationDiscovery>();
    // Exercise the Copy path directly: using `discovery` again after
    // passing the first copy by value would be a compile error if this
    // type had silently become `Clone`-only.
    let discovery = RevocationDiscovery::producer_signed_only();
    let _copy1 = discovery;
    let _copy2 = discovery;
    assert_eq!(discovery.max_requests, None);
    assert_eq!(discovery.max_bytes, None);
}

/// AC2: with both `max_requests` and `max_bytes` left `None` (what both
/// named constructors set), request counts are byte-identical to the
/// pre-#258 behavior — exact counts, not `> 0`.
#[tokio::test]
async fn budget_ac2_none_none_matches_pre_258_request_counts() {
    let rig = discovery_rig(0xB2).await;
    let before_search = rig.h.hits("search");
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default()
            .with_discovery(RevocationDiscovery::producer_signed_only()),
        ..Default::default()
    };
    let verified = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect("unbudgeted zero-match discovery must succeed exactly as before #258");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
    assert_eq!(
        rig.h.hits("search") - before_search,
        6,
        "producer_signed_only() with no budget must issue exactly 6 searches \
         (2 type_forms x 3 statuses), unchanged from v0.13.0"
    );

    let rig2 = discovery_rig(0xB3).await;
    let before_search2 = rig2.h.hits("search");
    let before_caps2 = rig2.h.hits("acdp_json");
    let policy2 = VerificationPolicy {
        revocations: RevocationPolicy::default()
            .with_discovery(RevocationDiscovery::all_trust_classes()),
        ..Default::default()
    };
    let verified2 = VerifiedContext::fetch_with_policy(
        &rig2.client,
        &rig2.h.resolver,
        &rig2.target_ctx_id,
        &policy2,
    )
    .await
    .expect("unbudgeted zero-match dual discovery must succeed exactly as before #258");
    assert_eq!(
        verified2.key_status(),
        KeyAuthorization::CurrentlyAuthorized
    );
    assert_eq!(
        rig2.h.hits("search") - before_search2,
        12,
        "all_trust_classes() with no budget must issue exactly 12 searches \
         (6 per lookup), unchanged from v0.13.0"
    );
    assert_eq!(
        rig2.h.hits("acdp_json") - before_caps2,
        1,
        "the registry-attested lookup's single unconditional capabilities() \
         fetch must be unaffected by the (unset) budget"
    );
}

/// AC3 (load-bearing — the test that distinguishes a combined budget from
/// two per-lookup budgets): the SAME `max_requests: Some(N)` must yield
/// the same total ceiling whether `include_registry_attested` is `false`
/// or `true`. Natural (unbudgeted) totals are 6 requests single-lookup and
/// 13 (12 search + 1 caps) dual-lookup — both well above `N = 4` — so if
/// discovery instead handed each lookup its OWN budget of 4, the dual run
/// would observe up to 8 requests, not <= 4. See probe (b) in the
/// falsifiability tests below for the mutation that turns this red.
#[tokio::test]
async fn budget_ac3_combined_ceiling_not_doubled_by_include_registry_attested() {
    const N: usize = 4;

    let rig = discovery_rig(0xB4).await;
    let before_search = rig.h.hits("search");
    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.max_requests = Some(NonZeroUsize::new(N).unwrap());
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    let err = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect_err("max_requests: Some(4) must exhaust before the natural 6 searches complete");
    assert!(
        matches!(err, AcdpError::RevocationDiscoveryFailed { .. }),
        "got {err:?}"
    );
    let single_total = rig.h.hits("search") - before_search;
    assert_eq!(
        single_total, N,
        "single-lookup total must be exactly N — check-before-issue is exact here"
    );

    let rig2 = discovery_rig(0xB5).await;
    let before_search2 = rig2.h.hits("search");
    let before_caps2 = rig2.h.hits("acdp_json");
    let mut discovery2 = RevocationDiscovery::all_trust_classes();
    discovery2.max_requests = Some(NonZeroUsize::new(N).unwrap());
    let policy2 = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery2),
        ..Default::default()
    };
    let err2 = VerifiedContext::fetch_with_policy(
        &rig2.client,
        &rig2.h.resolver,
        &rig2.target_ctx_id,
        &policy2,
    )
    .await
    .expect_err("max_requests: Some(4) must exhaust before the natural 13 requests complete");
    assert!(matches!(err2, AcdpError::RevocationDiscoveryFailed { .. }));
    let dual_total =
        (rig2.h.hits("search") - before_search2) + (rig2.h.hits("acdp_json") - before_caps2);
    assert!(
        dual_total <= N,
        "dual-lookup total ({dual_total}) must be <= N ({N}) — a combined budget, \
         not one ceiling per lookup (which would allow up to 2N = {})",
        2 * N
    );
}

/// AC7: check-before-issue is proven both ways. Single-lookup (serial,
/// `include_registry_attested: false`): `hits()` total is exactly `K`.
/// Both-classes (concurrent under `try_join!`): `hits()` total is `<= K`
/// and never `K + 1` — the weaker bound is required because `try_join!`
/// cancels the sibling future the instant one arm errors, so a request
/// whose slot was already reserved can be dropped before the server
/// records it. Uses a different K than AC3 to keep the two tests
/// independent.
#[tokio::test]
async fn budget_ac7_check_before_issue_exact_single_bounded_dual() {
    const K: usize = 3;

    let rig = discovery_rig(0xB6).await;
    let before_search = rig.h.hits("search");
    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.max_requests = Some(NonZeroUsize::new(K).unwrap());
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    VerifiedContext::fetch_with_policy(&rig.client, &rig.h.resolver, &rig.target_ctx_id, &policy)
        .await
        .expect_err("K=3 must exhaust before the natural 6 searches complete");
    assert_eq!(
        rig.h.hits("search") - before_search,
        K,
        "single-lookup, serial requests: hits() must be exactly K"
    );

    let rig2 = discovery_rig(0xB7).await;
    let before_search2 = rig2.h.hits("search");
    let before_caps2 = rig2.h.hits("acdp_json");
    let mut discovery2 = RevocationDiscovery::all_trust_classes();
    discovery2.max_requests = Some(NonZeroUsize::new(K).unwrap());
    let policy2 = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery2),
        ..Default::default()
    };
    VerifiedContext::fetch_with_policy(
        &rig2.client,
        &rig2.h.resolver,
        &rig2.target_ctx_id,
        &policy2,
    )
    .await
    .expect_err("K=3 must exhaust before the natural 13 requests complete");
    let dual_total =
        (rig2.h.hits("search") - before_search2) + (rig2.h.hits("acdp_json") - before_caps2);
    assert!(
        dual_total <= K,
        "both-classes, concurrent requests: hits() ({dual_total}) must be <= K ({K})"
    );
}

/// A dedicated `max_bytes`-only exhaustion test (no `max_requests` set):
/// with `max_bytes: Some(1)`, the FIRST search response's bytes already
/// exceed the budget, so the SECOND check-before-issue call must refuse
/// before a second request is ever sent.
#[tokio::test]
async fn budget_max_bytes_alone_exhausts_before_second_request() {
    let rig = discovery_rig(0xB8).await;
    let before_search = rig.h.hits("search");
    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.max_bytes = Some(1);
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    let err = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect_err("max_bytes: Some(1) must exhaust after the first response is read");
    match &err {
        AcdpError::RevocationDiscoveryFailed { source } => {
            assert!(
                matches!(**source, AcdpError::RevocationDiscoveryBudgetExceeded(_)),
                "got {source:?}"
            );
            assert!(source.to_string().contains("max_bytes"), "got {source}");
        }
        other => panic!("expected RevocationDiscoveryFailed, got {other:?}"),
    }
    assert_eq!(
        rig.h.hits("search") - before_search,
        1,
        "exactly one search must be issued before the byte budget is observed as exhausted"
    );
}

/// AC4 + AC6: exhaustion under `FailClosed` returns
/// `Err(RevocationDiscoveryFailed { source })` where `source` is
/// `AcdpError::RevocationDiscoveryBudgetExceeded`, from all four
/// `Err`-propagating entry points, `VerificationReport::policy_phase_error`
/// from `fetch_report_diagnose`, and the error (both the wrapper and the
/// inner `source`) is NEVER transient — unlike the 503 case covered by
/// `phase4_ac4_fail_closed_503_propagates_as_revocation_discovery_failed`.
#[tokio::test]
async fn budget_ac4_ac6_fail_closed_propagates_and_is_not_transient() {
    let rig = discovery_rig(0xB9).await;
    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.max_requests = Some(NonZeroUsize::new(2).unwrap());
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };

    fn assert_budget_failure(err: &AcdpError) {
        match err {
            AcdpError::RevocationDiscoveryFailed { source } => {
                assert!(
                    matches!(**source, AcdpError::RevocationDiscoveryBudgetExceeded(_)),
                    "got {source:?}"
                );
            }
            other => panic!("expected RevocationDiscoveryFailed, got {other:?}"),
        }
        assert!(
            !err.is_transient(),
            "budget exhaustion must never be transient; got {err:?}"
        );
    }

    let err = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect_err("fetch_with_policy must propagate budget exhaustion");
    assert_budget_failure(&err);

    let err = VerifiedContext::fetch_current_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_lineage_id,
        &policy,
    )
    .await
    .expect_err("fetch_current_with_policy must also propagate");
    assert_budget_failure(&err);

    let err =
        VerifiedContext::fetch_report(&rig.client, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect_err("fetch_report must also propagate");
    assert_budget_failure(&err);

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
    assert_budget_failure(&err);

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
        Some(e @ AcdpError::RevocationDiscoveryFailed { .. }) => assert_budget_failure(e),
        other => panic!("expected Some(RevocationDiscoveryFailed), got {other:?}"),
    }
}

/// AC5: under `ProceedWithKnown`, budget exhaustion yields `Ok`,
/// verification proceeds on `known` alone, and the failure is retrievable
/// from BOTH `VerifiedContext::revocation_discovery_failure()` and
/// `VerificationReport::revocation_discovery` — never silent.
#[tokio::test]
async fn budget_ac5_proceed_with_known_surfaces_failure_without_erroring() {
    let rig = discovery_rig(0xBA).await;
    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.max_requests = Some(NonZeroUsize::new(2).unwrap());
    discovery.on_failure = DiscoveryFailurePolicy::ProceedWithKnown;
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };

    let verified = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect("ProceedWithKnown must let verification succeed on `known` alone");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
    let failure = verified
        .revocation_discovery_failure()
        .expect("the swallowed budget failure must still be observable");
    match failure {
        AcdpError::RevocationDiscoveryFailed { source } => {
            assert!(matches!(
                **source,
                AcdpError::RevocationDiscoveryBudgetExceeded(_)
            ));
        }
        other => panic!("expected RevocationDiscoveryFailed, got {other:?}"),
    }

    let (verified2, report) =
        VerifiedContext::fetch_report(&rig.client, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect("ProceedWithKnown must let fetch_report succeed too");
    assert!(verified2.revocation_discovery_failure().is_some());
    match &report.revocation_discovery {
        Some(Err(e)) => match e {
            AcdpError::RevocationDiscoveryFailed { source } => {
                assert!(matches!(
                    **source,
                    AcdpError::RevocationDiscoveryBudgetExceeded(_)
                ));
            }
            other => panic!("expected RevocationDiscoveryFailed, got {other:?}"),
        },
        other => panic!("expected Some(Err(RevocationDiscoveryFailed)), got {other:?}"),
    }
}

/// AC8: the caller's ORIGINAL `RegistryClient` carries no budget. A
/// budget is attached only to the discovery-scoped clone `verify_retrieved`
/// builds internally, so a plain `retrieve` issued directly on `rig.client`
/// AFTER an exhausted discovery must succeed — no cross-contamination.
#[tokio::test]
async fn budget_ac8_original_client_carries_no_budget() {
    let rig = discovery_rig(0xBB).await;
    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.max_requests = Some(NonZeroUsize::new(1).unwrap());
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    VerifiedContext::fetch_with_policy(&rig.client, &rig.h.resolver, &rig.target_ctx_id, &policy)
        .await
        .expect_err("max_requests: Some(1) must exhaust against a 6-search natural total");

    // The ORIGINAL client — never handed to `with_discovery_budget` —
    // must still work normally after the exhausted discovery above.
    let ctx = rig
        .client
        .retrieve(&rig.target_ctx_id)
        .await
        .expect("the caller's original client must carry no budget at all");
    assert_eq!(ctx.body.ctx_id, rig.target_ctx_id);
}

/// M1 (verification-gap closure): every budget test above reuses
/// `discovery_rig` with NO revocations seeded, so discovery only ever
/// issues `search` (`hits("context")` and `hits("lineage")` never move)
/// — deleting `check_discovery_budget()?` from `RegistryClient::retrieve`
/// or `RegistryClient::lineage` leaves the whole suite green. This test
/// seeds exactly one revocation so `find_revocations` actually retrieves
/// the matching candidate (`client.retrieve`, the "context" route) AND
/// walks its lineage (`client.lineage`, the "lineage" route), and picks
/// `max_requests` to land exactly on the boundary between "the retrieve
/// got through" and "the lineage walk was refused before it was sent".
///
/// Natural request order for one producer-signed match under
/// `producer_signed_only()`: the double loop tries all 2 type_forms x 3
/// statuses unconditionally (no early exit), and `(type_form=
/// "key-revocation", status="active")` — the very first pair — is where
/// a freshly seeded, non-superseded, non-retracted revocation matches.
/// So the call order is: search #1 (match) -> retrieve #2 (inline, the
/// instant a new candidate is seen) -> search #3..#7 (the remaining 5
/// pairs, no match) -> exactly one `client.lineage` walk of the newly
/// discovered lineage (call #8, since the candidate was already `seen`
/// via the retrieve above, the walk only re-confirms membership). Seven
/// calls precede the lineage walk (6 search + 1 retrieve), so
/// `max_requests: Some(7)` lets all seven through — both budget-checked,
/// both counted — and refuses only the eighth, the lineage call, before
/// it is ever sent to the server.
///
/// `hits("context")`'s expected delta is 2, not 1: `fetch_with_policy`
/// always does its OWN top-level retrieve of the target through the
/// CALLER's (unbudgeted) client before discovery ever runs — see the
/// block comment above `budget_ac1_revocation_discovery_still_copy` —
/// plus the ONE discovery-scoped retrieve of the seeded candidate.
#[tokio::test]
async fn budget_m1_seeded_revocation_bounds_retrieve_and_lineage() {
    const N: usize = 7;

    let rig = discovery_rig(0xC8).await;
    rig.h
        .seed_revocations(&rig.producer, &rig.producer_fp, &[rig.receipt_time])
        .await;
    let before_search = rig.h.hits("search");
    let before_context = rig.h.hits("context");
    let before_lineage = rig.h.hits("lineage");

    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.max_requests = Some(NonZeroUsize::new(N).unwrap());
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    let err = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect_err(
        "max_requests: Some(7) must exhaust exactly at the lineage walk, after \
         the 6 searches and the one matching candidate's retrieve already went through",
    );
    match &err {
        AcdpError::RevocationDiscoveryFailed { source } => {
            assert!(
                matches!(**source, AcdpError::RevocationDiscoveryBudgetExceeded(_)),
                "got {source:?}"
            );
        }
        other => panic!("expected RevocationDiscoveryFailed, got {other:?}"),
    }

    assert_eq!(
        rig.h.hits("search") - before_search,
        6,
        "all 6 (type_form, status) searches must complete before the budget bites"
    );
    assert_eq!(
        rig.h.hits("context") - before_context,
        2,
        "the top-level retrieve (1) plus the one matching candidate's \
         discovery-scoped retrieve (1) must both be let through — retrieve's \
         own `check_discovery_budget()?` reserved slot #7 rather than refusing it"
    );
    assert_eq!(
        rig.h.hits("lineage") - before_lineage,
        0,
        "the lineage walk must be refused BEFORE any request reaches the server — \
         this is the assertion that goes red if `check_discovery_budget()?` is \
         deleted from `RegistryClient::lineage`"
    );
}

/// N2 (load-bearing — the byte-budget analogue of AC3): the SAME
/// `max_bytes` must yield the same total ceiling whether
/// `include_registry_attested` is `false` or `true`, exactly as AC3
/// proves for `max_requests`. Zero revocations are seeded (as in the
/// `budget_ac2`/`ac3`/`ac7` family above), so every `/contexts/search`
/// response is a fixed-size ~33-byte empty-match body (measured against
/// this harness, not assumed) and `max_bytes: Some(100)` is calibrated
/// below, in the SAME test, against a single-lookup run first — so this
/// test does not hardcode a byte size that a harness change could
/// silently invalidate.
///
/// Single-lookup calibration first: with `max_bytes: Some(100)` and
/// `producer_signed_only()`, successive ~33-byte responses accumulate
/// 33, 66, 99, 132 — the 4th request's own check-before-issue still
/// sees 99 < 100 and is let through, and only the 5th observes the
/// overrun. So `K1` (the single-lookup total) is expected to land
/// strictly between 1 and the natural unbudgeted total of 6 — asserted,
/// not assumed, so a harness response-size change fails loudly here
/// rather than silently weakening the dual-lookup assertion below.
///
/// Dual-lookup with the SAME `max_bytes: Some(100)`: a genuinely
/// COMBINED byte counter can only ever total `K1` requests-worth of
/// bytes, split however the concurrent `try_join!` interleaves the two
/// lookups — so the dual total must be `<= K1`. A (bugged) per-lookup
/// separate budget would instead let EACH lookup independently
/// accumulate up to `K1` requests before its own copy of the counter
/// trips, for a dual total of up to `2 * K1` — comfortably more than
/// `K1` and easily distinguished from the combined case. (`<=`, not
/// `==`, for the same reason AC3/AC7 use `<=` for the dual case: a
/// `try_join!` race can let both lookups' very first, unrecorded-yet
/// requests through before either observes the other's bytes.)
#[tokio::test]
async fn budget_n2_max_bytes_combines_across_both_lookups() {
    const MAX_BYTES: u64 = 100;

    let rig1 = discovery_rig(0xC9).await;
    let before_search1 = rig1.h.hits("search");
    let mut discovery1 = RevocationDiscovery::producer_signed_only();
    discovery1.max_bytes = Some(MAX_BYTES);
    let policy1 = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery1),
        ..Default::default()
    };
    VerifiedContext::fetch_with_policy(
        &rig1.client,
        &rig1.h.resolver,
        &rig1.target_ctx_id,
        &policy1,
    )
    .await
    .expect_err("max_bytes: Some(100) must exhaust before the natural 6 searches complete");
    let k1 = rig1.h.hits("search") - before_search1;
    assert!(
        k1 > 1 && k1 < 6,
        "calibration invariant broken (k1={k1}) — this harness's search response \
         size must have changed; re-tune MAX_BYTES rather than trusting the \
         assertions below"
    );

    let rig2 = discovery_rig(0xCB).await;
    let before_search2 = rig2.h.hits("search");
    let before_caps2 = rig2.h.hits("acdp_json");
    let mut discovery2 = RevocationDiscovery::all_trust_classes();
    discovery2.max_bytes = Some(MAX_BYTES);
    let policy2 = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery2),
        ..Default::default()
    };
    let err2 = VerifiedContext::fetch_with_policy(
        &rig2.client,
        &rig2.h.resolver,
        &rig2.target_ctx_id,
        &policy2,
    )
    .await
    .expect_err("max_bytes: Some(100) must exhaust before the natural 13 requests complete");
    assert!(
        matches!(
            &err2,
            AcdpError::RevocationDiscoveryFailed { source }
                if matches!(**source, AcdpError::RevocationDiscoveryBudgetExceeded(_))
        ),
        "got {err2:?}"
    );
    let dual_total =
        (rig2.h.hits("search") - before_search2) + (rig2.h.hits("acdp_json") - before_caps2);
    assert!(
        dual_total <= k1,
        "dual-lookup total ({dual_total}) must be <= the single-lookup \
         calibration (k1={k1}) — a combined byte budget, not one ceiling per \
         lookup (which would allow up to 2*k1 = {})",
        2 * k1
    );
}

/// N2 (continued): both knobs set simultaneously, with `max_bytes`
/// exhausted from the FIRST response and `max_requests` left generous
/// enough to never bind on its own. This exercises
/// `check_before_request`'s byte-exhausted-so-don't-consume-a-request-slot
/// ordering (`registry.rs`'s `check_before_request`: the byte check runs
/// first and is a side-effect-free load) in the presence of a
/// `max_requests` value — a configuration no other test in this suite
/// runs, since every other `max_bytes`-only test leaves `max_requests`
/// unset.
#[tokio::test]
async fn budget_n2_both_knobs_set_byte_exhaustion_does_not_consume_request_slot() {
    let rig = discovery_rig(0xCA).await;
    let before_search = rig.h.hits("search");

    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.max_bytes = Some(1);
    // Generous enough that if the byte-exhausted check still consumed a
    // request slot, the natural 6-search total would still complete
    // "successfully" from `max_requests`'s point of view alone — so the
    // ONLY thing that can produce a budget failure here is the byte
    // check, and it must fire on the SECOND call, not later.
    discovery.max_requests = Some(NonZeroUsize::new(6).unwrap());
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    let err = VerifiedContext::fetch_with_policy(
        &rig.client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy,
    )
    .await
    .expect_err(
        "with both knobs set, max_bytes: Some(1) must still exhaust after the \
         first response, well before max_requests: Some(6) would ever bind",
    );
    match &err {
        AcdpError::RevocationDiscoveryFailed { source } => {
            assert!(
                matches!(**source, AcdpError::RevocationDiscoveryBudgetExceeded(_)),
                "got {source:?}"
            );
            assert!(
                source.to_string().contains("max_bytes"),
                "the byte check must be the one that fires, not max_requests; got {source}"
            );
        }
        other => panic!("expected RevocationDiscoveryFailed, got {other:?}"),
    }
    assert_eq!(
        rig.h.hits("search") - before_search,
        1,
        "byte-exhausted must refuse the SECOND request outright — it must not \
         consume a request-count slot first and let the request through anyway"
    );
}

// ── Issue #257: the revocation cache (facts + markers) ──────────────────────
//
// D-A: the cache is TWO objects. Facts (verified `KeyRevocation`s) are always
// unioned into classification, indefinitely, per RFC-ACDP-0014 §7:121 — an
// anti-rollback security control. Freshness markers ("vantage V completed a
// full, untruncated discovery for producer P at time T") are TTL-bounded,
// per-vantage, and off by default (`freshness: Duration::ZERO`), because §8
// warns that absence of search results is not evidence of absence.
//
// AC2 and AC6 carry the security argument (B1): facts must survive an
// induced discovery failure, and a marker must never be minted on anything
// short of full, untruncated success.

/// A two-key `did:web:localhost:<path>` identity for the cache tests below:
/// `key-1` signs ordinary/target content, `key-2` signs revocations of
/// `key-1` (RFC-ACDP-0014 §5 step 2 forbids self-revocation). Deliberately
/// receipt-signer-free — most of these tests reach RFC-ACDP-0014 §7 step 4
/// ("no verified receipt ⇒ fail closed") rather than the receipt-attested
/// pre/post-boundary distinction `discovery_rig` uses, which keeps the setup
/// minimal; the tests that specifically need a receipt-attested boundary (or
/// the registry's own §6 identity) reuse `discovery_rig` instead.
struct CacheIdentity {
    path: &'static str,
    #[allow(dead_code)] // kept for callers that want the raw DID string
    producer_did: String,
    did_doc: serde_json::Value,
    target: Producer,
    revoker: Producer,
    target_fp: String,
}

fn cache_identity(seed: u8, path: &'static str) -> CacheIdentity {
    let target_key = SigningKey::from_bytes(&[seed; 32]);
    let target_pub = target_key.verifying_key_bytes();
    let target_fp = fingerprint_ed25519(&target_pub);
    let revoker_key = SigningKey::from_bytes(&[seed.wrapping_add(1); 32]);
    let revoker_pub = revoker_key.verifying_key_bytes();
    let producer_did = candidate_did(path);
    let did_doc =
        two_key_ed25519_did_doc(&producer_did, "key-1", &target_pub, "key-2", &revoker_pub);
    let target = Producer::new(
        target_key,
        AgentDid::new(producer_did.as_str()),
        format!("{producer_did}#key-1"),
    );
    let revoker = Producer::new(
        revoker_key,
        AgentDid::new(producer_did.as_str()),
        format!("{producer_did}#key-2"),
    );
    CacheIdentity {
        path,
        producer_did,
        did_doc,
        target,
        revoker,
        target_fp,
    }
}

/// Publish a plain, non-revocation, receipt-less target context signed by
/// `id.target` on a real `LineageServerHarness`, via the harness's real
/// `RegistryServer`/`InMemoryStore` (not a hand-built mock).
async fn publish_plain_target(h: &LineageServerHarness, id: &CacheIdentity) -> CtxId {
    let req = id
        .target
        .publish_request()
        .acdp_version("0.3.0")
        .title("cache test target")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
        .build()
        .expect("build");
    let resp = h
        .server
        .publish_verified(&req, None, &h.resolver)
        .await
        .expect("publish");
    resp.ctx_id
}

/// Publish an `n`-node `derived_from` CHAIN signed by `id.target` on a real
/// `LineageServerHarness`: `chain[0]` has no parent, `chain[i]` (`i > 0`) has
/// `derived_from: [chain[i-1]]`. Returns oldest→newest. Used by the issue
/// #260 `CrossRegistryResolver` revocation-discovery tests below, which walk
/// `derived_from` FROM `chain[n-1]` back to `chain[0]` — `n-1` ancestors
/// actually pass through [`CrossRegistryResolver::resolve`] (the root itself
/// is excluded per `walk_derived_from`'s doc), each one triggering its own
/// revocation-discovery attempt under the policy the test's resolver
/// carries.
async fn publish_derived_chain(
    h: &LineageServerHarness,
    id: &CacheIdentity,
    n: usize,
) -> Vec<CtxId> {
    assert!(n >= 1, "a chain needs at least one node");
    let mut chain: Vec<CtxId> = Vec::with_capacity(n);
    for i in 0..n {
        let mut builder = id
            .target
            .publish_request()
            .acdp_version("0.3.0")
            .title(format!("resolver chain node {i}"))
            .context_type(ContextType::Analysis)
            .visibility(Visibility::Public);
        if let Some(parent) = chain.last() {
            builder = builder.derived_from(vec![parent.clone()]);
        }
        let req = builder.build().expect("build");
        let resp = h
            .server
            .publish_verified(&req, None, &h.resolver)
            .await
            .expect("publish");
        chain.push(resp.ctx_id);
    }
    chain
}

/// Build a plain, non-revocation `Body` signed by `producer` at an
/// explicit `ctx_id`/`lineage_id`, without going through any server —
/// for the hand-built single-route mocks below (mirrors `revocation_body`,
/// used elsewhere in this file for the same reason, minus the
/// `key-revocation` content type).
fn plain_signed_body(
    producer: &Producer,
    ctx_id: &str,
    lineage_id: &LineageId,
    created_at: DateTime<Utc>,
) -> Body {
    let req = producer
        .publish_request()
        .acdp_version("0.3.0")
        .title("cache test target (mock)")
        .context_type(ContextType::Analysis)
        .visibility(Visibility::Public)
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

/// AC1: the anti-rollback case in its purest form. Warm the cache against
/// `h1`, which genuinely serves R for producer P; then verify a FRESH
/// target under the SAME producer identity against `h2`, an entirely
/// separate, real `LineageServerHarness` that has never seen R at all — a
/// genuine, successful, empty discovery (not an error, not a truncation),
/// simulating a registry that has stopped serving a revocation it once
/// served. The cached fact must still fail-close verification on `h2`.
///
/// Facts are keyed only by producer `agent_id` (never by vantage), so this
/// works across two independent registries sharing nothing but the
/// identity string — precisely the anti-rollback property RFC-ACDP-0014
/// §7:121 licenses.
#[tokio::test]
async fn cache_ac1_fact_survives_a_registry_that_stops_serving_it() {
    let id = cache_identity(0xC1, "cache-ac1");
    let cache = RevocationCache::new();

    let h1 = LineageServerHarness::builder(lifecycle_caps())
        .with_producer_did_document(id.path, id.did_doc.clone())
        .build()
        .await;
    let boundary = at("2026-05-01T00:00:00.000Z");
    h1.seed_revocations(&id.revoker, &id.target_fp, &[boundary])
        .await;
    let client1 = h1.client().with_revocation_cache(cache.clone());
    let discovery = RevocationDiscovery::producer_signed_only();
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    let t1 = publish_plain_target(&h1, &id).await;
    let err = VerifiedContext::fetch_with_policy(&client1, &h1.resolver, &t1, &policy)
        .await
        .expect_err(
            "warm-up: R must be found via discovery and fail closed (§7 step 4 — no receipt)",
        );
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    // A second, entirely separate real harness — same identity, no
    // revocation ever seeded. `hits("search")` below proves this call
    // genuinely re-ran discovery (not suppressed by a marker: freshness
    // is ZERO by default) and found nothing new.
    let h2 = LineageServerHarness::builder(lifecycle_caps())
        .with_producer_did_document(id.path, id.did_doc.clone())
        .build()
        .await;
    let client2 = h2.client().with_revocation_cache(cache);
    let t2 = publish_plain_target(&h2, &id).await;
    let err2 = VerifiedContext::fetch_with_policy(&client2, &h2.resolver, &t2, &policy)
        .await
        .expect_err(
            "the cached fact R must still fail-close verification even though h2's own \
             discovery genuinely found nothing",
        );
    assert!(
        matches!(err2, AcdpError::KeyNotAuthorized(_)),
        "got {err2:?}"
    );
    assert!(
        h2.hits("search") > 0,
        "sanity: h2's discovery must have genuinely run (not been skipped) and found nothing"
    );
}

/// AC2 (the B1 criterion): facts survive an induced 503 under
/// `ProceedWithKnown`. Warm the cache (R is genuinely discovered and
/// fails verification closed), then induce a transport error and switch
/// to `ProceedWithKnown` — the fact must still fail-close the SAME
/// target, even though this call's own discovery attempt failed.
#[tokio::test]
async fn cache_ac2_facts_survive_induced_503_under_proceed_with_known() {
    let rig = discovery_rig(0xE1).await;
    let cache = RevocationCache::new();
    let client = rig.client.with_revocation_cache(cache);
    rig.h
        .seed_revocations(&rig.producer, &rig.producer_fp, &[rig.receipt_time])
        .await;

    let discovery = RevocationDiscovery::producer_signed_only();
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    let err =
        VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect_err("warm-up discovery must find R and fail closed");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    rig.h
        .set_error("search", axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let mut discovery2 = RevocationDiscovery::producer_signed_only();
    discovery2.on_failure = DiscoveryFailurePolicy::ProceedWithKnown;
    let policy2 = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery2),
        ..Default::default()
    };
    let err2 =
        VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy2)
            .await
            .expect_err(
                "the cached fact R must still fail-close verification even though this \
         call's discovery attempt failed (503)",
            );
    assert!(
        matches!(err2, AcdpError::KeyNotAuthorized(_)),
        "got {err2:?}"
    );
}

/// AC2 (continued): facts survive an induced `SearchTruncated`. Genuine
/// page-cap truncation needs a hand-built mock (the real harness cannot
/// serve enough pages — see the repo map), so this test warms the cache
/// against a real harness (`h1`, seeding R), then verifies a fresh target
/// under the SAME producer identity against a minimal mock registry (`h2`)
/// whose `/contexts/search` always returns a stuck cursor.
#[tokio::test]
async fn cache_ac2_facts_survive_induced_search_truncated_under_proceed_with_known() {
    use std::collections::HashMap;

    let id = cache_identity(0xC3, "cache-ac2b");
    let cache = RevocationCache::new();

    let h1 = LineageServerHarness::builder(lifecycle_caps())
        .with_producer_did_document(id.path, id.did_doc.clone())
        .build()
        .await;
    let boundary = at("2026-05-01T00:00:00.000Z");
    h1.seed_revocations(&id.revoker, &id.target_fp, &[boundary])
        .await;
    let client1 = h1.client().with_revocation_cache(cache.clone());
    let discovery = RevocationDiscovery::producer_signed_only();
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    let t1 = publish_plain_target(&h1, &id).await;
    let err = VerifiedContext::fetch_with_policy(&client1, &h1.resolver, &t1, &policy)
        .await
        .expect_err("warm-up: R must be found via discovery and fail closed");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    // Minimal mock: DID doc + one target context + a search route that
    // always truncates. No `/lineages/{id}` route is needed — a search
    // response of `matches: []` never names a lineage_id to walk.
    let t2_ctx_id_str = "acdp://registry.example.com/00000000-0000-4000-8000-0000000000c3";
    let t2_lineage = LineageId::parse(format!("lin:sha256:{}", "7".repeat(64))).unwrap();
    let t2_body = plain_signed_body(&id.target, t2_ctx_id_str, &t2_lineage, Utc::now());
    let t2_full_json = serde_json::to_value(full_context(t2_body)).unwrap();
    let doc = id.did_doc.clone();
    let path = id.path;
    let router = Router::new()
        .route(
            "/contexts/search",
            get(
                |_: axum::extract::Query<HashMap<String, String>>| async move {
                    Json(json!({"matches": [], "next_cursor": "stuck"}))
                },
            ),
        )
        .route(
            &candidate_did_route(path),
            get(move || {
                let doc = doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/contexts/{id}",
            get(
                move |axum::extract::Path(_id): axum::extract::Path<String>| {
                    let body = t2_full_json.clone();
                    async move { Json(body) }
                },
            ),
        );
    let tls2 = TlsTestServer::start(router).await;
    let resolver2 = WebResolver::with_test_endpoint(&tls2.root_cert_pem, "localhost", tls2.addr)
        .expect("pinned resolver");
    let client2 = RegistryClient::with_test_endpoint(
        &format!("https://{REGISTRY_AUTHORITY}"),
        tls2.addr,
        &tls2.root_cert_pem,
    )
    .expect("pinned client")
    .with_revocation_cache(cache);

    let mut discovery2 = RevocationDiscovery::producer_signed_only();
    discovery2.on_failure = DiscoveryFailurePolicy::ProceedWithKnown;
    let policy2 = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery2),
        ..Default::default()
    };
    let t2_ctx_id = CtxId::parse(t2_ctx_id_str).unwrap();
    let err2 = VerifiedContext::fetch_with_policy(&client2, &resolver2, &t2_ctx_id, &policy2)
        .await
        .expect_err(
            "the cached fact R must still fail-close verification even though this \
             call's discovery attempt hit SearchTruncated",
        );
    assert!(
        matches!(err2, AcdpError::KeyNotAuthorized(_)),
        "got {err2:?}"
    );
}

/// AC2 (continued): facts survive an induced Phase 1 (#258) budget
/// exhaustion.
#[tokio::test]
async fn cache_ac2_facts_survive_induced_budget_exhaustion_under_proceed_with_known() {
    let rig = discovery_rig(0xE2).await;
    let cache = RevocationCache::new();
    let client = rig.client.with_revocation_cache(cache);
    rig.h
        .seed_revocations(&rig.producer, &rig.producer_fp, &[rig.receipt_time])
        .await;

    let discovery = RevocationDiscovery::producer_signed_only();
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    let err =
        VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect_err("warm-up discovery must find R and fail closed");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    let mut discovery2 = RevocationDiscovery::producer_signed_only();
    discovery2.max_requests = Some(NonZeroUsize::new(1).unwrap());
    discovery2.on_failure = DiscoveryFailurePolicy::ProceedWithKnown;
    let policy2 = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery2),
        ..Default::default()
    };
    let err2 =
        VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy2)
            .await
            .expect_err(
                "the cached fact R must still fail-close verification even though this \
         call's discovery attempt hit the request budget",
            );
    assert!(
        matches!(err2, AcdpError::KeyNotAuthorized(_)),
        "got {err2:?}"
    );
}

/// AC3: with a cache attached and `freshness: ZERO` (the default), a
/// second identical verify searches EXACTLY as much as the first — the
/// cache saves zero requests by default.
#[tokio::test]
async fn cache_ac3_default_freshness_zero_saves_no_requests() {
    let rig = discovery_rig(0xE3).await;
    let cache = RevocationCache::new();
    let client = rig.client.with_revocation_cache(cache);
    let discovery = RevocationDiscovery::producer_signed_only();
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };

    let before = rig.h.hits("search");
    VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
        .await
        .expect("no revocation seeded; must verify cleanly");
    let after_call1 = rig.h.hits("search");
    let delta1 = after_call1 - before;
    assert!(delta1 > 0, "the first call must actually search");

    VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
        .await
        .expect("must verify cleanly again");
    let delta2 = rig.h.hits("search") - after_call1;
    assert_eq!(
        delta2, delta1,
        "with freshness: ZERO (the default), attaching a cache must save exactly zero \
         requests — the second call must search exactly as much as the first"
    );
}

/// AC5a: with a generous `freshness` window, a marker minted by a clean
/// baseline call suppresses a REPEAT lookup entirely — even after a new
/// revocation is published in the meantime.
///
/// The window is deliberately LARGE (30 s). An earlier version of this
/// test used a 50 ms window and a 60 ms sleep to prove suppression and
/// expiry on one timeline, and it was flaky on CI (`ubuntu/beta` and
/// `windows/stable` both failed at the in-window assertion). The cause
/// was not margin-tuning: `seed_revocations` performs a real Ed25519
/// publish over TLS *between* minting the marker and checking it, so on
/// a loaded runner the window expired mid-test, discovery re-ran, and R2
/// fail-closed where the test expected suppression. Splitting the two
/// properties apart removes the race rather than widening it — neither
/// half now depends on work finishing inside a deadline. Expiry is
/// proven separately by `cache_ac5b_*`.
#[tokio::test]
async fn cache_ac5a_freshness_window_suppresses_repeat_lookup() {
    let rig = discovery_rig(0xE5).await;
    let cache = RevocationCache::new();
    let client = rig.client.with_revocation_cache(cache);
    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.freshness = std::time::Duration::from_secs(30);
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };

    let verified =
        VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect("clean baseline mints the marker");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
    let after_warm = rig.h.hits("search");
    assert!(after_warm > 0, "the baseline call must actually search");

    // R2 is reachable only by discovery — never placed in `known`.
    rig.h
        .seed_revocations(&rig.producer, &rig.producer_fp, &[rig.receipt_time])
        .await;

    let still_ok =
        VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect("within the freshness window, R2 must not be applied");
    assert_eq!(still_ok.key_status(), KeyAuthorization::CurrentlyAuthorized);
    assert_eq!(
        rig.h.hits("search"),
        after_warm,
        "within the freshness window, discovery must be skipped entirely — zero new \
         search requests"
    );
}

/// AC5b: a marker STOPS suppressing once its `freshness` elapses, so a
/// revocation published after the marker was minted is still discovered.
///
/// This is the half that closes RFC-ACDP-0014 §7:121's actual silence —
/// §7:121 licenses caching a verified revocation indefinitely but says
/// nothing about re-checking for NEW ones. A marker that never expired
/// would reintroduce exactly that gap, so this test must stay able to
/// fail: it goes RED if suppression becomes permanent.
///
/// The window is deliberately TINY (1 ms) against a 250 ms sleep, which
/// is the opposite race to `cache_ac5a_*` and equally unloseable — CI
/// slowness can only make the window MORE expired, never less.
#[tokio::test]
async fn cache_ac5b_freshness_expiry_reveals_new_revocation() {
    let rig = discovery_rig(0xE6).await;
    let cache = RevocationCache::new();
    let client = rig.client.with_revocation_cache(cache);
    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.freshness = std::time::Duration::from_millis(1);
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };

    let verified =
        VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect("clean baseline mints the marker");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
    let after_warm = rig.h.hits("search");

    rig.h
        .seed_revocations(&rig.producer, &rig.producer_fp, &[rig.receipt_time])
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    let err =
        VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect_err(
                "after the freshness window elapses, R2 must be discovered and fail closed",
            );
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
    assert!(
        rig.h.hits("search") > after_warm,
        "discovery must have genuinely re-run after the freshness window elapsed"
    );
}

/// AC6: no marker is minted on an induced `SearchTruncated` — a second
/// call, still well within a long freshness window, must search again
/// rather than being (wrongly) suppressed by a marker from the truncated
/// attempt. Self-contained mock (no receipt, no real backing store): the
/// point here is purely marker-absence, observed via request counts.
#[tokio::test]
async fn cache_ac6_no_marker_minted_on_induced_search_truncated() {
    use std::collections::HashMap;

    let id = cache_identity(0xE6, "cache-ac6-truncated");
    let target_ctx_id_str = "acdp://registry.example.com/00000000-0000-4000-8000-0000000000e6";
    let lineage = LineageId::parse(format!("lin:sha256:{}", "8".repeat(64))).unwrap();
    let body = plain_signed_body(&id.target, target_ctx_id_str, &lineage, Utc::now());
    let full_json = serde_json::to_value(full_context(body)).unwrap();

    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let doc = id.did_doc.clone();
    let path = id.path;
    let router = Router::new()
        .route(
            "/contexts/search",
            get({
                let hits = hits.clone();
                move |_: axum::extract::Query<HashMap<String, String>>| {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Json(json!({"matches": [], "next_cursor": "stuck"}))
                    }
                }
            }),
        )
        .route(
            &candidate_did_route(path),
            get(move || {
                let doc = doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/contexts/{id}",
            get(
                move |axum::extract::Path(_id): axum::extract::Path<String>| {
                    let body = full_json.clone();
                    async move { Json(body) }
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
    .expect("pinned client")
    .with_revocation_cache(RevocationCache::new());

    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.freshness = std::time::Duration::from_secs(60);
    discovery.on_failure = DiscoveryFailurePolicy::ProceedWithKnown;
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    let target_ctx_id = CtxId::parse(target_ctx_id_str).unwrap();

    let verified = VerifiedContext::fetch_with_policy(&client, &resolver, &target_ctx_id, &policy)
        .await
        .expect(
            "ProceedWithKnown must let verification succeed despite the induced SearchTruncated",
        );
    assert!(
        verified.revocation_discovery_failure().is_some(),
        "the induced SearchTruncated must be recorded, not silent"
    );
    let hits_after_1 = hits.load(std::sync::atomic::Ordering::SeqCst);
    assert!(hits_after_1 > 0);

    let verified2 = VerifiedContext::fetch_with_policy(&client, &resolver, &target_ctx_id, &policy)
        .await
        .expect("ProceedWithKnown must let verification succeed again");
    assert!(verified2.revocation_discovery_failure().is_some());
    assert!(
        hits.load(std::sync::atomic::Ordering::SeqCst) > hits_after_1,
        "a truncated (not fully successful) discovery must never mint a marker: the \
         second call, still within the freshness window, must have searched again"
    );
}

/// AC6 (continued): no marker is minted on an induced Phase 1 (#258)
/// budget exhaustion.
#[tokio::test]
async fn cache_ac6_no_marker_minted_on_induced_budget_exhaustion() {
    let rig = discovery_rig(0xE7).await;
    let cache = RevocationCache::new();
    let client = rig.client.with_revocation_cache(cache);
    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.freshness = std::time::Duration::from_secs(60);
    discovery.max_requests = Some(NonZeroUsize::new(1).unwrap());
    discovery.on_failure = DiscoveryFailurePolicy::ProceedWithKnown;
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };

    let before = rig.h.hits("search");
    VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
        .await
        .expect(
            "ProceedWithKnown must let verification succeed despite the induced budget exhaustion",
        );
    let after1 = rig.h.hits("search");
    assert!(
        after1 > before,
        "the first call must have issued at least one search before exhausting the budget"
    );

    VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
        .await
        .expect("must succeed again");
    assert!(
        rig.h.hits("search") > after1,
        "a budget-exhausted discovery must never mint a marker: the second call, \
         still within the freshness window, must have searched again"
    );
}

/// AC6 (continued): no marker is minted on an induced `total_timeout`
/// trip.
#[tokio::test]
async fn cache_ac6_no_marker_minted_on_induced_total_timeout() {
    let rig = discovery_rig(0xE8).await;
    let cache = RevocationCache::new();
    let client = rig.client.with_revocation_cache(cache);
    rig.h
        .set_delay("search", std::time::Duration::from_millis(300));
    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.freshness = std::time::Duration::from_secs(60);
    discovery.total_timeout = std::time::Duration::from_millis(50);
    discovery.on_failure = DiscoveryFailurePolicy::ProceedWithKnown;
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };

    let before = rig.h.hits("search");
    VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
        .await
        .expect("ProceedWithKnown must let verification succeed despite the induced timeout");
    rig.h.clear_delay("search");
    let after1 = rig.h.hits("search");
    assert!(
        after1 > before,
        "the first call must have issued at least one search before timing out"
    );

    VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
        .await
        .expect("must succeed again");
    assert!(
        rig.h.hits("search") > after1,
        "a timed-out discovery must never mint a marker: the second call, still \
         within the freshness window, must have searched again"
    );
}

/// AC7(a): a marker minted for `producer_signed_only()` does not suppress
/// the independent registry-attested lookup a subsequent
/// `all_trust_classes()` call makes for the same producer, within the
/// same freshness window.
#[tokio::test]
async fn cache_ac7a_marker_for_one_class_does_not_suppress_the_other() {
    let rig = discovery_rig(0xE9).await;
    let cache = RevocationCache::new();
    let client = rig.client.with_revocation_cache(cache);

    let mut only = RevocationDiscovery::producer_signed_only();
    only.freshness = std::time::Duration::from_secs(60);
    let policy_only = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(only),
        ..Default::default()
    };
    VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy_only)
        .await
        .expect("clean baseline under producer_signed_only()");

    let acdp_json_before = rig.h.hits("acdp_json");
    let mut all = RevocationDiscovery::all_trust_classes();
    all.freshness = std::time::Duration::from_secs(60);
    let policy_all = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(all),
        ..Default::default()
    };
    VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy_all)
        .await
        .expect("clean baseline under all_trust_classes()");
    assert!(
        rig.h.hits("acdp_json") > acdp_json_before,
        "a marker minted for producer-signed discovery must not suppress the \
         independent registry-attested lookup"
    );
}

/// AC7(b): a `producer_signed_only()` run against a cache holding a
/// registry-attested fact does NOT apply it.
#[tokio::test]
async fn cache_ac7b_producer_signed_only_ignores_a_cached_registry_attested_fact() {
    let seed = 0xEAu8;
    let rig = discovery_rig(seed).await;
    let cache = RevocationCache::new();
    let client = rig.client.with_revocation_cache(cache);

    // A genuine registry-attested revocation of the target's key,
    // published under the registry's own identity — `SigningKey` is not
    // `Clone`, so the receipt signer `discovery_rig` configured is
    // reconstructed here from the same seed rather than threaded through.
    let registry_signer_key = SigningKey::from_bytes(&[seed; 32]);
    let registry = Producer::new(
        registry_signer_key,
        AgentDid::new(REGISTRY_DID),
        format!("{REGISTRY_DID}#receipt-key-1"),
    );
    let req = registry
        .publish_request()
        .acdp_version("0.3.0")
        .title("registry-attested revocation")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": rig.producer_fp,
            "compromised_since": rig.receipt_time
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "revoked_key_controller": rig.producer_did,
        }))
        .build()
        .expect("build");
    rig.h
        .server
        .publish_verified(&req, None, &rig.h.resolver)
        .await
        .expect("registry-attested revocation publish");

    let all = RevocationDiscovery::all_trust_classes();
    let policy_all = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(all),
        ..Default::default()
    };
    let err = VerifiedContext::fetch_with_policy(
        &client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy_all,
    )
    .await
    .expect_err("the registry-attested revocation must be found and fail closed");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    let only = RevocationDiscovery::producer_signed_only();
    let policy_only = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(only),
        ..Default::default()
    };
    let verified = VerifiedContext::fetch_with_policy(
        &client,
        &rig.h.resolver,
        &rig.target_ctx_id,
        &policy_only,
    )
    .await
    .expect("producer_signed_only() must not apply a cached registry-attested fact");
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
}

/// Falsifiability-probe target (AC13c): the registry-attested marker key
/// must be the producer/controller DID, never the registry's own search
/// identity — otherwise a marker minted for one producer would suppress
/// the lookup for every OTHER producer at the same registry too. Two
/// distinct producers, one registry: warming producer P1's
/// registry-attested marker must not suppress producer P2's independent
/// lookup.
#[tokio::test]
async fn cache_ac7c_registry_attested_marker_is_per_producer_not_per_registry() {
    let id1 = cache_identity(0xED, "cache-ac7c-p1");
    let id2 = cache_identity(0xEE, "cache-ac7c-p2");
    let h = LineageServerHarness::builder(lifecycle_caps())
        .with_producer_did_document(id1.path, id1.did_doc.clone())
        .with_producer_did_document(id2.path, id2.did_doc.clone())
        .with_well_known_acdp()
        .build()
        .await;
    let t1 = publish_plain_target(&h, &id1).await;
    let t2 = publish_plain_target(&h, &id2).await;

    let cache = RevocationCache::new();
    let client = h.client().with_revocation_cache(cache);
    let mut discovery = RevocationDiscovery::all_trust_classes();
    discovery.freshness = std::time::Duration::from_secs(60);
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };

    VerifiedContext::fetch_with_policy(&client, &h.resolver, &t1, &policy)
        .await
        .expect("baseline P1 mints P1's registry-attested marker");

    let acdp_json_before = h.hits("acdp_json");
    VerifiedContext::fetch_with_policy(&client, &h.resolver, &t2, &policy)
        .await
        .expect("baseline P2");
    assert!(
        h.hits("acdp_json") > acdp_json_before,
        "a registry-attested marker minted for producer P1 must not suppress the \
         lookup for a DIFFERENT producer P2 at the SAME registry"
    );
}

/// AC8: a marker minted for vantage A does not suppress discovery at a
/// different vantage B, for the same producer and cache. Two
/// `RegistryClient`s pointed at the SAME real harness (`RegistryClient::authority()`
/// reads the logical host+port from the client's own base URL, not the
/// physical socket `.resolve()` pins it to) give genuinely different
/// vantage strings without needing a second server.
#[tokio::test]
async fn cache_ac8_marker_is_per_vantage() {
    // Deliberately the receipt-less `cache_identity` rig, not
    // `discovery_rig`: `discovery_rig`'s receipt phase cross-checks the
    // receipt's `registry_did` against `client.authority()`
    // (RFC-ACDP-0010's serving-authority binding), which would itself
    // fail once vantage B's explicit port makes that authority differ
    // from the one the receipt was minted under — a real but unrelated
    // failure mode this test must not trip over.
    let id = cache_identity(0xEB, "cache-ac8");
    let h = LineageServerHarness::builder(lifecycle_caps())
        .with_producer_did_document(id.path, id.did_doc.clone())
        .build()
        .await;
    let t = publish_plain_target(&h, &id).await;

    let cache = RevocationCache::new();
    let client_a = h.client().with_revocation_cache(cache.clone());
    let alt_base = format!("https://localhost:{}", h.tls.addr.port());
    let client_b = RegistryClient::with_test_endpoint(&alt_base, h.tls.addr, &h.tls.root_cert_pem)
        .expect("alt-authority client")
        .with_revocation_cache(cache);
    assert_ne!(
        client_a.authority(),
        client_b.authority(),
        "sanity: the two clients must report different vantages"
    );

    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.freshness = std::time::Duration::from_secs(60);
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };

    VerifiedContext::fetch_with_policy(&client_a, &h.resolver, &t, &policy)
        .await
        .expect("baseline via vantage A mints A's marker");

    let before_b = h.hits("search");
    VerifiedContext::fetch_with_policy(&client_b, &h.resolver, &t, &policy)
        .await
        .expect("baseline via vantage B");
    assert!(
        h.hits("search") > before_b,
        "a marker minted for vantage A must not suppress discovery at a different \
         vantage B, even for the same producer"
    );
}

/// AC9: a suppressed registry-attested lookup issues ZERO requests,
/// including no `capabilities()` fetch — the marker check must precede
/// that unconditional call, not merely the search loop.
#[tokio::test]
async fn cache_ac9_marker_precedes_capabilities_fetch() {
    let rig = discovery_rig(0xEC).await;
    let cache = RevocationCache::new();
    let client = rig.client.with_revocation_cache(cache);
    let mut discovery = RevocationDiscovery::all_trust_classes();
    discovery.freshness = std::time::Duration::from_secs(60);
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };

    VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
        .await
        .expect("baseline mints the registry-attested marker");
    let acdp_json_after_warm = rig.h.hits("acdp_json");
    assert!(acdp_json_after_warm > 0);

    VerifiedContext::fetch_with_policy(&client, &rig.h.resolver, &rig.target_ctx_id, &policy)
        .await
        .expect("second call within the freshness window");
    assert_eq!(
        rig.h.hits("acdp_json"),
        acdp_json_after_warm,
        "a fresh marker must suppress the registry-attested lookup BEFORE its \
         unconditional capabilities() fetch — zero new requests, not just zero new \
         searches"
    );
}

/// AC11 (partial — the rest is `cargo semver-checks` plus a lockfile diff,
/// run as part of verification, not expressible as a unit test):
/// `RevocationDiscovery` still derives `Copy` with the new `freshness`
/// field, and both named constructors still default it to `Duration::ZERO`.
#[test]
fn cache_ac11_revocation_discovery_still_copy_with_freshness_field() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<RevocationDiscovery>();
    let discovery = RevocationDiscovery::producer_signed_only();
    let _copy1 = discovery;
    let _copy2 = discovery;
    assert_eq!(discovery.freshness, std::time::Duration::ZERO);
}

// ── Phase-2 verification-pass gap closures (fresh-Opus review of
// #257/#258/#260, BLOCKER-1 / MATERIAL-2 / MATERIAL-3) ──────────────────────
//
// BLOCKER-1: the cache's stored facts now carry the vantage that minted
// them. A producer-signed fact is self-contained (RFC-ACDP-0014 §8) and
// crosses vantages (already covered by `cache_ac1`, above). A
// registry-attested fact is one specific registry's claim (§6: "apply it
// ... for contexts served by or receipted by that same registry") and must
// NOT apply at a different vantage — `cache_blocker1_*` below covers that
// direction, which was previously untested and unenforced.
//
// MATERIAL-2: no existing test recorded a non-empty fact set twice for the
// same `agent_id` via two INDEPENDENT, real discoveries — the unit test
// `record_success_dedups_identical_facts` only clones one in-memory value.
// `cache_material2_*` below warms a cache via a live harness and re-verifies
// several times at `freshness: ZERO` (so every call genuinely re-discovers),
// asserting the fact count never grows past 1.
//
// MATERIAL-3: `discover: None` previously seeded nothing at all, even with a
// cache attached — contradicting the rustdoc/CHANGELOG claim that attaching
// a cache "unconditionally" seeds facts. `cache_material3_*` below proves
// the fix: a `discover: None` call still seeds the cached producer-signed
// fact and issues zero live discovery requests.

/// BLOCKER-1: a registry-attested revocation minted (cached) while talking
/// to vantage A must NOT apply when the SAME cache is read while talking to
/// a DIFFERENT vantage B — even under `all_trust_classes()`.
///
/// Two `RegistryClient`s point at the SAME physical harness
/// (`RegistryClient::authority()` reads the client's own base URL, not the
/// pinned socket — see `cache_ac8`, which establishes this exact trick).
/// `client_a`'s vantage ("localhost") matches `REGISTRY_DID`'s own
/// authority, so a live discovery genuinely finds and applies the
/// registry-attested revocation there. `client_b`'s vantage
/// ("localhost:<port>") does NOT match `REGISTRY_DID`'s authority, so
/// `client_b`'s OWN live discovery legitimately finds nothing (RFC-ACDP-0014
/// §6 step 2 / the RFC-ACDP-0011 §7 house binding rejects the mismatch) —
/// any failure at `client_b` can therefore only come from an incorrectly
/// unfiltered seeded fact, isolating exactly the bug this test targets.
///
/// `receipts: ReceiptPolicy::Ignore` sidesteps the UNRELATED failure mode
/// `cache_ac8` already documented: `discovery_rig`'s minted receipt cross-
/// checks its `registry_did` against `client.authority()`, which would
/// itself fail at vantage B purely because of the differing port, for a
/// reason that has nothing to do with this test.
#[tokio::test]
async fn cache_blocker1_registry_attested_fact_does_not_cross_vantage() {
    let seed = 0xF1u8;
    let rig = discovery_rig(seed).await;
    let cache = RevocationCache::new();
    let client_a = rig.client.clone().with_revocation_cache(cache.clone());

    // A genuine registry-attested revocation of the target's key, published
    // under the registry's own identity — mirrors `cache_ac7b`.
    let registry_signer_key = SigningKey::from_bytes(&[seed; 32]);
    let registry = Producer::new(
        registry_signer_key,
        AgentDid::new(REGISTRY_DID),
        format!("{REGISTRY_DID}#receipt-key-1"),
    );
    let req = registry
        .publish_request()
        .acdp_version("0.3.0")
        .title("registry-attested revocation (blocker-1)")
        .context_type(ContextType::KeyRevocation)
        .visibility(Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": rig.producer_fp,
            "compromised_since": "2026-01-01T00:00:00.000Z",
            "revoked_key_controller": rig.producer_did,
        }))
        .build()
        .expect("build");
    rig.h
        .server
        .publish_verified(&req, None, &rig.h.resolver)
        .await
        .expect("registry-attested revocation publish");

    let all = RevocationDiscovery::all_trust_classes();
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(all),
        receipts: ReceiptPolicy::Ignore,
        ..Default::default()
    };

    let err =
        VerifiedContext::fetch_with_policy(&client_a, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect_err(
                "vantage A: live discovery must find and apply the registry-attested revocation, \
         warming the cache with origin = A",
            );
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    let alt_base = format!("https://localhost:{}", rig.h.tls.addr.port());
    let client_b =
        RegistryClient::with_test_endpoint(&alt_base, rig.h.tls.addr, &rig.h.tls.root_cert_pem)
            .expect("alt-authority client")
            .with_revocation_cache(cache);
    assert_ne!(
        client_a.authority(),
        client_b.authority(),
        "sanity: the two clients must report different vantages"
    );

    let verified =
        VerifiedContext::fetch_with_policy(&client_b, &rig.h.resolver, &rig.target_ctx_id, &policy)
            .await
            .expect(
                "vantage B: the registry-attested fact minted at vantage A must NOT apply here — \
         B's own live discovery legitimately finds nothing (registry-binding mismatch), and \
         the cached fact must be filtered out by origin",
            );
    assert_eq!(verified.key_status(), KeyAuthorization::CurrentlyAuthorized);
}

/// MATERIAL-2: dedup must hold across INDEPENDENT, real discoveries against
/// a live harness, not merely across clones of one in-memory value (the
/// gap the unit test `record_success_dedups_identical_facts` leaves open).
/// With `freshness: Duration::ZERO` (the default), every one of the N
/// verifies below genuinely re-runs discovery against the harness — the
/// entry's fact count must never grow past 1.
#[tokio::test]
async fn cache_material2_dedup_holds_across_independent_real_discoveries() {
    let id = cache_identity(0xF2, "cache-material2");
    let cache = RevocationCache::new();

    let h = LineageServerHarness::builder(lifecycle_caps())
        .with_producer_did_document(id.path, id.did_doc.clone())
        .build()
        .await;
    let boundary = at("2026-05-01T00:00:00.000Z");
    h.seed_revocations(&id.revoker, &id.target_fp, &[boundary])
        .await;
    let client = h.client().with_revocation_cache(cache.clone());
    let discovery = RevocationDiscovery::producer_signed_only(); // freshness: ZERO
    let policy = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    let t = publish_plain_target(&h, &id).await;

    for i in 0..6 {
        let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &t, &policy)
            .await
            .expect_err(&format!("call {i}: R must still be found and fail closed"));
        assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
    }
    assert!(
        h.hits("search") > 6,
        "sanity: each of the 6 calls above must have genuinely re-run discovery \
         (freshness: ZERO never suppresses a lookup)"
    );
    assert_eq!(
        cache.fact_count(id.producer_did.as_str()),
        1,
        "dedup must hold across independently-run discoveries against a live harness, not \
         merely across clones of one in-memory value — the entry must not grow past 1 fact \
         across 6 separate re-discoveries of the same revocation"
    );
}

/// MATERIAL-3: `discover: None` must still seed a cached producer-signed
/// fact — attaching a `RevocationCache` is itself the opt-in for
/// anti-rollback, independent of whether `discover` is configured on any
/// given call. Warm the cache with discovery on, then re-verify the SAME
/// context with `discover: None` and confirm it still fails closed, with
/// ZERO new discovery requests (the fact must come purely from the cache,
/// not from a live re-discovery).
#[tokio::test]
async fn cache_material3_seeds_producer_signed_fact_even_with_discover_none() {
    let id = cache_identity(0xF3, "cache-material3");
    let cache = RevocationCache::new();

    let h = LineageServerHarness::builder(lifecycle_caps())
        .with_producer_did_document(id.path, id.did_doc.clone())
        .build()
        .await;
    let boundary = at("2026-05-01T00:00:00.000Z");
    h.seed_revocations(&id.revoker, &id.target_fp, &[boundary])
        .await;
    let client = h.client().with_revocation_cache(cache);
    let discovery = RevocationDiscovery::producer_signed_only();
    let policy_discover = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    let t = publish_plain_target(&h, &id).await;

    let err = VerifiedContext::fetch_with_policy(&client, &h.resolver, &t, &policy_discover)
        .await
        .expect_err("warm-up: discovery must find R and fail closed");
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");

    let searches_before = h.hits("search");
    let policy_no_discover = VerificationPolicy {
        revocations: RevocationPolicy::new(Vec::new()), // discover: None
        ..Default::default()
    };
    let err2 = VerifiedContext::fetch_with_policy(&client, &h.resolver, &t, &policy_no_discover)
        .await
        .expect_err(
            "discover: None must still seed the cached producer-signed fact and fail closed \
             (MATERIAL-3) — this is what extends anti-rollback to fetch/fetch_current, which \
             can never set `discover` at all",
        );
    assert!(
        matches!(err2, AcdpError::KeyNotAuthorized(_)),
        "got {err2:?}"
    );
    assert_eq!(
        h.hits("search"),
        searches_before,
        "discover: None must issue ZERO live discovery requests — the fact must come purely \
         from the seeded cache, never from a fresh search"
    );
}

// ── issue #260 (Phase 3): CrossRegistryResolver revocation-discovery ────────
//
// All tests below drive `acdp::client::CrossRegistryResolver` against the
// same real `LineageServerHarness` used throughout this file (never a
// hand-built mock), via `publish_derived_chain` (defined above,
// `publish_plain_target`'s neighbor) for the multi-node `derived_from`
// chains AC1/AC2/AC6/AC7 need, and `resolver.seed_client` to avoid real DNS
// resolution — the same trick `fed_006_registry_did_mismatch` /
// `sec_01_cross_registry_pins_authority_dns` (`tests/tls_conformance.rs`)
// already use.

/// AC1: **the multiplier does not materialize, on genuine default
/// configuration.** A walk over `CHAIN_LEN - 1` ancestor nodes from the
/// SAME producer, same registry, must issue producer-signed discovery
/// searches exactly ONCE (`2 type_forms x 3 statuses = 6`, matching the
/// pre-#258/#257 constant this wave's Phase 1 pinned), not once per node
/// (which would be `6 * (CHAIN_LEN - 1) = 24`) — via the resolver's
/// DEFAULT walk-scoped cache (no `with_revocation_cache` call at all) and
/// `RevocationDiscovery::producer_signed_only()` with `freshness` left
/// completely untouched (i.e. `Duration::ZERO`, the type default).
///
/// This restores the plan's original AC1 wording ("on default
/// configuration") to its literal reading (MATERIAL-3, fresh-Opus
/// whole-wave review): the resolver's own walk-scoped cache derives its
/// effective `RevocationDiscovery::freshness` from
/// `ResolverOptions::total_timeout` internally
/// (`CrossRegistryResolver::resolve_inner`'s `walk_scoped_freshness`
/// parameter), so a caller who sets nothing beyond
/// `producer_signed_only()` still gets suppression — no nonzero
/// `freshness` knob required. AC2 (below) is the honest counterpart:
/// a caller-supplied cache (`with_revocation_cache`) never gets this
/// derived value, so `freshness: ZERO` there still suppresses nothing.
///
/// This also exercises AC3 ("shared across every client the resolver
/// builds") and AC4(a) ("a seeded client with no cache participates in the
/// walk-wide cache"): `h.client()` carries no `RevocationCache` of its own,
/// and `resolve_inner`'s fill-if-absent logic treats a client already
/// sitting in `client_cache` (whether it got there via `seed_client` or a
/// lazy build) identically — there is no separate code path for "lazily
/// built" the way `seed_client` bypasses only the network-building step,
/// not the cache-attach step.
#[tokio::test]
async fn resolver_ac1_walk_scoped_cache_suppresses_repeat_discovery_by_default() {
    use acdp::client::CrossRegistryResolver;

    const CHAIN_LEN: usize = 5;

    let id = cache_identity(0xF0, "resolver-ac1");
    let registry_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();
    let h = LineageServerHarness::builder(lifecycle_caps())
        .with_registry_did_document(ed25519_did_doc(REGISTRY_DID, "key-1", &registry_pub))
        .with_well_known_acdp()
        .with_producer_did_document(id.path, id.did_doc.clone())
        .build()
        .await;
    let chain = publish_derived_chain(&h, &id, CHAIN_LEN).await;
    let root_body = h
        .server
        .retrieve(chain.last().unwrap(), None)
        .expect("retrieve")
        .expect("found")
        .body;

    // Genuine defaults (MATERIAL-3): `producer_signed_only()` with
    // `freshness` completely untouched — no test manually raises it.
    let discovery = RevocationDiscovery::producer_signed_only();
    assert_eq!(
        discovery.freshness,
        std::time::Duration::ZERO,
        "sanity: genuine defaults — producer_signed_only()'s freshness is untouched"
    );
    let policy = RevocationPolicy::default().with_discovery(discovery);

    let resolver = CrossRegistryResolver::new()
        .with_did_resolver(
            WebResolver::with_test_endpoint(&h.tls.root_cert_pem, "localhost", h.tls.addr)
                .expect("pinned resolver"),
        )
        .with_revocation_policy(policy);
    resolver.seed_client(REGISTRY_AUTHORITY, h.client());

    let before = h.hits("search");
    let ancestors = resolver
        .walk_derived_from(&root_body)
        .await
        .expect("a discovery-enabled walk over plain (non-revoked) contexts must succeed");
    assert_eq!(ancestors.len(), CHAIN_LEN - 1);
    let delta = h.hits("search") - before;
    let counterfactual = 6 * (CHAIN_LEN - 1);
    assert_eq!(
        delta,
        6,
        "issue #260 AC1 (MATERIAL-3): a walk over {} ancestor nodes from the SAME \
         producer/authority, on GENUINE default configuration (no with_revocation_cache, \
         no manual freshness override), must issue producer-signed discovery exactly \
         ONCE (6 searches), not once per node (which would be {counterfactual}) — the \
         resolver's own walk-scoped cache derives its effective freshness from \
         ResolverOptions::total_timeout, which is what collapses this without the caller \
         needing to touch RevocationDiscovery::freshness at all",
        CHAIN_LEN - 1,
    );
}

/// AC2: the honest counterpart to AC1. An EXPLICITLY caller-supplied cache
/// (`with_revocation_cache`, bypassing the resolver's own walk-scoped
/// default) with `freshness` left at its type default (`Duration::ZERO`)
/// suppresses NOTHING — discovery still runs once per node. Proves the
/// cost claim is falsifiable in both directions: merely sharing a cache
/// object is not what suppresses discovery; a nonzero `freshness` is what
/// does, exactly as in Phase 2's direct (non-resolver) model.
#[tokio::test]
async fn resolver_ac2_explicit_cache_with_zero_freshness_suppresses_nothing() {
    use acdp::client::CrossRegistryResolver;

    const CHAIN_LEN: usize = 5;

    let id = cache_identity(0xF6, "resolver-ac2");
    let registry_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();
    let h = LineageServerHarness::builder(lifecycle_caps())
        .with_registry_did_document(ed25519_did_doc(REGISTRY_DID, "key-1", &registry_pub))
        .with_well_known_acdp()
        .with_producer_did_document(id.path, id.did_doc.clone())
        .build()
        .await;
    let chain = publish_derived_chain(&h, &id, CHAIN_LEN).await;
    let root_body = h
        .server
        .retrieve(chain.last().unwrap(), None)
        .expect("retrieve")
        .expect("found")
        .body;

    let discovery = RevocationDiscovery::producer_signed_only();
    assert_eq!(
        discovery.freshness,
        std::time::Duration::ZERO,
        "sanity: producer_signed_only()'s freshness defaults to ZERO"
    );
    let policy = RevocationPolicy::default().with_discovery(discovery);

    let resolver = CrossRegistryResolver::new()
        .with_did_resolver(
            WebResolver::with_test_endpoint(&h.tls.root_cert_pem, "localhost", h.tls.addr)
                .expect("pinned resolver"),
        )
        .with_revocation_policy(policy)
        .with_revocation_cache(RevocationCache::new());
    resolver.seed_client(REGISTRY_AUTHORITY, h.client());

    let before = h.hits("search");
    let ancestors = resolver
        .walk_derived_from(&root_body)
        .await
        .expect("a discovery-enabled walk over plain (non-revoked) contexts must succeed");
    assert_eq!(ancestors.len(), CHAIN_LEN - 1);
    let delta = h.hits("search") - before;
    assert_eq!(
        delta,
        6 * (CHAIN_LEN - 1),
        "issue #260 AC2: a caller-supplied cache with freshness ZERO must suppress NOTHING \
         — discovery runs once per node ({} nodes x 6 searches each)",
        CHAIN_LEN - 1,
    );
}

/// AC4(b): `seed_client` is preserve-if-present, the other half of
/// fill-if-absent (AC1/AC3/AC4(a) above cover the fill-if-absent half). A
/// client that already carries its OWN `RevocationCache` (warmed with a
/// fact BEFORE it is seeded into the resolver) keeps that cache — the
/// resolver must NOT overwrite it with its own (also explicitly attached,
/// but empty) cache.
///
/// Both the control and the test resolver below carry their OWN,
/// resolver-level `RevocationCache` (empty) — this is deliberate: it is
/// what makes the mutation "always overwrite" actually observable. If the
/// resolver carried no cache of its own at all (`cache: None` in
/// `resolve_inner`), preserve-vs-overwrite would have nothing to overwrite
/// WITH, and this test could not fail under that mutation — exactly the
/// kind of unfalsifiable AC this wave's own review process has twice
/// caught before (see `plans/PROGRESS.md`'s #248/#257 notes).
///
/// Isolated with a positive control: the SAME resolver configuration
/// (no revocation policy, i.e. `discover: None`, but WITH its own empty
/// resolver-level cache) seeded with a PLAIN (un-warmed) client succeeds —
/// proving that the fail-closed result seen with the warmed client below
/// comes specifically from the preserved fact, not from some other effect.
#[tokio::test]
async fn resolver_ac4b_seeded_client_with_its_own_cache_is_preserved() {
    use acdp::client::CrossRegistryResolver;

    let id = cache_identity(0xF2, "resolver-ac4b");
    let registry_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();
    let h = LineageServerHarness::builder(lifecycle_caps())
        .with_registry_did_document(ed25519_did_doc(REGISTRY_DID, "key-1", &registry_pub))
        .with_well_known_acdp()
        .with_producer_did_document(id.path, id.did_doc.clone())
        .build()
        .await;
    let boundary = at("2026-05-01T00:00:00.000Z");
    h.seed_revocations(&id.revoker, &id.target_fp, &[boundary])
        .await;
    let t = publish_plain_target(&h, &id).await;

    let make_resolver = || {
        CrossRegistryResolver::new()
            .with_did_resolver(
                WebResolver::with_test_endpoint(&h.tls.root_cert_pem, "localhost", h.tls.addr)
                    .expect("pinned resolver"),
            )
            // The resolver itself carries an explicit, but EMPTY, cache —
            // No `with_revocation_policy` call: `discover: None`.
            .with_revocation_cache(RevocationCache::new())
    };

    // Positive control: a PLAIN seeded client (no cache of its own) under
    // this same discover:None + resolver-level-empty-cache config
    // succeeds — `RevocationPolicy::default()` carries no `known` and no
    // `discover`, so the phase is inert regardless of what the harness has
    // seeded, and the resolver's own cache is empty either way.
    let control = make_resolver();
    control.seed_client(REGISTRY_AUTHORITY, h.client());
    control
        .resolve(&t)
        .await
        .expect("control: discover:None + an empty cache must be inert and succeed");

    // Warm a SEPARATE client's OWN cache with the fact BEFORE seeding it:
    // a direct discovery call with `freshness: ZERO` (the default) records
    // only the FACT, not a marker, isolating "the fact survived seeding"
    // from "the marker suppressed re-discovery".
    let pre_cache = RevocationCache::new();
    let warmed_client = h.client().with_revocation_cache(pre_cache);
    let discovery = RevocationDiscovery::producer_signed_only();
    let policy_discover = VerificationPolicy {
        revocations: RevocationPolicy::default().with_discovery(discovery),
        ..Default::default()
    };
    let warm_err =
        VerifiedContext::fetch_with_policy(&warmed_client, &h.resolver, &t, &policy_discover)
            .await
            .expect_err("warm-up: discovery must find the seeded revocation and fail closed");
    assert!(
        matches!(warm_err, AcdpError::KeyNotAuthorized(_)),
        "got {warm_err:?}"
    );

    // Seed the ALREADY-WARM client into a FRESH discover:None resolver that
    // ALSO carries its own (different, empty) cache. If preserve-if-present
    // holds, the warmed client's own fact-bearing cache wins and the call
    // still fails closed; if the resolver instead overwrote it with its
    // own empty one (the mutation this test guards against), the fact
    // would be lost and the call would wrongly succeed.
    let test_resolver = make_resolver();
    test_resolver.seed_client(REGISTRY_AUTHORITY, warmed_client);
    let err = test_resolver.resolve(&t).await.expect_err(
        "issue #260 AC4(b): a seeded client's OWN pre-attached cache must be preserved, not \
         overwritten by the resolver's own (empty) cache — its already-recorded fact must \
         still fail closed",
    );
    assert!(matches!(err, AcdpError::KeyNotAuthorized(_)), "got {err:?}");
}

/// AC5: **vantage binding is pinned, not merely structural.** A freshness
/// marker minted while resolving via one `RegistryClient` vantage
/// (`.authority()`) must not suppress discovery when the SAME producer and
/// SAME context are later resolved via a DIFFERENT vantage — even when both
/// share one `RevocationCache` (`with_revocation_cache`). `client.authority()`
/// (read by `crate::revocation`'s marker/fact bookkeeping, RFC-ACDP-0014 §6
/// scoping) is deliberately NOT the same string as the resolver-level
/// authority key used for `client_for` lookups / DID matching — vantage B
/// below is re-seeded under the SAME resolver-level key ("localhost",
/// matching the ctx_id's own embedded authority and the harness's real
/// `registry_did`) but is a physically different `RegistryClient` (a
/// different `.base`, hence a different `.authority()`), pinned to the
/// SAME physical harness. This is what proves the scoping is genuinely
/// per-vantage rather than accidentally per-resolver-authority-key.
#[tokio::test]
async fn resolver_ac5_vantage_binding_pins_discovery_to_the_serving_client() {
    use acdp::client::CrossRegistryResolver;

    let id = cache_identity(0xF3, "resolver-ac5");
    let registry_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();
    let h = LineageServerHarness::builder(lifecycle_caps())
        .with_registry_did_document(ed25519_did_doc(REGISTRY_DID, "key-1", &registry_pub))
        .with_well_known_acdp()
        .with_producer_did_document(id.path, id.did_doc.clone())
        .build()
        .await;
    let t = publish_plain_target(&h, &id).await;

    let mut discovery = RevocationDiscovery::producer_signed_only();
    discovery.freshness = std::time::Duration::from_secs(60);
    let policy = RevocationPolicy::default().with_discovery(discovery);
    let shared_cache = RevocationCache::new();

    let resolver = CrossRegistryResolver::new()
        .with_did_resolver(
            WebResolver::with_test_endpoint(&h.tls.root_cert_pem, "localhost", h.tls.addr)
                .expect("pinned resolver"),
        )
        .with_revocation_policy(policy)
        .with_revocation_cache(shared_cache);

    // Vantage A: the harness's own client, `.authority() == "localhost"`.
    resolver.seed_client(REGISTRY_AUTHORITY, h.client());
    resolver
        .resolve(&t)
        .await
        .expect("vantage A baseline mints A's marker");

    // Vantage B: SAME ctx_id / producer / physical harness, re-seeded under
    // the SAME resolver-level authority KEY, but a DIFFERENT `RegistryClient`
    // (a different `.base` — same host `localhost` so the harness's
    // `localhost`-only TLS certificate still validates, but this base
    // explicitly spells out the real port, `h.tls.addr.port()` — hence a
    // different `.authority()` string than vantage A's portless `h.client()`
    // base), pinned via `.resolve()` to the SAME physical socket regardless
    // of the URL's own port.
    let alt_base = format!("https://localhost:{}", h.tls.addr.port());
    let vantage_b = RegistryClient::with_test_endpoint(&alt_base, h.tls.addr, &h.tls.root_cert_pem)
        .expect("vantage B client");
    assert_ne!(
        vantage_b.authority().as_deref(),
        Some("localhost"),
        "sanity: vantage B must report a genuinely different authority"
    );
    resolver.seed_client(REGISTRY_AUTHORITY, vantage_b);

    let before_b = h.hits("search");
    resolver.resolve(&t).await.expect("vantage B baseline");
    assert!(
        h.hits("search") > before_b,
        "issue #260 AC5: a freshness marker minted while resolving via vantage A must NOT \
         suppress discovery when the SAME producer/context is later resolved via a DIFFERENT \
         vantage B, even though both share one RevocationCache"
    );

    // N1 (fresh-Opus whole-wave review): a positive control. Without this,
    // AC5 would pass under a probe where NOTHING is ever suppressed (e.g.
    // `marker_fresh` always returning `false`) — `hits("search") >
    // before_b` is equally true either way. Re-seed vantage A and resolve
    // again: A's own marker (minted just above, `freshness: 60s`) MUST
    // still suppress discovery, distinguishing "B correctly not
    // suppressed" from "nothing is ever suppressed at all".
    resolver.seed_client(REGISTRY_AUTHORITY, h.client());
    let before_a_again = h.hits("search");
    resolver
        .resolve(&t)
        .await
        .expect("vantage A, resolved again, reuses its own fresh marker");
    assert_eq!(
        h.hits("search"),
        before_a_again,
        "issue #260 AC5 positive control: a SECOND resolve via vantage A must be suppressed \
         by A's own still-fresh marker — proving discovery CAN be suppressed at all, which is \
         what makes 'vantage B is not suppressed' above a meaningful contrast rather than a \
         tautology"
    );
}

/// AC6: the concrete payoff of the walk-scoped cache, on GENUINE default
/// configuration (MATERIAL-3: `producer_signed_only()` with `freshness`
/// untouched — the resolver's own walk-scoped cache derives its effective
/// freshness from this test's (scaled-down) `ResolverOptions::total_timeout`
/// internally). A per-`search`-request delay makes ONE discovery round
/// cost roughly `6 * 80ms = 480ms`; an (incorrect) per-node cache would
/// cost `CHAIN_LEN - 1` rounds — about 1.9s for 4 ancestors — comfortably
/// over the small `total_timeout` below. The walk-scoped default keeps the
/// walk to ONE round regardless of chain length, so it finishes
/// comfortably inside budget. Uses a scaled-down `total_timeout` (not the
/// literal 30s default) so the test runs fast while still proving the
/// same structural property the 30s default relies on in production.
#[tokio::test]
async fn resolver_ac6_walk_scoped_cache_lets_a_discovery_enabled_walk_complete() {
    use acdp::client::{CrossRegistryResolver, ResolverOptions};

    const CHAIN_LEN: usize = 5;

    let id = cache_identity(0xF4, "resolver-ac6");
    let registry_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();
    let h = LineageServerHarness::builder(lifecycle_caps())
        .with_registry_did_document(ed25519_did_doc(REGISTRY_DID, "key-1", &registry_pub))
        .with_well_known_acdp()
        .with_producer_did_document(id.path, id.did_doc.clone())
        .build()
        .await;
    let chain = publish_derived_chain(&h, &id, CHAIN_LEN).await;
    let root_body = h
        .server
        .retrieve(chain.last().unwrap(), None)
        .expect("retrieve")
        .expect("found")
        .body;

    h.set_delay("search", std::time::Duration::from_millis(80));

    // Genuine defaults (MATERIAL-3): no manual freshness override. The
    // resolver's own walk-scoped cache derives its effective freshness
    // from `ResolverOptions::total_timeout` below (800ms) — comfortably
    // above the ~480ms one discovery round takes, so the walk still
    // completes in ONE round.
    let discovery = RevocationDiscovery::producer_signed_only();
    let policy = RevocationPolicy::default().with_discovery(discovery);

    let resolver = CrossRegistryResolver::new()
        .with_did_resolver(
            WebResolver::with_test_endpoint(&h.tls.root_cert_pem, "localhost", h.tls.addr)
                .expect("pinned resolver"),
        )
        .with_revocation_policy(policy)
        .with_options(ResolverOptions {
            total_timeout: std::time::Duration::from_millis(800),
            ..ResolverOptions::default()
        });
    resolver.seed_client(REGISTRY_AUTHORITY, h.client());

    let ancestors = resolver.walk_derived_from(&root_body).await.expect(
        "issue #260 AC6: a discovery-enabled walk must complete within a small total_timeout \
         because the walk-scoped cache collapses discovery to ONE round regardless of chain \
         length",
    );
    assert_eq!(ancestors.len(), CHAIN_LEN - 1);
}

/// AC7: with no revocation configuration injected at all (no
/// `with_revocation_policy` call — `RevocationPolicy::default()` is inert:
/// empty `known`, `discover: None`), resolver behavior is byte-identical to
/// v0.13.0 — zero discovery-related search traffic.
#[tokio::test]
async fn resolver_ac7_no_revocation_config_is_byte_identical_to_pre_260() {
    use acdp::client::CrossRegistryResolver;

    const CHAIN_LEN: usize = 4;

    let id = cache_identity(0xF5, "resolver-ac7");
    let registry_pub = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes();
    let h = LineageServerHarness::builder(lifecycle_caps())
        .with_registry_did_document(ed25519_did_doc(REGISTRY_DID, "key-1", &registry_pub))
        .with_well_known_acdp()
        .with_producer_did_document(id.path, id.did_doc.clone())
        .build()
        .await;
    let chain = publish_derived_chain(&h, &id, CHAIN_LEN).await;
    let root_body = h
        .server
        .retrieve(chain.last().unwrap(), None)
        .expect("retrieve")
        .expect("found")
        .body;

    let resolver = CrossRegistryResolver::new().with_did_resolver(
        WebResolver::with_test_endpoint(&h.tls.root_cert_pem, "localhost", h.tls.addr)
            .expect("pinned resolver"),
    );
    resolver.seed_client(REGISTRY_AUTHORITY, h.client());
    assert_eq!(
        resolver.revocation_policy(),
        &RevocationPolicy::default(),
        "sanity: a resolver with no with_revocation_policy call carries the inert default"
    );

    let before = h.hits("search");
    let ancestors = resolver
        .walk_derived_from(&root_body)
        .await
        .expect("walk must complete");
    assert_eq!(ancestors.len(), CHAIN_LEN - 1);
    assert_eq!(
        h.hits("search"),
        before,
        "issue #260 AC7: with no revocation configuration injected, resolver behavior is \
         byte-identical to pre-#260 — zero discovery-related search traffic"
    );
}
