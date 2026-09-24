//! Witness-cosigning conformance bindings (ACDP 0.4, RFC-ACDP-0015) —
//! the wit-001..004 fixtures executed against the SDK.
//!
//! - `wit-001` is executed arithmetically (the runner's
//!   `check_witness_cosignature_vector` behavior): the cosignature JCS
//!   preimage canonical form, the cosignature hash, the signing input
//!   (ASCII `"sha256:<hex>"`), and the Ed25519 signature — all via a
//!   deterministic re-mint under the witness test keypair (seed `0x33`),
//!   byte-compared against the fixture; the `witnessed_checkpoint` chains
//!   to the `log-001` tree-size-5 golden checkpoint.
//! - `wit-003` is the quorum golden: two distinct witnesses (seeds
//!   `0x33`, `0x44`) cosign the same `log-001` tuple → §8 yields
//!   2-witnessed.
//! - `wit-004` is behavioral: a cosignature signed by the WRONG witness
//!   key MUST fail consumer verification as
//!   [`acdp::AcdpError::InvalidWitnessCosignature`].
//! - `wit-002` is behavioral: a witness holding a retained head MUST NOT
//!   cosign a checkpoint that fails consistency against it (the §7
//!   obligation, driven end-to-end through `mint_cosignature_checked`).
//!
//! Fixture-gate pattern as `tests/transparency_log.rs`: locates the spec
//! via `ACDP_SPEC_DIR` (fallback: sibling checkout), skips gracefully
//! when absent, and hard-fails under `ACDP_REQUIRE_CONFORMANCE`.

#[cfg(all(feature = "client", feature = "server", feature = "test-transport"))]
mod common;

use std::path::{Path, PathBuf};

use acdp::types::cosignature::{LogCosignature, WitnessSigner, COSIGNATURE_VERSION};
use acdp::types::log::LogCheckpoint;
use acdp::AcdpError;

// ── Spec locator (the strict gate from tests/conformance.rs) ─────────────────

fn require_conformance() -> bool {
    std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok()
}

fn spec_root() -> Option<PathBuf> {
    if let Ok(env) = std::env::var("ACDP_SPEC_DIR") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
        assert!(
            !require_conformance(),
            "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR '{}' does not exist",
            p.display()
        );
    } else {
        assert!(
            !require_conformance(),
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
        !require_conformance(),
        "ACDP_REQUIRE_CONFORMANCE is set but no ACDP spec checkout could be located"
    );
    None
}

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

fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

fn seed32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

fn parse_ts(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .unwrap()
        .with_timezone(&chrono::Utc)
}

/// A minimal witness did.json with the key in BOTH `verificationMethod`
/// and `assertionMethod` (RFC-ACDP-0015 §9).
#[cfg(feature = "client")]
fn witness_doc(did: &str, fragment: &str, pub_key: &[u8; 32]) -> serde_json::Value {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let vm_id = format!("{did}#{fragment}");
    serde_json::json!({
        "id": did,
        "verificationMethod": [{
            "id": vm_id,
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(pub_key) }
        }],
        "assertionMethod": [vm_id],
    })
}

/// Build the `log-001` tree-size-5 golden checkpoint the wit-* vectors
/// chain to (`chains_to_log_fixture`).
fn log001_checkpoint(root: &Path) -> Option<LogCheckpoint> {
    let path = root.join("schemas/conformance/log-001-leaf-and-root-golden.json");
    if fixture_missing(&path) {
        return None;
    }
    let v = read_json(&path);
    Some(LogCheckpoint::from_value(&v["vectors"][0]["expected"]["log_checkpoint"]).unwrap())
}

// ═══════════════════════════════════════════════════════════════════════
// wit-001 — cosignature golden vector (executed arithmetically)
// ═══════════════════════════════════════════════════════════════════════

/// Deterministic witness-keyed re-mint reproduces the fixture's canonical
/// preimage bytes, cosignature hash, signing input, and Ed25519
/// signature; the assembled `log_cosignature` equals the fixture; the
/// `witnessed_checkpoint` chains to the `log-001` checkpoint (steps 1–7).
#[test]
fn wit_001_cosignature_golden_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/wit-001-cosignature-golden.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let Some(checkpoint) = log001_checkpoint(&root) else {
        return;
    };

    let kp = &v["witness_test_keypair"];
    let seed = seed32(kp["private_seed_hex"].as_str().unwrap());
    let witness_pub = acdp::crypto::SigningKey::from_bytes(&seed).verifying_key_bytes();
    // The fixture's declared witness public key is our derived one.
    assert_eq!(
        hex::encode(witness_pub),
        kp["public_key_hex"].as_str().unwrap(),
        "wit-001: witness test public key derivation"
    );

    let vector = &v["vectors"][0];
    let unsigned = &vector["cosignature_unsigned"];
    let expected = &vector["expected"];
    let witness_id = unsigned["witness_id"].as_str().unwrap();
    let key_id = kp["key_id"].as_str().unwrap();

    // Step 1: JCS canonical form of the cosignature minus `signature`.
    let canonical = acdp::crypto::try_canonicalize_value(unsigned).unwrap();
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        expected["canonical_form"].as_str().unwrap(),
        "wit-001: cosignature canonical preimage bytes (RFC-ACDP-0015 §4–§5)"
    );

    // Step 2: cosignature hash = 'sha256:' + SHA-256 hex of the canonical
    // bytes; also the signing input.
    let cosig_hash = LogCosignature::preimage_hash_of_value(unsigned).unwrap();
    assert_eq!(
        cosig_hash.as_str(),
        expected["cosignature_hash"].as_str().unwrap(),
        "wit-001: cosignature hash (RFC-ACDP-0015 §5 step 2)"
    );
    assert_eq!(
        cosig_hash.as_str(),
        expected["signature_input"].as_str().unwrap(),
        "wit-001: the signing input IS the ASCII cosignature-hash string"
    );

    // Steps 3 + 5: deterministic witness-keyed re-mint over the log-001
    // checkpoint reproduces the pinned signature; the witnessed_checkpoint
    // chains to log-001.
    let signer = WitnessSigner::new(
        acdp::crypto::SigningKey::from_bytes(&seed),
        witness_id,
        key_id,
    )
    .unwrap();
    let minted = signer
        .mint(
            &checkpoint,
            parse_ts(unsigned["witnessed_at"].as_str().unwrap()),
        )
        .unwrap();
    assert_eq!(minted.cosignature_version, COSIGNATURE_VERSION);
    assert_eq!(
        minted.signature.value,
        expected["signature_value_base64"].as_str().unwrap(),
        "wit-001: deterministic Ed25519 re-mint must reproduce the fixture signature"
    );
    assert_eq!(
        hex::encode(base64_decode(&minted.signature.value)),
        expected["signature_value_hex"].as_str().unwrap(),
        "wit-001: signature hex form"
    );
    assert_eq!(
        serde_json::to_value(&minted).unwrap(),
        expected["log_cosignature"],
        "wit-001: minted wire form must equal the fixture log_cosignature"
    );
    // Chaining (step 5): the cosigned tuple IS the log-001 checkpoint.
    assert_eq!(minted.witnessed_checkpoint.log_id, checkpoint.log_id);
    assert_eq!(minted.witnessed_checkpoint.tree_size, checkpoint.tree_size);
    assert_eq!(minted.witnessed_checkpoint.root_hash, checkpoint.root_hash);

    // The pinned wire cosignature round-trips the closed parse and
    // verifies against the witness test public key over the RAW preimage.
    let wire = &expected["log_cosignature"];
    let parsed = LogCosignature::from_value(wire).unwrap();
    let raw_hash = LogCosignature::preimage_hash_of_value(wire).unwrap();
    assert_eq!(raw_hash, cosig_hash);
    parsed
        .verify_signature_against_hash(&raw_hash, Some(&witness_pub), None)
        .unwrap();
    parsed.cross_check_against_checkpoint(&checkpoint).unwrap();

    // Step 7 — the consumer §8 procedure end-to-end (client feature).
    #[cfg(feature = "client")]
    {
        let doc = witness_doc(witness_id, "witness-key-1", &witness_pub);
        let verified = acdp::client::verify_witness_cosignature_value(
            wire,
            &doc,
            &checkpoint,
            Some(parse_ts(unsigned["witnessed_at"].as_str().unwrap())),
            None,
        )
        .expect("wit-001: §8 consumer verification must pass");
        assert_eq!(verified.witness_id, witness_id);

        // 1-witnessed for a consumer trusting this witness.
        let mut docs = std::collections::HashMap::new();
        docs.insert(witness_id.to_string(), doc);
        let trusted: std::collections::HashSet<String> =
            [witness_id.to_string()].into_iter().collect();
        let report = acdp::client::evaluate_witness_quorum(
            std::slice::from_ref(wire),
            &docs,
            &trusted,
            &checkpoint,
            &acdp::client::WitnessPolicy::default(),
            Some(parse_ts(unsigned["witnessed_at"].as_str().unwrap())),
        );
        assert_eq!(
            report.witnessed_count,
            v["expected_quorum"]["witnessed_count"].as_u64().unwrap() as usize,
            "wit-001: 1-witnessed (RFC-ACDP-0015 §8)"
        );
        assert!(report.meets_quorum);
    }
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(s).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════
// wit-003 — quorum golden vector (executed arithmetically)
// ═══════════════════════════════════════════════════════════════════════

/// Two distinct witnesses (seeds `0x33`, `0x44`) each re-mint their
/// cosignature byte-for-byte over the same `log-001` tuple; the §8
/// N-witnessed count over distinct `witness_id` values equals 2.
#[test]
fn wit_003_quorum_verification_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/wit-003-quorum-verification.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    let Some(checkpoint) = log001_checkpoint(&root) else {
        return;
    };

    // Each vector: deterministic per-witness re-mint reproduces the pinned
    // canonical form / hash / signature.
    #[allow(unused_mut)]
    let mut cosig_wires: Vec<serde_json::Value> = Vec::new();
    #[cfg(feature = "client")]
    let mut docs = std::collections::HashMap::new();
    #[cfg(feature = "client")]
    let mut trusted: std::collections::HashSet<String> = std::collections::HashSet::new();

    for vector in v["vectors"].as_array().unwrap() {
        let kp = &vector["witness_test_keypair"];
        let seed = seed32(kp["private_seed_hex"].as_str().unwrap());
        let unsigned = &vector["cosignature_unsigned"];
        let expected = &vector["expected"];
        let witness_id = unsigned["witness_id"].as_str().unwrap();

        let canonical = acdp::crypto::try_canonicalize_value(unsigned).unwrap();
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            expected["canonical_form"].as_str().unwrap(),
            "wit-003: {witness_id} canonical form"
        );
        let hash = LogCosignature::preimage_hash_of_value(unsigned).unwrap();
        assert_eq!(
            hash.as_str(),
            expected["cosignature_hash"].as_str().unwrap()
        );

        let signer = WitnessSigner::new(
            acdp::crypto::SigningKey::from_bytes(&seed),
            witness_id,
            format!("{witness_id}#witness-key-1"),
        )
        .unwrap();
        let minted = signer
            .mint(
                &checkpoint,
                parse_ts(unsigned["witnessed_at"].as_str().unwrap()),
            )
            .unwrap();
        assert_eq!(
            minted.signature.value,
            expected["signature_value_base64"].as_str().unwrap(),
            "wit-003: {witness_id} deterministic re-mint"
        );
        let wire = serde_json::to_value(&minted).unwrap();

        #[cfg(feature = "client")]
        {
            let witness_pub = acdp::crypto::SigningKey::from_bytes(&seed).verifying_key_bytes();
            docs.insert(
                witness_id.to_string(),
                witness_doc(witness_id, "witness-key-1", &witness_pub),
            );
            trusted.insert(witness_id.to_string());
        }
        cosig_wires.push(wire);
    }

    // §8 N-witnessed = distinct witness_id values verifying over one tuple.
    #[cfg(feature = "client")]
    {
        // Evaluate at a `now` past both witnessed_at values so neither is
        // future-skewed; the fixture pins a witnessed_count of 2.
        let now = parse_ts("2026-07-04T12:10:00.000Z");
        let report = acdp::client::evaluate_witness_quorum(
            &cosig_wires,
            &docs,
            &trusted,
            &checkpoint,
            &acdp::client::WitnessPolicy {
                min_witnesses: 2,
                ..acdp::client::WitnessPolicy::default()
            },
            Some(now),
        );
        assert_eq!(
            report.witnessed_count,
            v["expected_quorum"]["witnessed_count"].as_u64().unwrap() as usize,
            "wit-003: 2-witnessed (RFC-ACDP-0015 §8)"
        );
        assert!(report.meets_quorum, "min_witnesses=2 policy satisfied");
        assert!(report.failures.is_empty());
    }
}

// ═══════════════════════════════════════════════════════════════════════
// wit-004 — cosignature key mismatch (behavioral)
// ═══════════════════════════════════════════════════════════════════════

/// A cosignature whose `signature.value` was produced by the WRONG
/// witness key (witness B over witness A's body) MUST fail consumer
/// verification as `invalid_witness_cosignature` (§8 step 2, §10) — the
/// analogue of `rcpt-003`/`log-004` for the witness layer. The
/// cosignature parses and is well-formed; the failure is cryptographic.
#[test]
fn wit_004_cosignature_key_mismatch_fixture() {
    let Some(root) = spec_root() else { return };
    let path = root.join("schemas/conformance/wit-004-cosignature-key-mismatch.json");
    if fixture_missing(&path) {
        return;
    }
    let v = read_json(&path);
    // The checkpoint is only needed for the §8 consumer procedure below
    // (client feature); the type-level checks work off the pinned hash.
    let Some(_checkpoint) = log001_checkpoint(&root) else {
        return;
    };
    let wire = &v["cosignature"];

    // It parses (well-formed) and its hash is the pinned genuine one.
    let cosig = LogCosignature::from_value(wire).unwrap();
    let raw_hash = LogCosignature::preimage_hash_of_value(wire).unwrap();
    assert_eq!(
        raw_hash.as_str(),
        v["expected"]["cosignature_hash"].as_str().unwrap(),
        "wit-004: the cosignature hash is the genuine wit-001 hash"
    );

    // Type level: the pinned value does NOT verify under witness A's key
    // (17cb79...); it DOES verify under the wrong signer's key (witness B,
    // d75979...).
    let a_pub = seed32(
        v["witness_did_document"]["assertion_method_key_public_hex"]
            .as_str()
            .unwrap(),
    );
    let b_pub = seed32(v["wrong_signer_key_public_hex"].as_str().unwrap());
    let err = cosig
        .verify_signature_against_hash(&raw_hash, Some(&a_pub), None)
        .unwrap_err();
    assert!(
        matches!(err, AcdpError::InvalidWitnessCosignature(_)),
        "wit-004: wrong-key value must fail under witness A's key, got {err:?}"
    );
    assert!(
        !err.is_transient(),
        "a bad cosignature will not verify on retry"
    );
    cosig
        .verify_signature_against_hash(&raw_hash, Some(&b_pub), None)
        .expect("wit-004 premise: the value is a valid signature by witness B's key");

    // Consumer §8 procedure: resolving witness A's assertionMethod key and
    // verifying MUST fail with invalid_witness_cosignature.
    #[cfg(feature = "client")]
    {
        let witness_id = cosig.witness_id.as_str();
        let doc = witness_doc(witness_id, "witness-key-1", &a_pub);
        let err = acdp::client::verify_witness_cosignature_value(
            wire,
            &doc,
            &_checkpoint,
            Some(parse_ts(wire["witnessed_at"].as_str().unwrap())),
            None,
        )
        .expect_err("wit-004: §8 step 2 MUST fail");
        assert!(
            matches!(err, AcdpError::InvalidWitnessCosignature(_)),
            "wit-004: got {err:?}"
        );

        // It does NOT count toward N for a consumer trusting witness A.
        let mut docs = std::collections::HashMap::new();
        docs.insert(witness_id.to_string(), doc);
        let trusted: std::collections::HashSet<String> =
            [witness_id.to_string()].into_iter().collect();
        let report = acdp::client::evaluate_witness_quorum(
            std::slice::from_ref(wire),
            &docs,
            &trusted,
            &_checkpoint,
            &acdp::client::WitnessPolicy::default(),
            Some(parse_ts(wire["witnessed_at"].as_str().unwrap())),
        );
        assert_eq!(
            report.witnessed_count, 0,
            "wit-004: 0-witnessed (failed cosig)"
        );
        assert!(!report.meets_quorum);
        assert_eq!(
            report.failures.len(),
            1,
            "the failing cosignature is recorded"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// wit-002 — consistency-refusal (behavioral, §7 obligation end-to-end)
// ═══════════════════════════════════════════════════════════════════════

/// A witness holding a retained size-3 head MUST NOT cosign a
/// signature-valid size-5 checkpoint whose `root_hash` is inconsistent
/// with it (RFC-ACDP-0015 §7 step 2). Driven end-to-end through
/// `mint_cosignature_checked` over an in-process TLS registry: the
/// genuine (consistent) checkpoint is cosigned; the rewritten one is
/// refused with the consistency verdict (`InvalidLogProof`), and NO
/// cosignature is produced — the entire point of witnessing.
#[cfg(all(feature = "client", feature = "server", feature = "test-transport"))]
#[tokio::test]
#[allow(deprecated)] // test-transport resolver constructor; gated in 0.4.0
async fn wit_002_consistency_refusal_fixture() {
    use acdp::client::{mint_cosignature_checked, WitnessConsistencyCheck};
    use acdp::did::WebResolver;
    use acdp::registry::MerkleLog;
    use acdp::types::log::{LogConsistencyProof, LogLeaf, LOG_LEAF_VERSION};
    use acdp::types::receipt::ReceiptSigner;
    use acdp::types::{ContentHash, CtxId};
    use common::{ed25519_did_doc, TlsTestServer};

    let Some(_root) = spec_root() else { return };

    const REGISTRY_DID: &str = "did:web:localhost";
    const LOG_ID: &str = "did:web:localhost/log/1";
    const WITNESS_DID: &str = "did:web:witness.example.org";
    const REG_SEED: [u8; 32] = [0x11u8; 32];
    const WIT_SEED: [u8; 32] = [0x33u8; 32];

    let signer = ReceiptSigner::new(
        acdp::crypto::SigningKey::from_bytes(&REG_SEED),
        REGISTRY_DID,
        format!("{REGISTRY_DID}#receipt-key-1"),
    )
    .unwrap();

    // Five genuine publish events; the witness retained the size-3 head.
    let mut log = MerkleLog::new(LOG_ID).unwrap();
    for i in 0..5u8 {
        let ctx_id = format!("acdp://localhost/00000000-0000-4000-8000-0000000000{i:02}");
        log.append(LogLeaf {
            leaf_version: LOG_LEAF_VERSION.into(),
            lineage_id: acdp::crypto::derive_lineage_id(&CtxId(ctx_id.clone())),
            ctx_id: CtxId(ctx_id),
            origin_registry: "localhost".into(),
            created_at: parse_ts("2026-07-01T01:00:00.123Z"),
            content_hash: ContentHash(format!("sha256:{}", "b".repeat(64))),
            key_fingerprint: format!("sha256:{}", "c".repeat(64)),
            receipt_hash: format!("sha256:{}", "d".repeat(64)),
        })
        .unwrap();
    }
    let genuine_cp5 = log.checkpoint(&signer, chrono::Utc::now()).unwrap();
    let cp3 = log.checkpoint_at(&signer, 3, chrono::Utc::now()).unwrap();
    let retained_root = cp3.root_hash.clone(); // the retained size-3 head
    let consistency = log.consistency_proof_response(3, &genuine_cp5).unwrap();
    let consistency_wire = serde_json::to_value(&consistency).unwrap();

    // A fabricated size-5 checkpoint: same size, REWRITTEN root, but a
    // GENUINE registry signature (so §7 step 1 passes — the point is that
    // consistency, step 2, is the gate).
    let rewritten_root = format!("sha256:{}", "de".repeat(32));
    let fabricated_cp5 = signer
        .mint_log_checkpoint(LOG_ID, 5, &rewritten_root, chrono::Utc::now())
        .unwrap();
    let mut fabricated_consistency = consistency_wire.clone();
    fabricated_consistency["log_checkpoint"] = serde_json::to_value(&fabricated_cp5).unwrap();

    // Live did:web document for the registry's receipt key.
    let registry_pub = acdp::crypto::SigningKey::from_bytes(&REG_SEED).verifying_key_bytes();
    let doc = ed25519_did_doc(REGISTRY_DID, "receipt-key-1", &registry_pub);
    let tls = TlsTestServer::start(axum::Router::new().route(
        "/.well-known/did.json",
        axum::routing::get(move || {
            let doc = doc.clone();
            async move { axum::Json(doc) }
        }),
    ))
    .await;
    let resolver = WebResolver::with_test_endpoint(&tls.root_cert_pem, "localhost", tls.addr)
        .expect("pinned resolver");
    let skew = chrono::Duration::seconds(120);

    let wsigner = WitnessSigner::new(
        acdp::crypto::SigningKey::from_bytes(&WIT_SEED),
        WITNESS_DID,
        format!("{WITNESS_DID}#witness-key-1"),
    )
    .unwrap();

    // The GENUINE checkpoint is consistent with the retained head → the
    // witness cosigns it.
    let genuine_wire = serde_json::to_value(&genuine_cp5).unwrap();
    let cosig = mint_cosignature_checked(
        &wsigner,
        &genuine_wire,
        "localhost",
        REGISTRY_DID,
        Some(WitnessConsistencyCheck {
            retained_root_hash: &retained_root,
            consistency_proof: &consistency_wire,
        }),
        chrono::Utc::now(),
        skew,
        &resolver,
    )
    .await
    .expect("wit-002: a consistent checkpoint is cosigned");
    assert_eq!(cosig.witnessed_checkpoint.root_hash, genuine_cp5.root_hash);

    // The REWRITTEN checkpoint is signature-valid but NOT consistent with
    // the retained head → the witness MUST refuse. No cosignature.
    let fabricated_wire = serde_json::to_value(&fabricated_cp5).unwrap();
    let err = mint_cosignature_checked(
        &wsigner,
        &fabricated_wire,
        "localhost",
        REGISTRY_DID,
        Some(WitnessConsistencyCheck {
            retained_root_hash: &retained_root,
            consistency_proof: &fabricated_consistency,
        }),
        chrono::Utc::now(),
        skew,
        &resolver,
    )
    .await
    .expect_err("wit-002: a checkpoint failing consistency MUST NOT be cosigned");
    assert!(
        matches!(err, AcdpError::InvalidLogProof(_)),
        "wit-002: consistency refusal is the RFC-ACDP-0012 §9.2 verdict, got {err:?}"
    );
    assert!(
        !err.is_transient(),
        "a rewritten history will not become consistent on retry"
    );

    // Premise sanity: the fabricated checkpoint's OWN signature is valid
    // (so §7 step 1 passed and step 2 — consistency — is what refused).
    let raw_hash = LogCheckpoint::preimage_hash_of_value(&fabricated_wire).unwrap();
    fabricated_cp5
        .verify_signature_against_hash(&raw_hash, Some(&registry_pub), None)
        .expect("wit-002 premise: the rewritten checkpoint's registry signature verifies");
    // And the genuine consistency proof does NOT verify against the
    // rewritten root — the exact refusal reason.
    let bad_proof = {
        let mut p = fabricated_consistency.clone();
        p["log_checkpoint"] = serde_json::to_value(&fabricated_cp5).unwrap();
        LogConsistencyProof::from_value(&p).unwrap()
    };
    assert!(matches!(
        bad_proof
            .verify_against_first_root(&retained_root)
            .unwrap_err(),
        AcdpError::InvalidLogProof(_)
    ));
}
