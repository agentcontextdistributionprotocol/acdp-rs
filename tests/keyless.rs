//! RFC-ACDP-0021 keyless signing (0.5.0, Draft): the `kl-001` known
//! answers and decision tables, the consumer-side fail-closed rules of
//! `kl-007`, and the fixture binding for the `kl-` family.
//!
//! The registry-side fixtures (`kl-002`, `kl-003`, `kl-004`, and the
//! registry halves of `kl-007`/`kl-009`) are a registry's to run; this
//! crate checks the request and body shapes they rest on. Consumer
//! verification over a live registry (`kl-005`, `kl-006`, `kl-009`) is in
//! `tests/keyless_verify.rs` and the chain stage (`kl-008`) in
//! `crates/acdp-chain/tests/keyless.rs`.

use std::path::PathBuf;

use acdp::crypto::{canonicalize, compute_content_hash, derive_lineage_id, SigningKey};
use acdp::did::DidDocument;
use acdp::types::keyless::{
    classify, is_keyless_key_id, may_supersede, pop_preimage, token_hash, IdentityNow, Jwk,
    KeyAttestation, KeylessFacts, KeylessReason, KeylessSigner, KeylessStatus, ReceiptFacts,
    WorkloadIdentity,
};
use acdp::types::{Body, CtxId};
use acdp::AcdpError;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

const REGISTRY_SEED: [u8; 32] = [0x11; 32];
const EPHEMERAL_SEED: [u8; 32] = [0x66; 32];
const REGISTRY_KEY_ID: &str = "did:web:registry.example.com#receipt-key-1";
const ATTESTATION_CTX: &str = "acdp://registry.example.com/7a1c0f3e-5b2d-4c8e-9f10-2b3c4d5e6f70";

fn spec_root() -> Option<PathBuf> {
    let require = std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok();
    let candidates = [
        std::env::var("ACDP_SPEC_DIR").ok().map(PathBuf::from),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join("agentcontextdistributionprotocol")),
    ];
    let found = candidates.into_iter().flatten().find(|p| p.exists());
    assert!(
        found.is_some() || !require,
        "ACDP_REQUIRE_CONFORMANCE is set but no ACDP spec checkout could be located"
    );
    found
}

fn read(rel: &str) -> Option<Value> {
    let root = spec_root()?;
    let path = root.join(rel);
    let require = std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok();
    match std::fs::read(&path) {
        Ok(bytes) => Some(serde_json::from_slice(&bytes).unwrap()),
        Err(_) if !require => None,
        Err(e) => panic!("{}: {e}", path.display()),
    }
}

fn kl_001() -> Option<Value> {
    read("schemas/conformance/kl-001-keyless-golden.json")
}

fn vector<'a>(fx: &'a Value, kind: &str) -> &'a Value {
    fx["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["kind"] == kind)
        .unwrap_or_else(|| panic!("kl-001 has no '{kind}' vector"))
}

/// The wire code of the variants keyless refusals use.
fn code(e: &AcdpError) -> &'static str {
    match e {
        AcdpError::KeyResolution(_) => "key_resolution_failed",
        AcdpError::KeyResolutionUnreachable(_) => "key_resolution_unreachable",
        AcdpError::KeyNotAuthorized(_) => "key_not_authorized",
        AcdpError::NotAuthorized(_) => "not_authorized",
        AcdpError::InvalidSignature(_) => "invalid_signature",
        AcdpError::SchemaViolation(_) => "schema_violation",
        other => panic!("unexpected variant {other:?}"),
    }
}

fn at(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

/// A stored body around `producer_content`, as a registry would serve it.
fn stored_body(ctx_id: &str, producer_content: &Value, key_id: &str, sig: &str) -> Body {
    let content_hash = compute_content_hash(producer_content).unwrap();
    let ctx = CtxId::parse(ctx_id).unwrap();
    let mut v = producer_content.clone();
    let m = v.as_object_mut().unwrap();
    m.insert("ctx_id".into(), json!(ctx_id));
    m.insert("lineage_id".into(), json!(derive_lineage_id(&ctx)));
    m.insert("origin_registry".into(), json!(ctx.authority()));
    m.insert("created_at".into(), json!("2026-10-26T09:00:00.000Z"));
    m.insert("content_hash".into(), json!(content_hash));
    m.insert(
        "signature".into(),
        json!({"algorithm": "ed25519", "key_id": key_id, "value": sig}),
    );
    serde_json::from_value(v).unwrap()
}

/// kl-001 vector 1: the attestation body's canonical form, content hash
/// and registry signature, and the §5.3 checks on it.
#[test]
fn kl_001_attestation_body() {
    let Some(fx) = kl_001() else { return };
    let v = vector(&fx, "attestation");
    let pc = &v["producer_content"];
    let exp = &v["expected"];

    let canon = String::from_utf8(canonicalize(pc).unwrap()).unwrap();
    assert_eq!(canon, exp["canonical_form"].as_str().unwrap());
    let hash = compute_content_hash(pc).unwrap();
    assert_eq!(hash.as_str(), exp["content_hash"]);
    let sig = SigningKey::from_bytes(&REGISTRY_SEED).sign_string(hash.as_str());
    assert_eq!(sig, exp["signature_value_base64"]);

    let att = KeyAttestation::from_metadata(&pc["metadata"]).unwrap();
    assert_eq!(
        att.public_key_jwk.thumbprint().unwrap(),
        exp["jwk_thumbprint"]
    );
    assert_eq!(
        att.public_key_jwk,
        serde_json::from_value::<Jwk>(fx["ephemeral_test_keypair"]["public_key_jwk"].clone())
            .unwrap()
    );
    assert_eq!(
        att.key_fingerprint,
        fx["ephemeral_test_keypair"]["key_fingerprint"]
    );
    assert!(is_keyless_key_id(&att.key_id));

    let body = stored_body(v["ctx_id"].as_str().unwrap(), pc, REGISTRY_KEY_ID, &sig);
    assert_eq!(KeyAttestation::from_body(&body).unwrap(), att);
    acdp::crypto::verify_content_hash(&serde_json::to_value(&body).unwrap(), &body.content_hash)
        .unwrap();

    // kl-006 E: an attestation whose agent_id is not did:web:<ctx_id
    // authority> is attestation_invalid.
    let foreign = stored_body(
        "acdp://other.example.com/7a1c0f3e-5b2d-4c8e-9f10-2b3c4d5e6f70",
        pc,
        REGISTRY_KEY_ID,
        &sig,
    );
    assert!(KeyAttestation::from_body(&foreign).is_err());

    // §5.3 metadata rules the schema cannot express.
    let mutate = |f: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut m = pc["metadata"].clone();
        f(m.as_object_mut().unwrap());
        KeyAttestation::from_metadata(&m)
    };
    assert!(mutate(&|m| {
        m.insert("algorithm".into(), json!("ecdsa-p256"));
    })
    .is_err());
    assert!(mutate(&|m| {
        m.insert(
            "key_fingerprint".into(),
            json!(format!("sha256:{}", "0".repeat(64))),
        );
    })
    .is_err());
    assert!(mutate(&|m| {
        m.insert("not_after".into(), json!("2026-10-26T10:00:00.001Z"));
    })
    .is_err());
    assert!(mutate(&|m| {
        m.insert("not_after".into(), json!("2026-10-26T09:00:00.000Z"));
    })
    .is_err());
    assert!(mutate(&|m| {
        m.insert("controller".into(), json!("did:key:z6Mk"));
    })
    .is_err());
    assert!(mutate(&|m| {
        m.insert("extra".into(), json!(1));
    })
    .is_err());
    // The full hour is allowed.
    assert!(mutate(&|m| {
        m.insert("not_after".into(), json!("2026-10-26T10:00:00.000Z"));
    })
    .is_ok());
}

/// kl-001 vector 2: the keyless-signed body.
#[test]
fn kl_001_keyless_body() {
    let Some(fx) = kl_001() else { return };
    let v = vector(&fx, "keyless_body");
    let pc = &v["producer_content"];
    let exp = &v["expected"];

    let canon = String::from_utf8(canonicalize(pc).unwrap()).unwrap();
    assert_eq!(canon, exp["canonical_form"].as_str().unwrap());
    let hash = compute_content_hash(pc).unwrap();
    assert_eq!(hash.as_str(), exp["content_hash"]);
    let sig = SigningKey::from_bytes(&EPHEMERAL_SEED).sign_string(hash.as_str());
    assert_eq!(sig, exp["signature"]["value"]);

    let key_id = exp["signature"]["key_id"].as_str().unwrap();
    let body = stored_body(
        "acdp://registry.example.com/0b9e8d7c-6a5f-4e3d-8c2b-1a0f9e8d7c6b",
        pc,
        key_id,
        &sig,
    );
    let r = body.key_attestation().unwrap().unwrap();
    assert_eq!(r.ctx_id.as_str(), ATTESTATION_CTX);
    acdp::validation::validate_body(&body).unwrap();

    // The attested key verifies the signature (§8.1 step 6).
    let att =
        KeyAttestation::from_metadata(&vector(&fx, "attestation")["producer_content"]["metadata"])
            .unwrap();
    assert!(att.binds(&body.agent_id, &body.signature));
    att.public_key_jwk
        .verify("ed25519", &sig, hash.as_str())
        .unwrap();
}

/// kl-001 vector 2, built by the producer API.
#[cfg(feature = "keyless")]
#[test]
fn kl_001_keyless_body_from_the_producer() {
    use acdp::producer::keyless::EphemeralKey;
    use acdp::types::ContextType;
    let Some(fx) = kl_001() else { return };
    let att_v = vector(&fx, "attestation");
    let v = vector(&fx, "keyless_body");
    let pc = &v["producer_content"];
    let exp = &v["expected"];

    let sig = SigningKey::from_bytes(&REGISTRY_SEED)
        .sign_string(att_v["expected"]["content_hash"].as_str().unwrap());
    let att_body = stored_body(
        ATTESTATION_CTX,
        &att_v["producer_content"],
        REGISTRY_KEY_ID,
        &sig,
    );
    let producer = EphemeralKey::from_key(SigningKey::from_bytes(&EPHEMERAL_SEED).into())
        .into_producer(&att_body)
        .unwrap();
    let req = producer
        .publish_request()
        .title(pc["title"].as_str().unwrap())
        .summary(pc["summary"].as_str().unwrap())
        .context_type(ContextType::Analysis)
        .acdp_version("0.5.0")
        .build()
        .unwrap();
    assert_eq!(req.content_hash.as_str(), exp["content_hash"]);
    assert_eq!(
        serde_json::to_value(&req.signature).unwrap(),
        exp["signature"]
    );
    assert_eq!(
        req.key_attestation,
        Some(
            serde_json::from_value::<acdp::types::keyless::KeyAttestationRef>(
                pc["key_attestation"].clone()
            )
            .unwrap()
        )
    );

    // The member survives materialization and reads back typed.
    let body = Body::from_publish_request(
        &req,
        CtxId::parse("acdp://registry.example.com/0b9e8d7c-6a5f-4e3d-8c2b-1a0f9e8d7c6b").unwrap(),
        derive_lineage_id(
            &CtxId::parse("acdp://registry.example.com/0b9e8d7c-6a5f-4e3d-8c2b-1a0f9e8d7c6b")
                .unwrap(),
        ),
        "registry.example.com",
        at("2026-10-26T09:05:00.000Z"),
    );
    assert_eq!(body.key_attestation().unwrap(), req.key_attestation);
    acdp::crypto::verify_content_hash(&serde_json::to_value(&body).unwrap(), &body.content_hash)
        .unwrap();

    // Another key is refused.
    assert!(EphemeralKey::generate().into_producer(&att_body).is_err());
}

/// kl-001 vector 3: token hash and proof of possession.
#[test]
fn kl_001_proof_of_possession() {
    let Some(fx) = kl_001() else { return };
    let v = vector(&fx, "pop");
    let exp = &v["expected"];
    let token = v["token"].as_str().unwrap();
    assert_eq!(token_hash(token), exp["token_hash"]);
    let p = &v["pop_preimage"];
    let pre = pop_preimage(
        p["controller"].as_str().unwrap(),
        p["registry_did"].as_str().unwrap(),
        p["token_hash"].as_str().unwrap(),
        p["key_fingerprint"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(pre, exp["pop_canonical_form"].as_str().unwrap());
    assert_eq!(
        SigningKey::from_bytes(&EPHEMERAL_SEED).sign_string(&pre),
        exp["pop_value_base64"]
    );
}

/// kl-001 vector 6 (0.5.0-draft.2): an ecdsa-p256 proof of possession is
/// the 64-byte `r||s` form; the same signature DER-encoded is rejected
/// (§5.1). Verify-only: ECDSA signatures are not deterministic.
#[test]
fn kl_001_proof_of_possession_p256() {
    let Some(fx) = kl_001() else { return };
    let v = vector(&fx, "pop_p256");
    let exp = &v["expected"];
    let kp = &fx["p256_test_keypair"];
    let jwk: Jwk = serde_json::from_value(kp["public_key_jwk"].clone()).unwrap();
    assert_eq!(jwk.algorithm().unwrap(), "ecdsa-p256");
    assert_eq!(jwk.thumbprint().unwrap(), kp["jwk_thumbprint"]);
    assert_eq!(jwk.fingerprint().unwrap(), kp["key_fingerprint"]);
    let token = v["token"].as_str().unwrap();
    let p = &v["pop_preimage"];
    assert_eq!(token_hash(token), p["token_hash"]);
    assert_eq!(p["key_fingerprint"], kp["key_fingerprint"]);
    let pre = pop_preimage(
        p["controller"].as_str().unwrap(),
        p["registry_did"].as_str().unwrap(),
        p["token_hash"].as_str().unwrap(),
        p["key_fingerprint"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(pre, exp["pop_canonical_form"].as_str().unwrap());
    let p1363 = v["pop_value_base64"].as_str().unwrap();
    let der = v["pop_value_der_base64"].as_str().unwrap();
    assert_eq!(exp["p1363_accepted"], true);
    assert_eq!(exp["der_rejected"], true);
    jwk.verify("ecdsa-p256", p1363, &pre)
        .expect("the r||s form verifies");
    assert!(
        jwk.verify("ecdsa-p256", der, &pre).is_err(),
        "the DER form is rejected"
    );
}

/// kl-001 vector 4: the §8.1/§8.2 key-status table, all 21 cases.
#[test]
fn kl_001_key_status_table() {
    let Some(fx) = kl_001() else { return };
    let v = vector(&fx, "classification");
    let nb = at(v["window"]["not_before"].as_str().unwrap());
    let na = at(v["window"]["not_after"].as_str().unwrap());
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 21);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let a = &c["attestation"];
        let facts = KeylessFacts {
            attestation_valid: a["valid"].as_bool().unwrap(),
            attester_accepted: a["registry_accepted"].as_bool().unwrap(),
            bindings_ok: a["bindings_ok"].as_bool().unwrap(),
            retracted: a["retracted"].as_bool().unwrap(),
            receipt: (!c["receipt"].is_null()).then(|| ReceiptFacts {
                verified: c["receipt"]["verified"].as_bool().unwrap(),
                registry_is_attester: c["receipt"]["registry_is_attester"].as_bool().unwrap(),
                fingerprint_matches: c["receipt"]["fingerprint_matches"].as_bool().unwrap(),
                created_at: at(c["receipt"]["created_at"].as_str().unwrap()),
            }),
            not_before: nb,
            not_after: na,
            signature_valid: c["signature_valid"].as_bool().unwrap(),
            compromised_since: c["revocations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| at(r["compromised_since"].as_str().unwrap()))
                .collect(),
        };
        let now = match &c["identity_listed_now"] {
            Value::Bool(true) => IdentityNow::Listed,
            Value::Bool(false) => IdentityNow::NotListed,
            Value::String(s) if s == "unreachable" => IdentityNow::Unreachable,
            other => panic!("{name}: identity_listed_now {other}"),
        };
        let got = match classify(&facts, now) {
            Ok(KeylessStatus::CurrentlyAuthorized) => json!({"status": "currently_authorized"}),
            Ok(KeylessStatus::HistoricallyAuthorized) => {
                json!({"status": "historically_authorized"})
            }
            Ok(KeylessStatus::HistoricallyAuthorizedPreCompromise) => {
                json!({"status": "historically_authorized_pre_compromise"})
            }
            Err(r) => json!({"status": "refused", "reason": r.as_str()}),
        };
        assert_eq!(got, c["expected"], "kl-001 vector 4 case {name}");
    }
}

fn signer(v: &Value) -> KeylessSigner {
    match v["kind"].as_str().unwrap() {
        "controller" => KeylessSigner::Controller,
        "keyless" => KeylessSigner::Keyless {
            identity: serde_json::from_value::<WorkloadIdentity>(v["identity"].clone()).unwrap(),
            org_wide: v["org_wide"].as_bool().unwrap(),
        },
        k => panic!("signer kind {k}"),
    }
}

/// kl-001 vector 5: the §7 supersession table, all 9 cases.
#[test]
fn kl_001_supersession_table() {
    let Some(fx) = kl_001() else { return };
    let cases = vector(&fx, "supersession")["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for c in cases {
        let got = match may_supersede(&signer(&c["predecessor"]), &signer(&c["successor"])) {
            Ok(()) => json!({"result": "allowed"}),
            Err(r) => json!({"result": "refused", "reason": r.as_str()}),
        };
        assert_eq!(got, c["expected"], "kl-001 vector 5 case {}", c["name"]);
    }
}

/// kl-001 vector 4, as errors: each refusal maps onto an existing
/// `AcdpError` variant and reads back its reason (§13.3).
#[test]
fn consumer_reasons_reuse_existing_codes() {
    for (reason, want) in [
        (KeylessReason::AttestationInvalid, "key_resolution_failed"),
        (KeylessReason::UntrustedAttester, "key_not_authorized"),
        (KeylessReason::AttestationMismatch, "key_not_authorized"),
        (KeylessReason::Unplaceable, "key_not_authorized"),
        (
            KeylessReason::OutsideAttestationWindow,
            "key_not_authorized",
        ),
        (KeylessReason::InvalidSignature, "invalid_signature"),
        (KeylessReason::AttestationWithdrawn, "key_not_authorized"),
        (KeylessReason::Revoked, "key_not_authorized"),
        (
            KeylessReason::ControllerUnreachable,
            "key_resolution_unreachable",
        ),
    ] {
        let e = reason.error("x");
        assert_eq!(code(&e), want, "{reason}");
        assert_eq!(KeylessReason::of(&e), Some(reason));
    }
    // Only the controller fetch is transient.
    assert!(KeylessReason::ControllerUnreachable
        .error("x")
        .is_transient());
    assert!(!KeylessReason::Revoked.error("x").is_transient());
}

/// kl-003 C–G, from the client side: a registry's `details.reason`
/// survives `from_wire_error` on the existing variant.
#[test]
fn kl_003_registry_reasons_survive_the_wire() {
    for (want, reason) in [
        ("key_not_authorized", "outside_attestation_window"),
        ("key_resolution_failed", "attestation_missing"),
        ("key_resolution_failed", "attestation_foreign"),
        ("key_resolution_failed", "attestation_mismatch"),
        ("key_not_authorized", "attestation_mismatch"),
        ("key_not_authorized", "attestation_withdrawn"),
        ("not_authorized", "keyless_identity_mismatch"),
        ("key_not_authorized", "identity_not_authorized"),
    ] {
        let wire: acdp::types::WireError = serde_json::from_value(json!({
            "error": {"code": want, "message": "refused", "details": {"reason": reason}}
        }))
        .unwrap();
        let e = AcdpError::from_wire_error(wire);
        assert_eq!(code(&e), want);
        assert_eq!(KeylessReason::of(&e).map(|r| r.as_str()), Some(reason));
    }
}

/// kl-003 I: `key_attestation` with a non-keyless key id is a
/// `schema_violation` before anything is sent.
#[test]
fn kl_003_i_key_attestation_needs_a_keyless_key_id() {
    let Some(fx) = kl_001() else { return };
    let mut pc = vector(&fx, "keyless_body")["producer_content"].clone();
    pc["agent_id"] = json!("did:web:agents.example.com:ci");
    let body = stored_body(
        "acdp://registry.example.com/0b9e8d7c-6a5f-4e3d-8c2b-1a0f9e8d7c6b",
        &pc,
        "did:web:agents.example.com:ci#key-1",
        &SigningKey::from_bytes(&EPHEMERAL_SEED).sign_string("x"),
    );
    let err = acdp::validation::validate_body(&body).unwrap_err();
    assert_eq!(code(&err), "schema_violation", "{err}");
}

/// kl-007 B: a DID document listing an `acdp-kl-` method never yields it.
#[test]
fn kl_007_b_reserved_fragment_is_refused() {
    let Some(fx) = kl_001() else { return };
    let key_id = vector(&fx, "keyless_body")["expected"]["signature"]["key_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let doc: DidDocument = serde_json::from_value(json!({
        "id": "did:web:agents.example.com:ci",
        "verificationMethod": [{
            "id": key_id,
            "type": "Ed25519VerificationKey2020",
            "controller": "did:web:agents.example.com:ci",
            "publicKeyJwk": fx["ephemeral_test_keypair"]["public_key_jwk"]
        }],
        "assertionMethod": [key_id]
    }))
    .unwrap();
    let fragment = key_id.split_once('#').unwrap().1;
    assert!(doc.find_by_fragment(fragment).is_none());
}

/// Every `kl-` fixture is bound to a test.
#[test]
fn kl_fixtures_each_have_tests() {
    const BOUND: &[(&str, &str)] = &[
        (
            "kl-001",
            "keyless::kl_001_{attestation_body,keyless_body,proof_of_possession,proof_of_possession_p256,key_status_table,supersession_table}",
        ),
        (
            "kl-002",
            "registry-side; request shape: acdp-types keyless tests, acdp-producer keyless::tests",
        ),
        (
            "kl-003",
            "registry-side; keyless::kl_003_registry_reasons_survive_the_wire, kl_003_i_key_attestation_needs_a_keyless_key_id",
        ),
        ("kl-004", "registry-side; table: keyless::kl_001_supersession_table"),
        ("kl-005", "keyless_verify::kl_005_*"),
        ("kl-006", "keyless_verify::kl_006_*"),
        (
            "kl-007",
            "keyless::kl_007_b_reserved_fragment_is_refused, keyless_verify::kl_007_*",
        ),
        ("kl-008", "acdp-chain keyless::kl_008_*"),
        (
            "kl-009",
            "keyless_verify::*kl_009_*, acdp-chain keyless::kl_009_f_non_org_wide_keyless_revocation_not_applied",
        ),
    ];
    let Some(root) = spec_root() else {
        return;
    };
    let mut ids: Vec<String> = std::fs::read_dir(root.join("schemas/conformance"))
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().into_string().unwrap();
            name.starts_with("kl-").then(|| name[..6].to_owned())
        })
        .collect();
    ids.sort();
    let bound: Vec<&str> = BOUND.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, bound, "unbound kl fixtures");
}

/// Every registry `details.reason` token in the spec's
/// `registries/error-codes.md` keyless table has a `KeylessReason`, which
/// `from_wire_error` keeps on the error (RFC-ACDP-0021 §13.3).
#[test]
fn registry_reason_tokens_match_the_spec() {
    let Some(root) = spec_root() else { return };
    let text = std::fs::read_to_string(root.join("registries/error-codes.md")).unwrap();
    let table = text
        .split("## Keyless-signing reason tokens")
        .nth(1)
        .expect("error-codes.md has the keyless reason table")
        .split("\n## ")
        .next()
        .unwrap();
    // | `token` | Status | `code` [/ `code`] | Meaning | Reference |
    let rows: Vec<(&str, &str)> = table
        .lines()
        .filter(|l| l.starts_with("| `"))
        .map(|l| {
            let cells: Vec<&str> = l.split('|').map(str::trim).collect();
            (cells[1].trim_matches('`'), cells[3])
        })
        .collect();
    assert!(rows.iter().any(|(t, _)| *t == "issuer_unreachable"));
    for (token, codes) in rows {
        let r = KeylessReason::parse(token)
            .unwrap_or_else(|| panic!("no KeylessReason for spec token '{token}'"));
        assert!(r.is_registry_token(), "{token} is a registry token");
        // A token on one code: our error for it carries that code.
        if !codes.contains('/') {
            assert_eq!(code(&r.error("x")), codes.trim_matches('`'), "{token}");
        }
    }
    // The one transient registry refusal.
    assert!(KeylessReason::IssuerUnreachable.error("x").is_transient());
}
