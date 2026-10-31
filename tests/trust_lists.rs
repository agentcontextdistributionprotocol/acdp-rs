//! Registry trust lists (RFC-ACDP-0020, Final at 0.5.0) — trust-001..006.
//!
//! - trust-001 is executed: the golden list's canonical form,
//!   `content_hash` and Ed25519 signature, every row of the evaluation
//!   table, and `examples/trust-report/golden-trust-report.json` byte
//!   for byte (JCS).
//! - trust-002..006 are behavioral and run against real signed lists
//!   (the sig-003 `0x42` did:key issuer), with or without the spec.
//!
//! trust-007 (carriage in an RFC-ACDP-0017 bundle and the report bound
//! to a verdict) is in `crates/acdp-chain/tests/trust.rs`.

use std::path::PathBuf;

use acdp::crypto::SigningKey;
use acdp::producer::Producer;
use acdp::types::body::Body;
use acdp::types::lifecycle::{LifecycleEvent, LifecycleEventType};
use acdp::types::primitives::{AgentDid, ContextType, CtxId, Visibility};
use acdp::types::trust_list::{
    advance_floor, evaluate, select_version, validate_list_version, IssuerPin, ListStatus,
    ListVersion, NodeTrust, PinState, ReceiptInput, TrustList, TrustOutcome, TrustPass,
    TrustReason, TrustReport, TrustSubject, VerifiedListBody, TRUST_LIST_SCHEMA_URI,
    TRUST_LIST_TYPE,
};
use acdp::verify::trust::verify_list_offline;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

const ISSUER_SEED: [u8; 32] = [0x42; 32];
const OTHER_SEED: [u8; 32] = [0x43; 32];
const ISSUER: &str = "did:key:z6MkghLt1e8m1fmANsdJJco3aCLV8Xnigr5UWwC3u5iZFPd3";
const LIST_ID: &str = "tenant-acme.production";
const PINNED_RECEIPT_KEY: &str =
    "sha256:10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d";
const REGISTRY: &str = "registry.example.com";
const T: &str = "2026-10-27T00:00:00.000Z";

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

fn at(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

fn pin() -> IssuerPin {
    IssuerPin::new(ISSUER, LIST_ID)
}

/// `examples/trust-list/golden-trust-list.json`.
fn golden_metadata() -> Value {
    json!({
        "trust_list_version": "acdp-trust-list/1",
        "list_id": LIST_ID,
        "serial": 7,
        "issued_at": "2026-10-26T00:00:00.000Z",
        "valid_from": "2026-10-01T00:00:00.000Z",
        "valid_until": "2027-04-01T00:00:00.000Z",
        "entries": [
            {
                "registry_did": "did:web:registry.example.com",
                "origin": "registry.example.com",
                "receipt_key_fingerprints": [PINNED_RECEIPT_KEY],
                "required_profiles": ["acdp-registry-receipts", "acdp-registry-lifecycle"]
            },
            {
                "registry_did": "did:web:partner.example.org",
                "origin": "partner.example.org",
                "scope": {
                    "agent_id_prefixes": ["did:web:agents.partner.example.org:"],
                    "types": ["analysis", "data_snapshot"]
                },
                "valid_until": "2026-12-01T00:00:00.000Z"
            },
            {
                "registry_did": "did:web:sandbox.example.net",
                "origin": "sandbox.example.net",
                "scope": { "did_methods": ["did:key"] },
                "valid_from": "2026-11-01T00:00:00.000Z"
            },
            {
                "registry_did": "did:web:partner.example.org",
                "origin": "partner.example.org",
                "scope": { "agent_ids": ["did:web:auditor.example.com"] }
            }
        ]
    })
}

/// A list signed by `seed` as a publish-request body (the out-of-band
/// form, §7).
fn signed(seed: &[u8; 32], metadata: Value) -> Value {
    let serial = metadata["serial"].clone();
    let producer = Producer::new_did_key(SigningKey::from_bytes(seed));
    let req = producer
        .publish_request()
        .title("Trust list — tenant acme, production")
        .summary(format!(
            "Registries tenant acme relies on in production (RFC-ACDP-0020), serial {serial}."
        ))
        .context_type(ContextType::Custom(TRUST_LIST_TYPE.into()))
        .visibility(Visibility::Public)
        .schema_uri(TRUST_LIST_SCHEMA_URI)
        .metadata(metadata)
        .acdp_version("0.5.0")
        .build()
        .unwrap();
    serde_json::to_value(req).unwrap()
}

/// A golden-shaped list with `serial`, issued at `issued_at`.
fn list(serial: u64, issued_at: &str) -> Value {
    let mut m = golden_metadata();
    m["serial"] = json!(serial);
    m["issued_at"] = json!(issued_at);
    m
}

/// `acdp://registry.example.com/<l…>`.
fn ctx(l: char) -> String {
    let r = |n: usize| l.to_string().repeat(n);
    format!(
        "acdp://{REGISTRY}/{}-{}-4{}-8{}-{}",
        r(8),
        r(4),
        r(3),
        r(3),
        r(12)
    )
}

/// The publish request as the registry stores it under `ctx(id)`.
fn stored(req: &Value, id: char) -> Value {
    let req: acdp::types::PublishRequest = serde_json::from_value(req.clone()).unwrap();
    let ctx_id = CtxId::parse(ctx(id)).unwrap();
    let lineage = acdp::crypto::hash::derive_lineage_id(&ctx_id);
    let body = Body::from_publish_request(
        &req,
        ctx_id,
        lineage,
        REGISTRY,
        at("2026-10-26T00:00:01.000Z"),
    );
    serde_json::to_value(body).unwrap()
}

fn lifecycle(
    seed: &[u8; 32],
    actor: &str,
    key_id: &str,
    id: char,
    kind: LifecycleEventType,
) -> Value {
    let e = LifecycleEvent::new(
        format!("00000001-0000-4000-8000-{:012}", id as u32),
        CtxId::parse(ctx(id)).unwrap(),
        kind,
        at("2026-10-26T12:00:00.000Z"),
        AgentDid::new(actor),
        None,
    )
    .unwrap()
    .sign_with(SigningKey::from_bytes(seed), key_id)
    .unwrap();
    serde_json::to_value(e).unwrap()
}

fn issuer_key_id(req: &Value) -> String {
    req["signature"]["key_id"].as_str().unwrap().to_string()
}

fn version(req: &Value) -> ListVersion {
    verify_list_offline(req, &pin(), &[], false).unwrap()
}

fn latest(versions: &[ListVersion], floor: Option<u64>) -> PinState {
    select_version(&pin(), versions, at(T), TrustPass::Latest, floor)
}

fn subject<'a>(ctx_id: &'a str, origin: &'a str, agent: &'a str, ty: &'a str) -> TrustSubject<'a> {
    TrustSubject {
        ctx_id,
        origin_registry: origin,
        agent_id: agent,
        context_type: ty,
    }
}

const A_BODY: &str = "acdp://registry.example.com/3c9d7a1e-5b2f-4c8d-9e0a-1f2b3c4d5e6f";
const PRODUCER: &str = "did:web:agents.example.com:test-producer";

fn pinned_receipt() -> ReceiptInput {
    ReceiptInput {
        registry_did: "did:web:registry.example.com".into(),
        registry_key_fingerprint: PINNED_RECEIPT_KEY.into(),
    }
}

/// The A1 body (registry.example.com, pinned receipt) against `states`.
fn a1(states: &[PinState]) -> NodeTrust {
    evaluate(
        &subject(A_BODY, REGISTRY, PRODUCER, "analysis"),
        states,
        at(T),
        Some(&pinned_receipt()),
        None,
    )
}

// ── trust-001 ──────────────────────────────────────────────────────────────

#[test]
fn trust_001_golden_list() {
    let req = signed(&ISSUER_SEED, golden_metadata());
    assert_eq!(req["agent_id"], ISSUER);
    let hash = "sha256:206fe1d0f0c3610e9a7d55638b7baa1883b625c71373b92747f25e07f3678bf3";
    assert_eq!(req["content_hash"], hash);
    assert_eq!(
        req["signature"]["value"],
        "F4i+OHnLx0lExnr4iL3cjiIh+p8GRjjDbVenIh5TCWG3EB/iPTW5jJf6e/d37vml/TeSffkbhYyXUIMiDp+3DQ=="
    );
    let v = version(&req);
    assert_eq!(
        (v.list.serial, v.content_hash.as_str(), v.ctx_id.as_deref()),
        (7, hash, None)
    );

    let Some(fixture) = read("schemas/conformance/trust-001-trust-list-golden.json") else {
        return;
    };
    let vector = &fixture["vectors"][0];
    let expected = &vector["expected"];
    let content: Value = vector["producer_content"].clone();
    let mut content_of_ours = req.clone();
    let obj = content_of_ours.as_object_mut().unwrap();
    obj.remove("content_hash");
    obj.remove("signature");
    assert_eq!(content_of_ours, content, "producer_content");
    let (preimage, _) = acdp::crypto::hash::canonical_preimage(&content).unwrap();
    assert_eq!(
        String::from_utf8(preimage).unwrap(),
        expected["canonical_form"].as_str().unwrap()
    );
    assert_eq!(req["content_hash"], expected["content_hash"]);
    assert_eq!(expected["signature_input"], expected["content_hash"]);
    assert_eq!(
        req["signature"]["value"],
        expected["signature_value_base64"]
    );
    let sig = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        req["signature"]["value"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        hex::encode(sig),
        expected["signature_value_hex"].as_str().unwrap()
    );
    assert_eq!(req, expected["publish_request_body"]);
    assert_eq!(fixture["test_keypair"]["did_key"], ISSUER);
    let golden = read("examples/trust-list/golden-trust-list.json").unwrap();
    assert_eq!(golden, golden_metadata());
    TrustList::from_metadata(&golden).unwrap();
}

#[test]
fn trust_001_evaluation_table() {
    let Some(fixture) = read("schemas/conformance/trust-001-trust-list-golden.json") else {
        return;
    };
    let v = version(&signed(&ISSUER_SEED, golden_metadata()));
    let rows = fixture["vectors"][1]["evaluations"].as_array().unwrap();
    assert_eq!(rows.len(), 20);
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let t = at(row["T"].as_str().unwrap());
        let states = vec![select_version(
            &pin(),
            std::slice::from_ref(&v),
            t,
            TrustPass::Latest,
            Some(7),
        )];
        let b = &row["body"];
        let s = |k: &str| b[k].as_str().unwrap();
        let receipt = row.get("receipt").map(|r| ReceiptInput {
            registry_did: r["registry_did"].as_str().unwrap().into(),
            registry_key_fingerprint: r["registry_key_fingerprint"].as_str().unwrap().into(),
        });
        let caps: Option<Vec<String>> = row
            .get("capabilities_profiles")
            .map(|c| serde_json::from_value(c.clone()).unwrap());
        let got = evaluate(
            &subject(s("ctx_id"), s("origin_registry"), s("agent_id"), s("type")),
            &states,
            t,
            receipt.as_ref(),
            caps.as_deref(),
        );
        let e = &row["expected"];
        assert_eq!(
            serde_json::to_value(got.outcome).unwrap(),
            e["outcome"],
            "{name}"
        );
        assert_eq!(
            got.reason.map(|r| serde_json::to_value(r).unwrap()),
            e.get("reason").cloned(),
            "{name}"
        );
        assert_eq!(
            got.entry_index,
            e.get("entry_index").and_then(Value::as_u64),
            "{name}"
        );
        assert_eq!(
            got.profiles_checked,
            e["profiles_checked"].as_bool().unwrap(),
            "{name}"
        );
        // §8: issuer and list_id exactly when an entry decided.
        let decided = got.entry_index.is_some();
        assert_eq!(got.issuer.is_some(), decided, "{name}");
        assert_eq!(got.list_id.is_some(), decided, "{name}");
        if decided {
            assert_eq!(
                (got.issuer.as_deref(), got.list_id.as_deref()),
                (Some(ISSUER), Some(LIST_ID))
            );
        }
    }
}

#[test]
fn trust_001_golden_report() {
    let Some(golden) = read("examples/trust-report/golden-trust-report.json") else {
        return;
    };
    let v = version(&signed(&ISSUER_SEED, golden_metadata()));
    let t = at(T);
    let states = vec![latest(&[v], None)];
    let partner = "acdp://partner.example.org/3c9d7a1e-5b2f-4c8d-9e0a-1f2b3c4d5e6f";
    let unknown = "acdp://unknown.example.com/3c9d7a1e-5b2f-4c8d-9e0a-1f2b3c4d5e6f";
    let nodes = vec![
        evaluate(
            &subject(unknown, "unknown.example.com", PRODUCER, "analysis"),
            &states,
            t,
            None,
            None,
        ),
        a1(&states),
        evaluate(
            &subject(
                partner,
                "partner.example.org",
                "did:web:agents.partner.example.org:analyst",
                "analysis",
            ),
            &states,
            t,
            None,
            None,
        ),
    ];
    let report = TrustReport::new(TrustPass::Latest, t, &states, nodes, None, None);
    assert_eq!(
        report.report_digest,
        golden["report_digest"].as_str().unwrap()
    );
    assert_eq!(report.to_jcs(), acdp_jcs::canonicalize_value(&golden));
    assert_eq!(report.compute_digest(), report.report_digest);
    let parsed: TrustReport = serde_json::from_value(golden).unwrap();
    assert_eq!(parsed, report);
}

// ── trust-002 ──────────────────────────────────────────────────────────────

#[test]
fn trust_002_list_validation() {
    let good = signed(&ISSUER_SEED, golden_metadata());
    let step = |req: &Value, p: &IssuerPin, revoked: bool| {
        let err = verify_list_offline(req, p, &[], revoked).unwrap_err();
        // The version is ignored; with nothing else held the pin is
        // list_invalid (no_valid_version) and nothing is trusted.
        let state = select_version(p, &[], at(T), TrustPass::Latest, None);
        assert_eq!(a1(&[state]).outcome, TrustOutcome::ListInvalid);
        err.step
    };
    let p = pin();

    // A — one byte of the signature flipped.
    let mut a = good.clone();
    let sig = a["signature"]["value"].as_str().unwrap().to_string();
    let flipped = if sig.starts_with('F') {
        sig.replacen('F', "G", 1)
    } else {
        sig.replacen(&sig[..1], "F", 1)
    };
    a["signature"]["value"] = json!(flipped);
    assert_eq!(step(&a, &p, false), 1);
    // B — an entry changed after signing.
    let mut b = good.clone();
    b["metadata"]["entries"][0]["origin"] = json!("evil.example.com");
    assert_eq!(step(&b, &p, false), 1);
    // C — re-signed by another did:key.
    assert_eq!(step(&signed(&OTHER_SEED, golden_metadata()), &p, false), 2);
    // D — another list_id under the same issuer.
    let mut m = golden_metadata();
    m["list_id"] = json!("tenant-acme.staging");
    assert_eq!(step(&signed(&ISSUER_SEED, m), &p, false), 2);
    // E — the pin names a different issuer key.
    let other_fp = acdp::crypto::fingerprint::fingerprint_ed25519(
        &SigningKey::from_bytes(&OTHER_SEED).verifying_key_bytes(),
    );
    let pinned = pin().with_issuer_key_fingerprints([other_fp]);
    assert_eq!(step(&good, &pinned, false), 3);
    let own_fp = acdp::crypto::fingerprint::fingerprint_ed25519(
        &SigningKey::from_bytes(&ISSUER_SEED).verifying_key_bytes(),
    );
    verify_list_offline(
        &good,
        &pin().with_issuer_key_fingerprints([own_fp]),
        &[],
        false,
    )
    .unwrap();
    // F — schema failures: an unknown entry member, a port.
    for f in [
        |m: &mut Value| m["entries"][1]["note"] = json!("x"),
        |m: &mut Value| m["entries"][1]["origin"] = json!("partner.example.org:8443"),
    ] {
        let mut m = golden_metadata();
        f(&mut m);
        assert_eq!(step(&signed(&ISSUER_SEED, m), &p, false), 4);
    }
    // G — registry_did and origin disagree: the whole version is invalid.
    let mut m = golden_metadata();
    m["entries"][0]["registry_did"] = json!("did:web:evil.example.com");
    assert_eq!(step(&signed(&ISSUER_SEED, m), &p, false), 4);
    // H — inverted window.
    let mut m = golden_metadata();
    m["valid_from"] = json!("2027-05-01T00:00:00.000Z");
    assert_eq!(step(&signed(&ISSUER_SEED, m), &p, false), 4);
    // I — a revoked issuer key.
    assert_eq!(step(&good, &p, true), 5);
    // J — a list has no member that names a pin, and evaluation only
    // ever reads the pins it is given.
    let mut m = golden_metadata();
    m["trusted_issuers"] = json!([{"issuer": "did:web:evil.example.com", "list_id": "x"}]);
    assert!(TrustList::from_metadata(&m).is_err());
    let foreign = VerifiedListBody {
        agent_id: "did:web:evil.example.com",
        context_type: TRUST_LIST_TYPE,
        metadata: Some(&golden_metadata()),
        content_hash: "sha256:00",
        ctx_id: None,
        issuer_key_fingerprint: None,
        issuer_key_revoked: false,
        retracted: false,
    };
    assert_eq!(validate_list_version(&p, &foreign).unwrap_err().step, 2);
}

// ── trust-003 ──────────────────────────────────────────────────────────────

#[test]
fn trust_003_series_state() {
    let v = |serial| {
        version(&signed(
            &ISSUER_SEED,
            list(serial, "2026-10-26T00:00:00.000Z"),
        ))
    };
    // A — accepting serial 7 persists floor 7.
    let v7 = v(7);
    let floor = advance_floor(None, [&v7]);
    assert_eq!(floor, Some(7));
    assert_eq!(
        latest(std::slice::from_ref(&v7), floor).status,
        ListStatus::Used
    );
    // B — only serial 5 later: rollback, even though it is valid.
    let mut m5 = list(5, "2026-10-20T00:00:00.000Z");
    m5["entries"].as_array_mut().unwrap().push(json!({
        "registry_did": "did:web:dropped.example.com", "origin": "dropped.example.com"
    }));
    let v5 = version(&signed(&ISSUER_SEED, m5));
    let s = latest(&[v5], floor);
    assert_eq!(
        (s.status, s.reason),
        (ListStatus::Invalid, Some(TrustReason::Rollback))
    );
    let dropped = evaluate(
        &subject(
            "acdp://dropped.example.com/3c9d7a1e-5b2f-4c8d-9e0a-1f2b3c4d5e6f",
            "dropped.example.com",
            PRODUCER,
            "analysis",
        ),
        &[s],
        at(T),
        None,
        None,
    );
    assert_eq!(
        (dropped.outcome, dropped.reason),
        (TrustOutcome::ListInvalid, Some(TrustReason::Rollback))
    );
    // C — serial 8 arrives: selected, floor 8.
    let v8 = v(8);
    let held = vec![v7.clone(), v8.clone()];
    let floor = advance_floor(floor, &held);
    assert_eq!(floor, Some(8));
    let s = latest(&held, floor);
    assert_eq!(
        (s.status, s.version.unwrap().list.serial),
        (ListStatus::Used, 8)
    );
    // D — two valid serial-8 versions with different hashes.
    let mut m = list(8, "2026-10-26T00:00:00.000Z");
    m["entries"].as_array_mut().unwrap().pop();
    let v8b = version(&signed(&ISSUER_SEED, m));
    assert_ne!(v8.content_hash, v8b.content_hash);
    let held = vec![v7.clone(), v8.clone(), v8b.clone()];
    let s = latest(&held, floor);
    assert_eq!(
        (s.status, s.reason),
        (ListStatus::Invalid, Some(TrustReason::Equivocation))
    );
    // E — serial 9 recovers.
    let mut held = held;
    held.push(v(9));
    let s = latest(&held, advance_floor(floor, &held));
    assert_eq!(
        (s.status, s.version.unwrap().list.serial),
        (ListStatus::Used, 9)
    );
    // F — the same serial-8 bytes from two registries are one version.
    let req8 = signed(&ISSUER_SEED, list(8, "2026-10-26T00:00:00.000Z"));
    let here = verify_list_offline(&stored(&req8, 'a'), &pin(), &[], false).unwrap();
    let mut other_registry = stored(&req8, 'b');
    other_registry["ctx_id"] = json!(ctx('b').replace(REGISTRY, "mirror.example.net"));
    other_registry["origin_registry"] = json!("mirror.example.net");
    other_registry["lineage_id"] = json!(acdp::crypto::hash::derive_lineage_id(
        &CtxId::parse(other_registry["ctx_id"].as_str().unwrap()).unwrap()
    ));
    let there = verify_list_offline(&other_registry, &pin(), &[], false).unwrap();
    assert_ne!(here.ctx_id, there.ctx_id);
    assert_eq!(here.content_hash, there.content_hash);
    let s = latest(&[here, there], Some(8));
    assert_eq!(s.status, ListStatus::Used);
}

// ── trust-004 ──────────────────────────────────────────────────────────────

#[test]
fn trust_004_retraction() {
    let req6 = signed(&ISSUER_SEED, list(6, "2026-10-20T00:00:00.000Z"));
    let req7 = signed(&ISSUER_SEED, list(7, "2026-10-26T00:00:00.000Z"));
    let key_id = issuer_key_id(&req7);
    let v6 = verify_list_offline(&stored(&req6, '6'), &pin(), &[], false).unwrap();
    let retract7 = lifecycle(
        &ISSUER_SEED,
        ISSUER,
        &key_id,
        '7',
        LifecycleEventType::Retracted,
    );

    // A — the issuer retracts serial 7: neither 7 nor 6 is used.
    let v7r = verify_list_offline(
        &stored(&req7, '7'),
        &pin(),
        std::slice::from_ref(&retract7),
        false,
    )
    .unwrap();
    assert!(v7r.retracted);
    let held = vec![v6.clone(), v7r.clone()];
    let floor = advance_floor(None, &held);
    assert_eq!(floor, Some(7));
    let s = latest(&held, floor);
    assert_eq!(
        (s.status, s.reason),
        (ListStatus::Invalid, Some(TrustReason::Retracted))
    );
    // A republish by the issuer reverses it.
    let republish = lifecycle(
        &ISSUER_SEED,
        ISSUER,
        &key_id,
        '7',
        LifecycleEventType::Republished,
    );
    let mut back = republish.clone();
    back["event_id"] = json!("00000002-0000-4000-8000-000000000055");
    let back = LifecycleEvent::from_value(&back).unwrap();
    let back = serde_json::to_value(
        LifecycleEvent::new(
            back.event_id,
            back.ctx_id,
            back.event_type,
            back.occurred_at,
            back.actor,
            None,
        )
        .unwrap()
        .sign_with(SigningKey::from_bytes(&ISSUER_SEED), &key_id)
        .unwrap(),
    )
    .unwrap();
    assert!(
        !verify_list_offline(&stored(&req7, '7'), &pin(), &[retract7, back], false)
            .unwrap()
            .retracted
    );
    // B — the issuer reissues as serial 8.
    let v8 = version(&signed(&ISSUER_SEED, list(8, "2026-10-26T06:00:00.000Z")));
    let held = vec![v6.clone(), v7r, v8];
    let s = latest(&held, advance_floor(floor, &held));
    assert_eq!(
        (s.status, s.version.unwrap().list.serial),
        (ListStatus::Used, 8)
    );
    // C — a registry-actor retraction does not withdraw the list.
    let registry_did = "did:web:registry.example.com";
    let by_registry = lifecycle(
        &[0x11; 32],
        registry_did,
        &format!("{registry_did}#receipt-key-1"),
        '7',
        LifecycleEventType::Retracted,
    );
    let v7 = verify_list_offline(&stored(&req7, '7'), &pin(), &[by_registry], false).unwrap();
    assert!(!v7.retracted);
    assert_eq!(
        latest(&[v6.clone(), v7.clone()], Some(7)).status,
        ListStatus::Used
    );
    // D — retracting serial 6 while 7 is current changes nothing.
    let retract6 = lifecycle(
        &ISSUER_SEED,
        ISSUER,
        &key_id,
        '6',
        LifecycleEventType::Retracted,
    );
    let v6r = verify_list_offline(&stored(&req6, '6'), &pin(), &[retract6], false).unwrap();
    assert!(v6r.retracted);
    let s = latest(&[v6r, v7], Some(7));
    assert_eq!(
        (s.status, s.version.unwrap().list.serial),
        (ListStatus::Used, 7)
    );
}

// ── trust-005 ──────────────────────────────────────────────────────────────

#[test]
fn trust_005_as_of_selection() {
    let mut m6 = list(6, "2026-09-01T00:00:00.000Z");
    m6["valid_from"] = json!("2026-09-01T00:00:00.000Z");
    let v6 = version(&signed(&ISSUER_SEED, m6.clone()));
    let v7 = version(&signed(&ISSUER_SEED, list(7, "2026-10-26T00:00:00.000Z")));
    let held = vec![v6.clone(), v7.clone()];
    let as_of =
        |vs: &[ListVersion], t: &str| select_version(&pin(), vs, at(t), TrustPass::AsOf, Some(7));
    // A — T before serial 7 was issued: serial 6, despite the present floor 7.
    let s = as_of(&held, "2026-10-10T00:00:00.000Z");
    assert_eq!(
        (s.status, s.version.unwrap().list.serial),
        (ListStatus::Used, 6)
    );
    // B — later T: serial 7.
    assert_eq!(
        as_of(&held, "2026-11-01T00:00:00.000Z")
            .version
            .unwrap()
            .list
            .serial,
        7
    );
    // C — before any version.
    let s = as_of(&held, "2026-08-01T00:00:00.000Z");
    assert_eq!(
        (s.status, s.reason),
        (ListStatus::Invalid, Some(TrustReason::NoValidVersion))
    );
    // D — a retraction admitted after T is not counted (the caller marks
    // only the retractions its pass admits).
    assert_eq!(
        as_of(&held, "2026-10-10T00:00:00.000Z").status,
        ListStatus::Used
    );
    // E — admitted before T: retracted, and serial 5 is not used.
    let v5 = version(&signed(&ISSUER_SEED, list(5, "2026-08-15T00:00:00.000Z")));
    let v6r = ListVersion {
        retracted: true,
        ..v6.clone()
    };
    let s = as_of(&[v5.clone(), v6r, v7.clone()], "2026-10-10T00:00:00.000Z");
    assert_eq!(
        (s.status, s.reason),
        (ListStatus::Invalid, Some(TrustReason::Retracted))
    );
    // F — serial 6 expired at T, serial 7 not yet issued: no fallback.
    let mut m6short = m6;
    m6short["valid_until"] = json!("2026-10-05T00:00:00.000Z");
    let v6short = version(&signed(&ISSUER_SEED, m6short));
    let mut m5wide = list(5, "2026-08-15T00:00:00.000Z");
    m5wide["valid_from"] = json!("2026-08-15T00:00:00.000Z");
    let v5wide = version(&signed(&ISSUER_SEED, m5wide));
    let s = as_of(&[v5wide, v6short, v7], "2026-10-10T00:00:00.000Z");
    assert_eq!(
        (s.status, s.reason),
        (ListStatus::Expired, Some(TrustReason::ListWindow))
    );
    assert_eq!(s.version.unwrap().list.serial, 6);
    // G — a did:web issuer's DID document as of T: crates/acdp-chain/tests/trust.rs.
}

// ── trust-006 ──────────────────────────────────────────────────────────────

const CONSORTIUM: &str = "consortium.registries";

fn consortium(entries: Value) -> (IssuerPin, Value) {
    let issuer = Producer::new_did_key(SigningKey::from_bytes(&OTHER_SEED));
    let req = signed(
        &OTHER_SEED,
        json!({
            "trust_list_version": "acdp-trust-list/1",
            "list_id": CONSORTIUM,
            "serial": 1,
            "issued_at": "2026-10-01T00:00:00.000Z",
            "valid_from": "2026-10-01T00:00:00.000Z",
            "valid_until": "2027-01-01T00:00:00.000Z",
            "entries": entries
        }),
    );
    drop(issuer);
    let pin = IssuerPin::new(req["agent_id"].as_str().unwrap(), CONSORTIUM);
    (pin, req)
}

#[test]
fn trust_006_multiple_lists() {
    let golden = latest(&[version(&signed(&ISSUER_SEED, golden_metadata()))], None);
    let (p2, req2) = consortium(json!([
        {"registry_did": "did:web:sandbox.example.net", "origin": "sandbox.example.net"},
        {"registry_did": "did:web:registry.example.com", "origin": "registry.example.com",
         "scope": {"types": ["alert"]}},
        {"registry_did": "did:web:partner.example.org", "origin": "partner.example.org",
         "valid_until": "2026-10-15T00:00:00.000Z"}
    ]));
    let v2 = verify_list_offline(&req2, &p2, &[], false).unwrap();
    let second = select_version(&p2, &[v2], at(T), TrustPass::Latest, None);
    assert_eq!(second.status, ListStatus::Used);
    let both = [golden.clone(), second.clone()];
    let pin_issuer = |n: &NodeTrust| n.issuer.clone().unwrap();

    // A — union: only pin 2 lists sandbox.example.net.
    let sandbox = "acdp://sandbox.example.net/3c9d7a1e-5b2f-4c8d-9e0a-1f2b3c4d5e6f";
    let n = evaluate(
        &subject(sandbox, "sandbox.example.net", PRODUCER, "analysis"),
        &both,
        at(T),
        None,
        None,
    );
    assert_eq!(
        (n.outcome, pin_issuer(&n)),
        (TrustOutcome::Trusted, p2.issuer.clone())
    );
    // B — no narrowing: pin 2 scopes registry.example.com to alerts.
    let n = a1(&both);
    assert_eq!(
        (n.outcome, pin_issuer(&n)),
        (TrustOutcome::Trusted, ISSUER.to_string())
    );
    // C — precedence: pin 1 out_of_scope, pin 2 expired → expired.
    let partner = "acdp://partner.example.org/3c9d7a1e-5b2f-4c8d-9e0a-1f2b3c4d5e6f";
    let n = evaluate(
        &subject(
            partner,
            "partner.example.org",
            "did:web:agents.partner.example.org:analyst",
            "alert",
        ),
        &both,
        at(T),
        None,
        None,
    );
    assert_eq!(
        (n.outcome, n.reason),
        (TrustOutcome::Expired, Some(TrustReason::EntryWindow))
    );
    assert_eq!(pin_issuer(&n), p2.issuer);
    // D — tie-break: both trust it; the lower (issuer, list_id) decides.
    let (p3, req3) = consortium(json!([
        {"registry_did": "did:web:registry.example.com", "origin": "registry.example.com"}
    ]));
    let third = select_version(
        &p3,
        &[verify_list_offline(&req3, &p3, &[], false).unwrap()],
        at(T),
        TrustPass::Latest,
        None,
    );
    let n = a1(&[third.clone(), golden.clone()]);
    let golden_pin = pin();
    let lower = std::cmp::min(p3.series(), golden_pin.series());
    assert_eq!(
        (n.issuer.as_deref(), n.list_id.as_deref()),
        (Some(lower.0), Some(lower.1))
    );
    // E — a broken pin does not poison.
    let broken = select_version(&p2, &[], at(T), TrustPass::Latest, None);
    assert_eq!(a1(&[broken, golden.clone()]).outcome, TrustOutcome::Trusted);
    // F — no transitive inclusion: a list from an unpinned issuer is
    // not a version of any pin, so it is never selected.
    let (_, unpinned) = consortium(json!([
        {"registry_did": "did:web:unknown.example.com", "origin": "unknown.example.com"}
    ]));
    assert_eq!(
        verify_list_offline(&unpinned, &pin(), &[], false)
            .unwrap_err()
            .step,
        2
    );
    let unknown = "acdp://unknown.example.com/3c9d7a1e-5b2f-4c8d-9e0a-1f2b3c4d5e6f";
    let n = evaluate(
        &subject(unknown, "unknown.example.com", PRODUCER, "analysis"),
        &[golden],
        at(T),
        None,
        None,
    );
    assert_eq!(
        (n.outcome, n.reason),
        (TrustOutcome::UntrustedRegistry, Some(TrustReason::NoEntry))
    );
    // No pins at all.
    let n = a1(&[]);
    assert_eq!(
        (n.outcome, n.reason),
        (TrustOutcome::ListInvalid, Some(TrustReason::NoValidVersion))
    );
}

#[test]
fn trust_fixtures_each_have_tests() {
    const BOUND: &[(&str, &str)] = &[
        ("trust-001", "trust_lists::trust_001_golden_list"),
        ("trust-002", "trust_lists::trust_002_list_validation (K: acdp-chain trust::trust_002_k_issuer_key_revocation_classes)"),
        ("trust-003", "trust_lists::trust_003_series_state"),
        ("trust-004", "trust_lists::trust_004_retraction"),
        ("trust-005", "trust_lists::trust_005_as_of_selection"),
        ("trust-006", "trust_lists::trust_006_multiple_lists"),
        ("trust-007", "acdp-chain trust::trust_007_bundle_and_report"),
    ];
    let Some(root) = spec_root() else {
        return;
    };
    let mut ids: Vec<String> = std::fs::read_dir(root.join("schemas/conformance"))
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().into_string().unwrap();
            name.starts_with("trust-").then(|| name[..9].to_owned())
        })
        .collect();
    ids.sort();
    let bound: Vec<&str> = BOUND.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, bound, "unbound trust fixtures");
}
