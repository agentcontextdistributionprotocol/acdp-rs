//! RFC-ACDP-0019 known answers: mcp-001 byte for byte, and the pure
//! (no relay) halves of mcp-005..007. The relayed scenarios of
//! mcp-002..007 run in `tests/relay.rs`.

mod common;

use acdp::{
    crypto::{canonicalize_value, SigningKey},
    producer::Producer,
    types::{primitives::Visibility, CtxId},
};
use acdp_mcp_proxy::{
    provenance,
    record::{self, BodyOptions, Embedding, Salt, ServerIdentity, ToolCall, Transport},
};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

fn ts(v: &Value) -> DateTime<Utc> {
    v.as_str().unwrap().parse().unwrap()
}

/// The mcp-001 vector's inputs as a server identity and an observed call.
fn mcp_001_call(v: &Value) -> (ServerIdentity, ToolCall) {
    let inputs = &v["inputs"];
    let meta = &v["producer_content"]["metadata"];
    let server = ServerIdentity {
        name: meta["server"]["name"].as_str().unwrap().into(),
        version: meta["server"]["version"].as_str().map(Into::into),
        protocol_version: meta["mcp_protocol_version"].as_str().unwrap().into(),
        transport: Transport::Stdio,
        endpoint_hash: record::endpoint_hash(&inputs["endpoint"]),
    };
    let call = ToolCall {
        tool: meta["tool"].as_str().unwrap().into(),
        arguments: inputs["arguments"].clone(),
        request_id: Some(inputs["request_id"].clone()),
        result: inputs["call_tool_result"].as_object().unwrap().clone(),
        started_at: ts(&meta["started_at"]),
        completed_at: ts(&meta["completed_at"]),
    };
    (server, call)
}

fn zero_seed_producer() -> Producer {
    Producer::new_did_key(SigningKey::from_bytes(&[0u8; 32]))
}

#[test]
fn mcp_001_reproduces_byte_for_byte() {
    let Some(dir) = common::spec_dir() else {
        eprintln!("skipping mcp-001: no spec checkout");
        return;
    };
    let f = common::fixture(&dir, "mcp-001-tool-result-golden.json");
    let schemas = common::Schemas::load(&dir);
    let v = &f["vectors"][0];
    let exp = &v["expected"];
    let salt = Salt::from_base64url(v["inputs"]["salt"].as_str().unwrap()).unwrap();
    assert_eq!(hex::encode(salt.as_bytes()), exp["salt_hex"]);

    let (server, call) = mcp_001_call(v);
    let hashed = record::hashed_result(&call.result);
    assert_eq!(hashed, exp["hashed_result"]);
    assert_eq!(server.endpoint_hash, exp["endpoint_hash"]);
    assert_eq!(
        record::call_hash(&call.arguments, Some(&salt)),
        exp["arguments_hash"]
    );
    assert_eq!(record::call_hash(&hashed, Some(&salt)), exp["result_hash"]);
    assert_eq!(
        record::call_hash(&v["inputs"]["request_id"], Some(&salt)),
        exp["request_id_hash"]
    );
    let derived: Vec<Value> = record::derived_from(&call.arguments)
        .into_iter()
        .map(|c| c.0.into())
        .collect();
    assert_eq!(Value::from(derived), exp["derived_from"]);

    let producer = zero_seed_producer();
    let prepared = record::prepare(&producer, &server, &call, &BodyOptions::default(), || {
        Ok(salt.clone())
    })
    .unwrap();
    let req = serde_json::to_value(&prepared.request).unwrap();
    assert_eq!(req["agent_id"], f["test_keypair"]["did_key"]);

    // The ProducerContent's canonical form, byte for byte.
    let mut pc = req.as_object().unwrap().clone();
    pc.remove("content_hash");
    pc.remove("signature");
    assert_eq!(
        String::from_utf8(canonicalize_value(&Value::Object(pc))).unwrap(),
        exp["canonical_form"].as_str().unwrap()
    );
    assert_eq!(req["content_hash"], exp["content_hash"]);
    assert_eq!(req["signature"]["value"], exp["signature_value_base64"]);
    assert_eq!(req, exp["publish_request_body"]);
    assert_eq!(prepared.idempotency_key, exp["idempotency_key"]);
    assert_eq!(prepared.salt.as_ref(), Some(&salt));
    schemas.validate("record", &req["metadata"]).unwrap();

    // The returned CallToolResult once the registry assigned the ctx_id.
    let assigned = &v["registry_assigned"];
    let ctx_id = CtxId::parse(assigned["ctx_id"].as_str().unwrap()).unwrap();
    let link = provenance::published(
        &ctx_id,
        &prepared.request.content_hash,
        prepared.salt.as_ref(),
    );
    assert_eq!(link["registry"], assigned["origin_registry"]);
    schemas.validate("provenance", &link).unwrap();
    let mut returned = call.result.clone();
    assert!(provenance::attach(&mut returned, link));
    assert_eq!(Value::Object(returned), exp["returned_result"]);
}

#[test]
fn mcp_001_body_verifies_offline() {
    let Some(dir) = common::spec_dir() else {
        return;
    };
    let f = common::fixture(&dir, "mcp-001-tool-result-golden.json");
    let mut body = f["vectors"][0]["expected"]["publish_request_body"].clone();
    let assigned = &f["vectors"][0]["registry_assigned"];
    for k in ["ctx_id", "origin_registry", "created_at", "lineage_id"] {
        body[k] = assigned[k].clone();
    }
    acdp::crypto::verify_body_value_offline(&body).unwrap();
}

#[test]
fn mcp_005_derived_from() {
    let ok1 = "acdp://registry.example.com/7b1d0c52-3e4f-4a6b-8c9d-0e1f2a3b4c5d";
    let ok2 = "acdp://registry.example.com/0f9e8d7c-6b5a-4c3d-9e2f-1a0b9c8d7e6f";
    // A — JCS preorder: key "b" sorts before "z" regardless of insertion.
    let args = json!({ "z": ok1, "b": [ok2, { "x": ok1 }] });
    let got: Vec<String> = record::derived_from(&args)
        .into_iter()
        .map(|c| c.0)
        .collect();
    assert_eq!(got, [ok2, ok1]);

    // RFC 8785 orders keys by UTF-16 code units, not UTF-8 bytes: U+FB01
    // (one unit 0xFB01) sorts after U+1F600 (surrogates 0xD83D…) though
    // its UTF-8 encoding sorts first.
    let args = json!({ "\u{fb01}": ok1, "\u{1f600}": ok2 });
    let got: Vec<String> = record::derived_from(&args)
        .into_iter()
        .map(|c| c.0)
        .collect();
    assert_eq!(got, [ok2, ok1]);

    // B — near-misses: keys, embedded in text, upper-case authority,
    // non-v4 UUID, bad variant digit.
    let args = json!({
        ok1: "key, not value",
        "text": format!("see {ok1} for details"),
        "upper": "acdp://Registry.example.com/7b1d0c52-3e4f-4a6b-8c9d-0e1f2a3b4c5d",
        "v1": "acdp://registry.example.com/7b1d0c52-3e4f-1a6b-8c9d-0e1f2a3b4c5d",
        "variant": "acdp://registry.example.com/7b1d0c52-3e4f-4a6b-7c9d-0e1f2a3b4c5d",
    });
    assert!(record::derived_from(&args).is_empty());

    // D — cap at 1000.
    let many: Vec<String> = (0..1100)
        .map(|i| format!("acdp://r.example/00000000-0000-4000-8000-{i:012x}"))
        .collect();
    let got = record::derived_from(&json!({ "refs": many }));
    assert_eq!(got.len(), record::MAX_DERIVED_FROM);
    assert_eq!(got[999].0, many[999]);
}

#[test]
fn mcp_006_embedding_allowlist() {
    let Some(dir) = common::spec_dir() else {
        return;
    };
    let f = common::fixture(&dir, "mcp-001-tool-result-golden.json");
    let schemas = common::Schemas::load(&dir);
    let (server, call) = mcp_001_call(&f["vectors"][0]);
    let producer = zero_seed_producer();
    let salt = || Salt::random();

    // A — default: not embedded.
    let p = record::prepare(&producer, &server, &call, &BodyOptions::default(), salt).unwrap();
    let req = serde_json::to_value(&p.request).unwrap();
    assert_eq!(req["data_refs"], json!([]));
    assert_eq!(req["metadata"]["embedded"], false);

    // B — allowlisted: one embedded DataRef, unsalted hashes.
    let opts = BodyOptions {
        embedding: Embedding::Allowlisted {
            external_base: None,
        },
        ..BodyOptions::default()
    };
    let p = record::prepare(&producer, &server, &call, &opts, salt).unwrap();
    let req = serde_json::to_value(&p.request).unwrap();
    let hashed = record::hashed_result(&call.result);
    assert_eq!(
        req["data_refs"],
        json!([{ "type": "primary_result", "format": "json",
                 "embedded": { "encoding": "json", "content": hashed } }])
    );
    let m = &req["metadata"];
    assert_eq!(
        (m["embedded"].clone(), m["salted"].clone()),
        (json!(true), json!(false))
    );
    assert_eq!(m["result_hash"], record::call_hash(&hashed, None));
    assert!(p.salt.is_none());
    schemas.validate("record", m).unwrap();

    // C — over the cap: external DataRef when configured, else
    // unembedded and salted.
    let mut big = call.clone();
    big.result.insert(
        "content".into(),
        json!([{ "type": "text", "text": "x".repeat(70_000) }]),
    );
    let p = record::prepare(&producer, &server, &big, &opts, salt).unwrap();
    let req = serde_json::to_value(&p.request).unwrap();
    assert_eq!(req["data_refs"], json!([]));
    assert_eq!(
        (
            req["metadata"]["embedded"].clone(),
            req["metadata"]["salted"].clone()
        ),
        (json!(false), json!(true))
    );

    let ext = BodyOptions {
        embedding: Embedding::Allowlisted {
            external_base: Some("https://results.example.com/mcp/".into()),
        },
        ..BodyOptions::default()
    };
    let p = record::prepare(&producer, &server, &big, &ext, salt).unwrap();
    let req = serde_json::to_value(&p.request).unwrap();
    let hashed = record::hashed_result(&big.result);
    let h = acdp::crypto::compute_content_hash(&hashed).unwrap();
    let payload = p.external.as_ref().unwrap();
    assert_eq!(payload.bytes, canonicalize_value(&hashed));
    assert_eq!(
        req["data_refs"],
        json!([{ "type": "primary_result", "format": "json", "content_hash": h.as_str(),
                 "location": format!("https://results.example.com/mcp/{}.json", payload.hex) }])
    );
    assert_eq!(req["metadata"]["embedded"], true);
}

#[test]
fn mcp_007_salt_rules() {
    let Some(dir) = common::spec_dir() else {
        return;
    };
    let f = common::fixture(&dir, "mcp-001-tool-result-golden.json");
    let (server, call) = mcp_001_call(&f["vectors"][0]);
    let producer = zero_seed_producer();
    let opts = BodyOptions::default();

    // A + B — every unembedded record is salted, freshly per body.
    let a = record::prepare(&producer, &server, &call, &opts, Salt::random).unwrap();
    let b = record::prepare(&producer, &server, &call, &opts, Salt::random).unwrap();
    let (ma, mb) = (
        a.request.metadata.as_ref().unwrap(),
        b.request.metadata.as_ref().unwrap(),
    );
    assert_eq!(ma["salted"], true);
    assert_ne!(ma["arguments_hash"], mb["arguments_hash"]);
    assert_ne!(a.salt, b.salt);
    assert_eq!(a.salt.unwrap().to_base64url().len(), 43);

    // C — endpoint_hash is unsalted and stable.
    assert_eq!(ma["server"]["endpoint_hash"], mb["server"]["endpoint_hash"]);

    // D — no secrets: redacted args, and HTTP userinfo/query/fragment.
    let args = [
        "-y".to_string(),
        "pkg".into(),
        "--token".into(),
        "s3cret".into(),
    ];
    let d = record::stdio_descriptor("npx", &args, &[3]);
    assert_eq!(
        d,
        json!({ "command": "npx", "args": ["-y", "pkg", "--token", "<redacted>"] })
    );
    assert!(!canonicalize_value(&d).windows(6).any(|w| w == b"s3cret"));
    let d = record::http_descriptor("https://user:pw@mcp.example.com/v1/mcp?key=abc#frag").unwrap();
    assert_eq!(d, json!({ "url": "https://mcp.example.com/v1/mcp" }));
    assert_eq!(
        record::endpoint_hash(&d),
        record::endpoint_hash(&record::http_descriptor("https://mcp.example.com/v1/mcp").unwrap())
    );
}

#[test]
fn visibility_and_failure_shapes() {
    let Some(dir) = common::spec_dir() else {
        return;
    };
    let schemas = common::Schemas::load(&dir);
    assert_eq!(BodyOptions::default().visibility, Visibility::Private);
    schemas
        .validate("provenance", &provenance::failed(None))
        .unwrap();
    schemas
        .validate("provenance", &provenance::failed(Some("rate_limited")))
        .unwrap();
    let closed = provenance::fail_closed_result("t", provenance::failed(None));
    assert_eq!(closed["isError"], true);
    assert_eq!(closed["content"].as_array().unwrap().len(), 1);
}

/// Every `mcp-*` fixture the spec ships is bound to a test here or in
/// `tests/relay.rs`; a new fixture fails this until it is.
#[test]
fn mcp_fixtures_each_have_tests() {
    const BOUND: &[(&str, &str)] = &[
        ("mcp-001", "conformance::mcp_001_reproduces_byte_for_byte"),
        ("mcp-002", "relay::mcp_002_relays_the_result_unchanged"),
        (
            "mcp-003",
            "relay::mcp_003_provenance_shape_and_consumer_check",
        ),
        ("mcp-004", "relay::mcp_004_a_fail_open_on_registry_error"),
        ("mcp-005", "conformance::mcp_005_derived_from"),
        ("mcp-006", "conformance::mcp_006_embedding_allowlist"),
        ("mcp-007", "conformance::mcp_007_salt_rules"),
    ];
    let Some(dir) = common::spec_dir() else {
        return;
    };
    let mut ids: Vec<String> = std::fs::read_dir(dir.join("schemas/conformance"))
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().into_string().unwrap();
            name.starts_with("mcp-").then(|| name[..7].to_owned())
        })
        .collect();
    ids.sort();
    let bound: Vec<&str> = BOUND.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, bound, "unbound mcp fixtures");
}
