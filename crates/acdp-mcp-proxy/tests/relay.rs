//! The relayed scenarios of mcp-002..007: the proxy in front of a stub
//! MCP server that returns the mcp-001 CallToolResult, publishing to a
//! wiremock registry.

mod common;

use std::{collections::HashMap, sync::Arc, time::Duration};

use acdp::{client::RegistryClient, crypto::SigningKey, producer::Producer};
use acdp_mcp_proxy::{
    provenance::META_KEY,
    record::{self, BodyOptions, Embedding, Salt, Transport},
    relay::{ExternalStore, ToolPolicy},
    Proxy,
};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, Request, ResponseTemplate,
};

const CTX_ID: &str = "acdp://registry.example.com/3c2b1a09-8f7e-4d6c-9b5a-4e3d2c1b0a9f";
const PING_REPLY: &str = r#"{"jsonrpc": "2.0",  "id": 9, "result": {}}"#;

fn mcp_001_result() -> Value {
    json!({
        "content": [{ "type": "text", "text": "EMEA 0.42%, AMER 0.31%, APAC 0.27%" }],
        "structuredContent": { "rates": { "AMER": 0.31, "APAC": 0.27, "EMEA": 0.42 } },
        "isError": false,
        "_meta": { "com.example/trace": "abc123" }
    })
}

fn mcp_001_arguments() -> Value {
    json!({
        "query": "Q3 card-fraud rate by region",
        "sources": [
            "acdp://registry.example.com/7b1d0c52-3e4f-4a6b-8c9d-0e1f2a3b4c5d",
            { "ref": "acdp://registry.example.com/0f9e8d7c-6b5a-4c3d-9e2f-1a0b9c8d7e6f" },
            "acdp://registry.example.com/7b1d0c52-3e4f-4a6b-8c9d-0e1f2a3b4c5d"
        ],
        "limit": 5
    })
}

fn publish_ok() -> ResponseTemplate {
    ResponseTemplate::new(201).set_body_json(json!({
        "ctx_id": CTX_ID,
        "lineage_id": "lin:sha256:53269327c5284c8d8389e5687a6604e81c64e81587e6518687cb41a7f3ea5647",
        "version": 1,
        "created_at": "2026-10-26T14:03:12.040Z",
        "status": "active"
    }))
}

fn wire_error(status: u16, code: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_json(json!({ "error": { "code": code, "message": code } }))
}

/// Stub stdio MCP server: `initialize`, `ping`, and `tools/call`
/// answered from `results` by tool name.
async fn stub_server(
    input: DuplexStream,
    mut output: DuplexStream,
    results: HashMap<String, Value>,
) {
    let mut lines = BufReader::new(input).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let msg: Value = serde_json::from_str(&line).unwrap();
        let Some(id) = msg.get("id").cloned() else {
            continue;
        };
        let reply = match msg["method"].as_str() {
            Some("initialize") => json!({ "jsonrpc": "2.0", "id": id, "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "fraud-stats", "version": "1.4.2" }
            }})
            .to_string(),
            Some("ping") => PING_REPLY.to_string(),
            Some("tools/call") => {
                let tool = msg["params"]["name"].as_str().unwrap();
                json!({ "jsonrpc": "2.0", "id": id, "result": results[tool] }).to_string()
            }
            _ => continue,
        };
        output.write_all(reply.as_bytes()).await.unwrap();
        output.write_all(b"\n").await.unwrap();
    }
}

struct Harness {
    to_proxy: DuplexStream,
    from_proxy: Lines<BufReader<DuplexStream>>,
    next_id: u64,
}

impl Harness {
    async fn start(proxy: Proxy, results: HashMap<String, Value>) -> Self {
        let (to_proxy, client_in) = tokio::io::duplex(1 << 20);
        let (client_out, from_proxy) = tokio::io::duplex(1 << 20);
        let (server_in, stub_in) = tokio::io::duplex(1 << 20);
        let (stub_out, server_out) = tokio::io::duplex(1 << 20);
        tokio::spawn(stub_server(stub_in, stub_out, results));
        tokio::spawn(Arc::new(proxy).run(client_in, client_out, server_in, server_out));
        let mut h = Self {
            to_proxy,
            from_proxy: BufReader::new(from_proxy).lines(),
            next_id: 1,
        };
        let init = h
            .request(
                "initialize",
                json!({ "protocolVersion": "2025-06-18", "capabilities": {},
                     "clientInfo": { "name": "test", "version": "0" } }),
            )
            .await;
        assert_eq!(init["result"]["serverInfo"]["name"], "fraud-stats");
        h
    }

    async fn send(&mut self, line: &str) {
        self.to_proxy.write_all(line.as_bytes()).await.unwrap();
        self.to_proxy.write_all(b"\n").await.unwrap();
    }

    async fn recv_line(&mut self) -> String {
        tokio::time::timeout(Duration::from_secs(20), self.from_proxy.next_line())
            .await
            .expect("proxy reply")
            .unwrap()
            .expect("proxy closed")
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.send(&msg.to_string()).await;
        let reply: Value = serde_json::from_str(&self.recv_line().await).unwrap();
        assert_eq!(reply["id"], id);
        reply
    }

    async fn call(&mut self, tool: &str, arguments: Value) -> Value {
        let r = self
            .request(
                "tools/call",
                json!({ "name": tool, "arguments": arguments }),
            )
            .await;
        r["result"].clone()
    }
}

fn proxy(registry: RegistryClient) -> Proxy {
    Proxy {
        producer: Producer::new_did_key(SigningKey::from_bytes(&[0u8; 32])),
        registry,
        transport: Transport::Stdio,
        endpoint_hash: record::endpoint_hash(&record::stdio_descriptor(
            "npx",
            &["-y".into(), "@example/fraud-stats-mcp@1.4.2".into()],
            &[],
        )),
        default_policy: ToolPolicy::default(),
        tools: HashMap::new(),
        publish_timeout: Duration::from_secs(10),
        max_attempts: 2,
        external: None,
    }
}

fn results() -> HashMap<String, Value> {
    HashMap::from([("regional_fraud_rate".to_string(), mcp_001_result())])
}

async fn registry_ok() -> (MockServer, RegistryClient) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/contexts"))
        .respond_with(publish_ok())
        .mount(&server)
        .await;
    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    (server, client)
}

async fn published(server: &MockServer) -> Vec<Request> {
    server.received_requests().await.unwrap_or_default()
}

fn without_meta(v: &Value) -> Value {
    let mut v = v.clone();
    v.as_object_mut().unwrap().remove("_meta");
    v
}

#[tokio::test]
async fn mcp_002_relays_the_result_unchanged() {
    let (reg, client) = registry_ok().await;
    let mut h = Harness::start(proxy(client), results()).await;

    // Messages other than tools/call results pass byte for byte.
    h.send(r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#).await;
    assert_eq!(h.recv_line().await, PING_REPLY);

    // A — content, structuredContent, isError unchanged; result_hash
    // recomputes with the returned salt.
    let got = h.call("regional_fraud_rate", mcp_001_arguments()).await;
    let upstream = mcp_001_result();
    assert_eq!(without_meta(&got), without_meta(&upstream));
    let reqs = published(&reg).await;
    assert_eq!(reqs.len(), 1);
    let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    let salt = Salt::from_base64url(got["_meta"][META_KEY]["salt"].as_str().unwrap()).unwrap();
    let hashed = record::hashed_result(got.as_object().unwrap());
    assert_eq!(
        body["metadata"]["result_hash"],
        record::call_hash(&hashed, Some(&salt))
    );

    // B — upstream _meta keys kept; only io.acdp/provenance added.
    let meta = got["_meta"].as_object().unwrap();
    assert_eq!(meta["com.example/trace"], "abc123");
    assert_eq!(meta.len(), 2);
}

#[tokio::test]
async fn mcp_002_c_upstream_provenance_is_left_alone() {
    let (reg, client) = registry_ok().await;
    let mut upstream = mcp_001_result();
    upstream["_meta"][META_KEY] = json!({ "ctx_id": "upstream's own" });
    let mut h = Harness::start(
        proxy(client),
        HashMap::from([("regional_fraud_rate".to_string(), upstream.clone())]),
    )
    .await;
    let got = h.call("regional_fraud_rate", mcp_001_arguments()).await;
    assert_eq!(got, upstream);
    assert_eq!(
        published(&reg).await.len(),
        1,
        "the record is still published"
    );
}

#[tokio::test]
async fn mcp_003_provenance_shape_and_consumer_check() {
    let dir = common::spec_dir();
    let (reg, client) = registry_ok().await;
    let mut p = proxy(client);
    p.tools.insert(
        "embedded_tool".into(),
        ToolPolicy {
            body: BodyOptions {
                embedding: Embedding::Allowlisted {
                    external_base: None,
                },
                ..BodyOptions::default()
            },
            ..ToolPolicy::default()
        },
    );
    let mut rs = results();
    rs.insert("embedded_tool".into(), mcp_001_result());
    let mut h = Harness::start(p, rs).await;

    // A — published and salted.
    let got = h.call("regional_fraud_rate", mcp_001_arguments()).await;
    let link = &got["_meta"][META_KEY];
    let body: Value = serde_json::from_slice(&published(&reg).await[0].body).unwrap();
    assert_eq!(link["ctx_id"], CTX_ID);
    assert_eq!(link["content_hash"], body["content_hash"]);
    assert_eq!(link["registry"], "registry.example.com");
    let salt = Salt::from_base64url(link["salt"].as_str().unwrap()).unwrap();
    if let Some(dir) = &dir {
        common::Schemas::load(dir)
            .validate("provenance", link)
            .unwrap();
    }

    // D — the consumer verifies the body, then the result against it;
    // one changed byte fails the result_hash check.
    let mut stored = body.clone();
    stored["ctx_id"] = CTX_ID.into();
    stored["origin_registry"] = "registry.example.com".into();
    stored["created_at"] = "2026-10-26T14:03:12.040Z".into();
    stored["lineage_id"] =
        "lin:sha256:53269327c5284c8d8389e5687a6604e81c64e81587e6518687cb41a7f3ea5647".into();
    acdp::crypto::verify_body_value_offline(&stored).unwrap();
    assert_eq!(stored["type"], record::CONTEXT_TYPE);
    assert_eq!(stored["metadata"]["tool"], "regional_fraud_rate");
    let hashed = record::hashed_result(got.as_object().unwrap());
    assert_eq!(
        stored["metadata"]["result_hash"],
        record::call_hash(&hashed, Some(&salt))
    );
    let mut tampered = hashed.clone();
    tampered["content"][0]["text"] = "EMEA 0.43%, AMER 0.31%, APAC 0.27%".into();
    assert_ne!(
        stored["metadata"]["result_hash"],
        record::call_hash(&tampered, Some(&salt))
    );
    // Arguments and request id recompute too (§4.3 step 5).
    assert_eq!(
        stored["metadata"]["arguments_hash"],
        record::call_hash(&mcp_001_arguments(), Some(&salt))
    );
    assert_eq!(
        stored["metadata"]["request_id_hash"],
        record::call_hash(&json!(2), Some(&salt))
    );

    // B — salt absent exactly when the record is unsalted.
    let got = h.call("embedded_tool", json!({})).await;
    let link = &got["_meta"][META_KEY];
    assert!(link.get("salt").is_none());
    let body: Value = serde_json::from_slice(&published(&reg).await[1].body).unwrap();
    assert_eq!(body["metadata"]["salted"], false);
}

#[tokio::test]
async fn mcp_003_c_no_link_before_the_publish_response() {
    let reg = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(publish_ok().set_delay(Duration::from_millis(600)))
        .mount(&reg)
        .await;
    let client = RegistryClient::with_test_transport(&reg.uri()).unwrap();
    let mut h = Harness::start(proxy(client), results()).await;
    let t = std::time::Instant::now();
    let got = h.call("regional_fraud_rate", mcp_001_arguments()).await;
    assert!(t.elapsed() >= Duration::from_millis(600));
    assert_eq!(got["_meta"][META_KEY]["ctx_id"], CTX_ID);
}

#[tokio::test]
async fn mcp_004_a_fail_open_on_registry_error() {
    let reg = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(wire_error(429, "rate_limited"))
        .mount(&reg)
        .await;
    let client = RegistryClient::with_test_transport(&reg.uri()).unwrap();
    let mut h = Harness::start(proxy(client), results()).await;
    let got = h.call("regional_fraud_rate", mcp_001_arguments()).await;
    assert_eq!(without_meta(&got), without_meta(&mcp_001_result()));
    assert_eq!(got["_meta"]["com.example/trace"], "abc123");
    assert_eq!(
        got["_meta"][META_KEY],
        json!({ "failed": true, "error": "rate_limited" })
    );
    assert_eq!(published(&reg).await.len(), 2, "retried up to max_attempts");
}

#[tokio::test]
async fn mcp_004_b_fail_open_when_unreachable_or_slow() {
    // Connection refused.
    let refused = RegistryClient::with_test_transport("http://127.0.0.1:1").unwrap();
    let mut h = Harness::start(proxy(refused), results()).await;
    let got = h.call("regional_fraud_rate", mcp_001_arguments()).await;
    assert_eq!(got["_meta"][META_KEY], json!({ "failed": true }));

    // The publish timeout elapses.
    let reg = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(publish_ok().set_delay(Duration::from_secs(5)))
        .mount(&reg)
        .await;
    let mut p = proxy(RegistryClient::with_test_transport(&reg.uri()).unwrap());
    p.publish_timeout = Duration::from_millis(300);
    let mut h = Harness::start(p, results()).await;
    let got = h.call("regional_fraud_rate", mcp_001_arguments()).await;
    assert_eq!(got["_meta"][META_KEY], json!({ "failed": true }));
    assert_eq!(without_meta(&got), without_meta(&mcp_001_result()));
}

#[tokio::test]
async fn mcp_004_c_fail_closed_withholds_the_result() {
    let reg = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(wire_error(400, "schema_violation"))
        .mount(&reg)
        .await;
    let mut p = proxy(RegistryClient::with_test_transport(&reg.uri()).unwrap());
    p.tools.insert(
        "regional_fraud_rate".into(),
        ToolPolicy {
            fail_closed: true,
            ..ToolPolicy::default()
        },
    );
    let mut h = Harness::start(p, results()).await;
    let got = h.call("regional_fraud_rate", mcp_001_arguments()).await;
    assert_eq!(got["isError"], true);
    let content = got["content"].as_array().unwrap();
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["type"], "text");
    assert!(
        !got.to_string().contains("EMEA"),
        "upstream content withheld"
    );
    assert!(got.get("structuredContent").is_none());
    assert_eq!(
        got["_meta"][META_KEY],
        json!({ "failed": true, "error": "schema_violation" })
    );
}

#[tokio::test]
async fn mcp_004_d_retries_resend_the_identical_body() {
    let reg = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(wire_error(429, "rate_limited"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&reg)
        .await;
    Mock::given(method("POST"))
        .respond_with(publish_ok())
        .with_priority(2)
        .mount(&reg)
        .await;
    let mut h = Harness::start(
        proxy(RegistryClient::with_test_transport(&reg.uri()).unwrap()),
        results(),
    )
    .await;
    let got = h.call("regional_fraud_rate", mcp_001_arguments()).await;
    assert_eq!(got["_meta"][META_KEY]["ctx_id"], CTX_ID);
    let reqs = published(&reg).await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].body, reqs[1].body, "byte-identical body");
    let key = |r: &Request| {
        r.headers
            .get("idempotency-key")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    };
    let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    let hex = body["content_hash"]
        .as_str()
        .unwrap()
        .trim_start_matches("sha256:");
    assert_eq!(key(&reqs[0]), format!("acdp-mcp-{hex}"));
    assert_eq!(key(&reqs[0]), key(&reqs[1]));
}

#[tokio::test]
async fn mcp_005_c_result_refs_are_not_inputs() {
    let (reg, client) = registry_ok().await;
    let mut result = mcp_001_result();
    result["content"][0]["text"] =
        "see acdp://registry.example.com/7b1d0c52-3e4f-4a6b-8c9d-0e1f2a3b4c5d".into();
    result["structuredContent"] =
        json!({ "ref": "acdp://registry.example.com/7b1d0c52-3e4f-4a6b-8c9d-0e1f2a3b4c5d" });
    let mut h = Harness::start(
        proxy(client),
        HashMap::from([("regional_fraud_rate".to_string(), result)]),
    )
    .await;
    h.call("regional_fraud_rate", json!({ "query": "plain" }))
        .await;
    let body: Value = serde_json::from_slice(&published(&reg).await[0].body).unwrap();
    assert_eq!(body["derived_from"], json!([]));

    // With the mcp-001 arguments: two distinct ids, JCS order.
    h.call("regional_fraud_rate", mcp_001_arguments()).await;
    let body: Value = serde_json::from_slice(&published(&reg).await[1].body).unwrap();
    assert_eq!(
        body["derived_from"],
        json!([
            "acdp://registry.example.com/7b1d0c52-3e4f-4a6b-8c9d-0e1f2a3b4c5d",
            "acdp://registry.example.com/0f9e8d7c-6b5a-4c3d-9e2f-1a0b9c8d7e6f"
        ])
    );
}

#[tokio::test]
async fn mcp_006_c_external_result_is_written_before_publishing() {
    let (reg, client) = registry_ok().await;
    let dir = std::env::temp_dir().join(format!("acdp-mcp-ext-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut p = proxy(client);
    p.external = Some(ExternalStore { dir: dir.clone() });
    p.default_policy.body.embedding = Embedding::Allowlisted {
        external_base: Some("https://results.example.com".into()),
    };
    let mut big = mcp_001_result();
    big["content"][0]["text"] = "x".repeat(70_000).into();
    let mut h = Harness::start(
        p,
        HashMap::from([("regional_fraud_rate".to_string(), big.clone())]),
    )
    .await;
    let got = h.call("regional_fraud_rate", json!({})).await;
    assert!(got["_meta"][META_KEY].get("salt").is_none());
    let body: Value = serde_json::from_slice(&published(&reg).await[0].body).unwrap();
    let loc = body["data_refs"][0]["location"].as_str().unwrap();
    let file = dir.join(loc.rsplit('/').next().unwrap());
    let bytes = std::fs::read(&file).unwrap();
    assert_eq!(
        acdp::crypto::compute_content_hash(&serde_json::from_slice(&bytes).unwrap())
            .unwrap()
            .as_str(),
        body["data_refs"][0]["content_hash"]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn over_long_tool_name_is_a_publish_failure() {
    let (reg, client) = registry_ok().await;
    let long = "t".repeat(257);
    let mut h = Harness::start(
        proxy(client),
        HashMap::from([(long.clone(), mcp_001_result())]),
    )
    .await;
    let got = h.call(&long, json!({})).await;
    assert_eq!(got["_meta"][META_KEY], json!({ "failed": true }));
    assert!(published(&reg).await.is_empty());
}

#[tokio::test]
async fn result_before_initialize_follows_the_tool_policy() {
    let (reg, client) = registry_ok().await;
    let mut p = proxy(client);
    p.default_policy.fail_closed = true;
    let (mut to_proxy, client_in) = tokio::io::duplex(1 << 16);
    let (client_out, from_proxy) = tokio::io::duplex(1 << 16);
    let (server_in, stub_in) = tokio::io::duplex(1 << 16);
    let (stub_out, server_out) = tokio::io::duplex(1 << 16);
    tokio::spawn(stub_server(stub_in, stub_out, results()));
    tokio::spawn(Arc::new(p).run(client_in, client_out, server_in, server_out));
    let call = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": { "name": "regional_fraud_rate", "arguments": {} } });
    to_proxy
        .write_all(format!("{call}\n").as_bytes())
        .await
        .unwrap();
    let mut lines = BufReader::new(from_proxy).lines();
    let reply: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(
        reply["result"]["_meta"][META_KEY],
        json!({ "failed": true })
    );
    assert!(published(&reg).await.is_empty());
}

#[tokio::test]
async fn skipped_tools_relay_without_a_record() {
    let (reg, client) = registry_ok().await;
    let mut p = proxy(client);
    p.default_policy.skip = true;
    let mut h = Harness::start(p, results()).await;
    let got = h.call("regional_fraud_rate", json!({})).await;
    assert_eq!(got, mcp_001_result());
    assert!(published(&reg).await.is_empty());
}

#[tokio::test]
async fn holder_verifies_the_link() {
    use acdp::types::{primitives::AgentDid, Body};
    use acdp_mcp_proxy::verify::{verify_link, HeldCall, LinkError};

    let (reg, client) = registry_ok().await;
    let mut h = Harness::start(proxy(client), results()).await;
    let got = h.call("regional_fraud_rate", mcp_001_arguments()).await;
    let link = got["_meta"][META_KEY].clone();
    let mut stored: Value = serde_json::from_slice(&published(&reg).await[0].body).unwrap();
    stored["ctx_id"] = CTX_ID.into();
    stored["origin_registry"] = "registry.example.com".into();
    stored["created_at"] = "2026-10-26T14:03:12.040Z".into();
    stored["lineage_id"] =
        "lin:sha256:53269327c5284c8d8389e5687a6604e81c64e81587e6518687cb41a7f3ea5647".into();
    let body: Body = acdp::crypto::verify_body_value_offline(&stored).unwrap();
    let proxy_did = vec![body.agent_id.clone()];
    let result = got.as_object().unwrap().clone();
    let args = mcp_001_arguments();
    let id = json!(2);
    let held = HeldCall {
        tool: "regional_fraud_rate",
        result: &result,
        arguments: Some(&args),
        request_id: Some(&id),
    };
    verify_link(&body, &link, &proxy_did, &held).unwrap();
    let step = |e: LinkError| match e {
        LinkError::Unrecognised { step, .. } | LinkError::Mismatch { step, .. } => step,
    };

    // Step 1 — bindings.
    let mut other = link.clone();
    other["ctx_id"] = "acdp://registry.example.com/0f9e8d7c-6b5a-4c3d-9e2f-1a0b9c8d7e6f".into();
    assert_eq!(
        step(verify_link(&body, &other, &proxy_did, &held).unwrap_err()),
        1
    );
    let mut other = link.clone();
    other["registry"] = "elsewhere.example.com".into();
    assert_eq!(
        step(verify_link(&body, &other, &proxy_did, &held).unwrap_err()),
        1
    );
    // Step 2 — untrusted proxy; closed record.
    let stranger = vec![AgentDid::new("did:web:someone.example.com")];
    assert!(matches!(
        verify_link(&body, &link, &stranger, &held),
        Err(LinkError::Unrecognised { step: 2, .. })
    ));
    let mut extra = body.clone();
    extra.metadata.as_mut().unwrap()["note"] = "x".into();
    assert_eq!(
        step(verify_link(&extra, &link, &proxy_did, &held).unwrap_err()),
        2
    );
    // Step 3 — only the canonical salt: flip a trailing bit.
    let s = link["salt"].as_str().unwrap();
    let last = s.chars().last().unwrap();
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let idx = alphabet.find(last).unwrap();
    let flipped = alphabet.chars().nth(idx ^ 1).unwrap();
    let mut bad = link.clone();
    bad["salt"] = format!("{}{flipped}", &s[..42]).into();
    assert!(matches!(
        verify_link(&body, &bad, &proxy_did, &held),
        Err(LinkError::Mismatch { step: 3, .. })
    ));
    let mut padded = link.clone();
    padded["salt"] = format!("{s}=").into();
    assert_eq!(
        step(verify_link(&body, &padded, &proxy_did, &held).unwrap_err()),
        3
    );
    // Step 4 — result, tool, isError.
    let mut tampered = result.clone();
    tampered["content"][0]["text"] = "EMEA 0.43%".into();
    let h2 = HeldCall {
        result: &tampered,
        ..held.clone()
    };
    assert!(matches!(
        verify_link(&body, &link, &proxy_did, &h2),
        Err(LinkError::Mismatch { step: 4, .. })
    ));
    let h2 = HeldCall {
        tool: "other_tool",
        ..held.clone()
    };
    assert_eq!(
        step(verify_link(&body, &link, &proxy_did, &h2).unwrap_err()),
        4
    );
    // Step 5 — wrong request id; absent request_id_hash is unchecked.
    let wrong = json!(3);
    let h2 = HeldCall {
        request_id: Some(&wrong),
        ..held.clone()
    };
    assert_eq!(
        step(verify_link(&body, &link, &proxy_did, &h2).unwrap_err()),
        5
    );
    let mut no_id = body.clone();
    no_id
        .metadata
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("request_id_hash");
    verify_link(&no_id, &link, &proxy_did, &h2).unwrap();
}
