//! mcp-008: MCP revisions without `initialize`, and results that are not
//! yet complete (RFC-ACDP-0019 §3.1–§3.2). The proxy sits in front of a
//! scripted stub server and publishes to a wiremock registry.
//!
//! Task-delivered results are not covered by this proxy (documented in
//! the README), so scenario E checks the non-covering behaviour: the task
//! handle and the completed `tasks/get` are relayed unchanged with no body.
//! Scenario E2 applies only to a covering proxy.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use acdp::{client::RegistryClient, crypto::SigningKey, producer::Producer};
use acdp_mcp_proxy::{
    provenance::META_KEY,
    record::{self, Salt, Transport},
    relay::{ToolPolicy, PROTOCOL_VERSION_META, SERVER_INFO_META},
    Proxy,
};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

const CTX_ID: &str = "acdp://registry.example.com/3c2b1a09-8f7e-4d6c-9b5a-4e3d2c1b0a9f";
const NEW_ERA: &str = "2026-07-28";

/// What the stub answers: the `result` for a request, by method and id.
type Script = Arc<dyn Fn(&Value) -> Option<Value> + Send + Sync>;

fn mcp_001_result() -> Value {
    json!({
        "content": [{ "type": "text", "text": "EMEA 0.42%, AMER 0.31%, APAC 0.27%" }],
        "structuredContent": { "rates": { "AMER": 0.31, "APAC": 0.27, "EMEA": 0.42 } },
        "isError": false,
        "_meta": { "com.example/trace": "abc123" }
    })
}

/// The mcp-001 result as a 2026-07-28 server returns it: serverInfo in
/// the result's `_meta`.
fn new_era_result() -> Value {
    let mut r = mcp_001_result();
    r["_meta"][SERVER_INFO_META] = json!({ "name": "fraud-stats", "version": "1.4.2" });
    r
}

/// Stub server that answers each request with `script`, recording every
/// line it writes so tests can compare relayed bytes.
async fn stub_server(
    input: DuplexStream,
    mut output: DuplexStream,
    script: Script,
    sent: Arc<Mutex<Vec<String>>>,
) {
    let mut lines = BufReader::new(input).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let msg: Value = serde_json::from_str(&line).unwrap();
        let Some(id) = msg.get("id").cloned() else {
            continue;
        };
        let Some(result) = script(&msg) else {
            continue;
        };
        let reply = json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string();
        sent.lock().unwrap().push(reply.clone());
        output.write_all(reply.as_bytes()).await.unwrap();
        output.write_all(b"\n").await.unwrap();
    }
}

struct Harness {
    to_proxy: DuplexStream,
    from_proxy: Lines<BufReader<DuplexStream>>,
    sent: Arc<Mutex<Vec<String>>>,
}

impl Harness {
    fn start(proxy: Proxy, script: Script) -> Self {
        let (to_proxy, client_in) = tokio::io::duplex(1 << 20);
        let (client_out, from_proxy) = tokio::io::duplex(1 << 20);
        let (server_in, stub_in) = tokio::io::duplex(1 << 20);
        let (stub_out, server_out) = tokio::io::duplex(1 << 20);
        let sent = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(stub_server(stub_in, stub_out, script, sent.clone()));
        tokio::spawn(Arc::new(proxy).run(client_in, client_out, server_in, server_out));
        Self {
            to_proxy,
            from_proxy: BufReader::new(from_proxy).lines(),
            sent,
        }
    }

    /// Send one request and return the reply line exactly as relayed.
    async fn raw(&mut self, id: u64, method: &str, params: Value) -> String {
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.to_proxy
            .write_all(format!("{msg}\n").as_bytes())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(20), self.from_proxy.next_line())
            .await
            .expect("proxy reply")
            .unwrap()
            .expect("proxy closed")
    }

    async fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        let reply: Value = serde_json::from_str(&self.raw(id, method, params).await).unwrap();
        assert_eq!(reply["id"], id);
        reply
    }

    /// The last line the stub wrote.
    fn last_sent(&self) -> String {
        self.sent.lock().unwrap().last().cloned().unwrap()
    }
}

/// `tools/call` params for the new era: the revision in `_meta`.
fn new_era_call(tool: &str, arguments: Value) -> Value {
    json!({ "name": tool, "arguments": arguments,
            "_meta": { PROTOCOL_VERSION_META: NEW_ERA } })
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

async fn registry_ok() -> (MockServer, RegistryClient) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/contexts"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "ctx_id": CTX_ID,
            "lineage_id": "lin:sha256:53269327c5284c8d8389e5687a6604e81c64e81587e6518687cb41a7f3ea5647",
            "version": 1,
            "created_at": "2026-10-26T14:03:12.040Z",
            "status": "active"
        })))
        .mount(&server)
        .await;
    let client = RegistryClient::with_test_transport(&server.uri()).unwrap();
    (server, client)
}

/// The `metadata` (the record) of every body published so far.
async fn records(server: &MockServer) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| serde_json::from_slice::<Value>(&r.body).unwrap()["metadata"].clone())
        .collect()
}

/// A script answering `tools/call` with `result` and nothing else.
fn calls_return(result: Value) -> Script {
    Arc::new(move |m| (m["method"] == "tools/call").then(|| result.clone()))
}

#[tokio::test]
async fn mcp_008_a_revision_and_identity_from_meta() {
    let (reg, client) = registry_ok().await;
    let mut h = Harness::start(proxy(client), calls_return(new_era_result()));
    let reply = h
        .request(
            1,
            "tools/call",
            new_era_call("regional_fraud_rate", json!({})),
        )
        .await;
    assert_eq!(reply["result"]["_meta"][META_KEY]["ctx_id"], CTX_ID);
    let recs = records(&reg).await;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["mcp_protocol_version"], NEW_ERA);
    assert_eq!(recs[0]["server"]["name"], "fraud-stats");
    assert_eq!(recs[0]["server"]["version"], "1.4.2");
}

#[tokio::test]
async fn mcp_008_b_missing_identity_is_not_a_failure() {
    let (reg, client) = registry_ok().await;
    let mut h = Harness::start(proxy(client), calls_return(mcp_001_result()));
    let reply = h
        .request(
            1,
            "tools/call",
            new_era_call("regional_fraud_rate", json!({})),
        )
        .await;
    let link = &reply["result"]["_meta"][META_KEY];
    assert_eq!(link["ctx_id"], CTX_ID, "a link, not a failure value");
    assert!(link.get("failed").is_none());
    let recs = records(&reg).await;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["mcp_protocol_version"], NEW_ERA);
    assert_eq!(recs[0]["server"]["name"], "unknown");
    assert!(recs[0]["server"].get("version").is_none());
}

/// Discover answers with the given `ttlMs`; calls return no serverInfo.
fn discover_then_calls(ttl_ms: u64) -> Script {
    Arc::new(move |m| match m["method"].as_str() {
        Some("server/discover") => Some(json!({
            "supportedVersions": [NEW_ERA],
            SERVER_INFO_META: { "name": "fraud-stats", "version": "1.4.2" },
            "ttlMs": ttl_ms
        })),
        Some("tools/call") => Some(mcp_001_result()),
        _ => None,
    })
}

#[tokio::test]
async fn mcp_008_c_server_discover_fallback() {
    let (reg, client) = registry_ok().await;
    let mut h = Harness::start(proxy(client), discover_then_calls(60_000));
    h.request(1, "server/discover", json!({})).await;
    h.request(
        2,
        "tools/call",
        new_era_call("regional_fraud_rate", json!({})),
    )
    .await;
    let recs = records(&reg).await;
    assert_eq!(recs[0]["server"]["name"], "fraud-stats");
    assert_eq!(recs[0]["server"]["version"], "1.4.2");
}

#[tokio::test]
async fn mcp_008_c_expired_discover_is_not_used() {
    let (reg, client) = registry_ok().await;
    let mut h = Harness::start(proxy(client), discover_then_calls(0));
    h.request(1, "server/discover", json!({})).await;
    h.request(
        2,
        "tools/call",
        new_era_call("regional_fraud_rate", json!({})),
    )
    .await;
    assert_eq!(records(&reg).await[0]["server"]["name"], "unknown");
}

#[tokio::test]
async fn mcp_008_d_input_required_the_completing_request_is_the_call() {
    let (reg, client) = registry_ok().await;
    let script: Script = Arc::new(|m| {
        if m["method"] != "tools/call" {
            return None;
        }
        Some(if m["params"].get("inputResponses").is_some() {
            new_era_result()
        } else {
            json!({
                "resultType": "input_required",
                "inputRequests": { "confirm": { "method": "elicitation/create",
                    "params": { "message": "Which EU region?" } } },
                "requestState": "opaque-state-1"
            })
        })
    });
    let mut h = Harness::start(proxy(client), script);

    // Round 1: relayed byte for byte, nothing published, no link.
    let raw = h
        .raw(
            1,
            "tools/call",
            new_era_call("regional_fraud_rate", json!({ "region": "EU" })),
        )
        .await;
    assert_eq!(raw, h.last_sent(), "input_required relayed unchanged");
    assert!(!raw.contains(META_KEY));
    assert!(records(&reg).await.is_empty());

    // Round 2: its own call, hashed over its own arguments and id.
    let mut params = new_era_call("regional_fraud_rate", json!({ "region": "EU-West" }));
    params["inputResponses"] =
        json!({ "confirm": { "action": "accept", "content": { "region": "EU-West" } } });
    params["requestState"] = json!("opaque-state-1");
    let reply = h.request(2, "tools/call", params).await;
    let salt =
        Salt::from_base64url(reply["result"]["_meta"][META_KEY]["salt"].as_str().unwrap()).unwrap();
    let recs = records(&reg).await;
    assert_eq!(recs.len(), 1, "exactly one body");
    let rec = &recs[0];
    let h_args = |v: Value| record::call_hash(&v, Some(&salt));
    assert_eq!(
        rec["arguments_hash"],
        h_args(json!({ "region": "EU-West" }))
    );
    assert_eq!(rec["request_id_hash"], h_args(json!(2)));
    assert_ne!(rec["arguments_hash"], h_args(json!({ "region": "EU" })));
    assert_ne!(rec["request_id_hash"], h_args(json!(1)));
    // Neither inputResponses nor requestState is hashed into the record.
    let mut with_inputs = json!({ "region": "EU-West" });
    with_inputs["inputResponses"] = json!({ "confirm": { "action": "accept" } });
    assert_ne!(rec["arguments_hash"], h_args(with_inputs));
    assert!(!rec.to_string().contains("opaque-state-1"));
}

#[tokio::test]
async fn mcp_008_e_task_handle_and_completed_task_publish_nothing() {
    let (reg, client) = registry_ok().await;
    let script: Script = Arc::new(|m| match m["method"].as_str() {
        Some("tools/call") => Some(json!({
            "resultType": "task",
            "task": { "taskId": "task-7", "status": "working" }
        })),
        Some("tasks/get") => Some(json!({
            "taskId": "task-7",
            "status": "completed",
            "result": new_era_result()
        })),
        _ => None,
    });
    let mut h = Harness::start(proxy(client), script);
    let handle = h
        .raw(
            1,
            "tools/call",
            new_era_call("regional_fraud_rate", json!({})),
        )
        .await;
    assert_eq!(handle, h.last_sent(), "task handle relayed unchanged");

    // Not covered by this proxy: the completed result is relayed as is.
    for id in [2, 3] {
        let got = h.raw(id, "tasks/get", json!({ "taskId": "task-7" })).await;
        assert_eq!(got, h.last_sent());
        assert!(!got.contains(META_KEY));
    }
    assert!(records(&reg).await.is_empty());
}

async fn legacy_before_initialize(fail_closed: bool) -> Value {
    let (reg, client) = registry_ok().await;
    let mut p = proxy(client);
    p.default_policy.fail_closed = fail_closed;
    let mut h = Harness::start(p, calls_return(mcp_001_result()));
    // A legacy request (no revision in _meta) and no initialize exchanged.
    let reply = h
        .request(
            1,
            "tools/call",
            json!({ "name": "regional_fraud_rate", "arguments": {} }),
        )
        .await;
    assert!(records(&reg).await.is_empty());
    reply["result"].clone()
}

#[tokio::test]
async fn mcp_008_f_legacy_result_before_initialize_is_a_publish_failure() {
    let open = legacy_before_initialize(false).await;
    assert_eq!(open["_meta"][META_KEY], json!({ "failed": true }));
    assert_eq!(open["content"], mcp_001_result()["content"]);

    let closed = legacy_before_initialize(true).await;
    assert_eq!(closed["isError"], true);
    assert_eq!(closed["content"].as_array().unwrap().len(), 1);
    assert!(!closed.to_string().contains("EMEA"));
    assert_eq!(closed["_meta"][META_KEY], json!({ "failed": true }));
}

#[tokio::test]
async fn mcp_008_g_unknown_result_type_is_relayed_unchanged() {
    let (reg, client) = registry_ok().await;
    let mut odd = mcp_001_result();
    odd["resultType"] = json!("partial");
    let mut h = Harness::start(proxy(client), calls_return(odd));
    let raw = h
        .raw(
            1,
            "tools/call",
            new_era_call("regional_fraud_rate", json!({})),
        )
        .await;
    assert_eq!(raw, h.last_sent());
    assert!(!raw.contains(META_KEY));
    assert!(records(&reg).await.is_empty());
}

#[tokio::test]
async fn mcp_008_complete_result_type_is_published() {
    let (reg, client) = registry_ok().await;
    let mut done = new_era_result();
    done["resultType"] = json!("complete");
    let mut h = Harness::start(proxy(client), calls_return(done.clone()));
    let reply = h
        .request(
            1,
            "tools/call",
            new_era_call("regional_fraud_rate", json!({})),
        )
        .await;
    assert_eq!(reply["result"]["resultType"], "complete");
    let recs = records(&reg).await;
    assert_eq!(recs.len(), 1);
    // resultType is outside the hashed result (§4.3).
    let salt =
        Salt::from_base64url(reply["result"]["_meta"][META_KEY]["salt"].as_str().unwrap()).unwrap();
    let hashed = record::hashed_result(new_era_result().as_object().unwrap());
    assert_eq!(
        recs[0]["result_hash"],
        record::call_hash(&hashed, Some(&salt))
    );
}

#[tokio::test]
async fn mcp_008_h_era_classified_per_request() {
    let (reg, client) = registry_ok().await;
    let script: Script = Arc::new(|m| match m["method"].as_str() {
        Some("initialize") => Some(json!({
            "protocolVersion": "2025-11-25",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "fraud-stats-legacy", "version": "1.4.1" }
        })),
        Some("tools/call") => Some(
            if m["params"]["_meta"].get(PROTOCOL_VERSION_META).is_some() {
                new_era_result()
            } else {
                mcp_001_result()
            },
        ),
        _ => None,
    });
    let mut h = Harness::start(proxy(client), script);
    h.request(
        1,
        "initialize",
        json!({ "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": { "name": "test", "version": "0" } }),
    )
    .await;
    let legacy = h
        .request(
            2,
            "tools/call",
            json!({ "name": "regional_fraud_rate", "arguments": {} }),
        )
        .await;
    let current = h
        .request(
            3,
            "tools/call",
            new_era_call("regional_fraud_rate", json!({})),
        )
        .await;
    for r in [&legacy, &current] {
        assert_eq!(r["result"]["_meta"][META_KEY]["ctx_id"], CTX_ID);
    }
    let recs = records(&reg).await;
    assert_eq!(recs.len(), 2);
    let by_version = |v: &str| {
        recs.iter()
            .find(|r| r["mcp_protocol_version"] == v)
            .unwrap_or_else(|| panic!("no record for {v}"))
    };
    let old = by_version("2025-11-25");
    assert_eq!(old["server"]["name"], "fraud-stats-legacy");
    assert_eq!(old["server"]["version"], "1.4.1");
    let new = by_version(NEW_ERA);
    assert_eq!(new["server"]["name"], "fraud-stats");
    assert_eq!(new["server"]["version"], "1.4.2");
}

/// A new-era call on a fresh connection, with no initialize, is not a
/// publish failure even under fail-closed (H's second half).
#[tokio::test]
async fn mcp_008_h_new_era_call_needs_no_initialize() {
    let (reg, client) = registry_ok().await;
    let mut p = proxy(client);
    p.default_policy.fail_closed = true;
    let mut h = Harness::start(p, calls_return(new_era_result()));
    let reply = h
        .request(
            1,
            "tools/call",
            new_era_call("regional_fraud_rate", json!({})),
        )
        .await;
    assert_eq!(reply["result"]["_meta"][META_KEY]["ctx_id"], CTX_ID);
    assert_eq!(records(&reg).await.len(), 1);
}
