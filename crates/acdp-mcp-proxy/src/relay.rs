//! The newline-delimited JSON-RPC relay (MCP stdio framing).
//!
//! Every line is forwarded byte-for-byte, except the response to a
//! client `tools/call`, which is held until its record's publish has
//! succeeded or failed (§6: no link before the publish response) and
//! then re-serialized with `io.acdp/provenance` added to `_meta`.
//!
//! The era is classified per request (§3.1). A `tools/call` whose `_meta`
//! carries [`PROTOCOL_VERSION_META`] (MCP 2026-07-28 and later) takes its
//! revision from there and its server identity from the result's `_meta`,
//! a fresh `server/discover` response, or `unknown`. Any other request
//! uses what the upstream `initialize` result reported.
//!
//! Only a complete result is published (§3.2). An `input_required` result,
//! a task handle and an unknown `resultType` are relayed unchanged with no
//! body. Task-delivered results are **not covered**: a `tasks/get`
//! response is relayed unchanged and carries no link.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use acdp::{client::RegistryClient, producer::Producer};
use chrono::Utc;
use serde_json::{Map, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{mpsc, Mutex},
    task::JoinSet,
};

use crate::{
    provenance,
    record::{self, BodyOptions, Salt, ServerIdentity, ToolCall, Transport},
};

/// Per-tool policy.
#[derive(Debug, Clone, Default)]
pub struct ToolPolicy {
    /// Publish a record for this tool (the default).
    pub skip: bool,
    /// Withhold the result when publishing fails (§7). Default fail-open.
    pub fail_closed: bool,
    /// Body options, including the §5 embedding allowlist entry.
    pub body: BodyOptions,
}

/// Where external (over-cap, allowlisted) results are written so the
/// operator's web server can serve them at the DataRef location.
#[derive(Debug, Clone)]
pub struct ExternalStore {
    /// Directory that receives `<hex>.json`.
    pub dir: std::path::PathBuf,
}

/// Everything the relay needs besides the four byte streams.
pub struct Proxy {
    /// The operator's signing identity.
    pub producer: Producer,
    /// The registry the proxy publishes to.
    pub registry: RegistryClient,
    /// How the upstream server is reached.
    pub transport: Transport,
    /// [`record::endpoint_hash`] of the upstream descriptor.
    pub endpoint_hash: String,
    /// Policy for tools without an entry in `tools`.
    pub default_policy: ToolPolicy,
    /// Per-tool overrides.
    pub tools: HashMap<String, ToolPolicy>,
    /// Bound on one publish including retries (§7 publish timeout).
    pub publish_timeout: Duration,
    /// Publish attempts for transient failures, same Idempotency-Key.
    pub max_attempts: u32,
    /// Sink for external results, when configured.
    pub external: Option<ExternalStore>,
}

/// The request `_meta` key that marks an MCP revision without
/// `initialize` and names it (§3.1).
pub const PROTOCOL_VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";
/// The `_meta` key carrying the server's self-reported identity (§3.1).
pub const SERVER_INFO_META: &str = "io.modelcontextprotocol/serverInfo";

// One entry per in-flight request, and few are in flight: boxing the
// call would only add an allocation per `tools/call`.
#[allow(clippy::large_enum_variant)]
enum Pending {
    Initialize,
    Discover,
    Call {
        tool: String,
        arguments: Value,
        id: Value,
        started_at: chrono::DateTime<Utc>,
        /// `Some` when the request carried [`PROTOCOL_VERSION_META`].
        protocol_version: Option<String>,
    },
}

/// Server name and version as reported, before the proxy's own fields.
#[derive(Clone)]
struct Reported {
    name: String,
    version: Option<String>,
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Pending>,
    /// From the upstream `initialize` result (legacy requests).
    server: Option<ServerIdentity>,
    /// From the latest `server/discover` response, until it expires.
    discovered: Option<(Reported, Instant)>,
}

fn id_key(id: &Value) -> String {
    id.to_string()
}

impl Proxy {
    fn policy(&self, tool: &str) -> &ToolPolicy {
        self.tools.get(tool).unwrap_or(&self.default_policy)
    }

    /// Relay until the client closes its input and every in-flight
    /// result has been written.
    pub async fn run<CI, CO, SI, SO>(
        self: Arc<Self>,
        client_in: CI,
        client_out: CO,
        server_in: SI,
        server_out: SO,
    ) -> std::io::Result<()>
    where
        CI: AsyncRead + Unpin + Send + 'static,
        CO: AsyncWrite + Unpin + Send + 'static,
        SI: AsyncWrite + Unpin + Send + 'static,
        SO: AsyncRead + Unpin + Send + 'static,
    {
        let state = Arc::new(Mutex::new(State::default()));
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

        let writer = tokio::spawn(async move {
            let mut out = client_out;
            while let Some(line) = rx.recv().await {
                out.write_all(&line).await?;
                out.write_all(b"\n").await?;
                out.flush().await?;
            }
            out.shutdown().await
        });

        let upstream = {
            let state = state.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(client_in).lines();
                let mut sink = server_in;
                while let Some(line) = lines.next_line().await? {
                    if let Ok(msg) = serde_json::from_str::<Value>(&line) {
                        let mut st = state.lock().await;
                        for m in messages(&msg) {
                            note_request(&mut st, m);
                        }
                    }
                    sink.write_all(line.as_bytes()).await?;
                    sink.write_all(b"\n").await?;
                    sink.flush().await?;
                }
                sink.shutdown().await
            })
        };

        let mut inflight = JoinSet::new();
        let mut lines = BufReader::new(server_out).lines();
        while let Some(line) = lines.next_line().await? {
            let completed_at = Utc::now();
            let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                let _ = tx.send(line.into_bytes());
                continue;
            };
            let calls = {
                let mut st = state.lock().await;
                let mut calls = Vec::new();
                for (i, m) in messages(&msg).enumerate() {
                    if let Some(c) = note_response(&mut st, m, completed_at) {
                        calls.push((i, c));
                    }
                }
                calls
                    .into_iter()
                    .filter(|(_, (c, _))| !self.policy(&c.tool).skip)
                    .map(|(i, (c, server))| (i, c, server))
                    .collect::<Vec<_>>()
            };
            if calls.is_empty() {
                let _ = tx.send(line.into_bytes());
                continue;
            }
            let proxy = self.clone();
            let tx = tx.clone();
            inflight.spawn(async move {
                let mut msg = msg;
                for (i, call, server) in calls {
                    let slot = match &mut msg {
                        Value::Array(a) => &mut a[i],
                        v => v,
                    };
                    let result = proxy.provenance_for(call, server.as_ref()).await;
                    slot["result"] = Value::Object(result);
                }
                let _ = tx.send(serde_json::to_vec(&msg).unwrap_or_default());
            });
        }
        while inflight.join_next().await.is_some() {}
        drop(tx);
        // The client side may still be open; the session ends with the
        // server's output.
        upstream.abort();
        writer.await.map_err(std::io::Error::other)?
    }

    /// Publish the record for one call and return the result the client
    /// sees (§6–§7).
    async fn provenance_for(
        &self,
        call: ToolCall,
        server: Option<&ServerIdentity>,
    ) -> Map<String, Value> {
        let policy = self.policy(&call.tool);
        let outcome = match server {
            Some(server) => {
                let server = ServerIdentity {
                    transport: self.transport,
                    endpoint_hash: self.endpoint_hash.clone(),
                    ..server.clone()
                };
                self.publish(&server, &call, policy).await
            }
            // A legacy call before the initialize result: nothing to fill
            // the record with (§3.1).
            None => Err(None),
        };
        let mut result = call.result;
        match outcome {
            Ok(value) => {
                provenance::attach(&mut result, value);
                result
            }
            Err(code) => {
                let failure = provenance::failed(code.as_deref());
                if policy.fail_closed {
                    provenance::fail_closed_result(&call.tool, failure)
                } else {
                    provenance::attach(&mut result, failure);
                    result
                }
            }
        }
    }

    async fn publish(
        &self,
        server: &ServerIdentity,
        call: &ToolCall,
        policy: &ToolPolicy,
    ) -> Result<Value, Option<String>> {
        let prepared = record::prepare(&self.producer, server, call, &policy.body, Salt::random)
            .map_err(|e| {
                eprintln!("acdp-mcp-proxy: cannot build record for {}: {e}", call.tool);
                None
            })?;
        if let Some(ext) = &prepared.external {
            let store = self.external.as_ref().ok_or(None)?;
            let path = store.dir.join(format!("{}.json", ext.hex));
            tokio::fs::write(&path, &ext.bytes).await.map_err(|e| {
                eprintln!("acdp-mcp-proxy: cannot write {}: {e}", path.display());
                None
            })?;
        }
        let publish = self.registry.publish_with_retry(
            &prepared.request,
            &prepared.idempotency_key,
            self.max_attempts,
        );
        match tokio::time::timeout(self.publish_timeout, publish).await {
            Ok(Ok(resp)) => Ok(provenance::published(
                &resp.ctx_id,
                &prepared.request.content_hash,
                prepared.salt.as_ref(),
            )),
            Ok(Err(e)) => {
                eprintln!("acdp-mcp-proxy: publish failed for {}: {e}", call.tool);
                Err(provenance::registry_error_code(&e))
            }
            Err(_) => {
                eprintln!("acdp-mcp-proxy: publish timed out for {}", call.tool);
                Err(None)
            }
        }
    }
}

/// The messages of a line: the object itself, or a batch's elements.
fn messages(v: &Value) -> Box<dyn Iterator<Item = &Value> + '_> {
    match v {
        Value::Array(a) => Box::new(a.iter()),
        v => Box::new(std::iter::once(v)),
    }
}

/// Client → server: remember `initialize` and `tools/call` requests.
fn note_request(st: &mut State, m: &Value) {
    let (Some(method), Some(id)) = (m.get("method").and_then(Value::as_str), m.get("id")) else {
        return;
    };
    let pending = match method {
        "initialize" => Pending::Initialize,
        "server/discover" => Pending::Discover,
        "tools/call" => {
            let params = m.get("params");
            let Some(tool) = params.and_then(|p| p.get("name")).and_then(Value::as_str) else {
                return;
            };
            // A present key marks the era even when its value is unusable.
            let protocol_version = params
                .and_then(|p| p.get("_meta"))
                .and_then(|meta| meta.get(PROTOCOL_VERSION_META))
                .map(|v| v.as_str().unwrap_or("unknown").to_owned());
            Pending::Call {
                protocol_version,
                tool: tool.to_owned(),
                arguments: params
                    .and_then(|p| p.get("arguments"))
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Map::new())),
                id: id.clone(),
                started_at: Utc::now(),
            }
        }
        _ => return,
    };
    st.pending.insert(id_key(id), pending);
}

/// `serverInfo`-shaped object → name and version. A missing or unnamed
/// object yields `None`.
fn reported(info: Option<&Value>) -> Option<Reported> {
    let info = info?.as_object()?;
    let s = |k: &str| info.get(k).and_then(Value::as_str);
    Some(Reported {
        name: s("name")?.to_owned(),
        version: s("version").map(str::to_owned),
    })
}

fn identity(reported: Option<Reported>, protocol_version: String) -> ServerIdentity {
    let reported = reported.unwrap_or(Reported {
        name: "unknown".into(),
        version: None,
    });
    ServerIdentity {
        name: reported.name,
        version: reported.version,
        protocol_version,
        // Filled from the proxy's own configuration at publish.
        transport: Transport::Stdio,
        endpoint_hash: String::new(),
    }
}

/// Is this result the call's outcome (§3.2)? An absent `resultType` means
/// `complete`; `input_required`, `task` and any other value are not.
fn is_complete(result: &Map<String, Value>) -> bool {
    match result.get("resultType") {
        None => true,
        Some(v) => v.as_str() == Some("complete"),
    }
}

/// Server → client: learn the server at `initialize` or `server/discover`;
/// return the call to record, with the server identity for its era
/// (`None`: a legacy call before `initialize`), when `m` completes a
/// `tools/call`.
fn note_response(
    st: &mut State,
    m: &Value,
    completed_at: chrono::DateTime<Utc>,
) -> Option<(ToolCall, Option<ServerIdentity>)> {
    if m.get("method").is_some() {
        return None;
    }
    let pending = st.pending.remove(&id_key(m.get("id")?))?;
    let result = m.get("result")?.as_object()?;
    match pending {
        Pending::Initialize => {
            st.server = Some(identity(
                reported(result.get("serverInfo")),
                result
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
            ));
            None
        }
        Pending::Discover => {
            // The identity may sit at the top level or in `_meta`; without
            // a `ttlMs` the response is not reused.
            let info = result.get(SERVER_INFO_META).or_else(|| {
                result
                    .get("_meta")
                    .and_then(|meta| meta.get(SERVER_INFO_META))
            });
            let ttl = result.get("ttlMs").and_then(Value::as_u64);
            if let (Some(r), Some(ttl)) = (reported(info), ttl) {
                st.discovered = Some((r, Instant::now() + Duration::from_millis(ttl)));
            }
            None
        }
        Pending::Call {
            tool,
            arguments,
            id,
            started_at,
            protocol_version,
        } => {
            if !is_complete(result) {
                // Relayed unchanged; the call that completes is its own
                // request, with its own arguments and id.
                return None;
            }
            let server = match protocol_version {
                Some(pv) => {
                    let from_result = reported(
                        result
                            .get("_meta")
                            .and_then(|meta| meta.get(SERVER_INFO_META)),
                    );
                    let from_discover = || {
                        st.discovered
                            .as_ref()
                            .filter(|(_, expires)| Instant::now() < *expires)
                            .map(|(r, _)| r.clone())
                    };
                    Some(identity(from_result.or_else(from_discover), pv))
                }
                None => st.server.clone(),
            };
            Some((
                ToolCall {
                    tool,
                    arguments,
                    request_id: Some(id),
                    result: result.clone(),
                    started_at,
                    completed_at,
                },
                server,
            ))
        }
    }
}
