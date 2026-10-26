//! The newline-delimited JSON-RPC relay (MCP stdio framing).
//!
//! Every line is forwarded byte-for-byte, except the response to a
//! client `tools/call`, which is held until its record's publish has
//! succeeded or failed (§6: no link before the publish response) and
//! then re-serialized with `io.acdp/provenance` added to `_meta`.

use std::{collections::HashMap, sync::Arc, time::Duration};

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

enum Pending {
    Initialize,
    Call {
        tool: String,
        arguments: Value,
        id: Value,
        started_at: chrono::DateTime<Utc>,
    },
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Pending>,
    server: Option<ServerIdentity>,
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
                    .filter(|(_, c)| !self.policy(&c.tool).skip)
                    .map(|(i, c)| (i, c, st.server.clone()))
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
            // No initialize result seen: nothing to fill the record with.
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
        "tools/call" => {
            let params = m.get("params");
            let Some(tool) = params.and_then(|p| p.get("name")).and_then(Value::as_str) else {
                return;
            };
            Pending::Call {
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

/// Server → client: learn the server at `initialize`; return the call
/// to record when `m` is a successful `tools/call` response.
fn note_response(
    st: &mut State,
    m: &Value,
    completed_at: chrono::DateTime<Utc>,
) -> Option<ToolCall> {
    if m.get("method").is_some() {
        return None;
    }
    let pending = st.pending.remove(&id_key(m.get("id")?))?;
    let result = m.get("result")?.as_object()?;
    match pending {
        Pending::Initialize => {
            let info = result.get("serverInfo");
            let s = |k: &str| info.and_then(|i| i.get(k)).and_then(Value::as_str);
            st.server = Some(ServerIdentity {
                name: s("name").unwrap_or("unknown").to_owned(),
                version: s("version").map(str::to_owned),
                protocol_version: result
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                // Filled from the proxy's own configuration at publish.
                transport: Transport::Stdio,
                endpoint_hash: String::new(),
            });
            None
        }
        Pending::Call {
            tool,
            arguments,
            id,
            started_at,
        } => Some(ToolCall {
            tool,
            arguments,
            request_id: Some(id),
            result: result.clone(),
            started_at,
            completed_at,
        }),
    }
}
