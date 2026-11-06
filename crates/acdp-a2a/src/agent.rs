//! The agent side end to end (RFC-ACDP-0022 §4–§7): a [`TaskSession`]
//! per task, and an [`Agent`] that publishes each completed artifact and
//! returns the chunk or snapshot to emit.
//!
//! The agent hands every `TaskArtifactUpdateEvent` it is about to emit
//! to [`Agent::on_chunk`], and every `Task` snapshot to
//! [`Agent::on_task`], and emits what comes back. The completing chunk is
//! returned only after the publish has settled, so a link only ever
//! names a published body (§6 "publish before the final chunk").

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use acdp::{
    client::{CrossRegistryResolver, RegistryClient},
    producer::Producer,
    types::{primitives::ContentHash, CtxId},
    AcdpError,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{
    assembly::{ChunkEffect, TaskAssembly},
    hash::Salt,
    inputs,
    link::{self, LINK_KEY},
    parts::PartError,
    record::{self, BodyTemplate, Completion, Embedding, PreviousBody, UrlContent},
};

/// How one artifact is published.
#[derive(Debug, Clone)]
pub struct ArtifactPolicy {
    /// The agent's own body fields.
    pub template: BodyTemplate,
    /// §5.3 embedding allowlist entry (default: never embed).
    pub embedding: Embedding,
    /// §6.2: withhold the artifact when publishing fails. Default
    /// fail-open.
    pub fail_closed: bool,
    /// §5.4: map `url` parts to `data_refs` (default true).
    pub map_url_parts: bool,
    /// Publish no body for this artifact.
    pub skip: bool,
}

impl ArtifactPolicy {
    /// Fail-open, unembedded, `url` parts mapped.
    pub fn new(template: BodyTemplate) -> Self {
        Self {
            template,
            embedding: Embedding::Never,
            fail_closed: false,
            map_url_parts: true,
            skip: false,
        }
    }
}

/// Per-artifact facts only the agent knows.
#[derive(Debug, Clone, Default)]
pub struct ArtifactHints {
    /// §4.3: the earlier task's body this artifact continues; it comes
    /// first in `derived_from`.
    pub continues: Option<CtxId>,
    /// §7 step 4: the verified inputs this artifact used. `None` keeps
    /// every verified cited input.
    pub used_inputs: Option<Vec<CtxId>>,
    /// §7 step 6: contexts the agent retrieved and used on its own.
    pub own_inputs: Vec<CtxId>,
    /// Relayed unchanged from another agent: never published (§4.2).
    pub relayed: bool,
    /// The A2A #1140 hash, for the `a2a.artifact` anchor (§10).
    pub a2a_artifact_hash: Option<ContentHash>,
    /// Overrides the agent's policy for this artifact.
    pub policy: Option<ArtifactPolicy>,
}

/// One task as the agent publishes it.
#[derive(Debug, Clone)]
pub struct TaskSession {
    assembly: TaskAssembly,
    cited: Vec<CtxId>,
    verified: HashSet<CtxId>,
    checked: HashSet<CtxId>,
    hints: HashMap<String, ArtifactHints>,
    url_contents: HashMap<String, UrlContent>,
    published: HashMap<String, PreviousBody>,
    links: HashMap<String, Value>,
    withheld: HashSet<String>,
}

impl TaskSession {
    /// The task `task_id` in the context `context_id`.
    pub fn new(task_id: impl Into<String>, context_id: impl Into<String>) -> Self {
        Self {
            assembly: TaskAssembly::new(task_id, context_id),
            cited: Vec::new(),
            verified: HashSet::new(),
            checked: HashSet::new(),
            hints: HashMap::new(),
            url_contents: HashMap::new(),
            published: HashMap::new(),
            links: HashMap::new(),
            withheld: HashSet::new(),
        }
    }

    /// Note a client message (A2A JSON `Message`) received before
    /// completion: its `io.acdp/inputs`, if valid, are cited (§7).
    pub fn observe_client_message(&mut self, message: &Value) {
        for id in inputs::cited_inputs([message]) {
            if !self.cited.contains(&id) {
                self.cited.push(id);
            }
        }
    }

    /// Record inputs the agent verified itself (RFC-ACDP-0001 §5.11).
    /// Without an input resolver on the [`Agent`], only these count.
    pub fn mark_inputs_verified(&mut self, ids: impl IntoIterator<Item = CtxId>) {
        for id in ids {
            self.checked.insert(id.clone());
            self.verified.insert(id);
        }
    }

    /// The facts the agent knows about one artifact.
    pub fn hints_mut(&mut self, artifact_id: &str) -> &mut ArtifactHints {
        self.hints.entry(artifact_id.to_owned()).or_default()
    }

    /// The bytes the agent serves at a `url` part's URL (§5.4).
    pub fn know_url_content(&mut self, url: impl Into<String>, bytes: &[u8]) {
        self.url_contents.insert(url.into(), UrlContent::of(bytes));
    }

    /// The cited inputs so far, in §7 order.
    pub fn cited_inputs(&self) -> &[CtxId] {
        &self.cited
    }

    /// The assembled artifacts.
    pub fn assembly(&self) -> &TaskAssembly {
        &self.assembly
    }

    /// The current link (published or failed) of a completed artifact.
    pub fn link(&self, artifact_id: &str) -> Option<&Value> {
        self.links.get(artifact_id)
    }

    /// The last body published for a key, which a re-emission supersedes.
    pub fn published(&self, artifact_id: &str) -> Option<&PreviousBody> {
        self.published.get(artifact_id)
    }

    /// Whether a fail-closed artifact is being withheld.
    pub fn is_withheld(&self, artifact_id: &str) -> bool {
        self.withheld.contains(artifact_id)
    }

    /// §7 `derived_from` for one artifact, from what the session knows.
    pub fn derived_from(&self, artifact_id: &str) -> Vec<CtxId> {
        let h = self.hints.get(artifact_id);
        let used = h.and_then(|h| h.used_inputs.as_ref());
        inputs::derived_from(
            h.and_then(|h| h.continues.as_ref()),
            &self.cited,
            |c| self.verified.contains(c) && used.is_none_or(|u| u.contains(c)),
            h.map(|h| h.own_inputs.as_slice()).unwrap_or(&[]),
        )
    }
}

/// What to emit for one chunk.
#[derive(Debug, Clone, PartialEq)]
pub enum ChunkOutput {
    /// Emit this chunk (with the link added when it completed the artifact).
    Emit(Value),
    /// Fail-closed (§6.2): do not emit the artifact. The agent MAY end
    /// the task `TASK_STATE_FAILED` with a status message naming this.
    Withhold {
        /// The withheld artifact.
        artifact_id: String,
        /// The `{failed: true, error?}` value describing the failure.
        failure: Value,
    },
}

/// What to emit for one Task snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskOutput {
    /// The snapshot, completed artifacts carrying their links and
    /// fail-closed artifacts removed.
    pub task: Value,
    /// Fail-closed artifacts removed from it, with their failure values.
    pub withheld: Vec<(String, Value)>,
}

enum Outcome {
    Linked(Value),
    Skipped,
    Withheld(Value),
}

type SaltSource = Arc<dyn Fn() -> Result<Salt, AcdpError> + Send + Sync>;
type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// An A2A server agent that publishes its completed artifacts (profile
/// `acdp-producer-a2a`).
pub struct Agent {
    producer: Producer,
    registry: RegistryClient,
    a2a_protocol_version: String,
    default_policy: ArtifactPolicy,
    by_name: HashMap<String, ArtifactPolicy>,
    publish_timeout: Duration,
    max_attempts: u32,
    external_dir: Option<PathBuf>,
    input_resolver: Option<CrossRegistryResolver>,
    salt_source: SaltSource,
    clock: Clock,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("a2a_protocol_version", &self.a2a_protocol_version)
            .field("publish_timeout", &self.publish_timeout)
            .field("max_attempts", &self.max_attempts)
            .finish_non_exhaustive()
    }
}

impl Agent {
    /// An agent signing as `producer`, publishing to `registry`, serving
    /// A2A `a2a_protocol_version` (the `AgentInterface.protocolVersion`).
    /// Defaults: 30 s publish timeout, 3 attempts, CSPRNG salts.
    pub fn new(
        producer: Producer,
        registry: RegistryClient,
        a2a_protocol_version: impl Into<String>,
        default_policy: ArtifactPolicy,
    ) -> Self {
        Self {
            producer,
            registry,
            a2a_protocol_version: a2a_protocol_version.into(),
            default_policy,
            by_name: HashMap::new(),
            publish_timeout: Duration::from_secs(30),
            max_attempts: 3,
            external_dir: None,
            input_resolver: None,
            salt_source: Arc::new(Salt::random),
            clock: Arc::new(Utc::now),
        }
    }

    /// Policy for artifacts with this `name` (e.g. an embedding allowlist).
    pub fn with_policy(mut self, artifact_name: impl Into<String>, p: ArtifactPolicy) -> Self {
        self.by_name.insert(artifact_name.into(), p);
        self
    }

    /// Bound on one publish including its retries (§6.2).
    pub fn with_publish_timeout(mut self, t: Duration) -> Self {
        self.publish_timeout = t;
        self
    }

    /// Publish attempts for transient failures, same Idempotency-Key.
    pub fn with_max_attempts(mut self, n: u32) -> Self {
        self.max_attempts = n.max(1);
        self
    }

    /// Directory receiving `<hex>.json` for over-cap embedded parts
    /// (§5.3), which the agent's web server serves at the external base.
    pub fn with_external_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.external_dir = Some(dir.into());
        self
    }

    /// Verify cited inputs through this resolver (§7 step 3) before
    /// they enter `derived_from`.
    pub fn with_input_resolver(mut self, r: CrossRegistryResolver) -> Self {
        self.input_resolver = Some(r);
        self
    }

    /// Replace the salt source (known-answer tests only; production
    /// salts MUST come from a CSPRNG, §5.2).
    pub fn with_salt_source(
        mut self,
        f: impl Fn() -> Result<Salt, AcdpError> + Send + Sync + 'static,
    ) -> Self {
        self.salt_source = Arc::new(f);
        self
    }

    /// Replace the completion clock (known-answer tests).
    pub fn with_clock(mut self, f: impl Fn() -> DateTime<Utc> + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(f);
        self
    }

    /// Hand the agent a chunk it is about to emit. Returns what to emit:
    /// the chunk unchanged unless it completed the artifact, in which case
    /// the publish has settled and the link is on `artifact.metadata`.
    pub async fn on_chunk(
        &self,
        s: &mut TaskSession,
        mut chunk: Value,
    ) -> Result<ChunkOutput, PartError> {
        if s.assembly.ingest_chunk(&chunk)? == ChunkEffect::Pending {
            return Ok(ChunkOutput::Emit(chunk));
        }
        let id = chunk["artifact"]["artifactId"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        Ok(match self.complete(s, &id).await {
            Outcome::Skipped => ChunkOutput::Emit(chunk),
            Outcome::Linked(l) => {
                link::attach(&mut chunk["artifact"], l);
                ChunkOutput::Emit(chunk)
            }
            Outcome::Withheld(failure) => ChunkOutput::Withhold {
                artifact_id: id,
                failure,
            },
        })
    }

    /// Hand the agent a Task snapshot it is about to emit. A terminal
    /// state completes (and publishes) every present, incomplete
    /// artifact first. Every completed artifact then carries its
    /// assembled parts and its link; fail-closed ones are removed.
    pub async fn on_task(
        &self,
        s: &mut TaskSession,
        mut task: Value,
    ) -> Result<TaskOutput, PartError> {
        for id in s.assembly.ingest_task(&task)? {
            let _ = self.complete(s, &id).await;
        }
        let mut withheld = Vec::new();
        if let Some(arts) = task.get_mut("artifacts").and_then(Value::as_array_mut) {
            arts.retain(|a| {
                let id = a.get("artifactId").and_then(Value::as_str).unwrap_or("");
                if s.withheld.contains(id) {
                    withheld.push((id.to_owned(), link::failed(None)));
                    false
                } else {
                    true
                }
            });
            for a in arts.iter_mut() {
                let Some(id) = a
                    .get("artifactId")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                else {
                    continue;
                };
                if !s.assembly.is_complete(&id) {
                    continue;
                }
                let (Some(l), Some(art)) = (s.links.get(&id), s.assembly.artifact(&id)) else {
                    continue;
                };
                a["parts"] = Value::Array(art.parts.clone());
                link::attach(a, l.clone());
            }
        }
        for (id, f) in &mut withheld {
            if let Some(v) = s.links.get(id.as_str()) {
                *f = v.clone();
            }
        }
        Ok(TaskOutput { task, withheld })
    }

    fn policy_for<'a>(&'a self, s: &'a TaskSession, id: &str) -> &'a ArtifactPolicy {
        if let Some(p) = s.hints.get(id).and_then(|h| h.policy.as_ref()) {
            return p;
        }
        s.assembly
            .artifact(id)
            .and_then(|a| a.name.as_ref())
            .and_then(|n| self.by_name.get(n))
            .unwrap_or(&self.default_policy)
    }

    async fn complete(&self, s: &mut TaskSession, id: &str) -> Outcome {
        let Some(art) = s.assembly.artifact(id).cloned() else {
            return Outcome::Skipped;
        };
        let hints = s.hints.get(id).cloned().unwrap_or_default();
        if hints.relayed || art.is_client_written() {
            return Outcome::Skipped;
        }
        let policy = self.policy_for(s, id).clone();
        if policy.skip {
            return Outcome::Skipped;
        }
        if let Some(r) = &self.input_resolver {
            let pending: Vec<CtxId> = s
                .cited
                .iter()
                .filter(|c| !s.checked.contains(*c))
                .cloned()
                .collect();
            let ok = inputs::verify_inputs(r, &pending).await;
            s.checked.extend(pending);
            s.verified.extend(ok);
        }
        let completion = Completion {
            a2a_protocol_version: &self.a2a_protocol_version,
            task_id: s.assembly.task_id(),
            context_id: s.assembly.context_id(),
            artifact: &art,
            completed_at: (self.clock)(),
            derived_from: s.derived_from(id),
            previous: s.published.get(id),
            map_url_parts: policy.map_url_parts,
            url_contents: &s.url_contents,
            a2a_artifact_hash: hints.a2a_artifact_hash.clone(),
        };
        let result = self.publish(&completion, &policy).await;
        match result {
            Ok((link, prev)) => {
                s.published.insert(id.to_owned(), prev);
                s.links.insert(id.to_owned(), link.clone());
                s.withheld.remove(id);
                Outcome::Linked(link)
            }
            Err(code) => {
                let failure = link::failed(code.as_deref());
                s.links.insert(id.to_owned(), failure.clone());
                if policy.fail_closed {
                    s.withheld.insert(id.to_owned());
                    Outcome::Withheld(failure)
                } else {
                    s.withheld.remove(id);
                    Outcome::Linked(failure)
                }
            }
        }
    }

    async fn publish(
        &self,
        c: &Completion<'_>,
        policy: &ArtifactPolicy,
    ) -> Result<(Value, PreviousBody), Option<String>> {
        let prepared = record::prepare(
            &self.producer,
            c,
            &policy.template,
            &policy.embedding,
            || (self.salt_source)(),
        )
        .map_err(|_| None)?;
        if let Some(ext) = &prepared.external {
            let dir = self.external_dir.as_ref().ok_or(None)?;
            tokio::fs::write(dir.join(format!("{}.json", ext.hex)), &ext.bytes)
                .await
                .map_err(|_| None)?;
        }
        let publish = self.registry.publish_with_retry(
            &prepared.request,
            &prepared.idempotency_key,
            self.max_attempts,
        );
        match tokio::time::timeout(self.publish_timeout, publish).await {
            Ok(Ok(resp)) => Ok((
                prepared.link(&resp.ctx_id),
                PreviousBody {
                    ctx_id: resp.ctx_id,
                    lineage_id: resp.lineage_id,
                    version: resp.version,
                },
            )),
            Ok(Err(e)) => Err(link::registry_error_code(&e)),
            Err(_) => Err(None),
        }
    }
}

/// Remove the link key from an artifact's metadata (for an agent that
/// re-serializes its own state); every other key is kept.
pub fn strip_link(artifact: &mut Value) {
    if let Some(m) = artifact.get_mut("metadata").and_then(Value::as_object_mut) {
        m.remove(LINK_KEY);
    }
}
