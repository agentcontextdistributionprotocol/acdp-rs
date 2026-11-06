//! Completion and assembly (RFC-ACDP-0022 §4.2–§4.3). Pure: no I/O, no
//! clock.
//!
//! A [`TaskAssembly`] follows one task's artifacts, keyed by
//! `artifactId` (A2A v1.0.1 Artifacts carry no role, so the
//! `(artifact_id, role)` key is the id alone). It assembles each
//! artifact from its `TaskArtifactUpdateEvent` chunks in emission order
//! and says when one completes: at the chunk with `lastChunk` true, or
//! when the task enters a terminal state while the artifact is present
//! and not yet complete. Further chunks for a completed key reopen it
//! (re-emission, §4.3); completing it again is a new completion.

use serde_json::{Map, Value};

use crate::{
    link::LINK_KEY,
    parts::{normalize_part, normalize_parts, PartError},
};

/// `TaskState` values that complete every present, incomplete artifact.
pub const TERMINAL_STATES: [&str; 4] = [
    "TASK_STATE_COMPLETED",
    "TASK_STATE_FAILED",
    "TASK_STATE_CANCELED",
    "TASK_STATE_REJECTED",
];

/// Interrupted states: they complete nothing.
pub const INTERRUPTED_STATES: [&str; 2] = ["TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED"];

/// The A2A role an agent's own artifact carries under a revision with
/// `Artifact.role` (A2A #2411).
pub const ROLE_AGENT: &str = "ROLE_AGENT";
/// A client-written artifact: never published (§4.2).
pub const ROLE_USER: &str = "ROLE_USER";
/// Read as [`ROLE_AGENT`] (§5.1).
pub const ROLE_UNSPECIFIED: &str = "ROLE_UNSPECIFIED";

/// Whether `state` is one of [`TERMINAL_STATES`].
pub fn is_terminal(state: &str) -> bool {
    TERMINAL_STATES.contains(&state)
}

/// An artifact as assembled so far.
#[derive(Debug, Clone, PartialEq)]
pub struct AssembledArtifact {
    /// `artifactId`.
    pub artifact_id: String,
    /// `Artifact.role` as last received, when the A2A revision carries it.
    pub role: Option<String>,
    /// `name` of the last chunk that carried one.
    pub name: Option<String>,
    /// `description` of the last chunk that carried one.
    pub description: Option<String>,
    /// The assembled parts, each in §5.1 A2A JSON form.
    pub parts: Vec<Value>,
    /// `Artifact.metadata` of the last chunk that carried it, without the
    /// link key. Not hashed (§4.4).
    pub metadata: Option<Map<String, Value>>,
}

impl AssembledArtifact {
    fn new(artifact_id: String) -> Self {
        Self {
            artifact_id,
            role: None,
            name: None,
            description: None,
            parts: Vec::new(),
            metadata: None,
        }
    }

    /// Whether the record carries `role` (§4.2): only when the artifact
    /// itself carries `ROLE_AGENT`.
    pub fn record_role(&self) -> Option<&str> {
        (self.role.as_deref() == Some(ROLE_AGENT)).then_some(ROLE_AGENT)
    }

    /// A client-written artifact (`ROLE_USER`), which the agent never
    /// publishes (§4.2).
    pub fn is_client_written(&self) -> bool {
        self.role.as_deref() == Some(ROLE_USER)
    }

    /// The artifact as a `Task.artifacts` snapshot entry: the assembled
    /// parts, the labels and the metadata, with `link` added under
    /// `io.acdp/provenance` when given (§6).
    pub fn to_snapshot(&self, link: Option<&Value>) -> Value {
        let mut a = Map::new();
        a.insert("artifactId".into(), self.artifact_id.clone().into());
        if let Some(n) = &self.name {
            a.insert("name".into(), n.clone().into());
        }
        if let Some(d) = &self.description {
            a.insert("description".into(), d.clone().into());
        }
        a.insert("parts".into(), Value::Array(self.parts.clone()));
        let mut meta = self.metadata.clone().unwrap_or_default();
        if let Some(l) = link {
            meta.insert(LINK_KEY.into(), l.clone());
        }
        if !meta.is_empty() || self.metadata.is_some() {
            a.insert("metadata".into(), Value::Object(meta));
        }
        if let Some(r) = &self.role {
            a.insert("role".into(), r.clone().into());
        }
        Value::Object(a)
    }
}

/// What one chunk did to its artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkEffect {
    /// Assembled; not complete yet.
    Pending,
    /// The chunk completed the artifact (`lastChunk` true).
    Completed,
}

#[derive(Debug, Clone)]
struct Entry {
    art: AssembledArtifact,
    complete: bool,
}

/// One task's artifacts (§4.2).
#[derive(Debug, Clone)]
pub struct TaskAssembly {
    task_id: String,
    context_id: String,
    entries: Vec<Entry>,
}

fn str_member(o: &Map<String, Value>, k: &str) -> Result<Option<String>, PartError> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(PartError(format!("{k} is not a string"))),
    }
}

fn own_metadata(o: &Map<String, Value>) -> Result<Option<Map<String, Value>>, PartError> {
    match o.get("metadata") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(m)) => {
            let mut m = m.clone();
            m.remove(LINK_KEY);
            Ok(Some(m))
        }
        Some(_) => Err(PartError("Artifact.metadata is not an object".into())),
    }
}

impl TaskAssembly {
    /// Follow the task `task_id` in the context `context_id`.
    pub fn new(task_id: impl Into<String>, context_id: impl Into<String>) -> Self {
        Self {
            task_id: task_id.into(),
            context_id: context_id.into(),
            entries: Vec::new(),
        }
    }

    /// The task's `id`.
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    /// The task's `contextId`.
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    fn entry_mut(&mut self, id: &str) -> &mut Entry {
        let i = match self.entries.iter().position(|e| e.art.artifact_id == id) {
            Some(i) => i,
            None => {
                self.entries.push(Entry {
                    art: AssembledArtifact::new(id.to_owned()),
                    complete: false,
                });
                self.entries.len() - 1
            }
        };
        &mut self.entries[i]
    }

    /// Assemble one `TaskArtifactUpdateEvent` in A2A JSON (§4.2).
    ///
    /// `append` false or absent replaces the parts so far; `append` true
    /// extends them; `name` and `description` are the last ones carried.
    /// A chunk for a completed artifact reopens it (§4.3).
    pub fn ingest_chunk(&mut self, chunk: &Value) -> Result<ChunkEffect, PartError> {
        let c = chunk
            .as_object()
            .ok_or_else(|| PartError("a chunk is not an object".into()))?;
        if let Some(t) = str_member(c, "taskId")? {
            if t != self.task_id {
                return Err(PartError(format!(
                    "chunk taskId {t} is not this task's {}",
                    self.task_id
                )));
            }
        }
        let a = c
            .get("artifact")
            .and_then(Value::as_object)
            .ok_or_else(|| PartError("chunk has no artifact object".into()))?;
        let id = str_member(a, "artifactId")?
            .ok_or_else(|| PartError("artifact has no artifactId".into()))?;
        let parts = match a.get("parts") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(p)) => normalize_parts(p)?,
            Some(_) => return Err(PartError("parts is not an array".into())),
        };
        let name = str_member(a, "name")?;
        let description = str_member(a, "description")?;
        let role = str_member(a, "role")?;
        let metadata = own_metadata(a)?;
        let append = c.get("append").and_then(Value::as_bool).unwrap_or(false);
        let last = c.get("lastChunk").and_then(Value::as_bool).unwrap_or(false);

        let e = self.entry_mut(&id);
        e.complete = false;
        if append {
            e.art.parts.extend(parts);
        } else {
            e.art.parts = parts;
        }
        if name.is_some() {
            e.art.name = name;
        }
        if description.is_some() {
            e.art.description = description;
        }
        if role.is_some() {
            e.art.role = role;
        }
        if metadata.is_some() {
            e.art.metadata = metadata;
        }
        if last {
            e.complete = true;
            Ok(ChunkEffect::Completed)
        } else {
            Ok(ChunkEffect::Pending)
        }
    }

    /// Note a Task snapshot (A2A JSON `Task`). Artifacts never streamed
    /// are adopted from it. When `status.state` is terminal, every
    /// present artifact not yet complete completes now (§4.2 case 2);
    /// their ids are returned in snapshot order.
    pub fn ingest_task(&mut self, task: &Value) -> Result<Vec<String>, PartError> {
        let state = task
            .pointer("/status/state")
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut present = Vec::new();
        for a in task
            .get("artifacts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let o = a
                .as_object()
                .ok_or_else(|| PartError("a Task artifact is not an object".into()))?;
            let id = str_member(o, "artifactId")?
                .ok_or_else(|| PartError("artifact has no artifactId".into()))?;
            if !self.entries.iter().any(|e| e.art.artifact_id == id) {
                let mut art = AssembledArtifact::new(id.clone());
                art.parts = match o.get("parts") {
                    Some(Value::Array(p)) => {
                        p.iter().map(normalize_part).collect::<Result<_, _>>()?
                    }
                    None | Some(Value::Null) => Vec::new(),
                    Some(_) => return Err(PartError("parts is not an array".into())),
                };
                art.name = str_member(o, "name")?;
                art.description = str_member(o, "description")?;
                art.role = str_member(o, "role")?;
                art.metadata = own_metadata(o)?;
                self.entries.push(Entry {
                    art,
                    complete: false,
                });
            }
            present.push(id);
        }
        if !is_terminal(state) {
            return Ok(Vec::new());
        }
        let mut done = Vec::new();
        for id in present {
            let e = self.entry_mut(&id);
            if !e.complete {
                e.complete = true;
                done.push(id);
            }
        }
        Ok(done)
    }

    /// The artifact as assembled so far.
    pub fn artifact(&self, artifact_id: &str) -> Option<&AssembledArtifact> {
        self.entries
            .iter()
            .find(|e| e.art.artifact_id == artifact_id)
            .map(|e| &e.art)
    }

    /// Whether the artifact is complete (and not reopened since).
    pub fn is_complete(&self, artifact_id: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.art.artifact_id == artifact_id && e.complete)
    }

    /// Every artifact, in first-seen order.
    pub fn artifacts(&self) -> impl Iterator<Item = &AssembledArtifact> {
        self.entries.iter().map(|e| &e.art)
    }
}
