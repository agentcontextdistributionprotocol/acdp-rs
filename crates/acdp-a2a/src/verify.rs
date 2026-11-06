//! Verification by a holder (RFC-ACDP-0022 §8).
//!
//! A holder with an A2A artifact and its `io.acdp/provenance` link:
//!
//! 1. **Body** — retrieves and verifies the body (RFC-ACDP-0001 §5.11)
//!    and binds it to the link (`ctx_id`, `registry`, `content_hash`);
//! 2. **Agent and record** — `agent_id` is trusted, equals the Card's
//!    `params.agentId` when the Card was used, encodes the Card's AITP
//!    AID when `agent_id` is a `did:key`; the closed record is valid;
//! 3. **Salt** — canonical encoding only, always present;
//! 4. **Artifact** — `parts_hash`, `artifact_id_hash`, labels and role
//!    recomputed from the held artifact;
//! 5. **Task** — `task_id_hash` / `context_id_hash`, when the ids are known;
//! 6. **Status** — reported, never decided here.
//!
//! The outcome is a local verdict with no wire code (§14). A
//! [`VerifyFailure`] names the step and a stable [`FailureKind::code`],
//! and [`VerifyFailure::is_unrecognised`] separates an untrusted or
//! unrecognised record (steps 1–3) from one that does not match the held
//! artifact (steps 4–5).
//!
//! Entry points: [`verify_with_context`] over a
//! [`VerifiedContext`] (the
//! resolver-verified path, which also reports status), [`resolve_and_verify`]
//! and [`fetch_and_verify`] (retrieve then verify), and [`verify_offline`]
//! for a `did:key` agent's body as received. [`verify_against_body`] is the
//! shared core and takes a body the caller has **already** verified.

use acdp::{
    client::{CrossRegistryResolver, RegistryClient, VerificationPolicy, VerifiedContext},
    did::WebResolver,
    types::{
        primitives::{AgentDid, Status},
        Body, CtxId,
    },
};
use serde_json::{Map, Value};

use crate::{
    assembly::{ROLE_AGENT, ROLE_UNSPECIFIED},
    card::{aid_matches_did_key, aitp_aids, card_pointer, CardParams},
    hash::{self, Salt},
    link::link_of,
    parts::normalize_parts,
    record::{record_description, record_name, RECORD_KEY, RECORD_VERSION},
};

/// What failed, with a stable snake_case [`code`](Self::code).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FailureKind {
    /// Step 1: the link is `{failed: true}` and names no body.
    FailedLink,
    /// Step 1: the link is not a published-link object.
    LinkInvalid,
    /// Step 1: the body could not be retrieved or does not verify.
    BodyUnverified,
    /// Step 1: the body's `ctx_id`, `origin_registry` or `content_hash`
    /// differs from the link's.
    LinkMismatch,
    /// Step 2: `agent_id` is not an agent the holder trusts.
    UntrustedAgent,
    /// Step 2: `agent_id` differs from the Card's `params.agentId`.
    CardMismatch,
    /// Step 2: a `did:key` `agent_id` does not encode the Card's AITP AID.
    AidMismatch,
    /// Step 2: no valid `acdp-a2a-artifact/1` record at `metadata["acdp:a2a"]`.
    RecordInvalid,
    /// Step 3: the link's salt is absent or not canonical base64url.
    SaltInvalid,
    /// Step 4: `parts_hash` does not match the held parts.
    PartsMismatch,
    /// Step 4: `artifact_id_hash` does not match the held `artifactId`.
    ArtifactIdMismatch,
    /// Step 4: the record's `name` or `description` differs from the held one.
    LabelMismatch,
    /// Step 4: the record's `role` differs from the held artifact's.
    RoleMismatch,
    /// Step 5: `task_id_hash` does not match the known task id.
    TaskMismatch,
    /// Step 5: `context_id_hash` does not match the known context id.
    ContextMismatch,
}

impl FailureKind {
    /// The §8 step that fails.
    pub fn step(self) -> u8 {
        use FailureKind as K;
        match self {
            K::FailedLink | K::LinkInvalid | K::BodyUnverified | K::LinkMismatch => 1,
            K::UntrustedAgent | K::CardMismatch | K::AidMismatch | K::RecordInvalid => 2,
            K::SaltInvalid => 3,
            K::PartsMismatch | K::ArtifactIdMismatch | K::LabelMismatch | K::RoleMismatch => 4,
            K::TaskMismatch | K::ContextMismatch => 5,
        }
    }

    /// Stable snake_case name (the `a2a-001` `expected_failure` vocabulary).
    pub fn code(self) -> &'static str {
        use FailureKind as K;
        match self {
            K::FailedLink => "failed_link",
            K::LinkInvalid => "link_invalid",
            K::BodyUnverified => "body_unverified",
            K::LinkMismatch => "link_mismatch",
            K::UntrustedAgent => "untrusted_agent",
            K::CardMismatch => "card_mismatch",
            K::AidMismatch => "aid_mismatch",
            K::RecordInvalid => "record_invalid",
            K::SaltInvalid => "salt_invalid",
            K::PartsMismatch => "parts_mismatch",
            K::ArtifactIdMismatch => "artifact_id_mismatch",
            K::LabelMismatch => "label_mismatch",
            K::RoleMismatch => "role_mismatch",
            K::TaskMismatch => "task_mismatch",
            K::ContextMismatch => "context_mismatch",
        }
    }
}

/// A failed §8 verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyFailure {
    /// What failed.
    pub kind: FailureKind,
    /// Human-readable detail.
    pub reason: String,
}

impl VerifyFailure {
    fn new(kind: FailureKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            reason: reason.into(),
        }
    }

    /// The §8 step that failed.
    pub fn step(&self) -> u8 {
        self.kind.step()
    }

    /// Steps 1–3: the link or record is not one to rely on. Otherwise
    /// (steps 4–5) the body is valid but is not a record of this artifact.
    pub fn is_unrecognised(&self) -> bool {
        self.step() <= 3
    }
}

impl std::fmt::Display for VerifyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let half = if self.is_unrecognised() {
            "provenance not recognised"
        } else {
            "provenance does not match the held artifact"
        };
        write!(
            f,
            "{half} (RFC-ACDP-0022 §8 step {}, {}): {}",
            self.step(),
            self.kind.code(),
            self.reason
        )
    }
}

impl std::error::Error for VerifyFailure {}

/// Which agents the holder trusts (§8 step 2, §13.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedAgents {
    /// Only these DIDs.
    Only(Vec<AgentDid>),
    /// Accept any `agent_id` here; the caller applies its own trust
    /// decision to [`HolderVerdict::agent_id`] afterwards.
    DeferToCaller,
}

/// The Agent Card the holder reached the agent through (§9), already
/// reduced to what §8 step 2 uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardContext {
    /// The pointer, `None` when the Card has no single well-formed entry.
    pub pointer: Option<CardParams>,
    /// The Card's AITP AIDs (RFC-AITP-0014 `params.aid`).
    pub aitp_aids: Vec<String>,
}

impl CardContext {
    /// From a Card's `capabilities.extensions`.
    pub fn from_extensions(extensions: &[Value]) -> Self {
        Self {
            pointer: card_pointer(extensions),
            aitp_aids: aitp_aids(extensions),
        }
    }
}

/// The holder's verification policy.
#[derive(Debug, Clone)]
pub struct HolderPolicy {
    /// Trusted agents.
    pub trusted: TrustedAgents,
    /// The Card, when the holder reached the agent through one.
    pub card: Option<CardContext>,
}

/// The artifact the holder holds.
#[derive(Debug, Clone, Copy)]
pub struct HeldArtifact<'a> {
    /// The A2A `Artifact` object as received, its `metadata` carrying the link.
    pub artifact: &'a Value,
    /// The task's `id`, when the holder knows it (the client does).
    pub task_id: Option<&'a str>,
    /// The task's `contextId`, when the holder knows it.
    pub context_id: Option<&'a str>,
}

impl<'a> HeldArtifact<'a> {
    /// A forwarded artifact: the task ids are unknown and stay unchecked.
    pub fn forwarded(artifact: &'a Value) -> Self {
        Self {
            artifact,
            task_id: None,
            context_id: None,
        }
    }
}

/// A successful verification.
#[derive(Debug, Clone, PartialEq)]
pub struct HolderVerdict {
    /// The verified body's `ctx_id`.
    pub ctx_id: CtxId,
    /// The agent that signed it.
    pub agent_id: AgentDid,
    /// Step 6: the body's registry status, when the path retrieved it.
    /// `superseded` means the agent published a later version of this
    /// artifact in the same task; `retracted` that it no longer stands
    /// behind it. What to do with either is the holder's policy.
    pub status: Option<Status>,
    /// Step 5: whether `task_id_hash` was checked.
    pub task_checked: bool,
    /// Step 5: whether `context_id_hash` was checked.
    pub context_checked: bool,
}

fn fail(kind: FailureKind, reason: impl Into<String>) -> VerifyFailure {
    VerifyFailure::new(kind, reason)
}

/// A link that names a body: its `ctx_id`, or the step-1 failure.
pub fn link_target(held: &HeldArtifact<'_>) -> Result<CtxId, VerifyFailure> {
    let link = published_link(held)?;
    let id = link
        .get("ctx_id")
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyFailure::new(FailureKind::LinkInvalid, "link has no ctx_id"))?;
    CtxId::parse(id)
        .map_err(|e| VerifyFailure::new(FailureKind::LinkInvalid, format!("link ctx_id: {e}")))
}

fn published_link<'v>(held: &HeldArtifact<'v>) -> Result<&'v Map<String, Value>, VerifyFailure> {
    use FailureKind as K;
    let link = link_of(held.artifact)
        .ok_or_else(|| VerifyFailure::new(K::LinkInvalid, "artifact has no io.acdp/provenance"))?
        .as_object()
        .ok_or_else(|| VerifyFailure::new(K::LinkInvalid, "link is not an object"))?;
    if link.contains_key("failed") {
        return Err(VerifyFailure::new(
            K::FailedLink,
            "link records a failed publish and names no body",
        ));
    }
    if let Some(k) = link
        .keys()
        .find(|k| !["ctx_id", "content_hash", "registry", "salt"].contains(&k.as_str()))
    {
        return Err(VerifyFailure::new(
            K::LinkInvalid,
            format!("unknown link member '{k}'"),
        ));
    }
    Ok(link)
}

/// Steps 1–6 against `body`, which the caller MUST already have verified
/// per RFC-ACDP-0001 §5.11 (`content_hash` and signature). `status` is
/// the registry status the caller retrieved, if any.
pub fn verify_against_body(
    body: &Body,
    status: Option<&Status>,
    held: &HeldArtifact<'_>,
    policy: &HolderPolicy,
) -> Result<HolderVerdict, VerifyFailure> {
    use FailureKind as K;

    // Step 1 — bind the verified body to the link.
    let link = published_link(held)?;
    let field = |k: &str| link.get(k).and_then(Value::as_str);
    if field("ctx_id") != Some(body.ctx_id.as_str()) {
        return Err(fail(K::LinkMismatch, "body ctx_id differs from the link's"));
    }
    if field("registry") != Some(body.origin_registry.as_str()) {
        return Err(fail(
            K::LinkMismatch,
            "body origin_registry differs from the link's registry",
        ));
    }
    if field("content_hash") != Some(body.content_hash.as_str()) {
        return Err(fail(
            K::LinkMismatch,
            "body content_hash differs from the link's",
        ));
    }

    // Step 2 — the agent, the Card binding and the closed record.
    if let TrustedAgents::Only(list) = &policy.trusted {
        if !list.contains(&body.agent_id) {
            return Err(fail(
                K::UntrustedAgent,
                format!("{} is not a trusted agent", body.agent_id.as_str()),
            ));
        }
    }
    if let Some(card) = &policy.card {
        // A dropped pointer (duplicate or malformed entry) removes only
        // the agentId check; the Card's AITP AID is still checked (§9).
        if let Some(p) = &card.pointer {
            if p.agent_id != body.agent_id {
                return Err(fail(
                    K::CardMismatch,
                    format!(
                        "Card params.agentId {} differs from agent_id {}",
                        p.agent_id.as_str(),
                        body.agent_id.as_str()
                    ),
                ));
            }
        }
        if body.agent_id.as_str().starts_with("did:key:") {
            if let Some(aid) = card
                .aitp_aids
                .iter()
                .find(|aid| !aid_matches_did_key(aid, &body.agent_id))
            {
                return Err(fail(
                    K::AidMismatch,
                    format!("did:key agent_id does not encode the Card's AITP AID {aid}"),
                ));
            }
        }
    }
    let rec = body
        .metadata
        .as_ref()
        .and_then(|m| m.get(RECORD_KEY))
        .ok_or_else(|| fail(K::RecordInvalid, "metadata has no acdp:a2a record"))?;
    check_record(rec).map_err(|r| fail(K::RecordInvalid, r))?;
    let rec = rec.as_object().expect("checked");
    let salted = rec["salted"] == true;

    // Step 3 — the salt, always present, canonical encoding only.
    let salt = match link.get("salt") {
        Some(Value::String(s)) => {
            Salt::from_base64url(s).map_err(|e| fail(K::SaltInvalid, e.to_string()))?
        }
        Some(_) => return Err(fail(K::SaltInvalid, "salt is not a string")),
        None => {
            return Err(fail(
                K::SaltInvalid,
                "link has no salt; the id hashes are always salted",
            ))
        }
    };

    // Step 4 — the held artifact.
    let art = held
        .artifact
        .as_object()
        .ok_or_else(|| fail(K::PartsMismatch, "held artifact is not an object"))?;
    let parts = match art.get("parts") {
        Some(Value::Array(p)) => {
            normalize_parts(p).map_err(|e| fail(K::PartsMismatch, e.to_string()))?
        }
        None | Some(Value::Null) => Vec::new(),
        Some(_) => return Err(fail(K::PartsMismatch, "held parts is not an array")),
    };
    let ph = hash::parts_hash(&Value::Array(parts), salted.then_some(&salt));
    if rec["parts_hash"] != ph.as_str() {
        return Err(fail(
            K::PartsMismatch,
            "parts_hash does not match the held parts",
        ));
    }
    let aid = art
        .get("artifactId")
        .and_then(Value::as_str)
        .ok_or_else(|| fail(K::ArtifactIdMismatch, "held artifact has no artifactId"))?;
    if rec["artifact_id_hash"] != hash::id_hash(aid, &salt).as_str() {
        return Err(fail(
            K::ArtifactIdMismatch,
            "artifact_id_hash does not match the held artifactId",
        ));
    }
    let held_str = |k: &str| art.get(k).and_then(Value::as_str);
    if let Some(n) = rec.get("name") {
        if record_name(held_str("name")).as_deref() != n.as_str() {
            return Err(fail(
                K::LabelMismatch,
                "record name differs from the held name",
            ));
        }
    }
    if let Some(d) = rec.get("description") {
        if record_description(held_str("description")).as_deref() != d.as_str() {
            return Err(fail(
                K::LabelMismatch,
                "record description differs from the held description",
            ));
        }
    }
    if let Some(r) = rec.get("role") {
        let held_role = match held_str("role") {
            None | Some(ROLE_UNSPECIFIED) => ROLE_AGENT,
            Some(r) => r,
        };
        if r != held_role {
            return Err(fail(
                K::RoleMismatch,
                "record role differs from the held role",
            ));
        }
    }

    // Step 5 — the task ids, when known.
    if let Some(t) = held.task_id {
        if rec["task_id_hash"] != hash::id_hash(t, &salt).as_str() {
            return Err(fail(
                K::TaskMismatch,
                "task_id_hash does not match the task id",
            ));
        }
    }
    if let Some(c) = held.context_id {
        if rec["context_id_hash"] != hash::id_hash(c, &salt).as_str() {
            return Err(fail(
                K::ContextMismatch,
                "context_id_hash does not match the context id",
            ));
        }
    }

    // Step 6 — status, reported.
    Ok(HolderVerdict {
        ctx_id: body.ctx_id.clone(),
        agent_id: body.agent_id.clone(),
        status: status.cloned(),
        task_checked: held.task_id.is_some(),
        context_checked: held.context_id.is_some(),
    })
}

/// §8 over a retrieved and verified context; step 6 reads its status.
pub fn verify_with_context(
    ctx: &VerifiedContext,
    held: &HeldArtifact<'_>,
    policy: &HolderPolicy,
) -> Result<HolderVerdict, VerifyFailure> {
    verify_against_body(ctx.body(), Some(&ctx.registry_state().status), held, policy)
}

/// §8 for a `did:key` agent's body exactly as received (offline:
/// `content_hash` recomputed over the raw JSON, signature checked, no
/// network). `status` is whatever the caller retrieved, if anything.
pub fn verify_offline(
    body: &Value,
    status: Option<&Status>,
    held: &HeldArtifact<'_>,
    policy: &HolderPolicy,
) -> Result<HolderVerdict, VerifyFailure> {
    published_link(held)?;
    let body = acdp::crypto::verify_body_value_offline(body)
        .map_err(|e| VerifyFailure::new(FailureKind::BodyUnverified, e.to_string()))?;
    verify_against_body(&body, status, held, policy)
}

/// Retrieve the link's body through `resolver` (RFC-ACDP-0006 §4.1, its
/// SSRF policy and allowlist; the Card never widens it) and run §8.
pub async fn resolve_and_verify(
    resolver: &CrossRegistryResolver,
    held: &HeldArtifact<'_>,
    policy: &HolderPolicy,
) -> Result<HolderVerdict, VerifyFailure> {
    let ctx_id = link_target(held)?;
    let ctx = resolver
        .resolve(&ctx_id)
        .await
        .map_err(|e| VerifyFailure::new(FailureKind::BodyUnverified, e.to_string()))?;
    verify_with_context(&ctx, held, policy)
}

/// Retrieve the link's body from `client`, verify it under
/// `verification`, and run §8. Choosing `client` is the caller's
/// registry-allowlist decision (§9: neither the Card nor the link widens
/// it); prefer [`resolve_and_verify`], which applies the resolver's.
pub async fn fetch_and_verify(
    client: &RegistryClient,
    resolver: &WebResolver,
    verification: &VerificationPolicy,
    held: &HeldArtifact<'_>,
    policy: &HolderPolicy,
) -> Result<HolderVerdict, VerifyFailure> {
    let ctx_id = link_target(held)?;
    let ctx = VerifiedContext::fetch_with_policy(client, resolver, &ctx_id, verification)
        .await
        .map_err(|e| VerifyFailure::new(FailureKind::BodyUnverified, e.to_string()))?;
    verify_with_context(&ctx, held, policy)
}

const RECORD_KEYS: &[&str] = &[
    "record_version",
    "a2a_protocol_version",
    "artifact_id_hash",
    "role",
    "task_id_hash",
    "context_id_hash",
    "parts_hash",
    "salted",
    "embedded",
    "name",
    "description",
    "completed_at",
];

fn is_hash(v: &Value) -> bool {
    v.as_str()
        .and_then(|s| s.strip_prefix("sha256:"))
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
}

fn is_timestamp(v: &Value) -> bool {
    // ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$
    let Some(s) = v.as_str() else { return false };
    let b = s.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    let head = b.len() >= 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19);
    head && match &b[19..] {
        [b'Z'] => true,
        [b'.', rest @ .., b'Z'] => !rest.is_empty() && rest.iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

fn bounded_str(v: Option<&Value>, max: usize) -> bool {
    v.and_then(Value::as_str)
        .is_some_and(|s| (1..=max).contains(&s.chars().count()))
}

/// `acdp-a2a-artifact.schema.json#/$defs/record`, closed: unknown
/// members are rejected, not ignored (§8 step 2).
pub fn check_record(rec: &Value) -> Result<(), String> {
    let m = rec.as_object().ok_or("record is not an object")?;
    if let Some(k) = m.keys().find(|k| !RECORD_KEYS.contains(&k.as_str())) {
        return Err(format!("unknown record member '{k}'"));
    }
    if m.get("record_version").and_then(Value::as_str) != Some(RECORD_VERSION) {
        return Err(format!("record_version is not {RECORD_VERSION}"));
    }
    if !bounded_str(m.get("a2a_protocol_version"), 64) {
        return Err("bad a2a_protocol_version".into());
    }
    for k in [
        "artifact_id_hash",
        "task_id_hash",
        "context_id_hash",
        "parts_hash",
    ] {
        if !m.get(k).is_some_and(is_hash) {
            return Err(format!("bad {k}"));
        }
    }
    if m.get("role").is_some_and(|r| r != ROLE_AGENT) {
        return Err("role is not ROLE_AGENT".into());
    }
    for k in ["salted", "embedded"] {
        if !m.get(k).is_some_and(Value::is_boolean) {
            return Err(format!("bad {k}"));
        }
    }
    if m["salted"] == false && m["embedded"] == false {
        return Err("salted false is allowed only with embedded true".into());
    }
    if m.contains_key("name") && !bounded_str(m.get("name"), 256) {
        return Err("bad name".into());
    }
    if m.contains_key("description") && !bounded_str(m.get("description"), 1024) {
        return Err("bad description".into());
    }
    if !m.get("completed_at").is_some_and(is_timestamp) {
        return Err("bad completed_at".into());
    }
    Ok(())
}
