//! Cited inputs and `derived_from` (RFC-ACDP-0022 §7).
//!
//! A client cites the ACDP contexts it supplies under
//! `Message.metadata["io.agentcontextdistributionprotocol/inputs"]`: a bare array of 1 to 1000
//! `ctx_id`s. Only explicit citations count: an `acdp://` string inside a
//! Part is content and is never extracted.

use acdp::{client::CrossRegistryResolver, types::CtxId};
use serde_json::Value;

/// The `Message.metadata` key for cited inputs.
pub const INPUTS_KEY: &str = "io.agentcontextdistributionprotocol/inputs";
/// RFC-ACDP-0002 `derived_from` maximum, and the `inputs` array maximum.
pub const MAX_DERIVED_FROM: usize = 1000;

/// The cited inputs of one message's `metadata`, or `None` when it cites
/// none or its value is invalid (not a bare array of 1–1000 `ctx_id`s).
/// An invalid value is ignored as a whole and never fails the task.
pub fn parse_inputs(message_metadata: &Value) -> Option<Vec<CtxId>> {
    let arr = message_metadata.get(INPUTS_KEY)?.as_array()?;
    if arr.is_empty() || arr.len() > MAX_DERIVED_FROM {
        return None;
    }
    arr.iter()
        .map(|v| v.as_str().and_then(|s| CtxId::parse(s).ok()))
        .collect()
}

/// The inputs cited across a task's client messages (A2A JSON `Message`
/// objects), in message order and then array order, first occurrence
/// kept. A value under `io.agentcontextdistributionprotocol/provenance` is never read for inputs.
pub fn cited_inputs<'a>(messages: impl IntoIterator<Item = &'a Value>) -> Vec<CtxId> {
    let mut out: Vec<CtxId> = Vec::new();
    for m in messages {
        let Some(ids) = m.get("metadata").and_then(parse_inputs) else {
            continue;
        };
        for id in ids {
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

/// §7 `derived_from`: the continued body's `ctx_id` first (§4.3), then
/// the cited inputs `keep` accepts (verified, and used for this
/// artifact), then the contexts the agent retrieved and used on its own;
/// first occurrence kept, at most [`MAX_DERIVED_FROM`].
pub fn derived_from(
    continuation: Option<&CtxId>,
    cited: &[CtxId],
    keep: impl Fn(&CtxId) -> bool,
    own: &[CtxId],
) -> Vec<CtxId> {
    let mut out: Vec<CtxId> = Vec::new();
    let candidates = continuation
        .into_iter()
        .chain(cited.iter().filter(|c| keep(c)))
        .chain(own.iter());
    for c in candidates {
        if out.len() >= MAX_DERIVED_FROM {
            break;
        }
        if !out.contains(c) {
            out.push(c.clone());
        }
    }
    out
}

/// Retrieve and verify each input (RFC-ACDP-0001 §5.11, fetched under
/// RFC-ACDP-0006 §7 and RFC-ACDP-0008 through the resolver's SSRF policy
/// and allowlist) and keep those that verify, order kept (§7 step 3).
pub async fn verify_inputs(resolver: &CrossRegistryResolver, inputs: &[CtxId]) -> Vec<CtxId> {
    let mut out = Vec::new();
    for id in inputs {
        if resolver.resolve(id).await.is_ok() {
            out.push(id.clone());
        }
    }
    out
}
