//! The Agent Card pointer `https://agentcontextdistributionprotocol.io/ext/a2a/v1` (RFC-ACDP-0022 §9)
//! and the AITP identity binding (§3.1).
//!
//! The Card is an **untrusted pointer**: it says where to look and which
//! DID to expect, never that the DID is to be trusted. The body's
//! signature is the evidence.

use acdp::{
    did::key::{resolve_did_key, DidKeyMaterial},
    types::primitives::{is_valid_dns_authority, AgentDid},
};
use base64::Engine as _;
use serde_json::{json, Value};

/// The extension URI, compared byte for byte.
pub const EXTENSION_URI: &str = "https://agentcontextdistributionprotocol.io/ext/a2a/v1";
/// RFC-AITP-0014's extension URI, which carries `params.aid`.
pub const AITP_EXTENSION_URI: &str = "https://agentidentitytrustprotocol.io/ext/a2a/v1";

/// `params` of the pointer (`acdp-a2a-artifact.schema.json#/$defs/card_params`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardParams {
    /// Hostname of the registry the agent publishes to.
    pub registry: String,
    /// The agent's DID; equals every body's `agent_id` (§3.1).
    pub agent_id: AgentDid,
}

/// The `AgentExtension` an agent puts in `capabilities.extensions`
/// (§9): `required` is always `false`.
pub fn card_extension(params: &CardParams, description: Option<&str>) -> Value {
    let mut ext = json!({
        "uri": EXTENSION_URI,
        "required": false,
        "params": {
            "registry": params.registry,
            "agentId": params.agent_id.as_str(),
        },
    });
    if let Some(d) = description {
        ext["description"] = d.into();
    }
    ext
}

/// The extensions list of an Agent Card (`capabilities.extensions`).
pub fn card_extensions(card: &Value) -> &[Value] {
    card.pointer("/capabilities/extensions")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// The pointer in an extensions list, or `None` when the list has no
/// entry for [`EXTENSION_URI`], more than one, or malformed `params`
/// (§9: the holder then treats the Card as if it had none). `required`
/// is ignored for trust; unknown `params` members are ignored.
pub fn card_pointer(extensions: &[Value]) -> Option<CardParams> {
    let mut entries = extensions
        .iter()
        .filter(|e| e.get("uri").and_then(Value::as_str) == Some(EXTENSION_URI));
    let entry = entries.next()?;
    if entries.next().is_some() {
        return None;
    }
    let params = entry.get("params")?.as_object()?;
    let registry = params.get("registry")?.as_str()?;
    if !is_valid_dns_authority(registry) || registry.contains(':') {
        return None;
    }
    let agent_id = AgentDid::parse(params.get("agentId")?.as_str()?).ok()?;
    Some(CardParams {
        registry: registry.to_owned(),
        agent_id,
    })
}

/// Every `params.aid` of RFC-AITP-0014 entries in an extensions list.
pub fn aitp_aids(extensions: &[Value]) -> Vec<String> {
    extensions
        .iter()
        .filter(|e| e.get("uri").and_then(Value::as_str) == Some(AITP_EXTENSION_URI))
        .filter_map(|e| e.pointer("/params/aid")?.as_str().map(str::to_owned))
        .collect()
}

/// The key an AITP AID names (RFC-AITP-0001 §5.3): `aid:pubkey:<43>` or
/// `aid:pubkey:ed25519:<43>` for Ed25519 (32 bytes), and
/// `aid:pubkey:p256:<44>` for a SEC1-compressed P-256 point (33 bytes),
/// base64url without padding.
pub fn aid_key(aid: &str) -> Option<DidKeyMaterial> {
    let rest = aid.strip_prefix("aid:pubkey:")?;
    let decode = |s: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .ok()
    };
    if let Some(k) = rest.strip_prefix("ed25519:") {
        return Some(DidKeyMaterial::Ed25519(decode(k)?.try_into().ok()?));
    }
    if let Some(k) = rest.strip_prefix("p256:") {
        let b: [u8; 33] = decode(k)?.try_into().ok()?;
        return matches!(b[0], 0x02 | 0x03).then_some(DidKeyMaterial::EcdsaP256(b));
    }
    if rest.contains(':') {
        return None;
    }
    Some(DidKeyMaterial::Ed25519(decode(rest)?.try_into().ok()?))
}

/// §3.1: a `did:key` `agent_id` encodes the same key as the AID (same
/// algorithm, same public key bytes). `false` for a malformed AID, a
/// malformed `did:key`, or any other DID method.
pub fn aid_matches_did_key(aid: &str, agent_id: &AgentDid) -> bool {
    if !agent_id.as_str().starts_with("did:key:") {
        return false;
    }
    match (aid_key(aid), resolve_did_key(agent_id.as_str())) {
        (Some(a), Ok(d)) => a == d,
        _ => false,
    }
}
