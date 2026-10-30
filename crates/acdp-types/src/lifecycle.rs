//! Lifecycle events & retraction (ACDP 0.3, RFC-ACDP-0013 — promoting
//! the RFC-ACDP-0009 §2.1 reservation).
//!
//! A [`LifecycleEvent`] is a signed, append-only record in
//! `registry_state.lifecycle_events`: who performed a formal state
//! action on a context (retraction, republication), when, and
//! optionally why. Retraction is **mark-not-delete**: the body of a
//! retracted context remains permanently retrievable, byte-identical to
//! what its producer signed; what changes is the reliance signal
//! (`status: retracted`), never the record.
//!
//! ## Schema shape (RFC-ACDP-0013 §4)
//!
//! The event OBJECT is **closed** (`additionalProperties: false`,
//! `acdp-lifecycle-event.schema.json`): every member is signed where a
//! signature is present, so an unknown member would change the preimage
//! — it is rejected at parse time, exactly like the receipt schemas.
//! The `event_type` VOCABULARY is **open**
//! (`registries/lifecycle-event-types.md`): an unrecognized value
//! matching the `^[a-z][a-z0-9_]*$` pattern is tolerated, preserved
//! verbatim on re-serialization, and has *no effect on retraction
//! state* (§7.3) — the same discipline as unknown
//! [`Status`](acdp_primitives::primitives::Status) values.
//!
//! ## Signing construction (RFC-ACDP-0013 §5)
//!
//! Reuses RFC-ACDP-0010 §5 **verbatim** (the shared helper in
//! [`crate::receipt`]): the preimage is the JCS-canonicalized event
//! minus the `signature` member, hashed with SHA-256; the signature is
//! over the **ASCII bytes of the `"sha256:<hex>"` string** — never the
//! raw digest, never the unprefixed hex.

use crate::body::Signature;
use crate::receipt::preimage_hash_of_map;
use acdp_primitives::error::AcdpError;
use acdp_primitives::primitives::{AgentDid, ContentHash, CtxId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum `reason` length (RFC-ACDP-0013 §4).
pub const MAX_REASON_CHARS: usize = 1024;

/// The lifecycle event kind — an **open** vocabulary
/// ([`registries/lifecycle-event-types.md`]): v1 registers `retracted`
/// and `republished`; unknown values matching the RFC-ACDP-0004 §4.1
/// pattern (`^[a-z][a-z0-9_]*$`, 1–64 chars) are tolerated with **no
/// effect on retraction state** and round-trip verbatim — mirroring how
/// [`Status`](acdp_primitives::primitives::Status) handles unknown
/// values. Registries MUST NOT accept unregistered values through the
/// RFC-ACDP-0013 §6 endpoints in 0.3.0 (§7.3): openness is for future
/// versions and consumers, not a free-form producer channel.
///
/// [`registries/lifecycle-event-types.md`]:
///     https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/registries/lifecycle-event-types.md
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleEventType {
    /// `retracted` — the context is formally withdrawn from reliance;
    /// `status` becomes `retracted` (dominating `superseded` and
    /// `expired`, RFC-ACDP-0013 §7.2).
    Retracted,
    /// `republished` — a prior retraction is reversed; `status`
    /// re-derives per RFC-ACDP-0004 §4 as though never retracted. Both
    /// events remain in the append-only history.
    Republished,
    /// An event type this version of the library does not recognize.
    /// Per RFC-ACDP-0013 §7.3: tolerate, preserve verbatim, no effect
    /// on retraction state until upgrade.
    Other(String),
}

impl LifecycleEventType {
    /// Validate against the schema pattern `^[a-z][a-z0-9_]*$`, length
    /// 1..=64 (the RFC-ACDP-0004 §4.1 pattern, reused by §4).
    fn pattern_ok(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 64
            && s.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    }

    /// Wire-form string representation.
    pub fn as_str(&self) -> &str {
        match self {
            LifecycleEventType::Retracted => "retracted",
            LifecycleEventType::Republished => "republished",
            LifecycleEventType::Other(s) => s,
        }
    }

    /// Parse an event-type string, validating the pattern. Values that
    /// do not match the pattern are malformed registry state and are
    /// rejected (RFC-ACDP-0013 §7.3).
    pub fn parse(s: &str) -> Result<Self, AcdpError> {
        match s {
            "retracted" => Ok(LifecycleEventType::Retracted),
            "republished" => Ok(LifecycleEventType::Republished),
            other => {
                if !Self::pattern_ok(other) {
                    return Err(AcdpError::SchemaViolation(format!(
                        "event_type '{other}' does not match the open-vocabulary pattern \
                         ^[a-z][a-z0-9_]*$ (length 1..=64, RFC-ACDP-0013 §4)"
                    )));
                }
                Ok(LifecycleEventType::Other(other.to_string()))
            }
        }
    }

    /// True for the v1 registered vocabulary (`retracted` /
    /// `republished`) — the only values registries may accept through
    /// the RFC-ACDP-0013 §6 endpoints in 0.3.0 (§7.3).
    pub fn is_registered(&self) -> bool {
        matches!(
            self,
            LifecycleEventType::Retracted | LifecycleEventType::Republished
        )
    }
}

impl Serialize for LifecycleEventType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LifecycleEventType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        LifecycleEventType::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for LifecycleEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A lifecycle event (RFC-ACDP-0013 §4) — one entry of
/// `registry_state.lifecycle_events`.
///
/// CLOSED schema (`acdp-lifecycle-event.schema.json`,
/// `additionalProperties: false`): exactly the seven specified members;
/// an unknown member changes the signed preimage and is rejected at
/// parse time. Lifecycle events are **registry state, outside the
/// body**: never an input to the producer's `content_hash`
/// (RFC-ACDP-0001 §5.7) and never stored inside a body (§4.1).
///
/// Event **ordering** is array position in `lifecycle_events` (the
/// registry-accepted order); `occurred_at` never participates in the
/// retraction-state derivation (§4.1, §7.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleEvent {
    /// UUID (RFC 9562 canonical lowercase form) minted by the actor.
    /// MUST be unique within the context's `lifecycle_events` array.
    pub event_id: String,
    /// The affected context. MUST equal the `ctx_id` of the context
    /// whose registry state carries the event — binding a signed event
    /// to exactly one context so it cannot be replayed against another.
    pub ctx_id: CtxId,
    /// The event kind (open vocabulary, §7.3).
    pub event_type: LifecycleEventType,
    /// When the actor performed the action: canonical
    /// millisecond-precision RFC 3339 UTC (RFC-ACDP-0001 §5.3). The
    /// strict serde on this field rejects any non-canonical byte form
    /// (which the schema pattern forbids) so a parsed event always
    /// re-serializes byte-identically — a signed member must never be
    /// silently normalized.
    #[serde(with = "strict_ms_rfc3339")]
    pub occurred_at: DateTime<Utc>,
    /// The DID of the party performing the action: `body.agent_id` for
    /// producer-initiated events; the registry's DID
    /// (`capabilities.registry_did`) for registry-initiated events.
    pub actor: AgentDid,
    /// Optional human-readable explanation (≤ 1024 chars).
    /// Informational only; MUST NOT drive automated decisions (§4).
    #[serde(
        default,
        deserialize_with = "crate::serde_helpers::de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub reason: Option<String>,
    /// Signature over the event hash (RFC-ACDP-0013 §5). REQUIRED on
    /// producer-initiated events; SHOULD be present on
    /// registry-initiated events.
    #[serde(
        default,
        deserialize_with = "crate::serde_helpers::de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub signature: Option<Signature>,
}

/// Fixed three-digit-millisecond RFC 3339 serde for event
/// `occurred_at`, STRICT on deserialize: the schema pattern
/// (`…SS.mmmZ`) admits exactly one byte form, and accepting a laxer
/// form here would silently change signed bytes on re-serialization.
mod strict_ms_rfc3339 {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(d)?;
        if !crate::receipt::is_canonical_ms_utc(&raw) {
            return Err(serde::de::Error::custom(format!(
                "occurred_at '{raw}' is not canonical millisecond-precision RFC 3339 UTC \
                 (`YYYY-MM-DDTHH:MM:SS.mmmZ`, RFC-ACDP-0001 §5.3 / RFC-ACDP-0013 §4)"
            )));
        }
        DateTime::parse_from_rfc3339(&raw)
            .map(|t| t.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }
}

/// True when `s` is a canonical RFC 9562 UUID string: 8-4-4-4-12
/// lowercase hex. Deliberately version-agnostic (the schema pattern is
/// `^[0-9a-f]{8}-…$`) — actors mint v4 or v7 UUIDs.
fn is_canonical_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, &c)| match i {
        8 | 13 | 18 | 23 => c == b'-',
        _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
    })
}

impl LifecycleEvent {
    /// Construct a validated, **unsigned** event (`occurred_at` is
    /// millisecond-truncated per RFC-ACDP-0001 §5.3). Producer-initiated
    /// events MUST subsequently be signed via [`Self::sign_with`];
    /// registry-initiated events SHOULD be.
    pub fn new(
        event_id: impl Into<String>,
        ctx_id: CtxId,
        event_type: LifecycleEventType,
        occurred_at: DateTime<Utc>,
        actor: AgentDid,
        reason: Option<String>,
    ) -> Result<Self, AcdpError> {
        let event = Self {
            event_id: event_id.into(),
            ctx_id,
            event_type,
            occurred_at: acdp_primitives::time::trunc_ms(occurred_at),
            actor,
            reason,
            signature: None,
        };
        event.validate()?;
        Ok(event)
    }

    /// Sign this event per RFC-ACDP-0013 §5 (the RFC-ACDP-0010 §5
    /// construction): JCS of the event minus `signature`, SHA-256, and
    /// a signature over the ASCII bytes of the full `"sha256:<hex>"`
    /// string. `key_id`'s DID portion MUST equal `actor` — the signing
    /// key need not be the key that signed the original body (§5:
    /// producers rotate keys), but it must belong to the actor's DID, and
    /// it must not be a keyless key (RFC-ACDP-0021 §6.3).
    pub fn sign_with(
        mut self,
        key: impl Into<acdp_crypto::sign::AcdpSigningKey>,
        key_id: impl Into<String>,
    ) -> Result<Self, AcdpError> {
        let key_id = key_id.into();
        match key_id.split_once('#') {
            Some((did, frag)) if did == self.actor.as_str() && !frag.is_empty() => {}
            _ => {
                return Err(AcdpError::SchemaViolation(format!(
                    "lifecycle event signature key_id '{key_id}' must be '<actor>#<fragment>' \
                     with DID portion equal to actor '{}' (RFC-ACDP-0013 §5)",
                    self.actor
                )));
            }
        }
        // RFC-ACDP-0021 §6.3: keyless keys do not sign lifecycle events in
        // this version (the event has no member naming an attestation).
        if crate::keyless::is_keyless_key_id(&key_id) {
            return Err(
                crate::keyless::KeylessReason::KeylessEventUnsupported.error(format!(
                "lifecycle event key_id '{key_id}' is a keyless key id; a producer-actor event \
                 needs a key in the actor's DID document (RFC-ACDP-0021 §6.3)"
            )),
            );
        }
        // The preimage removes `signature` entirely, so it is identical
        // before and after this assignment.
        let hash = self.preimage_hash()?;
        let key = key.into();
        let (algorithm, value) = key.sign_content_hash(&hash);
        self.signature = Some(Signature {
            algorithm: algorithm.into(),
            key_id,
            value,
        });
        Ok(self)
    }

    /// Parse an event from raw wire JSON, enforcing the closed schema
    /// plus the §4 semantic invariants ([`Self::validate`]). The
    /// canonical `occurred_at` byte form is enforced by the field's
    /// strict serde. An event failing this parse is malformed registry
    /// state — structurally non-conformant per §7.3.
    pub fn from_value(value: &serde_json::Value) -> Result<Self, AcdpError> {
        let event = Self::deserialize(value).map_err(|e| {
            AcdpError::SchemaViolation(format!("lifecycle event does not parse: {e}"))
        })?;
        event.validate()?;
        Ok(event)
    }

    /// The §4 semantic invariants not already enforced by serde:
    /// canonical-UUID `event_id`, well-formed `ctx_id` and `actor`,
    /// `reason` length.
    pub fn validate(&self) -> Result<(), AcdpError> {
        if !is_canonical_uuid(&self.event_id) {
            return Err(AcdpError::SchemaViolation(format!(
                "lifecycle event_id '{}' is not a canonical lowercase RFC 9562 UUID \
                 (RFC-ACDP-0013 §4)",
                self.event_id
            )));
        }
        CtxId::parse(self.ctx_id.as_str().to_string())?;
        AgentDid::parse(self.actor.as_str().to_string())?;
        if let Some(reason) = &self.reason {
            if reason.chars().count() > MAX_REASON_CHARS {
                return Err(AcdpError::SchemaViolation(format!(
                    "lifecycle event reason exceeds {MAX_REASON_CHARS} characters \
                     (RFC-ACDP-0013 §4)"
                )));
            }
        }
        Ok(())
    }

    /// Compute the event's preimage hash from the RAW wire JSON (the
    /// value minus `signature`, JCS-canonicalized as received).
    ///
    /// Verifiers MUST hash the event exactly as received rather than
    /// re-serializing a parsed struct — the same raw-JSON rule as
    /// [`crate::receipt::RegistryReceipt::preimage_hash_of_value`].
    pub fn preimage_hash_of_value(value: &serde_json::Value) -> Result<ContentHash, AcdpError> {
        let map = value.as_object().cloned().ok_or_else(|| {
            AcdpError::SchemaViolation("lifecycle event must be a JSON object".into())
        })?;
        preimage_hash_of_map(map)
    }

    /// Compute the event's preimage hash from the struct. Used at
    /// signing time; verifiers should prefer
    /// [`Self::preimage_hash_of_value`] over the raw wire JSON. (For
    /// events parsed through this type's strict serde the two agree —
    /// every field round-trips byte-identically.)
    pub fn preimage_hash(&self) -> Result<ContentHash, AcdpError> {
        Self::preimage_hash_of_value(&serde_json::to_value(self)?)
    }

    /// RFC-ACDP-0013 §5 actor binding: the DID portion of
    /// `signature.key_id` MUST equal `actor`. Returns the signature for
    /// further verification; a missing signature is an error (call
    /// sites that tolerate unsigned registry events check
    /// [`Self::is_signed`] first).
    pub fn actor_bound_signature(&self) -> Result<&Signature, AcdpError> {
        let signature = self.signature.as_ref().ok_or_else(|| {
            AcdpError::SchemaViolation(
                "lifecycle event has no signature (producer-initiated events MUST be \
                 signed, RFC-ACDP-0013 §5)"
                    .into(),
            )
        })?;
        match signature.key_id.split_once('#') {
            Some((did, frag)) if did == self.actor.as_str() && !frag.is_empty() => Ok(signature),
            _ => Err(AcdpError::InvalidSignature(format!(
                "lifecycle event signature.key_id '{}' is not a DID URL under actor '{}' \
                 (RFC-ACDP-0013 §5 actor binding)",
                signature.key_id, self.actor
            ))),
        }
    }

    /// True when the event carries a signature.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Verify the event signature against a known actor public key
    /// (pure — no DID resolution). Checks the §5 actor binding, then
    /// verifies over the ASCII bytes of the recomputed event hash.
    /// Resolver-backed verification lives in
    /// `acdp_verify::verify_lifecycle_event`.
    pub fn verify_signature_with_key(
        &self,
        actor_pub_ed25519: Option<&[u8; 32]>,
        actor_pub_p256_sec1: Option<&[u8]>,
    ) -> Result<(), AcdpError> {
        let hash = self.preimage_hash()?;
        self.verify_signature_against_hash(&hash, actor_pub_ed25519, actor_pub_p256_sec1)
    }

    /// Like [`Self::verify_signature_with_key`] but over an
    /// already-computed preimage hash — pair with
    /// [`Self::preimage_hash_of_value`] for raw-JSON verification.
    pub fn verify_signature_against_hash(
        &self,
        hash: &ContentHash,
        actor_pub_ed25519: Option<&[u8; 32]>,
        actor_pub_p256_sec1: Option<&[u8]>,
    ) -> Result<(), AcdpError> {
        let signature = self.actor_bound_signature()?;
        match signature.algorithm.as_str() {
            "ed25519" => {
                let key = actor_pub_ed25519.ok_or_else(|| {
                    AcdpError::InvalidSignature(
                        "event declares ed25519 but no ed25519 actor key was resolved".into(),
                    )
                })?;
                acdp_crypto::verify::verify_ed25519(key, &signature.value, hash.as_str())
            }
            "ecdsa-p256" => {
                let key = actor_pub_p256_sec1.ok_or_else(|| {
                    AcdpError::InvalidSignature(
                        "event declares ecdsa-p256 but no p256 actor key was resolved".into(),
                    )
                })?;
                acdp_crypto::verify::verify_ecdsa_p256(key, &signature.value, hash.as_str())
            }
            other => Err(AcdpError::UnsupportedAlgorithm(format!(
                "lifecycle event signature algorithm '{other}' is not supported"
            ))),
        }
    }
}

/// Derive the **retraction state** of a context from its
/// `lifecycle_events` (RFC-ACDP-0013 §7.1): consider only
/// `retracted`/`republished` events; the context is retracted iff the
/// **last such event in array order** is `retracted`. Unknown event
/// types have no effect (§7.3); `occurred_at` never participates.
pub fn retraction_state(events: &[LifecycleEvent]) -> bool {
    events
        .iter()
        .rev()
        .find_map(|e| match e.event_type {
            LifecycleEventType::Retracted => Some(true),
            LifecycleEventType::Republished => Some(false),
            LifecycleEventType::Other(_) => None,
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_crypto::SigningKey;
    use serde_json::json;

    const CTX: &str = "acdp://registry.example.com/12345678-1234-4321-8123-123456781234";
    const ACTOR: &str = "did:web:agents.example.com:test-producer";
    const EVENT_ID: &str = "018f6d0a-7b2e-4c4d-9e1f-3a5b7c9d1e2f";

    fn actor_key() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    fn signed_retraction() -> LifecycleEvent {
        LifecycleEvent::new(
            EVENT_ID,
            CtxId(CTX.into()),
            LifecycleEventType::Retracted,
            chrono::DateTime::parse_from_rfc3339("2026-07-04T09:15:42.000Z")
                .unwrap()
                .with_timezone(&Utc),
            AgentDid::new(ACTOR),
            Some("underlying data source found to be fabricated".into()),
        )
        .unwrap()
        .sign_with(actor_key(), format!("{ACTOR}#key-1"))
        .unwrap()
    }

    fn actor_pub() -> [u8; 32] {
        actor_key().verifying_key_bytes()
    }

    #[test]
    fn sign_verify_round_trip_incl_wire() {
        let event = signed_retraction();
        event
            .verify_signature_with_key(Some(&actor_pub()), None)
            .expect("freshly signed event must verify");

        // Wire round trip: closed parse, canonical occurred_at bytes,
        // raw-JSON preimage equals struct preimage.
        let wire = serde_json::to_value(&event).unwrap();
        assert_eq!(wire["occurred_at"], "2026-07-04T09:15:42.000Z");
        let parsed = LifecycleEvent::from_value(&wire).unwrap();
        assert_eq!(parsed, event);
        assert_eq!(
            LifecycleEvent::preimage_hash_of_value(&wire).unwrap(),
            event.preimage_hash().unwrap()
        );
        parsed
            .verify_signature_with_key(Some(&actor_pub()), None)
            .unwrap();
    }

    /// The preimage is the event minus `signature` only — identical for
    /// the signed and unsigned forms of the same event (§5 step 1).
    #[test]
    fn preimage_excludes_signature_only() {
        let signed = signed_retraction();
        let mut unsigned = signed.clone();
        unsigned.signature = None;
        assert_eq!(
            signed.preimage_hash().unwrap(),
            unsigned.preimage_hash().unwrap()
        );
    }

    #[test]
    fn tampered_fields_fail_verification() {
        let pubkey = actor_pub();

        let mut e = signed_retraction();
        e.reason = Some("innocuous edit".into());
        assert!(e.verify_signature_with_key(Some(&pubkey), None).is_err());

        let mut e = signed_retraction();
        e.ctx_id = CtxId("acdp://evil.example.com/12345678-1234-4321-8123-123456781234".into());
        assert!(e.verify_signature_with_key(Some(&pubkey), None).is_err());

        let mut e = signed_retraction();
        e.occurred_at += chrono::Duration::milliseconds(1);
        assert!(e.verify_signature_with_key(Some(&pubkey), None).is_err());

        // Actor-binding violation surfaces as InvalidSignature.
        let mut e = signed_retraction();
        e.actor = AgentDid::new("did:web:agents.example.com:other");
        let err = e
            .verify_signature_with_key(Some(&pubkey), None)
            .unwrap_err();
        assert!(matches!(err, AcdpError::InvalidSignature(_)), "got {err:?}");
    }

    /// RFC-ACDP-0013 §4: the event schema is CLOSED — an unknown member
    /// MUST be rejected at parse time (it would change the preimage).
    #[test]
    fn unknown_event_member_rejected() {
        let mut wire = serde_json::to_value(signed_retraction()).unwrap();
        wire.as_object_mut()
            .unwrap()
            .insert("severity".into(), json!("high"));
        let err = LifecycleEvent::from_value(&wire).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");
    }

    /// §7.3: unknown event_type VALUES matching the pattern are
    /// tolerated, round-trip verbatim, and have no retraction effect.
    #[test]
    fn unknown_event_type_tolerated_and_inert() {
        let mut wire = serde_json::to_value(signed_retraction()).unwrap();
        wire["event_type"] = json!("annotated");
        let parsed = LifecycleEvent::from_value(&wire).unwrap();
        assert_eq!(
            parsed.event_type,
            LifecycleEventType::Other("annotated".into())
        );
        assert!(!parsed.event_type.is_registered());
        // Verbatim re-serialization.
        assert_eq!(
            serde_json::to_value(&parsed).unwrap()["event_type"],
            json!("annotated")
        );
        // No effect on retraction state.
        assert!(!retraction_state(&[parsed]));

        // Pattern-violating values are malformed registry state.
        for bad in ["Retracted", "has space", "", "9starts_with_digit"] {
            let mut wire = serde_json::to_value(signed_retraction()).unwrap();
            wire["event_type"] = json!(bad);
            assert!(
                LifecycleEvent::from_value(&wire).is_err(),
                "event_type {bad:?} must be rejected"
            );
        }
    }

    /// §7.1: retraction state is the LAST retracted/republished event
    /// in array order; unknown types are transparent to the derivation.
    #[test]
    fn retraction_state_last_event_wins() {
        let retract = signed_retraction();
        let mut republish = retract.clone();
        republish.event_type = LifecycleEventType::Republished;
        let mut unknown = retract.clone();
        unknown.event_type = LifecycleEventType::Other("annotated".into());

        assert!(!retraction_state(&[]));
        assert!(retraction_state(std::slice::from_ref(&retract)));
        assert!(!retraction_state(&[retract.clone(), republish.clone()]));
        assert!(retraction_state(&[
            retract.clone(),
            republish.clone(),
            retract.clone()
        ]));
        // Trailing unknown event does not flip the state.
        assert!(retraction_state(&[retract.clone(), unknown.clone()]));
        assert!(!retraction_state(&[
            retract.clone(),
            republish.clone(),
            unknown
        ]));
    }

    #[test]
    fn semantic_invariants_rejected() {
        // Non-canonical occurred_at byte form (no milliseconds).
        let mut wire = serde_json::to_value(signed_retraction()).unwrap();
        wire["occurred_at"] = json!("2026-07-04T09:15:42Z");
        assert!(LifecycleEvent::from_value(&wire).is_err());

        // Uppercase / malformed event_id.
        let mut wire = serde_json::to_value(signed_retraction()).unwrap();
        wire["event_id"] = json!("018F6D0A-7B2E-4C4D-9E1F-3A5B7C9D1E2F");
        assert!(LifecycleEvent::from_value(&wire).is_err());
        let mut wire = serde_json::to_value(signed_retraction()).unwrap();
        wire["event_id"] = json!("not-a-uuid");
        assert!(LifecycleEvent::from_value(&wire).is_err());

        // Over-long reason.
        let mut wire = serde_json::to_value(signed_retraction()).unwrap();
        wire["reason"] = json!("x".repeat(1025));
        assert!(LifecycleEvent::from_value(&wire).is_err());

        // Present-but-null optional members violate the absent-vs-null
        // convention (RFC-ACDP-0005 §2.2.1).
        let mut wire = serde_json::to_value(signed_retraction()).unwrap();
        wire["reason"] = serde_json::Value::Null;
        assert!(LifecycleEvent::from_value(&wire).is_err());
        let mut wire = serde_json::to_value(signed_retraction()).unwrap();
        wire["signature"] = serde_json::Value::Null;
        assert!(LifecycleEvent::from_value(&wire).is_err());
    }

    #[test]
    fn sign_with_rejects_foreign_key_id() {
        let unsigned = LifecycleEvent::new(
            EVENT_ID,
            CtxId(CTX.into()),
            LifecycleEventType::Retracted,
            Utc::now(),
            AgentDid::new(ACTOR),
            None,
        )
        .unwrap();
        assert!(unsigned
            .clone()
            .sign_with(actor_key(), "did:web:other.example.com#key-1")
            .is_err());
        assert!(unsigned.sign_with(actor_key(), ACTOR).is_err()); // no fragment
    }
}
