//! Lifecycle event receipts (ACDP 0.5.0, RFC-ACDP-0017 §10, amending
//! RFC-ACDP-0013).
//!
//! An event receipt is a registry-signed acceptance time for one
//! lifecycle event. It gives the event a provable evidence time
//! (`accepted_at`), where the event's own `occurred_at` is only the
//! actor's claim. Registries serve the receipts in
//! `registry_state.event_receipts`, an array parallel to
//! `lifecycle_events`.
//!
//! The signing construction is RFC-ACDP-0010 §5 verbatim: JCS of the
//! object minus `signature`, SHA-256, and a signature over the ASCII
//! bytes of the full `"sha256:<hex>"` string. `receipt_type` is the
//! in-preimage domain separator.

use crate::body::Signature;
use crate::receipt::{
    is_canonical_ms_utc, preimage_hash_of_object, verify_signature_over_hash_with, ReceiptSigner,
};
use acdp_primitives::error::AcdpError;
use acdp_primitives::primitives::{ContentHash, CtxId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The `receipt_type` literal of an event receipt.
pub const EVENT_RECEIPT_TYPE: &str = "acdp-event-receipt/1";

/// A registry-signed lifecycle event receipt (RFC-ACDP-0017 §10.1).
///
/// CLOSED schema (`acdp-event-receipt.schema.json`,
/// `additionalProperties: false`): every member is signed, so an unknown
/// member would change the preimage and is rejected at parse time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventReceipt {
    /// Always [`EVENT_RECEIPT_TYPE`].
    pub receipt_type: String,
    /// The registry's identity, `did:web:<origin_registry>`.
    pub registry_did: String,
    /// The context the event belongs to.
    pub ctx_id: CtxId,
    /// The event's `event_id` (canonical lowercase UUID).
    pub event_id: String,
    /// `sha256:` + hex(SHA-256(JCS(event, *including* its signature))).
    pub event_hash: String,
    /// The event's zero-based position in `lifecycle_events`.
    pub index: u64,
    /// The registry's clock when it accepted the event (canonical
    /// millisecond RFC 3339 UTC).
    #[serde(with = "crate::receipt::ms_rfc3339")]
    pub accepted_at: DateTime<Utc>,
    /// Registry signature over the receipt preimage.
    pub signature: Signature,
}

impl EventReceipt {
    /// Parse an event receipt from raw wire JSON, enforcing the closed
    /// schema: exact `receipt_type`, canonical-UUID `event_id`,
    /// `sha256:<64 hex>` `event_hash`, the canonical millisecond byte
    /// form of the RAW `accepted_at`, and a `signature.key_id` under
    /// `registry_did`. Failures are [`AcdpError::InvalidReceipt`].
    pub fn from_value(value: &serde_json::Value) -> Result<Self, AcdpError> {
        let raw_accepted_at = value.get("accepted_at").and_then(|v| v.as_str());
        if !raw_accepted_at.is_some_and(is_canonical_ms_utc) {
            return Err(AcdpError::InvalidReceipt(
                "event receipt accepted_at is missing or not canonical millisecond-precision \
                 RFC 3339 UTC (RFC-ACDP-0017 §10.1)"
                    .into(),
            ));
        }
        let receipt = Self::deserialize(value)
            .map_err(|e| AcdpError::InvalidReceipt(format!("event receipt does not parse: {e}")))?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// The schema invariants serde does not enforce.
    pub fn validate(&self) -> Result<(), AcdpError> {
        if self.receipt_type != EVENT_RECEIPT_TYPE {
            return Err(AcdpError::InvalidReceipt(format!(
                "event receipt receipt_type '{}' ≠ '{EVENT_RECEIPT_TYPE}'",
                self.receipt_type
            )));
        }
        CtxId::parse(self.ctx_id.as_str().to_string())
            .map_err(|e| AcdpError::InvalidReceipt(format!("event receipt ctx_id: {e}")))?;
        if !is_canonical_uuid(&self.event_id) {
            return Err(AcdpError::InvalidReceipt(format!(
                "event receipt event_id '{}' is not a canonical lowercase UUID",
                self.event_id
            )));
        }
        if !is_sha256_digest(&self.event_hash) {
            return Err(AcdpError::InvalidReceipt(format!(
                "event receipt event_hash '{}' is not sha256:<64 lowercase hex>",
                self.event_hash
            )));
        }
        match self.signature.key_id.split_once('#') {
            Some((did, frag)) if did == self.registry_did && !frag.is_empty() => Ok(()),
            _ => Err(AcdpError::InvalidReceipt(format!(
                "event receipt signature.key_id '{}' is not a DID URL under registry_did '{}'",
                self.signature.key_id, self.registry_did
            ))),
        }
    }

    /// `event_hash` for a raw lifecycle event: `sha256:` +
    /// hex(SHA-256(JCS(event))), over the event exactly as stored,
    /// *including* its `signature` member (RFC-ACDP-0017 §10.1).
    pub fn event_hash_of_value(raw_event: &serde_json::Value) -> Result<String, AcdpError> {
        let canonical = acdp_jcs::try_canonicalize_value(raw_event)?;
        Ok(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(&canonical))
        ))
    }

    /// Preimage hash from the RAW wire JSON (the value minus
    /// `signature`). Verifiers MUST hash the receipt as received.
    pub fn preimage_hash_of_value(value: &serde_json::Value) -> Result<ContentHash, AcdpError> {
        preimage_hash_of_object(value, "event receipt")
    }

    /// Struct-based preimage hash, used at mint time.
    pub fn preimage_hash(&self) -> Result<ContentHash, AcdpError> {
        Self::preimage_hash_of_value(&serde_json::to_value(self)?)
    }

    /// Verify the signature over an already-computed preimage hash
    /// against a known registry public key (pure; no DID resolution).
    pub fn verify_signature_against_hash(
        &self,
        hash: &ContentHash,
        registry_pub_ed25519: Option<&[u8; 32]>,
        registry_pub_p256_sec1: Option<&[u8]>,
    ) -> Result<(), AcdpError> {
        verify_signature_over_hash_with(
            &self.signature,
            hash,
            registry_pub_ed25519,
            registry_pub_p256_sec1,
            "event receipt",
            AcdpError::InvalidReceipt,
        )
    }
}

impl ReceiptSigner {
    /// Mint an event receipt for the lifecycle event at `index`
    /// (RFC-ACDP-0017 §10.1), signed with the receipt signing key.
    ///
    /// `raw_event` is the event exactly as stored, including its
    /// `signature`; `event_hash` is computed from it here. The caller
    /// owns the §10.1 clock rules: `accepted_at` MUST NOT be backdated
    /// and MUST be ≥ the previous event's `accepted_at` and the
    /// context's `created_at`.
    pub fn mint_event_receipt(
        &self,
        ctx_id: &CtxId,
        raw_event: &serde_json::Value,
        index: u64,
        accepted_at: DateTime<Utc>,
    ) -> Result<EventReceipt, AcdpError> {
        let event_id = raw_event
            .get("event_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AcdpError::SchemaViolation("lifecycle event has no string event_id".into())
            })?
            .to_string();
        let mut receipt = EventReceipt {
            receipt_type: EVENT_RECEIPT_TYPE.to_string(),
            registry_did: self.registry_did().to_string(),
            ctx_id: ctx_id.clone(),
            event_id,
            event_hash: EventReceipt::event_hash_of_value(raw_event)?,
            index,
            accepted_at: acdp_primitives::time::trunc_ms(accepted_at),
            signature: Signature {
                algorithm: self.signing_key().algorithm().into(),
                key_id: self.key_id().to_string(),
                value: String::new(),
            },
        };
        receipt.validate()?;
        let hash = receipt.preimage_hash()?;
        let (algorithm, value) = self.signing_key().sign_content_hash(&hash);
        receipt.signature.algorithm = algorithm.into();
        receipt.signature.value = value;
        Ok(receipt)
    }
}

fn is_canonical_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

fn is_sha256_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_crypto::SigningKey;

    const CTX: &str = "acdp://registry.example.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    fn signer() -> ReceiptSigner {
        ReceiptSigner::new(
            SigningKey::from_bytes(&[0x11; 32]),
            "did:web:registry.example.com",
            "did:web:registry.example.com#receipt-key-1",
        )
        .unwrap()
    }

    fn event() -> serde_json::Value {
        serde_json::json!({
            "event_id": "018f6d0a-7b2e-4c4d-9e1f-3a5b7c9d1e2f",
            "ctx_id": CTX,
            "event_type": "retracted",
            "occurred_at": "2026-10-03T00:00:00.000Z",
            "actor": "did:web:registry.example.com"
        })
    }

    fn accepted() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-03T00:00:01.000Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn mint_round_trips_and_verifies() {
        let receipt = signer()
            .mint_event_receipt(&CtxId::parse(CTX).unwrap(), &event(), 0, accepted())
            .unwrap();
        let wire = serde_json::to_value(&receipt).unwrap();
        assert_eq!(wire["accepted_at"], "2026-10-03T00:00:01.000Z");
        let parsed = EventReceipt::from_value(&wire).unwrap();
        assert_eq!(parsed, receipt);
        let hash = EventReceipt::preimage_hash_of_value(&wire).unwrap();
        let key = SigningKey::from_bytes(&[0x11; 32]).verifying_key_bytes();
        parsed
            .verify_signature_against_hash(&hash, Some(&key), None)
            .unwrap();
        assert_eq!(
            parsed.event_hash,
            EventReceipt::event_hash_of_value(&event()).unwrap()
        );
    }

    #[test]
    fn closed_schema_rejects_unknown_member_and_bad_forms() {
        let receipt = signer()
            .mint_event_receipt(&CtxId::parse(CTX).unwrap(), &event(), 0, accepted())
            .unwrap();
        let wire = serde_json::to_value(&receipt).unwrap();

        let mut extra = wire.clone();
        extra["note"] = "x".into();
        assert!(EventReceipt::from_value(&extra).is_err());

        let mut short_ts = wire.clone();
        short_ts["accepted_at"] = "2026-10-03T00:00:01Z".into();
        assert!(EventReceipt::from_value(&short_ts).is_err());

        let mut wrong_type = wire.clone();
        wrong_type["receipt_type"] = "acdp-event-receipt/2".into();
        assert!(EventReceipt::from_value(&wrong_type).is_err());

        let mut foreign_key = wire;
        foreign_key["signature"]["key_id"] = "did:web:evil.example.com#k".into();
        assert!(EventReceipt::from_value(&foreign_key).is_err());
    }
}
