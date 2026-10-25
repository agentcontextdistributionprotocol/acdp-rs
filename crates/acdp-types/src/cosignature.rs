//! Transparency-log witness cosignatures (ACDP 0.4, RFC-ACDP-0015 —
//! promoted from the RFC-ACDP-0009 §2.12 reservation).
//!
//! A **cosignature** is an independent **witness's** signed observation
//! of an RFC-ACDP-0012 transparency-log checkpoint: the witness observed
//! a specific checkpoint tuple `{log_id, tree_size, root_hash,
//! timestamp}`, verified its signature and consistency from its retained
//! head (§7), and cosigned it at `witnessed_at`. A consumer that trusts
//! any one honest witness inherits split-view protection: a checkpoint is
//! believed only when parties the registry does not control also saw,
//! consistency-checked, and signed it.
//!
//! ## The one load-bearing departure from RFC-ACDP-0010/0011/0012
//!
//! RFC-ACDP-0011 head receipts and RFC-ACDP-0012 checkpoints all sign
//! with the **registry receipt key**. A cosignature signs with the
//! **witness's own key**, under the witness's own DID (§5, §12) — the
//! whole value of a cosignature is that it is *not* the registry's
//! signature. Witnesses are **not** registries: they have no publish
//! surface and mint no receipts (§3). The [`WitnessSigner`] therefore
//! introduces a new key role, distinct from [`crate::receipt::ReceiptSigner`].
//!
//! ## Signing construction
//!
//! Reuses RFC-ACDP-0010 §5 **verbatim** (§5): the preimage is the JCS
//! canonicalization (RFC 8785) of the object **minus `signature` only**
//! (there is no exclusion set beyond `signature`), SHA-256'd; the witness
//! signs the **ASCII bytes of the `"sha256:<hex>"` string**, not the raw
//! 32-byte digest, with `cosignature_version` acting as the in-preimage
//! domain separator.
//!
//! All verification failures here map to
//! [`AcdpError::InvalidWitnessCosignature`] — deliberately **not**
//! `InvalidLogProof`: a cosignature failure indicts a *witness's*
//! attestation (an independent signer), never the *log* itself; the
//! verdicts are independent (RFC-ACDP-0015 §8, §10).

use crate::body::Signature;
use crate::log::{decode_sha256_hex, parse_log_id, LogCheckpoint};
use crate::receipt::{
    is_canonical_ms_utc, ms_rfc3339, preimage_hash_of_object_with, verify_signature_over_hash_with,
};
use acdp_primitives::error::AcdpError;
use acdp_primitives::primitives::ContentHash;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The cosignature envelope version (RFC-ACDP-0015 §4). In-preimage
/// domain separator (the RFC-ACDP-0011 `receipt_version` /
/// RFC-ACDP-0012 `checkpoint_version` convention): a cosignature can
/// never be mistaken for — or replayed as — a checkpoint, a receipt, or
/// any other JCS-canonicalized ACDP object.
pub const COSIGNATURE_VERSION: &str = "acdp-cosig/1";

/// True when `id` is a well-formed witness DID (`did:web` or `did:key`)
/// — the RFC-ACDP-0015 §4 `witness_id` shape (a light structural check;
/// full resolution is the `client` feature's job).
fn is_witness_did(id: &str) -> bool {
    id.starts_with("did:web:") && id.len() > "did:web:".len()
        || id.starts_with("did:key:z") && id.len() > "did:key:z".len()
}

// ── Witnessed checkpoint (the identity-bearing subset) ───────────────────────

/// The identity-bearing subset of the RFC-ACDP-0012 §6 checkpoint the
/// witness observed: `{log_id, tree_size, root_hash, timestamp}`, copied
/// **verbatim** from the verified checkpoint (RFC-ACDP-0015 §4).
///
/// CLOSED schema (`additionalProperties: false`): the registry's
/// `checkpoint_version` and `signature` are deliberately NOT restated —
/// the consumer verifies the registry checkpoint signature independently
/// (RFC-ACDP-0012 §9.3). Every member is signed, so an unknown member
/// changes the preimage and is rejected at parse time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessedCheckpoint {
    /// The observed log instantiation identifier
    /// (`"<registry_did>/log/<instance>"`), copied verbatim from the
    /// checkpoint the witness verified.
    pub log_id: String,
    /// The observed checkpoint's `tree_size`.
    pub tree_size: u64,
    /// The observed checkpoint's `root_hash` (`"sha256:<hex>"`).
    /// Together with `log_id` and `tree_size` this is the tuple the
    /// N-witnessed count is computed over (RFC-ACDP-0015 §8).
    pub root_hash: String,
    /// The **registry-claimed** checkpoint timestamp (the RFC-ACDP-0012
    /// §6 `checkpoint.timestamp`), copied verbatim; canonical
    /// millisecond-precision RFC 3339 UTC. Registry-asserted — the
    /// witness does NOT vouch for it (`witnessed_at` is what the witness
    /// attests, RFC-ACDP-0015 §4).
    #[serde(with = "ms_rfc3339")]
    pub timestamp: DateTime<Utc>,
}

impl WitnessedCheckpoint {
    /// Copy the identity-bearing subset out of a verified checkpoint
    /// (RFC-ACDP-0015 §7 step 3 — `{log_id, tree_size, root_hash,
    /// timestamp}` verbatim).
    pub fn from_checkpoint(checkpoint: &LogCheckpoint) -> Self {
        Self {
            log_id: checkpoint.log_id.clone(),
            tree_size: checkpoint.tree_size,
            root_hash: checkpoint.root_hash.clone(),
            timestamp: checkpoint.timestamp,
        }
    }
}

// ── Cosignature ──────────────────────────────────────────────────────────────

/// A witness-signed cosignature of a transparency-log checkpoint
/// (RFC-ACDP-0015 §4).
///
/// CLOSED schema (`acdp-log-cosignature.schema.json`,
/// `additionalProperties: false`): every member is signed, so an unknown
/// member changes the preimage and is rejected at parse time; extensions
/// require a `cosignature_version` bump.
///
/// Cosignatures are **ephemeral, per-observation** evidence (the
/// RFC-ACDP-0011 §4 posture): a witness produces a fresh cosignature
/// (fresh `witnessed_at`) each time it re-observes the log, including at
/// an unchanged `tree_size` as a liveness signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogCosignature {
    /// MUST be exactly [`COSIGNATURE_VERSION`] (`"acdp-cosig/1"`).
    pub cosignature_version: String,
    /// The **witness's** DID (`did:web` or `did:key`) — the witness's
    /// own identity, distinct from the registry's `registry_did`
    /// (RFC-ACDP-0015 §3). The N-witnessed count (§8) is over DISTINCT
    /// `witness_id` values.
    pub witness_id: String,
    /// The identity-bearing subset of the checkpoint the witness
    /// observed, copied verbatim.
    pub witnessed_checkpoint: WitnessedCheckpoint,
    /// The **witness-clock** time at which the witness observed and
    /// cosigned the checkpoint; canonical millisecond-precision RFC 3339
    /// UTC (RFC-ACDP-0001 §5.3). Anchored against a party the registry
    /// does not control — it bounds when the checkpoint existed
    /// regardless of the registry's claimed `timestamp` (§4).
    #[serde(with = "ms_rfc3339")]
    pub witnessed_at: DateTime<Utc>,
    /// The **witness's** signature over the cosignature hash (§5 — the
    /// RFC-ACDP-0010 §5 construction verbatim, keyed by the witness's
    /// own `assertionMethod` key). `signature.key_id` MUST be a DID URL
    /// under `witness_id`.
    pub signature: Signature,
}

impl LogCosignature {
    /// RFC-ACDP-0015 §8 step 1 — schema-closed parse plus the §4/§5
    /// semantic invariants: exact `cosignature_version`, a well-formed
    /// witness DID, a well-formed `witnessed_checkpoint`
    /// (`log_id`/`root_hash` shape, canonical millisecond `timestamp`
    /// byte form), the canonical millisecond `witnessed_at` byte form
    /// (both checked on the RAW wire strings before any parsing
    /// normalization), and the §8 step 3 witness binding —
    /// `signature.key_id` is a DID URL under `witness_id`.
    pub fn from_value(value: &serde_json::Value) -> Result<Self, AcdpError> {
        let cosig = Self::deserialize(value).map_err(|e| {
            AcdpError::InvalidWitnessCosignature(format!("log_cosignature does not parse: {e}"))
        })?;
        if cosig.cosignature_version != COSIGNATURE_VERSION {
            return Err(AcdpError::InvalidWitnessCosignature(format!(
                "log_cosignature cosignature_version '{}' ≠ '{COSIGNATURE_VERSION}' \
                 (RFC-ACDP-0015 §4)",
                cosig.cosignature_version
            )));
        }
        if !is_witness_did(&cosig.witness_id) {
            return Err(AcdpError::InvalidWitnessCosignature(format!(
                "log_cosignature witness_id '{}' is not a did:web or did:key DID \
                 (RFC-ACDP-0015 §4)",
                cosig.witness_id
            )));
        }
        // witnessed_checkpoint identity-field shapes.
        parse_log_id(&cosig.witnessed_checkpoint.log_id).map_err(|e| {
            AcdpError::InvalidWitnessCosignature(format!("witnessed_checkpoint: {e}"))
        })?;
        decode_sha256_hex(&cosig.witnessed_checkpoint.root_hash).map_err(|e| {
            AcdpError::InvalidWitnessCosignature(format!("witnessed_checkpoint: {e}"))
        })?;

        // §4 canonical millisecond byte forms, checked on the RAW wire
        // strings (before parsing normalization).
        let wc_ts = value
            .get("witnessed_checkpoint")
            .and_then(|v| v.get("timestamp"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AcdpError::InvalidWitnessCosignature(
                    "log_cosignature witnessed_checkpoint.timestamp missing or not a string".into(),
                )
            })?;
        if !is_canonical_ms_utc(wc_ts) {
            return Err(AcdpError::InvalidWitnessCosignature(format!(
                "log_cosignature witnessed_checkpoint.timestamp '{wc_ts}' is not canonical \
                 millisecond-precision RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SS.mmmZ`, RFC-ACDP-0015 §4)"
            )));
        }
        let witnessed_at = value
            .get("witnessed_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AcdpError::InvalidWitnessCosignature(
                    "log_cosignature witnessed_at missing or not a string".into(),
                )
            })?;
        if !is_canonical_ms_utc(witnessed_at) {
            return Err(AcdpError::InvalidWitnessCosignature(format!(
                "log_cosignature witnessed_at '{witnessed_at}' is not canonical \
                 millisecond-precision RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SS.mmmZ`, RFC-ACDP-0015 §4)"
            )));
        }

        // §8 step 3 witness binding: signature.key_id is a DID URL under
        // witness_id.
        cosig.witness_key_did()?;
        Ok(cosig)
    }

    /// RFC-ACDP-0015 §8 step 3 — the witness DID that `signature.key_id`
    /// is a DID URL under, after checking that its DID portion equals
    /// `witness_id` and it carries a non-empty fragment.
    pub fn witness_key_did(&self) -> Result<&str, AcdpError> {
        match self.signature.key_id.split_once('#') {
            Some((did, frag)) if did == self.witness_id && !frag.is_empty() => Ok(did),
            _ => Err(AcdpError::InvalidWitnessCosignature(format!(
                "log_cosignature signature.key_id '{}' is not a DID URL under witness_id '{}' \
                 (RFC-ACDP-0015 §8 step 3)",
                self.signature.key_id, self.witness_id
            ))),
        }
    }

    /// The `(log_id, tree_size, root_hash)` tuple the N-witnessed count
    /// is computed over (RFC-ACDP-0015 §8). Two cosignatures count
    /// toward the same checkpoint iff this tuple is byte/numerically
    /// equal.
    pub fn checkpoint_tuple(&self) -> (&str, u64, &str) {
        (
            &self.witnessed_checkpoint.log_id,
            self.witnessed_checkpoint.tree_size,
            &self.witnessed_checkpoint.root_hash,
        )
    }

    /// Compute the cosignature hash from the RAW wire JSON (the value
    /// minus `signature`, JCS-canonicalized as received, SHA-256'd).
    /// Verifiers MUST hash the cosignature exactly as received — the same
    /// raw-JSON rule as [`crate::receipt::RegistryReceipt::preimage_hash_of_value`].
    pub fn preimage_hash_of_value(value: &serde_json::Value) -> Result<ContentHash, AcdpError> {
        preimage_hash_of_object_with(
            value,
            "log_cosignature",
            AcdpError::InvalidWitnessCosignature,
        )
    }

    /// Compute the cosignature hash from the struct. Used at MINT time
    /// (the struct's serializer emits the canonical three-digit-
    /// millisecond timestamps); verifiers should prefer
    /// [`Self::preimage_hash_of_value`] over the raw wire JSON.
    pub fn preimage_hash(&self) -> Result<ContentHash, AcdpError> {
        Self::preimage_hash_of_value(&serde_json::to_value(self)?)
    }

    /// RFC-ACDP-0015 §8 step 2 — verify the witness signature against a
    /// known witness public key (pure — no DID resolution; the `client`
    /// feature's `verify_witness_cosignature_value` resolves the witness
    /// DID and calls this).
    pub fn verify_signature_with_key(
        &self,
        witness_pub_ed25519: Option<&[u8; 32]>,
        witness_pub_p256_sec1: Option<&[u8]>,
    ) -> Result<(), AcdpError> {
        let hash = self.preimage_hash()?;
        self.verify_signature_against_hash(&hash, witness_pub_ed25519, witness_pub_p256_sec1)
    }

    /// Like [`Self::verify_signature_with_key`] but over an
    /// already-computed cosignature hash — pair with
    /// [`Self::preimage_hash_of_value`] for raw-JSON verification.
    pub fn verify_signature_against_hash(
        &self,
        hash: &ContentHash,
        witness_pub_ed25519: Option<&[u8; 32]>,
        witness_pub_p256_sec1: Option<&[u8]>,
    ) -> Result<(), AcdpError> {
        verify_signature_over_hash_with(
            &self.signature,
            hash,
            witness_pub_ed25519,
            witness_pub_p256_sec1,
            "log_cosignature",
            AcdpError::InvalidWitnessCosignature,
        )
    }

    /// RFC-ACDP-0015 §8 step 4 — checkpoint binding: the
    /// `witnessed_checkpoint`'s `log_id`, `tree_size`, and `root_hash`
    /// MUST equal, byte-for-byte / numerically, the corresponding fields
    /// of the checkpoint the consumer independently holds and verified
    /// (RFC-ACDP-0012 §9.3). A cosignature over a *different* tuple is
    /// evidence about a different checkpoint and MUST NOT be counted for
    /// this one. `timestamp` is deliberately not compared here — it is
    /// registry-asserted and the witness merely copies it (§4).
    pub fn cross_check_against_checkpoint(
        &self,
        checkpoint: &LogCheckpoint,
    ) -> Result<(), AcdpError> {
        let wc = &self.witnessed_checkpoint;
        if wc.log_id != checkpoint.log_id {
            return Err(AcdpError::InvalidWitnessCosignature(format!(
                "log_cosignature witnessed_checkpoint.log_id '{}' ≠ evaluated checkpoint log_id \
                 '{}' (RFC-ACDP-0015 §8 step 4)",
                wc.log_id, checkpoint.log_id
            )));
        }
        if wc.tree_size != checkpoint.tree_size {
            return Err(AcdpError::InvalidWitnessCosignature(format!(
                "log_cosignature witnessed_checkpoint.tree_size {} ≠ evaluated checkpoint \
                 tree_size {} (RFC-ACDP-0015 §8 step 4)",
                wc.tree_size, checkpoint.tree_size
            )));
        }
        if wc.root_hash != checkpoint.root_hash {
            return Err(AcdpError::InvalidWitnessCosignature(format!(
                "log_cosignature witnessed_checkpoint.root_hash '{}' ≠ evaluated checkpoint \
                 root_hash '{}' (RFC-ACDP-0015 §8 step 4)",
                wc.root_hash, checkpoint.root_hash
            )));
        }
        Ok(())
    }

    /// RFC-ACDP-0015 §8 step 5 — `witnessed_at` sanity against the
    /// consumer's clock: millisecond-truncated (RFC-ACDP-0001 §5.3) and
    /// not in the future beyond `max_clock_skew` (RECOMMENDED 120 s, the
    /// RFC-ACDP-0011 §7 step 6 allowance). A future-dated `witnessed_at`
    /// is a forged observation-time claim.
    ///
    /// This is the *verification* half only. Staleness (an old but
    /// honest `witnessed_at`) is consumer freshness policy (§8.1) —
    /// evaluate it separately via [`Self::age_at`]. For the
    /// anti-backdating use an old cosignature is *stronger* evidence.
    pub fn check_witnessed_at_skew(
        &self,
        now: DateTime<Utc>,
        max_clock_skew: chrono::Duration,
    ) -> Result<(), AcdpError> {
        if !self
            .witnessed_at
            .timestamp_subsec_nanos()
            .is_multiple_of(1_000_000)
        {
            return Err(AcdpError::InvalidWitnessCosignature(
                "log_cosignature witnessed_at is not millisecond-truncated (RFC-ACDP-0001 §5.3)"
                    .into(),
            ));
        }
        if self.witnessed_at > now + max_clock_skew {
            return Err(AcdpError::InvalidWitnessCosignature(format!(
                "log_cosignature witnessed_at '{}' is in the future beyond the {}s clock-skew \
                 allowance (consumer clock '{}') — forged observation-time claim \
                 (RFC-ACDP-0015 §8 step 5)",
                self.witnessed_at.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                max_clock_skew.num_seconds(),
                now.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            )));
        }
        Ok(())
    }

    /// The cosignature's age at `now` — the input to the consumer's §8.1
    /// freshness policy (RECOMMENDED maximum: 300 seconds for
    /// current-ness-sensitive decisions). Negative when `witnessed_at`
    /// is ahead of `now` (bounded by the step-5 skew check).
    pub fn age_at(&self, now: DateTime<Utc>) -> chrono::Duration {
        now - self.witnessed_at
    }
}

// ── Witness-side minting ─────────────────────────────────────────────────────

/// Witness-side cosignature minting identity: the **witness's** signing
/// key plus the DID URL it is published under in the witness's own DID
/// document (RFC-ACDP-0015 §5, §9).
///
/// Deliberately **not** [`crate::receipt::ReceiptSigner`]: the whole
/// value of a cosignature is that the signer is the witness, under the
/// witness's own DID and key — never the registry's receipt key (§5,
/// §12). Witnesses are independent parties (§3).
///
/// Key lifecycle (RFC-ACDP-0015 §9, the RFC-ACDP-0010 §9 rule applied to
/// the witness's own key): retired witness keys remain in the witness DID
/// document's `verificationMethod` indefinitely so historical
/// cosignatures stay verifiable; rotation removes a key from
/// `assertionMethod` only.
pub struct WitnessSigner {
    key: acdp_crypto::sign::AcdpSigningKey,
    /// e.g. `did:web:witness.example.org#witness-key-1`.
    key_id: String,
    /// e.g. `did:web:witness.example.org`.
    witness_id: String,
}

impl WitnessSigner {
    /// Create a witness signer. `witness_id` MUST be a `did:web` or
    /// `did:key` DID; `key_id`'s DID portion MUST equal `witness_id` and
    /// carry a non-empty fragment.
    pub fn new(
        key: impl Into<acdp_crypto::sign::AcdpSigningKey>,
        witness_id: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Result<Self, AcdpError> {
        let witness_id = witness_id.into();
        let key_id = key_id.into();
        if !is_witness_did(&witness_id) {
            return Err(AcdpError::SchemaViolation(format!(
                "witness signer witness_id must be did:web or did:key, got '{witness_id}'"
            )));
        }
        match key_id.split_once('#') {
            Some((did, frag)) if did == witness_id && !frag.is_empty() => {}
            _ => {
                return Err(AcdpError::SchemaViolation(format!(
                    "witness signer key_id '{key_id}' must be '<witness_id>#<fragment>'"
                )));
            }
        }
        Ok(Self {
            key: key.into(),
            key_id,
            witness_id,
        })
    }

    /// The witness DID this signer mints under.
    pub fn witness_id(&self) -> &str {
        &self.witness_id
    }

    /// The DID URL the witness signing key is published under (e.g.
    /// `did:web:witness.example.org#witness-key-1`).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Mint a signed cosignature over an observed checkpoint
    /// (RFC-ACDP-0015 §5, §7 step 3): copy the checkpoint's
    /// `{log_id, tree_size, root_hash, timestamp}` verbatim into
    /// `witnessed_checkpoint`, stamp `witnessed_at` (truncated here to
    /// milliseconds) from the witness's own clock, and sign with the
    /// witness key.
    ///
    /// This is the **raw** mint — it performs no witness obligation
    /// (§7): it does not verify the checkpoint's own signature or its
    /// consistency against a retained head. Callers acting as a
    /// production witness MUST use the `client` feature's
    /// `mint_cosignature_checked` (which runs the §7 obligation first),
    /// or run those checks themselves. A witness that cosigns a
    /// checkpoint failing consistency provides negative security value
    /// (§7).
    pub fn mint(
        &self,
        checkpoint: &LogCheckpoint,
        witnessed_at: DateTime<Utc>,
    ) -> Result<LogCosignature, AcdpError> {
        let mut cosig = LogCosignature {
            cosignature_version: COSIGNATURE_VERSION.to_string(),
            witness_id: self.witness_id.clone(),
            witnessed_checkpoint: WitnessedCheckpoint::from_checkpoint(checkpoint),
            witnessed_at: acdp_primitives::time::trunc_ms(witnessed_at),
            signature: Signature {
                algorithm: self.key.algorithm().into(),
                key_id: self.key_id.clone(),
                value: String::new(), // filled below
            },
        };
        let hash = cosig.preimage_hash()?;
        let (algorithm, value) = self.key.sign_content_hash(&hash);
        cosig.signature.algorithm = algorithm.into();
        cosig.signature.value = value;
        Ok(cosig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::ReceiptSigner;
    use acdp_crypto::SigningKey;

    const REGISTRY_DID: &str = "did:web:registry.example.com";
    const LOG_ID: &str = "did:web:registry.example.com/log/1";
    const WITNESS_DID: &str = "did:web:witness.example.org";

    fn checkpoint() -> LogCheckpoint {
        let root = crate::log::encode_sha256_hex(&acdp_crypto::merkle_tree_hash(&[]));
        ReceiptSigner::new(
            SigningKey::from_bytes(&[0x11u8; 32]),
            REGISTRY_DID,
            format!("{REGISTRY_DID}#receipt-key-1"),
        )
        .unwrap()
        .mint_log_checkpoint(LOG_ID, 0, &root, Utc::now())
        .unwrap()
    }

    fn witness_signer() -> WitnessSigner {
        WitnessSigner::new(
            SigningKey::from_bytes(&[0x33u8; 32]),
            WITNESS_DID,
            format!("{WITNESS_DID}#witness-key-1"),
        )
        .unwrap()
    }

    fn witness_pub() -> [u8; 32] {
        SigningKey::from_bytes(&[0x33u8; 32]).verifying_key_bytes()
    }

    #[test]
    fn mint_verify_round_trip() {
        let cp = checkpoint();
        let cosig = witness_signer().mint(&cp, Utc::now()).unwrap();
        assert_eq!(cosig.cosignature_version, COSIGNATURE_VERSION);
        cosig
            .verify_signature_with_key(Some(&witness_pub()), None)
            .expect("freshly minted cosignature must verify");

        // Wire round trip through the closed parse; raw and struct
        // preimages agree.
        let wire = serde_json::to_value(&cosig).unwrap();
        let parsed = LogCosignature::from_value(&wire).unwrap();
        assert_eq!(
            LogCosignature::preimage_hash_of_value(&wire).unwrap(),
            cosig.preimage_hash().unwrap()
        );
        parsed
            .verify_signature_with_key(Some(&witness_pub()), None)
            .unwrap();
        parsed.cross_check_against_checkpoint(&cp).unwrap();
        parsed
            .check_witnessed_at_skew(Utc::now(), chrono::Duration::seconds(120))
            .unwrap();
    }

    /// Closed schema + domain separation: an unknown member, a wrong
    /// `cosignature_version`, or a non-canonical timestamp all fail the
    /// parse.
    #[test]
    fn closed_schema_and_domain_separation() {
        let cosig = witness_signer().mint(&checkpoint(), Utc::now()).unwrap();

        let mut wire = serde_json::to_value(&cosig).unwrap();
        wire.as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::json!(1));
        assert!(matches!(
            LogCosignature::from_value(&wire).unwrap_err(),
            AcdpError::InvalidWitnessCosignature(_)
        ));

        let mut wire = serde_json::to_value(&cosig).unwrap();
        wire["cosignature_version"] = serde_json::json!("acdp-cosig/2");
        assert!(LogCosignature::from_value(&wire).is_err());

        // A cosignature never parses as a checkpoint and vice versa.
        let wire = serde_json::to_value(&cosig).unwrap();
        assert!(LogCheckpoint::from_value(&wire).is_err());

        let mut wire = serde_json::to_value(&cosig).unwrap();
        wire["witnessed_at"] = serde_json::json!("2026-07-04T12:00:05Z");
        assert!(LogCosignature::from_value(&wire).is_err());
    }

    /// Tampering any signed field breaks the signature (wit-004 shape at
    /// the type level).
    #[test]
    fn tampered_fields_fail_verification() {
        let pubkey = witness_pub();
        let base = witness_signer().mint(&checkpoint(), Utc::now()).unwrap();

        let mut c = base.clone();
        c.witnessed_at += chrono::Duration::milliseconds(1);
        assert!(c.verify_signature_with_key(Some(&pubkey), None).is_err());

        let mut c = base.clone();
        c.witnessed_checkpoint.tree_size += 1;
        assert!(c.verify_signature_with_key(Some(&pubkey), None).is_err());

        // Key mismatch: witness B's key over witness A's body.
        let wrong = SigningKey::from_bytes(&[0x44u8; 32]).verifying_key_bytes();
        assert!(base.verify_signature_with_key(Some(&wrong), None).is_err());
    }

    /// §8 step 4 checkpoint binding fires on a different tuple; §8 step 3
    /// witness binding fires on a foreign key_id DID.
    #[test]
    fn cross_checks_fire() {
        let cp = checkpoint();
        let cosig = witness_signer().mint(&cp, Utc::now()).unwrap();
        cosig.cross_check_against_checkpoint(&cp).unwrap();

        // A checkpoint at a different size / root is a different tuple.
        let root5 = crate::log::encode_sha256_hex(&[0xabu8; 32]);
        let other = ReceiptSigner::new(
            SigningKey::from_bytes(&[0x11u8; 32]),
            REGISTRY_DID,
            format!("{REGISTRY_DID}#receipt-key-1"),
        )
        .unwrap()
        .mint_log_checkpoint(LOG_ID, 5, &root5, Utc::now())
        .unwrap();
        assert!(matches!(
            cosig.cross_check_against_checkpoint(&other).unwrap_err(),
            AcdpError::InvalidWitnessCosignature(_)
        ));

        // Foreign key_id DID → witness binding fails at parse.
        let mut wire = serde_json::to_value(&cosig).unwrap();
        wire["signature"]["key_id"] = serde_json::json!("did:web:evil.example#k");
        assert!(LogCosignature::from_value(&wire).is_err());
    }

    #[test]
    fn signer_rejects_malformed_identity() {
        // Non-witness DID form.
        assert!(WitnessSigner::new(
            SigningKey::from_bytes(&[0x33u8; 32]),
            "not-a-did",
            "not-a-did#k",
        )
        .is_err());
        // key_id DID ≠ witness_id.
        assert!(WitnessSigner::new(
            SigningKey::from_bytes(&[0x33u8; 32]),
            WITNESS_DID,
            "did:web:other.example.org#k",
        )
        .is_err());
        // No fragment.
        assert!(WitnessSigner::new(
            SigningKey::from_bytes(&[0x33u8; 32]),
            WITNESS_DID,
            WITNESS_DID,
        )
        .is_err());
        // did:key witness is accepted.
        assert!(WitnessSigner::new(
            SigningKey::from_bytes(&[0x33u8; 32]),
            "did:key:z6MkExample",
            "did:key:z6MkExample#z6MkExample",
        )
        .is_ok());
    }

    /// An old cosignature passes step 5 — staleness is policy, not a
    /// verification failure; a future-dated one fails.
    #[test]
    fn witnessed_at_skew_and_age() {
        let cosig = witness_signer().mint(&checkpoint(), Utc::now()).unwrap();
        let skew = chrono::Duration::seconds(120);

        let now = cosig.witnessed_at + chrono::Duration::seconds(3600);
        cosig
            .check_witnessed_at_skew(now, skew)
            .expect("stale is not a step-5 failure");
        assert_eq!(cosig.age_at(now), chrono::Duration::seconds(3600));

        let now = cosig.witnessed_at - chrono::Duration::seconds(300);
        assert!(cosig.check_witnessed_at_skew(now, skew).is_err());
    }
}
