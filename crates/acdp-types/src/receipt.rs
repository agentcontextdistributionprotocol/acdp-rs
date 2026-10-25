//! Registry receipts (ACDP 0.2, RFC-ACDP-0010 — promoted from the
//! RFC-ACDP-0009 §2.7 reservation).
//!
//! A receipt is a **registry-signed attestation** binding the
//! registry-assigned identifiers (`ctx_id`, `lineage_id`,
//! `origin_registry`, `created_at`) and the resolved producer key
//! (`key_fingerprint`) to the producer's `content_hash`. It closes the
//! two v0.1.0 trust gaps documented in RFC-ACDP-0008 §9:
//!
//! - **Registry honesty (§9.1)** — without a receipt, a malicious
//!   registry can republish signed content under a different `ctx_id`
//!   or backdate `created_at` and producer-signature verification
//!   still passes. A receipt makes those claims attributable and
//!   non-repudiable (though not unforgeable at mint time — a registry
//!   can still lie when it first issues; the transparency log reserved
//!   by RFC-ACDP-0009 §2.11 is the next layer).
//! - **Historical key validity (§9.3)** — `key_fingerprint` records
//!   *which* producer key the registry resolved and verified at publish
//!   time, so consumers can verify old contexts after the producer
//!   rotates.
//!
//! ## Signing construction
//!
//! Deliberately identical to the producer signature (RFC-ACDP-0001
//! §5.8): the preimage is the JCS-canonicalized receipt object **minus
//! the `signature` field only** (no §5.7 exclusion set — the
//! registry-assigned fields are the entire point), hashed with SHA-256,
//! and the signature is over the **ASCII bytes of the
//! `"sha256:<hex>"` string**, not the raw digest.

use crate::body::Signature;
use acdp_jcs::try_canonicalize_value;
use acdp_primitives::error::AcdpError;
use acdp_primitives::primitives::{ContentHash, CtxId, LineageId, Status};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The lineage-head receipt envelope version (RFC-ACDP-0011 §4).
/// Doubles as an in-preimage domain separator: a head receipt can never
/// be mistaken for (or replayed as) an RFC-ACDP-0010 context receipt,
/// whose preimage carries no such member.
pub const LINEAGE_HEAD_RECEIPT_VERSION: &str = "acdp-lhr/1";

/// Shared RFC-ACDP-0010 §5 preimage hash over an object map: remove the
/// `signature` member, JCS-canonicalize, SHA-256. The one construction
/// shared by both receipt kinds (RFC-ACDP-0011 §5), log checkpoints
/// (RFC-ACDP-0012 §6), and lifecycle events (RFC-ACDP-0013 §5) —
/// implementations MUST NOT introduce a second canonicalization or
/// signing-input framing.
pub(crate) fn preimage_hash_of_map(
    mut map: serde_json::Map<String, serde_json::Value>,
) -> Result<ContentHash, AcdpError> {
    map.remove("signature");
    let canonical = try_canonicalize_value(&serde_json::Value::Object(map))?;
    let digest = Sha256::digest(&canonical);
    Ok(ContentHash(format!("sha256:{}", hex::encode(digest))))
}

/// Preimage hash of a JSON value, with the verdict-appropriate error
/// mapping for the not-an-object case (`InvalidReceipt` for receipts,
/// `InvalidLogProof` for log checkpoints — the verdicts are independent
/// per RFC-ACDP-0012 §9.3).
pub(crate) fn preimage_hash_of_object_with(
    value: &serde_json::Value,
    what: &str,
    mk_err: fn(String) -> AcdpError,
) -> Result<ContentHash, AcdpError> {
    let map = value
        .as_object()
        .cloned()
        .ok_or_else(|| mk_err(format!("{what} must be a JSON object")))?;
    preimage_hash_of_map(map)
}

/// RFC-ACDP-0010 §5 / RFC-ACDP-0011 §5 preimage hash with the
/// receipt-verdict error mapping.
fn preimage_hash_of_object(
    value: &serde_json::Value,
    what: &str,
) -> Result<ContentHash, AcdpError> {
    preimage_hash_of_object_with(value, what, AcdpError::InvalidReceipt)
}

/// Shared signature check over an already-computed preimage hash. All
/// registry-signed objects (context receipts, head receipts, log
/// checkpoints) use the identical RFC-ACDP-0010 §5 construction: the
/// signature is over the ASCII bytes of the full `"sha256:<hex>"`
/// string. `mk_err` selects the verdict (`InvalidReceipt` vs
/// `InvalidLogProof`); `what` names the object in messages.
pub(crate) fn verify_signature_over_hash_with(
    signature: &Signature,
    hash: &ContentHash,
    registry_pub_ed25519: Option<&[u8; 32]>,
    registry_pub_p256_sec1: Option<&[u8]>,
    what: &str,
    mk_err: fn(String) -> AcdpError,
) -> Result<(), AcdpError> {
    match signature.algorithm.as_str() {
        "ed25519" => {
            let key = registry_pub_ed25519.ok_or_else(|| {
                mk_err(format!(
                    "{what} declares ed25519 but no ed25519 registry key was resolved"
                ))
            })?;
            acdp_crypto::verify::verify_ed25519(key, &signature.value, hash.as_str())
                .map_err(|e| mk_err(format!("{what} signature: {e}")))
        }
        "ecdsa-p256" => {
            let key = registry_pub_p256_sec1.ok_or_else(|| {
                mk_err(format!(
                    "{what} declares ecdsa-p256 but no p256 registry key was resolved"
                ))
            })?;
            acdp_crypto::verify::verify_ecdsa_p256(key, &signature.value, hash.as_str())
                .map_err(|e| mk_err(format!("{what} signature: {e}")))
        }
        other => Err(mk_err(format!(
            "{what} signature algorithm '{other}' is not supported"
        ))),
    }
}

/// Both receipt kinds' signature check, with the receipt-verdict error
/// mapping.
fn verify_receipt_signature_over_hash(
    signature: &Signature,
    hash: &ContentHash,
    registry_pub_ed25519: Option<&[u8; 32]>,
    registry_pub_p256_sec1: Option<&[u8]>,
) -> Result<(), AcdpError> {
    verify_signature_over_hash_with(
        signature,
        hash,
        registry_pub_ed25519,
        registry_pub_p256_sec1,
        "receipt",
        AcdpError::InvalidReceipt,
    )
}

/// True when `raw` is canonical millisecond-precision RFC 3339 UTC with
/// exactly three fractional digits and a literal `Z`
/// (`YYYY-MM-DDTHH:MM:SS.mmmZ`, RFC-ACDP-0001 §5.3).
pub(crate) fn is_canonical_ms_utc(raw: &str) -> bool {
    let b = raw.as_bytes();
    b.len() == 24
        && b[10] == b'T'
        && b[19] == b'.'
        && b[23] == b'Z'
        && b[20..23].iter().all(u8::is_ascii_digit)
        && chrono::DateTime::parse_from_rfc3339(raw).is_ok()
}

/// Receipt-key status (RFC-ACDP-0010 §8 step 1, 0.5.0).
///
/// From a consumer's vantage a retired receipt key and a key that was
/// never a receipt key look the same, so the status is reported rather
/// than inferred: a receipt verified under a [`Self::Historical`] key
/// MUST NOT be presented as a currently-authorized registry attestation,
/// and under the strict profile it cannot place a revoked-key context
/// before the compromise boundary (RFC-ACDP-0014 §7 step 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReceiptKeyStatus {
    /// The receipt key is referenced by the registry DID document's
    /// `assertionMethod`.
    Current,
    /// The receipt key is present in `verificationMethod` only.
    Historical,
}

/// A registry-signed publication receipt.
///
/// CLOSED schema (RFC-ACDP-0010 §4, `additionalProperties: false`):
/// a receipt has exactly the eight specified members. Future receipt
/// fields require a schema bump, not field-level extensibility —
/// unknown members are rejected at parse time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryReceipt {
    /// The registry's own identity — MUST be `did:web:<authority>`
    /// where `<authority>` is the authority the context is served from.
    pub registry_did: String,
    /// The ctx_id this receipt attests.
    pub ctx_id: CtxId,
    /// The lineage the registry assigned.
    pub lineage_id: LineageId,
    /// The registry's authority (bare hostname form).
    pub origin_registry: String,
    /// Publication acceptance time. Canonical millisecond-precision
    /// RFC 3339 UTC, always serialized with exactly three fractional
    /// digits (`…SS.mmmZ`, RFC-ACDP-0010 §8 step 6) — chrono's default
    /// drops trailing zeros, which would change the preimage bytes.
    #[serde(with = "ms_rfc3339")]
    pub created_at: DateTime<Utc>,
    /// The producer's content hash this receipt binds.
    pub content_hash: ContentHash,
    /// Fingerprint of the producer key the registry resolved and
    /// verified at publish time (see [`acdp_crypto::fingerprint`]).
    pub key_fingerprint: String,
    /// Registry signature over the receipt preimage.
    pub signature: Signature,
}

/// Fixed three-digit-millisecond RFC 3339 serde for registry-signed
/// timestamps (`created_at`, `as_of`, log-checkpoint `timestamp`;
/// RFC-ACDP-0010 §8 step 6: `…T…SS.mmmZ`).
pub(crate) mod ms_rfc3339 {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&raw)
            .map(|t| t.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }
}

impl RegistryReceipt {
    /// Parse a receipt from the opaque JSON value carried in
    /// [`crate::body::FullContext::registry_receipt`].
    pub fn from_value(value: &serde_json::Value) -> Result<Self, AcdpError> {
        Self::deserialize(value)
            .map_err(|e| AcdpError::InvalidReceipt(format!("registry_receipt does not parse: {e}")))
    }

    /// Compute the preimage hash from the RAW wire JSON of a receipt
    /// (the value minus `signature`, canonicalized as received).
    ///
    /// Verifiers MUST hash the receipt exactly as received rather than
    /// re-serializing a parsed struct — the same "hash verification
    /// over raw JSON" rule as RFC-ACDP-0001 §6 bodies. Re-serialization
    /// can normalize byte details (e.g. timestamp fraction digits) and
    /// falsely fail an honest receipt.
    pub fn preimage_hash_of_value(value: &serde_json::Value) -> Result<ContentHash, AcdpError> {
        preimage_hash_of_object(value, "receipt")
    }

    /// Validate the §8 step 6 byte form of the receipt's raw
    /// `created_at`: canonical millisecond-precision RFC 3339 UTC with
    /// exactly three fractional digits and a literal `Z`.
    pub fn validate_created_at_form(value: &serde_json::Value) -> Result<(), AcdpError> {
        let raw = value
            .get("created_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AcdpError::InvalidReceipt("receipt created_at missing or not a string".into())
            })?;
        if !is_canonical_ms_utc(raw) {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt created_at '{raw}' is not canonical millisecond-precision \
                 RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SS.mmmZ`, RFC-ACDP-0010 §8 step 6)"
            )));
        }
        Ok(())
    }

    /// §8 step 3 body bindings: `lineage_id`, `origin_registry`, and
    /// `created_at` MUST equal the corresponding fields of the
    /// accompanying body. (`ctx_id` is bound separately against the
    /// *requested* identifier in [`Self::cross_check`].)
    pub fn cross_check_body(&self, body: &crate::body::Body) -> Result<(), AcdpError> {
        if self.lineage_id != body.lineage_id {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt lineage_id '{}' ≠ body lineage_id '{}'",
                self.lineage_id, body.lineage_id
            )));
        }
        if self.origin_registry != body.origin_registry {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt origin_registry '{}' ≠ body origin_registry '{}'",
                self.origin_registry, body.origin_registry
            )));
        }
        if self.created_at != body.created_at {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt created_at '{}' ≠ body created_at '{}'",
                self.created_at, body.created_at
            )));
        }
        Ok(())
    }

    /// Compute the receipt's signature preimage hash: SHA-256 over the
    /// JCS canonical form of the receipt **minus `signature` only**.
    ///
    /// Struct-based form, used at MINT time (the struct's serializer
    /// emits the canonical three-digit-millisecond `created_at`).
    /// Verifiers should prefer [`Self::preimage_hash_of_value`] over
    /// the raw wire JSON.
    pub fn preimage_hash(&self) -> Result<ContentHash, AcdpError> {
        Self::preimage_hash_of_value(&serde_json::to_value(self)?)
    }

    /// Verify the receipt signature against a known registry public
    /// key (pure — no DID resolution; the `client` feature's
    /// `verify_receipt_value` resolves the registry DID and calls
    /// this).
    pub fn verify_signature_with_key(
        &self,
        registry_pub_ed25519: Option<&[u8; 32]>,
        registry_pub_p256_sec1: Option<&[u8]>,
    ) -> Result<(), AcdpError> {
        let hash = self.preimage_hash()?;
        self.verify_signature_against_hash(&hash, registry_pub_ed25519, registry_pub_p256_sec1)
    }

    /// Like [`Self::verify_signature_with_key`] but over an
    /// already-computed preimage hash — pair with
    /// [`Self::preimage_hash_of_value`] for raw-JSON verification.
    pub fn verify_signature_against_hash(
        &self,
        hash: &ContentHash,
        registry_pub_ed25519: Option<&[u8; 32]>,
        registry_pub_p256_sec1: Option<&[u8]>,
    ) -> Result<(), AcdpError> {
        verify_receipt_signature_over_hash(
            &self.signature,
            hash,
            registry_pub_ed25519,
            registry_pub_p256_sec1,
        )
    }

    /// The pure (offline) subset of the RFC-ACDP-0010 cross-checks —
    /// everything except registry-DID resolution and the
    /// served-authority comparison, which need the `client` feature:
    ///
    /// - `ctx_id` equals the requested one.
    /// - `content_hash` equals the *independently recomputed* body hash
    ///   (pass the recomputed value, never the body's echoed field).
    /// - `key_fingerprint` equals the fingerprint of the resolved
    ///   producer key.
    /// - `created_at` is millisecond-truncated.
    /// - `registry_did` is `did:web:<origin_registry>` (internal
    ///   consistency; the serving-authority comparison is the client's
    ///   job).
    pub fn cross_check(
        &self,
        expected_ctx_id: &CtxId,
        recomputed_body_hash: &ContentHash,
        producer_key_fingerprint: &str,
    ) -> Result<(), AcdpError> {
        if &self.ctx_id != expected_ctx_id {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt ctx_id '{}' ≠ requested '{expected_ctx_id}'",
                self.ctx_id
            )));
        }
        if &self.content_hash != recomputed_body_hash {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt content_hash '{}' ≠ recomputed body hash '{recomputed_body_hash}'",
                self.content_hash
            )));
        }
        if self.key_fingerprint != producer_key_fingerprint {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt key_fingerprint '{}' ≠ resolved producer key '{producer_key_fingerprint}'",
                self.key_fingerprint
            )));
        }
        if !self
            .created_at
            .timestamp_subsec_nanos()
            .is_multiple_of(1_000_000)
        {
            return Err(AcdpError::InvalidReceipt(
                "receipt created_at is not millisecond-truncated (RFC-ACDP-0001 §5.3)".into(),
            ));
        }
        let expected_did = acdp_did::web::authority_to_did_web(&self.origin_registry);
        if self.registry_did != expected_did {
            return Err(AcdpError::InvalidReceipt(format!(
                "receipt registry_did '{}' ≠ did:web form of origin_registry ('{expected_did}')",
                self.registry_did
            )));
        }
        Ok(())
    }
}

// ── Lineage-head receipts (ACDP 0.3, RFC-ACDP-0011) ──────────────────────────

/// A registry-signed **lineage-head receipt** (RFC-ACDP-0011): the
/// registry's attestation that, as of `as_of`, the head of `lineage_id`
/// was `head_ctx_id` at `head_version` with `head_status`.
///
/// CLOSED schema (`acdp-lineage-head-receipt.schema.json`,
/// `additionalProperties: false`): every member is signed, so an
/// unknown member changes the preimage and is rejected at parse time.
/// The signing construction reuses RFC-ACDP-0010 §5 verbatim — JCS of
/// the object minus `signature`, SHA-256, signature over the ASCII
/// bytes of `"sha256:<hex>"` — with `receipt_version` acting as the
/// in-preimage domain separator.
///
/// Unlike [`RegistryReceipt`], head receipts are **ephemeral**: the
/// head moves on every supersession, so a registry mints a fresh
/// receipt (fresh `as_of`) per `/current` response (RFC-ACDP-0011 §6).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageHeadReceipt {
    /// MUST be exactly [`LINEAGE_HEAD_RECEIPT_VERSION`] (`"acdp-lhr/1"`).
    pub receipt_version: String,
    /// The attesting registry's DID — `did:web:<authority>` where
    /// `<authority>` is the registry's serving authority
    /// (RFC-ACDP-0011 §4, did:web-only as RFC-ACDP-0010 §4).
    pub registry_did: String,
    /// The attested lineage (RFC-ACDP-0001 §5.6).
    pub lineage_id: LineageId,
    /// The `ctx_id` of the head version. Its authority MUST equal the
    /// method-specific identifier of `registry_did` (lineages are
    /// single-registry, RFC-ACDP-0004 §5.3).
    pub head_ctx_id: CtxId,
    /// The head's `body.version` (≥ 1).
    pub head_version: u32,
    /// The head's registry-derived status at `as_of` (RFC-ACDP-0004
    /// §4). Never `superseded` — a superseded version is never the
    /// head — and never `retracted` (RFC-ACDP-0013 §8.3: a retracted
    /// version is never served as head); in practice `active` or
    /// `expired`. Kept as the raw wire string so byte-for-byte
    /// comparison with the served `registry_state.status` is exact
    /// (RFC-ACDP-0011 §7 step 5).
    pub head_status: String,
    /// Registry response-time clock when the head claim was evaluated.
    /// Canonical millisecond-precision RFC 3339 UTC, always serialized
    /// with exactly three fractional digits (RFC-ACDP-0001 §5.3).
    #[serde(with = "ms_rfc3339")]
    pub as_of: DateTime<Utc>,
    /// Registry signature over the receipt preimage — same envelope and
    /// same receipt signing key as RFC-ACDP-0010 §4/§5.
    pub signature: Signature,
}

impl LineageHeadReceipt {
    /// Parse a head receipt from the JSON value carried in
    /// [`crate::body::FullContext::lineage_head_receipt`], enforcing
    /// the closed schema plus the RFC-ACDP-0011 §4 semantic invariants
    /// (§7 step 1): exact `receipt_version`, `head_version ≥ 1`,
    /// `head_status` pattern and never `superseded`, `did:web`-only
    /// `registry_did`, canonical millisecond `as_of` byte form.
    pub fn from_value(value: &serde_json::Value) -> Result<Self, AcdpError> {
        let receipt = Self::deserialize(value).map_err(|e| {
            AcdpError::InvalidReceipt(format!("lineage_head_receipt does not parse: {e}"))
        })?;
        if receipt.receipt_version != LINEAGE_HEAD_RECEIPT_VERSION {
            return Err(AcdpError::InvalidReceipt(format!(
                "lineage_head_receipt receipt_version '{}' ≠ '{LINEAGE_HEAD_RECEIPT_VERSION}' \
                 (RFC-ACDP-0011 §4)",
                receipt.receipt_version
            )));
        }
        if receipt.head_version < 1 {
            return Err(AcdpError::InvalidReceipt(
                "lineage_head_receipt head_version must be >= 1".into(),
            ));
        }
        // Status pattern (RFC-ACDP-0004 §4.1) and the §4 rule that a
        // superseded version is never the head — nor a retracted one
        // (RFC-ACDP-0013 §8.3: never served as head).
        let status = Status::parse(&receipt.head_status).map_err(|e| {
            AcdpError::InvalidReceipt(format!("lineage_head_receipt head_status: {e}"))
        })?;
        if matches!(status, Status::Superseded | Status::Retracted) {
            return Err(AcdpError::InvalidReceipt(format!(
                "lineage_head_receipt head_status must never be '{}' \
                 (RFC-ACDP-0011 §4: a superseded version is never the head; \
                 RFC-ACDP-0013 §8.3: a retracted version is never served as head)",
                receipt.head_status
            )));
        }
        if !receipt.registry_did.starts_with("did:web:") {
            return Err(AcdpError::InvalidReceipt(format!(
                "lineage_head_receipt registry_did '{}' must be did:web \
                 (RFC-ACDP-0011 §4)",
                receipt.registry_did
            )));
        }
        // §4 byte form of the RAW wire `as_of`, checked before any
        // parsing normalization.
        Self::validate_as_of_form(value)?;
        Ok(receipt)
    }

    /// Compute the preimage hash from the RAW wire JSON of a head
    /// receipt (the value minus `signature`, canonicalized as
    /// received). Verifiers MUST hash the receipt exactly as received —
    /// same raw-JSON rule as [`RegistryReceipt::preimage_hash_of_value`].
    pub fn preimage_hash_of_value(value: &serde_json::Value) -> Result<ContentHash, AcdpError> {
        preimage_hash_of_object(value, "lineage_head_receipt")
    }

    /// Validate the §4 byte form of the raw `as_of`: canonical
    /// millisecond-precision RFC 3339 UTC with exactly three fractional
    /// digits and a literal `Z`.
    pub fn validate_as_of_form(value: &serde_json::Value) -> Result<(), AcdpError> {
        let raw = value.get("as_of").and_then(|v| v.as_str()).ok_or_else(|| {
            AcdpError::InvalidReceipt("lineage_head_receipt as_of missing or not a string".into())
        })?;
        if !is_canonical_ms_utc(raw) {
            return Err(AcdpError::InvalidReceipt(format!(
                "lineage_head_receipt as_of '{raw}' is not canonical millisecond-precision \
                 RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SS.mmmZ`, RFC-ACDP-0011 §4)"
            )));
        }
        Ok(())
    }

    /// Compute the receipt's signature preimage hash from the struct.
    /// Used at MINT time; verifiers should prefer
    /// [`Self::preimage_hash_of_value`] over the raw wire JSON.
    pub fn preimage_hash(&self) -> Result<ContentHash, AcdpError> {
        Self::preimage_hash_of_value(&serde_json::to_value(self)?)
    }

    /// Verify the receipt signature against a known registry public key
    /// (pure — no DID resolution; the `client` feature's
    /// `verify_lineage_head_receipt_value` resolves the registry DID and
    /// calls this).
    pub fn verify_signature_with_key(
        &self,
        registry_pub_ed25519: Option<&[u8; 32]>,
        registry_pub_p256_sec1: Option<&[u8]>,
    ) -> Result<(), AcdpError> {
        let hash = self.preimage_hash()?;
        self.verify_signature_against_hash(&hash, registry_pub_ed25519, registry_pub_p256_sec1)
    }

    /// Like [`Self::verify_signature_with_key`] but over an
    /// already-computed preimage hash — pair with
    /// [`Self::preimage_hash_of_value`] for raw-JSON verification.
    pub fn verify_signature_against_hash(
        &self,
        hash: &ContentHash,
        registry_pub_ed25519: Option<&[u8; 32]>,
        registry_pub_p256_sec1: Option<&[u8]>,
    ) -> Result<(), AcdpError> {
        verify_receipt_signature_over_hash(
            &self.signature,
            hash,
            registry_pub_ed25519,
            registry_pub_p256_sec1,
        )
    }

    /// RFC-ACDP-0011 §7 step 3 — registry binding (pure):
    ///
    /// - `registry_did` equals `did:web:<serving_authority>` — the
    ///   authority the response was actually fetched from;
    /// - `registry_did` equals `capabilities.registry_did`;
    /// - the DID portion of `signature.key_id` equals `registry_did`;
    /// - the authority component of `head_ctx_id` equals the
    ///   method-specific identifier of `registry_did` (lineages are
    ///   single-registry).
    pub fn cross_check_registry_binding(
        &self,
        serving_authority: &str,
        capabilities_registry_did: &str,
    ) -> Result<(), AcdpError> {
        let expected_did = acdp_did::web::authority_to_did_web(serving_authority);
        if self.registry_did != expected_did {
            return Err(AcdpError::InvalidReceipt(format!(
                "lineage_head_receipt registry_did '{}' ≠ serving authority's DID \
                 '{expected_did}' (RFC-ACDP-0011 §7 step 3)",
                self.registry_did
            )));
        }
        if self.registry_did != capabilities_registry_did {
            return Err(AcdpError::InvalidReceipt(format!(
                "lineage_head_receipt registry_did '{}' ≠ capabilities.registry_did \
                 '{capabilities_registry_did}' (RFC-ACDP-0011 §7 step 3)",
                self.registry_did
            )));
        }
        match self.signature.key_id.split_once('#') {
            Some((did, frag)) if did == self.registry_did && !frag.is_empty() => {}
            _ => {
                return Err(AcdpError::InvalidReceipt(format!(
                    "lineage_head_receipt signature.key_id '{}' is not a DID URL under \
                     registry_did '{}' (RFC-ACDP-0011 §7 step 3)",
                    self.signature.key_id, self.registry_did
                )));
            }
        }
        let head_authority_did = acdp_did::web::authority_to_did_web(self.head_ctx_id.authority());
        if head_authority_did != self.registry_did {
            return Err(AcdpError::InvalidReceipt(format!(
                "lineage_head_receipt head_ctx_id authority '{}' ≠ registry_did '{}' \
                 (RFC-ACDP-0011 §7 step 3: lineages are single-registry)",
                self.head_ctx_id.authority(),
                self.registry_did
            )));
        }
        Ok(())
    }

    /// RFC-ACDP-0011 §7 step 4 — lineage binding: `lineage_id` MUST
    /// equal the lineage the consumer requested (on `/current`) or the
    /// accompanying `body.lineage_id` (on full retrieval), byte-for-byte.
    pub fn cross_check_lineage(&self, requested: &LineageId) -> Result<(), AcdpError> {
        if &self.lineage_id != requested {
            return Err(AcdpError::InvalidReceipt(format!(
                "lineage_head_receipt lineage_id '{}' ≠ requested lineage '{requested}' \
                 (RFC-ACDP-0011 §7 step 4)",
                self.lineage_id
            )));
        }
        Ok(())
    }

    /// RFC-ACDP-0011 §7 steps 5 / 5b — head binding against the
    /// accompanying response.
    ///
    /// `on_current_endpoint = true` for `GET /lineages/{id}/current`,
    /// where the receipt MUST describe the very head being served
    /// (step 5 byte-match, fixture `lhr-002`). On full retrieval the
    /// step-5 match applies when `head_ctx_id` equals the retrieved
    /// `ctx_id`; otherwise the receipt claims the retrieved context is
    /// stale and step 5b's consistency rule applies (`head_version`
    /// strictly greater, served status `superseded` — or `retracted`
    /// on a registry also advertising `acdp-registry-lifecycle`, per
    /// the RFC-ACDP-0013 §7.2 precedence).
    pub fn cross_check_head(
        &self,
        served_ctx_id: &CtxId,
        served_version: u32,
        served_status: &Status,
        on_current_endpoint: bool,
    ) -> Result<(), AcdpError> {
        if on_current_endpoint || &self.head_ctx_id == served_ctx_id {
            if &self.head_ctx_id != served_ctx_id {
                return Err(AcdpError::InvalidReceipt(format!(
                    "lineage_head_receipt head_ctx_id '{}' ≠ served ctx_id '{served_ctx_id}' \
                     (RFC-ACDP-0011 §7 step 5: /current must serve the attested head)",
                    self.head_ctx_id
                )));
            }
            if self.head_version != served_version {
                return Err(AcdpError::InvalidReceipt(format!(
                    "lineage_head_receipt head_version {} ≠ served body.version \
                     {served_version} (RFC-ACDP-0011 §7 step 5)",
                    self.head_version
                )));
            }
            if self.head_status != served_status.as_str() {
                return Err(AcdpError::InvalidReceipt(format!(
                    "lineage_head_receipt head_status '{}' ≠ served registry_state.status \
                     '{}' (RFC-ACDP-0011 §7 step 5)",
                    self.head_status,
                    served_status.as_str()
                )));
            }
            return Ok(());
        }
        // Step 5b: full retrieval of a non-head version.
        if self.head_version <= served_version {
            return Err(AcdpError::InvalidReceipt(format!(
                "lineage_head_receipt names a different head '{}' but head_version {} is \
                 not greater than the served body.version {served_version} \
                 (RFC-ACDP-0011 §7 step 5b)",
                self.head_ctx_id, self.head_version
            )));
        }
        let non_head_served = matches!(served_status, Status::Superseded | Status::Retracted);
        if !non_head_served {
            return Err(AcdpError::InvalidReceipt(format!(
                "lineage_head_receipt names a different head '{}' but the served context's \
                 status is '{}', not 'superseded' (or 'retracted', RFC-ACDP-0013 §7.2) — \
                 self-contradictory response (RFC-ACDP-0011 §7 step 5b)",
                self.head_ctx_id,
                served_status.as_str()
            )));
        }
        Ok(())
    }

    /// RFC-ACDP-0011 §7 step 6 — `as_of` sanity against the consumer's
    /// clock: millisecond-truncated (RFC-ACDP-0001 §5.3) and not in the
    /// future beyond `max_clock_skew` (RECOMMENDED 120 s). A
    /// future-dated `as_of` is a forged freshness claim (fixture
    /// `lhr-004`).
    ///
    /// Note this is the *verification* half only. Staleness (an old but
    /// honest `as_of`) is consumer freshness policy (§6) — evaluate it
    /// separately via [`Self::age_at`].
    pub fn check_as_of_skew(
        &self,
        now: DateTime<Utc>,
        max_clock_skew: chrono::Duration,
    ) -> Result<(), AcdpError> {
        if !self
            .as_of
            .timestamp_subsec_nanos()
            .is_multiple_of(1_000_000)
        {
            return Err(AcdpError::InvalidReceipt(
                "lineage_head_receipt as_of is not millisecond-truncated (RFC-ACDP-0001 §5.3)"
                    .into(),
            ));
        }
        if self.as_of > now + max_clock_skew {
            return Err(AcdpError::InvalidReceipt(format!(
                "lineage_head_receipt as_of '{}' is in the future beyond the {}s clock-skew \
                 allowance (consumer clock '{}') — forged freshness claim \
                 (RFC-ACDP-0011 §7 step 6)",
                self.as_of.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                max_clock_skew.num_seconds(),
                now.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            )));
        }
        Ok(())
    }

    /// The receipt's age at `now` — the input to the consumer's §6
    /// freshness policy (RECOMMENDED maximum: 300 seconds). Negative
    /// when `as_of` is ahead of `now` (bounded by the step-6 skew
    /// check).
    pub fn age_at(&self, now: DateTime<Utc>) -> chrono::Duration {
        now - self.as_of
    }
}

/// Registry-side receipt minting identity: the signing key plus the
/// DID URL it is published under in the registry's own DID document.
///
/// Lifecycle rule (RFC-ACDP-0010, normative): retired receipt keys
/// MUST remain in the registry DID document's `verificationMethod`
/// indefinitely — rotation removes them from `assertionMethod` only
/// (stops new receipts, keeps every previously minted receipt
/// verifiable). Deleting an old key bricks every receipt it signed.
pub struct ReceiptSigner {
    key: acdp_crypto::sign::AcdpSigningKey,
    /// e.g. `did:web:registry.example.com#receipt-key-1`.
    key_id: String,
    /// e.g. `did:web:registry.example.com`.
    registry_did: String,
}

impl ReceiptSigner {
    /// Create a signer. `key_id`'s DID portion MUST equal
    /// `registry_did`, which MUST be the `did:web` form of the
    /// registry's serving authority.
    pub fn new(
        key: impl Into<acdp_crypto::sign::AcdpSigningKey>,
        registry_did: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Result<Self, AcdpError> {
        let registry_did = registry_did.into();
        let key_id = key_id.into();
        if !registry_did.starts_with("did:web:") {
            return Err(AcdpError::SchemaViolation(format!(
                "receipt signer registry_did must be did:web, got '{registry_did}'"
            )));
        }
        match key_id.split_once('#') {
            Some((did, frag)) if did == registry_did && !frag.is_empty() => {}
            _ => {
                return Err(AcdpError::SchemaViolation(format!(
                    "receipt signer key_id '{key_id}' must be '<registry_did>#<fragment>'"
                )));
            }
        }
        Ok(Self {
            key: key.into(),
            key_id,
            registry_did,
        })
    }

    /// The registry DID this signer mints under.
    pub fn registry_did(&self) -> &str {
        &self.registry_did
    }

    /// The DID URL the signing key is published under (e.g.
    /// `did:web:registry.example.com#receipt-key-1`).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The signing key — crate-internal so sibling modules (the
    /// RFC-ACDP-0012 log-checkpoint minter) can sign with the same
    /// receipt key without a second key role.
    pub(crate) fn signing_key(&self) -> &acdp_crypto::sign::AcdpSigningKey {
        &self.key
    }

    /// Mint a signed receipt for an accepted publication.
    ///
    /// `producer_key_fingerprint` MUST be the fingerprint of the key
    /// the validator *actually used* for producer-signature
    /// verification — not re-resolved later (that is the whole
    /// historical-validity guarantee).
    pub fn mint(
        &self,
        ctx_id: &CtxId,
        lineage_id: &LineageId,
        origin_registry: &str,
        created_at: DateTime<Utc>,
        content_hash: &ContentHash,
        producer_key_fingerprint: &str,
    ) -> Result<RegistryReceipt, AcdpError> {
        let mut receipt = RegistryReceipt {
            registry_did: self.registry_did.clone(),
            ctx_id: ctx_id.clone(),
            lineage_id: lineage_id.clone(),
            origin_registry: origin_registry.to_string(),
            created_at: acdp_primitives::time::trunc_ms(created_at),
            content_hash: content_hash.clone(),
            key_fingerprint: producer_key_fingerprint.to_string(),
            signature: Signature {
                algorithm: self.key.algorithm().into(),
                key_id: self.key_id.clone(),
                value: String::new(), // filled below
            },
        };
        let hash = receipt.preimage_hash()?;
        let (algorithm, value) = self.key.sign_content_hash(&hash);
        receipt.signature.algorithm = algorithm.into();
        receipt.signature.value = value;
        Ok(receipt)
    }

    /// Mint a signed **lineage-head receipt** (RFC-ACDP-0011 §5–§6):
    /// the registry's attestation that, as of `as_of` (its response-time
    /// clock, truncated here to milliseconds), the head of `lineage_id`
    /// is `head_ctx_id` at `head_version` with `head_status`.
    ///
    /// Signs with the same receipt signing key as [`Self::mint`] — head
    /// receipts introduce no new key role (RFC-ACDP-0011 §5, §8); the
    /// `receipt_version` member inside the preimage is what domain-
    /// separates the two receipt kinds.
    ///
    /// Refuses to mint an internally inconsistent receipt: a
    /// `superseded` head (never the head, RFC-ACDP-0011 §4), a
    /// `head_version` of 0, or a `head_ctx_id` whose authority is not
    /// this signer's registry (§4: lineages are single-registry).
    pub fn mint_lineage_head(
        &self,
        lineage_id: &LineageId,
        head_ctx_id: &CtxId,
        head_version: u32,
        head_status: &Status,
        as_of: DateTime<Utc>,
    ) -> Result<LineageHeadReceipt, AcdpError> {
        if matches!(head_status, Status::Superseded | Status::Retracted) {
            return Err(AcdpError::SchemaViolation(format!(
                "cannot mint a lineage-head receipt with head_status '{}' — a superseded \
                 version is never the head (RFC-ACDP-0011 §4) and a retracted version is \
                 never served as head (RFC-ACDP-0013 §8.3)",
                head_status.as_str()
            )));
        }
        if head_version < 1 {
            return Err(AcdpError::SchemaViolation(
                "cannot mint a lineage-head receipt with head_version 0 (RFC-ACDP-0011 §4)".into(),
            ));
        }
        let head_authority_did = acdp_did::web::authority_to_did_web(head_ctx_id.authority());
        if head_authority_did != self.registry_did {
            return Err(AcdpError::SchemaViolation(format!(
                "cannot mint a lineage-head receipt for head_ctx_id authority '{}' under \
                 registry_did '{}' (RFC-ACDP-0011 §4: lineages are single-registry)",
                head_ctx_id.authority(),
                self.registry_did
            )));
        }
        let mut receipt = LineageHeadReceipt {
            receipt_version: LINEAGE_HEAD_RECEIPT_VERSION.to_string(),
            registry_did: self.registry_did.clone(),
            lineage_id: lineage_id.clone(),
            head_ctx_id: head_ctx_id.clone(),
            head_version,
            head_status: head_status.as_str().to_string(),
            as_of: acdp_primitives::time::trunc_ms(as_of),
            signature: Signature {
                algorithm: self.key.algorithm().into(),
                key_id: self.key_id.clone(),
                value: String::new(), // filled below
            },
        };
        let hash = receipt.preimage_hash()?;
        let (algorithm, value) = self.key.sign_content_hash(&hash);
        receipt.signature.algorithm = algorithm.into();
        receipt.signature.value = value;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_crypto::SigningKey;

    fn test_signer() -> ReceiptSigner {
        ReceiptSigner::new(
            SigningKey::from_bytes(&[1u8; 32]),
            "did:web:registry.example.com",
            "did:web:registry.example.com#receipt-key-1",
        )
        .unwrap()
    }

    fn test_receipt() -> RegistryReceipt {
        test_signer()
            .mint(
                &CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into()),
                &LineageId(format!("lin:sha256:{}", "a".repeat(64))),
                "registry.example.com",
                chrono::DateTime::parse_from_rfc3339("2026-06-12T10:30:15.123Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                &ContentHash(format!("sha256:{}", "b".repeat(64))),
                "sha256:cafe0000000000000000000000000000000000000000000000000000000000ff",
            )
            .unwrap()
    }

    fn registry_pub() -> [u8; 32] {
        SigningKey::from_bytes(&[1u8; 32]).verifying_key_bytes()
    }

    #[test]
    fn mint_verify_round_trip() {
        let receipt = test_receipt();
        receipt
            .verify_signature_with_key(Some(&registry_pub()), None)
            .expect("freshly minted receipt must verify");
    }

    #[test]
    fn tampered_fields_fail_verification() {
        // rcpt-002-style: any mutated bound field breaks the signature.
        let pubkey = registry_pub();
        let mut r = test_receipt();
        r.created_at += chrono::Duration::milliseconds(1);
        assert!(r.verify_signature_with_key(Some(&pubkey), None).is_err());

        let mut r = test_receipt();
        r.ctx_id = CtxId("acdp://evil.example.com/12345678-1234-4321-8123-123456781234".into());
        assert!(r.verify_signature_with_key(Some(&pubkey), None).is_err());

        let mut r = test_receipt();
        r.key_fingerprint = format!("sha256:{}", "0".repeat(64));
        assert!(r.verify_signature_with_key(Some(&pubkey), None).is_err());
    }

    /// RFC-ACDP-0010 §4: the receipt schema is CLOSED. A receipt
    /// carrying an unknown member MUST be rejected at parse time.
    #[test]
    fn unknown_receipt_fields_rejected() {
        let mut wire = serde_json::to_value(test_receipt()).unwrap();
        wire.as_object_mut()
            .unwrap()
            .insert("transparency_log_index".into(), serde_json::json!(42));
        let err = RegistryReceipt::from_value(&wire).unwrap_err();
        assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");
    }

    /// Raw-JSON preimage equals the struct preimage for a minted
    /// receipt, and the fixed three-digit-millisecond `created_at`
    /// serialization survives a parse → re-serialize round trip even
    /// for whole-second timestamps (chrono would otherwise drop the
    /// `.000`).
    #[test]
    fn raw_and_struct_preimages_agree_incl_whole_second() {
        let receipt = test_receipt();
        let wire = serde_json::to_value(&receipt).unwrap();
        assert_eq!(
            RegistryReceipt::preimage_hash_of_value(&wire).unwrap(),
            receipt.preimage_hash().unwrap()
        );
        RegistryReceipt::validate_created_at_form(&wire).unwrap();

        // Whole-second created_at: serialization MUST keep `.000`.
        let signer = test_signer();
        let r = signer
            .mint(
                &receipt.ctx_id,
                &receipt.lineage_id,
                "registry.example.com",
                chrono::DateTime::parse_from_rfc3339("2026-06-12T09:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                &receipt.content_hash,
                &receipt.key_fingerprint,
            )
            .unwrap();
        let wire = serde_json::to_value(&r).unwrap();
        assert_eq!(wire["created_at"], "2026-06-12T09:00:00.000Z");
        RegistryReceipt::validate_created_at_form(&wire).unwrap();
        let parsed = RegistryReceipt::from_value(&wire).unwrap();
        parsed
            .verify_signature_with_key(Some(&registry_pub()), None)
            .expect("whole-second receipt must round-trip and verify");
    }

    #[test]
    fn cross_checks_fire() {
        let r = test_receipt();
        let ctx = r.ctx_id.clone();
        let hash = r.content_hash.clone();
        let fp = r.key_fingerprint.clone();

        r.cross_check(&ctx, &hash, &fp).expect("all aligned");

        // rcpt-004-style: wrong ctx_id.
        let other =
            CtxId("acdp://registry.example.com/aaaaaaaa-1234-4321-8123-123456781234".into());
        assert!(matches!(
            r.cross_check(&other, &hash, &fp).unwrap_err(),
            AcdpError::InvalidReceipt(_)
        ));
        // rcpt-003-style: fingerprint mismatch.
        assert!(r
            .cross_check(&ctx, &hash, &format!("sha256:{}", "9".repeat(64)))
            .is_err());
        // Body-hash mismatch.
        assert!(r
            .cross_check(
                &ctx,
                &ContentHash(format!("sha256:{}", "c".repeat(64))),
                &fp
            )
            .is_err());
    }

    #[test]
    fn signer_rejects_malformed_identity() {
        assert!(ReceiptSigner::new(
            SigningKey::from_bytes(&[1u8; 32]),
            "did:key:zNotWeb",
            "did:key:zNotWeb#k",
        )
        .is_err());
        assert!(ReceiptSigner::new(
            SigningKey::from_bytes(&[1u8; 32]),
            "did:web:registry.example.com",
            "did:web:other.example.com#k",
        )
        .is_err());
        assert!(ReceiptSigner::new(
            SigningKey::from_bytes(&[1u8; 32]),
            "did:web:registry.example.com",
            "did:web:registry.example.com",
        )
        .is_err());
    }

    // ── Lineage-head receipts (RFC-ACDP-0011) ────────────────────────

    fn test_head_receipt() -> LineageHeadReceipt {
        test_signer()
            .mint_lineage_head(
                &LineageId(format!("lin:sha256:{}", "a".repeat(64))),
                &CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into()),
                2,
                &Status::Active,
                chrono::DateTime::parse_from_rfc3339("2026-07-04T09:00:00.123Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            )
            .unwrap()
    }

    #[test]
    fn head_receipt_mint_verify_round_trip() {
        let r = test_head_receipt();
        assert_eq!(r.receipt_version, LINEAGE_HEAD_RECEIPT_VERSION);
        r.verify_signature_with_key(Some(&registry_pub()), None)
            .expect("freshly minted head receipt must verify");
        // Wire round trip through the closed parse.
        let wire = serde_json::to_value(&r).unwrap();
        LineageHeadReceipt::validate_as_of_form(&wire).unwrap();
        let parsed = LineageHeadReceipt::from_value(&wire).unwrap();
        parsed
            .verify_signature_with_key(Some(&registry_pub()), None)
            .unwrap();
        assert_eq!(
            LineageHeadReceipt::preimage_hash_of_value(&wire).unwrap(),
            r.preimage_hash().unwrap()
        );
    }

    /// The receipt_version domain separator: a head receipt's preimage
    /// can never collide with an RFC-ACDP-0010 receipt's, and a
    /// tampered/missing receipt_version fails the closed parse.
    #[test]
    fn head_receipt_domain_separation_and_closed_schema() {
        let r = test_head_receipt();
        let mut wire = serde_json::to_value(&r).unwrap();

        // Unknown member → rejected (closed schema).
        wire.as_object_mut()
            .unwrap()
            .insert("freshness_proof".into(), serde_json::json!(true));
        assert!(matches!(
            LineageHeadReceipt::from_value(&wire).unwrap_err(),
            AcdpError::InvalidReceipt(_)
        ));

        // Wrong receipt_version → rejected.
        let mut wire = serde_json::to_value(&r).unwrap();
        wire["receipt_version"] = serde_json::json!("acdp-lhr/2");
        assert!(LineageHeadReceipt::from_value(&wire).is_err());

        // A head receipt does NOT parse as an RFC-ACDP-0010 receipt
        // (different member set) and vice versa.
        let wire = serde_json::to_value(&r).unwrap();
        assert!(RegistryReceipt::from_value(&wire).is_err());
        let rcpt_wire = serde_json::to_value(test_receipt()).unwrap();
        assert!(LineageHeadReceipt::from_value(&rcpt_wire).is_err());
    }

    #[test]
    fn head_receipt_semantic_invariants_rejected() {
        let r = test_head_receipt();

        // superseded head — both at parse and at mint.
        let mut wire = serde_json::to_value(&r).unwrap();
        wire["head_status"] = serde_json::json!("superseded");
        assert!(LineageHeadReceipt::from_value(&wire).is_err());
        assert!(test_signer()
            .mint_lineage_head(
                &r.lineage_id,
                &r.head_ctx_id,
                1,
                &Status::Superseded,
                chrono::Utc::now(),
            )
            .is_err());

        // retracted head (RFC-ACDP-0013 §8.3) — likewise never a head.
        let mut wire = serde_json::to_value(&r).unwrap();
        wire["head_status"] = serde_json::json!("retracted");
        assert!(LineageHeadReceipt::from_value(&wire).is_err());
        assert!(test_signer()
            .mint_lineage_head(
                &r.lineage_id,
                &r.head_ctx_id,
                1,
                &Status::parse("retracted").unwrap(),
                chrono::Utc::now(),
            )
            .is_err());

        // head_version 0.
        let mut wire = serde_json::to_value(&r).unwrap();
        wire["head_version"] = serde_json::json!(0);
        assert!(LineageHeadReceipt::from_value(&wire).is_err());

        // Non-canonical as_of byte form (no milliseconds).
        let mut wire = serde_json::to_value(&r).unwrap();
        wire["as_of"] = serde_json::json!("2026-07-04T09:00:00Z");
        assert!(LineageHeadReceipt::from_value(&wire).is_err());

        // Foreign head_ctx_id authority refused at mint.
        assert!(test_signer()
            .mint_lineage_head(
                &r.lineage_id,
                &CtxId("acdp://evil.example.com/12345678-1234-4321-8123-123456781234".into()),
                1,
                &Status::Active,
                chrono::Utc::now(),
            )
            .is_err());
    }

    #[test]
    fn head_receipt_cross_checks_fire() {
        let r = test_head_receipt();

        // All aligned (§7 steps 3–5).
        r.cross_check_registry_binding("registry.example.com", "did:web:registry.example.com")
            .unwrap();
        r.cross_check_lineage(&r.lineage_id).unwrap();
        r.cross_check_head(&r.head_ctx_id, 2, &Status::Active, true)
            .unwrap();

        // lhr-003-style: wrong serving authority / capabilities DID.
        assert!(r
            .cross_check_registry_binding("hostile.example", "did:web:hostile.example")
            .is_err());
        assert!(r
            .cross_check_registry_binding("registry.example.com", "did:web:other.example")
            .is_err());

        // Wrong lineage.
        assert!(r
            .cross_check_lineage(&LineageId(format!("lin:sha256:{}", "f".repeat(64))))
            .is_err());

        // lhr-002-style: /current serving a different head.
        let other =
            CtxId("acdp://registry.example.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into());
        assert!(r
            .cross_check_head(&other, 3, &Status::Active, true)
            .is_err());
        // Version / status byte-match failures on the same ctx_id.
        assert!(r
            .cross_check_head(&r.head_ctx_id, 1, &Status::Active, true)
            .is_err());
        assert!(r
            .cross_check_head(&r.head_ctx_id, 2, &Status::Expired, true)
            .is_err());

        // §7 step 5b (full retrieval of a non-head version): consistent
        // when head_version > served AND served is superseded — or
        // retracted (RFC-ACDP-0013 §7.2 precedence) …
        r.cross_check_head(&other, 1, &Status::Superseded, false)
            .unwrap();
        r.cross_check_head(&other, 1, &Status::parse("retracted").unwrap(), false)
            .unwrap();
        // … self-contradictory otherwise (active or expired).
        assert!(r
            .cross_check_head(&other, 1, &Status::Active, false)
            .is_err());
        assert!(r
            .cross_check_head(&other, 1, &Status::Expired, false)
            .is_err());
        assert!(r
            .cross_check_head(&other, 2, &Status::Superseded, false)
            .is_err());
    }

    /// lhr-004-style: a future as_of beyond skew fails step 6; honest
    /// skew within the allowance passes; staleness is a separate
    /// verdict, not a step-6 failure.
    #[test]
    fn head_receipt_as_of_skew_and_age() {
        let r = test_head_receipt();
        let skew = chrono::Duration::seconds(120);

        let now = r.as_of - chrono::Duration::seconds(30); // as_of 30s ahead
        r.check_as_of_skew(now, skew).expect("within skew");

        let now = r.as_of - chrono::Duration::seconds(300); // as_of 5m ahead
        let err = r.check_as_of_skew(now, skew).unwrap_err();
        assert!(matches!(err, AcdpError::InvalidReceipt(_)), "got {err:?}");

        // An OLD receipt passes step 6 — age is policy, not verification.
        let now = r.as_of + chrono::Duration::seconds(3600);
        r.check_as_of_skew(now, skew)
            .expect("stale is not a step-6 failure");
        assert_eq!(r.age_at(now), chrono::Duration::seconds(3600));
    }
}
