//! Registry transparency log wire types (ACDP 0.3, RFC-ACDP-0012 —
//! promoted from the RFC-ACDP-0009 §2.11 reservation).
//!
//! The log is a per-registry, append-only RFC 6962-style Merkle tree
//! over publish events: one accepted publish → one [`LogLeaf`], forever.
//! The registry commits to the tree with signed [`LogCheckpoint`]s
//! (signed tree heads) and proves membership/history with
//! [`LogInclusion`] and [`LogConsistencyProof`]. Receipts
//! (RFC-ACDP-0010/0011) made registry claims *attributable*; the log
//! makes mint-time backdating, omission-after-the-fact, and
//! per-consumer equivocation *detectable by any auditor holding
//! checkpoints* (RFC-ACDP-0012 §3).
//!
//! ## Byte-level constructions
//!
//! - **Leaf encoding** — the JCS canonicalization (RFC 8785) of the
//!   closed leaf object; there is no exclusion set (§4).
//!   `leaf_hash = SHA-256(0x00 ‖ JCS(leaf))` (§5.1).
//! - **Checkpoint signing** — RFC-ACDP-0010 §5 verbatim (§6): JCS of
//!   the checkpoint minus `signature`, SHA-256, signature over the
//!   **ASCII bytes of the `"sha256:<hex>"` string** — with the
//!   registry's **receipt signing key** (no new key role).
//! - **Merkle arithmetic** — [`acdp_crypto::merkle`] (RFC 6962 §2.1
//!   with the `0x00`/`0x01` domain-separation prefixes; verification
//!   per RFC 9162 §2.1.3.2 / §2.1.4.2 as transcribed in §9).
//!
//! All verification failures here map to
//! [`AcdpError::InvalidLogProof`] — deliberately **not**
//! `InvalidReceipt`: a proof failure indicts the *log* (tree
//! membership, history consistency, checkpoint signature), not the
//! receipt, and the verdicts are independent (RFC-ACDP-0012 §9.3, §11).

use crate::body::Signature;
use crate::receipt::{
    is_canonical_ms_utc, ms_rfc3339, preimage_hash_of_object_with, verify_signature_over_hash_with,
    ReceiptSigner,
};
use acdp_jcs::try_canonicalize_value;
use acdp_primitives::error::AcdpError;
use acdp_primitives::primitives::{ContentHash, CtxId, LineageId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The leaf envelope version (RFC-ACDP-0012 §4). In-object domain
/// separator (the RFC-ACDP-0011 `receipt_version` convention): a leaf
/// can never be mistaken for an RFC-ACDP-0010 receipt preimage or any
/// other JCS-canonicalized ACDP object.
pub const LOG_LEAF_VERSION: &str = "acdp-log-leaf/1";

/// The checkpoint envelope version (RFC-ACDP-0012 §6). In-preimage
/// domain separator: a checkpoint can never be mistaken for — or
/// replayed as — a context receipt or head receipt.
pub const LOG_CHECKPOINT_VERSION: &str = "acdp-log/1";

/// Decode a repository-form `"sha256:<64 lowercase hex>"` string to the
/// raw 32-byte digest it encodes (RFC-ACDP-0012 §2: Merkle-internal
/// computation operates on the raw digests the wire strings encode).
pub fn decode_sha256_hex(prefixed: &str) -> Result<[u8; 32], AcdpError> {
    let hex_part = prefixed.strip_prefix("sha256:").ok_or_else(|| {
        AcdpError::InvalidLogProof(format!(
            "hash '{prefixed}' is not of the form 'sha256:<hex>' (RFC-ACDP-0012 §2)"
        ))
    })?;
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AcdpError::InvalidLogProof(format!(
            "hash '{prefixed}' is not 'sha256:' + 64 lowercase hex digits (RFC-ACDP-0012 §2)"
        )));
    }
    let bytes = hex::decode(hex_part)
        .map_err(|e| AcdpError::InvalidLogProof(format!("hash '{prefixed}': {e}")))?;
    bytes.try_into().map_err(|_| {
        AcdpError::InvalidLogProof(format!("hash '{prefixed}' does not encode 32 bytes"))
    })
}

/// Encode a raw 32-byte digest in the repository-wide wire form
/// `"sha256:" + lowercase_hex(...)` (RFC-ACDP-0012 §2).
pub fn encode_sha256_hex(digest: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(digest))
}

/// Split a `log_id` into `(registry_did, instance)` per RFC-ACDP-0012
/// §6: `"<registry_did>/log/<instance>"`, where `<registry_did>` is a
/// `did:web` DID and `<instance>` matches `[a-z0-9-]{1,32}`.
pub fn parse_log_id(log_id: &str) -> Result<(&str, &str), AcdpError> {
    let (did, instance) = log_id.split_once("/log/").ok_or_else(|| {
        AcdpError::InvalidLogProof(format!(
            "log_id '{log_id}' is not '<registry_did>/log/<instance>' (RFC-ACDP-0012 §6)"
        ))
    })?;
    let msi = did.strip_prefix("did:web:").ok_or_else(|| {
        AcdpError::InvalidLogProof(format!(
            "log_id '{log_id}' registry DID must be did:web (RFC-ACDP-0012 §6)"
        ))
    })?;
    if msi.is_empty()
        || !msi
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'%' | b':' | b'-'))
    {
        return Err(AcdpError::InvalidLogProof(format!(
            "log_id '{log_id}' has a malformed did:web method-specific identifier"
        )));
    }
    if instance.is_empty()
        || instance.len() > 32
        || !instance
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(AcdpError::InvalidLogProof(format!(
            "log_id '{log_id}' instance component must match [a-z0-9-]{{1,32}} (RFC-ACDP-0012 §6)"
        )));
    }
    Ok((did, instance))
}

// ── Leaf ─────────────────────────────────────────────────────────────────────

/// One transparency-log leaf: the closed object binding one accepted
/// publish event (RFC-ACDP-0012 §4).
///
/// CLOSED schema (`acdp-log-leaf.schema.json`,
/// `additionalProperties: false`): the leaf bytes are hashed into the
/// tree, so an unknown member would change the leaf hash; extensions
/// require a `leaf_version` bump. Every field other than `receipt_hash`
/// deliberately duplicates receipt fields so a verifier holding the
/// body and its verified receipt can reconstruct the leaf byte-for-byte
/// with no additional trust in the registry (§9.1 step 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogLeaf {
    /// MUST be exactly [`LOG_LEAF_VERSION`] (`"acdp-log-leaf/1"`).
    pub leaf_version: String,
    /// The registry-assigned context identifier (RFC-ACDP-0001 §5.5).
    /// Exactly one leaf per `ctx_id` — bodies are immutable, so a
    /// publish event happens once.
    pub ctx_id: CtxId,
    /// The registry-derived lineage identifier (RFC-ACDP-0001 §5.6).
    pub lineage_id: LineageId,
    /// The registry-assigned origin authority (bare DNS hostname). MUST
    /// equal the `ctx_id` authority and the log's registry DID
    /// authority.
    pub origin_registry: String,
    /// The registry-assigned creation timestamp — byte-identical to
    /// `body.created_at` and `registry_receipt.created_at`; canonical
    /// millisecond-precision RFC 3339 UTC, always serialized with
    /// exactly three fractional digits.
    #[serde(with = "ms_rfc3339")]
    pub created_at: DateTime<Utc>,
    /// The body's `content_hash` as verified at publish time.
    pub content_hash: ContentHash,
    /// The RFC-ACDP-0010 §6 fingerprint of the producer key resolved at
    /// publish time. MUST equal `registry_receipt.key_fingerprint`.
    pub key_fingerprint: String,
    /// The RFC-ACDP-0010 §2 receipt hash of this context's registry
    /// receipt (over the receipt preimage, i.e. minus `signature`) —
    /// binding the signed receipt statement while remaining stable
    /// across the sanctioned post-compromise re-mint (RFC-ACDP-0012 §4).
    pub receipt_hash: String,
}

impl LogLeaf {
    /// Parse a leaf from wire JSON, enforcing the closed schema, the
    /// exact `leaf_version`, and the canonical millisecond byte form of
    /// the RAW `created_at` (checked before parsing normalization).
    pub fn from_value(value: &serde_json::Value) -> Result<Self, AcdpError> {
        let leaf = Self::deserialize(value)
            .map_err(|e| AcdpError::InvalidLogProof(format!("log leaf does not parse: {e}")))?;
        if leaf.leaf_version != LOG_LEAF_VERSION {
            return Err(AcdpError::InvalidLogProof(format!(
                "log leaf leaf_version '{}' ≠ '{LOG_LEAF_VERSION}' (RFC-ACDP-0012 §4)",
                leaf.leaf_version
            )));
        }
        let raw = value
            .get("created_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AcdpError::InvalidLogProof("log leaf created_at missing or not a string".into())
            })?;
        if !is_canonical_ms_utc(raw) {
            return Err(AcdpError::InvalidLogProof(format!(
                "log leaf created_at '{raw}' is not canonical millisecond-precision RFC 3339 \
                 UTC (`YYYY-MM-DDTHH:MM:SS.mmmZ`, RFC-ACDP-0012 §4)"
            )));
        }
        Ok(leaf)
    }

    /// The **leaf encoding** — the exact bytes that are hashed: the JCS
    /// canonicalization (RFC 8785) of the leaf object, UTF-8. There is
    /// no exclusion set: every member is part of the leaf bytes
    /// (RFC-ACDP-0012 §4).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AcdpError> {
        try_canonicalize_value(&serde_json::to_value(self)?)
    }

    /// `SHA-256(0x00 ‖ JCS(leaf))` — the §5.1 leaf hash, raw digest.
    pub fn leaf_hash(&self) -> Result<[u8; 32], AcdpError> {
        Ok(acdp_crypto::merkle::leaf_hash(&self.canonical_bytes()?))
    }

    /// The §5.1 leaf hash in wire form (`"sha256:<hex>"`).
    pub fn leaf_hash_hex(&self) -> Result<String, AcdpError> {
        Ok(encode_sha256_hex(&self.leaf_hash()?))
    }

    /// Build the §4 leaf for one receipted publish event. A verifier
    /// uses it for §9.1 step 1, and a registry uses it at §7.1 append
    /// time, so both sides hash the same bytes.
    ///
    /// Pass only *verified* material:
    /// - `body` is the accepted body. Its `ctx_id`, `lineage_id`,
    ///   `origin_registry` and `created_at` are used.
    /// - `content_hash` is recomputed from the body, never the echoed
    ///   value.
    /// - `key_fingerprint` is the RFC-ACDP-0010 §6 fingerprint of the
    ///   resolved producer key.
    /// - `receipt_value` is the raw wire receipt. `receipt_hash` is its
    ///   §2 preimage hash (minus `signature`), recomputed here.
    ///
    /// # Errors
    /// [`AcdpError::InvalidReceipt`] when `receipt_value` is not a JSON
    /// object.
    pub fn for_publish(
        body: &crate::body::Body,
        content_hash: &ContentHash,
        key_fingerprint: &str,
        receipt_value: &serde_json::Value,
    ) -> Result<Self, AcdpError> {
        let receipt_hash = crate::receipt::RegistryReceipt::preimage_hash_of_value(receipt_value)?;
        Ok(Self {
            leaf_version: LOG_LEAF_VERSION.to_string(),
            ctx_id: body.ctx_id.clone(),
            lineage_id: body.lineage_id.clone(),
            origin_registry: body.origin_registry.clone(),
            created_at: body.created_at,
            content_hash: content_hash.clone(),
            key_fingerprint: key_fingerprint.to_string(),
            receipt_hash: receipt_hash.0,
        })
    }
}

// ── Checkpoint (signed tree head) ────────────────────────────────────────────

/// A registry-signed **checkpoint** (signed tree head): the registry's
/// commitment that, as of `timestamp`, the log `log_id` has `tree_size`
/// leaves and Merkle root `root_hash` (RFC-ACDP-0012 §6).
///
/// CLOSED schema (`acdp-log-checkpoint.schema.json`,
/// `additionalProperties: false`): every field is signed, so an unknown
/// member would change the preimage. The signing construction is
/// RFC-ACDP-0010 §5 **verbatim** — same receipt signing key, same
/// `"remove the signature member"` preimage rule, same ASCII
/// `"sha256:<hex>"` signing input — with `checkpoint_version` as the
/// in-preimage domain separator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogCheckpoint {
    /// MUST be exactly [`LOG_CHECKPOINT_VERSION`] (`"acdp-log/1"`).
    pub checkpoint_version: String,
    /// The log instantiation identifier
    /// `"<registry_did>/log/<instance>"` (§6). A new instance component
    /// is an explicit, detectable history reset (§7.4).
    pub log_id: String,
    /// The number of leaves this checkpoint commits to (0 is a valid,
    /// empty log).
    pub tree_size: u64,
    /// `"sha256:" + lowercase_hex(MTH(D[tree_size]))` per §5.2.
    pub root_hash: String,
    /// Registry-clock time at which this checkpoint was evaluated and
    /// signed; canonical millisecond-precision RFC 3339 UTC. Registry-
    /// asserted (§13) — consumers bound it with [`Self::check_timestamp_skew`]
    /// and their own freshness policy (§7.2).
    #[serde(with = "ms_rfc3339")]
    pub timestamp: DateTime<Utc>,
    /// The registry's signature over the checkpoint hash (§6 — the
    /// RFC-ACDP-0010 §5 construction verbatim). `signature.key_id` MUST
    /// be a DID URL under the `registry_did` embedded in `log_id`.
    pub signature: Signature,
}

impl LogCheckpoint {
    /// §9.3 step 1 — schema-closed parse: exact `checkpoint_version`,
    /// well-formed `log_id` and `root_hash`, canonical millisecond byte
    /// form of the RAW `timestamp` (checked before parsing
    /// normalization), and `signature.key_id` under the `log_id`'s
    /// registry DID.
    pub fn from_value(value: &serde_json::Value) -> Result<Self, AcdpError> {
        let checkpoint = Self::deserialize(value).map_err(|e| {
            AcdpError::InvalidLogProof(format!("log_checkpoint does not parse: {e}"))
        })?;
        if checkpoint.checkpoint_version != LOG_CHECKPOINT_VERSION {
            return Err(AcdpError::InvalidLogProof(format!(
                "log_checkpoint checkpoint_version '{}' ≠ '{LOG_CHECKPOINT_VERSION}' \
                 (RFC-ACDP-0012 §9.3 step 1)",
                checkpoint.checkpoint_version
            )));
        }
        parse_log_id(&checkpoint.log_id)?;
        decode_sha256_hex(&checkpoint.root_hash)?;
        let raw = value
            .get("timestamp")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AcdpError::InvalidLogProof(
                    "log_checkpoint timestamp missing or not a string".into(),
                )
            })?;
        if !is_canonical_ms_utc(raw) {
            return Err(AcdpError::InvalidLogProof(format!(
                "log_checkpoint timestamp '{raw}' is not canonical millisecond-precision \
                 RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SS.mmmZ`, RFC-ACDP-0012 §9.3 step 4)"
            )));
        }
        // signature.key_id MUST be a DID URL under the registry DID
        // embedded in log_id (§6).
        checkpoint.registry_did()?;
        Ok(checkpoint)
    }

    /// The registry DID embedded in `log_id`, after checking that
    /// `signature.key_id` is a DID URL under it (RFC-ACDP-0012 §6).
    pub fn registry_did(&self) -> Result<&str, AcdpError> {
        let (did, _instance) = parse_log_id(&self.log_id)?;
        match self.signature.key_id.split_once('#') {
            Some((key_did, frag)) if key_did == did && !frag.is_empty() => Ok(did),
            _ => Err(AcdpError::InvalidLogProof(format!(
                "log_checkpoint signature.key_id '{}' is not a DID URL under the log_id's \
                 registry DID '{did}' (RFC-ACDP-0012 §6)",
                self.signature.key_id
            ))),
        }
    }

    /// Compute the §6 checkpoint hash from the RAW wire JSON of a
    /// checkpoint (the value minus `signature`, JCS-canonicalized as
    /// received, SHA-256'd). Verifiers MUST hash the checkpoint exactly
    /// as received — the same raw-JSON rule as
    /// [`crate::receipt::RegistryReceipt::preimage_hash_of_value`].
    pub fn preimage_hash_of_value(value: &serde_json::Value) -> Result<ContentHash, AcdpError> {
        preimage_hash_of_object_with(value, "log_checkpoint", AcdpError::InvalidLogProof)
    }

    /// Compute the checkpoint hash from the struct. Used at MINT time
    /// (the struct's serializer emits the canonical three-digit-
    /// millisecond `timestamp`); verifiers should prefer
    /// [`Self::preimage_hash_of_value`] over the raw wire JSON.
    pub fn preimage_hash(&self) -> Result<ContentHash, AcdpError> {
        Self::preimage_hash_of_value(&serde_json::to_value(self)?)
    }

    /// The raw 32-byte digest `root_hash` encodes.
    pub fn root_hash_bytes(&self) -> Result<[u8; 32], AcdpError> {
        decode_sha256_hex(&self.root_hash)
    }

    /// §9.3 step 2 — verify the checkpoint signature against a known
    /// registry public key (pure — no DID resolution; the `client`
    /// feature's `verify_log_checkpoint_value` resolves the registry
    /// DID and calls this).
    pub fn verify_signature_with_key(
        &self,
        registry_pub_ed25519: Option<&[u8; 32]>,
        registry_pub_p256_sec1: Option<&[u8]>,
    ) -> Result<(), AcdpError> {
        let hash = self.preimage_hash()?;
        self.verify_signature_against_hash(&hash, registry_pub_ed25519, registry_pub_p256_sec1)
    }

    /// Like [`Self::verify_signature_with_key`] but over an
    /// already-computed checkpoint hash — pair with
    /// [`Self::preimage_hash_of_value`] for raw-JSON verification.
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
            "log_checkpoint",
            AcdpError::InvalidLogProof,
        )
    }

    /// §9.3 step 3 — registry binding (pure): the `registry_did` prefix
    /// of `log_id` MUST be `did:web:<authority>` where `<authority>` is
    /// the authority the checkpoint was fetched from AND equal
    /// `capabilities.registry_did`; the DID portion of
    /// `signature.key_id` MUST equal that DID (already enforced by
    /// [`Self::registry_did`]).
    pub fn cross_check_registry_binding(
        &self,
        serving_authority: &str,
        capabilities_registry_did: &str,
    ) -> Result<(), AcdpError> {
        let did = self.registry_did()?;
        let expected_did = acdp_did::web::authority_to_did_web(serving_authority);
        if did != expected_did {
            return Err(AcdpError::InvalidLogProof(format!(
                "log_checkpoint log_id registry DID '{did}' ≠ serving authority's DID \
                 '{expected_did}' (RFC-ACDP-0012 §9.3 step 3)"
            )));
        }
        if did != capabilities_registry_did {
            return Err(AcdpError::InvalidLogProof(format!(
                "log_checkpoint log_id registry DID '{did}' ≠ capabilities.registry_did \
                 '{capabilities_registry_did}' (RFC-ACDP-0012 §9.3 step 3)"
            )));
        }
        Ok(())
    }

    /// §9.3 step 4 — form: `timestamp` millisecond-truncated and not in
    /// the future beyond `max_clock_skew` (RECOMMENDED 120 s, the
    /// RFC-ACDP-0011 §7 step 6 allowance). Staleness (an old but honest
    /// `timestamp`) is consumer freshness policy (§7.2), evaluated
    /// separately via [`Self::age_at`].
    pub fn check_timestamp_skew(
        &self,
        now: DateTime<Utc>,
        max_clock_skew: chrono::Duration,
    ) -> Result<(), AcdpError> {
        if self.timestamp.timestamp_subsec_nanos() % 1_000_000 != 0 {
            return Err(AcdpError::InvalidLogProof(
                "log_checkpoint timestamp is not millisecond-truncated (RFC-ACDP-0001 §5.3)".into(),
            ));
        }
        if self.timestamp > now + max_clock_skew {
            return Err(AcdpError::InvalidLogProof(format!(
                "log_checkpoint timestamp '{}' is in the future beyond the {}s clock-skew \
                 allowance (consumer clock '{}') (RFC-ACDP-0012 §9.3 step 4)",
                self.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                max_clock_skew.num_seconds(),
                now.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            )));
        }
        Ok(())
    }

    /// The checkpoint's age at `now` — the input to the consumer's §7.2
    /// freshness policy (RECOMMENDED maximum: 300 seconds).
    pub fn age_at(&self, now: DateTime<Utc>) -> chrono::Duration {
        now - self.timestamp
    }
}

// ── Inclusion proof ──────────────────────────────────────────────────────────

/// An inclusion proof that one leaf is committed by a checkpointed
/// transparency-log tree (RFC-ACDP-0012 §8.2, §9.1): the RFC 6962
/// §2.1.1 audit path for `leaf_index` at `tree_size`, together with the
/// signed checkpoint it verifies against.
///
/// Returned by `GET /log/proof` (inclusion mode) and OPTIONALLY carried
/// as the top-level `log_inclusion` member of the full-retrieval
/// envelope (§10 — a **sibling** of `registry_receipt`, never a member
/// of it). CLOSED schema: a proof is arithmetic evidence with no
/// extension surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogInclusion {
    /// The log instantiation this proof belongs to. MUST equal
    /// `log_checkpoint.log_id` (§9.1 step 4).
    pub log_id: String,
    /// The 0-based append-order position of the leaf. MUST be
    /// `< tree_size`.
    pub leaf_index: u64,
    /// The tree size the proof is computed against. MUST equal
    /// `log_checkpoint.tree_size` (§9.1 step 4).
    pub tree_size: u64,
    /// The RFC 6962 §2.1.1 audit path `PATH(leaf_index, D[tree_size])`,
    /// ordered from the lowest tree level upward, each element
    /// `"sha256:<hex>"`. May be empty (`tree_size` 1).
    pub inclusion_path: Vec<String>,
    /// The signed checkpoint this proof verifies against (§9.3).
    pub log_checkpoint: LogCheckpoint,
    /// OPTIONAL convenience echo of the leaf, present on inclusion-mode
    /// `GET /log/proof` responses only when the requester is authorized
    /// to retrieve the context (§8.2), and absent from the
    /// retrieval-envelope `log_inclusion` member (§10). Verifiers MUST
    /// NOT trust it — the leaf is independently reconstructed from
    /// verified body and receipt material (§9.1 step 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf: Option<LogLeaf>,
}

impl LogInclusion {
    /// Parse an inclusion proof from the JSON value carried in
    /// [`crate::body::FullContext::log_inclusion`] (or a
    /// `GET /log/proof` inclusion-mode response), enforcing the closed
    /// schema, the embedded checkpoint's §9.3 step 1 form, and
    /// `tree_size ≥ 1`.
    pub fn from_value(value: &serde_json::Value) -> Result<Self, AcdpError> {
        let inclusion = Self::deserialize(value).map_err(|e| {
            AcdpError::InvalidLogProof(format!("log_inclusion does not parse: {e}"))
        })?;
        if inclusion.tree_size < 1 {
            return Err(AcdpError::InvalidLogProof(
                "log_inclusion tree_size must be >= 1 (an empty tree has no members)".into(),
            ));
        }
        // The embedded checkpoint's schema-closed invariants (§9.3
        // step 1) — reparse from the raw member so the RAW timestamp
        // byte form is checked too.
        if let Some(cp) = value.get("log_checkpoint") {
            LogCheckpoint::from_value(cp)?;
        }
        if let Some(leaf) = value.get("leaf") {
            LogLeaf::from_value(leaf)?;
        }
        Ok(inclusion)
    }

    /// §9.1 step 4 — binding checks: `tree_size` equals
    /// `log_checkpoint.tree_size`, `log_id` equals
    /// `log_checkpoint.log_id`, and `leaf_index < tree_size`.
    pub fn cross_check_binding(&self) -> Result<(), AcdpError> {
        if self.tree_size != self.log_checkpoint.tree_size {
            return Err(AcdpError::InvalidLogProof(format!(
                "log_inclusion tree_size {} ≠ log_checkpoint.tree_size {} \
                 (RFC-ACDP-0012 §9.1 step 4)",
                self.tree_size, self.log_checkpoint.tree_size
            )));
        }
        if self.log_id != self.log_checkpoint.log_id {
            return Err(AcdpError::InvalidLogProof(format!(
                "log_inclusion log_id '{}' ≠ log_checkpoint.log_id '{}' \
                 (RFC-ACDP-0012 §9.1 step 4)",
                self.log_id, self.log_checkpoint.log_id
            )));
        }
        if self.leaf_index >= self.tree_size {
            return Err(AcdpError::InvalidLogProof(format!(
                "log_inclusion leaf_index {} is not < tree_size {} (RFC-ACDP-0012 §9.1 step 4)",
                self.leaf_index, self.tree_size
            )));
        }
        Ok(())
    }

    /// §9.1 steps 4–6 — the pure arithmetic half of inclusion
    /// verification: binding checks, then fold the audit path over
    /// `leaf_hash` (the §5.1 hash of the *independently reconstructed*
    /// leaf — never an echoed one) and compare against the checkpoint's
    /// `root_hash`. Checkpoint signature verification (§9.3 step 2) is
    /// separate — see [`LogCheckpoint::verify_signature_with_key`] and
    /// the `client` feature's `verify_log_inclusion_value`.
    pub fn verify_leaf_hash(&self, leaf_hash: &[u8; 32]) -> Result<(), AcdpError> {
        self.cross_check_binding()?;
        let path = self
            .inclusion_path
            .iter()
            .map(|p| decode_sha256_hex(p))
            .collect::<Result<Vec<_>, _>>()?;
        let root = self.log_checkpoint.root_hash_bytes()?;
        if !acdp_crypto::merkle::verify_inclusion(
            leaf_hash,
            self.leaf_index,
            self.tree_size,
            &path,
            &root,
        ) {
            return Err(AcdpError::InvalidLogProof(format!(
                "inclusion_path for leaf_index {} does not fold to the checkpoint root_hash \
                 '{}' at tree_size {} (RFC-ACDP-0012 §9.1 step 6)",
                self.leaf_index, self.log_checkpoint.root_hash, self.tree_size
            )));
        }
        Ok(())
    }

    /// Convenience: [`Self::verify_leaf_hash`] over a reconstructed
    /// [`LogLeaf`] (§9.1 steps 1–2 + 4–6). Pass the leaf built from
    /// *verified* material — never the echoed `leaf` member.
    pub fn verify_reconstructed_leaf(&self, leaf: &LogLeaf) -> Result<(), AcdpError> {
        self.verify_leaf_hash(&leaf.leaf_hash()?)
    }
}

// ── Consistency proof ────────────────────────────────────────────────────────

/// A consistency-mode `GET /log/proof` response (RFC-ACDP-0012 §8.2):
/// the RFC 6962 §2.1.2 proof `PROOF(first, D[second])` that the tree at
/// `first_tree_size` is a prefix of the tree at `second_tree_size` —
/// the history-rewrite detector. The verifier supplies its own
/// *retained* root for `first_tree_size` (that retained root is the
/// whole point, §9.2).
///
/// Distinct shape from [`LogInclusion`] (the schema `$comment` is
/// explicit); closed for the same reason — arithmetic evidence has no
/// extension surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConsistencyProof {
    /// The log instantiation. Consistency proofs exist only within one
    /// `log_id` (§7.4).
    pub log_id: String,
    /// The earlier (retained) tree size.
    pub first_tree_size: u64,
    /// The later tree size. MUST equal `log_checkpoint.tree_size`.
    pub second_tree_size: u64,
    /// `PROOF(first, D[second])`, each element `"sha256:<hex>"`; empty
    /// when `first == second`.
    pub consistency_path: Vec<String>,
    /// A checkpoint at `second_tree_size` (§8.2), verified per §9.3.
    pub log_checkpoint: LogCheckpoint,
}

impl LogConsistencyProof {
    /// Parse a consistency proof from a `GET /log/proof`
    /// consistency-mode response, enforcing the closed schema and the
    /// embedded checkpoint's §9.3 step 1 form.
    pub fn from_value(value: &serde_json::Value) -> Result<Self, AcdpError> {
        let proof = Self::deserialize(value).map_err(|e| {
            AcdpError::InvalidLogProof(format!("consistency proof does not parse: {e}"))
        })?;
        if let Some(cp) = value.get("log_checkpoint") {
            LogCheckpoint::from_value(cp)?;
        }
        Ok(proof)
    }

    /// §9.2 — verify the proof between the verifier's **retained**
    /// earlier root (`first_root_hash`, wire form) and the embedded
    /// later checkpoint's root, plus the shape bindings (`log_id`s
    /// equal, `second_tree_size == log_checkpoint.tree_size`).
    /// Checkpoint signature verification (§9.3) is separate.
    ///
    /// A failure here between two *signature-valid* checkpoints of one
    /// `log_id` is not a soft error: it is cryptographic evidence that
    /// the registry rewrote logged history, and consumers SHOULD retain
    /// both checkpoints and the failing path as evidence (§9.2, §15).
    pub fn verify_against_first_root(&self, first_root_hash: &str) -> Result<(), AcdpError> {
        if self.log_id != self.log_checkpoint.log_id {
            return Err(AcdpError::InvalidLogProof(format!(
                "consistency proof log_id '{}' ≠ log_checkpoint.log_id '{}' \
                 (consistency proofs exist only within one log_id, RFC-ACDP-0012 §7.4)",
                self.log_id, self.log_checkpoint.log_id
            )));
        }
        if self.second_tree_size != self.log_checkpoint.tree_size {
            return Err(AcdpError::InvalidLogProof(format!(
                "consistency proof second_tree_size {} ≠ log_checkpoint.tree_size {} \
                 (RFC-ACDP-0012 §8.2)",
                self.second_tree_size, self.log_checkpoint.tree_size
            )));
        }
        let first_root = decode_sha256_hex(first_root_hash)?;
        let second_root = self.log_checkpoint.root_hash_bytes()?;
        let path = self
            .consistency_path
            .iter()
            .map(|p| decode_sha256_hex(p))
            .collect::<Result<Vec<_>, _>>()?;
        if !acdp_crypto::merkle::verify_consistency(
            self.first_tree_size,
            self.second_tree_size,
            &path,
            &first_root,
            &second_root,
        ) {
            return Err(AcdpError::InvalidLogProof(format!(
                "consistency_path does not prove the tree at size {} is a prefix of the tree \
                 at size {} — evidence of a logged-history rewrite; retain both checkpoints \
                 and this path (RFC-ACDP-0012 §9.2)",
                self.first_tree_size, self.second_tree_size
            )));
        }
        Ok(())
    }
}

// ── Checkpoint minting (registry side) ───────────────────────────────────────

impl ReceiptSigner {
    /// Mint a signed **log checkpoint** (RFC-ACDP-0012 §6): the
    /// registry's commitment that, as of `timestamp` (truncated here to
    /// milliseconds), the log `log_id` has `tree_size` leaves and
    /// Merkle root `root_hash`.
    ///
    /// Signs with the same receipt signing key as
    /// [`ReceiptSigner::mint`] — the log introduces **no new key role**
    /// (§2, §6); `checkpoint_version` inside the preimage is what
    /// domain-separates checkpoints from both receipt kinds.
    ///
    /// Refuses an internally inconsistent checkpoint: a `log_id` whose
    /// registry DID is not this signer's, a malformed `log_id`
    /// instance, or a malformed `root_hash`.
    pub fn mint_log_checkpoint(
        &self,
        log_id: &str,
        tree_size: u64,
        root_hash: &str,
        timestamp: DateTime<Utc>,
    ) -> Result<LogCheckpoint, AcdpError> {
        let (did, _instance) = parse_log_id(log_id)?;
        if did != self.registry_did() {
            return Err(AcdpError::SchemaViolation(format!(
                "cannot mint a checkpoint for log_id '{log_id}' under registry_did '{}' \
                 (RFC-ACDP-0012 §6: the log_id embeds the registry's own DID)",
                self.registry_did()
            )));
        }
        decode_sha256_hex(root_hash)?;
        let mut checkpoint = LogCheckpoint {
            checkpoint_version: LOG_CHECKPOINT_VERSION.to_string(),
            log_id: log_id.to_string(),
            tree_size,
            root_hash: root_hash.to_string(),
            timestamp: acdp_primitives::time::trunc_ms(timestamp),
            signature: Signature {
                algorithm: self.signing_key().algorithm().into(),
                key_id: self.key_id().to_string(),
                value: String::new(), // filled below
            },
        };
        let hash = checkpoint.preimage_hash()?;
        let (algorithm, value) = self.signing_key().sign_content_hash(&hash);
        checkpoint.signature.algorithm = algorithm.into();
        checkpoint.signature.value = value;
        Ok(checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_crypto::SigningKey;

    const REGISTRY_DID: &str = "did:web:registry.example.com";
    const LOG_ID: &str = "did:web:registry.example.com/log/1";

    fn signer() -> ReceiptSigner {
        ReceiptSigner::new(
            SigningKey::from_bytes(&[0x11u8; 32]),
            REGISTRY_DID,
            format!("{REGISTRY_DID}#receipt-key-1"),
        )
        .unwrap()
    }

    fn registry_pub() -> [u8; 32] {
        SigningKey::from_bytes(&[0x11u8; 32]).verifying_key_bytes()
    }

    fn leaf(i: u8) -> LogLeaf {
        let ctx_id =
            format!("acdp://registry.example.com/00000000-0000-4000-8000-0000000000{i:02}");
        LogLeaf {
            leaf_version: LOG_LEAF_VERSION.into(),
            lineage_id: acdp_crypto::derive_lineage_id(&CtxId(ctx_id.clone())),
            ctx_id: CtxId(ctx_id),
            origin_registry: "registry.example.com".into(),
            created_at: chrono::DateTime::parse_from_rfc3339("2026-07-01T01:00:00.123Z")
                .unwrap()
                .with_timezone(&Utc),
            content_hash: ContentHash(format!("sha256:{}", "b".repeat(64))),
            key_fingerprint: format!("sha256:{}", "c".repeat(64)),
            receipt_hash: format!("sha256:{}", "d".repeat(64)),
        }
    }

    #[test]
    fn leaf_closed_schema_and_version_enforced() {
        let l = leaf(1);
        let wire = serde_json::to_value(&l).unwrap();
        assert_eq!(LogLeaf::from_value(&wire).unwrap(), l);

        let mut extra = wire.clone();
        extra
            .as_object_mut()
            .unwrap()
            .insert("note".into(), serde_json::json!("x"));
        assert!(matches!(
            LogLeaf::from_value(&extra).unwrap_err(),
            AcdpError::InvalidLogProof(_)
        ));

        let mut wrong = wire.clone();
        wrong["leaf_version"] = serde_json::json!("acdp-log-leaf/2");
        assert!(LogLeaf::from_value(&wrong).is_err());

        let mut bad_ts = wire.clone();
        bad_ts["created_at"] = serde_json::json!("2026-07-01T01:00:00Z");
        assert!(LogLeaf::from_value(&bad_ts).is_err());
    }

    #[test]
    fn checkpoint_mint_verify_round_trip() {
        let root = encode_sha256_hex(&acdp_crypto::merkle_tree_hash(&[]));
        let cp = signer()
            .mint_log_checkpoint(LOG_ID, 0, &root, Utc::now())
            .unwrap();
        cp.verify_signature_with_key(Some(&registry_pub()), None)
            .expect("freshly minted checkpoint must verify");
        let wire = serde_json::to_value(&cp).unwrap();
        let parsed = LogCheckpoint::from_value(&wire).unwrap();
        let raw_hash = LogCheckpoint::preimage_hash_of_value(&wire).unwrap();
        assert_eq!(raw_hash, cp.preimage_hash().unwrap());
        parsed
            .verify_signature_against_hash(&raw_hash, Some(&registry_pub()), None)
            .unwrap();
        parsed
            .cross_check_registry_binding("registry.example.com", REGISTRY_DID)
            .unwrap();
        assert!(parsed
            .cross_check_registry_binding("hostile.example", "did:web:hostile.example")
            .is_err());
        parsed
            .check_timestamp_skew(Utc::now(), chrono::Duration::seconds(120))
            .unwrap();

        // log-004-style: tampering root_hash after signing fails.
        let mut tampered = wire.clone();
        tampered["root_hash"] = serde_json::json!(format!("sha256:{}", "f".repeat(64)));
        let t = LogCheckpoint::from_value(&tampered).unwrap();
        let t_hash = LogCheckpoint::preimage_hash_of_value(&tampered).unwrap();
        let err = t
            .verify_signature_against_hash(&t_hash, Some(&registry_pub()), None)
            .unwrap_err();
        assert!(matches!(err, AcdpError::InvalidLogProof(_)), "got {err:?}");
    }

    #[test]
    fn checkpoint_closed_schema_and_domain_separation() {
        let root = encode_sha256_hex(&acdp_crypto::merkle_tree_hash(&[]));
        let cp = signer()
            .mint_log_checkpoint(LOG_ID, 0, &root, Utc::now())
            .unwrap();
        let mut wire = serde_json::to_value(&cp).unwrap();
        wire.as_object_mut()
            .unwrap()
            .insert("witnesses".into(), serde_json::json!([]));
        assert!(matches!(
            LogCheckpoint::from_value(&wire).unwrap_err(),
            AcdpError::InvalidLogProof(_)
        ));

        let mut wire = serde_json::to_value(&cp).unwrap();
        wire["checkpoint_version"] = serde_json::json!("acdp-lhr/1");
        assert!(LogCheckpoint::from_value(&wire).is_err());

        // A checkpoint never parses as a receipt and vice versa.
        let wire = serde_json::to_value(&cp).unwrap();
        assert!(crate::receipt::LineageHeadReceipt::from_value(&wire).is_err());

        // Foreign log_id refused at mint; malformed instance refused.
        assert!(signer()
            .mint_log_checkpoint("did:web:evil.example.com/log/1", 0, &root, Utc::now())
            .is_err());
        assert!(signer()
            .mint_log_checkpoint(
                "did:web:registry.example.com/log/UPPER",
                0,
                &root,
                Utc::now()
            )
            .is_err());
        assert!(signer()
            .mint_log_checkpoint(LOG_ID, 0, "sha256:short", Utc::now())
            .is_err());
    }

    /// Inclusion + consistency round trip over minted leaves, plus the
    /// log-002-style tampered-path rejection.
    #[test]
    fn inclusion_and_consistency_round_trip() {
        let leaves: Vec<LogLeaf> = (0..5).map(leaf).collect();
        let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.leaf_hash().unwrap()).collect();
        let root = acdp_crypto::merkle_tree_hash(&hashes);
        let cp = signer()
            .mint_log_checkpoint(LOG_ID, 5, &encode_sha256_hex(&root), Utc::now())
            .unwrap();

        for (i, l) in leaves.iter().enumerate() {
            let path = acdp_crypto::inclusion_path(i, &hashes).unwrap();
            let inclusion = LogInclusion {
                log_id: LOG_ID.into(),
                leaf_index: i as u64,
                tree_size: 5,
                inclusion_path: path.iter().map(encode_sha256_hex).collect(),
                log_checkpoint: cp.clone(),
                leaf: None,
            };
            inclusion.verify_reconstructed_leaf(l).unwrap();
            // Wire round trip through the closed parse.
            let wire = serde_json::to_value(&inclusion).unwrap();
            assert!(wire.get("leaf").is_none(), "absent, never null");
            LogInclusion::from_value(&wire)
                .unwrap()
                .verify_leaf_hash(&hashes[i])
                .unwrap();

            // Tampered path element → §9.1 step 6 failure.
            if !inclusion.inclusion_path.is_empty() {
                let mut bad = inclusion.clone();
                let mut raw = decode_sha256_hex(&bad.inclusion_path[0]).unwrap();
                raw[0] ^= 1;
                bad.inclusion_path[0] = encode_sha256_hex(&raw);
                let err = bad.verify_reconstructed_leaf(l).unwrap_err();
                assert!(matches!(err, AcdpError::InvalidLogProof(_)), "got {err:?}");
            }
        }

        // Binding failures (§9.1 step 4).
        let path = acdp_crypto::inclusion_path(0, &hashes).unwrap();
        let mk = |leaf_index, tree_size, log_id: &str| LogInclusion {
            log_id: log_id.into(),
            leaf_index,
            tree_size,
            inclusion_path: path.iter().map(encode_sha256_hex).collect(),
            log_checkpoint: cp.clone(),
            leaf: None,
        };
        assert!(mk(0, 4, LOG_ID).verify_leaf_hash(&hashes[0]).is_err()); // ≠ checkpoint size
        assert!(mk(5, 5, LOG_ID).verify_leaf_hash(&hashes[0]).is_err()); // index ≥ size
        assert!(mk(0, 5, "did:web:registry.example.com/log/2")
            .verify_leaf_hash(&hashes[0])
            .is_err()); // log_id mismatch

        // Consistency 3 → 5.
        let first_root = acdp_crypto::merkle_tree_hash(&hashes[..3]);
        let proof = LogConsistencyProof {
            log_id: LOG_ID.into(),
            first_tree_size: 3,
            second_tree_size: 5,
            consistency_path: acdp_crypto::consistency_proof(3, &hashes)
                .unwrap()
                .iter()
                .map(encode_sha256_hex)
                .collect(),
            log_checkpoint: cp.clone(),
        };
        proof
            .verify_against_first_root(&encode_sha256_hex(&first_root))
            .unwrap();
        // A different retained root → history-rewrite evidence.
        let err = proof
            .verify_against_first_root(&format!("sha256:{}", "e".repeat(64)))
            .unwrap_err();
        assert!(matches!(err, AcdpError::InvalidLogProof(_)), "got {err:?}");
    }

    #[test]
    fn log_id_parsing() {
        assert_eq!(
            parse_log_id(LOG_ID).unwrap(),
            ("did:web:registry.example.com", "1")
        );
        for bad in [
            "did:web:registry.example.com",                       // no /log/
            "did:key:z6Mk/log/1",                                 // not did:web
            "did:web:registry.example.com/log/",                  // empty instance
            "did:web:registry.example.com/log/UP",                // uppercase instance
            &format!("did:web:r.example/log/{}", "a".repeat(33)), // too long
        ] {
            assert!(parse_log_id(bad).is_err(), "{bad} must be rejected");
        }
    }
}
