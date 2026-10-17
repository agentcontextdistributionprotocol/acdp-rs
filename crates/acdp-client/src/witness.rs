//! Client-side transparency-log **witness cosignature** verification and
//! the witness-side minting obligation (ACDP 0.4, RFC-ACDP-0015).
//!
//! Two roles live here:
//!
//! - **Consumer** — [`verify_witness_cosignature_value`] runs the §8
//!   verification procedure for one cosignature against a checkpoint the
//!   consumer has itself verified (RFC-ACDP-0012 §9.3), and
//!   [`evaluate_witness_quorum`] computes the §8 *N-witnessed* count over
//!   a set of cosignatures under a [`WitnessPolicy`].
//! - **Witness** — [`mint_cosignature_checked`] is the *safe* mint path:
//!   it runs the §7 obligation (verify the checkpoint's own signature,
//!   then verify consistency against a retained head) BEFORE signing. A
//!   witness MUST NOT cosign a checkpoint that fails consistency — that
//!   refusal is the entire point of witnessing (§7). The raw
//!   [`acdp_types::cosignature::WitnessSigner::mint`] performs no
//!   obligation and is for callers doing those checks themselves.
//!
//! Cosignature verification failures map to
//! [`AcdpError::InvalidWitnessCosignature`] — deliberately **not**
//! `InvalidLogProof`: a cosignature failure indicts a *witness's*
//! attestation (an independent signer), not the *log* (RFC-ACDP-0015
//! §8, §10). The obligation's checkpoint-signature and consistency
//! checks reuse the RFC-ACDP-0012 machinery verbatim, so they keep their
//! `InvalidLogProof` verdict (the checkpoint, not a witness, is at
//! fault).

use std::collections::{BTreeSet, HashMap, HashSet};

use acdp_did::web::WebResolver;
use acdp_did::DidDocument;
use acdp_primitives::error::AcdpError;
use acdp_types::cosignature::{LogCosignature, WitnessSigner};
use acdp_types::log::{LogCheckpoint, LogConsistencyProof};
use chrono::{DateTime, Utc};

use crate::log::verify_log_checkpoint_value;

/// RFC-ACDP-0015 §8 step 5 RECOMMENDED forward clock-skew allowance
/// (the RFC-ACDP-0011 §7 step 6 allowance).
pub const DEFAULT_WITNESS_MAX_CLOCK_SKEW_SECONDS: u32 = 120;

/// RFC-ACDP-0015 §8.1 RECOMMENDED maximum cosignature age for
/// current-ness-sensitive decisions.
pub const DEFAULT_WITNESS_MAX_AGE_SECONDS: u32 = 300;

/// Verify one witness cosignature against a checkpoint the consumer has
/// itself verified (RFC-ACDP-0012 §9.3), following the RFC-ACDP-0015 §8
/// procedure:
///
/// 1. **Schema-closed parse** — exact `cosignature_version`
///    (`"acdp-cosig/1"`), a well-formed witness DID, a well-formed
///    `witnessed_checkpoint`, canonical millisecond `witnessed_at` /
///    `witnessed_checkpoint.timestamp` byte forms, and the §8 step 3
///    structural witness binding (`signature.key_id` is a DID URL under
///    `witness_id`).
/// 2. **Recompute and verify the witness signature** — JCS-recompute the
///    preimage from the RAW wire JSON (minus `signature`), look up
///    `signature.key_id` in the supplied witness DID document, and verify
///    over the ASCII bytes of the cosignature hash. Key acceptance
///    follows RFC-ACDP-0015 §9 / RFC-ACDP-0010 §9: the key is looked up
///    in `verificationMethod` WITHOUT requiring `assertionMethod`
///    membership, so retired witness keys keep historical cosignatures
///    verifiable.
/// 3. **Witness binding** — the witness DID document's `id` MUST equal
///    the cosignature's `witness_id` (the DID portion of
///    `signature.key_id` was already bound to `witness_id` in step 1).
///    Whether `witness_id` is a witness the consumer *trusts* is
///    deployment policy — enforced by [`evaluate_witness_quorum`], not
///    here.
/// 4. **Checkpoint binding** — `witnessed_checkpoint.{log_id, tree_size,
///    root_hash}` MUST byte-/numerically-match `expected_checkpoint`.
/// 5. **`witnessed_at` well-formedness and skew** — millisecond-
///    truncated and not in the future beyond `max_clock_skew_seconds`
///    (default [`DEFAULT_WITNESS_MAX_CLOCK_SKEW_SECONDS`]).
///
/// This is a **pure** check: the witness DID document is supplied by the
/// caller (witness trust is bootstrapped out of band — RFC-ACDP-0015
/// §13 — and direct-from-witness consumers already hold it, §6.2). Pass
/// `now = None` to use the wall clock.
///
/// Staleness (an old but honest `witnessed_at`) is deliberately NOT a
/// failure here — it is consumer freshness policy (§8.1), evaluated by
/// [`evaluate_witness_quorum`] via `WitnessPolicy::max_age_seconds`. An
/// old cosignature is *stronger* anti-backdating evidence.
pub fn verify_witness_cosignature_value(
    cosig_value: &serde_json::Value,
    witness_did_doc: &serde_json::Value,
    expected_checkpoint: &LogCheckpoint,
    now: Option<DateTime<Utc>>,
    max_clock_skew_seconds: Option<u32>,
) -> Result<LogCosignature, AcdpError> {
    // §8 step 1: closed parse + §4/§5 invariants + step 3 structural
    // witness binding (key_id DID == witness_id).
    let cosig = LogCosignature::from_value(cosig_value)?;

    // §8 step 4: checkpoint binding against the independently-held,
    // independently-verified checkpoint.
    cosig.cross_check_against_checkpoint(expected_checkpoint)?;

    // §8 step 3: the resolving witness DID document's id MUST equal
    // witness_id.
    let doc: DidDocument = serde_json::from_value(witness_did_doc.clone()).map_err(|e| {
        AcdpError::InvalidWitnessCosignature(format!("witness DID document does not parse: {e}"))
    })?;
    if doc.id != cosig.witness_id {
        return Err(AcdpError::InvalidWitnessCosignature(format!(
            "witness DID document id '{}' ≠ cosignature witness_id '{}' \
             (RFC-ACDP-0015 §8 step 3)",
            doc.id, cosig.witness_id
        )));
    }

    // §8 step 2: resolve signature.key_id in the witness DID document and
    // verify over the RAW wire preimage (re-serializing the parsed struct
    // could normalize byte details and falsely reject an honest
    // cosignature — the mistake wit-004 exists to catch).
    let key_id = &cosig.signature.key_id;
    let (_did_part, fragment) = key_id.split_once('#').ok_or_else(|| {
        AcdpError::InvalidWitnessCosignature(format!(
            "witness cosignature signature.key_id '{key_id}' has no fragment"
        ))
    })?;
    let method = doc.find_by_fragment(fragment).ok_or_else(|| {
        AcdpError::InvalidWitnessCosignature(format!(
            "witness DID document has no verification method '#{fragment}' — witness keys \
             (including retired ones) must remain in verificationMethod (RFC-ACDP-0015 §9)"
        ))
    })?;
    let raw_hash = LogCosignature::preimage_hash_of_value(cosig_value)?;
    match cosig.signature.algorithm.as_str() {
        "ed25519" => {
            let key = method.ed25519_public_key_bytes().map_err(|e| {
                AcdpError::InvalidWitnessCosignature(format!("witness key extraction: {e}"))
            })?;
            cosig.verify_signature_against_hash(&raw_hash, Some(&key), None)?;
        }
        "ecdsa-p256" => {
            let key = method.ecdsa_p256_public_key_sec1().map_err(|e| {
                AcdpError::InvalidWitnessCosignature(format!("witness key extraction: {e}"))
            })?;
            cosig.verify_signature_against_hash(&raw_hash, None, Some(&key))?;
        }
        other => {
            return Err(AcdpError::InvalidWitnessCosignature(format!(
                "witness cosignature signature algorithm '{other}' is not supported"
            )));
        }
    }

    // §8 step 5: witnessed_at well-formedness + forward-skew.
    let now = now.unwrap_or_else(Utc::now);
    let skew = chrono::Duration::seconds(
        max_clock_skew_seconds.unwrap_or(DEFAULT_WITNESS_MAX_CLOCK_SKEW_SECONDS) as i64,
    );
    cosig.check_witnessed_at_skew(now, skew)?;

    Ok(cosig)
}

/// Consumer quorum and freshness policy for witness cosignatures
/// (RFC-ACDP-0015 §8.1), mirroring the RFC-ACDP-0011 freshness stance.
/// These are **local** consumer decisions, never wire-visible
/// requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessPolicy {
    /// Minimum number of DISTINCT trusted witnesses a checkpoint must
    /// carry before it is relied upon (RFC-ACDP-0015 §8.1). Default
    /// **1** — one honest witness suffices for split-view protection;
    /// deployments with stronger requirements SHOULD raise it.
    pub min_witnesses: u32,
    /// Maximum acceptable `witnessed_at` staleness for a decision that
    /// depends on the checkpoint being *current* (§8.1). Default
    /// `Some(300)`. A verified-but-older cosignature is reported as
    /// non-fresh (via [`WitnessQuorumReport::fresh_witnessed_count`]),
    /// never as a verification failure — for anti-backdating a
    /// cosignature never expires. `None` disables the freshness split.
    pub max_age_seconds: Option<u32>,
    /// RFC-ACDP-0015 §8 step 5 forward clock-skew allowance passed to
    /// [`verify_witness_cosignature_value`]. Default
    /// [`DEFAULT_WITNESS_MAX_CLOCK_SKEW_SECONDS`].
    pub max_clock_skew_seconds: u32,
}

impl Default for WitnessPolicy {
    fn default() -> Self {
        Self {
            min_witnesses: 1,
            max_age_seconds: Some(DEFAULT_WITNESS_MAX_AGE_SECONDS),
            max_clock_skew_seconds: DEFAULT_WITNESS_MAX_CLOCK_SKEW_SECONDS,
        }
    }
}

/// The outcome of [`evaluate_witness_quorum`]: the RFC-ACDP-0015 §8
/// *N-witnessed* verdict over one checkpoint, plus a §8.1 freshness
/// split.
#[derive(Debug, Clone)]
pub struct WitnessQuorumReport {
    /// *N* — the number of DISTINCT trusted `witness_id` values whose
    /// cosignatures passed §8 steps 1–5 over the evaluated checkpoint's
    /// `(log_id, tree_size, root_hash)` tuple. Multiple cosignatures
    /// from one witness count once.
    pub witnessed_count: usize,
    /// The distinct trusted witness DIDs that verified, sorted.
    pub witnesses: Vec<String>,
    /// `witnessed_count >= policy.min_witnesses` — the split-view /
    /// anti-rewrite quorum (a cosignature never expires for this use).
    pub meets_quorum: bool,
    /// Distinct verified witnesses whose (freshest) counted cosignature
    /// is within `policy.max_age_seconds`. Equal to `witnessed_count`
    /// when `max_age_seconds` is `None`.
    pub fresh_witnessed_count: usize,
    /// `fresh_witnessed_count >= policy.min_witnesses` — the quorum for
    /// current-ness-sensitive decisions (§8.1).
    pub meets_fresh_quorum: bool,
    /// Per-cosignature verification failures (§8 steps 1–5) for
    /// cosignatures that targeted the evaluated tuple and named a
    /// *trusted* witness. Cosignatures over a different checkpoint tuple,
    /// or from untrusted witnesses, are silently skipped — they are not
    /// failures, they simply do not count toward *N* (§8).
    pub failures: Vec<AcdpError>,
}

/// Compute the RFC-ACDP-0015 §8 *N-witnessed* verdict for a checkpoint
/// the consumer has itself verified.
///
/// `cosignatures` are raw cosignature wire values (e.g. a checkpoint
/// response's `witness_signatures` array, §6.1, or a direct-from-witness
/// fetch, §6.2). `witness_did_docs` maps each `witness_id` to its
/// resolved DID document (witness trust and discovery are deployment
/// policy — §13). `trusted_witnesses` is the set of witness DIDs the
/// consumer trusts; only cosignatures naming one of these can count.
///
/// A cosignature counts toward *N* iff it (a) names a trusted witness,
/// (b) covers the same `(log_id, tree_size, root_hash)` as
/// `expected_checkpoint`, and (c) passes every §8 step. Distinct
/// `witness_id` values are counted; repeats from one witness count once.
/// A cosignature that fails a step does not fail the checkpoint (that
/// verdict is RFC-ACDP-0012 §9.3, independent) — it is recorded in
/// [`WitnessQuorumReport::failures`] and simply does not count.
pub fn evaluate_witness_quorum(
    cosignatures: &[serde_json::Value],
    witness_did_docs: &HashMap<String, serde_json::Value>,
    trusted_witnesses: &HashSet<String>,
    expected_checkpoint: &LogCheckpoint,
    policy: &WitnessPolicy,
    now: Option<DateTime<Utc>>,
) -> WitnessQuorumReport {
    let now = now.unwrap_or_else(Utc::now);
    let expected_tuple = (
        expected_checkpoint.log_id.as_str(),
        expected_checkpoint.tree_size,
        expected_checkpoint.root_hash.as_str(),
    );

    let mut verified: BTreeSet<String> = BTreeSet::new();
    let mut fresh: BTreeSet<String> = BTreeSet::new();
    let mut failures: Vec<AcdpError> = Vec::new();

    for value in cosignatures {
        // Peek at the tuple + witness_id via the closed parse. A
        // malformed cosignature can't be attributed to a tuple/witness,
        // so it is skipped here rather than blamed on this checkpoint
        // (some other checkpoint's evaluator may record it).
        let Ok(peek) = LogCosignature::from_value(value) else {
            continue;
        };
        if peek.checkpoint_tuple() != expected_tuple {
            continue; // evidence about a different checkpoint (§8 step 4)
        }
        if !trusted_witnesses.contains(&peek.witness_id) {
            continue; // untrusted — cannot count toward N (§8 step 3)
        }
        // A trusted witness over our tuple: it MUST verify to count.
        let Some(doc) = witness_did_docs.get(&peek.witness_id) else {
            failures.push(AcdpError::InvalidWitnessCosignature(format!(
                "no DID document supplied for trusted witness '{}' — cannot verify its \
                 cosignature (RFC-ACDP-0015 §8 step 2)",
                peek.witness_id
            )));
            continue;
        };
        match verify_witness_cosignature_value(
            value,
            doc,
            expected_checkpoint,
            Some(now),
            Some(policy.max_clock_skew_seconds),
        ) {
            Ok(cosig) => {
                verified.insert(cosig.witness_id.clone());
                let within_age = policy
                    .max_age_seconds
                    .is_none_or(|max| cosig.age_at(now) <= chrono::Duration::seconds(max as i64));
                if within_age {
                    fresh.insert(cosig.witness_id);
                }
            }
            Err(e) => failures.push(e),
        }
    }

    let witnessed_count = verified.len();
    let fresh_witnessed_count = fresh.len();
    let min = policy.min_witnesses as usize;
    WitnessQuorumReport {
        witnessed_count,
        witnesses: verified.into_iter().collect(),
        meets_quorum: witnessed_count >= min,
        fresh_witnessed_count,
        meets_fresh_quorum: fresh_witnessed_count >= min,
        failures,
    }
}

// ── Witness-side obligation (the safe mint path) ─────────────────────────────

/// The retained-head consistency input to [`mint_cosignature_checked`]
/// (RFC-ACDP-0015 §7 step 2): the witness's retained root for `log_id`
/// at some earlier `tree_size`, and an RFC-ACDP-0012 §9.2 consistency
/// proof from that head to the checkpoint being cosigned.
pub struct WitnessConsistencyCheck<'a> {
    /// The `root_hash` (wire form `"sha256:<hex>"`) the witness retained
    /// for this log at the proof's `first_tree_size` — the anchor the
    /// new checkpoint's consistency is checked against.
    pub retained_root_hash: &'a str,
    /// The raw wire value of the RFC-ACDP-0012 consistency proof whose
    /// embedded `log_checkpoint` is the checkpoint being cosigned.
    pub consistency_proof: &'a serde_json::Value,
}

/// The **safe** witness mint path (RFC-ACDP-0015 §7): run the witness
/// obligation, then — only if it passes — cosign.
///
/// 1. **Verify the checkpoint's own signature** (§7 step 1) via the
///    RFC-ACDP-0012 §9.3 procedure ([`verify_log_checkpoint_value`]):
///    closed parse, signature against the registry DID key, registry
///    binding, and timestamp skew. A witness MUST NOT cosign a
///    checkpoint whose own signature does not verify.
/// 2. **Verify consistency from the retained head** (§7 step 2), when a
///    [`WitnessConsistencyCheck`] is supplied: the proof MUST be about
///    *this* checkpoint (same `log_id`, `tree_size`, `root_hash`), and
///    it MUST verify against the retained root (RFC-ACDP-0012 §9.2). A
///    witness **MUST NOT cosign a checkpoint that fails consistency**
///    against its retained head — that refusal is the entire point of
///    witnessing. On the witness's *first* observation of a log there is
///    no retained head; pass `None` (the checkpoint becomes the anchor,
///    proving no consistency yet, §7).
/// 3. **Cosign** (§7 step 3) with the witness key, copying the verified
///    checkpoint's `{log_id, tree_size, root_hash, timestamp}` verbatim
///    and stamping `witnessed_at`.
///
/// An obligation failure returns the underlying error and **no
/// cosignature** — a signature/consistency failure keeps its
/// RFC-ACDP-0012 `InvalidLogProof` verdict (the checkpoint, not a
/// witness, is at fault). On a consistency failure the witness MUST also
/// persist both checkpoints and the failing proof as evidence (§7,
/// RFC-ACDP-0012 §15); that retention is the caller's responsibility.
#[allow(clippy::too_many_arguments)]
pub async fn mint_cosignature_checked(
    signer: &WitnessSigner,
    checkpoint_value: &serde_json::Value,
    serving_authority: &str,
    capabilities_registry_did: &str,
    consistency: Option<WitnessConsistencyCheck<'_>>,
    witnessed_at: DateTime<Utc>,
    max_clock_skew: chrono::Duration,
    resolver: &WebResolver,
) -> Result<LogCosignature, AcdpError> {
    // §7 step 1: verify C's own checkpoint signature (RFC-ACDP-0012 §9.3).
    let checkpoint = verify_log_checkpoint_value(
        checkpoint_value,
        serving_authority,
        capabilities_registry_did,
        max_clock_skew,
        resolver,
    )
    .await?;

    // §7 step 2: consistency against the retained head, if any.
    if let Some(cc) = consistency {
        let proof = LogConsistencyProof::from_value(cc.consistency_proof)?;
        // The proof MUST be about the very checkpoint being cosigned —
        // otherwise a witness could be tricked into checking consistency
        // of an unrelated checkpoint.
        if proof.log_id != checkpoint.log_id
            || proof.second_tree_size != checkpoint.tree_size
            || proof.log_checkpoint.root_hash != checkpoint.root_hash
        {
            return Err(AcdpError::InvalidLogProof(
                "witness obligation: the consistency proof's checkpoint does not match the \
                 checkpoint being cosigned (RFC-ACDP-0015 §7 step 2)"
                    .into(),
            ));
        }
        // Fails with InvalidLogProof when C is not consistent with the
        // retained head — the witness MUST refuse to cosign (§7 step 2).
        proof.verify_against_first_root(cc.retained_root_hash)?;
    }

    // §7 step 3: only now cosign.
    signer.mint(&checkpoint, witnessed_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_crypto::SigningKey;
    use acdp_types::cosignature::WitnessSigner;
    use acdp_types::receipt::ReceiptSigner;

    const REGISTRY_DID: &str = "did:web:registry.example.com";
    const LOG_ID: &str = "did:web:registry.example.com/log/1";
    const WITNESS_A: &str = "did:web:witness.example.org";
    const WITNESS_B: &str = "did:web:witness-2.example.org";

    fn checkpoint(tree_size: u64, root: &str) -> LogCheckpoint {
        ReceiptSigner::new(
            SigningKey::from_bytes(&[0x11u8; 32]),
            REGISTRY_DID,
            format!("{REGISTRY_DID}#receipt-key-1"),
        )
        .unwrap()
        .mint_log_checkpoint(LOG_ID, tree_size, root, Utc::now())
        .unwrap()
    }

    /// Build a minimal witness did.json with the key in BOTH
    /// verificationMethod and assertionMethod.
    fn witness_doc(did: &str, fragment: &str, pub_key: &[u8; 32]) -> serde_json::Value {
        let vm_id = format!("{did}#{fragment}");
        serde_json::json!({
            "id": did,
            "verificationMethod": [{
                "id": vm_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": base64_url(pub_key),
                }
            }],
            "assertionMethod": [vm_id],
        })
    }

    fn base64_url(bytes: &[u8]) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn signer(seed: u8, witness_id: &str) -> WitnessSigner {
        WitnessSigner::new(
            SigningKey::from_bytes(&[seed; 32]),
            witness_id,
            format!("{witness_id}#witness-key-1"),
        )
        .unwrap()
    }

    #[test]
    fn single_cosignature_verifies_and_binds() {
        let root = acdp_types::log::encode_sha256_hex(&[0x0bu8; 32]);
        let cp = checkpoint(5, &root);
        let pub_a = SigningKey::from_bytes(&[0x33u8; 32]).verifying_key_bytes();
        let doc = witness_doc(WITNESS_A, "witness-key-1", &pub_a);
        let cosig = signer(0x33, WITNESS_A).mint(&cp, Utc::now()).unwrap();
        let wire = serde_json::to_value(&cosig).unwrap();

        verify_witness_cosignature_value(&wire, &doc, &cp, None, None)
            .expect("golden-shaped cosignature verifies");

        // §8 step 4: binding to a different checkpoint fails.
        let other = checkpoint(6, &root);
        assert!(matches!(
            verify_witness_cosignature_value(&wire, &doc, &other, None, None).unwrap_err(),
            AcdpError::InvalidWitnessCosignature(_)
        ));

        // §8 step 3: a DID doc whose id ≠ witness_id fails.
        let wrong_doc = witness_doc(WITNESS_B, "witness-key-1", &pub_a);
        assert!(verify_witness_cosignature_value(&wire, &wrong_doc, &cp, None, None).is_err());
    }

    /// wit-004 shape: a cosignature signed by the WRONG witness key does
    /// not verify under witness A's resolved key.
    #[test]
    fn key_mismatch_fails() {
        let root = acdp_types::log::encode_sha256_hex(&[0x0bu8; 32]);
        let cp = checkpoint(5, &root);
        // Body is witness A's, but sign with witness B's key.
        let mut cosig = signer(0x33, WITNESS_A).mint(&cp, Utc::now()).unwrap();
        let hash = cosig.preimage_hash().unwrap();
        let (_alg, wrong_value) =
            acdp_crypto::sign::AcdpSigningKey::from(SigningKey::from_bytes(&[0x44u8; 32]))
                .sign_content_hash(&hash);
        cosig.signature.value = wrong_value;
        let wire = serde_json::to_value(&cosig).unwrap();

        let pub_a = SigningKey::from_bytes(&[0x33u8; 32]).verifying_key_bytes();
        let doc = witness_doc(WITNESS_A, "witness-key-1", &pub_a);
        let err = verify_witness_cosignature_value(&wire, &doc, &cp, None, None).unwrap_err();
        assert!(
            matches!(err, AcdpError::InvalidWitnessCosignature(_)),
            "got {err:?}"
        );
        assert!(!err.is_transient());
    }

    /// wit-003 shape: two distinct trusted witnesses over the same tuple
    /// → 2-witnessed. Untrusted witnesses and different tuples do not
    /// count.
    #[test]
    fn quorum_counts_distinct_trusted_witnesses() {
        let root = acdp_types::log::encode_sha256_hex(&[0x0bu8; 32]);
        let cp = checkpoint(5, &root);

        let pub_a = SigningKey::from_bytes(&[0x33u8; 32]).verifying_key_bytes();
        let pub_b = SigningKey::from_bytes(&[0x44u8; 32]).verifying_key_bytes();
        let cosig_a =
            serde_json::to_value(signer(0x33, WITNESS_A).mint(&cp, Utc::now()).unwrap()).unwrap();
        let cosig_b =
            serde_json::to_value(signer(0x44, WITNESS_B).mint(&cp, Utc::now()).unwrap()).unwrap();
        // A second cosignature from witness A (fresh witnessed_at) counts once.
        let cosig_a2 = serde_json::to_value(
            signer(0x33, WITNESS_A)
                .mint(&cp, Utc::now() + chrono::Duration::seconds(1))
                .unwrap(),
        )
        .unwrap();

        let mut docs = HashMap::new();
        docs.insert(
            WITNESS_A.to_string(),
            witness_doc(WITNESS_A, "witness-key-1", &pub_a),
        );
        docs.insert(
            WITNESS_B.to_string(),
            witness_doc(WITNESS_B, "witness-key-1", &pub_b),
        );
        let trusted: HashSet<String> = [WITNESS_A.to_string(), WITNESS_B.to_string()]
            .into_iter()
            .collect();

        let report = evaluate_witness_quorum(
            &[cosig_a.clone(), cosig_b, cosig_a2],
            &docs,
            &trusted,
            &cp,
            &WitnessPolicy::default(),
            None,
        );
        assert_eq!(report.witnessed_count, 2, "distinct witnesses A and B");
        assert!(report.meets_quorum);
        // Sorted: WITNESS_B ('-') sorts before WITNESS_A ('.').
        assert_eq!(
            report.witnesses,
            vec![WITNESS_B.to_string(), WITNESS_A.to_string()]
        );
        assert!(report.failures.is_empty());

        // Only trusting A → 1-witnessed; require 2 → not met.
        let only_a: HashSet<String> = [WITNESS_A.to_string()].into_iter().collect();
        let strict = WitnessPolicy {
            min_witnesses: 2,
            ..WitnessPolicy::default()
        };
        let report = evaluate_witness_quorum(&[cosig_a], &docs, &only_a, &cp, &strict, None);
        assert_eq!(report.witnessed_count, 1);
        assert!(!report.meets_quorum);
    }
}
