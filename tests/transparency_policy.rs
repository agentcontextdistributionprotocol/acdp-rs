//! Transparency corroboration during verification (RFC-ACDP-0012 §9,
//! RFC-ACDP-0015 §8): `VerificationPolicy::{log_inclusion,
//! witness_quorum}` wire the log and witness verifiers into
//! `VerifiedContext` and `VerificationReport`. Their verdicts are reported
//! separately from the body, receipt and revocation verdicts. A failure
//! never invalidates the context unless the policy opts in (§9.3).

mod common;
mod world;

use std::sync::atomic::Ordering;

use acdp::client::{
    CannotVerifyReason, LogInclusionPolicy, LogInclusionVerdict, ReceiptPolicy, VerificationPolicy,
    VerifiedContext, WitnessEnforcement, WitnessQuorumPolicy,
};
use acdp::crypto::SigningKey;
use acdp::did::{did_key_from_ed25519, did_key_url};
use acdp::error::AcdpError;
use acdp::registry::MerkleLog;
use acdp::types::cosignature::WitnessSigner;
use acdp::types::log::{LogCheckpoint, LogLeaf};
use acdp::types::receipt::ReceiptSigner;
use acdp::types::{ContextType, FullContext};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use world::*;

const LOG_ID: &str = "did:web:localhost/log/1";
const W1: [u8; 32] = [0x51u8; 32];
const W2: [u8; 32] = [0x52u8; 32];
const WEB_WITNESS: &str = "did:web:witness.example";

fn one_key() -> Value {
    producer_doc(&[("key-1", K1)], &["key-1"])
}

fn registry_signer() -> ReceiptSigner {
    ReceiptSigner::new(
        SigningKey::from_bytes(&RECEIPT_SEED),
        REGISTRY_DID,
        format!("{REGISTRY_DID}#receipt-key-1"),
    )
    .unwrap()
}

fn did_key_witness(seed: [u8; 32]) -> WitnessSigner {
    let did = did_key_from_ed25519(&SigningKey::from_bytes(&seed).verifying_key_bytes());
    let key_id = did_key_url(&did).unwrap();
    WitnessSigner::new(SigningKey::from_bytes(&seed), did, key_id).unwrap()
}

fn web_witness() -> (WitnessSigner, Value) {
    let signer = WitnessSigner::new(
        SigningKey::from_bytes(&W2),
        WEB_WITNESS,
        format!("{WEB_WITNESS}#witness-key-1"),
    )
    .unwrap();
    let doc = json!({
        "id": WEB_WITNESS,
        "verificationMethod": [{
            "id": format!("{WEB_WITNESS}#witness-key-1"),
            "type": "JsonWebKey2020",
            "controller": WEB_WITNESS,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&W2).verifying_key_bytes()),
            }
        }],
        "assertionMethod": [format!("{WEB_WITNESS}#witness-key-1")],
    });
    (signer, doc)
}

/// The served wire value of `ctx`.
async fn others(w: &World) -> [FullContext; 2] {
    [
        w.publish("key-1", K1, ContextType::Analysis, None).await,
        w.publish("key-1", K1, ContextType::Analysis, None).await,
    ]
}

fn served(w: &World, ctx: &FullContext) -> Value {
    w.contexts
        .read()
        .unwrap()
        .get(ctx.body.ctx_id.as_str())
        .unwrap()
        .clone()
}

/// The registry's §7.1 leaf for `ctx`, built from the served receipt.
fn leaf_of(w: &World, ctx: &FullContext) -> LogLeaf {
    let v = served(w, ctx);
    let receipt = &v["registry_receipt"];
    LogLeaf::for_publish(
        &ctx.body,
        &ctx.body.content_hash,
        receipt["key_fingerprint"].as_str().unwrap(),
        receipt,
    )
    .unwrap()
}

/// Append `ctx` (between `others`) to a fresh log, checkpoint
/// it, and serve its inclusion proof as `log_inclusion`. Returns the
/// checkpoint.
fn serve_inclusion(w: &World, ctx: &FullContext, others: &[FullContext; 2]) -> LogCheckpoint {
    let mut log = MerkleLog::new(LOG_ID).unwrap();
    log.append(leaf_of(w, &others[0])).unwrap();
    let idx = log.append(leaf_of(w, ctx)).unwrap();
    log.append(leaf_of(w, &others[1])).unwrap();
    let cp = log
        .checkpoint(&registry_signer(), chrono::Utc::now())
        .unwrap();
    let proof = log.inclusion_proof(idx, &cp).unwrap();
    w.tamper(ctx.body.ctx_id.as_str(), |v| {
        v["log_inclusion"] = serde_json::to_value(&proof).unwrap();
    });
    cp
}

fn serve_cosignatures(w: &World, ctx: &FullContext, cosigs: Vec<Value>) {
    w.tamper(ctx.body.ctx_id.as_str(), |v| {
        v["witness_signatures"] = Value::Array(cosigs);
    });
}

fn cosign(signer: &WitnessSigner, cp: &LogCheckpoint) -> Value {
    serde_json::to_value(signer.mint(cp, chrono::Utc::now()).unwrap()).unwrap()
}

fn with_log(log_inclusion: LogInclusionPolicy) -> VerificationPolicy {
    VerificationPolicy {
        log_inclusion,
        ..VerificationPolicy::default()
    }
}

async fn fetch(w: &World, ctx: &FullContext, policy: &VerificationPolicy) -> VerifiedContext {
    VerifiedContext::fetch_with_policy(&w.client(), &w.resolver(), &ctx.body.ctx_id, policy)
        .await
        .expect("verifies")
}

#[tokio::test]
async fn valid_inclusion_is_reported_and_ignored_by_default() {
    let w = World::start(one_key()).await;
    let other = others(&w).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let cp = serve_inclusion(&w, &ctx, &other);

    // Default policy: the proof is preserved, not evaluated.
    let v = fetch(&w, &ctx, &VerificationPolicy::default()).await;
    assert!(v.log_inclusion_verdict().is_none());
    assert!(v.verified_log_inclusion().is_none());
    assert!(v.full_context().log_inclusion.is_some());

    for policy in [
        LogInclusionPolicy::VerifyIfPresent,
        LogInclusionPolicy::Require,
    ] {
        let v = fetch(&w, &ctx, &with_log(policy)).await;
        assert!(
            v.log_inclusion_verdict()
                .is_some_and(LogInclusionVerdict::is_included),
            "{policy:?}"
        );
        let inclusion = v.verified_log_inclusion().expect("verified");
        assert_eq!(inclusion.leaf_index, 1);
        assert_eq!(inclusion.log_checkpoint.root_hash, cp.root_hash);
        assert!(v.witness_quorum().is_none());
    }
}

/// §9.3: a failing proof "invalidates nothing else": it is reported, and
/// the context still verifies, unless the policy is `Require`.
#[tokio::test]
async fn failing_proof_is_reported_not_fatal_unless_required() {
    let w = World::start(one_key()).await;
    let other = others(&w).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    serve_inclusion(&w, &ctx, &other);
    // Serve `other`'s proof position for `ctx`: the leaf the consumer
    // rebuilds from `ctx` is not at index 0.
    w.tamper(ctx.body.ctx_id.as_str(), |v| {
        v["log_inclusion"]["leaf_index"] = json!(0);
    });

    let v = fetch(&w, &ctx, &with_log(LogInclusionPolicy::VerifyIfPresent)).await;
    assert!(
        matches!(
            v.log_inclusion_verdict()
                .and_then(LogInclusionVerdict::error),
            Some(AcdpError::InvalidLogProof(_))
        ),
        "{:?}",
        v.log_inclusion_verdict()
    );
    assert!(v.verified_log_inclusion().is_none());
    assert!(
        v.receipt_verdict().is_some_and(|r| r.is_ok()),
        "receipt verdict unaffected"
    );

    let err = VerifiedContext::fetch_with_policy(
        &w.client(),
        &w.resolver(),
        &ctx.body.ctx_id,
        &with_log(LogInclusionPolicy::Require),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AcdpError::InvalidLogProof(_)), "{err:?}");
}

/// A proof bound to another registry's checkpoint fails the §9.3 step 3
/// binding (log_id DID vs. serving authority and capabilities).
#[tokio::test]
async fn checkpoint_from_another_registry_is_rejected() {
    let w = World::start(one_key()).await;
    let other = others(&w).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    serve_inclusion(&w, &ctx, &other);
    w.tamper(ctx.body.ctx_id.as_str(), |v| {
        v["log_inclusion"]["log_checkpoint"]["log_id"] = json!("did:web:evil.example/log/1");
    });
    let v = fetch(&w, &ctx, &with_log(LogInclusionPolicy::VerifyIfPresent)).await;
    assert!(matches!(
        v.log_inclusion_verdict()
            .and_then(LogInclusionVerdict::error),
        Some(AcdpError::InvalidLogProof(_))
    ));
}

#[tokio::test]
async fn require_fails_on_an_absent_proof() {
    let w = World::start(one_key()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;

    let v = fetch(&w, &ctx, &with_log(LogInclusionPolicy::VerifyIfPresent)).await;
    assert!(
        v.log_inclusion_verdict().is_none(),
        "absent is not evaluated"
    );

    let err = VerifiedContext::fetch_with_policy(
        &w.client(),
        &w.resolver(),
        &ctx.body.ctx_id,
        &with_log(LogInclusionPolicy::Require),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AcdpError::InvalidLogProof(ref m) if m.contains("no log_inclusion")),
        "{err:?}"
    );
}

fn with_log_and_receipts(log_inclusion: LogInclusionPolicy) -> VerificationPolicy {
    VerificationPolicy {
        log_inclusion,
        receipts: ReceiptPolicy::VerifyAndReport,
        ..VerificationPolicy::default()
    }
}

/// Assert the log verdict is cannot-verify for `reason` under
/// `VerifyIfPresent`, and that `Require` fails closed without indicting
/// the log (spec #78 L1).
async fn assert_cannot_verify(w: &World, ctx: &FullContext, reason: CannotVerifyReason) {
    let v = fetch(
        w,
        ctx,
        &with_log_and_receipts(LogInclusionPolicy::VerifyIfPresent),
    )
    .await;
    let verdict = v.log_inclusion_verdict().expect("evaluated");
    assert_eq!(verdict.cannot_verify_reason(), Some(reason), "{verdict:?}");
    assert_eq!(verdict.as_str(), "cannot_verify");
    assert!(!verdict.is_included() && verdict.error().is_none());
    assert!(
        v.verified_log_inclusion().is_none(),
        "never reported logged"
    );

    let (_, report) = VerifiedContext::fetch_report(
        &w.client(),
        &w.resolver(),
        &ctx.body.ctx_id,
        &with_log_and_receipts(LogInclusionPolicy::VerifyIfPresent),
    )
    .await
    .unwrap();
    assert_eq!(
        report
            .log_inclusion_verdict
            .as_ref()
            .and_then(LogInclusionVerdict::cannot_verify_reason),
        Some(reason)
    );

    let err = VerifiedContext::fetch_with_policy(
        &w.client(),
        &w.resolver(),
        &ctx.body.ctx_id,
        &with_log_and_receipts(LogInclusionPolicy::Require),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AcdpError::InvalidReceipt(ref m) if m.contains("cannot be verified")),
        "{err:?}"
    );
}

/// log-005 A (spec #78 L1): with no receipt, the leaf cannot be rebuilt
/// from verified material, so the proof is cannot-verify — not logged,
/// and not `invalid_log_proof`.
#[tokio::test]
async fn log_005_a_proof_without_a_receipt_cannot_be_verified() {
    let w = World::start(one_key()).await;
    let other = others(&w).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    serve_inclusion(&w, &ctx, &other);
    w.strip_receipts.store(true, Ordering::SeqCst);
    assert_cannot_verify(&w, &ctx, CannotVerifyReason::ReceiptAbsent).await;
}

/// log-005 B: a tampered receipt is reported in its own verdict
/// (`invalid_receipt`); the log verdict is cannot-verify, as in A.
#[tokio::test]
async fn log_005_b_tampered_receipt_is_cannot_verify_and_reported_separately() {
    let w = World::start(one_key()).await;
    let other = others(&w).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    serve_inclusion(&w, &ctx, &other);
    w.tamper(ctx.body.ctx_id.as_str(), |v| {
        v["registry_receipt"]["created_at"] = json!("2020-01-01T00:00:00.000Z");
    });
    let v = fetch(
        &w,
        &ctx,
        &with_log_and_receipts(LogInclusionPolicy::VerifyIfPresent),
    )
    .await;
    assert!(
        matches!(v.receipt_verdict(), Some(Err(AcdpError::InvalidReceipt(_)))),
        "{:?}",
        v.receipt_verdict()
    );
    assert_cannot_verify(&w, &ctx, CannotVerifyReason::ReceiptInvalid).await;
}

/// log-005 C: a served `leaf` that matches the true leaf does not make an
/// unreceipted proof verifiable — the echo is never trusted.
#[tokio::test]
async fn log_005_c_echoed_leaf_is_never_trusted() {
    let w = World::start(one_key()).await;
    let other = others(&w).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    serve_inclusion(&w, &ctx, &other);
    let leaf = serde_json::to_value(leaf_of(&w, &ctx)).unwrap();
    w.tamper(ctx.body.ctx_id.as_str(), |v| {
        v["log_inclusion"]["leaf"] = leaf.clone();
    });
    w.strip_receipts.store(true, Ordering::SeqCst);
    assert_cannot_verify(&w, &ctx, CannotVerifyReason::ReceiptAbsent).await;
}

/// L1 + L2: without a receipt the inclusion is cannot-verify, but the
/// checkpoint itself still verifies (§9.3 needs no leaf), so a witness
/// quorum is counted over it. A tampered checkpoint is not witnessed and
/// fails via `invalid_log_proof`, while the log verdict stays
/// cannot-verify.
#[tokio::test]
async fn witness_quorum_without_a_receipt_uses_the_verified_checkpoint() {
    let w = World::start(one_key()).await;
    let other = others(&w).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let cp = serve_inclusion(&w, &ctx, &other);
    let w1 = did_key_witness(W1);
    serve_cosignatures(&w, &ctx, vec![cosign(&w1, &cp)]);
    w.strip_receipts.store(true, Ordering::SeqCst);
    let policy = VerificationPolicy {
        witness_quorum: Some(WitnessQuorumPolicy::new([w1.witness_id()])),
        ..VerificationPolicy::default()
    };
    let v = fetch(&w, &ctx, &policy).await;
    assert_eq!(
        v.log_inclusion_verdict()
            .and_then(LogInclusionVerdict::cannot_verify_reason),
        Some(CannotVerifyReason::ReceiptAbsent)
    );
    assert!(v.witness_quorum().unwrap().as_ref().unwrap().meets_quorum);

    // Scenario X shape: the root is altered after signing.
    w.tamper(ctx.body.ctx_id.as_str(), |v| {
        v["log_inclusion"]["log_checkpoint"]["root_hash"] =
            json!(format!("sha256:{}", "0".repeat(64)));
    });
    let v = fetch(&w, &ctx, &policy).await;
    assert!(
        matches!(v.witness_quorum(), Some(Err(AcdpError::InvalidLogProof(_)))),
        "{:?}",
        v.witness_quorum()
    );
    assert_eq!(
        v.log_inclusion_verdict()
            .and_then(LogInclusionVerdict::cannot_verify_reason),
        Some(CannotVerifyReason::ReceiptAbsent)
    );
}

/// wit-005 A: the checkpoint's root is altered after signing (log-004
/// tampering) and a trusted cosignature over the altered triple verifies.
/// Log-proof checking is off, but the checkpoint is verified anyway: not
/// witnessed, reported via `invalid_log_proof`, never
/// `invalid_witness_cosignature` — advisory or enforced.
#[tokio::test]
async fn wit_005_a_altered_checkpoint_is_never_witnessed() {
    let w = World::start(one_key()).await;
    let other = others(&w).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let mut cp = serve_inclusion(&w, &ctx, &other);
    let altered = format!("sha256:{}", "0".repeat(64));
    w.tamper(ctx.body.ctx_id.as_str(), |v| {
        v["log_inclusion"]["log_checkpoint"]["root_hash"] = json!(&altered);
    });
    cp.root_hash = altered;
    let w1 = did_key_witness(W1);
    serve_cosignatures(&w, &ctx, vec![cosign(&w1, &cp)]);

    let witnesses = WitnessQuorumPolicy::new([w1.witness_id()]);
    let policy = VerificationPolicy {
        witness_quorum: Some(witnesses.clone()),
        ..VerificationPolicy::default()
    };
    assert_eq!(policy.log_inclusion, LogInclusionPolicy::default());
    let v = fetch(&w, &ctx, &policy).await;
    assert!(
        matches!(v.witness_quorum(), Some(Err(AcdpError::InvalidLogProof(_)))),
        "{:?}",
        v.witness_quorum()
    );

    let enforced = VerificationPolicy {
        witness_quorum: Some(witnesses.enforce(WitnessEnforcement::RequireQuorum)),
        ..VerificationPolicy::default()
    };
    let err =
        VerifiedContext::fetch_with_policy(&w.client(), &w.resolver(), &ctx.body.ctx_id, &enforced)
            .await
            .unwrap_err();
    assert!(matches!(err, AcdpError::InvalidLogProof(_)), "{err:?}");
}

/// wit-005 B: the checkpoint verifies and the trusted cosignature over it
/// verifies — 1-witnessed — while inclusion, with no receipt, is reported
/// separately as cannot-verify.
#[tokio::test]
async fn wit_005_b_quorum_counts_without_a_receipt() {
    let w = World::start(one_key()).await;
    let other = others(&w).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let cp = serve_inclusion(&w, &ctx, &other);
    let w1 = did_key_witness(W1);
    serve_cosignatures(&w, &ctx, vec![cosign(&w1, &cp)]);
    w.strip_receipts.store(true, Ordering::SeqCst);
    let policy = VerificationPolicy {
        witness_quorum: Some(
            WitnessQuorumPolicy::new([w1.witness_id()]).enforce(WitnessEnforcement::RequireQuorum),
        ),
        ..VerificationPolicy::default()
    };
    let v = fetch(&w, &ctx, &policy).await;
    let report = v.witness_quorum().unwrap().as_ref().unwrap();
    assert_eq!(report.witnessed_count, 1);
    assert!(report.meets_quorum);
    assert_eq!(
        v.log_inclusion_verdict()
            .and_then(LogInclusionVerdict::cannot_verify_reason),
        Some(CannotVerifyReason::ReceiptAbsent)
    );
}

/// RFC-ACDP-0015 §8: trusted cosignatures over the verified checkpoint
/// count toward the quorum. Witnesses can be did:key (resolved offline) or
/// did:web with a pinned document. Untrusted witnesses never count.
#[tokio::test]
async fn witness_quorum_is_reported_over_the_verified_checkpoint() {
    let w = World::start(one_key()).await;
    let other = others(&w).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let cp = serve_inclusion(&w, &ctx, &other);
    let w1 = did_key_witness(W1);
    let (w2, w2_doc) = web_witness();
    let untrusted = did_key_witness([0x53u8; 32]);
    serve_cosignatures(
        &w,
        &ctx,
        vec![cosign(&w1, &cp), cosign(&w2, &cp), cosign(&untrusted, &cp)],
    );

    // Witness policy alone verifies the checkpoint (log policy Ignore).
    let witnesses = WitnessQuorumPolicy::new([w1.witness_id(), WEB_WITNESS])
        .with_document(WEB_WITNESS, w2_doc)
        .with_min_witnesses(2);
    let policy = VerificationPolicy {
        witness_quorum: Some(witnesses.clone()),
        ..VerificationPolicy::default()
    };
    let v = fetch(&w, &ctx, &policy).await;
    assert!(v
        .log_inclusion_verdict()
        .is_some_and(LogInclusionVerdict::is_included));
    let report = v.witness_quorum().unwrap().as_ref().unwrap();
    assert_eq!(report.witnessed_count, 2, "{report:?}");
    assert!(report.meets_quorum && report.meets_fresh_quorum);
    let mut expected = vec![w1.witness_id().to_string(), WEB_WITNESS.to_string()];
    expected.sort();
    assert_eq!(report.witnesses, expected);
    assert!(report.failures.is_empty(), "{:?}", report.failures);

    // Enforced quorum of 3: fails with invalid_witness_cosignature.
    let strict = VerificationPolicy {
        witness_quorum: Some(
            witnesses
                .clone()
                .with_min_witnesses(3)
                .enforce(WitnessEnforcement::RequireQuorum),
        ),
        ..VerificationPolicy::default()
    };
    let err =
        VerifiedContext::fetch_with_policy(&w.client(), &w.resolver(), &ctx.body.ctx_id, &strict)
            .await
            .unwrap_err();
    assert!(
        matches!(err, AcdpError::InvalidWitnessCosignature(ref m) if m.contains("2 of 3")),
        "{err:?}"
    );

    // Report-only, the same shortfall is a verdict, not a failure.
    let report_only = VerificationPolicy {
        witness_quorum: Some(witnesses.with_min_witnesses(3)),
        ..VerificationPolicy::default()
    };
    let v = fetch(&w, &ctx, &report_only).await;
    assert!(!v.witness_quorum().unwrap().as_ref().unwrap().meets_quorum);
}

/// A cosignature over a different checkpoint, or a trusted witness whose
/// DID document cannot be resolved, does not count. The resolution
/// failure is recorded.
#[tokio::test]
async fn witnesses_that_cannot_be_verified_do_not_count() {
    let w = World::start(one_key()).await;
    let other = others(&w).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let cp = serve_inclusion(&w, &ctx, &other);
    let w1 = did_key_witness(W1);
    let (w2, _doc) = web_witness();
    let mut stale = cp.clone();
    stale.tree_size = 2;
    serve_cosignatures(&w, &ctx, vec![cosign(&w1, &stale), cosign(&w2, &cp)]);

    // did:web:witness.example is unreachable under the test resolver.
    let policy = VerificationPolicy {
        witness_quorum: Some(
            WitnessQuorumPolicy::new([w1.witness_id(), WEB_WITNESS])
                .enforce(WitnessEnforcement::RequireFreshQuorum),
        ),
        ..VerificationPolicy::default()
    };
    let err =
        VerifiedContext::fetch_with_policy(&w.client(), &w.resolver(), &ctx.body.ctx_id, &policy)
            .await
            .unwrap_err();
    assert!(
        matches!(err, AcdpError::InvalidWitnessCosignature(ref m) if m.contains("0 of 1") && m.contains(WEB_WITNESS)),
        "{err:?}"
    );
}

/// With no `log_inclusion`, there is no checkpoint to corroborate. That is
/// an error verdict, and fatal only under enforcement.
#[tokio::test]
async fn witness_quorum_without_a_checkpoint() {
    let w = World::start(one_key()).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let witnesses = WitnessQuorumPolicy::new([did_key_witness(W1).witness_id()]);
    let policy = VerificationPolicy {
        witness_quorum: Some(witnesses.clone()),
        ..VerificationPolicy::default()
    };
    let v = fetch(&w, &ctx, &policy).await;
    assert!(matches!(
        v.witness_quorum(),
        Some(Err(AcdpError::InvalidLogProof(_)))
    ));

    let enforced = VerificationPolicy {
        witness_quorum: Some(witnesses.enforce(WitnessEnforcement::RequireQuorum)),
        ..VerificationPolicy::default()
    };
    VerifiedContext::fetch_with_policy(&w.client(), &w.resolver(), &ctx.body.ctx_id, &enforced)
        .await
        .expect_err("no checkpoint to corroborate");
}

/// The report family records both verdicts in their own fields.
#[tokio::test]
async fn report_carries_log_and_witness_verdicts() {
    let w = World::start(one_key()).await;
    let other = others(&w).await;
    let ctx = w.publish("key-1", K1, ContextType::Analysis, None).await;
    let cp = serve_inclusion(&w, &ctx, &other);
    let w1 = did_key_witness(W1);
    serve_cosignatures(&w, &ctx, vec![cosign(&w1, &cp)]);
    let policy = VerificationPolicy {
        log_inclusion: LogInclusionPolicy::VerifyIfPresent,
        witness_quorum: Some(WitnessQuorumPolicy::new([w1.witness_id()])),
        ..VerificationPolicy::default()
    };
    let (_, report) =
        VerifiedContext::fetch_report(&w.client(), &w.resolver(), &ctx.body.ctx_id, &policy)
            .await
            .unwrap();
    assert!(report
        .log_inclusion_verdict
        .as_ref()
        .is_some_and(LogInclusionVerdict::is_included));
    assert!(report.witness_quorum.unwrap().unwrap().meets_quorum);

    let (verified, report) = VerifiedContext::fetch_report_diagnose(
        &w.client(),
        &w.resolver(),
        &ctx.body.ctx_id,
        &policy,
    )
    .await
    .unwrap();
    assert!(verified.is_some());
    assert!(report
        .log_inclusion_verdict
        .as_ref()
        .is_some_and(LogInclusionVerdict::is_included));
}
