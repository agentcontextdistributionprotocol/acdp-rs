//! RFC-ACDP-0021 §10: keyless nodes in chain verification (`kl-008`),
//! over bundles of real signed bodies and receipts. The attestation is
//! an ordinary context in `contexts` (`e`); the keyless body is `a`.

#![cfg_attr(not(feature = "keyless"), allow(unused_imports))]

mod common;

use acdp_chain::*;
use acdp_crypto::SigningKey;
use acdp_producer::keyless::EphemeralKey;
use acdp_producer::Producer;
use acdp_types::body::Body;
use acdp_types::keyless::{
    KeyAttestation, WorkloadIdentity, ATTESTATION_VERSION, KEY_ATTESTATION_SCHEMA_URI,
    KEY_ATTESTATION_TYPE,
};
use acdp_types::lifecycle::LifecycleEventType;
use acdp_types::primitives::{AgentDid, ContextType, CtxId};
use common::*;
use serde_json::json;

const CONTROLLER: &str = "did:web:agents.example.com:ci";
const ISSUER: &str = "https://token.actions.githubusercontent.com";
const SUBJECT: &str = "repo:example/pipeline:ref:refs/heads/main";
const EPHEMERAL_SEED: [u8; 32] = [0x66; 32];
const NOT_BEFORE: &str = "2026-09-01T00:00:00.000Z";
const NOT_AFTER: &str = "2026-09-01T00:10:00.000Z";
const ATTESTED_AT: &str = "2026-09-01T00:00:00.000Z";
const SIGNED_AT: &str = "2026-09-01T00:05:00.000Z";

fn ephemeral() -> EphemeralKey {
    EphemeralKey::from_key(SigningKey::from_bytes(&EPHEMERAL_SEED).into())
}

fn stored(req: &acdp_types::publish::PublishRequest, id: char, created_at: &str) -> Body {
    let ctx_id = CtxId::parse(ctx(id)).unwrap();
    let lineage = acdp_crypto::hash::derive_lineage_id(&ctx_id);
    Body::from_publish_request(req, ctx_id, lineage, REGISTRY, at(created_at))
}

fn evidence(body: &Body, fp: &str) -> ContextEvidence {
    let mut ce = ContextEvidence::new(serde_json::to_value(body).unwrap());
    ce.registry_receipt = Some(receipt_for(body, fp));
    ce
}

/// The registry-signed attestation of the ephemeral key, stored as `e`.
fn attestation() -> Body {
    attestation_with(false)
}

fn attestation_with(org_wide: bool) -> Body {
    let key = ephemeral();
    let metadata = KeyAttestation {
        attestation_version: ATTESTATION_VERSION.into(),
        controller: CONTROLLER.into(),
        identity: WorkloadIdentity::Oidc {
            issuer: ISSUER.into(),
            subject: SUBJECT.into(),
        },
        org_wide,
        key_id: key.key_id(CONTROLLER).unwrap(),
        algorithm: "ed25519".into(),
        public_key_jwk: key.jwk().unwrap(),
        key_fingerprint: key.fingerprint().unwrap(),
        not_before: at(NOT_BEFORE),
        not_after: at(NOT_AFTER),
        token_hash: acdp_types::keyless::token_hash("kl-008"),
    };
    let registry = Producer::new(
        SigningKey::from_bytes(&REGISTRY_SEED),
        AgentDid::new(REGISTRY_DID),
        format!("{REGISTRY_DID}#receipt-key-1"),
    );
    let req = registry
        .publish_request()
        .title("Key attestation")
        .context_type(ContextType::Custom(KEY_ATTESTATION_TYPE.into()))
        .metadata(serde_json::to_value(&metadata).unwrap())
        .schema_uri(KEY_ATTESTATION_SCHEMA_URI)
        .acdp_version("0.5.0")
        .build()
        .unwrap();
    stored(&req, 'e', ATTESTED_AT)
}

fn controller_doc(listed: bool) -> serde_json::Map<String, serde_json::Value> {
    let identities = if listed {
        json!([{"type": "oidc", "issuer": ISSUER, "subject": SUBJECT}])
    } else {
        json!([])
    };
    let mut doc = did_doc(CONTROLLER, &[("key-1", KEY1)], &["key-1"]);
    doc.insert(
        "service".into(),
        json!([{
            "id": format!("{CONTROLLER}#acdp-keyless"),
            "type": "AcdpKeylessSigning",
            "serviceEndpoint": {"identities": identities}
        }]),
    );
    doc
}

/// `a`, signed by the ephemeral key under `k`, receipted inside the
/// window; the controller snapshot lists the identity iff `listed`.
fn keyless_bundle(listed: bool) -> Evidence {
    let att = attestation();
    let producer = ephemeral().into_producer(&att).unwrap();
    let req = producer
        .publish_request()
        .title("Nightly evaluation summary")
        .context_type(ContextType::Analysis)
        .acdp_version("0.5.0")
        .build()
        .unwrap();
    let a = stored(&req, 'a', SIGNED_AT);
    let mut e = bundle();
    put(&mut e, 'e', evidence(&att, &fingerprint(&REGISTRY_SEED)));
    put(
        &mut e,
        'a',
        evidence(&a, &ephemeral().fingerprint().unwrap()),
    );
    add_snapshot(
        &mut e,
        CONTROLLER,
        controller_doc(listed),
        REGISTRY_OBSERVED,
    );
    e
}

fn run(e: &Evidence, o: &Options) -> Node {
    let v = verify_chain(&[ctx('a')], &reparse(e), o).expect("verify_chain");
    v.nodes.into_iter().find(|n| n.ctx_id == ctx('a')).unwrap()
}

#[cfg(feature = "keyless")]
fn accepting() -> Options {
    Options::as_of(t()).with_keyless_attesters([REGISTRY_DID])
}

#[cfg(feature = "keyless")]
fn key(p: &Pass) -> &KeyStage {
    p.stages.key.as_ref().unwrap()
}

/// kl-008 A.
#[cfg(feature = "keyless")]
#[test]
fn kl_008_a_listed_identity_is_current() {
    let n = run(&keyless_bundle(true), &accepting());
    for p in [&n.latest, n.as_of.as_ref().unwrap()] {
        assert_eq!(key(p).value, KeyValue::Current);
        assert_eq!(key(p).basis, Some(Basis::Registry));
        assert_eq!(
            p.stages.signature.as_ref().unwrap().value,
            SignatureValue::Ok
        );
        assert_ne!(p.verdict, Verdict::Refused);
    }
}

/// kl-008 B.
#[cfg(feature = "keyless")]
#[test]
fn kl_008_b_unlisted_identity_is_historical_receipt_attested() {
    let n = run(&keyless_bundle(false), &accepting());
    for p in [&n.latest, n.as_of.as_ref().unwrap()] {
        assert_eq!(key(p).value, KeyValue::HistoricalReceiptAttested);
        assert_eq!(key(p).basis, Some(Basis::Registry));
    }
}

/// kl-008 C.
#[cfg(feature = "keyless")]
#[test]
fn kl_008_c_attestation_absent() {
    let mut e = keyless_bundle(true);
    e.contexts.remove(&ctx('e'));
    let n = run(&e, &accepting());
    assert_eq!(key(&n.latest).value, KeyValue::Unresolvable);
    assert_eq!(
        n.latest.stages.signature.as_ref().unwrap().value,
        SignatureValue::Unresolvable
    );
    let as_of = n.as_of.as_ref().unwrap();
    assert_eq!(key(as_of).value, KeyValue::Unknown);
    assert_eq!(key(as_of).reason.as_deref(), Some("no_evidence_at_as_of"));
}

/// kl-008 D: an admitted registry retraction of the attestation revokes
/// the key from `not_before` (RFC-ACDP-0021 §9.2).
#[cfg(feature = "keyless")]
#[test]
fn kl_008_d_retracted_attestation_revokes() {
    let mut e = keyless_bundle(true);
    let registry = Signer {
        did: REGISTRY_DID.into(),
        seed: REGISTRY_SEED,
        key_id: format!("{REGISTRY_DID}#receipt-key-1"),
    };
    let ev = event(
        &registry,
        'e',
        0,
        LifecycleEventType::Retracted,
        "2026-09-10T00:00:00.000Z",
    );
    let k = e.contexts.get_mut(&ctx('e')).unwrap();
    k.event_receipts = Some(vec![event_receipt('e', &ev, 0, "2026-09-10T00:00:01.000Z")]);
    k.lifecycle_events = Some(vec![ev]);
    let n = run(&e, &accepting());
    for p in [&n.latest, n.as_of.as_ref().unwrap()] {
        let kr = p.stages.key_revocation.as_ref().unwrap();
        assert_eq!(kr.value, KeyRevocationValue::Revoked);
        assert_eq!(kr.revocation_ctx_id.as_deref(), Some(ctx('e').as_str()));
        assert_eq!(key(p).value, KeyValue::Revoked);
        assert_eq!(p.verdict, Verdict::Refused);
    }
    // A retraction accepted after T is not admitted as of T.
    let k = e.contexts.get_mut(&ctx('e')).unwrap();
    let ev = k.lifecycle_events.as_ref().unwrap()[0].clone();
    k.event_receipts = Some(vec![event_receipt('e', &ev, 0, "2026-10-02T00:00:00.000Z")]);
    let n = run(&e, &accepting());
    assert_eq!(key(n.as_of.as_ref().unwrap()).value, KeyValue::Current);
    assert_eq!(key(&n.latest).value, KeyValue::Revoked);
}

/// kl-008 E: without RFC-ACDP-0021 support (or with no accepted
/// attester) the node is refused, never ok.
#[test]
fn kl_008_e_without_keyless_support_refused() {
    let n = run(&keyless_bundle(true), &Options::as_of(t()));
    for p in [&n.latest, n.as_of.as_ref().unwrap()] {
        assert_eq!(p.stages.key.as_ref().unwrap().value, KeyValue::Unresolvable);
        assert_eq!(
            p.stages.signature.as_ref().unwrap().value,
            SignatureValue::Unresolvable
        );
        assert_eq!(p.verdict, Verdict::Refused);
    }
}

/// The keyless bundle with the attestation `e` (`org_wide` as given), a
/// revocation `d` of `key-1` signed by the ephemeral key under it, and a
/// node `b` signed by `key-1` after the claimed compromise.
fn keyless_revocation_bundle(org_wide: bool) -> Evidence {
    let mut e = keyless_bundle(true);
    let att = attestation_with(org_wide);
    put(&mut e, 'e', evidence(&att, &fingerprint(&REGISTRY_SEED)));
    let producer = ephemeral().into_producer(&att).unwrap();
    let req = producer
        .publish_request()
        .title("Key revocation")
        .context_type(ContextType::KeyRevocation)
        .visibility(acdp_types::primitives::Visibility::Public)
        .metadata(json!({
            "revoked_key_fingerprint": fingerprint(&KEY1),
            "compromised_since": "2026-08-15T00:00:00.000Z",
        }))
        .acdp_version("0.5.0")
        .build()
        .unwrap();
    let r = stored(&req, 'd', SIGNED_AT);
    put(
        &mut e,
        'd',
        evidence(&r, &ephemeral().fingerprint().unwrap()),
    );
    let web = Signer {
        did: CONTROLLER.into(),
        seed: KEY1,
        key_id: format!("{CONTROLLER}#key-1"),
    };
    let b = body(&web, 'b', &[], "2026-09-02T00:00:00.000Z");
    put(&mut e, 'b', evidence(&b, &fingerprint(&KEY1)));
    e
}

/// [`keyless_revocation_bundle`] without the revocation `d`.
#[cfg(feature = "keyless")]
fn keyless_bundle_b() -> Evidence {
    let mut e = keyless_revocation_bundle(true);
    e.contexts.remove(&ctx('d'));
    e
}

fn key_revocation_of_b(e: &Evidence, o: &Options) -> KeyRevocationStage {
    let v = verify_chain(&[ctx('b')], &reparse(e), o).unwrap();
    let n = v.nodes.into_iter().find(|n| n.ctx_id == ctx('b')).unwrap();
    n.latest.stages.key_revocation.unwrap()
}

/// §9.3: a revocation signed by a keyless key that is not org-wide is
/// never applied.
#[cfg(feature = "keyless")]
#[test]
fn kl_009_f_non_org_wide_keyless_revocation_not_applied() {
    let kr = key_revocation_of_b(&keyless_revocation_bundle(false), &accepting());
    assert_ne!(kr.value, KeyRevocationValue::Revoked);
}

/// §9.3: a revocation signed by an org-wide keyless key is
/// producer-signed and applies.
#[cfg(feature = "keyless")]
#[test]
fn kl_009_org_wide_keyless_revocation_applies() {
    let kr = key_revocation_of_b(&keyless_revocation_bundle(true), &accepting());
    assert_eq!(kr.value, KeyRevocationValue::Revoked);
    assert_eq!(kr.revocation_ctx_id.as_deref(), Some(ctx('d').as_str()));
}

/// A keyless-signed revocation naming the key that this pass cannot
/// evaluate (no accepted attester, or no RFC-ACDP-0021 support) makes the
/// stage unknown, never not-revoked.
#[test]
fn kl_009_unevaluable_keyless_revocation_is_unknown() {
    let kr = key_revocation_of_b(&keyless_revocation_bundle(true), &Options::default());
    assert_eq!(kr.value, KeyRevocationValue::Unknown);
    assert_eq!(kr.revocation_ctx_id.as_deref(), Some(ctx('d').as_str()));
    // kl-008 F: nothing was established, so no basis or evidence_time.
    assert_eq!(kr.basis, None);
    assert_eq!(kr.evidence_time, None);
}

/// RFC-ACDP-0021 §10 (0.5.0-draft.2): a step-6 failure is
/// `signature: invalid`, with the key stage as located.
#[cfg(feature = "keyless")]
#[test]
fn kl_008_step_6_failure_is_signature_invalid() {
    let mut e = keyless_bundle(true);
    let a = e.contexts.get_mut(&ctx('a')).unwrap();
    // The signature is outside the content hash, so the receipt still
    // binds the body; only the signature fails.
    a.body["signature"]["value"] = json!(SigningKey::from_bytes(&[0x77; 32]).sign_string("x"));
    let n = run(&e, &accepting());
    for p in [&n.latest, n.as_of.as_ref().unwrap()] {
        assert_eq!(key(p).value, KeyValue::Current);
        assert_eq!(key(p).basis, Some(Basis::Registry));
        assert_eq!(
            p.stages.signature.as_ref().unwrap().value,
            SignatureValue::Invalid
        );
        assert_eq!(p.verdict, Verdict::Refused);
    }
}

/// §10: the key stage's `evidence_time` is the body receipt's
/// `created_at`, also for a currently authorized key.
#[cfg(feature = "keyless")]
#[test]
fn kl_008_evidence_time_is_the_body_receipt() {
    let n = run(&keyless_bundle(true), &accepting());
    assert_eq!(key(&n.latest).evidence_time.as_deref(), Some(SIGNED_AT));
}

/// §10 missing evidence: no controller snapshot selectable at T is
/// `unknown` as of T and `unresolvable` in the latest pass.
#[cfg(feature = "keyless")]
#[test]
fn kl_008_no_controller_snapshot() {
    let mut e = keyless_bundle(true);
    e.did_documents.as_mut().unwrap().remove(CONTROLLER);
    let n = run(&e, &accepting());
    assert_eq!(key(&n.latest).value, KeyValue::Unresolvable);
    let as_of = n.as_of.as_ref().unwrap();
    assert_eq!(key(as_of).value, KeyValue::Unknown);
    assert_eq!(key(as_of).reason.as_deref(), Some("no_evidence_at_as_of"));
    assert!(as_of.stages.signature.is_none());
}

/// §6.2, §10 (0.5.0-draft.3): a `key_attestation` beside a DID-document
/// key id breaks the presence rules: `key` and `signature` are
/// `unresolvable`, though the key is in the DID document.
#[cfg(feature = "keyless")]
#[test]
fn kl_008_key_attestation_on_a_did_document_key() {
    let mut e = keyless_bundle(true);
    let att = attestation();
    let web = Signer {
        did: CONTROLLER.into(),
        seed: KEY1,
        key_id: format!("{CONTROLLER}#key-1"),
    };
    let mut b = body(&web, 'b', &[], SIGNED_AT);
    b.extensions.insert(
        "key_attestation".into(),
        json!({"ctx_id": att.ctx_id.as_str(), "content_hash": att.content_hash.as_str()}),
    );
    b.content_hash = acdp_crypto::compute_content_hash(&serde_json::to_value(&b).unwrap()).unwrap();
    b.signature.value = SigningKey::from_bytes(&KEY1).sign_string(b.content_hash.as_str());
    put(&mut e, 'b', evidence(&b, &fingerprint(&KEY1)));
    let v = verify_chain(&[ctx('b')], &reparse(&e), &accepting()).unwrap();
    let n = v.nodes.into_iter().find(|n| n.ctx_id == ctx('b')).unwrap();
    for p in [&n.latest, n.as_of.as_ref().unwrap()] {
        assert_eq!(key(p).value, KeyValue::Unresolvable);
        assert_eq!(
            p.stages.signature.as_ref().unwrap().value,
            SignatureValue::Unresolvable
        );
        assert_eq!(p.verdict, Verdict::Refused);
    }
}

/// §10 attester acceptance: `pinned.keyless_attesters` is the source,
/// covered by `options_digest`; `with_keyless_attesters` builds it.
#[cfg(feature = "keyless")]
#[test]
fn keyless_attesters_are_pinned() {
    let o = accepting();
    let pinned = o.pinned.as_ref().unwrap();
    assert_eq!(pinned.keyless_attesters, vec![REGISTRY_DID.to_string()]);
    let v = verify_chain(&[ctx('a')], &reparse(&keyless_bundle(true)), &o).unwrap();
    assert!(v.options_digest.is_some());
    // Sorted and deduplicated in the normal form; the digest follows it.
    let p = Pinned::from_value(
        &json!({"keyless_attesters": ["did:web:b.example", "did:web:a.example"]}),
    )
    .unwrap();
    assert_eq!(
        p.normalized().keyless_attesters,
        vec![
            "did:web:a.example".to_string(),
            "did:web:b.example".to_string()
        ]
    );
    assert!(Pinned::from_value(&json!({"keyless_attesters": []})).is_err());
    assert!(Pinned::from_value(&json!({"keyless_attesters": ["x", "x"]})).is_err());
    // The superseded side channel is refused, never consulted.
    #[allow(deprecated)]
    {
        let mut o = Options::as_of(t());
        o.keyless_attesters = vec![REGISTRY_DID.into()];
        assert!(verify_chain(&[ctx('a')], &reparse(&keyless_bundle(true)), &o).is_err());
    }
}

/// RFC-ACDP-0017 §6.3: a verifier without RFC-ACDP-0021 support rejects
/// `pinned.keyless_attesters` as an unknown member.
#[cfg(not(feature = "keyless"))]
#[test]
fn keyless_attesters_need_keyless_support() {
    let p = Pinned::from_value(&json!({"keyless_attesters": [REGISTRY_DID]}));
    assert!(p.is_err());
}

/// kl-005 L (chain): a keyless-signed revocation whose signer is
/// definitively invalid is ignored, not `unknown`.
#[cfg(feature = "keyless")]
#[test]
fn kl_005_l_invalid_keyless_signer_is_ignored() {
    // A complete discovery record: an ignored revocation leaves the
    // stage not-revoked; an unevaluable one would make it unknown.
    let complete = |mut e: Evidence| {
        add_discovery(&mut e, CONTROLLER, discovery("2026-09-03T00:00:00.000Z"));
        e
    };
    let kr = key_revocation_of_b(&complete(keyless_bundle_b()), &accepting());
    assert_eq!(kr.value, KeyRevocationValue::NotRevoked);

    // Step 6: the revocation's signature does not verify.
    let mut e = complete(keyless_revocation_bundle(true));
    e.contexts.get_mut(&ctx('d')).unwrap().body["signature"]["value"] =
        json!(SigningKey::from_bytes(&[0x77; 32]).sign_string("x"));
    let kr = key_revocation_of_b(&e, &accepting());
    assert_eq!(kr.value, KeyRevocationValue::NotRevoked);

    // Step 7: the signer's attestation is withdrawn.
    let mut e = complete(keyless_revocation_bundle(true));
    let registry = Signer {
        did: REGISTRY_DID.into(),
        seed: REGISTRY_SEED,
        key_id: format!("{REGISTRY_DID}#receipt-key-1"),
    };
    let ev = event(
        &registry,
        'e',
        0,
        LifecycleEventType::Retracted,
        "2026-09-10T00:00:00.000Z",
    );
    let k = e.contexts.get_mut(&ctx('e')).unwrap();
    k.event_receipts = Some(vec![event_receipt('e', &ev, 0, "2026-09-10T00:00:01.000Z")]);
    k.lifecycle_events = Some(vec![ev]);
    let kr = key_revocation_of_b(&e, &accepting());
    assert_eq!(kr.value, KeyRevocationValue::NotRevoked);
}

/// kl-005 K (chain): an attestation not in evidence leaves the signer
/// unevaluable, so the stage is `unknown`.
#[cfg(feature = "keyless")]
#[test]
fn kl_005_k_attestation_unavailable_is_unknown() {
    let mut e = keyless_revocation_bundle(true);
    e.contexts.remove(&ctx('e'));
    let kr = key_revocation_of_b(&e, &accepting());
    assert_eq!(kr.value, KeyRevocationValue::Unknown);
    assert_eq!(kr.revocation_ctx_id.as_deref(), Some(ctx('d').as_str()));
}

/// §9.3 (0.5.0-draft.3): evidence that cannot be obtained is unavailable,
/// not invalid: an attestation without its receipt, or another context
/// supplied under the named `ctx_id`, leaves the revocation `unknown`.
#[cfg(feature = "keyless")]
#[test]
fn kl_005_k_unobtainable_evidence_is_unknown() {
    let mut e = keyless_revocation_bundle(true);
    e.contexts.get_mut(&ctx('e')).unwrap().registry_receipt = None;
    let kr = key_revocation_of_b(&e, &accepting());
    assert_eq!(kr.value, KeyRevocationValue::Unknown);
    assert_eq!(kr.revocation_ctx_id.as_deref(), Some(ctx('d').as_str()));
    assert_eq!(kr.basis, None);

    let mut e = keyless_revocation_bundle(true);
    let other = e.contexts[&ctx('a')].clone();
    e.contexts.insert(ctx('e'), other);
    let kr = key_revocation_of_b(&e, &accepting());
    assert_eq!(kr.value, KeyRevocationValue::Unknown);
}

/// §9.2 (0.5.0-draft.3): a registry-actor `retracted` event admitted on
/// the attester's RFC-ACDP-0013 §10.3 event receipt counts, unsigned.
#[cfg(feature = "keyless")]
#[test]
fn kl_008_d_receipted_registry_event_withdraws() {
    let mut e = keyless_bundle(true);
    let registry = Signer {
        did: REGISTRY_DID.into(),
        seed: REGISTRY_SEED,
        key_id: format!("{REGISTRY_DID}#receipt-key-1"),
    };
    let mut ev = event(
        &registry,
        'e',
        0,
        LifecycleEventType::Retracted,
        "2026-09-10T00:00:00.000Z",
    );
    ev.as_object_mut().unwrap().remove("signature");
    let k = e.contexts.get_mut(&ctx('e')).unwrap();
    k.event_receipts = Some(vec![event_receipt('e', &ev, 0, "2026-09-10T00:00:01.000Z")]);
    k.lifecycle_events = Some(vec![ev]);
    let n = run(&e, &accepting());
    for p in [&n.latest, n.as_of.as_ref().unwrap()] {
        let kr = p.stages.key_revocation.as_ref().unwrap();
        assert_eq!(kr.value, KeyRevocationValue::Revoked);
        assert_eq!(key(p).value, KeyValue::Revoked);
    }
}

/// RFC-ACDP-0021 §6.3, §10: a lifecycle event signed with a keyless key
/// is not admitted, so it never retracts the body.
#[cfg(feature = "keyless")]
#[test]
fn keyless_signed_event_is_not_admitted() {
    use acdp_types::lifecycle::LifecycleEvent;
    let mut e = keyless_bundle(true);
    let key_id = ephemeral().key_id(CONTROLLER).unwrap();
    let ev = LifecycleEvent::new(
        "00000000-0000-4000-8000-000000000097",
        CtxId::parse(ctx('a')).unwrap(),
        LifecycleEventType::Retracted,
        at("2026-09-10T00:00:00.000Z"),
        AgentDid::new(CONTROLLER),
        None,
    )
    .unwrap();
    // `sign_with` refuses a keyless key id; sign by hand as a rogue
    // producer would.
    assert!(ev
        .clone()
        .sign_with(SigningKey::from_bytes(&EPHEMERAL_SEED), &key_id)
        .is_err());
    let hash = ev.preimage_hash().unwrap();
    let mut raw = serde_json::to_value(&ev).unwrap();
    raw["signature"] = json!({
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": SigningKey::from_bytes(&EPHEMERAL_SEED).sign_string(hash.as_str()),
    });
    let a = e.contexts.get_mut(&ctx('a')).unwrap();
    a.event_receipts = Some(vec![event_receipt(
        'a',
        &raw,
        0,
        "2026-09-10T00:00:01.000Z",
    )]);
    a.lifecycle_events = Some(vec![raw]);
    let n = run(&e, &accepting());
    for p in [&n.latest, n.as_of.as_ref().unwrap()] {
        assert_ne!(
            p.stages.retraction.as_ref().map(|r| r.value),
            Some(RetractionValue::Retracted)
        );
    }
}

/// The bundle with the attester's DID document rotated to
/// `receipt-key-2`, keeping `receipt-key-1` in `verificationMethod`
/// (`retain`) or removing it entirely.
#[cfg(feature = "keyless")]
fn rotated_bundle(retain: bool) -> Evidence {
    let mut e = keyless_bundle(true);
    let mut methods = vec![("receipt-key-2", [0x12; 32])];
    if retain {
        methods.push(("receipt-key-1", REGISTRY_SEED));
    }
    let doc = did_doc(REGISTRY_DID, &methods, &["receipt-key-2"]);
    e.did_documents.as_mut().unwrap().insert(
        REGISTRY_DID.into(),
        vec![DidSnapshot::new(doc, REGISTRY_OBSERVED)],
    );
    e
}

/// kl-005 M (0.5.0-draft.4): the attestation's signing key left
/// `assertionMethod` but stayed in `verificationMethod`. Step 1 passes by
/// the RFC-ACDP-0010 §10 historical arm through its receipt, and the
/// node's key stage is unchanged.
#[cfg(feature = "keyless")]
#[test]
fn kl_005_m_attester_key_rotated() {
    let n = run(&rotated_bundle(true), &accepting());
    for p in [&n.latest, n.as_of.as_ref().unwrap()] {
        assert_eq!(key(p).value, KeyValue::Current);
        assert_eq!(
            p.stages.signature.as_ref().unwrap().value,
            SignatureValue::Ok
        );
    }
}

/// kl-005 N: the key is gone from `verificationMethod` (compromise), so
/// the attestation fails step 1 and the node is refused.
#[cfg(feature = "keyless")]
#[test]
fn kl_005_n_attester_key_removed() {
    let n = run(&rotated_bundle(false), &accepting());
    for p in [&n.latest, n.as_of.as_ref().unwrap()] {
        assert_eq!(key(p).value, KeyValue::Unresolvable);
        assert_eq!(p.verdict, Verdict::Refused);
    }
}
