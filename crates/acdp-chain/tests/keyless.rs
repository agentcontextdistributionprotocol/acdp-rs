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

/// The registry-signed attestation of the ephemeral key, stored as `k`.
fn attestation() -> Body {
    let key = ephemeral();
    let metadata = KeyAttestation {
        attestation_version: ATTESTATION_VERSION.into(),
        controller: CONTROLLER.into(),
        identity: WorkloadIdentity::Oidc {
            issuer: ISSUER.into(),
            subject: SUBJECT.into(),
        },
        org_wide: false,
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

/// §9.3: a revocation signed by a keyless key that is not org-wide is
/// never applied.
#[cfg(feature = "keyless")]
#[test]
fn kl_009_f_non_org_wide_keyless_revocation_not_applied() {
    let mut e = keyless_bundle(true);
    let att = attestation();
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
    // A node signed by key-1 after the claimed compromise.
    let web = Signer {
        did: CONTROLLER.into(),
        seed: KEY1,
        key_id: format!("{CONTROLLER}#key-1"),
    };
    let b = body(&web, 'b', &[], "2026-09-02T00:00:00.000Z");
    put(&mut e, 'b', evidence(&b, &fingerprint(&KEY1)));
    let v = verify_chain(&[ctx('b')], &reparse(&e), &accepting()).unwrap();
    let n = v.nodes.iter().find(|n| n.ctx_id == ctx('b')).unwrap();
    assert_ne!(
        n.latest.stages.key_revocation.as_ref().unwrap().value,
        KeyRevocationValue::Revoked
    );
}
