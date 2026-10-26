//! RFC-ACDP-0020 trust lists carried in an RFC-ACDP-0017 bundle:
//! trust-007 (carriage and the report bound to the verdict), plus the
//! bundle-dependent trust-005 G (a did:web issuer's DID document as of
//! T) and trust-006 F (an unpinned issuer's list confers nothing).

mod common;

use acdp_chain::*;
use acdp_crypto::SigningKey;
use acdp_producer::Producer;
use acdp_types::body::Body;
use acdp_types::primitives::{AgentDid, ContextType, CtxId, Visibility};
use acdp_types::trust_list::{
    IssuerPin, ListStatus, TrustOutcome, TrustPass, TrustReason, TRUST_LIST_SCHEMA_URI,
    TRUST_LIST_TYPE,
};
use common::*;
use serde_json::{json, Value};

const ISSUER: &str = "did:key:z6MkghLt1e8m1fmANsdJJco3aCLV8Xnigr5UWwC3u5iZFPd3";
const ISSUER_SEED: [u8; 32] = [0x42; 32];
const LIST_ID: &str = "tenant-acme.production";
const GOLDEN_HASH: &str = "sha256:206fe1d0f0c3610e9a7d55638b7baa1883b625c71373b92747f25e07f3678bf3";
const NOW: &str = "2026-10-27T00:00:00.000Z";
const LIST_RECEIPT: &str = "2026-10-26T00:00:01.000Z";

/// `examples/trust-list/golden-trust-list.json`, with `serial`.
fn golden_metadata(serial: u64) -> Value {
    json!({
        "trust_list_version": "acdp-trust-list/1",
        "list_id": LIST_ID,
        "serial": serial,
        "issued_at": "2026-10-26T00:00:00.000Z",
        "valid_from": "2026-10-01T00:00:00.000Z",
        "valid_until": "2027-04-01T00:00:00.000Z",
        "entries": [
            {
                "registry_did": "did:web:registry.example.com",
                "origin": "registry.example.com",
                "receipt_key_fingerprints": [fingerprint(&REGISTRY_SEED)],
                "required_profiles": ["acdp-registry-receipts", "acdp-registry-lifecycle"]
            },
            {
                "registry_did": "did:web:partner.example.org",
                "origin": "partner.example.org",
                "scope": {
                    "agent_id_prefixes": ["did:web:agents.partner.example.org:"],
                    "types": ["analysis", "data_snapshot"]
                },
                "valid_until": "2026-12-01T00:00:00.000Z"
            },
            {
                "registry_did": "did:web:sandbox.example.net",
                "origin": "sandbox.example.net",
                "scope": { "did_methods": ["did:key"] },
                "valid_from": "2026-11-01T00:00:00.000Z"
            },
            {
                "registry_did": "did:web:partner.example.org",
                "origin": "partner.example.org",
                "scope": { "agent_ids": ["did:web:auditor.example.com"] }
            }
        ]
    })
}

/// A trust list by `producer`, stored under `ctx(id)` and receipted at
/// `created_at`.
fn list_evidence(
    producer: &Producer,
    fp: &str,
    id: char,
    metadata: Value,
    created_at: &str,
) -> (Body, ContextEvidence) {
    let serial = metadata["serial"].clone();
    let req = producer
        .publish_request()
        .title("Trust list — tenant acme, production")
        .summary(format!(
            "Registries tenant acme relies on in production (RFC-ACDP-0020), serial {serial}."
        ))
        .context_type(ContextType::Custom(TRUST_LIST_TYPE.into()))
        .visibility(Visibility::Public)
        .schema_uri(TRUST_LIST_SCHEMA_URI)
        .metadata(metadata)
        .acdp_version("0.5.0")
        .build()
        .unwrap();
    let ctx_id = CtxId::parse(ctx(id)).unwrap();
    let lineage = acdp_crypto::hash::derive_lineage_id(&ctx_id);
    let body = Body::from_publish_request(&req, ctx_id, lineage, REGISTRY, at(created_at));
    let mut ce = ContextEvidence::new(serde_json::to_value(&body).unwrap());
    ce.registry_receipt = Some(receipt_for(&body, fp));
    (body, ce)
}

fn golden_list() -> (Body, ContextEvidence) {
    let p = Producer::new_did_key(SigningKey::from_bytes(&ISSUER_SEED));
    let (body, ce) = list_evidence(
        &p,
        &fingerprint(&ISSUER_SEED),
        'f',
        golden_metadata(7),
        LIST_RECEIPT,
    );
    assert_eq!(body.agent_id.as_str(), ISSUER);
    (body, ce)
}

fn with_golden_list() -> Evidence {
    let mut e = chain_001_bundle();
    put(&mut e, 'f', golden_list().1);
    e
}

fn trust_options() -> TrustOptions {
    TrustOptions::new(vec![IssuerPin::new(ISSUER, LIST_ID)], at(NOW))
}

fn roots() -> Vec<String> {
    vec![ctx('a')]
}

fn run(e: &Evidence, o: &Options) -> (ChainVerdict, ChainTrust) {
    verify_chain_with_trust(&roots(), &reparse(e), o, &trust_options()).expect("verify_chain")
}

fn without(v: &ChainVerdict, keys: &[&str]) -> Value {
    let mut v = serde_json::to_value(v).unwrap();
    for k in keys {
        v.as_object_mut().unwrap().remove(*k);
    }
    v
}

#[test]
fn trust_007_bundle_and_report() {
    let (golden, _) = golden_list();
    // The golden body: trust-001's content_hash.
    assert_eq!(golden.content_hash.as_str(), GOLDEN_HASH);

    // A — the verdict stages are unchanged; only evidence_digest,
    // horizon and verdict_digest move.
    let opts = Options::as_of(t());
    let before = verify_chain(&roots(), &reparse(&chain_001_bundle()), &opts).unwrap();
    let (after, trust) = run(&with_golden_list(), &opts);
    let moved = ["evidence_digest", "horizon", "verdict_digest"];
    assert_eq!(without(&before, &moved), without(&after, &moved));
    assert_eq!(before.horizon.as_deref(), Some("2026-09-30T00:00:00.000Z"));
    assert_eq!(after.horizon.as_deref(), Some(LIST_RECEIPT));
    assert_eq!(before.as_of_digest, after.as_of_digest);
    assert_ne!(before.evidence_digest, after.evidence_digest);

    // G — the trust step changes no chain-verdict member.
    let plain = verify_chain(&roots(), &reparse(&with_golden_list()), &opts).unwrap();
    assert_eq!(plain, after);

    // B — offline: every node is trusted through entry 0 (pinned receipt key).
    let latest = &trust.latest;
    assert_eq!(latest.lists.len(), 1);
    let l = &latest.lists[0];
    assert_eq!(
        (
            l.status,
            l.serial,
            l.content_hash.as_deref(),
            l.ctx_id.as_deref()
        ),
        (
            ListStatus::Used,
            Some(7),
            Some(GOLDEN_HASH),
            Some(ctx('f').as_str())
        )
    );
    let ids: Vec<&str> = latest.nodes.iter().map(|n| n.ctx_id.as_str()).collect();
    assert_eq!(ids, [ctx('a'), ctx('b'), ctx('c')]);
    for n in &latest.nodes {
        assert_eq!(
            (n.outcome, n.entry_index),
            (TrustOutcome::Trusted, Some(0)),
            "{}",
            n.ctx_id
        );
        assert_eq!(n.issuer.as_deref(), Some(ISSUER));
        assert!(!n.profiles_checked);
    }
    assert!(latest.all_trusted());
    assert_eq!(trust.floors[&(ISSUER.to_string(), LIST_ID.to_string())], 7);

    // D — determinism: the digest is over the JCS without report_digest,
    // and a second run emits the same bytes.
    assert_eq!(latest.compute_digest(), latest.report_digest);
    assert_eq!(
        run(&with_golden_list(), &opts).1.latest.to_jcs(),
        latest.to_jcs()
    );

    // E — binding.
    assert_eq!(
        latest.verdict_digest.as_deref(),
        Some(after.verdict_digest.as_str())
    );
    assert_eq!(
        latest.evidence_digest.as_deref(),
        Some(after.evidence_digest.as_str())
    );

    // F — two passes, each with its own evaluated_at. As of 2026-10-01
    // the list (issued 2026-10-26) does not exist yet.
    let as_of = trust.as_of.as_ref().unwrap();
    assert_eq!(
        (latest.pass, latest.evaluated_at.as_str()),
        (TrustPass::Latest, NOW)
    );
    assert_eq!(
        (as_of.pass, as_of.evaluated_at.as_str()),
        (TrustPass::AsOf, T)
    );
    assert_eq!(
        (
            as_of.lists[0].status,
            as_of.lists[0].reason,
            as_of.lists[0].serial
        ),
        (ListStatus::Invalid, Some(TrustReason::NoValidVersion), None)
    );
    for n in &as_of.nodes {
        assert_eq!(n.outcome, TrustOutcome::ListInvalid);
        assert_eq!((n.issuer.as_ref(), n.entry_index), (None, None));
    }
    let (_, latest_only) = run(&with_golden_list(), &Options::default());
    assert!(latest_only.as_of.is_none());
}

#[test]
fn trust_007_c_receipt_gating() {
    let mut e = with_golden_list();
    e.contexts.get_mut(&ctx('c')).unwrap().registry_receipt = None;
    let (v, trust) = run(&e, &Options::default());
    let c = v.nodes.iter().find(|n| n.ctx_id == ctx('c')).unwrap();
    assert_ne!(
        c.latest.stages.registry_receipt.as_ref().map(|r| r.value),
        Some(ReceiptValue::Ok)
    );
    let n = trust
        .latest
        .nodes
        .iter()
        .find(|n| n.ctx_id == ctx('c'))
        .unwrap();
    assert_eq!(
        (n.outcome, n.reason, n.entry_index),
        (
            TrustOutcome::UntrustedRegistry,
            Some(TrustReason::ReceiptRequired),
            Some(0)
        )
    );
    // A, still receipted, stays trusted: one untrusted node taints nothing.
    let a = trust
        .latest
        .nodes
        .iter()
        .find(|n| n.ctx_id == ctx('a'))
        .unwrap();
    assert_eq!(a.outcome, TrustOutcome::Trusted);
}

#[test]
fn trust_007_floor_and_issuer_retraction() {
    // A persisted floor above the bundle's serial: rollback.
    let opts = trust_options().with_floors([((ISSUER.to_string(), LIST_ID.to_string()), 8)].into());
    let (_, trust) = verify_chain_with_trust(
        &roots(),
        &reparse(&with_golden_list()),
        &Options::default(),
        &opts,
    )
    .unwrap();
    assert_eq!(trust.latest.lists[0].reason, Some(TrustReason::Rollback));
    assert_eq!(trust.floors[&(ISSUER.to_string(), LIST_ID.to_string())], 8);

    // An admitted, issuer-signed retraction withdraws the list; a
    // registry-actor one would not (only producer-actor events count).
    let issuer = Signer {
        did: ISSUER.into(),
        seed: ISSUER_SEED,
        key_id: golden_list().0.signature.key_id,
    };
    let mut e = with_golden_list();
    let ev = event(
        &issuer,
        'f',
        1,
        acdp_types::lifecycle::LifecycleEventType::Retracted,
        "2026-10-26T12:00:00.000Z",
    );
    let rc = event_receipt('f', &ev, 0, "2026-10-26T12:00:01.000Z");
    let ce = e.contexts.get_mut(&ctx('f')).unwrap();
    ce.lifecycle_events = Some(vec![ev]);
    ce.event_receipts = Some(vec![rc]);
    let (_, trust) = run(&e, &Options::default());
    assert_eq!(
        (trust.latest.lists[0].status, trust.latest.lists[0].reason),
        (ListStatus::Invalid, Some(TrustReason::Retracted))
    );
}

#[test]
fn trust_006_f_unpinned_issuer_list_is_ignored() {
    // Another did:key publishes a higher serial of the same list_id.
    let other = Producer::new_did_key(SigningKey::from_bytes(&[0x43; 32]));
    let (b, ce) = list_evidence(
        &other,
        &fingerprint(&[0x43; 32]),
        'e',
        golden_metadata(99),
        LIST_RECEIPT,
    );
    assert_ne!(b.agent_id.as_str(), ISSUER);
    let mut e = with_golden_list();
    put(&mut e, 'e', ce);
    let (_, trust) = run(&e, &Options::default());
    assert_eq!(trust.latest.lists[0].serial, Some(7));
    assert_eq!(trust.latest.lists.len(), 1);
}

#[test]
fn trust_005_g_did_web_issuer_as_of_t() {
    // Serial 6 is signed with key-1; the issuer drops key-1 on 2026-10-20.
    let k1 = Signer::web(KEY1, "key-1");
    let producer = Producer::new(
        SigningKey::from_bytes(&KEY1),
        AgentDid::new(WEB_PRODUCER),
        &k1.key_id,
    );
    let mut m = golden_metadata(6);
    m["issued_at"] = json!("2026-09-01T00:00:00.000Z");
    m["valid_from"] = json!("2026-09-01T00:00:00.000Z");
    let (_, ce) = list_evidence(
        &producer,
        &k1.fingerprint(),
        'd',
        m,
        "2026-09-01T00:00:01.000Z",
    );
    let mut e = chain_001_bundle();
    put(&mut e, 'd', ce);
    add_snapshot(
        &mut e,
        WEB_PRODUCER,
        did_doc(WEB_PRODUCER, &[("key-1", KEY1)], &["key-1"]),
        "2026-09-15T00:00:00.000Z",
    );
    add_snapshot(
        &mut e,
        WEB_PRODUCER,
        did_doc(WEB_PRODUCER, &[("key-2", KEY2)], &["key-2"]),
        "2026-10-20T00:00:00.000Z",
    );

    let trust = TrustOptions::new(vec![IssuerPin::new(WEB_PRODUCER, LIST_ID)], at(NOW));
    let (_, report) = verify_chain_with_trust(
        &roots(),
        &reparse(&e),
        &Options::as_of(at("2026-10-10T00:00:00.000Z")),
        &trust,
    )
    .unwrap();
    let as_of = report.as_of.unwrap();
    assert_eq!(
        (as_of.lists[0].status, as_of.lists[0].serial),
        (ListStatus::Used, Some(6))
    );
    assert!(as_of.all_trusted());
}

#[test]
fn unknown_issuer_revocation_passes_unless_local_policy_refuses() {
    // The bundle has no discovery for the list issuer: its key_revocation
    // stage is `unknown`. §5.2 step 5 (spec 25f8d3a) refuses only on an
    // applied revocation, so the list is used.
    let e = reparse(&with_golden_list());
    let (_, trust) =
        verify_chain_with_trust(&roots(), &e, &Options::default(), &trust_options()).unwrap();
    assert_eq!(trust.latest.lists[0].status, ListStatus::Used);

    // Local policy may refuse it; the verdict stays the same.
    let strict = TrustPolicy::default().refuse_unknown_issuer_revocation(true);
    let (v, trust) =
        verify_chain_with_trust_policy(&roots(), &e, &Options::default(), &trust_options(), strict)
            .unwrap();
    assert_eq!(
        (trust.latest.lists[0].status, trust.latest.lists[0].reason),
        (ListStatus::Invalid, Some(TrustReason::NoValidVersion))
    );
    assert_eq!(v, verify_chain(&roots(), &e, &Options::default()).unwrap());

    // With a complete discovery for the issuer, strict policy uses it.
    let mut e = with_golden_list();
    add_discovery(&mut e, ISSUER, discovery("2026-10-26T06:00:00.000Z"));
    let (_, trust) = verify_chain_with_trust_policy(
        &roots(),
        &reparse(&e),
        &Options::default(),
        &trust_options(),
        strict,
    )
    .unwrap();
    assert_eq!(trust.latest.lists[0].status, ListStatus::Used);
}

/// trust-002 K: §5.2 step 5 across every RFC-ACDP-0014 §7 class of the
/// issuer key, each produced by real evidence. A did:web issuer signs
/// serial 7 with key-1 (receipted 2026-10-26T00:00:01) and, where a
/// revocation applies, revokes key-1 with key-2.
#[test]
fn trust_002_k_issuer_key_revocation_classes() {
    const LIST_AT: &str = "2026-10-26T00:00:01.000Z";
    let k1 = Signer::web(KEY1, "key-1");
    let k2 = Signer::web(KEY2, "key-2");
    let bundle_for = |compromised_since: Option<&str>, receipted: bool, discovered: bool| {
        let producer = k1.producer();
        let (_, mut ce) = list_evidence(
            &producer,
            &k1.fingerprint(),
            'd',
            golden_metadata(7),
            LIST_AT,
        );
        if !receipted {
            ce.registry_receipt = None;
        }
        let mut e = bundle();
        put(&mut e, 'd', ce);
        add_snapshot(
            &mut e,
            WEB_PRODUCER,
            did_doc(
                WEB_PRODUCER,
                &[("key-1", KEY1), ("key-2", KEY2)],
                &["key-1", "key-2"],
            ),
            REGISTRY_OBSERVED,
        );
        if let Some(since) = compromised_since {
            put(
                &mut e,
                'e',
                revocation(&k2, 'e', &KEY1, since, "2026-10-26T06:00:00.000Z"),
            );
        }
        if discovered {
            add_discovery(&mut e, WEB_PRODUCER, discovery("2026-10-26T12:00:00.000Z"));
        }
        reparse(&e)
    };
    let pin = IssuerPin::new(WEB_PRODUCER, LIST_ID);
    let check = |e: &Evidence, policy: TrustPolicy| {
        let roots = [ctx('d')];
        let trust = TrustOptions::new(vec![pin.clone()], at(NOW));
        let (v, t) =
            verify_chain_with_trust_policy(&roots, e, &Options::default(), &trust, policy).unwrap();
        let class = v.nodes[0]
            .latest
            .stages
            .key_revocation
            .as_ref()
            .unwrap()
            .value;
        let l = &t.latest.lists[0];
        (class, l.status, l.reason)
    };
    let strict = TrustPolicy::default().refuse_unknown_issuer_revocation(true);
    let used = (ListStatus::Used, None);
    let invalid = (ListStatus::Invalid, Some(TrustReason::NoValidVersion));
    let cases = [
        (
            "not-revoked",
            bundle_for(None, true, true),
            KeyRevocationValue::NotRevoked,
            used,
            used,
        ),
        (
            "pre-compromise",
            bundle_for(Some("2026-10-26T03:00:00.000Z"), true, true),
            KeyRevocationValue::PreCompromise,
            used,
            used,
        ),
        (
            "unknown",
            bundle_for(None, true, false),
            KeyRevocationValue::Unknown,
            used,
            invalid,
        ),
        (
            "revoked",
            bundle_for(Some("2026-10-01T00:00:00.000Z"), true, true),
            KeyRevocationValue::Revoked,
            invalid,
            invalid,
        ),
        (
            "unplaceable",
            bundle_for(Some("2026-10-01T00:00:00.000Z"), false, true),
            KeyRevocationValue::Unplaceable,
            invalid,
            invalid,
        ),
    ];
    for (name, e, class, default, under_strict) in cases {
        let (c, s, r) = check(&e, TrustPolicy::default());
        assert_eq!(c, class, "{name}: class");
        assert_eq!((s, r), default, "{name}: default policy");
        let (_, s, r) = check(&e, strict);
        assert_eq!((s, r), under_strict, "{name}: refuse-unknown policy");
    }
}
