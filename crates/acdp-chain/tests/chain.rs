//! RFC-ACDP-0017 behavioral tests, one or more per chain-001..010
//! fixture, over bundles of real signed bodies and receipts
//! (`common/mod.rs`). Every verdict is also checked against
//! `acdp-chain-verdict.schema.json` when the spec checkout is found.

mod common;

use acdp_chain::*;
use acdp_types::lifecycle::LifecycleEventType;
use common::schema::Schemas;
use common::*;
use serde_json::{json, Value};

fn run(roots: &[char], e: &Evidence, o: &Options) -> ChainVerdict {
    let roots: Vec<String> = roots.iter().map(|c| ctx(*c)).collect();
    let v = verify_chain(&roots, &reparse(e), o).expect("verify_chain");
    check_invariants(&v);
    v
}

/// §9 invariants every verdict must satisfy.
fn check_invariants(v: &ChainVerdict) {
    if let Some(s) = Schemas::load() {
        s.validate_verdict(&v.to_value())
            .unwrap_or_else(|e| panic!("verdict fails the schema: {e}"));
    }
    assert_eq!(v.verdict_digest, verdict_digest(v));
    let mut sorted = v.nodes.iter().map(|n| n.ctx_id.clone()).collect::<Vec<_>>();
    sorted.sort();
    assert_eq!(
        sorted,
        v.nodes.iter().map(|n| n.ctx_id.clone()).collect::<Vec<_>>()
    );
    if v.as_of.is_none() {
        assert!(v.nodes.iter().all(|n| n.as_of.is_none()));
        assert!(v.chain.as_of.is_none() && v.tainted_paths.as_of.is_none());
        assert!(v.as_of_digest.is_none() && v.drift.is_empty());
    }
    // Determinism: a second run over the same bytes is byte-identical.
    for n in &v.nodes {
        let mut c = n.latest.caveats.clone();
        c.sort();
        assert_eq!(c, n.latest.caveats);
    }
}

fn node(v: &ChainVerdict, id: char) -> &Node {
    v.nodes
        .iter()
        .find(|n| n.ctx_id == ctx(id))
        .unwrap_or_else(|| panic!("no node {id}"))
}

fn as_of(n: &Node) -> &Pass {
    n.as_of.as_ref().expect("as-of pass")
}

fn drift(v: &ChainVerdict) -> Vec<(String, DriftKind)> {
    v.drift.iter().map(|d| (d.ctx_id.clone(), d.kind)).collect()
}

fn paths(p: &[&[char]]) -> Vec<Vec<String>> {
    p.iter()
        .map(|p| p.iter().map(|c| ctx(*c)).collect())
        .collect()
}

// ── chain-001 ────────────────────────────────────────────────────────────────

pub fn chain_001_bundle() -> Evidence {
    let p = Signer::did_key();
    let mut e = bundle();
    put(
        &mut e,
        'a',
        receipted(&p, 'a', &['b', 'c'], "2026-09-03T00:00:00.000Z"),
    );
    put(
        &mut e,
        'b',
        receipted(&p, 'b', &['c'], "2026-09-02T00:00:00.000Z"),
    );
    put(
        &mut e,
        'c',
        receipted(&p, 'c', &[], "2026-09-01T00:00:00.000Z"),
    );
    add_discovery(&mut e, KEY_PRODUCER, discovery("2026-09-30T00:00:00.000Z"));
    e
}

#[test]
fn chain_001_a_clean_dag_did_key_both_passes() {
    let v = run(&['a'], &chain_001_bundle(), &Options::as_of(t()));
    assert!(v.complete);
    assert_eq!(v.control, None);
    assert!(v.frontier.is_empty());
    assert_eq!(v.options_digest, None);
    assert_eq!(node(&v, 'a').depth, 0);
    assert_eq!(node(&v, 'b').depth, 1);
    assert_eq!(node(&v, 'c').depth, 1, "C is a DAG join, admitted once");
    for id in ['a', 'b', 'c'] {
        let n = node(&v, id);
        for p in [as_of(n), &n.latest] {
            let s = &p.stages;
            assert_eq!(s.presence.value, PresenceValue::Present);
            assert_eq!(s.identity.as_ref().unwrap().value, IdentityValue::Ok);
            assert_eq!(s.content_hash.as_ref().unwrap().value, ContentHashValue::Ok);
            assert_eq!(s.signature.as_ref().unwrap().value, SignatureValue::Ok);
            let r = s.registry_receipt.as_ref().unwrap();
            assert_eq!(
                (r.value, r.key_status),
                (ReceiptValue::Ok, Some(KeyStatus::Current))
            );
            let k = s.key.as_ref().unwrap();
            assert_eq!(
                (k.value, k.basis),
                (KeyValue::Current, Some(Basis::SelfEvident))
            );
            assert_eq!(
                s.retraction.as_ref().unwrap().value,
                RetractionValue::NotRetracted
            );
            let kr = s.key_revocation.as_ref().unwrap();
            assert_eq!(
                (kr.value, kr.basis),
                (KeyRevocationValue::NotRevoked, Some(Basis::Observed))
            );
            assert_eq!(p.verdict, Verdict::OkWithCaveats);
            assert_eq!(p.caveats, vec![Caveat::ObservedBasis]);
        }
    }
    assert_eq!(v.chain.as_of, Some(Verdict::OkWithCaveats));
    assert_eq!(v.chain.latest, Verdict::OkWithCaveats);
    assert!(v.drift.is_empty());
    assert_eq!(v.horizon.as_deref(), Some("2026-09-30T00:00:00.000Z"));
}

#[test]
fn chain_001_b_pinned_vantage_is_ok() {
    let mut pinned = Pinned::default();
    pinned.vantages = vec![REGISTRY.into()];
    let v = run(
        &['a'],
        &chain_001_bundle(),
        &Options::as_of(t()).with_pinned(pinned),
    );
    assert!(v.options_digest.is_some());
    for n in &v.nodes {
        assert_eq!(as_of(n).verdict, Verdict::Ok, "{}", n.ctx_id);
        assert_eq!(n.latest.verdict, Verdict::Ok);
        assert_eq!(
            n.latest.stages.key_revocation.as_ref().unwrap().basis,
            Some(Basis::Pinned)
        );
    }
    assert_eq!(v.chain.as_of, Some(Verdict::Ok));
    assert_eq!(v.chain.latest, Verdict::Ok);
}

#[test]
fn chain_001_c_no_as_of() {
    let v = run(&['a'], &chain_001_bundle(), &Options::default());
    assert_eq!(v.as_of, None);
    assert_eq!(v.as_of_digest, None);
    assert!(v.drift.is_empty());
}

// ── chain-002 ────────────────────────────────────────────────────────────────

pub fn chain_002_bundle(compromised_since: &str, with_discovery: bool) -> Evidence {
    let k1 = Signer::web(KEY1, "key-1");
    let k2 = Signer::web(KEY2, "key-2");
    let mut e = bundle();
    put(
        &mut e,
        'a',
        receipted(&k1, 'a', &['b'], "2026-09-20T00:00:00.000Z"),
    );
    put(
        &mut e,
        'b',
        receipted(&k1, 'b', &[], "2026-09-10T00:00:00.000Z"),
    );
    put(
        &mut e,
        'e',
        revocation(
            &k2,
            'e',
            &KEY1,
            compromised_since,
            "2026-10-05T00:00:00.000Z",
        ),
    );
    add_snapshot(
        &mut e,
        WEB_PRODUCER,
        did_doc(
            WEB_PRODUCER,
            &[("key-1", KEY1), ("key-2", KEY2)],
            &["key-1", "key-2"],
        ),
        "2026-09-30T00:00:00.000Z",
    );
    if with_discovery {
        add_discovery(&mut e, WEB_PRODUCER, discovery("2026-09-30T00:00:00.000Z"));
    }
    e
}

#[test]
fn chain_002_a_revocation_after_as_of() {
    let v = run(
        &['a'],
        &chain_002_bundle("2026-09-01T00:00:00.000Z", true),
        &Options::as_of(t()),
    );
    let a = node(&v, 'a');
    let kr = as_of(a).stages.key_revocation.as_ref().unwrap();
    assert_eq!(
        (kr.value, kr.basis, kr.evidence_time.as_deref()),
        (
            KeyRevocationValue::NotRevoked,
            Some(Basis::Observed),
            Some("2026-09-30T00:00:00.000Z")
        )
    );
    assert_eq!(as_of(a).verdict, Verdict::OkWithCaveats);
    assert_eq!(v.chain.as_of, Some(Verdict::OkWithCaveats));

    let kr = a.latest.stages.key_revocation.as_ref().unwrap();
    assert_eq!(kr.value, KeyRevocationValue::Revoked);
    assert_eq!(kr.revocation_ctx_id.as_deref(), Some(ctx('e').as_str()));
    assert_eq!(kr.basis, Some(Basis::Registry));
    assert_eq!(
        kr.evidence_time.as_deref(),
        Some("2026-10-05T00:00:00.000Z")
    );
    assert_eq!(
        a.latest.stages.key.as_ref().unwrap().value,
        KeyValue::Revoked
    );
    assert_eq!(a.latest.verdict, Verdict::Refused);
    assert_eq!(v.chain.latest, Verdict::Refused);
    assert_eq!(v.tainted_paths.latest, paths(&[&['a'], &['a', 'b']]));
    assert_eq!(v.tainted_paths.as_of, Some(vec![]));
    assert_eq!(
        drift(&v),
        vec![
            (ctx('a'), DriftKind::RevokedAfterAsOf),
            (ctx('b'), DriftKind::RevokedAfterAsOf)
        ]
    );
}

#[test]
fn chain_002_b_no_discovery_record_before_t() {
    let v = run(
        &['a'],
        &chain_002_bundle("2026-09-01T00:00:00.000Z", false),
        &Options::as_of(t()),
    );
    let a = node(&v, 'a');
    assert_eq!(
        as_of(a).stages.key_revocation.as_ref().unwrap().value,
        KeyRevocationValue::Unknown
    );
    assert_eq!(v.chain.as_of, Some(Verdict::Unknown));
    assert_eq!(v.chain.latest, Verdict::Refused);
    assert!(drift(&v).contains(&(ctx('a'), DriftKind::RevokedAfterAsOf)));
}

#[test]
fn chain_002_c_compromise_boundary_after_the_bodies() {
    let v = run(
        &['a'],
        &chain_002_bundle("2026-09-25T00:00:00.000Z", true),
        &Options::as_of(t()),
    );
    for id in ['a', 'b'] {
        let n = node(&v, id);
        assert_eq!(
            n.latest.stages.key_revocation.as_ref().unwrap().value,
            KeyRevocationValue::PreCompromise
        );
        assert!(n.latest.caveats.contains(&Caveat::PreCompromise));
        assert_eq!(n.latest.verdict, Verdict::OkWithCaveats);
        assert_eq!(as_of(n).verdict, Verdict::OkWithCaveats);
    }
    assert!(v.drift.is_empty());
}

// ── chain-003 ────────────────────────────────────────────────────────────────

pub fn chain_003_bundle(receipted_event: bool) -> Evidence {
    let p = Signer::did_key();
    let mut e = bundle();
    put(
        &mut e,
        'a',
        receipted(&p, 'a', &['b'], "2026-09-03T00:00:00.000Z"),
    );
    let mut b = receipted(&p, 'b', &[], "2026-09-02T00:00:00.000Z");
    let ev = event(
        &p,
        'b',
        0,
        LifecycleEventType::Retracted,
        "2026-10-03T00:00:00.000Z",
    );
    if receipted_event {
        b.event_receipts = Some(vec![event_receipt('b', &ev, 0, "2026-10-03T00:00:01.000Z")]);
    }
    b.lifecycle_events = Some(vec![ev]);
    put(&mut e, 'b', b);
    add_discovery(&mut e, KEY_PRODUCER, discovery("2026-09-30T00:00:00.000Z"));
    e
}

#[test]
fn chain_003_a_retraction_after_as_of() {
    let v = run(&['a'], &chain_003_bundle(true), &Options::as_of(t()));
    let b = node(&v, 'b');
    let r = as_of(b).stages.retraction.as_ref().unwrap();
    assert_eq!(
        (r.value, r.events_admitted),
        (RetractionValue::NotRetracted, Some(0))
    );
    let r = b.latest.stages.retraction.as_ref().unwrap();
    assert_eq!(
        (
            r.value,
            r.events_admitted,
            r.basis,
            r.evidence_time.as_deref()
        ),
        (
            RetractionValue::Retracted,
            Some(1),
            Some(Basis::Registry),
            Some("2026-10-03T00:00:01.000Z")
        )
    );
    assert_eq!(
        b.latest.caveats,
        vec![Caveat::ObservedBasis, Caveat::Retracted]
    );
    assert_eq!(b.latest.verdict, Verdict::OkWithCaveats);
    assert_eq!(v.tainted_paths.latest, paths(&[&['a', 'b']]));
    assert_eq!(v.tainted_paths.as_of, Some(vec![]));
    assert_eq!(drift(&v), vec![(ctx('b'), DriftKind::RetractedAfterAsOf)]);
    assert_eq!(v.horizon.as_deref(), Some("2026-10-03T00:00:01.000Z"));
}

#[test]
fn chain_003_b_unreceipted_event_latest_only() {
    let v = run(&['a'], &chain_003_bundle(false), &Options::as_of(t()));
    let b = node(&v, 'b');
    let r = b.latest.stages.retraction.as_ref().unwrap();
    assert_eq!(
        (r.value, r.basis),
        (RetractionValue::Retracted, Some(Basis::Observed))
    );
    assert_eq!(
        as_of(b).stages.retraction.as_ref().unwrap().value,
        RetractionValue::NotRetracted
    );
}

#[test]
fn chain_003_c_unprovable_prefix_is_unknown() {
    let p = Signer::did_key();
    let mut e = chain_003_bundle(false);
    let e0 = event(
        &p,
        'b',
        0,
        LifecycleEventType::Retracted,
        "2026-09-05T00:00:00.000Z",
    );
    let e1 = event(
        &p,
        'b',
        1,
        LifecycleEventType::Republished,
        "2026-09-06T00:00:00.000Z",
    );
    // Position 0 carries a receipt that fails §10.3 (it is minted for e1),
    // so e0 has no evidence time; e1's receipt verifies.
    let bad0 = event_receipt('b', &e1, 1, "2026-09-05T00:00:00.000Z");
    let ok1 = event_receipt('b', &e1, 1, "2026-09-06T00:00:00.000Z");
    let b = e.contexts.get_mut(&ctx('b')).unwrap();
    b.lifecycle_events = Some(vec![e0, e1]);
    b.event_receipts = Some(vec![bad0, ok1]);
    let v = run(&['a'], &e, &Options::as_of(t()));
    let r = as_of(node(&v, 'b')).stages.retraction.as_ref().unwrap();
    assert_eq!(
        (r.value, r.events_admitted),
        (RetractionValue::Unknown, Some(0))
    );
    assert_eq!(as_of(node(&v, 'b')).verdict, Verdict::Unknown);
}

// ── chain-004 ────────────────────────────────────────────────────────────────

fn chain_004_bundle() -> Evidence {
    let p = Signer::did_key();
    let mut e = chain_003_bundle(false);
    let ev = event(
        &p,
        'b',
        0,
        LifecycleEventType::Retracted,
        "2026-09-15T00:00:00.000Z",
    );
    let b = e.contexts.get_mut(&ctx('b')).unwrap();
    b.event_receipts = Some(vec![event_receipt('b', &ev, 0, "2026-10-04T00:00:00.000Z")]);
    b.lifecycle_events = Some(vec![ev]);
    e
}

#[test]
fn chain_004_backdated_retraction_is_reported_not_believed() {
    for require in [true, false] {
        let v = run(
            &['a'],
            &chain_004_bundle(),
            &Options::as_of(t()).with_require_attested_events(require),
        );
        let b = node(&v, 'b');
        assert_eq!(
            as_of(b).stages.retraction.as_ref().unwrap().value,
            RetractionValue::NotRetracted,
            "require_attested_events = {require}"
        );
        assert_eq!(
            drift(&v),
            vec![
                (ctx('b'), DriftKind::BackdatedEvent),
                (ctx('b'), DriftKind::RetractedAfterAsOf)
            ]
        );
    }
}

#[test]
fn chain_004_unattested_event_admitted_when_not_required() {
    // §6.4: with no event receipt at all, require_attested_events=false
    // admits the signed event as of T on basis observed.
    let p = Signer::did_key();
    let mut e = chain_003_bundle(false);
    let ev = event(
        &p,
        'b',
        0,
        LifecycleEventType::Retracted,
        "2026-09-15T00:00:00.000Z",
    );
    e.contexts.get_mut(&ctx('b')).unwrap().lifecycle_events = Some(vec![ev]);
    let v = run(
        &['a'],
        &e,
        &Options::as_of(t()).with_require_attested_events(false),
    );
    let r = as_of(node(&v, 'b')).stages.retraction.as_ref().unwrap();
    assert_eq!(
        (r.value, r.basis),
        (RetractionValue::Retracted, Some(Basis::Observed))
    );
    let v = run(&['a'], &e, &Options::as_of(t()));
    assert_eq!(
        as_of(node(&v, 'b'))
            .stages
            .retraction
            .as_ref()
            .unwrap()
            .value,
        RetractionValue::NotRetracted
    );
}

// ── chain-005 ────────────────────────────────────────────────────────────────

#[test]
fn chain_005_join_is_not_a_cycle() {
    let p = Signer::did_key();
    let mut e = bundle();
    put(
        &mut e,
        'a',
        receipted(&p, 'a', &['b', 'c'], "2026-09-04T00:00:00.000Z"),
    );
    put(
        &mut e,
        'b',
        receipted(&p, 'b', &['d'], "2026-09-03T00:00:00.000Z"),
    );
    put(
        &mut e,
        'c',
        receipted(&p, 'c', &['d'], "2026-09-02T00:00:00.000Z"),
    );
    put(
        &mut e,
        'd',
        receipted(&p, 'd', &[], "2026-09-01T00:00:00.000Z"),
    );
    let v = run(&['a'], &e, &Options::default());
    assert_eq!(v.nodes.len(), 4);
    assert_eq!(node(&v, 'd').depth, 2);
    assert!(v
        .nodes
        .iter()
        .all(|n| n.latest.stages.presence.value == PresenceValue::Present));
}

#[test]
fn chain_005_cycle_is_refused_on_every_member() {
    let p = Signer::did_key();
    let mut e = bundle();
    put(
        &mut e,
        'a',
        receipted(&p, 'a', &['b'], "2026-09-04T00:00:00.000Z"),
    );
    put(
        &mut e,
        'b',
        receipted(&p, 'b', &['c'], "2026-09-03T00:00:00.000Z"),
    );
    put(
        &mut e,
        'c',
        receipted(&p, 'c', &['b'], "2026-09-02T00:00:00.000Z"),
    );
    let v = run(&['a'], &e, &Options::default());
    for id in ['b', 'c'] {
        let n = node(&v, id);
        assert_eq!(n.latest.stages.presence.value, PresenceValue::Cycle);
        assert_eq!(n.latest.verdict, Verdict::Refused);
    }
    assert_ne!(
        node(&v, 'a').latest.stages.presence.value,
        PresenceValue::Cycle
    );
    assert_eq!(
        v.tainted_paths.latest,
        paths(&[&['a', 'b'], &['a', 'b', 'c']])
    );
}

// ── chain-006 ────────────────────────────────────────────────────────────────

fn star(children: &[char]) -> Evidence {
    let p = Signer::did_key();
    let mut e = bundle();
    put(
        &mut e,
        'a',
        receipted(&p, 'a', children, "2026-09-05T00:00:00.000Z"),
    );
    for c in children {
        put(
            &mut e,
            *c,
            receipted(&p, *c, &[], "2026-09-01T00:00:00.000Z"),
        );
    }
    e
}

fn limits(max_depth: u32, max_nodes: u32, max_fanout: u32) -> Limits {
    Limits {
        max_depth,
        max_nodes,
        max_fanout,
    }
}

#[test]
fn chain_006_a_fanout_truncates() {
    let v = run(
        &['a'],
        &star(&['b', 'c', 'd', 'e']),
        &Options::default().with_limits(limits(10, 500, 2)),
    );
    assert_eq!(v.frontier, vec![ctx('d'), ctx('e')]);
    assert_eq!(v.control, Some(Control::MaxFanout));
    assert!(!v.complete);
    assert_eq!(v.chain.latest, Verdict::Unknown);
}

#[test]
fn chain_006_b_depth_truncates() {
    let p = Signer::did_key();
    let mut e = bundle();
    put(
        &mut e,
        'a',
        receipted(&p, 'a', &['b'], "2026-09-04T00:00:00.000Z"),
    );
    put(
        &mut e,
        'b',
        receipted(&p, 'b', &['c'], "2026-09-03T00:00:00.000Z"),
    );
    put(
        &mut e,
        'c',
        receipted(&p, 'c', &['d'], "2026-09-02T00:00:00.000Z"),
    );
    put(
        &mut e,
        'd',
        receipted(&p, 'd', &[], "2026-09-01T00:00:00.000Z"),
    );
    let v = run(
        &['a'],
        &e,
        &Options::default().with_limits(limits(2, 500, 100)),
    );
    assert_eq!(v.frontier, vec![ctx('d')]);
    assert_eq!(v.control, Some(Control::MaxDepth));
    assert_eq!(v.nodes.len(), 3);
}

#[test]
fn chain_006_c_node_budget_truncates() {
    let v = run(
        &['a'],
        &star(&['b', 'c', 'd']),
        &Options::default().with_limits(limits(10, 3, 100)),
    );
    assert_eq!(v.frontier, vec![ctx('d')]);
    assert_eq!(v.control, Some(Control::MaxNodes));
}

#[test]
fn chain_006_d_limits_above_default_are_rejected() {
    let e = star(&['b']);
    for l in [
        limits(10, 500, 101),
        limits(11, 500, 100),
        limits(10, 501, 100),
        limits(10, 0, 100),
    ] {
        let err = verify_chain(&[ctx('a')], &e, &Options::default().with_limits(l)).unwrap_err();
        assert!(matches!(err, ChainError::InvalidOptions(_)), "{l:?}");
    }
}

// ── chain-007 ────────────────────────────────────────────────────────────────

fn chain_007_bundle(with_early_snapshot: bool) -> Evidence {
    let k1 = Signer::web(KEY1, "key-1");
    let mut e = bundle();
    put(
        &mut e,
        'a',
        receipted(&k1, 'a', &[], "2026-09-10T00:00:00.000Z"),
    );
    if with_early_snapshot {
        add_snapshot(
            &mut e,
            WEB_PRODUCER,
            did_doc(WEB_PRODUCER, &[("key-1", KEY1)], &["key-1"]),
            "2026-09-20T00:00:00.000Z",
        );
    }
    add_snapshot(
        &mut e,
        WEB_PRODUCER,
        did_doc(
            WEB_PRODUCER,
            &[("key-1", KEY1), ("key-2", KEY2)],
            &["key-2"],
        ),
        "2026-10-10T00:00:00.000Z",
    );
    add_discovery(&mut e, WEB_PRODUCER, discovery("2026-09-30T00:00:00.000Z"));
    e
}

#[test]
fn chain_007_a_clean_rotation_is_not_drift() {
    let v = run(&['a'], &chain_007_bundle(true), &Options::as_of(t()));
    let a = node(&v, 'a');
    let k = as_of(a).stages.key.as_ref().unwrap();
    assert_eq!(
        (k.value, k.basis, k.evidence_time.as_deref()),
        (
            KeyValue::Current,
            Some(Basis::Observed),
            Some("2026-09-20T00:00:00.000Z")
        )
    );
    let k = a.latest.stages.key.as_ref().unwrap();
    assert_eq!(k.value, KeyValue::HistoricalReceiptAttested);
    assert!(a.latest.caveats.contains(&Caveat::HistoricalKey));
    assert!(a.latest.caveats.contains(&Caveat::ObservedBasis));
    assert!(v.drift.is_empty());
}

#[test]
fn chain_007_b_no_snapshot_at_t_is_unprovable() {
    let v = run(&['a'], &chain_007_bundle(false), &Options::as_of(t()));
    let a = node(&v, 'a');
    let k = as_of(a).stages.key.as_ref().unwrap();
    assert_eq!(
        (k.value, k.reason.as_deref()),
        (KeyValue::Unknown, Some("no_evidence_at_as_of"))
    );
    assert_eq!(as_of(a).verdict, Verdict::Unknown);
    assert_eq!(drift(&v), vec![(ctx('a'), DriftKind::AsOfUnprovable)]);
}

#[test]
fn chain_007_c_pinned_snapshot_promotes_basis() {
    let mut pinned = Pinned::default();
    pinned.snapshots = vec![PinnedSnapshot::new(
        WEB_PRODUCER,
        did_doc(WEB_PRODUCER, &[("key-1", KEY1)], &["key-1"]),
        "2026-09-20T00:00:00.000Z",
    )];
    let v = run(
        &['a'],
        &chain_007_bundle(false),
        &Options::as_of(t()).with_pinned(pinned),
    );
    let p = as_of(node(&v, 'a'));
    assert_eq!(p.stages.key.as_ref().unwrap().basis, Some(Basis::Pinned));
    assert_eq!(
        p.stages.signature.as_ref().unwrap().basis,
        Some(Basis::Pinned)
    );
}

#[test]
fn chain_007_d_pinned_bad_key_still_fails() {
    let mut pinned = Pinned::default();
    pinned.snapshots = vec![PinnedSnapshot::new(
        WEB_PRODUCER,
        did_doc(WEB_PRODUCER, &[("key-1", [0x77; 32])], &["key-1"]),
        "2026-09-25T00:00:00.000Z",
    )];
    let v = run(
        &['a'],
        &chain_007_bundle(true),
        &Options::as_of(t()).with_pinned(pinned),
    );
    let p = as_of(node(&v, 'a'));
    assert_eq!(
        p.stages.signature.as_ref().unwrap().value,
        SignatureValue::Invalid
    );
    assert_eq!(p.verdict, Verdict::Refused);
}

// ── chain-008 ────────────────────────────────────────────────────────────────

fn chain_008_bundle() -> Evidence {
    let p = Signer::did_key();
    let mut e = bundle();
    put(
        &mut e,
        'a',
        receipted(&p, 'a', &['b', 'c', 'd'], "2026-09-04T00:00:00.000Z"),
    );
    put(
        &mut e,
        'b',
        receipted(&p, 'b', &[], "2026-09-03T00:00:00.000Z"),
    );
    put(
        &mut e,
        'c',
        receipted(&p, 'c', &[], "2026-09-02T00:00:00.000Z"),
    );
    put(
        &mut e,
        'd',
        receipted(&p, 'd', &[], "2026-09-01T00:00:00.000Z"),
    );
    add_discovery(&mut e, KEY_PRODUCER, discovery("2026-09-30T00:00:00.000Z"));
    e
}

#[test]
fn chain_008_a_tampered_body_is_refused() {
    let mut e = chain_008_bundle();
    e.contexts.get_mut(&ctx('b')).unwrap().body["title"] = json!("Tampered");
    let v = run(&['a'], &e, &Options::default());
    let b = node(&v, 'b');
    assert_eq!(
        b.latest.stages.content_hash.as_ref().unwrap().value,
        ContentHashValue::Mismatch
    );
    assert_eq!(b.latest.verdict, Verdict::Refused);
    assert_eq!(v.tainted_paths.latest, paths(&[&['a', 'b']]));
}

#[test]
fn chain_008_b_body_under_the_wrong_key_is_an_identity_mismatch() {
    let p = Signer::did_key();
    let mut e = chain_008_bundle();
    put(
        &mut e,
        'c',
        receipted(&p, 'e', &[], "2026-09-02T00:00:00.000Z"),
    );
    let v = run(&['a'], &e, &Options::default());
    assert_eq!(
        node(&v, 'c').latest.stages.identity.as_ref().unwrap().value,
        IdentityValue::Mismatch
    );
    assert_eq!(node(&v, 'c').latest.verdict, Verdict::Refused);
}

#[test]
fn chain_008_c_missing_nodes() {
    for (omitted, expected) in [
        (Some(OmittedReason::Withheld), PresenceValue::Withheld),
        (
            Some(OmittedReason::NotRetrievable),
            PresenceValue::Unresolved,
        ),
        (Some(OmittedReason::Limit), PresenceValue::Unresolved),
        (None, PresenceValue::Absent),
    ] {
        let mut e = chain_008_bundle();
        e.contexts.remove(&ctx('d'));
        if let Some(reason) = omitted {
            e.omitted = Some(vec![Omitted::new(ctx('d'), reason)]);
        }
        let v = run(&['a'], &e, &Options::default());
        let d = node(&v, 'd');
        assert_eq!(d.latest.stages.presence.value, expected);
        assert_eq!(d.latest.verdict, Verdict::Unknown);
        assert!(d.derived_from.is_none());
        assert!(d.latest.stages.identity.is_none());
        assert_eq!(v.chain.latest, Verdict::Unknown);
    }
}

#[test]
fn chain_008_d_receipt_disagreeing_with_body_is_an_identity_mismatch() {
    let p = Signer::did_key();
    let mut e = chain_008_bundle();
    let b = body(&p, 'b', &[], "2026-09-03T00:00:00.000Z");
    let mut other = b.clone();
    other.created_at = at("2026-09-03T00:00:00.001Z");
    e.contexts.get_mut(&ctx('b')).unwrap().registry_receipt =
        Some(receipt_for(&other, &p.fingerprint()));
    let v = run(&['a'], &e, &Options::default());
    let n = node(&v, 'b');
    assert_eq!(
        n.latest.stages.identity.as_ref().unwrap().value,
        IdentityValue::Mismatch
    );
    assert_eq!(n.latest.verdict, Verdict::Refused);
}

#[test]
fn chain_008_e_did_key_snapshot_rejects_the_bundle() {
    let mut e = chain_008_bundle();
    add_snapshot(
        &mut e,
        KEY_PRODUCER,
        did_doc(KEY_PRODUCER, &[], &[]),
        "2026-09-01T00:00:00.000Z",
    );
    let err = verify_chain(&[ctx('a')], &e, &Options::default()).unwrap_err();
    assert!(matches!(err, ChainError::InvalidEvidence(_)));
    assert!(Evidence::from_value(&e.to_value()).is_err());
}

// ── chain-009 ────────────────────────────────────────────────────────────────

/// B with e0 retracted / e1 republished, both producer-signed; the
/// receipts are supplied per scenario.
fn chain_009_bundle(receipts: impl FnOnce(&Value, &Value) -> Vec<Value>) -> Evidence {
    let p = Signer::did_key();
    let mut e = chain_003_bundle(false);
    let e0 = event(
        &p,
        'b',
        0,
        LifecycleEventType::Retracted,
        "2026-09-05T00:00:00.000Z",
    );
    let e1 = event(
        &p,
        'b',
        1,
        LifecycleEventType::Republished,
        "2026-09-06T00:00:00.000Z",
    );
    let b = e.contexts.get_mut(&ctx('b')).unwrap();
    b.event_receipts = Some(receipts(&e0, &e1));
    b.lifecycle_events = Some(vec![e0, e1]);
    e
}

fn b_retraction(v: &ChainVerdict) -> (&RetractionStage, &RetractionStage) {
    let b = node(v, 'b');
    (
        as_of(b).stages.retraction.as_ref().unwrap(),
        b.latest.stages.retraction.as_ref().unwrap(),
    )
}

#[test]
fn chain_009_a_well_formed_receipts_verify() {
    let v = run(
        &['a'],
        &chain_009_bundle(|e0, e1| {
            vec![
                event_receipt('b', e0, 0, "2026-09-05T00:00:00.000Z"),
                event_receipt('b', e1, 1, "2026-09-06T00:00:00.000Z"),
            ]
        }),
        &Options::as_of(t()),
    );
    let (a, l) = b_retraction(&v);
    for r in [a, l] {
        assert_eq!(
            (r.value, r.events_admitted, r.basis),
            (
                RetractionValue::NotRetracted,
                Some(2),
                Some(Basis::Registry)
            )
        );
    }
}

/// C, D, F: a receipt failing §10.3 steps 2–7 is treated as absent: e0
/// has no evidence time, so as of T the prefix is unprovable, and the
/// latest pass admits e0 on its signature alone (basis observed).
fn assert_receipt0_absent(v: &ChainVerdict) {
    let (a, l) = b_retraction(v);
    assert_eq!(a.value, RetractionValue::Unknown);
    assert_eq!(
        (l.value, l.events_admitted, l.basis),
        (
            RetractionValue::NotRetracted,
            Some(2),
            Some(Basis::Observed)
        )
    );
}

#[test]
fn chain_009_c_wrong_index_is_absent() {
    let v = run(
        &['a'],
        &chain_009_bundle(|e0, e1| {
            vec![
                event_receipt('b', e0, 1, "2026-09-05T00:00:00.000Z"),
                event_receipt('b', e1, 1, "2026-09-06T00:00:00.000Z"),
            ]
        }),
        &Options::as_of(t()),
    );
    assert_receipt0_absent(&v);
}

#[test]
fn chain_009_d_event_hash_without_signature_is_absent() {
    let v = run(
        &['a'],
        &chain_009_bundle(|e0, e1| {
            let mut unsigned = e0.clone();
            unsigned.as_object_mut().unwrap().remove("signature");
            vec![
                event_receipt('b', &unsigned, 0, "2026-09-05T00:00:00.000Z"),
                event_receipt('b', e1, 1, "2026-09-06T00:00:00.000Z"),
            ]
        }),
        &Options::as_of(t()),
    );
    assert_receipt0_absent(&v);
}

#[test]
fn chain_009_e_decreasing_accepted_at_is_invalid_in_both_passes() {
    let v = run(
        &['a'],
        &chain_009_bundle(|e0, e1| {
            vec![
                event_receipt('b', e0, 0, "2026-09-07T00:00:00.000Z"),
                event_receipt('b', e1, 1, "2026-09-06T00:00:00.000Z"),
            ]
        }),
        &Options::as_of(t()),
    );
    let (a, l) = b_retraction(&v);
    assert_eq!(a.value, RetractionValue::Invalid);
    assert_eq!(l.value, RetractionValue::Invalid);
    assert_eq!(as_of(node(&v, 'b')).verdict, Verdict::Unknown);
    assert_eq!(node(&v, 'b').latest.verdict, Verdict::Unknown);
}

#[test]
fn chain_009_f_wrong_registry_is_absent() {
    let v = run(
        &['a'],
        &chain_009_bundle(|e0, e1| {
            let other = acdp_types::receipt::ReceiptSigner::new(
                acdp_crypto::SigningKey::from_bytes(&REGISTRY_SEED),
                "did:web:other.example.com",
                "did:web:other.example.com#receipt-key-1",
            )
            .unwrap();
            let r0 = other
                .mint_event_receipt(
                    &acdp_types::primitives::CtxId::parse(ctx('b')).unwrap(),
                    e0,
                    0,
                    at("2026-09-05T00:00:00.000Z"),
                )
                .unwrap();
            vec![
                serde_json::to_value(r0).unwrap(),
                event_receipt('b', e1, 1, "2026-09-06T00:00:00.000Z"),
            ]
        }),
        &Options::as_of(t()),
    );
    assert_receipt0_absent(&v);
}

// ── chain-010 ────────────────────────────────────────────────────────────────

#[test]
fn chain_010_c_evidence_after_t_keeps_as_of_digest() {
    let base = chain_002_bundle("2026-09-01T00:00:00.000Z", true);
    let before = run(&['a'], &base, &Options::as_of(t()));

    let k1 = Signer::web(KEY1, "key-1");
    let mut later = base.clone();
    let ev = event(
        &k1,
        'a',
        0,
        LifecycleEventType::Retracted,
        "2026-10-06T00:00:00.000Z",
    );
    let a = later.contexts.get_mut(&ctx('a')).unwrap();
    a.event_receipts = Some(vec![event_receipt('a', &ev, 0, "2026-10-06T00:00:00.000Z")]);
    a.lifecycle_events = Some(vec![ev]);
    add_snapshot(
        &mut later,
        WEB_PRODUCER,
        did_doc(
            WEB_PRODUCER,
            &[("key-1", KEY1), ("key-2", KEY2)],
            &["key-2"],
        ),
        "2026-10-07T00:00:00.000Z",
    );
    let after = run(&['a'], &later, &Options::as_of(t()));

    assert_ne!(before.evidence_digest, after.evidence_digest);
    assert_ne!(before.verdict_digest, after.verdict_digest);
    assert_eq!(before.as_of_digest, after.as_of_digest);
    assert!(before.as_of_digest.is_some());
}

#[test]
fn chain_010_d_evidence_at_or_before_t_changes_as_of_digest() {
    let base = chain_002_bundle("2026-09-01T00:00:00.000Z", true);
    let before = run(&['a'], &base, &Options::as_of(t()));
    let mut more = base.clone();
    add_discovery(
        &mut more,
        WEB_PRODUCER,
        discovery("2026-09-30T12:00:00.000Z"),
    );
    let after = run(&['a'], &more, &Options::as_of(t()));
    assert_ne!(before.as_of_digest, after.as_of_digest);
}

#[test]
fn chain_010_e_no_extra_members() {
    let v = run(
        &['a'],
        &chain_002_bundle("2026-09-01T00:00:00.000Z", true),
        &Options::as_of(t()),
    );
    let value = v.to_value();
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys.len(), 17);
    assert!(!value.to_string().contains("null,\"basis\""));
    // A typed round trip is lossless and closed.
    let back: ChainVerdict = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(back, v);
    let mut extra = value;
    extra["duration_ms"] = json!(3);
    assert!(serde_json::from_value::<ChainVerdict>(extra).is_err());
}

#[test]
fn chain_010_f_timeout() {
    let e = chain_002_bundle("2026-09-01T00:00:00.000Z", true);
    // The budget fires before the root is expanded: B is never reached.
    let v = verify_chain_with_budget(&[ctx('a')], &e, &Options::as_of(t()), &mut || true).unwrap();
    assert_eq!(v.control, Some(Control::Timeout));
    assert!(!v.complete);
    assert_eq!(v.nodes.len(), 1);
    assert!(
        v.chain.latest >= Verdict::Unknown,
        "an incomplete walk is at best unknown"
    );
}

// ── options and bundle posture ───────────────────────────────────────────────

#[test]
fn determinism_and_root_normalization() {
    let e = chain_001_bundle();
    let one = verify_chain(&[ctx('a')], &e, &Options::as_of(t())).unwrap();
    let two = verify_chain(&[ctx('a'), ctx('a')], &reparse(&e), &Options::as_of(t())).unwrap();
    assert_eq!(one.to_jcs(), two.to_jcs());
    assert!(verify_chain::<&str>(&[], &e, &Options::default()).is_err());
    assert!(verify_chain(&["not-a-ctx"], &e, &Options::default()).is_err());
}

#[test]
fn pinned_normalization_and_digest() {
    assert_eq!(Pinned::default().digest(), None);
    assert_eq!(Pinned::from_value(&json!({})).unwrap().digest(), None);
    let a = Pinned::from_value(&json!({"vantages": ["b.example", "a.example"]})).unwrap();
    let mut b = Pinned::default();
    b.vantages = vec!["a.example".into(), "b.example".into(), "a.example".into()];
    assert_eq!(a.digest(), b.digest());
    assert!(Pinned::from_value(&json!({"vantages": []})).is_err());
    assert!(Pinned::from_value(&json!({"vantages": ["a.example", "a.example"]})).is_err());
    assert!(Pinned::from_value(&json!({"other": ["x"]})).is_err());
    assert!(Pinned::from_value(
        &json!({"snapshots": [{"did": KEY_PRODUCER, "document": {}, "instant": T}]})
    )
    .is_err());
}

#[test]
fn bundle_posture() {
    let mut v = chain_001_bundle().to_value();
    v["_note"] = json!("annotations are allowed and digested");
    let e = Evidence::from_value(&v).unwrap();
    assert_ne!(e.digest(), chain_001_bundle().digest());
    v["note"] = json!("x");
    assert!(Evidence::from_value(&v).is_err());
    let mut v = chain_001_bundle().to_value();
    v["omitted"] = Value::Null;
    assert!(Evidence::from_value(&v).is_err());
    let mut v = chain_001_bundle().to_value();
    v["contexts"][ctx('a')]["registry_receipt"]["extra"] = json!(1);
    assert!(Evidence::from_value(&v).is_err());
}

// ── KATs (chain-001 A, chain-002 A, chain-003 A, chain-010 A) ───────────────

/// Known-answer vectors for the cross-implementation digests (§9.3,
/// chain-010 A). Each file carries the roots, options, the evidence
/// bundle, the verdict, and the three digests; the bundle is rebuilt from
/// the fixed seeds and must reproduce the file byte-for-byte. Regenerate
/// with `ACDP_UPDATE_KATS=1` after a deliberate change.
#[test]
fn kats_reproduce() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/kats");
    let t_opts = Options::as_of(t());
    let cases: [(&str, &str, Evidence); 4] = [
        ("chain-001", "A", chain_001_bundle()),
        (
            "chain-002",
            "A",
            chain_002_bundle("2026-09-01T00:00:00.000Z", true),
        ),
        ("chain-003", "A", chain_003_bundle(true)),
        // chain-010 A is the chain-002 A bundle (its fixture's "base").
        (
            "chain-010",
            "A",
            chain_002_bundle("2026-09-01T00:00:00.000Z", true),
        ),
    ];
    let update = std::env::var("ACDP_UPDATE_KATS").is_ok_and(|v| v == "1");
    for (id, scenario, evidence) in cases {
        let v = run(&['a'], &evidence, &t_opts);
        let kat = json!({
            "id": id,
            "scenario": scenario,
            "roots": [ctx('a')],
            "options": {
                "as_of": T,
                "limits": Limits::DEFAULT,
                "pinned": Value::Null,
                "require_attested_events": true,
            },
            "evidence": evidence.to_value(),
            "verdict": v.to_value(),
            "evidence_digest": v.evidence_digest,
            "as_of_digest": v.as_of_digest,
            "verdict_digest": v.verdict_digest,
        });
        let path = dir.join(format!("{id}-{}.json", scenario.to_lowercase()));
        let text = serde_json::to_string_pretty(&kat).unwrap() + "\n";
        if update {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&path, &text).unwrap();
        }
        let pinned = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("{} missing; run with ACDP_UPDATE_KATS=1", path.display()))
            .replace("\r\n", "\n");
        assert_eq!(pinned, text, "{id} {scenario} drifted from its KAT");
        // The pinned evidence, parsed back, re-verifies to the same digests.
        let file: Value = serde_json::from_str(&pinned).unwrap();
        let again = verify_chain(
            &[ctx('a')],
            &Evidence::from_value(&file["evidence"]).unwrap(),
            &t_opts,
        )
        .unwrap();
        assert_eq!(json!(again.verdict_digest), file["verdict_digest"]);
        assert_eq!(json!(again.as_of_digest), file["as_of_digest"]);
        assert_eq!(json!(again.evidence_digest), file["evidence_digest"]);
    }
}
