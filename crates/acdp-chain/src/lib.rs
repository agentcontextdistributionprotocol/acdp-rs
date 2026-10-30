//! Offline, as-of chain verification for ACDP (RFC-ACDP-0017, Final
//! at 0.5.0; §10–§11 remain Draft).
//!
//! [`verify_chain`] walks a context's `derived_from` DAG inside an
//! [`Evidence`] bundle and answers two questions about every node:
//!
//! - **as of T**: was this verifiable using only evidence dated ≤ T?
//! - **latest**: what does all the evidence in the bundle say now?
//!
//! It is pure: no network, no clock, no async. Given the same roots,
//! bundle bytes and options it emits a byte-identical
//! [`ChainVerdict`] (§9.3), whose `as_of_digest` is the value to seal
//! at T: it stays fixed as evidence dated after T accumulates.
//!
//! The online collector (`collect_evidence`, `verify_chain_online`)
//! lives in `acdp-client`; it fetches first, then runs this same
//! function over what it collected.
//!
//! ```no_run
//! use acdp_chain::{verify_chain, Evidence, Options};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let bundle: serde_json::Value = serde_json::from_str("{}")?;
//! let evidence = Evidence::from_value(&bundle)?;
//! let t = "2026-10-01T00:00:00.000Z".parse()?;
//! let verdict = verify_chain(
//!     &["acdp://registry.example.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
//!     &evidence,
//!     &Options::as_of(t),
//! )?;
//! println!("{:?} as of T, {:?} latest", verdict.chain.as_of, verdict.chain.latest);
//! # Ok(()) }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod evidence;
#[cfg(feature = "keyless")]
mod keyless;
mod keys;
mod options;
mod stages;
mod syntax;
mod trust;
mod verdict;
mod walk;

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

pub use error::ChainError;
pub use evidence::{
    CheckpointEvidence, ConsistencyProofEvidence, ContextEvidence, DidSnapshot, DiscoveryOutcome,
    DiscoveryRecord, Evidence, Omitted, OmittedReason, EVIDENCE_VERSION,
};
pub use options::{Limits, Options, Pinned, PinnedSnapshot};
pub use trust::{ChainTrust, TrustOptions, TrustPolicy};
pub use verdict::*;

use crate::evidence::OmittedReason as Reason;
use crate::keys::BundleKeys;
use crate::stages::{Basic, Engine, PassAt, PassFacts};
use crate::syntax::{fmt_ts, is_ctx_id, jcs_digest};

/// Verify the chain from `roots` over `evidence` (RFC-ACDP-0017 §6).
///
/// Returns `Err` only when the bundle fails its schema (§4.1) or the
/// options are out of range (§6.1(4), §6.3); every failed check inside
/// a well-formed bundle is a stage value in the verdict.
pub fn verify_chain<S: AsRef<str>>(
    roots: &[S],
    evidence: &Evidence,
    options: &Options,
) -> Result<ChainVerdict, ChainError> {
    verify_chain_with_budget(roots, evidence, options, &mut || false)
}

/// [`verify_chain`] under a caller-enforced time budget (§6.1(5)).
///
/// `should_stop` is polled before each node is expanded and evaluated.
/// Once it returns `true` the walk stops, `control` is `timeout`,
/// `complete` is false, and the verdict is exempt from §9.3
/// determinism.
pub fn verify_chain_with_budget<S: AsRef<str>>(
    roots: &[S],
    evidence: &Evidence,
    options: &Options,
    should_stop: &mut dyn FnMut() -> bool,
) -> Result<ChainVerdict, ChainError> {
    run(roots, evidence, options, should_stop, None).map(|(v, _)| v)
}

/// [`verify_chain`] plus the optional RFC-ACDP-0020 trust step (§7, §8).
///
/// Trust-list bodies are read from the same bundle's `contexts`: every
/// `acdp:trust-list` body whose issuer is pinned in `trust`, verified
/// with that pass's evidence (as-of DID documents, admitted issuer
/// retractions, applied revocations). Each pass yields one
/// `acdp-trust-report/1` bound to the verdict by `verdict_digest`. The
/// verdict is exactly what [`verify_chain`] returns: the trust step
/// never changes it.
pub fn verify_chain_with_trust<S: AsRef<str>>(
    roots: &[S],
    evidence: &Evidence,
    options: &Options,
    trust: &TrustOptions,
) -> Result<(ChainVerdict, ChainTrust), ChainError> {
    verify_chain_with_trust_policy(roots, evidence, options, trust, TrustPolicy::default())
}

/// [`verify_chain_with_trust`] under a local [`TrustPolicy`] stricter
/// than RFC-ACDP-0020 requires.
pub fn verify_chain_with_trust_policy<S: AsRef<str>>(
    roots: &[S],
    evidence: &Evidence,
    options: &Options,
    trust: &TrustOptions,
    policy: TrustPolicy,
) -> Result<(ChainVerdict, ChainTrust), ChainError> {
    let (verdict, report) = run(
        roots,
        evidence,
        options,
        &mut || false,
        Some((trust, policy)),
    )?;
    Ok((verdict, report.expect("trust options were given")))
}

fn run<S: AsRef<str>>(
    roots: &[S],
    evidence: &Evidence,
    options: &Options,
    should_stop: &mut dyn FnMut() -> bool,
    trust: Option<(&TrustOptions, TrustPolicy)>,
) -> Result<(ChainVerdict, Option<ChainTrust>), ChainError> {
    options.check()?;
    let roots: Vec<String> = roots.iter().map(|r| r.as_ref().to_string()).collect();
    if roots.is_empty() {
        return Err(error::options("verify_chain needs at least one root"));
    }
    if let Some(bad) = roots.iter().find(|r| !is_ctx_id(r)) {
        return Err(error::options(format!("root '{bad}' is not a ctx_id")));
    }
    let parsed = evidence.parse()?;
    let pinned = options.pinned.clone().unwrap_or_default().normalized();
    // RFC-ACDP-0021 §10: accepted attesters come from `pinned` only.
    #[cfg(feature = "keyless")]
    let keyless_attesters = pinned.keyless_attesters.clone();
    let engine = Engine {
        #[cfg(feature = "keyless")]
        keyless_attesters,
        parsed: &parsed,
        keys: BundleKeys::new(&parsed, &pinned),
        pinned,
        require_attested_events: options.require_attested_events,
    };

    let walk = walk::walk(&roots, &parsed, options.limits, should_stop);
    let cycles = walk::cycle_nodes(&walk);
    let paths = walk::shortest_paths(&walk);
    let complete = walk.control.is_none();

    let passes: Vec<PassAt> = match options.as_of {
        Some(t) => vec![PassAt::Latest, PassAt::AsOf(t)],
        None => vec![PassAt::Latest],
    };
    // Every context's revocation-independent stages, per pass: the
    // applied revocations and the horizon need them bundle-wide.
    let mut basics: BTreeMap<(usize, &str), Basic> = BTreeMap::new();
    for (i, pass) in passes.iter().enumerate() {
        for (key, pc) in &parsed.contexts {
            basics.insert((i, key), engine.basic(key, pc, *pass));
        }
    }
    let per_pass = |i: usize| -> BTreeMap<&str, Basic> {
        basics
            .iter()
            .filter(|((p, _), _)| *p == i)
            .map(|((_, k), b)| (*k, b.clone()))
            .collect()
    };
    let revocations: Vec<_> = passes
        .iter()
        .enumerate()
        .map(|(i, pass)| engine.applied_revocations(&per_pass(i), *pass))
        .collect();

    let mut nodes = Vec::with_capacity(walk.depth.len());
    let mut facts: BTreeMap<String, Vec<PassFacts>> = BTreeMap::new();
    for (ctx_id, depth) in &walk.depth {
        let pc = parsed.contexts.get(ctx_id.as_str());
        let mut pass_objects = Vec::new();
        let mut node_facts = Vec::new();
        for (i, pass) in passes.iter().enumerate() {
            let (pass_obj, f) = if cycles.contains(ctx_id) {
                (Engine::bare(PresenceValue::Cycle), PassFacts::default())
            } else if let Some(pc) = pc {
                let basic = &basics[&(i, ctx_id.as_str())];
                engine.full(pc, basic, &revocations[i], *pass)
            } else {
                let value = match parsed.omitted.get(ctx_id.as_str()) {
                    Some(Reason::Withheld) => PresenceValue::Withheld,
                    Some(_) => PresenceValue::Unresolved,
                    None => PresenceValue::Absent,
                };
                (Engine::bare(value), PassFacts::default())
            };
            pass_objects.push(pass_obj);
            node_facts.push(f);
        }
        let latest = pass_objects.remove(0);
        let as_of = pass_objects.pop();
        let derived_from = match (pc, latest.stages.presence.value) {
            (Some(pc), PresenceValue::Present) => Some(
                pc.body
                    .derived_from
                    .iter()
                    .map(|c| c.as_str().to_string())
                    .collect(),
            ),
            _ => None,
        };
        facts.insert(ctx_id.clone(), node_facts);
        nodes.push(Node {
            ctx_id: ctx_id.clone(),
            depth: *depth,
            derived_from,
            as_of,
            latest,
        });
    }

    let chain_verdict = |pick: &dyn Fn(&Node) -> Option<&Pass>| -> Option<Verdict> {
        let worst = nodes.iter().filter_map(pick).map(|p| p.verdict).max()?;
        Some(if complete {
            worst
        } else {
            worst.max(Verdict::Unknown)
        })
    };
    let tainted = |pick: &dyn Fn(&Node) -> Option<&Pass>| -> Vec<Vec<String>> {
        let mut out: Vec<Vec<String>> = nodes
            .iter()
            .filter(|n| {
                pick(n).is_some_and(|p| {
                    p.verdict == Verdict::Refused
                        || p.stages
                            .retraction
                            .as_ref()
                            .is_some_and(|r| r.value == RetractionValue::Retracted)
                })
            })
            .filter_map(|n| paths.get(&n.ctx_id).cloned())
            .collect();
        out.sort();
        out
    };
    let as_of_set = options.as_of.is_some();
    let chain = ChainVerdicts {
        as_of: if as_of_set {
            chain_verdict(&|n| n.as_of.as_ref())
        } else {
            None
        },
        latest: chain_verdict(&|n| Some(&n.latest)).unwrap_or(Verdict::Unknown),
    };
    let tainted_paths = TaintedPaths {
        as_of: as_of_set.then(|| tainted(&|n| n.as_of.as_ref())),
        latest: tainted(&|n| Some(&n.latest)),
    };
    let drift = if as_of_set {
        drift(&nodes, &facts)
    } else {
        Vec::new()
    };

    let mut verdict = ChainVerdict {
        verdict_version: VERDICT_VERSION.to_string(),
        roots: walk.roots.clone(),
        as_of: options.as_of.map(fmt_ts),
        horizon: horizon(&engine, &per_pass(0)).map(fmt_ts),
        limits: options.limits,
        require_attested_events: options.require_attested_events,
        options_digest: options.pinned.as_ref().and_then(Pinned::digest),
        evidence_digest: evidence.digest(),
        complete,
        control: walk.control,
        frontier: walk.frontier.clone(),
        nodes,
        chain,
        tainted_paths,
        drift,
        as_of_digest: None,
        verdict_digest: String::new(),
    };
    verdict.as_of_digest = as_of_projection(&verdict).map(|p| jcs_digest(&p));
    verdict.verdict_digest = verdict_digest(&verdict);
    let trust = trust.map(|(opts, policy)| {
        trust::Run {
            engine: &engine,
            parsed: &parsed,
            passes: &passes,
            basics: &basics,
            revocations: &revocations,
            policy,
        }
        .evaluate(&verdict, opts)
    });
    Ok((verdict, trust))
}

/// `verdict_digest` (§9.2): the verdict without both digests.
pub fn verdict_digest(verdict: &ChainVerdict) -> String {
    let mut v = verdict.to_value();
    if let Value::Object(map) = &mut v {
        map.remove("as_of_digest");
        map.remove("verdict_digest");
    }
    jcs_digest(&v)
}

/// The §9.2 as-of projection, or `None` when `as_of` is `null`.
///
/// `chain.as_of` and `tainted_paths.as_of` are carried nested, as
/// `{"chain": {"as_of": …}, "tainted_paths": {"as_of": …}}`.
pub fn as_of_projection(verdict: &ChainVerdict) -> Option<Value> {
    verdict.as_of.as_ref()?;
    let nodes: Vec<Value> = verdict
        .nodes
        .iter()
        .map(|n| {
            let mut m = serde_json::Map::new();
            m.insert("ctx_id".into(), json!(n.ctx_id));
            m.insert("depth".into(), json!(n.depth));
            if let Some(d) = &n.derived_from {
                m.insert("derived_from".into(), json!(d));
            }
            m.insert("as_of".into(), json!(n.as_of));
            Value::Object(m)
        })
        .collect();
    Some(json!({
        "verdict_version": verdict.verdict_version,
        "roots": verdict.roots,
        "as_of": verdict.as_of,
        "limits": verdict.limits,
        "require_attested_events": verdict.require_attested_events,
        "options_digest": verdict.options_digest,
        "complete": verdict.complete,
        "control": verdict.control,
        "frontier": verdict.frontier,
        "nodes": nodes,
        "chain": { "as_of": verdict.chain.as_of },
        "tainted_paths": { "as_of": verdict.tainted_paths.as_of },
    }))
}

/// §5.4: the greatest evidence time in the bundle, over evidence that
/// verifies (latest pass).
fn horizon(engine: &Engine<'_, '_>, latest: &BTreeMap<&str, Basic>) -> Option<DateTime<Utc>> {
    let parsed = engine.parsed;
    let mut times: Vec<DateTime<Utc>> = Vec::new();
    for (key, pc) in &parsed.contexts {
        if let Some(r) = latest.get(key).and_then(|b| b.receipt.as_ref()) {
            times.push(r.created_at);
        }
        times.extend(engine.verified_event_times(pc));
        if let Some((inclusion, raw)) = &pc.log_inclusion {
            if let Some(raw_cp) = raw.get("log_checkpoint") {
                if engine.checkpoint_signature(&inclusion.log_checkpoint, raw_cp, PassAt::Latest)
                    == Some(true)
                {
                    times.push(inclusion.log_checkpoint.timestamp);
                }
            }
        }
    }
    for list in parsed.snapshots.values() {
        times.extend(list.iter().map(|(t, _)| *t));
    }
    for list in parsed.discovery.values() {
        times.extend(list.iter().map(|d| d.completed_at));
    }
    for c in &parsed.checkpoints {
        if engine.checkpoint_signature(&c.checkpoint, c.raw, PassAt::Latest) == Some(true) {
            times.push(c.checkpoint.timestamp);
        }
    }
    times.into_iter().max()
}

/// §8.4.
fn drift(nodes: &[Node], facts: &BTreeMap<String, Vec<PassFacts>>) -> Vec<Drift> {
    let mut out = BTreeSet::new();
    for n in nodes {
        let Some(a) = &n.as_of else { continue };
        let l = &n.latest;
        let mut kinds = BTreeSet::new();
        if a.stages.presence.value == PresenceValue::NotYetPublished {
            kinds.insert(DriftKind::PublishedAfterAsOf);
        }
        let revoked = |p: &Pass| {
            p.stages.key_revocation.as_ref().is_some_and(|k| {
                matches!(
                    k.value,
                    KeyRevocationValue::Revoked | KeyRevocationValue::Unplaceable
                )
            })
        };
        if revoked(l) && !revoked(a) {
            kinds.insert(DriftKind::RevokedAfterAsOf);
        }
        let retraction = |p: &Pass| p.stages.retraction.as_ref().map(|r| r.value);
        if retraction(l) == Some(RetractionValue::Retracted)
            && retraction(a) != Some(RetractionValue::Retracted)
        {
            kinds.insert(DriftKind::RetractedAfterAsOf);
        }
        if retraction(l) == Some(RetractionValue::NotRetracted)
            && retraction(a) == Some(RetractionValue::Retracted)
        {
            kinds.insert(DriftKind::RepublishedAfterAsOf);
        }
        if facts
            .get(&n.ctx_id)
            .and_then(|f| f.get(1))
            .is_some_and(|f| f.backdated)
        {
            kinds.insert(DriftKind::BackdatedEvent);
        }
        let key_unprovable =
            a.stages
                .key
                .as_ref()
                .is_some_and(|k| k.reason.as_deref() == Some(REASON_NO_EVIDENCE_AT_AS_OF))
                && l.stages.key.as_ref().is_some_and(|k| {
                    !matches!(k.value, KeyValue::Unknown | KeyValue::Unresolvable)
                });
        let receipt_unprovable = a
            .stages
            .registry_receipt
            .as_ref()
            .is_some_and(|r| r.reason.as_deref() == Some(REASON_NO_EVIDENCE_AT_AS_OF))
            && l.stages
                .registry_receipt
                .as_ref()
                .is_some_and(|r| r.value == ReceiptValue::Ok);
        if key_unprovable || receipt_unprovable {
            kinds.insert(DriftKind::AsOfUnprovable);
        }
        if kinds.is_empty() && a.verdict != l.verdict {
            kinds.insert(DriftKind::VerdictChanged);
        }
        for kind in kinds {
            out.insert(Drift {
                ctx_id: n.ctx_id.clone(),
                kind,
            });
        }
    }
    out.into_iter().collect()
}
