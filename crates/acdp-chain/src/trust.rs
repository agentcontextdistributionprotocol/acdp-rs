//! The RFC-ACDP-0020 trust step alongside [`verify_chain`](crate::verify_chain)
//! (§7, §8): trust lists carried in the same bundle, evaluated per pass
//! into `acdp-trust-report/1` objects bound to the verdict.
//!
//! The trust step never changes the chain verdict (§8): an untrusted
//! node does not taint the RFC-ACDP-0017 graph. Combining the two is
//! the consumer's policy, for example [`TrustReport::all_trusted`].

use std::collections::BTreeMap;

use acdp_types::trust_list::{
    advance_floor, evaluate, select_version, validate_list_version, IssuerPin, ListVersion,
    PinState, ReceiptInput, TrustPass, TrustReport, TrustSubject, VerifiedListBody,
    TRUST_LIST_TYPE,
};
use chrono::{DateTime, Utc};

use crate::evidence::Parsed;
use crate::stages::{AppliedRevocation, Basic, Engine, PassAt};
use crate::verdict::{
    ChainVerdict, ContentHashValue, IdentityValue, KeyRevocationValue, KeyValue, Pass,
    PresenceValue, ReceiptValue, SignatureValue,
};

/// The consumer's trust configuration for one run.
#[derive(Debug, Clone)]
pub struct TrustOptions {
    /// Issuer pins, from configuration only (RFC-ACDP-0020 §5.1). A
    /// trust-list body in the bundle whose issuer is not pinned confers
    /// nothing.
    pub pins: Vec<IssuerPin>,
    /// The persisted per-pin floors, by (`issuer`, `list_id`), for the
    /// latest pass (§5.3). The as-of pass derives its own.
    pub floors: BTreeMap<(String, String), u64>,
    /// T for the latest pass. `verify_chain` reads no clock, so the
    /// caller supplies "now".
    pub now: DateTime<Utc>,
    /// C: the profiles each registry advertises, by lowercase origin,
    /// when the consumer fetched its capabilities document (§6.3).
    pub capabilities: BTreeMap<String, Vec<String>>,
}

impl TrustOptions {
    /// Trust options for `pins`, evaluated at `now` in the latest pass,
    /// with no persisted floors and no capabilities.
    pub fn new(pins: Vec<IssuerPin>, now: DateTime<Utc>) -> Self {
        Self {
            pins,
            floors: BTreeMap::new(),
            now,
            capabilities: BTreeMap::new(),
        }
    }

    /// Supply the persisted floors (§5.3).
    pub fn with_floors(mut self, floors: BTreeMap<(String, String), u64>) -> Self {
        self.floors = floors;
        self
    }

    /// Supply C for the registry at `origin`.
    pub fn with_capabilities(mut self, origin: &str, profiles: Vec<String>) -> Self {
        self.capabilities
            .insert(origin.to_ascii_lowercase(), profiles);
        self
    }
}

/// Local trust policy beyond RFC-ACDP-0020's requirements. The default
/// is exactly the RFC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrustPolicy {
    /// Also refuse a list version whose issuer-key revocation status is
    /// `unknown` in the pass (no discovery evidence for the issuer).
    /// §5.2 step 5 refuses only on an applied revocation and allows this
    /// as local policy.
    pub refuse_unknown_issuer_revocation: bool,
}

impl TrustPolicy {
    /// Set [`Self::refuse_unknown_issuer_revocation`].
    pub fn refuse_unknown_issuer_revocation(mut self, refuse: bool) -> Self {
        self.refuse_unknown_issuer_revocation = refuse;
        self
    }
}

/// The trust step's result.
#[derive(Debug, Clone)]
pub struct ChainTrust {
    /// The latest-pass report.
    pub latest: TrustReport,
    /// The as-of report, when the run has an as-of pass.
    pub as_of: Option<TrustReport>,
    /// The latest-pass state of every pin.
    pub latest_pins: Vec<PinState>,
    /// The floors to persist after this run (§5.3): each pin's highest
    /// valid serial seen in the bundle, never lower than before.
    pub floors: BTreeMap<(String, String), u64>,
}

pub(crate) struct Run<'e, 'p, 'a> {
    pub engine: &'e Engine<'p, 'a>,
    pub parsed: &'p Parsed<'a>,
    pub passes: &'e [PassAt],
    pub basics: &'e BTreeMap<(usize, &'a str), Basic>,
    pub revocations: &'e [Vec<AppliedRevocation>],
    pub policy: TrustPolicy,
}

fn type_str(t: &acdp_types::primitives::ContextType) -> String {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// §5.2 step 1 and step 5 as the pass sees the list's own stages, with
/// the same strictness RFC-ACDP-0017 applies to a revocation body.
fn verifies(pass: &Pass, policy: TrustPolicy) -> (bool, bool) {
    let s = &pass.stages;
    let ok = s.presence.value == PresenceValue::Present
        && s.identity
            .as_ref()
            .is_some_and(|c| c.value != IdentityValue::Mismatch)
        && s.content_hash
            .as_ref()
            .is_some_and(|c| c.value == ContentHashValue::Ok)
        && s.signature
            .as_ref()
            .is_some_and(|c| c.value == SignatureValue::Ok);
    // Step 5 refuses on an applied revocation only (`revoked`, or
    // `unplaceable`: one that applies but cannot be placed against the
    // list). `unknown` (no discovery evidence) passes unless local policy
    // refuses it.
    let key = s.key.as_ref().map(|k| k.value);
    let revoked = matches!(key, Some(KeyValue::Revoked | KeyValue::Unplaceable))
        || s.key_revocation.as_ref().is_some_and(|k| {
            matches!(
                k.value,
                KeyRevocationValue::Revoked | KeyRevocationValue::Unplaceable
            ) || (policy.refuse_unknown_issuer_revocation && k.value == KeyRevocationValue::Unknown)
        });
    let located = matches!(
        key,
        Some(KeyValue::Current | KeyValue::HistoricalReceiptAttested)
    );
    (ok && (located || revoked), revoked)
}

impl Run<'_, '_, '_> {
    /// The §5.2-valid versions of every pin, in pass `i`.
    fn versions(&self, i: usize, pins: &[IssuerPin]) -> Vec<Vec<ListVersion>> {
        let pass = self.passes[i];
        let mut out = vec![Vec::new(); pins.len()];
        for (key, pc) in &self.parsed.contexts {
            let ty = type_str(&pc.body.context_type);
            if ty != TRUST_LIST_TYPE {
                continue;
            }
            let issuer = pc.body.agent_id.as_str();
            if !pins.iter().any(|p| p.issuer == issuer) {
                continue;
            }
            let basic = &self.basics[&(i, *key)];
            let (pass_obj, _) = self.engine.full(pc, basic, &self.revocations[i], pass);
            let (ok, revoked) = verifies(&pass_obj, self.policy);
            if !ok {
                continue;
            }
            let retracted = self.engine.producer_retracted(pc, pass);
            let candidate = VerifiedListBody {
                agent_id: issuer,
                context_type: &ty,
                metadata: pc.body.metadata.as_ref(),
                content_hash: pc.body.content_hash.as_str(),
                ctx_id: Some(key),
                issuer_key_fingerprint: basic.fingerprint.as_deref(),
                issuer_key_revoked: revoked,
                retracted,
            };
            for (j, pin) in pins.iter().enumerate() {
                if let Ok(v) = validate_list_version(pin, &candidate) {
                    out[j].push(v);
                }
            }
        }
        out
    }

    pub(crate) fn evaluate(&self, verdict: &ChainVerdict, opts: &TrustOptions) -> ChainTrust {
        let mut floors = opts.floors.clone();
        let mut reports = Vec::new();
        let mut latest_pins = Vec::new();
        for (i, pass) in self.passes.iter().enumerate() {
            let (tp, t) = match pass {
                PassAt::Latest => (TrustPass::Latest, opts.now),
                PassAt::AsOf(t) => (TrustPass::AsOf, *t),
            };
            let versions = self.versions(i, &opts.pins);
            let states: Vec<PinState> = opts
                .pins
                .iter()
                .zip(&versions)
                .map(|(pin, vs)| {
                    let series = (pin.issuer.clone(), pin.list_id.clone());
                    let floor = opts.floors.get(&series).copied();
                    if tp == TrustPass::Latest {
                        if let Some(f) = advance_floor(floor, vs) {
                            floors.insert(series, f);
                        }
                    }
                    select_version(pin, vs, t, tp, floor)
                })
                .collect();
            let mut nodes = Vec::new();
            for node in &verdict.nodes {
                let p = if i == 0 {
                    Some(&node.latest)
                } else {
                    node.as_of.as_ref()
                };
                let Some(p) = p.filter(|p| p.stages.presence.value == PresenceValue::Present)
                else {
                    continue;
                };
                let Some(pc) = self.parsed.contexts.get(node.ctx_id.as_str()) else {
                    continue;
                };
                let body = &pc.body;
                // §8: the node's receipt only when its receipt stage is ok.
                let receipt = p
                    .stages
                    .registry_receipt
                    .as_ref()
                    .filter(|r| r.value == ReceiptValue::Ok)
                    .and_then(|_| self.basics[&(i, node.ctx_id.as_str())].receipt.as_ref())
                    .and_then(|r| {
                        Some(ReceiptInput {
                            registry_did: acdp_did::web::authority_to_did_web(
                                &body.origin_registry,
                            ),
                            registry_key_fingerprint: r.registry_key_fingerprint.clone()?,
                        })
                    });
                let ty = type_str(&body.context_type);
                let caps = opts
                    .capabilities
                    .get(&body.origin_registry.to_ascii_lowercase())
                    .map(Vec::as_slice);
                nodes.push(evaluate(
                    &TrustSubject::of(body, &ty),
                    &states,
                    t,
                    receipt.as_ref(),
                    caps,
                ));
            }
            reports.push(TrustReport::new(
                tp,
                t,
                &states,
                nodes,
                Some(verdict.verdict_digest.clone()),
                Some(verdict.evidence_digest.clone()),
            ));
            if i == 0 {
                latest_pins = states;
            }
        }
        let mut reports = reports.into_iter();
        ChainTrust {
            latest: reports.next().expect("the latest pass always runs"),
            as_of: reports.next(),
            latest_pins,
            floors,
        }
    }
}
