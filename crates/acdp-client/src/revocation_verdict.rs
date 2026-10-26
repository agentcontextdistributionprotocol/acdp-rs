//! Typed, attributable revocation verdicts (RFC-ACDP-0014 §7/§8, 0.5.0
//! "Attribution", "Producer scope", "Discovery outcome classes",
//! "Caching").
//!
//! One assessment runs for every verification that applies a
//! [`RevocationPolicy`]: [`VerifiedContext`](crate::VerifiedContext)'s
//! `fetch*` family and [`find_revocations_verdict`] share it, so a re-check
//! sees the same known revocations, cache, discovery budget, and failure
//! policy as the original verification.
//!
//! The assessment has three outcomes, never collapsed:
//!
//! - [`RevocationVerdict::Revoked`] — a verified, in-scope revocation names
//!   the signing key; [`RevocationEffect`] says which §7 step applied.
//! - [`RevocationVerdict::NotRevoked`] — none does. `complete` says whether
//!   every configured discovery lookup finished; `observed_at` reports a
//!   cached absence's age.
//! - [`RevocationVerdict::Unknown`] — discovery could not finish, for a
//!   typed [`UnknownReason`]. `unknown` is never treated as not-revoked and
//!   is never cached.

use std::time::{Duration, SystemTime};

use acdp_did::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_types::primitives::AgentDid;
use acdp_types::receipt::ReceiptKeyStatus;
use acdp_types::revocation::{KeyRevocation, RevocationTrustClass};
use chrono::{DateTime, Utc};

pub use acdp_types::revocation::{
    RevocationEffect, RevocationRefusal, RevocationSource, SourcedRevocation, UnknownReason,
};

use crate::registry::{DiscoveryBudget, RegistryClient};
use crate::revocation::{find_registry_attested_lookup, find_revocations_lookup, Lookup};
use crate::verified::{DiscoveryFailurePolicy, DiscoveryOutcome, RevocationPolicy};

/// RFC-ACDP-0014 §8 "Caching" RECOMMENDED bound on how long a cached
/// complete absence (a negative) may suppress a discovery lookup: 300 s.
/// Both [`RevocationDiscovery`](crate::RevocationDiscovery) named
/// constructors use it.
pub const RECOMMENDED_NEGATIVE_FRESHNESS: Duration = Duration::from_secs(300);

/// The typed revocation verdict for one context's signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationVerdict {
    /// A verified, in-scope revocation names the signing key.
    Revoked {
        /// §7 step 2 ([`RevocationEffect::PreCompromise`], accepted), step 3
        /// ([`RevocationEffect::Revoked`]) or step 4
        /// ([`RevocationEffect::Unplaceable`]).
        effect: RevocationEffect,
        /// Effective boundary T (the §4 earliest `compromised_since`).
        boundary: DateTime<Utc>,
        /// The revocation that fixes `boundary`, attributed.
        revocation: SourcedRevocation,
        /// The receipt-attested publish time compared, if any.
        placement: Option<DateTime<Utc>>,
    },
    /// No verified, in-scope revocation names the signing key.
    NotRevoked {
        /// `true` when §8 discovery was configured and every configured
        /// lookup completed untruncated (live or from a fresh cached
        /// absence). `false` when discovery was off: only the caller's
        /// known revocations and cached facts were consulted.
        complete: bool,
        /// Whether the registry-attested class was among the completed
        /// lookups.
        registry_attested_checked: bool,
        /// When a cached complete absence answered at least one lookup,
        /// the earliest time such an absence was observed; `None` when
        /// every lookup ran live.
        observed_at: Option<SystemTime>,
    },
    /// Discovery could not establish the key's status.
    Unknown {
        /// Why.
        reason: UnknownReason,
        /// The failure, rendered.
        detail: String,
    },
}

impl RevocationVerdict {
    /// Whether the verdict refuses the context (§7 step 3 or 4).
    #[must_use]
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            RevocationVerdict::Revoked {
                effect: RevocationEffect::Revoked | RevocationEffect::Unplaceable,
                ..
            }
        )
    }

    /// Whether the verdict is `unknown`.
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        matches!(self, RevocationVerdict::Unknown { .. })
    }

    /// The `unknown` reason, if any.
    #[must_use]
    pub fn unknown_reason(&self) -> Option<UnknownReason> {
        match self {
            RevocationVerdict::Unknown { reason, .. } => Some(*reason),
            _ => None,
        }
    }
}

/// A complete revocation assessment: the verdict, out-of-scope hints, and
/// what discovery did.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RevocationAssessment {
    /// The verdict.
    pub verdict: RevocationVerdict,
    /// Verified revocations that do NOT speak for the producer (RFC-ACDP-0014
    /// §7 "Producer scope", 0.5.0) — reported, never applied.
    pub hints: Vec<SourcedRevocation>,
    /// §8 discovery: `None` when not configured; `Some(Ok)` with what each
    /// trust class found; `Some(Err(AcdpError::RevocationUnknown { .. }))`
    /// when discovery could not finish.
    pub discovery: Option<Result<DiscoveryOutcome, AcdpError>>,
    /// An in-scope revocation names the key and the context is placed
    /// before T — even when the verdict is `Unknown` (discovery could not
    /// rule out an earlier T). Drives the historical signature rule.
    pub(crate) pre_compromise: bool,
    pub(crate) on_failure: DiscoveryFailurePolicy,
}

impl RevocationAssessment {
    /// Apply the policy: a refusal becomes [`AcdpError::KeyRevoked`]; an
    /// `unknown` verdict becomes [`AcdpError::RevocationUnknown`] under
    /// [`DiscoveryFailurePolicy::FailClosed`] and is returned as `Ok` under
    /// [`DiscoveryFailurePolicy::ProceedWithKnown`].
    pub fn enforce(self) -> Result<Self, AcdpError> {
        if let RevocationVerdict::Revoked {
            effect: effect @ (RevocationEffect::Revoked | RevocationEffect::Unplaceable),
            boundary,
            revocation,
            placement,
        } = &self.verdict
        {
            return Err(AcdpError::KeyRevoked(Box::new(RevocationRefusal::new(
                *effect,
                revocation.revoked_key_fingerprint.clone(),
                *boundary,
                revocation.clone(),
                *placement,
                refusal_detail(*effect, *boundary, *placement),
            ))));
        }
        if self.verdict.is_unknown() && self.on_failure == DiscoveryFailurePolicy::FailClosed {
            if let Some(Err(e)) = &self.discovery {
                return Err(e.clone());
            }
        }
        Ok(self)
    }

    /// Whether the signing key is placed before an in-scope compromise
    /// boundary (§7 step 2): the signature must be verified under the
    /// RFC-ACDP-0010 §10 historical rule.
    #[must_use]
    pub fn pre_compromise(&self) -> bool {
        self.pre_compromise
    }
}

fn fmt_ms(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn refusal_detail(
    effect: RevocationEffect,
    boundary: DateTime<Utc>,
    placement: Option<DateTime<Utc>>,
) -> String {
    match (effect, placement) {
        (RevocationEffect::Revoked, Some(t)) => format!(
            "the receipt-attested publish time {} is at/after the compromise boundary {}, so \
             the signature is not attributable to the producer — fail closed regardless of \
             DID-document state or receipt validity (RFC-ACDP-0014 §7 step 3)",
            fmt_ms(t),
            fmt_ms(boundary),
        ),
        (RevocationEffect::Unplaceable, Some(_)) => format!(
            "the context's receipt is signed by a historical receipt key (verificationMethod \
             only), which cannot place a revoked-key context before the compromise boundary \
             {} under the strict profile — unplaceable, fail closed (RFC-ACDP-0014 §7 steps 1 \
             and 4)",
            fmt_ms(boundary),
        ),
        _ => format!(
            "the context has no verified registry receipt, so its publish time cannot be \
             placed relative to the compromise boundary {} — an unplaceable revoked-key \
             signature is exactly the artifact an attacker mints freely; the strict profile \
             fails closed (RFC-ACDP-0014 §7 step 4)",
            fmt_ms(boundary),
        ),
    }
}

/// Revocations gathered for one producer, before the signing key is known.
#[derive(Debug)]
pub(crate) struct Gathered {
    in_scope: Vec<SourcedRevocation>,
    hints: Vec<SourcedRevocation>,
    discovery: Option<Result<DiscoveryOutcome, AcdpError>>,
    complete: bool,
    registry_attested_checked: bool,
    observed_at: Option<SystemTime>,
    on_failure: DiscoveryFailurePolicy,
}

impl Gathered {
    /// Whether any in-scope revocation exists — the caller resolves the
    /// signing key's fingerprint only then.
    pub(crate) fn has_in_scope(&self) -> bool {
        !self.in_scope.is_empty()
    }
}

fn source_rank(s: &RevocationSource) -> u8 {
    match s {
        RevocationSource::Known => 0,
        RevocationSource::Discovered { .. } => 1,
        _ => 2,
    }
}

/// Collect known, cached, and (when configured) discovered revocations for
/// `agent_id`, scope them, and record what discovery did. Never fails: a
/// discovery failure is captured as `unknown`.
pub(crate) async fn gather(
    client: &RegistryClient,
    resolver: &WebResolver,
    agent_id: &AgentDid,
    policy: &RevocationPolicy,
) -> Gathered {
    let vantage = client.authority();
    let include_attested = policy.discover.is_some_and(|d| d.include_registry_attested);
    let on_failure = policy
        .discover
        .map_or(DiscoveryFailurePolicy::FailClosed, |d| d.on_failure);

    let mut all: Vec<SourcedRevocation> = policy
        .known
        .iter()
        .map(|r| r.sourced(RevocationSource::Known))
        .collect();
    // Facts survive every failure below: read before discovery runs.
    if let Some((cache, _)) = client.revocation_cache() {
        all.extend(
            cache
                .facts_for(agent_id.as_str(), include_attested, vantage.as_deref())
                .into_iter()
                .map(|(r, origin)| r.sourced(RevocationSource::Cached { origin })),
        );
    }

    let mut gathered = Gathered {
        in_scope: Vec::new(),
        hints: Vec::new(),
        discovery: None,
        complete: false,
        registry_attested_checked: false,
        observed_at: None,
        on_failure,
    };

    if let Some(discovery) = &policy.discover {
        // One combined budget for both lookups, on a client clone, so
        // unrelated traffic on `client` is never charged to it.
        let budget = DiscoveryBudget::new(discovery.max_requests, discovery.max_bytes);
        let dclient = client
            .with_discovery_budget(budget)
            .with_revocation_freshness(discovery.freshness);
        let fut = async {
            tokio::try_join!(
                find_revocations_lookup(&dclient, resolver, agent_id),
                async {
                    if include_attested {
                        find_registry_attested_lookup(&dclient, resolver, agent_id)
                            .await
                            .map(Some)
                    } else {
                        Ok(None)
                    }
                },
            )
        };
        let failure = match tokio::time::timeout(discovery.total_timeout, fut).await {
            Ok(Ok((signed, attested))) => {
                let outcome = DiscoveryOutcome {
                    producer_signed: signed.revocations.len(),
                    registry_attested: attested.as_ref().map(|l| l.revocations.len()),
                };
                gathered.observed_at = [Some(&signed), attested.as_ref()]
                    .into_iter()
                    .flatten()
                    .filter_map(|l: &Lookup| l.cached_since)
                    .min();
                gathered.complete = true;
                gathered.registry_attested_checked = attested.is_some();
                let authority = vantage.clone().unwrap_or_default();
                for l in std::iter::once(signed).chain(attested) {
                    all.extend(l.revocations.iter().map(|r: &KeyRevocation| {
                        r.sourced(RevocationSource::Discovered {
                            authority: authority.clone(),
                        })
                    }));
                }
                gathered.discovery = Some(Ok(outcome));
                None
            }
            Ok(Err(e)) => Some(e),
            Err(_elapsed) => Some(AcdpError::CrossRegistryResolutionFailed(format!(
                "revocation auto-discovery exceeded total_timeout={:?}",
                discovery.total_timeout
            ))),
        };
        if let Some(source) = failure {
            let reason = source.unknown_reason();
            let detail = format!(
                "RFC-ACDP-0014 §8 discovery for {agent_id} at {} could not finish: {source}",
                vantage.as_deref().unwrap_or("<no authority>")
            );
            gathered.discovery = Some(Err(AcdpError::RevocationUnknown {
                reason,
                source: Box::new(source),
                detail,
            }));
        }
    }

    (gathered.in_scope, gathered.hints) = scope(all, agent_id);
    gathered
}

/// RFC-ACDP-0014 §7 producer scope: split revocations into those that
/// speak for `agent_id` and out-of-scope hints (deduplicated).
fn scope(
    all: Vec<SourcedRevocation>,
    agent_id: &AgentDid,
) -> (Vec<SourcedRevocation>, Vec<SourcedRevocation>) {
    let (mut in_scope, mut hints) = (Vec::new(), Vec::new());
    for r in all {
        if r.speaks_for(agent_id) {
            in_scope.push(r);
        } else if !hints.contains(&r) {
            hints.push(r);
        }
    }
    (in_scope, hints)
}

/// Decide the verdict for `signing_key_fingerprint` (`None` when there is
/// no in-scope revocation, so no fingerprint was resolved).
pub(crate) fn decide(
    gathered: Gathered,
    signing_key_fingerprint: Option<&str>,
    receipt_placement: Option<(DateTime<Utc>, ReceiptKeyStatus)>,
    accept_historical_receipt_key: bool,
) -> RevocationAssessment {
    // §4: the earliest boundary across every in-scope revocation naming the
    // key; ties prefer producer-signed, then the most direct source.
    let fixing = signing_key_fingerprint.and_then(|fp| {
        gathered
            .in_scope
            .iter()
            .filter(|r| r.revoked_key_fingerprint == fp)
            .min_by_key(|r| {
                (
                    r.compromised_since,
                    r.trust_class != RevocationTrustClass::ProducerSigned,
                    source_rank(&r.source),
                )
            })
            .cloned()
    });
    let named = fixing.map(|revocation| {
        let boundary = revocation.compromised_since;
        let (effect, placement) = match receipt_placement {
            Some((t, ReceiptKeyStatus::Historical)) if !accept_historical_receipt_key => {
                (RevocationEffect::Unplaceable, Some(t))
            }
            Some((t, _)) if t < boundary => (RevocationEffect::PreCompromise, Some(t)),
            Some((t, _)) => (RevocationEffect::Revoked, Some(t)),
            None => (RevocationEffect::Unplaceable, None),
        };
        RevocationVerdict::Revoked {
            effect,
            boundary,
            revocation,
            placement,
        }
    });

    let pre_compromise = matches!(
        named,
        Some(RevocationVerdict::Revoked {
            effect: RevocationEffect::PreCompromise,
            ..
        })
    );
    let unknown = match &gathered.discovery {
        Some(Err(AcdpError::RevocationUnknown { reason, detail, .. })) => {
            Some(RevocationVerdict::Unknown {
                reason: *reason,
                detail: detail.clone(),
            })
        }
        _ => None,
    };
    // A refusal is definitive; `unknown` outranks an acceptance (an
    // unfinished discovery could hide an earlier boundary).
    let verdict = match (named, unknown) {
        (Some(v), _) if v.is_refusal() => v,
        (_, Some(u)) => u,
        (Some(v), None) => v,
        (None, None) => RevocationVerdict::NotRevoked {
            complete: gathered.complete,
            registry_attested_checked: gathered.registry_attested_checked,
            observed_at: gathered.observed_at,
        },
    };
    RevocationAssessment {
        verdict,
        hints: gathered.hints,
        discovery: gathered.discovery,
        pre_compromise,
        on_failure: gathered.on_failure,
    }
}

/// Assess `signing_key_fingerprint`'s revocation status for `agent_id`
/// under `policy` — the same assessment
/// [`VerifiedContext::fetch_with_policy`](crate::VerifiedContext::fetch_with_policy)
/// runs, for re-checking an already-verified context without refetching
/// it. Shares `policy.known`, `client`'s attached
/// [`RevocationCache`](crate::RevocationCache), and `policy.discover`'s
/// budget, deadline, freshness, and failure policy.
///
/// `receipt_placement` is the context's verified receipt `created_at` and
/// receipt-key status (see
/// [`VerifiedContext::verified_receipt`](crate::VerifiedContext::verified_receipt)
/// and [`VerifiedContext::receipt_key_status`](crate::VerifiedContext::receipt_key_status)),
/// or `None` when it has no verified receipt.
///
/// Returns the typed assessment and never fails on a verdict: call
/// [`RevocationAssessment::enforce`] to turn a refusal into
/// [`AcdpError::KeyRevoked`] and an `unknown` (under `FailClosed`) into
/// [`AcdpError::RevocationUnknown`]. `Err` only for a malformed `agent_id`.
pub async fn find_revocations_verdict(
    client: &RegistryClient,
    resolver: &WebResolver,
    agent_id: &AgentDid,
    signing_key_fingerprint: &str,
    receipt_placement: Option<(DateTime<Utc>, ReceiptKeyStatus)>,
    policy: &RevocationPolicy,
) -> Result<RevocationAssessment, AcdpError> {
    let agent_id = AgentDid::parse(agent_id.as_str())?;
    let gathered = gather(client, resolver, &agent_id, policy).await;
    Ok(decide(
        gathered,
        Some(signing_key_fingerprint),
        receipt_placement,
        policy.accept_historical_receipt_key_for_pre_t,
    ))
}

/// Classify `revocations` (all treated as caller-supplied) for
/// `signing_key_fingerprint` — the synchronous core of
/// [`classify_under_revocation_placed`](crate::classify_under_revocation_placed).
/// No producer-scope filter: the caller chose these revocations.
pub(crate) fn decide_known(
    revocations: &[KeyRevocation],
    signing_key_fingerprint: &str,
    receipt_placement: Option<(DateTime<Utc>, ReceiptKeyStatus)>,
    accept_historical_receipt_key: bool,
) -> RevocationAssessment {
    let gathered = Gathered {
        in_scope: revocations
            .iter()
            .map(|r| r.sourced(RevocationSource::Known))
            .collect(),
        hints: Vec::new(),
        discovery: None,
        complete: false,
        registry_attested_checked: false,
        observed_at: None,
        on_failure: DiscoveryFailurePolicy::FailClosed,
    };
    decide(
        gathered,
        Some(signing_key_fingerprint),
        receipt_placement,
        accept_historical_receipt_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_types::primitives::{ContextType, CtxId, Visibility};
    use serde_json::{json, Value};

    fn spec_dir() -> Option<std::path::PathBuf> {
        let candidates = [
            std::env::var("ACDP_SPEC_DIR")
                .ok()
                .map(std::path::PathBuf::from),
            Some(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../agentcontextdistributionprotocol"),
            ),
        ];
        candidates
            .into_iter()
            .flatten()
            .find(|p| p.join("schemas/conformance").exists())
    }

    /// One `rev-007` member as acdp would hold it after discovery: built
    /// as a publish request and parsed by `KeyRevocation`, which applies
    /// the §4/§10 type rule and derives the trust class. `None` when acdp
    /// would not treat it as a revocation at all.
    fn member(m: &Value) -> Option<SourcedRevocation> {
        let agent = AgentDid::new(m["agent_id"].as_str().unwrap());
        let mut meta = json!({ "revoked_key_fingerprint": m["revoked_key_fingerprint"] });
        for k in ["compromised_since", "revoked_key_controller"] {
            if let Some(v) = m.get(k) {
                meta[k] = v.clone();
            }
        }
        let req = acdp_producer::Producer::new(
            acdp_crypto::SigningKey::from_bytes(&[0x42; 32]),
            agent.clone(),
            format!("{agent}#key-9"),
        )
        .publish_request()
        .title("rev-007 member")
        .context_type(serde_json::from_value::<ContextType>(m["type"].clone()).ok()?)
        .visibility(Visibility::Public)
        .metadata(meta)
        .build()
        .ok()?;
        let mut r = KeyRevocation::from_publish_request(&req).ok()?;
        r.ctx_id = Some(CtxId(m["ctx_id"].as_str().unwrap().to_owned()));
        Some(r.sourced(RevocationSource::Discovered {
            authority: "registry.example.com".into(),
        }))
    }

    /// rev-007 (spec aa9701c): every known-answer vector through `scope`
    /// and `decide`, the code `find_revocations_verdict` and
    /// `VerifiedContext` run.
    #[test]
    fn rev_007_classification_known_answers() {
        let Some(spec) = spec_dir() else {
            assert!(
                std::env::var("ACDP_REQUIRE_CONFORMANCE").is_err(),
                "ACDP_REQUIRE_CONFORMANCE is set but the spec checkout was not found"
            );
            eprintln!("ACDP spec not found; skipping rev-007");
            return;
        };
        let path = spec.join("schemas/conformance/rev-007-classification-known-answers.json");
        let fixture: Value =
            serde_json::from_slice(&std::fs::read(&path).expect("rev-007 fixture")).unwrap();
        let mut disagreements = Vec::new();
        for v in fixture["vectors"].as_array().unwrap() {
            let i = &v["input"];
            let agent = AgentDid::new(i["context"]["agent_id"].as_str().unwrap());
            let fp = i["context"]["key_fingerprint"].as_str().unwrap();
            let all = i["revocations"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(member)
                .collect();
            let (in_scope, hints) = scope(all, &agent);
            let unknown = i["unknown_lookups"].as_u64().unwrap() > 0;
            let discovery = if unknown {
                Err(AcdpError::RevocationUnknown {
                    reason: UnknownReason::Transient,
                    source: Box::new(AcdpError::Http("lookup failed".into())),
                    detail: "rev-007 unknown lookup".into(),
                })
            } else {
                Ok(DiscoveryOutcome {
                    producer_signed: in_scope.len(),
                    registry_attested: Some(0),
                })
            };
            let placement = match &i["receipt"] {
                r if r.is_null() || r["verified"] == false => None,
                r => Some((
                    r["created_at"].as_str().unwrap().parse().unwrap(),
                    match r["key_status"].as_str().unwrap() {
                        "current" => ReceiptKeyStatus::Current,
                        _ => ReceiptKeyStatus::Historical,
                    },
                )),
            };
            let gathered = Gathered {
                in_scope,
                hints,
                complete: !unknown,
                registry_attested_checked: !unknown,
                discovery: Some(discovery),
                observed_at: None,
                on_failure: DiscoveryFailurePolicy::FailClosed,
            };
            let got = match decide(gathered, Some(fp), placement, false).verdict {
                RevocationVerdict::Revoked {
                    effect,
                    boundary,
                    revocation,
                    ..
                } => json!({
                    "key_revocation": match effect {
                        RevocationEffect::PreCompromise => "pre-compromise",
                        RevocationEffect::Revoked => "revoked",
                        _ => "unplaceable",
                    },
                    "boundary": fmt_ms(boundary),
                    "revocation_ctx_id": revocation.ctx_id.map(|c| c.0),
                }),
                RevocationVerdict::NotRevoked { .. } => json!({
                    "key_revocation": "not-revoked", "boundary": null, "revocation_ctx_id": null
                }),
                RevocationVerdict::Unknown { .. } => json!({
                    "key_revocation": "unknown", "boundary": null, "revocation_ctx_id": null
                }),
            };
            if got != v["expected"] {
                disagreements.push(format!(
                    "{}: acdp {got}, expected {}",
                    v["name"], v["expected"]
                ));
            }
        }
        assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
    }
}
