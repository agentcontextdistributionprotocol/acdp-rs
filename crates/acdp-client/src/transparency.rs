//! Opt-in transparency corroboration during verification: the
//! RFC-ACDP-0012 §9 log-inclusion verdict and the RFC-ACDP-0015 §8
//! witness-quorum verdict. Both are reachable from
//! [`VerificationPolicy`](crate::VerificationPolicy), and each is reported
//! separately from the body, receipt and revocation verdicts.
//!
//! RFC-ACDP-0012 §9.3: "Log-proof failure invalidates nothing else". The
//! log and witness verdicts are therefore *reported* by default and fail
//! verification only when the caller opts in:
//! - [`LogInclusionPolicy::Require`] for the log;
//! - a [`WitnessEnforcement`] other than `Report` for witnesses.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use acdp_did::web::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_types::body::FullContext;
use acdp_types::log::{LogInclusion, LogLeaf};
use acdp_types::receipt::RegistryReceipt;

use crate::log::verify_log_inclusion_value;
use crate::witness::{evaluate_witness_quorum, WitnessPolicy, WitnessQuorumReport};

/// RFC-ACDP-0012 §9.3 step 4 forward clock-skew allowance applied to the
/// checkpoint carried in `log_inclusion` (RECOMMENDED 120 s, the
/// RFC-ACDP-0011 §7 step 6 allowance).
pub const DEFAULT_LOG_MAX_CLOCK_SKEW_SECONDS: u32 = 120;

/// How verification treats a retrieval's `log_inclusion` member
/// (RFC-ACDP-0012 §10). Default [`Self::Ignore`]: corroboration is
/// opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogInclusionPolicy {
    /// Do not evaluate `log_inclusion`; preserve it verbatim. A
    /// [`VerificationPolicy::witness_quorum`](crate::VerificationPolicy::witness_quorum)
    /// still verifies the proof's checkpoint, because cosignatures can only
    /// be checked against a checkpoint the consumer verified itself
    /// (RFC-ACDP-0015 §8).
    #[default]
    Ignore,
    /// Verify `log_inclusion` per RFC-ACDP-0012 §9.1 when present and
    /// report the verdict. A failure is reported and never fails
    /// verification (§9.3).
    VerifyIfPresent,
    /// Fail verification with `invalid_log_proof` unless `log_inclusion`
    /// is present and verifies. Inclusion needs the RFC-ACDP-0010 receipt
    /// to rebuild the leaf (§9.1 step 1), so a context without a verified
    /// receipt fails too. A registry that advertises
    /// `acdp-registry-transparency-log` MAY still leave the proof off a
    /// response (§10). Use this only with registries known to serve it.
    Require,
}

/// When a witness-quorum shortfall fails verification
/// (RFC-ACDP-0015 §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum WitnessEnforcement {
    /// Report the quorum and never fail on it.
    #[default]
    Report,
    /// Fail unless `min_witnesses` distinct trusted witnesses cosigned the
    /// checkpoint. This is the split-view and anti-rewrite use, where a
    /// cosignature never expires.
    RequireQuorum,
    /// Fail unless `min_witnesses` of those cosignatures are also within
    /// `max_age_seconds`. Use it for decisions that depend on the
    /// checkpoint being current (§8.1).
    RequireFreshQuorum,
}

/// Witness corroboration of the checkpoint carried in `log_inclusion`
/// (RFC-ACDP-0015 §8).
///
/// Cosignatures are read from the retrieval's top-level
/// `witness_signatures` member (§6.1). Witness trust is deployment
/// policy, bootstrapped out of band (§13). Only the
/// [`trusted_witnesses`](Self::trusted_witnesses) can count toward the
/// quorum. Each witness's DID document comes from one of two places:
/// - [`pinned_documents`](Self::pinned_documents), for a direct-from-witness
///   deployment that already holds it (§6.2);
/// - otherwise it is resolved: `did:web` through the verification's
///   [`WebResolver`] (with its SSRF protections), `did:key` offline.
///
/// A witness whose document cannot be obtained does not count, and the
/// reason is recorded in [`WitnessQuorumReport::failures`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WitnessQuorumPolicy {
    /// Witness DIDs the consumer trusts.
    pub trusted_witnesses: BTreeSet<String>,
    /// Witness DID documents held out of band, by witness DID. These take
    /// precedence over resolution.
    pub pinned_documents: BTreeMap<String, serde_json::Value>,
    /// Quorum size, freshness bound and clock skew. Defaults to
    /// [`WitnessPolicy::default`]: one witness, 300 s, 120 s.
    pub witness: WitnessPolicy,
    /// Whether a shortfall fails verification. Default
    /// [`WitnessEnforcement::Report`].
    pub enforcement: WitnessEnforcement,
}

impl WitnessQuorumPolicy {
    /// Trust `witnesses`, with the default quorum (one witness), report-only.
    #[must_use]
    pub fn new<I, S>(witnesses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            trusted_witnesses: witnesses.into_iter().map(Into::into).collect(),
            pinned_documents: BTreeMap::new(),
            witness: WitnessPolicy::default(),
            enforcement: WitnessEnforcement::Report,
        }
    }

    /// Use `document` for `witness_id` instead of resolving it.
    #[must_use]
    pub fn with_document(
        mut self,
        witness_id: impl Into<String>,
        document: serde_json::Value,
    ) -> Self {
        self.pinned_documents.insert(witness_id.into(), document);
        self
    }

    /// Require `n` distinct trusted witnesses.
    #[must_use]
    pub fn with_min_witnesses(mut self, n: u32) -> Self {
        self.witness.min_witnesses = n;
        self
    }

    /// Replace the quorum, freshness and skew settings.
    #[must_use]
    pub fn with_witness_policy(mut self, witness: WitnessPolicy) -> Self {
        self.witness = witness;
        self
    }

    /// Set when a shortfall fails verification.
    #[must_use]
    pub fn enforce(mut self, enforcement: WitnessEnforcement) -> Self {
        self.enforcement = enforcement;
        self
    }
}

/// The two transparency verdicts of one verification.
#[derive(Debug, Clone, Default)]
pub(crate) struct TransparencyVerdicts {
    /// `None` when not evaluated.
    pub(crate) log: Option<Result<LogInclusion, AcdpError>>,
    /// `None` when no witness policy was set.
    pub(crate) witness: Option<Result<WitnessQuorumReport, AcdpError>>,
}

impl TransparencyVerdicts {
    pub(crate) fn log_verdict(&self) -> Option<Result<(), AcdpError>> {
        self.log
            .as_ref()
            .map(|r| r.as_ref().map(|_| ()).map_err(Clone::clone))
    }
}

/// The verified material the leaf is rebuilt from (§9.1 step 1).
pub(crate) struct LeafMaterial<'a> {
    pub(crate) receipt: &'a RegistryReceipt,
    pub(crate) receipt_value: &'a serde_json::Value,
}

/// Evaluate the log and witness verdicts for `ctx`, then enforce the
/// policy.
///
/// The caller passes a `ctx` whose `body.content_hash` is the recomputed
/// value. `material` is `None` when no receipt was verified.
pub(crate) async fn evaluate(
    client: &crate::RegistryClient,
    ctx: &FullContext,
    material: Option<LeafMaterial<'_>>,
    serving_authority: &str,
    log_policy: LogInclusionPolicy,
    witness_policy: Option<&WitnessQuorumPolicy>,
    resolver: &WebResolver,
) -> Result<TransparencyVerdicts, AcdpError> {
    let evaluate_log = match log_policy {
        LogInclusionPolicy::Ignore => witness_policy.is_some(),
        LogInclusionPolicy::VerifyIfPresent | LogInclusionPolicy::Require => true,
    };
    let mut out = TransparencyVerdicts::default();

    if evaluate_log {
        out.log = match &ctx.log_inclusion {
            Some(value) => Some(
                verify_inclusion(client, ctx, value, material, serving_authority, resolver).await,
            ),
            None if log_policy == LogInclusionPolicy::Require => {
                return Err(AcdpError::InvalidLogProof(
                    "policy requires a transparency-log inclusion proof but the response \
                     carries no log_inclusion (RFC-ACDP-0012 §10)"
                        .into(),
                ));
            }
            None => None,
        };
        if log_policy == LogInclusionPolicy::Require {
            if let Some(Err(e)) = &out.log {
                return Err(e.clone());
            }
        }
    }

    if let Some(policy) = witness_policy {
        let verdict = match &out.log {
            Some(Ok(inclusion)) => Ok(evaluate_witnesses(ctx, inclusion, policy, resolver).await),
            Some(Err(e)) => Err(AcdpError::InvalidLogProof(format!(
                "witness quorum not evaluated: the checkpoint did not verify ({e})"
            ))),
            None => Err(AcdpError::InvalidLogProof(
                "witness quorum not evaluated: the response carries no log_inclusion \
                 checkpoint to corroborate (RFC-ACDP-0015 §6.1)"
                    .into(),
            )),
        };
        enforce_witnesses(&verdict, policy)?;
        out.witness = Some(verdict);
    }
    Ok(out)
}

async fn verify_inclusion(
    client: &crate::RegistryClient,
    ctx: &FullContext,
    value: &serde_json::Value,
    material: Option<LeafMaterial<'_>>,
    serving_authority: &str,
    resolver: &WebResolver,
) -> Result<LogInclusion, AcdpError> {
    let material = material.ok_or_else(|| {
        AcdpError::InvalidLogProof(
            "log_inclusion cannot be verified without a verified registry receipt: the \
             leaf binds the receipt hash and producer-key fingerprint (RFC-ACDP-0012 §9.1 \
             step 1)"
                .into(),
        )
    })?;
    // The receipt's key_fingerprint was cross-checked against the
    // resolved producer key by RFC-ACDP-0010 §8, so it is verified
    // material.
    let leaf = LogLeaf::for_publish(
        &ctx.body,
        &ctx.body.content_hash,
        &material.receipt.key_fingerprint,
        material.receipt_value,
    )?;
    // §9.3 step 1 binds the checkpoint to `capabilities.registry_did`,
    // fetched from the authority that served the context.
    let caps = client.capabilities().await?;
    verify_log_inclusion_value(
        value,
        &leaf,
        serving_authority,
        &caps.registry_did,
        chrono::Duration::seconds(i64::from(DEFAULT_LOG_MAX_CLOCK_SKEW_SECONDS)),
        resolver,
    )
    .await
}

async fn evaluate_witnesses(
    ctx: &FullContext,
    inclusion: &LogInclusion,
    policy: &WitnessQuorumPolicy,
    resolver: &WebResolver,
) -> WitnessQuorumReport {
    let cosignatures: Vec<serde_json::Value> = match ctx.extensions.get("witness_signatures") {
        Some(serde_json::Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    // Only witnesses that are trusted AND named by a served cosignature
    // need a document; resolving the rest would be wasted fetches.
    let named: HashSet<&str> = cosignatures
        .iter()
        .filter_map(|c| c.get("witness_id").and_then(|v| v.as_str()))
        .collect();
    let mut docs: HashMap<String, serde_json::Value> = HashMap::new();
    let mut resolution_failures = Vec::new();
    for witness in policy
        .trusted_witnesses
        .iter()
        .filter(|w| named.contains(w.as_str()))
    {
        match witness_document(witness, policy, resolver).await {
            Ok(doc) => {
                docs.insert(witness.clone(), doc);
            }
            Err(e) => resolution_failures.push(AcdpError::InvalidWitnessCosignature(format!(
                "could not obtain the DID document of trusted witness '{witness}': {e}"
            ))),
        }
    }
    let trusted: HashSet<String> = policy.trusted_witnesses.iter().cloned().collect();
    let mut report = evaluate_witness_quorum(
        &cosignatures,
        &docs,
        &trusted,
        &inclusion.log_checkpoint,
        &policy.witness,
        None,
    );
    // `evaluate_witness_quorum` also records the missing document; keep the
    // more specific resolution error in front of it.
    resolution_failures.append(&mut report.failures);
    report.failures = resolution_failures;
    report
}

async fn witness_document(
    witness: &str,
    policy: &WitnessQuorumPolicy,
    resolver: &WebResolver,
) -> Result<serde_json::Value, AcdpError> {
    if let Some(doc) = policy.pinned_documents.get(witness) {
        return Ok(doc.clone());
    }
    if witness.starts_with("did:key:") {
        return Ok(serde_json::to_value(acdp_did::key::did_key_document(
            witness,
        )?)?);
    }
    Ok(serde_json::to_value(resolver.resolve(witness).await?)?)
}

fn enforce_witnesses(
    verdict: &Result<WitnessQuorumReport, AcdpError>,
    policy: &WitnessQuorumPolicy,
) -> Result<(), AcdpError> {
    let (needed, fresh) = match policy.enforcement {
        WitnessEnforcement::Report => return Ok(()),
        WitnessEnforcement::RequireQuorum => (policy.witness.min_witnesses, false),
        WitnessEnforcement::RequireFreshQuorum => (policy.witness.min_witnesses, true),
    };
    let report = verdict.as_ref().map_err(Clone::clone)?;
    let (met, count) = if fresh {
        (report.meets_fresh_quorum, report.fresh_witnessed_count)
    } else {
        (report.meets_quorum, report.witnessed_count)
    };
    if met {
        return Ok(());
    }
    Err(AcdpError::InvalidWitnessCosignature(format!(
        "witness quorum not met: {count} of {needed} required distinct trusted witnesses{} \
         cosigned the checkpoint (RFC-ACDP-0015 §8.1){}",
        if fresh {
            " (within max_age_seconds)"
        } else {
            ""
        },
        match report.failures.first() {
            Some(e) => format!("; first failure: {e}"),
            None => String::new(),
        }
    )))
}
