//! The per-node stages (RFC-ACDP-0017 §7) and the node verdict (§8.1),
//! evaluated for one pass over the evidence that pass admits.

use std::collections::BTreeMap;

use acdp_types::body::Body;
use acdp_types::event_receipt::EventReceipt;
use acdp_types::lifecycle::{retraction_state, LifecycleEvent};
use acdp_types::log::{LogCheckpoint, LogLeaf};
use acdp_types::primitives::ContentHash;
use acdp_types::receipt::RegistryReceipt;
use acdp_types::revocation::{KeyRevocation, RevocationTrustClass};
use chrono::{DateTime, Utc};

use crate::evidence::{DiscoveryOutcome, Parsed, ParsedContext};
use crate::keys::{BundleKeys, Missing};
use crate::options::Pinned;
use crate::syntax::fmt_ts;
use crate::verdict::*;

/// Which pass is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassAt {
    Latest,
    AsOf(DateTime<Utc>),
}

impl PassAt {
    pub(crate) fn t(self) -> Option<DateTime<Utc>> {
        match self {
            PassAt::Latest => None,
            PassAt::AsOf(t) => Some(t),
        }
    }

    /// Whether evidence dated `time` is admitted (§5.2).
    fn admits(self, time: DateTime<Utc>) -> bool {
        self.t().is_none_or(|t| time <= t)
    }

    fn no_evidence_reason(self) -> Option<String> {
        matches!(self, PassAt::AsOf(_)).then(|| REASON_NO_EVIDENCE_AT_AS_OF.to_string())
    }
}

/// A registry receipt that verified in a pass.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedReceipt {
    pub created_at: DateTime<Utc>,
    pub key_status: KeyStatus,
    pub basis: Basis,
    pub key_fingerprint: String,
    /// The RFC-ACDP-0010 §6 fingerprint of the registry key that signed
    /// the receipt (RFC-ACDP-0020 §6.1's receipt input).
    pub registry_key_fingerprint: Option<String>,
}

/// The stages that do not depend on key revocation: what a revocation
/// context itself must pass before it is applied (no recursion).
#[derive(Debug, Clone)]
pub(crate) struct Basic {
    pub presence: Presence,
    pub undated: bool,
    pub identity: Identity,
    pub content_hash: ContentHashStage,
    pub signature: Option<SignatureStage>,
    pub receipt_stage: ReceiptStage,
    pub receipt: Option<VerifiedReceipt>,
    pub key: KeyStage,
    /// The fingerprint of the located producer key.
    pub fingerprint: Option<String>,
    /// A keyless node's attestation, when it checked through §8.1 steps
    /// 1–5 (RFC-ACDP-0021).
    #[cfg(feature = "keyless")]
    pub keyless: Option<crate::keyless::Attested>,
    /// Why a keyless node's signer did not check through steps 1–3.
    #[cfg(feature = "keyless")]
    pub keyless_failure: Option<crate::keyless::Unattested>,
}

impl Basic {
    fn sig_ok(&self) -> bool {
        self.signature
            .as_ref()
            .is_some_and(|s| s.value == SignatureValue::Ok)
    }
}

/// A key-revocation context the pass applies.
#[derive(Debug, Clone)]
pub(crate) struct AppliedRevocation {
    pub ctx_id: String,
    pub revocation: KeyRevocation,
    pub evidence_time: Option<DateTime<Utc>>,
    /// A revocation signed by a keyless key that this pass could not
    /// evaluate (no RFC-ACDP-0021 support, an unaccepted attester, or an
    /// attestation that does not verify). It never applies, but naming
    /// the node's key it makes the stage `unknown` (RFC-ACDP-0021 §9.3,
    /// RFC-ACDP-0014 §7: unknown outranks not-revoked and
    /// pre-compromise).
    pub unevaluated: bool,
}

/// Evaluation context shared by both passes.
pub(crate) struct Engine<'p, 'a> {
    pub parsed: &'p Parsed<'a>,
    pub keys: BundleKeys,
    pub pinned: Pinned,
    pub require_attested_events: bool,
    /// RFC-ACDP-0021 §11 accepted attesters.
    #[cfg(feature = "keyless")]
    pub keyless_attesters: Vec<String>,
}

/// What the full evaluation of one present node in one pass yields,
/// beyond the stages themselves (drift needs it).
#[derive(Debug, Clone, Default)]
pub(crate) struct PassFacts {
    /// Events whose receipt verifies with `occurred_at` ≤ T < `accepted_at`.
    pub backdated: bool,
}

impl Engine<'_, '_> {
    pub(crate) fn registry_basis(&self, registry_did: &str) -> Basis {
        if self.pinned.registries.iter().any(|d| d == registry_did) {
            Basis::Pinned
        } else {
            Basis::Registry
        }
    }

    /// §7.2–§7.6 without key revocation.
    pub(crate) fn basic(&self, key: &str, pc: &ParsedContext<'_>, pass: PassAt) -> Basic {
        let body = &pc.body;
        let recomputed = acdp_crypto::compute_content_hash(pc.raw_body).ok();
        let hash_ok = recomputed.as_ref() == Some(&body.content_hash);

        // RFC-ACDP-0021 §10: a keyless key is located by its attestation.
        #[cfg(feature = "keyless")]
        let attested = Self::is_keyless_node(body).then(|| self.keyless_attested(body, pass));
        let check = match () {
            #[cfg(feature = "keyless")]
            () if attested.is_some() => match attested.as_ref().unwrap() {
                Ok(a) => Ok(a.key_check()),
                Err(u) => Err(u.missing()),
            },
            () => self.keys.check(
                &body.signature,
                &body.content_hash,
                body.agent_id.as_str(),
                pass.t(),
            ),
        };
        let fingerprint = check.as_ref().ok().and_then(|c| c.fingerprint.clone());

        let (receipt_stage, receipt) =
            self.receipt(key, pc, recomputed.as_ref(), fingerprint.as_deref(), pass);

        let (presence, undated) = match (&receipt, pass) {
            (Some(r), PassAt::AsOf(t)) if r.created_at > t => (
                Presence {
                    value: PresenceValue::NotYetPublished,
                    evidence_time: Some(fmt_ts(r.created_at)),
                    basis: Some(r.basis),
                },
                false,
            ),
            (Some(r), _) => (
                Presence {
                    value: PresenceValue::Present,
                    evidence_time: Some(fmt_ts(r.created_at)),
                    basis: Some(r.basis),
                },
                false,
            ),
            (None, pass) => (
                Presence {
                    value: PresenceValue::Present,
                    evidence_time: None,
                    basis: None,
                },
                matches!(pass, PassAt::AsOf(_)),
            ),
        };

        let carried_disagrees = pc.receipt.as_ref().is_some_and(|(r, _)| {
            r.ctx_id != body.ctx_id
                || r.lineage_id != body.lineage_id
                || r.origin_registry != body.origin_registry
                || r.created_at != body.created_at
        });
        let identity = if key != body.ctx_id.as_str()
            || carried_disagrees
            || acdp_verify::verify_registry_assigned_bindings(body).is_err()
        {
            Identity {
                value: IdentityValue::Mismatch,
                basis: None,
                reason: None,
            }
        } else if let Some(r) = &receipt {
            Identity {
                value: IdentityValue::Ok,
                basis: Some(r.basis),
                reason: None,
            }
        } else {
            Identity {
                value: IdentityValue::Unbound,
                basis: None,
                reason: None,
            }
        };

        let (signature, key_stage) = match check {
            Err(m) => missing_stages(m, pass),
            Ok(c) => {
                let signature = SignatureStage {
                    value: if c.valid {
                        SignatureValue::Ok
                    } else {
                        SignatureValue::Invalid
                    },
                    basis: Some(c.basis),
                };
                let value = if c.in_assertion {
                    Some(KeyValue::Current)
                } else if receipt.is_some() {
                    // RFC-ACDP-0010 §10: a verified receipt binds this
                    // key's fingerprint to a registry-attested time.
                    Some(KeyValue::HistoricalReceiptAttested)
                } else {
                    None
                };
                let key_stage = match value {
                    Some(value) => KeyStage {
                        value,
                        basis: Some(c.basis),
                        evidence_time: c.evidence_time.map(fmt_ts),
                        reason: None,
                    },
                    None => KeyStage {
                        value: KeyValue::Unresolvable,
                        basis: None,
                        evidence_time: None,
                        reason: None,
                    },
                };
                (Some(signature), key_stage)
            }
        };
        // RFC-ACDP-0021 §10: steps 4–5 place the signature; any other
        // failure on present evidence is unresolvable in both passes.
        #[cfg(feature = "keyless")]
        let (signature, key_stage, keyless, keyless_failure) = match attested {
            Some(Ok(a)) => match receipt
                .as_ref()
                .filter(|r| Self::keyless_placed(body, &a, Some(r)))
            {
                Some(r) => {
                    let (signature, key_stage) = self
                        .keyless_stages(body, &a, r, pass)
                        .unwrap_or_else(|m| missing_stages(m, pass));
                    (signature, key_stage, Some(a), None)
                }
                None => {
                    let (signature, key_stage) = missing_stages(Missing::Malformed, pass);
                    (signature, key_stage, None, None)
                }
            },
            Some(Err(u)) => (signature, key_stage, None, Some(u)),
            None => (signature, key_stage, None, None),
        };

        Basic {
            presence,
            undated,
            identity,
            content_hash: ContentHashStage {
                value: if hash_ok {
                    ContentHashValue::Ok
                } else {
                    ContentHashValue::Mismatch
                },
                basis: Basis::SelfEvident,
            },
            signature,
            receipt_stage,
            receipt,
            key: key_stage,
            fingerprint,
            #[cfg(feature = "keyless")]
            keyless,
            #[cfg(feature = "keyless")]
            keyless_failure,
        }
    }

    /// §7.5: RFC-ACDP-0010 §8 against the registry document chosen per
    /// §6.2.
    fn receipt(
        &self,
        key: &str,
        pc: &ParsedContext<'_>,
        recomputed: Option<&ContentHash>,
        producer_fingerprint: Option<&str>,
        pass: PassAt,
    ) -> (ReceiptStage, Option<VerifiedReceipt>) {
        let invalid = |reason: Option<String>| {
            (
                ReceiptStage {
                    value: ReceiptValue::Invalid,
                    key_status: None,
                    basis: None,
                    evidence_time: None,
                    reason,
                },
                None,
            )
        };
        let Some((r, raw)) = &pc.receipt else {
            return (
                ReceiptStage {
                    value: ReceiptValue::Absent,
                    key_status: None,
                    basis: None,
                    evidence_time: None,
                    reason: None,
                },
                None,
            );
        };
        let body = &pc.body;
        let Some(recomputed) = recomputed else {
            return invalid(None);
        };
        let Ok(expected_ctx) = acdp_types::primitives::CtxId::parse(key) else {
            return invalid(None);
        };
        // With no located producer key the receipt's own fingerprint
        // stands in; the key stage then decides on the producer side.
        let fp = producer_fingerprint.unwrap_or(&r.key_fingerprint);
        let registry_did = acdp_did::web::authority_to_did_web(&body.origin_registry);
        if r.registry_did != registry_did
            || r.cross_check(&expected_ctx, recomputed, fp).is_err()
            || r.cross_check_body(body).is_err()
        {
            return invalid(None);
        }
        let Ok(hash) = RegistryReceipt::preimage_hash_of_value(raw) else {
            return invalid(None);
        };
        match self
            .keys
            .check(&r.signature, &hash, &r.registry_did, pass.t())
        {
            Ok(c) if c.valid => {
                let basis = self.registry_basis(&r.registry_did);
                let key_status = if c.in_assertion {
                    KeyStatus::Current
                } else {
                    KeyStatus::Historical
                };
                (
                    ReceiptStage {
                        value: ReceiptValue::Ok,
                        key_status: Some(key_status),
                        basis: Some(basis),
                        evidence_time: Some(fmt_ts(r.created_at)),
                        reason: None,
                    },
                    Some(VerifiedReceipt {
                        created_at: r.created_at,
                        key_status,
                        basis,
                        key_fingerprint: r.key_fingerprint.clone(),
                        registry_key_fingerprint: c.fingerprint.clone(),
                    }),
                )
            }
            Ok(_) | Err(Missing::Malformed) => invalid(None),
            // §7.5: `no_evidence_at_as_of` only when the registry's
            // snapshots all postdate T; none at all is a bare invalid.
            Err(Missing::NoEvidence) => match pass {
                PassAt::AsOf(t) if self.keys.only_after(&r.registry_did, t) => {
                    invalid(pass.no_evidence_reason())
                }
                _ => invalid(None),
            },
        }
    }

    /// The key-revocation contexts a pass applies (§5.3, §7.9), each
    /// having passed the strict pipeline on its own body.
    pub(crate) fn applied_revocations(
        &self,
        basics: &BTreeMap<&str, Basic>,
        pass: PassAt,
    ) -> Vec<AppliedRevocation> {
        let mut out = Vec::new();
        for (key, pc) in &self.parsed.contexts {
            if !pc.body.context_type.is_key_revocation() {
                continue;
            }
            let Some(b) = basics.get(key) else { continue };
            let strict = b.presence.value == PresenceValue::Present
                && b.content_hash.value == ContentHashValue::Ok
                && b.identity.value != IdentityValue::Mismatch
                && b.sig_ok()
                && matches!(
                    b.key.value,
                    KeyValue::Current | KeyValue::HistoricalReceiptAttested
                );
            // As of T a revocation applies only once its own evidence
            // time is ≤ T; an unreceipted one has none (§5.1, §5.3).
            let dated = match pass {
                PassAt::Latest => true,
                PassAt::AsOf(_) => b.receipt.is_some(),
            };
            if !dated {
                continue;
            }
            // RFC-ACDP-0021 §9.3: a keyless-signed revocation is judged by
            // its signer's §8.1 steps 1–7, not by the key stage.
            if acdp_types::keyless::is_keyless_key_id(&pc.body.signature.key_id) {
                if let Some(r) = self.keyless_signed_revocation(key, pc, b, pass) {
                    out.push(r);
                }
                continue;
            }
            if !strict {
                continue;
            }
            let Ok(revocation) = KeyRevocation::from_body(&pc.body) else {
                continue;
            };
            let Some(fp) = &b.fingerprint else { continue };
            if revocation.check_not_self_signed(fp).is_err() {
                continue;
            }
            if revocation.trust_class == RevocationTrustClass::RegistryAttested
                && revocation.publisher.as_str()
                    != acdp_did::web::authority_to_did_web(&pc.body.origin_registry)
            {
                continue;
            }
            out.push(AppliedRevocation {
                ctx_id: key.to_string(),
                revocation,
                evidence_time: b.receipt.as_ref().map(|r| r.created_at),
                unevaluated: false,
            });
        }
        out
    }

    /// A key-revocation context signed by a keyless key (RFC-ACDP-0021
    /// §9.3), when it is admitted: applied (org-wide signer that checks),
    /// or unevaluated (no RFC-ACDP-0021 support, an unaccepted attester,
    /// an attestation not in evidence), which never applies but makes a
    /// stage naming the key `unknown`. A definitively invalid signer, or
    /// a non-org-wide one, gives `None`: ignored.
    fn keyless_signed_revocation(
        &self,
        key: &str,
        pc: &ParsedContext<'_>,
        b: &Basic,
        pass: PassAt,
    ) -> Option<AppliedRevocation> {
        if b.presence.value != PresenceValue::Present
            || b.content_hash.value != ContentHashValue::Ok
            || b.identity.value == IdentityValue::Mismatch
        {
            return None;
        }
        let revocation = KeyRevocation::from_body(&pc.body).ok()?;
        if revocation.trust_class != RevocationTrustClass::ProducerSigned
            || revocation.publisher != revocation.revoked_key_controller
        {
            return None;
        }
        #[cfg(feature = "keyless")]
        {
            self.keyless_revocation(key, pc, b, pass)
        }
        #[cfg(not(feature = "keyless"))]
        {
            let _ = pass;
            Some(AppliedRevocation {
                ctx_id: key.to_string(),
                revocation,
                evidence_time: b.receipt.as_ref().map(|r| r.created_at),
                unevaluated: true,
            })
        }
    }

    /// The full pass over one present node: §7.7–§7.9 on top of
    /// [`Basic`], the key override, and the §8.1 verdict.
    pub(crate) fn full(
        &self,
        pc: &ParsedContext<'_>,
        basic: &Basic,
        revocations: &[AppliedRevocation],
        pass: PassAt,
    ) -> (Pass, PassFacts) {
        let mut stages = Stages {
            presence: basic.presence.clone(),
            ..Stages::default()
        };
        if basic.presence.value != PresenceValue::Present {
            return (finish(stages, false), PassFacts::default());
        }
        let log = self.log(pc, basic, pass);
        let (retraction, facts) = self.retraction(pc, pass);
        #[cfg(feature = "keyless")]
        let revocations = &[
            revocations,
            self.attestation_retraction(basic, pass).as_slice(),
        ]
        .concat();
        let key_revocation = self.key_revocation(&pc.body, basic, revocations, pass);
        let mut key = basic.key.clone();
        if matches!(
            key_revocation.value,
            KeyRevocationValue::Revoked | KeyRevocationValue::Unplaceable
        ) {
            key = KeyStage {
                value: if key_revocation.value == KeyRevocationValue::Revoked {
                    KeyValue::Revoked
                } else {
                    KeyValue::Unplaceable
                },
                basis: key_revocation.basis,
                evidence_time: key_revocation.evidence_time.clone(),
                reason: None,
            };
        }
        stages.identity = Some(basic.identity.clone());
        stages.content_hash = Some(basic.content_hash.clone());
        stages.signature = basic.signature.clone();
        stages.registry_receipt = Some(basic.receipt_stage.clone());
        stages.key = Some(key);
        stages.log = Some(log);
        stages.retraction = Some(retraction);
        stages.key_revocation = Some(key_revocation);
        (finish(stages, basic.undated), facts)
    }

    /// §7.7.
    fn log(&self, pc: &ParsedContext<'_>, basic: &Basic, pass: PassAt) -> LogStage {
        let stage = |value| LogStage {
            value,
            tree_size: None,
            checkpoint_time: None,
            witnesses: None,
            basis: None,
            reason: None,
        };
        let Some((inclusion, raw)) = &pc.log_inclusion else {
            return stage(LogValue::Absent);
        };
        let checkpoint = &inclusion.log_checkpoint;
        if !pass.admits(checkpoint.timestamp) {
            return stage(LogValue::Absent);
        }
        let (Some(receipt), Some((_, raw_receipt))) = (&basic.receipt, &pc.receipt) else {
            return stage(LogValue::CannotVerify);
        };
        let body = &pc.body;
        let registry_did = acdp_did::web::authority_to_did_web(&body.origin_registry);
        if checkpoint.registry_did().ok() != Some(registry_did.as_str()) {
            return stage(LogValue::Invalid);
        }
        let Some(raw_checkpoint) = raw.get("log_checkpoint") else {
            return stage(LogValue::Invalid);
        };
        match self.checkpoint_signature(checkpoint, raw_checkpoint, pass) {
            Some(true) => {}
            Some(false) => return stage(LogValue::Invalid),
            None => return stage(LogValue::CannotVerify),
        }
        let leaf = LogLeaf::for_publish(
            body,
            &body.content_hash,
            &receipt.key_fingerprint,
            raw_receipt,
        );
        if leaf
            .and_then(|leaf| inclusion.verify_reconstructed_leaf(&leaf))
            .is_err()
        {
            return stage(LogValue::Invalid);
        }
        LogStage {
            value: LogValue::Included,
            tree_size: Some(checkpoint.tree_size),
            checkpoint_time: Some(fmt_ts(checkpoint.timestamp)),
            witnesses: Some(self.witnesses(checkpoint, pass)),
            basis: Some(self.registry_basis(&registry_did)),
            reason: None,
        }
    }

    /// The checkpoint signature under the registry document chosen for
    /// the pass: `Some(valid)`, or `None` when no document is available.
    pub(crate) fn checkpoint_signature(
        &self,
        checkpoint: &LogCheckpoint,
        raw: &serde_json::Value,
        pass: PassAt,
    ) -> Option<bool> {
        let did = checkpoint.registry_did().ok()?;
        let hash = LogCheckpoint::preimage_hash_of_value(raw).ok()?;
        match self.keys.check(&checkpoint.signature, &hash, did, pass.t()) {
            Ok(c) => Some(c.valid),
            Err(Missing::Malformed) => Some(false),
            Err(Missing::NoEvidence) => None,
        }
    }

    /// Distinct pinned witnesses whose RFC-ACDP-0015 §8 cosignatures over
    /// this checkpoint verify (no skew check offline; as of T, only
    /// cosignatures `witnessed_at` ≤ T count).
    fn witnesses(&self, checkpoint: &LogCheckpoint, pass: PassAt) -> u64 {
        let mut seen = std::collections::BTreeSet::new();
        for c in &self.parsed.checkpoints {
            for (cosig, raw) in &c.cosignatures {
                if !self.pinned.witnesses.contains(&cosig.witness_id)
                    || seen.contains(cosig.witness_id.as_str())
                    || !pass.admits(cosig.witnessed_at)
                    || cosig.cross_check_against_checkpoint(checkpoint).is_err()
                    || cosig.witness_key_did().is_err()
                {
                    continue;
                }
                let Ok(hash) = acdp_types::cosignature::LogCosignature::preimage_hash_of_value(raw)
                else {
                    continue;
                };
                if self
                    .keys
                    .check(&cosig.signature, &hash, &cosig.witness_id, pass.t())
                    .is_ok_and(|k| k.valid)
                {
                    seen.insert(cosig.witness_id.as_str());
                }
            }
        }
        seen.len() as u64
    }

    /// How event `raw` (already parsed as `event`) stands in this pass:
    /// `(signed, authorized, unsigned_registry)`. `signed`: its signature
    /// verifies under its actor's located key. `authorized`: that key is
    /// in `assertionMethod` too (always, for a non-producer actor).
    /// `unsigned_registry`: an unsigned origin-registry event, admissible
    /// only on a verified receipt.
    fn event_status(
        &self,
        body: &Body,
        event: &LifecycleEvent,
        raw: &serde_json::Value,
        pass: PassAt,
    ) -> (bool, bool, bool) {
        let registry_did = acdp_did::web::authority_to_did_web(&body.origin_registry);
        if !event.is_signed() {
            let unsigned_registry =
                event.ctx_id == body.ctx_id && event.actor.as_str() == registry_did;
            return (false, false, unsigned_registry);
        }
        let Ok((event, hash)) = acdp_verify::lifecycle_event_prechecks(
            raw,
            &body.ctx_id,
            &body.agent_id,
            Some(&registry_did),
        ) else {
            return (false, false, false);
        };
        let Some(signature) = &event.signature else {
            return (false, false, false);
        };
        let producer = event.actor == body.agent_id;
        match self
            .keys
            .check(signature, &hash, event.actor.as_str(), pass.t())
        {
            Ok(k) if k.valid => (true, k.in_assertion || !producer, false),
            _ => (false, false, false),
        }
    }

    /// §7.8 with §10.3 event-receipt verification.
    pub(crate) fn retraction(
        &self,
        pc: &ParsedContext<'_>,
        pass: PassAt,
    ) -> (RetractionStage, PassFacts) {
        let body = &pc.body;
        let registry_did = acdp_did::web::authority_to_did_web(&body.origin_registry);
        let n = pc.events.len();

        // §10.3 steps 2–7 and 9, per receipt position. Step 9 (accepted
        // at or after the context's created_at) is per-receipt, so a
        // receipt failing it is absent before step 8 compares pairs.
        let mut accepted: Vec<Option<DateTime<Utc>>> = vec![None; n];
        for (j, (r, raw)) in pc.event_receipts.iter().enumerate() {
            if j >= n {
                continue;
            }
            let (_, raw_event) = &pc.events[j];
            let ok = r
                .check_binding(
                    &body.origin_registry,
                    &body.ctx_id,
                    raw_event,
                    j as u64,
                    body.created_at,
                )
                .is_ok()
                && EventReceipt::preimage_hash_of_value(raw).is_ok_and(|hash| {
                    self.keys
                        .check(&r.signature, &hash, &registry_did, pass.t())
                        .is_ok_and(|k| k.valid)
                });
            if ok {
                accepted[j] = Some(r.accepted_at);
            }
        }
        // Step 8: accepted_at non-decreasing over the receipts that verify
        // and that the pass admits (as of T, those accepted ≤ T).
        let mut last: Option<DateTime<Utc>> = None;
        for a in accepted.iter().flatten().filter(|a| pass.admits(**a)) {
            if last.is_some_and(|l| *a < l) {
                return (
                    RetractionStage {
                        value: RetractionValue::Invalid,
                        events_admitted: None,
                        basis: None,
                        evidence_time: None,
                        reason: None,
                    },
                    PassFacts::default(),
                );
            }
            last = Some(*a);
        }

        let mut facts = PassFacts::default();
        let mut admitted: Vec<Option<Basis>> = Vec::with_capacity(n);
        for (i, (event, raw)) in pc.events.iter().enumerate() {
            let (signed, authorized, unsigned_registry) = self.event_status(body, event, raw, pass);
            let signed_ok = signed && authorized;
            let basis = match (pass, accepted[i]) {
                (PassAt::AsOf(t), Some(a)) => {
                    if event.occurred_at <= t && a > t {
                        facts.backdated = true;
                    }
                    (a <= t && (signed_ok || unsigned_registry)).then_some(Basis::Registry)
                }
                (PassAt::AsOf(t), None) => {
                    (!self.require_attested_events && signed_ok && event.occurred_at <= t)
                        .then_some(Basis::Observed)
                }
                // §7.8 item 1: a verified receipt also admits a producer
                // key that is only in verificationMethod (receipt-attested
                // historical key, by analogy with RFC-ACDP-0010 §10).
                (PassAt::Latest, Some(_)) => {
                    (signed || unsigned_registry).then_some(Basis::Registry)
                }
                (PassAt::Latest, None) => signed_ok.then_some(Basis::Observed),
            };
            admitted.push(basis);
        }
        let prefix = admitted.iter().take_while(|b| b.is_some()).count();
        if matches!(pass, PassAt::AsOf(_)) && admitted[prefix..].iter().any(Option::is_some) {
            return (
                RetractionStage {
                    value: RetractionValue::Unknown,
                    events_admitted: Some(prefix as u64),
                    basis: None,
                    evidence_time: None,
                    reason: None,
                },
                facts,
            );
        }
        let events: Vec<LifecycleEvent> =
            pc.events[..prefix].iter().map(|(e, _)| e.clone()).collect();
        let value = if retraction_state(&events) {
            RetractionValue::Retracted
        } else {
            RetractionValue::NotRetracted
        };
        (
            RetractionStage {
                value,
                events_admitted: Some(prefix as u64),
                basis: admitted[..prefix].iter().flatten().max().copied(),
                // §7.8 item 2: the last admitted event's verified
                // accepted_at, if it has one.
                evidence_time: prefix
                    .checked_sub(1)
                    .and_then(|last| accepted[last])
                    .map(fmt_ts),
                reason: None,
            },
            facts,
        )
    }

    /// RFC-ACDP-0020 §5.3: whether the events this pass admits withdraw
    /// the body by the producer's own signed `retracted` event. Only
    /// producer-actor events that verify count; a registry-actor
    /// retraction never withdraws a trust list.
    pub(crate) fn producer_retracted(&self, pc: &ParsedContext<'_>, pass: PassAt) -> bool {
        let (stage, _) = self.retraction(pc, pass);
        let Some(n) = stage.events_admitted else {
            return false;
        };
        let body = &pc.body;
        let events: Vec<LifecycleEvent> = pc.events[..n as usize]
            .iter()
            .filter(|(e, raw)| {
                e.actor == body.agent_id && {
                    let (signed, authorized, _) = self.event_status(body, e, raw, pass);
                    signed && authorized
                }
            })
            .map(|(e, _)| e.clone())
            .collect();
        retraction_state(&events)
    }

    /// §7.9: RFC-ACDP-0014 §7–§8 over what the pass admits.
    fn key_revocation(
        &self,
        body: &Body,
        basic: &Basic,
        revocations: &[AppliedRevocation],
        pass: PassAt,
    ) -> KeyRevocationStage {
        let stage = |value| KeyRevocationStage {
            value,
            revocation_ctx_id: None,
            basis: None,
            evidence_time: None,
            reason: None,
        };
        let producer = body.agent_id.as_str();
        // §7.9 scope. A registry-attested revocation must come from the
        // node's origin registry or the registry that receipted it
        // (RFC-ACDP-0014 §6); a verified receipt here is always minted by
        // `did:web:<origin_registry>` (§7.5), so the two coincide.
        let node_registry = acdp_did::web::authority_to_did_web(&body.origin_registry);
        let in_scope: Vec<&AppliedRevocation> = revocations
            .iter()
            .filter(|a| {
                let r = &a.revocation;
                r.revoked_key_controller.as_str() == producer
                    && match r.trust_class {
                        RevocationTrustClass::ProducerSigned => r.publisher.as_str() == producer,
                        RevocationTrustClass::RegistryAttested => {
                            r.publisher.as_str() == node_registry
                        }
                    }
            })
            .collect();

        let fingerprint_of = || {
            basic
                .fingerprint
                .as_deref()
                .or(basic.receipt.as_ref().map(|r| r.key_fingerprint.as_str()))
        };
        // An unevaluated keyless-signed revocation naming this key.
        let pending = fingerprint_of().and_then(|fp| {
            in_scope
                .iter()
                .filter(|a| a.unevaluated && a.revocation.revokes(fp))
                .map(|a| a.ctx_id.clone())
                .min()
        });
        let in_scope: Vec<&AppliedRevocation> =
            in_scope.into_iter().filter(|a| !a.unevaluated).collect();
        let unknown_pending = |ctx_id: String| KeyRevocationStage {
            revocation_ctx_id: Some(ctx_id),
            ..stage(KeyRevocationValue::Unknown)
        };

        if !in_scope.is_empty() {
            let fingerprint = basic
                .fingerprint
                .as_deref()
                .or(basic.receipt.as_ref().map(|r| r.key_fingerprint.as_str()));
            let Some(fp) = fingerprint else {
                return stage(KeyRevocationValue::Unknown);
            };
            // RFC-ACDP-0014 §7: the earliest boundary decides; a
            // producer-signed revocation outranks a registry-attested one
            // at the same boundary.
            let fixing = in_scope
                .iter()
                .filter(|a| a.revocation.revokes(fp))
                .min_by(|a, b| {
                    let rank = |x: &AppliedRevocation| {
                        (
                            x.revocation.compromised_since,
                            x.revocation.trust_class != RevocationTrustClass::ProducerSigned,
                            x.ctx_id.clone(),
                        )
                    };
                    rank(a).cmp(&rank(b))
                });
            if let Some(fixing) = fixing {
                let value = match &basic.receipt {
                    None => KeyRevocationValue::Unplaceable,
                    Some(r) if r.key_status == KeyStatus::Historical => {
                        KeyRevocationValue::Unplaceable
                    }
                    Some(r) if r.created_at < fixing.revocation.compromised_since => {
                        KeyRevocationValue::PreCompromise
                    }
                    Some(_) => KeyRevocationValue::Revoked,
                };
                if value == KeyRevocationValue::PreCompromise {
                    if let Some(ctx_id) = pending {
                        return unknown_pending(ctx_id);
                    }
                }
                return KeyRevocationStage {
                    value,
                    revocation_ctx_id: Some(fixing.ctx_id.clone()),
                    basis: Some(Basis::Registry),
                    evidence_time: fixing.evidence_time.map(fmt_ts),
                    reason: None,
                };
            }
            // Revocations that name other keys prove nothing about this
            // one: the bundle is untrusted and may omit the revoking
            // context. Only discovery decides not-revoked (§7.9).
        }

        if let Some(ctx_id) = pending {
            return unknown_pending(ctx_id);
        }

        let records = || self.parsed.discovery.get(producer).into_iter().flatten();
        // §7.9: a vantage saw a revocation the bundle does not carry.
        if records().any(|d| d.outcome == DiscoveryOutcome::Revoked && pass.admits(d.completed_at))
        {
            return stage(KeyRevocationValue::Unknown);
        }
        let deciding = records()
            .enumerate()
            .filter(|(_, d)| {
                d.outcome == DiscoveryOutcome::NotRevokedComplete && pass.admits(d.completed_at)
            })
            .max_by_key(|(i, d)| (self.vantage_pinned(d.vantage), d.completed_at, *i));
        match deciding {
            Some((_, d)) => KeyRevocationStage {
                basis: Some(if self.vantage_pinned(d.vantage) {
                    Basis::Pinned
                } else {
                    Basis::Observed
                }),
                evidence_time: Some(fmt_ts(d.completed_at)),
                ..stage(KeyRevocationValue::NotRevoked)
            },
            None => stage(KeyRevocationValue::Unknown),
        }
    }

    fn vantage_pinned(&self, vantage: &str) -> bool {
        self.pinned.vantages.iter().any(|v| v == vantage)
    }

    /// The pass object for a node with no body to evaluate (missing, or
    /// on a cycle).
    pub(crate) fn bare(value: PresenceValue) -> Pass {
        finish(
            Stages {
                presence: Presence {
                    value,
                    evidence_time: None,
                    basis: None,
                },
                ..Stages::default()
            },
            false,
        )
    }

    /// The latest-pass `accepted_at` of every event receipt that passes
    /// §10.3 on its own (every step but the cross-receipt step 8), for
    /// the horizon (§5.4).
    pub(crate) fn verified_event_times(&self, pc: &ParsedContext<'_>) -> Vec<DateTime<Utc>> {
        let body = &pc.body;
        let registry_did = acdp_did::web::authority_to_did_web(&body.origin_registry);
        pc.event_receipts
            .iter()
            .enumerate()
            .filter(|(j, (r, raw))| {
                let Some((_, raw_event)) = pc.events.get(*j) else {
                    return false;
                };
                r.check_binding(
                    &body.origin_registry,
                    &body.ctx_id,
                    raw_event,
                    *j as u64,
                    body.created_at,
                )
                .is_ok()
                    && EventReceipt::preimage_hash_of_value(raw).is_ok_and(|hash| {
                        self.keys
                            .check(&r.signature, &hash, &registry_did, None)
                            .is_ok_and(|k| k.valid)
                    })
            })
            .map(|(_, (r, _))| r.accepted_at)
            .collect()
    }
}

/// §8.1: the verdict and caveats of a pass from its stages.
fn finish(stages: Stages, undated: bool) -> Pass {
    let s = &stages;
    let refused = matches!(
        s.presence.value,
        PresenceValue::Cycle | PresenceValue::NotYetPublished
    ) || s
        .identity
        .as_ref()
        .is_some_and(|x| x.value == IdentityValue::Mismatch)
        || s.content_hash
            .as_ref()
            .is_some_and(|x| x.value == ContentHashValue::Mismatch)
        || s.signature.as_ref().is_some_and(|x| {
            matches!(
                x.value,
                SignatureValue::Invalid | SignatureValue::Unresolvable
            )
        })
        || s.key.as_ref().is_some_and(|x| {
            matches!(
                x.value,
                KeyValue::Revoked | KeyValue::Unplaceable | KeyValue::Unresolvable
            )
        })
        || s.key_revocation.as_ref().is_some_and(|x| {
            matches!(
                x.value,
                KeyRevocationValue::Revoked | KeyRevocationValue::Unplaceable
            )
        });
    let unknown = matches!(
        s.presence.value,
        PresenceValue::Withheld | PresenceValue::Unresolved | PresenceValue::Absent
    ) || s.key.as_ref().is_some_and(|x| x.value == KeyValue::Unknown)
        || s.key_revocation
            .as_ref()
            .is_some_and(|x| x.value == KeyRevocationValue::Unknown)
        || s.retraction.as_ref().is_some_and(|x| {
            matches!(x.value, RetractionValue::Unknown | RetractionValue::Invalid)
        })
        || s.registry_receipt
            .as_ref()
            .is_some_and(|x| x.value == ReceiptValue::Invalid)
        || s.log.as_ref().is_some_and(|x| x.value == LogValue::Invalid);

    let mut caveats = Vec::new();
    if undated {
        caveats.push(Caveat::Undated);
    }
    if s.identity
        .as_ref()
        .is_some_and(|x| x.value == IdentityValue::Unbound)
    {
        caveats.push(Caveat::IdentityUnbound);
    }
    if s.key
        .as_ref()
        .is_some_and(|x| x.value == KeyValue::HistoricalReceiptAttested)
    {
        caveats.push(Caveat::HistoricalKey);
    }
    if s.key_revocation
        .as_ref()
        .is_some_and(|x| x.value == KeyRevocationValue::PreCompromise)
    {
        caveats.push(Caveat::PreCompromise);
    }
    if s.registry_receipt
        .as_ref()
        .is_some_and(|x| x.key_status == Some(KeyStatus::Historical))
    {
        caveats.push(Caveat::HistoricalReceiptKey);
    }
    if s.retraction
        .as_ref()
        .is_some_and(|x| x.value == RetractionValue::Retracted)
    {
        caveats.push(Caveat::Retracted);
    }
    if s.log
        .as_ref()
        .is_some_and(|x| x.value == LogValue::CannotVerify)
    {
        caveats.push(Caveat::LogCannotVerify);
    }
    let bases = [
        s.presence.basis,
        s.identity.as_ref().and_then(|x| x.basis),
        s.signature.as_ref().and_then(|x| x.basis),
        s.registry_receipt.as_ref().and_then(|x| x.basis),
        s.key.as_ref().and_then(|x| x.basis),
        s.log.as_ref().and_then(|x| x.basis),
        s.retraction.as_ref().and_then(|x| x.basis),
        s.key_revocation.as_ref().and_then(|x| x.basis),
    ];
    if bases.contains(&Some(Basis::Observed)) {
        caveats.push(Caveat::ObservedBasis);
    }
    caveats.sort();

    let verdict = if refused {
        Verdict::Refused
    } else if unknown {
        Verdict::Unknown
    } else if !caveats.is_empty() {
        Verdict::OkWithCaveats
    } else {
        Verdict::Ok
    };
    Pass {
        verdict,
        caveats,
        stages,
    }
}

/// §7.6: the `signature` and `key` stages for a key that could not be
/// located. One that cannot resolve whatever the evidence is
/// unresolvable in both passes, and so is the signature; missing
/// evidence is `unknown` in the as-of pass, with the signature omitted.
fn missing_stages(m: Missing, pass: PassAt) -> (Option<SignatureStage>, KeyStage) {
    let unresolvable = || {
        (
            Some(SignatureStage {
                value: SignatureValue::Unresolvable,
                basis: None,
            }),
            KeyStage {
                value: KeyValue::Unresolvable,
                basis: None,
                evidence_time: None,
                reason: None,
            },
        )
    };
    match (m, pass) {
        (Missing::NoEvidence, PassAt::AsOf(_)) => (
            None,
            KeyStage {
                value: KeyValue::Unknown,
                basis: None,
                evidence_time: None,
                reason: pass.no_evidence_reason(),
            },
        ),
        _ => unresolvable(),
    }
}
