//! Keyless nodes (RFC-ACDP-0021 §10).
//!
//! The attestation is an ordinary context the bundle carries in
//! `contexts`, with its receipt. It is evaluated with the same stages as
//! any node; the keyless body's own receipt then places the signature in
//! the attestation window. `current` vs `historical_receipt_attested`
//! comes from whether the controller's chosen snapshot lists the
//! attested identity. A retracted attestation enters the
//! `key_revocation` stage as a registry-attested revocation with
//! `compromised_since` = `not_before` (§9.2).

use acdp_types::body::Body;
use acdp_types::keyless::{KeyAttestation, ListedIdentities};
use acdp_types::primitives::AgentDid;
use acdp_types::revocation::{KeyRevocation, RevocationTrustClass};

use crate::keys::{KeyCheck, Missing};
use crate::stages::{AppliedRevocation, Basic, Engine, PassAt, VerifiedReceipt};
use crate::syntax::{fmt_ts, parse_ts};
use crate::verdict::*;

/// A keyless body's attestation, checked through §8.1 step 6.
#[derive(Debug, Clone)]
pub(crate) struct Attested {
    /// The attestation's `ctx_id`.
    pub ctx_id: String,
    /// The attesting registry (`agent_id` of the attestation).
    pub attester: String,
    pub attestation: KeyAttestation,
}

impl Attested {
    /// What the key-location step reports: the attested key, whose
    /// signature has verified.
    pub(crate) fn key_check(&self) -> KeyCheck {
        KeyCheck {
            basis: Basis::Registry,
            evidence_time: None,
            in_assertion: false,
            fingerprint: Some(self.attestation.key_fingerprint.clone()),
            valid: true,
        }
    }
}

impl Engine<'_, '_> {
    /// §8.1 steps 1–6 against the bundle. `NoEvidence` when the pass
    /// has no attestation to evaluate; `Malformed` for every other
    /// failure (both give `unresolvable` per §10).
    pub(crate) fn keyless_attested(&self, body: &Body, pass: PassAt) -> Result<Attested, Missing> {
        let reference = body
            .key_attestation()
            .ok()
            .flatten()
            .ok_or(Missing::Malformed)?;
        let key = reference.ctx_id.as_str();
        let pc = self.parsed.contexts.get(key).ok_or(Missing::NoEvidence)?;
        if pc.body.content_hash != reference.content_hash
            || acdp_types::keyless::is_keyless_key_id(&pc.body.signature.key_id)
        {
            return Err(Missing::Malformed);
        }
        let b = self.basic(key, pc, pass);
        if b.presence.value != PresenceValue::Present || b.key.value == KeyValue::Unknown {
            return Err(Missing::NoEvidence);
        }
        let sig_ok = b
            .signature
            .as_ref()
            .is_some_and(|s| s.value == SignatureValue::Ok);
        if b.content_hash.value != ContentHashValue::Ok
            || b.identity.value != IdentityValue::Ok
            || !sig_ok
            || !matches!(
                b.key.value,
                KeyValue::Current | KeyValue::HistoricalReceiptAttested
            )
            || b.receipt.is_none()
        {
            return Err(Missing::Malformed);
        }
        let attestation = KeyAttestation::from_body(&pc.body).map_err(|_| Missing::Malformed)?;
        let attester = pc.body.agent_id.as_str().to_string();
        if !self.keyless_attesters.contains(&attester)
            || !attestation.binds(&body.agent_id, &body.signature)
            || attestation
                .public_key_jwk
                .verify(
                    &body.signature.algorithm,
                    &body.signature.value,
                    body.content_hash.as_str(),
                )
                .is_err()
        {
            return Err(Missing::Malformed);
        }
        Ok(Attested {
            ctx_id: key.to_string(),
            attester,
            attestation,
        })
    }

    /// §8.1 steps 7–9 and the §10 stage values, given the body's
    /// verified receipt.
    pub(crate) fn keyless_stages(
        &self,
        body: &Body,
        attested: &Attested,
        receipt: Option<&VerifiedReceipt>,
        pass: PassAt,
    ) -> (Option<SignatureStage>, KeyStage) {
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
        // A verified receipt is always minted by the body's origin
        // registry (§7.5); it places the key only if that registry is
        // the attester and `created_at` is in the window.
        let Some(r) = receipt else {
            return unresolvable();
        };
        if acdp_did::web::authority_to_did_web(&body.origin_registry) != attested.attester
            || !attested.attestation.window_contains(r.created_at)
        {
            return unresolvable();
        }
        let basis = self.registry_basis(&attested.attester);
        let listed = self
            .keys
            .document(body.agent_id.as_str(), pass.t())
            .filter(|(doc, _, _)| {
                ListedIdentities::of(doc)
                    .find(&attested.attestation.identity)
                    .is_some()
            });
        let (value, evidence_time) = match listed {
            Some((_, _, time)) => (KeyValue::Current, time),
            None => (KeyValue::HistoricalReceiptAttested, r.created_at),
        };
        (
            Some(SignatureStage {
                value: SignatureValue::Ok,
                basis: Some(basis),
            }),
            KeyStage {
                value,
                basis: Some(basis),
                evidence_time: Some(fmt_ts(evidence_time)),
                reason: None,
            },
        )
    }

    /// §9.2: an admitted retraction of the attestation, as the
    /// registry-attested revocation of the attested key it amounts to.
    pub(crate) fn attestation_retraction(
        &self,
        basic: &Basic,
        pass: PassAt,
    ) -> Option<AppliedRevocation> {
        let attested = basic.keyless.as_ref()?;
        let pc = self.parsed.contexts.get(attested.ctx_id.as_str())?;
        let (stage, _) = self.retraction(pc, pass);
        if stage.value != RetractionValue::Retracted {
            return None;
        }
        let a = &attested.attestation;
        Some(AppliedRevocation {
            ctx_id: attested.ctx_id.clone(),
            revocation: KeyRevocation {
                revoked_key_fingerprint: a.key_fingerprint.clone(),
                compromised_since: a.not_before,
                reason: Some("key attestation retracted (RFC-ACDP-0021 §9.2)".into()),
                revoked_key_id: Some(a.key_id.clone()),
                revoked_key_controller: AgentDid::new(&a.controller),
                publisher: AgentDid::new(&attested.attester),
                trust_class: RevocationTrustClass::RegistryAttested,
                ctx_id: None,
            },
            evidence_time: stage.evidence_time.as_deref().and_then(parse_ts),
            unevaluated: false,
        })
    }
}
