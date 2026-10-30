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

/// A keyless body's attestation, checked through §8.1 steps 1–3, with
/// the step-6 signature result.
#[derive(Debug, Clone)]
pub(crate) struct Attested {
    /// The attestation's `ctx_id`.
    pub ctx_id: String,
    /// The attesting registry (`agent_id` of the attestation).
    pub attester: String,
    pub attestation: KeyAttestation,
    /// §8.1 step 6: the signature verifies under `public_key_jwk`. A
    /// failure is `signature: invalid` with the key as located (§10).
    pub signature_valid: bool,
}

/// Why a keyless signer did not check through §8.1 steps 1–3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unattested {
    /// The attestation is absent from the bundle or not yet admitted at
    /// T: not evaluable.
    NoEvidence,
    /// Other step-1 evidence could not be obtained: the attestation's
    /// receipt or the attester's DID document, or the bundle carries
    /// another context under the attestation's `ctx_id`. Unresolvable for
    /// the node, but a revocation signed under it is not evaluable
    /// (§9.3 "unavailable").
    Unavailable,
    /// Step 2: the attester is not in `pinned.keyless_attesters`: not
    /// evaluable.
    Unaccepted,
    /// Steps 1 and 3, on evidence that is present: definitively invalid.
    Invalid,
}

impl Unattested {
    /// The §10 key-stage reading: missing evidence, or unresolvable.
    pub(crate) fn missing(self) -> Missing {
        match self {
            Self::NoEvidence => Missing::NoEvidence,
            Self::Unavailable | Self::Unaccepted | Self::Invalid => Missing::Malformed,
        }
    }
}

impl Attested {
    /// What the key-location step reports: the attested key and whether
    /// the signature verified under it.
    pub(crate) fn key_check(&self) -> KeyCheck {
        KeyCheck {
            basis: Basis::Registry,
            evidence_time: None,
            in_assertion: false,
            fingerprint: Some(self.attestation.key_fingerprint.clone()),
            valid: self.signature_valid,
        }
    }
}

impl Engine<'_, '_> {
    /// Whether `body` takes the keyless path: a keyless key id, or a
    /// `key_attestation` member, which on any other key id gives `key`
    /// and `signature` `unresolvable` (§6.2, §10).
    pub(crate) fn is_keyless_node(body: &Body) -> bool {
        acdp_types::keyless::is_keyless_key_id(&body.signature.key_id)
            || body
                .extensions
                .contains_key(acdp_types::keyless::KEY_ATTESTATION_FIELD)
    }

    /// §8.1 steps 1–3 against the bundle, and step 6's signature check.
    pub(crate) fn keyless_attested(
        &self,
        body: &Body,
        pass: PassAt,
    ) -> Result<Attested, Unattested> {
        // §6.2: a keyless key id needs `key_attestation` (step 1), and the
        // member on any other key id is misplaced.
        if !acdp_types::keyless::is_keyless_key_id(&body.signature.key_id) {
            return Err(Unattested::Invalid);
        }
        let reference = body
            .key_attestation()
            .ok()
            .flatten()
            .ok_or(Unattested::Invalid)?;
        let key = reference.ctx_id.as_str();
        let pc = self
            .parsed
            .contexts
            .get(key)
            .ok_or(Unattested::NoEvidence)?;
        // §9.3: a supplied context that is not the named one leaves the
        // named attestation unavailable.
        if pc.body.ctx_id.as_str() != key {
            return Err(Unattested::Unavailable);
        }
        if pc.body.content_hash != reference.content_hash
            || acdp_types::keyless::is_keyless_key_id(&pc.body.signature.key_id)
        {
            return Err(Unattested::Invalid);
        }
        let b = self.basic(key, pc, pass);
        if b.presence.value != PresenceValue::Present {
            return Err(Unattested::NoEvidence);
        }
        if pc.receipt.is_none() || !self.keys.has_snapshot(pc.body.agent_id.as_str(), pass.t()) {
            return Err(Unattested::Unavailable);
        }
        // With the attester's snapshot at hand, a key it no longer lists
        // in `verificationMethod` is its compromise signal, not missing
        // evidence: step 1 fails (§8.1 step 1, `kl-005` N). A key only
        // rotated out of `assertionMethod` is `historical_receipt_attested`
        // through the attestation's receipt and passes (`kl-005` M).
        if b.key.value == KeyValue::Unknown {
            return Err(Unattested::Invalid);
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
            return Err(Unattested::Invalid);
        }
        let attestation = KeyAttestation::from_body(&pc.body).map_err(|_| Unattested::Invalid)?;
        let attester = pc.body.agent_id.as_str().to_string();
        if !self.keyless_attesters.contains(&attester) {
            return Err(Unattested::Unaccepted);
        }
        if !attestation.binds(&body.agent_id, &body.signature) {
            return Err(Unattested::Invalid);
        }
        let signature_valid = attestation
            .public_key_jwk
            .verify(
                &body.signature.algorithm,
                &body.signature.value,
                body.content_hash.as_str(),
            )
            .is_ok();
        Ok(Attested {
            ctx_id: key.to_string(),
            attester,
            attestation,
            signature_valid,
        })
    }

    /// §8.1 steps 4–5: the body's verified receipt is the attester's
    /// and falls in the window.
    pub(crate) fn keyless_placed(
        body: &Body,
        attested: &Attested,
        receipt: Option<&VerifiedReceipt>,
    ) -> bool {
        // A verified receipt is always minted by the body's origin
        // registry (§7.5).
        receipt.is_some_and(|r| {
            acdp_did::web::authority_to_did_web(&body.origin_registry) == attested.attester
                && attested.attestation.window_contains(r.created_at)
        })
    }

    /// The §10 `signature` and `key` stages for a placed keyless node:
    /// step 6 and step 9 against the chosen snapshot. `NoEvidence` when
    /// no controller snapshot is selectable at T.
    pub(crate) fn keyless_stages(
        &self,
        body: &Body,
        attested: &Attested,
        receipt: &VerifiedReceipt,
        pass: PassAt,
    ) -> Result<(Option<SignatureStage>, KeyStage), Missing> {
        if !self.keys.has_snapshot(body.agent_id.as_str(), pass.t()) {
            return Err(Missing::NoEvidence);
        }
        let basis = self.registry_basis(&attested.attester);
        let listed = self
            .keys
            .document(body.agent_id.as_str(), pass.t())
            .filter(|(doc, _, _)| {
                ListedIdentities::of(doc)
                    .find(&attested.attestation.identity)
                    .is_some()
            })
            .is_some();
        // The attester's receipt placed the signature: basis `registry`,
        // `evidence_time` the body receipt's `created_at` (§10).
        let value = if listed {
            KeyValue::Current
        } else {
            KeyValue::HistoricalReceiptAttested
        };
        Ok((
            Some(SignatureStage {
                value: if attested.signature_valid {
                    SignatureValue::Ok
                } else {
                    SignatureValue::Invalid
                },
                basis: Some(basis),
            }),
            KeyStage {
                value,
                basis: Some(basis),
                evidence_time: Some(fmt_ts(receipt.created_at)),
                reason: None,
            },
        ))
    }

    /// RFC-ACDP-0021 §9.3: a key revocation signed by a keyless key,
    /// with its signer evaluated by §8.1 steps 1–7 (no step 8, no step
    /// 9). `None` when it is ignored: definitively invalid, or signed
    /// under a non-org-wide attestation (a hint, never applied).
    pub(crate) fn keyless_revocation(
        &self,
        key: &str,
        pc: &crate::evidence::ParsedContext<'_>,
        b: &Basic,
        pass: PassAt,
    ) -> Option<AppliedRevocation> {
        let revocation = KeyRevocation::from_body(&pc.body).ok()?;
        let entry = |unevaluated| AppliedRevocation {
            ctx_id: key.to_string(),
            revocation: revocation.clone(),
            evidence_time: b.receipt.as_ref().map(|r| r.created_at),
            unevaluated,
        };
        match (&b.keyless, b.keyless_failure) {
            (
                _,
                Some(Unattested::NoEvidence | Unattested::Unavailable | Unattested::Unaccepted),
            ) => Some(entry(true)),
            (Some(a), None) => {
                let withdrawn = self
                    .parsed
                    .contexts
                    .get(a.ctx_id.as_str())
                    .is_some_and(|att| {
                        self.retraction(att, pass).0.value == RetractionValue::Retracted
                    });
                (a.signature_valid
                    && !withdrawn
                    && a.attestation.org_wide
                    && revocation
                        .check_not_self_signed(&a.attestation.key_fingerprint)
                        .is_ok())
                .then(|| entry(false))
            }
            _ => None,
        }
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
