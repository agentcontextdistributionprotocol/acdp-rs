//! Keyless-signed bodies, consumer side (RFC-ACDP-0021 §8, §11; 0.5.0
//! Draft).
//!
//! [`KeylessPolicy`] says which registries this consumer accepts as
//! attesters (§11). It exists in every build so that
//! [`VerificationPolicy`](crate::VerificationPolicy) has one shape; the
//! default accepts none, and without the `keyless` feature it is not
//! consulted at all: a keyless key id then fails closed in
//! [`VerifiedContext::fetch`](crate::VerifiedContext::fetch) like any key
//! the DID document does not list.
//!
//! With the `keyless` feature, `VerifiedContext` runs §8.1 in place of
//! RFC-ACDP-0001 §5.11 for a keyless key id, in this order (the first
//! failure decides, and its reason token rides on the error, see
//! [`KeylessReason::of`](acdp_types::keyless::KeylessReason::of)):
//!
//! 1. the attestation, fetched from the serving registry by
//!    `key_attestation.ctx_id`, matches `key_attestation.content_hash`,
//!    is signed under its registry's DID, carries a valid receipt and
//!    meets §5.3 (`attestation_invalid`);
//! 2. the attesting registry is accepted (`untrusted_attester`);
//! 3. `agent_id`, `key_id` and `algorithm` match it
//!    (`attestation_mismatch`);
//! 4. the body's receipt verifies, comes from the attester and names the
//!    attested fingerprint (`unplaceable`) — the receipt is required
//!    whatever [`ReceiptPolicy`](crate::ReceiptPolicy) says, because it
//!    is the only time that places a keyless signature;
//! 5. its `created_at` lies in the window (`outside_attestation_window`);
//! 6. the signature verifies under the attested key
//!    (`invalid_signature`);
//! 7. the attestation is not retracted (`attestation_withdrawn`);
//! 8. RFC-ACDP-0014 revocations of the attested fingerprint, gathered by
//!    `agent_id` under [`RevocationPolicy`](crate::RevocationPolicy)
//!    (`revoked`, or pre-compromise);
//! 9. the controller's current DID document lists the identity
//!    (currently authorized), does not (historically authorized), or
//!    cannot be fetched (`controller_unreachable`, transient).
//!
//! The outcome is one of the three existing
//! [`KeyAuthorization`](crate::KeyAuthorization) values or an error.
//!
//! **Keyless-signed revocations (§9.3).** Revocation discovery sets a
//! candidate signed by a keyless key aside and verifies its signer by
//! §8.1 steps 1–7 under this same [`KeylessPolicy`]. One under an
//! `org_wide` attestation is producer-signed and applies; one under a
//! non-org-wide attestation is only a hint (`kl-005` G). One that cannot
//! be evaluated (no `keyless` feature, an unaccepted attester, an
//! attestation that does not verify) makes the verdict for the key it
//! names `unknown`, never not-revoked.

use acdp_types::trust_list::PinState;
use chrono::{DateTime, Utc};

/// Which registries a consumer accepts as keyless attesters (§11).
///
/// A registry is accepted when its DID is in [`Self::attesters`], or when
/// [`Self::trust_lists`] is set and the keyless-signed body evaluates
/// `trusted` (RFC-ACDP-0020 §6.2) with the attesting registry as its
/// receipting registry. The default accepts none, so every keyless-signed
/// body is refused with `untrusted_attester` (`kl-006` A).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeylessPolicy {
    /// Attesting registries' `did:web` DIDs, compared byte for byte.
    pub attesters: Vec<String>,
    /// RFC-ACDP-0020 trust-list acceptance.
    pub trust_lists: Option<KeylessTrust>,
}

impl KeylessPolicy {
    /// Accept the registries `attesters` (their `did:web` DIDs).
    pub fn attesters<I, S>(attesters: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            attesters: attesters.into_iter().map(Into::into).collect(),
            trust_lists: None,
        }
    }

    /// Also accept a registry for a body the trust lists `trust` trust.
    pub fn with_trust_lists(mut self, trust: KeylessTrust) -> Self {
        self.trust_lists = Some(trust);
        self
    }
}

/// The RFC-ACDP-0020 inputs for §11 trust-list acceptance: the pins'
/// §5.4 state at `t` (from [`TrustLists::select`](crate::trust::TrustLists::select))
/// and, when fetched, the attesting registry's advertised profiles (C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeylessTrust {
    /// The pin states at `t`.
    pub pins: Vec<PinState>,
    /// The evaluation time.
    pub t: DateTime<Utc>,
    /// The attesting registry's capabilities `profiles`, if fetched.
    pub capabilities: Option<Vec<String>>,
}

impl KeylessTrust {
    /// The state of `lists` at `t`.
    pub fn at(
        lists: &crate::trust::TrustLists,
        t: DateTime<Utc>,
        capabilities: Option<Vec<String>>,
    ) -> Self {
        Self {
            pins: lists.select(t),
            t,
            capabilities,
        }
    }
}

#[cfg(feature = "keyless")]
pub(crate) use verify::{verify, verify_revocation_signer};

/// RFC-ACDP-0021 §6.2, §12: a `key_attestation` on a body whose key id is
/// not a keyless key id fails closed with `attestation_mismatch`.
#[cfg(feature = "keyless")]
pub(crate) fn check_presence(
    body: &acdp_types::body::Body,
) -> Result<(), acdp_primitives::error::AcdpError> {
    if !acdp_types::keyless::is_keyless_key_id(&body.signature.key_id)
        && body
            .extensions
            .contains_key(acdp_types::keyless::KEY_ATTESTATION_FIELD)
    {
        return Err(
            acdp_types::keyless::KeylessReason::AttestationMismatch.error(format!(
            "the body carries key_attestation but signature.key_id '{}' is not a keyless key id",
            body.signature.key_id
        )),
        );
    }
    Ok(())
}

/// A keyless-signed revocation candidate that could not be evaluated: no
/// `keyless` feature, an unaccepted attester, or an attestation that does
/// not verify. Naming the signing key it makes the verdict `unknown`
/// (RFC-ACDP-0014 §7: unknown outranks not-revoked and pre-compromise).
#[derive(Debug, Clone)]
pub(crate) struct Unevaluated {
    pub fingerprint: String,
    pub detail: String,
}

/// What became of the keyless-signed candidates discovery set aside.
#[derive(Debug, Default)]
pub(crate) struct KeylessRevocations {
    /// Signed under an `org_wide` attestation: producer-signed, applied
    /// (§9.3).
    pub applied: Vec<acdp_types::revocation::KeyRevocation>,
    /// Signed under a non-org-wide attestation: reported, never applied
    /// (`kl-005` G).
    pub hints: Vec<acdp_types::revocation::KeyRevocation>,
    pub unevaluated: Vec<Unevaluated>,
}

/// Evaluate keyless-signed revocation candidates for `agent_id`
/// (RFC-ACDP-0021 §9.3). A candidate whose own shape is invalid, that
/// does not speak for `agent_id`, or that revokes its own signing key is
/// dropped, as for any revocation.
pub(crate) async fn evaluate_revocations(
    client: &crate::registry::RegistryClient,
    resolver: &acdp_did::web::WebResolver,
    agent_id: &acdp_types::primitives::AgentDid,
    deferred: &[acdp_types::body::FullContext],
    policy: &KeylessPolicy,
) -> KeylessRevocations {
    use acdp_types::revocation::{KeyRevocation, RevocationTrustClass};
    let mut out = KeylessRevocations::default();
    #[cfg(feature = "keyless")]
    let since = std::time::Instant::now();
    for ctx in deferred {
        let Ok(rev) = KeyRevocation::from_body(&ctx.body) else {
            continue;
        };
        if rev.publisher != *agent_id || rev.trust_class != RevocationTrustClass::ProducerSigned {
            continue;
        }
        #[cfg(feature = "keyless")]
        let outcome = verify_revocation_signer(client, resolver, ctx, policy, since).await;
        #[cfg(not(feature = "keyless"))]
        let outcome: Result<acdp_types::keyless::KeyAttestation, Unsupported> = {
            let _ = (client, resolver, policy);
            Err(Unsupported)
        };
        match outcome {
            Ok(att) => {
                if rev.check_not_self_signed(&att.key_fingerprint).is_err() {
                    continue;
                }
                if att.org_wide {
                    out.applied.push(rev);
                } else {
                    out.hints.push(rev);
                }
            }
            // §9.3: a definitively invalid signer is ignored.
            #[cfg(feature = "keyless")]
            Err(e) if !e.unavailable => {}
            Err(e) => out.unevaluated.push(Unevaluated {
                fingerprint: rev.revoked_key_fingerprint.clone(),
                detail: format!(
                    "the revocation {} of {} is signed by the keyless key {} and could not be \
                     evaluated: {}",
                    ctx.body.ctx_id.as_str(),
                    rev.revoked_key_fingerprint,
                    ctx.body.signature.key_id,
                    signer_failure(&e),
                ),
            }),
        }
    }
    out
}

#[cfg(feature = "keyless")]
fn signer_failure(e: &verify::Step1) -> &acdp_primitives::error::AcdpError {
    &e.error
}

/// Without the `keyless` feature no keyless signer is evaluable.
#[cfg(not(feature = "keyless"))]
struct Unsupported;

#[cfg(not(feature = "keyless"))]
fn signer_failure(_: &Unsupported) -> &'static str {
    "built without the `keyless` feature (RFC-ACDP-0021)"
}

#[cfg(feature = "keyless")]
mod verify {
    use super::KeylessPolicy;
    use crate::receipt::{verify_receipt_placed, PlacedReceipt};
    use crate::registry::RegistryClient;
    use crate::verified::{KeyAuthorization, KeyPhases, RevocationPolicy};
    use acdp_did::web::WebResolver;
    use acdp_primitives::error::AcdpError;
    use acdp_types::body::{Body, FullContext};
    use acdp_types::keyless::{
        classify, decide_until_identity, IdentityNow, KeyAttestation, KeyAttestationRef,
        KeylessFacts, KeylessReason, KeylessStatus, ListedIdentities, ReceiptFacts,
    };
    use acdp_types::primitives::CtxId;
    use acdp_types::trust_list::{evaluate, ReceiptInput, TrustOutcome, TrustSubject};
    use acdp_verify::Verifier;
    use std::time::Instant;

    /// A verified attestation (§8.1 step 1).
    struct Attestation {
        metadata: KeyAttestation,
        /// The attesting registry's DID (the attestation's `agent_id`).
        registry: String,
        retracted: bool,
    }

    fn invalid(e: impl std::fmt::Display) -> AcdpError {
        KeylessReason::AttestationInvalid.error(e)
    }

    /// A §8.1 step-1 failure. `unavailable` when the attestation could
    /// not be fetched or checked (not found, or a transient failure):
    /// a revocation signed under it is not evaluable rather than
    /// invalid (§9.3).
    pub(crate) struct Step1 {
        pub(crate) error: Box<AcdpError>,
        pub(crate) unavailable: bool,
    }

    impl Step1 {
        fn invalid(error: AcdpError) -> Self {
            Self {
                error: Box::new(error),
                unavailable: false,
            }
        }

        fn unavailable(error: AcdpError) -> Self {
            Self {
                error: Box::new(error),
                unavailable: true,
            }
        }
    }

    impl From<Step1> for AcdpError {
        fn from(s: Step1) -> Self {
            *s.error
        }
    }

    /// §8.1 step 1. Transient failures propagate unchanged (retry later);
    /// every other failure is `attestation_invalid`.
    async fn attestation(
        client: &RegistryClient,
        resolver: &WebResolver,
        reference: &KeyAttestationRef,
        serving_authority: &str,
        since: Instant,
    ) -> Result<Attestation, Step1> {
        // §6.3 step 2: a registry accepts only attestations it minted, so
        // the attestation of a body it serves is its own.
        if reference.ctx_id.authority() != serving_authority {
            return Err(Step1::invalid(invalid(format!(
                "key_attestation.ctx_id '{}' is not on the serving registry '{serving_authority}'",
                reference.ctx_id
            ))));
        }
        let ctx = match client.retrieve(&reference.ctx_id).await {
            Ok(ctx) => ctx,
            Err(e) if e.is_transient() => return Err(Step1::unavailable(e)),
            Err(e) => {
                return Err(Step1::unavailable(invalid(format!(
                    "fetching the attestation: {e}"
                ))))
            }
        };
        let metadata = check_attestation(resolver, &ctx, reference, serving_authority, since)
            .await
            .map_err(|mut s| {
                // Transient failures propagate unchanged (retry later).
                if s.error.is_transient() {
                    s.unavailable = true;
                } else {
                    s.error = Box::new(invalid(&s.error));
                }
                s
            })?;
        Ok(Attestation {
            metadata,
            registry: ctx.body.agent_id.as_str().to_owned(),
            retracted: ctx.registry_state.status.is_retracted(),
        })
    }

    async fn check_attestation(
        resolver: &WebResolver,
        ctx: &FullContext,
        reference: &KeyAttestationRef,
        serving_authority: &str,
        since: Instant,
    ) -> Result<KeyAttestation, Step1> {
        // §9.3 "unavailable versus invalid": evidence that could not be
        // obtained (another context than the one named, no receipt, no
        // attester DID document) is unavailable; obtained evidence that
        // fails a check is invalid.
        acdp_verify::verify_ctx_id_binding(ctx.body.ctx_id.as_str(), reference.ctx_id.as_str())
            .map_err(Step1::unavailable)?;
        acdp_verify::verify_context_hash(ctx).map_err(Step1::invalid)?;
        if ctx.body.content_hash != reference.content_hash {
            return Err(Step1::invalid(AcdpError::HashMismatch {
                stored: reference.content_hash.clone(),
                recomputed: ctx.body.content_hash.clone(),
            }));
        }
        acdp_validation::validate_body(&ctx.body).map_err(Step1::invalid)?;
        let metadata = KeyAttestation::from_body(&ctx.body).map_err(Step1::invalid)?;
        let receipt = ctx.registry_receipt.as_ref().ok_or_else(|| {
            Step1::unavailable(AcdpError::InvalidReceipt(
                "the attestation carries no receipt".into(),
            ))
        })?;
        resolver
            .resolve(ctx.body.agent_id.as_str())
            .await
            .map_err(Step1::unavailable)?;
        let verifier = Verifier::new(resolver).fresh_since(since);
        verifier
            .verify_body_signature(&ctx.body)
            .await
            .map_err(Step1::invalid)?;
        let registry_fp = acdp_crypto::fingerprint::fingerprint_for_key_id_since(
            &ctx.body.signature.key_id,
            &ctx.body.signature.algorithm,
            resolver,
            since,
        )
        .await
        .map_err(Step1::invalid)?;
        verify_receipt_placed(
            receipt,
            &reference.ctx_id,
            &ctx.body,
            &ctx.body.content_hash,
            &registry_fp,
            serving_authority,
            resolver,
            since,
        )
        .await
        .map_err(Step1::invalid)?;
        Ok(metadata)
    }

    /// §11: does the consumer accept `registry` as the attester of `body`?
    fn accepted(
        policy: &KeylessPolicy,
        registry: &str,
        body: &Body,
        placed: Option<&PlacedReceipt>,
    ) -> bool {
        if policy.attesters.iter().any(|a| a == registry) {
            return true;
        }
        let (Some(trust), Some(placed)) = (&policy.trust_lists, placed) else {
            return false;
        };
        if placed.receipt.registry_did != registry {
            return false;
        }
        let ty = serde_json::to_value(&body.context_type)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let receipt = ReceiptInput {
            registry_did: placed.receipt.registry_did.clone(),
            registry_key_fingerprint: placed.registry_key_fingerprint.clone(),
        };
        let node = evaluate(
            &TrustSubject::of(body, &ty),
            &trust.pins,
            trust.t,
            Some(&receipt),
            trust.capabilities.as_deref(),
        );
        node.outcome == TrustOutcome::Trusted
    }

    /// §8.1 step 9 against a document fetched for this verification.
    async fn identity_now(
        resolver: &WebResolver,
        attestation: &KeyAttestation,
        since: Instant,
    ) -> IdentityNow {
        let listed = |doc: &acdp_did::DidDocument| {
            ListedIdentities::of(doc)
                .find(&attestation.identity)
                .is_some()
        };
        match resolver
            .resolve_until(&attestation.controller, since, listed)
            .await
        {
            Ok(r) if listed(&r.document) => IdentityNow::Listed,
            // Absence is final only against a fresh document.
            Ok(r) if r.fresh => IdentityNow::NotListed,
            Ok(_) | Err(_) => IdentityNow::Unreachable,
        }
    }

    fn refusal(reason: KeylessReason, body: &Body, att: &KeyAttestation) -> AcdpError {
        let key_id = &body.signature.key_id;
        let detail = match reason {
            KeylessReason::UntrustedAttester => format!(
                "the attesting registry of '{key_id}' is not an accepted attester \
                 (RFC-ACDP-0021 §11; configure VerificationPolicy.keyless)"
            ),
            KeylessReason::AttestationMismatch => format!(
                "agent_id, key_id or algorithm differ from the attestation of '{}'",
                att.key_id
            ),
            KeylessReason::Unplaceable => "no verified receipt from the attesting registry \
                 names the attested key (RFC-ACDP-0021 §8.1 step 4)"
                .to_string(),
            KeylessReason::OutsideAttestationWindow => format!(
                "the receipt places the signature outside [{}, {})",
                acdp_primitives::time::fmt_rfc3339_ms(att.not_before),
                acdp_primitives::time::fmt_rfc3339_ms(att.not_after)
            ),
            KeylessReason::InvalidSignature => {
                format!("the signature does not verify under the key attested for '{key_id}'")
            }
            KeylessReason::AttestationWithdrawn => {
                "the attesting registry retracted the attestation (RFC-ACDP-0021 §9.2)".to_string()
            }
            KeylessReason::ControllerUnreachable => format!(
                "the DID document of '{}' could not be fetched fresh",
                att.controller
            ),
            other => format!("keyless verification refused: {other}"),
        };
        reason.error(detail)
    }

    /// §8.1 steps 1–7 for a keyless-signed body: the attestation, the
    /// placed receipt, and every fact but the revocations (step 8) and
    /// the current identity (step 9).
    struct Signer {
        att: Attestation,
        placed: Option<Result<PlacedReceipt, AcdpError>>,
        facts: KeylessFacts,
    }

    #[allow(clippy::too_many_arguments)]
    async fn signer(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx: &FullContext,
        expected_ctx_id: &CtxId,
        serving_authority: &str,
        policy: &KeylessPolicy,
        since: Instant,
    ) -> Result<Signer, Step1> {
        let body = &ctx.body;
        // §6.2: a keyless key id with no `key_attestation` fails step 1.
        let reference = body
            .key_attestation()
            .map_err(Step1::invalid)?
            .ok_or_else(|| {
                Step1::invalid(KeylessReason::AttestationInvalid.error(format!(
                    "signature.key_id '{}' is a keyless key id but the body has no \
                     key_attestation",
                    body.signature.key_id
                )))
            })?;

        // Step 1 decides alone: nothing below can be evaluated without it.
        let att = attestation(client, resolver, &reference, serving_authority, since).await?;
        let meta = &att.metadata;

        // Step 4's receipt is verified up front: step 2's trust-list path
        // reads the receipting registry from it. The order of the
        // decisions is still §8.1's (`classify`).
        let placed = match &ctx.registry_receipt {
            None => None,
            Some(value) => Some(
                verify_receipt_placed(
                    value,
                    expected_ctx_id,
                    body,
                    &body.content_hash,
                    &meta.key_fingerprint,
                    serving_authority,
                    resolver,
                    since,
                )
                .await,
            ),
        };
        let placed_ok = placed.as_ref().and_then(|p| p.as_ref().ok());
        let receipt = placed.as_ref().map(|p| match p {
            Ok(p) => ReceiptFacts {
                verified: true,
                registry_is_attester: p.receipt.registry_did == att.registry,
                fingerprint_matches: p.receipt.key_fingerprint == meta.key_fingerprint,
                created_at: p.receipt.created_at,
            },
            Err(_) => ReceiptFacts {
                verified: false,
                registry_is_attester: false,
                fingerprint_matches: false,
                created_at: meta.not_before,
            },
        });
        let facts = KeylessFacts {
            attestation_valid: true,
            attester_accepted: accepted(policy, &att.registry, body, placed_ok),
            bindings_ok: meta.binds(&body.agent_id, &body.signature),
            receipt,
            not_before: meta.not_before,
            not_after: meta.not_after,
            signature_valid: meta
                .public_key_jwk
                .verify(
                    &body.signature.algorithm,
                    &body.signature.value,
                    body.content_hash.as_str(),
                )
                .is_ok(),
            retracted: att.retracted,
            compromised_since: Vec::new(),
        };
        Ok(Signer { att, placed, facts })
    }

    /// §9.3: verify the keyless signer of a key-revocation candidate set
    /// aside by discovery, through §8.1 steps 1–7 under the same attester
    /// policy as bodies. Returns its attestation (the caller applies it
    /// only when `org_wide`); revocations of the signing key and its
    /// identity today are not consulted (no step 8 or 9).
    ///
    /// A failure is `unavailable` (not evaluable: the attester is not
    /// accepted, or the attestation could not be had) or definitively
    /// invalid (ignored, as any revocation whose signature fails).
    pub(crate) async fn verify_revocation_signer(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx: &FullContext,
        policy: &KeylessPolicy,
        since: Instant,
    ) -> Result<KeyAttestation, Step1> {
        let body = &ctx.body;
        acdp_verify::verify_context_hash(ctx).map_err(Step1::invalid)?;
        acdp_validation::validate_body(body).map_err(Step1::invalid)?;
        let serving_authority = client
            .authority()
            .unwrap_or_else(|| body.ctx_id.authority().to_string());
        let s = signer(
            client,
            resolver,
            ctx,
            &body.ctx_id,
            &serving_authority,
            policy,
            since,
        )
        .await?;
        match decide_until_identity(&s.facts) {
            Ok(_) => Ok(s.att.metadata),
            Err(reason) => Err(Step1 {
                error: Box::new(refusal(reason, body, &s.att.metadata)),
                unavailable: reason == KeylessReason::UntrustedAttester,
            }),
        }
    }

    /// RFC-ACDP-0021 §8.1 for a keyless-signed body whose content hash
    /// the caller has already recomputed.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn verify(
        client: &RegistryClient,
        resolver: &WebResolver,
        ctx: &FullContext,
        expected_ctx_id: &CtxId,
        serving_authority: &str,
        policy: &KeylessPolicy,
        revocations: &RevocationPolicy,
        since: Instant,
    ) -> Result<KeyPhases, AcdpError> {
        let body = &ctx.body;
        let Signer {
            att,
            placed,
            mut facts,
        } = signer(
            client,
            resolver,
            ctx,
            expected_ctx_id,
            serving_authority,
            policy,
            since,
        )
        .await
        .map_err(AcdpError::from)?;
        let meta = &att.metadata;
        let placed_ok = placed.as_ref().and_then(|p| p.as_ref().ok());

        // Step 8's input: revocations of the attested fingerprint,
        // discovered by agent_id (§9.3), placed by the receipt.
        let gathered = crate::revocation_verdict::gather(
            client,
            resolver,
            &body.agent_id,
            revocations,
            policy,
        )
        .await;
        let assessment = crate::revocation_verdict::decide(
            gathered,
            Some(&meta.key_fingerprint),
            placed_ok.map(|p| (p.receipt.created_at, p.key_status)),
            revocations.accept_historical_receipt_key_for_pre_t,
        );
        let compromised_since = match &assessment.verdict {
            crate::RevocationVerdict::Revoked { boundary, .. } => vec![*boundary],
            _ => Vec::new(),
        };

        facts.compromised_since = compromised_since;

        // Step 9 only when steps 1–8 leave it to decide.
        let now = match decide_until_identity(&facts) {
            Ok(None) => identity_now(resolver, meta, since).await,
            _ => IdentityNow::Unreachable,
        };
        let status = match classify(&facts, now) {
            Ok(status) => status,
            // The revocation refusal keeps its typed form.
            Err(KeylessReason::Revoked) => {
                return Err(match assessment.enforce() {
                    Err(e) => e,
                    Ok(_) => refusal(KeylessReason::Revoked, body, meta),
                })
            }
            Err(reason) => return Err(refusal(reason, body, meta)),
        };
        // An unfinished discovery fails closed under its policy, and the
        // strict receipt-key profile can still refuse a pre-compromise
        // placement.
        let revocation = assessment.enforce()?;
        let placed = placed_ok.expect("classify accepted only with a verified receipt");
        Ok(KeyPhases {
            key_status: match status {
                KeylessStatus::CurrentlyAuthorized => KeyAuthorization::CurrentlyAuthorized,
                KeylessStatus::HistoricallyAuthorized => KeyAuthorization::HistoricallyAuthorized,
                KeylessStatus::HistoricallyAuthorizedPreCompromise => {
                    KeyAuthorization::HistoricallyAuthorizedPreCompromise
                }
            },
            verified_receipt: Some(placed.receipt.clone()),
            receipt_key_status: Some(placed.key_status),
            receipt_registry_key_fingerprint: Some(placed.registry_key_fingerprint.clone()),
            receipt_verdict: Some(Ok(())),
            revocation,
        })
    }
}
