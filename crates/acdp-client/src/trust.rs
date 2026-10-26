//! Registry trust lists online (RFC-ACDP-0020, 0.5.0 Draft): the
//! consumer profile `acdp-consumer-trust-list` over [`VerifiedContext`].
//!
//! [`TrustLists`] holds the consumer's issuer pins, every list version
//! that passed §5.2, and the per-pin floors to persist (§5.3). Feed it
//! verified list bodies — fetched with [`VerifiedContext::fetch`] (whose
//! policy enforces RFC-ACDP-0014 revocation for the issuer key) or
//! carried out of band — then evaluate verified bodies against it.
//!
//! ```no_run
//! # async fn demo(client: &acdp_client::RegistryClient, resolver: &acdp_did::WebResolver,
//! #     list_ctx: &acdp_types::primitives::CtxId, body_ctx: &acdp_types::primitives::CtxId)
//! # -> Result<(), Box<dyn std::error::Error>> {
//! use acdp_client::trust::TrustLists;
//! use acdp_client::VerifiedContext;
//! use acdp_types::trust_list::IssuerPin;
//!
//! let mut lists = TrustLists::new(vec![IssuerPin::new(
//!     "did:web:security.acme.example",
//!     "tenant-acme.production",
//! )]); // .with_floors(persisted)
//! let list = VerifiedContext::fetch(client, resolver, list_ctx).await?;
//! lists.add_verified(&list, resolver).await?;
//! let body = VerifiedContext::fetch(client, resolver, body_ctx).await?;
//! let node = lists.evaluate(&body, chrono::Utc::now(), None);
//! if !node.is_trusted() { /* refuse: §6.2, only `trusted` permits reliance */ }
//! // persist lists.floors()
//! # Ok(()) }
//! ```
//!
//! Selection here is the latest pass. Lists carried in an RFC-ACDP-0017
//! bundle, with as-of DID documents and admitted retractions, go through
//! `acdp_chain::verify_chain_with_trust` instead.

use std::collections::BTreeMap;

use acdp_did::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_types::lifecycle::retraction_state;
use acdp_types::trust_list::{
    advance_floor, evaluate, select_version, validate_list_version, IssuerPin, ListRejected,
    ListVersion, NodeTrust, PinState, ReceiptInput, TrustPass, TrustReport, TrustSubject,
    VerifiedListBody,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::revocation_verdict::RevocationVerdict;
use crate::VerifiedContext;

/// A pin's series key: (`issuer`, `list_id`).
pub type Series = (String, String);

/// The consumer's trust-list state: pins, held versions, floors.
#[derive(Debug, Clone, Default)]
pub struct TrustLists {
    pins: Vec<IssuerPin>,
    floors: BTreeMap<Series, u64>,
    versions: Vec<Vec<ListVersion>>,
    refuse_unknown_issuer_revocation: bool,
}

fn series(pin: &IssuerPin) -> Series {
    (pin.issuer.clone(), pin.list_id.clone())
}

fn rejected(step: u8, e: AcdpError) -> ListRejected {
    ListRejected {
        step,
        reason: e.to_string(),
    }
}

impl TrustLists {
    /// Trust lists for `pins` (§5.1: from configuration only).
    pub fn new(pins: Vec<IssuerPin>) -> Self {
        let versions = vec![Vec::new(); pins.len()];
        Self {
            pins,
            floors: BTreeMap::new(),
            versions,
            refuse_unknown_issuer_revocation: false,
        }
    }

    /// Local policy: also refuse, in [`Self::add_verified`], a list whose
    /// issuer-key revocation status is unknown (an `Unknown` verdict, or no
    /// complete RFC-ACDP-0014 discovery). RFC-ACDP-0020 §5.2 step 5 refuses only
    /// on an applied revocation and allows this as local policy.
    pub fn refuse_unknown_issuer_revocation(mut self, refuse: bool) -> Self {
        self.refuse_unknown_issuer_revocation = refuse;
        self
    }

    /// Restore the floors persisted by an earlier run (§5.3).
    pub fn with_floors(mut self, floors: BTreeMap<Series, u64>) -> Self {
        self.floors = floors;
        self
    }

    /// The pins.
    pub fn pins(&self) -> &[IssuerPin] {
        &self.pins
    }

    /// The floors to persist (§5.3): per pin, the highest serial among
    /// the valid versions held, retracted ones included. Never decreases.
    pub fn floors(&self) -> &BTreeMap<Series, u64> {
        &self.floors
    }

    /// Hold the version `check` validates for each pin, and advance
    /// those pins' floors. Returns how many pins accepted it.
    fn hold(
        &mut self,
        mut check: impl FnMut(&IssuerPin) -> Result<ListVersion, ListRejected>,
    ) -> Result<usize, ListRejected> {
        let mut accepted = 0;
        let mut first_err = None;
        for (pin, held) in self.pins.iter().zip(self.versions.iter_mut()) {
            match check(pin) {
                Ok(v) => {
                    accepted += 1;
                    let key = series(pin);
                    if let Some(f) = advance_floor(self.floors.get(&key).copied(), [&v]) {
                        self.floors.insert(key, f);
                    }
                    // A refetch of the same copy replaces the old one, so
                    // a later retraction is seen.
                    held.retain(|h| (&h.content_hash, &h.ctx_id) != (&v.content_hash, &v.ctx_id));
                    held.push(v);
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        match (accepted, first_err) {
            (0, Some(e)) => Err(e),
            (0, None) => Err(ListRejected {
                step: 2,
                reason: "no pins are configured".into(),
            }),
            (n, _) => Ok(n),
        }
    }

    /// Hold a list version retrieved and verified by
    /// [`VerifiedContext::fetch`] (§5.2 step 1, with RFC-ACDP-0014
    /// revocation per the fetch policy).
    ///
    /// Retractions (§5.3) are read from the retrieved
    /// `registry_state.lifecycle_events`: only events whose actor is the
    /// issuer and that verify under the issuer's key count. A
    /// registry-actor retraction never withdraws a list.
    pub async fn add_verified(
        &mut self,
        list: &VerifiedContext,
        resolver: &WebResolver,
    ) -> Result<usize, ListRejected> {
        let body = list.body();
        let fingerprint = acdp_crypto::fingerprint::fingerprint_for_key_id(
            &body.signature.key_id,
            &body.signature.algorithm,
            resolver,
        )
        .await
        .map_err(|e| rejected(1, e))?;
        let mut issuer_events = Vec::new();
        for e in list.registry_state().lifecycle_events.iter().flatten() {
            if e.actor != body.agent_id {
                continue;
            }
            let Ok(raw) = serde_json::to_value(e) else {
                continue;
            };
            if let Ok(ev) = acdp_verify::verify_lifecycle_event(
                &raw,
                &body.ctx_id,
                &body.agent_id,
                None,
                resolver,
            )
            .await
            {
                issuer_events.push(ev);
            }
        }
        // §5.2 step 5: only an applied revocation refuses; an incomplete
        // discovery (unknown) refuses only under local policy.
        let verdict = list.revocation_verdict();
        let unknown = matches!(
            verdict,
            RevocationVerdict::Unknown { .. }
                | RevocationVerdict::NotRevoked {
                    complete: false,
                    ..
                }
        );
        let revoked = verdict.is_refusal() || (self.refuse_unknown_issuer_revocation && unknown);
        let ty = context_type(&body.context_type);
        let candidate = VerifiedListBody {
            agent_id: body.agent_id.as_str(),
            context_type: &ty,
            metadata: body.metadata.as_ref(),
            content_hash: body.content_hash.as_str(),
            ctx_id: Some(body.ctx_id.as_str()),
            issuer_key_fingerprint: Some(&fingerprint),
            issuer_key_revoked: revoked,
            retracted: retraction_state(&issuer_events),
        };
        self.hold(|pin| validate_list_version(pin, &candidate))
    }

    /// Hold a `did:key`-issued list carried out of band (§7): a retrieved
    /// body or its signed publish-request form, with any issuer-signed
    /// lifecycle events. `issuer_key_revoked` is the caller's
    /// RFC-ACDP-0014 §7 verdict for the issuer key.
    pub fn add_offline(
        &mut self,
        raw: &Value,
        retractions: &[Value],
        issuer_key_revoked: bool,
    ) -> Result<usize, ListRejected> {
        self.hold(|pin| {
            acdp_verify::trust::verify_list_offline(raw, pin, retractions, issuer_key_revoked)
        })
    }

    /// §5.4 latest-pass state of every pin at `t`, against the floors.
    pub fn select(&self, t: DateTime<Utc>) -> Vec<PinState> {
        self.pins
            .iter()
            .zip(&self.versions)
            .map(|(pin, held)| {
                select_version(
                    pin,
                    held,
                    t,
                    TrustPass::Latest,
                    self.floors.get(&series(pin)).copied(),
                )
            })
            .collect()
    }

    /// §6.2 for one verified body at `t`. The receipt input is the
    /// verified receipt's registry key (never its `key_fingerprint`);
    /// `capabilities` is C, the profiles the body's registry advertises,
    /// when the consumer fetched them.
    pub fn evaluate(
        &self,
        body: &VerifiedContext,
        t: DateTime<Utc>,
        capabilities: Option<&[String]>,
    ) -> NodeTrust {
        evaluate_against(&self.select(t), body, t, capabilities)
    }

    /// The §8 latest-pass report over `bodies` at `t`. `capabilities`
    /// maps a lowercase registry origin to its advertised profiles.
    pub fn report(
        &self,
        bodies: &[&VerifiedContext],
        t: DateTime<Utc>,
        capabilities: &BTreeMap<String, Vec<String>>,
    ) -> TrustReport {
        let states = self.select(t);
        let nodes = bodies
            .iter()
            .map(|b| {
                let caps = capabilities
                    .get(&b.body().origin_registry.to_ascii_lowercase())
                    .map(Vec::as_slice);
                evaluate_against(&states, b, t, caps)
            })
            .collect();
        TrustReport::new(TrustPass::Latest, t, &states, nodes, None, None)
    }
}

fn context_type(t: &acdp_types::primitives::ContextType) -> String {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn evaluate_against(
    states: &[PinState],
    b: &VerifiedContext,
    t: DateTime<Utc>,
    capabilities: Option<&[String]>,
) -> NodeTrust {
    let body = b.body();
    let receipt = b.verified_receipt().and_then(|r| {
        Some(ReceiptInput {
            registry_did: r.registry_did.clone(),
            registry_key_fingerprint: b.receipt_registry_key_fingerprint()?.to_string(),
        })
    });
    let ty = context_type(&body.context_type);
    evaluate(
        &TrustSubject::of(body, &ty),
        states,
        t,
        receipt.as_ref(),
        capabilities,
    )
}
