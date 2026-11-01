//! Retraction recall, consumer side (ACDP 0.5.0 Draft, RFC-ACDP-0018,
//! profile `acdp-consumer-recall`).
//!
//! - [`Since`] and [`ChangeFeed`] — read a registry's `GET /changes`
//!   tail from a persisted cursor ([`crate::RegistryClient::changes`] is
//!   the single-page call underneath).
//! - [`verify_change`] — the §7 procedure that turns a change entry (a
//!   hint) into a [`ChangeVerdict`]: [`ChangeVerdict::Verified`] with the
//!   [`ChangeEffect`] to apply, or [`ChangeVerdict::Rejected`], which MUST
//!   NOT change any reliance decision.
//! - [`SeenChanges`] — §7 idempotency, by (registry authority, `seq`),
//!   valid only between resyncs.
//!
//! The processing loop a consumer runs:
//!
//! ```no_run
//! # async fn ex(
//! #     client: &acdp_client::RegistryClient,
//! #     resolver: &acdp_did::WebResolver,
//! #     filter: acdp_types::change::WatchFilter,
//! #     persisted: acdp_client::Since,
//! # ) -> Result<(), acdp_primitives::AcdpError> {
//! use acdp_client::recall::{verify_change, ChangeFeed, ChangeVerdict, SeenChanges};
//! use acdp_client::VerificationPolicy;
//!
//! let mut feed = ChangeFeed::new(client, filter).since(persisted);
//! let mut seen = SeenChanges::new();
//! let authority = client.authority().unwrap_or_default();
//! loop {
//!     let page = match feed.fetch().await {
//!         // `cursor_expired`, or `invalid_cursor` on a persisted cursor.
//!         Err(e) if feed.needs_resync(&e) => {
//!             // §7 "Resync": re-verify every watched context directly,
//!             // then start again from the head with fresh dedup state.
//!             feed.resync(&mut seen);
//!             continue;
//!         }
//!         other => other?,
//!     };
//!     for change in &page.changes {
//!         if !seen.is_new(&authority, change.seq()) {
//!             continue;
//!         }
//!         match verify_change(client, resolver, change, None, &VerificationPolicy::default())
//!             .await?
//!         {
//!             ChangeVerdict::Verified(_effect) => { /* re-evaluate reliance */ }
//!             ChangeVerdict::Rejected(_why) => { /* no reliance change; re-verify directly */ }
//!             _ => {}
//!         }
//!         seen.mark(&authority, change.seq());
//!     }
//!     feed.advance(&page); // persist feed.position() here
//!     if !page.has_more {
//!         break;
//!     }
//! }
//! # Ok(()) }
//! ```

use std::collections::BTreeMap;

use acdp_did::web::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_primitives::revocation::{RevocationSource, SourcedRevocation};
use acdp_types::body::Body;
use acdp_types::change::{Change, ChangeEvidence, ChangeHint, ChangesResponse, WatchFilter};
use acdp_types::lifecycle::{retraction_state, LifecycleEvent, LifecycleEventType};
use acdp_types::primitives::CtxId;
use acdp_types::receipt::RegistryReceipt;
use acdp_types::revocation::RevocationTrustClass;
use acdp_types::EventReceipt;
use serde_json::Value;

use crate::receipt::verify_event_receipt_value;
use crate::revocation::verify_revocation_candidate;
use crate::verified::{ReceiptPolicy, VerificationPolicy, VerifiedContext};
use crate::RegistryClient;

// ── Reading the feed ─────────────────────────────────────────────────────────

/// Where a `GET /changes` request starts (RFC-ACDP-0018 §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Since {
    /// The oldest retained entry (`since` absent): replay history.
    Start,
    /// The current head (`since=head`): no entries, just the head cursor.
    /// Where a new consumer, or one resyncing after `cursor_expired`,
    /// starts.
    Head,
    /// After a cursor from an earlier response.
    Cursor(String),
}

impl Since {
    /// The `since` query value, or `None` to omit the parameter.
    pub fn as_query(&self) -> Option<&str> {
        match self {
            Since::Start => None,
            Since::Head => Some("head"),
            Since::Cursor(c) => Some(c),
        }
    }
}

/// A consumer's position in one registry's changes feed: the filter it
/// watches and the cursor it has processed up to.
///
/// [`Self::fetch`] reads the next page WITHOUT moving the cursor; call
/// [`Self::advance`] once every entry of that page has been processed,
/// then persist [`Self::position`] (§7 "Cursor persistence"). A crash in
/// between re-reads the page, which [`SeenChanges`] makes harmless.
#[derive(Clone)]
pub struct ChangeFeed<'a> {
    client: &'a RegistryClient,
    filter: WatchFilter,
    limit: Option<u32>,
    since: Since,
}

impl<'a> ChangeFeed<'a> {
    /// A feed over `client`'s registry, watching `filter`, starting at
    /// [`Since::Start`].
    pub fn new(client: &'a RegistryClient, filter: WatchFilter) -> Self {
        Self {
            client,
            filter,
            limit: None,
            since: Since::Start,
        }
    }

    /// Start from `since` (a persisted position, or [`Since::Head`]).
    pub fn since(mut self, since: Since) -> Self {
        self.since = since;
        self
    }

    /// Ask for at most `limit` entries per page.
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// The position the next [`Self::fetch`] reads from.
    pub fn position(&self) -> &Since {
        &self.since
    }

    /// The watched filter.
    pub fn filter(&self) -> &WatchFilter {
        &self.filter
    }

    /// Read the page after [`Self::position`]. Does not move the cursor.
    pub async fn fetch(&self) -> Result<ChangesResponse, AcdpError> {
        self.client
            .changes(&self.since, &self.filter, self.limit)
            .await
    }

    /// Move past `page` (to its `next_cursor`) once all of its entries
    /// are processed.
    pub fn advance(&mut self, page: &ChangesResponse) {
        self.since = Since::Cursor(page.next_cursor.clone());
    }

    /// After `cursor_expired` and a direct re-verification of every
    /// watched context: resume from the head (§7 "Resync").
    ///
    /// Prefer [`Self::resync`], which also clears the (authority, `seq`)
    /// dedup state: a registry that reset its sequence may reuse numbers
    /// the consumer already processed (fixture `rec-006` J).
    pub fn reset_to_head(&mut self) {
        self.since = Since::Head;
    }

    /// Whether `err`, returned by [`Self::fetch`], means the consumer has
    /// lost its place and must resync (RFC-ACDP-0018 §7 "Resync"):
    ///
    /// - [`AcdpError::CursorExpired`], at any position;
    /// - [`AcdpError::InvalidCursor`] while [`Self::position`] is a
    ///   [`Since::Cursor`] — a cursor this consumer persisted from an
    ///   earlier response. The registry issued it, so the consumer treats
    ///   the refusal exactly as `cursor_expired` and never retries the
    ///   same cursor forever (fixture `rec-006` I).
    pub fn needs_resync(&self, err: &AcdpError) -> bool {
        match err {
            AcdpError::CursorExpired => true,
            AcdpError::InvalidCursor(_) => matches!(self.since, Since::Cursor(_)),
            _ => false,
        }
    }

    /// The §7 "Resync" bookkeeping, after re-verifying every watched
    /// context directly: resume from [`Since::Head`] and forget this
    /// registry's dedup high-water mark in `seen`, since dedup by `seq`
    /// is valid only between resyncs (fixture `rec-006` I–J).
    pub fn resync(&mut self, seen: &mut SeenChanges) {
        self.reset_to_head();
        if let Some(authority) = self.client.authority() {
            seen.forget(&authority);
        }
    }

    /// React to an authenticated change hint (RFC-ACDP-0018 §8.2): read
    /// the page after this feed's OWN position. The hint's `head_cursor`
    /// is informational and never used: jumping to it would skip
    /// entries (fixture `rec-007` E). Verify the hint's `ACDP-Signature`
    /// first ([`acdp_types::change::verify_hint_signature`]).
    ///
    /// A hint naming another registry is
    /// [`AcdpError::SchemaViolation`].
    pub async fn on_hint(&self, hint: &ChangeHint) -> Result<ChangesResponse, AcdpError> {
        if self.client.authority().as_deref() != Some(hint.registry_authority.as_str()) {
            return Err(AcdpError::SchemaViolation(format!(
                "change hint names registry '{}', not this feed's",
                hint.registry_authority
            )));
        }
        self.fetch().await
    }
}

/// §7 idempotency: delivery is at-least-once, so a consumer deduplicates
/// by (registry authority, `seq`) — but only **between resyncs**.
///
/// Because `seq` is strictly increasing per registry and a feed is
/// processed in ascending order, a per-authority high-water mark is the
/// whole state: an entry at or below it was already processed. Mark an
/// entry only once its verdict is final (a transient `Err` from
/// [`verify_change`] leaves it unmarked, to be retried).
///
/// A resync (`cursor_expired`, or `invalid_cursor` on a persisted cursor)
/// MUST clear the mark: after a sequence reset the registry may serve a
/// different entry at a `seq` already processed, and that entry is new
/// (fixture `rec-006` J). [`ChangeFeed::resync`] does this; otherwise
/// call [`Self::forget`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeenChanges {
    high_water: BTreeMap<String, u64>,
}

impl SeenChanges {
    /// Nothing seen.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether entry `seq` of `authority` is not yet processed.
    pub fn is_new(&self, authority: &str, seq: u64) -> bool {
        self.high_water.get(authority).is_none_or(|hw| seq > *hw)
    }

    /// Record entry `seq` of `authority` as processed.
    pub fn mark(&mut self, authority: &str, seq: u64) {
        let hw = self.high_water.entry(authority.to_owned()).or_insert(seq);
        *hw = (*hw).max(seq);
    }

    /// Forget everything recorded for `authority` (on resync).
    pub fn forget(&mut self, authority: &str) {
        self.high_water.remove(authority);
    }

    /// Check and record in one step: `true` the first time.
    pub fn first_time(&mut self, authority: &str, seq: u64) -> bool {
        let new = self.is_new(authority, seq);
        if new {
            self.mark(authority, seq);
        }
        new
    }
}

// ── Verifying entries ────────────────────────────────────────────────────────

/// What a consumer already holds for the context a `lifecycle` entry is
/// about. Lets [`verify_change`] apply the entry without re-retrieving,
/// which §7 step 1 allows only when every earlier event (indexes `0` to
/// `index − 1`) is held and verified.
#[derive(Debug, Clone, Copy)]
pub struct HeldContext<'a> {
    /// The context's verified body.
    pub body: &'a Body,
    /// Its verified lifecycle events, raw as served, in array order from
    /// index 0.
    pub events: &'a [Value],
}

/// Where a verified `lifecycle` entry's retraction state was derived
/// from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleSource {
    /// The consumer's [`HeldContext`] plus the entry's event.
    Held,
    /// A fresh, verified retrieval of the context.
    Retrieved,
}

/// The verified effect of a change entry: what the consumer should
/// re-evaluate. Policy (whether reliance moves) stays the consumer's.
#[derive(Debug)]
#[non_exhaustive]
pub enum ChangeEffect {
    /// A lifecycle event of the affected context, verified.
    Lifecycle {
        /// The verified event.
        event: LifecycleEvent,
        /// The context's retraction state over its full event list
        /// (RFC-ACDP-0013 §7.1).
        retracted: bool,
        /// Where the full list came from.
        source: LifecycleSource,
    },
    /// The affected context was superseded by this verified version,
    /// whose receipt verified and matches the entry's.
    Superseded {
        /// The new version.
        new_version: Box<VerifiedContext>,
    },
    /// A verified revocation that speaks for the entry's `agent_id`
    /// (RFC-ACDP-0014 §7 producer scope). Apply it with the §7
    /// compromise boundary and the earliest-`compromised_since` fold.
    KeyRevocation {
        /// The revocation, attributed to this registry.
        revocation: SourcedRevocation,
    },
}

/// The outcome of [`verify_change`] (RFC-ACDP-0018 §7).
#[derive(Debug)]
#[non_exhaustive]
pub enum ChangeVerdict {
    /// The entry verified; re-evaluate reliance per the effect.
    Verified(ChangeEffect),
    /// The entry failed verification. It MUST NOT change any reliance
    /// decision; the consumer SHOULD re-verify the affected context
    /// directly, since a faulty source could equally drop a real entry.
    Rejected(AcdpError),
}

impl ChangeVerdict {
    /// The effect, when verified.
    pub fn effect(&self) -> Option<&ChangeEffect> {
        match self {
            ChangeVerdict::Verified(e) => Some(e),
            ChangeVerdict::Rejected(_) => None,
        }
    }

    /// The reason, when rejected.
    pub fn rejection(&self) -> Option<&AcdpError> {
        match self {
            ChangeVerdict::Verified(_) => None,
            ChangeVerdict::Rejected(e) => Some(e),
        }
    }
}

/// Verify one change entry from `client`'s feed (RFC-ACDP-0018 §7).
///
/// For every kind, the §7 envelope rule first:
/// [`Change::check_consistency`] (`recorded_at` and `ctx_id` agree with
/// the evidence). Then, by kind:
///
/// - **`lifecycle`** — the context's body comes from `held` or a verified
///   retrieval under `policy`; it must be the entry's context, producer
///   and lineage, at this registry. The event is verified under
///   RFC-ACDP-0013 §5 and its event receipt under RFC-ACDP-0017 §10.3
///   (*i* = `event_receipt.index`, against the body's `created_at`).
///   The retraction state is then derived over the full event list:
///   from `held` when it covers indexes `0..index` (a held event at
///   `index` must equal the entry's), otherwise from a re-retrieval whose
///   `lifecycle_events[index]` must equal the entry's event under JCS.
///   Every `retracted`/`republished` event in that list is verified.
/// - **`superseded`** — `superseded_by` is retrieved and verified under
///   `policy` with its receipt required; it must originate at the
///   serving registry (§7 origin binding); its `supersedes`,
///   `lineage_id` and `agent_id` must be the entry's, and its verified
///   receipt must equal the entry's.
/// - **`key_revocation`** — the revocation context is retrieved and
///   verified under RFC-ACDP-0014 §5 (including the historical-key arm)
///   or §6 (a registry-attested one must be published by this registry);
///   the served receipt must verify under RFC-ACDP-0010 §8 and equal the
///   entry's under JCS; and the revocation must
///   speak for the entry's `agent_id` (§7 producer scope).
///
/// `Ok(Rejected)` is a final verdict. `Err` means the entry could not be
/// decided (a transient failure: network, rate-limited DID refresh) or
/// `held` is for another context; leave the entry unprocessed and retry.
pub async fn verify_change(
    client: &RegistryClient,
    resolver: &WebResolver,
    change: &Change,
    held: Option<HeldContext<'_>>,
    policy: &VerificationPolicy,
) -> Result<ChangeVerdict, AcdpError> {
    if let Some(h) = held {
        if &h.body.ctx_id != change.ctx_id() {
            return Err(AcdpError::SchemaViolation(format!(
                "held context {} is not the entry's {}",
                h.body.ctx_id,
                change.ctx_id()
            )));
        }
    }
    let outcome = match change.check_consistency() {
        Err(e) => Err(e),
        Ok(()) => match change.evidence() {
            ChangeEvidence::Lifecycle {
                event,
                event_receipt,
            } => {
                verify_lifecycle(client, resolver, change, event, event_receipt, held, policy).await
            }
            ChangeEvidence::Superseded {
                superseded_by,
                registry_receipt,
            } => {
                verify_superseded(
                    client,
                    resolver,
                    change,
                    superseded_by,
                    registry_receipt,
                    policy,
                )
                .await
            }
            ChangeEvidence::KeyRevocation { registry_receipt } => {
                verify_key_revocation(client, resolver, change, registry_receipt).await
            }
        },
    };
    match outcome {
        Ok(effect) => Ok(ChangeVerdict::Verified(effect)),
        Err(e) if e.is_transient() => Err(e),
        Err(e) => Ok(ChangeVerdict::Rejected(e)),
    }
}

fn reject(change: &Change, why: impl std::fmt::Display) -> AcdpError {
    AcdpError::SchemaViolation(format!(
        "change {} ({} {}): {why} (RFC-ACDP-0018 §7)",
        change.seq(),
        change.kind(),
        change.ctx_id()
    ))
}

fn serving_authority(client: &RegistryClient) -> Result<String, AcdpError> {
    client
        .authority()
        .ok_or_else(|| AcdpError::SchemaViolation("registry client base URL has no host".into()))
}

/// The entry's context, producer and lineage, at this registry.
fn check_body_binding(change: &Change, body: &Body, authority: &str) -> Result<(), AcdpError> {
    if &body.ctx_id != change.ctx_id() {
        return Err(AcdpError::ContextIdMismatch {
            requested: change.ctx_id().as_str().to_owned(),
            served: body.ctx_id.as_str().to_owned(),
        });
    }
    if &body.agent_id != change.agent_id() {
        return Err(reject(
            change,
            format!("the context's producer is {}", body.agent_id),
        ));
    }
    if &body.lineage_id != change.lineage_id() {
        return Err(reject(
            change,
            format!("the context's lineage is {}", body.lineage_id),
        ));
    }
    if body.origin_registry != authority {
        return Err(reject(
            change,
            format!(
                "the context originates at {}, not this registry",
                body.origin_registry
            ),
        ));
    }
    Ok(())
}

/// JCS byte equality, via the RFC-ACDP-0017 §10.1 hash (SHA-256 of JCS).
fn jcs_equal(a: &Value, b: &Value) -> Result<bool, AcdpError> {
    Ok(EventReceipt::event_hash_of_value(a)? == EventReceipt::event_hash_of_value(b)?)
}

async fn verify_lifecycle(
    client: &RegistryClient,
    resolver: &WebResolver,
    change: &Change,
    raw_event: &Value,
    raw_receipt: &Value,
    held: Option<HeldContext<'_>>,
    policy: &VerificationPolicy,
) -> Result<ChangeEffect, AcdpError> {
    let authority = serving_authority(client)?;
    let index = EventReceipt::from_value(raw_receipt)?.index;
    let index_usize = usize::try_from(index).map_err(|_| reject(change, "index out of range"))?;
    // §7 step 1: the held list may stand in for a retrieval only when it
    // covers every earlier event.
    let held = held.filter(|h| h.events.len() >= index_usize);
    let retrieved;
    let (body, list, source): (&Body, Vec<Value>, LifecycleSource) = match held {
        Some(h) => {
            let mut list = h.events.to_vec();
            match list.get(index_usize) {
                Some(have) if !jcs_equal(have, raw_event)? => {
                    return Err(reject(
                        change,
                        format!("the held event at index {index} differs from the entry's"),
                    ));
                }
                Some(_) => {}
                None => list.push(raw_event.clone()),
            }
            (h.body, list, LifecycleSource::Held)
        }
        None => {
            retrieved =
                VerifiedContext::fetch_with_policy(client, resolver, change.ctx_id(), policy)
                    .await?;
            let list: Vec<Value> = retrieved
                .registry_state()
                .lifecycle_events
                .iter()
                .flatten()
                .map(serde_json::to_value)
                .collect::<Result<_, _>>()?;
            match list.get(index_usize) {
                Some(served) if jcs_equal(served, raw_event)? => {}
                _ => {
                    return Err(reject(
                        change,
                        format!(
                            "the re-retrieved lifecycle_events[{index}] is not the entry's event"
                        ),
                    ))
                }
            }
            (retrieved.body(), list, LifecycleSource::Retrieved)
        }
    };
    check_body_binding(change, body, &authority)?;
    let registry_did = acdp_did::web::authority_to_did_web(&authority);
    let event = acdp_verify::verify_lifecycle_event(
        raw_event,
        change.ctx_id(),
        &body.agent_id,
        Some(&registry_did),
        resolver,
    )
    .await?;
    verify_event_receipt_value(
        raw_receipt,
        &authority,
        change.ctx_id(),
        raw_event,
        index,
        body.created_at,
        resolver,
        std::time::Instant::now(),
    )
    .await?;
    // RFC-ACDP-0013 §7.1 over the full list. A held list was verified by
    // the caller; a retrieved one is verified here for the events that
    // decide the state.
    let mut events = Vec::with_capacity(list.len());
    for (i, raw) in list.iter().enumerate() {
        let parsed = if i == index_usize {
            event.clone()
        } else if source == LifecycleSource::Retrieved {
            let parsed = LifecycleEvent::from_value(raw)?;
            if matches!(
                parsed.event_type,
                LifecycleEventType::Retracted | LifecycleEventType::Republished
            ) {
                acdp_verify::verify_lifecycle_event(
                    raw,
                    change.ctx_id(),
                    &body.agent_id,
                    Some(&registry_did),
                    resolver,
                )
                .await?
            } else {
                parsed
            }
        } else {
            LifecycleEvent::from_value(raw)?
        };
        events.push(parsed);
    }
    Ok(ChangeEffect::Lifecycle {
        retracted: retraction_state(&events),
        event,
        source,
    })
}

async fn verify_superseded(
    client: &RegistryClient,
    resolver: &WebResolver,
    change: &Change,
    superseded_by: &CtxId,
    raw_receipt: &Value,
    policy: &VerificationPolicy,
) -> Result<ChangeEffect, AcdpError> {
    let policy = VerificationPolicy {
        receipts: ReceiptPolicy::Require,
        ..policy.clone()
    };
    let authority = serving_authority(client)?;
    let new_version =
        VerifiedContext::fetch_with_policy(client, resolver, superseded_by, &policy).await?;
    let body = new_version.body();
    if body.origin_registry != authority {
        return Err(reject(
            change,
            format!(
                "{superseded_by} originates at {}, not this registry",
                body.origin_registry
            ),
        ));
    }
    if body.supersedes.as_ref() != Some(change.ctx_id()) {
        return Err(reject(
            change,
            format!("{superseded_by} does not supersede it"),
        ));
    }
    if &body.lineage_id != change.lineage_id() {
        return Err(reject(
            change,
            format!("{superseded_by} is in lineage {}", body.lineage_id),
        ));
    }
    if &body.agent_id != change.agent_id() {
        return Err(reject(
            change,
            format!(
                "{superseded_by} has producer {} (RFC-ACDP-0003 §3.1)",
                body.agent_id
            ),
        ));
    }
    let matches_entry = match (new_version.verified_receipt(), new_version.receipt()) {
        (Some(_), Some(served)) => jcs_equal(served, raw_receipt)?,
        _ => false,
    };
    if !matches_entry {
        return Err(reject(
            change,
            "the entry's registry_receipt is not the new version's verified receipt",
        ));
    }
    Ok(ChangeEffect::Superseded {
        new_version: Box::new(new_version),
    })
}

async fn verify_key_revocation(
    client: &RegistryClient,
    resolver: &WebResolver,
    change: &Change,
    raw_receipt: &Value,
) -> Result<ChangeEffect, AcdpError> {
    let authority = serving_authority(client)?;
    let ctx = client.retrieve(change.ctx_id()).await?;
    if &ctx.body.ctx_id != change.ctx_id() {
        return Err(AcdpError::ContextIdMismatch {
            requested: change.ctx_id().as_str().to_owned(),
            served: ctx.body.ctx_id.as_str().to_owned(),
        });
    }
    if &ctx.body.lineage_id != change.lineage_id() {
        return Err(reject(
            change,
            format!("the revocation is in lineage {}", ctx.body.lineage_id),
        ));
    }
    let since = std::time::Instant::now();
    let revocation = verify_revocation_candidate(&ctx, client, resolver, since).await?;
    if revocation.trust_class == RevocationTrustClass::RegistryAttested {
        let caps = client.capabilities().await?;
        revocation.cross_check_registry_binding(&authority, &caps.registry_did)?;
    }
    RegistryReceipt::from_value(raw_receipt)?;
    let Some(served) = ctx.registry_receipt.as_ref() else {
        return Err(reject(
            change,
            "the revocation is served without a registry_receipt",
        ));
    };
    if !jcs_equal(served, raw_receipt)? {
        return Err(reject(
            change,
            "the entry's registry_receipt is not the receipt served with the revocation",
        ));
    }
    // The served receipt verifies under RFC-ACDP-0010 §8 on every arm
    // (the producer-signed §5 path need not touch it), so JCS equality
    // above makes the entry's copy verified too (RFC-ACDP-0018 §7 step 3).
    // `content_hash` was recomputed and checked by the candidate pipeline.
    let body = &ctx.body;
    let producer_fp = acdp_crypto::fingerprint::fingerprint_for_key_id_since(
        &body.signature.key_id,
        &body.signature.algorithm,
        resolver,
        since,
    )
    .await?;
    crate::receipt::verify_receipt_value_since(
        served,
        &body.ctx_id,
        body,
        &body.content_hash,
        &producer_fp,
        &authority,
        resolver,
        since,
    )
    .await?;
    let revocation = revocation.sourced(RevocationSource::Discovered { authority });
    if !revocation.speaks_for(change.agent_id()) {
        return Err(reject(
            change,
            format!(
                "the revocation does not speak for {} (RFC-ACDP-0014 §7 producer scope)",
                change.agent_id()
            ),
        ));
    }
    Ok(ChangeEffect::KeyRevocation { revocation })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_query_values() {
        assert_eq!(Since::Start.as_query(), None);
        assert_eq!(Since::Head.as_query(), Some("head"));
        assert_eq!(Since::Cursor("abc".into()).as_query(), Some("abc"));
    }

    #[test]
    fn seen_changes_dedups_by_authority_and_seq() {
        let mut seen = SeenChanges::new();
        assert!(seen.first_time("a.example.com", 5));
        assert!(!seen.first_time("a.example.com", 5));
        assert!(!seen.is_new("a.example.com", 4));
        assert!(seen.is_new("b.example.com", 5));
        assert!(seen.first_time("a.example.com", 6));
        seen.mark("a.example.com", 2);
        assert!(!seen.is_new("a.example.com", 6));
        // A resync clears one authority's mark only.
        assert!(seen.first_time("b.example.com", 9));
        seen.forget("a.example.com");
        assert!(seen.is_new("a.example.com", 6));
        assert!(!seen.is_new("b.example.com", 9));
    }
}
