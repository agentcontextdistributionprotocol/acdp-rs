//! Registry persistence abstraction (feature = "server").
//!
//! [`RegistryStore`] is the minimal contract a registry implementation
//! must satisfy: store an immutable [`Body`] under a registry-assigned
//! [`CtxId`], track the parent lineage, mark predecessors superseded,
//! and project search/lineage queries. The trait is synchronous and
//! object-safe so a [`RegistryServer`](super::server::RegistryServer)
//! can be parameterised over any backend (in-memory for tests, SQLite
//! for production, etc.) without an async runtime dependency.
//!
//! [`InMemoryStore`] is the reference implementation used by the
//! integration tests and intended as a drop-in for prototyping.

use std::sync::Mutex;

use acdp_primitives::error::AcdpError;
use acdp_types::{
    body::{Body, FullContext, RegistryState},
    lifecycle::{LifecycleEvent, LifecycleEventType},
    primitives::{AgentDid, CtxId, LineageId, Status, Visibility},
    publish::{PublishRequest, PublishResponse},
    search::{SearchParams, SearchResponse, SearchResult},
};

/// Abstract registry persistence backend.
///
/// Synchronous — the in-memory implementation is mutex-guarded; async
/// backends should wrap blocking calls with `spawn_blocking` at the
/// HTTP boundary.
pub trait RegistryStore: Send + Sync {
    /// Persist a freshly-assigned context. `body.ctx_id` and
    /// `body.lineage_id` are already populated by the server.
    fn put(&self, body: Body) -> Result<(), AcdpError>;

    /// Retrieve a stored context by `ctx_id`.
    fn get(&self, ctx_id: &CtxId) -> Result<Option<FullContext>, AcdpError>;

    /// All contexts in a lineage, oldest first.
    fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError>;

    /// Returns the newest version of a lineage that is **neither
    /// [`Status::Superseded`] nor [`Status::Retracted`]** — either
    /// [`Status::Active`] or [`Status::Expired`] (an
    /// expired-but-unreplaced body is still the latest version, and
    /// callers need to see it to know it has lapsed; a retracted one is
    /// never a head, RFC-ACDP-0013 §8.3).
    ///
    /// Returns `Ok(None)` when the lineage is unknown or every version is
    /// superseded or retracted (RFC-ACDP-0004 §5.2: "if no such version
    /// exists, returns not_found" — fixtures `ret-002` / `lc-003`).
    /// Visibility rules are NOT applied here — filter at the server
    /// layer via [`crate::registry::server::RegistryServer::current`].
    fn current(&self, lineage_id: &LineageId) -> Result<Option<FullContext>, AcdpError>;

    /// Mark `ctx_id`'s registry state as `superseded`. Idempotent.
    fn mark_superseded(&self, ctx_id: &CtxId) -> Result<(), AcdpError>;

    /// First-version `ctx_id` for a lineage, used to derive the
    /// lineage_id of a supersession publish per RFC-ACDP-0001 §5.6.
    ///
    /// LINEAGE ANCHORING (WS-D3). Implementations SHOULD answer this
    /// (and the supersession checks in [`Self::commit_publish`]) from
    /// **persisted rows** — the immediate predecessor's stored
    /// `lineage_id`/`version` and a lineage index — NOT by re-walking
    /// the full `supersedes` chain at publish time. A registry's own
    /// storage is trusted; anchoring removes the
    /// `lineage_walk_failed` liveness failure where a v(N+1) publish is
    /// rejected because some deep intermediate is unretrievable even
    /// though the immediate predecessor exists. Reserve the full
    /// chain walk for offline integrity audits, off the publish path.
    /// (`InMemoryStore` implements exactly this pattern.)
    fn first_version_ctx_id(&self, lineage_id: &LineageId) -> Result<Option<CtxId>, AcdpError>;

    /// Keyword/filter search. Implementations MUST apply the RFC-ACDP-0008
    /// §4.5 search-disclosure rules using `requester`:
    ///
    /// | Visibility   | Surfaces in search to                        |
    /// |--------------|----------------------------------------------|
    /// | `public`     | anyone                                       |
    /// | `restricted` | producer (`agent_id`) **or** any DID in `audience` |
    /// | `private`    | producer (`agent_id`) only — audience members must already know the ctx_id |
    ///
    /// `requester == None` represents an anonymous caller. Public
    /// contexts surface only when `anonymous_public_reads` is true (the
    /// capability flag from [`RegistryServer`](super::server::RegistryServer));
    /// the store implements the same predicate as `RegistryServer::retrieve`
    /// so the two endpoints stay symmetric (RFC-ACDP-0008 §4.5).
    ///
    /// Projection follows RFC-ACDP-0005 §2.2 `match_summary`.
    fn search(
        &self,
        params: &SearchParams,
        requester: Option<&AgentDid>,
        anonymous_public_reads: bool,
    ) -> Result<SearchResponse, AcdpError>;

    // ── Idempotency (RFC-ACDP-0003 §6) ─────────────────────────────────
    //
    // Stores supporting the `idempotency_key` capability MUST implement
    // these three methods. The default impls treat the store as
    // non-idempotent: lookup always returns `None`, record is a no-op,
    // evict is a no-op. A `RegistryServer` configured with
    // `caps.supports_idempotency_key = false` MUST never call them
    // (RFC-ACDP-0007 §3.2).
    //
    // ATOMICITY CONTRACT (WS-D4). Keys are scoped per `agent_id`: two
    // different agents using the same key never interact. The
    // idempotency record and the body persistence MUST commit
    // atomically (single transaction / compare-and-swap / one lock —
    // see `commit_publish`); a backend that cannot provide this (e.g.
    // an eventually-consistent store) MUST NOT be paired with
    // `supports_idempotency_key: true`, because concurrent identical-key
    // publishes could mint two ctx_ids and silently defeat the
    // guarantee the capability advertises. Durable backends should
    // enforce a UNIQUE constraint on `(agent_id, idempotency_key)` and
    // insert it in the same transaction as the context row.

    /// Look up a prior publish record for `(agent_id, key)`.
    ///
    /// Returns `Some((content_hash, response))` if a record exists and
    /// has not expired. Scoping by `agent_id` prevents a malicious
    /// producer from poisoning another producer's key namespace
    /// (RFC-ACDP-0003 §6 — idem-004 fixture).
    fn idempotency_lookup(
        &self,
        _agent_id: &AgentDid,
        _key: &str,
    ) -> Result<Option<IdempotencyRecord>, AcdpError> {
        Ok(None)
    }

    /// Record a successful publish under `(agent_id, key)` with TTL
    /// `expires_at`. Calling on a store that does not support
    /// idempotency is a no-op.
    fn idempotency_record(
        &self,
        _agent_id: &AgentDid,
        _key: &str,
        _hash: &acdp_types::primitives::ContentHash,
        _response: &acdp_types::publish::PublishResponse,
        _expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AcdpError> {
        Ok(())
    }

    /// Evict records whose `expires_at` is past `now`. Implementations
    /// may call this on a janitor schedule or lazily at lookup time.
    fn idempotency_evict_expired(
        &self,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AcdpError> {
        Ok(())
    }

    // ── Atomic publish commit (FEAT-01) ────────────────────────────────

    /// Atomically commit a publish: idempotency lookup, supersession
    /// validation, body insertion, predecessor supersession marking,
    /// and idempotency record write — all under a single critical
    /// section so two concurrent publishes targeting the same
    /// `supersedes` (or sharing an `idempotency_key`) cannot both
    /// succeed.
    ///
    /// Eliminates the TOCTOU races that the old
    /// `put → mark_superseded → idempotency_record` sequence allowed.
    /// Returns:
    /// - `Inserted(response)` — the body was newly persisted.
    /// - `IdempotentReplay(response)` — a prior record with the same
    ///   `(agent_id, key, content_hash)` was found and its response is
    ///   replayed verbatim (idem-002).
    ///
    /// On supersession contention (predecessor already marked
    /// `Superseded`, lineage mismatch, etc.) returns
    /// `AcdpError::SupersededTarget { reason, … }`. On idempotency-key
    /// collision with a different `content_hash` returns
    /// `AcdpError::DuplicatePublish` (idem-003).
    fn commit_publish(&self, commit: PublishCommit<'_>) -> Result<PublishCommitOutcome, AcdpError>;

    // ── Lifecycle events (ACDP 0.3, RFC-ACDP-0013) ─────────────────────

    /// Atomically append a lifecycle event and apply its status effect
    /// (RFC-ACDP-0013 §6 steps 4–5).
    ///
    /// CONTRACT — an implementation MUST, under one critical section /
    /// transaction:
    ///
    /// 1. Resolve `event.ctx_id`; unknown → [`AcdpError::NotFound`]
    ///    (visibility filtering is the server's job, before this call).
    /// 2. **Retry idempotency** (§6): if an already-appended event has
    ///    the same `event_id` *and identical content*, append nothing
    ///    and return [`LifecycleCommitOutcome::IdempotentReplay`] with
    ///    the current projected context; same `event_id` with
    ///    *different* content → [`AcdpError::SchemaViolation`].
    /// 3. **Strict alternation** (§6 step 4, §7.1): `retracted` is
    ///    accepted only when the context's retraction state is *not
    ///    retracted*; `republished` only when it *is*. A violation
    ///    (double retract, spurious republish) →
    ///    [`AcdpError::InvalidLifecycleTransition`], with **no state
    ///    change**. An unregistered `event_type` →
    ///    [`AcdpError::SchemaViolation`] (§7.3).
    /// 4. Append the event at the END of `lifecycle_events` (append-only
    ///    — never remove, reorder, or mutate, §4.1) atomically with the
    ///    status effect, and return
    ///    [`LifecycleCommitOutcome::Applied`] with the post-transition
    ///    context (`status` reflecting the §7.2 precedence:
    ///    `retracted` > `superseded` > `expired` > `active`).
    ///
    /// The default returns [`AcdpError::NotImplemented`] — deliberately
    /// NOT a benign no-op like the idempotency defaults: silently
    /// dropping a retraction would defeat the withdrawal the producer
    /// signed, whereas a missing idempotency record only costs a
    /// replay. A `RegistryServer` enabled with
    /// [`with_lifecycle`](crate::registry::server::RegistryServer::with_lifecycle)
    /// MUST be paired with a store that implements this method; a
    /// registry not advertising `acdp-registry-lifecycle` never calls
    /// it (and its wire layer maps the error to `not_implemented` /
    /// HTTP 501, the §6 rule).
    fn commit_lifecycle_event(
        &self,
        event: &LifecycleEvent,
    ) -> Result<LifecycleCommitOutcome, AcdpError> {
        let _ = event;
        Err(AcdpError::NotImplemented(
            "this RegistryStore backend does not implement lifecycle events \
             (RFC-ACDP-0013): commit_lifecycle_event is not available"
                .into(),
        ))
    }
}

/// Outcome of an atomic [`RegistryStore::commit_lifecycle_event`].
#[derive(Debug)]
pub enum LifecycleCommitOutcome {
    /// The event was appended and the status effect applied; carries
    /// the post-transition full context (RFC-ACDP-0013 §6 step 5: the
    /// caller sees the new state in the shape it already knows).
    Applied(FullContext),
    /// The event's `event_id` matched an already-appended event with
    /// identical content — nothing was appended; carries the current
    /// state (§6 retry idempotency: a producer whose POST timed out
    /// after the append must not receive a spurious
    /// `invalid_lifecycle_transition`).
    IdempotentReplay(FullContext),
}

impl LifecycleCommitOutcome {
    /// The post-transition (or current, on replay) full context.
    pub fn into_context(self) -> FullContext {
        match self {
            LifecycleCommitOutcome::Applied(ctx)
            | LifecycleCommitOutcome::IdempotentReplay(ctx) => ctx,
        }
    }
}

/// Single-shot atomic publish input (FEAT-01).
///
/// Passed to [`RegistryStore::commit_publish`] so the predecessor
/// lookup, supersession check, body insertion, predecessor
/// supersession marking, and idempotency record are all done under one
/// critical section. Eliminates TOCTOU races between two concurrent
/// publishes that target the same `supersedes` ctx_id or share an
/// `idempotency_key`.
pub struct PublishCommit<'a> {
    /// The validated, signature-verified publish request.
    pub req: &'a PublishRequest,
    /// The hostname the registry serves — used to mint `ctx_id`s and
    /// stored verbatim into `body.origin_registry` (BUG-01).
    pub authority: &'a str,
    /// Idempotency wiring, present iff the registry advertises
    /// `caps.supports_idempotency_key` and the request carries an
    /// `Idempotency-Key`.
    pub idempotency: Option<PendingIdempotencyCommit<'a>>,
    /// Tenant this publish is scoped to, if the registry is multi-tenant.
    /// `None` means untenanted (single-tenant / V0). A multi-tenant store
    /// MUST persist this atomically with the context row so the tenancy is
    /// never observable as the default bucket (and never stranded there on a
    /// crash between insert and a separate stamping UPDATE). Stores that do
    /// not implement tenancy ignore it.
    pub tenant: Option<&'a str>,
    /// Receipt minting hook (ACDP 0.2, RFC-ACDP-0010). When present,
    /// the store MUST invoke it with the fully assigned [`Body`]
    /// (ctx_id / lineage_id / created_at populated) **inside the same
    /// critical section / transaction as the insert**, persist the
    /// returned receipt with the context, and include it in the
    /// response. A context published under the
    /// `acdp-registry-receipts` profile must never exist without its
    /// receipt — a crash between insert and mint must not be
    /// observable. `None` for receipt-less (0.1.0-mode) registries.
    #[allow(clippy::type_complexity)]
    pub receipt_minter:
        Option<&'a (dyn Fn(&Body) -> Result<serde_json::Value, AcdpError> + Send + Sync)>,
    /// RFC-ACDP-0014 §4 `supersedes`-row admission hook (key-revocation
    /// lineages). `Some` iff the registry's RFC-0014 version gate is on
    /// (`key_revocation_gate_applies`) **and** `req.supersedes` is set;
    /// otherwise `None`.
    ///
    /// Stores MUST invoke it with the predecessor's stored [`Body`],
    /// inside the same critical section / transaction as their own
    /// supersession checks, and only **after** producer-continuity and
    /// tenant scoping have already passed — never before. Calling it
    /// earlier turns the check into a cross-tenant, non-owner
    /// existence-and-type oracle: the predecessor's presence and
    /// `context_type` would leak to a caller who does not own it and is
    /// not scoped to its tenant. `Err` from the closure MUST abort the
    /// commit — no insert, no supersession side effect. A store that
    /// silently ignores a `Some` hook fails to enforce an RFC-ACDP-0014
    /// §4 MUST.
    #[allow(clippy::type_complexity)]
    pub predecessor_admission: Option<&'a (dyn Fn(&Body) -> Result<(), AcdpError> + Send + Sync)>,
}

/// Idempotency parameters threaded through [`PublishCommit`].
pub struct PendingIdempotencyCommit<'a> {
    /// The key the producer supplied in the `Idempotency-Key` header.
    pub key: &'a str,
    /// TTL after which the idempotency record may be evicted (typically
    /// `caps.limits.idempotency_key_ttl_seconds`).
    pub ttl: chrono::Duration,
}

/// Outcome of an atomic [`RegistryStore::commit_publish`].
#[derive(Debug)]
pub enum PublishCommitOutcome {
    /// Fresh publish — the body was newly persisted and the response
    /// describes the just-assigned identifiers.
    Inserted(PublishResponse),
    /// `(agent_id, idempotency_key)` had a prior record with the same
    /// `content_hash` — return the original response per idem-002.
    IdempotentReplay(PublishResponse),
}

impl PublishCommitOutcome {
    /// The response either way, discarding the insert/replay distinction.
    ///
    /// This is what every `publish_*` entry point that predates
    /// [`RegistryServer::publish_verified_in_tenant_with_outcome`] returns,
    /// and the reason the distinction was invisible to callers: a registry
    /// front-end answering `POST /contexts` needs it to choose between
    /// `201 Created` + `Location` on a fresh publish and `200 OK` on an
    /// idempotent replay (RFC-ACDP-0003 idem-002, which requires 200 and
    /// explicitly NOT 201). Prefer the `*_with_outcome` entry points when
    /// that choice is yours to make.
    pub fn into_response(self) -> PublishResponse {
        match self {
            Self::Inserted(r) | Self::IdempotentReplay(r) => r,
        }
    }

    /// Borrow the response without consuming the outcome.
    pub fn response(&self) -> &PublishResponse {
        match self {
            Self::Inserted(r) | Self::IdempotentReplay(r) => r,
        }
    }

    /// `true` when this publish was served from a prior record rather than
    /// newly persisted — i.e. the caller must answer `200`, not `201`.
    pub fn is_replay(&self) -> bool {
        matches!(self, Self::IdempotentReplay(_))
    }
}

/// Cached publish response keyed by `(agent_id, idempotency_key)`
/// (RFC-ACDP-0003 §6).
#[derive(Debug, Clone)]
pub struct IdempotencyRecord {
    /// The original request's `content_hash`. A retry with the same key
    /// but a different hash MUST be rejected as `duplicate_publish`.
    pub content_hash: acdp_types::primitives::ContentHash,
    /// The response the registry returned on the first acceptance.
    pub response: acdp_types::publish::PublishResponse,
    /// Eviction time (TTL window from caps.limits.idempotency_key_ttl_seconds).
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

// ── In-memory reference implementation ───────────────────────────────────────

/// Minimal in-memory backend. Not durable; intended for tests and
/// prototyping. Concurrency-safe (a single `Mutex` over the table).
#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// All contexts keyed by `ctx_id`. Insertion-ordered per lineage
    /// thanks to the parallel `lineages` index.
    by_ctx: std::collections::BTreeMap<String, FullContext>,
    /// `lineage_id -> [ctx_id, ctx_id, ...]` in publish order.
    lineages: std::collections::BTreeMap<String, Vec<String>>,
    /// `(agent_did, idempotency_key) -> record` (RFC-ACDP-0003 §6).
    idempotency: std::collections::HashMap<(String, String), IdempotencyRecord>,
}

impl InMemoryStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("InMemoryStore mutex poisoned")
    }
}

/// RFC-ACDP-0004 §4 (as amended by RFC-ACDP-0013 §7.2) — derive the
/// served `status` at read time from the stored state, the lifecycle
/// event history, and the clock, so a registry that does not run a
/// janitor still surfaces the correct lifecycle status.
///
/// Precedence: `retracted` > `superseded` > `expired` > `active`.
/// Retraction state is derived from `lifecycle_events` (§7.1) and
/// dominates everything — including a stored `Superseded` and a lapsed
/// `expires_at`; republication removes the retraction from the
/// derivation (not the history) and the status re-derives as though
/// never retracted.
pub(crate) fn project_status(
    state: &RegistryState,
    body: &Body,
    now: chrono::DateTime<chrono::Utc>,
) -> Status {
    if state.is_retracted() {
        return Status::Retracted;
    }
    match &state.status {
        Status::Active => match body.expires_at {
            Some(exp) if exp <= now => Status::Expired,
            _ => Status::Active,
        },
        other => other.clone(),
    }
}

/// Materialize the effective view of a stored context: applies
/// [`project_status`] to override the stored status when retracted or
/// expired.
pub(crate) fn project_context(
    mut ctx: FullContext,
    now: chrono::DateTime<chrono::Utc>,
) -> FullContext {
    ctx.registry_state.status = project_status(&ctx.registry_state, &ctx.body, now);
    ctx
}

/// RFC-ACDP-0008 §4.5 search-disclosure rule.
///
/// Note the asymmetry vs retrieval: a `Private` context surfaces in search
/// **only** to its producer — audience members must already know the
/// `ctx_id` to fetch it. `Restricted` surfaces to producer + audience.
///
/// `anonymous_public_reads` mirrors the capability advertisement
/// (RFC-ACDP-0008 §4.5): a registry that does NOT permit anonymous
/// public reads MUST suppress public contexts for unauthenticated
/// callers in both `retrieve` and `search`. The retrieval helper
/// already consults this flag; this function pulls it through to the
/// store-side search path (BUG-02).
fn can_surface_in_search(
    body: &Body,
    requester: Option<&AgentDid>,
    anonymous_public_reads: bool,
) -> bool {
    match body.visibility {
        Visibility::Public => anonymous_public_reads || requester.is_some(),
        Visibility::Restricted => match requester {
            None => false,
            Some(r) => {
                r == &body.agent_id
                    || body
                        .audience
                        .as_deref()
                        .is_some_and(|a| a.iter().any(|d| d == r))
            }
        },
        Visibility::Private => requester == Some(&body.agent_id),
    }
}

impl RegistryStore for InMemoryStore {
    fn put(&self, body: Body) -> Result<(), AcdpError> {
        let ctx_id = body.ctx_id.0.clone();
        let lineage_id = body.lineage_id.0.clone();
        let ctx = FullContext {
            body,
            registry_state: RegistryState {
                status: Status::Active,
                lifecycle_events: None,
                extensions: Default::default(),
            },
            registry_receipt: None,
            lineage_head_receipt: None,
            log_inclusion: None,
            extensions: Default::default(),
        };
        let mut g = self.lock();
        if g.by_ctx.contains_key(&ctx_id) {
            return Err(AcdpError::SchemaViolation(format!(
                "duplicate ctx_id '{ctx_id}' in store"
            )));
        }
        g.by_ctx.insert(ctx_id.clone(), ctx);
        g.lineages.entry(lineage_id).or_default().push(ctx_id);
        Ok(())
    }

    fn get(&self, ctx_id: &CtxId) -> Result<Option<FullContext>, AcdpError> {
        let now = chrono::Utc::now();
        Ok(self
            .lock()
            .by_ctx
            .get(ctx_id.as_str())
            .cloned()
            .map(|c| project_context(c, now)))
    }

    fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError> {
        let now = chrono::Utc::now();
        let g = self.lock();
        let Some(ids) = g.lineages.get(lineage_id.as_str()) else {
            return Ok(Vec::new());
        };
        Ok(ids
            .iter()
            .filter_map(|id| g.by_ctx.get(id).cloned().map(|c| project_context(c, now)))
            .collect())
    }

    fn current(&self, lineage_id: &LineageId) -> Result<Option<FullContext>, AcdpError> {
        let now = chrono::Utc::now();
        let g = self.lock();
        let Some(ids) = g.lineages.get(lineage_id.as_str()) else {
            return Ok(None);
        };
        // RFC-ACDP-0004 §5: "Returns the unique version that has no
        // successor. If no such version exists, returns not_found."
        // Walk newest-to-oldest and return the first version that is
        // neither `Superseded` nor `Retracted`. Both `Active` and
        // `Expired` count — an expired body that hasn't been replaced
        // is still the latest, and the consumer needs to see it (with
        // status=Expired) to know it has lapsed. A retracted version is
        // NEVER a head (RFC-ACDP-0013 §8.3): it has been explicitly
        // withdrawn from reliance, and falling back to a superseded
        // predecessor would silently serve a replaced context — so
        // retracting a linear lineage's head yields `None` (fixture
        // `lc-003`).
        //
        // BUG-04: an earlier fallback returned the last entry even when
        // every version was `Superseded`; that's a protocol violation.
        // Now we return `None` instead.
        for id in ids.iter().rev() {
            if let Some(ctx) = g.by_ctx.get(id) {
                let projected = project_context(ctx.clone(), now);
                if !matches!(
                    projected.registry_state.status,
                    Status::Superseded | Status::Retracted
                ) {
                    return Ok(Some(projected));
                }
            }
        }
        Ok(None)
    }

    fn commit_lifecycle_event(
        &self,
        event: &LifecycleEvent,
    ) -> Result<LifecycleCommitOutcome, AcdpError> {
        let now = chrono::Utc::now();
        let mut g = self.lock();
        let ctx = g.by_ctx.get_mut(event.ctx_id.as_str()).ok_or_else(|| {
            AcdpError::NotFound(format!(
                "context '{}' not found in this registry",
                event.ctx_id
            ))
        })?;
        let events = ctx
            .registry_state
            .lifecycle_events
            .as_deref()
            .unwrap_or(&[]);

        // §6 retry idempotency / duplicate event_id (step 2).
        if let Some(prior) = events.iter().find(|e| e.event_id == event.event_id) {
            if prior == event {
                return Ok(LifecycleCommitOutcome::IdempotentReplay(project_context(
                    ctx.clone(),
                    now,
                )));
            }
            return Err(AcdpError::SchemaViolation(format!(
                "event_id '{}' was already appended with different content \
                 (RFC-ACDP-0013 §4: event_id MUST be unique within lifecycle_events)",
                event.event_id
            )));
        }

        // §6 step 4 — strict retracted/republished alternation against
        // the §7.1 retraction state, under the same lock as the append.
        let currently_retracted = acdp_types::lifecycle::retraction_state(events);
        match &event.event_type {
            LifecycleEventType::Retracted if currently_retracted => {
                return Err(AcdpError::InvalidLifecycleTransition(format!(
                    "context '{}' is already retracted — double retract violates the \
                     strict alternation rule (RFC-ACDP-0013 §6 step 4)",
                    event.ctx_id
                )));
            }
            LifecycleEventType::Republished if !currently_retracted => {
                return Err(AcdpError::InvalidLifecycleTransition(format!(
                    "context '{}' is not retracted — republish requires a prior \
                     retraction (RFC-ACDP-0013 §6 step 4)",
                    event.ctx_id
                )));
            }
            LifecycleEventType::Other(other) => {
                return Err(AcdpError::SchemaViolation(format!(
                    "event_type '{other}' is not registered for acceptance in 0.3.0 — \
                     only 'retracted' and 'republished' transition state \
                     (RFC-ACDP-0013 §7.3)"
                )));
            }
            LifecycleEventType::Retracted | LifecycleEventType::Republished => {}
        }

        // §6 step 5 — append atomically with the status effect. The
        // served status is DERIVED from this same array (§7.2
        // precedence, applied by `project_status`), so appending the
        // event IS the status change; the stored status keeps tracking
        // the supersession fact only.
        ctx.registry_state
            .lifecycle_events
            .get_or_insert_with(Vec::new)
            .push(event.clone());
        Ok(LifecycleCommitOutcome::Applied(project_context(
            ctx.clone(),
            now,
        )))
    }

    fn mark_superseded(&self, ctx_id: &CtxId) -> Result<(), AcdpError> {
        let mut g = self.lock();
        if let Some(ctx) = g.by_ctx.get_mut(ctx_id.as_str()) {
            ctx.registry_state.status = Status::Superseded;
        }
        Ok(())
    }

    fn first_version_ctx_id(&self, lineage_id: &LineageId) -> Result<Option<CtxId>, AcdpError> {
        let g = self.lock();
        Ok(g.lineages
            .get(lineage_id.as_str())
            .and_then(|ids| ids.first().cloned())
            .map(CtxId))
    }

    fn idempotency_lookup(
        &self,
        agent_id: &AgentDid,
        key: &str,
    ) -> Result<Option<IdempotencyRecord>, AcdpError> {
        // Lazy TTL eviction at lookup time keeps the table bounded
        // without requiring a janitor — see idempotency_evict_expired.
        self.idempotency_evict_expired(chrono::Utc::now())?;
        let g = self.lock();
        Ok(g.idempotency
            .get(&(agent_id.as_str().to_string(), key.to_string()))
            .cloned())
    }

    fn idempotency_record(
        &self,
        agent_id: &AgentDid,
        key: &str,
        hash: &acdp_types::primitives::ContentHash,
        response: &acdp_types::publish::PublishResponse,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AcdpError> {
        let mut g = self.lock();
        g.idempotency.insert(
            (agent_id.as_str().to_string(), key.to_string()),
            IdempotencyRecord {
                content_hash: hash.clone(),
                response: response.clone(),
                expires_at,
            },
        );
        Ok(())
    }

    fn idempotency_evict_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AcdpError> {
        let mut g = self.lock();
        g.idempotency.retain(|_, r| r.expires_at > now);
        Ok(())
    }

    fn commit_publish(&self, commit: PublishCommit<'_>) -> Result<PublishCommitOutcome, AcdpError> {
        use crate::registry::validator::assign_identifiers;

        let PublishCommit {
            req,
            authority,
            idempotency,
            // InMemoryStore does not model tenancy (it is a single-tenant
            // reference/test backend); the durable backends honor this.
            tenant: _,
            receipt_minter,
            predecessor_admission,
        } = commit;
        let now = chrono::Utc::now();
        let mut g = self.lock();

        // ── 1. Idempotency replay / collision ────────────────────────
        if let Some(idem) = &idempotency {
            let idem_key = (req.agent_id.as_str().to_string(), idem.key.to_string());
            if let Some(prior) = g.idempotency.get(&idem_key) {
                if prior.expires_at > now {
                    return if prior.content_hash == req.content_hash {
                        // idem-002: same key + same hash → replay.
                        Ok(PublishCommitOutcome::IdempotentReplay(
                            prior.response.clone(),
                        ))
                    } else {
                        // idem-003: same key + different hash → duplicate_publish.
                        Err(AcdpError::DuplicatePublish(format!(
                            "Idempotency-Key '{}' was previously used by '{}' \
                             with a different content_hash",
                            idem.key, req.agent_id
                        )))
                    };
                }
                // Expired record — fall through and overwrite below.
            }
        }

        // ── 2. Supersession lookups + coherence checks ──────────────
        let first_v1 = if let Some(prev) = &req.supersedes {
            let prev_full = g.by_ctx.get(prev.as_str()).cloned().ok_or_else(|| {
                AcdpError::SupersededTarget {
                    reason: acdp_primitives::error::SupersessionReason::NotFound,
                    message: format!("supersedes target '{prev}' not found in this registry"),
                }
            })?;

            // Producer-continuity: only the predecessor's producer (or a
            // declared contributor) may publish a successor in its lineage.
            // Signature verification only proves the *requester* signed
            // their own request — it does not bind `supersedes` to the
            // predecessor's owner. Without this check any signer could
            // supersede another producer's context (`Superseded` side
            // effect below + `current(lineage)` re-pointing), a full
            // lineage takeover. RFC-ACDP-0001 §5.9 supersession is
            // producer-scoped.
            let is_owner = req.agent_id == prev_full.body.agent_id
                || prev_full.body.contributors.contains(&req.agent_id);
            if !is_owner {
                // Uniform with the genuine not-found case above: a
                // non-owner learns neither that the predecessor exists nor
                // its version / superseded status (supersession existence
                // oracle). Anyone who can legitimately read the
                // predecessor learns nothing new from this shape.
                return Err(AcdpError::SupersededTarget {
                    reason: acdp_primitives::error::SupersessionReason::NotFound,
                    message: format!("supersedes target '{prev}' not found in this registry"),
                });
            }

            // Lineage coherence — when the producer self-verifies.
            if let Some(declared) = &req.lineage_id {
                if declared != &prev_full.body.lineage_id {
                    return Err(AcdpError::SupersededTarget {
                        reason: acdp_primitives::error::SupersessionReason::LineageMismatch,
                        message: format!(
                            "declared lineage_id '{declared}' ≠ predecessor's '{}'",
                            prev_full.body.lineage_id
                        ),
                    });
                }
            }
            // Version coherence: new.version MUST be predecessor.version + 1.
            if req.version != prev_full.body.version + 1 {
                return Err(AcdpError::SupersededTarget {
                    reason: acdp_primitives::error::SupersessionReason::VersionMismatch,
                    message: format!(
                        "version {} ≠ predecessor.version + 1 ({})",
                        req.version,
                        prev_full.body.version + 1
                    ),
                });
            }
            // FEAT-01 atomicity: the check that previously raced with
            // another concurrent publish. Now under the same lock as
            // the insert below — exactly one of two contenders succeeds.
            if matches!(prev_full.registry_state.status, Status::Superseded) {
                return Err(AcdpError::SupersededTarget {
                    reason: acdp_primitives::error::SupersessionReason::AlreadySuperseded,
                    message: format!("supersedes target '{prev}' has already been superseded"),
                });
            }

            // RFC-ACDP-0014 §4 `supersedes`-row enforcement. Runs AFTER
            // producer-continuity, lineage/version coherence, and
            // AlreadySuperseded have all passed — never earlier — so a
            // non-owner (or wrong-tenant, on multi-tenant stores) probe
            // is already turned away as `SupersededTarget::NotFound`
            // above and never reaches this line. Doing this check first
            // would make it a cross-tenant, non-owner
            // existence-and-type oracle on the predecessor.
            if let Some(admission) = predecessor_admission {
                admission(&prev_full.body)?;
            }

            // Derive the v1 ctx_id from the predecessor's lineage —
            // same logic as `first_version_ctx_id`, inlined to stay
            // under the existing lock.
            g.lineages
                .get(prev_full.body.lineage_id.as_str())
                .and_then(|ids| ids.first().cloned())
                .map(CtxId)
        } else {
            None
        };

        // ── 3. Identifier assignment ────────────────────────────────
        let validated = crate::registry::validator::ValidatedPublish {
            recomputed_hash: req.content_hash.clone(),
        };
        let (ctx_id, lineage_id) =
            assign_identifiers(authority, &req.supersedes, first_v1.as_ref(), &validated)?;

        // ── 4. Build the stored Body ────────────────────────────────
        // Single materialization point (IMP-02): the constructor copies
        // every producer field and ms-truncates `created_at`, so this
        // backend cannot drift from the SQL backends when a producer
        // field is added.
        let body =
            Body::from_publish_request(req, ctx_id.clone(), lineage_id.clone(), authority, now);
        let created_at = body.created_at;

        // ── 5. Insert (mirrors `put` but inline so we keep the lock) ─
        let ctx_id_str = body.ctx_id.0.clone();
        let lineage_id_str = body.lineage_id.0.clone();
        if g.by_ctx.contains_key(&ctx_id_str) {
            // UUID collision is astronomically unlikely but we still
            // surface it as a SchemaViolation rather than silently
            // overwriting.
            return Err(AcdpError::SchemaViolation(format!(
                "ctx_id collision: '{ctx_id_str}' already exists"
            )));
        }
        // Receipt minting (RFC-ACDP-0010) — inside the critical section,
        // before the insert becomes visible, so a context published
        // under the receipts profile never exists without its receipt.
        let registry_receipt = receipt_minter.map(|mint| mint(&body)).transpose()?;

        let stored = FullContext {
            body,
            registry_state: RegistryState {
                status: Status::Active,
                lifecycle_events: None,
                extensions: Default::default(),
            },
            registry_receipt: registry_receipt.clone(),
            // Head receipts are ephemeral serve-time attestations —
            // never persisted; `RegistryServer::current` mints per
            // response (RFC-ACDP-0011 §6).
            lineage_head_receipt: None,
            log_inclusion: None,
            extensions: Default::default(),
        };
        g.by_ctx.insert(ctx_id_str.clone(), stored);
        g.lineages
            .entry(lineage_id_str)
            .or_default()
            .push(ctx_id_str);

        // ── 6. Mark predecessor superseded ──────────────────────────
        if let Some(prev) = &req.supersedes {
            if let Some(prev_ctx) = g.by_ctx.get_mut(prev.as_str()) {
                prev_ctx.registry_state.status = Status::Superseded;
            }
        }

        let response = PublishResponse {
            ctx_id,
            lineage_id,
            version: req.version,
            created_at,
            status: Status::Active,
            registry_receipt,
        };

        // ── 7. Idempotency record ───────────────────────────────────
        if let Some(idem) = idempotency {
            let expires_at = now + idem.ttl;
            g.idempotency.insert(
                (req.agent_id.as_str().to_string(), idem.key.to_string()),
                IdempotencyRecord {
                    content_hash: req.content_hash.clone(),
                    response: response.clone(),
                    expires_at,
                },
            );
        }

        Ok(PublishCommitOutcome::Inserted(response))
    }

    fn search(
        &self,
        params: &SearchParams,
        requester: Option<&AgentDid>,
        anonymous_public_reads: bool,
    ) -> Result<SearchResponse, AcdpError> {
        let g = self.lock();
        let now = chrono::Utc::now();

        let q_lower = params.q.as_deref().map(str::to_lowercase);
        let domain = params.domain.as_deref();
        let agent = params.agent_id.as_deref();
        let context_type = params.context_type.as_deref();
        let derived_from = params.derived_from.as_deref();
        let schema_uri = params.schema_uri.as_deref();
        let tags: Option<Vec<&str>> = params.tags.as_deref().map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .collect()
        });

        // BUG-10: parse date-time filter params at the boundary so the
        // hot loop just compares DateTime<Utc> values.
        let created_after = parse_opt_rfc3339(&params.created_after)?;
        let created_before = parse_opt_rfc3339(&params.created_before)?;
        let dp_start_after = parse_opt_rfc3339(&params.data_period_start_after)?;
        let dp_end_before = parse_opt_rfc3339(&params.data_period_end_before)?;
        let expires_after = parse_opt_rfc3339(&params.expires_after)?;
        let expires_before = parse_opt_rfc3339(&params.expires_before)?;

        let mut matches: Vec<&FullContext> = g
            .by_ctx
            .values()
            .filter(|ctx| {
                let body = &ctx.body;

                // RFC-ACDP-0008 §4.5 search-disclosure gate (note the
                // private/restricted asymmetry: private contexts surface
                // in search only to their producer).
                if !can_surface_in_search(body, requester, anonymous_public_reads) {
                    return false;
                }

                if let Some(q) = &q_lower {
                    let haystack = format!(
                        "{} {} {} {} {} {}",
                        body.title,
                        body.description.as_deref().unwrap_or(""),
                        body.summary.as_deref().unwrap_or(""),
                        body.domain.as_deref().unwrap_or(""),
                        body.agent_id.as_str(),
                        body.tags.as_ref().map(|t| t.join(" ")).unwrap_or_default(),
                    )
                    .to_lowercase();
                    if !haystack.contains(q) {
                        return false;
                    }
                }
                if let Some(d) = domain {
                    if body.domain.as_deref() != Some(d) {
                        return false;
                    }
                }
                if let Some(a) = agent {
                    if body.agent_id.as_str() != a {
                        return false;
                    }
                }
                if let Some(t) = context_type {
                    let body_type = serde_json::to_value(&body.context_type)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_default();
                    if body_type != t {
                        return false;
                    }
                }
                if let Some(df) = derived_from {
                    if !body.derived_from.iter().any(|c| c.as_str() == df) {
                        return false;
                    }
                }
                if let Some(req_tags) = &tags {
                    let body_tags = body.tags.as_deref().unwrap_or(&[]);
                    if !req_tags.iter().all(|t| body_tags.iter().any(|bt| bt == t)) {
                        return false;
                    }
                }
                if let Some(uri) = schema_uri {
                    if body.schema_uri.as_deref() != Some(uri) {
                        return false;
                    }
                }
                if let Some(after) = created_after {
                    if body.created_at < after {
                        return false;
                    }
                }
                if let Some(before) = created_before {
                    if body.created_at > before {
                        return false;
                    }
                }
                if let Some(after) = dp_start_after {
                    match &body.data_period {
                        Some(p) if p.start >= after => {}
                        _ => return false,
                    }
                }
                if let Some(before) = dp_end_before {
                    match &body.data_period {
                        Some(p) if p.end <= before => {}
                        _ => return false,
                    }
                }
                if let Some(after) = expires_after {
                    match body.expires_at {
                        Some(e) if e >= after => {}
                        _ => return false,
                    }
                }
                if let Some(before) = expires_before {
                    match body.expires_at {
                        Some(e) if e <= before => {}
                        _ => return false,
                    }
                }
                // Status filter — registry default is `active`. Compare
                // against PROJECTED status so a stored-Active body whose
                // expires_at has passed is filtered out (RFC-ACDP-0004 §4)
                // and a retracted context falls out of default searches —
                // and out of status=superseded / status=expired even where
                // those facts also hold (RFC-ACDP-0013 §8.2: the §7.2
                // precedence applies to the filter).
                let want_status = params.status.as_deref().unwrap_or("active");
                let effective = project_status(&ctx.registry_state, body, now);
                if effective.as_str() != want_status {
                    return false;
                }
                true
            })
            .collect();

        // Newest first; IMP-03 — fall back to ctx_id for a deterministic
        // total order when many contexts share a millisecond.
        matches.sort_by(|a, b| {
            b.body
                .created_at
                .cmp(&a.body.created_at)
                .then_with(|| a.body.ctx_id.as_str().cmp(b.body.ctx_id.as_str()))
        });

        // BUG-08: capture `total_estimate` BEFORE cursor filtering so
        // it represents the total count across all pages (RFC-ACDP-0005
        // §3 — clients use this for "page 1 of N" UIs). If we captured
        // it after `retain`, page 2 would show "80 matches" for a
        // 100-item search, page 3 "60", and so on.
        let total_estimate = Some(matches.len() as u64);

        // BUG-10 cursor: opaque base64 of "<created_at_ms>:<ctx_id>".
        // ≥1h validity is implicit — cursors do not embed a timestamp,
        // so they remain valid until the underlying context is deleted.
        let cursor_anchor = params
            .cursor
            .as_deref()
            .map(decode_cursor)
            .transpose()?
            .flatten();
        if let Some((anchor_ms, anchor_id)) = &cursor_anchor {
            matches.retain(|c| {
                let ms = c.body.created_at.timestamp_millis();
                ms < *anchor_ms || (ms == *anchor_ms && c.body.ctx_id.as_str() > anchor_id.as_str())
            });
        }

        // Clamp into [1, 100]: `limit` is attacker-controlled and never
        // lower-bounded. `limit=0` with ≥1 match would compute `limit - 1`
        // below → debug-build subtraction panic (request-thread DoS) /
        // release-build wrap to usize::MAX → broken pagination.
        let limit = params.limit.unwrap_or(50).clamp(1, 100) as usize;
        let next_cursor = if matches.len() > limit {
            matches.get(limit - 1).map(|c| {
                encode_cursor(c.body.created_at.timestamp_millis(), c.body.ctx_id.as_str())
            })
        } else {
            None
        };

        let projected: Vec<SearchResult> = matches
            .iter()
            .take(limit)
            .map(|ctx| SearchResult {
                ctx_id: ctx.body.ctx_id.clone(),
                lineage_id: ctx.body.lineage_id.clone(),
                agent_id: ctx.body.agent_id.clone(),
                title: ctx.body.title.clone(),
                summary: ctx.body.summary.clone(),
                context_type: ctx.body.context_type.clone(),
                domain: ctx.body.domain.clone(),
                created_at: ctx.body.created_at,
                status: project_status(&ctx.registry_state, &ctx.body, now),
                // RFC-ACDP-0008 §4.5: only disclose visibility when the
                // requester is authorized for it. Public is always safe.
                // For restricted/private, the search filter above guarantees
                // the requester is producer-or-audience, so it's safe to
                // surface the label.
                visibility: Some(ctx.body.visibility.clone()),
            })
            .collect();

        Ok(SearchResponse {
            matches: projected,
            total_estimate,
            next_cursor,
        })
    }
}

/// Parse an optional RFC 3339 string parameter; surface a
/// [`AcdpError::SchemaViolation`] on malformed input.
fn parse_opt_rfc3339(
    s: &Option<String>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, AcdpError> {
    let Some(raw) = s.as_deref() else {
        return Ok(None);
    };
    let dt = chrono::DateTime::parse_from_rfc3339(raw)
        .map_err(|e| AcdpError::SchemaViolation(format!("malformed datetime '{raw}': {e}")))?;
    Ok(Some(dt.with_timezone(&chrono::Utc)))
}

/// Cursor TTL — clients SHOULD re-fetch after this window.
/// RFC-ACDP-0005 §3 leaves the exact value to implementations; 1 hour
/// matches the common "≥1h" cursor-validity expectation.
const CURSOR_TTL: chrono::Duration = chrono::Duration::seconds(3600);

/// Opaque cursor encoding — base64 of
/// `<mint_unix_ms>:<created_at_millis>:<ctx_id>`.
///
/// The `mint_unix_ms` prefix lets [`decode_cursor`] enforce the
/// `CURSOR_TTL` window and surface `AcdpError::CursorExpired` rather
/// than silently accepting an ancient cursor (FEAT-04). Plain
/// `STANDARD` engine so cursors are stable across machines.
fn encode_cursor(created_at_ms: i64, ctx_id: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mint_ms = chrono::Utc::now().timestamp_millis();
    STANDARD.encode(format!("{mint_ms}:{created_at_ms}:{ctx_id}"))
}

fn decode_cursor(s: &str) -> Result<Option<(i64, String)>, AcdpError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let bytes = STANDARD
        .decode(s)
        .map_err(|_| AcdpError::InvalidCursor("cursor is not valid base64".into()))?;
    let decoded = String::from_utf8(bytes)
        .map_err(|_| AcdpError::InvalidCursor("cursor is not utf-8".into()))?;
    // Format: "<mint_ms>:<anchor_ms>:<ctx_id>". The mint timestamp
    // prefix is FEAT-04 expiry tracking.
    let mut parts = decoded.splitn(3, ':');
    let mint_str = parts
        .next()
        .ok_or_else(|| AcdpError::InvalidCursor("cursor missing mint timestamp".into()))?;
    let anchor_str = parts
        .next()
        .ok_or_else(|| AcdpError::InvalidCursor("cursor missing anchor timestamp".into()))?;
    let ctx_id = parts
        .next()
        .ok_or_else(|| AcdpError::InvalidCursor("cursor missing ctx_id".into()))?;
    let mint_ms: i64 = mint_str
        .parse()
        .map_err(|_| AcdpError::InvalidCursor("cursor mint millis is not an integer".into()))?;
    let anchor_ms: i64 = anchor_str
        .parse()
        .map_err(|_| AcdpError::InvalidCursor("cursor anchor millis is not an integer".into()))?;

    // FEAT-04: reject cursors older than CURSOR_TTL with the
    // dedicated `cursor_expired` wire code so clients can distinguish
    // "you typo'd the cursor" (InvalidCursor) from "your cursor aged
    // out, restart the scan from page 1" (CursorExpired).
    let now = chrono::Utc::now().timestamp_millis();
    let age_ms = now.saturating_sub(mint_ms);
    if age_ms > CURSOR_TTL.num_milliseconds() {
        // CursorExpired is a unit variant in the wire-error mapping;
        // the diagnostic ("aged Xms ago") is intentionally surfaced
        // via Display rather than a payload so it round-trips through
        // `AcdpError::from_wire_error`.
        return Err(AcdpError::CursorExpired);
    }
    Ok(Some((anchor_ms, ctx_id.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_crypto::SigningKey;
    use acdp_producer::Producer;
    use acdp_types::body::{DataPeriod, Signature};
    use acdp_types::primitives::{AgentDid, ContentHash, ContextType, Visibility};
    use chrono::Utc;

    fn fake_body(ctx_id: &str, lineage_id: &str, title: &str) -> Body {
        Body {
            ctx_id: CtxId(ctx_id.into()),
            lineage_id: LineageId(lineage_id.into()),
            origin_registry: "registry.example.com".into(),
            created_at: Utc::now(),
            content_hash: ContentHash("sha256:0".into()),
            signature: Signature {
                algorithm: "ed25519".into(),
                key_id: "did:web:agents.example.com:test#key-1".into(),
                value: "A".repeat(88),
            },
            version: 1,
            supersedes: None,
            agent_id: AgentDid::new("did:web:agents.example.com:test"),
            contributors: vec![],
            title: title.into(),
            context_type: ContextType::DataSnapshot,
            data_refs: vec![],
            derived_from: vec![],
            visibility: Visibility::Public,
            audience: None,
            acdp_version: None,
            description: None,
            summary: None,
            tags: None,
            domain: None,
            expires_at: None,
            data_period: None,
            metadata: None,
            schema_uri: None,
            anchors: None,
            extensions: Default::default(),
        }
    }

    #[test]
    fn put_get_round_trip() {
        let s = InMemoryStore::new();
        let id = "acdp://r/12345678-1234-4321-8123-123456781234";
        let lin = "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111";
        s.put(fake_body(id, lin, "A")).unwrap();
        let got = s.get(&CtxId(id.into())).unwrap().unwrap();
        assert_eq!(got.body.title, "A");
        assert!(matches!(got.registry_state.status, Status::Active));
    }

    #[test]
    fn lineage_orders_by_publish_order() {
        let s = InMemoryStore::new();
        let lin = "lin:sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let v1 = "acdp://r/12345678-1234-4321-8123-000000000001";
        let v2 = "acdp://r/12345678-1234-4321-8123-000000000002";
        s.put(fake_body(v1, lin, "v1")).unwrap();
        s.put(fake_body(v2, lin, "v2")).unwrap();
        let lineage = s.lineage(&LineageId(lin.into())).unwrap();
        assert_eq!(lineage.len(), 2);
        assert_eq!(lineage[0].body.title, "v1");
        assert_eq!(lineage[1].body.title, "v2");
    }

    #[test]
    fn supersession_marks_predecessor() {
        let s = InMemoryStore::new();
        let lin = "lin:sha256:3333333333333333333333333333333333333333333333333333333333333333";
        let v1 = "acdp://r/12345678-1234-4321-8123-000000000003";
        s.put(fake_body(v1, lin, "v1")).unwrap();
        s.mark_superseded(&CtxId(v1.into())).unwrap();
        let got = s.get(&CtxId(v1.into())).unwrap().unwrap();
        assert!(matches!(got.registry_state.status, Status::Superseded));
    }

    // BUG-11 — Status::Expired derived from body.expires_at at read time.

    fn expired_body(
        ctx_id: &str,
        lineage_id: &str,
        title: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Body {
        let mut b = fake_body(ctx_id, lineage_id, title);
        b.expires_at = Some(expires_at);
        b
    }

    #[test]
    fn get_projects_active_to_expired_when_past_expires_at() {
        use chrono::Duration;
        let s = InMemoryStore::new();
        let lin = "lin:sha256:5555555555555555555555555555555555555555555555555555555555555555";
        let id = "acdp://r/12345678-1234-4321-8123-000000000006";
        s.put(expired_body(
            id,
            lin,
            "old",
            chrono::Utc::now() - Duration::hours(1),
        ))
        .unwrap();
        let got = s.get(&CtxId(id.into())).unwrap().unwrap();
        assert!(
            matches!(got.registry_state.status, Status::Expired),
            "expected Status::Expired projection, got {:?}",
            got.registry_state.status
        );
    }

    #[test]
    fn get_keeps_active_when_expires_at_in_future() {
        use chrono::Duration;
        let s = InMemoryStore::new();
        let lin = "lin:sha256:6666666666666666666666666666666666666666666666666666666666666666";
        let id = "acdp://r/12345678-1234-4321-8123-000000000007";
        s.put(expired_body(
            id,
            lin,
            "fresh",
            chrono::Utc::now() + Duration::hours(1),
        ))
        .unwrap();
        let got = s.get(&CtxId(id.into())).unwrap().unwrap();
        assert!(matches!(got.registry_state.status, Status::Active));
    }

    #[test]
    fn search_status_active_filters_out_expired() {
        use chrono::Duration;
        let s = InMemoryStore::new();
        let lin = "lin:sha256:7777777777777777777777777777777777777777777777777777777777777777";
        let id = "acdp://r/12345678-1234-4321-8123-000000000008";
        s.put(expired_body(
            id,
            lin,
            "old",
            chrono::Utc::now() - Duration::hours(1),
        ))
        .unwrap();
        let resp = s.search(&SearchParams::default(), None, true).unwrap();
        assert!(
            resp.matches.is_empty(),
            "expired must not surface under status=active default"
        );
        // Asking for `expired` SHOULD surface it.
        let resp = s
            .search(
                &SearchParams {
                    status: Some("expired".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(resp.matches.len(), 1);
    }

    /// BUG-10 — date/time filter is honored.
    #[test]
    fn search_filters_by_created_after() {
        let s = InMemoryStore::new();
        let lin = "lin:sha256:8888888888888888888888888888888888888888888888888888888888888888";
        let mut body = fake_body(
            "acdp://r/12345678-1234-4321-8123-000000000009",
            lin,
            "match",
        );
        body.created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        s.put(body).unwrap();
        // `created_after` AFTER body.created_at → 0 matches
        let resp = s
            .search(
                &SearchParams {
                    created_after: Some("2026-02-01T00:00:00.000Z".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(resp.matches.len(), 0);
        // `created_after` BEFORE body.created_at → 1 match
        let resp = s
            .search(
                &SearchParams {
                    created_after: Some("2025-12-01T00:00:00.000Z".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(resp.matches.len(), 1);
    }

    #[test]
    fn search_invalid_rfc3339_filter_rejected() {
        let s = InMemoryStore::new();
        let err = s
            .search(
                &SearchParams {
                    created_after: Some("not-a-date".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }

    /// BUG-10 cursor round-trips and pages correctly.
    #[test]
    fn search_cursor_pages_results() {
        let s = InMemoryStore::new();
        let lin = "lin:sha256:9999999999999999999999999999999999999999999999999999999999999999";
        // Insert 5 contexts with distinct created_at so order is deterministic.
        let base = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for i in 0..5u8 {
            let mut body = fake_body(
                &format!("acdp://r/12345678-1234-4321-8123-00000000010{i}"),
                lin,
                "match",
            );
            body.created_at = base + chrono::Duration::minutes(i as i64);
            s.put(body).unwrap();
        }
        let p1 = s
            .search(
                &SearchParams {
                    limit: Some(2),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(p1.matches.len(), 2);
        let cursor = p1.next_cursor.expect("page 1 should carry a cursor");
        let p2 = s
            .search(
                &SearchParams {
                    limit: Some(2),
                    cursor: Some(cursor.clone()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(p2.matches.len(), 2);
        // No overlap between page 1 and page 2.
        for r in &p2.matches {
            assert!(
                !p1.matches.iter().any(|q| q.ctx_id == r.ctx_id),
                "page 2 overlapped page 1"
            );
        }
        // BUG-08: total_estimate MUST be stable across pages — captured
        // BEFORE cursor filtering. Before the fix, page 2 reported a
        // smaller total than page 1 (the remaining-from-cursor count).
        assert_eq!(
            p1.total_estimate, p2.total_estimate,
            "total_estimate MUST be stable across pages (BUG-08); \
             p1={:?}, p2={:?}",
            p1.total_estimate, p2.total_estimate
        );
        assert_eq!(
            p1.total_estimate,
            Some(5),
            "total_estimate MUST reflect total matches across all pages, got {:?}",
            p1.total_estimate
        );
    }

    #[test]
    fn search_limit_zero_does_not_underflow() {
        // P1-1: limit=0 with ≥1 match previously computed `limit - 1`
        // (debug panic / release wrap). It MUST be clamped to ≥1.
        let s = InMemoryStore::new();
        let lin = "lin:sha256:8888888888888888888888888888888888888888888888888888888888888888";
        for i in 0..3u8 {
            let body = fake_body(
                &format!("acdp://r/12345678-1234-4321-8123-00000000020{i}"),
                lin,
                "match",
            );
            s.put(body).unwrap();
        }
        let page = s
            .search(
                &SearchParams {
                    limit: Some(0),
                    ..Default::default()
                },
                None,
                true,
            )
            .expect("limit=0 must not panic or error");
        // Clamped to 1: one result, and a cursor since more remain.
        assert_eq!(page.matches.len(), 1);
        assert!(page.next_cursor.is_some());
    }

    #[test]
    fn search_malformed_cursor_rejected() {
        let s = InMemoryStore::new();
        let err = s
            .search(
                &SearchParams {
                    cursor: Some("not_base64!@#".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap_err();
        assert!(matches!(err, AcdpError::InvalidCursor(_)));
    }

    /// FEAT-04: a cursor whose embedded mint timestamp is older than
    /// `CURSOR_TTL` MUST surface as `CursorExpired`, not `InvalidCursor`.
    /// Clients distinguish "you typo'd the cursor" from "your cursor
    /// aged out, restart the scan from page 1".
    #[test]
    fn search_aged_cursor_rejected_as_cursor_expired() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let s = InMemoryStore::new();
        // Mint a cursor 7200s in the past — twice the 3600s TTL.
        let stale_mint_ms = chrono::Utc::now().timestamp_millis() - 7200 * 1000;
        let aged = STANDARD.encode(format!(
            "{stale_mint_ms}:0:acdp://r/12345678-1234-4321-8123-1234567812aa"
        ));
        let err = s
            .search(
                &SearchParams {
                    cursor: Some(aged),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap_err();
        assert!(
            matches!(err, AcdpError::CursorExpired),
            "expired cursor MUST surface CursorExpired, got {err:?}"
        );
    }

    #[test]
    fn search_filters_by_status_default_active() {
        let s = InMemoryStore::new();
        let lin = "lin:sha256:4444444444444444444444444444444444444444444444444444444444444444";
        let v1 = "acdp://r/12345678-1234-4321-8123-000000000004";
        let v2 = "acdp://r/12345678-1234-4321-8123-000000000005";
        s.put(fake_body(v1, lin, "old")).unwrap();
        s.put(fake_body(v2, lin, "new")).unwrap();
        s.mark_superseded(&CtxId(v1.into())).unwrap();
        let resp = s
            .search(
                &SearchParams {
                    q: Some("old".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        // Only `active` matches — superseded "old" filtered out.
        assert_eq!(resp.matches.len(), 0);
        let resp = s
            .search(
                &SearchParams {
                    q: Some("new".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(resp.matches.len(), 1);
    }

    /// End-to-end: producer → server pipeline using the actual signing
    /// path. Uses a builder and the `RegistryServer` (see server.rs)
    /// to confirm the integration story.
    #[test]
    fn store_round_trip_from_real_publish_request() {
        use crate::registry::server::RegistryServer;
        use acdp_types::capabilities::{CapabilitiesDocument, Limits};

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let p = Producer::new(
            key,
            AgentDid::new("did:web:agents.example.com:test"),
            "did:web:agents.example.com:test#key-1",
        );
        let req = p
            .publish_request()
            .title("hello")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();

        let caps = CapabilitiesDocument {
            acdp_version: "0.1.0".into(),
            registry_did: "did:web:registry.example.com".into(),
            supported_signature_algorithms: vec!["ed25519".into()],
            supported_did_methods: vec!["did:web".into()],
            profiles: vec!["acdp-registry-core".into()],
            limits: Limits {
                max_payload_bytes: 1_048_576,
                max_embedded_bytes: 65_536,
                idempotency_key_ttl_seconds: None,
                max_publish_per_minute: None,
            },
            read_authentication_methods: vec![],
            anonymous_public_reads: true,
            supports_idempotency_key: false,
            extensions: Default::default(),
        };

        let server = RegistryServer::new(InMemoryStore::new(), caps, "registry.example.com");
        let resp = server.publish_unverified_for_tests(&req).unwrap();
        assert_eq!(resp.version, 1);
        let ctx = server.retrieve(&resp.ctx_id, None).unwrap().unwrap();
        assert_eq!(ctx.body.title, "hello");

        // Ignore unused imports under different feature combinations
        let _: Option<DataPeriod> = ctx.body.data_period.clone();
    }
}

#[cfg(test)]
mod publish_commit_outcome_tests {
    use super::*;
    use acdp_types::publish::PublishResponse;
    use acdp_types::Status;

    fn response(version: u32) -> PublishResponse {
        PublishResponse {
            registry_receipt: None,
            ctx_id: acdp_types::CtxId(
                "acdp://registry.example.com/12345678-1234-4321-8123-000000000099".into(),
            ),
            lineage_id: acdp_types::LineageId(
                "lin:sha256:9999999999999999999999999999999999999999999999999999999999999999"
                    .into(),
            ),
            version,
            created_at: chrono::Utc::now(),
            status: Status::Active,
        }
    }

    /// `is_replay` is the whole point of this type surviving past
    /// `commit_via_store`, so it is asserted on BOTH variants rather than
    /// only on the interesting one: a `matches!` that had been written
    /// against the wrong variant passes a one-sided test.
    #[test]
    fn is_replay_discriminates_both_ways() {
        assert!(
            !PublishCommitOutcome::Inserted(response(1)).is_replay(),
            "a fresh insert must not report as a replay — a registry reading \
             this answers 200 instead of 201 Created"
        );
        assert!(
            PublishCommitOutcome::IdempotentReplay(response(1)).is_replay(),
            "a replay must report as one — a registry reading this answers \
             201 Created to a retry, which idem-002 forbids explicitly"
        );
    }

    /// Both variants must yield their OWN response, not a fixed arm. An
    /// `into_response` mistakenly written as `Self::Inserted(r) => r, _ =>
    /// <the other one>` is caught by varying `version` per variant rather
    /// than reusing one value — the field is read, so the assertion cannot
    /// pass on a response the test never built.
    #[test]
    fn into_response_and_response_yield_the_carried_value_on_both_variants() {
        let inserted = PublishCommitOutcome::Inserted(response(1));
        let replayed = PublishCommitOutcome::IdempotentReplay(response(7));

        assert_eq!(inserted.response().version, 1);
        assert_eq!(replayed.response().version, 7);

        // `response()` borrows, so the outcome is still usable afterwards —
        // that is the property the registry needs (inspect, then consume).
        assert_eq!(inserted.into_response().version, 1);
        assert_eq!(replayed.into_response().version, 7);
    }
}
