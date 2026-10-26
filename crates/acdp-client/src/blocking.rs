//! Synchronous, runtime-agnostic facade over the async client (feature
//! `blocking`).
//!
//! [`BlockingClient`] lets synchronous code (a sync trait impl, a plugin
//! host, a thread pool) call [`RegistryClient`], [`VerifiedContext`],
//! [`CrossRegistryResolver`] and [`verify_change`] without owning a tokio
//! runtime:
//!
//! - **Its own runtime.** Every call runs on a small multi-threaded tokio
//!   runtime that the facade starts on a dedicated thread and shuts down
//!   on that same thread when the last clone is dropped. The caller's
//!   thread only waits, so the facade works from plain threads and from
//!   inside an existing tokio runtime alike, without the "cannot start a
//!   runtime from within a runtime" panic.
//! - **A hard per-call deadline.** Each method takes a
//!   [`std::time::Instant`]. When it passes, the call returns
//!   [`AcdpError::DeadlineExceeded`] and the in-flight work is cancelled.
//!   No partial result is ever returned: a deadline fails closed. A
//!   deadline already in the past fails without issuing any request.
//! - **Thread-safe.** [`BlockingClient`] is `Clone + Send + Sync`; clones
//!   share the runtime and the underlying clients, so one instance can
//!   serve many threads concurrently.
//!
//! Give the facade its own [`RegistryClient`], [`WebResolver`] and
//! [`CrossRegistryResolver`] rather than sharing instances that are also
//! used on another runtime: an HTTP connection is driven by the runtime
//! that opened it, and a pooled connection whose runtime has gone fails
//! on reuse.
//!
//! Called from inside a tokio runtime, the facade blocks the calling
//! worker thread while it waits (on a multi-threaded runtime it first
//! hands the worker's other tasks off with
//! `tokio::task::block_in_place`). Async callers should prefer the async
//! API; the facade is for code that cannot be async.
//!
//! ```no_run
//! use std::time::{Duration, Instant};
//! use acdp_client::blocking::BlockingClient;
//! use acdp_client::{RegistryClient, VerificationPolicy};
//! use acdp_did::WebResolver;
//! use acdp_types::CtxId;
//!
//! # fn main() -> Result<(), acdp_primitives::error::AcdpError> {
//! let client = BlockingClient::new(
//!     RegistryClient::new("https://registry.example.com")?,
//!     WebResolver::new(),
//! )?;
//! let ctx_id = CtxId(
//!     "acdp://registry.example.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
//! );
//! let deadline = Instant::now() + Duration::from_secs(2);
//! let verified =
//!     client.fetch_verified(&ctx_id, &VerificationPolicy::default(), deadline)?;
//! println!("{}", verified.body().ctx_id);
//! # Ok(())
//! # }
//! ```

use std::future::Future;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Instant;

use acdp_did::WebResolver;
use acdp_primitives::error::AcdpError;
use acdp_types::body::{Body, FullContext};
use acdp_types::change::{Change, ChangesResponse, WatchFilter};
use acdp_types::primitives::{CtxId, LineageId};
use serde_json::Value;

use crate::recall::{verify_change, ChangeVerdict, HeldContext, Since};
use crate::{CrossRegistryResolver, RegistryClient, VerificationPolicy, VerifiedContext};

/// Default number of runtime worker threads (see
/// [`BlockingClient::with_worker_threads`]).
pub const DEFAULT_WORKER_THREADS: usize = 2;

/// The facade's runtime. The runtime itself lives on `acdp-blocking-rt`,
/// which blocks on `shutdown` and then drops the runtime there: dropping a
/// runtime from async context panics, and the last [`BlockingClient`]
/// clone may well be dropped inside one.
struct Executor {
    handle: tokio::runtime::Handle,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl Executor {
    fn start(worker_threads: usize) -> Result<Self, AcdpError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads.max(1))
            .thread_name("acdp-blocking-worker")
            .enable_all()
            .build()
            .map_err(|e| AcdpError::Http(format!("blocking facade: runtime start failed: {e}")))?;
        let handle = rt.handle().clone();
        let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
        std::thread::Builder::new()
            .name("acdp-blocking-rt".into())
            .spawn(move || {
                // Err means the sender dropped: the last clone is gone.
                let _ = rt.block_on(stopped);
                rt.shutdown_background();
            })
            .map_err(|e| AcdpError::Http(format!("blocking facade: thread start failed: {e}")))?;
        Ok(Self {
            handle,
            _shutdown: shutdown,
        })
    }

    /// Run `fut` on the facade runtime and wait for it until `deadline`.
    fn run<T, F>(&self, deadline: Instant, fut: F) -> Result<T, AcdpError>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, AcdpError>> + Send + 'static,
    {
        let expired = || AcdpError::DeadlineExceeded("blocking call did not finish in time".into());
        if Instant::now() >= deadline {
            return Err(expired());
        }
        let (tx, rx) = mpsc::sync_channel(1);
        let task = self.handle.spawn(async move {
            let out = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), fut)
                .await
                .unwrap_or_else(|_| Err(expired()));
            let _ = tx.send(out);
        });
        let wait = || {
            let left = deadline.saturating_duration_since(Instant::now());
            rx.recv_timeout(left)
        };
        let received = match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
            Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(wait),
            _ => wait(),
        };
        match received {
            Ok(out) => out,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                task.abort();
                Err(expired())
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(AcdpError::Http(
                "blocking facade: task ended without a result".into(),
            )),
        }
    }
}

struct Inner {
    exec: Executor,
    client: RegistryClient,
    resolver: WebResolver,
}

/// A synchronous client with a hard per-call deadline. See the
/// [module docs](self).
#[derive(Clone)]
pub struct BlockingClient {
    inner: Arc<Inner>,
    cross: Option<Arc<CrossRegistryResolver>>,
}

impl std::fmt::Debug for BlockingClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingClient")
            .field("cross_registry", &self.cross.is_some())
            .finish_non_exhaustive()
    }
}

impl BlockingClient {
    /// Wrap `client` (the registry every call goes to) and `resolver`
    /// (DID resolution for verification), with
    /// [`DEFAULT_WORKER_THREADS`] runtime workers.
    pub fn new(client: RegistryClient, resolver: WebResolver) -> Result<Self, AcdpError> {
        Self::with_worker_threads(client, resolver, DEFAULT_WORKER_THREADS)
    }

    /// As [`Self::new`], with `worker_threads` runtime workers (at least
    /// one). More workers let more concurrent calls verify signatures in
    /// parallel; network waits do not need them.
    pub fn with_worker_threads(
        client: RegistryClient,
        resolver: WebResolver,
        worker_threads: usize,
    ) -> Result<Self, AcdpError> {
        Ok(Self {
            inner: Arc::new(Inner {
                exec: Executor::start(worker_threads)?,
                client,
                resolver,
            }),
            cross: None,
        })
    }

    /// Enable [`Self::resolve`] with `resolver`. The result shares this
    /// client's runtime; clones made before the call keep their previous
    /// configuration.
    pub fn with_cross_registry(mut self, resolver: CrossRegistryResolver) -> Self {
        self.cross = Some(Arc::new(resolver));
        self
    }

    /// The wrapped registry client.
    pub fn client(&self) -> &RegistryClient {
        &self.inner.client
    }

    /// The wrapped DID resolver.
    pub fn resolver(&self) -> &WebResolver {
        &self.inner.resolver
    }

    /// Run any future against the wrapped clients under `deadline`. The
    /// escape hatch for async APIs without a dedicated method: `f`
    /// receives a handle to this client and returns the future to run.
    ///
    /// ```no_run
    /// # use std::time::{Duration, Instant};
    /// # use acdp_client::blocking::BlockingClient;
    /// # fn f(c: &BlockingClient) -> Result<(), acdp_primitives::error::AcdpError> {
    /// let caps = c.run(Instant::now() + Duration::from_secs(1), |c| async move {
    ///     c.client().capabilities().await
    /// })?;
    /// # Ok(()) }
    /// ```
    pub fn run<T, F, Fut>(&self, deadline: Instant, f: F) -> Result<T, AcdpError>
    where
        T: Send + 'static,
        F: FnOnce(BlockingClient) -> Fut,
        Fut: Future<Output = Result<T, AcdpError>> + Send + 'static,
    {
        self.inner.exec.run(deadline, f(self.clone()))
    }

    /// [`RegistryClient::retrieve`]: the context as served, unverified.
    pub fn retrieve(&self, ctx_id: &CtxId, deadline: Instant) -> Result<FullContext, AcdpError> {
        let ctx_id = ctx_id.clone();
        self.run(
            deadline,
            |c| async move { c.client().retrieve(&ctx_id).await },
        )
    }

    /// [`VerifiedContext::fetch_with_policy`]: retrieve and verify.
    pub fn fetch_verified(
        &self,
        ctx_id: &CtxId,
        policy: &VerificationPolicy,
        deadline: Instant,
    ) -> Result<VerifiedContext, AcdpError> {
        let (ctx_id, policy) = (ctx_id.clone(), policy.clone());
        self.run(deadline, |c| async move {
            VerifiedContext::fetch_with_policy(c.client(), c.resolver(), &ctx_id, &policy).await
        })
    }

    /// [`VerifiedContext::fetch_current_with_policy`]: retrieve and verify
    /// a lineage's current head.
    pub fn fetch_current_verified(
        &self,
        lineage_id: &LineageId,
        policy: &VerificationPolicy,
        deadline: Instant,
    ) -> Result<VerifiedContext, AcdpError> {
        let (lineage_id, policy) = (lineage_id.clone(), policy.clone());
        self.run(deadline, |c| async move {
            VerifiedContext::fetch_current_with_policy(
                c.client(),
                c.resolver(),
                &lineage_id,
                &policy,
            )
            .await
        })
    }

    /// [`CrossRegistryResolver::resolve`]: resolve and verify a context at
    /// whichever registry `ctx_id` names. Requires
    /// [`Self::with_cross_registry`]; otherwise fails with
    /// [`AcdpError::SchemaViolation`] without issuing a request.
    pub fn resolve(&self, ctx_id: &CtxId, deadline: Instant) -> Result<VerifiedContext, AcdpError> {
        let Some(cross) = self.cross.clone() else {
            return Err(AcdpError::SchemaViolation(
                "BlockingClient::resolve needs with_cross_registry".into(),
            ));
        };
        let ctx_id = ctx_id.clone();
        self.run(deadline, |_| async move { cross.resolve(&ctx_id).await })
    }

    /// [`RegistryClient::changes`]: one page of the changes feed. Entries
    /// are hints until [`Self::verify_change`] passes.
    pub fn changes(
        &self,
        since: &Since,
        filter: &WatchFilter,
        limit: Option<u32>,
        deadline: Instant,
    ) -> Result<ChangesResponse, AcdpError> {
        let (since, filter) = (since.clone(), filter.clone());
        self.run(deadline, move |c| async move {
            c.client().changes(&since, &filter, limit).await
        })
    }

    /// [`verify_change`] (RFC-ACDP-0018 §7). `held` is copied, so the
    /// borrow ends when this returns. `Ok(Rejected)` is a final verdict;
    /// `Err` (including [`AcdpError::DeadlineExceeded`]) means the entry
    /// was not decided and should be retried.
    pub fn verify_change(
        &self,
        change: &Change,
        held: Option<HeldContext<'_>>,
        policy: &VerificationPolicy,
        deadline: Instant,
    ) -> Result<ChangeVerdict, AcdpError> {
        let change = change.clone();
        let held: Option<(Body, Vec<Value>)> = held.map(|h| (h.body.clone(), h.events.to_vec()));
        let policy = policy.clone();
        self.run(deadline, |c| async move {
            let held = held
                .as_ref()
                .map(|(body, events)| HeldContext { body, events });
            verify_change(c.client(), c.resolver(), &change, held, &policy).await
        })
    }
}
