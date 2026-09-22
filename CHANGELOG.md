# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- *(server)* split `RegistryServer`'s publish pipeline into a `prove_publish_identity*` /
  `commit_proven` pair, alongside the existing composed entry points
  ([#273](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/273)).
  `prove_publish_identity` (did:web), `prove_publish_identity_did_key`, and
  `prove_publish_identity_pinned` each run RFC-ACDP-0003 §2.1 steps 1-8 (plus the
  RFC-ACDP-0014 §5 step 2 self-revocation check, where applicable) and return an opaque
  `Proven<'a>` — proof that a request's identity was cryptographically established —
  without persisting anything. `commit_proven(proven, idempotency_key, tenant)` completes
  the publish via the same atomic store commit the existing entry points already use.
  `Proven` has no public constructor and is not `Clone`: the only way to produce one is a
  successful `prove_publish_identity*` call, and it is a move-only, one-shot value, so a
  proof can't be committed twice. `commit_proven` also rejects a `Proven` established
  against a different registry authority. This lets a caller (e.g. a rate-limit charge
  that should only ever apply once identity is genuinely established) gate a side effect
  strictly between proof and commit, without duplicating the verification pipeline by
  hand — `publish_verified_in_tenant_with_outcome` and its `_did_key`/`_pinned` siblings
  are now one-line compositions of `prove_*` + `commit_proven`, unchanged in behavior.
  Purely additive.

### Changed

- **[BREAKING] `acdp-types`'s `EmbeddedContent` gained a new field, `content_hash`, and
  `acdp-validation`'s Check-8 publish-time integrity check now verifies it** ([#284](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/284)).
  RFC-ACDP-0002 §6.3/§6.6 (spec commit `16211e6`) codify a DataRef-embedded payload's own
  `content_hash` member, distinct from the DataRef-root `content_hash` (§6.1) — a DataRef MAY
  carry both over the same decoded bytes. `verify_embedded_hash` (`crates/acdp-validation`)
  previously read only the root field even for embedded refs, which was actually a bug: it meant
  the SDK could not model or verify §6.6's real Check-8 obligation at all. It now checks both
  fields when both are present — the embedded field (the spec's new, primary obligation) and the
  pre-existing root field (kept intentionally, not dropped, since §6.6 only makes the root check
  optional for embedded refs, never forbidden, and this repo's own consumer-side `location`-form
  fetch verification already depends on that root-check code path). A mismatch on either field is
  `AcdpError::DataRefHashMismatch`. `EmbeddedContent` is a plain `pub struct` (not
  `#[non_exhaustive]`), so this field addition breaks any external `EmbeddedContent { encoding,
  content }` struct-literal construction — callers must add `content_hash: None`/`Some(..)`.

- **[BREAKING] did:key resolver faults surfaced by `acdp-validation` no longer downgrade to
  `schema_violation`** ([#285](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/285)).
  `validate_did_key_key_id_form` and `validate_agent_did` previously wrapped every did:key
  resolver error (RFC-ACDP-0001 §5.11.1 steps 1-4) in `AcdpError::SchemaViolation`. The spec
  (commit `16211e6`) settles that `key_resolution_failed` is the REQUIRED code for these faults;
  `schema_violation` is only a MAY-level tolerance for a registry's own stricter grammar, and only
  for specific steps (`dk-002`'s `alternative_applies_to_cases: [1, 2]`), never a blanket
  requirement. Both functions now propagate the resolver's own `AcdpError::KeyResolution`
  directly. Listed as breaking because it changes the concrete error variant/wire code a caller
  observes for a case that was previously rejected, even though the request is still rejected
  either way.

- **[BREAKING] `acdp-server` registries advertising `acdp_version >= 0.5.0` now enforce
  RFC-ACDP-0014 §4/§10's 0.5.0 registry amendments; `SupersessionReason` gained a new
  variant and is now `#[non_exhaustive]`**.
  A non-revocation context superseding a `key-revocation` (or interim `acdp:key-revocation`)
  target is now rejected with `AcdpError::SupersededTarget { reason:
  SupersessionReason::RevocationTypeMismatch, .. }` instead of `SchemaViolation`, on
  registries advertising `acdp_version >= 0.5.0` (RFC-ACDP-0014 §4). Below 0.5.0 the
  rejection is unchanged — still `SchemaViolation` — since weakening it there would be a
  security regression with no conformance upside (nothing requires accepting the
  supersession below 0.5.0). Additionally, a `>= 0.5.0` registry now rejects any *new*
  publish typed as the interim `acdp:key-revocation` form outright, unconditionally,
  regardless of `supersedes` (RFC-ACDP-0014 §10 — the interim form is retired at 0.5.0 in
  favor of the standard `key-revocation` context_type). Below 0.5.0, the interim form is
  still accepted and §4-validated exactly as before. `SupersessionReason` gained
  `RevocationTypeMismatch` and is now `#[non_exhaustive]` (safe: its variants are unit-like,
  so no external struct-literal construction site breaks; only external exhaustive `match`
  arms need a wildcard now). A malformed `acdp_version` string fails closed toward
  rejecting (matching the existing §4 gate's polarity) but never claims the new error code —
  it still surfaces as `SchemaViolation`, since the new code is reserved for registries that
  legitimately declare `>= 0.5.0`.

### Fixed

- *(client)* restore `Send` on every public async entry point that discovers revocations
  ([#279](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/279)).
  0.13.2 accidentally made `find_revocations`, `find_registry_attested_revocations`,
  `VerifiedContext::fetch`/`fetch_with_policy`/`fetch_current`/`fetch_current_with_policy`/
  `fetch_report`, and `CrossRegistryResolver::resolve`/`walk_derived_from` all `!Send`:
  `discover_revocations` (`crates/acdp-client/src/revocation.rs`) holds two `&dyn Fn(..)`
  closure parameters across an `.await` point, and `&dyn Fn` is `Send` only when the trait
  object itself is `Sync` — the parameters were missing that bound. This broke
  `axum::handler::Handler` compatibility (and any other executor requiring `Send` futures)
  for every caller doing cross-registry resolution. Fixed by adding `+ Sync` to both
  parameters. A new compile-only regression test, `tests/send_futures.rs`, asserts `Send`
  for all nine affected entry points.

## [0.13.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.13.1...acdp-v0.13.2) - 2026-09-13

### Added

- *(primitives)* type the `unsupported_media_type` wire code (415) as
  `AcdpError::UnsupportedMediaType`
  ([#268](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/268))

  RFC-ACDP-0007 §4.1/§5 gained the code on the 0.5.0 line (spec #68), growing
  `acdp-error.schema.json`'s closed enum from 25 to 26. Until now the code
  deserialized into the untyped `AcdpError::Registry` catch-all. It is
  deliberately **not** in `is_transient`: retrying a request with the same
  `Content-Type` gets the same 415.

  Additive on a `#[non_exhaustive]` enum, so matching downstream code keeps
  compiling.

### Changed

- *(ci)* adopt spec `108ff76` (was `d1f06d0`), which brings in
  `err-002-unsupported-media-type` and `examples/error/unsupported-media-type.json`

### Fixed

- *(test)* `error_example_deserializes` checked one hard-coded filename, so every
  error example the spec added after it was written went unexercised — it now
  scans `examples/error/` and asserts each code maps to a typed variant. A new
  `wire_error_codes_cover_the_spec_enum` reads the enum out of the pinned
  `acdp-error.schema.json` directly, so a future pin bump that adopts a 27th code
  fails until the three-edit rule is followed rather than passing silently.

### Other

- close out the #240/#252/#249 assumption and record this pass
- *(decisions)* record the #268/#252/#259/#265/#249/#264 wrap-up decisions

## [0.13.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.13.0...acdp-v0.13.1) - 2026-09-12

### Added

- *(client)* revocation discovery budget, cache, and resolver injection (#257, #258, #260) ([#263](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/263))

- *(client)* cache RFC-ACDP-0014 §8 revocation-discovery results
  ([#257](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/257))

  A new `RevocationCache` (`RegistryClient::with_revocation_cache`) is two objects sharing
  one lock, not one. **Facts** — verified `KeyRevocation`s discovery finds — are always
  unioned into classification, indefinitely, per §7:114's "cache
  verified revocations indefinitely": a revocation is monotone, so seeding from cached
  facts can only tighten a verdict, never loosen one, making the fact store an
  anti-rollback control rather than a performance feature — a registry that serves a
  revocation once and later hides it (or goes offline) cannot make an already-warmed
  client forget it. This seeding happens even when a call sets `discover: None` (attaching
  a cache is itself the opt-in, independent of whether that call runs live discovery),
  which is what extends the protection to `VerifiedContext::fetch`/`fetch_current` — the
  `discover: None` path seeds producer-signed facts only, never registry-attested ones.
  A **producer-signed** fact is self-contained (§8) and applies regardless of which
  registry served it; a **registry-attested** one is additionally tagged with the vantage
  that minted it and applies only when read back through a client talking to that SAME
  vantage (§6 scopes it to "contexts served by or receipted by that same registry") — so
  sharing one cache across clients for two different registries never lets registry A's
  attestation apply to a context served by registry B. **Freshness markers** — "vantage V
  completed a full, untruncated discovery for this producer/trust-class at time T" — are a
  cached *absence*, which
  §7:114 does not license and §8 explicitly warns about; they are bounded by a new
  `RevocationDiscovery::freshness: Duration` field (`Copy`-preserving, additive,
  defaulting to `Duration::ZERO` — off — from both named constructors), per vantage, per
  trust class, and minted only on a fully successful, untruncated discovery — never on a
  transport error, a `SearchTruncated`, a budget exhaustion, or a `total_timeout` trip, so
  a transient blip can never become a silent window-long downgrade. With the default
  `freshness: ZERO`, attaching a cache saves zero requests and changes nothing observable
  except anti-rollback. No new Cargo dependency: the bound is hand-rolled (a capacity-
  triggered `Mutex<HashMap<..>>`, following `CrossRegistryResolver`'s existing
  `client_cache`/`caps_cache` pattern), matching the plan's `bindings/*/Cargo.lock`
  constraint. `crates/acdp-client/src/revocation.rs` gains only the marker check/record
  calls at the top and tail of `find_revocations` / `find_registry_attested_revocations`;
  the fact union itself lives downstream, at `verify_retrieved`'s `effective` merge, so a
  cached fact survives every induced discovery failure on this call (the security-critical
  placement issue #257's design calls B1).

- *(client)* bound revocation auto-discovery by request count and cumulative bytes, not
  just wall clock ([#258](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/258))

  `RevocationDiscovery::total_timeout` only ever bounded wall clock — a hostile-but-fast
  registry could still drive thousands of requests and megabytes of traffic well inside
  the timeout (see the type's own worst-case numbers: ~6,160 requests / ~6.1 GB
  producer-signed-only, ~12,321 / ~12.2 GB for both trust classes). `RevocationDiscovery`
  gains two additive, `Copy` fields — `max_requests: Option<NonZeroUsize>` and
  `max_bytes: Option<u64>` — both `None` (unbounded) from `producer_signed_only()` and
  `all_trust_classes()`, so existing callers see byte-identical behavior. When set, the
  two knobs bound the **combined** total across BOTH trust-class lookups: enabling
  `include_registry_attested` does not double the ceiling. Enforcement lives inside
  `RegistryClient`'s four request methods (`capabilities`, `retrieve`, `lineage`,
  `search`), checked before each request is issued, on a client clone
  `verify_retrieved` creates once per discovery and hands to both concurrent lookups —
  the caller's original client is never charged. Exhaustion raises the new
  `AcdpError::RevocationDiscoveryBudgetExceeded`, wrapped in
  `AcdpError::RevocationDiscoveryFailed` and dispatched through `on_failure` exactly like
  the existing `SearchTruncated` case; it is never transient. No wire code (RFC-ACDP-0014
  §10 forbids one) — this is a client-side guard only. Bounds registry traffic only
  (`WebResolver` DID-document fetches are not counted) and successfully-parsed response
  bodies only (a non-success response's error-envelope read is never charged).
  `crates/acdp-client/src/revocation.rs` is unchanged by this work.

- *(client)* let `CrossRegistryResolver` carry RFC-ACDP-0014 revocation discovery
  ([#260](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/260))

  `CrossRegistryResolver` could not carry revocation auto-discovery at all (LIM-1): it
  built its own internal `VerificationPolicy` per node with no injection point, so every
  node it resolved verified with `known`-only revocations regardless of what the caller
  configured elsewhere. Closed additively with exactly three new methods —
  `with_revocation_policy(RevocationPolicy) -> Self`, `with_revocation_cache(RevocationCache)
  -> Self`, and the `revocation_policy(&self) -> &RevocationPolicy` readback — no new
  types, and `ResolverOptions` is untouched (a revocation field there would let a caller
  tuning `max_depth` via `with_options`'s "replace the complete struct" contract silently
  reset their revocation configuration). `with_revocation_policy` takes a
  `RevocationPolicy`, never a full `VerificationPolicy`: the resolver derives
  `receipts` itself, per node, from that node's own advertised capabilities (`Require`
  iff the upstream claims `acdp-registry-receipts`) — a capability-dependent escalation a
  caller cannot express statically for a walk whose authorities are not known in advance,
  so accepting a full policy would either silently override the caller's `receipts` or
  let a caller unknowingly strip `Require` on a receipts-capable upstream.

  **The cache is walk-scoped by default.** Unless `with_revocation_cache` is called,
  `CrossRegistryResolver::walk_derived_from` creates a FRESH `RevocationCache` for that
  call only and shares it across every node the walk visits. For this resolver-built
  cache, the effective `RevocationDiscovery::freshness` is derived internally from
  `ResolverOptions::total_timeout`, so discovery for a given `(authority, trust class)`
  runs at most once per walk rather than once per node, regardless of `max_nodes` — on
  genuine default configuration, with no caller action required — because no cached
  absence outlives the call. A caller-supplied cache (`with_revocation_cache`) is
  different: its own `freshness` governs unmodified, so `Duration::ZERO` (the type
  default) still suppresses nothing there — a caller who wants discovery to stay warm
  across separate walks opts in explicitly via `with_revocation_cache` and chooses that
  cache's staleness exposure themselves.

  `seed_client` is fill-if-absent, preserve-if-present: a client
  handed to (or built by) the resolver that carries no `RevocationCache` of its own is
  given the active one (walk-scoped or resolver-level); a client that already carries its
  own keeps it. Vantage binding (RFC-ACDP-0014 §6 scoping) falls out for free: discovery
  always uses the per-authority client `client_for` selects, so each node's revocations are
  discovered at the authority that actually served it. No new resolver-level request/byte
  budget — issue #258's `RevocationDiscovery::max_requests`/`max_bytes` already bound
  per-node discovery cost.

### Other

- *(decisions)* record the issue #248 revocation auto-discovery decisions

## [0.13.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.12.0...acdp-v0.13.0) - 2026-09-11

### Added

- *(client)* [**breaking**] discover revocations in the verify pipeline ([#256](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/256))

### Added

- *(client)* [**breaking**] `verify_retrieved` can auto-discover revocations instead of
  relying solely on caller-supplied ones
  ([#248](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/248))

  RFC-ACDP-0014 §8 says consumers SHOULD discover revocations rather than depend entirely
  on an out-of-band feed. `RevocationPolicy` gains `discover: Option<RevocationDiscovery>`
  alongside the existing `known`: when set, `verify_retrieved` itself runs
  `find_revocations` and (opt-in) `find_registry_attested_revocations` — concurrently,
  under one `total_timeout` — and unions the result with `known` before applying the §7
  boundary rule. `known` keeps working exactly as before; `discover` is purely additive on
  top of it. New `RevocationDiscovery` (constructed via `producer_signed_only()` or
  `all_trust_classes()` — deliberately no `Default`, since silently skipping the
  registry-attested trust class would hide RFC-ACDP-0014 §6's "lost every key" fallback),
  `DiscoveryFailurePolicy` (`FailClosed` default, or `ProceedWithKnown`), and
  `DiscoveryOutcome` (counts discovery *output* only, never `known`). New
  `AcdpError::RevocationDiscoveryFailed`, no wire code. New
  `VerifiedContext::revocation_discovery_failure()` and
  `VerificationReport::revocation_discovery` so a `ProceedWithKnown` swallow is never
  silent. Honored by all five policy-taking entry points (`fetch_with_policy`,
  `fetch_current_with_policy`, `fetch_report`, `fetch_report_diagnose`,
  `fetch_report_with_fetcher`); `fetch`/`fetch_current` hardcode the default policy and
  `CrossRegistryResolver` has no policy-injection point, so neither can carry `discover`
  (documented limitations, not oversights).

  **BREAKING.** `RevocationPolicy` is now `#[non_exhaustive]`. Migrate
  `RevocationPolicy { known: revs }` to `RevocationPolicy::new(revs)` (identical
  behavior — `discover` defaults to `None`). `AcdpError` now derives `Clone` (additive,
  not breaking) so a discovery failure under `ProceedWithKnown` can be independently
  owned by both new surfaces from a single call.

  **Cost.** Discovery is opt-in but expensive when enabled: up to ~6,160 requests for
  producer-signed-only, ~12,321 for both trust classes, in the worst case against a
  hostile registry (see `RevocationDiscovery`'s rustdoc for the derivation).
  `total_timeout` (default 30s, matching `ResolverOptions::total_timeout`) bounds wall
  clock only — not bytes or memory. Setting `discover` puts a Tokio time-driver
  requirement (`enable_time`) on the core verify path.

## [0.12.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.11.0...acdp-v0.12.0) - 2026-09-11

### Fixed

- *(client)* [**breaking**] propagate transient verification failures in revocation
  discovery ([#248](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/248),
  [#253](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/253))

  `find_revocations`, `find_registry_attested_revocations`, and the lineage walk behind
  `find_revocations_in_lineage` used to swallow *every* `verify_revocation_body` failure for
  a discovered candidate, including transport failures — a producer's `did:web` host being
  unreachable, rate-limited, or otherwise un-askable. Since `classify_under_revocation(&[],
  …)` treats an empty revocation set as "proceed," a candidate that could not be *checked*
  read identically to one that was checked and found clean: anyone able to disrupt a
  producer's DID host (or a lineage member's) could make a real revocation vanish from
  discovery, invisibly.

  **Behavior change.** A transient failure (`AcdpError::is_transient() == true` —
  `KeyResolutionUnreachable`, `RateLimited`, `CrossRegistryResolutionFailed`,
  `RegistryInternal`, `Http`) for any candidate now makes all three functions return `Err`
  instead of a possibly-incomplete `Ok(vec![])`/`Ok(vec![...])`. A *permanent* verification
  failure (bad signature, hash mismatch, schema violation, a DID that resolves but denies the
  key) is still dropped with a `tracing::warn!` (behind the `tracing` feature) exactly as
  before — that case cannot manufacture a false authorization, so it stays fail-open to avoid
  handing a hostile registry a one-garbage-candidate denial-of-service lever.

  **Who is affected:** any caller of `find_revocations`, `find_registry_attested_revocations`,
  or `find_revocations_in_lineage` — directly, or indirectly via the discovery helpers a
  caller has wired into its own `RevocationPolicy.known` assembly — behind a producer or
  registry DID host that is sometimes unreachable. Such a call now surfaces `Err` (retryable
  per `AcdpError::is_transient()`) rather than silently under-reporting revocations. No public
  signature changed, so this break is invisible to `cargo-semver-checks`; the version bump is
  the signal.

### Other

- *(reconcile)* dispose the binding-toolchain pinning assumption

## [0.11.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.10.1...acdp-v0.11.0) - 2026-09-11

### Fixed

- *(client)* [**breaking**] make `fetch_report*` honor the caller's `VerificationPolicy`
  ([#245](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/245))

  `fetch_report`, `fetch_report_with_fetcher` and `fetch_report_diagnose` never called the
  verification spine: they hardcoded `key_status: CurrentlyAuthorized` and
  `verified_receipt: None`, so `policy.receipts`, `policy.revocations` and — on the diagnose
  path — `policy.allow_unknown_status` were silently ignored. They now honor the policy.

  **Behavior changes in both directions. Two fire under `VerificationPolicy::default()` with
  no caller opt-in:**

  - A present-but-invalid registry receipt is now rejected with `invalid_receipt` where it was
    previously accepted (fail-closed tightening).
  - A key rotated out of `assertionMethod` but backed by a verified receipt now verifies as
    `HistoricallyAuthorized` where it previously failed with `key_not_authorized` — **a
    deliberate loosening**, matching what `fetch_with_policy` has always done.

  Also tightened, but only for callers who set the relevant field: `ReceiptPolicy::Require`
  with no receipt now fails; a `revocations.known` entry covering the signing key is now
  enforced; and `allow_unknown_status: false` now withholds the handle on the diagnose path.

  `fetch_report_diagnose` never starts returning `Err` — it withholds the handle and records
  the reason in the new `VerificationReport::policy_phase_error`.

  **Callers pinned to `VerificationPolicy::strict_v0_1_0()` are unaffected**: the report family
  previously behaved as that policy, so their outcomes are byte-identical.

  No public signature changed (`cargo semver-checks` is clean); the minor bump is for the
  behavioral break, which it cannot see.

### Other

- *(interop)* pin required and total arity across all three bindings ([#242](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/242))
- *(bindings)* track the npm lockfile and pin @napi-rs/cli exactly ([#240](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/240))
- *(assumptions)* record #240 as evidence for the deferred npm ci decision
- *(interop)* add a wasm parity manifest and harness ([#229](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/229))

## [0.10.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.10.0...acdp-v0.10.1) - 2026-09-10

### Added

- *(server)* add publish_unverified_in_tenant_for_tests ([#237](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/237))

### Other

- *(supply-chain)* cargo deny is the sole RustSec gate in CI, not cargo audit ([#224](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/224)) ([#236](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/236))
- correct three inaccurate claims and record the assumption dispositions ([#233](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/233))

## [0.10.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.9.1...acdp-v0.10.0) - 2026-09-07

### Added

- *(bindings)* [**breaking**] bind the receipt to the served body via a required body_json ([#230](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/230))
- *(server)* [**breaking**] enforce the RFC-ACDP-0014 §4 supersedes row at publish ([#227](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/227))

### Other

- *(wasm)* remap build paths and gate the release on a real determinism check
- *(supply-chain)* pin every install-action tool version and make misses fail closed
- *(bindings)* commit binding lockfiles, pin the wasm toolchain, gate every build on --locked
- *(release)* only cut a release for feat/fix/perf commits ([#222](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/222))

### Changed

- **[BREAKING] `acdp-server`'s `PublishCommit` gained a new field,
  `predecessor_admission`, wiring the RFC-ACDP-0014 §4 `supersedes` row for
  `key-revocation` contexts at publish time** ([#216](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/216)).
  0.9.1 shipped `PublishValidator`'s §4 shape/§5 step-2 enforcement but
  explicitly left the `supersedes` row unimplemented ("a revocation context
  MAY be superseded only by another `key-revocation` context from the same
  signer class") because checking it needs the superseded context's stored
  type and signer class, which the registry-agnostic validator cannot see.
  `RegistryServer::commit_via_store` now builds a
  `Fn(&Body) -> Result<(), AcdpError>` closure over
  `check_revocation_supersession` and threads it through
  `RegistryStore::commit_publish` as `PublishCommit::predecessor_admission` —
  `Some` iff the registry's `acdp_version` clears the RFC-ACDP-0014 §4 gate
  (`>= 0.3.0`, fail-closed on a malformed version string) **and** the
  incoming request carries a `supersedes`; `None` otherwise, so a
  pre-0.3.0 registry's behavior is unchanged. `InMemoryStore::commit_publish`
  invokes it immediately after its existing producer-continuity,
  lineage/version-coherence, and `AlreadySuperseded` checks have all passed
  — never before them, since checking type/signer-class ahead of ownership
  would turn the hook into a cross-tenant, non-owner existence-and-type
  oracle on the predecessor (an attacker could learn "the ctx_id I don't
  own is a key-revocation" from the shape of the error alone).
  **Registry-visible behavior change:** a registry advertising
  `acdp_version >= 0.3.0` now rejects, with `schema_violation`, a publish
  that supersedes a `key-revocation` context with anything other than
  another `key-revocation` context from the same signer class
  (`ProducerSigned` vs. `RegistryAttested`) — previously such a publish
  was accepted and would silently re-point the lineage head away from the
  revocation.
  **For downstream `RegistryStore` implementors:** this is a one-way-door
  break to a public struct — `PublishCommit` is deliberately **not**
  `#[non_exhaustive]`, so the compiler forces every implementation to
  acknowledge the new field rather than silently continuing to build a
  `PublishCommit` that never enforces this MUST. The fix is one line:
  destructure (or construct) `predecessor_admission` alongside the
  existing `receipt_minter` field, and — for a store's own
  `commit_publish` — call it with the predecessor's stored `Body` at the
  same point `InMemoryStore` does (after ownership/lineage/version
  checks, before the insert). A store that adds the field to satisfy the
  compiler but never calls the closure will compile cleanly and silently
  fail to enforce the RFC-ACDP-0014 §4 `supersedes` row — the field
  existing is not itself enforcement. This is **not** expected to be the
  last breaking change to `PublishCommit`; treat it as a security-hook
  pattern other stores should expect to see repeated as RFC-ACDP-0014 and
  similar rows gain registry-side enforcement.

## [0.9.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.9.0...acdp-v0.9.1) - 2026-09-06

### Added

- **The Python, Node and wasm SDKs can now perform the RFC-ACDP-0006 §4.1 step-7
  context-identity binding** ([#206](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/206),
  [#214](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/214)).
  **If you verify retrieved contexts through a binding, read this.** `ctx_id` is
  registry-assigned and sits in the RFC-ACDP-0001 §5.7 exclusion set, so it is stripped from
  ProducerContent before hashing — neither `content_hash` recomputation nor the producer
  signature covers it. Until now the bindings offered no way to check it on the receipt-less
  path, so a consumer calling `verify_content_hash` + `verify_signature` and treating
  `true`/`true` as "this is the context I asked for" was exposed to context substitution: a
  compromised registry could serve any other validly-signed body from the same producer under
  the requested context's URL and every other check would still pass. The Rust client has
  enforced this since 0.9.0; the SDKs had no equivalent.
  New: `AcdpVerifier.verify_ctx_id_binding(body_json, expected_ctx_id)` (Python),
  `AcdpVerifier.verifyCtxIdBinding(bodyJson, expectedCtxId)` (Node), and
  `verifyCtxIdBinding(bodyJson, expectedCtxId)` (wasm), all backed by
  `acdp::verify::verify_ctx_id_binding`. **Add it to your verify sequence for any retrieval
  that arrives without a registry receipt** — the documented recipes in `docs/bindings.md` and
  each binding's README have been updated to include the step. It fails closed: both
  identifiers are parsed before comparison, so a malformed id on either side is an error
  rather than a silent pass. Note this is deliberately stricter than conformance fixture
  `fed-011`'s `uri_encoding_and_path_style_equivalence` case — non-canonical forms are refused
  rather than normalised, which yields false refusals, never false acceptances.
  Every unvalidated `CtxId` construction in the bindings was also routed through
  `CtxId::parse`, including two `derived_from` sites in the Python and Node producers.
- *(server)* enforce RFC-ACDP-0014 §4/§5 key-revocation validation at publish ([#207](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/207)) ([#217](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/217)) — see **Changed** below for what this rejects.
- `KeyRevocation::from_publish_request`, so the RFC-ACDP-0014 §4 shape table can be validated
  from a `PublishRequest` and not only from a retrieved `Body`. One implementation now backs
  both entry points.

### Other

- re-arm the release semver gate ([#208](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/208)) ([#212](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/212)).
  `release-plz.toml`'s `semver_check = true` gate was documented as blocking but had been
  reporting a false green: the pinned `cargo-semver-checks` could not parse current stable
  rustdoc output, and release-plz classifies a tool crash as "API compatible". It logged
  `✓ API compatible changes` for all 12 crates on a release that carried a known breaking
  change. The tool is now pinned to a working version in both the advisory CI job and the
  blocking release gate, and a non-advisory job fails when the tool cannot run rather than
  when it merely finds a break. Filed upstream as release-plz/release-plz#3018. This affects
  release tooling only — no library behaviour changes.

### Changed

- **`PublishValidator` now enforces the RFC-ACDP-0014 §4 `key-revocation` shape table at
  publish time, gated on `acdp_version >= 0.3.0`** (#207).
  Registries advertising `acdp_version >= 0.3.0` previously accepted and persisted any
  `key-revocation` body regardless of shape — an audience-restricted revocation, one
  missing `revoked_key_fingerprint`/`compromised_since`, or one with a
  `revoked_key_controller` that disagreed with `agent_id` all passed cleanly. The gate now
  calls `KeyRevocation::from_publish_request` (added on this same branch/release) and
  rejects a shape violation with `schema_violation`; a `did:key`-signed revocation whose
  key_id fingerprint matches its own `revoked_key_fingerprint` is separately rejected with
  `key_not_authorized` (RFC-ACDP-0014 §5 step 2 — a revocation MUST NOT be signed by the
  very key it revokes), since that check now lives in the shared `from_parts` core and is
  reachable from publish, not only from the retrieval-side path. The gate also applies to
  the RFC-ACDP-0014 §10 interim `acdp:key-revocation` custom type, not just the standard
  `key-revocation` type — `ContextType::is_key_revocation()` treats both as equivalent.
  The gate also enforces the controller-class rule §4/§6 need but `from_publish_request`
  cannot check on its own (it has no registry identity): a `revoked_key_controller`
  different from `agent_id` is only valid when `agent_id` is this registry's own DID (§6
  registry-attested); conversely a revocation published under the registry's own DID with
  *no* controller is now rejected too, since §6 makes the controller REQUIRED there —
  leaving it absent would otherwise be silently classified as the registry revoking its own
  key. A malformed `acdp_version` on the registry's own capabilities document fails
  **closed** (gate stays on), not open.
  **Registry-visible behavior change:** any `acdp-registry-*` implementation embedding this
  crate's `PublishValidator` and declaring `acdp_version >= 0.3.0` will start rejecting
  `key-revocation` publishes it accepted before this release. This is publish-time only —
  bodies already stored under an older validator are not re-validated retroactively.
  Producer-side validation (`RequestBuilder::build`) is intentionally untouched: the check
  only fires registry-side, per §4's own scoping ("Registries advertising...").
  `RegistryServer::publish_verified_in_tenant` (the `did:web`/resolver-backed publish path)
  now additionally enforces the §5 step 2 not-self-signed rule for a resolved `did:web`
  signing key, rejecting with `key_not_authorized` when the resolved key's fingerprint
  equals the revocation's own `metadata.revoked_key_fingerprint`; the `did:key` path was
  already covered (see above) since its fingerprint is derivable offline.
  `publish_pinned_verified_in_tenant` (operator-pinned key, no DID resolution) gets the same
  check at no added cost, since the caller-supplied key is already in hand.
  `publish_unverified_for_tests` is unchanged — it has no resolved key to check at all, by
  its own no-DID-resolution contract.
  This adds no new DID resolution in practice: `publish_verified_in_tenant` already
  resolves the producer's `did:web` document unconditionally, for every publish, to verify
  the request signature (RFC-ACDP-0003 steps 7–8) — a DID-host outage already fails every
  `publish_verified` call today, key-revocation or not. The fingerprint computation this
  phase adds re-resolves the *same* DID microseconds later, against `WebResolver`'s LRU
  cache, so there is no new network round-trip and no new operational risk.
  **Not yet enforced:** the §4 table's `supersedes` row ("a revocation context MAY be
  superseded only by another `key-revocation` context from the same signer class") is *not*
  implemented by this gate — checking it needs the superseded context's stored type and
  signer class, which the registry-agnostic `PublishValidator` cannot see (it has no store
  access). Tracked in
  [#216](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/216); everything
  else in the §4 table is enforced as described above.

## [0.9.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.8.5...acdp-v0.9.0) - 2026-09-06

### Changed

- **[BREAKING] `AcdpError` and `VerificationReport` are now `#[non_exhaustive]`**
  ([#205](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/205)).
  Downstream crates that match exhaustively on `AcdpError` must add a `_` wildcard arm.
  `VerificationReport` can no longer be constructed via struct literal outside
  `acdp-client`; it is an output-only diagnostic type and was never intended to be.
  Taken deliberately in this release rather than later: the two fixes below already
  forced a break (a new error variant and a new report field), so marking both types
  now means downstream absorbs **one** break instead of one per future RFC — this
  protocol keeps adding wire error codes (25 today, up from 21). Precedent:
  `SsrfReason` in `acdp-safe-http` already takes this stance.

### Fixed

- **Context substitution is now refused across every verified retrieval path** (#189,
  [#200](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/200)).
  `verify_retrieved` accepted an `expected_ctx_id` but never compared it to
  `ctx.body.ctx_id`, so a registry serving context B where A was requested passed every
  check — hash recomputation, producer signature, DID resolution and key authorization
  are all self-referential over whatever body came back. `ctx_id` is registry-assigned
  and sits in the RFC-ACDP-0001 §5.7 exclusion set, so neither `content_hash` nor the
  producer signature covers it; a client-side equality check is the only binding
  available when no receipt is served. The receipt path already bound it, so the gap was
  exactly `ReceiptPolicy::VerifyIfPresent` with `registry_receipt: None` — the whole
  core-profile v0.1.0 world.
  This implements **RFC-ACDP-0006 §4.1 step 7 (NORMATIVE)**, added to the spec in
  `285e9dc` with conformance fixture `fed-011-ctx-id-binding.json`; it is conformance,
  not optional hardening. New error variant `AcdpError::ContextIdMismatch` — step 7
  permits a consumer-side "equivalent typed error", and reusing
  `CrossRegistryResolutionFailed` would have been wrong because it is classified
  *transient*, so retry-aware callers would have retried a substitution attack.
  It does **not** close RFC-ACDP-0008 §9.1 in full: a registry that genuinely republishes
  content under a new `ctx_id` still passes; only serve-time substitution is caught.
  **Consumer-visible behavior change:** a non-canonical `ctx_id` argument to the `acdp`
  CLI now exits locally with `schema_violation` before any network request, rather than
  producing a registry 404.

- **`find_revocations` now enforces query scope and trust class** (#191,
  [#204](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/204)).
  Its doc claimed a producer-scoped query cannot return registry-attested revocations;
  nothing enforced it. The trust class is derived purely from
  `revoked_key_controller != agent_id`, and the only §5 identity check compares the
  signing key to the revoked key, never publisher identity — so a producer could publish
  `agent_id = P, revoked_key_controller = Q` revoking Q's fingerprint, and it would
  verify and be returned by a P-scoped query. Because RFC-ACDP-0014 §7 encourages caching
  keyed by `revoked_key_fingerprint`, that is a cross-producer DoS reached through a store
  write, from a body that verified.
  **Caller-visible behavior change:** results are now filtered to those whose `publisher`
  equals the queried `agent_id` **and** whose trust class is `ProducerSigned`. Callers
  that relied on this function to surface §6 registry attestations must switch to
  `find_registry_attested_revocations`, added in the same release. Note `agent_id` is
  matched by **exact bytes** — `AgentDid` does not normalize case — so a case-variant DID
  yields an empty result; pass the DID as published.
  Dropped candidates are surfaced via `tracing::warn!` when the `tracing` feature is
  enabled (RFC-ACDP-0014 §13's first-named mitigation, "surfacing which DID issued each
  acted-upon revocation").

### Added

- `find_registry_attested_revocations` and `KeyRevocation::cross_check_registry_binding`
  ([#204](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/204)) —
  RFC-ACDP-0014 §8's prescribed registry-scoped discovery query, and the §6 publisher
  binding it relies on. Required rather than additive: the `find_revocations` filtering
  above would otherwise remove a documented capability with no replacement.

### Other

- move off yanked wnaf 0.14.0 ([#201](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/201))

## [0.8.5](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.8.4...acdp-v0.8.5) - 2026-08-30

### Fixed

- release-hygiene follow-ups (tag lag, CHANGELOG gap, stale spec pin)

## [0.8.4](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.8.3...acdp-v0.8.4) - 2026-08-30

### Other

- reconcile RS-11 ACDP_VERSION default-bump assumption ([#180](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/180))

## [0.8.3](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.8.2...acdp-v0.8.3) - 2026-08-30

### Added

- *(bindings)* expose anchors (RFC-ACDP-0016) in acdp-py and acdp-node ([#175](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/175))

### Other

- *(release-runbook)* record the RS-8 anchors release as done ([#177](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/177))

## [0.8.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.8.1...acdp-v0.8.2) - 2026-08-30

### Added

- *(types)* add anchors support (RFC-ACDP-0016, 0.5.0) ([#169](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/169))

### Other

- *(deps)* bump the major-updates group across 1 directory with 9 updates ([#157](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/157))
- *(deps)* bump the minor-and-patch group across 1 directory with 6 updates ([#147](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/147))
- W4-RS hygiene batch (RS-6/7/9/11/12) ([#164](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/164))
- record RS-3's require-mode conformance evidence (RS-4) ([#160](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/160))
- close conformance CI gap, add fixture-family coverage, harden bindings supply chain ([#153](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/153))

### Changed

- **`ACDP_VERSION` default bumped `0.2.0` → `0.4.0`** (RS-11, family plan
  `agentcontextdistributionprotocol/plans/siblings/acdp-rs.md`). `RequestBuilder`
  has emitted `acdp_version` explicitly by default since the 0.2.0 line (WS-D1); that
  default tracked the wrong constant once RFC-ACDP-0011..0014 (0.3.0) and
  RFC-ACDP-0015 witness cosigning (0.4.0, promoted to Final 2026-08) shipped in this
  crate — a default-using producer was stamping `0.2.0` on bodies the crate already
  fully supports minting/verifying at 0.4.0. `ACDP_VERSION` now tracks the newest
  Final wire line, matching the design intent ("remove the omitted-vs-explicit
  ambiguity for everything built going forward").
  **Producer-visible behavior change:** any caller relying on the *implicit* default
  remaining `"0.2.0"` — rather than calling `.acdp_version(...)` /
  `.omit_acdp_version()` explicitly — will see their next default-built
  `content_hash` change (the JCS preimage includes `acdp_version`), and the emitted
  value move to `"0.4.0"`. A registry that hasn't adopted 0.4.0-line semantics yet
  should pin the version it expects explicitly rather than relying on the crate's
  default. No schema/validation requirement is newly triggered by this (there is no
  version-gated *required* field for produced bodies at 0.3.0 or 0.4.0 in this
  crate's `acdp-validation` — only `CapabilitiesDocument.acdp_version >= 0.3.0`
  gates a requirement, and that's a registry's own capabilities document, not a
  producer's request). See `ASSUMPTIONS.md` for the alternative considered
  (feature-derived default) and why it was rejected.

### Conformance evidence

RS-4 (family plan `agentcontextdistributionprotocol/plans/siblings/acdp-rs.md`): the Rust
half of RFC-ACDP-0015's Final-promotion evidence-input contract (SPEC-1), recording the
require-mode conformance run at the pin bumped by RS-3 (#159).

- **Crate / tag:** `acdp` (workspace-lockstep) `v0.8.1` — the currently released tag; the
  pending `v0.8.2` release PR (#154) had not merged at the time of this run.
- **Pinned spec SHA:** `bff3cf3afbdcea619834916e8f0bcac7e82ba658` (spec `main` as of
  2026-08-28).
- **Command:** `ACDP_SPEC_DIR=<pinned spec checkout> ACDP_REQUIRE_CONFORMANCE=1 cargo test
  --workspace --all-features` — 658 passed, 0 failed, exit 0.
- **Executed `wit-*` fixtures** (RFC-ACDP-0015 witness cosigning, the promotion-gating
  family): `wit_001_cosignature_golden_fixture`, `wit_002_consistency_refusal_fixture`,
  `wit_003_quorum_verification_fixture`, `wit_004_cosignature_key_mismatch_fixture` — all
  executed (not skipped), confirmed via `ACDP_REQUIRE_CONFORMANCE=1`'s hard-fail-on-missing
  behavior.
- **Also executed** (previously CI-silent, closed by RS-1/#153): `tests/transparency_log.rs`
  (`log_*`), `tests/key_revocation.rs` (`rev_*`), `tests/lifecycle.rs` (`lc_*`) — all green.
- **CI run:** https://github.com/agentcontextdistributionprotocol/acdp-rs/actions/runs/33232085544/job/99046540516
  (the `conformance (spec fixtures)` job on PR #159, which carried this exact pin and
  command; the PR itself is a pure pin bump with no test/fixture changes, so this run is the
  authoritative in-CI execution of the run recorded above).

## [0.8.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.8.0...acdp-v0.8.1) - 2026-07-10

### Other

- release v0.8.0 ([#128](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/128))

## [0.8.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.6.2...acdp-v0.8.0) - 2026-07-10

### Other

- unify the whole ecosystem to 0.8.0 and auto-release the SDKs ([#127](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/127))

## [0.6.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.6.1...acdp-v0.6.2) - 2026-07-10

### Added

- *(server)* publish_pinned_verified_in_tenant for operator-pinned keys ([#116](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/116))

## [0.6.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.5.3...acdp-v0.6.1) - 2026-07-09

### Added

- *(acdp-wasm)* publish browser wasm binding to npm

### Other

- release v0.6.0
- unify the acdp family to a single lockstep version (0.6.0)
- commit refreshed cargo-vet imports.lock
- fix supply-chain gates (crossbeam advisory + stale vet exemptions)
- update Cargo.lock for acdp-verify dev-dependencies
- refresh for the 0.2.0 trust & hardening layer and workspace split
- *(verify)* add direct coverage for the acdp-verify crate
- fix toolchain bug, pin spec, expand dependabot, add release smoke gates

## [0.6.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.5.3...acdp-v0.6.0) - 2026-07-09

### Added

- *(acdp-wasm)* publish browser wasm binding to npm

### Other

- unify the acdp family to a single lockstep version (0.6.0)
- commit refreshed cargo-vet imports.lock
- fix supply-chain gates (crossbeam advisory + stale vet exemptions)
- update Cargo.lock for acdp-verify dev-dependencies
- refresh for the 0.2.0 trust & hardening layer and workspace split
- *(verify)* add direct coverage for the acdp-verify crate
- fix toolchain bug, pin spec, expand dependabot, add release smoke gates

## [0.5.3](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.5.2...acdp-v0.5.3) - 2026-07-06

### Added

- *(bindings)* expose RFC-ACDP-0015 witness-cosigning surface (py + node 0.7.0)
- *(types)* add LogCosignature witness-cosignature types (RFC-ACDP-0015)

## [0.5.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.5.1...acdp-v0.5.2) - 2026-07-06

### Other

- add research-track evaluation memos (wasm, did:webvh, post-quantum)

## [0.5.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.5.0...acdp-v0.5.1) - 2026-07-06

### Added

- *(bindings)* expose ACDP 0.3.0 verification surfaces in both SDKs

### Other

- add supply-chain security policy
- add cargo-vet supply-chain dependency vetting
- *(bindings)* pin the 0.3.0 golden vectors and cross-binding parity

## [0.5.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.4.0...acdp-v0.5.0) - 2026-07-05

### Added

- feat!(client): hard-gate SSRF-relaxed test constructors behind test-transport
- [**breaking**] lifecycle events & retraction — RFC-ACDP-0013 (acdp/0.3.0 draft)

### Other

- rustfmt after integration merges
- Merge feature/rfc-0014-revocation: RFC-ACDP-0014 SDK surface
- Merge feature/rfc-0012-log-verification: RFC-ACDP-0012 SDK surface

## [0.4.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.3.0...acdp-v0.3.1) - 2026-07-05

### Added

- *(tracing)* instrument verify pipeline and server publish path
- *(client)* fallible WebResolver constructors; feature-gate SSRF-relaxed test constructors behind test-transport

### Other

- fix double-comparison lint; docs: fix intra-doc link; chore: bump anyhow past RUSTSEC-2026-0190
- bind lhr-001..004 fixtures and RFC-ACDP-0011 end-to-end suite
- rustfmt fuzz target; lockfile update for tracing deps
- *(bench)* criterion benchmarks for sign/verify, JCS, content-hash, SSRF classify

## [0.3.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-v0.2.1...acdp-v0.3.0) - 2026-06-24

### Other

- preserve acdp::crypto::verify::* module path in the facade
- split acdp into a fine-grained Cargo workspace

## [0.2.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/v0.2.0...v0.2.1) - 2026-06-14

### Added

- *(bindings)* resolve retired registry receipt keys per RFC-ACDP-0010 §9

## [0.2.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/v0.1.0...v0.2.0) - 2026-06-13

### Added

- *(registry)* add publish_verified_did_key_in_tenant
- [**breaking**] ACDP 0.2.0 trust & hardening — registry receipts, did:key, divergence diagnostics

### Fixed

- *(registry)* scope the §7 no-degraded-mode check to newly inserted contexts

### Other

- add unit coverage for core types and crypto error paths
- add supersession + end-to-end examples and negative-input tests
- add library usage guides under docs/

Implements the four workstreams of
`plans/acdp-0.2-trust-hardening-2026-06-12.md`, verified against the
spec's published 0.2.0 Draft (RFC-ACDP-0010 + the RFC-ACDP-0001
amendments) and its conformance pack: `sig-003`, `fp-001`, `rcpt-001`
(arithmetic golden vectors, reproduced byte-for-byte), `can-012`
(divergence corpus), `dk-001..004`, and `rcpt-002..004` are all
executed by `tests/conformance.rs`; `rot-001` and `fed-009` behaviors
are covered by `tests/receipts.rs`. `ACDP_VERSION` is now `0.2.0` and
the builder default emits it explicitly (RFC-ACDP-0001 §6: the
omission default is closed for 0.2.0 builders). The receipt object is
a CLOSED schema per RFC-ACDP-0010 §4; receipt verification hashes the
raw wire JSON (never a re-serialized struct) and binds `lineage_id` /
`origin_registry` / `created_at` to the accompanying body per §8
step 3. `acdp-registry-receipts` requires capabilities
`acdp_version >= 0.2.0`, and `publish_unverified_for_tests` is
unavailable on receipts-advertising registries (§7: no degraded
mode).

### Added — did:key (WS-C)
- `did::key`: pure offline `did:key` resolution (Ed25519 + P-256
  compressed, multicodec-checked), encoding helpers, and the
  `did:key:z<mb>#z<mb>` key-URL convention. No network, no SSRF
  surface; verification outlives the producer's infrastructure.
- `Producer::new_did_key` / `Producer::new_did_key_p256` — identity
  derived from the key, no domain or DID hosting required.
- `crypto::verify_body_offline` /
  `verify_publish_request_signature_offline` /
  `verify_did_key_envelope` — full did:key verification with
  `--no-default-features`.
- `RegistryServer::publish_verified_did_key` — RFC-conformant publish
  without the `client` feature; gated on `supported_did_methods`
  advertising `"did:key"` (rejected with `key_resolution_failed`
  otherwise).

### Added — registry receipts (WS-A, RFC-ACDP-0010 draft)
- `types::receipt::{RegistryReceipt, ReceiptSigner}` — registry-signed
  attestation binding `ctx_id` / `lineage_id` / `origin_registry` /
  `created_at` / `key_fingerprint` to the producer `content_hash`.
  Preimage construction is identical to the producer signature
  (JCS minus `signature`, sign the ASCII `"sha256:<hex>"` string).
- `crypto::fingerprint` — pinned `key_fingerprint` encoding (SHA-256
  over raw Ed25519 / SEC1-compressed P-256 public key bytes).
- `RegistryServer::with_receipt_signer` — mints receipts atomically
  with persistence (via the new `PublishCommit::receipt_minter` hook),
  returns them in `PublishResponse::registry_receipt`, and advertises
  the `acdp-registry-receipts` profile.
- Client verification: `client::verify_receipt_value`, the
  `ReceiptPolicy` (`Ignore` / `VerifyIfPresent` default / `Require`)
  policy axis, and `VerifiedContext::{verified_receipt, key_status}`.
- New wire error code `invalid_receipt` (`AcdpError::InvalidReceipt`,
  permanent).

### Added — historical key validity (WS-B)
- `HistoricalKeyPolicy::AcceptWithReceipt` (default): a producer key
  rotated out of `assertionMethod` but retained in
  `verificationMethod` verifies as
  `KeyAuthorization::HistoricallyAuthorized` **only** when a verified
  receipt attests its fingerprint; fails closed otherwise.

### Changed — sharp edges (WS-D)
- **BREAKING (hash-visible):** `RequestBuilder` now emits
  `acdp_version` explicitly by default. The omitted and explicit forms
  are distinct JCS preimages; requests built with default settings
  hash differently than under 0.1.x. Use
  `RequestBuilder::omit_acdp_version()` to reproduce omitted-form
  hashes (e.g. the `sig-001` golden vector).
- **BREAKING (API):** `VerificationPolicy::verify_registry_receipt`
  (bool) replaced by the `receipts: ReceiptPolicy` /
  `historical_keys: HistoricalKeyPolicy` fields;
  `PublishCommit` gains `receipt_minter`; `PublishResponse` gains
  `registry_receipt`.
- `crypto::{canonical_preimage, explain_hash_mismatch}` — divergence
  diagnostics that name the known cross-implementation hash pitfalls
  (acdp_version toggle, null-vs-absent, sub-ms timestamps).
- Lineage anchoring and idempotency atomicity contracts documented on
  `RegistryStore` (the `InMemoryStore` already implements both).

## [0.1.0] - 2026-05-19

First public release. Full conformance with the **ACDP v0.1.0 Final**
specification (promoted to Final on 2026-05-19): the complete spec
conformance fixture suite, the `sig-001` / `can-001` / `lin-001` golden
vectors, and the `acdp-consumer` profile.

### Added — repository hygiene
- Project metadata: repository, homepage, documentation, README, exclude rules,
  `[package.metadata.docs.rs]` for all-features doc builds.
- GitHub Actions CI: rustfmt, clippy (default + no-default-features),
  cross-platform tests (Linux/macOS/Windows + beta), MSRV check (1.86),
  doc build with `-D warnings`, cargo-deny, cargo-audit, llvm-cov coverage.
- `release-plz` workflow for automated crates.io publishing.
- Dependabot configuration for cargo and github-actions.
- `rustfmt.toml`, `deny.toml`, and `.gitignore`.
- HTTP-mocked tests for `RegistryClient` and `WebResolver` (wiremock).
- Property-based tests for JCS canonicalization (proptest).
- `CONTRIBUTING.md`, `SECURITY.md`.

### Changed — wire-shape conformance (Phase 0)
- **BREAKING:** `PublishResponse` no longer carries `content_hash`; gains
  `version: u32` and `status: Status` per
  `acdp-publish-response.schema.json` (fixture pub-007).
- **BREAKING:** `SearchResponse.results` renamed to `matches` per
  `acdp-search-response.schema.json` (fixture vis-003); back-compat
  accessor `results()` provided.
- **BREAKING:** `SearchResult` (the `match_summary` projection) gains
  `summary: Option<String>`, types `context_type` as `ContextType`, drops
  `tags` and `description`.
- **BREAKING:** `DataRef` rewritten — `ref_type: DataRefType` is required
  (closed enum); `description`, `size_bytes`, `schema_version` added;
  `location: Option<Location>` (URI or structured locator); typed
  constructors (`uri`, `uri_verified`, `structured`,
  `embedded_{json,utf8,base64}`).
- **BREAKING:** `DataPeriod.start` and `.end` are now required (was
  `Option`).
- **BREAKING:** `Status` is now an open enum with `Other(String)` for
  forward-compat (e.g. `retracted` per RFC-ACDP-0009 §2.1); helper methods
  `is_active`, `is_superseded`, `is_expired`, `as_other`.
- `summary: Option<String>` added to `Body`, `PublishRequest`, and
  `RequestBuilder`; included in the ProducerContent hash preimage.
- `RequestBuilder::version` setter required for v2+ supersession;
  `Producer::supersede_body(&Body)` propagates `version + 1` and
  `expected_lineage_id`. v1+supersedes and v2+ without version both
  rejected.
- `assign_identifiers` now takes `first_version_ctx_id`; derives
  `lineage_id` from the v1 ctx_id on supersession (was incorrectly
  derived from the new ctx_id).
- `RegistryClient` applies RFC-ACDP-0006 §7.4 timeouts (5s connect,
  30s total).
- Producer-side `expires_at` and `data_period` setters truncate to
  millisecond precision per RFC-ACDP-0001 §5.3.

### Added — validation (Phase 1)
- New `validation` module providing `validate_publish_request`,
  `validate_body`, `validate_data_ref`, `validate_metadata`,
  `validate_identifiers`, `compute_embedded_hash`, `verify_embedded_hash`.
- `RequestBuilder::build()` runs full schema validation before emission.
- Runtime checks: public-no-audience, array uniqueness/size, string
  length, `data_period.start ≤ end`, `DataRef` oneOf + URI credential
  rejection + structured-scheme pattern + embedded ≤ 64 KB +
  `utf8`/`base64` content must be string, metadata depth ≤ 8 / JCS size
  ≤ 64 KB / ≤ 100 properties, `did:web` enforcement, signature length
  for `ed25519` / `ecdsa-p256`, embedded `content_hash` semantics
  (`json` → JCS, `utf8` → raw bytes, `base64` → decoded bytes).

### Added — error taxonomy and typed IDs (Phase 2)
- 13 new `AcdpError` variants matching RFC-ACDP-0007 §5 wire codes:
  `NotFound`, `NotAuthorized`, `RateLimited`, `PayloadTooLarge`,
  `EmbeddedTooLarge`, `SupersededTarget { reason, message }`,
  `UnsupportedAlgorithm`, `NotImplemented`, `CursorExpired`,
  `InvalidCursor`, `DuplicatePublish`, `CrossRegistryResolutionFailed`,
  `RegistryInternal`. New `SupersessionReason` enum.
- `RegistryClient::parse_success` now maps `WireError.code` to typed
  variants via `AcdpError::from_wire_error`.
- `CtxId::parse`, `LineageId::parse`, `ContentHash::parse`,
  `AgentDid::parse`, `AgentDid::parse_web` perform full pattern
  validation per `acdp-common.schema.json`. `CtxId::uuid()` extracts the
  v4 UUID component.

### Added — builder and API (Phase 3)
- `RequestBuilder::expected_lineage_id` for v2+ self-verification (v1
  publications reject this field per RFC-ACDP-0003 §2.2).
- `PublishRequest.lineage_id: Option<LineageId>`.
- `SearchParams` gains `data_period_start_after`,
  `data_period_end_before`, `expires_after`, `expires_before` filters
  (RFC-ACDP-0005 §2.1). New `SearchParamsBuilder` accepting
  `DateTime<Utc>`.
- `PublishValidator::for_authority` rejects cross-registry supersession
  with `SupersededTarget { CrossRegistrySupersessionUnsupported }`.
- `CapabilitiesDocument.extensions: Map<String, Value>` (`#[serde(flatten)]`)
  preserves unknown forward-compat capability flags.
- `ContextType` deserializer rejects strings that are neither standard
  values nor namespaced custom types matching
  `^[a-z][a-z0-9_]*:[a-z][a-z0-9_-]*$`.

### Added — protocol completeness (Phase 4)
- `CrossRegistryResolver` (RFC-ACDP-0006 §4.1): seven-step algorithm
  with `walk_derived_from`, cycle detection, configurable `max_depth`
  (default 10), and optional authority allowlist.
- `registry::safe_http::SsrfPolicy` (RFC-ACDP-0006 §7): URL filtering
  for HTTPS-only, IP-literal rejection, RFC 1918 / loopback /
  link-local / multicast / IMDS (`169.254.169.254`) and IPv6
  equivalents (`::1`, `fc00::/7`, `fe80::/10`, IPv4-mapped); same-
  authority redirect check; constants `MAX_CONTEXT_BYTES` (1 MB),
  `MAX_METADATA_BYTES` (64 KB), `MAX_REDIRECTS` (3).
- `tests/conformance.rs` validates all 16 spec conformance fixtures
  parse, plus deserialization checks for every example under
  `examples/**/*.json`. The harness locates the spec via
  `ACDP_SPEC_DIR` (with a sibling-path fallback) and skips gracefully
  when neither is available.

### Added — quality of life (Phase 5)
- `FullContext.registry_receipt: Option<Value>` reserved for
  RFC-ACDP-0009 §2.7.
- `WebResolver` cache backed by `lru::LruCache` (default capacity 1000),
  with `WebResolver::with_capacity(n)`.
- `PublishValidator::validate_post_schema` alias with RFC-aligned
  documentation.
- Optional `tracing` feature: `RegistryClient::{capabilities, publish,
  retrieve}` and `WebResolver::resolve` carry `#[tracing::instrument]`
  spans when enabled.

### Deferred
- IMP-09 — standalone `acdp-cli` crate (sign / verify / publish /
  retrieve / search). Out of scope for this revision.
- IMP-05 — auto-populating `acdp_version = "0.0.1"` in the builder
  would change the content_hash and break the `sig-001` golden vector;
  v0.0.1 producers MAY include it explicitly via
  `RequestBuilder::acdp_version`.

### Fixed
- `crypto::jcs` now compiles cleanly (missing `io::Write` import,
  `serde_json::Value::String` shadowing, map indexing).
- `producer::RequestBuilder::build` no longer emits JSON `null` for unset
  optional fields; the canonical form now matches the wire format produced by
  serde with `skip_serializing_if = "Option::is_none"`, so the `content_hash`
  for a minimal request matches the spec golden vector
  (`sig-001-ed25519-golden`).
- Or-pattern bug in `Visibility::Restricted` audience check.

### Security
- Cross-registry resolution builds its per-authority `RegistryClient`
  with `new_pinned`: the foreign authority's DNS is resolved up-front,
  every resolved IP is filtered through the `SsrfPolicy`, and the
  connection is pinned to that address — closing a DNS-rebinding /
  internal-host SSRF gap (SEC-01).
- `HttpsDataRefFetcher` builds its HTTP client with a `SafeDnsResolver`
  DNS hook and a same-authority redirect cap, so a producer-controlled
  `DataRef` location resolving into a private range is refused at DNS
  time and cross-authority redirects are rejected (SEC-02).
- `validate_origin_registry` rejects uppercase, underscores, and
  malformed labels by delegating to the shared DNS-authority validator
  (BUG-02).

[0.1.0]: https://github.com/agentcontextdistributionprotocol/acdp-rs/releases/tag/v0.1.0
