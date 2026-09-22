# ASSUMPTIONS

## Pin SHA for RS-1/RS-2 local verification
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** the user's literal instruction to pin the verification worktree to "the
  current spec main SHA" actually means the SHA already pinned in `ci.yml:75`
  (`f5b66b8f86f48ba16f79bba95eb246d6acb43989`), not today's live spec `main` HEAD
  (`2eb8fee`, 4 commits ahead) — since bumping the pin is explicitly out of scope (RS-3,
  wave 2, hazard H6) and testing against a different commit than the one CI actually uses
  would not be a faithful dry run of the CI job being edited.
- **Chose:** pinned the local verification worktree to `f5b66b8f86f48ba16f79bba95eb246d6acb43989`.
- **Alternatives:** pin to live spec `main` HEAD (rejected: tests a commit CI doesn't use);
  ask the user before proceeding (rejected: unambiguous given the "never bump the pin"
  hard rule, cheap to reverse).
- **Blast radius if wrong:** trivial — re-run the same commands against a different
  `worktree add` SHA. No code changes hinge on this choice.
- **Status:** CONFIRMED (2026-08-28) — see DECISIONS.md

## RS-2 KNOWN_FAMILIES / EXCUSED design (static vs. dynamic)
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** the RS-2 item's accept criterion ("dropping anc-001 fails the test until
  anc is executed or excused") requires a **static**, hand-maintained Rust-side
  `KNOWN_FAMILIES` list cross-checked against the **dynamic** canonical family list pulled
  from the pinned spec's `registries/profiles.json` — not a fully-dynamic design where the
  canonical list alone decides "known," which would let any new family silently pass.
- **Chose:** `KNOWN_FAMILIES: &[&str]` (28 entries, hand-reviewed) + `EXCUSED: &[(&str,
  &str)]` (currently empty) in `tests/conformance.rs`, matched against fixture ids via a
  longest-prefix-match ported from the spec's own `check-consistency.py::check_families`.
- **Alternatives:** derive "known" directly from `profiles.json` (rejected: defeats the
  forcing-function purpose — a new family would auto-pass); per-fixture (not per-family)
  coverage tracking (rejected: much finer-grained than RS-2 asks for, flagged as a future
  tightening in the plan's Long-term posture instead).
- **Blast radius if wrong:** low — verifier independently confirmed all 28 known families
  are genuinely covered (each has ≥1 fixture referenced by literal id somewhere in the test
  suite) and both accept-criteria negative scenarios (bare `anc-001` drop; drop +
  `profiles.json` addition) independently reproduced with the two distinct expected panic
  sites. If the design were wrong, the fix is a same-file, same-phase rewrite.
- **Status:** CONFIRMED (2026-08-28) — see DECISIONS.md

## RS-1 exclusion contingency (not needed)
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** RS-1's own text permits excluding a specific test target from the
  `--workspace` invocation if it genuinely fails at the pinned SHA due to a 0.2.0-branch
  fixture family not yet merged to spec `main`.
- **Chose:** ran the full `cargo test --workspace --all-features` against the pinned SHA
  (`f5b66b8f…`) under require-mode *before* touching `ci.yml`, empirically confirming zero
  failures — `wit-`, `log-`, `rev-`, `lc-` families and `crates/acdp-jcs/tests/differential_numbers.rs`
  (also newly swept in by `--workspace`) all pass. No exclusion was needed.
- **Alternatives:** none — this was a factual question resolved by running the suite, not
  a judgment call.
- **Blast radius if wrong:** none — this is a factual outcome, not a design decision.
- **Status:** CONFIRMED (empirically, by test run — not a genuine open question)

## Reusing root deny.toml for bindings advisory scanning
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** the root `deny.toml`'s `[licenses]`/`[bans]`/`[sources]` policy is generic
  enough to reuse for the bindings' dependency graphs via `--config`, and its one
  `[advisories] ignore` entry (RUSTSEC-2025-0134, axum-server-specific) is harmless when
  applied to graphs that don't pull axum-server at all.
- **Chose:** `cargo deny --manifest-path <binding>/Cargo.toml --config deny.toml check
  advisories` (scoped to `check advisories` only, not bare `check`), reusing the root file
  rather than authoring three near-duplicate `deny.toml`s.
- **Alternatives:** standalone `deny.toml` per binding (rejected: pure maintenance
  overhead with no current benefit, since the bindings never diverge from the root
  license/source policy today).
- **Blast radius if wrong:** low, and already partially confirmed — the reused ignore
  entry does produce a benign `advisory-not-detected` warning (not a failure) for each
  binding graph, exactly as anticipated. If the bindings' policy needs to diverge later
  (e.g. a binding-only license exception), splitting into standalone files is a small,
  additive change.
- **Status:** CONFIRMED (2026-08-28) — see DECISIONS.md

## Not reversing the binding-lockfiles-gitignored policy
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** RS-10's scope is "wire up advisory scanning," not "make the bindings'
  dependency graphs reproducible" — so the existing `.gitignore` policy (bindings'
  `Cargo.lock`/`package-lock.json` are gitignored, build output) stays as-is, and the new
  CI jobs resolve a fresh graph every run rather than auditing a pinned one.
- **Chose:** left `.gitignore` untouched; the new `bindings-deny`/`bindings-npm-audit`
  jobs audit whatever each manifest's version constraints resolve to at CI-run time.
- **Alternatives:** commit the three `Cargo.lock`s + `package-lock.json` for reproducible
  scanning (rejected: a materially larger, separate policy change — touches release
  workflow assumptions about what's "build output" — outside RS-10's stated scope).
- **Blast radius if wrong:** medium, ongoing — an unrelated transitive dependency landing
  a new RUSTSEC advisory can turn the new job red with no code change in a future PR. This
  is flagged explicitly in the job's own comment as expected supply-chain-gate behavior,
  not a flake to silence — but if it proves too noisy in practice, reversing this decision
  (committing the lockfiles) is a bigger, separate change.
- **Status:** CONFIRMED (2026-08-28) — see DECISIONS.md
- **Update (2026-09-06, plans/issues-196-199-215-216-followups.md Phase 2, superseded):**
  this plan's Phase 2 did exactly the reverse of what this entry confirmed — the three
  binding lockfiles (`bindings/{acdp-py,acdp-node,acdp-wasm}/Cargo.lock`) are now
  committed, and every binding build (`bindings.yml`, `bindings-release.yml`,
  `acdp-wasm-release.yml`) is gated on `--locked` against them. The original reasoning no
  longer holds: it was scoped to "wire up advisory scanning" for what were then treated as
  ordinary library dependency graphs, but the bindings are published application artifacts
  (an npm/PyPI/crates-equivalent end product, not a library other Rust crates depend on),
  and the unpinned release path was re-resolving on the order of ~217 packages fresh on
  every release build with no lockfile diff to review. This entry is left verbatim above as
  a record of the original decision and its reasoning at the time.
- **Update (2026-09-10, plans/issues-240-242-seamb-wave.md Phase 1, superseded):** the npm
  half of the 2026-09-06 update above ("no committed `package-lock.json`") is now also
  reversed. `bindings/acdp-node/package-lock.json` is committed, `.gitignore`'s acdp-node
  section no longer ignores it, and `@napi-rs/cli` is pinned to an exact `3.8.6` in both
  `package.json` and the lockfile (was `^3.8.6`, floating up to an untested 3.9.1). Unlike
  the Cargo halves, `npm ci` was evaluated and rejected as not viable here (`package.json`'s
  self-referential `optionalDependencies` on its own four platform packages resolve to a
  manifest version with no matching publish yet — see `ASSUMPTIONS.md`'s #240 entry below
  for the full measurement) — so `npm install` is kept, and `bindings.yml` gained a one-line
  `node -e` assertion after the install step that fails loudly if the resolved
  `@napi-rs/cli` version ever drifts off `3.8.6`. This closes the gap the 2026-09-06 update
  left open for the npm binding specifically.

## pyo3 version: bumped to 0.29 instead of the planned 0.24 line
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** discovered mid-implementation, not anticipated by the plan (which was
  researched before these advisories existed): `cargo deny check advisories` against the
  originally-planned pyo3 0.24.2 revealed **two additional 2026 RUSTSEC advisories**
  (RUSTSEC-2026-0176, out-of-bounds read in `PyList`/`PyTuple` iterator `nth`/`nth_back`;
  RUSTSEC-2026-0177, missing `Sync` bound on `PyCFunction::new_closure`), both only fixed
  at `>= 0.29.0`. RUSTSEC-2026-0176 is *unaffected* below `0.24.0` and only introduced
  starting at `0.24.0` — meaning the originally-planned 0.24 bump would have *newly
  introduced* a vulnerability that didn't exist at the starting version (0.22), while
  still leaving RUSTSEC-2025-0020 (the one RS-10 named) and RUSTSEC-2026-0177 unfixed.
  Landing 0.24 as literally planned would not have satisfied RS-10's own accept criterion
  ("advisory scan green in CI").
- **Chose:** bumped to `pyo3 = { version = "0.29", features = ["abi3-py39"] }` instead.
  Verified before committing to this: (1) `abi3-py39` still exists as a valid feature at
  0.29.2 (confirmed by inspecting pyo3's own `Cargo.toml` and by a successful `maturin
  develop --release` producing a `cp39-abi3` wheel) — so `requires-python = ">=3.9"` and
  the `bindings.yml` Python matrix (`3.9`/`3.11`/`3.13`) needed no change; (2) the
  migration was two call sites (`Python::with_gil` → `Python::attach`) plus the eight
  already-needed 0.24-era deprecation renames (`value_bound` → `value`, `get_type_bound`
  → `get_type`) — not the large migration effort initially feared; (3) all 172 existing
  Python tests pass unmodified, including the golden-vector parity constant
  (`sha256:f170150d…`) CLAUDE.md says must never drift; (4) `cargo deny check advisories`
  now genuinely exits 0 for this graph.
- **Alternatives:** stay on 0.24 and add reasoned `ignore` entries for RUSTSEC-2026-0176/
  -0177 to `deny.toml` (rejected: the "advisory scan green" criterion would then only be
  true by suppression, not by actually being unaffected — and unlike the existing
  RUSTSEC-2025-0134 ignore, verifying non-reachability of a memory-safety bug deep in
  pyo3's generated codegen is not something that can be confidently asserted by
  inspection); bump only as far as needed to fix each advisory individually (rejected: no
  intermediate version fixes both — both advisories' solution is ">= 0.29.0").
- **Blast radius if wrong:** low, independently verified by a fresh Opus verifier: pyo3
  0.29.2's own advisory-db entries confirm the version choice is strictly correct (clears
  RUSTSEC-2025-0020, -2026-0176, -2026-0177, and incidentally RUSTSEC-2026-0013 too); the
  `abi3-py39` claim was verified against pyo3's actual source, not assumed; all tests pass.
  If reversed, the two-call-site rename and the small deprecation cleanup are easy to
  revert together with the version pin.
- **Status:** CONFIRMED (2026-08-28) — see DECISIONS.md. Both required follow-ups applied:
  `bindings/acdp-py/CHANGELOG.md` now has an `## Unreleased` / `### Security` entry, and
  the PR description states the 0.24→0.29 deviation explicitly.

## bindings/acdp-wasm: pre-existing break discovered, excluded from new advisory job
- **Plan:** plans/rs-wave1-conformance-hardening.md
- **Assumed:** not part of RS-10's scope to fix. Discovered while implementing Phase 3:
  `bindings/acdp-wasm/Cargo.toml:61` pins `getrandom = { version = "0.4", features =
  ["js"] }`, but `getrandom` 0.4 has no `js` feature (only `wasm_js` — see the correctly
  written `getrandom_wasm` alias two lines below). This makes `cargo metadata` fail
  outright for that crate — not just for a new `cargo deny` job, but for **every**
  existing command in `bindings.yml`'s `acdp-wasm` job (native `cargo test`, both wasm32
  builds, `wasm-pack build`, `wasm-pack test --node`). Confirmed via `git log`/`git
  merge-base` that this predates the branch (introduced by commit `d511e03`, "build(deps):
  update getrandom requirement (#133)", already on `main` before this session started),
  and independently confirmed via `gh run view` that the live `acdp-wasm` job on `main` is
  currently failing (run `29128956237` at commit `c4c9be8`) while all 7 sibling jobs
  succeed.
- **Chose (original, since superseded — see Status below):** excluded `bindings/acdp-wasm`
  from the new `bindings-deny` job's matrix (only `[bindings/acdp-py, bindings/acdp-node]`),
  with an explicit comment in `bindings.yml` and `Makefile` naming the exact cause, the
  introducing commit, and stating this is pre-existing and out of scope for this PR. Did
  not attempt the guessed one-line fix (`["js"]` → `["wasm_js"]`) since that's an unrelated
  dependency-resolution bug, not an advisory-scanning concern, and bundling an unrelated fix
  into a supply-chain PR would make the diff harder to review/revert cleanly. **This
  guessed fix was also wrong** — see the reconcile outcome in the Status line below and
  DECISIONS.md for the actual root cause and fix that shipped instead.
- **Alternatives:** fix the one-line `getrandom` bug as a drive-by (rejected: unrequested
  scope creep on a security-supply-chain-focused PR, and the fix deserves its own review —
  e.g., confirming whether the unaliased `getrandom` entry should be removed entirely
  since `getrandom_wasm` may already cover its purpose, which needs more investigation
  than a blind feature-rename); silently include `acdp-wasm` in the matrix anyway
  (rejected: would make the new job spuriously, permanently red for a reason unrelated to
  what it's meant to gate).
- **Blast radius if wrong:** **this is the highest-priority open item from this session,
  independent of RS-1/RS-2/RS-10.** The `acdp-wasm` binding is currently unbuildable and
  untested on `main` — its golden-vector parity guard (`sig-001`/`wit-001` cross-checks
  per CLAUDE.md's binding conventions) is providing zero coverage today, and this has been
  true since 2026-07-10 with nobody noticing (matches the family-wide "idle since
  2026-07-10" status). This should be raised to the user/maintainer promptly and likely
  warrants its own small, dedicated PR — not something this plan's scope should silently
  absorb or silently leave undiscovered.
- **Status:** NEEDS-CHANGE → **applied and re-verified, DONE (2026-08-28)** — see
  DECISIONS.md. User chose to fix in this PR rather than defer. Root cause was corrected
  during reconciliation (the guessed `js`→`wasm_js` fix was wrong; the actual fix is
  reverting the unaliased `getrandom` entry to `version = "0.2"` — the manifest
  deliberately carries two getrandom majors, and a Dependabot bump had mistakenly touched
  the wrong one, a recurrence of a previously-fixed incident, PR #122 → #129 → #133).
  Verified via a dedicated Phase 4 + Opus gate: native tests, wasm32 debug+release builds,
  `wasm-pack test --node`, and `cargo deny check advisories` all pass; `acdp-wasm` is now
  included in the `bindings-deny` job's matrix and the `audit-bindings` Makefile target.

## RS-11: `ACDP_VERSION` default bump — constant bump vs. feature-derived
- **Plan:** `agentcontextdistributionprotocol/plans/siblings/acdp-rs.md` (RS-11, Wave 4)
- **Assumed:** the plan explicitly left the mechanism open ("decide the default stamp
  deliberately — constant bump or feature-derived") without naming a preferred answer,
  so this was a real fork requiring a judgment call, not a defaultable question with an
  obvious answer stated elsewhere.
- **Chose:** a straight constant bump, `ACDP_VERSION = "0.2.0"` → `"0.4.0"`
  (`crates/acdp-primitives/src/lib.rs:43`) — no cargo feature in this crate gates 0.3.0-
  vs-0.4.0-line wire support; every RFC-0011..0015 type is always compiled in, so
  "feature-derived" has nothing to condition on. The newest Final line is exactly what
  the WS-D1 "explicit by default" design intended the constant to track.
- **Alternatives:** (1) feature-derived default (rejected — no feature boundary exists
  to derive from in this crate today; would require inventing cargo features purely to
  serve this switch, which is speculative machinery for a problem that doesn't exist
  yet); (2) leave the constant at `0.2.0` and only fix the stale "drafts" wording
  (rejected — the plan explicitly flagged this as a real drift: "a defaults-using
  producer can't legitimately carry 0.3.0-line fields," which is still true today with
  0.4.0 now Final too); (3) stop and ask before touching the default (considered, but
  the plan's own framing — "decide... deliberately... changelog it," not "ask the human"
  — plus this session's established convention of proceeding on costly-but-reversible,
  non-one-way-door changes with documentation rather than blocking, argued for
  proceeding here).
- **Blast radius if wrong:** moderate, not severe, and cheaply reversible. Verified
  before making the change: no test in this repo asserts a fixed golden `content_hash`
  for a *default*-built (no explicit `.acdp_version(...)`/`.omit_acdp_version()`) request
  — the two golden vectors that pin exact hashes (sig-001, sig-003) both call one of
  those two explicit overrides, so they're unaffected. No `acdp-validation` rule imposes
  a new *required* field on a produced body at 0.3.0/0.4.0 (the only version gate,
  `caps.acdp_version >= 0.3.0 ⇒ supports_idempotency_key`, is on a registry's
  `CapabilitiesDocument`, not a producer's request) — so a bare `.build()` call still
  succeeds. The real exposure is ecosystem-wide: sibling repos that build a default
  `PublishRequest` (e.g. `acdp-playground`, `acdp-control-plane`) will start emitting
  `acdp_version: "0.4.0"` bodies the next time they pick up this crate version, and any
  registry pinned to reject or mis-handle that value would need updating first. If this
  turns out to be premature, reverting is a one-line constant change plus a follow-up
  changelog entry — not a schema or API removal.
- **Status:** CONFIRMED (2026-08-30) — see DECISIONS.md. Confirmed as-is: the constant
  bump has already shipped in two releases (0.8.2, 0.8.3) with no reported breakage; no
  golden vector or validation rule regressed. Reverting now would itself be a second
  wire-behavior change, so the bump stands.

## anchors supersede-settability (RS-8 binding follow-up)
- **Plan:** plans/rs8-bindings-anchors.md
- **Assumed:** the plan's Open Question 1 had no explicit spec answer for whether
  `anchors` should be settable on a supersession request, only that a clearly-best
  default existed and was cheap to reverse.
- **Chose:** exposed `anchors` on both `build_publish_request`/`buildPublishRequest`
  AND `build_supersede_request`/`buildSupersedeRequest`, in both `bindings/acdp-py`
  (`PyAcdpProducer`/`PyAcdpP256Producer`) and `bindings/acdp-node` (`PublishOpts`/
  `SupersedeOpts`) — mirroring `data_refs`'s treatment (JSON-parsed, available on both
  publish and supersede), not `derived_from`'s (publish-only, excluded from supersede).
  Reasoning: anchors are external evidence tied to *this version's* content (a
  blockchain/timestamping commitment over the current body), not an immutable
  lineage fact fixed at first publish — so a later version legitimately needs its own,
  different anchors, same as it needs its own `data_refs`.
- **Alternatives:** publish-only exposure (mirroring `derived_from`) — rejected because
  anchors describe per-version content evidence, not lineage provenance, so restricting
  it to publish-only would block a legitimate supersede use case (re-anchoring a
  corrected or updated version) for no protocol reason; the core `RequestBuilder`
  itself imposes no such restriction (`anchors()` is available in every builder state).
- **Blast radius if wrong:** low and cheaply reversible — this is a pre-1.0, previously
  entirely-absent binding parameter (RS-8's core work never touched either binding), so
  removing `anchors` from `SupersedeOpts`/`apply_supersede_fields` later is a normal,
  expected kind of binding-surface change, not a breaking-contract event. No wire format,
  schema, or core-crate API is affected either way — this is purely which FFI methods
  accept the parameter.
- **Status:** CONFIRMED (2026-08-30) — see DECISIONS.md for the full reconciliation
  record, including two follow-up fixes (clear-anchors capability, an unrelated
  `BODY_FIELD_NAMES` gap) that landed in the same PR as a result.

## Byte equality for CtxId comparison in context-identity binding (fed-011)
- **Plan:** plans/issues-189-191-client-binding-hardening.md
- **Assumed:** byte equality on `CtxId` satisfies conformance fixture
  `fed-011-ctx-id-binding.json`'s requirement that ids be "compared as parsed `acdp://`
  URIs, never as raw strings."
- **Chose:** derived `PartialEq` byte comparison in `verify_retrieved` and
  `fetch_report_inner`. This is sound *today* because the `ctx_id` schema
  (`schemas/json/acdp-common.schema.json:40`) mandates a unique canonical text form —
  lowercase DNS authority, lowercase v4 UUID — so byte equality and parsed equality
  coincide for every valid input. The served side is additionally canonicalized by
  `validate_identifiers` → `CtxId::parse`.
- **Alternatives:** decomposing both sides into (authority, uuid) and comparing
  components — rejected as machinery with no behavioural difference under
  canonical-form uniqueness.
- **Blast radius if wrong:** if a non-canonical or alias form ever becomes legitimate,
  byte equality would produce false refusals (fail-closed, so refusing valid resolves
  rather than accepting invalid ones). Fix would be relaxing the comparison at those two
  call sites — a pure behaviour change, no API break, since `ContextIdMismatch` already
  carries both textual forms.
- **Update (2026-09-06, plans/issues-206-208-bindings-registry-release-gate.md Phase 2,
  #206):** the bindings' equivalent check, `acdp_verify::verify_ctx_id_binding`, makes the
  parse-then-compare step explicit rather than relying on the served side having already
  been canonicalized by an upstream `validate_identifiers` call (the bindings have no such
  call): it parses *both* `served_ctx_id` and `expected_ctx_id` with `CtxId::parse` before
  comparing, so a malformed id on either side fails closed with `SchemaViolation` instead
  of reaching the equality check at all. This is the same deliberate divergence from
  `fed-011-ctx-id-binding.json`'s `uri_encoding_and_path_style_equivalence` case as the
  client's byte-equality choice above — canonical-form-only comparison produces false
  refusals for percent-encoded/path-style forms, never false acceptances — recorded again
  here because it is a second, independent call site making the same choice.
- **Status:** CONFIRMED (2026-09-06) — see DECISIONS.md. Confirmed as-is, no code change:
  fail-closed behavior, documented at both call sites (client and bindings) above.

## `String` (not `CtxId`) fields on `ContextIdMismatch` — corrected rationale
- **Plan:** plans/issues-189-191-client-binding-hardening.md
- **Assumed:** the outcome (`requested`/`served` typed as `String`, not `CtxId`) is
  correct, but the rationale as shipped — "a `CtxId` field would over-promise that it
  parsed" — is factually shaky: `CtxId` is an unvalidated `pub String` newtype today, and
  `ContentHash` in the sibling `HashMismatch` variant is identical in that respect, so the
  "over-promise" argument cuts against both fields equally and doesn't actually
  distinguish `ContextIdMismatch`'s choice.
- **Chose:** the corrected rationale — `requested`/`served` are forensic evidence
  (attacker-controlled text quoted back to an operator for diagnosis), and `String` stays
  honest under future hardening: if `CtxId` is later turned into a parse-validated type,
  a `CtxId` field on this variant would then need a validity bypass to hold a value that,
  by construction, failed to match what was requested. `String` requires no such escape
  hatch. No code change — this replaces the comment/doc rationale only.
- **Alternatives:** leave the original "over-promise" rationale in place (rejected: it is
  demonstrably not the distinguishing argument, since it applies equally to a field this
  PR is not questioning); retype the fields as `CtxId` now (out of scope — the task is
  fixing the rationale, not the type).
- **Blast radius if wrong:** none — this corrects documentation/reasoning only; the
  shipped field types (`String`) are unchanged.
- **Status:** CONFIRMED (2026-09-06) — see DECISIONS.md. Confirmed as-is: prose-only
  correction, zero blast radius, no code change.

## `semver-tool-health` is not a required status check
- **Plan:** plans/issues-206-208-bindings-registry-release-gate.md (Phase 1)
- **Assumed:** adding the job to `ci.yml` is sufficient to satisfy Phase 1's acceptance
  criterion 5 ("a tool-health check exists that is NOT continue-on-error").
- **Chose:** ship the job without touching branch protection. `main`'s required contexts are
  `[rustfmt, clippy, test (ubuntu/macos/windows × stable), conformance (spec fixtures),
  MSRV (1.86), docs, cargo-deny, cargo-vet]` — `semver-tool-health` is absent, so it reddens the
  run but does **not** block merge. The criterion is met literally; its intent needs a
  branch-protection update.
- **Alternatives:** adding it to required checks via `gh api .../branches/main/protection`
  — rejected here because repo-settings changes are outside the standing
  commit/PR/merge/publish authorization, and a required check that has never run green once
  would block every PR the moment it is added.
- **Blast radius if wrong:** a future cargo-semver-checks outage reddens CI visibly but someone
  could still merge past it — strictly better than today (silent false-green), strictly worse
  than a hard gate. Reversible: one branch-protection edit, best made after the job has a green
  history.
- **Status:** NEEDS-CHANGE (2026-09-06) — see DECISIONS.md. The stated blocker has
  expired: `semver-tool-health` (`ci.yml:275-277`) carries no `continue-on-error`, and at
  least 13 consecutive `ci.yml` runs on `main` — from `34079142407` back through
  `34013243642` (verified via `gh run list --workflow=ci.yml --branch main --limit 15
  --json databaseId,conclusion`; the run 8 positions back from `34079142407` is
  `34048649587`, not `34040888637`) — are all `success`, with the streak breaking only at
  a `cancelled` run further back. So a green workflow run now implies the job passed, not
  merely that it never ran red. Add `semver-tool-health` to `main`'s required contexts
  (10 → 11) via
  `gh api .../branches/main/protection`. This is a repo-settings change outside this
  phase's scope and is applied by the orchestrator at Release choreography step 6, after
  the 0.10.0 release PR (#228) has merged — not before, since adding it while #228 is open
  would require it green on a PR the advisory `semver` job is deliberately reddening.

## Unpublished-crate baseline behaviour in cargo-semver-checks is untested
- **Plan:** plans/issues-206-208-bindings-registry-release-gate.md (Phase 1)
- **Assumed:** a workspace crate with no crates.io baseline (newly added, never published) is
  skipped by cargo-semver-checks rather than treated as an error.
- **Chose:** ship without covering this branch. Not triggered by anything in this plan — Phases
  2-7 add public API to existing crates, they do not add a new crate.
- **Alternatives:** constructing a throwaway unpublished crate to observe the exit code —
  rejected as disproportionate for a path this plan cannot reach.
- **Blast radius if wrong:** if such a crate exits 101 rather than 0, the `semver-tool-health`
  job hard-reds on the PR that introduces it, with a misleading "tool error" diagnosis. Caught
  immediately (first CI run on that PR), fixed by an exclusion or an exit-code carve-out.
- **Status:** DEFERRED/MOOT (2026-09-06) — see DECISIONS.md. Unreachable today: no phase
  in any currently-active plan adds a new workspace crate. Self-diagnosing on the first PR
  that does — the first CI run on that PR either passes cleanly (proving the assumption
  right) or hard-reds with a "tool error" diagnosis (proving it wrong and identifying
  exactly which PR needs the exclusion/carve-out). No action needed until then.

## Binding lockfiles resolve independently of the root Cargo.lock
- **Plan:** plans/issues-196-199-215-216-followups.md
- **Assumed/Chose:** accept that the three binding lockfiles
  (`bindings/{acdp-py,acdp-node,acdp-wasm}/Cargo.lock`) resolve independently of the root
  `Cargo.lock` — each binding is its own standalone Cargo workspace, and 20-25 shared
  dependencies differ from root today, including `der` 0.8.1 → 0.8.2 (the P-256 parsing
  path) and `wasm-bindgen` 0.2.127 → 0.2.128.
- **Why it is defensible:** the bindings have their own test suites that exercise *their*
  graph — `make sdk-py`, `make sdk-node`, `make interop`, and `cd bindings/acdp-wasm &&
  cargo test` (which runs the conformance fixtures and golden vectors against the
  binding's own resolution). So the divergent graph is tested, just by a different suite
  than the root workspace's.
- **Alternatives rejected:** pinning ~25 deps in each binding lock to match root, which
  would be a permanent manual maintenance burden with no mechanism to enforce it, and
  which fights cargo's own resolution across genuinely separate workspaces.
- **Blast radius if wrong:** a crypto-path dependency (`der`) could in principle behave
  differently in the published SDK than in the root test suite. Named explicitly because
  it is the P-256 parsing path.
- **Also noted:** nothing currently asserts the binding locks stay current with their
  manifests — a dependency bump without regeneration surfaces as cargo's generic "cannot
  update the lock file" rather than an actionable "run `cargo generate-lockfile`". Known
  and accepted for now; no tripwire built in this phase.
- **Update (2026-09-06, plans/issues-196-199-215-216-followups.md Phase 2, #196a):**
  `cargo-deny`'s advisory gate (`bindings-deny` in `.github/workflows/bindings.yml`) now
  runs `--locked`, so it audits the pinned graph that ships rather than a freshly-resolved
  one. Trade-off, stated honestly: this loses the early-warning property of the unpinned
  form — an advisory affecting a *newer* version of an already-pinned dependency will no
  longer surface here until the lockfile is regenerated. Accepted because knowing "what we
  ship is clean" matters more for a crypto verifier than "what we might ship next is
  clean", and because Dependabot (`.github/dependabot.yml` has cargo entries for all three
  binding dirs) will regenerate the locks and surface it then.
- **Status:** CONFIRMED (2026-09-06) — see DECISIONS.md. Confirmed as-is: an accepted
  architectural trade-off (each binding is tested by its own suite against its own
  resolution), already re-verified once (Phase 2's `--locked` update above). No further
  action.

## Two remaining implicit-resolution tool ranges left unpinned (napi-rs, maturin)
- **Plan:** plans/issues-196-199-215-216-followups.md
- **Assumed:** Phase 3's remit is pinning `taiki-e/install-action` tool versions and
  Action SHAs so the *installed* tool bytes are deterministic — not auditing every
  package-manager version range anywhere in the repo's release tooling. Two pre-existing,
  unrelated instances of the same underlying risk (a build tool that can silently
  re-resolve to a newer release between runs) were found while doing that work but are
  out of scope for this phase.
- **What was found:**
  1. `bindings-release.yml` runs `npx napi …` at **release** time.
     `bindings/acdp-node/package-lock.json` is **not committed**, `@napi-rs/cli` is
     pinned only as `^3.8.6` in `package.json`, and the workflow uses `npm install`, not
     `npm ci`. The tool that builds the published `.node` binaries therefore re-resolves
     its own dependency graph on every release run, with no lockfile to make that
     resolution reproducible or diff-reviewable.
  2. `bindings.yml` runs `pip install 'maturin>=1.5,<2.0'` — an open range with no pin at
     all, so any `1.x` release maturin cuts is picked up immediately on the next CI run.
- **Why out of scope here:** fixing #1 properly means committing
  `bindings/acdp-node/package-lock.json` and switching `npm install` → `npm ci` across
  the node-touching workflow steps — a distinct change with its own blast radius (every
  npm-installing step in `bindings.yml`/`bindings-release.yml` would need auditing for
  compatibility with `ci`'s stricter lockfile-must-match-manifest behavior, and the
  lockfile itself becomes a file that needs to stay in sync going forward). Fixing #2
  means picking and pinning a specific maturin version/SHA-equivalent, a separate,
  independent decision. Neither is a `taiki-e/install-action` pin, and bundling either
  into this phase's diff would mix an unrelated fix into a PR whose stated purpose is the
  install-action tool-version/`fallback` hardening.
- **Blast radius:** the napi-rs one sits on the **release** path specifically — it builds
  the `.node` binaries that get published to npm, so an unreviewed transitive dependency
  bump there ships directly to consumers with no lockfile diff to catch it in review. The
  maturin one is lower-severity (an open semver range on a single build tool, not the
  publishable artifact's own dependency graph) but has the same "re-resolves silently"
  shape.
- **Status:** RESOLVED (2026-09-13) — both halves shipped; see the closing update at the
  end of this entry. The text below is preserved as written while this was still open:
  **evidenced. See acdp-rs#240 (filed 2026-09-10 during the
  issues-224-226-229-231-234 wave).** The deferred `npm install` → `npm ci` change is no longer
  hypothetical: the unpinned `"@napi-rs/cli": "^3.8.6"` caret range combined with a gitignored
  `bindings/acdp-node/package-lock.json` (`.gitignore:32`) caused CI to resolve a newer napi-rs
  whose codegen differs, so the committed `index.js`/`index.d.ts` are reported stale with ZERO
  source changes. That reddens `acdp-node (node 20/22)` on every `bindings.yml` run, and because
  `interop` declares `needs: [... acdp-node ...]`, it also SKIPS the interop job — silently
  disabling both the NAPI staleness guard and the #229 wasm-parity suite. The "own blast radius"
  reasoning for deferring still stands as written; what has changed is the cost of NOT doing it,
  which is now two guards not running rather than a tidiness concern. Tracked in #240 with the
  concrete options; this entry stays UNCONFIRMED only because the fix itself has not been made.
- **Update (2026-09-10, plans/issues-240-242-seamb-wave.md Phase 1):** item 1 (napi-rs) is
  now RESOLVED, item 2 (maturin) remains open/UNCONFIRMED. `bindings/acdp-node/package-lock.json`
  is committed, `@napi-rs/cli` is pinned to exact `3.8.6` in both `package.json` and the
  lockfile, and `bindings.yml` asserts the resolved version after `npm install`. Be precise
  about what did **not** change: `npm install` was deliberately KEPT, not switched to
  `npm ci` — `package.json`'s self-referential `optionalDependencies` on its own four
  platform packages (pinned to the manifest's `0.10.0`) have no matching publish yet (the
  highest published is `0.8.5`), so `npm ci` dies with `EUSAGE / Missing: ... from lock
  file` and `--omit=optional` does not help. That `npm ci` switch is filed as its own
  follow-up (Phase 4 of the same plan), not shipped here. The interop-job unblocking this
  entry described (the staleness guard + #229 wasm-parity suite both being skipped via
  `needs: [... acdp-node ...]`) is restored as a side effect: the guard now runs against a
  real, reviewable pin instead of a floating caret with no committed lock. The maturin
  half (`pip install 'maturin>=1.5,<2.0'`, an open range with no pin) was untouched by this
  phase and stays open — **now tracked as acdp-rs#252** (filed 2026-09-10 during this plan's
  `/reconcile` pass) rather than living only in this file. Disposition: **DEFERRED, not
  resolved.** Reasoning, recorded so it is not re-litigated: `@napi-rs/cli` GENERATES the
  committed `index.js`/`index.d.ts` that ship to consumers, so its drift was both invisible
  and consequential; maturin is a build tool whose output is a wheel and does not generate
  committed source that a guard diffs, so a bump there is far likelier to fail loudly than to
  silently alter a checked-in artifact. Lower severity, same shape. `pytest` is unpinned on the
  same two lines (`bindings.yml:79`, `:315`) and should be handled together with it.

- **Update (2026-09-13, close-out): RESOLVED — both halves shipped, entry closed.** Item 2
  (maturin) landed as **#252**: `bindings.yml:79` and `:331` now install
  `'maturin==1.15.0' 'pytest==8.4.2'`, and each is followed by an
  `importlib.metadata.version(...)` assertion (`:90`, `:336`) so a silently-resolved
  different version fails the job rather than running under it. The `pytest` half named in
  the paragraph above was handled in the same change, as that paragraph asked. The single
  pin had to be `8.4.2`, not the newest: the matrix was silently resolving **two pytest
  majors** (9.1.1 on 3.11/3.13, 8.4.2 on 3.9, since pytest 9 requires >=3.10 and
  `pyproject.toml` declares `requires-python = ">=3.9"`), so a uniform pin meant downgrading
  two legs rather than dropping the 3.9 leg — a support change, not a CI tweak.
- The `npm install` → `npm ci` switch this entry deferred — the one whose "own blast radius"
  reasoning is spelled out above — landed as **#249**. The blocker was exactly what the
  2026-09-10 update predicted: `package.json`'s self-referential `optionalDependencies` on
  its own four platform packages had no matching publish, so `npm ci` died with
  `EUSAGE / Missing: ... from lock file`. Removing that block was verified safe for
  publishing against installed `@napi-rs/cli@3.8.6`, whose
  `resolveRootOptionalDependencies` **writes** an entry per `napi.triples` target rather
  than merely updating pre-existing ones — so the published artifact still carries its
  platform deps. `bindings.yml:130`, `:348` and `:418` now run `npm ci`; the PR
  self-validated, since its own CI was the first run of the new command.
  `bindings-release.yml:184` deliberately stays on `npm install`, documented in place at
  `:170`: that step stamps the version *before* installing, so the manifest and the
  committed lockfile do not agree at that moment by construction.
- **Nothing in this entry remains open.** Both named gaps have a merged fix and a
  `DECISIONS.md` record; the register entry outlived them by a day.

## `Swatinem/rust-cache` runs before the `--locked` gate in three workflows
- **Plan:** plans/issues-196-199-215-216-followups.md (Phase 2, #196a)
- **Assumed:** that `Swatinem/rust-cache` cannot defeat the lockfile gate the way
  `cargo test` did (finding NEW-1, where an unlocked cargo invocation running *before* the
  gate silently repaired a stale lock, so the gate then passed).
- **Chose:** proceed without verifying. rust-cache runs before the gate in three places —
  `bindings.yml:179` (before `:190`), `bindings-release.yml:71` (before `:94`),
  `acdp-wasm-release.yml`'s `Swatinem/rust-cache` step (before its `--locked` gate step,
  a few steps later in the same job — exact line numbers have already shifted once
  during this plan and aren't worth re-pinning here). The round-3 verifier's reading is
  that
  rust-cache's `cargo metadata` call lives in its **post/cleanup** step, which runs after
  all job steps and therefore cannot repair a lock before the gate sees it. It explicitly
  did **not** confirm this against the action's source and recorded it as unconfirmed
  rather than asserting it.
- **Alternatives:** read `Swatinem/rust-cache`'s source at the pinned SHA
  (`f0d9c3887740aee45f6153b24b3a6b815192ec16`, v2.9.1) to confirm which step invokes
  `cargo metadata`; or move the gate above the cache restore, which would cost the gate
  step a cold registry fetch on every run.
- **Blast radius if wrong:** the same fail-open class as NEW-1 — the binding lockfile gates
  would look like protection while silently permitting a drifted lock. It would not fail
  loudly; it would just never catch anything. Cheap to fix (reorder two steps), but only if
  someone knows to look.
- **Status:** CONFIRMED-as-safe (2026-09-06, corrected) — see DECISIONS.md.

  **Retraction:** an earlier revision of this entry recorded, as a confirmed real gap,
  that rust-cache's `restore.js` (the action's `main` step, which runs in place in the
  job, not in post/cleanup) reaches a `cargo metadata --all-features --format-version 1`
  call with no `--locked` flag, and that this could silently repair a drifted binding
  lockfile before the `--locked` gate step ever inspected it — prescribing a step
  reorder in three workflows plus a follow-up issue. **That was wrong, and is retracted.**
  The step-ordering premise was true (rust-cache does precede the gate: `bindings.yml:179`
  before `:190`, `bindings-release.yml:71` before `:94`, `acdp-wasm-release.yml:123` before
  `:146`), but the call it reaches **does** pass `--no-deps`
  (`dist/cleanup-BPghO_DY.js:34492`), and `cargo metadata --no-deps` performs no dependency
  resolution and does not write `Cargo.lock` — proven on a synthetic crate with a
  deliberately drifted lock: with `--no-deps` the lockfile stayed byte-identical and still
  drifted; without `--no-deps` it was repaired. The **resolving** variant
  (`getPackagesOutsideWorkspaceRoot`, no `--no-deps`, `cleanup-BPghO_DY.js:34488`) has
  **zero call sites in `restore.js`** — its only caller is **`save.js:64`**, the `post:`
  step, which runs *after* the gate. So the earlier "hopeful reading" — that the resolving
  `cargo metadata` call lives in the post/cleanup step, which runs after all job steps —
  was **correct**; this round's contrary finding (that `restore.js` itself reaches an
  unlocked *resolving* call) was an over-read of which of the two `cargo metadata`
  invocations `restore.js` actually reaches, and is now retracted. **The existing gate
  placement in all three workflows is already sound. No workflow reorder is needed and no
  follow-up issue should be filed.**

## `cargo-vet` is knowingly installed from QuickInstall, not upstream
- **Plan:** plans/issues-196-199-215-216-followups.md (Phase 3)
- **Assumed:** that no other `taiki-e/install-action` pin/version combination gets
  `cargo-vet` 0.10.2 from a verified upstream artifact, and that `fallback: none` — the
  policy applied to every other pinned tool in this repo — is not viable for this one
  step.
- **What was found:** three alternatives were tried and each is closed off.
  1. **Bump the `install-action` SHA.** Not possible: `manifests/cargo-vet.json` has never
     carried a `0.10.2` entry at any SHA, checked through the latest release (v2.87.7),
     which still tops out at `0.10`/`0.10.0`. There is no SHA to bump to.
  2. **Downgrade the `tool:` pin to `0.10.0`** (the version the manifest does have).
     Verified locally that `cargo-vet 0.10.0` cannot parse this repo's
     `supply-chain/imports.lock`, which uses crates.io's newer trusted-publisher schema
     (`trusted-publisher = "github:..."`, no `user-id` field): fails with `missing field
     `user-id``. Regenerating the lockfile with 0.10.0 would discard that
     trusted-publisher provenance data, a real quality regression, not just a version bump.
  3. **`fallback: none`**, the policy on every other install-action step in this repo.
     Would turn the manifest miss into a hard failure of `vet`, a required status check on
     `main`, on every single run.
- **Chose:** set `fallback: cargo-binstall` explicitly on the `cargo-vet` step (rather than
  relying on install-action's identical implicit default), and documented the gap plainly
  in both the step's comment and `docs/supply-chain.md`'s "Pinned-tool inventory" instead
  of letting it read as if every pin installs from a verified upstream artifact.
- **Filed upstream:** https://github.com/taiki-e/install-action/issues/1997, asking for a
  `cargo-vet` `0.10.2` manifest entry — the actual fix, once available, is to add that
  manifest coverage and this gap closes on its own with no further code change needed here.
- **Blast radius:** `cargo-vet` — the tool this repo relies on to audit its own dependency
  supply chain — is itself installed from QuickInstall, a third-party rebuild service, not
  a verified upstream release. A compromised or tampered QuickInstall rebuild of
  `cargo-vet` could produce a false-clean supply-chain audit result (the `vet` job passing
  while auditing with a tampered binary), which is a meaningfully different risk profile
  than every other tool in the table, none of which have this exposure.
- **Status:** DEFERRED (2026-09-06) — see DECISIONS.md. Analysis confirmed accurate; no
  further local action available (all three alternatives are closed off, as documented).
  Tracked via the filed upstream issue (`taiki-e/install-action#1997`); revisit once that
  manifest gains `0.10.2` coverage, at which point this gap closes with no code change
  needed here.

## `cargo-fuzz` is knowingly installed with an unconditional, undisableable QuickInstall fallback
- **Plan:** plans/issues-196-199-215-216-followups.md (Phase 3)
- **Assumed:** that the `fuzz.yml` comments this phase set out to correct had the direction
  of the gap backwards — they claimed a missing `tool:` version at the pinned
  `install-action` SHA (`82fc4055…`) "already hard-fails the step with no silent
  QuickInstall path," when reading `main.sh` at that SHA (`:612-618`, `:621-632`,
  `:692-700`) shows a manifest or version miss for a tool with `rust_crate` set (which
  `cargo-fuzz.json` has) falls through to `cargo binstall --force --no-confirm --locked`,
  not `bail`. The `fallback` input didn't exist yet at this SHA to disable that behavior —
  its absence means the binstall fallback is unconditional and cannot be turned off, not
  that it doesn't exist.
- **What was found:** two alternatives were tried and each is closed off, same shape as
  the `cargo-vet` gap above.
  1. **Bump the `install-action` SHA to get the `fallback` input.** Not possible without
     trading one gap for a worse one: `manifests/cargo-fuzz.json` does not exist at
     `0751bff5` (the SHA this repo already uses for `wasm-pack`/`cargo-deny`) —
     cargo-fuzz has been dropped from install-action's manifest set entirely (also absent
     from its `TOOLS.md`). A bump makes cargo-fuzz a permanent manifest miss: silent
     QuickInstall under the default `fallback`, or a hard-failing fuzz job if
     `fallback: none` were added.
  2. **Add `fallback: none` at the current SHA anyway.** Not possible: this SHA predates
     the `fallback` input's existence in `install-action`'s `action.yml` (only
     `tool`/`checksum` exist), so the key would be an undefined input — inert at best,
     misleading (implying a control that isn't there) at worst. This round is explicitly
     text-only and does not add a `fallback:` key for exactly this reason.
- **Chose:** left the `tool:` pin and SHA untouched (`cargo-fuzz@0.11.2` @ `82fc4055…`,
  currently present in that SHA's manifest and equal to its `latest`, so nothing installs
  from QuickInstall today) and rewrote the `fuzz.yml` comments plus
  `docs/supply-chain.md`'s "Pinned-tool inventory" to state the gap plainly — a second
  disclosed exception alongside `cargo-vet`, not a false reassurance that no gap exists.
- **Blast radius:** a future bump of the `cargo-fuzz@0.11.2` pin to a version absent from
  this SHA's manifest would silently pull a QuickInstall rebuild into the fuzzing job with
  no way to make that fail loudly at this SHA. Lower than the `cargo-vet` gap's blast
  radius: the fuzz job is not a required status check on `main` (weekly schedule + a
  PR-triggered build-only check), whereas `cargo-vet` gates every PR.
- **Status:** DEFERRED (2026-09-06) — see DECISIONS.md. Same shape as the `cargo-vet` gap
  above and equally closed-off locally; lower severity since `fuzz.yml` is not a required
  check. No action needed unless the `cargo-fuzz` pin or the `install-action` SHA changes.

## Binding versions are NOT independently versioned in practice (2026-09-06, Phase 8)

- **Context:** the owner's decision "bindings go to 0.9.0 with a migration note" rested on
  the plan's premise that the bindings, being outside release-plz's `version_group`, are
  "standalone packages versioned independently", so a breaking binding change is a
  "0.8.x → 0.9.0 bump on those packages alone".
- **The first half is true, the conclusion is not.** All three release workflows overwrite
  the manifest version with the dispatch input before building:
  `acdp-py-release.yml:83-88` (and again `:128-133`), `bindings-release.yml:96-101`
  (and `:155`), `acdp-wasm-release.yml:150-154`. `release-plz.yml:92-101` dispatches all
  three at the *crate's* version, and its own comment at `:88-90` says so outright:
  "the published artifact version == the acdp version".
- **Observed, not merely inferred:** PyPI `acdp` is at **0.9.1** while
  `bindings/acdp-py/Cargo.toml` read **0.8.0** before this phase. The manifest version is
  dead metadata on the cascade path; the published version tracks the crate family.
- **Consequence:** with the next release computing 0.10.0 (PR #227's `PublishCommit` break),
  Phase 8's manifests and CHANGELOG headings saying 0.9.0 would document a release that
  can never ship via the cascade.
- **The manifest version DOES matter on one path:** a manual `gh workflow run` with an
  empty `version` input, or an `acdp-{py,node,wasm}-v*` tag push, falls back to the tag /
  manifest. So the claim is true-only-under-conditions, and the conditions are not how
  releases actually happen.
- **Chose:** referred the call back to Fable, which is exactly the delegation the owner set
  up ("bindings go to 0.9.0" was the stated default to depart from only for a concrete
  reason, and this is a concrete reason). Decision and its rationale recorded in
  plans/PROGRESS.md.
- **Blast radius:** version strings only, and only before publish — fully reversible until
  the release PR merges. After publish, npm/PyPI immutability makes it permanent.
- **Status:** CONFIRMED (2026-09-06/07) — see DECISIONS.md. Resolved this session: Fable
  decided 0.10.0 for the bindings (matching the crate family's cascade-computed bump from
  PR #227's break), and PR #230 implemented it.

## Phase 1 (issues-273-279-284-285-rfc0014-wave) — CHANGELOG.md entry: correction
**RETRACTED.** The original entry here (skip the hand-edit, claiming only `chore: release`
commits touch `CHANGELOG.md`) was factually wrong — caught by Phase 1's verifier, which ran
`git log --pretty=format:"%h %s" -- CHANGELOG.md` and found 17 non-release commits hand-writing
`## [Unreleased]` entries in the same commit as breaking/notable code changes (e.g. `0f9425b
feat(server)!: ...`, `0fe9b77 feat(primitives): ...`). My original `git log` check was too
shallow (likely filtered to too-recent history) and I didn't verify the claim carefully enough
before acting on it. Fixed: added a proper `### Changed` / `[BREAKING]` entry to
`CHANGELOG.md`'s `## [Unreleased]` section covering both Phase 1 (#284) and Phase 2 (#285),
matching `0f9425b`'s style. No lasting blast radius — caught before commit.
- **Status:** CONFIRMED (self-corrected same session, before any commit)

## Phase 1 — verified.rs gate widened beyond the plan's named files
- **Plan:** plans/issues-273-279-284-285-rfc0014-wave.md, Phase 1
- **Assumed:** the plan named `acdp-client/src/verified.rs:1467,1600` as recompile-only
  (unconditional `verify_embedded_hash(dr)` calls needing no logic change).
- **Chose:** on inspection, both sites were actually gated by
  `if let (Some(emb), Some(_)) = (&dr.embedded, &dr.content_hash)` — only firing
  `verify_embedded_hash` when the *root* hash was present, silently skipping the
  embedded-only case that is Check 8's primary (RFC-required) obligation. Widened the gate to
  `dr.content_hash.is_some() || emb.content_hash.is_some()` at both sites, matching the fix
  already made in `acdp-client/src/data_ref.rs`.
- **Alternatives:** leave as the plan described (rejected — would ship Phase 1 with a real,
  newly-relevant gap in `VerifiedContext::fetch_report`/its sibling, undermining the phase's
  own purpose).
- **Blast radius if wrong:** low — strictly additive verification (more cases now get
  checked, previously-passing cases are unaffected); reversible by narrowing the condition
  back in one commit.
- **Status:** CONFIRMED (2026-09-22) — see DECISIONS.md. Independently re-checked against
  RFC-ACDP-0002-context-body.md:294-296 in the spec checkout: Check 8's obligation is
  scoped to `embedded.content_hash`; checking the root hash too is a permitted MAY, never
  forbidden. Both call sites match `data_ref.rs:240`'s already-fixed condition.

## Phase 1 — cargo-semver-checks environment mismatch, fell back to manual review
- **Plan:** plans/issues-273-279-284-285-rfc0014-wave.md, Phase 1, acceptance criterion 8
- **Assumed:** `cargo semver-checks -p acdp-types` would run and confirm the breaking flag.
- **Chose:** it failed with `unsupported rustdoc format v60 (supported: v53, v55, v56)` — a
  local nightly-toolchain/tool-version mismatch, not a code issue. Used the acceptance
  criterion's own explicit "(or manual review)" fallback: `EmbeddedContent` is a plain
  `pub struct` (not `#[non_exhaustive]`) with public fields; adding a field to it breaks any
  existing external `EmbeddedContent { encoding, content }` struct-literal construction
  (`E0063` missing field) — confirmed necessary in this very crate, where every
  construction site needed a `content_hash: None`/`Some(...)` addition to keep compiling.
  This is unambiguously a breaking change.
- **Alternatives:** install a matching nightly toolchain to unblock the tool (deferred — pure
  environment yak-shaving, not blocking, and `release-plz.yml`'s CI-hosted semver-checks run
  is the actually-blocking gate at release time, on a controlled toolchain).
- **Blast radius if wrong:** none on correctness (the breaking classification is independently
  certain); only affects whether local tooling can auto-confirm it pre-release.
- **Status:** CONFIRMED (2026-09-22) — see DECISIONS.md. The local toolchain was upgraded
  later this session (0.45.0 → 0.50.0) for an unrelated reason; re-ran it and it now
  independently confirms the exact breaking classification (`constructible_struct_adds_field`
  on `EmbeddedContent.content_hash`) manual review reached — tooling and manual reasoning
  now agree.

## Phase 2 (issues-273-279-284-285-rfc0014-wave) — pub-009 assertion widened beyond the plan's named files
- **Plan:** plans/issues-273-279-284-285-rfc0014-wave.md, Phase 2
- **Assumed:** the plan's Files section named only the two functions and their call sites as
  needing changes, plus new dk-driven tests to add.
- **Chose:** found `did_web_enforcement_fixtures`'s existing "pub-009" assertion block
  (tests/conformance.rs) directly exercised `validate_did_key_key_id_form` with a fragment
  mismatch and asserted the old `SchemaViolation` behavior — updated it to assert
  `KeyResolution`, matching the actual (correct, spec-required) new behavior.
- **Alternatives:** leave it (rejected — it would fail as soon as the fix landed, an
  immediate self-inflicted regression the plan's own acceptance criteria would have caught
  at `cargo test` time regardless, just later and with less context than fixing it here).
- **Blast radius if wrong:** none — this only tightens an existing assertion to match the
  behavior the phase's own acceptance criteria require; the test would fail loudly if the
  reasoning were wrong.
- **Status:** CONFIRMED (2026-09-22) — see DECISIONS.md. `KeyResolution` matches
  RFC-ACDP-0001 §5.11.1 step 1's MUST-level requirement (checked against the actual spec
  text), and the `pub-009` fixture passes under `ACDP_REQUIRE_CONFORMANCE=1`.

## Phase 4 (issues-273-279-284-285-rfc0014-wave) — Arm 3's error-code gate needs opposite fail-closed polarity from §10's rejection gate
- **Plan:** plans/issues-273-279-284-285-rfc0014-wave.md, Phase 4
- **Assumed:** the plan's approach section suggested one `>= 0.5.0` version-gate function,
  reused for both the new §10 interim-form-retirement check and Arm 3's error-code
  selection, both fail-closed the same way `key_revocation_gate_applies` already is
  (malformed input → gate ON).
- **Chose:** implemented it that way first, then ran the full test suite and hit a real,
  pre-existing regression test failure:
  `tests/key_revocation_publish_gate.rs::revocation_superseded_by_non_revocation_rejected_under_malformed_acdp_version`
  expects `SchemaViolation` under a malformed `acdp_version`, but reusing one fail-closed
  gate made Arm 3 emit the new `RevocationTypeMismatch` code instead. Realized the two
  gates need opposite polarity: §10's rejection gate must fail closed toward TRUE
  (malformed → reject, matching the existing security-conservative pattern), but Arm 3's
  error-CODE gate must fail closed toward FALSE (malformed → do NOT claim the new code) —
  `registries/error-codes.md` states `revocation_type_mismatch` "MUST NOT be emitted by
  implementations declaring acdp_version < 0.5.0," and a malformed version string is not a
  legitimate `>= 0.5.0` declaration either way, so claiming it would be the one thing that
  could violate that MUST NOT. Split into two functions:
  `key_revocation_retirement_gate_applies` (fail-closed true, §10 only) and
  `advertises_0_5_0_or_higher` (fail-closed false, Arm 3's code choice only) — both in
  `crates/acdp-server/src/registry/validator.rs`.
- **Alternatives:** keep the pre-existing test's expectation and update it to accept the
  new code under a malformed version (rejected — the test's own reasoning is specifically
  about the gate applying, not about which code fires under malformed input, and changing
  it to accept a spec violation would be masking a real bug, not fixing a stale assertion).
- **Blast radius if wrong:** low — worst case a malformed `acdp_version` on a genuinely
  `>= 0.5.0` registry would surface the older `SchemaViolation` code instead of the more
  specific `RevocationTypeMismatch` one; the request is still rejected either way, so no
  security regression, only a slightly less-specific error for an already-malformed
  capabilities document (itself a registry misconfiguration).
- **Status:** CONFIRMED (2026-09-22) — see DECISIONS.md. Independently confirmed the spec
  text (`registries/error-codes.md:60`) matches the claimed MUST-NOT verbatim, and that the
  asymmetric polarity is structurally correct (the two functions answer different questions,
  each with its own safe default under uncertainty), not a coincidental patch. Follow-up
  applied: `key_revocation_retirement_gate_applies` now has its own direct
  malformed-`acdp_version` test (previously only proven by structural identity with the
  well-tested `key_revocation_gate_applies`) — see
  `interim_form_retirement_gate_fails_closed_on_malformed_acdp_version` in
  `crates/acdp-server/src/registry/validator.rs`.

## Phase 4 (issues-273-279-284-285-rfc0014-wave) — added direct unit-test coverage beyond the plan's Tests field
- **Plan:** plans/issues-273-279-284-285-rfc0014-wave.md, Phase 4
- **Assumed:** the plan's own Tests field states Phase 4's new code paths are "covered by
  Phase 6 (the rev-003 O/P/Q/R conformance fixtures) plus the six pre-existing
  key_revocation_publish_gate.rs tests as regression coverage" — implying Phase 4 itself
  need not add direct tests for the new branches, deferring that to a later phase.
- **Chose:** added six direct unit tests in `crates/acdp-server/src/registry/validator.rs`'s
  own test module covering both new behaviors at both sides of the 0.5.0 boundary (Arm 3's
  new error code at >= 0.5.0 and unchanged below it at 0.4.9; the §10 interim-form
  rejection with and without `supersedes`, and confirming the standard form is NOT
  over-rejected) — on top of, not instead of, what the plan's Tests field names. Shipping
  new branching logic with zero direct coverage until a separate, later phase lands is a
  real gap under `/implement`'s "a phase without tests is not complete" constraint,
  independent of whether Phase 6 will eventually add fixture-driven coverage too.
- **Alternatives:** ship Phase 4 with only the plan's named coverage (rejected — see above);
  wait and add these tests as part of Phase 6 instead (rejected — Phase 6 is a separate,
  later PR per the plan's merge sequence, so Phase 4 would ship new, security-relevant
  branching logic completely untested in the interim).
- **Blast radius if wrong:** none — strictly additive test coverage; if any assumption
  about expected behavior embedded in these tests were wrong, the tests would fail loudly
  rather than silently passing.
- **Status:** CONFIRMED (2026-09-22) — see DECISIONS.md. Confirmed "test immediately
  rather than deferring to Phase 6" was the right call in retrospect: Phase 6 landed later,
  in a separate PR, so deferring would have left security-relevant fail-closed logic
  untested in `main` for an indeterminate stretch. The later Phase 6 facade-level tests are
  intentional two-layer coverage, not accidental duplication.

## Phase 5 (issues-273-279-284-285-rfc0014-wave) — plan's E/F "already covered" claims needed correction
- **Plan:** plans/issues-273-279-284-285-rfc0014-wave.md, Phase 5
- **Assumed:** the plan's "reuse, don't duplicate" guidance stated scenario E is "essentially
  already covered by `rev_002_earliest_boundary_across_lineage`" and scenario F is "essentially
  already covered by `find_revocations_recovers_retracted_predecessor_across_lineage_supersession`" —
  suggesting those two existing tests could be extended/renamed rather than adding new ones.
- **Chose:** verified both claims directly against the existing test bodies before writing any
  code (per the plan's own fallback instruction to "verify against the actual fixture keys...
  rather than assuming the existing test already targets the new JSON path"), found both too
  generous, and added four new dedicated tests instead of extending the two existing ones:
  `rev_002_earliest_boundary_across_lineage` tests a structurally different WIDENING lineage
  with non-fixture timestamps (its own comment disclaims being a lettered rev-002 scenario);
  `find_revocations_recovers_retracted_predecessor_across_lineage_supersession` proves discovery
  and the `effective_boundary` value but never drives a `classify_under_revocation` verdict.
  Left both existing tests untouched since they remain valid, independently useful coverage of
  adjacent properties, rather than repurposing them and losing that coverage.
- **Alternatives:** extend/rename the two existing tests as the plan suggested (rejected —
  would have either weakened their existing, still-useful assertions or produced a test doing
  double duty in a way that obscures which property each assertion is actually pinning); treat
  the plan's claim as authoritative without direct verification (rejected — the plan itself
  explicitly warned against this).
- **Blast radius if wrong:** none — strictly additive; the two pre-existing tests are unchanged
  and still pass, so no coverage was lost even if this correction turns out to have been overly
  cautious.
- **Status:** CONFIRMED (2026-09-22) — see DECISIONS.md. Both new-vs-existing test claims
  verified directly against the merged test bodies; the two pre-existing tests are untouched
  and all four new tests drive a real `classify_under_revocation` verdict using
  fixture-sourced timestamps, not just discovery.

## Phase 6 (issues-273-279-284-285-rfc0014-wave) — scoped down from "18 new tests" to the gaps a two-layer analysis actually found
- **Plan:** plans/issues-273-279-284-285-rfc0014-wave.md, Phase 6
- **Assumed:** the plan's acceptance criteria could be read as wanting a new test for every one
  of rev-003's 18 scenario letters (A-R) plus rev-004's 3, and explicitly warns against assuming
  any of them is "already covered" without checking.
- **Chose:** checked, per-scenario, against BOTH `crates/acdp-server/src/registry/validator.rs`'s
  own unit test module (thorough pre-existing coverage for A-M/Q, confirmed by reading each
  relevant test's body) and `tests/key_revocation_publish_gate.rs`'s facade-level tests
  (thorough for I/J and Arm 3 at 0.3.0/0.2.0, absent entirely for the 0.5.0 boundary) — then
  added exactly what survived that check: 3 validator-unit tests (N, P, R) + 4 facade tests
  (O, P, Q, R at 0.5.0) + 3 retrieval tests (rev-004 A/B/C, zero prior coverage anywhere).
  Deliberately did not add facade-level duplicates for A-M/Q, reasoning that the fixture's own
  text states those add no new normative requirement over 0.3.0 and this file's pre-existing
  self-revocation/Arm-3 tests already establish facade-level propagation for that class of rule.
- **Alternatives:** write all 18+3 as fresh tests regardless of existing coverage (rejected —
  the plan itself explicitly warns against assuming a fixture being new means the underlying
  obligation is untested, and 13+ near-duplicate facade tests of already-exhaustively-unit-tested
  shape rules would be low-signal bulk, not "genuinely missing" coverage); rely on validator.rs's
  unit coverage alone and skip the facade layer entirely for 0.5.0 (rejected — this file's own
  stated principle, used to justify Phase 6's original I/J facade tests, applies equally to the
  brand-new 0.5.0 logic Phase 4 of this same wave introduced).
- **Blast radius if wrong:** low — if this judgment under-covers, the gap is at the facade
  layer only (logic itself remains validator-unit-tested either way), and is straightforward to
  close later with more facade tests; nothing here weakens an existing assertion.
- **Status:** CONFIRMED (2026-09-22) — see DECISIONS.md. Verified counts against the actual
  merged diff (exactly 3+4+3 new tests, matching the claim) and independently re-checked 8
  of the 13 skipped rev-003 scenario letters directly against the pinned spec fixture — all
  8 have an exact pre-existing match (same rejection shape, same asserted error code/status).
  The gap analysis holds under independent scrutiny, not just self-report.

## Phase 8 (issues-273-279-284-285-rfc0014-wave) — added a `recomputed_hash()` accessor not named in the plan's public API list
- **Plan:** plans/issues-273-279-284-285-rfc0014-wave.md, Phase 8
- **Assumed:** the plan's Files section lists `recomputed_hash: ContentHash` as a private
  field on `Proven<'a>` and names exactly three accessors (`agent_id()`, `key_fingerprint()`,
  `request()`) — no fourth accessor for the hash.
- **Chose:** added `pub fn recomputed_hash(&self) -> &ContentHash` anyway. Built as specified
  first (field present, no accessor) and hit a real `-D warnings` failure:
  `#[derive(Debug)]` does not suppress `dead_code` for a field rustc considers otherwise
  unread (confirmed directly — `cargo build -p acdp-server --all-features` emitted "field
  `recomputed_hash` is never read ... `Proven` has a derived impl for the trait `Debug`, but
  this is intentionally ignored during dead code analysis"), so the field-with-no-consumer
  shape as literally specified does not compile clean under this repo's required lint gate.
  The plan's own resolved Open Question #4 explicitly declines to thread the real value
  through `commit_via_store`/the `RegistryStore` trait this phase (a materially bigger,
  cross-repo-relevant change to `PublishCommit`'s shape) — so the smallest fix consistent
  with that decision is exposing the field the same way the other three are exposed, rather
  than leaving it unused or suppressing the lint.
- **Alternatives:** `#[allow(dead_code)]` on the field (rejected — hides a real question about
  whether the field belongs at all, for a codebase with no other `allow(dead_code)`
  precedent found in this crate); drop the field entirely, keeping only what's consumed today
  (rejected — the plan explicitly wants `Proven` to carry the real recomputed hash rather
  than relying on a downstream re-fabrication, per the same Open Question #4 discussion; a
  caller holding only a `Proven`, not the original request, has no other way to learn the
  verified hash).
- **Blast radius if wrong:** trivial — an unused-but-harmless public getter; removing it
  later is not a breaking removal concern worth blocking on (it would be breaking in the
  strict semver sense, but this crate hasn't shipped `Proven` yet at all, so there is no
  external caller to break by adjusting the surface before the first release that includes it).
- **Status:** CHANGED (2026-09-22) — see DECISIONS.md. `/reconcile`'s independent review
  found the "no other way to learn the hash" premise above doesn't hold:
  `proven.request().content_hash` (one of the plan's own 3 named accessors,
  `PublishRequest.content_hash` being `pub`) already exposes the identical value, since
  `Proven` always borrows `req`. Removed `pub fn recomputed_hash()`; replaced it with a
  `debug_assert_eq!` inside `commit_proven` that actively checks the same invariant the
  field exists to prove, instead of exposing a public getter that duplicates existing
  surface. `Proven`'s public API is now exactly the plan's originally-named 3 accessors
  (`agent_id`, `key_fingerprint`, `request`). Applied immediately (not deferred) since this
  crate has not released `Proven` yet, making the change genuinely costless today.
