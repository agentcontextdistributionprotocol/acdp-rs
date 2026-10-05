# DECISIONS

Reconciliation log for `plans/archive/rs-wave1-conformance-hardening.md` (RS-1, RS-2, RS-10). Each
entry: the original assumption, the recommending agent's analysis, the user's verdict, and
the resulting status.

## 2026-08-28 — bindings/acdp-wasm: pre-existing break discovered, excluded from new advisory job

**Assumption:** `bindings/acdp-wasm` was found completely broken on `main` (unrelated to
this PR — `getrandom` version/feature mismatch making `cargo metadata` fail outright,
introduced by commit `d511e03`). Executor's original response: exclude it from the new
`bindings-deny` job's matrix, document why, don't fix here.

**Recommendation (Fable):** Keep the exclusion in the PR as originally shipped, but the
guessed one-line fix (`js`→`wasm_js`) was actually wrong — deeper investigation revealed
the manifest deliberately carries two `getrandom` majors (0.2 for `rand_core`/OsRng
needing feature `js`; 0.4 for `uuid` needing `wasm_js`, already correctly aliased as
`getrandom_wasm`). The real fix is reverting the unaliased entry to `version = "0.2"`.
Recommended: don't fix in this PR (different root cause, deserves its own review); file a
tracked GitHub issue with the corrected diagnosis instead.

**User verdict:** Fix it now in this PR.

**What happened:** Reverted `bindings/acdp-wasm/Cargo.toml`'s unaliased `getrandom` entry
to `version = "0.2", features = ["js"]`. Discovered during the fix that a Dependabot
`ignore` rule already existed for exactly this class of regression (added by PR #129,
after a first occurrence via PR #122) — no new ignore rule was needed, only the revert.
Traced the full incident history via `gh pr view`/`gh run view`: PR #133 (a Dependabot
major-update PR) had its scan run start before PR #129's ignore rule merged, created the
PR ~3 minutes after that merge, and was auto-merged ~5 minutes later *despite its own
`acdp-wasm` CI check showing FAILURE 28 seconds before the merge* — a real auto-merge
governance gap (not gated on every `bindings.yml` job), documented in a `.github/
dependabot.yml` comment but explicitly NOT fixed here (scope: dependency fix only, not
CI-governance changes). Added `bindings/acdp-wasm` to the `bindings-deny` job's matrix and
the `Makefile`'s `audit-bindings` target now that `cargo metadata` resolves. Verified via a
dedicated Phase 4 + Opus verification gate: `cargo metadata`, native test (golden vectors),
`cargo build --target wasm32-unknown-unknown` (debug+release), `wasm-pack test --node`
(golden vectors), and `cargo deny check advisories` all pass; confirmed reverting to
getrandom 0.2 does not reintroduce any known RUSTSEC advisory (zero advisories exist
against any getrandom version in the local advisory DB).

**Status:** NEEDS-CHANGE → **applied and re-verified, DONE.** Not a merge blocker — the fix
landed as this PR's Phase 4.

## 2026-08-28 — pyo3 version: bumped to 0.29 instead of the planned 0.24

**Assumption:** Plan specified bumping `bindings/acdp-py`'s pyo3 to the `0.24` line to
clear RUSTSEC-2025-0020 while staying below a believed `abi3-py39`-dropping boundary at
0.26. Mid-implementation, `cargo deny check advisories` against 0.24.2 revealed two
additional 2026 RUSTSEC advisories (RUSTSEC-2026-0176, introduced at 0.24.0 and only fixed
at 0.29.0; RUSTSEC-2026-0177, unfixed at both 0.22 and 0.24) — landing 0.24 as literally
planned would not have achieved this PR's own "advisory scan green" criterion. Executor
bumped further to 0.29 instead, verifying `abi3-py39` still works there (no Python-matrix
widening needed), the migration was minimal (2 call-site renames), and all 172 tests pass
unmodified.

**Recommendation (Fable):** Confirm — 0.29 is the minimum version clearing all four
relevant advisories (no safer intermediate exists), MSRV is unaffected (0.29.2 needs
1.83, repo is 1.86), the vulnerable APIs aren't used anywhere in this binding's code, and
landing at the current head makes the *next* bump smaller, not larger. Two required
follow-ups: add a `bindings/acdp-py/CHANGELOG.md` entry (none existed for this bump), and
state the 0.24→0.29 deviation explicitly in the PR description.

**User verdict:** Confirm + do both follow-ups.

**What happened:** Added an `## Unreleased` / `### Security` section to
`bindings/acdp-py/CHANGELOG.md` (the file previously had no "unreleased" convention —
introduced one, consistent with the root `CHANGELOG.md`'s `[Unreleased]` pattern)
documenting the pyo3 bump and all three RUSTSEC advisories it clears. The PR description
(written at `/ship` time) states the deviation explicitly per this decision.

**Status:** CONFIRMED (2026-08-28)

## 2026-08-28 — Four lower-stakes design choices

Batched per the user's explicit choice to confirm all four together, after independent
Opus review of each against the actual current code (not just the original plan text):

1. **Pin SHA for RS-1/RS-2 local verification** (`f5b66b8f86f48ba16f79bba95eb246d6acb43989`,
   matching `ci.yml:75`, not live spec `main` HEAD) — recommendation: confirm, close
   permanently (no code artifact encodes this choice; it only affected local testing).
2. **RS-2's static `KNOWN_FAMILIES`/dynamic-`profiles.json` bucketing split** — recommendation:
   confirm; a fully-dynamic design would defeat the forcing-function purpose. Noted (not
   actioned, deferred per the plan's own Long-term posture): nothing yet asserts a
   `KNOWN_FAMILIES` entry still has real test coverage, so the list could silently drift to
   "listed but untested" over time — a future tightening, not a current gap.
3. **Reusing root `deny.toml` for bindings advisory scanning** — recommendation: confirm;
   sounder than originally assumed, since `check advisories` doesn't even evaluate the
   `[licenses]`/`[bans]` sections the reuse concern was originally about.
4. **Leaving binding lockfiles gitignored** (fresh-resolution scanning, not pinned) —
   recommendation: confirm; for a vulnerability gate specifically, auditing what a
   downstream consumer actually gets from the published manifest is arguably the *better*
   target population, not merely an accepted tradeoff.

**User verdict:** Confirm all four, no changes.

**Status:** CONFIRMED (2026-08-28) — all four, no code changes.

## anchors supersede-settability (RS-8 binding follow-up)

- **Plan:** plans/archive/rs8-bindings-anchors.md
- **Assumption:** `anchors` exposed on both publish and supersede in both bindings,
  mirroring `data_refs` (not `derived_from`'s publish-only treatment).
- **Recommendation (fresh Opus subagent):** confirm as-is. The decisive point: since
  `Producer::new_version_from` (fixed in this same branch) now carries `anchors`
  forward on supersede, making anchors publish-only would make it an unreachable,
  permanently-frozen field after v1 — worse than the chosen option. Nothing in the core
  validation, wire schema, or RFC-ACDP-0016 framing suggests lineage-style (immutable)
  treatment; anchors are ordinary ProducerContent with no version coupling.
- **User verdict:** Confirm.
- **Status:** CONFIRMED (2026-08-30) — no code change from the as-implemented state.

Two side findings surfaced during this recommendation, both acted on before shipping
(not deferred):
1. **`anchors` had no way to be cleared on supersede** from either binding — omitting it
   carries the previous version's anchors forward forever (correct default), but there
   was no explicit "clear" signal, unlike `data_refs` (a plain `Vec`, where `[]` is a
   legal wire value). User verdict: fix now. See the `clear_anchors` addition
   (`RequestBuilder::clear_anchors`, plus `clear_anchors`/`clearAnchors` supersede-only
   binding parameters) landed in the same PR as this plan's phases.
2. **Unrelated pre-existing bug**: `BODY_FIELD_NAMES` in
   `crates/acdp-server/src/registry/lifecycle.rs` is missing `"anchors"` (introduced by
   RS-8/PR #169, not this branch) — a lifecycle envelope carrying an `anchors` member
   gets a generic `schema_violation` instead of the correct `immutable_field`. User
   verdict: fix now, same PR.

## 2026-08-30 — RS-11: `ACDP_VERSION` default bump (constant bump vs. feature-derived)

**Assumption:** `crates/acdp-primitives/src/lib.rs:51`'s default `ACDP_VERSION` constant
was bumped from `"0.2.0"` to `"0.4.0"` (PR #164, merged 2026-08-28) — every producer that
builds a `PublishRequest` without an explicit `.acdp_version(...)` now stamps `0.4.0`
instead of `0.2.0`. The plan (RS-11, Wave 4) left the mechanism open and flagged this as
the item most warranting deliberate human review before/at the next crate release, since
it changes wire output ecosystem-wide, not just in this repo.

**Analysis at reconciliation time:** the change has already shipped in two releases
(0.8.2 on 2026-08-28, 0.8.3 on 2026-08-30) with no reported breakage. No golden vector
(`sig-001`, `sig-003`) regressed — both pin an explicit version override. No
`acdp-validation` rule imposes a new required field on a producer at 0.3.0/0.4.0. The
only real exposure is downstream consumers (`acdp-playground`, `acdp-control-plane`, or
any other sibling repo relying on the un-pinned default) picking up `0.4.0`-stamped
bodies on their next crate bump — reverting now would itself be a second wire-behavior
change, not a neutral no-op, so standing pat is the lower-churn option.

**User verdict:** Confirm as-is.

**Status:** CONFIRMED (2026-08-30) — no code change; `ASSUMPTIONS.md` entry updated to
CONFIRMED.

## 2026-09-06 — Phase 9 dispositions (plans/archive/issues-196-199-215-216-followups.md)

Four `UNCONFIRMED` entries carried a disposition already recorded in Phase 9's own table
in the plan. Recorded here as the reconciliation log entry, with `ASSUMPTIONS.md`
cross-referenced back to this section.

1. **Byte equality for CtxId comparison (fed-011)** — **CONFIRM as-is.** Fail-closed
   behavior, documented at two independent call sites (client `verify_retrieved`/
   `fetch_report_inner` and the bindings' `verify_ctx_id_binding`), no code change. A
   non-canonical/alias form becoming legitimate would produce false refusals, never false
   acceptances — the safe direction to be wrong in.
2. **`String` (not `CtxId`) on `ContextIdMismatch`** — **CONFIRM as-is.** The correction is
   prose/rationale only (the original "over-promise" argument didn't actually distinguish
   this field from `HashMismatch`'s `ContentHash`); the shipped field types are unchanged.
   Zero blast radius.
3. **`semver-tool-health` is not a required status check** — **NEEDS-CHANGE.** The
   assumption's stated blocker ("a required check that has never run green once would
   block every PR") has expired: verified via `gh run list --workflow=ci.yml --branch
   main --limit 15 --json databaseId,conclusion` that at least 13 consecutive runs on
   `main` — from `34079142407` back through `34013243642` (the run 8 positions back from
   `34079142407` is `34048649587`, not `34040888637`) — are all `success`, with the streak
   breaking only at a `cancelled` run further back, and `semver-tool-health`
   (`ci.yml:275-277`, whose `needs: [semver]` is at `ci.yml:277`) carries no
   `continue-on-error`, so a workflow success implies the job passed. Add
   `semver-tool-health` to `main`'s required contexts (10 → 11) via `gh api
   .../branches/main/protection`. This is a repo-settings change, applied by the
   orchestrator at Release choreography step 6 — after the 0.10.0 release PR (#228) has
   merged, not before, since adding it while #228 is open would require it green on a PR
   whose advisory `semver` job (`needs: [semver]`) is deliberately reddened by an
   intentional `feat!`. Not applied in this phase's diff — out of this executor's scope.
4. **Unpublished-crate baseline behaviour in cargo-semver-checks** — **DEFER/MOOT.**
   Unreachable today: no phase in any active plan adds a new workspace crate. Self-
   diagnosing the first time one does (either the job passes cleanly, or it hard-reds with
   a misleading "tool error" diagnosis that immediately identifies the PR needing a
   carve-out). No action taken.

**User verdict:** None recorded. Unlike every other entry in this log, the owner gave no
per-item verdict on these four dispositions — they were resolved by agents (Opus
recommending, this executor applying) acting under the owner's standing delegation for
this run's Phase 9 cleanup pass, not by an explicit owner decision on each item. This line
exists to make that absence visible rather than silently omitting the field the top of
this file promises: **these four dispositions are pending the owner's review**, not an
owner-approved verdict, until the owner says otherwise.

**What happened:** `ASSUMPTIONS.md` entries updated in place with the above dispositions
and dated. No code changes for any of the four (item 3's branch-protection PATCH is
explicitly deferred to the orchestrator's choreography step 6).

**Status:** All four applied as dispositioned above (2026-09-06).

## 2026-09-06 — Five additional `UNCONFIRMED` entries dispositioned (Phase 9)

Entries added to `ASSUMPTIONS.md` during this plan's implementation, dispositioned as part
of Phase 9's cleanup pass rather than left open indefinitely.

1. **Binding lockfiles resolve independently of the root `Cargo.lock`** — **CONFIRM
   as-is.** Accepted architectural trade-off: each binding is a standalone workspace
   tested by its own suite (`make sdk-py`/`sdk-node`/`interop`, `cd bindings/acdp-wasm &&
   cargo test`) against its own resolution. Already re-verified once, when Phase 2 moved
   `bindings-deny`'s advisory scan to `--locked` (auditing the pinned graph that ships,
   not a freshly-resolved one). No further action.
2. **`Swatinem/rust-cache` runs before the `--locked` gate in three workflows** —
   **CONFIRMED-as-safe. A prior revision of this entry recorded a "confirmed real gap"
   here and it was wrong; that finding is retracted.** The prior text claimed that
   `restore.js` — the action's `main` step, which runs in place in the job wherever the
   step is listed, not in post/cleanup — reaches a `cargo metadata --all-features
   --format-version 1` call with **no** `--locked` flag, and that because rust-cache
   precedes the `--locked` gate step in all three workflows (`bindings.yml:179` before
   `:190`, `bindings-release.yml:71` before `:94`, `acdp-wasm-release.yml:123` before
   `:146`), it could silently repair a drifted binding lockfile before the gate ever
   inspected it — the same fail-open shape as `NEW-1`, via a different actor. **That
   conclusion does not hold.** The step-ordering premise (rust-cache before the gate, at
   those exact line numbers) is true and unchanged. But the `cargo metadata` call that
   `restore.js` actually reaches passes **`--no-deps`**
   (`dist/cleanup-BPghO_DY.js:34492`), and `cargo metadata --no-deps` performs no
   dependency resolution and does not write `Cargo.lock` — confirmed on a synthetic crate
   with a deliberately drifted lock: with `--no-deps` the lockfile stayed byte-identical
   and still drifted; without `--no-deps` it was repaired. The **resolving** variant
   (`getPackagesOutsideWorkspaceRoot`, no `--no-deps`, `cleanup-BPghO_DY.js:34488`) has
   **zero call sites in `restore.js`** — its only caller is **`save.js:64`**, the `post:`
   step, which runs *after* the gate. In other words, the round-3 verifier's original
   "hopeful reading" — that the resolving `cargo metadata` call lives in the post/cleanup
   step, which runs after all job steps — was **correct**. The contrary finding recorded
   in this entry's prior revision was an over-read (conflating the two distinct
   `cargo metadata` invocations in rust-cache's source) and is now retracted. **The
   existing gate placement in all three workflows is already sound; no workflow reorder
   is needed and no follow-up issue should be filed.**
3. **`cargo-vet` installed from QuickInstall, not upstream** — **DEFER.** Analysis
   confirmed accurate; all three considered alternatives remain closed off (no
   `install-action` manifest entry for `0.10.2` exists at any SHA; downgrading to
   `0.10.0` breaks parsing of this repo's trusted-publisher lockfile schema;
   `fallback: none` would hard-fail a required check on every PR). Tracked via the filed
   upstream issue (`taiki-e/install-action#1997`); revisit once that manifest gains
   `0.10.2` coverage.
4. **`cargo-fuzz` installed with an unconditional, undisableable QuickInstall fallback** —
   **DEFER.** Same shape as the `cargo-vet` gap, equally closed off locally (the
   `install-action` SHA that would add the `fallback` input has no `cargo-fuzz.json`
   manifest at all). Lower severity: `fuzz.yml` is not a required status check. No action
   needed unless the `cargo-fuzz` pin or the `install-action` SHA changes.
5. **Binding versions are NOT independently versioned in practice** — **CONFIRMED,
   resolved this session.** All three binding release workflows overwrite the manifest
   version with the dispatch input before building, and `release-plz.yml` dispatches all
   three at the crate family's computed version — so "bindings go to 0.9.0" (the plan's
   original default) could never actually ship once PR #227's break pushed the crate
   family to 0.10.0. Referred to Fable per the owner's standing delegation; Fable decided
   0.10.0 for the bindings, matching the crate family, and PR #230 implemented it.

**User verdict:** None recorded for items 1-4 — like the four dispositions in the entry
above, these were resolved by agents acting under the owner's standing delegation for this
run's Phase 9 cleanup pass, not by an explicit owner decision on each item, and remain
**pending the owner's review**. Item 5 is the one genuine exception, and it is *not* an
owner verdict on "0.10.0" either: the owner did set an explicit position for this item
specifically ("bindings go to 0.9.0") and explicitly delegated the final call to Fable;
Fable then chose 0.10.0 on the evidence above, overriding the owner's stated default for
cause. Record it accurately as that — a delegated decision with the owner's default
overridden — not as the owner having verdicted "0.10.0."

**What happened:** `ASSUMPTIONS.md` entries updated in place with the above dispositions
and dated; no code changes from this pass except item 5, already shipped in PR #230.

**Status:** Items 1, 2, 3, 4, 5 all closed/confirmed/deferred as above. Item 2
(`rust-cache` ordering) was recorded in an earlier revision as a confirmed real gap
needing a workflow reorder and a follow-up issue; that was wrong and has been retracted
above — no reorder and no follow-up issue are needed.

## issues-240-242-seamb-wave — /reconcile, 2026-09-10

One `UNCONFIRMED` entry was in scope at the end of this plan. Settled by Opus under the
standing delegation; no owner decision was required and none is implied.

**1. The napi-rs half of the binding-toolchain pinning entry — CONFIRMED, resolved.**
Shipped in Phase 1 (PR #244, `f241b2f`): `bindings/acdp-node/package-lock.json` is tracked,
`@napi-rs/cli` is pinned to exact `3.8.6` in both manifest and lockfile, and both
`bindings.yml` and `bindings-release.yml` assert the resolved version after `npm install`.
Proven live — `acdp-node (node 20/22)` pass on PR #244, and `interop` executed for the first
time since #229 merged.

**2. The maturin half — DEFERRED, and now tracked as #252.**
`bindings.yml:79` and `:315` install `'maturin>=1.5,<2.0'` (and an unpinned `pytest`) from an
open range. Same "re-resolves silently" shape as #240, deliberately NOT fixed in this wave.

*Reasoning, recorded so it is not re-litigated:* the two are not equivalent in severity, and
flattening them would be wrong. `@napi-rs/cli` **generates the committed `index.js`/`index.d.ts`
that ship to consumers** — its drift was invisible (no lockfile diff to review) and
consequential (it silently disabled two CI guards). maturin is a build tool whose output is a
wheel; it does not generate committed source that a guard diffs, so a bump is far likelier to
fail loudly than to silently alter a checked-in artifact.

*What changed:* it moved out of a gitignored plan file and this register into a tracked issue
(#252) with three costed options. That is the actual gap that was closed — the item was
invisible for two waves, not unanalyzed.

**3. `npm ci` — REJECTED on measurement, tracked as #249.**
Not an `ASSUMPTIONS.md` entry, recorded here because the owner named `npm ci` as the intended
fix for #240 and this run did not ship it. Measured: `npm ci` fails `EUSAGE / Missing:
@agentcontextdistributionprotocol/acdp-*-* from lock file`, because `package.json` declares
self-referential `optionalDependencies` on its own four platform packages at the manifest
version while the highest published is 0.8.5. `--omit=optional` does not help; rewriting to
0.8.5 makes it succeed, isolating the cause. **Structural, not incidental** — the manifest
version always leads the published version, so `npm ci` would break after every bump even with
npm publishing healthy. A second independent blocker: `bindings-release.yml:160-165` stamps the
version before installing.

This was reported to the owner before Phase 1 began and the corrected approach
(lockfile + exact pin, keep `npm install`) was taken with that stated. **It was also validated
by the 0.11.0 release itself:** the binding release workflow stamps `package.json` to the
release version while the committed lock still reads 0.10.0, and `npm install` self-heals that
silently. `npm ci` would have hard-failed the release.

**Owner verdict:** none recorded for items 1-3. All three were settled by Opus under the
standing delegation for this run and remain **pending the owner's review**.

---

## issue #248 — revocation auto-discovery (wave closed 2026-09-11, shipped in 0.12.0 + 0.13.0)

All items below were settled by Opus under the standing delegation for this run and remain
**pending the owner's review**. No `ASSUMPTIONS.md` entry was opened by this wave: the plan's
open questions were all decided at plan time (D1–D7, LIM-1/LIM-2) and the four deliberate
deferrals are now tracked as issues rather than register entries.

**1. `Clone` on `AcdpError` — ADOPTED, after escalation.**
Phase 4's executor added `#[derive(Clone)]` to `AcdpError` without it being in the plan. Because
that is a permanent public commitment on the central type of a 13-crate published workspace, it
was escalated to Fable as a one-way door rather than accepted as incidental plumbing.

*Verdict: KEEP.* The premise is genuine — `VerifiedContext` and `VerificationReport` are sibling
owned values returned from one call, so a borrow is self-referential and does not compile with
`unsafe` forbidden. The decisive fact is that value semantics was **already** this type's design:
`From<std::io::Error>` (`crates/acdp-primitives/src/error.rs:468-472`) and `From<reqwest::Error>`
(`:474-481`) both stringify into `Http(String)`. `Clone` only makes explicit what the type
already was. `Arc<AcdpError>` was the one real alternative and is worse — it would sit beside
`policy_phase_error: Option<AcdpError>` and `data_ref_embedded` as bare errors, an asymmetry
every downstream matcher pays for.

*Foreclosure, stated rather than left implicit:* future variants' payloads must remain `Clone`;
a variant needing a structured source uses `Arc<dyn Error + Send + Sync>` (Clone regardless of
inner type, preserves `source()`), never `Box<dyn Error>` or a bare `io::Error`. That obligation
is now written on the enum doc at `error.rs:36` — it was the only legitimate criticism of the
decision, and it is closed.

*Independently corroborated:* `cargo-semver-checks --workspace` on PR #256 reported exactly 1
failure in 196 checks — `struct_marked_non_exhaustive` on `RevocationPolicy` — and did **not**
flag `Clone`, confirming a new trait impl is additive.

**2. Discovery executes inside `verify_retrieved`, not behind a wrapper (D1).**
A `fetch_with_discovery` wrapper family was considered and rejected. #245 established
`verify_retrieved` as the sole reader of the authorization-phase policy fields; a wrapper would
discover revocations *outside* that phase while the spine-lock test stayed green — a tripwire
standing over a violated invariant. Measured and confirmed: the lock does **not** block the
wrapper shape, which is precisely why the wrapper is wrong.

**3. Union without deduplication (D-series, Phase 4).**
`effective_boundary` is a `filter().map().min()` fold, so duplicates are inert and two sources
disagreeing resolves to the earliest — the fail-closed direction RFC-ACDP-0014 §4 mandates.
Dedup is unavailable regardless: `KeyRevocation` is not `Hash` and the returned vectors carry no
`ctx_id`.

**4. `ProceedWithKnown` discards ALL discovery output when either lookup fails.**
Partial success is deliberately not representable. A half-populated revocation set is
indistinguishable from a complete one, so treating it as complete would reintroduce the same
class of fail-open this wave existed to close. The failure is recorded on both
`VerifiedContext::revocation_discovery_failure()` and `VerificationReport::revocation_discovery`.

**5. Four items deliberately NOT built — filed, not deferred silently.**
#257 (revocation cache, D4), #258 (request-count/byte budget, D4), #259 (§8's narrow trigger,
D7 — unimplementable at the chosen insertion point, since discovery precedes the signature
phase), #260 (`CrossRegistryResolver` policy injection, LIM-1 — blocked on #257, since
`max_nodes: 100` makes per-node discovery unviable uncached).

**6. `tokio-macros` in the binding lockfiles — fixed forward, guard NOT weakened (#261).**
Enabling tokio's `macros` feature for `try_join!` pulled a new crate into the committed binding
lockfiles, which failed `release-plz.yml`'s sync guard (`cargo update -w touched a non-version
line`). The guard is correct: a release-time sync should bump versions, not pull a new crate
into a published wheel's dependency graph. The structural change landed as its own reviewable
commit instead of relaxing the assertion. **This was also the first live proof of the #240
lockfile-pinning work** — the resulting sync commit changed exactly **32** `acdp*` version
lines, matching that phase's stated acceptance criterion.

## issues #257 / #258 / #260 — revocation budget, cache, resolver injection (wave closed 2026-09-12)

Settled by Opus under the standing delegation for this run; **pending the owner's review**. The
two genuine one-way doors went to Fable *before* implementation, and a third was found and adopted
during whole-wave review.

**1. The cache is TWO objects, not one — facts always seed, only markers may skip. (Fable.)**
#257 framed this as "does a hit skip discovery or only seed it?". Separating the two dissolves the
question. **Facts** (verified `KeyRevocation`s) are licensed by RFC-ACDP-0014 §7:114 to be cached
indefinitely, are always unioned and never substituted, and — because revocations are monotone —
can only tighten a verdict. That makes the fact store an **anti-rollback security control, not a
performance feature**: it saves zero requests by default, and the docs say so rather than
overselling it. **Markers** ("vantage V was asked for P, class C, at t") are a cached *absence*,
which §7:114 does not license and §8 warns about directly; they are TTL-bounded, per-vantage, and
off by default (`freshness: Duration::ZERO`).

*Foreclosure, stated rather than implied:* this door is one-way in one direction only.
Skip-default → seed-default later is a perf regression; seed-default → skip-default later is a
silent security regression and effectively unshippable. Seeding by default is both the safe
posture and the one that keeps the remaining freedom.

**2. Facts merge inside `verify_retrieved`, downstream of the failure arms.**
The discovery failure arms set `discovered = Vec::new()`. Folding cached facts into the lookups'
return value would therefore **erase them on exactly the path an attacker can force** — a 503, an
induced `SearchTruncated`, or (newly, thanks to #258) a budget trip. The verifier caught this as a
BLOCKER; it was not in the executor's first implementation. Merging at the `effective` site keeps
facts surviving every failure mode, and is still spine-lock-safe.

**3. Registry-attested facts are scoped to their minting vantage; producer-signed are not.**
The live path binds attested revocations via `cross_check_registry_binding`; the first cache
implementation discarded that binding, so a shared handle would apply one registry's claim
everywhere. RFC-ACDP-0014 §6 is normative — attested revocations apply to contexts *"served by or
receipted by that same registry"*. The asymmetry is the RFC's: §8 makes producer-signed revocations
self-contained ("verifies identically wherever it came from"), so they **should** cross vantages,
and the wave's own anti-rollback test depends on it. Filtering both would have broken anti-rollback;
filtering neither was the blocker.

**4. Facts seed even when `discover: None`.** Three doc sites claimed facts apply "unconditionally"
while the code returned an empty set on that arm. Resolved in the code rather than by watering down
the docs: attaching a cache *is* the opt-in, seeding is monotone, and it is the only anti-rollback
`fetch`/`fetch_current` can ever get, since LIM-2 leaves them unable to opt into discovery at all.
Producer-signed only on that arm — there is no `include_registry_attested` to consult and D6
requires an explicit opt-in.

**5. #260 is non-breaking: builders on the resolver, injecting `RevocationPolicy`. (Fable.)**
Three additive methods; `ResolverOptions` untouched. A field there would have been breaking, but it
is also wrong on the merits: `with_options`'s contract is *"replace the complete options struct"*,
so a revocation field would mean a caller tuning `max_depth` silently resets their revocation
config. Injecting a whole `VerificationPolicy` was rejected because the resolver *derives* `receipts`
per node from advertised capabilities — a caller-supplied static policy cannot express "Require iff
this authority claims the profile", so the API would either silently override the caller or become a
**downgrade primitive**. `revocations` is the one field the resolver never sets. Non-breaking is what
made the whole wave a patch (0.13.1) rather than a minor.

**6. Walk-scoped cache freshness derived from `ResolverOptions::total_timeout` — adopted in review.**
A third option nobody had evaluated. Because the resolver's walk-scoped cache dies with the call, a
marker cannot outlive an operation `total_timeout` already bounds — so deriving freshness there
delivers #260's headline benefit on genuine defaults without touching `marker_fresh`, without a new
public method, and without regressing the direct path. It **restored the plan's original acceptance
criterion**, which said "on default configuration" and which the executor had been forced to
reinterpret after a factual error in the plan text (see below). Caller-supplied caches keep the
caller's own freshness, including `ZERO`, since that handle may outlive the walk.

**7. No new Cargo dependency — `lru` deliberately rejected.** It was the obvious choice and is
already in `acdp-client`'s built graph transitively. But a **direct** edge rewrites the
`acdp-client` entry in `bindings/acdp-py/Cargo.lock` and `bindings/acdp-node/Cargo.lock`, and
`release-plz.yml`'s sync guard hard-fails when a release-time sync touches a non-`version = "` line
— the failure that broke the #248 release. The bound is hand-rolled instead. Because eviction can
only lose caching and never safety, capacity-triggered eviction suffices; no LRU recency tracking.

**8. Two planned phases were REMOVED after review showed they were not prerequisites.**
The plan opened with an extraction refactor of `revocation.rs` and a test-harness phase, both
asserted as required. Both claims were false. Every client request site propagates with `?`, so a
budget enforced in `RegistryClient` on a per-discovery clone is check-before-issue and
combined-across-lookups by construction — #258 shipped with `revocation.rs` untouched. And only
*page-cap* exhaustion is unreachable in the harness; request-budget exhaustion is testable today.
Rather than do a ~1141-line refactor of security-critical code in the same release as three
security fixes, both were filed as #264 and #265.

**9. Process finding — four acceptance criteria across two waves had tests that could not fail.**
#248's union test, this wave's dedup test, the registry-attested marker test, and the `seed_client`
overwrite test. All four were green and proving nothing; mutation probes caught every one, and
reading the tests caught none. A fifth near-miss: a naive `max_bytes: Some(1)` budget test cannot
distinguish a combined budget from a per-lookup one, and had to be calibrated against measured
response sizes. **Treat "apply the mutation, confirm RED, restore" as mandatory per phase.**

**10. A CI failure that was not a flaky-timeout to widen.** `cache_ac5_*` failed on
`ubuntu/beta` and `windows/stable`. The test proved suppression and expiry on one timeline with a
50 ms window, and called `seed_revocations` — a real Ed25519 publish over TLS — *inside* the window
it was measuring. No margin fixes that. Split into two tests racing in opposite directions
(`ac5a`: 30 s window, unloseable to slowness; `ac5b`: 1 ms window vs a 250 ms sleep, where slowness
can only help). Each half is mutation-proven to catch the failure the other cannot. The 50 ms/60 ms
budget originated in this plan — in a wave whose own plan warns that #248 shipped a spuriously
passing timing test.

## Wrap-up wave: #268 / #252 / #259 / #265 / #249 / #264 (closed 2026-09-12)

Settled by Opus under the standing delegation; **pending the owner's review**.

**1. #268 — adopt `unsupported_media_type`, but SPEC-FIRST. (Fable.)**
`acdp-registry-rs` minted a non-canonical wire code for HTTP 415 and asked us to converge. The
name is right (follows `unsupported_algorithm`, mirrors 415's reason phrase) and was endorsed.
The decisive fact the filing underweighted: `acdp-error.schema.json` pins `error.code` to a
**closed 25-value enum** with `additionalProperties: false`, so they are currently
schema-non-conformant, not merely un-typed. We therefore did **not** add the `AcdpError` variant:
the canon's enum is the authority the round-trip test cites, and removing a variant later is
breaking even on a `#[non_exhaustive]` enum. Spec issue filed (spec#67); variant lands after
adoption. Also corrected their premise that "there is no code→status mapping in the canon" — the
§5 table has an HTTP column, which makes `schema_violation` (pinned to 400) worse for a 415, not
better. Flagged a defect in their emitter: the message names `application/json` where
RFC-ACDP-0001 §3 makes `application/acdp+json` canonical.

**2. #259 — CLOSED won't-fix, and the recorded reason was wrong.**
#248's D7 (and the issue itself) said the §8 narrow trigger is "unimplementable at the chosen
insertion point." **That premise is false** — `signature.key_id` is in the body pre-verification
and `assertionMethod` membership comes from DID resolution, which does not depend on the
signature check. It is expressible. The real reason is stronger: §8's minimum trigger fires only
for a key **outside** `assertionMethod`, while §9 makes removal of a revoked key a **SHOULD** and
declares the membership **"irrelevant to §7."** Gating discovery on it would condition a §7 input
on a fact the spec says is irrelevant to §7 — skipping discovery exactly when a revoked key is
still listed. That is a fail-open of the class #248 existed to close. The cost motive also
evaporated once #257/#260 shipped caching, which is the safe way to get the same saving.

**3. #252 — a single pytest pin had to be 8.4.2, downgrading two legs.**
The matrix silently resolved **two pytest majors**: 9.1.1 on 3.11/3.13, 8.4.2 on 3.9 (pytest 9
needs ≥3.10; `pyproject.toml` declares `requires-python = ">=3.9"`). Chose the uniform pin over
per-version environment markers because testing on two majors is a real confound, and confirmed
empirically — all three legs plus interop passed on 8.4.2 before merge. Dropping the 3.9 leg was
rejected as a support change, not a CI tweak.

**4. #249 — removing the self-referential `optionalDependencies` is safe for publishing.**
Verified against installed `@napi-rs/cli@3.8.6`: `resolveRootOptionalDependencies` starts from
`{ ...asRecord(existing) }` (and `asRecord(undefined)` is `undefined`, so an absent block spreads
to `{}`), then **assigns** an entry per `napi.triples` target at the stamped version — it writes,
it does not merely update. Corroborated by published `acdp@0.8.5`, whose deps are all `0.8.5`
even though the release workflow's only manifest mutation is `jq '.version=$v'`. The publish job
deliberately stays on `npm install`: it stamps before installing, and it is the one job gating a
real release. The PR self-validated — its own CI ran the new `npm ci`.

**5. #264 — the extraction needed five parameters, and one is unguarded.**
Two more differences than first thought: the `tracing::warn!` payloads differ structurally, and
the `MAX_LINEAGE_WALKS` message differs by identity *label*. Five mutation probes; four reddened.
The fifth — swapping the drop-site discriminator — left all 96 tests green, so the `bool` became a
`DropSite` enum. Stated precisely in the commit: that makes a swap **visible in review, not
detectable by tests**. Two findings worth keeping: hoisting `truncated` **does not compile** (the
message interpolates `{type_form}`/`{status}`), an accidental type-level guard; and the 6-pair
property **is** permanently guarded by `budget_ac2_none_none_matches_pre_258_request_counts` —
the #258 wave's test now serving as this refactor's regression guard. I had wrongly told the
verifier it was unguarded.

**6. Stale release PR #267 closed.** release-plz opened two release PRs for 0.13.1 six minutes
apart; #266 shipped. #267 would have re-added a duplicate `## [0.13.1]` changelog section,
including reintroducing the malformed duplicate `### Added` fixed on #266's branch.

**7. Orchestration error, recorded so it is not repeated.** Two agents were dispatched against
the same working clone with no isolation; one switched the branch out from under the other
mid-task. No work was lost (the affected agent had already pushed), but that was luck. Later
agents used `isolation: "worktree"`. **Concurrent agents must not share a working tree.**

## #268 adopted, spec pin `d1f06d0` → `108ff76`, and the #240/#252/#249 close-out (2026-09-13)

Settled by Opus under the standing delegation. This pass started as doc-and-pin hygiene and
grew one real code change, for a reason worth recording.

**1. The scope changed mid-pass because the spec moved, and taking the new SHA was the right
call rather than the convenient one.** The pass was planned against spec `8555ec7`, where
`git diff d1f06d0..8555ec7 -- schemas examples rfcs` is **empty** — a provably inert adopt.
Between planning and execution the spec merged `108ff76` ("unsupported_media_type (415) on the
0.5.0 line, plus an error-code sync guard", spec #68), which **adopts spec#67 and unblocks
acdp-rs#268** — the repo's only open issue, recorded a day earlier as blocked pending exactly
this. Pinning to `8555ec7` would have meant deliberately adopting a SHA that was current for
three days and leaving the code that supersedes it on the floor. Pinning to `108ff76` without
the variant would have adopted a wire code this library types as an opaque catch-all. So the
variant landed with the pin.

**2. #268's three-edit rule, executed as CLAUDE.md specifies.** `AcdpError::UnsupportedMediaType`
+ the `from_wire_error` arm + `all_25_wire_codes_round_trip` → `all_26_...` with its count and
citation updated. `is_transient` was revisited and **deliberately left alone**: retrying with the
same `Content-Type` returns the same 415, so it is permanent — pinned by a new negative assertion
rather than left implicit. Additive on a `#[non_exhaustive]` enum, so downstream `match` arms keep
compiling; per `release_commits = "^(feat|fix|perf)"` this **does** now open a release train
(0.13.2, patch — additive under 0.x), which the hygiene-only version would not have.

**3. The suite was green at `108ff76` *before* the variant existed — that is the finding.**
Running conformance against a clean extract of the new SHA passed 66/66 with `unsupported_media_type`
completely untyped. `error_example_deserializes` read **one hard-coded filename**
(`examples/error/invalid-signature.json`), so the spec's new error example was exercised by
nothing; and `all_25_wire_codes_round_trip` pins a hand-written list, which can only catch a code
*we* forgot, never the spec growing one. `CLAUDE.md`'s claim that conformance drives "every
`examples/**/*.json`" is simply false — the tests name individual paths.

Two mechanisms close it, and both were mutation-proved by deleting the `from_wire_error` arm:
`error_example_deserializes` now scans the directory and asserts each code maps off the
`AcdpError::Registry` catch-all (red, naming the file); `wire_error_codes_cover_the_spec_enum`
reads the enum out of the pinned `acdp-error.schema.json` itself (red, naming the code and the
three-edit rule). The second is the one that generalizes: a future pin bump adopting a 27th code
now fails until it is typed. Restored byte-identical after probing.

**4. `bb09c43` is inert for this repo — checked, not assumed.** It rewrote
`acdp-registry-core.self_test_only` from a decorated string to a bare fixture stem and moved
`acdp-registry-federated.self_test_only_added` to `behavioral_requirements`. This repo's only
consumer of that file, `tests/conformance.rs`'s
`all_conformance_fixtures_are_bucketed_into_known_families`, reads **`fixture_families` and
nothing else**. A runner doing `self_test_only.includes(id)` was the beneficiary; we are not one.

**5. No bump PR was dispatched, and that was correct, not a broken automation.** `acdp-rs` *is*
in the spec's `notify-spec-consumers.yml` matrix, but that workflow only added `registries/**` to
its path filter **in `8555ec7` itself** — the commit *after* the one that changed `registries/`.
`bdb15f0` touched only `README.md`, also outside the filter. Recorded because "pin is stale, no PR
opened" reads like a broken dispatch until you check the ordering.

**6. The #240/#252/#249 register entry was closed a day late, not left open on purpose.**
`ASSUMPTIONS.md`'s binding-toolchain entry still read `UNCONFIRMED` although **both** halves had
shipped: maturin/pytest pinned and version-asserted (#252), and `npm install` → `npm ci` (#249).
The historical narrative is **preserved as written** and framed as such rather than rewritten —
the two surviving in-body `UNCONFIRMED` mentions sit inside that preserved text, governed by the
entry's `RESOLVED` status line above them. Amending a register in place to make a grep look tidy
would destroy the record of what was believed when.

**7. `CLAUDE.md` understates the crate and cannot be fixed by a PR.** It describes coverage
through RFC-ACDP-0008/0010 and never mentions **RFC-ACDP-0011 through 0016**, though all are
implemented — 0016 (typed external anchors, the open 0.5.0 Draft line) has
`crates/acdp-types/src/anchor.rs`, `tests/anchors.rs`, and anc-004's executed content-hash golden
vector in `tests/conformance.rs`. It also mis-describes how conformance consumes `examples/`
(see item 3). The file is gitignored (`.gitignore:65`), so it was corrected in the working tree
only and is **not** in this PR — noted here because this is the only durable place it can be.

**8. The local toolchain is broken, independently of this change.** Command Line Tools ship
`MacOSX27.0.sdk` while the `ld`/`tapi` executables are 26.6, so every link fails with
`tapi error: malformed file ... unknown architecture arm64e.x1`. Worked around for this pass with
`SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk`; **no repo config was changed**,
since this is a machine-level mismatch and CI's Linux runners are unaffected. A CLT update is the
real fix.

## 2026-09-22 — issues-273-279-284-285-rfc0014-wave: /reconcile (8 entries)

All 8 phases implemented and merged to `main` (PRs #288, #289, #290, #291, #287, #292);
only Phase 7's final acceptance criterion (merging the regenerated release PR and
verifying crates.io/PyPI/npm publication) remains, deliberately held per explicit
instruction. Ran three parallel fresh-Opus analysis passes (low blast radius throughout —
no genuine one-way door among these 8, so none needed Fable or a stop for confirmation)
against every `UNCONFIRMED` entry tagged to this plan. 7 CONFIRMED as-is, 1 CHANGED and
applied.

**1. Phase 1 — `verified.rs` embedded-hash gate widening. CONFIRMED.** Independently
cross-referenced against `RFC-ACDP-0002-context-body.md:294-296` in the spec checkout:
Check 8's obligation is scoped to `embedded.content_hash`; checking the root hash too is
an explicitly-permitted MAY, never forbidden. Both call sites (`verified.rs:1467,1605`)
match `data_ref.rs:240`'s already-fixed condition. Optional, non-blocking follow-up noted
(not applied): no test exercises the *embedded-only* case through
`VerifiedContext::fetch_report` specifically — `tls_conformance.rs`'s existing test only
covers the root-hash-present case, which the old (buggy) gate already handled correctly.

**2. Phase 1 — cargo-semver-checks environment mismatch, fell back to manual review.
CONFIRMED.** Re-ran `cargo semver-checks -p acdp-types` with the now-updated tool
(0.45.0 → 0.50.0, fixed earlier this session for an unrelated reason) — it runs cleanly
and independently confirms the exact breaking classification (`constructible_struct_adds_field`
on `EmbeddedContent.content_hash`) the manual review reached. Tooling and manual reasoning
now agree.

**3. Phase 2 — pub-009 assertion widened beyond the plan's named files. CONFIRMED.**
`tests/conformance.rs`'s `did_web_enforcement_fixtures` now asserts `KeyResolution`
(not the old `SchemaViolation`), matching RFC-ACDP-0001 §5.11.1 step 1's MUST-level
requirement (confirmed against the actual spec text, not paraphrase) and passing under
`ACDP_REQUIRE_CONFORMANCE=1` against the real `pub-009` fixture.

**4. Phase 4 — Arm 3's error-code gate needs opposite fail-closed polarity from §10's
rejection gate. CONFIRMED**, with real scrutiny applied (this is security-relevant
fail-closed logic, not rubber-stamped). Independently confirmed the spec text
(`registries/error-codes.md:60`) matches the claimed MUST-NOT verbatim, confirmed the
regression test (`revocation_superseded_by_non_revocation_rejected_under_malformed_acdp_version`)
still pins the correct polarity, and reasoned through *why* the asymmetry is structurally
correct rather than a coincidental patch: the two functions answer genuinely different
questions ("does the stricter rule apply?" vs. "may I assert an unverified >= 0.5.0
claim?"), each with its own safe default under uncertainty. Two optional, non-blocking
suggestions were raised and one applied now (see item 9); the other — extracting the
duplicated `major > 0 || minor >= N` arithmetic into one shared parser with per-call-site
defaults — was **not** applied: it's cosmetic de-duplication with no behavior change, and
the existing doc comments already carry the main risk-mitigation (explicitly
cross-referencing the polarity split for future readers), so the abstraction isn't earning
its keep yet.

**5. Phase 4 — added direct unit-test coverage beyond the plan's Tests field.
CONFIRMED.** All six named tests exist, are substantive, and pass. Confirmed "test
immediately rather than deferring to Phase 6" was the right call in retrospect: Phase 6
landed later, in a separate PR, so deferring would have left security-relevant branching
logic (a fail-closed gate governing whether a compromised key can escape a revocation
lineage) untested in `main` for an indeterminate stretch. Noted, not fixed: 3-4 of these
six now have near-identical-named Phase 6 facade-level twins — intentional two-layer
coverage (unit pins the logic, facade pins that `RegistryServer`'s plumbing actually wires
it through), per this file's own stated testing-pyramid rationale, not accidental
duplication.

**6. Phase 5 — rev-002 E/F/G/H tests. CONFIRMED.** The two pre-existing tests are
untouched; all four new tests drive a real `classify_under_revocation` verdict (not just
discovery), using fixture-sourced timestamps. Minor bookkeeping note (not a code issue):
the phase's own running test-count arithmetic in `PROGRESS.md` has an off-by-one baseline
(97, not 96) — doesn't affect any scenario-coverage claim, not worth correcting a closed
narrative entry for.

**7. Phase 6 — scoped down from "18 new tests" to the gaps a two-layer analysis actually
found. CONFIRMED.** Verified counts against the actual merged diff (exactly 3+4+3 new
tests, matching the claim) and independently re-checked 8 of the 13 skipped rev-003
scenario letters against the pinned spec fixture directly — all 8 have an exact
pre-existing match (same rejection shape, same asserted error code/status). The gap
analysis holds under independent scrutiny, not just self-report.

**8. Phase 8 — added a `recomputed_hash()` accessor not named in the plan's public API
list. CHANGED, applied this pass.** The dead-code-lint claim was independently reproduced
(a fresh `rustc -D warnings` repro plus rebuilding the real crate). But the fix itself was
not the best available one: `Proven::request().content_hash` (one of the plan's original
3 named accessors, `PublishRequest.content_hash` being `pub`) already exposes the
identical value, since `Proven` always borrows `req` — so the field genuinely has no
legitimate external consumer, and ASSUMPTIONS.md's stated reason for keeping a public
getter ("a caller holding only a `Proven` has no other way to learn the hash") does not
hold. Replaced `pub fn recomputed_hash()` with a `debug_assert_eq!` inside
`commit_proven` that actively checks the same invariant the field exists to prove, instead
of exposing a public getter that duplicates existing surface. `Proven`'s public API is now
exactly the plan's originally-named 3 accessors (`agent_id`, `key_fingerprint`,
`request`). Applied now rather than deferred: this crate has not released `Proven` yet
(still under `## [Unreleased]`), so the change is genuinely costless today and would need
a deprecation cycle after the next release.

**9. Applied alongside item 8:** a direct malformed-`acdp_version` test for
`key_revocation_retirement_gate_applies` (Entry 4's other optional suggestion) —
previously only proven by code-inspection/structural-identity with the well-tested
`key_revocation_gate_applies`, now has its own
`interim_form_retirement_gate_fails_closed_on_malformed_acdp_version` test.

**Disposition:** all 9 items decided by Opus (fresh independent analysis per entry,
none escalated — no genuine one-way door among them). 7 confirmed as-is, 2 applied as
small, safe, low-blast-radius fixes (both re-verified: full workspace suite green,
`--no-default-features` green, fmt/clippy clean on both feature sets, acdp-server lib
133 → 134 tests). No code follow-up needed before the next `/ship`. ASSUMPTIONS.md
entries for all 8 original items marked `CONFIRMED (2026-09-22)`.

## 2026-09-22 — PR #283 merged, v0.14.0 released (issues-273-279-284-285-rfc0014-wave, Phase 7 closed)

Explicit user authorization: "Go ahead and merge #283 and release." This was the one
deliberately-held, genuinely irreversible action in the whole plan — public package
publication to crates.io/PyPI/npm.

**What was found and fixed along the way, not just executed:**

1. PR #283's CI checks were sitting in GitHub's `action_required` state — a bot-authored
   PR has its workflow runs held for manual approval rather than actually running. Approved
   all 4 held runs before treating anything as green; a naive merge on the PR's apparent
   "no checks reported" state would have skipped real verification entirely.
2. `cargo-semver-checks (advisory)` — red on both prior PRs this run (#292, #293) for
   expected reasons — passed clean here, since the PR's breaking-change list matches
   exactly what Phases 1/4/8 of this plan shipped (no unexpected extra breakage).
3. The npm SDK-bindings publish genuinely, partially failed on its first attempt: 3 of 4
   platform packages (`acdp-darwin-x64`/`-darwin-arm64`/`-linux-x64-gnu`) published, but
   `acdp-linux-arm64-gnu` hit a transient `IDENTITY_TOKEN_READ_ERROR` and the job aborted
   before reaching it — while the root loader package had already published at 0.14.0,
   referencing all 4 platforms as `optionalDependencies`. This would have broken
   `npm install` on linux/arm64 (a version that doesn't exist can't resolve as an optional
   dependency the way an incompatible-platform skip can). Confirmed real (not propagation
   lag) by re-querying the npm registry API directly until each package's own `versions`
   map settled, rather than trusting a single read or the local `npm view` cache.
4. Before retrying, read `@napi-rs/cli`'s actual `pre-publish` source in
   `bindings/acdp-node/node_modules/@napi-rs/cli/dist/cli.js` to confirm its `execSync('npm
   publish', ...)` call site only swallows "You cannot publish over the previously published
   versions" and rethrows everything else — establishing that `gh run rerun --failed` was
   actually safe (idempotent for the 3 already-published packages) rather than assumed safe.
   The rerun published the missing package cleanly; skipped the other 3 as expected.
5. Final state independently verified against all 3 registries directly (crates.io API,
   PyPI API, npm registry API) rather than inferred from CI going green: 13/13 crates at
   0.14.0, 5/5 npm packages at 0.14.0, PyPI at 0.14.0.

**Disposition:** merged and released. Phase 7 (and the whole
`issues-273-279-284-285-rfc0014-wave` plan) marked `Status: DONE` in
`plans/archive/issues-273-279-284-285-rfc0014-wave.md` and `plans/archive/rs-wave1-PROGRESS.md`. No code change
resulted from this entry (it's a release-process finding, not a code one) — noted here so
a future release isn't surprised by the same `action_required`/OIDC-flake/propagation-lag
shape if it recurs.

## Reconcile: docs-refresh-2026-10 (PR #325) — 2026-10-03
Eight assumptions, all reversible. Analyzed by a fresh Opus agent against `main`; seven settled by Opus, one (public support policy) decided by the maintainer.

| Entry | Decision | Decided by | Evidence |
|---|---|---|---|
| CLAUDE.md edits left uncommitted | CONFIRMED | Opus | `CLAUDE.md` and `plans/` are in `.gitignore`; force-adding would change repo policy. |
| SECURITY.md support window | CONFIRMED with change: "latest minor release only", no version numbers | Maintainer | A public commitment to security reporters. Hardcoded `0.14.x` goes stale each minor bump; reworded in the follow-up PR. |
| Embedded-ref root `content_hash` not checked | CONFIRMED | Opus | `verify_embedded_hash` checks `embedded.content_hash` only; pinned by `verify_embedded_hash_ignores_root_only_content_hash`. |
| LIM-2 pointer to rustdoc | CONFIRMED | Opus | `RevocationPolicy` rustdoc names LIM-2; a link into ignored `plans/` would 404. |
| `HttpsDataRefFetcher` third mapping | CONFIRMED | Opus | `data_ref.rs` maps via `AcdpError::Http(e.to_string())`, flattening the source chain (issue #321). |
| Verification stage table order | CONFIRMED | Opus | Matches `verify_retrieved` order in `crates/acdp-client/src/verified.rs`. |
| Runbook history deleted, not archived | CONFIRMED | Opus | `git show 115ce3d:docs/release-runbook.md` resolves; `plans/` is untracked. |
| Audited crypto versions kept in table | CONFIRMED | Opus | Audited column makes the exemption-only coverage visible; the plan's `0.23.40` grep was the error. Re-certification tracked in #322. |

## #322 supply-chain audit policy (2026-10-04)

Policy for re-certifying the crypto-critical crates of issue #322 (plan
`plans/supply-chain-recertify-322.md`, Phase 1). Every later #322 audit PR applies it.
The Tier A set is the 11 crates in `scripts/crypto-critical.txt`: `ed25519-dalek`,
`curve25519-dalek`, `signature`, `sha2`, `zeroize`, `subtle`, `p256`, `ecdsa`,
`elliptic-curve`, `rustls`, and `ring`.

**Decision: re-certify, do not formally accept the exemptions.** Every Tier A review is
feasible; the largest is about 5k lines, or a 5k-line diff. An exemption survives only
under the concern rule below.

1. **Criteria: built-in `safe-to-deploy`, with no custom criterion.** That means fully
   reasoning about every `unsafe` block and every powerful import. It does not require a
   full logic review. **Not claimed:** cryptographic correctness, constant-time
   behaviour, or side-channel resistance. Every note says so. A `crypto-reviewed`
   criterion was rejected because we cannot honestly meet it.
2. **Method rule.** Do a **full** audit (`version = "<locked>"`) when the delta's changed
   lines are ≥75% of the crate's full `src/` lines. Also do a full audit when the delta
   crosses a major or pre-1.0-minor rewrite that touches most `unsafe` sites; that is a
   reviewer judgement. Otherwise do a **delta** audit (`delta = "<audited> -> <locked>"`).
   Never build a delta on a base we now believe was wrong.
3. **Notes template.** A multi-line TOML string with these fields: `Scope`; `Source`
   (the crates.io tarball sha256, equal to the `Cargo.lock` checksum); `unsafe` (count,
   with a soundness argument per cluster); `asm/SIMD`; `build.rs / proc-macro`;
   `Powerful imports`; `New deps`; `Advisories` (`cargo deny check advisories` clean on
   <date>); `Not claimed: cryptographic correctness, constant-time behaviour,
   side-channel resistance.`; and `Method: Reviewed with Claude (Opus) assistance;
   worksheet in <PR URL>`. Every factual field must be reproducible with
   `scripts/vet-facts.sh <crate> <locked> [<base>]`.
4. **`who` and sign-off.** `who = "Ajit Koti <ajitkoti@zer07labs.com>"`. The `Method:`
   line is exact. Open the PR as a draft first, so the URL exists before `certify`
   runs. The per-crate findings worksheet goes in the PR body. **Audit PRs are never
   auto-merged.** **Approval (amended 2026-10-05, maintainer decision
   `322-policy4-approval`):** the maintainer approves an audit PR by merging it by hand
   themselves, and by posting a PR comment that names the worksheets for `<crates>`
   that they read. No approving GitHub review is required: the author cannot approve
   their own PR. An agent's merge, including one made on a standing "merge when green"
   instruction, is not this approval. `/ship` never merges an audit PR; it stops on
   green CI and waits for the maintainer. Check the comment with
   `gh pr view <n> --json comments`.
5. **Record command.** Run it non-interactively, with flags verified on cargo-vet 0.10.2:
   `cargo vet certify <crate> <from> [<to>] --criteria safe-to-deploy --who "…"
   --notes "$(cat notes.txt)" --accept-all`. Omit `<to>` for a full audit. Then
   `git diff --stat supply-chain/imports.lock` must be empty. If it is not, check out
   the file again and confirm `cargo vet --locked` is still green. If it is not green,
   stop: no new imports are allowed. Then run `cargo vet --locked`. If `certify` edits
   `config.toml` beyond the target exemption, rerun with `--no-minimize-exemptions`,
   remove that one exemption by hand, and run `cargo vet fmt`.
6. **Concern rule.** It applies when a review finds any of these: unsound or unexplained
   `unsafe`; unexpected network, filesystem, or process access; a build.rs or proc-macro
   that does more than cfg selection or codegen; obfuscated or vendored binary content;
   a RUSTSEC hit; or a review that cannot be finished. **Carve-out (amended 2026-10-04,
   Fable decision on `322-sha2`):** this rule does not apply when the unsound code is
   unreachable in any stable-toolchain build of any ACDP artifact; in that case certify
   and record the discretion in the audit notes (`Discretion:` lines). (A second limb,
   for builder-only `--cfg` opt-ins compiled into no ACDP-built or ACDP-tested artifact,
   was proposed 2026-10-05 in `322-getrandom` and awaits the maintainer's
   acknowledgement.) For a crate under the concern rule:
   - Do not certify it.
   - Keep its exemption, with `notes = "KEPT EXEMPT (#322): <reason>; see DECISIONS.md
     '322-<crate>'"`.
   - Add a DECISIONS.md entry tagged `Needs: Fable decision`. It states the concern, the
     evidence (`file:line`), and the options: accept the exemption, pin an older audited
     version, or report upstream. It must contain the anchor text `322-<crate>`
     verbatim.
   - Change the guard marker to `allow-exempt:DECISIONS#322-<crate>@<version>` (the
     `@<version>` pin was added 2026-10-04 in Phase 5; see item 7).
   - The phase still closes, with that crate listed as an exception.
7. **Guard and marker semantics.** The `cargo-vet` required check runs
   `scripts/check-crypto-vet.sh` after `cargo vet --locked`. The guard reads
   `cargo vet --locked --output-format=json`, plus the locked versions from
   `cargo metadata --locked --all-features`.
   - **No marker:** every locked version must be in `vetted_fully`.
   - **`allow-exempt:#322-pending`:** passes while the crate is still exempted.
   - **`allow-exempt:DECISIONS#322-<crate>@<version>`:** the anchor must be exactly
     `322-<crate>` for that line's crate, and DECISIONS.md must contain it as a whole token.
     **Amended 2026-10-04 (Phase 5, verifier finding):** the `@<version>` is required.
     Every unaudited locked version, and every `[[exemptions.<crate>]]` version in
     `supply-chain/config.toml`, must equal it. Otherwise the guard fails ("re-audit, or
     update the DECISIONS.md entry and the marker"). Without the pin, a bump could be met
     by moving the exemption.
   - Both markers fail as **stale** once every locked version is fully vetted, which
     forces each phase to remove its own markers.
   - Any other marker fails, as does a listed crate that is not in `Cargo.lock`.
   - The nine pending exemptions also carry
     `notes = "allow-exempt:#322-pending (issue #322)"` in `supply-chain/config.toml`, for
     human readers only. The guard does not read them.
   - The list lives in `scripts/`, because cargo-vet rewrites `supply-chain/` and drops
     its comments.
   - Self-tests are in `scripts/test-check-crypto-vet.sh`.
   - Rejected alternatives: a cargo-vet `[policy]` knob (none exists); failing on any
     exemption (that would block on the ~250-crate long tail); and TOML comments as
     markers (cargo-vet drops them).
8. **Dependabot.** A `crypto` group, listed first in the root `cargo` entry, holds the
   direct crypto deps only: `ed25519-dalek`, `p256`, `sha2`, `zeroize`, and `rustls`.
   `allow: dependency-type: all` is per ecosystem entry, so it would flood PRs for the
   whole transitive graph. Transitive Tier A crates move only through a lock rewrite,
   and the guard catches that once the crate's pending marker is removed.

**Status:** DECIDED (maintainer-settled policy, recorded in Phase 1).

## #322 322-sha2: sha2 0.11.0 concern review, certified with discretion (2026-10-04)

**Needs: Fable decision.** Concern-rule entry for issue #322, Phase 2. Anchor: `322-sha2`.
The worksheet is `supply-chain/worksheets/sha2-0.11.0.md`.

**Concern.** The opt-in `riscv-zknh` backend is unsound for some inputs. Evidence:
`src/sha256/riscv_zknh/utils.rs:44,61` and `src/sha512/riscv_zknh/utils.rs:44,61,94,110`.

- `load_unaligned_block` derives `bp = block.as_ptr().wrapping_sub(offset)` and then calls
  `ptr::read(bp.add(1 + i))`.
- `<*const T>::add` is UB if `bp` lies before the allocation. That happens when an
  unaligned block starts within the first `offset` bytes of an align-1 allocation.
- The backend is reachable only with `--cfg sha2_backend="riscv-zknh"` or
  `--cfg sha2_256_backend="riscv-zknh"`. These are the only keys that select it, in both
  `src/sha256.rs:5` and `src/sha512.rs:5`.
- It also needs nightly (or stable with RUSTC_BOOTSTRAP=1, which is not a supported configuration) (`#![feature(riscv_ext_intrinsics)]`, `src/lib.rs:9-16`).
- No Cargo feature enables it, so it is **unreachable in every ACDP build** and in every
  stable build.

**Rest of the review.** All other `unsafe` sites were reviewed and found sound: the
default soft path, cpufeatures-dispatched x86 SHA-NI/AVX2 and aarch64 SHA2/SHA3, the
wasm32 simd128 backend, and loongarch64 asm.

One non-blocking observation was recorded: the default aarch64 backend loads 16 bytes
through `&K32[t]` / `&K64[t]`. That is a reference to one element of an immutable
`static`, and the read stays in bounds of the static. It is an error only under Stacked
Borrows, and 0.10.9, which we audited, used the identical pattern.

**Options.**
1. *(recommended)* Certify the full 0.11.0 audit with a scope line: "excludes the
   nightly-only opt-in `riscv-zknh` backend (out-of-allocation `ptr::add`, see the
   worksheet)". Also report S-1 and S-2 upstream to RustCrypto/hashes.
2. Accept the exemption until upstream ships a fix, then delta-audit the fixed release.
3. Pin back to 0.10.9 (audited). This is **not viable**: ed25519-dalek 3 and the
   `digest` 0.11 stack require sha2 0.11.

**Interim state.**
- The `[[exemptions.sha2]]` entry stays, with `notes = "KEPT EXEMPT (#322): …"`.
- The guard marker is `allow-exempt:DECISIONS#322-sha2`.
- Upstream has not been reported yet; that is pending this decision. (Since filed:
  RustCrypto/hashes#920.)

**Decision (Fable, after independent verification, 2026-10-04): option 1.** sha2 0.11.0 is
certified `safe-to-deploy` (full) with two `Discretion:` note lines, under the Policy 6
carve-out: the riscv-zknh finding is unreachable in any stable build. S-1 is fixed upstream
in RustCrypto/hashes#879 (lands in 0.11.1, unreleased). S-2 is unfixed upstream. The
exemption and the guard marker are removed. S-2 was filed upstream on 2026-10-05 as
RustCrypto/hashes#920 (text from `supply-chain/worksheets/sha2-0.11.0.md`).

**Status:** DECIDED.

## #322 322-zeroize: zeroize 1.9.0 kept exempt (2026-10-04)

**Needs: Fable decision.** Concern-rule entry for issue #322, Phase 2. Anchor:
`322-zeroize`. The worksheet is `supply-chain/worksheets/zeroize-1.9.0.md`.

**Concern.** The new safe `pub fn optimization_barrier<T: ?Sized>(val: &T)` is unsound on
targets without stable `asm!`, and under Miri. Evidence: `src/barrier.rs:92-100`.

- The fallback calls an `#[inline(never)]` helper that does `read_volatile(p)` with
  `p: *const u8`, on byte 0 of `*val`.
- If that byte is uninitialized, producing the `u8` is UB. That covers padding,
  `MaybeUninit`, and the payload bytes after a typed `None` write.
- Safe code can trigger it, for example
  `optimization_barrier(&MaybeUninit::<u8>::uninit())`.
- The crate itself can reach it: `impl Zeroize for Option<Z>` does `write_volatile(self,
  None)` and then `optimization_barrier(self)` (`src/lib.rs:403-405`).
- 1.8.2 used `compiler_fence(SeqCst)` and had no such read.

**Reachability for ACDP.**
- Native x86_64 and aarch64 builds use the sound empty-`asm!` path (`src/barrier.rs:68-73`).
- `bindings/acdp-wasm` (wasm32) resolves zeroize 1.9.0 and uses the fallback.
- ACDP's own erasures are of `[u8; 32]`-style data, whose byte 0 is initialized after the
  write, so no known ACDP call site triggers the UB.

**Rest of the review.** All other `unsafe` sites were reviewed and found sound: the
volatile writes, `volatile_set`, and the SIMD register impls. One non-blocking
observation: `zeroize_flat_type` calls `optimization_barrier(&data)` on the pointer
variable, not the pointee (`src/lib.rs:823`). That is redundant, not harmful.

**Method.** Full. The ratio is 0.72, below 0.75, so the numeric rule said delta. Full was
chosen under the rewrite clause, because the delta replaces the barrier at every
volatile-write site and adds the crate's only `asm!`.

**Options.**
1. *(recommended)* Report Z-1 upstream to RustCrypto/utils. The fix is to read through
   `MaybeUninit<u8>` or drop the volatile read. Accept the exemption until a fixed
   release, then delta-audit it.
2. Certify with a scope line ("sound on asm targets; the non-asm/Miri fallback of
   `optimization_barrier` is excluded"). This is weaker, because the wasm binding uses
   exactly that fallback.
3. Pin back to 1.8.2 (audited 2026-07-05) with `cargo update -p zeroize --precise 1.8.2`.
   The dependents' requirements allow it: ed25519-dalek `1.5`, elliptic-curve `1.7`,
   curve25519-dalek and crypto-bigint `1`, and acdp-crypto `1`. Still to verify: whether
   `zeroize_derive` 1.5, required by 1.9.0, also works with 1.8.2, and the binding locks.

**Interim state.**
- The `[[exemptions.zeroize]]` entry stays, with `notes = "KEPT EXEMPT (#322): …"`.
- The guard marker is `allow-exempt:DECISIONS#322-zeroize`.
- Upstream has not been reported yet; that is pending this decision. (Since filed:
  RustCrypto/utils#1549.)

**Decision (Fable, after independent verification, 2026-10-04): option 1, keep exempt.**
- The carve-out does not apply: `bindings/acdp-wasm` is a published ACDP artifact, and its
  stable wasm32 build compiles the faulty fallback.
- Do **not** pin to 1.8.2: that means lock churn across three bindings, a fight with
  Dependabot, and an MSRV change (1.60 vs 1.85).
- **Exit criterion:** delta-audit zeroize 1.9.1 when it is released. RustCrypto/utils#1535
  (merged 2026-09-11) removes the internal callers of `optimization_barrier`. If the safe
  `pub fn` remains unchanged but unused internally, it then qualifies for the discretion
  carve-out, provided no ACDP artifact calls it.
- The exemption and the `allow-exempt:DECISIONS#322-zeroize` marker stay. Z-1 was filed
  upstream on 2026-10-05 as RustCrypto/utils#1549 (text from
  `supply-chain/worksheets/zeroize-1.9.0.md`).

**Status:** DECIDED.

## #322 completion status (2026-10-04)

Closing entry for issue #322 (plan `plans/supply-chain-recertify-322.md`, Phase 5). All
five phases are merged, each as a separate PR: #332 (Phase 1), #334 (Phase 2), #335
(Phase 3), #336 (Phase 4) and #345 (Phase 5), all merged 2026-10-04. #338, the first
Phase 5 PR, was closed unmerged and superseded by #345. Issue #322 closed on 2026-10-04.

**Audited at the locked version (10 of the 11 Tier A crates).** Each has a
`safe-to-deploy` audit by `Ajit Koti`, reviewed with Claude (Opus) assistance, with a
worksheet in `supply-chain/worksheets/`:

| Crate | Version | Method | Phase |
|---|---|---|---|
| `signature` | 3.0.0 | full | P2 |
| `sha2` | 0.11.0 | full; two `Discretion:` lines (`322-sha2`) | P2 |
| `ed25519-dalek` | 3.0.0 | delta from 2.2.0 | P3 |
| `curve25519-dalek` | 5.0.0 | delta from 4.1.3; `docsrs` discretion | P3 |
| `elliptic-curve` | 0.14.1 | full | P4 |
| `ecdsa` | 0.17.0 | full; test-fixture discretion | P4 |
| `p256` | 0.14.0 | full; test-fixture discretion | P4 |
| `rustls` | 0.23.45 | delta from 0.23.40 (40 files, +732/-135; 0 `unsafe`) | P5 |
| `subtle` | 2.6.1 | 2026-07-05 audit, still at the locked version | — |
| `ring` | 0.17.14 | 2026-07-05 audit, still at the locked version | — |

- The rustls delta contains the RUSTSEC-2026-0285 fix: handshake alignment is now
  "no pending handshake data", rechecked at every key change.
- Its only powerful import, `KeyLogFile` (`SSLKEYLOGFILE`), is opt-in through
  `ClientConfig::key_log`. reqwest and ACDP never set it.
- The production provider is ring (reqwest `rustls-tls`; rustls features `ring`, `std`,
  `tls12`). aws-lc-rs is in the dev graph only.
- The audit claims neither TLS protocol correctness nor certificate-validation
  correctness.

**What no audit claims.** No #322 audit claims cryptographic correctness, constant-time
behaviour, side-channel resistance, or (for rustls) TLS protocol or certificate-validation
correctness. `safe-to-deploy` here means the `unsafe` code, the build scripts, and the
powerful imports were reasoned about at the exact bytes in `Cargo.lock`.

**Remains exempt, and why.**
- **`zeroize` 1.9.0** (`322-zeroize`).
  - Z-1: the safe `optimization_barrier` reads a possibly-uninitialized byte on non-`asm!`
    targets, and the published wasm32 binding builds that path.
  - Exit criterion: delta-audit 1.9.1.
  - The guard marker `allow-exempt:DECISIONS#322-zeroize@1.9.0` pins the exemption to
    1.9.0. A bump to 1.9.1 fails the guard until 1.9.1 is audited, or until this entry
    and the marker are deliberately updated.
- **The 35 supporting crypto crates (Tier B)** were out of scope for #322. Each is covered
  by an exemption only, and none is on the guard list:
  - RustCrypto support: `ed25519`, `curve25519-dalek-derive`, `digest`, `crypto-common`,
    `block-buffer`, `cpufeatures`, `hybrid-array`, `ctutils`, `cmov`, `zeroize_derive`,
    `rfc6979`, `hmac`, `sec1`, `spki`, `pkcs8`, `base16ct`, `base64ct`, `primeorder`,
    `primefield`, `wnaf`, `ff`, `group`, `const-oid`, `der`, `crypto-bigint`, `typenum`,
    `cpubits`;
  - key generation: `rand_core`, `getrandom`;
  - TLS stack: `rustls-webpki`, `rustls-pki-types`, `tokio-rustls`, `hyper-rustls`,
    `webpki-roots`, `untrusted`.
- `aws-lc-rs` / `aws-lc-sys` are dev-only. Their exemptions over-claim `safe-to-deploy`
  where `safe-to-run` would do.

**Guard state.**
- `scripts/check-crypto-vet.sh` is enforcing in the required `cargo-vet` check.
- `scripts/crypto-critical.txt` has no `#322-pending` line. The only marker left is
  `zeroize allow-exempt:DECISIONS#322-zeroize@1.9.0`. The guard requires DECISIONS
  markers to carry a version and fails on a version mismatch (self-tests g–g4).
- The `#322-pending` marker type is still parsed, because the self-tests exercise it, but
  it is unused.
- `dependabot-auto-merge.yml` never enables auto-merge for the `crypto` group
  (`steps.meta.outputs.dependency-group != 'crypto'`, an output of the pinned
  `dependabot/fetch-metadata` v3.1.0).
- The upgrade workflow is in `docs/supply-chain.md` "Upgrading a crypto-critical crate":
  `vet-facts.sh` -> worksheet -> `certify` -> maintainer review.

**Findings for ACDP (not vet concerns; owned by the maintainer).**
- **E-1 (ed25519-dalek).** ACDP verifies with `VerifyingKey::verify`, not `verify_strict`,
  so small-order keys and small-order `R` are accepted. Evaluate `verify_strict` or
  `is_weak()` rejection at DID-key load. That needs spec input (RFC-ACDP-0002) and a
  golden-vector review.
- **P-1 (p256).** `NORMALIZE_S = false`: high-S verifies, so `ecdsa-p256` signature bytes
  are malleable. ACDP's signer does not normalize either. One effect: a lifecycle-event
  retry with a flipped signature gets `SchemaViolation` instead of `IdempotentReplay`
  (`crates/acdp-server/src/registry/store.rs:585-596`). Recommendation: document
  non-uniqueness in the spec registry, and emit low-S from ACDP signers.
- **P-2 (p256).** `from_sec1_bytes` accepts the SEC1 compact tag `0x05`. ACDP's wire paths
  cannot reach it, and fingerprints use the re-compressed point. Informational.
- **P-3 (p256).** ACDP signs with P-256 as well as verifying. The review covered both
  paths. Hygiene: `P256SigningKey::seed_bytes` passes the secret through a non-zeroized
  `FieldBytes` temporary.
- **Upstream reports (filed 2026-10-05).**
  - Z-1: RustCrypto/utils#1549 (text from `supply-chain/worksheets/zeroize-1.9.0.md`).
  - S-2 (aarch64 one-element-reference loads): RustCrypto/hashes#920 (text from
    `supply-chain/worksheets/sha2-0.11.0.md`).
  - S-1 is already fixed upstream (RustCrypto/hashes#879).

**Follow-up issues (since filed: 1 = #339, 2 = #340, 3 = acdp-registry-rs#387 (closed;
cargo vet set up) with the guard in acdp-registry-rs#405 and the
re-vet / pin-parity ask in acdp-registry-rs#411, 4 = #341, 5 = #342 / #343,
6 = #344).**
1. Certify the Tier B supporting crypto crates, cheap `forbid(unsafe_code)` ones first,
   adding each to the guard list once certified. Also move the `aws-lc-*` exemptions to
   `safe-to-run`.
2. The bindings' lockfiles have no vet coverage (`bindings/acdp-py`, `acdp-node`,
   `acdp-wasm`). Today they resolve the same Tier A versions, which nothing enforces. Add
   a lock-parity check against the root for the guard-list crates.
3. `acdp-registry-rs` has no `cargo vet` setup. Propose `cargo vet init` importing this
   repo's `audits.toml`.
4. zeroize 1.9.1 delta audit once released (the `322-zeroize` exit criterion).
5. ACDP-side follow-ups for E-1 and P-1/P-3 above.
6. Optional: transitive crypto-critical crates can still move inside a non-`crypto`
   Dependabot group, which is auto-merge eligible. Consider gating auto-merge on the
   guard list rather than on the group name.

(Done in Phase 5, no longer a follow-up: `dependabot-auto-merge.yml` skips the `crypto`
group.)

**Status:** DONE. PRs #332, #334, #335, #336 and #345 merged on 2026-10-04 (#338
superseded by #345), and issue #322 is closed.

## #339 aws-lc-rs dropped from the graph instead of re-exempted as safe-to-run (2026-10-04)

**Context.** The #322 completion status above noted that the `aws-lc-rs` 1.18.0 /
`aws-lc-sys` 0.44.0 exemptions over-claim `safe-to-deploy` and should move to
`safe-to-run`. Re-verified before acting: with both exemptions edited to `safe-to-run`,
`cargo vet --locked` failed with `aws-lc-rs:1.18.0 missing ["safe-to-deploy"]` (and the
same for `aws-lc-sys`). Cause: the dev-dependencies `axum-server` (feature `tls-rustls`,
which enables `rustls/aws-lc-rs`) and `rustls` (feature `aws-lc-rs`) unify features into
the single `rustls` 0.23.45 that reqwest's `rustls-tls` uses in production. In cargo-vet's
feature-unified view that makes `rustls -> aws-lc-rs` a normal edge, and `rustls` needs
`safe-to-deploy`, so `aws-lc-*` inherit it. `cargo tree -e features -i aws-lc-rs` showed
the path through `axum-server feature "tls-rustls"`.

**Decision.** Remove the dependency rather than relabel it:
- root `[dev-dependencies]`: `axum-server` uses `tls-rustls-no-provider`; the dev
  `rustls` enables `ring` instead of `aws-lc-rs`;
- `tests/common/mod.rs` installs `rustls::crypto::ring::default_provider()`, the provider
  production already uses, so the test harness now exercises the same TLS backend;
- `cargo update -w` removed only `aws-lc-rs`, `aws-lc-sys`, `cmake`, `dunce`, `fs_extra`,
  `jobserver`, `pkg-config` from `Cargo.lock` (plus the `aws-lc-rs` edges of `rustls` /
  `rustls-webpki` and `cc`'s `jobserver`/`libc` edges); nothing was added or upgraded;
- the seven now-unused exemptions were removed from `supply-chain/config.toml`.
  `cargo vet prune` also proposed swapping the still-used `rustc_version` and `shlex`
  exemptions for newly imported audits (and dropping stale `allocator-api2` imports);
  those are unrelated to this change and were left out.

**Why not `safe-to-run`.** A `safe-to-run` exemption cannot be expressed while the edge
is normal, and a C/asm crypto library we never ship or call in production is better
absent than exempted. The bindings' lockfiles never contained `aws-lc-*`
(`scripts/check-bindings-lock-parity.sh` passes). Guard list and guard script unchanged.

**Reversibility.** Two-way door: re-adding `tls-rustls` would bring `aws-lc-*` back and
need `safe-to-deploy` coverage again. `docs/supply-chain.md` says not to.

**Status:** DONE (PR for #339, aws-lc part). Follow-up 1 of the #322 completion status
no longer includes the `aws-lc-*` move.

## #339 Tier B batch B1: six support crates certified (2026-10-04)

Issue #339, plan `plans/remaining-issues-2026-10.md` P6, batch B1 (PR #355). The #322 audit
policy above applies unchanged: built-in `safe-to-deploy`, notes template, `who` per Policy 4,
concern rule, maintainer approving review before merge.

| Crate | Version | Method | Worksheet finding |
|---|---|---|---|
| `wnaf` | 0.14.1 | full (no base) | W-1: debug-build panic for window sizes 7/8; ACDP uses W = 5; fixed upstream |
| `ff` | 0.14.0 | full (no base) | none; optional `ff_derive` not in any lock |
| `spki` | 0.8.0 | full (no base) | `std`-gated caller-path file helpers (off); test-fixture discretion |
| `crypto-common` | 0.2.2 | full (no base) | CC-1: `[u128; N]` `SerializableState` always panics (unused); fixed upstream (RustCrypto/traits#2471) |
| `zeroize_derive` | 1.5.0 | full (no base) | pure codegen proc-macro; generated code has no `unsafe` |
| `ed25519` | 3.0.0 | full (no base) | none on ACDP paths (no features enabled); test-fixture discretion |

- All six are `#![forbid(unsafe_code)]` with 0 `unsafe` lines, no build.rs, and no asm. No
  concern-rule trigger, so none was kept exempt.
- W-1 and CC-1 are panics in safe code, not memory-safety issues, and are unreachable from
  ACDP. Both are already fixed on upstream master; there is nothing to report.
- Each crate's exemption is removed and the crate is added to `scripts/crypto-critical.txt`
  without a marker (17 guarded crates; only `zeroize` keeps a marker).
- The bindings' lockfiles (py, node, wasm) resolve the same six versions and checksums as the
  root, so `scripts/check-bindings-lock-parity.sh` passes with the larger list. Its self-test
  now derives the expected crate count from the list instead of hard-coding 11.
- Remaining Tier B: 29 crates, batches B2-B7.

**Status:** AUTHORED. Merges only after the maintainer's approving review naming the six
worksheets (Policy 4).

## #339 Tier B batch B2: hmac, rfc6979, pkcs8, sec1, primefield, digest certified (2026-10-04)

Batch B2 of issue #339 (plan P6), under the "#322 supply-chain audit policy" unchanged:
built-in `safe-to-deploy` only, no claim of cryptographic correctness or constant-time
behaviour, `who = "Ajit Koti <ajitkoti@zer07labs.com>"`, reviewed with Claude (Opus)
assistance, maintainer approval required before merge.

| Crate | Version | Method | Worksheet |
|---|---|---|---|
| `hmac` | 0.13.0 | full (no prior audit); test-fixture discretion | `supply-chain/worksheets/hmac-0.13.0.md` |
| `rfc6979` | 0.6.0 | full (no prior audit) | `supply-chain/worksheets/rfc6979-0.6.0.md` |
| `pkcs8` | 0.11.0 | full (no prior audit); test-fixture discretion | `supply-chain/worksheets/pkcs8-0.11.0.md` |
| `sec1` | 0.8.1 | full (no prior audit); test-fixture discretion | `supply-chain/worksheets/sec1-0.8.1.md` |
| `primefield` | 0.14.0 | full (no prior audit) | `supply-chain/worksheets/primefield-0.14.0.md` |
| `digest` | 0.11.3 | full (no prior audit of 0.11.x); test-fixture discretion | `supply-chain/worksheets/digest-0.11.3.md` |

- All six have zero `unsafe` lines, no `asm!`, no build script, and no proc-macro. For
  all six the evidence is a grep of the full source. `pkcs8`, `sec1`, `primefield` and
  `digest` carry `#![forbid(unsafe_code)]`, and `hmac` and `rfc6979` set it as a
  `Cargo.toml` lint, but both are only corroborating hints: Cargo builds registry
  dependencies with `--cap-lints allow`, which caps source-level `forbid` attributes and
  `Cargo.toml` lints alike.
- `primefield` and `digest` are mostly `#[macro_export]` macros that expand in caller
  crates (`p256`; `sha2`, `hmac`), where their `forbid` does not apply. Every macro arm
  was read; none contains `unsafe` or a powerful import.
- The only powerful import is in `pkcs8` and `sec1` under `std` (enabled in ACDP):
  explicit `read_*_der_file` / `write_*_der_file` trait helpers on a caller-chosen path.
  Neither crate nor ACDP calls them, so this is documented opt-in I/O, not "unexpected"
  I/O under the concern rule.
- Test-only binary fixtures (`.blb`/`.der`/`.bin` under `tests/`) are recorded as
  `Discretion:` lines, following the ecdsa/p256 precedent. None is compiled into a
  non-test build.
- `sec1` is on ACDP's untrusted-input path (`p256::ecdsa::VerifyingKey::from_sec1_bytes`):
  `EncodedPoint::from_bytes` validates the tag and exact length before copying.
- The six crates were added to `scripts/crypto-critical.txt` with no marker. All three
  binding lockfiles lock the same six versions with the same checksums as the root.
- No concern was found; nothing in this batch was kept exempt.

**Status:** AUTHORED. Pending the maintainer's approving review naming the worksheets read
(Policy 4); never auto-merged.

## #339 Tier B batch B3: untrusted, cpubits, hyper-rustls, group, tokio-rustls, primeorder certified (2026-10-04)

Batch B3 of issue #339 (plan P6), under the "#322 supply-chain audit policy" unchanged:
built-in `safe-to-deploy` only, no claim of cryptographic correctness or constant-time
behaviour, `who = "Ajit Koti <ajitkoti@zer07labs.com>"`, reviewed with Claude (Opus)
assistance, maintainer approval required before merge.

| Crate | Version | Method | Worksheet |
|---|---|---|---|
| `untrusted` | 0.9.0 | full (no prior audit); discretion on packaged CI scripts | `supply-chain/worksheets/untrusted-0.9.0.md` |
| `cpubits` | 0.1.1 | full (no prior audit); observation CB-1 | `supply-chain/worksheets/cpubits-0.1.1.md` |
| `hyper-rustls` | 0.27.9 | full (no prior audit) | `supply-chain/worksheets/hyper-rustls-0.27.9.md` |
| `group` | 0.14.0 | full (no prior audit); observation G-1 | `supply-chain/worksheets/group-0.14.0.md` |
| `tokio-rustls` | 0.26.4 | full (no prior audit); test-fixture discretion | `supply-chain/worksheets/tokio-rustls-0.26.4.md` |
| `primeorder` | 0.14.0 | full (no prior audit) | `supply-chain/worksheets/primeorder-0.14.0.md` |

- None of the six has a `forbid(unsafe_code)` attribute or `Cargo.toml` lint (the
  "no-attribute" batch). For each, the evidence is a grep of the full source, tests
  included: 0 `unsafe` sites, no `asm!`, no build script, no proc-macro.
- **TLS adapters.** `hyper-rustls` and `tokio-rustls` do network I/O by design, but only on
  the caller's connector or stream. In the features ACDP compiles, neither builds a
  certificate verifier: only hyper-rustls's `rustls-platform-verifier` feature, which is
  off, installs one. Neither touches `dangerous()` or installs a key-log hook. Both pass
  the caller's `rustls::ClientConfig` through unchanged, apart from ALPN.
  - Features: ACDP compiles `hyper-rustls` with `http1`, `ring`, `tls12`, `webpki-roots`
    and `webpki-tokio`, and `tokio-rustls` with `ring` and `tls12`. The default feature
    sets are off, so `aws-lc-rs`, `native-tokio` / `rustls-native-certs`, `logging` and
    `early-data` are not compiled.
  - Trust roots: reqwest's config uses webpki roots. ACDP's public
    `with_root_cert_pem` / `root_cert_pem` APIs (`crates/acdp-did/src/web.rs:108`, `:117`;
    `crates/acdp-client/src/registry.rs:332`, `:748`) add caller-supplied roots. Nothing
    disables verification.
  - Plain HTTP: hyper-rustls passes `http://` through in cleartext (`force_https: false`
    on reqwest's path). ACDP rejects non-`https` URLs by default, through
    `SsrfPolicy::check_url` -> `classify_url` (`crates/acdp-safe-http/src/lib.rs:186`,
    `:204`). That is not this crate's doing, and `SsrfPolicy.allow_http` (`:140`, default
    `false`) is a public opt-in.

  No concern was found, so neither crate was kept exempt.
- `cpubits` (`#[macro_export]` macros expanding in `crypto-bigint`) and `primeorder` (generic
  curve arithmetic, monomorphized in `p256`) had every macro arm and every feature-gated file
  read. `primeorder`'s `dev` macro is compiled only with `dev`, which is off.
- Observations, neither a vet concern: **CB-1**, cpubits's single-size `16 => {..}` arm fails
  to compile (a stray comma; compile-time only, unused, still on upstream master). **G-1**,
  group's wNAF helper misbehaves at window sizes 0 and 64 (a panic or wrong result; no
  caller in ACDP's graph). Reporting either upstream is the maintainer's call.
- `untrusted`, `hyper-rustls` and `tokio-rustls` are lock-only in the py and node bindings
  (not compiled into their builds) and absent from wasm. `cpubits`, `group` and `primeorder`
  are compiled into all three bindings. Every binding lockfile that has them locks the same
  versions and checksums as the root, so `scripts/check-bindings-lock-parity.sh` passes
  with 29 crates.
- The six crates were added to `scripts/crypto-critical.txt` (block `# Batch B3:`) with no
  marker: 29 guarded crates, of which only `zeroize` keeps a marker. Remaining Tier B: 17
  crates.
- No concern was found; nothing in this batch was kept exempt.

## #339 Tier B batch B4: rand_core (0.10.1, 0.9.5), ctutils, webpki-roots, typenum certified (2026-10-04)

Batch B4 of issue #339 (plan P6), under the "#322 supply-chain audit policy" unchanged:
built-in `safe-to-deploy` only, no claim of cryptographic correctness or constant-time
behaviour, `who = "Ajit Koti <ajitkoti@zer07labs.com>"`, reviewed with Claude (Opus)
assistance, maintainer approval required before merge.

| Crate | Version | Method | Worksheet |
|---|---|---|---|
| `rand_core` | 0.10.1 | full (no prior audit); all files read | `supply-chain/worksheets/rand_core-0.10.1.md` |
| `rand_core` | 0.9.5 | full (no prior audit); all files read; was a `safe-to-run` exemption | `supply-chain/worksheets/rand_core-0.9.5.md` |
| `ctutils` | 0.4.2 | full (no prior audit); non-test code read, test modules grep-scanned | `supply-chain/worksheets/ctutils-0.4.2.md` |
| `webpki-roots` | 1.0.9 | full (no prior audit); header read, table checked exhaustively by script; test-fixture discretion | `supply-chain/worksheets/webpki-roots-1.0.9.md` |
| `typenum` | 1.20.1 | full (no prior audit); generated files shape-checked exhaustively, runtime bodies extracted, impl headers sampled; generated-test discretion | `supply-chain/worksheets/typenum-1.20.1.md` |

- All five have zero `unsafe` lines (grep of the full source; `forbid(unsafe_code)` in
  `ctutils`, `webpki-roots` and `typenum` is only a hint, since `--cap-lints allow` caps it
  for registry dependencies), no `asm!`, no build script, and no proc-macro.
- **`rand_core` 0.9.5 decision.** It is a dev-only dependency (`proptest` -> `rand` 0.9.5),
  previously exempted as `safe-to-run`. The full read found nothing that falls short of
  `safe-to-deploy`: its only external effect is the documented OS-RNG call through
  getrandom 0.3 under `os_rng`. Certifying it at `safe-to-deploy` (which implies
  `safe-to-run`) lets `rand_core` be listed once in the guard with both locked versions
  fully audited, and covers the case where 0.9 ever becomes a normal dependency.
- **`ctutils`.** Constant-time behaviour is explicitly not claimed. All predication is
  delegated to `cmov` (B6, still exempted). Safe-code panics noted (`ct_lookup` index
  overflow, an upstream TODO; signed `ct_neg` of `MIN` in debug); none is a memory-safety
  issue, and no use of `CtLookup`/`CtFind` was found in ACDP's graph.
- **`webpki-roots`.** A trust boundary: it is the default root store for ACDP's HTTPS
  clients via reqwest's `rustls-tls`. The audit establishes what the table contains: 121
  `TrustAnchor` entries whose subject/SPKI bytes equal the certificates (and fingerprints)
  in their comments, generated by upstream's `tests/codegen.rs` from CCADB's Mozilla
  report; one Mozilla-applied name constraint (TUBITAK, `.tr`). It does **not** claim the
  root set is correct or current.
- **`typenum`.** Not every line was read; the worksheet lists what was read in full
  (exported macros, `lib.rs`, `marker_traits.rs`, `tuple.rs`), what was checked by script
  (all generated code, all `fn` bodies and `const` initialisers), and what was sampled
  (type-level `impl` headers and `where` clauses).
- The four crates were added to `scripts/crypto-critical.txt` under `# Batch B4:` with no
  marker (33 guarded crates after B3 and B4). Binding lockfiles: `rand_core` 0.10.1,
  `ctutils` and `typenum` match the root in py/node/wasm; `webpki-roots` matches in py/node
  (locked there but not compiled: the bindings build `acdp` with default features off, so it
  is not in their active `cargo tree`) and is absent from wasm; `rand_core` 0.9.5 is absent
  from all three. `scripts/check-bindings-lock-parity.sh` passes.
- No concern was found; nothing in this batch was kept exempt. Remaining Tier B: 13 crates
  (35 minus the 22 certified in B1-B4).

**Status:** AUTHORED. Pending the maintainer's approving review naming the worksheets read
(Policy 4); never auto-merged.

## #339 Tier B batch B5: base16ct, base64ct, rustls-pki-types, const-oid, der, curve25519-dalek-derive certified (2026-10-04)

Batch B5 of issue #339 (plan P6) ran under the unchanged "#322 supply-chain audit policy":

- built-in `safe-to-deploy` only;
- no claim of cryptographic correctness or constant-time behaviour, including the
  constant-time encoding that `base16ct` and `base64ct` advertise;
- `who = "Ajit Koti <ajitkoti@zer07labs.com>"`, reviewed with Claude (Opus) assistance;
- maintainer approval required before merge.

| Crate | Version | Method | `unsafe` | Worksheet |
|---|---|---|---|---|
| `base16ct` | 1.0.0 | full (no prior audit); all files read | 4 (`from_utf8_unchecked` on self-written ASCII) | `supply-chain/worksheets/base16ct-1.0.0.md` |
| `base64ct` | 1.8.3 | full (no prior audit); all files read | 4 (`decode_in_place` raw-pointer chunking, `from_utf8_unchecked`) | `supply-chain/worksheets/base64ct-1.8.3.md` |
| `rustls-pki-types` | 1.15.1 | full (no prior audit); all files read; embedded DER blobs decoded | 1 (`[u16; 8] -> [u8; 16]` value transmute) | `supply-chain/worksheets/rustls-pki-types-1.15.1.md` |
| `const-oid` | 0.10.2 | full (no prior audit); hand-written files read; feature-gated generated OID DB shape-checked by script | 1 (`repr(transparent)` DST cast) | `supply-chain/worksheets/const-oid-0.10.2.md` |
| `der` | 0.8.1 | full (no prior audit); non-test code of all 56 `src/` files read, doc comments skimmed, some test modules grep-only | 4 (`repr(transparent)` DST casts) | `supply-chain/worksheets/der-0.8.1.md` |
| `curve25519-dalek-derive` | 0.1.1 | full (no prior audit); all files read, plus curve25519-dalek 5.0.0's dispatch | 0 executed; 5 in generated templates | `supply-chain/worksheets/curve25519-dalek-derive-0.1.1.md` |

Each `unsafe` site is quoted with its invariant in the worksheet and in the `audits.toml`
note. None needs a precondition that the safe API leaves open.

**Empirical backing (scratch crate, release build with debug assertions on; Miri not run):**
- `base64ct`: exhaustive dirty-buffer encode and round trip over every 1-, 2- and 3-byte
  input, for all 8 alphabets.
- `base16ct`: exhaustive over every 2-byte input.
- `der`: 300k random and semi-structured decodes, with no panic.

**Filesystem APIs (not concern triggers).** `rustls-pki-types`
(`PemObject::from_pem_file`) and `der` (`Document`/`SecretDocument::read_der_file` /
`write_der_file`, under `std`, which is on) expose documented file APIs that act on a
caller-named path.
- ACDP never calls them. Neither do the dependents on ACDP's path: reqwest parses PEM from
  memory, and sec1, spki and pkcs8 only wrap the APIs in their own opt-in `*_file` methods.
- `scripts/vet-facts.sh` misses `der`'s brace import `use std::{fs, path::Path}`, so this was
  found by reading.

**`der` discretion (D-1, D-2): safe-code non-termination, unreachable from ACDP.**
- **D-1:** `ValueOrd` for `ContextSpecific`/`Application`/`Private`
  (`src/asn1/internal_macros.rs:276-286`) recurses without end.
- **D-2:** `TryFrom<AnyRef> for bool` (`src/asn1/boolean.rs:49-55`) recurses through the
  blanket `TryInto`.
- Both were confirmed: a stack overflow and abort in debug builds, and a hang or overflow in
  release builds.
- Neither involves `unsafe`. On native targets the stack overflow aborts at the guard page.
  In `acdp-wasm` (wasm32, which has no guard page) it would end in a wasm trap; it is still
  unreachable there. ACDP parses no DER, and no dependent on its path compares
  context-specific values or calls `bool::try_from(AnyRef)`.
- Both are recorded as `Discretion:` lines. Recommend an upstream report to
  RustCrypto/formats; this audit did not file one.

**`curve25519-dalek-derive`.** It is a proc-macro, and its generated safe wrappers call
`#[target_feature]` functions in `unsafe` with no check. Soundness belongs to the macro's
user.
- The user's "safe" function body becomes the body of a generated `unsafe fn` (`src/lib.rs:436`,
  `:459`), so it is an unsafe context. curve25519-dalek 5.0.0 is edition 2024, where
  `unsafe_op_in_unsafe_fn` only warns, and `--cap-lints` silences that warning. So unsafe
  operations compile in those bodies with no `unsafe` token, and a full-source grep of
  curve25519-dalek undercounts its unsafe operations.
- In ACDP the only user is curve25519-dalek 5.0.0. Its vector backend is `pub(crate)`, and
  every entry goes through `get_selected_backend()` cpufeatures detection, as its own audit
  records.
- It is compiled on all x86_64 targets, including Linux, macOS and Windows; the py and node
  releases ship `x86_64-apple-darwin` and `x86_64-unknown-linux-gnu`. It is absent from the aarch64 host build and from the
  wasm32 binding.

**`base64ct`** is lock-only: it is compiled into no ACDP build, because `spki`'s `base64`
feature is off. It was certified anyway, so its lock entry and the guard list stay covered.

**Guard list and docs.**
- The six crates were added to `scripts/crypto-critical.txt` under `# Batch B5:` with no
  marker, for 39 guarded crates.
- `docs/supply-chain.md` counts and table were updated.
- Binding lockfiles:
  - all six match the root wherever they are locked;
  - `rustls-pki-types` is absent from the wasm lock;
  - `scripts/check-bindings-lock-parity.sh` passes.

No concern was found, and nothing in this batch was kept exempt. Remaining Tier B: 7 crates
(35 minus the 28 certified in B1-B5): `block-buffer`, `cpufeatures`, `hybrid-array`, `cmov`,
`crypto-bigint`, `getrandom`, `rustls-webpki`.

**Status:** AUTHORED. Pending the maintainer's approving review naming the worksheets read
(Policy 4); never auto-merged.

## #339 322-cpufeatures: cpufeatures 0.3.1 certified with a Discretion line (2026-10-04, decided 2026-10-05)

Concern-rule entry for issue #339, batch B6. Anchor: `322-cpufeatures`. The worksheet is
`supply-chain/worksheets/cpufeatures-0.3.1.md`.

**Finding (CF-1).** On x86, `__detect_target_features!` reads CPUID leaf 7 (sub-leaves 0
and 1) without reading leaf 0 to check the maximum supported basic leaf. Evidence:
`src/x86.rs:49-51` (`[cpuid(1), cpuid_count(7, 0), cpuid_count(7, 1)]`).

- On Intel, a basic leaf above the maximum returns the highest basic leaf's data, so on a
  CPU or VM whose maximum basic leaf is below 7 the "leaf 7" bits are bits of another leaf.
- In ACDP's graph the leaf-7 checks are:
  - `sha` (EBX bit 29), used by `sha2` 0.11.0 for SHA-NI SHA-256 (`src/sha256.rs:55`);
  - `avx2` (EBX bit 5), used by `sha2` for SHA-512 (`src/sha512.rs:50`) and by
    `curve25519-dalek` 5.0.0 (`src/backend.rs:67`).
- A spurious bit would make those crates run `#[target_feature]` code the CPU lacks.
- Every `unsafe`/`asm!` site in cpufeatures is itself sound (worksheet table).
- Reachability:
  - compiled into the x86_64 builds (the root crate on Linux/Windows, and the py/node
    x86_64 wheels);
  - not compiled for wasm32 (`compile_error!`, `src/lib.rs:25-31`);
  - aarch64 is unaffected.

The B6 review held the crate back by default ("default to not certifying") and put the
following options up for decision:
1. Certify with a `Discretion:` line.
2. Keep it exempt until upstream ships a fix.
3. Pin back. This is not possible: `sha2` 0.11.0 requires `cpufeatures` `^0.3`
   (`Cargo.toml:79-80`).

**Decision (Fable, 2026-10-05): option 1, certify `safe-to-deploy` (full) with a
`Discretion:` line.** Fable verified CF-1 from source independently. The reasons recorded
are below. The platform facts are the decision reviewer's, and the B6 review did not
re-measure them.

- CF-1 is a correctness gap in a **safe** function whose input (CPUID) is not
  attacker-controlled. Every `unsafe`/`asm!` site in the crate is sound.
- The predicates ACDP's graph evaluates cannot misfire on any supported platform:
  - `sha` is ANDed (by `sha2`) with leaf-1 SSE2, SSSE3 and SSE4.1.
  - `avx2` is ANDed inside cpufeatures with leaf-1 AVX and the XCR0 XMM+YMM state, gated
    on OSXSAVE (`src/x86.rs:68-71`, `:92`, `:126`).
- Every CPU with those leaf-1 bits has a native maximum basic leaf of at least 0xA.
- No QEMU CPU model that exposes SSE4.1 or AVX has a level below 0xA.
- The firmware "Limit CPUID Maxval" setting caps the maximum at leaf 2 or 3. That yields
  zeros or a false AND, and Linux and Windows clear the setting.
- Rosetta 2 reports a maximum basic leaf of 0xD (measured).
- Only a manual hypervisor `level=` override on an AVX-class CPU model reaches the gap, and
  then the result is a deterministic `SIGILL`.
- The decision keeps ACDP consistent with the already-certified `sha2` 0.11.0 and
  `curve25519-dalek` 5.0.0 audits, whose notes rest on this detection.

**Upstream.** RustCrypto/utils#1510 (opened 2026-07-26) already tracks this, and fix PR
RustCrypto/utils#1528 (opened 2026-09-02, still open) gates leaves 1, 7.0 and 7.1 on
`CPUID.0:EAX`. The B6 worksheet's earlier statement that nothing had been filed upstream
was stale, and its draft upstream issue is superseded. It must not be filed.

**State after the decision:**
- An `[[audits.cpufeatures]]` full `safe-to-deploy` audit of 0.3.1 has been added. Its notes
  carry the `Discretion:` paragraph, observation CF-2 (Apple `sysctlbyname` panics if a node
  is missing), and "Not claimed: correctness of feature detection on every CPU
  configuration".
- `[[exemptions.cpufeatures]]` has been removed.
- `scripts/crypto-critical.txt` lists `cpufeatures` with no marker.

**Exit criterion:** delta-audit the cpufeatures release that carries #1528.

**Status:** DECIDED (Fable, 2026-10-05).

## #339 Tier B batch B6: cpufeatures, block-buffer, cmov, hybrid-array, crypto-bigint certified (2026-10-04)

Batch B6 of issue #339 (plan P6, "real unsafe/asm") ran under the "#322 supply-chain audit
policy", unchanged:
- built-in `safe-to-deploy` only;
- no claim of cryptographic correctness or constant-time behaviour;
- `who = "Ajit Koti <ajitkoti@zer07labs.com>"`;
- reviewed with Claude (Opus) assistance;
- maintainer approval required before merge.

| Crate | Version | Method | `unsafe` / `asm!` | Worksheet |
|---|---|---|---|---|
| `cpufeatures` | 0.3.1 | full; all 589 src lines read; Discretion line (`322-cpufeatures`) | 11 / 1 | `supply-chain/worksheets/cpufeatures-0.3.1.md` |
| `block-buffer` | 0.12.1 | full; all 756 src lines read | 21 / 0 | `supply-chain/worksheets/block-buffer-0.12.1.md` |
| `cmov` | 0.5.4 | full; all 1,702 src lines read | 25 / 7 | `supply-chain/worksheets/cmov-0.5.4.md` |
| `hybrid-array` | 0.4.14 | full; non-table src read, 552-entry size table script-checked; CI-files discretion | 37 / 0 | `supply-chain/worksheets/hybrid-array-0.4.14.md` |
| `crypto-bigint` | 0.7.5 | full; 37,233 compiled lines (150 files) read in full by seven Claude sub-reviews, with `unsafe` sites and file/line counts confirmed by the main review; 8,702 uncompiled lines (44 files) grep-only | 14 (13 compiled) / 0 | `supply-chain/worksheets/crypto-bigint-0.7.5.md` |

**Soundness of the `unsafe` and `asm!` sites.**
- Each worksheet gives every `unsafe` and `asm!` site a written invariant and verdict. All
  are sound as written.
- `cmov`'s `asm!` operand and option declarations (`nomem`, `nostack`, `pure`, the flags
  clobber, register widths) were checked against each instruction.
- `cmov`'s `NonZero`/`Ordering` writes:
  - Their soundness rests on the ISA rule that `CMOVcc`/`CSEL` leave one of their two
    operands, together with the fact that each element's final value is a whole element of
    one operand.
  - The remainder path's `word_to_slice` (`src/slice.rs:399-403`) briefly stores 0 through
    the integer view. That is not UB, because nothing reads the element at the `NonZero`
    type in between.
- Constant-time behaviour and branch-freedom are **not** claimed.

**Per-artifact backends.**

| Build | `cmov` | `cpufeatures` |
|---|---|---|
| x86_64 | x86 `asm!` | CPUID path |
| aarch64 | aarch64 `asm!` | `sysctlbyname` / `AT_HWCAP` paths |
| wasm32 binding | pure-Rust soft path | not compiled |

`crypto-bigint` compiles the same file set on the host and on wasm32 (from rustc dep-info).

**Observations (not vet concerns).**
- BB-1: block-buffer's `Clone` `SAFETY` comment is stale.
- CB-R1: crypto-bigint `floor_root_vartime` panics for large exponents. This is safe code,
  and nothing in ACDP's graph calls it.
- CF-2: cpufeatures panics on Apple if a `hw.optional.*` node is missing.

**Guard list.**
- The five crates were added under `# Batch B6:` with no marker.
- The list now guards 44 crates: 11 Tier A plus 33 Tier B.
- 43 of them are covered by our own audits. `zeroize` is again the sole deliberate exception
  (`322-zeroize`).
- All three binding lockfiles lock the same five versions and checksums as the root.

**Remaining Tier B:** 2 crates (35 minus the 33 certified in B1-B6): `getrandom` (0.2.17,
0.3.4, 0.4.3) and `rustls-webpki`, both batch B7.

**Status:** AUTHORED. Pending the maintainer's approving review naming the worksheets read
(Policy 4); never auto-merged.

## #339 322-getrandom: getrandom 0.4.3 / 0.3.4 linux_raw findings, certified with Discretion lines (2026-10-05)

Concern-rule entry for issue #339, batch B7a (plan decision C2). Anchor: `322-getrandom`. The
worksheets are `supply-chain/worksheets/getrandom-0.4.3.md` (findings GR4-1, GR4-2) and
`supply-chain/worksheets/getrandom-0.3.4.md` (GR3-1, GR3-2). Labels: LR-1 = GR4-1 = GR3-1;
LR-2 = GR4-2 = GR3-2.
- getrandom 0.4.3 is a direct dependency of `acdp-crypto`, which uses it for key
  generation (`crates/acdp-crypto/src/sign.rs:56`, `:143`).
- 0.3.4 is a dev-only dependency (proptest -> rand 0.9 -> rand_core 0.9).
- 0.2.17 has no `linux_raw` backend, so it has no finding of this kind.

**Findings.** Both findings are in the opt-in `linux_raw` backend and date from its
introduction (upstream #572, 0.3.0).

How the backend is selected:
- It is selected only by the final binary's builder, via
  `--cfg getrandom_backend="linux_raw"` (0.4.3 `src/backends.rs:17-19`; 0.3.4 `:18-21`).
- No Cargo feature enables it.
- A library's cfg does not propagate to its dependents (getrandom README, "Opt-in
  backends").
- The default ladder selects it only for `target_env = ""` (0.4.3 `:38-40`; 0.3.4
  `:50-53`), and that is never an ACDP target.

No artifact ACDP builds or tests compiles the file. The rustc dep-info for each target:

| Target | Backend compiled |
|---|---|
| linux-gnu | `linux_android_with_fallback` + `use_file` |
| darwin | `getentropy` |
| windows | `windows` |
| wasm32 | `wasm_js` |

The two findings:

- **LR-1 (loongarch64).** The `syscall 0` block declares no clobbers (0.4.3
  `linux_raw.rs:61-75`; 0.3.4 `:50-60`). The kernel clobbers `$t0`-`$t8`:
  - `handle_syscall` (`arch/loongarch/kernel/entry.S:22-81`) overwrites t0-t2 before it saves
    anything, and never runs `SAVE_TEMP`.
  - `RESTORE_ALL_AND_RET` then reloads t0-t8 from `pt_regs` slots that this path never filled
    (`asm/stackframe.h:216-226`, `:269-274`).
  - glibc (`__SYSCALL_CLOBBERS`) and musl (`SYSCALL_CLOBBERLIST`) both list `$t0`-`$t8` as
    clobbered.

  This is UB whenever a live value sits in a t-register across the block. Sampled release
  codegen keeps every live value in a-registers, so no miscompile was observed. rustix has no
  loongarch64 `linux_raw` arch. Affected targets: `loongarch64-unknown-linux-{gnu,musl}`
  (tier 2, stable).
- **LR-2 (x32; aarch64 ILP32).** On these ABIs the x86_64 and aarch64 arms pass 32-bit `buf`
  and `buflen` in 64-bit input registers, and the asm! rules leave the upper bits undefined.
  - `sys_getrandom` is a common 64-bit entry that reads the full `len` with no length cap.
  - So garbage upper bits in `rsi` can make the kernel write past the buffer before
    `fill_inner` checks the length.
  - Sampled x32 codegen passes the caller's incoming `%rdi`/`%rsi` to the first syscall
    without zero-extending them.
  - rustix refuses both x32 and ILP32.

  Affected targets: `x86_64-unknown-linux-gnux32` (tier 2, stable). aarch64 ILP32 is tier 3.
- Neither finding can be steered by an attacker: the syscall inputs are the program's own
  `buf`/`len`/`flags`.
- **Observation, not a finding.** On LP64 the `u32` syscall number and flags sit in 64-bit
  registers. This is harmless:
  - x86_64 and aarch64 discard the upper bits, and `flags` is `unsigned int`.
  - loongarch64, riscv64 and s390x range-check the full register, so garbage would give
    `-ENOSYS`, which becomes an `Err`.

**Why the existing carve-out does not fit.** The Policy 6 carve-out applies to code
"unreachable in any stable-toolchain build of any ACDP artifact". The `322-sha2` precedent met
that because its code needed nightly. Here, a crates.io consumer on loongarch64 with stable rustc
who sets the cfg does compile LR-1 into a binary that contains `acdp`. Calling the code
unreachable would therefore overclaim.

**Options.**
1. Certify, calling the code unreachable. Rejected: it overclaims.
2. Keep 0.4.3 exempt, with the marker `allow-exempt:DECISIONS#322-getrandom@0.4.3`, and
   certify 0.3.4 (dev-only, so it is in no artifact) and 0.2.17.
   - Feasible: only one version stays exempt, so G4's replan stop is not triggered.
   - But an exemption records a finished audit, and a known bug, as merely "unaudited".
3. Pin back. Not viable: `acdp-crypto` needs getrandom 0.4 `SysRng`, which 0.2.17 does not
   have.
4. *(chosen)* Certify 0.4.3 and 0.3.4 at `safe-to-deploy` (full audit). 0.4.3 needs an explicit
   second limb of the carve-out. 0.3.4 is dev-only and in no ACDP artifact, so the original
   carve-out already covers GR3-1/GR3-2; its notes cite this entry only for consistency. For
   both:
   - add one `Discretion:` line per finding, stating the real reachability;
   - report both findings upstream;
   - document in `docs/supply-chain.md` that a builder's `--cfg getrandom_backend` override
     is outside ACDP's audits.

**Decision (Fable, after independently verifying the kernel, libc, rustix, Rust-reference and
codegen facts, 2026-10-05): option 4.** The reasons:
- `safe-to-deploy` asks that an attacker cannot manipulate the code's runtime behaviour, and
  says the crate need not be bug-free. That claim holds even for a builder who opts in.
- The knob is a whole-build setting that only the final builder can choose. Upstream warns
  against it, and it matters only on targets ACDP neither builds nor tests.
- A certification that discloses the findings tells importers more than an exemption does.
  `imports.lock` carries the notes to them.
- The decision is consistent with two precedents: `322-sha2` (no Cargo feature reaches the
  code) and `322-cpufeatures` (a hazard no attacker can steer).

**Policy 6 carve-out, second limb (proposed 2026-10-05 by this decision; needs the
maintainer's explicit acknowledgement at PR review under Policy 4).** The concern rule also does
not apply when the unsound code meets all four conditions:
- (a) it is selected only by a whole-build knob that the final binary's builder must set
  explicitly (`--cfg` or RUSTFLAGS). A Cargo feature never qualifies, because a dependency can
  turn one on through feature unification;
- (b) none of the artifacts ACDP builds or tests compiles it;
- (c) untrusted input cannot steer it;
- (d) it has been reported upstream, or a report has been drafted and is held for the
  maintainer.

Such code is certified with one `Discretion:` line per finding. The line names the knob, the
targets, the hazard, the observed codegen and the upstream status. The exit criterion is a delta
audit of the fix. Code that is selected by default on any stable tier-1/2 target is still a
concern.

**Fallback if the maintainer declines the limb:** option 2. That means removing the 0.4.3 audit
entry, restoring its exemption with `notes = "KEPT EXEMPT (#322): linux_raw LR-1/LR-2; see
DECISIONS.md '322-getrandom'"`, and marking the guard line `getrandom
allow-exempt:DECISIONS#322-getrandom@0.4.3`. 0.3.4 stays certified, because it is in no ACDP
artifact and the original carve-out already covers it. No replan and no guard-script change
is needed (only the list line gains the marker). The text that would then be wrong must also be
reverted:
- the 0.4.3 worksheet Verdict;
- the B7a entry's table and guard-list text below (44 audited becomes 43, with two exceptions);
- in `docs/supply-chain.md`, the getrandom table row, the getrandom paragraph, the "Forty-four
  of the forty-five" sentence in §The crypto-critical set, and the §Contributor workflow
  "every crate except `zeroize`" counts.

**Other `Discretion:` lines in this batch use the original carve-out.** They cover code that
needs nightly, a tier-3 target, or a compiler older than ACDP's MSRV:
- the `extern_impl` backend (0.4.3 GR4-3; nightly `extern_item_impls`), where a safe user
  function can make `fill_uninit` expose uninitialized bytes;
- the ESP-IDF FFI declaration (`-> u32` for a C `void` function): 0.4.3 GR4-4, 0.3.4 GR3-3,
  0.2.17 GR2-1.

**Target state once G1-G4 of batch B7a land (G1 delivers the 0.4.3 parts):**
- `[[audits.getrandom]]` has full `safe-to-deploy` entries for 0.4.3 and 0.3.4 that carry the
  `Discretion:` lines. Their notes add "Not claimed: soundness of the opt-in linux_raw backend
  on loongarch64 or on 32-bit-pointer x86_64/aarch64 ABIs".
- 0.2.17 is certified on its own clean audit, apart from GR2-1.
- All three `[[exemptions.getrandom]]` entries are removed.
- `scripts/crypto-critical.txt` lists `getrandom` with no marker.

**Upstream.** Nothing has been filed. As of 2026-10-05, master's `linux_raw.rs` is identical to
0.4.3, and no upstream issue or PR covers either finding. The report draft (both findings in one
issue, plus the LP64 nit) is in the 0.4.3 worksheet. It is held until the maintainer approves
filing it under the project's name.

**Exit criterion:** delta-audit the getrandom release that fixes LR-1 and LR-2 (or that gates
the x32/ILP32 arms with `compile_error!`), and drop these `Discretion:` lines then.

**Status:** DECIDED (Fable, 2026-10-05). The Policy 6 second limb and the upstream filing await
the maintainer's acknowledgement at PR review.

## #339 Tier B batch B7a: getrandom 0.2.17, 0.3.4, 0.4.3 certified (2026-10-05)

Batch B7a of issue #339 (plan `plans/b7-webpki-getrandom.md`, PR-G) ran under the "#322
supply-chain audit policy". Its terms:
- built-in `safe-to-deploy` only;
- no claim of cryptographic correctness, constant-time behaviour or RNG output quality;
- `who = "Ajit Koti <ajitkoti@zer07labs.com>"`;
- reviewed with Claude (Opus) assistance;
- the maintainer must approve before merge.

The `linux_raw` decision (C2) went to a Claude (Fable) decision review; see `322-getrandom`.

| Crate | Version | Method | `unsafe` code lines / `asm!` blocks | Worksheet |
|---|---|---|---|---|
| `getrandom` | 0.4.3 | full; all 2,582 src lines (35 files) read in two Claude sub-review partitions, with every `unsafe` site, `unsafe fn` and `asm!` block verdicted by the main review; four Discretion lines (GR4-1/GR4-2 `linux_raw`, `322-getrandom`; GR4-3 nightly `extern_impl`; GR4-4 tier-3 esp-idf) | 109 / 9 | `supply-chain/worksheets/getrandom-0.4.3.md` |
| `getrandom` | 0.2.17 | full; all 1,739 src lines (24 files) read the same way; one Discretion line (GR2-1 tier-3 esp-idf) | 56 / 0 | `supply-chain/worksheets/getrandom-0.2.17.md` |
| `getrandom` | 0.3.4 | full; all 2,445 src lines (31 files) read the same way; certified at `safe-to-deploy` although its exemption was `safe-to-run` (dev-only; the `rand_core` 0.9.5 B4 precedent); three Discretion lines (GR3-1/GR3-2 `linux_raw`, GR3-3 tier-3 esp-idf); `build.rs` `rustc -vV` spawn judged to be cfg selection | 92 / 9 | `supply-chain/worksheets/getrandom-0.3.4.md` |

**Method evidence common to all three versions.**
- Compiled sets come from rustc dep-info, per target and per backend/feature, with the
  scratch crate depending on the exact version.
- A tarball copy was built as a path dependency with `unsafe_op_in_unsafe_fn` set to `deny`:
  - 0.4.3 builds clean on every combination that builds at all.
  - 0.2.17 and 0.3.4 fail by design, since they use editions 2018 and 2021. Every hit maps to
    a site-table row.
- Fill tests (lengths 0..=4096, a 1 MiB + 7 buffer, 16 concurrent first-use threads) ran:
  - natively;
  - under Miri on darwin, linux-gnu and windows-msvc;
  - in Docker on aarch64 Linux (for 0.4.3 and 0.3.4 also with the forced `/dev/urandom`
    fallback; for 0.2.17 also with the syscall-only `linux_disable_fallback`);
  - for 0.4.3 and 0.2.17, on wasm32 under Node.

**Per-artifact backends** (from dep-info):

| Build | 0.4.3 (`sys_rng`; `wasm_js` on wasm) | 0.2.17 (via ring) | 0.3.4 (dev-only) |
|---|---|---|---|
| linux-gnu | libc `getrandom` via `dlsym`, `/dev/urandom` after polling `/dev/random` | getrandom(2) syscall, same file fallback | same as 0.4.3 |
| apple-darwin | `getentropy` | `getentropy` | `getentropy` |
| windows-msvc | `ProcessPrng` (result checked) | `BCryptGenRandom`, `RtlGenRandom` fallback | `ProcessPrng` (result only debug-asserted, GR3-O1) |
| wasm32 binding | Web Crypto `getRandomValues` | `js.rs`, compiled but never called (#363) | not built |

**Observations (not vet concerns).**
- GR2-O1: `bindings/acdp-wasm` carries a vestigial getrandom 0.2 dependency, and the comments
  in `bindings/acdp-wasm/Cargo.toml:52-57` and `.github/dependabot.yml:75-80` are stale.
  Follow-up: #363. The audit PR changes no code.
- GR3-O1: in 0.3.4, `ProcessPrng`'s return value is checked only by `debug_assert!`. 0.4.3
  checks it.
- GR4-O3 / GR3-O3: `wasi_p2_3` / `wasi_p2` rely on std's runtime `align_to` returning a prefix
  and suffix shorter than 8. This is the default on `wasm32-wasip2`, which is not an ACDP
  target.
- In both newer versions: a dead `__msan_unpoison` declaration, and a debug-only futex
  `debug_assert` that can trip on `EINTR`.

**Guard list.**
- `getrandom` was added under `# Batch B7:` with no marker. It covers every locked version
  (0.2.17, 0.3.4, 0.4.3).
- The list now guards 45 crates: 11 Tier A and 34 Tier B.
- 44 of them are covered by our own audits. `zeroize` is again the sole deliberate exception
  (`322-zeroize`).
- The py, node and wasm binding lockfiles lock 0.2.17 and 0.4.3 with the root's checksums;
  0.3.4 appears only in the root lock.

**Remaining Tier B:** 1 crate (35 minus the 34 certified in B1-B7a), `rustls-webpki`, which is
the rest of batch B7.

**Maintainer items for this PR:**
- the proposed Policy 6 second limb (`322-getrandom`), with its fallback;
- whether to file the drafted upstream `linux_raw` report;
- plan Q4: how a self-authored PR's approval is evidenced.

**Status:** AUTHORED. Pending the maintainer's approving review naming the worksheets read
(Policy 4); never auto-merged.

## #339 322-rustls-webpki: rustls-webpki 0.103.15 certified safe-to-deploy (full), W-O8 recorded as an observation (2026-10-05)

Critical decision C1 of plan `plans/b7-webpki-getrandom.md` (W2), issue #339, batch B7b.
Anchor: `322-rustls-webpki`. The worksheet is
`supply-chain/worksheets/rustls-webpki-0.103.15.md`. An independent Claude (Opus) verifier
checked it and gave PASS after three rounds.

**Why this went to a Claude (Fable) decision review.** `rustls-webpki` decides whether every
ACDP HTTPS peer (a `did:web` host, a registry, a `data_ref` origin) is who it claims to be. It
does this through `rustls` 0.23.45's `WebPkiServerVerifier` under `reqwest`. Guarding it as
"audited" would signal more than the vet criterion delivers unless the notes scope the claim.

**Evidence (worksheet `file:line`).**
- `unsafe` 0, no `asm!`, no FFI, no `build.rs`, no proc-macro (l.175-178). The decision
  reviewer confirmed this with its own grep.
- Every line of all 19 `src/` files was read, 10,040 lines; the six partition totals sum to
  10,040 (l.54-66). The compiled set (17 files, 5,880 non-test lines) comes from rustc
  dep-info, not only from reading `cfg`s (l.100-104).
- There are 25 panic-macro sites, each with a reachability argument. None is reachable from a
  server-presented chain, from CRL bytes or from a caller-supplied name (l.220-246, l.295-296).
- The RUSTSEC-2023-0053 budget is present and fatal (l.270-280):
  - `Budget` is at `verify_cert.rs:292-345` and is consumed at `:126`, before every recursive
    descent.
  - `error.rs:357-375` maps exhaustion to `ControlFlow::Break`.
  - Recursion depth is capped at 6 sub-CAs, so at most 7 frames (`:847`, `:802-805`; l.266-269).
- All five advisories (2023-0053, 2026-0049, -0098, -0099, -0104) are mapped to the code that
  carries each fix (l.341-347). `cargo deny check advisories` was clean on 2026-10-05 (l.184).
- CRL parsing and revocation checking are compiled but never reached (l.298-337). None of
  ACDP's five `Client::builder` sites configures CRLs, so rustls passes `revocation = None`.
  The code was still read in full and is panic-free.
- Upstream test suite at tag `v/0.103.15` with ACDP's features: 398 passed, 0 failed, and
  both BetterTLS suites passed (l.108-113). 10,000,000 mutation iterations produced 0 panics
  (l.114-139).
- **W-O8.** Path building re-parses every peer-supplied intermediate on each budgeted call
  (`verify_cert.rs:108`), and that parsing is outside the budget.
  - The cost is bounded by about 200,000 x the bytes of intermediates, and rustls caps the
    Certificate message at 64 KiB (`rustls-0.23.45/src/msgs/deframer/handshake.rs:376`).
  - Measured: 0.5-1 s of CPU per malicious handshake, worst 758 ms. Plain degenerate chains
    stop within 66 ms (l.140-168, l.281-286, l.400-406).
  - It is still present on upstream `main` (`verify_cert.rs:149-150`, 2026-10-05), and no
    upstream issue tracks it.
- Concerns under Policy 6: none (l.411-422). The worksheet recommends option 1 (l.424-437).

**Options.**
1. *(chosen)* Certify `safe-to-deploy`, full audit of 0.103.15. A `Not claimed:` line in the
   notes excludes path-validation, name-constraint and revocation correctness.
2. Certify with a `Discretion:` line for W-O8 and an upstream report.
3. Keep exempt under the concern rule with `allow-exempt:DECISIONS#322-rustls-webpki@0.103.15`.

**Decision: option 1.** Claude (Fable) took it on 2026-10-05, after checking for itself the
budget, the fatal-error mapping, the depth cap, the rustls message cap and upstream `main`.
The reasons:
- **The flip criteria are not met.** They were: a panic or unbounded work reachable from a
  server-presented chain; an open RUSTSEC on 0.103.15; a review that could not be finished.
  W-O8 is bounded on both axes (200,000 calls x a 64 KiB message). Its ceiling is seconds of
  CPU on slow hardware, not unbounded, and the measured 758 ms sits well inside it.
- **W-O8 is not a concern-rule trigger.** The rule lists: `unsafe`; unexpected net/fs/process
  access; a build.rs or proc-macro beyond cfg; obfuscated or binary content; a RUSTSEC hit; an
  unfinishable review. A deliberate CPU budget is none of these. Option 3 is therefore not
  available on this evidence, and using the marker without a trigger would misuse the Policy 7
  semantics.
- **W-O8 does not get a `Discretion:` line.** In this repo a `Discretion:` line records a
  defect or hazard that the reviewer chose to certify past: `der` D-1/D-2 (non-termination),
  `cpufeatures` CF-1, `getrandom` LR-1/LR-2, and the test-only I/O in `webpki-roots`. W-O8 is
  upstream's deliberate, tested design. The 200,000-call limit is copied from mozilla::pkix
  (`verify_cert.rs:336-338`) and pinned by `test_too_many_path_calls` (`:981`), and it is the
  RUSTSEC-2023-0053 fix itself. A `Discretion:` line would tell importers that something is
  being overlooked when nothing is. So it is recorded as an `Observations:` line with the
  measured cost, as wnaf W-1 and cpufeatures CF-2 were.
- **Rule for later reviews.** `Discretion:` is for a defect, a hazard, or an item in a concern-rule
  category (such as test-only binary fixtures or packaged scripts) that is certified past, with
  its reachability or harmlessness argument. `Observations:` is for a non-defect property that importers should
  know, including a bounded DoS cost.
- **The scoping does not over-claim.** `docs/supply-chain.md` already defines what
  `safe-to-deploy` claims here and carries the certificate-validation carve-out for `rustls`;
  W4 extends it to `rustls-webpki`. The two crates at the same boundary were certified with
  the same scoping: `rustls` 0.23.45 and `webpki-roots` 1.0.9 both say "Not claimed:
  certificate-validation correctness", and `webpki-roots` adds a "This is a trust boundary"
  sentence. The rustls-webpki notes carry both.
- **An exemption would understate a finished audit.** It would record a full 10,040-line read,
  a 10M-iteration mutation loop and a worst-case timing study as "unaudited", as `322-getrandom`
  already noted. `imports.lock` carries certified notes, including W-O8, to importers; an
  exemption carries nothing.

**Upstream.** Nothing was filed.
- W-O8 is a performance-hardening suggestion (parse the intermediates once per
  `build_chain`), not a vulnerability. Filing it as a plain enhancement issue under the
  project's name, after the PR merges so the worksheet link exists, is recommended but
  optional. It is not a condition of this certification.
- W-O1 is already fixed on upstream `main`.
- W-O2 (keyCertSign enforcement) landed on `main` in 2026-06. It is validation behaviour,
  which the audit does not claim.

**State after the decision (W3/W4):**
- An `[[audits.rustls-webpki]]` full `safe-to-deploy` audit of 0.103.15 is added. It has the
  worksheet's `Scope:` and `Not claimed:` wording, an `Observations:` line (W-O8, W-O1, W-O2),
  a `Role:` line that says "This is a trust boundary", and no `Discretion:` line.
- `[[exemptions.rustls-webpki]]` 0.103.15 is removed from `supply-chain/config.toml`.
- `scripts/crypto-critical.txt` lists `rustls-webpki` under `# Batch B7:` with no marker.
- `docs/supply-chain.md`'s "What a `safe-to-deploy` audit here claims" paragraph extends the
  rustls carve-out to "(for rustls and rustls-webpki) TLS protocol and certificate-validation
  correctness".
- The worksheet's Verdict line changes from RECOMMENDED to CERTIFIED.

**Exit criterion and re-audit trigger.** Nothing pending upstream gates this certification.
The next `rustls-webpki` bump gets the normal Policy 2 audit. That review should:
- check whether intermediates are now parsed once per `build_chain`, and drop the W-O8
  observation if so;
- note whether issuer keyCertSign enforcement (W-O2) landed, since that changes validation
  behaviour on the trust boundary.

A new RUSTSEC entry against 0.103.15 reopens the audit; the `cargo deny` CI gate catches it.

**Status:** DECIDED (Fable, 2026-10-05).

## #339 Tier B batch B7b: rustls-webpki 0.103.15 certified (2026-10-05)

Batch B7b of issue #339 (plan `plans/b7-webpki-getrandom.md`, PR-W, #364) ran under the
"#322 supply-chain audit policy". Its terms:
- built-in `safe-to-deploy` only;
- no claim of cryptographic correctness, constant-time behaviour or side-channel resistance,
  and none of certificate path-validation, name-constraint or revocation correctness;
- `who = "Ajit Koti <ajitkoti@zer07labs.com>"`;
- reviewed with Claude (Opus) assistance;
- the maintainer must approve before merge.

The certify-or-keep-exempt call (C1) went to a Claude (Fable) decision review; see
`322-rustls-webpki`.

| Crate | Version | Method | `unsafe` code lines / `asm!` blocks | Worksheet |
|---|---|---|---|---|
| `rustls-webpki` | 0.103.15 | full; all 10,040 src lines (19 files) read in six Claude sub-review partitions, cross-checked by the main review; no `Discretion:` line; W-O8 recorded as an observation (`322-rustls-webpki`) | 0 / 0 | `supply-chain/worksheets/rustls-webpki-0.103.15.md` |

**Method evidence.**
- The compiled set comes from rustc dep-info: 17 files, with `aws_lc_rs_algs.rs` and
  `alg_tests.rs` not compiled.
- The upstream suite at tag `v/0.103.15` passed with ACDP's features: 398 tests, 0 failures,
  plus both BetterTLS suites.
- A 10M-iteration random and semi-structured DER loop produced 0 panics. It exercised
  `EndEntityCert`, `verify_for_usage` (with and without CRLs), name checks, CRL parsing and
  trust anchors.
- Worst-case path-building timing was measured with degenerate chains and with chains padded
  with fillers.
- The five `rustls-webpki` advisories were each mapped to the code carrying the fix.

**Observations (not vet concerns).**
- W-O8: bounded but material DoS cost, about 0.5-1 s of CPU per malicious handshake (worst
  758 ms), from unbudgeted re-parsing of intermediates. Upstream `main` still does this.
- W-O1: the OID display decoder is wrong (fixed upstream).
- W-O2: issuer keyUsage is not enforced in this version (upstream `main` adds keyCertSign).
- CRL parsing and revocation checking are compiled but unreached. No ACDP HTTPS client
  configures CRLs.

**Guard list.**
- `rustls-webpki` was added under `# Batch B7:` with no marker.
- The list now guards 46 crates: 11 Tier A and 35 Tier B.
- 45 of them are covered by our own audits. `zeroize` is the sole deliberate exception
  (`322-zeroize`).
- The py and node binding lockfiles lock 0.103.15 with the root's checksum. The wasm binding
  does not contain it.

**Remaining Tier B:** none (35 of 35 certified in B1-B7b).

**Status:** AUTHORED. The maintainer approves this PR by merging it by hand after reading the
worksheet, and a PR comment names the worksheet the verifier covered (plan Q4; the precedent
is #362). Never auto-merged.

## #339 completion status (2026-10-05)

Closing entry for issue #339, which certifies the 35 supporting crypto crates (Tier B) that
#322 left exempted. The batches were B1 (#355), B2 (#356), B3 (#357), B4 (#358), B5 (#360),
B6 (#359), B7a (#362) and B7b (#364). Policy: DECISIONS.md "#322 supply-chain audit policy",
applied unchanged.

**Result.**
- All 35 Tier B crates are covered by our own `safe-to-deploy` audits at every locked version.
  Each has a worksheet in `supply-chain/worksheets/` and is on the guard list.
- No Tier B crate is exempted.
- `scripts/crypto-critical.txt` guards 46 crates: 11 Tier A and 35 Tier B.
- 45 of the 46 pass as fully audited.

**Exceptions and discretion records.**
- **Kept exempt:** `zeroize` 1.9.0 (Tier A, `322-zeroize`). The pinned marker is
  `allow-exempt:DECISIONS#322-zeroize@1.9.0`, and the exit criterion is a delta audit of 1.9.1.
- **Certified with `Discretion:` lines:**
  - `cpufeatures` 0.3.1 (`322-cpufeatures`);
  - `getrandom` 0.4.3 and 0.3.4 (`322-getrandom`, the opt-in `linux_raw` backend), plus
    nightly/tier-3 backend discretion in 0.4.3, 0.3.4 and 0.2.17;
  - `der` 0.8.1 (D-1/D-2, unreachable recursion bugs);
  - test-fixture, generated-file, packaged-file or test-only-I/O discretion notes, all
    harmless and outside any non-test build: `ed25519`, `spki`, `hmac`, `pkcs8`, `sec1`,
    `digest`, `untrusted`, `tokio-rustls`, `typenum`, `webpki-roots`, `rustls-pki-types` and
    `hybrid-array` (Tier B), plus `ecdsa` and `p256` (Tier A);
  - and the Tier A `sha2` (`322-sha2`) and `curve25519-dalek` (nightly `docsrs` path) lines.
  - The full list is every `Discretion:` line in `supply-chain/audits.toml`.
- **Certified with a recorded observation instead of a discretion:** `rustls-webpki` 0.103.15
  (`322-rustls-webpki`, W-O8 bounded DoS cost).

**Follow-ups outside the audits.**
- #363: drop the vestigial getrandom 0.2 dependency in `acdp-wasm`.
- Optional: an upstream enhancement report for W-O8, to be filed only on the maintainer's
  go-ahead.
- The drafted `linux_raw` report (`322-getrandom`), also only on the maintainer's go-ahead.
- Plan Q4: whether to amend the Policy 4 wording to match how self-authored PRs are approved.

**Status:** AUTHORED with #364. Issue #339 closes when #364 merges.

## #322 322-policy4-approval: audit PR approval is the maintainer's manual merge plus a PR comment (2026-10-05)

Maintainer decision, dated 2026-10-05. Anchor: `322-policy4-approval`. It settles plan Q4 of
`plans/b7-webpki-getrandom.md`, listed as a follow-up in "#339 completion status".

**The gap.** Policy 4 of "#322 supply-chain audit policy" required an approving GitHub review
from the maintainer before an audit PR merged. The maintainer is also the PR author, and
GitHub does not let an author approve their own PR, so that review could never exist.

**Decision.** For an audit PR, the maintainer's approval is:
- their own manual merge of the PR, done by hand by the maintainer (an agent's merge,
  including one on a standing "merge all PRs when green" instruction, does not count); and
- a PR comment, posted by the maintainer, that names the worksheets they read.

No approving GitHub review is required. Audit PRs are still never auto-merged, and `/ship`
does not merge one at all: it stops on green CI and waits for the maintainer. Policy 4 now
carries this wording, marked as amended 2026-10-05. `docs/supply-chain.md` (step 8, "Get
sign-off") says the same.

**Other acknowledgements.** Text elsewhere that asks for the maintainer's acknowledgement
"at PR review" (for example the proposed Policy 6 second limb in `322-getrandom`, and the
matching `supply-chain/audits.toml` and worksheet lines) now means a PR comment from the
maintainer that states the acknowledgement, on the PR the maintainer merges. The second limb
still awaits that acknowledgement; this entry does not supply it.

**Not retroactive.** This changes the policy text from 2026-10-05 on. It does not rewrite
what happened before it:
- The audit PRs #355, #356, #357, #358, #359, #360, #362 and #364 were merged with 0 GitHub
  reviews.
- #355-#360 have no PR comment. #362 and #364 each have one comment, posted by the agent
  that merged them on the maintainer's standing instruction. Those comments name the
  worksheets the Claude (Opus) verifiers covered, not worksheets the maintainer read. So
  none of these PRs is recorded as meeting the amended rule.
- Dated records written under the old wording are left as written. Examples are the
  `**Status:**` lines above that say "Pending the maintainer's approving review" or "Merges
  only after the maintainer's approving review", the #339 batch B1 entry's "maintainer approving
  review before merge", and the "acknowledgement at PR review" lines. They record the
  policy text in force when each was authored.

**Status:** DECIDED (maintainer, 2026-10-05).
