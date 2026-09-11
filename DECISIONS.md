# DECISIONS

Reconciliation log for `plans/rs-wave1-conformance-hardening.md` (RS-1, RS-2, RS-10). Each
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

- **Plan:** plans/rs8-bindings-anchors.md
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

## 2026-09-06 — Phase 9 dispositions (plans/issues-196-199-215-216-followups.md)

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
