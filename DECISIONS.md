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
`plans/issues-273-279-284-285-rfc0014-wave.md` and `plans/PROGRESS.md`. No code change
resulted from this entry (it's a release-process finding, not a code one) — noted here so
a future release isn't surprised by the same `action_required`/OIDC-flake/propagation-lag
shape if it recurs.
