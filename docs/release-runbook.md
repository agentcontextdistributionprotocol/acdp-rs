# Release runbook — binding tags & publishes

**Human-assisted (RS-6).** This is a runbook, not automation: every step here needs
rights a CI session doesn't have (pushing tags, pausing/resuming workflows, PyPI/npm
publish credentials). No step in this document has been executed by an agent — verify
the "current state" section against `git tag`, `npm view`, and PyPI before acting, since
it can drift the moment someone else runs a step.

## Why this exists

The three language-binding release workflows (`bindings-release.yml` for
`acdp-node`, `acdp-py-release.yml`, `acdp-wasm-release.yml`) are **tag-triggered**:
pushing a tag matching `acdp-node-v*` / `acdp-py-v*` / `acdp-wasm-v*` runs the full
build-and-publish job unconditionally (`if: github.event_name == 'push' || !inputs.dry_run`
— the `dry_run` input only guards a manual `workflow_dispatch`, never a tag push). Some
past releases were published via manual `workflow_dispatch` **without** a corresponding
tag ever being pushed, so `git tag` now understates what's actually live on npm/PyPI.

**⚠ H11:** pushing a *retroactive* tag for a version that is already published will
refire the matching workflow and attempt to publish that exact version again — npm/PyPI
reject a republish of an existing version, so the run fails loudly (a red CI run, no
data corruption) rather than silently succeeding or overwriting anything. Loud-but-safe
is still not free: it wastes a CI run, pages whoever watches Actions, and (on the node
workflow specifically) sits *before* the `acdp-released` dispatch step to
`acdp-control-plane`, which only fires on the steps after a successful publish — so a
failed retroactive-tag run does **not** spuriously trigger a downstream auto-bump PR
there. Still, don't rely on "it'll just fail safely" as the plan — pick one of the three
options below deliberately.

## Reproducibility of the `acdp-wasm` artifact (#196c)

**For releases ≤ `acdp-wasm-v0.8.5`, the trust root is the SLSA attestation, not byte
reproduction.** Every one of those published `.wasm` modules embeds runner-absolute
paths — `/home/runner/.cargo/registry/src/index.crates.io-*/<crate>-<ver>/src/*.rs`
for ~30 dependency crates, plus rustc-sysroot standard-library paths — because no
`--remap-path-prefix` existed anywhere in this repo until this change. Those paths are
baked into the already-published bytes and cannot be removed retroactively, so
attempting to rebuild any of `0.7.0` through `0.8.5` on your own machine and diff the
result against npm **will not match**, even on an identical toolchain, and that
mismatch means nothing — it is not evidence of tampering. Do not attempt it. Instead,
verify provenance the way `docs/supply-chain.md` §1 already documents:

```bash
gh attestation verify acdp_wasm_bg.wasm --repo agentcontextdistributionprotocol/acdp-rs
```

**Cross-machine reproduction becomes possible only for releases built *after* this
change**, and even then only on a matching toolchain: `acdp-wasm-release.yml` now
composes a `RUSTFLAGS` that remaps the cargo registry root, the workspace checkout, and
the rustc sysroot to fixed, machine-independent prefixes, and runs a determinism gate
in-job (a second build into a distinct `CARGO_TARGET_DIR`, `cmp`-checked against the
first, failing the release on any mismatch). That gate proves same-runner
reproducibility on every release going forward; it does not by itself prove
cross-runner (e.g. your laptop vs. `ubuntu-latest`) reproducibility, which additionally
requires an identical rustc/wasm-pack/wasm-bindgen/walrus toolchain — pin `1.98.0`
(`acdp-wasm-release.yml`'s `dtolnay/rust-toolchain` step) and `wasm-pack@0.15.0`
(`docs/supply-chain.md`'s pinned-tool inventory) locally before comparing.

**A byte delta between two releases with no `.rs` change is expected and benign, not a
red flag.** Crate-version bumps alone perturb fat-LTO codegen — a version string
embedded in `Cargo.toml`/`CARGO_PKG_VERSION` changes symbol content even when no logic
changes, and LTO's whole-program optimization can reshuffle codegen decisions as a
result. The `+3 functions / +481 code bytes / data +0` signature observed between
`acdp-wasm v0.8.3` and `v0.8.5` is exactly that: both builds provably used identical
`wasm-pack 0.15.0`, `rustc 1.98.0 (88d9e12ae)`, `walrus 0.26.4`, and `wasm-bindgen
0.2.127` (see issue #196) — so issue #196's original "unpinned wasm-pack" diagnosis
for that delta was wrong; the real cause is fat-LTO codegen perturbation from a
version-string bump, not a tool-version drift. Don't re-open that diagnosis on a
future delta with the same shape; check the tool versions first, the way this
investigation eventually did.

## Automated tag-on-publish (as of 2026-08-30)

`release-plz.yml` has a "Release SDK bindings at the acdp version" step that dispatches
all three binding release workflows (`acdp-py-release.yml`, `bindings-release.yml`,
`acdp-wasm-release.yml`) via `workflow_dispatch -f dry_run=false` whenever the core
`acdp` crate itself releases — that's the SDK cascade referenced throughout this doc.

As of 2026-08-30, each of those three workflows now pushes its own matching git tag
(`acdp-py-v$VER` / `acdp-node-v$VER` / `acdp-wasm-v$VER`) automatically, in a "Tag the
release" step that runs immediately after a successful `workflow_dispatch`-triggered
publish (gated on `github.event_name == 'workflow_dispatch' && !inputs.dry_run`, so it
never fires on an actual tag push — the tag already exists in that case — or on a dry
run — nothing was published). This closes the root cause behind the "Why this exists"
section above: a `workflow_dispatch` publish can no longer land without a tag.

That same "Tag the release" step also fails the job if the `version` input was left
blank on a manual dispatch — deliberately, since a blank version can't be turned into a
sane tag name. This runs *after* the publish itself, so a manual non-dry-run dispatch
with a blank `version` will now publish successfully and then fail the job at the tag
step (a previously-green pattern that is red now). Always pass an explicit
`-f version=...` on a manual non-dry-run dispatch.

**This does not retire the manual tag-push instructions elsewhere in this document**
(Steps 1–2 below, and the RS-8 addendum's Steps further down). Those remain exactly what
you want for the **manual** release path — a human deliberately dispatching a workflow
or pushing a tag themselves outside the automated cascade, e.g. testing a binding
release before the core crate is ready to cut, or recovering from a failed automated
cascade. The automated tagging above is simply no longer the *only* path that produces
a correctly-tagged release; it's the path the SDK cascade takes by default.

One remaining scope limit on this automation, so this doc doesn't imply broader coverage
than what actually shipped (a second, related limit — described in earlier revisions of
this section as "consumer-bump notification stays manual-path-only" — was fixed as of
2026-09-25; see below):

- **Fixed 2026-09-25 — consumer-bump notification no longer manual-path-only.** Through
  2026-09-24, `acdp-py-release.yml` / `bindings-release.yml`'s consumer-notification
  dispatch steps were gated `if: github.event_name == 'push'`, so they fired only on an
  actual tag-push trigger, never on the automated `workflow_dispatch` cascade — meaning
  every release-plz-driven release silently skipped notifying `acdp-playground` and
  `acdp-control-plane` (a skipped step is green, so this went unnoticed for nine-plus
  releases; see issues #302 and #304). Both workflows now fire the dispatch on the
  `workflow_dispatch` path too — `acdp-py-release.yml`'s two notification steps lost
  their now-redundant per-step `if:` entirely (the job already carries an equivalent
  job-level gate); `bindings-release.yml`'s gained a wider predicate anchored on
  `steps.publish-root.outcome`, since that file has no job-level gate of its own. Full
  history, root-cause analysis, and the corrected design (including why the two files'
  fixes differ in shape) are in `plans/issues-302-304-release-dispatch-fix.md`.
- **A partial-failure recovery re-run correctly skips the tag step.** The "Tag the
  release" step uses a plain `if:` (carrying only its own gate above), which implicitly
  requires `success()` on everything before it in the job. If an earlier step in that
  publish job fails — including on a partial-failure recovery re-run — the tag step is
  skipped. This is intentional, not a bug: an incomplete publish should not get tagged
  as if it fully succeeded.

## Current state (verified 2026-08-29 — re-check before acting)

The sibling plan (`agentcontextdistributionprotocol/plans/siblings/acdp-rs.md`, RS-6)
was written 2026-08-28 and states PyPI is "still 0.7.0." That's now stale — live
PyPI/npm state as of this runbook is materially ahead of what the plan assumed:

| Artifact | Last **tagged** release | Published versions (npm/PyPI, ground truth) | Local manifest version |
|---|---|---|---|
| `acdp` crate (this repo) | `acdp-v0.8.1` | — | `0.8.1` (`Cargo.toml` workspace version) |
| `acdp-node` (npm `@agentcontextdistributionprotocol/acdp`) | `acdp-node-v0.7.0` | **0.7.0, 0.8.0, 0.8.1** — 0.8.0 and 0.8.1 both published tag-less via `workflow_dispatch` on 2026-07-10 (runs at commits `c2a89032` and `c4c9be8d`) | `0.8.0` (`bindings/acdp-node/package.json`, stale relative to what's already published) |
| `acdp-py` (PyPI `acdp`) | `acdp-py-v0.7.0` | **0.7.0, 0.8.0, 0.8.1** — 0.8.0 and 0.8.1 both published tag-less via `workflow_dispatch` on 2026-07-10, same two commits as node | `0.8.0` (`bindings/acdp-py/Cargo.toml`, stale) |
| `acdp-wasm` (npm `@agentcontextdistributionprotocol/acdp-wasm`) | `acdp-wasm-v0.7.0` | **0.7.0, 0.8.0** — the 0.8.0 `workflow_dispatch` at commit `be72ca24` succeeded; a same-day follow-up attempt at 0.8.1 (commit `c4c9be8d`, run `29129059112`) **failed** during `cargo metadata` on a `getrandom` version conflict (`acdp-wasm` required `getrandom ^0.4` with feature `js`, which only exists on `0.2.x`) — that bug was the dual-major `getrandom` pin mixup fixed later by PR #153 (commit `c55eacd`, 2026-08-28). **0.8.1 was never published for wasm** *(stale as of 2026-08-30 — a 0.8.1 retry did later succeed, tagged `acdp-wasm-v0.8.1`, and npm now holds `0.7.0` through `0.8.4`; see the manifest column and re-run `npm view`/`git tag` before trusting this cell)*. | `0.8.4` (`bindings/acdp-wasm/Cargo.toml`, bumped as of 2026-08-30 to match npm's actual latest published version, `0.8.4` — the bump is purely cosmetic per the workflow's re-stamp-at-build-time design and not itself a publish; see "Automated tag-on-publish" above) |

Per "Automated tag-on-publish" above, any future `workflow_dispatch` publish (manual or
via the automated cascade) now tags itself automatically; no human backfill should be
needed going forward for new releases.

Re-run these checks before executing anything below — another session or the bot may
have moved the state again:

```bash
git tag -l "acdp-node-v*" "acdp-py-v*" "acdp-wasm-v*" | sort -V
npm view @agentcontextdistributionprotocol/acdp versions --json
npm view @agentcontextdistributionprotocol/acdp-wasm versions --json
curl -s https://pypi.org/pypi/acdp/json | python3 -c "import json,sys; print(sorted(json.load(sys.stdin)['releases']))"
```

## The plan

Target: all three bindings published **and tagged** at the crate family version,
`0.8.1` — matching the accept criterion ("node/py/wasm published at the family version
with matching git tags"). Node and py content is already there (published, just
untagged); wasm genuinely needs one more publish.

### Step 0 — pause the tag-triggered workflows

Do this before pushing *any* tag in this runbook, retroactive or new — it's what makes
every following step safe regardless of which option below you pick for the retroactive
markers:

```bash
gh workflow disable bindings-release.yml
gh workflow disable acdp-py-release.yml
gh workflow disable acdp-wasm-release.yml
```

(`gh workflow enable <name>` reverses this — needed again at the end of Step 2.)

### Step 1 — retroactive markers for what's already published, tag-less

With the workflows paused, tags can be pushed safely — nothing will fire. Point each
tag at the exact commit that workflow run actually published from (not current `HEAD`),
so the tag is historically accurate:

```bash
git tag acdp-node-v0.8.0 c2a89032a5b706d95efd1e5e69e1f7df22aa6084
git tag acdp-node-v0.8.1 c4c9be8d68dda2842b6a9b06efc2157d79090198
git tag acdp-py-v0.8.0   c2a89032a5b706d95efd1e5e69e1f7df22aa6084
git tag acdp-py-v0.8.1   c4c9be8d68dda2842b6a9b06efc2157d79090198
git tag acdp-wasm-v0.8.0 be72ca24fe7d0246b1fe132ef10c0eaed7ecfc0b
git push origin acdp-node-v0.8.0 acdp-node-v0.8.1 acdp-py-v0.8.0 acdp-py-v0.8.1 acdp-wasm-v0.8.0
```

Do **not** tag `acdp-wasm-v0.8.1` here — it was never actually published (see the table
above), so tagging it would be a false historical record. It gets a real, live tag in
Step 2 instead.

This is "tag with workflows paused" (H11 option 1) rather than non-triggering tag names:
it keeps the permanent tag names consistent with the live ones future releases will use
(`acdp-node-v0.8.0`, not some `retroactive/…` variant that `git describe`/tooling won't
recognize), at the cost of the two-step pause/resume — a fine trade for a one-time
backfill.

### Step 2 — the real, live wasm 0.8.1 publish

This is the one artifact that genuinely isn't at the family version yet.

1. Confirm the `getrandom` fix from PR #153 is present on the commit you're releasing
   from (it is, as of `main` post-2026-08-28) — spot-check:
   ```bash
   grep -n "getrandom" bindings/acdp-wasm/Cargo.toml
   # expect: getrandom = { version = "0.2", features = ["js"] }
   #         getrandom_wasm = { package = "getrandom", version = "0.4", features = ["wasm_js"] }
   ```
2. Bumping `bindings/acdp-wasm/Cargo.toml`'s `version` ahead of a release is **optional,
   low-priority cleanup**, same as the equivalent node/py manifest bump in Step 3 below
   — the workflow re-stamps this from the tag name at build time regardless, so the
   committed value is never functionally required for a publish to succeed; it only
   keeps the working tree honest for a human reader. (As of 2026-08-30, the manifest
   already reads `0.8.4`, ahead of any version this Step 2 was originally written
   against — bump it again to whatever version you're actually releasing before
   dispatching, or skip it and let the workflow's re-stamp handle it.)
3. Re-enable just the wasm workflow and do a dry run first, to catch any other drift
   before spending a real publish attempt:
   ```bash
   gh workflow enable acdp-wasm-release.yml
   gh workflow run acdp-wasm-release.yml -f version=0.8.1 -f dry_run=true
   # watch it green, then:
   git tag acdp-wasm-v0.8.1 <the commit the dry run built from>
   git push origin acdp-wasm-v0.8.1
   ```
   The pushed tag triggers the real (non-dry-run) publish.
4. Re-enable the other two workflows now that no more retroactive tags are pending:
   ```bash
   gh workflow enable bindings-release.yml
   gh workflow enable acdp-py-release.yml
   ```

### Step 3 — local manifest hygiene (optional, low-risk cleanup)

`bindings/acdp-node/package.json` and `bindings/acdp-py/Cargo.toml` still declare
`0.8.0` locally even though `0.8.1` is already published — harmless (the release
workflows stamp the version from the tag at build time, not from the committed
manifest) but confusing to a reader. Bump both to `0.8.1` in a normal PR, no tag
implications either way.

### Step 4 — unblocks

Once this runbook's tags exist, per `00-overview.md` §3: `PG-1` (PyPI→family version,
already effectively true, just needed the tag) and `UI-1` (wasm bump + tagged release)
are unblocked, and `CI-3` (tag-triggered publish = propagation head) can record this as
the policy going forward.

## RS-8 binding follow-up release (`anchors`, RFC-ACDP-0016) — DONE (2026-08-30)

PR #175 merged to `main` as `510ca40` (2026-08-30). Both dry runs went green
(`acdp-py-release.yml`, `bindings-release.yml`, `-f version=0.8.3`), then real tags
`acdp-py-v0.8.3` and `acdp-node-v0.8.3` were pushed against `510ca40`. Both release
workflows completed successfully — `acdp` `0.8.3` is live on PyPI, and
`@agentcontextdistributionprotocol/acdp` `0.8.3` plus all four platform packages
(`acdp-darwin-arm64`, `acdp-darwin-x64`, `acdp-linux-x64-gnu`, `acdp-linux-arm64-gnu`)
are live on npm. Verified via real `pip install acdp==0.8.3` / `npm install
@agentcontextdistributionprotocol/acdp@0.8.3` installs plus an end-to-end
publish-request-with-`anchors` + `verify_content_hash` smoke test against each
installed package, not just the registry listing.

One transient hiccup, not a real failure: `acdp-linux-x64-gnu@0.8.3`'s versioned
registry endpoint 404'd for about a minute after the CI publish step reported success
(the CI log showed the correct `+ @agentcontextdistributionprotocol/acdp-linux-x64-gnu@0.8.3`
line) — the same npm read-replica propagation lag this runbook's own earlier section
already diagnosed for a different package. Resolved on its own; no republish needed.

`acdp-py`/`acdp-node` are now genuinely in lock-step at `0.8.3` (previously drifted,
`0.8.1`/`0.8.2` respectively — see the superseded "Current state" section below, kept
for historical context on the drift pattern rather than deleted).

### Current state (as of 2026-08-29, BEFORE the above — historical, do not use for a
future release; re-check `git tag` / the registries fresh each time)

| Artifact | Latest git tag | Actually live | Committed manifest |
|---|---|---|---|
| `acdp` (PyPI) | `acdp-py-v0.8.1` | **`0.8.2`** (verified via `pypi.org/pypi/acdp/json`) | `bindings/acdp-py/Cargo.toml`: `0.8.0` (stale either way — irrelevant to publish, see below) |
| `@agentcontextdistributionprotocol/acdp` (npm) | `acdp-node-v0.8.2` | `0.8.2` (verified via `registry.npmjs.org`) | `bindings/acdp-node/package.json`: `0.8.0` (same) |

The git tag for `acdp-py` understates reality by one patch version — a `0.8.2` was
published to PyPI without a matching tag ever being pushed, the exact pattern this
runbook's "Why this exists" section describes. This doesn't block anything below; it
just means the target version is computed from the **live registry**, not from `git
tag`.

Neither committed manifest (`Cargo.toml`/`package.json`) needs to change before
tagging — confirmed for both workflows, not assumed: `bindings-release.yml`'s and
`acdp-py-release.yml`'s "Stamp release version" steps both compute the published
version as `${{ inputs.version }}` (dispatch) or `${GITHUB_REF_NAME#acdp-*-v}` (tag
push), then overwrite the manifest file at build time — the committed value is never
read. Only the `CHANGELOG.md` entries need to already exist (they do — see the
`## Unreleased` sections in both `bindings/acdp-py/CHANGELOG.md` and
`bindings/acdp-node/CHANGELOG.md`).

### Target versions

Following the precedent set by RS-8's own core-crate release (`0.8.1` → `0.8.2`, a
**patch** bump for the same purely-additive, non-breaking `anchors` field): both
bindings go from their live `0.8.2` to **`0.8.3`**. This happens to restore py/node
lock-step (both currently live at `0.8.2`, matching for once) — a side effect, not a
guarantee this holds for the *next* release after this one.

### Steps

1. **Dry-run first, both workflows**, to catch a build break before it's irreversible:
   ```bash
   gh workflow run acdp-py-release.yml --ref feat/rs8-bindings-anchors -f dry_run=true -f version=0.8.3
   gh workflow run bindings-release.yml --ref feat/rs8-bindings-anchors -f dry_run=true -f version=0.8.3
   ```
   Wait for both to go green (`gh run watch <id> --exit-status` or `gh run list
   --workflow=<name> --limit 1`) before continuing. If either fails, fix and re-dry-run
   — do not proceed to a real tag push on a red dry run.
   Note: dispatch this against `feat/rs8-bindings-anchors` only until it merges to
   `main`; once merged, dispatch (and the real tag, below) should point at `main`.
2. **Push the real tags**, once merged to `main` and both dry runs are green:
   ```bash
   git tag -a acdp-py-v0.8.3 -m "acdp-py v0.8.3" <main-HEAD-sha>
   git tag -a acdp-node-v0.8.3 -m "acdp-node v0.8.3" <main-HEAD-sha>
   git push origin acdp-py-v0.8.3 acdp-node-v0.8.3
   ```
   Each push triggers its workflow for real (`if: github.event_name == 'push'` skips
   the `dry_run` gate entirely — a tag push always publishes).
3. **Verify live**, the same way the earlier 0.8.2 npm incident was diagnosed in this
   family's history — don't trust the packument/listing endpoint alone (it can lag);
   check the versioned endpoint directly:
   ```bash
   curl -s -H "User-Agent: acdp-rs-session (you@example.com)" https://pypi.org/pypi/acdp/0.8.3/json | head -c 200
   curl -s -H "User-Agent: acdp-rs-session (you@example.com)" https://registry.npmjs.org/@agentcontextdistributionprotocol/acdp/0.8.3
   ```
   For npm specifically, also confirm the 4 platform packages
   (`acdp-darwin-arm64`/`acdp-darwin-x64`/`acdp-linux-x64-gnu`/`acdp-linux-arm64-gnu`)
   published at `0.8.3` too, not just the root loader package — the `bindings-release.yml`
   `publish` job runs `napi pre-publish` (platform packages) and `npm publish` (root) as
   two separate steps; a partial success there is a known past failure mode for this
   pipeline (napi-cli 3.x's `--gh-release` default caused exactly this on the 0.8.2
   release — since fixed, but worth an explicit check here rather than assuming).
4. **H11 reminder**: if step 1's dry run or step 2's tag push needs a re-run for any
   reason, do NOT re-push a tag for a version that already published successfully —
   npm/PyPI reject the republish (harmless 403, per this family's own incident history)
   but it's a wasted, alarming red CI run. Bump to the next patch instead if a real
   do-over is needed.

## Coordination note for SPEC-11 (`docs/version-matrix.md` refresh, spec repo)

This is a **read**, not an edit — `docs/version-matrix.md` lives in the spec repo
(`agentcontextdistributionprotocol/agentcontextdistributionprotocol`), not here; per this
family's cross-repo convention, the spec-repo session doing SPEC-11 should pull the
following facts from this runbook rather than this repo editing that file directly:

- `acdp` (Rust, this repo): crate `0.8.1`, tags `acdp-v0.8.1` etc. — already current.
- `acdp-node` / `acdp-py` / `acdp-wasm`: once this runbook's Steps 1–2 are executed,
  all three sit at `0.8.1` with matching git tags (`acdp-node-v0.8.1`, `acdp-py-v0.8.1`,
  `acdp-wasm-v0.8.1`) and their published registries (npm, npm, PyPI respectively).
- The RFC coverage is identical across all four artifacts (RFC-ACDP-0001 through 0015,
  0009 reserved) — `acdp-wasm` is verification-only (no producer/signing surface), the
  other three implement both sides.
- If Step 2 hasn't run yet when SPEC-11 executes, say so explicitly in the version
  matrix rather than asserting `0.8.1` for wasm — check `npm view
  @agentcontextdistributionprotocol/acdp-wasm versions` first.
