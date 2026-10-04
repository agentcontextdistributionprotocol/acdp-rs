# Release runbook — binding tags & publishes

**Human-assisted.** This is a runbook, not automation: the manual steps here need
rights a CI session doesn't have (pushing tags, pausing/resuming workflows, PyPI/npm
publish credentials). Check the live state with the commands in
[Checking release state](#checking-release-state) before acting, since it can drift the
moment someone else runs a step.

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
there. Still, don't rely on "it'll just fail safely" as the plan — use the
[manual tag push](#manual-tag-push) procedure below.

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

**This does not retire the [manual tag push](#manual-tag-push) procedure below.** It
remains exactly what you want for the **manual** release path — a human deliberately dispatching a workflow
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
  history and root-cause analysis are on issues #302 and #304.
- **Fixed 2026-09-27 — `acdp-wasm-release.yml` gained a consumer-bump notification too.**
  Unlike the two workflows above, `acdp-wasm-release.yml` never had a consumer-dispatch
  step at all (not merely mis-gated), so `acdp-ui-console` (the `acdp-wasm` npm consumer)
  had no automated bump path. It now fires `repository_dispatch: acdp-released` to
  `acdp-ui-console` on the same `steps.publish.outcome == 'success' && (push ||
  !inputs.dry_run)` shape as `bindings-release.yml`'s dispatch (#307, #308).
- **A partial-failure recovery re-run correctly skips the tag step.** The "Tag the
  release" step uses a plain `if:` (carrying only its own gate above), which implicitly
  requires `success()` on everything before it in the job. If an earlier step in that
  publish job fails — including on a partial-failure recovery re-run — the tag step is
  skipped. This is intentional, not a bug: an incomplete publish should not get tagged
  as if it fully succeeded.

## Release dispatch matrix

Each release workflow notifies one downstream consumer with a
`repository_dispatch` of type `acdp-released`, carrying `{version, ecosystem}`:

| Workflow | Ecosystem | Dispatch target (`acdp-released`) | Source |
|---|---|---|---|
| `release-plz.yml` | cargo | `acdp-registry-rs` | `.github/workflows/release-plz.yml:121` |
| `acdp-py-release.yml` | uv | `acdp-playground` | `.github/workflows/acdp-py-release.yml:277` |
| `bindings-release.yml` | npm | `acdp-control-plane` | `.github/workflows/bindings-release.yml:309` |
| `acdp-wasm-release.yml` | npm | `acdp-ui-console` | `.github/workflows/acdp-wasm-release.yml:354` (#308) |

`notify-website.yml` is separate: on a push to `main` that touches `docs/`,
`bindings/`, or `README.md`, it sends `docs-updated` to `acdp-website`. It is not part
of the release cascade.

The receiving side (`bump-consume.yml` in each consumer) is owned by `acdp-ci`; see
[`DELIVERY-STANDARD.md` → SDK propagation](https://github.com/agentcontextdistributionprotocol/acdp-ci/blob/main/DELIVERY-STANDARD.md#sdk-propagation-a-new-acdp-package--its-consumers).
Re-derive this table with `grep -n dispatches .github/workflows/*.yml`.

## Manual tag push

Pushing a binding tag (`acdp-node-v*` / `acdp-py-v*` / `acdp-wasm-v*`) runs the full
publish job. To push one without publishing (for example, a retroactive marker for a
version that is already live), pause the tag-triggered workflows first:

```bash
gh workflow disable bindings-release.yml
gh workflow disable acdp-py-release.yml
gh workflow disable acdp-wasm-release.yml
```

Point the tag at the exact commit the publish was built from, not current `HEAD`, then
push it and run `gh workflow enable <name>` for each workflow. Never re-push a tag for a
version that already published successfully (H11). Bump to the next patch instead if a
real do-over is needed.

## Checking release state

```bash
git tag -l "acdp-node-v*" "acdp-py-v*" "acdp-wasm-v*" | sort -V
npm view @agentcontextdistributionprotocol/acdp versions --json
npm view @agentcontextdistributionprotocol/acdp-wasm versions --json
curl -s https://pypi.org/pypi/acdp/json | python3 -c "import json,sys; print(sorted(json.load(sys.stdin)['releases']))"
```

Which SDK versions implement which protocol line is recorded in the spec's
[`docs/version-matrix.md`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/docs/version-matrix.md),
not here.

The 0.8.x-era release history (the 2026-08-29 state table, the 0.8.1 retroactive-tag plan, and the RS-8 0.8.3 binding release) was removed from this runbook on 2026-10-03; it remains in git history (`git show 115ce3d:docs/release-runbook.md`).
