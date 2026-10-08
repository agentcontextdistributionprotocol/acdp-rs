# Release runbook — binding tags & publishes

**Human-assisted.** This is a runbook, not automation: the manual steps here need
rights a CI session doesn't have (pushing tags, pausing/resuming workflows, PyPI/npm
publish credentials). Check the live state with the commands in
[Checking release state](#checking-release-state) before acting, since it can drift the
moment someone else runs a step.

## How releases are triggered

The three language-binding release workflows (`bindings-release.yml` for
`acdp-node`, `acdp-py-release.yml`, `acdp-wasm-release.yml`) run in two ways:

- **SDK cascade (default).** When the core `acdp` crate releases,
  `release-plz.yml`'s "Release SDK bindings at the acdp version" step dispatches
  all three via `workflow_dispatch -f dry_run=false`. Each workflow then pushes its
  own git tag (`acdp-py-v$VER` / `acdp-node-v$VER` / `acdp-wasm-v$VER`) in a "Tag the
  release" step after a successful publish. That step is gated on
  `github.event_name == 'workflow_dispatch' && !inputs.dry_run`, so it never fires on
  a tag push (the tag already exists) or on a dry run (nothing was published).
- **Tag push (manual).** Pushing a tag matching `acdp-node-v*` / `acdp-py-v*` /
  `acdp-wasm-v*` runs the full build-and-publish job unconditionally
  (`if: github.event_name == 'push' || !inputs.dry_run` — the `dry_run` input only
  guards a manual `workflow_dispatch`, never a tag push).

Behaviors to know before acting:

- **A manual non-dry-run dispatch needs `-f version=...`.** The "Tag the release"
  step fails the job on a blank `version` input. It runs *after* the publish, so a
  blank version publishes successfully and then turns the job red at the tag step.
- **A partial-failure recovery re-run skips the tag step.** "Tag the release" uses a
  plain `if:`, which implicitly requires `success()` on every earlier step, so an
  incomplete publish is never tagged as if it fully succeeded.
- **Consumer notification fires on both paths.** Each workflow sends
  `acdp-released` to its downstream consumer (see the
  [dispatch matrix](#release-dispatch-matrix)) after a successful publish, whether
  the run came from a tag push or from the cascade's `workflow_dispatch`.
- **Some older releases have no tag.** A few past versions were published by a
  manual `workflow_dispatch` before the workflows tagged automatically, so
  `git tag` can understate what is live on npm/PyPI — check the registries (see
  [Checking release state](#checking-release-state)).
- **Never push a tag for a version that is already published.** It refires the
  workflow and tries to republish that exact version; npm/PyPI reject it, so the run
  fails loudly (a red CI run, no data corruption). The failure sits before the
  consumer dispatch, so no spurious downstream bump PR is opened — but it still
  wastes a run. Use the [manual tag push](#manual-tag-push) procedure instead.

## Reproducibility of the `acdp-wasm` artifact

**For releases up to and including `acdp-wasm-v0.8.5`, the trust root is the SLSA
attestation, not byte reproduction.** Those published `.wasm` modules embed
runner-absolute paths (cargo registry sources for ~30 dependency crates, plus
rustc-sysroot standard-library paths), which cannot be removed retroactively. A
rebuild of any of `0.7.0` through `0.8.5` will **not** match npm, even on an
identical toolchain, and that mismatch is not evidence of tampering. Verify
provenance instead (see `docs/supply-chain.md` §1):

```bash
gh attestation verify acdp_wasm_bg.wasm --repo agentcontextdistributionprotocol/acdp-rs
```

**From `acdp-wasm-v0.14.0` on** (the first npm release after `0.8.5`),
`acdp-wasm-release.yml` composes a `RUSTFLAGS` that remaps the cargo registry root,
the workspace checkout, and the rustc sysroot to fixed, machine-independent
prefixes, and runs a determinism gate in-job (a second build into a distinct
`CARGO_TARGET_DIR`, `cmp`-checked against the first, failing the release on any
mismatch). That gate proves same-runner reproducibility; cross-runner reproduction
(your laptop vs. `ubuntu-latest`) additionally requires an identical
rustc/wasm-pack/wasm-bindgen/walrus toolchain — use the rustc pinned in
`acdp-wasm-release.yml`'s `dtolnay/rust-toolchain` step and the `wasm-pack` version
in `docs/supply-chain.md`'s pinned-tool inventory before comparing.

**A byte delta between two releases with no `.rs` change is expected and benign.**
Crate-version bumps alone perturb fat-LTO codegen: the version string embedded via
`CARGO_PKG_VERSION` changes symbol content, and whole-program optimization can
reshuffle codegen as a result. Before suspecting anything, check that the two
builds used the same tool versions; a small function/code-byte delta with identical
tools is this effect, not tool drift.

## Release dispatch matrix

Each release workflow notifies one downstream consumer with a
`repository_dispatch` of type `acdp-released`, carrying `{version, ecosystem}`:

| Workflow | Ecosystem | Dispatch target (`acdp-released`) | Source |
|---|---|---|---|
| `release-plz.yml` | cargo | `acdp-registry-rs` | `.github/workflows/release-plz.yml:121` |
| `acdp-py-release.yml` | uv | `acdp-playground` | `.github/workflows/acdp-py-release.yml:275` |
| `bindings-release.yml` | npm | `acdp-control-plane` | `.github/workflows/bindings-release.yml:309` |
| `acdp-wasm-release.yml` | npm | `acdp-ui-console` | `.github/workflows/acdp-wasm-release.yml:354` |

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
version that already published successfully. Bump to the next patch instead if a
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
