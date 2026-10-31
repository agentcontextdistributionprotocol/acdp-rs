# Deferred

Items seen but below the bar (bug, blocker, security issue, expensive design flaw, regression). One line each.

- 2026-10-30: ~50 open `chore(spec)` bot PRs (#418–#493) are superseded by main's 1560e0f spec pin; close them in a sweep.
- 2026-10-30: release-plz PR #497 only backfills 0.19.0 CHANGELOG headings for crates already published by #495; no CI ran on it; merge or close in a sweep.
- 2026-10-30: Dependabot PRs #409, #411, #413, #414, #415, #416 are red on cargo-vet (plus MSRV on #416 and bindings cargo-deny on #415); main's cargo-deny is green, so none fix an advisory.
- 2026-10-30: `semver-tool-health` / `cargo-semver-checks` are not required status checks (DECISIONS.md "NEEDS-CHANGE" item 3); repo-settings hardening.
- 2026-10-30: maturin pin in bindings (ASSUMPTIONS.md item 2, still UNCONFIRMED); bindings.yml is green on main.
