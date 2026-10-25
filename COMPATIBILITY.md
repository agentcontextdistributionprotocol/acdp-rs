# Compatibility promise

This page says what a version number of the `acdp` crates promises, what
counts as a breaking change, and how one ships. CI enforces it (see
[How it is enforced](#how-it-is-enforced)).

Wire format and protocol semantics are owned by the ACDP specification and
its [`VERSIONING.md`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/VERSIONING.md),
not by this page. This page covers the Rust API.

## What is covered

- The public Rust API of every published library crate in this workspace:
  `acdp` and the `acdp-*` crates under `crates/`, at the paths they are
  documented under, including the historical `acdp::{types, crypto, did,
  client, registry, ...}` paths.
- Cargo features, their names, and what the default feature set contains.
- The minimum supported Rust version (MSRV), currently **1.87**.

Not covered:

- Items behind the `test-transport` feature, which is for test harnesses
  only and must never be enabled in production builds.
- Items marked `#[doc(hidden)]`.
- The `acdp` CLI's human-readable output.
- The language bindings (`bindings/`). They are versioned and released on
  their own.

## Version numbers

All crates are released in lockstep at one shared version. While the
crates are at `0.x`, versions follow Cargo's rules for `0.x`:

| Change | Release | Example |
|---|---|---|
| Breaking change (below) | next **minor** | `0.15.1` → `0.16.0` |
| New API, bug fix, security fix, dependency update | next **patch** | `0.15.1` → `0.15.2` |

So a dependency written as `acdp = "0.15"` (or `"~0.15.1"`) picks up every
compatible release and never a breaking one. Pinning with `=` is not needed
to stay safe.

`1.0` will follow the same rules one place to the left (breaking → major).

## What counts as breaking

A change is breaking if code that compiled and ran against the previous
release can stop compiling, or can start behaving differently in a way the
previous release's documentation did not allow. In particular:

- Anything `cargo-semver-checks` reports: removing or renaming a public
  item, changing a function signature, adding a field to a struct that
  callers can build, adding a variant to an enum that is not
  `#[non_exhaustive]`, and so on.
- **Auto traits.** A public type losing `Send`, `Sync`, `Unpin`,
  `UnwindSafe` or `RefUnwindSafe`.
- **Futures.** The future returned by a public `async fn` losing `Send`.
  Public types are `Send + Sync` (and `'static` when they have no lifetime
  parameter); public futures are `Send`. Futures borrow their arguments,
  so to spawn one, move owned or `Arc`-shared arguments into an
  `async move` block. Futures are not promised to be `Sync`.
  [`tests/auto_traits.rs`](tests/auto_traits.rs) lists what is checked.
- **MSRV.** Raising the minimum supported Rust version.
- **Features.** Removing or renaming a Cargo feature, or removing something
  from the default feature set.
- **Default wire version.** Changing which ACDP version builders emit by
  default (`ACDP_VERSION`).

Not breaking:

- Adding a variant to a `#[non_exhaustive]` enum (for example `AcdpError`),
  or a field to a `#[non_exhaustive]` struct.
- Adding new public items, new optional features, or new methods.
- **Security fixes** that make verification stricter, even if something
  that was accepted before is now rejected. These ship in a patch release
  and are called out in the changelog. Where the spec allows it, the
  library fails closed.

## How a breaking change ships

1. The PR title is a Conventional Commit with `!`, for example
   `feat(client)!: ...` or `fix!: ...`. Use `feat` or `fix`: release-plz
   only releases those (and `perf`). It reads the marker and bumps the
   minor version.
2. The PR adds a migration note: a changelog entry saying what to change,
   and, for a larger change, a `docs/migrating-to-<version>.md` guide like
   [`docs/migrating-to-0.15.md`](docs/migrating-to-0.15.md).
3. Breaking changes are batched where possible, so consumers absorb them
   in fewer releases.

If `cargo-semver-checks` reports something that is not actually a break
(for example, an item moved to another crate and re-exported at the same
path), a maintainer adds the `semver-checks-override` label and says why in
the PR description.

## Deprecation

Before a public item is removed, it is marked `#[deprecated]` with a note
naming its replacement. It stays for at least **one full minor release
line and at least three months**, whichever is longer. Removal is itself a
breaking change and ships in a minor release.

Exception: an item that is unsafe to keep (for example, one that cannot be
used without a security problem) can be removed sooner. The changelog says
why.

## MSRV

The MSRV only moves in a minor release, never in a patch. A new MSRV is
a Rust release that has been stable for at least six months. CI builds the
whole workspace on the MSRV toolchain.

## How it is enforced

| Check | Where | What it catches |
|---|---|---|
| `cargo-semver-checks` (required) | [`.github/workflows/semver.yml`](.github/workflows/semver.yml), decision in [`scripts/semver-gate.sh`](scripts/semver-gate.sh) | API breaks against the last release on crates.io, including auto-trait changes on public types. An undeclared break fails the PR. |
| Auto-trait guard | [`tests/auto_traits.rs`](tests/auto_traits.rs), [`tests/send_futures.rs`](tests/send_futures.rs) | A public future losing `Send`, or a public type losing `Send`/`Sync`. `cargo-semver-checks` cannot see futures. Also run in the default `client` build. |
| MSRV (required) | `ci.yml`, `msrv` job | Code that needs a newer compiler. |
| release-plz `semver_check` | [`release-plz.toml`](release-plz.toml) | Raises the release's version bump if a break got through anyway. |

When you add a public `async fn`, add it to `tests/auto_traits.rs`.
