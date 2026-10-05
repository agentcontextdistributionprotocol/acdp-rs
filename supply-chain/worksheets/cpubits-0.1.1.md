# Review worksheet: `cpubits` 0.1.1 (issue #339, Tier B batch B3)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.1.1"`). No concern-rule
  trigger. One non-blocking observation (CB-1, a compile-time macro bug in an arm no
  dependent uses).
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.1.1 (locked) | `15b85f9c39137c3a891689859392b1bd49812121d0d61c9caf00d46ed5ce06ae` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is identical (`diff -r`) to the
`~/.cargo/registry/src` copy that was read, except Cargo's own `.cargo-ok` marker. Reproduce
the facts with `scripts/vet-facts.sh cpubits 0.1.1`.

The root `Cargo.lock` and all three binding lockfiles (py, node, wasm) lock 0.1.1 with the
same checksum.

## Method

- No prior audit of `cpubits` exists in `audits.toml` or the imported sets, so **full**.
- `src/` is one file, `src/lib.rs` (462 lines), read in full, with `Cargo.toml` (and
  `.orig`) and the packaged `Cargo.lock` (no dependencies).
- The crate is two `#[macro_export]` `macro_rules!` macros that expand in the caller
  (`crypto-bigint` 0.7.5), plus one `const`. Every arm was read.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 sites (full-source grep, including every macro body). There is no `#![forbid(unsafe_code)]` attribute and no `Cargo.toml` lint. The grep is the evidence. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no |
| Exported macros | `cpubits!` (`src/lib.rs:152-315`) and the vendored `cfg_if!` (`:321-388`). Both expand only to `#[cfg(...)]`-gated copies of the caller's own tokens, plus `compile_error!("unsupported target pointer width")` as the fallback arm (`:309-312`). They add no code of their own, no `unsafe` and no imports. |
| Powerful imports | none. `#![no_std]` (`src/lib.rs:1`); the only `include_str!` is `#![doc = include_str!("../README.md")]` (`:2`). |
| `cfg` inputs | Reads `cfg(cpubits = "16"/"32"/"64")` overrides (`:286-296`), set only by `RUSTFLAGS --cfg`; ACDP sets none. Otherwise `target_pointer_width`, with 64-bit promotion for ARMv7 and `wasm32` (`:256-261`). |
| Dependencies | none |
| Features ACDP enables | none (the crate defines none) |
| Reached via | `crypto-bigint` 0.7.5 (only dependent; for example `src/word.rs:6`, `src/limb.rs:41`), under `rfc6979` -> `ecdsa` -> `p256`. Locked in the root and all three bindings. ACDP itself does not invoke `cpubits` (no hits in `crates/`, `src/`, `tests/`). |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour (what was read)

- `pub const CPUBITS: u32` (`:391-397`) is the macro applied to `16`/`32`/`64` literals.
- `cfg_if!` (`:323-388`) is the upstream `cfg-if` algorithm: each branch is emitted under
  `#[cfg(all(<yes>, not(any(<previous>))))]`, so exactly one branch survives.
- The `#[cfg(test)]` module (`:399-462`) only compares `CPUBITS` with `usize::BITS`.

## Observation CB-1 (non-blocking)

The single-size `16 => { ... }` arm (`:156-161`) re-invokes the macro as
`16 => { ... }, 32 | 64 => { }`, with a comma after the first block (`:158`). No arm accepts
that comma, so `cpubits! { 16 => { ... } }` fails to compile ("no rules expected `,`";
reproduced with `rustc` on a copy of the two macros). It is a compile-time error, never
runtime behaviour, and no dependent uses that form, since the ACDP graph builds. The
comment on the `32 =>` arm (`:163-164`) also says "ignored on 32-bit and 64-bit platforms"
where it means 16- and 64-bit. Both are still present on upstream `master` (checked
2026-10-04). Reporting upstream is the maintainer's call.

## Concerns

None. Compile-time `cfg` selection only; no `unsafe`, no I/O, no build-time code.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, and whether
the word-size heuristic is optimal for a given target.
