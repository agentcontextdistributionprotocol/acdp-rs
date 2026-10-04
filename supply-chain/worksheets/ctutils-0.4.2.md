# Review worksheet: `ctutils` 0.4.2 (issue #339, Tier B batch B4)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.4.2"`). No concern-rule
  trigger.
- **Constant-time behaviour is NOT claimed.** `ctutils` is a constant-time utility crate.
  This audit says only that its code is safe to deploy (no `unsafe`, no I/O, no build-time
  code). Whether its operations are constant-time depends on `cmov` (separate Tier B crate,
  still exempted) and on the compiler, and was not assessed.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.4.2 (locked) | `7d5515a3834141de9eafb9717ad39eea8247b5674e6066c404e8c4b365d2a29e` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is identical (`diff -r`; only cargo's
`.cargo-ok` marker differs) to the `~/.cargo/registry/src` copy that was read. Reproduce the
facts with `scripts/vet-facts.sh ctutils 0.4.2`. The root lockfile and all three binding
lockfiles lock 0.4.2 with this checksum.

## Method

- No prior audit of `ctutils` exists, so **full**.
- `src/` is 3,425 lines. Every non-test line was read: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (140), `src/choice.rs` (961; non-test `:1-626`), `src/ct_option.rs` (918;
  non-test `:1-664`), `src/traits.rs` (13), `src/traits/ct_assign.rs` (213),
  `src/traits/ct_eq.rs` (327; non-test `:1-244`), `src/traits/ct_find.rs` (127; non-test
  `:1-85`), `src/traits/ct_gt.rs` (102; non-test `:1-67`), `src/traits/ct_lookup.rs` (137;
  non-test `:1-87`), `src/traits/ct_lt.rs` (111; non-test `:1-67`), `src/traits/ct_neg.rs`
  (167; non-test `:1-104`), `src/traits/ct_select.rs` (209; non-test `:1-159`);
  `src/traits/ct_assign.rs` has no test module. The `#[cfg(test)]`
  modules at the end of each file and `tests/proptests.rs` (58, a proptest harness) were
  grep-scanned for `unsafe`, includes and `std::` imports (none), not line-read.
- **Exported macros (expand in caller crates).** `map!` (`src/ct_option.rs:12-15`) expands
  to `$crate::CtOption::new($mapper($opt.to_inner_unchecked()), $opt.is_some())`;
  `unwrap_or!` (`:27-32`) expands to `$select(&$default, $opt.as_inner_unchecked(),
  $opt.is_some())`. Both call only safe public methods plus a caller-supplied path. The
  other `macro_rules!` (`bitle!`/`bitlt!`/`bitnz!` in `choice.rs:10-30`, the `impl_*`
  generators in `traits/*.rs`) are crate-private and were read; they emit safe trait impls.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0, including both exported macros (grep of the full source, comment lines excluded; the grep is the evidence). `#![forbid(unsafe_code)] // `unsafe` should go in `cmov`` at `src/lib.rs:7` is only a corroborating hint (cargo builds registry deps with `--cap-lints allow`). |
| asm / SIMD / intrinsics | none in this crate. All predication is delegated to `cmov`: `Cmov::cmovnz` (`traits/ct_assign.rs:69`, `:85`) and `CmovEq::cmoveq` (`traits/ct_eq.rs:83`, `:101`). `cmov`'s `unsafe`/`asm!` is outside this audit. |
| build.rs | none (`build = false`) |
| proc-macro | no |
| Powerful imports | none. `#![no_std]` (`src/lib.rs:1`); `extern crate alloc` only under feature `alloc` (`:122-123`, off in ACDP); `#![doc = include_str!("../README.md")]`. No `std::{fs,net,process,env}`, `env!`, `include_bytes!`. |
| Binary content | none |
| Dependencies | `cmov` ^0.5.3 (locked 0.5.4); optional `subtle` 2 (feature `subtle`; locked 2.6.1). Dev-only: `proptest`. |
| Features ACDP enables | `subtle` (root `--all-features`); `alloc` off |
| Reached via | `crypto-bigint` 0.7.5, `digest` 0.11.3 (`mac` feature: `CtOutput` / `verify_slice`), `sec1` 0.8.1 |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour (what was read)

- `choice.rs`: `Choice(pub(crate) u8)` (`:42`); every public constructor masks to the low
  bit (`from_*_lsb`) or derives 0/1 from bit tricks (`bitle!`/`bitlt!`/`bitnz!` shift the
  top bit down by `BITS - 1`). `select_*` are `a ^ (mask & (a ^ b))`; masks are
  `wrapping_neg` of the 0/1 value. `to_u8` passes the byte through `core::hint::black_box`
  (`:398-403`). `subtle` conversions (`:595-625`) go through `unwrap_u8` / `Choice::from`.
- `ct_option.rs`: `CtOption { value, is_some }` (`:42-46`); `expect`/`unwrap` assert
  `is_some` (`:125-127`, `:444-449`); `*_unchecked` accessors return the value
  regardless (documented, safe); combinators use `ct_select`.
- `traits/ct_assign.rs`: `CtAssignSlice::ct_assign_slice` asserts equal lengths
  (`:42-48`) before the element loop; the integer impls forward to `cmov`.
- `traits/ct_eq.rs`: slice equality starts from `len().ct_eq(len())` (`:51`) and ANDs
  element results; integer impls forward to `cmov`; `Ordering` compares as `i8`.
- `traits/ct_gt.rs`, `traits/ct_lt.rs`: `overflowing_sub` borrow bit; `Ordering` maps
  `-1/0/1` to `0/1/2` before comparing as `u8`.
- `traits/ct_neg.rs`: signed impls use `-*self` (`:29`, `:35`), a debug-build overflow
  panic for `MIN`; unsigned use `wrapping_neg`; `NonZeroU*` re-wraps with
  `expect("should be non-zero")` (`:89`), unreachable because the wrapping negation of a
  non-zero value is non-zero.
- `traits/ct_lookup.rs`: `i += Idx::from(1u8)` (`:36`) can overflow for a slice longer than
  `Idx::MAX` (debug panic; release wrap gives a wrong match). Upstream marks it TODO.
- `traits/ct_find.rs`, `traits/ct_select.rs`: built from `insert_if` / `ct_assign` /
  `ct_select`; `CtSelectArray` uses `core::array::from_fn`.

**ACDP reachability of the panics.** All of the above are safe-code panics, not
memory-safety issues. A grep of the `ctutils` dependents in ACDP's graph (`crypto-bigint`
0.7.5, `sec1` 0.8.1, `digest` 0.11.3) and of `p256`, `elliptic-curve`, `primefield`,
`primeorder`, `ecdsa`, `rfc6979`, `hmac` found no use of `CtLookup` or `CtFind`;
`crypto-bigint` implements `CtNeg` for its own `BoxedUint` (`uint/boxed/ct.rs:38`).

## Concerns

None under the concern rule.

## Not claimed

Cryptographic correctness, **constant-time behaviour**, side-channel resistance. The
names `ct_*` and `Choice` describe upstream's intent; this audit did not verify it.
