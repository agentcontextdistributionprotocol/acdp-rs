# Review worksheet: `ctutils` 0.4.5 (RUSTSEC-2026-0385)

- **Verdict:** CERTIFIED `safe-to-deploy`, delta audit (`delta = "0.4.2 -> 0.4.5"`).
  No concern-rule trigger.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-24
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"
- **Why now:** RUSTSEC-2026-0385 (non-constant-time mask generation and `u128` comparisons),
  patched in `>= 0.4.4`, turned the blocking `cargo deny check` job red on `main` and on
  PR #406. 0.4.5 is locked rather than 0.4.4 because `crypto-bigint` 0.7.6 requires
  `ctutils ^0.4.5`.

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.4.5 (locked) | `38d28fb6aa7dd680b3ffd1a3e64e115c177bdba63c0ae7f9cd48129ff05c4fa0` | `Cargo.lock` checksum (root, and the `bindings/acdp-py` / `bindings/acdp-node` / `bindings/acdp-wasm` lockfiles) |
| 0.4.2 (prior audit) | `7d5515a3834141de9eafb9717ad39eea8247b5674e6066c404e8c4b365d2a29e` | crates.io index `cksum`, and the `Cargo.lock` checksum this audit replaces |

Reproduce the facts with `scripts/vet-facts.sh ctutils 0.4.5 0.4.2`.

## Method

- Delta: 11 files, +602/-80. That is 682 changed lines against 3,838 `src/` lines, a ratio
  of 0.18, so the method rule says **delta**.
- **Every hunk was read** (the whole 1,636-line unified diff, including `tests/` and
  `Cargo.toml`).
- Base: 0.4.2, full audit 2026-10-04 (#339 B4).

## The change

- `Choice` mask generation (`to_u8_mask`, `to_u16_mask` … `to_u128_mask`) now goes through
  `to_u8()`, which passes the value through `core::hint::black_box`, instead of reading the
  raw `.0` field. This is the RUSTSEC-2026-0385 fix: these `const fn`s cannot use cmov's
  `asm!`, and the optimizer could turn the raw form into a branch.
- `u128` `lt` / `le` / `gt` are split into `u64` halves on 32-bit targets (`from_u128_lt`
  and friends). `CtGt` / `CtLt` for `u128` use them.
- `Choice::and` is hardened on Thumb-1. `to_bool` / `to_u8` become `const fn`. The
  `to_bool_vartime` / `to_u8_vartime` names remain as deprecated aliases.
- New `pub mod primitives`, consumed by crypto-bigint 0.7.6:
  - the `bitle` / `bitlt` / `bitborrow` / `bitnz` compare macros;
  - `borrowing_sub_u32` / `u64`, with `black_box` on the borrow;
  - `leading_zeros_*` / `trailing_zeros_*`, with a branch-free software fallback on targets
    without native `clz`;
  - `overflowing_add_u64` / `u128`, using `u32` halves on RV32.

  All of it is plain wrapping integer arithmetic.
- Integer casts use `cast_unsigned` / `cast_signed`.
- The remaining hunks are unit tests and proptests.

## Facts

- `unsafe`: 0 sites (full-source grep). `#![forbid(unsafe_code)]` at `src/lib.rs:7`.
- asm/SIMD: none in this crate. Predication is still delegated to `cmov` 0.5.4, audited
  separately.
- `build.rs` / proc-macro: none.
- Powerful imports: none.
- Dependencies: the `subtle` requirement goes from `2` to `2.6` (locked 2.6.1, unchanged).
  No new crates.
- `rust-version` moves from 1.85 to 1.87, above ACDP's previous 1.86 MSRV. ACDP's MSRV
  moves to 1.87 in the same change.

## Not claimed

- Cryptographic correctness.
- Constant-time behaviour and side-channel resistance. That the fix yields branch-free code
  is upstream's claim (RustCrypto/utils#1569, BINSEC-verified upstream).
