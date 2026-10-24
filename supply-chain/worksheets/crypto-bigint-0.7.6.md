# Review worksheet: `crypto-bigint` 0.7.6 (RUSTSEC-2026-0387)

- **Verdict:** CERTIFIED `safe-to-deploy`, delta audit (`delta = "0.7.5 -> 0.7.6"`).
  No concern-rule trigger: no `unsafe` line changed, no new runtime dependency outside the
  audited `ctutils`, no build script, no vendored binaries.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-24
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"
- **Why now:** RUSTSEC-2026-0387 (timing variability in operations intended to be
  constant-time), patched in `>= 0.7.6`, turned the blocking `cargo deny check` job red on
  `main` and on PR #406.

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.7.6 (locked) | `6bb08299a6046833a879ace115697f12fd2bd6c8d3e93c909ffc9e0738e7cae0` | `Cargo.lock` checksum (root, and the `bindings/acdp-py` / `bindings/acdp-node` / `bindings/acdp-wasm` lockfiles) |
| 0.7.5 (prior audit) | `1a52aa3fcda4e6302a9f48734f234d35d4721b96f8fe07d073f07ce9df4f0271` | crates.io index `cksum`, and the `Cargo.lock` checksum this audit replaces |

Reproduce the facts with `scripts/vet-facts.sh crypto-bigint 0.7.6 0.7.5`.

## Method

- Delta: 60 files, +1459/-666 (excluding Cargo.lock, Cargo.toml.orig and .cargo_vcs_info.json).
  That is 2,125 changed lines against 46,650 `src/` lines, a ratio of 0.05, so the method rule
  says **delta**.
- **Every hunk was read**: the 3,427-line `src/` diff and the 120-line metadata diff
  (`Cargo.toml`, `CHANGELOG.md`, `README.md`).
- Base: 0.7.5, full audit 2026-10-04 (#339 B6).
- ACDP's compiled feature set is unchanged: `getrandom`, `hybrid-array`, `rand_core`,
  `subtle`, `zeroize`. `alloc` is off, so the `boxed/*` hunks (`BoxedUint` sqrt and gcd,
  `BoxedMontyForm::invert`, `safegcd/boxed`) were read but are not compiled into ACDP.

## The change

Constant-time fixes (the advisory):

- `src/word.rs`: `borrowing_sub`, `leading_zeros`, `trailing_zeros` and
  `overflowing_add_wide` are re-exported from the new `ctutils::primitives` module.
  `choice_from_nz` and `choice_from_wide_eq` delegate to `Choice::from_u*_nz` / `from_u*_eq`.
  `choice_to_mask` / `choice_to_wide_mask` use `to_u8()` (black_box-backed) instead of
  `to_u8_vartime()`.
- `Limb` bit counts and `Limb::borrowing_sub` go through those `word::` helpers. The old
  `primitives::borrowing_sub` is removed.
- `UintRef` drops `#[derive(PartialEq, Eq)]` (a short-circuiting slice compare) for manual
  impls: `PartialEq` is `ct_eq`, and `Ord` / `PartialOrd` use the constant-time `cmp`.
- `src/uint/ref_type/div.rs`: the quotient correction `quo.saturating_sub(borrow & 1)`
  becomes a masked `wrapping_sub`. `div_exact` and `div_exact_vartime` derive exactness from
  trailing-zero counts instead of an early return.
- `BoxedMontyForm::invert` uses `CtOption::unwrap_or` instead of branching on invertibility
  (not compiled for ACDP).
- `modular/mul`: the Montgomery reduction carry uses `overflowing_add_wide` with a `Choice`
  mask. `square_repeat_montgomery_form` does one conditional subtraction per iteration
  (#1344).
- About 70 hunks are mechanical: `to_bool_vartime()` becomes `to_bool()`, mostly in
  tests and `assert!`s.

Correctness fixes:

- `src/uint/sub_mod.rs` `try_sub_with_carry`: `(_, carry) = carry.borrowing_sub(..)` becomes
  `(carry, _) = ..`, so the carry is now the subtraction result, not its borrow. A unit test
  is added.
- `src/uint/mul/karatsuba.rs`: the square path discarded the carry out of
  `wrapping_square(x1, z2)`. It is now added into the tail carry.
- `src/uint/mod_symbol.rs`: the optimized binary-GCD Jacobi path is removed after
  issue #1295 (middle-bit variations gave wrong symbols). The classic path is always used.
- `src/modular/safegcd.rs` `iterations`: computed in `u64` with
  `assert!(.. <= u32::MAX, "precision too large for safegcd")`. Previously
  `45907 * bits + 30179` overflowed `u32` from 93,558 bits.
- `bingcd`: the `jacobi_neg` plumbing is removed from the optimized path.
- Square root: `Uint`, `NonZero<Uint>` and `BoxedUint` `floor_sqrt` / `checked_sqrt` now call
  a new `UintRef::sqrt_assign{,_vartime}` (`src/uint/ref_type/sqrt.rs`, 298 lines,
  Brent-Zimmermann Algorithm 1.12 with a Hacker's Delight word-level base case). This replaces
  the Newton iteration and fixes the issue #1303 edge case.
- `UintRef` add/sub slice helpers (`carrying_add_assign_slice`,
  `conditional_add_assign_slice`, `borrowing_sub_assign_slice`,
  `conditional_borrowing_sub_assign`) now accept `self` longer than `rhs` and propagate the
  carry/borrow through the tail. The length `assert!`s relax from `==` to `>=`, and indexing
  stays bounded by the respective slice lengths.

## `unsafe` review

`vet-facts.sh` counts 14 `unsafe` lines, the same 14 sites as in 0.7.5. No diff line adds or
removes `unsafe`. Hunks adjacent to a site:

| Site | Hunk | Verdict |
|---|---|---|
| `src/uint/ref_type/cmp.rs:85` (transmute `i8` to `Ordering`) | `ord` now from `to_u8()` instead of `to_u8_vartime()` | Still `(0 or 1) * (+1 or -1)`, so it is in `{-1, 0, 1}`. Valid `repr(i8)` `Ordering`. Sound. |
| `src/uint/encoding.rs:402/413` (`cast_slice{,_mut}`) | new `Zeroize for EncodedUint` beside them | Safe impl, zeroizes the inner `[Word; LIMBS]`. Sites unchanged. |
| `src/uint/ref_type.rs:47/57/73` (`repr(transparent)` casts) | derive removed, manual `Eq`/`Ord` added in `cmp.rs` | Layout attribute unchanged. Sound. |
| `src/non_zero.rs:120`, `src/odd.rs:130` | `assert!` in neighbouring `const fn`s switched to `to_bool()` | Sites unchanged. |

## Panics added (safe code)

- `UintRef::ct_assign` asserts `self.bits_precision() >= other.bits_precision()`. Previously
  it was a `debug_assert_eq!`, with equal length enforced by ctutils' `ct_assign_slice`.
- `safegcd::iterations` asserts precision <= 1,864,517,463 bits.
- `sqrt_assign` asserts the scratch buffers are long enough. `sqrt_rem_small` asserts
  `len < 4`.

None of these is reachable at the P-256 sizes ACDP uses.

## Facts

- `unsafe`: 14 sites, unchanged.
- asm/SIMD: none.
- `build.rs` / proc-macro: none.
- Powerful imports: none.
- Dependencies: `ctutils` requirement `0.4` becomes `0.4.5` (audited separately,
  `ctutils-0.4.5.md`). Dev-only: `num-bigint` 0.5, `num-modular` 0.7.
- `rust-version` is 1.87, above ACDP's previous 1.86 MSRV. ACDP's MSRV moves to 1.87 in the
  same change.

## Not claimed

- Cryptographic correctness.
- Constant-time behaviour and side-channel resistance. The advisory fix is a constant-time
  fix, and that the generated code is now branch-free is upstream's claim
  (RustCrypto/crypto-bigint#1365).
