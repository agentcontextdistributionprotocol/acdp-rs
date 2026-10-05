# Review worksheet: `crypto-bigint` 0.7.5 (issue #339, Tier B batch B6)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.7.5"`). No concern-rule
  trigger. One observation (CB-R1, a safe-code panic).
- **Scope of the read (exact):** the 150 `src/` files compiled under the features ACDP
  enables, **37,233 lines, were read in full**; the 44 files not compiled in any ACDP
  artifact (8,702 lines: the `alloc`-only `boxed` modules, `der`, `rlp`, `extra-sizes`) were
  **grep-scanned only**. `src/` total: 45,935 lines. `tests/` and `benches/` were
  grep-scanned only.
- **Constant-time behaviour is NOT claimed** (crypto-bigint is a constant-time-oriented
  big-integer library; this audit did not assess whether any operation is constant-time).
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance:
  the compiled files were read in seven partitions by Claude (Opus) sub-reviews, each of
  which confirmed a full line-by-line read of its files and listed every `unsafe`,
  pointer, FFI, `static`, `std`, include, macro-export and `cfg` occurrence; the main review
  read every `unsafe` site and its surrounding code directly and cross-checked the
  partition reports against a full-source grep (they agree: 13 compiled `unsafe` sites).
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.7.5 (locked) | `1a52aa3fcda4e6302a9f48734f234d35d4721b96f8fe07d073f07ce9df4f0271` | `Cargo.lock` checksum |

Downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`; sha256 matches;
the extracted tree (`diff -r`-identical to `~/.cargo/registry/src` apart from `.cargo-ok`)
is what was read. Reproduce with `scripts/vet-facts.sh crypto-bigint 0.7.5`. The root and
all three binding lockfiles lock 0.7.5 with this checksum.

## Which files are compiled

The compiled set was taken from rustc's own dep-info, not from reading `cfg`s:
`cargo check --locked --workspace --all-features --all-targets` (root, host aarch64-apple-darwin)
and `cargo check --locked --target wasm32-unknown-unknown` in `bindings/acdp-wasm` both
list the **same 150 `.rs` files** (plus `README.md` via `include_str!`). No compiled file
has a `cfg(target_arch)` or `cfg(target_os)`; word size is chosen through the `cpubits`
crate (B3; 64-bit words on 64-bit targets **and on wasm32**, which cpubits promotes;
32-bit words on other 32-bit targets) and two `target_pointer_width` variants of
`usize_lt` (`src/primitives.rs:99`, `:107`). The py and node bindings resolve the same
features as the root.

Features ACDP enables (`cargo metadata` resolve, root `--all-features` and all three
bindings): `getrandom`, `hybrid-array`, `rand_core`, `subtle`, `zeroize`. **Off:** `alloc`
(so every `boxed` module), `der`, `serde`, `rlp`, `extra-sizes`.

| Partition | Files | Lines | Read |
|---|---|---|---|
| 1: `bitlen`, `checked`, `encoding`, `int.rs`, `int/{add..mul}` | 20 | 5,615 | full |
| 2: `int/{neg..types}`, `jacobi`, `lib.rs`, `limb.rs`, `limb/*`, `modular.rs` | 33 | 5,097 | full |
| 3: `modular/{add, bingcd*, const_monty_form*, div_by_2, fixed_monty_form*, lincomb}` | 33 | 5,347 | full |
| 4: `modular/{monty_params..sub}`, `non_zero`, `odd`, `primitives`, `traits` | 12 | 5,815 | full |
| 5: `uint.rs`, `uint/{add_mod..encoding}` | 15 | 5,413 | full |
| 6: `uint/{from..pow, rand}`, `uint/ref_type.rs`, `uint/ref_type/add.rs` | 17 | 4,709 | full |
| 7: `uint/ref_type/{bits..sub}`, `uint/{resize..sub}`, `word`, `wrapping` | 20 | 5,237 | full |
| **compiled total** | **150** | **37,233** | **full** |
| not compiled (`modular/boxed_monty_form*`, `modular/safegcd/boxed`, `uint/boxed*`, `uint/encoding/{der,rlp}`, `uint/extra_sizes`) | 44 | 8,702 | grep only |

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 14 in `src/` (`vet-facts.sh`); 13 in compiled files (verdicts below), 1 in `src/uint/boxed/from.rs:73` (`alloc`, not compiled; also sound, see below). No `unsafe` in `tests/` or `benches/`. `Cargo.toml` sets `[lints.rust] unsafe_code = "deny"` with per-site `#[allow(unsafe_code)]`; only a hint (`--cap-lints allow`). |
| asm / SIMD | none (no `asm!`, no `core::arch`) |
| build.rs / proc-macro | none / no |
| Powerful imports | none in compiled code: `#![no_std]`, no `std::` use, no `extern`/FFI, no `static mut`, no interior-mutable statics, no `env!`, `include_str!("../README.md")` for docs only. `extern crate alloc` only under `alloc` (off). |
| OS randomness | only `Random::try_random()` / `random()` (`src/traits.rs:470-473`, `:483-487`, feature `getrandom`), which call `getrandom::SysRng` when a caller explicitly invokes them. Everything else takes a caller-supplied `rand_core` RNG. Nothing runs at load time. `getrandom` itself is B7 (still exempt). |
| `#[macro_export]` | `const_monty_params!`, `const_prime_monty_params!`, `const_monty_form!`, `impl_modulus!` (`src/modular/const_monty_form/macros.rs:25`, `:68`, `:108`, `:125`): expand to a unit struct and `const` parameter impls evaluated at compile time; no `unsafe`. Used by `primefield`/`p256`. |
| Dependencies (compiled) | `cpubits` 0.1 (B3), `ctutils` 0.4 (B4), `num-traits` 0.2, `hybrid-array` 0.4.12+ (this batch), `rand_core` 0.10 (B4), `getrandom` 0.4 (`sys_rng`), `subtle` 2.6, `zeroize` 1. Not compiled: `der`, `rlp`, `serdect`. |
| Reached via | `elliptic-curve` 0.14.1, `primefield` 0.14.0, `rfc6979` 0.6.0 (P-256 signing and verification). No direct ACDP use. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## `unsafe` sites and verdicts (compiled)

| Site | What | Argument | Verdict |
|---|---|---|---|
| `src/limb.rs:132-134` | `array_as_words`: `&[Limb; N]` -> `&[Word; N]` | `Limb` is `#[repr(transparent)] pub struct Limb(pub Word)` (`src/limb.rs:56-57`). | sound |
| `src/limb.rs:143-145` | `array_as_mut_words` | same; any `Word` is a valid `Limb`. | sound |
| `src/limb.rs:155-157` | `slice_as_words`: fat-pointer cast `[Limb]` -> `[Word]` | same; length metadata preserved. | sound |
| `src/limb.rs:166-168` | `slice_as_mut_words` | same. | sound |
| `src/non_zero.rs:120` | `new_ref_unchecked`: `&T` -> `&NonZero<T>` (`T: ?Sized`) | `NonZero<T: ?Sized>(T)` is `#[repr(transparent)]` (`:48-49`); `pub(crate)`. "Non-zero" is a logical invariant only: no `unsafe` in the crate depends on it (the 13 sites here are the only `unsafe`), so a violated invariant can give a wrong result or a panic, never UB. | sound |
| `src/odd.rs:130` | `new_ref_unchecked`: `&T` -> `&Odd<T>` | `Odd<T: ?Sized>(T)` is `#[repr(transparent)]` (`:44-45`); same logical-invariant argument. | sound |
| `src/uint.rs:289-291` | `as_int`: `&Uint<L>` -> `&Int<L>` | `Int<const LIMBS: usize>(Uint<LIMBS>)` is `#[repr(transparent)]` (`src/int.rs:48-49`); `Uint`'s own repr is irrelevant to this cast. Every bit pattern is a valid `Int`. | sound |
| `src/uint/encoding.rs:395` | `cast_slice`: `&[Word]` -> `&[u8]`, `len = size_of_val` | `u8` has align 1; `Word` (u32/u64) has no padding, so every byte is initialized. The `*const` -> `*mut` cast is cosmetic (only a shared slice is built). | sound |
| `src/uint/encoding.rs:406` | `cast_slice_mut` | same; every byte pattern is a valid `Word`. | sound |
| `src/uint/ref_type.rs:47-49` | `UintRef::new`: `&[Limb]` -> `&UintRef` | `#[repr(transparent)] pub struct UintRef { limbs: [Limb] }` (`:32-38`); metadata preserved. | sound |
| `src/uint/ref_type.rs:57-59` | `UintRef::new_mut` | same. | sound |
| `src/uint/ref_type.rs:73` | `new_flattened_mut`: `&mut [[Limb; N]]` -> `&mut [Limb]`, `len = slice.len() * N` | Exact element count of a live exclusive borrow; cannot overflow, since the borrow's byte size is at most `isize::MAX`. (Its comment says "Word" for `Limb`; cosmetic.) | sound |
| `src/uint/ref_type/cmp.rs:85-87` | `transmute::<i8, Ordering>(ord)` in `pub(crate) const fn cmp` | `ord = (c as i8) * sgn` (`:76-81`) where `c` and the inputs to `sgn` are `Choice`s built inside this function from limb values (`lsb_to_choice`, `is_nonzero`, which reach `word::choice_from_lsb` / `choice_from_nz`, `src/word.rs:81-104`, and mask to the low bit through `ctutils::Choice::from_u8_lsb`), so they are 0 or 1; `select_u8(255, 1)` then gives 255 or 1, i.e. `sgn` in {-1, 1}. So `ord` is in {-1, 0, 1}, exactly `Ordering`'s `#[repr(i8)]` discriminants. No caller-supplied `Choice` reaches it. | sound |

Not compiled: `src/uint/boxed/from.rs:73-80` (`alloc`) rebuilds a `Vec<Word>` as
`Vec<Limb>` with `from_raw_parts` after `mem::forget`; same layout and alignment
(`repr(transparent)`), same length and capacity, same allocator. Sound, recorded for
completeness.

## Observations (not vet concerns)

- **CB-R1 (safe panic).** `NonZero<Uint>::floor_root_vartime` (`src/uint/root.rs:57`)
  shifts by `rt_bits * (exp - 1)`; `Uint::shr` asserts `shift < BITS`
  (`src/uint/ref_type/shr.rs:51`), so large exponents
  (for example a top-bit-set 256-bit value with `exp` in 129..=255) panic instead of
  returning a root. Safe code, not a memory-safety issue. A grep of `elliptic-curve`,
  `primefield`, `primeorder`, `rfc6979`, `ecdsa` and `p256` found no caller of
  `floor_root_vartime` / `checked_root_vartime`.
- Panics on malformed fixed-size input in the documented `from_*_hex` / `from_*_slice`
  constructors and the checked operators (`+`, `*`, `/` by zero) are by design; the
  fallible alternatives return `CtOption` / `Result`.
- `check_limbs!(x, $min)` in `src/uint/from.rs:5-14` ignores `$min`; undersized targets hit
  ordinary bounds-check panics. Safe code.

## Concerns

None under the concern rule.

## Not claimed

Cryptographic correctness (of any arithmetic, Montgomery form, inversion, GCD, square
root or random sampling), **constant-time behaviour**, side-channel resistance.
