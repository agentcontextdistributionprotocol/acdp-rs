# Review worksheet: `curve25519-dalek` 5.0.0 (issue #322, Phase 3)

- **Verdict:** CERTIFIED `safe-to-deploy`, delta audit (`delta = "4.1.3 -> 5.0.0"`), with
  one recorded discretion (C-1: a docs-only, nightly-only visibility hole), under the
  Policy 6 carve-out. Every `unsafe` site at 5.0.0 was read and has a verdict below, so the
  `unsafe` claim does not depend on the base audit.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 5.0.0 (locked) | `b5eed333089e2e1c1ac8c6c0398e5e2497b4c9926ca6d0365ed1e099afa5bc23` | `Cargo.lock` checksum |
| 4.1.3 (prior audit) | `97fb8b7c4503de7d6ae7b42ab72a5a59857b4c937ec27a3d4539dba95b5ab2be` | crates.io index `cksum` |

To reproduce: `scripts/vet-facts.sh curve25519-dalek 5.0.0 4.1.3`.

## Method

- Delta 4.1.3 -> 5.0.0: **73 files, +5045/-2187** per `vet-facts.sh` (excluding
  Cargo.lock, Cargo.toml.orig, and .cargo_vcs_info.json). The plan quoted 62 files,
  +4031/-1157 from `cargo vet suggest`, which counts differently. Per the plan, the
  script's numbers are used.
- 7,232 changed lines against 34,619 `src/` lines is a ratio of 0.21, so the method rule
  says **delta**.
- About 1,100 of the changed lines are module moves (`foo/mod.rs` -> `foo.rs`, under
  `clippy::mod_module_files`). Each pair was diffed directly. The only content changes
  in them are the `nightly` -> `curve25519_dalek_backend = "avx512"` cfg swap,
  `#[path]`/`include_str!` path fixes, lifetime elision, and the new `len`/`is_empty`.
- Read in full: every hunk of `build.rs`, `Cargo.toml`, `src/lib.rs`, `src/backend.rs`,
  all of `src/backend/vector/**`, `src/backend/serial/**`, `src/constants.rs`,
  `src/field.rs`, `src/scalar.rs`, `src/edwards.rs`, `src/edwards/affine.rs`,
  `src/montgomery.rs`, and `src/traits.rs`.
- Skimmed for `unsafe` / powerful imports / I/O only: `src/ristretto.rs`,
  `src/ristretto/elligator.rs`, and `src/lizard/**`. All are safe code. Lizard sits
  behind the `lizard` feature, which ACDP does not enable.
- **Base spot-check (4.1.3, audited 2026-07-05).** The base note says "audited unsafe
  confined to gated SIMD backends". That wording is **imprecise**. 4.1.3 also has three
  non-SIMD `unsafe` sites:
  - `backend/serial/u64/scalar.rs:182` and `backend/serial/u32/scalar.rs:193`: a
    `read_volatile` `black_box` on a stack `u64`/`u32` (the RUSTSEC-2024-0344 timing
    fix);
  - `constants.rs:88`: the `RistrettoBasepointTable` cast.

  All three were re-read now and are **sound**. The base's conclusion holds and only its
  description was loose. Because every 5.0.0 `unsafe` site is verdicted below
  independently, the delta inherits no `unsafe` reasoning from the base. This is recorded
  as an assumption (ASSUMPTIONS.md, #322 Phase 3) rather than as a switch to a full audit
  of 34.6k lines.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 33 lines with an explicit `unsafe` token (was 35 at 4.1.3). This grep count undercounts the unsafe surface; see "Generated `unsafe` contexts" below. The 33: `backend/vector/avx2/field.rs` 8, `backend/vector/ifma/field.rs` 9 (one at `:647` is in the `cfg(test)` module at `:638`), `backend/vector/packed_simd.rs` 15, `constants.rs:85` 1. The two serial `black_box` sites were **removed**. Verdicts below. |
| `forbid(unsafe_code)` | no |
| asm | none. SIMD uses `core::arch::x86_64` intrinsics only. |
| build.rs | 162 lines. Reads only `CARGO_CFG_TARGET_ARCH`, `CARGO_CFG_TARGET_POINTER_WIDTH`, `CARGO_CFG_TARGET_FEATURE` (new), `CARGO_CFG_CURVE25519_DALEK_BITS`, and `CARGO_CFG_CURVE25519_DALEK_BACKEND`. Calls `rustc_version::version()` / `version_meta()`, which run `$RUSTC -vV`; that was already true in 4.1.3. Emits only `cargo:rustc-cfg=…` and one `cargo:warning`. No filesystem, network, or `OUT_DIR` writes. This is cfg selection only. Dropped: the `nightly` cfg. |
| proc-macro | no. It depends on `curve25519-dalek-derive 0.1.1` (proc-macro, Tier B, still exempted), on x86_64 non-serial/non-fiat builds only. |
| Powerful imports | none in `src/` (`#![no_std]`). `include_str!` is used only for README/docs strings. Non-Rust files are docs, `tests/build_tests.sh` (a test script, not run by a build), and `vendor/ristretto.sage` (not built). There are no binary blobs. |
| Dependencies | `digest` 0.10 -> 0.11 (now `features = ["block-api"]`), `ff`/`group` 0.13 -> 0.14 (optional, `group` feature), `rand_core` 0.6.4 -> 0.10, `subtle` 2.3 -> 2.6 (`const-generics`), `cpufeatures` 0.2.6 -> 0.3 (x86_64), `fiat-crypto` 0.2.1 -> 0.3.0 (only under `--cfg curve25519_dalek_backend="fiat"`). **Removed** feature: `group-bits`. **Added** feature: `lizard`. Dev-only: `bincode`/`rand` replaced by `postcard`/`getrandom`/`proptest`. |
| Features ACDP enables | `digest`, `precomputed-tables`, `rand_core`, `zeroize`, identical in the root workspace (all features, all targets, dev included) and in the py, node, and wasm bindings (`cargo tree -e features`). `alloc` is off, so the default features are not enabled through ed25519-dalek. `group`, `lizard`, `serde`, and `legacy_compatibility` are off. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Backend selection: what ACDP actually compiles

`build.rs` chooses `curve25519_dalek_bits` from the pointer width (unless overridden), and
then `curve25519_dalek_backend`:

- **Forced `fiat` / `serial`.** Used as given.
- **Forced `simd` / `avx512`.** Allowed only on x86_64 with 64-bit; otherwise it panics
  (a build error). Forced `avx512` also emits `simd`.
- **Default.** `avx512` (plus `simd`) is chosen only if rustc is 1.89 or later (or
  nightly) **and** the target *statically* enables `avx512ifma` **and** `avx512vl`
  (`CARGO_CFG_TARGET_FEATURE`, that is, `-C target-feature`/`target-cpu`). Otherwise the
  backend is `simd` on x86_64 with 64-bit, and `serial` everywhere else.
- **What changed.** In 4.1.3, IFMA was compiled only with `cfg(nightly)`. It is now
  reachable on stable, but only through a static target-feature opt-in.

At runtime, `backend.rs::get_selected_backend()` dispatches with `cpufeatures::new!`.
It tries `avx512ifma`+`avx512vl` (if compiled), then `avx2`, and otherwise falls back to
`Serial`. This is the same structure as 4.1.3.

| ACDP artifact | Target | Compiled backend | Runtime |
|---|---|---|---|
| Root crates, CI, and py/node wheels on x86_64 | x86_64, 64-bit | `simd` (AVX2) + serial u64. IFMA is **not** compiled, because no ACDP build sets `target-feature`/`target-cpu` (checked in `.github/`, `bindings/*/.cargo`, and the wasm RUSTFLAGS composer). | AVX2 if CPUID reports it, otherwise serial |
| macOS/Linux aarch64 (dev, wheels) | aarch64 | `serial`, u64. Confirmed by the build-script output in `target/debug/build/curve25519-dalek-*/output`: `bits="64"`, `backend="serial"`. curve25519-dalek has **no NEON backend**. | serial |
| `bindings/acdp-wasm` | wasm32 | `serial`, u32 (pointer width 32). The wasm RUSTFLAGS set only `getrandom_backend`. | serial |
| none | – | `fiat` (needs a forced cfg) | – |

## `unsafe` sites and verdicts

### Generated `unsafe` contexts (correction, 2026-10-05)

A grep for the `unsafe` token undercounts this crate's unsafe code, so the 33-line count
above is a count of explicit tokens, not a bound on unsafe operations.

- `curve25519-dalek-derive` 0.1.1 (worksheet `curve25519-dalek-derive-0.1.1.md`) rewrites
  each safe `fn` or method covered by `#[unsafe_target_feature("…")]` into a safe wrapper.
  The original body moves into a generated `#[target_feature(enable = "…")] unsafe fn` (a
  trait method for `impl` items), and the wrapper calls it in `unsafe {}`. A fn that is
  already `unsafe fn` (`ifma/field.rs` `madd52lo`/`madd52hi`) only gains
  `#[target_feature]`; it gets no wrapper, and its callers still need `unsafe`.
- So every such body is an unsafe context. An unsafe operation there compiles with no
  `unsafe` token: the crate is edition 2024, where `unsafe_op_in_unsafe_fn` only warns, and
  `--cap-lints` silences that warning for registry dependencies.
- At 5.0.0 there are 69 `#[unsafe_target_feature]` attributes under `src/backend/vector/`
  (`packed_simd.rs` 17, `avx2/field.rs` 8, `avx2/edwards.rs` 16, `ifma/field.rs` 13,
  `ifma/edwards.rs` 15). Most sit on `impl` blocks, and each method in those blocks is
  rewritten, so the number of affected bodies is larger than 69.
- There are also 5 `#[unsafe_target_feature_specialize]` modules
  (`scalar_mul/{pippenger,precomputed_straus,straus,variable_base,vartime_double_base}.rs`).
  The macro emits one copy of each module per feature set and applies the same rewrite to
  every fn and impl method in each copy.
- The verdicts below do not rest on the token count. The grep for
  `load|store|ptr|as *|get_unchecked|MaybeUninit` under `backend/vector/` does not depend
  on the `unsafe` token and is empty. A brace-tracking re-scan on 2026-10-05, plus a read of the
  `$…_intrinsic` macro-parameter calls in `packed_simd.rs`, also found every `core::arch`
  intrinsic call under `backend/vector/` inside an explicit `unsafe`
  block or `unsafe fn`. So at 5.0.0 the counted lines cover every intrinsic call. A future
  delta must still read each `#[unsafe_target_feature]` body as unsafe code.

The soundness model rests on one invariant. `#[unsafe_target_feature("…")]`
(curve25519-dalek-derive) turns a function into a **safe** wrapper around a
`#[target_feature(enable = …)] unsafe fn`. So soundness depends on every path into
`backend::vector` being reached only after feature detection.

- **Entry points.** Every reference to `vector::` outside `src/backend/vector/` is in
  `src/backend.rs`, at lines 89-273. Each is a `match get_selected_backend()` arm, or a
  `VartimePrecomputedStraus` variant that can only be constructed in such an arm (lines
  112-127). CPU features do not change within a process.
- **Visibility.** `backend` is `pub(crate)` (`lib.rs:91-92`), except under `cfg(docsrs)`.
  That exception is finding C-1.

| Site(s) | What | Verdict |
|---|---|---|
| `backend/vector/packed_simd.rs:56` | `PartialEq for u32x8/u64x4`: `_mm256_cmpeq_epi8` + `_mm256_movemask_epi8` on two register values. | **Sound.** Register-only. It sits inside `#[unsafe_target_feature("avx2")]`, so it is reached only on the AVX2 path. |
| `packed_simd.rs:91,110,120,130` | `Add`/`Sub`/`BitAnd`/`BitXor`: `_mm256_{add,sub}_epi{32,64}`, `_mm256_and_si256`, `_mm256_xor_si256`. | **Sound.** Register-only and wrapping. |
| `packed_simd.rs:157,162,167` | `shl/shr/extract<const N>`: `_mm256_s{l,r}li_epi{32,64}`, `_mm256_extract_epi{32,64}`. | **Sound.** Immediate-operand intrinsics; an out-of-range `N` for `extract` is a compile-time assertion in `core::arch`, not UB. |
| `packed_simd.rs:248,300` | `new_const`: `transmute::<[u64;4], __m256i>` / `transmute::<[u32;8], __m256i>` (5.0.0 only adds explicit turbofish types). | **Sound.** The sizes match (32 bytes), every bit pattern is a valid `__m256i`, and the code is a `const fn` with no feature requirement. |
| `packed_simd.rs:265,277,322,335,348` | `_mm256_set_epi64x`, `_mm256_set1_epi64x`, `_mm256_set_epi32`, `_mm256_set1_epi32`, `_mm256_mul_epu32`. | **Sound.** Register-only, inside avx2 target-feature fns. |
| `backend/vector/avx2/field.rs:73,94,229,269,437,461,484,668` | unpack/repack, blend, shuffle, permute, and multiply in `FieldElement2625x4`: `_mm256_unpack{lo,hi}_epi32`, `_mm256_blend_epi32`, `_mm256_shuffle_epi32`, `_mm256_permutevar8x32_epi32`, `_mm256_srlv_epi32`, `_mm256_mul_epu32`. | **Sound.** No pointer, load, or store intrinsic appears anywhere under `backend/vector/` (grep for `load|store|ptr|as *|get_unchecked|MaybeUninit` is empty). Every op is register-to-register. The file is unchanged from 4.1.3 except `#![allow(unused_unsafe)]` and import order. |
| `backend/vector/ifma/field.rs:28,36` | `unsafe fn madd52lo/madd52hi`, `#[unsafe_target_feature("avx512ifma,avx512vl")]`, which wrap `_mm256_madd52{lo,hi}_epu64`. | **Sound.** Register-only. Callers are themselves `avx512ifma,avx512vl` target-feature fns. |
| `ifma/field.rs:67,99,277,412,444,496` | `_mm256_permute4x64_epi64`, `_mm256_blend_epi32`, and `madd52*` calls in `F51x4Unreduced/Reduced`. | **Sound.** Register-only. The module exists only with `cfg(curve25519_dalek_backend = "avx512")` (`backend/vector.rs:19-20`), and its runtime entry requires a `cpufeatures` `avx512ifma`+`avx512vl` token. The IFMA code also uses the `avx2` `u64x4` operators; `avx512vl` implies `avx2`, in Rust's feature implications and on every CPU. |
| `ifma/field.rs:647` | `madd52lo` in a test. | Test-only (`cfg(test)` plus static avx512 target features). |
| `constants.rs:85` | `&*(ED25519_BASEPOINT_TABLE as *const EdwardsBasepointTable as *const RistrettoBasepointTable)`, in a `static`. | **Sound.** `RistrettoBasepointTable` is `#[repr(transparent)]` over `EdwardsBasepointTable` (`ristretto.rs:1079-1080`), and the referent is `'static`. Unchanged. |
| **Removed:** `backend/serial/u{32,64}/scalar.rs` `black_box` (`read_volatile` of a stack integer). | The 4.1.3 RUSTSEC-2024-0344 optimization barrier in `Scalar52/Scalar29::sub`. | Replaced by `conditional_add_l(Choice)`, which uses `u64/u32::conditional_select`. subtle 2.6.1's `Choice::from(u8)` keeps its own `read_volatile` `black_box` barrier (`subtle/src/lib.rs:224-238`; ACDP's subtle features are `const-generics`, `i128`, so not `core_hint_black_box`). **Not claimed:** that the generated code is branch-free. |

## Findings

### C-1 (discretion, under the Policy 6 carve-out): `--cfg docsrs` exposes the target-feature wrappers publicly

- **Where:** `src/lib.rs:89-92` has `#[cfg(docsrs)] pub mod backend;`. The chain
  `backend::vector::packed_simd::{u64x4, u32x8}` is `pub`, and `u64x4::new`, `splat`,
  and the operator impls are safe `avx2` target-feature wrappers.
- **The problem:** in a `docsrs` build, external safe code could call them on a CPU
  without AVX2. That is UB, because they are `#[target_feature]` code reached without
  detection.
- **Reachability:** `cfg(docsrs)` also activates `#![cfg_attr(docsrs,
  feature(doc_cfg))]` (`lib.rs:13`). That is rejected on stable (E0554) unless
  `RUSTC_BOOTSTRAP` is set, which is not a supported configuration. So the hole is
  nightly-only and docs-only, and unreachable in any stable-toolchain build of any ACDP
  artifact.
- **History:** the same `pub mod backend` under `docsrs` existed in 4.1.3
  (`lib.rs:99-100`).
- **Upstream note (not filed):** the `docsrs` re-export could be limited to `serial`,
  or the vector wrappers marked `unsafe`.

### Non-blocking observations

- **Constant-time-adjacent changes (not claimed as CT):**
  - The scalar-sub barrier moved into subtle (see the table).
  - `CompressedEdwardsY: PartialEq` became `ct_eq` (`edwards.rs:184-187`), with a
    `Hash` that is still derived; it is consistent, being byte equality.
  - The new `AffinePoint` (`edwards/affine.rs`) uses `ct_eq` and `conditional_select`.
  - The new RFC 9380 `hash_to_curve` / `encode_to_curve` / `expand_msg_xmd`
    (`field.rs`, `edwards.rs`, `montgomery.rs::elligator_encode`) use
    `conditional_select` and contain only assertion panics (on output length and the
    domain-separator length).
  - `EdwardsPoint::random` rejection-samples on RNG output; that variable time is over
    public randomness.
  - None of these new APIs is on ACDP's Ed25519 path.
- **Logic change in vartime code:** the precomputed Straus implementation (serial and
  vector) now uses width-8 NAFs for the static points. That matches its
  `NafLookupTable8` tables; 4.1.3 used width 5 against the same tables. The assert was
  relaxed from `sp == static_nafs.len()` to `sp >= static_nafs.len()`, and the loop runs
  `0..static_nafs.len()`. That is safe, bounds-checked indexing on public inputs. ACDP
  does not use `VartimePrecomputedMultiscalarMul`.
- **API removals:** the deprecated `constants::BASEPOINT_ORDER` (it is now
  `pub(crate)`), `nonspec_map_to_curve`, the `group-bits` feature, and
  `PrimeFieldBits`. `Scalar::from_bits` is no longer marked deprecated. ed25519-dalek uses
  it only under `legacy_compatibility`, which ACDP does not enable.
- **Batch APIs:** `invert_batch` / `compress_batch` now have const-generic stack variants
  alongside the `_alloc` variants. `Scalar::invert_batch_internal` still zeroizes its
  scratch (now via `scratch.iter_mut()`).

## Zeroize interplay (zeroize 1.9.0 remains exempt, DECISIONS.md `322-zeroize`)

- Every `Zeroize` impl in 5.0.0 zeroizes **fully initialized integer arrays**, or an
  `IterMut` over tables of such points:
  - `Scalar.bytes: [u8;32]`;
  - `FieldElement51([u64;5])` / `FieldElement2625([u32;10])`;
  - `MontgomeryPoint([u8;32])`;
  - `CompressedEdwardsY` / `CompressedRistretto`;
  - `EdwardsPoint`, `RistrettoPoint`, and the Niels points;
  - the `window.rs` lookup tables;
  - `AffinePoint` via `DefaultIsZeroes`.
- None zeroizes an `Option<Z>`, `MaybeUninit`, or a padded type. So curve25519-dalek's
  own calls never trigger Z-1, the uninitialized-byte-0 `read_volatile` in zeroize's
  non-asm `optimization_barrier` fallback, even on wasm32, where that fallback is
  compiled.
- Whether the barrier (asm on x86_64/aarch64, the volatile-read fallback on wasm32)
  actually prevents a compiler from eliding the writes is a property of zeroize. It is
  not claimed here.
- `alloc` is off in ACDP, so `zeroize/alloc` is not pulled in through this crate.

## Not claimed

The review does not claim:
- cryptographic correctness of any backend (serial, fiat, AVX2, IFMA) or of the new
  hash-to-curve code;
- constant-time behaviour;
- side-channel resistance.

As behavioural evidence only, the `sig-001` golden vector pins Ed25519 output on the
backends that CI exercises.

These Tier B crates remain exempted: `curve25519-dalek-derive 0.1.1`, `cpufeatures 0.3.1`,
`digest 0.11.3`, `rand_core 0.10.1`, and `rustc_version 0.4.1` (a build-dependency).
