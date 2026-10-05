# Review worksheet: `hybrid-array` 0.4.14 (issue #339, Tier B batch B6)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.4.14"`). No concern-rule
  trigger. One `Discretion:` line (packaged upstream CI workflow files, not compiled).
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.4.14 (locked) | `707114b52a152fa7bdb290cd7cd5912d9467273b6d74e21b8d81aca1f8533f6b` | `Cargo.lock` checksum |

Downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`; sha256 matches;
the extracted tree (`diff -r`-identical to `~/.cargo/registry/src` apart from `.cargo-ok`)
is what was read. Reproduce with `scripts/vet-facts.sh hybrid-array 0.4.14`. The root and
all three binding lockfiles lock 0.4.14 with this checksum.

## Method

- No prior audit, so **full**.
- `src/` is 3,228 lines. **Read line by line:** `src/lib.rs` (1,223), `src/traits.rs`
  (289), `src/from_fn.rs` (106), `src/flatten.rs` (137), `src/iter.rs` (132), and the
  macros plus non-table lines of `src/sizes.rs` (1,248). Also `Cargo.toml`.
- **`src/sizes.rs` size table, checked by script:** the default (non-`extra-sizes`) table is
  552 `N => U<N>` mappings (`:55-609`) fed through `impl_array_sizes_with_import!`
  (`:45-53`) to `impl_array_sizes!` (`:21-43`), each emitting
  `unsafe impl ArraySize for U<N> { type ArrayType<T> = [T; N]; }`. A script confirmed that
  every one of the 552 has the literal `N` equal to the digits of its `U<N>` name; the
  `U<N>` types are re-exported from `typenum::consts` (`:49`), audited in B4. The
  `extra-sizes` block (`:614-1248`, hand-built `uint!` bit strings) is behind a feature ACDP
  does not enable and was **not** verified bit by bit.
- `src/serde.rs` (93, feature `serde`, off) was read for `unsafe` (none).
- `tests/` (`mod.rs` 583, `ctutils.rs` 42, `subtle.rs` 29) grep-scanned: one `unsafe`
  (`tests/mod.rs:468`, `assume_init` after writing all six elements), test-only.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 37 in `src/` (every one has a verdict below), plus 1 in `tests/`. No `forbid(unsafe_code)`. |
| asm / SIMD | none |
| build.rs / proc-macro | none / no |
| Powerful imports | none. `#![no_std]`; `extern crate alloc` under `alloc` (`src/lib.rs:98-99`); `include_str!("../README.md")` for docs. |
| Packaged non-Rust files | `.github/workflows/hybrid-array.yml`, `.github/workflows/publish.yml`, `.github/dependabot.yml`, `.codecov.yml`, `.clippy.toml`. Upstream CI configuration; never compiled or executed by a build. |
| Dependencies | `typenum` 1.20 (`const-generics`; locked 1.20.1, B4). Optional: `subtle`, `zeroize`, `ctutils`, `bytemuck`, `zerocopy` (`derive`), `serde`, `arbitrary`. |
| Features ACDP enables | `alloc`, `subtle`, `zeroize` (root `--all-features` and all three bindings, `cargo metadata` resolve). `bytemuck`, `zerocopy`, `ctutils`, `serde`, `arbitrary`, `extra-sizes` are off. |
| Targets | no `cfg(target_*)`; identical code on every target. |
| Reached via | `block-buffer`, `crypto-bigint`, `crypto-common`, `elliptic-curve`, `sec1`, `wnaf` (`cargo tree -i hybrid-array`). No direct ACDP use. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## The foundational invariant

`Array<T, U>` is `#[repr(transparent)] pub struct Array<T, U: ArraySize>(pub U::ArrayType<T>)`
(`src/lib.rs:164-165`). `ArraySize` is a `pub unsafe trait` (`src/traits.rs:22`) whose
documented safety contract (`:14-17`) is that `ArrayType<T>` is an array of exactly
`U::USIZE` elements. The only impls in the crate are the macro-generated ones above, so the
contract holds for every `ArraySize` the crate provides (552 script-checked mappings). A
third-party `unsafe impl ArraySize` that broke the contract would be that crate's
unsoundness, not this one's; nothing in ACDP's graph defines one (a grep of the registry
sources of all 361 registry crates in the root and binding lockfiles for
`impl ... ArraySize for` matched only `hybrid-array`'s own `src/sizes.rs`).

Every `unsafe` site below relies on that contract plus typenum arithmetic (`Sum`, `Diff`,
`Prod`, `Quot` only type-check when the result is the arithmetic value, and `Sub` is not
implemented when it would underflow).

## `unsafe` sites and verdicts

| Site | What | Argument | Verdict |
|---|---|---|---|
| `src/lib.rs:180`, `:188` | `as_slice` / `as_mut_slice`: `from_raw_parts(as_ptr(), U::USIZE)` | `repr(transparent)` over `[T; USIZE]`. | sound |
| `src/lib.rs:230-239` | `concat`: write `U` then `N` elements into `Array<MaybeUninit<T>, Sum<U,N>>`, `assume_init` | `split_at_mut(self.len())`; both `into_iter`s yield exactly `U` and `N` items (core array iterators), so all `U+N` slots are written; `MaybeUninit::write` cannot panic. | sound |
| `src/lib.rs:252-257` | `split`: `ManuallyDrop` + two `ptr::read` (head at 0, tail at `N`) | `U: Sub<N>` implies `N <= U`; `Diff<U,N>` has `U-N` elements, so the reads cover exactly the original elements once; `ManuallyDrop` prevents a double drop; alignment is `T`'s. | sound |
| `src/lib.rs:268-273`, `:284-289` | `split_ref` / `split_ref_mut` | Same bounds; the two `&mut` halves are disjoint. | sound |
| `src/lib.rs:302`, `:319` | `slice_as_array(_mut)` | guarded by `slice.len() == U::USIZE`. | sound |
| `src/lib.rs:340-345`, `:363-368` | `slice_as_chunks(_mut)` | `assert!(U::USIZE != 0)`; `chunks_len = len / U`, `tail_pos = U * chunks_len <= len`; the two ranges are disjoint and in bounds. | sound |
| `src/lib.rs:384`, `:400` | `slice_as_flattened(_mut)` | length via `checked_mul(...).expect(...)`. | sound |
| `src/lib.rs:495`, `:502` | `cast_from_core(_mut)` | where-clause `ArrayType<T> = [T; N]`; `repr(transparent)`. | sound |
| `src/lib.rs:509`, `:516`, `:523`, `:530` | slice casts between `[Array<T,U>]` and `[[T; N]]` | same where-clause; equal layout; length preserved. | sound |
| `src/lib.rs:550` | `uninit()`: `MaybeUninit::uninit().assume_init()` at type `[MaybeUninit<T>; N]` | an array of `MaybeUninit` has no validity requirement (the standard idiom). | sound |
| `src/lib.rs:560-575` | `pub unsafe fn assume_init`: `mem::transmute_copy` from `Array<MaybeUninit<T>,U>` to `Array<T,U>` | Caller contract (all initialized). Sizes are equal (both `[_; USIZE]`), so `transmute_copy` reads exactly the source; the source's drop is a no-op. Internal callers: `concat` (above) and `try_from_fn` (below). | sound |
| `src/lib.rs:945`, `:949` | `unsafe impl Send/Sync for Array<T,U>` where `T: Send/Sync` | needed because the field is an associated type; with the contract it is `[T; N]`, which has the same auto-trait rule. `U` is a zero-sized marker that is not stored. | sound |
| `src/lib.rs:963`, `:979` | `TryFrom<&[T]>` / `&mut [T]` for `&Array` | `check_slice_length` (`:1214-1223`) first. | sound |
| `src/lib.rs:1106`, `:1115` | `unsafe impl Pod` / `Zeroable` | feature `bytemuck`, **not compiled in ACDP**. `[T; N]` of `Pod`/`Zeroable` is `Pod`/`Zeroable` and the wrapper is transparent. | sound |
| `src/from_fn.rs:28-33` | `try_from_fn`: fill `Array<MaybeUninit<T>,U>`, `assume_init` | reached only after `try_from_fn_erased` returned `Ok`, which fills all `len` slots (loop `:49-54`). | sound |
| `src/from_fn.rs:53`, `:80-90` | `push_unchecked`: `get_unchecked_mut(initialized).write(item)` | loop condition `initialized < len` (`:49`); private type. | sound |
| `src/from_fn.rs:93-105` | `Guard::drop`: `drop_in_place` for `0..initialized` | exactly the initialized prefix; runs on early `Err` return and on panic from `f`; `mem::forget` on success (`:56`). | sound |
| `src/flatten.rs:30-33` | `Flatten`: `ptr::read` of `[[T; M]; N]` as `[T; M*N]` | `Prod<M,N>` elements; identical layout; `ManuallyDrop` source. | sound |
| `src/flatten.rs:59-66` | owned `Unflatten`: `from_fn` of `ptr::read` at `i * Q` | `Rem<M, Output = U0>` so `N = M*Q`; reads cover `0..N` exactly once; `checked_mul(...).expect` cannot fire for in-bounds `i`; `ptr::read` cannot panic, so no element is read twice on unwind; `ManuallyDrop` source. | sound |
| `src/flatten.rs:80-88` | borrowed `Unflatten`: `&*ptr.cast()` then `ptr.add(Q)` | parts within `self`; the final `add` reaches one-past-the-end, which is allowed. | sound |
| `src/sizes.rs:26` | `unsafe impl ArraySize for U<N>` (macro) | `ArrayType<T> = [T; N]` with `N == U<N>::USIZE` (552 checked; the macro also emits a test asserting it, `:34-41`). | sound |
| `src/traits.rs:22` | `pub unsafe trait ArraySize` | the declaration of the contract. | n/a |

`Zeroize for Array` (`src/lib.rs:1193-1203`, feature `zeroize`, on) forwards to the
element `Zeroize` impls through `iter_mut().zeroize()`, and the `ZeroizeOnDrop` marker
(`:1205-1211`) relies on each element zeroizing in its own `Drop`. Neither has `unsafe`.
The `subtle` impls (`:1158-1191`) are safe loops.

## Concerns

None under the concern rule.

**Discretion:** the tarball ships upstream CI files (`.github/workflows/*.yml`,
`.github/dependabot.yml`, `.codecov.yml`). They are configuration for upstream's GitHub
repository, are not referenced by `Cargo.toml`, and are never compiled or run by a
dependent's build (same precedent as `untrusted` 0.9.0, B3).

## Not claimed

Cryptographic correctness, constant-time behaviour (including the `subtle` impls),
side-channel resistance.
