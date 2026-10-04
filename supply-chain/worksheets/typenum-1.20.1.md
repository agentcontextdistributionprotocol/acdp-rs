# Review worksheet: `typenum` 1.20.1 (issue #339, Tier B batch B4)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "1.20.1"`). No concern-rule
  trigger. One `Discretion:` line records the generated test file.
- **Read vs sampled.** This is a 19,354-line crate, about 64% of it generated. Not every line
  was read by eye. The Method section states exactly what was read in full, what was
  checked mechanically (and how), and what was only sampled.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 1.20.1 (locked) | `b6f5e870be6c3b371b77fe0ee0bafb859fa4964b4404c27de1d380043c4dda20` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is identical (`diff -r`; only cargo's
`.cargo-ok` marker differs) to the `~/.cargo/registry/src` copy that was read. Reproduce the
facts with `scripts/vet-facts.sh typenum 1.20.1`. The root lockfile and all three binding
lockfiles lock 1.20.1 with this checksum. `.cargo_vcs_info.json`: upstream commit
`0db9a0f731981f29266b63586c29fa07e4477b1a`.

## Method

- No prior audit of `typenum` exists, so **full**.
- **Exhaustive greps over all of `src/`** (19,354 lines): `unsafe`, `transmute`, `asm!`,
  `extern`, `include`, `env!`, `std::`, raw pointers (`*const`/`*mut`), `no_mangle`,
  `link`, `export_name`, `static` items, `macro_export`, `proc_macro`, and every `cfg` /
  `cfg_attr`. Results: no `unsafe`, `asm!`, `transmute`, raw pointer, `static` item, FFI
  attribute, `include_*` or `std::` use; `extern` appears only as
  `#[macro_use] extern crate typenum;` inside doc examples; `cfg` conditions are limited to
  features `i128`, `const-generics`, `scale_info`, `strict`, plus `docsrs`, `test` and
  `target_pointer_width`.
- **Read in full:** `Cargo.toml` and `.orig`, `src/lib.rs` (173), `src/marker_traits.rs`
  (189), `src/gen.rs` (4), `src/tuple.rs` (158), and all six `#[macro_export]` macros:
  `assert_type_eq!` (`src/lib.rs:132-138`), `assert_type!` (`src/lib.rs:141-147`),
  `tarr!` (`src/array.rs:43-52`), `cmp!` (`src/type_operators.rs:535-578`), `op!` and
  `__op_internal__!` (`src/gen/op.rs:322-1030`). Also read: the `impl_pow_f!` /
  `impl_pow_i!` generators (`src/type_operators.rs:92-240`).
- **Generated files, checked mechanically and exhaustively** (Python script over the whole
  file, not sampled):
  - `src/gen/consts.rs` (6,567 lines): after the doc header and four `use` lines, the file
    is exactly 3,440 `pub type <Name> = <type>;` statements whose right-hand sides contain
    only the tokens `UInt`, `UTerm`, `B0`, `B1`, `PInt`, `NInt`, `U<digits>`, `<`, `>`, `,`.
    All 1,148 `U<n>` aliases were decoded from their `UInt<..., B0|B1>` nesting and equal
    `n`; every `P<n>`/`N<n>` is `PInt<U<n>>`/`NInt<U<n>>`; `True = B1`, `False = B0`.
  - `src/gen/generic_const_mappings.rs` (4,758 lines): after the header at lines 1-57 (doc,
    `use crate::*;`, `pub type U<const N: usize>`, `pub struct Const<const N: usize>`,
    `pub trait ToUInt`, read in full), every line is one of
    `impl ToUInt for Const<N> {`, `    type Output = U<N>;` (with the same `N`), `}`, blank,
    or one of two `#[cfg(target_pointer_width ...)]` attributes: 1,148 impls, 110 cfgs,
    0 other lines.
  - `src/gen/op.rs` (1,030 lines): lines 1-321 are the generated-code marker and the doc comment; the two macros were
    read; additionally a script confirmed the macro section contains no `unsafe`, `fn`,
    `impl`, `let`, `static`, `extern`, `include` or `env!`, and that its only `$crate::`
    paths are 26 type aliases from `src/operator_aliases.rs` (`AbsVal And Compare Cube Diff
    Eq Exp Gcf Gr GrEq Le LeEq Log2 Maximum Minimum Mod NotEq Or Prod Quot Shleft Shright
    Sqrt Square Sum Xor`). `op!` expands to a type expression only.
- **Hand-written type-level modules, runtime content extracted mechanically:**
  `src/uint.rs` (2,871), `src/int.rs` (1,528), `src/private.rs` (592),
  `src/type_operators.rs` (626), `src/array.rs` (396), `src/bit.rs` (347),
  `src/operator_aliases.rs` (115, all `pub type` aliases). A script extracted the body of
  every `fn` and every `const` initialiser across the hand-written modules, skipping
  `#[cfg(test)]` modules, and every distinct body line was reviewed. The counts depend on
  the extraction method: this line-based brace counter found approximately 420 bodies,
  43 distinct initialisers and 318 distinct body lines (it also picks up some `#[test]`
  fns outside `cfg(test)` modules); an independent brace-aware extraction counted 413 and
  41. **Sampled, not each read:** the `impl` headers, `where` clauses and
  associated-type lines of those modules (type-level only; they generate no runtime code
  beyond the bodies above).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0, including all six exported macros and all generated code (grep of the full source, comment lines excluded; the grep is the evidence). `#![forbid(unsafe_code)]` at `src/lib.rs:43` is only a corroborating hint (cargo builds registry deps with `--cap-lints allow`). |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`). The CHANGELOG records that the old build script was replaced by checked-in generated code; the generator is the upstream workspace member `generate` (`Cargo.toml.orig:32`), which is not in the tarball. |
| proc-macro | no |
| Powerful imports | none. `#![no_std]` (`src/lib.rs:42`), no `alloc`, no `include_*`, `env!`, `std::{fs,net,process,env}`. |
| Binary content | none |
| Generated test file | `tests/generated.rs` (21,247 lines, `// THIS IS GENERATED CODE`): integration test only, not compiled into any non-test build. Grep found no `unsafe`, `include` or `std::{fs,net,process,env}`. Recorded as a discretion line. |
| Dependencies | optional `scale-info` 1.0 (feature `scale_info`, off in ACDP). No other dependencies. |
| Features ACDP enables | `const-generics` (root `--all-features`) |
| Reached via | `hybrid-array` 0.4.14 only (`cargo tree -i typenum -e normal`) |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour (what runs at run time)

- Every type is a zero-sized marker (`B0`, `B1`, `UTerm`, `UInt<U, B>`, `PInt`, `NInt`,
  `Z0`, `ATerm`, `TArr`, `Greater`/`Less`/`Equal`). The `fn` bodies (approximately 420) are constructors
  (`UInt::new()`, `PInt::new()`, struct literals), forwards to other type operators,
  `Ordering` constants, `Debug`/`Binary` `write!` impls, and conversions
  (`to_u8`..`to_isize` built as `B::to_u8() | U::to_*() << 1`).
- The associated constants (`U8`, `USIZE`, `I32`, ...) are computed in `const` context; an
  overflow there is a compile error, not a run-time fault.
- `src/tuple.rs`: `Len` and `Index`/`IndexMut<U0..U11>` for tuples up to 12 elements; the
  index impls bind by pattern (`let (.., $t, ..) = self; $t`), no arithmetic.
- `src/type_operators.rs:92-240`: `Pow` for `f32`/`f64` (square-and-multiply loop) and for
  primitive integers (`self.pow(n)`); integer overflow there is an ordinary debug-build
  panic.
- Exported macros expand only to type expressions (`op!`, `tarr!`, `cmp!`) or to
  `const _: PhantomData<...> = PhantomData;` type assertions (`assert_type_eq!`,
  `assert_type!`).

## Concerns

None. No `unsafe`, no I/O, no build-time code, and no run-time code beyond trivial
constructors and conversions.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, and the
arithmetic correctness of the type-level operators.
