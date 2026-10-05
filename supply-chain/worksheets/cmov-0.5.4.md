# Review worksheet: `cmov` 0.5.4 (issue #339, Tier B batch B6)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.5.4"`). No concern-rule
  trigger.
- **Constant-time behaviour is NOT claimed, and neither is it claimed that the `asm!`
  "implements what it says" in the constant-time sense.** `cmov` is a constant-time
  conditional-move crate. This audit says only that its `unsafe` and `asm!` are memory-safe
  and that the operand/option declarations of every `asm!` are consistent with the
  instructions used. Whether the generated code is branch-free or constant-time was not
  assessed. The soundness arguments below rely only on architectural (ISA) semantics: a
  `CMOVcc` / `CSEL` always leaves one of its two operands in the destination.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.5.4 (locked) | `0c9ea0ac24bc397ab3c98583a3c9ba74fa56b09a4449bbe172b9b1ddb016027a` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`,
its sha256 matches, and that extracted tree (`diff -r`-identical to the
`~/.cargo/registry/src` copy apart from cargo's `.cargo-ok` marker) is what was read.
Reproduce with `scripts/vet-facts.sh cmov 0.5.4`. The root and all three binding
lockfiles lock 0.5.4 with this checksum.

## Method

- No prior audit, so **full**.
- `src/` is 1,702 lines; **all of it was read line by line** (including the `#[cfg(test)]`
  modules): `src/lib.rs` (337), `src/macros.rs` (63), `src/array.rs` (29),
  `src/slice.rs` (547), `src/backends.rs` (17), `src/backends/x86.rs` (220),
  `src/backends/aarch64.rs` (181), `src/backends/soft.rs` (308). Also `Cargo.toml`.
- `tests/core_impls.rs` (379), `tests/proptests.rs` (128), `tests/regression.rs` (50) were
  grep-scanned: no `unsafe`, no `std::{fs,net,process,env}`, no includes.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 25 (`vet-facts.sh`; a `\bunsafe\b` grep finds 26 because it also matches `#![allow(clippy::undocumented_unsafe_blocks)]` at `src/lib.rs:8`). Every site has a verdict below. No `forbid(unsafe_code)`. |
| asm | 7 `asm!` invocations in 3 files: `src/backends/x86.rs:16`, `:33`; `src/backends/aarch64.rs:8`, `:27`; `src/backends/soft.rs:151` (arm), `:167` (riscv32), `:189` (riscv64). |
| build.rs / proc-macro | none / no |
| Powerful imports | none. `#![no_std]`; `include_str!("../README.md")` for docs only. |
| Dependencies | none (dev-only: `proptest`) |
| Features ACDP enables | none (the crate has no features) |
| Reached via | `ctutils` 0.4.2 only (`cargo tree -i cmov`), which reaches `crypto-bigint`, `digest`, `sec1`. ACDP has no direct use. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Which backend each ACDP artifact compiles

`src/backends.rs:4-17`: `x86` module on `x86`/`x86_64`, `aarch64` module on `aarch64`
(both `not(miri)`); `soft` otherwise. `soft` has `asm!` only for `arm`, `riscv32`,
`riscv64`.

| Artifact / target | Backend | `asm!` compiled |
|---|---|---|
| root crate, CI Linux/Windows x86_64; py/node wheels x86_64 (linux-gnu, apple-darwin) | `x86` | `x86.rs:16`, `:33` (64-bit `u64` impls at `:100-112`, `:194-220`) |
| CI macOS (aarch64), py/node wheels aarch64 (apple-darwin, linux-gnu) | `aarch64` | `aarch64.rs:8`, `:27` |
| `bindings/acdp-wasm` (wasm32-unknown-unknown) | `soft`, pure-Rust `masknz!` path (`soft.rs:125-140`) | none |
| 32-bit x86 (not built by ACDP CI/release; possible for crates.io users) | `x86` with `u64` split into two `u32` (`x86.rs:74-98`, `:168-192`) | `x86.rs:16`, `:33` |
| arm / riscv (not built by ACDP) | `soft` with asm mask | `soft.rs:151` / `:167` / `:189` |

## `asm!` sites: operands, options, instruction semantics

| Site | Instructions | Operands / options | Verdict |
|---|---|---|---|
| `x86.rs:13-26` (`cmov!`, used for `u16`/`u32` with `{1:e},{2:e}` and x86_64 `u64` with `{1:r},{2:r}`) | `test {0},{0}` then `cmovnz`/`cmovz {1},{2}` | `in(reg_byte) condition` (8-bit `test`), `inlateout(reg) *dst`, `in(reg) *src`; `options(pure, nomem, nostack)`. No memory operand (`nomem` correct); no stack use (`nostack` correct); flags are written by `test`, and `preserves_flags` is **not** claimed, so the flags clobber is declared. `inlateout` is read before it is written. For `u16`, the 32-bit `cmov` reads/writes the full register; only the low 16 bits are taken as output. | sound |
| `x86.rs:28-46` (`cmov_eq!`) | `xor {0},{1}` (width `:x` for u16, `:e` u32, `:r` u64) then `cmovz`/`cmovnz {2:e},{3:e}` | `inout(reg) *lhs => _` (scratch, discarded), `in(reg) *rhs`, `inlateout(reg) tmp` (u16 copy of `*output`), `in(reg) condition` (u16); `pure, nomem, nostack`, flags clobber declared. The `xor` width matches the type, so unspecified upper register bits of narrow inputs do not affect ZF. Output is masked `& 0xFF` back to `u8`. | sound |
| `aarch64.rs:5-19` (`csel!`, via `csel32!`/`csel64!`) | `tst {0:w|x}, 0xff` then `csel {1},{2},{3},NE|EQ` | `in(reg) condition` (u8; `tst ... 0xff` looks only at the low byte, so unspecified upper bits are ignored), `inlateout(reg) *dst`, `in(reg) *src`, `in(reg) *dst`; `pure, nomem, nostack`; NZCV clobber declared (no `preserves_flags`). | sound |
| `aarch64.rs:22-43` (`cseleq!`, via `cseleq16/32/64!`) | `eor {0},{1},{2}`; `tst {0:w},0xffff` (u16) or `cmp {0},0` (u32/u64); `csel {3},{4},{5},NE|EQ` | `out(reg) _` scratch (not `lateout`, so it cannot alias the inputs read by the same `eor`), `in(reg) *lhs`, `in(reg) *rhs`, `inlateout(reg) tmp`, `in(reg) condition`, `in(reg) tmp`; `pure, nomem, nostack`; flags clobber declared. The u16 variant masks with `0xffff`, handling unspecified upper bits. | sound |
| `soft.rs:147-160` (arm only) | `rsbs mask, cond, #0`; `sbcs mask, mask, mask` | `lateout(reg) mask`, `in(reg) condition`; `nostack, nomem`; flags clobber declared. Yields `0` or `u32::MAX`. Not compiled for any ACDP artifact. | sound |
| `soft.rs:163-176` (riscv32 `masknz32`), `:185-198` (riscv64 `masknz64`) | `seqz`; `addi -1` | `lateout(reg)`, `in(reg)`; `nostack, nomem`; no flags on RISC-V. Not compiled for any ACDP artifact. | sound |

`pure` is used only with `nomem` and register outputs that are a function of the inputs, as
required.

**Hardware availability.** `CMOVcc` needs a P6-class (i686) CPU; Rust's `i586` targets lack
it. ACDP builds no i586 artifact; an i586 user build would fault with `#UD`
(SIGILL). `CSEL`, `EOR`, `TST`, `CMP` are base AArch64.

## Other `unsafe` sites

| Site | What | Invariant and argument | Verdict |
|---|---|---|---|
| `src/lib.rs:280` | `NonZero*::new_unchecked(n)` after `n.cmovnz(&src.get(), c)` | `n` starts as `self.get()` (non-zero); the integer `cmovnz` leaves either that value or `src.get()` (non-zero). All integer backends return exactly one operand: `x86`/`aarch64` by ISA semantics, `soft` because `masknz!` yields `0` or `MAX` and `masksel` is `(a & !m) | (b & m)`. The `u8` and `u128` impls (`:74-114`) apply the same `condition` to every part, so no mixing occurs. | sound |
| `src/lib.rs:326-328` | `Ordering` written from `i8` via a pointer cast | `n` is `*self as i8` or `*src as i8` (same reasoning), i.e. -1, 0 or 1; `Ordering` is `#[repr(i8)]`; both have size and align 1. | sound |
| `src/slice.rs:170-171` (macro `impl_cmov_with_cast!`, instantiated at `:180-200`) | `&mut [Src]` / `&[Src]` reinterpreted as `[Dst]` for `cmovnz` | Size and align equality are `const`-asserted (`:165`, `:313-314`, `:333-334`). Signed -> unsigned is valid for all bit patterns. For `NonZero*` -> int and `Ordering` -> `i8` (-> `u8`), each element's **final** value is a whole element taken from `self` or `value`: the word-chunked `[u8]`/`[u16]` paths (`:38-116`) select whole words and store each element once, and the remainder goes through `slice_to_word` / `cmovnz` / `word_to_slice` (`:365-405`), which round-trips exactly. **Intermediate state:** `word_to_slice` (`:399-403`) first stores `T::from(0u8)` into each remainder element and then ORs its bytes in, so through the integer view a `NonZero*` remainder element briefly holds 0 (or, for 16-bit and wider elements, a partial value that can be 0). This is not UB: during that window the original `&mut [NonZero*]` / `&mut [Ordering]` is reborrowed by the integer view and nothing reads the memory at the `NonZero`/`Ordering` type; every element is valid again before `cmovnz` returns and the original borrow can be used. (For `Ordering`, 0 is `Equal` and valid anyway.) | sound |
| `src/slice.rs:270-271` (macro `impl_cmoveq_with_cast!`, `:280-300`) | shared reinterpretation for `cmovne` | read-only; same size/align assertions. | sound |
| `src/slice.rs:311-324`, `:331-344` | `unsafe fn cast_slice` / `cast_slice_mut` | Private; slice pointer cast keeps the length; size/align equal by `const` assertion; callers above supply valid-typed pairs. | sound |
| `src/slice.rs:425`, `:446` | `split_at_unchecked` / `split_at_mut_unchecked(len / N * N)` | `len / N * N <= len`; `N != 0` asserted first (`:421`, `:442`). | sound |
| `src/slice.rs:428`, `:449`, `:462-471`, `:482-491` | `slice_as_chunks_unchecked(_mut)`: `from_raw_parts(ptr.cast::<[T; N]>(), len / N)` | Called only on the prefix whose length is a multiple of `N`; `[T; N]` has `T`'s alignment and size `N * size_of::<T>()`. | sound |

The `[u8]` `cmovne` short-circuit on unequal lengths (`slice.rs:213-216`) is a
documented variable-time path, not a safety issue.

## Concerns

None under the concern rule.

## Not claimed

Cryptographic correctness, **constant-time behaviour**, branch-freedom of the generated
code, side-channel resistance. CVE-2026-23519, cited in the source comments
(`src/macros.rs:13`, `src/backends/soft.rs:5`, `:146`) as a compiler-inserted branch in the
portable mask path, concerns constant-time behaviour, which this audit does not assess.
