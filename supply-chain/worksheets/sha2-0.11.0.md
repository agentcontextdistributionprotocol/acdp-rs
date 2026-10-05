# Review worksheet: `sha2` 0.11.0 (issue #322, Phase 2)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.11.0"`), with
  recorded discretion. Under the Policy 6 carve-out, S-1 is unreachable in any
  stable-toolchain build of any ACDP artifact. Fable decided this after independent
  verification, recorded in DECISIONS.md `322-sha2`. The audit notes carry two
  `Discretion:` lines, for S-1 and S-2.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"

The review was finished. Every `unsafe` site was read and has a verdict below.
- One opt-in backend contains code that is unsound for some inputs (finding S-1). It
  needs nightly (or stable with RUSTC_BOOTSTRAP=1, which is not a supported configuration) plus an explicit `--cfg`, so it is unreachable in every stable build.
- The backends that ACDP actually builds were found sound.

## Upstream status (2026-10-04)

- **S-1:** fixed upstream in RustCrypto/hashes#879. The fix ships in 0.11.1, which is
  unreleased.
- **S-2:** unfixed upstream. Reported on 2026-10-05 as RustCrypto/hashes#920, using the
  issue text below.

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.11.0 (locked) | `446ba717509524cb3f22f17ecc096f10f4822d76ab5c0b9822c5f9c284e825f4` | `Cargo.lock` checksum |
| 0.10.9 (prior audit) | `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` | crates.io index `cksum` |

To reproduce: `scripts/vet-facts.sh sha2 0.11.0 0.10.9`.

## Method

- Delta: 57 files, +2766/-1858. That is 4,624 changed lines against 3,151 `src/` lines, a
  ratio of 1.47, so the method rule says **full**.
- The backend tree was restructured. `sha256/{x86,aarch64,soft}.rs` became
  `x86_sha.rs`, `aarch64_sha2.rs`, and `soft/{unroll,compact}.rs`. New backends:
  `riscv_zknh`, `wasm32_simd128`, and `x86_avx2` (SHA-512).
- Every `src/` file was read in full. `tests/mod.rs` and `benches/mod.rs` were skimmed;
  they are test-only and not built into dependents.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 50 non-comment `unsafe` code lines. `vet-facts.sh` reports 53 raw hits, but 3 of them are asm-template comments (`// left = unsafe { ptr::read(bp) };`) at `sha256/riscv_zknh/utils.rs:51` and `sha512/riscv_zknh/utils.rs:51,101`. Verdicts below. |
| asm | `core::arch::asm!` in 4 files: `sha256/loongarch64_asm.rs`, `sha512/loongarch64_asm.rs`, `sha256/riscv_zknh/utils.rs`, and `sha512/riscv_zknh/utils.rs`. The x86, aarch64, and wasm backends use `core::arch` intrinsics only. |
| build.rs / proc-macro | none / no |
| Powerful imports | none. The crate is `#![no_std]`; the only `include_str!` is the README doc string. |
| Binary files | 18 changed: `tests/data/*.blb` / `*.bin` (KAT and serialization blobs, read by `tests/mod.rs` only). Not compiled into the library, so not a concern. |
| Dependencies | `digest` 0.10.7 becomes 0.11, `cpufeatures` 0.2 becomes 0.3, and `cfg-if` stays 1. **Removed:** `sha2-asm` and the `asm` / `asm-aarch64` / `loongarch64_asm` features, which drops the C/asm build dependency of 0.10.x. |
| Features ACDP enables | `alloc`, `default`, `oid`. Not `zeroize`, so the `Drop` impls in `block_api.rs:89-98/208-216` are no-ops. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Backend selection (`src/sha256.rs`, `src/sha512.rs`)

A `cfg_if!` chain chooses the backend:

1. A forced backend via `--cfg`. The cfg keys select these backends:
   - `soft`: `sha2_backend` or `sha2_256_backend`, in both files.
   - `riscv-zknh`: `sha2_backend` or `sha2_256_backend`, in both `sha256.rs:5` and
     `sha512.rs:5`. `sha2_512_backend` has no riscv-zknh arm, an upstream quirk.
   - `x86-sha` / `aarch64-sha2`: `sha2_256_backend`.
   - `x86-avx2` / `aarch64-sha3`: `sha2_512_backend`.

   Each
   forced SIMD backend is guarded by a `compile_error!` unless the matching
   `target_feature` is statically enabled, so the `unsafe` call is justified at compile
   time.
2. `target_arch = "loongarch64"`: inline asm, always used on that arch.
3. `wasm32` with `simd128`: intrinsics. Their availability is a compile-time
   `target_feature`.
4. Otherwise the **default** path. `soft` is compiled together with runtime dispatch:
   - **x86/x86_64:** `cpufeatures::new!(shani_cpuid, "sha","sse2","ssse3","sse4.1")`
     selects SHA-256 SHA-NI, and `cpufeatures::new!(avx2_cpuid, "avx2")` selects SHA-512
     AVX2. cpufeatures 0.3.1's `x86.rs` uses CPUID plus `xgetbv` for the ymm OS-support
     bit on AVX2.
   - **aarch64:** `sha2_hwcap` / `sha3_hwcap` select the backend. cpufeatures uses
     `getauxval` on Linux and `sysctlbyname` on Apple.
   - When detection is false, the backend falls back to `soft::compress`.

ACDP's builds (x86_64 Linux CI, aarch64 macOS dev, wasm32 binding) take path 4, or
path 3 on wasm with simd128 (otherwise soft). None of them takes path 1.

Non-security observations (they cause compile errors, not unsoundness):
- `sha256.rs:39` (forced `aarch64-sha2`) and `sha512.rs:24` (forced `x86-avx2`) declare
  the wrong `compress` signature, swapping u32/64-byte and u64/128-byte. That would fail
  to type-check if anyone enabled those cfgs.
- `lib.rs:13` repeats `sha2_256_backend` where `sha2_512_backend` was meant.

## `unsafe` sites and verdicts

| Site(s) | What | Verdict |
|---|---|---|
| `sha256.rs:16,31,41,67,72` and `sha512.rs:16,26,36,62,67` | Calls into `#[target_feature]` `unsafe fn compress`. | **Sound.** Each call is preceded by a `compile_error!` static target-feature check (forced) or a cpufeatures runtime check (default). |
| `sha256/x86_sha.rs:14,46` | SHA-NI `schedule` / `compress`. `_mm_loadu_si128` from `state.as_ptr().cast()` at offsets 0 and 1 (32 bytes of `[u32;8]`), and from `block.as_ptr().cast()` at offsets 0..3 (64 bytes of `[u8;64]`). Stores mirror the loads. `K32X4[$i]` is bounds-checked indexing (`$i` <= 15 of 16). | **Sound.** All loads and stores are unaligned (`loadu`/`storeu`) and stay inside the referenced arrays. |
| `sha256/aarch64_sha2.rs:13` | NEON SHA2 `compress`. `vld1q_u32(state[0..4].as_ptr())` and `vst1q_u32(..)` are in bounds. `vld1q_u8(block[a..a+16].as_ptr())` is in bounds. `vld1q_u32(&K32[t])` for t in {0,4,..,60} reads `K32[t..t+4]` of the 64-element `static`. | **Sound in practice** (observation S-2). |
| `sha512/aarch64_sha3.rs:11` | NEON SHA3 `compress`. Same structure; `vld1q_u64(&K64[t])`, with t <= 78, reads `K64[t..t+2]` of 80 elements. | Same as above (S-2). |
| `sha512/x86_avx2.rs:18,47,60,82,115,136,243` | AVX/AVX2 SHA-512. `compress` handles an odd leading block with the 128-bit path, then processes pairs: `blocks.as_ptr().add(i)` reads `data.add(0..8)` and `data.add(8..16)`, that is, blocks i and i+1. Because `start_block` makes the remaining count even, `i+1 < len`. `K64.as_ptr().add(k)` with k <= 78 reads 2 u64 out of 80; `K64` is a promoted `const` array. `t2[8*i+j]` stays at or below 39 of 40 (safe indexing). | **Sound.** |
| `sha512/x86_avx2.rs:330,335` | `cast_ms`: `&[__m128i;8]` to `&[u64;16]`. `cast_rs`: `&[__m128i;40]` to `&[u64;80]`. | **Sound.** The sizes are identical, the alignment of u64 (8) is at most that of __m128i (16), and every bit pattern is a valid u64. |
| `sha256/soft/unroll.rs:39` and `sha512/soft/unroll.rs:33` | `rk(i)`: `K.as_ptr().add(i)` with `ptr::read` / `read_volatile`, where `i` is the literal 0..63 (or 0..79) from `repeat64!` / `repeat80!`. | **Sound.** The index is in bounds; the volatile read is only a codegen hint. |
| `sha256/wasm32_simd128.rs:20,31,50,141` and `sha512/wasm32_simd128.rs:18,29,48,135` | simd128 `v128_load` from `block.as_ptr().cast()` at offsets 0..3 (or 0..7), and from `K.as_ptr().add(..)`, which stays in bounds by the same index arithmetic as AVX2. | **Sound.** `v128_load` permits unaligned access; the feature is static (`compile_error!`). |
| `sha256/loongarch64_asm.rs:89` and `sha512/loongarch64_asm.rs:88` | Inline asm. `blocks.is_empty()` returns early, as in 0.10.9, so the loop never runs with a zero count. Scratch space is `addi.d $sp,-64/-128`, restored afterwards. `nostack` is not claimed, so the stack adjustment is permitted. Loads stay in `state` / `blocks` (`$a1 += 64/128`, `$a2` counts the blocks) and `K32`/`K64`. Every clobbered register is declared, and `preserves_flags` is set. | **Sound** (by reading; not run on hardware). |
| `sha256/riscv_zknh/utils.rs:18` and `sha512/riscv_zknh/utils.rs:16,32` | Aligned block loads after an `is_aligned()` check. | **Sound.** |
| `sha256/riscv_zknh/utils.rs:49-77` and `sha512/riscv_zknh/utils.rs:49-77,99-126` | Unaligned block loads (`load_unaligned_block`). | **UNSOUND for some inputs (S-1).** Unreachable in any stable build: discretion recorded. |
| `sha*/riscv_zknh/utils.rs` `opaque_load` (sha256 :87, sha512 :138,150) | `assert!(R < k.len())` precedes an asm load at `R*4` (or `R*8`, plus +4 on rv32). | **Sound.** |

## Findings

### S-1 (discretion; would block without the Policy 6 carve-out): out-of-allocation pointer arithmetic in the riscv-zknh backend

`src/sha256/riscv_zknh/utils.rs:44,61` and `src/sha512/riscv_zknh/utils.rs:44,61,94,110`.

How it goes wrong:
- `load_unaligned_block` computes `bp = block.as_ptr().wrapping_sub(offset)`, which rounds
  down to word alignment. It then performs `ptr::read(bp.add(1 + i))`.
- `<*const T>::add` requires `bp` itself to lie inside the allocation.
- If the 64- or 128-byte block starts fewer than `offset` bytes into an allocation whose
  base is not word-aligned (for example, a stack `[u8; N]` at an odd address passed to
  `Sha256::update`), then `bp` points before the allocation. The `add` is then Undefined
  Behaviour, even though every word actually read lies within the block.
- The bracketing `asm!` loads at `0(bp)` and `16*4(bp)` also touch up to 3 (or 7) bytes
  outside the block. The code accepts that because aligned words cannot cross a page.

Reachability:
- Only with `--cfg sha2_backend="riscv-zknh"` or `--cfg sha2_256_backend="riscv-zknh"`.
  These are the only keys that select it, in both `sha256.rs:5` and `sha512.rs:5`.
- That cfg turns on `#![feature(riscv_ext_intrinsics)]` (`lib.rs:9-16`), so it needs
  **nightly (or stable with RUSTC_BOOTSTRAP=1, which is not a supported configuration)**.
- No Cargo feature enables it, so it is unreachable in ACDP's builds and in any
  stable-toolchain build.

The fix is to use `wrapping_add`, or to compute from `block.as_ptr()` with `read_unaligned`.

### S-2 (non-blocking observation): pointer to one array element used for a 16-byte load

- **Where:** `src/sha256/aarch64_sha2.rs:33-80` (`vld1q_u32(&K32[t])`) and
  `src/sha512/aarch64_sha3.rs:39-153` (`vld1q_u64(&K64[t])`).
- **What happens:** the pointer comes from a reference to **one** element, and the load
  reads 4 (or 2) elements.
- **Why it is not a memory-safety problem:**
  - The access stays inside the 256-byte (or 640-byte) `static`/`const` allocation.
  - The allocation is immutable, so no conflicting write can exist.
  - The pattern is an error only under the Stacked Borrows model. Tree Borrows accepts
    accesses outside the range of the originating reference, and the Rust Reference
    leaves the aliasing rules undetermined.
- **History:** 0.10.9, which we audited in 2026-07, used the identical pattern
  (`sha2-0.10.9/src/sha256/aarch64.rs:44`).
- **Reachability:** it is on the **default** path on aarch64 (Apple Silicon, Graviton)
  whenever the SHA2 or SHA3 hwcap is present.
- **Upstream fix:** `K32[t..].as_ptr()`.

### Other notes

- `block_api.rs`:
  - `update_blocks` uses `Array::cast_slice_to_core` (hybrid-array, Tier B) to view
    `&[Array<u8, U64>]` as `&[[u8; 64]]`.
  - `finalize_variable_core` pads through `digest`'s `Buffer::len64_padding_be` /
    `len128_padding_be` (Tier B).
  - Serialization is safe code with fixed-size `split`.
- The `zeroize` feature only zeroizes the state in `Drop`, and ACDP does not enable it.

## Not claimed

The review does not claim:
- that any backend computes SHA-2 correctly;
- constant-time behaviour;
- side-channel resistance.

As behavioural evidence only, ACDP's `sig-001` / `can-001` golden vectors pin
`content_hash` (SHA-256) on the backends that CI exercises.

These Tier B crates remain exempted: `digest 0.11.3`, `block-buffer 0.12.1`,
`cpufeatures 0.3.1`, `hybrid-array 0.4.14`, and `crypto-common 0.2.2`.

## Upstream issue: RustCrypto/hashes (S-2). Filed 2026-10-05 as RustCrypto/hashes#920.

> **Title:** sha2 0.11.0 aarch64 backends load 16 bytes through a one-element reference
> (`vld1q_u32(&K32[t])`)
>
> In `src/sha256/aarch64_sha2.rs` (lines 33-80), the round constants are loaded with
> `vld1q_u32(&K32[t])`. The same pattern appears in `src/sha512/aarch64_sha3.rs`
> (lines 39-153) as `vld1q_u64(&K64[t])`. The pointer comes from `&K32[t]`, a reference
> to a single `u32`, but the intrinsic reads four elements.
>
> The read stays inside the `static` table, so this is not an out-of-bounds access in
> practice. Under Stacked Borrows, however, the derived pointer's provenance covers only
> the one element, so Miri (SB) would report it. 0.10.x had the same pattern.
>
> Suggested fix: `vld1q_u32(K32[t..].as_ptr())` and `vld1q_u64(K64[t..].as_ptr())`,
> which carry provenance for the rest of the table.
>
> Separately: will 0.11.1 ship #879, the riscv-zknh `load_unaligned_block`
> `wrapping_sub`/`add` fix? Is there a planned release date?
