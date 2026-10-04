# Review worksheet: `zeroize` 1.9.0 (issue #322, Phase 2)

- **Verdict:** NOT CERTIFIED. KEPT EXEMPT under the #322 concern rule. See DECISIONS.md
  `322-zeroize` (`Needs: Fable decision`).
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"

The review was finished. Every `unsafe` site was read and has a verdict below. It is held
back because the new `optimization_barrier`, a safe public function, can read
uninitialized memory as `u8` on targets without stable `asm!` (finding Z-1). That is
unsound. The asm path that ACDP's native builds take is sound.

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 1.9.0 (locked) | `e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e` | `Cargo.lock` checksum |
| 1.8.2 (prior audit) | `b97154e67e32c85465826e8bcc1c59429aaaf107c1e4a9e53c8d8ccd5eff88d0` | crates.io index `cksum` |

To reproduce: `scripts/vet-facts.sh zeroize 1.9.0 1.8.2`.

## Method decision: full, under the rewrite clause

- **Ratio.** The delta is 12 files, +574/-194 (excluding Cargo.lock and the other
  exclusions). That is 768 changed lines against 1,061 `src/` lines, a ratio of **0.72**.
  This is below 0.75, so the numeric rule alone says *delta*.
- **Rewrite clause.** Full was chosen under the clause, as the plan decided. The delta
  replaces the crate's core erasure guarantee: `atomic_fence()`, which was
  `compiler_fence(SeqCst)`, is removed. A new `optimization_barrier` replaces it after
  **every** volatile write site: 12 of the 17 unsafe lines sit next to it, plus the SIMD
  impls. The barrier introduces the crate's **only** `asm!` (`src/barrier.rs`) and a
  `read_volatile` fallback. `zeroize_stack` (`src/stack.rs`) is new too.
- **Base notes.** The 1.8.2 base audit's notes are one line. Per Policy 2, a delta should
  not inherit them for a change to the core mechanism.
- **Cost.** The full read is 1,061 lines, barely more than the delta, so the full audit
  costs nothing extra.

Read in full: `src/lib.rs`, `src/barrier.rs`, `src/stack.rs`, `src/x86.rs`,
`src/aarch64.rs`, and `Cargo.toml`. The diff against 1.8.2 was also read hunk by hunk.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 17 (verdicts below) |
| asm | `src/barrier.rs:69`: `asm!("# {}", in(reg) ptr, options(readonly, preserves_flags, nostack))`. It is an empty asm body (a comment), used as a compiler barrier. It is gated on `not(miri)` and an arch in {aarch64, arm, arm64ec, loongarch64, riscv32, riscv64, s390x, x86, x86_64}. |
| build.rs / proc-macro | none / no. `zeroize_derive` 1.5 is the proc-macro companion: Tier B and exempted. |
| Powerful imports | none. The crate is `#![no_std]`, with `extern crate alloc/std` behind features. `std` is used only for `CString`. |
| Dependencies | `zeroize_derive` requirement 1.3 becomes 1.5; `serde` 1.0 becomes 1. Both are optional. |
| Features ACDP enables | `alloc`, `default`, `derive` (`zeroize_derive`) |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |
| API changes | `Zeroizing<Z: ?Sized>` is now `#[repr(transparent)]`. New items: `optimization_barrier` and `zeroize_stack`. The `__m512*` impls are no longer behind the `simd` feature. |

## `unsafe` sites and verdicts

| Site | What | Verdict |
|---|---|---|
| `lib.rs:736` `volatile_write` | `ptr::write_volatile(dst: &mut T, src)` with `T: Copy` | **Sound.** `dst` is a valid `&mut`. |
| `lib.rs:748-762` `volatile_set` | A loop of `dst.add(i)` and `write_volatile`, for `i < count` | **Sound under its documented contract.** Every caller satisfies it (below). |
| `lib.rs:387-393` (`Option<Z>`) | `volatile_set(self as *mut u8, 0, size_of::<Self>())` | **Sound.** The place is valid for `size_of::<Self>()` bytes with u8 alignment. Zero bytes are written after `take()`, and they are overwritten next. |
| `lib.rs:403` (`Option<Z>`) | `write_volatile(self, None)` | **Sound.** It restores a valid value. The old value was already dropped by `take()`. |
| `lib.rs:420` (`MaybeUninit<Z>`) | `write_volatile(self, MaybeUninit::zeroed())` | **Sound.** |
| `lib.rs:446` (`[MaybeUninit<Z>]`) | `volatile_set` over `len * size_of::<Z>()` bytes, using `checked_mul` and `isize::try_from` | **Sound.** |
| `lib.rs:472` (`[Z: DefaultIsZeroes]`) | `volatile_set(self.as_mut_ptr(), Z::default(), len)`, after `isize::try_from(len)` | **Sound.** |
| `lib.rs:481` (`str`) | `as_bytes_mut().zeroize()` | **Sound.** All-zero bytes are valid UTF-8. |
| `lib.rs:568` (`String`) | `as_mut_vec().zeroize()`. The Vec impl zeroizes, then `clear()`s, then zeroizes the spare capacity, leaving len 0. | **Sound.** |
| `lib.rs:814-823` `zeroize_flat_type` (`pub unsafe fn`) | `volatile_set(data as *mut u8, 0, size_of::<F>())` | **Sound under its documented contract.** See observation Z-2 for the barrier argument. |
| `x86.rs:16` and `aarch64.rs:13` | `volatile_write(self, mem::zeroed())` for `__m128/256/512*` and NEON vector types | **Sound.** These are plain-data SIMD types, so all-zero is valid. |
| `barrier.rs:68-73` | The empty `asm!` with a pointer input and `readonly`, no `pure` / `nomem` | **Sound.** No instructions run and nothing is written. Because the asm is neither `pure` nor `nomem`, the compiler must assume the pointed-to memory is read, so earlier writes to it cannot be elided or sunk past it. |
| `barrier.rs:92-100` | A non-asm fallback: `custom_black_box(p: *const u8) { read_volatile(p) }` on the first byte of `*val` | **UNSOUND (Z-1).** |

## Findings

### Z-1 (blocks certification): `optimization_barrier` fallback reads possibly-uninitialized memory as `u8`

**Where.** `src/barrier.rs:92-100`. On targets **outside** the asm list, and under Miri,
`optimization_barrier<T: ?Sized>(val: &T)` does this:

```rust
#[inline(never)]
fn custom_black_box(p: *const u8) {
    let _ = unsafe { core::ptr::read_volatile(p) };
}
core::hint::black_box(val);
if size_of_val(val) > 0 {
    custom_black_box(core::ptr::from_ref(val).cast::<u8>());
}
```

**Why it is UB.** `read_volatile::<u8>` produces a `u8`. If byte 0 of `*val` is
uninitialized, the read is Undefined Behaviour (an integer from uninit memory, per the
Rust Reference). Byte 0 is uninitialized for:
- padding;
- `MaybeUninit`;
- the payload bytes left after a typed write of an enum variant.

`optimization_barrier` is a **safe `pub fn`**, so safe code can trigger this. For
example: `zeroize::optimization_barrier(&core::mem::MaybeUninit::<u8>::uninit())` on
`wasm32-unknown-unknown`.

**Reachable inside the crate.** `impl Zeroize for Option<Z>` (`lib.rs:403-405`) performs
`write_volatile(self, None)` and then `optimization_barrier(self)`. A typed write of
`None` leaves the non-`None` payload bytes uninitialized. If the layout puts payload
rather than the tag or niche at offset 0, the fallback read is UB.

**Not in 1.8.2.** That version used `compiler_fence(SeqCst)`, which reads nothing.

**Reachability for ACDP.**
- Native builds (x86_64 and aarch64) use the sound asm path.
- `bindings/acdp-wasm` builds for wasm32, which uses the fallback. It resolves zeroize
  1.9.0 too, though the bindings are not vet-gated.
- The ACDP secret paths zeroize `[u8; 32]` arrays (ed25519-dalek `SigningKey`), whose
  byte 0 is initialized zeros after the write. So no known ACDP call site hits the UB,
  but the crate-level claim cannot be made.
- In practice LLVM is unlikely to miscompile a discarded volatile byte load. The finding
  is still a Rust-level soundness defect in a safe API.

**Fix for upstream.** Use `black_box` alone, or read through `MaybeUninit<u8>`
(`read_volatile(p.cast::<MaybeUninit<u8>>())`).

### Z-2 (non-blocking observation): `zeroize_flat_type` puts the barrier on the pointer variable

`src/lib.rs:823` calls `optimization_barrier(&data)`, where `data: *mut F`. That takes a
reference to the local pointer, not to the pointee. The erasure itself is still
guaranteed, because `volatile_set` performs volatile writes, which cannot be elided. The
barrier there is redundant rather than harmful. This is not a soundness issue.

### Erasure semantics vs. 1.8.2

- Volatile writes are unchanged. They remain the guarantee that the zeroing is not
  optimized away.
- The `SeqCst` compiler fence is replaced by the asm barrier on asm targets. That barrier
  is at least as strong for the zeroed object, since it forces the compiler to treat the
  bytes as read after the writes.
- On non-asm targets the barrier is `black_box` plus the Z-1 volatile read.

## Not claimed

The review does not claim:
- that zeroization is complete (copies via moves or reallocation are documented upstream
  as out of scope);
- constant-time behaviour;
- side-channel resistance.

`zeroize_derive 1.5.0` remains exempted (Tier B).
