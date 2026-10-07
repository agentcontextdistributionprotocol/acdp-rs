# Review worksheet: `zeroize` 1.9.1 (issue #341, exit criterion of `322-zeroize`)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "1.9.1"`), with one
  `Discretion:` line under the Policy 6 carve-out (observation Z-3 below). Finding Z-1 of
  the 1.9.0 review is fixed. The `[[exemptions.zeroize]]` entry and the guard marker
  `allow-exempt:DECISIONS#322-zeroize@1.9.0` are removed.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-07
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"; exit criterion in
  DECISIONS.md `322-zeroize`.

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 1.9.1 (locked) | `e13084392c5e4bc371903e2935a5eaeed24905a7511356b883835e18a78f6879` | `Cargo.lock` checksum (root and py/node/wasm binding locks identical) |
| 1.9.0 (previous lock, reviewed in full, exempt) | `e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e` | crates.io index `cksum` |
| 1.8.2 (prior audit, 2026-07-05) | `b97154e67e32c85465826e8bcc1c59429aaaf107c1e4a9e53c8d8ccd5eff88d0` | crates.io index `cksum` |

All three tarballs were also downloaded from `static.crates.io` independently of
`scripts/vet-facts.sh`, and their sha256 values match the table. The diffs that were read
were produced from the extracted trees. Reproduce the facts with
`scripts/vet-facts.sh zeroize 1.9.1 1.9.0` and `scripts/vet-facts.sh zeroize 1.9.1 1.8.2`.

1.9.1 was released 2026-10-06. Its CHANGELOG lists RustCrypto/utils#1497 (opaque `Debug`
for `Zeroizing`), #1535 (internal callers of `optimization_barrier` removed), #1525 (no
double zeroization in `Vec`), #1538 (test-only), and #1551 (the Z-1 fix; merged
2026-10-06, closing our report RustCrypto/utils#1549).

## Method decision: full audit of 1.9.1

- **No valid delta base at 1.9.0.** Issue #341 and the `322-zeroize` exit criterion say
  "delta-audit 1.9.0 -> 1.9.1", but 1.9.0 was never certified (it was exempt), so a
  `delta = "1.9.0 -> 1.9.1"` entry would chain onto an unaudited version and `cargo vet`
  would not count 1.9.1 as vetted. Moving the exemption is not allowed (Policy 7).
- **The audited base is 1.8.2.** `vet-facts.sh zeroize 1.9.1 1.8.2`: 12 files, +619/-203,
  822 changed lines against 1,061 `src/` lines, a ratio of **0.77**. That is above 0.75,
  so the method rule says **full**. (The rewrite clause, applied for the same base in the
  1.9.0 review, points the same way.)
- **What was read.** All 1,061 `src/` lines of 1.9.1 in full (`lib.rs` 850, `barrier.rs`
  104, `stack.rs` 52, `x86.rs` 25, `aarch64.rs` 30), plus `Cargo.toml`. The 1.9.0 -> 1.9.1
  diff (8 files, +78/-42, ratio 0.11) was also read hunk by hunk and checked against the
  per-site verdicts of `supply-chain/worksheets/zeroize-1.9.0.md`, which was itself a full
  read with every `unsafe` site verdicted.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 17, the same sites as 1.9.0 (line numbers shift by the removed barrier calls). The one changed site is `src/barrier.rs:96` (Z-1 fix). |
| asm | `src/barrier.rs:69`, unchanged: `asm!("# {}", in(reg) ptr, options(readonly, preserves_flags, nostack))`. An empty asm body used as a compiler barrier, gated on `not(miri)` and an arch in {aarch64, arm, arm64ec, loongarch64, riscv32, riscv64, s390x, x86, x86_64}. |
| build.rs / proc-macro | none (`build = false`) / no. |
| Powerful imports | none. `#![no_std]`; `alloc` / `std` behind features; `std` used only for `CString`; `include_str!` of README for docs. |
| Dependencies | unchanged: optional `serde` 1, optional `zeroize_derive` 1.5 (audited 1.5.0). |
| `Cargo.toml` delta | version bump; the clippy lint `from_iter_instead_of_collect` removed. `rust-version` stays 1.85 (ACDP MSRV 1.86). |
| Features ACDP enables | `alloc`, `default`, `derive` (root and all three bindings) |
| Advisories | `cargo deny check advisories`: ok on 2026-10-07 |

## `unsafe` sites and verdicts (1.9.1 line numbers)

| Site | What | Verdict |
|---|---|---|
| `lib.rs:736-738` `volatile_write` | `ptr::write_volatile(dst: &mut T, src)`, `T: Copy` | **Sound.** `dst` is a valid `&mut`. |
| `lib.rs:749-765` `volatile_set` | loop of `dst.add(i)` + `write_volatile`, `i < count` | **Sound under its documented contract**; every caller below meets it. |
| `lib.rs:385-391` (`Option<Z>`) | `volatile_set(self as *mut u8, 0, size_of::<Self>())` after `take()` | **Sound.** Valid for `size_of::<Self>()` bytes, u8 alignment; overwritten with `None` next. |
| `lib.rs:401` (`Option<Z>`) | `write_volatile(self, None)` | **Sound.** Restores a valid value; the old one was dropped by `take()`. The barrier call after it (the 1.9.0 Z-1 trigger) is gone. |
| `lib.rs:415` (`MaybeUninit<Z>`) | `write_volatile(self, MaybeUninit::zeroed())` | **Sound.** |
| `lib.rs:430-440` (`[MaybeUninit<Z>]`) | `volatile_set` over `len * size_of::<Z>()` bytes with `checked_mul` + `isize::try_from` | **Sound.** |
| `lib.rs:457-465` (`[Z: DefaultIsZeroes]`) | `volatile_set(self.as_mut_ptr(), Z::default(), len)` after `isize::try_from(len)` | **Sound.** |
| `lib.rs:473` (`str`) | `as_bytes_mut().zeroize()` | **Sound.** All-zero bytes are valid UTF-8. |
| `lib.rs:563` (`String`) | `as_mut_vec().zeroize()`; the `Vec` impl leaves len 0 | **Sound.** |
| `lib.rs:815-824` `zeroize_flat_type` | `pub unsafe fn`, `volatile_set(data as *mut u8, 0, size_of::<F>())` | **Sound under its documented caller contract.** The redundant barrier on the pointer variable (1.9.0 observation Z-2) is removed. |
| `x86.rs:16`, `aarch64.rs:13` | `volatile_write(self, mem::zeroed())` on SIMD register types | **Sound.** All-zero is a valid `__m*` / NEON value. |
| `barrier.rs:68-74` | empty `asm!` with the pointer as an input register | **Sound.** No instructions; `readonly`/`nostack`/`preserves_flags` are honest. |
| `barrier.rs:96` (non-asm fallback) | `read_volatile(p.cast::<MaybeUninit<u8>>())`, guarded by `size_of_val(val) > 0` | **Sound for any initialization state (Z-1 fixed).** `p` comes from a `&T` with non-zero size, so one byte is dereferenceable; alignment 1; a `MaybeUninit<u8>` may hold an uninitialized byte. See Z-3 for the remaining concurrency caveat. |

## Behaviour changes in 1.9.0 -> 1.9.1

- **Internal barriers removed (#1535).** Every `optimization_barrier(self)` after a
  volatile write is gone (`DefaultIsZeroes`, `NonZero*`, `Option`, `MaybeUninit`, both slice
  impls, SIMD impls, `zeroize_flat_type`). Erasure now rests on the volatile writes alone,
  which the compiler may not elide. 1.8.2 had volatile writes plus `compiler_fence(SeqCst)`;
  1.9.1 has volatile writes only. This is not a memory-safety change. Erasure efficacy is
  upstream's claim and is not claimed here (see *Not claimed*).
- The only remaining in-crate caller of `optimization_barrier` is `zeroize_stack`
  (`src/stack.rs:51`), which passes `&[0u8; N]`, a fully initialized local array with no
  interior mutability. `zeroize_stack` is safe; a large `N` can only overflow the stack
  (a guarded abort on native targets; on wasm32-unknown-unknown there is no guard page, but
  nothing calls `zeroize_stack`).
- **`Vec<Z>::zeroize` (#1525).** It now zeroizes the spare capacity first, then the
  initialized elements, then `clear()`s. Before, it zeroized elements, cleared, and then
  zeroized the whole capacity. Sound (`spare_capacity_mut` is `&mut [MaybeUninit<Z>]`).
  Hygiene difference: the bytes of elements left behind by their own `Drop` (for example
  the pointer/capacity words of an inner `Vec`) are no longer wiped after `clear()`. ACDP's
  secret paths do not zeroize a `Vec` of droppable elements.
- **`Zeroizing<Z>` Debug (#1497).** The derived `Debug` (which printed the secret) is
  replaced by an opaque `Zeroizing { .. }` impl for every `Z`. A hardening; no `unsafe`.
- `tests/alloc.rs` (#1538) is test-only and not compiled into any ACDP artifact.

## Findings

### Z-1 (1.9.0 blocker): fixed

The 1.9.0 fallback did `read_volatile(p)` with `p: *const u8`, which produces a `u8` from a
possibly-uninitialized byte. 1.9.1 reads `MaybeUninit<u8>` (`src/barrier.rs:93-97`), which
is valid for any byte. In addition, no crate-internal code path calls the barrier on data
that could be uninitialized: the `Option<Z>` trigger is removed and `zeroize_stack` passes
an initialized array.

### Z-3 (new observation, discretion): the non-asm fallback can race with interior mutability

`optimization_barrier<T: ?Sized>(val: &T)` is a safe `pub fn`. On non-asm targets its
fallback performs a non-atomic `read_volatile` of byte 0 of `*val`. If `T` has interior
mutability (an atomic, or a `Mutex`'s state word) and another thread writes that byte at
the same time, the read is a data race, which is UB (the `read_volatile` documentation:
volatile accesses behave exactly like non-atomic accesses for concurrency). This was
present unchanged in 1.9.0 and is not touched by #1551.

Why it is under the Policy 6 carve-out (the case the `322-zeroize` decision anticipated:
"an unused safe pub fn"):

- No code in any ACDP artifact calls it. A grep for `optimization_barrier|zeroize_stack`
  over the `.rs` sources of all 362 registry crate-versions in the four lockfiles (all
  present locally) hits only zeroize 1.9.1 itself (`pub use`, `stack.rs`, `barrier.rs`, and
  `tests/alloc.rs`). ACDP's own `crates/`, `src/`, and `bindings/` have no hits.
- Inside zeroize the one caller, `zeroize_stack`, passes a local array with no
  interior mutability, and nothing in the graph calls `zeroize_stack`.
- The only ACDP artifact on the fallback is `bindings/acdp-wasm`, built for
  `wasm32-unknown-unknown` without the `atomics` target feature
  (`bindings/acdp-wasm/.cargo/config.toml` sets only the getrandom cfg), so it has no
  threads and the race cannot occur there even in principle.
- Native builds use the empty `asm!` path, which reads no memory.

Not filed upstream by this review. Suggested text for the maintainer, if wanted: "the
non-asm fallback of `optimization_barrier` does a non-atomic `read_volatile` through a
shared reference; for `T` with interior mutability this races with concurrent atomic
writes. `core::hint::black_box(val)` alone avoids the read."

## ACDP exposure

- ACDP's secret path is acdp-crypto's `#[derive(ZeroizeOnDrop)] SigningKey` wrapping
  `ed25519_dalek::SigningKey`, whose `Drop` zeroizes `[u8; 32]` / `Scalar` with
  `volatile_write`. Under 1.9.1 that is a volatile write with no barrier read on any target.
  The node and py bindings also hold `Zeroizing<[u8; 32]>` directly (for example
  `bindings/acdp-node/src/producer.rs:277`), with the same volatile-write behaviour.
- The Tier A/B crates whose audit notes cite Z-1 (curve25519-dalek, ecdsa, elliptic-curve,
  p256, primefield, rustls; zeroize_derive's note only says "zeroize 1.9.0, still exempt") zeroize fully initialized values;
  those notes now refer to a fixed finding.

## Not claimed

- that zeroization is complete or effective against the optimizer (copies via moves or
  reallocation are documented upstream as out of scope; the barrier removal is upstream's
  design choice);
- cryptographic correctness, constant-time behaviour, side-channel resistance.
