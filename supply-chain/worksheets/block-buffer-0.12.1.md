# Review worksheet: `block-buffer` 0.12.1 (issue #339, Tier B batch B6)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.12.1"`). No concern-rule
  trigger. One non-blocking observation (BB-1, a stale `SAFETY` comment).
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.12.1 (locked) | `d2f6c7dbe95a6ed67ad9f18e57daf93a2f034c524b99fd2b76d18fdfeb6660aa` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`,
its sha256 matches, and that extracted tree (identical to the `~/.cargo/registry/src` copy
apart from cargo's `.cargo-ok` marker) is what was read. Reproduce the facts with
`scripts/vet-facts.sh block-buffer 0.12.1`. The root lockfile and all three binding
lockfiles (py, node, wasm) lock 0.12.1 with this checksum.

## Method

- No prior audit, so **full**.
- `src/` is 756 lines; **all of it was read line by line**: `src/lib.rs` (451),
  `src/sealed.rs` (106), `src/read.rs` (199). Also read: `Cargo.toml` (and `.orig`).
- `tests/mod.rs` (435) was grep-scanned and its test list read: it uses `hex_literal::hex!`
  vectors and `std::panic::catch_unwind` for the exception-safety tests; no file, network
  or binary content.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 21 (`vet-facts.sh`; a `\bunsafe\b` grep finds 22 because it also matches the attribute `#![allow(clippy::undocumented_unsafe_blocks)]` at `src/lib.rs:41`). Every site has a verdict below. No `forbid(unsafe_code)`. |
| asm / SIMD | none |
| build.rs / proc-macro | none / no |
| Powerful imports | none. `#![no_std]`; no `std::{fs,net,process,env}`, `env!`, `include_bytes!`. |
| Binary content | none |
| Dependencies | `hybrid-array` 0.4 (locked 0.4.14, this batch); optional `zeroize` 1.8 (feature `zeroize`). Dev-only: `hex-literal`. |
| Features ACDP enables | none (`cargo metadata` resolve, root `--all-features` and all three bindings): the `zeroize` impls (`src/lib.rs:424-442`, `src/read.rs:181-190`) are not compiled. |
| Targets | No `cfg(target_*)` anywhere; the same code is compiled on x86_64, aarch64, wasm32 and 32-bit targets. |
| Reached via | `digest` 0.11.3 (`EagerBuffer` / `LazyBuffer` in the `core_api` wrappers used by `sha2` 0.11.0 and `hmac` 0.13.0). ACDP has no direct use. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Data-structure invariants

`BlockBuffer<BS, K>` is `{ buffer: MaybeUninit<Array<u8, BS>>, pos: K::Pos }` with
`BS` in `U1..=U255` (`sealed::BlockSizes`, `IsLess<U256> + NonZero`, `src/sealed.rs:106`),
so every position fits in a `u8`.

- **Eager** (`Pos = ()`): the cursor is stored in the **last byte of `buffer`**
  (`src/sealed.rs:39-58`). Invariant E: `pos < BS`; bytes `0..pos` and byte `BS-1` are
  initialized.
- **Lazy** (`Pos = u8`): the cursor is the `pos` field (`src/sealed.rs:76-84`). Invariant
  L: `pos <= BS`; bytes `0..pos` are initialized.
- `ReadBuffer<BS>` (`src/read.rs`) holds a fully initialized `Array<u8, BS>` whose byte 0 is
  the cursor. Invariant R: `1 <= buffer[0] <= BS`.

Establishment: `Default` calls `K::set_pos(.., 0)` (`src/lib.rs:99-107`), which for Eager
writes the last byte. Every public mutator re-establishes the invariant before returning,
and the two places that temporarily break it (`digest_blocks` with `pos != 0`,
`digest_pad`) hold a `ResetGuard` whose `Drop` resets the cursor, including on unwind from
the caller's `compress` closure (`src/lib.rs:444-451`, `src/read.rs:192-199`). The
closures receive `&Array` / `&[Array]`, never the buffer, so they cannot observe the broken
state.

## `unsafe` sites and verdicts

| Site | What | Invariant and argument | Verdict |
|---|---|---|---|
| `src/lib.rs:114` | `Clone` via `ptr::read(self)` | All fields are plain bytes (`MaybeUninit<[u8; N]>`, `()` or `u8`) and own no resource, so a bitwise copy is an independent valid value; copying uninit bytes inside `MaybeUninit` is allowed. See BB-1 for the stale comment. | sound |
| `src/lib.rs:151-153` | `try_new` -> `set_data_unchecked(buf)` | Guarded by `K::invariant(buf.len(), BS)` at `:146`. | sound |
| `src/lib.rs:177-181` | `digest_blocks` fast path: `copy_nonoverlapping` of `n` bytes at `pos`, then `set_pos(pos+n)` | Taken only if `K::invariant(n, BS - pos)` (`:173`): Eager `n < rem`, Lazy `n <= rem`, so the write ends before `BS` (Eager: at most index `BS-2`, so the cursor byte is untouched) / at `BS` (Lazy). Source `input` and destination `&mut self` cannot overlap. | sound |
| `src/lib.rs:195-199` | `digest_blocks` with `pos != 0`: copy `rem` bytes to `pos`, `assume_init_ref` | `left.len() == rem == BS - pos` (`split_at(rem)` at `:185`; the fast path was not taken, so `n >= rem`), so bytes `pos..BS` are written and `0..pos` were initialized: the whole block is initialized. Eager's cursor byte is overwritten; the `ResetGuard` (`:188`) restores `pos = 0` when it drops after `compress`. | sound |
| `src/lib.rs:210-212` | `set_data_unchecked(leftover)` | `split_blocks` returns Eager `leftover.len() < BS` (`Array::slice_as_chunks`), Lazy `<= BS` (the last full block is kept back, `src/sealed.rs:92-100`). | sound |
| `src/lib.rs:219-221` | `reset` -> `set_pos_unchecked(0)` | 0 satisfies both invariants. | sound |
| `src/lib.rs:241-243` | `get_pos`: `unreachable_unchecked()` if the invariant fails | The invariant holds at every point a `&self` is observable (above), so the branch is dead; `debug_assert!(false)` precedes it. | sound |
| `src/lib.rs:253` | `get_data`: `from_raw_parts(buffer, get_pos())` | Bytes `0..pos` are initialized; `pos <= BS`. | sound |
| `src/lib.rs:266-268` | `set`: `set_pos_unchecked(pos)` | `assert!(K::invariant(pos, BS))` at `:262`; `buffer` was just fully initialized at `:263`. | sound |
| `src/lib.rs:292` | `unsafe fn set_pos_unchecked` | Private; contract documented (`:285-290`); every caller listed here satisfies it. | sound |
| `src/lib.rs:304-309` | `unsafe fn set_data_unchecked`: set the cursor first, then copy `buf` | Private; callers guarantee `K::invariant(buf.len(), BS)`. For Eager, `buf.len() < BS`, so the copy never reaches the cursor byte written first. | sound |
| `src/lib.rs:353` | `deserialize` -> `set_data_unchecked(data)` | `pos` validated at `:342`; `data.len() == pos` (`split_at(pos)`, `:346`); tail checked to be zero. | sound |
| `src/lib.rs:386-391` | `digest_pad`: write `delim` at `pos`, zero `pad_len = BS-pos-1` bytes, `assume_init_mut` | Eager `pos < BS`, so `pad_len` does not underflow and the writes cover exactly `pos..BS`; `0..pos` were initialized. Cursor restored by `ResetGuard` (`:382`). `suffix_dst_pos` comes from `checked_sub(...).expect` (`:378-380`); the later slice copies are bounds-checked safe code. | sound |
| `src/sealed.rs:41-45` | Eager `get_pos`: `ptr::read` of byte `N-1` | `N >= 1` (`NonZero`), so `N-1` is in bounds; that byte is initialized by `Default` and only ever written, never left uninitialized (it is covered by every full-block write). | sound |
| `src/sealed.rs:53-57` | Eager `set_pos`: `ptr::write` of byte `N-1` | In bounds as above; `val < BS <= 255` fits in `u8`. | sound |
| `src/read.rs:26` | `ReadBuffer::default` -> `set_pos_unchecked(BS)` | `BS >= 1`. | sound |
| `src/read.rs:47-49` | `get_pos`: `unreachable_unchecked()` if `pos == 0 || pos > BS` | Invariant R holds at every observable point (below). | sound |
| `src/read.rs:72` | `unsafe fn set_pos_unchecked` | Private; contract `0 < pos <= BS`. | sound |
| `src/read.rs:88` | `read_cached`: `set_pos(pos + min(rem, len))` | `pos >= 1` and `pos + new_len <= pos + rem = BS`. | sound |
| `src/read.rs:125` | `write_block`: `set_pos(read_len)` | `read_len != 0` (`:108`) and `assert!(read_len < BS)` (`:111`). `gen_block` may overwrite byte 0; the guard (`:113`) resets to `BS` on unwind and is `mem::forget`-ed only after both closures return. | sound |

`ReadBuffer::deserialize` (`src/read.rs:170-178`) validates `1 <= buffer[0] <= BS`
before constructing, so it cannot install a state that breaks invariant R.

## Observations

- **BB-1 (stale comment, not a defect).** The `SAFETY` comment on `Clone`
  (`src/lib.rs:112-113`) says `BlockBuffer` "does not implement `Drop`", but it does
  (`src/lib.rs:433-439`; the body only zeroizes under the `zeroize` feature). The bitwise
  copy is still sound because no field owns a resource; with `zeroize` on, each copy
  zeroizes only its own bytes. Nothing to report beyond the comment.

## Concerns

None under the concern rule.

## Not claimed

Cryptographic correctness (for example, that the padding matches any hash
specification), constant-time behaviour, side-channel resistance.
