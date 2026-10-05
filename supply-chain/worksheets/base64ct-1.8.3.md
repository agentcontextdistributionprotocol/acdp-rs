# Review worksheet: `base64ct` 1.8.3 (issue #339, Tier B batch B5)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "1.8.3"`). No concern-rule
  trigger. There are 4 `unsafe` sites, all in `src/encoding.rs`, and all are sound for every
  input reachable from the safe public API.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 1.8.3 (locked) | `2af50177e190e07a26ab74f8b1efbfe2ef87da2116221318cb1c2e82baf7de06` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`.
Its sha256 matches. Its extracted tree is identical (`diff -r`) to the `~/.cargo/registry/src`
copy that was read, apart from Cargo's own `.cargo-ok` marker. Reproduce the facts with
`scripts/vet-facts.sh base64ct 1.8.3`.

All four lockfiles lock 1.8.3 with the same checksum: the root and the py, node and wasm
bindings.

## Method

- No prior audit of `base64ct` exists in `audits.toml` or the imported sets, so this is a
  **full** audit.
- `src/` is 2,092 lines, and every file was read in full:
  - `Cargo.toml` (and `.orig`)
  - `src/lib.rs` (108)
  - `src/alphabet.rs` (125)
  - `src/alphabet/{bcrypt,crypt,pbkdf2,shacrypt,standard,url}.rs` (33/40/33/69/54/54)
  - `src/encoding.rs` (376)
  - `src/decoder.rs` (635)
  - `src/encoder.rs` (364)
  - `src/errors.rs` (81)
  - `src/line_ending.rs` (53)
  - `src/test_vectors.rs` (67, `#[cfg(test)]`)
- `tests/*.rs` (test-only) were inspected. They contain no `unsafe`, no `include_*` and no fs
  access.
- **Empirical check (scratch crate, release build with debug assertions and overflow checks
  on), for each of the 8 alphabets** (`Base64`, `Base64Unpadded`, `Base64Url`,
  `Base64UrlUnpadded`, `Base64Bcrypt`, `Base64Pbkdf2`, `Base64ShaCrypt` and the deprecated
  `Base64Crypt`):
  - Every 3-byte input (2^24), every 2-byte input and every 1-byte input was encoded into a
    0x00-filled buffer and into a 0xFF-filled buffer.
  - Both outputs were identical, so every output byte is written. They were ASCII and valid
    UTF-8, and they round-tripped through `decode` and `decode_in_place`.
  - 20,000 random inputs of 0-299 bytes passed the same checks, and `encode_string` gave
    ASCII.
  - 200,000 random garbage strings were fed to `decode_in_place` and `decode`, with no panic.
  - Miri was not run (it is not installed). The soundness argument below is by reasoning, and
    the empirical check backs it.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 4, all in `src/encoding.rs`: `:125`, `:155`, `:231`, `:245` (full-source grep, comment lines excluded; the grep is the evidence). `src/lib.rs:8-19` only `#![warn(unsafe_code)]`, and each site carries `#[allow(unsafe_code)]`. Lints are capped by `--cap-lints` for registry deps anyway. |
| asm / SIMD / intrinsics | none |
| build.rs | none |
| proc-macro | no |
| Exported macros | none |
| Powerful imports | none. `#![no_std]` (`src/lib.rs:1`); `alloc`/`std` only behind features. No `std::{fs,net,process,env}`, `env!`, `include_bytes!`. The only `include_str!` is the README doc. `std` only adds `io::Write for Encoder` (`src/encoder.rs:169`), `io::Read for Decoder` (`src/decoder.rs:250`) and `From<Error> for io::Error` (`src/errors.rs:74`). These are in-memory adaptors with no OS I/O. |
| Dependencies | none (normal). Dev: `base64` 0.22, `proptest` 1.6. |
| Features ACDP enables | **Not compiled in any ACDP build.** `cargo tree --locked -i base64ct` prints nothing for the root (`--all-features`, host and `--target all`), for `acdp --no-default-features` (host and wasm32), and for the py, node and wasm bindings (native and `--target all`). It is lock-only in all four lockfiles. Its only dependent in the lock is `spki` 0.8.0, through its optional `base64` feature, which is off. |
| Reached via | nothing at runtime. ACDP's base64 is the `base64` 0.23 crate. `grep -rn base64ct crates src tests bindings/*/src` gives no hits. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## The alphabet set is closed

`Encoding` (`src/encoding.rs:31`) has the supertrait `Alphabet`, and the unsafe code is in the
blanket `impl<T: Alphabet> Encoding for T` (`:64`). `Alphabet` is a `pub trait` in the private
module `mod alphabet` (`src/lib.rs:79`). Only concrete alphabet types are re-exported
(`:89-105`), so downstream crates cannot name `Alphabet` or implement it. The unsafe code
therefore only ever runs with the 8 in-crate alphabets, and their `encode_6bits` /
`decode_3bytes` tables were all covered by the exhaustive check.

## `unsafe` sites

1. **`src/encoding.rs:125-135` (`decode_in_place`, full-chunk loop).** For each
   `chunk in 0..full_chunks` (`full_chunks = buf.len() / 4`), the loop does three things:
   - it forms `p3 = buf.as_mut_ptr().add(3*chunk) as *mut [u8; 3]` and
     `p4 = buf.as_ptr().add(4*chunk) as *const [u8; 4]`;
   - it reads `&*p4` into `decode_3bytes`, which writes a stack `tmp_out`;
   - it then writes `*p3 = tmp_out`.

   - **Bounds:** chunk <= `full_chunks - 1`, so `4*chunk + 4 <= buf.len()` and
     `3*chunk + 3 <= 4*chunk + 4`. Both pointers and their 3-/4-byte extents are in bounds,
     and `add` stays in the allocation. In the padded case `buf` was first re-sliced to
     `&mut buf[..unpadded_len]` (`:111`). That slicing is checked, and `decode_padding`
     (`:265-299`) derives `unpadded_len` with `checked_sub`.
   - **Aliasing:**
     - `p3` and `p4` are both raw pointers from `as_mut_ptr`/`as_ptr`. std documents that
       these do not materialize a reference to the slice and may be mixed.
     - The shared reference `&*p4` lives only for the `decode_3bytes` call. The overlapping
       write through `p3` happens after it ends.
     - The arrays are `u8`, so there are no alignment or validity requirements.
2. **`src/encoding.rs:155-166` (`decode_in_place`, tail).** It calls
   `copy_nonoverlapping(tmp_out.as_ptr(), buf.as_mut_ptr().add(dst_rem_pos), dst_rem_len)`,
   then `buf.get_unchecked(..dlen)`. The block only runs when `err == 0`.
   - With `k = full_chunks` and `l = buf.len() - 4k` (in 0..=3), `dst_rem_pos = 3k` and
     `dlen = decoded_len(buf.len()) = 3k + floor(3l/4)` (`:347-352`, overflow-free).
   - So `dst_rem_len = floor(3l/4)` is in {0, 1, 2}, which is <= 3 = `tmp_out.len()`. The
     source read stays in `tmp_out`.
   - `3k + floor(3l/4) <= 4k + l = buf.len()`, so both the destination range and `..dlen` are
     in bounds.
   - The source is a stack array and the destination is `buf`, so they do not overlap.
   - The function has the `#[allow(clippy::arithmetic_side_effects)]` note. Every subtraction
     here is non-negative by construction.
3. **`src/encoding.rs:231` (`encode`).** It calls `str::from_utf8_unchecked(dst)`, where
   `dst = &mut dst[..elen]` is caller-supplied and may contain arbitrary non-UTF-8 bytes.
   - **Invariant:** all `elen` bytes are written with ASCII.
   - `elen` comes from `encoded_len_inner` (`:365-376`, `checked_mul`; `None` gives `Err`),
     and the code checks `elen <= dst.len()` (`:191`).
   - **Coverage, padded alphabets:** `elen = 4*ceil(n/3)`.
     - The zip `(&mut src_chunks).zip(&mut dst_chunks)` (`:200`) writes `floor(n/3)` full
       chunks. `Zip` pulls the source first, and the `&mut` iterators do not use the
       `TrustedRandomAccess` path, so no destination chunk is skipped.
     - If `n % 3 != 0`, the next destination chunk gets `encode_3bytes` and then the `PAD`
       mask (`:207-215`).
   - **Coverage, unpadded alphabets:** `elen = ceil(4n/3)`. The remainder
     (`into_remainder`, 0-3 bytes) is filled from `tmp_out` (`:218-224`).
   - **ASCII:**
     - `encode_3bytes` (`src/alphabet.rs:77-89`) passes only `b0 >> 2` or `& 63` values,
       so `encode_6bits` always gets an input in 0..=63.
     - The table-driven `encode_6bits` (`:93-104`) maps 0..=63 into the alphabet. This was
       hand-checked for `standard`, giving `A-Z a-z 0-9 + /`.
     - For all 8 alphabets, the exhaustive check covers every 6-bit value at every position.
     - `PAD` is `b'='`.
   - The `debug_assert!(str::from_utf8(dst).is_ok())` at `:227` held throughout the
     empirical run.
4. **`src/encoding.rs:245` (`encode_string`).** It calls `String::from_utf8_unchecked(dst)`
   on `vec![0u8; elen]`.
   - `encode` returns `Ok` on it, because the length is exact. The `expect`s cannot fire
     except for `encoded_len_inner` overflow, which is a documented panic and not UB.
   - `encode` wrote every byte, as in site 3, and even an unwritten 0x00 would be valid
     UTF-8.

`Encoder::finish` / `finish_with_remaining` (`src/encoder.rs`) use the **checked**
`str::from_utf8`, and `Decoder` uses only safe slicing over caller buffers.

## Concerns

None.

## Not claimed

Cryptographic correctness, constant-time behaviour (the crate advertises constant-time
encoding/decoding; that is **not** claimed or verified here), and side-channel resistance.
