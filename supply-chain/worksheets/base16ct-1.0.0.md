# Review worksheet: `base16ct` 1.0.0 (issue #339, Tier B batch B5)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "1.0.0"`). No concern-rule
  trigger. There are 4 `unsafe` sites, all `from_utf8_unchecked` on output the crate wrote
  itself, and all are sound.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 1.0.0 (locked) | `fd307490d624467aa6f74b0eabb77633d1f758a7b25f12bceb0b22e08d9726f6` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`.
Its sha256 matches. Its extracted tree is identical (`diff -r`) to the `~/.cargo/registry/src`
copy that was read, apart from Cargo's own `.cargo-ok` marker. Reproduce the facts with
`scripts/vet-facts.sh base16ct 1.0.0`.

All four lockfiles lock 1.0.0 with the same checksum: the root `Cargo.lock` and the py, node
and wasm binding lockfiles.

## Method

- No prior audit of `base16ct` exists in `audits.toml` or the imported sets, so this is a
  **full** audit.
- `src/` is 381 lines, and every file was read in full:
  - `Cargo.toml` (and `.orig`)
  - `src/lib.rs` (122)
  - `src/lower.rs` (78)
  - `src/upper.rs` (78), which `diff` shows differs from `lower.rs` only in the A-F constants
    and doc wording
  - `src/mixed.rs` (37)
  - `src/display.rs` (35)
  - `src/error.rs` (31)
- `tests/lib.rs` (163) and `benches/mod.rs` (69) were inspected. Both are test-only and
  contain no `unsafe`, no `include_*` and no fs access.
- **Empirical check (scratch crate, release build with debug assertions and overflow checks
  on):**
  - Every 2-byte input (65,536 of them, lower and upper) was encoded into a 0x00-filled
    buffer and into a 0xFF-filled buffer. The two outputs were equal, matching `format!`'s
    hex, with no unwritten byte.
  - 20,000 random inputs of 0-289 bytes went through `encode_string`, compared to a
    reference.
  - The same inputs round-tripped through `mixed::decode_vec`.
  - A too-small `dst` always returns `Err`.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 4: `src/lower.rs:35`, `:49`; `src/upper.rs:35`, `:49` (full-source grep, comment lines excluded; the grep is the evidence). There is no `forbid`/`deny(unsafe_code)` attribute. Lints would be capped by `--cap-lints` for registry deps anyway. |
| asm / SIMD / intrinsics | none |
| build.rs | none |
| proc-macro | no |
| Exported macros | none |
| Powerful imports | none. `#![no_std]` (`src/lib.rs:1`); `alloc` only behind the `alloc` feature. No `std::{fs,net,process,env}`, `env!`, `include_*`. |
| Dependencies | none (normal, build or dev) |
| Features ACDP enables | `alloc`, in every build: the root (`--all-features`), `acdp --no-default-features` on the host and on wasm32, and the py, node and wasm bindings |
| Reached via | `sec1` 0.8.1 (`HexDisplay` at `src/point.rs:9`; `base16ct::mixed::decode` in `FromStr for EncodedPoint` at `:352`) and `elliptic-curve` 0.14.1 (`src/error.rs:24`, `src/scalar/value.rs:11`, `:458`, `src/scalar/nonzero.rs:9`, `:434`). ACDP calls it directly nowhere (`grep -rn base16ct crates src tests bindings/*/src`: no hits). ACDP's own hex is the `hex` 0.4 crate. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## `unsafe` sites

1. **`src/lower.rs:35` / `src/upper.rs:35`.** `encode_str` calls
   `core::str::from_utf8_unchecked(r)`, where `r` is the slice `encode` returned.
   - **Invariant:** every byte of `r` is ASCII.
   - **Argument:**
     - `encode` (`:22-31`) sets `dst = dst.get_mut(..encoded_len(src))`, which is checked
       and returns `Err(InvalidLength)` if `dst` is too short. That slice has exactly `2n`
       bytes for `n = src.len()`. `encoded_len` (`src/lib.rs:98-100`) is `len * 2`, which
       cannot overflow because a `[u8]` holds at most `isize::MAX` bytes.
     - `src.iter().zip(dst.chunks_exact_mut(2))` pairs all `n` source bytes with all `n`
       two-byte chunks, and writes both bytes of each chunk (`:27-28`). So every byte of `r`
       is written on this call. Bytes the caller left in `dst` (even non-UTF-8 ones) are all
       overwritten.
     - `encode_nibble` (`:72-78`) is called only with `src >> 4` or `src & 0x0f`, so its
       input is 0..=15. It returns `0x30 + v` for v <= 9. For v >= 10 the mask
       `(0x39 - ret) >> 8` is all ones, so it returns `0x30 + v + (0x61 - 0x3a)` =
       `0x61..=0x66` (lower), or `0x41..=0x46` (upper). Every value is ASCII.
     - The empirical dirty-buffer check above confirms this.
2. **`src/lower.rs:49` / `src/upper.rs:49`.** `encode_string` calls
   `String::from_utf8_unchecked(dst)`.
   - `dst` is `vec![0u8; elen]` with `elen = encoded_len(input)`. `encode` is given the whole
     vector and returns `Ok` (the length is exact, so the `expect` cannot fire). It writes
     all `elen` bytes as in site 1.
   - Even an unwritten byte would be 0x00, which is valid UTF-8.

`HexDisplay` (`src/display.rs`) uses `encode_str` with a 2-byte buffer per input byte, so
site 1 covers it.

## Behaviour (what was read)

- `decode_inner` (`src/lib.rs:102-122`) uses only checked slicing.
  - Odd-length input gives `InvalidLength`.
  - `decode_nibble` returns a value with high bits set for a non-hex byte, and these are
    OR-ed into `err`.
  - The crate advertises a branch-free style, but no constant-time property is claimed or
    relied on here.
- No panics are reachable from the public API except `encode_string`'s documented
  `usize::MAX/2` note. That note is unreachable for real slices, as shown above.

## Concerns

None.

## Not claimed

Cryptographic correctness, constant-time behaviour (the crate advertises constant-time
encoding; that is **not** claimed or verified here), and side-channel resistance.
