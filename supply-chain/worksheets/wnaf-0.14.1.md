# Review worksheet: `wnaf` 0.14.1 (issue #339, Tier B batch B1)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.14.1"`). No concern-rule
  trigger. One non-blocking observation (W-1, a debug-build panic for window sizes 7 and 8,
  not reachable from ACDP and already fixed upstream).
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.14.1 (locked) | `795ca18b3fdb5e62bf982199278341ddcf7ebf7d32e25e212ad05d496e95f6fa` | `Cargo.lock` checksum |

There is no prior audit of `wnaf` (ours or imported), so there is no delta base. The tarball
was also downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`; its
sha256 matches, and its extracted tree is identical to the `~/.cargo/registry/src` copy that
was read (only cargo's `.cargo-ok` marker differs). Reproduce the facts with
`scripts/vet-facts.sh wnaf 0.14.1`.

## Method

- **Full** (no audited base). `src/` is 718 lines.
- Read in full: `Cargo.toml`, `Cargo.toml.orig`, `src/lib.rs` (199), `src/base.rs` (110),
  `src/boxed.rs` (217), `src/limb_buffer.rs` (69), `src/scalar.rs` (70), `src/traits.rs` (53).
  There are no tests, benches, examples, or binary files in the tarball.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 sites (full-source grep; forbid is capped by --cap-lints for registry deps, so the grep is the evidence). `#![forbid(unsafe_code)]` is at `src/lib.rs:8`. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no |
| Powerful imports | none. `#![no_std]` (`src/lib.rs:1`); `alloc` only under the `alloc` feature (`:11-13`); `include_str!("../README.md")` is a doc string (`:9`). No `std::{fs,net,process,env}`, `env!`, `option_env!`, or `include_bytes!`. |
| Binary content | none |
| Dependencies | `hybrid-array` 0.4.13 (as `array`), `ff` 0.14, `group` 0.14, `primefield` 0.14, all `default-features = false`. |
| Features ACDP enables | none. `primeorder` 0.14.0 depends on it with `default-features = false` (`primeorder-0.14.0/Cargo.toml:94-96`), so `alloc` / `BoxedWnaf` is not compiled. Same in the py, node, and wasm bindings. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## What the code does

- `wnaf_table` (`src/lib.rs:55-65`) fills a slice with `P, 3P, 5P, ...` using only `Group`
  operations; it writes through a `&mut [G]` iterator.
- `wnaf_form` (`src/lib.rs:70-150`) converts a little-endian scalar into signed wNAF digits.
  `LimbBuffer` (`src/limb_buffer.rs`) reads 8-byte limbs with `split_at` / `copy_from_slice`
  and zero-extends past the end; `get` asserts the requested index is current or next
  (`:63`). Every write is a bounds-checked slice index (`wnaf[cursor]`), so a logic error
  panics; it cannot write out of bounds.
- `wnaf_multi_exp` (`src/lib.rs:157-194`) is Straus interleaving; table lookups are
  bounds-checked (`table[(n / 2) as usize]`, `:185,187`).
- `WnafBase` / `WnafScalar` (`src/base.rs`, `src/scalar.rs`) are fixed-size `hybrid-array`
  storage typed by window size; `traits.rs` maps window sizes U2..U8 to table sizes and
  exports `impl_wnaf_size_for_scalar!`.
- The crate is explicitly variable-time (crate description, `src/base.rs:54-55`).

**ACDP use.** `primeorder` uses `WnafBase`/`WnafScalar` with `DefaultWnafWindowSize = U5`
(`primeorder-0.14.0/src/projective.rs:39-45`) for `mul_vartime` and the vartime linear
combinations behind ECDSA P-256 verification (public data). `recommended_wnaf_for_num_scalars`
returns 5 (`projective.rs:392-394`).

## Observations (not vet concerns)

- **W-1 (debug-build panic, window sizes 7 and 8).** `digit()` uses `Digit::try_from(n)
  .expect("overflow")` under `debug_assertions` (`src/lib.rs:71-80`). For `W = 7`,
  `digit(width)` with `width = 128` panics in the negative-digit branch (`:126`); for
  `W = 8`, `digit(window_val)` panics for odd `window_val >= 128` (`:120`). In release builds
  (overflow checks off) the `as` cast and wrapping `i8` arithmetic happen to produce the
  correct digit; with overflow checks on, the `-=` at `:126` panics instead. Either way it is
  a panic, never memory unsafety. ACDP only instantiates `W = 5`, where all values fit in `i8`.
  Upstream master already rewrote the branch as `-digit(width - window_val)` with a comment
  about windows 7 and 8 (checked 2026-10-04); nothing to report.

## Concerns

None.

## Not claimed

Cryptographic correctness, constant-time behaviour (the crate is variable-time by design),
side-channel resistance. `ff`, `group`, `primefield`, and `hybrid-array` are separate crates;
`ff` 0.14.0 is audited in this batch, the others remain exempted.
