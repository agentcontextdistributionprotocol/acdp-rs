# Review worksheet: `rand_core` 0.10.1 (issue #339, Tier B batch B4)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.10.1"`). No concern-rule
  trigger.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.10.1 (locked) | `63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is identical (`diff -r`; only cargo's
`.cargo-ok` marker differs) to the `~/.cargo/registry/src` copy that was read. Reproduce the
facts with `scripts/vet-facts.sh rand_core 0.10.1`. The root lockfile and all three binding
lockfiles (py, node, wasm) lock 0.10.1 with this checksum.

## Method

- No prior audit of `rand_core` exists in `audits.toml` or the imported sets, so **full**.
- `src/` is 1,073 lines. Every file was read in full: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (272), `src/block.rs` (308), `src/seedable_rng.rs` (206),
  `src/unwrap_err.rs` (70), `src/utils.rs` (151), `src/word.rs` (66). Doc comments were
  read as documentation; their doctests compile only under `cargo test`.
- `tests/block.rs`, `tests/mod.rs`, `tests/utils.rs` inspected (ASCII Rust, test-only).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 (grep of the full source, comment lines excluded; the grep is the evidence). The crate has no `forbid(unsafe_code)` attribute or lint; `Cargo.toml` only sets `clippy::undocumented_unsafe_blocks = "warn"`. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no; no `macro_rules!` at all |
| Powerful imports | none. `#![no_std]` (`src/lib.rs:4`), no `alloc`; the only include is `#![doc = include_str!("../README.md")]` (`src/lib.rs:5`). No `std::{fs,net,process,env}`, `env!`, `include_bytes!`, `extern`, or `cfg`. |
| Binary content | none |
| Dependencies | none (no `[dependencies]`, no features) |
| Features ACDP enables | none (root `--all-features`) |
| Reached via | `acdp-crypto` directly, `ed25519-dalek` (`rand_core` feature), `curve25519-dalek`, `elliptic-curve`, `crypto-common`, `crypto-bigint`, `ff`, `getrandom` 0.4, and others in the RustCrypto stack |
| ACDP call sites | `rand_core::UnwrapErr(getrandom::SysRng)` in `crates/acdp-crypto/src/sign.rs:56` (Ed25519 `SigningKey::generate`) and `:143` (P-256 `SigningKey::generate`) |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour (what was read)

- `lib.rs`: `TryRng` (`:189-201`) with a blanket impl over `DerefMut` (`:203-223`);
  `Rng` as the infallible sub-trait, blanket over `TryRng<Error = Infallible>`
  (`:49-89`, matching on `Ok(x)` only, which is exhaustive for `Infallible`); marker traits
  `TryCryptoRng`/`CryptoRng`; deprecated `RngCore`/`TryRngCore` stubs.
- `block.rs`: `BlockRng` (`:114-308`) keeps its read index in `results[0]`. `new` sets it to
  `N` (empty), `reconstruct` to `N - remaining.len()` (only when `remaining.len() < N`),
  `set_index` debug-asserts `0 < index <= N`. `next_word`, `next_u64_from_u32` and
  `fill_bytes` regenerate when `index >= N` and then index only within `0..N`;
  `remaining_results` slices `results[index..]` with `index <= N`. `reset_and_skip` asserts
  `n < N`. All indexing is bounds-checked safe Rust; a generator that panics mid-`generate`
  can only lead to a later safe panic.
- `seedable_rng.rs`: `seed_from_u64` expands a `u64` with PCG32 (`:192-206`) into the seed;
  `from_rng`/`try_from_rng`/`fork` fill a default seed from another RNG.
- `unwrap_err.rs`: `UnwrapErr<R>` (`:30`) maps an inner error to a panic (`:51-53`), by
  design; this is the wrapper ACDP uses to turn `getrandom::SysRng` into a `CryptoRng`
  (panics on OS RNG failure).
- `utils.rs`: `next_u64_via_u32`, `fill_bytes_via_next_word` (chunked copy, remainder
  bounded by `rem.len()`), `next_word_via_fill`, `read_words` (asserts the exact byte
  length before copying).
- `word.rs`: sealed `Word` for `u32`/`u64`; `from_usize`/`into_usize` `unwrap` a
  `try_into`, which can fail only for a block size `N > u32::MAX`.

## Concerns

None. Pure trait definitions and safe helpers; no `unsafe`, no I/O, no dependencies.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, and the
quality of any RNG. ACDP's randomness comes from `getrandom` 0.4.3 (Tier B, still exempted).
