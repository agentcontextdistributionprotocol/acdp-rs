# Review worksheet: `hmac` 0.13.0 (issue #339, Tier B batch B2)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.13.0"`). No concern-rule
  trigger. One `Discretion:` line records the test-only binary fixtures.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.13.0 (locked) | `6303bc9732ae41b04cb554b844a762b4115a61bfaa81e3e83050991eeb56863f` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is byte-identical (`diff -r`) to the
`~/.cargo/registry/src` copy that was read. Reproduce the facts with
`scripts/vet-facts.sh hmac 0.13.0`.

## Method

- No prior audit of `hmac` exists in `audits.toml` or the imported sets, so **full**.
- `src/` is 466 lines. Every file was read in full: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (58), `src/block_api.rs` (215), `src/simple.rs` (69),
  `src/simple_reset.rs` (92), `src/utils.rs` (32).
- `src/lib.rs:34-52` invokes `digest::buffer_fixed!` (twice). That macro is defined in
  digest 0.11.3 and expands into this crate; its expansion for `MacTraits KeyInit` and
  `ResetMacTraits KeyInit` was read in `digest-0.11.3/src/buffer_macros/fixed.rs`
  (see the digest worksheet). It contains no `unsafe`.
- `tests/mod.rs` and `tests/data/*.blb` were inspected (test-only).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 (grep, comment lines excluded). No `#![forbid(unsafe_code)]` attribute in `src/`; `Cargo.toml` sets `[lints.rust] unsafe_code = "forbid"`. The grep is the evidence. The `Cargo.toml` lint is only a corroborating hint: Cargo builds registry dependencies with `--cap-lints allow`, which caps `Cargo.toml` lints and source-level `forbid` attributes alike. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no |
| Powerful imports | none. `#![no_std]`, no `alloc`; the only `include_str!` is `#![doc = include_str!("../README.md")]`. No `std::{fs,net,process,env}`, `env!`, `option_env!`, `include_bytes!` in `src/`. |
| Binary content | `tests/data/*.blb` (11 blobby test-vector files, 85-9650 bytes: RFC 2104/4231, Wycheproof, GOST vectors), loaded only by `include_bytes!` in the `tests/mod.rs` integration-test macro. Not compiled into any non-test build. Recorded as a discretion line. |
| Dependencies | `digest` 0.11.2 (feature `mac`). Dev-only: `digest/dev`, `hex-literal`, `md-5`, `sha1`, `sha2`, `streebog`. |
| Features ACDP enables | none (`cargo metadata` resolve: empty feature set, root `--all-features` and py/node/wasm bindings identical). `zeroize` is off. |
| Reached via | `rfc6979` 0.6.0 (only dependent) -> `ecdsa` 0.17.0 signing. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour (what was read)

- `utils::get_der_key` (`src/utils.rs:9-32`): copies a key no longer than the block size
  into a zeroed block; a longer key is hashed first, then copied (truncating only if the
  digest output exceeded the block size). All slicing is bounded by the two `len()`
  comparisons. No panics reachable.
- `HmacCore::new_from_slice` (`src/block_api.rs:52-69`): XORs IPAD, absorbs one block into
  the inner core, flips to OPAD (`IPAD ^ OPAD`), absorbs into the outer core. Always `Ok`,
  so the `expect("HMAC accepts keys of any length")` in `KeyInit::new`
  (`:49`, `:148`, `simple.rs:25`, `simple_reset.rs:27`) is unreachable.
- `finalize_fixed_core` (`:81-90`, `:181-190`): inner finalize into a stack `Output`,
  reset the buffer, feed the inner hash into the outer core. The reset variant clones the
  outer core instead of mutating it (`:187`), and `Reset` restores the saved inner state
  (`:193-198`).
- `SimpleHmac` / `SimpleHmacReset` (`src/simple.rs`, `src/simple_reset.rs`): the same
  construction over the `Digest` trait for lazy hashes. rfc6979 0.6 uses `SimpleHmac`
  (`rfc6979-0.6.0/src/hmac_drbg.rs:77-79`).
- `Debug` impls print no key material (`"HmacCore { ... }"`).

## Concerns

None. A pure-safe-Rust generic HMAC over the digest traits; no `unsafe`, no I/O, no build
time code.

**Hygiene observation (not a vet concern):** the derived/padded key block (`buf`) and the
inner/outer core states are not zeroized, since the `zeroize` feature is off in ACDP; the
same applies to rfc6979's DRBG state (ecdsa worksheet). Stack/heap residue is outside the
`safe-to-deploy` scope.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance.
