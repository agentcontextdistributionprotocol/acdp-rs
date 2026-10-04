# Review worksheet: `digest` 0.11.3 (issue #339, Tier B batch B2)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.11.3"`). No concern-rule
  trigger. One `Discretion:` line records the test-only binary fixture.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.11.3 (locked) | `f1dd6dbb5841937940781866fa1281a1ff7bd3bf827091440879f9994983d5c2` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is byte-identical (`diff -r`) to the
`~/.cargo/registry/src` copy that was read. Reproduce the facts with
`scripts/vet-facts.sh digest 0.11.3`.

## Method

- No prior audit of `digest` 0.11.x exists in `audits.toml` or the imported sets, so
  **full**.
- `src/` is 2,857 lines. Every file was read in full: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (261), `src/digest.rs` (238), `src/mac.rs` (266), `src/xof_fixed.rs` (152),
  `src/block_api.rs` (163), `src/block_api/ct_variable.rs` (205), `src/buffer_macros.rs`
  (3), `src/buffer_macros/fixed.rs` (488), `src/buffer_macros/variable.rs` (211),
  `src/buffer_macros/xof.rs` (319), `src/dev.rs` (159), `src/dev/fixed.rs` (62),
  `src/dev/mac.rs` (163), `src/dev/rng.rs` (38), `src/dev/xof.rs` (50),
  `src/dev/variable.rs` (79). `tests/dummy_fixed.rs` and `tests/data/` inspected.
- **Macro-generated code paths.** `buffer_fixed!`, `buffer_ct_variable!` and
  `buffer_xof!` are `#[macro_export]` and expand inside the calling crate (in ACDP's
  graph: `sha2` 0.11.0 `src/lib.rs:34-64` and `hmac` 0.13.0 `src/lib.rs:34-52` invoke
  `buffer_fixed!`), where this crate's `forbid(unsafe_code)` does not apply. Every arm
  was read, including the recursive `impl_inner` dispatch: `FixedHashTraits` ->
  `BaseFixedTraits AlgorithmName Default Clone HashMarker Reset FixedOutputReset
  SerializableState ZeroizeOnDrop`; `MacTraits` -> `BaseFixedTraits MacMarker`;
  `ResetMacTraits` -> `MacTraits Reset FixedOutputReset`; `BaseFixedTraits` -> `Debug
  BlockSizeUser OutputSizeUser CoreProxy Update FixedOutput`; plus the `oid:`,
  `CustomizedInit`, `InnerInit`, `KeyInit` arms. Every generated impl is a safe forward
  to the core type or to `block_buffer` (`digest_blocks`, `reset`, `serialize`,
  `deserialize`). The `const _: () = { fn check(v: &T) { v as &dyn Trait; } }` items are
  compile-time trait-bound assertions. No arm contains `unsafe`, `asm!`, or a powerful
  import, so none is injected into callers.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0, including all macro bodies; (grep of the full source, comment lines excluded; the grep is the evidence). `#![forbid(unsafe_code)]` at `src/lib.rs:4` is only a corroborating hint: Cargo builds registry dependencies with `--cap-lints allow`, which caps source-level `forbid` attributes as well as `Cargo.toml` lints. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no |
| Powerful imports | none in compiled ACDP code. `#![no_std]`; `alloc` only under `alloc`; `include_str!("../README.md")` is a doc string. The three `include_bytes!` hits (`src/dev.rs:36`, `:71`, `src/dev/mac.rs:147`) are inside the `new_test!`, `hash_serialization_test!` and `new_mac_test!` macros of the `dev` module, which is compiled only with feature `dev` (`src/lib.rs:49-50`, off in ACDP) and whose macros emit `#[test]` functions. |
| Dead file | `src/dev/variable.rs` is not declared by `src/dev.rs` (which has `mod fixed; mod mac; mod rng; mod xof;`), so it is never compiled; it references a `VariableOutput` trait that 0.11.3 does not define. Harmless. |
| Binary content | `tests/data/fixed_hash_serialization.bin` (16 bytes: a serialized dummy hash state), read only by the `tests/dummy_fixed.rs:119` integration test. Not compiled into any non-test build. Recorded as a discretion line. |
| Dependencies | `crypto-common` 0.2 (renamed `common`); optional `blobby` 0.4 (`dev`), `block-buffer` 0.12 (`block-api`), `const-oid` 0.10 (`oid`), `ctutils` 0.4 (`mac`), `zeroize` 1.7. Dev-only: `sha2` 0.11. |
| Features ACDP enables | `alloc`, `block-api`, `default`, `mac`, `oid`, `rand_core` (root `--all-features` and py/node/wasm bindings identical). `dev`, `getrandom`, `zeroize` off. |
| Reached via | `sha2` 0.11.0 (ACDP `content_hash`), `hmac`, `ecdsa`, `elliptic-curve`, `signature`, `curve25519-dalek`. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour (what was read)

- `lib.rs`: trait definitions (`Update`, `FixedOutput(Reset)`, `XofReader`,
  `ExtendableOutput(Reset)`, `CustomizedInit`, `TryCustomizedInit` blanket, error types).
  The `alloc` helpers (`:135-199`) allocate `vec![0u8; n]` of a caller-chosen size.
- `digest.rs`: blanket `Digest` over `FixedOutput + Default + Update + HashMarker`
  (`:59-131`); `DynDigest` blanket (`:181-224`) with length-checked `try_into` for
  output buffers. The `unwrap()`s in the default `DynDigest::finalize{,_reset}`
  (`:144`, `:154`) size the buffer from `output_size()` first, so they cannot fail for a
  conforming impl, and the blanket impl overrides them anyway.
- `mac.rs`: blanket `Mac` (`:84-181`); `verify_slice*` check the length before a
  `ctutils` comparison; `verify_truncated_*` reject `n == 0 || n > OutputSize` before
  slicing (`:161-180`), so no out-of-range slice. `CtOutput` `PartialEq` uses `ct_eq`
  (`:226-231`); its `Drop` zeroizes only with `zeroize` (off; empty drop otherwise).
- `block_api.rs` / `ct_variable.rs`: traits plus `CtOutWrapper`. `finalize_fixed_core`
  (`ct_variable.rs:103-116`) computes `m = full.len() - n`, with `n <= full.len()`
  guaranteed by the `IsLessOrEqual<.., Output = True>` type bound. `Default`
  (`:125-130`) `unwrap`s `T::new(OutSize::USIZE)`, valid by the same bound.
- `xof_fixed.rs`: `XofFixedWrapper` forwards every trait to the inner XOF.
- `dev/` (feature `dev`, off): test helpers and a fixed-seed xorshift RNG used only to
  feed test data.

## Concerns

None.

## Not claimed

Cryptographic correctness, constant-time behaviour (including of `CtOutput`/`verify_*`),
side-channel resistance. Buffering is delegated to `block-buffer` (Tier B, still
exempted).
