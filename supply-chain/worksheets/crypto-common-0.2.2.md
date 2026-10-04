# Review worksheet: `crypto-common` 0.2.2 (issue #339, Tier B batch B1)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.2.2"`). No concern-rule
  trigger. One non-blocking observation (CC-1, a deterministic panic in an unused
  `SerializableState` impl, already fixed upstream).
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.2.2 (locked) | `ce6e4c961d6cd6c9a86db418387425e8bdeaf05b3c8bc1411e6dca4c252f1453` | `Cargo.lock` checksum |

There is no prior audit of `crypto-common` (ours or imported), so there is no delta base. The
tarball was also downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is identical to the `~/.cargo/registry/src` copy
that was read (only cargo's `.cargo-ok` marker differs). Reproduce the facts with
`scripts/vet-facts.sh crypto-common 0.2.2`.

## Method

- **Full** (no audited base). `src/` is 853 lines.
- Read in full: `Cargo.toml`, `Cargo.toml.orig`, `src/lib.rs` (398), `src/generate.rs` (92),
  `src/hazmat.rs` (363; lines 170-363 are macro invocation lists of type sizes).
  There are no tests, benches, examples, or binary files in the tarball.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 sites (full-source grep; forbid is capped by --cap-lints for registry deps, so the grep is the evidence). `#![forbid(unsafe_code)]` is at `src/lib.rs:8`. |
| asm / SIMD / intrinsics | none |
| build.rs | none |
| proc-macro | no |
| Powerful imports | none directly. `#![no_std]` (`src/lib.rs:1`); `include_str!("../README.md")` is a doc string (`:3`). **OS entropy, by delegation:** under the `getrandom` feature (on in ACDP), `Generate::try_generate` / `generate` read the system RNG through `getrandom::SysRng` (`src/generate.rs:4-5,28-45`); `generate` panics if the OS RNG fails (documented, `:36-40`). That is an explicit, documented API whose purpose is key generation; the syscall itself is in `getrandom` 0.4.3 (Tier B, still exempted). |
| Binary content | none |
| Dependencies | `hybrid-array` 0.4.7; optional `getrandom` 0.4 (`sys_rng`), `rand_core` 0.10. |
| Features ACDP enables | `getrandom`, `rand_core` (via `elliptic-curve/getrandom`, `digest/rand_core`, `primefield`) — identical in the root and the py, node, wasm bindings. `zeroize` (→ `hybrid-array/zeroize`) is off. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## What the code does

- `src/lib.rs`: size-carrying traits (`BlockSizeUser`, `ParBlocksSizeUser`, `OutputSizeUser`,
  `KeySizeUser`, `IvSizeUser`, `InnerUser`), `Reset`, `AlgorithmName`, `KeyExport`, the
  `KeyInit` / `KeyIvInit` / `TryKeyInit` / `InnerInit` / `InnerIvInit` constructors (slice
  forms do a length check through `<&Array>::try_from` and return `InvalidLength` /
  `InvalidKey`, `:169-173,202-206,273-277,301-304`), `IvState` / `SetIvState::peek`
  (`:321-326`), blanket impls for wrapper types (`:329-369`), and two unit error types.
- `src/generate.rs`: `Generate` for `u32`, `u64`, `[u8; N]`, and `Array<u8|u32|u64, U>`, all
  filling from a caller RNG (`:48-92`).
- `src/hazmat.rs`: `SerializableState` (serialize / deserialize an internal state as a byte
  `Array`) with macro impls for unsigned integers and fixed arrays of them.
- No global state, no I/O beyond the `getrandom` delegation above.

**ACDP use.** Trait vocabulary under `digest` / `sha2` / `hmac` and the `elliptic-curve` /
`primefield` stack. ACDP's P-256 key generation passes its own `getrandom::SysRng` to
`p256::ecdsa::SigningKey::generate_from_rng` (`crates/acdp-crypto/src/sign.rs:136-143`), so
it supplies the RNG itself. This crate's `Generate::generate()` / `try_generate()` SysRng path
is compiled, because `elliptic-curve/getrandom` enables the `getrandom` feature, but ACDP
does not call it.

## Observations (not vet concerns)

- **CC-1 (deterministic panic, unused).** `impl_serializable_state_u128_array!` passes `U8`
  as the per-element size for `u128` (`src/hazmat.rs:162-168`), which is 16 bytes. So for
  every `[u128; N]` impl, `serialize` calls `copy_from_slice` of 16 bytes into an 8-byte chunk
  (`:116`) and `deserialize` unwraps a failed 8-to-16-byte `try_into` (`:130`). Both panic on
  every call; neither is memory-unsafe (safe slice methods). Nothing in ACDP's graph uses
  `SerializableState` for `[u128; N]` (`sha2` 0.11.0 implements it by hand for its own cores,
  `sha2-0.11.0/src/block_api.rs:103,221`), and ACDP never serializes hash state. Fixed
  upstream in RustCrypto/traits#2471 (commit `14d3d2ce9`, 2026-07-03); not yet in a release
  as of 0.2.2. Nothing to report.

## Concerns

None.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, and RNG quality,
which belongs to `getrandom` / the OS.
