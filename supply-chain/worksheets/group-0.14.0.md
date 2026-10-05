# Review worksheet: `group` 0.14.0 (issue #339, Tier B batch B3)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.14.0"`). No concern-rule
  trigger. One non-blocking observation (G-1, degenerate wNAF window sizes in a helper that
  nothing in ACDP's graph calls).
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.14.0 (locked) | `7fd1a1c7a5206c5b7a3f5a0d7ccd3ff85d0c8f5133d62a02680255b0004af5f4` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is identical (`diff -r`) to the
`~/.cargo/registry/src` copy that was read, except Cargo's own `.cargo-ok` marker. Reproduce
the facts with `scripts/vet-facts.sh group 0.14.0`.

The root `Cargo.lock` and all three binding lockfiles (py, node, wasm) lock 0.14.0 with the
same checksum.

## Method

- No prior audit of `group` exists in `audits.toml` or the imported sets, so **full**.
- `src/` is 1,256 lines. Every file was read in full: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (226), `src/cofactor.rs` (60), `src/prime.rs` (14), `src/wnaf.rs` (512),
  `src/tests/mod.rs` (444; compiled only with the `tests` feature, `src/lib.rs:21-22`).
- Also inspected: `rust-toolchain.toml` (pins 1.85.0 for upstream development; Cargo ignores
  a dependency's toolchain file), `.github/workflows/ci.yml`, and the packaged `Cargo.lock`.
  There is no `tests/` or `benches/` directory.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 sites (full-source grep). There is no `#![forbid(unsafe_code)]` attribute and no `Cargo.toml` lint. The grep is the evidence. |
| asm / SIMD / intrinsics | none |
| build.rs | none (no `build.rs` file; `vet-facts` reports none) |
| proc-macro | no |
| Exported macros | none |
| Powerful imports | none. `#![no_std]` (`src/lib.rs:1`), `alloc` only behind the `alloc` feature (`:5-7`). No `std::{fs,net,process,env}`, `env!`, `option_env!`, `include_bytes!`, `include_str!`. |
| Binary content | none |
| Dependencies | `ff` 0.14, `rand_core` 0.10, `subtle` 2.2.1. Optional: `rand` 0.10, `rand_xorshift` 0.5 (feature `tests`), `memuse` 0.2 (feature `wnaf-memuse`). |
| Features ACDP enables | `alloc` only: root `--all-features` (normal and dev edges), `acdp --no-default-features`, and the py, node and wasm bindings alike. `tests` and `wnaf-memuse` are off, so `rand`, `rand_xorshift` and `memuse` are not compiled. |
| Reached via | `elliptic-curve` 0.14.1 and `wnaf` 0.14.1 (the only direct dependents), under `p256` -> `acdp-crypto` (P-256 signing and verification, for example `crates/acdp-crypto/src/verify.rs:57`, `crates/acdp-did/src/key.rs:150`). ACDP names `group` nowhere directly (no hits in `crates/`, `src/`, `tests/`). |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour (what was read)

- `src/lib.rs`, `src/cofactor.rs` and `src/prime.rs` are trait definitions (`Group`,
  `Curve`, `CurveAffine`, `GroupEncoding`, `UncompressedEncoding`, `CofactorGroup`,
  `PrimeGroup` and friends) plus three default methods:
  - `Group::random` (`src/lib.rs:81-84`) is an irrefutable `let Ok(..)` over an infallible
    RNG;
  - `Curve::batch_normalize` (`:121-127`) asserts equal lengths, then converts element by
    element;
  - `CofactorGroup::is_small_order` (`src/cofactor.rs:38-40`).
  The `unchecked` decoders are documented as dangerous (`src/lib.rs:194-199`, `:215-221`).
  The curve implementations (here `primeorder`, see its worksheet) decide what they do.
- `src/wnaf.rs` (feature `alloc`, compiled): `wnaf_table` (`:18-28`), the `LimbBuffer`
  little-endian limb reader (`:34-89`, slicing bounded by the `match` on `buf.len()`),
  `wnaf_form` (`:93-147`) and `wnaf_exp` (`:153-175`, table lookups bounds-checked).
  `LimbBuffer::get` asserts the requested limb is the current or next one (`:83`).
- **Nothing in ACDP's graph calls group's wNAF helpers.** `primeorder` uses the separate
  `wnaf` crate (B1-audited) for its variable-time multiplication
  (`primeorder-0.14.0/src/projective.rs:29`, `:42-45`), and no dependent references
  `group::Wnaf*` (grep over `elliptic-curve`, `primeorder`, `p256`, `ecdsa`, `wnaf`,
  `primefield` sources).
- `src/tests/mod.rs` is a curve test-suite generator over a fixed-seed XorShift RNG; it is
  compiled only with the `tests` feature (off).

## Observation G-1 (non-blocking)

`wnaf_form` accepts `window` in `2..=64` by `debug_assert` only (`:95-97`). The endpoints
misbehave: `window = 64` makes `1u64 << window` (`:107`) overflow, and `window = 0` makes
`1 << (window - 1)` in `wnaf_table` (`:20`, `:24`) underflow. In a debug build each is an
overflow panic; in a release build the shift masks to a meaningless window, which `wnaf_exp`'s
bounds-checked indexing then turns into a panic or a wrong result. It is never memory
unsafety, `recommended_wnaf_for_num_scalars` is documented to return 2..=22, and no crate in
ACDP's graph calls these helpers.

## Concerns

None. Safe-Rust trait definitions plus an allocation-backed wNAF helper; no `unsafe`, no
I/O, no build-time code.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance.
