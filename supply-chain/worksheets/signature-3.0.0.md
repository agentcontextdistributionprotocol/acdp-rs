# Review worksheet: `signature` 3.0.0 (issue #322, Phase 2)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "3.0.0"`).
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 3.0.0 (locked) | `28d567dcbaf0049cb8ac2608a76cd95ff9e4412e1899d389ee400918ca7537f5` | `Cargo.lock` checksum |
| 2.2.0 (prior audit) | `77549399552de45a898a580c1b41d445bf730df867cc44e6c0233bbc4b8329de` | crates.io index `cksum` |

The tarballs were downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`,
and both sha256 values match. Reproduce the facts with
`scripts/vet-facts.sh signature 3.0.0 2.2.0`.

## Method

- Delta 2.2.0 -> 3.0.0: 11 files, +632/-431 (excluding Cargo.lock, Cargo.toml.orig, and
  .cargo_vcs_info.json). That is 1,063 changed lines against 798 `src/` lines, a ratio of
  1.33.
- The ratio is at least 0.75, so the method rule says **full**.
- Every file in the crate was read: `Cargo.toml`, `Cargo.toml.orig`, `src/lib.rs`,
  `src/error.rs`, `src/encoding.rs`, `src/keypair.rs`, `src/hazmat.rs`,
  `src/verifier.rs`, and `src/signer.rs`.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0. `#![forbid(unsafe_code)]` is at `src/lib.rs:8`, unconditional. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no. The optional `derive` dependency on `signature_derive`, which 2.2.0 had, was **removed** in 3.0.0. |
| Powerful imports | none. The crate is `#![no_std]`; `extern crate alloc` applies only under the `alloc` feature. The only `include_str!` is `#![doc = include_str!("../README.md")]`, a compile-time doc string. There is no `std::{fs,net,process,env}`, `env!`, `option_env!`, or `include_bytes!`. |
| Dependencies | `digest` 0.10.6 becomes `0.11` (optional, `default-features = false`). `rand_core` 0.6.4 becomes `0.10` (optional, `default-features = false`). Removed: `derive`, plus the dev-deps `hex-literal` and `sha2`. |
| Features ACDP enables | `alloc`, `digest`, `rand_core` (from `cargo tree -e features`, via ed25519 / ed25519-dalek / ecdsa) |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Trait surface (what was read)

- **Signing:** `Signer`, `MultipartSigner`, `SignerMut`, `DigestSigner<D: Update, S>`, and
  the `rand_core`-gated `RandomizedSigner`, `RandomizedMultipartSigner`,
  `RandomizedDigestSigner`, `RandomizedSignerMut`, and `RandomizedMultipartSignerMut`,
  plus the `Async*` equivalents. Blanket impls:
  - `RandomizedSignerMut` for every `RandomizedSigner`;
  - `AsyncSigner` for every `Signer`;
  - `AsyncRandomizedSigner` for every `RandomizedSigner`.

  They only forward to the synchronous method.
- **Verifying:** `Verifier`, `MultipartVerifier`, `DigestVerifier`, `AsyncVerifier` (blanket
  impl over `Verifier`), `AsyncMultipartVerifier` (blanket), and `AsyncDigestVerifier`.
- **Hazmat:** `PrehashSigner`, `RandomizedPrehashSigner`, `PrehashVerifier`,
  `AsyncPrehashSigner`, and `AsyncRandomizedPrehashSigner`. These are declarations only;
  the warnings are documented.
- **Other:** `Keypair` (blanket impl over `KeypairRef: AsRef<VerifyingKey>`, which
  clones), and `SignatureEncoding` (its default `to_bytes` clones and calls
  `try_into().ok().expect(..)`).
- **`Error`:** an opaque `#[non_exhaustive]` struct. Under `alloc` it has an optional
  `Box<dyn core::error::Error + Send + Sync>` source. `Debug` and `Display` print no
  secret data.
- **Panics:** the default infallible methods (`sign`, `multipart_sign`, `sign_digest`,
  `sign_with_rng`, and the others) call `.expect("signature operation failed")` on the
  `try_*` result. This is documented behaviour, not a safety issue. ACDP signs with
  ed25519-dalek, whose `try_sign` is infallible for in-memory keys.

## Concerns

None. This is a pure trait-definition crate: no `unsafe`, no I/O, no build-time code, and
a smaller dependency surface than 2.2.0, since the proc-macro dependency was dropped.

## Not claimed

Cryptographic correctness, constant-time behaviour, and side-channel resistance. Those
belong to implementors (ed25519-dalek, ecdsa), which are reviewed in Phases 3 and 4.
`digest 0.11` and `rand_core 0.10` are Tier B and remain exempted. This audit is per crate.
