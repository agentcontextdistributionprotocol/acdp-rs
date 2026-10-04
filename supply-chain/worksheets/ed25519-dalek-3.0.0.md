# Review worksheet: `ed25519-dalek` 3.0.0 (issue #322, Phase 3)

- **Verdict:** CERTIFIED `safe-to-deploy`, delta audit (`delta = "2.2.0 -> 3.0.0"`).
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 3.0.0 (locked) | `6ebaa1a2bf1290ab3bfe5a7b771d050ebffab2711c19a81691c683a5144a25de` | `Cargo.lock` checksum |
| 2.2.0 (prior audit) | `70e796c081cee67dc755e1a36a0a172b897fab85fc3f6bc48307991f64e4eca9` | crates.io index `cksum` |

To reproduce: `scripts/vet-facts.sh ed25519-dalek 3.0.0 2.2.0`.

## Method

- Delta 2.2.0 -> 3.0.0: 17 files, +770/-264 (excluding Cargo.lock, Cargo.toml.orig, and
  .cargo_vcs_info.json). That is 1,034 changed lines against 3,552 `src/` lines, a ratio
  of 0.29, so the method rule says **delta**. No rewrite clause applies: the crate has
  no `unsafe` at either version.
- Every hunk of the `src/` and `Cargo.toml` diff was read: `lib.rs`, `errors.rs`,
  `context.rs`, `hazmat.rs`, `signature.rs`, `signing.rs`, `verifying.rs`,
  `verifying/stream.rs`, `batch.rs`, and the new `batch/transcript.rs` (read in full).
  Tests, benches, README, and CHANGELOG were skimmed.
- **Base spot-check (2.2.0, audited 2026-07-05).** The base note says "no build.rs,
  unsafe only via vetted curve25519-dalek backends, zeroizes secret material, no
  network/fs/process access". Confirmed: 2.2.0 has `#![cfg_attr(not(test),
  forbid(unsafe_code))]`, no build script, and `Drop` zeroizing `SigningKey` and
  `ExpandedSecretKey`.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0, in every feature configuration (grep of `src/` finds only prose links to "ed25519-unsafe-libs"). |
| `forbid(unsafe_code)` | **Now conditional:** `src/lib.rs:246` is `#![cfg_attr(not(any(test, feature = "batch")), forbid(unsafe_code))]`. In 2.2.0 it was `not(test)` only. ACDP does not enable `batch` (see below), so the lint is active in every ACDP build. With `batch` on, the lint is off, but there is still no `unsafe` in the crate source. |
| asm / SIMD | none |
| build.rs / proc-macro | none / no |
| Powerful imports | none. `#![no_std]`; `extern crate std` only under `cfg(test)`. The `std` feature was **removed**; `core::error::Error` is used instead. |
| Dependencies | `curve25519-dalek` 4 -> 5.0.0, `ed25519` 2.2 -> 3, `sha2` 0.10 -> 0.11, `signature` 2 -> 3, `rand_core` 0.6.4 -> 0.10. **Removed:** `merlin` and the `asm` feature (`sha2/asm`). **Added (optional, `batch` only):** `keccak` 0.2 and `strobe-rs` 0.13, used by a vendored Merlin transcript (`src/batch/transcript.rs`). Neither is in ACDP's graph. |
| Features ACDP enables | `default`, `fast`, `rand_core`, `signature`, `zeroize`. The same set in the root workspace (all features, all targets, including dev-deps), `bindings/acdp-py`, `bindings/acdp-node`, and `bindings/acdp-wasm` (wasm32), from `cargo tree -e features`. `batch`, `hazmat`, `digest`, `pkcs8`, `serde`, and `legacy_compatibility` are **not** enabled. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## What changed (read)

- **Multipart API.** `Signer::try_sign` now forwards to `MultipartSigner::try_multipart_sign`,
  and `Verifier::verify` to `MultipartVerifier::multipart_verify`. `raw_sign` and
  `raw_verify` take `&[&[u8]]` and feed each slice to the hasher in order. For a single
  message slice the hash input is byte-identical to 2.2.0.
- **Digest API.** `DigestSigner` / `DigestVerifier` now take a closure that fills a fresh
  `D::new()`, instead of a pre-filled digest (signature 3 trait shape). Prehashed sign
  and verify themselves are unchanged. Not used by ACDP.
- **Key traits.** New `KeySizeUser` / `TryKeyInit` (`digest` feature) and `Generate`
  (`digest` + `rand_core`) for `SigningKey`. `TryKeyInit::new` calls `from_bytes`.
  `Generate::try_generate_from_rng` mirrors `generate`, but with a fallible RNG.
- **RNG.** `SigningKey::generate` takes `rand_core` 0.10 `CryptoRng` and is gated on
  `feature = "rand_core"` only (it was `any(test, rand_core)`). ACDP passes
  `UnwrapErr(SysRng)`.
- **pkcs8.** `DynSignatureAlgorithmIdentifier` was replaced by the static
  `SignatureAlgorithmIdentifier`; `PrivateKeyInfo` became `PrivateKeyInfoRef`; error
  variants changed. Not enabled by ACDP.
- **Batch.** `merlin` was replaced by a vendored transcript over `strobe-rs`. It is safe
  code with no I/O. Not enabled by ACDP.
- **Errors.** `InternalError` implements `core::error::Error` unconditionally.
  `SignatureError::from_source` is used under `alloc` (it was under `std`).

## Verification semantics (relevant to ACDP)

ACDP verifies with `VerifyingKey::verify` (`crates/acdp-crypto/src/verify.rs:30,63`),
not `verify_strict`. The checks behind it are **unchanged** in this delta:

- `InternalSignature::try_from` runs `check_scalar` (`src/signature.rs:87-95`):
  `Scalar::from_canonical_bytes`. It rejects any `s >= l`, so scalar malleability is
  rejected. `legacy_compatibility`, which relaxes this check (`signature.rs:68-84`), is
  not enabled.
- `raw_verify` (`src/verifying.rs:211`) recomputes `R' = [s]B - [k]A` and compares its
  compressed encoding with the signature's `R` bytes. So a non-canonical `R` encoding
  cannot verify. The comparison is now constant-time, because curve25519-dalek 5's
  `CompressedEdwardsY: PartialEq` became `ct_eq`. It still means byte equality.
- `verify` does **not** reject small-order (weak) public keys or a small-order `R`.
  `verify_strict` (`verifying.rs:367`) adds both checks, and `VerifyingKey::is_weak`
  (`verifying.rs:200`) is available. That was also true of 2.2.0.

**Finding E-1 (non-blocking, ACDP-side; not a vet concern).** Because ACDP's verify path
accepts weak keys, a producer that publishes a small-order key in its DID document could
create signatures that verify for more than one message (a repudiation or ambiguity
property of that producer's own key). Upstream documents this trade-off. Recommendation:
open a follow-up issue to evaluate `verify_strict` or an `is_weak()` rejection at DID-key
load. That change touches the signature-acceptance surface, so it needs spec input
(RFC-ACDP-0002) and golden-vector review. It is not part of this audit.

## Secret handling (zeroize)

- `impl Drop for SigningKey` (`src/signing.rs:719`) zeroizes `secret_key: [u8; 32]`.
- `impl Drop for ExpandedSecretKey` (`src/hazmat.rs:68`) zeroizes `scalar` (a `Scalar`,
  whose impl zeroizes `[u8; 32]`) and `hash_prefix: [u8; 32]`.
- Both are unchanged from 2.2.0 and gated on `zeroize`, which ACDP enables.
- Every target is a fully initialized integer array. Neither crate zeroizes an
  `Option<Z>`, `MaybeUninit`, or a padded type, so no dalek call site triggers zeroize
  1.9.0's Z-1 (DECISIONS.md `322-zeroize`). Whether the zeroize barrier stops a
  compiler from eliding the writes is zeroize's property. zeroize stays exempt and is not
  claimed here.
- As in 2.2.0, `SigningKey::generate` leaves its stack temporary `secret: SecretKey`
  un-zeroized (`signing.rs:213-217`). This is an upstream hardening gap, not a soundness
  issue.

## Concerns

None under the concern rule. There is no `unsafe`, no I/O, and no build-time code. The
only safety-lint change (`forbid` lifted under `batch`) does not affect ACDP and covers no
`unsafe` code.

## Not claimed

The review does not claim:
- cryptographic correctness;
- constant-time behaviour;
- side-channel resistance.

As behavioural evidence only, the `sig-001` golden vector pins the Ed25519 signature
bytes.

These Tier B crates remain exempted: `ed25519 3.0.0`, `rand_core 0.10.1`, and
`digest 0.11.3`. `curve25519-dalek 5.0.0` is audited separately in this phase.
