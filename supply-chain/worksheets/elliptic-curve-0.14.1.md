# Review worksheet: `elliptic-curve` 0.14.1 (issue #322, Phase 4)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.14.1"`). No concern-rule
  trigger; no discretion lines needed.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.14.1 (locked) | `9d65aa39b3a5c1c9c1b745c9a019234bb7a21b77abcb4f4d266d706e2d577d65` | `Cargo.lock` checksum |
| 0.13.8 (prior audit) | `b5e6043086bf7973472e0c7dff2142ea0b680d30e18d9cc40f267efbf222bd47` | crates.io index `cksum` |

The locked tarball was also downloaded from `static.crates.io` independently of
`scripts/vet-facts.sh`; its sha256 matches, and its extracted tree is byte-identical to the
`~/.cargo/registry/src` copy that was read. Reproduce the facts with
`scripts/vet-facts.sh elliptic-curve 0.14.1 0.13.8`.

## Method

- Delta 0.13.8 -> 0.14.1: 38 files, +3422/-4284 per `vet-facts.sh` (excluding Cargo.lock,
  Cargo.toml.orig, and .cargo_vcs_info.json; the plan quoted +3120/-3988 from
  `cargo vet suggest`, which counts differently). 7,706 changed lines against 5,243 `src/`
  lines is a ratio of 1.47, so the method rule says **full**. A delta would be larger than
  the crate and would inherit the thin 2026-07-05 base note.
- Read in full: `Cargo.toml`, `src/lib.rs`, `src/point/non_identity.rs`,
  `src/scalar/nonzero.rs`, `src/scalar/value.rs`, `src/scalar/blinded.rs`,
  `src/public_key.rs`, `src/secret_key.rs`, `src/sec1.rs`.
- Read for `unsafe` / powerful imports / panics / I/O: `src/arithmetic.rs`, `src/ops.rs`,
  `src/macros.rs`, `src/hazmat.rs`, `src/field.rs`, `src/scalar.rs`, `src/point.rs`,
  `src/error.rs`, `src/secret_key/pkcs8.rs`, `src/ecdh.rs` (feature off in ACDP),
  `src/dev.rs` + `src/dev/mock_curve.rs` (feature `dev`, off in ACDP).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 4, verdicts below. The crate root is `#![deny(unsafe_code)] // Only allowed for newtype casts.` (`src/lib.rs:8`); each site carries a local `#[allow(unsafe_code)]`. |
| asm / SIMD / intrinsics | none |
| build.rs | none |
| proc-macro | no |
| Powerful imports | `#![no_std]`; `alloc` only under the `alloc` feature; no `extern crate std` (the `std` feature only forwards to `pkcs8?/std`, `sec1?/std`). The only OS access is the `getrandom` feature: `BlindedScalar::new` / `try_new` (`src/scalar/blinded.rs:44-56`) use `common::getrandom::SysRng`, the OS entropy source; `getrandom` is enabled in ACDP (via p256 `std`). Acceptable: entropy only, no fs/net/process. `include_str!("../README.md")` is a doc string. |
| Binary content | none (`tests/examples/*.der/.pem` are PKCS#8 test fixtures read only by `tests/`). |
| Dependencies | `generic-array` 0.14 -> `hybrid-array` 0.4.13 (renamed `array`), `crypto-bigint` 0.5 -> 0.7.5 (renamed `bigint`), new `crypto-common` 0.2 (`common`), `digest` 0.11, `ff`/`group` 0.14, `rand_core` 0.10, `sec1` 0.8, `pkcs8` 0.11, `base16ct` 1, `subtle` 2.6, `hkdf` 0.13 (ecdh, off), `pem-rfc7468` 1 (pem, off), `serdect` 0.4 (serde, off). Removed: `base64ct`, `serde_json`, `tap`. |
| Features ACDP enables | `alloc, arithmetic, digest, ff, getrandom, group, sec1, std` — identical in the root workspace (`--all-features`) and the py, node, and wasm32 bindings (`cargo tree -e features`). `pkcs8`, `pem`, `serde`, `ecdh`, `dev` are off. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## `unsafe` sites and verdicts

| Site | What | Verdict |
|---|---|---|
| `src/point/non_identity.rs:63` | `NonIdentity::array_as_inner`: `&*points.as_ptr().cast()` turning `&[NonIdentity<P>; N]` into `&[P; N]`. | **Sound.** `NonIdentity<P>` is `#[repr(transparent)]` over its single field `point: P` (`:25-30`), so size, alignment, and layout are identical; the result borrows the same lifetime and is shared (read-only), so the non-identity invariant cannot be broken through it. |
| `src/point/non_identity.rs:73` | `slice_as_inner`: `&*(ptr::from_ref(points) as *const [P])`. | **Sound.** Same `repr(transparent)` argument; a slice-pointer cast keeps the length metadata. |
| `src/scalar/nonzero.rs:73` | `NonZeroScalar::cast_array_as_inner`: `&[NonZeroScalar<C>; N]` -> `&[Scalar<C>; N]`. | **Sound.** `#[repr(transparent)]` over `scalar: Scalar<C>` (`:32-40`), shared borrow only. |
| `src/scalar/nonzero.rs:83` | `cast_slice_as_inner`: slice-pointer cast. | **Sound.** As above. |

No other `unsafe` keyword appears outside comments.

## Behaviour ACDP relies on (P-256 path)

- **Public-key decoding.** `PublicKey::from_sec1_bytes` (`src/public_key.rs:126`) parses with
  `sec1::EncodedPoint::from_bytes` (tag in {0x00, 0x02, 0x03, 0x04, 0x05} and exact length,
  `sec1-0.8.1/src/point.rs:82-101,527-536`), then `from_sec1_point` (`:188-194`) delegates
  the on-curve check to the curve (`primeorder` `AffinePoint::from_coordinates` checks
  `y² = x³ + ax + b` with field elements range-checked by `from_repr`; `decompress` checks
  the square root) and rejects the identity tag. See the p256 worksheet, finding P-2, for
  the 0x05 "compact" tag.
- **Scalar range checks.** `ScalarValue::new` / `from_bytes` / `from_slice`
  (`src/scalar/value.rs:69-89`) reject values `>= n`; `SecretKey::from_bytes`
  (`src/secret_key.rs:137-147`) additionally rejects zero. `NonZeroScalar::new` rejects zero.
- **Constant-time-adjacent code (not claimed as CT).** Choices and options come from
  `subtle` and, new in 0.14, `ctutils` (`ctutils::{Choice, CtOption}` re-exported via
  `crypto-bigint` 0.7, used by the SEC1 decode path). `NonZeroScalar::generate` and
  `NonIdentity::generate` rejection-sample on RNG output (documented variable time over
  public randomness).
- **Observation (upstream, not on ACDP's path):** `SecretKey`'s `Generate` impl
  (`src/secret_key.rs:398-409`) uses `ScalarValue::try_generate_from_rng`, i.e.
  `random_mod_vartime` over `[0, n)`, so it can in principle return zero (probability
  about 2^-256), contradicting the non-zero invariant that `From<&SecretKey> for
  NonZeroScalar` only `debug_assert!`s. ACDP generates keys via
  `ecdsa::SigningKey::generate_from_rng`, which goes through `NonZeroScalar` rejection
  sampling instead.

## Zeroize interplay (zeroize 1.9.0 remains exempt, DECISIONS.md `322-zeroize`)

- `SecretKey` has `Drop` -> `self.inner.zeroize()` (`src/secret_key.rs:377-385`), where
  `ScalarValue: DefaultIsZeroes` (`src/scalar/value.rs:265`) wraps a fixed-width
  `crypto-bigint` `Uint` (an array of limbs, no padding). `NonZeroScalar::zeroize`
  (`src/scalar/nonzero.rs:384-396`) zeroizes the inner `Scalar` (curve-defined; for p256 a
  `DefaultIsZeroes` `U256`) and then writes `ONE` to keep the invariant. `BlindedScalar`
  zeroizes both scalars on drop. `NonIdentity::zeroize` writes the generator (no secret).
  `Zeroizing<FieldBytes>` wraps fully initialized byte arrays.
- None of these zeroizes an `Option<Z>`, `MaybeUninit`, or a padded type, so zeroize's Z-1
  (uninitialized byte 0 read in the non-asm `optimization_barrier` fallback, compiled on
  the wasm32 binding) is not triggered by this crate. Barrier efficacy is zeroize's
  property, not claimed. `zeroize/alloc` is enabled through this crate's `alloc` feature.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance.

These Tier B crates remain exempted: `crypto-bigint 0.7.5`, `ctutils 0.4.2`,
`hybrid-array 0.4.14`, `crypto-common 0.2.2`, `digest 0.11.3`, `ff 0.14.0`, `group 0.14.0`,
`sec1 0.8.1`, `base16ct 1.0.0`, `rand_core 0.10.1`, and `getrandom 0.4.3`. (`subtle 2.6.1`
is audited.)
