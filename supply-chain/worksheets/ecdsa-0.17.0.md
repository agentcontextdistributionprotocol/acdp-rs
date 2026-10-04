# Review worksheet: `ecdsa` 0.17.0 (issue #322, Phase 4)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.17.0"`). No concern-rule
  trigger. One `Discretion:` line records the test-only binary fixture.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.17.0 (locked) | `c0681a4fc24c767085329728d8dfba959af91228aa4610cca4f8ce317ba46ae0` | `Cargo.lock` checksum |
| 0.16.9 (prior audit) | `ee27f32b5c5292967d2d4a9d7f1e0b0aed2c15daded5a60300e4abb9d8020bca` | crates.io index `cksum` |

The locked tarball was also downloaded from `static.crates.io` independently of
`scripts/vet-facts.sh`; its sha256 matches, and its extracted tree is byte-identical to the
`~/.cargo/registry/src` copy that was read. Reproduce the facts with
`scripts/vet-facts.sh ecdsa 0.17.0 0.16.9`.

## Method

- Delta 0.16.9 -> 0.17.0: 13 files, +1516/-1259 per `vet-facts.sh` (the plan quoted 14
  files, +1548/-1289 from `cargo vet suggest`). 2,775 changed lines against 3,336 `src/`
  lines is a ratio of 0.83, so the method rule says **full**.
- Read in full: `Cargo.toml`, `src/lib.rs`, `src/hazmat.rs`, `src/verifying.rs`,
  `src/signing.rs`.
- Read for `unsafe` / powerful imports / panics / I/O: `src/der.rs`, `src/recovery.rs`,
  `src/dev.rs` (feature `dev`, off in ACDP).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 (grep, comment lines excluded). `Cargo.toml` `[lints.rust] unsafe_code = "forbid"`; note that Cargo caps lints for registry dependencies, so the grep, not the lint, is the evidence for ACDP builds. |
| asm / SIMD / intrinsics | none |
| build.rs | none |
| proc-macro | no |
| Powerful imports | none in the compiled crate. `#![no_std]`, `alloc` only under `alloc`; `include_str!("../README.md")` is a doc string. The one `include_bytes!` (`src/dev.rs:256`) is inside the `new_wycheproof_test!` macro, in the `dev` module (`#[cfg(feature = "dev")]`, `src/lib.rs:43-44`), expanded only by test code. |
| Binary content | `src/test_vectors/data/wycheproof-mock.blb`, 2 bytes (`00 00`, an empty blobby file), consumed only by the `cfg(test)` `wycheproof_mock` test (`src/dev.rs:308-319`). Not compiled into any non-test build. Recorded as a discretion line. |
| Dependencies | `der` 0.7 -> 0.8, `digest` 0.10.7 -> 0.11 (`oid`), `elliptic-curve` 0.13.6 -> 0.14, `rfc6979` 0.4 -> 0.6, `serdect` 0.2 -> 0.4, `sha2` 0.10 -> 0.11 (optional), `signature` `>=2.0,<2.3` -> 3, `spki` 0.7.2 -> 0.8; **added** `zeroize` 1.5. |
| Features ACDP enables | `algorithm, alloc, der, digest, spki, std` — identical in the root workspace (`--all-features`) and the py, node, and wasm32 bindings (`cargo tree -e features`). `pkcs8`, `pem`, `serde`, `sha2`, `dev`, `getrandom` (of this crate) are off. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour ACDP relies on

ACDP calls `Signature::from_slice`, `VerifyingKey::{from_sec1_bytes, verify,
to_sec1_point}`, and `SigningKey::{generate_from_rng, from_bytes, to_bytes, sign,
verifying_key}` through `p256::ecdsa` (see the p256 worksheet for the ACDP call sites).

- **Signature parsing.** `Signature::from_slice` (`src/lib.rs:212-216`) requires exactly
  64 bytes, then `from_scalars` (`:237-247`) requires `r` and `s` in `[1, n-1]`
  (`ScalarValue::from_slice` range check, then explicit zero rejection).
- **Hash-then-verify.** `Verifier::verify` -> `multipart_verify` -> `verify_digest` with
  `C::Digest` (SHA-256 for P-256, `p256/src/ecdsa.rs:72-74`) -> `verify_prehash` ->
  `hazmat::verify_prehashed` (`src/hazmat.rs:136-158`): `z = bytes2scalar(H(m))`
  (truncate to `n`'s bit length, reduce mod `n`), `s⁻¹` via `invert_vartime` (public
  data), `x(u1·G + u2·Q)` via `mul_by_generator_and_mul_add_vartime`, then compare
  `r == x mod n`.
- **Low-S / malleability.** `verify_prehashed` rejects high-S only when
  `C::NORMALIZE_S` (`:142`). P-256 sets `NORMALIZE_S = false`
  (`p256/src/ecdsa.rs:60`), so both `(r, s)` and `(r, n-s)` verify. ACDP-relevant
  finding P-1 (p256 worksheet).
- **Signing.** `Signer::sign` -> `sign_prehash` -> `sign_prehashed_rfc6979`
  (`src/hazmat.rs:102-125`): RFC 6979 `KGenerator` (rfc6979 0.6, HMAC-SHA-256), retry
  until `k` is a valid non-zero scalar and `sign_prehashed` (`:52-94`) yields non-zero
  `r, s`. `R = k·G` uses the non-vartime `mul_by_generator`; `k⁻¹` uses the
  constant-time-intended `invert`. No low-S normalization for P-256.
- **Not reached by ACDP:** DER signatures (`der.rs`; the ACDP wire form is r‖s and DER is
  rejected by length), `SignatureWithOid`, public-key recovery (`recovery.rs`).

## Zeroize interplay (zeroize 1.9.0 remains exempt, DECISIONS.md `322-zeroize`)

- `SigningKey` has an explicit `Drop` that zeroizes `secret_scalar: NonZeroScalar<C>`
  (`src/signing.rs:453-459`) plus a `ZeroizeOnDrop` marker. `SigningKey` derives `Clone`,
  so every clone zeroizes independently. `Signature::zeroize` (`src/lib.rs:483-488`) writes
  `ONE` to both components (no secret).
- These zeroize fully initialized fixed-width integers; no `Option<Z>` / `MaybeUninit` /
  padded type, so zeroize's Z-1 is not triggered.
- **Hygiene observation (not a vet concern, unchanged from 0.16.9):** temporaries derived
  from secrets are not zeroized: `d.to_repr()` passed into `KGenerator::new`
  (`src/hazmat.rs:112`), the `k_bytes` buffer and `k` scalar in the RFC 6979 loop
  (`:114-123`), and rfc6979 0.6's HMAC-DRBG state (no zeroize dependency at all). The
  same pattern exists in the audited 0.16.9 / rfc6979 0.4.0. Stack residue is outside the
  `safe-to-deploy` scope.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance.

These Tier B crates remain exempted: `rfc6979 0.6.0`, `hmac 0.13.0`, `der 0.8.1`,
`spki 0.8.0`, `digest 0.11.3`. (`elliptic-curve`, `signature`, `subtle` are audited;
`zeroize` is exempt under `322-zeroize`.)
