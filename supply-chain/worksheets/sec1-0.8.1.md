# Review worksheet: `sec1` 0.8.1 (issue #339, Tier B batch B2)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.8.1"`). No concern-rule
  trigger. One `Discretion:` line records the test-only binary fixture.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.8.1 (locked) | `d56d437c2f19203ce5f7122e507831de96f3d2d4d3be5af44a0b0a09d8a80e4d` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is byte-identical (`diff -r`) to the
`~/.cargo/registry/src` copy that was read. Reproduce the facts with
`scripts/vet-facts.sh sec1 0.8.1`.

## Method

- No prior audit of `sec1` exists in `audits.toml` or the imported sets, so **full**.
- `src/` is 1,274 lines. Every file was read in full: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (67), `src/error.rs` (61), `src/parameters.rs` (77),
  `src/private_key.rs` (176), `src/traits.rs` (77), `src/point.rs` (816, of which
  `:590-816` is `#[cfg(test)]`). `tests/*.rs` and `tests/examples/*` inspected
  (test-only).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0. `#![forbid(unsafe_code)]` unconditional at `src/lib.rs:8`. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no |
| Powerful imports | Filesystem only, behind `std`, which ACDP enables: `use std::path::Path` (`src/traits.rs:7-8`) for the provided trait methods `DecodeEcPrivateKey::read_sec1_der_file` (`:36-39`) and `EncodeEcPrivateKey::write_sec1_der_file` (`:66-69`), delegating to `der::SecretDocument`. PEM variants need `pem` (off). Explicit caller-invoked helpers on a caller-chosen path; unused by the crate and by ACDP (grep). No network, process or env access. |
| Binary content | `tests/examples/p256-priv.der` (121 bytes, ASN.1 SEQUENCE) and `.pem`, loaded only by `tests/`. Not compiled into any non-test build. Recorded as a discretion line. |
| Dependencies | optional `base16ct` 1, `ctutils` 0.4, `der` 0.8 (`oid`), `hybrid-array` 0.4.6, `serdect` 0.4, `subtle` 2, `zeroize` 1. Dev-only: `hex-literal`, `tempfile`. |
| Features ACDP enables | `alloc`, `ctutils`, `default`, `der`, `point`, `std`, `subtle`, `zeroize` (root `--all-features` and py/node/wasm bindings identical). `pem`, `serde` off. |
| Reached via | `elliptic-curve` 0.14.1. **On ACDP's untrusted-input path:** `p256::ecdsa::VerifyingKey::from_sec1_bytes` (called from `crates/acdp-did/src/key.rs:150` and the P-256 verify paths in `crates/acdp-types/src/{receipt,lifecycle,log,cosignature}.rs`) parses through `EncodedPoint::from_bytes`. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour (what was read)

- `EncodedPoint::from_bytes` (`src/point.rs:82-102`): reads the tag byte (`first()`,
  error on empty), validates it with `Tag::from_u8` (`:527-536`: 0, 2, 3, 4, 5 only),
  requires `input.len() == tag.message_len(field_size)` exactly, then copies into an
  `Array` of the uncompressed size (`1 + 2*n`, always `>= expected_len`). No panic path.
- Invariant: `bytes[0]` is always a valid tag. Every constructor (`from_bytes`,
  `from_affine_coordinates` `:114-134`, `identity`/`Default` = 0, `ct_select` /
  `conditional_select` choosing between two valid points, `Zeroize` resetting to identity
  `:449-452`) preserves it, and the field is private. So the `expect("invalid tag")` in
  `tag()` (`:184-187`) and the `expect("size invariants were violated")` in
  `coordinates()` (`:196-211`) are unreachable.
- `FromStr` (`:350-356`) decodes hex into a fixed max-size buffer, then re-validates
  through `from_bytes`.
- `EcPrivateKey::decode_value` (`src/private_key.rs:99-116`): version must be 1; key,
  parameters and public key are borrowed slices from `der`'s bounded reader. `Debug`
  (`:146-153`) omits the private key.
- `ModulusSize` (`:31-56`) is a type-level size computation only.

## Findings for ACDP (not vet concerns)

- The compact tag `0x05` is accepted by `from_bytes`; this is the p256 worksheet's
  finding P-2 (informational: ACDP fingerprints use the re-compressed point).

## Concerns

None.

## Not claimed

Cryptographic correctness (including point validity, which is checked by the curve crate),
constant-time behaviour, side-channel resistance, and ASN.1 parsing correctness (delegated
to `der`, Tier B, still exempted).
