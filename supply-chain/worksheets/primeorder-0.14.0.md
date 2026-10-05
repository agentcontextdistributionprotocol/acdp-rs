# Review worksheet: `primeorder` 0.14.0 (issue #339, Tier B batch B3)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.14.0"`). No concern-rule
  trigger.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.14.0 (locked) | `5c9f42978c78a00e3d68f69fc03e57a234debae69da4020a4fb588fcdcd07b06` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is identical (`diff -r`) to the
`~/.cargo/registry/src` copy that was read, except Cargo's own `.cargo-ok` marker. Reproduce
the facts with `scripts/vet-facts.sh primeorder 0.14.0`.

The root `Cargo.lock` and all three binding lockfiles (py, node, wasm) lock 0.14.0 with the
same checksum.

## Method

- No prior audit of `primeorder` exists in `audits.toml` or the imported sets, so **full**.
- `src/` is 2,899 lines. Every file was read in full: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (84), `src/affine.rs` (574), `src/projective.rs` (1,004),
  `src/point_arithmetic.rs` (456), `src/mul_backend.rs` (68), `src/tables.rs` (12),
  `src/tables/lookup.rs` (82), `src/tables/radix16.rs` (173), `src/tables/basepoint.rs`
  (144, feature `basepoint-table`), `src/osswu.rs` (150, feature `hash2curve`), `src/dev.rs`
  (152, feature `dev`).
- There is no `tests/` or `benches/` directory. The packaged `Cargo.lock` is ignored for
  dependents.
- The code is generic over the curve (`C: PrimeCurveParams`) and is monomorphized in `p256`.
  `p256` 0.14.0 binds it to `EquationAIsMinusThree` and the `VariableOnly` backend
  (`p256-0.14.0/src/arithmetic.rs:44`, `:47`, the non-`precomputed-tables` branch).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 sites (full-source grep, including the `#[macro_export]` macro in `src/dev.rs`). There is no `#![forbid(unsafe_code)]` attribute. The `Cargo.toml` `[lints]` (expanded from upstream's workspace) are `warn`/`allow` levels only, and none of them is `unsafe_code`. The grep is the evidence. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no |
| Exported macros | `test_projective_arithmetic!` (`src/dev.rs:4-152`), which generates `#[test]` functions. It exists only with the `dev` feature (`src/lib.rs:21-22`), which is off; no `unsafe`, no imports. |
| Powerful imports | none. `#![no_std]` (`src/lib.rs:1`). `extern crate std` only with `std` (`:12-13`), used only by `std::sync::LazyLock` in the `basepoint-table` code (`src/tables/basepoint.rs:18-19`), which is not compiled. The only `include_str!` is the README doc (`src/lib.rs:3`). |
| Dependencies | `elliptic-curve` 0.14.1 (`arithmetic`, `sec1`), `primefield` 0.14, `wnaf` 0.14. Optional: `once_cell` 1.21, `serdect` 0.4. |
| Features ACDP enables | `alloc`, `std`: root `--all-features` (normal and dev edges), `acdp --no-default-features`, and the py, node and wasm bindings alike. `basepoint-table`, `critical-section`, `hash2curve`, `serde` and `dev` are off, so `once_cell` and `serdect` are not compiled. |
| Reached via | `p256` 0.14.0 (only dependent), under `acdp-crypto` and `acdp-did`. ACDP names `primeorder` nowhere directly (no hits in `crates/`, `src/`, `tests/`). |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## What ACDP reaches

- **Untrusted P-256 public keys.** `p256::ecdsa::VerifyingKey::from_sec1_bytes`
  (`crates/acdp-did/src/key.rs:150`, `crates/acdp-crypto/src/fingerprint.rs:28`) goes to
  `elliptic-curve`'s `PublicKey::from_sec1_bytes`, then to
  `AffinePoint::from_sec1_point` (`src/affine.rs:222-231`):
  - uncompressed input goes through `from_coordinates` (`:100-108`): both coordinates via
    `FieldElement::from_repr`, kept only if `y^2 = x^3 + ax + b` holds;
  - compressed input goes through `decompress` (`:183-198`): `from_repr`, then `sqrt`, then
    parity selection;
  - the SEC1 identity maps to `IDENTITY` (`:224`). Rejecting the identity as a public key is
    `elliptic-curve`'s job (`public_key.rs:188-192`), not this crate's.
- **Verification** (`ecdsa` `hazmat.rs:150`):
  `mul_by_generator_and_mul_add_vartime` (`src/mul_backend.rs:31-40`), then
  `lincomb_vartime` (`src/projective.rs:498-510`), then the `wnaf` crate (B1-audited).
- **Signing** (`ecdsa` `hazmat.rs:67`): `mul_by_generator` (`src/mul_backend.rs:16-18`), then
  `ProjectivePoint::mul` (`src/projective.rs:133-137`), which builds a `LookupTable`
  (`src/tables/lookup.rs:30-38`) and a `Radix16Decomposition`
  (`src/tables/radix16.rs:31-55`) and runs `lincomb` (`src/projective.rs:532-557`).

## Behaviour (what was read)

- **Point formulas** (`src/point_arithmetic.rs`): the complete Renes-Costello-Batina 2015
  formulas, as straight-line field arithmetic over the curve's `FieldElement`, for generic
  `a` (`:56-208`), `a = -3` (`:214-319`) and `a = 0` (`:325-455`). There is no indexing and
  there are no branches on data. The mixed-addition variants `conditional_assign` on
  `rhs.is_identity()`. Debug builds assert that the specialized `a` matches the curve
  (`:33-49`).
- **Bounds and panics**, all checked indexing:
  - `LookupTable::select` (`src/tables/lookup.rs:43-65`) is a constant-pattern scan over 8
    entries, with a `debug_assert` on `-8..=8` (`:44`). Its digit inputs come from
    `Radix16Decomposition::new`, whose re-centering keeps digits in `[-8, 8]` and cannot
    overflow `i8` (`radix16.rs:48-52`).
  - `lincomb` indexes `digit[d - 1]` / `digit[i]` with `d = Radix16Digits` (`:539-553`).
  - `batch_normalize` asserts equal lengths (`src/projective.rs:325`), and the generic
    helper's indexing is bounds-checked (`:452-478`).
  - `to_bytes` and `to_compact_encoded_point` slice by the encoded length within the
    fixed-size `CompressedPoint` (`src/affine.rs:327-332`, `:376-383`).
- **Off in ACDP:** `basepoint-table` (`LazyLock`-initialized tables), `hash2curve` (OSSWU
  map; `tv4.invert().unwrap()` at `src/osswu.rs:146`), `serde`, `dev`.
- `ProjectivePoint::to_affine` returns `IDENTITY` when `z` is not invertible
  (`src/projective.rs:74-78`). Equality is projective cross-multiplication (`:165-170`).

## Concerns

None. Pure safe-Rust generic curve arithmetic; no `unsafe`, no I/O, no build-time code.

## Not claimed

Cryptographic correctness (including of the RCB formulas and the point validation),
constant-time behaviour (no claim is made for `select`, `lincomb` or the `conditional_*`
paths), side-channel resistance.
