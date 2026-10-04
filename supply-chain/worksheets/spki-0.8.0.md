# Review worksheet: `spki` 0.8.0 (issue #339, Tier B batch B1)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.8.0"`). No concern-rule
  trigger. One `Discretion:` line records the test-only DER fixtures.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.8.0 (locked) | `1d9efca8738c78ee9484207732f728b1ef517bbb1833d6fc0879ca898a522f6f` | `Cargo.lock` checksum |

There is no prior audit of `spki` (ours or imported), so there is no delta base. The tarball
was also downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`; its
sha256 matches, and its extracted tree is identical to the `~/.cargo/registry/src` copy that
was read (only cargo's `.cargo-ok` marker differs). Reproduce the facts with
`scripts/vet-facts.sh spki 0.8.0`.

## Method

- **Full** (no audited base). `src/` is 828 lines.
- Read in full: `Cargo.toml`, `Cargo.toml.orig`, `src/lib.rs` (77), `src/algorithm.rs` (213),
  `src/spki.rs` (231), `src/traits.rs` (217), `src/error.rs` (74), `src/digest.rs` (16),
  `benches/mod.rs` (32).
- Read for powerful imports / fixtures: `tests/spki.rs` (191), `tests/traits.rs` (103), the six
  files in `tests/examples/`.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 sites (full-source grep; forbid is capped by --cap-lints for registry deps, so the grep is the evidence). `#![forbid(unsafe_code)]` is at `src/lib.rs:8`. |
| asm / SIMD / intrinsics | none |
| build.rs | none |
| proc-macro | no (optional `arbitrary` uses `derive`; feature off in ACDP) |
| Powerful imports | **Filesystem, opt-in, off in ACDP.** Under the `std` feature, `DecodePublicKey::read_public_key_der_file` / `read_public_key_pem_file` and `EncodePublicKey::write_public_key_der_file` / `write_public_key_pem_file` (`src/traits.rs:18-19,55-70,105-122`) take a caller-supplied `Path` and delegate to `der::Document`'s file helpers. These are explicit, documented API calls with caller-chosen paths, not ambient I/O; `std` is not enabled in any ACDP build. No `std::{net,process,env}`, `env!`, `option_env!`. `include_str!("../README.md")` is a doc string (`src/lib.rs:3`). The `include_bytes!` in `tests/` and `benches/` load the fixtures below and are not part of the library. |
| Binary content | `tests/examples/{ed25519-pub,p256-pub,rsa2048-pub}.der` (44, 91, 294 bytes). Each is byte-identical to the base64 body of its sibling `.pem` (checked by decoding). Used only by `tests/*.rs` and `benches/mod.rs` (a nightly `#![feature(test)]` bench). Recorded as a discretion line. |
| Dependencies | `der` 0.8 (`oid`); optional `arbitrary` 1.4, `base64ct` 1, `digest` 0.11, `sha2` 0.11. Dev: `hex-literal`, `tempfile` (used by `tests/traits.rs` for the file round-trip tests). |
| Features ACDP enables | `alloc` only (root `--all-features` and the py, node, wasm bindings, from `cargo tree -e features`; via `ecdsa`'s `spki` feature). `std`, `pem`, `base64`, `fingerprint`, `digest`, `arbitrary` are off. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## What the code does

- `AlgorithmIdentifier<Params>` (`src/algorithm.rs:25-32`): DER `SEQUENCE { oid, parameters
  OPTIONAL }`, decoded and encoded through `der`'s `Reader` / `Writer` traits
  (`:34-61`); `assert_algorithm_oid` / `assert_parameters_oid` / `assert_oids` compare OIDs
  and return `Error::OidUnknown` on mismatch (`:106-145`); `oids()` treats a `NULL`
  parameter as absent (`:172-186`).
- `SubjectPublicKeyInfo<Params, Key>` (`src/spki.rs:52-58`): `SEQUENCE { algorithm,
  subjectPublicKey }`, same decode/encode pattern (`:99-128`); optional SHA-256 fingerprint
  through `DigestWriter` (`fingerprint` feature, `:91-96`; `src/digest.rs`).
- `traits.rs`: `DecodePublicKey` (blanket impl over `TryFrom<SubjectPublicKeyInfoRef>`,
  `:73-80`), `EncodePublicKey`, `AssociatedAlgorithmIdentifier`,
  `SignatureAlgorithmIdentifier`, and their `Dyn*` allocating forms.
- All parsing is delegated to `der`; this crate adds no length arithmetic or buffer
  handling of its own.

**ACDP use.** Pulled in by `ecdsa` 0.17.0's `spki` feature for the `AssociatedAlgorithmIdentifier`
/ `SignatureAlgorithmIdentifier` impls. ACDP's wire paths parse P-256 keys as SEC1 points
(`VerifyingKey::from_sec1_bytes`) and never decode SPKI DER, so `spki`'s decoders are not on
an ACDP input path.

## Concerns

None.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, and DER parsing
correctness, which lives in `der` 0.8.1 (Tier B, still exempted).
