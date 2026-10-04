# Review worksheet: `pkcs8` 0.11.0 (issue #339, Tier B batch B2)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.11.0"`). No concern-rule
  trigger. One `Discretion:` line records the test-only binary fixtures.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.11.0 (locked) | `451913da69c775a56034ea8d9003d27ee8948e12443eae7c038ba100a4f21cb7` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is byte-identical (`diff -r`) to the
`~/.cargo/registry/src` copy that was read. Reproduce the facts with
`scripts/vet-facts.sh pkcs8 0.11.0`.

## Method

- No prior audit of `pkcs8` exists in `audits.toml` or the imported sets, so **full**.
- `src/` is 1,153 lines. Every file was read in full: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (106), `src/error.rs` (135), `src/version.rs` (66),
  `src/private_key_info.rs` (468), `src/traits.rs` (185),
  `src/encrypted_private_key_info.rs` (193; compiled only with the `pkcs5` dependency,
  off in ACDP). `tests/*.rs` and `tests/examples/*` inspected (test-only).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 (grep of the full source, comment lines excluded; the grep is the evidence). `#![forbid(unsafe_code)]` at `src/lib.rs:8` is only a corroborating hint: Cargo builds registry dependencies with `--cap-lints allow`, which caps source-level `forbid` attributes as well as `Cargo.toml` lints. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no |
| Powerful imports | Filesystem only, behind `std`, which ACDP enables: `use std::path::Path` (`src/traits.rs:21-22`) for the provided trait methods `DecodePrivateKey::read_pkcs8_der_file` (`:90-93`) and `EncodePrivateKey::write_pkcs8_der_file` (`:170-173`), which delegate to `der::SecretDocument::{read_der_file, write_der_file}`. The PEM variants also need `pem` (off). These are explicit, caller-invoked helpers on a caller-chosen path; nothing in the crate calls them, and ACDP does not call them (grep of `crates/`, `bindings/`, `tests/`, `examples/`). Not "unexpected" I/O. No network, process or env access; `getrandom::SysRng` (`encrypted_private_key_info.rs:72`) is behind the `getrandom` feature (off). |
| Binary content | `tests/examples/*.der` (14 DER files, 44-1217 bytes, each starting with an ASN.1 SEQUENCE `0x30`; Ed25519/X25519/P-256/BIGN/RSA test keys and encrypted variants) plus matching `.pem`, loaded only by `include_bytes!`/`include_str!` and `read_*_file` in `tests/`. Not compiled into any non-test build. Recorded as a discretion line. |
| Dependencies | `der` 0.8 (`oid`), `spki` 0.8; optional `ctutils` 0.4, `getrandom` 0.4, `pkcs5` 0.8, `rand_core` 0.10. Dev-only: `hex-literal`, `tempfile`. |
| Features ACDP enables | `alloc`, `std` (root `--all-features` and py/node/wasm bindings identical). `pkcs5`, `encryption`, `getrandom`, `pem`, `ctutils`, `3des`, `des-insecure`, `sha1-insecure` are off. |
| Reached via | `elliptic-curve` 0.14.1 (`pkcs8` feature). ACDP's wire paths parse raw SEC1 / JWK keys, not PKCS#8 documents. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour (what was read)

- `PrivateKeyInfo::decode_value` (`src/private_key_info.rs:217-248`): decodes `Version`
  (only 0 or 1, `src/version.rs:53-62`), `AlgorithmIdentifier`, the private-key OCTET
  STRING, optional `[0]` attributes (ignored), optional `[1]` public key; rejects a
  version/public-key mismatch (`:228-236`); skips trailing context-specific extensions
  (`:239-241`). All parsing is delegated to `der`'s bounded `Reader`.
- Encoding (`:251-271`) and `SecretDocument` conversions (`:312-342`) delegate to `der`.
  `Debug` (`:298-310`) omits the private key.
- `CtEq`/`PartialEq` (`:349-385`) are behind `ctutils` (off in ACDP).
- `error.rs`: plain enums and `From` conversions; no I/O.

## Concerns

None. The only powerful import is the explicit opt-in filesystem helper pair described
above, which is the documented purpose of those methods.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, and ASN.1
parsing correctness (delegated to `der`, Tier B, still exempted).
