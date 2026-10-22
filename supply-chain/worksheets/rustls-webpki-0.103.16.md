# Review worksheet: `rustls-webpki` 0.103.16 (RUSTSEC-2026-0382)

- **Verdict:** CERTIFIED `safe-to-deploy`, delta audit (`delta = "0.103.15 -> 0.103.16"`).
  One concern-rule trigger (vendored binary content), inspected below; no concern.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-21
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"
- **Why now:** RUSTSEC-2026-0382 (CVE-2026-111943, emSign intermediate distrust), patched in
  `>= 0.103.16`, turned the blocking `cargo deny check` job red on PR #404.

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.103.16 (locked) | `4443b1b6d39d7c663139942cc4558262562d2c84123bb6282ef177009ca8b281` | `Cargo.lock` checksum (root, and the `bindings/acdp-py` / `bindings/acdp-node` lockfiles) |
| 0.103.15 (prior audit) | `f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2` | crates.io index `cksum`, and the `Cargo.lock` checksum this audit replaces |

Both tarballs were also downloaded from `static.crates.io` independently of
`scripts/vet-facts.sh`, and the diff that was read came from those two extracted trees.
Reproduce the facts with `scripts/vet-facts.sh rustls-webpki 0.103.16 0.103.15`.

## Method

- Delta: 12 files, +160/-3 (excluding Cargo.lock, Cargo.toml.orig and .cargo_vcs_info.json).
  That is 163 changed lines against 10,197 `src/` lines, a ratio of 0.02, so the method rule
  says **delta**. The crate has no `unsafe` at either version.
- **Every hunk was read** (the whole 253-line unified diff): `Cargo.toml` (version line only),
  `src/end_entity.rs`, `src/error.rs`, `src/verify_cert.rs`, and the eight new binary files
  under `src/data/distrusted/`.
- Base: 0.103.15, full audit 2026-10-05 (#339 B7b, DECISIONS.md `322-rustls-webpki`).

## The change

- `verify_cert.rs` adds `pub(crate) const DISTRUSTED_SPKIS: &[&[u8]]`, eight
  `include_bytes!("data/distrusted/*.spki.der")` entries.
- `ChainOptions` gains `distrusted_spkis: &'a [&'a [u8]]`.
  - `EndEntityCert::verify_for_usage` (`end_entity.rs`) sets it to `DISTRUSTED_SPKIS`.
  - That is the entry point rustls 0.23.46's `WebPkiServerVerifier` uses for every ACDP
    HTTPS client, so the check is on ACDP's path.
- `build_chain_inner` returns `Error::CertDistrusted` in two cases:
  - first, when the current path head's SPKI is in the list (before any issuer search);
  - then, when a matched trust anchor's SPKI is in the list. This replaces the former
    `// TODO: check_distrust(...)` comment.
- The match is exact byte-slice equality on the SPKI contents (`slice::contains`).
  - There is no parsing, allocation or arithmetic.
  - The list is 8 entries, so the added cost per candidate path is negligible against the
    existing `Budget`.
- `Error::CertDistrusted` is a new variant. It ranks at 270, the same as `CertRevoked`.
  - rustls 0.23.46 `src/webpki/mod.rs:139` maps unrecognised webpki errors to
    `CertificateError::Other`.
  - The handshake therefore fails closed, and ACDP surfaces it the same way as any other
    TLS failure.
- The remaining +124 lines are a `cfg(test)` test (`distrusted_spki`) plus one test
  `ChainOptions` literal.

## Vendored binary content (concern-rule trigger)

All eight blobs are 118 bytes. Each one, wrapped in a DER `SEQUENCE` header, parses with
`openssl pkey -pubin` as a 384-bit EC (P-384) SubjectPublicKeyInfo. Each is only ever
compared, never executed or parsed.

| File | sha256 of the wrapped SPKI |
|---|---|
| `EMDVTLSCAG3B.spki.der` | `ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105` |
| `EMDVTLSCAG3C.spki.der` | `49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f` |
| `EMEVTLSCAG3B.spki.der` | `e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41` |
| `EMEVTLSCAG3C.spki.der` | `5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0` |
| `EMOVCSCAG3B.spki.der` | `ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6` |
| `EMOVCSCAG3C.spki.der` | `92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30` |
| `EMOVTLSCAG3B.spki.der` | `43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b` |
| `EMOVTLSCAG3C.spki.der` | `63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8` |

A wrong or extra key could only make validation stricter, never looser, so the trigger
raises no concern.

## Facts

- `unsafe`: 0 sites (full-source grep).
- asm/SIMD: none.
- `build.rs` / proc-macro: none.
- New dependencies: none.

## Not claimed

- Certificate-validation correctness.
- That the eight keys are exactly, and completely, the distrusted emSign intermediates.
  That is upstream's claim (rustls/webpki#546; Mozilla bug 2083449).
