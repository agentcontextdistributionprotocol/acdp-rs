# Review worksheet: `webpki-roots` 1.0.10 (RUSTSEC-2026-0381)

- **Verdict:** CERTIFIED `safe-to-deploy`, delta audit (`delta = "1.0.9 -> 1.0.10"`).
  No concern-rule trigger.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-21
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"
- **Why now:** RUSTSEC-2026-0381 (CVE-2026-111943, emSign distrust), patched in `>= 1.0.10`,
  turned the blocking `cargo deny check` job red on PR #404.

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 1.0.10 (locked) | `1c1c8e20c8a38fc7d65abfe74eb7280e4aa667e8eec8bc84996d2874810748d9` | `Cargo.lock` checksum (root, and the `bindings/acdp-py` / `bindings/acdp-node` lockfiles) |
| 1.0.9 (prior audit) | `7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a` | crates.io index `cksum`, and the `Cargo.lock` checksum this audit replaces |

Reproduce the facts with `scripts/vet-facts.sh webpki-roots 1.0.10 1.0.9`.

## Method

- Delta: 2 files, +2/-30, 32 changed lines against 4,575 `src/` lines, a ratio of 0.01.
  The method rule says **delta**.
- **Every hunk was read** (the whole 53-line unified diff).
- Base: 1.0.9, full audit 2026-10-04 (#339 B4, worksheet `webpki-roots-1.0.9.md`).

## The change

- `src/lib.rs`: exactly one `TrustAnchor` is removed from `TLS_SERVER_ROOTS`, together with
  its comment block.
  - The removed root is `emSign ECC Root CA - G3`, SHA-256
    `86:a1:ec:ba:08:9c:4a:8d:3b:be:27:34:c6:12:ba:34:1d:81:3e:04:3c:f9:e8:a8:62:cd:5c:57:a3:6b:be:6b`.
  - The table goes from 121 to 120 entries. No entry is added or altered.
- The other emSign roots (Root CA - C1, Root CA - G1, ECC Root CA - C3) remain, as upstream
  intends. The distrust targets the intermediates under G3, which rustls-webpki 0.103.16
  also blocks by key (see `rustls-webpki-0.103.16.md`).
- `Cargo.toml`: the version, and `rust-version` 1.70 -> 1.71 (below ACDP's 1.86 MSRV).

## Facts

- `unsafe`: 0 sites; `#![forbid(unsafe_code, unstable_features)]` at `src/lib.rs:26`.
- asm/SIMD: none.
- `build.rs` / proc-macro: none.
- New dependencies: none.

## Not claimed

- Root-set correctness.
