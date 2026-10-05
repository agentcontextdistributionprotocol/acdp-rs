# Review worksheet: `untrusted` 0.9.0 (issue #339, Tier B batch B3)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.9.0"`). No concern-rule
  trigger. One `Discretion:` line records the upstream CI helper scripts packaged in the
  tarball.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.9.0 (locked) | `8ecb6da28b8a351d773b68d5825ac39017e680750f980f3a1a85cd8dd28a47c1` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is identical (`diff -r`) to the
`~/.cargo/registry/src` copy that was read, except Cargo's own `.cargo-ok` marker. Reproduce
the facts with `scripts/vet-facts.sh untrusted 0.9.0`.

The root `Cargo.lock` and the py and node binding lockfiles lock 0.9.0 with the same
checksum. The wasm binding does not lock `untrusted`.

## Method

- No prior audit of `untrusted` exists in `audits.toml` or the imported sets, so **full**.
- `src/` is 402 lines. Every file was read in full: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (121), `src/input.rs` (101), `src/no_panic.rs` (40), `src/reader.rs` (140).
- Also read: `tests/tests.rs` (134, test-only), and the non-Rust files `mk/cargo.sh`,
  `mk/install-build-tools.sh`, `mk/runner`, `mk/llvm-snapshot.gpg.key`, `deny.toml`,
  `.github/workflows/ci.yml` (see Discretion).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 sites (full-source grep over every `.rs` file, including tests). There is no `#![forbid(unsafe_code)]` attribute and no `Cargo.toml` lint. The grep is the evidence. |
| asm / SIMD / intrinsics | none |
| build.rs | none (no `build.rs` file and no `build` key) |
| proc-macro | no |
| Exported macros | none |
| Powerful imports | none. `#![no_std]` (`src/lib.rs:87`), no `alloc`. No `std::{fs,net,process,env}`, `env!`, `option_env!`, `include_bytes!` or `include_str!` in any `.rs` file. |
| Packaged non-Rust content | `mk/*.sh`, `mk/runner` (upstream CI/test-runner shell scripts) and `mk/llvm-snapshot.gpg.key` (the apt.llvm.org public key, PEM text). Cargo never runs them: there is no build script. Recorded as a discretion line. No binary files. |
| Dependencies | none (normal, build or dev) |
| Features ACDP enables | none (the crate defines none) |
| Reached via | `ring` 0.17.14 and `rustls-webpki` 0.103.15 (the only direct dependents), under `rustls` 0.23.45 -> `hyper-rustls` -> `reqwest` (`acdp-client`, `acdp-did`, `acdp-safe-http` with `client`). In the py and node bindings the crate is lock-only: `cargo tree -e all -i untrusted` prints nothing for their builds. ACDP calls `untrusted` directly nowhere (`grep -rn "untrusted::" crates src tests`: no hits). |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour (what was read)

- `no_panic::Slice` (`src/no_panic.rs:6-40`) wraps `&[u8]` and exposes only `get(i)` and
  `subslice(range)`, both via `slice::get`, so they return `None` instead of panicking.
- `Reader::read_byte` (`src/reader.rs:73-81`) increments the cursor only after a successful
  `get`, so `i <= len` always holds. `read_bytes` (`:89-98`) uses `checked_add` and a checked
  `subslice` before moving the cursor.
- The two `unwrap()` calls are unreachable given that invariant: `read_bytes_to_end`
  (`:103-106`) asks for exactly `len - i` bytes, and `read_partial` (`:111-119`) takes
  `start..self.i` after the closure ran, and no method moves `i` backwards (the fields are
  private).
- `Input::read_all` (`src/input.rs:64-75`) and `read_all_optional` (`src/lib.rs:101-121`)
  reject trailing input. The `Debug` impls (`src/input.rs:30-34`, `src/reader.rs:34-38`)
  print no input bytes.

## Discretion

`mk/cargo.sh`, `mk/install-build-tools.sh`, `mk/runner` (upstream CI helpers) and
`mk/llvm-snapshot.gpg.key` are shipped in the crates.io tarball but are not referenced by
`Cargo.toml` and are never executed by Cargo or by any ACDP build.

## Concerns

None. A small, pure-safe-Rust, `no_std` cursor over a borrowed byte slice; no `unsafe`, no
I/O, no build-time code.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, and the
correctness of the parsers built on it (`ring`, `rustls-webpki`).
