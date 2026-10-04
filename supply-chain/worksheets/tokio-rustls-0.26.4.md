# Review worksheet: `tokio-rustls` 0.26.4 (issue #339, Tier B batch B3)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.26.4"`). No concern-rule
  trigger. The crate is an async I/O adapter around rustls connections: reading and writing
  the caller's stream is its documented purpose, and it opens no connection itself. One
  `Discretion:` line records the test-only PEM certificates and key.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.26.4 (locked) | `1729aa945f29d91ba541258c8df89027d5792d85a8841fb65e8bf0f4ede4ef61` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is identical (`diff -r`) to the
`~/.cargo/registry/src` copy that was read, except Cargo's own `.cargo-ok` marker. Reproduce
the facts with `scripts/vet-facts.sh tokio-rustls 0.26.4`.

**Bindings.** The root `Cargo.lock` and the py and node binding lockfiles lock 0.26.4 with the
same checksum. The wasm binding does not lock `tokio-rustls`. (The 0.26.5 that the py and
node locks carried earlier was re-locked to 0.26.4 in #346.)

## Method

- No prior audit of `tokio-rustls` exists in `audits.toml` or the imported sets, so
  **full**.
- `src/` is 2,191 lines. Every file was read in full: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (231), `src/client.rs` (544), `src/server.rs` (481),
  `src/common/mod.rs` (438), `src/common/handshake.rs` (98), and
  `src/common/test_stream.rs` (399, `#[cfg(test)]`, declared at `src/common/mod.rs:437-438`).
- The integration tests were inspected for powerful imports and fixtures: `tests/test.rs`
  (327), `tests/utils.rs` (154), `tests/early-data.rs` (109), `tests/badssl.rs` (101),
  `tests/certs/main.rs` (71), and `tests/certs/{root.pem,chain.pem,end.key}`.
- The `reqwest` 0.12.28 call sites were read to see which part of the crate ACDP reaches.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 sites (full-source grep, `src/` and `tests/`). There is no `#![forbid(unsafe_code)]` attribute and no `Cargo.toml` lint. The grep is the evidence. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no |
| Exported macros | none. `ready!` (`src/lib.rs:54-61`) is crate-private. |
| Powerful imports | none in compiled library code. I/O goes only through the caller's `IO: AsyncRead + AsyncWrite`. `AsRawFd` / `AsRawSocket` (`src/lib.rs:122-140`, `src/client.rs:232-250`, `src/server.rs:463-481`) only forward the inner stream's descriptor. The one `src/` `include_bytes!("../../README.md")` (`src/common/test_stream.rs:171`) is test data in a `#[cfg(test)]` module. Under `tests/`: `std::net`/`tokio::net` sockets (`badssl.rs` dials badssl.com; `test.rs`, `early-data.rs` use local listeners), and `std::fs::File` in `tests/certs/main.rs`, an `#[ignore]` test that regenerates the test certificates. None of it is built outside this crate's own `cargo test`. |
| Dependencies | `rustls` 0.23.27+ (`std`), `tokio` 1. Dev-only: `argh`, `futures-util`, `lazy_static`, `rcgen`, `tokio` (`full`), `webpki-roots`. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Features compiled into ACDP

From `cargo tree --locked -e features -i tokio-rustls`:

| Build | tokio-rustls features |
|---|---|
| Root workspace, `--all-features`, normal edges (and the same with dev edges) | `ring`, `tls12` |
| `acdp` with `--no-default-features` | not in the graph |
| `bindings/acdp-py`, `bindings/acdp-node` | lock-only; `cargo tree -e all -i tokio-rustls` prints nothing for their builds |
| `bindings/acdp-wasm` | not in the lockfile |

- The `default` feature is off: dependents use `default-features = false`, and `tls12` is
  enabled explicitly (with `ring`). `early-data` (0-RTT),
  `aws_lc_rs`, `fips`, `brotli`, `zlib` and `logging` are **not** compiled, so the
  `#[cfg(feature = "early-data")]` items in `src/client.rs` (for example
  `poll_early_data`, `:277-298`, and `poll_handle_early_data`, `:480-544`) were read but are
  not in any ACDP build.
- Direct dependents: `reqwest` 0.12.28 and `hyper-rustls` 0.27.9 (production client), and
  `axum-server` 0.8.0 (dev-dependency only: the TLS test harness,
  `tests/common/mod.rs:20`, `:70`, `:90`, uses the server side). ACDP calls `tokio_rustls`
  nowhere directly (no hits in `crates/`, `src/`, `tests/`).
- Client paths: hyper-rustls `HttpsConnector::call` (see that worksheet), and reqwest's
  HTTPS-over-proxy tunnel (`reqwest src/connect.rs:840-853`, `#[cfg(feature = "__rustls")]`).
  reqwest's SOCKS path (`connect_socks`, `:537-611`) is behind the `socks` feature, which
  is off.

## Certificate verification and configuration wiring

- `TlsConnector` wraps the caller's `Arc<ClientConfig>` (`src/client.rs:116-124`) and never
  modifies it. `connect_impl` (`:56-101`) calls
  `ClientConnection::new_with_alpn(config, domain, alpn)` (`:68`). The only override is ALPN,
  and only through the explicit `with_alpn` (`:103-108`). Verifier, roots and name checks
  are rustls's, driven by the caller's config and the `ServerName` it passes.
- `connect_with(domain, stream, f: FnOnce(&mut ClientConnection))` (`src/client.rs:47-54`)
  lets a caller adjust the session before the handshake. Neither reqwest nor hyper-rustls
  calls it: both use plain `connect`.
- No `dangerous()`, no custom verifier, no key-log hook in the crate (grep over `src/`).
- `TlsAcceptor` / `LazyConfigAcceptor` (`src/server.rs`) likewise wrap the caller's
  `ServerConfig`. In ACDP this is only the dev-only test harness.

## Behaviour (what was read)

- `Stream::read_io` / `write_io` (`src/common/mod.rs:100-128`) move TLS records between
  rustls and the inner stream. After a `process_new_packets` error they make one
  best-effort alert write and return `InvalidData` (`:109-116`).
- `handshake` (`:130-189`) loops write -> flush -> read until rustls stops handshaking. EOF
  during the handshake is `UnexpectedEof` (`:173-177`).
- Every slice is bounded by `min` (`:246-247`, `src/client.rs:310-311`,
  `src/server.rs:364-365`). `SyncReadAdapter` / `SyncWriteAdapter` (`:378-435`) turn
  `Poll::Pending` into `WouldBlock`.
- `MidHandshake::poll` panics if polled again after completion (`src/common/handshake.rs:66`),
  the usual `Future` contract. The `LazyConfigAcceptor` `unwrap` (`src/server.rs:180`)
  follows an `is_some` match (`:144-152`). The `unreachable!` (`src/server.rs:399`) exists
  only with `early-data`.

## Discretion

`tests/certs/root.pem`, `tests/certs/chain.pem` (PEM test certificates) and
`tests/certs/end.key` (a PEM EC test private key, generated by the `#[ignore]` test in
`tests/certs/main.rs`) are read only by `tests/utils.rs` via `include_str!`. They are text,
not binary, and are not compiled into any non-test build.

## Concerns

None. Safe-Rust async glue over rustls `ConnectionCommon`: no `unsafe`, no build-time code,
no file/process/environment access in library code. It neither weakens nor configures
certificate verification.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, TLS protocol
correctness, and certificate-validation correctness (rustls, rustls-webpki and the
provider).
