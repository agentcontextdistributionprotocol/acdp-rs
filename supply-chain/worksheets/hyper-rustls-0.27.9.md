# Review worksheet: `hyper-rustls` 0.27.9 (issue #339, Tier B batch B3)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.27.9"`). No concern-rule
  trigger. The crate is an HTTPS connector adapter: network I/O is its documented purpose,
  and it performs none beyond the connection its caller asks for.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.27.9 (locked) | `33ca68d021ef39cf6463ab54c1d0f5daf03377b70561305bb89a8f83aab66e0f` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is identical (`diff -r`) to the
`~/.cargo/registry/src` copy that was read, except Cargo's own `.cargo-ok` marker. Reproduce
the facts with `scripts/vet-facts.sh hyper-rustls 0.27.9`.

The root `Cargo.lock` and the py and node binding lockfiles lock 0.27.9 with the same
checksum. The wasm binding does not lock `hyper-rustls`.

## Method

- No prior audit of `hyper-rustls` exists in `audits.toml` or the imported sets, so
  **full**.
- `src/` is 1,138 lines. Every file was read in full: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (76), `src/config.rs` (134), `src/connector.rs` (307),
  `src/connector/builder.rs` (500), `src/stream.rs` (121).
- The tarball has no `tests/`, `examples/` or `benches/` (the `include` list in
  `Cargo.toml.orig` keeps only `src/**/*.rs`, the licences and the README). The packaged
  `Cargo.lock` is ignored for dependents.
- The `reqwest` 0.12.28 call sites were read to see which part of the crate ACDP reaches
  (`src/connect.rs:663-693`, `:763-766`, `:849-853`).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 sites (full-source grep). There is no `#![forbid(unsafe_code)]` attribute and no `Cargo.toml` lint. The grep is the evidence. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no |
| Exported macros | none. The `debug!`/`warn_` shims (`src/lib.rs:50-60`) are crate-private no-ops when `logging` is off. |
| Powerful imports | none outside tests. Network I/O happens only through the caller-supplied inner connector (`T: Service<Uri>`) and `tokio_rustls::TlsConnector`. The only direct socket type is `tokio::net::TcpStream` in the `#[cfg(all(test, ...))]` module (`src/connector.rs:214-307`), whose tests dial `google.com`; never compiled outside `cargo test` of this crate. No `std::{fs,process,env}`, `env!`, `include_bytes!`. |
| Dependencies | `http` 1, `hyper` 1, `hyper-util` 0.1 (`client-legacy`, `tokio`), `rustls` 0.23, `tokio` 1, `tokio-rustls` 0.26, `tower-service` 0.3. Optional: `log`, `rustls-native-certs`, `rustls-platform-verifier`, `webpki-roots`. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Features compiled into ACDP

From `cargo tree --locked -e features -i hyper-rustls`:

| Build | hyper-rustls features |
|---|---|
| Root workspace, `--all-features`, normal edges (and the same with dev edges) | `http1`, `ring`, `tls12`, `webpki-roots`, `webpki-tokio` |
| `acdp` with `--no-default-features` | not in the graph |
| `bindings/acdp-py`, `bindings/acdp-node` | lock-only; `cargo tree -e all -i hyper-rustls` prints nothing for their builds |
| `bindings/acdp-wasm` | not in the lockfile |

- The crate's default features (`native-tokio`, `logging`, `aws-lc-rs`) are **off**: reqwest
  depends on it with `default-features = false` and enables `http1`, `tls12`, `ring` and
  `webpki-tokio` through its `rustls-tls-webpki-roots` / `__rustls-ring` features. So
  `rustls-native-certs` (OS certificate store reads), `rustls-platform-verifier` and
  `aws-lc-rs` are not compiled.
- Its only direct dependent is `reqwest` 0.12.28. ACDP calls `hyper_rustls` nowhere
  directly (no hits in `crates/`, `src/`, `tests/`); it reaches it via
  `reqwest::ClientBuilder::use_rustls_tls()` (`crates/acdp-did/src/web.rs:342`,
  `crates/acdp-safe-http/src/lib.rs:487`, `crates/acdp-client/src/registry.rs:792`, `:830`,
  `crates/acdp-client/src/data_ref.rs:156`).

## Certificate verification and configuration wiring

- In the features ACDP compiles, hyper-rustls builds no certificate verifier. Only the
  off `rustls-platform-verifier` feature installs one (`src/config.rs:66-71`). It never
  touches `ClientConfig::dangerous()`, it configures trust roots only in the opt-in
  `ConfigBuilderExt` helpers (`src/config.rs:59-126`), and the only `ClientConfig` field it
  writes is `alpn_protocols` (`src/connector/builder.rs:261`, `:279`, `:346`).
- reqwest builds its own `rustls::ClientConfig` (webpki roots, ring provider; see the rustls
  worksheet). ACDP's public API can add caller-supplied trust anchors to it through reqwest's
  `add_root_certificate`:
  - `WebResolver::with_root_cert_pem` and `with_capacity_and_root_cert_pem`
    (`crates/acdp-did/src/web.rs:108`, `:117`, applied at `:348-352`);
  - `RegistryClient::with_root_cert_pem` and `root_cert_pem`
    (`crates/acdp-client/src/registry.rs:332`, `:748`, applied by `apply_root_cert`,
    `:856-866`).

  These add roots; nothing in ACDP disables verification. reqwest wraps that config with
  `HttpsConnector::from((http, tls))`
  (`reqwest src/connect.rs:674`). That `From` impl (`src/connector.rs:126-138`) sets
  `force_https: false` and the `DefaultServerNameResolver`. hyper-rustls's own
  `with_webpki_roots` helpers (`src/config.rs:116-125`, `src/connector/builder.rs:153-177`)
  are compiled but not called on that path.
- `HttpsConnector::call` (`src/connector.rs:85-123`): `http` URIs go to the inner connector
  without TLS when `force_https` is false (`:89-94`). Any other non-`https` scheme fails
  (`:95-98`), and so does a missing scheme (`:100`). For `https` it resolves the server name
  **before** connecting (`:104-109`) and then runs
  `TlsConnector::from(cfg).connect(hostname, tcp)` (`:111-122`), so rustls verifies the
  certificate against that name.
- `DefaultServerNameResolver` (`:152-169`) takes `uri.host()`, strips IPv6 brackets, and
  fails closed through `ServerName::try_from` on an invalid name.
- **Plain HTTP is the caller's policy, not this crate's.** With `force_https: false`, an
  `http://` URL is sent in cleartext. By default ACDP rejects non-`https` URLs itself,
  before any request: `SsrfPolicy::check_url` (`crates/acdp-safe-http/src/lib.rs:186`)
  delegates to `classify_url`, whose scheme check is at `:204`, and the test
  `https_only_by_default` is at `:699`. `SsrfPolicy.allow_http` (`:140`, default `false`) is
  a public opt-in that turns this off (test `allow_http_can_be_opted_into`, `:867`). That is a
  property of ACDP's code and configuration, not one this audit attributes to hyper-rustls.
- Panics: `with_tls_config` asserts that the caller left `alpn_protocols` empty
  (`src/connector/builder.rs:60-66`, documented); `with_platform_verifier` `expect`s (`:76-79`,
  `src/config.rs:61-64`) are behind the feature that is off. reqwest's path hits neither.
- `MaybeHttpsStream` (`src/stream.rs`) only forwards `poll_*` calls to the inner stream, and
  `Debug` prints only `Http(..)`/`Https(..)`.

## Concerns

None. Safe-Rust glue between hyper's connector API and tokio-rustls: no `unsafe`, no build
time code, no file/process/environment access. The verifier and roots come from the
caller's `ClientConfig`, and the defaults ACDP compiles in do not change certificate
verification.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, TLS protocol
correctness, and certificate-validation correctness (those belong to rustls, rustls-webpki
and the provider).
