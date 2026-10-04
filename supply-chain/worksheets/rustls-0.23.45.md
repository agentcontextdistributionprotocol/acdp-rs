# Review worksheet: `rustls` 0.23.45 (issue #322, Phase 5)

- **Verdict:** CERTIFIED `safe-to-deploy`, delta audit (`delta = "0.23.40 -> 0.23.45"`).
  No concern-rule trigger.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.23.45 (locked) | `0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634` | `Cargo.lock` checksum |
| 0.23.40 (prior audit) | `ef86cd5876211988985292b91c96a8f2d298df24e75989a43a3c73f2d4d8168b` | crates.io index `cksum`, and the `Cargo.lock` checksum this repo locked before `8c7a21b` (2026-07-06) |

Both tarballs were also downloaded from `static.crates.io` independently of
`scripts/vet-facts.sh`, and their sha256 values match the table. The diff that was read
was produced from those two extracted trees. Reproduce the facts with
`scripts/vet-facts.sh rustls 0.23.45 0.23.40`.

## Method

- Delta 0.23.40 -> 0.23.45: 40 files, +732/-135 (excluding Cargo.lock, Cargo.toml.orig,
  and .cargo_vcs_info.json). That is 867 changed lines against 48,215 `src/` lines, a
  ratio of 0.02, so the method rule says **delta**. No rewrite clause applies, because the
  crate has no `unsafe` at either version.
- **Every hunk was read** (the whole 1,952-line unified diff): `Cargo.toml`, `README.md`,
  `client/{builder,client_conn,common,ech,hs,tls12,tls13}.rs`, `common_state.rs`,
  `compress.rs`, `conn.rs`, `crypto/aws_lc_rs/{mod,sign,ticketer}.rs`,
  `crypto/ring/{mod,sign}.rs`, `enums.rs`, `error.rs`, `key_log_file.rs`, `lib.rs`,
  `msgs/{base,enums,handshake,persist}.rs`, `msgs/deframer/handshake.rs`, `quic.rs`,
  `server/{builder,hs,server_conn,tls12,tls13}.rs`, `stream.rs`, `suites.rs`,
  `vecbuf.rs`, `webpki/{anchors,verify}.rs`, and the test files
  `msgs/{handshake_test,message_test}.rs` and `server/test.rs`.
- At 0.23.45, unchanged code was also read where the delta depends on it:
  `KeyLogFile`, `ClientConfigBuilder` defaults, `versions.rs`, the
  `check_aligned_handshake` call sites, and the handshake deframer.
- **Base (0.23.40, audited 2026-07-05).** Its note says "memory-safe TLS in Rust, unsafe
  limited to vetted crypto providers". Spot-checked: 0.23.40 also carries
  `#![forbid(unsafe_code, unused_must_use)]`, and its `build.rs` is byte-identical to
  0.23.45's. The delta adds no `unsafe` reasoning that depends on the base.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0. `#![forbid(unsafe_code, unused_must_use)]` is unconditional at `src/lib.rs:332`. The only plain-word hit is prose at `src/manual/features.rs:75`. |
| asm / SIMD | none (cryptography lives in the provider crates, `ring` / `aws-lc-rs`) |
| build.rs | Unchanged, 13 lines. With the `read_buf` feature on a nightly compiler it prints `cargo:rustc-cfg=read_buf`; otherwise `main` is empty. There is no fs, network, or env access. ACDP does not enable `read_buf`. |
| proc-macro | no |
| Powerful imports | `src/key_log_file.rs` (`std::env::var_os`, `std::fs::OpenOptions`). See **KeyLogFile** below. `std::net::TcpStream` (`src/stream.rs:265`) is in a doc/test module. `std::fs::File` in `crypto/aws_lc_rs/hpke.rs:1039` is in `#[cfg(test)]`. Time: `std::time::SystemTimeError` conversion in `error.rs`, and `SystemTime` in tests only; the delta adds no clock use outside tests. Every `include_bytes!` hit is in test code (`*_test.rs`, `test.rs`, `#[cfg(test)]` modules, `verifybench.rs`). |
| New deps | none. The dependency set in `Cargo.lock` is identical at both versions: `aws-lc-rs`, `once_cell`, `ring`, `rustls-pki-types`, `rustls-webpki`, `subtle`, `zeroize`. Only requirement floors moved: `aws-lc-rs` 1.14 -> 1.18 (optional), and `rustls-webpki` 0.103.5 -> 0.103.14 (locked 0.103.15; Tier B, still exempted). |
| Advisories | `cargo deny check`: advisories ok, bans ok, licenses ok, sources ok (2026-10-04). |

## Features and crypto provider compiled into ACDP

From `cargo tree --locked -e features -i rustls`:

| Build | rustls features | Provider |
|---|---|---|
| Normal graph, root workspace (`--all-features`, and `acdp` default features) | `ring`, `std`, `tls12` | **ring** |
| Dev graph (`--all-targets`, tests only) | adds `aws-lc-rs` / `aws_lc_rs`, through the root `[dev-dependencies] rustls` (`Cargo.toml:191`) and `axum-server` `tls-rustls` | aws-lc-rs, installed explicitly by the test harness (`tests/common/mod.rs:59`) |
| `bindings/acdp-py`, `bindings/acdp-node` | not compiled. Their `Cargo.lock` files carry `rustls 0.23.45` with the same checksum (the lock resolves the optional `acdp/client` graph), but `cargo tree -e all -i rustls` prints nothing for the actual build. | n/a |
| `bindings/acdp-wasm` | not in the lockfile | n/a |

- **How the provider is selected.** ACDP never builds a `rustls::ClientConfig` itself.
  It calls `reqwest::ClientBuilder::use_rustls_tls()` (in `acdp-did/src/web.rs`,
  `acdp-client/src/registry.rs`, `acdp-client/src/data_ref.rs`, and
  `acdp-safe-http/src/lib.rs`).
- reqwest 0.12.28 (`src/async_impl/client.rs:763-777`) uses
  `CryptoProvider::get_default()` and falls back to `rustls::crypto::ring::default_provider()`.
  It then calls `ClientConfig::builder_with_provider(..).with_protocol_versions(ALL_VERSIONS)`,
  which is TLS 1.3 + TLS 1.2. ACDP sets no minimum version.
- `logging` is off, so rustls's `log` macros compile to nothing.

## Behaviour that matters to ACDP's TLS client

- **KeyLogFile (`SSLKEYLOGFILE`).** `KeyLogFile::new()` reads `SSLKEYLOGFILE` and appends
  key material to that path. It is **opt-in**: it is used only if an application assigns it
  to `ClientConfig::key_log`.
  - The builder default is `key_log: Arc::new(NoKeyLog {})` (`src/client/builder.rs:178`).
  - reqwest 0.12.28 never sets `key_log`; a grep for `key_log` / `KeyLog` over reqwest and
    hyper-rustls 0.27.9 finds nothing.
  - ACDP never constructs `KeyLogFile` (grep of `crates/`, `src/`, `tests/`, `examples/`).
  - So setting `SSLKEYLOGFILE` in an ACDP process does nothing.
  - Delta: on Unix the file is now created `0o600` (`OpenOptionsExt::mode`) instead of
    being left to the umask, plus a cosmetic `truncate(0)` -> `clear()`. Both are hardening.
- **Early data.** The client default is `enable_early_data: false`. reqwest sets it only
  under its `http3` feature, which ACDP does not enable. The delta does not change client
  0-RTT behaviour; it keeps the 1.2-downgrade-with-0-RTT failure.
- **Session resumption.** reqwest keeps `Resumption::default()`, which is the in-memory
  store. In the delta:
  - New: an RFC 9149 `ticket_request` client extension, off by default
    (`send_ticket_request: None`), and a server-side `max_tls13_tickets` (default 0, which
    keeps the old behaviour).
  - `persist.rs` obfuscated-ticket-age: `age_secs as u32 * 1000` (could overflow, a panic in
    debug builds) became `u32::try_from(..).unwrap_or(MAX).saturating_mul(1000)`.
- **Certificate verification.** The webpki integration is unchanged apart from one
  fail-closed check:
  - `webpki/verify.rs` `verify_tls12_signature` now rejects a scheme that has no TLS 1.2
    `SignatureAlgorithm`, raising `PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme`.
  - The TLS 1.3 path and `WebPkiServerVerifier` are not touched.
  - `SignatureScheme::algorithm()` now returns `Option`. The old `Unknown(0)` sentinel
    is now `None`, and each caller either filters on it or fails closed.
  - The aws-lc-rs provider (dev only for ACDP) gains ML-DSA-44/65/87 signature
    verification and ML-DSA signing keys. These are TLS 1.3 only. The ring provider gains
    nothing.
- **Cipher-suite and version negotiation (client), tightened.**
  - A ServerHello's cipher suite must now be one the client actually **offered**
    (`offered_cipher_suites`). Before, any suite in the provider was accepted.
  - `supports_version` and `find_cipher_suite` now take the transport (`Protocol::Tcp`
    / `Quic`), so QUIC can never pick TLS 1.2.
  - Signature schemes that are not valid for TLS 1.2 are dropped from the ClientHello
    when no TLS 1.3 suite is configured.
  - In TLS 1.2, a ServerKeyExchange signed with the wrong algorithm now sends an
    `illegal_parameter` alert (before: an error with no alert).
- **RUSTSEC-2026-0285 fix (why 0.23.43 -> 0.23.45 happened).**
  - The advisory: TLS 1.3 handshake messages were accepted at the wrong encryption level
    when they followed a key-changing message in the same record (RFC 8446 §5.1). Patched
    in `>= 0.23.45`. 0.23.40, the audited base, was affected; 0.23.45 is the first fixed
    release.
  - The fix is in the delta:
    - `msgs/deframer/handshake.rs` `is_aligned()` changed from "no *partial* fragment" to
      `!is_active()`, meaning no pending handshake data at all, complete or partial.
    - `conn.rs` `take_handshake_message` now recomputes `common_state.aligned_handshake`
      after each message is taken from the deframer.
  - Every key-change point already calls `check_aligned_handshake()`: client `hs.rs:880`,
    `tls13.rs:226,1426,1554`, `tls12.rs:854,1156,1259`, server equivalents, and
    `tls13/key_schedule.rs:532`. A message left buffered across a key change now fails
    with `unexpected_message` / `KeyEpochWithPendingFragment`.
  - This is a strict tightening. Its protocol correctness is upstream's claim, not ours.
- **ECH.** When ECH is rejected, the client now authenticates against the outer
  `public_name` (RFC 9849 §6.1.6). ACDP and reqwest never set an ECH mode, so this does not
  apply.
- **Server-side changes** (HelloRetryRequest: the second ClientHello may not withdraw a PSK
  or change cipher suite; TLS 1.2 is refused after HRR; the TLS 1.2 client-auth scheme
  filter; RFC 9149 hints) are compiled in but unused by ACDP in production. The only rustls
  server is the `axum-server` test harness.

## Panics and arithmetic in the delta

- Removed panic/wrap risks:
  - `aws_lc_rs/ticketer.rs`: `len() - tag_len` became `checked_sub` (truncated-ticket
    underflow), with a new regression test.
  - `handshake.rs` `encoding_for_binder_signing` and server `tls13.rs` binder slicing now
    use `saturating_sub`.
  - The `persist.rs` overflow (above).
- Added: `debug_assert!(len >= C::MIN)` in `PayloadU24` encode/`From`. It is debug-only and
  covers locally built payloads. On the read side, an empty OCSP response is now rejected
  with `InvalidMessage::IllegalEmptyList` instead of being accepted (`opaque
  OCSPResponse<1..2^24-1>`).
- Every added `unwrap()`, `expect()`, and `unreachable!()` is in test code. The
  `let Some(Some(suite)) = … else` in client `hs.rs` returns an alert instead of panicking.

## Secret handling

- `KeyProvider::load_private_key` in both the ring and aws-lc-rs providers now wraps the
  incoming `PrivateKeyDer` in `zeroize::Zeroizing`, so the DER is wiped on drop. That is a
  hardening.
- ACDP's client never loads a private key: reqwest's `with_no_client_auth()` and no
  identity. The path is reached only by the dev TLS harness.
- The target is `rustls-pki-types` `Der` byte storage, which is fully initialized. rustls
  is not compiled into `bindings/acdp-wasm`, the only artifact that builds zeroize's
  non-asm fallback. So zeroize 1.9.0's Z-1 (DECISIONS.md `322-zeroize`, still exempt) is
  not reachable through rustls in any ACDP artifact.

## Concerns

None under the concern rule:
- no `unsafe`;
- no new network, filesystem, process, or env access (the only fs/env code, `KeyLogFile`,
  is pre-existing, opt-in, and unused by ACDP, and the delta hardens its file mode);
- `build.rs` is unchanged and cfg-only;
- no binary content: the tarball holds only `.rs`, `.md`, `.toml`, and licence files
  (`src/testdata` is excluded from the package, so the test-only `include_bytes!` targets
  are not even shipped);
- no open RUSTSEC advisory at 0.23.45.

## Alternative considered

`cargo vet suggest` offers a reverse delta 0.23.40 -> 0.23.37 plus the bytecode-alliance
`0.23.37 -> 0.23.45` audit. That path is smaller and second-party, so it is more credible.
It was rejected only because importing that entry means an unlocked `imports.lock` refresh,
which rewrites the frozen snapshot of all three import sources (plan Phase 5, rejected
alternative). Revisit it as corroboration when `imports.lock` is refreshed for its own
reasons.

## Not claimed

The review does not claim:
- TLS protocol correctness, including that the RUSTSEC-2026-0285 fix is complete;
- certificate-validation correctness;
- cryptographic correctness, constant-time behaviour, or side-channel resistance.

These Tier B crates remain exempted: `rustls-webpki 0.103.15`, `rustls-pki-types 1.15.1`,
`hyper-rustls 0.27.9`, `tokio-rustls 0.26.4`, `webpki-roots 1.0.9`, and `untrusted 0.9.0`.
`once_cell 1.21.4` (a non-crypto support crate) is also exempted. `aws-lc-rs` / `aws-lc-sys`
are dev-only (Tier D). `ring 0.17.14` and `subtle 2.6.1` are audited separately;
`zeroize 1.9.0` stays exempt (`322-zeroize`).
