# Review worksheet: `rustls` 0.23.46 (RUSTSEC-2026-0346..0349)

- **Verdict:** CERTIFIED `safe-to-deploy`, delta audit (`delta = "0.23.45 -> 0.23.46"`).
  No concern-rule trigger.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-16
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"
- **Why now:** four RUSTSEC advisories against rustls 0.23.45, all patched in `>= 0.23.46`,
  turned the blocking `cargo deny check` job red on `main` and on PR #386.

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.23.46 (locked) | `48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf` | `Cargo.lock` checksum (root, and the `bindings/acdp-py` / `bindings/acdp-node` lockfiles) |
| 0.23.45 (prior audit) | `0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634` | crates.io index `cksum`, and the `Cargo.lock` checksum this audit replaces |

Both tarballs were also downloaded from `static.crates.io` independently of
`scripts/vet-facts.sh`. The diff that was read came from those two extracted trees.
Reproduce the facts with `scripts/vet-facts.sh rustls 0.23.46 0.23.45`.

## Method

- Delta 0.23.45 -> 0.23.46: 22 files, +1158/-165 (excluding Cargo.lock, Cargo.toml.orig
  and .cargo_vcs_info.json). That is 1,323 changed lines against 49,208 `src/` lines, a
  ratio of 0.03, so the method rule says **delta**. No rewrite clause applies, because the
  crate has no `unsafe` at either version.
- **Every hunk was read** (the whole 2,322-line unified diff): `Cargo.toml` (version line
  only), `client/{ech,handy,hs,tls13}.rs`, `common_state.rs`, `compress.rs`, `conn.rs`,
  `conn/unbuffered.rs`, `crypto/aws_lc_rs/hpke.rs`, `error.rs`, `limited_cache.rs`,
  `msgs/message/inbound.rs`, `msgs/persist.rs`, `record_layer.rs`, `server/{handy,tls13}.rs`,
  `stream.rs`, `tls13/key_schedule.rs`, and the test files `client/test.rs`,
  `msgs/message_test.rs` and `server/test.rs`.
- **Base (0.23.45, audited 2026-10-04,** worksheet `rustls-0.23.45.md`). Its
  `#![forbid(unsafe_code, unused_must_use)]` and 13-line `build.rs` are unchanged.
- The consumers of the changed write path were read at their locked versions:
  tokio-rustls 0.26.4 `src/common/mod.rs:289,326,353` (`writer().write`,
  `write_vectored`, `flush`) is how every ACDP HTTPS client drives rustls.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0. `#![forbid(unsafe_code, unused_must_use)]` unconditional at `src/lib.rs:332`. |
| asm / SIMD | none |
| build.rs | unchanged (13 lines, cfg-only `read_buf` on nightly; ACDP does not enable `read_buf`) |
| proc-macro | no |
| Powerful imports | unchanged from 0.23.45: only the opt-in `KeyLogFile` (`std::env::var_os`, `std::fs::OpenOptions`), which neither reqwest nor ACDP sets. Every `include_bytes!` hit is test code, and the targets are excluded from the package. The delta adds no fs, network, env, process or clock access outside tests. |
| New deps | none. `Cargo.toml` differs only in `version`. `compress.rs` now calls `brotli_decompressor::{BrotliDecompressStream, BrotliState::new_strict}` and `zlib_rs::Inflate`; both crates were already optional dependencies behind the non-default `brotli` / `zlib` features. |
| Lockfile effect | root: rustls version + checksum only. Bindings: the same two lines; an unrelated `quinn-udp` `windows-sys` re-resolution that `cargo update` also produced was dropped, keeping the binding lock change to rustls only. |
| Advisories | `cargo deny check`: advisories ok, bans ok, licenses ok, sources ok (2026-10-16). |

## Features and provider compiled into ACDP

Unchanged from 0.23.45 (`cargo tree -e features -i rustls --edges normal`):
`ring`, `std`, `tls12`, via reqwest 0.12.28 `rustls-tls` → hyper-rustls 0.27.9 /
tokio-rustls 0.26.4. `brotli`, `zlib`, `logging`, `read_buf` and `aws-lc-rs` are off in
the normal graph (aws-lc-rs is dev-only, for the TLS test harness). The py/node bindings
lock rustls but do not compile it; the wasm binding does not lock it.

## The four advisories, and the hunk that fixes each

| Advisory | Fix in the delta | Reachable in ACDP at 0.23.45? |
|---|---|---|
| RUSTSEC-2026-0346 — `Debug` of client session values printed the TLS 1.2 master secret / TLS 1.3 resumption PSK | `msgs/persist.rs`: derived `Debug` replaced by hand-written impls for `Tls13ClientSessionValue`, `ClientSessionCommon` (skips `secret`) and `ServerSessionValue` (skips `master_secret`); each destructures `Self` so a new field cannot slip in unnoticed. Regression tests assert `a5a5` is absent. | No. Only custom `ClientSessionStore` impls that log values are affected; reqwest uses the built-in in-memory store and ACDP formats no session value. |
| RUSTSEC-2026-0347 — buffered application data sent to the outer server after ECH rejection | `client/tls13.rs`: `start_traffic` moved **after** the `EchStatus::Rejected` fatal-alert return, so no buffered plaintext is encrypted for a server only authenticated as `public_name`. | No. ACDP and reqwest never configure ECH. |
| RUSTSEC-2026-0348 — Brotli certificate decompression could allocate 1 GiB pre-authentication | `compress.rs`: `BrotliState::new_strict` (large-window extension off) with a streaming decode that requires `available_in == 0 && available_out == 0`; zlib switched to `Inflate` with `total_in == input.len()` so trailing bytes are rejected. Tests for large-window and trailing data. | No. The `brotli` / `zlib` features are off. |
| RUSTSEC-2026-0349 — an unauthenticated ServerHello could poison the per-server key-exchange hint (downgrade from a hybrid group) | `client/tls13.rs`: `set_kx_hint` moved from ServerHello processing to after the server's `Finished` is verified; the group travels in a new `kx_group` field threaded through every `Expect*` state (mechanical, all hunks read). | Yes in principle (reqwest keeps the default resumption store, which holds kx hints). Impact is low for ACDP because the ring provider offers no post-quantum hybrid group, but the fix is now in. |

## Other behaviour changes in the delta

- **Protected `change_cipher_spec` (RFC 9846 §5).** `msgs/message/inbound.rs` rejects a
  TLS 1.3 record whose inner content type is CCS with
  `PeerMisbehaved::IllegalMiddleboxChangeCipherSpec`; `conn.rs` maps it to an
  `unexpected_message` alert. Fail-closed tightening.
- **ECH after HelloRetryRequest (RFC 9849 §6.1.4-6).** `client/ech.rs` records the HRR
  decision (`accepted_by_hello_retry_request`) and makes it final: accept-then-reject is
  `illegal_parameter` (`EchAcceptanceVariedAfterRetry`, new `PeerMisbehaved` variant),
  reject-then-confirm stays rejected. ECH is unused by ACDP.
- **TLS 1.3 key-update sequencing.** `record_layer.rs` `pre_encrypt_action` now orders
  the hard-limit arm first and uses `>=` against `write_seq_max`, so a multi-record write
  that jumps past the soft limit is caught. `common_state.rs` checks the **last** fragment
  before encrypting any (no partial send across the limit) and can stop before the
  record that would take the last sequence number so a `key_update` goes first;
  `conn.rs` `send_plaintext` loops `buffer_plaintext` / `maybe_refresh_traffic_keys`;
  `key_schedule.rs` clears the pending flag after the update it just sent. Only reachable
  near the AEAD record limit (millions of records on one connection).
- **Writer surfaces fatal errors.** `conn.rs` `PlaintextSink::{write, write_vectored,
  flush}` now return the connection's stored fatal error (`io::ErrorKind::InvalidData`)
  instead of silently accepting plaintext. This is the tokio-rustls path ACDP uses; it
  turns a silent drop into an error, which reqwest already maps to a request error.
- **`stream.rs` (sync `Stream`, unused by ACDP's async stack):** `prepare_read` returns
  buffered plaintext before doing I/O, and `flush` writes until no TLS output remains,
  maps `Ok(0)` to `WriteZero`, retries `Interrupted`, always flushes the socket, and then
  reports a stored fatal error.
- **Session caches.** `limited_cache.rs` evicts on `len > max` (a stored bound) instead
  of `VecDeque::capacity()`, which the allocator may round up; capacity 1 now keeps its
  entry. `ClientSessionMemoryCache::new` docs now state the per-server rounding. Memory
  stays bounded; eviction is now exact.
- **Server-only (compiled, unused in ACDP production; the only rustls server is the
  axum-server test harness):** early data accepted only for PSK index 0 (RFC 8446
  §4.2.10); a client `Certificate` with a non-empty `certificate_request_context` is a
  `decode_error`.
- **aws-lc-rs HPKE (dev-only for ACDP):** moved from `SealingKey`/`OpeningKey` with a
  `NonceSequence` to `LessSafeKey` with explicit nonces; `open` now increments the
  sequence number only after a successful open (new `failed_open_does_not_consume_sequence`
  test). Each `compute_nonce` is used for exactly one seal/open, and the sequence
  increment is checked before sealing, so nonce reuse is not introduced.

## Panics and arithmetic in the delta

- No new `unwrap`/`expect`/`unreachable!`/indexing in non-test code, apart from the
  pre-existing `unreachable!` in client `hs.rs` (restructured from a `match` arm into a
  `let … else`, same invariant: ECH state implies TLS 1.3).
- `send_appdata_encrypt` uses `(iter.len() as u64).checked_sub(1)`; `pre_encrypt_action`
  uses `saturating_add`. No new unchecked arithmetic.

## Concerns

None under the concern rule:
- no `unsafe`;
- no new network, filesystem, process or env access;
- `build.rs` unchanged and cfg-only;
- no binary content added to the package;
- no open RUSTSEC advisory at 0.23.46 (the four above are patched by it).

## Not claimed

- TLS protocol correctness, including completeness of the four advisory fixes;
- certificate-validation correctness;
- cryptographic correctness, constant-time behaviour, or side-channel resistance.

The crates around rustls are unchanged by this bump (same versions and checksums), so
their existing audits stand: `rustls-webpki 0.103.15`, `rustls-pki-types 1.15.1`,
`hyper-rustls 0.27.9`, `tokio-rustls 0.26.4`, `webpki-roots 1.0.9`, `untrusted 0.9.0`.
