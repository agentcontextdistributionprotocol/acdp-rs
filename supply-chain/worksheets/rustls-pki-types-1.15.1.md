# Review worksheet: `rustls-pki-types` 1.15.1 (issue #339, Tier B batch B5)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "1.15.1"`). No concern-rule
  trigger.
  - There is one `unsafe` site, a value transmute `[u16; 8] -> [u8; 16]`, and it is sound.
  - Filesystem access exists only in the documented, caller-initiated `PemObject::from_pem_file`
    / `pem_file_iter` APIs, under `std`. ACDP's dependency path does not call them.
  - The 19 `include_bytes!` blobs are fixed AlgorithmIdentifier encodings, decoded and checked
    below (one `Discretion:` line).
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 1.15.1 (locked) | `2f4925028c7eb5d1fcdaf196971378ed9d2c1c4efc7dc5d011256f76c99c0a96` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`.
Its sha256 matches. Its extracted tree is identical (`diff -r`) to the `~/.cargo/registry/src`
copy that was read, apart from Cargo's own `.cargo-ok` marker. Reproduce the facts with
`scripts/vet-facts.sh rustls-pki-types 1.15.1`.

The root `Cargo.lock` and the py and node binding lockfiles lock 1.15.1 with the same
checksum. The wasm binding does not lock `rustls-pki-types`.

## Method

- No prior audit of `rustls-pki-types` exists in `audits.toml` or the imported sets, so this
  is a **full** audit.
- `src/` is 4,103 lines, and every file was read in full:
  - `Cargo.toml` (and `.orig`)
  - `src/lib.rs` (1,172)
  - `src/server_name.rs` (1,224), including the IP-address parser adapted from `core`
  - `src/pem.rs` (562)
  - `src/base64.rs` (750)
  - `src/alg_id.rs` (395)
  - `src/data/README.md`
- Every `src/data/*.der` file was hex-dumped and decoded by hand (see the table below).
- The `Cargo.toml.orig` `include` list ships only `src/**/*.rs`, `src/data/*.der`, the
  licences and the README. There is no `tests/` or `benches/` directory. The doc examples in
  `src/lib.rs` that open `tests/data/*.pem` (`:118-120`, `:307-310`, `:374-377`, `:441-445`)
  are doctests and do not compile into the library.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 1: `src/server_name.rs:532` (full-source grep, comment lines excluded; the grep is the evidence). There is no `forbid`/`deny(unsafe_code)` attribute. Lints would be capped by `--cap-lints` for registry deps anyway. |
| asm / SIMD / intrinsics | none |
| build.rs | none |
| proc-macro | no |
| Exported macros | none |
| Powerful imports | (a) **Filesystem, explicit API only:** `use std::fs::File` (`src/pem.rs:9`). `PemObject::from_pem_file` / `pem_file_iter` (`:36-56`, `#[cfg(feature = "std")]`) open the caller-named path through `File::open` and read it with `BufReader`. Nothing else in the crate touches the filesystem. (b) **Clock:** `UnixTime::now` (`src/lib.rs:964-970`) reads `SystemTime::now()` (`web_time` on wasm-unknown with `web`; that feature is off). The `.unwrap()` there is a panic only if the clock is before 1970. (c) **`std::net`:** the 24 `std::net` hits in `src/server_name.rs` are pure value conversions (`From` impls between `std::net::{IpAddr,Ipv4Addr,Ipv6Addr}` and the crate's own types) with no sockets. (d) **`include_bytes!`:** 19, all in `src/alg_id.rs`, all of `src/data/alg-*.der` (see Discretion). No `std::{process,env}`, `env!`, `option_env!`. |
| Dependencies | `zeroize` 1 (optional, through `alloc`); `web-time` 1 (wasm32-unknown, through `web`). Dev: `criterion` 0.8, `crabgrind` =0.1.9 (x86_64-linux). |
| Features ACDP enables | `alloc`, `default` and `std`, on the root: normal edges through `reqwest` 0.12.28 (the `client` feature), `rustls` 0.23.45, `rustls-webpki` 0.103.15 and `webpki-roots`; dev edges through `axum-server` 0.8.0 and `rcgen` 0.14.10 (the TLS test harness). `web` is off. **Not compiled** in the py or node bindings (`cargo tree -i` prints nothing, native and `--target all`). Absent from the wasm binding's lockfile. |
| Reached via | reqwest `ServerName::try_from(host)` (`reqwest-0.12.28/src/connect.rs:577`, `:872`), reqwest PEM parsing of caller-supplied root certificates through `CertificateDer::pem_reader_iter` over an in-memory reader (`src/tls.rs:54`, `:232`), `pem::from_buf` (`:352`) and `pem_slice_iter` (`:474`), and rustls `UnixTime::now`. ACDP calls the crate directly nowhere (`grep -rn "rustls_pki_types\|pki_types" crates src tests bindings/*/src`: no hits). ACDP does not call `from_pem_file` / `pem_file_iter` (no hits). |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## `unsafe` site

**`src/server_name.rs:532`**, in `impl From<[u16; 8]> for Ipv6Addr` (`:516-535`):

```rust
unsafe { mem::transmute::<[u16; 8], [u8; 16]>(addr16) }
```

- It is a by-value transmute. Both types are 16 bytes with no padding, and every bit pattern
  is a valid `[u8; 16]`.
- `transmute` checks the size equality at compile time.
- No pointer, lifetime or alignment is involved, because the result is a fresh array.
- The input is arbitrary, and the transmute has no input precondition, so the call is sound
  for every value.
- `addr16` holds big-endian (`to_be`) words, so the byte order is the network order. That is
  a correctness property, and it is not needed for soundness.
- Callers are `Ipv6Addr::from([u16; 8])` and the IPv6 text parser (`parser::read_ipv6_addr`),
  which is reached from `ServerName::try_from(&str)` on attacker-influenced host strings.

## Discretion: embedded DER blobs

The 19 `include_bytes!` files are AlgorithmIdentifier *value* encodings, without the outer
`SEQUENCE`, as `src/data/README.md` says. Each was hex-dumped and decoded:

| File(s) | Bytes | Decoded content |
|---|---|---|
| `alg-ecdsa-p256.der` | 19 | OID 1.2.840.10045.2.1 (id-ecPublicKey), OID 1.2.840.10045.3.1.7 (P-256) |
| `alg-ecdsa-p256k1.der`, `-p384`, `-p521` | 16 each | id-ecPublicKey plus OID 1.3.132.0.{10,34,35} |
| `alg-ecdsa-sha{256,384,512}.der` | 10 each | OID 1.2.840.10045.4.3.{2,3,4} |
| `alg-ed25519.der`, `alg-ed448.der` | 5 each | OID 1.3.101.{112,113} |
| `alg-ml-dsa-{44,65,87}.der` | 11 each | OID 2.16.840.1.101.3.4.3.{17,18,19} |
| `alg-rsa-encryption.der`, `alg-rsa-pkcs1-sha{256,384,512}.der` | 13 each | OID 1.2.840.113549.1.1.{1,11,12,13}, NULL |
| `alg-rsa-pss-sha{256,384,512}.der` | 65 each | OID 1.2.840.113549.1.1.10 plus RSASSA-PSS-params (hash sha2-{256,384,512}, MGF1 with the same hash, salt length 32/48/64) |

These are public constant bytes exposed as `&'static [u8]` (`AlgorithmIdentifier`,
`src/alg_id.rs:365-395`). They are not code, and nothing in the crate executes them.

## Behaviour (what was read)

- **PEM parser** (`src/pem.rs`):
  - Line-oriented, over a slice, a `BufRead`, or the explicit file API.
  - A section body accumulates at most `MAX_PEM_SECTION_SIZE` = 256 MiB (`:334-344`) before
    `SectionTooLarge`.
  - `&line[11..pos]` (`:301`) is reached only after `line.starts_with(b"-----BEGIN ")`, which
    is 11 bytes, and exactly 5 trailing dashes. The reverse scan stops at the space at index
    10, so `pos >= 11`. It is checked slicing in any case.
  - Base64 decoding uses the crate's own safe decoder (`src/base64.rs`, no `unsafe`, checked
    indexing). There are separate `decode_secret` / `decode_public` entry points.
- **`PrivateKeyDer::try_from(&[u8])`** (`src/lib.rs:200-280`) peeks at DER tags with checked
  slicing only. Private-key `Debug` impls print `[secret key elided]` (`:355`, `:422`,
  `:490`). `Zeroize` impls (`:138`, `:331`, `:398`, ...) apply to the owned `'static` forms.
- **`ServerName` / `DnsName` validation and the IP parser** (`src/server_name.rs`) are safe
  code over byte slices, with no allocation beyond the owned-name forms.

## Concerns

None.
- The filesystem access is the documented purpose of two opt-in APIs, and ACDP never calls
  them.
- The one transmute is sound for all inputs.

## Not claimed

Cryptographic correctness, constant-time behaviour (the crate's base64 decoder aims at
constant time for secret sections; that is **not** claimed or verified here), side-channel
resistance, and the correctness of DNS-name/IP validation or PEM parsing.
