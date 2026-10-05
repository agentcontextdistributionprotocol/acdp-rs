# Review worksheet: `rustls-webpki` 0.103.15 (issue #339, Tier B batch B7b)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.103.15"`). No
  concern-rule trigger and no `Discretion:` line. This was the plan's critical decision C1.
  The worksheet recommended option 1, and Claude (Fable) decided it on 2026-10-05
  (DECISIONS.md `322-rustls-webpki`). The bounded DoS cost W-O8 is recorded as an
  `Observations:` line in the audit notes.
  - There is no `unsafe`, no `asm!`, no build script and no FFI in the crate.
  - No panic, unbounded loop or unbounded recursion is reachable from a server-presented
    certificate chain, from CRL bytes or from a caller-supplied name (inventory below).
  - The RUSTSEC-2023-0053 path-building budget is present and enforced, and the four 2026
    advisories are fixed in this version.
  - CRL parsing and revocation checking are compiled into ACDP but never reached: no ACDP
    HTTPS client configures CRLs.
- **Trust boundary.** This crate decides whether every ACDP HTTPS peer (a `did:web` host, a
  registry, a `data_ref` origin) is who it claims to be. The audit claims that the crate's
  *code* is safe to deploy under the vet criterion. **It does not claim that certificate path
  validation, name-constraint evaluation or revocation checking is correct**, nor
  cryptographic correctness. Those remain upstream's responsibility, as for `rustls` and
  `webpki-roots`.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
  The main review (Opus) split `src/` into six partitions, W1-a to W1-f below, and each was
  read line by line by its own fresh Opus agent. The main review read the path-building core
  (`verify_cert.rs:40-175`), the OID decoder (`:718-755`), `crl/mod.rs:110-130` and
  `der.rs:221-258` directly. It cross-checked every partition report against its own
  full-source greps; the counts agree (see Facts).
- **Date:** 2026-10-05
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.103.15 (locked) | `f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2` | `Cargo.lock` checksum (root l.2173) |

- The tarball was downloaded from `static.crates.io` independently of
  `scripts/vet-facts.sh`. Its sha256 matches, and its extracted tree is identical (`diff -r`)
  to the `~/.cargo/registry/src` copy that was read, apart from Cargo's own `.cargo-ok`
  marker. Reproduce the facts with `scripts/vet-facts.sh rustls-webpki 0.103.15`.
- The root, py and node lockfiles lock 0.103.15 with this checksum. The wasm binding's lock
  does not contain it.
- `.cargo_vcs_info.json`: upstream commit `c14836d8de33c0ad0ac7dcb28fe9aade20831a4d`,
  `path_in_vcs` empty. That is the peeled commit of upstream tag `v/0.103.15`
  (`git ls-remote https://github.com/rustls/webpki 'refs/tags/*0.103.15*'`).
- A clone of `rustls/webpki` at that tag has a `src/` identical to the tarball's, except for
  `src/test_utils.rs`, which is upstream-only and declared only under `#[cfg(test)]`
  (`lib.rs:76-77`). The tag's `Cargo.toml` is identical to the tarball's `Cargo.toml.orig`.

## Method: exactly what was read

- No prior audit of `rustls-webpki` exists in `audits.toml` or `imports.lock`, so this is a
  **full** audit. Imports are not allowed (Policy 5), so no third-party audit was used as a
  base.
- `src/` is **10,040 lines in 19 `.rs` files**, plus three 11-byte `.der` blobs. **Every line
  of all 19 files was read**, `#[cfg(test)]` modules and the not-compiled `aws_lc_rs_algs.rs`
  included. Each file is in exactly one partition:

| Partition | Files (lines) | Partition total |
|---|---|---|
| W1-a path building and chain validation | `verify_cert.rs` (1,373), `end_entity.rs` (240), `trust_anchor.rs` (141), `rpk_entity.rs` (84) | 1,838 |
| W1-b names | `subject_name/mod.rs` (472), `subject_name/dns_name.rs` (1,059), `subject_name/ip_address.rs` (706) | 2,237 |
| W1-c CRLs | `crl/mod.rs` (374), `crl/types.rs` (1,287) | 1,661 |
| W1-d DER and certificate parsing | `der.rs` (908), `cert.rs` (749), `x509.rs` (119), `time.rs` (283) | 2,059 |
| W1-e signature algorithms | `signed_data.rs` (269), `ring_algs.rs` (303), `aws_lc_rs_algs.rs` (346, not compiled), `alg_tests.rs` (648, test-only) | 1,566 |
| W1-f crate surface and cross-cutting sweep | `lib.rs` (219), `error.rs` (460), plus the crate-wide panic/arithmetic sweep | 679 |
| **Total** | 19 files | **10,040** |

- W1-f also read `Cargo.toml`, `Cargo.toml.orig`, `.cargo_vcs_info.json` and `README.md`,
  and swept all of `src/` for panic sites and input-derived arithmetic in non-test code.
- W1-e decoded the three `src/data/*.der` blobs with `xxd` and `openssl asn1parse`.
- There is no `tests/`, `benches/` or `build.rs` in the tarball.

### Compiled and test-only line ranges (features `alloc`, `ring`, `std`)

A test region starts at its first `#[cfg(...)]` attribute line and runs to the end of the
file. A script that matches braces confirmed that no non-test item follows any test module.

| File | Compiled | Test-only (`cfg(test)`) | Not compiled |
|---|---|---|---|
| `lib.rs` | 1-219 (the `mod test_utils` declaration at 76-77 is test-only) | — | the `cfg(feature = "aws-lc-rs")` items: `mod aws_lc_rs_algs` (59-60), `pub mod aws_lc_rs` (120-133) and the `aws_lc_rs::*` entries of `ALL_VERIFICATION_ALGS` (169-214) |
| `error.rs` | 1-460 | — | — |
| `verify_cert.rs` | 1-902 | 903-1373 | — |
| `end_entity.rs` | 1-179 | 180-240 | — |
| `trust_anchor.rs` | 1-104 | 105-141 | — |
| `rpk_entity.rs` | 1-51 | 52-84 | — |
| `subject_name/mod.rs` | 1-406 | 407-472 | — |
| `subject_name/dns_name.rs` | 1-533 (the `not(alloc)` arm at 52-53 is off) | 534-1059 | — |
| `subject_name/ip_address.rs` | 1-185 (the `not(alloc)` arm at 53-54 is off) | 186-565 and 567-706 (566 is blank) | — |
| `crl/mod.rs` | 1-275 | 276-374 | — |
| `crl/types.rs` | 1-907 | 908-1287 | — |
| `der.rs` | 1-470 | 471-908 | — |
| `cert.rs` | 1-408 | 409-749 | — |
| `x509.rs` | 1-119 | — | — |
| `time.rs` | 1-181 | 182-283 | — |
| `signed_data.rs` | 1-269 | — | — |
| `ring_algs.rs` | 1-212 | 213-303 | — |
| `aws_lc_rs_algs.rs` | — | (269-346 would be test-only) | 1-346 (`aws-lc-rs` off) |
| `alg_tests.rs` | — | 1-545 and 602-648 (pulled in only by `#[path]` inside `ring_algs.rs:213`'s test module) | 546-600 (`ml_dsa`, needs `aws-lc-rs`) |

The compiled non-test ranges above total 5,880 lines in 17 `.rs` files. rustc's dep-info for
the scratch build below (`target/release/deps/webpki-baa484398cd895d2.d`, features
`alloc,ring,std`) lists exactly those 17 files plus the three `src/data/*.der` blobs, and
neither `aws_lc_rs_algs.rs` nor `alg_tests.rs`. So the compiled set comes from rustc, not only
from reading `cfg`s.

### Empirical checks

- **Upstream test suite.** At tag `v/0.103.15`, with ACDP's features
  (`cargo test --locked --no-default-features --features std,ring`, aarch64-apple-darwin):
  398 passed, 0 failed, 2 ignored. The two ignored tests are the slow BetterTLS suites in
  `tests/better_tls.rs` (path building and name constraints). Run separately with
  `--include-ignored`, both passed. The suite includes the budget, name-constraint and CRL
  regression tests that the tarball cannot compile.
- **Random-DER loop.** A scratch crate (outside the repo) depended on
  `rustls-webpki = "=0.103.15"` with `alloc,ring,std`. It was built in release mode with
  `debug-assertions` and `overflow-checks` on.
  - The corpus was the 227 `.der` files in upstream `tests/`: 181 certificates and other
    DER, plus 46 CRLs that parse.
  - The mutations were bit flips, random and boundary bytes (`00 01 7f 80 81 82 84 ff`),
    truncation, insertion and deletion, block copies and junk splices. One input in 20 was
    pure random bytes.
  - Each iteration ran one of the following:
    - `EndEntityCert::try_from` on a mutated certificate. On success, it then ran
      `verify_for_usage(ALL_VERIFICATION_ALGS, ...)`. The trust anchors were the 145
      fixture certificates that parse as anchors, the intermediates came from the same fixture directory (mutated or not),
      the verification time was one of six instants, `KeyUsage` was server or client auth,
      and one third of runs added `RevocationOptions` built from mutated CRLs. Finally it
      ran `verify_is_valid_for_subject_name` for DNS and IP names.
    - `BorrowedCertRevocationList::from_der`, iteration over the revoked entries,
      `to_owned`, `OwnedCertRevocationList::from_der` and `find_serial`.
    - `anchor_from_trusted_cert`.
  - "Anchors" here are the fixture certificates that happen to parse as trust anchors, not
    real root CAs.
  - Result of 10,000,000 iterations: **0 panics**. 1,205,738 end-entity certificates parsed,
    9,230 full chain verifications succeeded (from which we *infer* that the name-constraint
    and revocation paths were reached; coverage was not measured), 237,402 CRLs parsed and 249,706 trust anchors
    parsed. Harness
    `fuzzloop/src/main.rs` sha256 `3efd7e6a…b665`. It is not added to the repo; audit PRs add
    no fuzz targets.
- **Worst-case path-building time.** Scratch tests were added to the upstream clone, outside
  the repo. They reuse upstream's `make_issuer` / `IntermediateChain` helpers and run in a
  release build on aarch64-apple-darwin. The size limit that matters is rustls's: one
  handshake message may be at most 64 KiB (`rustls-0.23.45/src/msgs/deframer/handshake.rs:376`,
  `MAX_HANDSHAKE_SIZE = 0xffff`), which bounds the peer's whole certificate list.
  - *Degenerate chains only* (upstream's `test_too_many_path_calls` shape, 10-180
    intermediates that all match the issuer): every run stops on the fatal
    `MaximumPathBuildCallsExceeded` / `MaximumSignatureChecksExceeded` within 66 ms.
  - *Degenerate chains padded with non-matching filler intermediates.* This construction was
    found by the W1 verifier and reproduced by the main review. It is the expensive case:
    each of the up to 200,000 budgeted calls re-parses every filler with `Cert::from_der`
    (`verify_cert.rs:108`) before the subject comparison, and that work is not budgeted.

    | Matching + filler | Bytes | Time | Result |
    |---|---|---|---|
    | 10 + 140 | 63,861 | **758 ms** | `MaximumPathBuildCallsExceeded` |
    | 12 + 130 | 60,488 | 494 ms | `MaximumPathBuildCallsExceeded` |
    | 8 + 150 | 67,236 (over 64 KiB) | 488 ms | `MaximumPathDepthExceeded` |
    | 10 + 0 | 4,442 | 58 ms | `MaximumPathBuildCallsExceeded` |
    | 6 + 160 | 70,590 (over 64 KiB) | 34 ms | `UnknownIssuer` (no budget exhausted) |
  - **Conclusion:** the work is bounded by roughly 200,000 x (bytes of intermediates parsed
    per call), and the 64 KiB message cap bounds those bytes. A malicious server can make one
    handshake cost about **0.5-1 s of CPU** on this machine. It can be more on slower hardware
    or with a better-tuned chain, but not unboundedly more, because smaller fillers mean more
    of them in the same bytes and the parse cost tracks bytes. This is bounded, material, and
    upstream's chosen budget (the RUSTSEC-2023-0053 fix). The cost lands on the client that
    chose to connect to that server. ACDP's 30 s request timeout does not cut it short, since
    the work is synchronous CPU inside the handshake. Recorded as W-O8. This measurement is
    evidence, not a proof of the worst case.
- Miri was not run. The crate has no `unsafe`, so Miri would add little.

## Facts

| Item | Finding |
|---|---|
| `unsafe` | **0**. `grep -rnw unsafe src` prints nothing; `scripts/vet-facts.sh` reports "unsafe code lines: 0". There is no `#![forbid(unsafe_code)]`; `lib.rs:36` is `#![deny(missing_docs, clippy::as_conversions)]`, and it is only a hint because registry deps build with `--cap-lints allow`. |
| asm / SIMD / FFI | none (`grep -rn 'asm!' src`: 0). No `extern` blocks, `#[link]`, `static mut`, interior-mutable statics, `transmute`, `from_raw_parts`, `MaybeUninit`, `set_len` or raw pointers in any file. All six partitions report none, and the greps agree. |
| build.rs | none (`build = false`) |
| proc-macro | no. No `#[macro_export]`. The only macro is the crate-local `oid!` (`der.rs:464`). |
| Powerful imports | `#![no_std]`. `extern crate std` is under `cfg(any(feature = "std", test))` (`lib.rs:49-50`). The only non-test `std` use is `impl ::std::error::Error for Error` (`error.rs:384-385`). `std::net::IpAddr` (`subject_name/ip_address.rs:678`) and `std::time::Duration` (`crl/types.rs:911`) are test-only. No `std::{fs,process,env}`, no clock reads (time is always passed in as `UnixTime`), no network. |
| `include_*!` | Compiled: `ring_algs.rs:114, 135, 156` embed the three `src/data/*.der` blobs (see below). Not compiled: the same three in `aws_lc_rs_algs.rs:176, 196, 216`. Every other `include_bytes!` is in test code and reads `../tests/` fixtures that the tarball does not ship. No `include_str!`. |
| Dependencies | Normal: `rustls-pki-types` 1.12 (as `pki-types`, audited in B5) and `untrusted` 0.9 (audited in B3). Optional: `ring` 0.17 (on, the Tier A `ring` audit) and `aws-lc-rs` 1.18 (off). The dev-dependencies are not used by ACDP. |
| Features ACDP enables | `alloc`, `ring`, `std` (`cargo tree --locked --workspace --all-features -e features -i rustls-webpki@0.103.15`). `aws-lc-rs` and `aws-lc-rs-fips` are off. |
| Reached via | `rustls` 0.23.45 (`WebPkiServerVerifier`), under `hyper-rustls` / `tokio-rustls` / `reqwest` 0.12.28 `rustls-tls`. `reqwest` is used by `acdp-client`, `acdp-did`, `acdp-safe-http` and `acdp-primitives` (the last only for `From<reqwest::Error>`). Dev-only: the `axum-server` TLS test harness. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-05 (advisory DB at `ef6173cb`, 2026-10-03). The DB lists five `rustls-webpki` advisories; all are patched at or below 0.103.15 (table below). |
| Manifest notes | The `include` list names files that no longer exist (`src/calendar.rs`, `src/subject_name/{name,verify}.rs`, `src/name/{verify,name}.rs`). This is stale and harmless. `.orig` has a `[[bench]]` for the unshipped `benches/benchmark.rs`; the normalized manifest sets `autobenches = false`. |

## Which code each ACDP artifact compiles

| Artifact | Compiles `rustls-webpki`? | Evidence |
|---|---|---|
| `acdp` library and workspace crates with `client`/`server` (crates.io; CI on linux, macOS, windows) | yes, features `alloc,ring,std`; all non-test code except `aws_lc_rs_algs.rs` | `cargo tree --locked --workspace --all-features -e normal -i rustls-webpki@0.103.15` |
| `acdp-cli` | yes (through `acdp-client`) | same tree |
| `acdp --no-default-features` | no | `cargo tree --locked -p acdp --no-default-features -e normal -i rustls-webpki@0.103.15`: "nothing to print" |
| py wheels, node prebuilts | no: locked but not compiled | `cargo tree --locked -i rustls-webpki --target all` in `bindings/acdp-py` and `bindings/acdp-node`: "nothing to print" |
| wasm verifier (`wasm32-unknown-unknown`) | no: not in the lock | `bindings/acdp-wasm/Cargo.lock` has no `rustls-webpki` entry |

The crate has no target-specific `cfg`, so the compiled set is the same on every target. The
only `cfg`s are feature and test `cfg`s, plus the inert docs.rs-only
`#![cfg_attr(webpki_docsrs, feature(doc_cfg))]` (`lib.rs:46`).

## `unsafe` sites

None. There is no token-less unsafe surface either: no `extern` blocks, no exported symbols
and no macro-generated FFI.

## Embedded binary content

| File | Bytes | Decoded (`openssl asn1parse -inform DER`) | Verdict |
|---|---|---|---|
| `src/data/alg-rsa-pkcs1-sha256-absent-params.der` | `06 09 2a 86 48 86 f7 0d 01 01 0b` (11) | `OBJECT :sha256WithRSAEncryption` (1.2.840.113549.1.1.11) | correct |
| `src/data/alg-rsa-pkcs1-sha384-absent-params.der` | `06 09 2a 86 48 86 f7 0d 01 01 0c` (11) | `OBJECT :sha384WithRSAEncryption` (…1.12) | correct |
| `src/data/alg-rsa-pkcs1-sha512-absent-params.der` | `06 09 2a 86 48 86 f7 0d 01 01 0d` (11) | `OBJECT :sha512WithRSAEncryption` (…1.13) | correct |

Each blob is the body of an AlgorithmIdentifier SEQUENCE with the parameters absent: a bare
OID with no outer SEQUENCE and no NULL. That matches how they are used. `signed_data.rs:126`
strips the outer SEQUENCE before the byte comparison at `:189`. The params-present forms
come from `rustls-pki-types` (B5), and those are the same 11 bytes plus `05 00`. No other
binary content exists in the tarball.

## Panic and DoS inventory (non-test code)

The full-source sweep (W1-f; cross-checked by the main review's own script over the
5,880 compiled non-test lines) finds **25** panic-macro sites: 12 `.unwrap()`,
6 `unreachable!`, 5 `assert!` and 2 `debug_assert!`. It finds **0** `panic!`, `expect`,
`todo!`, `unimplemented!` and `unwrap_unchecked`. None is reachable from untrusted input.

| Site | Construct | Reachable from untrusted input? | Why it cannot fire |
|---|---|---|---|
| `verify_cert.rs:234`, `:246` | `unwrap` | callable, cannot fire | `IntermediateIterator` covers only `[..used]`, and every slot below `used` is `Some`. `push` (`:807-808`) writes before it increments, and `pop` (`:818-819`) decrements before it clears. |
| `verify_cert.rs:813` | `debug_assert!(used > 0)` | no | `pop` runs only after a successful `push` (`:127-130`). There is also an explicit `used == 0` return at `:814`. |
| `verify_cert.rs:842` | `unwrap` | callable, cannot fire | `idx` is `used`, or a `PathIter` index that counts down from it. The `0` arm is excluded, so `idx - 1 < used`. |
| `x509.rs:80` | `.last().unwrap()` | yes, cannot fire | The extension id length is checked to be exactly 3 at `:73`. |
| `time.rs:126`, `:166` | `unreachable!` | no | The month is bounded to 1..=12 by `read_two_digits` (`:72`). The only callers are `:73` and `:84`. |
| `time.rs:148` | `debug_assert!` | no | `year >= 1970` is checked at `:144` first. |
| `der.rs:246` | `assert!` | no | Only in `asn1_wrap`'s `len >= 0x80` branch, so `len.to_be_bytes()` has a non-zero byte. Called from `cert.rs:237` on an SPKI that has already been parsed. |
| `crl/types.rs:591` | `assert!(!only_contains_attribute_certs)` | no | The IDP always comes from `IssuingDistributionPoint::from_der`, which rejects that flag (`:544-546`). The only caller is `:119`. |
| `crl/mod.rs:125` | `assert!(issuer == issuer_subject)` | no | The only caller is `verify_cert.rs:156`. Path building links a certificate only to a parent whose subject equals its issuer (`verify_cert.rs:70` for anchors, `:109` for intermediates). `check_signed_chain` (`:147-169`) walks from the anchor down, passing the previous subject. |
| `subject_name/dns_name.rs:103` | `from_utf8(..).unwrap()` | yes, cannot fire | Construction goes through `try_from_ascii`, which checks `is_valid_dns_id` and allows ASCII `[A-Za-z0-9_.*-]` only. |
| `dns_name.rs:294`, `:301` | `unreachable!` | yes, cannot fire | `skip(n)` with `n <= len`, guarded by `presented.len() > reference.len()` (`:260`). |
| `dns_name.rs:311` | `unreachable!` (`IdRole::Presented`) | no | The callers pass only `Reference` (`:41`) or `NameConstraint` (`subject_name/mod.rs:134`). |
| `dns_name.rs:325` | `unreachable!` | yes, cannot fire | It follows a successful `peek(b'*')`. |
| `dns_name.rs:371-372` | `assert!` (both readers at end) | yes, cannot fire | Every non-returning exit of the loop at `:338-369` leaves both readers at end. |
| `ip_address.rs:91-92` | `read_byte().unwrap()` | yes, cannot fire | The lengths are proven equal (4/4 or 16/16) at `:80-86`. |
| `ip_address.rs:135-136` | `read_bytes(len/2).unwrap()` | yes, cannot fire | The constraint length is proven to be 8 or 32 (`:114-132`). |
| `ip_address.rs:148-150` | `read_byte().unwrap()` x3 | yes, cannot fire | All three readers are the same length, and the loop breaks at `name.at_end()` (`:178`). |

- **Indexing.** There are 14 sites (W1-f B2): `verify_cert.rs:87, 265, 737, 747, 807, 819,
  842`, `der.rs:254, 361` and `subject_name/mod.rs:380-386`. Each is guarded by the `used <=
  6` invariant, an `enumerate` bound, the `:358` length check, the `:246` assert or
  `chunks_exact(2)`.
- **Arithmetic.** The budget counters use `checked_sub` (`verify_cert.rs:303, 312, 321`).
  Every other operation on input-derived values is bounded by an earlier check:
  - DER length shifts are at most 3 bytes (`der.rs:176-200`).
  - Time fields are at most 9999 (`time.rs`).
  - DNS counters are at most 253 (`dns_name.rs:414`).
  - `sub_ca_count` is at most 6.
  - `ip_address.rs:161` is at most 16.

  `verify_cert.rs:731` `(cur << 8) + (byte & 0x7f)` cannot panic: the shift amount is a
  constant, and the low byte is zero before the add. It is a display bug (W-O1).
- **`as` casts.** Five, all bounded:
  - `der.rs:84` and `:91` (the `repr(u8)` `Tag` to `usize` / `u8`);
  - `der.rs:231` (`len < 0x80`);
  - `der.rs:251` (at most 8);
  - `crl/mod.rs:201` (a `repr(u8)` enum to `usize`).
- **Recursion.** There is one recursive function, `build_chain_inner` (`verify_cert.rs:128`).
  It is bounded by `MAX_SUB_CA_COUNT = 6` (`:847`; `push` returns `MaximumPathDepthExceeded`
  at `:802-805`), so it goes at most 7 frames deep. DER parsing has a fixed nesting depth
  through closures; there is no recursive descent (W1-d).
- **Budget (`verify_cert.rs:292-345`), the RUSTSEC-2023-0053 fix.** A fresh
  `Budget::default()` is created per `build_chain` (`:47`).
  - `signatures = 100` is consumed at `signed_data.rs:165`. CRL signature checks share it.
  - `build_chain_calls = 200_000` is consumed at `verify_cert.rs:126`, before every
    recursive descent.
  - `name_constraint_comparisons = 250_000` is consumed at `subject_name/mod.rs:113`, once
    per GeneralSubtree entry and before the per-type `continue`.

  All three errors are fatal. `error.rs:357-375` maps them to `ControlFlow::Break`, which
  stops the whole search (`verify_cert.rs:97-100`, `loop_while_non_fatal_error`). Upstream's
  `test_too_many_signatures`, `test_too_many_path_calls` and `name_constraint_budget` pass.
- **Unbudgeted but bounded work.**
  - Each `build_chain_inner` call re-parses every peer-supplied intermediate with
    `Cert::from_der` before the issuer comparison (`verify_cert.rs:108`). The cost is
    therefore at most 200,000 times the bytes of intermediates, and the 64 KiB handshake
    message bounds those bytes. Measured: about 0.5-1 s of CPU per malicious handshake with
    filler-padded chains (Empirical checks; W-O8).
  - SAN iteration with no name constraints is linear in the certificate.
  - CRL `find_serial` is linear in the CRL. It is unreachable in ACDP (below).
- **Lengths.** The default `TWO_BYTE_DER_SIZE = 0xFFFF` limit applies to certificate
  parsing (`der.rs:211, 265`; `cert.rs:73`), and CRLs use `MAX_DER_SIZE` (`der.rs:271`).
  Indefinite lengths and lengths of 5 or more bytes are rejected (`der.rs:206-207`), and so
  is non-minimal length encoding. Every `nested` call goes through `read_all`, so trailing
  data is rejected.

**Verdict:** no reachable panic and no unbounded work from a server-presented chain. The
bounded worst case is material, about 0.5-1 s of CPU per malicious handshake (W-O8).

## CRL verdicts

ACDP's HTTPS clients are built at exactly five sites (`grep -rnE 'Client::builder' crates`):
`crates/acdp-did/src/web.rs:341`, `crates/acdp-client/src/registry.rs:791` and `:829`,
`crates/acdp-client/src/data_ref.rs:155`, and `crates/acdp-safe-http/src/lib.rs:486`.
- None of them calls reqwest 0.12.28's CRL API (`ClientBuilder::add_crl` / `add_crls`,
  `src/async_impl/client.rs:1867-1884`; blocking `src/blocking/client.rs:807, 819`), and none
  builds a `reqwest::tls::CertificateRevocationList` (`from_pem` / `from_pem_bundle`,
  `src/tls.rs:434-463`).
- None calls `use_preconfigured_tls` (`async_impl/client.rs:2158`).
- None calls `danger_accept_invalid_hostnames` / `danger_accept_invalid_certs`.
- No ACDP crate builds a rustls `ClientConfig` or `WebPkiServerVerifier` itself (`grep`:
  no hits).
- The only TLS configuration ACDP applies is `add_root_certificate` for a caller-supplied
  extra root (`acdp-did/src/web.rs:351`, behind `with_root_cert_pem` /
  `with_capacity_and_root_cert_pem` at `:108`, `:117`; `acdp-client/src/registry.rs:865`,
  behind `RegistryClientBuilder::root_cert_pem` at `:748` and the `test-transport`-gated
  `with_root_cert_pem` at `:332`).

With no CRLs configured, reqwest calls `config_builder.with_root_certificates(..)`
(`async_impl/client.rs:792-793`). rustls's `WebPkiServerVerifier` then passes
`revocation = None` (`rustls-0.23.45/src/webpki/server_verifier.rs:244`).

**(i) CRL-object parsing and revocation checking (`crl/`): compiled, unreached in ACDP's
configuration.** webpki consults revocation only at `verify_cert.rs:155-165`
(`if let Some(revocation_opts) = &self.revocation`). A `RevocationOptions` cannot be built
without at least one CRL (`crl/mod.rs:59-62`). CRL parsing runs only when a caller calls
`BorrowedCertRevocationList::from_der` / `OwnedCertRevocationList::from_der` on bytes it
chose. The code was still read in full, and it has no panic reachable from CRL bytes (W1-c).

**(ii) The CRL distribution-points extension inside each certificate: compiled, unreached
in ACDP's configuration.**
- `cert.rs:314` stores extension 31 raw (field `cert.rs:47`). At parse time it checks only
  that the extension is a single SEQUENCE with no trailing data (`:324-330`).
- The contents are parsed lazily by `crl_distribution_points()` (`cert.rs:244-248`).
- Its only non-test caller is `IssuingDistributionPoint::authoritative_for`
  (`crl/types.rs:600`), reached as `crl/mod.rs:136` → `types.rs:96` → `:119`. That needs
  `RevocationOptions` and a CRL that carries an IDP.
- The DistributionPoint and `reasons` parsing (`cert.rs:361-407`, `der.rs:373-397`) was
  still read, and it cannot panic (next section).

## Advisories: regression targets

| Advisory | Patched | Status in 0.103.15 (code that carries the fix) |
|---|---|---|
| RUSTSEC-2023-0053, CPU DoS in path building | `>= 0.101.4` | **Fixed.** `Budget` (`verify_cert.rs:292-345`). Calls are consumed at `:126` and signatures at `signed_data.rs:165`. Exhaustion is fatal via `error.rs:357-375`. Measured: plain degenerate chains stop within 66 ms; filler-padded chains take up to 758 ms (W-O8). |
| RUSTSEC-2026-0049, CRL distribution-point matching | `>= 0.103.10` | **Fixed.** `authoritative_for` (`crl/types.rs:600-650`) tries every certificate DP (malformed, indirect, reason-partitioned and non-FullName DPs `continue`, `:608-621`), every name in each DP (`:625-630`), and every IDP URI (`:637-645`), and returns `false` only after all of them are exhausted (`:650`). Unreached in ACDP (CRL verdicts). |
| RUSTSEC-2026-0098, URI name constraints wrongly accepted | `>= 0.103.12` | **Fixed.** `subject_name/mod.rs:166-177`. A URI SAN against a URI subtree gives permitted → `false` and excluded → `true`, so any URI constraint rejects a URI SAN (fail closed). There is deliberately no catch-all arm (`:129`). |
| RUSTSEC-2026-0099, name constraints accepted for wildcard names | `>= 0.103.12` | **Fixed.** `subject_name/dns_name.rs:314-336`, condition at `:322`. Wildcard expansion is skipped for `NameConstraint(Subtrees::Permitted)`, so `*.example.com` does not satisfy permitted `www.example.com`. Excluded subtrees still expand it. Regression tests: `dns_name.rs:964-972`, `:992-1058`. |
| RUSTSEC-2026-0104, panic on an empty `onlySomeReasons` BIT STRING in CRL parsing | `>= 0.103.13` | **Fixed.** `crl/types.rs:525-529` parses `[3]` through `der::bit_string_flags`, and `:554-556` rejects any `onlySomeReasons` with `UnsupportedRevocationReasonsPartitioning`, at CRL load (`:445-447`) and before matching (`:107`). Upstream regression test: `crl/types.rs:1270-1286` (`83 01 00` → error). |

**The same empty-BIT-STRING pattern in the certificate's own CRL DP `reasons`**
(`cert.rs:387` → `der::bit_string_flags`, `der.rs:373-397`) **cannot panic.**
- An empty value fails `read_byte` with `BadDer` (`der.rs:379`).
- `[0x00]` takes the `(0, None) => Ok` arm (`:387`) with empty `raw_bits`, and every later
  `bit_set` returns `false` through the length check at `der.rs:358` before it indexes at
  `:361`.
- Padding of 1-7 with no data byte, padding of 8 or more, or non-zero padding bits all give
  `BadDer` (`:384`, `:388`, `:392`).

The parse is reached only on the revocation path (CRL verdict (ii)).

The local registry also holds 0.103.13. `src/subject_name/` and `der.rs` are byte-identical
to it, and `crl/` differs only by a cosmetic `?` rewrite of `find_serial`
(`crl/types.rs:315-324`). That is consistent with the 2026 fixes all predating 0.103.13.

## Signature dispatch (observed, not claimed)

- `signed_data.rs:187-190` selects a candidate algorithm only when its `signature_alg_id()`
  bytes exactly equal the certificate's signatureAlgorithm.
- The SPKI algorithm must then byte-equal `public_key_alg_id()` (`:228-238`).
- Verification is `ring::signature::UnparsedPublicKey::verify` (`ring_algs.rs:41-43`). Every
  ring error maps to `InvalidSignatureForPublicKey`.
- An unknown algorithm or key-type mismatch returns an `Unsupported…` error (`:205-219`),
  never `Ok`. SHA-1 and P-521 are not in the ring list.
- The outer and inner signature algorithms must match (`cert.rs:89-91`). Unknown critical
  extensions are rejected under the default `Strict` policy (`x509.rs:26-31`), and
  duplicates of the known extensions are rejected (`cert.rs:323`).

## Findings and observations (hygiene; none is a concern-rule trigger)

- **W-O1. OID decoder shifts by 8 instead of 7** (`verify_cert.rs:731`). Multi-byte arcs
  decode to wrong numbers, and the crate's own test (`:916-922`) encodes the same mistake.
  - Impact is display only: `KeyPurposeId` `Debug`, `to_decoded_oid()` in
    `RequiredEkuNotFoundContext.present`, and `KeyUsage::oid_values()`.
  - EKU matching is a raw byte comparison (`:570`), so no validation decision changes, and
    it cannot panic.
  - **Already fixed upstream:** `rustls/webpki` `main` now uses
    `cur.saturating_mul(128).saturating_add(..)`. No report is needed.
- **W-O2. keyUsage is ignored on issuers in this version** (`verify_cert.rs:359-363`).
  Upstream `main` has since added keyCertSign enforcement (commit `a0bf40810`, 2026-06-10).
  This is validation behaviour, which the audit does not claim.
- **W-O3.** A repeated *unknown* non-critical extension is not detected (`cert.rs:323`
  covers the known ones). This is a minor RFC 5280 deviation, not a safety issue.
- **W-O4.** Excluded-subtree wildcard expansion over-rejects. `*.a.b` matches excluded
  `.x.a.b` (`dns_name.rs:328-335`), so the result fails closed.
- **W-O5.** IP name-constraint address bits outside the mask need not be zero
  (`ip_address.rs:175`), which is lenient. Mask contiguity is enforced (`:161-168`).
- **W-O6.** Malformed DNS SANs are skipped rather than failing the check
  (`dns_name.rs:43`).
- **W-O7.** The serial number is parsed leniently: any INTEGER contents, stored only
  (`cert.rs:274-288`).
- **W-O8. Unbudgeted re-parsing of intermediates.** Path building re-parses each
  peer-supplied intermediate on every budgeted call (`verify_cert.rs:108`). A filler-padded
  chain within the 64 KiB handshake limit costs about 0.5-1 s of CPU per handshake
  (measured worst 758 ms). This is bounded and is upstream's chosen budget, so it is not a
  concern-rule trigger. It is a DoS-cost observation: an attacker-controlled HTTPS endpoint
  can make an ACDP client spend that much CPU per connection attempt. Possible upstream
  hardening, not filed: parse the intermediates once per `build_chain`.
- **W-O9.** The manifest `include` list is stale, and `tests/`, `benches/` and
  `src/test_utils.rs` are not shipped. The tarball's own unit tests therefore cannot build
  outside upstream, and they were run from the tagged upstream clone instead.

## Concerns

None under the concern rule:
- no `unsafe`;
- no unexpected network, filesystem or process access;
- no build.rs or proc-macro;
- no obfuscated or vendored binary content (the three blobs are decoded above);
- no open RUSTSEC entry;
- the review was finished.

No reachable panic, unbounded loop or unbounded recursion from untrusted input was found
(the C1 flip criteria in the plan). The one material, bounded cost is W-O8.

## Recommendation for W2 (C1)

- **Certify `safe-to-deploy`, full (option 1).** No `Discretion:` line is needed, because
  no finding rests on a reachability carve-out: the CRL paths are reviewed and panic-free,
  not merely unreached. W-O8 (about 0.5-1 s of CPU per malicious handshake, measured worst 758 ms; bounded) is not a
  concern-rule trigger and does not meet the plan's "unbounded work" flip criterion. The
  notes should still state it as an observation.
- **Proposed notes scope (`Not claimed:` line):** "Not claimed: cryptographic correctness,
  constant-time behaviour, side-channel resistance; certificate path-validation,
  name-constraint and revocation correctness (upstream's responsibility, as for rustls and
  webpki-roots)."
- **Proposed `Scope:` wording:** "full audit of 0.103.15 (no prior audit). src/ is 10040
  lines in 19 .rs files plus three 11-byte .der blobs; every line read, cfg(test) modules
  and the not-compiled aws_lc_rs_algs.rs included."

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, and the
correctness of certificate path validation, name-constraint evaluation and revocation
checking.
