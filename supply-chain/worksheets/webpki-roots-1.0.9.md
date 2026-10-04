# Review worksheet: `webpki-roots` 1.0.9 (issue #339, Tier B batch B4)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "1.0.9"`). No concern-rule
  trigger. One `Discretion:` line records the test-only network/file-writing generator and
  the test-only DER fixtures.
- **Trust boundary.** This crate is the default trust-anchor set for every ACDP HTTPS
  client. The audit claims that the crate's *code* is safe to deploy and that the table is
  exactly the certificates its comments name (verified below). **It does not claim that the
  root set is correct, complete, current, or appropriate for ACDP.** That is Mozilla's /
  CCADB's and upstream's responsibility.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 1.0.9 (locked) | `7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is identical (`diff -r`; only cargo's
`.cargo-ok` marker differs) to the `~/.cargo/registry/src` copy that was read. Reproduce the
facts with `scripts/vet-facts.sh webpki-roots 1.0.9`. The root, py and node lockfiles lock
1.0.9 with this checksum; the wasm binding does not contain it. In py and node it is locked
but not compiled: the bindings build `acdp` with `default-features = false`, and
`cargo tree -i webpki-roots -e all --target all --all-features` in `bindings/acdp-py` and
`bindings/acdp-node` prints nothing.
`.cargo_vcs_info.json`: upstream commit `0a553dbc8b3f18ea05c4f881cffa3f2d005d0d30`,
path `webpki-roots` in the `rustls/webpki-roots` workspace.

## Where the data comes from and how it is regenerated

- `src/lib.rs` is the only source file. Its header comment says it is generated from the
  Mozilla `IncludedCACertificateReportPEMCSV` report via ccadb.org (`src/lib.rs:18-22`).
- The generator is the integration test `tests/codegen.rs` (`new_generated_code_is_fresh`,
  `:12-97`). It calls `webpki_ccadb::fetch_ccadb_roots()` (a path dependency in the upstream
  workspace that is stripped from the published `Cargo.toml`, so the test cannot run from the
  tarball), checks each root's DER SHA-256 against the CCADB metadata fingerprint
  (`:23-26`), derives subject/SPKI with `webpki::anchor_from_trusted_cert` (`:28-38`), takes
  name constraints from CCADB's Mozilla-applied constraints (`:40-45`), emits a comment block
  (issuer, subject, label, serial, fingerprint, PEM; `:55-67`) and a `TrustAnchor` literal
  (`:70-87`), and, if the result differs from the checked-in file, rewrites `src/lib.rs` and
  fails (`:91-96`). Regeneration therefore happens upstream by running that test.
- The checked-in header (`src/lib.rs:1-37`) equals the generator's `HEADER` constant
  (`tests/codegen.rs:135-172`) byte for byte (checked by script).

## Method

- No prior audit of `webpki-roots` exists, so **full**.
- `src/lib.rs` is 4,603 lines: the 37-line header (read in full: docs, `#![no_std]`,
  `#![forbid(unsafe_code, unstable_features)]`, a `#![deny(..)]` lint list, and
  `use pki_types::{Der, TrustAnchor};`), the declaration
  `pub const TLS_SERVER_ROOTS: &[TrustAnchor<'static>] = &[` at `:38`, and 4,565 table lines
  (`:39-4603`).
- **Table check (mechanical and exhaustive, Python 3.9 + `cryptography` 50.0.1).**
  1. *Shape.* Every one of the 4,565 table lines matches exactly one of the generator's
     line forms: `  /*`, `   * <text>`, `   */`, `  TrustAnchor {`,
     `    subject: Der::from_slice(b"...")`,
     `    subject_public_key_info: Der::from_slice(b"...")`,
     `    name_constraints: None` or `    name_constraints: Some(Der::from_slice(b"..."))`,
     `  },`, blank, or the closing `];`. 0 unmatched lines. Counts: 121 comment blocks,
     121 `TrustAnchor` literals, 120 `None` and 1 `Some` name constraints, 1 closing `];`.
     So the table contains only byte-string literals passed to the `const fn`
     `Der::from_slice`; there is no other code in it.
  2. *Content.* For each of the 121 entries, the PEM in the entry's comment was
     base64-decoded and parsed as X.509. Its SHA-256 equals the commented
     `SHA256 Fingerprint`; the `subject` literal equals the certificate's subject `Name`
     contents and the `subject_public_key_info` literal equals its `SubjectPublicKeyInfo`
     contents (outer SEQUENCE header stripped, as `anchor_from_trusted_cert` does).
     0 mismatches. Every certificate has `basicConstraints cA=true`; none has a
     `notAfter` before 2026.
  3. *Name constraints.* One entry, "TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1"
     (comment at `src/lib.rs:1222`, literal at `:1258`), carries
     `a0 07 30 05 82 03 2e 74 72`: `permittedSubtrees` containing one `dNSName` `.tr`. This
     restricts that root to `.tr` names (a Mozilla-applied constraint); it does not widen
     trust.
- `tests/codegen.rs` (172) read in full; `tests/verify.rs` (202) read: name-constraint and
  TUBITAK chain tests using `rcgen`/`webpki`; it `include_bytes!` the three fixtures
  (`:168-170`).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 (grep of the full source; the grep is the evidence). `#![forbid(unsafe_code, unstable_features)]` at `src/lib.rs:26` is only a corroborating hint (cargo builds registry deps with `--cap-lints allow`). |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no; no macros exported |
| Powerful imports | none in `src/`. `#![no_std]`; no `fn`, no `static`, no `include_*`; one `pub const` table. |
| Binary content | `tests/data/tubitak/{root,inter,subj}.der` (1127, 1654, 1649 bytes): DER certificates loaded by `include_bytes!` in `tests/verify.rs:168-170` only. Not compiled into any non-test build. Recorded as a discretion line. |
| Test-only I/O | `tests/codegen.rs` fetches CCADB over the network (`:14`) and may `fs::write` `src/lib.rs` (`:92-95`). Test-only, upstream-only (needs the stripped `webpki-ccadb` path dependency); never built for ACDP. Recorded as a discretion line. |
| Dependencies | `rustls-pki-types` 1.8 (`default-features = false`, renamed `pki-types`). Dev-only: `aws-lc-rs`, `hex`, `percent-encoding`, `rcgen`, `rustls`, `tokio`, `rustls-webpki`, `x509-parser`, `yasna`; dev-dependencies of a dependency are not resolved into ACDP's graph. |
| Features ACDP enables | none (the crate has no features) |
| Reached via | `reqwest` 0.12 feature `rustls-tls` -> `rustls-tls-webpki-roots` (`reqwest-0.12.28/Cargo.toml` features), and `hyper-rustls` 0.27.9 |
| ACDP use | `reqwest` with `features = ["json", "rustls-tls"]` in `crates/acdp-client/Cargo.toml:41`, `crates/acdp-did/Cargo.toml:37`, `crates/acdp-safe-http/Cargo.toml:29`, `crates/acdp-primitives/Cargo.toml:28`. These anchors are the default roots for `RegistryClient`, `WebResolver` and the data-ref fetcher; `WebResolver::with_root_cert_pem` (`crates/acdp-did/src/web.rs:108`, applied with `add_root_certificate` in `build_http_client`) and the `RegistryClient` extra-root path (`crates/acdp-client/src/registry.rs:865`, `builder.add_root_certificate(cert)`) add a caller-supplied root to these anchors; they do not replace them. No ACDP source file names `webpki_roots` directly. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Concerns

None under the concern rule. The crate is a static table plus a `const` declaration; it has
no runtime code, no I/O and no `unsafe`.

**Not a vet concern, recorded for readers:** a compiled-in root store does not update
without a rebuild, and the crate's own docs (`src/lib.rs:11-15`) recommend a platform
verifier for applications that cannot be recompiled. Root-set freshness for ACDP follows
the `webpki-roots` version in `Cargo.lock`.

## Not claimed

That the root set is correct, complete, current, or fit for ACDP; certificate-validation
correctness (`rustls-webpki`, a separate Tier B crate); cryptographic correctness;
constant-time behaviour; side-channel resistance.

## Appendix: the 121 trust anchors in 1.0.9

Generated from `src/lib.rs` by script; label and fingerprint are taken from each entry's
comment, which step 2 above checked against the embedded certificate and literals.

| # | Entry starts at | Label | SHA-256 fingerprint |
|---|---|---|---|
| 1 | `src/lib.rs:39` | DigiCert TLS ECC P384 Root G5 | `018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05` |
| 2 | `src/lib.rs:66` | D-TRUST BR Root CA 2 2023 | `0552e6f83fdf65e8fa9670e666df28a4e21340b510cbe52566f97c4fb94b2bd1` |
| 3 | `src/lib.rs:112` | TrustAsia TLS RSA Root CA | `06c08d7dafd876971eb1124fe67f847ec0c7a158d3ea53cbe940e2ea9791f4c3` |
| 4 | `src/lib.rs:157` | D-TRUST EV Root CA 1 2020 | `08170d1aa36453901a2f959245e347db0c8d37abaabc56b81aa100dc958970db` |
| 5 | `src/lib.rs:188` | Telia EC TLS Root CA v3 | `098e08a91dbbf77478b96cceb89b1413a5da37b7c862606a955deb07179f4326` |
| 6 | `src/lib.rs:215` | emSign Root CA - C1 | `125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f` |
| 7 | `src/lib.rs:249` | SECOM TLS RSA Root CA 2024 | `1435f225c5d252d7a21948cc3ce62aecfa88001e3dd72d1cc3555100eb372f93` |
| 8 | `src/lib.rs:294` | COMODO ECC Certification Authority | `1793927a0614549789adce2f8f34f7f0b66d0f3ae3a3b84d21ec15dbba4fadc7` |
| 9 | `src/lib.rs:323` | GlobalSign | `179fbc148a3dd00fd24ea13458cc43bfa7f59c8182d783a513f6ebec100c8924` |
| 10 | `src/lib.rs:350` | Amazon Root CA 3 | `18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4` |
| 11 | `src/lib.rs:375` | SwissSign RSA TLS Root CA 2022 - 1 | `193144f431e0fddb740717d4de926a571133884b4360d30e272913cbe660ce41` |
| 12 | `src/lib.rs:420` | Amazon Root CA 2 | `1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4` |
| 13 | `src/lib.rs:464` | SSL.com EV Root Certification Authority ECC | `22a2c1f7bded704cc1e701b5f408c310880fe956b5de2a4a44f99c873a25a7c8` |
| 14 | `src/lib.rs:493` | Telia Root CA v2 | `242b69742fcb1e5b2abf98898b94572187544e5b4d9911786573621f6a74b82c` |
| 15 | `src/lib.rs:538` | Izenpe.com | `2530cc8e98321502bad96f9b1fba1b099e2d299e0f4548bb914f363bc0d4531f` |
| 16 | `src/lib.rs:585` | GlobalSign | `2cabeafe37d06ca22aba7391c0033d25982952c453647349763a3ab5ad6ccf69` |
| 17 | `src/lib.rs:630` | Starfield Root Certificate Authority - G2 | `2ce1cb0bf9d2f9e102993fbe215152c3b2dd0cabde1c68e5319b839154dbb7f5` |
| 18 | `src/lib.rs:666` | TunTrust Root CA | `2e44102ab58cb85419451c8e19d9acf3662cafbc614b6a53960a30f7d0e2eb41` |
| 19 | `src/lib.rs:712` | SSL.com EV Root Certification Authority RSA R2 | `2e7bf16cc22485a7bbe2aa8696750761b0ae39be3b2fe9d0cc6d4ef73491425c` |
| 20 | `src/lib.rs:759` | IdenTrust Public Sector Root CA 1 | `30d0895a9a448a262091635522d1f52010b5867acae12c78ef958fd4f4389f2f` |
| 21 | `src/lib.rs:803` | vTrus ECC Root CA | `30fbba2c32238e2a98547af97931e550428b9b3f1c8eeb6633dcfa86c5b27dd3` |
| 22 | `src/lib.rs:830` | DigiCert Global Root G3 | `31ad6648f8104138c738f39ea4320133393e3a18cc02296ef97c2ac9ef6731d0` |
| 23 | `src/lib.rs:858` | SSL.com Root Certification Authority ECC | `3417bb06cc6007da1b961c920b8ab4ce3fad820e4aa30b9acbc4a74ebdcebc65` |
| 24 | `src/lib.rs:887` | GTS Root R4 | `349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d` |
| 25 | `src/lib.rs:913` | GTS Root R3 | `34d8a73ee208d9bcdb0d956520934b4e40e69482596e8b6f73c8426b010a6f48` |
| 26 | `src/lib.rs:939` | Microsoft ECC Root Certificate Authority 2017 | `358df39d764af9e1b766e9c972df352ee15cfac227af6ad1d70e8e4a6edcba02` |
| 27 | `src/lib.rs:967` | DigiCert TLS RSA4096 Root G5 | `371a00dc0533b3721a7eeb40e8419e70799d2b0a0f2c1d80693165f7cec4ad75` |
| 28 | `src/lib.rs:1011` | Microsec e-Szigno Root CA 2009 | `3c5f81fea5fab82c64bfa2eaecafcde8e077fc8620a7cae537163df36edbf378` |
| 29 | `src/lib.rs:1048` | TWCA CYBER Root CA | `3f63bb2814be174ec8b6439cf08d6d56f0b7c405883a5648a334424d6b3ec558` |
| 30 | `src/lib.rs:1093` | HARICA TLS ECC Root CA 2021 | `3f99cc474acfce4dfed58794665e478d1547739f2e780f1bb4ca9b133097d401` |
| 31 | `src/lib.rs:1121` | emSign Root CA - G1 | `40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367` |
| 32 | `src/lib.rs:1156` | Hellenic Academic and Research Institutions ECC RootCA 2015 | `44b545aa8a25e65a73ca15dc27fc36d24c1cb9953a066539b11582dc487b4833` |
| 33 | `src/lib.rs:1186` | Go Daddy Root Certificate Authority - G2 | `45140b3247eb9cc8c5b4f0d7b53091f73292089e6e5a63e2749dd3aca9198eda` |
| 34 | `src/lib.rs:1222` | TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1 | `46edc3689046d53a453fb3104ab80dcaec658b2660ea1629dd7e867990648716` |
| 35 | `src/lib.rs:1261` | D-TRUST Root Class 3 CA 2 2009 | `49e7a442acf0ea6287050054b52564b650e4f49e42e348d6aa38e039e957b1c1` |
| 36 | `src/lib.rs:1299` | SecureSign Root CA14 | `4b009c1034494f9ab56bba3ba1d62731fc4d20d8955adcec10a925607261e338` |
| 37 | `src/lib.rs:1344` | GlobalSign Root R46 | `4fa3126d8d3a11d1c4855a4f807cbad6cf919d3a5a88b03bea2c6372d93c40c9` |
| 38 | `src/lib.rs:1388` | USERTrust ECC Certification Authority | `4ff460d54b9c86dabfbcfc5712e0400d2bed3fbc4d4fbdaa86e06adcd2a9ad7a` |
| 39 | `src/lib.rs:1417` | Security Communication RootCA2 | `513b2cecb810d4cde5dd85391adfc6c2dd60d87bb736d2b521484aa47a0ebef6` |
| 40 | `src/lib.rs:1451` | COMODO RSA Certification Authority | `52f0e1c4e58ec629291b60317f074671b85d7ea80d5b07273463534b32b40234` |
| 41 | `src/lib.rs:1498` | DigiCert Trusted Root G4 | `552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988` |
| 42 | `src/lib.rs:1543` | AC RAIZ FNMT-RCM SERVIDORES SEGUROS | `554153b13d2cf9ddb753bfbe1a4e0ae08d0aa4187058fe60a2b862b2e4b87bcb` |
| 43 | `src/lib.rs:1572` | Actalis Authentication Root CA | `55926084ec963a64b96e2abe01ce0ba86a64fbfebcc7aab5afc155b37fd76066` |
| 44 | `src/lib.rs:1618` | Starfield Services Root Certificate Authority - G2 | `568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5` |
| 45 | `src/lib.rs:1655` | BJCA Global Root CA2 | `574df6931e278039667b720afdc1600fc27eb66dd3092979fb73856487212882` |
| 46 | `src/lib.rs:1682` | Telekom Security TLS ECC Root 2020 | `578af4ded0853f4e5998db4aeaf9cbea8d945f60b620a38d1a3c13b2bc7ba8e1` |
| 47 | `src/lib.rs:1710` | Autoridad de Certificacion Firmaprofesional CIF A62634068 | `57de0583efd2b26e0361da99da9df4648def7ee8441c3b728afa9bcde0f9b26a` |
| 48 | `src/lib.rs:1758` | TWCA Global Root CA | `59769007f7685d0fcd50872f9f95d5755a5b2b457d81f3692b610a98672f0e1b` |
| 49 | `src/lib.rs:1802` | Hongkong Post Root CA 3 | `5a2fc03f0c83b090bbfa40604b0988446c7636183df9846e17101a447fb8efd6` |
| 50 | `src/lib.rs:1849` | Certum Trusted Network CA | `5c58468d55f58e497e743982d2b50010b6d165374acf83a7d4a32db768c4408e` |
| 51 | `src/lib.rs:1884` | CFCA EV ROOT | `5cc3d78e4e1d5e45547a04e6873e64f90cf9536d1ccc2ef800f355c4c5fd70fd` |
| 52 | `src/lib.rs:1929` | IdenTrust Commercial Root CA 1 | `5d56499be4d2e08bcfcad08a3e38723d50503bde706948e42f55603019e528ae` |
| 53 | `src/lib.rs:1973` | certSIGN ROOT CA G2 | `657cfe2fa73faa38462571f332a2363a46fce7020951710702cdfbb6eeda3305` |
| 54 | `src/lib.rs:2017` | ISRG Root X2 | `69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470` |
| 55 | `src/lib.rs:2044` | SECOM TLS ECC Root CA 2024 | `6ab2ab75f51cb4f4f0156203fbf6f646232f514be059f62833308b82b4d72db1` |
| 56 | `src/lib.rs:2072` | Certum EC-384 CA | `6b328085625318aa50d173c98d8bda09d57e27413d114cf787a0f5d06c030cf6` |
| 57 | `src/lib.rs:2100` | OISTE WISeKey Global Root GB CA | `6b9c08e86eb0f767cfad65cd98b62149e5494a67f5845e7bd1ed019f27b86bd6` |
| 58 | `src/lib.rs:2135` | NetLock Arany (Class Gold) Főtanúsítvány | `6c61dac3a2def031506be036d2a6fe401994fbd13df9c8d466599274c446ec98` |
| 59 | `src/lib.rs:2172` | Certainly Root R1 | `77b82cd8644c4305f7acc5cb156b45675004033d51c60c6202a8e0c33467d3a0` |
| 60 | `src/lib.rs:2216` | Sectigo Public Server Authentication Root R46 | `7bb647a62aeeac88bf257aa522d01ffea395e0ab45c73f93f65654ec38f25a06` |
| 61 | `src/lib.rs:2261` | DigiCert Assured ID Root G2 | `7d05ebb682339f8c9451ee094eebfefa7953a114edb2f44949452fab7d2fc185` |
| 62 | `src/lib.rs:2296` | DigiCert Assured ID Root G3 | `7e37cb8b4c47090cab36551ba6f45db840680fba166a952db100717f43053fc2` |
| 63 | `src/lib.rs:2324` | Atos TrustedRoot Root CA RSA TLS 2021 | `81a9088ea59fb364c548a6f85559099b6f0405efbf18e5324ec9f457ba00112f` |
| 64 | `src/lib.rs:2368` | OISTE WISeKey Global Root GC CA | `8560f91c3624daba9570b5fea0dbe36ff11a8323be9486854fb3f34a5571198d` |
| 65 | `src/lib.rs:2396` | SSL.com Root Certification Authority RSA | `85666a562ee0be5ce925c1d8890a6f76a87ec16d4d7d5f29ea7419cf20123b69` |
| 66 | `src/lib.rs:2443` | emSign ECC Root CA - G3 | `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b` |
| 67 | `src/lib.rs:2471` | QuoVadis Root CA 3 G3 | `88ef81de202eb018452e43f864725cea5fbd1fc2d9d205730709c5d8b8690f46` |
| 68 | `src/lib.rs:2515` | NAVER Global Root Certification Authority | `88f438dcf8ffd1fa8f429115ffe5f82ae1e06e0c70c375faad717b34a49e7265` |
| 69 | `src/lib.rs:2561` | vTrus Root CA | `8a71de6559336f426c26e53880d00d88a18da4c6a91f0dcb6194e206c5c96387` |
| 70 | `src/lib.rs:2605` | QuoVadis Root CA 1 G3 | `8a866fd1b276b57e578e921c65828a2bed58e9f2f288054134b7f1f4bfc9cc74` |
| 71 | `src/lib.rs:2649` | D-TRUST EV Root CA 2 2023 | `8e8221b2e7d4007836a1672f0dcc299c33bc07d316f132fa1a206d587150f1ce` |
| 72 | `src/lib.rs:2695` | Amazon Root CA 1 | `8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e` |
| 73 | `src/lib.rs:2728` | SSL.com TLS RSA Root CA 2022 | `8faf7d2e2cb4709bb8e0b33666bf75a5dd45b5de480f8ea8d4bfe6bebc17f2ed` |
| 74 | `src/lib.rs:2773` | QuoVadis Root CA 2 G3 | `8fe4fb0af93a4d0d67db0bebb23e37c71bf325dcbcdd240ea04daf58b47e1840` |
| 75 | `src/lib.rs:2817` | T-TeleSec GlobalRoot Class 2 | `91e2f5788d5810eba7ba58737de1548a8ecacd014598bc0b143e041b17052552` |
| 76 | `src/lib.rs:2853` | ISRG Root X1 | `96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6` |
| 77 | `src/lib.rs:2897` | Buypass Class 2 Root CA | `9a114025197c5bb95d94e63d55cd43790847b646b23cdf11ada4a00eff15fb48` |
| 78 | `src/lib.rs:2941` | ACCVRAIZ1 | `9a6ec012e1a7da9dbe34194d478ad7c0db1822fb071df12981496ed104384113` |
| 79 | `src/lib.rs:2998` | OISTE Server Root RSA G1 | `9ae36232a5189ffddb353dfd26520c015395d22777dac59db57b98c089a651e6` |
| 80 | `src/lib.rs:3043` | UCA Global G2 Root | `9bea11c976fe014764c1be56a6f914b5a560317abd9988393382e5161aa0493c` |
| 81 | `src/lib.rs:3087` | Hellenic Academic and Research Institutions RootCA 2015 | `a040929a02ce53b4acf4f2ffc6981ce4496f755e6d45fe0b2a692bcd52523f36` |
| 82 | `src/lib.rs:3135` | SZAFIR ROOT CA2 | `a1339d33281a0b56e557d3d32b1ce7f9367eb094bd5fa72a7e5004c8ded7cafe` |
| 83 | `src/lib.rs:3169` | GlobalSign | `b085d70b964f191a73e4af0d54ae7a0e07aafdaf9b71dd0862138ab7325a24a2` |
| 84 | `src/lib.rs:3194` | Atos TrustedRoot Root CA ECC TLS 2021 | `b2fae53e14ccd7ab9212064701ae279c1d8988facb775fa8a008914e663988a8` |
| 85 | `src/lib.rs:3221` | Certainly Root E1 | `b4585f22e4ac756a4e8612a1361c5d9d031a93fd84febb778fa3068b0fc42dc2` |
| 86 | `src/lib.rs:3247` | e-Szigno TLS Root CA 2023 | `b49141502d00663d740f2e7ec340c52800962666121a36d09cf7dd2b90384fb4` |
| 87 | `src/lib.rs:3278` | Certum Trusted Network CA 2 | `b676f2eddae8775cd36cb0f63cd1d4603961f49e6265ba013a2f0307b6d0b804` |
| 88 | `src/lib.rs:3325` | emSign ECC Root CA - C3 | `bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3` |
| 89 | `src/lib.rs:3352` | TrustAsia Global Root CA G4 | `be4b56cb5056c0136a526df444508daa36a0b54f42e4ac38f72af470e479654c` |
| 90 | `src/lib.rs:3380` | e-Szigno Root CA 2017 | `beb00b30839b9bc32c32e4447905950641f26421b15ed089198b518ae2ea1b99` |
| 91 | `src/lib.rs:3408` | TWCA Root Certification Authority | `bfd88fe1101c41ae3e801bf8be56350ee9bad1a6b9bd515edc5c6d5b8711ac44` |
| 92 | `src/lib.rs:3442` | GDCA TrustAUTH R5 ROOT | `bfff8fd04433487d6a8aa60c1a29767a9fc2bbb05e420f713a13b992891d3893` |
| 93 | `src/lib.rs:3487` | TrustAsia TLS ECC Root CA | `c0076b9ef0531fb1a656d67c4ebe97cd5dbaa41ef44598acc2489878c92d8711` |
| 94 | `src/lib.rs:3514` | SSL.com TLS ECC Root CA 2022 | `c32ffd9f46f936d16c3673990959434b9ad60aafbb9e7cf33654f144cc1ba143` |
| 95 | `src/lib.rs:3541` | Microsoft RSA Root Certificate Authority 2017 | `c741f70f4b2a8d88bf2e71c14122ef53ef10eba0cfa5e64cfa20f418853073e0` |
| 96 | `src/lib.rs:3587` | Sectigo Public Server Authentication Root E46 | `c90f26f0fb1b4018b22227519b5ca2b53e2ca5b3be5cf18efe1bef47380c5383` |
| 97 | `src/lib.rs:3614` | DigiCert Global Root G2 | `cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f` |
| 98 | `src/lib.rs:3649` | GlobalSign | `cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b` |
| 99 | `src/lib.rs:3683` | GlobalSign Root E46 | `cbb9c44d84b8043e1050ea31a69f514955d7bfd2e2c6b49301019ad61d9f5058` |
| 100 | `src/lib.rs:3709` | Telia RSA TLS Root CA v3 | `d13db1294c45ebc6fc86c6bbf69fa29bdfe692dff7c713c243c7a956c6a2284c` |
| 101 | `src/lib.rs:3754` | UCA Extended Validation Root | `d43af9b35473755c9684fc06d7d8cb70ee5c28e773fb294eb41ee71722924d24` |
| 102 | `src/lib.rs:3798` | Certigna Root CA | `d48d3d23eedb50a459e55197601c27774b9d7b18c94d5a059511a10250b93168` |
| 103 | `src/lib.rs:3847` | GTS Root R1 | `d947432abde7b7fa90fc2e6b59101b1280e0e1c7e4e40fa3c6887fff57a7f4cf` |
| 104 | `src/lib.rs:3891` | HARICA TLS RSA Root CA 2021 | `d95d0e8eda79525bf9beb11b14d2100d3294985f0c62d9fabd9cd999eccb7b1d` |
| 105 | `src/lib.rs:3937` | TrustAsia Global Root CA G3 | `e0d3226aeb1163c2e48ff9be3b50b4c6431be7bb1eacc5c36b5d5ec509039a08` |
| 106 | `src/lib.rs:3983` | CA Disig Root R2 | `e23d4a036d7b70e9f595b1422079d2b91edfbb1fb651a0633eaa8a9dc5f80703` |
| 107 | `src/lib.rs:4027` | Amazon Root CA 4 | `e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092` |
| 108 | `src/lib.rs:4053` | D-TRUST BR Root CA 1 2020 | `e59aaa816009c22bff5b25bad37df306f049797c1f81d85ab089e657bd8f0044` |
| 109 | `src/lib.rs:4084` | Security Communication ECC RootCA1 | `e74fbda55bd564c473a36b441aa799c8a68e077440e8288b9fa1e50e4bbaca11` |
| 110 | `src/lib.rs:4111` | SecureSign Root CA15 | `e778f0f095fe843729cd1a0082179e5314a9c291442805e1fb1d8fb6b8886c3a` |
| 111 | `src/lib.rs:4138` | USERTrust RSA Certification Authority | `e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2` |
| 112 | `src/lib.rs:4185` | AC RAIZ FNMT-RCM | `ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab5573894179b93fa` |
| 113 | `src/lib.rs:4230` | Buypass Class 3 Root CA | `edf7ebbca27a2a384d387b7d4010c666e2edb4843e4c29b4ae1d5b9332e6b24d` |
| 114 | `src/lib.rs:4274` | D-TRUST Root Class 3 CA 2 EV 2009 | `eec5496b988ce98625b934092eec2908bed0b0f316c2d4730c84eaf1f3d34881` |
| 115 | `src/lib.rs:4312` | OISTE Server Root ECC G1 | `eec997c0c30f216f7e3b8b307d2bae42412d753fc8219dafd1520b2572850f49` |
| 116 | `src/lib.rs:4339` | Telekom Security TLS RSA Root 2023 | `efc65cadbb59adb6efe84da22311b35624b71b3b1ea0da8b6655174ec8978646` |
| 117 | `src/lib.rs:4385` | HiPKI Root CA - G1 | `f015ce3cc239bfef064be9f1d2c417e1a0264a0a94be1f0c8d121864eb6949cc` |
| 118 | `src/lib.rs:4429` | BJCA Global Root CA1 | `f3896f88fe7c0a882766a7fa6ad2749fb57a7f3e98fb769c1fa7b09c2c44d5ae` |
| 119 | `src/lib.rs:4474` | ANF Secure Server Root CA | `fb8fec759169b9106b1e511644c618c51304373f6c0643088d8beffd1b997599` |
| 120 | `src/lib.rs:4521` | T-TeleSec GlobalRoot Class 3 | `fd73dad31c644ff1b43bef0ccdda96710b9cd9875eca7e31707af3e96d522bbd` |
| 121 | `src/lib.rs:4557` | Certum Trusted Root CA | `fe7696573855773e37a95e7ad4d9cc96c30157c15d31765ba9b15704e1ae78fd` |
