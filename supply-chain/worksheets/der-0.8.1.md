# Review worksheet: `der` 0.8.1 (issue #339, Tier B batch B5)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.8.1"`). No concern-rule
  trigger.
  - There are 4 `unsafe` sites, all `#[repr(transparent)]` DST newtype reference casts, and
    all are sound.
  - Filesystem access exists only in documented, caller-initiated `Document` /
    `SecretDocument` file APIs, under `std`. Nothing on ACDP's dependency path calls them.
  - Two **safe-code non-termination bugs** were found and confirmed (D-1, D-2 below). They are
    not memory-safety issues, and they are unreachable from every ACDP artifact. Both are
    recorded as `Discretion:` lines and recommended for an upstream report.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.8.1 (locked) | `a69dedd701da44b0536442edf09c81a64b0ab97a7a4a5e3d1971f00027cbc63d` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`.
Its sha256 matches. Its extracted tree is identical (`diff -r`) to the `~/.cargo/registry/src`
copy that was read, apart from Cargo's own `.cargo-ok` marker. Reproduce the facts with
`scripts/vet-facts.sh der 0.8.1`.

All four lockfiles lock 0.8.1 with the same checksum: the root and the py, node and wasm
bindings.

## Method: exactly what was read

- No prior audit of `der` exists in `audits.toml` or the imported sets, so this is a **full**
  audit.
- `src/` is 14,534 lines in 55 files.
- **Read in full: the non-test code of all 55 `src/` files**, every line except `///` / `//!`
  doc-comment lines:
  - `lib.rs`, `bytes.rs`, `string.rs`, `datetime.rs`, `decode.rs`, `document.rs`,
    `encode.rs`, `encode_ref.rs`, `encoding_rules.rs`, `error.rs`, `header.rs`, `length.rs`,
    `length/indefinite.rs`, `ord.rs`, `reader.rs`, `reader/{pem,position,slice}.rs`,
    `referenced.rs`, `tag.rs`, `tag/{class,mode,number}.rs`, `writer.rs`,
    `writer/{pem,slice}.rs`;
  - `asn1.rs`, `asn1/{any,application,bit_string,bit_string/allowed_len_bit_string,bmp_string,boolean,choice,context_specific,general_string,generalized_time,ia5_string,integer,integer/int,integer/uint,internal_macros,null,octet_string,oid,optional,printable_string,private,real,sequence,sequence_of,set_of,teletex_string,utc_time,utf8_string,videotex_string}.rs`.
  - This includes the files behind features that are off in ACDP: `real.rs` (`real`),
    `length/indefinite.rs` (`ber`), `reader/pem.rs` / `writer/pem.rs` (`pem`), and the
    `heapless`, `arbitrary` and `time` blocks.
- **Doc comments** were skimmed, not read line by line. That covers the `src/lib.rs` crate
  docs (lines 1-306 are mostly `//!`) and the `///` item docs. Doc-test examples do not
  compile into the library.
- **In-file `#[cfg(test)]` unit-test modules** were read for most files. For the others they
  were checked by grep only, not read line by line: no `unsafe`, no `fs`, no `include_*`.
  - Those test modules sit at the end of the files: `asn1/{null,oid,printable_string,real,sequence_of,set_of,teletex_string,utc_time,utf8_string,videotex_string,ia5_string,integer/uint}.rs`, `datetime.rs`, `encoding_rules.rs`, `header.rs`, `length.rs`, `length/indefinite.rs`, `reader/{position,slice}.rs`, `tag.rs` and `writer/slice.rs`.
  - A script confirmed that no non-test item follows any column-0 `#[cfg(test)]` module.
- **`tests/`** (`datetime.rs` 59, `derive.rs` 1,257, `derive_no_alloc.rs` 170, `nesting.rs` 50,
  `pem.rs` 82, `set_of.rs` 68) was grep-checked: no `unsafe`. The only `include_*` is
  `tests/pem.rs:13`/`:16`, which loads the 44-byte `tests/examples/spki.der` and its PEM
  form. These are test-only and are not built into any non-test artifact.
- `Cargo.toml` (and `.orig`) were read. Note: `scripts/vet-facts.sh` reports "powerful-import
  hits: none" for this crate. Its pattern matches `std::fs` but not the brace import
  `use std::{fs, path::Path}` at `src/document.rs:11`, so the file I/O below was found by
  reading.
- **Empirical check (scratch crate, release build with debug assertions and overflow checks
  on):**
  - 300,000 random and semi-structured inputs were fed through 25 decoders, with no panic:
    `AnyRef`, `Any`, `&OctetStringRef`, `BitStringRef`, `IntRef`/`UintRef`/`Int`/`Uint`,
    `i64`/`u64`/`u128`, `ObjectIdentifier`, `Utf8StringRef`, `PrintableStringRef`,
    `Ia5StringRef`, `BmpString`, `UtcTime`, `GeneralizedTime`, `&SequenceRef`,
    `SetOfVec<u8>`, `Vec<AnyRef>`, `Null`, `Document`, `ContextSpecific<u8>` and
    `const_oid::ObjectIdentifierRef::from_bytes`.
  - Two targeted programs confirmed D-1 and D-2.
  - Miri was not run (it is not installed).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 4: `src/bytes.rs:29`, `src/string.rs:26`, `src/asn1/octet_string.rs:37`, `src/asn1/sequence.rs:55` (full-source grep, comment lines excluded; the grep is the evidence). `#![deny(unsafe_code)]` is at `src/lib.rs:8` (comment: "only allowed for casting newtype references"), and each site carries `#[allow(unsafe_code)]`. Lints are capped by `--cap-lints` for registry deps, so neither is relied on. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no. `der_derive` (the optional `derive` feature) is off and not in any ACDP graph. |
| Exported macros | none (`internal_macros.rs` macros are crate-private) |
| Powerful imports | **Filesystem, explicit API only (`std`, on in ACDP):** `use std::{fs, path::Path}` (`src/document.rs:11`). `Document::read_der_file` / `write_der_file` (`:119-131`) and `SecretDocument::read_der_file` / `write_der_file` (`:300-312`) read or write a caller-named path; `write_secret_file` creates it with mode 0o600 on unix (`:391-408`). The `read_pem_file` / `write_pem_file` variants need `pem`, which is off. **`std::io`:** `impl<W: io::Write> Writer for W` (`src/writer.rs:29-35`) and `From<io::Error>` (`src/error.rs:167-177`) do no I/O of their own. **Clock:** none. `SystemTime` is only converted from or to (`datetime.rs`, `utc_time.rs`, `generalized_time.rs`), never read with `now()`. No `std::{net,process,env}`, `env!`, `include_bytes!`. The only `include_str!` is the README doc. |
| Dependencies (optional) | `arbitrary`, `bytes`, `const-oid`, `der_derive`, `derive_arbitrary`, `flagset`, `heapless`, `pem-rfc7468`, `time`, `zeroize`. Dev: `hex-literal`, `proptest`. |
| Features ACDP enables | `alloc`, `oid`, `std` and `zeroize`, identical in every build: root `--all-features`, `acdp --no-default-features` on host and wasm32, and the py, node and wasm bindings. `ber`, `real`, `pem`, `derive`, `heapless`, `flagset`, `time`, `bytes` and `arbitrary` are off. |
| Reached via | `ecdsa` 0.17.0 (`der` feature), `sec1` 0.8.1 and `spki` 0.8.0 (`pkcs8` 0.11.0 also locks it). ACDP calls `der` directly nowhere (`grep -rn "der::" crates src tests bindings/*/src`: no hits). ACDP parses no DER: P-256 keys come in through `VerifyingKey::from_sec1_bytes` (`crates/acdp-crypto/src/verify.rs:59`, `crates/acdp-crypto/src/fingerprint.rs:28`, `crates/acdp-did/src/key.rs:150`), and signatures through fixed-size `Signature::from_slice` (`verify.rs:71`). |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## `unsafe` sites

All four have the same shape: `&*(ptr_to_inner as *const Self)`, where `Self` is
`#[repr(transparent)]` over a single unsized field.

1. **`src/bytes.rs:26-32`**, `BytesRef::new_unchecked(&[u8]) -> &BytesRef`, with
   `#[repr(transparent)] pub(crate) struct BytesRef([u8])` (`:8-10`).
2. **`src/string.rs:23-29`**, `StringRef::new_unchecked(&str) -> &StringRef`, with
   `#[repr(transparent)] pub struct StringRef(str)` (`:8-10`).
3. **`src/asn1/octet_string.rs:34-40`**, `OctetStringRef::from_bytes_ref(&BytesRef) -> &Self`,
   with `#[repr(transparent)] pub struct OctetStringRef { inner: BytesRef }` (`:14-17`).
4. **`src/asn1/sequence.rs:52-58`**, `SequenceRef::from_bytes_ref(&BytesRef) -> &Self`, with
   `#[repr(transparent)] pub struct SequenceRef { body: BytesRef }` (`:32-35`).

The argument is the same for all four, on every path from the safe API:

- **Layout and metadata:** `repr(transparent)` gives the wrapper the layout and pointer
  metadata (slice length) of its only field. The cast is between unsized pointees with the
  same metadata kind (`usize` length), so the fat pointer's length is kept.
- **Validity:**
  - The source is a live shared reference: non-null, aligned, and dereferenceable for its
    length.
  - In site 2 the source is a `&str`, so the UTF-8 validity that `str` requires holds for
    `StringRef(str)`. Every caller passes a real `&str`: `StringRef::new` (`:15-20`),
    `from_bytes` through the checked `str::from_utf8` (`:32-34`), and `StringOwned`'s
    `String` (`:173`, `:179`).
- **Provenance and lifetime:** the result is a shared reference derived from the input, so it
  is read-only. The signatures `fn(&'a X) -> &'a Self` tie the lifetime to the borrow.
- **The "unchecked" invariant is a library invariant, not a safety one.**
  `new_unchecked` skips only the `Length::new_usize` check (len <= `u32::MAX`). The only code
  that relies on it is `len()` (`src/bytes.rs:45-50`, `src/string.rs:47-52`): a
  `debug_assert!` plus `as u32`. A violation could only yield a wrong `Length`, which is
  logic and not UB.
- Every unchecked caller passes a length that is already bounded:
  - `EMPTY` (`&[]`);
  - `prefix` (a sub-slice of an already-checked `BytesRef`, `:58-65`);
  - `BytesOwned` / `StringOwned` (constructors checked, `:112`, `:197`, `:209`;
    `string.rs:74`, `:167`);
  - `AnyRef` default (`src/asn1/any.rs:36`).
- No other `unsafe` exists that could amplify a wrong length.

## Safe-code findings (not memory safety)

**D-1. Unbounded recursion in `ValueOrd` for `ContextSpecific` / `Application` / `Private`.**
`src/asn1/internal_macros.rs:276-286` (instantiated for `ContextSpecific`, `Application` and `Private` at `src/asn1/context_specific.rs:13`, `application.rs:13`, `private.rs:13`):

```rust
fn value_cmp(&self, other: &Self) -> Result<Ordering, Error> {
    match self.tag_mode {
        TagMode::Explicit => self.der_cmp(other),
        TagMode::Implicit => self.value_cmp(other),   // calls itself
    }
}
```

- The `Implicit` arm recurses unconditionally. The likely intent is
  `self.value.value_cmp(&other.value)`.
- The `Explicit` arm calls the blanket `DerOrd::der_cmp` (`src/ord.rs:34-53`). When the two
  headers are equal, that calls back into `value_cmp`, so comparing two explicit values with
  equal headers also never terminates.
- **Confirmed:** comparing two equal `ContextSpecific<u8>` values in debug builds ends in
  `thread 'main' has overflowed its stack` and abort (exit 134), for both modes. In release
  builds the `Implicit` case spins as an infinite loop (it was still running after 120 s and
  was killed), and the `Explicit` case overflows the stack.

**D-2. Unbounded recursion in `impl TryFrom<AnyRef<'_>> for bool`.** `src/asn1/boolean.rs:49-55`
has the body `any.try_into()`. The only `TryInto<bool>` is the blanket impl that calls
`bool::try_from(any)` again.
- **Confirmed:** `bool::try_from(AnyRef::from_der(&[0x01, 0x01, 0xff]))` overflows the stack
  in debug builds and hangs in release builds (killed by a 15 s alarm).
- The normal decode path (`bool::from_der` / `AnyRef::decode_as::<bool>`, through
  `DecodeValue`) is unaffected.

**Why they are not a concern-rule trigger, and are unreachable in ACDP:**
- Neither involves `unsafe`. On native targets a stack overflow hits the guard page and
  aborts, and the release-mode case is a hang. Both trigger on *any* input once the API is
  called, so they are not attacker-selected parsing paths.
- No ACDP crate calls `der` at all (see Facts). Of `der`'s dependents in ACDP's graph:
  - `sec1` 0.8.1 and `pkcs8` 0.11.0 construct and decode `ContextSpecific` fields but never
    compare them (no `value_cmp` / `der_cmp` / `SetOf` over them);
  - `spki` 0.8.0's `value_cmp` impls compare OIDs, parameters and bit strings, not
    context-specific values;
  - `ecdsa` 0.17.0 uses neither.

  This was checked with `grep -rnE "ContextSpecific|SetOf|der_cmp|value_cmp|bool::try_from"`
  over those four crates' `src/`.
- Recorded as `Discretion:` lines. **Recommendation:** report both upstream to
  RustCrypto/formats. This audit did not file the report.

**Other observations (hygiene, not vet concerns):**
- `impl<W: io::Write> Writer for W` (`src/writer.rs:30-35`) calls `io::Write::write` once
  and ignores a short write. That is a correctness issue for callers who use it; ACDP does
  not.
- `header.rs:118`'s `debug_assert_eq!(is_constructed, tag.is_constructed())` holds for every
  input. Universal tags are matched by exact byte in `Tag::decode_with_constructed_bit`
  (`src/tag.rs:276-328`), and an unknown or constructed universal byte is rejected. For the
  other classes, the flag is read from the same bit.
- Nesting depth is bounded at 64 (`src/reader/position.rs:20`, `:75-79`), so nested decoding
  cannot exhaust the stack.

## Concerns

None under the concern rule. D-1 and D-2 are recorded above as discretion items.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, and DER
canonicality or encoding correctness.
