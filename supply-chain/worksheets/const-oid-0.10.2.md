# Review worksheet: `const-oid` 0.10.2 (issue #339, Tier B batch B5)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.10.2"`). No concern-rule
  trigger. There is one `unsafe` site, a `#[repr(transparent)]` DST newtype cast, and it is
  sound.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.10.2 (locked) | `a6ef517f0926dd24a1582492c791b6a4818a4d94e789a334894aa15b0d12f55c` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`.
Its sha256 matches. Its extracted tree is identical (`diff -r`) to the `~/.cargo/registry/src`
copy that was read, apart from Cargo's own `.cargo-ok` marker. Reproduce the facts with
`scripts/vet-facts.sh const-oid 0.10.2`.

All four lockfiles lock 0.10.2 with the same checksum: the root and the py, node and wasm
bindings.

## Method

- No prior audit of `const-oid` exists in `audits.toml` or the imported sets, so this is a
  **full** audit.
- `src/` is 6,839 lines, of which `src/db/generated.rs` is 5,615. Every hand-written file was
  read in full:
  - `Cargo.toml` (and `.orig`)
  - `src/lib.rs` (399)
  - `src/arcs.rs` (180)
  - `src/buffer.rs` (52)
  - `src/checked.rs` (31)
  - `src/encoder.rs` (170)
  - `src/error.rs` (89)
  - `src/parser.rs` (131)
  - `src/traits.rs` (25)
  - `src/db.rs` (147)
- **`src/db/generated.rs` (5,615 lines)** is compiled only with the `db` feature, which is
  **off in every ACDP build**. It was checked mechanically by a script, not read line by line.
  The script found that every non-blank, non-comment line is one of three things:
  - a `pub mod` header or closing brace;
  - a `pub const NAME: crate::ObjectIdentifier = crate::ObjectIdentifier::new_unwrap("<digits and dots>");` item (1,492 `new_unwrap` calls in total);
  - a row of the `DB` tuple table that refers to those consts and string literals.

  These are compile-time constants with no functions, `unsafe`, macros or I/O.
- `tests/oid.rs` (289), `tests/oid_ref.rs` (71) and `tests/proptests.rs` (56) were inspected.
  They are test-only and use only `hex-literal`, `proptest` and `regex`, with no `unsafe` and
  no fs access.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 1: `src/lib.rs:320` (full-source grep, comment lines excluded; the grep is the evidence). `#![deny(unsafe_code)]` is at `src/lib.rs:9` with `#[allow(unsafe_code)]` at `:319`. Lints are capped by `--cap-lints` for registry deps, so neither is relied on. |
| asm / SIMD / intrinsics | none |
| build.rs | none |
| proc-macro | no |
| Exported macros | none |
| Powerful imports | none. `#![no_std]` (`src/lib.rs:1`). The only `include_str!` is the README doc. No `std::{fs,net,process,env}`, `env!`, `include_bytes!`. |
| Dependencies | optional `arbitrary` 1.4 (feature `arbitrary`, off). Dev: `hex-literal`, `proptest`, `regex`. |
| Features ACDP enables | none: the feature set is empty in every build (root `--all-features`, `acdp --no-default-features` on host and wasm32, and the py, node and wasm bindings). `db` and `arbitrary` are off. |
| Reached via | `der` 0.8.1 (feature `oid`; `src/asn1/oid.rs`) and `digest` 0.11.3 (feature `oid`). ACDP calls it directly nowhere (`grep -rn const_oid crates src tests bindings/*/src`: no hits). |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## `unsafe` site

**`src/lib.rs:315-323`**, `ObjectIdentifierRef::from_bytes_unchecked` (`pub(crate) const fn`):

```rust
unsafe { &*(ber as *const [u8] as *const ObjectIdentifierRef) }
```

with `#[repr(transparent)] pub struct ObjectIdentifierRef { ber: [u8] }` (`:294-300`).

- **Layout:** `repr(transparent)` over a single `[u8]` field guarantees the same layout and
  the same pointer metadata (the slice length). The `as` cast of the fat pointer keeps that
  length.
- **Validity, provenance and lifetime:**
  - The pointer comes from a live `&[u8]`, so it is non-null, aligned (`u8`) and
    dereferenceable for its length.
  - The result is only ever a shared reference, so no write is possible.
  - The signature `fn(&[u8]) -> &Self` ties the output lifetime to the input borrow.
- **Library invariant, not a safety invariant:** the bytes are supposed to be well-formed BER.
  - `from_bytes` (`:306-311`) validates through `Arcs::try_next` before casting.
  - The other caller, `ObjectIdentifier::as_oid_ref` (`:143-145`), passes a buffer built by
    the crate's own `Encoder` or by `TryFrom<&ObjectIdentifierRef>` (`:234`), whose
    source was already validated.
  - Malformed bytes could at worst reach the `expect("OID malformed")` in `Arcs::next`
    (`src/arcs.rs:119`). That is a panic, not UB. No other `unsafe` exists that could turn a
    broken BER invariant into memory unsafety.

## Behaviour (what was read)

- **Panics, all non-UB:**
  - `new_unwrap` (`:93`) and `Error::panic` (`src/error.rs:59-66`) panic on invalid input, by
    design, for `const` construction.
  - `Arcs::next` `expect` (`src/arcs.rs:119`).
  - `Buffer::as_bytes` uses `split_at(length)` (`src/buffer.rs:16`), which panics if
    `length > SIZE`. That cannot happen for buffers built by `Encoder`, because `encode_base128` checks
    `end_pos > MAX_SIZE` at `src/encoder.rs:100`.
- **Hygiene observation:** `Encoder::finish` stores `length: self.cursor as u8`
  (`src/encoder.rs:89`), which would truncate for a `MAX_SIZE > 255` instantiation. Every ACDP
  path uses the default `MAX_SIZE` of 39 (`src/lib.rs:48`). A truncated length gives a short
  slice through the checked `split_at`, which is a correctness issue and not memory
  unsafety.
- Parsing (`src/parser.rs`) and encoding (`src/encoder.rs`) are `const fn` code with
  checked/`checked_*` arithmetic (`src/checked.rs`) and bounds-checked indexing.

## Concerns

None.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, and the
correctness of the OID database names.
