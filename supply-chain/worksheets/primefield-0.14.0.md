# Review worksheet: `primefield` 0.14.0 (issue #339, Tier B batch B2)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.14.0"`). No concern-rule
  trigger.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.14.0 (locked) | `c555a6e4eb7d4e158fcb028c835c3b8642206ddc279b5c6b202ef9a8bdb592f4` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is byte-identical (`diff -r`) to the
`~/.cargo/registry/src` copy that was read. Reproduce the facts with
`scripts/vet-facts.sh primefield 0.14.0`.

## Method

- No prior audit of `primefield` exists in `audits.toml` or the imported sets, so **full**.
- `src/` is 2,501 lines. Every file was read in full: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (29), `src/error.rs` (18), `src/traits.rs` (39), `src/dev.rs` (190),
  `src/monty.rs` (1,090, of which `:999-1090` is `#[cfg(test)]`), `src/macros.rs` (808),
  `src/macros/fiat.rs` (327). The crate ships no `tests/`.
- **Macros.** Most of the crate is `#[macro_export]` macros that expand inside the
  calling crate, where this crate's `forbid(unsafe_code)` does not apply. Every macro
  body was read: `monty_field_params!` (`macros.rs:29-57`), `monty_field_element!`
  (`:102-619`), `monty_field_arithmetic!` (`:627-721`), `monty_field_reduce!`
  (`:726-747`), `field_op!` (`:752-781`), `monty_field_element_doc!` (`:787-808`),
  `fiat_monty_field_arithmetic!` (`fiat.rs:10-190`), `fiat_bernstein_yang_invert!`
  (`:195-274`), `test_fiat_monty_field_arithmetic!` (`:285-327`), and the test/bench
  macros in `dev.rs`. None contains `unsafe`, `asm!`, or a powerful import, so they inject
  none into their callers. In ACDP's graph, `p256` 0.14.0 expands `monty_field_params!`,
  `monty_field_element!`, `monty_field_element_doc!` and (in `#[cfg(test)]`)
  `test_primefield!` (`p256-0.14.0/src/arithmetic/{field,scalar}.rs`).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0, including all macro bodies. `#![forbid(unsafe_code)]` unconditional at `src/lib.rs:8`. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no |
| Powerful imports | none. `#![no_std]`, no `alloc`; `include_str!("../README.md")` is a doc string. `dev.rs` macros reference `::criterion` and `#[test]`; they compile only where a bench/test invokes them. |
| Binary content | none |
| Dependencies | `crypto-bigint` 0.7.5 (renamed `bigint`; `rand_core`, `hybrid-array`, `subtle`), `crypto-common` 0.2 (renamed `common`; `rand_core`), `ff` 0.14, `rand_core` 0.10, `subtle` 2.6 (`const-generics`), `zeroize` 1.7. All `default-features = false` except `common`. No `[features]` table. |
| Features ACDP enables | none (no features defined; root and py/node/wasm bindings identical). |
| Reached via | `p256` 0.14.0 (field and scalar types), `primeorder` 0.14.0, `wnaf` 0.14.1. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour (what was read)

- `MontyFieldElement::from_bytes` (`src/monty.rs:75-100`): copies the repr into a
  zero-padded `ByteArray` (`offset = len.saturating_sub(repr.len())`), decodes per the
  configured byte order, then `from_uint` (`:165-170`) range-checks against the modulus
  with `ct_lt` and returns a `CtOption`. `from_slice` (`:107-113`) length-checks with
  `Array::try_from`.
- `from_hex_vartime`, `from_u32`, `from_u64`, `const_invert` (`:125-202`, `:388-395`)
  `assert!`/`expect` on misuse; they are `const fn`s used for compile-time constants
  (`PrimeField` consts `:484-492`), so a violation is a compile error in the curve crate,
  not a runtime path.
- `Field::try_random` (`:440-449`): rejection sampling over `from_bytes`.
- Arithmetic (`:316-424`) and all `subtle`/`ctutils` impls (`:721-801`) forward to
  `crypto-bigint`'s `ConstMontyForm`. `Ord`/`PartialOrd` (`:964-979`) are variable-time
  comparisons of canonical values (documented trait semantics).
- `fiat_bernstein_yang_invert!` (`fiat.rs:195-274`): fixed-iteration safegcd loop over
  caller-supplied fiat-crypto functions on fixed-size arrays; `f[f.len() - 1]` on a
  `[_; nlimbs + 1]` array is in bounds.
- `monty_field_element!` emits `DefaultIsZeroes` (`macros.rs:617`) for the field type;
  zeroization writes `Default` (zero) over a fully initialized value, so zeroize 1.9.0's
  Z-1 (DECISIONS.md `322-zeroize`) is not triggered.

## Concerns

None.

## Not claimed

Cryptographic correctness (field arithmetic, constants, inversion), constant-time
behaviour, side-channel resistance. Arithmetic is delegated to `crypto-bigint` (Tier B,
still exempted).
