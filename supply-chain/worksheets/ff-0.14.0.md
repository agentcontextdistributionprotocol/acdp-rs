# Review worksheet: `ff` 0.14.0 (issue #339, Tier B batch B1)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.14.0"`). No concern-rule
  trigger.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.14.0 (locked) | `a1f686ab92a9fb0eaf188f6c6c87b89490baa6fdb0db4544ba4dc47f7942489f` | `Cargo.lock` checksum |

There is no prior audit of `ff` (ours or imported), so there is no delta base. The tarball
was also downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`; its
sha256 matches, and its extracted tree is identical to the `~/.cargo/registry/src` copy that
was read (only cargo's `.cargo-ok` marker differs). Reproduce the facts with
`scripts/vet-facts.sh ff 0.14.0`.

## Method

- **Full** (no audited base). `src/` is 771 lines.
- Read in full: `Cargo.toml`, `Cargo.toml.orig`, `rust-toolchain.toml`, `src/lib.rs` (512),
  `src/batch.rs` (131), `src/helpers.rs` (128).
- Skimmed: `tests/derive.rs` (161; integration test, needs the `derive` feature),
  `.github/workflows/ci.yml` (upstream CI config, not built).
- The `ff_derive` proc-macro is an optional dependency (`derive` feature). It is **not in
  ACDP's `Cargo.lock`** (nor in any binding lock), so it was not reviewed and is not covered
  by this audit's reasoning about ACDP builds.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 sites (full-source grep; forbid is capped by --cap-lints for registry deps, so the grep is the evidence). `#![forbid(unsafe_code)]` is at `src/lib.rs:7`. |
| asm / SIMD / intrinsics | none |
| build.rs | none |
| proc-macro | no (the optional `ff_derive` dependency is one; off in ACDP and absent from the lock) |
| Powerful imports | none. `#![no_std]` (`src/lib.rs:3`); `extern crate alloc` only under `alloc` (`:9-10`). No `std::{fs,net,process,env}`, `env!`, `option_env!`, `include_*!`. |
| Binary content | none |
| Dependencies | `rand_core` 0.10 and `subtle` 2.2.1 (`i128`), both `default-features = false`; optional `bitvec` 1, `byteorder` 1, `ff_derive` 0.14. Dev: `blake2b_simd`, `getrandom`. |
| Features ACDP enables | `alloc` only (root `--all-features` and the py, node, wasm bindings, from `cargo tree -e features`). `bits`/`bitvec`, `derive`, `std` are off; `bitvec` and `ff_derive` are not in `Cargo.lock`. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## What the code does

- `src/lib.rs`: the `Field`, `PrimeField`, `WithSmallOrderMulGroup`, `FromUniformBytes`, and
  (under `bits`) `PrimeFieldBits` trait definitions. Default methods: `random` (wraps
  `try_random` with an irrefutable `let Ok`, `:82-85`), `is_zero`, `cube`, `sqrt_alt`,
  `sqrt`, `pow` (square-and-multiply with `conditional_assign`, `:171-182`), `pow_vartime`
  (`:192-205`), `from_str_vartime` (decimal parse, `:220-256`), `from_u128` (`:268-276`).
  Under `derive`, `arith_impl` has `const fn` `sbb`/`adc`/`mac` on `u128` (`:491-512`).
- `src/batch.rs`: Montgomery batch inversion. `BatchInvert` collects into a `Vec` (`alloc`);
  `BatchInverter::invert_with_external_scratch` asserts equal lengths (`:75`). Both call
  `acc.invert().unwrap()` (`:42,82,118`); since zero elements are skipped by
  `conditional_select`, `acc` is a product of non-zero elements and the unwrap cannot fail
  for a correct `Field` impl.
- `src/helpers.rs`: generic `sqrt_tonelli_shanks` and `sqrt_ratio_generic`. The latter has an
  `assert!` on the square / non-square invariant (`:120-122`) and a `CtOption::unwrap`
  (`:126`); these are panics on a broken `Field` impl, not memory hazards.
- Everything is safe Rust over caller-provided types; no global state, no I/O.

**ACDP use.** Trait vocabulary for `elliptic-curve`, `group`, `primefield`, `primeorder`,
`p256`, and `wnaf` (the P-256 field and scalar types implement `Field` / `PrimeField`). ACDP
does not call `ff` directly.

## Observations (not vet concerns)

- `sqrt_tonelli_shanks` (`src/helpers.rs:18-64`) is not called anywhere in ACDP's P-256
  stack (grep of `p256`, `primefield`, `primeorder`, `elliptic-curve`, `group`).
  `sqrt_ratio_generic` is: `p256-0.14.0/src/arithmetic/scalar.rs:277`,
  `primefield-0.14.0/src/monty.rs:472`, and the `primefield` macro (`macros.rs:313`). It calls
  the type's own `sqrt`, and its only panics (`:120-122`, `:126`) fire when the
  square / non-square invariant of a `Field` impl is broken. Timing is out of scope.

## Concerns

None.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance. Correctness of
any `Field` / `PrimeField` implementation belongs to the implementing crate.
