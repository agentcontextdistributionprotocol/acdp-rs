# Review worksheet: `zeroize_derive` 1.5.0 (issue #339, Tier B batch B1)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "1.5.0"`). No concern-rule
  trigger: the proc-macro does pure token-to-token codegen.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 1.5.0 (locked) | `3c50655cbb0fe3fc43170059e702f1ce5e19b84cec58dc87b037a09935c2f328` | `Cargo.lock` checksum |

There is no prior audit of `zeroize_derive` (ours or imported), so there is no delta base.
The tarball was also downloaded from `static.crates.io` independently of
`scripts/vet-facts.sh`; its sha256 matches, and its extracted tree is identical to the
`~/.cargo/registry/src` copy that was read (only cargo's `.cargo-ok` marker differs).
Reproduce the facts with `scripts/vet-facts.sh zeroize_derive 1.5.0`.

## Method

- **Full** (no audited base). `src/lib.rs` is the only source file: 870 lines, of which
  `:425-870` is the `#[cfg(test)]` module.
- Read in full: `Cargo.toml`, `Cargo.toml.orig`, `src/lib.rs`.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0. `#![forbid(unsafe_code)]` at `src/lib.rs:4`, unconditional. The **generated** code contains no `unsafe` either (every `quote!` block was read: `:61-85`, `:105-119`, `:378-391`, `:419-422`). |
| asm / SIMD / intrinsics | none |
| build.rs | none |
| proc-macro | **yes** (`[lib] proc-macro = true`). Two derives: `Zeroize` (`:33-36`) and `ZeroizeOnDrop` (`:94-97`), helper attribute `zeroize`. |
| Proc-macro behaviour | Parses the `DeriveInput` with `syn`, reads only `#[zeroize(drop / bound = ".." / skip)]` attributes, collects generic type params used in non-skipped fields (`syn::visit`, `:142-163`), and emits impls with `quote!`. No `std::{fs,net,process,env}`, no `env!` / `option_env!` / `include_*!`, no `Command`, no `proc_macro::tracked_*`, no global or static state. It reads nothing outside its input token stream. Malformed input fails with `panic!` / `assert!` messages, which rustc reports as compile errors (`:204,226,235-315,336-339,348,401,405`). |
| Powerful imports | none |
| Binary content | none |
| Dependencies | `proc-macro2` 1, `quote` 1, `syn` 2 (`full`, `extra-traits`, `visit`); host-only. |
| Features ACDP enables | `default` (the crate has no features); pulled in by `zeroize`'s `derive` feature, which `acdp-crypto` enables (`crates/acdp-crypto/Cargo.toml:32`). Same in the py, node, and wasm bindings. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Generated code (what ends up in ACDP binaries)

- `#[derive(Zeroize)]` emits `impl ::zeroize::Zeroize for T { fn zeroize(&mut self) { match
  self { T { f1, f2, .. } => { f1.zeroize(); f2.zeroize() } _ => {} } } }`, skipping
  `#[zeroize(skip)]` fields and variants, with `T: Zeroize` bounds added for used type
  parameters unless `#[zeroize(bound = "..")]` overrides them (`:38-86`, `:328-392`). With
  the deprecated `#[zeroize(drop)]`, it also emits `impl Drop { fn drop(&mut self) {
  self.zeroize() } }` (`:60-71`).
- `#[derive(ZeroizeOnDrop)]` emits `impl Drop` that calls `field.zeroize_or_on_drop()` for
  each non-skipped field, plus the marker `impl ::zeroize::ZeroizeOnDrop for T {}`
  (`:99-120`, `:416-423`). `zeroize_or_on_drop` is resolved by autoref specialization over
  `zeroize::__internal::{AssertZeroize, AssertZeroizeOnDrop}`
  (`zeroize-1.9.0/src/lib.rs:828-850`): a no-op for a field that is itself `ZeroizeOnDrop`
  (it zeroizes in its own `Drop`), else `Zeroize::zeroize`. A field that is neither fails to
  compile.
- **ACDP's one use** is `#[derive(ZeroizeOnDrop)] pub struct SigningKey(DalekSigningKey)`
  (`crates/acdp-crypto/src/sign.rs:26-27`). `ed25519_dalek::SigningKey` is `ZeroizeOnDrop`, so
  the generated `Drop` is a no-op and erasure happens in ed25519-dalek's own `Drop` (audited).

## Interplay with `zeroize` 1.9.0 (still exempt, DECISIONS.md `322-zeroize`)

The generated code calls `zeroize`'s public traits only; it does not call
`optimization_barrier` directly. Whether a given `zeroize()` reaches Z-1's fallback depends on
`zeroize`'s own impls, which remain exempt and tracked under `322-zeroize`. This audit does not
cover `zeroize`.

## Concerns

None.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, and that
zeroization actually clears memory, which is `zeroize`'s job (exempt under `322-zeroize`).
