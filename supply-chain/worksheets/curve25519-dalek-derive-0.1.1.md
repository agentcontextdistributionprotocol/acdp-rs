# Review worksheet: `curve25519-dalek-derive` 0.1.1 (issue #339, Tier B batch B5)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.1.1"`). No concern-rule
  trigger.
  - This is a proc-macro that does token rewriting only, with no build-time I/O.
  - Its *output* contains `unsafe`. It wraps `#[target_feature]` functions in safe wrappers,
    which moves the "CPU supports the feature" precondition into the attribute name
    (`unsafe_target_feature`).
  - Each such wrapper is sound only if every call happens after runtime feature detection.
    For the one user in ACDP's graph, `curve25519-dalek` 5.0.0, that discharge was verified,
    and its own audit records it.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.1.1 (locked) | `f46882e17999c6cc590af592290432be3bce0428cb0d5f8b6715e4dc7b383eb3` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`.
Its sha256 matches. Its extracted tree is identical (`diff -r`) to the `~/.cargo/registry/src`
copy that was read, apart from Cargo's own `.cargo-ok` marker. Reproduce the facts with
`scripts/vet-facts.sh curve25519-dalek-derive 0.1.1`.

All four lockfiles lock 0.1.1 with the same checksum: the root and the py, node and wasm
bindings.

## Method

- No prior audit of `curve25519-dalek-derive` exists in `audits.toml` or the imported sets,
  so this is a **full** audit.
- `src/` is 466 lines in one file. Read in full:
  - `Cargo.toml` (and `.orig`)
  - `src/lib.rs` (466)
  - `README.md` (198), which documents the macro's contract
  - `tests/tests.rs` (148, test-only)
- The consumer side was read in `curve25519-dalek` 5.0.0:
  - the `Cargo.toml` target condition;
  - `build.rs`, the backend `cfg` selection at `:44-91`;
  - `src/backend.rs:30-75`, the `get_selected_backend` dispatch;
  - `src/lib.rs:87-92`, the backend module visibility;
  - the list of `#[unsafe_target_feature]` sites (grep).

## Facts

| Item | Finding |
|---|---|
| `unsafe` grep hits | 5, all inside `quote!` output templates, which is **generated** code, not code this crate runs: `src/lib.rs:428`, `:436`, `:446`, `:459`, `:460`. The macro itself runs no `unsafe` (full-source grep; the grep is the evidence). There is no `forbid`/`deny` attribute. Lints would be capped by `--cap-lints` for registry deps anyway. |
| asm / SIMD / intrinsics | none in this crate. It only emits `#[target_feature(enable = "...")]` attributes. |
| build.rs | none |
| proc-macro | **yes** (`proc-macro = true`). It exports two attribute macros, `#[unsafe_target_feature("...")]` (`:93-98`) and `#[unsafe_target_feature_specialize(...)]` (`:100-149`). |
| Build-time behaviour | Pure `syn` parse → AST rewrite → `quote!` (`syn` with `full`, `quote`, `proc-macro2`). No `std::{fs,net,process,env}`, `env!`, `include_bytes!`, no file reads, no environment reads, no `Command`. The only `include_str!` is the README doc (`:1`). Errors are emitted as `compile_error!` through `syn::Error::into_compile_error` (`:7-26`). |
| Dependencies | `proc-macro2` 1.0.66, `quote` 1.0.31, `syn` 2.0.27 (`full`). No dev deps. |
| Features ACDP enables | none (the crate defines none) |
| Where it is compiled | Only as a dependency of `curve25519-dalek` 5.0.0, under `[target.'cfg(all(not(curve25519_dalek_backend = "fiat"), not(curve25519_dalek_backend = "serial"), target_arch = "x86_64"))'.dependencies]` (`curve25519-dalek-5.0.0/Cargo.toml:157`). So it builds **only for x86_64 targets**. `cargo tree -i` finds it in root `--target all` and in py and node on `x86_64-unknown-linux-gnu`. It is **not** in the host aarch64 build, and **not** in `acdp-wasm` on `wasm32-unknown-unknown` (only in `--target all`, which includes x86_64). wasm32 builds use the serial u32 backend and never compile this macro or its output. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## What the macro generates

**`#[unsafe_target_feature("F")]` on a free `fn f(args) -> R { body }`** (`process_function`,
`:290-466`, the `outer == None` branch at `:451-464`) generates:

```rust
#[inline(always)] /* #[cfg(target_feature = "F")] only if the fn had #[test] */ /* doc/cfg/allow/deny/rustfmt::skip passed through */
vis fn f(args) -> R {
    #[target_feature(enable = "F")] /* #[inline] if the fn had #[inline] or #[inline(always)] */
    unsafe fn _impl_f(args) -> R { body }
    unsafe { _impl_f(args) }
}
```

**On an `impl` block** (`process_impl`, `:247-278`), every `fn` item is rewritten through the
`outer == Some(..)` branch (`:420-450`). The output is a safe method containing a local trait
`__Impl_f__` with an `unsafe fn _impl_f`, an impl of that trait for `Self` that carries the
`#[target_feature]`, and an `unsafe { <Self as __Impl_f__>::_impl_f(...) }` call. That is how
methods with `self` are supported.

**On a `mod`** (`process_mod`, `:166-245`), it applies the same rewrite to each direct `fn` or
`impl` item and leaves other items unchanged.

**`#[unsafe_target_feature_specialize("F1", "F2", conditional("F3", cfg_expr))]` on a `mod m`**
(`:100-149`):
- It emits one copy of the module per feature set, named `m_<features>`.
- Each copy has the rewrite above applied for that feature set.
- `conditional(...)` adds `#[cfg(cfg_expr)]` to that copy.
- Items tagged `#[for_target_feature("X")]` are kept only in copies whose feature set
  includes `X` (`:173-224`).

**Already-`unsafe fn`s** only gain `#[target_feature]` (`:295-301`), and their callers still
need `unsafe`. `const`, `async`, `extern` ABI, variadic and `default` fns, and unsafe impls,
are rejected (`:248-249`, `:255`, `:303-306`). Unknown attributes are also rejected (`:412`).

## The generated `unsafe`, and why it is sound in ACDP

- Calling a `#[target_feature]` function on a CPU without that feature is undefined
  behaviour.
- The generated safe wrapper calls `_impl_f` in `unsafe {}` and checks nothing at runtime. So
  **soundness of the expanded code depends entirely on the macro user calling the wrapper
  only when the feature is present.**
- The README (`:9`, `:23-30`, `:81-82`) documents this: the attribute "moves the `unsafe`
  from the function prototype into the macro name". Applying `#[unsafe_target_feature]` is
  therefore the user's `unsafe` assertion, much like writing `unsafe impl`.
- The macro does nothing else unsafe:
  - It passes the function body through verbatim.
  - It keeps argument types, generics and where-clauses (`:416-418`).
  - It turns `_` patterns into fresh identifiers (`:354-375`).
  - It does not change visibility.
- The single user in ACDP's graph, **`curve25519-dalek` 5.0.0**, discharges the obligation:
  - The vector backend that carries every `#[unsafe_target_feature]` /
    `unsafe_target_feature_specialize` site lives in `src/backend/vector/`
    (`avx2/{field,edwards}.rs`, `ifma/field.rs`, `packed_simd.rs`, `scalar_mul/*.rs`).
  - The `backend` module is `pub(crate)` outside docsrs (`src/lib.rs:87-92`), so no
    downstream crate can call a wrapper directly.
  - Every crate-internal entry point dispatches through `get_selected_backend()`
    (`src/backend.rs:55-75`). That function returns `Avx512` only when
    `cpufeatures::new!(cpuid_avx512, "avx512ifma", "avx512vl")` succeeds, and `Avx2` only when
    `cpufeatures::new!(cpuid_avx2, "avx2")` succeeds. Otherwise it returns `Serial`.
  - `build.rs` (`:44-91`) compiles the `simd` backend only on x86_64 with a 64-bit target,
    and `avx512` only when explicitly configured or statically enabled.
  - The existing `curve25519-dalek` 4.1.3 -> 5.0.0 audit (`audits.toml`, notes `unsafe:`
    line) records the same argument.
- **Test-only caveat:** `tests/tests.rs:146-147` calls the specialised
  `inner_spec_avx2::spec_function` wrapper with no feature check. That would be UB on a
  non-AVX2 CPU, and it illustrates the contract above. It is compiled only for this crate's
  own `cargo test` on x86/x86_64, never in any ACDP build.

## Concerns

None under the concern rule. The proc-macro does only codegen. The `unsafe` it emits is
explained, and in ACDP's only consumer it is guarded by runtime CPU detection.

## Not claimed

- Cryptographic correctness, constant-time behaviour and side-channel resistance.
- The correctness of `cpufeatures` detection. That is a separate Tier B crate, and this audit
  relies on it as `curve25519-dalek`'s audit does.
- The soundness of any other future user of this macro.
