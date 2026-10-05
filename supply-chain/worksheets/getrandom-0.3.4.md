# Review worksheet: `getrandom` 0.3.4 (issue #339, Tier B batch B7a)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.3.4"`), with three
  `Discretion:` lines: **GR3-1** and **GR3-2** (the same two `linux_raw` soundness bugs as
  0.4.3 GR4-1/GR4-2; DECISIONS.md `322-getrandom`) and **GR3-3** (tier-3 ESP-IDF FFI return
  type). 0.3.4 is a dev-only dependency of ACDP, so none of this code is in any ACDP
  artifact and the original Policy 6 carve-out already covers all three; the
  builder-only-opt-in limb is cited for consistency with 0.4.3. Every `unsafe` site,
  `unsafe fn` body, `asm!` block and `extern` block has a verdict below. All code selected
  by default on any stable tier-1/2 target is sound.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus)
  assistance. The 31 `src/` files were split into two partitions, each read line by line
  by a fresh Claude (Opus) sub-review: **G3-a** (core and the default backends:
  `lib.rs`, `error.rs`, `error_std_impls.rs`, `util.rs`, `util_libc.rs`, `lazy.rs`,
  `backends.rs`, `backends/{use_file,linux_android_with_fallback,sanitizer,getrandom,getentropy,windows,wasm_js}.rs`,
  `build.rs`, `Cargo.toml`) and **G3-b** (`backends/{custom,linux_raw,rdrand,rndr,efi_rng,windows_legacy,unsupported,esp_idf,fuchsia,hermit,netbsd,solaris,solid,vxworks,wasi_p1,wasi_p2,apple_other}.rs`,
  `tests/`, `benches/`). The main review then read every `unsafe` site and all 16
  `unsafe fn` definitions itself, cross-checked the partition counts against its own
  full-source grep, and read `build.rs` in full for the `rustc -vV` spawn.
  The `linux_raw` decision (C2) was escalated to a Claude (Fable) decision review, which
  verified the 0.3.4 line references as well (DECISIONS.md `322-getrandom`).
- **Date:** 2026-10-05
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)
- **Criteria note:** `config.toml` exempted 0.3.4 at `safe-to-run` because ACDP reaches it
  only as a dev-dependency. It is certified here at `safe-to-deploy` (the plan's G3
  choice): the review is the same full review given to 0.2.17 and 0.4.3, and the stronger
  criterion stays valid if a future dependency update moves 0.3.4 into a shipped graph.

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.3.4 (locked) | `899def5c37c4fd7b2664648c28120ecec138e4d395b459e5ca34f9cce2dd77fd` | `Cargo.lock` checksum (root l.1099-1102) |

Downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`; sha256
matches; the extracted tree is `diff -r`-identical to `~/.cargo/registry/src` apart from
`.cargo-ok`. Reproduce with `scripts/vet-facts.sh getrandom 0.3.4`. 0.3.4 is in the root
lockfile only; none of the three binding lockfiles contains it.

## Method

- No prior audit of any getrandom version exists locally, so **full**. Version diffs to
  0.4.3 (`diff -r` of `src/backends/`) were used only as a reading aid: most backends
  differ from 0.4.3 by edition-2021 forms and the absence of `extern_impl`.
- **Read scope:** all 31 `src/` files (2,445 lines), `build.rs` (57), `tests/mod.rs` (297),
  `benches/buffer.rs` (121), `Cargo.toml` and `Cargo.toml.orig`.
- **Edition 2021:** every `unsafe fn` body is wholly an unsafe context, so all 16
  definitions were read whole: 15 `unsafe fn` (13 names: `util.rs:10`, `:35`,
  `util_libc.rs:32`, `backends/sanitizer.rs:15`, `:50`, `backends/linux_raw.rs:10`,
  `backends/rndr.rs:24`, `:47`, `backends/rdrand.rs:31`, `:51`, `:106`, and the cfg-paired
  `rdrand_u32`/`rdrand_u64` at `:126`/`:132` (x86_64) and `:138`/`:144` (x86)) plus
  `backends/netbsd.rs:20` `unsafe extern "C" fn polyfill_using_kern_arand`. (The plan's
  Context table gives 15 `unsafe fn` and 10 `asm!` lines; the fresh grep gives 15 + the
  netbsd `unsafe extern "C" fn`, and 9 `asm!` blocks, the tenth "asm" grep hit being the
  module doc comment at `linux_raw.rs:1`.)
- **Grep cross-check:** `grep -rnw unsafe src tests benches build.rs` gives 98 lines (93 in
  `src/`, 4 in `benches/buffer.rs`, 1 in `tests/mod.rs:264`). `scripts/vet-facts.sh`
  reports 92 unsafe code lines (it excludes the doc line `util.rs:31`). The partition
  reports sum to the same set.
- **Mechanical `unsafe fn` check.** A copy of the tarball with `unsafe_op_in_unsafe_fn`,
  `missing_unsafe_on_extern` and `unsafe_attr_outside_unsafe` set to `deny` was built as a
  path dependency (scratch `lintdetail.sh`, which runs `cargo check --target <t>` with
  `RUSTFLAGS="--cfg getrandom_backend=..."` and collects every `error[...]` location)
  across the default arms of the installable targets and with every stable
  `--cfg getrandom_backend=` value on both linux-gnu triples, both apple-darwin triples
  and windows-msvc. Default-arm results: linux-gnu, musl, android, darwin, freebsd,
  illumos and netbsd hit only `util_libc.rs:32`; windows-msvc (x86_64 and i686) only
  `windows.rs:44`; fuchsia only `fuchsia.rs:8`; wasip1 only `wasi_p1.rs:10`; SGX the five
  `rdrand.rs` ops; wasip2 and `aarch64-apple-ios` build clean. `lintdetail.out` also holds
  non-lint errors from backend/target combinations that do not apply (the crate's own
  `compile_error!` at `linux_raw.rs:7`, `rdrand.rs:9`, `rndr.rs:13`/`:77`,
  `windows_legacy.rs:18`, and E0425/E0433 for `linux_getrandom` on darwin and Windows);
  those are not unsafe sites. Because the crate is edition 2021 the build fails by design; the hits
  are exactly the unsafe operations in `unsafe fn` bodies and the `extern` blocks without
  `unsafe`, and every lint hit maps to a row below:
  - `extern` blocks: `backends/custom.rs:9`, `backends/fuchsia.rs:8`,
    `backends/wasi_p1.rs:10`, `backends/windows_legacy.rs:23`, `backends/windows.rs:44`
    (also `util_libc.rs:18`, `lib.rs:103`, `backends/sanitizer.rs:18`, `hermit.rs:5`,
    `solid.rs:7` and `esp_idf.rs:7` under cfgs or targets not built, read directly).
  - unsafe ops in `unsafe fn` bodies: `util_libc.rs:32`, `backends/linux_raw.rs:42`
    (aarch64) and `:101` (x86_64), `backends/rdrand.rs:56`, `:111`, `:118`, `:127`,
    `:133`, `backends/rndr.rs:30`, `:50`, `:57`. The x86 (32-bit) `rdrand_u32`/`rdrand_u64`
    ops at `rdrand.rs:139`, `:145`, `:146` were not lint-built (no i686 rdrand run) and
    were read directly.
  - Other `unsafe fn` bodies (`util.rs:10`, `:35`, `sanitizer.rs:15`, `:50`) already wrap
    their operations in explicit blocks.
- **Compiled-set evidence from rustc dep-info:** scratch crate depending on
  `getrandom = "=0.3.4"` with feature `std` (ACDP's only feature for it), `cargo check
  --target <t>`, file list read from `target/<t>/debug/deps/getrandom-*.d`.
- **Empirical backing** (scratch crate, debug assertions on): `fill` and `fill_uninit` on
  every length 0..=4096, a 1 MiB + 7 buffer, `u32`/`u64`, and 16 concurrent first-use
  threads. aarch64-apple-darwin native: pass. Miri on `aarch64-apple-darwin`,
  `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`: pass, no UB reported. aarch64
  Linux (Docker `rust:1-slim`, rustc 1.99.0): pass, and with
  `--cfg getrandom_test_linux_fallback` (`/dev/random` poll plus `/dev/urandom`): pass.
- **Advisories:** `cargo deny check advisories`: ok on 2026-10-05.

## Facts

| Item | Finding |
|---|---|
| `unsafe` | 93 `src/` lines with the token (92 code lines per `vet-facts.sh`); 15 `unsafe fn` definitions (13 names; the rdrand_u32/u64 cfg pairs) plus netbsd's `unsafe extern "C" fn`; no `unsafe impl`. No `forbid(unsafe_code)`. |
| asm | 9 `asm!` blocks: `backends/linux_raw.rs` (7 per-arch syscall stubs, `:23`, `:42`, `:53`, `:63`, `:73`, `:86`, `:101`) and `backends/rndr.rs` (`:30`, `:92`). Neither is compiled for ACDP. |
| build.rs | 57 lines. (1) Reads `CARGO_CFG_SANITIZE` and emits `cfg(getrandom_msan)` if it contains `memory` (`:37-40`). (2) **On Windows targets only** (`CARGO_CFG_TARGET_FAMILY == "windows"`, `:44-45`) it spawns `$RUSTC_WRAPPER $RUSTC -vV` or `$RUSTC -vV` via `std::process::Command` (`:7-31`), parses the minor version from the first line, and emits `getrandom_backend="windows_legacy"` if it is below 78 (`:49-55`); on failure it prints a `cargo:warning`. No file writes, no network, no other environment reads. **Judgement:** this is cfg selection. The spawned program is the compiler Cargo already runs (or the user's own wrapper), with a fixed argument, and only its version line is used; it is the `rustc_version` pattern used widely. ACDP's MSRV is 1.86, so the `windows_legacy` branch is never taken in ACDP builds. |
| proc-macro | no |
| Powerful imports | `#![no_std]`; `extern crate std` under feature `std` (`error.rs:2`, `error_std_impls.rs:1`), in `efi_rng.rs:13` (nightly) and `rndr.rs:76` (feature detection). `std::process` only in `build.rs`. |
| Expected OS access | as 0.4.3: `/dev/urandom` and `/dev/random` (open/read/poll/close), futex wait/wake, `nanosleep`, `dlsym("getrandom")`, `getentropy`, `ProcessPrng` (raw-dylib), errno location. |
| Dependencies | `cfg-if` 1; `libc` 0.2.154+ (target-gated); `wasip2` 1 (wasm32-wasip2); `wasm-bindgen` 0.2.98 (feature `wasm_js`); `js-sys` (atomics only); `r-efi` 5 (uefi). |
| Features | `std`, `wasm_js`. ACDP: `std`. |
| `Cargo.toml` metadata | `[package.metadata.cross]` pre-build `curl`/`tar` commands (NetBSD sysroot), ignored by Cargo. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-05 |

## Reachability in ACDP

Dev-only. `cargo tree --locked --workspace --all-features -e features --target all -i
getrandom@0.3.4`: `rand_core` 0.9.5 (`os_rng`) <- `rand` 0.9.5 <- `proptest` 1.11.0, a
dev-dependency of `acdp` and `acdp-jcs`. `rand_core` 0.9.5 calls `getrandom::u32`,
`getrandom::u64` and `getrandom::fill` (`rand_core-0.9.5/src/os.rs:88-98`). It is compiled
for `cargo test` on CI's Linux, macOS and Windows runners and never shipped.

## Which code each build compiles

Command per row: `cargo check --target <t> --features std` in a scratch crate on
`getrandom = "=0.3.4"`, then the `src/*.rs` list from the dep-info file.

| Target | Compiled `src/` files | Backend |
|---|---|---|
| `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` (CI tests) | `lib.rs backends.rs error.rs error_std_impls.rs util.rs util_libc.rs backends/{linux_android_with_fallback,use_file,sanitizer}.rs` | libc `getrandom` via `dlsym`, `/dev/urandom` fallback |
| `x86_64-apple-darwin`, `aarch64-apple-darwin` (CI tests) | `lib.rs backends.rs error.rs error_std_impls.rs util.rs util_libc.rs backends/getentropy.rs` | `getentropy` |
| `x86_64-pc-windows-msvc` (CI tests) | `lib.rs backends.rs error.rs error_std_impls.rs util.rs backends/windows.rs` | `ProcessPrng` |
| `wasm32-unknown-unknown` | `compile_error!` without feature `wasm_js` | not built by ACDP |

## Backend matrix (reusable for delta audits)

`backends.rs`, first match wins. Same shape as 0.4.3 without `extern_impl`; the
`getrandom_backend="wasm_js"` arm (`:34-46`) is still present and requires feature
`wasm_js`, and on OS-less wasm32 the feature alone also selects it (`:188-192`).

| Selector | Backend | Stable? | ACDP | Verdict |
|---|---|---|---|---|
| `--cfg getrandom_backend="custom"` | `custom.rs` (built) | stable opt-in | no | sound given the contract |
| `="linux_getrandom"` | `getrandom.rs` (built: both linux-gnu) | stable opt-in | no | sound |
| `="linux_raw"` | `linux_raw.rs` (built: both linux-gnu, loongarch64-gnu, x32) | stable opt-in | no | arm/aarch64/riscv/s390x/x86/x86_64: sound; loongarch64: **GR3-1**; x32: **GR3-2** |
| `="rdrand"` / `="rndr"` | `rdrand.rs` / `rndr.rs` (built on x86_64 / aarch64) | stable opt-in | no | sound |
| `="efi_rng"` | `efi_rng.rs` | nightly (`lib.rs:13`) | no | sound given firmware contract |
| `="windows_legacy"` (also set by `build.rs` for rustc < 1.78) | `windows_legacy.rs` (built) | stable | no (MSRV 1.86) | sound |
| `="wasm_js"`, `="unsupported"` | `wasm_js.rs` (built with feature) / `unsupported.rs` (built) | stable | no | sound |
| linux `target_env=""` | `linux_raw.rs` | tier 3 | no | as above |
| espidf | `esp_idf.rs` | tier 3 | no | **GR3-3 (Discretion)** |
| haiku, redox, nto, aix | `use_file.rs` | tier 2/3 | no | sound |
| macos, openbsd, vita, emscripten | `getentropy.rs` (built) | stable | CI tests | sound |
| linux/android with fallback set (`:73-121`) | `linux_android_with_fallback.rs` + `use_file.rs` (built) | stable tier 1/2 | CI tests | sound |
| other linux/android, BSDs, illumos, hurd, cygwin, horizon | `getrandom.rs` (built: freebsd, illumos, loongarch64-gnu) | stable tier 2 | no | sound |
| solaris / netbsd / fuchsia / apple other | `solaris.rs` / `netbsd.rs` (built) / `fuchsia.rs` (built) / `apple_other.rs` (built) | stable tier 2 | no | sound |
| wasm32-wasi p1 / p2 | `wasi_p1.rs` (built) / `wasi_p2.rs` (built) | stable tier 2 | no | sound (GR3-O3) |
| hermit / vxworks / solid_asp3 / win7 | `hermit.rs` / `vxworks.rs` / `solid.rs` / `windows_legacy.rs` | tier 3 | no | sound |
| windows | `windows.rs` (built) | stable tier 1 | CI tests | sound (GR3-O1) |
| x86_64 SGX | `rdrand.rs` + `lazy.rs` (built) | stable tier 2 default | no | sound |

## `unsafe` / `asm!` sites and verdicts

Shorthand as in the 0.4.3 worksheet: **SLICE** (pointer and length from a live
`&mut [MaybeUninit<u8>]`), **INIT** (backends write only OS/JS/hardware output).

| Site | What | Argument | Verdict |
|---|---|---|---|
| `lib.rs:70` | `slice_as_uninit_mut(dest)` in `fill` | INIT holds for every backend | sound |
| `lib.rs:102-105` | `extern "C" { fn __msan_unpoison }` under msan | declared, never called (dead) | sound (GR3-O2) |
| `lib.rs:109` | `slice_assume_init_mut(dest)` in `fill_uninit` | empty, or `fill_inner` returned `Ok`, and every backend returns `Ok` only after writing every byte (Windows: per the documented `ProcessPrng` contract, GR3-O1) | sound |
| `error.rs:129`, `:136` | `new_unchecked(CUSTOM_START + n)` / `(INTERNAL_START + n)` | non-zero, no overflow | sound |
| `util.rs:10-14`, `:35-39` | `unsafe fn slice_assume_init_mut` / `slice_as_uninit_mut`, blocks `:13`, `:38` | same layout; caller contract | sound |
| `util.rs:18-19`, `:26` | zero-fill then assume-init (dead code); shared reborrow | as 0.4.3 | sound |
| `util.rs:56-63`, `:71-78` | byte view over a local `MaybeUninit<u32/u64>`; `assume_init` after `Ok` | in bounds, unique | sound |
| `util_libc.rs:16-21` | `extern "C" fn __errno()` (horizon, vita; tier 3) | newlib ABI | sound |
| `util_libc.rs:32`, `:38` | `unsafe fn get_errno`; body op: deref `errno_location()`; call | libc thread-local errno pointer | sound |
| `backends/sanitizer.rs:15-28` | `unsafe fn unpoison`; msan `extern "C"` + call in a block | no-op without msan | sound |
| `backends/sanitizer.rs:50-61` | `unsafe fn unpoison_linux_getrandom_result`: unpoisons `buf[..ret]` only when `ret >= 0` and in bounds | as 0.4.3 | sound |
| `backends/use_file.rs:49`, `:63`, `:142`, `:161`, `:175`, `:217`, `:231` | `read(fd, ptr, len)` (SLICE); `open(path, O_RDONLY\|O_CLOEXEC)` in `open_readonly(path: &[u8])`, whose NUL termination is enforced by `assert!(path.contains(&0))` (`:60-61`) and both paths are literals ending in `\0` (`FILE_PATH = b"/dev/urandom\0"` `:21`, `b"/dev/random\0"` `:208`); `nanosleep`, futex wait/wake on the aligned `&FD: AtomicI32`, `poll` on one `pollfd`, `close` | error-path and C-string-form differences from 0.4.3 (`last_os_error`, byte-string paths); the unsafe arguments are equivalent | sound (GR3-O4) |
| `backends/linux_android_with_fallback.rs:14`, `:18`, `:30`, `:35`, `:40`, `:43`, `:96-97` | fn-pointer type; `usize::MAX` `NonNull` sentinel; `dlsym(RTLD_DEFAULT, b"getrandom\0")` (`:28-30`, NUL-terminated literal); transmutes between `NonNull<c_void>` and the fn pointer only for non-null values (`:38-40`, `:87-96`); zero-length probe with a dangling pointer (`:43`); call with SLICE. The pointer is published in `GETRANDOM_FN: AtomicPtr` with Release (`:68`) and loaded with Acquire (`:86`) | sound | sound |
| `backends/getrandom.rs:28-35` | `libc::getrandom(ptr, len, 0)` then `unpoison_linux_getrandom_result` | SLICE | sound |
| `backends/getentropy.rs:21` | `getentropy(chunk, <= 256)` | SLICE | sound |
| `backends/windows.rs:32-46`, `:53` | raw-dylib `extern "system" ProcessPrng(*mut u8, usize) -> BOOL`; call | documented signature; see GR3-O1 for the result check | sound |
| `backends/wasm_js.rs:58-67` | `#[wasm_bindgen] extern "C"` `getRandomValues` import (`catch`) | generated wrapper; chunk-bounded view | sound (not in ACDP) |
| `backends/custom.rs:9-12` | `extern "Rust" fn __getrandom_v03_custom`; call | SLICE; same contract as 0.4.3 | sound given the contract |
| `backends/linux_raw.rs:10-118` | `unsafe fn getrandom_syscall`; body ops: one `asm!` per arch (no explicit block, edition 2021) | operand lists as 0.4.3 (`:23-34` arm, `:42-49` aarch64, `:53-60` loongarch64, `:63-70` riscv, `:73-80` s390x, `:86-94` x86, `:101-111` x86_64/x32); the `u32` syscall number and flags in 64-bit registers are harmless for the same reason given in the 0.4.3 worksheet | arm, aarch64 LP64, riscv, s390x, x86, x86_64: sound; loongarch64: **GR3-1**; x32 (and aarch64 ILP32, tier 3): **GR3-2** |
| `backends/linux_raw.rs:126-127` | call; `unpoison_linux_getrandom_result` | SLICE; over-long return caught by `get_mut` (`:131`) | sound (on the arches above) |
| `backends/rdrand.rs:31-48`, `:51-63` | `#[target_feature(enable="rdrand")] unsafe fn rdrand` (`rdrand_step` at `:34`, a safe call on the rustc 1.99 toolchain used here (target_feature 1.1: the function enables `rdrand`), so no lint hit; on older toolchains it is an unsafe op inside the `unsafe fn` body, equally sound), `self_test` (op `rdrand()` `:56`) | intrinsic in a function with the same feature | sound |
| `backends/rdrand.rs:70`, `:74`, `:101` | `__cpuid(0)`, `__cpuid(1)` (after `eax >= 1`), `self_test()` after the RDRAND/AMD checks | as 0.4.3 | sound |
| `backends/rdrand.rs:106-123`, `:126-149` | `unsafe fn rdrand_exact` (ops `:111`, `:118`), `rdrand_u32`/`rdrand_u64` (x86_64 ops `:127`, `:133`; x86 ops `:139`, `:145`, `:146`, the u64 built from two u32) | same feature; lengths match | sound |
| `backends/rdrand.rs:156`, `:165`, `:174` | calls after `RDRAND_GOOD` | gated | sound |
| `backends/rndr.rs:24-44`, `:47-61` | `unsafe fn rndr` (`asm!` `mrs RNDR` + `NZCV`, op `:30`), `rndr_fill` (ops `:50`, `:57`) | as 0.4.3 | sound |
| `backends/rndr.rs:91-97`, `:117`, `:127`, `:137` | `mrs ID_AA64ISAR0_EL1` (no_std Linux); calls after detection | as 0.4.3 | sound |
| `backends/efi_rng.rs:35`, `:57`, `:71`, `:78`, `:105` | UEFI `locate_handle`, `open_protocol`, `assume_init` on success, `get_rng` | nightly only; as 0.4.3 | sound (GR3-O5) |
| `backends/windows_legacy.rs:22-26`, `:37` | `SystemFunction036` `RtlGenRandom`; per-chunk call | documented signature | sound |
| `backends/netbsd.rs:20-41` | `unsafe extern "C" fn polyfill_using_kern_arand`; its only unsafe op is `sysctl(KERN_ARND)` in the explicit block at `:33`, with `len = min(buflen, 256)` and a result accepted only if `len <= 256` (`:36`) | MIB valid; kernel writes at most `len`; the `x86_64-unknown-netbsd` lint build has no hit here | sound |
| `backends/netbsd.rs:43-77` | fn-pointer type; `dlsym(RTLD_DEFAULT, b"getrandom\0")` (`:50-52`); the polyfill as fallback when null (`:53-56`), so `init` never returns null; `AtomicPtr` Release store (`:58`) / Acquire load (`:70`); `transmute::<*mut c_void, GetRandomFn>` of that non-null pointer (`:74`); call with SLICE (`:75-77`) | NetBSD 10 `getrandom` signature; differs from 0.4.3 (no `NonNull::new_unchecked`) but equivalent | sound |
| `backends/apple_other.rs:10`, `fuchsia.rs:8-14`, `hermit.rs:5-40`, `solaris.rs:29`, `solid.rs:7-13`, `vxworks.rs:18-43`, `wasi_p1.rs:10-25` | per-OS FFI | same code and arguments as the 0.4.3 rows | sound |
| `backends/wasi_p2.rs:19`, `:29`, `:41` | `align_to_mut::<MaybeUninit<u64>>()`; prefix/suffix `copy_nonoverlapping` from `wasip2::random::random::get_random_u64()` | as 0.4.3 `wasi_p2_3.rs` (GR3-O3) | sound |
| `backends/esp_idf.rs:7-9`, `:18` | `extern "C" fn esp_fill_random(...) -> u32` | C prototype returns `void`; see **GR3-3** | Discretion (tier 3) |
| `benches/buffer.rs:40`, `:42`, `:64`, `:66`; `tests/mod.rs:264` | bench byte views; test custom-backend definition | bench/test only | sound |

No `static mut`, no `unsafe impl`, no `#[macro_export]`.

## Fail-closed behaviour

Same as 0.4.3 for every backend ACDP compiles, with one difference: on Windows,
`ProcessPrng`'s return value is checked only by `debug_assert!` (GR3-O1).

## Findings

### GR3-1 (Discretion): loongarch64 `linux_raw` misses `$t0`-`$t8` clobbers

Same bug as 0.4.3 GR4-1 (full kernel, libc and codegen evidence in that worksheet).
`backends/linux_raw.rs:50-60`: `syscall 0` declares `in("$a7")`, `inlateout("$a0")`,
`in("$a1")`, `in("$a2")`, `options(nostack, preserves_flags)` and no clobbers, while the
kernel's `handle_syscall` returns `$t0`-`$t8` holding values loaded from `pt_regs` slots that
the syscall path never filled. In 0.3.4 the arm matches every `target_arch = "loongarch64"`
(no `target_abi` filter; `TODO(MSRV-1.78)` at `:51`). Sampled release codegen for
`loongarch64-unknown-linux-gnu` keeps the live values in a-registers (no miscompile
observed). Reachable only with the builder-set `--cfg getrandom_backend="linux_raw"`
(`backends.rs:18-21`), or by default for `target_env = ""` (`:50-53`), on targets ACDP never
builds. Not attacker-controllable. 0.3.4 reaches ACDP only as a dev-dependency, so this is in
no ACDP artifact.

### GR3-2 (Discretion): x32 / aarch64-ILP32 `linux_raw` leaves upper register bits undefined

Same bug as 0.4.3 GR4-2. The x86_64 arm (`backends/linux_raw.rs:95-111`; cfg is
`target_arch = "x86_64"` only, x32 syscall bit at `:97-99`) and the aarch64 arm (`:35-49`)
pass 32-bit `buf` and `buflen` in 64-bit input registers on x32/ILP32. The kernel's common
64-bit `sys_getrandom` reads the full `len`, so undefined upper bits could make it write past
the buffer before `fill_inner`'s `dest.get_mut(len..)` check (`:131`). Reachable only with
the builder-set cfg on `x86_64-unknown-linux-gnux32` (tier 2); aarch64 ILP32 is tier 3.
Dev-only in ACDP. The upstream report drafted in the 0.4.3 worksheet covers both versions.

### GR3-3 (Discretion, tier 3): ESP-IDF FFI return type

`backends/esp_idf.rs:7-9` declares `esp_fill_random(...) -> u32` for a C `void` function
(FFI UB; the value is discarded at `:18`). `target_os = "espidf"` only (`backends.rs:54-56`),
tier 3, needs `-Z build-std` (Policy 6 carve-out; plan rule 3).

### build.rs judgement (Policy 6 "build.rs that does more than cfg selection")

`build.rs` spawns `rustc -vV` (or `$RUSTC_WRAPPER $RUSTC -vV`) on Windows targets only, and
uses only the minor version, to choose between two backends. That is cfg selection: no
output except `cargo:` directives, no files, no network, and the spawned program is the
compiler Cargo already invokes. Not a concern.

## Other observations (non-blocking)

- **GR3-O1.** `backends/windows.rs:53-60` returns `Ok(())` without checking
  `ProcessPrng`'s result in release builds (`debug_assert!(result == TRUE)`), relying on
  Microsoft's documented guarantee that it always returns TRUE on Windows 10 and later
  (the minimum for Rust's tier-1 Windows targets). 0.4.3's own comment
  (`windows.rs:55-67`) notes that Windows 8 and Wine's implementation can fail, and 0.4.3
  checks the result (`:68-72`). If the contract were violated, `fill_uninit` would return
  uninitialized bytes behind `Ok`, and `u32()`/`u64()` would `assume_init` an unwritten
  local (`util.rs:53-63`, `:68-78`), which is UB. ACDP reaches 0.3.4 through `rand_core`
  0.9.5's `getrandom::u32`, `u64` and `fill` (`rand_core-0.9.5/src/os.rs:88-98`), only in
  dev/test builds. Not a concern:
  the code relies on a documented OS contract on supported Windows versions, as every
  backend relies on its OS API.
- **GR3-O2.** `lib.rs:102-105` declares `__msan_unpoison` and never calls it.
- **GR3-O3.** `wasi_p2.rs` relies on `align_to_mut` returning a prefix and suffix shorter
  than 8 (true for std's runtime implementation); see the 0.4.3 worksheet GR4-O3.
- **GR3-O4.** `use_file.rs` futex `debug_assert` can trip on `EINTR` in debug builds; a
  cached fd is never closed (by design).
- **GR3-O5.** `efi_rng.rs` caches the protocol pointer across `ExitBootServices`; nightly.
- `backends.rs:188-192` selects `wasm_js` by the feature alone, so the error text at
  `:194-200` that says the feature alone is insufficient is out of date (cosmetic).
- `linux_android_with_fallback.rs`: the `dlsym` result is assumed to have libc's
  `getrandom` signature, the same assumption libstd makes.

## Concerns

None. GR3-1 and GR3-2 are certified with `Discretion:` lines (DECISIONS.md `322-getrandom`;
dev-only, so covered by the original carve-out regardless of the maintainer's call on the
second limb). GR3-3 is a `Discretion:` line under the original carve-out.

## Not claimed

Soundness of the opt-in `linux_raw` backend on loongarch64 or on 32-bit-pointer
x86_64/aarch64 ABIs (GR3-1, GR3-2), RNG output quality or entropy, correctness of each OS's
RNG, the soundness of the wasm-bindgen glue, firmware, or user-supplied `custom` functions beyond their documented
contracts, cryptographic correctness, constant-time behaviour, side-channel resistance.
