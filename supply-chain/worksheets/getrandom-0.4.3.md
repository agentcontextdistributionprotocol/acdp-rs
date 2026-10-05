# Review worksheet: `getrandom` 0.4.3 (issue #339, Tier B batch B7a)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.4.3"`), with four
  `Discretion:` lines: **GR4-1** and **GR4-2** (two soundness bugs in the opt-in
  `linux_raw` backend, certified under the Policy 6 builder-only-opt-in limb proposed in
  DECISIONS.md `322-getrandom` and awaiting the maintainer's acknowledgement at PR review),
  **GR4-3** (nightly-only `extern_impl` backend) and
  **GR4-4** (tier-3 ESP-IDF FFI return type), both under the original Policy 6 carve-out.
  Every `unsafe` site, `unsafe fn` body, `asm!` block and `extern` block has a verdict
  below. All code selected by default on any stable tier-1/2 target is sound, and every
  backend ACDP compiles is sound.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus)
  assistance. The 35 `src/` files were split into two partitions, each read line by line
  by a fresh Claude (Opus) sub-review: **G1-a** (core and the backends ACDP compiles:
  `lib.rs`, `error.rs`, `error_std_impls.rs`, `util.rs`, `sys_rng.rs`, `utils/*`,
  `backends.rs`, `backends/{use_file,linux_android_with_fallback,getrandom,getentropy,windows,wasm_js}.rs`)
  and **G1-b** (`backends/{custom,extern_impl,linux_raw,rdrand,rndr,efi_rng,windows_legacy,unsupported,esp_idf,fuchsia,hermit,netbsd,solaris,solid,vxworks,wasi_p1,wasi_p2_3,apple_other}.rs`,
  `build.rs`, `tests/`, `benches/`, `Cargo.toml` and `.orig`). The main review then read
  every `unsafe` site and all 6 `unsafe fn` bodies itself, cross-checked the partition
  counts against its own full-source grep, and checked the linux_raw syscall clobbers
  against the Linux kernel source (finding GR4-1).
  The C2 decision on GR4-1/GR4-2 was escalated to a Claude (Fable) decision review, which
  re-verified the kernel, libc, Rust-reference and codegen facts independently (DECISIONS.md
  `322-getrandom`).
- **Date:** 2026-10-05
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.4.3 (locked) | `300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099` | `Cargo.lock` checksum (root l.1111-1114) |

Downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`; sha256
matches; the extracted tree is `diff -r`-identical to `~/.cargo/registry/src` apart from
`.cargo-ok`. Reproduce with `scripts/vet-facts.sh getrandom 0.4.3`. The root lockfile and
all three binding lockfiles lock 0.4.3 with this checksum.

## Method

- No prior audit of any getrandom version exists locally, so **full**. Version diffs to
  0.2.17/0.3.4 were used only as a reading aid.
- **Read scope:** all 35 `src/` files (2,582 lines), `build.rs` (11), `tests/mod.rs` (213),
  `tests/sys_rng.rs` (18), `benches/buffer.rs` (123), `Cargo.toml` and `Cargo.toml.orig`,
  and the custom-backend contract in `README.md` (included as the crate docs, `lib.rs:10`).
- **Edition 2024:** an `unsafe fn` body is not an unsafe context, but `unsafe_op_in_unsafe_fn`
  only warns and `--cap-lints allow` silences it for registry builds, so all 6 `unsafe fn`
  bodies (`util.rs:9`, `:33`, `utils/sanitizer.rs:15`, `backends/linux_raw.rs:12`,
  `backends/rndr.rs:24`, `:49`) were read whole.
- **Grep cross-check:** `grep -rnw unsafe src tests benches build.rs` gives 118 lines: 114
  in `src/` and 4 in `benches/buffer.rs` (`:42`, `:44`, `:66`, `:68`). Of the 114, 4 are
  comments in `backends/rdrand.rs` (`:31`, `:35`, `:37`, `:78`) and 1 is a doc comment in
  `util.rs:30`; `scripts/vet-facts.sh` reports 109 unsafe code lines. The partition reports
  (G1-a: 41 code hits; G1-b: 71 code lines, 75 with comments, plus 4 in benches) sum to the
  same set.
- **Mechanical `unsafe fn` check.** A copy of the tarball, with
  `unsafe_op_in_unsafe_fn = "deny"` added to its `[lints.rust]` (the edition-2024 copy
  already rejects `extern` blocks and `no_mangle` without `unsafe`), was built as a path
  dependency on the six artifact targets, on the installable tier-2 targets with a
  different default arm (`x86_64-fortanix-unknown-sgx`, `wasm32-wasip1`, `wasm32-wasip2`,
  `aarch64-linux-android`, `x86_64-unknown-{freebsd,netbsd,illumos,fuchsia,linux-musl}`,
  `aarch64-apple-ios`, `i686-pc-windows-msvc`), and with every stable
  `--cfg getrandom_backend=` value (`custom`, `linux_getrandom`, `linux_raw`, `rdrand`,
  `rndr`, `unsupported`, `windows_legacy`) on both linux-gnu triples, both apple-darwin
  triples and windows-msvc, plus `linux_raw` on `loongarch64-unknown-linux-gnu` and
  `x86_64-unknown-linux-gnux32`. **Every combination that builds at all builds clean**
  (the failures are the crate's own `compile_error!` for a backend/target mismatch, e.g.
  `rdrand` on aarch64, and `efi_rng`/`extern_impl`, which need nightly). For the cfgs
  built, every unsafe operation in an `unsafe fn` is in an explicit `unsafe {}` block. It
  proves nothing about `asm!` clobber lists (see GR4-1).
- **Compiled-set evidence from rustc dep-info:** scratch crate depending on
  `getrandom = "=0.4.3"`, `cargo check --target <t> --features <f>`, file list read from
  `target/<t>/debug/deps/getrandom-*.d`. Per-artifact features, from each artifact's own
  workspace (`cargo tree --locked -e features,normal --target <t> -i getrandom@0.4.3`): root
  and both wheel workspaces: `default, sys_rng` on all five native triples;
  `bindings/acdp-wasm` on `wasm32-unknown-unknown`: `default, sys_rng, wasm_js`. The
  unified root `cargo metadata` set (`std, sys_rng, wasm_js`) was also built; it adds only
  `error_std_impls.rs`. `bindings/acdp-wasm/.cargo/config.toml`'s
  `--cfg getrandom_backend="wasm_js"` is inert at 0.4.3 (no such arm in `backends.rs`).
- **Empirical backing** (scratch crate, debug assertions on): `fill` and `fill_uninit` on
  every length 0..=4096, a 1 MiB + 7 buffer, `u32`/`u64`, `UnwrapErr(SysRng)`
  (`next_u64`, `fill_bytes`), and 16 concurrent first-use threads; every byte of
  `fill_uninit`'s output read back.
  - aarch64-apple-darwin native: pass. Miri on `aarch64-apple-darwin`,
    `x86_64-unknown-linux-gnu` (dlsym + getrandom path) and `x86_64-pc-windows-msvc`
    (`ProcessPrng`): pass, no UB reported.
  - aarch64 Linux (Docker `rust:1-slim`, rustc 1.99.0): pass; also with
    `--cfg getrandom_test_linux_fallback`, which forces the `/dev/random` poll plus
    `/dev/urandom` read path: pass. Miri cannot run that path (`poll` is not shimmed),
    recorded as not run.
  - wasm32-unknown-unknown with `wasm_js` under Node v26.8.1 (`wasm-bindgen-test-runner`
    0.2.129, matching the lockfile): pass.
- **Advisories:** `cargo deny check advisories`: ok on 2026-10-05.

## Facts

| Item | Finding |
|---|---|
| `unsafe` | 114 `src/` lines with the token (109 code lines per `vet-facts.sh`); 6 `unsafe fn`; 4 bench lines; no `unsafe impl`. No `forbid(unsafe_code)`. |
| asm | 10 lines: `backends/linux_raw.rs` (7 per-arch syscall stubs, `:29`, `:52`, `:67`, `:79`, `:91`, `:106`, `:125`) and `backends/rndr.rs` (`:31`, `:95`). Neither file is compiled for any ACDP artifact. |
| build.rs | 11 lines: prints `rerun-if-changed`, reads `CARGO_CFG_SANITIZE`, emits `cfg(getrandom_msan)` if it contains `memory`. No process, file or network access. |
| proc-macro | no |
| Powerful imports | `#![no_std]`; `extern crate std` only under feature `std` (`error.rs:1-2`, `error_std_impls.rs:1`), in `efi_rng.rs:12` (nightly) and `rndr.rs:79` (`is_aarch64_feature_detected!`). No `std::{fs,net,process,env}` in `src/`. |
| Expected OS access | `open`/`read` of `/dev/urandom`, `open`/`poll`/`close` of `/dev/random`, futex wait/wake, `nanosleep` (`backends/use_file.rs:21-222`); `dlsym(RTLD_DEFAULT, "getrandom")` and the `getrandom` call (`linux_android_with_fallback.rs:24`, `:35`, `:83`); `getentropy` (`getentropy.rs:29`); `ProcessPrng` from `bcryptprimitives.dll` via raw-dylib (`windows.rs:30-51`); JS `globalThis.crypto.getRandomValues` (`wasm_js.rs:58-67`); errno via libc's errno location (`utils/get_errno.rs:28`). Raw syscalls via `asm!` only in the opt-in `linux_raw`. |
| Dependencies | `cfg-if` 1; `rand_core` 0.10 (feature `sys_rng`, audited in B4); `libc` 0.2.154+ (target-gated); `wasm-bindgen` 0.2.98+ (feature `wasm_js`, OS-less wasm); `js-sys` (wasm + `target_feature="atomics"` only, not ACDP); `r-efi` 6 (uefi + nightly `efi_rng` only). |
| Features | `std`, `sys_rng`, `wasm_js`. |
| `Cargo.toml` metadata | `[package.metadata.cross]` pre-build `curl`/`tar` commands for a NetBSD sysroot (`Cargo.toml:45-53`); read only by the `cross` tool in upstream CI, ignored by Cargo. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-05 |

## Which code each ACDP artifact compiles

Command per row: `cargo check --target <t> --features sys_rng[,wasm_js]` in a scratch crate
on `getrandom = "=0.4.3"`, then the `src/*.rs` list from
`target/<t>/debug/deps/getrandom-*.d`.

| Artifact / target | Features | Compiled `src/` files | Backend |
|---|---|---|---|
| root, CI, py/node wheels: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | `sys_rng` | `lib.rs backends.rs error.rs util.rs sys_rng.rs backends/linux_android_with_fallback.rs backends/use_file.rs utils/{get_errno,lazy_ptr,sanitizer,sys_fill_exact}.rs` | libc `getrandom` via `dlsym`, `/dev/urandom` fallback |
| root, CI macOS, wheels: `x86_64-apple-darwin`, `aarch64-apple-darwin` | `sys_rng` | `lib.rs backends.rs error.rs util.rs sys_rng.rs backends/getentropy.rs utils/get_errno.rs` | `getentropy` |
| CI / consumers: `x86_64-pc-windows-msvc` (also `i686-pc-windows-msvc`) | `sys_rng` | `lib.rs backends.rs error.rs util.rs sys_rng.rs backends/windows.rs` | `ProcessPrng` |
| `bindings/acdp-wasm`: `wasm32-unknown-unknown` | `sys_rng, wasm_js` | `lib.rs backends.rs error.rs util.rs sys_rng.rs backends/wasm_js.rs` | Web Crypto `getRandomValues` (non-atomics path) |

What ACDP calls: `acdp-crypto` draws Ed25519 and P-256 keys from
`rand_core::UnwrapErr(getrandom::SysRng)` (`crates/acdp-crypto/src/sign.rs:50-58`,
`:138-145`); `SysRng` (`sys_rng.rs:36-55`) forwards to `u32()`, `u64()` and `fill()`, and
`UnwrapErr` panics on any `Err`. `crypto-bigint`, `crypto-common` and `uuid` (v4 ids) also
reach `fill`.

## Backend matrix (reusable for delta audits)

Selector (`backends.rs`, first match wins) -> backend -> toolchain/tier -> ACDP artifact ->
verdict. "Built" = dep-info confirmed on that target.

| Selector | Backend | Stable? | In an ACDP artifact | Verdict |
|---|---|---|---|---|
| `--cfg getrandom_backend="custom"` (`:11-13`) | `custom.rs` (built on all five native triples) | stable opt-in | no | sound given the contract |
| `="linux_getrandom"` (`:14-16`) | `getrandom.rs` (built: both linux-gnu) | stable opt-in | no | sound |
| `="linux_raw"` (`:17-19`) | `linux_raw.rs` (built: both linux-gnu, loongarch64-gnu, x32) | stable opt-in | no | aarch64/arm/riscv/s390x/x86/x86_64: sound; loongarch64: **GR4-1**; x32: **GR4-2**; aarch64 ILP32: GR4-2 (tier 3) |
| `="rdrand"` (`:20-22`) | `rdrand.rs` (built: x86_64 linux, darwin, windows) | stable opt-in | no | sound |
| `="rndr"` (`:23-25`) | `rndr.rs` (built: aarch64 linux and darwin) | stable opt-in | no | sound |
| `="efi_rng"` (`:26-28`) | `efi_rng.rs` | **nightly** (`lib.rs:12`, `feature(uefi_std)`), uefi | no | sound given the firmware contract (read only) |
| `="windows_legacy"` (`:29-31`) | `windows_legacy.rs` (built: x86_64 msvc) | stable opt-in | no | sound |
| `="unsupported"` (`:32-34`) | `unsupported.rs` (built) | stable opt-in | no | sound (always `Err`) |
| `="extern_impl"` (`:35-37`) | `extern_impl.rs` | **nightly** (`lib.rs:13`, `feature(extern_item_impls)`) | no | **GR4-3 (Discretion)** |
| linux, `target_env=""` (`:38-40`) | `linux_raw.rs` | no ACDP target (all ACDP Linux targets are `gnu`) | no | as `linux_raw` above |
| espidf (`:41-43`) | `esp_idf.rs` | tier 3 | no | **GR4-4 (Discretion)** |
| haiku, redox, nto, aix (`:44-51`) | `use_file.rs` (no poll) | tier 2/3 | no | sound |
| macos, openbsd, vita, emscripten (`:52-59`) | `getentropy.rs` (built: both darwin) | stable | **yes** | sound |
| android {aarch64, arm, x86, x86_64}; linux {aarch64, arm, powerpc{,64}, s390x, x86, x86_64}; linux-musl except riscv (`:60-107`) | `linux_android_with_fallback.rs` + `use_file.rs` (built: both gnu, musl, android, x32) | stable tier 1/2 | **yes** | sound |
| other android/linux (e.g. riscv64, loongarch64), dragonfly, freebsd, hurd, illumos, cygwin, horizon-arm (`:108-121`) | `getrandom.rs` (built: freebsd, illumos, loongarch64-gnu) | stable tier 2 | no | sound |
| solaris / netbsd / fuchsia (`:122-130`) | `solaris.rs` / `netbsd.rs` (built) / `fuchsia.rs` (built) | stable tier 2 | no | sound |
| ios, visionos, watchos, tvos (`:131-138`) | `apple_other.rs` (built: aarch64-apple-ios) | stable tier 2 | no | sound |
| wasm32-wasi p1 / p2,p3 (`:139-148`) | `wasi_p1.rs` (built) / `wasi_p2_3.rs` (built: wasip2) | stable tier 2 default | no | sound (GR4-O3) |
| hermit / x86_64 motor / vxworks / solid_asp3 (`:149-160`) | `hermit.rs` / `rdrand.rs` / `vxworks.rs` / `solid.rs` | tier 3 | no | sound (read only) |
| windows, `target_vendor="win7"` (`:161-163`) | `windows_legacy.rs` | tier 3 | no | sound |
| windows (`:164-166`) | `windows.rs` (built: x86_64 and i686 msvc) | stable tier 1 | **yes** | sound |
| x86_64 SGX (`:167-169`) | `rdrand.rs` + `utils/lazy_bool.rs` (built: `x86_64-fortanix-unknown-sgx`) | stable tier 2 **default** | no | sound |
| OS-less wasm with feature `wasm_js` (`:170-183`) | `wasm_js.rs` (built) | stable | **yes** (acdp-wasm) | sound |

## `unsafe` / `asm!` sites and verdicts

Shorthand: **SLICE** = pointer and length come from a live `&mut [MaybeUninit<u8>]`, so the
callee may write at most `len` bytes into valid memory; **INIT** = the backend writes only
OS/JS/hardware output into `dest`, never uninitialized bytes (contract at
`backends.rs:3-8`).

| Site | What | Argument | Verdict |
|---|---|---|---|
| `lib.rs:91` | `slice_as_uninit_mut(dest)` in `fill` | INIT holds for every backend; the reference does not escape | sound |
| `lib.rs:123-126` | `unsafe extern "C" { fn __msan_unpoison }` under `cfg(getrandom_msan)` | declared, never called (dead); no unsafe op | sound (GR4-O1) |
| `lib.rs:130` | `slice_assume_init_mut(dest)` in `fill_uninit` | reached only for an empty `dest` or after `fill_inner` returned `Ok`, and every backend returns `Ok` only after writing every byte (see "Fail-closed") | sound, except under GR4-3 (nightly `extern_impl`) |
| `error.rs:156`, `:163` | `NonZero::new_unchecked(2^17 + n)` / `(2^16 + n)`, `n: u16` | non-zero, at most 196,607, fits `i32` and `usize` | sound |
| `util.rs:9-13` | `unsafe fn slice_assume_init_mut`; block `:12` (fat-pointer cast) | same layout; caller guarantees initialization | sound |
| `util.rs:16-18` | `write_bytes(0)` then `slice_assume_init_mut` (dead code, `allow(dead_code)`) | zeroes first | sound |
| `util.rs:22-25` | shared `&[T] -> &[MaybeUninit<T>]` | read-only | sound |
| `util.rs:33-37` | `unsafe fn slice_as_uninit_mut`; block `:36` | caller must not write uninit | sound |
| `util.rs:44-47`, `:59-62` | `from_raw_parts_mut` over a local `MaybeUninit<u32/u64>` as bytes | in bounds, align 1, unique | sound |
| `util.rs:51`, `:66` | `assume_init()` | only after `fill_uninit` returned `Ok` on a non-empty slice | sound |
| `utils/get_errno.rs:15-18` | `unsafe extern "C" { fn __errno() }` (horizon-arm, vita; tier 3) | newlib ABI | sound |
| `utils/get_errno.rs:28` | `ptr::read(errno_location())` | libc's thread-local errno pointer | sound |
| `utils/sanitizer.rs:15-27` | `unsafe fn unpoison`; under msan `unsafe extern "C" __msan_unpoison` + call `:23` | callers pass only the prefix the OS reported written; no-op without msan | sound |
| `utils/sys_fill_exact.rs:24` | `sanitizer::unpoison(l)` | `l` is exactly the `res` bytes just written (`split_at_mut_checked`) | sound |
| `backends/use_file.rs:49-51` | `libc::read(fd, ptr, len)` | SLICE; `fd` published Release / loaded Acquire | sound |
| `backends/use_file.rs:57` | `libc::open(c"…", O_RDONLY\|O_CLOEXEC)` | C-string literal | sound |
| `backends/use_file.rs:131-133` | `nanosleep` (non-Linux) | valid stack pointers | sound |
| `backends/use_file.rs:150`, `:164` | `syscall(SYS_futex, &FD, FUTEX_WAIT\|PRIVATE, FD_ONGOING_INIT, null)` / `FUTEX_WAKE` | `&FD` is an aligned 32-bit atomic; the kernel compares and sleeps atomically | sound |
| `backends/use_file.rs:206`, `:220` | `poll(&mut pfd, 1, -1)`, `close(fd)` | valid `pollfd`; closed on both paths | sound |
| `backends/linux_android_with_fallback.rs:13` | `unsafe extern "C" fn` pointer type | matches `ssize_t getrandom(void*, size_t, unsigned)` | sound |
| `backends/linux_android_with_fallback.rs:17` | `NonNull::new_unchecked(usize::MAX)` sentinel | non-zero; compared, never called | sound |
| `backends/linux_android_with_fallback.rs:24` | `dlsym(RTLD_DEFAULT, c"getrandom")` (non-musl) | C-string literal; the symbol's signature is the same assumption libstd makes | sound |
| `backends/linux_android_with_fallback.rs:28`, `:33`, `:81` | `transmute` fn pointer <-> `*mut c_void` | same size; non-null; `:81` only after the sentinel check `:77` | sound |
| `backends/linux_android_with_fallback.rs:35` | probe `getrandom_fn(dangling, 0, 0)` | length 0, nothing written | sound |
| `backends/linux_android_with_fallback.rs:82-84` | `getrandom_fn(ptr, len, 0)` | SLICE | sound |
| `backends/getrandom.rs:28-30` | `libc::getrandom(ptr, len, 0)` | SLICE | sound |
| `backends/getentropy.rs:29` | `libc::getentropy(chunk, len <= 256)` | SLICE | sound |
| `backends/windows.rs:30-44`, `:51` | `#[link(name="bcryptprimitives", kind="raw-dylib")] unsafe extern "system" fn ProcessPrng(*mut u8, usize) -> BOOL` (x86: `import_name_type="undecorated"`); call | matches the documented signature; result checked against `TRUE` (`:68-72`) | sound |
| `backends/wasm_js.rs:58-67` | `#[wasm_bindgen] unsafe extern "C"` import of `globalThis.crypto.getRandomValues` with `catch`, taking `&mut [MaybeUninit<u8>]` (non-atomics, ACDP's build) or `&js_sys::Uint8Array` (atomics) | safe wrapper generated by wasm-bindgen; JS writes initialized bytes into a view of the chunk, at most 65,536 bytes (`:14`, `:19`); soundness rests on the wasm-bindgen glue (exempted) and the host's `getRandomValues` | sound |
| `backends/custom.rs:9-12` | `unsafe extern "Rust" fn __getrandom_v03_custom(*mut u8, usize) -> Result<(), Error>`; call | SLICE; contract in README "Custom backend": defined once, `#[unsafe(no_mangle)] unsafe extern "Rust"`, buffer MAY be uninitialized, return `Ok(())` only after fully filling it | sound given the contract |
| `backends/extern_impl.rs:6-19` | `#[eii(fill_uninit)] pub(crate) fn fill_inner(...)` (bodiless, user-supplied **safe** fn) | see **GR4-3** | Discretion (nightly) |
| `backends/linux_raw.rs:12-143` | `unsafe fn getrandom_syscall`; body ops: one `asm!` per arch, each in its own `unsafe {}` | no `nomem`/`readonly` (correct: the kernel writes `buf`); `nostack` and `preserves_flags` correct (the trap does not touch the user stack; flags are restored on return) | per-arch rows below |
| `backends/linux_raw.rs:28-41` | arm eabi: save r7 in `tmp=out(reg)`, `svc 0` with nr 384, `inlateout("r0")`, `in r1/r2` | kernel preserves all but r0; r7 restored | sound |
| `backends/linux_raw.rs:51-60` | aarch64: `svc 0`, `in x8` 278, `inlateout x0`, `in x1/x2` | kernel preserves all but x0 | sound for LP64; ILP32 (tier 3): GR4-2 |
| `backends/linux_raw.rs:66-75` | loongarch64: `syscall 0`, `in $a7` 278, `inlateout $a0`, `in $a1/$a2` | **does not declare `$t0`-`$t8` clobbered**; see **GR4-1** | GR4-1 |
| `backends/linux_raw.rs:78-87` | riscv32/64: `ecall`, `in a7` 278, `inlateout a0`, `in a1/a2` | kernel preserves all but a0 | sound |
| `backends/linux_raw.rs:90-98` | s390x: `svc 0`, `in r1` 349, `inlateout r2`, `in r3/r4` | kernel preserves all but r2 | sound |
| `backends/linux_raw.rs:105-115` | x86: `int 0x80`, `in eax` 355, `in ebx/ecx/edx`, `lateout eax` | kernel preserves all but eax | sound |
| `backends/linux_raw.rs:124-136` | x86_64/x32: `syscall`, `in rax` 318 (+`0x40000000` on x32), `in rdi/rsi/rdx`, `lateout rax`, `lateout rcx`, `lateout r11` | kernel-clobbered rcx/r11 declared. The syscall number and `flags` are `u32` in 64-bit registers, so their upper 32 bits are unspecified; the kernel reads the number as `int` (`movslq %eax`, Linux >= 5.x) or masks and range-checks it as `unsigned long` (older kernels: out of range -> `-ENOSYS`, an `Err`), and `getrandom`'s `flags` is `unsigned int`, so neither can select another syscall or flag. Same reasoning for `x8`/`x2` on aarch64 (`el0_svc_common` takes `int scno`); on loongarch64, riscv64 and s390x the kernel range-checks the full register, so garbage would give `-ENOSYS`, an `Err`; every sampled build materialises the constants with zero-extending instructions. An observation, not a finding | sound for x86_64; x32: **GR4-2** |
| `backends/linux_raw.rs:151`, `:156` | call `getrandom_syscall(ptr, len, 0)`; `unpoison(l)` | SLICE; over-long return caught by `split_at_mut_checked`; EINTR retried; negative -> errno | sound (on the arches above) |
| `backends/rdrand.rs:39` | `rdrand_step(&mut val)` inside `#[target_feature(enable="rdrand")] fn rdrand` | intrinsic in a function with the same feature | sound |
| `backends/rdrand.rs:80`, `:85` | `__cpuid(0)`, `__cpuid(1)` | CPUID on every Rust x86 target; leaf 1 after `eax >= 1`; skipped under `target_feature="rdrand"` (SGX requires it, `:47-50`) | sound |
| `backends/rdrand.rs:112`, `:175`, `:184`, `:193` | `self_test()`, `rdrand_u32/u64()`, `rdrand_exact()` | after the CPUID bit-30 and AMD-family checks (`:87-108`) or static `rdrand`; then cached in `RDRAND_GOOD` | sound |
| `backends/rndr.rs:24-46` | `#[target_feature(enable="rand")] unsafe fn rndr`; body op: `asm!("mrs {x}, RNDR", "mrs {nzcv}, NZCV")`, two `out(reg)`, no options | conservative: no `preserves_flags` claimed, flags read in the same block | sound |
| `backends/rndr.rs:49-63` | `unsafe fn rndr_fill`; body ops: `rndr()` at `:52`, `:59` | same feature; `copy_from_slice` lengths match | sound |
| `backends/rndr.rs:94-99` | `asm!("mrs {id}, ID_AA64ISAR0_EL1")` (no_std Linux only) | Linux emulates this read at EL0 (>= 4.11); on older kernels a `SIGILL`, not UB | sound |
| `backends/rndr.rs:120`, `:130`, `:140` | `rndr()` / `rndr_fill()` | after `is_rndr_available()` | sound |
| `backends/efi_rng.rs:32`, `:54`, `:68`, `:75`, `:103` | `locate_handle` (16-handle buffer, size in bytes, bounds-checked `:47`), `open_protocol(GET_PROTOCOL)`, `assume_init` only on success then null-checked, `get_rng` probe, `get_rng(dest)` | UEFI firmware contract; nightly only | sound (GR4-O4) |
| `backends/windows_legacy.rs:22-26`, `:37` | `#[link(name="advapi32")]`, `link_name="SystemFunction036"` `RtlGenRandom(*mut c_void, u32) -> u8`; call per `i32::MAX` chunk | matches the documented signature; `!= TRUE` -> `Err` | sound |
| `backends/apple_other.rs:10` | `libc::CCRandomGenerateBytes(ptr, len)` | SLICE; checked against `kCCSuccess` | sound |
| `backends/esp_idf.rs:7-9`, `:18` | `unsafe extern "C" fn esp_fill_random(*mut c_void, usize) -> u32`; call | C prototype returns `void`; see **GR4-4** | Discretion (tier 3) |
| `backends/fuchsia.rs:7-10`, `:14` | `#[link(name="zircon")] zx_cprng_draw`; call | Zircon ABI; SLICE | sound |
| `backends/hermit.rs:5-13`, `:18-20`, `:29-31`, `:40` | three `extern "C"` decls; `MaybeUninit` + `assume_init` only on return 0; read loop with checked `get_mut` | Hermit kernel ABI | sound |
| `backends/netbsd.rs:19-40` | `unsafe extern "C" fn polyfill_using_kern_arand`; body op: `sysctl(KERN_ARND)` with `len <= 256` at `:32` | MIB valid; kernel writes at most `len` | sound |
| `backends/netbsd.rs:42`, `:47`, `:55`, `:66-69` | `unsafe extern "C" fn` pointer type `GetRandomFn`; `dlsym`, `new_unchecked` of a fn-pointer cast, `transmute` to `GetRandomFn`, call | fn pointers are non-null; NetBSD 10 signature | sound |
| `backends/solaris.rs:27`, `:35` | `libc::getrandom(ptr, len <= 1024, GRND_RANDOM)`; `ptr::read(___errno())` | SLICE; anything but a full chunk -> `Err` | sound |
| `backends/solid.rs:7-9`, `:13` | `extern "C" SOLID_RNG_SampleRandomBytes`; call | SOLID OS ABI | sound |
| `backends/vxworks.rs:15`, `:18-20`, `:40`, `:44` | `randSecure`, `usleep`, `randABytes` (`i32::MAX` chunks), `errnoGet` | VxWorks libc | sound |
| `backends/wasi_p1.rs:9-12`, `:25` | `#[link(wasm_import_module="wasi_snapshot_preview1")] random_get(i32, i32)`; call with pointer/length cast to `i32` | wasm32 only, so the casts are lossless | sound |
| `backends/wasi_p2_3.rs:17-29` | `unsafe extern "C"` with `safe fn get_random_u64() -> u64`, `link(wasm_import_module="wasi:random/random@0.2.0"/"0.3.0")` | takes no pointer, so `safe` is justified; rests on the WASI host | sound |
| `backends/wasi_p2_3.rs:44`, `:54-56`, `:66-68` | `align_to_mut::<MaybeUninit<u64>>()`; `copy_nonoverlapping` of `prefix.len()` / `suffix.len()` bytes from an 8-byte local | every bit pattern valid for `MaybeUninit`; in bounds because std's runtime `align_to` returns a prefix and suffix shorter than 8 (GR4-O3) | sound |
| `benches/buffer.rs:42`, `:44`, `:66`, `:68` | `from_raw_parts_mut` over `MaybeUninit<u32/u64>`; `assume_init` after `Ok` | bench only | sound |

No `static mut`, no `unsafe impl`, no `#[macro_export]`, no `include_bytes!` (only
`include_str!("../README.md")` for docs, `lib.rs:10`). Interior-mutable statics:
`use_file.rs:41` (`FD`), `linux_android_with_fallback.rs:74` (`LazyPtr`),
`rdrand.rs:119`, `rndr.rs:75` (`LazyBool`), `netbsd.rs:63`, `efi_rng.rs:98` (`LazyPtr`),
`vxworks.rs:11`. `LazyPtr`/`LazyBool` use `Relaxed`: they publish only the cached word, and
racing callers each compute the same value (`utils/lazy_ptr.rs:7-18`); `LazyPtr` never
caches an error.

## Fail-closed behaviour (observed, not claimed as RNG quality)

- `sys_fill_exact` (`utils/sys_fill_exact.rs:14-41`): advances only by a positive return
  that fits (`split_at_mut_checked`, else `UNEXPECTED`), retries EINTR, returns any other
  errno, and treats `0` or another negative value as `UNEXPECTED`.
- Linux (ACDP's linux artifacts): the probe (`linux_android_with_fallback.rs:21-61`) falls
  back to `/dev/urandom` only on a missing symbol, `ENOSYS`, or `EPERM` (Linux, seccomp);
  the fallback first polls `/dev/random` for readiness with no timeout
  (`use_file.rs:196-222`), so it cannot return pre-seed output; errors are not cached
  (`FD` returns to `FD_UNINIT`, `:90-95`).
- Darwin: any `getentropy` failure -> `Err` (`getentropy.rs:28-35`).
- Windows: `ProcessPrng` result other than `TRUE` -> `Err(UNEXPECTED)` (`windows.rs:68-72`);
  a missing DLL fails at load time (raw-dylib).
- wasm: a throwing or missing `getRandomValues` is caught by `catch` -> `Err(WEB_CRYPTO)`
  (`wasm_js.rs:19-23`, `:62`); never a partial `Ok`.
- `fill_uninit` never exposes `dest` on `Err`; under `UnwrapErr(SysRng)` any error panics,
  so ACDP never signs with a key drawn from failed or partial output.
- `esp_idf`, `fuchsia` and `wasi_p2_3` have no failure path (their APIs return nothing).

## Findings

### GR4-1 (Discretion, builder-only opt-in): loongarch64 `linux_raw` misses `$t0`-`$t8` clobbers

`backends/linux_raw.rs:61-75`: the `syscall 0` block declares `in("$a7")`,
`inlateout("$a0")`, `in("$a1")`, `in("$a2")`, `options(nostack, preserves_flags)` and no
clobbers. The Linux LoongArch syscall path does not preserve the temporaries:
`handle_syscall` (`arch/loongarch/kernel/entry.S:22-81`) overwrites t0-t2 at l.24-27 before
saving any state, never runs `SAVE_TEMP`, calls the C `do_syscall` (t0-t8 are caller-saved),
and returns through `RESTORE_ALL_AND_RET`, whose `RESTORE_TEMP` reloads t0-t8 from `pt_regs`
slots this path never wrote (`arch/loongarch/include/asm/stackframe.h:216-226`, `:269-274`).
glibc (`__SYSCALL_CLOBBERS`) and musl (`SYSCALL_CLOBBERLIST`) both declare `$t0`-`$t8`
clobbered. Under the `asm!` rules the block is UB whenever the compiler keeps a live value in
a t-register across it.

- Codegen: release builds of `fill` and `u64` for `loongarch64-unknown-linux-gnu` keep every
  live value in `$a1`/`$a3`/`$a4`/`$a7` across the `syscall` (no miscompile observed; this is
  register-allocator luck, not a guarantee, because `fill_inner` is `#[inline]`).
- The file cites rustix, but rustix has no loongarch64 `linux_raw` arch.
- Reachability: only when the final binary's builder sets
  `--cfg getrandom_backend="linux_raw"` (`backends.rs:17-19`) on
  `loongarch64-unknown-linux-{gnu,musl}` (tier 2, stable); no Cargo feature selects it and a
  library's cfg does not propagate (README "Opt-in backends"). The default ladder selects
  `linux_raw` only for `target_env=""` (`backends.rs:38-40`). No artifact ACDP builds or
  tests compiles this file. Not attacker-controllable: the inputs are the program's own
  `buf`/`len`/`flags`.
- Fix: declare `out("$t0") _` through `out("$t8") _`.

### GR4-2 (Discretion, builder-only opt-in): x32 / aarch64-ILP32 `linux_raw` leaves upper register bits undefined

`backends/linux_raw.rs:116-136`: the x86_64 arm also compiles for `target_abi="x32"`
(`target_pointer_width = "32"`, syscall number OR'd with `__X32_SYSCALL_BIT`, `:120-122`), and
the aarch64 arm (`:42-60`) for `target_abi="ilp32"`. There `buf` and `buflen` are 32-bit
values passed as `in("rdi")`/`in("rsi")` (`in("x0")`/`in("x1")`), and the Rust reference
leaves the upper bits of a register holding a narrower input undefined. On x32, `getrandom`
is a common 64-bit syscall entry with no compat wrapper: `sys_getrandom`
(`drivers/char/random.c`) reads the full 64-bit `len`, `import_ubuf` only rejects ranges
beyond `TASK_SIZE_MAX`, and there is no length cap, so garbage upper bits in `rsi` can make
the kernel write past the buffer before `fill_inner`'s length check (`:155`) runs; garbage in
`rdi` yields `EFAULT`.

- Codegen: on `x86_64-unknown-linux-gnux32`, `fill` passes the caller's incoming
  `%rdi`/`%rsi` to the first `syscall` without zero-extension (later iterations use
  zero-extending 32-bit ops). On x32 LLVM nearly always produces zero-extended 32-bit values,
  so the practical hit rate is low, but nothing guarantees it.
- rustix refuses x32 and arm64-ILP32 for this class of reason (`rustix` `build.rs:24-29`).
- Reachability: only the builder-set `--cfg getrandom_backend="linux_raw"` on
  `x86_64-unknown-linux-gnux32` (tier 2, stable, needs `CONFIG_X86_X32_ABI`); aarch64 ILP32
  targets are tier 3. Never in an ACDP-built or ACDP-tested artifact. Not
  attacker-controllable.
- On LP64 targets the same `u32` syscall number and `flags` in 64-bit registers are harmless
  (see the x86_64 row of the site table): the pointer and length are full width there.
- Fix: widen explicitly (`buf as usize as u64`, `buflen as u64`), or gate those arms on
  `target_pointer_width = "64"` with a `compile_error!` otherwise.

**Upstream report** (drafted, held for the maintainer's go-ahead per DECISIONS.md
`322-getrandom`; nothing related is open upstream, and master's `linux_raw.rs` is identical to
0.4.3): title "`linux_raw`: syscall `asm!` under-declares clobbers on loongarch64 ($t0-$t8)
and passes 32-bit `buf`/`len` in 64-bit registers on x32/ILP32", body as the two sections
above with the two proposed fixes. Both bugs date from the backend's introduction (#572,
0.3.0).

### GR4-3 (Discretion, nightly): `extern_impl` lets a safe function make `fill_uninit` expose uninitialized bytes

`backends/extern_impl.rs:6-7` declares `fill_inner` with `#[eii(fill_uninit)]`, so the
implementation is a user-written **safe** `fn(&mut [MaybeUninit<u8>]) -> Result<(), Error>`
(README "Externally implemented interface"). `lib.rs:130` then calls
`slice_assume_init_mut(dest)` on any `Ok`. A safe implementation that returns `Ok(())`
without writing every byte therefore lets safe code observe uninitialized memory through
`fill_uninit`'s `&mut [u8]`, which is UB caused by safe code (the `custom` backend avoids this
by making the user function `unsafe extern "Rust"`). The backend requires
`#![feature(extern_item_impls)]` (`lib.rs:13`), so it is unreachable in any
stable-toolchain build of any ACDP artifact (Policy 6 carve-out, `322-sha2` precedent; plan
rule 3).

### GR4-4 (Discretion, tier 3): ESP-IDF FFI return type

`backends/esp_idf.rs:7-9` declares `esp_fill_random(...) -> u32`; the ESP-IDF prototype
returns `void`. Calling through a mismatched declaration is UB under Rust's FFI rules (the
value is discarded at `:18`). Selected only for `target_os = "espidf"` (`backends.rs:41-43`),
whose targets are tier 3 and need `-Z build-std` (Policy 6 carve-out; plan rule 3). Same
declaration in 0.2.17 (GR2-1) and 0.3.4 (GR3-3).

## Other observations (non-blocking)

- **GR4-O1.** `lib.rs:123-126` declares `__msan_unpoison` and never calls it (the real call
  is in `utils/sanitizer.rs`); dead declaration.
- **GR4-O2.** `use_file.rs:152-158`: in a debug build, a `FUTEX_WAIT` interrupted by a
  signal without `SA_RESTART` returns `EINTR` and trips the `debug_assert`; release builds
  loop correctly. Linux fallback path only.
- **GR4-O3.** `wasi_p2_3.rs:44-68` relies on `align_to_mut` returning a prefix and suffix
  shorter than 8 bytes. The `align_to` docs permit returning everything in the prefix, but
  std's runtime implementation (via `align_offset`, which is exact at runtime) never does.
  Sound with the shipped std; the robust form is to copy `min(len, 8)` bytes. Default for
  `wasm32-wasip2` (stable tier 2); not an ACDP target.
- **GR4-O4.** `efi_rng.rs:98-100` caches the protocol pointer; using it after
  `ExitBootServices` would be a UEFI usage error. Nightly only.
- `solaris.rs:30-39`: a failing `getrandom` (-1) maps to `UNEXPECTED` rather than the errno
  (the `Ok(0)` arm can only see 0); still `Err`.
- `wasi_p1.rs:29`: `-code` overflows for `i32::MIN` (debug panic, release still `Err`);
  needs a hostile host.
- `utils/sanitizer.rs` unpoisoning and the `debug_assert`s in `use_file.rs` are the only
  debug-only paths; every `expect` in `error.rs`, `util.rs`, `wasm_js.rs`,
  `windows_legacy.rs` and `vxworks.rs` is guarded by a preceding check.

## Concerns

None. GR4-1 and GR4-2 would be concerns under the literal concern rule, because a stable
consumer build can reach them; they are certified under the Policy 6 builder-only-opt-in limb
recorded in DECISIONS.md `322-getrandom` (Fable decision; maintainer acknowledgement requested
at PR review). If the maintainer declines that limb, the fallback in that entry applies: 0.4.3
stays exempt with the single-version marker `allow-exempt:DECISIONS#322-getrandom@0.4.3`.
GR4-3 and GR4-4 are `Discretion:` lines under the original carve-out.

## Not claimed

Soundness of the opt-in `linux_raw` backend on loongarch64 or on 32-bit-pointer
x86_64/aarch64 ABIs (GR4-1, GR4-2), RNG output quality or entropy, correctness of each OS's RNG, the soundness of the
wasm-bindgen glue, firmware, or user-supplied `custom`/`extern_impl` functions beyond their
documented contracts, cryptographic correctness, constant-time behaviour, side-channel
resistance.
