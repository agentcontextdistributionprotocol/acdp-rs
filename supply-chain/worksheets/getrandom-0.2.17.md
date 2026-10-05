# Review worksheet: `getrandom` 0.2.17 (issue #339, Tier B batch B7a)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.2.17"`), with one
  `Discretion:` line for finding **GR2-1** (the ESP-IDF backend declares a C `void`
  function as returning `u32`; ESP-IDF targets are tier 3, so this is the Policy 6 /
  `322-sha2` carve-out). Every `unsafe` site, every `unsafe fn` body, every `extern`
  block and every macro-generated FFI import has a verdict below. All sites compiled for a
  stable tier-1/2 target are sound.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus)
  assistance. The 24 `src/` files were split into two partitions, each read line by line
  by a fresh Claude (Opus) sub-review: **G2-a** (core and the backends ACDP compiles:
  `lib.rs`, `error.rs`, `error_impls.rs`, `util.rs`, `util_libc.rs`, `lazy.rs`,
  `linux_android_with_fallback.rs`, `linux_android.rs`, `use_file.rs`, `getentropy.rs`,
  `apple-other.rs`, `windows.rs`, `js.rs`, `Cargo.toml`, plus `ring-0.17.14/src/rand.rs`
  for the call path) and **G2-b** (`custom.rs`, `rdrand.rs`, `espidf.rs`, `fuchsia.rs`,
  `getrandom.rs`, `hermit.rs`, `netbsd.rs`, `solaris.rs`, `solid.rs`, `vxworks.rs`,
  `wasi.rs`, `tests/`, `benches/`). The main review then read every `unsafe` site and all
  11 `unsafe fn` bodies itself and cross-checked the partition counts against its own
  full-source grep (below).
- **Date:** 2026-10-05
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.2.17 (locked) | `ff2abc00be7fca6ebc474524697ae276ad847ad0a6b3faa4bcb027e9a4614ad0` | `Cargo.lock` checksum (root l.1086-1089) |

Downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`; sha256
matches; the extracted tree is `diff -r`-identical to `~/.cargo/registry/src` apart from
`.cargo-ok`. Reproduce with `scripts/vet-facts.sh getrandom 0.2.17`. The root lockfile and
all three binding lockfiles (`bindings/acdp-{py,node,wasm}/Cargo.lock`) lock 0.2.17 with
this checksum.

## Method

- No prior audit of any getrandom version exists locally (`audits.toml`, `imports.lock`),
  so **full**. Version diffs to 0.3.4/0.4.3 were not used as an audit base.
- **Read scope:** all 24 `src/` files (1,739 lines), `Cargo.toml`, `tests/common/mod.rs`,
  `tests/{custom,normal,rdrand}.rs` and `benches/buffer.rs` (258 lines), read in full.
  There is no `build.rs`. Edition 2018, so every `unsafe fn` body is wholly an unsafe
  context; all 11 were read whole and each unsafe operation inside them has a row.
- **Grep cross-check:** `grep -rnw unsafe src tests benches` gives 59 lines (58 in `src/`,
  1 in `tests/rdrand.rs:19`). One of the 58 is a comment (`util_libc.rs:99`) and one is a
  doc line (`util.rs:29`). `scripts/vet-facts.sh` reports 56 unsafe code lines (58 minus the two
  comment lines). The partition reports (G2-a: 32 code tokens plus 2 comments; G2-b: 24 plus 1 in
  tests) sum to the same set.
- **Mechanical `unsafe fn` check.** A copy of the tarball was built as a path dependency
  with `unsafe_op_in_unsafe_fn`, `missing_unsafe_on_extern` and
  `unsafe_attr_outside_unsafe` set to `deny` in its `[lints.rust]`, across the matrix in
  "Which code each ACDP artifact compiles" (every target, plus features `custom`, `rdrand`,
  `custom,rdrand`, `linux_disable_fallback` and all four together on both linux-gnu and
  both apple-darwin triples and windows-msvc). Because the crate is edition 2018, the build
  fails by design; its value is the list of hits, which is exactly the set of unsafe
  operations inside `unsafe fn` bodies and `extern` blocks without `unsafe`, for the cfgs
  built. Every hit maps to a row below:
  - `extern` blocks: `apple-other.rs:7`, `custom.rs:91`, `fuchsia.rs:6`, `windows.rs:8`,
    `windows.rs:20`.
  - unsafe ops in `unsafe fn` bodies: `util.rs:10`, `util.rs:34`, `util_libc.rs:39`
    (errno-location call and deref), `util_libc.rs:139` (`libc::open`), `use_file.rs:103`,
    `use_file.rs:107`, `rdrand.rs:46`, `rdrand.rs:110`, `rdrand.rs:117`.
  - Built by the lint matrix with no further hits beyond the list above: `netbsd.rs`
    (`x86_64-unknown-netbsd`), `getrandom.rs` (freebsd, illumos), `apple-other.rs` (ios),
    `fuchsia.rs`, `wasi.rs`, `js.rs`, `windows.rs`.
  - Not built (tier 3, or no installable target), read in full: `espidf.rs`, `hermit.rs`,
    `solid.rs`, `vxworks.rs`, `solaris.rs` (stable tier 2, but no target installed here), the
    `util_libc.rs:25` horizon/vita `extern` block, and `custom.rs:74` (the macro body,
    expanded in a user crate).
- **Compiled-set evidence from rustc dep-info**, not from reading `cfg`s: a scratch crate
  depending on `getrandom = "=0.2.17"` was `cargo check`ed per target and per feature set,
  and the `src/*.rs` list was read from `target/<t>/debug/deps/getrandom-*.d`.
  Per-artifact features came from each artifact's own workspace:
  `cargo tree --locked -e features,normal --target <t> -i getrandom@0.2.17` (root: only
  `default`, via `ring`; `bindings/acdp-wasm` on `wasm32-unknown-unknown`: `js`;
  `bindings/acdp-py` and `acdp-node`: "nothing to print" on all four wheel triples).
- **Empirical backing** (scratch crate, debug assertions on): `getrandom` and
  `getrandom_uninit` on every length 0..=4096, a 1 MiB + 7 buffer, and 16 concurrent
  first-use threads; every byte of `getrandom_uninit`'s output read back.
  - aarch64-apple-darwin native: pass. Miri (nightly, `cargo miri test`) on
    `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`: pass,
    no UB reported (Miri shortens the length loop to 0..=300 and the large buffer to
    70,000 bytes).
  - aarch64 Linux (Docker `rust:1-slim`, rustc 1.99.0, kernel getrandom path): pass; also
    with feature `linux_disable_fallback` (syscall-only `linux_android.rs`): pass, natively
    and under Miri.
  - wasm32-unknown-unknown with `js` under Node v26.8.1 (`wasm-bindgen-test-runner`
    0.2.129, matching the lockfile): pass (the Web Crypto path, since Node 26 has
    `globalThis.crypto`).
- **Advisories:** `cargo deny check advisories`: ok on 2026-10-05.

## Facts

| Item | Finding |
|---|---|
| `unsafe` | 58 `src/` lines with the token (56 code lines per `vet-facts.sh`); 11 `unsafe fn`; 1 `unsafe impl` (`use_file.rs:112`); 1 test line. No `forbid(unsafe_code)`. |
| asm | none (`rdrand.rs` uses `core::arch` intrinsics, not `asm!`) |
| build.rs / proc-macro | none / no |
| Powerful imports | `#![no_std]`; `std` only via `extern crate std` in `error_impls.rs` (feature `std`, off in ACDP) and `js.rs` (`thread_local!`). No `std::{fs,net,process,env}`. Expected OS-RNG access: see below. |
| Expected OS access | `open`/`read` of `/dev/urandom` and `open`/`poll`/`close` of `/dev/random` (`use_file.rs:18-24`, `:59`, `:71-83`, via `util_libc.rs:136-149`); `syscall(SYS_getrandom)` (`util_libc.rs:153-161`); `getentropy` (`getentropy.rs:15`); `CCRandomGenerateBytes` (`apple-other.rs:17`); `BCryptGenRandom` with `RtlGenRandom` fallback (`windows.rs:7-56`); `dlsym` (`util_libc.rs:121`, NetBSD only); `strerror_r` (`error.rs:103`); `pthread_mutex_{lock,unlock}` (`use_file.rs:103,107`); JS `globalThis.crypto.getRandomValues`, `msCrypto`, or Node `module.require("crypto").randomFillSync` (`js.rs:71-155`). |
| Dependencies | `cfg-if` 1; `libc` 0.2.154+ (unix); `wasi` 0.11 (wasi); `wasm-bindgen` + `js-sys` (feature `js`, wasm32/64-unknown only). |
| Features | `custom`, `rdrand`, `linux_disable_fallback`, `js`, `std`, `test-in-browser`, `rustc-dep-of-std`. ACDP enables none natively and `js` in `acdp-wasm`. |
| Exported macro | `register_custom_getrandom!` (`custom.rs:67-87`), expands in the caller to a `#[no_mangle] unsafe fn __getrandom_custom` (Rust ABI). |
| Advisories | `cargo deny check advisories`: ok on 2026-10-05 |

## Reachability in ACDP

- **Native (root library, CLI, CI):** `ring` 0.17.14 is the only dependent
  (`cargo tree --locked --workspace --all-features -e features -i getrandom@0.2.17`:
  `ring` with feature `default` only). Read directly in
  `ring-0.17.14/src/rand.rs`: `SystemRandom`'s `fill` calls `fill_impl`, which calls
  `getrandom::getrandom(dest)` (`rand.rs:165`) on the caller's already-initialized
  `&mut [u8]` (`rand::generate` zeroes `[0; N]` first, `:57-58`) and maps any error to
  `error::Unspecified`. This is the RNG under every rustls handshake ACDP makes. ring
  declares `getrandom = "0.2.10"` with no features (`Cargo.toml:246-247`); the only ring
  feature that forwards to getrandom is `wasm32_unknown_unknown_js = ["getrandom/js"]`
  (`:180`). `less-safe-getrandom-custom-or-rdrand` (`Cargo.toml:173`, `rand.rs:125`) and
  `less-safe-getrandom-espidf` (`Cargo.toml:174`, `rand.rs:126`) are empty features that only
  widen ring's own cfg (the latter is the ring path to the tier-3 espidf backend, GR2-1);
  `dev_urandom_fallback` is not referenced in ring's `src/` at all. ACDP enables none of
  them. (Root `cargo metadata --all-features` resolves 0.2.17 with `js`, via
  `quinn-proto`'s wasm-only `ring` dependency; `quinn-proto` is lock-only, `cargo tree
  --locked -i quinn-proto --target all` prints nothing, so `js` is inert natively.)
- **py / node wheels:** lock-only. `cargo tree --locked -i getrandom@0.2.17 --target all`
  inside `bindings/acdp-py` and `bindings/acdp-node`: "nothing to print".
- **wasm verifier:** compiled (feature `js`, `js.rs`) but **never called**: inside
  `bindings/acdp-wasm`, `cargo tree --locked --target wasm32-unknown-unknown -i
  getrandom@0.2.17` shows `acdp-wasm` itself as the only dependent
  (`bindings/acdp-wasm/Cargo.toml:61`); nothing in its graph calls it. See GR2-O1.

## Which code each ACDP artifact compiles

Command per row: `cargo check --target <t> [--features <f>]` in a scratch crate depending
on `getrandom = "=0.2.17"`, then the `src/*.rs` list from
`target/<t>/debug/deps/getrandom-*.d`.

| Artifact / target | Features | Compiled `src/` files | Backend |
|---|---|---|---|
| root, CI: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | none (`js` inert) | `lib.rs error.rs util.rs util_libc.rs lazy.rs linux_android_with_fallback.rs use_file.rs` | getrandom(2) syscall, `/dev/urandom` fallback |
| root, CI macOS: `x86_64-apple-darwin`, `aarch64-apple-darwin` | none | `lib.rs error.rs util.rs util_libc.rs getentropy.rs` | `getentropy` |
| CI / consumers: `x86_64-pc-windows-msvc` (also `i686-pc-windows-msvc`) | none | `lib.rs error.rs util.rs windows.rs` | `BCryptGenRandom`, `RtlGenRandom` fallback |
| `bindings/acdp-wasm`: `wasm32-unknown-unknown` | `js` | `lib.rs error.rs util.rs js.rs` | Web Crypto / Node crypto (uncalled) |

`error_impls.rs` is compiled only with feature `std` (off everywhere in ACDP).

## Backend matrix (reusable for delta audits)

Selector -> backend file (`lib.rs:237-354`; first match wins) -> toolchain/tier -> ACDP
artifact -> verdict. "Built" means dep-info confirmed it on that target.

| Selector | Backend | Stable? | In an ACDP artifact | Verdict |
|---|---|---|---|---|
| linux {aarch64, arm, powerpc{,64}, s390x, x86, x86_64, musl}, android {aarch64, arm, x86, x86_64}, without `linux_disable_fallback` (`lib.rs:261-304`) | `linux_android_with_fallback.rs` + `use_file.rs` (built: x86_64/aarch64 gnu, x86_64 musl, aarch64-android) | stable tier 1/2 | yes (linux-gnu) | sound |
| any other linux/android, or feature `linux_disable_fallback` (`:305-307`) | `linux_android.rs` (built with the feature on x86_64/aarch64 gnu) | stable, consumer feature | no | sound |
| macos, openbsd, vita, emscripten (`:241-248`) | `getentropy.rs` (built: both darwin) | stable | yes (darwin) | sound |
| dragonfly, freebsd, hurd, illumos, horizon-arm, cygwin (`:249-260`) | `getrandom.rs` (built: freebsd, illumos) | stable tier 2 | no | sound |
| haiku, redox, nto, aix (`:238-240`) | `use_file.rs` (no poll) | tier 2/3 | no | sound |
| solaris / netbsd / fuchsia (`:308-315`) | `solaris.rs` / `netbsd.rs` (built) / `fuchsia.rs` (built) | stable tier 2 | no | sound |
| ios, visionos, watchos, tvos (`:316-317`) | `apple-other.rs` (built: aarch64-apple-ios) | stable tier 2 | no | sound |
| wasm32-wasi (`:318-319`) | `wasi.rs` (built: wasip1, wasip2) | stable tier 2 | no | sound |
| hermit / vxworks / solid_asp3 / espidf (`:320-328`) | `hermit.rs` / `vxworks.rs` / `solid.rs` / `espidf.rs` | tier 3 (read only) | no | sound; espidf: **GR2-1 (Discretion)** |
| windows (`:329-330`) | `windows.rs` (built: x86_64 and i686 msvc) | stable tier 1 | yes (CI, consumers) | sound |
| x86_64 SGX (`:331-333`), always | `rdrand.rs` + `lazy.rs` (built: `x86_64-fortanix-unknown-sgx`) | stable tier 2 default | no | sound |
| feature `rdrand` on x86/x86_64 (`:334-337`) | `rdrand.rs` only where no OS arm matched; on the six artifact targets it is **not selected** (dep-info unchanged with `--features rdrand`) | stable, consumer feature | no | sound |
| feature `js` on wasm32/64-unknown (`:338-341`) | `js.rs` (built) | stable | wasm (uncalled) | sound |
| feature `custom` (`:342-343`) | `custom.rs` is compiled whenever the feature is on (built on all five non-wasm targets), but selected only where no OS arm matched | stable, consumer feature | no | sound given the contract |

## `unsafe` sites and verdicts

Invariant shorthand: **SLICE** = pointer and length come from a live `&mut [MaybeUninit<u8>]`
(or `&mut [u8]`), so the callee may write at most `len` bytes into valid memory; **INIT** =
the backend writes only bytes produced by the OS/JS/hardware, never uninitialized bytes
(the contract stated at `lib.rs:231-236`).

| Site | What | Argument | Verdict |
|---|---|---|---|
| `lib.rs:374` | `slice_as_uninit_mut(dest)` in `getrandom` | INIT holds for every backend below; the reference does not escape | sound |
| `lib.rs:406` | `slice_assume_init_mut(dest)` in `getrandom_uninit` | reached only when `dest` is empty or `getrandom_inner` returned `Ok`, and every backend returns `Ok` only after filling all of `dest` (see "Fail-closed") | sound |
| `error.rs:23` | `NonZeroU32::new_unchecked(2^31 + n)`, `n: u16` (const fn) | non-zero, no overflow | sound |
| `error.rs:103` | `libc::strerror_r(errno, buf, 128)` | buffer and length agree; non-zero return gives `None`; result read up to NUL (or whole buffer) and UTF-8 checked (`:107-110`) | sound |
| `util.rs:8-10` | `unsafe fn slice_assume_init_mut`; body op: raw reborrow `[MaybeUninit<T>] -> [T]` | same layout; caller guarantees initialization | sound |
| `util.rs:15-16` | `write_bytes(ptr, 0, len)` then `slice_assume_init_mut` | zeroes first, so fully initialized | sound |
| `util.rs:24` | shared `&[T] -> &[MaybeUninit<T>]` | read-only view | sound |
| `util.rs:32-34` | `unsafe fn slice_as_uninit_mut`; body op: raw reborrow | caller must not write uninit (INIT) | sound |
| `util_libc.rs:25-28` | `extern "C" fn __errno()` (horizon-arm, vita only; tier 3) | newlib ABI; read only | sound |
| `util_libc.rs:39` | `unsafe fn get_errno`; body ops: call `errno_location()`, deref the returned pointer | libc's thread-local errno pointer is always valid | sound |
| `util_libc.rs:44` | call `get_errno()` | as above | sound |
| `util_libc.rs:100` | `const unsafe fn Weak::new` (no unsafe op in body) | contract: `name` NUL-terminated; the only use is `netbsd.rs:32` with `"getrandom\0"` | sound |
| `util_libc.rs:121` | `libc::dlsym(RTLD_DEFAULT, name)` | NUL-terminated name (contract above); `AtomicPtr` published with Release, read with Relaxed + Acquire fence (`:118-129`) | sound |
| `util_libc.rs:136-149` | `unsafe fn open_readonly`; body op: `libc::open(path, O_RDONLY\|O_CLOEXEC)` at `:139` | NUL termination is only debug-asserted (`:137`), but both callers pass literals ending in `\0` (`use_file.rs:18`, `:71`); EINTR retried | sound |
| `util_libc.rs:154-161` | `libc::syscall(SYS_getrandom, ptr, len, 0)` | SLICE; the probe at `linux_android_with_fallback.rs:20` passes an empty slice (dangling, len 0) | sound |
| `use_file.rs:23-25` | `libc::read(fd, ptr, len)` | SLICE; `fd` from `/dev/urandom` | sound |
| `use_file.rs:48-49` | `MUTEX.lock()`, then a `DropGuard` that unlocks | guard created immediately, so unlock runs on every return path including `?` and unwinding | sound |
| `use_file.rs:59`, `:71` | `open_readonly("/dev/urandom\0")`, `open_readonly("/dev/random\0")` | NUL-terminated literals | sound |
| `use_file.rs:77-79` | `DropGuard` closing the `/dev/random` fd | closes once on every path | sound |
| `use_file.rs:83` | `libc::poll(&mut pfd, 1, -1)` | valid pointer to one `pollfd` | sound |
| `use_file.rs:102-108` | `unsafe fn lock`/`unlock`; body ops: `pthread_mutex_lock`/`unlock(UnsafeCell::get())` | static mutex (never moves) initialized with `PTHREAD_MUTEX_INITIALIZER` (`:100`), non-recursive, always paired by the guard | sound |
| `use_file.rs:112` | `unsafe impl Sync for Mutex` | a pthread mutex is designed to be shared; the cell is touched only through pthread calls | sound |
| `getentropy.rs:15` | `libc::getentropy(chunk, len)` | SLICE; chunks of 256 (the API maximum) | sound |
| `apple-other.rs:7-14`, `:17` | `extern "C" fn CCRandomGenerateBytes(*mut c_void, usize) -> i32`; call | matches CommonRandom.h (`CCRNGStatus` is int32); SLICE | sound |
| `windows.rs:7-15`, `:29-36` | `#[link(name="bcrypt")] extern "system" BCryptGenRandom`; call with null handle and `BCRYPT_USE_SYSTEM_PREFERRED_RNG` | matches `NTSTATUS(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG)`; chunks of `u32::MAX` so the length cast is lossless | sound |
| `windows.rs:18-23`, `:44` | `#[link(name="advapi32")]`, `link_name="SystemFunction036"` `RtlGenRandom(*mut c_void, u32) -> u8`; fallback call | matches `BOOLEAN RtlGenRandom(PVOID, ULONG)`; not on UWP | sound |
| `windows.rs:55` | `NonZeroU32::new_unchecked(ret ^ (1 << 31))` | only when the top two bits are `11`, so bit 30 stays set | sound |
| `js.rs:77-99` (selection, no `unsafe`) | source chosen once and cached in a `thread_local!`: `globalThis.crypto` if it is an object (Web path, 256-byte `Uint8Array`, `:12`, `:98`); else on Node `module.require("crypto")` (Node path; an ES module without `require` gives `Err(NODE_ES_MODULE)`); else `msCrypto`; else `Err(WEB_CRYPTO)` | every failure is an `Err` | sound |
| `js.rs:42-44` | `Uint8Array::view_mut_raw(chunk ptr, len)` passed to Node `randomFillSync` | SLICE; chunks of at most `NODE_MAX_BUFFER_SIZE = 2^31-1` (`:14`, `:33`); the view lives only for one synchronous JS call with no Rust allocation in between; if wasm memory grows the view detaches and JS throws (an `Err`, not UB) | sound |
| `js.rs:63` | `sub_buf.raw_copy_to_ptr(chunk ptr)` | `sub_buf = buf.subarray(0, chunk.len())` and `chunk.len() <= 256 = buf.length` (`:12`, `:56`, `:98`) | sound |
| `js.rs:114-155` | `#[wasm_bindgen] extern "C"` (macro-generated imports: `crypto`/`msCrypto` getters, `getRandomValues` (catch), `randomFillSync` (catch), `module.require` getter (catch), `process.versions.node`) | safe wrappers generated by wasm-bindgen; soundness rests on the wasm-bindgen glue (itself exempted) and the JS host | sound |
| `custom.rs:67-87` | `#[macro_export] register_custom_getrandom!` expands to `#[no_mangle] unsafe fn __getrandom_custom(dest, len) -> u32` (Rust ABI); body op: `from_raw_parts_mut(dest, len)` at `:79` | the only caller (`:100`) passes a slice that `:99` has just zero-filled, so the slice is valid and initialized; the macro checks the user function's type (`:76-78`) | sound |
| `custom.rs:91-93`, `:100` | `extern "Rust" fn __getrandom_custom` declaration and call | the symbol is the macro's output (same signature); a hand-written definition is the user's responsibility; a non-zero return is always an `Err` (`:101-103`) | sound given the contract |
| `rdrand.rs:21-29` | `#[target_feature(enable="rdrand")] unsafe fn rdrand`; body op: `rdrand_step(&mut val)` | intrinsic called from a function with the same target feature; valid `&mut` | sound |
| `rdrand.rs:41-53` | `unsafe fn self_test`; body op: `rdrand()` | same target feature | sound |
| `rdrand.rs:60`, `:64` | `__cpuid(0)`, `__cpuid(1)` | CPUID exists on every Rust x86 target; leaf 1 only after `eax >= 1` (`:61`); skipped under `target_feature="rdrand"` (SGX) | sound |
| `rdrand.rs:91` | `self_test()` | after the CPUID ECX bit-30 check (`:84-87`) or with `rdrand` enabled at compile time | sound |
| `rdrand.rs:100` | `rdrand_exact(dest)` | only after `RDRAND_GOOD` is true (`:95-97`) | sound |
| `rdrand.rs:104-121` | `unsafe fn rdrand_exact`; body ops: `rdrand()` at `:110`, `:117` | same target feature; chunk length equals `size_of::<usize>()`, tail shorter, so `copy_from_slice` cannot panic | sound |
| `espidf.rs:5-7`, `:15` | `extern "C" fn esp_fill_random(*mut c_void, usize) -> u32`; call | ESP-IDF's prototype is `void esp_fill_random(void *buf, size_t len)`; see **GR2-1** | Discretion (tier 3) |
| `fuchsia.rs:5-8`, `:11` | `#[link(name="zircon")] extern "C" zx_cprng_draw`; call | matches the Zircon ABI; SLICE | sound |
| `getrandom.rs:22-24` | `libc::getrandom(ptr, len, 0)` | SLICE | sound |
| `hermit.rs:10-12`, `:16` | `extern "C" sys_read_entropy`; call | Hermit kernel ABI; SLICE; an over-long return fails the explicit `(res as usize) <= dest.len()` check (`:18`) | sound |
| `netbsd.rs:11-20` | `libc::sysctl(KERN_ARND)` per 256-byte chunk (the caller's `dest.chunks_mut(256)`, `:42`) | MIB valid; kernel writes at most `len` | sound |
| `netbsd.rs:28`, `:32-37` | `unsafe extern "C" fn` pointer type; `Weak::new("getrandom\0")`; `transmute(NonNull<c_void> -> GetRandomFn)`; call | same size; non-null; NetBSD 10 `getrandom` has this signature | sound |
| `solaris.rs:23` | `libc::getrandom(ptr, len <= 1024, GRND_RANDOM)` | SLICE; short read gives `UNEXPECTED` | sound |
| `solid.rs:5-7`, `:10` | `extern "C" SOLID_RNG_SampleRandomBytes`; call | SOLID OS ABI; SLICE | sound |
| `vxworks.rs:11`, `:18`, `:23` | `randSecure()`, `usleep(10)`, `randABytes(ptr, len as i32)` | chunk length capped at `i32::MAX` (`:22`) | sound |
| `wasi.rs:10` | `wasi::random_get(ptr, len)` (an `unsafe fn` in `wasi` 0.11) | SLICE; WASI host | sound |
| `tests/rdrand.rs:19` | `slice_as_uninit_mut(dest)` (test only) | rdrand writes only initialized bytes | sound |

No `static mut`, no `asm!`, no `include_*!`, no `#[export_name]`; `MaybeUninit` appears
only as a slice element type. Interior-mutable statics: `use_file.rs:32` (`FD:
AtomicUsize`), `:47` (`MUTEX`), `linux_android_with_fallback.rs:11` (`HAS_GETRANDOM:
LazyBool`), `rdrand.rs:95` (`RDRAND_GOOD`), `netbsd.rs:32` (`Weak`), `vxworks.rs:9`
(`AtomicBool`). `lazy.rs` uses `Relaxed` on a single `AtomicUsize`; a race only reruns an
idempotent `init` (`:34-42`). `use_file`'s `FD` is double-checked under the pthread mutex,
so `Relaxed` is enough there.

## Fail-closed behaviour (observed, not claimed as RNG quality)

- `sys_fill_exact` (`util_libc.rs:55-77`) loops until the buffer is empty: `res > 0`
  advances with `get_mut(res..)` (over-long returns become `Err(UNEXPECTED)`), `-1` with
  EINTR retries, any other errno is returned, `0` or another negative value is
  `Err(UNEXPECTED)`. A partial fill therefore always ends in `Err`.
- Linux probe (`linux_android_with_fallback.rs:19-33`): a zero-length `getrandom` call;
  `ENOSYS`, and `EPERM` on Linux (seccomp), select the file fallback; any other error keeps
  the syscall, whose real errors then propagate.
- `use_file` on Linux/Android only: opens `/dev/random`, polls `POLLIN` with an infinite
  timeout (EINTR/EAGAIN retried, other errors returned), closes it, then opens
  `/dev/urandom` (`use_file.rs:56-94`). Haiku/Redox/NTO/AIX read `/dev/urandom` directly.
- getentropy, Apple, windows (BCrypt, then RtlGenRandom, then `Err`), js (any JS throw,
  missing `crypto`, missing `require`: `Err`): fail closed. `fuchsia` and `espidf` have no
  failure path (the APIs return nothing).
- ring discards the error code and returns `Unspecified`, so a failure aborts the TLS
  operation rather than continuing with weak bytes.

## Findings

### GR2-1 (Discretion): ESP-IDF FFI return type

`espidf.rs:5-7` declares `fn esp_fill_random(buf: *mut c_void, len: usize) -> u32`; the
ESP-IDF C prototype is `void esp_fill_random(void *buf, size_t len)`. Calling a foreign
function through a declaration whose return type does not match is undefined behaviour in
Rust's model. In practice the return register is read and discarded (`:15`). The backend is
selected only for `target_os = "espidf"` (`lib.rs:326-327`), whose targets
(`riscv32imc-esp-espidf`, `xtensa-*-espidf`, ...) are tier 3 and need `-Z build-std`, so the
code is unreachable in any stable-toolchain build of any ACDP artifact (Policy 6 carve-out,
`322-sha2` precedent; plan rule 3). The same declaration is in getrandom 0.3.4 and 0.4.3
(`backends/esp_idf.rs:7-9`).

## Other observations (non-blocking)

- **GR2-O1, vestigial wasm dependency.** In `bindings/acdp-wasm` the 0.2 dependency
  (`Cargo.toml:61`, feature `js`) has no dependent but `acdp-wasm` itself (`cargo tree
  --locked --target wasm32-unknown-unknown -i getrandom@0.2.17`), and `acdp-wasm` never
  calls it. The comments at `bindings/acdp-wasm/Cargo.toml:52-57` and
  `.github/dependabot.yml:75-80` still say it serves "rand_core 0.6 / OsRng
  (acdp-crypto)"; `acdp-crypto` now uses rand_core 0.10 and getrandom 0.4 `SysRng`.
  Not changed in an audit PR; follow-up issue #363 filed.
- `solid.rs:16`: `-ret` overflows for `ret == i32::MIN` (debug panic, release wrap to a
  still-`Err` code). Tier 3, needs a hostile OS return.
- `use_file.rs:84-86` does not check `revents`; POLLERR/POLLHUP on a freshly opened
  `/dev/random` cannot happen in practice.
- `windows.rs:39` treats only NTSTATUS severity `11` as failure; BCryptGenRandom documents
  only success or error-severity codes.
- `register_custom_getrandom!` emits `#[no_mangle]` without `unsafe(...)`; it still compiles
  in an edition-2024 caller, because the attribute's span carries getrandom's edition 2018
  (checked with a scratch crate). No UB either way.
- The RDRAND self-test and AMD-family check run once and are cached; under
  `target_feature="rdrand"` the CPUID checks are skipped by design.
- `error.rs:165` still names "SecRandomCopyBytes" for the Apple error (cosmetic).

## Concerns

None under the concern rule. GR2-1 is recorded as a `Discretion:` line (tier-3-only code).

## Not claimed

RNG output quality or entropy, correctness of each OS's RNG, the soundness of the
wasm-bindgen glue and of user-supplied `custom` functions beyond their documented contract,
cryptographic correctness, constant-time behaviour, side-channel resistance.
