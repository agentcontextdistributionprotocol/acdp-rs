# Review worksheet: `cpufeatures` 0.3.1 (issue #339, Tier B batch B6)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.3.1"`), with one
  `Discretion:` line for finding **CF-1** (on x86, CPUID leaf 7 is read without checking
  the maximum supported basic leaf). Every `unsafe` and `asm!` site has a verdict below, and
  each one is sound. This review first held the crate back under "default to not
  certifying"; the decision to certify with a Discretion line is Fable's (2026-10-05,
  DECISIONS.md `322-cpufeatures`). **Exit criterion:** delta-audit the cpufeatures release
  carrying RustCrypto/utils#1528.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.3.1 (locked) | `5ca28b0ae3115b884660db4118d803791fd6756b6e88f39c0f3f7859060d7566` | `Cargo.lock` checksum |

Downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`; sha256 matches;
the extracted tree (`diff -r`-identical to `~/.cargo/registry/src` apart from `.cargo-ok`)
is what was read. Reproduce with `scripts/vet-facts.sh cpufeatures 0.3.1`. The root and
all three binding lockfiles lock 0.3.1 with this checksum.

## Method

- No prior audit, so **full**.
- `src/` is 589 lines; **all of it was read line by line**: `src/lib.rs` (109),
  `src/x86.rs` (149), `src/aarch64.rs` (183), `src/loongarch64.rs` (128), `src/miri.rs`
  (20). Also `Cargo.toml` (and `.orig`) and `tests/{x86,aarch64,loongarch64}.rs` (17, 17,
  33; each only calls `new!` and compares `init`/`get`).
- Almost all of the crate is `#[macro_export]` macros (`new!`, `__unless_target_features!`,
  `__detect_target_features!`, `check!`, `__xgetbv!`) that **expand in the caller crate**.
  The callers in ACDP's graph and the features they ask for:
  - `sha2` 0.11.0: `new!(shani_cpuid, "sha", "sse2", "ssse3", "sse4.1")`
    (`src/sha256.rs:55`), `new!(sha2_hwcap, "sha2")` (`:58`), `new!(avx2_cpuid, "avx2")`
    (`src/sha512.rs:50`), `new!(sha3_hwcap, "sha3")` (`:53`). cpufeatures is a dependency
    only on `x86`, `x86_64`, `aarch64` (`sha2` `Cargo.toml:79`).
  - `curve25519-dalek` 5.0.0: `new!(cpuid_avx2, "avx2")` (`src/backend.rs:67`) under
    `curve25519_dalek_backend = "simd"`, and `new!(cpuid_avx512, "avx512ifma", "avx512vl")`
    (`:58`) under the opt-in `avx512` backend; x86_64 only (`Cargo.toml:164`).

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 11 (every one has a verdict below). No `forbid(unsafe_code)`. |
| asm | 1 site: `src/loongarch64.rs:30-40` (`cpucfg`), loongarch64-linux only. |
| build.rs / proc-macro | none / no |
| Powerful imports | none of fs/net/process/env. OS calls: `libc::getauxval(AT_HWCAP)` (Linux/Android aarch64, loongarch64) and `libc::sysctlbyname("hw.optional.*")` (Apple aarch64), read-only CPU-capability queries. `#![no_std]`. |
| Dependencies | `libc` 0.2.155 on aarch64-{linux,android,apple} and loongarch64-linux only. |
| Features | none |
| `compile_error!` | on any arch other than aarch64 / loongarch64 / x86 / x86_64 (`src/lib.rs:25-31`), so it cannot be built for `wasm32`; neither `sha2` nor `curve25519-dalek` depends on it there. |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Which code each ACDP artifact compiles

| Artifact / target | Module | Detection mechanism |
|---|---|---|
| root/CI Linux & Windows x86_64; py/node wheels x86_64 linux-gnu and apple-darwin | `x86` | CPUID leaves 1, (7,0), (7,1); XGETBV |
| CI macOS (aarch64), py/node wheels aarch64-apple-darwin | `aarch64` (apple) | `sysctlbyname` for `dit`, `sha3`; `aes`, `sha2` assumed true |
| py/node wheels aarch64-unknown-linux-gnu | `aarch64` (linux) | `getauxval(AT_HWCAP)` |
| `bindings/acdp-wasm` (wasm32) | **not compiled** (not in the wasm32 `cargo tree`; `sha2` and `curve25519-dalek` depend on it only for x86/aarch64) | - |
| 32-bit x86 (no ACDP-built artifact) | `x86` | as x86_64 |

## `unsafe` / `asm!` sites and verdicts

| Site | What | Argument | Verdict |
|---|---|---|---|
| `src/x86.rs:41-47` | `unsafe fn cpuid` / `cpuid_count` wrappers (expanded in the caller) | thin wrappers over `core::arch::{__cpuid, __cpuid_count}`. | sound |
| `src/x86.rs:49-51` | `[cpuid(1), cpuid_count(7, 0), cpuid_count(7, 1)]` | `CPUID` exists on every x86_64 CPU and on every i586+ CPU Rust targets; executing it with any leaf is defined behaviour (out-of-range leaves return documented, if unhelpful, data). Not executed on SGX / `target_os = "none"` / UEFI (`:17-23`). See CF-1 for what the returned data means. | sound (CF-1) |
| `src/x86.rs:71` | `_xgetbv(XCR0)` | executed only if CPUID.1:ECX bits 26 (XSAVE) and 27 (OSXSAVE) are both set (`:68-70`), which is exactly when `XGETBV` is enabled. Leaf 1 is always in range. | sound |
| `src/aarch64.rs:37` | `libc::getauxval(AT_HWCAP)` | no preconditions; returns 0 if absent. | sound |
| `src/aarch64.rs:114-116`, `:122-126` | `check!("dit")`, `check!("sha3")` call `sysctlbyname` (expanded in caller) | see next row. | sound |
| `src/aarch64.rs:141` | `pub unsafe fn sysctlbyname(name)` | body is sound for every input: it asserts NUL termination (`:142-147`) before passing the pointer. | sound |
| `src/aarch64.rs:160-168` | `libc::sysctlbyname(name, &mut u32, &mut size=4, NULL, 0)` | valid NUL-terminated name; 4-byte aligned out-buffer with `size = 4`; `newp = NULL`, `newlen = 0` (read-only). `c_char` is `i8` on Apple aarch64, matching the cast. | sound |
| `src/loongarch64.rs:30-40` | `asm!("cpucfg" x3)`, `options(pure, nomem, preserves_flags, nostack)` | `cpucfg` reads a CPU configuration word into a register: no memory, no stack, LoongArch has no flags register, and the result depends only on the input word (`pure`). Not compiled for any ACDP artifact. | sound |
| `src/loongarch64.rs:49` | `libc::getauxval(AT_HWCAP)` | as above; not compiled for any ACDP artifact. | sound |

## Finding CF-1 (Discretion line)

`__detect_target_features!` on x86 (`src/x86.rs:34-55`) reads CPUID leaf 7 (sub-leaves 0
and 1) **without first reading leaf 0 to check that the CPU supports leaf 7**
(`src/x86.rs:49-51`).

- **Intel behaviour:** for a basic leaf above the maximum, CPUID returns the data of the
  highest supported basic leaf (Intel SDM, CPUID instruction description). AMD returns
  zeros, which is harmless here.
- **Effect if it misfires:** the checks in ACDP's graph that read leaf 7 are:
  - `sha` (EBX bit 29), for `sha2`'s SHA-NI SHA-256 backend;
  - `avx2` (EBX bit 5), for `sha2`'s SHA-512 AVX2 backend and `curve25519-dalek`'s AVX2
    backend.

  A spurious `1` would make them call `#[target_feature]` functions on a CPU without that
  feature. In practice that is a deterministic illegal-instruction trap (`SIGILL`). In
  Rust's model it is undefined behaviour in the dependent's `unsafe` code, which relies on
  this crate's answer.
- **Why the predicates ACDP uses do not misfire.**
  - Read from source by this review: `sha` is ANDed by `sha2` with the leaf-1 bits SSE2,
    SSSE3 and SSE4.1 (`sha2` `src/sha256.rs:55`). `avx2` is ANDed inside cpufeatures with
    leaf-1 AVX and with the XCR0 XMM+YMM state, which is read only when OSXSAVE is set
    (`src/x86.rs:68-71`, `:92`, `:126`).
  - Platform facts from the decision reviewer (Fable, DECISIONS.md `322-cpufeatures`; this
    review did not re-measure them):
    - every CPU with those leaf-1 bits has a native maximum basic leaf of at least 0xA;
    - no QEMU CPU model exposing SSE4.1 or AVX has a level below 0xA;
    - the firmware "Limit CPUID Maxval" setting caps the maximum at leaf 2 or 3, which
      yields zeros or a false AND, and Linux and Windows clear it;
    - Rosetta 2 reports a maximum basic leaf of 0xD (measured).

  So only a manual hypervisor `level=` override on an AVX-class CPU model reaches the gap,
  and the result is then a deterministic `SIGILL`. CF-1 is a correctness gap in a **safe**
  function whose input (CPUID) is not attacker-controlled.
- **Not affected:** the aarch64 builds (Apple and Linux) and the wasm32 build. aarch64
  Linux uses the kernel's `AT_HWCAP`. Apple uses `sysctlbyname` or architectural
  guarantees.
- **Upstream:** tracked as RustCrypto/utils#1510 (opened 2026-07-26). The fix,
  RustCrypto/utils#1528 (opened 2026-09-02, open), gates leaves 1, 7.0 and 7.1 on
  `CPUID.0:EAX`. An earlier draft of this worksheet said nothing had been filed upstream
  and carried a draft issue; that was stale. The draft is superseded and must not be filed.
- **Exit criterion:** delta-audit the cpufeatures release carrying #1528.

## Other observations (non-blocking)

- **CF-2 (Apple, safe panic).** `sysctlbyname` panics if the sysctl node is missing or
  returns an error (`assert_eq!(rc, 0)`, `src/aarch64.rs:170-171`). `sha2`'s SHA-512
  detection queries `hw.optional.armv8_2_sha512` and `hw.optional.armv8_2_sha3`; on an Apple
  OS lacking either node, the first SHA-512 use (Ed25519 signing/verification) would panic.
  Safe code; current Apple Silicon macOS provides these nodes (it was not checked on every
  OS version).
- `pub unsafe fn sysctlbyname` is marked `unsafe` but is sound for every input; the
  qualifier is unnecessary, not harmful.

## Concerns

None under the concern rule after the decision. CF-1 is recorded as a `Discretion:` line
(DECISIONS.md `322-cpufeatures`, decided by Fable on 2026-10-05).

## Not claimed

Correctness of feature detection on every CPU configuration (CF-1 is exactly that gap),
cryptographic correctness, constant-time behaviour, side-channel resistance.
