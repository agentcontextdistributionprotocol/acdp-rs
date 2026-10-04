# Review worksheet: `rand_core` 0.9.5 (issue #339, Tier B batch B4)

- **Verdict:** CERTIFIED `safe-to-deploy`, full audit (`version = "0.9.5"`). No concern-rule
  trigger. The previous exemption was `safe-to-run` (0.9.5 is a dev-only dependency in
  ACDP). The full read below meets the standard `safe-to-deploy` bar, which also implies
  `safe-to-run`, so the exemption is replaced by an audit rather than kept.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-04
- **Policy:** DECISIONS.md "#322 supply-chain audit policy" (applied to Tier B by #339)

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.9.5 (locked) | `76afc826de14238e6e8c374ddcc1fa19e374fd8dd986b0d2af0d02377261d83c` | `Cargo.lock` checksum |

The tarball was downloaded from `static.crates.io` independently of `scripts/vet-facts.sh`;
its sha256 matches, and its extracted tree is identical (`diff -r`; only cargo's
`.cargo-ok` marker differs) to the `~/.cargo/registry/src` copy that was read. Reproduce the
facts with `scripts/vet-facts.sh rand_core 0.9.5`. None of the three binding lockfiles
contains 0.9.5 (absent is allowed by `scripts/check-bindings-lock-parity.sh`).

## Why 0.9.5 is in the graph

`cargo tree --workspace --all-features -i rand_core@0.9.5 -e normal,build` prints nothing:
there is no normal or build edge. The only path is `proptest` 1.11.0 -> `rand` 0.9.5 ->
`rand_core` 0.9.5, and `proptest` is a dev-dependency of `acdp` and `acdp-jcs`. No ACDP
artifact ships this version. It is certified `safe-to-deploy` anyway because the review
supports it, and because a single audit level per crate keeps the guard list simple
(`rand_core` is listed once and both locked versions must be fully audited).

## Method

- No prior audit of `rand_core` exists, so **full**.
- `src/` is 1,701 lines. Every file was read in full: `Cargo.toml` (and `.orig`),
  `src/lib.rs` (771), `src/block.rs` (534), `src/impls.rs` (217), `src/le.rs` (64),
  `src/os.rs` (115). `#[cfg(test)]` modules (`src/lib.rs:613-771`, `src/block.rs:426-534`,
  `src/impls.rs:174-217`) and the `#[test]` fns in `src/os.rs:104-115` and `src/le.rs:42-64`
  were read as test code. No `tests/` directory.

## Facts

| Item | Finding |
|---|---|
| `unsafe` code lines | 0 (grep of the full source, comment lines excluded; the grep is the evidence). No `forbid(unsafe_code)` attribute or lint. |
| asm / SIMD / intrinsics | none |
| build.rs | none (`build = false`) |
| proc-macro | no; no exported macros |
| Powerful imports | OS randomness only, under feature `os_rng`: `OsRng` (`src/os.rs:83-100`) and `SeedableRng::try_from_os_rng` (`src/lib.rs:570-576`) call `getrandom::{fill, u32, u64}` (getrandom 0.3). Under `std`, `RngReadAdapter` (`src/lib.rs:590-604`) implements `std::io::Read` by filling the caller's buffer from an RNG; it opens no file or socket. No `std::{fs,net,process,env}`, `env!`, `include_*`. |
| Binary content | none |
| Dependencies | optional `getrandom` 0.3 (`os_rng`; locked 0.3.4), optional `serde` 1 with `derive` (`serde`) |
| Features ACDP enables | `os_rng`, `std` (via `rand` 0.9.5); `serde` off |
| Reached via | `proptest` -> `rand` 0.9.5 (dev-only, see above) |
| Advisories | `cargo deny check advisories`: ok on 2026-10-04 |

## Behaviour (what was read)

- `lib.rs`: `RngCore` (`:130-156`) with a `DerefMut` blanket (`:158-176`); `TryRngCore`
  (`:220-252`) with a blanket over `RngCore` (`:257-275`); `UnwrapErr`/`UnwrapMut`
  (`:297-356`) `unwrap()` inner errors (panic by design); `SeedableRng` (`:371-577`) with a
  PCG32 `seed_from_u64` (`:466-495`).
- `block.rs`: `BlockRng` (`:126-261`) and `BlockRng64` (`:285-424`) keep a separate `index`
  field. Every read checks `index >= results.len()` and regenerates first;
  `generate_and_set` asserts `index < len` (`:178`, `:341`); `fill_bytes` slices
  `results[index..]` only after that check. With the `serde` feature (off in ACDP) a
  deserialized out-of-range index is handled the same way (regenerate), and a
  zero-length `Results` could only cause a safe panic.
- `impls.rs`: `fill_bytes_via_next`, `fill_via_chunks` (bounded `chunks_exact_mut` + zip,
  remainder sliced to its own length), deprecated `fill_via_u{32,64}_chunks`,
  `next_u{32,64}_via_fill`.
- `le.rs`: `read_u{32,64}_into` assert `src.len() >= {4,8} * dst.len()` before the
  `try_into().unwrap()` on exact-size chunks.
- `os.rs`: thin `OsRng` over getrandom 0.3; `OsError` wraps `getrandom::Error`.

## Concerns

None. The only external effect is the documented OS-RNG call through getrandom, which is
what the `os_rng` feature exists for (not "unexpected" I/O under the concern rule).

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance, and RNG
quality. `getrandom` 0.3.4 is a separate Tier B crate, still exempted.
