# Review worksheet: `crypto-bigint` 0.7.9 (yank of 0.7.5–0.7.8)

- **Verdict:** CERTIFIED `safe-to-deploy`, delta audit (`delta = "0.7.6 -> 0.7.9"`).
  No concern-rule trigger: no `unsafe` line changed, no dependency change, no build script,
  no vendored binaries.
- **Reviewer:** Ajit Koti <ajitkoti@zer07labs.com>. Reviewed with Claude (Opus) assistance.
- **Date:** 2026-10-25
- **Policy:** DECISIONS.md "#322 supply-chain audit policy"
- **Why now:** upstream yanked 0.7.5–0.7.8 after the breaking `NonZero<T>` `Mul` fix
  ([#1373]). That turned `cargo deny check` (yanked) red on the three binding lockfiles in
  PR #431.

## Provenance

| Version | Tarball sha256 | Bound to |
|---|---|---|
| 0.7.9 (locked) | `d811ea23fdfbcce2e2d5132344d471abdb8f901ac496a0893a3df92e70525e52` | `Cargo.lock` checksum (root, and the `bindings/acdp-py` / `bindings/acdp-node` / `bindings/acdp-wasm` lockfiles) |
| 0.7.6 (prior audit) | `6bb08299a6046833a879ace115697f12fd2bd6c8d3e93c909ffc9e0738e7cae0` | crates.io index `cksum`, and the `Cargo.lock` checksum this audit replaces |

Reproduce the facts with `scripts/vet-facts.sh crypto-bigint 0.7.9 0.7.6`.

## Method

- Delta: 10 files, +199/−34 (excluding Cargo.lock, Cargo.toml.orig and .cargo_vcs_info.json).
  That is 233 changed lines against 46,747 `src/` lines, a ratio of 0.00, so the method rule
  says **delta**.
- **Every hunk was read**: 7 `src/` files, `Cargo.toml` (one new `[[test]]`), `CHANGELOG.md`,
  and the new `tests/const_prime_monty_params.rs`.
- ACDP's compiled feature set is unchanged: `getrandom`, `hybrid-array`, `rand_core`,
  `subtle`, `zeroize`. `alloc` is off, so the `boxed/*` hunks were read but are not compiled
  into ACDP.

## The change

- `src/uint/mul_mod.rs`, `src/uint/boxed/mul_mod.rs` (`mul_mod_special`, [#1368]):
  - The `(carry + 1) * c` step now widens before adding (`carry` can be `Limb::MAX`; the old
    `carry.0 + 1` overflowed). The boxed form uses `carrying_mul_add(c, c, 0)`, which equals
    `carry * c + c`.
  - For `LIMBS == 1`, `c = 0` no longer reaches `NonZero::new_unwrap(0)` (a panic). The divisor
    comes from `to_nz_or_one()`, and `Limb::select` picks the wrapping product in constant time
    when `c` is zero.
- `src/modular/safegcd/boxed.rs` ([#1367]): drops `.resize_unchecked(a.bits_precision())`, so
  the inverse keeps the modulus's precision instead of being truncated to the input's.
- `src/modular/mul.rs`: the Montgomery carry bit is `c.to_u8() as WideWord` instead of
  `choice_to_wide_mask(c) & 1`. Both are 0 or 1, so the value is the same.
- `src/modular/prime_params.rs` ([#1372]): `t = (p−1)/2^s` is computed once, with
  `shr_vartime`. `p` is a public parameter, and the function is already `_vartime`.
- `src/non_zero.rs` ([#1373]): the `ConstOne`, `One` and `Mul` impls for `NonZero<T>` now
  require `T: Integer`. This is API-only (the reason for the yank) and changes no code paths.
  The `unsafe` cast at line 120 is untouched.
- Otherwise, only new tests.

## Facts

- `unsafe`: 14 sites, the same 14 as 0.7.6, and no hunk touches or borders one.
- asm/SIMD: none. build.rs / proc-macro: none. Powerful imports: none.
- Dependencies: no change.
- Panics: none added; one removed (the `c = 0` `new_unwrap`).
- Builds: the workspace (all features, all targets) and the node and wasm bindings build
  against 0.7.9 with no source change.
- Advisories: `cargo deny check` clean after the bump, 2026-10-25.

## Not claimed

Cryptographic correctness, constant-time behaviour, side-channel resistance.

[#1367]: https://github.com/RustCrypto/crypto-bigint/pull/1367
[#1368]: https://github.com/RustCrypto/crypto-bigint/pull/1368
[#1372]: https://github.com/RustCrypto/crypto-bigint/pull/1372
[#1373]: https://github.com/RustCrypto/crypto-bigint/pull/1373
