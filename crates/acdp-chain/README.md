# acdp-chain

Offline, as-of chain verification over evidence bundles (RFC-ACDP-0017,
Final at 0.5.0; §10–§11 remain Draft) for the Agent Context Distribution Protocol (ACDP).

`verify_chain(roots, &evidence, &options)` walks a context's `derived_from`
DAG inside an `acdp-evidence/1` bundle and reports, for every node, what was
verifiable **as of T** (using only evidence dated ≤ T) and what the bundle
says **now**, as a deterministic `acdp-chain-verdict/1` object. It is pure: no
network, no clock, no async. Its `as_of_digest` is the value to seal at T; it
does not move as evidence dated after T accumulates.

Part of the [`acdp`](https://crates.io/crates/acdp) workspace — the reference
Rust implementation of the **Agent Context Distribution Protocol (ACDP)**. Most
users should depend on the umbrella [`acdp`](https://docs.rs/acdp) crate, which
re-exports this crate as `acdp::chain`.

## License

Licensed under `MIT OR Apache-2.0`. See the workspace [LICENSE](../../LICENSE).
