# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-primitives-v0.10.0...acdp-primitives-v0.10.1) - 2026-09-10

### Added

- *(client)* assemble revocation lineages so the earliest-T rule can actually apply ([#226](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/226)) ([#239](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/239))

## [0.9.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-primitives-v0.8.5...acdp-primitives-v0.9.0) - 2026-09-06

### Added

- [**breaking**] mark AcdpError and VerificationReport #[non_exhaustive] ([#205](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/205))

### Fixed

- *(client)* bind the served ctx_id to the requested one ([#189](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/189)) ([#200](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/200))

## [0.8.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-primitives-v0.8.1...acdp-primitives-v0.8.2) - 2026-08-30

### Other

- *(deps)* bump the major-updates group across 1 directory with 9 updates ([#157](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/157))
- W4-RS hygiene batch (RS-6/7/9/11/12) ([#164](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/164))

## [0.6.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-primitives-v0.6.0...acdp-primitives-v0.6.1) - 2026-07-09

### Other

- release v0.6.0

## [0.6.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-primitives-v0.4.0...acdp-primitives-v0.6.0) - 2026-07-09

### Other

- unify the acdp family to a single lockstep version (0.6.0)

## [0.4.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-primitives-v0.3.0...acdp-primitives-v0.4.0) - 2026-07-06

### Added

- *(error)* add InvalidWitnessCosignature wire code (RFC-ACDP-0015)

## [0.3.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-primitives-v0.2.0...acdp-primitives-v0.3.0) - 2026-07-06

### Other

- *(primitives)* [**breaking**] make acdp::types the canonical WireError path

## [0.2.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-primitives-v0.1.1...acdp-primitives-v0.2.0) - 2026-07-05

### Added

- [**breaking**] lifecycle events & retraction — RFC-ACDP-0013 (acdp/0.3.0 draft)
- *(error)* typed wire codes for the 0.3.0 RFCs — invalid_log_proof, immutable_field, invalid_lifecycle_transition

### Other

- Merge feature/rfc-0014-revocation: RFC-ACDP-0014 SDK surface

## [0.1.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-primitives-v0.1.0...acdp-primitives-v0.1.1) - 2026-06-24

### Other

- release

## [0.1.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/releases/tag/acdp-primitives-v0.1.0) - 2026-06-24

### Other

- split acdp into a fine-grained Cargo workspace
