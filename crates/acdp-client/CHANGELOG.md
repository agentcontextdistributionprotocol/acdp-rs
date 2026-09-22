# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.14.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.14.0...acdp-client-v0.14.1) - 2026-09-22

### Fixed

- post-release review of the RFC-0014 wave — 3 bugs, coverage gaps, doc drift ([#296](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/296))

## [0.14.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.13.2...acdp-client-v0.14.0) - 2026-09-22

### Added

- *(types,validation)* [**breaking**] EmbeddedContent.content_hash + did:key resolver errors (#284, #285) ([#288](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/288))

### Fixed

- *(client)* restore Send on revocation-discovery futures ([#289](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/289))

## [0.13.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.13.1...acdp-client-v0.13.2) - 2026-09-13

### Other

- *(client)* extract shared revocation discovery engine ([#272](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/272))

## [0.13.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.13.0...acdp-client-v0.13.1) - 2026-09-12

### Added

- *(client)* revocation discovery budget, cache, and resolver injection (#257, #258, #260) ([#263](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/263))

## [0.13.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.12.0...acdp-client-v0.13.0) - 2026-09-11

### Added

- *(client)* [**breaking**] discover revocations in the verify pipeline ([#256](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/256))

## [0.12.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.11.0...acdp-client-v0.12.0) - 2026-09-11

### Fixed

- *(client)* [**breaking**] propagate transient verification failures in revocation discovery ([#248](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/248)) ([#253](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/253))

## [0.11.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.10.1...acdp-client-v0.11.0) - 2026-09-11

### Fixed

- *(client)* [**breaking**] make fetch_report* honor the caller's VerificationPolicy

## [0.10.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.10.0...acdp-client-v0.10.1) - 2026-09-10

### Added

- *(client)* assemble revocation lineages so the earliest-T rule can actually apply ([#226](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/226)) ([#239](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/239))

## [0.10.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.9.1...acdp-client-v0.10.0) - 2026-09-07

### Other

- *(changelog)* backfill the 0.9.1 stanza for eight sub-crates ([#220](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/220))

## [0.9.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.9.0...acdp-client-v0.9.1) - 2026-09-06

### Other

- release v0.9.1 ([#213](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/213))

## [0.9.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.8.5...acdp-client-v0.9.0) - 2026-09-06

### Added

- [**breaking**] mark AcdpError and VerificationReport #[non_exhaustive] ([#205](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/205))

### Fixed

- *(client)* enforce query scope and trust class in find_revocations ([#191](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/191)) ([#204](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/204))
- *(client)* bind the served ctx_id to the requested one ([#189](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/189)) ([#200](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/200))

### Other

- release v0.8.5 ([#187](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/187))

## [0.8.5](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.8.4...acdp-client-v0.8.5) - 2026-08-31

### Other

- release v0.8.4 ([#181](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/181))

## [0.8.4](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.8.3...acdp-client-v0.8.4) - 2026-08-30

### Other

- release v0.8.3 ([#178](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/178))

## [0.8.3](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.8.2...acdp-client-v0.8.3) - 2026-08-30

### Other

- release v0.8.3 ([#176](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/176))

## [0.8.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.8.1...acdp-client-v0.8.2) - 2026-08-30

### Other

- *(deps)* bump the major-updates group across 1 directory with 9 updates ([#157](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/157))
- W4-RS hygiene batch (RS-6/7/9/11/12) ([#164](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/164))

## [0.8.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.8.0...acdp-client-v0.8.1) - 2026-07-10

### Other

- release v0.8.0 ([#128](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/128))

## [0.8.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.6.2...acdp-client-v0.8.0) - 2026-07-10

### Other

- unify the whole ecosystem to 0.8.0 and auto-release the SDKs ([#127](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/127))

## [0.6.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.4.1...acdp-client-v0.6.1) - 2026-07-09

### Other

- release v0.6.0
- unify the acdp family to a single lockstep version (0.6.0)

## [0.6.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.4.1...acdp-client-v0.6.0) - 2026-07-09

### Other

- unify the acdp family to a single lockstep version (0.6.0)

## [0.4.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.4.0...acdp-client-v0.4.1) - 2026-07-06

### Added

- *(client)* witness cosignature verification, quorum, and safe mint (RFC-ACDP-0015)

### Other

- *(conformance)* bind wit-001..004 witness-cosigning fixtures (RFC-ACDP-0015)

## [0.4.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.3.0...acdp-client-v0.4.0) - 2026-07-06

### Added

- *(client)* [**breaking**] add RegistryClient::builder, deprecate new_pinned

### Other

- *(client)* drop the private-item intra-doc link in RegistryClientBuilder::build
- *(client)* [**breaking**] encapsulate VerifiedContext behind accessors

## [0.3.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.2.0...acdp-client-v0.3.0) - 2026-07-05

### Added

- feat!(client): hard-gate SSRF-relaxed test constructors behind test-transport
- *(revocation)* producer key-revocation signal (RFC-ACDP-0014, rev-001/rev-002)

### Other

- Merge feature/rfc-0014-revocation: RFC-ACDP-0014 SDK surface

## [0.2.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-client-v0.1.0...acdp-client-v0.2.0) - 2026-07-05

### Added

- *(client)* verify lineage-head receipts on /current (RFC-ACDP-0011 §7)
- *(client)* fallible WebResolver constructors; feature-gate SSRF-relaxed test constructors behind test-transport

## [0.1.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/releases/tag/acdp-client-v0.1.0) - 2026-06-24

### Other

- split acdp into a fine-grained Cargo workspace
