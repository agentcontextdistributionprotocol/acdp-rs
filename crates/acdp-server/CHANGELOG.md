# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.10.0...acdp-server-v0.10.1) - 2026-09-10

### Added

- *(client)* assemble revocation lineages so the earliest-T rule can actually apply ([#226](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/226)) ([#239](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/239))
- *(server)* add publish_unverified_in_tenant_for_tests ([#237](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/237))

## [0.10.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.9.1...acdp-server-v0.10.0) - 2026-09-07

### Added

- *(server)* [**breaking**] enforce the RFC-ACDP-0014 §4 supersedes row at publish ([#227](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/227))

## [0.9.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.9.0...acdp-server-v0.9.1) - 2026-09-06

### Added

- *(server)* enforce RFC-ACDP-0014 §4/§5 key-revocation validation at publish ([#207](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/207)) ([#217](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/217))

## [0.9.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.8.5...acdp-server-v0.9.0) - 2026-09-06

### Other

- release v0.8.5 ([#187](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/187))

## [0.8.5](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.8.4...acdp-server-v0.8.5) - 2026-08-31

### Other

- release v0.8.4 ([#181](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/181))

## [0.8.3](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.8.2...acdp-server-v0.8.3) - 2026-08-30

### Added

- *(bindings)* expose anchors (RFC-ACDP-0016) in acdp-py and acdp-node ([#175](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/175))

## [0.8.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.8.1...acdp-server-v0.8.2) - 2026-08-30

### Added

- *(types)* add anchors support (RFC-ACDP-0016, 0.5.0) ([#169](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/169))

### Other

- *(deps)* bump the major-updates group across 1 directory with 9 updates ([#157](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/157))
- W4-RS hygiene batch (RS-6/7/9/11/12) ([#164](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/164))

## [0.8.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.8.0...acdp-server-v0.8.1) - 2026-07-10

### Other

- release v0.8.0 ([#128](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/128))

## [0.8.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.6.2...acdp-server-v0.8.0) - 2026-07-10

### Other

- unify the whole ecosystem to 0.8.0 and auto-release the SDKs ([#127](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/127))

## [0.6.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.6.1...acdp-server-v0.6.2) - 2026-07-10

### Added

- *(server)* publish_pinned_verified_in_tenant for operator-pinned keys ([#116](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/116))

## [0.6.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.3.2...acdp-server-v0.6.1) - 2026-07-09

### Other

- release v0.6.0
- unify the acdp family to a single lockstep version (0.6.0)

## [0.6.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.3.2...acdp-server-v0.6.0) - 2026-07-09

### Other

- unify the acdp family to a single lockstep version (0.6.0)

## [0.3.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.3.1...acdp-server-v0.3.2) - 2026-07-06

### Other

- updated the following local packages: acdp-primitives, acdp-types, acdp-safe-http, acdp-did, acdp-crypto, acdp-validation, acdp-verify, acdp-producer

## [0.3.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.3.0...acdp-server-v0.3.1) - 2026-07-06

### Other

- updated the following local packages: acdp-primitives, acdp-safe-http, acdp-did, acdp-crypto, acdp-types, acdp-validation, acdp-verify, acdp-producer

## [0.3.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.2.0...acdp-server-v0.3.0) - 2026-07-05

### Added

- [**breaking**] lifecycle events & retraction — RFC-ACDP-0013 (acdp/0.3.0 draft)

### Other

- rustfmt after integration merges
- Merge feature/rfc-0012-log-verification: RFC-ACDP-0012 SDK surface

## [0.2.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-server-v0.1.0...acdp-server-v0.2.0) - 2026-07-05

### Added

- *(server)* mint lineage-head receipts on /current (RFC-ACDP-0011 §6)
- feat!(types): 0.3.0 capabilities surface — limits.max_publish_per_minute + version-conditional idempotency rule
- *(tracing)* instrument verify pipeline and server publish path
- *(types)* Body::from_publish_request — single PublishRequest→Body materialization point (IMP-02)

## [0.1.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/releases/tag/acdp-server-v0.1.0) - 2026-06-24

### Other

- split acdp into a fine-grained Cargo workspace
