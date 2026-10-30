# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.19.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-chain-v0.18.3...acdp-chain-v0.19.0) - 2026-10-30

### Added

- *(keyless)* [**breaking**] typed issuer_unreachable and keyless_event_unsupported reasons ([#496](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/496))

## [0.18.3](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-chain-v0.18.2...acdp-chain-v0.18.3) - 2026-10-30

No enum change: no new `KeyAuthorization` or `RevocationTrustClass` variant (and no new `KeylessReason` or `AcdpError` variant). RFC-ACDP-0021 draft.4: a key attestation signed under an attester key that was rotated out of `assertionMethod` but kept in `verificationMethod` now verifies through its receipt (`kl-005` M). A key removed from `verificationMethod` is `attestation_invalid` (`kl-005` N).

### Fixed

- *(keyless)* attestations survive attester key rotation (RFC-ACDP-0021 draft.4) ([#494](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/494))

## [0.18.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-chain-v0.18.1...acdp-chain-v0.18.2) - 2026-10-30

No enum change: no new `KeyAuthorization` or `RevocationTrustClass` variant (and no new `KeylessReason` or `AcdpError` variant). `acdp-chain`'s `Options::keyless_attesters` is deprecated in favour of `pinned.keyless_attesters`.

### Added

- *(keyless)* adopt RFC-ACDP-0021 0.5.0-draft.3 rulings ([#486](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/486))

## [0.18.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-chain-v0.18.0...acdp-chain-v0.18.1) - 2026-10-27

No enum change: no new `KeyAuthorization`, `RevocationTrustClass` or
`UnknownReason` variant. A keyless-signed key revocation found by discovery
is now verified through RFC-ACDP-0021 §8.1 under `VerificationPolicy.keyless`.
It applies when its attestation is org-wide and is only a hint otherwise. One
that cannot be evaluated makes the verdict `unknown` (`unverifiable_candidate`),
never not-revoked; before this fix it was dropped and read as not-revoked.
`acdp-chain` follows the same rules.

### Fixed

- *(keyless)* evaluate keyless-signed key revocations; unknown when unevaluable ([#480](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/480))

## [0.18.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-chain-v0.17.3...acdp-chain-v0.18.0) - 2026-10-26

### Added

- [**breaking**] RFC-ACDP-0021 keyless signing behind the keyless feature ([#478](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/478))
- *(trust)* opt-in refusal of unknown issuer-key revocation; trust-002 K; pin spec 3e0d8b0 ([#471](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/471))

## [0.17.3](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-chain-v0.17.2...acdp-chain-v0.17.3) - 2026-10-26

### Added

- registry trust lists (RFC-ACDP-0020); pin spec a1324f8 ([#467](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/467))

## [0.17.2](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-chain-v0.17.1...acdp-chain-v0.17.2) - 2026-10-26

### Other

- *(chain)* bind chain-011 cross-implementation vectors; pin spec 1511b08 ([#448](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/448))

## [0.17.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-chain-v0.17.0...acdp-chain-v0.17.1) - 2026-10-26

### Fixed

- *(chain,client)* apply the RFC-ACDP-0017/0018 rulings in spec c411d94 and 3d41e31 ([#437](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/437))

## [0.17.0](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-chain-v0.16.1...acdp-chain-v0.17.0) - 2026-10-25

### Added

- [**breaking**] RFC-ACDP-0018 retraction recall (changes feed, hints, acdp-consumer-recall) ([#431](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/431))

## [0.16.1](https://github.com/agentcontextdistributionprotocol/acdp-rs/compare/acdp-chain-v0.16.0...acdp-chain-v0.16.1) - 2026-10-25

### Added

- *(chain)* acdp-chain — RFC-ACDP-0017 offline as-of chain verification ([#417](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/417))
