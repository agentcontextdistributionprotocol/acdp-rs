# Security Policy

`acdp-rs` implements protocol-critical cryptographic operations (JCS
canonicalization, SHA-256 content hashing, Ed25519 and ECDSA-P256
signing/verification, DID resolution). We take security reports seriously.

## Supported versions

Only the latest minor release line receives security fixes; older minors are
unsupported — upgrade to the latest release.

| Version              | Supported          |
|----------------------|--------------------|
| latest minor release   | :white_check_mark: |
| older minors           | :x:                |

## Reporting a vulnerability

Reporting follows the organization-wide
[security policy](https://github.com/agentcontextdistributionprotocol/.github/blob/main/SECURITY.md):
report privately by email to **security@zer07labs.com**.
**Do not open a public GitHub issue.** Response-time targets are stated
in that policy.

Please include:
- A description of the issue and its impact.
- Steps to reproduce, or a minimal proof-of-concept.
- The version (or commit hash) you tested against.
- Whether the issue affects published `crates.io` releases or only `main`.

## Out of scope

The following are not considered vulnerabilities in this crate:
- Bugs in upstream dependencies (please report those upstream).
- DoS via maliciously large payloads at deserialization (mitigated by the
  registry's `limits.max_payload_bytes`; not enforced by this crate's parser).
- Misuse of the `SigningKey` API in a way that leaks the seed before
  zeroization (e.g., storing the seed in a `Vec<u8>` that outlives the key).

## Responsible defaults applied automatically

The public client APIs (`RegistryClient`, `WebResolver`,
`CrossRegistryResolver`, `HttpsDataRefFetcher`) apply their SSRF, size,
timeout, redirect, and signature-verification defenses without any opt-in —
including strict Ed25519 verification, algorithm-downgrade rejection, `ctx_id`
binding of the served body, and DNS-rebinding protection. The full list, with
RFC citations, is maintained in
[docs/security.md → Defenses applied by default](docs/security.md#defenses-applied-by-default);
ECDSA-P256 signing emits low-S signatures — see
[docs/security.md → ECDSA-P256 signatures](docs/security.md#ecdsa-p256-signatures-low-s-on-emit-high-s-accepted).
