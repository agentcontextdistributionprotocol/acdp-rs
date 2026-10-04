# Security Policy

`acdp-rs` implements protocol-critical cryptographic operations (JCS
canonicalization, SHA-256 content hashing, Ed25519 signing/verification, DID
resolution). We take security reports seriously.

## Supported versions

Only the latest minor release line receives security fixes (currently
`0.14.x`); older minors are unsupported — upgrade to the latest release.

| Version              | Supported          |
|----------------------|--------------------|
| latest minor (0.14.x) | :white_check_mark: |
| older minors (< 0.14) | :x:                |

## Reporting a vulnerability

**Please do not open a public GitHub issue.** Instead:

- Use GitHub's [private vulnerability reporting](https://github.com/agentcontextdistributionprotocol/acdp-rs/security/advisories/new) form, or
- Email the maintainers at `security@acdp.dev` (PGP key on request).

Please include:
- A description of the issue and its impact.
- Steps to reproduce, or a minimal proof-of-concept.
- The version (or commit hash) you tested against.
- Whether the issue affects published `crates.io` releases or only `main`.

We aim to acknowledge reports within **3 business days** and to provide a
remediation plan within **14 days** for confirmed vulnerabilities.

## Out of scope

The following are not considered vulnerabilities in this crate:
- Bugs in upstream dependencies (please report those upstream).
- DoS via maliciously large payloads at deserialization (mitigated by the
  registry's `limits.max_payload_bytes`; not enforced by this crate's parser).
- Misuse of the `SigningKey` API in a way that leaks the seed before
  zeroization (e.g., storing the seed in a `Vec<u8>` that outlives the key).

## Responsible defaults applied automatically

When you use the public client APIs (`RegistryClient`, `WebResolver`,
`CrossRegistryResolver`, `Verifier`), these protections apply without any
opt-in:

| Defense | Source | Where it lives |
|---|---|---|
| HTTPS-only for outbound calls | RFC-ACDP-0006 §7.2 | `safe_http::SsrfPolicy` |
| IP-literal rejection (forces DNS) | §7.1 | `safe_http::SsrfPolicy` |
| Private/loopback/link-local IPv4 + IPv6 + IMDS blocking | §7.1 | `safe_http::SsrfPolicy` |
| 5 s connect / 30 s total request timeout | §7.4 | `RegistryClient`, `WebResolver` |
| 1 MB context body cap, 64 KB capabilities/DID-doc cap | §7.3 | `client::registry::read_body_capped` |
| Max 3 redirects, same authority only | §7.5 | both clients |
| Ed25519 mandatory for signature verification | RFC-ACDP-0001 §5.10 | `crypto::verify` |
| Algorithm-downgrade rejection (signature.algorithm vs declared method type) | RFC-ACDP-0008 §3.9 | `crypto::verify::Verifier::verify_body` |
| Embedded data ≤ 64 KB decoded | RFC-ACDP-0002 §6.3 | `validation::validate_data_ref` |
| Embedded `embedded.content_hash` verified when present | RFC-ACDP-0002 §6.3/§6.6, RFC-ACDP-0003 §2.1 step 3 | `validation::verify_embedded_hash` (also wired into `PublishValidator`) |
| Cross-registry resolver verifies registry DID document binding | RFC-ACDP-0006 §4.1 step 3 | `client::cross_registry::CrossRegistryResolver::resolve` |
| Tag / DID / ctx_id pattern checks at validation | schema | `validation` module |
| Producer-side timestamp truncation to ms | RFC-ACDP-0001 §5.3 | `time::trunc_ms` |
| Wire-error → typed error mapping | RFC-ACDP-0007 §5 | `AcdpError::from_wire_error` |
| `Status` open enum (forward compat) | RFC-ACDP-0004 §4.1 | `types::Status` |

DNS-rebinding protection (RFC-ACDP-0006 §7.6) is **active**: every HTTP client
the crate builds filters resolved IPs through the SSRF policy at DNS time,
before connecting. See
[docs/security.md](docs/security.md#dns-rebinding-protection-is-active),
including how the refusal surfaces as an error on each path.
