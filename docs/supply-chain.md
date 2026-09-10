# Supply-chain security

**Crate**: `acdp` &nbsp;|&nbsp; **Scope**: build provenance, action pinning, dependency vetting

`acdp` is a cryptographic-protocol SDK: the code that verifies producer
signatures and enforces the SSRF/HTTPS defenses is exactly the code an attacker
would most like to tamper with between our CI and your `Cargo.lock` /
`node_modules` / site-packages. This page documents the controls that make a
released artifact **traceable back to a specific commit built by this repo's
CI**, how *you* verify that, and how contributors keep the dependency graph
vetted.

Four layers, each independently verifiable:

| Layer | Control | Where |
|---|---|---|
| Released artifacts | Build provenance / signed attestations | npm `--provenance`, PyPI PEP 740, GitHub `attest-build-provenance` |
| CI itself | Every third-party Action pinned to a commit SHA | `.github/workflows/*` |
| Dependency graph | `cargo vet` — every dep audited or explicitly exempted (BLOCKING CI gate) | `supply-chain/` |
| Advisories & licenses | `cargo deny` | `deny.toml`, CI |

---

## 1. Verifying a released artifact came from this repo

Every publishable artifact this repo produces carries provenance minted from the
release workflow's OIDC identity. The mechanism differs per ecosystem.

### npm (`acdp` Node SDK)

Published by [`bindings-release.yml`](../.github/workflows/bindings-release.yml)
with **npm provenance** (`npm publish --provenance`, plus
`NPM_CONFIG_PROVENANCE=true` for the `napi prepublish` platform packages). The
publish job holds `id-token: write`, and npm mints a signed provenance
statement (Sigstore-backed) linking the tarball to this repo, workflow, and
commit.

```bash
# The registry shows a "Provenance" panel on the package page; from the CLI:
npm view acdp --json | jq '.dist.attestations'      # provenance present?
npm audit signatures                                  # verify install-time
```

On npm's website the package page displays a green **"Built and signed on GitHub
Actions"** badge with the source repo, commit, and workflow file.

> First-release note: npm provenance requires **npm ≥ 9.5** (the release runner
> uses Node 20 → npm ≥ 10, so this is satisfied) and a public package. On the
> *first* provenance-enabled publish, confirm the badge appears on
> `https://www.npmjs.com/package/acdp` and that `npm audit signatures` passes
> for a fresh install — this is the one step that can only be checked against
> the live registry.

### npm (`@agentcontextdistributionprotocol/acdp-wasm` — browser WebAssembly verifier)

Published by
[`acdp-wasm-release.yml`](../.github/workflows/acdp-wasm-release.yml) on an
`acdp-wasm-v*` tag with the same **npm provenance** mechanism as the Node SDK
(`npm publish --provenance --access public`, publish job holds
`id-token: write`). The job also attests the raw `.wasm` with
`actions/attest-build-provenance` before publishing, so the module carries
both an npm provenance statement and a GitHub SLSA attestation.

```bash
npm view @agentcontextdistributionprotocol/acdp-wasm --json | jq '.dist.attestations'
npm audit signatures

# Verify the raw wasm module against this repo:
gh attestation verify ./node_modules/@agentcontextdistributionprotocol/acdp-wasm/acdp_wasm_bg.wasm \
    --repo agentcontextdistributionprotocol/acdp-rs
```

**This attestation is the trust root, not byte reproduction** — for every release
through `acdp-wasm-v0.8.5` the published module embeds runner-absolute paths and
cannot be independently rebuilt to a matching hash on your own machine. Releases built
after `--remap-path-prefix` + the in-job determinism gate landed (#196c) are proven
reproducible same-runner, by the gate itself; cross-runner reproduction (e.g. your
laptop vs. `ubuntu-latest`) is plausible given a matching toolchain but has not been
tested by anyone. See `docs/release-runbook.md`'s "Reproducibility of the `acdp-wasm`
artifact" section for exactly which releases that covers and why an unexplained byte
delta between two releases is not automatically a red flag.

### PyPI (`acdp` Python SDK)

Published by [`acdp-py-release.yml`](../.github/workflows/acdp-py-release.yml)
via `pypa/gh-action-pypi-publish` with `attestations: true` and **PyPI Trusted
Publishing** (OIDC, no long-lived token). Each wheel/sdist gets a **PEP 740**
digital attestation uploaded alongside it.

- On the PyPI release page, each file shows a **"Verified details / provenance"**
  section naming the GitHub repo + workflow.
- Programmatically, the attestations are served from PyPI's integrity API
  (`https://pypi.org/integrity/acdp/<version>/<filename>/provenance`).

> First-release note: PyPI attestations are default-on when `id-token: write`
> is present; we set `attestations: true` explicitly so the guarantee is visible
> and cannot silently regress. On the first attested release, confirm the
> provenance section renders on the PyPI file listing.

### GitHub build-provenance (raw wheels, sdist, `.node` prebuilts)

Independently of the registry mechanisms above, the build jobs attest every
**raw binary artifact** before it is uploaded, using
`actions/attest-build-provenance`. This produces a signed SLSA provenance
statement (stored via GitHub's attestations API) binding the artifact's SHA-256
to this repo + workflow + commit. Belt and suspenders: it covers the artifact
even if you obtained it outside the registry.

```bash
# Verify a downloaded wheel / sdist / .node against this repo:
gh attestation verify ./acdp-0.3.0-cp39-abi3-manylinux_2_17_x86_64.whl \
    --repo agentcontextdistributionprotocol/acdp-rs

gh attestation verify ./acdp.linux-x64-gnu.node \
    --repo agentcontextdistributionprotocol/acdp-rs
```

A pass prints the workflow, commit SHA, and signer identity. A mismatch (or an
artifact never built here) fails closed.

### crates.io (`acdp` and the workspace crates)

`acdp` is published to crates.io by
[`release-plz.yml`](../.github/workflows/release-plz.yml), which drives
`cargo publish`. **Status: documented follow-up, deliberately conservative.**

- `cargo publish` today has no build-provenance / attestation mechanism
  comparable to npm `--provenance` or PyPI PEP 740.
- crates.io **Trusted Publishing** (OIDC, no long-lived `CARGO_REGISTRY_TOKEN`)
  is being rolled out upstream. We have **not** altered release-plz's
  version/publish flow to adopt it yet — doing so touches the release
  machinery and is out of scope for a conservative supply-chain pass.
- Migration plan (tracked in the workflow header comment): when
  `release-plz-action` documents an `id-token: write` OIDC path, add
  `permissions: id-token: write` to the release-plz **job only** and drop
  `CARGO_REGISTRY_TOKEN`.

Until then, crate integrity rests on crates.io's own immutable-version guarantee
plus the `Cargo.lock` checksums, and provenance for the *contents* is available
via the GitHub build-provenance attestations above (same commits, same CI).

---

## 2. GitHub Actions pinning policy

**Policy (one consistent rule, applied repo-wide):**

- **Third-party Actions are pinned to a full 40-character commit SHA**, with a
  trailing `# vX.Y.Z` (or ref-name) comment for human readability. A moving tag
  like `@v2` is a mutable pointer the upstream owner can re-target at any commit;
  a SHA is immutable. This is the [OpenSSF Scorecard "Pinned-Dependencies"
  control](https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies).
- **First-party `actions/*` Actions MAY stay on a major version tag** (`@v4`,
  `@v5`). These are maintained by GitHub itself under the same trust boundary as
  the runner; pinning them buys little and costs a lot of churn. This covers
  `actions/checkout`, `actions/setup-node`, `actions/setup-python`,
  `actions/upload-artifact`, `actions/download-artifact`, and
  `actions/attest-build-provenance`.

### Special cases (ref name doubles as configuration)

Two upstreams use the *ref name* to select behavior. Pinning them to a SHA
**preserves that behavior**, because each behavior lives on its own branch/tag
whose `action.yml` bakes in the default:

- **`dtolnay/rust-toolchain@stable|nightly|1.86.0`** — the `stable` branch's
  `action.yml` defaults `toolchain: stable`, `nightly` → `nightly`, and the
  `1.86.0` branch hard-codes `toolchain: 1.86.0`. We pin each ref to *its own*
  branch SHA, so no explicit `toolchain:` input is needed and the toolchain
  selection is unchanged.
- **`taiki-e/install-action@cargo-deny|cargo-fuzz|…`** — each tool shorthand is a
  tag whose `action.yml` defaults `tool:` to that tool, so the ref name alone
  would resolve the right *tool*. It does **not**, however, pin the right
  *version* of that tool: the shorthand tag's `action.yml` only fixes which
  tool the Action installs, not which release, and that release is looked up
  at runtime from a per-tool manifest baked into the same commit. We
  therefore also set `with: tool: <name>@<version>` on every step (see
  "Pinned-tool inventory" below) — that explicit `@<version>` is what's
  actually load-bearing here, not the shorthand tag.

The trailing comment on these records the ref name (`# stable`, `# cargo-deny`)
rather than a semver, because that is what identifies the pinned behavior.

### Pinned-action inventory

| Action | Pinned SHA | Version / ref |
|---|---|---|
| `Swatinem/rust-cache` | `f0d9c3887740aee45f6153b24b3a6b815192ec16` | v2.9.1 |
| `dtolnay/rust-toolchain` (stable) | `4be7066ada62dd38de10e7b70166bc74ed198c30` | stable branch |
| `dtolnay/rust-toolchain` (nightly) | `efcb852328a9f50117170cc43094fb6f09eaf1ae` | nightly branch |
| `dtolnay/rust-toolchain` (1.86.0) | `2767295e193a2ee92d23c1ff586f596cb6d94a7a` | 1.86.0 branch |
| `taiki-e/install-action` (cargo-deny) | `0751bff5da373f43f04fdc57a72795931a822bd7` | cargo-deny tag |
| `taiki-e/install-action` (cargo-semver-checks) | `7b8d4719ee4aaa279bdf55df38dacb9ebfe12a6c` | v2.87.6 |
| `taiki-e/install-action` (cargo-llvm-cov) | `7c1105379b6217809b9ed26c163a46c65c7a528f` | cargo-llvm-cov tag |
| `taiki-e/install-action` (cargo-fuzz) | `82fc405565b9cf90abfe700ba43b4751ce2fe422` | cargo-fuzz tag |
| `taiki-e/install-action` (cargo-vet) | `c0ae9b92c15529ec87e792a1233f3f4a6c726bfa` | cargo-vet tag |
| `mlugg/setup-zig` | `d1434d08867e3ee9daa34448df10607b98908d29` | v2.2.1 |
| `PyO3/maturin-action` | `e83996d129638aa358a18fbd1dfb82f0b0fb5d3b` | v1.51.0 |
| `pypa/gh-action-pypi-publish` | `dc37677b2e1c63e2034f94d8a5b11f265b73ba33` | release/v1 (v1.14.0) |
| `peter-evans/repository-dispatch` | `28959ce8df70de7be546dd1250a005dd32156697` | v4.0.1 |
| `MarcoIeni/release-plz-action` | `aec534bbd8631793b9b3b8f1ee6cd886c322e17f` | v0.5.133 |
| `codecov/codecov-action` | `fb8b3582c8e4def4969c97caa2f19720cb33a72f` | v7.0.0 |
| `dependabot/fetch-metadata` | `25dd0e34f4fe68f24cc83900b1fe3fe149efef98` | v3.1.0 |

**First-party (major tag by policy):** `actions/checkout@v7`,
`actions/setup-node@v7`, `actions/setup-python@v7`, `actions/upload-artifact@v7`,
`actions/download-artifact@v8`, `actions/attest-build-provenance@v4`,
`actions/create-github-app-token@v3`.

### Pinned-tool inventory (`taiki-e/install-action`)

Pinning the *Action* to a SHA is not sufficient on its own for
`taiki-e/install-action`: it resolves the tool version to install from a
per-tool manifest file that is baked into the Action's commit, so an
unpinned `tool: cargo-deny` step can start installing a different
`cargo-deny` release the day upstream cuts a new manifest on that same SHA's
branch — the SHA pin freezes the *installer*, not the *installed bytes*.
Every `tool:` input in this repo is therefore pinned `tool: <name>@<version>`
in addition to the SHA, and each version below was checked against the
manifest at the pinned SHA at the time it was written down (`gh api
repos/taiki-e/install-action/contents/manifests/<tool>.json?ref=<sha>`).

That check on its own is not enough to make a mismatch fail loudly, though.
`taiki-e/install-action`'s `fallback` input **defaults to `cargo-binstall`**,
so if a pinned version is later found to be absent from the manifest (drift,
or a mistake at pin time), the step does not error — it logs a warning and
silently reinstalls the tool from **QuickInstall, a third-party rebuild
service**, not the verified upstream release. This has already happened in
this repo (see the `cargo-vet` row below). Every other step in this repo
therefore sets `fallback: none`, which is what actually converts a missing
version into a hard install failure — with two exceptions, both documented
as known gaps below: the `cargo-fuzz` SHA predates the `fallback` input
existing at all (its `action.yml` at that commit only has
`tool`/`checksum`), so there is no `fallback: none` to set there — the
cargo-binstall fallback is unconditional and cannot be disabled at that
pin, meaning a missing version would silently reinstall from QuickInstall
rather than hard-failing; and `cargo-vet`, whose `fallback` is set
explicitly to `cargo-binstall` because `none` is not viable there — see the
"Known gap" callouts below.

| Tool | `tool:` pin | Installed via (`install-action` SHA) | `fallback` | Workflow(s) |
|---|---|---|---|---|
| `wasm-pack` | `wasm-pack@0.15.0` | `0751bff5da373f43f04fdc57a72795931a822bd7` | `none` | `acdp-wasm-release.yml`, `bindings.yml` |
| `cargo-deny` | `cargo-deny@0.19.9` | `0751bff5da373f43f04fdc57a72795931a822bd7` | `none` | `ci.yml`, `bindings.yml` |
| `cargo-llvm-cov` | `cargo-llvm-cov@0.8.7` | `7c1105379b6217809b9ed26c163a46c65c7a528f` | `none` | `ci.yml` |
| `cargo-fuzz` | `cargo-fuzz@0.11.2` | `82fc405565b9cf90abfe700ba43b4751ce2fe422` | `cargo-binstall`, unconditional — no `fallback` input exists at this SHA to disable it (known gap, see below) | `fuzz.yml` (build + run jobs) |
| `cargo-vet` | `cargo-vet@0.10.2` | `c0ae9b92c15529ec87e792a1233f3f4a6c726bfa` | `cargo-binstall` (known gap, see below) | `ci.yml` |
| `cargo-semver-checks` | `cargo-semver-checks@0.50.0` | `7b8d4719ee4aaa279bdf55df38dacb9ebfe12a6c` | `none` | `ci.yml` |

**Known gap — `cargo-vet@0.10.2`:** no `install-action` manifest, at any
SHA, carries `cargo-vet` 0.10.2 — checked through the latest release,
v2.87.7: `manifests/cargo-vet.json` there contains only `0.10` / `0.10.0`
(`latest = 0.10.0`). Upstream has never published a manifest entry for
0.10.2, so unlike every other tool in this table, **bumping the
`install-action` SHA cannot close this gap** — there is no SHA to bump to.
Downgrading the `tool:` pin to `0.10.0` (the version actually in the
manifest) is not available either: `cargo-vet 0.10.0` cannot parse this
repo's `supply-chain/imports.lock` (crates.io "trusted publisher" entries,
e.g. `[[publisher.wit-bindgen]]`, need a schema newer than 0.10.0 supports —
verified locally: `missing field `user-id``), and regenerating the lockfile
with 0.10.0 would discard that trusted-publisher data. With both a SHA bump
and a downgrade ruled out, `fallback: none` (used everywhere else in this
table) would simply hard-fail a required status check on every run. So this
one step sets `fallback: cargo-binstall` explicitly instead of relying on
the (identical) implicit default, to make the behavior visible rather than
silent: `cargo-vet` 0.10.2 is installed via **cargo-binstall from
QuickInstall, a third-party rebuild**, not a verified upstream release
artifact. This is a known, accepted gap, not an oversight — it is the one
tool in this table not installed from a verified upstream artifact, and it
happens to be the tool that audits this repo's own supply chain. Tracked
upstream: [taiki-e/install-action#1997](https://github.com/taiki-e/install-action/issues/1997)
(requesting a 0.10.2 manifest entry).

**Known gap — `cargo-fuzz@0.11.2`:** the `install-action` SHA pinned above
(`82fc4055…`) predates the `fallback` input entirely — its `action.yml` at
that commit defines only `tool`/`checksum`, not `fallback`. That means the
cargo-binstall fallback that `install-action` applies whenever a pinned
version is absent from its manifest **is unconditional at this SHA and
cannot be turned off**: there is no `fallback: none` to set the way every
other tool in this table can. A future bump of the `cargo-fuzz@0.11.2` pin to a
version absent from this SHA's manifest would therefore silently reinstall
from QuickInstall, a third-party rebuild, rather than hard-failing the
fuzz job. Today this is inert: `cargo-fuzz` 0.11.2 IS present in this SHA's
manifest and equals its `latest`, so nothing installs from QuickInstall
right now. Unlike the `cargo-vet` gap above, **bumping the SHA does not
close this gap — it cannot**: `manifests/cargo-fuzz.json` does not exist
at all as of `0751bff5` (the SHA this table uses for `wasm-pack` /
`cargo-deny`) — cargo-fuzz has been dropped from install-action's
supported tool set entirely (also gone from its `TOOLS.md`), so any newer
SHA guarantees a permanent manifest miss: silent QuickInstall under the
default `fallback`, or a hard-failing fuzz job if `fallback: none` were
added anyway. This is a known, accepted gap, not an oversight: the pinned
version is verified correct today, and the blast radius is lower than the
`cargo-vet` gap above — this only gates the fuzz job (weekly schedule +
its own PR-triggered build check), not a required status check on `main`.
There is no available upstream fix to track (no manifest exists to
request).

### Updating a pinned Action

Resolve the new SHA from the tag and update both the SHA and the comment:

```bash
gh api repos/OWNER/REPO/commits/TAG --jq .sha
# then edit `- uses: OWNER/REPO@<new-sha> # TAG` in the workflow
```

Dependabot (`.github/dependabot.yml`, if enabled for `github-actions`) will
open PRs that bump the SHA and keep the comment in sync.

---

## 3. Dependency vetting with `cargo vet`

Every third-party crate in the **locked** dependency graph must be covered by
one of: (a) a local audit we performed, (b) an audit imported from a trusted
external set, or (c) an explicit exemption. This is enforced by a **BLOCKING**
CI job — a new or version-bumped dependency that is not yet covered fails the
build.

```bash
cargo vet --locked        # what CI runs; must be green
```

Config lives under [`supply-chain/`](../supply-chain/):

| File | Role |
|---|---|
| `config.toml` | Trusted import sources, per-crate policy, and the `exemptions` block (the vetted-but-not-yet-audited long tail). |
| `audits.toml` | **Our own** audit certifications (the crypto-critical set). |
| `imports.lock` | Frozen snapshot of the imported audit sets — committed so `--locked` is reproducible. |

### Imported audit sets

We import the shared audit sets from three organizations that publish their
`cargo vet` audits publicly:

- **Mozilla** — `https://raw.githubusercontent.com/mozilla/supply-chain/main/audits.toml`
- **Google** — `https://raw.githubusercontent.com/google/supply-chain/main/audits.toml`
- **Bytecode Alliance** — `https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/supply-chain/audits.toml`

These cover a large fraction of the common ecosystem (serde, tokio, hyper,
rustls internals, …) so we don't re-audit what better-resourced teams already
have. Refresh them with `cargo vet` (updates `imports.lock`).

### The crypto-critical set — audited by us

The crates that implement or underpin ACDP's signature and TLS security were
inspected and **certified locally** (`safe-to-deploy`), not merely exempted.
The inspection criteria for each: canonical upstream source, latest compatible
release, and no open RUSTSEC advisory (verified locally with `cargo audit`, 2026-07-05). See
`supply-chain/audits.toml` for the full per-crate notes.

| Crate | Version | Upstream | Role in ACDP |
|---|---|---|---|
| `ed25519-dalek` | 2.2.0 | dalek-cryptography | Mandatory signature primitive (RFC-ACDP-0002) |
| `curve25519-dalek` | 4.1.3 | dalek-cryptography | Curve arithmetic under ed25519 (≥4.1.3 fixes the timing advisory) |
| `signature` | 2.2.0 | RustCrypto | Signature traits |
| `sha2` | 0.10.9 | RustCrypto | `content_hash` / `lineage_id` (RFC-ACDP-0001 §5.7) |
| `zeroize` | 1.8.2 | RustCrypto | Secret-key zeroing (`SigningKey` `ZeroizeOnDrop`) |
| `subtle` | 2.6.1 | dalek-cryptography | Constant-time primitives |
| `p256` | 0.13.2 | RustCrypto | P-256 verification-method support |
| `ecdsa` | 0.16.9 | RustCrypto | Generic ECDSA under p256 |
| `elliptic-curve` | 0.13.8 | RustCrypto | Curve trait framework |
| `rustls` | 0.23.40 | rustls | HTTPS transport (RFC-ACDP-0008) |
| `ring` | 0.17.14 | briansmith | Default rustls crypto provider |

### Contributor workflow

**When you add or bump a dependency**, `cargo vet --locked` will fail locally
and in CI until it's covered. Two paths:

- **Certify it** (preferred for anything security-sensitive — crypto, TLS,
  parsing untrusted input, `unsafe`). Actually read the source of that version,
  then:

  ```bash
  cargo vet certify <crate> <version> \
      --criteria safe-to-deploy \
      --who "Your Name <you@example.com>" \
      --notes "Reviewed: <what you checked — unsafe, I/O, build.rs, provenance>."
  ```

  `safe-to-deploy` = safe to ship to users; `safe-to-run` = safe to run in
  dev/CI only (test-only deps). `certify` auto-removes any now-redundant
  exemption.

- **Exempt it** (acceptable for the low-risk long tail — leaf utility crates,
  build-only helpers) when a full audit isn't warranted yet:

  ```bash
  cargo vet add-exemption <crate> <version>   # or edit config.toml's exemptions
  ```

Then run `cargo vet --locked` to confirm green and commit the `supply-chain/`
changes with your PR. Run `cargo vet prune` occasionally to drop exemptions that
an imported audit now covers.

**Who audits.** The crypto-critical set is audited by the crate maintainers and
must stay `safe-to-deploy` with real inspection notes — treat a change there as
a security review, not a rubber stamp. The long-tail exemptions are a
maintenance backlog: prefer converting them to real audits (ours or imported)
over time. First-party workspace crates (`acdp`, `acdp-*`) are configured
`audit-as-crates-io = false` — they're our own code and need no audit or
exemption, and their version bumps therefore never trip the gate.

---

## 4. Advisory and license posture (`cargo deny`)

`cargo deny check` runs alongside `cargo vet` in CI and covers the axes `vet`
does not:

- **`cargo deny check`** ([`deny.toml`](../deny.toml)) — advisories, license
  allow-list, banned/duplicate crates, and source registries. Blocking; the
  **sole** RustSec advisory gate in CI (see the comment at
  `.github/workflows/ci.yml:138-141`). `cargo audit` is not run in CI at all
  and remains an optional local check documented in `CONTRIBUTING.md`.

**Advisory allowlist:** `deny.toml` currently carries **no** `[advisories] ignore`
entries (`ignore = []`) — the tree has no allowlisted advisories. The former
`RUSTSEC-2025-0134` entry (`rustls-pemfile` unmaintained) was retired when
`axum-server` 0.8 switched to `rustls`' built-in PEM helpers, dropping
`rustls-pemfile` from the graph entirely; none of the crypto-critical crates
carries an advisory.

Together: **`vet`** answers "did a human look at this code?", **`deny`**
answers "is there a known-bad advisory or license here?", and the **provenance +
pinning** layers answer "did this actually come from our CI?".
