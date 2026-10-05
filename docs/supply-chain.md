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

### npm (`@agentcontextdistributionprotocol/acdp` Node SDK)

Published by [`bindings-release.yml`](../.github/workflows/bindings-release.yml)
with **npm provenance** (`npm publish --provenance`, plus
`NPM_CONFIG_PROVENANCE=true` for the `napi prepublish` platform packages). The
publish job holds `id-token: write`, and npm mints a signed provenance
statement (Sigstore-backed) linking the tarball to this repo, workflow, and
commit.

```bash
# The registry shows a "Provenance" panel on the package page; from the CLI:
npm view @agentcontextdistributionprotocol/acdp --json | jq '.dist.attestations'   # provenance present?
npm audit signatures                                  # verify install-time
```

On npm's website the package page displays a green **"Built and signed on GitHub
Actions"** badge with the source repo, commit, and workflow file.

> First-release note: npm provenance requires **npm ≥ 9.5** (the release runner
> uses Node 20 → npm ≥ 10, so this is satisfied) and a public package. On the
> *first* provenance-enabled publish, confirm the badge appears on
> `https://www.npmjs.com/package/@agentcontextdistributionprotocol/acdp` and that `npm audit signatures` passes
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
gh attestation verify ./acdp-<version>-cp39-abi3-manylinux_2_17_x86_64.whl \
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
| `taiki-e/install-action` (cargo-deny) | `0751bff5da373f43f04fdc57a72795931a822bd7` | cargo-deny and wasm-pack install pin |
| `taiki-e/install-action` (cargo-semver-checks) | `7b8d4719ee4aaa279bdf55df38dacb9ebfe12a6c` | v2.87.6 |
| `taiki-e/install-action` (cargo-llvm-cov) | `7c1105379b6217809b9ed26c163a46c65c7a528f` | cargo-llvm-cov tag |
| `taiki-e/install-action` (cargo-fuzz) | `82fc405565b9cf90abfe700ba43b4751ce2fe422` | cargo-fuzz tag |
| `taiki-e/install-action` (cargo-vet) | `c0ae9b92c15529ec87e792a1233f3f4a6c726bfa` | cargo-vet tag |
| `mlugg/setup-zig` | `d1434d08867e3ee9daa34448df10607b98908d29` | v2.2.1 |
| `PyO3/maturin-action` | `e83996d129638aa358a18fbd1dfb82f0b0fb5d3b` | v1.51.0 |
| `pypa/gh-action-pypi-publish` | `dc37677b2e1c63e2034f94d8a5b11f265b73ba33` | release/v1 (v1.14.0) |
| `peter-evans/repository-dispatch` | `28959ce8df70de7be546dd1250a005dd32156697` | v4.0.1 |
| `MarcoIeni/release-plz-action` | `b8d6b54b02889ff2ae2bb82e8b57c3a8fc1683a5` | v0.5.139 |
| `codecov/codecov-action` | `303a32d7a59b442fa8d48b6a1cc6825c09c847a5` | v7.1.1 |
| `dependabot/fetch-metadata` | `25dd0e34f4fe68f24cc83900b1fe3fe149efef98` | v3.1.0 |

**First-party (major tag by policy):** `actions/checkout@v7`,
`actions/setup-node@v7`, `actions/setup-python@v7`, `actions/upload-artifact@v7`,
`actions/download-artifact@v8`, `actions/attest-build-provenance@v4`,
`actions/create-github-app-token@v3`.

**Org-internal reusable workflows (major tag):**
`agentcontextdistributionprotocol/acdp-ci/.github/workflows/bump-spec-ref.yml@v1`.
(This repo no longer calls acdp-ci's `auto-merge.yml@v1`: it armed auto-merge on
every patch/minor Dependabot PR, crypto included. `dependabot-auto-merge.yml`
replaces it; see [Dependabot auto-merge](#dependabot-auto-merge).)
The `v1` tag is moved only by the acdp-ci release procedure; see acdp-ci's
[`DELIVERY-STANDARD.md` → Releasing `acdp-ci` (the `v1` tag)](https://github.com/agentcontextdistributionprotocol/acdp-ci/blob/main/DELIVERY-STANDARD.md#releasing-acdp-ci-the-v1-tag).

To re-check this inventory, every row must match
`grep -ho "uses: [^ ]*@[^ ]*" .github/workflows/*.yml | sort -u`.

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

### Binding toolchain pins

The language-binding builds also pin `maturin`/`pytest`, `@napi-rs/cli`, the wasm
release `rustc`, and `wasm-pack`, and build against committed lockfiles with
`--locked`. The table is in
[Language bindings → Pinned binding toolchain](bindings.md#pinned-binding-toolchain).

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
cargo vet --locked              # what CI runs; must be green
scripts/check-crypto-vet.sh     # also in CI: crypto-critical crates audited (zeroize: documented exemption)
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

### The crypto-critical set

The forty-six crates that implement or underpin ACDP's signature and TLS
security are listed in
[`scripts/crypto-critical.txt`](../scripts/crypto-critical.txt): the eleven
Tier A crates, which issue #322 (completed 2026-10-04) re-certified at the
versions in `Cargo.lock`, and all thirty-five Tier B support crates, certified
by issue #339 (batch B1: `wnaf`, `ff`, `spki`, `crypto-common`, `zeroize_derive`,
`ed25519`; batch B2: `hmac`, `rfc6979`, `pkcs8`, `sec1`, `primefield`,
`digest`; batch B3: `untrusted`, `cpubits`, `hyper-rustls`, `group`,
`tokio-rustls`, `primeorder`; batch B4: `rand_core`, `ctutils`, `webpki-roots`,
`typenum`; batch B5: `base16ct`, `base64ct`, `rustls-pki-types`, `const-oid`,
`der`, `curve25519-dalek-derive`; batch B6: `cpufeatures`, `block-buffer`,
`cmov`, `hybrid-array`, `crypto-bigint`; batch B7a: `getrandom` at all three locked
versions; batch B7b: `rustls-webpki`). **Forty-five of the forty-six are
covered by our own audit at every locked version. `zeroize` is the one deliberate
exception:** it stays exempt under the #322 concern rule. The per-crate review worksheets are in
[`supply-chain/worksheets/`](../supply-chain/worksheets/), and the notes are in
`supply-chain/audits.toml`.

**What a `safe-to-deploy` audit here claims.** The reviewer read the code at
that exact version, or the diff from an audited version. The tarball sha256 was
checked against the `Cargo.lock` checksum. Every `unsafe` block, `asm!`, build
script, and powerful import (filesystem, network, process, or environment
access) was reasoned about. **It does not claim** cryptographic correctness,
constant-time behaviour, side-channel resistance, or (for rustls and
rustls-webpki) TLS protocol and certificate-validation correctness, including
rustls-webpki's path-validation, name-constraint and revocation logic. Those remain upstream's responsibility.
The 2026-07-05 audits of the older versions recorded less: canonical source,
latest release, and no open advisory.

| Crate | Locked (`Cargo.lock`) | Audited (`audits.toml`) | Locked version covered by | Upstream | Role in ACDP |
|---|---|---|---|---|---|
| `ed25519-dalek` | 3.0.0 | 2.2.0, 2.2.0 → 3.0.0 | audit (delta, 2026-10-04) | dalek-cryptography | Mandatory signature primitive (RFC-ACDP-0002) |
| `curve25519-dalek` | 5.0.0 | 4.1.3, 4.1.3 → 5.0.0 | audit (delta, 2026-10-04; discretion note on the nightly-only `docsrs` path) | dalek-cryptography | Curve arithmetic under ed25519 |
| `signature` | 3.0.0 | 2.2.0, 3.0.0 | audit (full, 2026-10-04) | RustCrypto | Signature traits |
| `sha2` | 0.11.0 | 0.10.9, 0.11.0 | audit (full, 2026-10-04; discretion notes, DECISIONS.md `322-sha2`) | RustCrypto | `content_hash` / `lineage_id` (RFC-ACDP-0001 §5.7) |
| `zeroize` | 1.9.0 | 1.8.2 | **exemption**, kept under the #322 concern rule (DECISIONS.md `322-zeroize`) | RustCrypto | Secret-key zeroing (`SigningKey` `ZeroizeOnDrop`) |
| `subtle` | 2.6.1 | 2.6.1 | audit (2026-07-05) | dalek-cryptography | Constant-time primitives |
| `p256` | 0.14.0 | 0.13.2, 0.14.0 | audit (full, 2026-10-04; discretion note on a test-only fixture) | RustCrypto | `ecdsa-p256` signing and verification-method support |
| `ecdsa` | 0.17.0 | 0.16.9, 0.17.0 | audit (full, 2026-10-04; discretion note on a test-only fixture) | RustCrypto | Generic ECDSA under p256 |
| `elliptic-curve` | 0.14.1 | 0.13.8, 0.14.1 | audit (full, 2026-10-04) | RustCrypto | Curve trait framework |
| `rustls` | 0.23.45 | 0.23.40, 0.23.40 → 0.23.45 | audit (delta, 2026-10-04) | rustls | HTTPS transport (RFC-ACDP-0008) |
| `ring` | 0.17.14 | 0.17.14 | audit (2026-07-05) | briansmith | the only rustls crypto provider, in production (via reqwest's `rustls-tls`) and in the TLS test harness; `aws-lc-rs` is not in the graph (#339) |
| `ed25519` | 3.0.0 | 3.0.0 | audit (full, 2026-10-04, #339 B1; discretion note on test-only fixtures) | RustCrypto | `Signature` byte container under ed25519-dalek |
| `crypto-common` | 0.2.2 | 0.2.2 | audit (full, 2026-10-04, #339 B1) | RustCrypto | Size/key-init traits under `digest`, `sha2`, `elliptic-curve` |
| `zeroize_derive` | 1.5.0 | 1.5.0 | audit (full, 2026-10-04, #339 B1) | RustCrypto | `ZeroizeOnDrop` derive on `acdp-crypto`'s `SigningKey` |
| `spki` | 0.8.0 | 0.8.0 | audit (full, 2026-10-04, #339 B1; discretion note on test-only fixtures) | RustCrypto | SPKI / `AlgorithmIdentifier` types under `ecdsa` |
| `ff` | 0.14.0 | 0.14.0 | audit (full, 2026-10-04, #339 B1) | zkcrypto | Field traits under the P-256 stack |
| `wnaf` | 0.14.1 | 0.14.1 | audit (full, 2026-10-04, #339 B1) | RustCrypto | Variable-time wNAF multiplication under `primeorder` (P-256 verify) |
| `hmac` | 0.13.0 | 0.13.0 | audit (full, 2026-10-04, #339 B2; discretion note on test-only fixtures) | RustCrypto | HMAC under rfc6979 |
| `rfc6979` | 0.6.0 | 0.6.0 | audit (full, 2026-10-04, #339 B2) | RustCrypto | Deterministic ECDSA nonces for P-256 signing |
| `pkcs8` | 0.11.0 | 0.11.0 | audit (full, 2026-10-04, #339 B2; discretion note on test-only fixtures) | RustCrypto | PKCS#8 key encoding under elliptic-curve |
| `sec1` | 0.8.1 | 0.8.1 | audit (full, 2026-10-04, #339 B2; discretion note on a test-only fixture) | RustCrypto | SEC1 point/key encoding (parses untrusted P-256 keys) |
| `primefield` | 0.14.0 | 0.14.0 | audit (full, 2026-10-04, #339 B2) | RustCrypto | Prime-field types under p256 |
| `digest` | 0.11.3 | 0.11.3 | audit (full, 2026-10-04, #339 B2; discretion note on a test-only fixture) | RustCrypto | Hash/MAC traits under sha2, hmac, ecdsa, signature |
| `untrusted` | 0.9.0 | 0.9.0 | audit (full, 2026-10-04, #339 B3; discretion note on packaged CI scripts) | briansmith | Panic-free input reader under ring and rustls-webpki (certificate parsing) |
| `cpubits` | 0.1.1 | 0.1.1 | audit (full, 2026-10-04, #339 B3) | RustCrypto | Compile-time word-size selection under crypto-bigint |
| `hyper-rustls` | 0.27.9 | 0.27.9 | audit (full, 2026-10-04, #339 B3) | rustls | HTTPS connector between reqwest/hyper and rustls |
| `group` | 0.14.0 | 0.14.0 | audit (full, 2026-10-04, #339 B3) | zkcrypto | Elliptic-curve group traits under the P-256 stack |
| `tokio-rustls` | 0.26.4 | 0.26.4 | audit (full, 2026-10-04, #339 B3; discretion note on test-only PEM fixtures) | rustls | Async TLS stream adapter under hyper-rustls and reqwest |
| `primeorder` | 0.14.0 | 0.14.0 | audit (full, 2026-10-04, #339 B3) | RustCrypto | Generic prime-order curve arithmetic under p256 (sign, verify, SEC1 key decoding) |
| `rand_core` | 0.10.1, 0.9.5 | 0.10.1, 0.9.5 | audit (full, 2026-10-04, #339 B4; 0.9.5 is dev-only and now meets `safe-to-deploy`) | rust-random | RNG traits; `UnwrapErr(getrandom::SysRng)` in key generation (0.10.1); proptest's `rand` (0.9.5) |
| `ctutils` | 0.4.2 | 0.4.2 | audit (full, 2026-10-04, #339 B4; constant-time behaviour not claimed) | RustCrypto | Constant-time selection/equality helpers under digest, sec1, crypto-bigint |
| `webpki-roots` | 1.0.9 | 1.0.9 | audit (full, 2026-10-04, #339 B4; table checked against its embedded certificates; root-set correctness not claimed) | rustls | Default trust anchors for every ACDP HTTPS client (reqwest `rustls-tls`) |
| `typenum` | 1.20.1 | 1.20.1 | audit (full, 2026-10-04, #339 B4; generated files shape-checked, impl headers sampled) | paholg | Type-level integers under hybrid-array |
| `base16ct` | 1.0.0 | 1.0.0 | audit (full, 2026-10-04, #339 B5; constant-time behaviour not claimed) | RustCrypto | Hex encoding under sec1 and elliptic-curve (`HexDisplay`, `FromStr`) |
| `base64ct` | 1.8.3 | 1.8.3 | audit (full, 2026-10-04, #339 B5; constant-time behaviour not claimed) | RustCrypto | Lock-only: `spki`'s optional `base64` feature is off, so it is compiled into no ACDP build |
| `rustls-pki-types` | 1.15.1 | 1.15.1 | audit (full, 2026-10-04, #339 B5; discretion note on embedded AlgorithmIdentifier blobs) | rustls | Certificate/key/`ServerName` types and PEM parsing under rustls and reqwest |
| `const-oid` | 0.10.2 | 0.10.2 | audit (full, 2026-10-04, #339 B5; generated OID database shape-checked, feature off) | RustCrypto | OID type under der and digest |
| `der` | 0.8.1 | 0.8.1 | audit (full, 2026-10-04, #339 B5; discretion notes on two safe-code recursion bugs unreachable from ACDP) | RustCrypto | ASN.1 DER codec under ecdsa, sec1, spki (ACDP itself parses no DER) |
| `curve25519-dalek-derive` | 0.1.1 | 0.1.1 | audit (full, 2026-10-04, #339 B5; generated `unsafe` relies on curve25519-dalek's runtime CPU dispatch) | dalek-cryptography | `#[unsafe_target_feature]` proc-macro for curve25519-dalek's x86_64 AVX2/AVX-512 backends |
| `cpufeatures` | 0.3.1 | 0.3.1 | audit (full, 2026-10-04, #339 B6; discretion note on the x86 CPUID max-leaf gap, DECISIONS.md `322-cpufeatures`; correctness of feature detection on every CPU configuration not claimed) | RustCrypto | Runtime CPU-feature detection for sha2 and curve25519-dalek SIMD backends |
| `block-buffer` | 0.12.1 | 0.12.1 | audit (full, 2026-10-04, #339 B6; 21 `unsafe` lines verdicted) | RustCrypto | Block buffering under digest (sha2, hmac) |
| `cmov` | 0.5.4 | 0.5.4 | audit (full, 2026-10-04, #339 B6; x86/aarch64 `asm!` checked for memory safety; constant-time behaviour not claimed) | RustCrypto | Conditional-move primitives under ctutils |
| `hybrid-array` | 0.4.14 | 0.4.14 | audit (full, 2026-10-04, #339 B6; size table script-checked; discretion note on packaged CI files) | RustCrypto | Fixed-size arrays under digest, crypto-bigint, elliptic-curve, sec1 |
| `crypto-bigint` | 0.7.5 | 0.7.5 | audit (full, 2026-10-04, #339 B6; the 37,233 compiled lines were read in full by seven Claude sub-reviews, with every `unsafe` site and the file/line counts independently confirmed by the main review; uncompiled `boxed`/`der`/`rlp` modules grep-only; constant-time behaviour not claimed) | RustCrypto | Big-integer arithmetic under the P-256 stack |
| `getrandom` | 0.4.3, 0.2.17, 0.3.4 | 0.4.3, 0.2.17, 0.3.4 | audit (full, 2026-10-05, #339 B7a; discretion notes on the opt-in `linux_raw` backend, DECISIONS.md `322-getrandom`, and on nightly/tier-3 backends; 0.3.4 is dev-only and meets `safe-to-deploy`; RNG output quality not claimed) | rust-random | OS RNG: `UnwrapErr(SysRng)` in key generation (0.4.3); ring's `SystemRandom` under rustls (0.2.17; uncalled in the wasm binding, #363); proptest's `rand` (0.3.4) |
| `rustls-webpki` | 0.103.15 | 0.103.15 | audit (full, 2026-10-05, #339 B7b; 0 `unsafe`; DECISIONS.md `322-rustls-webpki`; bounded path-building DoS cost recorded as an observation; certificate-validation correctness not claimed) | rustls | Certificate path validation behind rustls's `WebPkiServerVerifier` for every ACDP HTTPS client (trust boundary); its CRL code is compiled but unreached |

**`zeroize` 1.9.0 is exempt, not audited.** Its new safe
`optimization_barrier` reads a possibly-uninitialized byte on targets without
stable `asm!`. The `bindings/acdp-wasm` wasm32 build is one of those targets
(DECISIONS.md `322-zeroize`, finding Z-1). Native builds use the sound `asm!`
path, and no known ACDP call site triggers the fault. Z-1 is reported
upstream as RustCrypto/utils#1549. **Exit criterion:**
delta-audit zeroize 1.9.1 when it is released (RustCrypto/utils#1535 removes the
crate's internal callers of `optimization_barrier`). Its guard line carries
`allow-exempt:DECISIONS#322-zeroize@1.9.0`, which pins the exemption to 1.9.0.

**`cpufeatures` 0.3.1 is audited with a discretion note.** On x86 it reads
CPUID leaf 7 without checking the maximum basic leaf (`src/x86.rs:49-51`), so
on a CPU or VM whose maximum basic leaf is below 7 the leaf-7 bits can be
spurious (DECISIONS.md `322-cpufeatures`). Every `unsafe` and `asm!` site is
sound. The predicates ACDP's graph uses (`sha` ANDed with SSSE3 and SSE4.1;
`avx2` ANDed with AVX and the XCR0 YMM state) cannot misfire on any supported
platform; only a manual hypervisor CPUID-level override on an AVX-class CPU
model reaches the gap, and the result is a deterministic `SIGILL`. Upstream
tracks it as RustCrypto/utils#1510, with the fix open in #1528. **Exit
criterion:** delta-audit the cpufeatures release carrying #1528.

**`getrandom` is audited with discretion notes; builder `--cfg` overrides are outside what we
vouch for.** The audits are full reviews of every backend. Every backend getrandom compiles
for an ACDP artifact is sound: for 0.4.3, the Linux libc `getrandom`/`/dev/urandom` path,
`getentropy` on macOS, `ProcessPrng` on Windows and Web Crypto on wasm32; for 0.2.17 (ring),
the getrandom(2) syscall path, `getentropy`, `BCryptGenRandom`/`RtlGenRandom` (the wasm
binding no longer depends on 0.2 since #363, so its `js.rs` is no longer compiled). So is every backend selected by default on a stable
tier-1/2 target. The opt-in `linux_raw` backend
has two soundness bugs, on loongarch64 (undeclared `$t0`-`$t8` clobbers) and on x32/ILP32
(32-bit pointer and length in 64-bit registers). They are reachable only when the final
binary's builder sets `--cfg getrandom_backend="linux_raw"` on those targets
(DECISIONS.md `322-getrandom`). **ACDP's getrandom audits cover the backend getrandom
selects by default; a builder's `--cfg getrandom_backend=...` override is outside them and
is the builder's responsibility.** **Exit criterion:** delta-audit the getrandom release
that fixes `linux_raw`.

**`rustls-webpki` 0.103.15 is audited, and its DoS cost is recorded.** It has no `unsafe`, and
no panic is reachable from a server-presented chain. Path building is bounded by upstream's
RUSTSEC-2023-0053 budget (200,000 build-chain calls). That budget does not cover re-parsing
the peer's intermediates on each call, so a malicious HTTPS server can make one handshake
cost about 0.5-1 s of CPU (measured worst 758 ms, within rustls's 64 KiB Certificate message
cap). This is bounded and deliberate upstream design, so it is recorded as an observation, not
a concern (DECISIONS.md `322-rustls-webpki`, finding W-O8). CRL parsing and revocation
checking are compiled but never reached: no ACDP HTTPS client configures CRLs.

**All 35 supporting crypto crates (Tier B) are certified.** #322 covered only the eleven
Tier A crates. Issue #339 certified the 35 support crates on the same signing, hashing, key
generation, and TLS paths, and added each to the guard list:
- batch B1: `ed25519`, `crypto-common`, `zeroize_derive`, `spki`, `ff`, `wnaf`;
- B2: `hmac`, `rfc6979`, `pkcs8`, `sec1`, `primefield`, `digest`;
- B3: `untrusted`, `cpubits`, `hyper-rustls`, `group`, `tokio-rustls`, `primeorder`;
- B4: `rand_core` at both locked versions, `ctutils`, `webpki-roots`, `typenum`;
- B5: `base16ct`, `base64ct`, `rustls-pki-types`, `const-oid`, `der`,
  `curve25519-dalek-derive`;
- B6: `cpufeatures`, `block-buffer`, `cmov`, `hybrid-array`, `crypto-bigint`;
- B7a: `getrandom` at all three locked versions;
- B7b: `rustls-webpki`.

No Tier B crate is covered by an exemption.

**`aws-lc-rs` is not in the dependency graph (#339).** It used to come in only
through the TLS test harness (`axum-server`'s `tls-rustls` feature and the dev
`rustls` `aws-lc-rs` feature). Cargo unifies features, so that dev-only choice
switched on the optional `aws-lc-rs` dependency of the *production* `rustls`
that reqwest uses. `cargo vet` therefore saw `rustls -> aws-lc-rs` as a normal
edge and required `safe-to-deploy` for `aws-lc-rs` and `aws-lc-sys`: moving
their exemptions to `safe-to-run` failed `cargo vet --locked`. The harness now
uses `axum-server`'s `tls-rustls-no-provider` feature and the `ring` provider,
the same one production builds use (`tests/common/mod.rs` installs
`rustls::crypto::ring::default_provider()`). `aws-lc-rs`, `aws-lc-sys`, and
their build-only dependencies (`cmake`, `dunce`, `fs_extra`, `jobserver`,
`pkg-config`) left `Cargo.lock`, and their exemptions were removed. Keep it this
way: do not enable `tls-rustls`, `rustls/aws-lc-rs`, or `rustls`'s default
features in any dev-dependency. Check with
`cargo tree --workspace --all-features -e features -i aws-lc-rs`, which should
report that the package is not found.

**Coverage outside this repo's root lockfile.** The three bindings
(`bindings/acdp-py`, `bindings/acdp-node`, `bindings/acdp-wasm`) have their
own `Cargo.lock` files and **no `cargo vet` gate**. The root audits cover them
by version only, and
[`scripts/check-bindings-lock-parity.sh`](../scripts/check-bindings-lock-parity.sh)
(#340) enforces that parity. For every crate in `crypto-critical.txt`, each
registry `(version, checksum)` pair in a binding lockfile must also appear in
the root `Cargo.lock`:

- A listed crate absent from a binding is fine.
- A listed crate absent from the root lockfile fails, as a list typo would.
- A binding version the root does not lock fails, and so does the same version
  with a different checksum.

Exit status is 0 on pass, 1 on a violation, and 2 on a missing, empty, or
malformed lockfile. The check needs only POSIX awk, so it runs the same under
BSD awk (macOS) and GNU awk (CI). It runs in the required `cargo-vet` CI job
after the crypto-critical guard, preceded by its self-test
[`scripts/test-check-bindings-lock-parity.sh`](../scripts/test-check-bindings-lock-parity.sh).

**When it fails**, re-lock the binding to the root version rather than
auditing a second version:

```sh
cargo update -p <crate> --precise <root-version> --manifest-path bindings/acdp-<py|node|wasm>/Cargo.toml
scripts/check-bindings-lock-parity.sh
```

Bump the root first if the binding genuinely needs the newer version, so the
audit lands at the root and the bindings follow. The check covers only the
guard list. When the check was added, `der` and `tokio-rustls` were not on it,
but the bindings were re-locked to the root's `der` 0.8.1 and `tokio-rustls`
0.26.4 in the same change (they had drifted to 0.8.2 and 0.26.5).
`tokio-rustls` joined the guard list in #339 batch B3 and `der` in batch B5, so
the check now covers both.

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

**Crypto-critical crates may not take the exempt path.** The crates listed in
[`scripts/crypto-critical.txt`](../scripts/crypto-critical.txt) must be covered
by a real audit at every locked version. `cargo vet` alone cannot enforce
this, because it passes an exempted crate exactly like an audited one, so the
`cargo-vet` CI job also runs
[`scripts/check-crypto-vet.sh`](../scripts/check-crypto-vet.sh). That guard
fails when a listed crate is exempted or only partially vetted, so moving an
exemption to a bumped version no longer turns CI green.

The guard is now **enforcing**: since #322 closed, every listed crate except
`zeroize` carries no marker (forty-five of the forty-six, including all
thirty-five Tier B crates added by #339 batches B1-B7b). The list file documents
two markers:

- `allow-exempt:DECISIONS#322-<crate>@<version>` is for a crate kept exempt
  under the #322 concern rule. **Only `zeroize` uses it**
  (`allow-exempt:DECISIONS#322-zeroize@1.9.0`). It must meet three conditions:
  - DECISIONS.md must contain the anchor `322-<crate>` as a whole token.
  - The `@<version>` is required.
  - Every unaudited locked version, and every
    `[[exemptions.<crate>]]` version in `supply-chain/config.toml`, must equal
    the pinned version. Otherwise the guard fails with "re-audit, or update the
    DECISIONS.md entry and the marker".

  This means moving zeroize's exemption to a newer release no longer passes.
  The `322-zeroize` exit criterion is a delta audit of 1.9.1.
- `allow-exempt:#322-pending` was the in-progress marker. No line uses it any
  more. Adding it back needs a DECISIONS.md entry.

A marker left on a crate that is now fully audited also fails ("stale marker —
remove it"). Run
the guard locally with `scripts/check-crypto-vet.sh`, and run its self-tests
with `scripts/test-check-crypto-vet.sh` (add `--with-network` to also exercise
`vet-facts.sh`). Both need `jq`. CI runs the self-tests (without
`--with-network`) in the required `cargo-vet` job.

After any certify or exemption change, run `cargo vet --locked` to confirm
green and commit the `supply-chain/` changes with your PR. Run `cargo vet prune`
occasionally to drop exemptions that an imported audit now covers.

### Upgrading a crypto-critical crate

The `crypto` group in `.github/dependabot.yml` puts the direct crypto
dependencies in their own PR: `ed25519-dalek`, `p256`, `sha2`, `zeroize`, and
`rustls`. The transitive ones (`curve25519-dalek`, `signature`, `ecdsa`,
`elliptic-curve`, `subtle`, `ring`) move only with a lock rewrite. The guard
catches either case. When a bump turns `cargo-vet` red:

1. **Get the facts.** Run `scripts/vet-facts.sh <crate> <new> <audited-base>`.
   It downloads the crates.io tarball(s), checks them against the `Cargo.lock`
   checksum (and the index checksum for the base), and prints the facts an
   audit note quotes: the diff stat with Cargo.lock excluded, the delta/full
   ratio and the method it implies, `unsafe` code lines as `file:line`,
   `forbid(unsafe_code)`, `asm!`, `build.rs`, `proc-macro`, powerful imports,
   and dependency changes.
2. **Pick the method.** If the changed lines are ≥75% of the crate's `src/`
   lines, or the release rewrites the crate's `unsafe` code, do a full audit.
   Otherwise do a delta from the audited base.
3. **Read the code.** Use `cargo vet diff <crate> <base> <new> --mode=local`,
   or `cargo vet inspect <crate> <new> --mode=local` for a full audit.
4. **Write the worksheet.** Add `supply-chain/worksheets/<crate>-<version>.md`
   in the format of the existing ones. It covers provenance, the facts table,
   a verdict on every `unsafe` cluster and powerful import, the features ACDP
   compiles in, findings, and what is not claimed.
5. **Certify.** Run the non-interactive command with the notes template:

   ```bash
   cargo vet certify <crate> <base> <new> --criteria safe-to-deploy \
       --who "Ajit Koti <ajitkoti@zer07labs.com>" --notes "$(cat notes.txt)" --accept-all
   # full audit: cargo vet certify <crate> <new> …
   git diff --stat supply-chain/imports.lock   # must be empty
   cargo vet --locked && scripts/check-crypto-vet.sh
   ```

   `certify` removes the now-redundant exemption.
6. **If the review finds a concern**, do **not** certify. A concern is unsound
   or unexplained `unsafe`, unexpected I/O, a build script doing more than cfg
   selection, vendored binaries, a RUSTSEC hit, or a review you cannot finish.
   Instead:
   - keep or add the exemption, with a `KEPT EXEMPT (#322)` note;
   - add a DECISIONS.md entry anchored `322-<crate>` that lists the options;
   - set the guard marker to `allow-exempt:DECISIONS#322-<crate>@<version>`.
7. **Push to the Dependabot branch.** `dependabot-auto-merge.yml` never turns
   on auto-merge for a PR that changes a crypto-critical crate in any of the
   four lockfiles, whatever its Dependabot group (see
   [Dependabot auto-merge](#dependabot-auto-merge)), and turns it off if an
   earlier push had it on. Your push does not re-run that workflow (it runs
   only for Dependabot's own pushes), so check before merging that
   auto-merge is still off (`gh pr view <n> --json autoMergeRequest`).
8. **Get sign-off.** The maintainer posts an approving review that says which
   worksheet they read. Only then is the PR merged.

The criteria, the method rule, the notes template, the `who` / sign-off rule,
and the concern rule are all in DECISIONS.md "#322 supply-chain audit policy".
For these crates, "move the exemption to the new version" is no longer an
available move.

**Who audits.** The crypto-critical set is audited by the crate maintainers and
should be `safe-to-deploy` with real inspection notes — treat a change there as
a security review, not a rubber stamp. The long-tail exemptions are a
maintenance backlog: prefer converting them to real audits (ours or imported)
over time. First-party workspace crates (`acdp`, `acdp-*`) are configured
`audit-as-crates-io = false` — they're our own code and need no audit or
exemption, and their version bumps therefore never trip the gate.

### Dependabot auto-merge

`.github/workflows/dependabot-auto-merge.yml` turns on GitHub auto-merge (the
merge still waits for every required check) only when all of these hold:

- the update is patch or minor;
- the PR is not from the `crypto` Dependabot group;
- `scripts/dependabot-crypto-gate.sh` exits 0;
- `main` is protected with required status checks.

Otherwise it leaves auto-merge off, and turns it off if an earlier run had
turned it on. The group check alone is not enough. A transitive
crypto-critical crate can move inside another group's PR (for example
`minor-and-patch`, or one of the bindings' Dependabot entries). If an
imported audit covers the new version, `cargo-vet` and the guard are both
green, and the PR would merge with no maintainer review (#344).

**The gate.** `scripts/dependabot-crypto-gate.sh --base <rev> --head <rev>`
reads the four lockfiles (`Cargo.lock` and `bindings/acdp-{py,node,wasm}/Cargo.lock`)
at the merge base and at the head, straight from git objects. It turns each
`[[package]]` block into a `name|version|source|checksum` row. If any row of a
crate in `scripts/crypto-critical.txt` differs between the two sides, the PR
needs review. That covers a bump, an added second version, a removal, and a
source or checksum change. A change to the gate script, the guard list, or
the workflow file also needs review. The guard list is parsed like
`check-crypto-vet.sh` parses it: comments are skipped and markers ignored.

| Exit | Meaning | Workflow |
|---|---|---|
| 0 | No crypto-critical crate or gate file touched | auto-merge on (if the other conditions hold) |
| 1 | Touched; the crates and rows are printed | auto-merge off; job green with a notice |
| 2 | Error: unknown revision, lockfile missing on either side, empty or malformed lockfile or guard list | auto-merge off; job red |

**Trust boundary.** The workflow runs on `pull_request`, never
`pull_request_target`. It checks out with `persist-credentials: false` and
loads the gate script and guard list from the PR's **base** commit (`git
cat-file`), so a PR cannot weaken the gate that judges it. The workflow file
itself still runs from the PR's head (that is how `pull_request` works). This
is why a change to it counts as touched. Turning auto-merge off first asks
whether it is on, so the "auto-merge is not enabled" case needs no
error-string matching. Any other `gh` failure fails the job.

This workflow replaces the shared acdp-ci `auto-merge.yml@v1` caller. That
caller armed auto-merge on every patch/minor Dependabot PR, crypto included,
and raced this workflow's decision. Its branch-protection check is kept here.

**Self-tests.** `scripts/test-dependabot-crypto-gate.sh` builds a scratch git
repo from copies of the real lockfiles and list. It then checks one case per
behaviour. Clean cases (no change, a non-crypto bump, a GitHub Actions-only
PR, an unlisted crate whose name shares a prefix) exit 0. Touched cases
(`subtle` bumped, a second `ring`, a crypto crate removed, a checksum-only or
source-only change, a binding-only change, a gate file edited) exit 1. Error
cases (malformed, empty, or one-sided lockfiles, a bad list or revision) exit
2. It also covers list comment and marker parsing, a base-loaded copy of the
gate, and the real tree HEAD vs HEAD. Every case runs under each awk on PATH
(BSD awk on macOS; gawk, mawk, original-awk, and busybox where installed).
The required `cargo-vet` CI job runs it after the guard, together with
`scripts/test-check-crypto-vet.sh`.

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

**rustls RUSTSEC-2026-0285:** fixed by bumping `rustls` 0.23.43 → 0.23.45
(`b547227`, 2026-09-19), with the `cargo vet` exemption moved to 0.23.45 in the
same change set (`09197e0`). No `deny.toml` ignore entry was needed. #322 later
replaced that exemption with a delta audit, 0.23.40 → 0.23.45, whose
worksheet reads the fix (`supply-chain/worksheets/rustls-0.23.45.md`).

Together: **`vet`** answers "did a human look at this code?", **`deny`**
answers "is there a known-bad advisory or license here?", and the **provenance +
pinning** layers answer "did this actually come from our CI?".
