# Research memo: post-quantum signature migration (ML-DSA)

**Status:** evaluation / not scheduled — **forward-looking, not imminent.**
**Scope:** adding a post-quantum signature algorithm (ML-DSA / FIPS 204) to
ACDP's algorithm-agility registry, and what it costs at the wire, body-size, and
DID-document layers.
**Effort:** algorithm-agility plumbing is **S**; a production-ready ML-DSA
implementation + conformance vectors is **M**, gated on external crate maturity.

---

## 1. What algorithm agility already gives us

ACDP was designed so a new signature algorithm is an **additive** change, not a
wire change. The machinery already in the codebase:

- **An open algorithm vocabulary.** `signature.algorithm` is a lowercase-ASCII
  string matching `^[a-z][a-z0-9-]*$`; the schema is deliberately *not* an enum
  (`registries/signature-algorithms.md`). Runtime gating is via a registry's
  `supported_signature_algorithms` capability (RFC-ACDP-0001 §5.10,
  RFC-ACDP-0007). Adding an algorithm is "add a row to the registry + implement
  verify/sign," per that registry's "Adding an algorithm" section.
- **String-dispatched verify/sign.** In `acdp-verify/src/lib.rs`, the
  resolver-backed verifier dispatches on `signature.algorithm.as_str()` with
  arms for `"ed25519"` and `"ecdsa-p256"` (and an explicit `other =>` rejection:
  *"verifier does not support signature algorithm '{other}'"*). The `did:key`
  and offline paths dispatch identically. Signing mirrors this: `acdp-crypto`'s
  `AcdpSigningKey` enum (`Ed25519` / `P256`) returns
  `(algorithm_str, base64_signature)`, and the byte-level primitives live in
  `acdp-crypto/src/{sign,verify}.rs`.
- **Algorithm-downgrade rejection already enforced.** Before dispatch, the
  verifier checks `method.declared_algorithm()` (from the DID document's
  `verificationMethod.type` / `publicKeyJwk`) equals `signature.algorithm`
  (RFC-ACDP-0008 §3.9). A PQ algorithm must extend `declared_algorithm()` so the
  DID-document key type and the signature algorithm are bound — otherwise a PQ
  key could be routed through the wrong verifier.
- **Reserved identifiers already in the registry.**
  `registries/signature-algorithms.md` ends with: *"Reserved future
  identifiers: `ed448`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` (post-quantum,
  pending NIST FIPS 204 stabilization)."* The names are already carved out — the
  work is implementation + vectors, not naming.

**Net:** adding `ml-dsa-65` is, structurally, the same three-file change adding
`ecdsa-p256` was — a new match arm in `acdp-crypto` verify/sign, an
`AcdpSigningKey` variant, a `declared_algorithm()` case, and a registry row. No
body field, `content_hash` preimage, or signing-input framing changes: the
signing input stays the ASCII bytes of the `"sha256:<hex>"` `content_hash`
string (RFC-ACDP-0001 §5.8) regardless of algorithm.

---

## 2. ML-DSA (FIPS 204) as the PQ choice

ML-DSA (Module-Lattice Digital Signature Algorithm, standardized as **FIPS 204**
in Aug 2024, formerly CRYSTALS-Dilithium) is the natural target: it is a NIST-
standardized, stateless, hash-and-sign lattice signature — a drop-in *shape* for
ed25519/p256 (a keypair, `sign(msg) -> bytes`, `verify(pk, msg, sig)`), which is
exactly what ACDP's `sign_content_hash` / `verify_*` contract needs. The three
parameter sets map to the reserved identifiers:

| Identifier | NIST level | Public key | Signature |
|---|---|---|---|
| `ml-dsa-44` | Category 2 | ~1312 B | ~2420 B |
| `ml-dsa-65` | Category 3 | ~1952 B | ~3309 B |
| `ml-dsa-87` | Category 5 | ~2592 B | ~4627 B |

(SLH-DSA / FIPS 205 is the hash-based alternative — far larger signatures,
smaller keys, more conservative security assumptions. If a second PQ family is
ever wanted it would get its own reserved identifiers; ML-DSA is the pragmatic
first PQ signature and the one already reserved.)

---

## 3. The honest size problem

This is the one place PQ is not a drop-in. Ed25519 and ecdsa-p256 signatures are
**64 bytes** (88 base64 chars); ML-DSA signatures are **KB-scale**, and public
keys likewise. Concrete ACDP impacts:

- **Body size.** `signature.value` grows from 88 base64 chars to ~3.2 KB
  (ml-dsa-44) – ~6.2 KB (ml-dsa-87) of base64. Well within `limits.max_payload_bytes`
  (the client caps context bodies at 1 MB), but it is a ~40–70× growth in the
  signature envelope and materially larger `derived_from` chains (each ancestor
  is independently signed — a deep lineage multiplies the cost).
- **The 64 KB embedded cap is *not* directly threatened, but adjacent.** The
  64 KB `embedded_too_large` cap (RFC-ACDP-0008 §4.2) is on *embedded data*, and
  the same 64 KB cap applies to **DID documents** and capabilities responses
  (see `CLAUDE.md` security defaults). A DID document publishing an ML-DSA key
  (~2.6 KB for ml-dsa-87, base64-encoded in a JWK/multibase field) stays well
  under 64 KB for a single key — but a document retaining *many rotated PQ keys*
  (which RFC-ACDP-0010 §9/§10 key-retention discipline explicitly encourages —
  keep rotated keys in `verificationMethod` indefinitely) could approach it.
  Worth modeling before committing a cap.
- **Key-material encoding needs a registry decision.** ecdsa-p256 mandates a JWK
  `{kty:EC, crv:P-256, x, y}` form (`registries/signature-algorithms.md`). ML-DSA
  has no settled JWK representation yet (COSE/JOSE PQ registrations are still
  stabilizing). A PQ registry entry MUST define the *exact* wire encoding of both
  the signature value bytes and the DID-document public-key form (multibase
  multicodec vs a JWK `AlgorithmKeyPair`), or interop breaks — the same
  discipline the ecdsa-p256 entry applied ("Define the wire form of the
  signature value bytes").

---

## 4. Rust crate landscape — be honest, it is less mature than ed25519-dalek

ACDP's current crypto is pure-Rust (`ed25519-dalek` 3 from dalek-cryptography;
`p256`, `sha2` from RustCrypto) —
pure-Rust, widely audited, and `wasm`-clean (see the WASM memo; no `ring`). The
PQ story is not at that level yet:

- **RustCrypto `ml-dsa`.** RustCrypto maintains an `ml-dsa` crate (FIPS 204).
  Pros: same ecosystem/traits as the existing stack (`signature::{Signer,
  Verifier}`), pure-Rust, plausibly `no_std`/`wasm`-friendly like the rest of
  RustCrypto — which would keep the WASM target story intact. Cons: it is **newer
  and less battle-tested** than `ed25519-dalek`; PQ crates broadly have **not**
  had the years of audit and deployment ed25519 has, and several are pre-1.0
  with churning APIs.
- **Other options** (`pqcrypto`/`pqcrypto-mldsa` wrapping the C PQClean
  reference, `fips204` pure-Rust) exist but bring tradeoffs: C-backed crates
  reintroduce a non-pure-Rust dependency (the `ring`-class WASM/audit problem the
  project currently avoids), while pure-Rust crates are young.
- **Constant-time / side-channel maturity.** Lattice signing has real side-
  channel considerations; the guarantees in young Rust crates are not yet on par
  with the mature ECC crates. For a protocol whose §5.10 already forbids
  low-entropy/insecure key generation, adopting a PQ crate before its
  constant-time story is credible would be premature.

**Assessment:** the *plumbing* can be built today against RustCrypto `ml-dsa`;
**production adoption should wait** until a chosen crate reaches audit-ready
maturity and stable APIs. This is a maturity gate, not a design blocker.

---

## 5. Proposed plan

### 5.1 Test-vector plan (the gating deliverable)

Follow the existing golden-vector discipline exactly. `acdp-crypto` pins
`sig-001` (ed25519) and `sig-002` (ecdsa-p256) as in-crate golden tests
(`sign.rs`), and `tests/conformance.rs` binds the spec fixtures. For ML-DSA:

- Add a `sig-003-ml-dsa-65-golden.json` (or per-parameter-set) conformance
  fixture in the spec, mirroring `sig-001`/`sig-002`: a fixed TEST-ONLY keypair,
  the `content_hash` `"sha256:f170150d…"` preimage already reused across
  `sig-001`/`sig-002`, and the expected signature + public-key encoding.
- **Determinism caveat.** ML-DSA has both a deterministic (hedged-off) and a
  randomized signing mode. Golden vectors require the **deterministic** variant
  (as `sig-002` uses RFC 6979 deterministic ECDSA precisely so vectors are
  byte-reproducible). The registry entry MUST pin deterministic mode for
  reproducibility, exactly as the ecdsa-p256 entry does.
- Wire the fixture into `tests/conformance.rs` and add an in-crate regression in
  `acdp-crypto/src/sign.rs` mirroring `sign_and_verify_ecdsa_p256_golden`.
- The bindings' golden-vector parity rule (`CLAUDE.md`: `bindings/interop`
  asserts byte equality) extends to the PQ vector once a crate is chosen.

### 5.2 Registry entry

A new row in `registries/signature-algorithms.md` per its "Adding an algorithm"
rules (public stable spec = FIPS 204 ✓; single deterministic primitive = pin
deterministic mode ✓; defined signature wire-form bytes = **must specify**; ≥1
independent implementation = ✓ once the ecosystem matures). Plus the normative
key-material and DID-document-verification-method subsections ML-DSA needs (the
ecdsa-p256 entry is the template).

### 5.3 Code changes (small, mechanical)

Same three-coordinated-edit shape as any algorithm addition:
`acdp-crypto` verify + sign primitives and `AcdpSigningKey` variant →
`declared_algorithm()` case in `acdp-did/src/document.rs` (so §3.9 downgrade
rejection binds the PQ key type) → dispatch arms in `acdp-verify` (resolver,
offline, and `did:key` paths). Note `did:key` support would need a **new
multicodec** for ML-DSA public keys (the current `key.rs` only knows
`ed25519-pub` `0xed 0x01` and P-256 compressed) — a `did:webvh`/`did:web` PQ key
is easier than a `did:key` PQ key.

### 5.4 Hybrid (ed25519 + ML-DSA) — worth specifying?

**Probably yes, and deliberately.** During the transition, "harvest-now-decrypt-
later" does not apply to *signatures* the way it does to encryption (a signature
forged in 2035 does not retroactively help an attacker much), so the urgency is
lower — but **hybrid signing** (require *both* an ed25519 and an ML-DSA signature
to verify) hedges against either primitive failing and against immature-PQ-crate
bugs. Two ways to model it in ACDP:

- **Dual algorithm identifier** (`ml-dsa-65+ed25519`) with a defined composite
  wire form — one `signature` object, concatenated/structured value. Simpler for
  the single-`signature`-object body but needs a careful composite encoding spec.
- **Two verification methods + a policy** ("verify as current only if both a PQ
  and a classical assertion key verify"). Fits ACDP's existing `verificationMethod`
  model better and reuses the key-retention machinery, but needs a body that can
  carry two signatures — a wire change ACDP has so far avoided (`signature` is a
  single object). The RFC-ACDP-0015 `witness_signatures` **array** precedent
  shows the project is willing to add signature-array members additively when
  justified.

Recommend specifying hybrid as an explicit *option* in the PQ RFC rather than
mandating it, keyed to how much confidence the chosen ML-DSA crate has earned.

### 5.5 Phased timeline (maturity-keyed, not urgency-keyed)

1. **Now (S):** keep the reserved identifiers; do nothing wire-facing. Track
   RustCrypto `ml-dsa` maturity and NIST/JOSE-COSE PQ-encoding stabilization.
2. **When a crate is audit-ready (M):** land the plumbing behind a
   non-default/experimental feature + the golden vector; do **not** advertise it
   in `supported_signature_algorithms` for production registries yet.
3. **When the ecosystem + encoding standards settle:** promote via an RFC in a
   future spec line, likely with hybrid as the recommended transition mode; then
   registries may advertise it.

---

## 6. Recommendation

Post-quantum is **forward-looking, not imminent**, and the codebase is already
well-positioned for it: algorithm agility is real (string-dispatched
verify/sign, open vocabulary, downgrade rejection, reserved `ml-dsa-*` names),
so the migration is additive and wire-frozen bodies are unaffected. The two
genuine gates are **crate maturity** (RustCrypto `ml-dsa` is promising and keeps
the pure-Rust/wasm-clean posture, but PQ crates are years behind `ed25519-dalek`
in audit and stability — do not adopt prematurely) and the **size /
key-encoding** decisions (KB-scale signatures and DID keys, no settled JWK form
yet). Recommend keeping the identifiers reserved, building the plumbing +
deterministic golden vector behind an experimental feature once RustCrypto
`ml-dsa` is audit-ready, specifying hybrid as an option rather than a mandate,
and sequencing the production promotion to NIST/ecosystem maturity rather than to
any near-term urgency.
