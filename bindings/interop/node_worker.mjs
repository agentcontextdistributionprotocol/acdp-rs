#!/usr/bin/env node
// ACDP interop worker — Node.js side.
//
// A long-lived process speaking line-delimited JSON-RPC over
// stdin/stdout. The Python interop test suite (test_interop.py) spawns
// one of these and drives every step through the Node binding. The
// worker only computes one side of each step; the test relays the wire
// JSON between Python and Node so a green run proves byte-compatible
// PublishRequest output across the two languages.
//
// Protocol (one JSON object per line):
//   request : {"id": int, "method": str, "params": {...}}
//   response: {"id": int, "ok": true,  "result": {...}}
//           | {"id": int, "ok": false, "error": str}
//
// Producer handles are integers into a per-process registry; they are
// opaque to the caller.

import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const nodeDir = join(here, '..', 'acdp-node');
const mod = await import(pathToFileURL(join(nodeDir, 'index.js')).href);
const AcdpProducer = mod.AcdpProducer ?? mod.default?.AcdpProducer;
const AcdpP256Producer = mod.AcdpP256Producer ?? mod.default?.AcdpP256Producer;
const AcdpVerifier = mod.AcdpVerifier ?? mod.default?.AcdpVerifier;
const AcdpCanonicalizer = mod.AcdpCanonicalizer ?? mod.default?.AcdpCanonicalizer;
const AcdpMerkle = mod.AcdpMerkle ?? mod.default?.AcdpMerkle;
const AcdpSsrfPolicy = mod.AcdpSsrfPolicy ?? mod.default?.AcdpSsrfPolicy;
const AcdpDid = mod.AcdpDid ?? mod.default?.AcdpDid;
const AcdpDidDocument = mod.AcdpDidDocument ?? mod.default?.AcdpDidDocument;
if (
  !AcdpProducer ||
  !AcdpP256Producer ||
  !AcdpVerifier ||
  !AcdpCanonicalizer ||
  !AcdpMerkle ||
  !AcdpSsrfPolicy ||
  !AcdpDid ||
  !AcdpDidDocument
) {
  throw new Error(
    'acdp-node binding not built (or missing classes) — run `npm run build:debug` in bindings/acdp-node/',
  );
}
const pkgVersion = JSON.parse(
  readFileSync(join(nodeDir, 'package.json'), 'utf8'),
).version;

// Reflect a class's public surface as snake_case names (static methods +
// instance methods + getters) so the Python parity test can compare it
// against the Python binding and the shared manifest without caring about
// JS camelCase. Mirrors the filtering in test_parity.py.
const SKIP = new Set(['length', 'name', 'prototype', 'arguments', 'caller']);
const toSnake = (s) => s.replace(/([A-Z])/g, '_$1').toLowerCase();
function describeClass(Cls) {
  const statics = Object.getOwnPropertyNames(Cls).filter((n) => !SKIP.has(n));
  const proto = Object.getOwnPropertyNames(Cls.prototype).filter(
    (n) => n !== 'constructor',
  );
  return [...new Set([...statics, ...proto])].map(toSnake).sort();
}

// Run an SSRF check and report a verdict comparable to the Python side:
// allowed (no throw) or rejected with the stable reason on Error.code.
function ssrfVerdict(fn) {
  try {
    fn();
    return { allowed: true };
  } catch (err) {
    return { allowed: false, reason: err?.code ?? null };
  }
}

const registry = new Map();
let nextHandle = 0;
const store = (obj) => {
  const handle = nextHandle++;
  registry.set(handle, obj);
  return handle;
};

const methods = {
  ping: () => ({ sdk: 'acdp-node', version: pkgVersion }),

  // Reflect the Node binding's public surface for the parity test:
  // { version, classes: { ClassName: [snake_case method names...] } }.
  describe: () => ({
    version: pkgVersion,
    classes: {
      AcdpProducer: describeClass(AcdpProducer),
      AcdpP256Producer: describeClass(AcdpP256Producer),
      AcdpVerifier: describeClass(AcdpVerifier),
      AcdpCanonicalizer: describeClass(AcdpCanonicalizer),
      AcdpMerkle: describeClass(AcdpMerkle),
      AcdpSsrfPolicy: describeClass(AcdpSsrfPolicy),
      AcdpDid: describeClass(AcdpDid),
      AcdpDidDocument: describeClass(AcdpDidDocument),
    },
  }),

  // Reflect the wasm binding's flat function surface for the parity
  // test. UNLIKE every other method here, the wasm pkg is loaded lazily
  // — right here, inside the handler, wrapped in try/catch — rather than
  // at module top level. `bindings/acdp-wasm/pkg/` is a gitignored build
  // artifact that most contributor machines won't have (no wasm-pack
  // run), and this worker's module-scoped `node` fixture
  // (test_parity.py) is required by EVERY existing parity/interop test.
  // A top-level `await import(...)` that throws when the wasm pkg is
  // missing — mirroring the acdp-node imports above — would take down
  // this entire worker process (and therefore every test that uses it)
  // on any machine without a wasm build, not just the wasm-specific
  // tests. So: on failure, return a structured `{ available: false,
  // reason }` instead of throwing; the Python side turns that into a
  // `pytest.skip` (or a hard failure under ACDP_REQUIRE_WASM_PARITY=1).
  describe_wasm: async () => {
    try {
      const wasmDir = join(here, '..', 'acdp-wasm', 'pkg');
      const modUrl = pathToFileURL(join(wasmDir, 'acdp_wasm.js')).href;
      const wasmMod = await import(modUrl);
      const wasmBytes = readFileSync(join(wasmDir, 'acdp_wasm_bg.wasm'));
      await wasmMod.default({ module_or_path: wasmBytes });
      // wasm-bindgen's `--target web` module namespace carries the 25
      // #[wasm_bindgen] free functions plus its own init machinery
      // (`default` — the init function itself, re-exported under that
      // name — and `initSync`) and, in other wasm-bindgen output shapes,
      // internal helpers prefixed `__`. None of those three are ACDP
      // surface, so they're excluded here; everything else exported as
      // a function is a real export to pin.
      const functions = Object.getOwnPropertyNames(wasmMod)
        .filter((k) => typeof wasmMod[k] === 'function')
        .filter((k) => k !== 'default' && k !== 'initSync' && !/^__/.test(k))
        .map(toSnake)
        .sort();
      return { available: true, functions };
    } catch (err) {
      return { available: false, reason: String(err?.message ?? err) };
    }
  },

  // ── Sync primitives (AcdpCanonicalizer / AcdpSsrfPolicy) ──────────────
  canonicalize: (p) => ({ result: AcdpCanonicalizer.canonicalize(p.json) }),

  content_hash: (p) => ({ result: AcdpCanonicalizer.contentHash(p.json) }),

  // Each returns { allowed } or { allowed: false, reason } so the Python
  // side can assert the stable reason codes match across bindings.
  ssrf_check_url: (p) =>
    ssrfVerdict(() => AcdpSsrfPolicy.production().checkUrl(p.url)),

  ssrf_check_ip: (p) =>
    ssrfVerdict(() => AcdpSsrfPolicy.production().checkIp(p.ip)),

  ssrf_check_redirect: (p) =>
    ssrfVerdict(() =>
      AcdpSsrfPolicy.production().checkRedirectAuthority(p.from_url, p.to_url),
    ),

  // Returns { handle, agent_did, key_id, public_key_b64 }.
  new_producer: (p) => {
    const producer = p.seed
      ? AcdpProducer.fromSeed(Buffer.from(p.seed), p.agent_did, p.key_id)
      : AcdpProducer.generate(p.agent_did, p.key_id);
    return {
      handle: store(producer),
      agent_did: producer.agentDid,
      key_id: producer.keyId,
      public_key_b64: producer.publicKeyB64,
    };
  },

  // Returns { handle, agent_did, key_id, public_key_sec1_b64 }. The
  // returned handle is accepted by build_publish_request / sign_challenge
  // exactly like an Ed25519 producer handle (both classes share the
  // method surface).
  new_p256_producer: (p) => {
    const producer = p.seed
      ? AcdpP256Producer.fromSeed(Buffer.from(p.seed), p.agent_did, p.key_id)
      : AcdpP256Producer.generate(p.agent_did, p.key_id);
    return {
      handle: store(producer),
      agent_did: producer.agentDid,
      key_id: producer.keyId,
      public_key_sec1_b64: producer.publicKeySec1B64,
    };
  },

  // opts is the JS-side PublishOpts (camelCase). Returns the wire JSON
  // string (so byte equality with the Python side is observable).
  // Works for both Ed25519 and P-256 producer handles.
  build_publish_request: (p) => ({
    raw: registry.get(p.producer).buildPublishRequest(p.opts),
  }),

  build_supersede_request: (p) => ({
    raw: registry.get(p.producer).buildSupersedeRequest(
      p.previous_body_json,
      p.opts,
    ),
  }),

  sign_challenge: (p) => ({
    signature: registry.get(p.producer).signChallenge(p.signing_input),
  }),

  verify_content_hash: (p) => ({
    ok: AcdpVerifier.verifyContentHash(p.body_json, p.expected_hash),
  }),

  verify_ctx_id_binding: (p) => ({
    ok: AcdpVerifier.verifyCtxIdBinding(p.body_json, p.expected_ctx_id),
  }),

  verify_receipt: (p) => ({
    ok: AcdpVerifier.verifyReceipt(
      p.receipt_json,
      p.body_json,
      p.registry_public_key_b64,
      p.expected_ctx_id,
      p.recomputed_body_hash,
      p.producer_key_fingerprint,
    ),
  }),

  verify_signature: (p) => ({
    ok: AcdpVerifier.verifySignature(
      p.pub_key_b64,
      p.sig_b64,
      p.content_hash,
    ),
  }),

  verify_signature_p256: (p) => ({
    ok: AcdpVerifier.verifySignatureP256(
      p.pub_key_sec1_b64,
      p.sig_b64,
      p.content_hash,
    ),
  }),

  // ── ACDP 0.3 surface (AcdpVerifier verdicts / AcdpMerkle) ─────────────
  // Each returns the raw JSON string the binding produced (so byte
  // equality with the Python side is observable).
  build_log_leaf: (p) => ({
    raw: AcdpVerifier.buildLogLeaf(p.receipt_json),
  }),

  parse_key_revocation: (p) => ({
    raw: AcdpVerifier.parseKeyRevocation(
      p.body_json,
      p.signer_fingerprint ?? null,
    ),
  }),

  classify_under_revocation: (p) => ({
    raw: AcdpVerifier.classifyUnderRevocation(
      p.revocations_json,
      p.signer_fingerprint,
      p.receipt_created_at ?? null,
    ),
  }),

  verify_lineage_head_receipt: (p) => ({
    raw: AcdpVerifier.verifyLineageHeadReceipt(
      p.receipt_json,
      p.expected_json,
      p.registry_did_doc_json,
      p.now ?? null,
      p.max_skew_secs ?? null,
      p.max_age_secs ?? null,
    ),
  }),

  verify_log_checkpoint: (p) => ({
    raw: AcdpVerifier.verifyLogCheckpoint(
      p.checkpoint_json,
      p.registry_did_doc_json,
      p.expected_log_id ?? null,
      p.now ?? null,
      p.max_skew_secs ?? null,
    ),
  }),

  verify_log_inclusion: (p) => ({
    raw: AcdpVerifier.verifyLogInclusion(
      p.inclusion_json,
      p.checkpoint_json,
      p.leaf_json,
    ),
  }),

  verify_log_consistency: (p) => ({
    raw: AcdpVerifier.verifyLogConsistency(
      p.consistency_json,
      p.checkpoint_json,
      p.first_root_hash,
    ),
  }),

  verify_lifecycle_event: (p) => ({
    raw: AcdpVerifier.verifyLifecycleEvent(
      p.event_json,
      p.actor_did_doc_json ?? null,
      p.expected_ctx_id,
    ),
  }),

  // ── ACDP 0.4 witness cosignatures (RFC-ACDP-0015) ─────────────────────
  build_witness_cosignature: (p) => ({
    raw: AcdpVerifier.buildWitnessCosignature(
      p.witnessed_checkpoint_json,
      p.witness_did,
      p.witness_seed_hex,
      p.witnessed_at_rfc3339,
    ),
  }),

  verify_witness_cosignature: (p) => ({
    raw: AcdpVerifier.verifyWitnessCosignature(
      p.cosig_json,
      p.witness_did_doc_json,
      p.expected_checkpoint_json,
      p.now ?? null,
      p.max_clock_skew_secs ?? null,
    ),
  }),

  evaluate_witness_quorum: (p) => ({
    raw: AcdpVerifier.evaluateWitnessQuorum(
      p.cosignatures_json,
      p.expected_checkpoint_json,
      p.trusted_witness_dids_json,
      p.witness_did_docs_json,
      p.policy_json,
      p.now ?? null,
    ),
  }),

  merkle_leaf_hash: (p) => ({ result: AcdpMerkle.leafHash(p.leaf_json) }),

  merkle_node_hash: (p) => ({
    result: AcdpMerkle.nodeHash(p.left_hash, p.right_hash),
  }),

  merkle_root_hash: (p) => ({
    result: AcdpMerkle.rootHash(p.leaf_hashes_json),
  }),

  // ── did:web helpers (AcdpDid / AcdpDidDocument) ───────────────────────
  did_web_to_url: (p) => ({ result: AcdpDid.webToUrl(p.did) }),

  did_strip_fragment: (p) => ({ result: AcdpDid.stripFragment(p.did_url) }),

  // Parse a DID document and resolve a key. Returns { ok, key } on
  // success, or { ok: false, reason } carrying the stable Error.code so
  // the Python side can assert the reason vocabulary matches.
  did_key_for_algorithm: (p) => {
    try {
      const doc = AcdpDidDocument.parse(p.doc_json, p.expected_did);
      const k = doc.keyForAlgorithm(p.requested_key_id, p.requested_alg);
      return {
        ok: true,
        key: {
          key_id: k.keyId,
          algorithm: k.algorithm,
          public_key_b64: k.publicKeyB64,
        },
      };
    } catch (err) {
      return { ok: false, reason: err?.code ?? null };
    }
  },
};

const rl = createInterface({ input: process.stdin });
for await (const line of rl) {
  const trimmed = line.trim();
  if (!trimmed) continue;
  const req = JSON.parse(trimmed);
  let resp;
  try {
    const handler = methods[req.method];
    if (!handler) throw new Error(`unknown method: ${req.method}`);
    resp = { id: req.id, ok: true, result: await handler(req.params ?? {}) };
  } catch (err) {
    resp = { id: req.id, ok: false, error: String(err?.message ?? err) };
  }
  process.stdout.write(JSON.stringify(resp) + '\n');
}
