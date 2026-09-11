"""Cross-language ACDP interop integration tests.

Exercises a real ACDP producer flow where both ends run in *different
language runtimes*:

* the **Python** end runs in-process via the ``acdp`` extension built by
  ``maturin develop``, and
* the **Node** end runs in a ``node`` subprocess driven over
  line-delimited JSON-RPC (see ``node_worker.mjs``).

Both ends sign a `PublishRequest` from the same all-zero Ed25519 seed
with the same inputs. JCS + SHA-256 is deterministic and Ed25519 with a
fixed seed is deterministic too, so the `content_hash` AND the
`signature.value` MUST be byte-identical across both bindings. We also
cross-verify: Node verifies Python-produced bodies and vice versa.

Run from ``bindings/interop/`` after building both bindings::

    (cd ../acdp-py    && maturin develop)
    (cd ../acdp-node  && npm install && npm run build:debug)
    pytest

or simply ``make interop``, which builds both bindings first.

``acdp-node``'s ``package-lock.json`` is committed, so the ``npm install``
above resolves the pinned dependency graph rather than a fresh one.
"""

import json
import os
import re
import shutil
import subprocess
import sys

import pytest

import acdp


HERE = os.path.dirname(os.path.abspath(__file__))

# Identity used by both ends. The all-zero seed is what `sig-001` golden
# fixture uses, so its content_hash + signature are pinned constants in
# both binding test suites.
SEED = bytes(32)
AGENT_DID = "did:web:agents.example.com:test-producer"
KEY_ID = f"{AGENT_DID}#key-1"
GOLDEN_HASH = (
    "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5"
)
GOLDEN_SIG = (
    "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ=="
)
# sig-001/sig-002 were signed under the 0.1.x omitted-`acdp_version`
# form; the 0.2 builders emit the field by default, so the golden
# tests reproduce the pinned preimage via the explicit opt-out.
PY_OMIT = {"omit_acdp_version": True}
NODE_OMIT = {"omitAcdpVersion": True}


# ── Node side: a subprocess worker driven over JSON-RPC ─────────────────


class NodeWorker:
    """A ``node node_worker.mjs`` subprocess driven over JSON-RPC stdio."""

    def __init__(self) -> None:
        self._proc = subprocess.Popen(
            ["node", os.path.join(HERE, "node_worker.mjs")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,  # surface Node-side errors into pytest output
            text=True,
            bufsize=1,
        )
        self._next_id = 0

    def _rpc(self, method: str, params: dict) -> dict:
        self._next_id += 1
        request = {"id": self._next_id, "method": method, "params": params}
        self._proc.stdin.write(json.dumps(request) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            raise RuntimeError(
                f"node worker exited before answering {method!r}"
            )
        return json.loads(line)

    def call(self, method: str, **params):
        resp = self._rpc(method, params)
        if not resp.get("ok"):
            raise RuntimeError(f"node.{method} failed: {resp['error']}")
        return resp["result"]

    def call_expect_error(self, method: str, **params) -> str:
        resp = self._rpc(method, params)
        if resp.get("ok"):
            raise AssertionError(f"node.{method} unexpectedly succeeded")
        return resp["error"]

    def close(self) -> None:
        try:
            self._proc.stdin.close()
            self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()


@pytest.fixture(scope="module")
def node():
    """A live Node interop worker, shared across the module's tests."""
    if shutil.which("node") is None:
        pytest.skip("node executable not found on PATH")
    worker = NodeWorker()
    try:
        worker.call("ping")  # fail fast if the acdp-node binding is not built
        yield worker
    finally:
        worker.close()


# ── Tests ───────────────────────────────────────────────────────────────


def _python_publish(opts: dict) -> str:
    """Build a wire JSON publish request from the Python binding."""
    p = acdp.AcdpProducer.from_seed(SEED, AGENT_DID, KEY_ID)
    return p.build_publish_request(**opts)


def _node_publish(node, opts_camel: dict) -> str:
    """Build a wire JSON publish request from the Node binding."""
    producer = node.call(
        "new_producer", agent_did=AGENT_DID, key_id=KEY_ID, seed=list(SEED)
    )
    return node.call(
        "build_publish_request",
        producer=producer["handle"],
        opts=opts_camel,
    )["raw"]


def test_python_matches_golden_hash_and_signature():
    raw = _python_publish(
        {
            "title": "Golden test vector — minimal first version",
            "context_type": "data_snapshot",
            **PY_OMIT,
        }
    )
    req = json.loads(raw)
    assert req["content_hash"] == GOLDEN_HASH
    assert req["signature"]["value"] == GOLDEN_SIG


def test_node_matches_golden_hash_and_signature(node):
    raw = _node_publish(
        node,
        {
            "title": "Golden test vector — minimal first version",
            "contextType": "data_snapshot",
            **NODE_OMIT,
        },
    )
    req = json.loads(raw)
    assert req["content_hash"] == GOLDEN_HASH
    assert req["signature"]["value"] == GOLDEN_SIG


def test_python_and_node_emit_byte_identical_publish_requests(node):
    """The JCS + SHA-256 content_hash and the deterministic Ed25519
    signature MUST match byte-for-byte across both bindings when given
    the same seed and the same minimal first-version inputs.
    """
    py_raw = _python_publish(
        {
            "title": "Golden test vector — minimal first version",
            "context_type": "data_snapshot",
        }
    )
    node_raw = _node_publish(
        node,
        {
            "title": "Golden test vector — minimal first version",
            "contextType": "data_snapshot",
        },
    )
    py_req = json.loads(py_raw)
    node_req = json.loads(node_raw)

    assert py_req["content_hash"] == node_req["content_hash"]
    assert py_req["signature"]["value"] == node_req["signature"]["value"]
    assert py_req["signature"]["algorithm"] == node_req["signature"]["algorithm"]
    assert py_req["signature"]["key_id"] == node_req["signature"]["key_id"]
    assert py_req["agent_id"] == node_req["agent_id"]


def test_python_and_node_match_on_a_richer_body(node):
    """Same equality check with summary, tags, domain, derived_from,
    contributors set — exercises every optional field that lands in the
    hash preimage.
    """
    derived = (
        "acdp://registry.example.com/12345678-1234-4321-8123-123456781234"
    )
    py_raw = _python_publish(
        {
            "title": "Interop body",
            "context_type": "analysis",
            "summary": "rich body",
            "tags": ["interop", "golden"],
            "domain": "test.interop",
            "derived_from": [derived],
            "contributors": ["did:web:agents.example.com:contributor"],
            "description": "Cross-language byte-equality assertion.",
        }
    )
    node_raw = _node_publish(
        node,
        {
            "title": "Interop body",
            "contextType": "analysis",
            "summary": "rich body",
            "tags": ["interop", "golden"],
            "domain": "test.interop",
            "derivedFrom": [derived],
            "contributors": ["did:web:agents.example.com:contributor"],
            "description": "Cross-language byte-equality assertion.",
        },
    )
    assert json.loads(py_raw)["content_hash"] == json.loads(node_raw)["content_hash"]
    assert (
        json.loads(py_raw)["signature"]["value"]
        == json.loads(node_raw)["signature"]["value"]
    )


def test_node_verifies_python_signature(node):
    """A PublishRequest built in Python verifies cleanly through the
    Node verifier — same Ed25519 algorithm, same JCS preimage.
    """
    raw = _python_publish(
        {"title": "From Python", "context_type": "data_snapshot"}
    )
    req = json.loads(raw)
    pub_key_b64 = acdp.AcdpProducer.from_seed(
        SEED, AGENT_DID, KEY_ID
    ).public_key_b64

    assert node.call(
        "verify_content_hash",
        body_json=raw,
        expected_hash=req["content_hash"],
    )["ok"]
    assert node.call(
        "verify_signature",
        pub_key_b64=pub_key_b64,
        sig_b64=req["signature"]["value"],
        content_hash=req["content_hash"],
    )["ok"]


def test_python_verifies_node_signature(node):
    """And the reverse: Node-built request verifies in Python."""
    producer = node.call(
        "new_producer", agent_did=AGENT_DID, key_id=KEY_ID, seed=list(SEED)
    )
    raw = node.call(
        "build_publish_request",
        producer=producer["handle"],
        opts={"title": "From Node", "contextType": "data_snapshot"},
    )["raw"]
    req = json.loads(raw)

    assert acdp.AcdpVerifier.verify_content_hash(raw, req["content_hash"])
    assert acdp.AcdpVerifier.verify_signature(
        producer["public_key_b64"],
        req["signature"]["value"],
        req["content_hash"],
    )


CTX_BINDING_CTX = (
    "acdp://registry.example.com/12345678-1234-4321-8123-123456781234"
)
CTX_BINDING_OTHER_UUID = (
    "acdp://registry.example.com/00000000-0000-4000-8000-000000000000"
)
CTX_BINDING_OTHER_AUTHORITY = (
    "acdp://other.example.com/12345678-1234-4321-8123-123456781234"
)


def _body_with_ctx_id(ctx_id):
    """A full retrieval-shape `Body` JSON with the given `ctx_id` —
    `verify_ctx_id_binding` only reads `ctx_id`, so content_hash/signature need
    not be mutually consistent here."""
    return json.dumps(
        {
            "ctx_id": ctx_id,
            "lineage_id": "lin:sha256:" + "a" * 64,
            "origin_registry": "registry.example.com",
            "created_at": "2026-01-01T00:00:00.000Z",
            "version": 1,
            "supersedes": None,
            "agent_id": AGENT_DID,
            "contributors": [],
            "title": "interop ctx_id binding",
            "type": "data_snapshot",
            "data_refs": [],
            "derived_from": [],
            "visibility": "public",
            "content_hash": GOLDEN_HASH,
            "signature": {
                "algorithm": "ed25519",
                "key_id": KEY_ID,
                "value": GOLDEN_SIG,
            },
        }
    )


def test_verify_ctx_id_agrees_across_bindings_on_match(node):
    """Positive control: py and node both accept matching ids."""
    body = _body_with_ctx_id(CTX_BINDING_CTX)
    assert acdp.AcdpVerifier.verify_ctx_id_binding(body, CTX_BINDING_CTX)
    assert node.call(
        "verify_ctx_id_binding", body_json=body, expected_ctx_id=CTX_BINDING_CTX
    )["ok"]


def test_verify_ctx_id_agrees_across_bindings_on_mismatch(node):
    """py and node both reject a UUID-only mismatch AND an
    authority-only mismatch — and, critically, both reject it for the
    SAME reason (a served/expected mismatch), not just "both fail"."""
    body = _body_with_ctx_id(CTX_BINDING_CTX)
    with pytest.raises(Exception, match=r"(?i)context substitution") as py_exc:
        acdp.AcdpVerifier.verify_ctx_id_binding(body, CTX_BINDING_OTHER_UUID)
    node_err = node.call_expect_error(
        "verify_ctx_id_binding",
        body_json=body,
        expected_ctx_id=CTX_BINDING_OTHER_UUID,
    )
    assert "context substitution" in str(py_exc.value).lower()
    assert "context substitution" in node_err.lower()

    with pytest.raises(Exception, match=r"(?i)context substitution") as py_exc:
        acdp.AcdpVerifier.verify_ctx_id_binding(body, CTX_BINDING_OTHER_AUTHORITY)
    node_err = node.call_expect_error(
        "verify_ctx_id_binding",
        body_json=body,
        expected_ctx_id=CTX_BINDING_OTHER_AUTHORITY,
    )
    assert "context substitution" in str(py_exc.value).lower()
    assert "context substitution" in node_err.lower()


def test_verify_ctx_id_agrees_across_bindings_on_malformed(node):
    """py and node both reject a malformed expected ctx_id — and both
    for the SAME reason (a schema/parse violation, not a mismatch)."""
    body = _body_with_ctx_id(CTX_BINDING_CTX)
    with pytest.raises(ValueError) as py_exc:
        acdp.AcdpVerifier.verify_ctx_id_binding(body, "not-a-ctx-id")
    node_err = node.call_expect_error(
        "verify_ctx_id_binding", body_json=body, expected_ctx_id="not-a-ctx-id"
    )
    reason_re = re.compile(r"schema violation|invalid|ctx_id", re.IGNORECASE)
    assert reason_re.search(str(py_exc.value))
    assert reason_re.search(node_err)
    # And it must NOT be misreported as a mismatch on either side.
    assert "context substitution" not in str(py_exc.value).lower()
    assert "context substitution" not in node_err.lower()


# ── verify_receipt (RFC-ACDP-0010 §8 registry receipts) ──────────────────
#
# rcpt-001 golden vector: a receipt over the sig-001 content_hash, minted
# by a registry whose Ed25519 receipt key has seed [0x11]*32, binding the
# fp-001 producer-key fingerprint. Mirrors the py/node binding suites'
# own `RCPT001`/`RCPT_001` fixtures exactly.

RCPT_001 = {
    "registry_did": "did:web:registry.example.com",
    "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
    "lineage_id": "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
    "origin_registry": "registry.example.com",
    "created_at": "2026-04-16T10:30:15.123Z",
    "content_hash": "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
    "key_fingerprint": "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "did:web:registry.example.com#receipt-key-1",
        "value": "vBgQKmn17pHXXY95C07BBeconmjDIdYIvxN5B+YXrQ7tIzFsDNsh1TglzgxOyPUp8lwTz7zwMNiK+Sn5whveDg==",
    },
}

# The sig-001 body `RCPT_001` attests, assembled from sig-001's
# `producer_content`/`publish_request_body` plus its `registry_assigned`
# block — `rcpt-001-receipt-golden.json` ships no paired body. `supersedes`
# is included as `null` (not omitted): `Body` has no `#[serde(default)]`
# on that field, so the key MUST be present even when null.
RCPT_BODY = {
    "ctx_id": RCPT_001["ctx_id"],
    "lineage_id": RCPT_001["lineage_id"],
    "origin_registry": RCPT_001["origin_registry"],
    "created_at": RCPT_001["created_at"],
    "content_hash": RCPT_001["content_hash"],
    "signature": {
        "algorithm": "ed25519",
        "key_id": KEY_ID,
        "value": GOLDEN_SIG,
    },
    "version": 1,
    "supersedes": None,
    "agent_id": AGENT_DID,
    "contributors": [],
    "title": "Golden test vector — minimal first version",
    "type": "data_snapshot",
    "data_refs": [],
    "derived_from": [],
    "visibility": "public",
}

RCPT_REGISTRY_KEY_B64 = acdp.AcdpProducer.from_seed(
    bytes([0x11] * 32), "did:web:x", "did:web:x#k"
).public_key_b64


def test_verify_receipt_agrees_across_bindings_on_match(node):
    """Positive control: py and node both accept the rcpt-001 receipt
    against its accompanying body."""
    receipt_json = json.dumps(RCPT_001)
    body_json = json.dumps(RCPT_BODY)
    assert acdp.AcdpVerifier.verify_receipt(
        receipt_json,
        body_json,
        RCPT_REGISTRY_KEY_B64,
        RCPT_001["ctx_id"],
        RCPT_001["content_hash"],
        RCPT_001["key_fingerprint"],
    )
    assert node.call(
        "verify_receipt",
        receipt_json=receipt_json,
        body_json=body_json,
        registry_public_key_b64=RCPT_REGISTRY_KEY_B64,
        expected_ctx_id=RCPT_001["ctx_id"],
        recomputed_body_hash=RCPT_001["content_hash"],
        producer_key_fingerprint=RCPT_001["key_fingerprint"],
    )["ok"]


def test_verify_receipt_agrees_across_bindings_on_body_lineage_id_mismatch(node):
    """py and node both reject a body/receipt `lineage_id` mismatch (RFC-
    ACDP-0010 §8 step 3) — and, critically, both reject it for the SAME
    reason (a lineage_id body-binding mismatch), not just "both fail".
    Mirrors the pattern used for ctx_id binding (and PR #214) above."""
    receipt_json = json.dumps(RCPT_001)
    mismatched_body_json = json.dumps(
        {**RCPT_BODY, "lineage_id": "lin:sha256:" + "b" * 64}
    )
    with pytest.raises(Exception, match=r"(?i)lineage_id") as py_exc:
        acdp.AcdpVerifier.verify_receipt(
            receipt_json,
            mismatched_body_json,
            RCPT_REGISTRY_KEY_B64,
            RCPT_001["ctx_id"],
            RCPT_001["content_hash"],
            RCPT_001["key_fingerprint"],
        )
    node_err = node.call_expect_error(
        "verify_receipt",
        receipt_json=receipt_json,
        body_json=mismatched_body_json,
        registry_public_key_b64=RCPT_REGISTRY_KEY_B64,
        expected_ctx_id=RCPT_001["ctx_id"],
        recomputed_body_hash=RCPT_001["content_hash"],
        producer_key_fingerprint=RCPT_001["key_fingerprint"],
    )
    assert "lineage_id" in str(py_exc.value).lower()
    assert "lineage_id" in node_err.lower()


def test_verify_receipt_agrees_across_bindings_on_malformed_body(node):
    """py and node both reject a malformed body_json as a HOST-input
    error — distinguishable from a verification/mismatch failure — and
    for the same reason on both sides."""
    receipt_json = json.dumps(RCPT_001)
    with pytest.raises(ValueError, match=r"(?i)body") as py_exc:
        acdp.AcdpVerifier.verify_receipt(
            receipt_json,
            "not json",
            RCPT_REGISTRY_KEY_B64,
            RCPT_001["ctx_id"],
            RCPT_001["content_hash"],
            RCPT_001["key_fingerprint"],
        )
    node_err = node.call_expect_error(
        "verify_receipt",
        receipt_json=receipt_json,
        body_json="not json",
        registry_public_key_b64=RCPT_REGISTRY_KEY_B64,
        expected_ctx_id=RCPT_001["ctx_id"],
        recomputed_body_hash=RCPT_001["content_hash"],
        producer_key_fingerprint=RCPT_001["key_fingerprint"],
    )
    assert "body" in str(py_exc.value).lower()
    assert "body" in node_err.lower()
    # And it must NOT be misreported as a lineage_id/mismatch failure.
    assert "lineage_id" not in str(py_exc.value).lower()
    assert "lineage_id" not in node_err.lower()


def test_sign_challenge_is_deterministic_across_bindings(node):
    """Both bindings sign the same auth-challenge bytes with the same
    seed and MUST produce the same base64 signature.
    """
    signing_input = (
        "acdp-registry-auth:v1:nonce-abc:"
        f"{AGENT_DID}:registry.example.com:1748000000"
    )
    py_sig = acdp.AcdpProducer.from_seed(
        SEED, AGENT_DID, KEY_ID
    ).sign_challenge(signing_input)
    producer = node.call(
        "new_producer", agent_did=AGENT_DID, key_id=KEY_ID, seed=list(SEED)
    )
    node_sig = node.call(
        "sign_challenge",
        producer=producer["handle"],
        signing_input=signing_input,
    )["signature"]
    assert py_sig == node_sig


# ── ECDSA-P256 cross-language parity ─────────────────────────────────────

# sig-002 golden vector: private scalar = 1 (public key = the P-256
# generator G). ECDSA-P256 here is RFC 6979 deterministic in both
# bindings (both wrap the same Rust `p256` crate), so the signature
# value is reproducible AND byte-identical across languages.
P256_SEED = bytes(31) + bytes([1])
P256_GOLDEN_HASH = GOLDEN_HASH  # content_hash excludes the signature
P256_GOLDEN_SIG = (
    "O+b+E5OIecgwCnjDyTqsiwwy3VTdBHbVhiRR9k3FAPZHvLJ5dyYYVPPUWbl0dKDdgKMw2dWrnKWRANJVoS9vNw=="
)
P256_MINIMAL = {"title": "Golden test vector — minimal first version"}


def _python_p256_publish(opts: dict) -> str:
    p = acdp.AcdpP256Producer.from_seed(P256_SEED, AGENT_DID, KEY_ID)
    return p.build_publish_request(**opts)


def _node_p256_publish(node, opts_camel: dict) -> str:
    producer = node.call(
        "new_p256_producer", agent_did=AGENT_DID, key_id=KEY_ID, seed=list(P256_SEED)
    )
    return node.call(
        "build_publish_request",
        producer=producer["handle"],
        opts=opts_camel,
    )["raw"]


def test_p256_python_matches_golden():
    req = json.loads(
        _python_p256_publish(
            {**P256_MINIMAL, "context_type": "data_snapshot", **PY_OMIT}
        )
    )
    assert req["content_hash"] == P256_GOLDEN_HASH
    assert req["signature"]["algorithm"] == "ecdsa-p256"
    assert req["signature"]["value"] == P256_GOLDEN_SIG


def test_p256_node_matches_golden(node):
    req = json.loads(
        _node_p256_publish(
            node, {**P256_MINIMAL, "contextType": "data_snapshot", **NODE_OMIT}
        )
    )
    assert req["content_hash"] == P256_GOLDEN_HASH
    assert req["signature"]["algorithm"] == "ecdsa-p256"
    assert req["signature"]["value"] == P256_GOLDEN_SIG


def test_p256_python_and_node_emit_byte_identical_requests(node):
    """RFC 6979 deterministic ECDSA over P-256 MUST match byte-for-byte
    across both bindings given the same seed and inputs."""
    py_req = json.loads(
        _python_p256_publish({**P256_MINIMAL, "context_type": "data_snapshot"})
    )
    node_req = json.loads(
        _node_p256_publish(node, {**P256_MINIMAL, "contextType": "data_snapshot"})
    )
    assert py_req["content_hash"] == node_req["content_hash"]
    assert py_req["signature"]["value"] == node_req["signature"]["value"]
    assert py_req["signature"]["algorithm"] == node_req["signature"]["algorithm"] == "ecdsa-p256"


def test_p256_sign_challenge_is_deterministic_across_bindings(node):
    """RFC 6979 makes P-256 challenge signing reproducible, so both
    bindings MUST produce the same signature for the same input."""
    signing_input = (
        "acdp-registry-auth:v1:nonce-abc:"
        f"{AGENT_DID}:registry.example.com:1748000000"
    )
    py_sig = acdp.AcdpP256Producer.from_seed(
        P256_SEED, AGENT_DID, KEY_ID
    ).sign_challenge(signing_input)
    producer = node.call(
        "new_p256_producer", agent_did=AGENT_DID, key_id=KEY_ID, seed=list(P256_SEED)
    )
    node_sig = node.call(
        "sign_challenge",
        producer=producer["handle"],
        signing_input=signing_input,
    )["signature"]
    assert py_sig == node_sig


def test_node_verifies_python_p256_signature(node):
    """A P-256 PublishRequest built in Python verifies through the Node
    `verifySignatureP256` path — proves the new verifier surface is
    cross-compatible with the producer surface."""
    raw = _python_p256_publish({**P256_MINIMAL, "context_type": "data_snapshot"})
    req = json.loads(raw)
    pub_sec1 = acdp.AcdpP256Producer.from_seed(
        P256_SEED, AGENT_DID, KEY_ID
    ).public_key_sec1_b64
    assert node.call(
        "verify_signature_p256",
        pub_key_sec1_b64=pub_sec1,
        sig_b64=req["signature"]["value"],
        content_hash=req["content_hash"],
    )["ok"]


def test_python_verifies_node_p256_signature(node):
    """And the reverse: a Node-built P-256 request verifies in Python."""
    producer = node.call(
        "new_p256_producer", agent_did=AGENT_DID, key_id=KEY_ID, seed=list(P256_SEED)
    )
    raw = node.call(
        "build_publish_request",
        producer=producer["handle"],
        opts={**P256_MINIMAL, "contextType": "data_snapshot"},
    )["raw"]
    req = json.loads(raw)
    assert acdp.AcdpVerifier.verify_signature_p256(
        producer["public_key_sec1_b64"],
        req["signature"]["value"],
        req["content_hash"],
    )


def test_extended_body_fields_are_byte_identical_across_bindings(node):
    """data_refs / data_period / expires_at land in the content_hash
    preimage; both bindings must parse and canonicalize them identically,
    so the hash and signature match byte-for-byte."""
    data_refs = json.dumps(
        [{"type": "primary_result", "location": "https://example.com/d.parquet"}]
    )
    data_period = json.dumps(
        {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"}
    )
    expires_at = "2026-06-01T00:00:00Z"

    py_raw = _python_publish(
        {
            "title": "Extended body",
            "context_type": "data_snapshot",
            "data_refs": data_refs,
            "data_period": data_period,
            "expires_at": expires_at,
        }
    )
    node_raw = _node_publish(
        node,
        {
            "title": "Extended body",
            "contextType": "data_snapshot",
            "dataRefs": data_refs,
            "dataPeriod": data_period,
            "expiresAt": expires_at,
        },
    )
    py_req = json.loads(py_raw)
    node_req = json.loads(node_raw)
    assert py_req["content_hash"] == node_req["content_hash"]
    assert py_req["signature"]["value"] == node_req["signature"]["value"]
    # And the fields actually made it onto the wire.
    assert py_req["data_refs"][0]["location"] == "https://example.com/d.parquet"
    assert py_req["data_period"] == node_req["data_period"]
    assert py_req["expires_at"] == node_req["expires_at"]


def test_anchors_are_byte_identical_across_bindings(node):
    """`anchors` (RFC-ACDP-0016) lands in the content_hash preimage; both
    bindings must parse and canonicalize it identically, so the hash and
    signature match byte-for-byte. Exercises `uri` (present), and TWO
    `extensions` keys (via `#[serde(flatten)]`) in deliberately
    non-alphabetical insertion order — JCS re-sorts object keys before
    hashing, so this also guards against either binding's JSON layer
    (de)serializing extensions in a way that silently reorders or drops
    one before it reaches the canonicalizer."""
    anchors = json.dumps(
        [
            {
                "scheme": "macp.commitment",
                "content_hash": "sha256:fa8fe6b9143b469866d31de09b81928cc44d226ed935162cd346ae80d14fd200",
                "uri": "https://example.com/commitments/1",
                "note": "cross-binding interop fixture",
                "confidence": "high",
            }
        ]
    )

    py_raw = _python_publish(
        {
            "title": "Anchored body",
            "context_type": "data_snapshot",
            "anchors": anchors,
        }
    )
    node_raw = _node_publish(
        node,
        {
            "title": "Anchored body",
            "contextType": "data_snapshot",
            "anchors": anchors,
        },
    )
    py_req = json.loads(py_raw)
    node_req = json.loads(node_raw)
    assert py_req["content_hash"] == node_req["content_hash"]
    assert py_req["signature"]["value"] == node_req["signature"]["value"]
    # And the field itself — including both flattened extension keys —
    # round-tripped identically on both sides.
    assert py_req["anchors"] == node_req["anchors"]
    assert py_req["anchors"][0]["uri"] == "https://example.com/commitments/1"
    assert py_req["anchors"][0]["note"] == "cross-binding interop fixture"
    assert py_req["anchors"][0]["confidence"] == "high"


# ── AcdpCanonicalizer cross-language parity ──────────────────────────────

# JCS is deterministic, so both bindings MUST emit byte-identical
# canonical forms and content hashes for the same JSON input.
_CANON_INPUTS = [
    '{ "b": 1, "a": 2 }',
    '{"x": -0.0}',  # negative-zero normalization (the classic JCS bug)
    '{"z": [3, 2, 1], "a": {"d": 4, "c": 3}}',
    '{"k": "café — π", "n": 42, "deep": {"arr": [1, 2, {"q": true}]}}',
]


@pytest.mark.parametrize("doc", _CANON_INPUTS)
def test_canonicalize_is_byte_identical_across_bindings(node, doc):
    py_out = acdp.AcdpCanonicalizer.canonicalize(doc)
    node_out = node.call("canonicalize", json=doc)["result"]
    assert py_out == node_out


@pytest.mark.parametrize("doc", _CANON_INPUTS)
def test_content_hash_is_identical_across_bindings(node, doc):
    py_out = acdp.AcdpCanonicalizer.content_hash(doc)
    node_out = node.call("content_hash", json=doc)["result"]
    assert py_out == node_out
    assert py_out.startswith("sha256:")


# ── AcdpSsrfPolicy cross-language reason parity ──────────────────────────

# Each binding surfaces the same stable reason taxonomy — Python on
# `SsrfRejected.reason`, Node on `Error.code`. The verdict (allowed vs
# rejected) and the reason code MUST match across both for every input.
def _py_ssrf_url(url: str) -> dict:
    pol = acdp.AcdpSsrfPolicy.production()
    try:
        pol.check_url(url)
        return {"allowed": True}
    except acdp.SsrfRejected as e:
        return {"allowed": False, "reason": e.reason}


def _py_ssrf_ip(ip: str) -> dict:
    pol = acdp.AcdpSsrfPolicy.production()
    try:
        pol.check_ip(ip)
        return {"allowed": True}
    except acdp.SsrfRejected as e:
        return {"allowed": False, "reason": e.reason}


def _py_ssrf_redirect(from_url: str, to_url: str) -> dict:
    pol = acdp.AcdpSsrfPolicy.production()
    try:
        pol.check_redirect_authority(from_url, to_url)
        return {"allowed": True}
    except acdp.SsrfRejected as e:
        return {"allowed": False, "reason": e.reason}


@pytest.mark.parametrize(
    "url",
    [
        "https://registry.example.com",  # allowed
        "http://registry.example.com",  # non_https
        "https://192.168.1.1",  # ip_literal
        "https://[::1]",  # ip_literal
        "not a url",  # invalid_url
    ],
)
def test_ssrf_check_url_reason_matches_across_bindings(node, url):
    py = _py_ssrf_url(url)
    nd = node.call("ssrf_check_url", url=url)
    assert py["allowed"] == nd["allowed"]
    assert py.get("reason") == nd.get("reason")


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",  # loopback
        "10.0.0.1",  # private
        "169.254.169.254",  # imds
        "239.0.0.1",  # multicast_or_reserved
        "8.8.8.8",  # allowed
        "fc00::1",  # private
        "fe80::1",  # imds
        "64:ff9b::a9fe:a9fe",  # imds (NAT64)
        "::ffff:10.0.0.1",  # private (v4-mapped)
        "2001:db8::1",  # allowed
    ],
)
def test_ssrf_check_ip_reason_matches_across_bindings(node, ip):
    py = _py_ssrf_ip(ip)
    nd = node.call("ssrf_check_ip", ip=ip)
    assert py["allowed"] == nd["allowed"]
    assert py.get("reason") == nd.get("reason")


@pytest.mark.parametrize(
    "from_url,to_url",
    [
        ("https://a.example/x", "https://a.example/y"),  # allowed
        ("https://a.example/x", "https://a.example:443/y"),  # allowed (:443)
        ("https://a.example/x", "https://b.example/y"),  # cross_authority
        ("https://a.example/x", "https://a.example:8443/y"),  # cross_authority
        ("https://a.example/x", "http://a.example/y"),  # cross_authority
    ],
)
def test_ssrf_check_redirect_reason_matches_across_bindings(node, from_url, to_url):
    py = _py_ssrf_redirect(from_url, to_url)
    nd = node.call("ssrf_check_redirect", from_url=from_url, to_url=to_url)
    assert py["allowed"] == nd["allowed"]
    assert py.get("reason") == nd.get("reason")


# ── did:web helpers (AcdpDid / AcdpDidDocument) ─────────────────────────

import base64  # noqa: E402  (kept local to the did helpers below)

_DID = "did:web:agents.example.com"
_DID_KEY_ID = f"{_DID}#key-1"


def _did_doc_for(public_key_b64: str, *, authorized: bool = True) -> str:
    """A did:web document carrying `public_key_b64` as the `#key-1`
    JsonWebKey2020 method, optionally authorized in assertionMethod."""
    raw = base64.b64decode(public_key_b64)
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return json.dumps(
        {
            "id": _DID,
            "verificationMethod": [
                {
                    "id": _DID_KEY_ID,
                    "type": "JsonWebKey2020",
                    "controller": _DID,
                    "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x},
                }
            ],
            "assertionMethod": [_DID_KEY_ID] if authorized else [],
        }
    )


def _py_did_resolve(doc_json: str, key_id: str, alg: str) -> dict:
    try:
        doc = acdp.AcdpDidDocument.parse(doc_json, _DID)
        k = doc.key_for_algorithm(key_id, alg)
        return {"ok": True, "key": k}
    except acdp.DidResolutionError as e:
        return {"ok": False, "reason": e.reason}


def test_did_web_to_url_matches_across_bindings(node):
    for did in ("did:web:example.com", "did:web:example.com:users:alice"):
        assert acdp.AcdpDid.web_to_url(did) == node.call("did_web_to_url", did=did)["result"]


def test_did_key_extraction_matches_across_bindings(node):
    """A document built from a deterministic producer's public key MUST
    resolve to that same key on both bindings — proving the
    assertionMethod gate + JWK extraction agree byte-for-byte."""
    p = acdp.AcdpProducer.from_seed(SEED, _DID, _DID_KEY_ID)
    doc_json = _did_doc_for(p.public_key_b64)

    py = _py_did_resolve(doc_json, _DID_KEY_ID, "ed25519")
    nd = node.call(
        "did_key_for_algorithm",
        doc_json=doc_json,
        expected_did=_DID,
        requested_key_id=_DID_KEY_ID,
        requested_alg="ed25519",
    )
    assert py["ok"] and nd["ok"]
    assert py["key"]["public_key_b64"] == nd["key"]["public_key_b64"] == p.public_key_b64


@pytest.mark.parametrize(
    "doc_authorized,key_id,alg,expected_reason",
    [
        (True, _DID_KEY_ID, "ecdsa-p256", "alg_mismatch"),  # downgrade defense
        (False, _DID_KEY_ID, "ed25519", "key_not_authorized"),  # not in assertionMethod
        (True, f"{_DID}#key-2", "ed25519", "key_not_found"),  # unknown fragment
        (True, _DID_KEY_ID, "rsa", "unsupported_algorithm"),
    ],
)
def test_did_rejection_reason_matches_across_bindings(
    node, doc_authorized, key_id, alg, expected_reason
):
    p = acdp.AcdpProducer.from_seed(SEED, _DID, _DID_KEY_ID)
    doc_json = _did_doc_for(p.public_key_b64, authorized=doc_authorized)

    py = _py_did_resolve(doc_json, key_id, alg)
    nd = node.call(
        "did_key_for_algorithm",
        doc_json=doc_json,
        expected_did=_DID,
        requested_key_id=key_id,
        requested_alg=alg,
    )
    assert py["ok"] is False and nd["ok"] is False
    assert py["reason"] == nd["reason"] == expected_reason
