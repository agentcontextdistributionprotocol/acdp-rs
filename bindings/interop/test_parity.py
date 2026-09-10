"""Cross-binding parity guards: keep the Python and Node SDKs in sync.

These tests fail — locally via ``make interop`` and in CI — the moment the
two bindings drift apart:

* **API-surface parity** — the Python (``acdp-py``) binding, the Node
  (``acdp-node``) binding, and the shared manifest
  (``expected_surface.json``) MUST all expose the same classes and the
  same methods. Method names are normalized to snake_case so Node's
  camelCase compares equal. Adding a method to one binding without the
  other — or without updating the manifest — is a failure.

* **wasm surface parity** — ``bindings/acdp-wasm`` is a flat
  ``#[wasm_bindgen]`` function surface (no classes) that legitimately
  diverges from the py/node class-based surface in a few places — those
  are pinned as permanent aliases in ``expected_surface.json``'s ``wasm``
  block, never silently "fixed" by renaming a shipped npm export. Unlike
  py/node, the wasm pkg is a gitignored build artifact
  (``bindings/acdp-wasm/pkg/``) most machines won't have, so these tests
  ``pytest.skip`` when it's absent — unless ``ACDP_REQUIRE_WASM_PARITY=1``
  (set in CI), which turns absence into a hard failure.

* **Version parity** — ``pyproject.toml``, both bindings' ``Cargo.toml``,
  ``acdp-wasm/Cargo.toml``, and ``package.json`` MUST carry the same
  version.

The manifest is the single source of truth: when you intentionally change
the public API, update ``expected_surface.json`` in the same change and
both bindings to match.

Run from ``bindings/interop/`` (after building both bindings), or via
``make interop``. Build the wasm pkg first (``make sdk-wasm``, or set
``ACDP_REQUIRE_WASM_PARITY=1``) to also exercise the wasm parity checks —
otherwise they skip.
"""

import json
import os
import re
import shutil
import subprocess
import sys

import pytest

import acdp

from test_interop import NodeWorker  # reuse the JSON-RPC worker harness

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
MANIFEST = os.path.join(HERE, "expected_surface.json")


def _load_manifest() -> dict:
    with open(MANIFEST, encoding="utf-8") as fh:
        return json.load(fh)["classes"]


def _load_wasm_manifest() -> dict:
    with open(MANIFEST, encoding="utf-8") as fh:
        return json.load(fh)["wasm"]


def _python_surface(class_name: str) -> list[str]:
    """The public surface of a Python binding class, snake_case (already)."""
    cls = getattr(acdp, class_name)
    return sorted(n for n in dir(cls) if not n.startswith("_"))


# ── API-surface parity ───────────────────────────────────────────────────


@pytest.fixture(scope="module")
def node():
    if shutil.which("node") is None:
        pytest.skip("node executable not found on PATH")
    worker = NodeWorker()
    try:
        worker.call("ping")  # fail fast if the acdp-node binding is not built
        yield worker
    finally:
        worker.close()


def test_python_surface_matches_manifest():
    manifest = _load_manifest()
    for class_name, methods in manifest.items():
        assert _python_surface(class_name) == sorted(methods), (
            f"Python {class_name} surface drifted from expected_surface.json"
        )


def test_node_surface_matches_manifest(node):
    manifest = _load_manifest()
    described = node.call("describe")["classes"]
    for class_name, methods in manifest.items():
        assert class_name in described, f"Node binding missing class {class_name}"
        assert sorted(described[class_name]) == sorted(methods), (
            f"Node {class_name} surface drifted from expected_surface.json"
        )


def test_python_and_node_class_sets_match(node):
    described = node.call("describe")["classes"]
    manifest = _load_manifest()
    assert set(described) == set(manifest), "Node class set drifted from manifest"
    # And every manifest class is actually importable from the Python SDK.
    for class_name in manifest:
        assert hasattr(acdp, class_name), f"Python binding missing class {class_name}"


def test_python_and_node_method_sets_match_each_other(node):
    """The strongest sync assertion: per class, the two bindings expose an
    identical (snake_case-normalized) method set — independent of the
    manifest, so the bindings can never silently diverge from each other."""
    described = node.call("describe")["classes"]
    for class_name in _load_manifest():
        py = _python_surface(class_name)
        nd = sorted(described[class_name])
        assert py == nd, (
            f"{class_name} surface differs between bindings:\n"
            f"  python only: {sorted(set(py) - set(nd))}\n"
            f"  node only:   {sorted(set(nd) - set(py))}"
        )


# ── wasm parity ───────────────────────────────────────────────────────────
#
# bindings/acdp-wasm is a flat #[wasm_bindgen] surface (25 free functions,
# no classes) that diverges from the py/node class-based surface in a few
# places — those divergences are permanent aliases (renaming a shipped npm
# export is breaking), never "fixes". expected_surface.json's "wasm" block
# is the manifest; see its "_comment" for the schema. Unlike py/node, this
# is a build artifact under bindings/acdp-wasm/pkg/ (gitignored) that most
# contributor machines won't have built, so these tests skip — rather than
# fail — when it's absent, unless ACDP_REQUIRE_WASM_PARITY=1 (CI sets it).


def _wasm_functions(node) -> list[str]:
    """The reflected wasm export surface (snake_case, sorted), or
    pytest.skip (pytest.fail under ACDP_REQUIRE_WASM_PARITY=1) if the
    acdp-wasm pkg/ build artifact isn't present."""
    result = node.call("describe_wasm")
    if result.get("available"):
        return sorted(result["functions"])
    reason = result.get("reason", "unknown reason")
    message = (
        f"acdp-wasm pkg/ not available ({reason}); build it with "
        "`make sdk-wasm` (or `cd bindings/acdp-wasm && wasm-pack build "
        "--target web --out-dir pkg`) to enable wasm parity checks"
    )
    if os.environ.get("ACDP_REQUIRE_WASM_PARITY") == "1":
        pytest.fail(message)
    pytest.skip(message)


def _wasm_resolve(class_name: str, method: str, aliases: dict) -> str | None:
    """The wasm function name a class method resolves to: its alias entry
    (which may be None for an explicit per-method absence) or, absent an
    alias, the identity (same snake_case name)."""
    return aliases.get(method, method)


def test_wasm_reflected_surface_matches_manifest(node):
    """Invariant 1: the live reflected wasm export surface is exactly
    `wasm.functions` (sorted, snake_case-normalized) — nothing added or
    removed from the wasm pkg without updating the manifest."""
    functions = _wasm_functions(node)
    manifest = _load_wasm_manifest()
    assert functions == sorted(manifest["functions"]), (
        "wasm reflected surface drifted from expected_surface.json's "
        "wasm.functions"
    )


def test_wasm_class_methods_resolve(node):
    """Invariant 2: every method of every non-"absent" class resolves —
    via its alias entry or the identity default — to a name in
    wasm.functions, except an explicit alias-value null (that one method
    has no wasm counterpart at all). Checked against the manifest's own
    `wasm.functions` list (not live reflection — that's invariant 1's
    job), so this invariant is a pure manifest self-consistency check;
    `_wasm_functions(node)` is called only to gate skip/require
    semantics identically to the other three invariants."""
    _wasm_functions(node)  # gate: skip/fail per wasm-availability semantics
    manifest = _load_wasm_manifest()
    functions = set(manifest["functions"])
    classes = _load_manifest()
    for class_name, mapping in manifest["class_map"].items():
        if mapping == "absent":
            continue
        aliases = mapping.get("aliases", {})
        for method in classes[class_name]:
            resolved = _wasm_resolve(class_name, method, aliases)
            if resolved is None:
                continue  # explicit per-method absence
            assert resolved in functions, (
                f"{class_name}.{method} resolves to {resolved!r}, which is "
                "not in wasm.functions"
            )


def test_wasm_no_unclassified_exports(node):
    """Invariant 3: set(wasm.functions) == the resolved names of every
    present class's methods, unioned with wasm_only — no entry in the
    manifest's `wasm.functions` can ever go unclassified. Checked
    against the manifest's own `functions` list (not live reflection —
    invariant 1 already pins the manifest to reality), so a stray or
    fake name added straight to wasm.functions is caught HERE, by this
    invariant, even though it would also make invariant 1 fail."""
    _wasm_functions(node)  # gate: skip/fail per wasm-availability semantics
    manifest = _load_wasm_manifest()
    functions = set(manifest["functions"])
    classes = _load_manifest()
    resolved: set[str] = set()
    for class_name, mapping in manifest["class_map"].items():
        if mapping == "absent":
            continue
        aliases = mapping.get("aliases", {})
        for method in classes[class_name]:
            name = _wasm_resolve(class_name, method, aliases)
            if name is not None:
                resolved.add(name)
    resolved |= set(manifest["wasm_only"])
    assert functions == resolved, (
        "wasm.functions and (classified methods ∪ wasm_only) diverge:\n"
        f"  wasm.functions only: {sorted(functions - resolved)}\n"
        f"  classified only:     {sorted(resolved - functions)}"
    )


def test_wasm_manifest_structural_hygiene(node):
    """Invariant 4: structural hygiene of the manifest itself — every
    alias key is actually a method of that class per `classes`; every
    alias value and every wasm_only entry names a real wasm.functions
    entry; every `classes` key is classified in class_map. Gated on the
    same `node`/wasm-availability fixture path as the other three
    invariants for consistent skip semantics, even though this check
    only inspects the manifest (no live reflection)."""
    _wasm_functions(node)  # gate: skip/fail per wasm-availability semantics
    manifest = _load_wasm_manifest()
    functions = set(manifest["functions"])
    classes = _load_manifest()

    assert set(classes) == set(manifest["class_map"]), (
        "every classes key must be classified in wasm.class_map (and "
        "vice versa)"
    )
    for class_name, mapping in manifest["class_map"].items():
        if mapping == "absent":
            continue
        aliases = mapping.get("aliases", {})
        methods = set(classes[class_name])
        for key, value in aliases.items():
            assert key in methods, (
                f"wasm.class_map.{class_name}.aliases key {key!r} is not "
                f"a method of {class_name} in classes"
            )
            if value is not None:
                assert value in functions, (
                    f"wasm.class_map.{class_name}.aliases[{key!r}] = "
                    f"{value!r} is not in wasm.functions"
                )
    for name in manifest["wasm_only"]:
        assert name in functions, f"wasm_only entry {name!r} not in wasm.functions"


# ── Version parity ───────────────────────────────────────────────────────


def _version_from_toml(path: str) -> str:
    """Read the package `version = "..."` from a TOML file without a TOML
    dependency (the line format is stable in these manifests)."""
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    raise AssertionError(f"no version found in {path}")


def _version_from_json(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["version"]


def test_binding_versions_are_in_sync():
    versions = {
        "acdp-py/pyproject.toml": _version_from_toml(
            os.path.join(REPO, "bindings", "acdp-py", "pyproject.toml")
        ),
        "acdp-py/Cargo.toml": _version_from_toml(
            os.path.join(REPO, "bindings", "acdp-py", "Cargo.toml")
        ),
        "acdp-node/Cargo.toml": _version_from_toml(
            os.path.join(REPO, "bindings", "acdp-node", "Cargo.toml")
        ),
        "acdp-node/package.json": _version_from_json(
            os.path.join(REPO, "bindings", "acdp-node", "package.json")
        ),
        "acdp-wasm/Cargo.toml": _version_from_toml(
            os.path.join(REPO, "bindings", "acdp-wasm", "Cargo.toml")
        ),
    }
    assert len(set(versions.values())) == 1, (
        f"binding versions out of sync: {versions}"
    )


def test_node_reported_version_matches_package(node):
    pkg_version = _version_from_json(
        os.path.join(REPO, "bindings", "acdp-node", "package.json")
    )
    assert node.call("describe")["version"] == pkg_version


if __name__ == "__main__":  # convenience: `python test_parity.py`
    sys.exit(pytest.main([__file__, "-v"]))
