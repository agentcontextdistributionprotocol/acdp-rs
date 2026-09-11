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

import inspect
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
NODE_DTS = os.path.join(REPO, "bindings", "acdp-node", "index.d.ts")
WASM_DTS = os.path.join(REPO, "bindings", "acdp-wasm", "pkg", "acdp_wasm.d.ts")


def _load_manifest() -> dict:
    with open(MANIFEST, encoding="utf-8") as fh:
        return json.load(fh)["classes"]


def _load_wasm_manifest() -> dict:
    with open(MANIFEST, encoding="utf-8") as fh:
        return json.load(fh)["wasm"]


def _load_arity_manifest() -> dict:
    with open(MANIFEST, encoding="utf-8") as fh:
        data = json.load(fh)
    arity = dict(data["arity"])
    arity.pop("_comment", None)
    return arity


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


# ── Arity parity (issue #242) ────────────────────────────────────────────
#
# Name-only parity (above) can't catch a field silently added to one
# binding's options object and not the other — and for the 4 "wide"
# methods (`{AcdpProducer,AcdpP256Producer}.build_{publish,supersede}_
# request`, which take a single camelCase options object on the Node
# side instead of ~15-19 plain parameters) that's exactly the surface
# most likely to drift, because a new field there is a new
# `content_hash` preimage input. `expected_surface.json`'s "arity" block
# pins REQUIRED and TOTAL parameter counts alongside the method names in
# "classes", so a drift in either direction fails loudly.
#
# Sources, one per binding — and NEVER `Function.length` anywhere below:
#   * Python  — `inspect.signature`, excluding `self`/`cls` and any
#     `*args`/`**kwargs` (none occur in this SDK). A property getter
#     makes `inspect.signature` raise `TypeError`; that is how a
#     "property" entry is detected, not a separate lookup.
#   * Node    — `bindings/acdp-node/index.d.ts`, parsed directly (no
#     subprocess, no live reflection needed). Measured against this
#     repo's own build: every native (napi-rs) method reports
#     `Function.length === 0` regardless of true arity — no JS-level
#     signal at all — so the `.d.ts` is the only real source of truth.
#   * wasm    — `bindings/acdp-wasm/pkg/acdp_wasm.d.ts`, parsed the same
#     way, anchored on `^export function` (see `_parse_wasm_dts_arity`'s
#     docstring for why the bare export name is a trap).
#
# The one normalization rule (verified against all 61 manifest entries —
# zero mismatches, including the 4 wide methods): expand a *parameter*
# whose declared type names an `export interface` in the same `.d.ts`
# file into that interface's own fields. Never expand a *return* type
# (`keyForAlgorithm(...): ResolvedDidKey` is the one such case in
# `index.d.ts` today) — this falls out for free here because the
# parsers below only ever look inside the parameter list, never at what
# follows the closing `)`.
#
# Required-ness keys off the trailing `?` on a field/param, NEVER off a
# `| null` union: a non-trailing `Option<T>` is declared as
# `name: T | null | undefined` (no `?`) in both `index.d.ts` and
# `acdp_wasm.d.ts`, and is REQUIRED despite the null in its type.

_INTERFACE_DECL_RE = re.compile(r"^export interface (\w+) \{$")
_CLASS_DECL_RE = re.compile(r"^export declare class (\w+) \{$")
_GETTER_RE = re.compile(r"^\s*(?:static\s+)?get\s+(\w+)\(\)\s*:")
_METHOD_RE = re.compile(r"^\s*(?:static\s+)?(\w+)\((.*)\)\s*:\s*.+$")
_PARAM_RE = re.compile(r"^(\w+)(\?)?:\s*(.+)$")
_WASM_EXPORT_RE = re.compile(r"^export function (\w+)\((.*)\):\s*.+;$")


def _camel_to_snake(name: str) -> str:
    """Mirror `node_worker.mjs`'s `toSnake` exactly (insert `_` before
    every uppercase letter, then lowercase) — the same normalization the
    live `describe` / `describe_wasm` RPCs apply, so a name computed
    here from a static `.d.ts` file must equal one reflected over the
    wire elsewhere in this suite."""
    return re.sub(r"([A-Z])", r"_\1", name).lower()


def _split_top_level(params: str) -> list[str]:
    """Split a `.d.ts` parameter list on commas, honoring nested
    `<...>` / `(...)` / `{...}` / `[...]` depth. No parameter in this
    SDK's surface nests a comma inside its own type today, but a bare
    `str.split(",")` would silently mis-split the day one does."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in params:
        if ch in "<({[":
            depth += 1
        elif ch in ">)}]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def _parse_dts_interfaces(lines: list[str]) -> dict[str, list[tuple[str, bool]]]:
    """Every `export interface Name { field?: T; ... }` block in a
    `.d.ts` file → `{Name: [(field_name, required), ...]}`. Doc-comment
    lines (`/**`, `*`, `*/`) are skipped by construction — they never
    start with a word character, so `_PARAM_RE` simply doesn't match
    them."""
    interfaces: dict[str, list[tuple[str, bool]]] = {}
    i = 0
    while i < len(lines):
        m = _INTERFACE_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        fields: list[tuple[str, bool]] = []
        i += 1
        while lines[i].strip() != "}":
            stripped = lines[i].strip()
            if stripped and not stripped.startswith(("/", "*")):
                fm = _PARAM_RE.match(stripped)
                if fm:
                    fields.append((fm.group(1), fm.group(2) is None))
            i += 1
        interfaces[name] = fields
        i += 1
    return interfaces


def _arity_from_dts_params(
    params: str, interfaces: dict[str, list[tuple[str, bool]]]
) -> tuple[int, int]:
    """(required, total) over a `.d.ts` parameter list, expanding any
    parameter whose declared type names an entry of `interfaces` into
    that interface's own fields — the single normalization rule this
    guard needs."""
    required = total = 0
    for token in _split_top_level(params):
        pm = _PARAM_RE.match(token)
        if not pm:
            continue
        _name, opt, type_text = pm.groups()
        type_text = type_text.strip()
        if type_text in interfaces:
            for _field_name, field_required in interfaces[type_text]:
                total += 1
                if field_required:
                    required += 1
        else:
            total += 1
            if opt is None:
                required += 1
    return required, total


def _parse_node_dts_arity(path: str) -> dict[str, dict]:
    """Every `export declare class Name { ... }` block in `index.d.ts`
    → `{Name: {snake_case_method: (required, total) | "property"}}`.

    Anchored on the two declaration shapes NAPI-RS actually emits for a
    method (`static? name(...): T`) and a getter (`static? get
    name(): T`) — never on `Function.length` (see the module-level
    comment above)."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    interfaces = _parse_dts_interfaces(lines)

    classes: dict[str, dict] = {}
    i = 0
    while i < len(lines):
        m = _CLASS_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        cname = m.group(1)
        methods: dict[str, object] = {}
        i += 1
        while lines[i].strip() != "}":
            line = lines[i]
            stripped = line.strip()
            if not stripped or stripped.startswith(("/", "*")):
                i += 1
                continue
            gm = _GETTER_RE.match(line)
            if gm:
                methods[_camel_to_snake(gm.group(1))] = "property"
                i += 1
                continue
            mm = _METHOD_RE.match(line)
            if mm:
                mname, params = mm.groups()
                methods[_camel_to_snake(mname)] = _arity_from_dts_params(
                    params, interfaces
                )
            i += 1
        classes[cname] = methods
        i += 1
    return classes


def _parse_wasm_dts_arity(path: str) -> dict[str, tuple[int, int]]:
    """Every top-level `export function name(...): T;` in
    `acdp_wasm.d.ts` → `{snake_case_name: (required, total)}`.

    **Anchored on `^export function` — deliberately not a bare-name
    grep.** `acdp_wasm.d.ts` also declares an `InitOutput` interface
    (e.g. `readonly verifyLineageHeadReceipt: (a, b, ..., m) => void`,
    13 raw wasm-ABI arguments for a method whose real signature takes 6)
    that re-declares every export's name at its raw ABI arity. A parser
    that matched the bare name would silently read those numbers
    instead. Anchoring on the full `^export function` declaration line
    excludes `InitOutput` (its lines read `readonly name: (...) =>
    void`, not `export function name(...): T;`) — that's the trap this
    anchor exists to avoid, and it works. It also excludes
    `export default function __wbg_init`, since the `default` keyword
    breaks the `^export function` match. It does NOT exclude
    `initSync`: that bootstrap helper is declared `export function
    initSync(...): InitOutput;`, so it matches and lands in the
    returned dict as `init_sync`. That's harmless — every lookup here
    is driven from the manifest or from Python's surface, never from
    this dict's key set, so an extra `init_sync` entry is never
    consulted."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    functions: dict[str, tuple[int, int]] = {}
    for line in lines:
        m = _WASM_EXPORT_RE.match(line.strip())
        if not m:
            continue
        name, params = m.groups()
        required = total = 0
        for token in _split_top_level(params):
            pm = _PARAM_RE.match(token)
            if not pm:
                continue
            _pname, opt, _type_text = pm.groups()
            total += 1
            if opt is None:
                required += 1
        functions[_camel_to_snake(name)] = (required, total)
    return functions


def _python_arity(class_name: str) -> dict:
    """Required/total arity for every public method of a Python binding
    class, via `inspect.signature` — excluding `self`/`cls` and any
    `*args`/`**kwargs` (none occur in this SDK's surface). A getter
    raises `TypeError` from `inspect.signature`; that is recorded as the
    literal string `"property"`."""
    cls = getattr(acdp, class_name)
    result: dict[str, object] = {}
    for name in _python_surface(class_name):
        attr = getattr(cls, name)
        try:
            sig = inspect.signature(attr)
        except (TypeError, ValueError):
            result[name] = "property"
            continue
        required = total = 0
        for p in sig.parameters.values():
            if p.name in ("self", "cls") or p.kind in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            ):
                continue
            total += 1
            if p.default is inspect.Parameter.empty:
                required += 1
        result[name] = (required, total)
    return result


def _python_arity_all() -> dict:
    return {cn: _python_arity(cn) for cn in _load_manifest()}


def _node_arity_all() -> dict:
    return _parse_node_dts_arity(NODE_DTS)


def _require_wasm_dts() -> str:
    """Path to the wasm `.d.ts`, or `pytest.skip` (`pytest.fail` under
    `ACDP_REQUIRE_WASM_PARITY=1`) if the gitignored `pkg/` build
    artifact isn't present — the same skip-vs-fail semantics
    `_wasm_functions` uses above, applied independently here since the
    arity checks parse the `.d.ts` directly and need no live `node`
    worker at all."""
    if os.path.isfile(WASM_DTS):
        return WASM_DTS
    message = (
        f"{WASM_DTS} not found; build it with `make sdk-wasm` (or `cd "
        "bindings/acdp-wasm && wasm-pack build --target web --out-dir "
        "pkg`) to enable wasm arity checks"
    )
    if os.environ.get("ACDP_REQUIRE_WASM_PARITY") == "1":
        pytest.fail(message)
    pytest.skip(message)


def test_python_arity_matches_manifest():
    """A1 — Python's `inspect.signature`-derived arity equals the
    manifest, for every one of the 61 entries."""
    manifest = _load_arity_manifest()
    python_arity = _python_arity_all()
    for class_name, methods in manifest.items():
        for method, expected in methods.items():
            got = python_arity[class_name][method]
            expected = tuple(expected) if isinstance(expected, list) else expected
            assert got == expected, (
                f"Python {class_name}.{method} arity {got} != manifest {expected}"
            )


def test_node_dts_arity_matches_manifest():
    """A2 — Node's `.d.ts`-derived arity (interface-expanded) equals the
    manifest, for every one of the 61 entries. Independent of A1: this
    reads only `index.d.ts`, never the Python extension."""
    manifest = _load_arity_manifest()
    node_arity = _node_arity_all()
    for class_name, methods in manifest.items():
        for method, expected in methods.items():
            got = node_arity[class_name][method]
            expected = tuple(expected) if isinstance(expected, list) else expected
            assert got == expected, (
                f"Node {class_name}.{method} arity {got} != manifest {expected}"
            )


def test_wasm_dts_arity_matches_manifest():
    """A3 — wasm's `.d.ts`-derived arity equals the manifest, for every
    class-mapped (non-"absent") method that resolves to a real wasm
    export. Independent of A2 even though both parse a `.d.ts`: this
    reads `acdp_wasm.d.ts`, a different file, produced by a different
    generator (wasm-bindgen, not napi-rs). Python (`inspect.signature`)
    is the only independently-sourced column here, and it anchors all
    61 entries through A1 and through A5's Python==Node leg — so a
    wrong-but-matching pair of JS numbers still reddens, unless the
    `.d.ts` had drifted AND the shared parsing helpers (`_split_top_level`,
    `_PARAM_RE`, `_camel_to_snake`) happened to mask it by exactly that
    amount on both sides at once — a double coincidence, not a single
    failure. Entry-dropping bugs fail loudly rather than silently: this
    test iterates the manifest and looks up the parsed dict, so a
    dropped entry raises `KeyError`. Skips (or fails under
    `ACDP_REQUIRE_WASM_PARITY=1`) when the gitignored wasm `pkg/` isn't
    built."""
    path = _require_wasm_dts()
    manifest = _load_arity_manifest()
    wasm_manifest = _load_wasm_manifest()
    wasm_arity = _parse_wasm_dts_arity(path)
    for class_name, mapping in wasm_manifest["class_map"].items():
        if mapping == "absent":
            continue
        aliases = mapping.get("aliases", {})
        for method, expected in manifest[class_name].items():
            if expected == "property":
                continue
            resolved = _wasm_resolve(class_name, method, aliases)
            if resolved is None:
                continue
            got = wasm_arity[resolved]
            expected = tuple(expected)
            assert got == expected, (
                f"wasm {class_name}.{method} (-> {resolved}) arity {got} "
                f"!= manifest {expected}"
            )


def test_arity_manifest_structural_hygiene():
    """A4 — manifest-only: every `arity` key is a `classes` entry and
    vice versa, and every non-"property" value is `[required, total]`
    with `required <= total`. Deliberately reads ONLY
    `expected_surface.json` — no Python/Node/wasm extraction at all —
    so a probe that corrupts the manifest itself (e.g. a `ghost_method`
    entry, or `required > total`) reddens this test with no build step
    of any kind."""
    classes = _load_manifest()
    arity = _load_arity_manifest()
    assert set(arity) == set(classes), (
        "arity top-level keys must be exactly the classes entries"
    )
    for class_name, methods in classes.items():
        arity_methods = arity[class_name]
        assert set(arity_methods) == set(methods), (
            f"arity.{class_name} method set != classes.{class_name}"
        )
        for method, value in arity_methods.items():
            if value == "property":
                continue
            assert (
                isinstance(value, list)
                and len(value) == 2
                and all(isinstance(n, int) for n in value)
            ), f"arity.{class_name}.{method} must be \"property\" or [int, int]: {value!r}"
            required, total = value
            assert required <= total, (
                f"arity.{class_name}.{method}: required ({required}) > total ({total})"
            )


def test_arity_cross_binding_matches():
    """A5 — cross-binding: Python's extracted arity equals Node's, and
    equals wasm's for every class-mapped method — computed directly
    from each binding's own source, independent of the manifest. This
    is what a manifest-corrupting probe (A4's target) must NOT be able
    to turn green by accident, and what catches a parser bug shared
    between A2 and A3 (both parse a `.d.ts`) that happened to agree
    with the manifest for the wrong reason — though A2/A3 read
    different files from different generators, so that specific
    failure mode is already unlikely; this test does not depend on that
    being true."""
    python_arity = _python_arity_all()
    node_arity = _node_arity_all()
    for class_name, methods in python_arity.items():
        for method, py_value in methods.items():
            nd_value = node_arity[class_name][method]
            assert py_value == nd_value, (
                f"{class_name}.{method} arity differs: python={py_value} "
                f"node={nd_value}"
            )

    path = _require_wasm_dts()  # skip, or fail under ACDP_REQUIRE_WASM_PARITY=1
    wasm_manifest = _load_wasm_manifest()
    wasm_arity = _parse_wasm_dts_arity(path)
    for class_name, mapping in wasm_manifest["class_map"].items():
        if mapping == "absent":
            continue
        aliases = mapping.get("aliases", {})
        for method, py_value in python_arity[class_name].items():
            if py_value == "property":
                continue
            resolved = _wasm_resolve(class_name, method, aliases)
            if resolved is None:
                continue
            wasm_value = wasm_arity[resolved]
            assert py_value == wasm_value, (
                f"{class_name}.{method} (-> {resolved}) arity differs: "
                f"python={py_value} wasm={wasm_value}"
            )


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
