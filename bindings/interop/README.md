# acdp — cross-language interop tests

Proves the Python and Node.js SDKs emit byte-compatible ACDP wire
output by building the same `PublishRequest` from the same all-zero
Ed25519 seed on each side and asserting:

* `content_hash` is byte-identical across both bindings (this follows
  from JCS being deterministic and SHA-256 being a function).
* `signature.value` is byte-identical across both bindings (Ed25519
  with a fixed seed is also deterministic).
* The Python verifier accepts Node-produced signatures and vice versa.
* Each side matches the spec's `sig-001` golden constants the Rust
  suite asserts (`f170150d…` / `ErkbV+FU…`).

The Python side runs in-process via the `acdp` extension built by
`maturin develop`. The Node side runs in a `node` subprocess driven
over line-delimited JSON-RPC (`node_worker.mjs`), which keeps a single
process alive across all tests so we don't pay subprocess startup per
RPC. Every wire message that crosses the language boundary is plain
JSON.

## Run

Build both bindings first (the Node side's `package-lock.json` is
committed, so its `npm install` resolves the pinned dependency graph
rather than fresh):

```bash
(cd ../acdp-py   && maturin develop)
(cd ../acdp-node && npm install && npm run build:debug)
pytest
```

Or from the repo root: `make interop` (builds both bindings, then runs
pytest).

## Why this exists

The acdp protocol is content-addressable: every consumer recomputes
`sha256(JCS(producer_content))` and refuses bodies whose hash doesn't
match. If the Python and Node bindings disagree on JCS canonicalization
— even in something as small as how an unset optional field is
serialized — they emit different `content_hash` values and registries
reject one of the two. These tests pin that invariant in CI.

## Drift guard (`test_parity.py`)

Behavioral interop only catches divergence in code paths a test happens to
exercise. `test_parity.py` adds structural guards so the two SDKs can
never silently drift:

* **API-surface parity** — `expected_surface.json` is the single source of
  truth for the public surface. The test asserts the Python binding, the
  Node binding (introspected over the worker's `describe` RPC), and the
  manifest all expose the same classes and methods (names normalized to
  snake_case, so Node's camelCase compares equal). Add a method to one
  binding without the other — or without updating the manifest — and the
  test fails.
* **Behavioral parity for the sync primitives** — `AcdpCanonicalizer`
  (`canonicalize` / `content_hash`) and `AcdpSsrfPolicy` (the stable
  reason taxonomy: Python's `SsrfRejected.reason` vs Node's `Error.code`)
  are cross-checked across both bindings in `test_interop.py`.
* **wasm surface parity** — `bindings/acdp-wasm` is a flat
  `#[wasm_bindgen]` function surface (25 free functions, no classes), not
  a class surface like py/node, so it gets its own `wasm` block in
  `expected_surface.json` rather than an entry under `classes`. That block
  pins the full export list (`functions`) and classifies every py/node
  class against it (`class_map`): a class with no wasm counterpart at all
  maps to `"absent"`; a present class's methods default to the identical
  snake_case name, with `aliases` naming the exceptions (a wasm function
  name, or `null` for a method with no wasm counterpart); `wasm_only`
  lists wasm exports with no class counterpart (e.g. `resolve_did_key`).
  Some aliases exist because wasm shipped a different name for the same
  operation before this guard existed (e.g. `verify_signature` →
  `verify_signature_ed25519`, `AcdpMerkle.leaf_hash` → `merkle_leaf_hash`)
  — **renaming a shipped npm export is a breaking change**, so those
  divergences are pinned as permanent aliases here, never "fixed" by
  renaming one side to match the other. Four invariants are enforced (one
  test function each, in `test_parity.py`): the reflected wasm surface
  equals `wasm.functions`; every class method resolves (via alias or
  identity) to a real wasm function; `wasm.functions` equals exactly the
  union of every resolved class method and `wasm_only` (so a new wasm
  export can never go unclassified); and the manifest's own internal
  structure is consistent (alias keys/values and `wasm_only` entries all
  point somewhere real). The wasm pkg is a gitignored build artifact
  (`bindings/acdp-wasm/pkg/`, built via `make sdk-wasm` or `wasm-pack
  build --target web --out-dir pkg`) most machines won't have, so these
  tests `pytest.skip` with a message pointing at `make sdk-wasm` when it's
  absent — unless `ACDP_REQUIRE_WASM_PARITY=1` (set in CI), which turns
  the skip into a hard failure. `make interop` does NOT require wasm-pack.
* **Arity parity** (closes #242) — name-only parity above can't catch a
  field silently added to one binding's options object and not the
  other, so `expected_surface.json` also carries an `arity` block: for
  every one of the 61 `classes` entries, `[required, total]` parameter
  counts (a property getter is recorded as the literal string
  `"property"`, never `[0, 0]`). Sources, one per binding — and never
  `Function.length`, which reports `0` for every native (napi-rs)
  method measured against this repo's own build, no JS-level signal at
  all:
  * **Python** — `inspect.signature`, excluding `self`/`cls` and any
    `*args`/`**kwargs` (none occur in this SDK).
  * **Node** — `bindings/acdp-node/index.d.ts`, parsed directly (no
    subprocess needed).
  * **wasm** — `bindings/acdp-wasm/pkg/acdp_wasm.d.ts`, parsed the same
    way, anchored on `^export function` — never the bare export name,
    which the file's `InitOutput` interface re-declares at its raw
    wasm-ABI arity (13 params for a method whose real signature takes
    6).

  Both `.d.ts` parsers apply one normalization rule: expand a parameter
  whose declared type names an `export interface` in the same file into
  that interface's own fields. This is what lets the 4 "wide" methods
  (`{AcdpProducer,AcdpP256Producer}.build_{publish,supersede}_request`,
  a single camelCase options object on the Node side) compare against
  Python's ~15-19 real keyword parameters. Required-ness keys off the
  trailing `?` on a field/param, **never** off a `| null` union — a
  non-trailing `Option<T>` is declared `name: T | null | undefined`
  (no `?`) in both `.d.ts` files and is REQUIRED despite the null.
  Five invariants (`test_parity.py`, functions named for their
  A1-A5 role): Python-vs-manifest, Node-vs-manifest, wasm-vs-manifest
  (class-mapped entries only), the manifest's own internal structural
  hygiene (read with no binding built at all), and a cross-binding
  check independent of the manifest. The wasm invariants use the same
  skip-vs-fail gating as the wasm surface-parity checks above.
* **Version parity** — `pyproject.toml`, both `Cargo.toml`s,
  `acdp-wasm/Cargo.toml`, and `package.json` must all carry the same
  version.

When you intentionally change the public API, update
`expected_surface.json` (and both bindings) in the same change. The guard
runs as part of `make interop` and the `bindings` CI workflow, so drift
fails the build locally and in CI.
