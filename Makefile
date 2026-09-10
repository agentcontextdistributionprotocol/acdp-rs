# acdp-rs — convenience targets for the Rust library and its language
# bindings. The bindings are standalone Cargo packages with their own
# [workspace] tables, so each is built and tested in its own directory.
# The root crate is single-package and untouched by these targets.

PY_DIR    := bindings/acdp-py
NODE_DIR  := bindings/acdp-node
WASM_DIR  := bindings/acdp-wasm
INTEROP   := bindings/interop

.PHONY: help test sdk-py sdk-node sdk-wasm interop sdk-all clean-bindings ci-bindings audit-bindings

help:
	@echo "Targets:"
	@echo "  test          - cargo test --all-features on the root crate"
	@echo "  sdk-py        - maturin develop + pytest in $(PY_DIR)"
	@echo "  sdk-node      - npm install + napi build:debug + node --test in $(NODE_DIR)"
	@echo "  sdk-wasm      - wasm-pack build --target web --out-dir pkg in $(WASM_DIR)"
	@echo "                  (optional: enables the wasm parity checks in \`make interop\`;"
	@echo "                  not required for interop/CI otherwise)"
	@echo "  sdk-all       - build both SDKs (no tests)"
	@echo "  interop       - sdk-py + sdk-node + pytest $(INTEROP)"
	@echo "  audit-bindings - cargo-deny advisories ($(PY_DIR), $(NODE_DIR), $(WASM_DIR)) + npm audit"
	@echo "  ci-bindings   - what bindings.yml runs locally"
	@echo "  clean-bindings - rm bindings/**/target node_modules and built artifacts"

test:
	cargo test --all-features

# ── Python SDK ──────────────────────────────────────────────────────────
# maturin must be installed (pip install maturin or pipx install maturin).
# `develop` installs an editable extension into the active venv.
sdk-py:
	cd $(PY_DIR) && maturin develop
	cd $(PY_DIR) && pytest tests/

# ── Node.js SDK ─────────────────────────────────────────────────────────
# `npm install` brings in @napi-rs/cli; `build:debug` is the fast path.
# Use the explicit `tests/*.mjs` glob: Node 22+ treats a bare directory
# argument to `--test` as a module path and fails with MODULE_NOT_FOUND,
# instead of recursing into the directory for test files.
sdk-node:
	cd $(NODE_DIR) && npm install
	cd $(NODE_DIR) && npm run build:debug
	cd $(NODE_DIR) && node --test tests/*.mjs

# ── wasm SDK (optional convenience) ─────────────────────────────────────
# Not part of `make interop` or CI's default path: bindings/acdp-wasm/pkg
# is gitignored and most contributor machines won't have wasm-pack. Build
# it here to turn the pytest-skipped wasm parity checks in
# bindings/interop/test_parity.py on locally.
sdk-wasm:
	cd $(WASM_DIR) && wasm-pack build --target web --out-dir pkg

sdk-all: sdk-py-build sdk-node-build

sdk-py-build:
	cd $(PY_DIR) && maturin develop

sdk-node-build:
	cd $(NODE_DIR) && npm install && npm run build:debug

# ── Interop ─────────────────────────────────────────────────────────────
# Builds both bindings first, then runs the cross-language pytest suite.
# Runs the whole interop dir: cross-language behavioral parity
# (test_interop.py) AND the API-surface / version drift guards
# (test_parity.py). A new parity test file is picked up automatically.
interop: sdk-py-build sdk-node-build
	cd $(INTEROP) && pytest

# ── Supply-chain scanning ───────────────────────────────────────────────
# Mirrors bindings.yml's bindings-deny + bindings-npm-audit jobs.
audit-bindings:
	cargo deny --manifest-path $(PY_DIR)/Cargo.toml check --config deny.toml advisories
	cargo deny --manifest-path $(NODE_DIR)/Cargo.toml check --config deny.toml advisories
	cargo deny --manifest-path $(WASM_DIR)/Cargo.toml check --config deny.toml advisories
	cd $(NODE_DIR) && npm install && npm audit

# What the CI workflow runs locally. Useful before pushing.
ci-bindings: test sdk-py sdk-node interop audit-bindings

# ── Cleanup ─────────────────────────────────────────────────────────────
clean-bindings:
	rm -rf $(PY_DIR)/target $(NODE_DIR)/target $(NODE_DIR)/node_modules
	rm -f  $(NODE_DIR)/index.js $(NODE_DIR)/index.d.ts $(NODE_DIR)/acdp.*.node
