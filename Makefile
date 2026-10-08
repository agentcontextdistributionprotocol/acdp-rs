# acdp-rs — convenience targets for the Rust workspace and its language
# bindings. The bindings are standalone Cargo packages with their own
# [workspace] tables (excluded from the root workspace), so each is built
# and tested in its own directory; only `test` touches the root workspace.

PY_DIR    := bindings/acdp-py
NODE_DIR  := bindings/acdp-node
WASM_DIR  := bindings/acdp-wasm
INTEROP   := bindings/interop

.PHONY: help test sdk-py sdk-node sdk-wasm interop sdk-all clean-bindings ci-bindings audit-bindings

help:
	@echo "Targets:"
	@echo "  test          - cargo test --workspace --all-features (root workspace)"
	@echo "  sdk-py        - maturin develop + pytest in $(PY_DIR)"
	@echo "  sdk-node      - npm ci (installs the committed package-lock.json exactly) +"
	@echo "                  napi build:debug + node --test in $(NODE_DIR)"
	@echo "  sdk-wasm      - wasm-pack build --target web --out-dir pkg in $(WASM_DIR)"
	@echo "                  (optional locally: enables the wasm parity checks in"
	@echo "                  \`make interop\`; CI's interop job always builds it)"
	@echo "  sdk-all       - build both SDKs (no tests)"
	@echo "  interop       - sdk-py + sdk-node + pytest $(INTEROP)"
	@echo "  audit-bindings - cargo-deny advisories for all three bindings + npm audit ($(NODE_DIR) only)"
	@echo "  ci-bindings   - a local subset of bindings.yml (see docs/bindings.md#build-details)"
	@echo "  clean-bindings - rm bindings/*/target, node_modules, wasm pkg and built artifacts"

test:
	cargo test --workspace --all-features

# ── Python SDK ──────────────────────────────────────────────────────────
# maturin must be installed (pip install maturin or pipx install maturin).
# `develop` installs an editable extension into the active venv.
sdk-py:
	cd $(PY_DIR) && maturin develop
	cd $(PY_DIR) && pytest tests/

# ── Node.js SDK ─────────────────────────────────────────────────────────
# `npm ci` brings in @napi-rs/cli from the committed package-lock.json
# exactly (including the exact @napi-rs/cli pin) and fails on
# manifest/lock drift, matching bindings.yml; `build:debug` is the fast path.
# Use the explicit `tests/*.mjs` glob: Node 22+ treats a bare directory
# argument to `--test` as a module path and fails with MODULE_NOT_FOUND,
# instead of recursing into the directory for test files.
sdk-node:
	cd $(NODE_DIR) && npm ci
	cd $(NODE_DIR) && npm run build:debug
	cd $(NODE_DIR) && node --test tests/*.mjs

# ── wasm SDK (optional convenience) ─────────────────────────────────────
# Not a prerequisite of `make interop`: bindings/acdp-wasm/pkg is gitignored
# and most contributor machines won't have wasm-pack, so the wasm parity
# checks in bindings/interop/test_parity.py skip without it. Build it here
# to turn them on locally. (CI's interop job does build it and sets
# ACDP_REQUIRE_WASM_PARITY=1, so a missing pkg fails there.)
sdk-wasm:
	cd $(WASM_DIR) && wasm-pack build --target web --out-dir pkg

sdk-all: sdk-py-build sdk-node-build

sdk-py-build:
	cd $(PY_DIR) && maturin develop

sdk-node-build:
	cd $(NODE_DIR) && npm ci && npm run build:debug

# ── Interop ─────────────────────────────────────────────────────────────
# Builds both bindings first, then runs the cross-language pytest suite.
# Runs the whole interop dir: cross-language behavioral parity
# (test_interop.py) AND the API-surface / version drift guards
# (test_parity.py). A new parity test file is picked up automatically.
interop: sdk-py-build sdk-node-build
	cd $(INTEROP) && pytest

# ── Supply-chain scanning ───────────────────────────────────────────────
# Mirrors bindings.yml's bindings-deny + bindings-npm-audit jobs: cargo-deny
# advisories cover all three bindings; npm audit covers acdp-node only
# (the only binding with an npm dependency graph).
audit-bindings:
	cargo deny --manifest-path $(PY_DIR)/Cargo.toml check --config deny.toml advisories
	cargo deny --manifest-path $(NODE_DIR)/Cargo.toml check --config deny.toml advisories
	cargo deny --manifest-path $(WASM_DIR)/Cargo.toml check --config deny.toml advisories
	cd $(NODE_DIR) && npm ci && npm audit

# A local subset of bindings.yml, useful before pushing. Not covered here:
# bindings-fmt, the acdp-wasm job, the v030/v040 copy-parity guard, and
# the python/node version matrices (see docs/bindings.md#build-details).
ci-bindings: test sdk-py sdk-node interop audit-bindings

# ── Cleanup ─────────────────────────────────────────────────────────────
clean-bindings:
	rm -rf $(PY_DIR)/target $(NODE_DIR)/target $(NODE_DIR)/node_modules
	rm -rf $(WASM_DIR)/target $(WASM_DIR)/pkg
	rm -f  $(NODE_DIR)/index.js $(NODE_DIR)/index.d.ts $(NODE_DIR)/acdp.*.node
