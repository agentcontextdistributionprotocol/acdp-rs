#!/usr/bin/env bash
# Self-tests for scripts/check-crypto-vet.sh (issue #322).
#
# Usage: scripts/test-check-crypto-vet.sh [--with-network]
#
# Runs the guard against the real tree (must pass) and against scratch copies
# of supply-chain/, the guard list, and DECISIONS.md that each inject one
# violation (must fail with exit 1, naming the crate). The real supply-chain/
# directory is never modified. --with-network also checks that
# scripts/vet-facts.sh rejects a corrupted crates.io tarball (downloads one
# crate). Requires cargo, cargo-vet, and jq (as the guard does).
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
guard="$script_dir/check-crypto-vet.sh"

with_network=0
case "${1:-}" in
    '') ;;
    --with-network) with_network=1 ;;
    *) echo "usage: scripts/test-check-crypto-vet.sh [--with-network]" >&2; exit 2 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0
failed=0
ok() { echo "PASS: $*"; passed=$((passed + 1)); }
bad() { echo "FAIL: $*" >&2; failed=$((failed + 1)); }

# Fresh scratch copies; prints the case directory.
new_case() {
    local d="$tmp/$1"
    mkdir -p "$d"
    cp -R "$repo_root/supply-chain" "$d/store"
    cp "$script_dir/crypto-critical.txt" "$d/list.txt"
    cp "$repo_root/DECISIONS.md" "$d/DECISIONS.md"
    printf '%s' "$d"
}

# Re-sort an edited scratch store, as cargo vet requires (`cargo vet fmt`).
fmt_store() {
    (cd "$repo_root" && cargo vet fmt --store-path "$1/store") >/dev/null
}

run_guard() {
    local d=$1
    fmt_store "$d"
    set +e
    "$guard" --store-path "$d/store" --list "$d/list.txt" --decisions "$d/DECISIONS.md" >"$d/out" 2>&1
    rc=$?
    set -e
}

# expect_fail <case> <crate> <expected-substring>
expect_fail() {
    local d=$1 crate=$2 needle=$3
    run_guard "$d"
    if [ "$rc" -eq 1 ] && grep -qF -- "FAIL: $crate" "$d/out" && grep -qF -- "$needle" "$d/out"; then
        ok "$(basename "$d"): guard exits 1 naming $crate ('$needle')"
    else
        bad "$(basename "$d"): expected exit 1 naming $crate with '$needle'; got rc=$rc:"
        sed 's/^/    /' "$d/out" >&2
    fi
}

expect_pass() {
    local d=$1
    run_guard "$d"
    if [ "$rc" -eq 0 ]; then
        ok "$(basename "$d"): guard exits 0"
    else
        bad "$(basename "$d"): expected exit 0; got rc=$rc:"
        sed 's/^/    /' "$d/out" >&2
    fi
}

# Replace the marker on <crate>'s line of a guard list.
set_marker() {
    local file=$1 crate=$2 marker=$3
    awk -v c="$crate" -v m="$marker" '$1 == c { print c (m == "" ? "" : " " m); next } { print }' \
        "$file" >"$file.new" && mv "$file.new" "$file"
}

# Remove every line mentioning <anchor> from a scratch DECISIONS.md, so a case
# can model "the anchor is absent" even when the real file records it.
drop_anchor() {
    local file=$1 anchor=$2
    grep -vF -- "$anchor" "$file" >"$file.new" || true
    mv "$file.new" "$file"
}

# 0. The real tree passes (no scratch copies at all).
set +e
"$guard" >"$tmp/real.out" 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ]; then ok "real tree: guard exits 0"; else bad "real tree: rc=$rc"; sed 's/^/    /' "$tmp/real.out" >&2; fi

# 0b. Unmodified scratch copies pass too (the harness itself is sound).
expect_pass "$(new_case clean-copy)"

# (a) subtle loses its audit and gains an exemption: cargo vet stays green,
#     the guard does not.
d=$(new_case a-subtle-exempted)
awk '
    /^\[\[audits\.subtle\]\]$/ { skip = 1; next }
    skip && /^\[/ { skip = 0 }
    !skip { print }
' "$d/store/audits.toml" >"$d/store/audits.toml.new" && mv "$d/store/audits.toml.new" "$d/store/audits.toml"
printf '\n[[exemptions.subtle]]\nversion = "2.6.1"\ncriteria = "safe-to-deploy"\n' >>"$d/store/config.toml"
fmt_store "$d"
if (cd "$repo_root" && cargo vet --locked --store-path "$d/store") >"$d/vet.out" 2>&1; then
    ok "a-subtle-exempted: cargo vet --locked stays green (the gap the guard closes)"
else
    bad "a-subtle-exempted: cargo vet --locked unexpectedly failed:"
    sed 's/^/    /' "$d/vet.out" >&2
fi
expect_fail "$d" subtle "not fully audited"

# (a2) an exempted crate's marker is dropped while it is still exempted.
d=$(new_case a2-unmarked-exempted)
set_marker "$d/list.txt" sha2 ""
expect_fail "$d" sha2 "not fully audited"

# (b) sha2 keeps its pending marker although it is now fully audited.
d=$(new_case b-stale-pending)
cat >>"$d/store/audits.toml" <<'EOF'

[[audits.sha2]]
who = "Guard Self-Test <test@example.invalid>"
criteria = "safe-to-deploy"
version = "0.11.0"
notes = "FAKE audit injected by scripts/test-check-crypto-vet.sh (scratch copy only)."
EOF
set_marker "$d/list.txt" sha2 "allow-exempt:#322-pending"
expect_fail "$d" sha2 "stale marker"

# (b2) the same stale check applies to a DECISIONS marker.
d=$(new_case b2-stale-decisions)
cat >>"$d/store/audits.toml" <<'EOF'

[[audits.sha2]]
who = "Guard Self-Test <test@example.invalid>"
criteria = "safe-to-deploy"
version = "0.11.0"
notes = "FAKE audit injected by scripts/test-check-crypto-vet.sh (scratch copy only)."
EOF
set_marker "$d/list.txt" sha2 "allow-exempt:DECISIONS#322-sha2"
printf '\nAnchor: 322-sha2\n' >>"$d/DECISIONS.md"
expect_fail "$d" sha2 "stale marker"

# (c) the plan's case: a DECISIONS marker naming a nonexistent anchor.
d=$(new_case c-nonexistent-anchor)
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#nonexistent"
expect_fail "$d" zeroize "must name anchor '322-zeroize' exactly"

# (c1) the anchor is the right shape but DECISIONS.md lacks it.
d=$(new_case c1-anchor-absent)
drop_anchor "$d/DECISIONS.md" "322-zeroize"
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-zeroize"
expect_fail "$d" zeroize "does not appear in"

# (c3) a prefix anchor (it would match as a substring) is rejected.
d=$(new_case c3-prefix-anchor)
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322"
expect_fail "$d" zeroize "must name anchor '322-zeroize' exactly"

# (c4) another crate's anchor is rejected even though DECISIONS.md has it.
d=$(new_case c4-other-crate-anchor)
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-sha2"
printf '\nAnchor: 322-sha2\n' >>"$d/DECISIONS.md"
expect_fail "$d" zeroize "must name anchor '322-zeroize' exactly"

# (c5) DECISIONS.md has only a longer token (322-zeroize-extra): no match.
d=$(new_case c5-longer-token-only)
drop_anchor "$d/DECISIONS.md" "322-zeroize"
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-zeroize"
printf '\nAnchor: 322-zeroize-extra\n' >>"$d/DECISIONS.md"
expect_fail "$d" zeroize "does not appear in"

# (c2) a DECISIONS marker whose anchor exists passes.
d=$(new_case c2-present-anchor)
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-zeroize"
printf '\nAnchor: 322-zeroize\n' >>"$d/DECISIONS.md"
expect_pass "$d"

# (d) an unknown marker.
d=$(new_case d-unknown-marker)
set_marker "$d/list.txt" p256 "allow-exempt:forever"
expect_fail "$d" p256 "unknown marker"

# (e) a listed crate that is not in Cargo.lock.
d=$(new_case e-not-locked)
printf 'no-such-crate-322\n' >>"$d/list.txt"
expect_fail "$d" no-such-crate-322 "not a registry crate in Cargo.lock"

# (f) a failing cargo vet is a guard failure.
d=$(new_case f-vet-fails)
awk '
    /^\[\[exemptions\.zeroize\]\]$/ { skip = 1; next }
    skip && /^\[/ { skip = 0 }
    !skip { print }
' "$d/store/config.toml" >"$d/store/config.toml.new" && mv "$d/store/config.toml.new" "$d/store/config.toml"
run_guard "$d"
if [ "$rc" -eq 1 ] && grep -qF "did not succeed" "$d/out"; then
    ok "f-vet-fails: guard exits 1 when cargo vet fails"
else
    bad "f-vet-fails: expected exit 1 ('did not succeed'); got rc=$rc"
    sed 's/^/    /' "$d/out" >&2
fi

if [ "$with_network" -eq 1 ]; then
    mkdir -p "$tmp/crates"
    curl -fsSL https://static.crates.io/crates/zeroize/zeroize-1.9.0.crate -o "$tmp/crates/zeroize-1.9.0.crate"
    printf 'x' >>"$tmp/crates/zeroize-1.9.0.crate"
    set +e
    VET_FACTS_CRATE_DIR="$tmp/crates" "$script_dir/vet-facts.sh" zeroize 1.9.0 >"$tmp/facts.out" 2>&1
    rc=$?
    set -e
    if [ "$rc" -ne 0 ] && grep -qF "checksum MISMATCH" "$tmp/facts.out"; then
        ok "vet-facts: corrupted tarball rejected (rc=$rc)"
    else
        bad "vet-facts: corrupted tarball not rejected (rc=$rc)"
        sed 's/^/    /' "$tmp/facts.out" >&2
    fi
fi

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
