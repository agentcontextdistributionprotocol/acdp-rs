#!/usr/bin/env bash
# Self-tests for scripts/check-crypto-vet.sh (issue #322).
#
# Usage: scripts/test-check-crypto-vet.sh [--with-network]
#
# Runs the guard against the real tree (must pass) and against scratch copies
# of supply-chain/, the guard list, and DECISIONS.md that each inject one
# violation (must fail with exit 1, naming the crate). The real supply-chain/
# directory is never modified. --with-network also checks that
# scripts/vet-facts.sh rejects a corrupted crates.io tarball and reports a
# brace import of std::fs (downloads two crates). Requires cargo, cargo-vet,
# and jq (as the guard does).
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

# Remove every [[audits.<crate>]] block from a scratch store.
strip_audits() {
    local d=$1 crate=$2
    awk -v hdr="[[audits.$crate]]" '
        $0 == hdr { skip = 1; next }
        skip && /^\[/ { skip = 0 }
        !skip { print }
    ' "$d/store/audits.toml" >"$d/store/audits.toml.new" && mv "$d/store/audits.toml.new" "$d/store/audits.toml"
}

# Turn zeroize back into an exempted crate in a scratch store: drop its audits
# and exempt the locked version. zeroize is the fixture for the DECISIONS
# marker cases because the real DECISIONS.md keeps the `322-zeroize` anchor
# (the crate itself is audited since 1.9.1, issue #341). The version is read
# from Cargo.lock so a zeroize bump does not break the fixtures.
zeroize_locked=$(awk '
    /^\[\[package\]\]/ { name = ""; next }
    /^name = / { name = $3; gsub(/"/, "", name); next }
    /^version = / && name == "zeroize" { v = $3; gsub(/"/, "", v); print v; exit }
' "$repo_root/Cargo.lock")
[ -n "$zeroize_locked" ] || { echo "test-check-crypto-vet: zeroize not in Cargo.lock" >&2; exit 1; }
exempt_zeroize() {
    local d=$1
    strip_audits "$d" zeroize
    printf '\n[[exemptions.zeroize]]\nversion = "%s"\ncriteria = "safe-to-deploy"\n' "$zeroize_locked" >>"$d/store/config.toml"
}

# (a2) an exempted crate without a marker fails.
d=$(new_case a2-unmarked-exempted)
exempt_zeroize "$d"
expect_fail "$d" zeroize "not fully audited"

# (b) the retired `#322-pending` marker is rejected: it carried no DECISIONS
#     anchor and no @version pin, so it could pass an exemption at any version.
d=$(new_case b-retired-pending)
exempt_zeroize "$d"
set_marker "$d/list.txt" zeroize "allow-exempt:#322-pending"
expect_fail "$d" zeroize "unknown marker"

# (b2) a DECISIONS marker left on a fully audited crate is stale (the real
#      store audits zeroize 1.9.1).
d=$(new_case b2-stale-decisions)
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-zeroize@$zeroize_locked"
expect_fail "$d" zeroize "stale marker"

# (c) the plan's case: a DECISIONS marker naming a nonexistent anchor.
d=$(new_case c-nonexistent-anchor)
exempt_zeroize "$d"
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#nonexistent@$zeroize_locked"
expect_fail "$d" zeroize "must name anchor '322-zeroize' exactly"

# (c1) the anchor is the right shape but DECISIONS.md lacks it.
d=$(new_case c1-anchor-absent)
exempt_zeroize "$d"
drop_anchor "$d/DECISIONS.md" "322-zeroize"
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-zeroize@$zeroize_locked"
expect_fail "$d" zeroize "does not appear in"

# (c3) a prefix anchor (it would match as a substring) is rejected.
d=$(new_case c3-prefix-anchor)
exempt_zeroize "$d"
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322@$zeroize_locked"
expect_fail "$d" zeroize "must name anchor '322-zeroize' exactly"

# (c4) another crate's anchor is rejected even though DECISIONS.md has it.
d=$(new_case c4-other-crate-anchor)
exempt_zeroize "$d"
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-sha2@$zeroize_locked"
printf '\nAnchor: 322-sha2\n' >>"$d/DECISIONS.md"
expect_fail "$d" zeroize "must name anchor '322-zeroize' exactly"

# (c5) DECISIONS.md has only a longer token (322-zeroize-extra): no match.
d=$(new_case c5-longer-token-only)
exempt_zeroize "$d"
drop_anchor "$d/DECISIONS.md" "322-zeroize"
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-zeroize@$zeroize_locked"
printf '\nAnchor: 322-zeroize-extra\n' >>"$d/DECISIONS.md"
expect_fail "$d" zeroize "does not appear in"

# (c2) a DECISIONS marker whose anchor exists passes.
d=$(new_case c2-present-anchor)
exempt_zeroize "$d"
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-zeroize@$zeroize_locked"
printf '\nAnchor: 322-zeroize\n' >>"$d/DECISIONS.md"
expect_pass "$d"

# (g) a DECISIONS marker without @<version> is rejected.
d=$(new_case g-missing-version)
exempt_zeroize "$d"
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-zeroize"
expect_fail "$d" zeroize "must pin the exempted version"

# (g2) the pinned version differs from the locked (exempted) version, as after
#      a bump whose exemption was moved instead of audited.
d=$(new_case g2-locked-version-mismatch)
exempt_zeroize "$d"
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-zeroize@0.0.1"
expect_fail "$d" zeroize "re-audit zeroize $zeroize_locked, or update the DECISIONS.md '322-zeroize' entry"

# (g3) config.toml exempts a version other than the pinned one.
d=$(new_case g3-exempted-version-mismatch)
exempt_zeroize "$d"
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-zeroize@$zeroize_locked"
printf '\n[[exemptions.zeroize]]\nversion = "0.0.1"\ncriteria = "safe-to-deploy"\n' >>"$d/store/config.toml"
expect_fail "$d" zeroize "config.toml exempts version 0.0.1"

# (g4) a matching pinned version passes.
d=$(new_case g4-version-match)
exempt_zeroize "$d"
set_marker "$d/list.txt" zeroize "allow-exempt:DECISIONS#322-zeroize@$zeroize_locked"
expect_pass "$d"

# (d) an unknown marker.
d=$(new_case d-unknown-marker)
set_marker "$d/list.txt" p256 "allow-exempt:forever"
expect_fail "$d" p256 "unknown marker"

# (e) a listed crate that is not in Cargo.lock.
d=$(new_case e-not-locked)
printf 'no-such-crate-322\n' >>"$d/list.txt"
expect_fail "$d" no-such-crate-322 "not a registry crate in Cargo.lock"

# (f) a failing cargo vet is a guard failure (zeroize loses its audits and
#     has no exemption).
d=$(new_case f-vet-fails)
strip_audits "$d" zeroize
run_guard "$d"
if [ "$rc" -eq 1 ] && grep -qF "did not succeed" "$d/out"; then
    ok "f-vet-fails: guard exits 1 when cargo vet fails"
else
    bad "f-vet-fails: expected exit 1 ('did not succeed'); got rc=$rc"
    sed 's/^/    /' "$d/out" >&2
fi

if [ "$with_network" -eq 1 ]; then
    mkdir -p "$tmp/crates"
    curl -fsSL https://static.crates.io/crates/zeroize/zeroize-$zeroize_locked.crate -o "$tmp/crates/zeroize-$zeroize_locked.crate"
    printf 'x' >>"$tmp/crates/zeroize-$zeroize_locked.crate"
    set +e
    VET_FACTS_CRATE_DIR="$tmp/crates" "$script_dir/vet-facts.sh" zeroize "$zeroize_locked" >"$tmp/facts.out" 2>&1
    rc=$?
    set -e
    if [ "$rc" -ne 0 ] && grep -qF "checksum MISMATCH" "$tmp/facts.out"; then
        ok "vet-facts: corrupted tarball rejected (rc=$rc)"
    else
        bad "vet-facts: corrupted tarball not rejected (rc=$rc)"
        sed 's/^/    /' "$tmp/facts.out" >&2
    fi
    # The brace import `use std::{fs, path::Path}` (der 0.8.1 src/document.rs:11)
    # must be reported as a powerful import.
    set +e
    "$script_dir/vet-facts.sh" der 0.8.1 >"$tmp/facts-der.out" 2>&1
    rc=$?
    set -e
    if [ "$rc" -eq 0 ] && grep -qE '^  src/document\.rs:11:use std::\{fs, path::Path\};' "$tmp/facts-der.out"; then
        ok "vet-facts: brace import std::{fs, ...} reported (der 0.8.1)"
    else
        bad "vet-facts: brace import std::{fs, ...} not reported for der 0.8.1 (rc=$rc)"
        sed 's/^/    /' "$tmp/facts-der.out" >&2
    fi
fi

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
