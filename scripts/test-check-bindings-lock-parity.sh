#!/usr/bin/env bash
# Self-tests for scripts/check-bindings-lock-parity.sh (issue #340).
#
# Usage: scripts/test-check-bindings-lock-parity.sh
#
# Runs the guard against the real tree (must pass) and against scratch copies
# of the root and binding lockfiles and the guard list that each inject one
# violation. The real lockfiles are never modified. Needs only POSIX tools.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
guard="$script_dir/check-bindings-lock-parity.sh"

[ $# -eq 0 ] || { echo "usage: scripts/test-check-bindings-lock-parity.sh" >&2; exit 2; }

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
    cp "$repo_root/Cargo.lock" "$d/root.lock"
    for b in py node wasm; do
        cp "$repo_root/bindings/acdp-$b/Cargo.lock" "$d/$b.lock"
    done
    cp "$script_dir/crypto-critical.txt" "$d/list.txt"
    printf '%s' "$d"
}

run_guard() {
    local d=$1
    set +e
    "$guard" --root "$d/root.lock" --list "$d/list.txt" "$d/py.lock" "$d/node.lock" "$d/wasm.lock" >"$d/out" 2>&1
    rc=$?
    set -e
}

# expect <case-dir> <rc> [<substring>...]: exit status and every substring.
expect() {
    local d=$1 want=$2 needle
    shift 2
    run_guard "$d"
    local good=1
    [ "$rc" -eq "$want" ] || good=0
    for needle in "$@"; do grep -qF -- "$needle" "$d/out" || good=0; done
    if [ "$good" -eq 1 ]; then
        ok "$(basename "$d"): exits $want${*:+ ($*)}"
    else
        bad "$(basename "$d"): expected exit $want with '$*'; got rc=$rc:"
        sed 's/^/    /' "$d/out" >&2
    fi
}

# edit_pkg <lock> <crate> <field> <new-value>: rewrite <field> in every
# [[package]] block named <crate>.
edit_pkg() {
    local lock=$1 crate=$2 field=$3 value=$4
    awk -v c="$crate" -v f="$field" -v v="$value" '
        /^\[\[package\]\]/ { cur = "" }
        /^name = / { cur = $0; sub(/^name = "/, "", cur); sub(/".*$/, "", cur) }
        cur == c && index($0, f " = ") == 1 { print f " = \"" v "\""; next }
        { print }
    ' "$lock" >"$lock.new" && mv "$lock.new" "$lock"
}

# drop_pkg <lock> <crate>: remove every [[package]] block named <crate>.
drop_pkg() {
    local lock=$1 crate=$2
    awk -v c="$crate" '
        function flush() { if (buf != "" && !skip) printf "%s", buf; buf = ""; skip = 0 }
        /^\[\[package\]\]/ { flush() }
        { buf = buf $0 "\n" }
        $0 == "name = \"" c "\"" { skip = 1 }
        END { flush() }
    ' "$lock" >"$lock.new" && mv "$lock.new" "$lock"
}

# add_pkg <lock> <crate> <version> <checksum>: append a registry package.
add_pkg() {
    printf '\n[[package]]\nname = "%s"\nversion = "%s"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "%s"\n' \
        "$2" "$3" "$4" >>"$1"
}

fake_sum=0000000000000000000000000000000000000000000000000000000000000000

# 0. The real tree passes (no scratch copies, default paths).
set +e
"$guard" >"$tmp/real.out" 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ]; then ok "real tree: exits 0"; else bad "real tree: rc=$rc"; sed 's/^/    /' "$tmp/real.out" >&2; fi

# 0b. Unmodified scratch copies pass too (the harness itself is sound).
expect "$(new_case clean-copy)" 0 "all 11 crypto-critical crates"

# (a) sha2 bumped in the py lock (version and checksum): names crate and binding.
d=$(new_case a-sha2-bumped-py)
edit_pkg "$d/py.lock" sha2 version 0.11.99
edit_pkg "$d/py.lock" sha2 checksum "$fake_sum"
expect "$d" 1 "FAIL: sha2 0.11.99 in" "py.lock is not in"

# (b) a second ring version in the node lock.
d=$(new_case b-second-ring-node)
add_pkg "$d/node.lock" ring 0.16.20 "$fake_sum"
expect "$d" 1 "FAIL: ring 0.16.20 in" "node.lock is not in"

# (c) a listed crate absent from the wasm lock is fine.
d=$(new_case c-absent-in-wasm)
drop_pkg "$d/wasm.lock" sha2
if grep -qx 'name = "sha2"' "$d/wasm.lock"; then bad "c-absent-in-wasm: fixture still has sha2"; fi
expect "$d" 0

# (d) same version, different checksum.
d=$(new_case d-checksum-changed)
edit_pkg "$d/wasm.lock" subtle checksum "$fake_sum"
expect "$d" 1 "FAIL: subtle 2.6.1 in" "has checksum $fake_sum, which differs"

# (e) a list typo (crate in no lockfile).
d=$(new_case e-list-typo)
printf 'sha-2\n' >>"$d/list.txt"
expect "$d" 1 "FAIL: sha-2: listed in list.txt but not a registry crate in"

# (e2) a listed crate present in a binding but absent from the root fails.
d=$(new_case e2-absent-from-root)
drop_pkg "$d/root.lock" subtle
expect "$d" 1 "FAIL: subtle: listed in list.txt but not a registry crate in"

# (f) malformed lockfiles: a package without version; no packages; empty;
#     missing; a registry package without checksum.
d=$(new_case f-malformed-no-version)
awk '/^name = "ring"$/ { print; getline; next } { print }' "$d/node.lock" >"$d/node.lock.new" && mv "$d/node.lock.new" "$d/node.lock"
expect "$d" 2 "malformed lockfile"

d=$(new_case f2-malformed-no-packages)
printf 'version = 4\n' >"$d/py.lock"
expect "$d" 2 "malformed lockfile"

d=$(new_case f3-empty-lock)
: >"$d/wasm.lock"
expect "$d" 2 "missing or empty"

d=$(new_case f4-missing-lock)
rm "$d/wasm.lock"
expect "$d" 2 "missing or empty"

d=$(new_case f5-malformed-no-checksum)
awk '!/^checksum = / || !prev_ring { print } { prev_ring = 0 } /^source = / && ring { prev_ring = 1 } /^name = / { ring = ($0 == "name = \"ring\"") }' \
    "$d/root.lock" >"$d/root.lock.new" && mv "$d/root.lock.new" "$d/root.lock"
expect "$d" 2 "malformed lockfile"

# (g) comment and marker lines in the list are parsed like check-crypto-vet.sh:
#     a marker containing `#` is not a comment; a trailing ` # x` is.
d=$(new_case g-list-comments)
printf '# a comment line naming no-such-crate\n   # indented comment\nsubtle   # trailing comment\nzeroize allow-exempt:#322-pending\n' >>"$d/list.txt"
expect "$d" 0 "all 11 crypto-critical crates"

# (h) a list with no crates.
d=$(new_case h-empty-list)
printf '# only comments\n' >"$d/list.txt"
expect "$d" 1 "names no crates"

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
