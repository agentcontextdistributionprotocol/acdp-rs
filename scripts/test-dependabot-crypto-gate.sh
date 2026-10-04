#!/usr/bin/env bash
# Self-tests for scripts/dependabot-crypto-gate.sh (issue #344).
#
# Usage: scripts/test-dependabot-crypto-gate.sh
#
# Builds a scratch git repository whose base commit holds copies of the real
# four lockfiles, the real guard list, and the gate script, then commits one
# change per case and checks the gate's exit status (0 untouched, 1 touched,
# 2 error) and the crate it names. Every case runs once per awk found on PATH
# (awk, gawk, mawk, original-awk, nawk, busybox awk), so BSD and GNU awk are
# both covered where installed. Also runs the gate against the real tree
# (HEAD vs HEAD, must exit 0). The real tree is never modified. Needs git.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
gate="$script_dir/dependabot-crypto-gate.sh"
lockfiles="Cargo.lock bindings/acdp-py/Cargo.lock bindings/acdp-node/Cargo.lock bindings/acdp-wasm/Cargo.lock"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0
failed=0
ok() { echo "PASS: $*"; passed=$((passed + 1)); }
bad() { echo "FAIL: $*" >&2; failed=$((failed + 1)); }

repo="$tmp/repo"
g() {
    git -C "$repo" -c user.name="Gate Self-Test" -c user.email=test@example.invalid \
        -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"
}

mkdir -p "$repo"
g init -q
for f in $lockfiles; do
    mkdir -p "$repo/$(dirname "$f")"
    cp "$repo_root/$f" "$repo/$f"
done
mkdir -p "$repo/scripts" "$repo/.github/workflows"
cp "$script_dir/crypto-critical.txt" "$repo/scripts/crypto-critical.txt"
cp "$gate" "$repo/scripts/dependabot-crypto-gate.sh"
printf 'name: ci\n' >"$repo/.github/workflows/ci.yml"
g add -A
g commit -q -m base
base=$(g rev-parse HEAD)
list="$tmp/list.txt"
cp "$script_dir/crypto-critical.txt" "$list"

# Start a case from <rev> (default: base); edits then go into the work tree.
start() {
    g checkout -q --detach "${1:-$base}"
    g reset -q --hard
}
# Commit the work tree; prints the new commit.
commit() {
    g add -A
    g commit -q --allow-empty -m "$1"
    g rev-parse HEAD
}

# set_field <lockfile> <crate> <version> <field> <new value>: rewrite one field
# of the [[package]] block <crate> <version>.
set_field() {
    local file="$repo/$1"
    # Buffer each block; rewrite the field once the block's identity is known.
    awk -v c="$2" -v v="$3" -v k="$4" -v nv="$5" '
        function out(   i) {
            for (i = 1; i <= nb; i++) {
                if (name == c && ver == v && index(buf[i], k " = ") == 1) { print k " = \"" nv "\""; hit++ }
                else print buf[i]
            }
            nb = 0; name = ""; ver = ""
        }
        /^\[/ { out() }
        /^name = "/ { name = $0; sub(/^name = "/, "", name); sub(/"$/, "", name) }
        /^version = "/ { ver = $0; sub(/^version = "/, "", ver); sub(/"$/, "", ver) }
        { buf[++nb] = $0 }
        END {
            out()
            if (!hit) { print "set_field: no " c " " v " " k > "/dev/stderr"; exit 1 }
        }
    ' "$file" >"$file.new" && mv "$file.new" "$file"
}

# drop_block <lockfile> <crate>: remove every [[package]] block of <crate>.
drop_block() {
    local file="$repo/$1"
    awk -v c="$2" '
        function out() { if (buf != "" && !drop) printf "%s", buf; buf = ""; drop = 0 }
        /^\[/ { out() }
        $0 == "name = \"" c "\"" { drop = 1 }
        { buf = buf $0 "\n" }
        END { out() }
    ' "$file" >"$file.new" && mv "$file.new" "$file"
}

# Version of <crate> in a lockfile (first block).
locked_version() {
    awk -v c="$2" '
        $0 == "name = \"" c "\"" { want = 1; next }
        want && /^version = / { v = $0; sub(/^version = "/, "", v); sub(/"$/, "", v); print v; exit }
    ' "$repo/$1"
}

# expect <name> <rc> <base> <head> [<needle>] [<list>]
awk_impl="awk"
expect() {
    local name=$1 want=$2 b=$3 h=$4 needle=${5:-} l=${6:-$list} rc=0
    AWK=$awk_impl "$gate" --repo "$repo" --base "$b" --head "$h" --list "$l" >"$tmp/out" 2>&1 || rc=$?
    if [ "$rc" -eq "$want" ] && { [ -z "$needle" ] || grep -qF -- "$needle" "$tmp/out"; }; then
        ok "[$awk_impl] $name: exit $rc${needle:+ ('$needle')}"
    else
        bad "[$awk_impl] $name: expected exit $want${needle:+ with '$needle'}; got rc=$rc:"
        sed 's/^/    /' "$tmp/out" >&2
    fi
}

# Build every case commit once (the awk used for editing is irrelevant).
subtle_v=$(locked_version Cargo.lock subtle)
sha2_v=$(locked_version Cargo.lock sha2)
ring_v=$(locked_version Cargo.lock ring)
anyhow_v=$(locked_version Cargo.lock anyhow)
node_sha2_v=$(locked_version bindings/acdp-node/Cargo.lock sha2)
for v in subtle_v sha2_v ring_v anyhow_v node_sha2_v; do
    [ -n "${!v}" ] || { echo "test setup: $v not found in the lockfiles" >&2; exit 2; }
done

start; c_none=$(commit "no change")
start; set_field Cargo.lock anyhow "$anyhow_v" version 99.0.0; c_noncrypto=$(commit "anyhow bump")
start; set_field Cargo.lock subtle "$subtle_v" version 99.0.0; c_subtle=$(commit "subtle bump")
start
printf '\n[[package]]\nname = "ring"\nversion = "0.16.20"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "3053cf52e236a3ed746dfc745aa9cacf1b791d846bdaf412f60a8d7d6e17c8fc"\n' >>"$repo/Cargo.lock"
c_ring2=$(commit "second ring")
start; drop_block Cargo.lock subtle; c_removed=$(commit "subtle removed")
start; set_field Cargo.lock sha2 "$sha2_v" checksum 0000000000000000000000000000000000000000000000000000000000000000
c_checksum=$(commit "sha2 checksum only")
start; set_field Cargo.lock ring "$ring_v" source "git+https://example.invalid/ring?rev=0#0"; c_source=$(commit "ring source")
start; set_field bindings/acdp-node/Cargo.lock sha2 "$node_sha2_v" version 99.0.0; c_binding=$(commit "binding-only sha2")
start; printf 'name: ci\n# bumped action\n' >"$repo/.github/workflows/ci.yml"; c_actions=$(commit "actions only")
start
printf '\n[[package]]\nname = "subtle-encoding"\nversion = "0.5.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "dcb1ed7b8330c5eed5441052651dd7a12c75e2ed88f2ec024ae1fa3a5e59945c"\n' >>"$repo/Cargo.lock"
c_prefix=$(commit "subtle-encoding added (name prefix of a listed crate)")
start; printf '# list edit\n' >>"$repo/scripts/crypto-critical.txt"; c_list_edit=$(commit "guard list edited")
start; printf '# gate edit\n' >>"$repo/scripts/dependabot-crypto-gate.sh"; c_gate_edit=$(commit "gate edited")
start; : >"$repo/Cargo.lock"; c_empty=$(commit "empty root lock")
start; printf 'not a lockfile\n' >"$repo/bindings/acdp-py/Cargo.lock"; c_garbage=$(commit "garbage py lock")
start; printf 'version = 4\n\n[[package]]\nname = "subtle"\nsource = "registry+x"\n' >"$repo/bindings/acdp-wasm/Cargo.lock"
c_noversion=$(commit "package without version")
start; set_field Cargo.lock subtle "$subtle_v" version '1"|2'; c_badstr=$(commit "bad string")
start; g rm -q bindings/acdp-wasm/Cargo.lock; c_missing_head=$(commit "wasm lock removed")
# Missing on the base side: base' lacks the file, head re-adds it.
c_missing_base=$c_missing_head
start "$c_missing_base"; mkdir -p "$repo/bindings/acdp-wasm"; cp "$repo_root/bindings/acdp-wasm/Cargo.lock" "$repo/bindings/acdp-wasm/Cargo.lock"
c_readded=$(commit "wasm lock re-added")
# A PR branch behind its base: base moved (subtle bumped on main) after the
# PR forked; the PR itself only bumps anyhow. Diffing from the merge base
# keeps that clean (0) instead of reporting main's change as the PR's.
c_main_ahead=$c_subtle

# Guard lists exercising the comment / marker parsing.
printf '# comment\n   # indented comment\n\nsubtle   allow-exempt:DECISIONS#322-subtle@1.0.0  # trailing comment\r\n#ring\n\t# tab comment\n' >"$tmp/list-markers.txt"
printf '# only comments\n\n   # nothing else\n' >"$tmp/list-empty.txt"
printf 'subtle\nsub#tle\n' >"$tmp/list-badname.txt"

awks=""
for a in awk gawk mawk original-awk nawk; do
    command -v "$a" >/dev/null 2>&1 && awks="$awks $a"
done
if command -v busybox >/dev/null 2>&1 && busybox awk 'BEGIN { exit 0 }' 2>/dev/null; then
    printf '#!/bin/sh\nexec busybox awk "$@"\n' >"$tmp/busybox-awk"
    chmod +x "$tmp/busybox-awk"
    awks="$awks $tmp/busybox-awk"
fi
echo "awk implementations under test:$awks"

for awk_impl in $awks; do
    expect "no change" 0 "$base" "$c_none"
    expect "head equals base" 0 "$base" "$base"
    expect "non-crypto bump (anyhow)" 0 "$base" "$c_noncrypto"
    expect "subtle bump" 1 "$base" "$c_subtle" "TOUCHED crypto-critical crates: subtle"
    expect "second ring version added" 1 "$base" "$c_ring2" "+ Cargo.lock: ring 0.16.20"
    expect "crypto crate removed" 1 "$base" "$c_removed" "- Cargo.lock: subtle $subtle_v"
    expect "checksum-only change" 1 "$base" "$c_checksum" "TOUCHED crypto-critical crates: sha2"
    expect "same version, different source" 1 "$base" "$c_source" "TOUCHED crypto-critical crates: ring"
    expect "binding-only change" 1 "$base" "$c_binding" "+ bindings/acdp-node/Cargo.lock: sha2 99.0.0"
    expect "github-actions only (no lockfile change)" 0 "$base" "$c_actions"
    expect "unlisted crate sharing a name prefix" 0 "$base" "$c_prefix"
    expect "guard list edited" 1 "$base" "$c_list_edit" "TOUCHED gate files: scripts/crypto-critical.txt"
    expect "gate script edited" 1 "$base" "$c_gate_edit" "TOUCHED gate files: scripts/dependabot-crypto-gate.sh"
    expect "PR branch behind base (diff from merge base)" 0 "$c_main_ahead" "$c_noncrypto"
    expect "empty lockfile" 2 "$base" "$c_empty" "no [[package]] blocks"
    expect "not a lockfile" 2 "$base" "$c_garbage" "no [[package]] blocks"
    expect "package without version" 2 "$base" "$c_noversion" "without name or version"
    expect "field not a plain string" 2 "$base" "$c_badstr" "not a plain string"
    expect "lockfile missing on head" 2 "$base" "$c_missing_head" "missing on the head side"
    expect "lockfile missing on base" 2 "$c_missing_base" "$c_readded" "missing on the base side"
    expect "unknown revision" 2 "$base" no-such-rev "unknown head revision"
    expect "list: markers and comments, listed crate" 1 "$base" "$c_subtle" "crates: subtle" "$tmp/list-markers.txt"
    expect "list: commented-out crate is not listed" 0 "$base" "$c_ring2" "" "$tmp/list-markers.txt"
    expect "list: unlisted crate" 0 "$base" "$c_checksum" "" "$tmp/list-markers.txt"
    expect "list: only comments" 2 "$base" "$c_none" "names no crates" "$tmp/list-empty.txt"
    expect "list: bad crate name" 2 "$base" "$c_none" "bad crate name" "$tmp/list-badname.txt"
    expect "list: missing file" 2 "$base" "$c_none" "guard list not found" "$tmp/no-such-list.txt"
done
awk_impl="awk"

# Usage errors.
rc=0
"$gate" --repo "$repo" --base "$base" >"$tmp/out" 2>&1 || rc=$?
if [ "$rc" -eq 2 ]; then ok "missing --head: exit 2"; else bad "missing --head: rc=$rc"; fi
rc=0
"$gate" --bogus >"$tmp/out" 2>&1 || rc=$?
if [ "$rc" -eq 2 ]; then ok "unknown argument: exit 2"; else bad "unknown argument: rc=$rc"; fi

# The workflow's path: a copy of the gate and list read from the base commit
# with `git cat-file`, run while the work tree holds the head.
start "$c_subtle"
g cat-file blob "$base:scripts/dependabot-crypto-gate.sh" >"$tmp/base-gate.sh"
g cat-file blob "$base:scripts/crypto-critical.txt" >"$tmp/base-list.txt"
rc=0
(cd "$repo" && bash "$tmp/base-gate.sh" --base "$base" --head "$c_subtle" --list "$tmp/base-list.txt") >"$tmp/out" 2>&1 || rc=$?
if [ "$rc" -eq 1 ] && grep -qF "crates: subtle" "$tmp/out"; then
    ok "base-loaded gate copy: exit 1 naming subtle"
else
    bad "base-loaded gate copy: rc=$rc"
    sed 's/^/    /' "$tmp/out" >&2
fi

# The real tree, HEAD vs HEAD.
rc=0
"$gate" --repo "$repo_root" --base HEAD --head HEAD >"$tmp/out" 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then ok "real tree HEAD vs HEAD: exit 0"; else bad "real tree HEAD vs HEAD: rc=$rc"; sed 's/^/    /' "$tmp/out" >&2; fi

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
