#!/usr/bin/env bash
# Bindings lock-parity guard for crypto-critical crates (issue #340).
#
# bindings/acdp-py, bindings/acdp-node and bindings/acdp-wasm each have their
# own Cargo.lock, and `cargo vet` only gates the root one. This guard makes
# the root audits cover the bindings by version: for every crate named in
# scripts/crypto-critical.txt, each registry (version, checksum) pair in a
# binding lockfile must also appear in the root Cargo.lock. A listed crate
# absent from a binding is fine; a listed crate absent from the root lockfile
# fails (typo, or a stale list line). Markers on list lines are ignored here
# (scripts/check-crypto-vet.sh owns them).
#
# Usage: scripts/check-bindings-lock-parity.sh [--root <Cargo.lock>]
#                                              [--list <file>] [<lock>...]
#   --root   root lockfile (default: Cargo.lock)
#   --list   guard list (default: scripts/crypto-critical.txt)
#   <lock>   binding lockfiles (default: bindings/acdp-{py,node,wasm}/Cargo.lock)
#
# Exit status: 0 when every binding matches, 1 on any violation, 2 on a usage
# error or a missing / empty / malformed lockfile. Needs only POSIX awk
# (BSD and GNU awk both work).
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)

root_lock="$repo_root/Cargo.lock"
list_file="$script_dir/crypto-critical.txt"

usage() {
    echo "usage: scripts/check-bindings-lock-parity.sh [--root <Cargo.lock>] [--list <file>] [<lock>...]" >&2
    exit 2
}

locks=()
while [ $# -gt 0 ]; do
    case "$1" in
        --root) [ $# -ge 2 ] || usage; root_lock=$2; shift 2 ;;
        --list) [ $# -ge 2 ] || usage; list_file=$2; shift 2 ;;
        -h | --help) usage ;;
        -*) echo "check-bindings-lock-parity: unknown argument: $1" >&2; usage ;;
        *) locks+=("$1"); shift ;;
    esac
done
if [ "${#locks[@]}" -eq 0 ]; then
    for b in acdp-py acdp-node acdp-wasm; do
        locks+=("$repo_root/bindings/$b/Cargo.lock")
    done
fi

[ -f "$list_file" ] || { echo "check-bindings-lock-parity: guard list not found: $list_file" >&2; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Show a path relative to the repo root when it is inside it.
rel() {
    case "$1" in
        "$repo_root"/*) printf '%s' "${1#"$repo_root"/}" ;;
        *) printf '%s' "$1" ;;
    esac
}

# parse_lock <lockfile> <out>: one `name|version|checksum` row per registry
# package. Exits 2 when the file is missing, empty, has no [[package]] block,
# or has a block without name/version, or a registry block without checksum.
parse_lock() {
    local lock=$1 out=$2
    if [ ! -s "$lock" ]; then
        echo "check-bindings-lock-parity: lockfile missing or empty: $(rel "$lock")" >&2
        exit 2
    fi
    if ! awk '
        function val(s) { sub(/^[^=]*=[[:space:]]*"/, "", s); sub(/".*$/, "", s); return s }
        function flush() {
            if (!inpkg) return
            if (name == "" || version == "") { bad = 1; return }
            if (source ~ /^registry\+/) {
                if (checksum == "") { bad = 1; return }
                print name "|" version "|" checksum
            }
        }
        /^\[\[package\]\][[:space:]]*$/ { flush(); inpkg = 1; pkgs++; name = version = source = checksum = ""; next }
        /^\[/ { flush(); inpkg = 0; next }
        inpkg && /^name[[:space:]]*=/ { name = val($0); next }
        inpkg && /^version[[:space:]]*=/ { version = val($0); next }
        inpkg && /^source[[:space:]]*=/ { source = val($0); next }
        inpkg && /^checksum[[:space:]]*=/ { checksum = val($0); next }
        END { flush(); if (bad || pkgs == 0) exit 3 }
    ' "$lock" | sort -u >"$out"; then
        echo "check-bindings-lock-parity: malformed lockfile (no [[package]] blocks, or a package without name/version/checksum): $(rel "$lock")" >&2
        exit 2
    fi
}

# Guard-list crate names (comments and markers stripped), one per line.
crates=$(awk '{ sub(/(^|[[:space:]])#.*$/, "") } NF { print $1 }' "$list_file" | sort -u)
if [ -z "$crates" ]; then
    echo "check-bindings-lock-parity: FAIL: guard list $(rel "$list_file") names no crates" >&2
    exit 1
fi

parse_lock "$root_lock" "$tmp/root"
i=0
for lock in "${locks[@]}"; do
    i=$((i + 1))
    parse_lock "$lock" "$tmp/lock.$i"
done

failures=0
fail() {
    echo "check-bindings-lock-parity: FAIL: $*" >&2
    failures=$((failures + 1))
}

# Rows of <crate> in a parsed lockfile, as `version|checksum`.
rows() { awk -F'|' -v n="$1" '$1 == n { print $2 "|" $3 }' "$2"; }

checked=0
for name in $crates; do
    checked=$((checked + 1))
    root_rows=$(rows "$name" "$tmp/root")
    if [ -z "$root_rows" ]; then
        fail "$name: listed in $(basename -- "$list_file") but not a registry crate in $(rel "$root_lock") (typo, or remove the line)"
        continue
    fi
    i=0
    for lock in "${locks[@]}"; do
        i=$((i + 1))
        for row in $(rows "$name" "$tmp/lock.$i"); do
            if ! printf '%s\n' "$root_rows" | grep -qxF -- "$row"; then
                ver=${row%%|*}
                sum=${row#*|}
                if printf '%s\n' "$root_rows" | grep -q -- "^${ver}|"; then
                    fail "$name $ver in $(rel "$lock") has checksum $sum, which differs from $(rel "$root_lock")"
                else
                    fail "$name $ver in $(rel "$lock") is not in $(rel "$root_lock") (root has: $(printf '%s\n' "$root_rows" | cut -d'|' -f1 | tr '\n' ' ' | sed 's/ $//'));" \
                        "re-lock the binding: cargo update -p $name --precise <root-version> --manifest-path $(rel "$(dirname -- "$lock")")/Cargo.toml"
                fi
            fi
        done
    done
done

if [ "$failures" -gt 0 ]; then
    echo "check-bindings-lock-parity: $failures violation(s); see docs/supply-chain.md 'Coverage outside this repo's root lockfile'." >&2
    exit 1
fi
echo "check-bindings-lock-parity: all $checked crypto-critical crates match the root lockfile in ${#locks[@]} binding lockfile(s)."
