#!/usr/bin/env bash
# Crypto-critical cargo-vet guard (issue #322).
#
# `cargo vet` passes when a crate is covered by an exemption instead of an
# audit, so on its own it cannot tell "audited" from "exempted". This guard
# closes that gap for the crates in scripts/crypto-critical.txt: each one must
# be in `vetted_fully` at every version in Cargo.lock, unless its line carries
# an allowed `allow-exempt:` marker. See that file for the marker semantics,
# and DECISIONS.md "#322 supply-chain audit policy".
#
# Usage: scripts/check-crypto-vet.sh [--store-path <dir>] [--list <file>]
#                                    [--decisions <file>]
#   --store-path  passed through to `cargo vet` (default: supply-chain/)
#   --list        guard list (default: scripts/crypto-critical.txt)
#   --decisions   file searched for DECISIONS# anchors (default: DECISIONS.md)
#
# Exit status: 0 when every listed crate passes, 1 on any violation, 2 on a
# usage or tooling error. Requires cargo, cargo-vet, and jq.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)

store_path=""
list_file="$script_dir/crypto-critical.txt"
decisions_file="$repo_root/DECISIONS.md"

usage() {
    echo "usage: scripts/check-crypto-vet.sh [--store-path <dir>] [--list <file>] [--decisions <file>]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --store-path) [ $# -ge 2 ] || usage; store_path=$2; shift 2 ;;
        --list) [ $# -ge 2 ] || usage; list_file=$2; shift 2 ;;
        --decisions) [ $# -ge 2 ] || usage; decisions_file=$2; shift 2 ;;
        -h | --help) usage ;;
        *) echo "check-crypto-vet: unknown argument: $1" >&2; usage ;;
    esac
done

for tool in cargo jq; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "check-crypto-vet: '$tool' not found on PATH" >&2
        exit 2
    }
done
[ -f "$list_file" ] || { echo "check-crypto-vet: guard list not found: $list_file" >&2; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

vet_args=(vet --locked --output-format=json)
if [ -n "$store_path" ]; then
    vet_args+=(--store-path "$store_path")
fi

# A failing `cargo vet` is a guard failure too (and its JSON has another shape).
if ! (cd "$repo_root" && cargo "${vet_args[@]}") >"$tmp/vet.json" 2>"$tmp/vet.err"; then
    echo "check-crypto-vet: FAIL: 'cargo ${vet_args[*]}' did not succeed:" >&2
    cat "$tmp/vet.err" "$tmp/vet.json" >&2
    exit 1
fi
if [ "$(jq -r '.conclusion // empty' "$tmp/vet.json")" != "success" ]; then
    echo "check-crypto-vet: FAIL: cargo vet conclusion is not 'success'" >&2
    cat "$tmp/vet.json" >&2
    exit 1
fi

(cd "$repo_root" && cargo metadata --format-version 1 --locked --all-features) \
    >"$tmp/metadata.json" 2>"$tmp/metadata.err" || {
    echo "check-crypto-vet: 'cargo metadata --locked' failed:" >&2
    cat "$tmp/metadata.err" >&2
    exit 2
}

# Registry-sourced versions of <crate> in the locked graph, one per line.
locked_versions() {
    jq -r --arg n "$1" \
        '.packages[] | select(.name == $n and ((.source // "") | startswith("registry+"))) | .version' \
        "$tmp/metadata.json" | sort -u
}

# Exit 0 if <crate> <version> is in `vetted_fully`.
fully_vetted() {
    jq -e --arg n "$1" --arg v "$2" \
        'any(.vetted_fully[]?; .name == $n and .version == $v)' \
        "$tmp/vet.json" >/dev/null
}

config_file="${store_path:-$repo_root/supply-chain}/config.toml"

# Versions of <crate> exempted in config.toml (`[[exemptions.<crate>]]`
# followed by `version = "..."`), one per line.
exempted_versions() {
    [ -f "$config_file" ] || return 0
    awk -v hdr="[[exemptions.$1]]" '
        /^\[/ { inside = ($0 == hdr); next }
        inside && /^version[[:space:]]*=/ {
            v = $0; sub(/^version[[:space:]]*=[[:space:]]*"/, "", v); sub(/".*$/, "", v); print v
        }
    ' "$config_file" | sort -u
}

failures=0
fail() {
    echo "check-crypto-vet: FAIL: $*" >&2
    failures=$((failures + 1))
}

list_name=$(basename -- "$list_file")
checked=0
# fd 3, so nothing in the loop body can consume the list from stdin.
while read -r name marker <&3 || [ -n "${name:-}" ]; do
    # Comments: a line starting with `#`; or whitespace then `#` (the `#` in
    # a marker such as `allow-exempt:DECISIONS#322-<crate>@<version>` follows a
    # `:` or other text, so it is not mistaken for a comment).
    case "${name:-}" in '' | '#'*) continue ;; esac
    marker=$(printf '%s' "${marker:-}" | sed -E 's/(^|[[:space:]])#.*$//; s/[[:space:]]+$//')
    checked=$((checked + 1))

    versions=$(locked_versions "$name")
    if [ -z "$versions" ]; then
        fail "$name: listed in $list_name but not a registry crate in Cargo.lock (typo, or remove the line)"
        continue
    fi

    total=0
    vetted=0
    unvetted=""
    for v in $versions; do
        total=$((total + 1))
        if fully_vetted "$name" "$v"; then
            vetted=$((vetted + 1))
        else
            unvetted="$unvetted $v"
        fi
    done
    unvetted=${unvetted# }

    case "$marker" in
        '')
            if [ -n "$unvetted" ]; then
                for v in $unvetted; do
                    fail "$name $v is crypto-critical but not fully audited (exempted or partially vetted)." \
                        "Crypto-critical crates may not take the exempt path. Review it and certify:" \
                        "  scripts/vet-facts.sh $name $v [<audited-base>]" \
                        "  cargo vet diff $name <audited-base> $v --mode=local   # or: cargo vet inspect $name $v --mode=local" \
                        "then 'cargo vet certify' per DECISIONS.md '#322 supply-chain audit policy'."
                done
            else
                echo "check-crypto-vet: ok: $name ($versions) fully audited"
            fi
            ;;
        allow-exempt:DECISIONS#?*)
            # (A DECISIONS marker is allow-exempt:DECISIONS#322-<crate>@<version>.)
            if [ "$vetted" -eq "$total" ]; then
                fail "$name: stale marker '$marker' -- remove it: every locked version ($versions) is now fully audited."
                continue
            fi
            case "$marker" in
                allow-exempt:DECISIONS#*)
                    # Format: allow-exempt:DECISIONS#322-<crate>@<version>.
                    # The @<version> pins the one exempted version the DECISIONS
                    # entry was written for, so a bump cannot be met by moving
                    # the exemption.
                    anchor=${marker#allow-exempt:DECISIONS#}
                    case "$anchor" in
                        *@?*) pinned=${anchor##*@}; anchor=${anchor%@*} ;;
                        *)
                            fail "$name: marker '$marker' must pin the exempted version: 'allow-exempt:DECISIONS#322-$name@<version>'."
                            continue
                            ;;
                    esac
                    # The anchor must be exactly `322-<crate>`, and DECISIONS.md
                    # must contain it as a whole token (not as a prefix of a
                    # longer name such as `322-<crate>-x`).
                    if [ "$anchor" != "322-$name" ]; then
                        fail "$name: marker '$marker' must name anchor '322-$name' exactly (got '$anchor')."
                        continue
                    fi
                    if [ ! -f "$decisions_file" ] ||
                        ! grep -qE -- "(^|[^A-Za-z0-9_-])${anchor}([^A-Za-z0-9_-]|\$)" "$decisions_file"; then
                        fail "$name: marker '$marker' names anchor '$anchor', which does not appear in $(basename "$decisions_file")."
                        continue
                    fi
                    mismatch=0
                    for v in $unvetted; do
                        if [ "$v" != "$pinned" ]; then
                            fail "$name: locked version $v is not fully audited and differs from the version pinned by '$marker' ($pinned):" \
                                "re-audit $name $v, or update the DECISIONS.md '$anchor' entry and the marker."
                            mismatch=1
                        fi
                    done
                    for v in $(exempted_versions "$name"); do
                        if [ "$v" != "$pinned" ]; then
                            fail "$name: supply-chain/config.toml exempts version $v, which differs from the version pinned by '$marker' ($pinned):" \
                                "re-audit $name $v, or update the DECISIONS.md '$anchor' entry and the marker."
                            mismatch=1
                        fi
                    done
                    [ "$mismatch" -eq 0 ] || continue
                    ;;
            esac
            echo "check-crypto-vet: ok: $name ($unvetted) allowed exempt by '$marker'"
            ;;
        *)
            fail "$name: unknown marker '$marker' (allowed: none, 'allow-exempt:DECISIONS#322-<crate>@<version>')."
            ;;
    esac
done 3<"$list_file"

if [ "$checked" -eq 0 ]; then
    fail "guard list $list_file names no crates"
fi

if [ "$failures" -gt 0 ]; then
    echo "check-crypto-vet: $failures violation(s); see docs/supply-chain.md 'Contributor workflow'." >&2
    exit 1
fi
echo "check-crypto-vet: all $checked crypto-critical crates pass."
