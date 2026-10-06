#!/usr/bin/env bash
# Reproducible review facts for a cargo-vet audit (issue #322).
#
# Usage: scripts/vet-facts.sh <crate> <locked-version> [<base-version>]
#
# Downloads the crates.io tarball(s), verifies their sha256 (the locked version
# against the Cargo.lock `checksum`, the base version against the crates.io
# index `cksum`), and prints the facts an audit note quotes (see the notes
# template in DECISIONS.md "#322 supply-chain audit policy"):
#   - diff stat vs. <base> (Cargo.lock, Cargo.toml.orig, .cargo_vcs_info.json
#     excluded), full src/ line count, delta/full ratio, implied method;
#   - unsafe code lines (file:line), forbid(unsafe_code), asm!/global_asm!;
#   - build.rs, proc-macro, powerful imports, dependency changes.
#
# `cargo vet diff --mode=local` / `cargo vet inspect --mode=local` remain the
# viewer reviewers read; this script only adds the quotable facts.
#
# Environment:
#   VET_FACTS_CRATE_DIR  directory checked first for <crate>-<version>.crate
#                        (skips the download; the checksum is still enforced).
#
# Exits non-zero on any download or checksum failure. Requires curl, tar, diff,
# and sha256sum or shasum.
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "usage: scripts/vet-facts.sh <crate> <locked-version> [<base-version>]" >&2
    exit 2
fi
crate=$1
locked=$2
base=${3:-}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
lockfile="$repo_root/Cargo.lock"

die() {
    echo "vet-facts: ERROR: $*" >&2
    exit 1
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Cargo.lock `checksum` of <crate> <version> (empty if absent).
lock_checksum() {
    awk -v n="$1" -v v="$2" '
        /^\[\[package\]\]/ { name = ""; ver = ""; next }
        /^name = / { name = $3; gsub(/"/, "", name); next }
        /^version = / { ver = $3; gsub(/"/, "", ver); next }
        /^checksum = / { c = $3; gsub(/"/, "", c); if (name == n && ver == v) print c }
    ' "$lockfile"
}

# crates.io sparse-index path for a crate name.
index_path() {
    local n
    n=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case ${#n} in
        1) printf '1/%s' "$n" ;;
        2) printf '2/%s' "$n" ;;
        3) printf '3/%s/%s' "${n:0:1}" "$n" ;;
        *) printf '%s/%s/%s' "${n:0:2}" "${n:2:2}" "$n" ;;
    esac
}

# crates.io index `cksum` of <crate> <version> (empty if absent).
index_checksum() {
    curl -fsSL "https://index.crates.io/$(index_path "$1")" -o "$tmp/index.jsonl" ||
        die "could not fetch the crates.io index entry for $1"
    grep -F "\"vers\":\"$2\"" "$tmp/index.jsonl" |
        sed -nE 's/.*"cksum":"([0-9a-f]{64})".*/\1/p' | head -n 1
}

# Fetch, verify, and unpack <crate> <version> into $tmp/<version>/.
fetch() {
    local v=$1 expected=$2 source=$3 file got
    file="$tmp/$crate-$v.crate"
    if [ -n "${VET_FACTS_CRATE_DIR:-}" ] && [ -f "$VET_FACTS_CRATE_DIR/$crate-$v.crate" ]; then
        cp "$VET_FACTS_CRATE_DIR/$crate-$v.crate" "$file"
    else
        curl -fsSL "https://static.crates.io/crates/$crate/$crate-$v.crate" -o "$file" ||
            die "download failed: $crate $v"
    fi
    got=$(sha256_of "$file")
    if [ "$got" != "$expected" ]; then
        die "checksum MISMATCH for $crate $v: tarball sha256 $got != $source $expected"
    fi
    echo "checksum OK: $crate $v sha256 $got == $source"
    mkdir -p "$tmp/$v"
    tar -xzf "$file" -C "$tmp/$v" || die "could not unpack $crate $v"
    [ -d "$tmp/$v/$crate-$v" ] || die "unexpected tarball layout for $crate $v"
}

locked_ck=$(lock_checksum "$crate" "$locked")
[ -n "$locked_ck" ] || die "$crate $locked is not in $lockfile (with a checksum)"
fetch "$locked" "$locked_ck" "Cargo.lock checksum"
new="$tmp/$locked/$crate-$locked"

if [ -n "$base" ]; then
    base_ck=$(index_checksum "$crate" "$base")
    [ -n "$base_ck" ] || die "$crate $base is not in the crates.io index"
    fetch "$base" "$base_ck" "crates.io index cksum"
    old="$tmp/$base/$crate-$base"
fi

# Lines of a grep -rn result whose content (after file:line:) is not a `//` comment.
drop_comments() {
    grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true
}

# grep -rnE over the crate's .rs files under <dir>, paths relative to the crate.
rs_grep() {
    local dir=$1 pattern=$2
    [ -d "$new/$dir" ] || return 0
    (cd "$new" && grep -rnE --include='*.rs' -- "$pattern" "$dir" || true) | sort -t: -k1,1 -k2,2n
}

echo
echo "== $crate $locked${base:+ (base $base)}"

src_lines=0
if [ -d "$new/src" ]; then
    src_lines=$(find "$new/src" -type f -name '*.rs' -exec cat {} + | wc -l | tr -d ' ')
fi
echo "full src/ lines (*.rs): $src_lines"

if [ -n "$base" ]; then
    (cd "$tmp" && diff -ruN -x Cargo.lock -x Cargo.toml.orig -x .cargo_vcs_info.json \
        "$base/$crate-$base" "$locked/$crate-$locked" >"$tmp/delta.diff") || true
    # +/- are counted only inside hunks, so a removed line that itself starts
    # with `--` is not mistaken for a file header.
    read -r files added removed binary < <(awk '
        /^diff / { files++; inh = 0; prevdiff = 1; next }
        /^Binary files / { bin++; if (!prevdiff) files++; prevdiff = 0; next }
        { prevdiff = 0 }
        /^@@/ { inh = 1; next }
        inh && /^\+/ { a++ }
        inh && /^-/ { d++ }
        END { printf "%d %d %d %d\n", files, a, d, bin }
    ' "$tmp/delta.diff")
    echo "diff stat (excl. Cargo.lock, Cargo.toml.orig, .cargo_vcs_info.json): $files files changed, +$added/-$removed"
    [ "$binary" -eq 0 ] || echo "binary files changed: $binary (inspect: vendored binary content is a concern-rule trigger)"
    if [ "$src_lines" -gt 0 ]; then
        ratio=$(awk -v c="$((added + removed))" -v s="$src_lines" 'BEGIN { printf "%.2f", c / s }')
        method=$(awk -v r="$ratio" 'BEGIN { print (r >= 0.75 ? "full" : "delta") }')
        echo "delta/full ratio: $ratio (changed lines $((added + removed)) / src lines $src_lines)"
        echo "method (ratio rule, >= 0.75 -> full): $method  [the rewrite clause of the method rule is a reviewer judgement]"
    fi
else
    echo "method: full (no base given)"
fi

echo
unsafe_hits=$(rs_grep src '(^|[^[:alnum:]_])unsafe[[:space:]]*(\{|fn([^[:alnum:]_]|$)|impl([^[:alnum:]_]|$)|trait([^[:alnum:]_]|$)|extern([^[:alnum:]_]|$))' | drop_comments)
if [ -n "$unsafe_hits" ]; then
    echo "unsafe code lines: $(printf '%s\n' "$unsafe_hits" | wc -l | tr -d ' ')"
    printf '%s\n' "$unsafe_hits" | sed 's/^/  /'
else
    echo "unsafe code lines: 0"
fi

# Crate-level attribute, unconditional or behind cfg_attr (single-line forms).
forbid_hits=$(rs_grep src '^[[:space:]]*#!\[forbid\([^]]*unsafe_code' | drop_comments)
cond_hits=$(rs_grep src '^[[:space:]]*#!\[cfg_attr\(.*forbid\([^]]*unsafe_code' | drop_comments)
if [ -n "$forbid_hits" ]; then
    echo "forbid(unsafe_code): yes"
    printf '%s\n' "$forbid_hits" | sed 's/^/  /'
elif [ -n "$cond_hits" ]; then
    echo "forbid(unsafe_code): conditional (cfg_attr -- check the condition against the features ACDP enables)"
    printf '%s\n' "$cond_hits" | sed 's/^/  /'
else
    echo "forbid(unsafe_code): no"
fi

asm_files=$(cd "$new" && grep -rlE --include='*.rs' -- '(^|[^[:alnum:]_])(global_)?asm!' . 2>/dev/null | sed 's|^\./||' | sort || true)
if [ -n "$asm_files" ]; then
    echo "files with asm!/global_asm!: $(printf '%s\n' "$asm_files" | wc -l | tr -d ' ')"
    printf '%s\n' "$asm_files" | sed 's/^/  /'
else
    echo "files with asm!/global_asm!: none"
fi

build_script=""
if [ -f "$new/build.rs" ]; then
    build_script="build.rs"
fi
declared=$(sed -nE 's/^build[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$new/Cargo.toml" | head -n 1)
if [ -n "$declared" ]; then
    build_script=$declared
fi
if [ -n "$build_script" ] && [ -f "$new/$build_script" ]; then
    echo "build script: $build_script ($(wc -l <"$new/$build_script" | tr -d ' ') lines)"
    echo "----- $build_script -----"
    cat "$new/$build_script"
    echo "----- end $build_script -----"
else
    echo "build script: none"
fi

if grep -qE '^proc-macro[[:space:]]*=[[:space:]]*true' "$new/Cargo.toml"; then
    echo "proc-macro = true: yes"
else
    echo "proc-macro = true: no"
fi

# `std::fs` etc., plus single-line brace imports such as `use std::{fs, path::Path}`
# (missed before, for der 0.8.1). A brace import split over several lines is
# still not matched; read the `use` blocks.
powerful_re='std::(fs|net|process|env)|std::\{(.*[^[:alnum:]_])?(fs|net|process|env)([^[:alnum:]_]|$)|Command::new|(^|[^[:alnum:]_])(option_)?env!|include_bytes!'
powerful=$( (rs_grep src "$powerful_re"
    if [ -n "$build_script" ] && [ -f "$new/$build_script" ]; then
        (cd "$new" && grep -nE -- "$powerful_re" "$build_script" |
            sed "s|^|$build_script:|" || true)
    fi) | drop_comments)
if [ -n "$powerful" ]; then
    echo "powerful-import hits: $(printf '%s\n' "$powerful" | wc -l | tr -d ' ')"
    printf '%s\n' "$powerful" | sed 's/^/  /'
else
    echo "powerful-import hits: none"
fi

# "<kind> <name> <req>" per dependency of a normalized (crates.io) Cargo.toml.
deps_of() {
    awk '
        function emit() { if (dname != "") print dkind, dname, (dreq == "" ? "*" : dreq); dname = "" }
        /^\[/ {
            emit()
            sec = $0; gsub(/^\[|\]$/, "", sec)
            table = 0
            if (match(sec, /(^|\.)(dev-|build-)?dependencies\./)) {
                k = substr(sec, RSTART, RLENGTH); sub(/^\./, "", k); sub(/\.$/, "", k)
                pre = substr(sec, 1, RSTART - 1)
                dkind = (pre == "" ? k : pre "." k)
                dname = substr(sec, RSTART + RLENGTH); dreq = ""
            } else if (sec ~ /(^|\.)(dev-|build-)?dependencies$/) {
                table = 1; tkind = sec
            }
            next
        }
        dname != "" && /^version[[:space:]]*=/ { dreq = $0; sub(/^[^=]*=[[:space:]]*/, "", dreq); gsub(/"/, "", dreq); next }
        table && /^[A-Za-z0-9_-]+[[:space:]]*=/ {
            n = $0; sub(/[[:space:]]*=.*/, "", n)
            r = $0; sub(/^[^=]*=[[:space:]]*/, "", r)
            if (r ~ /version[[:space:]]*=/) { sub(/.*version[[:space:]]*=[[:space:]]*"/, "", r); sub(/".*/, "", r) } else gsub(/"/, "", r)
            print tkind, n, r
        }
        END { emit() }
    ' "$1" | sort -u
}

if [ -n "$base" ]; then
    deps_of "$old/Cargo.toml" >"$tmp/deps.old"
    deps_of "$new/Cargo.toml" >"$tmp/deps.new"
    removed_deps=$(comm -23 "$tmp/deps.old" "$tmp/deps.new")
    added_deps=$(comm -13 "$tmp/deps.old" "$tmp/deps.new")
    echo "dependency changes (kind name req; a changed requirement shows as -/+):"
    if [ -z "$removed_deps$added_deps" ]; then
        echo "  none"
    else
        [ -z "$removed_deps" ] || printf '%s\n' "$removed_deps" | sed 's/^/  - /'
        [ -z "$added_deps" ] || printf '%s\n' "$added_deps" | sed 's/^/  + /'
    fi
else
    echo "dependencies (kind name req):"
    deps_of "$new/Cargo.toml" | sed 's/^/  /'
fi
