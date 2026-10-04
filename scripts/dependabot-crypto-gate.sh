#!/usr/bin/env bash
# Dependabot auto-merge gate (issue #344).
#
# Decides whether a Dependabot PR touches a crypto-critical crate
# (scripts/crypto-critical.txt), so .github/workflows/dependabot-auto-merge.yml
# can leave that PR for a maintainer. Gating on the Dependabot group name alone
# misses a transitive crypto crate that moves inside another group's PR (for
# example `minor-and-patch`) and the bindings' own Dependabot entries. Such a
# crate can be fully vetted through an imported audit, so `cargo-vet` would be
# green and the PR would merge with no maintainer review.
#
# Usage: scripts/dependabot-crypto-gate.sh --base <rev> --head <rev>
#                                          [--list <file>] [--repo <dir>]
#   --base, --head  git revisions; the diff is merge-base(base, head) .. head,
#                   which is exactly what the PR changes
#   --list          guard list (default: scripts/crypto-critical.txt next to
#                   this script); same format as for check-crypto-vet.sh, and
#                   only the crate name (first field) is used
#   --repo          git repository to read (default: the current directory)
#
# Everything is read from git objects (`git cat-file`), never from the work
# tree, so the CI workflow can run a copy of this script, and the list, taken
# from the PR's base commit while the checkout holds the PR's head.
#
# For each lockfile in LOCKFILES, every `[[package]]` block becomes a row
# `name|version|source|checksum`; the rows of listed crates are compared
# between the two sides. Any difference (a bump, a second version, a removal,
# a source or checksum change) counts as touched. So does a change to one of
# the gate's own files (PROTECTED_PATHS).
#
# Exit status (the workflow enables auto-merge only on 0):
#   0  no crypto-critical crate touched
#   1  touched; the crates (and protected paths) are printed
#   2  error: usage, unknown revision, a lockfile missing on either side,
#      an empty or malformed lockfile or guard list, or any tool failure
#
# Portable: bash 3.2+, POSIX awk (BSD awk, gawk, mawk; override with $AWK).
set -Eeuo pipefail
trap 'echo "dependabot-crypto-gate: ERROR: unexpected failure (line $LINENO)" >&2; exit 2' ERR

AWK=${AWK:-awk}
LOCKFILES="Cargo.lock bindings/acdp-py/Cargo.lock bindings/acdp-node/Cargo.lock bindings/acdp-wasm/Cargo.lock"
PROTECTED_PATHS="scripts/dependabot-crypto-gate.sh scripts/crypto-critical.txt .github/workflows/dependabot-auto-merge.yml"

die() {
    echo "dependabot-crypto-gate: ERROR: $*" >&2
    exit 2
}
usage() {
    echo "usage: scripts/dependabot-crypto-gate.sh --base <rev> --head <rev> [--list <file>] [--repo <dir>]" >&2
    exit 2
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
base=""
head=""
list_file="$script_dir/crypto-critical.txt"
repo="."

while [ $# -gt 0 ]; do
    case "$1" in
        --base) [ $# -ge 2 ] || usage; base=$2; shift 2 ;;
        --head) [ $# -ge 2 ] || usage; head=$2; shift 2 ;;
        --list) [ $# -ge 2 ] || usage; list_file=$2; shift 2 ;;
        --repo) [ $# -ge 2 ] || usage; repo=$2; shift 2 ;;
        -h | --help) usage ;;
        *) echo "dependabot-crypto-gate: unknown argument: $1" >&2; usage ;;
    esac
done
[ -n "$base" ] && [ -n "$head" ] || usage

for tool in git "$AWK" sort comm; do
    command -v "$tool" >/dev/null 2>&1 || die "'$tool' not found on PATH"
done
[ -f "$list_file" ] || die "guard list not found: $list_file"

g() { git -C "$repo" "$@"; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Crate names from the guard list. A line whose first non-blank character is
# `#` is a comment; only the first field is a name (markers and trailing
# comments are ignored). A name that is not a plausible crate name is an error.
names_rc=0
"$AWK" '
    { sub(/\r$/, "") }
    /^[[:space:]]*(#|$)/ { next }
    {
        if ($1 !~ /^[A-Za-z0-9_-]+$/) {
            printf "dependabot-crypto-gate: ERROR: guard list line %d: bad crate name \"%s\"\n", NR, $1 > "/dev/stderr"
            bad = 1
            exit 2
        }
        print $1
    }
' "$list_file" >"$tmp/names" || names_rc=$?
[ "$names_rc" -eq 0 ] || die "cannot parse guard list $list_file"
[ -s "$tmp/names" ] || die "guard list $list_file names no crates"

base_commit=$(g rev-parse --verify --quiet "$base^{commit}") || die "unknown base revision: $base"
head_commit=$(g rev-parse --verify --quiet "$head^{commit}") || die "unknown head revision: $head"
merge_base=$(g merge-base "$base_commit" "$head_commit") || die "no merge base between $base and $head"

# Rows `name|version|source|checksum`, one per [[package]] block, from a
# Cargo.lock on stdin. Exits 2 on an empty file, a file without packages, a
# block without name or version, or a field that is not a plain string.
parse_lock() {
    "$AWK" -v file="$1" '
        function fail(msg) {
            printf "dependabot-crypto-gate: ERROR: %s: line %d: %s\n", file, NR, msg > "/dev/stderr"
            bad = 1
            exit 2
        }
        function flush() {
            if (inpkg) {
                if (name == "" || version == "") fail("[[package]] block without name or version")
                print name "|" version "|" source "|" checksum
                count++
            }
            inpkg = 0
            name = ""; version = ""; source = ""; checksum = ""
        }
        { sub(/\r$/, "") }
        /^\[\[package\]\][[:space:]]*$/ { flush(); inpkg = 1; next }
        /^\[/ { flush(); next }
        inpkg && /^(name|version|source|checksum)[[:space:]]*=/ {
            key = $0; sub(/[[:space:]]*=.*$/, "", key)
            val = $0; sub(/^[^=]*=[[:space:]]*/, "", val); sub(/[[:space:]]+$/, "", val)
            if (val !~ /^"[^"|]*"$/) fail(key " is not a plain string")
            val = substr(val, 2, length(val) - 2)
            if (key == "name") { if (name != "") fail("duplicate name"); name = val }
            else if (key == "version") { if (version != "") fail("duplicate version"); version = val }
            else if (key == "source") { if (source != "") fail("duplicate source"); source = val }
            else { if (checksum != "") fail("duplicate checksum"); checksum = val }
        }
        END {
            if (bad) exit 2
            flush()
            if (count == 0) fail("no [[package]] blocks (empty or not a Cargo.lock)")
        }
    '
}

# lock_rows <commit> <side> <path>: rows of listed crates, prefixed by <path>.
lock_rows() {
    local commit=$1 side=$2 path=$3 rc=0
    g cat-file -e "$commit:$path" 2>/dev/null || die "$path is missing on the $side side ($commit)"
    g cat-file blob "$commit:$path" >"$tmp/blob" || die "cannot read $path at $commit"
    parse_lock "$side:$path" <"$tmp/blob" >"$tmp/rows" || rc=$?
    [ "$rc" -eq 0 ] || die "malformed lockfile $path on the $side side ($commit)"
    "$AWK" -v p="$path" '
        NR == FNR { want[$0] = 1; next }
        { split($0, f, "|"); if (f[1] in want) print p "|" $0 }
    ' "$tmp/names" "$tmp/rows"
}

: >"$tmp/base.rows"
: >"$tmp/head.rows"
for path in $LOCKFILES; do
    lock_rows "$merge_base" base "$path" >>"$tmp/base.rows"
    lock_rows "$head_commit" head "$path" >>"$tmp/head.rows"
done
LC_ALL=C sort -u "$tmp/base.rows" >"$tmp/base.sorted"
LC_ALL=C sort -u "$tmp/head.rows" >"$tmp/head.sorted"
LC_ALL=C comm -3 "$tmp/base.sorted" "$tmp/head.sorted" >"$tmp/diff"

# shellcheck disable=SC2086 # PROTECTED_PATHS is a space-separated list.
g diff --name-only "$merge_base" "$head_commit" -- $PROTECTED_PATHS >"$tmp/protected"

if [ ! -s "$tmp/diff" ] && [ ! -s "$tmp/protected" ]; then
    echo "dependabot-crypto-gate: ok: no crypto-critical crate touched ($merge_base..$head_commit)"
    exit 0
fi

if [ -s "$tmp/diff" ]; then
    # comm -3: a line only in base has no prefix, a line only in head a tab.
    "$AWK" '
        { s = "-" }
        /^\t/ { sub(/^\t/, ""); s = "+" }
        {
            split($0, f, "|")
            printf "dependabot-crypto-gate:   %s %s: %s %s (source %s, checksum %s)\n", s, f[1], f[2], f[3], \
                (f[4] == "" ? "none" : f[4]), (f[5] == "" ? "none" : f[5])
        }
    ' "$tmp/diff"
    touched=$("$AWK" '{ sub(/^\t/, ""); split($0, f, "|"); print f[2] }' "$tmp/diff" | LC_ALL=C sort -u | tr '\n' ' ')
    echo "dependabot-crypto-gate: TOUCHED crypto-critical crates: ${touched% }"
fi
if [ -s "$tmp/protected" ]; then
    echo "dependabot-crypto-gate: TOUCHED gate files: $(tr '\n' ' ' <"$tmp/protected" | sed 's/ $//')"
fi
echo "dependabot-crypto-gate: needs maintainer review; auto-merge must stay off."
exit 1
