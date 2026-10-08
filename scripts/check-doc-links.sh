#!/usr/bin/env bash
# Offline link/anchor checker for the hand-written Markdown docs.
#
# Checks every Markdown link (inline `[t](target)`, images, and reference
# definitions `[id]: target`) outside code fences and inline code spans:
#
#   * relative links      -> the file/directory must exist; a `#fragment` on a
#                            Markdown target must match a heading anchor.
#   * `#fragment` links   -> must match a heading anchor in the same file.
#   * GitHub blob/tree URLs for sibling org repos
#       https://github.com/agentcontextdistributionprotocol/<repo>/(blob|tree)/main/<path>[#anchor]
#                         -> mapped to a local sibling checkout and checked the
#                            same way. <repo> -> checkout:
#                              agentcontextdistributionprotocol -> $SPEC_DIR
#                              acdp-registry-rs, acdp-ci, acdp-verifier-py,
#                              .github / dotgithub              -> $SIBLINGS_DIR/<repo>
#                              acdp-rs                          -> this checkout
#                            A missing checkout is skipped with a notice (once).
#   * every other URL (http, mailto, ...) is ignored — this script is offline.
#
# Anchors follow GitHub's heading-slug rules: lowercase, drop punctuation
# except hyphens/underscores/spaces, spaces -> hyphens, repeated slugs get
# -1, -2, ... suffixes. Explicit `<a id=...>` / `<a name=...>` anchors count
# too. Line fragments (`#L10`, `#L10-L20`) are not checked.
#
# Note: sibling checkouts are checked as they are on disk; keep them on an
# up-to-date `main` for meaningful results.
#
# Usage: scripts/check-doc-links.sh [<file.md>...]
#   default files: README.md CONTRIBUTING.md SECURITY.md docs/**/*.md
#                  bindings/*/README.md
# Env:
#   SPEC_DIR      spec checkout   (default: ../agentcontextdistributionprotocol)
#   SIBLINGS_DIR  parent of the other sibling checkouts (default: ..)
#
# Exit status: 0 when every checked link resolves, 1 when any link is broken
# (each listed as file:line). Needs only bash, POSIX awk, grep and sed.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root"

SPEC_DIR=${SPEC_DIR:-../agentcontextdistributionprotocol}
SIBLINGS_DIR=${SIBLINGS_DIR:-..}
ORG_URL='https://github.com/agentcontextdistributionprotocol/'

work=$(mktemp -d "${TMPDIR:-/tmp}/check-doc-links.XXXXXX")
trap 'rm -rf "$work"' EXIT

if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=(README.md CONTRIBUTING.md SECURITY.md)
  while IFS= read -r f; do files+=("$f"); done < <(find docs -name '*.md' | sort)
  for f in bindings/*/README.md; do [ -f "$f" ] && files+=("$f"); done
fi

# --- anchors -----------------------------------------------------------------
# Prints one anchor per line for a Markdown file (GitHub slug rules).
# shellcheck disable=SC2016  # awk program, not shell
anchors_awk='
function slug(s,   t) {
  # inline links/images -> their text; drop HTML tags
  while (match(s, /!?\[[^]]*\]\([^)]*\)/)) {
    t = substr(s, RSTART, RLENGTH); sub(/^!?\[/, "", t); sub(/\]\(.*$/, "", t)
    s = substr(s, 1, RSTART - 1) t substr(s, RSTART + RLENGTH)
  }
  gsub(/<[^>]*>/, "", s)
  s = tolower(s)
  # Non-ASCII punctuation/symbols GitHub drops (byte-wise, UTF-8):
  gsub(/\342[\200-\277][\200-\277]/, "", s)         # U+2000-U+2FFF: dashes, quotes, arrows, math, dingbats
  gsub(/\302[\240-\277]|\303\227|\303\267/, "", s)  # Latin-1 symbols (section sign, middle dot, ...), times, divide
  gsub(/\360\237[\200-\277][\200-\277]|\357\270\217/, "", s)  # emoji + variation selector
  gsub(/[^a-z0-9 _\200-\377-]/, "", s)              # ASCII punctuation
  gsub(/ /, "-", s)
  return s
}
function emit(s,   b) {
  b = s
  if (b in seen) { s = b "-" seen[b]; seen[b]++ } else { seen[b] = 1 }
  print s
}
BEGIN { fence = "" }
{
  line = $0
  if (fence == "" && match(line, /^ {0,3}(```|~~~)/)) { fence = substr(line, RSTART + RLENGTH - 3, 3); prev = ""; next }
  if (fence != "") { if (line ~ ("^ {0,3}" fence)) fence = ""; next }
  while (match(line, /<a [^>]*(id|name)="[^"]*"/)) {
    a = substr(line, RSTART, RLENGTH); sub(/^.*(id|name)="/, "", a); sub(/"$/, "", a)
    print tolower(a); line = substr(line, RSTART + RLENGTH)
  }
  if ($0 ~ /^ {0,3}#{1,6}([ \t]|$)/) {
    h = $0; sub(/^ *#+[ \t]*/, "", h); sub(/[ \t]+#+[ \t]*$/, "", h); sub(/[ \t]+$/, "", h)
    emit(slug(h)); prev = ""; next
  }
  if (($0 ~ /^ {0,3}=+[ \t]*$/ || $0 ~ /^ {0,3}-+[ \t]*$/) && prev ~ /[^ \t]/ && prev !~ /^ {0,3}([-*+>|]|[0-9]+\.)/) {
    h = prev; sub(/^[ \t]+/, "", h); sub(/[ \t]+$/, "", h); emit(slug(h)); prev = ""; next
  }
  prev = $0
}'

anchor_cache() { # $1 = md file -> path of cached anchor list
  local key
  key=$(printf '%s' "$1" | cksum | awk '{print $1}')
  if [ ! -f "$work/$key" ]; then
    LC_ALL=C awk "$anchors_awk" "$1" > "$work/$key"
  fi
  printf '%s\n' "$work/$key"
}

has_anchor() { # $1 = md file, $2 = fragment
  local frag
  frag=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')
  grep -qxF -- "$frag" "$(anchor_cache "$1")"
}

# --- link extraction ---------------------------------------------------------
# Emits "file<TAB>line<TAB>target" for every link outside fences/code spans.
# shellcheck disable=SC2016  # awk program, not shell
extract_awk='
BEGIN { fence = "" }
{
  line = $0
  if (fence == "" && match(line, /^ {0,3}(```|~~~)/)) { fence = substr(line, RSTART + RLENGTH - 3, 3); next }
  if (fence != "") { if (line ~ ("^ {0,3}" fence)) fence = ""; next }
  gsub(/``[^`]*``/, "", line); gsub(/`[^`]*`/, "", line)
  if (match(line, /^ {0,3}\[[^]]+\]:[ \t]+[^ \t]+/)) {
    t = substr(line, RSTART, RLENGTH); sub(/^[^]]*\]:[ \t]+/, "", t)
    print FILENAME "\t" FNR "\t" t; next
  }
  while (match(line, /\]\([^)]*\)/)) {
    t = substr(line, RSTART + 2, RLENGTH - 3)
    line = substr(line, RSTART + RLENGTH)
    sub(/^[ \t]+/, "", t); sub(/[ \t].*$/, "", t); gsub(/^<|>$/, "", t)
    if (t != "") print FILENAME "\t" FNR "\t" t
  }
}'

# --- checking ----------------------------------------------------------------
broken=0
skipped_repos=" "

report() { # file line target reason
  printf '%s:%s: %s (%s)\n' "$1" "$2" "$3" "$4"
  broken=$((broken + 1))
}

# check_path <src-file> <line> <link> <resolved-path> <fragment>
check_path() {
  local src=$1 ln=$2 link=$3 path=$4 frag=$5
  if [ ! -e "$path" ]; then
    report "$src" "$ln" "$link" "missing: $path"; return
  fi
  [ -n "$frag" ] || return 0
  case "$frag" in L[0-9]*) return 0 ;; esac
  case "$path" in
    *.md|*.markdown)
      has_anchor "$path" "$frag" || report "$src" "$ln" "$link" "no anchor #$frag in $path" ;;
    *) ;;
  esac
}

LC_ALL=C awk "$extract_awk" "${files[@]}" > "$work/links.tsv"

while IFS=$'\t' read -r src ln target; do
  frag=""
  path_part=$target
  case "$target" in
    *'#'*) frag=${target#*#}; path_part=${target%%#*} ;;
  esac
  path_part=${path_part%%\?*}
  path_part=${path_part//%20/ }

  case "$target" in
    '#'*)
      has_anchor "$src" "$frag" || report "$src" "$ln" "$target" "no anchor #$frag in $src"
      continue ;;
    "$ORG_URL"*)
      rest=${path_part#"$ORG_URL"}
      repo=${rest%%/*}; rest=${rest#*/}
      case "$rest" in
        blob/main/*|tree/main/*) rel=${rest#*/main/} ;;
        blob/main|tree/main) rel="" ;;
        *) continue ;;
      esac
      case "$repo" in
        agentcontextdistributionprotocol) base=$SPEC_DIR ;;
        acdp-registry-rs|acdp-ci|acdp-verifier-py|dotgithub) base=$SIBLINGS_DIR/$repo ;;
        .github) base=$SIBLINGS_DIR/dotgithub ;;
        acdp-rs) base=. ;;
        *) continue ;;
      esac
      if [ ! -d "$base" ]; then
        case "$skipped_repos" in
          *" $repo "*) ;;
          *) echo "notice: no local checkout of $repo at $base; skipping its links" >&2
             skipped_repos="$skipped_repos$repo " ;;
        esac
        continue
      fi
      check_path "$src" "$ln" "$target" "$base/${rel:-.}" "$frag"
      continue ;;
    *:*) continue ;;   # any other scheme (http, https, mailto, ...)
  esac

  if [ -z "$path_part" ]; then continue; fi
  case "$path_part" in
    /*) resolved=".$path_part" ;;                  # repo-root relative
    *)  resolved="$(dirname -- "$src")/$path_part" ;;
  esac
  check_path "$src" "$ln" "$target" "$resolved" "$frag"
done < "$work/links.tsv"

total=$(wc -l < "$work/links.tsv" | tr -d ' ')
if [ "$broken" -gt 0 ]; then
  echo "check-doc-links: $broken broken link(s) out of $total checked in ${#files[@]} file(s)" >&2
  exit 1
fi
echo "check-doc-links: OK — $total link(s) in ${#files[@]} file(s)"
