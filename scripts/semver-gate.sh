#!/usr/bin/env bash
# Decide whether a cargo-semver-checks result blocks the build
# (COMPATIBILITY.md, "How a breaking change ships").
#
# Usage: STATUS=<exit code> VERSION=<workspace version> \
#        [PR_TITLE=<title>] [PR_LABELS_JSON=<json array>] scripts/semver-gate.sh
#
# Run from the repository root with full history and tags (the CI checkout
# uses fetch-depth: 0). Exit codes from cargo-semver-checks:
#   0   no semver-incompatible change: pass.
#   100 a break was found: pass only if the break is declared (below).
#   any other: the tool failed. Fail closed; semver-tool-health says why.
#
# A break is declared when any of these holds:
#   - PR_TITLE is a Conventional Commit with a `!` (`feat!:`, `fix(x)!:`).
#     A squash merge lands the title on main, and release-plz bumps the
#     minor (0.x) from it.
#   - A commit since the last release tag (acdp-v$VERSION) has a `!`
#     subject or a `BREAKING CHANGE:` footer. Without this, every PR after
#     a declared break would go red until the release PR merges, because
#     cargo-semver-checks compares the whole tree against crates.io, not
#     against main.
#   - The PR has the `semver-checks-override` label. Only for a verified
#     false positive (for example an item moved to another crate and
#     re-exported at the same path, which the tool reports as removed).
#     The PR description must say why.
set -euo pipefail

status="${STATUS:?STATUS is required}"
version="${VERSION:?VERSION is required}"
override_label="semver-checks-override"
breaking_subject='^[A-Za-z]+(\([^)]*\))?!:'
breaking_footer='^BREAKING[ -]CHANGE:'

case "$status" in
    0)
        echo "cargo-semver-checks: no semver-incompatible change."
        exit 0
        ;;
    100) ;;
    *)
        echo "::error::cargo-semver-checks exited with status $status: the tool failed, so no API verdict exists. Failing closed; see the semver-tool-health job."
        exit 1
        ;;
esac

if [ -n "${PR_TITLE:-}" ] && printf '%s\n' "$PR_TITLE" | grep -Eq "$breaking_subject"; then
    echo "::warning::Breaking API change declared by the PR title. The next release must bump the minor version (0.x); release-plz does this from the title."
    exit 0
fi

if [ -n "${PR_LABELS_JSON:-}" ] &&
    printf '%s' "$PR_LABELS_JSON" | jq -e --arg l "$override_label" 'any(.[]?; . == $l)' >/dev/null; then
    echo "::warning::'$override_label' label set: this break is treated as a verified false positive. The PR description must say why."
    exit 0
fi

tag="acdp-v$version"
if ! git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    echo "::error::Release tag $tag not found, so already-declared breaks cannot be checked. Fetch tags (fetch-depth: 0) or fix the version."
    exit 1
fi
if git log --format='%s%n%b' "$tag..HEAD" | grep -Eq "$breaking_subject|$breaking_footer"; then
    echo "::warning::A commit since $tag already declares a breaking change, so the next release bumps the minor version. Make sure that release's notes cover this change too."
    exit 0
fi

cat <<EOF
::error::cargo-semver-checks found a semver-incompatible change that is not declared.
Either:
  - remove the break (see COMPATIBILITY.md for what counts), or
  - declare it: retitle the PR as a Conventional Commit with '!' (for example 'feat(client)!: ...').
    Use feat! or fix!, because release-plz only releases feat/fix/perf commits.
    Add a migration note to CHANGELOG.md / docs, or
  - if the report is a verified false positive, add the '$override_label' label and say why in the PR description.
EOF
exit 1
