#!/usr/bin/env bash
# Writes skip=true|false to $GITHUB_OUTPUT. See action.yml for the inputs.
#
# Any doubt means skip=false, so the release goes ahead: an unreachable registry
# must not lose a release, and PyPI and npm both refuse to overwrite a published
# version, so the worst case is a wasted build or a red run, not a double publish.
set -euo pipefail

skip=false
finish() {
  echo "skip=$skip" >>"$GITHUB_OUTPUT"
  exit 0
}

VER="${INPUT_VERSION:-${GITHUB_REF_NAME#"$TAG_PREFIX"}}"

if [ "$DRY_RUN" = "true" ]; then
  echo "dry run: always build"
  finish
fi

# Rejects a bare ref name such as "main" before it reaches a URL.
if ! [[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+.][0-9A-Za-z.+-]+)?$ ]]; then
  echo "::warning::'$VER' is not a version; not checking the registry"
  finish
fi

case "$REGISTRY" in
  pypi)
    # A PyPI release is several uploads, so "the version exists" is not enough:
    # a partial upload has to go on to the publish job to be completed.
    body="$(curl -fsSL --retry 3 --max-time 30 "https://pypi.org/pypi/$PACKAGE/$VER/json" 2>/dev/null || true)"
    files="$(printf '%s' "$body" | jq -r '.urls | length' 2>/dev/null || true)"
    files="${files:-0}"
    echo "PyPI has $files file(s) for $PACKAGE $VER (a complete release has $MIN_FILES)"
    [ "$files" -ge "$MIN_FILES" ] || finish
    ;;
  npm)
    # `npm view` exits non-zero both for a missing version and for a registry
    # error, and either way nothing is known to be published.
    published="$(npm view "$PACKAGE@$VER" version 2>/dev/null || true)"
    echo "npm serves '$published' for $PACKAGE@$VER"
    [ "$published" = "$VER" ] || finish
    # The Node root still publishes when its platform packages fail, so the root
    # alone doesn't prove the release is complete. Rerunning retries them.
    deps="$(npm view "$PACKAGE@$VER" optionalDependencies --json 2>/dev/null || true)"
    for dep in $(printf '%s' "$deps" | jq -r 'select(type == "object" and (has("error") | not)) | keys[]' 2>/dev/null || true); do
      if [ "$(npm view "$dep@$VER" version 2>/dev/null || true)" != "$VER" ]; then
        echo "$dep@$VER is missing, so the release is incomplete"
        finish
      fi
    done
    ;;
  *)
    echo "::error::unknown registry '$REGISTRY'"
    exit 1
    ;;
esac

skip=true
echo "$PACKAGE $VER is already published; skipping the release"

# The tag is what release-plz.yml reconciles on, so a release that published but
# failed to tag would otherwise be dispatched again on every push to main.
TAG="$TAG_PREFIX$VER"
if ! git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null; then
  echo "tagging $TAG, which an earlier run published but did not tag"
  git config user.name "github-actions[bot]"
  git config user.email "github-actions[bot]@users.noreply.github.com"
  git tag -a "$TAG" -m "$TAG"
  git push origin "$TAG"
fi
finish
