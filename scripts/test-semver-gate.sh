#!/usr/bin/env bash
# Self-tests for scripts/semver-gate.sh.
#
# Usage: scripts/test-semver-gate.sh
#
# Builds a scratch git repo with a release tag and checks every pass/fail
# branch of the gate. The real repository is never touched. Requires git
# and jq (as the gate does).
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
gate="$script_dir/semver-gate.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0
failed=0

# expect <want-exit> <description> [VAR=value ...]
expect() {
    local want=$1 desc=$2
    shift 2
    local got=0
    (cd "$tmp/repo" && env "$@" bash "$gate") >"$tmp/out" 2>&1 || got=$?
    if [ "$got" -eq "$want" ]; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        echo "FAIL: $desc (want exit $want, got $got)"
        sed 's/^/    /' "$tmp/out"
    fi
}

git init -q "$tmp/repo"
commit() { git -C "$tmp/repo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m "$1"; }
commit "chore: release v1.2.3"
git -C "$tmp/repo" tag acdp-v1.2.3
commit "fix(client): ordinary fix"

expect 0 "clean result passes" STATUS=0 VERSION=1.2.3
expect 1 "tool error fails closed" STATUS=101 VERSION=1.2.3
expect 1 "abnormal exit fails closed" STATUS=137 VERSION=1.2.3
expect 1 "undeclared break fails" STATUS=100 VERSION=1.2.3 PR_TITLE="feat(client): add thing"
expect 1 "'!' outside the type prefix is not a declaration" STATUS=100 VERSION=1.2.3 PR_TITLE="feat: wow!: really"
expect 0 "PR title with ! passes" STATUS=100 VERSION=1.2.3 PR_TITLE="feat(client)!: drop thing"
expect 0 "PR title with ! and no scope passes" STATUS=100 VERSION=1.2.3 PR_TITLE="fix!: drop thing"
expect 1 "unrelated label does not pass" STATUS=100 VERSION=1.2.3 PR_LABELS_JSON='["release"]'
expect 0 "override label passes" STATUS=100 VERSION=1.2.3 PR_LABELS_JSON='["release","semver-checks-override"]'
expect 1 "null labels (push event) do not pass" STATUS=100 VERSION=1.2.3 PR_LABELS_JSON='null'
expect 1 "missing release tag fails" STATUS=100 VERSION=9.9.9

commit "chore: release v1.2.4"
git -C "$tmp/repo" tag acdp-v1.2.4
commit "$(printf 'refactor(types): rename\n\nBREAKING CHANGE: Foo is now Bar')"
expect 0 "BREAKING CHANGE footer since the tag passes" STATUS=100 VERSION=1.2.4

commit "chore: release v1.2.5"
git -C "$tmp/repo" tag acdp-v1.2.5
commit "feat(server)!: change store trait"
expect 0 "! subject since the tag passes" STATUS=100 VERSION=1.2.5
commit "chore: release v1.2.6"
git -C "$tmp/repo" tag acdp-v1.2.6
commit "fix: later"
expect 1 "a declaration before the current tag does not count" STATUS=100 VERSION=1.2.6

echo "semver-gate self-test: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
