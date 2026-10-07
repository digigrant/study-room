#!/usr/bin/env bash
# verify-checkout.sh DIR URL COMMIT TREE
#
# Proves a pinned upstream checkout is exactly what the lock manifest says
# (SPEC 10.1): the origin remote URL, the checked-out commit, the commit's
# tree hash, and a clean worktree with no modified, untracked or ignored
# files. Exits non-zero with one line per problem.
set -euo pipefail

dir=${1:?dir} url=${2:?url} commit=${3:?commit} tree=${4:?tree}
git_() { git -c safe.directory="$dir" -C "$dir" "$@"; }
problems=0
fail() { echo "verify-checkout: $dir: $*" >&2; problems=$((problems + 1)); }

[ -d "$dir/.git" ] || { echo "verify-checkout: $dir is not a git checkout" >&2; exit 1; }
actual_url=$(git_ remote get-url origin 2>/dev/null || true)
[ "$actual_url" = "$url" ] || fail "remote is '$actual_url', expected '$url'"
actual_commit=$(git_ rev-parse HEAD 2>/dev/null || true)
[ "$actual_commit" = "$commit" ] || fail "HEAD is $actual_commit, expected $commit"
actual_tree=$(git_ rev-parse 'HEAD^{tree}' 2>/dev/null || true)
[ "$actual_tree" = "$tree" ] || fail "tree is $actual_tree, expected $tree"
dirty=$(git_ status --porcelain --ignored --untracked-files=all 2>/dev/null || echo "status failed")
[ -z "$dirty" ] || fail "worktree is not clean: $(echo "$dirty" | head -5 | tr '\n' ' ')"
git_ diff --quiet HEAD -- 2>/dev/null || fail "worktree differs from HEAD"

[ "$problems" -eq 0 ] || exit 1
echo "verify-checkout: $dir ok ($commit, tree $tree)"
