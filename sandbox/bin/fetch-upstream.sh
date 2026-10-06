#!/usr/bin/env bash
# fetch-upstream.sh URL COMMIT TREE DEST
#
# Clones exactly COMMIT from URL into DEST (SPEC 10.1): no branch or tag is
# followed, so a moved upstream ref can never change what is built. The
# checkout is verified, left unmodified, and made root-owned and read-only.
set -euo pipefail

url=${1:?url} commit=${2:?commit} tree=${3:?tree} dest=${4:?dest}
here=$(cd "$(dirname "$0")" && pwd)

[[ $url =~ ^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\.git$ ]] || { echo "fetch-upstream: unexpected URL $url" >&2; exit 1; }
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo "fetch-upstream: commit must be a full SHA-1" >&2; exit 1; }
[[ $tree =~ ^[0-9a-f]{40}$ ]] || { echo "fetch-upstream: tree must be a full SHA-1" >&2; exit 1; }
[ ! -e "$dest" ] || { echo "fetch-upstream: $dest already exists" >&2; exit 1; }

mkdir -p "$(dirname "$dest")"
git init -q "$dest"
git -C "$dest" remote add origin "$url"
GIT_TERMINAL_PROMPT=0 git -C "$dest" fetch -q --depth 1 --no-tags origin "$commit"
git -C "$dest" -c advice.detachedHead=false checkout -q --detach FETCH_HEAD
"$here/verify-checkout.sh" "$dest" "$url" "$commit" "$tree"
chown -R root:root "$dest"
chmod -R a-w "$dest"
