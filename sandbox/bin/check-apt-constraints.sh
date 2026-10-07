#!/usr/bin/env bash
# check-apt-constraints.sh NAME:OP:VERSION...
# Fails unless every installed package satisfies its lock-manifest constraint.
set -euo pipefail
status=0
for spec in "$@"; do
  IFS=: read -r name op version <<<"$spec"
  installed=$(dpkg-query -W -f='${Version}' "$name" 2>/dev/null || true)
  if [ -z "$installed" ]; then
    echo "check-apt-constraints: $name is not installed" >&2; status=1; continue
  fi
  case "$op" in
    '>=') rel=ge ;; '=') rel=eq ;; '<=') rel=le ;; '>') rel=gt ;; '<') rel=lt ;;
    *) echo "check-apt-constraints: bad operator in $spec" >&2; status=1; continue ;;
  esac
  if [ "$rel" = eq ]; then
    case "$installed" in "$version"|"$version"-*|"$version"~*) ;; *) echo "check-apt-constraints: $name $installed is not $version" >&2; status=1 ;; esac
  elif ! dpkg --compare-versions "$installed" "$rel" "$version"; then
    echo "check-apt-constraints: $name $installed does not satisfy $op $version" >&2; status=1
  fi
done
exit "$status"
