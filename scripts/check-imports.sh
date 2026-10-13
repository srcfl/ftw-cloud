#!/usr/bin/env bash
# FTW Cloud may import the wire format from srcfl/ftw and nothing else of it.
# go/protocol imports nothing from the box (srcfl/ftw checks that), so this
# keeps every line of control, planner and storage code out of this build.

set -euo pipefail

reached=$(go list -deps -test -f '{{.ImportPath}}' ./... | awk '
  $1 ~ /^github\.com\/srcfl\/ftw\// &&
  $1 !~ /^github\.com\/srcfl\/ftw\/go\/protocol(\/|$)/ { print $1 }
' | sort -u)

if [ -n "${reached}" ]; then
  echo "ftw-cloud may import only github.com/srcfl/ftw/go/protocol. It reaches:" >&2
  printf '%s\n' "${reached}" >&2
  exit 1
fi

echo "ftw-cloud: only go/protocol from srcfl/ftw ($(go list -deps ./... | grep -c '^github.com/srcfl/ftw/') packages)"
