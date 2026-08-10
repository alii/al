#!/bin/sh
# Parses every .scrl file in the repository and fails on any parse error.
# This is the sync check between the hand-written tree-sitter grammar and the
# reference parser: anything the compiler's own corpus accepts must parse
# cleanly here too.
set -eu

cd "$(dirname "$0")"
root="$(cd ../.. && pwd)"

files=$(find "$root" -name '*.scrl' -not -path '*/target/*' -not -path '*/node_modules/*' -not -path '*/.git/*')
count=$(printf '%s\n' "$files" | wc -l | tr -d ' ')

# `tree-sitter parse -q` prints only files containing errors and exits
# non-zero if any did.
printf '%s\n' "$files" | xargs bun x tree-sitter parse -q
echo "corpus OK: $count files parsed without errors"
