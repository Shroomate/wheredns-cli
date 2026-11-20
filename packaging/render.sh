#!/bin/sh
# Renders a packaging template from a release's SHA256SUMS.
# Usage: packaging/render.sh VERSION SHA256SUMS TEMPLATE > OUTPUT
set -eu
version=$1 sums=$2 template=$3
script="s/@VERSION@/$version/g"
while read -r hash file; do
  target=${file#wheredns-v"$version"-}
  target=${target%.tar.gz}
  target=${target%.zip}
  script="$script;s/@SHA_${target}@/$hash/g"
done < "$sums"
out=$(sed "$script" "$template")
if printf '%s\n' "$out" | grep -q '@[A-Za-z0-9_-]*@'; then
  echo "render.sh: unfilled tokens in $template" >&2
  exit 1
fi
printf '%s\n' "$out"
