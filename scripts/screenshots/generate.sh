#!/bin/bash
# Regenerates docs/images from live wheredns runs.
# Needs: macOS or Linux, python3, Google Chrome, ImageMagick 7 (magick).
# Results reflect the network at the time of capture.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out="$root/docs/images"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cargo build --release --locked --manifest-path "$root/Cargo.toml" >/dev/null
bin="$root/target/release/wheredns"

cap() { # name cols title -- args...
  local name=$1 cols=$2 title=$3 lines=${4:-}
  shift 4
  python3 "$here/capture.py" "$cols" 60 "$work/$name.ansi" "$bin" "$@" --animate off
  python3 "$here/render.py" "$work/$name.ansi" "$work/$name.html" "$title" $lines
  "$here/shot.sh" "$work/$name.html" "$work/$name.png"
}

cap hero 100 "wheredns cloudflare.com where ping web" "" cloudflare.com where ping web --theme btop
cap email 100 "wheredns google.com email" "" google.com email --theme btop
cap dns 100 "wheredns example.com dns A AAAA MX NS TXT propagation" "" example.com dns A AAAA MX NS TXT propagation --theme btop
cap ip 100 "wheredns 8.8.8.8 ip blacklist ports" "" 8.8.8.8 ip blacklist ports --theme btop
python3 "$here/capture.py" 100 60 "$work/headers.ansi" bash -c "'$bin' headers --theme btop --animate off < '$root/tests/fixtures/invoice.eml'"
python3 "$here/render.py" "$work/headers.ansi" "$work/headers.html" "pbpaste | wheredns headers"
"$here/shot.sh" "$work/headers.html" "$work/headers.png"

# One theme per run, sequentially, to stay under RDAP rate limits.
for t in btop tty purple phosphor amber; do
  python3 "$here/capture.py" 84 40 "$work/theme-$t.ansi" "$bin" github.com where --theme "$t" --animate off
  n=$(sed $'s/\x1b\\[[0-9;]*m//g' "$work/theme-$t.ansi" | grep -n '╰' | head -1 | cut -d: -f1)
  python3 "$here/render.py" "$work/theme-$t.ansi" "$work/theme-$t.html" "wheredns github.com where --theme $t" "$n"
  "$here/shot.sh" "$work/theme-$t.html" "$work/theme-$t.png"
  sleep 3
done
w=$work
magick \( $w/theme-btop.png $w/theme-phosphor.png +append \) \( $w/theme-tty.png $w/theme-purple.png +append \) \
  \( $w/theme-amber.png \) -background none -gravity center -append +repage "$work/themes.png"
"$here/shot.sh" "$here/banner.html" "$work/banner.png"

for f in banner hero email dns ip headers themes; do cp "$work/$f.png" "$out/$f.png"; done
echo "updated $out"
