#!/bin/bash
# shot.sh page.html out.png: screenshot a page at 2x, cut out the #ff00ff
# backdrop and add a drop shadow on a transparent background.
CH=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
[ -x "$CH" ] || CH=$(command -v google-chrome || command -v chromium)
"$CH" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=2 --window-size=1100,3000 --screenshot="$2.raw.png" "file://$1" >/dev/null 2>&1
magick "$2.raw.png" -bordercolor '#ff00ff' -border 2 -fuzz 2% -trim +repage -alpha set -fuzz 18% -fill none -draw "alpha 0,0 floodfill" -draw "alpha %[fx:w-1],0 floodfill" -draw "alpha 0,%[fx:h-1] floodfill" -draw "alpha %[fx:w-1],%[fx:h-1] floodfill" -shave 1x1 "$2.win.png"
magick "$2.win.png" \( +clone -background black -shadow 55x24+0+18 \) +swap -background none -layers merge +repage -bordercolor none -border 8 -trim +repage -bordercolor none -border 24 "$2"
rm -f "$2.raw.png" "$2.win.png"
