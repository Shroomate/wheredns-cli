# render.py IN.ansi OUT.html TITLE [MAX_LINES]
# Converts truecolor SGR output into an HTML page styled as a terminal window.
import re, sys, html
src, out, title = sys.argv[1], sys.argv[2], sys.argv[3]
maxlines = int(sys.argv[4]) if len(sys.argv) > 4 else 10**9
data = open(src, 'rb').read().decode('utf-8', 'replace').replace('\r\n', '\n').replace('\r', '')
lines = data.split('\n')
while lines and not re.sub(r'\x1b\[[0-9;]*m', '', lines[-1]).strip(): lines.pop()
lines = lines[:maxlines]
bg_default = None
def parse(line):
    st = {'fg': None, 'bg': None, 'b': False, 'd': False, 'i': False, 'u': False}
    spans = []
    for part in re.split(r'(\x1b\[[0-9;]*m)', line):
        m = re.fullmatch(r'\x1b\[([0-9;]*)m', part)
        if m:
            p = [int(x) if x else 0 for x in m.group(1).split(';')] or [0]
            i = 0
            while i < len(p):
                c = p[i]
                if c == 0: st = {'fg': None, 'bg': None, 'b': False, 'd': False, 'i': False, 'u': False}
                elif c == 1: st['b'] = True
                elif c == 2: st['d'] = True
                elif c == 3: st['i'] = True
                elif c == 4: st['u'] = True
                elif c == 22: st['b'] = st['d'] = False
                elif c in (38, 48) and i + 4 < len(p) + 0 and p[i+1] == 2:
                    st['fg' if c == 38 else 'bg'] = '#%02x%02x%02x' % tuple(p[i+2:i+5]); i += 4
                elif c == 39: st['fg'] = None
                elif c == 49: st['bg'] = None
                i += 1
        elif part:
            spans.append((dict(st), part))
    return spans
body = []
for ln in lines:
    row = []
    for st, txt in parse(ln):
        css = []
        if st['fg']: css.append('color:' + st['fg'])
        if st['bg']: css.append('background:' + st['bg'])
        if st['b']: css.append('font-weight:700')
        if st['d']: css.append('opacity:.6')
        if st['i']: css.append('font-style:italic')
        if st['u']: css.append('text-decoration:underline')
        if st['bg'] and not bg_default: bg_default = st['bg']
        row.append('<span style="%s">%s</span>' % (';'.join(css), html.escape(txt)))
    body.append(''.join(row) or ' ')
bg = bg_default or '#000'
page = f'''<!doctype html><html><head><meta charset="utf-8"><style>
html,body{{margin:0;background:#ff00ff}}
.wrap{{padding:0;display:inline-block}}
.win{{background:{bg};border-radius:11px;overflow:hidden;box-shadow:inset 0 0 0 1px rgba(255,255,255,.10);display:inline-block}}
.bar{{height:34px;background:#1c1d21;display:flex;align-items:center;padding:0 14px;position:relative;border-bottom:1px solid #000}}
.dot{{width:12px;height:12px;border-radius:50%;margin-right:8px}}
.t{{position:absolute;left:0;right:0;text-align:center;color:#9a9ca3;font:500 13px -apple-system,BlinkMacSystemFont,sans-serif}}
pre{{margin:0;padding:14px 18px 18px;font:13.5px/1.17 Menlo,monospace;color:#e0e0e0;font-variant-ligatures:none}}
</style></head><body><div class="wrap"><div class="win"><div class="bar"><span class="dot" style="background:#ff5f57"></span><span class="dot" style="background:#febc2e"></span><span class="dot" style="background:#28c840"></span><div class="t">{html.escape(title)}</div></div><pre>{chr(10).join(body)}</pre></div></div></body></html>'''
open(out, 'w').write(page)
