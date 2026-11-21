# capture.py COLS ROWS OUT CMD...: run CMD in a pseudo-terminal of the given
# size and save its raw output (with color escapes) to OUT.
import os, pty, sys, struct, fcntl, termios, select, subprocess
cols, rows, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
args = sys.argv[4:]
pid, fd = pty.fork()
if pid == 0:
    os.environ['TERM'] = 'xterm-256color'
    os.environ['COLORTERM'] = 'truecolor'
    os.environ.pop('NO_COLOR', None)
    os.execvp(args[0], args)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
buf = b''
while True:
    try:
        r, _, _ = select.select([fd], [], [], 90)
        if not r: break
        d = os.read(fd, 65536)
        if not d: break
        buf += d
    except OSError:
        break
os.waitpid(pid, 0)
open(out, 'wb').write(buf)
