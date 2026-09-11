"""Open a pty of a given size, run a command in it, and let the size change.

Not named pty.py: that shadows the standard library module this imports.

Python's pty.spawn() is two lines shorter but takes its window size from its own
stdin. The agent's stdin is a pipe, so the shell would start at the default
80x24 and stay there no matter how big the car's screen is -- and tmux cannot
fix it from the outside, because `refresh-client -C` only applies to control
mode clients.

So: set TIOCSWINSZ on the pty directly. New sizes arrive on fd 3 as "COLSxROWS"
lines, one per resize, which keeps them out of the terminal stream where they
would be indistinguishable from what the user typed.

Usage: terminal.py <command> <cols> <rows>
"""
import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import threading

command, cols, rows = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

pid, fd = pty.fork()
if pid == 0:
    os.execv("/bin/sh", ["/bin/sh", "-c", command])


def set_size(c, r):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", r, c, 0, 0))
    # The shell is already running, so it only learns about the new size from
    # the signal. Without this the pty is resized and nothing redraws.
    os.kill(pid, signal.SIGWINCH)


set_size(cols, rows)


def control():
    for line in os.fdopen(3):
        try:
            c, r = line.strip().split("x")
            set_size(int(c), int(r))
        except (ValueError, OSError):
            pass  # A malformed size is not worth killing the session over.


threading.Thread(target=control, daemon=True).start()

while True:
    try:
        ready, _, _ = select.select([fd, 0], [], [])
    except (InterruptedError, OSError):
        break
    try:
        if fd in ready:
            data = os.read(fd, 65536)
            if not data:
                break
            os.write(1, data)
        if 0 in ready:
            data = os.read(0, 65536)
            if not data:
                break
            os.write(fd, data)
    except OSError:
        break

os.close(fd)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
