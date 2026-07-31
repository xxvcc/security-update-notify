#!/usr/bin/env python3
"""Regression test for PTY process-group cleanup after leader exit."""

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


CHILD = r"""
import os
import signal
import sys

ready, terminated = sys.argv[1:]

def stop(_signum, _frame):
    with open(terminated, "w", encoding="ascii") as marker:
        marker.write("terminated\n")
    raise SystemExit(0)

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGHUP, signal.SIG_IGN)
with open(ready, "w", encoding="ascii") as marker:
    marker.write(f"{os.getpid()} {os.getpgrp()}\n")
while True:
    signal.pause()
"""


LEADER = r"""
from pathlib import Path
import subprocess
import sys
import time

ready, terminated, child = sys.argv[1:]
subprocess.Popen([sys.executable, "-I", "-c", child, ready, terminated])
deadline = time.monotonic() + 5
while not Path(ready).exists():
    if time.monotonic() >= deadline:
        raise SystemExit("descendant did not start")
    time.sleep(0.01)
"""


def process_running(pid):
    try:
        state = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()[2]
    except FileNotFoundError:
        return False
    return state != "Z"


def main():
    driver = Path(__file__).with_name("pty-driver.py")
    with tempfile.TemporaryDirectory(prefix="sun-pty-driver-test-") as temporary:
        root = Path(temporary)
        ready = root / "ready"
        terminated = root / "terminated"
        output = root / "output"
        group_id = None
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(driver),
                    "--output",
                    str(output),
                    "--timeout",
                    "0.5",
                    "--",
                    sys.executable,
                    "-I",
                    "-c",
                    LEADER,
                    str(ready),
                    str(terminated),
                    CHILD,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if result.returncode != 125 or b"PTY scenario timed out" not in result.stderr:
                raise AssertionError(
                    f"driver returned {result.returncode}; stderr={result.stderr!r}"
                )
            pid, group_id = map(int, ready.read_text(encoding="ascii").split())
            if not terminated.exists():
                raise AssertionError("descendant process group did not receive SIGTERM")
            deadline = time.monotonic() + 2
            while process_running(pid) and time.monotonic() < deadline:
                time.sleep(0.01)
            if process_running(pid):
                raise AssertionError("descendant survived PTY driver cleanup")
        finally:
            if group_id is None and ready.exists():
                _, group_id = map(int, ready.read_text(encoding="ascii").split())
            if group_id is not None:
                try:
                    os.killpg(group_id, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    print("PTY process-group cleanup test passed")


if __name__ == "__main__":
    main()
