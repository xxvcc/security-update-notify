#!/usr/bin/env python3
"""Drive a command through a real PTY, synchronizing each response to a prompt."""

import argparse
import errno
import fcntl
import os
import pty
import select
import signal
import subprocess
import sys
import termios
import time


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument(
        "--step",
        action="append",
        nargs=3,
        metavar=("KIND", "PROMPT", "RESPONSE"),
        default=[],
        help="KIND is visible, hidden, or eof",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("missing command after --")
    for kind, _, _ in args.step:
        if kind not in {"visible", "hidden", "eof"}:
            parser.error(f"invalid step kind: {kind}")
    return args


def child_setup(slave_fd):
    os.setsid()
    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)


def terminate(proc):
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def main():
    args = parse_args()
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        args.command,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        preexec_fn=lambda: child_setup(slave_fd),
    )
    os.close(slave_fd)
    output = bytearray()
    cursor = 0
    deadline = time.monotonic() + args.timeout

    def read_once():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("PTY scenario timed out")
        ready, _, _ = select.select([master_fd], [], [], min(0.2, remaining))
        if not ready:
            return True
        try:
            chunk = os.read(master_fd, 65536)
        except OSError as exc:
            if exc.errno == errno.EIO:
                return False
            raise
        if not chunk:
            return False
        output.extend(chunk)
        return True

    try:
        for kind, prompt, response in args.step:
            needle = prompt.encode("utf-8")
            while True:
                index = output.find(needle, cursor)
                if index >= 0:
                    cursor = index + len(needle)
                    break
                if proc.poll() is not None or not read_once():
                    raise RuntimeError(f"process exited before prompt: {prompt!r}")

            if kind in {"visible", "hidden"}:
                want_echo = kind == "visible"
                echo_deadline = min(deadline, time.monotonic() + 3)
                while bool(termios.tcgetattr(master_fd)[3] & termios.ECHO) != want_echo:
                    if time.monotonic() >= echo_deadline:
                        state = "enabled" if want_echo else "disabled"
                        raise RuntimeError(
                            f"terminal echo did not become {state} at {kind} prompt: {prompt!r}"
                        )
                    time.sleep(0.01)

            payload = b"\x04" if kind == "eof" else response.encode("utf-8")
            os.write(master_fd, payload)

        while proc.poll() is None:
            read_once()
        while read_once():
            pass
        return_code = proc.wait()
    except Exception as exc:  # noqa: BLE001 - test driver must retain all diagnostics
        terminate(proc)
        print(f"PTY driver: {exc}", file=sys.stderr)
        return_code = 125
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass
        with open(args.output, "wb") as capture:
            capture.write(output)

    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
