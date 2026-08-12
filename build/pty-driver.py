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
import struct
import sys
import termios
import time


MAX_OUTPUT_BYTES = 8 << 20
DEFAULT_ROWS = 24
DEFAULT_COLUMNS = 80


def positive_timeout(value):
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not 0 < timeout <= 3600 or not timeout < float("inf"):
        raise argparse.ArgumentTypeError("timeout must be finite and in (0, 3600]")
    return timeout


def terminal_dimension(value):
    try:
        dimension = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("terminal dimension must be an integer") from exc
    if not 1 <= dimension <= 1000:
        raise argparse.ArgumentTypeError("terminal dimension must be in [1, 1000]")
    return dimension


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=positive_timeout, default=180.0)
    parser.add_argument("--rows", type=terminal_dimension, default=DEFAULT_ROWS)
    parser.add_argument("--columns", type=terminal_dimension, default=DEFAULT_COLUMNS)
    parser.add_argument(
        "--step",
        action="append",
        nargs=3,
        metavar=("KIND", "PROMPT", "RESPONSE"),
        default=[],
        help="KIND is visible, hidden, eof, or interrupt",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("missing command after --")
    for kind, _, _ in args.step:
        if kind not in {"visible", "hidden", "eof", "interrupt"}:
            parser.error(f"invalid step kind: {kind}")
    return args


def child_setup(slave_fd):
    os.setsid()
    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)


def process_group_exists(group_id):
    try:
        os.killpg(group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def terminate(proc):
    # The session leader may have exited while a descendant still holds the PTY.
    # Signal and observe the process group itself instead of using leader state as
    # a proxy for group lifetime.
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        proc.wait()
        return

    grace_deadline = time.monotonic() + 2
    while process_group_exists(proc.pid) and time.monotonic() < grace_deadline:
        proc.poll()
        time.sleep(0.01)
    if process_group_exists(proc.pid):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def main():
    args = parse_args()
    master_fd, slave_fd = pty.openpty()
    fcntl.ioctl(
        slave_fd,
        termios.TIOCSWINSZ,
        struct.pack("HHHH", args.rows, args.columns, 0, 0),
    )
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
        if len(output) + len(chunk) > MAX_OUTPUT_BYTES:
            remaining = MAX_OUTPUT_BYTES - len(output)
            output.extend(chunk[:remaining])
            raise RuntimeError(f"PTY output exceeded {MAX_OUTPUT_BYTES} bytes")
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

            if kind in {"visible", "hidden", "interrupt"}:
                want_echo = kind != "hidden"
                echo_deadline = min(deadline, time.monotonic() + 3)
                while bool(termios.tcgetattr(master_fd)[3] & termios.ECHO) != want_echo:
                    if time.monotonic() >= echo_deadline:
                        state = "enabled" if want_echo else "disabled"
                        raise RuntimeError(
                            f"terminal echo did not become {state} at {kind} prompt: {prompt!r}"
                        )
                    time.sleep(0.01)

            if kind == "eof":
                payload = b"\x04"
            elif kind == "interrupt":
                payload = b"\x03"
            else:
                payload = response.encode("utf-8")
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

    if return_code < 0:
        return 128 - return_code
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
