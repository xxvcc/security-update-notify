#!/usr/bin/env python3
"""Verify the same single-record SHA-256 protocol accepted by release clients."""

import hashlib
import os
import re
import sys
from pathlib import Path


def verify(archive, manifest):
    name = os.fsencode(archive.name)
    record_size = 64 + 2 + len(name) + 1
    with manifest.open("rb") as stream:
        record = stream.read(record_size + 1)
    match = re.fullmatch(rb"([0-9A-Fa-f]{64})  " + re.escape(name) + rb"\n", record)
    if match is None:
        raise ValueError("Invalid checksum file: expected exactly one record for " + archive.name)

    expected = match.group(1).decode("ascii").lower()
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ValueError("release checksum mismatch: " + archive.name)
    return expected


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify-checksum.py ARCHIVE MANIFEST")
    try:
        print(verify(Path(sys.argv[1]), Path(sys.argv[2])))
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
