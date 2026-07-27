#!/usr/bin/env python3
"""Validate the exact, reproducible security-update-notify release archive."""

from __future__ import annotations

import re
import sys
import tarfile
from pathlib import Path


VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[._-][0-9A-Za-z]+)?\Z")
COMPATIBILITY_INSTALL_SHIM = rb'''#!/bin/sh
set -eu

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  i386|i486|i586|i686) arch=386 ;;
  ppc64le) arch=ppc64le ;;
  s390x) arch=s390x ;;
  *)
    printf '%s\n' "security-update-notify 3.x does not support this architecture" >&2
    exit 2
    ;;
esac

runtime="./files/security-update-notify-linux-$arch"
if [ ! -f "$runtime" ] || [ ! -x "$runtime" ]; then
  printf '%s\n' "verified Go installer is missing for linux/$arch" >&2
  exit 1
fi
exec "$runtime" install "$@"
'''


def fail(message: str) -> None:
    raise SystemExit(f"release archive gate: {message}")


def main() -> None:
    if len(sys.argv) not in (4, 5):
        fail("usage: release-archive-test.py ARCHIVE VERSION EPOCH [SOURCE_ROOT]")

    archive = Path(sys.argv[1])
    version = sys.argv[2]
    if not VERSION_RE.fullmatch(version):
        fail(f"invalid version {version!r}")
    try:
        epoch = int(sys.argv[3])
    except ValueError:
        fail(f"invalid epoch {sys.argv[3]!r}")
    if epoch < 0:
        fail("epoch must not be negative")
    source_root = Path(sys.argv[4]).resolve() if len(sys.argv) == 5 else None

    if not archive.is_file() or archive.is_symlink():
        fail(f"archive is not a regular file: {archive}")
    size_limit = 256 * 1024 * 1024
    if not 0 < archive.stat().st_size <= size_limit:
        fail("archive size is outside the release limit")
    with archive.open("rb") as stream:
        gzip_header = stream.read(10)
    if (
        len(gzip_header) != 10
        or gzip_header[:3] != b"\x1f\x8b\x08"
        or gzip_header[3] != 0
        or gzip_header[4:8] != b"\0\0\0\0"
        or gzip_header[9] != 255
    ):
        fail("gzip header is not normalized")

    top = f"security-update-notify-{version}"
    source_modes = {
        ".env.example": 0o644,
        "CHANGELOG.md": 0o644,
        "LICENSE": 0o644,
        "README.md": 0o644,
        "README.en.md": 0o644,
        "VERSION": 0o644,
        "sun.sh": 0o755,
        "docs/development.en.md": 0o644,
        "docs/development.md": 0o644,
        "docs/go-port.md": 0o644,
        "docs/installation.en.md": 0o644,
        "docs/installation.md": 0o644,
        "docs/operations.en.md": 0o644,
        "docs/operations.md": 0o644,
        "docs/releasing.en.md": 0o644,
        "docs/releasing.md": 0o644,
        "docs/security.en.md": 0o644,
        "docs/security.md": 0o644,
        "files/needrestart-report-only.conf": 0o644,
        "files/release-signing.pub.asc": 0o644,
        "files/security-update-notify.logrotate": 0o644,
        "files/security-update-notify.service": 0o644,
    }
    elf_arches = {
        "amd64": (2, 1, 62),
        "arm64": (2, 1, 183),
        "386": (1, 1, 3),
        "ppc64le": (2, 1, 21),
        "s390x": (2, 2, 22),
    }
    file_modes = dict(source_modes)
    compatibility_modes = {
        "install.sh": 0o755,
        "files/security-update-notify": 0o644,
    }
    file_modes.update(compatibility_modes)
    for arch in elf_arches:
        file_modes[f"files/security-update-notify-linux-{arch}"] = 0o755
    directory_modes = {"": 0o755, "docs": 0o755, "files": 0o755}
    # tarfile normalizes a directory header's trailing slash while preserving
    # internal path spelling, so compare its canonical member names directly.
    expected = {
        top if not relative else f"{top}/{relative}" for relative in directory_modes
    }
    expected.update(f"{top}/{relative}" for relative in file_modes)

    with tarfile.open(archive, mode="r:gz") as bundle:
        members = bundle.getmembers()
        names = [member.name for member in members]
        if names != sorted(expected):
            missing = sorted(expected - set(names))
            extra = sorted(set(names) - expected)
            fail(
                "archive allowlist/order mismatch; "
                f"missing={missing}, extra={extra}, entries={len(names)}"
            )
        regular_members = [member for member in members if member.isfile()]
        declared_size = sum(member.size for member in regular_members)
        if any(member.size < 0 for member in regular_members) or declared_size > size_limit:
            fail("declared uncompressed size is outside the release limit")

        for member, name in zip(members, names):
            relative = name[len(top) :].strip("/")
            if member.uid != 0 or member.gid != 0 or member.uname or member.gname:
                fail(f"non-normalized ownership metadata: {name}")
            if member.mtime != epoch:
                fail(f"non-reproducible timestamp for {name}: {member.mtime} != {epoch}")
            if relative in directory_modes:
                if (
                    not member.isdir()
                    or member.size != 0
                    or member.mode & 0o7777 != directory_modes[relative]
                ):
                    fail(f"invalid directory type or mode: {name}")
                continue
            if not member.isfile() or member.mode & 0o7777 != file_modes[relative]:
                fail(f"invalid file type or mode: {name}")
            extracted = bundle.extractfile(member)
            if extracted is None:
                fail(f"could not read regular file: {name}")
            data = extracted.read()
            if source_root is not None and relative in source_modes:
                source = source_root / relative
                if source.is_symlink() or not source.is_file() or data != source.read_bytes():
                    fail(f"packaged source differs from repository: {relative}")
            if relative == "VERSION" and data != f'VERSION="{version}"\n'.encode("ascii"):
                fail("packaged VERSION is not bound to the release version")
            if relative == "install.sh" and data != COMPATIBILITY_INSTALL_SHIM:
                fail("generated 2.x compatibility installer content changed")
            if relative == "files/security-update-notify" and data != f'VERSION="{version}"\n'.encode("ascii"):
                fail("generated 2.x compatibility marker is not bound to the release version")
            if relative.startswith("files/security-update-notify-linux-"):
                arch = relative.rsplit("-", 1)[1]
                if len(data) < 20 or data[:4] != b"\x7fELF":
                    fail(f"{arch} runtime is not ELF")
                elf_class, elf_data, machine = elf_arches[arch]
                byte_order = "little" if elf_data == 1 else "big"
                actual = (data[4], data[5], int.from_bytes(data[18:20], byte_order))
                if actual != (elf_class, elf_data, machine):
                    fail(f"wrong ELF identity for {arch}: {actual}")

    print(f"release archive allowlist and metadata OK: {archive}")


if __name__ == "__main__":
    main()
