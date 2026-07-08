#!/usr/bin/env bash
set -euo pipefail
# build/reproducibility-check.sh — 可复现构建门：对同一目标连续构建两次，比对 sha256 必须相等。
# 在任何签名依赖构建产物字节稳定性之前（Phase 3+），此门必须常绿；Go 工具链的静默升级会改变
# 每个产物的 sha256，这正是我们要挡住的回归。
#
# Reproducible-build gate: build the same target twice and require identical sha256. This must stay green
# before any signing depends on byte-stable artifacts (Phase 3+); a silent Go toolchain bump changes every
# artifact's sha256, which is exactly the regression this guards.
#
# 用法 / Usage: build/reproducibility-check.sh [GOOS GOARCH]   (默认 linux amd64 / defaults to linux amd64)
GOOS="${1:-linux}"; GOARCH="${2:-amd64}"; VERSION="repro-test"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

"$ROOT/build/build.sh" "$GOOS" "$GOARCH" "$VERSION" "$tmp/a"
"$ROOT/build/build.sh" "$GOOS" "$GOARCH" "$VERSION" "$tmp/b"

a="$(sha256sum "$tmp/a" | awk '{print $1}')"
b="$(sha256sum "$tmp/b" | awk '{print $1}')"
if [[ "$a" != "$b" ]]; then
  echo "NOT reproducible for $GOOS/$GOARCH: $a != $b" >&2
  exit 1
fi
echo "reproducible $GOOS/$GOARCH: $a"
