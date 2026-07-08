#!/usr/bin/env bash
set -euo pipefail
# build/build.sh — 可复现地构建 SUN 的 Go 二进制（单个 GOOS/GOARCH）。
# Reproducible build of the SUN Go binary for one GOOS/GOARCH.
#
# 复现要点：CGO 关闭、-trimpath 抹掉本机路径、-buildid= 清空构建 ID、-s -w 去符号表，且
# GOTOOLCHAIN=local 禁止 Go 静默下载/切换工具链（工具链版本已在 go.mod 的 toolchain 指令中固定）。
# 同一工具链下两次构建应产出逐字节相同的二进制（见 reproducibility-check.sh）。
# Reproducibility: CGO off, -trimpath strips local paths, -buildid= clears the build ID, -s -w drops the
# symbol table, and GOTOOLCHAIN=local forbids Go silently downloading/switching toolchains (the version is
# pinned by the toolchain directive in go.mod). Two builds with the same toolchain are byte-identical.
#
# 用法 / Usage: build/build.sh GOOS GOARCH VERSION OUTPUT
usage() { echo "usage: build/build.sh GOOS GOARCH VERSION OUTPUT" >&2; exit 2; }
[[ $# -eq 4 ]] || usage
GOOS="$1"; GOARCH="$2"; VERSION="$3"; OUT="$4"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CGO_ENABLED=0 GOOS GOARCH GOTOOLCHAIN=local
go build -trimpath -buildvcs=false \
  -ldflags "-s -w -buildid= -X main.Version=${VERSION}" \
  -o "$OUT" ./cmd/security-update-notify
