#!/usr/bin/env bash
set -euo pipefail

# security-update-notify 引导安装器。
# Bootstrap installer for security-update-notify.
# 可将此脚本发布到你的网站，例如 https://example.com/install/sun.sh
# Publish this script on your website, e.g. https://example.com/install/sun.sh

REPO="${SECURITY_UPDATE_NOTIFY_REPO:-xxvcc/security-update-notify}"
VERSION="${SECURITY_UPDATE_NOTIFY_VERSION:-latest}"
BASE_URL="${SECURITY_UPDATE_NOTIFY_BASE_URL:-}"
RUN_MODE="menu"
INSTALL_ARGS=()

usage() {
  cat <<'EOF'
用法 / Usage:
  curl -fsSL https://example.com/install/sun.sh | sudo bash
  curl -fsSL https://example.com/install/sun.sh | sudo bash -s -- install [安装参数 / install args]

引导选项 / Bootstrap options:
  --version VERSION       发布版本，例如 1.1.0；默认 latest / Release version, e.g. 1.1.0. Default: latest
  --repo OWNER/REPO       GitHub 仓库；默认来自脚本配置 / GitHub repo. Default from script config
  --base-url URL          覆盖下载基础 URL / Override download base URL
  install                 下载后运行 install.sh / Run install.sh after download
  test                    下载后运行 test.sh / Run test.sh after download
  uninstall               下载后运行 uninstall.sh / Run uninstall.sh after download
  menu                    下载后运行 menu.sh（默认）/ Run menu.sh after download (default)

其余所有选项都会传递给选中的脚本。
All remaining options are passed to the selected script.
EOF
}

require_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || { echo "缺少 $1 的值 / Missing value for $1" >&2; exit 2; }; }
validate_version() { [[ "$1" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || { echo "无效版本 / Invalid VERSION: $1" >&2; exit 2; }; }

verify_checksum() {
  local file="$1" sha_file="$2" expected
  expected="$(awk 'NF {print $1; exit}' "$sha_file")"
  [[ "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || { echo "无效校验文件 / Invalid checksum file: $SHA_URL" >&2; exit 1; }
  printf '%s  %s\n' "$expected" "$file" | sha256sum -c -
}

safe_extract_tar() {
  local archive="$1" topdir="$2" entry listing_type
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    case "$entry" in
      /*|../*|*/../*|*/..|..)
        echo "压缩包中存在不安全路径 / Unsafe path in archive: $entry" >&2
        exit 1
        ;;
    esac
    case "$entry" in
      "$topdir"|"$topdir/"|"$topdir"/*) ;;
      *)
        echo "压缩包中存在非预期路径 / Unexpected path in archive: $entry" >&2
        exit 1
        ;;
    esac
  done < <(tar -tzf "$archive")
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    listing_type="${entry:0:1}"
    case "$listing_type" in
      -|d) ;;
      *)
        echo "压缩包中存在不支持的条目类型 / Unsupported archive entry type: $entry" >&2
        exit 1
        ;;
    esac
  done < <(tar -tzvf "$archive")
  tar --no-same-owner -xzf "$archive"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) require_arg "$1" "${2:-}"; VERSION="$2"; shift 2 ;;
    --repo) require_arg "$1" "${2:-}"; REPO="$2"; shift 2 ;;
    --base-url) require_arg "$1" "${2:-}"; BASE_URL="$2"; shift 2 ;;
    install|test|uninstall|menu) RUN_MODE="$1"; shift; INSTALL_ARGS+=("$@"); break ;;
    -h|--help) usage; exit 0 ;;
    *) INSTALL_ARGS+=("$1"); shift ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "请使用 sudo/root 运行 / Please run with sudo/root" >&2; exit 1; }
for c in curl tar sha256sum mktemp python3; do command -v "$c" >/dev/null 2>&1 || { echo "缺少必需命令 / Missing required command: $c" >&2; exit 1; }; done

[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "无效 REPO 格式 / Invalid REPO format: $REPO" >&2; exit 2; }

if [[ "$VERSION" == "latest" ]]; then
  [[ "$REPO" != "YOUR_GITHUB_USER/security-update-notify" ]] || { echo "发布前请设置 SECURITY_UPDATE_NOTIFY_REPO 或编辑引导脚本 REPO。/ Set SECURITY_UPDATE_NOTIFY_REPO or edit bootstrap REPO before publishing." >&2; exit 2; }
  api="https://api.github.com/repos/${REPO}/releases/latest"
  VERSION="$(curl -fsSL "$api" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))')"
fi
validate_version "$VERSION"

PKG="security-update-notify-${VERSION}.tar.gz"
PKG_DIR="security-update-notify-${VERSION}"
if [[ -n "$BASE_URL" ]]; then
  URL="${BASE_URL%/}/${PKG}"
  SHA_URL="${URL}.sha256"
else
  [[ "$REPO" != "YOUR_GITHUB_USER/security-update-notify" ]] || { echo "发布前请设置 SECURITY_UPDATE_NOTIFY_REPO 或编辑引导脚本 REPO。/ Set SECURITY_UPDATE_NOTIFY_REPO or edit bootstrap REPO before publishing." >&2; exit 2; }
  URL="https://github.com/${REPO}/releases/download/v${VERSION}/${PKG}"
  SHA_URL="${URL}.sha256"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
echo "正在下载 / Downloading: $URL"
curl -fL --retry 3 -o "$PKG" "$URL"
curl -fL --retry 3 -o "$PKG.sha256" "$SHA_URL"
verify_checksum "$PKG" "$PKG.sha256"
safe_extract_tar "$PKG" "$PKG_DIR"
cd "$PKG_DIR"

# 当通过 `curl ... | sudo bash` 调用时，stdin 是脚本流而不是用户终端。
# 因此只在最终 exec 目标脚本时重定向到 /dev/tty，避免校验后卡住。
# When invoked as `curl ... | sudo bash`, stdin is the script stream, not the
# user terminal. Do not run a standalone `exec < /dev/tty` here: bash would then
# start reading the remaining bootstrap script from the terminal and appear to
# hang after checksum verification. Redirect stdin only on the final exec.
run_target() {
  local script="$1"; shift
  if { : < /dev/tty; } 2>/dev/null; then
    exec "$script" "$@" < /dev/tty
  fi
  if [[ "$script" == "./menu.sh" && ! -t 0 ]]; then
    echo "菜单需要交互式终端，但当前不可用。/ No interactive terminal is available for the menu." >&2
    echo "请使用非交互模式，例如：bash sun.sh install --non-interactive -y ... / Run a non-interactive mode, for example: bash sun.sh install --non-interactive -y ..." >&2
    exit 2
  fi
  exec "$script" "$@"
}

case "$RUN_MODE" in
  menu) run_target ./menu.sh "${INSTALL_ARGS[@]}" ;;
  install) run_target ./install.sh "${INSTALL_ARGS[@]}" ;;
  test) exec ./test.sh "${INSTALL_ARGS[@]}" ;;
  uninstall) run_target ./uninstall.sh "${INSTALL_ARGS[@]}" ;;
  *) echo "无效模式 / Invalid mode: $RUN_MODE" >&2; exit 2 ;;
esac
