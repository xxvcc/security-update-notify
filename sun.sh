#!/usr/bin/env bash
set -euo pipefail

# security-update-notify 引导安装器。
# Bootstrap installer for security-update-notify.
# 稳定发布地址：https://dl.ll.cd/security-update-notify/sun.sh
# Stable URL: https://dl.ll.cd/security-update-notify/sun.sh

REPO="xxvcc/security-update-notify"
VERSION="latest"
BASE_URL=""
RELEASE_MIRROR_BASE="https://dl.ll.cd/security-update-notify"
VERIFY_SIGNATURE="required"
RELEASE_SIGNING_FINGERPRINT="C678256ACBFC6491BF5076655F3AE24999921FFC"
# 发布工具与镜像工作流读取此契约标记；引导器运行时不使用它。
# Release tooling reads this contract marker; the runtime bootstrap does not.
# shellcheck disable=SC2034
BOOTSTRAP_SIGNATURE_ASSET="sun.sh.asc"
# shellcheck disable=SC2034
BOOTSTRAP_VERSION_NOTATION="release-version@xxv.cc"
UI_LANG="${UI_LANG:-${SUN_LANG:-}}"
RUN_MODE="menu"
INSTALL_ARGS=()
CURL_RETRY_OPTIONS=()

# 双语输出助手：sun.sh 运行在“选择语言”之前，自身输出默认 zh；
# 仅当显式指定 --lang/UI_LANG/SUN_LANG 时才把语言传给目标脚本（否则菜单会提示选择）。
# Bilingual output helper: sun.sh runs before language selection, so its own output defaults to zh.
# The language is only passed to the target script when explicitly set via --lang/UI_LANG/SUN_LANG
# (otherwise the menu prompts for it as the first step).
m()  { if [ "${UI_LANG:-zh}" = en ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
say(){ if [ "${UI_LANG:-zh}" = en ]; then printf '%s\n' "$2"; else printf '%s\n' "$1"; fi; }

usage() {
  if [ "${UI_LANG:-zh}" = en ]; then
    cat <<'EOF'
Usage:
  set -o pipefail
  curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash
  curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash -s -- install [install args]

Bootstrap options:
  --lang LANG             Language for output and the selected script: zh | en
  --version VERSION       Release version, e.g. 1.1.0. Default: latest
  --repo OWNER/REPO       GitHub repo. Default from script config
  --base-url URL          Override download base URL
  --verify-signature MODE Signature verification: required | auto | off (default: required; auto is a compatibility alias)
  install                 Run the Go installer after download
  upgrade                 Upgrade with the Go installer and reuse existing config
  configure               Configure notification settings with the Go CLI
  doctor                  Run Go diagnostics
  check-upgrade           Check whether a newer release exists
  test                    Run Go tests/notification tests
  uninstall               Run the Go uninstaller
  menu                    Show the bootstrap menu (default)

All remaining options are passed to the selected Go subcommand.
EOF
  else
    cat <<'EOF'
用法:
  set -o pipefail
  curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash
  curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash -s -- install [安装参数]

引导选项:
  --lang LANG             输出与所选脚本的语言：zh | en
  --version VERSION       发布版本，例如 1.1.0；默认 latest
  --repo OWNER/REPO       GitHub 仓库；默认来自脚本配置
  --base-url URL          覆盖下载基础 URL
  --verify-signature MODE 签名校验模式：required | auto | off（默认 required；auto 为兼容别名）
  install                 下载后运行 Go 安装器
  upgrade                 使用 Go 安装器升级并复用已有配置
  configure               使用 Go CLI 修改消息通知设置
  doctor                  运行 Go 诊断
  check-upgrade           检查是否存在新版本
  test                    运行 Go 检查或通知测试
  uninstall               运行 Go 卸载器
  menu                    显示引导菜单（默认）

其余所有选项都会传递给选中的 Go 子命令。
EOF
  fi
}

require_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || { say "缺少 $1 的值" "Missing value for $1" >&2; exit 2; }; }
validate_version() { [[ ${#1} -le 128 && "$1" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || { say "无效版本: $1" "Invalid VERSION: $1" >&2; exit 2; }; }
curl_https() { curl --proto '=https' --proto-redir '=https' "$@"; }
configure_curl_retry_options() {
  local curl_help
  curl_help="$(curl --help all 2>/dev/null || true)"
  if [[ "$curl_help" == *"--retry-all-errors"* ]]; then
    CURL_RETRY_OPTIONS=(--retry-all-errors)
  elif [[ "$curl_help" == *"--retry-connrefused"* ]]; then
    CURL_RETRY_OPTIONS=(--retry-connrefused)
  fi
}
curl_retry() {
  curl_https --connect-timeout 20 --retry 4 --retry-delay 1 --retry-max-time 180 \
    "${CURL_RETRY_OPTIONS[@]}" "$@"
}
tar_clean_env() { env -u TAR_OPTIONS -u GZIP -u BZIP2 -u XZ_OPT tar "$@"; }

append_bootstrap_package() {
  local package="$1" existing
  for existing in "${BOOTSTRAP_PACKAGES[@]:-}"; do
    [[ "$existing" == "$package" ]] && return 0
  done
  BOOTSTRAP_PACKAGES+=("$package")
}

resolve_bootstrap_packages() {
  local family="$1" command package
  shift
  BOOTSTRAP_PACKAGES=()
  append_bootstrap_package ca-certificates
  for command in "$@"; do
    case "$command" in
      curl) package=curl ;;
      tar) package=tar ;;
      sha256sum|mktemp|env|uname|timeout) package=coreutils ;;
      python3) package=python3 ;;
      gpg)
        case "$family" in
          apt) package=gnupg ;;
          rpm) package=gnupg2 ;;
          *) return 2 ;;
        esac
        ;;
      *) return 2 ;;
    esac
    append_bootstrap_package "$package"
  done
}

gpg_primary_fingerprints() {
  local line want_fingerprint=0
  local -a fields=()
  while IFS= read -r line; do
    IFS=: read -r -a fields <<<"$line"
    case "${fields[0]:-}" in
      pub) want_fingerprint=1 ;;
      fpr)
        if [[ "$want_fingerprint" -eq 1 ]]; then
          [[ "${#fields[@]}" -gt 9 && -n "${fields[9]}" ]] && printf '%s\n' "${fields[9]}"
          want_fingerprint=0
        fi
        ;;
    esac
  done
}

gpg_status_has_pinned_signature() {
  local pin="$1" line last
  local -a fields=()
  while IFS= read -r line; do
    read -r -a fields <<<"$line"
    [[ "${#fields[@]}" -ge 3 ]] || continue
    last="${fields[${#fields[@]}-1]}"
    if [[ "${fields[0]}" == '[GNUPG:]' && "${fields[1]}" == VALIDSIG \
       && ( "${fields[2]}" == "$pin" || "$last" == "$pin" ) ]]; then
      return 0
    fi
  done
  return 1
}

parse_mirror_latest() {
  python3 -c '
import json, sys
root = sys.argv[1].rstrip("/")
data = json.load(sys.stdin)
version = str(data.get("version", ""))
tag = str(data.get("tag", ""))
base_url = str(data.get("base_url", ""))
if not version or tag != "v" + version or base_url != root + "/" + tag:
    raise SystemExit("invalid mirror latest manifest")
print(version)
' "$RELEASE_MIRROR_BASE"
}

verify_checksum() {
  local file="$1" sha_file="$2" expected
  expected="$(python3 - "$sha_file" "$file" <<'PY'
import os
import re
import sys

sha_file, filename = sys.argv[1:]
try:
    data = open(sha_file, "rb").read()
except OSError:
    raise SystemExit(1)
pattern = rb"([0-9A-Fa-f]{64})  " + re.escape(os.fsencode(filename)) + rb"\n"
match = re.fullmatch(pattern, data)
if match is None:
    raise SystemExit(1)
print(match.group(1).decode("ascii"))
PY
  )" || {
    say "无效校验文件（必须仅包含指定归档的一条记录）: $sha_file" \
        "Invalid checksum file (expected exactly one record for the selected archive): $sha_file" >&2
    exit 1
  }
  printf '%s  %s\n' "$expected" "$file" | sha256sum -c -
}

safe_extract_tar() {
  local archive="$1" topdir="$2"
  python3 - "$archive" "$topdir" <<'PY' || {
import sys
import tarfile

archive, topdir = sys.argv[1:]
entries = 0
total = 0
try:
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf:
            entries += 1
            if entries > 10000:
                raise ValueError("too many archive entries")
            name = member.name
            parts = name.split("/")
            if name.startswith("/") or name in ("", "..") or ".." in parts:
                raise ValueError("unsafe archive path")
            if not (name == topdir or name == topdir + "/" or name.startswith(topdir + "/")):
                raise ValueError("unexpected archive path")
            if not (member.isfile() or member.isdir()):
                raise ValueError("unsupported archive entry")
            if member.size < 0:
                raise ValueError("invalid archive size")
            if member.isfile():
                total += member.size
                if total > 256 * 1024 * 1024:
                    raise ValueError("archive is too large")
    if entries == 0:
        raise ValueError("empty archive")
except Exception:
    sys.exit(1)
PY
    say "压缩包安全检查失败" "Archive safety check failed" >&2
    exit 1
  }
  # --no-same-permissions：不从归档恢复 setuid/setgid 等特殊权限位（纵深防御）。
  # --no-same-permissions: do not restore setuid/setgid/special bits from the archive (defense in depth).
  tar_clean_env --no-same-owner --no-same-permissions -xzf "$archive"
}

gpg_release() {
  local home="$1"
  shift
  timeout --signal=TERM --kill-after=5s 30s gpg --batch --no-tty --homedir "$home" "$@"
}

release_signing_public_key() {
  cat <<'EOF'
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEahvWSxYJKwYBBAHaRw8BAQdA4dw6PpATHy6t/5pPCenY7QgLM0JrrRzmGy+U
6QCu1Om0RnNlY3VyaXR5LXVwZGF0ZS1ub3RpZnkgcmVsZWFzZSBzaWduaW5nIDxz
ZWN1cml0eS11cGRhdGUtbm90aWZ5QHh4di5jYz6IkAQTFggAOBYhBMZ4JWrL/GSR
v1B2ZV864kmZkh/8BQJqG9ZLAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJ
EF864kmZkh/8cd8BAPJzN0Gwyu18Sks3qp7oUhHGZDgXfomwwcMSRHsMbtYIAPwJ
/5ACw9n3BkfUYkGs76uTaVHtXEZFmXjNiegzaqkgDQ==
=AahY
-----END PGP PUBLIC KEY BLOCK-----
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lang) require_arg "$1" "${2:-}"; UI_LANG="$2"; shift 2 ;;
    --version) require_arg "$1" "${2:-}"; VERSION="$2"; shift 2 ;;
    --repo) require_arg "$1" "${2:-}"; REPO="$2"; shift 2 ;;
    --base-url) require_arg "$1" "${2:-}"; BASE_URL="$2"; shift 2 ;;
    --verify-signature) require_arg "$1" "${2:-}"; VERIFY_SIGNATURE="$2"; shift 2 ;;
    install|upgrade|configure|doctor|check-upgrade|test|uninstall|menu)
      RUN_MODE="$1"
      shift
      # --lang is a bootstrap option even when users naturally place it after
      # the subcommand. Consume it here and pass the selected language through
      # UI_LANG instead of forwarding a duplicate flag to the Go command.
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --lang) require_arg "$1" "${2:-}"; UI_LANG="$2"; shift 2 ;;
          *) INSTALL_ARGS+=("$1"); shift ;;
        esac
      done
      break
      ;;
    -h|--help) usage; exit 0 ;;
    *) INSTALL_ARGS+=("$1"); shift ;;
  esac
done

# 仅在显式且有效时导出语言，让目标脚本沿用；否则交给交互选择。
# Export the language only when explicitly set and valid, so the target command reuses it;
# otherwise leave it to the interactive selector.
case "${UI_LANG:-}" in
  zh|en) export UI_LANG ;;
  "") ;;
  *) say "无效语言: ${UI_LANG}（应为 zh 或 en）" "Invalid language: ${UI_LANG} (expected zh or en)" >&2; exit 2 ;;
esac

case "$VERIFY_SIGNATURE" in
  auto|required|off) ;;
  *) say "无效签名校验模式: $VERIFY_SIGNATURE" "Invalid signature verification mode: $VERIFY_SIGNATURE" >&2; exit 2 ;;
esac

(( EUID == 0 )) || { say "请使用 sudo/root 运行" "Please run with sudo/root" >&2; exit 1; }

# 第一步：交互选择语言。仅当未显式指定语言、有可用终端、且目标不是 --non-interactive 时弹出。
# 用 `read < /dev/tty` 只读一行终端输入，不影响 bash 继续从 stdin（curl 管道）读取脚本本身。
# First step: prompt for language interactively. Only when no language was set explicitly, a
# terminal is available, and the target is not --non-interactive. Reading one line from /dev/tty
# does not disturb bash reading the script itself from stdin (the curl pipe).
if [[ -z "${UI_LANG:-}" ]]; then
  sun_noninteractive=0
  if [[ "${#INSTALL_ARGS[@]}" -gt 0 ]]; then
    for a in "${INSTALL_ARGS[@]}"; do [[ "$a" == "--non-interactive" ]] && sun_noninteractive=1; done
  fi
  if [[ "$sun_noninteractive" -eq 0 ]] && { : < /dev/tty; } 2>/dev/null; then
    while true; do
      printf '%s\n' "请选择语言 / Choose a language:"
      printf '%s\n' "  1) 中文 (default)"
      printf '%s\n' "  2) English"
      if ! read -r -p "[1]: " sun_lang_choice < /dev/tty; then
        say "已取消。" "Cancelled." >&2
        exit 2
      fi
      case "${sun_lang_choice:-1}" in
        1|'') UI_LANG=zh; break ;;
        2) UI_LANG=en; break ;;
        *) printf '%s\n' "无效选择，请输入 1 或 2。 / Invalid choice; enter 1 or 2." >&2 ;;
      esac
    done
    export UI_LANG
  fi
fi

# Validate every option that does not require curl/python before invoking a
# package manager. The language prompt stays first so diagnostics use the
# user's selected language, but invalid input can never trigger apt/dnf writes.
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  say "无效 REPO 格式: $REPO" "Invalid REPO format: $REPO" >&2
  exit 2
}
if [[ "$VERSION" != "latest" ]]; then
  validate_version "$VERSION"
fi
if [[ -n "$BASE_URL" ]]; then
  { [[ "$BASE_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ ]] && [[ "$BASE_URL" != *".."* ]]; } || {
    say "--base-url 必须是干净的 https URL（不含 .. 等）: $BASE_URL" \
        "--base-url must be a clean https URL (no ..): $BASE_URL" >&2
    exit 2
  }
fi
if [[ "$VERSION" == "latest" || -z "$BASE_URL" ]]; then
  [[ "$REPO" != "YOUR_GITHUB_USER/security-update-notify" ]] || {
    say "发布前请传入 --repo 或编辑引导脚本 REPO。" "Pass --repo or edit bootstrap REPO before publishing." >&2
    exit 2
  }
fi

REQUIRED_COMMANDS=(curl tar sha256sum mktemp python3 env uname)
[[ "$VERIFY_SIGNATURE" == "off" ]] || REQUIRED_COMMANDS+=(gpg timeout)
missing_commands=()
for c in "${REQUIRED_COMMANDS[@]}"; do
  command -v "$c" >/dev/null 2>&1 || missing_commands+=("$c")
done
if [[ "${#missing_commands[@]}" -gt 0 ]]; then
  say "正在通过系统包管理器补齐引导依赖: ${missing_commands[*]}" \
      "Installing missing bootstrap dependencies through the system package manager: ${missing_commands[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    resolve_bootstrap_packages apt "${missing_commands[@]}" || {
      say "无法解析缺失命令对应的软件包。" "Could not resolve packages for the missing commands." >&2
      exit 1
    }
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${BOOTSTRAP_PACKAGES[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    resolve_bootstrap_packages rpm "${missing_commands[@]}" || {
      say "无法解析缺失命令对应的软件包。" "Could not resolve packages for the missing commands." >&2
      exit 1
    }
    dnf install -y "${BOOTSTRAP_PACKAGES[@]}"
  elif command -v microdnf >/dev/null 2>&1; then
    resolve_bootstrap_packages rpm "${missing_commands[@]}" || {
      say "无法解析缺失命令对应的软件包。" "Could not resolve packages for the missing commands." >&2
      exit 1
    }
    if ! microdnf install -y "${BOOTSTRAP_PACKAGES[@]}"; then
      if [[ " ${missing_commands[*]} " == *" gpg "* ]]; then
        say "microdnf 安装失败且 gpg 缺失；若上方出现 Invalid crypto engine，请先通过发行版救援环境或可信软件包缓存恢复 gnupg2，再重试。" \
            "microdnf failed while gpg is missing; if the error above contains Invalid crypto engine, restore gnupg2 from distribution rescue media or a trusted package cache, then retry." >&2
      fi
      exit 1
    fi
  elif command -v yum >/dev/null 2>&1; then
    resolve_bootstrap_packages rpm "${missing_commands[@]}" || {
      say "无法解析缺失命令对应的软件包。" "Could not resolve packages for the missing commands." >&2
      exit 1
    }
    yum install -y "${BOOTSTRAP_PACKAGES[@]}"
  else
    say "缺少必需命令且没有可用的 apt/dnf/microdnf/yum: ${missing_commands[*]}" \
        "Required commands are missing and apt/dnf/microdnf/yum is unavailable: ${missing_commands[*]}" >&2
    exit 1
  fi
  for c in "${REQUIRED_COMMANDS[@]}"; do
    command -v "$c" >/dev/null 2>&1 || {
      say "安装依赖后仍缺少必需命令: $c" "Required command is still missing after dependency installation: $c" >&2
      exit 1
    }
  done
fi

configure_curl_retry_options

if [[ "$VERSION" == "latest" ]]; then
  if ! VERSION="$(curl_retry --max-filesize 1048576 -fsSL "${RELEASE_MIRROR_BASE%/}/latest.json" 2>/dev/null | parse_mirror_latest 2>/dev/null)"; then
    say "发布镜像版本索引不可用，正在回退 GitHub。" "Release mirror index unavailable; falling back to GitHub."
    api="https://api.github.com/repos/${REPO}/releases/latest"
    VERSION="$(curl_retry --max-filesize 1048576 -fsSL "$api" | python3 -c 'import json,sys; t=json.load(sys.stdin)["tag_name"]; print(t[1:] if t.startswith("v") else t)')"
  fi
fi
validate_version "$VERSION"

PKG="security-update-notify-${VERSION}.tar.gz"
PKG_DIR="security-update-notify-${VERSION}"
DOWNLOAD_BASES=()
if [[ -n "$BASE_URL" ]]; then
  DOWNLOAD_BASES+=("${BASE_URL%/}")
else
  DOWNLOAD_BASES+=("${RELEASE_MIRROR_BASE%/}/v${VERSION}")
  DOWNLOAD_BASES+=("https://github.com/${REPO}/releases/download/v${VERSION}")
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

download_release_set() {
  local base
  for base in "${DOWNLOAD_BASES[@]}"; do
    URL="${base%/}/${PKG}"
    SHA_URL="${URL}.sha256"
    rm -f "$PKG" "$PKG.sha256" "$PKG.asc"
    say "正在下载: $URL" "Downloading: $URL"
    if curl_retry --max-filesize 268435456 -fL -o "$PKG" "$URL" \
        && curl_retry --max-filesize 1048576 -fL -o "$PKG.sha256" "$SHA_URL" \
        && { [[ "$VERIFY_SIGNATURE" == "off" ]] || curl_retry --max-filesize 1048576 -fsL -o "$PKG.asc" "${URL}.asc"; }; then
      SELECTED_BASE="$base"
      return 0
    fi
    if [[ "${#DOWNLOAD_BASES[@]}" -gt 1 && "$base" == "${RELEASE_MIRROR_BASE%/}/v${VERSION}" ]]; then
      say "发布镜像下载不完整，正在回退 GitHub。" "Release mirror download incomplete; falling back to GitHub."
    fi
  done
  say "所有发布下载源均不可用。" "All release download sources failed." >&2
  return 1
}

download_release_set
if [[ "$SELECTED_BASE" == "${RELEASE_MIRROR_BASE%/}/v${VERSION}" ]]; then
  say "已通过发布镜像下载。" "Downloaded through the release mirror."
fi
verify_checksum "$PKG" "$PKG.sha256"

verify_signature_if_available() {
  local sig_file gpg_home status eff="$VERIFY_SIGNATURE"
  local -a primary_fingerprints=()
  [[ "$eff" != "off" ]] || return 0
  # auto 作为兼容别名保留，但不再在缺少 gpg/签名时退回 sha256-only。
  # auto is kept as a compatibility alias, but no longer falls back to sha256-only when
  # gpg or the signature is missing.
  [[ "$eff" == "auto" ]] && eff="required"
  command -v gpg >/dev/null 2>&1 || { say "签名校验需要 gpg" "gpg is required for signature verification" >&2; exit 1; }
  sig_file="$TMP/$PKG.asc"
  [[ -f "$sig_file" ]] || { say "缺少 release 签名；拒绝继续" "Release signature is missing; refusing to continue" >&2; exit 1; }
  gpg_home="$TMP/gnupg"
  mkdir -p "$gpg_home"; chmod 700 "$gpg_home"
  release_signing_public_key | gpg_release "$gpg_home" --import >/dev/null 2>&1 || { say "导入签名公钥失败" "Failed to import signing public key" >&2; exit 1; }
  mapfile -t primary_fingerprints < <(
    gpg_release "$gpg_home" --with-colons --list-keys 2>/dev/null |
      gpg_primary_fingerprints
  )
  [[ -n "$RELEASE_SIGNING_FINGERPRINT" && "${#primary_fingerprints[@]}" -eq 1 \
     && "${primary_fingerprints[0]}" == "$RELEASE_SIGNING_FINGERPRINT" ]] || {
    say "签名 keyring 必须且只能包含固定指纹公钥；拒绝继续" \
        "Signing keyring must contain exactly the pinned primary key; refusing to continue" >&2
    exit 1
  }
  status="$(gpg_release "$gpg_home" --status-fd=1 --verify "$sig_file" "$TMP/$PKG" 2>/dev/null)" || {
    say "签名校验失败；拒绝继续" "Signature verification failed; refusing to continue" >&2
    exit 1
  }
  gpg_status_has_pinned_signature "$RELEASE_SIGNING_FINGERPRINT" <<<"$status" || {
    say "签名未绑定固定指纹；拒绝继续" "Signature is not bound to the pinned primary key; refusing to continue" >&2
    exit 1
  }
  say "签名校验通过 (${RELEASE_SIGNING_FINGERPRINT})" "Signature verified (${RELEASE_SIGNING_FINGERPRINT})"
}

verify_signature_if_available
safe_extract_tar "$PKG" "$PKG_DIR"
cd "$PKG_DIR"

# Bind the verified archive to the requested release, then select exactly one of
# the five supported Linux binaries. VERSION is the package's single source of
# truth; legacy Bash runtimes and installer scripts are deliberately not used.
package_version_lines=()
mapfile -t package_version_lines < VERSION 2>/dev/null || true
[[ "${#package_version_lines[@]}" -eq 1 \
   && "${package_version_lines[0]}" == "VERSION=\"$VERSION\"" ]] || {
  say "发布包根 VERSION 与请求版本($VERSION)不一致；拒绝继续。" \
      "Root VERSION does not match requested version ($VERSION); refusing to continue." >&2
  exit 1
}

case "$(uname -m)" in
  x86_64|amd64) go_arch=amd64 ;;
  aarch64|arm64) go_arch=arm64 ;;
  i386|i486|i586|i686) go_arch=386 ;;
  ppc64le) go_arch=ppc64le ;;
  s390x) go_arch=s390x ;;
  *)
    say "不支持当前架构: $(uname -m)" "Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac
GO_RUNTIME="./files/security-update-notify-linux-$go_arch"
[[ -f "$GO_RUNTIME" && ! -L "$GO_RUNTIME" && -x "$GO_RUNTIME" ]] || {
  say "发布包缺少可执行的 linux-$go_arch Go 二进制。" \
      "Release is missing an executable linux-$go_arch Go binary." >&2
  exit 1
}
runtime_version="$($GO_RUNTIME --version 2>/dev/null || true)"
[[ "$runtime_version" == "security-update-notify $VERSION" ]] || {
  say "Go 二进制版本与发布包不一致；拒绝继续。" \
      "Go binary version does not match the release; refusing to continue." >&2
  exit 1
}

# 当通过 `curl ... | sudo bash` 调用时，stdin 是脚本流而不是用户终端。
# 因此只在最终执行 Go 子命令时重定向到 /dev/tty，避免校验后卡住。
# When invoked as `curl ... | sudo bash`, stdin is the script stream, not the
# user terminal. Do not run a standalone `exec < /dev/tty` here: bash would then
# start reading the remaining bootstrap script from the terminal and appear to
# hang after checksum verification. Redirect stdin only on the final exec.
run_go() {
  local args=("$@")
  if [[ -n "${UI_LANG:-}" ]]; then args+=(--lang "$UI_LANG"); fi
  if { : < /dev/tty; } 2>/dev/null; then
    "$GO_RUNTIME" "${args[@]}" < /dev/tty
    exit $?
  fi
  "$GO_RUNTIME" "${args[@]}"
  exit $?
}

run_menu() {
  { : < /dev/tty; } 2>/dev/null || {
    say "菜单需要交互式终端，但当前不可用。" "No interactive terminal is available for the menu." >&2
    say "请使用非交互模式，例如：bash sun.sh install --non-interactive -y ..." \
        "Run a non-interactive mode, for example: bash sun.sh install --non-interactive -y ..." >&2
    exit 2
  }
  while true; do
    echo
    echo "security-update-notify"
    echo
    say "请选择操作：" "Choose an action:"
    say "1) 安装或升级" "1) Install or upgrade"
    say "2) 消息通知设置" "2) Message notification settings"
    say "3) 卸载" "3) Uninstall"
    say "4) 检查或诊断" "4) Check or diagnose"
    say "0) 退出" "0) Exit"
    if ! read -r -p "$(m '请输入选项 [1-4/0]: ' 'Enter choice [1-4/0]: ')" choice < /dev/tty; then
      say "已取消。" "Cancelled." >&2
      exit 2
    fi
    case "$choice" in
      1) run_go install "${INSTALL_ARGS[@]}" ;;
      2)
        [[ -r /etc/security-update-notify/telegram.env ]] || {
          say "尚未检测到已有安装，请先选择 '安装或升级'。" \
              "No existing installation was detected; choose Install or upgrade first." >&2
          continue
        }
        run_go configure notifications
        ;;
      3)
        echo
        say "卸载选项：" "Uninstall options:"
        say "1) 只移除程序，保留配置" "1) Remove program only, keep configuration"
        say "2) 移除程序并删除配置和状态" "2) Remove program and delete configuration/state"
        say "0) 返回" "0) Back"
        if ! read -r -p "$(m '请输入选项 [1/2/0]: ' 'Enter choice [1/2/0]: ')" uninstall_choice < /dev/tty; then
          say "已取消。" "Cancelled." >&2
          exit 2
        fi
        case "$uninstall_choice" in
          1) run_go uninstall ;;
          2) run_go uninstall --purge-config ;;
          0|'') continue ;;
          *) say "无效选项" "Invalid choice" >&2 ;;
        esac
        ;;
      4)
        echo
        say "检查选项：" "Check options:"
        say "1) 基础检查或诊断" "1) Basic check or doctor"
        say "2) 检查是否有新版" "2) Check for upgrade"
        say "3) 发送普通测试消息" "3) Send normal test message"
        say "4) 发送模拟重启提醒（不会真的重启）" "4) Send simulated reboot alert (does not reboot)"
        say "0) 返回" "0) Back"
        if ! read -r -p "$(m '请输入选项 [1/2/3/4/0]: ' 'Enter choice [1/2/3/4/0]: ')" check_choice < /dev/tty; then
          say "已取消。" "Cancelled." >&2
          exit 2
        fi
        case "$check_choice" in
          1) run_go doctor ;;
          2) run_go check-upgrade ;;
          3) run_go test --send-test --no-dedupe ;;
          4) run_go test --simulate-reboot --no-dedupe ;;
          0|'') continue ;;
          *) say "无效选项" "Invalid choice" >&2 ;;
        esac
        ;;
      0) exit 0 ;;
      *) say "无效选项" "Invalid choice" >&2 ;;
    esac
  done
}

case "$RUN_MODE" in
  menu) run_menu ;;
  upgrade) export SECURITY_UPDATE_NOTIFY_UPGRADE=1; run_go install "${INSTALL_ARGS[@]}" ;;
  install) run_go install "${INSTALL_ARGS[@]}" ;;
  configure)
    if [[ "${INSTALL_ARGS[0]:-}" == notifications ]]; then
      run_go configure "${INSTALL_ARGS[@]}"
    else
      run_go configure notifications "${INSTALL_ARGS[@]}"
    fi
    ;;
  doctor) run_go doctor "${INSTALL_ARGS[@]}" ;;
  check-upgrade) run_go check-upgrade "${INSTALL_ARGS[@]}" ;;
  test) run_go test "${INSTALL_ARGS[@]}" ;;
  uninstall) run_go uninstall "${INSTALL_ARGS[@]}" ;;
  *) say "无效模式: $RUN_MODE" "Invalid mode: $RUN_MODE" >&2; exit 2 ;;
esac
