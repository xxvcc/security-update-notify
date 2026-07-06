#!/usr/bin/env bash
set -euo pipefail

# security-update-notify 引导安装器。
# Bootstrap installer for security-update-notify.
# 可将此脚本发布到你的网站，例如 https://example.com/install/sun.sh
# Publish this script on your website, e.g. https://example.com/install/sun.sh

REPO="xxvcc/security-update-notify"
VERSION="latest"
BASE_URL=""
VERIFY_SIGNATURE="required"
RELEASE_SIGNING_FINGERPRINT="C678256ACBFC6491BF5076655F3AE24999921FFC"
UI_LANG="${UI_LANG:-${SUN_LANG:-}}"
RUN_MODE="menu"
INSTALL_ARGS=()

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
  curl -fsSL https://example.com/install/sun.sh | sudo bash
  curl -fsSL https://example.com/install/sun.sh | sudo bash -s -- install [install args]

Bootstrap options:
  --lang LANG             Language for output and the selected script: zh | en
  --version VERSION       Release version, e.g. 1.1.0. Default: latest
  --repo OWNER/REPO       GitHub repo. Default from script config
  --base-url URL          Override download base URL
  --verify-signature MODE Signature verification: required | auto | off (default: required; auto is a compatibility alias)
  install                 Run install.sh after download
  upgrade                 Upgrade and reuse existing config
  test                    Run test.sh after download
  uninstall               Run uninstall.sh after download
  menu                    Run menu.sh after download (default)

All remaining options are passed to the selected script.
EOF
  else
    cat <<'EOF'
用法:
  curl -fsSL https://example.com/install/sun.sh | sudo bash
  curl -fsSL https://example.com/install/sun.sh | sudo bash -s -- install [安装参数]

引导选项:
  --lang LANG             输出与所选脚本的语言：zh | en
  --version VERSION       发布版本，例如 1.1.0；默认 latest
  --repo OWNER/REPO       GitHub 仓库；默认来自脚本配置
  --base-url URL          覆盖下载基础 URL
  --verify-signature MODE 签名校验模式：required | auto | off（默认 required；auto 为兼容别名）
  install                 下载后运行 install.sh
  upgrade                 下载后升级并复用已有配置
  test                    下载后运行 test.sh
  uninstall               下载后运行 uninstall.sh
  menu                    下载后运行 menu.sh（默认）

其余所有选项都会传递给选中的脚本。
EOF
  fi
}

require_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || { say "缺少 $1 的值" "Missing value for $1" >&2; exit 2; }; }
validate_version() { [[ "$1" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || { say "无效版本: $1" "Invalid VERSION: $1" >&2; exit 2; }; }
curl_https() { curl --proto '=https' --proto-redir '=https' "$@"; }
tar_clean_env() { env -u TAR_OPTIONS -u GZIP -u BZIP2 -u XZ_OPT tar "$@"; }

verify_checksum() {
  local file="$1" sha_file="$2" expected
  expected="$(awk 'NF {print $1; exit}' "$sha_file")"
  [[ "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || { say "无效校验文件: $SHA_URL" "Invalid checksum file: $SHA_URL" >&2; exit 1; }
  printf '%s  %s\n' "$expected" "$file" | sha256sum -c -
}

safe_extract_tar() {
  local archive="$1" topdir="$2" entry listing_type
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    case "$entry" in
      /*|../*|*/../*|*/..|..)
        say "压缩包中存在不安全路径: $entry" "Unsafe path in archive: $entry" >&2
        exit 1
        ;;
    esac
    case "$entry" in
      "$topdir"|"$topdir/"|"$topdir"/*) ;;
      *)
        say "压缩包中存在非预期路径: $entry" "Unexpected path in archive: $entry" >&2
        exit 1
        ;;
    esac
  done < <(tar_clean_env -tzf "$archive")
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    listing_type="${entry:0:1}"
    case "$listing_type" in
      -|d) ;;
      *)
        say "压缩包中存在不支持的条目类型: $entry" "Unsupported archive entry type: $entry" >&2
        exit 1
        ;;
    esac
  done < <(tar_clean_env -tzvf "$archive")
  tar_clean_env --no-same-owner -xzf "$archive"
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
    install|upgrade|test|uninstall|menu) RUN_MODE="$1"; shift; INSTALL_ARGS+=("$@"); break ;;
    -h|--help) usage; exit 0 ;;
    *) INSTALL_ARGS+=("$1"); shift ;;
  esac
done

# 仅在显式且有效时导出语言，让目标脚本沿用；否则交给目标脚本（菜单）提示选择。
# Export the language only when explicitly set and valid, so the target script reuses it;
# otherwise leave it to the target script (the menu) to prompt for selection.
case "${UI_LANG:-}" in
  zh|en) export UI_LANG ;;
  "") ;;
  *) say "无效语言: ${UI_LANG}（应为 zh 或 en），将忽略" "Invalid language: ${UI_LANG} (expected zh or en), ignoring" >&2; UI_LANG="" ;;
esac

[[ "$(id -u)" -eq 0 ]] || { say "请使用 sudo/root 运行" "Please run with sudo/root" >&2; exit 1; }

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
    printf '%s\n' "请选择语言 / Choose a language:"
    printf '%s\n' "  1) 中文 (default)"
    printf '%s\n' "  2) English"
    read -r -p "[1]: " sun_lang_choice < /dev/tty || sun_lang_choice=1
    case "${sun_lang_choice:-1}" in 2) UI_LANG=en ;; *) UI_LANG=zh ;; esac
    export UI_LANG
  fi
fi

REQUIRED_COMMANDS=(curl tar sha256sum mktemp python3 env)
[[ "$VERIFY_SIGNATURE" == "off" ]] || REQUIRED_COMMANDS+=(gpg)
for c in "${REQUIRED_COMMANDS[@]}"; do command -v "$c" >/dev/null 2>&1 || { say "缺少必需命令: $c" "Missing required command: $c" >&2; exit 1; }; done

[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { say "无效 REPO 格式: $REPO" "Invalid REPO format: $REPO" >&2; exit 2; }

if [[ "$VERSION" == "latest" ]]; then
  [[ "$REPO" != "YOUR_GITHUB_USER/security-update-notify" ]] || { say "发布前请传入 --repo 或编辑引导脚本 REPO。" "Pass --repo or edit bootstrap REPO before publishing." >&2; exit 2; }
  api="https://api.github.com/repos/${REPO}/releases/latest"
  VERSION="$(curl_https -fsSL "$api" | python3 -c 'import json,sys; t=json.load(sys.stdin)["tag_name"]; print(t[1:] if t.startswith("v") else t)')"
fi
validate_version "$VERSION"

PKG="security-update-notify-${VERSION}.tar.gz"
PKG_DIR="security-update-notify-${VERSION}"
if [[ -n "$BASE_URL" ]]; then
  # 自定义下载源必须是 https（拒绝 http:// / file:// / ftp:// 等明文或本地协议）。
  # A custom download source must be https (reject http:// / file:// / ftp:// and other plaintext/local schemes).
  [[ "$BASE_URL" =~ ^https://[A-Za-z0-9.-]+ ]] || { say "--base-url 必须以 https:// 开头: $BASE_URL" "--base-url must start with https://: $BASE_URL" >&2; exit 2; }
  URL="${BASE_URL%/}/${PKG}"
  SHA_URL="${URL}.sha256"
else
  [[ "$REPO" != "YOUR_GITHUB_USER/security-update-notify" ]] || { say "发布前请传入 --repo 或编辑引导脚本 REPO。" "Pass --repo or edit bootstrap REPO before publishing." >&2; exit 2; }
  URL="https://github.com/${REPO}/releases/download/v${VERSION}/${PKG}"
  SHA_URL="${URL}.sha256"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
say "正在下载: $URL" "Downloading: $URL"
curl_https -fL --retry 3 -o "$PKG" "$URL"
curl_https -fL --retry 3 -o "$PKG.sha256" "$SHA_URL"
verify_checksum "$PKG" "$PKG.sha256"

verify_signature_if_available() {
  local sig_url sig_file actual_fpr gpg_home eff="$VERIFY_SIGNATURE"
  case "$VERIFY_SIGNATURE" in auto|required|off) ;; *) say "无效签名校验模式: $VERIFY_SIGNATURE" "Invalid signature verification mode: $VERIFY_SIGNATURE" >&2; exit 2 ;; esac
  [[ "$eff" != "off" ]] || return 0
  # auto 作为兼容别名保留，但不再在缺少 gpg/签名时退回 sha256-only。
  # auto is kept as a compatibility alias, but no longer falls back to sha256-only when
  # gpg or the signature is missing.
  [[ "$eff" == "auto" ]] && eff="required"
  command -v gpg >/dev/null 2>&1 || { say "签名校验需要 gpg" "gpg is required for signature verification" >&2; exit 1; }
  sig_url="${URL}.asc"
  sig_file="$TMP/$PKG.asc"
  curl_https -fsL --retry 2 -o "$sig_file" "$sig_url" || { say "缺少 release 签名；拒绝继续" "Release signature is missing; refusing to continue" >&2; exit 1; }
  gpg_home="$TMP/gnupg"
  mkdir -p "$gpg_home"; chmod 700 "$gpg_home"
  release_signing_public_key | GNUPGHOME="$gpg_home" gpg --batch --import >/dev/null 2>&1 || { say "导入签名公钥失败" "Failed to import signing public key" >&2; exit 1; }
  actual_fpr="$(GNUPGHOME="$gpg_home" gpg --batch --with-colons --list-keys 2>/dev/null | awk -F: '$1=="fpr" {print $10; exit}')"
  [[ -n "$RELEASE_SIGNING_FINGERPRINT" && "$actual_fpr" == "$RELEASE_SIGNING_FINGERPRINT" ]] || { say "签名公钥指纹不匹配（期望 $RELEASE_SIGNING_FINGERPRINT，实际 ${actual_fpr:-none}）；拒绝继续" "Signing key fingerprint mismatch (expected $RELEASE_SIGNING_FINGERPRINT, got ${actual_fpr:-none}); refusing to continue" >&2; exit 1; }
  GNUPGHOME="$gpg_home" gpg --batch --verify "$sig_file" "$TMP/$PKG" >/dev/null 2>&1 || { say "签名校验失败；拒绝继续" "Signature verification failed; refusing to continue" >&2; exit 1; }
  say "签名校验通过 (${RELEASE_SIGNING_FINGERPRINT})" "Signature verified (${RELEASE_SIGNING_FINGERPRINT})"
}

verify_signature_if_available
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
    "$script" "$@" < /dev/tty
    exit $?
  fi
  if [[ "$script" == "./menu.sh" && ! -t 0 ]]; then
    say "菜单需要交互式终端，但当前不可用。" "No interactive terminal is available for the menu." >&2
    say "请使用非交互模式，例如：bash sun.sh install --non-interactive -y ..." "Run a non-interactive mode, for example: bash sun.sh install --non-interactive -y ..." >&2
    exit 2
  fi
  "$script" "$@"
  exit $?
}

case "$RUN_MODE" in
  menu) run_target ./menu.sh "${INSTALL_ARGS[@]}" ;;
  upgrade) export SECURITY_UPDATE_NOTIFY_UPGRADE=1; run_target ./install.sh "${INSTALL_ARGS[@]}" ;;
  install) run_target ./install.sh "${INSTALL_ARGS[@]}" ;;
  test) exec ./test.sh "${INSTALL_ARGS[@]}" ;;
  uninstall) run_target ./uninstall.sh "${INSTALL_ARGS[@]}" ;;
  *) say "无效模式: $RUN_MODE" "Invalid mode: $RUN_MODE" >&2; exit 2 ;;
esac
