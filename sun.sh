#!/bin/bash -p

# Bash imports BASH_ENV and exported functions before reading a non-privileged
# script, so in-script cleanup alone is too late. The documented pipe entry and
# this shebang both enable privileged mode (-p), which suppresses those startup
# hooks. Keep this check before every overridable builtin or external helper.
if [[ $- != *p* ]]; then
  # A fatal expansion stops the shell before an imported function could replace
  # `exit` or another builtin used to reject this invocation.
  : "${BASH_VERSINFO[999]:?sun.sh requires Bash privileged mode; run it with /bin/bash -p}"
fi

# In -p mode Bash ignores exported function definitions but can retain their
# raw BASH_FUNC_* environment entries. Re-exec with an empty environment so a
# later Bash-script child cannot import them. For a pipe, the clean Bash reads
# the unconsumed script body from stdin; for a file, it reopens this same file.
if [[ ${SUN_BOOTSTRAP_CLEAN_PID:-} != "$BASHPID" ]]; then
  sun_clean_env=(
    PATH=/usr/sbin:/usr/bin:/sbin:/bin
    LC_ALL=C
    "TERM=${TERM-}"
    "TZ=${TZ-}"
    "http_proxy=${http_proxy-}"
    "https_proxy=${https_proxy-}"
    "no_proxy=${no_proxy-}"
    "all_proxy=${all_proxy-}"
    "HTTP_PROXY=${HTTP_PROXY-}"
    "HTTPS_PROXY=${HTTPS_PROXY-}"
    "NO_PROXY=${NO_PROXY-}"
    "ALL_PROXY=${ALL_PROXY-}"
    "UI_LANG=${UI_LANG-}"
    "SUN_LANG=${SUN_LANG-}"
  )
  if [[ -n ${BASH_SOURCE[0]:-} ]]; then
    exec -c /usr/bin/env -i "${sun_clean_env[@]}" \
      "SUN_BOOTSTRAP_CLEAN_PID=$BASHPID" \
      /bin/bash -p "${BASH_SOURCE[0]}" "$@"
  fi
  exec -c /usr/bin/env -i "${sun_clean_env[@]}" \
    /bin/bash -p -s -- "$@"
fi

set -euo pipefail

# Privileged bootstrap helpers must not be selected from /usr/local or a
# caller-controlled PATH. Every supported distribution installs them here.
readonly SYSTEM_PATH=/usr/sbin:/usr/bin:/sbin:/bin
PATH="$SYSTEM_PATH"
export PATH

# Capture the only supported caller-controlled UI setting, then remove
# inherited command overrides and reduce the privileged process environment to
# the same small compatibility allowlist used by the Go runtime. Proxy values
# remain available for installations that require an outbound proxy.
sun_requested_lang="${UI_LANG:-${SUN_LANG:-}}"
sun_inherited_names=()
mapfile -t sun_inherited_names < <(builtin compgen -A function)
for sun_name in "${sun_inherited_names[@]}"; do
  builtin unset -f "$sun_name" 2>/dev/null || true
done
builtin unalias -a 2>/dev/null || true
mapfile -t sun_inherited_names < <(builtin compgen -e)
for sun_name in "${sun_inherited_names[@]}"; do
  case "$sun_name" in
    TERM|TZ|http_proxy|https_proxy|no_proxy|all_proxy|HTTP_PROXY|HTTPS_PROXY|NO_PROXY|ALL_PROXY|PATH) ;;
    *) builtin unset "$sun_name" 2>/dev/null || true ;;
  esac
done
builtin export -n BASHOPTS SHELLOPTS 2>/dev/null || true
unset sun_inherited_names sun_name
LC_ALL=C
export LC_ALL PATH

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
UI_LANG="$sun_requested_lang"
unset sun_requested_lang
RUN_MODE="menu"
INSTALL_ARGS=()
CURL_RETRY_OPTIONS=()
readonly MAX_METADATA_BYTES=1048576
readonly MAX_ARCHIVE_BYTES=268435456
readonly MAX_TTY_INPUT_BYTES=1024
readonly SYSTEM_TEMP_BASE=/var/tmp

# 双语输出助手：sun.sh 运行在“选择语言”之前，自身输出默认 zh；
# 仅当显式指定 --lang/UI_LANG/SUN_LANG 时才把语言传给目标脚本（否则菜单会提示选择）。
# Bilingual output helper: sun.sh runs before language selection, so its own output defaults to zh.
# The language is only passed to the target script when explicitly set via --lang/UI_LANG/SUN_LANG
# (otherwise the menu prompts for it as the first step).
m()  { if [ "${UI_LANG:-zh}" = en ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
say(){ if [ "${UI_LANG:-zh}" = en ]; then printf '%s\n' "$2"; else printf '%s\n' "$1"; fi; }

read_tty_line() {
  local prompt="$1" value
  while true; do
    printf '%s' "$prompt" >&2
    value=""
    # Linux canonical TTY input is kernel-bounded; keep the smaller application
    # limit so every accepted menu answer also has an explicit contract.
    if ! IFS= read -r value < /dev/tty; then
      return 2
    fi
    if [[ "${#value}" -le "$MAX_TTY_INPUT_BYTES" ]]; then
      SUN_TTY_LINE="$value"
      return 0
    fi
    say "输入过长，请重新输入。" "Input is too long; try again." >&2
  done
}

confirm_tty_exact() {
  local token="$1" prompt="$2"
  read_tty_line "$prompt" || return 2
  if [[ "$SUN_TTY_LINE" == "$token" ]]; then
    return 0
  fi
  say "确认内容不匹配；已取消。" "Confirmation did not match; cancelled." >&2
  return 1
}

confirm_tty_yes_no() {
  local prompt="$1"
  while true; do
    read_tty_line "$prompt" || return 2
    case "$SUN_TTY_LINE" in
      y|Y) return 0 ;;
      ''|n|N) return 1 ;;
      *) say "无效输入，请输入 y 或 n。" "Invalid input; enter y or n." >&2 ;;
    esac
  done
}

usage() {
  if [ "${UI_LANG:-zh}" = en ]; then
    cat <<'EOF'
Usage:
  set -o pipefail
  curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p
  curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p -s -- install [install args]

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
  curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p
  curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p -s -- install [安装参数]

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
curl_https() { curl --disable --proto '=https' --proto-redir '=https' "$@"; }
configure_curl_retry_options() {
  local curl_help
  curl_help="$(curl --disable --help all 2>/dev/null || true)"
  if [[ "$curl_help" == *"--retry-all-errors"* ]]; then
    CURL_RETRY_OPTIONS=(--retry-all-errors)
  elif [[ "$curl_help" == *"--retry-connrefused"* ]]; then
    CURL_RETRY_OPTIONS=(--retry-connrefused)
  fi
}
curl_retry() {
  curl_https --connect-timeout 20 --retry 4 --retry-delay 1 --retry-max-time 180 --max-time 180 \
    "${CURL_RETRY_OPTIONS[@]}" "$@"
}
download_limited() {
  local limit="$1" output="$2" part="${2}.part"
  shift 2
  rm -f -- "$part"
  if curl_retry --max-filesize "$limit" "$@" | python3 -I -c '
import os
import sys

limit = int(sys.argv[1])
path = sys.argv[2]
if limit < 0:
    raise SystemExit(1)
try:
    with open(path, "xb") as output:
        remaining = limit
        while True:
            chunk = sys.stdin.buffer.read(min(65536, remaining + 1))
            if not chunk:
                break
            if len(chunk) > remaining:
                raise ValueError("download exceeds size limit")
            output.write(chunk)
            remaining -= len(chunk)
except Exception:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    raise SystemExit(1)
' "$limit" "$part"; then
    if mv -f -- "$part" "$output"; then
      return 0
    fi
  fi
  rm -f -- "$part"
  return 1
}

capture_limited() {
  local limit="$1" output="$2" duration="$3" part="${2}.part"
  shift 3
  rm -f -- "$part"
  if timeout --signal=TERM --kill-after=5s "$duration" "$@" 2>/dev/null | python3 -I -c '
import os
import sys

limit = int(sys.argv[1])
path = sys.argv[2]
if limit < 0:
    raise SystemExit(1)
try:
    with open(path, "xb") as output:
        remaining = limit
        while True:
            chunk = sys.stdin.buffer.read(min(65536, remaining + 1))
            if not chunk:
                break
            if len(chunk) > remaining:
                raise ValueError("command output exceeds size limit")
            output.write(chunk)
            remaining -= len(chunk)
except Exception:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    raise SystemExit(1)
' "$limit" "$part"; then
    if mv -f -- "$part" "$output"; then
      return 0
    fi
  fi
  rm -f -- "$part"
  return 1
}
tar_clean_env() { env -u TAR_OPTIONS -u GZIP -u BZIP2 -u XZ_OPT tar "$@"; }

create_trusted_temp_dir() {
  python3 -I - "$SYSTEM_TEMP_BASE" <<'PY'
import os
import secrets
import stat
import sys


def validate_directory(fd, path):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("{} is not a directory".format(path))
    if info.st_uid != 0:
        raise RuntimeError("{} is not owned by root".format(path))
    if (stat.S_IMODE(info.st_mode) & 0o022) and not (info.st_mode & stat.S_ISVTX):
        raise RuntimeError("{} is group/other-writable without the sticky bit".format(path))


def create(base):
    if os.geteuid() != 0:
        raise RuntimeError("trusted temporary directory creation requires root")
    if not base.startswith("/") or os.path.normpath(base) != base:
        raise RuntimeError("temporary base must be a clean absolute path")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    current_fd = os.open("/", flags)
    display_path = "/"
    try:
        validate_directory(current_fd, display_path)
        components = [] if base == "/" else base[1:].split("/")
        for component in components:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            display_path = os.path.join(display_path, component)
            try:
                validate_directory(next_fd, display_path)
            except Exception:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd

        old_umask = os.umask(0o077)
        try:
            for _ in range(100):
                name = "security-update-notify." + secrets.token_hex(16)
                try:
                    os.mkdir(name, 0o700, dir_fd=current_fd)
                except FileExistsError:
                    continue
                child_fd = -1
                try:
                    child_fd = os.open(name, flags, dir_fd=current_fd)
                    os.fchmod(child_fd, 0o700)
                    child = os.fstat(child_fd)
                    if (not stat.S_ISDIR(child.st_mode) or child.st_uid != 0 or
                            stat.S_IMODE(child.st_mode) != 0o700):
                        raise RuntimeError("created temporary directory failed validation")
                except Exception:
                    if child_fd >= 0:
                        os.close(child_fd)
                    try:
                        os.rmdir(name, dir_fd=current_fd)
                    except OSError:
                        pass
                    raise
                os.close(child_fd)
                print(base + "/" + name)
                return
            raise RuntimeError("could not allocate a unique temporary directory")
        finally:
            os.umask(old_umask)
    finally:
        os.close(current_fd)


try:
    create(sys.argv[1])
except (OSError, RuntimeError) as error:
    raise SystemExit("cannot create trusted temporary directory: {}".format(error))
PY
}

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
      sha256sum|mktemp|env|uname|timeout|wc) package=coreutils ;;
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
  local good_count=0 outcome_count=0 valid_count=0 pinned_count=0
  local -a fields=()
  while IFS= read -r line; do
    read -r -a fields <<<"$line"
    [[ "${#fields[@]}" -ge 2 && "${fields[0]}" == '[GNUPG:]' ]] || continue
    case "${fields[1]}" in
      GOODSIG)
        ((outcome_count += 1))
        ((good_count += 1))
        ;;
      EXPSIG|EXPKEYSIG|REVKEYSIG|BADSIG|ERRSIG)
        # VALIDSIG only proves the signature bytes. GnuPG also emits it for an
        # expired or revoked signing key and can still exit zero, so exactly
        # one high-level outcome must exist and that outcome must be GOODSIG.
        ((outcome_count += 1))
        ;;
      VALIDSIG)
        [[ "${#fields[@]}" -ge 3 ]] || continue
        last="${fields[${#fields[@]}-1]}"
        ((valid_count += 1))
        if [[ "${fields[2]}" == "$pin" || "$last" == "$pin" ]]; then
          ((pinned_count += 1))
        fi
        ;;
    esac
  done
  [[ "$outcome_count" -eq 1 && "$good_count" -eq 1 \
     && "$valid_count" -eq 1 && "$pinned_count" -eq 1 ]]
}

parse_mirror_latest() {
  python3 -I -c '
import json, sys
root = sys.argv[1].rstrip("/")
limit = int(sys.argv[2])
raw = sys.stdin.buffer.read(limit + 1)
if len(raw) > limit:
    raise SystemExit("mirror latest manifest exceeds size limit")
data = json.loads(raw)
version = str(data.get("version", ""))
tag = str(data.get("tag", ""))
base_url = str(data.get("base_url", ""))
if not version or tag != "v" + version or base_url != root + "/" + tag:
    raise SystemExit("invalid mirror latest manifest")
print(version)
' "$RELEASE_MIRROR_BASE" "$MAX_METADATA_BYTES"
}

parse_github_latest() {
  python3 -I -c '
import json, sys
limit = int(sys.argv[1])
raw = sys.stdin.buffer.read(limit + 1)
if len(raw) > limit:
    raise SystemExit("GitHub latest response exceeds size limit")
tag = json.loads(raw)["tag_name"]
if not isinstance(tag, str):
    raise SystemExit("invalid GitHub latest response")
print(tag[1:] if tag.startswith("v") else tag)
' "$MAX_METADATA_BYTES"
}

verify_checksum() {
  local file="$1" sha_file="$2" expected
  expected="$(python3 -I - "$sha_file" "$file" <<'PY'
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
  python3 -I - "$archive" "$topdir" <<'PY' || {
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
  timeout --signal=TERM --kill-after=5s 30s gpg --no-options --batch --no-tty --homedir "$home" "$@"
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
      if ! read_tty_line "[1]: "; then
        say "已取消。" "Cancelled." >&2
        exit 2
      fi
      sun_lang_choice="$SUN_TTY_LINE"
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

REQUIRED_COMMANDS=(curl tar sha256sum mktemp python3 env uname timeout wc)
[[ "$VERIFY_SIGNATURE" == "off" ]] || REQUIRED_COMMANDS+=(gpg)
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
  if ! VERSION="$(curl_retry --max-filesize "$MAX_METADATA_BYTES" -fsSL "${RELEASE_MIRROR_BASE%/}/latest.json" 2>/dev/null | parse_mirror_latest 2>/dev/null)"; then
    say "发布镜像版本索引不可用，正在回退 GitHub。" "Release mirror index unavailable; falling back to GitHub."
    api="https://api.github.com/repos/${REPO}/releases/latest"
    VERSION="$(curl_retry --max-filesize "$MAX_METADATA_BYTES" -fsSL "$api" | parse_github_latest)"
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

TMP="$(create_trusted_temp_dir)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

download_release_set() {
  local base
  for base in "${DOWNLOAD_BASES[@]}"; do
    URL="${base%/}/${PKG}"
    SHA_URL="${URL}.sha256"
    rm -f "$PKG" "$PKG.sha256" "$PKG.asc"
    say "正在下载: $URL" "Downloading: $URL"
    if download_limited "$MAX_ARCHIVE_BYTES" "$PKG" -fL "$URL" \
        && download_limited "$MAX_METADATA_BYTES" "$PKG.sha256" -fL "$SHA_URL" \
        && { [[ "$VERIFY_SIGNATURE" == "off" ]] || download_limited "$MAX_METADATA_BYTES" "$PKG.asc" -fsL "${URL}.asc"; }; then
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
    say "签名未唯一绑定固定指纹；拒绝继续" \
        "Signature is not uniquely bound to the pinned primary key; refusing to continue" >&2
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
runtime_version_file="$TMP/runtime-version"
expected_runtime_version="security-update-notify $VERSION"
if ! capture_limited 4096 "$runtime_version_file" 15s "$GO_RUNTIME" --version; then
  say "Go 二进制版本探针失败、超时或输出过大；拒绝继续。" \
      "Go binary version probe failed, timed out, or produced too much output; refusing to continue." >&2
  exit 1
fi
runtime_version=""
IFS= read -r runtime_version < "$runtime_version_file" || true
[[ "$runtime_version" == "$expected_runtime_version" \
   && "$(wc -c < "$runtime_version_file")" -eq "$((${#expected_runtime_version} + 1))" ]] || {
  say "Go 二进制版本与发布包不一致；拒绝继续。" \
      "Go binary version does not match the release; refusing to continue." >&2
  exit 1
}

# 当通过 `curl ... | sudo /bin/bash -p` 调用时，stdin 是脚本流而不是用户终端。
# 因此只在最终执行 Go 子命令时重定向到 /dev/tty，避免校验后卡住。
# When invoked as `curl ... | sudo /bin/bash -p`, stdin is the script stream, not the
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
    say "请使用非交互模式，例如：/bin/bash -p sun.sh install --non-interactive -y ..." \
        "Run a non-interactive mode, for example: /bin/bash -p sun.sh install --non-interactive -y ..." >&2
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
    if ! read_tty_line "$(m '请输入选项 [1-4/0]: ' 'Enter choice [1-4/0]: ')"; then
      say "已取消。" "Cancelled." >&2
      exit 2
    fi
    choice="$SUN_TTY_LINE"
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
        if ! read_tty_line "$(m '请输入选项 [1/2/0]: ' 'Enter choice [1/2/0]: ')"; then
          say "已取消。" "Cancelled." >&2
          exit 2
        fi
        uninstall_choice="$SUN_TTY_LINE"
        case "$uninstall_choice" in
          1)
            if confirm_tty_exact YES "$(m '输入 YES 确认卸载并保留配置: ' 'Type YES to uninstall and keep configuration: ')"; then
              run_go uninstall
            else
              confirm_rc=$?
              [[ "$confirm_rc" -eq 1 ]] || { say "已取消。" "Cancelled." >&2; exit 2; }
              continue
            fi
            ;;
          2)
            if confirm_tty_exact PURGE "$(m '这会恢复 SUN 受管的 apt/dnf 自动更新配置，并删除 SUN 配置、通知凭据、状态、升级备份和日志。输入 PURGE 确认: ' 'This restores SUN-managed apt/dnf automatic-update configuration and removes SUN configuration, notification credentials, state, upgrade backups, and logs. Type PURGE to confirm: ')"; then
              run_go uninstall --purge-config
            else
              confirm_rc=$?
              [[ "$confirm_rc" -eq 1 ]] || { say "已取消。" "Cancelled." >&2; exit 2; }
              continue
            fi
            ;;
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
        if ! read_tty_line "$(m '请输入选项 [1/2/3/4/0]: ' 'Enter choice [1/2/3/4/0]: ')"; then
          say "已取消。" "Cancelled." >&2
          exit 2
        fi
        check_choice="$SUN_TTY_LINE"
        case "$check_choice" in
          1) run_go doctor ;;
          2) run_go check-upgrade ;;
          3)
            if confirm_tty_yes_no "$(m '此操作将发送测试通知，是否继续？[y/N]: ' 'This action will send a test notification. Continue? [y/N]: ')"; then
              run_go test --send-test --no-dedupe
            else
              confirm_rc=$?
              [[ "$confirm_rc" -eq 1 ]] || { say "已取消。" "Cancelled." >&2; exit 2; }
              continue
            fi
            ;;
          4)
            if confirm_tty_yes_no "$(m '此操作将发送测试通知，是否继续？[y/N]: ' 'This action will send a test notification. Continue? [y/N]: ')"; then
              run_go test --simulate-reboot --no-dedupe
            else
              confirm_rc=$?
              [[ "$confirm_rc" -eq 1 ]] || { say "已取消。" "Cancelled." >&2; exit 2; }
              continue
            fi
            ;;
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
