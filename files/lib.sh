# shellcheck shell=bash
# files/lib.sh — security-update-notify 安装/菜单/测试/卸载脚本共用的辅助函数。
# 仅供解包后运行的脚本 source；运行时二进制(/usr/local/sbin/security-update-notify)与 sun.sh
# 引导脚本刻意自包含（前者单文件安装、后者在解包前运行），不引用本文件。
# Shared helpers for the install/menu/test/uninstall scripts. Sourced only by scripts that run from the
# extracted package. The runtime binary and the sun.sh bootstrap are intentionally self-contained
# (the former is installed as a single file, the latter runs before extraction) and do NOT use this file.

# 双语输出：UI_LANG=zh|en 决定终端语言（默认 zh）。m 不换行，say 换行。
# Bilingual output: UI_LANG=zh|en selects the terminal language (default zh). m: no newline, say: newline.
m()  { if [ "${UI_LANG:-zh}" = en ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
say(){ if [ "${UI_LANG:-zh}" = en ]; then printf '%s\n' "$2"; else printf '%s\n' "$1"; fi; }

# 读取 /etc/os-release，设置全局 ID / VERSION_ID / PRETTY_NAME / ID_LIKE（缺文件则全为空）。
# Read /etc/os-release into globals ID / VERSION_ID / PRETTY_NAME / ID_LIKE (all empty if absent).
lib_read_os_release() {
  ID=""; VERSION_ID=""; PRETTY_NAME=""; ID_LIKE=""
  [[ -r /etc/os-release ]] || return 0
  local line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    case "$line" in
      ID=*|VERSION_ID=*|PRETTY_NAME=*|ID_LIKE=*)
        key="${line%%=*}"
        value="${line#*=}"
        if [[ "$value" == \"*\" && "$value" == *\" ]]; then value="${value:1:${#value}-2}"; fi
        if [[ "$value" == \'*\' && "$value" == *\' ]]; then value="${value:1:${#value}-2}"; fi
        case "$key" in ID|VERSION_ID|PRETTY_NAME|ID_LIKE) printf -v "$key" '%s' "$value" ;; esac
        ;;
    esac
  done </etc/os-release
}

# 由 ID/VERSION_ID/ID_LIKE 判定后端与支持级别，设置：
#   LIB_BACKEND  = apt | dnf | unknown
#   LIB_SUPPORT  = supported | best-effort | unsupported
# 衍生发行版（Oracle Linux/CloudLinux 等）用 ID_LIKE 兜底后端。
# Map ID/VERSION_ID/ID_LIKE to LIB_BACKEND (apt|dnf|unknown) and LIB_SUPPORT
# (supported|best-effort|unsupported); derivatives fall back to ID_LIKE for the backend.
lib_detect_backend() {
  LIB_BACKEND="unknown"; LIB_SUPPORT="unsupported"
  case "${ID:-}" in
    debian) LIB_BACKEND="apt"; case "${VERSION_ID:-}" in 12|13) LIB_SUPPORT="supported" ;; 11) LIB_SUPPORT="best-effort" ;; esac ;;
    ubuntu) LIB_BACKEND="apt"; case "${VERSION_ID:-}" in 22.04|24.04) LIB_SUPPORT="supported" ;; 20.04) LIB_SUPPORT="best-effort" ;; esac ;;
    rhel|rocky|almalinux) LIB_BACKEND="dnf"; case "${VERSION_ID%%.*}" in 8|9) LIB_SUPPORT="supported" ;; esac ;;
    fedora) LIB_BACKEND="dnf"; LIB_SUPPORT="supported" ;;
    centos) LIB_BACKEND="dnf"; case "${VERSION_ID%%.*}" in 8|9) LIB_SUPPORT="best-effort" ;; esac ;;
    amzn) LIB_BACKEND="dnf"; case "${VERSION_ID:-}" in 2023) LIB_SUPPORT="best-effort" ;; esac ;;
  esac
  if [[ "$LIB_BACKEND" == "unknown" && -n "${ID_LIKE:-}" ]]; then
    case " $ID_LIKE " in
      *" debian "*|*" ubuntu "*) LIB_BACKEND="apt" ;;
      *" rhel "*|*" fedora "*|*" centos "*) LIB_BACKEND="dnf" ;;
    esac
  fi
}
