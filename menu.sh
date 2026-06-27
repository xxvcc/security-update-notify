#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 共用辅助函数：m/say 双语输出等。
# shellcheck source=files/lib.sh
. "$SCRIPT_DIR/files/lib.sh"

if [[ "$(id -u)" -ne 0 ]]; then
  printf '%s\n' "请以 root 运行，例如 sudo ./menu.sh / Please run as root, e.g. sudo ./menu.sh" >&2
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lang) [[ -n "${2:-}" ]] || { say "缺少 --lang 的值" "Missing value for --lang" >&2; exit 2; }; UI_LANG="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# 第一步：选择语言（已通过 --lang / UI_LANG / SUN_LANG 指定则跳过）。
# First step: choose a language (skipped if already set via --lang / UI_LANG / SUN_LANG).
UI_LANG="${UI_LANG:-${SUN_LANG:-}}"
case "${UI_LANG:-}" in
  zh|en) ;;
  *)
    printf '%s\n' "请选择语言 / Choose a language:"
    printf '%s\n' "  1) 中文 (default)"
    printf '%s\n' "  2) English"
    read -r -p "[1]: " _lang_choice
    case "${_lang_choice:-1}" in 2) UI_LANG=en ;; *) UI_LANG=zh ;; esac
    ;;
esac
export UI_LANG

while true; do
  echo
  echo "security-update-notify"
  echo
  say "请选择操作：" "Choose an action:"
  say "1) 安装或升级" "1) Install or upgrade"
  say "2) 卸载" "2) Uninstall"
  say "3) 检查或诊断" "3) Check or diagnose"
  say "0) 退出" "0) Exit"
  read -r -p "$(m '请输入选项 [1-3/0]: ' 'Enter choice [1-3/0]: ')" choice
  case "$choice" in
    1)
      exec "$SCRIPT_DIR/install.sh"
      ;;
    2)
      echo
      say "卸载选项：" "Uninstall options:"
      say "1) 只移除程序，保留配置" "1) Remove program only, keep configuration"
      say "2) 移除程序并删除配置和状态" "2) Remove program and delete configuration/state"
      say "0) 返回" "0) Back"
      read -r -p "$(m '请输入选项 [1/2/0]: ' 'Enter choice [1/2/0]: ')" u
      case "$u" in
        1) exec "$SCRIPT_DIR/uninstall.sh" ;;
        2) exec "$SCRIPT_DIR/uninstall.sh" --purge-config ;;
        0|'') continue ;;
        *) say "无效选项" "Invalid choice" >&2 ;;
      esac
      ;;
    3)
      echo
      say "检查选项：" "Check options:"
      say "1) 基础检查或诊断" "1) Basic check or doctor"
      say "2) 检查是否有新版" "2) Check for upgrade"
      say "3) 发送普通测试消息" "3) Send normal test message"
      say "4) 发送模拟重启提醒（不会真的重启）" "4) Send simulated reboot alert (does not reboot)"
      say "0) 返回" "0) Back"
      read -r -p "$(m '请输入选项 [1/2/3/4/0]: ' 'Enter choice [1/2/3/4/0]: ')" t
      case "$t" in
        1) exec "$SCRIPT_DIR/test.sh" ;;
        2) exec /usr/local/sbin/security-update-notify --check-upgrade ;;
        3) exec "$SCRIPT_DIR/test.sh" --send-test --no-dedupe ;;
        4) exec "$SCRIPT_DIR/test.sh" --simulate-reboot --no-dedupe ;;
        0|'') continue ;;
        *) say "无效选项" "Invalid choice" >&2 ;;
      esac
      ;;
    0) exit 0 ;;
    *) say "无效选项" "Invalid choice" >&2 ;;
  esac
done
