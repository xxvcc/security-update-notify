#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请以 root 运行，例如 sudo ./menu.sh / Please run as root, e.g. sudo ./menu.sh" >&2
  exit 1
fi

while true; do
  cat <<'MENU'

security-update-notify

请选择操作 / Choose an action:
1) 安装或升级 / Install or upgrade
2) 卸载 / Uninstall
3) 检查或诊断 / Check or diagnose
0) 退出 / Exit
MENU
  read -r -p "请输入选项 / Enter choice [1-3/0]: " choice
  case "$choice" in
    1)
      exec "$SCRIPT_DIR/install.sh"
      ;;
    2)
      echo
      echo "卸载选项 / Uninstall options:"
      echo "1) 只移除程序，保留配置 / Remove program only, keep configuration"
      echo "2) 移除程序并删除配置和状态 / Remove program and delete configuration/state"
      echo "0) 返回 / Back"
      read -r -p "请输入选项 / Enter choice [1/2/0]: " u
      case "$u" in
        1) exec "$SCRIPT_DIR/uninstall.sh" ;;
        2) exec "$SCRIPT_DIR/uninstall.sh" --purge-config ;;
        0|'') continue ;;
        *) echo "无效选项 / Invalid choice" >&2 ;;
      esac
      ;;
    3)
      echo
      echo "检查选项 / Check options:"
      echo "1) 基础检查或诊断 / Basic check or doctor"
      echo "2) 发送普通测试消息 / Send normal test message"
      echo "3) 发送模拟重启提醒（不会真的重启）/ Send simulated reboot alert (does not reboot)"
      echo "0) 返回 / Back"
      read -r -p "请输入选项 / Enter choice [1/2/3/0]: " t
      case "$t" in
        1) exec "$SCRIPT_DIR/test.sh" ;;
        2) exec "$SCRIPT_DIR/test.sh" --send-test --no-dedupe ;;
        3) exec "$SCRIPT_DIR/test.sh" --simulate-reboot --no-dedupe ;;
        0|'') continue ;;
        *) echo "无效选项 / Invalid choice" >&2 ;;
      esac
      ;;
    0) exit 0 ;;
    *) echo "无效选项 / Invalid choice" >&2 ;;
  esac
done
