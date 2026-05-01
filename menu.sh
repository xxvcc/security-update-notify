#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run as root, e.g. sudo ./menu.sh" >&2
  exit 1
fi

while true; do
  cat <<'MENU'

security-update-notify

请选择操作：
1) 安装 / 升级
2) 卸载
3) 检测 / 诊断
0) 退出
MENU
  read -r -p "请输入选项 [1-3/0]: " choice
  case "$choice" in
    1)
      exec "$SCRIPT_DIR/install.sh"
      ;;
    2)
      echo
      echo "卸载选项："
      echo "1) 只卸载程序，保留配置"
      echo "2) 卸载程序并删除配置/状态"
      echo "0) 返回"
      read -r -p "请输入选项 [1/2/0]: " u
      case "$u" in
        1) exec "$SCRIPT_DIR/uninstall.sh" ;;
        2) exec "$SCRIPT_DIR/uninstall.sh" --purge-config ;;
        0|'') continue ;;
        *) echo "无效选项" >&2 ;;
      esac
      ;;
    3)
      echo
      echo "检测选项："
      echo "1) 基础检测 / doctor"
      echo "2) 发送正常测试消息"
      echo "3) 发送模拟重启告警（不会真的重启）"
      echo "0) 返回"
      read -r -p "请输入选项 [1/2/3/0]: " t
      case "$t" in
        1) exec "$SCRIPT_DIR/test.sh" ;;
        2) exec "$SCRIPT_DIR/test.sh" --send-test --no-dedupe ;;
        3) exec "$SCRIPT_DIR/test.sh" --simulate-reboot --no-dedupe ;;
        0|'') continue ;;
        *) echo "无效选项" >&2 ;;
      esac
      ;;
    0) exit 0 ;;
    *) echo "无效选项" >&2 ;;
  esac
done
