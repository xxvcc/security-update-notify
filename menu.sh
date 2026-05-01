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

Choose an action:
1) Install / upgrade
2) Uninstall
3) Check / diagnose
0) Exit
MENU
  read -r -p "Enter choice [1-3/0]: " choice
  case "$choice" in
    1)
      exec "$SCRIPT_DIR/install.sh"
      ;;
    2)
      echo
      echo "Uninstall options:"
      echo "1) Remove program only, keep configuration"
      echo "2) Remove program and delete configuration/state"
      echo "0) Back"
      read -r -p "Enter choice [1/2/0]: " u
      case "$u" in
        1) exec "$SCRIPT_DIR/uninstall.sh" ;;
        2) exec "$SCRIPT_DIR/uninstall.sh" --purge-config ;;
        0|'') continue ;;
        *) echo "Invalid choice" >&2 ;;
      esac
      ;;
    3)
      echo
      echo "Check options:"
      echo "1) Basic check / doctor"
      echo "2) Send normal test message"
      echo "3) Send simulated reboot alert (does not reboot)"
      echo "0) Back"
      read -r -p "Enter choice [1/2/3/0]: " t
      case "$t" in
        1) exec "$SCRIPT_DIR/test.sh" ;;
        2) exec "$SCRIPT_DIR/test.sh" --send-test --no-dedupe ;;
        3) exec "$SCRIPT_DIR/test.sh" --simulate-reboot --no-dedupe ;;
        0|'') continue ;;
        *) echo "Invalid choice" >&2 ;;
      esac
      ;;
    0) exit 0 ;;
    *) echo "Invalid choice" >&2 ;;
  esac
done
