#!/usr/bin/env bash
set -euo pipefail

PURGE_CONFIG=0
usage(){ echo "Usage: sudo ./uninstall.sh [--purge-config]"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-config) PURGE_CONFIG=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ "$(id -u)" -eq 0 ]] || { echo "Please run as root" >&2; exit 1; }

systemctl disable --now security-update-notify.timer 2>/dev/null || true
rm -f /etc/systemd/system/security-update-notify.service /etc/systemd/system/security-update-notify.timer
rm -f /etc/logrotate.d/security-update-notify
rm -f /usr/local/sbin/security-update-notify
systemctl daemon-reload

if [[ "$PURGE_CONFIG" -eq 1 ]]; then
  rm -rf /etc/security-update-notify /var/lib/security-update-notify /var/log/security-update-notify.log /etc/logrotate.d/security-update-notify
  rm -f /etc/apt/apt.conf.d/52unattended-upgrades-local
  rm -f /etc/needrestart/conf.d/99-security-update-notify-report-only.conf
  echo "Removed config/state too. Note: packages and /etc/apt/apt.conf.d/20auto-upgrades were left in place."
  ls /etc/dnf/automatic.conf.bak.* >/dev/null 2>&1 && echo "Note: /etc/dnf/automatic.conf backups remain; remove manually if desired." || true
fi

echo "Uninstalled security-update-notify."
