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
  if [[ -f /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak ]]; then
    cp -a /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak /etc/apt/apt.conf.d/20auto-upgrades
    rm -f /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak
    echo "Restored /etc/apt/apt.conf.d/20auto-upgrades from security-update-notify backup."
  fi
  rm -f /etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify
  rm -f /etc/apt/apt.conf.d/52unattended-upgrades-local
  rm -f /etc/needrestart/conf.d/99-security-update-notify-report-only.conf
  latest_dnf_backup="$(ls -1t /etc/dnf/automatic.conf.bak.* 2>/dev/null | head -1 || true)"
  if [[ -n "$latest_dnf_backup" ]]; then
    cp -a "$latest_dnf_backup" /etc/dnf/automatic.conf
    echo "Restored /etc/dnf/automatic.conf from $latest_dnf_backup."
  fi
  echo "Removed config/state too. Packages installed as dependencies were left in place."
fi

echo "Uninstalled security-update-notify."
