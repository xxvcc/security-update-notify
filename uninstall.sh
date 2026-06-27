#!/usr/bin/env bash
set -euo pipefail

# 双语输出助手：UI_LANG=zh|en 决定终端显示语言（默认 zh）。
# Bilingual output helper: UI_LANG=zh|en selects the terminal language (default zh).
m()  { if [ "${UI_LANG:-zh}" = en ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
say(){ if [ "${UI_LANG:-zh}" = en ]; then printf '%s\n' "$2"; else printf '%s\n' "$1"; fi; }

PURGE_CONFIG=0
usage(){ say "用法: sudo ./uninstall.sh [--purge-config] [--lang zh|en]" "Usage: sudo ./uninstall.sh [--purge-config] [--lang zh|en]"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-config) PURGE_CONFIG=1; shift ;;
    --lang) [[ -n "${2:-}" ]] || { say "缺少 --lang 的值" "Missing value for --lang" >&2; exit 2; }; UI_LANG="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf '%s\n' "未知参数 / Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
UI_LANG="${UI_LANG:-${SUN_LANG:-}}"
case "${UI_LANG:-}" in zh|en) ;; *) UI_LANG=zh ;; esac
[[ "$(id -u)" -eq 0 ]] || { say "请以 root 运行" "Please run as root" >&2; exit 1; }

systemctl disable --now security-update-notify.timer 2>/dev/null || true
rm -f /etc/systemd/system/security-update-notify.service /etc/systemd/system/security-update-notify.timer
rm -f /etc/logrotate.d/security-update-notify
rm -f /usr/local/sbin/security-update-notify
systemctl daemon-reload

if [[ "$PURGE_CONFIG" -eq 1 ]]; then
  rm -rf /etc/security-update-notify /var/lib/security-update-notify /etc/logrotate.d/security-update-notify /var/backups/security-update-notify
  rm -f /var/log/security-update-notify.log /var/log/security-update-notify.log.*
  if [[ -f /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak ]]; then
    cp -a /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak /etc/apt/apt.conf.d/20auto-upgrades
    rm -f /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak
    say "已从 security-update-notify 备份恢复 /etc/apt/apt.conf.d/20auto-upgrades。" "Restored /etc/apt/apt.conf.d/20auto-upgrades from security-update-notify backup."
  fi
  rm -f /etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify
  rm -f /etc/apt/apt.conf.d/52unattended-upgrades-local
  rm -f /etc/needrestart/conf.d/99-security-update-notify-report-only.conf
  latest_dnf_backup=""
  if compgen -G '/etc/dnf/automatic.conf.security-update-notify.bak.*' >/dev/null; then
    latest_dnf_backup="$(find /etc/dnf -maxdepth 1 -type f -name 'automatic.conf.security-update-notify.bak.*' -printf '%T@ %p\n' | sort -rn | awk 'NR==1 {sub(/^[^ ]+ /, ""); print}')"
  elif compgen -G '/etc/dnf/automatic.conf.bak.*' >/dev/null; then
    latest_dnf_backup="$(find /etc/dnf -maxdepth 1 -type f -name 'automatic.conf.bak.*' -printf '%T@ %p\n' | sort -rn | awk 'NR==1 {sub(/^[^ ]+ /, ""); print}')"
    say "警告：使用旧版 dnf 备份命名恢复；新版本会使用 security-update-notify 专用备份名。" "WARN: using legacy dnf backup naming for restore; newer versions use a security-update-notify-specific backup name."
  fi
  if [[ -n "$latest_dnf_backup" ]]; then
    cp -a "$latest_dnf_backup" /etc/dnf/automatic.conf
    say "已从 $latest_dnf_backup 恢复 /etc/dnf/automatic.conf。" "Restored /etc/dnf/automatic.conf from $latest_dnf_backup."
  fi
  say "已同时删除配置、状态与升级备份（含 token 副本）；作为依赖安装的软件包已保留。" "Removed config, state, and upgrade backups (which held token copies). Packages installed as dependencies were left in place."
fi

say "已卸载 security-update-notify。" "Uninstalled security-update-notify."
