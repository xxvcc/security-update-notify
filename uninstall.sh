#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 共用辅助函数：m/say 双语输出等。
# shellcheck source=files/lib.sh
. "$SCRIPT_DIR/files/lib.sh"

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
rm -f /etc/systemd/system/security-update-notify.service.d/credentials.conf
rmdir /etc/systemd/system/security-update-notify.service.d 2>/dev/null || true
rm -f /etc/logrotate.d/security-update-notify
rm -f /usr/local/sbin/security-update-notify
# 加 || true：在无 systemd 总线的环境（容器/降级 init）daemon-reload 会非零退出；若不容错，set -e
# 会在此中止，使后面的 --purge-config 不执行、telegram.env（含 token）残留磁盘。
systemctl daemon-reload || true

if [[ "$PURGE_CONFIG" -eq 1 ]]; then
  rm -rf /etc/security-update-notify /var/lib/security-update-notify /etc/logrotate.d/security-update-notify /var/backups/security-update-notify
  rm -f /etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred
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
  say "已同时删除配置、通知凭据、状态与升级备份（含 token 副本）；作为依赖安装的软件包已保留。" "Removed config, notification credentials, state, and upgrade backups (which held token copies). Packages installed as dependencies were left in place."
fi

say "已卸载 security-update-notify。" "Uninstalled security-update-notify."
