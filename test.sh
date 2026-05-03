#!/usr/bin/env bash
set -euo pipefail

SEND_TEST=0; SIMULATE_REBOOT=0; NO_DEDUPE=0
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
usage(){ cat <<'EOU'
用法 / Usage: sudo ./test.sh [选项 / options]
  --send-test        发送普通 OK Telegram 测试消息 / Send a normal OK Telegram test message
  --simulate-reboot  发送模拟“需要重启”提醒；不会真的重启 / Send a simulated reboot-required alert; does not reboot
  --no-dedupe        本次测试绕过去重抑制 / Bypass duplicate-alert suppression for this test
  --verbose          诊断中显示完整 Telegram Chat ID / Show full Telegram chat ID in diagnostics
EOU
}
VERBOSE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --send-test) SEND_TEST=1; shift ;;
    --simulate-reboot) SIMULATE_REBOOT=1; shift ;;
    --no-dedupe) NO_DEDUPE=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数 / Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ "$(id -u)" -eq 0 ]] || { echo "请以 root 运行 / Please run as root" >&2; exit 1; }

[[ -r /etc/os-release ]] || { echo "错误：无法读取 /etc/os-release / ERROR /etc/os-release not readable" >&2; exit 1; }
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  case "$line" in
    ID=*|VERSION_ID=*|PRETTY_NAME=*)
      key="${line%%=*}"
      value="${line#*=}"
      if [[ "$value" == \"*\" && "$value" == *\" ]]; then value="${value:1:${#value}-2}"; fi
      if [[ "$value" == \'*\' && "$value" == *\' ]]; then value="${value:1:${#value}-2}"; fi
      case "$key" in ID|VERSION_ID|PRETTY_NAME) printf -v "$key" '%s' "$value" ;; esac
      ;;
  esac
done </etc/os-release
BACKEND="unknown"; SUPPORT="unsupported"
case "${ID:-}" in
  debian) BACKEND=apt; case "${VERSION_ID:-}" in 12|13) SUPPORT=supported ;; 11) SUPPORT=best-effort ;; esac ;;
  ubuntu) BACKEND=apt; case "${VERSION_ID:-}" in 22.04|24.04) SUPPORT=supported ;; 20.04) SUPPORT=best-effort ;; esac ;;
  rhel|rocky|almalinux) BACKEND=dnf; case "${VERSION_ID%%.*}" in 8|9) SUPPORT=supported ;; esac ;;
  fedora) BACKEND=dnf; SUPPORT=supported ;;
  centos) BACKEND=dnf; case "${VERSION_ID%%.*}" in 8|9) SUPPORT=best-effort ;; esac ;;
  amzn) BACKEND=dnf; case "${VERSION_ID:-}" in 2023) SUPPORT=best-effort ;; esac ;;
esac

echo "== 操作系统 / OS =="; sed -n '1,8p' /etc/os-release; echo "支持状态 / Support: $SUPPORT"; echo "后端 / Backend: $BACKEND"; [[ -d /run/systemd/system ]] && echo "systemd: 是 / yes" || echo "systemd: 否 / no"; echo

echo "== 软件包 / packages =="
if [[ "$BACKEND" == apt ]]; then
  for pkg in unattended-upgrades needrestart apt-listchanges python3 ca-certificates; do dpkg -s "$pkg" >/dev/null 2>&1 && echo "正常 / OK $pkg $(dpkg-query -W -f='${Version}' "$pkg")" || echo "缺失 / MISSING $pkg"; done
elif [[ "$BACKEND" == dnf ]]; then
  for pkg in dnf-automatic python3 ca-certificates yum-utils dnf-utils; do rpm -q "$pkg" >/dev/null 2>&1 && echo "正常 / OK $(rpm -q "$pkg")" || true; done
  command -v needs-restarting >/dev/null && echo "正常 / OK needs-restarting present" || echo "缺失 / MISSING needs-restarting"
else
  echo "不支持的后端 / Unsupported backend"
fi
echo

echo "== 配置文件 / config files =="
for f in /etc/security-update-notify/telegram.env /usr/local/sbin/security-update-notify /etc/systemd/system/security-update-notify.service /etc/systemd/system/security-update-notify.timer /var/log/security-update-notify.log /etc/logrotate.d/security-update-notify; do
  [[ -e "$f" ]] && stat -c '正常 / OK %a %U:%G %n' "$f" || echo "缺失 / MISSING $f"
done
[[ "$BACKEND" == apt ]] && for f in /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify /etc/needrestart/conf.d/99-security-update-notify-report-only.conf; do [[ -e "$f" ]] && stat -c '正常 / OK %a %U:%G %n' "$f" || echo "缺失 / MISSING $f"; done
[[ "$BACKEND" == dnf && -e /etc/dnf/automatic.conf ]] && stat -c '正常 / OK %a %U:%G %n' /etc/dnf/automatic.conf
echo

echo "== 语法和 systemd / syntax and systemd =="
bash -n /usr/local/sbin/security-update-notify && echo "正常：脚本语法通过 / OK script syntax"
/usr/local/sbin/security-update-notify --version
/usr/local/sbin/security-update-notify --doctor
systemd-analyze verify /etc/systemd/system/security-update-notify.service /etc/systemd/system/security-update-notify.timer >"$TMP_DIR/systemd-verify.log" 2>&1 && echo "正常：systemd 单元通过 / OK systemd units" || { cat "$TMP_DIR/systemd-verify.log"; exit 1; }
echo

echo "== 定时器 / timer =="; systemctl is-enabled security-update-notify.timer; systemctl list-timers security-update-notify.timer --no-pager; echo

echo "== 重启/服务重启检测 / reboot/restart detection =="
if [[ "$BACKEND" == apt ]]; then
  [[ -f /var/run/reboot-required ]] && { echo "REBOOT_REQUIRED / 需要重启=yes"; cat /var/run/reboot-required.pkgs 2>/dev/null || true; } || echo "REBOOT_REQUIRED / 需要重启=no"
  needrestart -b 2>&1 | sed -n '1,120p' || true
elif [[ "$BACKEND" == dnf ]]; then
  needs-restarting -r 2>&1 || true
  needs-restarting 2>&1 | sed -n '1,120p' || true
fi
echo

CONFIG=/etc/security-update-notify/telegram.env
if [[ ! -r "$CONFIG" ]]; then
  echo "错误：配置文件不可读 / ERROR config file not readable: /etc/security-update-notify/telegram.env" >&2
  exit 1
fi

load_config_file() {
  local file="$1" line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    [[ "$line" == *"="* ]] || { echo "配置行无效 / Invalid config line in $file" >&2; return 2; }
    key="${line%%=*}"
    value="${line#*=}"
    key="${key//[[:space:]]/}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo "配置键无效 / Invalid config key in $file: $key" >&2; return 2; }
    value="${value#${value%%[![:space:]]*}}"
    value="${value%${value##*[![:space:]]}}"
    if [[ "$value" != \"* && "$value" != \'* ]]; then
      value="${value%%[[:space:]]#*}"
      value="${value%${value##*[![:space:]]}}"
    fi
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then value="${value:1:${#value}-2}"; fi
    if [[ "$value" == \'*\' && "$value" == *\' ]]; then value="${value:1:${#value}-2}"; fi
    case "$key" in
      TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|HOST_LABEL|NOTIFY_OK|DEDUP_MODE|DEDUP_INTERVAL_DAYS|NOTIFY_LANG|BACKEND)
        printf -v "$key" '%s' "$value"
        ;;
      *) echo "配置键不支持 / Unsupported config key in $file: $key" >&2; return 2 ;;
    esac
  done <"$file"
}

load_config_file "$CONFIG" || exit $?

telegram_get_me() {
  printf '%s' "${TELEGRAM_BOT_TOKEN:-}" | python3 -c '
import json, sys, urllib.request

token = sys.stdin.read()
if not token:
    print("缺少 TELEGRAM_BOT_TOKEN / missing TELEGRAM_BOT_TOKEN", file=sys.stderr)
    sys.exit(2)

try:
    with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/getMe", timeout=20) as response:
        body = response.read().decode("utf-8", "replace")
except Exception as exc:
    print(exc, file=sys.stderr)
    sys.exit(1)

print(body)
try:
    ok = bool(json.loads(body).get("ok"))
except Exception:
    ok = False
sys.exit(0 if ok else 1)
'
}

echo "== Telegram 配置 / telegram config =="
[[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] && echo "正常：token 已配置（${#TELEGRAM_BOT_TOKEN} 字符）/ OK token present (${#TELEGRAM_BOT_TOKEN} chars)" || echo "缺失：token / MISSING token"
if [[ -n "${TELEGRAM_CHAT_ID:-}" ]]; then
  if [[ "$VERBOSE" -eq 1 ]]; then
    echo "正常：chat id 已配置 / OK chat id present: ${TELEGRAM_CHAT_ID}"
  else
    chat_tail="${TELEGRAM_CHAT_ID: -4}"
    echo "正常：chat id 已配置 / OK chat id present: ****${chat_tail}"
  fi
else
  echo "缺失：chat id / MISSING chat id"
fi
telegram_get_me >/dev/null && echo "正常：Telegram Bot Token 可用 / OK Telegram bot token works" || { echo "错误：Telegram getMe 失败 / ERROR Telegram getMe failed" >&2; exit 1; }

args=(); [[ "$NO_DEDUPE" -eq 1 ]] && args+=(--no-dedupe)
[[ "$SEND_TEST" -eq 1 ]] && { echo "== 发送 OK 测试 / send OK test =="; /usr/local/sbin/security-update-notify --test-ok "${args[@]}"; echo "正常：测试消息已发送 / OK sent test message"; }
[[ "$SIMULATE_REBOOT" -eq 1 ]] && { echo "== 发送模拟重启提醒 / send simulated reboot alert =="; /usr/local/sbin/security-update-notify --test-reboot "${args[@]}"; echo "正常：模拟重启提醒已发送 / OK sent simulated reboot alert"; }
echo "所有检查已完成。/ All checks completed."
