#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 共用辅助函数：m/say 双语输出、os-release 读取、后端检测。
# shellcheck source=files/lib.sh
. "$SCRIPT_DIR/files/lib.sh"

SEND_TEST=0; SIMULATE_REBOOT=0; NO_DEDUPE=0
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
usage(){
  if [ "${UI_LANG:-zh}" = en ]; then
    cat <<'EOU'
Usage: sudo ./test.sh [options]
  --send-test        Send a normal OK Telegram test message
  --simulate-reboot  Send a simulated reboot-required alert; does not reboot
  --no-dedupe        Bypass duplicate-alert suppression for this test
  --verbose          Show full Telegram chat ID in diagnostics
  --lang zh|en       Terminal language
EOU
  else
    cat <<'EOU'
用法: sudo ./test.sh [选项]
  --send-test        发送普通 OK Telegram 测试消息
  --simulate-reboot  发送模拟“需要重启”提醒；不会真的重启
  --no-dedupe        本次测试绕过去重抑制
  --verbose          诊断中显示完整 Telegram Chat ID
  --lang zh|en       终端语言
EOU
  fi
}
VERBOSE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --send-test) SEND_TEST=1; shift ;;
    --simulate-reboot) SIMULATE_REBOOT=1; shift ;;
    --no-dedupe) NO_DEDUPE=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    --lang) [[ -n "${2:-}" ]] || { say "缺少 --lang 的值" "Missing value for --lang" >&2; exit 2; }; UI_LANG="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf '%s\n' "未知参数 / Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
UI_LANG="${UI_LANG:-${SUN_LANG:-}}"
case "${UI_LANG:-}" in zh|en) ;; *) UI_LANG=zh ;; esac
[[ "$(id -u)" -eq 0 ]] || { say "请以 root 运行" "Please run as root" >&2; exit 1; }

[[ -r /etc/os-release ]] || { say "错误：无法读取 /etc/os-release" "ERROR: /etc/os-release not readable" >&2; exit 1; }
lib_read_os_release
lib_detect_backend
BACKEND="$LIB_BACKEND"; SUPPORT="$LIB_SUPPORT"

say "== 操作系统 ==" "== OS =="; sed -n '1,8p' /etc/os-release; say "支持状态: $SUPPORT" "Support: $SUPPORT"; say "后端: $BACKEND" "Backend: $BACKEND"; [[ -d /run/systemd/system ]] && say "systemd: 是" "systemd: yes" || say "systemd: 否" "systemd: no"; echo

say "== 软件包 ==" "== packages =="
if [[ "$BACKEND" == apt ]]; then
  for pkg in unattended-upgrades needrestart apt-listchanges python3 ca-certificates; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then ver="$(dpkg-query -W -f='${Version}' "$pkg")"; say "正常 $pkg $ver" "OK $pkg $ver"; else say "缺失 $pkg" "MISSING $pkg"; fi
  done
elif [[ "$BACKEND" == dnf ]]; then
  for pkg in dnf-automatic python3 ca-certificates yum-utils dnf-utils; do rpm -q "$pkg" >/dev/null 2>&1 && say "正常 $(rpm -q "$pkg")" "OK $(rpm -q "$pkg")" || true; done
  command -v needs-restarting >/dev/null && say "正常 needs-restarting present" "OK needs-restarting present" || say "缺失 needs-restarting" "MISSING needs-restarting"
else
  say "不支持的后端" "Unsupported backend"
fi
echo

say "== 配置文件 ==" "== config files =="
for f in /etc/security-update-notify/telegram.env /usr/local/sbin/security-update-notify /etc/systemd/system/security-update-notify.service /etc/systemd/system/security-update-notify.timer /var/log/security-update-notify.log /etc/logrotate.d/security-update-notify; do
  [[ -e "$f" ]] && stat -c "$(m '正常 ' 'OK ')%a %U:%G %n" "$f" || say "缺失 $f" "MISSING $f"
done
[[ "$BACKEND" == apt ]] && for f in /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify /etc/needrestart/conf.d/99-security-update-notify-report-only.conf; do [[ -e "$f" ]] && stat -c "$(m '正常 ' 'OK ')%a %U:%G %n" "$f" || say "缺失 $f" "MISSING $f"; done
[[ "$BACKEND" == dnf && -e /etc/dnf/automatic.conf ]] && stat -c "$(m '正常 ' 'OK ')%a %U:%G %n" /etc/dnf/automatic.conf
echo

say "== 语法和 systemd ==" "== syntax and systemd =="
bash -n /usr/local/sbin/security-update-notify && say "正常：脚本语法通过" "OK script syntax"
/usr/local/sbin/security-update-notify --version
/usr/local/sbin/security-update-notify --doctor --skip-telegram --lang "$UI_LANG"
systemd-analyze verify /etc/systemd/system/security-update-notify.service /etc/systemd/system/security-update-notify.timer >"$TMP_DIR/systemd-verify.log" 2>&1 && say "正常：systemd 单元通过" "OK systemd units" || { cat "$TMP_DIR/systemd-verify.log"; exit 1; }
echo

say "== 定时器 ==" "== timer =="; systemctl is-enabled security-update-notify.timer; systemctl list-timers security-update-notify.timer --no-pager; echo

say "== 重启/服务重启检测 ==" "== reboot/restart detection =="
if [[ "$BACKEND" == apt ]]; then
  [[ -f /var/run/reboot-required ]] && { say "需要重启=yes" "REBOOT_REQUIRED=yes"; cat /var/run/reboot-required.pkgs 2>/dev/null || true; } || say "需要重启=no" "REBOOT_REQUIRED=no"
  needrestart -b 2>&1 | sed -n '1,120p' || true
elif [[ "$BACKEND" == dnf ]]; then
  needs-restarting -r 2>&1 || true
  needs-restarting -s 2>&1 | sed -n '1,120p' || true
fi
echo

CONFIG=/etc/security-update-notify/telegram.env
if [[ ! -r "$CONFIG" ]]; then
  say "错误：配置文件不可读: /etc/security-update-notify/telegram.env" "ERROR: config file not readable: /etc/security-update-notify/telegram.env" >&2
  exit 1
fi

load_config_file() {
  local file="$1" line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    [[ "$line" == *"="* ]] || { say "配置行无效: $file" "Invalid config line in $file" >&2; return 2; }
    key="${line%%=*}"
    value="${line#*=}"
    key="${key//[[:space:]]/}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { say "配置键无效: $file: $key" "Invalid config key in $file: $key" >&2; return 2; }
    value="${value#${value%%[![:space:]]*}}"
    value="${value%${value##*[![:space:]]}}"
    if [[ "$value" != \"* && "$value" != \'* ]]; then
      value="${value%%[[:space:]]#*}"
      value="${value%${value##*[![:space:]]}}"
    fi
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then value="${value:1:${#value}-2}"; fi
    if [[ "$value" == \'*\' && "$value" == *\' ]]; then value="${value:1:${#value}-2}"; fi
    case "$key" in
      TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|HOST_LABEL|PUBLIC_IP|INCLUDE_PUBLIC_IP|NOTIFY_OK|NOTIFY_UPGRADE|DEDUP_MODE|DEDUP_INTERVAL_DAYS|NOTIFY_LANG|BACKEND|CONFIG_VERSION)
        printf -v "$key" '%s' "$value"
        ;;
      *) say "配置键不支持: $file: $key" "Unsupported config key in $file: $key" >&2; return 2 ;;
    esac
  done <"$file"
}

load_config_file "$CONFIG" || exit $?

telegram_get_me() {
  printf '%s' "${TELEGRAM_BOT_TOKEN:-}" | python3 -c '
import json, re, sys, urllib.request

token = sys.stdin.read()
if not token:
    print("缺少 TELEGRAM_BOT_TOKEN / missing TELEGRAM_BOT_TOKEN", file=sys.stderr)
    sys.exit(2)
if not re.match(r"^\d+:[A-Za-z0-9_-]+$", token):
    print("TELEGRAM_BOT_TOKEN 格式无效 / invalid TELEGRAM_BOT_TOKEN format", file=sys.stderr)
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

say "== Telegram 配置 ==" "== telegram config =="
[[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] && say "正常：token 已配置（${#TELEGRAM_BOT_TOKEN} 字符）" "OK token present (${#TELEGRAM_BOT_TOKEN} chars)" || say "缺失：token" "MISSING token"
if [[ -n "${TELEGRAM_CHAT_ID:-}" ]]; then
  if [[ "$VERBOSE" -eq 1 ]]; then
    say "正常：chat id 已配置: ${TELEGRAM_CHAT_ID}" "OK chat id present: ${TELEGRAM_CHAT_ID}"
  else
    chat_tail="${TELEGRAM_CHAT_ID: -4}"
    say "正常：chat id 已配置: ****${chat_tail}" "OK chat id present: ****${chat_tail}"
  fi
else
  say "缺失：chat id" "MISSING chat id"
fi
if [[ "${INCLUDE_PUBLIC_IP:-1}" =~ ^(1|true|yes|on)$ ]]; then
  if [[ -n "${PUBLIC_IP:-}" ]]; then
    say "公网 IP：使用手动配置: ${PUBLIC_IP}" "Public IP: using configured value: ${PUBLIC_IP}"
  else
    say "公网 IP：运行时自动获取" "Public IP: auto-detected at runtime"
  fi
else
  say "公网 IP：通知中不显示" "Public IP: not shown in notifications"
fi
telegram_get_me >/dev/null && say "正常：Telegram Bot Token 可用" "OK Telegram bot token works" || { say "错误：Telegram getMe 失败" "ERROR: Telegram getMe failed" >&2; exit 1; }

args=(); [[ "$NO_DEDUPE" -eq 1 ]] && args+=(--no-dedupe)
[[ "$SEND_TEST" -eq 1 ]] && { say "== 发送 OK 测试 ==" "== send OK test =="; /usr/local/sbin/security-update-notify --test-ok "${args[@]}"; say "正常：测试消息已发送" "OK sent test message"; }
[[ "$SIMULATE_REBOOT" -eq 1 ]] && { say "== 发送模拟重启提醒 ==" "== send simulated reboot alert =="; /usr/local/sbin/security-update-notify --test-reboot "${args[@]}"; say "正常：模拟重启提醒已发送" "OK sent simulated reboot alert"; }
say "所有检查已完成。" "All checks completed."
