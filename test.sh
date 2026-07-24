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
  --send-test        Send a normal OK message to configured channels
  --simulate-reboot  Send a simulated reboot-required alert; does not reboot
  --no-dedupe        Bypass duplicate-alert suppression for this test
  --verbose          Show full recipient IDs in diagnostics
  --lang zh|en       Terminal language
EOU
  else
    cat <<'EOU'
用法: sudo ./test.sh [选项]
  --send-test        向已配置渠道发送普通 OK 测试消息
  --simulate-reboot  发送模拟“需要重启”提醒；不会真的重启
  --no-dedupe        本次测试绕过去重抑制
  --verbose          诊断中显示完整接收人 ID
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
  for pkg in dnf-automatic python3 ca-certificates yum-utils dnf-utils; do if rpm -q "$pkg" >/dev/null 2>&1; then say "正常 $(rpm -q "$pkg")" "OK $(rpm -q "$pkg")"; else say "缺失 $pkg" "MISSING $pkg"; fi; done
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
# 安装的运行时可能是 Go 二进制（主运行时）或 bash 脚本（冷门架构兜底）。只有 bash 脚本才做语法检查；
# 对 Go 二进制跑 bash -n 会报“cannot execute binary file”并跳过 OK 行。按 shebang 判别。
if [[ -e /usr/local/sbin/security-update-notify ]] && head -c2 /usr/local/sbin/security-update-notify 2>/dev/null | grep -q '#!'; then
  bash -n /usr/local/sbin/security-update-notify && say "正常：脚本语法通过" "OK script syntax"
else
  say "跳过：Go 二进制运行时，无需脚本语法检查" "SKIP Go binary runtime; no script syntax check"
fi
/usr/local/sbin/security-update-notify --version
/usr/local/sbin/security-update-notify --doctor --lang "$UI_LANG"
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
      NOTIFY_CHANNELS|TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|FEISHU_APP_ID|FEISHU_RECEIVE_ID|HOST_LABEL|PUBLIC_IP|INCLUDE_PUBLIC_IP|NOTIFY_OK|NOTIFY_UPGRADE|DEDUP_MODE|DEDUP_INTERVAL_DAYS|NOTIFY_LANG|BACKEND|CONFIG_VERSION|CHECK_UPDATE_HEALTH|STALE_UPDATE_DAYS|CHECK_EOL)
        printf -v "$key" '%s' "$value"
        ;;
      *) say "配置键不支持: $file: $key" "Unsupported config key in $file: $key" >&2; return 2 ;;
    esac
  done <"$file"
}

load_config_file "$CONFIG" || exit $?
NOTIFY_CHANNELS="${NOTIFY_CHANNELS:-telegram}"

channel_selected() {
  case ",${NOTIFY_CHANNELS}," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

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

say "== 通知配置 ==" "== notification config =="
say "渠道: $NOTIFY_CHANNELS" "Channels: $NOTIFY_CHANNELS"
if channel_selected telegram; then
  [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] && say "正常：Telegram token 已配置（${#TELEGRAM_BOT_TOKEN} 字符）" "OK Telegram token present (${#TELEGRAM_BOT_TOKEN} chars)" || say "缺失：Telegram token" "MISSING Telegram token"
  if [[ -n "${TELEGRAM_CHAT_ID:-}" ]]; then
    if [[ "$VERBOSE" -eq 1 ]]; then
      say "正常：Telegram chat id 已配置: ${TELEGRAM_CHAT_ID}" "OK Telegram chat id present: ${TELEGRAM_CHAT_ID}"
    else
      chat_tail="${TELEGRAM_CHAT_ID: -4}"
      say "正常：Telegram chat id 已配置: ****${chat_tail}" "OK Telegram chat id present: ****${chat_tail}"
    fi
  else
    say "缺失：Telegram chat id" "MISSING Telegram chat id"
  fi
fi
if channel_selected feishu; then
  [[ -n "${FEISHU_APP_ID:-}" ]] && say "正常：飞书 App ID 已配置" "OK Feishu App ID present" || say "缺失：飞书 App ID" "MISSING Feishu App ID"
  if [[ -n "${FEISHU_RECEIVE_ID:-}" ]]; then
    if [[ "$VERBOSE" -eq 1 ]]; then
      say "正常：飞书 open_id 已配置: ${FEISHU_RECEIVE_ID}" "OK Feishu open_id present: ${FEISHU_RECEIVE_ID}"
    else
      receive_tail="${FEISHU_RECEIVE_ID: -4}"
      say "正常：飞书 open_id 已配置: ****${receive_tail}" "OK Feishu open_id present: ****${receive_tail}"
    fi
  else
    say "缺失：飞书 open_id" "MISSING Feishu open_id"
  fi
  if [[ -r /etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred ]]; then
    say "正常：飞书加密 systemd credential 存在" "OK encrypted Feishu systemd credential present"
  elif [[ -r /etc/security-update-notify/credentials/feishu-app-secret ]]; then
    say "正常：飞书 root-only 凭据文件存在" "OK root-only Feishu credential file present"
  else
    say "缺失：飞书 App Secret 凭据" "MISSING Feishu App Secret credential"
  fi
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
args=(); [[ "$NO_DEDUPE" -eq 1 ]] && args+=(--no-dedupe)
[[ "$SEND_TEST" -eq 1 ]] && { say "== 发送 OK 测试 ==" "== send OK test =="; /usr/local/sbin/security-update-notify --test-ok "${args[@]}"; say "正常：测试消息已发送" "OK sent test message"; }
[[ "$SIMULATE_REBOOT" -eq 1 ]] && { say "== 发送模拟重启提醒 ==" "== send simulated reboot alert =="; /usr/local/sbin/security-update-notify --test-reboot "${args[@]}"; say "正常：模拟重启提醒已发送" "OK sent simulated reboot alert"; }
say "所有检查已完成。" "All checks completed."
