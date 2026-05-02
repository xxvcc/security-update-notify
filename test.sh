#!/usr/bin/env bash
set -euo pipefail

SEND_TEST=0; SIMULATE_REBOOT=0; NO_DEDUPE=0
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
usage(){ cat <<'EOU'
Usage: sudo ./test.sh [options]
  --send-test        Send a normal OK Telegram test message
  --simulate-reboot  Send a simulated reboot-required alert; does not reboot
  --no-dedupe        Bypass duplicate-alert suppression for this test
  --verbose          Show full Telegram chat ID in diagnostics
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
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ "$(id -u)" -eq 0 ]] || { echo "Please run as root" >&2; exit 1; }

. /etc/os-release
BACKEND="unknown"; SUPPORT="unsupported"
case "${ID:-}" in
  debian) BACKEND=apt; case "${VERSION_ID:-}" in 12|13) SUPPORT=supported ;; 11) SUPPORT=best-effort ;; esac ;;
  ubuntu) BACKEND=apt; case "${VERSION_ID:-}" in 22.04|24.04) SUPPORT=supported ;; 20.04) SUPPORT=best-effort ;; esac ;;
  rhel|rocky|almalinux) BACKEND=dnf; case "${VERSION_ID%%.*}" in 8|9) SUPPORT=supported ;; esac ;;
  fedora) BACKEND=dnf; SUPPORT=supported ;;
  centos) BACKEND=dnf; case "${VERSION_ID%%.*}" in 8|9) SUPPORT=best-effort ;; esac ;;
  amzn) BACKEND=dnf; case "${VERSION_ID:-}" in 2023) SUPPORT=best-effort ;; esac ;;
esac

echo "== OS =="; sed -n '1,8p' /etc/os-release; echo "Support: $SUPPORT"; echo "Backend: $BACKEND"; [[ -d /run/systemd/system ]] && echo "systemd: yes" || echo "systemd: no"; echo

echo "== packages =="
if [[ "$BACKEND" == apt ]]; then
  for pkg in unattended-upgrades needrestart apt-listchanges python3 ca-certificates; do dpkg -s "$pkg" >/dev/null 2>&1 && echo "OK $pkg $(dpkg-query -W -f='${Version}' "$pkg")" || echo "MISSING $pkg"; done
elif [[ "$BACKEND" == dnf ]]; then
  for pkg in dnf-automatic python3 ca-certificates yum-utils dnf-utils; do rpm -q "$pkg" >/dev/null 2>&1 && echo "OK $(rpm -q "$pkg")" || true; done
  command -v needs-restarting >/dev/null && echo "OK needs-restarting present" || echo "MISSING needs-restarting"
else
  echo "Unsupported backend"
fi
echo

echo "== config files =="
for f in /etc/security-update-notify/telegram.env /usr/local/sbin/security-update-notify /etc/systemd/system/security-update-notify.service /etc/systemd/system/security-update-notify.timer /var/log/security-update-notify.log /etc/logrotate.d/security-update-notify; do
  [[ -e "$f" ]] && stat -c 'OK %a %U:%G %n' "$f" || echo "MISSING $f"
done
[[ "$BACKEND" == apt ]] && for f in /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify /etc/needrestart/conf.d/99-security-update-notify-report-only.conf; do [[ -e "$f" ]] && stat -c 'OK %a %U:%G %n' "$f" || echo "MISSING $f"; done
[[ "$BACKEND" == dnf && -e /etc/dnf/automatic.conf ]] && stat -c 'OK %a %U:%G %n' /etc/dnf/automatic.conf
echo

echo "== syntax/systemd =="
bash -n /usr/local/sbin/security-update-notify && echo "OK script syntax"
/usr/local/sbin/security-update-notify --version
/usr/local/sbin/security-update-notify --doctor
systemd-analyze verify /etc/systemd/system/security-update-notify.service /etc/systemd/system/security-update-notify.timer >"$TMP_DIR/systemd-verify.log" 2>&1 && echo "OK systemd units" || { cat "$TMP_DIR/systemd-verify.log"; exit 1; }
echo

echo "== timer =="; systemctl is-enabled security-update-notify.timer; systemctl list-timers security-update-notify.timer --no-pager; echo

echo "== reboot/restart detection =="
if [[ "$BACKEND" == apt ]]; then
  [[ -f /var/run/reboot-required ]] && { echo REBOOT_REQUIRED=yes; cat /var/run/reboot-required.pkgs 2>/dev/null || true; } || echo REBOOT_REQUIRED=no
  needrestart -b 2>&1 | sed -n '1,120p' || true
elif [[ "$BACKEND" == dnf ]]; then
  needs-restarting -r 2>&1 || true
  needs-restarting 2>&1 | sed -n '1,120p' || true
fi
echo

CONFIG=/etc/security-update-notify/telegram.env
if [[ ! -r "$CONFIG" ]]; then
  echo "ERROR config file not readable: /etc/security-update-notify/telegram.env" >&2
  exit 1
fi

load_config_file() {
  local file="$1" line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    [[ "$line" == *"="* ]] || { echo "Invalid config line in $file" >&2; return 2; }
    key="${line%%=*}"
    value="${line#*=}"
    key="${key//[[:space:]]/}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo "Invalid config key in $file: $key" >&2; return 2; }
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
      *) echo "Unsupported config key in $file: $key" >&2; return 2 ;;
    esac
  done <"$file"
}

load_config_file "$CONFIG" || exit $?

telegram_get_me() {
  printf '%s' "${TELEGRAM_BOT_TOKEN:-}" | python3 -c '
import json, sys, urllib.request

token = sys.stdin.read()
if not token:
    print("missing TELEGRAM_BOT_TOKEN", file=sys.stderr)
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

echo "== telegram config =="
[[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] && echo "OK token present (${#TELEGRAM_BOT_TOKEN} chars)" || echo "MISSING token"
if [[ -n "${TELEGRAM_CHAT_ID:-}" ]]; then
  if [[ "$VERBOSE" -eq 1 ]]; then
    echo "OK chat id present: ${TELEGRAM_CHAT_ID}"
  else
    chat_tail="${TELEGRAM_CHAT_ID: -4}"
    echo "OK chat id present: ****${chat_tail}"
  fi
else
  echo "MISSING chat id"
fi
telegram_get_me >/dev/null && echo "OK Telegram bot token works" || { echo "ERROR Telegram getMe failed" >&2; exit 1; }

args=(); [[ "$NO_DEDUPE" -eq 1 ]] && args+=(--no-dedupe)
[[ "$SEND_TEST" -eq 1 ]] && { echo "== send OK test =="; /usr/local/sbin/security-update-notify --test-ok "${args[@]}"; echo "OK sent test message"; }
[[ "$SIMULATE_REBOOT" -eq 1 ]] && { echo "== send simulated reboot alert =="; /usr/local/sbin/security-update-notify --test-reboot "${args[@]}"; echo "OK sent simulated reboot alert"; }
echo "All checks completed."
