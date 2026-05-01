#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK_TIME="${CHECK_TIME:-09:00}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
HOST_LABEL="${HOST_LABEL:-}"
DEDUP_MODE="${DEDUP_MODE:-}"
DEDUP_INTERVAL_DAYS="${DEDUP_INTERVAL_DAYS:-3}"
BACKEND="${BACKEND:-auto}"
SEND_TEST=0
SKIP_TELEGRAM_TEST=0
NON_INTERACTIVE=0
ASSUME_YES=0
ALLOW_BEST_EFFORT=0

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [options]

Options:
  --telegram-token TOKEN       Telegram bot token
  --telegram-chat-id CHAT_ID   Telegram target chat id
  --time HH:MM                 Daily check time, default 09:00
  --host-label NAME            Optional host label in notifications
  --dedup-mode MODE            always | daily | interval
  --dedup-interval-days N      Used when mode=interval, default 3
  --backend BACKEND            auto | apt | dnf, default auto
  --allow-best-effort          Permit best-effort distro versions
  --send-test                  Send additional test message after install
  --skip-telegram-test         Skip pre-install Telegram token/chat validation
  --non-interactive            Fail if required options are missing
  -y, --yes                    Do not prompt before installing packages
  -h, --help                   Show help
EOF
}

require_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || { echo "Missing value for $1" >&2; exit 2; }; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --telegram-token) require_arg "$1" "${2:-}"; TELEGRAM_BOT_TOKEN="$2"; shift 2 ;;
    --telegram-chat-id) require_arg "$1" "${2:-}"; TELEGRAM_CHAT_ID="$2"; shift 2 ;;
    --time) require_arg "$1" "${2:-}"; CHECK_TIME="$2"; shift 2 ;;
    --host-label) require_arg "$1" "${2:-}"; HOST_LABEL="$2"; shift 2 ;;
    --dedup-mode) require_arg "$1" "${2:-}"; DEDUP_MODE="$2"; shift 2 ;;
    --dedup-interval-days) require_arg "$1" "${2:-}"; DEDUP_INTERVAL_DAYS="$2"; shift 2 ;;
    --backend) require_arg "$1" "${2:-}"; BACKEND="$2"; shift 2 ;;
    --send-test) SEND_TEST=1; shift ;;
    --skip-telegram-test) SKIP_TELEGRAM_TEST=1; shift ;;
    --allow-best-effort) ALLOW_BEST_EFFORT=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

require_root() { [[ "$(id -u)" -eq 0 ]] || { echo "Please run as root, e.g. sudo ./install.sh" >&2; exit 1; }; }
shell_quote() { printf "%q" "$1"; }
prompt_secret() {
  local var_name="$1" prompt="$2" current
  set +u; current="${!var_name}"; set -u
  [[ -n "$current" ]] && return
  [[ "$NON_INTERACTIVE" -eq 1 ]] && { echo "Missing required option: $prompt" >&2; exit 2; }
  echo "$prompt (input is hidden; press Enter when done):"
  read -r -s current; echo
  while [[ -z "$current" ]]; do
    echo "$prompt cannot be empty. Input is still hidden; press Enter when done:"
    read -r -s current; echo
  done
  echo "$prompt received."
  printf -v "$var_name" '%s' "$current"
}
prompt_text() { local var_name="$1" prompt="$2" default="$3" current; set +u; current="${!var_name}"; set -u; [[ -n "$current" ]] && return; [[ "$NON_INTERACTIVE" -eq 1 ]] && { printf -v "$var_name" '%s' "$default"; return; }; read -r -p "$prompt [$default]: " current; printf -v "$var_name" '%s' "${current:-$default}"; }
prompt_required_text() { local var_name="$1" prompt="$2" current; set +u; current="${!var_name}"; set -u; [[ -n "$current" ]] && return; [[ "$NON_INTERACTIVE" -eq 1 ]] && { echo "Missing required option: $prompt" >&2; exit 2; }; while [[ -z "$current" ]]; do read -r -p "$prompt: " current; done; printf -v "$var_name" '%s' "$current"; }
valid_time() { [[ "$1" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; }

telegram_preflight() {
  [[ "$SKIP_TELEGRAM_TEST" -eq 1 ]] && { echo "Skipping Telegram preflight test."; return; }
  while true; do
    echo "Validating Telegram Bot Token..."
    local getme bot_user
    if ! getme="$(curl -fsS --connect-timeout 10 --max-time 20 "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getMe" 2>/tmp/security-update-notify-tg.err)"; then
      echo "❌ Telegram token validation failed."
      cat /tmp/security-update-notify-tg.err 2>/dev/null || true
    elif ! printf '%s' "$getme" | grep -q '"ok":true'; then
      echo "❌ Telegram token is invalid. Response: $getme"
    else
      bot_user="$(printf '%s' "$getme" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("result",{}).get("username", "unknown"))' 2>/dev/null || echo unknown)"
      echo "✅ Token is valid: @${bot_user}"
      echo "Sending test message to Telegram Chat ID..."
      local text="✅ security-update-notify Telegram test succeeded. Host: $(hostname -f 2>/dev/null || hostname)"
      if curl -fsS --connect-timeout 10 --max-time 20         -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"         -d "chat_id=${TELEGRAM_CHAT_ID}"         --data-urlencode "text=${text}" >/tmp/security-update-notify-send.out 2>/tmp/security-update-notify-tg.err; then
        echo "✅ Telegram test message sent."
        return
      else
        echo "❌ Telegram test message failed."
        cat /tmp/security-update-notify-tg.err 2>/dev/null || true
      fi
    fi
    cat <<'EOF'
Possible causes:
1. Bot token is wrong
2. Chat ID is wrong
3. You have not sent /start to the bot
4. The bot is not in the target group or cannot post there
5. This server cannot reach api.telegram.org
EOF
    if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
      echo "Non-interactive mode: Telegram preflight failed." >&2
      exit 2
    fi
    read -r -p "Re-enter Telegram token and chat ID? [Y/n]: " retry
    [[ "${retry:-Y}" =~ ^[Yy]$ ]] || { echo "Telegram preflight failed; aborting." >&2; exit 2; }
    TELEGRAM_BOT_TOKEN=""
    TELEGRAM_CHAT_ID=""
    prompt_secret TELEGRAM_BOT_TOKEN "Telegram Bot Token"
    prompt_required_text TELEGRAM_CHAT_ID "Telegram Chat ID"
  done
}

require_root
[[ -r /etc/os-release ]] || { echo "Missing /etc/os-release" >&2; exit 1; }
# shellcheck disable=SC1091
. /etc/os-release

SUPPORTED=0; SUPPORT_LABEL="unsupported"; DETECTED_BACKEND="unknown"
case "${ID:-}" in
  debian) DETECTED_BACKEND="apt"; case "${VERSION_ID:-}" in 12|13) SUPPORTED=1; SUPPORT_LABEL="supported" ;; 11) SUPPORTED=1; SUPPORT_LABEL="best-effort" ;; esac ;;
  ubuntu) DETECTED_BACKEND="apt"; case "${VERSION_ID:-}" in 22.04|24.04) SUPPORTED=1; SUPPORT_LABEL="supported" ;; 20.04) SUPPORTED=1; SUPPORT_LABEL="best-effort" ;; esac ;;
  rhel|rocky|almalinux) DETECTED_BACKEND="dnf"; case "${VERSION_ID%%.*}" in 8|9) SUPPORTED=1; SUPPORT_LABEL="supported" ;; esac ;;
  fedora) DETECTED_BACKEND="dnf"; SUPPORTED=1; SUPPORT_LABEL="supported" ;;
  centos) DETECTED_BACKEND="dnf"; case "${VERSION_ID%%.*}" in 8|9) SUPPORTED=1; SUPPORT_LABEL="best-effort" ;; esac ;;
  amzn) DETECTED_BACKEND="dnf"; case "${VERSION_ID:-}" in 2023) SUPPORTED=1; SUPPORT_LABEL="best-effort" ;; esac ;;
esac
[[ "$BACKEND" == "auto" ]] && BACKEND="$DETECTED_BACKEND"
case "$BACKEND" in apt|dnf) ;; *) echo "Invalid/unsupported backend: $BACKEND" >&2; exit 2 ;; esac

if [[ "$SUPPORTED" -ne 1 ]]; then
  cat >&2 <<EOF
Unsupported distribution: ID=${ID:-unknown} VERSION_ID=${VERSION_ID:-unknown}

Supported:
- Debian 12 / 13
- Ubuntu 22.04 / 24.04
- RHEL/Rocky/AlmaLinux 8 / 9
- Fedora current releases

Best effort:
- Debian 11
- Ubuntu 20.04
- CentOS Stream 8 / 9
- Amazon Linux 2023

This installer intentionally stops on unsupported distributions because update and reboot detection are distro-specific.
EOF
  exit 1
fi

if [[ "$SUPPORT_LABEL" == "best-effort" && "$ALLOW_BEST_EFFORT" -ne 1 ]]; then
  cat >&2 <<EOF
Detected ${PRETTY_NAME:-$ID $VERSION_ID}, which is best-effort support.
Re-run with --allow-best-effort if you explicitly want to install here.
EOF
  exit 1
fi

echo "Detected ${PRETTY_NAME:-$ID $VERSION_ID} ($SUPPORT_LABEL, backend=$BACKEND)."
[[ -d /run/systemd/system ]] || { echo "systemd is required; containers without systemd are not supported." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemctl is required" >&2; exit 1; }

# Telegram preflight needs curl/python3/CA roots even on fresh servers.
MINIMAL_PACKAGES=()
case "$BACKEND" in
  apt)
    for pkg in curl python3 ca-certificates; do dpkg -s "$pkg" >/dev/null 2>&1 || MINIMAL_PACKAGES+=("$pkg"); done
    if [[ "${#MINIMAL_PACKAGES[@]}" -gt 0 ]]; then
      echo "Installing minimal preflight packages: ${MINIMAL_PACKAGES[*]}"
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${MINIMAL_PACKAGES[@]}"
    fi
    ;;
  dnf)
    for pkg in curl python3 ca-certificates; do rpm -q "$pkg" >/dev/null 2>&1 || MINIMAL_PACKAGES+=("$pkg"); done
    if [[ "${#MINIMAL_PACKAGES[@]}" -gt 0 ]]; then
      echo "Installing minimal preflight packages: ${MINIMAL_PACKAGES[*]}"
      if command -v dnf >/dev/null 2>&1; then dnf install -y "${MINIMAL_PACKAGES[@]}"; elif command -v yum >/dev/null 2>&1; then yum install -y "${MINIMAL_PACKAGES[@]}"; else echo "dnf or yum is required" >&2; exit 1; fi
    fi
    ;;
esac

prompt_secret TELEGRAM_BOT_TOKEN "Telegram Bot Token"
prompt_required_text TELEGRAM_CHAT_ID "Telegram Chat ID"
prompt_text CHECK_TIME "Daily check time HH:MM" "09:00"
if [[ -z "$DEDUP_MODE" ]]; then
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then DEDUP_MODE="interval"; else
    echo "Same-alert reminder mode:"; echo "  1) always   same alert only once until state changes"; echo "  2) daily    same alert once per day"; echo "  3) interval same alert every N days (recommended)"; read -r -p "Choose [3]: " choice
    case "${choice:-3}" in 1) DEDUP_MODE="always" ;; 2) DEDUP_MODE="daily" ;; 3) DEDUP_MODE="interval" ;; *) echo "Invalid choice" >&2; exit 2 ;; esac
  fi
fi
case "$DEDUP_MODE" in always|daily|interval) ;; *) echo "Invalid dedup mode: $DEDUP_MODE" >&2; exit 2 ;; esac
if [[ "$DEDUP_MODE" == "interval" ]]; then
  if [[ "$DEDUP_INTERVAL_DAYS" == "3" && "$NON_INTERACTIVE" -ne 1 ]]; then read -r -p "Repeat same alert every N days [3]: " ans; DEDUP_INTERVAL_DAYS="${ans:-3}"; fi
  [[ "$DEDUP_INTERVAL_DAYS" =~ ^[0-9]+$ ]] && [[ "$DEDUP_INTERVAL_DAYS" -ge 1 ]] || { echo "Invalid interval days" >&2; exit 2; }
fi
valid_time "$CHECK_TIME" || { echo "Invalid --time, expected HH:MM" >&2; exit 2; }
if [[ "$SEND_TEST" -eq 0 && "$NON_INTERACTIVE" -ne 1 ]]; then read -r -p "Send additional test Telegram message after install? [y/N]: " ans; [[ "${ans:-N}" =~ ^[Yy]$ ]] && SEND_TEST=1; fi

telegram_preflight

install_missing_packages() {
  [[ "${#MISSING_PACKAGES[@]}" -eq 0 ]] && { echo "All required packages are already installed."; return; }
  echo "Missing packages: ${MISSING_PACKAGES[*]}"
  if [[ "$ASSUME_YES" -ne 1 && "$NON_INTERACTIVE" -ne 1 ]]; then read -r -p "Install missing packages now? [Y/n]: " ans; [[ "${ans:-Y}" =~ ^[Yy]$ ]] || { echo "Cannot continue without required packages." >&2; exit 1; }; fi
  case "$BACKEND" in
    apt) apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING_PACKAGES[@]}" ;;
    dnf) if command -v dnf >/dev/null 2>&1; then dnf install -y "${MISSING_PACKAGES[@]}"; elif command -v yum >/dev/null 2>&1; then yum install -y "${MISSING_PACKAGES[@]}"; else echo "dnf or yum is required" >&2; exit 1; fi ;;
  esac
}

MISSING_PACKAGES=()
case "$BACKEND" in
  apt)
    command -v apt-get >/dev/null || { echo "apt-get is required" >&2; exit 1; }
    REQUIRED_PACKAGES=(unattended-upgrades needrestart apt-listchanges curl python3 ca-certificates)
    for pkg in "${REQUIRED_PACKAGES[@]}"; do dpkg -s "$pkg" >/dev/null 2>&1 || MISSING_PACKAGES+=("$pkg"); done
    ;;
  dnf)
    command -v rpm >/dev/null || { echo "rpm is required for dnf backend" >&2; exit 1; }
    REQUIRED_PACKAGES=(dnf-automatic curl python3 ca-certificates)
    [[ "${ID:-}" == "fedora" ]] && REQUIRED_PACKAGES+=(dnf-utils) || REQUIRED_PACKAGES+=(yum-utils)
    for pkg in "${REQUIRED_PACKAGES[@]}"; do rpm -q "$pkg" >/dev/null 2>&1 || MISSING_PACKAGES+=("$pkg"); done
    ;;
esac
install_missing_packages

install -d -m 0750 /etc/security-update-notify /var/lib/security-update-notify /usr/local/sbin
touch /var/log/security-update-notify.log
chmod 0640 /var/log/security-update-notify.log
if [[ -d /etc/logrotate.d ]]; then
  install -m 0644 "$SCRIPT_DIR/files/security-update-notify.logrotate" /etc/logrotate.d/security-update-notify
fi
install -m 0750 "$SCRIPT_DIR/files/security-update-notify" /usr/local/sbin/security-update-notify
install -m 0644 "$SCRIPT_DIR/files/security-update-notify.service" /etc/systemd/system/security-update-notify.service

if [[ "$BACKEND" == "apt" ]]; then
  install -d -m 0755 /etc/needrestart/conf.d
  install -m 0644 "$SCRIPT_DIR/files/needrestart-report-only.conf" /etc/needrestart/conf.d/99-security-update-notify-report-only.conf
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
  cat >/etc/apt/apt.conf.d/52unattended-upgrades-local <<'EOF'
// Local policy: install Debian/Ubuntu security updates automatically, do not reboot automatically.
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Ubuntu,archive=${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::SyslogEnable "true";
EOF
elif [[ "$BACKEND" == "dnf" ]]; then
  if [[ -f /etc/dnf/automatic.conf ]]; then
    cp -a /etc/dnf/automatic.conf "/etc/dnf/automatic.conf.bak.$(date +%Y%m%d%H%M%S)"
    python3 - <<'PY'
from pathlib import Path
p=Path('/etc/dnf/automatic.conf')
s=p.read_text()
def set_ini(section,key,val):
    global s
    lines=s.splitlines(); out=[]; in_sec=False; seen=False; done=False
    for line in lines:
        stripped=line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            if in_sec and not done:
                out.append(f'{key} = {val}'); done=True
            in_sec=(stripped==f'[{section}]'); seen=seen or in_sec; out.append(line); continue
        if in_sec and stripped.startswith(key): out.append(f'{key} = {val}'); done=True
        else: out.append(line)
    if not seen: out += [f'[{section}]', f'{key} = {val}']
    elif in_sec and not done: out.append(f'{key} = {val}')
    s='\n'.join(out)+'\n'
for sec,key,val in [('commands','upgrade_type','security'),('commands','apply_updates','yes'),('emitters','emit_via','stdio'),('base','debuglevel','1')]: set_ini(sec,key,val)
p.write_text(s)
PY
  fi
fi

umask 077
{
  echo "# Telegram notification settings for security-update-notify."
  echo "# Keep this file root-only: it contains the bot token."
  printf 'TELEGRAM_BOT_TOKEN=%s\n' "$(shell_quote "$TELEGRAM_BOT_TOKEN")"
  printf 'TELEGRAM_CHAT_ID=%s\n' "$(shell_quote "$TELEGRAM_CHAT_ID")"
  printf 'HOST_LABEL=%s\n' "$(shell_quote "$HOST_LABEL")"
  echo 'NOTIFY_OK=0'
  printf 'DEDUP_MODE=%s\n' "$(shell_quote "$DEDUP_MODE")"
  printf 'DEDUP_INTERVAL_DAYS=%s\n' "$(shell_quote "$DEDUP_INTERVAL_DAYS")"
  printf 'BACKEND=%s\n' "$(shell_quote "$BACKEND")"
} >/etc/security-update-notify/telegram.env
chmod 600 /etc/security-update-notify/telegram.env
cat >/etc/systemd/system/security-update-notify.timer <<EOF
[Unit]
Description=Daily security update reboot/service-restart notification

[Timer]
OnCalendar=*-*-* ${CHECK_TIME}:00
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
EOF

chmod 644 /etc/systemd/system/security-update-notify.service /etc/systemd/system/security-update-notify.timer
systemctl daemon-reload
if [[ "$BACKEND" == "apt" ]]; then
  systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
  systemctl enable --now unattended-upgrades.service >/dev/null 2>&1 || true
elif [[ "$BACKEND" == "dnf" ]]; then
  systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 || true
fi
systemctl enable --now security-update-notify.timer >/dev/null

bash -n /usr/local/sbin/security-update-notify
systemctl list-timers security-update-notify.timer --no-pager
[[ "$SEND_TEST" -eq 1 ]] && /usr/local/sbin/security-update-notify --test-ok --no-dedupe

echo "Installed security-update-notify."
echo "Config: /etc/security-update-notify/telegram.env"
echo "Timer:  systemctl list-timers security-update-notify.timer"
