#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER_BASHPID="$BASHPID"
# 共用辅助函数：m/say 双语输出、os-release 读取、后端检测。
# shellcheck source=files/lib.sh
. "$SCRIPT_DIR/files/lib.sh"
CHECK_TIME="${CHECK_TIME:-}"
NOTIFY_CHANNELS="${NOTIFY_CHANNELS:-}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
FEISHU_APP_ID="${FEISHU_APP_ID:-}"
FEISHU_RECEIVE_ID="${FEISHU_RECEIVE_ID:-}"
FEISHU_APP_SECRET_FILE="${FEISHU_APP_SECRET_FILE:-}"
# The literal App Secret is accepted only through the hidden prompt and kept in shell memory.
FEISHU_APP_SECRET=""
FEISHU_AUTH_VALIDATED=0
FEISHU_APP_ID_EXPLICIT=0
FEISHU_RECEIVE_ID_EXPLICIT=0
[[ -z "$FEISHU_APP_ID" ]] || FEISHU_APP_ID_EXPLICIT=1
[[ -z "$FEISHU_RECEIVE_ID" ]] || FEISHU_RECEIVE_ID_EXPLICIT=1
EXISTING_FEISHU_APP_ID=""
readonly FEISHU_API_BASE_URL="https://open.feishu.cn"
HOST_LABEL="${HOST_LABEL:-}"
PUBLIC_IP="${PUBLIC_IP:-}"
INCLUDE_PUBLIC_IP="${INCLUDE_PUBLIC_IP:-}"
DEDUP_MODE="${DEDUP_MODE:-}"
DEDUP_INTERVAL_DAYS="${DEDUP_INTERVAL_DAYS:-}"
NOTIFY_LANG="${NOTIFY_LANG:-}"
BACKEND="${BACKEND:-}"
CONFIG_VERSION="${CONFIG_VERSION:-}"
NOTIFY_UPGRADE="${NOTIFY_UPGRADE:-}"
UI_LANG="${UI_LANG:-${SUN_LANG:-}}"
SEND_TEST=0
SKIP_TELEGRAM_TEST=0
SKIP_FEISHU_TEST=0
NON_INTERACTIVE=0
ASSUME_YES=0
ALLOW_BEST_EFFORT=0
NOTIFY_OK="${NOTIFY_OK:-}"
CHECK_UPDATE_HEALTH="${CHECK_UPDATE_HEALTH:-}"
STALE_UPDATE_DAYS="${STALE_UPDATE_DAYS:-}"
CHECK_EOL="${CHECK_EOL:-}"
CONFIG_FILE="/etc/security-update-notify/telegram.env"
FEISHU_CREDENTIAL_DIR="/etc/security-update-notify/credentials"
FEISHU_CREDENTIAL_FILE="$FEISHU_CREDENTIAL_DIR/feishu-app-secret"
FEISHU_ENCRYPTED_CREDENTIAL="/etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred"
FEISHU_CREDENTIAL_DROPIN="/etc/systemd/system/security-update-notify.service.d/credentials.conf"
TIMER_FILE="/etc/systemd/system/security-update-notify.timer"
SERVICE_FILE="/etc/systemd/system/security-update-notify.service"
BIN_FILE="/usr/local/sbin/security-update-notify"
LOGROTATE_FILE="/etc/logrotate.d/security-update-notify"
BACKUP_ROOT="/var/backups/security-update-notify"
BACKUP_DIR=""
# 安装/升级会管理（创建或覆盖）的文件——备份与回滚都基于这份清单。
# Files this installer manages (creates/overwrites) — both backup and rollback use this list.
MANAGED_PATHS=(
  usr/local/sbin/security-update-notify
  etc/security-update-notify/telegram.env
  etc/systemd/system/security-update-notify.service
  etc/systemd/system/security-update-notify.service.d/credentials.conf
  etc/systemd/system/security-update-notify.timer
  etc/logrotate.d/security-update-notify
  etc/apt/apt.conf.d/20auto-upgrades
  etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify
  etc/needrestart/conf.d/99-security-update-notify-report-only.conf
  etc/dnf/automatic.conf
)
ROLLBACK_DONE=0
POST_INSTALL_CHECK=1
IN_UPGRADE="${SECURITY_UPDATE_NOTIFY_UPGRADE:-0}"
OLD_VERSION="unknown"
EXISTING_CONFIG_LOADED=0
EXISTING_TIMER_LOADED=0
ENV_FILE=""
TMP_DIR=""
FEISHU_CREDENTIAL_CHANGED=0
OLD_FEISHU_CREDENTIAL_KIND="none"
OLD_FEISHU_SECRET=""
OLD_FEISHU_ENCRYPTED_BACKUP=""
cleanup() { [[ -z "$TMP_DIR" ]] || rm -rf "$TMP_DIR"; }
trap cleanup EXIT

usage() {
  if [ "${UI_LANG:-zh}" = en ]; then
    cat <<'EOF'
Usage: sudo ./install.sh [options]

Options:
  --notify-channels LIST        telegram | feishu | telegram,feishu (default telegram)
  --telegram-token TOKEN       Telegram bot token
  --telegram-token-file FILE   Read Telegram bot token from file, safer for automation
  --env-file FILE              Load install options from a dotenv-style file
  --telegram-chat-id CHAT_ID   Telegram target chat id
  --feishu-app-id APP_ID       Feishu application App ID
  --feishu-app-secret-file F   Read Feishu App Secret from file; never stored in normal config
  --feishu-receive-id OPEN_ID  Explicit recipient open_id (required for non-interactive installs)
  --time HH:MM                 Daily check time, default 09:00
  --host-label NAME            Optional host label in notifications
  --public-ip IP               Manually set public IP in notifications
  --include-public-ip BOOL     Show public IP in notifications, default 1
  --notify-ok BOOL             Send OK notification when no action is needed, default 0
  --notify-upgrade BOOL        Send notification after successful upgrade, default 0
  --dedup-mode MODE            once | daily | interval（默认/default daily；旧名 always=once）
  --dedup-interval-days N      Used when mode=interval, default 3
  --notify-lang LANG           Notification language: zh | en (defaults to --lang)
  --lang LANG                  Terminal language: zh | en, default zh
  --backend BACKEND            auto | apt | dnf, default auto
  --allow-best-effort          Permit best-effort distro versions
  --send-test                  Send additional test message after install
  --skip-telegram-test         Skip pre-install Telegram token/chat validation
  --skip-feishu-test           Skip pre-install Feishu credential validation
  --skip-notify-test           Skip all pre-install channel validation
  --skip-post-install-check    Skip post-install/upgrade self-check
  --non-interactive            Fail if required options are missing
  -y, --yes                    Do not prompt before installing packages
  -h, --help                   Show help
EOF
  else
    cat <<'EOF'
用法: sudo ./install.sh [选项]

选项:
  --notify-channels LIST        telegram | feishu | telegram,feishu（默认 telegram）
  --telegram-token TOKEN       Telegram Bot Token
  --telegram-token-file FILE   从文件读取 Telegram Bot Token，更适合自动化
  --env-file FILE              从 dotenv 风格文件加载安装选项
  --telegram-chat-id CHAT_ID   Telegram 目标 Chat ID
  --feishu-app-id APP_ID       飞书应用 App ID
  --feishu-app-secret-file F   从文件读取飞书 App Secret；不写入普通配置
  --feishu-receive-id OPEN_ID  显式指定接收人 open_id（非交互安装必需）
  --time HH:MM                 每日检查时间，默认 09:00
  --host-label NAME            通知中的可选主机标签
  --public-ip IP               手动指定通知中的公网 IP
  --include-public-ip BOOL     是否在通知中显示公网 IP，默认 1
  --notify-ok BOOL             无需处理时是否也发送 OK 通知，默认 0
  --notify-upgrade BOOL        升级成功后是否发送通知，默认 0
  --dedup-mode MODE            once | daily | interval（默认/default daily；旧名 always=once）
  --dedup-interval-days N      mode=interval 时使用，默认 3
  --notify-lang LANG           通知语言：zh | en（默认跟随 --lang）
  --lang LANG                  终端语言：zh | en，默认 zh
  --backend BACKEND            auto | apt | dnf，默认 auto
  --allow-best-effort          允许尽力支持的发行版
  --send-test                  安装后额外发送测试消息
  --skip-telegram-test         跳过安装前 Telegram token/chat 校验
  --skip-feishu-test           跳过安装前飞书凭据校验
  --skip-notify-test           跳过所有渠道的安装前校验
  --skip-post-install-check    跳过安装/升级后的自检
  --non-interactive            缺少必需选项时直接失败
  -y, --yes                    安装软件包前不再询问
  -h, --help                   显示帮助
EOF
  fi
}

choose_language() {
  case "${UI_LANG:-}" in zh|en) return ;; esac
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then UI_LANG=zh; return; fi
  printf '%s\n' "请选择语言 / Choose a language:"
  printf '%s\n' "  1) 中文 (default)"
  printf '%s\n' "  2) English"
  local choice; read -r -p "[1]: " choice
  case "${choice:-1}" in 2) UI_LANG=en ;; *) UI_LANG=zh ;; esac
}

load_env_file() {
  local file="$1" line key value lower
  [[ -r "$file" ]] || { say "无法读取 env 文件: $file" "Cannot read env file: $file" >&2; exit 2; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    key="${line%%=*}"
    value="${line#*=}"
    key="${key//[[:space:]]/}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { say "env 文件中的键无效: $file: $key" "Invalid env key in $file: $key" >&2; exit 2; }
    value="${value#${value%%[![:space:]]*}}"
    value="${value%${value##*[![:space:]]}}"
    if [[ "$value" != \"* && "$value" != \'* ]]; then
      value="${value%%[[:space:]]#*}"
      value="${value%${value##*[![:space:]]}}"
    fi
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then value="${value:1:${#value}-2}"; fi
    if [[ "$value" == \'*\' && "$value" == *\' ]]; then value="${value:1:${#value}-2}"; fi
    case "$key" in
      NOTIFY_CHANNELS|TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|FEISHU_APP_ID|FEISHU_RECEIVE_ID|FEISHU_APP_SECRET_FILE|CHECK_TIME|HOST_LABEL|PUBLIC_IP|INCLUDE_PUBLIC_IP|DEDUP_MODE|DEDUP_INTERVAL_DAYS|NOTIFY_LANG|BACKEND|CONFIG_VERSION|UI_LANG|CHECK_UPDATE_HEALTH|STALE_UPDATE_DAYS|CHECK_EOL)
        printf -v "$key" '%s' "$value"
        case "$key" in
          FEISHU_APP_ID)
            FEISHU_APP_ID_EXPLICIT=0
            [[ -z "$value" ]] || FEISHU_APP_ID_EXPLICIT=1
            ;;
          FEISHU_RECEIVE_ID)
            FEISHU_RECEIVE_ID_EXPLICIT=0
            [[ -z "$value" ]] || FEISHU_RECEIVE_ID_EXPLICIT=1
            ;;
        esac
        ;;
      SEND_TEST|SKIP_TELEGRAM_TEST|SKIP_FEISHU_TEST|NON_INTERACTIVE|ASSUME_YES|ALLOW_BEST_EFFORT|NOTIFY_OK|NOTIFY_UPGRADE|POST_INSTALL_CHECK)
        lower="${value,,}"
        [[ "$lower" =~ ^(0|1|true|false|yes|no)$ ]] || { say "$key 在 $file 中的布尔值无效" "Invalid boolean for $key in $file" >&2; exit 2; }
        case "$lower" in 1|true|yes) printf -v "$key" '%s' 1 ;; *) printf -v "$key" '%s' 0 ;; esac
        ;;
      *) say "$file 中存在不支持的 env 键: $key" "Unsupported env key in $file: $key" >&2; exit 2 ;;
    esac
  done <"$file"
}


set_config_default() {
  local key="$1" value="$2" current
  set +u; current="${!key:-}"; set -u
  [[ -n "$current" ]] && return
  printf -v "$key" '%s' "$value"
}

load_existing_config_defaults() {
  local file="$1" line key value
  [[ -r "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    [[ "$line" == *"="* ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    key="${key//[[:space:]]/}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    value="${value#${value%%[![:space:]]*}}"
    value="${value%${value##*[![:space:]]}}"
    if [[ "$value" != \"* && "$value" != \'* ]]; then
      value="${value%%[[:space:]]#*}"
      value="${value%${value##*[![:space:]]}}"
    fi
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then value="${value:1:${#value}-2}"; fi
    if [[ "$value" == \'*\' && "$value" == *\' ]]; then value="${value:1:${#value}-2}"; fi
    case "$key" in
      FEISHU_APP_ID)
        EXISTING_FEISHU_APP_ID="$value"
        set_config_default "$key" "$value"
        EXISTING_CONFIG_LOADED=1
        ;;
      NOTIFY_CHANNELS|TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|FEISHU_RECEIVE_ID|HOST_LABEL|PUBLIC_IP|INCLUDE_PUBLIC_IP|NOTIFY_OK|NOTIFY_UPGRADE|DEDUP_MODE|DEDUP_INTERVAL_DAYS|NOTIFY_LANG|BACKEND|CONFIG_VERSION|CHECK_UPDATE_HEALTH|STALE_UPDATE_DAYS|CHECK_EOL)
        set_config_default "$key" "$value"
        EXISTING_CONFIG_LOADED=1
        ;;
      *) : ;; # Forward-compatible: ignore unknown keys in an installed config.
    esac
  done <"$file"
}

load_existing_timer_default() {
  local file="$1" line
  [[ -z "${CHECK_TIME:-}" && -r "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ "$line" =~ ^OnCalendar=\*-\*-\*[[:space:]]+([0-9]{2}:[0-9]{2}):[0-9]{2}$ ]]; then
      CHECK_TIME="${BASH_REMATCH[1]}"
      EXISTING_TIMER_LOADED=1
      return 0
    fi
  done <"$file"
}

require_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || { say "缺少 $1 的值" "Missing value for $1" >&2; exit 2; }; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file) require_arg "$1" "${2:-}"; ENV_FILE="$2"; load_env_file "$2"; shift 2 ;;
    --notify-channels) require_arg "$1" "${2:-}"; NOTIFY_CHANNELS="$2"; shift 2 ;;
    --telegram-token) require_arg "$1" "${2:-}"; TELEGRAM_BOT_TOKEN="$2"; say "提示：--telegram-token 会让 token 出现在进程列表(ps)中，自动化建议改用 --telegram-token-file。" "Note: --telegram-token exposes the token in the process list (ps); for automation prefer --telegram-token-file." >&2; shift 2 ;;
    --telegram-token-file) require_arg "$1" "${2:-}"; TELEGRAM_BOT_TOKEN="$(tr -d '\r\n' <"$2")"; shift 2 ;;
    --telegram-chat-id) require_arg "$1" "${2:-}"; TELEGRAM_CHAT_ID="$2"; shift 2 ;;
    --feishu-app-id) require_arg "$1" "${2:-}"; FEISHU_APP_ID="$2"; FEISHU_APP_ID_EXPLICIT=1; shift 2 ;;
    --feishu-app-secret-file) require_arg "$1" "${2:-}"; FEISHU_APP_SECRET_FILE="$2"; shift 2 ;;
    --feishu-receive-id) require_arg "$1" "${2:-}"; FEISHU_RECEIVE_ID="$2"; FEISHU_RECEIVE_ID_EXPLICIT=1; shift 2 ;;
    --time) require_arg "$1" "${2:-}"; CHECK_TIME="$2"; shift 2 ;;
    --host-label) require_arg "$1" "${2:-}"; HOST_LABEL="$2"; shift 2 ;;
    --public-ip) require_arg "$1" "${2:-}"; PUBLIC_IP="$2"; shift 2 ;;
    --include-public-ip) require_arg "$1" "${2:-}"; INCLUDE_PUBLIC_IP="$2"; shift 2 ;;
    --notify-ok) require_arg "$1" "${2:-}"; NOTIFY_OK="$2"; shift 2 ;;
    --notify-upgrade) require_arg "$1" "${2:-}"; NOTIFY_UPGRADE="$2"; shift 2 ;;
    --dedup-mode) require_arg "$1" "${2:-}"; DEDUP_MODE="$2"; shift 2 ;;
    --dedup-interval-days) require_arg "$1" "${2:-}"; DEDUP_INTERVAL_DAYS="$2"; shift 2 ;;
    --notify-lang) require_arg "$1" "${2:-}"; NOTIFY_LANG="$2"; shift 2 ;;
    --lang) require_arg "$1" "${2:-}"; UI_LANG="$2"; shift 2 ;;
    --backend) require_arg "$1" "${2:-}"; BACKEND="$2"; shift 2 ;;
    --send-test) SEND_TEST=1; shift ;;
    --skip-telegram-test) SKIP_TELEGRAM_TEST=1; shift ;;
    --skip-feishu-test) SKIP_FEISHU_TEST=1; shift ;;
    --skip-notify-test) SKIP_TELEGRAM_TEST=1; SKIP_FEISHU_TEST=1; shift ;;
    --skip-post-install-check) POST_INSTALL_CHECK=0; shift ;;
    --allow-best-effort) ALLOW_BEST_EFFORT=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf '%s\n' "未知参数 / Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
case "${UI_LANG:-}" in zh|en) ;; *) UI_LANG="" ;; esac

require_root() { [[ "$(id -u)" -eq 0 ]] || { say "请以 root 运行，例如 sudo ./install.sh" "Please run as root, e.g. sudo ./install.sh" >&2; exit 1; }; }
validate_config_value() {
  local name="$1" value="$2"
  case "$value" in
    *$'\n'*|*$'\r'*) say "$name 不能包含换行" "$name cannot contain newlines" >&2; exit 2 ;;
  esac
  if [[ "$value" == *"'"* && "$value" == *\"* ]]; then
    say "$name 不能同时包含单引号和双引号" "$name cannot contain both single and double quotes" >&2
    exit 2
  fi
}
validate_config_values() {
  local name value
  for name in NOTIFY_CHANNELS TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID FEISHU_APP_ID FEISHU_RECEIVE_ID HOST_LABEL PUBLIC_IP INCLUDE_PUBLIC_IP NOTIFY_OK NOTIFY_UPGRADE DEDUP_MODE DEDUP_INTERVAL_DAYS NOTIFY_LANG BACKEND CONFIG_VERSION CHECK_UPDATE_HEALTH STALE_UPDATE_DAYS CHECK_EOL; do
    set +u; value="${!name}"; set -u
    validate_config_value "$name" "$value"
  done
}
config_quote() {
  local value="$1"
  if [[ "$value" == *"'"* ]]; then
    printf '"%s"' "$value"
  else
    printf "'%s'" "$value"
  fi
}

channel_selected() {
  case ",${NOTIFY_CHANNELS:-}," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

normalize_notify_channels() {
  local raw item has_telegram=0 has_feishu=0
  local -a items=()
  raw="${NOTIFY_CHANNELS//[[:space:]]/}"
  IFS=',' read -r -a items <<<"${raw,,}"
  [[ "${#items[@]}" -gt 0 ]] || { say "通知渠道不能为空" "Notification channels cannot be empty" >&2; exit 2; }
  for item in "${items[@]}"; do
    case "$item" in
      telegram) has_telegram=1 ;;
      feishu) has_feishu=1 ;;
      *) say "无效通知渠道: $item" "Invalid notification channel: $item" >&2; exit 2 ;;
    esac
  done
  case "$has_telegram$has_feishu" in
    10) NOTIFY_CHANNELS=telegram ;;
    01) NOTIFY_CHANNELS=feishu ;;
    11) NOTIFY_CHANNELS=telegram,feishu ;;
    *) say "通知渠道不能为空" "Notification channels cannot be empty" >&2; exit 2 ;;
  esac
}

choose_notify_channels() {
  [[ -z "${NOTIFY_CHANNELS:-}" ]] || { normalize_notify_channels; return; }
  if [[ "$EXISTING_CONFIG_LOADED" -eq 1 || "$NON_INTERACTIVE" -eq 1 ]]; then
    NOTIFY_CHANNELS=telegram
    return
  fi
  say "通知渠道:" "Notification channels:"
  say "  1) Telegram（默认）" "  1) Telegram (default)"
  say "  2) 飞书" "  2) Feishu"
  say "  3) Telegram + 飞书" "  3) Telegram + Feishu"
  local choice
  read -r -p "$(m '请选择 [1]: ' 'Choose [1]: ')" choice
  case "${choice:-1}" in
    1) NOTIFY_CHANNELS=telegram ;;
    2) NOTIFY_CHANNELS=feishu ;;
    3) NOTIFY_CHANNELS=telegram,feishu ;;
    *) say "无效选项" "Invalid choice" >&2; exit 2 ;;
  esac
}

feishu_credential_available() {
  [[ -n "$FEISHU_APP_SECRET" || -r "$FEISHU_APP_SECRET_FILE" || -r "$FEISHU_ENCRYPTED_CREDENTIAL" || -r "$FEISHU_CREDENTIAL_FILE" ]]
}

load_feishu_secret_source() {
  [[ -n "$FEISHU_APP_SECRET_FILE" ]] || return 0
  local secret_fd path_identity fd_identity owner mode
  if [[ -L "$FEISHU_APP_SECRET_FILE" ]] || ! exec {secret_fd}<"$FEISHU_APP_SECRET_FILE"; then
    say "飞书 App Secret 路径必须是普通文件（不能是符号链接）: $FEISHU_APP_SECRET_FILE" \
        "Feishu App Secret path must be a regular file (not a symlink): $FEISHU_APP_SECRET_FILE" >&2
    exit 2
  fi
  path_identity="$(stat -c '%d:%i' -- "$FEISHU_APP_SECRET_FILE" 2>/dev/null || true)"
  fd_identity="$(stat -Lc '%d:%i' -- "/proc/self/fd/$secret_fd" 2>/dev/null || true)"
  owner="$(stat -Lc '%u' -- "/proc/self/fd/$secret_fd" 2>/dev/null || true)"
  mode="$(stat -Lc '%a' -- "/proc/self/fd/$secret_fd" 2>/dev/null || true)"
  if [[ "$path_identity" != "$fd_identity" || ! -f "/proc/self/fd/$secret_fd" ]]; then
    exec {secret_fd}<&-
    say "飞书 App Secret 路径在检查期间发生变化，或不是普通文件。" \
        "Feishu App Secret path changed during validation or is not a regular file." >&2
    exit 2
  fi
  if [[ "$owner" != "0" || ! "$mode" =~ ^[0-7]{3,4}$ || $(( 8#$mode & 077 )) -ne 0 ]]; then
    exec {secret_fd}<&-
    say "飞书 App Secret 文件必须属于 root，且不能允许组用户或其他用户读取（建议 0600）。" \
        "Feishu App Secret file must be root-owned and inaccessible to group/other users (0600 recommended)." >&2
    exit 2
  fi
  FEISHU_APP_SECRET="$(tr -d '\r\n' <&"$secret_fd")"
  exec {secret_fd}<&-
  FEISHU_APP_SECRET_FILE=""
  [[ -n "$FEISHU_APP_SECRET" ]] || {
    say "飞书 App Secret 文件去除换行后为空。" "Feishu App Secret file is empty after removing line endings." >&2
    exit 2
  }
}

validate_feishu_receive_id() {
  [[ "${FEISHU_RECEIVE_ID:-}" =~ ^ou_[A-Za-z0-9_-]+$ ]] || {
    say "无效飞书接收人：必须是当前应用下的 open_id（以 ou_ 开头）。" \
        "Invalid Feishu recipient: expected an app-scoped open_id starting with ou_." >&2
    exit 2
  }
}

new_feishu_secret_to_stdout() {
  if [[ -n "$FEISHU_APP_SECRET" ]]; then
    printf '%s' "$FEISHU_APP_SECRET"
  elif [[ -n "$FEISHU_APP_SECRET_FILE" && -r "$FEISHU_APP_SECRET_FILE" ]]; then
    tr -d '\r\n' <"$FEISHU_APP_SECRET_FILE"
  else
    return 1
  fi
}

feishu_secret_to_stdout() {
  if new_feishu_secret_to_stdout; then
    return 0
  fi
  if [[ -r "$FEISHU_ENCRYPTED_CREDENTIAL" ]] && command -v systemd-creds >/dev/null 2>&1; then
    systemd-creds decrypt --name=feishu_app_secret "$FEISHU_ENCRYPTED_CREDENTIAL" - 2>/dev/null
  elif [[ -r "$FEISHU_CREDENTIAL_FILE" ]]; then
    cat "$FEISHU_CREDENTIAL_FILE"
  else
    return 1
  fi
}

feishu_scan_directory() {
  local output_file="$1" error_file="$2"
  local base_url="${FEISHU_API_BASE_URL:-https://open.feishu.cn}"
  if { printf '%s\0' "$FEISHU_APP_ID"; feishu_secret_to_stdout; printf '\0%s' "$base_url"; } | python3 -c '
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_RESPONSE = 4 * 1024 * 1024
payload = sys.stdin.buffer.read().split(b"\0", 2)
app_id = payload[0].decode("utf-8", "replace") if len(payload) > 0 else ""
secret = payload[1].decode("utf-8", "replace") if len(payload) > 1 else ""
base_url = payload[2].decode("utf-8", "replace").rstrip("/") if len(payload) > 2 else ""
parsed_base = urllib.parse.urlparse(base_url)
allowed_base = (
    (parsed_base.scheme == "https" and parsed_base.hostname == "open.feishu.cn" and parsed_base.port in (None, 443))
    or (parsed_base.scheme == "http" and parsed_base.hostname in ("127.0.0.1", "::1"))
)
if not app_id or not secret:
    print("Missing Feishu App ID or App Secret", file=sys.stderr)
    sys.exit(2)
if not allowed_base or parsed_base.path not in ("", "/") or parsed_base.username or parsed_base.password or parsed_base.query or parsed_base.fragment:
    print("Invalid Feishu API base URL", file=sys.stderr)
    sys.exit(2)

def read_limited(response):
    body = response.read(MAX_RESPONSE + 1)
    if len(body) > MAX_RESPONSE:
        raise RuntimeError("Feishu API response too large")
    try:
        return json.loads(body)
    except Exception as exc:
        raise RuntimeError("Invalid Feishu API response") from exc

def request_json(path, body, token=None):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{base_url}{path}",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return read_limited(response)
        except urllib.error.HTTPError as exc:
            try:
                error_body = read_limited(exc)
            except Exception:
                error_body = {}
            api_code = error_body.get("code") if isinstance(error_body, dict) else None
            retryable = exc.code == 429 or 500 <= exc.code < 600 or api_code == 99991400
            if retryable and attempt < 2:
                headers = exc.headers or {}
                reset = headers.get("x-ogw-ratelimit-reset", "") or headers.get("Retry-After", "")
                try:
                    delay = float(reset)
                    if delay > time.time():
                        delay -= time.time()
                except (TypeError, ValueError):
                    delay = 2 ** attempt
                time.sleep(min(max(delay, 0), 5))
                continue
            if api_code == 99991400:
                raise RuntimeError("Feishu API rate limited: code=99991400") from exc
            raise RuntimeError(f"Feishu API HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError("Feishu API request failed") from exc
    raise RuntimeError("Feishu API request failed")

try:
    auth = request_json(
        "/open-apis/auth/v3/tenant_access_token/internal",
        {"app_id": app_id, "app_secret": secret},
    )
    auth_code = auth.get("code")
    if auth_code != 0 or not auth.get("tenant_access_token"):
        raise RuntimeError(f"Feishu authentication failed: code={auth_code}")
    token = auth["tenant_access_token"]
    users = []
    seen_ids = set()
    seen_page_tokens = set()
    page_token = ""
    for _ in range(1000):
        page_request = {"page_size": 100}
        if page_token:
            page_request["page_token"] = page_token
        result = request_json(
            "/open-apis/directory/v1/employees/filter?employee_id_type=open_id&department_id_type=open_department_id",
            {
                "filter": {
                    "conditions": [
                        {
                            "field": "base_info.departments.department_id",
                            "operator": "eq",
                            "value": "\"0\"",
                        },
                        {
                            "field": "work_info.staff_status",
                            "operator": "eq",
                            "value": "1",
                        },
                    ]
                },
                "required_fields": [
                    "base_info.employee_id",
                    "base_info.name",
                    "base_info.mobile",
                ],
                "page_request": page_request,
            },
            token,
        )
        result_code = result.get("code")
        if result_code != 0:
            raise RuntimeError(f"Feishu directory scan failed: code={result_code}")
        data = result.get("data") if isinstance(result.get("data"), dict) else {}
        if data.get("abnormals"):
            raise RuntimeError("Feishu directory scan incomplete: abnormals returned")
        employees = data.get("employees") if isinstance(data.get("employees"), list) else []
        for employee in employees:
            if not isinstance(employee, dict):
                continue
            info = employee.get("base_info") if isinstance(employee.get("base_info"), dict) else {}
            open_id = info.get("employee_id")
            if not isinstance(open_id, str) or not re.fullmatch(r"ou_[A-Za-z0-9_-]+", open_id):
                continue
            if open_id in seen_ids:
                continue
            seen_ids.add(open_id)
            outer_name = info.get("name") if isinstance(info.get("name"), dict) else {}
            inner_name = outer_name.get("name") if isinstance(outer_name.get("name"), dict) else {}
            i18n = inner_name.get("i18n_value") if isinstance(inner_name.get("i18n_value"), dict) else {}
            name = i18n.get("zh_cn") or inner_name.get("default_value") or ""
            mobile = info.get("mobile") if isinstance(info.get("mobile"), str) else ""
            users.append({"name": str(name), "mobile_tail": mobile[-4:] if mobile else "", "open_id": open_id})
        page_response = data.get("page_response") if isinstance(data.get("page_response"), dict) else {}
        next_token = page_response.get("page_token")
        page_token = next_token if isinstance(next_token, str) else ""
        if not page_token:
            break
        if page_token in seen_page_tokens:
            raise RuntimeError("Feishu directory pagination repeated a page token")
        seen_page_tokens.add(page_token)
    else:
        raise RuntimeError("Feishu directory pagination exceeded 1000 pages")
    json.dump(users, sys.stdout, ensure_ascii=False)
except Exception as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)
' >"$output_file" 2>"$error_file"; then
    FEISHU_AUTH_VALIDATED=1
    return 0
  fi
  return 1
}

feishu_render_directory_users() {
  python3 - "$1" "${UI_LANG:-zh}" <<'PY'
import json
import re
import sys
import unicodedata

path, language = sys.argv[1:]
with open(path, encoding="utf-8") as fh:
    users = json.load(fh)

def clean(value, fallback):
    text = "".join(" " if unicodedata.category(ch).startswith("C") else ch for ch in str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > 60:
        text = text[:57] + "..."
    return text or fallback

for index, user in enumerate(users, 1):
    unnamed = "(unnamed)" if language == "en" else "（未命名）"
    mobile_label = "mobile tail" if language == "en" else "手机号尾号"
    name = clean(user.get("name"), unnamed)
    tail = clean(user.get("mobile_tail"), "----")
    open_id = clean(user.get("open_id"), "invalid")
    print(f"  {index}) {name} | {mobile_label} {tail} | {open_id}")
PY
}

feishu_directory_user_count() {
  python3 - "$1" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    users = json.load(fh)
print(len(users))
PY
}

feishu_directory_user_id() {
  python3 - "$1" "$2" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    users = json.load(fh)
index = int(sys.argv[2]) - 1
if index < 0 or index >= len(users):
    sys.exit(2)
print(users[index]["open_id"])
PY
}

prompt_manual_feishu_receive_id() {
  FEISHU_RECEIVE_ID=""
  while true; do
    prompt_required_text FEISHU_RECEIVE_ID "飞书接收人 open_id" "Feishu recipient open_id"
    if [[ "$FEISHU_RECEIVE_ID" =~ ^ou_[A-Za-z0-9_-]+$ ]]; then
      return 0
    fi
    say "无效 open_id：必须以 ou_ 开头，请重新输入。" \
        "Invalid open_id: it must start with ou_. Please try again." >&2
    FEISHU_RECEIVE_ID=""
  done
}

select_feishu_recipient() {
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    say "非交互模式不会等待用户序号；请显式提供 --feishu-receive-id。" \
        "Non-interactive mode cannot wait for a numbered choice; provide --feishu-receive-id explicitly." >&2
    exit 2
  fi
  TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
  local users_file="$TMP_DIR/feishu-directory-users.json"
  local error_file="$TMP_DIR/feishu-directory.err"
  local count choice selected action
  while true; do
    say "正在扫描应用通讯录范围内的在职飞书用户..." \
        "Scanning active Feishu users visible to this application..."
    : >"$error_file"
    if feishu_scan_directory "$users_file" "$error_file"; then
      count="$(feishu_directory_user_count "$users_file")"
      if [[ "$count" -gt 0 ]]; then
        say "找到 $count 位可见在职用户，请选择接收人：" \
            "Found $count visible active user(s). Choose the recipient:"
        feishu_render_directory_users "$users_file"
        while true; do
          read -r -p "$(m '输入序号（m 手动输入，r 重新扫描）: ' 'Enter a number (m manual, r rescan): ')" choice
          case "$choice" in
            m|M)
              prompt_manual_feishu_receive_id
              return 0
              ;;
            r|R) break ;;
            *[!0-9]*|'')
              say "请输入 1-$count 之间的序号。" "Enter a number from 1 to $count." >&2
              ;;
            *)
              if selected="$(feishu_directory_user_id "$users_file" "$choice" 2>/dev/null)"; then
                FEISHU_RECEIVE_ID="$selected"
                say "已选择飞书接收人: $FEISHU_RECEIVE_ID" "Selected Feishu recipient: $FEISHU_RECEIVE_ID"
                return 0
              fi
              say "请输入 1-$count 之间的序号。" "Enter a number from 1 to $count." >&2
              ;;
          esac
        done
        continue
      fi
      say "未找到可见的在职用户。结果受应用通讯录数据范围限制。" \
          "No visible active users were found. Results are limited by the application directory scope." >&2
    else
      say "飞书用户扫描失败。" "Feishu user scan failed." >&2
      cat "$error_file" >&2 2>/dev/null || true
    fi
    say "请检查应用已发布并具备 directory:employee:list、姓名和手机号字段权限，以及正确的通讯录数据范围。" \
        "Check that the app is published with directory:employee:list, name/mobile field permissions, and the intended directory data scope." >&2
    say "  1) 重试扫描" "  1) Retry scan"
    say "  2) 手动输入 open_id（默认）" "  2) Enter open_id manually (default)"
    say "  3) 中止安装" "  3) Abort installation"
    read -r -p "$(m '请选择 [2]: ' 'Choose [2]: ')" action
    case "${action:-2}" in
      1) continue ;;
      2) prompt_manual_feishu_receive_id; return 0 ;;
      3) say "安装已中止。" "Installation aborted." >&2; exit 2 ;;
      *) say "无效选项。" "Invalid choice." >&2 ;;
    esac
  done
}

snapshot_feishu_credential() {
  TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
  if [[ -r "$FEISHU_ENCRYPTED_CREDENTIAL" ]]; then
    OLD_FEISHU_CREDENTIAL_KIND=encrypted
    OLD_FEISHU_ENCRYPTED_BACKUP="$TMP_DIR/old-feishu-app-secret.cred"
    cp -a "$FEISHU_ENCRYPTED_CREDENTIAL" "$OLD_FEISHU_ENCRYPTED_BACKUP"
  elif [[ -r "$FEISHU_CREDENTIAL_FILE" ]]; then
    OLD_FEISHU_CREDENTIAL_KIND=plain
    OLD_FEISHU_SECRET="$(cat "$FEISHU_CREDENTIAL_FILE")"
  else
    OLD_FEISHU_CREDENTIAL_KIND=none
  fi
}

restore_feishu_credential() {
  [[ "$FEISHU_CREDENTIAL_CHANGED" -eq 1 ]] || return 0
  case "$OLD_FEISHU_CREDENTIAL_KIND" in
    encrypted)
      install -d -m 0700 "$(dirname "$FEISHU_ENCRYPTED_CREDENTIAL")"
      install -m 0600 "$OLD_FEISHU_ENCRYPTED_BACKUP" "$FEISHU_ENCRYPTED_CREDENTIAL"
      rm -f "$FEISHU_CREDENTIAL_FILE"
      ;;
    plain)
      install -d -m 0700 "$FEISHU_CREDENTIAL_DIR"
      local restore_tmp="$TMP_DIR/restore-feishu-app-secret"
      ( umask 077; printf '%s' "$OLD_FEISHU_SECRET" >"$restore_tmp" )
      install -m 0600 "$restore_tmp" "$FEISHU_CREDENTIAL_FILE"
      rm -f "$FEISHU_ENCRYPTED_CREDENTIAL"
      ;;
    none)
      rm -f "$FEISHU_ENCRYPTED_CREDENTIAL" "$FEISHU_CREDENTIAL_FILE"
      ;;
  esac
}

install_feishu_credential() {
  if ! channel_selected feishu; then
    # Disabling Feishu must not leave its App Secret at rest. Snapshot first so a later installer
    # failure can still restore the previous channel configuration and credential atomically.
    snapshot_feishu_credential
    FEISHU_CREDENTIAL_CHANGED=1
    rm -f "$FEISHU_ENCRYPTED_CREDENTIAL" "$FEISHU_CREDENTIAL_FILE" "$FEISHU_CREDENTIAL_DROPIN"
    rmdir "$FEISHU_CREDENTIAL_DIR" 2>/dev/null || true
    return 0
  fi
  if [[ -z "$FEISHU_APP_SECRET" && -z "$FEISHU_APP_SECRET_FILE" ]]; then
    if [[ -r "$FEISHU_ENCRYPTED_CREDENTIAL" ]]; then
      install -d -m 0755 "$(dirname "$FEISHU_CREDENTIAL_DROPIN")"
      printf '%s\n' '[Service]' "LoadCredentialEncrypted=feishu_app_secret:$FEISHU_ENCRYPTED_CREDENTIAL" >"$FEISHU_CREDENTIAL_DROPIN"
      chmod 0644 "$FEISHU_CREDENTIAL_DROPIN"
    elif [[ -r "$FEISHU_CREDENTIAL_FILE" ]]; then
      rm -f "$FEISHU_CREDENTIAL_DROPIN"
    else
      say "缺少飞书 App Secret 凭据" "Missing Feishu App Secret credential" >&2
      return 2
    fi
    return 0
  fi

  snapshot_feishu_credential
  FEISHU_CREDENTIAL_CHANGED=1
  TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
  if command -v systemd-creds >/dev/null 2>&1; then
    install -d -m 0700 "$(dirname "$FEISHU_ENCRYPTED_CREDENTIAL")"
    systemd-creds setup >/dev/null 2>&1 || true
    local encrypted_tmp="$TMP_DIR/new-feishu-app-secret.cred"
    if ! new_feishu_secret_to_stdout | systemd-creds encrypt --name=feishu_app_secret --with-key=host - "$encrypted_tmp" >/dev/null; then
      say "飞书 App Secret 加密失败" "Failed to encrypt Feishu App Secret" >&2
      return 1
    fi
    install -m 0600 "$encrypted_tmp" "$FEISHU_ENCRYPTED_CREDENTIAL"
    rm -f "$FEISHU_CREDENTIAL_FILE"
    install -d -m 0755 "$(dirname "$FEISHU_CREDENTIAL_DROPIN")"
    printf '%s\n' '[Service]' "LoadCredentialEncrypted=feishu_app_secret:$FEISHU_ENCRYPTED_CREDENTIAL" >"$FEISHU_CREDENTIAL_DROPIN"
    chmod 0644 "$FEISHU_CREDENTIAL_DROPIN"
    say "飞书 App Secret 已保存为加密的 systemd credential。" "Feishu App Secret stored as an encrypted systemd credential."
  else
    install -d -m 0700 "$FEISHU_CREDENTIAL_DIR"
    local plain_tmp="$TMP_DIR/new-feishu-app-secret"
    ( umask 077; new_feishu_secret_to_stdout >"$plain_tmp" )
    install -m 0600 "$plain_tmp" "$FEISHU_CREDENTIAL_FILE"
    rm -f "$FEISHU_ENCRYPTED_CREDENTIAL" "$FEISHU_CREDENTIAL_DROPIN"
    say "警告：当前 systemd 不支持加密凭据；App Secret 已保存为独立的 root-only 0600 文件，不进入普通配置或升级备份。" \
        "WARN: encrypted systemd credentials are unavailable; the App Secret is in a dedicated root-only 0600 file, excluded from normal config and upgrade backups."
  fi
}

current_installed_version() {
  if [[ -x "$BIN_FILE" ]]; then
    "$BIN_FILE" --version 2>/dev/null | awk '{print $2; exit}'
  else
    printf 'none\n'
  fi
}

create_backup() {
  local ts rel
  ts="$(date +%Y%m%d%H%M%S)"
  BACKUP_DIR="$BACKUP_ROOT/$ts"
  install -d -m 0700 "$BACKUP_DIR"
  : >"$BACKUP_DIR/manifest"
  for rel in "${MANAGED_PATHS[@]}"; do
    if [[ -e "/$rel" ]]; then
      install -d -m 0700 "$BACKUP_DIR/$(dirname "$rel")"
      cp -a "/$rel" "$BACKUP_DIR/$rel"
      printf '%s\n' "$rel" >>"$BACKUP_DIR/manifest"
    fi
  done
  printf '%s\n' "$BACKUP_DIR" >"$BACKUP_ROOT/latest"
  # 备份目录含 telegram.env 的 token 副本：设为 0700，并只保留最近 3 份，裁剪更旧的。
  # Backups hold token copies of telegram.env: keep them 0700 and prune to the most recent 3.
  local keep=3 old
  while IFS= read -r old; do [[ -n "$old" ]] && rm -rf "$old"; done < <(
    find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -name '[0-9]*' -printf '%f\n' 2>/dev/null \
      | sort -r | tail -n "+$((keep+1))" | sed "s|^|$BACKUP_ROOT/|")
  say "已创建安装/升级前备份: $BACKUP_DIR" "Pre-install/upgrade backup created: $BACKUP_DIR"
}

capture_dependency_created_defaults() {
  [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]] || return 0
  local rel captured=0
  for rel in "${MANAGED_PATHS[@]}"; do
    [[ -e "/$rel" && ! -e "$BACKUP_DIR/$rel" ]] || continue
    install -d -m 0700 "$BACKUP_DIR/$(dirname "$rel")"
    cp -a "/$rel" "$BACKUP_DIR/$rel"
    printf '%s\n' "$rel" >>"$BACKUP_DIR/manifest"
    captured=1
  done
  [[ "$captured" -eq 0 ]] || say "已补充备份依赖包创建的默认配置。" "Captured default config files created by dependencies."
}

restore_backup() {
  [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]] || return 0
  [[ "$ROLLBACK_DONE" -eq 0 ]] || return 0
  ROLLBACK_DONE=1
  say "安装/升级失败，正在回滚: $BACKUP_DIR" "Install/upgrade failed; rolling back: $BACKUP_DIR" >&2
  local rel dmode
  for rel in "${MANAGED_PATHS[@]}"; do
    case "$rel" in
      etc/security-update-notify/*) dmode=0750 ;;
      *) dmode=0755 ;;
    esac
    if [[ -e "$BACKUP_DIR/$rel" ]]; then
      install -d -m "$dmode" "$(dirname "/$rel")"
      cp -a "$BACKUP_DIR/$rel" "/$rel"
    else
      # 本次运行新建、备份里没有的文件：删除，避免回滚后留下半新半旧的状态。
      # File created by this run and absent from the backup: remove it so rollback is clean.
      rm -f "/$rel"
    fi
  done
  restore_feishu_credential
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart security-update-notify.timer >/dev/null 2>&1 || true
  say "已回滚: $BACKUP_DIR" "Rolled back: $BACKUP_DIR" >&2
}

on_error() {
  local rc=$?
  if [[ "$BASHPID" != "$INSTALLER_BASHPID" ]]; then
    trap - ERR
    return "$rc"
  fi
  trap - ERR
  restore_backup
  exit "$rc"
}
prompt_secret() {
  local var_name="$1" prompt_zh="$2" prompt_en="$3" current p
  set +u; current="${!var_name}"; set -u
  [[ -n "$current" ]] && return
  p="$(m "$prompt_zh" "$prompt_en")"
  [[ "$NON_INTERACTIVE" -eq 1 ]] && { say "缺少必需选项: $prompt_zh" "Missing required option: $prompt_en" >&2; exit 2; }
  say "$p（输入隐藏，完成后按 Enter）" "$p (input is hidden; press Enter when done):"
  read -r -s current; echo
  while [[ -z "$current" ]]; do
    say "$p 不能为空；输入仍会隐藏，完成后按 Enter。" "$p cannot be empty. Input is still hidden; press Enter when done:"
    read -r -s current; echo
  done
  say "已收到 $p。" "$p received."
  printf -v "$var_name" '%s' "$current"
}
prompt_text() { local var_name="$1" prompt_zh="$2" prompt_en="$3" default="$4" current; set +u; current="${!var_name}"; set -u; [[ -n "$current" ]] && return; [[ "$NON_INTERACTIVE" -eq 1 ]] && { printf -v "$var_name" '%s' "$default"; return; }; read -r -p "$(m "$prompt_zh" "$prompt_en") [$default]: " current; printf -v "$var_name" '%s' "${current:-$default}"; }
prompt_required_text() { local var_name="$1" prompt_zh="$2" prompt_en="$3" current; set +u; current="${!var_name}"; set -u; [[ -n "$current" ]] && return; [[ "$NON_INTERACTIVE" -eq 1 ]] && { say "缺少必需选项: $prompt_zh" "Missing required option: $prompt_en" >&2; exit 2; }; while [[ -z "$current" ]]; do read -r -p "$(m "$prompt_zh" "$prompt_en"): " current; done; printf -v "$var_name" '%s' "$current"; }
valid_time() { [[ "$1" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; }

configure_feishu_inputs() {
  prompt_required_text FEISHU_APP_ID "飞书 App ID" "Feishu App ID"
  if [[ -n "$FEISHU_APP_SECRET_FILE" && ! -r "$FEISHU_APP_SECRET_FILE" ]]; then
    say "无法读取飞书 App Secret 文件: $FEISHU_APP_SECRET_FILE" "Cannot read Feishu App Secret file: $FEISHU_APP_SECRET_FILE" >&2
    exit 2
  fi
  load_feishu_secret_source
  if ! feishu_credential_available; then
    prompt_secret FEISHU_APP_SECRET "飞书 App Secret" "Feishu App Secret"
  fi
  if [[ -z "$FEISHU_RECEIVE_ID" ]]; then
    select_feishu_recipient
  fi
  validate_feishu_receive_id
}

telegram_preflight() {
  channel_selected telegram || return 0
  [[ "$SKIP_TELEGRAM_TEST" -eq 1 ]] && { say "跳过 Telegram 预检。" "Skipping Telegram preflight test."; return; }
  local tg_err send_out
  TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
  tg_err="$TMP_DIR/telegram.err"
  send_out="$TMP_DIR/send.out"
  while true; do
    say "正在验证 Telegram Bot Token..." "Validating Telegram Bot Token..."
    local getme bot_user
    if ! getme="$(printf '%s' "$TELEGRAM_BOT_TOKEN" | python3 -c '
import json, re, sys, urllib.request

token = sys.stdin.read()
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
' 2>"$tg_err")"; then
      say "❌ Telegram token 校验失败。" "❌ Telegram token validation failed."
      cat "$tg_err" 2>/dev/null || true
    else
      bot_user="$(printf '%s' "$getme" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("result",{}).get("username", "unknown"))' 2>/dev/null || echo unknown)"
      say "✅ Token 有效: @${bot_user}" "✅ Token is valid: @${bot_user}"
      say "正在向 Telegram Chat ID 发送测试消息..." "Sending test message to Telegram Chat ID..."
      local text
      text="$(m '✅ security-update-notify Telegram 测试成功。主机: ' '✅ security-update-notify Telegram test succeeded. Host: ')$(hostname -f 2>/dev/null || hostname)"
      if printf '%s\0%s\0%s' "$TELEGRAM_BOT_TOKEN" "$TELEGRAM_CHAT_ID" "$text" | python3 -c '
import json, re, sys, urllib.parse, urllib.request

payload = sys.stdin.buffer.read().split(b"\0", 2)
token = payload[0].decode("utf-8", "replace") if len(payload) > 0 else ""
chat_id = payload[1].decode("utf-8", "replace") if len(payload) > 1 else ""
text = payload[2].decode("utf-8", "replace") if len(payload) > 2 else ""
if not re.match(r"^\d+:[A-Za-z0-9_-]+$", token):
    print("TELEGRAM_BOT_TOKEN 格式无效 / invalid TELEGRAM_BOT_TOKEN format", file=sys.stderr)
    sys.exit(2)
url = f"https://api.telegram.org/bot{token}/sendMessage"
data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
try:
    with urllib.request.urlopen(url, data=data, timeout=20) as response:
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
' >"$send_out" 2>"$tg_err"; then
        say "✅ Telegram 测试消息已发送。" "✅ Telegram test message sent."
        return
      else
        say "❌ Telegram 测试消息发送失败。" "❌ Telegram test message failed."
        cat "$tg_err" 2>/dev/null || true
      fi
    fi
    if [ "${UI_LANG:-zh}" = en ]; then
      cat <<'EOF'
Possible causes:
1. Bot token is wrong
2. Chat ID is wrong
3. You have not sent /start to the bot
4. The bot is not in the target group or cannot post there
5. This server cannot reach api.telegram.org
EOF
    else
      cat <<'EOF'
可能原因:
1. Bot Token 错误
2. Chat ID 错误
3. 你还没有给 bot 发送 /start
4. bot 不在目标群组中，或没有发消息权限
5. 这台服务器无法访问 api.telegram.org
EOF
    fi
    if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
      say "非交互模式：Telegram 预检失败。" "Non-interactive mode: Telegram preflight failed." >&2
      exit 2
    fi
    read -r -p "$(m '重新输入 Telegram token 和 chat ID？[Y/n]: ' 'Re-enter Telegram token and chat ID? [Y/n]: ')" retry
    [[ "${retry:-Y}" =~ ^[Yy]$ ]] || { say "Telegram 预检失败，安装中止。" "Telegram preflight failed; aborting." >&2; exit 2; }
    TELEGRAM_BOT_TOKEN=""
    TELEGRAM_CHAT_ID=""
    prompt_secret TELEGRAM_BOT_TOKEN "Telegram Bot Token" "Telegram Bot Token"
    prompt_required_text TELEGRAM_CHAT_ID "Telegram Chat ID" "Telegram Chat ID"
  done
}

feishu_preflight() {
  channel_selected feishu || return 0
  [[ "$SKIP_FEISHU_TEST" -eq 1 ]] && { say "跳过飞书预检。" "Skipping Feishu preflight test."; return; }
  TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
  local fs_err="$TMP_DIR/feishu.err"
  while true; do
    if [[ "$FEISHU_AUTH_VALIDATED" -eq 1 ]]; then
      say "✅ 飞书应用凭据已在用户扫描时验证。" "✅ Feishu application credentials were validated during the user scan."
      return 0
    fi
    say "正在验证飞书 App ID 和 App Secret（不会发送消息）..." "Validating Feishu App ID and App Secret (no message will be sent)..."
    if { printf '%s\0' "$FEISHU_APP_ID"; feishu_secret_to_stdout; } | python3 -c '
import json, sys, time, urllib.error, urllib.request

payload = sys.stdin.buffer.read().split(b"\0", 1)
app_id = payload[0].decode("utf-8", "replace") if payload else ""
secret = payload[1].decode("utf-8", "replace") if len(payload) > 1 else ""
if not app_id or not secret:
    print("缺少飞书 App ID 或 App Secret / missing Feishu App ID or App Secret", file=sys.stderr)
    sys.exit(2)
req = urllib.request.Request(
    "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
    data=json.dumps({"app_id": app_id, "app_secret": secret}).encode(),
    headers={"Content-Type": "application/json; charset=utf-8"},
    method="POST",
)
for attempt in range(3):
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            body = response.read(1048577)
        break
    except urllib.error.HTTPError as exc:
        try:
            error_body = exc.read(1048577)
        except Exception:
            error_body = b""
        try:
            error_data = json.loads(error_body) if len(error_body) <= 1048576 else {}
        except Exception:
            error_data = {}
        api_code = error_data.get("code") if isinstance(error_data, dict) else None
        retryable = exc.code == 429 or 500 <= exc.code < 600 or api_code == 99991400
        if retryable and attempt < 2:
            headers = exc.headers or {}
            reset = headers.get("x-ogw-ratelimit-reset", "") or headers.get("Retry-After", "")
            try:
                delay = float(reset)
                if delay > time.time():
                    delay -= time.time()
            except (TypeError, ValueError):
                delay = 2 ** attempt
            time.sleep(min(max(delay, 0), 5))
            continue
        print(f"Feishu token HTTP {exc.code}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, TimeoutError, OSError):
        if attempt < 2:
            time.sleep(2 ** attempt)
            continue
        print("Feishu token request failed", file=sys.stderr)
        sys.exit(1)
else:
    print("Feishu token request failed", file=sys.stderr)
    sys.exit(1)
if len(body) > 1048576:
    print("Feishu token response too large", file=sys.stderr)
    sys.exit(1)
try:
    data = json.loads(body)
except Exception:
    print("Invalid Feishu token response", file=sys.stderr)
    sys.exit(1)
if data.get("code") != 0 or not data.get("tenant_access_token"):
    print(f"Feishu token failed: code={data.get('"'"'code'"'"')}", file=sys.stderr)
    sys.exit(1)
' 2>"$fs_err"; then
      FEISHU_AUTH_VALIDATED=1
      say "✅ 飞书应用凭据有效。" "✅ Feishu application credentials are valid."
      return 0
    fi
    say "❌ 飞书凭据校验失败。" "❌ Feishu credential validation failed."
    cat "$fs_err" 2>/dev/null || true
    if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
      say "非交互模式：飞书预检失败。" "Non-interactive mode: Feishu preflight failed." >&2
      exit 2
    fi
    read -r -p "$(m '重新输入飞书凭据？[Y/n]: ' 'Re-enter Feishu credentials? [Y/n]: ')" retry
    [[ "${retry:-Y}" =~ ^[Yy]$ ]] || { say "飞书预检失败，安装中止。" "Feishu preflight failed; aborting." >&2; exit 2; }
    FEISHU_APP_ID=""
    FEISHU_RECEIVE_ID=""
    FEISHU_APP_SECRET_FILE=""
    FEISHU_APP_SECRET=""
    FEISHU_AUTH_VALIDATED=0
    configure_feishu_inputs
  done
}

require_root
choose_language
OLD_VERSION="$(current_installed_version)"
if [[ "$OLD_VERSION" != "none" || -e "$CONFIG_FILE" || -e "$TIMER_FILE" || -e "$SERVICE_FILE" ]]; then
  IN_UPGRADE=1
fi
# 安装前先快照并挂上回滚 trap：失败时恢复已有文件、删除本次新建的文件（全新安装也适用）。
# Snapshot before any change and arm the rollback trap: on failure restore pre-existing files and
# remove files this run created (applies to fresh installs too).
create_backup
trap on_error ERR
load_existing_config_defaults "$CONFIG_FILE"
load_existing_timer_default "$TIMER_FILE"
if [[ "$FEISHU_APP_ID_EXPLICIT" -eq 1 && "$FEISHU_RECEIVE_ID_EXPLICIT" -eq 0 \
      && -n "$FEISHU_RECEIVE_ID" && "$FEISHU_APP_ID" != "$EXISTING_FEISHU_APP_ID" ]]; then
  FEISHU_RECEIVE_ID=""
  say "飞书 App ID 已变更；旧应用的 open_id 不会复用，请重新选择或显式提供接收人。" \
      "Feishu App ID changed; the previous app-scoped open_id will not be reused. Select or provide a recipient again."
fi
[[ "$EXISTING_CONFIG_LOADED" -eq 1 ]] && say "检测到已有配置，升级时将复用未显式覆盖的旧设置。" "Existing config detected; reusing old settings not explicitly overridden."
[[ "$EXISTING_TIMER_LOADED" -eq 1 ]] && say "检测到已有定时器时间：$CHECK_TIME" "Existing timer time detected: $CHECK_TIME"
choose_notify_channels
: "${CHECK_TIME:=09:00}"
: "${DEDUP_INTERVAL_DAYS:=3}"
: "${NOTIFY_LANG:=$UI_LANG}"
: "${BACKEND:=auto}"
: "${INCLUDE_PUBLIC_IP:=1}"
: "${NOTIFY_OK:=0}"
: "${NOTIFY_UPGRADE:=0}"
: "${CHECK_UPDATE_HEALTH:=1}"
: "${STALE_UPDATE_DAYS:=7}"
: "${CHECK_EOL:=1}"
# 始终写入安装器当前的配置 schema 版本，不沿用旧值（避免升级后写回过期的 CONFIG_VERSION）。
# Always write the installer's current config schema version; do not reuse the old one (so an upgrade
# does not write back a stale CONFIG_VERSION).
CONFIG_VERSION=3
[[ -r /etc/os-release ]] || { say "缺少 /etc/os-release" "Missing /etc/os-release" >&2; exit 1; }
lib_read_os_release
lib_detect_backend
DETECTED_BACKEND="$LIB_BACKEND"; SUPPORT_LABEL="$LIB_SUPPORT"
SUPPORTED=0; [[ "$LIB_SUPPORT" != "unsupported" ]] && SUPPORTED=1
[[ "$BACKEND" == "auto" ]] && BACKEND="$DETECTED_BACKEND"
case "$BACKEND" in apt|dnf) ;; *) say "无效或不支持的后端: $BACKEND" "Invalid/unsupported backend: $BACKEND" >&2; exit 2 ;; esac

if [[ "$SUPPORTED" -ne 1 ]]; then
  if [ "${UI_LANG:-zh}" = en ]; then
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
  else
    cat >&2 <<EOF
不支持的发行版: ID=${ID:-unknown} VERSION_ID=${VERSION_ID:-unknown}

正式支持:
- Debian 12 / 13
- Ubuntu 22.04 / 24.04
- RHEL/Rocky/AlmaLinux 8 / 9
- Fedora 当前版本

尽力支持:
- Debian 11
- Ubuntu 20.04
- CentOS Stream 8 / 9
- Amazon Linux 2023

安装器会在不支持的发行版上停止，因为更新与重启检测和发行版强相关。
EOF
  fi
  exit 1
fi

if [[ "$SUPPORT_LABEL" == "best-effort" && "$ALLOW_BEST_EFFORT" -ne 1 ]]; then
  if [ "${UI_LANG:-zh}" = en ]; then
    cat >&2 <<EOF
Detected ${PRETTY_NAME:-$ID $VERSION_ID}, which is best-effort support.

Re-run with --allow-best-effort if you explicitly want to install here.
EOF
  else
    cat >&2 <<EOF
检测到 ${PRETTY_NAME:-$ID $VERSION_ID}，该系统属于尽力支持范围。

如果明确要在这里安装，请加 --allow-best-effort 重新运行。
EOF
  fi
  exit 1
fi

say "检测到 ${PRETTY_NAME:-$ID $VERSION_ID} ($SUPPORT_LABEL, backend=$BACKEND)。" "Detected ${PRETTY_NAME:-$ID $VERSION_ID} ($SUPPORT_LABEL, backend=$BACKEND)."
[[ -d /run/systemd/system ]] || { say "需要 systemd；不支持没有 systemd 的容器。" "systemd is required; containers without systemd are not supported." >&2; exit 1; }
command -v systemctl >/dev/null || { say "需要 systemctl" "systemctl is required" >&2; exit 1; }

# 通知渠道预检即使在全新服务器上也需要 python3/CA 根证书。
# Notification preflight needs python3/CA roots even on fresh servers.
MINIMAL_PACKAGES=()
case "$BACKEND" in
  apt)
    for pkg in python3 ca-certificates; do dpkg -s "$pkg" >/dev/null 2>&1 || MINIMAL_PACKAGES+=("$pkg"); done
    if [[ "${#MINIMAL_PACKAGES[@]}" -gt 0 ]]; then
      say "正在安装预检所需的最小软件包: ${MINIMAL_PACKAGES[*]}" "Installing minimal preflight packages: ${MINIMAL_PACKAGES[*]}"
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${MINIMAL_PACKAGES[@]}"
    fi
    ;;
  dnf)
    for pkg in python3 ca-certificates; do rpm -q "$pkg" >/dev/null 2>&1 || MINIMAL_PACKAGES+=("$pkg"); done
    if [[ "${#MINIMAL_PACKAGES[@]}" -gt 0 ]]; then
      say "正在安装预检所需的最小软件包: ${MINIMAL_PACKAGES[*]}" "Installing minimal preflight packages: ${MINIMAL_PACKAGES[*]}"
      if command -v dnf >/dev/null 2>&1; then dnf install -y "${MINIMAL_PACKAGES[@]}"; elif command -v yum >/dev/null 2>&1; then yum install -y "${MINIMAL_PACKAGES[@]}"; else say "需要 dnf 或 yum" "dnf or yum is required" >&2; exit 1; fi
    fi
    ;;
esac

if channel_selected telegram; then
  prompt_secret TELEGRAM_BOT_TOKEN "Telegram Bot Token" "Telegram Bot Token"
  prompt_required_text TELEGRAM_CHAT_ID "Telegram Chat ID" "Telegram Chat ID"
fi
if channel_selected feishu; then
  configure_feishu_inputs
fi
case "$NOTIFY_LANG" in zh|en) ;; *) say "无效通知语言: $NOTIFY_LANG（应为 zh 或 en）" "Invalid notify language: $NOTIFY_LANG (expected zh or en)" >&2; exit 2 ;; esac
case "${INCLUDE_PUBLIC_IP,,}" in 1|true|yes|on) INCLUDE_PUBLIC_IP=1 ;; 0|false|no|off) INCLUDE_PUBLIC_IP=0 ;; *) say "无效 INCLUDE_PUBLIC_IP: $INCLUDE_PUBLIC_IP（应为 0 或 1）" "Invalid INCLUDE_PUBLIC_IP: $INCLUDE_PUBLIC_IP (expected 0 or 1)" >&2; exit 2 ;; esac
case "${NOTIFY_OK,,}" in 1|true|yes|on) NOTIFY_OK=1 ;; 0|false|no|off) NOTIFY_OK=0 ;; *) say "无效 NOTIFY_OK: $NOTIFY_OK（应为 0 或 1）" "Invalid NOTIFY_OK: $NOTIFY_OK (expected 0 or 1)" >&2; exit 2 ;; esac
case "${NOTIFY_UPGRADE,,}" in 1|true|yes|on) NOTIFY_UPGRADE=1 ;; 0|false|no|off) NOTIFY_UPGRADE=0 ;; *) say "无效 NOTIFY_UPGRADE: $NOTIFY_UPGRADE（应为 0 或 1）" "Invalid NOTIFY_UPGRADE: $NOTIFY_UPGRADE (expected 0 or 1)" >&2; exit 2 ;; esac
case "${CHECK_UPDATE_HEALTH,,}" in 1|true|yes|on) CHECK_UPDATE_HEALTH=1 ;; 0|false|no|off) CHECK_UPDATE_HEALTH=0 ;; *) say "无效 CHECK_UPDATE_HEALTH: $CHECK_UPDATE_HEALTH（应为 0 或 1）" "Invalid CHECK_UPDATE_HEALTH: $CHECK_UPDATE_HEALTH (expected 0 or 1)" >&2; exit 2 ;; esac
[[ "$STALE_UPDATE_DAYS" =~ ^[0-9]+$ ]] || { say "无效 STALE_UPDATE_DAYS: $STALE_UPDATE_DAYS（应为非负整数）" "Invalid STALE_UPDATE_DAYS: $STALE_UPDATE_DAYS (expected a non-negative integer)" >&2; exit 2; }
case "${CHECK_EOL,,}" in 1|true|yes|on) CHECK_EOL=1 ;; 0|false|no|off) CHECK_EOL=0 ;; *) say "无效 CHECK_EOL: $CHECK_EOL（应为 0 或 1）" "Invalid CHECK_EOL: $CHECK_EOL (expected 0 or 1)" >&2; exit 2 ;; esac
prompt_text CHECK_TIME "每日检查时间 HH:MM" "Daily check time HH:MM" "09:00"
if [[ -z "$DEDUP_MODE" ]]; then
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then DEDUP_MODE="daily"; else
    say "相同告警重复提醒模式:" "Same-alert reminder mode:"
    say "  1) once     状态变化前同一告警只提醒一次" "  1) once     same alert only once until state changes"
    say "  2) daily    同一告警每天最多提醒一次（推荐）" "  2) daily    same alert once per day (recommended)"
    say "  3) interval 同一告警每 N 天提醒一次" "  3) interval same alert every N days"
    read -r -p "$(m '请选择 [2]: ' 'Choose [2]: ')" choice
    case "${choice:-2}" in 1) DEDUP_MODE="once" ;; 2) DEDUP_MODE="daily" ;; 3) DEDUP_MODE="interval" ;; *) say "无效选项" "Invalid choice" >&2; exit 2 ;; esac
  fi
fi
case "$DEDUP_MODE" in once|always|daily|interval) ;; *) say "无效去重模式: $DEDUP_MODE（应为 once/daily/interval）" "Invalid dedup mode: $DEDUP_MODE (expected once/daily/interval)" >&2; exit 2 ;; esac
[[ "$DEDUP_MODE" == "always" ]] && DEDUP_MODE="once"  # 把旧值 always 迁移为 once / migrate legacy always -> once
if [[ "$DEDUP_MODE" == "interval" ]]; then
  if [[ "$DEDUP_INTERVAL_DAYS" == "3" && "$NON_INTERACTIVE" -ne 1 ]]; then read -r -p "$(m '同一告警每 N 天重复提醒 [3]: ' 'Repeat same alert every N days [3]: ')" ans; DEDUP_INTERVAL_DAYS="${ans:-3}"; fi
  [[ "$DEDUP_INTERVAL_DAYS" =~ ^[0-9]+$ ]] && [[ "$DEDUP_INTERVAL_DAYS" -ge 1 ]] || { say "无效间隔天数" "Invalid interval days" >&2; exit 2; }
fi
valid_time "$CHECK_TIME" || { say "无效 --time，期望 HH:MM" "Invalid --time, expected HH:MM" >&2; exit 2; }
if [[ "$SEND_TEST" -eq 0 && "$NON_INTERACTIVE" -ne 1 ]]; then read -r -p "$(m '安装后向已配置渠道额外发送测试消息？[y/N]: ' 'Send an additional test message to configured channels after install? [y/N]: ')" ans; [[ "${ans:-N}" =~ ^[Yy]$ ]] && SEND_TEST=1; fi

# 在写入任何系统文件 / 发送预检消息之前先校验配置值（拒绝换行、引号冲突等）。
# Validate config values before writing any system file or sending the preflight message.
validate_config_values

telegram_preflight
feishu_preflight

install_missing_packages() {
  [[ "${#MISSING_PACKAGES[@]}" -eq 0 ]] && { say "所有必需软件包均已安装。" "All required packages are already installed."; return; }
  say "缺少软件包: ${MISSING_PACKAGES[*]}" "Missing packages: ${MISSING_PACKAGES[*]}"
  if [[ "$ASSUME_YES" -ne 1 && "$NON_INTERACTIVE" -ne 1 ]]; then read -r -p "$(m '现在安装缺少的软件包？[Y/n]: ' 'Install missing packages now? [Y/n]: ')" ans; [[ "${ans:-Y}" =~ ^[Yy]$ ]] || { say "缺少必需软件包，无法继续。" "Cannot continue without required packages." >&2; exit 1; }; fi
  case "$BACKEND" in
    apt) apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING_PACKAGES[@]}" ;;
    dnf) if command -v dnf >/dev/null 2>&1; then dnf install -y "${MISSING_PACKAGES[@]}"; elif command -v yum >/dev/null 2>&1; then yum install -y "${MISSING_PACKAGES[@]}"; else say "需要 dnf 或 yum" "dnf or yum is required" >&2; exit 1; fi ;;
  esac
}

MISSING_PACKAGES=()
case "$BACKEND" in
  apt)
    command -v apt-get >/dev/null || { say "需要 apt-get" "apt-get is required" >&2; exit 1; }
    REQUIRED_PACKAGES=(unattended-upgrades needrestart apt-listchanges python3 ca-certificates)
    for pkg in "${REQUIRED_PACKAGES[@]}"; do dpkg -s "$pkg" >/dev/null 2>&1 || MISSING_PACKAGES+=("$pkg"); done
    ;;
  dnf)
    command -v rpm >/dev/null || { say "dnf 后端需要 rpm" "rpm is required for dnf backend" >&2; exit 1; }
    REQUIRED_PACKAGES=(dnf-automatic python3 ca-certificates)
    [[ "${ID:-}" == "fedora" ]] && REQUIRED_PACKAGES+=(dnf-utils) || REQUIRED_PACKAGES+=(yum-utils)
    for pkg in "${REQUIRED_PACKAGES[@]}"; do rpm -q "$pkg" >/dev/null 2>&1 || MISSING_PACKAGES+=("$pkg"); done
    ;;
esac
install_missing_packages
capture_dependency_created_defaults

install -d -m 0750 /etc/security-update-notify /var/lib/security-update-notify
# /usr/local/sbin 是共享的 FHS 目录（标准 0755）：仅在缺失时按 0755 创建，绝不把已存在目录收紧到
# 0750（那会破坏该目录下其它非 root 可执行文件的访问）。
[[ -d /usr/local/sbin ]] || install -d -m 0755 /usr/local/sbin
touch /var/log/security-update-notify.log
chmod 0640 /var/log/security-update-notify.log
if [[ -d /etc/logrotate.d ]]; then
  install -m 0644 "$SCRIPT_DIR/files/security-update-notify.logrotate" /etc/logrotate.d/security-update-notify
fi
# 运行时二进制选择（桥）：优先安装本架构的 Go 二进制，缺失则回退到自包含的 bash 运行时
# （冷门架构兜底）。发布包内 Go 二进制名为 files/security-update-notify-linux-<arch>。
# Runtime binary selection (bridge): prefer this arch's Go binary, else fall back to the self-contained
# bash runtime (orphan-arch fallback). Go binaries are shipped as files/security-update-notify-linux-<arch>.
RUNTIME_IS_GO=0
case "$(uname -m)" in
  x86_64|amd64) go_arch=amd64 ;;
  aarch64|arm64) go_arch=arm64 ;;
  i386|i486|i586|i686) go_arch=386 ;;
  ppc64le) go_arch=ppc64le ;;
  s390x) go_arch=s390x ;;
  *) go_arch="" ;;
esac
if [[ -n "$go_arch" && -f "$SCRIPT_DIR/files/security-update-notify-linux-$go_arch" ]]; then
  install -m 0755 "$SCRIPT_DIR/files/security-update-notify-linux-$go_arch" /usr/local/sbin/security-update-notify
  RUNTIME_IS_GO=1
  say "已安装 Go 运行时二进制（linux-$go_arch）。" "Installed the Go runtime binary (linux-$go_arch)."
else
  install -m 0750 "$SCRIPT_DIR/files/security-update-notify" /usr/local/sbin/security-update-notify
  say "已安装 bash 运行时（无本架构 Go 二进制，回退兜底）。" "Installed the bash runtime (no Go binary for this arch; fallback)."
fi
install -m 0644 "$SCRIPT_DIR/files/security-update-notify.service" /etc/systemd/system/security-update-notify.service

if [[ "$BACKEND" == "apt" ]]; then
  install -d -m 0755 /etc/needrestart/conf.d
  install -m 0644 "$SCRIPT_DIR/files/needrestart-report-only.conf" /etc/needrestart/conf.d/99-security-update-notify-report-only.conf
  if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
    timestamp="$(date +%Y%m%d%H%M%S)"
    cp -a /etc/apt/apt.conf.d/20auto-upgrades "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak.$timestamp"
    if [[ ! -e /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak ]]; then
      cp -a /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak
    fi
  fi
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
  cat >/etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify <<'EOF'
// 本地策略：永不自动重启。发行版软件包保留其默认 Origins-Pattern 安全规则。
// Local policy: never reboot automatically. The distribution package keeps
// its default Origins-Pattern security rules.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::SyslogEnable "true";
EOF
elif [[ "$BACKEND" == "dnf" ]]; then
  if [[ -f /etc/dnf/automatic.conf ]]; then
    cp -a /etc/dnf/automatic.conf "/etc/dnf/automatic.conf.security-update-notify.bak.$(date +%Y%m%d%H%M%S)"
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
        line_key = stripped.split('=', 1)[0].strip() if '=' in stripped else ''
        if in_sec and line_key == key: out.append(f'{key} = {val}'); done=True
        else: out.append(line)
    if not seen: out += [f'[{section}]', f'{key} = {val}']
    elif in_sec and not done: out.append(f'{key} = {val}')
    s='\n'.join(out)+'\n'
for sec,key,val in [('commands','upgrade_type','security'),('commands','apply_updates','yes'),('emitters','emit_via','stdio'),('base','debuglevel','1')]: set_ini(sec,key,val)
p.write_text(s)
PY
  fi
fi

install_feishu_credential

umask 077
{
  echo "# security-update-notify 通知设置；NOTIFY_CHANNELS 可选 telegram、feishu 或两者 / Notification settings; NOTIFY_CHANNELS may be telegram, feishu, or both."
  echo "# 请保持此文件仅 root 可读；飞书 App Secret 使用独立凭据，不写入此文件 / Keep this file root-only; the Feishu App Secret is stored separately."
  printf 'CONFIG_VERSION=%s\n' "$(config_quote "$CONFIG_VERSION")"
  printf 'NOTIFY_CHANNELS=%s\n' "$(config_quote "$NOTIFY_CHANNELS")"
  printf 'TELEGRAM_BOT_TOKEN=%s\n' "$(config_quote "$TELEGRAM_BOT_TOKEN")"
  printf 'TELEGRAM_CHAT_ID=%s\n' "$(config_quote "$TELEGRAM_CHAT_ID")"
  printf 'FEISHU_APP_ID=%s\n' "$(config_quote "$FEISHU_APP_ID")"
  printf 'FEISHU_RECEIVE_ID=%s\n' "$(config_quote "$FEISHU_RECEIVE_ID")"
  printf 'HOST_LABEL=%s\n' "$(config_quote "$HOST_LABEL")"
  printf 'PUBLIC_IP=%s\n' "$(config_quote "$PUBLIC_IP")"
  printf 'INCLUDE_PUBLIC_IP=%s\n' "$(config_quote "$INCLUDE_PUBLIC_IP")"
  printf 'NOTIFY_OK=%s\n' "$(config_quote "$NOTIFY_OK")"
  printf 'NOTIFY_UPGRADE=%s\n' "$(config_quote "$NOTIFY_UPGRADE")"
  printf 'DEDUP_MODE=%s\n' "$(config_quote "$DEDUP_MODE")"
  printf 'DEDUP_INTERVAL_DAYS=%s\n' "$(config_quote "$DEDUP_INTERVAL_DAYS")"
  printf 'NOTIFY_LANG=%s\n' "$(config_quote "$NOTIFY_LANG")"
  printf 'BACKEND=%s\n' "$(config_quote "$BACKEND")"
  printf 'CHECK_UPDATE_HEALTH=%s\n' "$(config_quote "$CHECK_UPDATE_HEALTH")"
  printf 'STALE_UPDATE_DAYS=%s\n' "$(config_quote "$STALE_UPDATE_DAYS")"
  printf 'CHECK_EOL=%s\n' "$(config_quote "$CHECK_EOL")"
} >/etc/security-update-notify/telegram.env
chmod 600 /etc/security-update-notify/telegram.env
cat >/etc/systemd/system/security-update-notify.timer <<EOF
[Unit]
Description=安全更新每日重启/服务重启通知 / Daily security update reboot/service-restart notification

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

# bash 运行时才做语法检查；Go 二进制不是脚本。
[[ "$RUNTIME_IS_GO" -eq 1 ]] || bash -n /usr/local/sbin/security-update-notify
if [[ "$POST_INSTALL_CHECK" -eq 1 ]]; then
  /usr/local/sbin/security-update-notify --version
  systemd-analyze verify /etc/systemd/system/security-update-notify.service /etc/systemd/system/security-update-notify.timer
  # --doctor 是咨询性自检：它会因主机环境（磁盘将满、发行版已 EOL 等）而返回非零，这些并不代表
  # 安装本身失败。故不让它触发 ERR trap 回滚——只打印警告，安装保持完好。
  if ! /usr/local/sbin/security-update-notify --doctor --skip-notify --lang "$UI_LANG"; then
    say "安装已完成，但自检报告了主机环境问题（如磁盘将满或发行版已 EOL）；安装本身完好，请按提示处理环境问题。" \
        "Install completed, but the self-check reported a host-environment issue (e.g. low disk or an EOL release); the install itself is intact—address the reported condition." >&2
  fi
fi
systemctl list-timers security-update-notify.timer --no-pager
[[ "$SEND_TEST" -eq 1 ]] && /usr/local/sbin/security-update-notify --test-ok --no-dedupe

if [[ "$IN_UPGRADE" == "1" && "$NOTIFY_UPGRADE" == "1" ]]; then
  /usr/local/sbin/security-update-notify --notify-upgrade-event --upgrade-from "$OLD_VERSION" --upgrade-to "$(/usr/local/sbin/security-update-notify --version | awk '{print $2; exit}')" || true
fi

trap - ERR
FEISHU_APP_SECRET=""
OLD_FEISHU_SECRET=""

say "已安装 security-update-notify。" "Installed security-update-notify."
[[ -n "$BACKUP_DIR" ]] && say "升级备份: $BACKUP_DIR" "Upgrade backup: $BACKUP_DIR"
say "配置文件: /etc/security-update-notify/telegram.env" "Config: /etc/security-update-notify/telegram.env"
channel_selected feishu && say "飞书 App Secret: 独立 systemd/root 凭据（不在普通配置和升级备份中）" "Feishu App Secret: separate systemd/root credential (not in normal config or upgrade backups)"
say "查看定时器: systemctl list-timers security-update-notify.timer" "Timer:  systemctl list-timers security-update-notify.timer"
