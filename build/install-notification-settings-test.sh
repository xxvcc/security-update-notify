#!/usr/bin/env bash
# Exercise the installer's interactive notification-platform and credential-change state transitions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

python3 - "$ROOT/install.sh" "$TMP/harness.sh" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text()
start = source.index("channel_selected() {")
end = source.index("\nfeishu_credential_available() {", start)
functions = source[start:end]
harness = r'''#!/usr/bin/env bash
set -euo pipefail
UI_LANG="${UI_LANG:-zh}"
NON_INTERACTIVE="${NON_INTERACTIVE:-0}"
EXISTING_CONFIG_LOADED="${TEST_EXISTING_CONFIG_LOADED:-1}"
CONFIGURE_NOTIFICATIONS="${TEST_CONFIGURE_NOTIFICATIONS:-0}"
NOTIFY_CHANNELS_EXPLICIT="${TEST_NOTIFY_CHANNELS_EXPLICIT:-0}"
NOTIFY_CHANNELS="${TEST_NOTIFY_CHANNELS:-telegram}"
EXISTING_NOTIFY_CHANNELS="${TEST_EXISTING_NOTIFY_CHANNELS:-$NOTIFY_CHANNELS}"
NOTIFICATION_SETTINGS_CHANGED="${TEST_NOTIFICATION_SETTINGS_CHANGED:-0}"
TELEGRAM_CONFIGURATION_CHANGED="${TEST_TELEGRAM_CONFIGURATION_CHANGED:-0}"
FEISHU_CONFIGURATION_CHANGED="${TEST_FEISHU_CONFIGURATION_CHANGED:-0}"
FEISHU_FORCE_NEW_SECRET=0
TELEGRAM_BOT_TOKEN="${TEST_TELEGRAM_BOT_TOKEN:-old-token}"
TELEGRAM_CHAT_ID="${TEST_TELEGRAM_CHAT_ID:-old-chat}"
TELEGRAM_BOT_TOKEN_EXPLICIT="${TEST_TELEGRAM_BOT_TOKEN_EXPLICIT:-0}"
TELEGRAM_CHAT_ID_EXPLICIT="${TEST_TELEGRAM_CHAT_ID_EXPLICIT:-0}"
FEISHU_APP_ID="${TEST_FEISHU_APP_ID:-cli_old}"
FEISHU_RECEIVE_ID="${TEST_FEISHU_RECEIVE_ID:-ou_old}"
FEISHU_APP_SECRET=""
FEISHU_APP_SECRET_FILE="${TEST_FEISHU_APP_SECRET_FILE:-}"
FEISHU_APP_ID_EXPLICIT="${TEST_FEISHU_APP_ID_EXPLICIT:-0}"
FEISHU_RECEIVE_ID_EXPLICIT="${TEST_FEISHU_RECEIVE_ID_EXPLICIT:-0}"
FEISHU_APP_SECRET_FILE_EXPLICIT="${TEST_FEISHU_APP_SECRET_FILE_EXPLICIT:-0}"
FEISHU_RECIPIENT_SELECTED=0
m() { if [[ "$UI_LANG" == "en" ]]; then printf %s "$2"; else printf %s "$1"; fi; }
say() { printf '%s\n' "$(m "$1" "$2")"; }
''' + functions + r'''
TELEGRAM_PREFLIGHT_CALLS=0
FEISHU_PREFLIGHT_CALLS=0
telegram_preflight() { TELEGRAM_PREFLIGHT_CALLS=$((TELEGRAM_PREFLIGHT_CALLS + 1)); }
feishu_preflight() { FEISHU_PREFLIGHT_CALLS=$((FEISHU_PREFLIGHT_CALLS + 1)); }
case "${1:-prompt}" in
  prompt) prompt_existing_notification_settings ;;
  prompt-dispatch) prompt_existing_notification_settings; run_notification_preflights ;;
  configure-dispatch) prompt_existing_notification_settings; run_notification_preflights ;;
  dispatch) run_notification_preflights ;;
  manage) manage_notification_settings ;;
  fresh)
    EXISTING_CONFIG_LOADED=0
    NOTIFY_CHANNELS=""
    choose_notify_channels
    ;;
esac
printf 'CHANNELS=%s\n' "$NOTIFY_CHANNELS"
printf 'TELEGRAM_TOKEN=%s\nTELEGRAM_CHAT=%s\n' "$TELEGRAM_BOT_TOKEN" "$TELEGRAM_CHAT_ID"
printf 'FEISHU_APP=%s\nFEISHU_RECIPIENT=%s\n' "$FEISHU_APP_ID" "$FEISHU_RECEIVE_ID"
printf 'FEISHU_SECRET_FILE=%s\n' "$FEISHU_APP_SECRET_FILE"
printf 'SETTINGS_CHANGED=%s\nTELEGRAM_CHANGED=%s\nFEISHU_CHANGED=%s\nFORCE_FEISHU_SECRET=%s\n' \
  "$NOTIFICATION_SETTINGS_CHANGED" "$TELEGRAM_CONFIGURATION_CHANGED" \
  "$FEISHU_CONFIGURATION_CHANGED" "$FEISHU_FORCE_NEW_SECRET"
printf 'TELEGRAM_PREFLIGHT_CALLS=%s\nFEISHU_PREFLIGHT_CALLS=%s\n' \
  "$TELEGRAM_PREFLIGHT_CALLS" "$FEISHU_PREFLIGHT_CALLS"
'''
Path(sys.argv[2]).write_text(harness)
PY
chmod +x "$TMP/harness.sh"

printf '\n' | "$TMP/harness.sh" >"$TMP/keep.out"
grep -Fxq 'CHANNELS=telegram' "$TMP/keep.out"
grep -Fxq 'TELEGRAM_TOKEN=old-token' "$TMP/keep.out"
grep -Fxq 'SETTINGS_CHANGED=0' "$TMP/keep.out"

printf 'y\n2\n3\n1\n' | "$TMP/harness.sh" >"$TMP/add-feishu.out"
grep -Fxq 'CHANNELS=telegram,feishu' "$TMP/add-feishu.out"
grep -Fxq 'TELEGRAM_TOKEN=old-token' "$TMP/add-feishu.out"
grep -Fxq 'FEISHU_APP=' "$TMP/add-feishu.out"
grep -Fxq 'FEISHU_RECIPIENT=' "$TMP/add-feishu.out"
grep -Fxq 'TELEGRAM_CHANGED=0' "$TMP/add-feishu.out"
grep -Fxq 'FEISHU_CHANGED=1' "$TMP/add-feishu.out"
grep -Fxq 'FORCE_FEISHU_SECRET=1' "$TMP/add-feishu.out"

printf 'y\n2\n2\n1\n' | TEST_NOTIFY_CHANNELS=telegram,feishu "$TMP/harness.sh" >"$TMP/remove-telegram.out"
grep -Fxq 'CHANNELS=feishu' "$TMP/remove-telegram.out"
grep -Fxq 'TELEGRAM_TOKEN=' "$TMP/remove-telegram.out"
grep -Fxq 'TELEGRAM_CHAT=' "$TMP/remove-telegram.out"
grep -Fxq 'FEISHU_APP=cli_old' "$TMP/remove-telegram.out"
grep -Fxq 'FEISHU_RECIPIENT=ou_old' "$TMP/remove-telegram.out"

printf 'y\n2\n1\n1\n' | TEST_NOTIFY_CHANNELS=feishu "$TMP/harness.sh" >"$TMP/switch-to-telegram.out"
grep -Fxq 'CHANNELS=telegram' "$TMP/switch-to-telegram.out"
grep -Fxq 'TELEGRAM_TOKEN=' "$TMP/switch-to-telegram.out"
grep -Fxq 'FEISHU_APP=' "$TMP/switch-to-telegram.out"
grep -Fxq 'FEISHU_RECIPIENT=' "$TMP/switch-to-telegram.out"
grep -Fxq 'TELEGRAM_CHANGED=1' "$TMP/switch-to-telegram.out"
grep -Fxq 'FEISHU_CHANGED=0' "$TMP/switch-to-telegram.out"

printf 'y\n3\n1\n' | "$TMP/harness.sh" >"$TMP/change-telegram.out"
grep -Fxq 'TELEGRAM_TOKEN=' "$TMP/change-telegram.out"
grep -Fxq 'TELEGRAM_CHAT=' "$TMP/change-telegram.out"
grep -Fxq 'TELEGRAM_CHANGED=1' "$TMP/change-telegram.out"
grep -Fxq 'SETTINGS_CHANGED=1' "$TMP/change-telegram.out"

printf 'y\n4\n1\n1\n' | TEST_NOTIFY_CHANNELS=feishu "$TMP/harness.sh" >"$TMP/change-recipient.out"
grep -Fxq 'FEISHU_APP=cli_old' "$TMP/change-recipient.out"
grep -Fxq 'FEISHU_RECIPIENT=' "$TMP/change-recipient.out"
grep -Fxq 'FEISHU_CHANGED=1' "$TMP/change-recipient.out"
grep -Fxq 'FORCE_FEISHU_SECRET=0' "$TMP/change-recipient.out"

printf 'y\n4\n2\n1\n' | TEST_NOTIFY_CHANNELS=feishu "$TMP/harness.sh" >"$TMP/change-app.out"
grep -Fxq 'FEISHU_APP=' "$TMP/change-app.out"
grep -Fxq 'FEISHU_RECIPIENT=' "$TMP/change-app.out"
grep -Fxq 'FEISHU_CHANGED=1' "$TMP/change-app.out"
grep -Fxq 'FORCE_FEISHU_SECRET=1' "$TMP/change-app.out"

printf 'y\n4\n3\n1\n' | TEST_NOTIFY_CHANNELS=feishu "$TMP/harness.sh" >"$TMP/change-secret.out"
grep -Fxq 'FEISHU_APP=cli_old' "$TMP/change-secret.out"
grep -Fxq 'FEISHU_RECIPIENT=ou_old' "$TMP/change-secret.out"
grep -Fxq 'FEISHU_CHANGED=1' "$TMP/change-secret.out"
grep -Fxq 'FORCE_FEISHU_SECRET=1' "$TMP/change-secret.out"

printf '1\n' | TEST_CONFIGURE_NOTIFICATIONS=1 "$TMP/harness.sh" >"$TMP/configure-mode.out"
grep -Fxq 'CHANNELS=telegram' "$TMP/configure-mode.out"

printf '1\n' | TEST_CONFIGURE_NOTIFICATIONS=1 TEST_NOTIFY_CHANNELS=telegram,feishu \
  "$TMP/harness.sh" configure-dispatch >"$TMP/configure-noop-dispatch.out"
grep -Fxq 'SETTINGS_CHANGED=0' "$TMP/configure-noop-dispatch.out"
grep -Fxq 'TELEGRAM_PREFLIGHT_CALLS=0' "$TMP/configure-noop-dispatch.out"
grep -Fxq 'FEISHU_PREFLIGHT_CALLS=0' "$TMP/configure-noop-dispatch.out"

TEST_NOTIFY_CHANNELS=telegram,feishu "$TMP/harness.sh" dispatch >"$TMP/normal-dispatch.out"
grep -Fxq 'TELEGRAM_PREFLIGHT_CALLS=1' "$TMP/normal-dispatch.out"
grep -Fxq 'FEISHU_PREFLIGHT_CALLS=1' "$TMP/normal-dispatch.out"

TEST_NOTIFY_CHANNELS=feishu TEST_EXISTING_NOTIFY_CHANNELS=telegram,feishu \
  TEST_NOTIFY_CHANNELS_EXPLICIT=1 "$TMP/harness.sh" prompt-dispatch >"$TMP/explicit-remove-telegram.out"
grep -Fxq 'CHANNELS=feishu' "$TMP/explicit-remove-telegram.out"
grep -Fxq 'TELEGRAM_TOKEN=' "$TMP/explicit-remove-telegram.out"
grep -Fxq 'TELEGRAM_CHAT=' "$TMP/explicit-remove-telegram.out"
grep -Fxq 'FEISHU_APP=cli_old' "$TMP/explicit-remove-telegram.out"
grep -Fxq 'SETTINGS_CHANGED=1' "$TMP/explicit-remove-telegram.out"
grep -Fxq 'FEISHU_CHANGED=0' "$TMP/explicit-remove-telegram.out"
grep -Fxq 'TELEGRAM_PREFLIGHT_CALLS=0' "$TMP/explicit-remove-telegram.out"
grep -Fxq 'FEISHU_PREFLIGHT_CALLS=0' "$TMP/explicit-remove-telegram.out"

TEST_NOTIFY_CHANNELS=telegram TEST_EXISTING_NOTIFY_CHANNELS=telegram,feishu \
  TEST_NOTIFY_CHANNELS_EXPLICIT=1 "$TMP/harness.sh" prompt-dispatch >"$TMP/explicit-remove-feishu.out"
grep -Fxq 'CHANNELS=telegram' "$TMP/explicit-remove-feishu.out"
grep -Fxq 'SETTINGS_CHANGED=1' "$TMP/explicit-remove-feishu.out"
grep -Fxq 'TELEGRAM_PREFLIGHT_CALLS=0' "$TMP/explicit-remove-feishu.out"
grep -Fxq 'FEISHU_PREFLIGHT_CALLS=0' "$TMP/explicit-remove-feishu.out"

TEST_NOTIFY_CHANNELS=telegram TEST_EXISTING_NOTIFY_CHANNELS=feishu \
  TEST_NOTIFY_CHANNELS_EXPLICIT=1 "$TMP/harness.sh" >"$TMP/explicit-add-telegram-missing.out"
grep -Fxq 'TELEGRAM_TOKEN=' "$TMP/explicit-add-telegram-missing.out"
grep -Fxq 'TELEGRAM_CHAT=' "$TMP/explicit-add-telegram-missing.out"
grep -Fxq 'FEISHU_APP=' "$TMP/explicit-add-telegram-missing.out"
grep -Fxq 'TELEGRAM_CHANGED=1' "$TMP/explicit-add-telegram-missing.out"

TEST_NOTIFY_CHANNELS=telegram TEST_EXISTING_NOTIFY_CHANNELS=feishu \
  TEST_NOTIFY_CHANNELS_EXPLICIT=1 TEST_TELEGRAM_BOT_TOKEN=new-token \
  TEST_TELEGRAM_CHAT_ID=new-chat TEST_TELEGRAM_BOT_TOKEN_EXPLICIT=1 \
  TEST_TELEGRAM_CHAT_ID_EXPLICIT=1 "$TMP/harness.sh" >"$TMP/explicit-add-telegram.out"
grep -Fxq 'TELEGRAM_TOKEN=new-token' "$TMP/explicit-add-telegram.out"
grep -Fxq 'TELEGRAM_CHAT=new-chat' "$TMP/explicit-add-telegram.out"

TEST_NOTIFY_CHANNELS=telegram,feishu TEST_EXISTING_NOTIFY_CHANNELS=telegram \
  TEST_NOTIFY_CHANNELS_EXPLICIT=1 TEST_FEISHU_APP_ID=cli_new \
  TEST_FEISHU_RECEIVE_ID=ou_new TEST_FEISHU_APP_SECRET_FILE=/new-secret \
  TEST_FEISHU_APP_ID_EXPLICIT=1 TEST_FEISHU_RECEIVE_ID_EXPLICIT=1 \
  TEST_FEISHU_APP_SECRET_FILE_EXPLICIT=1 "$TMP/harness.sh" >"$TMP/explicit-add-feishu.out"
grep -Fxq 'FEISHU_APP=cli_new' "$TMP/explicit-add-feishu.out"
grep -Fxq 'FEISHU_RECIPIENT=ou_new' "$TMP/explicit-add-feishu.out"
grep -Fxq 'FEISHU_SECRET_FILE=/new-secret' "$TMP/explicit-add-feishu.out"
grep -Fxq 'FEISHU_CHANGED=1' "$TMP/explicit-add-feishu.out"
grep -Fxq 'FORCE_FEISHU_SECRET=1' "$TMP/explicit-add-feishu.out"

TEST_NOTIFY_CHANNELS=telegram,feishu TEST_EXISTING_NOTIFY_CHANNELS=telegram,feishu \
  TEST_NOTIFY_CHANNELS_EXPLICIT=1 TEST_TELEGRAM_BOT_TOKEN=new-token \
  TEST_TELEGRAM_CHAT_ID=new-chat TEST_TELEGRAM_BOT_TOKEN_EXPLICIT=1 \
  TEST_TELEGRAM_CHAT_ID_EXPLICIT=1 "$TMP/harness.sh" prompt-dispatch >"$TMP/explicit-rotate-telegram.out"
grep -Fxq 'SETTINGS_CHANGED=1' "$TMP/explicit-rotate-telegram.out"
grep -Fxq 'TELEGRAM_CHANGED=1' "$TMP/explicit-rotate-telegram.out"
grep -Fxq 'FEISHU_CHANGED=0' "$TMP/explicit-rotate-telegram.out"
grep -Fxq 'TELEGRAM_PREFLIGHT_CALLS=1' "$TMP/explicit-rotate-telegram.out"
grep -Fxq 'FEISHU_PREFLIGHT_CALLS=0' "$TMP/explicit-rotate-telegram.out"

TEST_NOTIFY_CHANNELS=telegram,feishu TEST_EXISTING_NOTIFY_CHANNELS=telegram,feishu \
  TEST_NOTIFY_CHANNELS_EXPLICIT=1 TEST_FEISHU_APP_SECRET_FILE=/new-secret \
  TEST_FEISHU_APP_SECRET_FILE_EXPLICIT=1 "$TMP/harness.sh" prompt-dispatch >"$TMP/explicit-rotate-feishu.out"
grep -Fxq 'SETTINGS_CHANGED=1' "$TMP/explicit-rotate-feishu.out"
grep -Fxq 'TELEGRAM_CHANGED=0' "$TMP/explicit-rotate-feishu.out"
grep -Fxq 'FEISHU_CHANGED=1' "$TMP/explicit-rotate-feishu.out"
grep -Fxq 'FORCE_FEISHU_SECRET=1' "$TMP/explicit-rotate-feishu.out"
grep -Fxq 'TELEGRAM_PREFLIGHT_CALLS=0' "$TMP/explicit-rotate-feishu.out"
grep -Fxq 'FEISHU_PREFLIGHT_CALLS=1' "$TMP/explicit-rotate-feishu.out"

printf '3\n' | TEST_EXISTING_CONFIG_LOADED=0 "$TMP/harness.sh" fresh >"$TMP/fresh.out"
grep -Fq '接收平台:' "$TMP/fresh.out"
grep -Fxq 'CHANNELS=telegram,feishu' "$TMP/fresh.out"

set +e
NON_INTERACTIVE=1 TEST_CONFIGURE_NOTIFICATIONS=1 "$TMP/harness.sh" >"$TMP/noninteractive-configure.out" 2>&1
noninteractive_rc=$?
NON_INTERACTIVE=1 TEST_CONFIGURE_NOTIFICATIONS=1 TEST_NOTIFY_CHANNELS_EXPLICIT=1 \
  "$TMP/harness.sh" >"$TMP/noninteractive-explicit-configure.out" 2>&1
noninteractive_explicit_rc=$?
TEST_EXISTING_CONFIG_LOADED=0 TEST_CONFIGURE_NOTIFICATIONS=1 "$TMP/harness.sh" >"$TMP/missing-config.out" 2>&1
missing_config_rc=$?
set -e
[[ "$noninteractive_rc" -eq 2 ]] || { echo "Expected non-interactive settings exit 2, got $noninteractive_rc" >&2; exit 1; }
[[ "$noninteractive_explicit_rc" -eq 2 ]] || { echo "Expected explicit non-interactive settings exit 2, got $noninteractive_explicit_rc" >&2; exit 1; }
[[ "$missing_config_rc" -eq 2 ]] || { echo "Expected missing-config settings exit 2, got $missing_config_rc" >&2; exit 1; }
grep -Fq '需要交互式终端' "$TMP/noninteractive-configure.out"
grep -Fq '需要交互式终端' "$TMP/noninteractive-explicit-configure.out"
grep -Fq "尚未检测到已有安装" "$TMP/missing-config.out"

echo "Install notification settings test passed."
