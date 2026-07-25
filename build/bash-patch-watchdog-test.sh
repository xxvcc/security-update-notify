#!/usr/bin/env bash
# Exercise all seven patch-watchdog checks in the Bash fallback with deterministic command mocks.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

RUNTIME="$ROOT/files/security-update-notify"
RUNTIME_VERSION="$(sed -n 's/^VERSION="\([^"]*\)"/\1/p' "$RUNTIME" | head -1)"
[[ -n "$RUNTIME_VERSION" ]]
MOCK_BIN="$TMP/bin"
STATE_DIR="$TMP/state"
APT_LISTS="$TMP/apt-lists"
mkdir -p "$MOCK_BIN" "$STATE_DIR" "$APT_LISTS"

cat >"$MOCK_BIN/apt-get" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  '-s upgrade')
    [[ "${PATCH_TEST_MODE:-}" == pending ]] && echo 'Inst openssl [1.0] (1.1 Debian-Security:stable-security [amd64])'
    exit 0
    ;;
  '-s --ignore-hold upgrade')
    if [[ "${PATCH_TEST_MODE:-}" == hold ]]; then
      echo 'Inst openssl [1.0] (1.1 Debian-Security:stable-security [amd64])'
    elif [[ "${PATCH_TEST_MODE:-}" == pending ]]; then
      echo 'Inst openssl [1.0] (1.1 Debian-Security:stable-security [amd64])'
    fi
    exit 0
    ;;
  'check -qq')
    [[ "${PATCH_TEST_MODE:-}" == broken ]] && exit 1
    exit 0
    ;;
esac
exit 0
EOF

cat >"$MOCK_BIN/apt-mark" <<'EOF'
#!/usr/bin/env bash
[[ "$*" == showhold && "${PATCH_TEST_MODE:-}" == hold ]] && echo openssl
exit 0
EOF

cat >"$MOCK_BIN/apt-config" <<'EOF'
#!/usr/bin/env bash
if [[ "${PATCH_TEST_MODE:-}" == drift ]]; then
  echo 'APT::Periodic::Update-Package-Lists "0";'
  echo 'APT::Periodic::Unattended-Upgrade "0";'
  exit 0
fi
cat <<'OUT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename}-security";
Unattended-Upgrade::Automatic-Reboot "false";
OUT
EOF

cat >"$MOCK_BIN/dpkg" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == '--audit' && "${PATCH_TEST_MODE:-}" == broken ]]; then
  echo 'package is only half configured'
fi
exit 0
EOF

cat >"$MOCK_BIN/needrestart" <<'EOF'
#!/usr/bin/env bash
if [[ "${PATCH_TEST_MODE:-}" == service ]]; then
  cat <<'OUT'
NEEDRESTART-VER: 3.6
NEEDRESTART-KCUR: 6.1.0
NEEDRESTART-KEXP: 6.1.0
NEEDRESTART-KSTA: 1
NEEDRESTART-SVC: ssh.service
OUT
fi
exit 0
EOF

cat >"$MOCK_BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  is-enabled) exit 0 ;;
  list-timers) exit 0 ;;
  show)
    unit="${2:-}"; property="${4:-}"
    if [[ "$property" == Result ]]; then
      if [[ "$unit" == apt-daily.service && "${PATCH_TEST_MODE:-}" == repository ]]; then
        echo failed
      else
        echo success
      fi
    fi
    exit 0
    ;;
esac
exit 0
EOF

cat >"$MOCK_BIN/journalctl" <<'EOF'
#!/usr/bin/env bash
[[ "${PATCH_TEST_MODE:-}" == repository ]] && echo 'TLS certificate verification failed'
exit 0
EOF

cat >"$MOCK_BIN/python3" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == - && "${2:-}" == xxvcc/security-update-notify ]]; then
  printf 'query\n' >>"$PATCH_TEST_VERSION_CALLS"
  printf '%s\n' "${PATCH_TEST_LATEST:-9.9.9}"
  exit 0
fi
exec /usr/bin/python3 "$@"
EOF

chmod +x "$MOCK_BIN"/*
printf 'Valid-Until: Fri, 25 Jul 2099 12:00:00 +0000\n' >"$APT_LISTS/debian-security_InRelease"

# Lock the shared Go/Bash dynamic-reason wire value (sorted details, no trailing newline, first 12 hex).
eval "$(awk '/^stable_patch_reason\(\) \{/{copy=1} /^repository_signature_error\(\) \{/{copy=0} copy' "$RUNTIME")"
test "$(stable_patch_reason blocked-packages openssl)" = blocked-packages-41ffca929b95

write_config() {
  local health="$1" self_update="$2"
  cat >"$TMP/runtime.env" <<EOF
CONFIG_VERSION=4
NOTIFY_CHANNELS=telegram
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
HOST_LABEL=patch-test-host
INCLUDE_PUBLIC_IP=0
NOTIFY_OK=0
NOTIFY_UPGRADE=0
DEDUP_MODE=once
DEDUP_INTERVAL_DAYS=3
NOTIFY_LANG=zh
BACKEND=apt
CHECK_UPDATE_HEALTH=$health
STALE_UPDATE_DAYS=7
CHECK_EOL=0
PENDING_ALERT_DAYS=3
RESTART_ALERT_DAYS=7
CHECK_SELF_UPDATE=$self_update
SELF_UPDATE_CHECK_DAYS=7
EOF
}

run_runtime() {
  local mode="$1" output="$2"
  shift 2
  set +e
  PATH="$MOCK_BIN:$PATH" \
    PATCH_TEST_MODE="$mode" \
    PATCH_TEST_VERSION_CALLS="$TMP/version.calls" \
    SECURITY_UPDATE_NOTIFY_ENV="$TMP/runtime.env" \
    SECURITY_UPDATE_NOTIFY_STATE_DIR="$STATE_DIR" \
    SECURITY_UPDATE_NOTIFY_LOCK_FILE="$TMP/runtime.lock" \
    SECURITY_UPDATE_NOTIFY_LOG_FILE="$TMP/runtime.log" \
    SECURITY_UPDATE_NOTIFY_APT_LISTS_DIR="$APT_LISTS" \
    "$RUNTIME" "$@" >"$output" 2>&1
  LAST_RC=$?
  set -e
}

# State lifecycle: a normal run creates first_seen and a cleared condition removes it.
write_config 0 0
run_runtime pending "$TMP/pending-first.out"
test -s "$STATE_DIR/pending-security.first_seen"
run_runtime healthy "$TMP/pending-clear.out"
test ! -e "$STATE_DIR/pending-security.first_seen"

# 1. A pending security backlog crosses the configured age threshold.
printf '%s\n' "$(( $(date +%s) - 4 * 86400 ))" >"$STATE_DIR/pending-security.first_seen"
run_runtime pending "$TMP/pending-stale.out" --doctor --skip-notify
grep -Fq '待安装安全更新已连续存在 4 天（阈值 3 天）' "$TMP/pending-stale.out"

# 2. apt hold hides a security update that appears with --ignore-hold.
write_config 1 0
run_runtime hold "$TMP/hold.out" --doctor --skip-notify
grep -Fq '安全更新被 hold、versionlock 或 exclude 阻止：openssl' "$TMP/hold.out"

# 3. Effective auto-update policy drift is detected.
run_runtime drift "$TMP/drift.out" --doctor --skip-notify
grep -Fq 'APT 每日软件源刷新策略未启用' "$TMP/drift.out"
grep -Fq 'APT 自动安全更新策略未启用' "$TMP/drift.out"

# 4. Package-manager integrity failures are detected.
run_runtime broken "$TMP/broken.out" --doctor --skip-notify
grep -Fq 'dpkg 报告未完成或损坏的软件包状态' "$TMP/broken.out"
grep -Fq 'APT 依赖一致性检查失败' "$TMP/broken.out"

# 5. Expired metadata and a repository TLS/signature failure are classified separately.
printf 'Valid-Until: Fri, 25 Jul 2025 12:00:00 +0000\n' >"$APT_LISTS/debian-security_InRelease"
run_runtime repository "$TMP/repository.out" --doctor --skip-notify
grep -Fq 'APT 软件源元数据签名、有效期或 TLS 校验失败' "$TMP/repository.out"
grep -Fq 'APT 软件源元数据已过有效期' "$TMP/repository.out"
printf 'Valid-Until: Fri, 25 Jul 2099 12:00:00 +0000\n' >"$APT_LISTS/debian-security_InRelease"
printf 'Valid-Until: Fri, 25 Jul 2099 12:00:00 +0000\n' >"$APT_LISTS/debian-main_InRelease"
touch -d '8 days ago' "$APT_LISTS/debian-security_InRelease"
touch "$APT_LISTS/debian-main_InRelease"
run_runtime healthy "$TMP/repository-stale-security.out" --doctor --skip-notify
grep -Fq 'APT 软件源元数据已超过 7 天未刷新' "$TMP/repository-stale-security.out"
touch "$APT_LISTS/debian-security_InRelease"

# 6. A service-restart requirement escalates only after its age threshold.
printf '%s\n' "$(( $(date +%s) - 8 * 86400 ))" >"$STATE_DIR/service-restart.first_seen"
run_runtime service "$TMP/service-stale.out" --doctor --skip-notify
grep -Fq '服务重启需求已持续 8 天（阈值 7 天）' "$TMP/service-stale.out"

# 7. The SUN release check caches for seven days, doctor forces a read-only refresh, and test mode skips it.
write_config 0 1
: >"$TMP/version.calls"
rm -rf "$STATE_DIR"
mkdir -p "$STATE_DIR"
run_runtime healthy "$TMP/version-first.out"
test "$(wc -l <"$TMP/version.calls")" -eq 1
test "$(cat "$STATE_DIR/self-update.latest")" = 9.9.9
checked_before="$(cat "$STATE_DIR/self-update.checked_at")"
run_runtime healthy "$TMP/version-cached.out"
test "$(wc -l <"$TMP/version.calls")" -eq 1
run_runtime healthy "$TMP/version-doctor.out" --doctor --skip-notify
test "$(wc -l <"$TMP/version.calls")" -eq 2
test "$(cat "$STATE_DIR/self-update.checked_at")" = "$checked_before"
grep -Fq "SUN 新版本可用：$RUNTIME_VERSION -> 9.9.9" "$TMP/version-doctor.out"

rm -rf "$STATE_DIR"
mkdir -p "$STATE_DIR"
run_runtime healthy "$TMP/version-test-ok.out" --test-ok
test "$(wc -l <"$TMP/version.calls")" -eq 2
test ! -e "$STATE_DIR/self-update.checked_at"

echo "Bash patch watchdog covers backlog age, blocked updates, policy drift, package integrity, repository health, restart age, and notify-only SUN version caching"
