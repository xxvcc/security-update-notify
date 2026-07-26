#!/usr/bin/env bash
# Human-style PTY gate for fresh installs and transactional rollback. Run only
# in a disposable Debian container with the repository mounted at /src.
set -euo pipefail

[[ -f /.dockerenv && "${SUN_CONTAINER_TEST:-0}" == 1 ]] || {
  echo "build/interactive-test.sh must run only in a disposable container" >&2
  exit 2
}
awk '$5 == "/src" && $6 ~ /(^|,)ro(,|$)/ { found = 1 } END { exit !found }' /proc/self/mountinfo || {
  echo "build/interactive-test.sh requires /src to be mounted read-only" >&2
  exit 2
}

ROOT=/src
TMP="$(mktemp -d)"
API_PID=""
cleanup() {
  if [[ -n "$API_PID" ]]; then
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_contains() {
  local file="$1" text="$2"
  grep -Fq "$text" "$file" || {
    sed -n '1,240p' "$file" >&2
    fail "$(basename "$file") is missing: $text"
  }
}

assert_not_contains() {
  local file="$1" text="$2"
  if grep -Fq "$text" "$file"; then
    sed -n '1,240p' "$file" >&2
    fail "$(basename "$file") unexpectedly contains: $text"
  fi
}

assert_eq() {
  local actual="$1" expected="$2" label="$3"
  [[ "$actual" == "$expected" ]] || fail "$label: got $actual, want $expected"
}

api_count() {
  local event="$1"
  grep -cF "\"event\":\"$event\"" "$API_LOG" || true
}

reset_api_log() {
  : >"$API_LOG"
}

run_pty() {
  local expected="$1" output="$2"
  shift 2
  set +e
  python3 "$ROOT/build/pty-driver.py" --output "$output" "$@"
  local actual=$?
  set -e
  if [[ "$actual" -ne "$expected" ]]; then
    sed -n '1,260p' "$output" >&2
    fail "PTY command exited $actual, want $expected"
  fi
}

export DEBIAN_FRONTEND=noninteractive
/usr/bin/apt-get update -qq
/usr/bin/apt-get install -y -qq --no-install-recommends ca-certificates openssl python3 >/dev/null

CERT_DIR="$TMP/certs"
mkdir -p "$CERT_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
  -subj '/CN=SUN PTY Test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
  -subj '/CN=api.telegram.org' >/dev/null 2>&1
printf '%s\n' \
  'subjectAltName=DNS:api.telegram.org,DNS:open.feishu.cn' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' >"$CERT_DIR/server.ext"
openssl x509 -req -days 2 -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -extfile "$CERT_DIR/server.ext" -out "$CERT_DIR/server.crt" >/dev/null 2>&1
cp "$CERT_DIR/ca.crt" /usr/local/share/ca-certificates/sun-pty-test.crt
update-ca-certificates >/dev/null
printf '%s\n' \
  '127.0.0.1 api.telegram.org' \
  '127.0.0.1 open.feishu.cn' >>/etc/hosts

API_LOG="$TMP/api.jsonl"
reset_api_log
telegram_secret='123456:ptyHiddenToken'
telegram_chat_id='-100777'
dual_telegram_secret='123456:ptyDualHiddenToken'
dual_telegram_chat_id='-100778'
explicit_secret='123456:ptyExplicitHidden'
explicit_chat_id='-100888'
feishu_app_id='cli_pty_app'
feishu_secret='feishu-pty-hidden-secret'
dual_feishu_app_id='cli_pty_dual'
dual_feishu_secret='feishu-pty-dual-hidden-secret'
skip_feishu_app_id='cli_pty_skip'
skip_feishu_secret='feishu-pty-skip-secret'
feishu_receive_id='ou_pty_user'
EXPECTATIONS="$TMP/api-expectations.json"
cat >"$EXPECTATIONS" <<EOF
{
  "telegram": {
    "$telegram_secret": ["$telegram_chat_id"],
    "$dual_telegram_secret": ["$dual_telegram_chat_id"],
    "$explicit_secret": ["$explicit_chat_id"]
  },
  "feishu": {
    "$feishu_app_id": {
      "secret": "$feishu_secret",
      "receive_ids": ["$feishu_receive_id"]
    },
    "$dual_feishu_app_id": {
      "secret": "$dual_feishu_secret",
      "receive_ids": ["$feishu_receive_id"]
    },
    "$skip_feishu_app_id": {
      "secret": "$skip_feishu_secret",
      "receive_ids": ["$feishu_receive_id"]
    }
  }
}
EOF
chmod 0600 "$EXPECTATIONS"
python3 "$ROOT/build/fake-notify-api.py" \
  --cert "$CERT_DIR/server.crt" --key "$CERT_DIR/server.key" --log "$API_LOG" \
  --expectations "$EXPECTATIONS" &
API_PID=$!
for _ in {1..100}; do
  if (exec 3<>/dev/tcp/127.0.0.1/443) 2>/dev/null; then
    exec 3>&-
    exec 3<&-
    break
  fi
  sleep 0.05
done
kill -0 "$API_PID" 2>/dev/null || fail "fake notification API did not start"

MOCK_BIN="$TMP/bin"
MOCK_STATE="$TMP/mock-state"
mkdir -p "$MOCK_BIN" "$MOCK_STATE" /run/systemd/system /etc/systemd/system \
  /etc/apt/apt.conf.d /var/log /etc/logrotate.d

cat >"$MOCK_BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state="${SUN_PTY_STATE:?}"
link=/etc/systemd/system/timers.target.wants/security-update-notify.timer
command="${1:-}"
shift || true
case "$command" in
  is-enabled)
    unit="${*: -1}"
    if [[ "$unit" == security-update-notify.timer ]]; then
      if [[ -L "$link" ]]; then echo enabled; exit 0; fi
      if [[ -f /etc/systemd/system/security-update-notify.timer ]]; then echo disabled; exit 1; fi
      echo not-found
      exit 1
    fi
    echo enabled
    ;;
  is-active)
    unit="${*: -1}"
    [[ "$unit" != security-update-notify.timer || -e "$state/timer-active" ]]
    ;;
  disable)
    if [[ " $* " == *" security-update-notify.timer "* ]]; then
      rm -f "$link" /run/systemd/system/timers.target.wants/security-update-notify.timer \
        "$state/timer-active"
    fi
    ;;
  enable)
    if [[ " $* " == *" security-update-notify.timer "* ]]; then
      mkdir -p "$(dirname "$link")"
      ln -sfn ../security-update-notify.timer "$link"
      [[ " $* " == *" --now "* ]] && touch "$state/timer-active"
    fi
    ;;
  start)
    [[ "${1:-}" == security-update-notify.timer ]] && touch "$state/timer-active"
    ;;
  stop|daemon-reload|reset-failed)
    ;;
  show)
    ;;
  list-timers)
    if [[ "${FAIL_LIST_TIMERS:-0}" == 1 ]]; then
      echo "forced list-timers failure" >&2
      exit 1
    fi
    echo "security-update-notify.timer mock"
    ;;
  *)
    echo "mock systemctl: unsupported arguments: $command $*" >&2
    exit 1
    ;;
esac
EOF

cat >"$MOCK_BIN/systemd-analyze" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$MOCK_BIN/dpkg" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == -s && -n "${2:-}" ]]; then
  if [[ "$2" == apt-listchanges && ! -e "${SUN_PTY_STATE:?}/dependencies-installed" ]]; then
    exit 1
  fi
  printf 'Package: %s\nStatus: install ok installed\n' "$2"
  exit 0
fi
exec /usr/bin/dpkg "$@"
EOF

cat >"$MOCK_BIN/apt-get" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SUN_PTY_STATE:?}/apt-get.log"
case "${1:-}" in
  update|check)
    exit 0
    ;;
  install)
    touch "$SUN_PTY_STATE/dependencies-installed"
    exit 0
    ;;
  -s)
    exit 0
    ;;
esac
exit 0
EOF

cat >"$MOCK_BIN/needrestart" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

chmod 0755 "$MOCK_BIN"/*
export SUN_PTY_STATE="$MOCK_STATE"
export PATH="$MOCK_BIN:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

version="$(sed -n 's/^VERSION="\([^"]*\)"$/\1/p' "$ROOT/VERSION")"
[[ -n "$version" && "$(wc -l <"$ROOT/VERSION")" -eq 1 ]] || fail "invalid VERSION"
runtime="${SUN_PTY_RUNTIME:-}"
if [[ -z "$runtime" ]]; then
  tarball="$ROOT/dist/security-update-notify-$version.tar.gz"
  [[ -f "$tarball" ]] || fail "release tarball missing: $tarball"
  tar -xzf "$tarball" -C "$TMP"
  runtime="$TMP/security-update-notify-$version/files/security-update-notify-linux-amd64"
fi
[[ -x "$runtime" ]] || fail "packaged amd64 runtime is missing"
[[ "$("$runtime" --version)" == "security-update-notify $version" ]] || fail "runtime version does not match $version"

echo "### PTY EOF cancellation before a fresh install"
run_pty 2 "$TMP/eof.out" \
  --step eof '请选择语言 / Choose a language' '' \
  -- "$runtime" install --skip-post-install-check
assert_contains "$TMP/eof.out" '已取消。'
assert_not_contains "$TMP/eof.out" 'EOF'
[[ ! -e /usr/local/sbin/security-update-notify ]] || fail "EOF cancellation mutated the installation"

echo "### Human-style fresh Telegram install with invalid-input retries"
reset_api_log
run_pty 0 "$TMP/telegram.out" \
  --step visible '请选择语言 / Choose a language' $'9\n' \
  --step visible '请选择语言 / Choose a language' $'1\n' \
  --step visible '接收平台:' $'9\n' \
  --step visible '接收平台:' $'1\n' \
  --step hidden 'Telegram Bot Token（输入隐藏）:' $'\n' \
  --step hidden 'Telegram Bot Token（输入隐藏）:' "$telegram_secret"$'\n' \
  --step visible 'Telegram Chat ID:' $'\n' \
  --step visible 'Telegram Chat ID:' "$telegram_chat_id"$'\n' \
  --step visible '每日检查时间 HH:MM' $'25:00\n' \
  --step visible '每日检查时间 HH:MM' $'08:45\n' \
  --step visible '1) 仅一次' $'9\n' \
  --step visible '1) 仅一次' $'3\n' \
  --step visible '同一告警每 N 天重复提醒' $'0\n' \
  --step visible '同一告警每 N 天重复提醒' $'5\n' \
  --step visible '额外发送测试消息' $'maybe\n' \
  --step visible '额外发送测试消息' $'n\n' \
  --step visible '现在安装这些软件包？' $'maybe\n' \
  --step visible '现在安装这些软件包？' $'y\n' \
  -- "$runtime" install --skip-post-install-check --include-public-ip 0
for text in \
  '无效选择，请重新输入。' \
  '输入不能为空，请重新输入。' \
  '时间无效，请使用 HH:MM' \
  '请输入大于 0 的整数。' \
  '无效输入，请输入 y 或 n。' \
  '正在安装依赖软件包: apt-listchanges' \
  'Telegram 测试消息已发送。' \
  '已安装 security-update-notify。'; do
  assert_contains "$TMP/telegram.out" "$text"
done
assert_not_contains "$TMP/telegram.out" "$telegram_secret"
assert_eq "$(api_count telegram_get_me)" 1 "default Telegram getMe count"
assert_eq "$(api_count telegram_send)" 1 "default Telegram preflight send count"
assert_contains /etc/security-update-notify/telegram.env "TELEGRAM_CHAT_ID='$telegram_chat_id'"
assert_contains /etc/security-update-notify/telegram.env "DEDUP_MODE='interval'"
assert_contains /etc/security-update-notify/telegram.env "DEDUP_INTERVAL_DAYS='5'"
assert_contains /etc/systemd/system/security-update-notify.timer 'OnCalendar=*-*-* 08:45:00'
[[ -L /etc/systemd/system/timers.target.wants/security-update-notify.timer ]] || fail "timer was not enabled"
[[ -e "$MOCK_STATE/timer-active" ]] || fail "timer was not started"
apt-config dump >"$TMP/apt-config.out" 2>&1
assert_not_contains "$TMP/apt-config.out" "Ignoring file '20auto-upgrades.security-update-notify"

binary_sha="$(sha256sum /usr/local/sbin/security-update-notify | awk '{print $1}')"
config_sha="$(sha256sum /etc/security-update-notify/telegram.env | awk '{print $1}')"
service_sha="$(sha256sum /etc/systemd/system/security-update-notify.service | awk '{print $1}')"
timer_sha="$(sha256sum /etc/systemd/system/security-update-notify.timer | awk '{print $1}')"
apt_sha="$(sha256sum /etc/apt/apt.conf.d/20auto-upgrades | awk '{print $1}')"

echo "### Human-style failed upgrade rolls the installation back"
run_pty 1 "$TMP/rollback.out" \
  --step visible '额外发送测试消息' $'invalid\n' \
  --step visible '额外发送测试消息' $'n\n' \
  -- env FAIL_LIST_TIMERS=1 "$runtime" install --lang zh --skip-post-install-check \
    --host-label pty-rollback-must-not-survive --include-public-ip 0
assert_contains "$TMP/rollback.out" '无效输入，请输入 y 或 n。'
assert_contains "$TMP/rollback.out" 'forced list-timers failure'
assert_eq "$(sha256sum /usr/local/sbin/security-update-notify | awk '{print $1}')" "$binary_sha" "runtime rollback"
assert_eq "$(sha256sum /etc/security-update-notify/telegram.env | awk '{print $1}')" "$config_sha" "config rollback"
assert_eq "$(sha256sum /etc/systemd/system/security-update-notify.service | awk '{print $1}')" "$service_sha" "service rollback"
assert_eq "$(sha256sum /etc/systemd/system/security-update-notify.timer | awk '{print $1}')" "$timer_sha" "timer rollback"
assert_eq "$(sha256sum /etc/apt/apt.conf.d/20auto-upgrades | awk '{print $1}')" "$apt_sha" "APT policy rollback"
assert_not_contains /etc/security-update-notify/telegram.env 'pty-rollback-must-not-survive'
[[ -L /etc/systemd/system/timers.target.wants/security-update-notify.timer ]] || fail "rollback lost timer enablement"
[[ -e "$MOCK_STATE/timer-active" ]] || fail "rollback lost timer activity"

/usr/local/sbin/security-update-notify uninstall --purge-config --lang en >/dev/null

echo "### Human-style fresh Telegram + Feishu install validates both receiving platforms"
reset_api_log
run_pty 0 "$TMP/dual-default.out" \
  --step visible '接收平台:' $'3\n' \
  --step hidden 'Telegram Bot Token（输入隐藏）:' "$dual_telegram_secret"$'\n' \
  --step visible 'Telegram Chat ID:' "$dual_telegram_chat_id"$'\n' \
  --step visible '飞书 App ID / Feishu App ID:' "$dual_feishu_app_id"$'\n' \
  --step hidden '飞书 App Secret / Feishu App Secret（输入隐藏）:' "$dual_feishu_secret"$'\n' \
  --step visible '每日检查时间 HH:MM' $'\n' \
  --step visible '1) 仅一次' $'\n' \
  --step visible '确认飞书接收人可用？' $'\n' \
  --step visible '请选择飞书接收人编号:' $'1\n' \
  -- "$runtime" install --lang zh --skip-post-install-check --include-public-ip 0
assert_contains "$TMP/dual-default.out" 'Telegram 测试消息已发送。'
assert_contains "$TMP/dual-default.out" '飞书接收人测试消息已发送。'
assert_not_contains "$TMP/dual-default.out" "$dual_telegram_secret"
assert_not_contains "$TMP/dual-default.out" "$dual_feishu_secret"
assert_eq "$(api_count telegram_get_me)" 1 "dual Telegram getMe count"
assert_eq "$(api_count telegram_send)" 1 "dual Telegram preflight send count"
assert_eq "$(api_count feishu_directory)" 1 "dual Feishu directory count"
assert_eq "$(api_count feishu_token)" 3 "dual Feishu token count"
assert_eq "$(api_count feishu_send)" 1 "dual Feishu strong-test count"
assert_contains /etc/security-update-notify/telegram.env "NOTIFY_CHANNELS='telegram,feishu'"
assert_contains /etc/security-update-notify/telegram.env "TELEGRAM_CHAT_ID='$dual_telegram_chat_id'"
assert_contains /etc/security-update-notify/telegram.env "FEISHU_APP_ID='$dual_feishu_app_id'"
assert_contains /etc/security-update-notify/telegram.env "FEISHU_RECEIVE_ID='$feishu_receive_id'"
/usr/local/sbin/security-update-notify uninstall --purge-config --lang en >/dev/null

echo "### Fresh Feishu install performs the default strong recipient test"
reset_api_log
run_pty 0 "$TMP/feishu-default.out" \
  --step visible '接收平台:' $'2\n' \
  --step visible '飞书 App ID / Feishu App ID:' $'\n' \
  --step visible '飞书 App ID / Feishu App ID:' "$feishu_app_id"$'\n' \
  --step hidden '飞书 App Secret / Feishu App Secret（输入隐藏）:' $'\n' \
  --step hidden '飞书 App Secret / Feishu App Secret（输入隐藏）:' "$feishu_secret"$'\n' \
  --step visible '每日检查时间 HH:MM' $'\n' \
  --step visible '1) 仅一次' $'\n' \
  --step visible '确认飞书接收人可用？' $'\n' \
  --step visible '请选择飞书接收人编号:' $'9\n' \
  --step visible '请选择飞书接收人编号:' $'1\n' \
  -- "$runtime" install --lang zh --skip-post-install-check --include-public-ip 0
assert_contains "$TMP/feishu-default.out" '输入不能为空，请重新输入。'
assert_contains "$TMP/feishu-default.out" '无效编号。'
assert_contains "$TMP/feishu-default.out" '飞书接收人测试消息已发送。'
assert_not_contains "$TMP/feishu-default.out" "$feishu_secret"
assert_eq "$(api_count feishu_directory)" 1 "default Feishu directory count"
assert_eq "$(api_count feishu_token)" 3 "default Feishu token count"
assert_eq "$(api_count feishu_send)" 1 "default Feishu strong-test count"
assert_contains /etc/security-update-notify/telegram.env "FEISHU_RECEIVE_ID='$feishu_receive_id'"
/usr/local/sbin/security-update-notify uninstall --purge-config --lang en >/dev/null

echo "### --skip-notify-test suppresses the default Feishu delivery"
reset_api_log
run_pty 0 "$TMP/feishu-skip.out" \
  --step visible '接收平台:' $'2\n' \
  --step visible '飞书 App ID / Feishu App ID:' "$skip_feishu_app_id"$'\n' \
  --step hidden '飞书 App Secret / Feishu App Secret（输入隐藏）:' "$skip_feishu_secret"$'\n' \
  --step visible '每日检查时间 HH:MM' $'\n' \
  --step visible '1) 仅一次' $'\n' \
  --step visible '请选择飞书接收人编号:' $'1\n' \
  -- "$runtime" install --lang zh --skip-notify-test --skip-post-install-check --include-public-ip 0
assert_not_contains "$TMP/feishu-skip.out" '确认飞书接收人可用？'
assert_not_contains "$TMP/feishu-skip.out" "$skip_feishu_secret"
assert_eq "$(api_count feishu_directory)" 1 "skipped Feishu directory count"
assert_eq "$(api_count feishu_token)" 1 "skipped Feishu token count"
assert_eq "$(api_count feishu_send)" 0 "skipped Feishu message count"
/usr/local/sbin/security-update-notify uninstall --purge-config --lang en >/dev/null

echo "### Explicit --send-test overrides the preflight skip only for the post-install test"
reset_api_log
run_pty 0 "$TMP/explicit-send.out" \
  --step visible '接收平台:' $'1\n' \
  --step hidden 'Telegram Bot Token（输入隐藏）:' "$explicit_secret"$'\n' \
  --step visible 'Telegram Chat ID:' "$explicit_chat_id"$'\n' \
  --step visible '每日检查时间 HH:MM' $'\n' \
  --step visible '1) 仅一次' $'\n' \
  -- "$runtime" install --lang zh --skip-notify-test --send-test \
    --skip-post-install-check --include-public-ip 0
assert_not_contains "$TMP/explicit-send.out" "$explicit_secret"
assert_eq "$(api_count telegram_get_me)" 0 "explicit skipped preflight getMe count"
assert_eq "$(api_count telegram_send)" 1 "explicit post-install send count"
assert_contains "$TMP/explicit-send.out" '已安装 security-update-notify。'
/usr/local/sbin/security-update-notify uninstall --purge-config --lang en >/dev/null

echo "Interactive PTY installation, notification, and rollback tests passed"
