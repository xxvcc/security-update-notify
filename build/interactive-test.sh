#!/usr/bin/env bash
# Human-style PTY gate for fresh installs and transactional rollback. Run only
# in a disposable Debian container with the repository mounted at /src.
set -euo pipefail

[[ -f /.dockerenv && "${SUN_CONTAINER_TEST:-0}" == 1 ]] || {
  echo "build/interactive-test.sh must run only in a disposable container" >&2
  exit 2
}
awk '$5 == "/src" { found = 1; if ($6 !~ /(^|,)ro(,|$)/) unsafe = 1 } END { exit !(found && !unsafe) }' /proc/self/mountinfo || {
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
  python3 -I "$ROOT/build/pty-driver.py" --output "$output" "$@"
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
menu_config_secret='123456:ptyMenuConfigHidden'
menu_config_chat_id='-100889'
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
    "$explicit_secret": ["$explicit_chat_id"],
    "$menu_config_secret": ["$menu_config_chat_id"]
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
python3 -I "$ROOT/build/fake-notify-api.py" \
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
enabled_dir="$state/enabled"
active_dir="$state/active-units"
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
    if [[ -e "$enabled_dir/$unit" ]]; then
      echo enabled
      exit 0
    fi
    echo disabled
    exit 1
    ;;
  is-active)
    unit="${*: -1}"
    if [[ "$unit" == security-update-notify.timer && -e "$state/timer-active" ]] || \
       [[ "$unit" != security-update-notify.timer && -e "$active_dir/$unit" ]]; then
      echo active
      exit 0
    fi
    echo inactive
    exit 3
    ;;
  disable)
    for unit in "$@"; do
      [[ "$unit" == -* ]] && continue
      rm -f "$enabled_dir/$unit"
      [[ " $* " == *" --now "* ]] && rm -f "$active_dir/$unit"
      if [[ "$unit" == security-update-notify.timer ]]; then
        rm -f "$link" /run/systemd/system/timers.target.wants/security-update-notify.timer
        [[ " $* " == *" --now "* ]] && rm -f "$state/timer-active"
      fi
    done
    ;;
  enable)
    mkdir -p "$enabled_dir" "$active_dir"
    for unit in "$@"; do
      [[ "$unit" == -* ]] && continue
      touch "$enabled_dir/$unit"
      [[ " $* " == *" --now "* ]] && touch "$active_dir/$unit"
      if [[ "$unit" == security-update-notify.timer ]]; then
        mkdir -p "$(dirname "$link")"
        ln -sfn ../security-update-notify.timer "$link"
        [[ " $* " == *" --now "* ]] && touch "$state/timer-active"
      fi
    done
    ;;
  start)
    unit="${*: -1}"
    mkdir -p "$active_dir"
    touch "$active_dir/$unit"
    if [[ "$unit" == security-update-notify.timer ]]; then
      touch "$state/timer-active"
    fi
    ;;
  stop)
    unit="${*: -1}"
    rm -f "$active_dir/$unit"
    if [[ "$unit" == security-update-notify.timer ]]; then
      rm -f "$state/timer-active"
    fi
    ;;
  daemon-reload|reset-failed)
    ;;
  show)
    ;;
  list-timers)
    if [[ "${SUN_FAIL_LIST_TIMERS:-0}" == 1 ]]; then
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
  if [[ "$2" == unattended-upgrades && ! -e "${SUN_PTY_STATE:?}/dependencies-installed" ]]; then
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
    if [[ " $* " == *' unattended-upgrades '* && \
          ! -e /etc/apt/apt.conf.d/20auto-upgrades ]]; then
      printf '%s\n' \
        'APT::Periodic::Update-Package-Lists "1";' \
        'APT::Periodic::Unattended-Upgrade "1";' \
        >/etc/apt/apt.conf.d/20auto-upgrades
    fi
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

cat >"$MOCK_BIN/unattended-upgrade" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == --help ]]
EOF

chmod 0755 "$MOCK_BIN"/*
export SUN_PTY_STATE="$MOCK_STATE"
export SUN_CONTAINER_TEST_COMMAND_PATH="$MOCK_BIN"
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
  '正在安装依赖软件包: unattended-upgrades' \
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
[[ -e "$MOCK_STATE/enabled/apt-daily-upgrade.timer" ]] || fail "APT automatic timer was not enabled"
[[ -f /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak ]] || \
  fail "dependency-created APT vendor baseline was not preserved"
[[ ! -e /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.absent.bak && \
   ! -e /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.dependency-default.bak ]] || \
  fail "promoted APT baseline retained transient metadata"
apt_vendor_sha="$(sha256sum /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak | awk '{print $1}')"
apt-config dump >"$TMP/apt-config.out" 2>&1
assert_not_contains "$TMP/apt-config.out" "Ignoring file '20auto-upgrades.security-update-notify"

binary_sha="$(sha256sum /usr/local/sbin/security-update-notify | awk '{print $1}')"
config_sha="$(sha256sum /etc/security-update-notify/telegram.env | awk '{print $1}')"
service_sha="$(sha256sum /etc/systemd/system/security-update-notify.service | awk '{print $1}')"
timer_sha="$(sha256sum /etc/systemd/system/security-update-notify.timer | awk '{print $1}')"
apt_sha="$(sha256sum /etc/apt/apt.conf.d/20auto-upgrades | awk '{print $1}')"

echo "### Installed short alias and explicit systemd run contract"
[[ -L /usr/local/sbin/sun ]] || fail "installed sun alias is not a symbolic link"
assert_eq "$(readlink /usr/local/sbin/sun)" "security-update-notify" "installed sun alias target"
assert_contains /etc/systemd/system/security-update-notify.service \
  'ExecStart=/usr/local/sbin/security-update-notify run'

echo "### Bare security-update-notify remains the non-interactive run contract"
command -v flock >/dev/null || fail "flock is required for the bare-run compatibility test"
exec 9>/run/security-update-notify.lock
flock -n 9 || fail "could not hold the runtime lock for the bare-run compatibility test"
set +e
printf '0\n' | /usr/local/sbin/security-update-notify >"$TMP/menu-bare.out" 2>&1
menu_bare_rc=$?
set -e
flock -u 9
exec 9>&-
assert_eq "$menu_bare_rc" 0 "bare security-update-notify exit status under lock contention"
[[ ! -s "$TMP/menu-bare.out" ]] || fail "bare security-update-notify was not a quiet run under lock contention"

echo "### Short alias opens the Chinese menu through argv[0]"
run_pty 0 "$TMP/menu-sun.out" \
  --rows 24 --columns 40 \
  --step visible '请选择 [0-9]（回车重新显示菜单）: ' $'0\n' \
  -- /usr/local/sbin/sun
assert_contains "$TMP/menu-sun.out" '1) 预览本次检查（不发送、不写状态）'
assert_contains "$TMP/menu-sun.out" '0) 退出'

echo "### Explicit English menu runs one read-only action and continues"
run_pty 0 "$TMP/menu-preview.out" \
  --step visible 'Select [0-9] (Enter redraws the menu): ' $'1\n' \
  --step visible 'Select [0-9] (Enter redraws the menu): ' $'0\n' \
  -- /usr/local/sbin/security-update-notify menu --lang en
assert_contains "$TMP/menu-preview.out" '1) Preview this check (no delivery or state writes)'
assert_contains "$TMP/menu-preview.out" $'HASH\t'

echo "### A failed routine action exits with its original status"
mv /etc/security-update-notify/telegram.env "$TMP/menu-action-config"
printf '%s\n' 'invalid-config-line' >/etc/security-update-notify/telegram.env
chmod 0600 /etc/security-update-notify/telegram.env
run_pty 2 "$TMP/menu-action-failure.out" \
  --step visible 'Select [0-9] (Enter redraws the menu): ' $'1\n' \
  -- /usr/local/sbin/security-update-notify menu --lang en
rm -f /etc/security-update-notify/telegram.env
mv "$TMP/menu-action-config" /etc/security-update-notify/telegram.env
assert_eq "$(grep -cF 'Select [0-9] (Enter redraws the menu): ' "$TMP/menu-action-failure.out")" 1 \
  "failed action menu prompt count"

echo "### Blank input redraws and the language switch applies immediately"
run_pty 0 "$TMP/menu-language.out" \
  --step visible '请选择 [0-9]（回车重新显示菜单）: ' $'\n' \
  --step visible '请选择 [0-9]（回车重新显示菜单）: ' $'9\n' \
  --step visible '选择 / Select [0-2]: ' $'2\n' \
  --step visible 'Select [0-9] (Enter redraws the menu): ' $'0\n' \
  -- /usr/local/sbin/security-update-notify menu --lang zh
assert_contains "$TMP/menu-language.out" 'Interface language switched to English for this session.'
assert_contains "$TMP/menu-language.out" '1) Preview this check (no delivery or state writes)'
assert_eq "$(grep -cF '1) 预览本次检查（不发送、不写状态）' "$TMP/menu-language.out")" 2 \
  "menu redraw count before language switch"

echo "### Menu EOF is a localized cancellation with status 2"
run_pty 2 "$TMP/menu-eof.out" \
  --step eof 'Select [0-9] (Enter redraws the menu): ' '' \
  -- /usr/local/sbin/security-update-notify menu --lang en
assert_contains "$TMP/menu-eof.out" 'Input ended; cancelled.'
assert_not_contains "$TMP/menu-eof.out" 'EOF'

echo "### Menu Ctrl-C terminates by SIGINT"
run_pty 130 "$TMP/menu-interrupt.out" \
  --step interrupt 'Select [0-9] (Enter redraws the menu): ' '' \
  -- /usr/local/sbin/security-update-notify menu --lang en
assert_not_contains "$TMP/menu-interrupt.out" 'Input ended; cancelled.'

echo "### Menu refuses non-TTY streams before reading a selection"
set +e
printf '0\n' | /usr/local/sbin/security-update-notify menu --lang en >"$TMP/menu-nontty.out" 2>&1
menu_nontty_rc=$?
set -e
assert_eq "$menu_nontty_rc" 2 "non-TTY menu exit status"
assert_contains "$TMP/menu-nontty.out" \
  'The interactive menu requires stdin, stdout, and stderr to all be attached to a real terminal.'
assert_not_contains "$TMP/menu-nontty.out" 'Preview this check'

echo "### Upgrade and purge cancellation do not dispatch either action"
reset_api_log
run_pty 0 "$TMP/menu-cancel.out" \
  --step visible 'Select [0-9] (Enter redraws the menu): ' $'7\n' \
  --step visible 'The upgrade will download and verify a release. Type YES to continue: ' $'NO\n' \
  --step visible 'Select [0-9] (Enter redraws the menu): ' $'8\n' \
  --step visible 'Select [0-2]: ' $'2\n' \
  --step visible 'removes SUN configuration, notification credentials, state, upgrade backups, and logs. Type PURGE to confirm: ' $'NO\n' \
  --step visible 'Select [0-9] (Enter redraws the menu): ' $'0\n' \
  -- /usr/local/sbin/security-update-notify menu --lang en
assert_eq "$(grep -cF 'Confirmation did not match; cancelled.' "$TMP/menu-cancel.out")" 2 \
  "cancelled terminal-action count"
assert_not_contains "$TMP/menu-cancel.out" 'Downloading and verifying release'
[[ ! -s "$API_LOG" ]] || fail "cancelled menu actions reached the notification API"
assert_eq "$(sha256sum /usr/local/sbin/security-update-notify | awk '{print $1}')" "$binary_sha" \
  "cancelled menu runtime"
assert_eq "$(sha256sum /etc/security-update-notify/telegram.env | awk '{print $1}')" "$config_sha" \
  "cancelled menu config"
assert_eq "$(sha256sum /etc/systemd/system/security-update-notify.service | awk '{print $1}')" "$service_sha" \
  "cancelled menu service"
assert_eq "$(sha256sum /etc/systemd/system/security-update-notify.timer | awk '{print $1}')" "$timer_sha" \
  "cancelled menu timer"
[[ -L /usr/local/sbin/sun && "$(readlink /usr/local/sbin/sun)" == security-update-notify ]] || \
  fail "cancelled menu actions changed the sun alias"

echo "### Menu configuration shares the PTY reader and preserves hidden input"
reset_api_log
run_pty 0 "$TMP/menu-configure.out" \
  --step visible 'Select [0-9] (Enter redraws the menu): ' $'4\n' \
  --step visible 'Change receiving platforms? [y/N]: ' $'n\n' \
  --step visible 'Change Telegram settings? [y/N]: ' $'y\n' \
  --step hidden 'Telegram Bot Token (input hidden): ' "$menu_config_secret"$'\n' \
  --step visible 'Telegram Chat ID: ' "$menu_config_chat_id"$'\n' \
  --step visible 'Send an additional post-install test message to configured receiving platforms? [y/N]: ' $'n\n' \
  -- /usr/local/sbin/sun --lang en
assert_contains "$TMP/menu-configure.out" 'Current notification method: telegram'
assert_contains "$TMP/menu-configure.out" 'Telegram test message sent.'
assert_contains "$TMP/menu-configure.out" 'Upgraded security-update-notify.'
assert_not_contains "$TMP/menu-configure.out" "$menu_config_secret"
assert_eq "$(api_count telegram_get_me)" 1 "menu configure Telegram getMe count"
assert_eq "$(api_count telegram_send)" 1 "menu configure Telegram preflight send count"
assert_contains /etc/security-update-notify/telegram.env "TELEGRAM_CHAT_ID='$menu_config_chat_id'"
config_sha="$(sha256sum /etc/security-update-notify/telegram.env | awk '{print $1}')"

echo "### Human-style failed upgrade rolls the installation back"
run_pty 1 "$TMP/rollback.out" \
  --step visible '额外发送测试消息' $'invalid\n' \
  --step visible '额外发送测试消息' $'n\n' \
  -- env SUN_FAIL_LIST_TIMERS=1 "$runtime" install --lang zh --skip-post-install-check \
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

echo "### Confirmed menu purge exits after dispatch and removes its own entrypoints"
mkdir -p /var/lib/systemd/timers
printf '%s\n' 'SUN timer state' >/var/lib/systemd/timers/stamp-security-update-notify.timer
printf '%s\n' 'unrelated timer state' >/var/lib/systemd/timers/stamp-unrelated.timer
run_pty 0 "$TMP/menu-purge.out" \
  --step visible 'Select [0-9] (Enter redraws the menu): ' $'8\n' \
  --step visible 'Select [0-2]: ' $'2\n' \
  --step visible 'removes SUN configuration, notification credentials, state, upgrade backups, and logs. Type PURGE to confirm: ' $'PURGE\n' \
  -- /usr/local/sbin/sun --lang en
assert_contains "$TMP/menu-purge.out" 'Uninstalled security-update-notify.'
[[ ! -e /usr/local/sbin/security-update-notify ]] || fail "menu purge retained the runtime"
[[ ! -L /usr/local/sbin/sun && ! -e /usr/local/sbin/sun ]] || fail "menu purge retained the sun alias"
[[ ! -e /var/lib/systemd/timers/stamp-security-update-notify.timer &&
   ! -L /var/lib/systemd/timers/stamp-security-update-notify.timer ]] ||
  fail "menu purge retained the SUN timer timestamp"
assert_contains /var/lib/systemd/timers/stamp-unrelated.timer 'unrelated timer state'
assert_eq "$(sha256sum /etc/apt/apt.conf.d/20auto-upgrades | awk '{print $1}')" "$apt_vendor_sha" \
  "retained unattended-upgrades vendor baseline"
find /etc/apt/apt.conf.d -maxdepth 1 -name '20auto-upgrades.security-update-notify*' -print -quit | \
  grep -q . && fail "APT baseline metadata survived purge"

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
/usr/local/sbin/security-update-notify uninstall --purge-config --lang en </dev/null >/dev/null

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
/usr/local/sbin/security-update-notify uninstall --purge-config --lang en </dev/null >/dev/null

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
/usr/local/sbin/security-update-notify uninstall --purge-config --lang en </dev/null >/dev/null

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
/usr/local/sbin/security-update-notify uninstall --purge-config --lang en </dev/null >/dev/null

echo "Interactive PTY installation, notification, and rollback tests passed"
