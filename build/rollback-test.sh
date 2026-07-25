#!/usr/bin/env bash
# 安装/升级回滚测试：覆盖运行锁竞争、启用 timer 后的晚失败，以及已有 timer 的 enabled/active 状态恢复。
# 后续升级故障还必须把配置、二进制和飞书凭据回滚到 install #1 的状态。
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null; apt-get install -y python3 ca-certificates file systemd >/dev/null
mkdir -p /run/systemd/system /etc/systemd/system /usr/local/sbin /etc/security-update-notify \
         /var/lib/security-update-notify /var/log /etc/logrotate.d

# systemctl 桩：真实建/删 persistent/runtime enable symlink，并记录 active 状态。
export MOCK_SYSTEMD_STATE=/tmp/security-update-notify-mock-systemd
mkdir -p "$MOCK_SYSTEMD_STATE"
printf '0\n' >"$MOCK_SYSTEMD_STATE/active"
printf '0\n' >"$MOCK_SYSTEMD_STATE/service-queued"
export FAIL_ACTIVE_DURING_RELOAD=1
export QUEUE_SERVICE_ON_TIMER_DISABLE=1
cat >/usr/local/bin/systemctl <<'EOF'
#!/usr/bin/env bash
set -u
state="${MOCK_SYSTEMD_STATE:?}"
active="$state/active"
service_queued="$state/service-queued"
persistent_link=/etc/systemd/system/timers.target.wants/security-update-notify.timer
runtime_link=/run/systemd/system/timers.target.wants/security-update-notify.timer
unit=/etc/systemd/system/security-update-notify.timer
has_project_timer=0
has_project_service=0
has_now=0
has_runtime=0
for arg in "$@"; do
  [[ "$arg" == security-update-notify.timer ]] && has_project_timer=1
  [[ "$arg" == security-update-notify.service ]] && has_project_service=1
  [[ "$arg" == --now ]] && has_now=1
  [[ "$arg" == --runtime ]] && has_runtime=1
done
if [[ "${1:-}" == "enable" ]]; then
  [[ "$has_project_timer" -eq 1 ]] || exit 0
  [[ "${FAIL_ENABLE:-0}" != "1" ]] || { echo "mock: enable failed" >&2; exit 1; }
  if [[ "$has_runtime" -eq 1 ]]; then
    mkdir -p "$(dirname "$runtime_link")"
    ln -sfn /etc/systemd/system/security-update-notify.timer "$runtime_link"
  else
    mkdir -p "$(dirname "$persistent_link")"
    ln -sfn ../security-update-notify.timer "$persistent_link"
  fi
  [[ "$has_now" -eq 0 ]] || printf '1\n' >"$active"
  exit 0
fi
case "${1:-}" in
  disable)
    [[ "$has_project_timer" -eq 1 ]] || exit 0
    if [[ "$has_runtime" -eq 1 ]]; then
      rm -f "$runtime_link"
    else
      rm -f "$persistent_link" "$runtime_link"
    fi
    [[ "$has_now" -eq 0 ]] || printf '0\n' >"$active"
    if [[ "$has_now" -eq 1 && "${QUEUE_SERVICE_ON_TIMER_DISABLE:-0}" == "1" ]]; then
      printf '1\n' >"$service_queued"
    fi
    ;;
  start|restart)
    if [[ "$has_project_timer" -eq 1 ]]; then
      [[ "${FAIL_START:-0}" != "1" ]] || { echo "mock: start failed" >&2; exit 1; }
      printf '1\n' >"$active"
    fi
    ;;
  stop)
    [[ "$has_project_timer" -eq 0 ]] || printf '0\n' >"$active"
    [[ "$has_project_service" -eq 0 ]] || printf '0\n' >"$service_queued"
    ;;
  list-timers)
    if [[ "$has_project_timer" -eq 1 && "${FAIL_LIST_TIMERS:-0}" == "1" ]]; then
      echo "mock: list-timers failed" >&2
      exit 1
    fi
    echo "mock timer"
    ;;
  is-enabled)
    [[ "$has_project_timer" -eq 1 ]] || exit 1
    if [[ -L "$persistent_link" ]]; then
      echo enabled
      exit 0
    fi
    if [[ -L "$runtime_link" ]]; then
      echo enabled-runtime
      exit 0
    fi
    if [[ -e "$unit" ]]; then
      echo disabled
    else
      echo not-found
    fi
    exit 1
    ;;
  is-active)
    [[ "$has_project_timer" -eq 1 && "$(cat "$active")" == 1 ]]
    ;;
  daemon-reload)
    if [[ "${FAIL_ACTIVE_DURING_RELOAD:-0}" == "1" && "$(cat "$active")" == 1 ]]; then
      echo "mock: timer remained active during transactional daemon-reload" >&2
      exit 1
    fi
    if [[ "$(cat "$service_queued")" == 1 ]]; then
      echo "mock: queued timer service survived the runtime-lock barrier" >&2
      exit 1
    fi
    ;;
  *) exit 0 ;;
esac
EOF
chmod +x /usr/local/bin/systemctl

# Force one already-installed package to appear missing during a selected upgrade. The apt-get shim then
# proves the old SUN timer/service was quiesced before dependency installation can touch managed defaults.
cat >/usr/local/bin/dpkg <<'EOF'
#!/usr/bin/env bash
if [[ "${FORCE_MISSING_MINIMAL:-0}" == "1" && "${1:-}" == "-s" && "${2:-}" == "python3" \
      && ! -e "$MOCK_SYSTEMD_STATE/minimal-installed" ]]; then
  exit 1
fi
if [[ "${FORCE_MISSING_PACKAGE:-0}" == "1" && "${1:-}" == "-s" && "${2:-}" == "apt-listchanges" ]]; then
  exit 1
fi
exec /usr/bin/dpkg "$@"
EOF
cat >/usr/local/bin/apt-get <<'EOF'
#!/usr/bin/env bash
for fd in /proc/$$/fd/*; do
  [[ "$(readlink "$fd" 2>/dev/null || true)" != /run/security-update-notify.install.lock ]] \
    || { echo "mock: package manager inherited installer lock fd" >&2; exit 1; }
done
: >"$MOCK_SYSTEMD_STATE/installer-lock-not-inherited"
if [[ "${FORCE_MISSING_MINIMAL:-0}" == "1" || "${FORCE_MISSING_PACKAGE:-0}" == "1" ]]; then
  [[ "$(cat "$MOCK_SYSTEMD_STATE/active")" == 0 ]] || { echo "mock: dependency mutation began while timer active" >&2; exit 1; }
  [[ "$(cat "$MOCK_SYSTEMD_STATE/service-queued")" == 0 ]] || { echo "mock: dependency mutation began with service queued" >&2; exit 1; }
  : >"$MOCK_SYSTEMD_STATE/dependency-after-quiesce"
  if [[ "${FORCE_MISSING_MINIMAL:-0}" == "1" ]]; then
    : >"$MOCK_SYSTEMD_STATE/minimal-installed"
    : >"$MOCK_SYSTEMD_STATE/minimal-after-quiesce"
  fi
  exit 0
fi
exec /usr/bin/apt-get "$@"
EOF
chmod +x /usr/local/bin/dpkg /usr/local/bin/apt-get
printf '#!/usr/bin/env bash\nexit 0\n' >/usr/local/bin/systemd-analyze; chmod +x /usr/local/bin/systemd-analyze

cat >/usr/local/bin/python3 <<'EOF'
#!/usr/bin/env bash
if [[ "${FORCE_TELEGRAM_PREFLIGHT_TEMPORARY:-0}" == "1" ]]; then
  cat >/dev/null
  echo "mock: Telegram preflight temporarily unavailable" >&2
  exit 75
fi
exec /usr/bin/python3 "$@"
EOF
chmod +x /usr/local/bin/python3

REAL_SYSTEMD_CREDS="$(command -v systemd-creds || true)"
[[ -n "$REAL_SYSTEMD_CREDS" ]] || { echo "systemd-creds is required for the encrypted credential rollback test" >&2; exit 1; }
cat >/usr/local/bin/systemd-creds <<EOF
#!/usr/bin/env bash
if [[ "\${FAIL_CRED_ENCRYPT:-0}" == "1" && "\${1:-}" == "encrypt" ]]; then
  echo "mock: credential encryption failed" >&2
  exit 1
fi
exec "$REAL_SYSTEMD_CREDS" "\$@"
EOF
chmod +x /usr/local/bin/systemd-creds

TARBALL="$(ls /src/dist/security-update-notify-*.tar.gz)"
cd /tmp || exit 1
tar -xzf "$TARBALL"
PKGDIR="$(basename "$TARBALL" .tar.gz)"
cd "/tmp/$PKGDIR" || exit 1

printf %s rollback-secret-one >/tmp/feishu-secret-one
printf %s rollback-secret-two >/tmp/feishu-secret-two
chmod 600 /tmp/feishu-secret-one /tmp/feishu-secret-two

FAIL=0
echo "### Fresh install with a contended runtime lock -> no false-success verification"
rm -f /tmp/runtime-lock-held
(
  exec 8>/run/security-update-notify.lock
  flock -n 8
  : >/tmp/runtime-lock-held
  while [[ ! -e /usr/local/sbin/security-update-notify ]]; do sleep 0.01; done
  sleep 0.5
) &
runtime_lock_holder=$!
while [[ ! -e /tmp/runtime-lock-held ]]; do sleep 0.01; done
SECURITY_UPDATE_NOTIFY_LOCK_WAIT_SECONDS=0 ./install.sh --notify-channels feishu \
  --feishu-app-id cli_locked --feishu-receive-id ou_locked --feishu-app-secret-file /tmp/feishu-secret-one \
  --send-test --skip-notify-test --non-interactive -y --skip-post-install-check --lang en >/tmp/lock-install.log 2>&1
rc_lock=$?
wait "$runtime_lock_holder"
[ "$rc_lock" = 75 ] && echo "  ok: lock contention preserved installer exit 75" \
  || { echo "  FAIL: lock contention exit $rc_lock, expected 75"; FAIL=1; }
grep -qF 'Timed out waiting for the security-update-notify lock' /tmp/lock-install.log \
  && grep -qiE 'roll|回滚' /tmp/lock-install.log \
  && echo "  ok: lock timeout triggered transactional rollback" \
  || { echo "  FAIL: missing lock-timeout rollback diagnostics"; FAIL=1; }
[[ ! -e /usr/local/sbin/security-update-notify && ! -e /etc/security-update-notify/telegram.env \
   && ! -e /etc/systemd/system/security-update-notify.timer \
   && ! -L /etc/systemd/system/timers.target.wants/security-update-notify.timer \
   && ! -L /run/systemd/system/timers.target.wants/security-update-notify.timer ]] \
  && echo "  ok: failed fresh install left no managed runtime/timer files" \
  || { echo "  FAIL: failed fresh install left managed files"; FAIL=1; }
[[ "$(cat "$MOCK_SYSTEMD_STATE/active")" == 0 ]] \
  || { echo "  FAIL: lock rollback changed fresh timer state"; FAIL=1; }

echo "### Concurrent installer transaction -> reject before backup or mutation"
backup_count_before="$(find /var/backups/security-update-notify -mindepth 1 -maxdepth 1 -type d | wc -l)"
marker_count_before="$(find /run -maxdepth 1 -type f -name 'security-update-notify.install.*' | wc -l)"
exec 9>/run/security-update-notify.install.lock
flock -n 9
./install.sh --notify-channels telegram --telegram-token 123456:abc_DEF-ghi --telegram-chat-id -100 \
  --skip-notify-test --non-interactive -y --skip-post-install-check >/tmp/install-lock.log 2>&1
rc_install_lock=$?
flock -u 9
exec 9>&-
backup_count_after="$(find /var/backups/security-update-notify -mindepth 1 -maxdepth 1 -type d | wc -l)"
marker_count_after="$(find /run -maxdepth 1 -type f -name 'security-update-notify.install.*' | wc -l)"
[[ "$rc_install_lock" -eq 75 ]] \
  && echo "  ok: concurrent installer rejected with temporary-failure exit 75" \
  || { echo "  FAIL: concurrent installer exit $rc_install_lock, expected 75"; FAIL=1; }
[[ "$backup_count_after" == "$backup_count_before" && ! -e /usr/local/sbin/security-update-notify ]] \
  && echo "  ok: rejected concurrent installer created no backup or managed runtime" \
  || { echo "  FAIL: rejected concurrent installer changed backup or runtime state"; FAIL=1; }
[[ "$marker_count_after" == "$marker_count_before" ]] \
  && echo "  ok: rejected concurrent installer left no handshake marker" \
  || { echo "  FAIL: rejected concurrent installer leaked a handshake marker"; FAIL=1; }
grep -qF '安装或升级事务正在运行' /tmp/install-lock.log \
  || { echo "  FAIL: missing concurrent-installer diagnostic"; FAIL=1; }

echo "### Fresh install failing after enable --now -> remove symlink and stop timer"
FAIL_LIST_TIMERS=1 ./install.sh --notify-channels telegram \
  --telegram-token 123456:abc_DEF-ghi --telegram-chat-id -100 \
  --skip-notify-test --non-interactive -y --skip-post-install-check >/tmp/late-fresh.log 2>&1
rc_late_fresh=$?
[ "$rc_late_fresh" != 0 ] && echo "  ok: forced late failure reached rollback" \
  || { echo "  FAIL: forced list-timers failure unexpectedly succeeded"; FAIL=1; }
[[ ! -e /etc/systemd/system/security-update-notify.timer \
   && ! -L /etc/systemd/system/timers.target.wants/security-update-notify.timer \
   && ! -L /run/systemd/system/timers.target.wants/security-update-notify.timer \
   && "$(cat "$MOCK_SYSTEMD_STATE/active")" == 0 ]] \
  && echo "  ok: fresh rollback restored absent/disabled/inactive timer state" \
  || { echo "  FAIL: fresh rollback left timer enablement or activity"; FAIL=1; }

echo "### Install #1 (host-label=first, dual channel, secret=one) -> should succeed"
./install.sh --notify-channels telegram,feishu \
  --telegram-token 123456:abc_DEF-ghi --telegram-chat-id -100 \
  --feishu-app-id cli_first --feishu-receive-id ou_first --feishu-app-secret-file /tmp/feishu-secret-one \
  --host-label first --skip-notify-test --non-interactive -y >/tmp/i1.log 2>&1
rc1=$?
[ "$rc1" = 0 ] && echo "  ok: install #1 exit 0" || { echo "  FAIL: install #1 exit $rc1"; tail -40 /tmp/i1.log; FAIL=1; }
grep -qF "HOST_LABEL='first'" /etc/security-update-notify/telegram.env && echo "  ok: config HOST_LABEL='first'" || { echo "  FAIL: config not 'first'"; FAIL=1; }
grep -qF "NOTIFY_CHANNELS='telegram,feishu'" /etc/security-update-notify/telegram.env && echo "  ok: dual channel config" || { echo "  FAIL: dual channel config missing"; FAIL=1; }
file /usr/local/sbin/security-update-notify | grep -q ELF && echo "  ok: Go binary installed" || { echo "  FAIL: not a Go binary"; FAIL=1; }
b1=$(sha256sum /usr/local/sbin/security-update-notify | awk '{print $1}')
if [[ -s /etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred ]]; then
  cred_path=/etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred
elif [[ -s /etc/security-update-notify/credentials/feishu-app-secret ]]; then
  cred_path=/etc/security-update-notify/credentials/feishu-app-secret
else
  echo "  FAIL: Feishu credential not installed"; exit 1
fi
c1=$(sha256sum "$cred_path" | awk '{print $1}')
[[ "$(readlink /etc/systemd/system/timers.target.wants/security-update-notify.timer)" == ../security-update-notify.timer \
   && ! -L /run/systemd/system/timers.target.wants/security-update-notify.timer \
   && "$(cat "$MOCK_SYSTEMD_STATE/active")" == 1 ]] \
  || { echo "  FAIL: install #1 did not enable and start timer"; FAIL=1; }
if grep -Eq 'WARN timer not enabled|警告：timer 未启用' /tmp/i1.log; then
  echo "  FAIL: default post-install doctor ran before timer activation"; FAIL=1
else
  echo "  ok: default post-install doctor observed the activated timer"
fi
if grep -RqsF rollback-secret-one /etc/security-update-notify/telegram.env /var/backups/security-update-notify /tmp/i1.log; then
  echo "  FAIL: Feishu secret leaked into config, backup, or log"; exit 1
fi

echo "### Notification settings no-op -> no backup, preflight, or timer mutation"
settings_backup_before="$(find /var/backups/security-update-notify -mindepth 1 -maxdepth 1 -type d | wc -l)"
printf '1\n' | ./install.sh --configure-notifications --skip-notify-test --lang en >/tmp/settings-noop.log 2>&1
rc_settings_noop=$?
settings_backup_after="$(find /var/backups/security-update-notify -mindepth 1 -maxdepth 1 -type d | wc -l)"
[[ "$rc_settings_noop" -eq 0 && "$settings_backup_after" == "$settings_backup_before" \
   && "$(cat "$MOCK_SYSTEMD_STATE/active")" == 1 ]] \
  && grep -qF 'Message notification settings were not changed.' /tmp/settings-noop.log \
  && echo "  ok: unchanged settings exited before backup and timer quiescence" \
  || { echo "  FAIL: unchanged settings performed installation work"; FAIL=1; }

echo "### Non-interactive notification settings conflict -> reject before transaction"
./install.sh --configure-notifications --notify-channels telegram --non-interactive --lang en >/tmp/settings-conflict.log 2>&1
rc_settings_conflict=$?
settings_conflict_backup_after="$(find /var/backups/security-update-notify -mindepth 1 -maxdepth 1 -type d | wc -l)"
[[ "$rc_settings_conflict" -eq 2 && "$settings_conflict_backup_after" == "$settings_backup_before" \
   && "$(cat "$MOCK_SYSTEMD_STATE/active")" == 1 ]] \
  && grep -qF 'requires an interactive terminal' /tmp/settings-conflict.log \
  && echo "  ok: conflicting settings flags were not silently ignored" \
  || { echo "  FAIL: conflicting settings flags entered the installer transaction"; FAIL=1; }

echo "### Same-channel Telegram credential rotation -> validate only Telegram"
printf %s 123456:rotated_DEF >/tmp/telegram-token-rotated
chmod 600 /tmp/telegram-token-rotated
./install.sh --telegram-token-file /tmp/telegram-token-rotated --telegram-chat-id -200 \
  --skip-telegram-test --skip-feishu-test --non-interactive -y --skip-post-install-check \
  --lang en >/tmp/telegram-rotation.log 2>&1
rc_telegram_rotation=$?
[[ "$rc_telegram_rotation" -eq 0 ]] \
  && grep -qF "TELEGRAM_BOT_TOKEN='123456:rotated_DEF'" /etc/security-update-notify/telegram.env \
  && grep -qF "TELEGRAM_CHAT_ID='-200'" /etc/security-update-notify/telegram.env \
  && grep -qF 'Skipping Telegram preflight test.' /tmp/telegram-rotation.log \
  && grep -qF 'Feishu settings are unchanged; skipping duplicate preflight.' /tmp/telegram-rotation.log \
  && ! grep -qF 'Skipping Feishu preflight test.' /tmp/telegram-rotation.log \
  && echo "  ok: credential rotation persisted and skipped the unaffected platform" \
  || { echo "  FAIL: same-channel credential rotation did not use selective preflight"; FAIL=1; }

echo "### Telegram temporary preflight failure -> exit 75 and full rollback"
printf %s 123456:temporary_DEF >/tmp/telegram-token-temporary
chmod 600 /tmp/telegram-token-temporary
FORCE_TELEGRAM_PREFLIGHT_TEMPORARY=1 ./install.sh \
  --telegram-token-file /tmp/telegram-token-temporary --telegram-chat-id -300 \
  --non-interactive -y --skip-post-install-check --lang en >/tmp/telegram-temporary.log 2>&1
rc_telegram_temporary=$?
[[ "$rc_telegram_temporary" -eq 75 ]] \
  && grep -qF 'network preflight temporarily failed; credentials were not changed' /tmp/telegram-temporary.log \
  && grep -qiE 'roll|回滚' /tmp/telegram-temporary.log \
  && grep -qF "TELEGRAM_BOT_TOKEN='123456:rotated_DEF'" /etc/security-update-notify/telegram.env \
  && grep -qF "TELEGRAM_CHAT_ID='-200'" /etc/security-update-notify/telegram.env \
  && [[ "$(cat "$MOCK_SYSTEMD_STATE/active")" == 1 ]] \
  && echo "  ok: temporary failure propagated exit 75 and restored prior credentials/timer" \
  || { echo "  FAIL: temporary Telegram failure did not roll back transactionally"; FAIL=1; }

echo "### Explicit validation exit after timer quiescence -> transactional ROLLBACK"
./install.sh --notify-lang invalid --skip-notify-test --non-interactive -y --skip-post-install-check >/tmp/post-quiesce-exit.log 2>&1
rc_post_quiesce=$?
[[ "$rc_post_quiesce" -eq 2 ]] \
  && grep -qiE 'roll|回滚' /tmp/post-quiesce-exit.log \
  && [[ "$(readlink /etc/systemd/system/timers.target.wants/security-update-notify.timer)" == ../security-update-notify.timer \
        && "$(cat "$MOCK_SYSTEMD_STATE/active")" == 1 ]] \
  && echo "  ok: explicit exit restored the pre-upgrade timer state" \
  || { echo "  FAIL: explicit post-quiesce exit bypassed rollback"; FAIL=1; }

echo "### App ID scope guard (new App ID without a new open_id) -> reject"
./install.sh --feishu-app-id cli_changed --skip-notify-test --non-interactive -y --skip-post-install-check >/tmp/app-id-change.log 2>&1
rc_scope=$?
[ "$rc_scope" != 0 ] && echo "  ok: app-scoped open_id reuse rejected" || { echo "  FAIL: old open_id reused with a new App ID"; FAIL=1; }
grep -qF "旧应用的 open_id 不会复用" /tmp/app-id-change.log \
  && grep -qF -- "--feishu-receive-id" /tmp/app-id-change.log \
  && echo "  ok: recipient must be selected or supplied again" \
  || { echo "  FAIL: missing App ID scope guard diagnostics"; FAIL=1; }
grep -qF "FEISHU_APP_ID='cli_first'" /etc/security-update-notify/telegram.env \
  && grep -qF "FEISHU_RECEIVE_ID='ou_first'" /etc/security-update-notify/telegram.env \
  || { echo "  FAIL: rejected App ID change altered installed config"; FAIL=1; }
[[ "$(readlink /etc/systemd/system/timers.target.wants/security-update-notify.timer)" == ../security-update-notify.timer \
   && "$(cat "$MOCK_SYSTEMD_STATE/active")" == 1 ]] \
  || { echo "  FAIL: pre-mutation validation failure changed timer state"; FAIL=1; }

echo "### Install #2 (host-label=second, secret=two, FAIL_ENABLE=1) -> ROLLBACK"
for future_backup in 99991231235957 99991231235958 99991231235959; do
  mkdir -m 0700 "/var/backups/security-update-notify/$future_backup"
done
FAIL_ENABLE=1 FORCE_MISSING_MINIMAL=1 FORCE_MISSING_PACKAGE=1 ./install.sh --host-label second --feishu-app-id cli_second --feishu-receive-id ou_second \
  --feishu-app-secret-file /tmp/feishu-secret-two --skip-notify-test --non-interactive -y --skip-post-install-check >/tmp/i2.log 2>&1
rc2=$?
[ "$rc2" != 0 ] && echo "  ok: install #2 failed (exit $rc2) as forced" || { echo "  FAIL: install #2 unexpectedly succeeded"; FAIL=1; }
grep -qiE 'roll|回滚' /tmp/i2.log && echo "  ok: rollback message present" || { echo "  FAIL: no rollback message"; tail -3 /tmp/i2.log; FAIL=1; }
failed_backup="$(grep -oE '/var/backups/security-update-notify/[0-9]{14}(-[0-9]{3})?' /tmp/i2.log | head -1)"
[[ -n "$failed_backup" && -d "$failed_backup" ]] \
  && echo "  ok: active transaction backup survived future-dated retention entries" \
  || { echo "  FAIL: active transaction backup was pruned"; FAIL=1; }
[[ -e "$MOCK_SYSTEMD_STATE/dependency-after-quiesce" ]] \
  && echo "  ok: timer/service quiesced before managed dependency mutation" \
  || { echo "  FAIL: dependency-install ordering was not exercised"; FAIL=1; }
[[ -e "$MOCK_SYSTEMD_STATE/minimal-after-quiesce" ]] \
  && echo "  ok: timer/service quiesced before minimal preflight dependency mutation" \
  || { echo "  FAIL: minimal preflight dependency ordering was not exercised"; FAIL=1; }
[[ -e "$MOCK_SYSTEMD_STATE/installer-lock-not-inherited" ]] \
  && echo "  ok: package manager did not inherit the installer lock descriptor" \
  || { echo "  FAIL: installer lock inheritance assertion was not exercised"; FAIL=1; }

echo "### post-rollback assertions"
if grep -qF "HOST_LABEL='first'" /etc/security-update-notify/telegram.env; then
  echo "  ok: config ROLLED BACK to 'first' (install #2's 'second' was reverted)"
else
  echo "  FAIL: config not rolled back:"; grep HOST_LABEL /etc/security-update-notify/telegram.env; FAIL=1
fi
b2=$(sha256sum /usr/local/sbin/security-update-notify 2>/dev/null | awk '{print $1}')
[ "$b1" = "$b2" ] && echo "  ok: binary restored to install #1" || { echo "  FAIL: binary not restored"; FAIL=1; }
c2=$(sha256sum "$cred_path" 2>/dev/null | awk '{print $1}')
[ "$c1" = "$c2" ] && echo "  ok: Feishu credential restored to install #1" || { echo "  FAIL: Feishu credential not restored"; FAIL=1; }
grep -qF "FEISHU_APP_ID='cli_first'" /etc/security-update-notify/telegram.env && echo "  ok: Feishu config restored" || { echo "  FAIL: Feishu config not restored"; FAIL=1; }
[[ "$(readlink /etc/systemd/system/timers.target.wants/security-update-notify.timer)" == ../security-update-notify.timer \
   && ! -L /run/systemd/system/timers.target.wants/security-update-notify.timer \
   && "$(cat "$MOCK_SYSTEMD_STATE/active")" == 1 ]] \
  && echo "  ok: enabled/active timer state restored after failed upgrade" \
  || { echo "  FAIL: enabled/active timer state not restored (persistent=$(readlink /etc/systemd/system/timers.target.wants/security-update-notify.timer 2>/dev/null || echo none), runtime=$(readlink /run/systemd/system/timers.target.wants/security-update-notify.timer 2>/dev/null || echo none), active=$(cat "$MOCK_SYSTEMD_STATE/active"))"; FAIL=1; }
if grep -RqsF rollback-secret-two /etc/security-update-notify/telegram.env /var/backups/security-update-notify /tmp/i2.log; then
  echo "  FAIL: replacement Feishu secret leaked into config, backup, or log"; FAIL=1
fi

echo "### Install #2b (previous timer disabled/inactive, late failure) -> exact state ROLLBACK"
systemctl disable --now security-update-notify.timer
FAIL_LIST_TIMERS=1 ./install.sh --host-label disabled-before-upgrade \
  --skip-notify-test --non-interactive -y --skip-post-install-check >/tmp/i2b.log 2>&1
rc2b=$?
[ "$rc2b" != 0 ] || { echo "  FAIL: disabled-state late failure unexpectedly succeeded"; FAIL=1; }
[[ ! -L /etc/systemd/system/timers.target.wants/security-update-notify.timer \
   && ! -L /run/systemd/system/timers.target.wants/security-update-notify.timer \
   && "$(cat "$MOCK_SYSTEMD_STATE/active")" == 0 ]] \
  && echo "  ok: prior disabled/inactive timer state restored exactly" \
  || { echo "  FAIL: disabled/inactive timer state not restored"; FAIL=1; }
grep -qF "HOST_LABEL='first'" /etc/security-update-notify/telegram.env \
  || { echo "  FAIL: config not restored after disabled-state failure"; FAIL=1; }
systemctl enable --now security-update-notify.timer

echo "### Install #2c (previous timer enabled-runtime/active, late failure) -> exact symlink ROLLBACK"
systemctl disable --now security-update-notify.timer
systemctl enable --runtime --now security-update-notify.timer
runtime_target="$(readlink /run/systemd/system/timers.target.wants/security-update-notify.timer)"
FAIL_LIST_TIMERS=1 ./install.sh --host-label runtime-enabled-before-upgrade \
  --skip-notify-test --non-interactive -y --skip-post-install-check >/tmp/i2c.log 2>&1
rc2c=$?
[ "$rc2c" != 0 ] || { echo "  FAIL: enabled-runtime late failure unexpectedly succeeded"; FAIL=1; }
[[ ! -L /etc/systemd/system/timers.target.wants/security-update-notify.timer \
   && "$(readlink /run/systemd/system/timers.target.wants/security-update-notify.timer)" == "$runtime_target" \
   && "$(cat "$MOCK_SYSTEMD_STATE/active")" == 1 ]] \
  && echo "  ok: prior enabled-runtime symlink target and active state restored exactly" \
  || { echo "  FAIL: enabled-runtime/active state not restored exactly"; FAIL=1; }
grep -qF "HOST_LABEL='first'" /etc/security-update-notify/telegram.env \
  || { echo "  FAIL: config not restored after enabled-runtime failure"; FAIL=1; }
systemctl disable --now security-update-notify.timer
systemctl enable --now security-update-notify.timer

echo "### Install #3 (disable Feishu, FAIL_ENABLE=1) -> credential cleanup ROLLBACK"
FAIL_ENABLE=1 ./install.sh --notify-channels telegram --host-label telegram-only \
  --skip-notify-test --non-interactive -y --skip-post-install-check >/tmp/i3.log 2>&1
rc3=$?
[ "$rc3" != 0 ] && echo "  ok: install #3 failed (exit $rc3) as forced" || { echo "  FAIL: install #3 unexpectedly succeeded"; FAIL=1; }
grep -qF "NOTIFY_CHANNELS='telegram,feishu'" /etc/security-update-notify/telegram.env \
  && echo "  ok: dual-channel config restored after failed disable" \
  || { echo "  FAIL: channel config not restored after failed disable"; FAIL=1; }
c3=$(sha256sum "$cred_path" 2>/dev/null | awk '{print $1}')
[ "$c1" = "$c3" ] && echo "  ok: Feishu credential restored after failed disable" \
  || { echo "  FAIL: Feishu credential not restored after failed disable"; FAIL=1; }

echo "### Install #4 (credential encryption failure) -> full ROLLBACK"
FAIL_CRED_ENCRYPT=1 ./install.sh --host-label credential-failure \
  --feishu-app-id cli_fourth --feishu-receive-id ou_fourth \
  --feishu-app-secret-file /tmp/feishu-secret-two --skip-notify-test \
  --non-interactive -y --skip-post-install-check >/tmp/i4.log 2>&1
rc4=$?
[ "$rc4" != 0 ] && echo "  ok: install #4 failed (exit $rc4) as forced" \
  || { echo "  FAIL: credential encryption failure unexpectedly succeeded"; FAIL=1; }
grep -qiE 'roll|回滚' /tmp/i4.log \
  && echo "  ok: credential failure triggered rollback" \
  || { echo "  FAIL: credential failure bypassed rollback"; tail -5 /tmp/i4.log; FAIL=1; }
grep -qF "HOST_LABEL='first'" /etc/security-update-notify/telegram.env \
  && grep -qF "FEISHU_APP_ID='cli_first'" /etc/security-update-notify/telegram.env \
  || { echo "  FAIL: config not restored after credential failure"; FAIL=1; }
c4=$(sha256sum "$cred_path" 2>/dev/null | awk '{print $1}')
[ "$c1" = "$c4" ] && echo "  ok: credential restored after encryption failure" \
  || { echo "  FAIL: credential not restored after encryption failure"; FAIL=1; }
if grep -RqsF rollback-secret-two /etc/security-update-notify/telegram.env /var/backups/security-update-notify /tmp/i4.log; then
  echo "  FAIL: failed replacement secret leaked into config, backup, or log"; FAIL=1
fi

echo "### Install #5 (rollback cannot reactivate prior timer) -> report incomplete rollback"
FAIL_START=1 FAIL_LIST_TIMERS=1 ./install.sh --host-label rollback-start-failure \
  --skip-notify-test --non-interactive -y --skip-post-install-check >/tmp/i5.log 2>&1
rc5=$?
[[ "$rc5" -eq 1 ]] || { echo "  FAIL: incomplete rollback exit $rc5, expected 1"; FAIL=1; }
grep -qE 'Rollback could not fully restore the pre-install state|回滚未能完整恢复安装前状态' /tmp/i5.log \
  && echo "  ok: timer restoration failure was surfaced, not swallowed" \
  || { echo "  FAIL: missing incomplete rollback diagnostic"; FAIL=1; }
systemctl start security-update-notify.timer

echo "### Successful Feishu disable -> remove persisted credential"
./install.sh --notify-channels telegram --skip-notify-test --non-interactive -y \
  --skip-post-install-check --lang en >/tmp/disable-feishu.log 2>&1
rc_disable_feishu=$?
[[ "$rc_disable_feishu" -eq 0 ]] \
  && grep -qF "NOTIFY_CHANNELS='telegram'" /etc/security-update-notify/telegram.env \
  && [[ ! -e /etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred \
        && ! -e /etc/security-update-notify/credentials/feishu-app-secret \
        && ! -e /etc/systemd/system/security-update-notify.service.d/credentials.conf \
        && "$(cat "$MOCK_SYSTEMD_STATE/active")" == 1 ]] \
  && echo "  ok: successful platform removal deleted the Feishu credential" \
  || {
    echo "  FAIL: successful Feishu disable left config, credential, or timer inconsistent"
    echo "  rc=$rc_disable_feishu active=$(cat "$MOCK_SYSTEMD_STATE/active")"
    grep '^NOTIFY_CHANNELS=' /etc/security-update-notify/telegram.env 2>/dev/null || true
    find /etc/credstore.encrypted /etc/security-update-notify/credentials \
      /etc/systemd/system/security-update-notify.service.d -maxdepth 1 -type f -print 2>/dev/null || true
    tail -30 /tmp/disable-feishu.log
    FAIL=1
  }

if [ "$FAIL" = 0 ]; then echo "### ROLLBACK TEST PASSED"; else echo "### ROLLBACK TEST FAILED"; exit 1; fi
