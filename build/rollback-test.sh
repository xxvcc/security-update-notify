#!/usr/bin/env bash
# 升级回滚测试：install #1 成功；install #2 在写完新配置后让 systemctl enable 失败 -> ERR trap ->
# restore_backup 必须把配置/二进制回滚到 install #1 的状态（保护 fleet 免于半途失败的升级）。
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null; apt-get install -y python3 ca-certificates file systemd >/dev/null
mkdir -p /run/systemd/system /etc/systemd/system /usr/local/sbin /etc/security-update-notify \
         /var/lib/security-update-notify /var/log /etc/logrotate.d

# systemctl 桩：FAIL_ENABLE=1 时，对 security-update-notify.timer 的 enable 返回非零（其余正常）。
cat >/usr/local/bin/systemctl <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "enable" ]]; then
  for a in "$@"; do
    [[ "$a" == "security-update-notify.timer" && "${FAIL_ENABLE:-0}" == "1" ]] && { echo "mock: enable failed" >&2; exit 1; }
  done
  exit 0
fi
case "${1:-}" in
  daemon-reload|restart|disable|start) exit 0 ;;
  list-timers) echo "mock timer"; exit 0 ;;
  is-enabled) exit 0 ;;
  *) exit 0 ;;
esac
EOF
chmod +x /usr/local/bin/systemctl
printf '#!/usr/bin/env bash\nexit 0\n' >/usr/local/bin/systemd-analyze; chmod +x /usr/local/bin/systemd-analyze

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

echo "### Install #1 (host-label=first, dual channel, secret=one) -> should succeed"
./install.sh --notify-channels telegram,feishu \
  --telegram-token 123456:abc_DEF-ghi --telegram-chat-id -100 \
  --feishu-app-id cli_first --feishu-receive-id ou_first --feishu-app-secret-file /tmp/feishu-secret-one \
  --host-label first --skip-notify-test --non-interactive -y --skip-post-install-check >/tmp/i1.log 2>&1
rc1=$?
FAIL=0
[ "$rc1" = 0 ] && echo "  ok: install #1 exit 0" || { echo "  FAIL: install #1 exit $rc1"; FAIL=1; }
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
if grep -RqsF rollback-secret-one /etc/security-update-notify/telegram.env /var/backups/security-update-notify /tmp/i1.log; then
  echo "  FAIL: Feishu secret leaked into config, backup, or log"; exit 1
fi

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

echo "### Install #2 (host-label=second, secret=two, FAIL_ENABLE=1) -> ROLLBACK"
FAIL_ENABLE=1 ./install.sh --host-label second --feishu-app-id cli_second --feishu-receive-id ou_second \
  --feishu-app-secret-file /tmp/feishu-secret-two --skip-notify-test --non-interactive -y --skip-post-install-check >/tmp/i2.log 2>&1
rc2=$?
[ "$rc2" != 0 ] && echo "  ok: install #2 failed (exit $rc2) as forced" || { echo "  FAIL: install #2 unexpectedly succeeded"; FAIL=1; }
grep -qiE 'roll|回滚' /tmp/i2.log && echo "  ok: rollback message present" || { echo "  FAIL: no rollback message"; tail -3 /tmp/i2.log; FAIL=1; }

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
if grep -RqsF rollback-secret-two /etc/security-update-notify/telegram.env /var/backups/security-update-notify /tmp/i2.log; then
  echo "  FAIL: replacement Feishu secret leaked into config, backup, or log"; FAIL=1
fi

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

if [ "$FAIL" = 0 ]; then echo "### ROLLBACK TEST PASSED"; else echo "### ROLLBACK TEST FAILED"; exit 1; fi
