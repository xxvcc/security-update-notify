#!/usr/bin/env bash
# 升级回滚测试：install #1 成功；install #2 在写完新配置后让 systemctl enable 失败 -> ERR trap ->
# restore_backup 必须把配置/二进制回滚到 install #1 的状态（保护 fleet 免于半途失败的升级）。
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null; apt-get install -y python3 ca-certificates file >/dev/null
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

TARBALL="$(ls /src/dist/security-update-notify-*.tar.gz)"
cd /tmp && tar -xzf "$TARBALL"; PKGDIR="$(basename "$TARBALL" .tar.gz)"; cd "/tmp/$PKGDIR"

echo "### Install #1 (host-label=first) -> should succeed"
./install.sh --telegram-token 123456:abc_DEF-ghi --telegram-chat-id -100 --host-label first \
  --skip-telegram-test --non-interactive -y --skip-post-install-check >/tmp/i1.log 2>&1
rc1=$?
FAIL=0
[ "$rc1" = 0 ] && echo "  ok: install #1 exit 0" || { echo "  FAIL: install #1 exit $rc1"; FAIL=1; }
grep -qF "HOST_LABEL='first'" /etc/security-update-notify/telegram.env && echo "  ok: config HOST_LABEL='first'" || { echo "  FAIL: config not 'first'"; FAIL=1; }
file /usr/local/sbin/security-update-notify | grep -q ELF && echo "  ok: Go binary installed" || { echo "  FAIL: not a Go binary"; FAIL=1; }
b1=$(sha256sum /usr/local/sbin/security-update-notify | awk '{print $1}')

echo "### Install #2 (host-label=second, FAIL_ENABLE=1) -> writes 'second' then enable fails -> ROLLBACK"
FAIL_ENABLE=1 ./install.sh --host-label second --skip-telegram-test --non-interactive -y --skip-post-install-check >/tmp/i2.log 2>&1
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

if [ "$FAIL" = 0 ]; then echo "### ROLLBACK TEST PASSED"; else echo "### ROLLBACK TEST FAILED"; exit 1; fi
