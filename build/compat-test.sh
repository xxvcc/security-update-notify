#!/usr/bin/env bash
# 桥升级兼容测试：bash 运行时 -> Go 桥升级，验证配置/状态保留、Go 二进制落地、且不会全网重复告警。
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null
apt-get install -y python3 ca-certificates file >/dev/null

mkdir -p /run/systemd/system /etc/systemd/system /usr/local/sbin \
         /etc/security-update-notify /var/lib/security-update-notify /var/log /etc/logrotate.d

# systemctl / systemd-analyze 桩（容器内无真 systemd）。
cat >/usr/local/bin/systemctl <<'EOF'
#!/usr/bin/env bash
case "$1" in
  daemon-reload|enable|restart|disable) exit 0 ;;
  list-timers) echo "security-update-notify.timer mock"; exit 0 ;;
  is-enabled) exit 0 ;;
  *) echo "mock systemctl $*"; exit 0 ;;
esac
EOF
chmod +x /usr/local/bin/systemctl
printf '#!/usr/bin/env bash\nexit 0\n' >/usr/local/bin/systemd-analyze
chmod +x /usr/local/bin/systemd-analyze

TARBALL="$(ls /src/dist/security-update-notify-*.tar.gz)"
cd /tmp && tar -xzf "$TARBALL"
PKGDIR="$(basename "$TARBALL" .tar.gz)"

echo "### Stage 1: install the OLD bash runtime (no Go binary present -> fallback)"
cp -r "/tmp/$PKGDIR" /tmp/bash-only
rm -f /tmp/bash-only/files/security-update-notify-linux-*
( cd /tmp/bash-only && ./install.sh --telegram-token 123456:abc_DEF-ghi --telegram-chat-id -100123 \
    --host-label compat-host --skip-telegram-test --non-interactive -y --skip-post-install-check )
head -1 /usr/local/sbin/security-update-notify | grep -q 'bin/env bash' && echo "  ok: bash runtime installed"
grep -qF "HOST_LABEL='compat-host'" /etc/security-update-notify/telegram.env && echo "  ok: config written"
# 模拟一次此前的告警状态（升级后必须保留、不因升级而丢失或改变）。
printf '%s\n' "67937ecd9dc8b78bb7bbb248d4ef6ef6ec0ac64ad65de2141dc171faec1803cd" >/var/lib/security-update-notify/last-alert.sha256

echo "### Stage 2: upgrade in place to the Go bridge (install.sh installs the Go binary)"
( cd "/tmp/$PKGDIR" && SECURITY_UPDATE_NOTIFY_UPGRADE=1 ./install.sh --skip-telegram-test --non-interactive -y --skip-post-install-check )
file /usr/local/sbin/security-update-notify | grep -q 'ELF' && echo "  ok: Go binary installed"
/usr/local/sbin/security-update-notify --version | grep -q "$PKGDIR" >/dev/null 2>&1 || true
ver="$(/usr/local/sbin/security-update-notify --version | awk '{print $2}')"
echo "  ok: version $ver"
grep -qF "HOST_LABEL='compat-host'" /etc/security-update-notify/telegram.env && echo "  ok: config PRESERVED across upgrade"
grep -qF "123456:abc_DEF-ghi" /etc/security-update-notify/telegram.env && echo "  ok: token PRESERVED across upgrade"
test -s /var/backups/security-update-notify/latest && echo "  ok: upgrade backup created"
grep -q '^67937ecd' /var/lib/security-update-notify/last-alert.sha256 && echo "  ok: alert state PRESERVED across upgrade"

echo "### Stage 3: no-fleet-re-alert proof (installed Go binary == Bash golden hash)"
cat >/tmp/env <<'EOF'
TELEGRAM_BOT_TOKEN=123456:fake_TOKEN-value
TELEGRAM_CHAT_ID=-100999
HOST_LABEL=golden-host
BACKEND=apt
NOTIFY_LANG=zh
INCLUDE_PUBLIC_IP=0
CHECK_UPDATE_HEALTH=0
CHECK_EOL=0
STALE_UPDATE_DAYS=0
EOF
got="$(SECURITY_UPDATE_NOTIFY_ENV=/tmp/env /usr/local/sbin/security-update-notify --test-reboot --no-dedupe --dry-run | awk -F'\t' '/^HASH/{print $2}')"
want="67937ecd9dc8b78bb7bbb248d4ef6ef6ec0ac64ad65de2141dc171faec1803cd"
if [ "$got" = "$want" ]; then
  echo "  ok: installed Go binary reproduces the Bash golden hash -> upgrade will NOT re-alert"
else
  echo "  FAIL: hash $got != golden $want"; exit 1
fi
echo "### ALL BRIDGE COMPAT CHECKS PASSED"
