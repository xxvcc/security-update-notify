#!/usr/bin/env bash
# 桥升级兼容测试：bash 运行时 -> Go 桥升级，验证配置/状态保留、Go 二进制落地、且不会全网重复告警。
set -euo pipefail

# 断言助手：`cond && echo ok` 形式在 set -e 下不致命（非末尾的 && 左元被豁免），保留断言会
# 静默失败。ok 让每条断言都能真正 fail 整个测试。
ok() { if eval "$1"; then echo "  ok: $2"; else echo "  FAIL: $2" >&2; exit 1; fi; }
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
ok "head -1 /usr/local/sbin/security-update-notify | grep -q 'bin/env bash'" "bash runtime installed"
ok "grep -qF \"HOST_LABEL='compat-host'\" /etc/security-update-notify/telegram.env" "config written"
ok "grep -qF \"CONFIG_VERSION='3'\" /etc/security-update-notify/telegram.env" "config upgraded to schema v3"
ok "grep -qF \"NOTIFY_CHANNELS='telegram'\" /etc/security-update-notify/telegram.env" "legacy/default channel is Telegram"
# 模拟一次此前的告警状态（升级后必须保留、不因升级而丢失或改变）。
printf '%s\n' "67937ecd9dc8b78bb7bbb248d4ef6ef6ec0ac64ad65de2141dc171faec1803cd" >/var/lib/security-update-notify/last-alert.sha256

echo "### Stage 2: upgrade in place to the Go bridge (install.sh installs the Go binary)"
( cd "/tmp/$PKGDIR" && SECURITY_UPDATE_NOTIFY_UPGRADE=1 ./install.sh --skip-telegram-test --non-interactive -y --skip-post-install-check )
ok "file /usr/local/sbin/security-update-notify | grep -q 'ELF'" "Go binary installed"
ver="$(/usr/local/sbin/security-update-notify --version | awk '{print $2}')"
echo "  ok: version $ver"
ok "grep -qF \"HOST_LABEL='compat-host'\" /etc/security-update-notify/telegram.env" "config PRESERVED across upgrade"
ok "grep -qF '123456:abc_DEF-ghi' /etc/security-update-notify/telegram.env" "token PRESERVED across upgrade"
ok "grep -qF \"NOTIFY_CHANNELS='telegram'\" /etc/security-update-notify/telegram.env" "notification channel PRESERVED across upgrade"
ok "test -s /var/backups/security-update-notify/latest" "upgrade backup created"
ok "grep -q '^67937ecd' /var/lib/security-update-notify/last-alert.sha256" "alert state PRESERVED across upgrade"

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
