#!/usr/bin/env bash
# Container-only compatibility gate: upgrade a representative 2.x/schema-3
# installation in place with the 3.x Go installer.
set -euo pipefail

[[ -f /.dockerenv || "${SUN_CONTAINER_TEST:-0}" == 1 ]] || {
  echo "build/compat-test.sh must run only in a disposable container" >&2
  exit 2
}

ok() {
  if eval "$1"; then
    echo "  ok: $2"
  else
    echo "  FAIL: $2" >&2
    exit 1
  fi
}

export DEBIAN_FRONTEND=noninteractive
mkdir -p /run/systemd/system /etc/systemd/system /usr/local/sbin \
  /etc/security-update-notify /var/lib/security-update-notify /var/log /etc/logrotate.d \
  /tmp/mock-systemd /usr/local/bin

cat >/usr/local/bin/systemctl <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state=/tmp/mock-systemd
case "${1:-}" in
  is-enabled)
    if [[ -e "$state/enabled" ]]; then echo enabled; exit 0; fi
    echo disabled
    exit 1
    ;;
  is-active)
    [[ -e "$state/active" ]]
    ;;
  disable)
    rm -f "$state/enabled" "$state/active"
    ;;
  enable)
    if [[ " $* " == *" security-update-notify.timer "* ]]; then
      touch "$state/enabled"
      [[ " $* " == *" --now "* ]] && touch "$state/active"
    fi
    ;;
  start)
    [[ "${2:-}" == security-update-notify.timer ]] && touch "$state/active"
    ;;
  stop|daemon-reload)
    ;;
  list-timers)
    echo "security-update-notify.timer mock"
    ;;
  *)
    echo "mock systemctl: unsupported arguments: $*" >&2
    exit 1
    ;;
esac
EOF
chmod 0755 /usr/local/bin/systemctl
printf '#!/usr/bin/env bash\nexit 0\n' >/usr/local/bin/systemd-analyze
chmod 0755 /usr/local/bin/systemd-analyze

tarball="$(find /src/dist -maxdepth 1 -type f -name 'security-update-notify-*.tar.gz' -print -quit)"
[[ -n "$tarball" ]] || { echo "release tarball missing under /src/dist" >&2; exit 1; }
version="$(sed -n 's/^VERSION="\([^"]*\)"$/\1/p' /src/VERSION)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([._-][0-9A-Za-z]+)?$ \
   && "$(wc -l </src/VERSION)" -eq 1 ]] || {
  echo "invalid canonical VERSION" >&2
  exit 1
}
work=/tmp/sun-compat-release
mkdir -p "$work"
tar -xzf "$tarball" -C "$work"
package_dir="$work/$(basename "$tarball" .tar.gz)"
runtime="$package_dir/files/security-update-notify-linux-amd64"
[[ -x "$runtime" ]] || { echo "amd64 Go runtime missing" >&2; exit 1; }
[[ -x "$package_dir/install.sh" ]] || { echo "2.x compatibility launcher missing" >&2; exit 1; }
[[ "$(cat "$package_dir/files/security-update-notify")" == "VERSION=\"$version\"" ]] || {
  echo "2.x compatibility version marker is not bound to $version" >&2
  exit 1
}

cat >/etc/security-update-notify/telegram.env <<'EOF'
CONFIG_VERSION='3'
NOTIFY_CHANNELS='telegram'
TELEGRAM_BOT_TOKEN='123456:abc_DEF-ghi'
TELEGRAM_CHAT_ID='-100123'
HOST_LABEL='compat-host'
PUBLIC_IP=''
INCLUDE_PUBLIC_IP='0'
NOTIFY_OK='0'
NOTIFY_UPGRADE='0'
DEDUP_MODE='daily'
DEDUP_INTERVAL_DAYS='3'
NOTIFY_LANG='en'
BACKEND='apt'
CHECK_UPDATE_HEALTH='0'
STALE_UPDATE_DAYS='0'
CHECK_EOL='0'
EOF
chmod 0600 /etc/security-update-notify/telegram.env
printf 'legacy-runtime\n' >/usr/local/sbin/security-update-notify
chmod 0755 /usr/local/sbin/security-update-notify
printf '[Unit]\nDescription=legacy\n' >/etc/systemd/system/security-update-notify.service
printf '[Timer]\nOnCalendar=*-*-* 08:30:00\n' >/etc/systemd/system/security-update-notify.timer
printf '%s\n' '67937ecd9dc8b78bb7bbb248d4ef6ef6ec0ac64ad65de2141dc171faec1803cd' \
  >/var/lib/security-update-notify/last-alert.sha256
touch /tmp/mock-systemd/enabled /tmp/mock-systemd/active

echo "### Upgrade representative 2.x state through the generated 3.x compatibility bridge"
(
  cd "$package_dir"
  ./install.sh --skip-notify-test --non-interactive -y --skip-post-install-check --lang en
)

ok "[[ \"$(/usr/local/sbin/security-update-notify --version)\" == 'security-update-notify $version' ]]" \
  "Go $version runtime installed"
ok "grep -qF \"CONFIG_VERSION='4'\" /etc/security-update-notify/telegram.env" \
  "configuration upgraded to schema 4"
ok "grep -qF \"HOST_LABEL='compat-host'\" /etc/security-update-notify/telegram.env" \
  "host label preserved"
ok "grep -qF \"TELEGRAM_BOT_TOKEN='123456:abc_DEF-ghi'\" /etc/security-update-notify/telegram.env" \
  "Telegram token preserved"
ok "grep -qF \"NOTIFY_CHANNELS='telegram'\" /etc/security-update-notify/telegram.env" \
  "notification platform preserved"
ok "grep -qF \"PENDING_ALERT_DAYS='3'\" /etc/security-update-notify/telegram.env" \
  "new pending-patch default added"
ok "grep -qF \"RESTART_ALERT_DAYS='7'\" /etc/security-update-notify/telegram.env" \
  "new restart-age default added"
ok "grep -qF \"CHECK_SELF_UPDATE='1'\" /etc/security-update-notify/telegram.env" \
  "self-update check default added"
ok "grep -q '^67937ecd' /var/lib/security-update-notify/last-alert.sha256" \
  "deduplication state preserved"
ok "test -s /var/backups/security-update-notify/latest" "transaction backup created"
ok "test -e /tmp/mock-systemd/enabled && test -e /tmp/mock-systemd/active" \
  "project timer enabled and active"

echo "3.0 compatibility upgrade test passed"
