#!/usr/bin/env bash
# Container-only compatibility gate: upgrade a representative 2.x/schema-3
# installation in place with the 3.x Go installer.
set -euo pipefail

[[ -f /.dockerenv && "${SUN_CONTAINER_TEST:-0}" == 1 ]] || {
  echo "build/compat-test.sh must run only in a disposable container" >&2
  exit 2
}
awk '$5 == "/src" && $6 ~ /(^|,)ro(,|$)/ { found = 1 } END { exit !found }' /proc/self/mountinfo || {
  echo "build/compat-test.sh requires /src to be mounted read-only" >&2
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
  /etc/apt/apt.conf.d /tmp/mock-systemd /usr/local/bin

cat >/usr/local/bin/systemctl <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state=/tmp/mock-systemd
link=/etc/systemd/system/timers.target.wants/security-update-notify.timer
enabled_dir="$state/enabled"
active_dir="$state/active-units"
case "${1:-}" in
  is-enabled)
    unit="${!#}"
    if [[ "$unit" == security-update-notify.timer && -L "$link" ]]; then
      echo enabled
      exit 0
    fi
    if [[ -e "$enabled_dir/$unit" ]]; then
      echo enabled
      exit 0
    fi
    echo disabled
    exit 1
    ;;
  is-active)
    unit="${!#}"
    if [[ "$unit" == security-update-notify.timer && -e "$state/active" ]] || \
       [[ "$unit" != security-update-notify.timer && -e "$active_dir/$unit" ]]; then
      echo active
      exit 0
    fi
    echo inactive
    exit 3
    ;;
  disable)
    for unit in "${@:2}"; do
      [[ "$unit" == -* ]] && continue
      rm -f "$enabled_dir/$unit"
      [[ " $* " == *" --now "* ]] && rm -f "$active_dir/$unit"
      if [[ "$unit" == security-update-notify.timer ]]; then
        rm -f "$link" /run/systemd/system/timers.target.wants/security-update-notify.timer
        [[ " $* " == *" --now "* ]] && rm -f "$state/active"
      fi
    done
    ;;
  enable)
    mkdir -p "$enabled_dir" "$active_dir"
    for unit in "${@:2}"; do
      [[ "$unit" == -* ]] && continue
      touch "$enabled_dir/$unit"
      [[ " $* " == *" --now "* ]] && touch "$active_dir/$unit"
      if [[ "$unit" == security-update-notify.timer ]]; then
        mkdir -p "$(dirname "$link")"
        ln -sfn ../security-update-notify.timer "$link"
        [[ " $* " == *" --now "* ]] && touch "$state/active"
      fi
    done
    ;;
  start)
    unit="${!#}"
    mkdir -p "$active_dir"
    touch "$active_dir/$unit"
    if [[ "$unit" == security-update-notify.timer ]]; then
      touch "$state/active"
    fi
    ;;
  stop)
    unit="${!#}"
    rm -f "$active_dir/$unit"
    if [[ "$unit" == security-update-notify.timer ]]; then
      rm -f "$state/active"
    fi
    ;;
  daemon-reload)
    ;;
  list-timers)
    if [[ "${FAIL_LIST_TIMERS:-0}" == 1 ]]; then
      echo "forced compatibility list-timers failure" >&2
      exit 1
    fi
    echo "security-update-notify.timer mock"
    ;;
  *)
    echo "mock systemctl: unsupported arguments: $*" >&2
    exit 1
    ;;
esac
EOF
chmod 0755 /usr/local/bin/systemctl
ok "! systemctl is-enabled --quiet apt-daily-upgrade.timer >/dev/null" \
  "APT automatic timer starts disabled"
printf '#!/usr/bin/env bash\nexit 0\n' >/usr/local/bin/systemd-analyze
chmod 0755 /usr/local/bin/systemd-analyze

version="$(sed -n 's/^VERSION="\([^"]*\)"$/\1/p' /src/VERSION)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([._-][0-9A-Za-z]+)?$ \
   && "$(wc -l </src/VERSION)" -eq 1 ]] || {
  echo "invalid canonical VERSION" >&2
  exit 1
}
tarball="/src/dist/security-update-notify-${version}.tar.gz"
[[ -f "$tarball" ]] || { echo "release tarball missing: $tarball" >&2; exit 1; }
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
best_effort_args=()
if [[ "${SUN_ALLOW_BEST_EFFORT:-0}" == 1 ]]; then
  best_effort_args=(--allow-best-effort)
fi

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
printf 'security-update-notify: original file absent\n' \
  >/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.absent
cat >/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak.20260725010203 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
printf '%s\n' '67937ecd9dc8b78bb7bbb248d4ef6ef6ec0ac64ad65de2141dc171faec1803cd' \
  >/var/lib/security-update-notify/last-alert.sha256
mkdir -p /etc/systemd/system/timers.target.wants
ln -s ../security-update-notify.timer \
  /etc/systemd/system/timers.target.wants/security-update-notify.timer
touch /tmp/mock-systemd/active

echo "### Failed compatibility upgrade restores legacy APT metadata"
set +e
(
  cd "$package_dir"
  FAIL_LIST_TIMERS=1 ./install.sh --skip-notify-test --non-interactive -y \
    --skip-post-install-check --lang en "${best_effort_args[@]}"
) >/tmp/sun-compat-failure.out 2>&1
failure_rc=$?
set -e
ok "[[ '$failure_rc' -eq 1 ]]" "late compatibility failure returned 1"
if ! grep -Fq 'forced compatibility list-timers failure' /tmp/sun-compat-failure.out; then
  echo "  diagnostic: compatibility upgrade failed before the injected late failure" >&2
  sed -n '1,240p' /tmp/sun-compat-failure.out >&2
fi
ok "grep -Fq 'forced compatibility list-timers failure' /tmp/sun-compat-failure.out" \
  "late compatibility failure retained its cause"
ok "! grep -Fq 'rollback was incomplete' /tmp/sun-compat-failure.out" \
  "late compatibility rollback completed"
ok "grep -Fxq 'legacy-runtime' /usr/local/sbin/security-update-notify" \
  "legacy runtime restored"
ok "grep -qF \"CONFIG_VERSION='3'\" /etc/security-update-notify/telegram.env" \
  "schema 3 configuration restored"
ok "test ! -e /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.absent && \
    test -f /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak.20260725010203 && \
    cmp -s /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak.20260725010203 \
      /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak" \
  "legacy APT vendor baseline promoted durably"
ok "test ! -e /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.absent.bak && \
    test ! -e /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.dependency-default.bak && \
    test ! -e /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.20260725010203.bak" \
  "transient migrated APT metadata rolled back"
ok "test -L /etc/systemd/system/timers.target.wants/security-update-notify.timer && \
    test -e /tmp/mock-systemd/active" \
  "legacy timer state restored"

echo "### Upgrade representative 2.x state through the generated 3.x compatibility bridge"
(
  cd "$package_dir"
  ./install.sh --skip-notify-test --non-interactive -y --skip-post-install-check --lang en \
    "${best_effort_args[@]}"
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
ok "test -L /etc/systemd/system/timers.target.wants/security-update-notify.timer && \
    test -e /tmp/mock-systemd/active" \
  "project timer enabled and active"
ok "test -e /tmp/mock-systemd/enabled/apt-daily-upgrade.timer" \
  "APT automatic timer enablement tracked"
ok "test ! -e /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.absent && \
    test ! -e /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak.20260725010203" \
  "legacy APT metadata names migrated"
ok "test ! -e /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.absent.bak && \
    test ! -e /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.dependency-default.bak && \
    test -f /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak && \
    test -f /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.20260725010203.bak" \
  "migrated APT vendor baseline retained without transient proof"
apt-config dump >/tmp/sun-compat-apt-config.out 2>&1
ok "! grep -Fq \"Ignoring file '20auto-upgrades.security-update-notify\" /tmp/sun-compat-apt-config.out" \
  "migrated APT metadata is silently ignored"

echo "3.0 compatibility upgrade test passed"
