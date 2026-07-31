#!/usr/bin/env bash
# Destructive integration gate for the Go installer/uninstaller transaction.
# This script writes real system paths and therefore refuses to run outside a
# disposable container.
set -euo pipefail

[[ -f /.dockerenv && "${SUN_CONTAINER_TEST:-0}" == 1 ]] || {
  echo "build/rollback-test.sh must run only in a disposable container" >&2
  exit 2
}
awk '$5 == "/src" { found = 1; if ($6 !~ /(^|,)ro(,|$)/) unsafe = 1 } END { exit !(found && !unsafe) }' /proc/self/mountinfo || {
  echo "build/rollback-test.sh requires /src to be mounted read-only" >&2
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
mkdir -p /run/systemd/system /etc/systemd/system /usr/local/sbin /usr/local/bin \
  /etc/security-update-notify /var/lib/security-update-notify /var/log /etc/logrotate.d \
  /etc/apt/apt.conf.d /tmp/mock-systemd
export SUN_CONTAINER_TEST_COMMAND_PATH=/usr/local/bin

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
    if [[ "${SUN_FAIL_LIST_TIMERS:-0}" == 1 ]]; then
      echo "forced list-timers failure" >&2
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
work=/tmp/sun-rollback-release
mkdir -p "$work"
tar -xzf "$tarball" -C "$work"
package_dir="$work/$(basename "$tarball" .tar.gz)"
runtime="$package_dir/files/security-update-notify-linux-amd64"
[[ -x "$runtime" ]] || { echo "amd64 Go runtime missing" >&2; exit 1; }

install_args=(
  install
  --notify-channels telegram
  --telegram-token 123456:abc_DEF-ghi
  --telegram-chat-id -100123
  --skip-notify-test
  --non-interactive
  -y
  --skip-post-install-check
  --lang en
)
best_effort_args=()
if [[ "${SUN_ALLOW_BEST_EFFORT:-0}" == 1 ]]; then
  best_effort_args=(--allow-best-effort)
  install_args+=("${best_effort_args[@]}")
fi

cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
EOF
baseline_sha="$(sha256sum /etc/apt/apt.conf.d/20auto-upgrades | awk '{print $1}')"

echo "### Busy install lock returns EX_TEMPFAIL"
exec 9>/run/security-update-notify.install.lock
flock -n 9
set +e
"$runtime" "${install_args[@]}" >/tmp/install-lock.out 2>&1
lock_rc=$?
set -e
flock -u 9
exec 9>&-
ok "[[ '$lock_rc' -eq 75 ]]" "busy install lock returned 75"
ok "[[ ! -e /usr/local/sbin/security-update-notify ]]" "lock failure changed no installation files"

echo "### Fresh Go installation"
"$runtime" "${install_args[@]}"
ok "[[ \"$(/usr/local/sbin/security-update-notify --version)\" == 'security-update-notify $version' ]]" \
  "Go runtime installed"
ok "grep -qF \"CONFIG_VERSION='4'\" /etc/security-update-notify/telegram.env" \
  "schema 4 configuration installed"
ok "[[ -L /etc/systemd/system/timers.target.wants/security-update-notify.timer ]]" \
  "timer enabled"
ok "[[ -e /tmp/mock-systemd/active ]]" "timer active"
ok "[[ -e /tmp/mock-systemd/enabled/apt-daily-upgrade.timer ]]" \
  "APT automatic timer enablement tracked"
ok "[[ -f /etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak ]]" \
  "stable APT baseline backup created"
apt-config dump >/tmp/sun-apt-config.out 2>&1
ok "! grep -Fq \"Ignoring file '20auto-upgrades.security-update-notify\" /tmp/sun-apt-config.out" \
  "SUN APT metadata names are silently ignored"

binary_sha="$(sha256sum /usr/local/sbin/security-update-notify | awk '{print $1}')"
config_sha="$(sha256sum /etc/security-update-notify/telegram.env | awk '{print $1}')"
service_sha="$(sha256sum /etc/systemd/system/security-update-notify.service | awk '{print $1}')"
timer_sha="$(sha256sum /etc/systemd/system/security-update-notify.timer | awk '{print $1}')"
apt_sha="$(sha256sum /etc/apt/apt.conf.d/20auto-upgrades | awk '{print $1}')"

echo "### Late upgrade failure rolls back files and timer state"
set +e
SUN_FAIL_LIST_TIMERS=1 "$runtime" install --host-label should-not-survive \
  --skip-notify-test --non-interactive -y --skip-post-install-check --lang en \
  "${best_effort_args[@]}" \
  >/tmp/late-upgrade.out 2>&1
upgrade_rc=$?
set -e
ok "[[ '$upgrade_rc' -eq 1 ]]" "late activation failure returned 1"
ok "grep -qF 'forced list-timers failure' /tmp/late-upgrade.out" "failure cause was retained"
ok "[[ \"$(sha256sum /usr/local/sbin/security-update-notify | awk '{print $1}')\" == '$binary_sha' ]]" \
  "runtime rolled back"
ok "[[ \"$(sha256sum /etc/security-update-notify/telegram.env | awk '{print $1}')\" == '$config_sha' ]]" \
  "configuration rolled back"
ok "[[ \"$(sha256sum /etc/systemd/system/security-update-notify.service | awk '{print $1}')\" == '$service_sha' ]]" \
  "service unit rolled back"
ok "[[ \"$(sha256sum /etc/systemd/system/security-update-notify.timer | awk '{print $1}')\" == '$timer_sha' ]]" \
  "timer unit rolled back"
ok "[[ \"$(sha256sum /etc/apt/apt.conf.d/20auto-upgrades | awk '{print $1}')\" == '$apt_sha' ]]" \
  "APT policy rolled back"
ok "[[ -L /etc/systemd/system/timers.target.wants/security-update-notify.timer \
       && -e /tmp/mock-systemd/active ]]" "timer enablement and activity rolled back"
ok "! grep -q should-not-survive /etc/security-update-notify/telegram.env" \
  "failed override did not survive"

echo "### Non-purge uninstall keeps configuration"
"$runtime" uninstall --lang en
ok "[[ ! -e /usr/local/sbin/security-update-notify ]]" "runtime removed"
ok "[[ -f /etc/security-update-notify/telegram.env ]]" "configuration retained"

echo "### Reinstall from retained configuration"
"$runtime" install --skip-notify-test --non-interactive -y --skip-post-install-check --lang en \
  "${best_effort_args[@]}"
ok "[[ \"$(/usr/local/sbin/security-update-notify --version)\" == 'security-update-notify $version' ]]" \
  "runtime reinstalled"

echo "### Purge uninstall restores baseline and removes private state"
mkdir -p /var/lib/security-update-notify
printf 'state\n' >/var/lib/security-update-notify/pending-security.first-seen
"$runtime" uninstall --purge-config --lang en
ok "[[ ! -e /usr/local/sbin/security-update-notify ]]" "runtime purged"
ok "[[ ! -e /etc/security-update-notify ]]" "configuration and credentials purged"
ok "[[ ! -e /var/lib/security-update-notify ]]" "state purged"
ok "[[ ! -e /var/backups/security-update-notify ]]" "transaction backups purged"
ok "[[ \"$(sha256sum /etc/apt/apt.conf.d/20auto-upgrades | awk '{print $1}')\" == '$baseline_sha' ]]" \
  "APT baseline restored"
ok "! find /etc/apt/apt.conf.d -maxdepth 1 -name '20auto-upgrades.security-update-notify*' | grep -q ." \
  "SUN APT backups removed"

echo "Go installer rollback and uninstaller integration test passed"
