#!/usr/bin/env bash
# Real RPM-family container smoke test for bootstrap dependency installation
# and the Go install lifecycle. EL minimal images exercise microdnf recovery;
# Fedora exercises the DNF5 automatic plugin. Containers have no running
# systemd, so activation uses a stateful systemctl contract mock.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(mktemp)"
cleanup() {
  local status=$?
  if [[ "$status" -ne 0 && -s "$OUT" ]]; then
    cat "$OUT" >&2
  fi
  rm -f "$OUT"
  return "$status"
}
trap cleanup EXIT

[[ -f /.dockerenv && "${SUN_CONTAINER_TEST:-0}" == 1 ]] || {
  echo "build/rocky-bootstrap-test.sh must run only in a disposable container" >&2
  exit 2
}
awk '$5 == "/src" { found = 1; if ($6 !~ /(^|,)ro(,|$)/) unsafe = 1 } END { exit !(found && !unsafe) }' /proc/self/mountinfo || {
  echo "build/rocky-bootstrap-test.sh requires /src to be mounted read-only" >&2
  exit 2
}

# /etc/os-release is provided by every supported container image.
# shellcheck disable=SC1091
source /etc/os-release
distro_id="${ID:-}"
distro_version="${VERSION_ID:-}"
fixture_family=''
engine=''
el_major=''
expected_missing=''
automatic_timer=''
automatic_timer_variants=()

case "$distro_id" in
  rocky|almalinux)
    fixture_family=el
    engine=dnf4
    automatic_timer=dnf-automatic.timer
    automatic_timer_variants=(
      dnf-automatic-notifyonly.timer
      dnf-automatic-download.timer
      dnf-automatic-install.timer
    )
    command -v microdnf >/dev/null
    el_major="$(rpm -E '%{rhel}')"
    [[ ! -x /usr/bin/dnf && ! -x /usr/bin/yum ]]

    # EL9 exposes curl-minimal. EL8 and EL10 minimal use full curl; all retain
    # coreutils-single so bootstrap must not introduce the conflicting package.
    case "$el_major" in
      8)
        rpm -q curl coreutils-single gnupg2 >/dev/null
        expected_missing='tar python3'
        ;;
      9)
        if rpm -q curl >/dev/null 2>&1; then
          rpm -e --nodeps curl
        fi
        microdnf install -y curl-minimal >/dev/null
        rpm -q curl-minimal coreutils-single gnupg2 >/dev/null
        # Exercise recovery of a missing gpg command while leaving the shared
        # libraries microdnf needs available in the disposable fixture.
        rpm -e --justdb --nodeps gnupg2
        mv /usr/bin/gpg /usr/bin/gpg.security-update-notify-hidden
        if command -v gpg >/dev/null; then
          echo 'gpg command unexpectedly remains available in the EL9 fixture' >&2
          exit 1
        fi
        if rpm -q gnupg2 >/dev/null 2>&1; then
          echo 'gnupg2 unexpectedly remains installed in the EL9 fixture' >&2
          exit 1
        fi
        expected_missing='tar python3 gpg'
        ;;
      10)
        rpm -q curl coreutils-single >/dev/null
        if rpm -q gnupg2 >/dev/null 2>&1; then
          echo 'gnupg2 unexpectedly starts installed in the EL10 fixture' >&2
          exit 1
        fi
        if command -v gpg >/dev/null; then
          echo 'gpg command unexpectedly starts available in the EL10 fixture' >&2
          exit 1
        fi
        expected_missing='tar python3 gpg'
        ;;
      *)
        printf 'unsupported EL major version in test fixture: %s\n' "$el_major" >&2
        exit 2
        ;;
    esac
    ;;
  fedora)
    fixture_family=fedora
    engine=dnf5
    automatic_timer=dnf5-automatic.timer
    automatic_timer_variants=(dnf-automatic.timer)
    case "$distro_version" in
      43|44) ;;
      *)
        printf 'unsupported Fedora version in test fixture: %s\n' "$distro_version" >&2
        exit 2
        ;;
    esac
    command -v dnf >/dev/null
    rpm -q coreutils dnf5 dnf5-plugins gnupg2 >/dev/null
    if command -v python3 >/dev/null; then
      echo 'python3 unexpectedly starts available in the Fedora fixture' >&2
      exit 1
    fi
    expected_missing='python3'
    ;;
  *)
    printf 'unsupported distribution in RPM fixture: %s %s\n' "$distro_id" "$distro_version" >&2
    exit 2
    ;;
esac

assert_automatic_timer_symlinks() {
  local timer_wants=/etc/systemd/system/timers.target.wants
  local unit
  [[ -f "/usr/lib/systemd/system/$automatic_timer" ]]
  [[ -L "$timer_wants/$automatic_timer" ]]
  [[ "$(readlink -f "$timer_wants/$automatic_timer")" == "$(readlink -f "/usr/lib/systemd/system/$automatic_timer")" ]]
  for unit in "${automatic_timer_variants[@]}"; do
    if [[ -L "$timer_wants/$unit" ]]; then
      printf 'conflicting dnf-automatic timer survived installation: %s\n' "$unit" >&2
      return 1
    fi
  done
}

assert_same_file() {
  local left="$1"
  local right="$2"
  local left_sha right_sha
  left_sha="$(sha256sum "$left" | awk '{print $1}')"
  right_sha="$(sha256sum "$right" | awk '{print $1}')"
  [[ "$left_sha" == "$right_sha" ]]
}

assert_sun_alias() {
  [[ -L /usr/local/sbin/sun ]]
  [[ "$(readlink -- /usr/local/sbin/sun)" == security-update-notify ]]
}

assert_sun_alias_absent() {
  [[ ! -e /usr/local/sbin/sun && ! -L /usr/local/sbin/sun ]]
}

version="$(sed -n 's/^VERSION="\([^"]*\)"$/\1/p' "$ROOT/VERSION")"
[[ -n "$version" && "$(wc -l <"$ROOT/VERSION")" -eq 1 ]]

set +e
/bin/bash -p "$ROOT/sun.sh" --lang en --version "$version" --base-url https://127.0.0.1:9 \
  install --non-interactive >"$OUT" 2>&1
rc=$?
set -e

[[ "$rc" -eq 1 ]] || {
  cat "$OUT" >&2
  printf 'sun.sh exited %s, expected download failure after dependency bootstrap\n' "$rc" >&2
  exit 1
}
grep -Fq "Installing missing bootstrap dependencies through the system package manager: $expected_missing" "$OUT"
grep -Fq 'All release download sources failed.' "$OUT"
command -v tar >/dev/null
command -v python3 >/dev/null
command -v gpg >/dev/null
if [[ "$fixture_family" == el ]]; then
  rpm -q coreutils-single gnupg2 >/dev/null
  if rpm -q coreutils >/dev/null 2>&1; then
    echo 'bootstrap replaced coreutils-single with coreutils' >&2
    exit 1
  fi
  if [[ "$el_major" == 9 ]]; then
    rpm -q curl-minimal >/dev/null
    if rpm -q curl >/dev/null 2>&1; then
      echo 'bootstrap replaced curl-minimal with curl on EL9' >&2
      exit 1
    fi
    rm -f /usr/bin/gpg.security-update-notify-hidden
  else
    rpm -q curl >/dev/null
  fi
else
  rpm -q coreutils dnf5 dnf5-plugins gnupg2 >/dev/null
  dnf_version="$(dnf --version)"
  grep -Fq 'dnf5 version' <<<"$dnf_version"
fi

printf '%s %s bootstrap dependency test passed\n' "$distro_id" "$distro_version"

if [[ -n "${SUN_INSTALL_BINARY:-}" ]]; then
  [[ -x "$SUN_INSTALL_BINARY" ]] || {
    printf 'SUN_INSTALL_BINARY is not executable: %s\n' "$SUN_INSTALL_BINARY" >&2
    exit 1
  }
  if [[ "$fixture_family" == el ]]; then
    [[ ! -x /usr/bin/dnf && ! -x /usr/bin/yum ]]
  fi

  fake_bin="$(mktemp -d)"
  fake_systemd_state="$(mktemp -d)"
  export SUN_MOCK_SYSTEMCTL_STATE="$fake_systemd_state"
  export SUN_DNF_VENDOR_BASELINE="$fake_systemd_state/dnf-vendor-automatic.conf"
  token_file="$(mktemp)"
  printf '%s\n' '123456:rpm_container_fixture' >"$token_file"
  chmod 0600 "$token_file"
  mkdir -p /run/systemd/system
  cat >"$fake_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state="${SUN_MOCK_SYSTEMCTL_STATE:?}"
unit="${*: -1}"
timer_wants=/etc/systemd/system/timers.target.wants
case "${1:-}" in
  is-enabled)
    if [[ -e "$state/enabled/$unit" || -L "$timer_wants/$unit" ]]; then
      echo enabled
      exit 0
    fi
    echo disabled
    exit 1
    ;;
  is-active)
    if [[ -e "$state/active/$unit" ]]; then
      echo active
      exit 0
    fi
    echo inactive
    exit 3
    ;;
  list-timers)
    if [[ "${SUN_FAIL_LIST_TIMERS:-0}" == 1 ]]; then
      echo 'forced RPM-container list-timers failure' >&2
      exit 1
    fi
    echo 'security-update-notify.timer mock'
    ;;
  enable)
    mkdir -p "$state/enabled" "$state/active" "$timer_wants"
    for unit in "${@:2}"; do
      [[ "$unit" == -* ]] && continue
      : >"$state/enabled/$unit"
      if [[ "$unit" == *.timer ]]; then
        unit_file="/usr/lib/systemd/system/$unit"
        if [[ -e "/etc/systemd/system/$unit" ]]; then
          unit_file="/etc/systemd/system/$unit"
        fi
        ln -sfn "$unit_file" "$timer_wants/$unit"
      fi
      if [[ " $* " == *" --now "* ]]; then
        : >"$state/active/$unit"
      fi
    done
    ;;
  disable)
    for unit in "${@:2}"; do
      [[ "$unit" == -* ]] && continue
      rm -f "$state/enabled/$unit" "$state/active/$unit"
      if [[ "$unit" == *.timer ]]; then
        rm -f "$timer_wants/$unit"
      fi
    done
    ;;
  start)
    mkdir -p "$state/active"
    : >"$state/active/$unit"
    ;;
  stop)
    rm -f "$state/active/$unit"
    ;;
  daemon-reload)
    ;;
  *)
    echo "unsupported mock systemctl invocation: $*" >&2
    exit 1
    ;;
esac
EOF
  chmod 0755 "$fake_bin/systemctl"
  if [[ "$engine" == dnf4 ]]; then
    cat >"$fake_bin/microdnf" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
set +e
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/microdnf "$@"
status=$?
set -e
[[ "$status" -eq 0 ]] || exit "$status"

installed_automatic=0
for argument in "$@"; do
  if [[ "$argument" == dnf-automatic ]]; then
    installed_automatic=1
  fi
done
if [[ "${SUN_SEED_DNF4_TIMER_VARIANTS:-0}" == 1 && "$installed_automatic" == 1 ]]; then
  [[ -f /etc/dnf/automatic.conf ]]
  cp /etc/dnf/automatic.conf "${SUN_DNF_VENDOR_BASELINE:?}"
  timer_wants=/etc/systemd/system/timers.target.wants
  mkdir -p "$timer_wants"
  for unit in \
    dnf-automatic.timer \
    dnf-automatic-notifyonly.timer \
    dnf-automatic-download.timer \
    dnf-automatic-install.timer; do
    link="$timer_wants/$unit"
    vendor="/usr/lib/systemd/system/$unit"
    if [[ ! -f "$vendor" ]]; then
      printf 'dnf-automatic package did not install the expected timer unit: %s\n' "$vendor" >&2
      exit 1
    fi
    # /run/systemd/system exists for the installer guard, but this fixture has
    # no systemd PID 1. Seed the package's real units explicitly so the test
    # deterministically exercises removal of every conflicting timer variant.
    ln -sfn "$vendor" "$link"
  done
  : >"${SUN_MOCK_SYSTEMCTL_STATE:?}/dnf4-timer-variants-seeded"
fi
EOF
    chmod 0755 "$fake_bin/microdnf"
  else
    cat >"$fake_bin/dnf" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
set +e
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/dnf "$@"
status=$?
set -e
[[ "$status" -eq 0 ]] || exit "$status"

installed_automatic=0
for argument in "$@"; do
  if [[ "$argument" == dnf5-plugin-automatic ]]; then
    installed_automatic=1
  fi
done
if [[ "${SUN_SEED_DNF5_COMPAT_TIMER:-0}" == 1 && "$installed_automatic" == 1 ]]; then
  unit=dnf-automatic.timer
  vendor="/usr/lib/systemd/system/$unit"
  [[ -f "$vendor" ]]
  state="${SUN_MOCK_SYSTEMCTL_STATE:?}"
  timer_wants=/etc/systemd/system/timers.target.wants
  mkdir -p "$state/enabled" "$state/active" "$timer_wants"
  : >"$state/enabled/$unit"
  : >"$state/active/$unit"
  ln -sfn "$vendor" "$timer_wants/$unit"
  : >"$state/dnf5-compat-timer-seeded"
fi
EOF
    chmod 0755 "$fake_bin/dnf"
  fi
  fixture_path="$fake_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export SUN_CONTAINER_TEST_COMMAND_PATH="$fake_bin"
  export SUN_SEED_DNF4_TIMER_VARIANTS=0
  export SUN_SEED_DNF5_COMPAT_TIMER=0
  if [[ "$engine" == dnf4 ]]; then
    export SUN_SEED_DNF4_TIMER_VARIANTS=1
  else
    export SUN_SEED_DNF5_COMPAT_TIMER=1
  fi
  if PATH="$fixture_path" systemctl is-enabled --quiet "$automatic_timer" >/dev/null 2>&1; then
    echo 'automatic-update timer unexpectedly starts enabled in the mock' >&2
    exit 1
  fi

  PATH="$fixture_path" "$SUN_INSTALL_BINARY" install \
    --lang en \
    --non-interactive \
    --yes \
    --notify-channels telegram \
    --telegram-token-file "$token_file" \
    --telegram-chat-id '-100123' \
    --skip-notify-test \
    --skip-post-install-check

  if [[ "$engine" == dnf4 ]]; then
    rpm -q dnf-automatic ca-certificates yum-utils >/dev/null
    command -v dnf >/dev/null
    command -v dnf-automatic >/dev/null
    command -v needs-restarting >/dev/null
    dnf-automatic --help >/dev/null
    if [[ "$distro_id" == rocky && "$el_major" == 10 ]]; then
      rpm -q dnf >/dev/null
    fi
  else
    rpm -q dnf5-plugin-automatic ca-certificates dnf5-plugins >/dev/null
    dnf automatic --help >/dev/null
    dnf needs-restarting --help >/dev/null
    plugin_files="$(rpm -ql dnf5-plugin-automatic)"
    grep -Fxq "/usr/lib/systemd/system/$automatic_timer" <<<"$plugin_files"
    advisory_json="$(mktemp)"
    dnf advisory list --security --updates --json >"$advisory_json"
    python3 -I - "$advisory_json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    data = json.load(stream)
if not isinstance(data, list):
    raise SystemExit("DNF5 advisory JSON root must be a list")
PY
    set +e
    dnf check-upgrade --security >"$OUT" 2>&1
    check_upgrade_rc=$?
    set -e
    [[ "$check_upgrade_rc" -eq 0 || "$check_upgrade_rc" -eq 100 ]]
    bash /src/build/dnf5-versionlock-test.sh
  fi
  grep -Fxq "BACKEND='dnf'" /etc/security-update-notify/telegram.env
  grep -Fq 'upgrade_type = security' /etc/dnf/automatic.conf
  grep -Fq 'apply_updates = yes' /etc/dnf/automatic.conf
  grep -Fq 'reboot = never' /etc/dnf/automatic.conf
  [[ -e "$fake_systemd_state/enabled/$automatic_timer" ]]
  [[ ! -e /etc/dnf/automatic.conf.security-update-notify.dependency-default.bak ]]
  if [[ "$engine" == dnf4 ]]; then
    assert_same_file "$SUN_DNF_VENDOR_BASELINE" /etc/dnf/automatic.conf.security-update-notify.bak
    [[ ! -e /etc/dnf/automatic.conf.security-update-notify.absent.bak ]]
    [[ -e "$fake_systemd_state/dnf4-timer-variants-seeded" ]]
  else
    [[ -e "$fake_systemd_state/dnf5-compat-timer-seeded" ]]
  fi
  assert_automatic_timer_symlinks
  for unit in "${automatic_timer_variants[@]}"; do
    if [[ -e "$fake_systemd_state/enabled/$unit" || -e "$fake_systemd_state/active/$unit" ]]; then
      printf 'conflicting automatic-update timer survived installation: %s\n' "$unit" >&2
      exit 1
    fi
  done
  /usr/local/sbin/security-update-notify --version
  assert_sun_alias

  binary_sha="$(sha256sum /usr/local/sbin/security-update-notify | awk '{print $1}')"
  config_sha="$(sha256sum /etc/security-update-notify/telegram.env | awk '{print $1}')"
  set +e
  SUN_FAIL_LIST_TIMERS=1 PATH="$fixture_path" "$SUN_INSTALL_BINARY" install \
    --lang en --non-interactive --yes --host-label must-not-survive \
    --skip-notify-test --skip-post-install-check >"$OUT" 2>&1
  upgrade_rc=$?
  set -e
  [[ "$upgrade_rc" -eq 1 ]]
  grep -Fq 'forced RPM-container list-timers failure' "$OUT"
  [[ "$(sha256sum /usr/local/sbin/security-update-notify | awk '{print $1}')" == "$binary_sha" ]]
  [[ "$(sha256sum /etc/security-update-notify/telegram.env | awk '{print $1}')" == "$config_sha" ]]
  if grep -Fq 'must-not-survive' /etc/security-update-notify/telegram.env; then
    echo 'failed-upgrade configuration survived rollback' >&2
    exit 1
  fi
  [[ -e "$fake_systemd_state/enabled/$automatic_timer" ]]
  [[ ! -e /etc/dnf/automatic.conf.security-update-notify.dependency-default.bak ]]
  assert_automatic_timer_symlinks

  PATH="$fixture_path" "$SUN_INSTALL_BINARY" install \
    --lang en --non-interactive --yes --host-label rpm-container-upgraded \
    --skip-notify-test --skip-post-install-check
  grep -Fxq "HOST_LABEL='rpm-container-upgraded'" /etc/security-update-notify/telegram.env
  [[ ! -e /etc/dnf/automatic.conf.security-update-notify.dependency-default.bak ]]
  assert_automatic_timer_symlinks
  assert_sun_alias

  PATH="$fixture_path" "$SUN_INSTALL_BINARY" uninstall --purge-config --lang en
  [[ ! -e /usr/local/sbin/security-update-notify ]]
  assert_sun_alias_absent
  [[ ! -e /etc/security-update-notify ]]
  [[ ! -e /var/lib/security-update-notify ]]
  [[ ! -e /var/backups/security-update-notify ]]
  if [[ "$engine" == dnf4 ]]; then
    assert_same_file "$SUN_DNF_VENDOR_BASELINE" /etc/dnf/automatic.conf
    [[ ! -e /etc/dnf/automatic.conf.security-update-notify.bak ]]
  else
    [[ ! -e /etc/dnf/automatic.conf ]]
  fi
  assert_automatic_timer_symlinks
  [[ ! -e /etc/dnf/automatic.conf.security-update-notify.absent.bak ]]
  [[ ! -e /etc/dnf/automatic.conf.security-update-notify.dependency-default.bak ]]
  [[ -e "$fake_systemd_state/enabled/$automatic_timer" ]]
  [[ ! -e "$fake_systemd_state/enabled/security-update-notify.timer" ]]

  legacy_vendor="$(mktemp)"
  if [[ "$engine" == dnf4 ]]; then
    cp /etc/dnf/automatic.conf "$legacy_vendor"
  else
    cat >"$legacy_vendor" <<'EOF'
[commands]
upgrade_type = default
apply_updates = no

[emitters]
emit_via = stdio

[base]
debuglevel = 1
EOF
  fi
  legacy_timestamp=/etc/dnf/automatic.conf.security-update-notify.bak.20260725010203
  cp "$legacy_vendor" "$legacy_timestamp"
  cat >/etc/dnf/automatic.conf <<'EOF'
[commands]
upgrade_type = security
apply_updates = yes

[emitters]
emit_via = stdio

[base]
debuglevel = 1
EOF
  mkdir -p /etc/security-update-notify /var/lib/security-update-notify
  cat >/etc/security-update-notify/telegram.env <<'EOF'
CONFIG_VERSION='3'
NOTIFY_CHANNELS='telegram'
TELEGRAM_BOT_TOKEN='123456:rpm_schema3_fixture'
TELEGRAM_CHAT_ID='-100123'
HOST_LABEL='rpm-schema3-host'
PUBLIC_IP=''
INCLUDE_PUBLIC_IP='0'
NOTIFY_OK='0'
NOTIFY_UPGRADE='0'
DEDUP_MODE='daily'
DEDUP_INTERVAL_DAYS='3'
NOTIFY_LANG='en'
BACKEND='dnf'
CHECK_UPDATE_HEALTH='0'
STALE_UPDATE_DAYS='0'
CHECK_EOL='0'
EOF
  chmod 0600 /etc/security-update-notify/telegram.env
  cat >/usr/local/sbin/security-update-notify <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == --version ]]; then
  echo 'security-update-notify 2.2.4'
fi
EOF
  chmod 0755 /usr/local/sbin/security-update-notify
  printf '[Unit]\nDescription=legacy schema-3 service\n' \
    >/etc/systemd/system/security-update-notify.service
  printf '[Timer]\nOnCalendar=*-*-* 08:30:00\n' \
    >/etc/systemd/system/security-update-notify.timer
  PATH="$fixture_path" systemctl enable --now security-update-notify.timer

  PATH="$fixture_path" "$SUN_INSTALL_BINARY" install \
    --lang en --non-interactive --yes --skip-notify-test --skip-post-install-check
  grep -Fxq "CONFIG_VERSION='4'" /etc/security-update-notify/telegram.env
  grep -Fxq "HOST_LABEL='rpm-schema3-host'" /etc/security-update-notify/telegram.env
  grep -Fxq "TELEGRAM_BOT_TOKEN='123456:rpm_schema3_fixture'" \
    /etc/security-update-notify/telegram.env
  grep -Fxq "PENDING_ALERT_DAYS='3'" /etc/security-update-notify/telegram.env
  grep -Fxq "RESTART_ALERT_DAYS='7'" /etc/security-update-notify/telegram.env
  grep -Fxq "CHECK_SELF_UPDATE='1'" /etc/security-update-notify/telegram.env
  assert_same_file "$legacy_vendor" /etc/dnf/automatic.conf.security-update-notify.bak
  [[ -e "$legacy_timestamp" ]]
  grep -Fq 'upgrade_type = security' /etc/dnf/automatic.conf
  grep -Fq 'apply_updates = yes' /etc/dnf/automatic.conf
  grep -Fq 'reboot = never' /etc/dnf/automatic.conf
  [[ -e "$fake_systemd_state/enabled/security-update-notify.timer" ]]
  assert_automatic_timer_symlinks
  assert_sun_alias

  PATH="$fixture_path" "$SUN_INSTALL_BINARY" uninstall --purge-config --lang en
  assert_sun_alias_absent
  assert_same_file "$legacy_vendor" /etc/dnf/automatic.conf
  [[ ! -e /etc/dnf/automatic.conf.security-update-notify.bak ]]
  if compgen -G '/etc/dnf/automatic.conf.security-update-notify.bak.*' >/dev/null; then
    echo 'schema-3 DNF timestamp backup survived purge' >&2
    exit 1
  fi
  [[ ! -e /etc/security-update-notify ]]
  [[ ! -e /var/lib/security-update-notify ]]
  [[ ! -e "$fake_systemd_state/enabled/security-update-notify.timer" ]]
  [[ -e "$fake_systemd_state/enabled/$automatic_timer" ]]
  assert_automatic_timer_symlinks

  printf '%s %s Go install, rollback, schema-3 upgrade, and uninstall lifecycle test passed\n' \
    "$distro_id" "$distro_version"
fi
