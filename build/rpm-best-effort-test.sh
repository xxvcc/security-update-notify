#!/usr/bin/env bash
# Container-only lifecycle smoke test for publicly available best-effort
# RPM-family distributions. Package transactions are real; systemd activation
# uses a stateful mock because these images do not run systemd as PID 1.
set -euo pipefail

[[ -f /.dockerenv && "${SUN_CONTAINER_TEST:-0}" == 1 ]] || {
  echo "build/rpm-best-effort-test.sh must run only in a disposable container" >&2
  exit 2
}
awk '$5 == "/src" { found = 1; if ($6 !~ /(^|,)ro(,|$)/) unsafe = 1 } END { exit !(found && !unsafe) }' /proc/self/mountinfo || {
  echo "build/rpm-best-effort-test.sh requires /src to be mounted read-only" >&2
  exit 2
}
[[ -x "${SUN_INSTALL_BINARY:-}" ]] || {
  echo "SUN_INSTALL_BINARY must name the mounted executable installer" >&2
  exit 2
}

# /etc/os-release is provided by every supported container image.
# shellcheck disable=SC1091
source /etc/os-release
distro_id="${ID:-}"
distro_version="${VERSION_ID:-}"
distro_major="${distro_version%%.*}"
utility_package=yum-utils
case "$distro_id:$distro_major" in
  centos:9|centos:10|ol:8|ol:9|ol:10) ;;
  amzn:2023)
    utility_package=dnf-utils
    ;;
  *)
    printf 'unsupported best-effort RPM fixture: %s %s\n' "$distro_id" "$distro_version" >&2
    exit 2
    ;;
esac

assert_same_file() {
  local left="$1"
  local right="$2"
  [[ "$(sha256sum "$left" | awk '{print $1}')" == "$(sha256sum "$right" | awk '{print $1}')" ]]
}

real_package_manager=''
for candidate in dnf microdnf yum; do
  if command -v "$candidate" >/dev/null 2>&1; then
    real_package_manager="$(command -v "$candidate")"
    break
  fi
done
[[ -n "$real_package_manager" ]] || {
  echo 'no RPM package manager is available' >&2
  exit 2
}

fake_bin="$(mktemp -d)"
mock_state="$(mktemp -d)"
vendor_baseline="$(mktemp)"
token_file="$(mktemp)"
printf '%s\n' '123456:rpm_best_effort_fixture' >"$token_file"
chmod 0600 "$token_file"
export SUN_BEST_EFFORT_STATE="$mock_state"
export SUN_BEST_EFFORT_VENDOR="$vendor_baseline"
export SUN_REAL_PACKAGE_MANAGER="$real_package_manager"
mkdir -p /run/systemd/system /etc/systemd/system

package_manager_name="$(basename "$real_package_manager")"
cat >"$fake_bin/$package_manager_name" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
set +e
"${SUN_REAL_PACKAGE_MANAGER:?}" "$@"
status=$?
set -e
[[ "$status" -eq 0 ]] || exit "$status"

installed_automatic=0
for argument in "$@"; do
  if [[ "$argument" == dnf-automatic ]]; then
    installed_automatic=1
  fi
done
if [[ "$installed_automatic" == 1 && -f /etc/dnf/automatic.conf ]]; then
  cp /etc/dnf/automatic.conf "${SUN_BEST_EFFORT_VENDOR:?}"
  : >"${SUN_BEST_EFFORT_STATE:?}/vendor-recorded"
fi
EOF
chmod 0755 "$fake_bin/$package_manager_name"

cat >"$fake_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state="${SUN_BEST_EFFORT_STATE:?}"
enabled="$state/enabled"
active="$state/active"
command="${1:-}"
unit="${*: -1}"
case "$command" in
  is-enabled)
    if [[ -e "$enabled/$unit" ]]; then
      echo enabled
      exit 0
    fi
    echo disabled
    exit 1
    ;;
  is-active)
    if [[ -e "$active/$unit" ]]; then
      echo active
      exit 0
    fi
    echo inactive
    exit 3
    ;;
  enable)
    mkdir -p "$enabled" "$active"
    for unit in "${@:2}"; do
      [[ "$unit" == -* ]] && continue
      : >"$enabled/$unit"
      if [[ " $* " == *" --now "* ]]; then
        : >"$active/$unit"
      fi
    done
    ;;
  disable)
    for unit in "${@:2}"; do
      [[ "$unit" == -* ]] && continue
      rm -f "$enabled/$unit"
      if [[ " $* " == *" --now "* ]]; then
        rm -f "$active/$unit"
      fi
    done
    ;;
  start)
    mkdir -p "$active"
    : >"$active/$unit"
    ;;
  stop)
    rm -f "$active/$unit"
    ;;
  daemon-reload)
    ;;
  list-timers)
    echo 'security-update-notify.timer mock'
    ;;
  *)
    echo "unsupported mock systemctl invocation: $*" >&2
    exit 1
    ;;
esac
EOF
chmod 0755 "$fake_bin/systemctl"

if [[ -f /etc/dnf/automatic.conf ]]; then
  cp /etc/dnf/automatic.conf "$vendor_baseline"
  : >"$mock_state/vendor-recorded"
fi
fixture_path="$fake_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export SUN_CONTAINER_TEST_COMMAND_PATH="$fake_bin"

PATH="$fixture_path" "$SUN_INSTALL_BINARY" install \
  --allow-best-effort \
  --lang en \
  --non-interactive \
  --yes \
  --notify-channels telegram \
  --telegram-token-file "$token_file" \
  --telegram-chat-id '-100123' \
  --skip-notify-test \
  --skip-post-install-check

rpm -q dnf-automatic ca-certificates "$utility_package" >/dev/null
command -v dnf >/dev/null
command -v dnf-automatic >/dev/null
command -v needs-restarting >/dev/null
grep -Fxq "CONFIG_VERSION='4'" /etc/security-update-notify/telegram.env
grep -Fxq "BACKEND='dnf'" /etc/security-update-notify/telegram.env
grep -Fq 'upgrade_type = security' /etc/dnf/automatic.conf
grep -Fq 'apply_updates = yes' /etc/dnf/automatic.conf
grep -Fq 'reboot = never' /etc/dnf/automatic.conf
[[ -e "$mock_state/enabled/dnf-automatic.timer" ]]
[[ -e "$mock_state/enabled/security-update-notify.timer" ]]
if [[ -e "$mock_state/vendor-recorded" ]]; then
  assert_same_file "$vendor_baseline" /etc/dnf/automatic.conf.security-update-notify.bak
fi
/usr/local/sbin/security-update-notify --version

PATH="$fixture_path" "$SUN_INSTALL_BINARY" install \
  --allow-best-effort --lang en --non-interactive --yes \
  --host-label rpm-best-effort-upgraded --skip-notify-test --skip-post-install-check
grep -Fxq "HOST_LABEL='rpm-best-effort-upgraded'" /etc/security-update-notify/telegram.env
[[ -e "$mock_state/enabled/dnf-automatic.timer" ]]
[[ -e "$mock_state/enabled/security-update-notify.timer" ]]

PATH="$fixture_path" "$SUN_INSTALL_BINARY" uninstall --purge-config --lang en
[[ ! -e /usr/local/sbin/security-update-notify ]]
[[ ! -e /etc/security-update-notify ]]
[[ ! -e /var/lib/security-update-notify ]]
[[ ! -e /var/backups/security-update-notify ]]
[[ ! -e /etc/dnf/automatic.conf.security-update-notify.bak ]]
[[ ! -e /etc/dnf/automatic.conf.security-update-notify.absent.bak ]]
[[ ! -e /etc/dnf/automatic.conf.security-update-notify.dependency-default.bak ]]
if [[ -e "$mock_state/vendor-recorded" ]]; then
  assert_same_file "$vendor_baseline" /etc/dnf/automatic.conf
else
  [[ ! -e /etc/dnf/automatic.conf ]]
fi
[[ -e "$mock_state/enabled/dnf-automatic.timer" ]]
[[ ! -e "$mock_state/enabled/security-update-notify.timer" ]]

printf '%s %s best-effort RPM lifecycle test passed\n' "$distro_id" "$distro_version"
