#!/usr/bin/env bash
# Real Rocky minimal smoke test for bootstrap dependency installation. It
# preserves each release's minimal curl/coreutils providers, removes gpg where
# microdnf can recover it, then stops at an unreachable HTTPS release URL after
# the bootstrap dependencies have been installed.
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
awk '$5 == "/src" && $6 ~ /(^|,)ro(,|$)/ { found = 1 } END { exit !found }' /proc/self/mountinfo || {
  echo "build/rocky-bootstrap-test.sh requires /src to be mounted read-only" >&2
  exit 2
}

command -v microdnf >/dev/null
[[ ! -x /usr/bin/dnf && ! -x /usr/bin/yum ]]

# EL9 provides curl-minimal, while EL8's repositories expose only the full curl
# package. Exercise each release's real package layout while retaining the
# conflict-prone coreutils-single provider on both.
rocky_major="$(rpm -E '%{rhel}')"
case "$rocky_major" in
  8)
    rpm -q curl coreutils-single gnupg2 >/dev/null
    ;;
  9)
    rpm -e --nodeps curl
    microdnf install -y curl-minimal >/dev/null
    rpm -q curl-minimal coreutils-single gnupg2 >/dev/null
    ;;
  *)
    printf 'unsupported Rocky major version in test fixture: %s\n' "$rocky_major" >&2
    exit 2
    ;;
esac

# EL9 microdnf can restore gnupg2 while gpg itself is absent. EL8 microdnf
# requires gpg to initialize its own crypto engine, so test its supported
# minimal-image state instead and leave recovery diagnostics to the mock gate.
expected_missing='tar python3'
if [[ "$rocky_major" == 9 ]]; then
  rpm -e --justdb --nodeps gnupg2
  mv /usr/bin/gpg /usr/bin/gpg.security-update-notify-hidden
  ! command -v gpg >/dev/null
  ! rpm -q gnupg2 >/dev/null 2>&1
  expected_missing='tar python3 gpg'
fi

version="$(sed -n 's/^VERSION="\([^"]*\)"$/\1/p' "$ROOT/VERSION")"
[[ -n "$version" && "$(wc -l <"$ROOT/VERSION")" -eq 1 ]]

set +e
bash "$ROOT/sun.sh" --lang en --version "$version" --base-url https://127.0.0.1:9 \
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
rpm -q coreutils-single gnupg2 >/dev/null
! rpm -q coreutils >/dev/null 2>&1
if [[ "$rocky_major" == 9 ]]; then
  rpm -q curl-minimal >/dev/null
  ! rpm -q curl >/dev/null 2>&1
else
  rpm -q curl >/dev/null
fi
if [[ "$rocky_major" == 9 ]]; then
  rm -f /usr/bin/gpg.security-update-notify-hidden
fi

echo 'Rocky minimal bootstrap dependency test passed'

if [[ -n "${SUN_INSTALL_BINARY:-}" ]]; then
  [[ -x "$SUN_INSTALL_BINARY" ]] || {
    printf 'SUN_INSTALL_BINARY is not executable: %s\n' "$SUN_INSTALL_BINARY" >&2
    exit 1
  }
  [[ ! -x /usr/bin/dnf && ! -x /usr/bin/yum ]]

  fake_bin="$(mktemp -d)"
  token_file="$(mktemp)"
  printf '%s\n' '123456:rocky_minimal_fixture' >"$token_file"
  chmod 0600 "$token_file"
  mkdir -p /run/systemd/system
  cat >"$fake_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  is-enabled)
    echo disabled
    exit 1
    ;;
  is-active)
    exit 1
    ;;
  list-timers)
    if [[ "${SUN_FAIL_LIST_TIMERS:-0}" == 1 ]]; then
      echo 'forced Rocky list-timers failure' >&2
      exit 1
    fi
    echo 'security-update-notify.timer mock'
    ;;
  disable|enable|start|stop|daemon-reload)
    ;;
  *)
    echo "unsupported mock systemctl invocation: $*" >&2
    exit 1
    ;;
esac
EOF
  chmod 0755 "$fake_bin/systemctl"

  PATH="$fake_bin:/usr/bin:/bin" "$SUN_INSTALL_BINARY" install \
    --lang en \
    --non-interactive \
    --yes \
    --notify-channels telegram \
    --telegram-token-file "$token_file" \
    --telegram-chat-id '-100123' \
    --skip-notify-test \
    --skip-post-install-check

  rpm -q dnf-automatic ca-certificates yum-utils >/dev/null
  command -v needs-restarting >/dev/null
  grep -Fxq "BACKEND='dnf'" /etc/security-update-notify/telegram.env
  grep -Fq 'upgrade_type = security' /etc/dnf/automatic.conf
  grep -Fq 'apply_updates = yes' /etc/dnf/automatic.conf
  /usr/local/sbin/security-update-notify --version

  binary_sha="$(sha256sum /usr/local/sbin/security-update-notify | awk '{print $1}')"
  config_sha="$(sha256sum /etc/security-update-notify/telegram.env | awk '{print $1}')"
  set +e
  SUN_FAIL_LIST_TIMERS=1 PATH="$fake_bin:/usr/bin:/bin" "$SUN_INSTALL_BINARY" install \
    --lang en --non-interactive --yes --host-label must-not-survive \
    --skip-notify-test --skip-post-install-check >"$OUT" 2>&1
  upgrade_rc=$?
  set -e
  [[ "$upgrade_rc" -eq 1 ]]
  grep -Fq 'forced Rocky list-timers failure' "$OUT"
  [[ "$(sha256sum /usr/local/sbin/security-update-notify | awk '{print $1}')" == "$binary_sha" ]]
  [[ "$(sha256sum /etc/security-update-notify/telegram.env | awk '{print $1}')" == "$config_sha" ]]
  ! grep -Fq 'must-not-survive' /etc/security-update-notify/telegram.env

  PATH="$fake_bin:/usr/bin:/bin" "$SUN_INSTALL_BINARY" install \
    --lang en --non-interactive --yes --host-label rocky-upgraded \
    --skip-notify-test --skip-post-install-check
  grep -Fxq "HOST_LABEL='rocky-upgraded'" /etc/security-update-notify/telegram.env

  PATH="$fake_bin:/usr/bin:/bin" "$SUN_INSTALL_BINARY" uninstall --purge-config --lang en
  [[ ! -e /usr/local/sbin/security-update-notify ]]
  [[ ! -e /etc/security-update-notify ]]
  [[ ! -e /var/lib/security-update-notify ]]
  [[ ! -e /var/backups/security-update-notify ]]
  ! grep -Fq 'upgrade_type = security' /etc/dnf/automatic.conf

  echo 'Rocky minimal Go install, rollback, upgrade, and uninstall lifecycle test passed'
fi
