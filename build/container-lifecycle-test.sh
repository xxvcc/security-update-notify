#!/usr/bin/env bash
# Prepare only the disposable CI image, then run the original lifecycle gate.
set -euo pipefail

[[ -f /.dockerenv && "${SUN_CONTAINER_TEST:-0}" == 1 && "$EUID" -eq 0 ]] || {
  echo "build/container-lifecycle-test.sh requires a disposable root container" >&2
  exit 2
}
awk '$5 == "/src" { found = 1; if ($6 !~ /(^|,)ro(,|$)/) unsafe = 1 } END { exit !(found && !unsafe) }' /proc/self/mountinfo || {
  echo "build/container-lifecycle-test.sh requires /src to be mounted read-only" >&2
  exit 2
}
[[ "$#" -eq 1 ]] || {
  echo "usage: container-lifecycle-test.sh compat|rollback|rocky-bootstrap" >&2
  exit 2
}
case "$1" in
  compat|rollback|rocky-bootstrap) ;;
  *) echo "unsupported lifecycle gate: $1" >&2; exit 2 ;;
esac

# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}:${VERSION_ID:-}:$1" in
  debian:11:compat|debian:11:rollback)
    # Bullseye's live security index can reference packages already archived.
    # This fixture checks historical compatibility, not current security support.
    [[ -s /sun-test-ca-certificates.crt ]] || {
      echo "Debian 11 CI requires a read-only public CA bundle at /sun-test-ca-certificates.crt" >&2
      exit 2
    }
    printf 'Acquire::https::CaInfo "/sun-test-ca-certificates.crt";\n' \
      >/etc/apt/apt.conf.d/99sun-container-ca
    cat >/etc/apt/sources.list <<'EOF'
deb https://archive.debian.org/debian bullseye main
deb https://archive.debian.org/debian-security bullseye-security main
deb https://archive.debian.org/debian bullseye-updates main
EOF
    echo 'CI fixture: official Debian archive HTTPS sources; TLS, signature and expiry checks remain enabled.'
    rm -rf /var/lib/apt/lists/*
    apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 \
      -o Acquire::https::Timeout=30 -o APT::Update::Error-Mode=any update
    ;;
  fedora:44:rocky-bootstrap)
    # Use the same repository metadata without the stalled zchunk transfer path.
    # Keep repository URLs, TLS, GPG and checksum verification unchanged.
    configuration=/etc/dnf/dnf.conf
    sed -i '/^[[:space:]]*zchunk[[:space:]]*=/d' "$configuration"
    if grep -q '^\[main\]' "$configuration"; then
      sed -i '/^\[main\]/a zchunk=False' "$configuration"
    else
      printf '\n[main]\nzchunk=False\n' >>"$configuration"
    fi
    echo 'CI fixture: Fedora 44 zchunk=False; repository verification remains enabled.'
    ;;
esac

exec bash "/src/build/$1-test.sh"
