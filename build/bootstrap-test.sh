#!/usr/bin/env bash
# Regression gate for bootstrap argument parsing, TTY cancellation, and exact
# dependency package selection. It never downloads or installs a release.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

expect_rc() {
  local expected="$1"
  shift
  set +e
  "$@" >"$TMP/out" 2>&1
  local actual=$?
  set -e
  [[ "$actual" -eq "$expected" ]] || {
    cat "$TMP/out" >&2
    printf 'exit %s, expected %s: %s\n' "$actual" "$expected" "$*" >&2
    exit 1
  }
}

expect_rc 2 bash "$ROOT/sun.sh" --verify-signature off --version bad/value install --lang en --non-interactive
grep -Fq 'Invalid VERSION: bad/value' "$TMP/out"

expect_rc 2 bash "$ROOT/sun.sh" --lang en --verify-signature off --version bad/value install --non-interactive
grep -Fq 'Invalid VERSION: bad/value' "$TMP/out"

# Invalid bootstrap arguments must fail before a missing-command scan can
# invoke the package manager. The fake PATH exposes apt-get and none of the
# bootstrap tools, so any ordering regression leaves a sentinel behind.
mkdir -p "$TMP/invalid-path"
cat >"$TMP/invalid-path/apt-get" <<EOF
#!/bin/bash
printf 'called\n' >'$TMP/package-manager-called'
exit 99
EOF
chmod 0755 "$TMP/invalid-path/apt-get"
expect_rc 2 /usr/bin/env PATH="$TMP/invalid-path" /bin/bash "$ROOT/sun.sh" \
  --lang en --verify-signature off --version bad/value install --non-interactive
[[ ! -e "$TMP/package-manager-called" ]]
expect_rc 2 /usr/bin/env PATH="$TMP/invalid-path" /bin/bash "$ROOT/sun.sh" \
  --lang en --verify-signature off --repo invalid --version 1.0.0 install --non-interactive
[[ ! -e "$TMP/package-manager-called" ]]
expect_rc 2 /usr/bin/env PATH="$TMP/invalid-path" /bin/bash "$ROOT/sun.sh" \
  --lang en --verify-signature off --base-url http://invalid.example --version 1.0.0 install --non-interactive
[[ ! -e "$TMP/package-manager-called" ]]

mkdir -p "$TMP/microdnf-path"
for command in curl tar sha256sum mktemp python3 env uname timeout; do
  ln -s "$(command -v "$command")" "$TMP/microdnf-path/$command"
done
cat >"$TMP/microdnf-path/microdnf" <<'EOF'
#!/bin/bash
echo 'gpgme_engine_check_version() error: Invalid crypto engine' >&2
exit 1
EOF
chmod 0755 "$TMP/microdnf-path/microdnf"
expect_rc 1 /usr/bin/env PATH="$TMP/microdnf-path" /bin/bash "$ROOT/sun.sh" \
  --lang en --version 1.0.0 --base-url https://invalid.example install --non-interactive
grep -Fq 'restore gnupg2 from distribution rescue media or a trusted package cache' "$TMP/out"

set +e
printf '9\n2\n' | script -qefc \
  "bash '$ROOT/sun.sh' --verify-signature off --version bad/value install" /dev/null \
  >"$TMP/invalid-language" 2>&1
interactive_rc=$?
set -e
[[ "$interactive_rc" -eq 2 ]]
grep -Fq 'Invalid choice; enter 1 or 2.' "$TMP/invalid-language"
grep -Fq 'Invalid VERSION: bad/value' "$TMP/invalid-language"

set +e
timeout 10s script -qefc \
  "bash '$ROOT/sun.sh' --verify-signature off --version bad/value install" /dev/null \
  </dev/null >"$TMP/out" 2>&1
eof_rc=$?
set -e
[[ "$eof_rc" -eq 2 ]] || {
  cat "$TMP/out" >&2
  printf 'TTY EOF exit %s, expected 2\n' "$eof_rc" >&2
  exit 1
}
grep -Fq '已取消。' "$TMP/out"

python3 - "$ROOT/sun.sh" "$TMP/packages.sh" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
start = source.index("append_bootstrap_package() {")
end = source.index("\nparse_mirror_latest()", start)
Path(sys.argv[2]).write_text(source[start:end] + "\n", encoding="utf-8")
PY

# shellcheck source=/dev/null
source "$TMP/packages.sh"
resolve_bootstrap_packages rpm gpg
[[ "${BOOTSTRAP_PACKAGES[*]}" == 'ca-certificates gnupg2' ]]
resolve_bootstrap_packages rpm python3 gpg
[[ "${BOOTSTRAP_PACKAGES[*]}" == 'ca-certificates python3 gnupg2' ]]
resolve_bootstrap_packages apt curl tar sha256sum mktemp python3 env uname gpg timeout
[[ "${BOOTSTRAP_PACKAGES[*]}" == 'ca-certificates curl tar coreutils python3 gnupg' ]]

primary_fingerprints="$(gpg_primary_fingerprints <<'EOF'
pub:-:2048:1:0123456789ABCDEF:0:0::::::
fpr:::::::::PRIMARYFINGERPRINT:
uid:::::::::Release Key:
sub:-:2048:1:FEDCBA9876543210:0:0::::::
fpr:::::::::SUBKEYFINGERPRINT:
pub:-:2048:1:1111111111111111:0:0::::::
fpr:::::::::SECONDPRIMARY:
EOF
)"
[[ "$primary_fingerprints" == $'PRIMARYFINGERPRINT\nSECONDPRIMARY' ]]

gpg_status_has_pinned_signature PRIMARYPIN \
  <<<'[GNUPG:] VALIDSIG SUBKEY 20260726 0 0 0 0 0 PRIMARYPIN'
gpg_status_has_pinned_signature PRIMARYPIN \
  <<<'[GNUPG:] VALIDSIG PRIMARYPIN 20260726 0 0 0 0 0 OTHER'
if gpg_status_has_pinned_signature PRIMARYPIN \
    <<<'[GNUPG:] VALIDSIG WRONG 20260726 0 0 0 0 0 OTHER'; then
  echo 'GPG status parser accepted an unpinned signature' >&2
  exit 1
fi

mkdir -m 0700 "$TMP/gnupg"
gpg --batch --no-tty --homedir "$TMP/gnupg" \
  --import "$ROOT/files/release-signing.pub.asc" >/dev/null 2>&1
actual_primary_fingerprints="$(
  gpg --batch --no-tty --homedir "$TMP/gnupg" --with-colons --list-keys 2>/dev/null |
    gpg_primary_fingerprints
)"
[[ "$actual_primary_fingerprints" == C678256ACBFC6491BF5076655F3AE24999921FFC ]]

if grep -En '(^|[^[:alnum:]_])awk([[:space:]]|$)' "$ROOT/sun.sh" >"$TMP/awk-usage"; then
  cat "$TMP/awk-usage" >&2
  echo 'sun.sh unexpectedly depends on awk' >&2
  exit 1
fi

echo 'Bootstrap argument, TTY, and package-selection tests passed'
