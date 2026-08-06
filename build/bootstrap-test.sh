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

expect_rc 1 /bin/bash "$ROOT/sun.sh" --verify-signature off --version bad/value install --lang en --non-interactive
grep -Fq 'sun.sh requires Bash privileged mode' "$TMP/out"

expect_rc 2 /bin/bash -p "$ROOT/sun.sh" --verify-signature off --version bad/value install --lang en --non-interactive
grep -Fq 'Invalid VERSION: bad/value' "$TMP/out"

expect_rc 2 /bin/bash -p "$ROOT/sun.sh" --lang en --verify-signature off --version bad/value install --non-interactive
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
expect_rc 2 /usr/bin/env PATH="$TMP/invalid-path" /bin/bash -p "$ROOT/sun.sh" \
  --lang en --verify-signature off --version bad/value install --non-interactive
[[ ! -e "$TMP/package-manager-called" ]]
expect_rc 2 /usr/bin/env PATH="$TMP/invalid-path" /bin/bash -p "$ROOT/sun.sh" \
  --lang en --verify-signature off --repo invalid --version 1.0.0 install --non-interactive
[[ ! -e "$TMP/package-manager-called" ]]
expect_rc 2 /usr/bin/env PATH="$TMP/invalid-path" /bin/bash -p "$ROOT/sun.sh" \
  --lang en --verify-signature off --base-url http://invalid.example --version 1.0.0 install --non-interactive
[[ ! -e "$TMP/package-manager-called" ]]

mkdir -p "$TMP/microdnf-path"
for command in curl tar sha256sum mktemp python3 env uname timeout wc; do
  ln -s "$(command -v "$command")" "$TMP/microdnf-path/$command"
done
cat >"$TMP/microdnf-path/microdnf" <<'EOF'
#!/bin/bash
echo 'gpgme_engine_check_version() error: Invalid crypto engine' >&2
exit 1
EOF
chmod 0755 "$TMP/microdnf-path/microdnf"
# Production ignores caller PATH. Patch only this disposable copy's fixed path
# so the dependency-recovery branch can still be exercised without replacing
# host commands.
sed "s|^readonly SYSTEM_PATH=.*|readonly SYSTEM_PATH='$TMP/microdnf-path'|" \
  "$ROOT/sun.sh" >"$TMP/microdnf-sun.sh"
expect_rc 1 /bin/bash -p "$TMP/microdnf-sun.sh" \
  --lang en --version 1.0.0 --base-url https://invalid.example install --non-interactive
grep -Fq 'restore gnupg2 from distribution rescue media or a trusted package cache' "$TMP/out"

set +e
printf '9\n2\n' | script -qefc \
  "/bin/bash -p '$ROOT/sun.sh' --verify-signature off --version bad/value install" /dev/null \
  >"$TMP/invalid-language" 2>&1
interactive_rc=$?
set -e
[[ "$interactive_rc" -eq 2 ]]
grep -Fq 'Invalid choice; enter 1 or 2.' "$TMP/invalid-language"
grep -Fq 'Invalid VERSION: bad/value' "$TMP/invalid-language"

set +e
timeout 10s script -qefc \
  "/bin/bash -p '$ROOT/sun.sh' --verify-signature off --version bad/value install" /dev/null \
  </dev/null >"$TMP/out" 2>&1
eof_rc=$?
set -e
[[ "$eof_rc" -eq 2 ]] || {
  cat "$TMP/out" >&2
  printf 'TTY EOF exit %s, expected 2\n' "$eof_rc" >&2
  exit 1
}
grep -Fq '已取消。' "$TMP/out"

python3 -I - "$ROOT/sun.sh" "$TMP/packages.sh" <<'PY'
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
resolve_bootstrap_packages apt curl tar sha256sum mktemp python3 env uname gpg timeout wc
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

gpg_status_has_pinned_signature PRIMARYPIN <<'EOF'
[GNUPG:] GOODSIG KEYID signer
[GNUPG:] VALIDSIG SUBKEY 20260726 0 0 0 0 0 PRIMARYPIN
EOF
gpg_status_has_pinned_signature PRIMARYPIN <<'EOF'
[GNUPG:] GOODSIG KEYID signer
[GNUPG:] VALIDSIG PRIMARYPIN 20260726 0 0 0 0 0 OTHER
EOF
if gpg_status_has_pinned_signature PRIMARYPIN \
    <<EOF
[GNUPG:] GOODSIG KEYID signer
[GNUPG:] VALIDSIG WRONG 20260726 0 0 0 0 0 OTHER
EOF
then
  echo 'GPG status parser accepted an unpinned signature' >&2
  exit 1
fi
if gpg_status_has_pinned_signature PRIMARYPIN \
    <<<'[GNUPG:] VALIDSIG PRIMARYPIN 20260726 0 0 0 0 0 PRIMARYPIN'; then
  echo 'GPG status parser accepted VALIDSIG without GOODSIG' >&2
  exit 1
fi
for outcome in EXPSIG EXPKEYSIG REVKEYSIG BADSIG ERRSIG; do
  if gpg_status_has_pinned_signature PRIMARYPIN <<EOF
[GNUPG:] $outcome KEYID signer
[GNUPG:] VALIDSIG PRIMARYPIN 20260726 0 0 0 0 0 PRIMARYPIN
EOF
  then
    echo "GPG status parser accepted disqualifying outcome: $outcome" >&2
    exit 1
  fi
done
if gpg_status_has_pinned_signature PRIMARYPIN <<'EOF'
[GNUPG:] GOODSIG KEYID signer
[GNUPG:] VALIDSIG PRIMARYPIN 20260726 0 0 0 0 0 OTHER
[GNUPG:] GOODSIG KEYID signer
[GNUPG:] VALIDSIG SUBKEY 20260726 0 0 0 0 0 PRIMARYPIN
EOF
then
  echo 'GPG status parser accepted multiple valid signatures' >&2
  exit 1
fi

# Exercise the status contract with real GnuPG. Two individually valid armored
# detached signatures can be concatenated; GnuPG verifies both and exits zero,
# but the bootstrap must reject the ambiguous multi-signature asset.
real_home="$TMP/real-signature-gnupg"
mkdir -m 0700 "$real_home"
gpg --no-options --batch --no-tty --homedir "$real_home" \
  --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'bootstrap real signature <bootstrap-real@example.invalid>' \
  ed25519 sign 0 >/dev/null 2>&1
real_fingerprint="$(
  gpg --no-options --batch --no-tty --homedir "$real_home" --with-colons --list-keys 2>/dev/null |
    gpg_primary_fingerprints
)"
[[ -n "$real_fingerprint" && "$real_fingerprint" != *$'\n'* ]]
printf 'bootstrap signature parser fixture\n' >"$TMP/real-payload"
for signature in one two; do
  gpg --no-options --batch --no-tty --homedir "$real_home" \
    --pinentry-mode loopback --passphrase '' --armor --detach-sign \
    -o "$TMP/$signature.asc" "$TMP/real-payload"
done
real_status="$(
  gpg --no-options --batch --no-tty --homedir "$real_home" --status-fd=1 \
    --verify "$TMP/one.asc" "$TMP/real-payload" 2>"$TMP/real-gpg.log"
)"
gpg_status_has_pinned_signature "$real_fingerprint" <<<"$real_status"
{
  cat "$TMP/one.asc"
  printf '\n'
  cat "$TMP/two.asc"
} >"$TMP/two-valid-signatures.asc"
multi_status="$(
  gpg --no-options --batch --no-tty --homedir "$real_home" --status-fd=1 \
    --verify "$TMP/two-valid-signatures.asc" "$TMP/real-payload" 2>"$TMP/multi-gpg.log"
)"
[[ "$(grep -c '^\[GNUPG:\] GOODSIG ' <<<"$multi_status")" -eq 2 ]]
[[ "$(grep -c '^\[GNUPG:\] VALIDSIG ' <<<"$multi_status")" -eq 2 ]]
if gpg_status_has_pinned_signature "$real_fingerprint" <<<"$multi_status"; then
  echo 'GPG status parser accepted two concatenated valid detached signatures' >&2
  exit 1
fi

# GnuPG 2.2 emits EXPKEYSIG together with VALIDSIG and exits zero when the key
# has expired since signing. This real fixture ensures VALIDSIG cannot override
# the high-level expired-key result.
expired_home="$TMP/expired-signature-gnupg"
mkdir -m 0700 "$expired_home"
gpg --no-options --batch --no-tty --homedir "$expired_home" \
  --pinentry-mode loopback --passphrase '' --faked-system-time 20200101T000000 \
  --quick-generate-key 'bootstrap expired signature <bootstrap-expired@example.invalid>' \
  ed25519 sign 1d >/dev/null 2>&1
expired_fingerprint="$(
  gpg --no-options --batch --no-tty --homedir "$expired_home" --with-colons --list-keys 2>/dev/null |
    gpg_primary_fingerprints
)"
gpg --no-options --batch --no-tty --homedir "$expired_home" \
  --pinentry-mode loopback --passphrase '' --faked-system-time 20200101T010000 \
  --armor --detach-sign -o "$TMP/expired.asc" "$TMP/real-payload"
set +e
expired_status="$(
  gpg --no-options --batch --no-tty --homedir "$expired_home" --status-fd=1 \
    --verify "$TMP/expired.asc" "$TMP/real-payload" 2>"$TMP/expired-gpg.log"
)"
expired_rc=$?
set -e
[[ "$expired_rc" -eq 0 ]]
grep -q '^\[GNUPG:\] EXPKEYSIG ' <<<"$expired_status"
grep -q '^\[GNUPG:\] VALIDSIG ' <<<"$expired_status"
if gpg_status_has_pinned_signature "$expired_fingerprint" <<<"$expired_status"; then
  echo 'GPG status parser accepted a signature from an expired signing key' >&2
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

grep -Fxq 'readonly SYSTEM_PATH=/usr/sbin:/usr/bin:/sbin:/bin' "$ROOT/sun.sh"
grep -Fxq 'curl_https() { curl --disable --proto '\''=https'\'' --proto-redir '\''=https'\'' "$@"; }' "$ROOT/sun.sh"
grep -Fq 'gpg --no-options --batch --no-tty --homedir' "$ROOT/sun.sh"

# The privileged bootstrap must create its workspace under a fixed system base.
# Validate each opened component before using mkdirat through the checked base FD.
python3 -I - "$ROOT/sun.sh" "$TMP/trusted-temp-function.sh" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
start = source.index("create_trusted_temp_dir() {")
end = source.index("\n\nappend_bootstrap_package()", start)
Path(sys.argv[2]).write_text(source[start:end] + "\n", encoding="utf-8")
PY
# shellcheck source=/dev/null
source "$TMP/trusted-temp-function.sh"
trusted_temp_base="$TMP/trusted-temp-base"
attacker_temp_base="$TMP/attacker-temp-base"
mkdir -m 0700 "$trusted_temp_base" "$attacker_temp_base"
SYSTEM_TEMP_BASE="$trusted_temp_base"
export TMPDIR="$attacker_temp_base"
trusted_temp="$(create_trusted_temp_dir)"
[[ "$(dirname "$trusted_temp")" == "$trusted_temp_base" ]]
[[ "$(stat -c '%u:%a' "$trusted_temp")" == '0:700' ]]
[[ -z "$(find "$attacker_temp_base" -mindepth 1 -maxdepth 1 -print -quit)" ]]
rm -rf -- "$trusted_temp"

unsafe_ancestor="$TMP/unsafe-temp-ancestor"
mkdir -m 0700 "$unsafe_ancestor"
mkdir -m 0700 "$unsafe_ancestor/base"
chmod 0777 "$unsafe_ancestor"
SYSTEM_TEMP_BASE="$unsafe_ancestor/base"
if create_trusted_temp_dir >"$TMP/unsafe-temp.out" 2>&1; then
  echo 'sun.sh accepted a group/other-writable non-sticky temporary ancestor' >&2
  exit 1
fi
grep -Fq 'group/other-writable without the sticky bit' "$TMP/unsafe-temp.out"

sticky_ancestor="$TMP/sticky-temp-ancestor"
mkdir -m 0700 "$sticky_ancestor"
mkdir -m 0700 "$sticky_ancestor/base"
chmod 1777 "$sticky_ancestor"
SYSTEM_TEMP_BASE="$sticky_ancestor/base"
sticky_temp="$(create_trusted_temp_dir)"
[[ "$(dirname "$sticky_temp")" == "$sticky_ancestor/base" ]]
rm -rf -- "$sticky_temp"

real_temp_base="$TMP/real-temp-base"
mkdir -m 0700 "$real_temp_base"
ln -s "$real_temp_base" "$TMP/symlink-temp-base"
SYSTEM_TEMP_BASE="$TMP/symlink-temp-base"
if create_trusted_temp_dir >"$TMP/symlink-temp.out" 2>&1; then
  echo 'sun.sh followed a symlink temporary-path component' >&2
  exit 1
fi

if (( EUID == 0 )); then
  untrusted_temp_base="$TMP/untrusted-owner-temp-base"
  mkdir -m 0700 "$untrusted_temp_base"
  chown 65534:65534 "$untrusted_temp_base"
  # shellcheck disable=SC2034 # Consumed by the dynamically sourced helper.
  SYSTEM_TEMP_BASE="$untrusted_temp_base"
  if create_trusted_temp_dir >"$TMP/untrusted-owner-temp.out" 2>&1; then
    echo 'sun.sh accepted a temporary base not owned by root' >&2
    exit 1
  fi
  grep -Fq 'is not owned by root' "$TMP/untrusted-owner-temp.out"
fi

grep -Fxq 'readonly SYSTEM_TEMP_BASE=/var/tmp' "$ROOT/sun.sh"
grep -Fq 'os.open(component, flags, dir_fd=current_fd)' "$ROOT/sun.sh"
grep -Fq 'os.mkdir(name, 0o700, dir_fd=current_fd)' "$ROOT/sun.sh"
# shellcheck disable=SC2016 # Match the literal command substitution in sun.sh.
grep -Fq 'TMP="$(create_trusted_temp_dir)"' "$ROOT/sun.sh"
# shellcheck disable=SC2016 # Reject the old literal mktemp command substitution.
if grep -Fq 'TMP="$(mktemp -d)"' "$ROOT/sun.sh"; then
  echo 'sun.sh still creates its privileged workspace with path-resolved mktemp' >&2
  exit 1
fi

# Privileged mode must suppress Bash startup hooks before sun.sh executes. The
# remaining environment is then reduced before any package or download helper
# runs, while the explicit UI language and proxy remain available.
cat >"$TMP/bash-env" <<EOF
: >"$TMP/bash-env-called"
EOF
mkdir -p "$TMP/clean-path"
for command in tar sha256sum mktemp python3 env uname timeout wc rm mv; do
  ln -s "$(command -v "$command")" "$TMP/clean-path/$command"
done
cat >"$TMP/clean-path/curl" <<EOF
#!/bin/bash
set -eu
if [[ "\${1:-}" == --disable && "\${2:-}" == --help ]]; then
  exit 0
fi
{
  printf 'UI_LANG=%s\n' "\${UI_LANG-unset}"
  printf 'https_proxy=%s\n' "\${https_proxy-unset}"
  printf 'BASH_ENV=%s\n' "\${BASH_ENV-unset}"
  printf 'LD_PRELOAD=%s\n' "\${LD_PRELOAD-unset}"
  printf 'APT_CONFIG=%s\n' "\${APT_CONFIG-unset}"
  printf 'PYTHONPATH=%s\n' "\${PYTHONPATH-unset}"
  printf 'PATH=%s\n' "\${PATH-unset}"
  printf 'readonly_type=%s\n' "\$(type -t readonly)"
} >"$TMP/clean-env"
case "\${!#}" in
  */latest.json)
    printf '%s\n' '{"version":"9.9.9","tag":"v9.9.9","base_url":"https://dl.ll.cd/security-update-notify/v9.9.9"}'
    ;;
  *) exit 22 ;;
esac
EOF
chmod 0755 "$TMP/clean-path/curl"
sed "s|^readonly SYSTEM_PATH=.*|readonly SYSTEM_PATH='$TMP/clean-path'|" \
  "$ROOT/sun.sh" >"$TMP/clean-env-sun.sh"

hostile_environment=(
  UI_LANG=en
  https_proxy=http://proxy.example.invalid:8080
  "BASH_ENV=$TMP/bash-env"
  "LD_PRELOAD=$TMP/not-a-library.so"
  "APT_CONFIG=$TMP/apt.conf"
  "PYTHONPATH=$TMP/python"
  "PATH=$TMP/invalid-path"
  "BASH_FUNC_builtin%%=() { : >\"$TMP/function-called\"; return 97; }"
  "BASH_FUNC_readonly%%=() { : >\"$TMP/function-called\"; return 97; }"
  "BASH_FUNC_mapfile%%=() { : >\"$TMP/function-called\"; return 97; }"
  "BASH_FUNC_command%%=() { : >\"$TMP/function-called\"; return 97; }"
  "BASH_FUNC_exec%%=() { : >\"$TMP/function-called\"; return 97; }"
  "BASH_FUNC_exit%%=() { : >\"$TMP/function-called\"; return 97; }"
  "BASH_FUNC_unset%%=() { : >\"$TMP/function-called\"; return 97; }"
)
expect_rc 1 /usr/bin/env "${hostile_environment[@]}" \
  /bin/bash -p "$TMP/clean-env-sun.sh" \
    --lang en --verify-signature off install --non-interactive
grep -Fq 'All release download sources failed.' "$TMP/out"
[[ ! -e "$TMP/bash-env-called" && ! -e "$TMP/function-called" ]]
grep -Fxq 'UI_LANG=en' "$TMP/clean-env"
grep -Fxq 'https_proxy=http://proxy.example.invalid:8080' "$TMP/clean-env"
grep -Fxq 'BASH_ENV=unset' "$TMP/clean-env"
grep -Fxq 'LD_PRELOAD=unset' "$TMP/clean-env"
grep -Fxq 'APT_CONFIG=unset' "$TMP/clean-env"
grep -Fxq 'PYTHONPATH=unset' "$TMP/clean-env"
grep -Fxq "PATH=$TMP/clean-path" "$TMP/clean-env"
grep -Fxq 'readonly_type=builtin' "$TMP/clean-env"

expect_rc 1 /usr/bin/env "${hostile_environment[@]}" \
  /bin/bash -p -s -- --lang en --verify-signature off install --non-interactive \
  <"$TMP/clean-env-sun.sh"
grep -Fq 'All release download sources failed.' "$TMP/out"
[[ ! -e "$TMP/bash-env-called" && ! -e "$TMP/function-called" ]]
grep -Fxq 'BASH_ENV=unset' "$TMP/clean-env"
grep -Fxq 'LD_PRELOAD=unset' "$TMP/clean-env"

echo 'Bootstrap argument, TTY, and package-selection tests passed'
