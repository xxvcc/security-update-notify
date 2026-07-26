#!/usr/bin/env bash
# Public-release canary for disposable GitHub-hosted Ubuntu runners only.
set -euo pipefail

die() {
  echo "live canary: $*" >&2
  exit 1
}

[[ "${GITHUB_ACTIONS:-}" == "true" && "${RUNNER_ENVIRONMENT:-}" == "github-hosted" ]] ||
  die "refusing to run outside a GitHub-hosted runner"
[[ "$(id -u)" -eq 0 ]] || die "root is required"
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || die "RUNNER_TEMP is unavailable"
[[ "${GITHUB_REPOSITORY:-}" == "xxvcc/security-update-notify" ]] ||
  die "unexpected repository: ${GITHUB_REPOSITORY:-unset}"

# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" =~ ^(22\.04|24\.04)$ ]] ||
  die "unsupported canary host: ${PRETTY_NAME:-unknown}"

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin="C678256ACBFC6491BF5076655F3AE24999921FFC"
bootstrap_version_notation="release-version@xxv.cc"
mirror_root="https://dl.ll.cd/security-update-notify"
work="$(mktemp -d "$RUNNER_TEMP/security-update-notify-canary.XXXXXX")"
cleanup_failed=0

cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  if [[ -x /usr/local/sbin/security-update-notify ]]; then
    if ! /usr/local/sbin/security-update-notify uninstall --purge-config --lang en; then
      cleanup_failed=1
    fi
  fi
  rm -rf "$work"
  if [[ "$rc" -eq 0 && "$cleanup_failed" -ne 0 ]]; then
    rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT

for command in apt-get curl dpkg gpg gh head jq python3 sha256sum stat systemctl systemd-analyze tar timeout; do
  command -v "$command" >/dev/null 2>&1 || die "missing command: $command"
done
[[ ! -e /usr/local/sbin/security-update-notify ]] || die "runner is not clean: SUN is already installed"
[[ ! -e /etc/security-update-notify ]] || die "runner is not clean: SUN config already exists"

apt_policy=/etc/apt/apt.conf.d/20auto-upgrades
apt_policy_was_present=0
if [[ -e "$apt_policy" || -L "$apt_policy" ]]; then
  [[ -f "$apt_policy" && ! -L "$apt_policy" ]] || die "unexpected APT policy node"
  apt_policy_was_present=1
  cp --preserve=all "$apt_policy" "$work/apt-policy.before"
fi

capture_bounded_rc() {
  local output="$1"
  shift
  local rc
  set +e
  timeout --signal=TERM --kill-after=5s 60s "$@" 2>&1 | head -c 65536 >"$output"
  rc="${PIPESTATUS[0]}"
  set -e
  printf '%s\n' "$rc"
}

apt_check_before_rc="$(capture_bounded_rc "$work/apt-check.before" apt-get check -qq)"
dpkg_audit_before_rc="$(capture_bounded_rc "$work/dpkg-audit.before" dpkg --audit)"
dpkg_audit_before_clean=0
if [[ "$dpkg_audit_before_rc" -eq 0 && ! -s "$work/dpkg-audit.before" ]]; then
  dpkg_audit_before_clean=1
fi
if [[ "$apt_check_before_rc" -ne 0 ]]; then
  echo "NOTICE: hosted runner already fails apt-get check (rc=$apt_check_before_rc); output follows." >&2
  head -c 4096 "$work/apt-check.before" >&2
fi
if [[ "$dpkg_audit_before_clean" -ne 1 ]]; then
  echo "NOTICE: hosted runner already has a non-clean dpkg audit (rc=$dpkg_audit_before_rc); output follows." >&2
  head -c 4096 "$work/dpkg-audit.before" >&2
fi
echo "Canary patch-maintenance diagnostics are isolated from hosted-runner history; package consistency remains gated against the pre-install baseline."

assert_package_state_not_regressed() {
  local phase="$1"
  local apt_output="$work/apt-check.$phase"
  local dpkg_output="$work/dpkg-audit.$phase"
  local apt_rc dpkg_rc
  apt_rc="$(capture_bounded_rc "$apt_output" apt-get check -qq)"
  dpkg_rc="$(capture_bounded_rc "$dpkg_output" dpkg --audit)"
  if [[ "$apt_check_before_rc" -eq 0 && "$apt_rc" -ne 0 ]]; then
    head -c 4096 "$apt_output" >&2
    die "SUN changed a clean apt-get check baseline into a failure during $phase"
  fi
  if [[ "$dpkg_audit_before_clean" -eq 1 && ( "$dpkg_rc" -ne 0 || -s "$dpkg_output" ) ]]; then
    head -c 4096 "$dpkg_output" >&2
    die "SUN changed a clean dpkg audit baseline during $phase"
  fi
}

curl_args=(
  --fail --silent --show-error --location
  --retry 4 --retry-all-errors --connect-timeout 15 --max-time 180
  --proto '=https' --proto-redir '=https'
)
cache_key="${GITHUB_RUN_ID:-manual}-$(date +%s)"
curl "${curl_args[@]}" --max-filesize 1048576 \
  --output "$work/latest.json" "$mirror_root/latest.json?canary=$cache_key"

jq -e '
  (keys | sort) == ["base_url", "published_at", "sha256", "signing_fingerprint", "tag", "version"] and
  (.version | type == "string") and (.tag | type == "string") and
  (.base_url | type == "string") and (.sha256 | type == "string") and
  (.signing_fingerprint | type == "string") and (.published_at | type == "string")
' "$work/latest.json" >/dev/null || die "invalid latest.json schema"

version="$(jq -r .version "$work/latest.json")"
tag="$(jq -r .tag "$work/latest.json")"
base_url="$(jq -r .base_url "$work/latest.json")"
manifest_sha="$(jq -r .sha256 "$work/latest.json")"
manifest_pin="$(jq -r .signing_fingerprint "$work/latest.json")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([._-][0-9A-Za-z]+)?$ && "${#version}" -le 64 ]] ||
  die "invalid version in latest.json"
[[ "$tag" == "v$version" ]] || die "latest tag/version mismatch"
[[ "$base_url" == "$mirror_root/$tag" ]] || die "unexpected mirror base URL"
[[ "$manifest_sha" =~ ^[0-9a-f]{64}$ ]] || die "invalid manifest checksum"
[[ "$manifest_pin" == "$pin" ]] || die "latest manifest signer mismatch"

github_latest="$(gh api "repos/$GITHUB_REPOSITORY/releases/latest" --jq .tag_name)"
[[ "$github_latest" == "$tag" ]] || die "mirror Latest $tag differs from GitHub Latest $github_latest"
release_json="$work/release.json"
gh api "repos/$GITHUB_REPOSITORY/releases/tags/$tag" >"$release_json"
release_immutable="$(jq -r .immutable "$release_json")"
if [[ "$release_immutable" != "true" && "$tag" != "v3.0.1" ]]; then
  die "release $tag is not immutable"
fi

archive="security-update-notify-$version.tar.gz"
bootstrap_signature_asset=""
if jq -e 'any(.assets[]; .name == "sun.sh.asc")' "$release_json" >/dev/null; then
  bootstrap_signature_asset="sun.sh.asc"
  jq -e --arg archive "$archive" '
    (.draft | not) and (.prerelease | not) and
    ([.assets[].name] | sort) ==
      ([$archive, ($archive + ".asc"), ($archive + ".sha256"), "sun.sh.asc"] | sort) and
    all(.assets[]; .state == "uploaded" and .size > 0)
  ' "$release_json" >/dev/null || die "GitHub release asset set is invalid"
else
  [[ "$tag" == "v3.0.1" ]] || die "release $tag has no signed first-install bootstrap"
  jq -e --arg archive "$archive" '
    (.draft | not) and (.prerelease | not) and
    ([.assets[].name] | sort) == ([$archive, ($archive + ".asc"), ($archive + ".sha256")] | sort) and
    all(.assets[]; .state == "uploaded" and .size > 0)
  ' "$release_json" >/dev/null || die "legacy GitHub release asset set is invalid"
fi

mkdir "$work/github" "$work/mirror"
github_base="https://github.com/$GITHUB_REPOSITORY/releases/download/$tag"
for suffix in "" .sha256 .asc; do
  asset="$archive$suffix"
  max_size=1048576
  [[ -z "$suffix" ]] && max_size=268435456
  curl "${curl_args[@]}" --max-filesize "$max_size" \
    --output "$work/github/$asset" "$github_base/$asset?canary=$cache_key"
  curl "${curl_args[@]}" --max-filesize "$max_size" \
    --output "$work/mirror/$asset" "$base_url/$asset?canary=$cache_key"
  cmp "$work/github/$asset" "$work/mirror/$asset" || die "GitHub/mirror mismatch: $asset"
done
if [[ -n "$bootstrap_signature_asset" ]]; then
  curl "${curl_args[@]}" --max-filesize 1048576 \
    --output "$work/github/$bootstrap_signature_asset" \
    "$github_base/$bootstrap_signature_asset?canary=$cache_key"
  curl "${curl_args[@]}" --max-filesize 1048576 \
    --output "$work/mirror/$bootstrap_signature_asset" \
    "$base_url/$bootstrap_signature_asset?canary=$cache_key"
  cmp "$work/github/$bootstrap_signature_asset" "$work/mirror/$bootstrap_signature_asset" ||
    die "GitHub/mirror mismatch: $bootstrap_signature_asset"
fi

[[ "$(wc -l <"$work/mirror/$archive.sha256")" -eq 1 ]] || die "invalid checksum manifest line count"
read -r expected_sha expected_name extra <"$work/mirror/$archive.sha256"
[[ "$expected_sha" == "$manifest_sha" && "$expected_name" == "$archive" && -z "${extra:-}" ]] ||
  die "checksum manifest is not bound to latest.json"
actual_sha="$(sha256sum "$work/mirror/$archive" | awk '{print $1}')"
[[ "$actual_sha" == "$expected_sha" ]] || die "release checksum mismatch"

export GNUPGHOME="$work/gnupg"
install -d -m 0700 "$GNUPGHOME"
gpg --batch --import "$root_dir/files/release-signing.pub.asc" >/dev/null 2>&1
mapfile -t fingerprints < <(
  gpg --batch --with-colons --list-keys |
    awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }'
)
[[ "${#fingerprints[@]}" -eq 1 && "${fingerprints[0]}" == "$pin" ]] ||
  die "verification keyring does not contain exactly the pinned key"
status="$(gpg --batch --status-fd=1 --verify \
  "$work/mirror/$archive.asc" "$work/mirror/$archive" 2>"$work/gpg.log")" || {
  cat "$work/gpg.log" >&2
  die "release signature verification failed"
}
awk -v pin="$pin" '
  $1 == "[GNUPG:]" && $2 == "VALIDSIG" {
    valid_count++
    if ($3 == pin || $NF == pin) pinned_count++
  }
  END { exit !(valid_count == 1 && pinned_count == 1) }
' <<<"$status" || die "release signature is not uniquely bound to the pinned key"

python3 - "$work/mirror/$archive" "security-update-notify-$version/sun.sh" "$work/signed-sun.sh" <<'PY'
import pathlib
import sys
import tarfile

archive, member_name, output = sys.argv[1:]
with tarfile.open(archive, "r:gz") as bundle:
    matches = [member for member in bundle.getmembers() if member.name == member_name]
    if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 2 * 1024 * 1024:
        raise SystemExit("signed archive does not contain exactly one bounded regular sun.sh")
    stream = bundle.extractfile(matches[0])
    if stream is None:
        raise SystemExit("could not read signed sun.sh")
    pathlib.Path(output).write_bytes(stream.read())
PY
curl "${curl_args[@]}" --max-filesize 2097152 \
  --output "$work/stable-sun.sh" "$mirror_root/sun.sh?canary=$cache_key"
cmp "$work/signed-sun.sh" "$work/stable-sun.sh" || die "stable bootstrap differs from signed release"
if [[ -n "$bootstrap_signature_asset" ]]; then
  curl "${curl_args[@]}" --max-filesize 2097152 \
    --output "$work/versioned-sun.sh" "$base_url/sun.sh?canary=$cache_key"
  curl "${curl_args[@]}" --max-filesize 1048576 \
    --output "$work/versioned-release-signing.pub.asc" \
    "$base_url/release-signing.pub.asc?canary=$cache_key"
  cmp "$work/signed-sun.sh" "$work/versioned-sun.sh" ||
    die "versioned bootstrap differs from signed release"
  cmp "$work/stable-sun.sh" "$work/versioned-sun.sh" ||
    die "stable bootstrap differs from versioned bootstrap"
  cmp "$root_dir/files/release-signing.pub.asc" "$work/versioned-release-signing.pub.asc" ||
    die "versioned verification key differs from the pinned source key"
  bootstrap_status="$(gpg --batch --known-notation "$bootstrap_version_notation" \
    --status-fd=1 --show-notation --verify \
    "$work/mirror/$bootstrap_signature_asset" "$work/stable-sun.sh" 2>"$work/bootstrap-gpg.log")" || {
    cat "$work/bootstrap-gpg.log" >&2
    die "bootstrap signature verification failed"
  }
  awk -v pin="$pin" -v notation="$bootstrap_version_notation" -v version="$version" '
    $1 == "[GNUPG:]" && $2 == "VALIDSIG" { valid_count++; if ($3 == pin || $NF == pin) pinned_count++ }
    $1 == "[GNUPG:]" && $2 == "NOTATION_NAME" { name_count++; if (NF == 3 && $3 == notation) name_match++ }
    $1 == "[GNUPG:]" && $2 == "NOTATION_FLAGS" { flags_count++; if (NF == 4 && $3 == 1 && $4 == 1) flags_match++ }
    $1 == "[GNUPG:]" && $2 == "NOTATION_DATA" { data_count++; if (NF == 3 && $3 == version) data_match++ }
    END { exit !(valid_count == 1 && pinned_count == 1 && name_count == 1 && name_match == 1 &&
                 flags_count == 1 && flags_match == 1 && data_count == 1 && data_match == 1) }
  ' <<<"$bootstrap_status" ||
    die "bootstrap signature is not uniquely bound to the pinned key and release version"
fi

echo "Installing public $tag on ${PRETTY_NAME} through the verified stable bootstrap"
canary_env="$work/canary-install.env"
telegram_token_file="$work/telegram.token"
install -m 0600 /dev/null "$canary_env"
install -m 0600 /dev/null "$telegram_token_file"
printf '%s\n' \
  'CHECK_UPDATE_HEALTH=0' \
  'STALE_UPDATE_DAYS=0' \
  'PENDING_ALERT_DAYS=0' \
  'RESTART_ALERT_DAYS=0' \
  'CHECK_EOL=0' \
  'CHECK_SELF_UPDATE=0' >"$canary_env"
printf '%s\n' '123456:canary_ABCDEFGHIJKLMNOPQRSTUVWXYZ' >"$telegram_token_file"
bash "$work/stable-sun.sh" \
  --lang en --version "$version" --base-url "$base_url" install \
  --env-file "$canary_env" \
  --notify-channels telegram \
  --telegram-token-file "$telegram_token_file" \
  --telegram-chat-id '-1001234567890' \
  --host-label "github-canary-${VERSION_ID}" \
  --include-public-ip 0 \
  --notify-ok 0 \
  --notify-upgrade 0 \
  --skip-notify-test \
  --skip-post-install-check \
  --non-interactive -y

[[ "$(/usr/local/sbin/security-update-notify --version)" == "security-update-notify $version" ]] ||
  die "installed version mismatch"
[[ "$(stat -c %U:%G:%a /usr/local/sbin/security-update-notify)" == "root:root:755" ]] ||
  die "installed runtime ownership or mode mismatch"
[[ "$(stat -c %U:%G:%a /etc/security-update-notify/telegram.env)" == "root:root:600" ]] ||
  die "installed config ownership or mode mismatch"
for expected in \
  "CHECK_UPDATE_HEALTH='0'" \
  "STALE_UPDATE_DAYS='0'" \
  "PENDING_ALERT_DAYS='0'" \
  "RESTART_ALERT_DAYS='0'" \
  "CHECK_EOL='0'" \
  "CHECK_SELF_UPDATE='0'"; do
  key="${expected%%=*}"
  matches="$(grep -c "^${key}=" /etc/security-update-notify/telegram.env || :)"
  [[ "$matches" -eq 1 ]] || die "installed canary isolation setting is not unique: $key"
  grep -qxF "$expected" /etc/security-update-notify/telegram.env ||
    die "installed canary isolation setting is missing: $key"
done
systemctl is-enabled --quiet security-update-notify.timer || die "timer is not enabled"
systemctl is-active --quiet security-update-notify.timer || die "timer is not active"
systemd-analyze verify \
  /etc/systemd/system/security-update-notify.service \
  /etc/systemd/system/security-update-notify.timer
/usr/local/sbin/security-update-notify doctor --skip-notify --lang en
assert_package_state_not_regressed after-install
dry_run_output="$(/usr/local/sbin/security-update-notify run \
  --test-reboot --no-dedupe --dry-run --wait-lock 0 --lang en)"
grep -q $'^HASH\t' <<<"$dry_run_output" || die "dry-run did not produce a stable hash"

/usr/local/sbin/security-update-notify uninstall --purge-config --lang en
[[ ! -e /usr/local/sbin/security-update-notify ]] || die "runtime remained after purge"
[[ ! -e /etc/security-update-notify ]] || die "config remained after purge"
[[ ! -e /var/lib/security-update-notify ]] || die "state remained after purge"
[[ ! -e /etc/systemd/system/security-update-notify.service ]] || die "service remained after purge"
[[ ! -e /etc/systemd/system/security-update-notify.timer ]] || die "timer remained after purge"
assert_package_state_not_regressed after-purge
if [[ "$apt_policy_was_present" -eq 1 ]]; then
  cmp "$work/apt-policy.before" "$apt_policy" || die "APT policy content was not restored"
  [[ "$(stat -c %U:%G:%a "$work/apt-policy.before")" == "$(stat -c %U:%G:%a "$apt_policy")" ]] ||
    die "APT policy metadata was not restored"
else
  [[ ! -e "$apt_policy" && ! -L "$apt_policy" ]] || die "originally absent APT policy was not removed"
fi

echo "Live public-release canary passed for $tag on ${PRETTY_NAME}"
