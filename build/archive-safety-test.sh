#!/usr/bin/env bash
# Exercise the only remaining Bash archive validator against hostile tar metadata.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { [[ "${KEEP_TMP:-0}" == 1 ]] || rm -rf "$TMP"; }
trap cleanup EXIT

python3 -I - "$TMP" <<'PY'
import gzip
import io
import sys
import tarfile
from pathlib import Path

root = Path(sys.argv[1])
top = "security-update-notify-9.9.9"

def archive(name, members):
    with tarfile.open(root / name, "w:gz") as tf:
        for info, data in members:
            tf.addfile(info, io.BytesIO(data) if data is not None else None)

def regular(name, data=b"ok"):
    info = tarfile.TarInfo(name)
    info.mode = 0o644
    info.size = len(data)
    return info, data

directory = tarfile.TarInfo(top)
directory.type = tarfile.DIRTYPE
directory.mode = 0o755
archive("valid.tar.gz", [(directory, None), regular(f"{top}/VERSION", b'VERSION="9.9.9"\n')])
archive("traversal.tar.gz", [regular(f"{top}/../escape")])
archive("unexpected.tar.gz", [regular("other/VERSION")])
link = tarfile.TarInfo(f"{top}/link")
link.type = tarfile.SYMTYPE
link.linkname = "/etc/shadow"
archive("symlink.tar.gz", [(link, None)])
archive("empty.tar.gz", [])

with tarfile.open(root / "many.tar.gz", "w:gz") as tf:
    for index in range(10001):
        info = tarfile.TarInfo(f"{top}/entry-{index}")
        info.size = 0
        tf.addfile(info, io.BytesIO())

oversized = tarfile.TarInfo(f"{top}/oversized")
oversized.size = 256 * 1024 * 1024 + 1
payload = oversized.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024
with gzip.open(root / "oversized.tar.gz", "wb") as fh:
    fh.write(payload)
PY

python3 -I - "$ROOT/sun.sh" "$ROOT/build/live-canary.sh" "$TMP" <<'PY'
import sys
from pathlib import Path

sun = Path(sys.argv[1]).read_text()
live_canary = Path(sys.argv[2]).read_text()
out = Path(sys.argv[3])

def extract(source, start_marker, end_marker):
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]

sun_function = extract(sun, "safe_extract_tar() {", "\nrelease_signing_public_key()",)
checksum_function = extract(sun, "verify_checksum() {", "\nsafe_extract_tar()",)
curl_functions = extract(sun, "curl_https() {", "\ntar_clean_env()",)
capture_function = extract(sun, "capture_limited() {", "\ntar_clean_env()",)
latest_functions = extract(sun, "parse_mirror_latest() {", "\nverify_checksum() {",)
canary_download_functions = extract(live_canary, "curl_args=(", "\ncache_key=",)

(out / "sun-harness.sh").write_text("""#!/usr/bin/env bash
set -euo pipefail
UI_LANG=en
say() { printf '%s\\n' \"$2\" >&2; }
tar_clean_env() { env -u TAR_OPTIONS -u GZIP -u BZIP2 -u XZ_OPT tar \"$@\"; }
""" + sun_function + "\ncd \"$3\"\nsafe_extract_tar \"$1\" \"$2\"\n")

(out / "checksum-harness.sh").write_text("""#!/usr/bin/env bash
set -euo pipefail
UI_LANG=en
say() { printf '%s\\n' \"$2\" >&2; }
""" + checksum_function + "\nverify_checksum \"$1\" \"$2\"\n")

(out / "curl-retry-harness.sh").write_text("""#!/usr/bin/env bash
set -euo pipefail
CURL_RETRY_OPTIONS=()
retry_help=\"$1\"
capture=\"$2\"
curl() {
  if [[ \"${1:-}\" == --disable && \"${2:-}\" == --help ]]; then
    case \"$retry_help\" in
      all-errors) printf '%s\\n' '     --retry-all-errors Retry all errors' ;;
      connrefused) printf '%s\\n' '     --retry-connrefused Retry on connection refused' ;;
      basic) printf '%s\\n' '     --retry <num> Retry request if transient problems occur' ;;
    esac
    return 0
  fi
  printf '%s\\n' \"$@\" >\"$capture\"
}
""" + curl_functions + "\nconfigure_curl_retry_options\ncurl_retry -f https://example.invalid/release\n")

(out / "download-limit-harness.sh").write_text("""#!/usr/bin/env bash
set -euo pipefail
CURL_RETRY_OPTIONS=()
curl() {
  printf '%s\\n' "$@" >"$FAKE_CURL_ARGS"
  python3 -I -c 'import os, sys; sys.stdout.buffer.write(b"x" * int(os.environ["FAKE_RESPONSE_BYTES"]))'
}
""" + curl_functions + "\ndownload_limited \"$1\" \"$2\" -fsL https://example.invalid/chunked\n")

(out / "capture-limit-harness.sh").write_text("""#!/usr/bin/env bash
set -euo pipefail
limit="$1"
output="$2"
duration="$3"
bytes="$4"
delay="$5"
""" + capture_function + """
capture_limited "$limit" "$output" "$duration" python3 -I -c '
import sys
import time
time.sleep(float(sys.argv[2]))
sys.stdout.buffer.write(b"x" * int(sys.argv[1]))
' "$bytes" "$delay"
""")

(out / "canary-download-limit-harness.sh").write_text("""#!/usr/bin/env bash
set -euo pipefail
curl() {
  printf '%s\\n' "$@" >"$FAKE_CURL_ARGS"
  python3 -I -c 'import os, sys; sys.stdout.buffer.write(b"x" * int(os.environ["FAKE_RESPONSE_BYTES"]))'
}
""" + canary_download_functions + "\ndownload_limited \"$1\" \"$2\" https://example.invalid/chunked\n")

(out / "latest-limit-harness.sh").write_text("""#!/usr/bin/env bash
set -euo pipefail
readonly MAX_METADATA_BYTES=256
RELEASE_MIRROR_BASE=https://mirror.example/releases
""" + latest_functions + """
case "$1" in
  mirror) parse_mirror_latest ;;
  github) parse_github_latest ;;
  *) exit 2 ;;
esac
""")
PY
chmod +x \
  "$TMP/sun-harness.sh" \
  "$TMP/checksum-harness.sh" \
  "$TMP/curl-retry-harness.sh" \
  "$TMP/download-limit-harness.sh" \
  "$TMP/capture-limit-harness.sh" \
  "$TMP/canary-download-limit-harness.sh" \
  "$TMP/latest-limit-harness.sh"

top=security-update-notify-9.9.9
mkdir "$TMP/extract"
"$TMP/sun-harness.sh" "$TMP/valid.tar.gz" "$top" "$TMP/extract"
[[ "$(cat "$TMP/extract/$top/VERSION")" == 'VERSION="9.9.9"' ]]

for archive in traversal unexpected symlink empty many oversized; do
  mkdir "$TMP/extract-$archive"
  if (cd "$TMP" && "$TMP/sun-harness.sh" "$TMP/$archive.tar.gz" "$top" "$TMP/extract-$archive") \
      >"$TMP/sun-$archive.out" 2>&1; then
    echo "sun.sh accepted hostile archive: $archive" >&2
    exit 1
  fi
  grep -Fq 'Archive safety check failed' "$TMP/sun-$archive.out"
done

mkdir "$TMP/checksum"
pkg=security-update-notify-9.9.9.tar.gz
printf 'trusted release bytes\n' >"$TMP/checksum/$pkg"
digest="$(sha256sum "$TMP/checksum/$pkg")"
digest="${digest%% *}"
printf '%s  %s\n' "$digest" "$pkg" >"$TMP/checksum/valid.sha256"
(
  cd "$TMP/checksum"
  "$TMP/checksum-harness.sh" "$pkg" valid.sha256
)

printf '%s  %s\n' "$digest" other.tar.gz >"$TMP/checksum/wrong-name.sha256"
printf '%s  %s\n%s  %s\n' "$digest" "$pkg" "$digest" other.tar.gz >"$TMP/checksum/multiple.sha256"
printf '%s %s\n' "$digest" "$pkg" >"$TMP/checksum/one-space.sha256"
printf '%s *%s\n' "$digest" "$pkg" >"$TMP/checksum/binary-marker.sha256"
printf '%s  %s' "$digest" "$pkg" >"$TMP/checksum/no-newline.sha256"
for checksum in wrong-name multiple one-space binary-marker no-newline; do
  if (
    cd "$TMP/checksum"
    "$TMP/checksum-harness.sh" "$pkg" "$checksum.sha256"
  ) >"$TMP/checksum-$checksum.out" 2>&1; then
    echo "sun.sh accepted malformed checksum file: $checksum" >&2
    exit 1
  fi
  grep -Fq 'Invalid checksum file' "$TMP/checksum-$checksum.out"
done

"$TMP/curl-retry-harness.sh" all-errors "$TMP/curl-all.args"
[[ "$(head -n 1 "$TMP/curl-all.args")" == '--disable' ]]
grep -Fxq -- '--retry-all-errors' "$TMP/curl-all.args"
grep -Fxq -- '--retry' "$TMP/curl-all.args"
grep -Fxq -- '4' "$TMP/curl-all.args"
grep -Fxq -- '--retry-max-time' "$TMP/curl-all.args"
grep -Fxq -- '--max-time' "$TMP/curl-all.args"
"$TMP/curl-retry-harness.sh" connrefused "$TMP/curl-connrefused.args"
grep -Fxq -- '--retry-connrefused' "$TMP/curl-connrefused.args"
if grep -Fxq -- '--retry-all-errors' "$TMP/curl-connrefused.args"; then
  echo "sun.sh enabled unsupported --retry-all-errors" >&2
  exit 1
fi
"$TMP/curl-retry-harness.sh" basic "$TMP/curl-basic.args"
if grep -Eq -- '^--retry-(all-errors|connrefused)$' "$TMP/curl-basic.args"; then
  echo "sun.sh enabled an unsupported curl retry extension" >&2
  exit 1
fi

printf '%s\n' '{"version":"9.9.9","tag":"v9.9.9","base_url":"https://mirror.example/releases/v9.9.9"}' |
  "$TMP/latest-limit-harness.sh" mirror >"$TMP/latest-mirror.out"
[[ "$(cat "$TMP/latest-mirror.out")" == 9.9.9 ]]
printf '%s\n' '{"tag_name":"v9.9.9"}' |
  "$TMP/latest-limit-harness.sh" github >"$TMP/latest-github.out"
[[ "$(cat "$TMP/latest-github.out")" == 9.9.9 ]]
for source in mirror github; do
  if python3 -I -c 'import sys; sys.stdout.buffer.write(b"x" * 257)' |
      "$TMP/latest-limit-harness.sh" "$source" >"$TMP/latest-$source-oversized.out" 2>&1; then
    echo "sun.sh accepted an oversized $source latest response" >&2
    exit 1
  fi
  grep -Fq 'exceeds size limit' "$TMP/latest-$source-oversized.out"
done

FAKE_CURL_ARGS="$TMP/download-exact.args" FAKE_RESPONSE_BYTES=16 \
  "$TMP/download-limit-harness.sh" 16 "$TMP/download-exact"
[[ "$(wc -c <"$TMP/download-exact")" -eq 16 ]]
grep -Fxq -- '--max-filesize' "$TMP/download-exact.args"
grep -Fxq -- '16' "$TMP/download-exact.args"

if FAKE_CURL_ARGS="$TMP/download-oversized.args" FAKE_RESPONSE_BYTES=17 \
    "$TMP/download-limit-harness.sh" 16 "$TMP/download-oversized" \
      >"$TMP/download-oversized.out" 2>&1; then
  echo "sun.sh accepted a chunked response beyond the download limit" >&2
  exit 1
fi
[[ ! -e "$TMP/download-oversized" ]]
[[ ! -e "$TMP/download-oversized.part" ]]

FAKE_CURL_ARGS="$TMP/canary-download-exact.args" FAKE_RESPONSE_BYTES=16 \
  "$TMP/canary-download-limit-harness.sh" 16 "$TMP/canary-download-exact"
[[ "$(wc -c <"$TMP/canary-download-exact")" -eq 16 ]]
grep -Fxq -- '--max-time' "$TMP/canary-download-exact.args"
grep -Fxq -- '--max-filesize' "$TMP/canary-download-exact.args"

if FAKE_CURL_ARGS="$TMP/canary-download-oversized.args" FAKE_RESPONSE_BYTES=17 \
    "$TMP/canary-download-limit-harness.sh" 16 "$TMP/canary-download-oversized" \
      >"$TMP/canary-download-oversized.out" 2>&1; then
  echo "live canary accepted a chunked response beyond the download limit" >&2
  exit 1
fi
[[ ! -e "$TMP/canary-download-oversized" ]]
[[ ! -e "$TMP/canary-download-oversized.part" ]]

"$TMP/capture-limit-harness.sh" 16 "$TMP/capture-exact" 2s 16 0
[[ "$(wc -c <"$TMP/capture-exact")" -eq 16 ]]
if "$TMP/capture-limit-harness.sh" 16 "$TMP/capture-oversized" 2s 17 0; then
  echo "sun.sh accepted command output beyond the capture limit" >&2
  exit 1
fi
[[ ! -e "$TMP/capture-oversized" && ! -e "$TMP/capture-oversized.part" ]]
if "$TMP/capture-limit-harness.sh" 16 "$TMP/capture-timeout" 0.2s 0 10; then
  echo "sun.sh accepted a command that exceeded the capture timeout" >&2
  exit 1
fi
[[ ! -e "$TMP/capture-timeout" && ! -e "$TMP/capture-timeout.part" ]]

[[ "$(grep -Fc "curl \"\${curl_args[@]}\"" "$ROOT/build/live-canary.sh")" -eq 1 ]]
grep -Fq -- '--disable --fail --silent --show-error --location' "$ROOT/build/live-canary.sh"
grep -Fq 'canary_install_started=0' "$ROOT/build/live-canary.sh"
# shellcheck disable=SC2016 # These assertions intentionally match literal shell variables.
grep -Fq 'if [[ "$canary_install_started" -eq 1 && -x /usr/local/sbin/security-update-notify ]]; then' \
  "$ROOT/build/live-canary.sh"
grep -Fq 'unset GH_TOKEN GITHUB_TOKEN' "$ROOT/build/live-canary.sh"
[[ "$(head -n 1 "$ROOT/sun.sh")" == '#!/bin/bash -p' ]]
# shellcheck disable=SC2016 # These assertions intentionally match literal shell variables.
[[ "$(grep -Fc 'exec -c /usr/bin/env -i "${sun_clean_env[@]}"' "$ROOT/sun.sh")" -eq 2 ]]
# shellcheck disable=SC2016 # The assertion intentionally matches literal shell variables.
grep -Fq '[[ "$outcome_count" -eq 1 && "$good_count" -eq 1' "$ROOT/sun.sh"
# shellcheck disable=SC2016 # The assertion intentionally matches literal shell variables.
grep -Fq '&& "$valid_count" -eq 1 && "$pinned_count" -eq 1 ]]' "$ROOT/sun.sh"
# shellcheck disable=SC2016 # The assertion intentionally matches literal shell variables.
grep -Fq 'gpg_status_has_pinned_signature "$RELEASE_SIGNING_FINGERPRINT" <<<"$status"' \
  "$ROOT/sun.sh"
grep -Fxq 'readonly MAX_METADATA_BYTES=1048576' "$ROOT/sun.sh"
grep -Fxq 'readonly MAX_ARCHIVE_BYTES=268435456' "$ROOT/sun.sh"
grep -Fq 'REQUIRED_COMMANDS=(curl tar sha256sum mktemp python3 env uname timeout wc)' "$ROOT/sun.sh"
grep -Fq 'TERM|TZ|http_proxy|https_proxy|no_proxy|all_proxy|HTTP_PROXY|HTTPS_PROXY|NO_PROXY|ALL_PROXY|PATH)' \
  "$ROOT/sun.sh"
# shellcheck disable=SC2016 # The assertion intentionally matches a literal shell variable.
grep -Fq 'builtin unset -f "$sun_name"' "$ROOT/sun.sh"
# shellcheck disable=SC2016 # The assertion intentionally matches literal shell variables.
grep -Fq 'capture_limited 4096 "$runtime_version_file" 15s "$GO_RUNTIME" --version' "$ROOT/sun.sh"

echo "sun.sh archive, checksum, and retry safety tests passed."
