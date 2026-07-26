#!/usr/bin/env bash
# Exercise the only remaining Bash archive validator against hostile tar metadata.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { [[ "${KEEP_TMP:-0}" == 1 ]] || rm -rf "$TMP"; }
trap cleanup EXIT

python3 - "$TMP" <<'PY'
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

python3 - "$ROOT/sun.sh" "$TMP" <<'PY'
import sys
from pathlib import Path

sun = Path(sys.argv[1]).read_text()
out = Path(sys.argv[2])

def extract(source, start_marker, end_marker):
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]

sun_function = extract(sun, "safe_extract_tar() {", "\nrelease_signing_public_key()",)
checksum_function = extract(sun, "verify_checksum() {", "\nsafe_extract_tar()",)
curl_functions = extract(sun, "curl_https() {", "\ntar_clean_env()",)

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
  if [[ \"${1:-}\" == --help ]]; then
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
PY
chmod +x "$TMP/sun-harness.sh" "$TMP/checksum-harness.sh" "$TMP/curl-retry-harness.sh"

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
grep -Fxq -- '--retry-all-errors' "$TMP/curl-all.args"
grep -Fxq -- '--retry' "$TMP/curl-all.args"
grep -Fxq -- '4' "$TMP/curl-all.args"
grep -Fxq -- '--retry-max-time' "$TMP/curl-all.args"
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

echo "sun.sh archive, checksum, and retry safety tests passed."
