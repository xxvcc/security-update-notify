#!/usr/bin/env bash
set -euo pipefail

# Bootstrap installer for security-update-notify.
# Publish this script on your website, e.g. https://example.com/install/sun.sh

REPO="${SECURITY_UPDATE_NOTIFY_REPO:-xxvcc/security-update-notify}"
VERSION="${SECURITY_UPDATE_NOTIFY_VERSION:-latest}"
BASE_URL="${SECURITY_UPDATE_NOTIFY_BASE_URL:-}"
RUN_MODE="menu"
INSTALL_ARGS=()

usage() {
  cat <<'EOF'
Usage:
  curl -fsSL https://example.com/install/sun.sh | sudo bash
  curl -fsSL https://example.com/install/sun.sh | sudo bash -s -- install [install args]

Bootstrap options:
  --version VERSION       Release version, e.g. 1.1.0. Default: latest
  --repo OWNER/REPO       GitHub repo. Default from script config
  --base-url URL          Override download base URL
  install                 Run install.sh after download
  test                    Run test.sh after download
  uninstall               Run uninstall.sh after download
  menu                    Run menu.sh after download (default)

All remaining options are passed to the selected script.
EOF
}

require_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || { echo "Missing value for $1" >&2; exit 2; }; }
validate_version() { [[ "$1" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || { echo "Invalid VERSION: $1" >&2; exit 2; }; }

verify_checksum() {
  local file="$1" sha_file="$2" expected
  expected="$(awk 'NF {print $1; exit}' "$sha_file")"
  [[ "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || { echo "Invalid checksum file: $SHA_URL" >&2; exit 1; }
  printf '%s  %s\n' "$expected" "$file" | sha256sum -c -
}

safe_extract_tar() {
  local archive="$1" topdir="$2" entry
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    case "$entry" in
      /*|../*|*/../*|*/..|..)
        echo "Unsafe path in archive: $entry" >&2
        exit 1
        ;;
    esac
    case "$entry" in
      "$topdir"|"$topdir/"|"$topdir"/*) ;;
      *)
        echo "Unexpected path in archive: $entry" >&2
        exit 1
        ;;
    esac
  done < <(tar -tzf "$archive")
  tar --no-same-owner -xzf "$archive"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) require_arg "$1" "${2:-}"; VERSION="$2"; shift 2 ;;
    --repo) require_arg "$1" "${2:-}"; REPO="$2"; shift 2 ;;
    --base-url) require_arg "$1" "${2:-}"; BASE_URL="$2"; shift 2 ;;
    install|test|uninstall|menu) RUN_MODE="$1"; shift; INSTALL_ARGS+=("$@"); break ;;
    -h|--help) usage; exit 0 ;;
    *) INSTALL_ARGS+=("$1"); shift ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "Please run with sudo/root" >&2; exit 1; }
for c in curl tar sha256sum mktemp python3; do command -v "$c" >/dev/null 2>&1 || { echo "Missing required command: $c" >&2; exit 1; }; done

[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "Invalid REPO format: $REPO" >&2; exit 2; }

if [[ "$VERSION" == "latest" ]]; then
  [[ "$REPO" != "YOUR_GITHUB_USER/security-update-notify" ]] || { echo "Set SECURITY_UPDATE_NOTIFY_REPO or edit bootstrap REPO before publishing." >&2; exit 2; }
  api="https://api.github.com/repos/${REPO}/releases/latest"
  VERSION="$(curl -fsSL "$api" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))')"
fi
validate_version "$VERSION"

PKG="security-update-notify-${VERSION}.tar.gz"
PKG_DIR="security-update-notify-${VERSION}"
if [[ -n "$BASE_URL" ]]; then
  URL="${BASE_URL%/}/${PKG}"
  SHA_URL="${URL}.sha256"
else
  [[ "$REPO" != "YOUR_GITHUB_USER/security-update-notify" ]] || { echo "Set SECURITY_UPDATE_NOTIFY_REPO or edit bootstrap REPO before publishing." >&2; exit 2; }
  URL="https://github.com/${REPO}/releases/download/v${VERSION}/${PKG}"
  SHA_URL="${URL}.sha256"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
echo "Downloading $URL"
curl -fL --retry 3 -o "$PKG" "$URL"
curl -fL --retry 3 -o "$PKG.sha256" "$SHA_URL"
verify_checksum "$PKG" "$PKG.sha256"
safe_extract_tar "$PKG" "$PKG_DIR"
cd "$PKG_DIR"

# When invoked as `curl ... | sudo bash`, stdin is the script stream, not the
# user terminal. Do not run a standalone `exec < /dev/tty` here: bash would then
# start reading the remaining bootstrap script from the terminal and appear to
# hang after checksum verification. Redirect stdin only on the final exec.
run_target() {
  local script="$1"; shift
  if [[ -r /dev/tty ]]; then
    exec "$script" "$@" < /dev/tty
  fi
  if [[ "$script" == "./menu.sh" && ! -t 0 ]]; then
    echo "No interactive terminal is available for the menu." >&2
    echo "Run a non-interactive mode, for example: bash sun.sh install --non-interactive -y ..." >&2
    exit 2
  fi
  exec "$script" "$@"
}

case "$RUN_MODE" in
  menu) run_target ./menu.sh "${INSTALL_ARGS[@]}" ;;
  install) run_target ./install.sh "${INSTALL_ARGS[@]}" ;;
  test) exec ./test.sh "${INSTALL_ARGS[@]}" ;;
  uninstall) run_target ./uninstall.sh "${INSTALL_ARGS[@]}" ;;
  *) echo "Invalid mode: $RUN_MODE" >&2; exit 2 ;;
esac
