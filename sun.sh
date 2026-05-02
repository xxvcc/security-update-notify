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

PKG="security-update-notify-${VERSION}.tar.gz"
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
sha256sum -c "$PKG.sha256"
tar -xzf "$PKG"
cd "security-update-notify-${VERSION}"

case "$RUN_MODE" in
  menu) exec ./menu.sh "${INSTALL_ARGS[@]}" ;;
  install) exec ./install.sh "${INSTALL_ARGS[@]}" ;;
  test) exec ./test.sh "${INSTALL_ARGS[@]}" ;;
  uninstall) exec ./uninstall.sh "${INSTALL_ARGS[@]}" ;;
  *) echo "Invalid mode: $RUN_MODE" >&2; exit 2 ;;
esac
