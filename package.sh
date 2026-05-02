#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(grep -E '^VERSION=' files/security-update-notify | head -1 | cut -d'"' -f2)"
fi
[[ -n "$VERSION" ]] || { echo "Cannot determine version" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"
PKG="security-update-notify-$VERSION"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$ROOT"
bash -n install.sh menu.sh test.sh uninstall.sh package.sh sun.sh files/security-update-notify
[[ -f README.md ]] || { echo "README.md missing" >&2; exit 1; }
[[ -f README.en.md ]] || { echo "README.en.md missing" >&2; exit 1; }
[[ -f .env.example ]] || { echo ".env.example missing" >&2; exit 1; }
[[ -f CHANGELOG.md ]] || { echo "CHANGELOG.md missing" >&2; exit 1; }
[[ -f LICENSE ]] || { echo "LICENSE missing" >&2; exit 1; }
[[ -f files/security-update-notify.service ]] || { echo "service file missing" >&2; exit 1; }
[[ -f files/needrestart-report-only.conf ]] || { echo "needrestart config missing" >&2; exit 1; }
[[ -f files/security-update-notify.logrotate ]] || { echo "logrotate file missing" >&2; exit 1; }

mkdir -p "$WORK/$PKG" "$DIST"
rm -f "$DIST"/security-update-notify-*.tar.gz "$DIST"/security-update-notify-*.tar.gz.sha256
tar -C "$ROOT" \
  --exclude='./.git' \
  --exclude='./.github' \
  --exclude='./dist' \
  --exclude='./*.tar.gz' \
  --exclude='./*.sha256' \
  --exclude='./.env' \
  --exclude='./.env.*' \
  --exclude='*.bak' \
  --exclude='*.tmp' \
  --exclude='./*~' \
  --exclude='./.DS_Store' \
  --exclude='./.vscode' \
  --exclude='./.idea' \
  --exclude='./.cache' \
  --exclude='./README-longlan.md' \
  --exclude='./.gitignore' \
  --exclude='./package.sh' \
  --exclude='./sun.sh' \
  -cf - . | tar -C "$WORK/$PKG" --strip-components=1 -xf -
cp "$ROOT/.env.example" "$WORK/$PKG/.env.example"

# Normalize executable permissions.
chmod 0755 "$WORK/$PKG"/*.sh "$WORK/$PKG/files/security-update-notify"
chmod 0644 "$WORK/$PKG/README.md" "$WORK/$PKG/README.en.md" "$WORK/$PKG/CHANGELOG.md" "$WORK/$PKG/LICENSE" "$WORK/$PKG/files/security-update-notify.service" "$WORK/$PKG/files/needrestart-report-only.conf" "$WORK/$PKG/files/security-update-notify.logrotate"
[[ -f "$WORK/$PKG/.env.example" ]] && chmod 0644 "$WORK/$PKG/.env.example"

# Safety: release package must not contain local runtime config/state files.
if find "$WORK/$PKG" -type f \( -name '.env' -o -name '.env.*' ! -name '.env.example' -o -name 'telegram.env' -o -name '*.log' -o -name 'last-alert*' \) | grep -q .; then
  echo "Refusing to package runtime config/state files" >&2
  find "$WORK/$PKG" -type f \( -name '.env' -o -name '.env.*' ! -name '.env.example' -o -name 'telegram.env' -o -name '*.log' -o -name 'last-alert*' \) >&2
  exit 1
fi

TAR="$DIST/$PKG.tar.gz"
SHA="$TAR.sha256"
SOURCE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}"
tar -C "$WORK" --sort=name --mtime="@$SOURCE_EPOCH" --owner=0 --group=0 --numeric-owner -cf - "$PKG" | gzip -n >"$TAR"
(cd "$DIST" && sha256sum "$PKG.tar.gz" >"$PKG.tar.gz.sha256")

printf 'Created:\n  %s\n  %s\n' "$TAR" "$SHA"
cat "$SHA"
