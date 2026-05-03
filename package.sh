#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(grep -E '^VERSION=' files/security-update-notify | head -1 | cut -d'"' -f2)"
fi
[[ -n "$VERSION" ]] || { echo "无法确定版本 / Cannot determine version" >&2; exit 1; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([._-][0-9A-Za-z]+)?$ ]] || { echo "无效版本 / Invalid version: $VERSION" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"
PKG="security-update-notify-$VERSION"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$ROOT"
bash -n install.sh menu.sh test.sh uninstall.sh package.sh sun.sh files/security-update-notify

ALLOW_DIRTY_PACKAGE="${ALLOW_DIRTY_PACKAGE:-0}"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if ! git diff --quiet HEAD -- install.sh menu.sh test.sh uninstall.sh package.sh sun.sh files/security-update-notify files/needrestart-report-only.conf files/security-update-notify.logrotate files/security-update-notify.service README.md README.en.md CHANGELOG.md LICENSE .env.example; then
    if [[ "$ALLOW_DIRTY_PACKAGE" == "1" && -n "${SOURCE_DATE_EPOCH:-}" ]]; then
      echo "警告：由于 ALLOW_DIRTY_PACKAGE=1 且 SOURCE_DATE_EPOCH 已设置，将打包未提交的发布文件改动。/ WARNING: packaging uncommitted tracked release-file changes because ALLOW_DIRTY_PACKAGE=1 and SOURCE_DATE_EPOCH is set." >&2
    else
      echo "拒绝在发布文件存在未提交改动时打包。/ Refusing to package with uncommitted tracked release-file changes." >&2
      echo "请先提交发布文件改动，或为本地测试构建设置 ALLOW_DIRTY_PACKAGE=1 和 SOURCE_DATE_EPOCH。/ Commit the release-file changes first, or set ALLOW_DIRTY_PACKAGE=1 with SOURCE_DATE_EPOCH for a local test build." >&2
      exit 1
    fi
  fi
fi
[[ -f README.md ]] || { echo "缺少 README.md / README.md missing" >&2; exit 1; }
[[ -f README.en.md ]] || { echo "缺少 README.en.md / README.en.md missing" >&2; exit 1; }
[[ -f .env.example ]] || { echo "缺少 .env.example / .env.example missing" >&2; exit 1; }
[[ -f CHANGELOG.md ]] || { echo "缺少 CHANGELOG.md / CHANGELOG.md missing" >&2; exit 1; }
[[ -f LICENSE ]] || { echo "缺少 LICENSE / LICENSE missing" >&2; exit 1; }
[[ -f files/security-update-notify.service ]] || { echo "缺少 service 文件 / service file missing" >&2; exit 1; }
[[ -f files/needrestart-report-only.conf ]] || { echo "缺少 needrestart 配置 / needrestart config missing" >&2; exit 1; }
[[ -f files/security-update-notify.logrotate ]] || { echo "缺少 logrotate 文件 / logrotate file missing" >&2; exit 1; }

mkdir -p "$WORK/$PKG/files" "$DIST"
rm -f "$DIST"/security-update-notify-*.tar.gz "$DIST"/security-update-notify-*.tar.gz.sha256

# 只复制明确允许进入发布包的文件，避免未跟踪的本地文件或维护笔记误入 release。
# Copy only explicitly allowed release files, preventing untracked local files or maintainer notes from leaking into releases.
for f in .env.example CHANGELOG.md LICENSE README.md README.en.md install.sh menu.sh test.sh uninstall.sh; do
  cp "$ROOT/$f" "$WORK/$PKG/$f"
done
for f in needrestart-report-only.conf security-update-notify security-update-notify.logrotate security-update-notify.service; do
  cp "$ROOT/files/$f" "$WORK/$PKG/files/$f"
done

# 规范化可执行权限。
# Normalize executable permissions.
chmod 0755 "$WORK/$PKG"/*.sh "$WORK/$PKG/files/security-update-notify"
chmod 0644 "$WORK/$PKG/.env.example" "$WORK/$PKG/README.md" "$WORK/$PKG/README.en.md" "$WORK/$PKG/CHANGELOG.md" "$WORK/$PKG/LICENSE" "$WORK/$PKG/files/security-update-notify.service" "$WORK/$PKG/files/needrestart-report-only.conf" "$WORK/$PKG/files/security-update-notify.logrotate"

# 安全检查：发布包不能包含本地运行配置或状态文件。
# Safety: release package must not contain local runtime config/state files.
if find "$WORK/$PKG" -type f \( -name '.env' -o -name '.env.*' ! -name '.env.example' -o -name 'telegram.env' -o -name '*.log' -o -name 'last-alert*' \) | grep -q .; then
  echo "拒绝打包运行时配置或状态文件 / Refusing to package runtime config/state files" >&2
  find "$WORK/$PKG" -type f \( -name '.env' -o -name '.env.*' ! -name '.env.example' -o -name 'telegram.env' -o -name '*.log' -o -name 'last-alert*' \) >&2
  exit 1
fi

TAR="$DIST/$PKG.tar.gz"
SHA="$TAR.sha256"
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_EPOCH="$SOURCE_DATE_EPOCH"
elif git rev-parse --verify "v$VERSION^{}" >/dev/null 2>&1; then
  SOURCE_EPOCH="$(git log -1 --format=%ct "v$VERSION^{}")"
elif git rev-parse --verify HEAD >/dev/null 2>&1; then
  SOURCE_EPOCH="$(git log -1 --format=%ct HEAD)"
else
  echo "无法确定 SOURCE_DATE_EPOCH；请显式设置。/ Cannot determine SOURCE_DATE_EPOCH; set it explicitly." >&2
  exit 1
fi
[[ "$SOURCE_EPOCH" =~ ^[0-9]+$ ]] || { echo "无效 SOURCE_DATE_EPOCH / Invalid SOURCE_DATE_EPOCH: $SOURCE_EPOCH" >&2; exit 1; }
tar -C "$WORK" --sort=name --mtime="@$SOURCE_EPOCH" --owner=0 --group=0 --numeric-owner -cf - "$PKG" | gzip -n >"$TAR"
(cd "$DIST" && sha256sum "$PKG.tar.gz" >"$PKG.tar.gz.sha256")

printf '已创建 / Created:\n  %s\n  %s\n' "$TAR" "$SHA"
cat "$SHA"
