# Changelog

## 1.1.1

Security and release-quality fixes.

- Fixed safe serialization of Telegram configuration values to prevent shell injection when sourced by root-run scripts.
- Fixed DNF backend reboot detection so `needs-restarting -r` non-zero exit does not abort notification logic.
- Ensured fresh installs install minimal Telegram preflight dependencies before validating token/chat ID.
- Improved uninstall cleanup for service, timer, and logrotate integration.
- Added clearer missing-argument handling in installer and bootstrap scripts.
- Added clearer test failure when configuration is missing.
- Added generic service description.
- Added package generation and checksum validation workflow.

## 1.1.0

Multi-distro and release-prep update.

- Renamed runtime tool to `security-update-notify` while preserving `debian-security-notify` compatibility symlink.
- Added `apt` backend for Debian/Ubuntu.
- Added `dnf` backend for RHEL/Rocky/AlmaLinux/Fedora/CentOS Stream/Amazon Linux 2023 support tiers.
- Added interactive menu: install/upgrade, uninstall, diagnostics.
- Added Telegram preflight validation.
- Added `--allow-best-effort`, `--version`, and `--doctor`.
- Added log file and logrotate configuration.
- Added bootstrap installer for website-hosted one-command installs.
- Added package script producing `.tar.gz` and `.sha256` release artifacts.

## 1.0.0

Initial Debian/Ubuntu-focused version.

- Configured unattended security updates without automatic reboot.
- Added reboot-required and `needrestart` checks.
- Added Telegram notifications with same-alert deduplication.
- Added systemd timer scheduling.
