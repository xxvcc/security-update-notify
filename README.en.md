# security-update-notify

<p align="center">
  <a href="https://github.com/xxvcc/security-update-notify/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/xxvcc/security-update-notify?style=flat-square&label=release&color=2EA043"></a>
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian-12%20%7C%2013-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04%20%7C%2026.04-E95420?style=flat-square&logo=ubuntu&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-8%20%7C%209%20%7C%2010-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> Automatically install security updates, then notify through Telegram, Feishu, or both when a server/service restart, patch-maintenance problem, or SUN release needs attention.

**security-update-notify** (**SUN**) is designed for servers, VPS hosts, and small infrastructure. It uses native apt/dnf automatic-update mechanisms and a systemd timer. It never reboots automatically, listens on no inbound port, and accepts no message commands.

Since 3.0, installation, runtime checks, diagnostics, uninstall, and self-upgrade are implemented in Go. The only maintained Shell product entry point is the first-install `sun.sh` bootstrap. Official packages contain linux/amd64, arm64, 386, ppc64le, and s390x. See [3.x Go architecture](docs/go-port.md) for implementation and migration details.

**Languages**: [中文](README.md) | English

## Quick install

Convenient interactive install:

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p
```

This compatibility entry point initially trusts the bootstrap delivered over HTTPS; the bootstrap still requires checksum and GPG verification for the Release it downloads. For production or a threat model that includes the download origin, use the [explicit-version, pinned-fingerprint procedure that verifies before execution](docs/installation.en.md#high-assurance-first-install-recommended-for-production).

Verify the installation:

```bash
security-update-notify --version
sudo security-update-notify doctor
systemctl list-timers security-update-notify.timer
```

See [Installation and upgrade](docs/installation.en.md) for notification preparation, source builds, non-interactive deployment, and upgrade options.

## What it solves

Distributions can usually install security patches automatically, but updates may still require human action:

- a new kernel is installed while the host still runs the old kernel;
- services continue using old shared libraries;
- the automatic-update timer, repositories, or package-manager state becomes unhealthy;
- hold, versionlock, or exclude policy blocks a security update;
- restart requirements or patch backlogs remain unresolved.

SUN automates security updates and turns the states that genuinely need an administrator into low-noise notifications.

## Main features

- Installs security updates through the distribution's official mechanism, but never reboots automatically.
- Sends through Telegram, Feishu, or both, with independent deduplication and retry state.
- Detects full-reboot, service-restart, patch-backlog, and distro-EOL conditions.
- Checks automatic-update policy, timers, repository metadata, and package-manager consistency.
- Provides a single-language Chinese or English interface and notifications.
- Supports interactive setup, config reuse, non-interactive deployment, and signed self-upgrade.
- Defaults to at most one repeated alert per day; once-only and every-N-days modes are available.
- Makes only required outbound HTTPS requests, with no web panel or remote command endpoint.

## How it works

```text
distribution apt/dnf automatic-update timer
    -> installs security updates
    -> SUN systemd timer checks maintenance state
    -> sends only notifications that need human attention
```

SUN never runs `reboot` or automatically restarts services. The administrator always controls the maintenance window and final action.

## Supported systems

### Official support

| Family | Versions | Backend |
| --- | --- | --- |
| Debian | 12, 13 | `apt` |
| Ubuntu | 22.04, 24.04, 26.04 | `apt` |
| RHEL-compatible (tested on Rocky / AlmaLinux) | 8, 9, 10 | `dnf` (DNF4) |
| Fedora | 43, 44 | `dnf` (DNF5) |

Official packages support amd64, arm64, 386, ppc64le, and s390x. Unlisted architectures do not fall back to the old Shell runtime.

### Best-effort support

These systems require an explicit `--allow-best-effort`:

- Debian 11
- Ubuntu 20.04 with a valid Ubuntu Pro/ESM security source
- CentOS Stream 9 / 10
- Oracle Linux 8 / 9 / 10
- CloudLinux 8 / 9 / 10
- Amazon Linux 2023

Best-effort means the SUN code path is compatible; administrators must still confirm that subscriptions and security sources are valid. Ubuntu 20.04 checks local `esm-infra` state automatically. Amazon Linux 2023 still requires the administrator to track and advance release snapshots. Some Oracle Linux 8 vendor images set `/etc/dnf` to `root:root 0775`; SUN rejects a group-writable privileged directory, so first confirm that it is root-owned and not a symlink, then run `sudo chmod 0755 /etc/dnf`. Unlisted `ID_LIKE` derivatives are never promoted to official support automatically; see [Operations and recovery](docs/operations.en.md) for detection and rollback rules.

### Not supported

- Alpine, Arch Linux, SUSE / openSUSE
- containers or minimal systems without complete systemd
- EOL systems without an active vendor or extended security source

## Prepare notifications

Telegram:

1. Open [@BotFather](https://t.me/BotFather) and create a bot.
2. Send `/start` to the bot and prepare its Bot Token and destination Chat ID.
3. For group alerts, add the bot to the group and allow it to send messages.

Feishu:

1. Create a custom enterprise application and enable its bot.
2. Grant `directory:employee:list`, `directory:employee.base.name.name:read`, `directory:employee.base.mobile:read`, and `im:message:send_as_bot`.
3. Publish the app, include the recipient in both app availability and directory data scopes, and prepare the App ID and App Secret.

The interactive installer scans visible employees for selection and stores only the app-scoped `open_id`. The App Secret uses a separate systemd/root credential and never enters normal config. See [Installation and upgrade](docs/installation.en.md) for preflight, strong verification, and automated secret-file requirements.

## Common operations

Run diagnostics now:

```bash
sudo security-update-notify doctor
```

Send a test notification:

```bash
sudo security-update-notify test --send-test --no-dedupe
```

Check for and install a SUN update:

```bash
security-update-notify check-upgrade
sudo security-update-notify upgrade
```

The configuration is root-readable by default. When running `check-upgrade` as an unprivileged user,
pass `--lang zh` or `--lang en` if its terminal language must match the installed configuration. A direct
unprivileged `upgrade` preserves an omitted language across sudo so the root process can read it again.

Change notification platforms, application, or recipient:

```bash
sudo security-update-notify configure notifications
```

View logs:

```bash
sudo tail -n 100 /var/log/security-update-notify.log
```

Uninstall the program while retaining config:

```bash
sudo security-update-notify uninstall
```

Remove config and state too:

```bash
sudo security-update-notify uninstall --purge-config
```

`--purge-config` restores managed apt/dnf configuration and removes credentials, state, and upgrade backups. After interruption or a concurrent file change, read the [restoration semantics](docs/operations.en.md#uninstall) before retrying.

## Common configuration

See [.env.example](.env.example) for the complete example and defaults. Common settings include:

| Setting | Default | Purpose |
| --- | --- | --- |
| `NOTIFY_CHANNELS` | `telegram` | `telegram`, `feishu`, or both |
| `NOTIFY_LANG` | `zh` | notification language |
| `INCLUDE_PUBLIC_IP` | `1` | include the egress IP in notifications |
| `DEDUP_MODE` | `daily` | `once`, `daily`, or `interval` |
| `PENDING_ALERT_DAYS` | `3` | age before a persistent patch backlog alerts |
| `RESTART_ALERT_DAYS` | `7` | age before a restart requirement escalates |
| `CHECK_UPDATE_HEALTH` | `1` | check policy, package state, and repository health |
| `CHECK_EOL` | `1` | check distro security-support status |
| `CHECK_SELF_UPDATE` | `1` | periodically notify about SUN releases; never auto-upgrade |

The installer makes normal config root-only. Prefer `configure notifications` or rerunning the installer instead of bypassing credential validation with hand-built config.

## Security boundaries

- Notifications make outbound HTTPS requests only to the Telegram Bot API and/or `open.feishu.cn`.
- A public-IP echo service is used by default and can be disabled with `INCLUDE_PUBLIC_IP=0`.
- Install and self-upgrade prefer `dl.ll.cd` and fall back to GitHub on transport failure.
- Releases require SHA-256, GPG signature, and pinned-fingerprint verification by default.
- The Feishu App Secret never enters normal config, command lines, logs, or upgrade backups.
- SUN exposes no HTTP endpoint, receives no remote commands, and never reboots automatically.

See [Security and trust model](docs/security.en.md) for signature verification, first-execution trust, credential, and network threat boundaries.

## Documentation

### Users and administrators

- [Installation and upgrade](docs/installation.en.md): verified install, automation, notification preflight, and upgrades.
- [Operations and recovery](docs/operations.en.md): watchdog, managed files, APT/DNF, uninstall, and restoration.
- [Security and trust model](docs/security.en.md): signatures, network, credentials, and first-install trust.

### Contributors and maintainers

- [Development and local validation](docs/development.en.md): build, test, and container gates.
- [Maintainer release process](docs/releasing.en.md): offline signing, immutable Releases, mirror, and canaries.
- [3.x Go architecture](docs/go-port.md): module, compatibility, and release invariants.
- [Changelog](CHANGELOG.md)

## License

MIT. See [LICENSE](LICENSE).
