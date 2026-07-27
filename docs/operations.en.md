# Operations and recovery

[中文](operations.md) | [Back to README](../README.en.md)

This guide covers reminder policy, patch-maintenance checks, managed files, APT/DNF behavior, routine commands, uninstall, and restoration semantics.

## Duplicate alert modes

| Mode | Behavior |
| --- | --- |
| `once` | Send once for the same alert until the state changes (was `always`, still accepted). |
| `daily` | Send the same alert at most once per day (**default / recommended**). |
| `interval` | Send the same alert every N days. Default: `3`. |

`daily` is the default: at most one reminder per day keeps nudging you while a reboot stays pending without spamming. For something quieter use `once` (only once) or `interval` (every N days).

With dual delivery, each channel has independent state. If Telegram succeeds and Feishu fails, the next run retries only Feishu instead of repeating Telegram.

## Security-update watchdog

In addition to reboot/service-restart and distro-EOL detection, SUN runs seven patch-maintenance checks by default:

1. Alert when pending security patches remain continuously beyond the threshold, `3` days by default.
2. Alert immediately when APT hold or DNF versionlock/exclude hides a security patch.
3. Detect drift in APT or dnf-automatic security-update policy and timer settings.
4. Run `dpkg --audit`, `apt-get check`, or `dnf check` to detect a broken package-manager state.
5. Check APT InRelease metadata for missing, expired, or stale data and distinguish refresh failures from signature/TLS errors; DNF metadata and signature/TLS failures are also classified separately.
6. Escalate full-reboot or service-restart requirements that remain beyond the threshold, `7` days by default.
7. Check for a SUN release every `7` days by default and send a notice only. It **never upgrades SUN automatically**.

| Key | Default | What it does |
| --- | --- | --- |
| `CHECK_UPDATE_HEALTH` | `1` | Checks the auto-update mechanism, effective policy, package consistency, and repository health: disabled timers, failed/stale runs, low disk space, policy drift, broken package state, missing/expired/stale metadata, and signature/TLS errors. Set `0` to disable this group; backlog age, restart age, EOL, and SUN release notices remain enabled. |
| `STALE_UPDATE_DAYS` | `7` | Days without a successful automatic security update before it's considered stale; set `0` to disable this sub-check. |
| `PENDING_ALERT_DAYS` | `3` | Days that pending security updates may remain before alerting; set `0` to disable backlog alerts. The first-seen time is kept in root-only state and removed after the backlog clears. |
| `RESTART_ALERT_DAYS` | `7` | Days before a persistent full-reboot or service-restart requirement is escalated; set `0` to disable age escalation. SUN never restarts the host or services automatically. |
| `CHECK_SELF_UPDATE` | `1` | Periodically check for a SUN release; notify only, never auto-upgrade. |
| `SELF_UPDATE_CHECK_DAYS` | `7` | SUN release-check interval. Successful results are cached; `security-update-notify doctor` forces a read-only refresh. |
| `CHECK_EOL` | `1` | Distro end-of-life (EOL) warning: a past-EOL release triggers an alert, an approaching one (within 90 days) is informational. Ubuntu 20.04 automatically checks the local `esm-infra` state. Consider `0` only for an external extended-support arrangement that SUN cannot recognize, accepting that it disables every EOL check. |

The pending count remains informational until it reaches `PENDING_ALERT_DAYS`. DNF's high-severity subtotal includes both `critical` and `important`. Run `security-update-notify doctor` anytime to inspect all seven checks, pending counts, and the SUN release result; diagnostics never mutate age or release-cache state. Simulated `security-update-notify test` modes and `security-update-notify run --dry-run` neither write this state nor make the periodic release request.

## Installed files

```text
/usr/local/sbin/security-update-notify
/etc/security-update-notify/telegram.env
/etc/systemd/system/security-update-notify.service
/etc/systemd/system/security-update-notify.service.d/credentials.conf  # encrypted Feishu credential
/etc/systemd/system/security-update-notify.timer
/etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred # newer systemd
/etc/security-update-notify/credentials/feishu-app-secret              # older-systemd fallback
/etc/logrotate.d/security-update-notify
/var/lib/security-update-notify/
/var/backups/security-update-notify/
/var/log/security-update-notify.log
```

Depending on the backend, the installer also manages apt's `/etc/apt/apt.conf.d/20auto-upgrades`, `/etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify`, and `/etc/needrestart/conf.d/99-security-update-notify-report-only.conf`, or DNF's `/etc/dnf/automatic.conf`. Original baselines, absence markers, proofs, and timestamped backups live beside the managed policy; the backend sections below define their exact restoration rules.

Notification options, the Telegram Bot Token, Feishu App ID, and recipient `open_id` are stored in:

```text
/etc/security-update-notify/telegram.env
```

The installer writes it as root-only (`0600`). The Feishu App Secret is never written there: it uses an encrypted systemd credential when available, or a separate root-only `0600` file on older systemd. Normal upgrade backups do not copy the App Secret.

## Backend details

### Debian / Ubuntu (`apt`)

SUN configures or uses:

- `unattended-upgrades`
- `needrestart`
- `apt-listchanges`
- apt periodic timers

The installer enables unattended-upgrades security update timers. Before each overwrite of `/etc/apt/apt.conf.d/20auto-upgrades`, it saves a timestamped SUN-specific backup. If the file existed before SUN, the first install also preserves a fixed original baseline; if it was absent, SUN records a validated, rollback-protected absence marker before package-manager writes. When the `unattended-upgrades` dependency installed by this SUN transaction creates the distribution default, SUN binds its exact contents to a SHA-256 proof, promotes that file to the fixed baseline, and removes the absence marker. Purge can therefore retain the package and distribution timer while restoring a usable vendor configuration. A partial dependency transaction may be retried or purged only when the proof exactly matches the current file; a missing, damaged, or mismatched proof fails closed and preserves the evidence. If the package did not create the file, the original-absence marker remains authoritative and purge restores the file to absence. Markers, proofs, and timestamped backups in the APT configuration directory end in `.bak`, so apt silently ignores them instead of printing invalid-extension notices; upgrades migrate the older names. `--purge-config` finally removes SUN's baseline, marker, proof, and timestamped backups.

It checks:

- `/var/run/reboot-required`
- `/var/run/reboot-required.pkgs`
- `needrestart -b`

### RHEL-compatible / Fedora (`dnf`)

`BACKEND` remains the stable value `dnf` for both DNF4 and DNF5; SUN detects the installed generation internally.

DNF4 (RHEL-compatible 8–10, lifecycle-tested on Rocky/AlmaLinux, and best-effort EL derivatives) configures or uses:

- `dnf-automatic`
- `yum-utils` (Amazon Linux 2023 uses the actual package name `dnf-utils`)
- `ca-certificates`
- an explicit `dnf` package on EL10 minimal systems, whose base image may provide only `microdnf`

DNF4 checks:

- `needs-restarting -r` (whether a full reboot is required)
- `needs-restarting -s` (systemd services that need a restart; no longer the raw `needs-restarting` process list, which caused false alerts)
- `dnf -q updateinfo list security`

DNF5 (Fedora 43/44) uses `dnf5-plugin-automatic`, `dnf5-plugins`, and `ca-certificates`, and enables the native `dnf5-automatic.timer`. The package also ships the separate compatibility name `dnf-automatic.timer`; SUN disables that timer if it was enabled so the identical job cannot run twice, and restores its exact state if installation fails. Runtime health checks still recognize either unit name. DNF5 checks use:

- `dnf -q advisory list --security --updates --json`
- `dnf -q check-upgrade --security` (including its update-present exit code `100`)
- `dnf needs-restarting` and `dnf needs-restarting -s`

SUN intersects DNF5 advisory JSON with the actual transaction candidate set so advisory-only packages are not reported as installable updates. It separately clears ordinary excludes for the complete advisory set and uses the per-query option `--setopt=disable_excludes=*` to calculate transaction candidates without versionlock or exclude filtering. The differences identify security packages blocked by locks, excludes, or transaction constraints. This query does not modify `/etc/dnf/versionlock.toml` or persistent DNF configuration.

Both generations use `/etc/dnf/automatic.conf`. If it exists, SUN preserves one fixed original baseline when it first takes ownership and saves an additional timestamped copy before each overwrite; if it was absent, the absence marker explicitly records the DNF4 or DNF5 generation. When the retained DNF4 `dnf-automatic` dependency creates its distribution default during this installation, SUN adopts that post-dependency vendor file as the fixed baseline and removes the original-absence marker. `--purge-config` therefore restores a usable vendor configuration instead of leaving the retained, enabled distribution timer pointed at a missing file. If the dependency transaction fails after creating that vendor configuration, SUN leaves a SHA-256 proof bound to the file contents. An immediate purge then preserves the configuration and removes SUN metadata only when that proof exactly matches the current file; a damaged or mismatched proof fails closed and preserves the evidence. When upgrading an older DNF4 installation that still has an absence marker, SUN can migrate the validated earliest SUN timestamped backup and never mistakes the current managed configuration for the vendor baseline. A direct purge does not infer provenance from timestamp history alone: when a DNF4 marker and current file coexist without a fixed baseline or proof matching the current contents, it fails closed and preserves the evidence even if timestamped backups remain. The installer likewise stops only when it cannot establish a trusted baseline from the validated earliest timestamp or a matching proof. If `dnf-automatic` is already reported as installed but its configuration is missing and no trusted historical baseline exists, the installer also stops before enabling the timer; purge the incomplete SUN metadata, then reinstall the package or restore a trusted vendor configuration before retrying. DNF5 declares the path as optional and has a packaged vendor fallback, so a file that was originally absent keeps its validated absence marker and purge restores it to absence. A normal uninstall followed by reinstall does not replace a fixed baseline; purge finally removes SUN's baseline, marker, and timestamped backups.

DNF4 packages may preset `dnf-automatic.timer`, `dnf-automatic-notifyonly.timer`, `dnf-automatic-download.timer`, and `dnf-automatic-install.timer` together. After a successful SUN installation, only the primary `dnf-automatic.timer` remains enabled; the three mutually exclusive variants are disabled so multiple automatic jobs cannot run the same configuration in parallel. A failed installation restores the exact prior state of all four timers. A later successful uninstall does not guess or reconstruct the pre-install variant combination; it leaves every distribution timer in its state at uninstall time.

```ini
upgrade_type = security
apply_updates = yes
reboot = never
```

## Operations

Check timer status:

```bash
systemctl list-timers security-update-notify.timer
```

Run a check now:

```bash
sudo systemctl start security-update-notify.service
```

Change the notification language after installation:

```bash
sudoedit /etc/security-update-notify/telegram.env
# Set NOTIFY_LANG=zh (Chinese) or NOTIFY_LANG=en (English)
```

To switch receiving platforms or change the Feishu app or recipient, run `sudo security-update-notify configure notifications`. The Go installer validates the App ID/app-scoped `open_id` binding and creates, migrates, or removes the App Secret credential; do not bypass those steps by editing only `NOTIFY_CHANNELS`.

Run built-in diagnostics:

```bash
security-update-notify --version
security-update-notify check-upgrade
sudo security-update-notify doctor
```

View logs:

```bash
sudo tail -n 100 /var/log/security-update-notify.log
```

## Uninstall

Remove the program and systemd/logrotate integration, while keeping config and state:

```bash
sudo security-update-notify uninstall
```

Remove config and state too:

```bash
sudo security-update-notify uninstall --purge-config
```

Packages installed as dependencies are left in place. `--purge-config` removes SUN config, Telegram/Feishu credentials, state, upgrade backups (which may contain bot-token copies) and rotated logs, and restores apt/dnf automatic-update config when a SUN-created backup exists. The uninstaller leaves the distribution's own automatic timer in its current state: removing the monitoring tool does not actively disable security updates or override later administrator changes to that timer.

The uninstaller fails closed on concurrent changes that return normally: it uses directory handles, no-overwrite renames, and content/metadata revalidation, and retains `.security-update-notify-restore.*`, `.security-update-notify-purge.*`, or `.security-update-notify-conflict.*` evidence instead of overwriting or deleting an administrator-created concurrent file. `--purge-config` does not, however, promise transactional atomicity across SIGKILL, a kernel crash, or power loss; do not forcibly terminate it. If purge is interrupted, inspect those retained files and the current apt/dnf configuration before retrying.

## Related documentation

- [Installation and upgrade](installation.en.md)
- [Security and trust model](security.en.md)
- [3.x Go architecture and recovery invariants](go-port.md)
