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

Channel state is also bound to a stable target identity: Telegram uses the numeric bot identity plus Chat ID, while Feishu uses App ID plus the app-scoped `open_id`; only a one-way fingerprint is stored. When `configure notifications` changes a target, the installer marks that channel within the same rollback transaction before the new configuration becomes visible, so the next real alert cannot be suppressed by the old target's `once` or interval state. A failed send does not advance the target; only successful delivery commits its fingerprint. Existing target-less state is silently bound to the current target the first time deduplication suppresses it, without sending a message. Later runtime checks can therefore detect manual target changes in the protected config file.

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
| `CHECK_UPDATE_HEALTH` | `1` | Checks the auto-update mechanism, effective policy, package consistency, and repository health: disabled or inactive timers, failed/stale runs, low disk space, policy drift, broken package state, missing/expired/stale metadata, and signature/TLS errors. Set `0` to disable this group; backlog age, restart age, EOL, and SUN release notices remain enabled. |
| `STALE_UPDATE_DAYS` | `7` | Days without a successful automatic security update before it's considered stale; set `0` to disable this sub-check. |
| `PENDING_ALERT_DAYS` | `3` | Days that pending security updates may remain before alerting; set `0` to disable backlog alerts. The first-seen time is kept in root-only state and removed after the backlog clears. |
| `RESTART_ALERT_DAYS` | `7` | Days before a persistent full-reboot or service-restart requirement is escalated; set `0` to disable age escalation. SUN never restarts the host or services automatically. |
| `CHECK_SELF_UPDATE` | `1` | Periodically check for a SUN release; notify only, never auto-upgrade. |
| `SELF_UPDATE_CHECK_DAYS` | `7` | SUN release-check interval. Successful results are cached; `security-update-notify doctor` forces a read-only refresh. |
| `CHECK_EOL` | `1` | Distro end-of-life (EOL) warning: a past-EOL release triggers an alert, an approaching one (within 90 days) is informational. Ubuntu 20.04 automatically checks the local `esm-infra` state. Consider `0` only for an external extended-support arrangement that SUN cannot recognize, accepting that it disables every EOL check. |

The pending count remains informational until it reaches `PENDING_ALERT_DAYS`. DNF's high-severity subtotal includes both `critical` and `important`. An automatic-update timer alerts whenever it is enabled but not active; an active timer with no successful-run or trigger history is treated as waiting for its first run. Patch-backlog, full-reboot, and service-restart age tracking uses three-state observations: confirmed presence accumulates age, confirmed absence clears it, and a command failure, truncated output, or incomplete parse is unknown. An unknown run neither evaluates a stale alert nor loses the earlier `first_seen` value.

Run `security-update-notify doctor` anytime to inspect all seven checks, pending counts, and the SUN release result. Each item is explicitly reported as `OK`, `SKIP`, or `UNKNOWN`; unknown results return a nonzero status, while a check explicitly disabled by configuration does not fail merely because it is skipped. Diagnostics never mutate age or release-cache state. Simulated `security-update-notify test` modes and `security-update-notify run --dry-run` neither write this state nor make the periodic release request.

## Installed files

```text
/usr/local/sbin/security-update-notify
/usr/local/sbin/sun -> security-update-notify                              # when the path was free at install time
/etc/security-update-notify/telegram.env
/etc/systemd/system/security-update-notify.service
/etc/systemd/system/security-update-notify.service.d/credentials.conf  # encrypted Feishu credential
/etc/systemd/system/security-update-notify.timer
/etc/systemd/system/timers.target.wants/security-update-notify.timer   # persistent systemd enablement link
/run/systemd/system/timers.target.wants/security-update-notify.timer   # only while upgrading old runtime enablement
/var/lib/systemd/timers/stamp-security-update-notify.timer             # systemd Persistent timer state
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

The installer writes it as root-only (`0600`). The Feishu App Secret is never written there: it uses an encrypted systemd credential when available, or a separate root-only `0600` file on older systemd. Normal upgrade backups do not copy the App Secret. `TELEGRAM_BOT_TOKEN` does live in this file, so every upgrade copies it along with the rest of the configuration into `/var/backups/security-update-notify/<timestamp>/`, again at mode `0600` and retained for the current plus two previous transactions. An ordinary `uninstall` leaves those backups untouched and only `--purge-config` removes them, so rotating or revoking a Telegram Bot Token has to cover that directory too.

## Installation transactions and interruption recovery

Before stopping an existing unit or changing any managed path, the installer durably writes a transaction journal to the current `/var/backups/security-update-notify/<timestamp>/transaction.json`. An existing Feishu App Secret never enters that backup directory or journal; when rollback needs it, the installer creates only a fixed-name, root-only private recovery copy beside the original credential. Normal errors, cancellation, and the first `SIGHUP`, `SIGINT`, or `SIGTERM` wait for transaction rollback before the process exits. After `SIGKILL`, a kernel crash, or power loss, the next installation holds the install lock and scans every valid backup directory before parsing a new request. It fully validates journal state, the path allowlist, every snapshot, and all private recovery material before the first `systemctl` call or filesystem restoration.

Package-manager invocation is a separate fail-closed boundary. Before invoking it, the journal is durably marked unsafe for automatic recovery; the transaction becomes recoverable again only after dependency-created configuration baselines and the related automatic-unit state have both been captured and persisted. If the process stops in that interval or trustworthy capture cannot be completed, the installer does not use post-hoc probes such as `dpkg --audit`, `apt-get check`, or `rpm --verifydb` to guess that rollback is safe, and it does not automatically rewrite a partially changed host. The journal and private recovery material remain in place. Later install and uninstall attempts then stop before running systemd commands or deleting files. An administrator must inspect and repair package-manager state and complete a trusted manual recovery from the journal; do not delete the locator or recovery material first.

## Backend details

### Debian / Ubuntu (`apt`)

SUN configures or uses:

- `unattended-upgrades`
- `needrestart`
- `apt-listchanges`
- apt periodic timers

The installer enables unattended-upgrades security update timers. Before each overwrite of `/etc/apt/apt.conf.d/20auto-upgrades`, it saves a timestamped SUN-specific backup. If the file existed before SUN, the first install also preserves a fixed original baseline; if it was absent, SUN records a validated, rollback-protected absence marker before package-manager writes. When the `unattended-upgrades` dependency installed by this SUN transaction creates the distribution default, SUN binds its exact contents to a SHA-256 proof, promotes that file to the fixed baseline, and removes the absence marker. Purge can therefore retain the package and distribution timer while restoring a usable vendor configuration. A partial dependency transaction may be retried or purged only when the proof exactly matches the current file; a missing, damaged, or mismatched proof fails closed and preserves the evidence. If the package did not create the file, the original-absence marker remains authoritative and purge restores the file to absence. Markers, proofs, and timestamped backups in the APT configuration directory end in `.bak`, so apt silently ignores them instead of printing invalid-extension notices; upgrades migrate the older names. `--purge-config` finally removes SUN's baseline, marker, proof, and timestamped backups, and also cleans up the 1.1.x-era `/etc/apt/apt.conf.d/52unattended-upgrades-local`, but only when that file's bytes exactly match the policy 1.1.x wrote. 3.x never creates it, so an administrator's own file at the same path is left untouched.

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

## Interactive menu

After installation, the short command is the recommended menu entrypoint; the full command is always available
as a fallback:

```bash
sudo sun
sudo security-update-notify menu
```

Use `--lang zh` or `--lang en` to select the interface language for this invocation, for example
`sudo security-update-notify menu --lang en`. The menu can preview a run, run a check now, run the system
doctor, change notification settings, test notifications, check for a new release, upgrade, uninstall,
switch the interface language, or exit. Switching the interface language affects only the current menu and
the actions it dispatches; persistent notification language remains controlled by `NOTIFY_LANG`.

The menu deliberately has a strict interactive boundary: the effective UID must be root and standard input,
standard output, and standard error must all be attached to real TTYs. Pipes, redirections, cron, systemd
units, and non-terminal SSH invocations are refused before any selection is read. A bare
`security-update-notify` retains its established "run one check" behavior regardless of TTY state. Scripts,
cron jobs, and systemd units should invoke `security-update-notify run` explicitly; the installed systemd
service uses that explicit `run` subcommand too.

Successful read-only and routine actions return to the prompt, and a blank line redraws the complete menu.
An action failure exits immediately with that action's original status. Once notification configuration,
upgrade, or uninstall has actually been dispatched, the menu exits with that command's status so an old
privileged process does not continue accepting work after configuration changes or after its binary has been
replaced or removed. Cancelling upgrade or uninstall at the menu's own confirmation does not dispatch the
action, causes no action side effects, and returns to the menu.

Entrypoints that have external effects or modify the host use fail-closed confirmation. Run-now and test-send
confirmations default to `N`; upgrade requires the exact word `YES`; uninstall while retaining configuration
requires the exact word `YES`. A full purge restores SUN-managed apt/dnf automatic-update configuration and
removes SUN configuration, notification credentials, state, upgrade backups, and logs; it requires the exact
word `PURGE`. End-of-file (for example, `Ctrl-D` at a prompt) is a cancellation and returns `2`.
`Ctrl-C` terminates by signal, normally observed by the shell as status `130`. If an action has already begun,
it retains that subcommand's existing lock, transactional rollback, and exit-status behavior.

The installer implements the short command as the relative symlink
`/usr/local/sbin/sun -> security-update-notify`. It creates the link when the path is absent and reuses that
exact link. A regular file, directory, or link to any other target is never overwritten: core installation
can still complete, but prints a warning. At uninstall time, only a relative link still pointing exactly to
`security-update-notify` is removed; any other file, directory, or link is preserved. Use
`sudo security-update-notify menu` after a conflict.

Direct downgrades to a release that predates the interactive menu are unsupported. If its binary is installed
manually, an existing `sun` link may remain, but that older binary does not dispatch by invocation name:
`sudo sun` then performs the older release's bare check, which may send notifications and write state. Uninstall
the current release normally before downgrading. If a manual downgrade has already occurred, stop using `sun`,
remove it only after verifying that it is still the exact relative link above, and use the older release's
documented long-form commands.

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

The configuration is root-readable by default, so an unprivileged `check-upgrade` cannot discover
`NOTIFY_LANG`; pass `--lang zh` or `--lang en` when its terminal language must match the installation.
For a direct unprivileged `upgrade`, an omitted language remains omitted across sudo so the root child can
pre-read the configuration again, while an explicit language is passed through unchanged.

View logs:

```bash
sudo tail -n 100 /var/log/security-update-notify.log
```

## Uninstall

Remove the program and systemd/logrotate integration, including SUN's timer enablement links and Persistent
timestamp, while retaining SUN's business configuration and `/var/lib/security-update-notify` state:

```bash
sudo security-update-notify uninstall
```

Remove config and state too:

```bash
sudo security-update-notify uninstall --purge-config
```

When both stdin and stderr are real TTYs, a full purge first displays its removal scope and requires the exact
word `PURGE`; a mismatch, EOF, or read failure cancels with status `2`. Automation that has confirmed the action
through an external control may pass `--yes` (or `-y`) explicitly. A non-interactive pipe or redirection does not
prompt or consume stdin, preserving the existing automation contract.

Both ordinary uninstall and `--purge-config` remove only the exact SUN timer unit, enablement links, and Persistent
timestamp; a same-name link whose target was replaced by an administrator is preserved. The Persistent timestamp
is removed only when it is a root-owned regular file that forbids group/other write and has exactly one hard link;
an unexpected type or metadata is retained and reported as an error. Packages installed as dependencies are left in
place. `--purge-config` additionally removes SUN config, Telegram/Feishu
credentials, state, upgrade backups (which may contain bot-token copies), and rotated logs, and restores apt/dnf
automatic-update config when a SUN-created backup exists. The uninstaller leaves the distribution's own automatic
timer and timestamps in their current state: removing the monitoring tool does not actively disable security updates
or override later administrator changes to that timer.

Both ordinary uninstall and `--purge-config` acquire the install and runtime locks before scanning installation journals and the fixed private-recovery paths. If an interrupted transaction or private recovery material exists, uninstall fails closed before any `systemctl` call, unit removal, or configuration cleanup. Rerun the installer first for an automatically recoverable transaction. A transaction marked unsafe during the package-manager phase requires the inspection and manual repair described above and cannot be bypassed through uninstall.

The uninstaller fails closed on concurrent changes that return normally: it uses directory handles, no-overwrite renames, and content/metadata revalidation, and retains `.security-update-notify-restore.*`, `.security-update-notify-purge.*`, or `.security-update-notify-conflict.*` evidence instead of overwriting or deleting an administrator-created concurrent file. `--purge-config` does not, however, promise transactional atomicity across SIGKILL, a kernel crash, or power loss; do not forcibly terminate it. If purge is interrupted, inspect those retained files and the current apt/dnf configuration before retrying.

Ordinary file and directory removal may also retain `.security-update-notify-remove-pending.*`, legacy
`.security-update-notify-remove.*`, or identity-bearing `.security-update-notify-remove-owned.*` entries. An
opened parent is trusted as private only while it remains root-owned and forbids group/other write. A retry then
automatically removes only an owned entry whose stable identity still matches. A parent that no longer meets
those conditions, or a pending or legacy entry, is retained and fails closed.
`/var/log` is a shared parent, so every retained quarantine there fails closed and remains in place even when an
owned identity matches: a forgeable name is not cross-process proof of ownership. With no retained quarantine,
the current purge still removes SUN's log and rotated logs normally. Never delete retained entries by name
alone. Compare the reported original and quarantine paths, inode, type, ownership, contents, and available
backups before an administrator decides to restore the original name or remove the entry. Preserve the evidence
and recover from a trusted backup when ownership cannot be established.

## Related documentation

- [Installation and upgrade](installation.en.md)
- [Security and trust model](security.en.md)
- [3.x Go architecture and recovery invariants](go-port.md)
