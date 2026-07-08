# security-update-notify

<p align="center">
  <a href="https://github.com/xxvcc/security-update-notify/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/xxvcc/security-update-notify?style=flat-square&label=release&color=2EA043"></a>
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian-12%20%7C%2013-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-E95420?style=flat-square&logo=ubuntu&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-8%20%7C%209-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> Install security updates automatically. Get a clean Telegram alert only when a reboot or service restart needs your attention.

**security-update-notify** — or **SUN** — is a small Linux utility for people who maintain servers and do not want to miss important post-update actions.

It uses your distro's native update tools, runs from a systemd timer, and sends outbound-only Telegram notifications. No dashboard. No agent port. No remote-control bot.

> Since **2.0**, the runtime is a statically-compiled **Go binary**, shipped per architecture (amd64/arm64/386/ppc64le/s390x); unbuilt architectures fall back to the self-contained Bash runtime. The runtime itself needs neither `python3` nor `curl` — only the `install.sh` installer still uses `python3` for its Telegram preflight.

**Languages**: [中文](README.md) | English

## One-line install

```bash
curl -fsSL https://sun.xxv.cc | sudo bash
```

---

## Why use it?

Most servers can install security updates automatically. The part people miss is what happens after:

- the kernel was updated, but the machine still runs the old kernel;
- services are still using old shared libraries;
- a reboot is needed, but nobody notices until much later;
- update tools are noisy, so alerts get ignored.

SUN keeps the boring part automatic and makes the human part obvious.

## What you get

- **Automatic security updates** through official distro mechanisms.
- **No automatic reboot** — you stay in control of downtime.
- **Telegram alerts only when action is needed**.
- **Reboot and service-restart detection** with `needrestart` or `needs-restarting`.
- **Security-update watchdog**: beyond kernel/service restarts, it watches three commonly-missed things — ① whether the auto-update mechanism itself is unhealthy (timer disabled, last run failed, no successful update for too long, disk nearly full); ② whether security updates are still pending (dnf also counts critical/important); ③ whether the distro's security support is ending or already ended (EOL). A mechanism problem or a past-EOL release triggers an alert; the pending count and an approaching EOL ride along with alerts as info. All three can be turned off in the config.
- **Single-language UI (Chinese or English)**: the installer, menu and diagnostics pick a language as the first step (Chinese or English, default Chinese) and then render all terminal interaction in that one language — no more mixed zh/en. The choice also becomes the default Telegram alert language, overridable with `--notify-lang`.
- **Public IP in notifications**: auto-detect the server public IP by default; you can also set it manually or disable it. Auto-detection is done by the Go runtime with the standard library and adds no `curl`/`python3` dependency.
- **Duplicate alert suppression**: once, daily, or every N days.
- **Interactive and non-interactive install/upgrade**: rerunning the installer reuses the existing config.
- **systemd timer based scheduling**.
- **No inbound network listener**.

Example Telegram alert (`NOTIFY_LANG=en`):

```text
⚠️ Security update action required

Host: prod-web-01
Public IP: 203.0.113.10
OS: Debian GNU/Linux 12 (bookworm)
Backend: apt
Current kernel: 6.1.0-43-amd64
Time: 2026-05-02 09:08 CST

Full reboot: Required
Related packages/security updates:
linux-image-amd64

Restart detection summary:
Kernel: current 6.1.0-43-amd64, expected 6.1.0-44-amd64
Services to review/restart (2):
• nginx.service
• ssh.service

Recommendation: SSH into this server during a suitable maintenance window and run reboot if a full reboot is required. If only services need restarting, review them first and restart the affected services manually.
```

## How it works

```text
distro auto-update timer (apt/dnf)
    ↓
install security updates
    ↓
SUN systemd timer
    ↓
check post-update reboot / service-restart state
    ↓
send Telegram message only if attention is required
```

SUN does **not**:

- reboot the server;
- expose a web service;
- accept Telegram commands;
- use Telegram polling or webhooks;
- open any inbound port.

## Supported systems

### Officially supported

| Family | Versions | Backend |
| --- | --- | --- |
| Debian | 12, 13 | `apt` |
| Ubuntu | 22.04, 24.04 | `apt` |
| RHEL / Rocky / AlmaLinux | 8, 9 | `dnf` |
| Fedora | current releases | `dnf` |

### Best-effort support

These require `--allow-best-effort`:

- Debian 11
- Ubuntu 20.04
- CentOS Stream 8 / 9
- Amazon Linux 2023

### Not supported

- Alpine
- Arch Linux
- SUSE / openSUSE
- containers or minimal systems without full systemd
- end-of-life systems without security updates

## Quick start

### 1. Create a Telegram bot

1. Open Telegram and talk to [@BotFather](https://t.me/BotFather).
2. Create a bot and copy the bot token.
3. Send `/start` to your new bot.
4. Get your target chat ID.

For groups, add the bot to the group and make sure it can send messages there.

### 2. Install

Recommended: use the website-hosted bootstrap installer. It downloads the latest GitHub Release, verifies the `.sha256` file and GPG signature (required by default), then opens the interactive menu:

```bash
curl -fsSL https://sun.xxv.cc | sudo bash
```

If you prefer running from source:

```bash
git clone https://github.com/xxvcc/security-update-notify.git
cd security-update-notify
sudo ./install.sh
```

The installer first asks you to choose a UI language (Chinese or English, default Chinese): it sets the language for all subsequent interaction and the default Telegram alert language. It then asks for:

- Telegram Bot Token;
- Telegram Chat ID;
- daily check time, default `09:00`;
- duplicate-alert behavior;
- whether to send an extra test message after installation.

To skip the interactive language prompt, pass `--lang zh` or `--lang en`.

Before writing the config, it verifies Telegram with:

- `getMe` for the bot token;
- `sendMessage` for the chat ID and bot permissions.

### 3. Verify

```bash
sudo ./test.sh
sudo ./test.sh --send-test --no-dedupe
sudo ./test.sh --simulate-reboot --no-dedupe
```

The simulated reboot test only sends a test alert. It does **not** reboot the server.

## Non-interactive install

Useful for provisioning scripts:

```bash
sudo ./install.sh \
  --telegram-token '123456:ABC...' \
  --telegram-chat-id 'CHAT_ID' \
  --time '09:00' \
  --notify-lang en \
  --dedup-mode interval \
  --dedup-interval-days 3 \
  --host-label 'prod-web-01' \
  --public-ip '203.0.113.10' \
  --non-interactive \
  -y
```

For safer automation, use a local `.env` file so the token does not appear in shell history or process lists:

```bash
cp .env.example .env
chmod 600 .env
sudoedit .env

sudo ./install.sh --env-file .env --non-interactive -y
```

You can also keep only the token in a root-only file:

```bash
sudo install -m 600 /dev/null /root/.security-update-notify-token
sudoedit /root/.security-update-notify-token

sudo ./install.sh \
  --telegram-token-file /root/.security-update-notify-token \
  --telegram-chat-id 'CHAT_ID' \
  --non-interactive \
  -y
```

Common options:

```bash
--env-file FILE            # read install config from dotenv-style file, recommended for automation
--telegram-token-file FILE # read Telegram Bot Token from file
--backend apt              # force apt backend
--backend dnf              # force dnf backend
--notify-lang zh           # Telegram alert language: Chinese, default
--notify-lang en           # Telegram alert language: English
--lang en                  # terminal interaction language: English (default zh)
--public-ip IP             # manually set public IP in notifications; auto-detected at runtime when empty
--include-public-ip 0      # disable public IP in notifications; default 1
--notify-ok 1             # send OK notification when no action is needed; default 0
--notify-upgrade 1        # send Telegram notification after successful upgrade; default 0
--skip-post-install-check # skip post-install/upgrade self-check
--allow-best-effort        # allow best-effort distro versions
--send-test                # send an extra install-complete test message
--skip-telegram-test       # skip Telegram preflight validation
```


### Upgrade

Rerun the one-line installer to upgrade to the latest release:

```bash
curl -fsSL https://sun.xxv.cc | sudo bash -s -- upgrade --non-interactive -y
```

Once SUN is installed you can also run `sudo security-update-notify --upgrade` directly: it downloads the latest GitHub release, verifies `.sha256`, and requires a GPG signature against the pinned fingerprint (fail-closed by default — it refuses if the signature is missing) before upgrading.

If SUN is already installed, the installer reads `/etc/security-update-notify/telegram.env` and the existing timer time first. Options not explicitly overridden by CLI flags or `--env-file` keep their old values, so you usually do not need to re-enter the Telegram token or chat ID. Before upgrading, key files are backed up to `/var/backups/security-update-notify/<timestamp>`; failed upgrades attempt an automatic rollback. A post-upgrade self-check runs by default; use `--notify-upgrade 1` to send a Telegram notification after a successful upgrade.

## Duplicate alert modes

| Mode | Behavior |
| --- | --- |
| `once` | Send once for the same alert until the state changes (was `always`, still accepted). |
| `daily` | Send the same alert at most once per day (**default / recommended**). |
| `interval` | Send the same alert every N days. Default: `3`. |

`daily` is the default: at most one reminder per day keeps nudging you while a reboot stays pending without spamming. For something quieter use `once` (only once) or `interval` (every N days).

## Security-update watchdog

Beyond reboot/service-restart detection, SUN runs three extra checks by default (all can be disabled in `/etc/security-update-notify/telegram.env`):

| Key | Default | What it does |
| --- | --- | --- |
| `CHECK_UPDATE_HEALTH` | `1` | Detects whether the auto-update mechanism is healthy: the timer (`apt-daily-upgrade` / `dnf-automatic`) is disabled, the last run failed, no successful update for more than `STALE_UPDATE_DAYS` days, or `/` or `/boot` has less than 200 MB free. Any hit triggers an alert. |
| `STALE_UPDATE_DAYS` | `7` | Days without a successful automatic security update before it's considered stale; set `0` to disable this sub-check. |
| `CHECK_EOL` | `1` | Distro end-of-life (EOL) warning: a past-EOL release triggers an alert, an approaching one (within 90 days) is informational. Set `0` if you have extended support such as Ubuntu ESM. |

The pending security-update count is informational — it rides along with alerts and shows in `--doctor`, but does not trigger an alert on its own. Run `security-update-notify --doctor` anytime to see the current state of all three.

## Installed files

```text
/usr/local/sbin/security-update-notify
/etc/security-update-notify/telegram.env
/etc/systemd/system/security-update-notify.service
/etc/systemd/system/security-update-notify.timer
/etc/logrotate.d/security-update-notify
/var/lib/security-update-notify/
/var/log/security-update-notify.log
```

Telegram credentials and notification options are stored in:

```text
/etc/security-update-notify/telegram.env
```

The installer writes it as root-only (`0600`).

## Backend details

### Debian / Ubuntu (`apt`)

SUN configures or uses:

- `unattended-upgrades`
- `needrestart`
- `apt-listchanges`
- apt periodic timers

The installer enables unattended-upgrades security update timers. Before each overwrite of `/etc/apt/apt.conf.d/20auto-upgrades`, it saves a timestamped SUN-specific backup; on first install it also keeps a fixed-name backup, and `--purge-config` restores that fixed backup when it exists.

It checks:

- `/var/run/reboot-required`
- `/var/run/reboot-required.pkgs`
- `needrestart -b`

### RHEL-compatible / Fedora (`dnf`)

SUN configures or uses:

- `dnf-automatic`
- `yum-utils` or `dnf-utils`
- `python3`, `ca-certificates`

It checks:

- `needs-restarting -r` (whether a full reboot is required)
- `needs-restarting -s` (systemd services that need a restart; no longer the raw `needs-restarting` process list, which caused false alerts)
- `dnf updateinfo list security updates`

If `/etc/dnf/automatic.conf` exists, SUN first saves a timestamped backup, then configures security-only automatic updates; `--purge-config` attempts to restore the newest SUN-created backup.

```ini
upgrade_type = security
apply_updates = yes
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

Change Telegram alert language after installation:

```bash
sudoedit /etc/security-update-notify/telegram.env
# Set NOTIFY_LANG=zh (Chinese) or NOTIFY_LANG=en (English)
```

Run built-in diagnostics:

```bash
security-update-notify --version
security-update-notify --check-upgrade
sudo security-update-notify --doctor
```

View logs:

```bash
sudo tail -n 100 /var/log/security-update-notify.log
```

## Uninstall

Remove the program and systemd/logrotate integration, while keeping config and state:

```bash
sudo ./uninstall.sh
```

Remove config and state too:

```bash
sudo ./uninstall.sh --purge-config
```

Packages installed as dependencies are left in place. `--purge-config` removes SUN config/state, upgrade backups (which contain bot-token copies) and rotated logs, and restores apt/dnf automatic-update config when a SUN-created backup exists.

## Release signatures

Release packages always include a `.sha256` checksum file. `package.sh` can also create a detached `.tar.gz.asc` signature automatically when a GPG secret key is available. `sun.sh` defaults to `required` signature verification; `auto` is kept only as a compatibility alias and also requires both gpg and the `.asc` signature. Only an explicit `--verify-signature off` skips signature verification.

Official releases (builds for a version with a corresponding `vX.Y.Z` tag, or builds with `RELEASE=1`) are **signed-mandatory**: `package.sh` requires a GPG signature and fails without a key, and after a release is published CI verifies the assets' signature and fingerprint against the repo's public key, failing the release checks if a signature is missing or mismatched. The private key never enters CI; it stays offline with the maintainer. In addition, `security-update-notify --upgrade` is **fail-closed** by default: it downloads the GitHub release directly, verifies sha256, and requires a GPG signature against an embedded public key and pinned fingerprint before extracting and upgrading (set `SECURITY_UPDATE_NOTIFY_UPGRADE_ALLOW_UNSIGNED=1` to upgrade on sha256 only in an emergency).

## Security notes

SUN is intentionally narrow:

- outbound HTTPS to Telegram Bot API only;
- no command receiver;
- no public HTTP endpoint;
- no automatic reboot;
- root-only Telegram credential file;
- explicit opt-in for best-effort distro support.

The release `.sha256` file protects against accidental corruption or version mismatch. If your threat model includes a compromised download source, keep the default signature verification enabled and do not use `--verify-signature off` or the unsigned-upgrade escape hatch.

## Build a release package

From the source checkout:

```bash
bash -n install.sh menu.sh test.sh uninstall.sh package.sh sun.sh files/security-update-notify
./package.sh
cd dist && sha256sum -c security-update-notify-*.tar.gz.sha256
```

Generated files:

```text
dist/security-update-notify-VERSION.tar.gz
dist/security-update-notify-VERSION.tar.gz.sha256
```

The release archive contains only user-facing installation, diagnostic, and documentation files. `sun.sh` is a website-hosted bootstrap script and is not included in release archives; publish it separately to your stable URL if you want to use it.

Release archive contents:

```text
.env.example
CHANGELOG.md
LICENSE
README.md
README.en.md
install.sh
menu.sh
test.sh
uninstall.sh
files/
```

## License

MIT. See [LICENSE](LICENSE).
