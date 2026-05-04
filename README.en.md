# security-update-notify

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian-12%20%7C%2013-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-E95420?style=flat-square&logo=ubuntu&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-8%20%7C%209-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> Install security updates automatically. Get a clean Telegram alert only when a reboot or service restart needs your attention.

**security-update-notify** — or **SUN** — is a small Linux utility for people who maintain servers and do not want to miss important post-update actions.

It uses your distro's native update tools, runs from a systemd timer, and sends outbound-only Telegram notifications. No dashboard. No agent port. No remote-control bot.

**Languages**: [中文](README.md) | English

## One-line install

```bash
curl -fsSL https://xxv.cc/sun.sh | sudo bash
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
- **Selectable Telegram alert language**: choose Chinese or English during installation. Default: Chinese.
- **Duplicate alert suppression**: once, daily, or every N days.
- **Interactive and non-interactive installation**.
- **systemd timer based scheduling**.
- **No inbound network listener**.

Example Telegram alert (`NOTIFY_LANG=en`):

```text
⚠️ Security update action required

Host: prod-web-01
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

Recommended: use the website-hosted bootstrap installer. It downloads the latest GitHub Release, verifies the `.sha256` file, then opens the interactive menu:

```bash
curl -fsSL https://xxv.cc/sun.sh | sudo bash
```

If you prefer running from source:

```bash
git clone https://github.com/xxvcc/security-update-notify.git
cd security-update-notify
sudo ./install.sh
```

The installer will ask for:

- Telegram Bot Token;
- Telegram Chat ID;
- Telegram alert language, default `zh` (Chinese);
- daily check time, default `09:00`;
- duplicate-alert behavior;
- whether to send an extra test message after installation.

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
--allow-best-effort        # allow best-effort distro versions
--send-test                # send an extra install-complete test message
--skip-telegram-test       # skip Telegram preflight validation
```

## Duplicate alert modes

| Mode | Behavior |
| --- | --- |
| `always` | Send once for the same alert until the state changes. |
| `daily` | Send the same alert at most once per day. |
| `interval` | Send the same alert every N days. Default: `3`. |

`interval` is the recommended default for production servers: it prevents spam but still reminds you if a reboot stays pending.

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

Telegram credentials are stored in:

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

- `needs-restarting -r`
- `needs-restarting`
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

Packages installed as dependencies are left in place. `--purge-config` removes SUN config/state and restores apt/dnf automatic-update config when a SUN-created backup exists.

## Security notes

SUN is intentionally narrow:

- outbound HTTPS to Telegram Bot API only;
- no command receiver;
- no public HTTP endpoint;
- no automatic reboot;
- root-only Telegram credential file;
- explicit opt-in for best-effort distro support.

The release `.sha256` file protects against accidental corruption or version mismatch. It is not a substitute for a signed release if your threat model includes a compromised download source.

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
