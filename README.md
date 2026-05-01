# security-update-notify

`security-update-notify` (SUN) is a small systemd-based Linux utility that installs unattended **security** updates, checks whether a reboot or service restart is needed, and sends Telegram alerts only when attention is required.

It is designed for people who manage multiple servers and want fast security update coverage without exposing a remote-control endpoint.

## Highlights

- Automatic security updates via the distribution's official mechanism
- No automatic reboot
- Reboot/service-restart detection
- Telegram notifications via outbound HTTPS only
- Duplicate-alert suppression (`always`, `daily`, or `interval`)
- Interactive menu and non-interactive install modes
- `apt` and `dnf` backends
- systemd timer scheduling
- Release packaging and checksum generation

## Security posture

SUN is intentionally notification-only:

- It does **not** reboot servers automatically.
- It does **not** listen on any network port.
- It does **not** use Telegram long polling or webhooks.
- It only sends outbound HTTPS requests to the Telegram Bot API.
- Telegram credentials are stored in `/etc/security-update-notify/telegram.env` with root-only permissions (`0600`).
- Runtime state is stored in `/var/lib/security-update-notify`.
- Logs are written to `/var/log/security-update-notify.log` and rotated with logrotate when available.
- Best-effort distributions require explicit `--allow-best-effort` opt-in.

Release `.sha256` files protect against accidental corruption or mismatch. They do **not** protect against a compromised release host. Stronger artifact signing may be added later.

## Supported systems

The installer is intentionally strict and stops on unsupported distributions.

### Supported

- Debian 12 / 13 (`apt` backend)
- Ubuntu 22.04 / 24.04 (`apt` backend)
- RHEL / Rocky Linux / AlmaLinux 8 / 9 (`dnf` backend)
- Fedora current releases (`dnf` backend)

### Best effort (`--allow-best-effort` required)

- Debian 11
- Ubuntu 20.04
- CentOS Stream 8 / 9
- Amazon Linux 2023

### Not supported yet

- Alpine
- Arch Linux
- SUSE / openSUSE
- Containers or minimal systems without full systemd
- EOL systems without active security repositories

## Backends

### `apt` backend

Installs/configures:

- `unattended-upgrades`
- `needrestart`
- `apt-listchanges`
- apt periodic timers

Detection:

- `/var/run/reboot-required`
- `/var/run/reboot-required.pkgs`
- `needrestart -b`

### `dnf` backend

Installs/configures:

- `dnf-automatic`
- `yum-utils` or `dnf-utils`
- `curl`, `python3`, `ca-certificates`

Detection:

- `needs-restarting -r`
- `needs-restarting`
- `dnf updateinfo list security updates`

When `/etc/dnf/automatic.conf` exists, the installer configures `dnf-automatic` with:

```ini
upgrade_type = security
apply_updates = yes
```

## Installation

### Interactive menu

```bash
sudo ./menu.sh
```

Menu:

```text
1) Install / upgrade
2) Uninstall
3) Check / diagnose
0) Exit
```

### Direct interactive install

```bash
sudo ./install.sh
```

Prompts for:

- Telegram Bot Token (hidden input; press Enter when done)
- Telegram Chat ID
- Daily check time, default `09:00`
- Same-alert reminder mode:
  - `always`: same alert only once until state changes
  - `daily`: same alert once per day
  - `interval`: same alert every N days, default/recommended `3`
- Whether to send an additional test message after install

Telegram validation runs by default after token and chat ID are entered:

- `getMe` validates the bot token
- `sendMessage` validates the chat ID and bot permissions
- Use `--skip-telegram-test` only when intentionally skipping this preflight

### Non-interactive install

```bash
sudo ./install.sh \
  --telegram-token '123456:ABC...' \
  --telegram-chat-id 'CHAT_ID' \
  --time '09:00' \
  --dedup-mode interval \
  --dedup-interval-days 3 \
  --non-interactive \
  -y
```

Optional flags:

```bash
sudo ./install.sh --backend apt ...
sudo ./install.sh --backend dnf ...
sudo ./install.sh --allow-best-effort ...
sudo ./install.sh --host-label 'prod-web-01' ...
sudo ./install.sh --skip-telegram-test ...
```

## One-command bootstrap installer

`sun.sh` is the website/bootstrap installer. Publish it at a stable URL, for example:

```text
https://example.com/install/sun.sh
```

Before publishing, edit its default `REPO`, or provide it at runtime:

```bash
curl -fsSL https://example.com/install/sun.sh | sudo SECURITY_UPDATE_NOTIFY_REPO='OWNER/security-update-notify' bash
```

Interactive menu:

```bash
curl -fsSL https://example.com/install/sun.sh | sudo bash
```

Non-interactive install:

```bash
curl -fsSL https://example.com/install/sun.sh | sudo bash -s -- install \
  --telegram-token 'TOKEN' \
  --telegram-chat-id 'CHAT_ID' \
  --non-interactive \
  -y
```

The bootstrap script downloads the release tarball and `.sha256`, verifies the checksum, extracts the package, then runs `menu.sh`, `install.sh`, `test.sh`, or `uninstall.sh`.

## What gets installed

- `/usr/local/sbin/security-update-notify`
- `/etc/security-update-notify/telegram.env`
- `/etc/systemd/system/security-update-notify.service`
- `/etc/systemd/system/security-update-notify.timer`
- `/etc/logrotate.d/security-update-notify` when logrotate is available
- backend-specific automatic security update configuration

Packages installed as needed:

- `apt`: `unattended-upgrades`, `needrestart`, `apt-listchanges`, `curl`, `python3`, `ca-certificates`
- `dnf`: `dnf-automatic`, `yum-utils` or `dnf-utils`, `curl`, `python3`, `ca-certificates`

## Testing and diagnostics

Read-only checks:

```bash
sudo ./test.sh
```

Send a normal OK test message:

```bash
sudo ./test.sh --send-test --no-dedupe
```

Send a simulated reboot-required alert. This does **not** reboot:

```bash
sudo ./test.sh --simulate-reboot --no-dedupe
```

Installed command diagnostics:

```bash
security-update-notify --version
sudo security-update-notify --doctor
```

Useful systemd/log commands:

```bash
systemctl list-timers security-update-notify.timer
sudo systemctl start security-update-notify.service
sudo tail -n 100 /var/log/security-update-notify.log
```

## Uninstall

Remove the program and system integration while keeping configuration/state:

```bash
sudo ./uninstall.sh
```

Remove configuration and state too:

```bash
sudo ./uninstall.sh --purge-config
```

Packages installed by the tool are intentionally left installed.

## Release packaging

Create a GitHub Release artifact:

```bash
./package.sh
```

This creates:

```text
dist/security-update-notify-VERSION.tar.gz
dist/security-update-notify-VERSION.tar.gz.sha256
```

## Repository layout

```text
.github/workflows/ci.yml      GitHub Actions CI
CHANGELOG.md                  Release notes
LICENSE                       MIT license
README.md                     Project documentation
sun.sh                        Website/bootstrap installer
install.sh                    Installer
menu.sh                       Interactive menu
package.sh                    Release package builder
test.sh                       Diagnostics/test helper
uninstall.sh                  Uninstaller
files/                        Installed runtime templates
```

## Development

Run local checks before committing:

```bash
bash -n install.sh menu.sh test.sh uninstall.sh package.sh sun.sh files/security-update-notify
./package.sh
cd dist && sha256sum -c security-update-notify-*.tar.gz.sha256
```

GitHub Actions runs the same syntax and packaging checks on push and pull requests.

## License

MIT. See [`LICENSE`](LICENSE).
