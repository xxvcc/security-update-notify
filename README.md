# security-update-notify

Portable security-update notifier for systemd Linux servers.

It configures unattended security updates, keeps automatic reboot disabled, checks whether reboot/service restarts are needed, then sends Telegram alerts only when attention is needed.

No public callback endpoint. No Telegram polling. No remote reboot button. Multiple servers can reuse the same Telegram bot token and chat ID because each host only calls `sendMessage`.

## Supported systems

The installer is intentionally strict and stops on unsupported distributions.

Supported:

- Debian 12 / 13 (`apt` backend)
- Ubuntu 22.04 / 24.04 (`apt` backend)
- RHEL / Rocky / AlmaLinux 8 / 9 (`dnf` backend)
- Fedora current releases (`dnf` backend)

Best effort (requires `--allow-best-effort`):

- Debian 11
- Ubuntu 20.04
- CentOS Stream 8 / 9
- Amazon Linux 2023

Not supported yet:

- Alpine, Arch, SUSE/openSUSE
- Containers or minimal systems without full systemd
- EOL systems without active security repositories

## Backends

### apt backend

Installs/configures:

- `unattended-upgrades`
- `needrestart`
- `apt-listchanges`
- apt periodic timers

Detection:

- `/var/run/reboot-required`
- `/var/run/reboot-required.pkgs`
- `needrestart -b`

### dnf backend

Installs/configures:

- `dnf-automatic`
- `yum-utils` or `dnf-utils`
- `curl`, `python3`, `ca-certificates`

Detection:

- `needs-restarting -r`
- `needs-restarting`
- `dnf updateinfo list security updates`

The DNF backend configures `dnf-automatic` with `upgrade_type = security` and `apply_updates = yes` where `/etc/dnf/automatic.conf` exists.

## What it installs

- `/usr/local/sbin/security-update-notify`
- `/etc/security-update-notify/telegram.env` (`0600`, contains bot token)
- `/etc/systemd/system/security-update-notify.service`
- `/etc/systemd/system/security-update-notify.timer`
- backend-specific automatic security update configuration

## Interactive menu

```bash
sudo ./menu.sh
```

The interactive entry starts with:

```text
1) 安装 / 升级
2) 卸载
3) 检测 / 诊断
0) 退出
```

## Interactive install directly

```bash
sudo ./install.sh
```

Prompts for:

- Telegram Bot Token（隐藏输入；Token 输入时不会回显，输完按回车即可）
- Telegram Chat ID
- Daily check time, default `09:00`
- Same-alert reminder mode:
  - `always`: same alert only once until state changes
  - `daily`: same alert once per day
  - `interval`: same alert every N days, default/recommended `3`
- Whether to send a test message


Telegram validation is run by default after entering token and chat ID:

- `getMe` validates the bot token
- `sendMessage` validates the chat ID and bot permissions
- use `--skip-telegram-test` only if you intentionally want to skip this preflight

## Non-interactive install

```bash
sudo ./install.sh \
  --telegram-token '123456:ABC...' \
  --telegram-chat-id 'CHAT_ID' \
  --time '09:00' \
  --dedup-mode interval \
  --dedup-interval-days 3 \
  --send-test \
  --non-interactive \
  -y
```

Force backend if needed:

```bash
sudo ./install.sh --backend apt ...
sudo ./install.sh --backend dnf ...
```


Best-effort systems require explicit opt-in:

```bash
sudo ./install.sh --allow-best-effort ...
```

Optional host label:

```bash
sudo ./install.sh --host-label 'prod-web-01' ...
```

## Test

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

## Useful commands

Check timer:

```bash
systemctl list-timers security-update-notify.timer
```

Run once manually:

```bash
sudo systemctl start security-update-notify.service
```

Run script directly:

```bash
sudo /usr/local/sbin/security-update-notify --test-ok --no-dedupe
```

Version:

```bash
security-update-notify --version
```

Doctor/config check:

```bash
sudo security-update-notify --doctor
```

Logs:

```bash
sudo tail -n 100 /var/log/security-update-notify.log
```



## Security notes

This tool is designed to reduce update lag without adding a remote-control surface.

- It does **not** automatically reboot servers.
- It does **not** listen on any network port.
- It does **not** use Telegram long polling or webhooks.
- It only sends outbound HTTPS requests to the Telegram Bot API.
- The Telegram token is stored in `/etc/security-update-notify/telegram.env` with root-only permissions (`0600`).
- Runtime state is stored under `/var/lib/security-update-notify`.
- Logs are written to `/var/log/security-update-notify.log` and rotated via logrotate when available.
- `best-effort` distributions require explicit `--allow-best-effort` opt-in.
- Release `.sha256` files protect against accidental corruption/mismatch, not against a compromised release host. Stronger signing may be added later.

Before deploying widely, test on one non-critical host first:

```bash
sudo ./test.sh --send-test --no-dedupe
sudo ./test.sh --simulate-reboot --no-dedupe
```

## Security model

- Updates are handled by the distro's official unattended update mechanism.
- Only security updates are enabled by the local policy where the distro supports that distinction.
- Automatic reboot is disabled.
- Restart detectors are report-only; they do not auto-restart services.
- Telegram token is root-only in `/etc/security-update-notify/telegram.env`.
- The script only sends outbound Telegram HTTPS requests; it does not listen on any port.

## Uninstall

```bash
sudo ./uninstall.sh
```

Remove config/state too:

```bash
sudo ./uninstall.sh --purge-config
```

Packages are intentionally left installed.

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

## Website bootstrap installer

Publish `bootstrap-install.sh` to your website, for example:

```text
https://example.com/install/security-update-notify.sh
```

Edit its default `REPO` first, or provide it at runtime:

```bash
curl -fsSL https://example.com/install/security-update-notify.sh | sudo SECURITY_UPDATE_NOTIFY_REPO='OWNER/security-update-notify' bash
```

Interactive menu:

```bash
curl -fsSL https://example.com/install/security-update-notify.sh | sudo bash
```

Non-interactive install:

```bash
curl -fsSL https://example.com/install/security-update-notify.sh | sudo bash -s -- install \
  --telegram-token 'TOKEN' \
  --telegram-chat-id 'CHAT_ID' \
  --non-interactive \
  -y
```

The bootstrap downloads the release tarball and `.sha256`, verifies checksum, then runs `menu.sh`, `install.sh`, `test.sh`, or `uninstall.sh`.

## Log rotation

The installer adds `/etc/logrotate.d/security-update-notify` when logrotate is available.

## Project metadata

- Changelog: `CHANGELOG.md`
- License: MIT, see `LICENSE`
- CI: `.github/workflows/ci.yml`
