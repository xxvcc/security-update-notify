# security-update-notify

<p align="center">
  <a href="https://github.com/xxvcc/security-update-notify/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/xxvcc/security-update-notify?style=flat-square&label=release&color=2EA043"></a>
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian-12%20%7C%2013-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-E95420?style=flat-square&logo=ubuntu&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-8%20%7C%209-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> Install security updates automatically. Get a clean Telegram and/or Feishu alert only when a reboot or service restart needs your attention.

**security-update-notify** — or **SUN** — is a small Linux utility for people who maintain servers and do not want to miss important post-update actions.

It uses your distro's native update tools, runs from a systemd timer, and makes outbound-only HTTPS requests: alerts go to the Telegram Bot API and/or Feishu Open Platform as configured; by default it also queries a public-IP echo service (api.ipify.org / ifconfig.me) for the egress IP (disable with `INCLUDE_PUBLIC_IP=0`, or set `PUBLIC_IP` manually); install and self-upgrade prefer the `dl.ll.cd` release mirror and fall back to GitHub when transport is unavailable. No dashboard. No agent port. No remote-control bot.

> Since **3.0**, installation, configuration, runtime checks, diagnostics, tests, uninstall, self-upgrade, and release packaging are implemented in Go. The only maintained shell product implementation is the first-install bootstrap, `sun.sh`. The Go packager also generates an `install.sh` launcher solely so 2.x clients can cross the major-version boundary; it only selects and `exec`s the verified Go installer, is never installed, and is not a second installer implementation. Official archives contain exactly five Linux binaries: amd64, arm64, 386, ppc64le, and s390x. There is no Bash runtime or fallback for unlisted architectures; unsupported machines are rejected before the Go installer runs (the bootstrap may already have installed its own download/verification dependencies).

The installed Go binary needs no `python3`, `curl`, or `tar` for routine checks and notifications. Self-upgrade still invokes `gpg` for signature verification, and OS/patch state still comes from the distribution's apt/dnf, needrestart/needs-restarting, and systemd commands as applicable.

**Languages**: [中文](README.md) | English

## One-line install

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash
```

The bootstrap requires `curl`, `tar`, `sha256sum`, `mktemp`, `python3`, `env`, `uname`, `gpg`, and `timeout`. When commands are missing, it first installs the corresponding bootstrap dependencies through apt, dnf, microdnf, or yum, then checks each command again. It fails before download/installation if no supported package manager exists or a command is still missing. GPG verification is mandatory by default.

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
- **Telegram and Feishu, individually or together**: Telegram keeps compact plain text while Feishu uses native JSON 2.0 cards; old configs remain Telegram-only, and dual delivery keeps separate dedup state so one failing channel does not repeat the other.
- **Reboot and service-restart detection** with `needrestart` or `needs-restarting`.
- **Patch-maintenance watchdog**: checks the auto-update mechanism, policy drift, hold/versionlock/exclude blocks, package-manager integrity, repository metadata, persistent patch backlogs, and overdue restart requirements. It also checks distro EOL and gives a weekly SUN release notice. Upgrades and restarts remain manual.
- **Single-language UI (Chinese or English)**: the installer, menu and diagnostics pick a language as the first step (Chinese or English, default Chinese) and then render all terminal interaction in that one language. The choice also becomes the default notification language, overridable with `--notify-lang`.
- **Public IP in notifications**: auto-detect the server public IP by default; you can also set it manually or disable it. Auto-detection is done by the Go runtime with the standard library and adds no `curl`/`python3` dependency.
- **Duplicate alert suppression**: once, daily, or every N days.
- **Interactive and non-interactive install/upgrade**: rerunning the installer reuses the existing config.
- **systemd timer based scheduling**.
- **No inbound network listener**.

Telegram text example (`NOTIFY_LANG=en`; Feishu presents the same state as a native card):

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

The Feishu channel sends embedded Card JSON 2.0 with `msg_type=interactive`: red for check failures or an EOL distribution, orange for reboot/service maintenance, green for successful tests or healthy state, and blue for SUN upgrades. Cards include host, IP, OS, check time, reboot state, maintenance summary, recommended commands, and a static project-documentation link. They use no tenant `template_id`; the only button opens a URL, so no event subscription, callback service, or extra permission is needed. Feishu 7.20+ fully renders JSON 2.0; older clients show only the card title and an upgrade-client prompt.

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
send to configured receiving platforms only if attention is required
```

SUN does **not**:

- reboot the server;
- expose a web service;
- accept Telegram or Feishu commands;
- use Telegram polling/webhooks or Feishu event callbacks;
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

### 1. Prepare message notifications

Telegram:

1. Open Telegram and talk to [@BotFather](https://t.me/BotFather).
2. Create a bot and copy the bot token.
3. Send `/start` to your new bot.
4. Get your target chat ID.

For groups, add the bot to the group and make sure it can send messages there.

Feishu:

1. Create a custom enterprise app in Feishu Open Platform and enable its bot.
2. Grant `directory:employee:list`, `directory:employee.base.name.name:read`, `directory:employee.base.mobile:read`, and `im:message:send_as_bot`.
3. Publish the app, include intended recipients in both its availability scope and directory data scope, and record the App ID and App Secret.

During an interactive install, SUN accepts the App ID and a hidden App Secret, then paginates through active employees visible via Directory v1. It shows a numbered “localized Chinese name + mobile tail + `open_id`” list. Only the selected `open_id` is persisted; the name and mobile tail are shown only for human verification. Runtime notifications send native JSON 2.0 cards directly to that `open_id` without querying the directory on every run. An `open_id` can differ between Feishu apps and must not be copied across apps; changing the App ID during an upgrade clears the previous recipient and requires a new selection or explicit `open_id`.

### 2. Install

#### High-assurance first install (recommended for production)

This procedure never pipes a network response into a shell. First confirm an explicit version from a trusted release announcement and replace `X.Y.Z` below. It downloads the versioned `sun.sh`, detached signature, and public key into a root-owned temporary directory, checks the pinned primary-key fingerprint and the critical version notation in the signature, and executes the script only after every check succeeds. The machine must already have `bash`, `curl`, and `gpg`; install them first through the distribution package manager or trusted offline media.

```bash
sudo bash <<'SUN_ROOT'
set -euo pipefail

SUN_VERSION='X.Y.Z' # replace with an explicit version confirmed through a trusted announcement
SUN_PIN='C678256ACBFC6491BF5076655F3AE24999921FFC'
SUN_NOTATION='release-version@xxv.cc'
[[ "$SUN_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([._-][0-9A-Za-z]+)?$ \
   && "${#SUN_VERSION}" -le 64 ]] || {
  echo 'Set SUN_VERSION to an explicit version, for example 3.0.2.' >&2
  exit 2
}

SUN_BASE="https://dl.ll.cd/security-update-notify/v${SUN_VERSION}"
SUN_WORK="$(mktemp -d)"
trap 'rm -rf "$SUN_WORK"' EXIT
chmod 0700 "$SUN_WORK"
mkdir "$SUN_WORK/gnupg"
chmod 0700 "$SUN_WORK/gnupg"

for asset in sun.sh sun.sh.asc release-signing.pub.asc; do
  curl --disable --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --connect-timeout 20 --retry 4 --retry-delay 1 --retry-max-time 180 \
    --max-filesize 1048576 \
    --output "$SUN_WORK/$asset" "$SUN_BASE/$asset"
done

gpg_cmd=(gpg --no-options --batch --no-tty --homedir "$SUN_WORK/gnupg")
"${gpg_cmd[@]}" --import "$SUN_WORK/release-signing.pub.asc" >/dev/null 2>&1
primary_fingerprints=()
want_primary=0
while IFS=: read -r -a fields; do
  case "${fields[0]:-}" in
    pub) want_primary=1 ;;
    fpr)
      if [[ "$want_primary" -eq 1 ]]; then
        primary_fingerprints+=("${fields[9]:-}")
        want_primary=0
      fi
      ;;
  esac
done < <("${gpg_cmd[@]}" --with-colons --list-keys 2>/dev/null)
[[ "${#primary_fingerprints[@]}" -eq 1 \
   && "${primary_fingerprints[0]}" == "$SUN_PIN" ]] || {
  echo 'The release key is not the sole primary key with the pinned fingerprint; refusing to execute.' >&2
  exit 1
}

status="$("${gpg_cmd[@]}" --known-notation "$SUN_NOTATION" --status-fd=1 --show-notation \
  --verify "$SUN_WORK/sun.sh.asc" "$SUN_WORK/sun.sh" 2>"$SUN_WORK/gpg.log")" || {
  cat "$SUN_WORK/gpg.log" >&2
  exit 1
}
valid_count=0
pinned_count=0
name_count=0
name_match=0
flags_count=0
flags_match=0
data_count=0
data_match=0
while read -r -a fields; do
  [[ "${fields[0]:-}" == '[GNUPG:]' ]] || continue
  case "${fields[1]:-}" in
    VALIDSIG)
      valid_count=$((valid_count + 1))
      last="${fields[${#fields[@]}-1]:-}"
      if [[ "${fields[2]:-}" == "$SUN_PIN" || "$last" == "$SUN_PIN" ]]; then
        pinned_count=$((pinned_count + 1))
      fi
      ;;
    NOTATION_NAME)
      name_count=$((name_count + 1))
      [[ "${#fields[@]}" -eq 3 && "${fields[2]:-}" == "$SUN_NOTATION" ]] &&
        name_match=$((name_match + 1))
      ;;
    NOTATION_FLAGS)
      flags_count=$((flags_count + 1))
      [[ "${#fields[@]}" -eq 4 && "${fields[2]:-}" == 1 && "${fields[3]:-}" == 1 ]] &&
        flags_match=$((flags_match + 1))
      ;;
    NOTATION_DATA)
      data_count=$((data_count + 1))
      [[ "${#fields[@]}" -eq 3 && "${fields[2]:-}" == "$SUN_VERSION" ]] &&
        data_match=$((data_match + 1))
      ;;
  esac
done <<<"$status"
[[ "$valid_count" -eq 1 && "$pinned_count" -eq 1 \
   && "$name_count" -eq 1 && "$name_match" -eq 1 \
   && "$flags_count" -eq 1 && "$flags_match" -eq 1 \
   && "$data_count" -eq 1 && "$data_match" -eq 1 ]] || {
  echo 'The bootstrap signature is not uniquely bound to the pinned fingerprint and target version; refusing to execute.' >&2
  exit 1
}

chmod 0700 "$SUN_WORK/sun.sh"
bash "$SUN_WORK/sun.sh" --version "$SUN_VERSION" --base-url "$SUN_BASE"
SUN_ROOT
```

An explicit version is part of this trust boundary: `latest.json` is an availability index, not a signed freshness proof. The hashed subpackets in `sun.sh.asc` contain the critical notation `release-version@xxv.cc=<version>`; verification authenticates the script bytes and requires this value to match the version confirmed by the administrator, so an older valid script and signature cannot be moved into a newer version directory. The versioned `sun.sh`, `sun.sh.asc`, and public key appear only after the mirror workflow verifies the signed archive and tag source, then reads the files back from the public mirror. The downloaded key file is not itself the trust root; the pinned fingerprint, which should also be checked through an independent trusted channel, is.

#### Convenient one-line install (compatibility entry point)

The website-hosted bootstrap downloads the latest signed Release, verifies the `.sha256` file and GPG signature (required by default), then opens the interactive menu:

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash
```

This command preserves the existing experience, but the downloaded `sun.sh` executes before that script has been checked against its detached signature. The first stage therefore trusts HTTPS, the domain, and the mirror/CDN; verifying the Release afterward cannot retroactively authenticate code that already ran. Use the high-assurance procedure above when the threat model includes a compromised download host or TLS endpoint.

When starting from the URL, `curl` must already be installed: the bootstrap cannot install a command before the script itself has been obtained. `set -o pipefail` makes a missing `curl`, DNS/TLS error, or failed download fail the complete pipeline instead of allowing the trailing `bash` to read empty input and report success. Once running, the bootstrap requires `curl`, `tar`, `sha256sum`, `mktemp`, `python3`, `env`, `uname`, `gpg`, and `timeout`. It installs only the packages corresponding to missing commands through apt, dnf, microdnf, or yum and then checks each command again; this avoids replacing `curl-minimal/coreutils-single` with conflicting full packages on minimal RPM systems. It fails before downloading or installing SUN when no supported package manager exists or a command is still missing. Release GPG verification is required by default.

If you prefer running from source:

```bash
git clone https://github.com/xxvcc/security-update-notify.git
cd security-update-notify
source ./VERSION
arch="$(go env GOARCH)"
case "$arch" in amd64|arm64|386|ppc64le|s390x) ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac
./build/build.sh linux "$arch" "$VERSION" ./security-update-notify
sudo ./security-update-notify install
```

Source builds require the Go toolchain pinned by `go.mod`, and the current machine must use one of the five release architectures above. `build/build.sh` injects the canonical root `VERSION`; do not install a plain `go run` or `go build` binary whose version was not injected.

The installer first asks for a UI language (Chinese or English, default Chinese), then lets you select Telegram, Feishu, or both platforms. It asks for the matching receiving-platform credentials:

- Telegram Bot Token / Chat ID; and/or
- Feishu App ID / hidden App Secret, followed by a recipient choice from the automatic scan;
- daily check time, default `09:00`;
- duplicate-alert behavior;
- whether to send a test message after installation; the first Feishu setup or an app, App Secret, or recipient change defaults to a Feishu-only verification message, which can be skipped with `n`.

To skip the interactive language prompt, pass `--lang zh` or `--lang en`.

Before writing the config, it performs receiving-platform preflight checks:

- Telegram: `getMe` validates the bot token, then `sendMessage` validates the chat ID and permission. Connection resets, timeouts, HTTP 429, and 5xx responses are retried three times. A persistent temporary network failure is not mislabeled as an invalid token and does not clear existing credentials; interactive mode can retry, skip this preflight, or abort, while non-interactive mode fails with exit `75` and rolls back;
- Feishu: obtains a `tenant_access_token` and scans active employees in the application's directory scope. If an `open_id` was supplied explicitly, it performs only the application-credential preflight. No message is sent during installation preflight.

Results are limited by the Feishu application's directory data scope. If scanning fails or returns no visible employees, the interactive installer can retry, accept a current-app `open_id` manually, or abort. Non-interactive mode requires `--feishu-receive-id` explicitly.

On the first Feishu setup or after changing the app, App Secret, or recipient, the installer sends a Feishu-only strong verification message by default to confirm that the selected `open_id` is within the bot availability; enter `n` in interactive mode, use `--skip-feishu-test`, or use `--skip-notify-test` to skip it explicitly. Non-interactive mode does not prompt, but performs the same strong verification by default. Strong verification waits up to 60 seconds for the runtime lock and rolls the transaction back on timeout or send failure, so “not sent” cannot be mistaken for success. Explicit `--send-test` additionally tests every configured receiving platform after installation and overrides skip only for that extra send; this extra test is advisory, so failure warns without rolling back the completed core installation or disabling its timer. The standalone `security-update-notify test --send-test` command still reports its own send result through its exit code.

### 3. Verify

```bash
sudo security-update-notify test
sudo security-update-notify test --send-test --no-dedupe
sudo security-update-notify test --simulate-reboot --no-dedupe
```

The simulated reboot test only sends a test alert. It does **not** reboot the server.

## Non-interactive install

Useful for provisioning scripts:

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash -s -- install \
  --notify-channels telegram \
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

For non-interactive Feishu installation, provide the App Secret through a separate root-only source file. Do not put it in `.env` or on the command line:

```bash
sudo install -m 600 /dev/null /root/.security-update-notify-feishu-secret
sudoedit /root/.security-update-notify-feishu-secret

set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash -s -- install \
  --notify-channels feishu \
  --feishu-app-id 'cli_xxx' \
  --feishu-receive-id 'ou_xxx' \
  --feishu-app-secret-file /root/.security-update-notify-feishu-secret \
  --non-interactive \
  -y
```

The App Secret source must be a root-owned regular file, not a symlink, with no group or other access (`0600` recommended). The installer validates these conditions and detects replacement during path validation before reading it.

The installer stores the App Secret as an encrypted systemd credential when available. Older systemd versions fall back to a separate root-only `0600` file. Neither form enters the normal config or upgrade backups.

After a successful install and credential check, remove the source file unless it is a stable entry point maintained by an external secret manager. This avoids retaining an unnecessary plaintext copy of the App Secret.

For safer automation, use a local `.env` file so the token does not appear in shell history or process lists:

```bash
cp .env.example .env
chmod 600 .env
sudoedit .env

set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | \
  sudo bash -s -- install --env-file "$PWD/.env" --non-interactive -y
```

You can also keep only the token in a root-only file:

```bash
sudo install -m 600 /dev/null /root/.security-update-notify-token
sudoedit /root/.security-update-notify-token

set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash -s -- install \
  --telegram-token-file /root/.security-update-notify-token \
  --telegram-chat-id 'CHAT_ID' \
  --non-interactive \
  -y
```

Common options:

```bash
--env-file FILE            # read install config from dotenv-style file, recommended for automation
--notify-channels LIST      # telegram | feishu | telegram,feishu
--telegram-token-file FILE # read Telegram Bot Token from file
--feishu-app-id APP_ID      # Feishu application App ID
--feishu-receive-id OPEN_ID # explicit recipient override; required non-interactively
--feishu-app-secret-file F  # read App Secret from a separate file
--backend apt              # force apt backend
--backend dnf              # force dnf backend
--notify-lang zh           # notification language: Chinese, default
--notify-lang en           # notification language: English
--lang en                  # terminal interaction language: English (default zh)
--public-ip IP             # manually set public IP in notifications; auto-detected at runtime when empty
--include-public-ip 0      # disable public IP in notifications; default 1
--notify-ok 1             # send OK notification when no action is needed; default 0
--notify-upgrade 1        # notify configured receiving platforms after successful upgrade; default 0
--skip-post-install-check # skip post-install/upgrade self-check
--allow-best-effort        # allow best-effort distro versions
--lock-wait SECONDS       # runtime-lock barrier, 0..3600 seconds; default 60
--send-test                # extra all-platform test; failure warns but does not roll back installation
--skip-telegram-test       # skip Telegram preflight validation
--skip-feishu-test         # skip Feishu preflight/default strong verification; selection still scans if needed
--skip-notify-test         # skip all preflights/default Feishu verification; explicit --send-test still sends
```

Once SUN is installed, `sudo security-update-notify install [options]` runs the same Go installer directly. Use `sudo security-update-notify configure notifications` to manage message notification settings transactionally on an existing installation.


### Upgrade

Rerun the one-line installer to upgrade to the latest release:

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash -s -- upgrade --non-interactive -y
```

Once SUN is installed you can also run `sudo security-update-notify upgrade` directly. Both the bootstrap and built-in upgrade first read `https://dl.ll.cd/security-update-notify/latest.json` and download the signed assets from that mirror; they fall back to GitHub when the mirror index or complete asset-set transfer is unavailable. The downloaded package still must pass `.sha256` and GPG verification against the embedded pinned fingerprint (fail-closed by default; a missing signature is rejected). The mirror improves transport availability but is not a trust root.

Only after all CI checks for an official GitHub Release pass does the `Mirror signed release` workflow re-verify and sync its versioned directory. It uses the verifier and offline fingerprint fixed in the default-branch workflow revision, treats the release tag only as non-executed data, and obtains deployment credentials from a GitHub Environment restricted to `main`. New releases must also contain `sun.sh.asc`, produced by the Go packager with the same offline key and bound to the explicit version. The workflow extracts `sun.sh` and the public key from the verified archive, verifies the bootstrap signature and version notation, and reads the complete versioned set back from `dl.ll.cd` before updating the compatibility stable `sun.sh` and finally `latest.json`. Manually rerunning an older release only repairs that version directory and cannot replace the stable bootstrap or current Latest manifest. Repository Release immutability is enabled; after every successful mirror and each Monday, an independent real GitHub-hosted Ubuntu 22.04/24.04 canary redownloads both public sources and exercises signature verification, installation, doctor, dry-run, timer state, uninstall, and APT-policy restoration.

If SUN is already installed, the installer reads `/etc/security-update-notify/telegram.env` and the existing timer time and keeps every setting that was not explicitly overridden. Run `sudo security-update-notify configure notifications` to change receiving platforms, Telegram credentials, the Feishu app, App Secret, or recipient transactionally. Removing a platform deletes its stored credentials; adding or editing one revalidates only that platform. Any failure rolls the whole installer transaction back. Legacy configs without `NOTIFY_CHANNELS` remain `telegram`, and other options not explicitly overridden keep their old values.

Before upgrading, key files are backed up to `/var/backups/security-update-notify/<timestamp>`, but the Feishu App Secret is not copied there; failed upgrades attempt an automatic rollback and restore the SUN timer's pre-install enablement link and active state. A post-upgrade self-check runs by default; use `--notify-upgrade 1` to notify the configured receiving platforms after a successful upgrade. Upgrade notices are best-effort: a notification failure never rolls back a completed upgrade, and the whole dual-send is not retried in a way that would duplicate a successful platform.

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
| `CHECK_EOL` | `1` | Distro end-of-life (EOL) warning: a past-EOL release triggers an alert, an approaching one (within 90 days) is informational. Set `0` if you have extended support such as Ubuntu ESM. |

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
/var/log/security-update-notify.log
```

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

The installer enables unattended-upgrades security update timers. Before each overwrite of `/etc/apt/apt.conf.d/20auto-upgrades`, it saves a timestamped SUN-specific backup. If the file existed before SUN, the first install also preserves a fixed original baseline; if it was absent, SUN records a validated, rollback-protected absence marker before package-manager writes. Metadata stored in the APT configuration directory ends in `.bak`, so apt silently ignores it instead of printing invalid-extension notices; upgrades migrate the older names. `--purge-config` restores the fixed baseline or removes the file to restore original absence, then deletes SUN's baseline, marker, and timestamped backups.

It checks:

- `/var/run/reboot-required`
- `/var/run/reboot-required.pkgs`
- `needrestart -b`

### RHEL-compatible / Fedora (`dnf`)

SUN configures or uses:

- `dnf-automatic`
- `yum-utils` or `dnf-utils`
- `ca-certificates`

It checks:

- `needs-restarting -r` (whether a full reboot is required)
- `needs-restarting -s` (systemd services that need a restart; no longer the raw `needs-restarting` process list, which caused false alerts)
- `dnf updateinfo list security updates`

If `/etc/dnf/automatic.conf` exists, SUN preserves one fixed original baseline when it first takes ownership, saves an additional timestamped copy before each overwrite, then configures security-only automatic updates. An upgrade from an older installation migrates the earliest SUN timestamped backup into that baseline; a normal uninstall followed by reinstall does not replace it. `--purge-config` restores the fixed original baseline and removes SUN's fixed and timestamped backups.

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

Packages installed as dependencies are left in place. `--purge-config` removes SUN config, Telegram/Feishu credentials, state, upgrade backups (which may contain bot-token copies) and rotated logs, and restores apt/dnf automatic-update config when a SUN-created backup exists.

## Release signatures

Release packages always include a `.sha256` checksum file. When the key is available, `go run ./cmd/sun-release package` creates two detached signatures: `.tar.gz.asc` for the archive and `sun.sh.asc` for the first-install bootstrap; the latter also carries a critical version notation in its hashed signature subpackets. Both are required for an official release or an existing version tag; an explicit `--sign off` is rejected before any `dist` file is created in either case. `sun.sh` defaults to `required` verification of the downloaded Release; `auto` is kept only as a compatibility alias and also requires gpg and the archive `.asc`. Only an explicit `--verify-signature off` skips Release signature verification.

Root `VERSION`, in the exact form `VERSION="X.Y.Z"`, is the single source of truth. Official releases (a corresponding `vX.Y.Z` tag or `RELEASE=1`) are **signed and fixed to all five Go architectures**. The Go release tool binds that root version to the unique CHANGELOG heading, tag, packaged version, and every binary's `--version`; the architecture set cannot be overridden. It fails when Go, Bash (used only to syntax-check `sun.sh`), any amd64/arm64/386/ppc64le/s390x build, or the GPG private key matching the pinned fingerprint is missing. Explicit GitHub Release assets are the tarball, checksum, tarball signature, and `sun.sh.asc`: both release CI and the mirror gate verify this exact four-asset set and bind the bootstrap signature to `sun.sh` from the verified archive, the pinned primary key, and the explicit release version. The private key never enters CI; it stays offline with the maintainer. In addition, `security-update-notify upgrade` is **fail-closed** by default: it prefers the fixed release mirror and falls back to GitHub, verifies sha256, and requires a GPG signature against an embedded public key and pinned fingerprint before extracting and upgrading (set `SECURITY_UPDATE_NOTIFY_UPGRADE_ALLOW_UNSIGNED=1` to upgrade on sha256 only in an emergency).

## Security notes

SUN is intentionally narrow:

- outbound HTTPS only: alerts to the Telegram Bot API and/or `open.feishu.cn` as configured; by default also a public-IP echo service (api.ipify.org / ifconfig.me) for the egress IP (disable with `INCLUDE_PUBLIC_IP=0`); install and self-upgrade prefer `dl.ll.cd` and fall back to GitHub. If you lock this down with an egress firewall, allow those destinations or disable the corresponding features;
- no command receiver;
- no public HTTP endpoint;
- no automatic reboot;
- root-only normal notification config; the Feishu App Secret uses a separate systemd/root credential and never enters normal config, command lines, logs, or upgrade backups;
- explicit opt-in for best-effort distro support.

The release `.sha256` file protects against accidental corruption or version mismatch. If your threat model includes a compromised download source, keep the default signature verification enabled and do not use `--verify-signature off` or the unsigned-upgrade escape hatch.

The archive signature authenticates Release contents; before any first execution, `sun.sh.asc` authenticates the bootstrap bytes and binds them to their release version through a critical notation. The convenient `curl | bash` path cannot use the latter because it has already run the code; only the high-assurance procedure treats the fixed fingerprint as the initial trust anchor outside the network. Signatures do not prove which version is latest and do not protect a compromised local root account, `gpg`, or shell, so an administrator must confirm the intended version and fingerprint through an independent trusted channel.

## Build a release package

From the source checkout:

```bash
bash -n sun.sh build/*.sh
shellcheck -s bash -S warning sun.sh build/*.sh
unformatted="$(rg --files cmd internal -g '*.go' -0 | xargs -0 gofmt -l)"
test -z "$unformatted"
go vet ./...
go test -race -cover ./...
build/archive-safety-test.sh
build/runtime-lock-test.sh
build/reproducibility-check.sh linux amd64
docker run --rm -e SUN_CONTAINER_TEST=1 -v "$PWD:/src:ro" debian:12 bash /src/build/compat-test.sh
docker run --rm -e SUN_CONTAINER_TEST=1 -v "$PWD:/src:ro" debian:12 bash /src/build/rollback-test.sh
go run ./cmd/sun-release package
cd dist && sha256sum -c security-update-notify-*.tar.gz.sha256
```

`build/compat-test.sh` and `build/rollback-test.sh` modify system paths and must only be run with the disposable Docker commands above, never directly on the host. An official release must also pass CI's five-architecture execution, hostile-archive, signature, and public-asset verification gates.

Generated files:

```text
dist/security-update-notify-VERSION.tar.gz
dist/security-update-notify-VERSION.tar.gz.sha256
dist/security-update-notify-VERSION.tar.gz.asc  # signed build
dist/sun.sh.asc                                  # signed build, high-assurance first install
```

The release archive contains only user-facing installation, diagnostic, bootstrap, migration-compatibility, and documentation files. `sun.sh` is included in the signed archive; signed builds also create `sun.sh.asc` outside the archive so nondeterministic signature time never enters the reproducible tarball. The mirror extracts the script and key from the verified archive and publishes them with the detached signature in the immutable version directory; the compatibility stable URL still serves only `sun.sh`. `install.sh` and `files/security-update-notify` are generated by the Go packager as a minimal launcher and version marker for old 2.x self-upgrade clients. They contain no legacy installer/runtime logic and are never installed.

Release archive contents:

```text
.env.example
CHANGELOG.md
LICENSE
README.md
README.en.md
VERSION
sun.sh
install.sh                              # 2.x -> 3.0 Go launcher only
files/needrestart-report-only.conf
files/release-signing.pub.asc
files/security-update-notify            # old-client version marker only
files/security-update-notify.logrotate
files/security-update-notify.service
files/security-update-notify-linux-amd64
files/security-update-notify-linux-arm64
files/security-update-notify-linux-386
files/security-update-notify-linux-ppc64le
files/security-update-notify-linux-s390x
```

## License

MIT. See [LICENSE](LICENSE).
