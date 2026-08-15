# Installation and upgrade

[中文](installation.md) | [Back to README](../README.en.md)

This guide is for administrators installing or automating SUN. It covers notification setup, verified first install, the convenient bootstrap, non-interactive options, validation, and upgrades.

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

This procedure never pipes a network response into a shell. First confirm an explicit version from a trusted release announcement and replace `X.Y.Z` below. It downloads the versioned `sun.sh`, detached signature, and public key into a root-owned temporary directory, checks the pinned primary-key fingerprint and the critical version notation in the signature, and executes the script only after every check succeeds. The machine must already have `bash`, `curl`, `python3`, and `gpg`; install them first through the distribution package manager or trusted offline media.

```bash
sudo /bin/bash -p <<'SUN_ROOT'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

SUN_VERSION='X.Y.Z' # replace with an explicit version confirmed through a trusted announcement
SUN_PIN='C678256ACBFC6491BF5076655F3AE24999921FFC'
SUN_NOTATION='release-version@xxv.cc'
[[ "$SUN_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([._-][0-9A-Za-z]+)?$ \
   && "${#SUN_VERSION}" -le 64 ]] || {
  echo 'Replace X.Y.Z in SUN_VERSION with an explicit version confirmed through a trusted release announcement.' >&2
  exit 2
}

SUN_BASE="https://dl.ll.cd/security-update-notify/v${SUN_VERSION}"
SUN_WORK="$(mktemp -d /tmp/security-update-notify.XXXXXX)"
trap 'rm -rf "$SUN_WORK"' EXIT
chmod 0700 "$SUN_WORK"
mkdir "$SUN_WORK/gnupg"
chmod 0700 "$SUN_WORK/gnupg"

download_limited() {
  local asset="$1" output part
  output="$SUN_WORK/$asset"
  part="${output}.part"
  rm -f -- "$part"
  if curl --disable --fail --silent --show-error --location \
      --proto '=https' --proto-redir '=https' \
      --connect-timeout 20 --retry 4 --retry-delay 1 --retry-max-time 180 \
      --max-time 180 --max-filesize 1048576 "$SUN_BASE/$asset" |
      python3 -I -c '
import os
import sys

limit = 1048576
path = sys.argv[1]
try:
    with open(path, "xb") as output:
        remaining = limit
        while True:
            chunk = sys.stdin.buffer.read(min(65536, remaining + 1))
            if not chunk:
                break
            if len(chunk) > remaining:
                raise ValueError("download exceeds size limit")
            output.write(chunk)
            remaining -= len(chunk)
except Exception:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    raise SystemExit(1)
' "$part"; then
    if mv -f -- "$part" "$output"; then
      return 0
    fi
  fi
  rm -f -- "$part"
  return 1
}

for asset in sun.sh sun.sh.asc release-signing.pub.asc; do
  download_limited "$asset"
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
good_count=0
outcome_count=0
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
    GOODSIG)
      outcome_count=$((outcome_count + 1))
      good_count=$((good_count + 1))
      ;;
    EXPSIG|EXPKEYSIG|REVKEYSIG|BADSIG|ERRSIG)
      outcome_count=$((outcome_count + 1))
      ;;
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
[[ "$outcome_count" -eq 1 && "$good_count" -eq 1 \
   && "$valid_count" -eq 1 && "$pinned_count" -eq 1 \
   && "$name_count" -eq 1 && "$name_match" -eq 1 \
   && "$flags_count" -eq 1 && "$flags_match" -eq 1 \
   && "$data_count" -eq 1 && "$data_match" -eq 1 ]] || {
  echo 'The bootstrap signature is not uniquely bound to the pinned fingerprint and target version; refusing to execute.' >&2
  exit 1
}

chmod 0700 "$SUN_WORK/sun.sh"
/bin/bash -p "$SUN_WORK/sun.sh" --version "$SUN_VERSION" --base-url "$SUN_BASE"
SUN_ROOT
```

An explicit version is part of this trust boundary: `latest.json` is an availability index, not a signed freshness proof. The hashed subpackets in `sun.sh.asc` contain the critical notation `release-version@xxv.cc=<version>`; verification authenticates the script bytes and requires this value to match the version confirmed by the administrator, so an older valid script and signature cannot be moved into a newer version directory. The versioned `sun.sh`, `sun.sh.asc`, and public key appear only after the mirror workflow verifies the signed archive and tag source, then reads the files back from the public mirror. The downloaded key file is not itself the trust root; the pinned fingerprint, which should also be checked through an independent trusted channel, is.

#### Convenient one-line install (compatibility entry point)

The website-hosted bootstrap downloads the latest signed Release, verifies the `.sha256` file and GPG signature (required by default), then opens the interactive menu:

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p
```

This command preserves the existing experience, but the downloaded `sun.sh` executes before that script has been checked against its detached signature. The first stage therefore trusts HTTPS, the domain, and the mirror/CDN; verifying the Release afterward cannot retroactively authenticate code that already ran. Use the high-assurance procedure above when the threat model includes a compromised download host or TLS endpoint.

When starting from the URL, `curl` must already be installed: the bootstrap cannot install a command before the script itself has been obtained. `set -o pipefail` makes a missing `curl`, DNS/TLS error, or failed download fail the complete pipeline instead of allowing the trailing Bash process to read empty input and report success. The documented entry requires `/bin/bash -p`, causing Bash to ignore `BASH_ENV` and exported shell functions before it reads the bootstrap. The script then rebuilds the privileged child environment from a fixed `PATH`/`LC_ALL`, a UI language validated as `zh` or `en`, terminal and timezone settings, and upper/lowercase proxy variables; caller-supplied aliases, dynamic-loader, Python, package-manager, and systemd/Git environment overrides do not survive. Once running, the bootstrap requires `curl`, `tar`, `sha256sum`, `mktemp`, `python3`, `env`, `uname`, `gpg`, `timeout`, and `wc`. It installs only the packages corresponding to missing commands through apt, dnf, microdnf, or yum and then checks each command again; this avoids replacing `curl-minimal/coreutils-single` with conflicting full packages on minimal RPM systems. It fails before downloading or installing SUN when no supported package manager exists or a command is still missing. Release GPG verification is required by default.

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

- Telegram: `getMe` validates the bot token, then `sendMessage` validates the chat ID and permission. Read-only `getMe` makes up to three attempts when it encounters connection resets, timeouts, HTTP 408, 429, or 5xx responses; 429 honors a server `retry_after` capped at 30 seconds. To avoid duplicate messages, `sendMessage` retries only when the server explicitly returns HTTP 429; transport errors, HTTP 408, 5xx responses, and interrupted responses return a temporary failure without an immediate resend. A persistent temporary network failure is not mislabeled as an invalid token and does not clear existing credentials; interactive mode can retry, skip this preflight, or abort, while non-interactive mode fails with exit `75` and rolls back;
- Feishu: obtains a `tenant_access_token` and scans active employees in the application's directory scope. If an `open_id` was supplied explicitly, it performs only the application-credential preflight. Token and directory operations may retry HTTP 408/429/5xx within bounds; a message POST returns a temporary failure without an immediate resend on HTTP 408 or 5xx. No message is sent during installation preflight.

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
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p -s -- install \
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
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p -s -- install \
  --notify-channels feishu \
  --feishu-app-id 'cli_xxx' \
  --feishu-receive-id 'ou_xxx' \
  --feishu-app-secret-file /root/.security-update-notify-feishu-secret \
  --non-interactive \
  -y
```

The App Secret source must be a root-owned regular file, not a symlink, with no group or other access (`0600` recommended), and it must have exactly one hard link. The installer validates these conditions and detects replacement during path validation before reading it.

The installer stores the App Secret as an encrypted systemd credential when available. Older systemd versions fall back to a separate root-only `0600` file. Neither form enters the normal config or upgrade backups.

After a successful install and credential check, remove the source file unless it is a stable entry point maintained by an external secret manager. This avoids retaining an unnecessary plaintext copy of the App Secret.

For safer automation, use a local `.env` file so the token does not appear in shell history or process lists:

```bash
cp .env.example .env
chmod 600 .env
sudoedit .env

set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | \
  sudo /bin/bash -p -s -- install --env-file "$PWD/.env" --non-interactive -y
```

You can also keep only the token in a root-only file:

```bash
sudo install -m 600 /dev/null /root/.security-update-notify-token
sudoedit /root/.security-update-notify-token

set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p -s -- install \
  --telegram-token-file /root/.security-update-notify-token \
  --telegram-chat-id 'CHAT_ID' \
  --non-interactive \
  -y
```

A Bot Token is a bearer credential exactly like the App Secret, so the token source file follows the same contract: a root-owned regular file, not a symlink, with no group or other access (`0600` recommended), and exactly one hard link. The installer validates these conditions before reading it.

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
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p -s -- upgrade --non-interactive -y
```

Once SUN is installed you can also run `sudo security-update-notify upgrade` directly. Both the bootstrap and built-in upgrade first read `https://dl.ll.cd/security-update-notify/latest.json` and download the signed assets from that mirror; they fall back to GitHub when the mirror index or complete asset-set transfer is unavailable. The downloaded package still must pass `.sha256` and GPG verification against the embedded pinned fingerprint (fail-closed by default; a missing signature is rejected). The mirror improves transport availability but is not a trust root.

If SUN is already installed, the installer reads `/etc/security-update-notify/telegram.env` and the existing timer time and keeps every setting that was not explicitly overridden. Run `sudo security-update-notify configure notifications` to change receiving platforms, Telegram credentials, the Feishu app, App Secret, or recipient transactionally. Removing a platform deletes its stored credentials; adding or editing one revalidates only that platform. Any failure rolls the whole installer transaction back. Legacy configs without `NOTIFY_CHANNELS` remain `telegram`, and other options not explicitly overridden keep their old values.

Before upgrading, key files are backed up to `/var/backups/security-update-notify/<timestamp>`, but the Feishu App Secret is not copied there. Ordinary failures and termination signals roll back before exit and restore the SUN timer's pre-install enablement link and active state; after SIGKILL, a crash, or power loss, the next install first recovers any interrupted transaction that is safe to roll back. While trustworthy package-manager state capture is incomplete, the installer does not guess that rollback is safe: it retains the transaction evidence and both install and uninstall fail closed. See [Installation transactions and interruption recovery](operations.en.md#installation-transactions-and-interruption-recovery) for the exact boundary and manual-recovery requirements. A post-upgrade self-check runs by default; use `--notify-upgrade 1` to notify the configured receiving platforms after a successful upgrade. Upgrade notices are best-effort: a notification failure never rolls back a completed upgrade, and the whole dual-send is not retried in a way that would duplicate a successful platform.

## Related documentation

- [Operations and recovery](operations.en.md)
- [Security and trust model](security.en.md)
