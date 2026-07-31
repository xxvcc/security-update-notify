# Security and trust model

[中文](security.md) | [Back to README](../README.en.md)

This guide records the network, credential, Release-signing, and first-install trust boundaries relevant to users and security reviewers.

## Release signatures

Release packages always include a `.sha256` checksum file. When the key is available, `go run ./cmd/sun-release package` creates two detached signatures: `.tar.gz.asc` for the archive and `sun.sh.asc` for the first-install bootstrap; the latter also carries a critical version notation in its hashed signature subpackets. Both are required for an official release or an existing version tag; an explicit `--sign off` is rejected before any `dist` file is created in either case. `sun.sh` defaults to `required` verification of the downloaded Release; `auto` is kept only as a compatibility alias and also requires gpg and the archive `.asc`. Only an explicit `--verify-signature off` skips Release signature verification.

Root `VERSION`, in the exact form `VERSION="X.Y.Z"`, is the single source of truth. Official releases (a corresponding `vX.Y.Z` tag or `RELEASE=1`) are **signed and fixed to all five Go architectures**. The Go release tool binds that root version to the unique CHANGELOG heading, tag, packaged version, and every binary's `--version`; the architecture set cannot be overridden. It fails when Go, Bash (used only to syntax-check `sun.sh`), any amd64/arm64/386/ppc64le/s390x build, or the GPG private key matching the pinned fingerprint is missing. Explicit GitHub Release assets are the tarball, checksum, tarball signature, and `sun.sh.asc`. Unprivileged release CI provides an early defense-in-depth check. A mirror-workflow runner without an Environment then independently verifies those assets and executes all five authenticated runtime probes. Only after that succeeds does a fresh deployment runner receive the Environment-scoped identity; it revalidates asset structure, checksums, GPG, the archive, and bootstrap version binding from scratch without executing release payloads. The private key never enters CI; it stays offline with the maintainer. In addition, `security-update-notify upgrade` is **fail-closed** by default: it prefers the fixed release mirror and falls back to GitHub, verifies sha256, and requires a GPG signature against an embedded public key and pinned fingerprint before extracting and upgrading. The emergency `SECURITY_UPDATE_NOTIFY_UPGRADE_ALLOW_UNSIGNED=1` path permits sha256-only verification only when `gpg` is genuinely absent from the trusted system path; whenever `gpg` exists, a missing or invalid signature still fails closed.

## Security notes

SUN is intentionally narrow:

- outbound HTTPS only: alerts to the Telegram Bot API and/or `open.feishu.cn` as configured; by default also a public-IP echo service (api.ipify.org / ifconfig.me) for the egress IP (disable with `INCLUDE_PUBLIC_IP=0`); install and self-upgrade prefer `dl.ll.cd` and fall back to GitHub. If you lock this down with an egress firewall, allow those destinations or disable the corresponding features;
- no command receiver;
- no public HTTP endpoint;
- no automatic reboot;
- root-only normal notification config; the Feishu App Secret uses a separate systemd/root credential and never enters normal config, command lines, logs, or upgrade backups;
- explicit opt-in for best-effort distro support.

The release `.sha256` file protects against accidental corruption or version mismatch. If your threat model includes a compromised download source, keep the default signature verification enabled and do not use `--verify-signature off` or the unsigned-upgrade escape hatch.

The archive signature authenticates Release contents; before any first execution, `sun.sh.asc` authenticates the bootstrap bytes and binds them to their release version through a critical notation. The convenient `curl | /bin/bash -p` path cannot use the latter because it has already run the code; `-p` only suppresses `BASH_ENV` and exported-function injection before Bash reads that code and does not authenticate the network response. Only the high-assurance procedure treats the fixed fingerprint as the initial trust anchor outside the network. Signatures do not prove which version is latest and do not protect a compromised local root account, `gpg`, or shell, so an administrator must confirm the intended version and fingerprint through an independent trusted channel.

## Related documentation

- [High-assurance first install](installation.en.md#high-assurance-first-install-recommended-for-production)
- [Maintainer release process](releasing.en.md)
- [3.x Go architecture and release constraints](go-port.md)
