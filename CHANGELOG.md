# 变更记录

## 2.2.0

飞书通知升级为原生 Card JSON 2.0；Telegram 文本、去重哈希和按渠道独立恢复语义保持兼容。
Upgrades Feishu notifications to native Card JSON 2.0 while preserving Telegram text, dedup hashes, and channel-local recovery semantics.

- 飞书卡片：正常告警、`--test-ok`、`--test-reboot` 与升级成功通知均使用 `msg_type=interactive` 的内嵌 JSON 2.0 卡片；不依赖租户 `template_id` 或 CardKit 实例。
  Feishu cards: regular alerts, `--test-ok`, `--test-reboot`, and successful-upgrade notices now use embedded JSON 2.0 cards with `msg_type=interactive`; no tenant `template_id` or CardKit instance is required.
- 状态表达：失败或 EOL 使用红色，需要重启或服务维护使用橙色，测试成功/健康使用绿色，SUN 升级使用蓝色；卡片展示主机、IP、系统、内核、检查时间、重启/服务状态、更新摘要、建议命令和项目文档链接。
  Status presentation: red for failures or EOL, orange for reboot/service maintenance, green for successful tests or healthy state, and blue for SUN upgrades; cards include host, IP, OS, kernel, check time, reboot/service state, update summary, recommended commands, and project documentation.
- 渠道兼容：Telegram 正文继续逐字节保持原格式；现有去重哈希、每渠道独立状态及双发部分失败后的单渠道重试不变。旧配置缺少 `NOTIFY_CHANNELS` 时仍默认 Telegram。
  Channel compatibility: Telegram keeps its byte-identical text body; existing dedup hashes, per-channel state, and single-channel retry after a partial dual-send failure are unchanged. Legacy configs without `NOTIFY_CHANNELS` still default to Telegram.
- 安全边界：卡片只包含静态展示组件和 `open_url` 文档按钮，不新增事件订阅、回调服务或权限；请求体限制在飞书 30 KB 上限内，超长动态内容安全截断。App Secret 处理方式不变。
  Security boundary: cards contain only static display components and an `open_url` documentation button, with no event subscription, callback service, or new permission; request bodies remain within Feishu's 30 KB limit and oversized dynamic content is safely truncated. App Secret handling is unchanged.
- 双运行时与测试：Go 主运行时和 Bash 备用运行时同步实现；新增 JSON/转义/尺寸/颜色、真实请求体、429 重试、升级卡片、双渠道部分失败及卡片降级测试；打包守卫同时拒绝未提交改动与未跟踪发布源文件。飞书客户端 7.20 及以上完整显示 JSON 2.0；旧客户端只显示标题和升级提示。
  Dual runtimes and tests: both the Go runtime and Bash fallback implement the same card behavior, with coverage for JSON/escaping/size/colors, real request bodies, 429 retries, upgrade cards, partial dual-delivery failure, and fallback behavior; the package guard rejects both uncommitted changes and untracked release-source files. Feishu 7.20+ fully renders JSON 2.0; older clients show only the title and upgrade prompt.

## 2.1.0

新增 Telegram / 飞书可选通知渠道，并完整覆盖 Go 主运行时、Bash 备用运行时、安装升级、自检和升级通知。
Adds selectable Telegram / Feishu notification channels across the Go runtime, Bash fallback, installation/upgrades, diagnostics, and upgrade notifications.

- 通知渠道：新增 `NOTIFY_CHANNELS=telegram|feishu|telegram,feishu`；旧配置缺少该项时仍默认为 Telegram，无需手工迁移。飞书固定使用应用级 `open_id` 单发普通文本。
  Notification channels: add `NOTIFY_CHANNELS=telegram|feishu|telegram,feishu`; legacy configs without it remain Telegram-only with no manual migration. Feishu sends plain text to an app-scoped `open_id` only.
- 安装选人：交互安装在输入飞书 App ID / Secret 后，通过 Directory v1 分页扫描应用可见的在职员工，显示中文名、手机号尾号和 `open_id` 供编号选择；只持久化选中的 `open_id`。保留手动回退，非交互安装仍要求显式 `--feishu-receive-id`。
  Recipient onboarding: after the Feishu App ID / Secret, interactive installation paginates active employees visible via Directory v1 and shows localized Chinese name, mobile tail, and `open_id` for numbered selection; only the chosen `open_id` is persisted. Manual fallback remains available, while non-interactive installation still requires `--feishu-receive-id` explicitly.
- 作用域与故障安全：更换 App ID 时不再静默复用旧应用的 `open_id`；Directory 部分成功响应会中止选人，飞书限流按官方响应重试；凭据加密/写入失败会可靠触发完整回滚。
  Scope and failure safety: changing the App ID no longer silently reuses the previous app-scoped `open_id`; partial Directory responses abort selection, Feishu rate limits follow the API retry signals, and credential encryption/write failures reliably trigger a full rollback.
- 独立去重：Telegram 继续使用历史 `last-alert.*` 状态文件，飞书使用独立状态；双发部分失败后只重试失败渠道，不会重复已成功渠道。
  Independent deduplication: Telegram keeps its historical `last-alert.*` files while Feishu uses separate state; after a partial dual-delivery failure, only the failed channel is retried.
- 凭据安全：飞书 App Secret 不进入普通配置、命令行、环境变量或升级备份；新 systemd 优先使用加密 credential，旧版本回退到独立 root-only `0600` 文件。停用飞书、卸载清理与失败回滚均覆盖两种凭据。
  Credential safety: the Feishu App Secret never enters normal config, command lines, environment variables, or upgrade backups; newer systemd uses an encrypted credential, with a separate root-only `0600` file fallback. Disabling Feishu, uninstall cleanup, and rollback cover both forms.
- 预检与诊断：Telegram 继续验证 token 与实际接收目标；飞书自动选人同时验证 App ID / Secret 和 Directory 权限，显式接收人路径只验证凭据，均不发送消息。`--doctor`、`test.sh`、升级成功通知和 Bash 回退均按配置渠道运行；升级通知明确采用 best-effort 语义。
  Preflight and diagnostics: Telegram still validates the token and actual target; Feishu auto-selection validates both App ID / Secret and Directory access, while the explicit-recipient path validates credentials only, without sending. `--doctor`, `test.sh`, upgrade notifications, and the Bash fallback all honor configured channels; upgrade notices explicitly use best-effort semantics.
- 测试/文档：新增飞书 API、渠道解析、双发部分失败、旧配置升级、Secret 不泄露和凭据回滚测试；更新中英文安装与安全说明。
  Tests/docs: add coverage for the Feishu API, channel parsing, dual-delivery partial failure, legacy upgrades, Secret non-disclosure, and credential rollback; update Chinese and English installation/security guidance.

## 2.0.3

安全与稳健性加固发布（三轮逐行审计的后续修复；未发现 critical/RCE）。运行时决策与去重哈希对正常输入保持不变。
Security and robustness hardening release (follow-up to a three-round line-by-line audit; no critical/RCE found). Runtime decisions and the dedup hash are unchanged for normal inputs.

- 安全：网络错误时不再把 Telegram bot token 写入 stderr/journal。token 位于请求 URL 路径中，Go 的 `*url.Error` 会保留路径，此前一次网络错误即泄露 `TELEGRAM_BOT_TOKEN`；现只保留操作名与底层原因。
  Security: the Telegram bot token no longer leaks to stderr/journal on a network error. The token sits in the request URL path, which Go's `*url.Error` preserves, so any transport error previously exposed `TELEGRAM_BOT_TOKEN`; only the operation and underlying cause are surfaced now.
- 安全：验签公钥文件含多把公钥时拒绝。指纹 pin 仅校验第一把、而 `gpg --verify` 信任整个 keyring，此前"真key+攻击者key"的文件可绕过 pin（仅 `sun verify-release` 路径；自升级用内置单公钥）。
  Security: reject a public-key file that holds more than one key. The fingerprint pin only checked the first key while `gpg --verify` trusts the whole keyring, so a real-key+attacker-key file defeated the pin (only the `sun verify-release` path; self-upgrade uses the single embedded key).
- 安装器：装后自检 `--doctor` 改为咨询式——磁盘将满、发行版已 EOL 等主机环境问题不再回滚一个本身正确的安装；且不再把共享的 `/usr/local/sbin` 收紧到 0750。
  Installer: the post-install `--doctor` self-check is advisory — low disk or an EOL release no longer rolls back an otherwise-correct install; and the shared `/usr/local/sbin` is no longer retightened to 0750.
- 稳健性：下载体、Telegram 响应体、子进程输出增加大小上限；获取单实例锁失败时以非零退出，不再无锁裸跑（对齐 Bash `flock -n 9 || exit 0`）。
  Robustness: bound the download body, Telegram response body and child-process output; a failed single-instance lock now exits non-zero instead of running lock-less (matching the bash `flock -n 9 || exit 0`).
- 一致性：config/os-release 引号顺序双层剥离、磁盘可用量改用 `f_frsize`（与 `df` 一致）、公网 IP 读到 EOF、语义化版本预发布数字比较防溢出——均与 Bash 运行时逐字节对齐。
  Consistency: sequential double-then-single quote stripping in config/os-release, disk-available via `f_frsize` (matching `df`), read the public IP to EOF, and an overflow-safe prerelease numeric compare — all aligned byte-for-byte with the bash runtime.
- 打包/CI：脏树守卫纳入 `cmd/ internal/ go.mod`；tar 目录权限归一以保证可复现；CI 与兼容测试的负向断言改为真正 fail（此前裸 `! grep` 与 `cond && echo` 被 `set -e` 豁免、会放过回归）。`uninstall.sh` 容错 `systemctl daemon-reload`，使 `--purge-config` 仍会删除 token。
  Packaging/CI: the dirty-tree guard now covers `cmd/ internal/ go.mod`; tar directory modes are normalized for reproducibility; negative assertions in CI and the compat test now hard-fail (a bare `! grep` and `cond && echo` are exempt from `set -e` and silently passed regressions). `uninstall.sh` tolerates a failing `systemctl daemon-reload` so `--purge-config` still removes the token.
- 文档：更正 README 的出站说明（除 Telegram 外，默认还会向公网 IP 探测服务发起请求、自升级时访问 GitHub），并说明 Bash 回退运行时仍依赖 `python3`。
  Docs: correct the README egress note (besides Telegram, by default it also queries a public-IP echo service and contacts GitHub on self-upgrade) and clarify that the bash fallback runtime still needs `python3`.

## 2.0.2

文档与测试加固发布；运行时行为与 2.0.1 完全一致（无功能改动）。
Documentation and test-hardening release; runtime behavior is identical to 2.0.1 (no functional change).

- 修正 README：明确 2.0 起运行时为静态 Go 二进制、按架构分发（未构建架构回退 Bash），并更正"公网 IP 使用 Python 标准库/依赖 python3、curl"的过时说明（运行时不再依赖 python3/curl，仅安装器预检仍用 python3）。
  Corrected the README: state that since 2.0 the runtime is a static Go binary shipped per architecture (with a Bash fallback), and fix the stale claim that public-IP detection uses Python / that the runtime depends on `python3`/`curl` (the runtime no longer does; only the installer's preflight still uses `python3`).
- 新增 CI 守卫（不改运行时）：QEMU 下真实执行全部非 amd64 架构（arm64/386/ppc64le/s390x）并校验 golden hash 一致；发布签名 fail-closed（错误密钥/指纹/sha256 一律拒绝）；8 个之外的边缘消息渲染 bash↔Go 逐字节差分；install.sh 升级失败回滚。
  Added CI guards (no runtime change): actually execute every non-amd64 arch (arm64/386/ppc64le/s390x) under QEMU and check the golden hash matches; release-signature fail-closed (wrong key/fingerprint/sha256 all rejected); byte-for-byte bash↔Go differential for message-rendering edge cases beyond the core 8; install.sh upgrade-failure rollback.

## 2.0.1

2.0.0 Go 运行时的两处行为回归修复（在真实主机升级测试中发现）。
Two behavior regressions in the 2.0.0 Go runtime, found during real-host upgrade testing.

- 恢复运行日志：Go 运行时重新向 `/var/log/security-update-notify.log` 写入运行事件（`check ok`/`silent ok`/`alert`/`dedup suppressed`/`telegram sent`/`telegram failed`），格式、时间戳与 `0640` 权限与 1.9.x 一致，logrotate 照常工作。2.0.0 遗漏了这一日志。
  Restored operational logging: the Go runtime again writes run events to `/var/log/security-update-notify.log` (`check ok`/`silent ok`/`alert`/`dedup suppressed`/`telegram sent`/`telegram failed`) with the same format, timestamp and `0640` permissions as 1.9.x, so logrotate keeps working. 2.0.0 had dropped this.
- 不支持的后端（既非 `apt` 也非 `dnf`，例如无法识别的发行版使 `auto` 解析为 unknown）现在与 1.9.x 一样以退出码 2 拒绝，而不是静默继续。
  An unsupported backend (neither `apt` nor `dnf`, e.g. an unrecognized distro resolving `auto` to unknown) is now rejected with exit code 2 as in 1.9.x, instead of silently proceeding.
- 新增可选环境变量覆盖运行时路径，便于隔离测试：`SECURITY_UPDATE_NOTIFY_STATE_DIR` / `_LOG_FILE` / `_LOCK_FILE`（默认与原路径一致）。
  Added optional env overrides for runtime paths to ease isolated testing: `SECURITY_UPDATE_NOTIFY_STATE_DIR` / `_LOG_FILE` / `_LOCK_FILE` (defaults unchanged).

## 2.0.0

运行时从 Bash + 内嵌 python3 重写为单个静态 Go 二进制；行为逐字节保持一致，已装机器可无缝原地升级。
Runtime rewritten from Bash + embedded python3 into a single static Go binary; behavior is byte-identical,
so installed hosts upgrade in place seamlessly.

- 运行时（`/usr/local/sbin/security-update-notify`）改为 Go 静态二进制：`run`（裸调用）、`--test-ok`、`--test-reboot`、`--no-dedupe`、`--doctor`、`--check-upgrade`、`--upgrade`（自升级）、`--notify-upgrade-event`、`--version`、`--lang` 全部移植。
  The runtime is now a static Go binary: `run` (bare), `--test-ok`, `--test-reboot`, `--no-dedupe`, `--doctor`, `--check-upgrade`, `--upgrade` (self-upgrade), `--notify-upgrade-event`, `--version`, `--lang` are all ported.
- **去除 `python3` 与 `curl` 运行时依赖**：所有 HTTP/JSON（GitHub API、Telegram getMe/sendMessage、公网 IP）、sha256、tar 安全解包、语义化版本比较、文件锁、磁盘检查改用 Go 标准库（`net/http`、`crypto/sha256`、`archive/tar`、`syscall`）。签名校验仍委托 `gpg`；`needrestart`/`needs-restarting`/`apt`/`dnf`/`systemctl` 等系统命令仍按需调用。
  **Dropped the `python3` and `curl` runtime dependencies**: all HTTP/JSON (GitHub API, Telegram getMe/sendMessage, public IP), sha256, safe tar extraction, semantic-version comparison, file locking and disk checks now use the Go standard library. Signature verification still delegates to `gpg`; system commands (`needrestart`/`needs-restarting`/`apt`/`dnf`/`systemctl`) are still invoked as needed.
- **行为逐字节保持一致**：告警去重哈希、中英文通知正文、`telegram.env` 配置格式、退出码均与 1.9.x 完全一致，从 1.9.x 原地升级不会因实现变化而重复告警。CI 用从真 Bash 运行时捕获的 golden 向量对去重哈希与通知正文做逐字节回归校验，并在容器内验证 bash→Go 升级保留配置/状态且不重复告警。
  **Byte-identical behavior**: the dedup hash, bilingual (zh/en) notification text, `telegram.env` format and exit codes are unchanged from 1.9.x, so an in-place upgrade does not re-alert. CI diffs the dedup hash and rendered text against golden vectors captured from the real Bash runtime, and verifies in a container that a bash→Go upgrade preserves config/state without re-alerting.
- **分发（桥）**：同一份可复现、GPG 签名的 tarball 现同时包含各架构的 Go 二进制（amd64/arm64/386/ppc64le/s390x）与原 Bash 运行时。`install.sh` 优先安装本架构的 Go 二进制，未构建的架构自动回退到 Bash 运行时——任何架构都不会失去升级能力。已装的 1.9.x 机器自升级时会拉取本包并平滑换成 Go 二进制。
  **Distribution (bridge)**: the same reproducible, GPG-signed tarball now ships per-arch Go binaries (amd64/arm64/386/ppc64le/s390x) alongside the original Bash runtime. `install.sh` prefers this arch's Go binary and falls back to the Bash runtime for unbuilt arches — no architecture loses the ability to upgrade. Installed 1.9.x hosts self-upgrade into this package and switch to the Go binary in place.
- 自升级信任链不变：下载 GitHub 发布包 → 校验 sha256 → 用内置并 pin 指纹的公钥强制校验 GPG 签名（解包前，fail-closed）→ 安全解包（拒绝路径穿越/特殊条目、剥离 setuid）→ 版本绑定 → 由存活的父进程运行已校验包内的 `install.sh` 完成替换。
  The self-upgrade trust chain is unchanged: download the GitHub release → verify sha256 → mandatory GPG verification against the embedded, fingerprint-pinned key (before extraction, fail-closed) → safe extraction (reject traversal/special entries, strip setuid) → version binding → a surviving parent process runs the verified package's `install.sh` to complete the swap.

## 1.9.4

版本比较与状态写入健壮性修复。
Version-comparison and state-write robustness fixes.

- 自升级版本比较改用语义化比较（`python3`）替换 `sort -V`：`sort -V` 会把预发布号（如 `1.0.0-rc1`）排在正式版 `1.0.0` 之上，导致从 rc 升级到正式版被误判为“降级”而拒绝自升级；解析失败一律按“非更新”处理（fail-closed），数字段仅接受纯 ASCII 数字，畸形 tag 不会被解析成伪数值。多段版本（`1.7.0.1 > 1.7.0`）与预发布优先级仍按预期处理。
  Self-upgrade version comparison now uses a semantic-version compare (`python3`) instead of `sort -V`: `sort -V` ranks a pre-release such as `1.0.0-rc1` above the release `1.0.0`, so an rc→final upgrade was mis-judged as a downgrade and refused; a parse failure is treated as "not newer" (fail-closed), and numeric segments accept only pure ASCII digits so a malformed tag cannot parse to a bogus number. Multi-segment versions (`1.7.0.1 > 1.7.0`) and pre-release precedence are preserved.
- 告警去重状态文件改为原子写入（`mktemp` + rename）：`>` 会先截断再写，崩溃或磁盘满时可能留下被截断/清空的状态文件；改为临时文件加原子重命名，且 hash 先于时间戳落盘，中途崩溃只会让下次更倾向“发送”，不会静默抑制真实告警。
  The alert-dedup state files are now written atomically (`mktemp` + rename): `>` truncates before writing, so a crash or full disk could leave a truncated/empty state file; writes now go through a temp file plus atomic rename, with the hash committed before the timestamp, so a mid-write crash only biases the next run toward sending, never toward silently suppressing a real alert.
- 新增 CI 回归守卫，锁定上述修复：版本比较表用例（含禁止 `sort -V` 重现的源码断言）、状态原子写不变量、以及配置解析的 fail-open 不变量。
  Added CI regression guards locking in the above: version-comparison table cases (with a source assertion forbidding a `sort -V` regression), state-write atomicity invariants, and the config-parser fail-open invariant.

## 1.9.3

第四轮安全审计加固。
Fourth-pass security-audit hardening.

- 自升级签名不可被剥离降级：`gpg` 可用时签名恒为必需，即使攻击者让 `.asc` 下载失败也一律拒绝，绝不静默退回 sha256-only；`SECURITY_UPDATE_NOTIFY_UPGRADE_ALLOW_UNSIGNED=1` 的 sha256-only 分支仅在本机确实没有 `gpg` 且显式 opt-in 时保留，网络攻击者无法触发。
  Self-upgrade signature can no longer be stripped to force a downgrade: when `gpg` is available a signature is mandatory and a missing `.asc` is refused rather than silently falling back to sha256-only; the `SECURITY_UPDATE_NOTIFY_UPGRADE_ALLOW_UNSIGNED=1` sha256-only branch remains only for hosts that genuinely lack `gpg` and explicitly opt in, and cannot be triggered by a network attacker.
- 版本绑定：自升级解包后核对发布包内声明的 `VERSION` 必须等于请求的 `latest`（在顶层目录名 pin 之外再加一道），防止签名集合内的回滚/版本错配。
  Version binding: after extraction the self-upgrade checks that the package's declared `VERSION` equals the requested `latest` (in addition to the pinned top-dir name), preventing rollback/version mismatch within the signed set.
- 解包加固：自升级与 `sun.sh` 的 tar 解包新增 `--no-same-permissions`，不从归档恢复 setuid/setgid 等特殊权限位（纵深防御）。
  Extraction hardening: self-upgrade and `sun.sh` tar extraction now pass `--no-same-permissions`, not restoring setuid/setgid bits from the archive (defense in depth).
- 一致性与健壮性：取最新版本号的 API 请求也强制 HTTPS-only 重定向；`--base-url` 校验改为完整锚定并拒绝 `..`；`--doctor` 的 dnf 分支不再误报“yum 存在”；磁盘检查改用 `df -P -k` 消除块大小歧义；日志文件缺失时以 `0640` 创建；EOL 表补充 RHEL 系 10。
  Consistency/robustness: the latest-version API request also enforces HTTPS-only redirects; `--base-url` validation is fully anchored and rejects `..`; the `--doctor` dnf branch no longer falsely reports "yum present"; the disk check uses `df -P -k` to remove block-size ambiguity; the log file is created `0640` when absent; the EOL table gains RHEL-family 10.

## 1.9.2

- 三轮复审安全加固：发布包下载与自升级下载现在限制 curl 只允许 HTTPS 及 HTTPS 重定向；引导脚本、自升级与打包过程的 tar 调用会清理 `TAR_OPTIONS`/压缩工具环境变量，避免本地环境影响归档校验、解包或构建。
  Three-pass audit hardening: release downloads and self-upgrade downloads now restrict curl to HTTPS and HTTPS redirects only; bootstrap, self-upgrade, and packaging tar calls clear `TAR_OPTIONS`/compression-tool environment variables so local environment cannot affect archive verification, extraction, or builds.
- 配置校验加固：安装器会校验并规范化 `CHECK_UPDATE_HEALTH`、`CHECK_EOL` 与 `STALE_UPDATE_DAYS`；运行时遇到无效 watchdog 配置时默认保持安全检查开启。
  Config validation hardening: the installer validates and normalizes `CHECK_UPDATE_HEALTH`, `CHECK_EOL`, and `STALE_UPDATE_DAYS`; runtime defaults invalid watchdog config back to enabled checks.
- 回滚修复：依赖包安装后若创建了受管默认配置（例如 `/etc/dnf/automatic.conf`），安装器会在写入前补充备份，避免后续失败回滚时误删依赖包默认文件。
  Rollback fix: if dependency installation creates a managed default config (for example `/etc/dnf/automatic.conf`), the installer captures it before writing SUN config, avoiding accidental deletion during later rollback.

## 1.9.1

- 安全加固：`sun.sh` 默认改为必须校验 GPG 签名，`auto` 仅作为兼容别名且不再在缺少 gpg/签名时退回 sha256-only；引导脚本与自升级都使用内置公钥和 pin 指纹，并在解包前完成签名校验。
  Security hardening: `sun.sh` now requires GPG signature verification by default; `auto` is only a compatibility alias and no longer falls back to sha256-only when gpg/signature is missing. Both the bootstrap and self-upgrade paths use an embedded public key plus pinned fingerprint and verify before extraction.
- 修复安全更新看门狗：CentOS Linux / CentOS Stream 与 Amazon Linux 2023 的 EOL 日期表已修正；自动更新定时器触发过但没有成功运行记录时，不再被误判为健康。
  Security-update watchdog fixes: correct EOL dates for CentOS Linux / CentOS Stream and Amazon Linux 2023; a timer that has triggered without any recorded successful automatic-update run is no longer treated as healthy.

## 1.9.0

安全更新看门狗：在“内核/服务重启”之外，新增三项面向安全更新本身的检测，默认开启，均可在配置中关闭。

Security-update watchdog: three new checks focused on security updates themselves, in addition to kernel/service-restart detection. On by default, all configurable.

- 新增 `CHECK_UPDATE_HEALTH`（默认 `1`）：检测自动更新机制是否健康——定时器（`apt-daily-upgrade` / `dnf-automatic`）被禁用、上次运行失败（`Result != success`）、超过 `STALE_UPDATE_DAYS`（默认 `7`）天没有成功更新、`/` 或 `/boot` 剩余空间不足 200MB；任一命中即触发提醒。
  Added `CHECK_UPDATE_HEALTH` (default `1`): detects whether the auto-update mechanism is healthy — timer disabled, last run failed, no success for more than `STALE_UPDATE_DAYS` (default `7`) days, or `/`/`/boot` under 200 MB free; any hit triggers an alert.
- 新增待安装安全更新统计：随提醒与 `--doctor` 一并展示待装的安全更新数量（dnf 另计高危/重要），为信息项，不单独触发提醒。
  Added a pending-security-update count shown in alerts and `--doctor` (dnf also counts critical/important); informational only, never triggers an alert by itself.
- 新增 `CHECK_EOL`（默认 `1`）：发行版安全支持终止（EOL）提醒——已过 EOL 触发提醒，临近（90 天内）仅作信息展示；内置 Debian/Ubuntu/RHEL 系/Amazon Linux 的近似 EOL 日期表。
  Added `CHECK_EOL` (default `1`): distro end-of-life warning — past EOL triggers an alert, approaching (within 90 days) is informational; ships an approximate EOL table for Debian/Ubuntu/RHEL-family/Amazon Linux.
- 去重哈希纳入机制健康与 EOL 的稳定信号，避免同一状态被反复提醒；`--doctor` 自检新增以上三项的当前状态。
  The dedup hash now includes the stable health/EOL signals so the same state is not re-alerted; `--doctor` reports the current state of all three.

## 1.8.1

- 重复提醒模式 `always` 改名为更直白的 `once`（“只提醒一次”）；旧值 `always` 仍兼容接受，升级时安装器会自动迁移为 `once`。
  Renamed the `always` reminder mode to the clearer `once` ("remind only once"); the old value `always` is still accepted and the installer migrates it to `once` on upgrade.
- 默认重复提醒模式由 `interval` 改为 `daily`（每天最多提醒一次）；交互安装的默认选项与推荐项也随之改为 `daily`。
  The default reminder mode changed from `interval` to `daily` (at most once per day); the interactive default/recommended option is now `daily` too.

## 1.8.0

来自一次全面审计的修复与加固（经对抗式复核确认）。

Fixes and hardening from a comprehensive, adversarially-verified audit.

- 告警降噪（apt 端补齐与 dnf 一致的策略）：不再因 `needrestart` `KSTA=0`（内核状态未知）或 `NEEDRESTART-SESS`（用户会话，含管理员自己的 SSH 登录）误报；关注信号只取需要重启的服务（`SVC`）与真实内核更换。去重哈希改用稳定信号（排除动态公网 IP 与瞬时输出），避免同一状态被反复提醒。
  Alert-noise reduction (apt now matches the dnf policy): no longer triggered by `needrestart` `KSTA=0` (unknown kernel state) or `NEEDRESTART-SESS` (user sessions, incl. the admin's own SSH login); attention only from services needing restart (`SVC`) and a real kernel change. The dedup hash uses a stable signal (excluding the dynamic public IP and transient output) so the same state is not re-alerted.
- 版本比较改用 `sort -V`（移除旧的 awk 截断）：正确处理 4 段版本（`1.x.y.z`）与预发布后缀，修复补丁版“永不自动升级”；解析 `tag_name` 只精确去除前导 `v`。
  Version comparison uses `sort -V` (drops the old awk truncation): handles 4-part versions and pre-release suffixes, fixing patch releases that never auto-upgraded; `tag_name` strips only a leading `v`.
- 运行时锁定 `LC_ALL=C`，使重启检测的文案匹配与排序在任意系统语言下确定。
  Pin `LC_ALL=C` at runtime so restart-detection message matching and sorting are deterministic under any system language.
- `--upgrade` / `--check-upgrade` 在加载配置前也跟随已安装的 `NOTIFY_LANG`；`sudo` 重新执行时传递 `--lang`。
  `--upgrade` / `--check-upgrade` follow the installed `NOTIFY_LANG` even before config load; `--lang` is passed across the `sudo` re-exec.
- Telegram 发送：超长消息截断到 4096 上限；对 4xx（429 除外）不再重试。
  Telegram send: truncate over-long messages to the 4096 cap; do not retry on 4xx (except 429).
- 发行版识别用 `ID_LIKE` 兜底衍生版（Oracle Linux/CloudLinux 等）；探测 `needs-restarting -s` 支持，老版本回退“仅按整机重启”并给出可见提示。
  Distro detection falls back to `ID_LIKE` for derivatives (Oracle Linux/CloudLinux); probe `needs-restarting -s` support and degrade to reboot-only with a visible note on older dnf-utils.
- 安装器：全新安装失败也会回滚（先快照 + ERR trap），回滚会删除本次新建的文件；写任何系统文件前先校验配置；升级始终写入当前 `CONFIG_VERSION`；备份目录设为 `0700` 且只保留最近 3 份（含 token 副本）；`--telegram-token` 提示改用 `--telegram-token-file`。
  Installer: fresh-install failures now roll back too (snapshot + ERR trap), and rollback removes files this run created; config is validated before any system file is written; upgrades always write the current `CONFIG_VERSION`; backup dirs are `0700` and pruned to the most recent 3 (they hold token copies); `--telegram-token` warns to prefer `--telegram-token-file`.
- 引导脚本 `sun.sh`：`--verify-signature auto` 在有 gpg 时按 `required` 严格验签（fail-closed，与 `--upgrade` 一致），仅在无 gpg 时退回 sha256；`--base-url` 必须为 https；`upgrade` 模式走统一的 `/dev/tty` 路径。
  `sun.sh`: `--verify-signature auto` verifies strictly like `required` when gpg is present (fail-closed, matching `--upgrade`), falling back to sha256 only without gpg; `--base-url` must be https; `upgrade` mode uses the unified `/dev/tty` path.
- systemd 单元新增 `UMask=0077`、`SystemCallFilter=@system-service`。
  systemd unit gains `UMask=0077` and `SystemCallFilter=@system-service`.
- 打包/CI：`package.sh` 增加 `RELEASE=1` 信号，且只要存在 `vVERSION` tag 即强制签名；CI 的发布校验改为 checkout 对应 tag、校验 40 位指纹、遍历所有 tarball 资产。
  Packaging/CI: `package.sh` adds a `RELEASE=1` signal and requires signing whenever a `vVERSION` tag exists; the release-verify job checks out the released tag, validates the 40-hex fingerprint, and verifies every tarball asset.
- 内部重构：安装/菜单/测试/卸载脚本共用 `files/lib.sh`（`m`/`say` 双语输出、os-release 读取、后端检测），消除重复；运行时二进制与 `sun.sh` 引导脚本仍刻意自包含。
  Internal refactor: the install/menu/test/uninstall scripts share `files/lib.sh` (bilingual `m`/`say`, os-release reader, backend detection), removing duplication; the runtime binary and the `sun.sh` bootstrap remain intentionally self-contained.
- 文档：一键安装/升级命令的域名改为专用子域名 `https://sun.xxv.cc`（脚本挂在根路径），替换原 `https://xxv.cc/sun.sh`。
  Docs: the install/upgrade one-liners now use the dedicated subdomain `https://sun.xxv.cc` (script served at the root path), replacing `https://xxv.cc/sun.sh`.

- 引导脚本 `sun.sh` 纳入语言体系：交互运行时**第一步即提示选择语言**（中文 / English），其自身输出随之单语显示；也支持 `--lang zh|en` 与 `UI_LANG`/`SUN_LANG`。所选语言会传给目标脚本（菜单/安装器因此不再二次提示）；非交互（`--non-interactive`）或无可用终端时不提示，交由目标脚本按默认处理。
  The `sun.sh` bootstrap joins the language system: when run interactively it **prompts for the language as the first step** (zh / en) and renders its own output in that language; it also honors `--lang zh|en` and `UI_LANG`/`SUN_LANG`. The chosen language is passed to the target script (so the menu/installer do not prompt again); it does not prompt when `--non-interactive` is requested or no terminal is available.
- README（中/英）更新：补充首步语言选择与 `--lang`、已签名的 `security-update-notify --upgrade`，并修正 dnf 检测说明为 `needs-restarting -s`。
  README (zh/en): document the first-step language selection and `--lang`, the signed `security-update-notify --upgrade`, and correct the dnf detection note to `needs-restarting -s`.

## 1.7.0

- 交互体验：安装器、菜单、检查/诊断、卸载等终端交互不再中英文混排。进入时第一步选择语言（中文 / English），之后全部按所选语言单语显示；新增 `--lang zh|en` 参数与 `UI_LANG`/`SUN_LANG` 环境变量。
  Interactive UX: the installer, menu, check/doctor and uninstall no longer mix Chinese and English. A language is chosen as the first step (zh / en) and all subsequent terminal output is shown in that single language; adds a `--lang zh|en` option and `UI_LANG`/`SUN_LANG` env vars.
- 所选界面语言同时作为 Telegram 通知语言（`NOTIFY_LANG`）的默认值，去掉安装中重复的“通知语言”提问；仍可用 `--notify-lang` 单独覆盖。
  The chosen UI language also becomes the default Telegram notification language (`NOTIFY_LANG`), removing the duplicate prompt; `--notify-lang` still overrides it.
- 发布安全：正式 tag 构建强制签名（`package.sh` 在 `vX.Y.Z` tag 指向当前提交时要求 GPG 签名，无私钥则失败）；release 发布后 CI 用仓库内公钥校验产物的签名与指纹（只验证、不在 CI 内签名，发布私钥保持离线）。
  Release security: tagged builds require a signature (`package.sh` enforces GPG signing when `vX.Y.Z` points at HEAD), and after a release is published CI verifies the assets' signature and fingerprint with the repo public key (verify-only; the private key stays offline).
- README 新增动态 release 版本徽章（自动跟随最新 release）。
  README gains a dynamic release-version badge that tracks the latest release.

## 1.6.0

- 安全（自升级信任链）：`--upgrade` 不再 `curl https://xxv.cc/sun.sh | bash` 执行未校验的远程脚本。改为直接下载 GitHub 发布包，校验 sha256，并用本程序内置（pin）的指纹强制校验 GPG 签名，**默认 fail-closed**（缺少 gpg/签名即拒绝升级；可用 `SECURITY_UPDATE_NOTIFY_UPGRADE_ALLOW_UNSIGNED=1` 显式放行仅 sha256 的升级）。非 root 时改为 `sudo` 重新执行本地受信二进制，而非管道远程脚本。
  Security (self-upgrade trust chain): `--upgrade` no longer pipes an unverified remote script into root bash. It downloads the GitHub release directly, verifies sha256, and requires a GPG signature against a pinned fingerprint — fail-closed by default.
- dnf 后端降噪：不再因裸 `needs-restarting` 列出“仍在使用旧库的普通进程”就触发提醒（这类列表在长期运行的系统上几乎总是非空）；改为以 `needs-restarting -s`（需要重启的 systemd 服务）作为关注信号。整机重启判断优先匹配 `needs-restarting -r` 的输出文案，避免把命令报错（任意非零退出码）误判为“需要重启”。
  dnf backend noise reduction: stop alerting merely because bare `needs-restarting` lists processes using outdated libraries; use `needs-restarting -s` (services) as the attention signal, and detect reboot from the `-r` message rather than from any non-zero exit code.
- `uninstall.sh --purge-config` 现在会一并删除 `/var/backups/security-update-notify`（其中含 `telegram.env` 的 bot token 副本）与轮转日志。
  `uninstall.sh --purge-config` now also removes `/var/backups/security-update-notify` (which held bot-token copies) and rotated logs.

## 1.5.3

- Patch release: fix CI smoke-test shell quoting after the dynamic version check change.

## 1.5.2

- Patch release: make CI container smoke test validate the current script version dynamically instead of hardcoding `1.5.0`.

## 1.5.1

- Patch release: include CI fixes after v1.5.0 for ShellCheck compatibility and packaging without a CI signing secret key.
- Fix alert hash formatting argument count.

## 1.5.0

- 新增明确升级入口：`security-update-notify --check-upgrade`、`security-update-notify --upgrade`、`sun.sh upgrade`。
- 升级前自动备份关键文件到 `/var/backups/security-update-notify/<timestamp>`；安装/升级失败时尝试自动回滚。
- 安装/升级后默认运行自检：版本、systemd unit 校验、doctor（跳过 Telegram 联通性）。
- 新增 `NOTIFY_UPGRADE` / `--notify-upgrade`：升级成功后可发送 Telegram 通知。
- 新增 `CONFIG_VERSION=2`，为后续配置迁移预留稳定字段。
- 发布包支持可选 GPG detached signature；`sun.sh` 新增 `--verify-signature auto|required|off`。
- CI 增加升级默认值与通知回归覆盖。

## 1.4.0

- Telegram OK/告警提醒新增公网 IP 字段，默认运行时自动获取，便于多 VPS 场景下快速识别服务器。
- 新增 `PUBLIC_IP` 与 `INCLUDE_PUBLIC_IP` 配置项；可手动固定 IP，或关闭通知中的公网 IP 显示。
- 安装器支持 `--public-ip`、`--include-public-ip` 与 `--notify-ok` 参数，并会把对应配置写入 `telegram.env`。
- 安装器升级体验改进：重新运行安装器时会读取已有 `telegram.env` 和 timer 时间，未显式覆盖的选项自动沿用旧配置。

## 1.3.2

- 运行时及安装器中所有 Telegram API 调用新增 bot token 格式校验（`^\d+:[A-Za-z0-9_-]+$`），作为 URL 注入纵深防御。
- 运行时脚本明确注释说明 `set -uo pipefail` 故意省略 `-e` 的设计意图。
- systemd service 新增 `ProtectHostname`、`RestrictNamespaces`、`RestrictRealtime` 硬化指令。
- CI 新增 ShellCheck 静态分析步骤。
- `.env.example` 新增关于未引号值中 `#` 字符需要用引号包裹的说明。

## 1.3.1

- 修复 Telegram OK/告警提醒总是中英双语同屏的问题；`NOTIFY_LANG=zh|en` 现在只控制实际发送中文或英文。
- 更新安装器、`.env.example` 和 README 中关于 `NOTIFY_LANG` 的说明，避免将它描述为双语显示顺序。
- 加固安装器写入 `telegram.env` 的引用格式，避免 `HOST_LABEL` 中的空格或 `#` 被写成运行时不可还原的值。
- DNF 自动更新配置备份改用 security-update-notify 专用命名；卸载清理仍兼容旧版备份命名。
- 去重哈希纳入 `NOTIFY_LANG`，切换通知语言或升级到新版后不会被旧语言告警状态错误抑制。
- 引导安装脚本解包前额外拒绝符号链接、硬链接等非普通文件条目。

## 1.3.0

- 所有终端交互、帮助、菜单、错误、诊断输出和安装预检 Telegram 测试消息改为中英双语同屏。
- Telegram OK/告警提醒改为中英双语同屏；`NOTIFY_LANG=zh|en` 现在控制中文或英文优先显示顺序。
- README、`.env.example`、systemd 描述和 needrestart 配置注释同步更新为中英双语说明。
- 发布打包改为白名单复制明确文件，避免未跟踪本地文件或维护笔记误入 release。
- 收紧 DNF automatic INI 写入的键匹配，并修正 DNF 模拟重启测试摘要格式。

## 1.2.2

审计加固与发布流程改进。

- 引导脚本在无 TTY 环境下改为明确报错，不再尝试直接重定向不可用的 `/dev/tty`。
- 打包脚本拒绝在 release 文件存在未提交修改时打包，并优先使用匹配 tag 的 commit 时间生成可复现 tarball。
- 安装器移除 Telegram `getMe` 的字符串二次匹配，统一使用 JSON `ok` 字段判断。
- 诊断和运行时脚本不再 source `/etc/os-release`，改为解析需要的 allowlist 字段。
- apt 自动更新配置每次覆盖前都会创建带时间戳的备份，同时保留首次安装备份供 purge 恢复。
- dnf 配置恢复逻辑不再解析 `ls` 输出，改用 `find` 按修改时间选择最新备份。

## 1.2.1

修复一键安装与安装后测试流程。

- 修复 `curl ... | sudo bash` 在校验 release 包后可能卡住的问题：引导脚本不再在执行目标脚本前整体切换 stdin，而是在最终 exec 菜单/安装脚本时才接入 `/dev/tty`。
- 修复运行时 Telegram API 响应判断中的 shell 引号问题，避免安装后发送测试消息时报 Python `SyntaxError`。
- 诊断脚本同步使用 JSON 解析判断 Telegram `ok` 字段，避免字符串匹配与 shell 引号交互导致误判。
- 加固引导脚本：校验版本字符串、规范解析 `.sha256`、检查 tar 包路径并使用 `--no-same-owner` 解包。

## 1.2.0

安全性与用户体验改进。

- 新增 `.env.example` 与 `--env-file`，并保留 `--telegram-token-file`，便于自动化安装时避免 token 出现在 shell history 或进程列表；`.env` 支持未引号值的行尾注释与大小写布尔值。
- Telegram 通知新增中英文双语配置：`NOTIFY_LANG=zh|en`，安装时可选择，默认中文。
- Telegram 提醒摘要改为更易读的人工摘要，减少直接暴露 `needrestart` 原始输出；README 示例已同步新版格式。
- 增强 systemd service 基础硬化，并避免在服务运行时把 Telegram token 暴露到 curl 命令参数中；Telegram 调用会在 Python 进程启动后移除临时环境变量。
- `test.sh` 默认遮蔽 Telegram Chat ID，使用 `--verbose` 才显示完整值。
- 发布包改为使用可复现 gzip 元数据。
- apt 后端不再覆盖发行版默认 `Origins-Pattern`，只设置本工具需要的 unattended-upgrades 本地策略；首次安装会备份 `20auto-upgrades`，purge 时恢复。
- 移除运行时对 `curl` 的依赖，Telegram 调用统一使用 Python 标准库。
- 运行时与诊断脚本不再 `source` 配置文件，改为 allowlist 解析，降低 root 执行配置文件的风险。
- purge 卸载会尝试恢复 SUN 创建的 apt/dnf 配置备份。
- 打包前会清理旧版本 dist 产物，避免 CI/发布混入旧包。

## 1.1.1

安全与发布质量修复。

- 修复 Telegram 配置值写入方式，避免 root 脚本 `source` 配置文件时出现 shell 注入风险。
- 修复 DNF 后端重启检测逻辑，避免 `needs-restarting -r` 的非零退出码中断通知流程。
- 确保全新安装时，会先安装 Telegram 预检所需的最小依赖，再验证 token 和 chat ID。
- 改进卸载流程，清理 service、timer 与 logrotate 集成。
- 改进安装器与引导安装脚本的缺参提示。
- 改进配置缺失时的测试失败提示。
- 使用通用 service 描述，避免绑定个人环境。
- 增加发布打包与 sha256 校验流程。

## 1.1.0

多发行版支持与发布准备更新。

- 运行时工具改名为 `security-update-notify`。
- 新增 Debian/Ubuntu 的 `apt` 后端。
- 新增 RHEL/Rocky/AlmaLinux/Fedora/CentOS Stream/Amazon Linux 2023 的 `dnf` 后端支持层级。
- 新增交互式菜单：安装/升级、卸载、诊断。
- 新增 Telegram 预检。
- 新增 `--allow-best-effort`、`--version`、`--doctor`。
- 新增日志文件与 logrotate 配置。
- 新增网站托管的一键引导安装脚本。
- 新增生成 `.tar.gz` 和 `.sha256` 的打包脚本。

## 1.0.0

初始 Debian/Ubuntu 版本。

- 配置 unattended security updates，不自动重启。
- 增加 reboot-required 与 `needrestart` 检测。
- 增加 Telegram 通知，并对相同告警做去重。
- 增加 systemd timer 定时运行。
