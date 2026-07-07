# 变更记录

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
