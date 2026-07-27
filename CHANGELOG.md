# 变更记录

## 3.1.0

- 扩大并分级 Linux 支持矩阵：正式支持 Debian 12/13、Ubuntu 22.04/24.04/26.04、RHEL-compatible 8/9/10（Rocky/AlmaLinux 实测）及 Fedora 43/44；Debian 11、Ubuntu 20.04、CentOS Stream 9/10、Oracle Linux 8/9/10、CloudLinux 8/9/10 和 Amazon Linux 2023 进入显式 opt-in 的尽力支持。未知 `ID_LIKE` 衍生版只会在任何安装副作用前明确探测出 apt 或 DNF4/DNF5 且完整安装后 doctor 通过时接受，模糊或冲突 ancestry 失败关闭。
  Expands and tiers Linux compatibility: Debian 12/13, Ubuntu 22.04/24.04/26.04, RHEL-compatible 8/9/10 (lifecycle-tested on Rocky/AlmaLinux), and Fedora 43/44 are officially supported. Debian 11, Ubuntu 20.04, CentOS Stream 9/10, Oracle Linux 8/9/10, CloudLinux 8/9/10, and Amazon Linux 2023 require explicit best-effort opt-in. An unlisted `ID_LIKE` derivative is accepted only when apt or the installed DNF4/DNF5 generation is established before any installation side effect and the mandatory post-install doctor succeeds; ambiguous or conflicting ancestry fails closed.
- 新增完整 DNF5 后端：使用原生 automatic timer、JSON 安全公告、事务候选交集、`check-upgrade` 退出码 100、restart probes，以及不改写持久配置的 versionlock/exclude 绕过查询；DNF4 同时覆盖 EL10 极简系统、四种互斥 automatic timer 和 Amazon Linux 包名差异。软件源、EOL、被锁定安全包、待安装补丁及 doctor/watchdog 逻辑按发行版 profile 统一处理。
  Adds a complete DNF5 backend with the native automatic timer, JSON security advisories, transaction-candidate intersection, `check-upgrade` exit code 100, restart probes, and per-query versionlock/exclude bypass without persistent DNF changes. DNF4 now also covers EL10 minimal systems, all four mutually exclusive automatic timers, and Amazon Linux package naming. Repository health, EOL, blocked security packages, pending updates, doctor, and watchdog behavior are driven by the shared distribution profile.
- 加固 APT/DNF 配置所有权和回滚：在包管理器写入前记录原始缺失状态，用内容绑定的 SHA-256 proof 区分依赖包创建的 vendor 默认配置，迁移旧 schema/备份命名，并在来源、内容或 timer 状态无法证明时保留现场而非猜测。`/usr/lib/os-release` 只在规范路径确实不存在时回退，权限、I/O 或解析异常不再被另一份文件掩盖。
  Hardens APT/DNF configuration ownership and rollback: original absence is recorded before package-manager writes, content-bound SHA-256 proofs distinguish vendor defaults created by retained dependencies, old schema/backup names are migrated, and unverifiable provenance, content, or timer state preserves evidence instead of guessing. `/usr/lib/os-release` is now a fallback only when the canonical path is truly absent, so permission, I/O, or parse failures cannot be hidden by a second file.
- 重写 purge 恢复的文件系统边界：目录句柄配合 `openat`/`O_NOFOLLOW` 固定路径，快照内容、inode、mode、uid/gid、mtime 和 xattr，并通过 `RENAME_NOREPLACE`/`RENAME_EXCHANGE`、复验和 `.restore`/`.purge`/`.conflict` 证据避免覆盖或删除管理员并发创建的文件。正常返回的冲突会失败关闭；SIGKILL、内核崩溃或掉电中间点仍不承诺事务原子性，文档要求异常中断后先检查保留证据再重试。
  Reworks purge restoration at the filesystem boundary: directory handles plus `openat`/`O_NOFOLLOW` bind paths, snapshots retain content, inode, mode, uid/gid, mtime, and xattrs, and `RENAME_NOREPLACE`/`RENAME_EXCHANGE`, revalidation, and `.restore`/`.purge`/`.conflict` evidence prevent overwriting or deleting administrator-created concurrent files. Normally returned conflicts fail closed; transactional atomicity across SIGKILL, kernel crashes, or power loss remains explicitly out of scope, and the documentation requires inspecting retained evidence before retrying an interrupted purge.
- 扩大持续验证：五个正式 APT 版本各跑 schema-3、失败回滚/purge 和 PTY 通知生命周期；八个正式 RPM 镜像及八个尽力支持镜像使用实际打包产物验证依赖、安装、升级和卸载；Fedora 43/44 使用本地构造安全公告验证 DNF5 versionlock；amd64、arm64、386、ppc64le、s390x 均实际执行恢复 syscall。ShellCheck 提升到 info 级别，并修复会让 DNF5 门禁假绿或因 `pipefail`/SIGPIPE 偶发退出 141 的断言。
  Expands continuous verification: every official APT version runs schema-3 migration, failed-upgrade rollback/purge, and PTY notification lifecycles; eight official RPM images and eight best-effort images exercise dependencies, installation, upgrade, and uninstall with the packaged runtime; Fedora 43/44 use a locally built security advisory to verify DNF5 versionlock behavior; and restore syscalls execute on amd64, arm64, 386, ppc64le, and s390x. ShellCheck now runs at info severity, and the DNF5 assertions that could pass falsely or intermittently exit 141 under `pipefail`/SIGPIPE are fixed.

## 3.0.2

- 新增高保障首次安装信任链：正式打包使用同一离线固定指纹密钥同时签署发布归档和 `sun.sh`，并在脚本签名的 hashed 子包中用关键 notation 绑定根版本；镜像只在归档、源码、脚本签名、版本、公钥全部一致且公网回读复验成功后发布版本化 `sun.sh`、`sun.sh.asc` 和公钥。文档提供显式版本、root 自有临时目录、固定指纹与版本绑定校验后才执行脚本的流程；原 `curl | bash` 入口保持兼容并明确其第一阶段依赖 HTTPS。
  Adds a high-assurance first-install trust chain: official packaging signs both the release archive and `sun.sh` with the same offline pinned-fingerprint key and binds the root version in a critical notation inside the bootstrap signature's hashed subpackets. The mirror publishes versioned `sun.sh`, `sun.sh.asc`, and the public key only after archive/source/signature/version/key consistency checks and public read-back verification. Documentation now provides an explicit-version, root-owned temporary-directory flow that executes the bootstrap only after fingerprint and version-binding verification; the existing `curl | bash` entry remains compatible with its first-stage HTTPS trust boundary stated explicitly.
- 加固供应链和持续验证：GitHub Actions 全部固定到完整 commit SHA，并由 Dependabot 每周汇总更新；仓库启用不可变 Release，发布与镜像门禁要求新版本恰好包含四个签名资产。无部署权限的 release CI 只作为事件信号与纵深检查；默认分支镜像门禁按其固定 `head_sha` 检出并确认 tag 未移动，再独立校验签名、归档、五架构 ELF/静态链接与实际版本。离线固定指纹不再由 tag 自己决定，旧可变 Release 只允许从 `main` 手动修复，SSH 密钥只保留在仅允许 `main` 部署的 Environment；按 tag 的镜像并发和无丢弃 canary 避免无关 CI 完成替换待处理发布。race/atomic 总覆盖率门槛提高到 75%，并新增每周及镜像完成后在 GitHub 托管 Ubuntu 22.04/24.04 真机运行的公网下载、验签、安装、跳过假通知凭据联网探测的 doctor、dry-run、timer、卸载和 APT 状态恢复 canary；root-only 临时配置隔离托管 runner 预先存在的补丁维护状态，安装前后的有界 APT/dpkg 基线则防止产品引入新的包状态损坏。
  Hardens the supply chain and continuous verification: every GitHub Action is pinned to a full commit SHA with weekly grouped Dependabot updates; repository Release immutability is enabled, and release/mirror gates require exactly four signed assets for new versions. Unprivileged release CI is only an event signal and defense-in-depth check; the default-branch mirror gate checks out its fixed `head_sha`, confirms the tag has not moved, and independently verifies signatures, the archive, all five ELF/static-link identities, and actual versions. The offline pinned fingerprint is no longer selected by the tag, mutable legacy releases are manual repairs from `main` only, and SSH credentials exist only in an Environment restricted to `main`; per-tag mirror concurrency and non-dropping canaries prevent unrelated CI completions from replacing a pending release. The race/atomic total-coverage gate rises to 75%, with a real GitHub-hosted Ubuntu 22.04/24.04 canary running weekly and after mirror completion to exercise public downloads, signatures, installation, doctor without probing its fake notification credentials, dry-run, timer state, uninstall, and APT-state restoration. A root-only temporary configuration isolates pre-existing hosted-runner patch-maintenance state, while bounded pre/post APT and dpkg baselines ensure that the product does not introduce new package-state damage.

## 3.0.1

- 修复 APT 已卸载但残留 `config-files` 状态被误判为已安装的问题：安装器现在严格要求 `Status: install ok installed` 并补装缺失依赖，doctor 检查全部关键包且不会在依赖缺失时同时报告机制健康。APT 原始配置不存在时使用在包管理器写入前持久化的事务缺失标记，彻底清理可恢复“原本不存在”；标记与时间戳备份统一以 APT 静默忽略的 `.bak` 结尾，并迁移会让每次 apt 调用产生文件扩展名提示的旧命名；迁移后若安装在后续步骤失败，新旧动态元数据也会随事务完整回滚。DNF 使用固定原始基线，跨普通卸载、重装和 purge 仍恢复首次接管前的 `automatic.conf`。
  Fixes APT packages in `deinstall ok config-files` state being treated as installed: the installer now requires exact installed status and reinstalls missing dependencies, while doctor checks every required package and cannot also report a healthy mechanism when one is absent. A transaction-protected absence marker is persisted before package-manager writes so purge can restore an originally missing APT config even across abrupt interruption. The marker and timestamped backups now end in APT's silently ignored `.bak` suffix, and legacy names that emitted an invalid-extension notice during every apt invocation are migrated; if a later install step fails, both fixed and dynamically discovered metadata names are restored by the transaction. DNF keeps one fixed original baseline across normal uninstall, reinstall, and purge.
- 加固交互状态机：非法语言、平台、菜单、y/N、时间、去重模式、间隔和空必填项会本地化提示并循环重问，EOF 明确显示取消，隐藏输入不泄漏底层英文错误；依赖确认后立即显示安装阶段，临时 Telegram/飞书故障跳过时明确说明当前输入尚未验证。
  Hardens the interactive state machine: invalid language, platform, menu, yes/no, time, dedup mode, interval, and empty required input are localized and retried; EOF is an explicit cancellation and hidden input no longer leaks lower-level English errors. Dependency installation gets an immediate progress message, and skipped temporary Telegram/Feishu failures now say that current input remains unverified.
- 明确通知测试边界：`--skip-notify-test` 会抑制首次或变更飞书接收人的默认发送；该飞书强验证未跳过时仍属于事务并在失败时回滚。显式 `--send-test` 的额外全平台测试改为安装后咨询项，失败会告警但不再撤销已完成升级或关闭 timer。
  Clarifies notification-test boundaries: `--skip-notify-test` suppresses the default send for a new or changed Feishu recipient, while an unskipped strong Feishu verification remains transactional and rolls back on failure. An explicit `--send-test` all-platform check is now post-install advisory work: failure warns without undoing a completed upgrade or disabling its timer.
- 修复 Rocky/RHEL 极简系统的引导依赖冲突：`sun.sh` 只安装缺失命令对应的软件包，不再因只缺 `gpg` 而请求完整 `curl/coreutils` 与 `curl-minimal/coreutils-single` 冲突，并移除未纳入依赖检查的隐式 `awk` 要求；`install --lang` 与前置 `--lang` 都控制引导语言，非法选择重试，TTY 结束明确取消。文档标明 URL 启动必须预装 `curl`，推荐管道启用 `pipefail`。
  Fixes bootstrap conflicts on minimal Rocky/RHEL systems: `sun.sh` installs only packages mapped to missing commands, so a missing `gpg` no longer requests full `curl/coreutils` against `curl-minimal/coreutils-single`, and it no longer has an implicit unchecked dependency on `awk`. Both `install --lang` and a leading `--lang` control bootstrap output, invalid choices retry, and TTY EOF cancels explicitly. Documentation now identifies `curl` as a URL-entry prerequisite and enables `pipefail` in recommended pipelines.
- 所有日常外部命令均有界：`needrestart/needs-restarting`、systemd 查询和身份/时间探针分别使用明确超时，oneshot service 增加 15 分钟总上限，内置自升级的已验签安装器增加 1 小时上限；Telegram/飞书重试等待会响应 context 取消，不会越过交互预检 deadline。外部命令运行在独立进程组中，超时、`Ctrl+C`、`SIGHUP` 和 `SIGTERM` 会清理整个活动进程组，父进程异常退出另有直接子进程死亡保护，不会把当前包管理器或探针留在后台。systemd 属性查询对任意非零退出均失败，底层执行器把 context 超时作为显式错误返回。幂等 purge 只忽略目标 unit 的精确英文 missing-unit 诊断，权限、D-Bus 和其他错误仍保留。
  Bounds every routine external command: restart probes, systemd queries, and identity/time probes use explicit limits, the oneshot service has a 15-minute ceiling, and the verified installer launched by self-upgrade has a one-hour ceiling. Telegram and Feishu retry delays honor context cancellation instead of overrunning interactive-preflight deadlines. External commands run in dedicated process groups: timeouts, `Ctrl+C`, `SIGHUP`, and `SIGTERM` clean up the complete active group, while a parent-death guard protects the direct child on abnormal exit, so the current package manager or probe is not left running in the background. Any nonzero systemd property query fails, context timeouts are explicit executor errors, and idempotent purge suppresses only exact target-unit missing diagnostics while preserving permission, D-Bus, and unrelated failures.
- 收紧发布与 CI：正式 `--release` 或对应 annotated tag 在创建产物前拒绝 `--sign off`；生命周期脚本只选择根 `VERSION` 对应归档。固定 Go 1.26.5 修复标准库漏洞并加入固定 `govulncheck v1.6.0` 门禁，同时新增 bootstrap TTY/依赖、CLI 状态机、包状态、基线恢复、systemd 非零/超时及跨卸载重装回归。
  Tightens release and CI gates: an explicit official release or matching annotated tag rejects `--sign off` before creating artifacts, and lifecycle scripts select only the archive bound to root `VERSION`. Go 1.26.5 removes the affected standard-library toolchain and CI pins `govulncheck v1.6.0`, with new bootstrap TTY/package, CLI state-machine, package-status, baseline-restoration, systemd failure/timeout, and cross-uninstall/reinstall regressions.
- 收紧数值和归档边界：文件系统可用空间使用 128 位中间乘积并在超出通知数据类型时饱和，恶意 tar 权限值在窄化前显式拒绝，运行锁所有者也不再把 EUID 无条件转为 `uint32`。
  Tightens numeric and archive boundaries: filesystem free space uses a 128-bit intermediate product and saturates when the notification data type would overflow, hostile tar modes are rejected before narrowing, and runtime-lock ownership no longer converts the EUID to `uint32` without a range-preserving comparison.

## 3.0.0

- 完成全 Go 产品面迁移：安装/升级、消息通知设置、运行检查、诊断、显式通知测试、卸载、自升级和发布打包均由 Go 实现；`sun.sh` 是唯一维护的 Shell 产品实现，仅负责首次安装前的依赖补齐、下载、SHA-256、固定指纹 GPG 验签、安全解包和架构选择。旧安装、菜单、运行时、测试、卸载与打包实现均已删除。
  Completes the all-Go product migration: install/upgrade, notification settings, runtime checks, diagnostics, explicit notification tests, uninstall, self-upgrade, and release packaging are implemented in Go. `sun.sh` is the only maintained shell product implementation and is limited to first-install bootstrapping and verification. Legacy shell installer, menu, runtime, test, uninstall, and packaging implementations are removed.
- Go 安装器保留 schema 4 的 22 键配置与 `0/1/2/75` 退出码，增加独立安装锁、运行锁屏障、依赖安装确认、原子受管写入、root-only 备份、失败全量回滚、timer 精确状态恢复、飞书 Directory 选人及 systemd credential 生命周期；`security-update-notify configure notifications`、`test` 与 `uninstall` 成为正式子命令。
  The Go installer preserves schema 4's 22-key config and `0/1/2/75` exit codes while providing a dedicated install lock, runtime-lock barrier, dependency confirmation, atomic managed writes, root-only backups, full rollback, exact timer-state restoration, Feishu Directory onboarding, and the systemd-credential lifecycle. `security-update-notify configure notifications`, `test`, and `uninstall` are now first-class subcommands.
- 根 `VERSION` 成为唯一版本源，并绑定唯一 CHANGELOG 标题、tag、包内版本和二进制版本。Go 发布工具 `go run ./cmd/sun-release package` 生成可复现、明确白名单、SHA-256 与 GPG 签名的资产集；正式包固定且只包含 linux/amd64、arm64、386、ppc64le、s390x 五个 Go 二进制，不允许缩小集合，也不再为 armv7、riscv64 等未列架构回退到 Bash 运行时。
  Root `VERSION` is now the single source of truth and is bound to the unique changelog heading, tag, packaged version, and binary versions. The Go release tool, `go run ./cmd/sun-release package`, creates the reproducible allowlisted SHA-256/GPG-signed asset set. Official archives contain exactly linux/amd64, arm64, 386, ppc64le, and s390x Go binaries; the set cannot be reduced, and there is no Bash-runtime fallback for unlisted architectures such as armv7 or riscv64.
- 受支持架构上的 2.x 安装可通过验签自升级原地迁移：Go 打包器为 3.0 归档确定性生成只做架构选择与 `exec` 的 `install.sh` 启动器，以及供旧 Bash 客户端版本绑定的一行不可执行标记；旧进程由此进入已验证 Go 安装事务，保留配置、timer 时间、凭据和去重状态。迁移文件不安装到系统，也不恢复第二套 Shell 安装/运行时实现；未列架构在替换前明确失败。
  Existing 2.x installations on supported architectures migrate in place through verified self-upgrade. The Go packager deterministically generates a minimal `install.sh` architecture/exec launcher and a one-line non-executable version marker for old Bash clients; both lead into the authenticated Go transaction and are never installed. No second shell installer/runtime returns, and unlisted architectures fail before replacement.

- 三轮审计加固通知与凭据边界：Telegram/飞书 API 禁止重定向，限制凭据与响应大小，拒绝符号链接及多行凭据文件，并为 GPG 与 `systemd-creds` 操作增加显式目录和超时。
  Three audit passes harden notification and credential boundaries: Telegram/Feishu API redirects are refused, credential and response sizes are bounded, symlinked or multiline credential files are rejected, and GPG/`systemd-creds` operations use explicit homes and timeouts.
- 自升级归档统一限制路径、条目类型、条目数和声明解压大小；下载、latest 元数据、包内版本及子进程环境覆盖均改为严格绑定。去重状态先提交时间戳再提交 hash，第二步失败时不会静默抑制下一次真实告警。
  Self-upgrade archives now have consistent path, type, entry-count, and declared-size limits; downloads, latest metadata, packaged versions, and child-process environment overrides are strictly bound. Dedup state commits the timestamp before the hash so a failed second commit cannot silently suppress the next real alert.
- 发布和镜像门禁要求 tag、源码版本、五架构 Go 二进制及唯一三文件资产集一致，限制资产大小并绑定 checksum 文件名；Go 诊断接受 schema 4，`--purge-config` 删除 SUN 专用时间戳备份，CI 新增恶意归档与相关回归覆盖，并修复 Docker heredoc 烟测缺少 stdin 导致的空跑假阳性。
  Release and mirror gates now bind the tag, source version, all five Go binaries, and one exact three-file asset set, with asset-size and checksum-filename limits. Go diagnostics accept schema 4, `--purge-config` removes SUN-specific timestamped backups, CI covers hostile archives and related regressions, and the Docker heredoc smoke test no longer passes without running because stdin was detached.

## 2.3.0

- 新增七类补丁维护检测：待安装安全补丁连续滞留（默认 3 天）、APT hold / DNF versionlock 或 exclude 阻断、自动更新策略漂移、包管理器损坏状态、软件源元数据缺失/过期/陈旧及签名/TLS/刷新失败、整机或服务重启需求长期未处理（默认 7 天），以及每周 SUN 新版本提示。
  Adds seven patch-maintenance checks: persistent pending security patches (3 days by default), APT hold / DNF versionlock or exclude blocks, auto-update policy drift, broken package-manager state, missing/expired/stale repository metadata and signature/TLS/refresh failures, overdue host/service restart requirements (7 days by default), and a weekly SUN release notice.
- SUN 版本检查只通知、绝不自动升级；成功结果缓存 7 天，`--doctor` 强制只读刷新，`--test-ok`、`--test-reboot` 和 `--dry-run` 不写状态也不访问版本服务。
  SUN release checks are notify-only and never auto-upgrade. Successful results are cached for seven days; `--doctor` forces a read-only refresh, while `--test-ok`, `--test-reboot`, and `--dry-run` neither mutate state nor contact the release service.
- 配置升级到 schema 4，新增 `PENDING_ALERT_DAYS`、`RESTART_ALERT_DAYS`、`CHECK_SELF_UPDATE` 与 `SELF_UPDATE_CHECK_DAYS`；旧 schema 3 配置缺键时采用安全默认值。`CHECK_UPDATE_HEALTH=0` 关闭策略、完整性和软件源检查，但不影响补丁滞留、重启时长、EOL 或版本提示。
  Config schema 4 adds `PENDING_ALERT_DAYS`, `RESTART_ALERT_DAYS`, `CHECK_SELF_UPDATE`, and `SELF_UPDATE_CHECK_DAYS`; missing keys in schema 3 configs receive safe defaults. `CHECK_UPDATE_HEALTH=0` disables policy, integrity, and repository checks without disabling backlog age, restart age, EOL, or release notices.
- Go 主运行时与 Bash 兼容运行时保持相同原因码、11 字段去重帧、双语正文和飞书卡片语义；仅有 SUN 新版本时使用蓝色卡片。DNF 高危子计数同时包含 `critical` 与 `important`。
  The Go and Bash runtimes share reason codes, the existing 11-field dedup frame, bilingual messages, and Feishu-card semantics; a release-only notice uses a blue card. DNF's high-severity subtotal now includes both `critical` and `important`.

## 2.2.4

- 稳定安装入口迁移到 `https://dl.ll.cd/security-update-notify/sun.sh`，不再依赖 `sun.xxv.cc`；按项目划分的路径为同一下载域名上的后续项目保留独立命名空间。
  Moves the stable installer to `https://dl.ll.cd/security-update-notify/sun.sh`, removing the `sun.xxv.cc` dependency while preserving project-scoped namespaces for future downloads on the same domain.
- `sun.sh` 现在进入签名发布包。镜像工作流仅从校验 SHA-256、GPG 签名和固定指纹后的归档提取脚本，先回读校验版本化副本，再更新稳定脚本，最后更新 `latest.json`；旧版本补同步不能覆盖稳定入口。
  `sun.sh` is now part of the signed release archive. The mirror workflow extracts it only after SHA-256, GPG-signature, and pinned-fingerprint verification, reads back the versioned copy before updating the stable script and finally `latest.json`; repairs of old releases cannot replace the stable entry point.
- 所有 tag 的镜像任务共用仓库级并发锁，并在公网版本文件回读成功后重新确认 GitHub Latest，消除旧任务晚写覆盖新稳定入口的竞态。
  Mirror jobs for all tags share a repository-wide concurrency lock and reconfirm GitHub Latest after public version-file verification, eliminating the race where an older job could overwrite a newer stable entry point.
- 新增由 GitHub Release `published` 事件触发的签名发布镜像：工作流重新校验 SHA-256、GPG 签名和固定指纹后，通过受限 SSH 账号同步到 `https://dl.ll.cd/security-update-notify`；公开回读验签成功后才最后更新 `latest.json`。
  Adds a signed release mirror triggered by GitHub Release `published`: the workflow rechecks SHA-256, the GPG signature, and the pinned fingerprint before syncing through a restricted SSH account to `https://dl.ll.cd/security-update-notify`; `latest.json` is updated last only after public read-back verification succeeds.
- 一键安装器、Go 主运行时和 Bash 兼容运行时统一采用发布镜像优先、GitHub 回退。只有镜像传输不完整时才回退；一旦取得完整资产集合，任何校验失败都会中止，不会用回退掩盖镜像篡改。
  The bootstrap, Go runtime, and Bash compatibility runtime now prefer the release mirror and fall back to GitHub. Fallback occurs only for an incomplete transfer; once a complete asset set is selected, any verification failure aborts instead of hiding mirror tampering behind a fallback.

## 2.2.3

修复安装或升级时 Telegram 预检把临时网络故障误报为 Token 无效，并错误引导用户重录凭据的问题。
Fixes installer and upgrade Telegram preflight incorrectly reporting temporary network failures as invalid tokens and prompting users to replace valid credentials.

- 对连接重置、超时、HTTP 429 和 5xx 最多重试三次；耗尽后明确标记为临时网络故障，不清空 Token 或 Chat ID。
  Connection resets, timeouts, HTTP 429, and 5xx responses are retried up to three times; exhaustion is reported as a temporary network failure without clearing the token or chat ID.
- 交互模式可选择重试连接、跳过本次预检或中止；非交互模式以临时失败码 `75` 退出，使升级事务可靠回滚。Telegram 明确拒绝的 Token 或 Chat ID 仍进入凭据纠正流程。
  Interactive mode can retry, skip this preflight, or abort; non-interactive mode exits with temporary-failure code `75` so the upgrade transaction rolls back reliably. Tokens or chat IDs explicitly rejected by Telegram still enter the credential-correction flow.
- 新增“消息通知设置”交互入口：已有安装可查看当前通知方式、更改 Telegram/飞书接收平台，并分别修改 Telegram 凭据、飞书应用、App Secret 或接收人。移除平台会事务化删除其凭据，新增或修改时只重复验证受影响的平台。
  Adds interactive message-notification settings for existing installs: view the current method, change Telegram/Feishu receiving platforms, and separately update Telegram credentials, the Feishu app, App Secret, or recipient. Removing a platform transactionally deletes its credentials, while additions and edits revalidate only affected platforms.
- 无修改退出设置时不再创建备份、停止 timer 或发送预检消息；`--configure-notifications` 与非交互模式组合会在事务开始前明确拒绝，不会被显式平台参数静默绕过。
  Leaving notification settings unchanged no longer creates a backup, stops the timer, or sends preflight messages. Combining `--configure-notifications` with non-interactive mode is rejected before the transaction and cannot be silently bypassed by explicit platform arguments.
- 同平台凭据轮换会正确标记受影响平台；删除平台不会因跳过已移除平台的预检而返回失败。回归覆盖生产安装事务、临时故障退出码 `75` 回滚、成功凭据删除，以及 Telegram HTTP 429 和 socket 超时。
  Same-platform credential rotation now marks the affected platform correctly, and removing a platform no longer fails while skipping its preflight. Regression coverage includes the production install transaction, rollback on temporary-failure exit `75`, successful credential deletion, Telegram HTTP 429, and socket timeouts.

## 2.2.2

修复飞书 Directory v1 自动选人的分页结束判断，避免权限和凭据均正常时因末页沿用旧 `page_token` 而误报扫描失败。
Fixes Feishu Directory v1 recipient-selection pagination so a final page that retains the previous `page_token` no longer causes a false scan failure when credentials and permissions are valid.

- 分页契约：以 `page_response.has_more=false` 作为权威结束条件，即使响应仍包含旧 token 也正常完成扫描。
  Pagination contract: treat `page_response.has_more=false` as the authoritative end condition, even when the response retains the previous token.
- 故障安全：`has_more=true` 却缺少 token 时明确失败；确实仍有下一页且 token 重复时继续中止，避免死循环或静默遗漏用户。
  Failure safety: fail explicitly when `has_more=true` has no token, and still abort when a genuinely continuing page repeats a token, preventing loops or silently omitted users.
- 回归测试：覆盖末页旧 token、缺失下一页 token 和真实重复 token，同时保留通讯录权限、限流与部分响应测试。
  Regression coverage: add stale-final-token, missing-next-token, and true repeated-token cases while retaining permission, rate-limit, and partial-response tests.

## 2.2.1

飞书首次交互安装或更换接收人时，默认发送一条仅飞书的验证消息，确认所选用户位于机器人可用范围内；双通道安装不会因此重复测试 Telegram。
On the first interactive Feishu install or after changing the recipient, a Feishu-only verification message is sent by default to confirm that the selected user is within the bot availability; dual-channel installs do not duplicate the Telegram test.

- 安装闭环：验证提示默认为 `[Y/n]`，可输入 `n` 跳过；非交互安装保持不自动发送，显式 `--send-test` 仍测试所有已配置渠道。
  Installation closure: the verification prompt defaults to `[Y/n]` and can be skipped with `n`; non-interactive installs still send nothing automatically, while explicit `--send-test` continues to test every configured channel.
- 故障安全：装后测试及 `test.sh` 的显式发送最多等待现有检查释放运行锁 60 秒，超时以退出码 `75` 明确失败，不能把“未发送”误判为成功；升级在任何依赖包写入前禁用并停止旧 timer、跨过运行锁屏障，验证通过后才重新启用。独立安装事务锁会串行化并发安装且不向子进程泄露锁描述符；备份目录通过原子 `mkdir` 保证唯一，保留裁剪始终保护当前事务目录。失败回滚在恢复文件前再次静止 timer/service 并跨过运行锁，再恢复安装前 timer 的 persistent/runtime 启用链接与 active 状态。
  Failure safety: post-install tests and explicit sends from `test.sh` wait up to 60 seconds for an existing run to release the lock and fail explicitly with exit `75` on timeout, so “not sent” cannot be mistaken for success. Before any dependency-package write, upgrades disable and stop the old timer and cross the runtime-lock barrier; it is re-enabled only after verification succeeds. A separate installer transaction lock serializes concurrent installs without leaking its descriptor to child processes; atomic `mkdir` guarantees unique backup directories, and retention always protects the active transaction. Before restoring files, rollback again quiesces the timer/service and crosses the runtime lock, then restores the pre-install persistent/runtime enablement links and active state.
- 最小凭据面：临时验证配置只包含飞书渠道和接收标识，不包含 Telegram 凭据或飞书 App Secret。
  Minimal credential surface: the temporary verification config contains only the Feishu channel and recipient identity, never Telegram credentials or the Feishu App Secret.
- 测试：新增首次安装、双通道跳过、纯 Telegram、已有飞书配置、接收人变更、非交互、显式全渠道测试、Go/Bash 锁竞争、无锁 dry-run、被忽略构建源拦截，以及 fresh/upgrade timer 状态与时间回拨备份回滚覆盖。
  Tests: add coverage for first install, dual-channel opt-out, Telegram-only, existing Feishu configuration, recipient changes, non-interactive mode, explicit all-channel tests, Go/Bash lock contention, lock-free dry runs, ignored build-source rejection, and fresh/upgrade timer-state plus clock-rollback backup restoration.

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
- 告警去重状态文件改为原子写入（`mktemp` + rename）：`>` 会先截断再写，崩溃或磁盘满时可能留下被截断/清空的状态文件；改为临时文件加原子重命名，且时间戳先于 hash 落盘，中途崩溃只会让下次更倾向“发送”，不会静默抑制真实告警。
  The alert-dedup state files are now written atomically (`mktemp` + rename): `>` truncates before writing, so a crash or full disk could leave a truncated/empty state file; writes now go through a temp file plus atomic rename, with the timestamp committed before the hash, so a mid-write crash only biases the next run toward sending, never toward silently suppressing a real alert.
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
