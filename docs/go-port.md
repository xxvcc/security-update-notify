# security-update-notify 3.x 全 Go 架构 / 3.x all-Go architecture

本文记录 3.0.0 完成迁移后、持续加固到 3.1.x 的设计、Linux 兼容、恢复与发布约束。它描述当前实现，不是待办清单。

This document records the design after the completed 3.0.0 migration and its hardening through 3.1.x,
including Linux compatibility, recovery, security, and release constraints. It describes the current implementation.

## 结论 / Bottom line

除 `sun.sh` 外，安装后的产品入口全部由 Go 实现：安装、升级时复用配置、消息通知设置、定时检查、诊断、
显式通知测试、卸载、自升级和发布打包都由 Go 包及同一个受版本绑定的二进制承担。发布包不再包含第二套运行
时。为让已发布的 2.x 客户端跨过大版本，Go 打包器确定性生成一个只做架构选择与 `exec` 的 `install.sh`
迁移启动器和一个不可执行的版本标记；两者不进入安装结果，也不恢复旧 Shell 安装实现。

Except for `sun.sh`, every installed product entry point is implemented in Go. Release archives no longer
carry a second runtime. To let already-released 2.x clients cross the major-version boundary, the Go
packager deterministically generates a migration-only `install.sh` that selects and `exec`s the verified
Go installer plus a non-executable version marker. Neither is installed or restores the old shell installer.

“全 Go”仍有两个明确边界：

1. `sun.sh` 在可信 SUN 二进制存在之前运行，因此保留下载、SHA-256、固定指纹 GPG 验签、安全归档检查、
   解包和五架构选择。它是唯一维护的 Shell 产品实现，也是首次安装的引导信任边界。3.0 归档中的迁移启动器
   是签名包内的固定生成物，只把旧客户端交给 Go 安装器，不承担下载、验签或安装逻辑。
2. `apt-get`、`dpkg`、`dnf`、`dnf5`、`microdnf`、`yum`、`rpm`、`needrestart`、`needs-restarting`、`systemctl`、`systemd-creds` 和
   `gpg` 是操作系统或信任链的数据源。Go 代码以有界超时和净化环境执行它们，而不是不准确地重写它们。

Two boundaries remain explicit:

1. `sun.sh` runs before a trusted SUN binary exists. It therefore retains downloading, SHA-256,
   pinned-fingerprint GPG verification, archive validation, extraction, and five-architecture selection.
2. OS/trust commands such as `apt-get`, `dpkg`, `dnf`, `dnf5`, `microdnf`, `yum`, `rpm`, `needrestart`,
   `needs-restarting`, `systemctl`, `systemd-creds`, and `gpg` remain authoritative inputs executed with bounded timeouts and
   a sanitized environment.

这些外部命令统一在独立 Linux 进程组中运行；context 超时会终止整个组，入口进程也会把 `Ctrl+C`、
`SIGHUP` 和 `SIGTERM` 转发给所有活动组，并在父进程异常死亡时触发直接子进程死亡信号。这样既限制等待时间，
也避免中断安装、诊断或发布时遗留后台子进程。

All external commands run in dedicated Linux process groups. Context deadlines terminate the complete
group, entrypoints forward `Ctrl+C`, `SIGHUP`, and `SIGTERM` to every active group, and direct children
receive a parent-death signal on abnormal termination. This bounds waits without orphaning background
work when installation, diagnostics, or release packaging is interrupted.

## 命令面 / Command surface

安装后的 `/usr/local/sbin/security-update-notify` 是唯一管理和运行入口：

| 任务 / Task | 命令 / Command |
| --- | --- |
| 定时或手动检查 / scheduled or manual check | `security-update-notify run`（裸调用仍兼容为 run） |
| 安装或复用配置升级 / install or config-preserving upgrade | `security-update-notify install` |
| 消息通知设置 / notification settings | `security-update-notify configure notifications` |
| 诊断 / diagnostics | `security-update-notify doctor` |
| 检查新版 / check for a release | `security-update-notify check-upgrade` |
| 验签自升级 / verified self-upgrade | `security-update-notify upgrade` |
| 诊断和通知测试 / diagnostics and notification tests | `security-update-notify test` |
| 卸载 / uninstall | `security-update-notify uninstall` |
| 发布打包 / release packaging | `go run ./cmd/sun-release package` |

2.x 的 flag 风格运行参数仍为已装 systemd 单元和自动化保留兼容，但当前文档与新集成应使用显式子命令。
`test --send-test` 和 `test --simulate-reboot` 最多等待运行锁 60 秒；超时返回 `75`，不会把未发送误报为成功。

The 2.x flag-style runtime options remain compatible for installed systemd units and automation, but new
documentation and integrations use explicit subcommands. `test --send-test` and
`test --simulate-reboot` wait up to 60 seconds for the runtime lock and return `75` on timeout.

## Go 模块边界 / Go package boundaries

```text
cmd/security-update-notify/  单二进制入口 / single product binary
cmd/sun-release/             Go 发布工具 / Go release tool
internal/cli/                子命令、交互、隐藏输入、退出码 / command dispatch and UI
internal/installer/          安装计划、锁、备份、提交、回滚 / transactional installer
internal/uninstaller/        systemd、文件、凭据及可选配置清理 / transactional cleanup
internal/run/                检查、诊断、通知、自升级 / checks, diagnostics, delivery, upgrade
internal/backend/            apt/DNF4/DNF5 状态采集与解析 / apt, DNF4, and DNF5 collection
internal/osrel/              发行版 profile、支持分级与 DNF 代际 / distro profiles and support tiers
internal/aptconfig/          APT 基线、缺失标记与 proof / APT baseline metadata
internal/dnfconfig/          DNF4/DNF5 基线、缺失标记与 proof / DNF baseline metadata
internal/dependencyproof/    依赖创建配置的内容绑定证明 / dependency-default proofs
internal/watchdog/           补丁、策略、仓库、EOL 与版本提示 / maintenance policy
internal/config/             schema 4、22 键兼容格式 / schema-4 config
internal/dedup/              每平台去重状态 / per-platform deduplication
internal/telegram/           Telegram API
internal/feishu/             飞书凭据、Directory 与 Card JSON 2.0 / Feishu integration
internal/dist/               下载、校验、验签、安全归档、自升级 / verified distribution
internal/releasepkg/         五架构可复现打包与签名 / reproducible release packaging
internal/assets/             systemd、logrotate、needrestart、公钥与指纹 / embedded assets
```

## 发行版 profile 与支持分级 / Distribution profiles and support tiers

`BACKEND` 是稳定的用户配置值，只有 `apt` 和 `dnf`；内部 profile 另行区分 APT、DNF4 与 DNF5，并把依赖包、包查询、automatic config/timer/service 和 restart probe 绑定到同一 profile。

| 级别 / Tier | 发行版 / Distributions |
| --- | --- |
| 正式支持 / supported | Debian 12/13；Ubuntu 22.04/24.04/26.04；RHEL-compatible 8/9/10（Rocky/AlmaLinux 实测）；Fedora 43/44 |
| 尽力支持 / best-effort | Debian 11；Ubuntu 20.04；CentOS Stream 9/10；Oracle Linux 8/9/10；CloudLinux 8/9/10；Amazon Linux 2023 |

尽力支持必须显式传入 `--allow-best-effort`。未列出的 `ID_LIKE` 衍生版不会因 ancestry 自动升为正式支持：APT ancestry 必须唯一，DNF 系统还必须在任何包安装、备份或配置写入前，从已安装命令的版本输出明确判定 DNF4/DNF5。模糊、冲突或失败的 ancestry/engine 探测失败关闭。这类衍生版不得跳过安装后 doctor，doctor 失败会回滚安装事务。

Fedora 43/44 使用 DNF5 JSON advisory 与实际可执行事务的交集；RHEL-compatible 与尽力支持的 EL 衍生版使用 DNF4。Ubuntu 20.04 只有在 Ubuntu Pro 结构化状态明确显示 `esm-infra` 已启用时，才采用 ESM 支持终止日；不需要因此关闭全部 EOL 检查。

`BACKEND` remains the stable user-facing value (`apt` or `dnf`), while the internal profile distinguishes
APT, DNF4, and DNF5 and owns their packages, probes, automatic-update configuration, units, and restart
capabilities. Best-effort systems require explicit opt-in. Unlisted `ID_LIKE` derivatives additionally require
an unambiguous ancestry or pre-side-effect DNF generation probe and a mandatory post-install doctor; ambiguity
or a failed doctor rolls the transaction back. Ubuntu 20.04 extends its EOL date only when the structured Ubuntu
Pro status confirms `esm-infra` locally.

## 安装事务 / Installation transaction

Go 安装器保留并收紧了既有运维契约：

- 只允许 root 安装，使用独立安装锁串行化并发事务；锁描述符不传给包管理器或装后子进程。
- 在第一次受管写入或依赖包写入前静止旧 timer/service，并跨过运行锁屏障。
- 依赖缺失时，交互模式先确认，`--non-interactive` 或 `-y` 明确授权后使用 apt 或 dnf 安装；不支持的
  发行版默认拒绝，尽力支持必须显式开启。
- 关键文件在 `/var/backups/security-update-notify/<timestamp>` 中快照，目录唯一且 root-only；失败时再次
  静止任务、恢复文件、凭据以及 timer 的 persistent/runtime enablement 和 active 状态。
- 配置、systemd unit、logrotate、needrestart 与自动更新策略均以临时文件加原子替换提交；文件系统访问
  拒绝符号链接祖先、RootFS 越界和检查后替换竞态。
- APT 原始配置缺失标记先于包管理器写入持久化并纳入事务快照；若本次依赖事务创建 vendor 默认配置，内容绑定 proof 使其成为稳定基线。APT 配置目录中的标记、proof 和时间戳备份都使用静默忽略的 `.bak` 后缀，旧文件名在升级时保内容迁移。
- DNF4 对依赖创建的 `/etc/dnf/automatic.conf` 使用同样的可验证 vendor 基线；DNF5 的包声明该文件可缺失并提供内置 fallback，因此保留代际绑定的缺失标记。无法建立可信基线、proof 不匹配或元数据组合模糊时，安装、重试和 purge 都不猜测来源。
- purge 恢复使用目录句柄、无覆盖 rename、内容/元数据复验和 Linux 文件系统 syscall；管理员并发替换目标时
  保留 `.security-update-notify-restore.*`、`.security-update-notify-purge.*` 或
  `.security-update-notify-conflict.*` 现场，而不覆盖或删除新文件。
- 飞书 App Secret 优先转存为加密 systemd credential；旧 systemd 回退到独立 `0600` root-only 文件。
  Secret 不进入普通配置、命令行、日志或升级备份。
- 首次或变更飞书接收人时，交互和非交互安装都默认进行事务内飞书单平台强验证，失败会回滚；交互模式可
  输入 `n`，或使用 `--skip-feishu-test`、`--skip-notify-test`，明确抑制该默认发送。显式 `--send-test`
  还会在安装后额外测试全部已配置接收平台，其失败只作为咨询告警返回，不回滚核心安装。
- 运行锁屏障默认等待 60 秒，可用 `--lock-wait 0..3600` 或进程环境
  `SECURITY_UPDATE_NOTIFY_LOCK_WAIT_SECONDS` 调整；等待耗尽以临时失败码 `75` 回滚。
- 对已列出的发行版，装后 doctor 中的磁盘、EOL 等环境问题是咨询式，不回滚文件层面正确的安装；对未列 `ID_LIKE` 衍生版，同一 doctor 是不可跳过的支持门禁，失败必须回滚。

The Go installer serializes transactions, quiesces the old timer before managed or dependency writes,
crosses the runtime-lock barrier, snapshots and atomically commits managed state, and restores files,
credentials, and exact timer enablement/activity on failure. Secrets remain outside normal config and
backups. A new or changed Feishu recipient is strongly verified by default in both interactive and
non-interactive modes unless explicitly skipped; a separate all-platform post-install test remains opt-in and advisory.
Originally absent APT and DNF policies are recorded before package-manager writes. A dependency-created APT
or DNF4 vendor file is promoted only with trusted transaction provenance and content-bound proof; DNF5 retains
its generation-bound absence semantics. Purge uses directory handles, no-overwrite renames, and content/metadata
revalidation to preserve concurrent administrator changes. Post-install doctor findings are advisory on listed
distributions, but the same doctor is a mandatory rollback-producing support gate for an unlisted derivative.

## 兼容不变量 / Compatibility invariants

3.0 不要求已装机器手工迁移配置或去重状态。以下约束由回归测试锁定：

- 配置路径仍为 `/etc/security-update-notify/telegram.env`，名称仅为历史兼容。schema 固定为 4，写入
  22 个白名单键、固定顺序和既有 shell-like quote 格式；默认用单引号，值含单引号时才用双引号，禁止
  同时含两种引号，不使用反斜杠/JSON 转义；文件权限为 `0600`。旧配置缺 `NOTIFY_CHANNELS` 时按
  `telegram`，`DEDUP_MODE=always` 迁移为 `once`。
- 配置文件不可读时运行检查保持 fail-open；畸形行、非法键、非白名单键、缺必需凭据或不支持后端以
  配置错误 `2` fail-closed。
- 布尔兼容语义刻意不完全统一：`INCLUDE_PUBLIC_IP`、`CHECK_UPDATE_HEALTH`、`CHECK_EOL` 和
  `CHECK_SELF_UPDATE` 接受小写化后的 `1/true/yes/on`，`NOTIFY_OK` 与 `NOTIFY_UPGRADE` 仍只接受精确 `1`。
- 告警哈希保持恰好 11 个换行终止字段：主机、后端、语言、重启状态/包/摘要、健康状态/签名、EOL
  状态/签名。不得增加第 12 个字段；动态包名和版本先稳定排序再摘要。
- `HOST` 依次取 `hostname -f`、`hostname`、`unknown`；子进程统一 `LC_ALL=C`。`reboot_pkgs` 和服务列表
  使用 C locale 顺序排序去重且无末尾换行；`HEALTH_SIG` 排序、逗号连接并保留尾逗号。
- apt 的 `restart_signal` 固定为 KCUR/KEXP/KSTA 加排序服务列表，整体移除末尾换行；dnf 只使用排序服务
  列表。apt 的 restart summary 携带真实换行，dnf 保留字面 `\n`，渲染层各只进行一次兼容替换。
- needrestart 仅在 KCUR 与 KEXP 明确不同、KSTA 为 2/3 或出现任一 `NEEDRESTART-SVC:` 行时触发关注；
  KSTA=0、SESS 与 AUX 不触发。needs-restarting 先匹配明确“需要重启”文本，再匹配明确“不需要”文本，
  仅在都未匹配时把 rc=1 当作重启；其他非零退出不能误报重启。缺 `-s` 能力时只判断整机并给可见提示。
- 去重文件继续原子写入，先提交时间戳再提交 hash；第二步失败时保留旧 hash，使下一次倾向重发而不是
  静默压制真实告警。Telegram 与飞书有独立状态，双发部分失败只重试失败平台。
- 普通 timer 运行才写补丁 first-seen 与版本缓存；doctor 强制只读刷新；测试模拟与 dry-run 不写这些
  状态，也不触发周期版本请求。周期版本检查只通知，绝不自动升级。
- Telegram token 必须匹配 `^\d+:[A-Za-z0-9_-]+$`；正文超过 4096 rune 时截为前 4000 rune 加固定提示。
  最多尝试三次、间隔一秒，只重试网络错误、HTTP 429 和任意 5xx；`ok=false` 与其他 4xx 立即永久失败。
- 飞书固定向应用级 `open_id` 发送内嵌 Card JSON 2.0，不增加事件订阅或回调。App Secret 只从隐藏输入、
  systemd credential 或已验证的 root-only 普通文件进入内存；Directory v1 扫描只用于选人。更换 App ID
  时必须重新选择或显式提供接收人，不能跨应用复用 `open_id`。
- DNF5 的 JSON 安全公告必须与实际可执行的 `check-upgrade` 候选取交集；忽略 versionlock/exclude 的查询只使用单次命令选项，不修改持久 DNF 配置。DNF4 安装成功后只保留主 `dnf-automatic.timer` 启用，并禁用三个互斥变体；安装回滚恢复四个 unit 的精确原状态。
- 退出码保持 `0/1/2/75`：成功或无需动作 / 操作或发送失败 / 参数配置错误 / 显式锁等待超时。默认运行
  锁竞争仍安静返回成功，避免 timer 重叠产生噪声。

Existing schema-4 config, state, notification text, per-platform retry behavior, and exit-code contracts
remain compatible. The tests treat the 11-field dedup frame, newline details, atomic commit order, and
read-only diagnostic/test behavior as byte-level invariants.

## 分发与信任链 / Distribution and trust chain

根 `VERSION` 是唯一版本源，必须恰好是一行 `VERSION="X.Y.Z"` 并带末尾换行。发布工具把它绑定到：

- 唯一的 `## X.Y.Z` CHANGELOG 标题；
- `vX.Y.Z` tag（存在或正式发布时）；
- tar 顶层目录和包内 `VERSION`；
- 五个 Go 二进制的编译期版本及 `--version` 输出；
- tarball、checksum、归档 detached signature 和 `sun.sh.asc` 的文件名，以及脚本签名中的关键版本 notation。

Root `VERSION` is the sole version source and is bound to the unique changelog heading, tag, archive
directory, packaged version, all binary versions, the four release-asset names, and the critical notation in
the bootstrap signature.

正式包固定且只支持以下 Linux 架构，集合不可由环境变量或命令行缩小：

```text
amd64  arm64  386  ppc64le  s390x
```

缺 Go、缺任一二进制、版本不一致或运行在未列架构时 fail-closed。没有 Bash 运行时回退，也没有 armv7、
riscv64 或其他架构的隐式兼容承诺。源码用户也必须按根 `VERSION` 注入版本后再执行 Go 安装子命令。

Missing Go, any binary, or any version binding fails closed. There is no runtime fallback and no implicit
support promise for armv7, riscv64, or any other architecture.

`sun.sh` 与 Go 自升级采用同一信任原则：镜像优先、GitHub 仅在完整资产集合传输失败时回退；一旦选定完整
集合，任何 checksum、签名、指纹或版本失败都会中止，不能用回退掩盖篡改。GPG 验签在解包前完成，固定
指纹 `C678256ACBFC6491BF5076655F3AE24999921FFC` 不可由环境覆盖。`gpg` 存在时签名恒为必需；Go 自升级的
SHA-256-only 应急分支仅在本机确实没有 `gpg` 且管理员显式设置
`SECURITY_UPDATE_NOTIFY_UPGRADE_ALLOW_UNSIGNED=1` 时可达，网络失败不能触发降级。`sun.sh` 默认也始终
要求签名，只有显式 `--verify-signature off` 才会关闭。归档检查拒绝绝对路径、`..`、顶层目录外条目、
链接/特殊文件、过多条目和超出声明上限的内容，并剥离归档所有者及特殊权限。

首次安装另有一条更早的信任边界：便捷 `curl | bash` 必须在脚本能够自验之前先信任 HTTPS。正式发布工具
因此使用同一离线密钥额外生成 `sun.sh.asc`；其 hashed 子包以关键 notation 绑定根 `VERSION`。镜像将它绑定到
已验签归档内的 `sun.sh` 和公钥，并只发布在不可变版本目录。高保障文档流程由管理员显式固定目标版本和主密钥指纹，在 root 自有临时目录完成脚本、指纹、critical 标志和版本 notation 的唯一性校验后
才运行脚本；它刻意不把未签名 `latest.json` 当作版本新鲜度证明。稳定 `sun.sh` 仅保留旧的一行入口兼容性，
不假装与多文件版本化信任集具有原子更新语义。

First install has an earlier trust boundary: convenient `curl | bash` must trust HTTPS before the script can
authenticate anything. Official packaging therefore creates `sun.sh.asc` with the same offline key and binds
the root `VERSION` in a critical notation inside the signature's hashed subpackets. The mirror binds it to
`sun.sh` and the public key from the verified archive and publishes the set only under an immutable version
directory. The high-assurance procedure pins both an explicit version and the primary-key fingerprint, then
checks the unique signature, critical flag, and version notation in a root-owned temporary directory before execution; it deliberately does not treat unsigned
`latest.json` as a freshness proof. Stable `sun.sh` remains only for one-line compatibility and is not presented
as an atomically updated multi-file trust set.

The 3.x self-upgrade path selects the exact current-architecture ELF and runs its Go
`install --non-interactive -y` transaction directly. A 2.x client first invokes the signed migration
launcher because its released code requires the historical `install.sh` path; that launcher immediately
execs the same Go transaction. Upgrade notifications are best effort and cannot roll back a committed upgrade.

## 发布与门禁 / Release workflow and gates

本地发布入口只有：

```bash
go run ./cmd/sun-release package
```

该工具使用明确白名单构建可复现 tar.gz，交叉编译固定五架构，生成 SHA-256，在正式发布时要求固定指纹的
GPG 私钥，签名后立即复验。未打 tag 的本地开发包可显式 `--sign off`；正式 tag 或 `--release` 不允许无
签名。脏发布源默认拒绝；仅开发诊断可同时显式提供 `--allow-dirty` 和固定
`--source-date-epoch`。

CI/发布门禁包括：

- CI 先对变更分类：只有 `.env.example`、CHANGELOG、README 或 `docs/` 变化时运行文档结构、版本绑定和高保障安装示例快速门禁；其他源码、构建脚本、workflow 或发布输入变化仍运行完整门禁。稳定的 `ci-gate` 聚合任务检查所选层级，是 `main` 唯一的 required status context；管理员仍受严格分支保护，不能直接推送、强推或删除 `main`。
- gofmt、vet、固定版本 `staticcheck`/`govulncheck`、race、至少 75% 的 atomic 总覆盖率和定向安全测试；
- `sun.sh` 及保留构建测试脚本的 Bash 语法、ShellCheck、TTY 输入和精确依赖解析；
- 两次独立构建逐字节一致；
- Go 发布白名单、固定五架构、版本绑定，以及正式发布唯一四文件资产集（归档、checksum、归档签名和带版本 notation 的 `sun.sh.asc`）；
- 五架构实际执行（非本机架构通过 QEMU），而不只做交叉编译；
- 恶意归档、错误 checksum、错误签名/密钥/指纹和 HTTPS 重定向拒绝；
- 五个正式 APT 版本的 schema-3 迁移、失败回滚/purge 和 PTY 通知生命周期；八个正式 RPM 镜像与八个尽力支持镜像的真实依赖、安装、升级和卸载；
- amd64、arm64、386、ppc64le、s390x 均实际执行关键恢复 syscall 测试，而不只做交叉编译；
- GitHub Release 公开资产及镜像公开回读的 SHA-256、GPG、指纹和版本复验。
- 所有 GitHub Actions 固定完整 commit SHA，正式 Release 不可变；无权限 release CI 仅作为事件信号，镜像由默认分支的受信 workflow revision 按固定 `head_sha` 独立复验 tag、签名、归档、五架构静态运行时与版本，tag 仅作为不执行的数据；部署密钥只存在于仅允许 `main` 的 `release-mirror` Environment，旧可变 Release 只允许手动修复；每次镜像成功后及每周在 GitHub 托管 Ubuntu 22.04/24.04 真机执行公网下载、安装、诊断、timer、卸载和 APT 基线恢复 canary。

容器兼容与回滚脚本会改系统路径，必须只在一次性容器中运行，禁止直接在宿主机执行。

## 2.x 到 3.0 的迁移 / Migration from 2.x

现有受支持架构机器可通过签名自升级原地迁移：下载并验证 3.0 包后，旧 2.x 进程调用包内固定的迁移启动器；
启动器按 `uname -m` 选择已验签的当前架构 Go 二进制并立即 `exec ... install`。旧 Bash 客户端读取同一包内的
不可执行版本标记完成版本绑定。schema 4 配置、timer 时间、通知凭据、去重状态和受管自动更新配置均保留；
失败恢复旧二进制、文件和 timer 状态。

Machines on a supported architecture migrate in place through verified self-upgrade. After authenticating
the 3.0 archive, a 2.x process invokes the fixed migration launcher, which immediately execs the verified
architecture-specific Go installer. A non-executable version marker satisfies older Bash clients' version
binding. Schema-4 config, timer schedule, credentials, dedup state, and managed policy are preserved.

未列架构没有 3.0 运行时，升级会在替换前明确失败。继续支持这类机器需要先新增完整 Go 构建、实跑、打包、
引导选择和 CI 门禁，不能通过恢复无验证回退路径绕过架构契约。
