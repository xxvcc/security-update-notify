# 日常运维与恢复

[English](operations.en.md) | [返回 README](../README.md)

本页说明提醒策略、补丁维护检查、受管文件、APT/DNF 行为、日常命令和卸载恢复语义。

## 重复提醒策略

| 模式 | 行为 |
| --- | --- |
| `once` | 同一个告警只发送一次，直到状态变化（旧名 `always`，仍兼容接受）。 |
| `daily` | 同一个告警每天最多发送一次（**默认 / 推荐**）。 |
| `interval` | 同一个告警每 N 天发送一次，默认 `3` 天。 |

默认 `daily`：每天最多提醒一次，既能在重启长期未处理时持续提醒，又不会频繁打扰。若想更安静可用 `once`（只提醒一次）或 `interval`（每 N 天一次）。

双发时每个渠道有独立状态：Telegram 成功而飞书失败时，下一次只重试飞书，不会重复发送 Telegram。

渠道状态还会绑定稳定接收目标：Telegram 使用 bot 数字身份与 Chat ID，飞书使用 App ID 与应用级 `open_id`，磁盘只保存不可逆指纹。通过 `configure notifications` 更换目标时，安装器会在新配置可见前、同一回滚事务中标记该渠道，使下一条真实告警不受旧目标的 `once`/间隔状态压制；发送失败不会推进目标，只有成功投递才提交新指纹。升级前已有的无指纹状态会在首次去重压制时静默绑定当前目标，不发送消息；之后运行时也能识别受保护配置文件中的手工目标变化。

## 安全更新看门狗

除了原有内核、服务重启和发行版 EOL 检测，SUN 默认还会执行七类补丁维护检查：

1. 待安装安全补丁连续存在达到阈值后告警，默认 `3` 天。
2. 发现 APT hold，或 DNF versionlock/exclude 阻止安全补丁时立即告警。
3. 检测 APT/dnf-automatic 的安全更新策略与定时器配置漂移。
4. 运行 `dpkg --audit`、`apt-get check` 或 `dnf check` 检测包管理器损坏状态。
5. 检查 APT InRelease 是否缺失、过期或长期未刷新，并区分软件源刷新失败与签名/TLS 错误；DNF 同样区分元数据读取与签名/TLS 错误。
6. 整机或服务重启需求持续达到阈值后升级告警，默认 `7` 天。
7. 默认每 `7` 天检查一次 SUN 最新发布，只发送新版本提示，**绝不自动升级 SUN**。

| 配置项 | 默认 | 说明 |
| --- | --- | --- |
| `CHECK_UPDATE_HEALTH` | `1` | 检测自动更新机制、有效策略、包管理器一致性和软件源健康：包括定时器禁用或未激活、上次运行失败、长时间无成功记录、磁盘不足、配置漂移、包状态损坏、元数据缺失/过期/陈旧及签名/TLS 错误。设为 `0` 会关闭这一组检查，但不会关闭补丁滞留、重启时长、EOL 或 SUN 版本提示。 |
| `STALE_UPDATE_DAYS` | `7` | 多少天没有成功的自动安全更新即视为异常；设为 `0` 关闭该子项。 |
| `PENDING_ALERT_DAYS` | `3` | 待安装安全更新连续存在多少天后告警；设为 `0` 关闭补丁滞留告警。首次发现时间保存在 root-only 状态文件中，补丁清空后自动移除。 |
| `RESTART_ALERT_DAYS` | `7` | 整机或服务重启需求持续多少天后升级告警；设为 `0` 关闭时长升级。不会自动重启机器或服务。 |
| `CHECK_SELF_UPDATE` | `1` | 周期检查 SUN 新版本；只提示，不自动升级。 |
| `SELF_UPDATE_CHECK_DAYS` | `7` | SUN 版本检查间隔；成功结果会缓存，`security-update-notify doctor` 可强制只读刷新。 |
| `CHECK_EOL` | `1` | 发行版安全支持终止（EOL）提醒：已过 EOL 触发提醒，临近（90 天内）仅作信息展示。Ubuntu 20.04 会自动核对本机 `esm-infra` 状态；只有使用 SUN 无法识别的外部延长支持时，才应考虑设 `0`，并接受这会关闭全部 EOL 检查。 |

待安装数量在阈值以内仍是信息项；达到 `PENDING_ALERT_DAYS` 后才转为风险告警。DNF 的高危子计数同时包含 `critical` 和 `important`。自动更新 timer 即使已经 enabled，只要不是 active 仍会告警；active 且尚无成功或触发历史时按等待首次运行处理。补丁积压、整机重启和服务重启的持续时间使用三态观测：明确存在才累计，明确不存在才清除；命令失败、输出截断或解析不完整属于未知，本轮不计算陈旧告警，也不会丢失之前的 `first_seen`。

可随时用 `security-update-notify doctor` 查看七项检测、当前待装数量和 SUN 版本结果；每项会明确显示 `OK`、`SKIP` 或 `UNKNOWN`，未知结果以非零状态退出，配置明确禁用的跳过项不会单独导致失败。诊断不会写入时长或版本缓存状态。`security-update-notify test` 的模拟模式和 `security-update-notify run --dry-run` 不写这些状态，也不会发起周期版本请求。

## 安装后写入的内容

```text
/usr/local/sbin/security-update-notify
/etc/security-update-notify/telegram.env
/etc/systemd/system/security-update-notify.service
/etc/systemd/system/security-update-notify.service.d/credentials.conf  # 使用加密飞书凭据时
/etc/systemd/system/security-update-notify.timer
/etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred # 新 systemd
/etc/security-update-notify/credentials/feishu-app-secret              # 旧 systemd 回退
/etc/logrotate.d/security-update-notify
/var/lib/security-update-notify/
/var/backups/security-update-notify/
/var/log/security-update-notify.log
```

根据后端，安装器还会管理 apt 的 `/etc/apt/apt.conf.d/20auto-upgrades`、`/etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify` 和 `/etc/needrestart/conf.d/99-security-update-notify-report-only.conf`，或 DNF 的 `/etc/dnf/automatic.conf`。对应原始基线、缺失标记、proof 和时间戳备份与受管配置位于同一配置目录；下文的后端说明给出具体恢复规则。

通知选项、Telegram Bot Token、飞书 App ID 和接收人 `open_id` 保存在：

```text
/etc/security-update-notify/telegram.env
```

安装器会将该文件设置为 root-only（`0600`）。飞书 App Secret 不写入其中：支持 `systemd-creds` 时使用加密 credential，否则回退到独立的 root-only `0600` 文件；普通升级备份不会复制 App Secret。

## 安装事务与中断恢复

安装器在停止现有 unit 或改写任一受管路径前，会先把事务日志持久化到当前 `/var/backups/security-update-notify/<timestamp>/transaction.json`。已有飞书 App Secret 不进入该备份目录或日志；需要回滚时，安装器只在原凭据旁创建固定名称、root-only 的私密恢复副本。正常错误、取消以及第一次 `SIGHUP`、`SIGINT` 或 `SIGTERM` 会等待事务回滚完成后再退出。若进程遭 `SIGKILL`、内核崩溃或主机掉电，下一次安装会在解析新请求前、持有安装锁后扫描全部合法备份目录；它会先完整校验日志状态、路径白名单、全部快照和私密恢复材料，再执行第一条 `systemctl` 或文件恢复操作。

包管理器调用是单独的失败关闭边界。调用前日志会先持久标记为“不适合自动恢复”；只有依赖产生的配置基线和相关 automatic unit 状态都已可信捕获并再次落盘后，事务才恢复为可自动回滚。若在此期间中断或无法完成可信捕获，安装器不会用 `dpkg --audit`、`apt-get check`、`rpm --verifydb` 等事后探测猜测可恢复性，也不会自动改回部分主机状态；事务日志和私密恢复材料会原样保留。此时后续安装与卸载都会在运行 systemd 命令或删除文件前拒绝继续，管理员必须先检查并修复包管理器现场，再根据日志完成受信的人工恢复；不要先删除这些定位与恢复材料。

## 后端说明

### Debian / Ubuntu (`apt`)

SUN 会配置或使用：

- `unattended-upgrades`
- `needrestart`
- `apt-listchanges`
- apt periodic timers

安装器会启用 unattended-upgrades 的安全更新周期任务。每次覆盖 `/etc/apt/apt.conf.d/20auto-upgrades` 前都会保存一份带时间戳的 SUN 专用备份；如果安装前已有该文件，首次安装还会固定保存原始基线；如果原本不存在，则在包管理器写入前记录一个受校验、可回滚的“原始缺失”标记。如果 SUN 本次安装的 `unattended-upgrades` 依赖包创建了发行版默认文件，SUN 会用内容绑定的 SHA-256 proof 确认来源，再把该文件提升为固定基线并移除缺失标记；因此 purge 保留依赖包和发行版 timer 时，也会恢复一份可用的 vendor 配置。部分依赖事务只在 proof 精确匹配当前文件时允许重试或 purge 保留它；proof 缺失、损坏或不匹配时会失败关闭并保留现场。若依赖包没有创建文件，原始缺失标记仍然有效，purge 会恢复为不存在。APT 目录内的标记、proof 和时间戳备份都以 `.bak` 结尾，避免 apt 对非配置文件输出扩展名提示；升级会迁移旧命名。`--purge-config` 最后会删除 SUN 的基线、标记、proof 及时间戳备份。

检测方式：

- `/var/run/reboot-required`
- `/var/run/reboot-required.pkgs`
- `needrestart -b`

### RHEL 兼容发行版 / Fedora (`dnf`)

`BACKEND` 对 DNF4 和 DNF5 都保持为稳定值 `dnf`，SUN 在内部识别实际代际。

DNF4（RHEL-compatible 8–10；生命周期在 Rocky/AlmaLinux 实测，以及尽力支持的 EL 衍生版）会配置或使用：

- `dnf-automatic`
- `yum-utils`（Amazon Linux 2023 使用实际包名 `dnf-utils`）
- `ca-certificates`
- EL10 极简系统还会显式安装 `dnf`，因为初始镜像可能只有 `microdnf`

DNF4 检测方式：

- `needs-restarting -r`（判断是否需要整机重启）
- `needs-restarting -s`（列出需要重启的 systemd 服务；不再用裸 `needs-restarting` 的整表进程，避免误报）
- `dnf -q updateinfo list security`

DNF5（Fedora 43/44）会使用 `dnf5-plugin-automatic`、`dnf5-plugins` 和 `ca-certificates`，并启用原生 `dnf5-automatic.timer`。该软件包还会安装独立的兼容名称 `dnf-automatic.timer`；若其原本已启用，SUN 会将它禁用，避免同一任务重复执行，安装失败则精确恢复原状态。运行时健康检查仍兼容两种 unit 名。DNF5 检测使用：

- `dnf -q advisory list --security --updates --json`
- `dnf -q check-upgrade --security`（正确处理有更新时的退出码 `100`）
- `dnf needs-restarting` 和 `dnf needs-restarting -s`

DNF5 的公告 JSON 会与实际可执行事务做交集，避免把仅有公告、但不适用于当前事务的包误报为可安装更新。SUN 另行清除普通 exclude 取得完整公告集合，并用单次查询选项 `--setopt=disable_excludes=*` 计算忽略 versionlock/exclude 的事务候选；两组差集用于发现被锁定、排除或事务约束阻塞的安全包。该查询不会改写 `/etc/dnf/versionlock.toml` 或持久 DNF 配置。

两代 DNF 都使用 `/etc/dnf/automatic.conf`。如果该文件存在，SUN 会在第一次管理时固定保存原始基线，每次覆盖前另存时间戳备份；如果原本缺失，缺失 marker 会明确记录 DNF4 或 DNF5 代际。DNF4 的 `dnf-automatic` 依赖包若在本次安装中创建了发行版默认配置，SUN 会把该依赖安装后的 vendor 文件固化为基线并移除“原始缺失”标记；因此 `--purge-config` 会恢复可用的 vendor 配置，而不会让保留且仍启用的发行版 timer 指向缺失文件。依赖事务若在创建 vendor 配置后失败，SUN 会留下与文件内容绑定的 SHA-256 证明；此时立即 purge 只在证明精确匹配当前文件时保留该配置并清理 SUN 元数据，证明损坏或不匹配则拒绝猜测并保留现场。升级带旧缺失标记的 DNF4 安装时，SUN 可从受校验的最早 SUN 时间戳备份迁移原始 vendor 配置，绝不会把当前受管配置误作基线。直接执行 purge 不会仅凭时间戳历史推断来源：DNF4 marker 与当前文件并存且没有固定基线或匹配当前内容的 proof 时，即使仍有时间戳备份也会失败关闭并保留现场。安装器只有在无法从受校验的最早时间戳或匹配 proof 建立可信基线时才会同样停止。如果 `dnf-automatic` 已显示为安装状态，但配置文件缺失且没有可信历史基线，安装器也会在启用 timer 前停止；需先 purge 本次未完成的 SUN 元数据，再重装该包或恢复可信 vendor 配置。DNF5 的配置路径由软件包声明为可缺失并有内置 vendor fallback；如果该文件原本不存在，SUN 保留受校验的缺失标记，purge 时恢复为不存在。普通卸载和随后重装不会改写固定基线；purge 最后会删除 SUN 的基线、标记及时间戳备份。

DNF4 软件包可能同时 preset `dnf-automatic.timer`、`dnf-automatic-notifyonly.timer`、`dnf-automatic-download.timer` 和 `dnf-automatic-install.timer`。SUN 安装成功后只保留主 `dnf-automatic.timer` 启用，并禁用其余三个互斥变体，避免同一套配置被多组 automatic job 并行执行；安装事务失败时会精确恢复四个 timer 的原状态。成功卸载不会猜测或重建安装前的变体组合，而是维持卸载当时所有发行版 timer 的状态。

```ini
upgrade_type = security
apply_updates = yes
reboot = never
```

## 日常操作

查看 timer：

```bash
systemctl list-timers security-update-notify.timer
```

立即运行一次检查：

```bash
sudo systemctl start security-update-notify.service
```

安装后修改通知语言：

```bash
sudoedit /etc/security-update-notify/telegram.env
# 设置 NOTIFY_LANG=zh（中文）或 NOTIFY_LANG=en（English）
```

切换接收平台、飞书应用或接收人时，请运行 `sudo security-update-notify configure notifications`。Go 安装器会验证 App ID 与应用级 `open_id` 的绑定，并负责创建、迁移或清理 App Secret 凭据；不要只手工修改 `NOTIFY_CHANNELS` 绕过这些步骤。

运行内置诊断：

```bash
security-update-notify --version
security-update-notify check-upgrade
sudo security-update-notify doctor
```

配置文件默认仅 root 可读，因此普通用户执行 `check-upgrade` 时无法自动读取 `NOTIFY_LANG`；如需匹配安装语言，
请显式传入 `--lang zh` 或 `--lang en`。普通用户直接执行 `upgrade` 且未给 `--lang` 时，程序会保留“未指定”状态，
在 sudo 后由 root 子进程重新预读配置；显式语言则会原样传过 sudo。

查看日志：

```bash
sudo tail -n 100 /var/log/security-update-notify.log
```

## 卸载

移除程序与 systemd/logrotate 集成，但保留配置和状态：

```bash
sudo security-update-notify uninstall
```

同时删除配置和状态：

```bash
sudo security-update-notify uninstall --purge-config
```

作为依赖安装的软件包会保留，不会自动卸载。`--purge-config` 会删除 SUN 的配置、Telegram/飞书凭据、状态、升级备份（其中可能含 bot token 副本）以及轮转日志，并在备份存在时恢复 apt/dnf 自动更新配置。卸载器不会改变发行版自身 automatic timer 的当前状态；它不会因为移除监控工具而主动关闭安全更新，也不会覆盖管理员之后对该 timer 的调整。

普通卸载与 `--purge-config` 都会先取得安装锁和运行锁，再扫描安装事务日志及固定的私密恢复路径。只要发现中断事务或私密恢复材料，卸载器就会在任何 `systemctl` 调用、unit 删除或配置清理之前失败关闭。可自动恢复的事务应先重新运行安装器完成回滚；包管理器阶段留下的“不适合自动恢复”事务必须按上文检查和人工修复，不能用卸载绕过。

卸载器会对正常返回的并发变化失败关闭：它使用目录句柄、无覆盖 rename 和内容/元数据复验，并保留 `.security-update-notify-restore.*`、`.security-update-notify-purge.*` 或 `.security-update-notify-conflict.*` 现场，避免覆盖或删除管理员同时创建的文件。但 `--purge-config` 不承诺跨 SIGKILL、内核崩溃或掉电中间点的事务原子性；执行时不要强制终止。若 purge 异常中断，请先检查这些保留文件和当前 apt/dnf 配置，不要在未确认现场前反复重试。

## 相关文档

- [安装与升级](installation.md)
- [安全与信任模型](security.md)
- [3.x Go 架构与恢复不变量](go-port.md)
