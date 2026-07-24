# security-update-notify

<p align="center">
  <a href="https://github.com/xxvcc/security-update-notify/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/xxvcc/security-update-notify?style=flat-square&label=release&color=2EA043"></a>
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian-12%20%7C%2013-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-E95420?style=flat-square&logo=ubuntu&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-8%20%7C%209-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> 自动安装安全更新；只有在需要重启服务器或重启服务时，才通过 Telegram、飞书或两者发送清晰提醒。

**security-update-notify**（简称 **SUN**）是一个轻量 Linux 工具，适合维护服务器、VPS 或小型基础设施的人使用。

它使用发行版原生更新机制，通过 systemd timer 定时运行，只发起出站 HTTPS 请求：提醒按配置发往 Telegram Bot API 和/或飞书开放平台；默认还会向公网 IP 探测服务（api.ipify.org / ifconfig.me）获取出口 IP（可用 `INCLUDE_PUBLIC_IP=0` 关闭或用 `PUBLIC_IP` 手动指定）；自升级时访问 GitHub。没有 Web 面板，没有常驻控制端口，也不接收消息命令。

> 自 **2.0** 起，运行时是一个静态编译的 **Go 二进制**，按架构分发（amd64/arm64/386/ppc64le/s390x）；未构建的架构自动回退到自包含的 Bash 运行时。**Go 二进制运行时**不依赖 `python3` 或 `curl`；而 Bash 回退运行时仍依赖 `python3`（用于通知 API 与版本/日期计算）。安装器 `install.sh` 在通知渠道预检时也使用 `python3`。

**语言 / Languages**：中文 | [English](README.en.md)

## 一键安装

```bash
curl -fsSL https://sun.xxv.cc | sudo bash
```

---

## 为什么需要它？

很多服务器都能自动安装安全更新，但真正容易被忽略的是更新之后：

- 内核已经更新，但服务器仍在运行旧内核；
- 服务还在使用旧版本共享库；
- 系统需要重启，但没人注意到；
- 更新日志太吵，真正重要的提醒反而被忽略。

SUN 负责把“安全更新”这件事自动化，同时只在确实需要人工处理时提醒你。

## 主要特性

- **自动安装安全更新**：使用发行版官方机制。
- **不自动重启服务器**：停机窗口仍由你决定。
- **Telegram / 飞书可单选，也可双发**：旧配置自动保持 Telegram；双发时两个渠道独立去重，一个渠道失败不会让另一个重复提醒。
- **检测整机重启与服务/进程重启需求**：基于 `needrestart` 或 `needs-restarting`。
- **安全更新看门狗**：除内核/服务重启外，再盯三件容易被忽视的事——① 自动更新机制是否异常（定时器被禁用、上次运行失败、长时间没有成功更新、磁盘将满）；② 是否还有待安装的安全更新（dnf 另计高危/重要）；③ 发行版安全支持是否即将或已经终止（EOL）。机制异常与已过 EOL 会触发提醒，待装数量与临近 EOL 仅随提醒一并展示；三项均可在配置中关闭。
- **中英文界面，单语显示**：安装、菜单、诊断在第一步选择语言（中文或英文，默认中文），之后整套终端交互只按所选语言显示，不再中英文混排；该选择同时作为通知语言的默认值，可用 `--notify-lang` 单独覆盖。
- **通知中显示公网 IP**：默认自动获取公网 IP，也可手动指定或关闭显示；自动获取由 Go 运行时用标准库完成，不新增 `curl`/`python3` 依赖。
- **重复提醒抑制**：支持只提醒一次、每天一次、每 N 天一次。
- **支持交互式与非交互式安装/升级**：重新运行安装器会复用已有配置。
- **使用 systemd timer 定时运行**。
- **不监听任何入站端口**。

通知示例（Telegram 与飞书正文一致，`NOTIFY_LANG=zh`）：

```text
⚠️ 安全更新后需要处理

主机：prod-web-01
公网 IP：203.0.113.10
系统：Debian GNU/Linux 12 (bookworm)
后端：apt
当前内核：6.1.0-43-amd64
时间：2026-05-02 09:08 CST

整机重启：需要
相关包/安全更新：
linux-image-amd64

重启检测摘要：
内核：当前 6.1.0-43-amd64，建议 6.1.0-44-amd64
建议评估/重启的服务（2 个）：
• nginx.service
• ssh.service

建议：请在方便的维护窗口 SSH 登录该服务器后手动执行 reboot；如只是服务需要重启，可先评估并重启对应服务。
```

## 工作方式

```text
发行版自动更新机制（apt/dnf timer）
    ↓
安装安全更新
    ↓
SUN 的 systemd timer
    ↓
检查更新后是否需要整机重启或服务重启
    ↓
只有在需要人工处理时才向已配置渠道发送消息
```

SUN **不会**：

- 自动重启服务器；
- 暴露 Web 服务；
- 接收 Telegram 或飞书命令；
- 使用 Telegram long polling、webhook 或飞书事件回调；
- 打开任何入站端口。

## 支持系统

### 正式支持

| 系统家族 | 版本 | 后端 |
| --- | --- | --- |
| Debian | 12, 13 | `apt` |
| Ubuntu | 22.04, 24.04 | `apt` |
| RHEL / Rocky / AlmaLinux | 8, 9 | `dnf` |
| Fedora | 当前版本 | `dnf` |

### 尽力支持

以下系统需要显式加 `--allow-best-effort`：

- Debian 11
- Ubuntu 20.04
- CentOS Stream 8 / 9
- Amazon Linux 2023

### 暂不支持

- Alpine
- Arch Linux
- SUSE / openSUSE
- 没有完整 systemd 的容器或极简系统
- 已停止安全更新的 EOL 系统

## 快速开始

### 1. 准备通知渠道

Telegram：

1. 在 Telegram 打开 [@BotFather](https://t.me/BotFather)。
2. 创建一个 bot，并复制 Bot Token。
3. 给新 bot 发送 `/start`。
4. 获取要接收提醒的 Chat ID。

如果要发到群组，把 bot 加入群组，并确认它有发消息权限。

飞书：

1. 在飞书开放平台创建企业自建应用并启用机器人。
2. 开通 `directory:employee:list`、`directory:employee.base.name.name:read`、`directory:employee.base.mobile:read` 和 `im:message:send_as_bot`。
3. 发布应用，并把目标用户纳入应用可用范围和通讯录数据范围；记录 App ID 和 App Secret。

交互安装时，SUN 会在输入 App ID 和隐藏输入 App Secret 后，通过 Directory v1 分页扫描应用可见的在职员工，并按“中文姓名 + 手机号尾号 + `open_id`”显示编号列表。你选择序号后，安装器只保存对应的 `open_id`；姓名和手机号尾号只用于人工核验。运行时仍固定使用 `open_id` 单发普通文本，不会每次通知都查询通讯录。不同飞书应用的 `open_id` 可能不同，不能跨应用复用；升级时如果更换 App ID，安装器会清除旧接收人并要求重新选择或显式提供 `open_id`。

### 2. 安装

推荐使用网站引导安装器。它会下载最新 GitHub Release、校验 `.sha256` 与 GPG 签名（默认必须通过），然后启动交互式菜单：

```bash
curl -fsSL https://sun.xxv.cc | sudo bash
```

如果你更想从源码运行，也可以：

```bash
git clone https://github.com/xxvcc/security-update-notify.git
cd security-update-notify
sudo ./install.sh
```

安装器会先让你选择界面语言（中文或英文，默认中文），然后选择 Telegram、飞书或双发。随后按所选渠道询问：

- Telegram Bot Token / Chat ID；和/或
- 飞书 App ID / 隐藏输入的 App Secret，然后从自动扫描结果中选择接收人；
- 每日检查时间，默认 `09:00`；
- 重复提醒策略；
- 安装后是否额外发送一条测试消息。

如果想跳过交互式语言选择，可在命令行加 `--lang zh` 或 `--lang en`。

写入配置前，安装器会先做渠道预检：

- Telegram：使用 `getMe` 验证 Bot Token，并用 `sendMessage` 验证 Chat ID 与权限；
- 飞书：获取 `tenant_access_token` 后扫描应用通讯录范围内的在职员工；如已显式提供 `open_id`，则只验证应用凭据。安装预检不会发送消息。

扫描结果受飞书应用“通讯录数据范围”限制。扫描失败或没有可见员工时，交互安装器允许重试、手动输入当前应用下的 `open_id`，或中止安装；非交互模式必须显式提供 `--feishu-receive-id`。

只有显式使用 `--send-test` 或 `test.sh --send-test` 才会向飞书 `open_id` 发送测试消息。请先确认该 `open_id` 就是预期接收人。

### 3. 验证

```bash
sudo ./test.sh
sudo ./test.sh --send-test --no-dedupe
sudo ./test.sh --simulate-reboot --no-dedupe
```

模拟重启测试只会发送测试提醒，**不会真的重启服务器**。

## 非交互式安装

适合放进初始化脚本、云服务器模板或批量部署流程：

```bash
sudo ./install.sh \
  --notify-channels telegram \
  --telegram-token '123456:ABC...' \
  --telegram-chat-id 'CHAT_ID' \
  --time '09:00' \
  --notify-lang zh \
  --dedup-mode interval \
  --dedup-interval-days 3 \
  --host-label 'prod-web-01' \
  --public-ip '203.0.113.10' \
  --non-interactive \
  -y
```

更安全的自动化方式是使用本地 `.env` 文件，避免 token 出现在 shell history 或进程列表：

```bash
cp .env.example .env
chmod 600 .env
sudoedit .env

sudo ./install.sh --env-file .env --non-interactive -y
```

也可以只把 token 单独放进 root-only 文件：

```bash
sudo install -m 600 /dev/null /root/.security-update-notify-token
sudoedit /root/.security-update-notify-token

sudo ./install.sh \
  --telegram-token-file /root/.security-update-notify-token \
  --telegram-chat-id 'CHAT_ID' \
  --non-interactive \
  -y
```

飞书非交互式安装使用独立的 App Secret 源文件，不能把 Secret 直接写进 `.env` 或命令行：

```bash
sudo install -m 600 /dev/null /root/.security-update-notify-feishu-secret
sudoedit /root/.security-update-notify-feishu-secret

sudo ./install.sh \
  --notify-channels feishu \
  --feishu-app-id 'cli_xxx' \
  --feishu-receive-id 'ou_xxx' \
  --feishu-app-secret-file /root/.security-update-notify-feishu-secret \
  --non-interactive \
  -y
```

App Secret 源文件必须是 root 所有的普通文件，不能是符号链接，也不能允许组用户或其他用户访问（建议 `0600`）。安装器会在读取前校验这些条件，并在路径检查期间检测文件替换。

安装器会优先把 App Secret 转存为加密的 systemd credential；旧 systemd 才回退到独立的 root-only `0600` 文件。两者都不进入普通配置或升级备份。

安装成功并确认凭据可用后，如果该源文件不是外部 Secret 管理器维护的固定入口，应删除它，避免额外保留一份 App Secret 明文。

常用参数：

```bash
--env-file FILE            # 从 dotenv 风格文件读取安装配置，推荐用于自动化
--notify-channels LIST      # telegram | feishu | telegram,feishu
--telegram-token-file FILE # 从文件读取 Telegram Bot Token
--feishu-app-id APP_ID      # 飞书应用 App ID
--feishu-receive-id OPEN_ID # 显式覆盖接收人；非交互安装必需
--feishu-app-secret-file F  # 从独立文件读取 App Secret
--backend apt              # 强制使用 apt 后端
--backend dnf              # 强制使用 dnf 后端
--notify-lang zh           # 通知语言：中文（默认）
--notify-lang en           # 通知语言：English
--lang en                  # 终端交互显示语言：English（默认 zh）
--public-ip IP             # 手动指定通知中的公网 IP；不填则运行时自动获取
--include-public-ip 0      # 关闭通知中的公网 IP 显示；默认 1
--notify-ok 1             # 无需处理时也发送 OK 通知；默认 0
--notify-upgrade 1        # 升级成功后向已配置渠道发送通知；默认 0
--skip-post-install-check # 跳过安装/升级后自检
--allow-best-effort        # 允许尽力支持的发行版
--send-test                # 安装完成后额外发送测试消息
--skip-telegram-test       # 跳过 Telegram 预检
--skip-feishu-test         # 跳过独立凭据预检；未指定接收人时仍需扫描选人
--skip-notify-test         # 跳过所有渠道预检
```


### 升级

重新运行一键安装器即可升级到最新 release：

```bash
curl -fsSL https://sun.xxv.cc | sudo bash -s -- upgrade --non-interactive -y
```

已安装 SUN 后，也可以直接运行 `sudo security-update-notify --upgrade`：它会下载最新 GitHub 发布包，校验 `.sha256`，并用内置 pin 的指纹强制校验 GPG 签名（默认 fail-closed，缺签名即拒绝）后才升级。

如果已安装过 SUN，安装器会自动读取 `/etc/security-update-notify/telegram.env` 和现有 timer 时间；旧配置没有 `NOTIFY_CHANNELS` 时自动按 `telegram` 处理，未显式覆盖的选项继续沿用。升级前会备份关键文件到 `/var/backups/security-update-notify/<timestamp>`，但飞书 App Secret 不进入该备份；升级失败会尝试自动回滚。升级后默认运行自检；可用 `--notify-upgrade 1` 向已配置渠道发送升级通知。升级通知采用 best-effort 语义，不会因通知失败回滚已经完成的升级，也不会整体重试双发而重复已成功渠道。

## 重复提醒策略

| 模式 | 行为 |
| --- | --- |
| `once` | 同一个告警只发送一次，直到状态变化（旧名 `always`，仍兼容接受）。 |
| `daily` | 同一个告警每天最多发送一次（**默认 / 推荐**）。 |
| `interval` | 同一个告警每 N 天发送一次，默认 `3` 天。 |

默认 `daily`：每天最多提醒一次，既能在重启长期未处理时持续提醒，又不会频繁打扰。若想更安静可用 `once`（只提醒一次）或 `interval`（每 N 天一次）。

双发时每个渠道有独立状态：Telegram 成功而飞书失败时，下一次只重试飞书，不会重复发送 Telegram。

## 安全更新看门狗

除了内核与服务重启检测，SUN 默认还会做三项检查（均可在 `/etc/security-update-notify/telegram.env` 中关闭）：

| 配置项 | 默认 | 说明 |
| --- | --- | --- |
| `CHECK_UPDATE_HEALTH` | `1` | 检测自动更新机制是否健康：定时器（`apt-daily-upgrade` / `dnf-automatic`）被禁用、上次运行失败、超过 `STALE_UPDATE_DAYS` 天没有成功更新、`/` 或 `/boot` 剩余空间不足 200MB。任一命中即触发提醒。 |
| `STALE_UPDATE_DAYS` | `7` | 多少天没有成功的自动安全更新即视为异常；设为 `0` 关闭该子项。 |
| `CHECK_EOL` | `1` | 发行版安全支持终止（EOL）提醒：已过 EOL 触发提醒，临近（90 天内）仅作信息展示。若已购买 Ubuntu ESM 等延长支持，可设 `0` 关闭。 |

待安装的安全更新数量为信息项，会随提醒或在 `--doctor` 自检中一并展示，本身不单独触发提醒。可随时用 `security-update-notify --doctor` 查看这三项的当前状态。

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
/var/log/security-update-notify.log
```

通知选项、Telegram Bot Token、飞书 App ID 和接收人 `open_id` 保存在：

```text
/etc/security-update-notify/telegram.env
```

安装器会将该文件设置为 root-only（`0600`）。飞书 App Secret 不写入其中：支持 `systemd-creds` 时使用加密 credential，否则回退到独立的 root-only `0600` 文件；普通升级备份不会复制 App Secret。

## 后端说明

### Debian / Ubuntu (`apt`)

SUN 会配置或使用：

- `unattended-upgrades`
- `needrestart`
- `apt-listchanges`
- apt periodic timers

安装器会启用 unattended-upgrades 的安全更新周期任务。每次覆盖 `/etc/apt/apt.conf.d/20auto-upgrades` 前都会保存一份带时间戳的 SUN 专用备份；首次安装时还会保留一份固定名称备份，`--purge-config` 会在该备份存在时恢复它。

检测方式：

- `/var/run/reboot-required`
- `/var/run/reboot-required.pkgs`
- `needrestart -b`

### RHEL 兼容发行版 / Fedora (`dnf`)

SUN 会配置或使用：

- `dnf-automatic`
- `yum-utils` 或 `dnf-utils`
- `python3`、`ca-certificates`

检测方式：

- `needs-restarting -r`（判断是否需要整机重启）
- `needs-restarting -s`（列出需要重启的 systemd 服务；不再用裸 `needs-restarting` 的整表进程，避免误报）
- `dnf updateinfo list security updates`

如果 `/etc/dnf/automatic.conf` 存在，SUN 会先保存一份带时间戳的备份，再将其配置为只安装安全更新；`--purge-config` 会尝试恢复最新一份 SUN 创建的备份。

```ini
upgrade_type = security
apply_updates = yes
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

切换通知渠道、飞书应用或接收人时，请重新运行安装器。安装器会验证 App ID 与应用级 `open_id` 的绑定，并负责创建、迁移或清理 App Secret 凭据；不要只手工修改 `NOTIFY_CHANNELS` 绕过这些步骤。

运行内置诊断：

```bash
security-update-notify --version
security-update-notify --check-upgrade
sudo security-update-notify --doctor
```

查看日志：

```bash
sudo tail -n 100 /var/log/security-update-notify.log
```

## 卸载

移除程序与 systemd/logrotate 集成，但保留配置和状态：

```bash
sudo ./uninstall.sh
```

同时删除配置和状态：

```bash
sudo ./uninstall.sh --purge-config
```

作为依赖安装的软件包会保留，不会自动卸载。`--purge-config` 会删除 SUN 的配置、Telegram/飞书凭据、状态、升级备份（其中可能含 bot token 副本）以及轮转日志，并在备份存在时恢复 apt/dnf 自动更新配置。

## Release 签名

发布包始终包含 `.sha256` 校验文件。`package.sh` 支持在存在 GPG 私钥时自动生成 `.tar.gz.asc` detached signature；`sun.sh` 默认以 `required` 模式校验签名，`auto` 仅作为兼容别名保留，也会要求 gpg 与 `.asc` 签名同时存在；只有显式传入 `--verify-signature off` 才会跳过签名校验。

正式发布（存在对应 `vX.Y.Z` tag，或显式设置 `RELEASE=1` 的构建）**强制签名**：`package.sh` 会要求 GPG 签名，没有私钥则构建失败；release 发布后 CI 会用仓库内公钥校验产物的签名与指纹，缺签名/不匹配即让该 release 的检查失败。私钥不进入 CI，仍由维护者离线持有。此外，`security-update-notify --upgrade` 默认 **fail-closed**：直接下载 GitHub 发布包，校验 sha256，并在解包前用内置公钥与 pin 指纹强制校验 GPG 签名后才升级（应急可设 `SECURITY_UPDATE_NOTIFY_UPGRADE_ALLOW_UNSIGNED=1` 仅按 sha256 升级）。

## 安全说明

SUN 的范围刻意保持很小：

- 出站仅 HTTPS：提醒按配置发往 Telegram Bot API 和/或 `open.feishu.cn`；默认另向公网 IP 探测服务（api.ipify.org / ifconfig.me）获取出口 IP（`INCLUDE_PUBLIC_IP=0` 可关闭）；自升级时访问 GitHub。若要用出口防火墙收紧，请把这些目的地一并放行或关闭对应功能；
- 不接收远程命令；
- 不提供公开 HTTP 入口；
- 不自动重启；
- 普通通知配置仅 root 可读；飞书 App Secret 使用独立 systemd/root 凭据，不进入普通配置、命令行、日志或升级备份；
- 尽力支持的发行版必须显式开启。

发布包的 `.sha256` 文件可以防止下载损坏或版本不匹配；如果你的威胁模型包含发布源被攻破，请保持默认签名校验开启，不要使用 `--verify-signature off` 或无签名升级逃生选项。

## 构建发布包

在源码目录运行：

```bash
bash -n install.sh menu.sh test.sh uninstall.sh package.sh sun.sh files/security-update-notify \
  build/compat-test.sh build/rollback-test.sh build/bash-feishu-test.sh \
  build/install-feishu-onboarding-test.sh
go vet ./...
go test -race -cover ./...
build/bash-feishu-test.sh
build/install-feishu-onboarding-test.sh
build/compat-test.sh
build/rollback-test.sh
./package.sh
cd dist && sha256sum -c security-update-notify-*.tar.gz.sha256
```

`build/compat-test.sh` 和 `build/rollback-test.sh` 使用 Docker；其余命令使用项目声明的 Go 工具链和本机 shell 工具。

生成文件：

```text
dist/security-update-notify-VERSION.tar.gz
dist/security-update-notify-VERSION.tar.gz.sha256
```

发布压缩包只包含面向用户的安装、诊断和文档文件。`sun.sh` 是用于网站托管的一键引导脚本，不放入发布压缩包；如需使用，请从源码仓库单独发布到你的稳定 URL。

发布包内容：

```text
.env.example
CHANGELOG.md
LICENSE
README.md
README.en.md
install.sh
menu.sh
test.sh
uninstall.sh
files/
```

## 许可证

MIT。详见 [LICENSE](LICENSE)。
