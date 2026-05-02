# security-update-notify

> 自动安装安全更新；只有在需要重启服务器或重启服务时，才发送一条清晰的 Telegram 提醒。

**security-update-notify**（简称 **SUN**）是一个轻量 Linux 工具，适合维护服务器、VPS 或小型基础设施的人使用。

它使用发行版原生更新机制，通过 systemd timer 定时运行，只向 Telegram Bot API 发起出站 HTTPS 请求。没有 Web 面板，没有常驻控制端口，也不会接收 Telegram 命令。

**语言 / Languages**：中文 | [English](README.en.md)

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian-12%20%7C%2013-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-E95420?style=flat-square&logo=ubuntu&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-8%20%7C%209-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

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
- **只在需要处理时发送 Telegram 提醒**。
- **检测整机重启与服务/进程重启需求**：基于 `needrestart` 或 `needs-restarting`。
- **Telegram 提醒支持中文或英文**：安装时可选择，默认中文。
- **重复提醒抑制**：支持只提醒一次、每天一次、每 N 天一次。
- **支持交互式与非交互式安装**。
- **使用 systemd timer 定时运行**。
- **不监听任何入站端口**。

Telegram 提醒示例：

```text
⚠️ 安全更新后需要处理

主机：prod-web-01
系统：Debian GNU/Linux 12 (bookworm)
后端：apt
当前内核：6.1.0-43-amd64
时间：2026-05-02 09:08 CST

整机重启：需要
相关包/安全更新：
linux-image-amd64

建议：请在方便的维护窗口 SSH 登录该服务器后手动执行 reboot。
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
只有在需要人工处理时发送 Telegram 消息
```

SUN **不会**：

- 自动重启服务器；
- 暴露 Web 服务；
- 接收 Telegram 命令；
- 使用 Telegram long polling 或 webhook；
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

### 1. 创建 Telegram Bot

1. 在 Telegram 打开 [@BotFather](https://t.me/BotFather)。
2. 创建一个 bot，并复制 Bot Token。
3. 给新 bot 发送 `/start`。
4. 获取要接收提醒的 Chat ID。

如果要发到群组，把 bot 加入群组，并确认它有发消息权限。

### 2. 安装

克隆项目并运行交互式安装器：

```bash
git clone https://github.com/xxvcc/security-update-notify.git
cd security-update-notify
sudo ./install.sh
```

安装器会询问：

- Telegram Bot Token；
- Telegram Chat ID；
- Telegram 提醒语言，默认中文；
- 每日检查时间，默认 `09:00`；
- 重复提醒策略；
- 安装后是否额外发送一条测试消息。

写入配置前，安装器会先做 Telegram 预检：

- 使用 `getMe` 验证 Bot Token；
- 使用 `sendMessage` 验证 Chat ID 与发消息权限。

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
  --telegram-token '123456:ABC...' \
  --telegram-chat-id 'CHAT_ID' \
  --time '09:00' \
  --notify-lang zh \
  --dedup-mode interval \
  --dedup-interval-days 3 \
  --host-label 'prod-web-01' \
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

常用参数：

```bash
--env-file FILE            # 从 dotenv 风格文件读取安装配置，推荐用于自动化
--telegram-token-file FILE # 从文件读取 Telegram Bot Token
--backend apt              # 强制使用 apt 后端
--backend dnf              # 强制使用 dnf 后端
--notify-lang zh           # Telegram 提醒语言：中文（默认）
--notify-lang en           # Telegram 提醒语言：英文
--allow-best-effort        # 允许尽力支持的发行版
--send-test                # 安装完成后额外发送测试消息
--skip-telegram-test       # 跳过 Telegram 预检
```

## 重复提醒策略

| 模式 | 行为 |
| --- | --- |
| `always` | 同一个告警只发送一次，直到状态变化。 |
| `daily` | 同一个告警每天最多发送一次。 |
| `interval` | 同一个告警每 N 天发送一次，默认 `3` 天。 |

生产环境推荐使用 `interval`：既不会频繁打扰，也能在重启长期未处理时继续提醒。

## 安装后写入的内容

```text
/usr/local/sbin/security-update-notify
/etc/security-update-notify/telegram.env
/etc/systemd/system/security-update-notify.service
/etc/systemd/system/security-update-notify.timer
/etc/logrotate.d/security-update-notify
/var/lib/security-update-notify/
/var/log/security-update-notify.log
```

Telegram 凭据保存在：

```text
/etc/security-update-notify/telegram.env
```

安装器会将该文件设置为 root-only（`0600`）。

## 后端说明

### Debian / Ubuntu (`apt`)

SUN 会配置或使用：

- `unattended-upgrades`
- `needrestart`
- `apt-listchanges`
- apt periodic timers

安装器会启用 unattended-upgrades 的安全更新周期任务，并在首次写入 `/etc/apt/apt.conf.d/20auto-upgrades` 前保存一份 SUN 专用备份；`--purge-config` 会在备份存在时恢复它。

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

- `needs-restarting -r`
- `needs-restarting`
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

安装后切换 Telegram 提醒语言：

```bash
sudoedit /etc/security-update-notify/telegram.env
# 设置 NOTIFY_LANG=zh 或 NOTIFY_LANG=en
```

运行内置诊断：

```bash
security-update-notify --version
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

作为依赖安装的软件包会保留，不会自动卸载。`--purge-config` 会删除 SUN 的配置/状态，并在备份存在时恢复 apt/dnf 自动更新配置。

## 安全说明

SUN 的范围刻意保持很小：

- 只向 Telegram Bot API 发起出站 HTTPS 请求；
- 不接收远程命令；
- 不提供公开 HTTP 入口；
- 不自动重启；
- Telegram 凭据文件仅 root 可读；
- 尽力支持的发行版必须显式开启。

发布包的 `.sha256` 文件可以防止下载损坏或版本不匹配；如果你的威胁模型包含发布源被攻破，请考虑额外的签名校验流程。

## 构建发布包

在源码目录运行：

```bash
bash -n install.sh menu.sh test.sh uninstall.sh package.sh sun.sh files/security-update-notify
./package.sh
cd dist && sha256sum -c security-update-notify-*.tar.gz.sha256
```

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
