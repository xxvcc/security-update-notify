# security-update-notify

<p align="center">
  <a href="https://github.com/xxvcc/security-update-notify/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/xxvcc/security-update-notify?style=flat-square&label=release&color=2EA043"></a>
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian-12%20%7C%2013-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04%20%7C%2026.04-E95420?style=flat-square&logo=ubuntu&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-8%20%7C%209%20%7C%2010-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> 自动安装安全更新；在需要重启服务器、重启服务、处理补丁维护异常或发现 SUN 新版本时，通过 Telegram、飞书或两者发送提醒。

**security-update-notify**（简称 **SUN**）适合维护服务器、VPS 和小型基础设施。它使用发行版原生 apt/dnf 自动更新机制，通过 systemd timer 定时检查，不自动重启，不监听入站端口，也不接收消息命令。

自 3.0 起，安装、运行、诊断、卸载和自升级均由 Go 实现；唯一维护的 Shell 产品入口是首次安装引导器 `sun.sh`。正式包固定提供 linux/amd64、arm64、386、ppc64le 和 s390x。实现与迁移细节见 [3.x Go 架构](docs/go-port.md)。

**语言 / Languages**：中文 | [English](README.en.md)

## 快速安装

便捷交互安装：

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p
```

这条兼容入口首先信任 HTTPS 下载到的引导脚本；脚本随后仍会强制校验 Release 的 checksum 和 GPG 签名。生产环境或下载源属于威胁模型时，请使用[固定版本、固定指纹且执行前验签的高保障流程](docs/installation.md#高保障首次安装生产环境推荐)。

安装后验证：

```bash
security-update-notify --version
sudo security-update-notify doctor
systemctl list-timers security-update-notify.timer
```

完整通知准备、源码安装、非交互部署和升级参数见[安装与升级](docs/installation.md)。

## 它解决什么问题

发行版通常能够自动安装安全补丁，但更新后仍可能需要人工处理：

- 新内核已安装，服务器仍运行旧内核；
- 服务继续使用旧版本共享库；
- 自动更新 timer 被禁用或未激活，软件源或包管理器状态异常；
- 安全更新被 hold、versionlock 或 exclude 阻塞；
- 重启或补丁滞留长期没有处理。

SUN 自动完成安全更新，并把真正需要管理员介入的状态整理成低噪声通知。

## 主要特性

- 使用发行版官方机制自动安装安全更新，但从不自动重启。
- Telegram、飞书可单选或双发，两个渠道独立去重和重试。
- 检测整机重启、服务重启、补丁滞留和发行版 EOL。
- 检查自动更新策略、timer 激活状态、软件源元数据和包管理器一致性。
- 支持中文或英文界面与通知，不在同一界面混排。
- 支持交互式安装、配置复用、非交互部署和签名自升级。
- 默认每天最多重复提醒一次，也支持只提醒一次或每 N 天提醒。
- 仅发起必要的出站 HTTPS 请求，没有 Web 面板或远程命令入口。

## 工作方式

```text
发行版 apt/dnf 自动更新 timer
    -> 安装安全更新
    -> SUN systemd timer 检查维护状态
    -> 仅在需要人工处理时发送通知
```

SUN 不会自动执行 `reboot`，也不会自动重启服务。维护窗口和最终操作始终由管理员决定。

## 支持系统

### 正式支持

| 系统家族 | 版本 | 后端 |
| --- | --- | --- |
| Debian | 12, 13 | `apt` |
| Ubuntu | 22.04, 24.04, 26.04 | `apt` |
| RHEL-compatible（Rocky / AlmaLinux 实测） | 8, 9, 10 | `dnf`（DNF4） |
| Fedora | 43, 44 | `dnf`（DNF5） |

正式包支持 amd64、arm64、386、ppc64le 和 s390x；未列架构不会回退到旧 Shell 运行时。

### 尽力支持

以下系统必须显式传入 `--allow-best-effort`：

- Debian 11
- Ubuntu 20.04（需要有效 Ubuntu Pro/ESM 安全源）
- CentOS Stream 9 / 10
- Oracle Linux 8 / 9 / 10
- CloudLinux 8 / 9 / 10
- Amazon Linux 2023

尽力支持只表示 SUN 的代码路径兼容，管理员仍须确认订阅和安全源有效。Ubuntu 20.04 会自动核对本机 `esm-infra`；Amazon Linux 2023 仍需管理员跟踪并前移发行快照。部分 Oracle Linux 8 厂商镜像将 `/etc/dnf` 设为 `root:root 0775`；除固定共享日志父目录 `/var/log` 外，SUN 仍会拒绝组可写的 `/etc/dnf` 等特权配置目录，管理员须先确认它由 root 所有且不是符号链接，再执行 `sudo chmod 0755 /etc/dnf`。未列出的 `ID_LIKE` 衍生版不会自动升级为正式支持，详细探测和回滚规则见[运维文档](docs/operations.md)。

### 暂不支持

- Alpine、Arch Linux、SUSE / openSUSE
- 没有完整 systemd 的容器或极简系统
- 已 EOL 且没有有效厂商或延长安全源的系统

## 准备通知平台

Telegram：

1. 在 Telegram 打开 [@BotFather](https://t.me/BotFather) 并创建 bot。
2. 给 bot 发送 `/start`，准备 Bot Token 和目标 Chat ID。
3. 群组通知需把 bot 加入群组并允许发消息。

飞书：

1. 创建企业自建应用并启用机器人。
2. 开通 `directory:employee:list`、`directory:employee.base.name.name:read`、`directory:employee.base.mobile:read` 和 `im:message:send_as_bot`。
3. 发布应用，把目标用户加入应用可用范围和通讯录数据范围，并准备 App ID 与 App Secret。

交互安装器会扫描应用可见员工供你选择，只保存应用级 `open_id`；App Secret 使用独立的 systemd/root 凭据，不写入普通配置。详细预检、强验证和自动化凭据文件要求见[安装与升级](docs/installation.md)。

## 常用操作

立即诊断：

```bash
sudo security-update-notify doctor
```

发送测试通知：

```bash
sudo security-update-notify test --send-test --no-dedupe
```

检查和安装 SUN 新版本：

```bash
security-update-notify check-upgrade
sudo security-update-notify upgrade
```

配置文件默认仅 root 可读。普通用户运行 `check-upgrade` 时，如需终端语言与已安装配置一致，请显式加
`--lang zh` 或 `--lang en`；普通用户直接运行 `upgrade` 时，未显式指定的语言会在 sudo 后由 root 进程重新读取。

修改通知平台、应用或接收人：

```bash
sudo security-update-notify configure notifications
```

查看日志：

```bash
sudo tail -n 100 /var/log/security-update-notify.log
```

卸载程序但保留配置：

```bash
sudo security-update-notify uninstall
```

同时清理配置和状态：

```bash
sudo security-update-notify uninstall --purge-config
```

`--purge-config` 会恢复受管 apt/dnf 配置并删除凭据、状态和升级备份；异常中断或并发文件变化时应先阅读[恢复语义](docs/operations.md#卸载)，不要盲目重复执行。

## 常用配置

完整示例和默认值见 [.env.example](.env.example)。常用设置包括：

| 配置项 | 默认 | 作用 |
| --- | --- | --- |
| `NOTIFY_CHANNELS` | `telegram` | `telegram`、`feishu` 或两者 |
| `NOTIFY_LANG` | `zh` | 通知语言 |
| `INCLUDE_PUBLIC_IP` | `1` | 是否在通知中显示出口 IP |
| `DEDUP_MODE` | `daily` | `once`、`daily` 或 `interval` |
| `PENDING_ALERT_DAYS` | `3` | 补丁持续滞留多久后告警 |
| `RESTART_ALERT_DAYS` | `7` | 重启需求持续多久后升级告警 |
| `CHECK_UPDATE_HEALTH` | `1` | 检查策略、包状态和软件源健康 |
| `CHECK_EOL` | `1` | 检查发行版安全支持状态 |
| `CHECK_SELF_UPDATE` | `1` | 周期提示 SUN 新版本，不自动升级 |

安装器会把普通配置设为 root-only。请优先使用 `configure notifications` 或重新运行安装器，不要绕过凭据验证直接拼接配置。

## 安全边界

- 通知只向 Telegram Bot API 和/或 `open.feishu.cn` 发起出站 HTTPS。
- 默认使用公网 IP 探测服务，可通过 `INCLUDE_PUBLIC_IP=0` 关闭。
- 安装和自升级优先访问 `dl.ll.cd`，传输失败时回退 GitHub。
- Release 默认必须通过 SHA-256、GPG 签名和固定指纹验证。
- 飞书 App Secret 不进入普通配置、命令行、日志或升级备份。
- SUN 不开放 HTTP 入口，不接收远程命令，不自动重启。

签名验证、首次执行信任边界、凭据和网络威胁模型见[安全与信任模型](docs/security.md)。

## 文档

### 用户与管理员

- [安装与升级](docs/installation.md)：高保障安装、非交互部署、通知预检和升级。
- [日常运维与恢复](docs/operations.md)：watchdog、受管文件、APT/DNF、卸载和恢复。
- [安全与信任模型](docs/security.md)：签名、网络、凭据和首次安装信任边界。

### 贡献者与维护者

- [开发与本地验证](docs/development.md)：构建、测试和容器门禁。
- [发布维护流程](docs/releasing.md)：离线签名、不可变 Release、镜像和 canary。
- [3.x Go 架构](docs/go-port.md)：模块边界、兼容和发布不变量。
- [变更记录](CHANGELOG.md)

## 许可证

MIT。详见 [LICENSE](LICENSE)。
