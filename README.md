# security-update-notify

`security-update-notify`（简称 SUN）是一个基于 systemd 的轻量 Linux 工具：它会使用发行版官方机制自动安装**安全更新**，检查更新后是否需要整机重启或服务/进程重启，并且只在需要人工关注时发送 Telegram 通知。

它适合管理多台服务器的人：既能尽快应用安全更新，又不暴露任何远程控制入口。

## 主要特性

- 通过发行版官方机制自动安装安全更新
- 不自动重启服务器
- 检测整机重启需求与服务/进程重启需求
- 只通过出站 HTTPS 调用 Telegram Bot API
- 支持重复提醒抑制：`always`、`daily`、`interval`
- 支持交互式菜单和非交互式安装
- 支持 `apt` 与 `dnf` 后端
- 使用 systemd timer 定时运行
- 支持生成发布压缩包与 sha256 校验文件

## 安全设计

SUN 是一个“只通知、不控制”的工具：

- 不会自动重启服务器。
- 不监听任何网络端口。
- 不使用 Telegram long polling 或 webhook。
- 只向 Telegram Bot API 发起出站 HTTPS 请求。
- Telegram 凭据保存在 `/etc/security-update-notify/telegram.env`，权限为 root-only（`0600`）。
- 运行状态保存在 `/var/lib/security-update-notify`。
- 日志写入 `/var/log/security-update-notify.log`；如果系统有 logrotate，会自动配置日志轮转。
- best-effort 发行版必须显式加 `--allow-best-effort` 才允许安装。

`.sha256` 文件用于防止下载损坏或版本不匹配。它不能防止发布源被攻破；更强的产物签名以后可以再加。

## 支持系统

安装器会严格检查发行版；不支持的系统会直接停止，避免错误配置更新机制。

### 正式支持

- Debian 12 / 13（`apt` 后端）
- Ubuntu 22.04 / 24.04（`apt` 后端）
- RHEL / Rocky Linux / AlmaLinux 8 / 9（`dnf` 后端）
- Fedora 当前版本（`dnf` 后端）

### 尽力支持（需要 `--allow-best-effort`）

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

## 后端说明

### `apt` 后端

安装/配置：

- `unattended-upgrades`
- `needrestart`
- `apt-listchanges`
- apt periodic timers

检测方式：

- `/var/run/reboot-required`
- `/var/run/reboot-required.pkgs`
- `needrestart -b`

### `dnf` 后端

安装/配置：

- `dnf-automatic`
- `yum-utils` 或 `dnf-utils`
- `curl`、`python3`、`ca-certificates`

检测方式：

- `needs-restarting -r`
- `needs-restarting`
- `dnf updateinfo list security updates`

如果 `/etc/dnf/automatic.conf` 存在，安装器会把 `dnf-automatic` 配置为只安装安全更新并自动应用：

```ini
upgrade_type = security
apply_updates = yes
```

## 安装

### 交互式菜单

```bash
sudo ./menu.sh
```

菜单内容：

```text
1) Install / upgrade
2) Uninstall
3) Check / diagnose
0) Exit
```

### 直接交互式安装

```bash
sudo ./install.sh
```

安装过程会询问：

- Telegram Bot Token（隐藏输入，输入后按 Enter）
- Telegram Chat ID
- 每日检查时间，默认 `09:00`
- 相同告警的重复提醒模式：
  - `always`：同一个告警只提醒一次，直到状态变化
  - `daily`：同一个告警每天最多提醒一次
  - `interval`：同一个告警每 N 天提醒一次，默认/推荐 `3`
- 安装后是否额外发送一条测试消息

默认会在输入 token 和 chat ID 后做 Telegram 预检：

- `getMe` 验证 bot token
- `sendMessage` 验证 chat ID 与 bot 发消息权限
- 只有在明确知道自己要跳过预检时，才使用 `--skip-telegram-test`

### 非交互式安装

```bash
sudo ./install.sh \
  --telegram-token '123456:ABC...' \
  --telegram-chat-id 'CHAT_ID' \
  --time '09:00' \
  --dedup-mode interval \
  --dedup-interval-days 3 \
  --non-interactive \
  -y
```

常用可选参数：

```bash
sudo ./install.sh --backend apt ...
sudo ./install.sh --backend dnf ...
sudo ./install.sh --allow-best-effort ...
sudo ./install.sh --host-label 'prod-web-01' ...
sudo ./install.sh --skip-telegram-test ...
```

## 一键引导安装器

`sun.sh` 是源码仓库中的网站引导安装器。它不会放进发布压缩包；如需使用，请单独发布到稳定 URL，例如：

```text
https://example.com/install/sun.sh
```

发布前请修改它的默认 `REPO`，也可以运行时传入：

```bash
curl -fsSL https://example.com/install/sun.sh | sudo SECURITY_UPDATE_NOTIFY_REPO='OWNER/security-update-notify' bash
```

交互式菜单：

```bash
curl -fsSL https://example.com/install/sun.sh | sudo bash
```

非交互式安装：

```bash
curl -fsSL https://example.com/install/sun.sh | sudo bash -s -- install \
  --telegram-token 'TOKEN' \
  --telegram-chat-id 'CHAT_ID' \
  --non-interactive \
  -y
```

引导脚本会下载发布压缩包和 `.sha256`，校验后解压，然后运行 `menu.sh`、`install.sh`、`test.sh` 或 `uninstall.sh`。

## 安装后写入的内容

- `/usr/local/sbin/security-update-notify`
- `/etc/security-update-notify/telegram.env`
- `/etc/systemd/system/security-update-notify.service`
- `/etc/systemd/system/security-update-notify.timer`
- `/etc/logrotate.d/security-update-notify`（如果系统有 logrotate）
- 后端相关的自动安全更新配置

按需安装的软件包：

- `apt`：`unattended-upgrades`、`needrestart`、`apt-listchanges`、`curl`、`python3`、`ca-certificates`
- `dnf`：`dnf-automatic`、`yum-utils` 或 `dnf-utils`、`curl`、`python3`、`ca-certificates`

## 测试与诊断

只读检查：

```bash
sudo ./test.sh
```

发送普通 OK 测试消息：

```bash
sudo ./test.sh --send-test --no-dedupe
```

发送模拟“需要重启”告警。这个命令**不会真的重启服务器**：

```bash
sudo ./test.sh --simulate-reboot --no-dedupe
```

已安装命令的诊断：

```bash
security-update-notify --version
sudo security-update-notify --doctor
```

常用 systemd / 日志命令：

```bash
systemctl list-timers security-update-notify.timer
sudo systemctl start security-update-notify.service
sudo tail -n 100 /var/log/security-update-notify.log
```

## 卸载

只移除程序和 systemd/logrotate 集成，保留配置与状态：

```bash
sudo ./uninstall.sh
```

同时删除配置与状态：

```bash
sudo ./uninstall.sh --purge-config
```

工具安装过的软件包会保留，不会自动卸载。

## 发布包内容

发布压缩包只包含面向用户的安装和诊断文件：

```text
CHANGELOG.md                  版本记录
LICENSE                       MIT 许可证
README.md                     项目文档
install.sh                    安装器
menu.sh                       交互菜单
test.sh                       诊断/测试工具
uninstall.sh                  卸载器
files/                        安装用运行时模板
```

`.github/`、`.gitignore`、`package.sh`、`sun.sh` 等源码维护文件会被故意排除，不进入发布压缩包。

## 开发

在源码仓库中，提交前建议运行：

```bash
bash -n install.sh menu.sh test.sh uninstall.sh package.sh sun.sh files/security-update-notify
./package.sh
cd dist && sha256sum -c security-update-notify-*.tar.gz.sha256
```

`package.sh` 会生成：

```text
dist/security-update-notify-VERSION.tar.gz
dist/security-update-notify-VERSION.tar.gz.sha256
```

GitHub Actions 会在 push 和 pull request 时运行同类语法检查与打包检查。

## 许可证

MIT。详见 [`LICENSE`](LICENSE)。
