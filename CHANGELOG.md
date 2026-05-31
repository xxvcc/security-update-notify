# 变更记录

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
