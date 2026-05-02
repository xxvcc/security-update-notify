# 变更记录

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
