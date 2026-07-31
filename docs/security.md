# 安全与信任模型

[English](security.en.md) | [返回 README](../README.md)

本页记录普通用户和安全审计人员需要了解的网络边界、凭据边界、Release 签名和首次安装信任模型。

## Release 签名

发布包始终包含 `.sha256` 校验文件。`go run ./cmd/sun-release package` 在可用时生成归档的 `.tar.gz.asc` 和引导器的 `sun.sh.asc` 两份 detached signature；后者还在签名 hashed 子包中写入关键的版本 notation。正式发布或已有对应 tag 时强制两份签名，并会在创建任何 `dist` 文件前拒绝显式 `--sign off`。`sun.sh` 默认以 `required` 模式校验下载的 Release，`auto` 仅作为兼容别名保留，也会要求 gpg 与归档 `.asc` 同时存在；只有显式传入 `--verify-signature off` 才会跳过 Release 签名校验。

根 `VERSION` 是唯一版本源，格式必须严格为 `VERSION="X.Y.Z"`。正式发布（存在对应 `vX.Y.Z` tag，或显式设置 `RELEASE=1`）**强制签名并固定包含五架构 Go 二进制**：Go 发布工具会绑定根版本、唯一 `CHANGELOG` 标题、tag、包内版本和每个二进制的 `--version`，且架构集合不可覆盖；缺少 Go、Bash（仅用于检查 `sun.sh` 语法）、任一 amd64/arm64/386/ppc64le/s390x 架构产物，或固定指纹对应的 GPG 私钥都会失败。正式 GitHub Release 的显式资产是 tarball、checksum、tarball signature 和 `sun.sh.asc`；无特权 release CI 提供前置纵深检查，默认分支镜像 workflow 中不持有 Environment 的验证 runner 再独立精确校验四件资产并实际探测五个运行时。随后全新的部署 runner 才取得受 Environment 约束的身份，从头复验资产结构、checksum、GPG、归档和引导器版本绑定，且不执行发布载荷。私钥不进入 CI，仍由维护者离线持有。此外，`security-update-notify upgrade` 默认 **fail-closed**：从固定发布镜像优先下载、GitHub 回退，校验 sha256，并在解包前用内置公钥与 pin 指纹强制校验 GPG 签名后才升级。应急变量 `SECURITY_UPDATE_NOTIFY_UPGRADE_ALLOW_UNSIGNED=1` 只有在可信系统路径中确实没有 `gpg` 时才允许 sha256-only；只要 `gpg` 存在，缺失或无效签名仍会失败关闭。

## 安全说明

SUN 的范围刻意保持很小：

- 出站仅 HTTPS：提醒按配置发往 Telegram Bot API 和/或 `open.feishu.cn`；默认另向公网 IP 探测服务（api.ipify.org / ifconfig.me）获取出口 IP（`INCLUDE_PUBLIC_IP=0` 可关闭）；安装和自升级优先访问 `dl.ll.cd`，不可用时访问 GitHub。若要用出口防火墙收紧，请把这些目的地一并放行或关闭对应功能；
- 不接收远程命令；
- 不提供公开 HTTP 入口；
- 不自动重启；
- 普通通知配置仅 root 可读；飞书 App Secret 使用独立 systemd/root 凭据，不进入普通配置、命令行、日志或升级备份；
- 尽力支持的发行版必须显式开启。

发布包的 `.sha256` 文件可以防止下载损坏或版本不匹配；如果你的威胁模型包含发布源被攻破，请保持默认签名校验开启，不要使用 `--verify-signature off` 或无签名升级逃生选项。

归档签名认证 Release 内容；`sun.sh.asc` 则在任何首次执行之前认证引导器字节，并通过关键 notation 绑定其发布版本。便捷 `curl | /bin/bash -p` 不能利用后者，因为代码已先运行；其中 `-p` 只负责在 Bash 读取代码前禁止 `BASH_ENV` 和导出函数注入，不能认证网络响应。高保障流程才把 fixed fingerprint 作为网络之外的初始信任锚。签名不证明“哪个版本是最新”，也不保护已被攻破的本机 root、`gpg` 或 shell，因此高保障流程要求管理员从独立可信渠道确认目标版本和指纹。

## 相关文档

- [高保障首次安装](installation.md#高保障首次安装生产环境推荐)
- [发布维护流程](releasing.md)
- [3.x Go 架构与发布约束](go-port.md)
