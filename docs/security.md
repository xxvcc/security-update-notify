# 安全与信任模型

[English](security.en.md) | [返回 README](../README.md)

本页记录普通用户和安全审计人员需要了解的网络边界、凭据边界、Release 签名和首次安装信任模型。

## Release 签名

发布包始终包含 `.sha256` 校验文件。`go run ./cmd/sun-release package` 在可用时生成归档的 `.tar.gz.asc` 和引导器的 `sun.sh.asc` 两份 detached signature；后者还在签名 hashed 子包中写入关键的版本 notation。正式发布或已有对应 tag 时强制两份签名，并会在创建任何 `dist` 文件前拒绝显式 `--sign off`。`sun.sh` 默认以 `required` 模式校验下载的 Release，`auto` 仅作为兼容别名保留，也会要求 gpg 与归档 `.asc` 同时存在；只有显式传入 `--verify-signature off` 才会跳过 Release 签名校验；关闭后 `sun.sh` 连 gpg 都不再要求安装，也不会下载 `.asc`。

根 `VERSION` 是唯一版本源，格式必须严格为 `VERSION="X.Y.Z"`。正式发布（存在对应 `vX.Y.Z` tag，或显式设置 `RELEASE=1`）**强制签名并固定包含五架构 Go 二进制**：Go 发布工具会绑定根版本、唯一 `CHANGELOG` 标题、tag、包内版本和每个二进制的 `--version`，且架构集合不可覆盖；缺少 Go、Bash（仅用于检查 `sun.sh` 语法）、任一 amd64/arm64/386/ppc64le/s390x 架构产物，或固定指纹对应的 GPG 私钥都会失败。正式 GitHub Release 的显式资产是 tarball、checksum、tarball signature 和 `sun.sh.asc`；无特权 release CI 提供前置纵深检查，默认分支镜像 workflow 中不持有 Environment 的验证 runner 再独立精确校验四件资产并实际探测五个运行时。随后全新的部署 runner 才取得受 Environment 约束的身份，从头复验资产结构、checksum、GPG、归档和引导器版本绑定，且不执行发布载荷。私钥不进入 CI，仍由维护者离线持有。此外，`security-update-notify upgrade` **始终 fail-closed**：从固定发布镜像优先下载、GitHub 回退，校验 sha256，并在解包前用内置公钥与 pin 指纹强制校验 GPG 签名；缺少 `gpg`、`.asc` 或有效签名都会拒绝升级。特权自升级忽略调用者的 `TMPDIR`，只在逐级 no-follow 验证过的 root 所有系统临时目录下创建私有工作区。

## 安全说明

SUN 的范围刻意保持很小：

- 出站仅 HTTPS：提醒按配置发往 Telegram Bot API 和/或 `open.feishu.cn`；默认另向公网 IP 探测服务（api.ipify.org / ifconfig.me）获取出口 IP（`INCLUDE_PUBLIC_IP=0` 可关闭）；安装和自升级优先访问 `dl.ll.cd`，不可用时访问 GitHub。若要用出口防火墙收紧，请把这些目的地一并放行或关闭对应功能。这些请求全部直连：SUN 自己的 HTTPS 客户端在传输层禁用代理，不读取 `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`；代理变量只刻意转发给包管理器、`gpg`、`systemctl` 等子进程以及 `sun.sh` 中的 `curl`。因此在出口只有 HTTP 代理的主机上，apt/dnf 仍能更新，通知和自升级检查却会失败。隔离测试唯一允许的明文例外是数值型回环 IP；`localhost`、其它主机名及其重定向均不属于例外；
- 特权生产进程忽略用于 Go/隔离测试的 API 根地址、配置、凭据、状态、锁、日志及后端探测路径环境覆盖。安装器子进程仅能通过继承的锁文件描述符复用父进程已经持有的主运行锁，并会把描述符重新绑定到规范锁 inode 后验证 flock 能力；单独伪造描述符环境值会失败关闭。systemd 正式提供的 `CREDENTIALS_DIRECTORY` 仍是受支持的凭据入口。不要把测试覆盖当作受限 sudo 委派接口。运行时打开已有配置前还要求其父目录为当前特权用户所有、不可由组或其他用户写入且不是符号链接，并通过固定目录描述符打开叶文件；安装器写入 `/etc/logrotate.d` 前执行等价的 root 目录信任检查；
- systemd 服务使用 `ProtectSystem=full`，因此 `/usr`、boot loader 目录和 `/etc` 在服务 mount namespace 内只读；该级别刻意不把整个文件系统改成只读，使不安装软件的 APT/DNF 查询子进程仍能写入其 `/var` 缓存、锁和状态路径。除 `/run/security-update-notify.lock` 运行锁外，服务自身的持久写入仅限 `/var/lib/security-update-notify` 与日志文件；
- 不接收远程命令；
- 不提供公开 HTTP 入口；
- 不自动重启；
- 普通通知配置仅 root 可读；飞书 App Secret 使用独立 systemd/root 凭据，不进入普通配置、命令行、日志或升级备份。Telegram Bot Token 属于普通配置，因此 `/var/backups/security-update-notify/<timestamp>/` 下的升级备份含有 `telegram.env` 的 `0600` 副本（保留当前及前两次事务）；普通 `uninstall` 会保留这些备份，只有 `--purge-config` 删除它们；
- 固定共享日志父目录 `/var/log` 是唯一允许 root 所有且组可写的特权目录例外，并假定其目录组只含受信的系统特权主体。日志叶仍以 no-follow 打开并要求 root 所有、不可组/其他写且只有一个硬链接；这些检查能限制符号链接、特殊文件、普通非 root 文件和硬链接注入，却不能阻止目录组成员 rename/unlink 条目，因此不保证日志命名完整性或可用性。自定义日志父目录和其他配置、状态、二进制目录仍拒绝组/其他写；
- 尽力支持的发行版必须显式开启。

发布包的 `.sha256` 文件可以防止下载损坏或版本不匹配；如果你的威胁模型包含发布源被攻破，请保持 `sun.sh` 的默认签名校验开启，不要使用 `--verify-signature off`。关闭时的影响范围要说清楚：`sun.sh` 既不要求本机装有 gpg，也不会去下载 `.asc`，唯一剩下的检查就是与归档同一 base URL 提供的 `.sha256`。它只能发现传输损坏或版本错配，不能识别恶意发布源、被攻破的 CDN 或 TLS 终结点——能替换归档的对手同样能替换该 checksum。Go 自升级没有关闭签名校验的选项。

归档签名认证 Release 内容；`sun.sh.asc` 则在任何首次执行之前认证引导器字节，并通过关键 notation 绑定其发布版本。便捷 `curl | /bin/bash -p` 不能利用后者，因为代码已先运行；其中 `-p` 只负责在 Bash 读取代码前禁止 `BASH_ENV` 和导出函数注入，不能认证网络响应。高保障流程才把 fixed fingerprint 作为网络之外的初始信任锚。签名不证明“哪个版本是最新”，也不保护已被攻破的本机 root、`gpg` 或 shell，因此高保障流程要求管理员从独立可信渠道确认目标版本和指纹。

## 相关文档

- [高保障首次安装](installation.md#高保障首次安装生产环境推荐)
- [发布维护流程](releasing.md)
- [3.x Go 架构与发布约束](go-port.md)
