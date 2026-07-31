# 发布维护流程

[English](releasing.en.md) | [返回 README](../README.md)

本页只面向具有离线签名密钥和 GitHub 发布权限的维护者，且必须在完整 Git 源码检出中执行；签名发行归档只保留这份流程供审计，不包含发布工具源码。普通用户应阅读[安装与升级](installation.md)和[安全与信任模型](security.md)。

## 发布前约束

- 根 `VERSION` 必须严格为一行 `VERSION="X.Y.Z"`，并在 CHANGELOG 中有唯一同版本标题。
- 发布提交必须位于受保护的 `main`，工作区干净，所选 CI 层级和 `ci-gate` 必须成功。
- 正式 tag 或 `--release` 构建必须能访问固定主指纹对应的离线 GPG 私钥；私钥不得进入 GitHub Actions。
- 正式包固定包含 amd64、arm64、386、ppc64le 和 s390x，不能缩小架构集合。

## 构建签名资产

先完成[开发与本地验证](development.md)中的门禁，然后运行：

```bash
go run ./cmd/sun-release package
cd dist && sha256sum -c security-update-notify-*.tar.gz.sha256
```

正式版本必须生成且只发布归档、checksum、归档 detached signature 和 `sun.sh.asc` 四项显式 Release 资产。打包器会在签名后立即复验；正式 tag 或 `--release` 不允许 `--sign off`。

打包器在生成归档后、签名前复验发布源内容及精确 HEAD/tag 身份，并在签名完成、取得输出目录独占锁后再次复验。同一输出目录的并发打包提交会串行执行；普通错误会尝试恢复原有集合，若恢复不完整则保留 `.sun-commit-backup-*` 证据，后续打包也会失败关闭等待人工处理。四个独立路径不是对未加锁读取者的一次文件系统原子切换；`SIGKILL`、内核崩溃或断电可能留下部分集合和恢复目录，不承诺崩溃原子性。只有命令成功返回且不存在恢复目录后，才能读取、校验或上传 `dist/`。

## 生成文件

```text
dist/security-update-notify-VERSION.tar.gz
dist/security-update-notify-VERSION.tar.gz.sha256
dist/security-update-notify-VERSION.tar.gz.asc  # 签名构建
dist/sun.sh.asc                                  # 签名构建，高保障首次安装
```

发布压缩包只包含安装、诊断、引导、迁移兼容所需的产品文件，以及 README 引用的用户和维护者文档；不包含构建工具、workflow 或私有运维资料。`sun.sh` 包含在签名压缩包中；签名构建还在压缩包之外生成 `sun.sh.asc`，不会把不确定签名时间写入可复现归档。镜像工作流从验签归档提取脚本和公钥，与 detached signature 一起发布到不可变版本目录；兼容稳定 URL 仍只提供 `sun.sh`。`install.sh` 与 `files/security-update-notify` 是 Go 打包器为旧 2.x 自升级客户端生成的最小启动器和版本标记，不包含旧安装或运行时逻辑，也不会落到已安装系统。

发布包内容：

```text
.env.example
CHANGELOG.md
LICENSE
README.md
README.en.md
VERSION
sun.sh
install.sh                              # 仅 2.x -> 3.0 的 Go 启动器
docs/development.en.md
docs/development.md
docs/go-port.md
docs/installation.en.md
docs/installation.md
docs/operations.en.md
docs/operations.md
docs/releasing.en.md
docs/releasing.md
docs/security.en.md
docs/security.md
files/needrestart-report-only.conf
files/release-signing.pub.asc
files/security-update-notify            # 仅旧客户端读取的版本标记
files/security-update-notify.logrotate
files/security-update-notify.service
files/security-update-notify-linux-amd64
files/security-update-notify-linux-arm64
files/security-update-notify-linux-386
files/security-update-notify-linux-ppc64le
files/security-update-notify-linux-s390x
```

## 发布与镜像保护

正式 GitHub Release 的无部署权限 CI 完成后，`Mirror signed release` 才开始同步；该 CI 只是事件信号和纵深检查，不能自行授权发布。真正的部署门禁来自受保护默认分支的 workflow revision：自动路径按成功 CI 的固定 `head_sha` 检出源码，确认 tag 仍指向同一提交，并通过 GitHub compare API 证明发布提交和实际执行的 workflow revision 都属于当前受保护 `main` 的历史；手动修复还会在仓库内明确拒绝从 `refs/heads/main` 以外的 ref 触发。GitHub concurrency 按 tag 隔离且不取消进行中的任务，因此无关版本不会替换同一版本的待处理同步；不同 tag 的不可变版本目录可以独立上传。工作流的 `verify-release` runner 不持有 Environment：它先用默认分支固定的离线指纹和验证器重新校验精确资产集、归档、五架构 ELF 身份与静态链接；tag 的源码检出始终只作为不执行的数据，完成签名和归档校验后的五个运行时会在空环境、固定 PATH、有界超时和输出限制下以 `--version` 实际执行。只有该 runner 成功后，全新的 `verify-and-sync` runner 才取得仅允许 `main` 的 GitHub Environment 身份；它从头复验资产结构、规范 checksum、元数据、GPG、归档和引导器签名，但不执行任何发布载荷。部署密钥不再保留仓库级副本；旧的可变 Release 只能从 `main` 手动修复。新版还必须包含 Go 打包器用同一离线密钥生成且绑定明确版本的 `sun.sh.asc`；部署 runner 从已验签归档提取 `sun.sh` 和公钥，复验脚本签名与版本 notation，上传不可变版本目录，并从 `dl.ll.cd` 回读完整版本化集合。只有这些验证全部通过，工作流才获取稳定 `sun.sh` 和 `latest.json` 共用的远端全局 `flock`；持锁后重新查询 GitHub Latest，依次更新兼容用稳定 `sun.sh` 和最后的 `latest.json`，逐项公网回读后才释放锁。远端会先在锁内快照原稳定文件；任一回读失败、控制通道 EOF/超时、信号或显式 `ABORT` 都会恢复二者，只有最终 `RELEASE` 才清除备份并提交。手动重跑旧版本只补齐其版本目录，不会覆盖当前稳定入口或 Latest。仓库已经启用不可变 Release；每次镜像成功后以及每周一，独立 GitHub 托管 Ubuntu 22.04/24.04 真机 canary 还会从两个公网源重新下载并实测验签、安装、doctor、dry-run、timer、卸载和 APT 配置恢复。

Release 必须先成为不可变状态。无部署权限的 release CI 验证公开资产后，默认分支上的镜像 workflow 才能使用受 Environment 限制的部署身份；tag 源码不执行，验签后的运行时只为实际版本探针调用。不要手工跳过 checksum、GPG、固定指纹、版本 notation、五架构实际版本、公网回读或 canary。

## 发布后核对

- GitHub Latest 指向目标不可变 Release，且显式资产集合恰好为四项。
- GitHub 与版本化镜像资产逐字节一致，checksum 和 GPG 验证通过。
- 稳定 `sun.sh`、版本化 `sun.sh` 和签名归档内脚本一致；关键 notation 绑定目标版本。
- Ubuntu 22.04/24.04 公网 canary 完成安装、doctor、dry-run、timer、卸载和 APT 基线恢复。
- 最后确认 `main`、远端提交、tag 和发布版本绑定一致。
