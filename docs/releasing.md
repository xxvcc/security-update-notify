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

正式 GitHub Release 的无部署权限 CI 完成后，`Mirror signed release` 才开始同步；该 CI 只是事件信号和纵深检查，不能自行授权发布。真正的部署门禁来自受保护默认分支的 workflow revision：自动路径按成功 CI 的固定 `head_sha` 检出源码并确认 tag 仍指向同一提交，随后用默认分支固定的离线指纹和验证器重新校验精确资产集、归档、五架构 ELF 身份、静态链接及每个二进制的实际 `--version`，release tag 始终只是不执行的数据。部署密钥只存在于仅允许 `main` 的 GitHub Environment，不再保留仓库级副本；旧的可变 Release 只能从 `main` 手动修复。新版还必须包含 Go 打包器用同一离线密钥生成且绑定明确版本的 `sun.sh.asc`；工作流从已验签归档提取 `sun.sh` 和公钥，复验脚本签名与版本 notation，并从 `dl.ll.cd` 回读完整版本化集合后，才依次更新兼容用稳定 `sun.sh` 和最后的 `latest.json`。手动重跑旧版本只补齐其版本目录，不会覆盖当前稳定入口或 Latest。仓库已经启用不可变 Release；每次镜像成功后以及每周一，独立 GitHub 托管 Ubuntu 22.04/24.04 真机 canary 还会从两个公网源重新下载并实测验签、安装、doctor、dry-run、timer、卸载和 APT 配置恢复。

Release 必须先成为不可变状态。无部署权限的 release CI 验证公开资产后，默认分支上的镜像 workflow 才能使用受 Environment 限制的部署身份；release tag 始终只作为不执行的数据。不要手工跳过 checksum、GPG、固定指纹、版本 notation、五架构实际版本、公网回读或 canary。

## 发布后核对

- GitHub Latest 指向目标不可变 Release，且显式资产集合恰好为四项。
- GitHub 与版本化镜像资产逐字节一致，checksum 和 GPG 验证通过。
- 稳定 `sun.sh`、版本化 `sun.sh` 和签名归档内脚本一致；关键 notation 绑定目标版本。
- Ubuntu 22.04/24.04 公网 canary 完成安装、doctor、dry-run、timer、卸载和 APT 基线恢复。
- 最后确认 `main`、远端提交、tag 和发布版本绑定一致。
