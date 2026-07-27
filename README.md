# security-update-notify

<p align="center">
  <a href="https://github.com/xxvcc/security-update-notify/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/xxvcc/security-update-notify?style=flat-square&label=release&color=2EA043"></a>
  <img alt="Linux" src="https://img.shields.io/badge/Linux-systemd-1793D1?style=flat-square&logo=linux&logoColor=white">
  <img alt="Debian" src="https://img.shields.io/badge/Debian-12%20%7C%2013-A81D33?style=flat-square&logo=debian&logoColor=white">
  <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04%20%7C%2026.04-E95420?style=flat-square&logo=ubuntu&logoColor=white">
  <img alt="RHEL compatible" src="https://img.shields.io/badge/RHEL%20compatible-8%20%7C%209%20%7C%2010-EE0000?style=flat-square&logo=redhat&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

> 自动安装安全更新；只有在需要重启服务器或重启服务时，才通过 Telegram、飞书或两者发送清晰提醒。

**security-update-notify**（简称 **SUN**）是一个轻量 Linux 工具，适合维护服务器、VPS 或小型基础设施的人使用。

它使用发行版原生更新机制，通过 systemd timer 定时运行，只发起出站 HTTPS 请求：提醒按配置发往 Telegram Bot API 和/或飞书开放平台；默认还会向公网 IP 探测服务（api.ipify.org / ifconfig.me）获取出口 IP（可用 `INCLUDE_PUBLIC_IP=0` 关闭或用 `PUBLIC_IP` 手动指定）；安装和自升级优先访问 `dl.ll.cd` 发布镜像，传输不可用时回退 GitHub。没有 Web 面板，没有常驻控制端口，也不接收消息命令。

> 自 **3.0** 起，安装、配置、运行、诊断、测试、卸载、自升级和发布打包均由 Go 实现；唯一维护的 Shell 产品实现是首次安装引导器 `sun.sh`。3.0 发布包会由 Go 打包器额外生成一个仅供 2.x 跨大版本自升级的 `install.sh` 启动器，它只选择并 `exec` 已验签的 Go 安装器，不会安装到系统，也不是第二套安装实现。正式包固定提供 linux/amd64、arm64、386、ppc64le、s390x 五个二进制，不再提供 Bash 运行时或未列架构回退；不支持的架构会在 Go 安装器运行前明确拒绝（引导器可能已补齐自身的下载/验签依赖）。

已安装的 Go 二进制不依赖 `python3`、`curl` 或 `tar` 完成日常检查与通知；自升级验签仍调用 `gpg`，系统状态与补丁管理仍按需调用发行版的 apt/dnf、needrestart/needs-restarting 和 systemd 命令。

**语言 / Languages**：中文 | [English](README.en.md)

## 一键安装

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash
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
- **Telegram / 飞书可单选，也可双发**：Telegram 保持紧凑纯文本，飞书使用原生 JSON 2.0 卡片；旧配置自动保持 Telegram，双发时两个渠道独立去重，一个渠道失败不会让另一个重复提醒。
- **检测整机重启与服务/进程重启需求**：基于 `needrestart` 或 `needs-restarting`。
- **补丁维护看门狗**：检查自动更新机制、策略漂移、hold/versionlock/exclude、包管理器损坏、软件源元数据、补丁滞留，以及重启需求是否拖延；另检查发行版 EOL，并每周提示 SUN 新版本。所有升级和重启仍由管理员手动执行。
- **中英文界面，单语显示**：安装、菜单、诊断在第一步选择语言（中文或英文，默认中文），之后整套终端交互只按所选语言显示，不再中英文混排；该选择同时作为通知语言的默认值，可用 `--notify-lang` 单独覆盖。
- **通知中显示公网 IP**：默认自动获取公网 IP，也可手动指定或关闭显示；自动获取由 Go 运行时用标准库完成，不新增 `curl`/`python3` 依赖。
- **重复提醒抑制**：支持只提醒一次、每天一次、每 N 天一次。
- **支持交互式与非交互式安装/升级**：重新运行安装器会复用已有配置。
- **使用 systemd timer 定时运行**。
- **不监听任何入站端口**。

Telegram 文本示例（`NOTIFY_LANG=zh`；飞书用原生卡片表达同一组状态）：

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

飞书通道发送内嵌的 Card JSON 2.0（`msg_type=interactive`）：红色表示检查失败或发行版已 EOL，橙色表示需要整机重启/服务维护，绿色表示测试成功或状态健康，蓝色表示 SUN 升级。卡片包含主机、IP、系统、检查时间、重启状态、维护摘要、建议命令和静态项目文档链接。它不使用租户 `template_id`，按钮只执行 URL 跳转，不需要事件订阅、回调服务或额外权限。飞书客户端 `7.20` 及以上完整显示 JSON 2.0；旧客户端只显示卡片标题和升级客户端提示。

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
只有在需要人工处理时才向已配置接收平台发送消息
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
| Ubuntu | 22.04, 24.04, 26.04 | `apt` |
| RHEL-compatible（Rocky / AlmaLinux 实测） | 8, 9, 10 | `dnf`（DNF4） |
| Fedora | 43, 44 | `dnf`（DNF5） |

### 尽力支持

以下系统需要显式加 `--allow-best-effort`：

- Debian 11
- Ubuntu 20.04（仅限已启用 Ubuntu Pro/ESM 安全源）
- CentOS Stream 9 / 10
- Oracle Linux 8 / 9 / 10
- CloudLinux 8 / 9 / 10
- Amazon Linux 2023

Amazon Linux 2023 默认锁定在一个发行快照，`dnf-automatic` 不会替管理员自动前移 `releasever`；旧快照可能看不到新快照中已经发布的安全公告。SUN 只能检查当前已启用快照，管理员仍须用 `dnf check-release-update` 跟踪并按 Amazon 的升级流程前移发行版本，因此该系统不能获得与正式支持发行版相同的补丁完整性承诺。

尽力支持表示 SUN 的代码路径兼容，不表示 SUN 能证明所有外部订阅或安全公告源仍然有效；管理员必须先确认系统确有持续更新的安全源。Ubuntu 20.04 的标准安全维护已经结束；SUN 只有在本机 Ubuntu Pro 客户端的结构化状态确认 `esm-infra` 已启用时，才按 ESM 的 2030-04-30 近似终止日计算支持期，否则继续告警该版本已结束安全支持。CentOS Stream 8 已停止维护，因此不再列入兼容矩阵。

无凭据 CI 会对 Debian 11、Ubuntu 20.04（不包含 ESM entitlement）、CentOS Stream 9/10、Oracle Linux 8/9/10 和 Amazon Linux 2023 执行容器生命周期 smoke；这验证安装、真实依赖包事务、升级、回滚与 purge 代码路径，不证明订阅、安全源完整性或真实 systemd D-Bus。CloudLinux 目前只有 profile、依赖和失败关闭测试，因为没有可公开、无授权拉取且适合重复 CI 的官方镜像。

未列出的 `ID_LIKE` 衍生版不会自动视为正式支持。只有显式传入 `--allow-best-effort`、能够从 ancestry 明确确认 apt，或在任何包安装、备份和配置写入前根据本机 `dnf`/`dnf5`/`yum` 版本输出明确探测出 DNF4/DNF5，并且依赖包、命令、配置、timer 和不可跳过的安装后 `doctor` 门禁全部通过时，安装器才会接受；模糊、冲突或失败的 DNF 探测会直接拒绝，同时声明 Debian/Ubuntu 与 RHEL/Fedora/CentOS 两类冲突 ancestry 的系统也会直接拒绝。

### 暂不支持

- Alpine
- Arch Linux
- SUSE / openSUSE
- 没有完整 systemd 的容器或极简系统
- 已 EOL 且没有有效厂商或延长安全源的系统

## 快速开始

### 1. 准备消息通知

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

交互安装时，SUN 会在输入 App ID 和隐藏输入 App Secret 后，通过 Directory v1 分页扫描应用可见的在职员工，并按“中文姓名 + 手机号尾号 + `open_id`”显示编号列表。你选择序号后，安装器只保存对应的 `open_id`；姓名和手机号尾号只用于人工核验。运行时固定使用该 `open_id` 单发原生 JSON 2.0 卡片，不会每次通知都查询通讯录。不同飞书应用的 `open_id` 可能不同，不能跨应用复用；升级时如果更换 App ID，安装器会清除旧接收人并要求重新选择或显式提供 `open_id`。

### 2. 安装

#### 高保障首次安装（生产环境推荐）

下面的流程不会把网络响应直接交给 shell。请先从可信发布公告确认要安装的明确版本，把 `X.Y.Z` 改成该版本；它在 root 自有临时目录中下载版本化 `sun.sh`、detached signature 和公钥，核对固定主密钥指纹及签名内的关键版本 notation，并且只有全部验证成功后才执行脚本。机器必须预先具有 `bash`、`curl` 和 `gpg`；请先通过发行版的软件包管理器或可信离线介质补齐它们。

```bash
sudo bash <<'SUN_ROOT'
set -euo pipefail

SUN_VERSION='X.Y.Z' # 必须改为从可信发布公告确认的明确版本
SUN_PIN='C678256ACBFC6491BF5076655F3AE24999921FFC'
SUN_NOTATION='release-version@xxv.cc'
[[ "$SUN_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([._-][0-9A-Za-z]+)?$ \
   && "${#SUN_VERSION}" -le 64 ]] || {
  echo '请先把 SUN_VERSION 改为明确版本，例如 3.0.2。' >&2
  exit 2
}

SUN_BASE="https://dl.ll.cd/security-update-notify/v${SUN_VERSION}"
SUN_WORK="$(mktemp -d)"
trap 'rm -rf "$SUN_WORK"' EXIT
chmod 0700 "$SUN_WORK"
mkdir "$SUN_WORK/gnupg"
chmod 0700 "$SUN_WORK/gnupg"

for asset in sun.sh sun.sh.asc release-signing.pub.asc; do
  curl --disable --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --connect-timeout 20 --retry 4 --retry-delay 1 --retry-max-time 180 \
    --max-filesize 1048576 \
    --output "$SUN_WORK/$asset" "$SUN_BASE/$asset"
done

gpg_cmd=(gpg --no-options --batch --no-tty --homedir "$SUN_WORK/gnupg")
"${gpg_cmd[@]}" --import "$SUN_WORK/release-signing.pub.asc" >/dev/null 2>&1
primary_fingerprints=()
want_primary=0
while IFS=: read -r -a fields; do
  case "${fields[0]:-}" in
    pub) want_primary=1 ;;
    fpr)
      if [[ "$want_primary" -eq 1 ]]; then
        primary_fingerprints+=("${fields[9]:-}")
        want_primary=0
      fi
      ;;
  esac
done < <("${gpg_cmd[@]}" --with-colons --list-keys 2>/dev/null)
[[ "${#primary_fingerprints[@]}" -eq 1 \
   && "${primary_fingerprints[0]}" == "$SUN_PIN" ]] || {
  echo '发布公钥不是固定指纹的唯一主密钥；拒绝执行。' >&2
  exit 1
}

status="$("${gpg_cmd[@]}" --known-notation "$SUN_NOTATION" --status-fd=1 --show-notation \
  --verify "$SUN_WORK/sun.sh.asc" "$SUN_WORK/sun.sh" 2>"$SUN_WORK/gpg.log")" || {
  cat "$SUN_WORK/gpg.log" >&2
  exit 1
}
valid_count=0
pinned_count=0
name_count=0
name_match=0
flags_count=0
flags_match=0
data_count=0
data_match=0
while read -r -a fields; do
  [[ "${fields[0]:-}" == '[GNUPG:]' ]] || continue
  case "${fields[1]:-}" in
    VALIDSIG)
      valid_count=$((valid_count + 1))
      last="${fields[${#fields[@]}-1]:-}"
      if [[ "${fields[2]:-}" == "$SUN_PIN" || "$last" == "$SUN_PIN" ]]; then
        pinned_count=$((pinned_count + 1))
      fi
      ;;
    NOTATION_NAME)
      name_count=$((name_count + 1))
      [[ "${#fields[@]}" -eq 3 && "${fields[2]:-}" == "$SUN_NOTATION" ]] &&
        name_match=$((name_match + 1))
      ;;
    NOTATION_FLAGS)
      flags_count=$((flags_count + 1))
      [[ "${#fields[@]}" -eq 4 && "${fields[2]:-}" == 1 && "${fields[3]:-}" == 1 ]] &&
        flags_match=$((flags_match + 1))
      ;;
    NOTATION_DATA)
      data_count=$((data_count + 1))
      [[ "${#fields[@]}" -eq 3 && "${fields[2]:-}" == "$SUN_VERSION" ]] &&
        data_match=$((data_match + 1))
      ;;
  esac
done <<<"$status"
[[ "$valid_count" -eq 1 && "$pinned_count" -eq 1 \
   && "$name_count" -eq 1 && "$name_match" -eq 1 \
   && "$flags_count" -eq 1 && "$flags_match" -eq 1 \
   && "$data_count" -eq 1 && "$data_match" -eq 1 ]] || {
  echo '引导器签名未唯一绑定固定指纹和目标版本；拒绝执行。' >&2
  exit 1
}

chmod 0700 "$SUN_WORK/sun.sh"
bash "$SUN_WORK/sun.sh" --version "$SUN_VERSION" --base-url "$SUN_BASE"
SUN_ROOT
```

使用明确版本是这条路径的一部分：`latest.json` 是可用性索引，不是签名的版本新鲜度证明。`sun.sh.asc` 的 hashed 子包包含关键 notation `release-version@xxv.cc=<版本>`；验签既核对脚本字节，也要求该值与人工确认的版本完全一致，因此旧版合法脚本和签名不能被搬到新版本目录冒充。版本目录中的 `sun.sh`、`sun.sh.asc` 和公钥只有在镜像工作流验签发布归档、核对 tag 源码并从公网回读复验后才会出现；公钥文件本身仍不是信任根，命令中固定且应从独立可信渠道核对的指纹才是。

#### 便捷一行安装（兼容入口）

网站引导器会下载最新签名 Release、校验 `.sha256` 与 GPG 签名（默认必须通过），然后启动交互式菜单：

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash
```

这条命令保持原有体验，但 `curl` 下载的 `sun.sh` 会在自身被 detached signature 验证之前执行，因此首次引导脚本的信任依赖 HTTPS、域名和镜像/CDN；脚本随后对 Release 的校验不能追溯认证已经运行的第一阶段。威胁模型包含下载站或 TLS 终点失陷时，请使用上面的高保障流程。

从网址启动引导器时，机器必须预先装有 `curl`，因为脚本尚未取得前不可能自行补装它。`set -o pipefail` 让缺少 `curl`、DNS/TLS 或下载失败成为整条管道的非零退出，而不是让末端 `bash` 读取空输入后误报成功。脚本运行后需要 `curl`、`tar`、`sha256sum`、`mktemp`、`python3`、`env`、`uname`、`gpg` 和 `timeout`；缺少命令时只通过 apt、dnf、microdnf 或 yum 安装对应的软件包，再逐项复查，避免在 RPM 极简系统上用完整 `curl/coreutils` 替换已安装的 `curl-minimal/coreutils-single`。没有受支持的包管理器或补齐后仍缺命令时会在下载/安装前失败。Release 的 GPG 签名默认强制校验。

如果你更想从源码运行，也可以：

```bash
git clone https://github.com/xxvcc/security-update-notify.git
cd security-update-notify
source ./VERSION
arch="$(go env GOARCH)"
case "$arch" in amd64|arm64|386|ppc64le|s390x) ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac
./build/build.sh linux "$arch" "$VERSION" ./security-update-notify
sudo ./security-update-notify install
```

源码构建需要仓库 `go.mod` 固定的 Go 工具链，且当前机器必须属于上述五个发布架构。`build/build.sh` 会把根 `VERSION` 注入二进制；不要直接用未注入版本的 `go run` 或普通 `go build` 产物安装。

安装器会先让你选择界面语言（中文或英文，默认中文），然后选择 Telegram、飞书或双平台。随后按所选接收平台询问：

- Telegram Bot Token / Chat ID；和/或
- 飞书 App ID / 隐藏输入的 App Secret，然后从自动扫描结果中选择接收人；
- 每日检查时间，默认 `09:00`；
- 重复提醒策略；
- 安装后是否发送测试消息；首次配置飞书或更换接收人时默认发送一条仅飞书的验证消息，输入 `n` 可跳过。

如果想跳过交互式语言选择，可在命令行加 `--lang zh` 或 `--lang en`。

写入配置前，安装器会先做接收平台预检：

- Telegram：使用 `getMe` 验证 Bot Token，并用 `sendMessage` 验证 Chat ID 与权限；连接重置、超时、HTTP 429 和 5xx 会自动重试三次。持续的临时网络故障不会被误报为 Token 无效，也不会清空旧凭据；交互模式可重试、跳过本次预检或中止，非交互模式以退出码 `75` 失败并回滚；
- 飞书：获取 `tenant_access_token` 后扫描应用通讯录范围内的在职员工；如已显式提供 `open_id`，则只验证应用凭据。安装预检不会发送消息。

扫描结果受飞书应用“通讯录数据范围”限制。扫描失败或没有可见员工时，交互安装器允许重试、手动输入当前应用下的 `open_id`，或中止安装；非交互模式必须显式提供 `--feishu-receive-id`。

首次配置飞书或更换应用、Secret、接收人时，安装器默认发送一条仅飞书的强验证消息，用于确认所选 `open_id` 位于机器人的可用范围内；交互模式输入 `n`，或使用 `--skip-feishu-test`、`--skip-notify-test`，可明确跳过。非交互模式不会弹出确认，但同样默认执行强验证。强验证会等待现有检查释放运行锁（最多 60 秒），超时或发送失败都会回滚，不能把“未发送”误判为成功。显式 `--send-test` 会在安装后额外测试全部已配置接收平台，并覆盖 skip 对“额外发送”的抑制；这条额外测试是咨询项，失败会显示警告但不会回滚已经完成的核心安装或关闭 timer。独立命令 `security-update-notify test --send-test` 仍以发送结果决定自身退出码。

### 3. 验证

```bash
sudo security-update-notify test
sudo security-update-notify test --send-test --no-dedupe
sudo security-update-notify test --simulate-reboot --no-dedupe
```

模拟重启测试只会发送测试提醒，**不会真的重启服务器**。

## 非交互式安装

适合放进初始化脚本、云服务器模板或批量部署流程：

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash -s -- install \
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

set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | \
  sudo bash -s -- install --env-file "$PWD/.env" --non-interactive -y
```

也可以只把 token 单独放进 root-only 文件：

```bash
sudo install -m 600 /dev/null /root/.security-update-notify-token
sudoedit /root/.security-update-notify-token

set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash -s -- install \
  --telegram-token-file /root/.security-update-notify-token \
  --telegram-chat-id 'CHAT_ID' \
  --non-interactive \
  -y
```

飞书非交互式安装使用独立的 App Secret 源文件，不能把 Secret 直接写进 `.env` 或命令行：

```bash
sudo install -m 600 /dev/null /root/.security-update-notify-feishu-secret
sudoedit /root/.security-update-notify-feishu-secret

set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash -s -- install \
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
--notify-upgrade 1        # 升级成功后向已配置接收平台发送通知；默认 0
--skip-post-install-check # 跳过安装/升级后自检
--allow-best-effort        # 允许尽力支持的发行版
--lock-wait SECONDS       # 运行锁屏障等待 0..3600 秒，默认 60
--send-test                # 安装后额外测试全部平台；失败告警但不回滚安装
--skip-telegram-test       # 跳过 Telegram 预检
--skip-feishu-test         # 跳过飞书预检及默认强验证；未指定接收人时仍需扫描选人
--skip-notify-test         # 跳过全部预检及默认飞书强验证；显式 --send-test 仍发送
```

已安装 SUN 后，可用 `sudo security-update-notify install [选项]` 直接执行同一 Go 安装器；管理已有安装的消息通知设置使用 `sudo security-update-notify configure notifications`。


### 升级

重新运行一键安装器即可升级到最新 release：

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo bash -s -- upgrade --non-interactive -y
```

已安装 SUN 后，也可以直接运行 `sudo security-update-notify upgrade`。一键安装器和内置升级都会优先读取 `https://dl.ll.cd/security-update-notify/latest.json` 并从同一镜像下载签名资产；镜像索引或完整资产集合传输失败时自动回退 GitHub。下载完成后仍会校验 `.sha256`，并用内置 pin 的指纹强制校验 GPG 签名（默认 fail-closed，缺签名即拒绝）后才升级。镜像只提供传输可用性，不是信任根。

正式 GitHub Release 的无部署权限 CI 完成后，`Mirror signed release` 才开始同步；该 CI 只是事件信号和纵深检查，不能自行授权发布。真正的部署门禁来自受保护默认分支的 workflow revision：自动路径按成功 CI 的固定 `head_sha` 检出源码并确认 tag 仍指向同一提交，随后用默认分支固定的离线指纹和验证器重新校验精确资产集、归档、五架构 ELF 身份、静态链接及每个二进制的实际 `--version`，release tag 始终只是不执行的数据。部署密钥只存在于仅允许 `main` 的 GitHub Environment，不再保留仓库级副本；旧的可变 Release 只能从 `main` 手动修复。新版还必须包含 Go 打包器用同一离线密钥生成且绑定明确版本的 `sun.sh.asc`；工作流从已验签归档提取 `sun.sh` 和公钥，复验脚本签名与版本 notation，并从 `dl.ll.cd` 回读完整版本化集合后，才依次更新兼容用稳定 `sun.sh` 和最后的 `latest.json`。手动重跑旧版本只补齐其版本目录，不会覆盖当前稳定入口或 Latest。仓库已经启用不可变 Release；每次镜像成功后以及每周一，独立 GitHub 托管 Ubuntu 22.04/24.04 真机 canary 还会从两个公网源重新下载并实测验签、安装、doctor、dry-run、timer、卸载和 APT 配置恢复。

如果已安装过 SUN，安装器会自动读取 `/etc/security-update-notify/telegram.env` 和现有 timer 时间，并复用未显式覆盖的设置。运行 `sudo security-update-notify configure notifications` 可以事务化更改接收平台、Telegram 配置、飞书应用、App Secret 或接收人。移除接收平台会删除其保存凭据，新增或修改只重复验证受影响的平台；任一步失败都会随安装事务回滚。旧配置没有 `NOTIFY_CHANNELS` 时自动按 `telegram` 处理，未显式覆盖的其他选项继续沿用。

升级前会备份关键文件到 `/var/backups/security-update-notify/<timestamp>`，但飞书 App Secret 不进入该备份；升级失败会尝试自动回滚，并恢复 SUN timer 安装前的启用链接与 active 状态。升级后默认运行自检；可用 `--notify-upgrade 1` 向已配置接收平台发送升级通知。升级通知采用 best-effort 语义，不会因通知失败回滚已经完成的升级，也不会整体重试双发而重复已成功平台。

## 重复提醒策略

| 模式 | 行为 |
| --- | --- |
| `once` | 同一个告警只发送一次，直到状态变化（旧名 `always`，仍兼容接受）。 |
| `daily` | 同一个告警每天最多发送一次（**默认 / 推荐**）。 |
| `interval` | 同一个告警每 N 天发送一次，默认 `3` 天。 |

默认 `daily`：每天最多提醒一次，既能在重启长期未处理时持续提醒，又不会频繁打扰。若想更安静可用 `once`（只提醒一次）或 `interval`（每 N 天一次）。

双发时每个渠道有独立状态：Telegram 成功而飞书失败时，下一次只重试飞书，不会重复发送 Telegram。

## 安全更新看门狗

除了原有内核、服务重启和发行版 EOL 检测，SUN 默认还会执行七类补丁维护检查：

1. 待安装安全补丁连续存在达到阈值后告警，默认 `3` 天。
2. 发现 APT hold，或 DNF versionlock/exclude 阻止安全补丁时立即告警。
3. 检测 APT/dnf-automatic 的安全更新策略与定时器配置漂移。
4. 运行 `dpkg --audit`、`apt-get check` 或 `dnf check` 检测包管理器损坏状态。
5. 检查 APT InRelease 是否缺失、过期或长期未刷新，并区分软件源刷新失败与签名/TLS 错误；DNF 同样区分元数据读取与签名/TLS 错误。
6. 整机或服务重启需求持续达到阈值后升级告警，默认 `7` 天。
7. 默认每 `7` 天检查一次 SUN 最新发布，只发送新版本提示，**绝不自动升级 SUN**。

| 配置项 | 默认 | 说明 |
| --- | --- | --- |
| `CHECK_UPDATE_HEALTH` | `1` | 检测自动更新机制、有效策略、包管理器一致性和软件源健康：包括定时器禁用、上次运行失败、长时间无成功记录、磁盘不足、配置漂移、包状态损坏、元数据缺失/过期/陈旧及签名/TLS 错误。设为 `0` 会关闭这一组检查，但不会关闭补丁滞留、重启时长、EOL 或 SUN 版本提示。 |
| `STALE_UPDATE_DAYS` | `7` | 多少天没有成功的自动安全更新即视为异常；设为 `0` 关闭该子项。 |
| `PENDING_ALERT_DAYS` | `3` | 待安装安全更新连续存在多少天后告警；设为 `0` 关闭补丁滞留告警。首次发现时间保存在 root-only 状态文件中，补丁清空后自动移除。 |
| `RESTART_ALERT_DAYS` | `7` | 整机或服务重启需求持续多少天后升级告警；设为 `0` 关闭时长升级。不会自动重启机器或服务。 |
| `CHECK_SELF_UPDATE` | `1` | 周期检查 SUN 新版本；只提示，不自动升级。 |
| `SELF_UPDATE_CHECK_DAYS` | `7` | SUN 版本检查间隔；成功结果会缓存，`security-update-notify doctor` 可强制只读刷新。 |
| `CHECK_EOL` | `1` | 发行版安全支持终止（EOL）提醒：已过 EOL 触发提醒，临近（90 天内）仅作信息展示。若已购买 Ubuntu ESM 等延长支持，可设 `0` 关闭。 |

待安装数量在阈值以内仍是信息项；达到 `PENDING_ALERT_DAYS` 后才转为风险告警。DNF 的高危子计数同时包含 `critical` 和 `important`。可随时用 `security-update-notify doctor` 查看七项检测、当前待装数量和 SUN 版本结果；诊断不会写入时长或版本缓存状态。`security-update-notify test` 的模拟模式和 `security-update-notify run --dry-run` 不写这些状态，也不会发起周期版本请求。

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

安装器会启用 unattended-upgrades 的安全更新周期任务。每次覆盖 `/etc/apt/apt.conf.d/20auto-upgrades` 前都会保存一份带时间戳的 SUN 专用备份；如果安装前已有该文件，首次安装还会固定保存原始基线；如果原本不存在，则在包管理器写入前记录一个受校验、可回滚的“原始缺失”标记。如果 SUN 本次安装的 `unattended-upgrades` 依赖包创建了发行版默认文件，SUN 会用内容绑定的 SHA-256 proof 确认来源，再把该文件提升为固定基线并移除缺失标记；因此 purge 保留依赖包和发行版 timer 时，也会恢复一份可用的 vendor 配置。部分依赖事务只在 proof 精确匹配当前文件时允许重试或 purge 保留它；proof 缺失、损坏或不匹配时会失败关闭并保留现场。若依赖包没有创建文件，原始缺失标记仍然有效，purge 会恢复为不存在。APT 目录内的标记、proof 和时间戳备份都以 `.bak` 结尾，避免 apt 对非配置文件输出扩展名提示；升级会迁移旧命名。`--purge-config` 最后会删除 SUN 的基线、标记、proof 及时间戳备份。

检测方式：

- `/var/run/reboot-required`
- `/var/run/reboot-required.pkgs`
- `needrestart -b`

### RHEL 兼容发行版 / Fedora (`dnf`)

`BACKEND` 对 DNF4 和 DNF5 都保持为稳定值 `dnf`，SUN 在内部识别实际代际。

DNF4（RHEL-compatible 8–10；生命周期在 Rocky/AlmaLinux 实测，以及尽力支持的 EL 衍生版）会配置或使用：

- `dnf-automatic`
- `yum-utils`（Amazon Linux 2023 使用实际包名 `dnf-utils`）
- `ca-certificates`
- EL10 极简系统还会显式安装 `dnf`，因为初始镜像可能只有 `microdnf`

DNF4 检测方式：

- `needs-restarting -r`（判断是否需要整机重启）
- `needs-restarting -s`（列出需要重启的 systemd 服务；不再用裸 `needs-restarting` 的整表进程，避免误报）
- `dnf -q updateinfo list security`

DNF5（Fedora 43/44）会使用 `dnf5-plugin-automatic`、`dnf5-plugins` 和 `ca-certificates`，并启用原生 `dnf5-automatic.timer`。该软件包还会安装独立的兼容名称 `dnf-automatic.timer`；若其原本已启用，SUN 会将它禁用，避免同一任务重复执行，安装失败则精确恢复原状态。运行时健康检查仍兼容两种 unit 名。DNF5 检测使用：

- `dnf -q advisory list --security --updates --json`
- `dnf -q check-upgrade --security`（正确处理有更新时的退出码 `100`）
- `dnf needs-restarting` 和 `dnf needs-restarting -s`

DNF5 的公告 JSON 会与实际可执行事务做交集，避免把仅有公告、但不适用于当前事务的包误报为可安装更新。SUN 另行清除普通 exclude 取得完整公告集合，并用单次查询选项 `--setopt=disable_excludes=*` 计算忽略 versionlock/exclude 的事务候选；两组差集用于发现被锁定、排除或事务约束阻塞的安全包。该查询不会改写 `/etc/dnf/versionlock.toml` 或持久 DNF 配置。

两代 DNF 都使用 `/etc/dnf/automatic.conf`。如果该文件存在，SUN 会在第一次管理时固定保存原始基线，每次覆盖前另存时间戳备份；如果原本缺失，缺失 marker 会明确记录 DNF4 或 DNF5 代际。DNF4 的 `dnf-automatic` 依赖包若在本次安装中创建了发行版默认配置，SUN 会把该依赖安装后的 vendor 文件固化为基线并移除“原始缺失”标记；因此 `--purge-config` 会恢复可用的 vendor 配置，而不会让保留且仍启用的发行版 timer 指向缺失文件。依赖事务若在创建 vendor 配置后失败，SUN 会留下与文件内容绑定的 SHA-256 证明；此时立即 purge 只在证明精确匹配当前文件时保留该配置并清理 SUN 元数据，证明损坏或不匹配则拒绝猜测并保留现场。升级带旧缺失标记的 DNF4 安装时，SUN 可从受校验的最早 SUN 时间戳备份迁移原始 vendor 配置，绝不会把当前受管配置误作基线。直接执行 purge 不会仅凭时间戳历史推断来源：DNF4 marker 与当前文件并存且没有固定基线或匹配当前内容的 proof 时，即使仍有时间戳备份也会失败关闭并保留现场。安装器只有在无法从受校验的最早时间戳或匹配 proof 建立可信基线时才会同样停止。如果 `dnf-automatic` 已显示为安装状态，但配置文件缺失且没有可信历史基线，安装器也会在启用 timer 前停止；需先 purge 本次未完成的 SUN 元数据，再重装该包或恢复可信 vendor 配置。DNF5 的配置路径由软件包声明为可缺失并有内置 vendor fallback；如果该文件原本不存在，SUN 保留受校验的缺失标记，purge 时恢复为不存在。普通卸载和随后重装不会改写固定基线；purge 最后会删除 SUN 的基线、标记及时间戳备份。

DNF4 软件包可能同时 preset `dnf-automatic.timer`、`dnf-automatic-notifyonly.timer`、`dnf-automatic-download.timer` 和 `dnf-automatic-install.timer`。SUN 安装成功后只保留主 `dnf-automatic.timer` 启用，并禁用其余三个互斥变体，避免同一套配置被多组 automatic job 并行执行；安装事务失败时会精确恢复四个 timer 的原状态。成功卸载不会猜测或重建安装前的变体组合，而是维持卸载当时所有发行版 timer 的状态。

```ini
upgrade_type = security
apply_updates = yes
reboot = never
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

切换接收平台、飞书应用或接收人时，请运行 `sudo security-update-notify configure notifications`。Go 安装器会验证 App ID 与应用级 `open_id` 的绑定，并负责创建、迁移或清理 App Secret 凭据；不要只手工修改 `NOTIFY_CHANNELS` 绕过这些步骤。

运行内置诊断：

```bash
security-update-notify --version
security-update-notify check-upgrade
sudo security-update-notify doctor
```

查看日志：

```bash
sudo tail -n 100 /var/log/security-update-notify.log
```

## 卸载

移除程序与 systemd/logrotate 集成，但保留配置和状态：

```bash
sudo security-update-notify uninstall
```

同时删除配置和状态：

```bash
sudo security-update-notify uninstall --purge-config
```

作为依赖安装的软件包会保留，不会自动卸载。`--purge-config` 会删除 SUN 的配置、Telegram/飞书凭据、状态、升级备份（其中可能含 bot token 副本）以及轮转日志，并在备份存在时恢复 apt/dnf 自动更新配置。卸载器不会改变发行版自身 automatic timer 的当前状态；它不会因为移除监控工具而主动关闭安全更新，也不会覆盖管理员之后对该 timer 的调整。

卸载器会对正常返回的并发变化失败关闭：它使用目录句柄、无覆盖 rename 和内容/元数据复验，并保留 `.security-update-notify-restore.*`、`.security-update-notify-purge.*` 或 `.security-update-notify-conflict.*` 现场，避免覆盖或删除管理员同时创建的文件。但 `--purge-config` 不承诺跨 SIGKILL、内核崩溃或掉电中间点的事务原子性；执行时不要强制终止。若 purge 异常中断，请先检查这些保留文件和当前 apt/dnf 配置，不要在未确认现场前反复重试。

## Release 签名

发布包始终包含 `.sha256` 校验文件。`go run ./cmd/sun-release package` 在可用时生成归档的 `.tar.gz.asc` 和引导器的 `sun.sh.asc` 两份 detached signature；后者还在签名 hashed 子包中写入关键的版本 notation。正式发布或已有对应 tag 时强制两份签名，并会在创建任何 `dist` 文件前拒绝显式 `--sign off`。`sun.sh` 默认以 `required` 模式校验下载的 Release，`auto` 仅作为兼容别名保留，也会要求 gpg 与归档 `.asc` 同时存在；只有显式传入 `--verify-signature off` 才会跳过 Release 签名校验。

根 `VERSION` 是唯一版本源，格式必须严格为 `VERSION="X.Y.Z"`。正式发布（存在对应 `vX.Y.Z` tag，或显式设置 `RELEASE=1`）**强制签名并固定包含五架构 Go 二进制**：Go 发布工具会绑定根版本、唯一 `CHANGELOG` 标题、tag、包内版本和每个二进制的 `--version`，且架构集合不可覆盖；缺少 Go、Bash（仅用于检查 `sun.sh` 语法）、任一 amd64/arm64/386/ppc64le/s390x 架构产物，或固定指纹对应的 GPG 私钥都会失败。正式 GitHub Release 的显式资产是 tarball、checksum、tarball signature 和 `sun.sh.asc`；无特权 release CI 提供前置纵深检查，默认分支上的镜像门禁再独立精确校验这四件资产，并把脚本签名同时绑定到验签归档中的 `sun.sh`、固定主密钥和明确版本。只有后者持有受 Environment 约束的部署能力。私钥不进入 CI，仍由维护者离线持有。此外，`security-update-notify upgrade` 默认 **fail-closed**：从固定发布镜像优先下载、GitHub 回退，校验 sha256，并在解包前用内置公钥与 pin 指纹强制校验 GPG 签名后才升级（应急可设 `SECURITY_UPDATE_NOTIFY_UPGRADE_ALLOW_UNSIGNED=1` 仅按 sha256 升级）。

## 安全说明

SUN 的范围刻意保持很小：

- 出站仅 HTTPS：提醒按配置发往 Telegram Bot API 和/或 `open.feishu.cn`；默认另向公网 IP 探测服务（api.ipify.org / ifconfig.me）获取出口 IP（`INCLUDE_PUBLIC_IP=0` 可关闭）；安装和自升级优先访问 `dl.ll.cd`，不可用时访问 GitHub。若要用出口防火墙收紧，请把这些目的地一并放行或关闭对应功能；
- 不接收远程命令；
- 不提供公开 HTTP 入口；
- 不自动重启；
- 普通通知配置仅 root 可读；飞书 App Secret 使用独立 systemd/root 凭据，不进入普通配置、命令行、日志或升级备份；
- 尽力支持的发行版必须显式开启。

发布包的 `.sha256` 文件可以防止下载损坏或版本不匹配；如果你的威胁模型包含发布源被攻破，请保持默认签名校验开启，不要使用 `--verify-signature off` 或无签名升级逃生选项。

归档签名认证 Release 内容；`sun.sh.asc` 则在任何首次执行之前认证引导器字节，并通过关键 notation 绑定其发布版本。便捷 `curl | bash` 不能利用后者，因为代码已先运行；高保障流程才把 fixed fingerprint 作为网络之外的初始信任锚。签名不证明“哪个版本是最新”，也不保护已被攻破的本机 root、`gpg` 或 shell，因此高保障流程要求管理员从独立可信渠道确认目标版本和指纹。

## 构建发布包

在源码目录运行：

```bash
bash -n sun.sh build/*.sh
shellcheck -s bash -S warning sun.sh build/*.sh
unformatted="$(rg --files cmd internal -g '*.go' -0 | xargs -0 gofmt -l)"
test -z "$unformatted"
go vet ./...
go test -race -cover ./...
build/archive-safety-test.sh
build/runtime-lock-test.sh
build/reproducibility-check.sh linux amd64
docker run --rm -e SUN_CONTAINER_TEST=1 -v "$PWD:/src:ro" debian:12 bash /src/build/compat-test.sh
docker run --rm -e SUN_CONTAINER_TEST=1 -v "$PWD:/src:ro" debian:12 bash /src/build/rollback-test.sh
go run ./cmd/sun-release package
cd dist && sha256sum -c security-update-notify-*.tar.gz.sha256
```

`build/compat-test.sh`、`build/rollback-test.sh`、`build/interactive-test.sh`、`build/rocky-bootstrap-test.sh` 和 `build/rpm-best-effort-test.sh` 会修改系统路径，只能在一次性 Docker 容器中运行，禁止直接在宿主机执行。正式发布还必须完成 CI 的五架构实跑、恶意归档、签名和公开资产复验门禁。

生成文件：

```text
dist/security-update-notify-VERSION.tar.gz
dist/security-update-notify-VERSION.tar.gz.sha256
dist/security-update-notify-VERSION.tar.gz.asc  # 签名构建
dist/sun.sh.asc                                  # 签名构建，高保障首次安装
```

发布压缩包只包含面向用户的安装、诊断、引导、迁移兼容和文档文件。`sun.sh` 包含在签名压缩包中；签名构建还在压缩包之外生成 `sun.sh.asc`，不会把不确定签名时间写入可复现归档。镜像工作流从验签归档提取脚本和公钥，与 detached signature 一起发布到不可变版本目录；兼容稳定 URL 仍只提供 `sun.sh`。`install.sh` 与 `files/security-update-notify` 是 Go 打包器为旧 2.x 自升级客户端生成的最小启动器和版本标记，不包含旧安装或运行时逻辑，也不会落到已安装系统。

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

## 许可证

MIT。详见 [LICENSE](LICENSE)。
