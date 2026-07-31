# 安装与升级

[English](installation.en.md) | [返回 README](../README.md)

本页面向安装和自动化部署 SUN 的管理员，包含通知平台准备、高保障首次安装、便捷安装、非交互参数、验证和升级。

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

下面的流程不会把网络响应直接交给 shell。请先从可信发布公告确认要安装的明确版本，把 `X.Y.Z` 改成该版本；它在 root 自有临时目录中下载版本化 `sun.sh`、detached signature 和公钥，核对固定主密钥指纹及签名内的关键版本 notation，并且只有全部验证成功后才执行脚本。机器必须预先具有 `bash`、`curl`、`python3` 和 `gpg`；请先通过发行版的软件包管理器或可信离线介质补齐它们。

```bash
sudo /bin/bash -p <<'SUN_ROOT'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

SUN_VERSION='X.Y.Z' # 必须改为从可信发布公告确认的明确版本
SUN_PIN='C678256ACBFC6491BF5076655F3AE24999921FFC'
SUN_NOTATION='release-version@xxv.cc'
[[ "$SUN_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([._-][0-9A-Za-z]+)?$ \
   && "${#SUN_VERSION}" -le 64 ]] || {
  echo '请先把 SUN_VERSION 中的 X.Y.Z 替换为从可信发布公告确认的明确版本。' >&2
  exit 2
}

SUN_BASE="https://dl.ll.cd/security-update-notify/v${SUN_VERSION}"
SUN_WORK="$(mktemp -d /tmp/security-update-notify.XXXXXX)"
trap 'rm -rf "$SUN_WORK"' EXIT
chmod 0700 "$SUN_WORK"
mkdir "$SUN_WORK/gnupg"
chmod 0700 "$SUN_WORK/gnupg"

download_limited() {
  local asset="$1" output part
  output="$SUN_WORK/$asset"
  part="${output}.part"
  rm -f -- "$part"
  if curl --disable --fail --silent --show-error --location \
      --proto '=https' --proto-redir '=https' \
      --connect-timeout 20 --retry 4 --retry-delay 1 --retry-max-time 180 \
      --max-time 180 --max-filesize 1048576 "$SUN_BASE/$asset" |
      python3 -I -c '
import os
import sys

limit = 1048576
path = sys.argv[1]
try:
    with open(path, "xb") as output:
        remaining = limit
        while True:
            chunk = sys.stdin.buffer.read(min(65536, remaining + 1))
            if not chunk:
                break
            if len(chunk) > remaining:
                raise ValueError("download exceeds size limit")
            output.write(chunk)
            remaining -= len(chunk)
except Exception:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    raise SystemExit(1)
' "$part"; then
    if mv -f -- "$part" "$output"; then
      return 0
    fi
  fi
  rm -f -- "$part"
  return 1
}

for asset in sun.sh sun.sh.asc release-signing.pub.asc; do
  download_limited "$asset"
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
good_count=0
outcome_count=0
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
    GOODSIG)
      outcome_count=$((outcome_count + 1))
      good_count=$((good_count + 1))
      ;;
    EXPSIG|EXPKEYSIG|REVKEYSIG|BADSIG|ERRSIG)
      outcome_count=$((outcome_count + 1))
      ;;
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
[[ "$outcome_count" -eq 1 && "$good_count" -eq 1 \
   && "$valid_count" -eq 1 && "$pinned_count" -eq 1 \
   && "$name_count" -eq 1 && "$name_match" -eq 1 \
   && "$flags_count" -eq 1 && "$flags_match" -eq 1 \
   && "$data_count" -eq 1 && "$data_match" -eq 1 ]] || {
  echo '引导器签名未唯一绑定固定指纹和目标版本；拒绝执行。' >&2
  exit 1
}

chmod 0700 "$SUN_WORK/sun.sh"
/bin/bash -p "$SUN_WORK/sun.sh" --version "$SUN_VERSION" --base-url "$SUN_BASE"
SUN_ROOT
```

使用明确版本是这条路径的一部分：`latest.json` 是可用性索引，不是签名的版本新鲜度证明。`sun.sh.asc` 的 hashed 子包包含关键 notation `release-version@xxv.cc=<版本>`；验签既核对脚本字节，也要求该值与人工确认的版本完全一致，因此旧版合法脚本和签名不能被搬到新版本目录冒充。版本目录中的 `sun.sh`、`sun.sh.asc` 和公钥只有在镜像工作流验签发布归档、核对 tag 源码并从公网回读复验后才会出现；公钥文件本身仍不是信任根，命令中固定且应从独立可信渠道核对的指纹才是。

#### 便捷一行安装（兼容入口）

网站引导器会下载最新签名 Release、校验 `.sha256` 与 GPG 签名（默认必须通过），然后启动交互式菜单：

```bash
set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p
```

这条命令保持原有体验，但 `curl` 下载的 `sun.sh` 会在自身被 detached signature 验证之前执行，因此首次引导脚本的信任依赖 HTTPS、域名和镜像/CDN；脚本随后对 Release 的校验不能追溯认证已经运行的第一阶段。威胁模型包含下载站或 TLS 终点失陷时，请使用上面的高保障流程。

从网址启动引导器时，机器必须预先装有 `curl`，因为脚本尚未取得前不可能自行补装它。`set -o pipefail` 让缺少 `curl`、DNS/TLS 或下载失败成为整条管道的非零退出，而不是让末端 Bash 读取空输入后误报成功。文档入口强制使用 `/bin/bash -p`，使 Bash 在读取引导器前忽略 `BASH_ENV` 和导出的 Shell 函数；脚本随后以固定 `PATH`/`LC_ALL`、经过 `zh|en` 校验的界面语言、终端、时区和大小写代理变量重建特权子进程环境，调用方的别名、动态链接器、Python、包管理器及 systemd/Git 环境覆盖不会继续传入。脚本运行后需要 `curl`、`tar`、`sha256sum`、`mktemp`、`python3`、`env`、`uname`、`gpg`、`timeout` 和 `wc`；缺少命令时只通过 apt、dnf、microdnf 或 yum 安装对应的软件包，再逐项复查，避免在 RPM 极简系统上用完整 `curl/coreutils` 替换已安装的 `curl-minimal/coreutils-single`。没有受支持的包管理器或补齐后仍缺命令时会在下载/安装前失败。Release 的 GPG 签名默认强制校验。

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

- Telegram：使用 `getMe` 验证 Bot Token，并用 `sendMessage` 验证 Chat ID 与权限；只读 `getMe` 会对连接重置、超时、HTTP 408、429 和 5xx 最多尝试三次，429 会遵循最长 30 秒的服务端 `retry_after`。为避免重复消息，`sendMessage` 只在服务端明确返回 HTTP 429 时重试；传输错误、HTTP 408、5xx 和响应中断作为临时失败返回，但不立即重发。持续的临时网络故障不会被误报为 Token 无效，也不会清空旧凭据；交互模式可重试、跳过本次预检或中止，非交互模式以退出码 `75` 失败并回滚；
- 飞书：获取 `tenant_access_token` 后扫描应用通讯录范围内的在职员工；如已显式提供 `open_id`，则只验证应用凭据。Token 和通讯录等可安全重复的请求会有界重试 HTTP 408/429/5xx；消息 POST 遇到 HTTP 408 或 5xx 只返回临时失败，不立即重发。安装预检不会发送消息。

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
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p -s -- install \
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
  sudo /bin/bash -p -s -- install --env-file "$PWD/.env" --non-interactive -y
```

也可以只把 token 单独放进 root-only 文件：

```bash
sudo install -m 600 /dev/null /root/.security-update-notify-token
sudoedit /root/.security-update-notify-token

set -o pipefail
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p -s -- install \
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
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p -s -- install \
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
curl -fsSL https://dl.ll.cd/security-update-notify/sun.sh | sudo /bin/bash -p -s -- upgrade --non-interactive -y
```

已安装 SUN 后，也可以直接运行 `sudo security-update-notify upgrade`。一键安装器和内置升级都会优先读取 `https://dl.ll.cd/security-update-notify/latest.json` 并从同一镜像下载签名资产；镜像索引或完整资产集合传输失败时自动回退 GitHub。下载完成后仍会校验 `.sha256`，并用内置 pin 的指纹强制校验 GPG 签名（默认 fail-closed，缺签名即拒绝）后才升级。镜像只提供传输可用性，不是信任根。

如果已安装过 SUN，安装器会自动读取 `/etc/security-update-notify/telegram.env` 和现有 timer 时间，并复用未显式覆盖的设置。运行 `sudo security-update-notify configure notifications` 可以事务化更改接收平台、Telegram 配置、飞书应用、App Secret 或接收人。移除接收平台会删除其保存凭据，新增或修改只重复验证受影响的平台；任一步失败都会随安装事务回滚。旧配置没有 `NOTIFY_CHANNELS` 时自动按 `telegram` 处理，未显式覆盖的其他选项继续沿用。

升级前会备份关键文件到 `/var/backups/security-update-notify/<timestamp>`，但飞书 App Secret 不进入该备份；升级失败会尝试自动回滚，并恢复 SUN timer 安装前的启用链接与 active 状态。升级后默认运行自检；可用 `--notify-upgrade 1` 向已配置接收平台发送升级通知。升级通知采用 best-effort 语义，不会因通知失败回滚已经完成的升级，也不会整体重试双发而重复已成功平台。

## 相关文档

- [日常运维与恢复](operations.md)
- [安全与信任模型](security.md)
