# security-update-notify — Bash → Go 端口设计与进度 / Bash→Go port design & status

本文件是全 Go 端口的活文档（single source of truth）。多智能体分析（inventory → 设计 → 对抗评审
→ 综合）的结论已固化于此，替代那次分析的临时输出。

This is the living design doc for the full Go port. It captures the conclusions of the multi-agent
analysis (inventory → design → adversarial critique → synthesis); the analysis's own output was ephemeral.

> **Current status (2.1.0):** the Go runtime, signed bridge distribution, self-upgrade path, and all original
> port phases are complete. Version 2.1.0 adds selectable Telegram/Feishu delivery, per-channel dedup state,
> Feishu diagnostics and upgrade notices, and configuration schema v3. The historical 2.0.0 release checklist
> remains below as design history, not as unfinished work.

## 诚实的底线 / Honest bottom line

“全 Go”是善意的误称：**~90–95% 的代码进 Go，但背后压着两个搬不走的事实。**

1. **引导信任根必须留在 shell。** `curl -fsSL https://sun.xxv.cc | sudo bash` 在任何可信二进制存在
   *之前*运行——编译产物不可能是被 `curl|bash` 的第一个东西，此刻也没有任何已装组件能验证它。所以
   `sun.sh` 必须继续承担下载和验证引导。它的**安全 TCB（fetch/sha256/指纹 pin/gpg 验签/安全解包）
   与桥发布时一致**，并负责按架构选择产物。脚本行数不是安全结论，关键是信任边界未扩大。
2. **`gpg` 与 OS “讲真话的命令” 仍是硬 `exec` 依赖。** needrestart / needs-restarting / apt / dpkg /
   dnf / rpm / systemctl / systemd-analyze / sudo / `hostname -f`（可能还有 `date -d`）无法在纯 Go 里
   忠实复刻——它们*就是*数据源。**“零依赖静态二进制”在 OS 边界上是假的。**

真正的收益是实的：**干掉 python3**（9 段内嵌全进 stdlib）、类型安全解析、单一静态二进制、可测试性。

## 已定决策 / Resolved decisions

- **签名方案：保持 GPG**（shim 与 Go 均 exec gpg）。迁 minisign/cosign“几乎全是成本”——废掉所有历史
  `.asc`、重写全部 CI 漂移守卫、丢掉 gpg 近乎全平台可用的优势，密码学收益约等于零。Ed25519 作为
  文档化的后续可选项。
- **切换时分发单元：版本化“桥” tarball**（内含 install.sh 与含 `VERSION=latest` 字节的运行时文件），
  让已装 Bash 机器的旧自升级链继续工作；不在切换点抛弃 noarch 语义。
- **install.sh / package.sh / sun.sh 主体：第一刀保持 shell**（特权、测试最全、收益近零）。
- **桥版本 2.0.0 已发布；当前演进版本为 2.1.0。** 2.1.0 在不改变桥信任链的前提下新增多通知渠道。
- **自升级：存活父进程做事务替换**（NOT rename-then-`syscall.Exec`）。

## Go 架构 / Architecture

单模块 `github.com/xxvcc/security-update-notify`，一个 `CGO_ENABLED=0` 静态二进制（`sun` 为别名）。

```
cmd/security-update-notify/   main → run()（后续 → cli.Main：旧 flag 翻译，裸调用永远 = run）
internal/
  version/    ✅ 语义化版本比较（fail-closed）——已从 PoC 迁入
  dist/       ✅ sha256 + pin 指纹 GPG 验签 + tar 安全检查（含解压上限）——已迁入
  golden/     ✅ 从真 Bash 运行时捕获的黄金向量（dedup hash + 归一化正文）——oracle
  config/     ✅ telegram.env 严格行解析器 + 逐字节复刻 writer（18 键白名单、schema v3、fail-open/closed 分裂）
  delivery/   ✅ Telegram / 飞书共同的渠道解析与发送接口；旧配置缺渠道时默认 Telegram
  feishu/     ✅ tenant token + 应用级 open_id 普通文本发送（rune 截断、3 次重试、限流信号）
  i18n/       ✅ UI_LANG / NOTIFY_LANG 解析（m/say 优先级），LC_ALL=C
  osrel/      ✅ os-release 解析 + 后端探测 + 支持分级（替代 lib.sh）
  backend/    ✅ needrestart -b 与 needs-restarting -r/-s 纯解析器（KCUR/KEXP/KSTA/SVC、文本优先 reboot
              判定、-s 能力探测）——单包合并 apt+dnf（原计划分两包，合并更便于共享 helper）
  watchdog/   ✅ 健康 / EOL / pending 纯逻辑（HEALTH_SIG 尾逗号、EOL 表与 ci.yml 一致）
  dedup/      ✅ 11 字段 sha256 + once/daily/interval + 原子状态写 + 渠道独立状态
  notify/     ✅ zh/en 消息模板 + format_restart_summary —— 8/8 golden message 逐字节通过
  telegram/   ✅ GetMe + SendMessage（net/http，rune 截断，3 次重试，只对 429/5xx 重试）—— 干掉 python3
  httpx/      ✅ 一个加固 http.Client（拒绝非 https 初始/跳转/最终 URL）—— 干掉 curl + urllib
  osrel/      ✅ os-release 解析 + AutoBackend（运行时语义）+ SupportTier（lib.sh 语义）
  sysexec/    ✅ exec 边界：子进程一律 LC_ALL=C；非零退出当数据不致命（镜像 set +e）
  systemd/    ✅ systemctl 查询封装（is-enabled / show -p PROP --value）
  lock/       ✅ flock 单实例锁（非阻塞，抢不到静默退 0）
  run/        ✅ Assemble + Collect + Execute；按渠道发送、部分失败隔离、doctor 与升级通知均支持双渠道
  cli/        ✅ 子命令分发 + 裸调用=run（--version/--test-*/--no-dedupe/--dry-run/--lang/--doctor/
              --check-upgrade/--notify-upgrade-event/--upgrade）
  dist/       ✅ sha256 + pin 指纹 GPG 验签 + tar 安全检查/解包（Extract 剥离 setuid）+ LatestRelease +
              Download（HTTPS-only 重试）+ VerifySHA256 + VerifyReleaseKey（内置公钥）—— 自升级信任链全套
  assets/     ✅ go:embed 公钥 + systemd 单元 + needrestart/logrotate + pin 指纹常量（CI 有 drift guard）
  run/        ✅ + SelfUpgrade（--upgrade：sudo 重执行 → 下载 → 验签(解包前) → 安全解包 → 版本绑定 →
              存活父进程运行 install.sh 完成替换；NOT rename-then-exec）+ Doctor + CheckUpgrade + NotifyUpgradeEvent
  installer/  ✅ 保持 shell：install/uninstall/menu/test；2.1.0 增加飞书自动选人与独立 credential 生命周期
build/        ✅ 可复现交叉编译（build.sh）+ 双构建 sha256 门（reproducibility-check.sh）+ 黄金捕获
sun.sh        ✅ 保持 shell 引导器；下载、sha256、指纹 pin、GPG 验签与安全解包信任边界不变
```

✅ 完成

## 兼容清单（必须逐字节复刻）/ Compat checklist — MUST reproduce exactly

升级兼容的成败点。任何一条错，已装机器升级后就会重复告警、丢配置或破坏回滚。

- **去重 `alert_hash`**：sha256 over 恰好 11 个字段，顺序 `HOST, BACKEND, NOTIFY_LANG,
  reboot_required, reboot_pkgs, restart_attention, restart_signal, HEALTH_ATTENTION, HEALTH_SIG,
  EOL_ATTENTION, EOL_SIG`，每个后跟一个 `\n`，**末尾也有 `\n`**；输出取 `sha256sum` 首个空白字段（小写十六进制）。
- **apt `restart_signal` 无末尾换行**（命令替换包裹，见 files/security-update-notify:897）：构造
  KCUR/KEXP/KSTA/svc 的 printf 成形字符串后 `TrimRight` 掉换行；空 SVC 时无双换行。**dnf `restart_signal`
  = `sort -u` 后的服务列表本身，无成帧、无末尾换行。**
- **`HOST` = `hostname -f`（再 `hostname`，再 `unknown`）——必须 EXEC**；`os.Hostname()` 返回短名，会
  悄悄改掉每台 FQDN 主机的 hash。
- **`HEALTH_SIG`** = `sort -u` 的 reason token（disabled/failed/stale/never-success/disk）逗号连接
  **带尾逗号**，无则空。**`reboot_pkgs`** = `sort -u` 换行连接，**无尾换行**。SVC 列表：`sort.Strings`
  （= C locale 字节序）+ 去重；子进程一律 `LC_ALL=C`。
- **状态回读 `TrimRight` 掉所有尾换行**（Bash `cat` 捕获）；否则每次运行都重发。`last-alert.sha256` =
  64hex+换行，`last-alert.sent_at` = epoch+换行；`STATE_DIR` 0750；临时文件 + rename 原子写，**hash 先于
  时间戳** rename；直写回退显式 0600。
- **telegram.env 线格式**（文件名为兼容历史保留）：18 键固定写序、两行双语头注释、`config_quote`
  （默认单引号，值含单引号才用双引号，**绝不反斜杠转义**；校验禁止同时含两种引号），强制
  `CONFIG_VERSION=3`，旧配置缺 `NOTIFY_CHANNELS` 时按 `telegram`，`DEDUP_MODE` always→once。
  **不要用 `strconv.Quote`/`%q`/JSON**。文件 0600。
- **配置读取“致命 vs 非致命”分裂**：文件不可读 → 继续（fail-open）；行无 `=` / 键正则不符 / 非白名单键 →
  exit 2（fail-closed）。`NOTIFY_LANG` 归一化为精确 zh/en，否则 zh（hash 字段 3 + 消息语言）。
- **按键真值不对称**：`INCLUDE_PUBLIC_IP`/`CHECK_UPDATE_HEALTH`/`CHECK_EOL` 接受 `1/true/yes/on`（小写化）；
  `NOTIFY_OK` 与 `NOTIFY_UPGRADE` 用 **精确 `==1`**。不要统一成一个 bool 解析器。
- **Telegram**：token 正则 `^\d+:[A-Za-z0-9_-]+$`；4096 截断按 **rune**（`RuneCountInString` → 取前 4000
  rune + `\n…(truncated)`），非字节长度；表单 `chat_id/text/disable_web_page_preview=true`；3 次尝试间隔
  1s；**仅**对 ok=false-break 或 HTTP 429/500/502/503/504 重试。
- **飞书**：App Secret 只从隐藏输入、systemd credential 或已验证的 root-only 普通文件进入内存；运行时
  使用应用级 `open_id` 单发普通文本。交互安装的 Directory v1 结果只用于人选确认，扫描范围受应用通讯录
  数据范围限制；更换 App ID 必须重新选择或显式提供接收人，禁止复用旧应用的 `open_id`。
- **needs-restarting reboot 判定优先级**：文本 `reboot is required` → 需要；否则
  `reboot should not be necessary|no core libraries` → 不需要；**仅当**上面都不匹配时 `rc==1` → 需要；
  其它非零 rc **不是** reboot 信号。needrestart：任一 `NEEDRESTART-SVC:` 行即触发 attention（`HasPrefix`
  bool，与用于信号的 SVC 值解耦）；KSTA∈{2,3} 或 KCUR≠KEXP 触发；KSTA=0/SESS/AUX **不**触发。
- **restart_summary 两种换行制**：apt 携带**真换行**（原始 needrestart -b），dnf 携带**字面 `\n`**；两者都过
  一次 `\n`→换行 的替换。保留谁携带哪种。
- **退出码**：`0` = 成功/无关注/silent-ok/去重抑制/--version/--help/--check-upgrade/--notify-upgrade-event/
  锁竞争/非更新；`1` = 任一已配置渠道发送失败/doctor 问题/自升级失败；`2` = 参数/配置错误/发送时缺渠道
  凭据/不支持后端/缺 flag 值。**裸调用 = run FOREVER**（旧 systemd 单元裸调用二进制直到 daemon-reload）。
- **信任链**：pin 指纹 `C678256ACBFC6491BF5076655F3AE24999921FFC`（不可被环境变量覆盖）；验签在解包之前；
  安全解包拒绝绝对路径 / 任何 `..` 段 / 顶层目录之外条目 / 非普通-非目录条目；解包 `--no-same-owner
  --no-same-permissions`；gpg 存在时签名强制（缺 .asc 即拒）；sha256-only 仅当 gpg 确实缺失且显式
  `SECURITY_UPDATE_NOTIFY_UPGRADE_ALLOW_UNSIGNED=1`；每次网络调用 HTTPS-only（拒绝非 https 初始 URL、
  跳转、最终 URL）。已在 PoC 的 archive.go 收敛 `path.Clean` 宽松点并加解压上限。
- **兼容桥**：切换版必须仍发一个版本化 tarball，内含 install.sh 与字节含 `VERSION=latest` 的运行时文件，
  让已装 Bash 机器的 `run_self_upgrade`（tarball 拉取 + 顶层目录 pin + VERSION 抓取）继续工作。

## 分阶段计划与进度 / Phased plan & status

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| **P0** CI/可复现地基 | 根模块 + 固定工具链；go 门（fmt/vet/race/交叉编译矩阵/双构建 sha256）；黄金向量捕获 | ✅ **完成** |
| **P1** 纯逻辑核心进 Go | version/config/dedup/i18n/notify/telegram/httpx/osrel/backend + bash↔Go 差分 oracle | ✅ **完成** |
| **P2** Go run 路径 + 桥 + 兼容测试 | cli/watchdog/systemd/flock/原子写；桥 tarball（per-arch Go 二进制 + bash 兜底）；bash→Go 升级兼容测试 | ✅ **完成**：run/doctor/check-upgrade/notify-upgrade 全部移植；package.sh 构建全 5 架构（amd64/arm64/386/ppc64le/s390x）Go 二进制入包（tarball 可复现），install.sh 按架构择二进制（缺失回退 bash）；真实容器兼容测试通过（配置/token/状态保留、不重复告警） |
| **P3** 切 latest + 自升级 | 翻正式版；port dist 自升级（存活父进程事务替换）、签名 manifest 绑定、双向不降级 | ✅ **完成并发布** |
| **P4** shell 安装面保持 | install.sh/uninstall/menu/test + package.sh | ✅ **有意保持 shell**：特权安装面测试充分，桥已负责安装 Go 二进制；2.1.0 继续在该边界加入飞书 onboarding 与 credential 管理 |

## 2.0.0 桥发布历史清单 / Historical 2.0.0 bridge release checklist

以下步骤已完成，保留用于解释 2.0.0 的发布设计与信任链：

1. `files/security-update-notify` 里 `VERSION="2.0.0"` + CHANGELOG 加 `## 2.0.0` 段（说明改为 Go 运行时、
   保留 bash 兜底、桥升级不重复告警）；提交 `release: v2.0.0`。
2. 打注解 tag `v2.0.0`，推 main + tag。
3. `./package.sh`：自动构建全 5 架构（amd64/arm64/386/ppc64le/s390x）Go 二进制入包、生成可复现
   tarball + `.sha256` + `.asc`（用 [[release-process]] 里的签名密钥）。桥 tarball 同时含 bash 运行时
   （供旧机自升级的版本绑定 + 未列架构兜底）。可用 `GO_BRIDGE_ARCHES="..."` 增删架构集。
4. **先发 prerelease**（不动 `latest`）做 canary：手动在一台机器 `--upgrade`，观察不重复告警；跑
   `build/compat-test.sh` 容器测试。CI 的 `verify-signed-release` 会校验签名。
5. canary 通过后再 publish 正式 release，移动 `latest`——已装 bash 机器（1.9.x）会自升级进桥、无缝换成
   Go 二进制。orphan 架构（不在 GO_BRIDGE_ARCHES）自动落 bash 兜底，绝不断链。

**架构集**：默认全 5 架构（amd64/arm64/386/ppc64le/s390x），覆盖 Go 常规 linux 目标；更冷门的（armv7/
riscv64 等）自动落 bash 运行时兜底，绝不断链。需要增删用 `GO_BRIDGE_ARCHES` 覆盖。

**P0 交付物（已验证）**：`go build/vet/test -race` 全绿；`build/reproducibility-check.sh` 证明同工具链
双构建 sha256 逐字节相等；5 架构（amd64/arm64/386/ppc64le/s390x）交叉编译通过；8 条确定性黄金向量
（apt/dnf × test-reboot/服务/健康/ok，含 HEALTH_SIG 尾逗号与 apt restart_signal 无尾换行两个 landmine），
`internal/golden` 守卫测试常绿。
