#!/usr/bin/env bash
set -euo pipefail
# build/golden/capture.sh — 用“真·Bash 运行时”产出黄金向量（known-answer vectors）。
#
# 为什么：去重 alert_hash 是对 11 个原始字节成帧字段做 sha256，任何一字节漂移都会让每台已装机器
# 在升级后重复告警一次。这是全 Go 端口的 make-or-break 门。此脚本在受控场景下驱动真实的
# files/security-update-notify（用命令桩喂固定的 needrestart/needs-restarting 输出、固定环境、
# 关看门狗噪声），记录：
#   - hash：运行后写入 STATE_FILE 的 alert_hash（端到端 oracle）
#   - message：捕获的 Telegram 正文（把易变行 OS/内核/时间/公网IP 归一化为占位符）
# Phase 1/2 的 Go 实现必须逐字节复刻同一 hash 与（归一化后的）message，否则视为回归。
#
# Why: the dedup alert_hash is sha256 over 11 raw byte-framed fields; a one-byte drift re-alerts every
# installed host once on upgrade — the make-or-break gate of the port. This drives the REAL runtime under
# controlled scenarios (command stubs feeding fixed needrestart/needs-restarting output, fixed env,
# watchdog noise off) and records the end-to-end hash from STATE_FILE plus the captured Telegram body
# (volatile OS/kernel/time/public-IP lines normalized to placeholders). The Go port must reproduce both.
#
# 输出 / Output: testdata/golden/scenarios.json

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# 黄金向量与其 Go 加载包同居，便于 go:embed（embed 无法引用包目录之外的文件）。
# The golden vectors live with their Go loader package so go:embed can reach them.
OUT_DIR="$ROOT/internal/golden/testdata"
RUNTIME="$ROOT/files/security-update-notify"
mkdir -p "$OUT_DIR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 归一化后的运行时副本：把状态/锁/日志路径重定向到临时目录。
bin_runtime="$WORK/security-update-notify"
cp "$RUNTIME" "$bin_runtime"
sed -i \
  -e "s|^STATE_DIR=.*|STATE_DIR=\"$WORK/state\"|" \
  -e "s|^LOCK_FILE=.*|LOCK_FILE=\"$WORK/lock\"|" \
  -e "s|^LOG_FILE=.*|LOG_FILE=\"$WORK/log\"|" \
  -e "s|/var/run/reboot-required|$WORK/rr|g" \
  "$bin_runtime"
# 隔离 apt 的 /var/run/reboot-required（宿主机状态，会污染 reboot_required/reboot_pkgs 两个 hash 字段，
# 使黄金向量在有该文件的机器与干净 CI runner 之间漂移）。默认不创建 -> reboot_required=0。
# Isolate apt's /var/run/reboot-required (host state that pollutes the hashed reboot_required/reboot_pkgs
# fields and would drift the golden between a host that has it and a clean CI runner). Absent by default.
chmod +x "$bin_runtime"

# ---- 命令桩 / command stubs ------------------------------------------------
stub="$WORK/bin"; mkdir -p "$stub"

# python3：捕获 sendMessage 的第 3 个 null 分隔字段（正文）到 $CAPTURE，返回 ok:true。
cat >"$stub/python3" <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/python3 -c 'import os, sys
payload = sys.stdin.buffer.read().split(b"\0", 2)
text = payload[2].decode("utf-8", "replace") if len(payload) > 2 else ""
cap = os.environ.get("CAPTURE")
if cap:
    open(cap, "w", encoding="utf-8").write(text)
print("{\"ok\": true}")
'
EOF

# needrestart -b：输出 $NR_B（apt 服务/内核场景）。
cat >"$stub/needrestart" <<'EOF'
#!/usr/bin/env bash
[[ -n "${NR_B:-}" ]] && printf '%s\n' "$NR_B"
exit 0
EOF

# needs-restarting -r/-s（dnf 场景），--help 声明支持 -s。
cat >"$stub/needs-restarting" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  --help) echo '  -r, --reboothint'; echo '  -s, --services'; exit 0 ;;
  -r) [[ -n "${NR_R_OUT:-}" ]] && printf '%s\n' "$NR_R_OUT"; exit "${NR_R_RC:-0}" ;;
  -s) [[ -n "${NR_S_OUT:-}" ]] && printf '%s\n' "$NR_S_OUT"; exit 0 ;;
  *)  exit 0 ;;
esac
EOF

# apt-get / dnf：collect_security_updates 会调用；置空以确定性地得到 0 个待装更新。
printf '#!/usr/bin/env bash\nexit 0\n' >"$stub/apt-get"
printf '#!/usr/bin/env bash\nexit 0\n' >"$stub/dnf"

# systemctl：看门狗健康检查。SYS_ENABLED 控制 is-enabled 退出码；show 一律空。
cat >"$stub/systemctl" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  is-enabled) exit "${SYS_ENABLED:-0}" ;;
  show) exit 0 ;;
  *) exit 0 ;;
esac
EOF

# df：看门狗磁盘检查；恒报充足空间（避免本机磁盘状态污染 HEALTH_SIG）。
cat >"$stub/df" <<'EOF'
#!/usr/bin/env bash
echo "Filesystem 1K-blocks Used Available Use% Mounted"
echo "/dev/x 100000000 1000000 99000000 2% /"
EOF

chmod +x "$stub"/*

# ---- 场景运行器 / scenario runner -----------------------------------------
# 归一化易变行：系统/OS、当前内核/Current kernel、时间/Time 归一化为占位符，使 message 稳定。
normalize() {
  sed -E \
    -e 's/^(系统：|OS: ).*/\1<OS>/' \
    -e 's/^(当前内核：|Current kernel: ).*/\1<KERNEL>/' \
    -e 's/^(时间：|Time: ).*/\1<NOW>/'
}

VECTORS="[]"
run_scenario() {
  local name="$1" flag="$2"; shift 2
  # 其余参数是 KEY=VALUE 形式的环境（含 env 文件键与桩控制变量）。
  local envfile="$WORK/env" cap="$WORK/cap.msg"
  : >"$envfile"; rm -f "$cap" "$WORK/state/last-alert.sha256" 2>/dev/null || true
  local -a runenv=()
  local kv
  for kv in "$@"; do
    case "$kv" in
      NR_B=*|NR_R_OUT=*|NR_R_RC=*|NR_S_OUT=*|SYS_ENABLED=*|CHECK_UPDATE_HEALTH=*|CHECK_EOL=*|STALE_UPDATE_DAYS=*)
        runenv+=("$kv") ;;                       # 传给进程的桩/开关
      *) printf '%s\n' "$kv" >>"$envfile" ;;     # 写入 env 文件（配置键）
    esac
  done
  # flag=="run" 表示普通检查（Bash 运行时无  run 子命令，裸调用即运行）。
  local -a flagarg=()
  [[ "$flag" != run ]] && flagarg+=("$flag")
  PATH="$stub:$PATH" CAPTURE="$cap" SECURITY_UPDATE_NOTIFY_ENV="$envfile" \
    env "${runenv[@]}" "$bin_runtime" "${flagarg[@]}" --no-dedupe >/dev/null 2>&1 || true
  local hash="" msg=""
  [[ -f "$WORK/state/last-alert.sha256" ]] && hash="$(tr -d '\n' <"$WORK/state/last-alert.sha256")"
  [[ -f "$cap" ]] && msg="$(normalize <"$cap")"
  VECTORS="$(HASH="$hash" MSG="$msg" NAME="$name" python3 - "$VECTORS" <<'PY'
import json, os, sys
v = json.loads(sys.argv[1])
v.append({"name": os.environ["NAME"], "hash": os.environ["HASH"], "message": os.environ["MSG"]})
print(json.dumps(v))
PY
)"
  printf '  %-28s hash=%s\n' "$name" "${hash:-<none>}"
}

# 通用确定性基线：固定主机名、关公网 IP、关看门狗噪声。
BASE_APT=(TELEGRAM_BOT_TOKEN=fake TELEGRAM_CHAT_ID=fake HOST_LABEL=golden-host INCLUDE_PUBLIC_IP=0 BACKEND=apt NOTIFY_LANG=zh CHECK_UPDATE_HEALTH=0 CHECK_EOL=0 STALE_UPDATE_DAYS=0)
BASE_DNF=(TELEGRAM_BOT_TOKEN=fake TELEGRAM_CHAT_ID=fake HOST_LABEL=golden-host INCLUDE_PUBLIC_IP=0 BACKEND=dnf NOTIFY_LANG=zh CHECK_UPDATE_HEALTH=0 CHECK_EOL=0 STALE_UPDATE_DAYS=0)

echo "capturing golden vectors:"

# 1) apt --test-reboot（内置固定摘要，全确定）zh & en
run_scenario apt-test-reboot-zh --test-reboot "${BASE_APT[@]}"
run_scenario apt-test-reboot-en --test-reboot "${BASE_APT[@]/NOTIFY_LANG=zh/NOTIFY_LANG=en}"

# 2) dnf --test-reboot zh & en
run_scenario dnf-test-reboot-zh --test-reboot "${BASE_DNF[@]}"
run_scenario dnf-test-reboot-en --test-reboot "${BASE_DNF[@]/NOTIFY_LANG=zh/NOTIFY_LANG=en}"

# 3) apt needrestart 服务场景（KCUR!=KEXP + SVC），命中 restart_signal 成帧路径
NR_B_SVC=$'NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.1.0-43-amd64\nNEEDRESTART-KEXP: 6.1.0-44-amd64\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: ssh.service'
run_scenario apt-needrestart-svc-zh  run "${BASE_APT[@]}" "NR_B=$NR_B_SVC"

# 4) dnf 服务场景（needs-restarting -s 两个服务，reboot 不需要）
run_scenario dnf-services-zh  run "${BASE_DNF[@]}" 'NR_R_OUT=Reboot should not be necessary.' NR_R_RC=0 $'NR_S_OUT=sshd.service\ncrond.service'

# 5) 看门狗：定时器未启用 -> HEALTH_SIG="disabled,"（锁定尾逗号 landmine）；apt，无重启
run_scenario apt-health-disabled-zh  run \
  TELEGRAM_BOT_TOKEN=fake TELEGRAM_CHAT_ID=fake HOST_LABEL=golden-host INCLUDE_PUBLIC_IP=0 BACKEND=apt NOTIFY_LANG=zh \
  CHECK_UPDATE_HEALTH=1 CHECK_EOL=0 STALE_UPDATE_DAYS=0 SYS_ENABLED=1 NR_B=''

# 6) ok 路径（无关注 + NOTIFY_OK=1），带公网 IP，dnf
run_scenario dnf-ok-pubip-zh --test-ok \
  TELEGRAM_BOT_TOKEN=fake TELEGRAM_CHAT_ID=fake HOST_LABEL=golden-host BACKEND=dnf NOTIFY_LANG=zh \
  NOTIFY_OK=1 INCLUDE_PUBLIC_IP=1 PUBLIC_IP=203.0.113.10 CHECK_UPDATE_HEALTH=0 CHECK_EOL=0 STALE_UPDATE_DAYS=0 \
  'NR_R_OUT=Reboot should not be necessary.' NR_R_RC=0 NR_S_OUT=''

printf '%s' "$VECTORS" | python3 -m json.tool >"$OUT_DIR/scenarios.json"
echo "wrote $OUT_DIR/scenarios.json ($(python3 -c 'import json;print(len(json.load(open("'"$OUT_DIR"'/scenarios.json"))))') vectors)"
