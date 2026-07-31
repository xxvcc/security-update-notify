#!/usr/bin/env bash
# Production-entrypoint lock contract for the compiled Go runtime.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

GO_RUNTIME="$TMP/security-update-notify-go"
"$ROOT/build/build.sh" linux amd64 lock-test "$GO_RUNTIME"
RUNTIMES=("$GO_RUNTIME")

cat >"$TMP/valid.env" <<'EOF'
CONFIG_VERSION=3
NOTIFY_CHANNELS=telegram
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
NOTIFY_LANG=en
BACKEND=apt
INCLUDE_PUBLIC_IP=0
CHECK_UPDATE_HEALTH=0
STALE_UPDATE_DAYS=0
CHECK_EOL=0
CHECK_SELF_UPDATE=0
EOF
chmod 0600 "$TMP/valid.env"

LOCK_FILE="$TMP/runtime.lock"
STATE_DIR="$TMP/state"
LOG_FILE="$TMP/runtime.log"
mkdir -p "$STATE_DIR"
LAST_RC=0

run_runtime() {
  local runtime="$1" config="$2" out="$3"
  shift 3
  set +e
  SECURITY_UPDATE_NOTIFY_ENV="$config" \
    SECURITY_UPDATE_NOTIFY_STATE_DIR="$STATE_DIR" \
    SECURITY_UPDATE_NOTIFY_LOCK_FILE="$LOCK_FILE" \
    SECURITY_UPDATE_NOTIFY_LOG_FILE="$LOG_FILE" \
    UI_LANG=en \
    "$runtime" "$@" >"$out" 2>&1
  LAST_RC=$?
  set -e
}

expect_rc() {
  local label="$1" expected="$2"
  if [[ "$LAST_RC" -ne "$expected" ]]; then
    echo "$label: exit $LAST_RC, expected $expected" >&2
    return 1
  fi
}

for runtime in "${RUNTIMES[@]}"; do
  name="$(basename "$runtime")"
  for invalid_wait in '' 00001 +1 -0 3601 9999 1s; do
    run_runtime "$runtime" "$TMP/missing.env" "$TMP/$name-invalid.out" --wait-lock "$invalid_wait" --doctor --skip-notify
    expect_rc "$name invalid --wait-lock [$invalid_wait]" 2
  done
done

exec 8>"$LOCK_FILE"
flock -n 8
run_runtime "$GO_RUNTIME" "$TMP/valid.env" "$TMP/go-dry-run.out" --test-ok --dry-run --wait-lock 0
expect_rc "Go dry-run remains lock-free under contention" 0
grep -q $'^HASH\t' "$TMP/go-dry-run.out"
run_runtime "$GO_RUNTIME" "$TMP/missing.env" "$TMP/go-doctor-dry-run.out" --doctor --dry-run --skip-notify --wait-lock 0
expect_rc "Go doctor keeps lock precedence over --dry-run" 75
for runtime in "${RUNTIMES[@]}"; do
  name="$(basename "$runtime")"
  run_runtime "$runtime" "$TMP/missing.env" "$TMP/$name-doctor.out" --doctor --skip-notify --wait-lock 0
  expect_rc "$name contended doctor" 75
  run_runtime "$runtime" "$TMP/missing.env" "$TMP/$name-notice.out" \
    --notify-upgrade-event --upgrade-from 2.2.0 --upgrade-to 2.2.1 --wait-lock 0
  expect_rc "$name contended upgrade notice" 75
  run_runtime "$runtime" "$TMP/missing.env" "$TMP/$name-run.out" --test-ok --wait-lock 0
  expect_rc "$name contended normal run" 75
  run_runtime "$runtime" "$TMP/missing.env" "$TMP/$name-default.out" --doctor --skip-notify
  expect_rc "$name default contention precedence" 0
done
flock -u 8
exec 8>&-

bad_lock="$TMP/missing-parent/runtime.lock"
LOCK_FILE="$bad_lock"
for runtime in "${RUNTIMES[@]}"; do
  name="$(basename "$runtime")"
  run_runtime "$runtime" "$TMP/valid.env" "$TMP/$name-lock-open-wait.out" --doctor --skip-notify --wait-lock 0
  expect_rc "$name explicit lock-open failure" 1
  grep -Eiq 'lock (file|error)|运行锁' "$TMP/$name-lock-open-wait.out"
  run_runtime "$runtime" "$TMP/valid.env" "$TMP/$name-lock-open-default.out" --doctor --skip-notify
  expect_rc "$name default lock-open failure" 1
done

LOCK_FILE="$TMP/runtime.lock"
for runtime in "${RUNTIMES[@]}"; do
  name="$(basename "$runtime")"
  ready="$TMP/$name-holder-ready"
  rm -f "$ready"
  flock -x "$LOCK_FILE" -c "touch '$ready'; sleep 0.3" &
  holder=$!
  for _ in {1..100}; do
    [[ -e "$ready" ]] && break
    sleep 0.01
  done
  [[ -e "$ready" ]] || { echo "$name lock holder did not start" >&2; exit 1; }
  run_runtime "$runtime" "$TMP/valid.env" "$TMP/$name-wake.out" --doctor --skip-notify --wait-lock 2
  if kill -0 "$holder" 2>/dev/null; then
    echo "$name returned before the held lock was released" >&2
    kill "$holder" 2>/dev/null || true
    wait "$holder" 2>/dev/null || true
    exit 1
  fi
  wait "$holder"
  [[ "$LAST_RC" -eq 0 || "$LAST_RC" -eq 1 ]] || {
    echo "$name wake-before-timeout exit $LAST_RC, expected doctor result 0 or 1" >&2
    exit 1
  }
  if grep -Fq 'Timed out waiting for the security-update-notify lock' "$TMP/$name-wake.out"; then
    echo "$name reported a timeout after waking before the deadline" >&2
    exit 1
  fi
done

echo "Go production entrypoint lock parsing, precedence, error, timeout, and wake semantics passed"
