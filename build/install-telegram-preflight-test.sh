#!/usr/bin/env bash
# Exercise the installer's Telegram preflight classification and retry behavior against a local mock.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

python3 - "$TMP/port" "$TMP/requests.jsonl" <<'PY' &
import http.server
import json
import socket
import socketserver
import sys
import time
import urllib.parse

port_file, requests_file = sys.argv[1:]

class Handler(http.server.BaseHTTPRequestHandler):
    attempts = {}

    def log_message(self, *_args):
        pass

    def send_json(self, body, status=200, headers=None):
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def handle_request(self):
        parts = urllib.parse.urlparse(self.path).path.split("/")
        if len(parts) != 3 or not parts[1].startswith("bot"):
            self.send_json({"ok": False, "error_code": 404, "description": "not found"}, 404)
            return
        token = urllib.parse.unquote(parts[1][3:])
        operation = parts[2]
        key = (token, operation)
        Handler.attempts[key] = Handler.attempts.get(key, 0) + 1
        attempt = Handler.attempts[key]
        with open(requests_file, "a", encoding="utf-8") as fh:
            print(json.dumps({"token": token, "operation": operation, "attempt": attempt}), file=fh)

        if token == "101:reset" and operation == "getMe" and attempt == 1:
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        if token == "102:temporary" and operation == "getMe":
            self.send_json(
                {"ok": False, "error_code": 503, "description": "temporary unavailable"},
                503,
                {"Retry-After": "0"},
            )
            return
        if token == "103:bad" and operation == "getMe":
            self.send_json({"ok": False, "error_code": 404, "description": "Not Found"}, 404)
            return
        if token == "104:badchat" and operation == "sendMessage":
            self.send_json({"ok": False, "error_code": 400, "description": "Bad Request: chat not found"}, 400)
            return
        if token == "105:sendretry" and operation == "sendMessage" and attempt < 3:
            self.send_json(
                {"ok": False, "error_code": 503, "description": "temporary unavailable"},
                503,
                {"Retry-After": "0"},
            )
            return
        if token == "106:ratelimit" and operation == "getMe":
            self.send_json(
                {"ok": False, "error_code": 429, "description": "too many requests"},
                429,
                {"Retry-After": "0"},
            )
            return
        if token == "107:timeout" and operation == "getMe":
            time.sleep(0.5)
            return
        if operation == "getMe":
            self.send_json({"ok": True, "result": {"username": "mock_bot"}})
            return
        if operation == "sendMessage":
            self.send_json({"ok": True, "result": {"message_id": 1}})
            return
        self.send_json({"ok": False, "error_code": 404, "description": "not found"}, 404)

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(size)
        self.handle_request()

with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
    with open(port_file, "w", encoding="ascii") as fh:
        fh.write(str(server.server_address[1]))
    server.serve_forever()
PY
SERVER_PID=$!
for _ in {1..100}; do
  [[ -s "$TMP/port" ]] && break
  sleep 0.05
done
[[ -s "$TMP/port" ]] || { echo "Telegram preflight mock did not start" >&2; exit 1; }
PORT="$(cat "$TMP/port")"

python3 - "$ROOT/install.sh" "$TMP/harness.sh" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text()
start = source.index("telegram_preflight_request() {")
end = source.index("\nfeishu_preflight() {", start)
functions = source[start:end]
harness = r'''#!/usr/bin/env bash
set -euo pipefail
UI_LANG="${UI_LANG:-zh}"
NON_INTERACTIVE="${NON_INTERACTIVE:-0}"
SKIP_TELEGRAM_TEST=0
NOTIFY_CHANNELS=telegram
TELEGRAM_BOT_TOKEN="${TEST_TELEGRAM_TOKEN:-100:ok}"
TELEGRAM_CHAT_ID="${TEST_TELEGRAM_CHAT_ID:--100123}"
TELEGRAM_API_BASE_URL="${TEST_TELEGRAM_API_BASE_URL:?}"
TELEGRAM_PREFLIGHT_TIMEOUT_SECONDS="${TEST_TELEGRAM_PREFLIGHT_TIMEOUT_SECONDS:-20}"
TMP_DIR="${TEST_TMP:?}"
m() { if [[ "$UI_LANG" == "en" ]]; then printf %s "$2"; else printf %s "$1"; fi; }
say() { printf '%s\n' "$(m "$1" "$2")"; }
channel_selected() { case ",$NOTIFY_CHANNELS," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
prompt_secret() {
  local name="$1" value
  printf 'called\n' >"$TMP_DIR/credential-prompt"
  read -r value
  printf -v "$name" %s "$value"
}
prompt_required_text() {
  local name="$1" value
  read -r value
  printf -v "$name" %s "$value"
}
''' + functions + r'''
telegram_preflight
printf 'TOKEN=%s\nCHAT_ID=%s\n' "$TELEGRAM_BOT_TOKEN" "$TELEGRAM_CHAT_ID"
'''
Path(sys.argv[2]).write_text(harness)
PY
chmod +x "$TMP/harness.sh"

export TEST_TELEGRAM_API_BASE_URL="http://127.0.0.1:$PORT"
export TEST_TMP="$TMP"

"$TMP/harness.sh" >"$TMP/success.out" 2>&1
grep -Fq 'Token 有效: @mock_bot' "$TMP/success.out"
grep -Fq 'Telegram 测试消息已发送。' "$TMP/success.out"

TEST_TELEGRAM_TOKEN=101:reset "$TMP/harness.sh" >"$TMP/reset-retry.out" 2>&1
grep -Fq 'Telegram 测试消息已发送。' "$TMP/reset-retry.out"

rm -f "$TMP/credential-prompt"
printf '2\n' | TEST_TELEGRAM_TOKEN=102:temporary "$TMP/harness.sh" >"$TMP/temporary-skip.out" 2>&1
grep -Fq '临时网络故障' "$TMP/temporary-skip.out"
grep -Fq '这不表示 Bot Token 或 Chat ID 无效' "$TMP/temporary-skip.out"
grep -Fq '当前凭据保持不变' "$TMP/temporary-skip.out"
grep -Fxq 'TOKEN=102:temporary' "$TMP/temporary-skip.out"
if [[ -e "$TMP/credential-prompt" ]]; then
  echo "Temporary Telegram failure incorrectly prompted for new credentials" >&2
  exit 1
fi

rm -f "$TMP/credential-prompt"
set +e
NON_INTERACTIVE=1 TEST_TELEGRAM_TOKEN=102:temporary "$TMP/harness.sh" >"$TMP/temporary-noninteractive.out" 2>&1
temporary_rc=$?
set -e
[[ "$temporary_rc" -eq 75 ]] || { echo "Expected temporary Telegram failure exit 75, got $temporary_rc" >&2; exit 1; }
grep -Fq '未修改凭据' "$TMP/temporary-noninteractive.out"
if [[ -e "$TMP/credential-prompt" ]]; then
  echo "Non-interactive temporary failure incorrectly prompted for new credentials" >&2
  exit 1
fi

rm -f "$TMP/credential-prompt"
printf 'y\n100:ok\n-100123\n' | TEST_TELEGRAM_TOKEN=103:bad "$TMP/harness.sh" >"$TMP/bad-token.out" 2>&1
grep -Fq 'Bot Token 校验被 API 拒绝' "$TMP/bad-token.out"
grep -Fq 'Telegram getMe rejected: HTTP 404: Not Found' "$TMP/bad-token.out"
grep -Fxq 'TOKEN=100:ok' "$TMP/bad-token.out"
[[ -e "$TMP/credential-prompt" ]] || { echo "Rejected Telegram token did not prompt for new credentials" >&2; exit 1; }

set +e
NON_INTERACTIVE=1 TEST_TELEGRAM_TOKEN=103:bad "$TMP/harness.sh" >"$TMP/bad-token-noninteractive.out" 2>&1
bad_token_rc=$?
set -e
[[ "$bad_token_rc" -eq 2 ]] || { echo "Expected rejected Telegram token exit 2, got $bad_token_rc" >&2; exit 1; }
grep -Fq '非交互模式：Telegram 凭据预检失败' "$TMP/bad-token-noninteractive.out"

set +e
NON_INTERACTIVE=1 TEST_TELEGRAM_TOKEN=invalid "$TMP/harness.sh" >"$TMP/invalid-token.out" 2>&1
invalid_token_rc=$?
set -e
[[ "$invalid_token_rc" -eq 2 ]] || { echo "Expected malformed Telegram token exit 2, got $invalid_token_rc" >&2; exit 1; }
grep -Fq 'Bot Token 本地格式无效' "$TMP/invalid-token.out"
grep -Fq 'invalid TELEGRAM_BOT_TOKEN format' "$TMP/invalid-token.out"

TEST_TELEGRAM_TOKEN=105:sendretry "$TMP/harness.sh" >"$TMP/send-retry.out" 2>&1
grep -Fq 'Telegram 测试消息已发送。' "$TMP/send-retry.out"

set +e
NON_INTERACTIVE=1 TEST_TELEGRAM_TOKEN=106:ratelimit "$TMP/harness.sh" >"$TMP/rate-limit.out" 2>&1
rate_limit_rc=$?
set -e
[[ "$rate_limit_rc" -eq 75 ]] || { echo "Expected Telegram HTTP 429 exit 75, got $rate_limit_rc" >&2; exit 1; }
grep -Fq 'Telegram getMe temporarily failed: HTTP 429' "$TMP/rate-limit.out"

set +e
NON_INTERACTIVE=1 TEST_TELEGRAM_TOKEN=107:timeout TEST_TELEGRAM_PREFLIGHT_TIMEOUT_SECONDS=0.1 \
  "$TMP/harness.sh" >"$TMP/timeout.out" 2>&1
timeout_rc=$?
set -e
[[ "$timeout_rc" -eq 75 ]] || { echo "Expected Telegram timeout exit 75, got $timeout_rc" >&2; exit 1; }
grep -Fq 'network request failed after 3 attempts' "$TMP/timeout.out"

set +e
printf 'n\n' | TEST_TELEGRAM_TOKEN=104:badchat "$TMP/harness.sh" >"$TMP/bad-chat.out" 2>&1
bad_chat_rc=$?
set -e
[[ "$bad_chat_rc" -eq 2 ]] || { echo "Expected rejected Telegram chat exit 2, got $bad_chat_rc" >&2; exit 1; }
grep -Fq '测试消息被 API 拒绝' "$TMP/bad-chat.out"
grep -Fq 'Telegram sendMessage rejected: HTTP 400: Bad Request: chat not found' "$TMP/bad-chat.out"

python3 - "$TMP/requests.jsonl" <<'PY'
import json
import sys

requests = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]

def count(token, operation):
    return sum(item["token"] == token and item["operation"] == operation for item in requests)

assert count("100:ok", "getMe") == 2
assert count("100:ok", "sendMessage") == 2
assert count("101:reset", "getMe") == 2
assert count("101:reset", "sendMessage") == 1
assert count("102:temporary", "getMe") == 6
assert count("103:bad", "getMe") == 2
assert count("105:sendretry", "sendMessage") == 3
assert count("106:ratelimit", "getMe") == 3
assert count("107:timeout", "getMe") == 3
assert count("104:badchat", "sendMessage") == 1
PY

echo "Install Telegram preflight test passed."
