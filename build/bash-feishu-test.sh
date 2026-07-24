#!/usr/bin/env bash
# Execute the Bash fallback's real embedded Python against a local Feishu mock.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

python3 - "$TMP/port" "$TMP/attempts" <<'PY' &
import http.server
import json
import socketserver
import sys
import threading
import urllib.parse

port_file, attempts_file = sys.argv[1:]

class Handler(http.server.BaseHTTPRequestHandler):
    message_attempts = 0

    def log_message(self, *_):
        pass

    def reply(self, status, payload, retry_after=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        if retry_after is not None:
            self.send_header("Retry-After", retry_after)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.endswith("/tenant_access_token/internal"):
            payload = json.loads(body)
            if payload != {"app_id": "cli_test", "app_secret": "fake-secret"}:
                self.reply(400, {"code": 1})
                return
            self.reply(200, {"code": 0, "tenant_access_token": "tenant-token"})
            return
        if parsed.path.endswith("/im/v1/messages"):
            Handler.message_attempts += 1
            payload = json.loads(body)
            card = json.loads(payload.get("content", "{}"))
            card_text = json.dumps(card, ensure_ascii=False)
            valid_card = (
                urllib.parse.parse_qs(parsed.query).get("receive_id_type") == ["open_id"]
                and self.headers.get("Authorization") == "Bearer tenant-token"
                and payload.get("receive_id") == "ou_lanny"
                and payload.get("msg_type") == "interactive"
                and card.get("schema") == "2.0"
                and card.get("header", {}).get("template") == "orange"
                and "bash-host" in card_text
                and "TEST-MODE-no-real-reboot" in card_text
                and "服务/进程重启" in card_text
                and "维护详情" in card_text
                and "重启检测" not in card_text
                and "sudo reboot" in card_text
            )
            valid_text = (
                urllib.parse.parse_qs(parsed.query).get("receive_id_type") == ["open_id"]
                and self.headers.get("Authorization") == "Bearer tenant-token"
                and payload.get("receive_id") == "ou_lanny"
                and payload.get("msg_type") == "text"
                and str(card.get("text", "")).startswith("fallback ")
            )
            kind = payload.get("msg_type", "")
            valid = valid_card or valid_text
            with open(attempts_file, "a", encoding="utf-8") as fh:
                fh.write(f"{Handler.message_attempts} {kind} {int(valid)}\n")
            if Handler.message_attempts == 3:
                self.reply(429, {"code": 999}, retry_after="0")
                return
            self.reply(200, {"code": 0})
            if Handler.message_attempts == 4:
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        self.reply(404, {"code": 404})

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
[[ -s "$TMP/port" ]] || { echo "Feishu mock did not start" >&2; exit 1; }

# Load only the credential/token/send helpers so the runtime's main flow does not execute.
eval "$(awk '
  /^feishu_secret_to_stdout\(\) \{/ { copy=1 }
  /^channel_configured\(\) \{/ { copy=0 }
  copy
' "$ROOT/files/security-update-notify")"

export FEISHU_APP_ID=cli_test
export FEISHU_RECEIVE_ID=ou_lanny
mkdir -p "$TMP/credentials"
printf %s fake-secret >"$TMP/credentials/feishu_app_secret"
chmod 600 "$TMP/credentials/feishu_app_secret"
export CREDENTIALS_DIRECTORY="$TMP/credentials"
MOCK_PORT="$(cat "$TMP/port")"
export SECURITY_UPDATE_NOTIFY_FEISHU_BASE_URL="http://127.0.0.1:$MOCK_PORT"
# These values are consumed by the function loaded with eval above.
# shellcheck disable=SC2034
NOTIFY_LANG=zh VERSION=2.2.0 HOST=bash-host INCLUDE_PUBLIC_IP=1 \
  PUBLIC_IP_VALUE=203.0.113.10 OS="Debian 12" BACKEND=apt KERNEL=6.1.0-test \
  NOW="2026-07-24 17:20:00 CST" reboot_required=1 restart_attention=1 \
  HEALTH_ATTENTION=0 PENDING_SEC_COUNT=2 EOL_ATTENTION=0 \
  reboot_pkgs=$'linux-image-amd64\nTEST-MODE-no-real-reboot' \
  rs_zh=$'当前内核：6.1.0-test\n需检查/重启服务：ssh.service' \
  rs_en=$'Current kernel: 6.1.0-test\nServices to review/restart: ssh.service' \
  HEALTH_TXT_ZH="" HEALTH_TXT_EN="" PENDING_TXT_ZH="• 待安装安全更新：2 项" \
  PENDING_TXT_EN="• Pending security updates: 2" EOL_TXT_ZH="" EOL_TXT_EN=""

saved_host="$HOST"
HOST=$'bad-\xff-<at id="all"></at>&'
hostile_card="$(feishu_build_check_card 1 "hostile fallback")"
HOST="$saved_host"
HOSTILE_CARD="$hostile_card" /usr/bin/python3 - <<'PY'
import json
import os

doc = json.loads(os.environ["HOSTILE_CARD"])
want = 'bad-�-<at id="all"></at>&'
found = False

def walk(value):
    global found
    if isinstance(value, dict):
        if value.get("content") == want:
            assert value.get("tag") == "plain_text"
            found = True
        for child in value.values():
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)

walk(doc)
assert found, "hostile host was not preserved as plain_text"
PY

reboot_required=0
restart_attention=0
PENDING_SEC_COUNT=0
PENDING_TXT_ZH=""
PENDING_TXT_EN=""
green_card="$(feishu_build_check_card 0 "healthy fallback")"
EOL_ATTENTION=1
EOL_TXT_ZH="发行版已结束安全支持"
EOL_TXT_EN="Distribution security support ended"
red_card="$(feishu_build_check_card 1 "EOL fallback")"
blue_card="$(feishu_build_upgrade_card 2.1.0 2.2.0 "upgrade fallback")"
GREEN_CARD="$green_card" RED_CARD="$red_card" BLUE_CARD="$blue_card" /usr/bin/python3 - <<'PY'
import json
import os

for name, want in (("GREEN_CARD", "green"), ("RED_CARD", "red"), ("BLUE_CARD", "blue")):
    doc = json.loads(os.environ[name])
    assert doc.get("schema") == "2.0"
    assert doc.get("header", {}).get("template") == want, (name, doc.get("header"))
PY
# shellcheck disable=SC2034
reboot_required=1 restart_attention=1 PENDING_SEC_COUNT=2 \
  PENDING_TXT_ZH="• 待安装安全更新：2 项" PENDING_TXT_EN="• Pending security updates: 2" \
  EOL_ATTENTION=0 EOL_TXT_ZH="" EOL_TXT_EN=""

feishu_send_message "fallback invalid card" '{"schema":"1.0"}'
oversized_card="$(/usr/bin/python3 -c 'import json; print(json.dumps({"schema":"2.0","body":{"content":"x"*(31*1024)}}))')"
feishu_send_message "fallback oversized card" "$oversized_card"
card="$(feishu_build_check_card 1 "hello from bash")"
feishu_send_message "hello from bash" "$card"
wait "$SERVER_PID"
SERVER_PID=""

diff -u "$TMP/attempts" - <<'EOF'
1 text 1
2 text 1
3 interactive 1
4 interactive 1
EOF
echo "Bash Feishu card passed JSON 2.0, plain-text safety/fallback, fixed open_id, and Retry-After checks"
