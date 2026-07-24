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
            valid = (
                urllib.parse.parse_qs(parsed.query).get("receive_id_type") == ["open_id"]
                and self.headers.get("Authorization") == "Bearer tenant-token"
                and payload.get("receive_id") == "ou_lanny"
                and payload.get("msg_type") == "text"
                and "hello from bash" in json.loads(payload.get("content", "{}")).get("text", "")
            )
            with open(attempts_file, "a", encoding="utf-8") as fh:
                fh.write(f"{Handler.message_attempts} {int(valid)}\n")
            if Handler.message_attempts == 1:
                self.reply(429, {"code": 999}, retry_after="0")
                return
            self.reply(200, {"code": 0})
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
feishu_send_message "hello from bash"
wait "$SERVER_PID"
SERVER_PID=""

diff -u "$TMP/attempts" - <<'EOF'
1 1
2 1
EOF
echo "Bash Feishu client passed token, fixed open_id, and Retry-After checks"
