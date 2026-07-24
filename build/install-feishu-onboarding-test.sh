#!/usr/bin/env bash
# Exercise the installer's real Feishu Directory scanner and numbered selection against a local mock.
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
import socketserver
import sys
import urllib.parse

port_file, requests_file = sys.argv[1:]

class Handler(http.server.BaseHTTPRequestHandler):
    retry_attempts = 0
    rate_limit_attempts = 0

    def log_message(self, *_args):
        pass

    def send_json(self, body, status=200, headers=None):
        encoded = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(size) or b"{}")
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/open-apis/auth/v3/tenant_access_token/internal":
            if body.get("app_id") == "cli_bad":
                self.send_json({"code": 10014, "msg": "app secret invalid"})
                return
            if body.get("app_secret") != "fake-secret":
                self.send_json({"code": 10014, "msg": "app secret invalid"})
                return
            self.send_json({"code": 0, "tenant_access_token": f"token-{body.get('app_id')}"})
            return
        if parsed.path != "/open-apis/directory/v1/employees/filter":
            self.send_json({"code": 404}, 404)
            return
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        app_id = token.removeprefix("token-")
        with open(requests_file, "a", encoding="utf-8") as fh:
            print(json.dumps({"app_id": app_id, "query": parsed.query, "body": body}), file=fh)
        if app_id == "cli_permission":
            self.send_json({"code": 99991672, "msg": "Access denied"})
            return
        if app_id == "cli_empty":
            self.send_json({"code": 0, "data": {"employees": [], "page_response": {"has_more": False, "page_token": ""}}})
            return
        if app_id == "cli_abnormal":
            self.send_json({"code": 0, "data": {"employees": [], "abnormals": [{"code": 99991672}]}})
            return
        if app_id == "cli_retry" and Handler.retry_attempts == 0:
            Handler.retry_attempts += 1
            self.send_json({"code": 500}, 500)
            return
        if app_id == "cli_rate_limit" and Handler.rate_limit_attempts == 0:
            Handler.rate_limit_attempts += 1
            self.send_json({"code": 99991400}, 400, {"x-ogw-ratelimit-reset": "0"})
            return
        page_token = body.get("page_request", {}).get("page_token", "")
        if not page_token:
            self.send_json({
                "code": 0,
                "data": {
                    "employees": [{
                        "base_info": {
                            "employee_id": "ou_first",
                            "mobile": "+8613800001234",
                            "name": {"name": {"default_value": "Old Name", "i18n_value": {"zh_cn": "王小明"}}},
                        }
                    }],
                    "page_response": {"has_more": True, "page_token": "next-page"},
                },
            })
            return
        if page_token == "next-page":
            self.send_json({
                "code": 0,
                "data": {
                    "employees": [
                        {"base_info": {"employee_id": "ou_first", "mobile": "+8613800001234"}},
                        {
                            "base_info": {
                                "employee_id": "ou_second",
                                "mobile": "",
                                "name": {"name": {"default_value": "Fallback Name", "i18n_value": {"zh_cn": ""}}},
                            }
                        },
                    ],
                    "page_response": {
                        "has_more": app_id == "cli_repeat",
                        "page_token": "next-page" if app_id == "cli_repeat" else "",
                    },
                },
            })
            return
        self.send_json({"code": 400, "msg": "unexpected page token"}, 400)

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
[[ -s "$TMP/port" ]] || { echo "Feishu onboarding mock did not start" >&2; exit 1; }
PORT="$(cat "$TMP/port")"

python3 - "$ROOT/install.sh" "$TMP/harness.sh" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text()
start = source.index("feishu_credential_available() {")
end = source.index("\nsnapshot_feishu_credential()", start)
functions = source[start:end]
harness = r'''#!/usr/bin/env bash
set -euo pipefail
UI_LANG="${UI_LANG:-zh}"
NON_INTERACTIVE="${NON_INTERACTIVE:-0}"
FEISHU_APP_ID="${FEISHU_TEST_APP_ID:-cli_test}"
FEISHU_APP_SECRET="fake-secret"
FEISHU_APP_SECRET_FILE=""
FEISHU_ENCRYPTED_CREDENTIAL="/nonexistent/encrypted"
FEISHU_CREDENTIAL_FILE="/nonexistent/plain"
FEISHU_AUTH_VALIDATED=0
FEISHU_API_BASE_URL="${TEST_FEISHU_API_BASE_URL:?}"
TMP_DIR="${TEST_TMP:?}"
m() { if [[ "$UI_LANG" == "en" ]]; then printf %s "$2"; else printf %s "$1"; fi; }
say() { printf '%s\n' "$(m "$1" "$2")"; }
prompt_required_text() {
  local name="$1" value
  read -r value
  printf -v "$name" %s "$value"
}
''' + functions + r'''
case "${1:-select}" in
  select)
    select_feishu_recipient
    printf 'RESULT=%s\n' "$FEISHU_RECEIVE_ID"
    ;;
  scan)
    if feishu_scan_directory "$TMP_DIR/users.json" "$TMP_DIR/error"; then
      printf 'COUNT=%s\n' "$(feishu_directory_user_count "$TMP_DIR/users.json")"
    else
      cat "$TMP_DIR/error" >&2
      exit 1
    fi
    ;;
esac
'''
Path(sys.argv[2]).write_text(harness)
PY
chmod +x "$TMP/harness.sh"

export TEST_FEISHU_API_BASE_URL="http://127.0.0.1:$PORT"
export TEST_TMP="$TMP"

printf '08\n9\n2\n' | "$TMP/harness.sh" select >"$TMP/select.out" 2>&1
grep -Fq '王小明 | 手机号尾号 1234 | ou_first' "$TMP/select.out"
grep -Fq 'Fallback Name | 手机号尾号 ---- | ou_second' "$TMP/select.out"
grep -Fq '请输入 1-2 之间的序号。' "$TMP/select.out"
grep -Fq 'RESULT=ou_second' "$TMP/select.out"

printf 'm\ninvalid\nou_manual\n' | "$TMP/harness.sh" select >"$TMP/manual.out" 2>&1
grep -Fq '无效 open_id' "$TMP/manual.out"
grep -Fq 'RESULT=ou_manual' "$TMP/manual.out"

printf '\nou_fallback\n' | FEISHU_TEST_APP_ID=cli_permission "$TMP/harness.sh" select >"$TMP/fallback.out" 2>&1
grep -Fq '飞书用户扫描失败。' "$TMP/fallback.out"
grep -Fq 'RESULT=ou_fallback' "$TMP/fallback.out"

FEISHU_TEST_APP_ID=cli_empty "$TMP/harness.sh" scan >"$TMP/empty.out"
grep -Fxq 'COUNT=0' "$TMP/empty.out"

if FEISHU_TEST_APP_ID=cli_permission "$TMP/harness.sh" scan >"$TMP/permission.out" 2>&1; then
  echo "Expected a directory permission failure" >&2
  exit 1
fi
grep -Fq 'Feishu directory scan failed: code=99991672' "$TMP/permission.out"

if FEISHU_TEST_APP_ID=cli_bad "$TMP/harness.sh" scan >"$TMP/auth.out" 2>&1; then
  echo "Expected an authentication failure" >&2
  exit 1
fi
grep -Fq 'Feishu authentication failed: code=10014' "$TMP/auth.out"

FEISHU_TEST_APP_ID=cli_retry "$TMP/harness.sh" scan >"$TMP/retry.out"
grep -Fxq 'COUNT=2' "$TMP/retry.out"

FEISHU_TEST_APP_ID=cli_rate_limit "$TMP/harness.sh" scan >"$TMP/rate-limit.out"
grep -Fxq 'COUNT=2' "$TMP/rate-limit.out"

if FEISHU_TEST_APP_ID=cli_abnormal "$TMP/harness.sh" scan >"$TMP/abnormal.out" 2>&1; then
  echo "Expected a partial Directory response to fail" >&2
  exit 1
fi
grep -Fq 'Feishu directory scan incomplete: abnormals returned' "$TMP/abnormal.out"

if FEISHU_TEST_APP_ID=cli_repeat "$TMP/harness.sh" scan >"$TMP/repeat.out" 2>&1; then
  echo "Expected a repeated page token to fail" >&2
  exit 1
fi
grep -Fq 'Feishu directory pagination repeated a page token' "$TMP/repeat.out"

if NON_INTERACTIVE=1 "$TMP/harness.sh" select >"$TMP/noninteractive.out" 2>&1; then
  echo "Expected non-interactive selection to fail" >&2
  exit 1
else
  rc=$?
  [[ "$rc" -eq 2 ]] || { echo "Unexpected non-interactive exit code: $rc" >&2; exit 1; }
fi
grep -Fq -- '--feishu-receive-id' "$TMP/noninteractive.out"

python3 - "$TMP/requests.jsonl" <<'PY'
import json
import sys

requests = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
normal = [item for item in requests if item["app_id"] == "cli_test"]
assert len(normal) >= 4, normal
first, second = normal[0], normal[1]
assert first["query"] == "employee_id_type=open_id&department_id_type=open_department_id"
assert second["body"]["page_request"]["page_token"] == "next-page"
expected_fields = ["base_info.employee_id", "base_info.name", "base_info.mobile"]
assert first["body"]["required_fields"] == expected_fields
assert first["body"]["filter"]["conditions"] == [
    {"field": "base_info.departments.department_id", "operator": "eq", "value": '"0"'},
    {"field": "work_info.staff_status", "operator": "eq", "value": "1"},
]
PY

if grep -R -Fq 'fake-secret' "$TMP" --exclude=harness.sh; then
  echo "Feishu App Secret leaked into test output or mock logs" >&2
  exit 1
fi

echo "Install Feishu onboarding test passed."
