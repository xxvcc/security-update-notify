#!/usr/bin/env python3
"""Loopback-only HTTPS fixture for Telegram and Feishu integration scenarios."""

import argparse
import json
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


MAX_REQUEST_BYTES = 1 << 20
TELEGRAM_PATH = re.compile(r"^/bot([^/]+)/(getMe|sendMessage)$")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--expectations", required=True)
    return parser.parse_args()


def load_expectations(path):
    raw = Path(path).read_bytes()
    if len(raw) > 64 << 10:
        raise ValueError("expectations file is too large")
    data = json.loads(raw)
    telegram = data.get("telegram")
    feishu = data.get("feishu")
    if not isinstance(telegram, dict) or not isinstance(feishu, dict):
        raise ValueError("expectations must contain telegram and feishu objects")

    telegram_targets = {}
    for token, chat_ids in telegram.items():
        if not isinstance(token, str) or not token or not isinstance(chat_ids, list):
            raise ValueError("invalid Telegram expectations")
        if not chat_ids or any(not isinstance(item, str) or not item for item in chat_ids):
            raise ValueError("invalid Telegram chat expectations")
        telegram_targets[token] = frozenset(chat_ids)

    feishu_apps = {}
    feishu_tokens = {}
    for index, (app_id, config) in enumerate(feishu.items(), start=1):
        if not isinstance(app_id, str) or not app_id or not isinstance(config, dict):
            raise ValueError("invalid Feishu expectations")
        secret = config.get("secret")
        receive_ids = config.get("receive_ids")
        if not isinstance(secret, str) or not secret or not isinstance(receive_ids, list):
            raise ValueError("invalid Feishu app expectations")
        if not receive_ids or any(not isinstance(item, str) or not item for item in receive_ids):
            raise ValueError("invalid Feishu recipient expectations")
        token = f"pty-tenant-token-{index}"
        feishu_apps[app_id] = {
            "secret": secret,
            "receive_ids": frozenset(receive_ids),
            "token": token,
        }
        feishu_tokens[token] = app_id
    return telegram_targets, feishu_apps, feishu_tokens


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    log_path = ""
    log_lock = threading.Lock()
    telegram_targets = {}
    feishu_apps = {}
    feishu_tokens = {}

    def log_message(self, _format, *_args):
        return

    def record(self, event):
        with self.log_lock:
            with open(self.log_path, "a", encoding="utf-8") as log:
                log.write(json.dumps({"event": event}, separators=(",", ":")) + "\n")

    def reply(self, payload, status=200):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def reject(self, status=403):
        self.reply({"error": "fixture request did not match expectations"}, status)

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > MAX_REQUEST_BYTES:
            return None
        return self.rfile.read(length)

    def feishu_app_from_bearer(self):
        prefix = "Bearer "
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith(prefix):
            return None
        return self.feishu_tokens.get(authorization[len(prefix) :])

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlsplit(self.path)
        match = TELEGRAM_PATH.fullmatch(parsed.path)
        if not match or match.group(2) != "getMe" or parsed.query:
            self.reject(404)
            return
        token = match.group(1)
        if token not in self.telegram_targets:
            self.reject()
            return
        self.record("telegram_get_me")
        self.reply({"ok": True, "result": {"id": 1, "is_bot": True}})

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        body = self.read_body()
        if body is None:
            self.reject(400)
            return
        parsed = urlsplit(self.path)
        telegram_match = TELEGRAM_PATH.fullmatch(parsed.path)
        if telegram_match and telegram_match.group(2) == "sendMessage" and not parsed.query:
            token = telegram_match.group(1)
            try:
                form = parse_qs(body.decode("utf-8"), strict_parsing=True)
            except (UnicodeDecodeError, ValueError):
                self.reject(400)
                return
            chat_ids = form.get("chat_id", [])
            if (
                token not in self.telegram_targets
                or len(chat_ids) != 1
                or chat_ids[0] not in self.telegram_targets[token]
                or len(form.get("text", [])) != 1
                or not form["text"][0]
                or form.get("disable_web_page_preview") != ["true"]
            ):
                self.reject()
                return
            self.record("telegram_send")
            self.reply({"ok": True, "result": {"message_id": 1}})
            return
        if parsed.path == "/open-apis/auth/v3/tenant_access_token/internal" and not parsed.query:
            try:
                payload = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.reject(400)
                return
            if not isinstance(payload, dict):
                self.reject(400)
                return
            app_id = payload.get("app_id")
            config = self.feishu_apps.get(app_id)
            if config is None or payload.get("app_secret") != config["secret"]:
                self.reject()
                return
            self.record("feishu_token")
            self.reply({"code": 0, "tenant_access_token": config["token"]})
            return
        if parsed.path == "/open-apis/directory/v1/employees/filter":
            query = parse_qs(parsed.query, strict_parsing=True)
            app_id = self.feishu_app_from_bearer()
            if app_id is None or query != {
                "employee_id_type": ["open_id"],
                "department_id_type": ["open_department_id"],
            }:
                self.reject()
                return
            try:
                payload = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.reject(400)
                return
            expected_filter = {
                "conditions": [
                    {
                        "field": "base_info.departments.department_id",
                        "operator": "eq",
                        "value": '"0"',
                    },
                    {"field": "work_info.staff_status", "operator": "eq", "value": "1"},
                ]
            }
            if (
                not isinstance(payload, dict)
                or set(payload) != {"filter", "required_fields", "page_request"}
                or payload.get("filter") != expected_filter
                or payload.get("required_fields")
                != ["base_info.employee_id", "base_info.name", "base_info.mobile"]
                or payload.get("page_request") != {"page_size": 100}
            ):
                self.reject()
                return
            self.record("feishu_directory")
            self.reply(
                {
                    "code": 0,
                    "data": {
                        "employees": [
                            {
                                "base_info": {
                                    "employee_id": "ou_pty_user",
                                    "mobile": "+8613800004321",
                                    "name": {
                                        "name": {
                                            "i18n_value": {"zh_cn": "PTY User"},
                                            "default_value": "PTY User",
                                        }
                                    },
                                }
                            }
                        ],
                        "abnormals": [],
                        "page_response": {"has_more": False, "page_token": ""},
                    },
                }
            )
            return
        if parsed.path == "/open-apis/im/v1/messages":
            query = parse_qs(parsed.query, strict_parsing=True)
            app_id = self.feishu_app_from_bearer()
            try:
                payload = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.reject(400)
                return
            config = self.feishu_apps.get(app_id)
            if (
                config is None
                or query != {"receive_id_type": ["open_id"]}
                or not isinstance(payload, dict)
                or set(payload) != {"receive_id", "msg_type", "content"}
                or payload.get("receive_id") not in config["receive_ids"]
                or payload.get("msg_type") not in {"text", "interactive"}
                or not isinstance(payload.get("content"), str)
                or not payload["content"]
            ):
                self.reject()
                return
            try:
                content = json.loads(payload["content"])
            except json.JSONDecodeError:
                self.reject(400)
                return
            if payload["msg_type"] == "text":
                content_valid = isinstance(content, dict) and isinstance(content.get("text"), str) and bool(content["text"])
            else:
                content_valid = isinstance(content, dict) and content.get("schema") == "2.0"
            if not content_valid:
                self.reject()
                return
            self.record("feishu_send")
            self.reply({"code": 0})
            return
        self.reject(404)


def main():
    args = parse_args()
    telegram, feishu_apps, feishu_tokens = load_expectations(args.expectations)
    FixtureHandler.log_path = args.log
    FixtureHandler.telegram_targets = telegram
    FixtureHandler.feishu_apps = feishu_apps
    FixtureHandler.feishu_tokens = feishu_tokens
    server = ThreadingHTTPServer(("127.0.0.1", 443), FixtureHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
