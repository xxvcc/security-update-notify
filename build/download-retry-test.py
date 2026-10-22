#!/usr/bin/env python3
"""Exercise retained download helpers against a real, local TLS server."""

from __future__ import annotations

import http.server
import os
from pathlib import Path
import signal
import ssl
import subprocess
import tempfile
import textwrap
import threading


ROOT = Path(__file__).resolve().parent.parent
PAYLOAD = b"trusted-response"


def payload_for(name: str) -> bytes:
    return b"x" * (1048576 - len(PAYLOAD)) + PAYLOAD if name.startswith("docs-") else PAYLOAD


def section(source: str, start: str, end: str) -> str:
    return source.split(start, 1)[1].split(end, 1)[0]


def download_harnesses() -> dict[str, str]:
    sun = (ROOT / "sun.sh").read_text()
    canary = (ROOT / "build/live-canary.sh").read_text()
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    mirror = (ROOT / ".github/workflows/mirror-release.yml").read_text()
    prefix = "#!/bin/bash\nset -euo pipefail\n"
    harnesses = {
        "bootstrap": prefix + "CURL_RETRY_OPTIONS=()\n" + "configure_curl_retry_options() {"
        + section(sun, "configure_curl_retry_options() {", "\ncapture_limited() {")
        + '\nconfigure_curl_retry_options\ndownload_limited "$1" "$2" --cacert "$3" -fsSL "$4"\n',
        "canary": prefix + "curl_args=("
        + section(canary, "curl_args=(", "\ncache_key=")
        + '\ndownload_limited "$1" "$2" --cacert "$3" "$4"\n',
    }
    ci_function = textwrap.dedent(
        "          download_limited() {"
        + section(ci, "          download_limited() {", "          github_base=")
    )
    # The tested implementation is unchanged apart from trusting this test's
    # private CA; no machine trust store or production endpoint is changed.
    ci_function = ci_function.replace(
        "/usr/bin/curl --disable", '/usr/bin/curl --disable --cacert "$SUN_TEST_CA"'
    )
    harnesses["release-ci"] = prefix + ci_function + '\ndownload_limited "$1" "$2" "$4"\n'
    scripts = mirror.split("<<'DOWNLOAD_SCRIPT'\n")[1:]
    if len(scripts) != 2:
        raise AssertionError("expected both mirror download helpers")
    for name, script in zip(("mirror-verifier", "mirror-deployer"), scripts):
        body = textwrap.dedent(script.split("          DOWNLOAD_SCRIPT", 1)[0])
        body = body.replace("curl --disable", 'curl --disable --cacert "$SUN_TEST_CA"')
        # The standalone helper takes three arguments; adapt the common test
        # command's additional CA argument before entering its original body.
        harnesses[name] = prefix + 'set -- "$1" "$2" "$4"\n' + body
    for name, filename in (("docs-zh", "installation.md"), ("docs-en", "installation.en.md")):
        source = (ROOT / "docs" / filename).read_text()
        body = "download_limited() {" + section(source, "download_limited() {", "\nfor asset in ")
        body = body.replace('["curl", "--disable"', '["curl", "--disable", "--cacert", os.environ["SUN_TEST_CA"]')
        harnesses[name] = prefix + body + '\nSUN_WORK="$(dirname -- "$2")"\nSUN_BASE="${4%/*}"\ndownload_limited "${4##*/}"\n'
    return harnesses


class Handler(http.server.BaseHTTPRequestHandler):
    attempts: dict[str, int] = {}

    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:
        attempt = self.attempts.get(self.path, 0) + 1
        self.attempts[self.path] = attempt
        payload = payload_for(self.path.split("/")[1])
        self.send_response(503 if self.path.endswith("/transient") and attempt == 1 else 200)
        if self.path.endswith("/oversized"):
            # No Content-Length: this exercises the download's streaming bound.
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                chunk = b"x" * (len(payload) + 4096)
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
        elif self.path.endswith("/retry") and attempt == 1:
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(b"incomplete-")
            self.wfile.flush()
        else:
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
        self.close_connection = True


def run_helper(script: Path, destination: Path, cert: Path, url: str) -> subprocess.CompletedProcess:
    environment = dict(os.environ, SUN_TEST_CA=str(cert), NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
    process = subprocess.Popen(
        ["/bin/bash", str(script), str(len(payload_for(destination.parent.name))), str(destination), str(cert), url],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=25)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sun-download-test-") as temporary:
        work = Path(temporary)
        cert, key = work / "cert.pem", work / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
             "-addext", "subjectAltName=IP:127.0.0.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for name, body in download_harnesses().items():
                script = work / (name + ".sh")
                script.write_text(body)
                (work / name).mkdir()
                for scenario in ("exact", "retry", "transient", "oversized"):
                    destination = work / name / scenario
                    destination.write_bytes(b"previous asset")
                    path = f"/{name}/{scenario}"
                    result = run_helper(script, destination, cert, f"https://127.0.0.1:{server.server_port}{path}")
                    # The documented first-install command uses curl's default
                    # retry policy: a truncated 200 must fail with no output,
                    # whereas a transient HTTP 503 is retried successfully.
                    fails = scenario == "oversized" or (scenario == "retry" and name.startswith("docs-"))
                    if fails:
                        assert result.returncode != 0, (name, scenario, "accepted failed response")
                        assert destination.read_bytes() == b"previous asset", (name, "damaged existing destination")
                    else:
                        assert result.returncode == 0, (name, scenario, result.stderr.decode())
                        assert destination.read_bytes() == payload_for(name), (name, scenario, "unexpected response bytes")
                        assert Handler.attempts[path] == (2 if scenario in ("retry", "transient") else 1)
                    assert not Path(str(destination) + ".part").exists(), (name, "left a partial download")
                print(f"{name}: exact size, interrupted response, transient retry, and chunked size limit passed")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()
