import http.server
import json
import socketserver
import threading
import time
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "analisador-logs-identificacao" / "analisador-logs.sh"


def run(args, **kwargs):
    import subprocess, sys

    cmd = [str(SCRIPT)] + args
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def test_webhook_receives_json(tmp_path):
    # Create a small auth.log with failed attempts
    log = tmp_path / "auth.log"
    log.write_text(
        "\n".join([
            "Jan 12 10:00:00 host sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2",
            "Jan 12 10:00:01 host sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2",
            "Jan 12 10:00:02 host sshd[1]: Failed password for invalid user admin from 203.0.113.6 port 22 ssh2",
        ])
    )

    out = tmp_path / "report.json"

    # Simple HTTP server to capture POST body
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            # store received payload on the server object
            self.server.received.append(body)
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args):
            # silence logs during tests
            return

    httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    httpd.received = []
    port = httpd.server_address[1]

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    try:
        res = run([
            "--log-file",
            str(log),
            "--threshold",
            "1",
            "--output",
            str(out),
            "--webhook",
            f"http://127.0.0.1:{port}",
        ], timeout=10)
        assert res.returncode == 0, (res.stdout.decode(), res.stderr.decode())

        # wait for server to receive the POST
        deadline = time.time() + 5
        while time.time() < deadline and not httpd.received:
            time.sleep(0.1)

        assert httpd.received, "Webhook did not receive any POST"
        body = httpd.received[0]
        data = json.loads(body.decode())
        assert "timestamp" in data
        assert "report_lines" in data
        # Ensure one of the report lines contains the IP we expect
        joined = "\n".join(data.get("report_lines", []))
        assert "203.0.113.5" in joined

    finally:
        httpd.shutdown()
        thread.join(timeout=1)
