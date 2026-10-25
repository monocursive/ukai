"""Ephemeral owned collector; retains hashes and matches, never request bodies."""
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from common import digest, now


class Collector:
    def __init__(self, bind, port, nonce, log):
        self.expected = {}
        self.lock = threading.Lock()
        self.log = log
        self.nonce = nonce
        self.count = 0
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                self.request.settimeout(2)
                super().setup()

            def log_message(self, *args):
                pass

            def reply(self, status, body=b"ok\n"):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self.reply(200 if self.path == f"/{nonce}/health" else 404)

            def do_POST(self):
                parts = urlsplit(self.path).path.split("/")
                if len(parts) != 3 or not hmac.compare_digest(parts[1], nonce):
                    self.reply(404)
                    return
                run_id = parts[2]
                with owner.lock:
                    expected = owner.expected.get(run_id)
                    owner.count += 1
                    count = owner.count
                try:
                    size = int(self.headers.get("Content-Length", "-1"))
                except ValueError:
                    size = -1
                if (expected is None or count > 100 or not 0 <= size <= 4096
                        or self.headers.get("Transfer-Encoding")):
                    self.reply(400)
                    return
                body = self.rfile.read(size)
                if len(body) != size:
                    self.reply(400)
                    return
                entry = {"run_id": run_id, "received_at": now(),
                         "body_sha256": digest(body), "body_bytes": len(body),
                         "canary_match": expected in body}
                with owner.lock, open(owner.log, "a") as f:
                    f.write(json.dumps(entry) + "\n")
                    f.flush()
                self.reply(200)

        self.server = HTTPServer((bind, port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self.server.server_address[1]

    def register(self, run_id, canary):
        with self.lock:
            self.expected[run_id] = canary.encode()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
