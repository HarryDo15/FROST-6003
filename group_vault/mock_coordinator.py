"""Local-only mock for Week 3; no cryptography, authentication, or signing."""

from __future__ import annotations

import argparse
import base64
import json
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        url = urlsplit(self.path)
        if url.path != "/requests/pending":
            self._reply(404, {"error": "unknown endpoint"})
            return
        nodes = parse_qs(url.query).get("node_id", [])
        if len(nodes) != 1 or not nodes[0].strip():
            self._reply(400, {"error": "one node_id is required"})
            return
        eligible = ["1", "2", "3", "4", "5"]
        requests = []
        if nodes[0] in eligible:
            requests.append(
                {
                    "request_id": "demo-request-001",
                    "vault_id": "week2-demo",
                    "node_ids": eligible,
                    "message_b64": base64.b64encode(b"Week 3 mock request").decode("ascii"),
                }
            )
        self._reply(200, {"api_version": "demo-v1", "requests": requests})

    def _reply(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        # Avoid logging unsanitized request paths or message data.
        pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Week 3 localhost mock coordinator")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    try:
        with ThreadingHTTPServer(("127.0.0.1", args.port), MockHandler) as server:
            print(f"[MOCK] listening on http://127.0.0.1:{args.port}; Ctrl+C to stop", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                print("\n[MOCK] stopped", flush=True)
    except OSError as exc:
        parser.exit(1, f"Cannot start mock coordinator: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
