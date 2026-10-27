"""Loopback-only streaming reverse proxy for private/self-signed model endpoints."""

from __future__ import annotations

import argparse
import http.client
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HOP_BY_HOP = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def handler(
    upstream_url: str, api_key_env: str, verify_tls: bool
) -> type[BaseHTTPRequestHandler]:
    upstream = urlsplit(upstream_url)
    if upstream.scheme not in {"http", "https"} or not upstream.hostname:
        raise ValueError("upstream must be an HTTP(S) URL")
    base_path = upstream.path.rstrip("/")

    class ProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _forward(self) -> None:
            if self.headers.get("Transfer-Encoding"):
                self.send_error(411, "chunked request bodies are not supported")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400, "invalid Content-Length")
                return
            body = self.rfile.read(length) if length else None
            headers = {
                key: value
                for key, value in self.headers.items()
                if key.lower() not in HOP_BY_HOP
            }
            headers["Authorization"] = f"Bearer {os.environ[api_key_env]}"
            target = base_path + self.path
            port = upstream.port or (443 if upstream.scheme == "https" else 80)
            if upstream.scheme == "https":
                context = (
                    ssl.create_default_context()
                    if verify_tls
                    else ssl._create_unverified_context()
                )
                connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                    upstream.hostname, port, timeout=30, context=context
                )
            else:
                connection = http.client.HTTPConnection(
                    upstream.hostname, port, timeout=30
                )
            try:
                connection.request(self.command, target, body=body, headers=headers)
                response = connection.getresponse()
                if connection.sock is not None:
                    connection.sock.settimeout(None)
                self.send_response(response.status, response.reason)
                for key, value in response.getheaders():
                    if key.lower() not in HOP_BY_HOP:
                        self.send_header(key, value)
                self.send_header("Connection", "close")
                self.end_headers()
                while True:
                    chunk = response.read1(64 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (OSError, http.client.HTTPException) as error:
                if not self.wfile.closed:
                    self.close_connection = True
                raise ConnectionError("upstream model endpoint failed") from error
            finally:
                connection.close()
                self.close_connection = True

        do_GET = _forward
        do_POST = _forward
        do_PUT = _forward
        do_DELETE = _forward
        do_PATCH = _forward

    return ProxyHandler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--api-key-env", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--verify-tls", action="store_true")
    args = parser.parse_args()
    if not os.environ.get(args.api_key_env):
        parser.error(f"environment variable is not set: {args.api_key_env}")
    server = ThreadingHTTPServer(
        ("127.0.0.1", args.port),
        handler(args.upstream, args.api_key_env, args.verify_tls),
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
