"""Shared test helpers: self-signed TLS server, config writers, fake nft."""

import http.server
import os
import ssl
import subprocess
import tempfile
import threading

V4_TEST = ["203.0.113.0/25", "203.0.113.128/26", "198.51.100.0/24", "192.0.2.0/24"]
V6_TEST = ["2001:db8:1::/48", "2001:db8:2::/48"]


def make_cert(directory: str) -> tuple:
    key, crt = os.path.join(directory, "key.pem"), os.path.join(directory, "cert.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
         "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        check=True, capture_output=True)
    return key, crt


class Server:
    """HTTPS server whose responses are controlled per path via .routes."""

    def __init__(self, directory: str):
        self.key, self.cert = make_cert(directory)
        self.routes: dict = {}
        self.hits: dict = {}
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def do_GET(self):  # noqa: N802
                outer.hits[self.path] = outer.hits.get(self.path, 0) + 1
                route = outer.routes.get(self.path)
                if route is None:
                    self.send_error(404)
                    return
                if callable(route):
                    route = route(outer.hits[self.path])
                status, body, *rest = route
                headers = rest[0] if rest else {}
                self.send_response(status)
                self.send_header("Content-Type", "text/plain")
                if "X-No-Length" not in headers:
                    self.send_header("Content-Length", str(len(body)))
                for k, v in headers.items():
                    if k != "X-No-Length":
                        self.send_header(k, v)
                self.end_headers()
                if isinstance(body, str):
                    body = body.encode()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path: str) -> str:
        return f"https://127.0.0.1:{self.port}{path}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def zone(cidrs) -> str:
    return "".join(c + "\n" for c in cidrs)


def write_config(directory: str, server: Server | None = None, **overrides) -> str:
    opts = {"countries": "xx", "min_entries_v4": "1", "min_entries_v6": "1", "service_user": "", "retries": "0",
            "retry_delay": "1", "connect_timeout": "5", "download_timeout": "20"}
    if server:
        opts.update(ca_file=server.cert, ipv4_url=server.url("/{cc}-v4.zone"), ipv6_url=server.url("/{cc}-v6.zone"))
    opts.update({k: str(v) for k, v in overrides.items()})
    path = os.path.join(directory, "test.conf")
    with open(path, "w") as fh:
        fh.write("".join(f"{k} = {v}\n" for k, v in opts.items()))
    os.chmod(path, 0o644)
    return path


FAKE_NFT = """#!/bin/sh
# Fake nft for failure injection. Behaviour is controlled by files next to this script.
d=$(dirname "$0")
case "$*" in
  *"-c -f"*) [ -e "$d/fail-check" ] && { echo "Error: injected check failure" >&2; exit 1; }; exit 0;;
  *"-f -"*) [ -e "$d/fail-load" ] && { echo "Error: injected load failure" >&2; exit 1; }; cat > "$d/last-loaded"; exit 0;;
  *"list table"*) [ -e "$d/listing.json" ] && { cat "$d/listing.json"; exit 0; }; echo "Error: No such file or directory" >&2; exit 1;;
esac
exit 0
"""


def make_fake_nft(directory: str) -> str:
    path = os.path.join(directory, "nft")
    with open(path, "w") as fh:
        fh.write(FAKE_NFT)
    os.chmod(path, 0o755)
    return path


def tmpdir() -> str:
    return tempfile.mkdtemp(prefix="rugb-test-")
