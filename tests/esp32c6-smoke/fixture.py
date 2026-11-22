#!/usr/bin/env python3
"""Minimal host-side HTTP/HTTPS fixture for the esp-emu smoke test."""
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ZENWAVE_ESP32C6_SMOKE_OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"FIXTURE_HIT {self.path}", flush=True)

    def log_message(self, *args):
        pass


def serve_https():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("certs/server.pem", "certs/server.key")
    server = ThreadingHTTPServer(("127.0.0.1", 8443), Fixture)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


threading.Thread(target=serve_https, daemon=True).start()
ThreadingHTTPServer(("127.0.0.1", 8080), Fixture).serve_forever()
