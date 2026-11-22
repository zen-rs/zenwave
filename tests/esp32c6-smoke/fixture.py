#!/usr/bin/env python3
"""Minimal host-side HTTP/1.1 + TLS 1.3 fixture for the esp-emu smoke test."""
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Fixture(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        reused = getattr(self.connection, "session_reused", None)
        body = f"ZENWAVE_ESP32C6_SMOKE_OK reused={reused}\n".encode()
        wants_close = "close=1" in self.path
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        if wants_close:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        if wants_close:
            self.close_connection = True
        print(f"FIXTURE_HIT {self.path} tls_reused={reused}", flush=True)

    def log_message(self, *args):
        pass


def serve_https():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain("certs/server.pem", "certs/server.key")
    server = ThreadingHTTPServer(("127.0.0.1", 8443), Fixture)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


threading.Thread(target=serve_https, daemon=True).start()
ThreadingHTTPServer(("127.0.0.1", 8080), Fixture).serve_forever()
