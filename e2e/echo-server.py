"""HTTPS echo server that reflects request headers back as JSON.

Used by e2e tests to verify Envoy credential injection.
Runs on port 443 with a self-signed certificate.
"""
import ssl
import json
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

# Generate self-signed cert
subprocess.run(
    [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", "/tmp/key.pem", "-out", "/tmp/cert.pem",
        "-days", "1", "-nodes", "-subj", "/CN=echo-server",
    ],
    check=True,
    capture_output=True,
)


class EchoHandler(BaseHTTPRequestHandler):
    def _respond(self):
        headers = {k: v for k, v in self.headers.items()}
        body = json.dumps({
            "headers": headers,
            "path": self.path,
            "method": self.command,
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def log_message(self, *args):
        pass


server = HTTPServer(("0.0.0.0", 443), EchoHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print("Echo server ready on :443", flush=True)
server.serve_forever()
