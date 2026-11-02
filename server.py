#!/usr/bin/env python3
"""
server.py
A minimal HTTPS server that REQUIRES clients to present a valid
certificate signed by our demo CA (mutual TLS / mTLS). Connections
without a valid client cert are rejected at the TLS handshake level,
before any application code runs.
"""

import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

CERT_DIR = "certs"
HOST, PORT = "localhost", 8443


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # self.connection is the wrapped SSL socket; getpeercert() gives us
        # the verified client certificate's fields.
        peer_cert = self.connection.getpeercert()
        client_cn = None
        if peer_cert:
            for field in peer_cert.get("subject", ()):
                for key, value in field:
                    if key == "commonName":
                        client_cn = value

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"Hello, {client_cn}! Your client certificate was verified.\n".encode())

    def log_message(self, fmt, *args):
        print("[server]", fmt % args)


def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=f"{CERT_DIR}/server.crt", keyfile=f"{CERT_DIR}/server.key")

    # This is what makes it mTLS: require AND verify a client certificate.
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=f"{CERT_DIR}/ca.crt")

    httpd = HTTPServer((HOST, PORT), Handler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"[*] mTLS server listening on https://{HOST}:{PORT}")
    print("[*] Only clients presenting a cert signed by our demo CA will be accepted.")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
