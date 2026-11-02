#!/usr/bin/env python3
"""
client.py
Connects to the mTLS demo server, presenting a client certificate. Run
with --no-client-cert to see the handshake get rejected instead.
"""

import argparse
import ssl
import socket

CERT_DIR = "certs"
HOST, PORT = "localhost", 8443


def main():
    parser = argparse.ArgumentParser(description="mTLS demo client")
    parser.add_argument("--no-client-cert", action="store_true",
                         help="Connect WITHOUT presenting a client cert, to see the server reject it")
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=f"{CERT_DIR}/ca.crt")  # trust our demo CA for the server cert

    if not args.no_client_cert:
        context.load_cert_chain(certfile=f"{CERT_DIR}/client.crt", keyfile=f"{CERT_DIR}/client.key")

    try:
        with socket.create_connection((HOST, PORT), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as tls_sock:
                tls_sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                response = b""
                while True:
                    chunk = tls_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                print(response.decode(errors="replace"))
    except ssl.SSLError as e:
        print(f"[!] TLS handshake failed: {e}")
        if args.no_client_cert:
            print("[*] This is expected — the server requires a client certificate and we didn't send one.")


if __name__ == "__main__":
    main()
