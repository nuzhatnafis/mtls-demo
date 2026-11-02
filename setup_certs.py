#!/usr/bin/env python3
"""
setup_certs.py
Generates a tiny CA, a server certificate, and a client certificate for
the mTLS demo — everything needed to run server.py and client.py.
"""

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT_DIR = "certs"


def gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def save(key, cert, name):
    with open(os.path.join(OUT_DIR, f"{name}.key"), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(os.path.join(OUT_DIR, f"{name}.crt"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    # --- CA ---
    ca_key = gen_key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mTLS Demo CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    save(ca_key, ca_cert, "ca")
    print("[+] CA created")

    # --- Server cert (CN=localhost, SAN=localhost/127.0.0.1) ---
    server_key = gen_key()
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name).issuer_name(ca_name)
        .public_key(server_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    save(server_key, server_cert, "server")
    print("[+] Server certificate created (CN=localhost)")

    # --- Client cert (identifies a specific user) ---
    client_key = gen_key()
    client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo-client-01")])
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name).issuer_name(ca_name)
        .public_key(client_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    save(client_key, client_cert, "client")
    print("[+] Client certificate created (CN=demo-client-01)")

    print(f"\nAll files written to ./{OUT_DIR}/")
    print("Run: python server.py   (in one terminal)")
    print("Run: python client.py   (in another terminal)")


if __name__ == "__main__":
    main()
