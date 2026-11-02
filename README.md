# mtls-demo

A working, from-scratch demonstration of **mutual TLS (mTLS)**: an HTTPS
server that requires every client to present a certificate signed by a
trusted CA, and reads the client's identity directly from that
certificate (no separate login/password step needed). This is the same
pattern used for service-to-service auth in zero-trust architectures,
Kubernetes service meshes, and internal APIs.

## What this demonstrates

- Normal TLS only proves the **server's** identity to the client.
- **mTLS** also proves the **client's** identity to the server — the
  server's `ssl.CERT_REQUIRED` + `load_verify_locations` rejects any
  connection that doesn't present a cert signed by the trusted CA, at the
  handshake level, before any application code even runs.
- The server then reads the client cert's Common Name
  (`getpeercert()`) to know *who* connected — this is a form of
  certificate-based authentication.

## Install

```bash
pip install -r requirements.txt
```

## Run it

**1. Generate the CA, server cert, and client cert:**
```bash
python setup_certs.py
```
This creates `certs/ca.{key,crt}`, `certs/server.{key,crt}`, and
`certs/client.{key,crt}`.

**2. Start the server (in one terminal):**
```bash
python server.py
```

**3. Connect with the client (in another terminal):**
```bash
python client.py
```
Expected output:
```
HTTP/1.0 200 OK
...
Hello, demo-client-01! Your client certificate was verified.
```

**4. See what happens without a client certificate:**
```bash
python client.py --no-client-cert
```
Expected output:
```
[!] TLS handshake failed: EOF occurred in violation of protocol
[*] This is expected — the server requires a client certificate and we didn't send one.
```

## How the identity flows

1. `setup_certs.py` creates a CA, then issues a server cert (CN=localhost)
   and a client cert (CN=demo-client-01), both signed by that CA.
2. `server.py` is configured with `verify_mode = ssl.CERT_REQUIRED` and
   trusts the CA — so only certs signed by it will complete the handshake.
3. `client.py` presents its client cert during the handshake.
4. Once connected, `server.py` calls `self.connection.getpeercert()` and
   pulls the client's Common Name straight out of the verified
   certificate to know who's talking to it.

## Ideas to extend

- Issue multiple client certs for different "users" and have the server
  authorize different endpoints based on CN (simple RBAC via certs)
- Add client certificate revocation checking (wire in `revocation-checker`)
- Swap the hand-rolled CA in `setup_certs.py` for `mini-ca-toolkit`'s
  intermediate hierarchy, for a more realistic multi-tier setup
- Containerize server and client separately to simulate real service-to-service mTLS

## License

MIT
