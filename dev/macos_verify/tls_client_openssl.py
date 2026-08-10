#!/usr/bin/env python3
"""Long-running TLS client for the `capture:openssl-python` check.

The Swift rig client (tls_client.swift) exercises Apple's Network framework,
which lands on libboringssl.dylib. This one deliberately exercises *genuine
OpenSSL* instead: CPython's `ssl` module links whatever libssl its interpreter
was built against, which on a Homebrew or pyenv Python is
/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib rather than anything under
/usr/lib.

That library used to match no registry entry at all on macOS — the LibreSSL
entry rejected it on path, the "Python OpenSSL" entry rejected it on path (a
Homebrew path contains no "python" component), and the generic entry rejected
it on name. So friTap attached, installed nothing, and logged no keys. This
script is the target that proves the routing fix.

Keeps handshaking in a loop so friTap can attach to a live process, and prints a
line per round so the harness can tell a working client from a broken one.
"""

import socket
import ssl
import sys
import time

HOST = "127.0.0.1"
PORT = 8443


def one_round(index: int) -> bool:
    # The rig's cert is self-signed and the point here is to complete a
    # handshake, not to validate a chain — an unverified context keeps the
    # client independent of where the harness wrote cert.pem.
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((HOST, PORT), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=HOST) as tls:
                tls.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                body = tls.recv(4096)
                print(f"round={index} proto={tls.version()} status={b'200' in body}",
                      flush=True)
                return True
    except Exception as exc:  # keep looping: a transient refusal is not fatal
        print(f"round={index} error={exc}", flush=True)
        return False


def main() -> int:
    print(f"openssl={ssl.OPENSSL_VERSION}", flush=True)
    for index in range(10_000):
        one_round(index)
        time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
