#!/usr/bin/env python3
"""Minimal local HTTPS server for the macOS verification rig.

Deliberately tiny and dependency-free: the point is to give the Swift client
something to complete a real TLS handshake against, entirely on loopback, so
the rig needs no outbound network and no third-party test service.

The cert/key are expected in the working directory (see verify.sh, which
generates them with openssl). Usage:

    python3 tls_server.py [--port 8443] [--cert cert.pem] [--key key.pem]
"""

import argparse
import http.server
import ssl


class QuietHandler(http.server.BaseHTTPRequestHandler):
    """Answers every GET with a 3-byte body and logs nothing.

    Silence matters: the rig greps friTap's output, and a chatty server
    interleaved on the same terminal makes those assertions unreliable.
    """

    def do_GET(self):
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", default="cert.pem")
    parser.add_argument("--key", default="key.pem")
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), QuietHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
