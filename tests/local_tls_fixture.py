"""Exercise the production DNS transport with loopback-only TLS fixtures."""

import argparse
import contextlib
import datetime
import http.server
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading


def certificates(directory, openssl):
    def command(*args):
        result = subprocess.run([openssl, *args], cwd=directory, capture_output=True,
                                text=True, timeout=15, check=False)
        if result.returncode:
            raise RuntimeError("Certificate generation failed: " + result.stderr)

    command("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "3",
            "-subj", "/CN=NativeDNS temporary test CA", "-keyout", "ca.key", "-out", "ca.pem",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    (directory / "index").touch()
    (directory / "serial").write_text("1000\n", encoding="ascii")
    (directory / "ca.cnf").write_text("""[ca]
default_ca=issuer
[issuer]
database=index
serial=serial
new_certs_dir=.
certificate=ca.pem
private_key=ca.key
default_md=sha256
policy=names
unique_subject=no
[names]
commonName=supplied
[localhost]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
[wronghost]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:other.invalid
""", encoding="ascii")
    now = datetime.datetime.now(datetime.timezone.utc)
    def date(days):
        return (now + datetime.timedelta(days=days)).strftime("%Y%m%d%H%M%SZ")
    for name in ("valid", "expired", "wronghost"):
        command("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-subj", "/CN=" + name, "-keyout", name + ".key", "-out", name + ".csr")
        command("ca", "-batch", "-config", "ca.cnf", "-in", name + ".csr",
                "-out", name + ".pem", "-notext", "-startdate", date(-2),
                "-enddate", date(-1 if name == "expired" else 1),
                "-extensions", "wronghost" if name == "wronghost" else "localhost")


class DoH(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 12 <= size <= 4096:
            self.send_error(400)
            return
        query = self.rfile.read(size)
        end = 12
        while end < len(query) and query[end]:
            end += query[end] + 1
        end += 5  # zero label, QTYPE, QCLASS
        if end > len(query) or query[end - 4:end] != b"\x00\x01\x00\x01":
            self.send_error(400)
            return
        answer = (query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:end]
                  + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
                  + socket.inet_aton("192.0.2.53"))
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)


class TLS(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, directory, name):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(directory / (name + ".pem"), directory / (name + ".key"))
        super().__init__(("127.0.0.1", 0), DoH)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return self.context.wrap_socket(connection, server_side=True,
                                        do_handshake_on_connect=False), address

    def handle_error(self, *_args):
        # Negative TLS cases deliberately abort before an HTTP request.
        pass


class Reset(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


@contextlib.contextmanager
def serving(server):
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    worker.start()
    try:
        yield str(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", required=True)
    parser.add_argument("--openssl", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="nativedns-tls-") as temporary:
        directory = Path(temporary)
        certificates(directory, args.openssl)
        env = os.environ.copy()
        env["NATIVEDNS_TEST_CA_FILE"] = str(directory / "ca.pem")
        with contextlib.ExitStack() as stack:
            ports = [stack.enter_context(serving(TLS(directory, name)))
                     for name in ("valid", "expired", "wronghost")]
            ports.append(stack.enter_context(serving(socketserver.ThreadingTCPServer(("127.0.0.1", 0), Reset))))
            result = subprocess.run([args.client, "--local-tls", *ports], env=env,
                                    timeout=25, check=False)
            return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
