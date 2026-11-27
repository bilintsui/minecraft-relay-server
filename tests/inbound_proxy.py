#!/usr/bin/env python3
"""Exercise inbound PROXY v1 through the production listener."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


def wait_for(check, description, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.01)
    raise AssertionError(description)


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Relay:
    def __init__(self, directory, binary, listen, backend, level):
        self.port = unused_port()
        self.log = directory / "access.log"
        self.config = directory / "config.json"
        self.console = directory / "console"
        self.settings = {
            "log": {"filename": str(self.log), "level": level},
            "listen": {"address": "127.0.0.1", "port": self.port, **listen},
            "proxy": [{"vhost": "game.example", "address": "127.0.0.1", "port": backend, "pheader": True}],
        }
        self.config.write_text(json.dumps(self.settings))
        with self.console.open("w") as output:
            self.process = subprocess.Popen([binary, "run", "-c", str(self.config)], stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                            start_new_session=True, env={k: v for k, v in os.environ.items() if k != "NOTIFY_SOCKET"})

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=4)

    def lines(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def stop(self):
        try:
            self.process.terminate()
            assert self.process.wait(timeout=7) == 0, self.console.read_text()
        finally:
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()


@contextmanager
def relay(binary, listen, backend=9, level=3):
    with tempfile.TemporaryDirectory(prefix="mcrelay-inbound-") as temp:
        server = Relay(Path(temp), binary, listen, backend, level)
        try:
            wait_for(lambda: any("accepting connections." in s for s in server.lines()), "listener readiness")
            yield server
        finally:
            server.stop()


def require_close(sock):
    try:
        assert sock.recv(1) == b"", "unexpected application reply"
    except ConnectionResetError:
        pass


def reject(server, chunks, expected, finish=False):
    with server.connect() as sock:
        port = sock.getsockname()[1]
        for data in chunks:
            sock.sendall(data)
        if finish:
            sock.shutdown(socket.SHUT_WR)
        require_close(sock)
    entries = [s for s in server.lines() if f"127.0.0.1:{port}," in s]
    assert len(entries) == 1 and entries[0].endswith(expected.format(port=port)), (expected, entries)


def admission(binary):
    v2 = b"\r\n\r\n\0\r\nQUIT\n"
    with relay(binary, {}) as direct:
        for payload, protocol in [(b"PROXY ", "proxy_v1"), (v2, "proxy_v2"), (b"\0", "unknown")]:
            reject(direct, [payload], "[WARN] src: 127.0.0.1:{port}, status: reject_invalid_protocol, received: " + protocol + ", expected: minecraft")
    with relay(binary, {"allow_proxy": True}) as incoming:
        for payload, protocol in [(b"\xfe", "minecraft"), (v2, "proxy_v2"), (b"X", "unknown")]:
            reject(incoming, [payload], "[WARN] src: 127.0.0.1:{port}, status: reject_invalid_protocol, received: " + protocol + ", expected: proxy_v1")

        def fragmented_v2():
            yield v2[:4]
            # Let the listener serve another connection before supplying the rest of the signature.
            with incoming.connect() as ping:
                ping.sendall(b"PROXY UNKNOWN\r\n\xfe")
                assert ping.recv(1) == b"\xff"
            yield v2[4:]

        reject(incoming, fragmented_v2(), "[WARN] src: 127.0.0.1:{port}, status: reject_invalid_protocol, received: proxy_v2, expected: proxy_v1")
        reason = "[WARN] peer: 127.0.0.1:{port}, status: reject_proxy_exception, exception: "
        reject(incoming, [b"PROXY TCP5\r\n"], reason + "malformed_header")
        reject(incoming, [b"PROXY UNKNOWN " + b"x" * 93], reason + "header_too_long")
        reject(incoming, [b"PROXY UNKNOWN\r"], reason + "header_eof", finish=True)
        with incoming.connect() as sock:
            sock.sendall(b"PROXY UNKNOWN\r")
            time.sleep(0.05)
            sock.sendall(b"\n\xfe")
            assert sock.recv(1) == b"\xff", "fragmented header lost the legacy ping"
    with relay(binary, {"allow_proxy": True, "proxy_settings": {"trusted_sources": []}}) as untrusted:
        reject(untrusted, [], reason + "untrusted_source")


def header_errors(binary):
    with relay(binary, {"allow_proxy": True}) as server:
        with server.connect() as reset:
            port = reset.getsockname()[1]
            reset.sendall(b"PROXY ")
            reset.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        match = f"peer: 127.0.0.1:{port}, status: reject_proxy_exception, exception: read_error, error: "
        wait_for(lambda: any(match in line for line in server.lines()), "header read error with saved errno")
        with server.connect() as partial:
            port = partial.getsockname()[1]
            partial.sendall(b"PROXY UNKNOWN\r")
            partial.settimeout(20)
            require_close(partial)
        match = f"peer: 127.0.0.1:{port}, status: reject_proxy_exception, exception: header_timeout"
        assert sum(line.endswith(match) for line in server.lines()) == 1


if __name__ == "__main__":
    admission(sys.argv[1])
    header_errors(sys.argv[1])
