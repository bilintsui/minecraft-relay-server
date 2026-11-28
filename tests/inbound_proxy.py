#!/usr/bin/env python3
"""Exercise inbound PROXY v1 through the production listener."""

from contextlib import contextmanager
import errno
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
    def __init__(self, directory, binary, listen, backend, level, pheader):
        self.port = unused_port()
        self.log = directory / "access.log"
        self.config = directory / "config.json"
        self.console = directory / "console"
        self.settings = {
            "log": {"filename": str(self.log), "level": level},
            "listen": {"address": "127.0.0.1", "port": self.port, **listen},
            "proxy": [{"vhost": "game.example", "address": "127.0.0.1", "port": backend, "pheader": pheader}],
        }
        self.config.write_text(json.dumps(self.settings))
        with self.console.open("w") as output:
            self.process = subprocess.Popen([binary, "run", "-c", str(self.config)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=output,
                                            start_new_session=True, env={k: v for k, v in os.environ.items() if k != "NOTIFY_SOCKET"})

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=4)

    def lines(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def reload(self, changes, *, error=None):
        self.settings["listen"].update(changes)
        self.config.write_text(json.dumps(self.settings))
        outcome = "[INFO] Configuration reloaded."
        if error is not None:
            field, reason = error
            outcome = f'[WARN] Invalid configuration entry "listen.{field}". Expected {reason}, will keep your old configurations'
        before = len(self.lines())
        self.process.send_signal(signal.SIGUSR1)
        wait_for(lambda: any(line.endswith(outcome) for line in self.lines()[before:]), outcome)

    def stop(self):
        try:
            self.process.terminate()
            assert self.process.wait(timeout=7) == 0, self.console.read_text()
        finally:
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()


@contextmanager
def relay(binary, listen, backend=9, level=3, *, pheader=True):
    with tempfile.TemporaryDirectory(prefix="mcrelay-inbound-") as temp:
        server = Relay(Path(temp), binary, listen, backend, level, pheader)
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


def game_request(intent):
    host = b"game.example"
    handshake = b"\x00\x2f" + bytes([len(host)]) + host + b"\x63\xdd" + bytes([intent])
    second = b"\x01\x00" if intent == 1 else b"\x03\x00\x01U"
    return bytes([len(handshake)]) + handshake + second


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        assert chunk, f"EOF after {len(data)} of {size} bytes"
        data.extend(chunk)
    return bytes(data)


@contextmanager
def backend_socket():
    with socket.socket() as backend:
        backend.bind(("127.0.0.1", 0))
        backend.listen()
        backend.settimeout(4)
        yield backend


def exchange(client, backend, header, expected_header, intent, suffix=b""):
    request = game_request(intent) + suffix
    client.sendall(header + request)
    with backend.accept()[0] as upstream:
        upstream.settimeout(4)
        expected = expected_header + request
        assert read_exact(upstream, len(expected)) == expected
        upstream.sendall(b"response")
        assert read_exact(client, 8) == b"response"


def forwarding(binary):
    declared = b"PROXY TCP4 198.51.100.23 203.0.113.8 0 25565\r\n"
    unknown = b"PROXY UNKNOWN ignored fields\r\n"
    mapped = b"PROXY TCP6 ::ffff:c633:6417 ::ffff:cb00:7108 0 25565\r\n"
    mixed = b"PROXY TCP6 ::ffff:c633:6417 2001:db8::8 0 25565\r\n"
    with backend_socket() as backend:
        for settings, outcome, cases in [
            ({}, "accepted_trusted", [(declared, declared), (unknown, None), (mapped, declared), (mixed, mixed)]),
            ({"trusted_sources": ["192.0.2.1"], "untrusted_policy": "ignore"}, "ignored_untrusted", [(declared, None), (unknown, None)]),
            ({"trusted_sources": [], "untrusted_policy": "accept"}, "accepted_untrusted", [(declared, declared), (unknown, None)]),
        ]:
            with relay(binary, {"allow_proxy": True, "proxy_settings": settings}, backend.getsockname()[1]) as server:
                for received, expected in cases:
                    for intent in (1, 2, 3):
                        with server.connect() as client:
                            actual = f"PROXY TCP4 127.0.0.1 127.0.0.1 {client.getsockname()[1]} {server.port}\r\n".encode()
                            exchange(client, backend, received, expected or actual, intent, b"extra stream bytes")
                            peer = f"127.0.0.1:{client.getsockname()[1]}"
                            source = peer if expected is None else "[::ffff:198.51.100.23]:0" if received == mixed else "198.51.100.23:0"
                            result = "unknown" if not settings and received == unknown else outcome
                            kind = {1: "motd", 2: "game", 3: "transfer"}[intent]
                            entries = [s for s in server.lines() if f"peer: {peer}," in s]
                            prefix = f"[INFO] peer: {peer}, proxy: {result}, src: {source}, type: {kind},"
                            assert len(entries) == 1 and prefix in entries[0] and "status: accept" in entries[0], entries


def access_levels(binary):
    header = b"PROXY TCP4 192.0.2.7 192.0.2.8 123 456\r\n"
    with backend_socket() as backend, relay(binary, {"allow_proxy": True}, backend.getsockname()[1], level=2) as incoming:
        with incoming.connect() as client:
            port = client.getsockname()[1]
            exchange(client, backend, header, header, 1)
            assert all(f"peer: 127.0.0.1:{port}," not in s for s in incoming.lines())
        for intent in (1, 2):
            with incoming.connect() as client:
                port = client.getsockname()[1]
                client.sendall(header + game_request(intent).replace(b"game.example", b"none.example"))
                assert client.recv(1)
                records = [s for s in incoming.lines() if f"peer: 127.0.0.1:{port}," in s]
                prefix = f"[WARN] peer: 127.0.0.1:{port}, proxy: accepted_trusted, src: 192.0.2.7:123, "
                assert len(records) == 1 and prefix in records[0] and "reject_vhostinvalid" in records[0], records


def access_aborts(binary):
    header = b"PROXY TCP6 2001:db8::7 2001:db8::8 123 456\r\n"
    peer = "127.0.0.1:{port}"
    with relay(binary, {}) as direct:
        reject(direct, [], f"[WARN] src: {peer}, status: abort_init", finish=True)
    for settings, cases in [
        ({}, [(header, "accepted_trusted", "[2001:db8::7]:123"), (b"PROXY UNKNOWN\r\n", "unknown", peer)]),
        ({"trusted_sources": [], "untrusted_policy": "accept"}, [(header, "accepted_untrusted", "[2001:db8::7]:123")]),
        ({"trusted_sources": [], "untrusted_policy": "ignore"}, [(header, "ignored_untrusted", peer)]),
    ]:
        with relay(binary, {"allow_proxy": True, "proxy_settings": settings}) as server:
            for wire, outcome, source in cases:
                reject(server, [wire], f"[WARN] peer: {peer}, proxy: {outcome}, src: {source}, status: abort_init", finish=True)


def forwarding_without_header(binary):
    header = b"PROXY TCP4 192.0.2.7 192.0.2.8 123 456\r\n"
    with backend_socket() as backend:
        for policy in ("ignore", "accept"):
            listen = {"allow_proxy": True, "proxy_settings": {"trusted_sources": [], "untrusted_policy": policy}}
            with relay(binary, listen, backend.getsockname()[1], pheader=False) as server:
                for intent in (1, 2, 3):
                    with server.connect() as client:
                        exchange(client, backend, header, b"", intent, bytes(range(256)))


def reload_and_errors(binary):
    with backend_socket() as backend, relay(binary, {"allow_proxy": True}, backend.getsockname()[1]) as server:
        header = b"PROXY TCP4 192.0.2.10 192.0.2.11 123 456\r\n"
        # The extra accepted socket and assembly timer prove the old policy was captured before SIGUSR1.
        fd_dir = Path(f"/proc/{server.process.pid}/fd")
        assert (fd_dir / "2").samefile(os.devnull), "listener retained the startup error stream after readiness"
        baseline = len(list(fd_dir.iterdir()))
        with server.connect() as held:
            held.sendall(b"PRO")
            wait_for(lambda: len(list(fd_dir.iterdir())) >= baseline + 2, "old connection acceptance")
            server.reload({"allow_proxy": False, "proxy_settings": {"trusted_sources": []}})
            reject(server, [b"PROXY "], "[WARN] src: 127.0.0.1:{port}, status: reject_invalid_protocol, received: proxy_v1, expected: minecraft")
            exchange(held, backend, header[3:], header, 2)
        server.reload({"allow_proxy": True})
        reject(server, [], "[WARN] peer: 127.0.0.1:{port}, status: reject_proxy_exception, exception: untrusted_source")
        active_log = server.settings["log"]
        candidate_log = server.log.with_name("candidate.log")
        server.settings["log"] = {"filename": str(candidate_log), "level": 0}
        for settings, field, reason in [
            ({"untrusted_policy": "Accept"}, "untrusted_policy", '"reject", "ignore" or "accept"'),
            ({"trusted_sources": ["::1", "localhost"]}, "trusted_sources[1]", "an IPv4 or IPv6 address"),
            ({"trusted_source": []}, "trusted_source", "version, trusted_sources or untrusted_policy"),
        ]:
            server.reload({"proxy_settings": settings}, error=(f"proxy_settings.{field}", reason))
        assert not candidate_log.exists(), "rejected configuration opened its log"
        server.settings["log"] = active_log
        reject(server, [], "[WARN] peer: 127.0.0.1:{port}, status: reject_proxy_exception, exception: untrusted_source")
        server.reload({"allow_proxy": False, "proxy_settings": {}})
        with server.connect() as direct:
            actual = f"PROXY TCP4 127.0.0.1 127.0.0.1 {direct.getsockname()[1]} {server.port}\r\n".encode()
            exchange(direct, backend, b"", actual, 1)
        server.reload({"allow_proxy": True, "proxy_settings": {"version": 1}})
        server.reload({"proxy_settings": {"version": 2}}, error=("proxy_settings.version", "the number 1"))
        with server.connect() as retained:
            exchange(retained, backend, header, header, 1)
        assert "Invalid configuration entry" not in server.console.read_text()
        warnings = [line for line in server.lines() if "Invalid configuration entry" in line or "Configuration reload rejected" in line]
        assert len(warnings) == 4, warnings
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


def socket_errors(binary):
    declared = b"PROXY TCP4 192.0.2.10 192.0.2.11 123 456\r\n"
    reason = "[WARN] peer: 127.0.0.1:{port}, status: reject_proxy_exception, exception: socket_endpoints_unavailable, error: " + os.strerror(errno.ENOTCONN)
    with backend_socket() as backend, relay(binary, {"allow_proxy": True}, backend.getsockname()[1]) as server:
        reject(server, [b"PROXY UNKNOWN\r\n"], reason)
        # A declared pair requires no socket lookup.
        with server.connect() as client:
            exchange(client, backend, declared, declared, 1)
        server.reload({"proxy_settings": {"trusted_sources": [], "untrusted_policy": "ignore"}})
        reject(server, [declared], reason)


def short_abort(binary):
    header = b"PROXY TCP4 192.0.2.7 192.0.2.8 123 456\r\n"
    expected = "[WARN] peer: 127.0.0.1:{port}, proxy: accepted_trusted, src: 192.0.2.7:123, status: abort_short"
    with relay(binary, {"allow_proxy": True}) as server:
        reject(server, [header + game_request(1)], expected)
        # Zero-TTL answers from the test resolver make the next route complete asynchronously.
        server.settings["proxy"][0]["address"] = "backend.test"
        server.reload({})
        reject(server, [header + game_request(1)], expected)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[2] == "socket-errors":
        socket_errors(sys.argv[1])
    elif len(sys.argv) == 3 and sys.argv[2] == "short-abort":
        short_abort(sys.argv[1])
    else:
        access_aborts(sys.argv[1])
        access_levels(sys.argv[1])
        admission(sys.argv[1])
        forwarding(sys.argv[1])
        forwarding_without_header(sys.argv[1])
        reload_and_errors(sys.argv[1])
