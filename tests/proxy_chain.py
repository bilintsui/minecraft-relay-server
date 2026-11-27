#!/usr/bin/env python3
"""Verify regenerated v1 headers across two relays and an optional HAProxy frontend."""

from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

from inbound_proxy import backend_socket, exchange, relay, unused_port, wait_for


@contextmanager
def frontend(binary, target, *, mapped_listener):
    with tempfile.TemporaryDirectory(prefix="mcrelay-haproxy-") as temp:
        port = unused_port()
        bind = f"[::ffff:127.0.0.1]:{port} v4v6" if mapped_listener else f"127.0.0.1:{port}"
        config = Path(temp) / "haproxy.cfg"
        config.write_text(f"""global
    maxconn 16
defaults
    mode tcp
    timeout connect 3s
    timeout client 5s
    timeout server 5s
listen minecraft
    bind {bind}
    server relay 127.0.0.1:{target} send-proxy
""")
        # -db keeps the foreground process under the test's ownership.
        with (Path(temp) / "stderr").open("w+") as errors:
            process = subprocess.Popen([binary, "-db", "-f", str(config)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors)
            try:
                def ready():
                    if process.poll() is not None:
                        errors.seek(0)
                        raise AssertionError(errors.read())
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            return True
                    except ConnectionRefusedError:
                        return False

                wait_for(ready, "HAProxy frontend readiness")
                yield port
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def check(port, backend, first, second, proxy_frontend):
    for intent in (1, 2, 3):
        listeners = ((first, proxy_frontend, len(first.lines())), (second, True, len(second.lines())))
        with socket.create_connection(("127.0.0.1", port), timeout=4) as client:
            original = client.getsockname()[1]
            source = f"127.0.0.1:{original}"
            expected = f"PROXY TCP4 127.0.0.1 127.0.0.1 {original} {port}\r\n".encode()
            exchange(client, backend, b"", expected, intent, bytes(range(256)) * 40)
            for server, proxied, start in listeners:
                entries = [s for s in server.lines()[start:] if f"src: {source}," in s and "status: accept" in s]
                assert len(entries) == 1 and "vhost: game.example," in entries[0], entries
                if proxied:
                    prefix = entries[0].split("[INFO] ", 1)[1].split(f", proxy: accepted_trusted, src: {source},", 1)
                    assert len(prefix) == 2 and prefix[0].startswith("peer: 127.0.0.1:") and prefix[0] != f"peer: {source}", entries
                else:
                    assert f"[INFO] src: {source}," in entries[0], entries


def main():
    binary = sys.argv[1]
    with backend_socket() as backend, relay(binary, {"allow_proxy": True}, backend.getsockname()[1]) as second:
        # A dual-stack listener accepts an IPv4 frontend as a trusted mapped peer.
        use_haproxy = len(sys.argv) == 3
        with relay(binary, {"address": "::", "allow_proxy": use_haproxy}, second.port) as first:
            if use_haproxy:
                # On a mapped IPv6 listener HAProxy can advertise the IPv4 client and listener with dotted TCP6 addresses.
                for mapped_listener in (False, True):
                    with frontend(sys.argv[2], first.port, mapped_listener=mapped_listener) as port:
                        check(port, backend, first, second, True)
            else:
                check(first.port, backend, first, second, False)


if __name__ == "__main__":
    main()
