#!/usr/bin/env python3
"""Check binary PROXY headers, their stream boundaries and effective endpoints."""

from pathlib import Path
import socket
import struct
import sys

from inbound_proxy import backend_socket, exchange, game_request, reject, relay, require_close, wait_for


SIGNATURE = b"\r\n\r\n\0\r\nQUIT\n"
LISTEN = {"allow_proxy": True, "proxy_settings": {"version": 2}}
EXCEPTION = "[WARN] peer: 127.0.0.1:{port}, status: reject_proxy_exception, exception: "


def header(command, family, payload=b""):
    return SIGNATURE + struct.pack("!BBH", command, family, len(payload)) + payload


def tcp(source, destination, sport, dport, tail=b""):
    ipv6 = ":" in source
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    addresses = socket.inet_pton(family, source) + socket.inet_pton(family, destination)
    return header(0x21, 0x21 if ipv6 else 0x11, addresses + struct.pack("!HH", sport, dport) + tail)


def admission(binary):
    with relay(binary, LISTEN) as server:
        for data, received in [(b"\xfe", "minecraft"), (b"PROXY ", "proxy_v1"), (b"X", "unknown")]:
            reject(server, [data], "[WARN] src: 127.0.0.1:{port}, status: reject_invalid_protocol, received: " + received + ", expected: proxy_v2")
        for data in [header(0x11, 0), header(0x22, 0), header(0x21, 0x41), header(0x21, 0x11, bytes(11)), header(0x21, 0x21, bytes(35))]:
            reject(server, [data], EXCEPTION + "malformed_header")
        for data in [SIGNATURE[:6], header(0x20, 0xff, b"opaque")[:-1], tcp("192.0.2.1", "198.51.100.2", 1, 2)[:-1]]:
            reject(server, [data], EXCEPTION + "header_eof", finish=True)
    for policy in ("ignore", "accept", "reject"):
        settings = {"version": 2, "trusted_sources": [], "untrusted_policy": policy}
        with relay(binary, {"allow_proxy": True, "proxy_settings": settings}) as server:
            if policy == "reject":
                reject(server, [], EXCEPTION + "untrusted_source")
            else:
                reject(server, [header(0x22, 0)], EXCEPTION + "malformed_header")


def forwarding(binary):
    declared = tcp("198.51.100.23", "203.0.113.8", 0, 65535)
    v1 = b"PROXY TCP4 198.51.100.23 203.0.113.8 0 65535\r\n"
    with backend_socket() as backend:
        for policy in ("trusted", "ignore", "accept"):
            settings = {"version": 2}
            if policy != "trusted":
                settings.update(trusted_sources=[], untrusted_policy=policy)
            with relay(binary, {"allow_proxy": True, "proxy_settings": settings}, backend.getsockname()[1]) as server:
                for data, supplied in [(declared, True), (header(0x20, 0xff, b"unused"), False), (header(0x21, 0), False),
                                       (header(0x21, 0x12, bytes(12)), False), (header(0x21, 0x31, bytes(216)), False)]:
                    with server.connect() as client:
                        port = client.getsockname()[1]
                        actual = f"PROXY TCP4 127.0.0.1 127.0.0.1 {port} {server.port}\r\n".encode()
                        use_header = supplied and policy != "ignore"
                        exchange(client, backend, data, v1 if use_header else actual, 1)
                        outcome = {"trusted": "accepted_trusted" if supplied else "unknown", "ignore": "ignored_untrusted", "accept": "accepted_untrusted"}[policy]
                        source = "198.51.100.23:0" if use_header else f"127.0.0.1:{port}"
                        entries = [line for line in server.lines() if f"peer: 127.0.0.1:{port}," in line]
                        assert len(entries) == 1 and f"proxy: {outcome}, src: {source}," in entries[0] and "status: accept" in entries[0], entries


def header_timeout(binary):
    with relay(binary, LISTEN) as server, server.connect() as partial:
        port = partial.getsockname()[1]
        partial.settimeout(20)
        partial.sendall(tcp("192.0.2.1", "198.51.100.2", 1, 2, b"\xe1\x00\x01Z")[:-1])
        require_close(partial)
        entries = [line for line in server.lines() if f"127.0.0.1:{port}," in line]
        assert len(entries) == 1 and entries[0].endswith(EXCEPTION.format(port=port) + "header_timeout"), entries


def stream_and_reload(binary):
    # The 12 address bytes, TLV prefix and value together exhaust the 16-bit length field.
    value = game_request(1).ljust(65520, b"\0")
    opaque = struct.pack("!BH", 0xe1, len(value)) + value
    wire = tcp("192.0.2.1", "198.51.100.2", 1234, 25565, opaque)
    assert len(wire) == 16 + 65535
    expected = b"PROXY TCP4 192.0.2.1 198.51.100.2 1234 25565\r\n"
    with backend_socket() as backend, relay(binary, LISTEN, backend.getsockname()[1]) as server:
        descriptors = Path(f"/proc/{server.process.pid}/fd")
        baseline = len(list(descriptors.iterdir()))
        with server.connect() as held:
            held.sendall(wire[:8])
            wait_for(lambda: len(list(descriptors.iterdir())) >= baseline + 2, "v2 connection acceptance")
            held.sendall(wire[8:-1])
            # An independent request proves the listener stays available while the last extension byte is missing.
            with server.connect() as control:
                exchange(control, backend, tcp("192.0.2.1", "198.51.100.2", 1234, 25565), expected, 1)
            server.reload({"proxy_settings": {"version": 1}})
            with server.connect() as fresh:
                exchange(fresh, backend, expected, expected, 1)
            exchange(held, backend, wire[-1:], expected, 2, bytes(range(256)))


def outbound(binary):
    tail = b"\xe1\x00\x03abc\x03\x00\x04\x00\x00\x00\x00"
    with backend_socket() as backend:
        for enabled in (False, True):
            with relay(binary, LISTEN, backend.getsockname()[1], pheader=enabled, pheader_version=2) as server:
                for source, destination, expected_source, expected_destination in [
                    ("192.0.2.4", "198.51.100.5", "192.0.2.4", "198.51.100.5"),
                    ("2001:db8::4", "2001:db8::5", "2001:db8::4", "2001:db8::5"),
                    ("::ffff:192.0.2.4", "::ffff:198.51.100.5", "192.0.2.4", "198.51.100.5"),
                    ("::ffff:192.0.2.4", "2001:db8::5", "::ffff:192.0.2.4", "2001:db8::5"),
                ]:
                    received = tcp(source, destination, 65535, 0, tail)
                    expected = tcp(expected_source, expected_destination, 65535, 0) if enabled else b""
                    for intent in (1, 2, 3):
                        with server.connect() as client:
                            exchange(client, backend, received, expected, intent, bytes(range(256)))

        with relay(binary, {}, backend.getsockname()[1], pheader_version=2) as direct:
            direct.settings["proxy"][0]["pheader_version"] = "2"
            direct.reload({}, error=("proxy[0].pheader_version", "the number 1 or 2"))
            with direct.connect() as client:
                expected = tcp("127.0.0.1", "127.0.0.1", client.getsockname()[1], direct.port)
                exchange(client, backend, b"", expected, 2)


if __name__ == "__main__":
    admission(sys.argv[1])
    forwarding(sys.argv[1])
    header_timeout(sys.argv[1])
    outbound(sys.argv[1])
    stream_and_reload(sys.argv[1])
