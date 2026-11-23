#!/usr/bin/env python3
"""Compare TCP refusal endpoints without using mcrelay's networking code."""

import argparse
from collections import Counter
import json
from pathlib import Path
import select
import socket
import time


def probe(mode):
    with socket.socket() as reservation, socket.socket() as connection:
        reservation.bind(("127.0.0.1", 0))
        target = reservation.getsockname()
        if mode == "closed_listener":
            reservation.listen()
        if mode != "reserved_bound":
            reservation.close()
        connection.setblocking(False)
        started = time.monotonic_ns()
        connect_error = connection.connect_ex(target)
        poll = select.poll()
        poll.register(connection, select.POLLOUT)
        events = poll.poll(1000)
        local = connection.getsockname()
        socket_error = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        state = connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)[0]
        try:
            peer = connection.getpeername()
        except OSError as error:
            peer = {"errno": error.errno}
        time.sleep(0.02)
        try:
            sent = connection.send(b"probe")
        except OSError as error:
            sent = {"errno": error.errno}
        return {"mode": mode, "target": target, "local": local, "peer": peer, "connect_errno": connect_error,
                "poll_events": events, "so_error": socket_error, "tcp_state": state,
                "send_after_20ms": sent, "elapsed_ns": time.monotonic_ns() - started}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=100)
    args = parser.parse_args()
    assert args.repetitions > 0
    records = []
    summary = {}
    for mode in ("closed_listener", "closed_bound", "reserved_bound"):
        samples = [probe(mode) for _ in range(args.repetitions)]
        records.extend(samples)
        summary[mode] = dict(Counter("so_error={},tcp_state={}".format(item["so_error"], item["tcp_state"]) for item in samples))
    report = {"kernel": Path("/proc/version").read_text().strip(), "os_release": Path("/etc/os-release").read_text(),
              "repetitions_per_mode": args.repetitions, "summary": summary, "records": records}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(summary))
