#!/usr/bin/env python3
"""Verify startup version identification against the executable's CLI."""

import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def check(binary, interval):
    version = subprocess.check_output([binary, "version"], text=True, timeout=5).strip()
    with tempfile.TemporaryDirectory(prefix="mcrelay-version-log-") as directory:
        root = Path(directory)
        log = root / "access.log"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = root / "config.json"
        config.write_text(json.dumps({
            "log": {"filename": str(log), "level": 2},
            "metrics": {"interval": interval},
            "listen": {"address": "127.0.0.1", "port": port},
            "proxy": [{"vhost": "version.example", "address": "127.0.0.1", "port": 9}],
        }))
        environment = dict(os.environ)
        environment.pop("NOTIFY_SOCKET", None)
        process = subprocess.Popen([binary, "run", "-c", str(config)], env=environment, start_new_session=True,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                text = log.read_text() if log.exists() else ""
                if "accepting connections." in text and (not interval or "family=histogram" in text):
                    break
                if process.poll() is not None:
                    raise AssertionError("daemon exited before readiness")
                time.sleep(0.01)
            else:
                raise AssertionError("daemon readiness not logged")
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=5) == 0
            lines = log.read_text().splitlines()
            banner = "[INFO] Starting mcrelay {} on PID {}...".format(version, process.pid)
            assert sum(line.endswith(banner) for line in lines) == 1, lines[:5]
            meta = [line for line in lines if "metrics schema=1 " in line and " family=meta " in line]
            assert bool(meta) == bool(interval)
            assert all(" version=" not in line for line in meta)
            if meta:
                assert lines.index(next(line for line in lines if line.endswith(banner))) < lines.index(meta[0])
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


if __name__ == "__main__":
    for metrics_interval in (0, 900):
        check(str(Path(sys.argv[1]).resolve()), metrics_interval)
