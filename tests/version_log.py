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


def check(binary, interval, report_tool=None):
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
        terminal = root / "stdout.log"
        with terminal.open("w") as output:
            process = subprocess.Popen([binary, "run", "-c", str(config)], env=environment, start_new_session=True,
                                       stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL)
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
            process.send_signal(signal.SIGUSR1)
            deadline = time.monotonic() + 5
            while "Configuration file unchanged." not in log.read_text():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError("unchanged-config reload did not finish")
                time.sleep(0.01)
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=5) == 0
            lines = log.read_text().splitlines()
            banner = "[INFO] Starting mcrelay {} on PID {}...".format(version, process.pid)
            assert sum(line.endswith(banner) for line in lines) == 1, lines[:5]
            terminal_lines = terminal.read_text().splitlines()
            assert terminal_lines.count(banner) == 1, terminal_lines
            assert terminal_lines.index(banner) < next(index for index, line in enumerate(terminal_lines) if line.startswith("[INFO] Binding on "))
            startup = next(index for index, line in enumerate(lines) if line.endswith(banner))
            binding = next(index for index, line in enumerate(lines) if "[INFO] Binding on " in line)
            bound = next(index for index, line in enumerate(lines) if line.endswith("[INFO] Bind Successful."))
            ready = next(index for index, line in enumerate(lines) if line.endswith("[INFO] Initial proxy route warm-up finished; accepting connections."))
            assert startup < binding < bound < ready
            meta = [line for line in lines if "metrics schema=1 " in line and " family=meta " in line]
            assert bool(meta) == bool(interval)
            assert all(" version=" not in line for line in meta)
            if meta:
                assert startup < lines.index(meta[0])
            if report_tool is not None:
                report = json.loads(subprocess.check_output([sys.executable, report_tool, "--format", "json", str(log)], text=True, timeout=5))
                assert report["ok"] and report["counts"]["complete_snapshots"] == 2
                assert len(report["instances"]) == 1 and report["instances"][0]["version"] == version
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def check_silent_start(binary, report_tool):
    with tempfile.TemporaryDirectory(prefix="mcrelay-version-silent-") as directory:
        root = Path(directory)
        log, config = root / "access.log", root / "config.json"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        settings = {
            "log": {"filename": str(log), "level": 1},
            "metrics": {"interval": 0},
            "listen": {"address": "127.0.0.1", "port": port},
            "proxy": [{"vhost": "version.example", "address": "127.0.0.1", "port": 9}],
        }
        config.write_text(json.dumps(settings))
        environment = dict(os.environ)
        environment.pop("NOTIFY_SOCKET", None)
        process = subprocess.Popen([binary, "run", "-c", str(config)], env=environment, start_new_session=True,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError("silent daemon did not bind")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.01)
            assert not log.exists() or "Starting mcrelay " not in log.read_text()
            with log.open("a") as output:
                output.write("[2020-01-01 08:00:00 UTC+08:00] [INFO] Starting mcrelay v-old on PID {}...\n".format(process.pid))
            settings["log"]["level"] = 2
            settings["metrics"]["interval"] = 900
            config.write_text(json.dumps(settings))
            process.send_signal(signal.SIGUSR1)
            deadline = time.monotonic() + 5
            while True:
                text = log.read_text()
                if "reason=reconfigure" in text and "name=route_ms request_mode=worker " in text:
                    break
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError("silent-start metrics enable did not finish")
                time.sleep(0.01)
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=5) == 0
            report = json.loads(subprocess.check_output([sys.executable, report_tool, "--format", "json", str(log)], text=True, timeout=5))
            assert report["ok"] and report["counts"]["complete_snapshots"] == 2
            assert len(report["instances"]) == 1
            item = report["instances"][0]
            assert item["first"]["seq"] == 1 and item["first"]["reason"] == "reconfigure"
            assert item["version"] is None and item["version_source"] is None
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


if __name__ == "__main__":
    tool = str(Path(sys.argv[2]).resolve()) if len(sys.argv) == 3 else None
    for metrics_interval in ((900,) if tool else (0, 900)):
        check(str(Path(sys.argv[1]).resolve()), metrics_interval, tool)
    if tool:
        check_silent_start(str(Path(sys.argv[1]).resolve()), tool)
