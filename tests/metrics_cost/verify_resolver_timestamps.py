#!/usr/bin/env python3
"""Native-only real-DNS regression for results completing after a batch sample."""

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import run as driver


async def main(args):
    args.results.mkdir(parents=True, exist_ok=False)
    os.environ["XDG_RUNTIME_DIR"] = "/run/user/{}".format(os.getuid())
    allowed = sorted(os.sched_getaffinity(0))
    assert len(allowed) >= 2, "two service/driver CPUs are required"
    args.service_cpu = allowed[1]
    os.sched_setaffinity(0, {allowed[0]})
    args.control = args.normal = args.binary
    args.dns_a_delay_ms = 0
    args.protocol_trace = False
    driver.save(args.results / "environment.json", {
        "kernel": driver.command("uname", "-a"), "os_release": Path("/etc/os-release").read_text(),
        "driver_cpu": allowed[0], "service_cpu": args.service_cpu, "argv": vars(args),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "purpose": "correctness regression with immediate A/AAAA replies; no resource-cost comparison",
    })
    verified = []
    for repetition in range(args.repetitions):
        for variant in ("B", "C") if repetition % 2 == 0 else ("C", "B"):
            await driver.trial(args, variant, "dns", repetition, args.requests, 1)
            directory = args.results / "dns-{}-r{}".format(variant, repetition)
            record = json.loads((directory / "result.json").read_text())
            assert record["initial_helpers"] == record["final_helpers"]
            assert record["dns"] == {"1": args.requests, "28": args.requests}
            if variant == "C":
                report = json.loads(subprocess.check_output([
                    sys.executable, str(driver.ROOT / "tools/metrics-report.py"), "--format", "json", str(directory / "access.log.gz")], text=True))
                assert report["ok"] and report["counts"]["complete_snapshots"] == 2
                assert len(report["instances"]) == 1 and not report["helper_failure_events"]
                counters = report["instances"][0]["counter_deltas"]
                for name in ("failure_exit", "failure_io", "failure_protocol", "failure_spawn", "failure_timeout", "spawn_success"):
                    assert counters["helper." + name] == 0, (directory, name, counters["helper." + name])
                for name in ("format_drops", "logger_errors", "scheduler_failures", "missed_intervals"):
                    assert counters["meta." + name] == 0, (directory, name)
                assert counters["listener.accepted_total"] == args.requests + min(args.requests, 20)
            verified.append({"directory": directory.name, "requests": args.requests, "helpers": record["final_helpers"]})
    driver.save(args.results / "verification.json", {"ok": True, "trials": verified, "measured_requests": args.requests * len(verified),
                                                    "a_response_delay_ms": 0, "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest()})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--tools", type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--results", type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--requests", type=int, default=5000)
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()
    assert args.requests > 0 and args.repetitions > 0
    asyncio.run(main(args))
