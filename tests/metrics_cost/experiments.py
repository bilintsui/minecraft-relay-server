#!/usr/bin/env python3
"""Paired fixed-version DNS costs and explicit memory/snapshot boundary cases."""

import argparse
import asyncio
import csv
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import socket
import statistics
import subprocess
import sys

import run as driver


def distribution(values):
    return {"n": len(values), "median": statistics.median(values), "mean": statistics.mean(values), "min": min(values), "max": max(values)}


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[int((len(ordered) - 1) * fraction)]


def validate(directory, expected_accepts):
    driver.validate_trial_log(directory)
    record = json.loads((directory / "result.json").read_text())
    if record["variant"] != "C":
        assert "metrics schema=" not in gzip.decompress((directory / "access.log.gz").read_bytes()).decode()
        return
    report = json.loads(subprocess.check_output([sys.executable, str(driver.ROOT / "tools/metrics-report.py"), "--format", "json", str(directory / "access.log.gz")], text=True))
    assert report["ok"] and report["counts"]["complete_snapshots"] == 2 and len(report["instances"]) == 1
    counters = report["instances"][0]["counter_deltas"]
    assert counters["listener.accepted_total"] == expected_accepts
    for name in ("failure_exit", "failure_io", "failure_protocol", "failure_spawn", "failure_timeout", "spawn_success"):
        assert counters["helper." + name] == 0
    for name in ("format_drops", "logger_errors", "scheduler_failures", "missed_intervals"):
        assert counters["meta." + name] == 0


async def dns(args):
    assert args.repetitions >= 2 and args.repetitions % 2 == 0
    rng = random.Random(23112026)
    orders = []
    for block in range(args.repetitions // 2):
        pair = ["AB", "BA"]
        rng.shuffle(pair)
        orders.extend(pair)
    driver.save(args.results / "orders.json", {"seed": 23112026, "two_pair_blocks": True, "orders": orders})
    for repetition, order in enumerate(orders):
        for variant in order:
            await driver.trial(args, variant, "dns", repetition, args.requests, 1)
            validate(args.results / "dns-{}-r{}".format(variant, repetition), args.requests + min(args.requests, 20))


async def memory(args):
    counts = [0, 64, 128, 256]
    for repetition in range(args.repetitions):
        order = list("ABC")
        random.Random(1311 + repetition).shuffle(order)
        for variant in order:
            await driver.memory_trial(args, variant, repetition, counts)
            directory = args.results / "memory-{}-r{}".format(variant, repetition)
            validate(directory, 100 + max(counts))
            record = json.loads((directory / "result.json").read_text())
            helpers = None
            for stage in record["stages"]:
                count = stage["workers"] if isinstance(stage["workers"], int) else 0
                for sample in stage["samples"]:
                    assert len(sample["processes"]) == count + 3 and not sample["unavailable_processes"]
                    current = sorted(p["pid"] for p in sample["processes"] if p["comm"].startswith("resolver-"))
                    helpers = current if helpers is None else helpers
                    assert current == helpers and len(current) == 2


def snapshot_trial(args, name, entries, published, jobs, iterations):
    stem = args.results / name
    log, timing, errors = stem.with_suffix(".log"), stem.with_suffix(".csv"), stem.with_suffix(".stderr")
    environment = os.environ.copy()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as blackhole:
        blackhole.bind(("127.0.0.1", 0))
        environment.update({"LD_PRELOAD": str(args.tools / "libdns_redirect.so"), "MCRELAY_BENCH_DNS_PORT": str(blackhole.getsockname()[1])})
        invocation = [str(args.tools / "snapshot_cost"), str(log), str(timing), str(iterations), str(entries), str(published), str(jobs)]
        with errors.open("w") as output:
            subprocess.run(invocation, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=output,
                           preexec_fn=lambda: os.sched_setaffinity(0, {args.service_cpu}), check=True, timeout=300)
    state = json.loads(errors.read_text())
    assert state["entries"] == entries and state["jobs"] == jobs and state["queued"] + state["dispatched"] == jobs
    assert state["published"] == published or state["publish_limited"]
    assert state["cache_owned_bytes"] <= state["cache_byte_limit"]
    report = json.loads(subprocess.check_output([sys.executable, str(driver.ROOT / "tools/metrics-report.py"), "--format", "json", str(log)], text=True))
    assert report["ok"] and report["counts"]["complete_snapshots"] == iterations + 10
    result = {"state": state, "iterations": iterations, "warmup": 10, "complete_snapshots": iterations + 10, "command": invocation,
              "binary_sha256": hashlib.sha256((args.tools / "snapshot_cost").read_bytes()).hexdigest(),
              "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
    driver.save(stem.with_suffix(".json"), result)
    driver.compress(log)
    print(json.dumps({"profile": name, "state": state}), flush=True)
    return state


def snapshots(args):
    caps = snapshot_trial(args, "caps", 0, 0, 0, 1)
    maximum, jobs = caps["entry_limit"], caps["job_limit"]
    assert maximum >= 2 * jobs
    cases = [("empty", 0, 0, 0), ("unpublished-512", 512, 0, 0), ("unpublished-full", maximum, 0, 0),
             ("positive-half", maximum // 2, maximum // 2, 0), ("positive-byte-bound", maximum, maximum, 0),
             ("jobs-full", jobs, 0, jobs), ("mixed-full", maximum, maximum // 2, jobs)]
    driver.save(args.results / "cases.json", {"entry_limit": maximum, "job_limit": jobs, "cases": cases,
        "supervisor_model": "owner state frozen after scheduling; two dispatched helpers and remaining queued jobs; responses are not consumed",
        "dns": "loopback UDP blackhole; no external DNS", "seed_base": 7311})
    for repetition in range(args.repetitions):
        order = list(cases)
        random.Random(7311 + repetition).shuffle(order)
        for name, entries, published, count in order:
            snapshot_trial(args, "{}-r{}".format(name, repetition), entries, published, count, args.iterations)


def summarize(root):
    report = {}
    dns_rows = [json.loads(p.read_text()) for p in (root / "dns").glob("*/result.json")]
    if dns_rows:
        groups = {v: sorted((r for r in dns_rows if r["variant"] == v), key=lambda r: r["repetition"]) for v in "AB"}
        orders = json.loads((root / "dns/orders.json").read_text())["orders"]
        assert len(groups["A"]) == len(groups["B"]) == len(orders) and len(orders) % 2 == 0
        for rows in groups.values():
            assert [r["repetition"] for r in rows] == list(range(len(orders)))
            assert len({r["count"] for r in rows}) == 1 and all(r["initial_helpers"] == r["final_helpers"] and r["dns_a_delay_ms"] == 0 for r in rows)
        costs = {v: [r["cpu_usec"] * 10 / r["count"] for r in rows] for v, rows in groups.items()}
        differences = [b - a for a, b in zip(costs["A"], costs["B"])]
        percents = [(b / a - 1) * 100 for a, b in zip(costs["A"], costs["B"])]
        blocks = [(sum(costs["A"][i:i + 2]), sum(costs["B"][i:i + 2])) for i in range(0, len(differences), 2)]
        rng = random.Random(4311)
        bootstrap = []
        for _ in range(20000):
            sampled = [rng.choice(blocks) for _ in blocks]
            bootstrap.append((sum(b for a, b in sampled) / sum(a for a, b in sampled) - 1) * 100)
        report["dns"] = {"cpu_ms_per_10000_requests": {v: distribution(values) for v, values in costs.items()},
                         "paired_ms": distribution(differences), "paired_percent": distribution(percents),
                         "pooled_cpu_percent": (sum(costs["B"]) / sum(costs["A"]) - 1) * 100,
                         "balanced_block_cpu_percent": [(b / a - 1) * 100 for a, b in blocks],
                         "exploratory_bootstrap_95_percent": [percentile(bootstrap, .025), percentile(bootstrap, .975)],
                         "bootstrap": "20,000 resamples of entire two-pair AB/BA blocks; seed 4311; does not model host bias"}
    memory_rows = [json.loads(p.read_text()) for p in (root / "memory").glob("*/result.json")]
    if memory_rows:
        report["memory_kib"] = {}
        for workers in [0, 64, 128, 256, "after_close"]:
            groups = {}
            for variant in "ABC":
                rows = sorted((r for r in memory_rows if r["variant"] == variant), key=lambda r: r["repetition"])
                groups[variant] = {kind: [statistics.median(s[kind + "_kib"] for s in next(t for t in r["stages"] if t["workers"] == workers)["samples"]) for r in rows]
                                   for kind in ("pss", "private")}
            report["memory_kib"][str(workers)] = {"groups": {v: {k: distribution(x) for k, x in values.items()} for v, values in groups.items()},
                "paired": {name: {kind: distribution([right - left for left, right in zip(groups[a][kind], groups[b][kind])]) for kind in ("pss", "private")}
                           for name, a, b in [("B_minus_A", "A", "B"), ("C_minus_A", "A", "C"), ("C_minus_B", "B", "C")]}}
    if (root / "snapshots/cases.json").exists():
        cases = json.loads((root / "snapshots/cases.json").read_text())["cases"]
        report["snapshots"] = {}
        for name, _, _, _ in cases:
            runs = []
            for path in sorted((root / "snapshots").glob(name + "-r*.csv")):
                with path.open() as source:
                    samples = list(csv.DictReader(source))
                cpu, wall = [int(r["cpu_ns"]) / 1e6 for r in samples], [int(r["wall_ns"]) / 1e6 for r in samples]
                runs.append({"state": json.loads(path.with_suffix(".json").read_text())["state"], "samples": len(samples),
                             "cpu_ms_mean": statistics.mean(cpu), "wall_ms_p95": percentile(wall, .95), "wall_ms_p99": percentile(wall, .99), "wall_ms_max": max(wall)})
            report["snapshots"][name] = {"runs": runs, "cpu_ms_run_means": distribution([r["cpu_ms_mean"] for r in runs]),
                                       "predicted_cpu_ms_per_day_at_900s": statistics.median(r["cpu_ms_mean"] for r in runs) * 96}
    driver.save(root / "summary.json", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("dns", "memory", "snapshots", "summarize"))
    parser.add_argument("--control", type=lambda value: Path(value).resolve())
    parser.add_argument("--normal", type=lambda value: Path(value).resolve())
    parser.add_argument("--tools", type=lambda value: Path(value).resolve())
    parser.add_argument("--results", type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--requests", type=int, default=5000)
    parser.add_argument("--iterations", type=int, default=1000)
    args = parser.parse_args()
    if args.mode == "summarize":
        summarize(args.results)
    else:
        args.results.mkdir(parents=True, exist_ok=False)
        os.environ["XDG_RUNTIME_DIR"] = "/run/user/{}".format(os.getuid())
        cpus = sorted(os.sched_getaffinity(0))
        assert len(cpus) >= 2
        args.service_cpu = cpus[1]
        os.sched_setaffinity(0, {cpus[0]})
        args.dns_a_delay_ms, args.protocol_trace = 0, False
        driver.save(args.results / "environment.json", {"kernel": driver.command("uname", "-a"), "cpuinfo": Path("/proc/cpuinfo").read_text(),
                    "argv": vars(args), "driver_cpu": cpus[0], "service_cpu": cpus[1], "page_size": os.sysconf("SC_PAGE_SIZE")})
        if args.mode == "snapshots":
            assert args.tools is not None
            snapshots(args)
        else:
            assert args.control is not None and args.normal is not None and args.tools is not None
            asyncio.run(dns(args) if args.mode == "dns" else memory(args))
