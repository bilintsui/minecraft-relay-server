#!/usr/bin/env python3
"""Audit saved results and final daemon logs independently of the load driver."""

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def audit(root):
    source = Path(__file__).resolve().parents[2]
    provenance = json.loads((root / "provenance.json").read_text())
    versions = set()
    rows = []
    combinations = Counter()
    for path in sorted(root.glob("*/*/result.json")):
        record = json.loads(path.read_text())
        directory = path.parent
        variant, profile = record["variant"], record["profile"]
        assert not record.get("protocol_trace_enabled"), path
        if "initial_helpers" in record:
            assert record["initial_helpers"] == record["final_helpers"], path
        if profile == "cadence":
            assert record.get("end_gate") == "all five complete periodic frames validated, followed by 50ms idle", path
        combinations[(directory.parent.name, profile, variant)] += 1
        log = directory / "access.log.gz"
        text = gzip.decompress(log.read_bytes()).decode()
        banners = [line for line in text.splitlines() if "] [INFO] Starting mcrelay " in line]
        assert len(banners) == 1, path
        versions.add(banners[0].split("Starting mcrelay ", 1)[1].split(" on PID ", 1)[0])
        unexpected = [line for line in text.splitlines() if "[CRIT]" in line or "resolver_helper status=" in line]
        assert not unexpected, (path, unexpected)
        if "binary_sha256" in record:
            assert record["binary_sha256"] == provenance["binaries"]["control" if variant == "A" else "normal"], path
        if "before" in record:
            assert record["after"]["cpu_stat"]["usage_usec"] - record["before"]["cpu_stat"]["usage_usec"] == record["cpu_usec"]
            assert record["cpu_usec"] >= 0
            helpers = lambda sample: sorted(item["pid"] for item in sample["processes"] if item["comm"].startswith("resolver-"))
            assert len(helpers(record["before"])) == 2 and helpers(record["before"]) == helpers(record["after"]), path
        if variant == "C":
            report = json.loads(subprocess.check_output([sys.executable, str(source / "tools/metrics-report.py"), "--format", "json", str(log)], text=True))
            expected_snapshots = 3 if profile == "cadence" else 2
            assert report["ok"] and report["counts"]["complete_snapshots"] == expected_snapshots, path
            assert len(report["instances"]) == 1
            item = report["instances"][0]
            assert all(item["counter_deltas"]["meta." + key] == 0 for key in ["format_drops", "logger_errors", "scheduler_failures", "missed_intervals"])
            assert item["counter_deltas"]["helper.spawn_success"] == 0, path
            count = record.get("count", 0)
            warm = min(count, 20 if profile == "dns" else 100)
            if profile == "memory":
                expected_accepts = 100 + max(stage["workers"] for stage in record["stages"] if isinstance(stage["workers"], int))
            else:
                expected_accepts = count + warm
            assert item["counter_deltas"]["listener.accepted_total"] == expected_accepts, (path, expected_accepts)
        else:
            assert "metrics schema=" not in text, path
        rows.append({"file": str(path.relative_to(root)), "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(), "variant": variant, "profile": profile})
    for profile in ["status", "dns", "workers", "idle", "memory"]:
        for variant in "ABC":
            assert combinations[("smoke", profile, variant)] == 1, (profile, variant)
            assert combinations[("suite", profile, variant)] == 5, (profile, variant)
    for variant in "BC":
        assert combinations[("cadence", "cadence", variant)] == 5
    assert len(versions) == 1, versions
    assert len(rows) == 100, len(rows)
    return {"ok": True, "audited_trials": len(rows), "versions": sorted(versions), "combinations": {"/".join(key): value for key, value in combinations.items()}, "logs": rows}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    report = audit(args.root)
    (args.root / "audit.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ["ok", "audited_trials", "versions"]}))
