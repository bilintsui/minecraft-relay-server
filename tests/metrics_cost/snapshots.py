#!/usr/bin/env python3
"""Repeat the real snapshot getter/emitter; validate and retain each output log."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess
import sys


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=1000)
    args = parser.parse_args()
    args.results.mkdir(exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    for repetition in range(args.repetitions):
        sizes = [0, 512]
        random.Random(512 + repetition).shuffle(sizes)
        for size in sizes:
            stem = args.results / "entries-{}-r{}".format(size, repetition)
            log, csv = stem.with_suffix(".log"), stem.with_suffix(".csv")
            invocation = [str(args.binary.resolve()), str(log), str(csv), str(args.iterations), str(size)]
            with stem.with_suffix(".stderr").open("wb") as errors:
                subprocess.run(invocation, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors, timeout=120)
            report = json.loads(subprocess.check_output([sys.executable, str(root / "tools/metrics-report.py"), "--format", "json", str(log)], text=True))
            assert report["ok"] and report["counts"]["complete_snapshots"] == args.iterations + 10
            summary = {"cache_entries": size, "repetition": repetition, "iterations": args.iterations, "warmup": 10,
                       "bytes": log.stat().st_size, "sha256": hashlib.sha256(log.read_bytes()).hexdigest(), "command": invocation,
                       "validated_complete_snapshots": report["counts"]["complete_snapshots"]}
            stem.with_suffix(".json").write_text(json.dumps(summary, indent=2) + "\n")
            with log.open("rb") as source, gzip.open(str(log) + ".gz", "wb") as target:
                shutil.copyfileobj(source, target)
            log.unlink()
            print(json.dumps(summary), flush=True)
