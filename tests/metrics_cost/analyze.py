#!/usr/bin/env python3
"""Summarize retained raw paired measurements without hiding negative deltas."""

import argparse
import csv
import json
from pathlib import Path
import statistics


def distribution(values):
    values = sorted(values)
    return {"n": len(values), "median": statistics.median(values), "min": min(values), "max": max(values), "mean": statistics.mean(values)}


def percentile(values, fraction):
    values = sorted(values)
    return values[min(len(values) - 1, int((len(values) - 1) * fraction))]


def analyze(root):
    records = [json.loads(path.read_text()) for path in (root / "suite").glob("*/result.json")]
    report = {"cpu_ms_per_10000_requests": {}, "latency_ms": {}, "memory_kib": {}, "memory_paired_difference_kib": {}, "snapshot": {}, "cadence_cpu_usec": {}}
    for profile in ("status", "dns", "workers"):
        subset = [item for item in records if item["profile"] == profile]
        groups = {variant: sorted((item for item in subset if item["variant"] == variant), key=lambda item: item["repetition"]) for variant in "ABC"}
        costs = {variant: [item["cpu_usec"] * 10 / item["count"] for item in group] for variant, group in groups.items()}
        paired = {name: [right - left for left, right in zip(costs[a], costs[b])] for name, a, b in (("B_minus_A", "A", "B"), ("C_minus_B", "B", "C"), ("C_minus_A", "A", "C"))}
        relative = {name: [(right - left) / left * 100 for left, right in zip(costs[a], costs[b])]
                    for name, a, b in (("B_minus_A", "A", "B"), ("C_minus_B", "B", "C"), ("C_minus_A", "A", "C"))}
        assert all(len(group) == 5 for group in groups.values()), (profile, groups)
        report["cpu_ms_per_10000_requests"][profile] = {"groups": {key: distribution(value) for key, value in costs.items()},
                                                            "paired_differences": {key: distribution(value) for key, value in paired.items()},
                                                            "paired_relative_percent": {key: distribution(value) for key, value in relative.items()}}
        latency = {}
        for variant in "ABC":
            runs = []
            for path in sorted((root / "suite").glob("{}-{}-*/latency.csv".format(profile, variant))):
                with path.open() as source:
                    values = [int(row["elapsed_ns"]) / 1e6 for row in csv.DictReader(source)]
                runs.append({"file": str(path.relative_to(root)), "p50": percentile(values, .50), "p95": percentile(values, .95), "p99": percentile(values, .99)})
            assert len(runs) == 5
            latency[variant] = {"runs": runs, "p50": distribution([run["p50"] for run in runs]),
                                "p95": distribution([run["p95"] for run in runs]), "p99": distribution([run["p99"] for run in runs])}
        report["latency_ms"][profile] = latency
    for workers in (0, 1, 16, 64):
        groups = {}
        paired_samples = {}
        for variant in "ABC":
            samples = []
            private = []
            for record in sorted((item for item in records if item["profile"] == "memory" and item["variant"] == variant), key=lambda item: item["repetition"]):
                stage = next(item for item in record["stages"] if item["workers"] == workers)
                samples.append(statistics.median(item["pss_kib"] for item in stage["samples"]))
                private.append(statistics.median(item["private_kib"] for item in stage["samples"]))
            assert len(samples) == 5
            groups[variant] = {"pss": distribution(samples), "private": distribution(private)}
            paired_samples[variant] = {"pss": samples, "private": private}
        report["memory_kib"][str(workers)] = groups
        report["memory_paired_difference_kib"][str(workers)] = {
            name: {kind: distribution([right - left for left, right in zip(paired_samples[a][kind], paired_samples[b][kind])]) for kind in ("pss", "private")}
            for name, a, b in (("B_minus_A", "A", "B"), ("C_minus_B", "B", "C"), ("C_minus_A", "A", "C"))}
    for entries in (0, 512):
        per_run = []
        for path in sorted((root / "snapshots").glob("entries-{}-*.csv".format(entries))):
            with path.open() as source:
                rows = list(csv.DictReader(source))
            cpu, wall = [int(row["cpu_ns"]) for row in rows], [int(row["wall_ns"]) for row in rows]
            per_run.append({"file": str(path.relative_to(root)), "cpu_ms_mean": statistics.mean(cpu) / 1e6,
                            "cpu_ms_median": statistics.median(cpu) / 1e6, "wall_ms_median": statistics.median(wall) / 1e6,
                            "wall_ms_p95": percentile(wall, .95) / 1e6, "wall_ms_p99": percentile(wall, .99) / 1e6, "wall_ms_max": max(wall) / 1e6})
        assert len(per_run) == 5
        average = distribution([run["cpu_ms_mean"] for run in per_run])
        report["snapshot"][str(entries)] = {"runs": per_run, "cpu_ms_per_snapshot": average,
            "predicted_cpu_ms_per_day_at_900s": average["median"] * 96,
            "predicted_percent_of_one_core_at_900s": average["median"] / 900000 * 100}
    cadence = [json.loads(path.read_text()) for path in (root / "cadence").glob("*/result.json")]
    if cadence:
        report["cadence_cpu_usec"]["full_frame_gate"] = all(item.get("end_gate") == "all five complete periodic frames validated, followed by 50ms idle" for item in cadence)
        for variant in ("B", "C"):
            report["cadence_cpu_usec"][variant] = distribution([item["cpu_usec"] for item in cadence if item["variant"] == variant])
        ordered = {variant: sorted((item for item in cadence if item["variant"] == variant), key=lambda item: item["repetition"]) for variant in ("B", "C")}
        report["cadence_cpu_usec"]["paired_C_minus_B"] = distribution([c["cpu_usec"] - b["cpu_usec"] for b, c in zip(ordered["B"], ordered["C"])])
    report["layouts"] = json.loads((root / "layouts.json").read_text())
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    report = analyze(args.root)
    (args.root / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = ["# Native Metrics resource measurements", "", "Units and paired differences retain all signs. Five repetitions per group.", "",
             "## CPU per 10,000 completed requests", "", "| Profile | A median ms | B median ms | C median ms | B−A median [min, max] ms | B−A median [min, max] % |", "|---|---:|---:|---:|---:|---:|"]
    for profile, values in report["cpu_ms_per_10000_requests"].items():
        group, delta = values["groups"], values["paired_differences"]["B_minus_A"]
        relative = values["paired_relative_percent"]["B_minus_A"]
        lines.append("| {} | {:.3f} | {:.3f} | {:.3f} | {:.3f} [{:.3f}, {:.3f}] | {:.3f} [{:.3f}, {:.3f}] |".format(
            profile, group["A"]["median"], group["B"]["median"], group["C"]["median"], delta["median"], delta["min"], delta["max"], relative["median"], relative["min"], relative["max"]))
    lines += ["", "## Group PSS", "", "Median KiB; includes listener, two helpers and the stated live workers. Differences are medians of repetition pairs, not differences of group medians.", "",
              "| Workers | A | B | C | Paired C−A median [min, max] KiB |", "|---|---:|---:|---:|---:|"]
    for workers, values in report["memory_kib"].items():
        delta = report["memory_paired_difference_kib"][workers]["C_minus_A"]["pss"]
        lines.append("| {} | {:.1f} | {:.1f} | {:.1f} | {:.1f} [{:.1f}, {:.1f}] |".format(workers, *(values[variant]["pss"]["median"] for variant in "ABC"), delta["median"], delta["min"], delta["max"]))
    lines += ["", "## Snapshot getter plus formatter and regular-file logging", "", "Ten warm-up frames excluded; 1,000 individually timed frames in each repetition.", ""]
    for entries, values in report["snapshot"].items():
        cost = values["cpu_ms_per_snapshot"]
        lines.append("- {} unpublished cache entries: {:.3f} ms CPU/frame (run means {:.3f}–{:.3f}); predicted {:.2f} ms CPU/day at 900 seconds.".format(entries, cost["median"], cost["min"], cost["max"], values["predicted_cpu_ms_per_day_at_900s"]))
    if report["cadence_cpu_usec"]:
        cadence = report["cadence_cpu_usec"]
        delta = cadence["paired_C_minus_B"]
        lines += ["", "## Actual 900-second idle cadence", "", "Complete-frame endpoint required in every record: {}.".format(cadence["full_frame_gate"]),
                  "Paired C−B CPU: {:.3f} ms, range {:.3f}–{:.3f} ms; independently accounted co-resident instances.".format(delta["median"] / 1000, delta["min"] / 1000, delta["max"] / 1000)]
    lines += ["", "## Compiler object sizes", "", "```json", json.dumps(report["layouts"]["size_difference_bytes"], indent=2), "```", "",
              "## Scope", "", "A is a source-level measurement control, not a supported product mode. B/C short load runs do not reach a 900-second periodic tick; their startup/shutdown frames are outside timed CPU windows.",
              "The separate cadence run uses five staggered, co-resident idle B/C pairs with independent cgroup CPU accounting. Its PSS is not a single-instance memory estimate.",
              "PSS shares pages across processes; per-process smaps values are in integer KiB and summation retains quantization error. cgroup memory.current also includes file cache and kernel memory. Sampled maxima are not guaranteed transient peaks.",
              "Snapshot timings use an idle supervisor and 0/512 unpublished cache entries; they do not establish worst-case cost at maximum cache/job capacity or slow-storage stalls.",
              "No sanitizer is enabled. Results are specific to this guest and workload; a range crossing zero does not establish zero cost. Operational acceptance remains a maintainer decision."]
    (args.root / "report.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines[:12]))
