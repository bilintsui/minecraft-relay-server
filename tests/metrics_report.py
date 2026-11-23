#!/usr/bin/env python3
"""Consumer regressions using anonymized snapshots from a production archive."""

import csv
import gzip
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "metrics-report.py"
FIXTURES = ROOT / "tests" / "fixtures" / "metrics"
DATA = (FIXTURES / "rotation-1.log").read_bytes() + (FIXTURES / "rotation-2.log").read_bytes()
METRICS = [line for line in DATA.splitlines(keepends=True) if b"] [INFO] metrics schema=1 " in line]
BATCHES = [b"".join(METRICS[index:index + 48]) for index in range(0, len(METRICS), 48)]
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("metrics_report", TOOL)
REPORT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REPORT
SPEC.loader.exec_module(REPORT)

LIMIT_COUNTER_ROWS = (
    ("attempt", "qtype", ("a", "aaaa", "srv"), ("response_limit", "orphan_response_limit")),
    ("cache", "qtype", ("a", "aaaa", "srv", "other"),
     ("acquire_reference_limit", "acquire_entry_limit", "acquire_id_limit", "acquire_owned_byte_limit", "publish_limit")),
    ("assembly", "qtype", ("a", "aaaa", "srv"), ("create_limit", "terminal_limit")),
    ("route", "request_mode", ("short", "worker"), ("outcome_limit",)),
)
LIMITS = {
    "listener.connection_limit": 336,
    "listener.worker_limit": 256,
    "capacity/storage.cache_entry_limit": 16384,
    "capacity/storage.cache_owned_byte_limit": 67108864,
    "capacity/storage.cache_result_byte_limit": 262144,
    "capacity/storage.assembly_owned_byte_limit": 1048576,
    "capacity/supervisor.job_limit": 4096,
    "capacity/supervisor.interactive_reserve": 256,
    "capacity/supervisor.helper_limit": 2,
}


def replace_fields(batch, selector, **updates):
    lines = batch.splitlines(keepends=True)
    matches = 0
    for index, line in enumerate(lines):
        if selector in line:
            matches += 1
            text = line.decode("ascii")
            for key, value in updates.items():
                text, count = re.subn(r"(?<= )" + re.escape(key) + r"=[^ \n]+", "{}={}".format(key, value), text)
                if count != 1:
                    raise AssertionError((selector, key, count))
            lines[index] = text.encode("ascii")
    if matches != 1:
        raise AssertionError((selector, matches))
    return b"".join(lines)


def limit_counters(batch, value):
    labels = []
    for family, dimension, values, keys in LIMIT_COUNTER_ROWS:
        for item in values:
            selector = (" family={} instance=101-1000-0 {}={} ".format(family, dimension, item)).encode("ascii")
            updates = dict.fromkeys(keys, value)
            if family == "route":
                line = next(line for line in batch.splitlines() if selector in line)
                fields = dict(token.split("=", 1) for token in line.decode().split() if "=" in token)
                updates["requests_started"] = min((1 << 64) - 1, int(fields["requests_started"]) + value - int(fields["outcome_limit"]))
            batch = replace_fields(batch, selector, **updates)
            labels.extend("{}/{}.{}".format(family, item, key) for key in keys)
    return batch, labels


def histogram(batch, name, count, total, bucket):
    selector = (" name=" + name + " ").encode("ascii")
    selector += b"qtype=a "
    line = next(line for line in batch.splitlines() if selector in line)
    fields = dict(token.split("=", 1) for token in line.decode().split() if "=" in token)
    updates = {}
    for key in fields:
        if key.startswith("le_"):
            updates[key] = count if key == "le_inf" or int(key[3:]) >= bucket else 0
        elif key == "count":
            updates[key] = count
        elif key.startswith("sum_"):
            updates[key] = total
        elif key == "sample_errors":
            updates[key] = 0
    return replace_fields(batch, selector, **updates)


class FragmentedInput(io.RawIOBase):
    def __init__(self, data):
        super().__init__()
        self.data = data
        self.offset = 0

    def readable(self):
        return True

    def readinto(self, target):
        size = min(len(target), len(self.data) - self.offset, 1 if self.offset == 0 else len(target))
        target[:size] = self.data[self.offset:self.offset + size]
        self.offset += size
        return size


class FailingInput(io.RawIOBase):
    def readable(self):
        return True

    def readinto(self, target):
        raise OSError("injected detection failure")


class MetricsReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="mcrelay-metrics-report-test-")
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def run_tool(self, data=None, paths=None, stdin=None, format="json", expected=0, extra=()):
        if paths is None:
            path = self.root / "input.log"
            path.write_bytes(DATA if data is None else data)
            paths = [path]
        result = subprocess.run([sys.executable, str(TOOL), "--format", format, *extra, *map(str, paths)], input=stdin,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(result.returncode, expected, result.stderr.decode() + result.stdout.decode()[:1000])
        self.assertNotIn(b"Traceback", result.stderr)
        return json.loads(result.stdout) if format == "json" and expected != 2 else result

    def test_baseline_deltas_and_high_water(self):
        report = self.run_tool()
        self.assertEqual(report["counts"]["complete_snapshots"], 4)
        self.assertEqual(report["counts"]["valid_metrics_lines"], 192)
        self.assertEqual(report["helper_events"], {"degraded": 2})
        self.assertEqual(report["helper_failure_events"], {"exit": 2})
        self.assertEqual(len(report["instances"]), 2)
        old = report["instances"][0]
        self.assertEqual(old["first"]["seq"], 67)
        self.assertEqual(old["counter_deltas"]["listener.accepted_total"], 0)
        self.assertEqual(old["counter_deltas"]["helper.spawn_success"], 2)
        self.assertEqual(old["lifetime_peaks"]["listener.connections_high_water"], 1)
        self.assertNotIn("listener.connections_high_water", report["aggregate_counter_deltas"])
        self.assertTrue(all(item["version"] is None for item in report["instances"]))

    def test_capacity_changes(self):
        for label, value in LIMITS.items():
            with self.subTest(field=label):
                row, key = label.split(".")
                family, _, scope = row.partition("/")
                selector = (" family=" + family + " ").encode("ascii") if not scope else (" scope=" + scope + " ").encode("ascii")
                last = replace_fields(BATCHES[1], selector, **{key: value + 1})
                report = self.run_tool(BATCHES[0] + last, expected=1)
                self.assertEqual(report["errors"], {"limit_changed": 1})
                self.assertEqual(report["issue_examples"][0]["detail"], label)
                self.assertEqual(report["instances"][0]["limits"][label], value + 1)
                self.assertNotIn(label, report["aggregate_counter_deltas"])

    def test_counter_decrease_is_unknown_not_negative(self):
        first = replace_fields(BATCHES[0], b" family=meta ", missed_intervals=1)
        report = self.run_tool(first + BATCHES[1], expected=1)
        self.assertEqual(report["errors"]["counter_decreased"], 1)
        self.assertIsNone(report["aggregate_counter_deltas"]["meta.missed_intervals"])

    def test_custom_directory_basename(self):
        (self.root / "relay").write_bytes(BATCHES[1])
        (self.root / "relay.1.gz").write_bytes(gzip.compress(BATCHES[0], mtime=0))
        report = self.run_tool(paths=[self.root], extra=("--log-name", "relay"))
        self.assertEqual(report["counts"]["complete_snapshots"], 2)
        self.assertEqual(report["instances"][0]["first"]["seq"], 67)

    def test_directory_and_natural_rotation_order(self):
        parts = [DATA[:DATA.index(METRICS[40])], b"".join(METRICS[40:95]), b"".join(METRICS[95:150]), b"".join(METRICS[150:])]
        (self.root / "access.log.14.gz").write_bytes(gzip.compress(parts[0], mtime=0))
        (self.root / "access.log.2.gz").write_bytes(gzip.compress(parts[1], mtime=0))
        (self.root / "access.log.1").write_bytes(parts[2])
        (self.root / "access.log").write_bytes(parts[3])
        # Helper records omitted by the excerpt splitting above are irrelevant
        # to snapshot assembly. Missing rotation number 13 is not a data gap.
        report = self.run_tool(paths=[self.root])
        self.assertEqual(report["counts"]["complete_snapshots"], 4)
        explicit = self.run_tool(paths=sorted(self.root.glob("access.log*")))
        self.assertEqual(explicit["aggregate_counter_deltas"], report["aggregate_counter_deltas"])

    def test_duplicate_key_and_misplaced_extension(self):
        for replacement, error in ((b" format_drops=0 extra=1 extra=2\n", "duplicate_keys"),
                                   (b" extra=1 format_drops=0\n", "invalid_baseline_order")):
            with self.subTest(error=error):
                data = BATCHES[0].replace(b" format_drops=0\n", replacement)
                report = self.run_tool(data, expected=1)
                self.assertIn(error, report["errors"])
                self.assertEqual(report["counts"].get("complete_snapshots", 0), 0)

    def test_duplicate_row_invalidates_the_batch(self):
        first = BATCHES[0].splitlines(keepends=True)
        report = self.run_tool(b"".join(first + [first[10]]) + BATCHES[1], expected=1)
        self.assertEqual(report["errors"]["duplicate_row"], 1)
        self.assertEqual(report["counts"]["complete_snapshots"], 1)

    def test_empty_timestamp_is_accepted(self):
        data = re.sub(rb"^\[[^\]]+\]", b"[]", BATCHES[0], flags=re.M)
        report = self.run_tool(data)
        self.assertIsNone(report["instances"][0]["first"]["time"])

    def test_file_and_gzip_stdin(self):
        for data in (DATA, gzip.compress(DATA, mtime=0)):
            with self.subTest(compressed=data[:2] == b"\x1f\x8b"):
                report = self.run_tool(paths=["-"], stdin=data)
                self.assertEqual(report["counts"]["complete_snapshots"], 4)

    def test_fixture_anonymization(self):
        self.assertNotIn(b"2026-", DATA)
        self.assertNotIn(b"username:", DATA)
        self.assertNotIn(b"/home/", DATA)
        self.assertEqual(set(re.findall(rb"\binstance=([^ ]+)", DATA)), {b"101-1000-0", b"102-2000-0"})
        self.assertEqual(set(re.findall(rb"\bpid=([0-9]+)", DATA)), {b"101", b"102", b"201", b"202"})

    def test_forged_prefix_inside_access_record_is_ignored(self):
        forged = (b"[2020-01-01 00:00:00 UTC+08:00] [INFO] src: 192.0.2.20, vhost: fake\\r\\n" + METRICS[0])
        report = self.run_tool(forged + DATA)
        self.assertEqual(report["counts"]["complete_snapshots"], 4)
        self.assertGreater(report["counts"]["ignored_lines"], 3)

    def test_histogram_units_and_bucket_bounds(self):
        first, last = BATCHES[:2]
        for name, total, bucket in (("attempt_ms", 6000, 5), ("ttl_seconds", 120, 60), ("assembly_bytes", 64, 64)):
            if name == "ttl_seconds":
                # TTL adds payload_kind to its selector.
                selector = b" name=ttl_seconds qtype=a payload_kind=positive "
                def set_ttl(batch, count, value):
                    fields = {key: count if key in ("count", "le_inf") or (key.startswith("le_") and int(key[3:]) >= 60) else 0
                              for key in ("le_0", "le_1", "le_5", "le_30", "le_60", "le_300", "le_1800", "le_3600", "le_21600", "le_86400", "le_604800", "le_2592000", "le_inf", "count")}
                    return replace_fields(batch, selector, sum_seconds=value, **fields)
                first, last = set_ttl(first, 0, 0), set_ttl(last, 2, total)
            else:
                first, last = histogram(first, name, 0, 0, bucket), histogram(last, name, 2, total, bucket)
        report = self.run_tool(first + last)
        hist = report["instances"][0]["histograms"]
        self.assertEqual(hist["attempt_ms/a"]["mean"], 3)
        self.assertEqual(hist["attempt_ms/a"]["percentile_upper_bounds"]["p95"], 5)
        self.assertEqual(hist["ttl_seconds/a/positive"]["mean"], 60)
        self.assertEqual(hist["assembly_bytes/a"]["mean"], 32)

    def test_invalid_helper_grammar(self):
        line = next(line for line in DATA.splitlines(keepends=True) if b"resolver_helper " in line)
        for modified in (line[:-1] + b" extra=1\n", line.replace(b"failure=exit", b"failure=unknown"),
                         line.replace(b" suppressed=0", b""), line.replace(b"slot=0 pid=201", b"pid=201 slot=0")):
            with self.subTest(line=modified):
                report = self.run_tool(DATA.replace(line, modified, 1), expected=1)
                self.assertEqual(report["errors"]["invalid_helper_event"], 1)

    def test_invalid_histogram_interval(self):
        first = histogram(BATCHES[0], "attempt_ms", 2, 6000, 5)
        last = histogram(BATCHES[1], "attempt_ms", 3, 7000, 5)
        last = replace_fields(last, b" name=attempt_ms qtype=a ", le_1=2)
        report = self.run_tool(first + last, expected=1)
        self.assertIn("invalid_histogram_delta", report["errors"])
        self.assertIsNone(report["instances"][0]["histograms"]["attempt_ms/a"]["count"])

    def test_invalid_timestamp_and_truncated_glued_line(self):
        bad_time = BATCHES[0].replace(b"[2020-01-01", b"[2020-99-99", 1)
        report = self.run_tool(bad_time, expected=1)
        self.assertIn("invalid_prefix_or_encoding", report["errors"])
        lines = BATCHES[0].splitlines(keepends=True)
        glued = lines[0][:-10] + lines[1] + b"".join(lines[2:])
        report = self.run_tool(glued, expected=1)
        self.assertIn("invalid_tokens", report["errors"])
        self.assertEqual(report["counts"].get("complete_snapshots", 0), 0)

    def test_limit_counter_decreases_are_unknown(self):
        first, labels = limit_counters(BATCHES[0], 29)
        last, _ = limit_counters(BATCHES[1], 11)
        report = self.run_tool(first + last, expected=1)
        self.assertEqual(set(report["errors"]), {"counter_decreased"})
        self.assertEqual(report["instances"][0]["limits"], LIMITS)
        for label in labels:
            with self.subTest(field=label):
                self.assertIsNone(report["instances"][0]["counter_deltas"][label])
                self.assertIsNone(report["aggregate_counter_deltas"][label])

    def test_limit_counter_saturation_is_not_a_capacity_change(self):
        first, labels = limit_counters(BATCHES[0], (1 << 64) - 2)
        last, _ = limit_counters(BATCHES[1], (1 << 64) - 1)
        report = self.run_tool(first + last)
        self.assertEqual(report["errors"], {})
        self.assertIn("counter_saturated", report["warnings"])
        self.assertEqual(report["instances"][0]["limits"], LIMITS)
        for label in labels:
            with self.subTest(field=label):
                self.assertIsNone(report["instances"][0]["counter_deltas"][label])
                self.assertIsNone(report["aggregate_counter_deltas"][label])

    def test_limit_counters_increase_without_capacity_changes(self):
        first, labels = limit_counters(BATCHES[0], 11)
        last, _ = limit_counters(BATCHES[1], 29)
        report = self.run_tool(first + last)
        self.assertTrue(report["ok"])
        self.assertEqual(report["errors"], {})
        self.assertEqual(report["counts"]["complete_snapshots"], 2)
        self.assertEqual(report["instances"][0]["limits"], LIMITS)
        self.assertEqual(len(labels), 34)
        for label in labels:
            with self.subTest(field=label):
                self.assertEqual(report["instances"][0]["counter_deltas"][label], 18)
                self.assertEqual(report["aggregate_counter_deltas"][label], 18)

    def test_missing_row_and_missing_baseline_key(self):
        lines = BATCHES[0].splitlines(keepends=True)
        report = self.run_tool(b"".join(lines[:10] + lines[11:]) + BATCHES[1], expected=1)
        self.assertEqual(report["errors"]["incomplete_snapshot"], 1)
        self.assertEqual(report["counts"]["complete_snapshots"], 1)
        report = self.run_tool(BATCHES[0].replace(b" format_drops=0", b"", 1), expected=1)
        self.assertIn("invalid_baseline_order", report["errors"])

    def test_numeric_overflow_and_crlf(self):
        report = self.run_tool(replace_fields(BATCHES[0], b" family=meta ", missed_intervals=1 << 64), expected=1)
        self.assertIn("invalid_numeric_or_reason", report["errors"])
        report = self.run_tool(BATCHES[0].replace(b"\n", b"\r\n"), expected=1)
        self.assertIn("invalid_physical_record", report["errors"])

    def test_optional_extensions_and_other_schema(self):
        report = self.run_tool(BATCHES[0].replace(b" format_drops=0\n", b" format_drops=0 future_value=ok\n"))
        self.assertEqual(report["counts"]["complete_snapshots"], 1)
        report = self.run_tool(BATCHES[0].replace(b"schema=1", b"schema=2") + BATCHES[1], expected=1)
        self.assertEqual(report["errors"]["unsupported_schema"], 48)
        self.assertEqual(report["counts"]["complete_snapshots"], 1)

    def test_output_formats_and_read_only_inputs(self):
        paths = [FIXTURES / "rotation-1.log", FIXTURES / "rotation-2.log"]
        before = [path.read_bytes() for path in paths]
        text = self.run_tool(paths=paths, format="text").stdout.decode()
        self.assertIn("4 complete", text)
        self.assertIn("version=unknown", text)
        result = self.run_tool(paths=paths, format="csv")
        rows = list(csv.DictReader(io.StringIO(result.stdout.decode())))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["accepted_delta"], "0")
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_resource_and_input_failures(self):
        self.run_tool(paths=[self.root / "missing.log"], expected=2)
        self.run_tool(gzip.compress(DATA, mtime=0)[:-5], expected=2)
        self.run_tool(extra=("--max-instances", "1"), expected=2)
        self.run_tool(b"ordinary log\n", expected=1)

    def test_route_conservation(self):
        first = replace_fields(BATCHES[0], b" family=route instance=101-1000-0 request_mode=short ", requests_started=999)
        report = self.run_tool(first + BATCHES[1], expected=1)
        self.assertIn("invariant_violation", report["errors"])

    def test_rotation_split_plain_and_gzip(self):
        second = self.root / "second.bin"
        second.write_bytes(gzip.compress((FIXTURES / "rotation-2.log").read_bytes(), mtime=0))
        report = self.run_tool(paths=[FIXTURES / "rotation-1.log", second])
        self.assertEqual(report["counts"]["complete_snapshots"], 4)

    def test_saturation_is_not_an_exact_zero_delta(self):
        last = replace_fields(BATCHES[1], b" family=meta ", missed_intervals=(1 << 64) - 1)
        report = self.run_tool(BATCHES[0] + last)
        self.assertEqual(report["warnings"]["counter_saturated"], 1)
        self.assertIsNone(report["aggregate_counter_deltas"]["meta.missed_intervals"])

    def test_sequence_gap_and_reverse_order(self):
        last = BATCHES[1].replace(b" seq=68 ", b" seq=70 ")
        report = self.run_tool(BATCHES[0] + last, expected=1)
        self.assertEqual(report["instances"][0]["sequence_gaps"], 2)
        report = self.run_tool(BATCHES[1] + BATCHES[0], expected=1)
        self.assertIn("out_of_order_sequence", report["errors"])

    def test_stdin_preserves_input_order_between_rotations(self):
        first = self.root / "access.log.1"
        last = self.root / "access.log"
        first.write_bytes(BATCHES[0])
        last.write_bytes(BATCHES[2] + BATCHES[3])
        banner = b"[2020-01-01 08:45:18 UTC+08:00] [INFO] Starting mcrelay v1.3 on PID 102...\n"
        report = self.run_tool(paths=[first, "-", last], stdin=BATCHES[1] + banner)
        self.assertEqual(report["counts"]["complete_snapshots"], 4)
        self.assertEqual(report["instances"][1]["version"], "v1.3")

    def test_startup_versions_and_pid_reuse(self):
        prefix = b"[2020-01-01 08:40:00 UTC+08:00] [INFO] Starting mcrelay v1.2 on PID 101...\n"
        newer = (BATCHES[2] + BATCHES[3]).replace(b"instance=102-2000-0", b"instance=101-2000-0").replace(b" pid=102 ", b" pid=101 ")
        data = prefix + BATCHES[0] + BATCHES[1]
        report = self.run_tool(data + newer)
        self.assertEqual([item["version"] for item in report["instances"]], [None, None])
        banner = b"[2020-01-01 08:45:18 UTC+08:00] [INFO] Starting mcrelay v1.3-alpha+abc1234-debug(80) on PID 101...\n"
        report = self.run_tool(data + banner + newer)
        self.assertEqual([item["version"] for item in report["instances"]], [None, "v1.3-alpha+abc1234-debug(80)"])

    def test_unconsumed_banner_is_not_used_after_silent_pid_reuse(self):
        banner = b"[2020-01-01 08:00:00 UTC+08:00] [INFO] Starting mcrelay v-old on PID 101...\n"
        newer = BATCHES[2].replace(b"instance=102-2000-0", b"instance=101-2000-0").replace(b" pid=102 ", b" pid=101 ")
        newer = replace_fields(newer, b" family=meta ", reason="reconfigure", uptime_ms=60000)
        report = self.run_tool(banner + newer)
        self.assertIsNone(report["instances"][0]["version"])
        self.assertIsNone(report["instances"][0]["version_source"])

    def test_rejected_startup_snapshot_does_not_establish_version(self):
        banner = b"[2020-01-01 08:45:18 UTC+08:00] [INFO] Starting mcrelay v1.3 on PID 102...\n"
        incomplete = b"".join(BATCHES[2].splitlines(keepends=True)[:-1])
        report = self.run_tool(banner + incomplete + BATCHES[3], expected=1)
        self.assertEqual(report["counts"]["complete_snapshots"], 1)
        self.assertIsNone(report["instances"][0]["version"])

    def test_equals_in_startup_version(self):
        banner = b"[2020-01-01 08:45:18 UTC+08:00] [INFO] Starting mcrelay v1.3-alpha(build=42) on PID 102...\n"
        report = self.run_tool(banner + BATCHES[2])
        self.assertEqual(report["instances"][0]["version"], "v1.3-alpha(build=42)")

    def test_custom_basename_rotations_match_directory_and_explicit_inputs(self):
        current, older = self.root / "relay", self.root / "relay.1.gz"
        current.write_bytes(BATCHES[1])
        older.write_bytes(gzip.compress(BATCHES[0]))
        directory = self.run_tool(paths=[self.root], extra=["--log-name", "relay"])
        explicit = self.run_tool(paths=[current, older], extra=["--log-name", "relay"])
        self.assertEqual(directory["instances"], explicit["instances"])
        self.assertEqual(explicit["counts"]["complete_snapshots"], 2)

    def test_fragmented_plain_and_gzip_stdin(self):
        for payload in (DATA, gzip.compress(DATA)):
            with self.subTest(gzip=payload.startswith(b"\x1f\x8b")):
                with io.BufferedReader(FragmentedInput(payload)) as source:
                    report = REPORT.Report()
                    with mock.patch.object(REPORT.sys, "stdin", SimpleNamespace(buffer=source)):
                        REPORT.read_inputs(["-"], report)
                    self.assertFalse(source.closed)
                    result = report.result()
                    self.assertTrue(result["ok"], result["errors"])
                    self.assertEqual(result["counts"]["complete_snapshots"], 4)

    def test_detection_failure_closes_owned_file(self):
        source = io.BufferedReader(FailingInput())
        self.addCleanup(source.close)
        with mock.patch.object(REPORT, "open", return_value=source, create=True):
            with self.assertRaisesRegex(OSError, "injected detection failure"):
                REPORT.read_inputs(["unreadable.log"], REPORT.Report())
        self.assertTrue(source.closed)

    def test_gzip_failure_closes_file_and_preserves_stdin(self):
        for standard_input in (False, True):
            with self.subTest(stdin=standard_input):
                source = io.BufferedReader(io.BytesIO(gzip.compress(DATA)[:-8]))
                self.addCleanup(source.close)
                with mock.patch.object(REPORT, "open", return_value=source, create=True):
                    with mock.patch.object(REPORT.sys, "stdin", SimpleNamespace(buffer=source)):
                        with self.assertRaises(EOFError):
                            REPORT.read_inputs(["-" if standard_input else "broken.gz"], REPORT.Report())
                self.assertEqual(source.closed, not standard_input)

    def test_short_stdin_detection(self):
        for payload in (b"", b"\x1f", b"\n"):
            with self.subTest(payload=payload):
                report = self.run_tool(paths=["-"], stdin=payload, expected=1)
                self.assertEqual(report["errors"], {"no_complete_snapshots": 1})
        self.run_tool(paths=["-"], stdin=b"\x1f\x8b", expected=2)

    def test_traffic_excerpt_uses_window_deltas(self):
        report = self.run_tool(paths=[FIXTURES / "traffic.log"])
        item = report["instances"][0]
        self.assertEqual(report["counts"]["complete_snapshots"], 2)
        self.assertEqual(report["counts"]["ignored_lines"], 1)
        self.assertEqual(item["counter_deltas"]["listener.accepted_total"], 6)
        self.assertEqual(item["counter_deltas"]["listener.worker_spawn_total"], 1)
        self.assertIsNone(item["version"])

    def test_unterminated_record_and_oversized_record(self):
        report = self.run_tool(BATCHES[0][:-1], expected=1)
        self.assertIn("invalid_physical_record", report["errors"])
        oversized = METRICS[0][:-1] + b" ignored=" + b"x" * 70000 + b"\n"
        report = self.run_tool(oversized + b"".join(METRICS[1:48]), expected=1)
        self.assertIn("invalid_physical_record", report["errors"])


if __name__ == "__main__":
    unittest.main()
