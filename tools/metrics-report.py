#!/usr/bin/env python3
"""Offline validation and reporting for mcrelay schema-1 metrics (Python 3.8+)."""

import argparse
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime
import csv
import gzip
import io
import json
from pathlib import Path
import re
import sys
import zlib

# Frozen schema-1 baseline from doc/information/metrics.md. No repository files
# are needed at runtime; later optional trailing fields remain compatible.
FIELDS = {
    'meta': (
        'reason lines pid started_mono_sec started_mono_nsec uptime_ms missed_intervals '
        'scheduler_failures logger_errors format_drops'
    ),
    'listener': (
        'accepted_total accept_capacity_rejected_total accept_fd_exhausted_total '
        'connection_track_failure_total connections_current connections_high_water connection_limit '
        'worker_spawn_total worker_fork_failure_total worker_capacity_refusal_total workers_current '
        'workers_high_water worker_limit listener_saturation_total'
    ),
    'capacity/storage': (
        'cache_entries_current cache_entries_high_water cache_entry_limit cache_owned_bytes_current '
        'cache_owned_bytes_high_water cache_owned_byte_limit cache_result_byte_limit '
        'assemblies_nonterminal_current assembly_owned_bytes_current assembly_owned_bytes_high_water '
        'assembly_owned_byte_limit cache_saturation_total assembly_saturation_total'
    ),
    'capacity/supervisor': (
        'jobs_current jobs_high_water job_limit interactive_reserve jobs_queued jobs_sending '
        'jobs_dispatched jobs_retry_wait jobs_complete jobs_background jobs_interactive '
        'orphaned_dispatched_current queue_background_current queue_background_high_water '
        'queue_interactive_current queue_interactive_high_water interests_background_current '
        'interests_interactive_current helper_limit supervisor_saturation_total'
    ),
    'schedule': (
        'started coalesced complete fresh bad_argument io limit memory time limit_interest_count '
        'limit_background_admission limit_total_admission limit_entry_reference'
    ),
    'attempt': (
        'dispatched response_ok response_bad_argument response_limit response_malformed response_memory '
        'response_nodata response_not_found response_permanent response_temporary response_truncated '
        'failure_exit failure_io failure_protocol failure_timeout retry_scheduled orphan_response_ok '
        'orphan_response_bad_argument orphan_response_limit orphan_response_malformed '
        'orphan_response_memory orphan_response_nodata orphan_response_not_found '
        'orphan_response_permanent orphan_response_temporary orphan_response_truncated '
        'completion_enqueued completion_taken attempt_abandoned_shutdown completion_abandoned_shutdown '
        'jobs_dispatched_current jobs_complete_current'
    ),
    'cache': (
        'acquire_created acquire_reused acquire_bad_argument acquire_reference_limit acquire_entry_limit '
        'acquire_id_limit acquire_owned_byte_limit acquire_memory publish_stored publish_transient '
        'publish_bad_argument publish_invalid publish_limit publish_memory publish_time '
        'publish_limit_result_bytes publish_limit_owned_bytes value_positive value_nxdomain value_nodata '
        'expiry_positive expiry_nxdomain expiry_nodata resident_positive resident_nxdomain '
        'resident_nodata'
    ),
    'assembly': (
        'create_ok create_bad_argument create_limit create_memory limit_result_shape limit_result_bytes '
        'limit_budget_bytes terminal_complete terminal_bad_argument terminal_limit terminal_memory '
        'terminal_protocol abandoned nonterminal_current'
    ),
    'route': (
        'requests_started resolution_local resolution_bypass resolution_immediate resolution_waited '
        'outcome_ready outcome_contradictory outcome_limit outcome_memory outcome_no_route '
        'outcome_service_unavailable outcome_timeout outcome_unavailable outcome_abandoned '
        'outcome_shutdown outcome_internal_error pending_current pending_high_water release_failure '
        'selected_ipv4 selected_ipv6'
    ),
    'helper': (
        'failure_exit failure_io failure_protocol failure_spawn failure_timeout spawn_attempt '
        'spawn_success recovery_success_streak recovery_stable_uptime observation_dropped state_idle '
        'state_sending state_busy state_backoff state_shutting_down state_stopped'
    ),
}

HISTOGRAM_FIELDS = {
    'dispatch_wait_ms': 'le_1 le_5 le_10 le_25 le_50 le_100 le_250 le_500 le_1000 le_2000 le_5000 le_10000 le_30000 le_inf count sum_us sample_errors',
    'attempt_ms': 'le_1 le_5 le_10 le_25 le_50 le_100 le_250 le_500 le_1000 le_2000 le_5000 le_10000 le_30000 le_inf count sum_us sample_errors',
    'ttl_seconds': 'le_0 le_1 le_5 le_30 le_60 le_300 le_1800 le_3600 le_21600 le_86400 le_604800 le_2592000 le_inf count sum_seconds',
    'assembly_bytes': 'le_0 le_64 le_256 le_1024 le_4096 le_16384 le_65536 le_262144 le_1048576 le_inf count sum_bytes',
    'route_ms': 'le_1 le_5 le_10 le_25 le_50 le_100 le_250 le_500 le_1000 le_2000 le_5000 le_10000 le_30000 le_inf count sum_us sample_errors',
}

MAX_U64 = (1 << 64) - 1
MAX_RECORD_BYTES = 65536
MAX_MESSAGE_BYTES = 2048
COMMON = ("schema", "seq", "family", "instance")
DELIVERY = ("missed_intervals", "scheduler_failures", "logger_errors", "format_drops")
PREFIX = re.compile(rb"^\[([^\]\r\n]*)\] \[(CRIT|WARN|INFO)\] (.*)$")
TOKEN = re.compile(r"^[a-z][a-z0-9_]*=[!-<>-~]+$")
DECIMAL = re.compile(r"^[0-9]{1,20}$")
INSTANCE = re.compile(r"^([0-9]{1,20})-([0-9]{1,20})-([0-9]{1,20})$")
STARTUP = re.compile(r"^Starting mcrelay (v[!-~]+) on PID ([0-9]+)\.\.\.$")
REASONS = {"startup", "periodic", "reconfigure", "disable", "shutdown"}


def schema_rows():
    rows = {}

    def add(family, dimensions=(), fields=None):
        identity = (family,) + tuple(value for key, value in dimensions)
        rows[identity] = (dimensions, tuple((fields or FIELDS[family]).split()))

    add("meta")
    add("listener")
    for scope in ("storage", "supervisor"):
        add("capacity", (("scope", scope),), FIELDS["capacity/" + scope])
    for priority in ("background", "interactive"):
        for qtype in ("a", "aaaa", "srv", "other"):
            add("schedule", (("priority", priority), ("qtype", qtype)))
    for family in ("attempt", "cache", "assembly"):
        for qtype in ("a", "aaaa", "srv") + (("other",) if family == "cache" else ()):
            add(family, (("qtype", qtype),))
    for mode in ("short", "worker"):
        add("route", (("request_mode", mode),))
    add("helper")
    for name, fields in HISTOGRAM_FIELDS.items():
        if name == "dispatch_wait_ms":
            dimensions = [(("priority", p), ("qtype", q)) for p in ("background", "interactive") for q in ("a", "aaaa", "srv")]
        elif name == "ttl_seconds":
            dimensions = [(("qtype", q), ("payload_kind", k)) for q in ("a", "aaaa", "srv") for k in ("positive", "nxdomain", "nodata")]
        elif name == "route_ms":
            dimensions = [(("request_mode", mode),) for mode in ("short", "worker")]
        else:
            dimensions = [(("qtype", q),) for q in ("a", "aaaa", "srv")]
        for values in dimensions:
            add("histogram", (("name", name),) + values, fields)
    return rows


ROWS = schema_rows()
BY_FAMILY = {}
for _identity, (_dimensions, _fields) in ROWS.items():
    BY_FAMILY.setdefault(_identity[0], []).append((_identity, _dimensions, _fields))


def counter(identity, key):
    family = identity[0]
    if family == "meta":
        return key in DELIVERY
    if family in ("listener", "capacity"):
        return key.endswith("_total")
    if family == "attempt":
        return not key.endswith("_current")
    if family == "cache":
        return not key.startswith("resident_")
    if family == "assembly":
        return key != "nonterminal_current"
    if family == "route":
        return key not in ("pending_current", "pending_high_water")
    if family == "helper":
        return not key.startswith("state_")
    return family in ("schedule", "histogram")


def capacity_limit(identity, key):
    return not counter(identity, key) and (key.endswith("_limit") or key == "interactive_reserve")


def timestamp(text):
    if not text:
        return None
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S UTC%z").isoformat()


def numbers(values):
    return all(DECIMAL.fullmatch(value) and int(value) <= MAX_U64 for value in values)


@dataclass
class Batch:
    sequence: int
    location: dict
    time: object
    rows: dict = field(default_factory=dict)
    bad: bool = False


@dataclass
class Instance:
    name: str
    version: object
    version_source: object
    startup: object = None
    batch: object = None
    first: object = None
    last: object = None
    peaks: dict = field(default_factory=dict)
    unknown: set = field(default_factory=set)
    count: int = 0
    reasons: Counter = field(default_factory=Counter)
    interval_min: object = None
    interval_max: object = None
    gaps: int = 0


class Report:
    def __init__(self, max_instances=1024):
        self.max_instances = max_instances
        self.instances = {}
        self.banners = {}
        self.counts = Counter()
        self.errors = Counter()
        self.warnings = Counter()
        self.examples = []
        self.helper_events = Counter()
        self.helper_failures = Counter()

    def issue(self, code, location, detail="", warning=False):
        (self.warnings if warning else self.errors)[code] += 1
        if len(self.examples) < 30:
            self.examples.append(dict(location, code=code, detail=detail, severity="warning" if warning else "error"))

    def batch_for(self, name, sequence, location, time):
        state = self.instances.get(name)
        if state is None:
            if len(self.instances) >= self.max_instances:
                raise ValueError("instance limit exceeded; increase --max-instances if intentional")
            pid = int(name.split("-", 1)[0])
            state = self.instances[name] = Instance(name, None, None, startup=self.banners.pop(pid, None))
        if state.batch is not None and sequence < state.batch.sequence:
            self.issue("out_of_order_sequence", location, name)
            return None
        if state.batch is None or sequence != state.batch.sequence:
            self.close_batch(state)
            state.batch = Batch(sequence, location, time)
        return state.batch

    def bad_record(self, code, location, message, time):
        self.issue(code, location)
        # A malformed row with a recognizable batch identity must poison that
        # batch, even when its other 48 rows happen to be present.
        identity = re.search(r"(?:^| )instance=([0-9]+-[0-9]+-[0-9]+)(?: |$)", message)
        sequence = re.search(r"(?:^| )seq=([0-9]{1,20})(?: |$)", message)
        if identity and sequence and INSTANCE.fullmatch(identity[1]) and 0 < int(sequence[1]) <= MAX_U64:
            batch = self.batch_for(identity[1], int(sequence[1]), location, time)
            if batch is not None:
                batch.bad = True

    def consume(self, raw, location, oversized=False):
        self.counts["physical_lines"] += 1
        terminated = raw.endswith(b"\n")
        line = raw[:-1] if terminated else raw
        match = PREFIX.fullmatch(line)
        if match is None:
            self.counts["ignored_lines"] += 1
            return
        stamp, level, encoded = match.groups()
        reserved = encoded.startswith((b"metrics schema=", b"resolver_helper", b"Starting mcrelay "))
        if not reserved:
            self.counts["ignored_lines"] += 1
            return
        try:
            message = encoded.decode("ascii")
            time = timestamp(stamp.decode("ascii"))
        except (UnicodeError, ValueError):
            self.bad_record("invalid_prefix_or_encoding", location, encoded.decode("ascii", "replace"), None)
            return
        if oversized or not terminated or len(encoded) > MAX_MESSAGE_BYTES or b"\r" in encoded or b"\0" in encoded:
            self.bad_record("invalid_physical_record", location, message, time)
            return
        if message.startswith("Starting mcrelay "):
            banner = STARTUP.fullmatch(message)
            if level != b"INFO" or banner is None or not 0 < int(banner[2]) <= (1 << 31) - 1:
                self.issue("invalid_startup_version", location)
                return
            self.banners[int(banner[2])] = (banner[1], location)
            if len(self.banners) > self.max_instances:
                raise ValueError("unmatched startup limit exceeded; increase --max-instances if intentional")
            self.counts["startup_version_records"] += 1
            return
        tokens = message.split(" ")
        if any(TOKEN.fullmatch(token) is None for token in tokens[1:]):
            self.bad_record("invalid_tokens", location, message, time)
            return
        items = [token.split("=", 1) for token in tokens[1:]]
        values = dict(items)
        keys = tuple(key for key, value in items)
        if len(items) != len(values):
            self.bad_record("duplicate_keys", location, message, time)
            return
        if tokens[0] == "resolver_helper":
            expected = {
                "degraded": ("status", "slot", "pid", "failure", "streak", "backoff_ms", "suppressed"),
                "recovered": ("status", "slot", "pid", "recovery", "degraded_ms", "suppressed", "last_failure"),
                "event_loss": ("status", "dropped"),
            }.get(values.get("status"))
            named = {"status", "failure", "recovery", "last_failure"}
            valid = keys == expected and numbers(value for key, value in items if key not in named)
            if values.get("status") == "degraded":
                valid = valid and level == b"WARN" and values.get("failure") in {"exit", "io", "protocol", "spawn", "timeout"}
            elif values.get("status") == "recovered":
                valid = valid and level == b"INFO" and values.get("recovery") in {"success_streak", "stable_uptime"}
                valid = valid and values.get("last_failure") in {"exit", "io", "protocol", "spawn", "timeout"}
            else:
                valid = valid and level == b"WARN"
            if not valid:
                self.issue("invalid_helper_event", location)
                return
            self.counts["helper_event_lines"] += 1
            self.helper_events[values["status"]] += 1
            if "failure" in values:
                self.helper_failures[values["failure"]] += 1
            return
        self.counts["metrics_candidate_lines"] += 1
        if values.get("schema") != "1":
            self.issue("unsupported_schema", location)
            return
        if level != b"INFO" or keys[:4] != COMMON:
            self.bad_record("invalid_common_fields", location, message, time)
            return
        candidates = [(identity, dimensions, fields) for identity, dimensions, fields in BY_FAMILY.get(values["family"], ())
                      if all(values.get(key) == value for key, value in dimensions)]
        if len(candidates) != 1:
            self.bad_record("invalid_family_dimensions", location, message, time)
            return
        identity, dimensions, fields = candidates[0]
        baseline = COMMON + tuple(key for key, value in dimensions) + fields
        if keys[:len(baseline)] != baseline:
            self.bad_record("invalid_baseline_order", location, message, time)
            return
        if not numbers((values["seq"],)) or int(values["seq"]) == 0 or INSTANCE.fullmatch(values["instance"]) is None:
            self.issue("invalid_instance_or_sequence", location)
            return
        if not numbers(values[key] for key in fields if key != "reason") or (identity == ("meta",) and values["reason"] not in REASONS):
            self.bad_record("invalid_numeric_or_reason", location, message, time)
            return
        row = {key: value if key == "reason" else int(value) for key, value in values.items() if key in fields}
        batch = self.batch_for(values["instance"], int(values["seq"]), location, time)
        if batch is None:
            return
        self.counts["valid_metrics_lines"] += 1
        if identity in batch.rows:
            self.issue("duplicate_row", location, "/".join(identity))
            batch.bad = True
        else:
            batch.rows[identity] = row

    def invariant_errors(self, state, batch):
        rows = batch.rows
        meta = rows[("meta",)]
        storage, jobs = rows[("capacity", "storage")], rows[("capacity", "supervisor")]
        checks = {
            "meta_identity": meta["lines"] == 48 and state.name == "{}-{}-{}".format(meta["pid"], meta["started_mono_sec"], meta["started_mono_nsec"])
                             and 0 < meta["pid"] <= (1 << 31) - 1 and meta["started_mono_nsec"] < 1000000000,
            "jobs_state_sum": jobs["jobs_current"] == sum(jobs["jobs_" + key] for key in ("queued", "sending", "dispatched", "retry_wait", "complete")),
            "jobs_priority_sum": jobs["jobs_current"] == jobs["jobs_background"] + jobs["jobs_interactive"],
            "dispatched_sum": jobs["jobs_dispatched"] == sum(rows[("attempt", q)]["jobs_dispatched_current"] for q in ("a", "aaaa", "srv")),
            "complete_sum": jobs["jobs_complete"] == sum(rows[("attempt", q)]["jobs_complete_current"] for q in ("a", "aaaa", "srv")),
            "orphan_subset": jobs["orphaned_dispatched_current"] <= jobs["jobs_dispatched"],
            "assembly_sum": storage["assemblies_nonterminal_current"] == sum(rows[("assembly", q)]["nonterminal_current"] for q in ("a", "aaaa", "srv")),
            "resident_subset": sum(rows[("cache", q)]["resident_" + kind] for q in ("a", "aaaa", "srv", "other")
                                   for kind in ("positive", "nxdomain", "nodata")) <= storage["cache_entries_current"],
        }
        for mode in ("short", "worker"):
            row = rows[("route", mode)]
            if all(value < MAX_U64 for value in row.values()):
                checks["route_settlement_" + mode] = row["requests_started"] == sum(v for k, v in row.items() if k.startswith("outcome_")) + row["pending_current"]
        for identity, row in rows.items():
            if identity[0] == "histogram" and all(value < MAX_U64 for value in row.values()):
                buckets = [value for key, value in row.items() if key.startswith("le_")]
                checks["histogram/" + "/".join(identity[1:])] = buckets == sorted(buckets) and row["le_inf"] == row["count"]
        return [key for key, valid in checks.items() if not valid]

    def close_batch(self, state):
        batch = state.batch
        if batch is None:
            return
        if len(batch.rows) != 48:
            self.issue("incomplete_snapshot", batch.location, "{} seq={} rows={}/48".format(state.name, batch.sequence, len(batch.rows)))
            batch.bad = True
        elif tuple(batch.rows) != tuple(ROWS):
            self.issue("invalid_row_order", batch.location, state.name)
            batch.bad = True
        else:
            for check in self.invariant_errors(state, batch):
                self.issue("invariant_violation", batch.location, check)
                batch.bad = True
        if batch.bad:
            self.counts["rejected_snapshots"] += 1
            return
        if state.first is None:
            if batch.sequence == 1 and batch.rows[("meta",)]["reason"] == "startup" and state.startup is not None:
                state.version, state.version_source = state.startup
            state.startup = None
        self.counts["complete_snapshots"] += 1
        if state.last is not None:
            if batch.sequence != state.last.sequence + 1:
                missing = batch.sequence - state.last.sequence - 1
                self.issue("sequence_gap", batch.location, "{} missing={}".format(state.name, missing))
                state.gaps += missing
            elapsed = batch.rows[("meta",)]["uptime_ms"] - state.last.rows[("meta",)]["uptime_ms"]
            if elapsed < 0:
                self.issue("uptime_decreased", batch.location, state.name)
            elif batch.rows[("meta",)]["reason"] == "periodic":
                state.interval_min = elapsed if state.interval_min is None else min(state.interval_min, elapsed)
                state.interval_max = elapsed if state.interval_max is None else max(state.interval_max, elapsed)
        for identity, row in batch.rows.items():
            for key, value in row.items():
                if not isinstance(value, int):
                    continue
                label = "/".join(identity) + "." + key
                state.peaks[label] = max(state.peaks.get(label, value), value)
                if counter(identity, key) and value == MAX_U64 and label not in state.unknown:
                    self.issue("counter_saturated", batch.location, label, warning=True)
                    state.unknown.add(label)
                if state.last is not None and (counter(identity, key) or key.endswith("_high_water")) and value < state.last.rows[identity][key]:
                    self.issue("counter_decreased", batch.location, label)
                    state.unknown.add(label)
                if state.last is not None and capacity_limit(identity, key) and value != state.last.rows[identity][key]:
                    self.issue("limit_changed", batch.location, label)
            if identity[0] == "histogram" and state.last is not None:
                old = state.last.rows[identity]
                if all(value < MAX_U64 for value in row.values()) and all(value < MAX_U64 for value in old.values()):
                    buckets = [value - old[key] for key, value in row.items() if key.startswith("le_")]
                    if buckets != sorted(buckets):
                        self.issue("invalid_histogram_delta", batch.location, "/".join(identity))
                        state.unknown.update("/".join(identity) + "." + key for key in row)
        state.first = state.first or batch
        state.last = batch
        state.count += 1
        state.reasons[batch.rows[("meta",)]["reason"]] += 1

    def result(self):
        for state in self.instances.values():
            self.close_batch(state)
            state.batch = None
        if not self.counts["complete_snapshots"]:
            self.issue("no_complete_snapshots", {})
        instances, aggregate = [], {}
        for state in self.instances.values():
            if state.first is None:
                continue
            deltas, current, limits = {}, {}, {}
            for identity, row in state.last.rows.items():
                for key, value in row.items():
                    if not isinstance(value, int):
                        continue
                    label = "/".join(identity) + "." + key
                    if counter(identity, key):
                        delta = None if label in state.unknown else value - state.first.rows[identity][key]
                        deltas[label] = delta
                        aggregate[label] = None if delta is None or aggregate.get(label, 0) is None else aggregate.get(label, 0) + delta
                    elif capacity_limit(identity, key):
                        limits[label] = value
                    elif key != "uptime_ms" and identity != ("meta",):
                        current[label] = value
            histograms = {}
            for identity in ROWS:
                if identity[0] != "histogram":
                    continue
                prefix = "/".join(identity) + "."
                fields = {key: deltas[prefix + key] for key in ROWS[identity][1]}
                unit, sum_key = ("ms", "sum_us") if "sum_us" in fields else ("seconds", "sum_seconds") if "sum_seconds" in fields else ("bytes", "sum_bytes")
                count = fields["count"]
                valid = all(value is not None for value in fields.values())
                mean = fields[sum_key] / count / (1000 if unit == "ms" else 1) if valid and count else None
                upper_bounds = {}
                for percentile in (50, 95, 99):
                    bound = next((key[3:] for key, value in fields.items() if key.startswith("le_") and value * 100 >= count * percentile), None) if valid and count else None
                    upper_bounds["p" + str(percentile)] = int(bound) if bound not in (None, "inf") else None
                histograms["/".join(identity[1:])] = {"count": count, "unit": unit, "mean": mean, "percentile_upper_bounds": upper_bounds,
                                                     "sample_errors": fields.get("sample_errors", 0)}
            span_ms = state.last.rows[("meta",)]["uptime_ms"] - state.first.rows[("meta",)]["uptime_ms"]
            instances.append({
                "instance": state.name, "version": state.version, "version_source": state.version_source,
                "first": {"seq": state.first.sequence, "time": state.first.time, "reason": state.first.rows[("meta",)]["reason"]},
                "last": {"seq": state.last.sequence, "time": state.last.time, "reason": state.last.rows[("meta",)]["reason"]},
                "complete_snapshots": state.count, "reasons": dict(state.reasons), "span_seconds": span_ms / 1000 if span_ms >= 0 else None,
                "sequence_gaps": state.gaps,
                "periodic_spacing_ms": {"min": state.interval_min, "max": state.interval_max},
                "counter_deltas": deltas, "current": current, "lifetime_peaks": {key: value for key, value in state.peaks.items() if key.endswith("_high_water")},
                "sampled_gauge_peaks": {key: state.peaks[key] for key in current if not key.endswith("_high_water")},
                "limits": limits, "histograms": histograms,
            })
        return {"report_schema": 1, "ok": not self.errors, "counts": dict(self.counts), "errors": dict(self.errors), "warnings": dict(self.warnings),
                "issue_examples": self.examples, "helper_events": dict(self.helper_events), "helper_failure_events": dict(self.helper_failures),
                "instances": instances, "aggregate_counter_deltas": aggregate,
                "notes": ["Counter deltas use the first complete snapshot of each instance as baseline; incomplete snapshots are excluded.",
                          "Lifetime high-water marks are not interval peaks; accounted bytes are not RSS.",
                          "Histogram percentiles are inclusive bucket upper bounds; null also represents an unbounded or unavailable result.",
                          "Versions require a matching startup record and an initial complete startup snapshot; later snapshots alone do not establish identity.",
                          "Route ready is not end-to-end connection success. Resource-cost acceptance requires separate measurements."]}


def expand_inputs(paths, log_name):
    expanded = []
    pattern = re.compile(re.escape(log_name) + r"(?:\.([0-9]+))?(?:\.gz)?$")
    for name in paths:
        if name != "-" and Path(name).is_dir():
            matches = [path for path in Path(name).iterdir() if path.is_file() and pattern.fullmatch(path.name)]
            if not matches:
                raise ValueError("no {} rotations found in {}".format(log_name, name))
            matches.sort(key=lambda path: -int(pattern.fullmatch(path.name)[1] or 0))
            expanded.extend(str(path) for path in matches)
        else:
            expanded.append(name)
    # Sort each recognized logrotate family in its first input position.
    # Gaps in rotation file numbers say nothing about metrics completeness.
    groups = []
    for name in expanded:
        configured = pattern.fullmatch(Path(name).name) if name != "-" else None
        match = re.fullmatch(r"(.+\.log)(?:\.([0-9]+))?(?:\.gz)?", Path(name).name) if name != "-" else None
        base, rotation = (log_name, int(configured[1] or 0)) if configured else (match[1], int(match[2] or 0)) if match else (None, 0)
        key = (str(Path(name).parent.resolve()), base) if base is not None else (name, None)
        if not groups or groups[-1][0] != key:
            groups.append((key, []))
        groups[-1][1].append((rotation, name))
    return [name for key, group in groups for index, name in sorted(group, key=lambda item: -item[0])]


class PrefixReader(io.RawIOBase):
    """Replay the bounded detection prefix without owning the underlying input."""

    def __init__(self, raw, prefix):
        super().__init__()
        self.raw = raw
        self.prefix = prefix

    def readable(self):
        return True

    def readinto(self, target):
        if self.prefix:
            size = min(len(target), len(self.prefix))
            target[:size], self.prefix = self.prefix[:size], self.prefix[size:]
            return size
        data = self.raw.read(len(target))
        if data is None:
            return None
        target[:len(data)] = data
        return len(data)


def read_inputs(paths, report):
    for name in paths:
        with ExitStack() as inputs:
            raw = sys.stdin.buffer if name == "-" else inputs.enter_context(open(name, "rb"))
            prefix = b""
            while len(prefix) < 2:
                part = raw.read(2 - len(prefix))
                if not part:
                    break
                prefix += part
            buffered = inputs.enter_context(io.BufferedReader(PrefixReader(raw, prefix)))
            stream = inputs.enter_context(gzip.GzipFile(fileobj=buffered)) if prefix == b"\x1f\x8b" else buffered
            number = 0
            while True:
                line = stream.readline(MAX_RECORD_BYTES + 1)
                if not line:
                    break
                number += 1
                report.counts["input_bytes"] += len(line)
                oversized = len(line) > MAX_RECORD_BYTES
                if oversized and not line.endswith(b"\n"):
                    while True:
                        tail = stream.readline(MAX_RECORD_BYTES + 1)
                        report.counts["input_bytes"] += len(tail)
                        if not tail or tail.endswith(b"\n"):
                            break
                report.consume(line, {"input": name, "line": number}, oversized)


def compact_rows(report):
    for item in report["instances"]:
        delta = item["counter_deltas"]
        yield {"instance": item["instance"], "version": item["version"], "first_time": item["first"]["time"], "last_time": item["last"]["time"],
               "snapshots": item["complete_snapshots"], "span_seconds": item["span_seconds"], "sequence_gaps": item["sequence_gaps"],
               "accepted_delta": delta["listener.accepted_total"], "worker_spawn_delta": delta["listener.worker_spawn_total"],
               "connections_high_water": item["lifetime_peaks"]["listener.connections_high_water"],
               "workers_high_water": item["lifetime_peaks"]["listener.workers_high_water"],
               "jobs_high_water": item["lifetime_peaks"]["capacity/supervisor.jobs_high_water"],
               "cache_owned_bytes_high_water": item["lifetime_peaks"]["capacity/storage.cache_owned_bytes_high_water"],
               **{key: delta["meta." + key] for key in DELIVERY}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog="Logrotate families are sorted oldest first; other inputs retain their supplied order. Exit: 0 valid report, 1 data errors, 2 usage/input error.")
    parser.add_argument("logs", nargs="+", help="log/gzip files, log directories, or '-' for stdin (plain or gzip)")
    parser.add_argument("--log-name", default="access.log", help="base filename for directory scanning and explicit rotation ordering (default: access.log)")
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text")
    parser.add_argument("--max-instances", type=int, default=1024, help="bound retained instance/startup state (default: 1024)")
    args = parser.parse_args(argv)
    if args.logs.count("-") > 1 or args.max_instances <= 0 or Path(args.log_name).name != args.log_name:
        parser.error("stdin can appear once, --max-instances must be positive, and --log-name must be a basename")
    report = Report(args.max_instances)
    try:
        read_inputs(expand_inputs(args.logs, args.log_name), report)
        result = report.result()
    except (OSError, EOFError, ValueError, zlib.error) as error:
        print("metrics-report: {}".format(error), file=sys.stderr)
        return 2
    if args.format == "json":
        json.dump(result, sys.stdout, indent=2, ensure_ascii=True)
        print()
    elif args.format == "csv":
        rows = list(compact_rows(result))
        if rows:
            writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        if not result["ok"]:
            print("metrics-report: {} validation errors; use --format json for details".format(sum(result["errors"].values())), file=sys.stderr)
    else:
        print("Snapshots: {} complete, {} rejected; helper events: {}".format(result["counts"].get("complete_snapshots", 0),
              result["counts"].get("rejected_snapshots", 0), sum(result["helper_events"].values())))
        print("Validation: {} errors, {} warnings".format(sum(result["errors"].values()), sum(result["warnings"].values())))
        print("Helper observations: {}; failures: {}".format(result["helper_events"], result["helper_failure_events"]))
        for row in compact_rows(result):
            print("\n{}  version={}".format(row["instance"], row["version"] or "unknown"))
            print("  {} -> {}; {} snapshots; {} seconds; {} sequence gaps".format(row["first_time"] or "unknown time", row["last_time"] or "unknown time",
                  row["snapshots"], row["span_seconds"], row["sequence_gaps"]))
            print("  Counter deltas: accepted={}, worker spawns={}; {}".format(row["accepted_delta"], row["worker_spawn_delta"],
                  ", ".join("{}={}".format(key, row[key]) for key in DELIVERY)))
            print("  Lifetime peaks: connections={}, workers={}, jobs={}, cache owned bytes={}".format(row["connections_high_water"],
                  row["workers_high_water"], row["jobs_high_water"], row["cache_owned_bytes_high_water"]))
        for item in result["instances"]:
            for mode in ("short", "worker"):
                prefix = "route/" + mode + "."
                outcomes = {key[len(prefix):]: value for key, value in item["counter_deltas"].items()
                            if key.startswith(prefix + "outcome_") and value != 0}
                print("  {} {} route outcomes: {}".format(item["instance"], mode, outcomes))
            for name, histogram in item["histograms"].items():
                if histogram["count"] and (name.startswith("attempt_ms/") or name.startswith("route_ms/")):
                    mean = "unavailable" if histogram["mean"] is None else format(histogram["mean"], ".3g")
                    bound = histogram["percentile_upper_bounds"]["p95"]
                    print("  {} {}: samples={}, mean={} {}, p95 upper bound={} {}".format(item["instance"], name, histogram["count"],
                          mean, histogram["unit"], bound if bound is not None else "unbounded/unknown", histogram["unit"]))
        for issue in result["issue_examples"]:
            print("{}: {}:{} {} {}".format(issue["severity"], issue.get("input", "-"), issue.get("line", "-"), issue["code"], issue["detail"]))
        print("\n" + "\n".join(result["notes"]))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
