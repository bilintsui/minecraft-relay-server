# Offline Metrics reports
`tools/metrics-report.py` is a standalone, read-only consumer of mcrelay schema-1 logs. It requires Python 3.8 or later and uses only the standard library. It does not connect to or control mcrelay, open a network endpoint, or change the server's metrics output. Python is not a dependency of the daemon.

## Run it
Read the current log and all numbered rotations from a directory:

```sh
python3 tools/metrics-report.py /var/log/mcrelay
```

The default basename is `access.log`; use `--log-name relay.log` for a different configuration. This option also recognizes explicit rotation families without a `.log` suffix, for example `--log-name relay /var/log/mcrelay/relay*`. Files can be plain or gzip-compressed. Numbered rotations are processed in descending numeric order, followed by the current file: `.14.gz`, `.11.gz`, `.2.gz`, `.1`, `access.log`. Missing rotation numbers are allowed; data completeness is determined from snapshot rows and sequences rather than filenames.

Explicit inputs and shell globs also work:

```sh
python3 tools/metrics-report.py /var/log/mcrelay/access.log*
python3 tools/metrics-report.py --format json access_with_metrics.log.gz > report.json
python3 tools/metrics-report.py --format csv /var/log/mcrelay > instances.csv
gzip -cd access.log.2.gz | python3 tools/metrics-report.py -
```

Consecutive inputs belonging to the same logrotate family are sorted oldest first. Other filenames and stdin retain their supplied order, so list differently named excerpts chronologically. Gzip is detected by its header, including on stdin. Reading multiple files preserves a batch across rotation boundaries between complete physical lines. A physical record missing its final LF is invalid; two partial physical records are never stitched together or resynchronized in the middle.

The default text report summarizes delivery health, per-instance counter deltas, lifetime capacity peaks, route outcomes, and nonempty attempt/route latency histograms. JSON contains the detailed counters, current gauges, limits, sampled gauge maxima, all histograms, and bounded diagnostic examples. CSV has one summary row per instance.

Debian packages also include the optional script at `/usr/share/doc/mcrelay/examples/metrics-report.py`; use that path with `python3` when running the packaged copy.

## Validation and exit status
The consumer recognizes metrics/helper records only after an exact logger prefix at the start of a physical LF-delimited line. Text embedded in an ordinary access record is ignored. It validates schema 1's required key order, unique keys, dimensions, unsigned values, row order, all 48 rows, and the documented gauge/route/histogram relationships. Unique optional trailing keys are accepted; unknown schema versions are reported without being interpreted as schema 1. Helper events use their separate closed grammar.

Duplicate/missing rows, invalid records, out-of-order sequences, sequence gaps, counter decreases, changed limits, and invalid histogram deltas are reported. A malformed row matching the currently assembled instance/sequence invalidates that batch even if its other 48 valid rows are present. Only complete batches passing row structure and snapshot consistency checks enter the report. Late records for earlier sequences are reported and ignored. Cross-snapshot failures are reported separately, with affected counter deltas made unknown where applicable.

| Exit | Meaning |
| --- | --- |
| 0 | At least one complete snapshot and no validation errors; inspect warnings too |
| 1 | Data validation errors, or no complete snapshots; a report is still produced |
| 2 | Usage/input failure, including unreadable files or invalid gzip; no complete report is produced |

Counter saturation is a warning. A saturated or decreasing field has a JSON `null` delta, which also propagates to its aggregate and histogram interpretation; it must not be treated as an exact zero. Missing/unbounded histogram percentile bounds also use `null`. With CSV output, unknown values are empty cells and validation errors are summarized on stderr; use JSON for diagnostic details.

The reader streams input without retaining whole files or every snapshot. It retains baseline/latest/current batches and spacing extrema per instance, plus bounded diagnostic examples. `--max-instances` bounds retained instance and unmatched-startup state (default 1024); exceeding it is an input error. Physical records longer than 64 KiB are drained as one record, and metrics/helper messages still have their independent 2048-byte limit. Input files are never modified.

## Interpret the result
- Deltas use the first complete snapshot of each instance as its baseline. Instances are never subtracted from each other. Data before the first available complete snapshot is outside that observation window. JSON `aggregate_counter_deltas` sums only those independent window deltas.
- Lifetime high-water marks are reported separately and never summed across instances. They can reflect activity before the observation window. Sampled gauge peaks describe only sampled values; module-owned bytes are not RSS.
- In a `cache` row, `publish_limit` counts publications rejected at a capacity limit. An increase is a valid counter delta. The `limit_changed` diagnostic applies to changes in a configured capacity such as `cache_owned_byte_limit` within one instance.
- Duration sums are recorded in microseconds, while reported duration means and histogram bounds are in milliseconds. TTL stays in seconds and assembly size in bytes. Percentiles are inclusive bucket upper bounds, not exact measurements.
- A startup record `Starting mcrelay <full-version> on PID <pid>...` can associate a build with the next matching metrics instance in input order only when its first complete snapshot has `seq=1 reason=startup`. Retain rotations containing both records. An old record is never used to infer a version for an instance first observed through reload or a later snapshot, even with the same PID. A consumed record is not reused. Historical, incomplete-startup or partial logs without this evidence report `version: null` / `version=unknown`; no wall-clock proximity, release date or currently installed binary is used to guess. PID-only startup records cannot establish identity across omitted process starts, so supply a continuous startup log for attribution.
- Ordinary access records are counted as ignored lines; client addresses, vhosts, and usernames are not copied into the report. Route `ready` is not an end-to-end connection success rate. Helper events and failure counters need operational context, especially for older builds that reported expected exits during service stop.
- This report supplies observation evidence. It does not automatically accept production CPU/RSS cost, authorize DNS/health policy changes, or prove behavior under a load absent from the sample.

## Regression coverage
`tests/fixtures/metrics/` contains anonymized excerpts from the supplied production archive. Run the standard-library regression suite directly with `python3 tests/metrics_report.py`, or use CTest's `metrics_report` case. CMake registers the Python consumer/startup-version tests when Python 3.8+ is available; the C-only build remains available without it.
