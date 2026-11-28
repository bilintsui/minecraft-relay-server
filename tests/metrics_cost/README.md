# Metrics resource measurement tools
Opt-in native Linux tools for measuring Metrics CPU and memory cost. They require Python 3.8+, the normal build dependencies, a user systemd manager with cgroup CPU/memory accounting, and at least two available CPUs. The driver and backend/DNS servers run outside the measured service cgroups.

## Comparison groups
| Group | Executable | Metrics interval |
| --- | --- | --- |
| A | Control built with an externally supplied patch removing Metrics accumulation, storage and output | `0` |
| B | Normal executable, accumulation enabled | `0` |
| C | Same executable as B, accumulation and output enabled | `900` |

The control patch must match the exact source and retain unrelated correctness fixes, resolver policy and capacity limits. All groups use matching Release flags/definitions without sanitizers. The test-only DNS redirect sends real resolver queries to a loopback provider; no system resolver edit is needed.

## Run the suite
Create a fresh `/tmp/mcrelay-metrics-cost-*` directory on the native test host. Put the committed source archive there as `source.tar` and its matching external control patch as `control.patch`, then run:

```sh
bash tests/metrics_cost/native.sh /tmp/mcrelay-metrics-cost-EXPERIMENT
```

The runner requires both inputs before building. It builds normal/control executables and support tools, verifies compiler flags and production symbol isolation, then runs smoke checks, fixed-work load and memory comparisons, snapshot timing, a real 900-second cadence check, analysis and audit. `phase`, `status` and per-stage logs record progress. Each daemon runs in its own pinned, accounted transient service with detached standard streams and exact-unit cleanup.

The lower-level tools accept `--help`:

| Tool | Purpose |
| --- | --- |
| `run.py` | Run `smoke`, `suite`, `dns` or `cadence` profiles with supplied control/normal binaries |
| `snapshots.py` | Time complete snapshot collection/output and validate each log with the formal consumer |
| `layouts.py` | Read compiler DWARF object sizes and member offsets from normal/control binaries |
| `analyze.py` | Summarize retained paired CPU, latency, memory and snapshot samples |
| `audit.py` | Independently check the standard suite's saved results and final daemon logs |

## Retain reproducible evidence
Keep each experiment's source archive, external control/diagnostic patches, tool versions, executable hashes, build flags, environment, commands and raw results together in an untracked archive. The runner records the external control patch's hash in `raw/provenance.json`. Source-modifying experiment patches, investigation reports and run reports are not part of the tracked tools. Use the original archived inputs and tool versions when reproducing an existing result.

Raw results include CPU endpoints, process/cgroup samples, latencies, query/response bytes and timestamps, compressed daemon logs and complete snapshot validation. Retrieve and verify the evidence before removing exact test processes, units and temporary directories. Diagnostic binaries and traces belong to their matching experiment archives and are excluded from cost comparisons.

## Interpret results
- Require identical completed work, exact backend/DNS counts, unchanged helper PID/start-time identities and clean final logs. DNS trials wait for both helpers to become idle between requests; `--dns-a-delay-ms` controls the provider's configured A-response delay and is retained in the result.
- Cgroup CPU includes listener, helpers and short-lived workers. Compare PSS/private pages for memory; summed RSS double-counts shared pages. Preserve cgroup memory and unavailable-process observations too.
- Match repetition pairs before taking difference medians, retain negative differences, and distinguish observed ranges from confidence intervals. Variation larger than the paired difference leaves that cost unresolved.
- Short C trials measure initialized/armed state rather than a 900-second periodic output. Cadence endpoints require the complete 48-line frame. Direct snapshot timing includes all owner getters and the production formatter/logger after warm-up, with individual CPU and wall samples retained.
- Measured cache/job occupancies, sampled memory maxima and wall-time tails apply to those scenarios. They do not establish hard latency, storage, maximum-cache/maximum-worker or long-duration leak bounds.

## Immediate-response DNS regression
```sh
python3 tests/metrics_cost/verify_resolver_timestamps.py \
    --binary PATH_TO_MCRELAY --tools SUPPORT_BUILD --results NEW_DIRECTORY
```

Exercises helper-response timestamp validation with immediate A/AAAA replies and output disabled/enabled. Work counts, helper identities, final logs, full C snapshots and error counters must pass. `--requests` and `--repetitions` control the run size; original samples, packets, timestamps and executable hashes are retained in the result directory.

The deterministic C regression also runs as `resolver_supervisor_test --response-timestamps`. Its clock wrapper is linked only to supervisor test targets.

## Paired DNS and capacity profiles
`experiments.py` runs `dns`, `memory` and `snapshots` into fresh subdirectories of one result root, then `summarize --results ROOT` creates `summary.json`. DNS/memory accept `--normal`, `--control` and `--tools`; snapshots require only `--tools`. Use `--help` for repetition, request and timing controls.

- DNS uses zero configured A-response delay and requires an even repetition count, for example `--repetitions 20`. Each two-pair block balances AB and BA order. The summary retains paired/pooled differences and exploratory whole-block bootstrap intervals; these do not remove host/VM bias.
- Memory repeats A/B/C through 0, 64, 128 and 256 live workers, with steady PSS/private/cgroup samples and an after-close sample. Numeric-route instances use a small cache.
- Snapshots cover empty and 512-entry baselines, full unpublished entries, positive-cache occupancy through the actual entry/owned-byte limit, full admitted jobs, and a mixed entry/positive/job profile. Requested/actual occupancies and compiled limits are retained; no production limit is overridden.

The fixture syntax is `snapshot_cost LOG CSV ITERATIONS CACHE_ENTRIES [PUBLISHED_ENTRIES] [JOBS]`. Job profiles require the test-only loopback redirect; the driver keeps a bound local UDP blackhole to prevent external DNS. Owner state is frozen after scheduling: helpers are limited and remaining jobs queue, while responses are not consumed during timing. This measures getter/formatter/file-output cost at known occupancy, rather than sustained saturated DNS service. Warm-up frames are excluded from timing and all complete output batches are validated.
