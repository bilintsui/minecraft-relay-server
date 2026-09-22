# Operational metrics

mcrelay can periodically write bounded aggregate metrics and resolver-helper state events through its existing logger. This first interface is log based: it does not open a metrics socket, add an HTTP endpoint or change resolver, routing or health policy.

## Enabling aggregate snapshots

Add the optional top-level object below to the runtime configuration:

```json
{
  "metrics": {
    "interval": 300
  }
}
```

`interval` is an integer number of seconds. The allowed values are `0`, which is the default and disables aggregate output, or `300` through `86400`. A fractional value, another JSON type or a value outside that range makes the configuration invalid. Unknown fields inside `metrics` are ignored for forward compatibility.

Aggregate output is effectively enabled only while `interval` is nonzero and `log.level` is at least INFORMATION (level 2). Reducing the log level below 2 disables aggregate output just like setting the interval to 0. Counters, histograms and lifetime high-water marks continue to accumulate while output is disabled; enabling it later exposes process-lifetime values rather than values collected only since enablement.

Resolver-helper `degraded` and `event_loss` WARNING records and `recovered` INFORMATION records do not depend on `metrics.interval`, although the normal log-level filter still applies to them.

## Output lifecycle

Every aggregate snapshot contains one sequence number and one reason:

- `startup` is emitted after initial route-runtime readiness when metrics start effectively enabled.
- `periodic` is emitted on the configured monotonic interval.
- `reconfigure` is emitted after a successful reload first enables metrics or changes the effective interval.
- `disable` is emitted after a successful reload disables metrics. It uses the previous log path and level before the new logging configuration takes effect.
- `shutdown` is emitted after normal resolver shutdown completes and before the metrics owners are destroyed.

Reload does not reset counters, histograms, high-water marks or sequence. A reload that leaves effective enablement and interval unchanged preserves the existing cadence and emits no lifecycle snapshot. A failed reload changes neither the metrics configuration nor its timer.

Sequence begins at 1 and is consumed whenever snapshot preparation starts. A gap can therefore mean a missing or partial delivery rather than a process restart. A new process has a different `instance` and starts its measurements again from zero.

## Log transport and operational cautions

Metrics use the configured log file and are interleaved with access records. With the supplied logrotate configurations, that file is created mode `0644`; aggregate capacity/failure data and resolver-helper PIDs are consequently readable wherever the access log is readable. Configure filesystem access accordingly. A dedicated metrics file is not part of schema 1.

The logger reopens the file for each physical line, so rotation or a sink failure can split or truncate one snapshot. Output is not atomic. A complete schema-1 snapshot has 48 lines, but `lines=48` in the meta record describes the expected shape and does not prove that all lines reached the sink.

Use absent or late `family=meta` records as the real-time delivery alert. `logger_errors` is only retrospective: during a persistent file-sink failure it cannot be delivered through that same sink, and in daemon mode the console is `/dev/null`. Once delivery recovers, it can help explain sequence gaps. `format_drops` reports lines rejected before logging, `scheduler_failures` reports metrics-timer failures, and `missed_intervals` reports elapsed timer periods that were intentionally collapsed into one snapshot.

No metrics failure changes routing, resolver or reload outcomes. A permanent metrics-timer failure disables later periodic output for that process, while helper event logs and the final normal shutdown snapshot remain available on a functioning log sink.

## Record recognition and batching

The logger writes physical records separated by LF. Message content has CR and LF escaped as printable text. Consumers must split only on LF and recognize records only at the beginning of a physical line; they must never search for a metrics-looking prefix in the middle of an access record.

The logger prefix is either:

```text
[YYYY-MM-DD HH:MM:SS UTC±HH:MM] [LEVEL]<SP>
[] [LEVEL]<SP>
```

`<SP>` denotes exactly one ASCII space. The empty timestamp form is possible if clock formatting fails. `LEVEL` is `INFO` for aggregate metrics and `INFO` or `WARN` for helper events. Immediately after that prefix, a candidate aggregate record begins with `metrics schema=` and a helper event begins with `resolver_helper`. Any bytes before the prefix, a truncated record, non-token trailing bytes or a second record glued onto the same physical line invalidate the entire line.

A schema-1 consumer parses only `metrics schema=1`. It must not interpret another decimal schema version as schema 1. Group aggregate lines by the pair `(instance, seq)`, require the fixed baseline dimensions and keys for each line, and confirm all 48 expected rows before treating the snapshot as complete.

Within a schema-1 line, baseline keys are unique and ordered. A compatible future extension may append unique optional `key=value` tokens only after the complete baseline. An older consumer ignores such unknown trailing tokens. A newer consumer must accept an older baseline record that lacks optional extension keys. Missing baseline keys, duplicate keys, known keys out of order, or an extension inserted before baseline completion invalidate the line.

## Aggregate schema 1

Every line begins with this message prefix, before family-specific dimensions and measurements:

```text
metrics schema=1 seq=<n> family=<name> instance=<pid>-<started_mono_sec>-<started_mono_nsec>
```

The preformatted message is bounded to 2048 bytes per line, excluding the logger's timestamp/level prefix and terminating LF. The meta row is emitted first, for example:

```text
metrics schema=1 seq=7 family=meta instance=1234-123456-789 reason=periodic lines=48 pid=1234 started_mono_sec=123456 started_mono_nsec=789 uptime_ms=3600000 missed_intervals=0 scheduler_failures=0 logger_errors=0 format_drops=0
```

One complete snapshot contains the following rows in fixed order:

| Family | Rows | Dimensions and purpose |
|---|---:|---|
| `meta` | 1 | Instance, sequence, reason, uptime and output/scheduler errors |
| `listener` | 1 | Accepted connections, live connections/workers, high-water marks, limits and failures |
| `capacity` | 2 | `scope=storage` and `scope=supervisor` gauges, limits and saturation |
| `schedule` | 8 | `priority=background|interactive` × `qtype=a|aaaa|srv|other` |
| `attempt` | 3 | `qtype=a|aaaa|srv` response, failure, retry, orphan and completion totals |
| `cache` | 4 | `qtype=a|aaaa|srv|other` acquisition, publication, payload and expiry totals |
| `assembly` | 3 | `qtype=a|aaaa|srv` creation, terminal, abandonment and limit totals |
| `route` | 2 | `request_mode=short|worker` resolution, outcome, pending and selected-family totals |
| `helper` | 1 | Failure, spawn, recovery, event-drop and current-state values |
| `histogram` | 23 | Dispatch wait 6, attempt 3, TTL 9, assembly size 3 and route duration 2 |

The fixed baseline measurement keys, in output order, are:

| Family and fixed dimensions | Measurement keys |
|---|---|
| `meta` | `reason lines pid started_mono_sec started_mono_nsec uptime_ms missed_intervals scheduler_failures logger_errors format_drops` |
| `listener` | `accepted_total accept_capacity_rejected_total accept_fd_exhausted_total connection_track_failure_total connections_current connections_high_water connection_limit worker_spawn_total worker_fork_failure_total worker_capacity_refusal_total workers_current workers_high_water worker_limit listener_saturation_total` |
| `capacity scope=storage` | `cache_entries_current cache_entries_high_water cache_entry_limit cache_owned_bytes_current cache_owned_bytes_high_water cache_owned_byte_limit cache_result_byte_limit assemblies_nonterminal_current assembly_owned_bytes_current assembly_owned_bytes_high_water assembly_owned_byte_limit cache_saturation_total assembly_saturation_total` |
| `capacity scope=supervisor` | `jobs_current jobs_high_water job_limit interactive_reserve jobs_queued jobs_sending jobs_dispatched jobs_retry_wait jobs_complete jobs_background jobs_interactive orphaned_dispatched_current queue_background_current queue_background_high_water queue_interactive_current queue_interactive_high_water interests_background_current interests_interactive_current helper_limit supervisor_saturation_total` |
| `schedule priority=<background\|interactive> qtype=<a\|aaaa\|srv\|other>` | `started coalesced complete fresh bad_argument io limit memory time limit_interest_count limit_background_admission limit_total_admission limit_entry_reference` |
| `attempt qtype=<a\|aaaa\|srv>` | `dispatched response_ok response_bad_argument response_limit response_malformed response_memory response_nodata response_not_found response_permanent response_temporary response_truncated failure_exit failure_io failure_protocol failure_timeout retry_scheduled orphan_response_ok orphan_response_bad_argument orphan_response_limit orphan_response_malformed orphan_response_memory orphan_response_nodata orphan_response_not_found orphan_response_permanent orphan_response_temporary orphan_response_truncated completion_enqueued completion_taken attempt_abandoned_shutdown completion_abandoned_shutdown jobs_dispatched_current jobs_complete_current` |
| `cache qtype=<a\|aaaa\|srv\|other>` | `acquire_created acquire_reused acquire_bad_argument acquire_reference_limit acquire_entry_limit acquire_id_limit acquire_owned_byte_limit acquire_memory publish_stored publish_transient publish_bad_argument publish_invalid publish_limit publish_memory publish_time publish_limit_result_bytes publish_limit_owned_bytes value_positive value_nxdomain value_nodata expiry_positive expiry_nxdomain expiry_nodata resident_positive resident_nxdomain resident_nodata` |
| `assembly qtype=<a\|aaaa\|srv>` | `create_ok create_bad_argument create_limit create_memory limit_result_shape limit_result_bytes limit_budget_bytes terminal_complete terminal_bad_argument terminal_limit terminal_memory terminal_protocol abandoned nonterminal_current` |
| `route request_mode=<short\|worker>` | `requests_started resolution_local resolution_bypass resolution_immediate resolution_waited outcome_ready outcome_contradictory outcome_limit outcome_memory outcome_no_route outcome_service_unavailable outcome_timeout outcome_unavailable outcome_abandoned outcome_shutdown outcome_internal_error pending_current pending_high_water release_failure selected_ipv4 selected_ipv6` |
| `helper` | `failure_exit failure_io failure_protocol failure_spawn failure_timeout spawn_attempt spawn_success recovery_success_streak recovery_stable_uptime observation_dropped state_idle state_sending state_busy state_backoff state_shutting_down state_stopped` |

The row enumeration order is `background` then `interactive`, and `a`, `aaaa`, `srv`, then `other` where applicable. `other` represents operations that fail before a real query type is available; attempts, assemblies and histograms never have an `other` row. Histogram rows appear as dispatch wait (`background`, then `interactive`, each with `a/aaaa/srv`), attempt (`a/aaaa/srv`), TTL (`a/aaaa/srv`, each with `positive/nxdomain/nodata`), assembly size (`a/aaaa/srv`), then route duration (`short/worker`).

### Histograms

Histogram `le_*` values are cumulative and bounds are inclusive. `count` equals `le_inf`. Duration sums use microseconds even though bucket names use milliseconds.

| Name | Dimensions | Fixed keys after dimensions |
|---|---|---|
| `dispatch_wait_ms` | `priority`, `qtype` | `le_1 le_5 le_10 le_25 le_50 le_100 le_250 le_500 le_1000 le_2000 le_5000 le_10000 le_30000 le_inf count sum_us sample_errors` |
| `attempt_ms` | `qtype` | `le_1 le_5 le_10 le_25 le_50 le_100 le_250 le_500 le_1000 le_2000 le_5000 le_10000 le_30000 le_inf count sum_us sample_errors` |
| `ttl_seconds` | `qtype`, `payload_kind=positive|nxdomain|nodata` | `le_0 le_1 le_5 le_30 le_60 le_300 le_1800 le_3600 le_21600 le_86400 le_604800 le_2592000 le_inf count sum_seconds` |
| `assembly_bytes` | `qtype` | `le_0 le_64 le_256 le_1024 le_4096 le_16384 le_65536 le_262144 le_1048576 le_inf count sum_bytes` |
| `route_ms` | `request_mode` | `le_1 le_5 le_10 le_25 le_50 le_100 le_250 le_500 le_1000 le_2000 le_5000 le_10000 le_30000 le_inf count sum_us sample_errors` |

Only duration histograms contain `sample_errors`. TTL measures the effective payload TTL before storage, including zero. Assembly size measures the dynamically owned result size, not the whole process.

## Helper event grammar

Helper observations have three closed, ordered forms:

```text
resolver_helper status=degraded slot=0 pid=1234 failure=io streak=2 backoff_ms=1000 suppressed=0
resolver_helper status=recovered slot=0 pid=1235 recovery=success_streak degraded_ms=4321 suppressed=3 last_failure=exit
resolver_helper status=event_loss dropped=4
```

These are complete grammars, not examples that permit extra fields. A missing, unknown, duplicate or misplaced field invalidates the line. Helper events do not inherit schema-1 optional-key rules.

`degraded` is rate limited independently per helper slot to at most one eligible log attempt per 10 seconds. `suppressed` is the cumulative number of degraded observations withheld by that limiter in the same degradation cycle; values from multiple event lines must not be added. Log-level filtering and logger failure do not add to `suppressed`. `recovered` is not rate limited. Ring overflow is reported separately through the aggregate `observation_dropped` value and rate-limited `event_loss` records.

## Interpreting values

- Gauges are current at snapshot time and can rise or fall. Cross-owner collection is sequential in the listener loop, not a global atomic transaction.
- Counters and histograms are lifetime cumulative and saturating. Compute deltas only between snapshots with the same `instance`; a process restart resets them.
- High-water marks mean the maximum since process start, not the maximum since the previous snapshot. Use current gauges and rejection/failure counter deltas to assess recent pressure.
- `cache_owned_bytes_*` and `assembly_owned_bytes_*` are module-accounted requested allocation sizes, not RSS or total heap use.
- Resident cache payloads can include data whose expiry has not yet been discovered by a cache view; `resident` does not mean `fresh`.
- `outcome_ready` means route resolution produced a usable local response or endpoint/worker plan. It does not mean the upstream connected, a STATUS relay completed or a player was served; `outcome_ready / requests_started` is not an end-to-end success rate.
- Stage 1 does not observe long-worker connect/relay results, worker exit success, inbound PROXY protocol, or overall endpoint health. STATUS short-connection outcomes are also intentionally not modeled as general endpoint health.

For unsaturated values within one snapshot, these relationships are useful validation checks:

```text
jobs_current = jobs_queued + jobs_sending + jobs_dispatched + jobs_retry_wait + jobs_complete
jobs_current = jobs_background + jobs_interactive
capacity.jobs_dispatched = sum_qtype(attempt.jobs_dispatched_current)
capacity.jobs_complete = sum_qtype(attempt.jobs_complete_current)
capacity.orphaned_dispatched_current <= capacity.jobs_dispatched
capacity.assemblies_nonterminal_current = sum_qtype(assembly.nonterminal_current)
sum_qtype,payload_kind(cache.resident_*) <= capacity.cache_entries_current
route.requests_started = sum(route.outcome_*) + route.pending_current
```

The last route identity is evaluated separately for `request_mode=short` and `request_mode=worker`. There is deliberately no corresponding identity between `requests_started` and `resolution_*`: failures before waiter creation have an outcome but no resolution classification.
