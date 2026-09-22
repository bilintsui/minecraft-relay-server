/*
 * listener_metrics.c: Tests for listener-owned capacity and route metrics
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "listener_metrics.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s\n", message); \
			return false; \
		} \
	} while (0)

#define LISTENER_METRICS_TEST_KEY_LIMIT	64U

/* section: types */
typedef struct {
	const char *data;
	size_t length;
} listener_metrics_test_key;

/* section: global variables */
static const char listener_metrics_assembly_keys[] =
	"schema seq family instance qtype create_ok create_bad_argument create_limit create_memory limit_result_shape limit_result_bytes limit_budget_bytes"
	" terminal_complete terminal_bad_argument terminal_limit terminal_memory terminal_protocol abandoned nonterminal_current";
static const char listener_metrics_assembly_size_keys[] =
	"schema seq family instance name qtype le_0 le_64 le_256 le_1024 le_4096 le_16384 le_65536 le_262144 le_1048576 le_inf count sum_bytes";
static const char listener_metrics_attempt_keys[] =
	"schema seq family instance qtype dispatched response_ok response_bad_argument response_limit response_malformed response_memory response_nodata"
	" response_not_found response_permanent response_temporary response_truncated failure_exit failure_io failure_protocol failure_timeout retry_scheduled"
	" orphan_response_ok orphan_response_bad_argument orphan_response_limit orphan_response_malformed orphan_response_memory orphan_response_nodata"
	" orphan_response_not_found orphan_response_permanent orphan_response_temporary orphan_response_truncated completion_enqueued completion_taken"
	" attempt_abandoned_shutdown completion_abandoned_shutdown jobs_dispatched_current jobs_complete_current";
static const char listener_metrics_cache_keys[] =
	"schema seq family instance qtype acquire_created acquire_reused acquire_bad_argument acquire_reference_limit acquire_entry_limit acquire_id_limit"
	" acquire_owned_byte_limit acquire_memory publish_stored publish_transient publish_bad_argument publish_invalid publish_limit publish_memory publish_time"
	" publish_limit_result_bytes publish_limit_owned_bytes value_positive value_nxdomain value_nodata expiry_positive expiry_nxdomain expiry_nodata"
	" resident_positive resident_nxdomain resident_nodata";
static const char listener_metrics_capacity_storage_keys[] =
	"schema seq family instance scope cache_entries_current cache_entries_high_water cache_entry_limit cache_owned_bytes_current cache_owned_bytes_high_water"
	" cache_owned_byte_limit cache_result_byte_limit assemblies_nonterminal_current assembly_owned_bytes_current assembly_owned_bytes_high_water"
	" assembly_owned_byte_limit cache_saturation_total assembly_saturation_total";
static const char listener_metrics_capacity_supervisor_keys[] =
	"schema seq family instance scope jobs_current jobs_high_water job_limit interactive_reserve jobs_queued jobs_sending jobs_dispatched jobs_retry_wait"
	" jobs_complete jobs_background jobs_interactive orphaned_dispatched_current queue_background_current queue_background_high_water queue_interactive_current"
	" queue_interactive_high_water interests_background_current interests_interactive_current helper_limit supervisor_saturation_total";
static const char listener_metrics_dispatch_wait_keys[] =
	"schema seq family instance name priority qtype le_1 le_5 le_10 le_25 le_50 le_100 le_250 le_500 le_1000 le_2000 le_5000 le_10000 le_30000"
	" le_inf count sum_us sample_errors";
static const char listener_metrics_duration_keys[] =
	"schema seq family instance name qtype le_1 le_5 le_10 le_25 le_50 le_100 le_250 le_500 le_1000 le_2000 le_5000 le_10000 le_30000 le_inf count"
	" sum_us sample_errors";
static const char listener_metrics_helper_degraded_keys[] = "status slot pid failure streak backoff_ms suppressed";
static const char listener_metrics_helper_event_loss_keys[] = "status dropped";
static const char listener_metrics_helper_keys[] =
	"schema seq family instance failure_exit failure_io failure_protocol failure_spawn failure_timeout spawn_attempt spawn_success recovery_success_streak"
	" recovery_stable_uptime observation_dropped state_idle state_sending state_busy state_backoff state_shutting_down state_stopped";
static const char listener_metrics_helper_recovered_keys[] = "status slot pid recovery degraded_ms suppressed last_failure";
static const char listener_metrics_listener_keys[] =
	"schema seq family instance accepted_total accept_capacity_rejected_total accept_fd_exhausted_total connection_track_failure_total connections_current"
	" connections_high_water connection_limit worker_spawn_total worker_fork_failure_total worker_capacity_refusal_total workers_current workers_high_water"
	" worker_limit listener_saturation_total";
static const char listener_metrics_meta_keys[] =
	"schema seq family instance reason lines pid started_mono_sec started_mono_nsec uptime_ms missed_intervals scheduler_failures logger_errors format_drops";
static const char listener_metrics_route_duration_keys[] =
	"schema seq family instance name request_mode le_1 le_5 le_10 le_25 le_50 le_100 le_250 le_500 le_1000 le_2000 le_5000 le_10000 le_30000 le_inf"
	" count sum_us sample_errors";
static const char listener_metrics_route_keys[] =
	"schema seq family instance request_mode requests_started resolution_local resolution_bypass resolution_immediate resolution_waited outcome_ready"
	" outcome_contradictory outcome_limit outcome_memory outcome_no_route outcome_service_unavailable outcome_timeout outcome_unavailable outcome_abandoned"
	" outcome_shutdown outcome_internal_error pending_current pending_high_water release_failure selected_ipv4 selected_ipv6";
static const char listener_metrics_schedule_keys[] =
	"schema seq family instance priority qtype started coalesced complete fresh bad_argument io limit memory time limit_interest_count limit_background_admission"
	" limit_total_admission limit_entry_reference";
static const char listener_metrics_ttl_keys[] =
	"schema seq family instance name qtype payload_kind le_0 le_1 le_5 le_30 le_60 le_300 le_1800 le_3600 le_21600 le_86400 le_604800 le_2592000 le_inf"
	" count sum_seconds";

/* section: functions (local) */
static char *file_read(const char *filename, size_t *size) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
		if (file != NULL) {
			fclose(file);
		}
		return NULL;
	}
	long length = ftell(file);
	if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		return NULL;
	}
	char *result = (char *)malloc((size_t)length + 1U);
	if (result == NULL) {
		fclose(file);
		return NULL;
	}
	size_t received = fread(result, 1, (size_t)length, file);
	if (received != (size_t)length || fclose(file) != 0) {
		free(result);
		return NULL;
	}
	result[received] = '\0';
	*size = received;
	return result;
}

static bool listener_metrics_key_equal(const listener_metrics_test_key *left, const listener_metrics_test_key *right) {
	return left->length == right->length && memcmp(left->data, right->data, left->length) == 0;
}

static bool listener_metrics_keys_tokenize(const char *record, listener_metrics_test_key *keys, size_t *key_count) {
	if (record == NULL || keys == NULL || key_count == NULL || record[0] == '\0') {
		return false;
	}
	size_t count = 0;
	const char *cursor = record;
	while (*cursor != '\0') {
		if (*cursor == ' ' || *cursor == '\n' || *cursor == '\r' || count >= LISTENER_METRICS_TEST_KEY_LIMIT) {
			return false;
		}
		const char *end = strchr(cursor, ' ');
		if (end == NULL) {
			end = cursor + strlen(cursor);
		}
		const char *equals = memchr(cursor, '=', (size_t)(end - cursor));
		if (equals == NULL || equals == cursor || equals + 1 == end || memchr(equals + 1, '=', (size_t)(end - equals - 1)) != NULL) {
			return false;
		}
		keys[count].data = cursor;
		keys[count].length = (size_t)(equals - cursor);
		for (size_t previous = 0; previous < count; previous++) {
			if (listener_metrics_key_equal(&keys[previous], &keys[count])) {
				return false;
			}
		}
		count++;
		if (*end == '\0') {
			break;
		}
		cursor = end + 1;
		if (*cursor == '\0') {
			return false;
		}
	}
	*key_count = count;
	return true;
}

static bool listener_metrics_word_get(const char *words, size_t index, listener_metrics_test_key *result) {
	if (words == NULL || result == NULL) {
		return false;
	}
	const char *cursor = words;
	for (size_t current = 0; *cursor != '\0'; current++) {
		const char *end = strchr(cursor, ' ');
		if (end == NULL) {
			end = cursor + strlen(cursor);
		}
		if (current == index) {
			result->data = cursor;
			result->length = (size_t)(end - cursor);
			return result->length > 0;
		}
		cursor = *end == '\0' ? end : end + 1;
	}
	return false;
}

static bool listener_metrics_keys_valid(const char *record, const char *baseline, const char *optional, bool allow_extensions) {
	listener_metrics_test_key keys[LISTENER_METRICS_TEST_KEY_LIMIT];
	size_t key_count;
	if (!listener_metrics_keys_tokenize(record, keys, &key_count)) {
		return false;
	}
	size_t baseline_count = 0;
	listener_metrics_test_key expected;
	while (listener_metrics_word_get(baseline, baseline_count, &expected)) {
		if (baseline_count >= key_count || !listener_metrics_key_equal(&keys[baseline_count], &expected)) {
			return false;
		}
		baseline_count++;
	}
	if (!allow_extensions) {
		return key_count == baseline_count;
	}
	size_t optional_position = 0;
	for (size_t actual = baseline_count; actual < key_count; actual++) {
		for (size_t optional_index = 0; listener_metrics_word_get(optional, optional_index, &expected); optional_index++) {
			if (listener_metrics_key_equal(&keys[actual], &expected)) {
				if (optional_index < optional_position) {
					return false;
				}
				optional_position = optional_index + 1;
				break;
			}
		}
	}
	return true;
}

static bool listener_metrics_record_valid(const char *record, const char *baseline, const char *optional, bool allow_extensions) {
	static const char prefix[] = "metrics ";
	return record != NULL && strncmp(record, prefix, sizeof(prefix) - 1U) == 0
		&& listener_metrics_keys_valid(record + sizeof(prefix) - 1U, baseline, optional, allow_extensions);
}

static bool listener_metrics_helper_record_valid(const char *record) {
	static const char prefix[] = "resolver_helper ";
	if (record == NULL || strncmp(record, prefix, sizeof(prefix) - 1U) != 0) {
		return false;
	}
	const char *fields = record + sizeof(prefix) - 1U;
	const char *keys = NULL;
	if (strncmp(fields, "status=degraded ", strlen("status=degraded ")) == 0) {
		keys = listener_metrics_helper_degraded_keys;
	} else if (strncmp(fields, "status=recovered ", strlen("status=recovered ")) == 0) {
		keys = listener_metrics_helper_recovered_keys;
	} else if (strncmp(fields, "status=event_loss ", strlen("status=event_loss ")) == 0) {
		keys = listener_metrics_helper_event_loss_keys;
	} else {
		return false;
	}
	return listener_metrics_keys_valid(fields, keys, NULL, false);
}

static const char *listener_metrics_schema_keys(size_t line_index) {
	if (line_index == 0) {
		return listener_metrics_meta_keys;
	}
	if (line_index == 1) {
		return listener_metrics_listener_keys;
	}
	if (line_index == 2) {
		return listener_metrics_capacity_storage_keys;
	}
	if (line_index == 3) {
		return listener_metrics_capacity_supervisor_keys;
	}
	if (line_index < 12) {
		return listener_metrics_schedule_keys;
	}
	if (line_index < 15) {
		return listener_metrics_attempt_keys;
	}
	if (line_index < 19) {
		return listener_metrics_cache_keys;
	}
	if (line_index < 22) {
		return listener_metrics_assembly_keys;
	}
	if (line_index < 24) {
		return listener_metrics_route_keys;
	}
	if (line_index == 24) {
		return listener_metrics_helper_keys;
	}
	if (line_index < 31) {
		return listener_metrics_dispatch_wait_keys;
	}
	if (line_index < 34) {
		return listener_metrics_duration_keys;
	}
	if (line_index < 43) {
		return listener_metrics_ttl_keys;
	}
	if (line_index < 46) {
		return listener_metrics_assembly_size_keys;
	}
	return line_index < LISTENER_METRICS_LINE_COUNT ? listener_metrics_route_duration_keys : NULL;
}

static bool listener_metrics_timestamp_valid(const char *timestamp, size_t length) {
	if (length == 0) {
		return true;
	}
	if (length != 29U || timestamp[4] != '-' || timestamp[7] != '-' || timestamp[10] != ' ' || timestamp[13] != ':' || timestamp[16] != ':'
		|| memcmp(timestamp + 19, " UTC", 4) != 0 || (timestamp[23] != '+' && timestamp[23] != '-') || timestamp[26] != ':') {
		return false;
	}
	static const size_t separators[] = { 4, 7, 10, 13, 16, 19, 20, 21, 22, 23, 26 };
	for (size_t index = 0; index < length; index++) {
		bool separator = false;
		for (size_t item = 0; item < sizeof(separators) / sizeof(separators[0]); item++) {
			separator = separator || index == separators[item];
		}
		if (!separator && (timestamp[index] < '0' || timestamp[index] > '9')) {
			return false;
		}
	}
	return true;
}

static const char *listener_metrics_file_message(const char *line, const char *level) {
	if (line == NULL || level == NULL || line[0] != '[' || strchr(line, '\n') != NULL || strchr(line, '\r') != NULL) {
		return NULL;
	}
	const char *timestamp_end = strstr(line, "] [");
	if (timestamp_end == NULL || !listener_metrics_timestamp_valid(line + 1, (size_t)(timestamp_end - line - 1))) {
		return NULL;
	}
	const char *level_start = timestamp_end + 3;
	size_t level_length = strlen(level);
	if (strncmp(level_start, level, level_length) != 0 || strncmp(level_start + level_length, "] ", 2) != 0 || level_start[level_length + 2] == '\0') {
		return NULL;
	}
	return level_start + level_length + 2;
}

static bool listener_metrics_test_capacity(void) {
	listener_metrics_state metrics = { 0 };
	listener_metrics_limits_set(&metrics, 100, 20);
	listener_metrics_accept_record(&metrics);
	listener_metrics_accept_record(&metrics);
	listener_metrics_accept_capacity_rejected_record(&metrics);
	listener_metrics_accept_fd_exhausted_record(&metrics);
	listener_metrics_connection_track_failure_record(&metrics);
	listener_metrics_connection_add(&metrics);
	listener_metrics_connection_add(&metrics);
	listener_metrics_connection_remove(&metrics);
	listener_metrics_worker_add(&metrics);
	listener_metrics_worker_add(&metrics);
	listener_metrics_worker_capacity_refusal_record(&metrics);
	listener_metrics_worker_fork_failure_record(&metrics);
	listener_metrics_worker_remove(&metrics);
	listener_metrics_snapshot snapshot;
	CHECK(listener_metrics_snapshot_get(&metrics, &snapshot), "capacity snapshot failed");
	CHECK(snapshot.accepted == 2 && snapshot.accept_capacity_rejected == 1 && snapshot.accept_fd_exhausted == 1,
		"accept counters were incorrect");
	CHECK(snapshot.connection_track_failure == 1 && snapshot.connections_current == 1 && snapshot.connections_high_water == 2,
		"connection counters were incorrect");
	CHECK(snapshot.worker_spawn == 2 && snapshot.worker_fork_failure == 1 && snapshot.worker_capacity_refusal == 1,
		"worker counters were incorrect");
	CHECK(snapshot.workers_current == 1 && snapshot.workers_high_water == 2, "worker gauges were incorrect");
	CHECK(snapshot.connection_limit == 100 && snapshot.worker_limit == 20 && snapshot.saturation_total == 0, "listener limits or saturation were incorrect");
	metrics.accepted = UINT64_MAX;
	listener_metrics_accept_record(&metrics);
	CHECK(metrics.accepted == UINT64_MAX && metrics.saturation_total == 1, "listener counter saturation was not recorded");
	listener_metrics_connection_remove(&metrics);
	listener_metrics_connection_remove(&metrics);
	listener_metrics_worker_remove(&metrics);
	listener_metrics_worker_remove(&metrics);
	CHECK(metrics.connections_current == 0 && metrics.workers_current == 0 && metrics.saturation_total == 3, "gauge underflow was not contained");
	return true;
}

static bool listener_metrics_test_consumer_grammar(void) {
	static const char baseline[] =
		"metrics schema=1 seq=7 family=meta instance=1234-10-20 reason=periodic lines=48 pid=1234 started_mono_sec=10 started_mono_nsec=20"
		" uptime_ms=1000 missed_intervals=0 scheduler_failures=0 logger_errors=0 format_drops=0";
	static const char optional[] = "extension_a extension_b";
	CHECK(listener_metrics_record_valid(baseline, listener_metrics_meta_keys, optional, true), "valid metrics baseline was rejected");
	CHECK(listener_metrics_record_valid(
		"metrics schema=1 seq=7 family=meta instance=1234-10-20 reason=periodic lines=48 pid=1234 started_mono_sec=10 started_mono_nsec=20"
		" uptime_ms=1000 missed_intervals=0 scheduler_failures=0 logger_errors=0 format_drops=0 unknown=1",
		listener_metrics_meta_keys, optional, true), "unique unknown metrics extension was rejected");
	CHECK(listener_metrics_record_valid(
		"metrics schema=1 seq=7 family=meta instance=1234-10-20 reason=periodic lines=48 pid=1234 started_mono_sec=10 started_mono_nsec=20"
		" uptime_ms=1000 missed_intervals=0 scheduler_failures=0 logger_errors=0 format_drops=0 extension_b=2",
		listener_metrics_meta_keys, optional, true), "old metrics baseline missing a known optional extension was rejected");
	CHECK(!listener_metrics_record_valid(
		"metrics schema=1 seq=7 family=meta instance=1234-10-20 reason=periodic lines=48 pid=1234 started_mono_sec=10 started_mono_nsec=20"
		" uptime_ms=1000 missed_intervals=0 scheduler_failures=0 logger_errors=0",
		listener_metrics_meta_keys, optional, true), "metrics record missing a baseline key was accepted");
	CHECK(!listener_metrics_record_valid(
		"metrics schema=1 seq=7 family=meta instance=1234-10-20 reason=periodic lines=48 pid=1234 started_mono_sec=10 started_mono_nsec=20"
		" uptime_ms=1000 missed_intervals=0 scheduler_failures=0 logger_errors=0 format_drops=0 reason=periodic",
		listener_metrics_meta_keys, optional, true), "metrics record with a duplicate known key was accepted");
	CHECK(!listener_metrics_record_valid(
		"metrics schema=1 seq=7 family=meta instance=1234-10-20 lines=48 reason=periodic pid=1234 started_mono_sec=10 started_mono_nsec=20"
		" uptime_ms=1000 missed_intervals=0 scheduler_failures=0 logger_errors=0 format_drops=0",
		listener_metrics_meta_keys, optional, true), "metrics record with an out-of-order known key was accepted");
	CHECK(!listener_metrics_record_valid(
		"metrics schema=1 seq=7 family=meta instance=1234-10-20 unknown=1 reason=periodic lines=48 pid=1234 started_mono_sec=10 started_mono_nsec=20"
		" uptime_ms=1000 missed_intervals=0 scheduler_failures=0 logger_errors=0 format_drops=0",
		listener_metrics_meta_keys, optional, true), "metrics extension before the complete baseline was accepted");
	CHECK(!listener_metrics_record_valid(
		"metrics schema=1 seq=7 family=meta instance=1234-10-20 reason=periodic lines=48 pid=1234 started_mono_sec=10 started_mono_nsec=20"
		" uptime_ms=1000 missed_intervals=0 scheduler_failures=0 logger_errors=0 format_drops=0 unknown=1 unknown=2",
		listener_metrics_meta_keys, optional, true), "metrics record with a duplicate unknown key was accepted");
	CHECK(!listener_metrics_record_valid(
		"metrics schema=1 seq=7 family=meta instance=1234-10-20 reason=periodic lines=48 pid=1234 started_mono_sec=10 started_mono_nsec=20"
		" uptime_ms=1000 missed_intervals=0 scheduler_failures=0 logger_errors=0 format_drops=0 trailing",
		listener_metrics_meta_keys, optional, true), "metrics record with non-token trailing bytes was accepted");
	CHECK(!listener_metrics_record_valid(
		"metrics schema=1 seq=7 family=meta instance=1234-10-20 reason=periodic lines=48 pid=1234 started_mono_sec=10 started_mono_nsec=20"
		" uptime_ms=1000 missed_intervals=0 scheduler_failures=0 logger_errors=0 format_drops=0 [2026-09-22]",
		listener_metrics_meta_keys, optional, true), "metrics record with a glued second record was accepted");
	CHECK(!listener_metrics_record_valid(
		"metrics schema=1 seq=7 family=meta instance=1234-10-20 reason=periodic lines=48 pid=1234 started_mono_sec=10 started_mono_nsec=20"
		" uptime_ms=1000 missed_intervals=0 scheduler_failures=0 logger_errors=0 format_drops=0 extension_b=2 extension_a=1",
		listener_metrics_meta_keys, optional, true), "metrics record with out-of-order known extensions was accepted");
	CHECK(listener_metrics_helper_record_valid("resolver_helper status=degraded slot=0 pid=1 failure=io streak=2 backoff_ms=1000 suppressed=0"),
		"valid degraded helper record was rejected");
	CHECK(listener_metrics_helper_record_valid(
		"resolver_helper status=recovered slot=0 pid=2 recovery=success_streak degraded_ms=10 suppressed=0 last_failure=io"),
		"valid recovered helper record was rejected");
	CHECK(listener_metrics_helper_record_valid("resolver_helper status=event_loss dropped=3"), "valid event-loss helper record was rejected");
	CHECK(!listener_metrics_helper_record_valid("resolver_helper status=event_loss dropped=3 unknown=1"), "helper record with an unknown field was accepted");
	CHECK(!listener_metrics_helper_record_valid("resolver_helper status=event_loss dropped=3 dropped=4"), "helper record with a duplicate field was accepted");
	CHECK(!listener_metrics_helper_record_valid("resolver_helper status=event_loss"), "helper record with a missing field was accepted");
	CHECK(!listener_metrics_helper_record_valid("resolver_helper dropped=3 status=event_loss"), "helper record with a misplaced field was accepted");
	const char *message = listener_metrics_file_message(
		"[2026-09-22 12:34:56 UTC+08:00] [INFO] metrics schema=1 seq=1 family=meta instance=1-1-1", "INFO");
	CHECK(message != NULL && strncmp(message, "metrics schema=1", strlen("metrics schema=1")) == 0, "normal metrics file prefix was rejected");
	message = listener_metrics_file_message("[] [WARN] resolver_helper status=event_loss dropped=1", "WARN");
	CHECK(message != NULL && listener_metrics_helper_record_valid(message), "empty timestamp or helper WARNING prefix was rejected");
	CHECK(listener_metrics_file_message(
		"access [] [INFO] metrics schema=1 seq=1 family=meta instance=1-1-1", "INFO") == NULL, "mid-line metrics prefix was accepted");
	return true;
}

static bool listener_metrics_test_helper_logs(void) {
	char filename[] = "/tmp/mcrelay-listener-metrics-helper-XXXXXX";
	int fd = mkstemp(filename);
	CHECK(fd != -1 && close(fd) == 0, "cannot prepare helper metrics log");
	const struct timespec started_at = { .tv_sec = 10, .tv_nsec = 0 };
	listener_metrics_runtime runtime;
	CHECK(listener_metrics_runtime_init(&runtime, 1234, &started_at), "cannot initialize helper metrics runtime");
	resolver_supervisor_observation observation = {
		.data.degraded = {
			.backoff_milliseconds = 1000,
			.cycle_id = 1,
			.failure = RESOLVER_SUPERVISOR_HELPER_FAILURE_IO,
			.failure_count = 1,
			.observed_at = { .tv_sec = 100 },
			.process_id = 2001,
			.slot = 0
		},
		.type = RESOLVER_SUPERVISOR_OBSERVATION_DEGRADED
	};
	struct timespec processed_at = { .tv_sec = 100 };
	errno = EDOM;
	listener_metrics_helper_observation_log(&runtime, &observation, filename, MKSYS_LEVEL_INFORMATION, &processed_at);
	CHECK(errno == EDOM, "degraded helper log changed errno");
	observation.data.degraded.failure = RESOLVER_SUPERVISOR_HELPER_FAILURE_EXIT;
	observation.data.degraded.failure_count = 2;
	processed_at.tv_sec = 101;
	listener_metrics_helper_observation_log(&runtime, &observation, filename, MKSYS_LEVEL_INFORMATION, &processed_at);
	CHECK(runtime.helper[0].suppressed == 1, "rate-limited helper event was not suppressed");
	observation.data.degraded.failure = RESOLVER_SUPERVISOR_HELPER_FAILURE_PROTOCOL;
	observation.data.degraded.failure_count = 3;
	processed_at.tv_sec = 110;
	listener_metrics_helper_observation_log(&runtime, &observation, filename, MKSYS_LEVEL_INFORMATION, &processed_at);
	CHECK(runtime.helper[0].suppressed == 1, "eligible degraded log reset cumulative suppression");
	memset(&observation, 0, sizeof(observation));
	observation.type = RESOLVER_SUPERVISOR_OBSERVATION_RECOVERED;
	observation.data.recovered.cycle_id = 1;
	observation.data.recovered.degraded_at.tv_sec = 100;
	observation.data.recovered.failure_count = 3;
	observation.data.recovered.last_failure = RESOLVER_SUPERVISOR_HELPER_FAILURE_EXIT;
	observation.data.recovered.observed_at.tv_sec = 112;
	observation.data.recovered.process_id = 2002;
	observation.data.recovered.recovery = RESOLVER_SUPERVISOR_HELPER_RECOVERY_STABLE_UPTIME;
	observation.data.recovered.slot = 0;
	processed_at.tv_sec = 112;
	listener_metrics_helper_observation_log(&runtime, &observation, filename, MKSYS_LEVEL_INFORMATION, &processed_at);
	CHECK(runtime.helper[0].cycle_id == 0 && runtime.helper[0].suppressed == 0, "recovery did not clear its suppression cycle");
	memset(&observation, 0, sizeof(observation));
	observation.type = RESOLVER_SUPERVISOR_OBSERVATION_DEGRADED;
	observation.data.degraded.backoff_milliseconds = 2000;
	observation.data.degraded.cycle_id = 2;
	observation.data.degraded.failure = RESOLVER_SUPERVISOR_HELPER_FAILURE_TIMEOUT;
	observation.data.degraded.failure_count = 2;
	observation.data.degraded.process_id = 2003;
	observation.data.degraded.slot = 0;
	processed_at.tv_sec = 113;
	listener_metrics_helper_observation_log(&runtime, &observation, filename, MKSYS_LEVEL_INFORMATION, &processed_at);
	CHECK(runtime.helper[0].cycle_id == 2 && runtime.helper[0].suppressed == 1, "new cycle inherited or lost suppression incorrectly");
	observation.data.degraded.cycle_id = 3;
	observation.data.degraded.failure_count = 4;
	processed_at.tv_sec = 114;
	listener_metrics_helper_observation_log(&runtime, &observation, filename, MKSYS_LEVEL_INFORMATION, &processed_at);
	CHECK(runtime.helper[0].cycle_id == 3 && runtime.helper[0].suppressed == 1, "lost recovery allowed suppression to cross cycles");
	memset(&observation, 0, sizeof(observation));
	observation.type = RESOLVER_SUPERVISOR_OBSERVATION_RECOVERED;
	observation.data.recovered.cycle_id = 3;
	observation.data.recovered.degraded_at.tv_sec = 113;
	observation.data.recovered.failure_count = 4;
	observation.data.recovered.last_failure = RESOLVER_SUPERVISOR_HELPER_FAILURE_PROTOCOL;
	observation.data.recovered.observed_at.tv_sec = 115;
	observation.data.recovered.process_id = 2004;
	observation.data.recovered.recovery = RESOLVER_SUPERVISOR_HELPER_RECOVERY_SUCCESS_STREAK;
	observation.data.recovered.slot = 0;
	processed_at.tv_sec = 115;
	listener_metrics_helper_observation_log(&runtime, &observation, filename, MKSYS_LEVEL_INFORMATION, &processed_at);
	processed_at.tv_sec = 120;
	listener_metrics_helper_observation_loss_log(&runtime, 1, filename, MKSYS_LEVEL_INFORMATION, &processed_at);
	processed_at.tv_sec = 121;
	listener_metrics_helper_observation_loss_log(&runtime, 2, filename, MKSYS_LEVEL_INFORMATION, &processed_at);
	CHECK(runtime.observation_dropped_seen == 1, "rate-limited event loss was consumed before a log attempt");
	processed_at.tv_sec = 130;
	listener_metrics_helper_observation_loss_log(&runtime, 2, filename, MKSYS_LEVEL_INFORMATION, &processed_at);
	CHECK(runtime.observation_dropped_seen == 2, "deferred event loss was not reported later");
	size_t content_size;
	char *content = file_read(filename, &content_size);
	CHECK(content != NULL && content_size > 0, "cannot read helper metrics log");
	CHECK(strstr(content, "status=degraded slot=0 pid=2001 failure=io streak=1 backoff_ms=1000 suppressed=0") != NULL,
		"first degraded helper log was incorrect");
	CHECK(strstr(content, "status=degraded slot=0 pid=2001 failure=protocol streak=3 backoff_ms=1000 suppressed=1") != NULL,
		"later degraded helper log did not retain cumulative suppression");
	CHECK(strstr(content, "status=recovered slot=0 pid=2002 recovery=stable_uptime degraded_ms=12000 suppressed=1 last_failure=exit") != NULL,
		"self-contained helper recovery log was incorrect");
	CHECK(strstr(content, "status=recovered slot=0 pid=2004 recovery=success_streak degraded_ms=2000 suppressed=1 last_failure=protocol") != NULL,
		"cross-cycle helper recovery log was incorrect");
	CHECK(strstr(content, "status=event_loss dropped=1") != NULL && strstr(content, "status=event_loss dropped=2") != NULL,
		"event-loss logs did not retain a rate-limited update");
	free(content);
	CHECK(unlink(filename) == 0, "cannot remove helper metrics log");
	return true;
}

static bool listener_metrics_test_invalid(void) {
	conf config = { .log.level = MKSYS_LEVEL_INFORMATION, .metrics.interval = 300 };
	listener_metrics_state metrics = { 0 };
	listener_metrics_route_request request = { 0 };
	const struct timespec now = { .tv_sec = 1, .tv_nsec = 0 };
	CHECK(!listener_metrics_route_start(NULL, &request, LISTENER_METRICS_REQUEST_SHORT, &now), "NULL metrics accepted route start");
	CHECK(!listener_metrics_route_start(&metrics, NULL, LISTENER_METRICS_REQUEST_SHORT, &now), "NULL request accepted route start");
	CHECK(!listener_metrics_route_start(&metrics, &request, LISTENER_METRICS_REQUEST_COUNT, &now), "invalid mode accepted route start");
	CHECK(!listener_metrics_route_start(&metrics, &request, LISTENER_METRICS_REQUEST_SHORT, NULL), "NULL time accepted route start");
	CHECK(listener_metrics_route_start(&metrics, &request, LISTENER_METRICS_REQUEST_SHORT, &now), "valid route start failed");
	CHECK(!listener_metrics_route_start(&metrics, &request, LISTENER_METRICS_REQUEST_SHORT, &now), "duplicate route start succeeded");
	CHECK(!listener_metrics_route_resolution_record(&metrics, &request, LISTENER_METRICS_RESOLUTION_COUNT), "invalid resolution succeeded");
	CHECK(!listener_metrics_route_settle(&metrics, &request, LISTENER_METRICS_OUTCOME_COUNT, LISTENER_METRICS_SELECTED_FAMILY_NONE, &now),
		"invalid outcome succeeded");
	CHECK(!listener_metrics_route_settle(&metrics, &request, LISTENER_METRICS_OUTCOME_READY, LISTENER_METRICS_SELECTED_FAMILY_COUNT, &now),
		"invalid family succeeded");
	CHECK(metrics.route[LISTENER_METRICS_REQUEST_SHORT].requests_started == 1 && metrics.route[LISTENER_METRICS_REQUEST_SHORT].outcome[0] == 0,
		"invalid route operations changed counters");
	CHECK(listener_metrics_effectively_enabled(&config), "valid metrics configuration was not effectively enabled");
	config.log.level = MKSYS_LEVEL_WARNING;
	CHECK(!listener_metrics_effectively_enabled(&config), "filtered metrics configuration remained effectively enabled");
	config.log.level = MKSYS_LEVEL_INFORMATION;
	config.metrics.interval = 0;
	CHECK(!listener_metrics_effectively_enabled(&config) && !listener_metrics_effectively_enabled(NULL), "disabled or NULL metrics configuration was enabled");
	return true;
}

static bool listener_metrics_test_output(void) {
	char filename[] = "/tmp/mcrelay-listener-metrics-output-XXXXXX";
	int fd = mkstemp(filename);
	CHECK(fd != -1 && close(fd) == 0, "cannot prepare aggregate metrics log");
	const struct timespec started_at = { .tv_sec = 10, .tv_nsec = 20 };
	const struct timespec now = { .tv_sec = 20, .tv_nsec = 30 };
	listener_metrics_runtime runtime;
	CHECK(listener_metrics_runtime_init(&runtime, 1234, &started_at), "cannot initialize aggregate metrics runtime");
	listener_metrics_aggregate_snapshot snapshot;
	memset(&snapshot, UINT8_MAX, sizeof(snapshot));
	char invalid_filename[sizeof(filename) + 16U];
	snprintf(invalid_filename, sizeof(invalid_filename), "%s/missing", filename);
	errno = ERANGE;
	listener_metrics_output(&runtime, LISTENER_METRICS_OUTPUT_STARTUP, &snapshot, invalid_filename, MKSYS_LEVEL_INFORMATION, &now);
	CHECK(errno == ERANGE, "failed aggregate output changed errno");
	CHECK(runtime.sequence == 1 && runtime.logger_errors == LISTENER_METRICS_LINE_COUNT && runtime.format_drops == 0,
		"failed aggregate output did not account each line exactly once");
	listener_metrics_output(&runtime, LISTENER_METRICS_OUTPUT_PERIODIC, &snapshot, filename, MKSYS_LEVEL_INFORMATION, &now);
	CHECK(runtime.sequence == 2 && runtime.logger_errors == LISTENER_METRICS_LINE_COUNT && runtime.format_drops == 0,
		"successful aggregate output changed error accounting");
	size_t content_size;
	char *content = file_read(filename, &content_size);
	CHECK(content != NULL && content_size > 0, "cannot read aggregate metrics log");
	static const char *const expected[] = {
		"family=meta ", "family=listener ", "family=capacity instance=1234-10-20 scope=storage ",
		"family=capacity instance=1234-10-20 scope=supervisor ",
		"family=schedule instance=1234-10-20 priority=background qtype=a ",
		"family=schedule instance=1234-10-20 priority=background qtype=aaaa ",
		"family=schedule instance=1234-10-20 priority=background qtype=srv ",
		"family=schedule instance=1234-10-20 priority=background qtype=other ",
		"family=schedule instance=1234-10-20 priority=interactive qtype=a ",
		"family=schedule instance=1234-10-20 priority=interactive qtype=aaaa ",
		"family=schedule instance=1234-10-20 priority=interactive qtype=srv ",
		"family=schedule instance=1234-10-20 priority=interactive qtype=other ",
		"family=attempt instance=1234-10-20 qtype=a ", "family=attempt instance=1234-10-20 qtype=aaaa ",
		"family=attempt instance=1234-10-20 qtype=srv ",
		"family=cache instance=1234-10-20 qtype=a ", "family=cache instance=1234-10-20 qtype=aaaa ",
		"family=cache instance=1234-10-20 qtype=srv ", "family=cache instance=1234-10-20 qtype=other ",
		"family=assembly instance=1234-10-20 qtype=a ", "family=assembly instance=1234-10-20 qtype=aaaa ",
		"family=assembly instance=1234-10-20 qtype=srv ",
		"family=route instance=1234-10-20 request_mode=short ", "family=route instance=1234-10-20 request_mode=worker ",
		"family=helper ",
		"family=histogram instance=1234-10-20 name=dispatch_wait_ms priority=background qtype=a ",
		"family=histogram instance=1234-10-20 name=dispatch_wait_ms priority=background qtype=aaaa ",
		"family=histogram instance=1234-10-20 name=dispatch_wait_ms priority=background qtype=srv ",
		"family=histogram instance=1234-10-20 name=dispatch_wait_ms priority=interactive qtype=a ",
		"family=histogram instance=1234-10-20 name=dispatch_wait_ms priority=interactive qtype=aaaa ",
		"family=histogram instance=1234-10-20 name=dispatch_wait_ms priority=interactive qtype=srv ",
		"family=histogram instance=1234-10-20 name=attempt_ms qtype=a ",
		"family=histogram instance=1234-10-20 name=attempt_ms qtype=aaaa ",
		"family=histogram instance=1234-10-20 name=attempt_ms qtype=srv ",
		"family=histogram instance=1234-10-20 name=ttl_seconds qtype=a payload_kind=positive ",
		"family=histogram instance=1234-10-20 name=ttl_seconds qtype=a payload_kind=nxdomain ",
		"family=histogram instance=1234-10-20 name=ttl_seconds qtype=a payload_kind=nodata ",
		"family=histogram instance=1234-10-20 name=ttl_seconds qtype=aaaa payload_kind=positive ",
		"family=histogram instance=1234-10-20 name=ttl_seconds qtype=aaaa payload_kind=nxdomain ",
		"family=histogram instance=1234-10-20 name=ttl_seconds qtype=aaaa payload_kind=nodata ",
		"family=histogram instance=1234-10-20 name=ttl_seconds qtype=srv payload_kind=positive ",
		"family=histogram instance=1234-10-20 name=ttl_seconds qtype=srv payload_kind=nxdomain ",
		"family=histogram instance=1234-10-20 name=ttl_seconds qtype=srv payload_kind=nodata ",
		"family=histogram instance=1234-10-20 name=assembly_bytes qtype=a ",
		"family=histogram instance=1234-10-20 name=assembly_bytes qtype=aaaa ",
		"family=histogram instance=1234-10-20 name=assembly_bytes qtype=srv ",
		"family=histogram instance=1234-10-20 name=route_ms request_mode=short ",
		"family=histogram instance=1234-10-20 name=route_ms request_mode=worker "
	};
	CHECK(sizeof(expected) / sizeof(expected[0]) == LISTENER_METRICS_LINE_COUNT, "aggregate test does not cover every schema line");
	char *cursor = content;
	for (size_t line_index = 0; line_index < LISTENER_METRICS_LINE_COUNT; line_index++) {
		char *line_end = strchr(cursor, '\n');
		CHECK(line_end != NULL, "aggregate snapshot ended before 48 physical lines");
		*line_end = '\0';
		const char *metrics_line = listener_metrics_file_message(cursor, "INFO");
		CHECK(metrics_line != NULL && strncmp(metrics_line, "metrics schema=1 seq=2 ", strlen("metrics schema=1 seq=2 ")) == 0
			&& strstr(metrics_line, expected[line_index]) != NULL, "aggregate schema line order or dimensions were incorrect");
		CHECK(listener_metrics_record_valid(metrics_line, listener_metrics_schema_keys(line_index), NULL, false),
			"aggregate schema baseline key set or order was incorrect");
		CHECK(strlen(metrics_line) <= LISTENER_METRICS_LINE_SIZE - 1U, "aggregate schema line exceeded its fixed budget");
		if (line_index == 0) {
			CHECK(strstr(metrics_line, "reason=periodic lines=48 pid=1234 started_mono_sec=10 started_mono_nsec=20 uptime_ms=10000") != NULL,
				"aggregate meta identity or reason was incorrect");
			CHECK(strstr(metrics_line, "logger_errors=48 format_drops=0") != NULL, "aggregate meta did not expose retrospective logger errors");
		}
		cursor = line_end + 1;
	}
	CHECK(*cursor == '\0', "aggregate snapshot emitted more than 48 physical lines");
	free(content);
	CHECK(unlink(filename) == 0, "cannot remove aggregate metrics log");
	return true;
}

static bool listener_metrics_test_route_duration_error(void) {
	listener_metrics_state metrics = { 0 };
	listener_metrics_route_request request = { 0 };
	const struct timespec start = { .tv_sec = 5, .tv_nsec = 0 };
	const struct timespec end = { .tv_sec = 4, .tv_nsec = 0 };
	CHECK(listener_metrics_route_start(&metrics, &request, LISTENER_METRICS_REQUEST_SHORT, &start), "duration-error route start failed");
	CHECK(listener_metrics_route_duration_enable(&request), "duration-error route did not enable timing");
	CHECK(listener_metrics_route_pending(&metrics, &request), "duration-error route did not become pending");
	CHECK(listener_metrics_route_resolution_record(&metrics, &request, LISTENER_METRICS_RESOLUTION_WAITED), "duration-error resolution failed");
	errno = EDOM;
	CHECK(listener_metrics_route_settle(&metrics, &request, LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, LISTENER_METRICS_SELECTED_FAMILY_NONE, &end),
		"duration-error route did not settle");
	CHECK(errno == EDOM, "duration-error settlement changed errno");
	listener_metrics_snapshot snapshot;
	CHECK(listener_metrics_snapshot_get(&metrics, &snapshot), "duration-error snapshot failed");
	CHECK(snapshot.route_duration[LISTENER_METRICS_REQUEST_SHORT].count == 0
		&& snapshot.route_duration[LISTENER_METRICS_REQUEST_SHORT].sample_errors == 1, "invalid route duration was not isolated");
	return true;
}

static bool listener_metrics_test_route_immediate(void) {
	listener_metrics_state metrics = { 0 };
	listener_metrics_route_request short_request = { 0 };
	listener_metrics_route_request worker_request = { 0 };
	const struct timespec now = { .tv_sec = 1, .tv_nsec = 0 };
	CHECK(listener_metrics_route_start(&metrics, &short_request, LISTENER_METRICS_REQUEST_SHORT, &now), "short route start failed");
	CHECK(listener_metrics_route_resolution_record(&metrics, &short_request, LISTENER_METRICS_RESOLUTION_LOCAL), "local resolution failed");
	CHECK(listener_metrics_route_settle(&metrics, &short_request, LISTENER_METRICS_OUTCOME_READY, LISTENER_METRICS_SELECTED_FAMILY_NONE, &now),
		"local route settlement failed");
	CHECK(listener_metrics_route_start(&metrics, &worker_request, LISTENER_METRICS_REQUEST_WORKER, &now), "worker route start failed");
	CHECK(listener_metrics_route_resolution_record(&metrics, &worker_request, LISTENER_METRICS_RESOLUTION_BYPASS), "bypass resolution failed");
	CHECK(listener_metrics_route_settle(&metrics, &worker_request, LISTENER_METRICS_OUTCOME_READY, LISTENER_METRICS_SELECTED_FAMILY_NONE, &now),
		"bypass route settlement failed");
	CHECK(!listener_metrics_route_settle(&metrics, &worker_request, LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, LISTENER_METRICS_SELECTED_FAMILY_IPV4, &now),
		"duplicate route settlement succeeded");
	CHECK(metrics.route[LISTENER_METRICS_REQUEST_SHORT].requests_started == 1
		&& metrics.route[LISTENER_METRICS_REQUEST_SHORT].resolution[LISTENER_METRICS_RESOLUTION_LOCAL] == 1
		&& metrics.route[LISTENER_METRICS_REQUEST_SHORT].outcome[LISTENER_METRICS_OUTCOME_READY] == 1, "local route metrics were incorrect");
	CHECK(metrics.route[LISTENER_METRICS_REQUEST_WORKER].requests_started == 1
		&& metrics.route[LISTENER_METRICS_REQUEST_WORKER].resolution[LISTENER_METRICS_RESOLUTION_BYPASS] == 1
		&& metrics.route[LISTENER_METRICS_REQUEST_WORKER].outcome[LISTENER_METRICS_OUTCOME_READY] == 1, "bypass route metrics were incorrect");
	CHECK(metrics.route_duration[LISTENER_METRICS_REQUEST_SHORT].count == 0 && metrics.route_duration[LISTENER_METRICS_REQUEST_WORKER].count == 0,
		"local or bypass route produced a duration sample");
	return true;
}

static bool listener_metrics_test_route_pending(void) {
	listener_metrics_state metrics = { 0 };
	listener_metrics_route_request request = { 0 };
	const struct timespec start = { .tv_sec = 1, .tv_nsec = 0 };
	const struct timespec end = { .tv_sec = 1, .tv_nsec = 50000000 };
	CHECK(listener_metrics_route_start(&metrics, &request, LISTENER_METRICS_REQUEST_WORKER, &start), "pending route start failed");
	CHECK(listener_metrics_route_duration_enable(&request), "pending route did not enable timing");
	CHECK(listener_metrics_route_pending(&metrics, &request), "pending route did not enter pending");
	CHECK(!listener_metrics_route_pending(&metrics, &request), "pending route entered pending twice");
	CHECK(listener_metrics_route_resolution_record(&metrics, &request, LISTENER_METRICS_RESOLUTION_WAITED), "waited resolution failed");
	CHECK(!listener_metrics_route_resolution_record(&metrics, &request, LISTENER_METRICS_RESOLUTION_IMMEDIATE), "route recorded two resolutions");
	CHECK(listener_metrics_route_settle(&metrics, &request, LISTENER_METRICS_OUTCOME_READY, LISTENER_METRICS_SELECTED_FAMILY_IPV6, &end),
		"pending route settlement failed");
	CHECK(!request.pending && request.settled, "pending route latch was incorrect");
	listener_metrics_state original = metrics;
	listener_metrics_snapshot snapshot;
	CHECK(listener_metrics_snapshot_get(&metrics, &snapshot), "pending route snapshot failed");
	CHECK(memcmp(&metrics, &original, sizeof(metrics)) == 0, "listener snapshot changed its source");
	const listener_metrics_route *route = &snapshot.route[LISTENER_METRICS_REQUEST_WORKER];
	CHECK(route->requests_started == 1 && route->pending_current == 0 && route->pending_high_water == 1, "pending route gauges were incorrect");
	CHECK(route->resolution[LISTENER_METRICS_RESOLUTION_WAITED] == 1 && route->outcome[LISTENER_METRICS_OUTCOME_READY] == 1,
		"pending route resolution or outcome was incorrect");
	CHECK(route->selected_family[LISTENER_METRICS_SELECTED_FAMILY_IPV6] == 1 && route->selected_family[LISTENER_METRICS_SELECTED_FAMILY_IPV4] == 0,
		"selected family was incorrect");
	CHECK(snapshot.route_duration[LISTENER_METRICS_REQUEST_WORKER].count == 1 && snapshot.route_duration[LISTENER_METRICS_REQUEST_WORKER].sum == 50000,
		"route duration sample was incorrect");
	CHECK(route->requests_started == route->pending_current + route->outcome[LISTENER_METRICS_OUTCOME_READY], "route conservation failed");
	return true;
}

static bool listener_metrics_test_route_terminal_variants(void) {
	listener_metrics_state metrics = { 0 };
	const struct timespec start = { .tv_sec = 1, .tv_nsec = 0 };
	const struct timespec end = { .tv_sec = 2, .tv_nsec = 0 };
	listener_metrics_route_request create_failure = { 0 };
	CHECK(listener_metrics_route_start(&metrics, &create_failure, LISTENER_METRICS_REQUEST_SHORT, &start), "create-failure route start failed");
	CHECK(listener_metrics_route_settle(&metrics, &create_failure, LISTENER_METRICS_OUTCOME_LIMIT, LISTENER_METRICS_SELECTED_FAMILY_IPV4, &end),
		"create-failure route settlement failed");
	listener_metrics_route_request abandoned = { 0 };
	CHECK(listener_metrics_route_start(&metrics, &abandoned, LISTENER_METRICS_REQUEST_SHORT, &start), "abandoned route start failed");
	CHECK(listener_metrics_route_duration_enable(&abandoned) && listener_metrics_route_pending(&metrics, &abandoned), "abandoned route did not become pending");
	CHECK(listener_metrics_route_resolution_record(&metrics, &abandoned, LISTENER_METRICS_RESOLUTION_WAITED), "abandoned resolution failed");
	CHECK(listener_metrics_route_settle(&metrics, &abandoned, LISTENER_METRICS_OUTCOME_ABANDONED, LISTENER_METRICS_SELECTED_FAMILY_NONE, &end),
		"abandoned route settlement failed");
	CHECK(listener_metrics_route_release_failure_record(&metrics, &abandoned), "route release failure was not recorded");
	const listener_metrics_route *route = &metrics.route[LISTENER_METRICS_REQUEST_SHORT];
	CHECK(route->requests_started == 2 && route->outcome[LISTENER_METRICS_OUTCOME_LIMIT] == 1 && route->outcome[LISTENER_METRICS_OUTCOME_ABANDONED] == 1,
		"terminal route outcomes were incorrect");
	CHECK(route->selected_family[LISTENER_METRICS_SELECTED_FAMILY_IPV4] == 0, "failed route recorded a selected family");
	CHECK(route->release_failure == 1 && route->requests_started == route->pending_current + 2, "release failure or route conservation was incorrect");
	CHECK(metrics.route_duration[LISTENER_METRICS_REQUEST_SHORT].count == 1, "route duration eligibility was incorrect");
	return true;
}

/* section: functions (entry point) */
int main(void) {
	if (!listener_metrics_test_capacity() || !listener_metrics_test_consumer_grammar() || !listener_metrics_test_helper_logs()
		|| !listener_metrics_test_invalid() || !listener_metrics_test_output() || !listener_metrics_test_route_duration_error()
		|| !listener_metrics_test_route_immediate() || !listener_metrics_test_route_pending() || !listener_metrics_test_route_terminal_variants()) {
		return 1;
	}
	return 0;
}
