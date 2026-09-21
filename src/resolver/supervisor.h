/*
 * resolver/supervisor.h: Header file of resolver/supervisor.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_RESOLVER_SUPERVISOR_H_INCLUDED_

#define _MRS_RESOLVER_SUPERVISOR_H_INCLUDED_

/* section: headers (library) */
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/* section: headers (project) */
#include "../metrics.h"
#include "cache.h"
#include "ipc_assembly.h"

/* section: defines */
/* helper pool */
#ifndef RESOLVER_SUPERVISOR_HELPER_COUNT
#define RESOLVER_SUPERVISOR_HELPER_COUNT	2
#endif
#ifndef RESOLVER_SUPERVISOR_JOB_LIMIT
#define RESOLVER_SUPERVISOR_JOB_LIMIT	4096
#endif
#ifndef RESOLVER_SUPERVISOR_INTERACTIVE_RESERVE
#define RESOLVER_SUPERVISOR_INTERACTIVE_RESERVE	256
#endif

/* helper recovery */
#ifndef RESOLVER_SUPERVISOR_RESPAWN_INITIAL_MS
#define RESOLVER_SUPERVISOR_RESPAWN_INITIAL_MS	100
#endif
#ifndef RESOLVER_SUPERVISOR_RESPAWN_MAX_MS
#define RESOLVER_SUPERVISOR_RESPAWN_MAX_MS	30000
#endif
#ifndef RESOLVER_SUPERVISOR_RESPAWN_RESET_STABLE_SEC
#define RESOLVER_SUPERVISOR_RESPAWN_RESET_STABLE_SEC	60
#endif
#ifndef RESOLVER_SUPERVISOR_RESPAWN_RESET_SUCCESS_COUNT
#define RESOLVER_SUPERVISOR_RESPAWN_RESET_SUCCESS_COUNT	3
#endif

/* query scheduling */
#ifndef RESOLVER_SUPERVISOR_QUERY_RETRY_INITIAL_MS
#define RESOLVER_SUPERVISOR_QUERY_RETRY_INITIAL_MS	1000
#endif
#ifndef RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS
#define RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS	60000
#endif
#ifndef RESOLVER_SUPERVISOR_QUERY_TIMEOUT_SEC
#define RESOLVER_SUPERVISOR_QUERY_TIMEOUT_SEC	10
#endif

/* scheduling jitter */
#ifndef RESOLVER_SUPERVISOR_JITTER_PERCENT
#define RESOLVER_SUPERVISOR_JITTER_PERCENT	20
#endif

/* shutdown */
#ifndef RESOLVER_SUPERVISOR_SHUTDOWN_GRACE_MS
#define RESOLVER_SUPERVISOR_SHUTDOWN_GRACE_MS	1000
#endif

/* section: types */
typedef struct resolver_supervisor resolver_supervisor;
typedef struct {
	resolver_cache_entry *entry;
	resolver_cache_publish_status publication;
	resolver_ipc_assembly_result response;
} resolver_supervisor_completion;
typedef enum {
	RESOLVER_SUPERVISOR_DNS_OUTCOME_OK,
	RESOLVER_SUPERVISOR_DNS_OUTCOME_BAD_ARGUMENT,
	RESOLVER_SUPERVISOR_DNS_OUTCOME_LIMIT,
	RESOLVER_SUPERVISOR_DNS_OUTCOME_MALFORMED,
	RESOLVER_SUPERVISOR_DNS_OUTCOME_MEMORY,
	RESOLVER_SUPERVISOR_DNS_OUTCOME_NODATA,
	RESOLVER_SUPERVISOR_DNS_OUTCOME_NOT_FOUND,
	RESOLVER_SUPERVISOR_DNS_OUTCOME_PERMANENT,
	RESOLVER_SUPERVISOR_DNS_OUTCOME_TEMPORARY,
	RESOLVER_SUPERVISOR_DNS_OUTCOME_TRUNCATED,
	RESOLVER_SUPERVISOR_DNS_OUTCOME_COUNT
} resolver_supervisor_dns_outcome;
typedef enum {
	RESOLVER_SUPERVISOR_EVENT_OK,
	RESOLVER_SUPERVISOR_EVENT_BAD_ARGUMENT,
	RESOLVER_SUPERVISOR_EVENT_IO,
	RESOLVER_SUPERVISOR_EVENT_TIME
} resolver_supervisor_event_status;
typedef enum {
	RESOLVER_SUPERVISOR_HELPER_FAILURE_NONE,
	RESOLVER_SUPERVISOR_HELPER_FAILURE_EXIT,
	RESOLVER_SUPERVISOR_HELPER_FAILURE_IO,
	RESOLVER_SUPERVISOR_HELPER_FAILURE_PROTOCOL,
	RESOLVER_SUPERVISOR_HELPER_FAILURE_SPAWN,
	RESOLVER_SUPERVISOR_HELPER_FAILURE_TIMEOUT,
	RESOLVER_SUPERVISOR_HELPER_FAILURE_COUNT
} resolver_supervisor_helper_failure;
typedef enum {
	RESOLVER_SUPERVISOR_HELPER_IDLE,
	RESOLVER_SUPERVISOR_HELPER_SENDING,
	RESOLVER_SUPERVISOR_HELPER_BUSY,
	RESOLVER_SUPERVISOR_HELPER_BACKOFF,
	RESOLVER_SUPERVISOR_HELPER_SHUTTING_DOWN,
	RESOLVER_SUPERVISOR_HELPER_STOPPED
} resolver_supervisor_helper_state;
#ifdef RESOLVER_SUPERVISOR_TEST_API
typedef struct {
	size_t consecutive_successes;
	uint64_t failure_count;
	int fd;
	pid_t last_failed_process_id;
	resolver_supervisor_helper_failure last_failure;
	struct timespec next_event_at;
	pid_t process_id;
	resolver_supervisor_helper_state state;
} resolver_supervisor_helper_view;
#endif
typedef enum {
	RESOLVER_SUPERVISOR_JOB_QUEUED,
	RESOLVER_SUPERVISOR_JOB_SENDING,
	RESOLVER_SUPERVISOR_JOB_DISPATCHED,
	RESOLVER_SUPERVISOR_JOB_RETRY_WAIT,
	RESOLVER_SUPERVISOR_JOB_COMPLETE,
	RESOLVER_SUPERVISOR_JOB_STATE_COUNT
} resolver_supervisor_job_state;
typedef enum {
	RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND,
	RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE,
	RESOLVER_SUPERVISOR_PRIORITY_COUNT
} resolver_supervisor_priority;
#ifdef RESOLVER_SUPERVISOR_TEST_API
typedef struct {
	size_t background_interest_count;
	struct timespec deadline;
	struct timespec dispatched_at;
	size_t interactive_interest_count;
	bool orphaned;
	resolver_supervisor_priority priority;
	uint64_t query_id;
	struct timespec retry_at;
	uint64_t retry_count;
	resolver_supervisor_job_state state;
} resolver_supervisor_job_view;
#endif
typedef enum {
	RESOLVER_SUPERVISOR_RELEASE_OK,
	RESOLVER_SUPERVISOR_RELEASE_SATISFIED,
	RESOLVER_SUPERVISOR_RELEASE_BAD_ARGUMENT,
	RESOLVER_SUPERVISOR_RELEASE_IO,
	RESOLVER_SUPERVISOR_RELEASE_TIME
} resolver_supervisor_release_status;
typedef enum {
	RESOLVER_SUPERVISOR_SCHEDULE_STARTED,
	RESOLVER_SUPERVISOR_SCHEDULE_COALESCED,
	RESOLVER_SUPERVISOR_SCHEDULE_COMPLETE,
	RESOLVER_SUPERVISOR_SCHEDULE_FRESH,
	RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT,
	RESOLVER_SUPERVISOR_SCHEDULE_IO,
	RESOLVER_SUPERVISOR_SCHEDULE_LIMIT,
	RESOLVER_SUPERVISOR_SCHEDULE_MEMORY,
	RESOLVER_SUPERVISOR_SCHEDULE_TIME,
	RESOLVER_SUPERVISOR_SCHEDULE_STATUS_COUNT
} resolver_supervisor_schedule_status;
typedef struct {
	uint64_t attempt_abandoned_shutdown;
	uint64_t completion_abandoned_shutdown;
	uint64_t completion_enqueued;
	uint64_t completion_taken;
	uint64_t dispatched;
	uint64_t failure[RESOLVER_SUPERVISOR_HELPER_FAILURE_COUNT];
	uint64_t jobs_complete_current;
	uint64_t jobs_dispatched_current;
	uint64_t orphan_response[RESOLVER_SUPERVISOR_DNS_OUTCOME_COUNT];
	uint64_t response[RESOLVER_SUPERVISOR_DNS_OUTCOME_COUNT];
	uint64_t retry_scheduled;
} resolver_supervisor_metrics_attempt;
typedef struct {
	uint64_t limit_background_admission;
	uint64_t limit_entry_reference;
	uint64_t limit_interest_count;
	uint64_t limit_total_admission;
	uint64_t status[RESOLVER_SUPERVISOR_SCHEDULE_STATUS_COUNT];
} resolver_supervisor_metrics_schedule;
typedef struct {
	resolver_supervisor_metrics_attempt attempt[METRICS_RESOLVER_QUERY_TYPE_COUNT];
	metrics_histogram_snapshot attempt_duration[METRICS_RESOLVER_QUERY_TYPE_COUNT];
	metrics_histogram_snapshot dispatch_wait[RESOLVER_SUPERVISOR_PRIORITY_COUNT][METRICS_RESOLVER_QUERY_TYPE_COUNT];
	uint64_t interests_current[RESOLVER_SUPERVISOR_PRIORITY_COUNT];
	uint64_t jobs_current;
	uint64_t jobs_high_water;
	uint64_t jobs_priority_current[RESOLVER_SUPERVISOR_PRIORITY_COUNT];
	uint64_t jobs_state_current[RESOLVER_SUPERVISOR_JOB_STATE_COUNT];
	uint64_t orphaned_dispatched_current;
	uint64_t queue_current[RESOLVER_SUPERVISOR_PRIORITY_COUNT];
	uint64_t queue_high_water[RESOLVER_SUPERVISOR_PRIORITY_COUNT];
	resolver_supervisor_metrics_schedule schedule[RESOLVER_SUPERVISOR_PRIORITY_COUNT][METRICS_QUERY_TYPE_COUNT];
	uint64_t saturation_total;
} resolver_supervisor_metrics_snapshot;

/* section: functions (exported) */
/* The cache outlives the supervisor. Completion ownership includes the retained cache-entry reference and any transient response payload. Destroy every taken completion before its supervisor. */
void resolver_supervisor_completion_destroy(resolver_supervisor_completion *completion);
/* Completions passed to completion_take must be zero-initialized or previously destroyed. */
bool resolver_supervisor_completion_take(resolver_supervisor *supervisor, resolver_supervisor_completion *completion);
resolver_supervisor *resolver_supervisor_create(const sigset_t *helper_signal_mask, const struct timespec *now);
void resolver_supervisor_destroy(resolver_supervisor *supervisor);
/* Use only in a forked non-listener child. This releases inherited local state without signalling or reaping listener-owned helper processes. The cache must outlive this call. */
void resolver_supervisor_dispose_in_child(resolver_supervisor *supervisor);
/* Release one interest retained by a STARTED or COALESCED background schedule. Completion releases every remaining interest implicitly. */
resolver_supervisor_release_status resolver_supervisor_entry_background_release(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now);
#ifdef RESOLVER_SUPERVISOR_TEST_API
/* Cancelling a dispatched entry suppresses retry and completion but lets the current helper response drain normally. */
bool resolver_supervisor_entry_cancel(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now);
#endif
/* Release one interest retained by a STARTED or COALESCED interactive schedule. Completion releases every remaining interest implicitly. */
resolver_supervisor_release_status resolver_supervisor_entry_interactive_release(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now);
/* A STARTED or COALESCED result retains one background interest until release or completion. Background scheduling observes the reserved interactive headroom. A schedule-time IO result
 * means the shared timer source failed and the caller must retire the supervisor without assuming ownership.
 */
resolver_supervisor_schedule_status resolver_supervisor_entry_schedule(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now);
/* A STARTED or COALESCED result retains one interactive interest until release or completion. FRESH and COMPLETE retain no interest. */
resolver_supervisor_schedule_status resolver_supervisor_entry_schedule_interactive(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now);
#ifdef RESOLVER_SUPERVISOR_TEST_API
bool resolver_supervisor_entry_view(const resolver_supervisor *supervisor, const resolver_cache_entry *entry, resolver_supervisor_job_view *result);
#endif
/* Register this stable nested-epoll descriptor for EPOLLIN in the listener; helper replacements remain internal. Sample now after readiness before processing events. */
int resolver_supervisor_event_fd(const resolver_supervisor *supervisor);
/* Drain helper responses before applying every deadline due at now. */
resolver_supervisor_event_status resolver_supervisor_events_process(resolver_supervisor *supervisor, const struct timespec *now);
#ifdef RESOLVER_SUPERVISOR_TEST_API
size_t resolver_supervisor_helper_count(const resolver_supervisor *supervisor);
bool resolver_supervisor_helper_view_get(const resolver_supervisor *supervisor, size_t helper_index, resolver_supervisor_helper_view *result);
size_t resolver_supervisor_job_count(const resolver_supervisor *supervisor);
#endif
bool resolver_supervisor_metrics_get(const resolver_supervisor *supervisor, resolver_supervisor_metrics_snapshot *result);
bool resolver_supervisor_shutdown(resolver_supervisor *supervisor, const struct timespec *now);
bool resolver_supervisor_shutdown_complete(const resolver_supervisor *supervisor);

#endif
