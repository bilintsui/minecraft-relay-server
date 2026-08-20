/*
 * resolver/supervisor.h: Listener-owned resolver helper supervision
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
	RESOLVER_SUPERVISOR_HELPER_FAILURE_TIMEOUT
} resolver_supervisor_helper_failure;
typedef enum {
	RESOLVER_SUPERVISOR_HELPER_IDLE,
	RESOLVER_SUPERVISOR_HELPER_SENDING,
	RESOLVER_SUPERVISOR_HELPER_BUSY,
	RESOLVER_SUPERVISOR_HELPER_BACKOFF,
	RESOLVER_SUPERVISOR_HELPER_SHUTTING_DOWN,
	RESOLVER_SUPERVISOR_HELPER_STOPPED
} resolver_supervisor_helper_state;
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
typedef enum {
	RESOLVER_SUPERVISOR_JOB_QUEUED,
	RESOLVER_SUPERVISOR_JOB_SENDING,
	RESOLVER_SUPERVISOR_JOB_DISPATCHED,
	RESOLVER_SUPERVISOR_JOB_RETRY_WAIT,
	RESOLVER_SUPERVISOR_JOB_COMPLETE
} resolver_supervisor_job_state;
typedef enum {
	RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND,
	RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE
} resolver_supervisor_priority;
typedef struct {
	struct timespec deadline;
	struct timespec dispatched_at;
	size_t interactive_interest_count;
	resolver_supervisor_priority priority;
	uint64_t query_id;
	struct timespec retry_at;
	uint64_t retry_count;
	resolver_supervisor_job_state state;
} resolver_supervisor_job_view;
typedef enum {
	RESOLVER_SUPERVISOR_SCHEDULE_STARTED,
	RESOLVER_SUPERVISOR_SCHEDULE_COALESCED,
	RESOLVER_SUPERVISOR_SCHEDULE_COMPLETE,
	RESOLVER_SUPERVISOR_SCHEDULE_FRESH,
	RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT,
	RESOLVER_SUPERVISOR_SCHEDULE_IO,
	RESOLVER_SUPERVISOR_SCHEDULE_LIMIT,
	RESOLVER_SUPERVISOR_SCHEDULE_MEMORY,
	RESOLVER_SUPERVISOR_SCHEDULE_TIME
} resolver_supervisor_schedule_status;

/* section: functions (exported) */
/* The cache outlives the supervisor. Completion ownership includes the retained cache-entry reference and any transient response payload. Destroy every taken completion before its supervisor. */
void resolver_supervisor_completion_destroy(resolver_supervisor_completion *completion);
/* Completions passed to completion_take must be zero-initialized or previously destroyed. */
bool resolver_supervisor_completion_take(resolver_supervisor *supervisor, resolver_supervisor_completion *completion);
resolver_supervisor *resolver_supervisor_create(const sigset_t *helper_signal_mask, const struct timespec *now);
void resolver_supervisor_destroy(resolver_supervisor *supervisor);
/* Use only in a forked non-listener child. This releases inherited local state without signalling or reaping listener-owned helper processes. The cache must outlive this call. */
void resolver_supervisor_dispose_in_child(resolver_supervisor *supervisor);
/* Cancelling a dispatched entry suppresses retry and completion but lets the current helper response drain normally. */
bool resolver_supervisor_entry_cancel(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now);
/* Release one interest retained by a STARTED or COALESCED interactive schedule. Completion releases every remaining interest implicitly. */
bool resolver_supervisor_entry_interactive_release(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now);
/* Background scheduling observes the reserved interactive headroom. A schedule-time IO result means the shared timer source failed and the caller must retire the supervisor. */
resolver_supervisor_schedule_status resolver_supervisor_entry_schedule(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now);
/* A STARTED or COALESCED result retains one interactive interest until release or completion. FRESH and COMPLETE retain no interest. */
resolver_supervisor_schedule_status resolver_supervisor_entry_schedule_interactive(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now);
bool resolver_supervisor_entry_view(const resolver_supervisor *supervisor, const resolver_cache_entry *entry, resolver_supervisor_job_view *result);
/* Register this stable nested-epoll descriptor for EPOLLIN in the listener; helper replacements remain internal. Sample now after readiness before processing events. */
int resolver_supervisor_event_fd(const resolver_supervisor *supervisor);
/* Drain helper responses before applying every deadline due at now. */
resolver_supervisor_event_status resolver_supervisor_events_process(resolver_supervisor *supervisor, const struct timespec *now);
size_t resolver_supervisor_helper_count(const resolver_supervisor *supervisor);
bool resolver_supervisor_helper_view_get(const resolver_supervisor *supervisor, size_t helper_index, resolver_supervisor_helper_view *result);
size_t resolver_supervisor_job_count(const resolver_supervisor *supervisor);
bool resolver_supervisor_shutdown(resolver_supervisor *supervisor, const struct timespec *now);
bool resolver_supervisor_shutdown_complete(const resolver_supervisor *supervisor);

#endif
