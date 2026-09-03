/*
 * resolver/supervisor.c: Listener-owned resolver helper supervision
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "../timeutil.h"
#include "cache.h"
#include "helper.h"
#include "ipc.h"
#include "ipc_assembly.h"

/* section: headers (self) */
#include "supervisor.h"

/* section: defines */
/* event source tags */
#define RESOLVER_SUPERVISOR_EVENT_TIMER	0U

/* hash */
#define RESOLVER_SUPERVISOR_FNV_OFFSET	UINT64_C(14695981039346656037)
#define RESOLVER_SUPERVISOR_FNV_PRIME	UINT64_C(1099511628211)
#define RESOLVER_SUPERVISOR_JITTER_QUERY_DOMAIN	UINT8_C(0x51)
#define RESOLVER_SUPERVISOR_JITTER_RESPAWN_DOMAIN	UINT8_C(0x52)

/* interest accounting; override only in focused tests that exercise the overflow boundary */
#ifndef RESOLVER_SUPERVISOR_INTEREST_COUNT_LIMIT
#define RESOLVER_SUPERVISOR_INTEREST_COUNT_LIMIT	SIZE_MAX
#endif

/* packet */
#define RESOLVER_SUPERVISOR_RECEIVE_BYTE_CAPACITY	(RESOLVER_IPC_PACKET_BYTE_LIMIT + 1U)

/* process names */
#define RESOLVER_SUPERVISOR_PROCESS_NAME_CAPACITY	16U

/* section: types */
typedef struct resolver_supervisor_job resolver_supervisor_job;
typedef enum {
	RESOLVER_SUPERVISOR_ASSIGN_OK,
	RESOLVER_SUPERVISOR_ASSIGN_RETRY,
	RESOLVER_SUPERVISOR_ASSIGN_LIMIT,
	RESOLVER_SUPERVISOR_ASSIGN_TIME,
	RESOLVER_SUPERVISOR_ASSIGN_IO
} resolver_supervisor_assign_status;
typedef enum {
	RESOLVER_SUPERVISOR_SEND_OK,
	RESOLVER_SUPERVISOR_SEND_IO,
	RESOLVER_SUPERVISOR_SEND_TIME
} resolver_supervisor_send_status;
typedef struct {
	size_t consecutive_successes;
	uint64_t failure_count;
	int fd;
	resolver_supervisor_job *job;
	pid_t last_failed_process_id;
	resolver_supervisor_helper_failure last_failure;
	struct timespec next_event_at;
	pid_t process_id;
	uint8_t request_packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t request_size;
	resolver_supervisor_helper_state state;
} resolver_supervisor_helper;
typedef struct {
	resolver_supervisor_job *head;
	resolver_supervisor_job *tail;
} resolver_supervisor_job_queue;
struct resolver_supervisor_job {
	size_t background_interest_count;
	bool cancelled;
	resolver_supervisor_job *completion_next;
	resolver_supervisor_job *completion_previous;
	struct timespec deadline;
	struct timespec dispatched_at;
	resolver_cache_entry *entry;
	resolver_supervisor_job *hash_next;
	size_t interactive_interest_count;
	bool orphaned;
	resolver_ipc_assembly *assembly;
	resolver_supervisor_priority priority;
	resolver_supervisor_job *queue_next;
	resolver_supervisor_job *queue_previous;
	uint64_t query_id;
	resolver_cache_publish_status publication;
	resolver_ipc_assembly_result response;
	struct timespec retry_at;
	uint64_t retry_count;
	size_t slot_index;
	resolver_supervisor_job_state state;
};
struct resolver_supervisor {
	resolver_ipc_assembly_budget *assembly_budget;
	resolver_supervisor_job_queue background_queue;
	resolver_supervisor_job **buckets;
	resolver_supervisor_job *completion_head;
	resolver_supervisor_job *completion_tail;
	int epoll_fd;
	resolver_supervisor_helper *helpers;
	sigset_t helper_signal_mask;
	resolver_supervisor_job_queue interactive_queue;
	size_t job_count;
	struct timespec last_now;
	uint64_t next_query_id;
	bool shutting_down;
	int timer_fd;
};

/* section: functions (local) */
static bool resolver_supervisor_completion_empty(const resolver_supervisor_completion *completion) {
	return completion != NULL && completion->entry == NULL && completion->publication == 0 && completion->response.budget == NULL && completion->response.completed_at.tv_sec == 0
		&& completion->response.completed_at.tv_nsec == 0 && completion->response.dynamic_bytes == 0 && completion->response.query_id == 0 && completion->response.query_type == 0
		&& completion->response.status == 0;
}

static uint64_t resolver_supervisor_hash_byte(uint64_t hash, uint8_t value) {
	return (hash ^ value) * RESOLVER_SUPERVISOR_FNV_PRIME;
}

static uint64_t resolver_supervisor_hash_u64(uint64_t hash, uint64_t value) {
	for (unsigned int shift = 56; ; shift -= 8) {
		hash = resolver_supervisor_hash_byte(hash, (uint8_t)(value >> shift));
		if (shift == 0) {
			return hash;
		}
	}
}

static uint64_t resolver_supervisor_delay_jitter(uint64_t base_milliseconds, uint64_t maximum_milliseconds, uint8_t domain, uint64_t identity, uint64_t attempt) {
	uint64_t hash = resolver_supervisor_hash_byte(RESOLVER_SUPERVISOR_FNV_OFFSET, domain);
	hash = resolver_supervisor_hash_u64(hash, identity);
	hash = resolver_supervisor_hash_u64(hash, attempt);
	int percentage = (int)(hash % (uint64_t)(RESOLVER_SUPERVISOR_JITTER_PERCENT * 2 + 1)) - RESOLVER_SUPERVISOR_JITTER_PERCENT;
	uint64_t factor = (uint64_t)(100 + percentage);
	uint64_t delay = factor == 0 ? 0 : (base_milliseconds > UINT64_MAX / factor ? UINT64_MAX : base_milliseconds * factor / 100U);
	return delay < maximum_milliseconds ? delay : maximum_milliseconds;
}

static uint64_t resolver_supervisor_delay_query_base(uint64_t retry_count) {
	if (retry_count == 0) {
		return 0;
	}
	uint64_t delay = RESOLVER_SUPERVISOR_QUERY_RETRY_INITIAL_MS;
	for (uint64_t index = 1; index < retry_count && delay < RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS; index++) {
		if (delay > RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS / 2U) {
			delay = RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS;
			break;
		}
		delay *= 2U;
	}
	return delay < RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS ? delay : RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS;
}

static uint64_t resolver_supervisor_delay_respawn_base(uint64_t failure_count) {
	if (failure_count <= 1) {
		return 0;
	}
	uint64_t delay = RESOLVER_SUPERVISOR_RESPAWN_INITIAL_MS;
	for (uint64_t index = 2; index < failure_count && delay < RESOLVER_SUPERVISOR_RESPAWN_MAX_MS; index++) {
		if (delay > RESOLVER_SUPERVISOR_RESPAWN_MAX_MS / 2U) {
			delay = RESOLVER_SUPERVISOR_RESPAWN_MAX_MS;
			break;
		}
		delay *= 2U;
	}
	return delay < RESOLVER_SUPERVISOR_RESPAWN_MAX_MS ? delay : RESOLVER_SUPERVISOR_RESPAWN_MAX_MS;
}

static bool resolver_supervisor_time_update(resolver_supervisor *supervisor, const struct timespec *now) {
	if (supervisor == NULL || !timeutil_valid(now) || timeutil_compare(now, &supervisor->last_now) < 0) {
		return false;
	}
	supervisor->last_now = *now;
	return true;
}

static size_t resolver_supervisor_job_bucket(const resolver_cache_entry *entry) {
	return (size_t)(resolver_cache_entry_id(entry) % (uint64_t)RESOLVER_SUPERVISOR_JOB_LIMIT);
}

static void resolver_supervisor_job_complete(resolver_supervisor *supervisor, resolver_supervisor_job *job, resolver_cache_publish_status publication,
	resolver_ipc_assembly_result *response) {
	job->background_interest_count = 0;
	job->interactive_interest_count = 0;
	job->publication = publication;
	job->response = *response;
	memset(response, 0, sizeof(*response));
	job->state = RESOLVER_SUPERVISOR_JOB_COMPLETE;
	job->completion_previous = supervisor->completion_tail;
	if (supervisor->completion_tail == NULL) {
		supervisor->completion_head = job;
	} else {
		supervisor->completion_tail->completion_next = job;
	}
	supervisor->completion_tail = job;
}

static void resolver_supervisor_job_completion_remove(resolver_supervisor *supervisor, resolver_supervisor_job *job) {
	if (job->completion_previous == NULL) {
		supervisor->completion_head = job->completion_next;
	} else {
		job->completion_previous->completion_next = job->completion_next;
	}
	if (job->completion_next == NULL) {
		supervisor->completion_tail = job->completion_previous;
	} else {
		job->completion_next->completion_previous = job->completion_previous;
	}
	job->completion_next = NULL;
	job->completion_previous = NULL;
}

static resolver_supervisor_job *resolver_supervisor_job_find(const resolver_supervisor *supervisor, const resolver_cache_entry *entry) {
	if (supervisor == NULL || entry == NULL) {
		return NULL;
	}
	for (resolver_supervisor_job *job = supervisor->buckets[resolver_supervisor_job_bucket(entry)]; job != NULL; job = job->hash_next) {
		if (job->entry == entry) {
			return job;
		}
	}
	return NULL;
}

static void resolver_supervisor_job_hash_remove(resolver_supervisor *supervisor, resolver_supervisor_job *job) {
	size_t bucket = resolver_supervisor_job_bucket(job->entry);
	resolver_supervisor_job **cursor = &supervisor->buckets[bucket];
	while (*cursor != NULL && *cursor != job) {
		cursor = &(*cursor)->hash_next;
	}
	if (*cursor == job) {
		*cursor = job->hash_next;
	}
	job->hash_next = NULL;
}

static resolver_supervisor_job *resolver_supervisor_job_queue_first(const resolver_supervisor *supervisor) {
	return supervisor->interactive_queue.head == NULL ? supervisor->background_queue.head : supervisor->interactive_queue.head;
}

static resolver_supervisor_job_queue *resolver_supervisor_job_queue_select(resolver_supervisor *supervisor, resolver_supervisor_priority priority) {
	return priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE ? &supervisor->interactive_queue : &supervisor->background_queue;
}

static void resolver_supervisor_job_queue_remove(resolver_supervisor *supervisor, resolver_supervisor_job *job) {
	resolver_supervisor_job_queue *queue = resolver_supervisor_job_queue_select(supervisor, job->priority);
	if (job->queue_previous == NULL) {
		queue->head = job->queue_next;
	} else {
		job->queue_previous->queue_next = job->queue_next;
	}
	if (job->queue_next == NULL) {
		queue->tail = job->queue_previous;
	} else {
		job->queue_next->queue_previous = job->queue_previous;
	}
	job->queue_next = NULL;
	job->queue_previous = NULL;
}

static void resolver_supervisor_job_destroy(resolver_supervisor *supervisor, resolver_supervisor_job *job) {
	if (job == NULL) {
		return;
	}
	if (job->state == RESOLVER_SUPERVISOR_JOB_QUEUED) {
		resolver_supervisor_job_queue_remove(supervisor, job);
	} else if (job->state == RESOLVER_SUPERVISOR_JOB_COMPLETE) {
		resolver_supervisor_job_completion_remove(supervisor, job);
	}
	resolver_supervisor_job_hash_remove(supervisor, job);
	resolver_ipc_assembly_destroy(job->assembly);
	resolver_ipc_assembly_result_destroy(&job->response);
	resolver_cache_entry_release(job->entry);
	if (supervisor->job_count > 0) {
		supervisor->job_count--;
	}
	free(job);
}

static void resolver_supervisor_job_queue_append(resolver_supervisor *supervisor, resolver_supervisor_job *job) {
	resolver_supervisor_job_queue *queue = resolver_supervisor_job_queue_select(supervisor, job->priority);
	job->queue_previous = queue->tail;
	if (queue->tail == NULL) {
		queue->head = job;
	} else {
		queue->tail->queue_next = job;
	}
	queue->tail = job;
	job->state = RESOLVER_SUPERVISOR_JOB_QUEUED;
}

static void resolver_supervisor_job_queue_prepend(resolver_supervisor *supervisor, resolver_supervisor_job *job) {
	resolver_supervisor_job_queue *queue = resolver_supervisor_job_queue_select(supervisor, job->priority);
	job->queue_next = queue->head;
	if (queue->head == NULL) {
		queue->tail = job;
	} else {
		queue->head->queue_previous = job;
	}
	queue->head = job;
	job->state = RESOLVER_SUPERVISOR_JOB_QUEUED;
}

static void resolver_supervisor_job_priority_downgrade(resolver_supervisor *supervisor, resolver_supervisor_job *job) {
	if (job->priority != RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE || job->interactive_interest_count != 0) {
		return;
	}
	bool queued = job->state == RESOLVER_SUPERVISOR_JOB_QUEUED;
	if (queued) {
		resolver_supervisor_job_queue_remove(supervisor, job);
	}
	job->priority = RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND;
	if (queued) {
		resolver_supervisor_job_queue_append(supervisor, job);
	}
}

static void resolver_supervisor_job_priority_promote(resolver_supervisor *supervisor, resolver_supervisor_job *job) {
	if (job->priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE) {
		return;
	}
	bool queued = job->state == RESOLVER_SUPERVISOR_JOB_QUEUED;
	if (queued) {
		resolver_supervisor_job_queue_remove(supervisor, job);
	}
	job->priority = RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE;
	if (queued) {
		resolver_supervisor_job_queue_append(supervisor, job);
	}
}

static bool resolver_supervisor_job_result_retryable(resolver_ipc_lookup_status status) {
	return status == RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR;
}

static void resolver_supervisor_job_retry(resolver_supervisor *supervisor, resolver_supervisor_job *job, const struct timespec *now) {
	if (job->cancelled || job->orphaned) {
		resolver_supervisor_job_destroy(supervisor, job);
		return;
	}
	if (job->retry_count < UINT64_MAX) {
		job->retry_count++;
	}
	uint64_t base_delay = resolver_supervisor_delay_query_base(job->retry_count);
	uint64_t delay = resolver_supervisor_delay_jitter(base_delay, RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS, RESOLVER_SUPERVISOR_JITTER_QUERY_DOMAIN,
		resolver_cache_entry_id(job->entry), job->retry_count);
	if (!timeutil_add_milliseconds(now, delay, &job->retry_at)) {
		resolver_ipc_assembly_result response = {
			.query_type = resolver_cache_entry_query_type(job->entry),
			.status = RESOLVER_IPC_LOOKUP_PERMANENT_ERROR
		};
		resolver_supervisor_job_complete(supervisor, job, RESOLVER_CACHE_PUBLISH_TIME, &response);
		return;
	}
	job->state = RESOLVER_SUPERVISOR_JOB_RETRY_WAIT;
}

static bool resolver_supervisor_job_timestamp_valid(const resolver_supervisor_job *job, const struct timespec *completed_at, const struct timespec *now) {
	return timeutil_valid(completed_at) && timeutil_compare(completed_at, &job->dispatched_at) >= 0
		&& timeutil_compare(completed_at, &job->deadline) <= 0 && timeutil_compare(completed_at, now) <= 0;
}

static void resolver_supervisor_process_reap(pid_t process_id) {
	if (process_id <= 0) {
		return;
	}
	while (waitpid(process_id, NULL, 0) == -1 && errno == EINTR) {
	}
}

static void resolver_supervisor_process_terminate(pid_t process_id, int signal_number) {
	if (process_id <= 0 || signal_number == 0) {
		return;
	}
	if (kill(process_id, signal_number) == -1 && errno != ESRCH) {
		return;
	}
	if (signal_number == SIGKILL) {
		resolver_supervisor_process_reap(process_id);
	}
}

static void resolver_supervisor_process_reap_or_kill(pid_t process_id) {
	if (process_id <= 0) {
		return;
	}
	pid_t result;
	do {
		result = waitpid(process_id, NULL, WNOHANG);
	} while (result == -1 && errno == EINTR);
	if (result == 0) {
		resolver_supervisor_process_terminate(process_id, SIGKILL);
	}
}

static int resolver_supervisor_helper_events_update(resolver_supervisor *supervisor, size_t helper_index) {
	resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
	if (helper->fd == -1) {
		return 0;
	}
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLRDHUP;
	if (helper->state == RESOLVER_SUPERVISOR_HELPER_SENDING) {
		event.events |= EPOLLOUT;
	}
	event.data.u32 = (uint32_t)(helper_index + 1U);
	return epoll_ctl(supervisor->epoll_fd, EPOLL_CTL_MOD, helper->fd, &event);
}

static void resolver_supervisor_helper_process_close(resolver_supervisor *supervisor, resolver_supervisor_helper *helper, int signal_number) {
	pid_t process_id = helper->process_id;
	if (helper->fd != -1) {
		epoll_ctl(supervisor->epoll_fd, EPOLL_CTL_DEL, helper->fd, NULL);
		close(helper->fd);
		helper->fd = -1;
	}
	helper->process_id = -1;
	if (signal_number == 0) {
		resolver_supervisor_process_reap_or_kill(process_id);
	} else {
		resolver_supervisor_process_terminate(process_id, signal_number);
	}
}

static void resolver_supervisor_helper_recovery_reset(resolver_supervisor_helper *helper) {
	helper->consecutive_successes = 0;
	helper->failure_count = 0;
	helper->last_failed_process_id = -1;
	helper->last_failure = RESOLVER_SUPERVISOR_HELPER_FAILURE_NONE;
	memset(&helper->next_event_at, 0, sizeof(helper->next_event_at));
}

static void resolver_supervisor_helper_respawn_schedule(resolver_supervisor *supervisor, size_t helper_index, resolver_supervisor_helper_failure failure, const struct timespec *now) {
	resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
	helper->consecutive_successes = 0;
	if (helper->failure_count < UINT64_MAX) {
		helper->failure_count++;
	}
	helper->last_failure = failure;
	helper->state = supervisor->shutting_down ? RESOLVER_SUPERVISOR_HELPER_STOPPED : RESOLVER_SUPERVISOR_HELPER_BACKOFF;
	if (supervisor->shutting_down) {
		memset(&helper->next_event_at, 0, sizeof(helper->next_event_at));
		return;
	}
	uint64_t base_delay = resolver_supervisor_delay_respawn_base(helper->failure_count);
	uint64_t delay = base_delay == 0 ? 0 : resolver_supervisor_delay_jitter(base_delay, RESOLVER_SUPERVISOR_RESPAWN_MAX_MS, RESOLVER_SUPERVISOR_JITTER_RESPAWN_DOMAIN,
		helper_index, helper->failure_count);
	if (!timeutil_add_milliseconds(now, delay, &helper->next_event_at)) {
		helper->next_event_at = *now;
	}
}

static void resolver_supervisor_helper_success(resolver_supervisor_helper *helper) {
	/* Success counting matters only while this slot retains recovery state from an earlier failure. */
	if (helper->failure_count == 0) {
		return;
	}
	helper->consecutive_successes++;
	if (helper->consecutive_successes >= RESOLVER_SUPERVISOR_RESPAWN_RESET_SUCCESS_COUNT) {
		resolver_supervisor_helper_recovery_reset(helper);
	}
}

static void resolver_supervisor_helper_fail(resolver_supervisor *supervisor, size_t helper_index, resolver_supervisor_helper_failure failure, const struct timespec *now) {
	resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
	helper->last_failed_process_id = helper->process_id;
	resolver_supervisor_job *job = helper->job;
	if (job != NULL) {
		bool dispatched = job->state == RESOLVER_SUPERVISOR_JOB_DISPATCHED;
		job->query_id = 0;
		resolver_ipc_assembly_destroy(job->assembly);
		job->assembly = NULL;
		helper->job = NULL;
		helper->request_size = 0;
		if (dispatched) {
			resolver_supervisor_job_retry(supervisor, job, now);
		} else if (job->cancelled) {
			resolver_supervisor_job_destroy(supervisor, job);
		} else {
			resolver_supervisor_job_queue_prepend(supervisor, job);
		}
	}
	resolver_supervisor_helper_process_close(supervisor, helper, failure == RESOLVER_SUPERVISOR_HELPER_FAILURE_EXIT ? 0 : SIGKILL);
	resolver_supervisor_helper_respawn_schedule(supervisor, helper_index, failure, now);
}

static int resolver_supervisor_helper_spawn(resolver_supervisor *supervisor, size_t helper_index, const struct timespec *now) {
	resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
	char process_name[RESOLVER_SUPERVISOR_PROCESS_NAME_CAPACITY];
	snprintf(process_name, sizeof(process_name), "resolver-%zu", helper_index);
	pid_t process_id;
	int socket_fd;
	if (resolver_helper_process_start(&supervisor->helper_signal_mask, process_name, &process_id, &socket_fd) == -1) {
		helper->last_failed_process_id = -1;
		resolver_supervisor_helper_respawn_schedule(supervisor, helper_index, RESOLVER_SUPERVISOR_HELPER_FAILURE_SPAWN, now);
		return -1;
	}
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLRDHUP;
	event.data.u32 = (uint32_t)(helper_index + 1U);
	if (epoll_ctl(supervisor->epoll_fd, EPOLL_CTL_ADD, socket_fd, &event) == -1) {
		helper->last_failed_process_id = process_id;
		close(socket_fd);
		resolver_supervisor_process_terminate(process_id, SIGKILL);
		resolver_supervisor_helper_respawn_schedule(supervisor, helper_index, RESOLVER_SUPERVISOR_HELPER_FAILURE_SPAWN, now);
		return -1;
	}
	helper->fd = socket_fd;
	helper->next_event_at = *now;
	if (helper->failure_count > 0 && !timeutil_add_seconds(now, RESOLVER_SUPERVISOR_RESPAWN_RESET_STABLE_SEC, &helper->next_event_at)) {
		helper->next_event_at = *now;
	}
	helper->process_id = process_id;
	helper->state = RESOLVER_SUPERVISOR_HELPER_IDLE;
	return 0;
}

static void resolver_supervisor_helper_stop(resolver_supervisor *supervisor, resolver_supervisor_helper *helper, bool force) {
	resolver_supervisor_helper_process_close(supervisor, helper, force ? SIGKILL : 0);
	helper->state = RESOLVER_SUPERVISOR_HELPER_STOPPED;
	memset(&helper->next_event_at, 0, sizeof(helper->next_event_at));
}

static resolver_supervisor_send_status resolver_supervisor_helper_request_send(resolver_supervisor *supervisor, size_t helper_index, const struct timespec *now) {
	resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
	resolver_supervisor_job *job = helper->job;
	struct timespec deadline;
	if (!timeutil_add_seconds(now, RESOLVER_SUPERVISOR_QUERY_TIMEOUT_SEC, &deadline)) {
		return RESOLVER_SUPERVISOR_SEND_TIME;
	}
	while (true) {
		ssize_t sent = send(helper->fd, helper->request_packet, helper->request_size, MSG_NOSIGNAL);
		if (sent == (ssize_t)helper->request_size) {
			job->state = RESOLVER_SUPERVISOR_JOB_DISPATCHED;
			job->dispatched_at = *now;
			job->deadline = deadline;
			helper->request_size = 0;
			helper->state = RESOLVER_SUPERVISOR_HELPER_BUSY;
			return resolver_supervisor_helper_events_update(supervisor, helper_index) == 0 ? RESOLVER_SUPERVISOR_SEND_OK : RESOLVER_SUPERVISOR_SEND_IO;
		}
		if (sent >= 0) {
			errno = EIO;
			return RESOLVER_SUPERVISOR_SEND_IO;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			job->state = RESOLVER_SUPERVISOR_JOB_SENDING;
			helper->state = RESOLVER_SUPERVISOR_HELPER_SENDING;
			return resolver_supervisor_helper_events_update(supervisor, helper_index) == 0 ? RESOLVER_SUPERVISOR_SEND_OK : RESOLVER_SUPERVISOR_SEND_IO;
		}
		return RESOLVER_SUPERVISOR_SEND_IO;
	}
}

static bool resolver_supervisor_query_id_allocate(resolver_supervisor *supervisor, uint64_t *result) {
	if (supervisor->next_query_id == 0 || result == NULL) {
		return false;
	}
	*result = supervisor->next_query_id++;
	return true;
}

static resolver_supervisor_assign_status resolver_supervisor_helper_job_assign(resolver_supervisor *supervisor, size_t helper_index, resolver_supervisor_job *job, const struct timespec *now) {
	resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
	uint64_t query_id;
	if (!timeutil_add_seconds(now, RESOLVER_SUPERVISOR_QUERY_TIMEOUT_SEC, &job->deadline)) {
		return RESOLVER_SUPERVISOR_ASSIGN_TIME;
	}
	if (!resolver_supervisor_query_id_allocate(supervisor, &query_id)) {
		return RESOLVER_SUPERVISOR_ASSIGN_LIMIT;
	}
	resolver_ipc_assembly *assembly;
	resolver_ipc_assembly_status assembly_status = resolver_ipc_assembly_create(supervisor->assembly_budget, resolver_cache_entry_name(job->entry), ns_c_in,
		resolver_cache_entry_query_type(job->entry), query_id, &assembly);
	if (assembly_status != RESOLVER_IPC_ASSEMBLY_OK) {
		return RESOLVER_SUPERVISOR_ASSIGN_RETRY;
	}
	resolver_ipc_request request = {
		.query_class = ns_c_in,
		.query_id = query_id,
		.query_type = resolver_cache_entry_query_type(job->entry)
	};
	snprintf(request.query_name, sizeof(request.query_name), "%s", resolver_cache_entry_name(job->entry));
	if (resolver_ipc_request_encode(&request, helper->request_packet, sizeof(helper->request_packet), &helper->request_size) != RESOLVER_IPC_CODEC_OK) {
		resolver_ipc_assembly_destroy(assembly);
		return RESOLVER_SUPERVISOR_ASSIGN_LIMIT;
	}
	job->assembly = assembly;
	job->query_id = query_id;
	job->slot_index = helper_index;
	helper->job = job;
	resolver_supervisor_send_status status = resolver_supervisor_helper_request_send(supervisor, helper_index, now);
	if (status == RESOLVER_SUPERVISOR_SEND_TIME) {
		job->query_id = 0;
		resolver_ipc_assembly_destroy(job->assembly);
		job->assembly = NULL;
		helper->job = NULL;
		helper->request_size = 0;
		helper->state = RESOLVER_SUPERVISOR_HELPER_IDLE;
		resolver_supervisor_helper_events_update(supervisor, helper_index);
		return RESOLVER_SUPERVISOR_ASSIGN_TIME;
	}
	return status == RESOLVER_SUPERVISOR_SEND_OK ? RESOLVER_SUPERVISOR_ASSIGN_OK : RESOLVER_SUPERVISOR_ASSIGN_IO;
}

static void resolver_supervisor_dispatch(resolver_supervisor *supervisor, const struct timespec *now) {
	if (supervisor->shutting_down) {
		return;
	}
	for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT && resolver_supervisor_job_queue_first(supervisor) != NULL; helper_index++) {
		resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
		if (helper->state != RESOLVER_SUPERVISOR_HELPER_IDLE) {
			continue;
		}
		while (helper->state == RESOLVER_SUPERVISOR_HELPER_IDLE && resolver_supervisor_job_queue_first(supervisor) != NULL) {
			resolver_supervisor_job *job = resolver_supervisor_job_queue_first(supervisor);
			resolver_supervisor_job_queue_remove(supervisor, job);
			resolver_supervisor_assign_status status = resolver_supervisor_helper_job_assign(supervisor, helper_index, job, now);
			if (status == RESOLVER_SUPERVISOR_ASSIGN_OK) {
				break;
			}
			if (status == RESOLVER_SUPERVISOR_ASSIGN_RETRY) {
				resolver_supervisor_job_retry(supervisor, job, now);
				continue;
			}
			if (status == RESOLVER_SUPERVISOR_ASSIGN_LIMIT) {
				resolver_ipc_assembly_result response = {
					.query_type = resolver_cache_entry_query_type(job->entry),
					.status = RESOLVER_IPC_LOOKUP_LIMIT
				};
				resolver_supervisor_job_complete(supervisor, job, RESOLVER_CACHE_PUBLISH_LIMIT, &response);
				continue;
			}
			if (status == RESOLVER_SUPERVISOR_ASSIGN_TIME) {
				resolver_ipc_assembly_result response = {
					.query_type = resolver_cache_entry_query_type(job->entry),
					.status = RESOLVER_IPC_LOOKUP_PERMANENT_ERROR
				};
				resolver_supervisor_job_complete(supervisor, job, RESOLVER_CACHE_PUBLISH_TIME, &response);
				continue;
			}
			resolver_supervisor_helper_fail(supervisor, helper_index, RESOLVER_SUPERVISOR_HELPER_FAILURE_IO, now);
		}
	}
}

static resolver_cache_publish_status resolver_supervisor_result_publish(resolver_supervisor_job *job, resolver_ipc_assembly_result *response) {
	if (response->query_type == ns_t_srv) {
		dns_srv_lookup_status lookup_status;
		if (!resolver_ipc_lookup_status_to_srv(response->status, &lookup_status)) {
			return RESOLVER_CACHE_PUBLISH_INVALID;
		}
		return resolver_cache_entry_publish_srv(job->entry, lookup_status, &response->completed_at, &response->payload.srv);
	}
	dns_address_lookup_status lookup_status;
	if (!resolver_ipc_lookup_status_to_address(response->status, &lookup_status)) {
		return RESOLVER_CACHE_PUBLISH_INVALID;
	}
	return resolver_cache_entry_publish_address(job->entry, lookup_status, &response->completed_at, &response->payload.address);
}

static void resolver_supervisor_helper_result_finish(resolver_supervisor *supervisor, size_t helper_index, const struct timespec *now) {
	resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
	resolver_supervisor_job *job = helper->job;
	resolver_ipc_assembly_result response = { 0 };
	if (job == NULL || !resolver_ipc_assembly_result_take(job->assembly, &response)) {
		resolver_supervisor_helper_fail(supervisor, helper_index, RESOLVER_SUPERVISOR_HELPER_FAILURE_PROTOCOL, now);
		return;
	}
	job->query_id = 0;
	resolver_ipc_assembly_destroy(job->assembly);
	job->assembly = NULL;
	if (!resolver_supervisor_job_timestamp_valid(job, &response.completed_at, now)) {
		bool timed_out = timeutil_valid(&response.completed_at) && timeutil_compare(&response.completed_at, &job->deadline) > 0;
		resolver_ipc_assembly_result_destroy(&response);
		resolver_supervisor_helper_fail(supervisor, helper_index, timed_out ? RESOLVER_SUPERVISOR_HELPER_FAILURE_TIMEOUT : RESOLVER_SUPERVISOR_HELPER_FAILURE_PROTOCOL, now);
		return;
	}
	helper->job = NULL;
	helper->state = RESOLVER_SUPERVISOR_HELPER_IDLE;
	resolver_supervisor_helper_success(helper);
	if (job->cancelled) {
		/* Explicit cancellation wins when a test-only cancel races with zero-interest orphaning. */
		resolver_ipc_assembly_result_destroy(&response);
		resolver_supervisor_job_destroy(supervisor, job);
		return;
	}
	if (resolver_supervisor_job_result_retryable(response.status)) {
		resolver_ipc_assembly_result_destroy(&response);
		resolver_supervisor_job_retry(supervisor, job, now);
		return;
	}
	resolver_cache_publish_status publication = RESOLVER_CACHE_PUBLISH_INVALID;
	if (response.status == RESOLVER_IPC_LOOKUP_OK || response.status == RESOLVER_IPC_LOOKUP_NODATA || response.status == RESOLVER_IPC_LOOKUP_NOT_FOUND) {
		publication = resolver_supervisor_result_publish(job, &response);
	}
	if (job->orphaned) {
		resolver_ipc_assembly_result_destroy(&response);
		resolver_supervisor_job_destroy(supervisor, job);
		return;
	}
	resolver_supervisor_job_complete(supervisor, job, publication, &response);
}

static bool resolver_supervisor_helper_receive_zero_is_end(int socket_fd) {
	uint8_t marker;
	ssize_t received;
	do {
		received = recv(socket_fd, &marker, sizeof(marker), MSG_DONTWAIT | MSG_PEEK);
	} while (received == -1 && errno == EINTR);
	return received == 0;
}

static void resolver_supervisor_helper_drain(resolver_supervisor *supervisor, size_t helper_index, const struct timespec *now) {
	resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
	while (helper->fd != -1) {
		uint8_t packet[RESOLVER_SUPERVISOR_RECEIVE_BYTE_CAPACITY];
		ssize_t received = recv(helper->fd, packet, sizeof(packet), MSG_DONTWAIT);
		if (received > 0) {
			if (helper->state == RESOLVER_SUPERVISOR_HELPER_SHUTTING_DOWN) {
				continue;
			}
			if ((uintmax_t)received > RESOLVER_IPC_PACKET_BYTE_LIMIT || helper->state != RESOLVER_SUPERVISOR_HELPER_BUSY || helper->job == NULL) {
				resolver_supervisor_helper_fail(supervisor, helper_index, RESOLVER_SUPERVISOR_HELPER_FAILURE_PROTOCOL, now);
				return;
			}
			resolver_ipc_assembly_status status = resolver_ipc_assembly_packet_consume(helper->job->assembly, packet, (size_t)received);
			if (status == RESOLVER_IPC_ASSEMBLY_COMPLETE) {
				resolver_supervisor_helper_result_finish(supervisor, helper_index, now);
			} else if (status != RESOLVER_IPC_ASSEMBLY_OK) {
				resolver_supervisor_helper_fail(supervisor, helper_index, RESOLVER_SUPERVISOR_HELPER_FAILURE_PROTOCOL, now);
				return;
			}
			continue;
		}
		if (received == 0) {
			if (helper->state == RESOLVER_SUPERVISOR_HELPER_SHUTTING_DOWN && resolver_supervisor_helper_receive_zero_is_end(helper->fd)) {
				resolver_supervisor_helper_stop(supervisor, helper, false);
				return;
			}
			resolver_supervisor_helper_failure failure = resolver_supervisor_helper_receive_zero_is_end(helper->fd) ? RESOLVER_SUPERVISOR_HELPER_FAILURE_EXIT
				: RESOLVER_SUPERVISOR_HELPER_FAILURE_PROTOCOL;
			resolver_supervisor_helper_fail(supervisor, helper_index, failure, now);
			return;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		resolver_supervisor_helper_fail(supervisor, helper_index, RESOLVER_SUPERVISOR_HELPER_FAILURE_IO, now);
		return;
	}
}

static void resolver_supervisor_timer_candidate(struct timespec *target, bool *available, const struct timespec *candidate) {
	if (!timeutil_valid(candidate)) {
		return;
	}
	if (!*available || timeutil_compare(candidate, target) < 0) {
		*target = *candidate;
		*available = true;
	}
}

static int resolver_supervisor_timer_rearm(resolver_supervisor *supervisor) {
	bool available = false;
	struct timespec target = { 0 };
	for (size_t bucket = 0; bucket < RESOLVER_SUPERVISOR_JOB_LIMIT; bucket++) {
		for (resolver_supervisor_job *job = supervisor->buckets[bucket]; job != NULL; job = job->hash_next) {
			if (job->state == RESOLVER_SUPERVISOR_JOB_DISPATCHED) {
				resolver_supervisor_timer_candidate(&target, &available, &job->deadline);
			} else if (job->state == RESOLVER_SUPERVISOR_JOB_RETRY_WAIT) {
				resolver_supervisor_timer_candidate(&target, &available, &job->retry_at);
			}
		}
	}
	for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
		resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
		if (helper->state == RESOLVER_SUPERVISOR_HELPER_BACKOFF || helper->state == RESOLVER_SUPERVISOR_HELPER_SHUTTING_DOWN || (helper->failure_count > 0
			&& (helper->state == RESOLVER_SUPERVISOR_HELPER_IDLE || helper->state == RESOLVER_SUPERVISOR_HELPER_SENDING || helper->state == RESOLVER_SUPERVISOR_HELPER_BUSY))) {
			resolver_supervisor_timer_candidate(&target, &available, &helper->next_event_at);
		}
	}
	struct itimerspec timer;
	memset(&timer, 0, sizeof(timer));
	if (available) {
		timer.it_value = target;
		if (timer.it_value.tv_sec == 0 && timer.it_value.tv_nsec == 0) {
			timer.it_value.tv_nsec = 1;
		}
	}
	return timerfd_settime(supervisor->timer_fd, TFD_TIMER_ABSTIME, &timer, NULL);
}

static int resolver_supervisor_timer_drain(int timer_fd) {
	while (true) {
		uint64_t expirations;
		ssize_t bytes = read(timer_fd, &expirations, sizeof(expirations));
		if (bytes == (ssize_t)sizeof(expirations)) {
			continue;
		}
		if (bytes == -1 && errno == EINTR) {
			continue;
		}
		if (bytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return 0;
		}
		errno = EIO;
		return -1;
	}
}

static void resolver_supervisor_timers_process_jobs(resolver_supervisor *supervisor, const struct timespec *now) {
	for (size_t bucket = 0; bucket < RESOLVER_SUPERVISOR_JOB_LIMIT; bucket++) {
		resolver_supervisor_job *job = supervisor->buckets[bucket];
		while (job != NULL) {
			resolver_supervisor_job *next = job->hash_next;
			if (job->state == RESOLVER_SUPERVISOR_JOB_RETRY_WAIT && timeutil_compare(now, &job->retry_at) >= 0) {
				resolver_supervisor_job_queue_append(supervisor, job);
			}
			job = next;
		}
	}
}

static void resolver_supervisor_timers_process_helpers(resolver_supervisor *supervisor, const struct timespec *now) {
	for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
		resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
		if (helper->state == RESOLVER_SUPERVISOR_HELPER_BUSY && helper->job != NULL && timeutil_compare(now, &helper->job->deadline) >= 0) {
			resolver_supervisor_helper_drain(supervisor, helper_index, now);
			if (helper->state == RESOLVER_SUPERVISOR_HELPER_BUSY && helper->job != NULL) {
				resolver_supervisor_helper_fail(supervisor, helper_index, RESOLVER_SUPERVISOR_HELPER_FAILURE_TIMEOUT, now);
			}
		}
		helper = &supervisor->helpers[helper_index];
		if (helper->failure_count > 0 && (helper->state == RESOLVER_SUPERVISOR_HELPER_IDLE || helper->state == RESOLVER_SUPERVISOR_HELPER_SENDING
			|| helper->state == RESOLVER_SUPERVISOR_HELPER_BUSY) && timeutil_compare(now, &helper->next_event_at) >= 0) {
			resolver_supervisor_helper_recovery_reset(helper);
		}
		helper = &supervisor->helpers[helper_index];
		if (helper->state == RESOLVER_SUPERVISOR_HELPER_BACKOFF && timeutil_compare(now, &helper->next_event_at) >= 0) {
			resolver_supervisor_helper_spawn(supervisor, helper_index, now);
		} else if (helper->state == RESOLVER_SUPERVISOR_HELPER_SHUTTING_DOWN && timeutil_compare(now, &helper->next_event_at) >= 0) {
			resolver_supervisor_helper_stop(supervisor, helper, true);
		}
	}
}

static void resolver_supervisor_jobs_destroy_all(resolver_supervisor *supervisor) {
	if (supervisor->buckets == NULL) {
		return;
	}
	for (size_t bucket = 0; bucket < RESOLVER_SUPERVISOR_JOB_LIMIT; bucket++) {
		while (supervisor->buckets[bucket] != NULL) {
			resolver_supervisor_job *job = supervisor->buckets[bucket];
			if (job->state == RESOLVER_SUPERVISOR_JOB_SENDING || job->state == RESOLVER_SUPERVISOR_JOB_DISPATCHED) {
				job->query_id = 0;
				resolver_ipc_assembly_destroy(job->assembly);
				job->assembly = NULL;
				if (job->slot_index < RESOLVER_SUPERVISOR_HELPER_COUNT && supervisor->helpers[job->slot_index].job == job) {
					supervisor->helpers[job->slot_index].job = NULL;
					supervisor->helpers[job->slot_index].request_size = 0;
				}
			}
			resolver_supervisor_job_destroy(supervisor, job);
		}
	}
}

static void resolver_supervisor_resources_destroy(resolver_supervisor *supervisor, bool terminate_processes) {
	if (supervisor == NULL) {
		return;
	}
	resolver_supervisor_jobs_destroy_all(supervisor);
	if (supervisor->helpers != NULL) {
		for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
			if (terminate_processes) {
				resolver_supervisor_helper_process_close(supervisor, &supervisor->helpers[helper_index], SIGKILL);
			} else if (supervisor->helpers[helper_index].fd != -1) {
				close(supervisor->helpers[helper_index].fd);
				supervisor->helpers[helper_index].fd = -1;
				supervisor->helpers[helper_index].process_id = -1;
			}
		}
	}
	if (supervisor->timer_fd != -1) {
		close(supervisor->timer_fd);
	}
	if (supervisor->epoll_fd != -1) {
		close(supervisor->epoll_fd);
	}
	resolver_ipc_assembly_budget_destroy(supervisor->assembly_budget);
	free(supervisor->buckets);
	free(supervisor->helpers);
	free(supervisor);
}

static resolver_supervisor_release_status resolver_supervisor_entry_release(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now,
	resolver_supervisor_priority priority) {
	if (supervisor == NULL || entry == NULL || now == NULL || supervisor->shutting_down
		|| (priority != RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND && priority != RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE)) {
		return RESOLVER_SUPERVISOR_RELEASE_BAD_ARGUMENT;
	}
	if (!resolver_supervisor_time_update(supervisor, now)) {
		return RESOLVER_SUPERVISOR_RELEASE_TIME;
	}
	resolver_supervisor_job *job = resolver_supervisor_job_find(supervisor, entry);
	if (job == NULL || job->state == RESOLVER_SUPERVISOR_JOB_COMPLETE) {
		return RESOLVER_SUPERVISOR_RELEASE_SATISFIED;
	}
	size_t *interest_count = priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE ? &job->interactive_interest_count : &job->background_interest_count;
	if (*interest_count == 0) {
		return RESOLVER_SUPERVISOR_RELEASE_BAD_ARGUMENT;
	}
	if (job->state != RESOLVER_SUPERVISOR_JOB_QUEUED && job->state != RESOLVER_SUPERVISOR_JOB_RETRY_WAIT
		&& job->state != RESOLVER_SUPERVISOR_JOB_SENDING && job->state != RESOLVER_SUPERVISOR_JOB_DISPATCHED) {
		return RESOLVER_SUPERVISOR_RELEASE_BAD_ARGUMENT;
	}
	resolver_supervisor_helper *sending_helper = NULL;
	if (job->state == RESOLVER_SUPERVISOR_JOB_SENDING) {
		if (job->slot_index >= RESOLVER_SUPERVISOR_HELPER_COUNT || supervisor->helpers[job->slot_index].job != job) {
			return RESOLVER_SUPERVISOR_RELEASE_BAD_ARGUMENT;
		}
		sending_helper = &supervisor->helpers[job->slot_index];
	}
	(*interest_count)--;
	bool events_updated = true;
	if (job->background_interest_count == 0 && job->interactive_interest_count == 0) {
		if (job->state == RESOLVER_SUPERVISOR_JOB_DISPATCHED) {
			job->orphaned = true;
			resolver_supervisor_job_priority_downgrade(supervisor, job);
		} else {
			if (sending_helper != NULL) {
				sending_helper->job = NULL;
				sending_helper->request_size = 0;
				sending_helper->state = RESOLVER_SUPERVISOR_HELPER_IDLE;
				events_updated = resolver_supervisor_helper_events_update(supervisor, job->slot_index) == 0;
				job->query_id = 0;
			}
			resolver_supervisor_job_destroy(supervisor, job);
		}
	} else {
		resolver_supervisor_job_priority_downgrade(supervisor, job);
	}
	resolver_supervisor_dispatch(supervisor, now);
	bool timer_updated = resolver_supervisor_timer_rearm(supervisor) == 0;
	return events_updated && timer_updated ? RESOLVER_SUPERVISOR_RELEASE_OK : RESOLVER_SUPERVISOR_RELEASE_IO;
}

static resolver_supervisor_schedule_status resolver_supervisor_entry_schedule_priority(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now,
	resolver_supervisor_priority priority) {
	if (supervisor == NULL || entry == NULL || now == NULL || supervisor->shutting_down
		|| (priority != RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND && priority != RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE)) {
		return RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT;
	}
	if (!resolver_supervisor_time_update(supervisor, now)) {
		return RESOLVER_SUPERVISOR_SCHEDULE_TIME;
	}
	resolver_cache_view cache_view;
	if (!resolver_cache_entry_view(entry, now, &cache_view)) {
		return RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT;
	}
	if (cache_view.status != RESOLVER_CACHE_VIEW_EMPTY) {
		return RESOLVER_SUPERVISOR_SCHEDULE_FRESH;
	}
	resolver_supervisor_job *existing = resolver_supervisor_job_find(supervisor, entry);
	if (existing != NULL) {
		if (existing->state == RESOLVER_SUPERVISOR_JOB_COMPLETE) {
			return RESOLVER_SUPERVISOR_SCHEDULE_COMPLETE;
		}
		size_t *interest_count = priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE ? &existing->interactive_interest_count : &existing->background_interest_count;
		if (*interest_count >= RESOLVER_SUPERVISOR_INTEREST_COUNT_LIMIT) {
			return RESOLVER_SUPERVISOR_SCHEDULE_LIMIT;
		}
		(*interest_count)++;
		existing->cancelled = false;
		existing->orphaned = false;
		if (priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE) {
			resolver_supervisor_job_priority_promote(supervisor, existing);
		}
		return RESOLVER_SUPERVISOR_SCHEDULE_COALESCED;
	}
	size_t admission_limit = priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE ? (size_t)RESOLVER_SUPERVISOR_JOB_LIMIT
		: (size_t)(RESOLVER_SUPERVISOR_JOB_LIMIT - RESOLVER_SUPERVISOR_INTERACTIVE_RESERVE);
	if (supervisor->job_count >= admission_limit) {
		return RESOLVER_SUPERVISOR_SCHEDULE_LIMIT;
	}
	resolver_supervisor_job *job = calloc(1, sizeof(*job));
	if (job == NULL) {
		return RESOLVER_SUPERVISOR_SCHEDULE_MEMORY;
	}
	if (!resolver_cache_entry_retain(entry)) {
		free(job);
		return RESOLVER_SUPERVISOR_SCHEDULE_LIMIT;
	}
	job->entry = entry;
	job->background_interest_count = priority == RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND ? 1U : 0U;
	job->interactive_interest_count = priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE ? 1U : 0U;
	job->priority = priority;
	job->slot_index = SIZE_MAX;
	size_t bucket = resolver_supervisor_job_bucket(entry);
	job->hash_next = supervisor->buckets[bucket];
	supervisor->buckets[bucket] = job;
	supervisor->job_count++;
	resolver_supervisor_job_queue_append(supervisor, job);
	resolver_supervisor_dispatch(supervisor, now);
	if (resolver_supervisor_timer_rearm(supervisor) == -1) {
		return RESOLVER_SUPERVISOR_SCHEDULE_IO;
	}
	return RESOLVER_SUPERVISOR_SCHEDULE_STARTED;
}

/* section: functions (exported) */
void resolver_supervisor_completion_destroy(resolver_supervisor_completion *completion) {
	if (completion == NULL) {
		return;
	}
	resolver_cache_entry_release(completion->entry);
	resolver_ipc_assembly_result_destroy(&completion->response);
	memset(completion, 0, sizeof(*completion));
}

bool resolver_supervisor_completion_take(resolver_supervisor *supervisor, resolver_supervisor_completion *completion) {
	if (supervisor == NULL || !resolver_supervisor_completion_empty(completion) || supervisor->completion_head == NULL) {
		return false;
	}
	resolver_supervisor_job *job = supervisor->completion_head;
	resolver_supervisor_job_completion_remove(supervisor, job);
	resolver_supervisor_job_hash_remove(supervisor, job);
	completion->entry = job->entry;
	completion->publication = job->publication;
	completion->response = job->response;
	job->entry = NULL;
	memset(&job->response, 0, sizeof(job->response));
	if (supervisor->job_count > 0) {
		supervisor->job_count--;
	}
	free(job);
	return true;
}

resolver_supervisor *resolver_supervisor_create(const sigset_t *helper_signal_mask, const struct timespec *now) {
	if (helper_signal_mask == NULL || !timeutil_valid(now) || RESOLVER_SUPERVISOR_HELPER_COUNT == 0 || RESOLVER_SUPERVISOR_JOB_LIMIT == 0
		|| RESOLVER_SUPERVISOR_INTERACTIVE_RESERVE > RESOLVER_SUPERVISOR_JOB_LIMIT || RESOLVER_SUPERVISOR_INTEREST_COUNT_LIMIT == 0
		|| RESOLVER_SUPERVISOR_HELPER_COUNT > INT_MAX - 1 || RESOLVER_SUPERVISOR_JITTER_PERCENT > 100 || RESOLVER_SUPERVISOR_QUERY_RETRY_INITIAL_MS == 0
		|| RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS < RESOLVER_SUPERVISOR_QUERY_RETRY_INITIAL_MS || RESOLVER_SUPERVISOR_QUERY_TIMEOUT_SEC == 0
		|| RESOLVER_SUPERVISOR_RESPAWN_INITIAL_MS == 0 || RESOLVER_SUPERVISOR_RESPAWN_MAX_MS < RESOLVER_SUPERVISOR_RESPAWN_INITIAL_MS
		|| RESOLVER_SUPERVISOR_RESPAWN_RESET_STABLE_SEC == 0 || RESOLVER_SUPERVISOR_RESPAWN_RESET_SUCCESS_COUNT == 0 || RESOLVER_SUPERVISOR_SHUTDOWN_GRACE_MS == 0) {
		errno = EINVAL;
		return NULL;
	}
	resolver_supervisor *supervisor = calloc(1, sizeof(*supervisor));
	if (supervisor == NULL) {
		return NULL;
	}
	supervisor->epoll_fd = -1;
	supervisor->timer_fd = -1;
	supervisor->next_query_id = 1;
	supervisor->last_now = *now;
	supervisor->helper_signal_mask = *helper_signal_mask;
	if ((size_t)RESOLVER_SUPERVISOR_JOB_LIMIT > SIZE_MAX / sizeof(*supervisor->buckets)
		|| (size_t)RESOLVER_SUPERVISOR_HELPER_COUNT > SIZE_MAX / sizeof(*supervisor->helpers)) {
		errno = EOVERFLOW;
		goto fail;
	}
	supervisor->assembly_budget = resolver_ipc_assembly_budget_create();
	supervisor->buckets = calloc(RESOLVER_SUPERVISOR_JOB_LIMIT, sizeof(*supervisor->buckets));
	supervisor->helpers = calloc(RESOLVER_SUPERVISOR_HELPER_COUNT, sizeof(*supervisor->helpers));
	supervisor->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	supervisor->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (supervisor->helpers != NULL) {
		for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
			supervisor->helpers[helper_index].fd = -1;
			supervisor->helpers[helper_index].last_failed_process_id = -1;
			supervisor->helpers[helper_index].process_id = -1;
			supervisor->helpers[helper_index].state = RESOLVER_SUPERVISOR_HELPER_STOPPED;
		}
	}
	if (supervisor->assembly_budget == NULL || supervisor->buckets == NULL || supervisor->helpers == NULL || supervisor->epoll_fd == -1 || supervisor->timer_fd == -1) {
		goto fail;
	}
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.u32 = RESOLVER_SUPERVISOR_EVENT_TIMER;
	if (epoll_ctl(supervisor->epoll_fd, EPOLL_CTL_ADD, supervisor->timer_fd, &event) == -1) {
		goto fail;
	}
	for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
		resolver_supervisor_helper_spawn(supervisor, helper_index, now);
	}
	if (resolver_supervisor_timer_rearm(supervisor) == -1) {
		goto fail;
	}
	return supervisor;
fail: {
	int saved_errno = errno;
	resolver_supervisor_destroy(supervisor);
	errno = saved_errno;
	return NULL;
}
}

void resolver_supervisor_destroy(resolver_supervisor *supervisor) {
	resolver_supervisor_resources_destroy(supervisor, true);
}

void resolver_supervisor_dispose_in_child(resolver_supervisor *supervisor) {
	resolver_supervisor_resources_destroy(supervisor, false);
}

resolver_supervisor_release_status resolver_supervisor_entry_background_release(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now) {
	return resolver_supervisor_entry_release(supervisor, entry, now, RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND);
}

bool resolver_supervisor_entry_cancel(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now) {
	if (!resolver_supervisor_time_update(supervisor, now)) {
		return false;
	}
	bool events_updated = true;
	resolver_supervisor_job *job = resolver_supervisor_job_find(supervisor, entry);
	if (job == NULL) {
		return false;
	}
	if (job->state == RESOLVER_SUPERVISOR_JOB_DISPATCHED) {
		job->cancelled = true;
		return true;
	}
	if (job->state == RESOLVER_SUPERVISOR_JOB_SENDING && job->slot_index < RESOLVER_SUPERVISOR_HELPER_COUNT) {
		resolver_supervisor_helper *helper = &supervisor->helpers[job->slot_index];
		if (helper->job == job) {
			helper->job = NULL;
			helper->request_size = 0;
			helper->state = RESOLVER_SUPERVISOR_HELPER_IDLE;
			events_updated = resolver_supervisor_helper_events_update(supervisor, job->slot_index) == 0;
		}
		job->query_id = 0;
	}
	resolver_supervisor_job_destroy(supervisor, job);
	resolver_supervisor_dispatch(supervisor, now);
	return events_updated && resolver_supervisor_timer_rearm(supervisor) == 0;
}

resolver_supervisor_release_status resolver_supervisor_entry_interactive_release(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now) {
	return resolver_supervisor_entry_release(supervisor, entry, now, RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE);
}

resolver_supervisor_schedule_status resolver_supervisor_entry_schedule(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now) {
	return resolver_supervisor_entry_schedule_priority(supervisor, entry, now, RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND);
}

resolver_supervisor_schedule_status resolver_supervisor_entry_schedule_interactive(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now) {
	return resolver_supervisor_entry_schedule_priority(supervisor, entry, now, RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE);
}

bool resolver_supervisor_entry_view(const resolver_supervisor *supervisor, const resolver_cache_entry *entry, resolver_supervisor_job_view *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	resolver_supervisor_job *job = resolver_supervisor_job_find(supervisor, entry);
	if (job == NULL || result == NULL) {
		return false;
	}
	result->background_interest_count = job->background_interest_count;
	result->deadline = job->deadline;
	result->dispatched_at = job->dispatched_at;
	result->interactive_interest_count = job->interactive_interest_count;
	result->orphaned = job->orphaned;
	result->priority = job->priority;
	result->query_id = job->query_id;
	result->retry_at = job->retry_at;
	result->retry_count = job->retry_count;
	result->state = job->state;
	return true;
}

int resolver_supervisor_event_fd(const resolver_supervisor *supervisor) {
	return supervisor == NULL ? -1 : supervisor->epoll_fd;
}

resolver_supervisor_event_status resolver_supervisor_events_process(resolver_supervisor *supervisor, const struct timespec *now) {
	if (supervisor == NULL || now == NULL) {
		return RESOLVER_SUPERVISOR_EVENT_BAD_ARGUMENT;
	}
	if (!resolver_supervisor_time_update(supervisor, now)) {
		return RESOLVER_SUPERVISOR_EVENT_TIME;
	}
	struct epoll_event events[RESOLVER_SUPERVISOR_HELPER_COUNT + 1U];
	int event_count;
	do {
		event_count = epoll_wait(supervisor->epoll_fd, events, (int)(RESOLVER_SUPERVISOR_HELPER_COUNT + 1U), 0);
	} while (event_count == -1 && errno == EINTR);
	if (event_count == -1) {
		return RESOLVER_SUPERVISOR_EVENT_IO;
	}
	uint32_t helper_events[RESOLVER_SUPERVISOR_HELPER_COUNT];
	memset(helper_events, 0, sizeof(helper_events));
	bool timer_ready = false;
	for (int event_index = 0; event_index < event_count; event_index++) {
		uint32_t tag = events[event_index].data.u32;
		if (tag == RESOLVER_SUPERVISOR_EVENT_TIMER) {
			timer_ready = true;
		} else if (tag <= RESOLVER_SUPERVISOR_HELPER_COUNT) {
			helper_events[tag - 1U] |= events[event_index].events;
		} else {
			return RESOLVER_SUPERVISOR_EVENT_IO;
		}
	}
	for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
		resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
		if ((helper_events[helper_index] & EPOLLOUT) && helper->state == RESOLVER_SUPERVISOR_HELPER_SENDING) {
			resolver_supervisor_send_status send_status = resolver_supervisor_helper_request_send(supervisor, helper_index, now);
			if (send_status == RESOLVER_SUPERVISOR_SEND_TIME) {
				resolver_supervisor_job *job = helper->job;
				job->query_id = 0;
				resolver_ipc_assembly_destroy(job->assembly);
				job->assembly = NULL;
				helper->job = NULL;
				helper->request_size = 0;
				helper->state = RESOLVER_SUPERVISOR_HELPER_IDLE;
				resolver_supervisor_helper_events_update(supervisor, helper_index);
				resolver_ipc_assembly_result response = {
					.query_type = resolver_cache_entry_query_type(job->entry),
					.status = RESOLVER_IPC_LOOKUP_PERMANENT_ERROR
				};
				resolver_supervisor_job_complete(supervisor, job, RESOLVER_CACHE_PUBLISH_TIME, &response);
			} else if (send_status == RESOLVER_SUPERVISOR_SEND_IO) {
				resolver_supervisor_helper_fail(supervisor, helper_index, RESOLVER_SUPERVISOR_HELPER_FAILURE_IO, now);
			}
		}
		if ((helper_events[helper_index] & EPOLLIN) && helper->fd != -1) {
			resolver_supervisor_helper_drain(supervisor, helper_index, now);
		}
		if ((helper_events[helper_index] & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) && supervisor->helpers[helper_index].fd != -1) {
			resolver_supervisor_helper_drain(supervisor, helper_index, now);
			if (supervisor->helpers[helper_index].fd != -1) {
				if (supervisor->helpers[helper_index].state == RESOLVER_SUPERVISOR_HELPER_SHUTTING_DOWN) {
					resolver_supervisor_helper_stop(supervisor, &supervisor->helpers[helper_index], false);
				} else {
					resolver_supervisor_helper_fail(supervisor, helper_index, RESOLVER_SUPERVISOR_HELPER_FAILURE_EXIT, now);
				}
			}
		}
	}
	if (timer_ready && resolver_supervisor_timer_drain(supervisor->timer_fd) == -1) {
		return RESOLVER_SUPERVISOR_EVENT_IO;
	}
	resolver_supervisor_timers_process_helpers(supervisor, now);
	resolver_supervisor_timers_process_jobs(supervisor, now);
	resolver_supervisor_dispatch(supervisor, now);
	return resolver_supervisor_timer_rearm(supervisor) == -1 ? RESOLVER_SUPERVISOR_EVENT_IO : RESOLVER_SUPERVISOR_EVENT_OK;
}

size_t resolver_supervisor_helper_count(const resolver_supervisor *supervisor) {
	return supervisor == NULL ? 0 : RESOLVER_SUPERVISOR_HELPER_COUNT;
}

bool resolver_supervisor_helper_view_get(const resolver_supervisor *supervisor, size_t helper_index, resolver_supervisor_helper_view *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (supervisor == NULL || helper_index >= RESOLVER_SUPERVISOR_HELPER_COUNT || result == NULL) {
		return false;
	}
	const resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
	result->consecutive_successes = helper->consecutive_successes;
	result->failure_count = helper->failure_count;
	result->fd = helper->fd;
	result->last_failed_process_id = helper->last_failed_process_id;
	result->last_failure = helper->last_failure;
	result->next_event_at = helper->next_event_at;
	result->process_id = helper->process_id;
	result->state = helper->state;
	return true;
}

size_t resolver_supervisor_job_count(const resolver_supervisor *supervisor) {
	return supervisor == NULL ? 0 : supervisor->job_count;
}

bool resolver_supervisor_shutdown(resolver_supervisor *supervisor, const struct timespec *now) {
	if (!resolver_supervisor_time_update(supervisor, now)) {
		return false;
	}
	if (supervisor->shutting_down) {
		return true;
	}
	supervisor->shutting_down = true;
	resolver_supervisor_jobs_destroy_all(supervisor);
	for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
		resolver_supervisor_helper *helper = &supervisor->helpers[helper_index];
		if (helper->fd == -1 || helper->process_id <= 0) {
			helper->state = RESOLVER_SUPERVISOR_HELPER_STOPPED;
			continue;
		}
		resolver_supervisor_process_terminate(helper->process_id, SIGTERM);
		helper->state = RESOLVER_SUPERVISOR_HELPER_SHUTTING_DOWN;
		if (!timeutil_add_milliseconds(now, RESOLVER_SUPERVISOR_SHUTDOWN_GRACE_MS, &helper->next_event_at)) {
			helper->next_event_at = *now;
		}
	}
	return resolver_supervisor_timer_rearm(supervisor) == 0;
}

bool resolver_supervisor_shutdown_complete(const resolver_supervisor *supervisor) {
	if (supervisor == NULL || !supervisor->shutting_down) {
		return false;
	}
	for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
		if (supervisor->helpers[helper_index].state != RESOLVER_SUPERVISOR_HELPER_STOPPED) {
			return false;
		}
	}
	return true;
}
