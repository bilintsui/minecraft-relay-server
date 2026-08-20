/*
 * resolver_supervisor.c: Tests for resolver helper supervision
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "resolver/cache.h"
#include "resolver/dns.h"
#include "resolver/helper.h"
#include "resolver/ipc.h"
#include "resolver/supervisor.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* fake helper */
#define SUPERVISOR_TEST_HELPER_LIMIT	64
#define SUPERVISOR_TEST_JITTER_QUERY_DOMAIN	UINT8_C(0x51)
#define SUPERVISOR_TEST_PROCESS_BASE	10000

/* hash */
#define SUPERVISOR_TEST_FNV_OFFSET	UINT64_C(14695981039346656037)
#define SUPERVISOR_TEST_FNV_PRIME	UINT64_C(1099511628211)

/* section: types */
typedef struct {
	bool active;
	bool close_on_sigterm;
	int last_signal;
	int peer_fd;
	pid_t process_id;
	size_t wait_count;
} supervisor_test_helper;

/* section: global variables */
static supervisor_test_helper supervisor_helpers[SUPERVISOR_TEST_HELPER_LIMIT];
static size_t supervisor_helper_count;
static size_t supervisor_start_failures;
static bool supervisor_use_real_helper;

int __real_kill(pid_t process_id, int signal_number);
int __real_resolver_helper_process_start(const sigset_t *signal_mask, pid_t *process_id, int *socket_fd);
pid_t __real_waitpid(pid_t process_id, int *status, int options);

/* section: functions (local) */
static resolver_cache_entry *supervisor_cache_entry_create(resolver_cache *cache, const char *name, uint16_t query_type) {
	resolver_cache_entry *entry = NULL;
	return resolver_cache_entry_acquire(cache, name, query_type, &entry) == RESOLVER_CACHE_ACQUIRE_OK ? entry : NULL;
}

static void supervisor_completion_clear(resolver_supervisor_completion *completion) {
	resolver_supervisor_completion_destroy(completion);
}

static supervisor_test_helper *supervisor_fake_find(pid_t process_id) {
	for (size_t index = 0; index < supervisor_helper_count; index++) {
		if (supervisor_helpers[index].process_id == process_id) {
			return &supervisor_helpers[index];
		}
	}
	return NULL;
}

static int supervisor_fake_peer(const resolver_supervisor *supervisor, size_t helper_index) {
	resolver_supervisor_helper_view view;
	if (!resolver_supervisor_helper_view_get(supervisor, helper_index, &view)) {
		return -1;
	}
	supervisor_test_helper *helper = supervisor_fake_find(view.process_id);
	return helper == NULL ? -1 : helper->peer_fd;
}

static void supervisor_fake_reset(void) {
	for (size_t index = 0; index < supervisor_helper_count; index++) {
		if (supervisor_helpers[index].peer_fd != -1) {
			close(supervisor_helpers[index].peer_fd);
		}
	}
	memset(supervisor_helpers, 0, sizeof(supervisor_helpers));
	for (size_t index = 0; index < SUPERVISOR_TEST_HELPER_LIMIT; index++) {
		supervisor_helpers[index].peer_fd = -1;
	}
	supervisor_helper_count = 0;
	supervisor_start_failures = 0;
	supervisor_use_real_helper = false;
}

static uint64_t supervisor_hash_byte(uint64_t hash, uint8_t value) {
	return (hash ^ value) * SUPERVISOR_TEST_FNV_PRIME;
}

static uint64_t supervisor_hash_u64(uint64_t hash, uint64_t value) {
	for (unsigned int shift = 56; ; shift -= 8) {
		hash = supervisor_hash_byte(hash, (uint8_t)(value >> shift));
		if (shift == 0) {
			return hash;
		}
	}
}

static bool supervisor_packet_send(int socket_fd, const void *packet, size_t packet_size) {
	ssize_t sent;
	do {
		sent = send(socket_fd, packet, packet_size, MSG_NOSIGNAL);
	} while (sent == -1 && errno == EINTR);
	return sent == (ssize_t)packet_size;
}

static bool supervisor_request_receive(int socket_fd, resolver_ipc_request *request) {
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	ssize_t received;
	do {
		received = recv(socket_fd, packet, sizeof(packet), 0);
	} while (received == -1 && errno == EINTR);
	return received > 0 && resolver_ipc_request_decode(packet, (size_t)received, request) == RESOLVER_IPC_CODEC_OK;
}

static bool supervisor_response_address_send(int socket_fd, const resolver_ipc_request *request, const struct timespec *completed_at, uint32_t ttl) {
	resolver_ipc_response_begin begin = {
		.completed_at = *completed_at,
		.query_class = request->query_class,
		.query_id = request->query_id,
		.query_type = request->query_type,
		.rcode = ns_r_noerror,
		.record_count = 1,
		.status = RESOLVER_IPC_LOOKUP_OK
	};
	snprintf(begin.canonical_name, sizeof(begin.canonical_name), "%s", request->query_name);
	snprintf(begin.question_name, sizeof(begin.question_name), "%s", request->query_name);
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_begin_encode(&begin, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK || !supervisor_packet_send(socket_fd, packet, packet_size)) {
		return false;
	}
	resolver_ipc_response_address address = {
		.index = 0,
		.query_id = request->query_id,
		.record = {
			.address = { .family = request->query_type == ns_t_a ? AF_INET : AF_INET6 },
			.effective_ttl = ttl,
			.record_ttl = ttl
		}
	};
	if (request->query_type == ns_t_a) {
		address.record.address.addr.v4 = htonl(UINT32_C(0xC0000201));
	} else {
		address.record.address.addr.v6[15] = 1;
	}
	if (resolver_ipc_response_address_encode(&address, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK || !supervisor_packet_send(socket_fd, packet, packet_size)) {
		return false;
	}
	resolver_ipc_response_end end = { .query_id = request->query_id, .record_count = 1 };
	return resolver_ipc_response_end_encode(&end, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK && supervisor_packet_send(socket_fd, packet, packet_size);
}

static bool supervisor_response_negative_send(int socket_fd, const resolver_ipc_request *request, const struct timespec *completed_at) {
	resolver_ipc_response_begin begin = {
		.canonical_name = "negative.supervisor.test",
		.completed_at = *completed_at,
		.negative = {
			.effective_ttl = 15,
			.minimum = 15,
			.owner = "supervisor.test",
			.record_ttl = 30,
			.valid = true
		},
		.question_name = "negative.supervisor.test",
		.query_class = request->query_class,
		.query_id = request->query_id,
		.query_type = request->query_type,
		.rcode = ns_r_noerror,
		.status = RESOLVER_IPC_LOOKUP_NODATA
	};
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (strcmp(request->query_name, begin.question_name) != 0 || resolver_ipc_response_begin_encode(&begin, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK
		|| !supervisor_packet_send(socket_fd, packet, packet_size)) {
		return false;
	}
	resolver_ipc_response_end end = { .query_id = request->query_id };
	return resolver_ipc_response_end_encode(&end, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK && supervisor_packet_send(socket_fd, packet, packet_size);
}

static bool supervisor_response_srv_send(int socket_fd, const resolver_ipc_request *request, const struct timespec *completed_at, uint32_t ttl) {
	resolver_ipc_response_begin begin = {
		.completed_at = *completed_at,
		.query_class = request->query_class,
		.query_id = request->query_id,
		.query_type = request->query_type,
		.rcode = ns_r_noerror,
		.record_count = 1,
		.status = RESOLVER_IPC_LOOKUP_OK
	};
	snprintf(begin.canonical_name, sizeof(begin.canonical_name), "%s", request->query_name);
	snprintf(begin.question_name, sizeof(begin.question_name), "%s", request->query_name);
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_begin_encode(&begin, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK || !supervisor_packet_send(socket_fd, packet, packet_size)) {
		return false;
	}
	resolver_ipc_response_srv record = {
		.index = 0,
		.query_id = request->query_id,
		.record = {
			.effective_ttl = ttl,
			.port = 25565,
			.priority = 10,
			.record_ttl = ttl,
			.target = "backend.supervisor.test",
			.weight = 20
		}
	};
	if (resolver_ipc_response_srv_encode(&record, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK || !supervisor_packet_send(socket_fd, packet, packet_size)) {
		return false;
	}
	resolver_ipc_response_end end = { .query_id = request->query_id, .record_count = 1 };
	return resolver_ipc_response_end_encode(&end, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK && supervisor_packet_send(socket_fd, packet, packet_size);
}

static bool supervisor_response_temporary_send(int socket_fd, const resolver_ipc_request *request, const struct timespec *completed_at) {
	resolver_ipc_response_begin begin = {
		.completed_at = *completed_at,
		.query_class = request->query_class,
		.query_id = request->query_id,
		.query_type = request->query_type,
		.rcode = ns_r_servfail,
		.status = RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR
	};
	snprintf(begin.question_name, sizeof(begin.question_name), "%s", request->query_name);
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_begin_encode(&begin, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK || !supervisor_packet_send(socket_fd, packet, packet_size)) {
		return false;
	}
	resolver_ipc_response_end end = { .query_id = request->query_id };
	return resolver_ipc_response_end_encode(&end, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK && supervisor_packet_send(socket_fd, packet, packet_size);
}

static uint64_t supervisor_retry_delay_expected(uint64_t entry_id, uint64_t retry_count) {
	uint64_t hash = supervisor_hash_byte(SUPERVISOR_TEST_FNV_OFFSET, SUPERVISOR_TEST_JITTER_QUERY_DOMAIN);
	hash = supervisor_hash_u64(hash, entry_id);
	hash = supervisor_hash_u64(hash, retry_count);
	int percentage = (int)(hash % (uint64_t)(RESOLVER_SUPERVISOR_JITTER_PERCENT * 2 + 1)) - RESOLVER_SUPERVISOR_JITTER_PERCENT;
	uint64_t base = RESOLVER_SUPERVISOR_QUERY_RETRY_INITIAL_MS;
	for (uint64_t index = 1; index < retry_count && base < RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS; index++) {
		base = base > RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS / 2U ? RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS : base * 2U;
	}
	uint64_t delay = base * (uint64_t)(100 + percentage) / 100U;
	return delay < RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS ? delay : RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS;
}

static struct timespec supervisor_time_add(const struct timespec *source, time_t seconds, long nanoseconds) {
	struct timespec result = {
		.tv_sec = source->tv_sec + seconds,
		.tv_nsec = source->tv_nsec + nanoseconds
	};
	while (result.tv_nsec >= 1000000000L) {
		result.tv_sec++;
		result.tv_nsec -= 1000000000L;
	}
	return result;
}

static uint64_t supervisor_time_difference_milliseconds(const struct timespec *later, const struct timespec *earlier) {
	time_t seconds = later->tv_sec - earlier->tv_sec;
	long nanoseconds = later->tv_nsec - earlier->tv_nsec;
	if (nanoseconds < 0) {
		seconds--;
		nanoseconds += 1000000000L;
	}
	return (uint64_t)seconds * 1000U + (uint64_t)nanoseconds / 1000000U;
}

static bool supervisor_test_arguments(void) {
	bool test_result = false;
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	struct timespec now = { .tv_sec = 100 };
	struct timespec invalid_time = { .tv_sec = -1 };
	resolver_supervisor *supervisor = NULL;
	resolver_cache *cache = NULL;
	resolver_cache_entry *entry = NULL;
	resolver_supervisor_completion completion = { 0 };
	supervisor_fake_reset();
	CHECK(resolver_supervisor_create(NULL, &now) == NULL && resolver_supervisor_create(&signal_mask, &invalid_time) == NULL, "invalid supervisor creation arguments were accepted");
	supervisor_start_failures = RESOLVER_SUPERVISOR_HELPER_COUNT;
	supervisor = resolver_supervisor_create(&signal_mask, &now);
	cache = resolver_cache_create();
	entry = supervisor_cache_entry_create(cache, "arguments.supervisor.test", ns_t_a);
	CHECK(supervisor != NULL && cache != NULL && entry != NULL, "argument-test state could not be created");
	CHECK(resolver_supervisor_event_fd(supervisor) >= 0 && resolver_supervisor_helper_count(supervisor) == RESOLVER_SUPERVISOR_HELPER_COUNT
		&& resolver_supervisor_job_count(supervisor) == 0, "supervisor creation state was invalid");
	for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
		resolver_supervisor_helper_view helper_view;
		CHECK(resolver_supervisor_helper_view_get(supervisor, helper_index, &helper_view) && helper_view.state == RESOLVER_SUPERVISOR_HELPER_BACKOFF
			&& helper_view.failure_count == 1, "initial helper-start failure was not retained as degraded state");
	}
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK, "initial helper-start failures were not retried");
	CHECK(resolver_supervisor_entry_schedule(NULL, entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT
		&& resolver_supervisor_entry_schedule(supervisor, NULL, &now) == RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT
		&& resolver_supervisor_entry_schedule_interactive(NULL, entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT
		&& resolver_supervisor_entry_schedule_interactive(supervisor, NULL, &now) == RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT, "invalid schedule arguments were accepted");
	CHECK(!resolver_supervisor_entry_interactive_release(NULL, entry, &now) && !resolver_supervisor_entry_interactive_release(supervisor, NULL, &now),
		"invalid interactive-interest release succeeded");
	CHECK(resolver_supervisor_events_process(supervisor, &invalid_time) == RESOLVER_SUPERVISOR_EVENT_TIME, "invalid event timestamp was accepted");
	CHECK(!resolver_supervisor_completion_take(supervisor, &completion) && !resolver_supervisor_helper_view_get(supervisor, RESOLVER_SUPERVISOR_HELPER_COUNT, &(resolver_supervisor_helper_view){ 0 }),
		"invalid supervisor inspection succeeded");
	test_result = true;

cleanup:
	supervisor_completion_clear(&completion);
	resolver_cache_entry_release(entry);
	resolver_supervisor_destroy(supervisor);
	resolver_cache_destroy(cache);
	supervisor_fake_reset();
	return test_result;
}

static bool supervisor_test_capacity(void) {
	bool test_result = false;
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	struct timespec now = { .tv_sec = 200 };
	resolver_supervisor *supervisor = NULL;
	resolver_cache *cache = NULL;
	resolver_cache_entry *entries[RESOLVER_SUPERVISOR_JOB_LIMIT + 1U];
	size_t background_limit = RESOLVER_SUPERVISOR_JOB_LIMIT - RESOLVER_SUPERVISOR_INTERACTIVE_RESERVE;
	memset(entries, 0, sizeof(entries));
	supervisor_fake_reset();
	supervisor = resolver_supervisor_create(&signal_mask, &now);
	cache = resolver_cache_create();
	CHECK(supervisor != NULL && cache != NULL, "capacity-test state could not be created");
	for (size_t index = 0; index < RESOLVER_SUPERVISOR_JOB_LIMIT + 1U; index++) {
		char name[64];
		snprintf(name, sizeof(name), "capacity-%zu.supervisor.test", index);
		entries[index] = supervisor_cache_entry_create(cache, name, ns_t_a);
		CHECK(entries[index] != NULL, "capacity-test cache entry could not be created");
	}
	for (size_t index = 0; index < background_limit; index++) {
		CHECK(resolver_supervisor_entry_schedule(supervisor, entries[index], &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "capacity-test job could not be scheduled");
	}
	CHECK(resolver_supervisor_job_count(supervisor) == background_limit
		&& resolver_supervisor_entry_schedule(supervisor, entries[0], &now) == RESOLVER_SUPERVISOR_SCHEDULE_COALESCED
		&& resolver_supervisor_entry_schedule(supervisor, entries[background_limit], &now) == RESOLVER_SUPERVISOR_SCHEDULE_LIMIT,
		"background capacity or coalescing was not enforced");
	CHECK(resolver_supervisor_entry_schedule_interactive(supervisor, entries[background_limit], &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED
		&& resolver_supervisor_job_count(supervisor) == RESOLVER_SUPERVISOR_JOB_LIMIT
		&& resolver_supervisor_entry_schedule_interactive(supervisor, entries[RESOLVER_SUPERVISOR_JOB_LIMIT], &now) == RESOLVER_SUPERVISOR_SCHEDULE_LIMIT,
		"interactive reserve was not available above the background boundary");
	resolver_supervisor_job_view job_view;
	CHECK(resolver_supervisor_entry_schedule_interactive(supervisor, entries[0], &now) == RESOLVER_SUPERVISOR_SCHEDULE_COALESCED
		&& resolver_supervisor_entry_view(supervisor, entries[0], &job_view) && job_view.priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE
		&& job_view.interactive_interest_count == 1 && resolver_supervisor_entry_interactive_release(supervisor, entries[0], &now),
		"existing-key interactive coalescing did not bypass admission or release cleanly");
	CHECK(resolver_supervisor_entry_cancel(supervisor, entries[background_limit], &now)
		&& resolver_supervisor_entry_schedule_interactive(supervisor, entries[RESOLVER_SUPERVISOR_JOB_LIMIT], &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED,
		"cancelled interactive capacity was not reusable");
	test_result = true;

cleanup:
	resolver_supervisor_destroy(supervisor);
	for (size_t index = 0; index < RESOLVER_SUPERVISOR_JOB_LIMIT + 1U; index++) {
		resolver_cache_entry_release(entries[index]);
	}
	resolver_cache_destroy(cache);
	supervisor_fake_reset();
	return test_result;
}

static bool supervisor_test_cancel(void) {
	bool test_result = false;
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	struct timespec now = { .tv_sec = 250 };
	resolver_supervisor *supervisor = NULL;
	resolver_cache *cache = NULL;
	resolver_cache_entry *entry = NULL;
	resolver_supervisor_completion completion = { 0 };
	supervisor_fake_reset();
	supervisor = resolver_supervisor_create(&signal_mask, &now);
	cache = resolver_cache_create();
	entry = supervisor_cache_entry_create(cache, "cancel.supervisor.test", ns_t_a);
	CHECK(supervisor != NULL && cache != NULL && entry != NULL, "cancel-test state could not be created");
	CHECK(resolver_supervisor_entry_schedule(supervisor, entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "cancel-test job could not be scheduled");
	resolver_supervisor_job_view job_view;
	CHECK(resolver_supervisor_entry_view(supervisor, entry, &job_view) && job_view.state == RESOLVER_SUPERVISOR_JOB_DISPATCHED
		&& resolver_supervisor_entry_cancel(supervisor, entry, &now), "dispatched job could not be marked cancelled");
	int peer_fd = supervisor_fake_peer(supervisor, 0);
	resolver_ipc_request request;
	CHECK(peer_fd != -1 && supervisor_request_receive(peer_fd, &request), "cancel-test request was not received");
	struct timespec completed_at = supervisor_time_add(&job_view.dispatched_at, 1, 0);
	CHECK(supervisor_response_address_send(peer_fd, &request, &completed_at, 30), "cancel-test response could not be sent");
	now = completed_at;
	resolver_cache_view cache_view;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_job_count(supervisor) == 0
		&& !resolver_supervisor_completion_take(supervisor, &completion) && resolver_cache_entry_view(entry, &now, &cache_view)
		&& cache_view.status == RESOLVER_CACHE_VIEW_EMPTY, "cancelled response was not drained and discarded");
	test_result = true;

cleanup:
	supervisor_completion_clear(&completion);
	resolver_supervisor_destroy(supervisor);
	resolver_cache_entry_release(entry);
	resolver_cache_destroy(cache);
	supervisor_fake_reset();
	return test_result;
}

static bool supervisor_test_child_dispose(void) {
	bool test_result = false;
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	struct timespec now = { .tv_sec = 275 };
	resolver_supervisor *supervisor = NULL;
	resolver_cache *cache = NULL;
	resolver_cache_entry *entry = NULL;
	supervisor_fake_reset();
	resolver_supervisor_dispose_in_child(NULL);
	supervisor = resolver_supervisor_create(&signal_mask, &now);
	cache = resolver_cache_create();
	entry = supervisor_cache_entry_create(cache, "child-dispose.supervisor.test", ns_t_a);
	CHECK(supervisor != NULL && cache != NULL && entry != NULL, "child-disposal test state could not be created");
	CHECK(resolver_supervisor_entry_schedule(supervisor, entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "child-disposal test job could not be scheduled");
	resolver_supervisor_dispose_in_child(supervisor);
	supervisor = NULL;
	for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
		CHECK(supervisor_helpers[helper_index].active && supervisor_helpers[helper_index].last_signal == 0 && supervisor_helpers[helper_index].wait_count == 0,
			"child disposal signalled or reaped a listener-owned helper");
		struct pollfd poll_fd = { .fd = supervisor_helpers[helper_index].peer_fd, .events = POLLIN | POLLHUP };
		CHECK(poll(&poll_fd, 1, 0) == 1 && (poll_fd.revents & POLLHUP) != 0, "child disposal did not close an inherited helper channel");
	}
	test_result = true;

cleanup:
	resolver_supervisor_destroy(supervisor);
	resolver_cache_entry_release(entry);
	resolver_cache_destroy(cache);
	supervisor_fake_reset();
	return test_result;
}

static bool supervisor_test_completion(void) {
	bool test_result = false;
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	struct timespec now = { .tv_sec = 300 };
	resolver_supervisor *supervisor = NULL;
	resolver_cache *cache = NULL;
	resolver_cache_entry *entry = NULL;
	resolver_cache_entry *negative_entry = NULL;
	resolver_cache_entry *srv_entry = NULL;
	resolver_cache_entry *zero_entry = NULL;
	resolver_supervisor_completion completion = { 0 };
	supervisor_fake_reset();
	supervisor = resolver_supervisor_create(&signal_mask, &now);
	cache = resolver_cache_create();
	entry = supervisor_cache_entry_create(cache, "positive.supervisor.test", ns_t_a);
	negative_entry = supervisor_cache_entry_create(cache, "negative.supervisor.test", ns_t_a);
	srv_entry = supervisor_cache_entry_create(cache, "_minecraft._tcp.supervisor.test", ns_t_srv);
	zero_entry = supervisor_cache_entry_create(cache, "zero.supervisor.test", ns_t_a);
	CHECK(supervisor != NULL && cache != NULL && entry != NULL && negative_entry != NULL && srv_entry != NULL && zero_entry != NULL, "completion-test state could not be created");
	CHECK(resolver_supervisor_entry_schedule(supervisor, entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "positive job could not be scheduled");
	resolver_supervisor_job_view job_view;
	CHECK(resolver_supervisor_entry_view(supervisor, entry, &job_view) && job_view.state == RESOLVER_SUPERVISOR_JOB_DISPATCHED, "positive job was not dispatched");
	int peer_fd = supervisor_fake_peer(supervisor, 0);
	resolver_ipc_request request;
	CHECK(peer_fd != -1 && supervisor_request_receive(peer_fd, &request), "positive request was not received");
	struct timespec completed_at = supervisor_time_add(&job_view.dispatched_at, 1, 0);
	CHECK(supervisor_response_address_send(peer_fd, &request, &completed_at, 30), "positive response could not be sent");
	now = completed_at;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK
		&& resolver_supervisor_entry_schedule(supervisor, entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_FRESH, "positive response was not published");
	CHECK(resolver_supervisor_completion_take(supervisor, &completion) && completion.entry == entry && completion.publication == RESOLVER_CACHE_PUBLISH_STORED
		&& completion.response.status == RESOLVER_IPC_LOOKUP_OK, "stored completion was not preserved");
	supervisor_completion_clear(&completion);
	CHECK(resolver_supervisor_entry_schedule(supervisor, negative_entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "negative job could not be scheduled");
	CHECK(resolver_supervisor_entry_view(supervisor, negative_entry, &job_view) && job_view.state == RESOLVER_SUPERVISOR_JOB_DISPATCHED, "negative job was not dispatched");
	peer_fd = supervisor_fake_peer(supervisor, 0);
	CHECK(peer_fd != -1 && supervisor_request_receive(peer_fd, &request), "negative request was not received");
	completed_at = supervisor_time_add(&job_view.dispatched_at, 1, 0);
	CHECK(supervisor_response_negative_send(peer_fd, &request, &completed_at), "negative response could not be sent");
	now = completed_at;
	resolver_cache_view cache_view;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_completion_take(supervisor, &completion)
		&& completion.publication == RESOLVER_CACHE_PUBLISH_STORED && completion.response.status == RESOLVER_IPC_LOOKUP_NODATA
		&& resolver_cache_entry_view(negative_entry, &now, &cache_view) && cache_view.status == RESOLVER_CACHE_VIEW_FRESH_NODATA, "authoritative negative response was not published");
	supervisor_completion_clear(&completion);
	CHECK(resolver_supervisor_entry_schedule(supervisor, zero_entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "TTL-zero job could not be scheduled");
	CHECK(resolver_supervisor_entry_view(supervisor, zero_entry, &job_view) && job_view.state == RESOLVER_SUPERVISOR_JOB_DISPATCHED, "TTL-zero job was not dispatched");
	peer_fd = supervisor_fake_peer(supervisor, 0);
	CHECK(peer_fd != -1 && supervisor_request_receive(peer_fd, &request), "TTL-zero request was not received");
	completed_at = supervisor_time_add(&job_view.dispatched_at, 1, 0);
	CHECK(supervisor_response_address_send(peer_fd, &request, &completed_at, 0), "TTL-zero response could not be sent");
	now = completed_at;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK
		&& resolver_supervisor_entry_schedule(supervisor, zero_entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_COMPLETE
		&& resolver_supervisor_entry_schedule_interactive(supervisor, zero_entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_COMPLETE
		&& resolver_supervisor_entry_view(supervisor, zero_entry, &job_view) && job_view.priority == RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND
		&& job_view.interactive_interest_count == 0, "TTL-zero completion was not coalescible without retaining interactive interest");
	CHECK(resolver_supervisor_completion_take(supervisor, &completion) && completion.publication == RESOLVER_CACHE_PUBLISH_TRANSIENT
		&& completion.response.payload.address.address_count == 1, "TTL-zero transient payload was not transferred");
	supervisor_completion_clear(&completion);
	CHECK(resolver_supervisor_entry_schedule(supervisor, srv_entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "SRV job could not be scheduled");
	CHECK(resolver_supervisor_entry_view(supervisor, srv_entry, &job_view) && job_view.state == RESOLVER_SUPERVISOR_JOB_DISPATCHED, "SRV job was not dispatched");
	peer_fd = supervisor_fake_peer(supervisor, 0);
	CHECK(peer_fd != -1 && supervisor_request_receive(peer_fd, &request) && request.query_type == ns_t_srv, "SRV request was not received");
	completed_at = supervisor_time_add(&job_view.dispatched_at, 1, 0);
	CHECK(supervisor_response_srv_send(peer_fd, &request, &completed_at, 20), "SRV response could not be sent");
	now = completed_at;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_completion_take(supervisor, &completion)
		&& completion.publication == RESOLVER_CACHE_PUBLISH_STORED && completion.response.query_type == ns_t_srv, "SRV response was not published");
	supervisor_completion_clear(&completion);
	CHECK(resolver_supervisor_entry_schedule(supervisor, zero_entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "later TTL-zero request did not start a new lookup");
	test_result = true;

cleanup:
	supervisor_completion_clear(&completion);
	resolver_supervisor_destroy(supervisor);
	resolver_cache_entry_release(entry);
	resolver_cache_entry_release(negative_entry);
	resolver_cache_entry_release(srv_entry);
	resolver_cache_entry_release(zero_entry);
	resolver_cache_destroy(cache);
	supervisor_fake_reset();
	return test_result;
}

static bool supervisor_test_priority(void) {
	bool test_result = false;
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	struct timespec now = { .tv_sec = 350 };
	resolver_supervisor *supervisor = NULL;
	resolver_cache *cache = NULL;
	resolver_cache_entry *entries[RESOLVER_SUPERVISOR_JOB_LIMIT];
	resolver_supervisor_completion completion = { 0 };
	memset(entries, 0, sizeof(entries));
	supervisor_fake_reset();
	supervisor = resolver_supervisor_create(&signal_mask, &now);
	cache = resolver_cache_create();
	CHECK(supervisor != NULL && cache != NULL, "priority-test state could not be created");
	for (size_t index = 0; index < RESOLVER_SUPERVISOR_JOB_LIMIT; index++) {
		char name[64];
		snprintf(name, sizeof(name), "priority-%zu.supervisor.test", index);
		entries[index] = supervisor_cache_entry_create(cache, name, ns_t_a);
		CHECK(entries[index] != NULL, "priority-test cache entry could not be created");
	}
	for (size_t index = 0; index < RESOLVER_SUPERVISOR_JOB_LIMIT - RESOLVER_SUPERVISOR_INTERACTIVE_RESERVE; index++) {
		CHECK(resolver_supervisor_entry_schedule(supervisor, entries[index], &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "priority-test background job could not be scheduled");
	}
	resolver_supervisor_job_view job_view;
	CHECK(resolver_supervisor_entry_view(supervisor, entries[2], &job_view) && job_view.state == RESOLVER_SUPERVISOR_JOB_QUEUED
		&& job_view.priority == RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND && job_view.interactive_interest_count == 0,
		"background queue state was invalid");
	CHECK(resolver_supervisor_entry_schedule_interactive(supervisor, entries[2], &now) == RESOLVER_SUPERVISOR_SCHEDULE_COALESCED
		&& resolver_supervisor_entry_view(supervisor, entries[2], &job_view) && job_view.priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE
		&& job_view.interactive_interest_count == 1 && resolver_supervisor_entry_interactive_release(supervisor, entries[2], &now)
		&& resolver_supervisor_entry_view(supervisor, entries[2], &job_view) && job_view.priority == RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND
		&& job_view.interactive_interest_count == 0 && job_view.state == RESOLVER_SUPERVISOR_JOB_QUEUED, "queued priority promotion or downgrade failed");
	CHECK(resolver_supervisor_entry_schedule_interactive(supervisor, entries[3], &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED
		&& resolver_supervisor_entry_view(supervisor, entries[3], &job_view) && job_view.state == RESOLVER_SUPERVISOR_JOB_QUEUED
		&& job_view.priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE && job_view.interactive_interest_count == 1,
		"new interactive job did not enter the interactive queue");
	int peer_fds[RESOLVER_SUPERVISOR_HELPER_COUNT];
	resolver_ipc_request requests[RESOLVER_SUPERVISOR_HELPER_COUNT];
	for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
		peer_fds[helper_index] = supervisor_fake_peer(supervisor, helper_index);
		CHECK(peer_fds[helper_index] != -1 && supervisor_request_receive(peer_fds[helper_index], &requests[helper_index])
			&& strcmp(requests[helper_index].query_name, resolver_cache_entry_name(entries[helper_index])) == 0, "initial priority-test request was invalid");
	}
	struct timespec completed_at = supervisor_time_add(&now, 1, 0);
	CHECK(supervisor_response_address_send(peer_fds[0], &requests[0], &completed_at, 30), "first priority-test response could not be sent");
	now = completed_at;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_completion_take(supervisor, &completion),
		"first priority-test response was not processed");
	supervisor_completion_clear(&completion);
	resolver_ipc_request interactive_request;
	CHECK(supervisor_request_receive(peer_fds[0], &interactive_request) && strcmp(interactive_request.query_name, resolver_cache_entry_name(entries[3])) == 0,
		"new interactive job did not dispatch before queued background work");
	CHECK(resolver_supervisor_entry_schedule_interactive(supervisor, entries[2], &now) == RESOLVER_SUPERVISOR_SCHEDULE_COALESCED
		&& resolver_supervisor_entry_schedule_interactive(supervisor, entries[2], &now) == RESOLVER_SUPERVISOR_SCHEDULE_COALESCED
		&& resolver_supervisor_entry_view(supervisor, entries[2], &job_view) && job_view.priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE
		&& job_view.interactive_interest_count == 2 && job_view.state == RESOLVER_SUPERVISOR_JOB_QUEUED, "queued background job was not promoted for both waiters");
	completed_at = supervisor_time_add(&now, 1, 0);
	CHECK(supervisor_response_address_send(peer_fds[1], &requests[1], &completed_at, 30), "second priority-test response could not be sent");
	now = completed_at;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_completion_take(supervisor, &completion),
		"second priority-test response was not processed");
	supervisor_completion_clear(&completion);
	resolver_ipc_request promoted_request;
	CHECK(supervisor_request_receive(peer_fds[1], &promoted_request) && strcmp(promoted_request.query_name, resolver_cache_entry_name(entries[2])) == 0
		&& resolver_supervisor_entry_view(supervisor, entries[2], &job_view) && job_view.state == RESOLVER_SUPERVISOR_JOB_DISPATCHED
		&& job_view.priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE && job_view.interactive_interest_count == 2,
		"promoted background job was not dispatched first");
	uint64_t query_id = job_view.query_id;
	CHECK(resolver_supervisor_entry_interactive_release(supervisor, entries[2], &now) && resolver_supervisor_entry_view(supervisor, entries[2], &job_view)
		&& job_view.priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE && job_view.interactive_interest_count == 1 && job_view.query_id == query_id
		&& resolver_supervisor_entry_interactive_release(supervisor, entries[2], &now) && resolver_supervisor_entry_view(supervisor, entries[2], &job_view)
		&& job_view.priority == RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND && job_view.interactive_interest_count == 0 && job_view.state == RESOLVER_SUPERVISOR_JOB_DISPATCHED
		&& job_view.query_id == query_id, "last-waiter release did not downgrade dispatched work without restarting it");
	completed_at = supervisor_time_add(&now, 1, 0);
	CHECK(supervisor_response_address_send(peer_fds[0], &interactive_request, &completed_at, 30), "interactive priority-test response could not be sent");
	now = completed_at;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK
		&& resolver_supervisor_entry_view(supervisor, entries[3], &job_view) && job_view.state == RESOLVER_SUPERVISOR_JOB_COMPLETE
		&& job_view.interactive_interest_count == 0 && resolver_supervisor_completion_take(supervisor, &completion),
		"completion did not release outstanding interactive interest");
	supervisor_completion_clear(&completion);
	test_result = true;

cleanup:
	supervisor_completion_clear(&completion);
	resolver_supervisor_destroy(supervisor);
	for (size_t index = 0; index < RESOLVER_SUPERVISOR_JOB_LIMIT; index++) {
		resolver_cache_entry_release(entries[index]);
	}
	resolver_cache_destroy(cache);
	supervisor_fake_reset();
	return test_result;
}

static bool supervisor_test_protocol_and_recovery(void) {
	bool test_result = false;
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	struct timespec now = { .tv_sec = 700 };
	resolver_supervisor *supervisor = NULL;
	resolver_cache *cache = NULL;
	resolver_cache_entry *entry = NULL;
	resolver_cache_entry *success_entries[RESOLVER_SUPERVISOR_RESPAWN_RESET_SUCCESS_COUNT];
	memset(success_entries, 0, sizeof(success_entries));
	resolver_supervisor_completion completion = { 0 };
	supervisor_fake_reset();
	supervisor = resolver_supervisor_create(&signal_mask, &now);
	cache = resolver_cache_create();
	entry = supervisor_cache_entry_create(cache, "protocol.supervisor.test", ns_t_a);
	CHECK(supervisor != NULL && cache != NULL && entry != NULL, "protocol-test state could not be created");
	CHECK(resolver_supervisor_entry_schedule_interactive(supervisor, entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "interactive protocol job could not be scheduled");
	resolver_supervisor_helper_view helper_view;
	CHECK(resolver_supervisor_helper_view_get(supervisor, 0, &helper_view), "protocol helper could not be inspected");
	supervisor_test_helper *failed_helper = supervisor_fake_find(helper_view.process_id);
	int peer_fd = failed_helper == NULL ? -1 : failed_helper->peer_fd;
	resolver_ipc_request request;
	CHECK(peer_fd != -1 && supervisor_request_receive(peer_fd, &request), "protocol request was not received");
	uint8_t malformed = 0;
	CHECK(supervisor_packet_send(peer_fd, &malformed, sizeof(malformed)), "malformed helper packet could not be sent");
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && failed_helper->last_signal == SIGKILL,
		"protocol-corrupt helper was not killed immediately");
	resolver_supervisor_job_view job_view;
	CHECK(resolver_supervisor_entry_view(supervisor, entry, &job_view) && job_view.state == RESOLVER_SUPERVISOR_JOB_RETRY_WAIT
		&& job_view.priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE && job_view.interactive_interest_count == 1,
		"protocol-corrupt helper job did not retain interactive priority through retry wait");
	CHECK(resolver_supervisor_helper_view_get(supervisor, 0, &helper_view) && helper_view.state == RESOLVER_SUPERVISOR_HELPER_IDLE && helper_view.failure_count == 1
		&& helper_view.last_failed_process_id == failed_helper->process_id && helper_view.last_failure == RESOLVER_SUPERVISOR_HELPER_FAILURE_PROTOCOL,
		"first helper replacement was not immediate or diagnosable");
	CHECK(resolver_supervisor_entry_cancel(supervisor, entry, &now), "protocol retry could not be cancelled");
	now = helper_view.next_event_at;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_helper_view_get(supervisor, 0, &helper_view)
		&& helper_view.failure_count == 0, "stable helper lifetime did not reset failure state");
	peer_fd = supervisor_fake_peer(supervisor, 0);
	CHECK(peer_fd != -1 && close(peer_fd) == 0, "first exited helper could not be simulated");
	supervisor_fake_find(helper_view.process_id)->peer_fd = -1;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_helper_view_get(supervisor, 0, &helper_view)
		&& helper_view.state == RESOLVER_SUPERVISOR_HELPER_IDLE && helper_view.failure_count == 1, "first exited helper was not replaced immediately");
	peer_fd = supervisor_fake_peer(supervisor, 0);
	CHECK(peer_fd != -1 && close(peer_fd) == 0, "second exited helper could not be simulated");
	supervisor_fake_find(helper_view.process_id)->peer_fd = -1;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_helper_view_get(supervisor, 0, &helper_view)
		&& helper_view.state == RESOLVER_SUPERVISOR_HELPER_BACKOFF && helper_view.failure_count == 2
		&& supervisor_time_difference_milliseconds(&helper_view.next_event_at, &now) <= RESOLVER_SUPERVISOR_RESPAWN_MAX_MS, "repeated helper failure did not enter bounded backoff");
	now = helper_view.next_event_at;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_helper_view_get(supervisor, 0, &helper_view)
		&& helper_view.state == RESOLVER_SUPERVISOR_HELPER_IDLE && helper_view.failure_count == 2, "backed-off helper was not restarted");
	for (size_t index = 0; index < RESOLVER_SUPERVISOR_RESPAWN_RESET_SUCCESS_COUNT; index++) {
		char name[64];
		snprintf(name, sizeof(name), "recovery-%zu.supervisor.test", index);
		success_entries[index] = supervisor_cache_entry_create(cache, name, ns_t_a);
		CHECK(success_entries[index] != NULL && resolver_supervisor_entry_schedule(supervisor, success_entries[index], &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED,
			"recovery success job could not be scheduled");
		CHECK(resolver_supervisor_entry_view(supervisor, success_entries[index], &job_view), "recovery success job could not be inspected");
		peer_fd = supervisor_fake_peer(supervisor, 0);
		CHECK(peer_fd != -1 && supervisor_request_receive(peer_fd, &request), "recovery success request was not received");
		struct timespec completed_at = supervisor_time_add(&job_view.dispatched_at, 1, 0);
		CHECK(supervisor_response_address_send(peer_fd, &request, &completed_at, 10), "recovery success response could not be sent");
		now = completed_at;
		CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_completion_take(supervisor, &completion),
			"recovery success response did not complete");
		supervisor_completion_clear(&completion);
	}
	CHECK(resolver_supervisor_helper_view_get(supervisor, 0, &helper_view) && helper_view.failure_count == 0 && helper_view.consecutive_successes == 0
		&& helper_view.last_failed_process_id == -1 && helper_view.last_failure == RESOLVER_SUPERVISOR_HELPER_FAILURE_NONE,
		"three valid responses did not reset helper failure state");
	test_result = true;

cleanup:
	supervisor_completion_clear(&completion);
	resolver_supervisor_destroy(supervisor);
	resolver_cache_entry_release(entry);
	for (size_t index = 0; index < RESOLVER_SUPERVISOR_RESPAWN_RESET_SUCCESS_COUNT; index++) {
		resolver_cache_entry_release(success_entries[index]);
	}
	resolver_cache_destroy(cache);
	supervisor_fake_reset();
	return test_result;
}

static bool supervisor_test_real_process(void) {
	bool test_result = false;
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	struct timespec now;
	resolver_supervisor *supervisor = NULL;
	resolver_cache *cache = NULL;
	resolver_cache_entry *entry = NULL;
	resolver_supervisor_completion completion = { 0 };
	supervisor_fake_reset();
	supervisor_use_real_helper = true;
	CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "real-helper start time could not be read");
	supervisor = resolver_supervisor_create(&signal_mask, &now);
	cache = resolver_cache_create();
	entry = supervisor_cache_entry_create(cache, "real-process.supervisor.test", ns_t_a);
	CHECK(supervisor != NULL && cache != NULL && entry != NULL, "real-helper test state could not be created");
	CHECK(resolver_supervisor_entry_schedule(supervisor, entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "real-helper job could not be scheduled");
	struct pollfd descriptor = { .fd = resolver_supervisor_event_fd(supervisor), .events = POLLIN };
	bool completed = false;
	for (int attempt = 0; attempt < 50 && !completed; attempt++) {
		int poll_result;
		do {
			poll_result = poll(&descriptor, 1, 100);
		} while (poll_result == -1 && errno == EINTR);
		CHECK(poll_result >= 0, "real-helper supervisor event source could not be polled");
		if (poll_result == 0) {
			continue;
		}
		CHECK((descriptor.revents & POLLIN) && clock_gettime(CLOCK_MONOTONIC, &now) == 0
			&& resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK, "real helper event could not be processed");
		completed = resolver_supervisor_completion_take(supervisor, &completion);
	}
	CHECK(completed && completion.publication == RESOLVER_CACHE_PUBLISH_STORED && completion.response.status == RESOLVER_IPC_LOOKUP_OK,
		"real helper response did not complete end to end");
	test_result = true;

cleanup:
	supervisor_completion_clear(&completion);
	resolver_supervisor_destroy(supervisor);
	resolver_cache_entry_release(entry);
	resolver_cache_destroy(cache);
	supervisor_fake_reset();
	return test_result;
}

static bool supervisor_test_retry(void) {
	bool test_result = false;
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	struct timespec now = { .tv_sec = 400 };
	resolver_supervisor *supervisor = NULL;
	resolver_cache *cache = NULL;
	resolver_cache_entry *entry = NULL;
	resolver_supervisor_completion completion = { 0 };
	supervisor_fake_reset();
	supervisor = resolver_supervisor_create(&signal_mask, &now);
	cache = resolver_cache_create();
	entry = supervisor_cache_entry_create(cache, "retry.supervisor.test", ns_t_a);
	CHECK(supervisor != NULL && cache != NULL && entry != NULL, "retry-test state could not be created");
	CHECK(resolver_supervisor_entry_schedule(supervisor, entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "retry job could not be scheduled");
	uint64_t previous_query_id = 0;
	resolver_supervisor_job_view dispatched_view;
	for (uint64_t retry_count = 1; retry_count <= 7; retry_count++) {
		CHECK(resolver_supervisor_entry_view(supervisor, entry, &dispatched_view) && dispatched_view.state == RESOLVER_SUPERVISOR_JOB_DISPATCHED
			&& dispatched_view.query_id != previous_query_id, "retry attempt was not dispatched with a new query ID");
		previous_query_id = dispatched_view.query_id;
		int peer_fd = supervisor_fake_peer(supervisor, 0);
		resolver_ipc_request request;
		CHECK(peer_fd != -1 && supervisor_request_receive(peer_fd, &request) && request.query_id == dispatched_view.query_id, "retry request was not received");
		struct timespec completed_at = supervisor_time_add(&dispatched_view.dispatched_at, 1, 0);
		CHECK(supervisor_response_temporary_send(peer_fd, &request, &completed_at), "temporary response could not be sent");
		now = completed_at;
		CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK, "temporary response could not be processed");
		resolver_supervisor_job_view retry_view;
		CHECK(resolver_supervisor_entry_view(supervisor, entry, &retry_view) && retry_view.state == RESOLVER_SUPERVISOR_JOB_RETRY_WAIT && retry_view.retry_count == retry_count
			&& retry_view.query_id == 0 && !resolver_supervisor_completion_take(supervisor, &completion), "temporary result did not enter retry wait");
		CHECK(supervisor_time_difference_milliseconds(&retry_view.retry_at, &now) == supervisor_retry_delay_expected(resolver_cache_entry_id(entry), retry_count),
			"query retry jitter was not deterministic");
		if (retry_count == 1) {
			struct timespec retry_at = retry_view.retry_at;
			CHECK(resolver_supervisor_entry_schedule(supervisor, entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_COALESCED
				&& resolver_supervisor_entry_schedule_interactive(supervisor, entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_COALESCED
				&& resolver_supervisor_entry_view(supervisor, entry, &retry_view) && retry_view.state == RESOLVER_SUPERVISOR_JOB_RETRY_WAIT
				&& retry_view.priority == RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE && retry_view.interactive_interest_count == 1
				&& retry_view.retry_at.tv_sec == retry_at.tv_sec && retry_view.retry_at.tv_nsec == retry_at.tv_nsec,
				"retry-wait promotion bypassed backoff or failed to retain interest");
			CHECK(resolver_supervisor_entry_interactive_release(supervisor, entry, &now) && resolver_supervisor_entry_view(supervisor, entry, &retry_view)
				&& retry_view.state == RESOLVER_SUPERVISOR_JOB_RETRY_WAIT && retry_view.priority == RESOLVER_SUPERVISOR_PRIORITY_BACKGROUND
				&& retry_view.interactive_interest_count == 0 && retry_view.retry_at.tv_sec == retry_at.tv_sec && retry_view.retry_at.tv_nsec == retry_at.tv_nsec,
				"retry-wait interest release did not downgrade without changing backoff");
		}
		now = retry_view.retry_at;
		CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK, "retry deadline could not be processed");
	}
	CHECK(resolver_supervisor_entry_view(supervisor, entry, &dispatched_view) && dispatched_view.state == RESOLVER_SUPERVISOR_JOB_DISPATCHED
		&& dispatched_view.query_id != previous_query_id, "post-backoff attempt was not dispatched");
	int peer_fd = supervisor_fake_peer(supervisor, 0);
	resolver_ipc_request request;
	CHECK(peer_fd != -1 && supervisor_request_receive(peer_fd, &request) && request.query_id == dispatched_view.query_id, "post-backoff request was not received");
	struct timespec completed_at = supervisor_time_add(&dispatched_view.dispatched_at, 1, 0);
	CHECK(supervisor_response_address_send(peer_fd, &request, &completed_at, 10), "retry success response could not be sent");
	now = completed_at;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_completion_take(supervisor, &completion)
		&& completion.publication == RESOLVER_CACHE_PUBLISH_STORED, "retried response did not complete");
	test_result = true;

cleanup:
	supervisor_completion_clear(&completion);
	resolver_supervisor_destroy(supervisor);
	resolver_cache_entry_release(entry);
	resolver_cache_destroy(cache);
	supervisor_fake_reset();
	return test_result;
}

static bool supervisor_test_shutdown(void) {
	bool test_result = false;
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	struct timespec now = { .tv_sec = 600 };
	resolver_supervisor *supervisor = NULL;
	supervisor_test_helper *helpers[RESOLVER_SUPERVISOR_HELPER_COUNT];
	memset(helpers, 0, sizeof(helpers));
	supervisor_fake_reset();
	supervisor = resolver_supervisor_create(&signal_mask, &now);
	CHECK(supervisor != NULL, "shutdown-test supervisor could not be created");
	for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
		resolver_supervisor_helper_view view;
		CHECK(resolver_supervisor_helper_view_get(supervisor, helper_index, &view), "shutdown helper could not be prepared");
		helpers[helper_index] = supervisor_fake_find(view.process_id);
		CHECK(helpers[helper_index] != NULL, "shutdown fake helper was unavailable");
	}
	helpers[RESOLVER_SUPERVISOR_HELPER_COUNT - 1U]->close_on_sigterm = false;
	CHECK(resolver_supervisor_shutdown(supervisor, &now), "orderly shutdown could not start");
	for (size_t helper_index = 0; helper_index < RESOLVER_SUPERVISOR_HELPER_COUNT; helper_index++) {
		CHECK(helpers[helper_index]->last_signal == SIGTERM, "orderly shutdown did not send SIGTERM");
	}
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && !resolver_supervisor_shutdown_complete(supervisor),
		"shutdown grace was not retained for the surviving helper");
	now = supervisor_time_add(&now, 1, 0);
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_shutdown_complete(supervisor)
		&& helpers[RESOLVER_SUPERVISOR_HELPER_COUNT - 1U]->last_signal == SIGKILL, "shutdown grace did not fall back to SIGKILL");
	test_result = true;

cleanup:
	resolver_supervisor_destroy(supervisor);
	supervisor_fake_reset();
	return test_result;
}

static bool supervisor_test_timeout_and_order(void) {
	bool test_result = false;
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	struct timespec now = { .tv_sec = 500 };
	resolver_supervisor *supervisor = NULL;
	resolver_cache *cache = NULL;
	resolver_cache_entry *entry = NULL;
	resolver_cache_entry *future_entry = NULL;
	resolver_cache_entry *late_entry = NULL;
	resolver_supervisor_completion completion = { 0 };
	supervisor_fake_reset();
	supervisor = resolver_supervisor_create(&signal_mask, &now);
	cache = resolver_cache_create();
	entry = supervisor_cache_entry_create(cache, "deadline.supervisor.test", ns_t_a);
	future_entry = supervisor_cache_entry_create(cache, "future.supervisor.test", ns_t_a);
	late_entry = supervisor_cache_entry_create(cache, "late.supervisor.test", ns_t_a);
	CHECK(supervisor != NULL && cache != NULL && entry != NULL && future_entry != NULL && late_entry != NULL, "deadline-test state could not be created");
	CHECK(resolver_supervisor_entry_schedule(supervisor, entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "deadline job could not be scheduled");
	resolver_supervisor_job_view job_view;
	CHECK(resolver_supervisor_entry_view(supervisor, entry, &job_view), "deadline job could not be inspected");
	int peer_fd = supervisor_fake_peer(supervisor, 0);
	resolver_ipc_request request;
	CHECK(peer_fd != -1 && supervisor_request_receive(peer_fd, &request), "deadline request was not received");
	CHECK(supervisor_response_address_send(peer_fd, &request, &job_view.deadline, 10), "deadline-boundary response could not be sent");
	now = supervisor_time_add(&job_view.deadline, 1, 0);
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK && resolver_supervisor_completion_take(supervisor, &completion)
		&& completion.publication == RESOLVER_CACHE_PUBLISH_STORED, "response ready with the timer was not drained first");
	supervisor_completion_clear(&completion);
	CHECK(resolver_supervisor_entry_schedule(supervisor, late_entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED, "late job could not be scheduled");
	CHECK(resolver_supervisor_entry_view(supervisor, late_entry, &job_view), "late job could not be inspected");
	peer_fd = supervisor_fake_peer(supervisor, 0);
	CHECK(peer_fd != -1 && supervisor_request_receive(peer_fd, &request), "late request was not received");
	struct timespec late_completed = supervisor_time_add(&job_view.deadline, 1, 0);
	CHECK(supervisor_response_address_send(peer_fd, &request, &late_completed, 10), "late response could not be sent");
	now = late_completed;
	CHECK(resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK, "late response processing failed");
	resolver_supervisor_job_view retry_view;
	CHECK(resolver_supervisor_entry_view(supervisor, late_entry, &retry_view) && retry_view.state == RESOLVER_SUPERVISOR_JOB_RETRY_WAIT
		&& !resolver_supervisor_completion_take(supervisor, &completion), "late helper result was accepted");
	resolver_supervisor_helper_view helper_view;
	CHECK(resolver_supervisor_helper_view_get(supervisor, 0, &helper_view) && helper_view.failure_count == 1 && helper_view.last_failure == RESOLVER_SUPERVISOR_HELPER_FAILURE_TIMEOUT,
		"late helper was not retired as timed out");
	CHECK(resolver_supervisor_entry_schedule(supervisor, future_entry, &now) == RESOLVER_SUPERVISOR_SCHEDULE_STARTED
		&& resolver_supervisor_entry_view(supervisor, future_entry, &job_view), "future-timestamp job could not be dispatched");
	peer_fd = supervisor_fake_peer(supervisor, 0);
	CHECK(peer_fd != -1 && supervisor_request_receive(peer_fd, &request), "future-timestamp request was not received");
	struct timespec future_completed = supervisor_time_add(&job_view.dispatched_at, 5, 0);
	now = supervisor_time_add(&job_view.dispatched_at, 1, 0);
	CHECK(supervisor_response_address_send(peer_fd, &request, &future_completed, 10) && resolver_supervisor_events_process(supervisor, &now) == RESOLVER_SUPERVISOR_EVENT_OK,
		"future-timestamp response could not be processed");
	CHECK(resolver_supervisor_entry_view(supervisor, future_entry, &retry_view) && retry_view.state == RESOLVER_SUPERVISOR_JOB_RETRY_WAIT
		&& resolver_supervisor_helper_view_get(supervisor, 0, &helper_view) && helper_view.last_failure == RESOLVER_SUPERVISOR_HELPER_FAILURE_PROTOCOL,
		"future helper completion timestamp was accepted");
	test_result = true;

cleanup:
	supervisor_completion_clear(&completion);
	resolver_supervisor_destroy(supervisor);
	resolver_cache_entry_release(entry);
	resolver_cache_entry_release(future_entry);
	resolver_cache_entry_release(late_entry);
	resolver_cache_destroy(cache);
	supervisor_fake_reset();
	return test_result;
}

/* section: functions (exported) */
dns_address_lookup_status __wrap_dns_address_lookup(const char *query_name, sa_family_t family, dns_address_result *result) {
	if (query_name == NULL || result == NULL || (family != AF_INET && family != AF_INET6)) {
		return DNS_ADDRESS_LOOKUP_BAD_ARGUMENT;
	}
	memset(result, 0, sizeof(*result));
	result->addresses = calloc(1, sizeof(*result->addresses));
	if (result->addresses == NULL) {
		return DNS_ADDRESS_LOOKUP_MEMORY;
	}
	result->address_count = 1;
	result->addresses[0].address.family = family;
	result->addresses[0].effective_ttl = 30;
	result->addresses[0].record_ttl = 30;
	if (family == AF_INET) {
		result->addresses[0].address.addr.v4 = htonl(UINT32_C(0xC0000201));
	} else {
		result->addresses[0].address.addr.v6[15] = 1;
	}
	snprintf(result->canonical_name, sizeof(result->canonical_name), "%s", query_name);
	snprintf(result->question_name, sizeof(result->question_name), "%s", query_name);
	return DNS_ADDRESS_LOOKUP_OK;
}

int __wrap_kill(pid_t process_id, int signal_number) {
	supervisor_test_helper *helper = supervisor_fake_find(process_id);
	if (helper == NULL) {
		return __real_kill(process_id, signal_number);
	}
	helper->last_signal = signal_number;
	if ((signal_number == SIGTERM && helper->close_on_sigterm) || signal_number == SIGKILL) {
		if (helper->peer_fd != -1) {
			close(helper->peer_fd);
			helper->peer_fd = -1;
		}
		helper->active = false;
	}
	return 0;
}

int __wrap_resolver_helper_process_start(const sigset_t *signal_mask, pid_t *process_id, int *socket_fd) {
	if (supervisor_use_real_helper) {
		return __real_resolver_helper_process_start(signal_mask, process_id, socket_fd);
	}
	if (supervisor_start_failures > 0) {
		supervisor_start_failures--;
		errno = EAGAIN;
		return -1;
	}
	if (signal_mask == NULL || process_id == NULL || socket_fd == NULL || supervisor_helper_count >= SUPERVISOR_TEST_HELPER_LIMIT) {
		errno = EINVAL;
		return -1;
	}
	int sockets[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == -1) {
		return -1;
	}
	supervisor_test_helper *helper = &supervisor_helpers[supervisor_helper_count];
	helper->active = true;
	helper->close_on_sigterm = true;
	helper->last_signal = 0;
	helper->peer_fd = sockets[1];
	helper->process_id = (pid_t)(SUPERVISOR_TEST_PROCESS_BASE + (int)supervisor_helper_count);
	supervisor_helper_count++;
	*process_id = helper->process_id;
	*socket_fd = sockets[0];
	return 0;
}

pid_t __wrap_waitpid(pid_t process_id, int *status, int options) {
	(void)options;
	if (status != NULL) {
		*status = 0;
	}
	supervisor_test_helper *helper = supervisor_fake_find(process_id);
	if (helper == NULL) {
		return __real_waitpid(process_id, status, options);
	}
	helper->wait_count++;
	return process_id;
}

/* section: functions (entry point) */
int main(void) {
	int test_result = EXIT_FAILURE;
	CHECK(supervisor_test_arguments(), "supervisor argument tests failed");
	CHECK(supervisor_test_capacity(), "supervisor capacity tests failed");
	CHECK(supervisor_test_cancel(), "supervisor cancellation tests failed");
	CHECK(supervisor_test_child_dispose(), "supervisor child-disposal tests failed");
	CHECK(supervisor_test_completion(), "supervisor completion tests failed");
	CHECK(supervisor_test_priority(), "supervisor priority tests failed");
	CHECK(supervisor_test_protocol_and_recovery(), "supervisor protocol and recovery tests failed");
	CHECK(supervisor_test_real_process(), "supervisor real-process tests failed");
	CHECK(supervisor_test_retry(), "supervisor retry tests failed");
	CHECK(supervisor_test_shutdown(), "supervisor shutdown tests failed");
	CHECK(supervisor_test_timeout_and_order(), "supervisor deadline tests failed");
	test_result = EXIT_SUCCESS;

cleanup:
	supervisor_fake_reset();
	return test_result;
}
