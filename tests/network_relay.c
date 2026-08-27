/*
 * network_relay.c: Tests for bounded bidirectional relay
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
#include "network.h"

/* section: defines */
#define RELAY_TEST_CHILD_ERROR	120
#ifndef RELAY_TEST_IO_TIMEOUT_MS
#define RELAY_TEST_IO_TIMEOUT_MS	3000
#endif
#ifndef RELAY_TEST_STREAM_TIMEOUT_MS
#define RELAY_TEST_STREAM_TIMEOUT_MS	15000
#endif

/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (false)

/* section: types */
typedef struct {
	int client_fd;
	int upstream_fd;
	pid_t relay_pid;
} relay_test_session;

/* section: global variables */
static size_t relay_send_injection_allowance;
static int relay_send_injection_fd = -1;
static bool relay_send_injection_pending;

/* section: functions (local) */
static bool relay_deadline_create(struct timespec *deadline, int timeout_ms) {
	if (deadline == NULL || timeout_ms < 1 || clock_gettime(CLOCK_MONOTONIC, deadline) == -1) {
		return false;
	}
	deadline->tv_sec += timeout_ms / 1000;
	deadline->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
	if (deadline->tv_nsec >= 1000000000L) {
		deadline->tv_sec++;
		deadline->tv_nsec -= 1000000000L;
	}
	return true;
}

static int relay_deadline_remaining_ms(const struct timespec *deadline) {
	struct timespec now;
	if (deadline == NULL || clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return -1;
	}
	int64_t seconds = (int64_t)deadline->tv_sec - (int64_t)now.tv_sec;
	int64_t nanoseconds = (int64_t)deadline->tv_nsec - (int64_t)now.tv_nsec;
	if (nanoseconds < 0) {
		seconds--;
		nanoseconds += INT64_C(1000000000);
	}
	if (seconds < 0 || (seconds == 0 && nanoseconds == 0)) {
		return 0;
	}
	if (seconds > INT_MAX / 1000) {
		return INT_MAX;
	}
	int64_t milliseconds = seconds * INT64_C(1000) + (nanoseconds + INT64_C(999999)) / INT64_C(1000000);
	return milliseconds > INT_MAX ? INT_MAX : (int)milliseconds;
}

static bool relay_expect_eof(int socket_fd, int timeout_ms) {
	uint8_t byte;
	struct pollfd event = { .fd = socket_fd, .events = POLLIN | POLLHUP };
	if (poll(&event, 1, timeout_ms) != 1) {
		return false;
	}
	ssize_t received = recv(socket_fd, &byte, sizeof(byte), MSG_DONTWAIT);
	return received == 0;
}

static bool relay_pair_create(int pair[2]) {
	struct sockaddr_in address;
	socklen_t address_size = sizeof(address);
	int listener_fd = -1;
	int receive_buffer_size = 16384;
	bool result = false;
	if (pair == NULL) {
		return false;
	}
	pair[0] = -1;
	pair[1] = -1;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	listener_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if ((listener_fd == -1) || (bind(listener_fd, (const struct sockaddr *)&address, sizeof(address)) == -1) || (listen(listener_fd, 1) == -1)
		|| (getsockname(listener_fd, (struct sockaddr *)&address, &address_size) == -1)) {
		goto cleanup;
	}
	pair[0] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if ((pair[0] == -1) || (setsockopt(pair[0], SOL_SOCKET, SO_RCVBUF, &receive_buffer_size, sizeof(receive_buffer_size)) == -1)
		|| (connect(pair[0], (const struct sockaddr *)&address, address_size) == -1)) {
		goto cleanup;
	}
	pair[1] = accept4(listener_fd, NULL, NULL, SOCK_CLOEXEC);
	if (pair[1] == -1) {
		goto cleanup;
	}
	result = true;

cleanup:
	if (listener_fd >= 0) {
		close(listener_fd);
	}
	if ((!result) && (pair[0] >= 0)) {
		close(pair[0]);
		pair[0] = -1;
	}
	if ((!result) && (pair[1] >= 0)) {
		close(pair[1]);
		pair[1] = -1;
	}
	return result;
}

static bool relay_read_exact(int socket_fd, void *buffer, size_t size, int timeout_ms) {
	size_t offset = 0;
	while (offset < size) {
		struct pollfd event = { .fd = socket_fd, .events = POLLIN };
		if (poll(&event, 1, timeout_ms) != 1) {
			return false;
		}
		ssize_t received = recv(socket_fd, (uint8_t *)buffer + offset, size - offset, MSG_DONTWAIT);
		if (received > 0) {
			offset += (size_t)received;
			continue;
		}
		if ((received < 0) && ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
			continue;
		}
		return false;
	}
	return true;
}

static bool relay_session_cleanup(relay_test_session *session) {
	bool result = true;
	if (session == NULL) {
		return false;
	}
	if (session->client_fd >= 0) {
		close(session->client_fd);
		session->client_fd = -1;
	}
	if (session->upstream_fd >= 0) {
		close(session->upstream_fd);
		session->upstream_fd = -1;
	}
	if (session->relay_pid > 0) {
		if (kill(session->relay_pid, SIGKILL) == -1 && (errno != ESRCH)) {
			result = false;
		}
		if (waitpid(session->relay_pid, NULL, 0) == -1 && (errno != ECHILD)) {
			result = false;
		}
		session->relay_pid = -1;
	}
	return result;
}

static bool relay_session_start(relay_test_session *session, const void *pending_out, size_t pending_size, bool inject_backpressure) {
	int client_pair[2] = { -1, -1 };
	int upstream_pair[2] = { -1, -1 };
	int send_buffer_size = 16384;
	if ((session == NULL) || (!relay_pair_create(client_pair)) || (!relay_pair_create(upstream_pair))) {
		if (client_pair[0] >= 0) {
			close(client_pair[0]);
		}
		if (client_pair[1] >= 0) {
			close(client_pair[1]);
		}
		if (upstream_pair[0] >= 0) {
			close(upstream_pair[0]);
		}
		if (upstream_pair[1] >= 0) {
			close(upstream_pair[1]);
		}
		return false;
	}
	if (setsockopt(upstream_pair[1], SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) == -1) {
		close(client_pair[0]);
		close(client_pair[1]);
		close(upstream_pair[0]);
		close(upstream_pair[1]);
		return false;
	}
	pid_t relay_pid = fork();
	if (relay_pid == -1) {
		close(client_pair[0]);
		close(client_pair[1]);
		close(upstream_pair[0]);
		close(upstream_pair[1]);
		return false;
	}
	if (relay_pid == 0) {
		close(client_pair[0]);
		close(upstream_pair[0]);
		if (inject_backpressure) {
			relay_send_injection_allowance = 4096U;
			relay_send_injection_fd = upstream_pair[1];
			relay_send_injection_pending = true;
		}
		net_relay_status status = net_relay(client_pair[1], upstream_pair[1], pending_out, pending_size);
		if (inject_backpressure && relay_send_injection_pending) {
			_exit(RELAY_TEST_CHILD_ERROR);
		}
		_exit(status == NET_RELAY_CLOSED ? EXIT_SUCCESS : (status == NET_RELAY_IDLE ? EXIT_FAILURE : RELAY_TEST_CHILD_ERROR));
	}
	close(client_pair[1]);
	close(upstream_pair[1]);
	session->client_fd = client_pair[0];
	session->upstream_fd = upstream_pair[0];
	session->relay_pid = relay_pid;
	return true;
}

static bool relay_session_wait(relay_test_session *session, net_relay_status expected, int timeout_ms) {
	int status;
	if ((session == NULL) || (session->relay_pid <= 0)) {
		return false;
	}
	for (int elapsed = 0; elapsed < timeout_ms; elapsed += 20) {
		pid_t waited = waitpid(session->relay_pid, &status, WNOHANG);
		if (waited == session->relay_pid) {
			session->relay_pid = -1;
			return WIFEXITED(status) && WEXITSTATUS(status) == (expected == NET_RELAY_CLOSED ? EXIT_SUCCESS : (expected == NET_RELAY_IDLE ? EXIT_FAILURE : RELAY_TEST_CHILD_ERROR));
		}
		if ((waited == -1) && (errno != EINTR)) {
			return false;
		}
		poll(NULL, 0, 20);
	}
	return false;
}

static bool relay_set_nonblocking(int socket_fd) {
	int flags = fcntl(socket_fd, F_GETFL);
	return flags >= 0 && fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool relay_shutdown_write(int socket_fd) {
	return shutdown(socket_fd, SHUT_WR) == 0;
}

static bool relay_write_all(int socket_fd, const void *buffer, size_t size, int timeout_ms) {
	size_t offset = 0;
	while (offset < size) {
		ssize_t sent = send(socket_fd, (const uint8_t *)buffer + offset, size - offset, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (sent > 0) {
			offset += (size_t)sent;
			continue;
		}
		if ((sent < 0) && ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
			struct pollfd event = { .fd = socket_fd, .events = POLLOUT };
			if (poll(&event, 1, timeout_ms) != 1) {
				return false;
			}
			continue;
		}
		return false;
	}
	return true;
}

static bool relay_test_activity(void) {
	relay_test_session session = { .client_fd = -1, .upstream_fd = -1, .relay_pid = -1 };
	bool test_result = false;
	static const uint8_t bytes[] = { 'a', 'b', 'c', 'd', 'e' };
	CHECK(relay_session_start(&session, NULL, 0, false), "could not start activity relay");
	CHECK(relay_set_nonblocking(session.client_fd) && relay_set_nonblocking(session.upstream_fd), "could not make activity sockets nonblocking");
	for (size_t index = 0; index < sizeof(bytes); index++) {
		uint8_t received;
		CHECK(relay_write_all(session.client_fd, &bytes[index], sizeof(bytes[index]), RELAY_TEST_IO_TIMEOUT_MS), "could not send activity byte");
		CHECK(relay_read_exact(session.upstream_fd, &received, sizeof(received), RELAY_TEST_IO_TIMEOUT_MS) && received == bytes[index], "activity byte was not relayed");
		poll(NULL, 0, 250);
	}
	CHECK(relay_session_wait(&session, NET_RELAY_IDLE, RELAY_TEST_IO_TIMEOUT_MS), "positive-byte activity did not refresh idle timeout");
	test_result = true;

cleanup:
	relay_session_cleanup(&session);
	return test_result;
}

static bool relay_test_arguments(void) {
	int pair[2] = { -1, -1 };
	uint8_t byte = 0;
	bool test_result = false;
	CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0, "could not create argument sockets");
	errno = 0;
	CHECK(net_relay(pair[0], pair[1], NULL, 1) == NET_RELAY_ERROR && errno == EINVAL, "NULL non-empty seed was accepted");
	pair[0] = -1;
	pair[1] = -1;
	CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0, "could not recreate argument sockets");
	errno = 0;
	CHECK(net_relay(pair[0], pair[1], &byte, NET_RELAY_BUFFER_BYTES + 1U) == NET_RELAY_ERROR && errno == EINVAL, "oversized seed was accepted");
	pair[0] = -1;
	pair[1] = -1;
	test_result = true;

cleanup:
	if (pair[0] >= 0) {
		close(pair[0]);
	}
	if (pair[1] >= 0) {
		close(pair[1]);
	}
	return test_result;
}

static bool relay_test_half_close(bool client_first) {
	relay_test_session session = { .client_fd = -1, .upstream_fd = -1, .relay_pid = -1 };
	static const uint8_t request[] = "request";
	static const uint8_t response[] = "response";
	uint8_t received[sizeof(request)];
	uint8_t returned[sizeof(response)];
	bool test_result = false;
	CHECK(relay_session_start(&session, NULL, 0, false), "could not start half-close relay");
	if (client_first) {
		CHECK(relay_write_all(session.client_fd, request, sizeof(request), RELAY_TEST_IO_TIMEOUT_MS), "could not send client half-close request");
		CHECK(relay_shutdown_write(session.client_fd), "could not half-close client");
		CHECK(relay_read_exact(session.upstream_fd, received, sizeof(received), RELAY_TEST_IO_TIMEOUT_MS) && memcmp(received, request, sizeof(request)) == 0,
			"client half-close request was truncated");
		CHECK(relay_expect_eof(session.upstream_fd, RELAY_TEST_IO_TIMEOUT_MS), "client half-close was not propagated upstream");
		CHECK(relay_write_all(session.upstream_fd, response, sizeof(response), RELAY_TEST_IO_TIMEOUT_MS), "could not send upstream half-close response");
		CHECK(relay_shutdown_write(session.upstream_fd), "could not half-close upstream");
		CHECK(relay_read_exact(session.client_fd, returned, sizeof(returned), RELAY_TEST_IO_TIMEOUT_MS) && memcmp(returned, response, sizeof(response)) == 0,
			"upstream half-close response was truncated");
		CHECK(relay_expect_eof(session.client_fd, RELAY_TEST_IO_TIMEOUT_MS), "upstream half-close was not propagated to client");
	} else {
		CHECK(relay_write_all(session.upstream_fd, response, sizeof(response), RELAY_TEST_IO_TIMEOUT_MS), "could not send upstream-first response");
		CHECK(relay_shutdown_write(session.upstream_fd), "could not half-close upstream first");
		CHECK(relay_read_exact(session.client_fd, returned, sizeof(returned), RELAY_TEST_IO_TIMEOUT_MS) && memcmp(returned, response, sizeof(response)) == 0,
			"upstream-first response was truncated");
		CHECK(relay_expect_eof(session.client_fd, RELAY_TEST_IO_TIMEOUT_MS), "upstream-first half-close was not propagated");
		CHECK(relay_write_all(session.client_fd, request, sizeof(request), RELAY_TEST_IO_TIMEOUT_MS), "could not send client response after half-close");
		CHECK(relay_shutdown_write(session.client_fd), "could not half-close client second");
		CHECK(relay_read_exact(session.upstream_fd, received, sizeof(received), RELAY_TEST_IO_TIMEOUT_MS) && memcmp(received, request, sizeof(request)) == 0,
			"client second half-close request was truncated");
		CHECK(relay_expect_eof(session.upstream_fd, RELAY_TEST_IO_TIMEOUT_MS), "client second half-close was not propagated");
	}
	CHECK(relay_session_wait(&session, NET_RELAY_CLOSED, RELAY_TEST_IO_TIMEOUT_MS), "half-close relay did not close cleanly");
	test_result = true;

cleanup:
	relay_session_cleanup(&session);
	return test_result;
}

static bool relay_test_hup_queued(void) {
	relay_test_session session = { .client_fd = -1, .upstream_fd = -1, .relay_pid = -1 };
	const size_t payload_size = (size_t)NET_RELAY_BUFFER_BYTES * 64U;
	uint8_t *payload = NULL;
	uint8_t *received = NULL;
	size_t sent = 0;
	bool test_result = false;
	int send_buffer_size = 16384;
	CHECK(relay_session_start(&session, NULL, 0, false), "could not start queued HUP relay");
	CHECK(relay_set_nonblocking(session.client_fd) && relay_set_nonblocking(session.upstream_fd), "could not make HUP sockets nonblocking");
	CHECK(setsockopt(session.client_fd, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) == 0, "could not limit HUP send buffer");
	payload = malloc(payload_size);
	received = malloc(payload_size);
	CHECK((payload != NULL) && (received != NULL), "could not allocate HUP buffers");
	for (size_t index = 0; index < payload_size; index++) {
		payload[index] = (uint8_t)(index * 13U + 3U);
	}
	while (sent < payload_size) {
		ssize_t written = send(session.client_fd, payload + sent, payload_size - sent, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (written > 0) {
			sent += (size_t)written;
			continue;
		}
		if ((written < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
			if (sent >= NET_RELAY_BUFFER_BYTES) {
				break;
			}
			struct pollfd event = { .fd = session.client_fd, .events = POLLOUT };
			CHECK(poll(&event, 1, RELAY_TEST_IO_TIMEOUT_MS) == 1, "HUP producer did not resume before filling the relay queue");
			continue;
		}
		CHECK((written < 0) && (errno == EINTR), "HUP payload send failed");
	}
	CHECK(sent >= NET_RELAY_BUFFER_BYTES, "HUP test did not queue enough data");
	close(session.client_fd);
	session.client_fd = -1;
	poll(NULL, 0, 250);
	CHECK(relay_read_exact(session.upstream_fd, received, sent, RELAY_TEST_IO_TIMEOUT_MS) && memcmp(payload, received, sent) == 0,
		"queued HUP payload was truncated or reordered");
	CHECK(relay_expect_eof(session.upstream_fd, RELAY_TEST_IO_TIMEOUT_MS), "queued HUP EOF was not propagated");
	CHECK(relay_shutdown_write(session.upstream_fd), "could not close queued HUP reverse direction");
	CHECK(relay_session_wait(&session, NET_RELAY_CLOSED, RELAY_TEST_IO_TIMEOUT_MS), "queued HUP relay did not close cleanly");
	test_result = true;

cleanup:
	free(payload);
	free(received);
	relay_session_cleanup(&session);
	return test_result;
}

static bool relay_test_hup_unread(void) {
	relay_test_session session = { .client_fd = -1, .upstream_fd = -1, .relay_pid = -1 };
	static const uint8_t payload[] = "data before hangup";
	uint8_t received[sizeof(payload)];
	bool test_result = false;
	CHECK(relay_session_start(&session, NULL, 0, false), "could not start HUP relay");
	CHECK(relay_write_all(session.client_fd, payload, sizeof(payload), RELAY_TEST_IO_TIMEOUT_MS), "could not send HUP payload");
	close(session.client_fd);
	session.client_fd = -1;
	CHECK(relay_read_exact(session.upstream_fd, received, sizeof(received), RELAY_TEST_IO_TIMEOUT_MS) && memcmp(received, payload, sizeof(payload)) == 0,
		"HUP discarded unread payload");
	CHECK(relay_expect_eof(session.upstream_fd, RELAY_TEST_IO_TIMEOUT_MS), "HUP did not propagate EOF after unread payload");
	CHECK(relay_shutdown_write(session.upstream_fd), "could not close reverse HUP test direction");
	CHECK(relay_session_wait(&session, NET_RELAY_CLOSED, RELAY_TEST_IO_TIMEOUT_MS), "HUP relay did not close cleanly");
	test_result = true;

cleanup:
	relay_session_cleanup(&session);
	return test_result;
}

static bool relay_test_idle(void) {
	relay_test_session session = { .client_fd = -1, .upstream_fd = -1, .relay_pid = -1 };
	bool test_result = false;
	CHECK(relay_session_start(&session, NULL, 0, false), "could not start idle relay");
	CHECK(relay_session_wait(&session, NET_RELAY_IDLE, RELAY_TEST_IO_TIMEOUT_MS), "idle relay did not expire");
	test_result = true;

cleanup:
	relay_session_cleanup(&session);
	return test_result;
}

static bool relay_test_seed(void) {
	relay_test_session session = { .client_fd = -1, .upstream_fd = -1, .relay_pid = -1 };
	static const uint8_t seed[] = { 's', 'e', 'e', 'd' };
	static const uint8_t client_bytes[] = { 'c', 'l', 'i', 'e', 'n', 't' };
	static const uint8_t expected[] = { 's', 'e', 'e', 'd', 'c', 'l', 'i', 'e', 'n', 't' };
	static const uint8_t response[] = { 'r', 'e', 'p', 'l', 'y' };
	uint8_t received[sizeof(expected)];
	uint8_t returned[sizeof(response)];
	bool test_result = false;
	CHECK(relay_session_start(&session, seed, sizeof(seed), false), "could not start seed relay");
	CHECK(relay_write_all(session.client_fd, client_bytes, sizeof(client_bytes), RELAY_TEST_IO_TIMEOUT_MS), "could not send seeded client bytes");
	CHECK(relay_read_exact(session.upstream_fd, received, sizeof(received), RELAY_TEST_IO_TIMEOUT_MS) && memcmp(received, expected, sizeof(expected)) == 0,
		"seed was not sent before client bytes");
	CHECK(relay_write_all(session.upstream_fd, response, sizeof(response), RELAY_TEST_IO_TIMEOUT_MS), "could not send seed response");
	CHECK(relay_read_exact(session.client_fd, returned, sizeof(returned), RELAY_TEST_IO_TIMEOUT_MS) && memcmp(returned, response, sizeof(response)) == 0,
		"seed relay reverse traffic failed");
	CHECK(relay_shutdown_write(session.client_fd) && relay_shutdown_write(session.upstream_fd), "could not close seed relay");
	CHECK(relay_session_wait(&session, NET_RELAY_CLOSED, RELAY_TEST_IO_TIMEOUT_MS), "seed relay did not close cleanly");
	test_result = true;

cleanup:
	relay_session_cleanup(&session);
	return test_result;
}

static bool relay_test_stream(void) {
	relay_test_session session = { .client_fd = -1, .upstream_fd = -1, .relay_pid = -1 };
	struct timespec deadline;
	uint8_t *payload = NULL;
	uint8_t *received = NULL;
	const size_t payload_size = (size_t)NET_RELAY_BUFFER_BYTES * 32U;
	size_t sent = 0;
	size_t received_size = 0;
	bool test_result = false;
	int send_buffer_size = 16384;
	CHECK(relay_deadline_create(&deadline, RELAY_TEST_STREAM_TIMEOUT_MS), "could not create stream deadline");
	CHECK(relay_session_start(&session, NULL, 0, true), "could not start stream relay");
	CHECK(relay_set_nonblocking(session.client_fd) && relay_set_nonblocking(session.upstream_fd), "could not make stream sockets nonblocking");
	CHECK(setsockopt(session.client_fd, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) == 0, "could not limit stream send buffer");
	payload = malloc(payload_size);
	received = malloc(payload_size);
	CHECK((payload != NULL) && (received != NULL), "could not allocate stream buffers");
	for (size_t index = 0; index < payload_size; index++) {
		payload[index] = (uint8_t)(index * 31U + 7U);
	}
	while ((sent < payload_size) || (received_size < payload_size)) {
		int wait_ms = relay_deadline_remaining_ms(&deadline);
		CHECK(wait_ms > 0, "stream relay exceeded its absolute deadline");
		bool progress = false;
		if (sent < payload_size) {
			ssize_t written = send(session.client_fd, payload + sent, payload_size - sent, MSG_DONTWAIT | MSG_NOSIGNAL);
			if (written > 0) {
				sent += (size_t)written;
				progress = true;
			} else if ((written < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
			} else if ((written < 0) && (errno != EINTR)) {
				fprintf(stderr, "stream stopped after sending %zu and receiving %zu bytes\n", sent, received_size);
				CHECK(false, "stream payload send failed");
			}
		}
		if (received_size < payload_size) {
			ssize_t read_count = recv(session.upstream_fd, received + received_size, payload_size - received_size, MSG_DONTWAIT);
			if (read_count > 0) {
				received_size += (size_t)read_count;
				progress = true;
			} else if ((read_count < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
			} else if ((read_count < 0) && (errno != EINTR)) {
				CHECK(false, "stream payload receive failed");
			} else if (read_count == 0) {
				CHECK(false, "stream relay closed early");
			}
		}
		if (!progress) {
			struct pollfd events[2] = {
				{ .fd = session.client_fd, .events = sent < payload_size ? POLLOUT : 0 },
				{ .fd = session.upstream_fd, .events = received_size < payload_size ? POLLIN : 0 }
			};
			CHECK(poll(events, 2, wait_ms) > 0, "stream relay made no progress before its absolute deadline");
		}
	}
	CHECK(memcmp(payload, received, payload_size) == 0, "stream payload was truncated or reordered");
	CHECK(relay_shutdown_write(session.client_fd) && relay_shutdown_write(session.upstream_fd), "could not close stream relay");
	CHECK(relay_session_wait(&session, NET_RELAY_CLOSED, RELAY_TEST_IO_TIMEOUT_MS), "stream relay did not close cleanly");
	test_result = true;

cleanup:
	free(payload);
	free(received);
	relay_session_cleanup(&session);
	return test_result;
}

/* section: functions (exported) */
ssize_t __real_send(int socket_fd, const void *buffer, size_t size, int flags);

ssize_t __wrap_send(int socket_fd, const void *buffer, size_t size, int flags) {
	if (relay_send_injection_pending && socket_fd == relay_send_injection_fd) {
		if (relay_send_injection_allowance == 0) {
			relay_send_injection_pending = false;
			errno = EAGAIN;
			return -1;
		}
		if (size > relay_send_injection_allowance) {
			size = relay_send_injection_allowance;
		}
		ssize_t result = __real_send(socket_fd, buffer, size, flags);
		if (result > 0) {
			relay_send_injection_allowance -= (size_t)result;
		}
		return result;
	}
	return __real_send(socket_fd, buffer, size, flags);
}

/* section: functions (entry point) */
int main(void) {
	signal(SIGPIPE, SIG_IGN);
	if (!relay_test_arguments()) {
		fprintf(stderr, "argument test failed\n");
		return EXIT_FAILURE;
	}
	if (!relay_test_idle()) {
		fprintf(stderr, "idle test failed\n");
		return EXIT_FAILURE;
	}
	if (!relay_test_seed()) {
		fprintf(stderr, "seed test failed\n");
		return EXIT_FAILURE;
	}
	if (!relay_test_stream()) {
		fprintf(stderr, "stream test failed\n");
		return EXIT_FAILURE;
	}
	if (!relay_test_activity()) {
		fprintf(stderr, "activity test failed\n");
		return EXIT_FAILURE;
	}
	if (!relay_test_half_close(true)) {
		fprintf(stderr, "client-first half-close test failed\n");
		return EXIT_FAILURE;
	}
	if (!relay_test_half_close(false)) {
		fprintf(stderr, "upstream-first half-close test failed\n");
		return EXIT_FAILURE;
	}
	if (!relay_test_hup_queued()) {
		fprintf(stderr, "queued HUP test failed\n");
		return EXIT_FAILURE;
	}
	if (!relay_test_hup_unread()) {
		fprintf(stderr, "HUP unread-data test failed\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
