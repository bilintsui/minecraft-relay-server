/*
 * resolver_helper.c: Tests for the resolver helper process runtime
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
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
#include "resolver/dns.h"
#include "resolver/helper.h"
#include "resolver/ipc.h"
#include "resolver/ipc_assembly.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* test process */
#define HELPER_TEST_SOCKET_BUFFER	1024
#define HELPER_TEST_TIMEOUT_MS		5000
#define HELPER_TEST_WAIT_INTERVAL_MS	10
#define HELPER_TEST_WAIT_INTERVAL_NS	10000000L

/* section: types */
typedef struct {
	pid_t process_id;
} helper_process_transfer;

/* section: functions (local) */
static pid_t helper_child_start(int *socket_fd) {
	if (socket_fd == NULL) {
		errno = EINVAL;
		return -1;
	}
	*socket_fd = -1;
	int sockets[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == -1) {
		return -1;
	}
	int send_buffer = HELPER_TEST_SOCKET_BUFFER;
	if (setsockopt(sockets[1], SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) == -1) {
		int saved_errno = errno;
		close(sockets[0]);
		close(sockets[1]);
		errno = saved_errno;
		return -1;
	}
	pid_t child = fork();
	if (child == -1) {
		int saved_errno = errno;
		close(sockets[0]);
		close(sockets[1]);
		errno = saved_errno;
		return -1;
	}
	if (child == 0) {
		close(sockets[0]);
		resolver_helper_status status = resolver_helper_run(sockets[1]);
		close(sockets[1]);
		_exit((int)status);
	}
	close(sockets[1]);
	*socket_fd = sockets[0];
	return child;
}

static bool helper_child_status_wait(pid_t child, int timeout_ms, int *process_status) {
	if (child <= 0 || timeout_ms < 0 || process_status == NULL) {
		errno = EINVAL;
		return false;
	}
	const struct timespec interval = { .tv_nsec = HELPER_TEST_WAIT_INTERVAL_NS };
	for (int elapsed_ms = 0; elapsed_ms <= timeout_ms; elapsed_ms += HELPER_TEST_WAIT_INTERVAL_MS) {
		int status;
		pid_t wait_result = waitpid(child, &status, WNOHANG);
		if (wait_result == child) {
			*process_status = status;
			return true;
		}
		if (wait_result == -1) {
			return false;
		}
		if (elapsed_ms < timeout_ms) {
			nanosleep(&interval, NULL);
		}
	}
	errno = ETIMEDOUT;
	return false;
}

static bool helper_child_wait(pid_t child, int timeout_ms, int *exit_status) {
	int process_status;
	if (exit_status == NULL || !helper_child_status_wait(child, timeout_ms, &process_status)) {
		return false;
	}
	*exit_status = WIFEXITED(process_status) ? WEXITSTATUS(process_status) : -1;
	return true;
}

static void helper_child_stop(pid_t *child, int *socket_fd) {
	if (socket_fd != NULL && *socket_fd != -1) {
		close(*socket_fd);
		*socket_fd = -1;
	}
	if (child == NULL || *child <= 0) {
		return;
	}
	int exit_status;
	if (!helper_child_wait(*child, 100, &exit_status)) {
		kill(*child, SIGKILL);
		waitpid(*child, NULL, 0);
	}
	*child = -1;
}

static bool helper_packet_send(int socket_fd, const void *packet, size_t packet_size) {
	while (true) {
		ssize_t sent = send(socket_fd, packet, packet_size, MSG_NOSIGNAL);
		if (sent == (ssize_t)packet_size) {
			return true;
		}
		if (sent >= 0) {
			errno = EIO;
			return false;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			return false;
		}
		struct pollfd descriptor = { .fd = socket_fd, .events = POLLOUT };
		int poll_result;
		do {
			poll_result = poll(&descriptor, 1, HELPER_TEST_TIMEOUT_MS);
		} while (poll_result == -1 && errno == EINTR);
		if (poll_result != 1 || !(descriptor.revents & POLLOUT)) {
			if (poll_result == 0) {
				errno = ETIMEDOUT;
			}
			return false;
		}
	}
}

static bool helper_process_descriptor_receive(int control_fd, pid_t *process_id, int *socket_fd) {
	if (process_id == NULL || socket_fd == NULL) {
		return false;
	}
	*process_id = -1;
	*socket_fd = -1;
	helper_process_transfer transfer;
	struct iovec payload = { .iov_base = &transfer, .iov_len = sizeof(transfer) };
	uint8_t control[CMSG_SPACE(sizeof(int))] = { 0 };
	struct msghdr message;
	memset(&message, 0, sizeof(message));
	message.msg_control = control;
	message.msg_controllen = sizeof(control);
	message.msg_iov = &payload;
	message.msg_iovlen = 1;
	ssize_t received;
	do {
		received = recvmsg(control_fd, &message, MSG_CMSG_CLOEXEC);
	} while (received == -1 && errno == EINTR);
	struct cmsghdr *header = CMSG_FIRSTHDR(&message);
	if (received != (ssize_t)sizeof(transfer) || message.msg_flags & (MSG_CTRUNC | MSG_TRUNC) || header == NULL || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS
		|| header->cmsg_len != CMSG_LEN(sizeof(int))) {
		return false;
	}
	memcpy(socket_fd, CMSG_DATA(header), sizeof(*socket_fd));
	*process_id = transfer.process_id;
	return *process_id > 0 && *socket_fd != -1;
}

static bool helper_process_descriptor_send(int control_fd, pid_t process_id, int socket_fd) {
	helper_process_transfer transfer = { .process_id = process_id };
	struct iovec payload = { .iov_base = &transfer, .iov_len = sizeof(transfer) };
	uint8_t control[CMSG_SPACE(sizeof(int))] = { 0 };
	struct msghdr message;
	memset(&message, 0, sizeof(message));
	message.msg_control = control;
	message.msg_controllen = sizeof(control);
	message.msg_iov = &payload;
	message.msg_iovlen = 1;
	struct cmsghdr *header = CMSG_FIRSTHDR(&message);
	if (header == NULL) {
		return false;
	}
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(socket_fd));
	memcpy(CMSG_DATA(header), &socket_fd, sizeof(socket_fd));
	ssize_t sent;
	do {
		sent = sendmsg(control_fd, &message, MSG_NOSIGNAL);
	} while (sent == -1 && errno == EINTR);
	return sent == (ssize_t)sizeof(transfer);
}

static bool helper_request_send(int socket_fd, uint64_t query_id, const char *query_name, uint16_t query_type) {
	resolver_ipc_request request = {
		.query_class = ns_c_in,
		.query_id = query_id,
		.query_type = query_type
	};
	if (query_name == NULL || snprintf(request.query_name, sizeof(request.query_name), "%s", query_name) < 0) {
		return false;
	}
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	return resolver_ipc_request_encode(&request, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK && helper_packet_send(socket_fd, packet, packet_size);
}

static bool helper_response_receive(int socket_fd, resolver_ipc_assembly *assembly, resolver_ipc_assembly_result *result) {
	while (true) {
		struct pollfd descriptor = { .fd = socket_fd, .events = POLLIN };
		int poll_result;
		do {
			poll_result = poll(&descriptor, 1, HELPER_TEST_TIMEOUT_MS);
		} while (poll_result == -1 && errno == EINTR);
		if (poll_result != 1 || !(descriptor.revents & POLLIN)) {
			if (poll_result == 0) {
				errno = ETIMEDOUT;
			}
			return false;
		}
		uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT + 1];
		ssize_t received;
		do {
			received = recv(socket_fd, packet, sizeof(packet), 0);
		} while (received == -1 && errno == EINTR);
		if (received <= 0 || (uintmax_t)received > RESOLVER_IPC_PACKET_BYTE_LIMIT) {
			return false;
		}
		resolver_ipc_assembly_status status = resolver_ipc_assembly_packet_consume(assembly, packet, (size_t)received);
		if (status == RESOLVER_IPC_ASSEMBLY_COMPLETE) {
			return resolver_ipc_assembly_result_take(assembly, result);
		}
		if (status != RESOLVER_IPC_ASSEMBLY_OK) {
			return false;
		}
	}
}

static int helper_time_compare(const struct timespec *left, const struct timespec *right) {
	if (left->tv_sec != right->tv_sec) {
		return left->tv_sec < right->tv_sec ? -1 : 1;
	}
	return left->tv_nsec == right->tv_nsec ? 0 : (left->tv_nsec < right->tv_nsec ? -1 : 1);
}

static bool helper_test_arguments(void) {
	pid_t process_id = 0;
	int socket_fd = 0;
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	return resolver_helper_run(-1) == RESOLVER_HELPER_BAD_ARGUMENT && resolver_helper_process_start(NULL, &process_id, &socket_fd) == -1 && process_id == -1 && socket_fd == -1
		&& resolver_helper_process_start(&signal_mask, NULL, &socket_fd) == -1 && socket_fd == -1 && resolver_helper_process_start(&signal_mask, &process_id, NULL) == -1 && process_id == -1;
}

static bool helper_test_parent_death(void) {
	int test_result = false;
	pid_t helper = -1;
	pid_t owner = -1;
	int helper_fd = -1;
	int control[2] = { -1, -1 };
	int owner_status;
	CHECK(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, control) == 0, "parent-death control channel could not be created");
	owner = fork();
	CHECK(owner != -1, "helper owner process could not be created");
	if (owner == 0) {
		close(control[0]);
		sigset_t signal_mask;
		pid_t process_id;
		int socket_fd;
		if (sigprocmask(SIG_SETMASK, NULL, &signal_mask) == -1 || resolver_helper_process_start(&signal_mask, &process_id, &socket_fd) == -1
			|| !helper_process_descriptor_send(control[1], process_id, socket_fd)) {
			_exit(EXIT_FAILURE);
		}
		close(socket_fd);
		close(control[1]);
		_exit(EXIT_SUCCESS);
	}
	close(control[1]);
	control[1] = -1;
	struct pollfd control_poll = { .fd = control[0], .events = POLLIN };
	CHECK(poll(&control_poll, 1, HELPER_TEST_TIMEOUT_MS) == 1 && (control_poll.revents & POLLIN), "helper descriptor was not transferred by its owner");
	CHECK(helper_process_descriptor_receive(control[0], &helper, &helper_fd), "helper descriptor transfer was malformed");
	CHECK(helper_child_wait(owner, HELPER_TEST_TIMEOUT_MS, &owner_status) && owner_status == EXIT_SUCCESS, "helper owner did not exit cleanly");
	owner = -1;
	struct pollfd helper_poll = { .fd = helper_fd, .events = POLLIN };
	CHECK(poll(&helper_poll, 1, HELPER_TEST_TIMEOUT_MS) == 1 && (helper_poll.revents & (POLLHUP | POLLIN)), "orphaned helper channel did not close");
	uint8_t marker;
	CHECK(recv(helper_fd, &marker, sizeof(marker), 0) == 0, "orphaned helper remained alive after parent death");
	helper = -1;
	test_result = true;

cleanup:
	if (owner > 0) {
		kill(owner, SIGKILL);
		waitpid(owner, NULL, 0);
	}
	if (helper > 0) {
		kill(helper, SIGKILL);
	}
	if (helper_fd != -1) {
		close(helper_fd);
	}
	if (control[0] != -1) {
		close(control[0]);
	}
	if (control[1] != -1) {
		close(control[1]);
	}
	return test_result;
}

static bool helper_test_process(void) {
	int test_result = false;
	pid_t child = -1;
	int socket_fd = -1;
	int process_status;
	int sentinel[2] = { -1, -1 };
	bool signal_mask_changed = false;
	sigset_t blocked_mask;
	sigset_t previous_mask;
	resolver_ipc_assembly_budget *budget = resolver_ipc_assembly_budget_create();
	resolver_ipc_assembly *assembly = NULL;
	resolver_ipc_assembly_result result = { 0 };
	CHECK(budget != NULL && pipe2(sentinel, O_CLOEXEC | O_NONBLOCK) == 0, "process test resources could not be created");
	sigemptyset(&blocked_mask);
	sigaddset(&blocked_mask, SIGTERM);
	CHECK(sigprocmask(SIG_BLOCK, &blocked_mask, &previous_mask) == 0, "parent signal mask could not be changed");
	signal_mask_changed = true;
	CHECK(resolver_helper_process_start(&previous_mask, &child, &socket_fd) == 0 && child > 0 && socket_fd != -1, "resolver helper process could not be started");
	CHECK(sigprocmask(SIG_SETMASK, &previous_mask, NULL) == 0, "parent signal mask could not be restored");
	signal_mask_changed = false;
	close(sentinel[1]);
	sentinel[1] = -1;
	struct pollfd sentinel_poll = { .fd = sentinel[0], .events = POLLIN };
	CHECK(poll(&sentinel_poll, 1, HELPER_TEST_TIMEOUT_MS) == 1 && (sentinel_poll.revents & POLLHUP), "resolver helper retained an unrelated inherited descriptor");
	int descriptor_flags = fcntl(socket_fd, F_GETFD);
	int status_flags = fcntl(socket_fd, F_GETFL);
	CHECK(descriptor_flags != -1 && (descriptor_flags & FD_CLOEXEC) && status_flags != -1 && (status_flags & O_NONBLOCK), "parent helper channel flags were incorrect");
	CHECK(resolver_ipc_assembly_create(budget, "missing.helper.test", ns_c_in, ns_t_a, 20, &assembly) == RESOLVER_IPC_ASSEMBLY_OK, "process response assembly could not be created");
	CHECK(helper_request_send(socket_fd, 20, "missing.helper.test", ns_t_a) && helper_response_receive(socket_fd, assembly, &result), "spawned helper did not process a request");
	CHECK(result.status == RESOLVER_IPC_LOOKUP_NOT_FOUND && result.query_id == 20, "spawned helper returned the wrong response");
	CHECK(kill(child, SIGUSR1) == 0, "reload signal could not be sent to helper");
	const struct timespec signal_delay = { .tv_nsec = HELPER_TEST_WAIT_INTERVAL_NS };
	nanosleep(&signal_delay, NULL);
	CHECK(kill(child, 0) == 0, "resolver helper did not ignore reload signal");
	CHECK(kill(child, SIGTERM) == 0, "termination signal could not be sent to helper");
	CHECK(helper_child_status_wait(child, HELPER_TEST_TIMEOUT_MS, &process_status), "terminated helper did not exit");
	child = -1;
	CHECK(WIFSIGNALED(process_status) && WTERMSIG(process_status) == SIGTERM, "resolver helper did not restore termination signal state");
	test_result = true;

cleanup:
	if (signal_mask_changed) {
		sigprocmask(SIG_SETMASK, &previous_mask, NULL);
	}
	resolver_ipc_assembly_result_destroy(&result);
	resolver_ipc_assembly_destroy(assembly);
	resolver_ipc_assembly_budget_destroy(budget);
	if (sentinel[0] != -1) {
		close(sentinel[0]);
	}
	if (sentinel[1] != -1) {
		close(sentinel[1]);
	}
	helper_child_stop(&child, &socket_fd);
	return test_result;
}

static bool helper_test_protocol(void) {
	int test_result = false;
	pid_t child = -1;
	int socket_fd = -1;
	int exit_status;
	uint8_t malformed = 0;

	child = helper_child_start(&socket_fd);
	CHECK(child > 0 && socket_fd != -1, "protocol helper could not be started");
	CHECK(helper_packet_send(socket_fd, &malformed, sizeof(malformed)), "malformed packet could not be sent");
	CHECK(helper_child_wait(child, HELPER_TEST_TIMEOUT_MS, &exit_status), "malformed packet did not terminate the helper");
	child = -1;
	CHECK(exit_status == RESOLVER_HELPER_PROTOCOL, "malformed packet returned the wrong helper status");
	close(socket_fd);
	socket_fd = -1;

	child = helper_child_start(&socket_fd);
	CHECK(child > 0 && socket_fd != -1, "zero-packet helper could not be started");
	CHECK(send(socket_fd, &malformed, 0, MSG_NOSIGNAL) == 0, "zero-length packet could not be sent");
	CHECK(helper_child_wait(child, HELPER_TEST_TIMEOUT_MS, &exit_status), "zero-length packet did not terminate the helper");
	child = -1;
	CHECK(exit_status == RESOLVER_HELPER_PROTOCOL, "zero-length packet returned the wrong helper status");
	close(socket_fd);
	socket_fd = -1;

	child = helper_child_start(&socket_fd);
	CHECK(child > 0 && socket_fd != -1, "oversized-packet helper could not be started");
	uint8_t oversized[RESOLVER_IPC_PACKET_BYTE_LIMIT + 1] = { 0 };
	CHECK(helper_packet_send(socket_fd, oversized, sizeof(oversized)), "oversized packet could not be sent");
	CHECK(helper_child_wait(child, HELPER_TEST_TIMEOUT_MS, &exit_status), "oversized packet did not terminate the helper");
	child = -1;
	CHECK(exit_status == RESOLVER_HELPER_PROTOCOL, "oversized packet returned the wrong helper status");
	close(socket_fd);
	socket_fd = -1;

	child = helper_child_start(&socket_fd);
	CHECK(child > 0 && socket_fd != -1, "shutdown helper could not be started");
	CHECK(shutdown(socket_fd, SHUT_WR) == 0, "helper channel could not be shut down");
	CHECK(helper_child_wait(child, HELPER_TEST_TIMEOUT_MS, &exit_status), "shutdown helper did not terminate");
	child = -1;
	CHECK(exit_status == RESOLVER_HELPER_OK, "clean channel shutdown returned the wrong helper status");
	test_result = true;

cleanup:
	helper_child_stop(&child, &socket_fd);
	return test_result;
}

static bool helper_test_responses(void) {
	int test_result = false;
	pid_t child = -1;
	int socket_fd = -1;
	int exit_status;
	resolver_ipc_assembly_budget *budget = resolver_ipc_assembly_budget_create();
	resolver_ipc_assembly *assembly = NULL;
	resolver_ipc_assembly_result result = { 0 };
	struct timespec before;
	struct timespec after;
	child = helper_child_start(&socket_fd);
	CHECK(budget != NULL && child > 0 && socket_fd != -1, "response helper could not be started");

	CHECK(resolver_ipc_assembly_create(budget, "alias.v6.helper.test", ns_c_in, ns_t_aaaa, 11, &assembly) == RESOLVER_IPC_ASSEMBLY_OK, "AAAA assembly could not be created");
	CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0 && helper_request_send(socket_fd, 11, "alias.v6.helper.test", ns_t_aaaa), "AAAA request could not be sent");
	CHECK(helper_response_receive(socket_fd, assembly, &result) && clock_gettime(CLOCK_MONOTONIC, &after) == 0, "AAAA response could not be assembled");
	CHECK(result.query_id == 11 && result.query_type == ns_t_aaaa && result.status == RESOLVER_IPC_LOOKUP_OK, "AAAA response metadata was incorrect");
	CHECK(result.payload.address.address_count == 2 && result.payload.address.cname_count == 1 && strcmp(result.payload.address.question_name, "alias.v6.helper.test") == 0
		&& strcmp(result.payload.address.canonical_name, "target.v6.helper.test") == 0, "AAAA response shape was incorrect");
	CHECK(result.payload.address.addresses[0].address.family == AF_INET6 && result.payload.address.addresses[1].address.family == AF_INET6
		&& result.payload.address.addresses[0].effective_ttl == 40 && result.payload.address.addresses[1].effective_ttl == 20, "AAAA records were incorrect");
	uint8_t expected_address[16];
	CHECK(inet_pton(AF_INET6, "2001:db8::11", expected_address) == 1 && memcmp(result.payload.address.addresses[0].address.addr.v6, expected_address, sizeof(expected_address)) == 0,
		"first AAAA address was incorrect");
	CHECK(helper_time_compare(&before, &result.completed_at) <= 0 && helper_time_compare(&result.completed_at, &after) <= 0, "AAAA completion timestamp was not monotonic");
	resolver_ipc_assembly_result_destroy(&result);
	resolver_ipc_assembly_destroy(assembly);
	assembly = NULL;

	CHECK(resolver_ipc_assembly_create(budget, "missing.helper.test", ns_c_in, ns_t_a, 12, &assembly) == RESOLVER_IPC_ASSEMBLY_OK, "negative assembly could not be created");
	CHECK(helper_request_send(socket_fd, 12, "missing.helper.test", ns_t_a) && helper_response_receive(socket_fd, assembly, &result), "negative response could not be assembled");
	CHECK(result.query_id == 12 && result.query_type == ns_t_a && result.status == RESOLVER_IPC_LOOKUP_NOT_FOUND && result.payload.address.address_count == 0
		&& result.payload.address.cname_count == 0, "resolver-level negative response was incorrect");
	resolver_ipc_assembly_result_destroy(&result);
	resolver_ipc_assembly_destroy(assembly);
	assembly = NULL;

	CHECK(resolver_ipc_assembly_create(budget, "_minecraft._tcp.bulk.helper.test", ns_c_in, ns_t_srv, 13, &assembly) == RESOLVER_IPC_ASSEMBLY_OK, "SRV assembly could not be created");
	CHECK(helper_request_send(socket_fd, 13, "_minecraft._tcp.bulk.helper.test", ns_t_srv), "SRV request could not be sent");
	const struct timespec backpressure_delay = { .tv_nsec = 100000000L };
	nanosleep(&backpressure_delay, NULL);
	CHECK(helper_response_receive(socket_fd, assembly, &result), "backpressured SRV response could not be assembled");
	CHECK(result.query_id == 13 && result.query_type == ns_t_srv && result.status == RESOLVER_IPC_LOOKUP_OK && result.payload.srv.record_count == DNS_SRV_RECORD_LIMIT,
		"SRV response metadata was incorrect");
	CHECK(result.payload.srv.records[0].priority == 0 && result.payload.srv.records[DNS_SRV_RECORD_LIMIT - 1].priority == DNS_SRV_RECORD_LIMIT - 1
		&& strstr(result.payload.srv.records[DNS_SRV_RECORD_LIMIT - 1].target, "srv127.") == result.payload.srv.records[DNS_SRV_RECORD_LIMIT - 1].target,
		"SRV response order was not preserved");
	resolver_ipc_assembly_result_destroy(&result);
	resolver_ipc_assembly_destroy(assembly);
	assembly = NULL;

	CHECK(shutdown(socket_fd, SHUT_WR) == 0, "response helper channel could not be shut down");
	CHECK(helper_child_wait(child, HELPER_TEST_TIMEOUT_MS, &exit_status), "response helper did not terminate");
	child = -1;
	CHECK(exit_status == RESOLVER_HELPER_OK, "response helper returned the wrong status");
	test_result = true;

cleanup:
	resolver_ipc_assembly_result_destroy(&result);
	resolver_ipc_assembly_destroy(assembly);
	resolver_ipc_assembly_budget_destroy(budget);
	helper_child_stop(&child, &socket_fd);
	return test_result;
}

/* section: functions (exported) */
dns_address_lookup_status __wrap_dns_address_lookup(const char *hostname, sa_family_t family, dns_address_result *result) {
	if (hostname == NULL || result == NULL) {
		return DNS_ADDRESS_LOOKUP_BAD_ARGUMENT;
	}
	if (strcmp(hostname, "missing.helper.test") == 0 && family == AF_INET) {
		return DNS_ADDRESS_LOOKUP_NOT_FOUND;
	}
	if (strcmp(hostname, "alias.v6.helper.test") != 0 || family != AF_INET6) {
		return DNS_ADDRESS_LOOKUP_BAD_ARGUMENT;
	}
	result->addresses = calloc(2, sizeof(*result->addresses));
	result->cnames = calloc(DNS_CNAME_DEPTH_LIMIT, sizeof(*result->cnames));
	if (result->addresses == NULL || result->cnames == NULL) {
		dns_address_result_destroy(result);
		return DNS_ADDRESS_LOOKUP_MEMORY;
	}
	result->address_count = 2;
	result->cname_count = 1;
	memcpy(result->question_name, "alias.v6.helper.test", sizeof("alias.v6.helper.test"));
	memcpy(result->canonical_name, "target.v6.helper.test", sizeof("target.v6.helper.test"));
	memcpy(result->cnames[0].owner, result->question_name, sizeof(result->cnames[0].owner));
	memcpy(result->cnames[0].target, result->canonical_name, sizeof(result->cnames[0].target));
	result->cnames[0].ttl = 40;
	for (size_t index = 0; index < result->address_count; index++) {
		result->addresses[index].address.family = AF_INET6;
		result->addresses[index].effective_ttl = index == 0 ? 40 : 20;
		result->addresses[index].record_ttl = index == 0 ? 100 : 20;
	}
	if (inet_pton(AF_INET6, "2001:db8::11", result->addresses[0].address.addr.v6) != 1 || inet_pton(AF_INET6, "2001:db8::12", result->addresses[1].address.addr.v6) != 1) {
		dns_address_result_destroy(result);
		return DNS_ADDRESS_LOOKUP_MALFORMED;
	}
	return DNS_ADDRESS_LOOKUP_OK;
}

dns_srv_lookup_status __wrap_dns_srv_lookup(const char *query_name, dns_srv_result *result) {
	if (query_name == NULL || result == NULL || strcmp(query_name, "_minecraft._tcp.bulk.helper.test") != 0) {
		return DNS_SRV_LOOKUP_BAD_ARGUMENT;
	}
	result->records = calloc(DNS_SRV_RECORD_LIMIT, sizeof(*result->records));
	if (result->records == NULL) {
		return DNS_SRV_LOOKUP_MEMORY;
	}
	result->record_count = DNS_SRV_RECORD_LIMIT;
	memcpy(result->question_name, "_minecraft._tcp.bulk.helper.test", sizeof("_minecraft._tcp.bulk.helper.test"));
	memcpy(result->canonical_name, result->question_name, sizeof(result->canonical_name));
	for (size_t index = 0; index < result->record_count; index++) {
		dns_srv_record *record = &result->records[index];
		record->effective_ttl = 60;
		record->port = (in_port_t)(25565U + index);
		record->priority = (uint16_t)index;
		record->record_ttl = 60;
		record->weight = (uint16_t)(DNS_SRV_RECORD_LIMIT - index);
		int target_size = snprintf(record->target, sizeof(record->target),
			"srv%03zu.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.helper.test", index);
		if (target_size <= 0 || (size_t)target_size >= sizeof(record->target)) {
			dns_srv_result_destroy(result);
			return DNS_SRV_LOOKUP_MALFORMED;
		}
	}
	return DNS_SRV_LOOKUP_OK;
}

/* section: functions (entry point) */
int main(void) {
	int test_result = EXIT_FAILURE;
	CHECK(helper_test_arguments(), "helper argument tests failed");
	CHECK(helper_test_parent_death(), "helper parent-death tests failed");
	CHECK(helper_test_process(), "helper process tests failed");
	CHECK(helper_test_protocol(), "helper protocol tests failed");
	CHECK(helper_test_responses(), "helper response tests failed");
	test_result = EXIT_SUCCESS;

cleanup:
	return test_result;
}
