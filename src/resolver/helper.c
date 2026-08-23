/*
 * resolver/helper.c: Resolver helper process runtime
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "dns.h"
#include "ipc.h"

/* section: headers (self) */
#include "helper.h"

/* section: defines */
/* packet */
#define RESOLVER_HELPER_RECEIVE_BYTE_CAPACITY	(RESOLVER_IPC_PACKET_BYTE_LIMIT + 1U)

/* process */
#define RESOLVER_HELPER_PROCESS_SOCKET_FD	3

/* section: types */
typedef enum {
	RESOLVER_HELPER_RECEIVE_DATA,
	RESOLVER_HELPER_RECEIVE_END,
	RESOLVER_HELPER_RECEIVE_IO,
	RESOLVER_HELPER_RECEIVE_PROTOCOL
} resolver_helper_receive_status;

/* section: functions (local) */
static resolver_helper_status resolver_helper_event_wait(int socket_fd, short events, short *result) {
	if (result == NULL) {
		return RESOLVER_HELPER_BAD_ARGUMENT;
	}
	struct pollfd descriptor = {
		.fd = socket_fd,
		.events = events
	};
	int poll_result;
	do {
		poll_result = poll(&descriptor, 1, -1);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result != 1 || descriptor.revents & POLLNVAL) {
		return RESOLVER_HELPER_IO;
	}
	*result = descriptor.revents;
	return RESOLVER_HELPER_OK;
}

static resolver_helper_receive_status resolver_helper_packet_receive(int socket_fd, void *packet, size_t packet_capacity, size_t *packet_size) {
	if (packet == NULL || packet_size == NULL || packet_capacity <= RESOLVER_IPC_PACKET_BYTE_LIMIT) {
		return RESOLVER_HELPER_RECEIVE_PROTOCOL;
	}
	*packet_size = 0;
	while (true) {
		short events;
		if (resolver_helper_event_wait(socket_fd, POLLIN, &events) != RESOLVER_HELPER_OK) {
			return RESOLVER_HELPER_RECEIVE_IO;
		}
		if (!(events & POLLIN)) {
			return events & POLLHUP ? RESOLVER_HELPER_RECEIVE_END : RESOLVER_HELPER_RECEIVE_IO;
		}
		ssize_t received = recv(socket_fd, packet, packet_capacity, 0);
		if (received > 0) {
			if ((uintmax_t)received > RESOLVER_IPC_PACKET_BYTE_LIMIT) {
				return RESOLVER_HELPER_RECEIVE_PROTOCOL;
			}
			*packet_size = (size_t)received;
			return RESOLVER_HELPER_RECEIVE_DATA;
		}
		if (received == 0) {
			uint8_t marker;
			ssize_t peeked;
			do {
				peeked = recv(socket_fd, &marker, sizeof(marker), MSG_DONTWAIT | MSG_PEEK);
			} while (peeked == -1 && errno == EINTR);
			if (peeked == 0) {
				return RESOLVER_HELPER_RECEIVE_END;
			}
			return peeked > 0 || errno == EAGAIN || errno == EWOULDBLOCK ? RESOLVER_HELPER_RECEIVE_PROTOCOL : RESOLVER_HELPER_RECEIVE_IO;
		}
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
			return RESOLVER_HELPER_RECEIVE_IO;
		}
	}
}

static resolver_helper_status resolver_helper_packet_send(int socket_fd, const void *packet, size_t packet_size) {
	if (packet == NULL || packet_size == 0 || packet_size > RESOLVER_IPC_PACKET_BYTE_LIMIT) {
		return RESOLVER_HELPER_INTERNAL;
	}
	while (true) {
		ssize_t sent = send(socket_fd, packet, packet_size, MSG_NOSIGNAL);
		if (sent == (ssize_t)packet_size) {
			return RESOLVER_HELPER_OK;
		}
		if (sent >= 0) {
			return RESOLVER_HELPER_IO;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			return RESOLVER_HELPER_IO;
		}
		short events;
		resolver_helper_status status = resolver_helper_event_wait(socket_fd, POLLOUT, &events);
		if (status != RESOLVER_HELPER_OK || !(events & POLLOUT)) {
			return RESOLVER_HELPER_IO;
		}
	}
}

static int resolver_helper_process_descriptors_prepare(int socket_fd) {
	if (socket_fd != RESOLVER_HELPER_PROCESS_SOCKET_FD) {
		if (dup3(socket_fd, RESOLVER_HELPER_PROCESS_SOCKET_FD, O_CLOEXEC) == -1) {
			return -1;
		}
		close(socket_fd);
	}
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	closefrom(RESOLVER_HELPER_PROCESS_SOCKET_FD + 1);
	return RESOLVER_HELPER_PROCESS_SOCKET_FD;
}

static int resolver_helper_process_signals_restore(const sigset_t *signal_mask) {
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);
	action.sa_handler = SIG_IGN;
	if (sigaction(SIGUSR1, &action, NULL) == -1) {
		return -1;
	}
	action.sa_handler = SIG_DFL;
	if (sigaction(SIGINT, &action, NULL) == -1 || sigaction(SIGTERM, &action, NULL) == -1) {
		return -1;
	}
	return sigprocmask(SIG_SETMASK, signal_mask, NULL);
}

static resolver_helper_status resolver_helper_process_child_run(int socket_fd, pid_t parent_pid, const sigset_t *signal_mask, const char *process_name) {
	if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1 || getppid() != parent_pid || resolver_helper_process_signals_restore(signal_mask) == -1) {
		return RESOLVER_HELPER_INTERNAL;
	}
	(void)prctl(PR_SET_NAME, process_name);
	socket_fd = resolver_helper_process_descriptors_prepare(socket_fd);
	if (socket_fd == -1) {
		return RESOLVER_HELPER_INTERNAL;
	}
	resolver_helper_status status = resolver_helper_run(socket_fd);
	close(socket_fd);
	return status;
}

static resolver_helper_status resolver_helper_response_address_packet_send(int socket_fd, const resolver_ipc_response_address *response) {
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_address_encode(response, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK) {
		return RESOLVER_HELPER_INTERNAL;
	}
	return resolver_helper_packet_send(socket_fd, packet, packet_size);
}

static resolver_helper_status resolver_helper_response_begin_send(int socket_fd, const resolver_ipc_response_begin *response) {
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_begin_encode(response, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK) {
		return RESOLVER_HELPER_INTERNAL;
	}
	return resolver_helper_packet_send(socket_fd, packet, packet_size);
}

static resolver_helper_status resolver_helper_response_cname_send(int socket_fd, const resolver_ipc_response_cname *response) {
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_cname_encode(response, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK) {
		return RESOLVER_HELPER_INTERNAL;
	}
	return resolver_helper_packet_send(socket_fd, packet, packet_size);
}

static resolver_helper_status resolver_helper_response_end_send(int socket_fd, const resolver_ipc_response_end *response) {
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_end_encode(response, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK) {
		return RESOLVER_HELPER_INTERNAL;
	}
	return resolver_helper_packet_send(socket_fd, packet, packet_size);
}

static resolver_helper_status resolver_helper_response_address_send(int socket_fd, const resolver_ipc_request *request) {
	dns_address_result result = { 0 };
	sa_family_t family = request->query_type == ns_t_a ? AF_INET : AF_INET6;
	dns_address_lookup_status lookup_status = dns_address_lookup(request->query_name, family, &result);
	resolver_ipc_lookup_status response_status;
	struct timespec completed_at;
	if (!resolver_ipc_lookup_status_from_address(lookup_status, &response_status) || clock_gettime(CLOCK_MONOTONIC, &completed_at) == -1) {
		dns_address_result_destroy(&result);
		return RESOLVER_HELPER_INTERNAL;
	}
	resolver_ipc_response_begin begin = {
		.cname_count = result.cname_count,
		.completed_at = completed_at,
		.negative = result.negative,
		.query_class = request->query_class,
		.query_id = request->query_id,
		.query_type = request->query_type,
		.rcode = result.rcode,
		.record_count = result.address_count,
		.status = response_status
	};
	memcpy(begin.canonical_name, result.canonical_name, sizeof(begin.canonical_name));
	memcpy(begin.question_name, result.question_name, sizeof(begin.question_name));
	resolver_helper_status status = resolver_helper_response_begin_send(socket_fd, &begin);
	for (size_t index = 0; status == RESOLVER_HELPER_OK && index < result.cname_count; index++) {
		resolver_ipc_response_cname cname = {
			.index = (uint16_t)index,
			.query_id = request->query_id,
			.record = result.cnames[index]
		};
		status = resolver_helper_response_cname_send(socket_fd, &cname);
	}
	for (size_t index = 0; status == RESOLVER_HELPER_OK && index < result.address_count; index++) {
		resolver_ipc_response_address address = {
			.index = (uint16_t)index,
			.query_id = request->query_id,
			.record = result.addresses[index]
		};
		status = resolver_helper_response_address_packet_send(socket_fd, &address);
	}
	if (status == RESOLVER_HELPER_OK) {
		resolver_ipc_response_end end = {
			.cname_count = result.cname_count,
			.query_id = request->query_id,
			.record_count = result.address_count
		};
		status = resolver_helper_response_end_send(socket_fd, &end);
	}
	dns_address_result_destroy(&result);
	return status;
}

static resolver_helper_status resolver_helper_response_srv_packet_send(int socket_fd, const resolver_ipc_response_srv *response) {
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_srv_encode(response, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK) {
		return RESOLVER_HELPER_INTERNAL;
	}
	return resolver_helper_packet_send(socket_fd, packet, packet_size);
}

static resolver_helper_status resolver_helper_response_srv_send(int socket_fd, const resolver_ipc_request *request) {
	dns_srv_result result = { 0 };
	dns_srv_lookup_status lookup_status = dns_srv_lookup(request->query_name, &result);
	resolver_ipc_lookup_status response_status;
	struct timespec completed_at;
	if (!resolver_ipc_lookup_status_from_srv(lookup_status, &response_status) || clock_gettime(CLOCK_MONOTONIC, &completed_at) == -1) {
		dns_srv_result_destroy(&result);
		return RESOLVER_HELPER_INTERNAL;
	}
	resolver_ipc_response_begin begin = {
		.cname_count = result.cname_count,
		.completed_at = completed_at,
		.negative = result.negative,
		.query_class = request->query_class,
		.query_id = request->query_id,
		.query_type = request->query_type,
		.rcode = result.rcode,
		.record_count = result.record_count,
		.status = response_status
	};
	memcpy(begin.canonical_name, result.canonical_name, sizeof(begin.canonical_name));
	memcpy(begin.question_name, result.question_name, sizeof(begin.question_name));
	resolver_helper_status status = resolver_helper_response_begin_send(socket_fd, &begin);
	for (size_t index = 0; status == RESOLVER_HELPER_OK && index < result.cname_count; index++) {
		resolver_ipc_response_cname cname = {
			.index = (uint16_t)index,
			.query_id = request->query_id,
			.record = result.cnames[index]
		};
		status = resolver_helper_response_cname_send(socket_fd, &cname);
	}
	for (size_t index = 0; status == RESOLVER_HELPER_OK && index < result.record_count; index++) {
		resolver_ipc_response_srv record = {
			.index = (uint16_t)index,
			.query_id = request->query_id,
			.record = result.records[index]
		};
		status = resolver_helper_response_srv_packet_send(socket_fd, &record);
	}
	if (status == RESOLVER_HELPER_OK) {
		resolver_ipc_response_end end = {
			.cname_count = result.cname_count,
			.query_id = request->query_id,
			.record_count = result.record_count
		};
		status = resolver_helper_response_end_send(socket_fd, &end);
	}
	dns_srv_result_destroy(&result);
	return status;
}

/* section: functions (exported) */
int resolver_helper_process_start(const sigset_t *signal_mask, const char *process_name, pid_t *process_id, int *socket_fd) {
	if (process_id != NULL) {
		*process_id = -1;
	}
	if (socket_fd != NULL) {
		*socket_fd = -1;
	}
	if (signal_mask == NULL || process_name == NULL || process_name[0] == '\0' || process_id == NULL || socket_fd == NULL) {
		errno = EINVAL;
		return -1;
	}
	int sockets[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == -1) {
		return -1;
	}
	pid_t parent_pid = getpid();
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
		_exit((int)resolver_helper_process_child_run(sockets[1], parent_pid, signal_mask, process_name));
	}
	close(sockets[1]);
	*process_id = child;
	*socket_fd = sockets[0];
	return 0;
}

resolver_helper_status resolver_helper_run(int socket_fd) {
	if (socket_fd < 0) {
		return RESOLVER_HELPER_BAD_ARGUMENT;
	}
	while (true) {
		/* The extra byte detects an oversized record without relying on MSG_TRUNC support for AF_UNIX SOCK_SEQPACKET. */
		uint8_t packet[RESOLVER_HELPER_RECEIVE_BYTE_CAPACITY];
		size_t packet_size;
		resolver_helper_receive_status receive_status = resolver_helper_packet_receive(socket_fd, packet, sizeof(packet), &packet_size);
		if (receive_status == RESOLVER_HELPER_RECEIVE_END) {
			return RESOLVER_HELPER_OK;
		}
		if (receive_status == RESOLVER_HELPER_RECEIVE_IO) {
			return RESOLVER_HELPER_IO;
		}
		if (receive_status != RESOLVER_HELPER_RECEIVE_DATA) {
			return RESOLVER_HELPER_PROTOCOL;
		}
		resolver_ipc_request request;
		if (resolver_ipc_request_decode(packet, packet_size, &request) != RESOLVER_IPC_CODEC_OK) {
			return RESOLVER_HELPER_PROTOCOL;
		}
		resolver_helper_status status = request.query_type == ns_t_srv ? resolver_helper_response_srv_send(socket_fd, &request)
			: resolver_helper_response_address_send(socket_fd, &request);
		if (status != RESOLVER_HELPER_OK) {
			return status;
		}
	}
}
