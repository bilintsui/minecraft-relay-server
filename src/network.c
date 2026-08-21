/*
 * network.c: Functions for fundamental communications
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* section: headers (self) */
#include "network.h"

/* section: functions (local) */
/* section: functions (exported) */
net_addr net_addr_parse(const char *address) {
	net_addr result;
	memset(&result, 0, sizeof(result));
	if (address != NULL && inet_pton(AF_INET, address, &result.addr.v4) == 1) {
		result.family = AF_INET;
		return result;
	}
	memset(&result.addr, 0, sizeof(result.addr));
	if (address != NULL && inet_pton(AF_INET6, address, result.addr.v6) == 1) {
		result.family = AF_INET6;
		return result;
	}
	result.err = NET_EARGADDR;
	return result;
}

net_connect_status net_connect_nonblocking(const net_addr *address, in_port_t port, int *socket_fd) {
	struct sockaddr_in address_v4;
	struct sockaddr_in6 address_v6;
	socklen_t address_size;
	const struct sockaddr *socket_address;
	int connect_error, result;
	if (socket_fd == NULL || address == NULL || address->err != NET_OK || ((address->family != AF_INET) && (address->family != AF_INET6))) {
		if (socket_fd != NULL) {
			*socket_fd = -1;
		}
		errno = NET_EARGADDR;
		return NET_CONNECT_BAD_ARGUMENT;
	}
	*socket_fd = -1;
	if (address->family == AF_INET) {
		memset(&address_v4, 0, sizeof(address_v4));
		address_v4.sin_family = AF_INET;
		address_v4.sin_port = htons(port);
		memcpy(&address_v4.sin_addr, &address->addr.v4, sizeof(address_v4.sin_addr));
		address_size = sizeof(address_v4);
		socket_address = (const struct sockaddr *)&address_v4;
	} else {
		memset(&address_v6, 0, sizeof(address_v6));
		address_v6.sin6_family = AF_INET6;
		address_v6.sin6_port = htons(port);
		memcpy(&address_v6.sin6_addr, &address->addr.v6, sizeof(address_v6.sin6_addr));
		address_size = sizeof(address_v6);
		socket_address = (const struct sockaddr *)&address_v6;
	}
	result = socket(address->family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (result == -1) {
		return NET_CONNECT_INTERNAL;
	}
	if (connect(result, socket_address, address_size) == 0) {
		*socket_fd = result;
		return NET_CONNECT_OK;
	}
	if ((errno == EINPROGRESS) || (errno == EALREADY) || (errno == EINTR)) {
		*socket_fd = result;
		return NET_CONNECT_PENDING;
	}
	connect_error = errno;
	close(result);
	errno = connect_error;
	return NET_CONNECT_FAILURE;
}

net_connect_status net_connect_nonblocking_complete(int socket_fd) {
	int socket_error;
	socklen_t socket_error_size = sizeof(socket_error);
	if (socket_fd < 0) {
		errno = NET_EARGADDR;
		return NET_CONNECT_BAD_ARGUMENT;
	}
	if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_size) == -1) {
		return NET_CONNECT_INTERNAL;
	}
	if (socket_error != 0) {
		errno = socket_error;
		return NET_CONNECT_FAILURE;
	}
	return NET_CONNECT_OK;
}

net_addrp net_ntop(sa_family_t family, const void *src, bool v6addition) {
	net_addrp pre_result;
	memset(&pre_result, 0, sizeof(pre_result));
	if (((family != AF_INET) && (family != AF_INET6)) || (src == NULL) || (inet_ntop(family, src, (char *)&pre_result, sizeof(pre_result)) == NULL)) {
		return pre_result;
	}
	if ((v6addition) && (family == AF_INET6)) {
		net_addrp result;
		memset(&result, 0, sizeof(result));
		snprintf((char *)&result, sizeof(result), "[%s]", (char *)&pre_result);
		return result;
	}
	return pre_result;
}

/*
 * net_relay - bidirectional zero-copy relay between two sockets.
 * Both sockets must be blocking (no O_NONBLOCK).  splice() on a
 * non-blocking socket can return EAGAIN/EWOULDBLOCK, which the
 * current EPOLLIN-only design does not handle.
 */
int net_relay(int socket_in, int socket_out) {
	int pipefd[2] = { -1, -1 };
	struct epoll_event ev, events[2];
	int epfd = -1, nfds, i, src, dst, ret = 0, pipe_sz;
	ssize_t bytes, written, res;
	if (pipe(pipefd) == -1) {
		ret = -1;
		goto cleanup;
	}
	pipe_sz = fcntl(pipefd[0], F_GETPIPE_SZ);
	if (pipe_sz <= 0) {
		pipe_sz = 65536;
	}
	epfd = epoll_create(2);
	if (epfd == -1) {
		ret = -1;
		goto cleanup;
	}
	ev.events = EPOLLIN;
	ev.data.fd = socket_in;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, socket_in, &ev) == -1) {
		ret = -1;
		goto cleanup;
	}
	ev.data.fd = socket_out;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, socket_out, &ev) == -1) {
		ret = -1;
		goto cleanup;
	}
	while (1) {
		nfds = epoll_wait(epfd, events, 2, -1);
		if (nfds == -1) {
			if (errno == EINTR) {
				continue;
			}
			ret = -1;
			goto cleanup;
		}
		for (i = 0; i < nfds; i++) {
			if (events[i].events & (EPOLLERR | EPOLLHUP)) {
				goto cleanup;
			}
			if (events[i].events & EPOLLIN) {
				src = events[i].data.fd;
				dst = (src == socket_in) ? socket_out : socket_in;
				bytes = splice(src, NULL, pipefd[1], NULL, pipe_sz, SPLICE_F_MOVE);
				if (bytes == 0) {
					goto cleanup;
				}
				if (bytes < 0) {
					if (errno == EINTR) {
						continue;
					}
					goto cleanup;
				}
				written = 0;
				while (written < bytes) {
					res = splice(pipefd[0], NULL, dst, NULL, bytes - written, SPLICE_F_MOVE);
					if (res <= 0) {
						if (res < 0 && errno == EINTR) {
							continue;
						}
						goto cleanup;
					}
					written += res;
				}
			}
		}
	}
cleanup:
	close(socket_in);
	close(socket_out);
	if (pipefd[0] != -1) {
		close(pipefd[0]);
	}
	if (pipefd[1] != -1) {
		close(pipefd[1]);
	}
	if (epfd != -1) {
		close(epfd);
	}
	return ret;
}

int net_socket(net_socket_action action, sa_family_t family, const void *address, in_port_t port, bool reuseaddr) {
	if ((action != NETSOCK_BIND) && (action != NETSOCK_CONN)) {
		errno = NET_EARGACTION;
		return -1;
	}
	if ((family != AF_INET) && (family != AF_INET6)) {
		errno = NET_EARGFAMILY;
		return -1;
	}
	if (address == NULL) {
		errno = NET_EARGADDR;
		return -1;
	}
	void *serv_addr = NULL;
	socklen_t stru_size = 0;
	if (family == AF_INET) {
		stru_size = sizeof(struct sockaddr_in);
		serv_addr = malloc(stru_size);
		if (serv_addr == NULL) {
			errno = NET_EMALLOC;
			return -1;
		}
		memset(serv_addr, 0, stru_size);
		struct sockaddr_in *addr = serv_addr;
		addr->sin_family = AF_INET;
		addr->sin_port = htons(port);
		memcpy(&(addr->sin_addr.s_addr), address, sizeof(uint32_t));
	} else if (family == AF_INET6) {
		stru_size = sizeof(struct sockaddr_in6);
		serv_addr = malloc(stru_size);
		if (serv_addr == NULL) {
			errno = NET_EMALLOC;
			return -1;
		}
		memset(serv_addr, 0, stru_size);
		struct sockaddr_in6 *addr = serv_addr;
		addr->sin6_family = AF_INET6;
		addr->sin6_port = htons(port);
		memcpy(&(addr->sin6_addr), address, sizeof(uint8_t) * 16);
	}
	int result = socket(family, SOCK_STREAM, 0);
	if (result == -1) {
		free(serv_addr);
		errno = NET_ESOCKET;
		return -1;
	}
	if (reuseaddr) {
		int socket_opt = 1;
		if (setsockopt(result, SOL_SOCKET, SO_REUSEADDR, &socket_opt, sizeof(socket_opt)) == -1) {
			free(serv_addr);
			close(result);
			errno = NET_EREUSEADDR;
			return -1;
		}
	}
	if (action == NETSOCK_BIND) {
		if (bind(result, serv_addr, stru_size) == -1) {
			free(serv_addr);
			close(result);
			errno = NET_EBIND;
			return -1;
		} else {
			/* Linux caps INT_MAX to the current net.core.somaxconn value. */
			if (listen(result, INT_MAX) == -1) {
				free(serv_addr);
				close(result);
				errno = NET_ELISTEN;
				return -1;
			}
		}
	} else if (action == NETSOCK_CONN) {
		if (connect(result, serv_addr, stru_size) == -1) {
			free(serv_addr);
			close(result);
			errno = NET_ECONNECT;
			return -1;
		}
	}
	free(serv_addr);
	return result;
}
