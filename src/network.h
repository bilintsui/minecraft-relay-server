/*
 * network.h: Header file of network.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_NETWORK_H_INCLUDED_

#define _MRS_NETWORK_H_INCLUDED_

/* section: headers (library) */
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* section: defines */
#ifndef NET_RELAY_BUFFER_BYTES
#define NET_RELAY_BUFFER_BYTES	16384U
#endif
#ifndef NET_RELAY_IDLE_TIMEOUT_SEC
#define NET_RELAY_IDLE_TIMEOUT_SEC	300
#endif

#if NET_RELAY_BUFFER_BYTES < 1
#error "The relay buffer size must be positive."
#endif
#if NET_RELAY_IDLE_TIMEOUT_SEC < 1 || NET_RELAY_IDLE_TIMEOUT_SEC > INT_MAX
#error "The relay idle timeout must be between 1 and INT_MAX seconds."
#endif

/* section: types */
typedef enum {
	NET_OK,
	NET_EARGFAMILY,
	NET_EMALLOC,
	NET_ENORECORD,
	NET_EARGACTION,
	NET_EARGADDR,
	NET_ESOCKET,
	NET_EREUSEADDR,
	NET_EBIND,
	NET_ELISTEN,
	NET_ECONNECT
} net_error;
typedef struct {
	sa_family_t family;
	net_error err;
	union {
		uint32_t v4;
		uint8_t v6[16];
	} addr;
} net_addr;
typedef union {
	char v4[INET_ADDRSTRLEN];
	char v6[INET6_ADDRSTRLEN + 2];
} net_addrp;
typedef struct {
	sa_family_t family;
	net_addrp address, address_clean;
	in_port_t port;
} net_addrbundle;
typedef enum {
	NET_CONNECT_OK,
	NET_CONNECT_PENDING,
	NET_CONNECT_FAILURE,
	NET_CONNECT_BAD_ARGUMENT,
	NET_CONNECT_INTERNAL
} net_connect_status;
typedef enum {
	NET_RELAY_CLOSED,
	NET_RELAY_ERROR,
	NET_RELAY_IDLE
} net_relay_status;
typedef enum {
	NETSOCK_BIND,
	NETSOCK_CONN
} net_socket_action;

/* section: functions (exported) */
net_addr net_addr_parse(const char *address);
net_connect_status net_connect_nonblocking(const net_addr *address, in_port_t port, int *socket_fd);
net_connect_status net_connect_nonblocking_complete(int socket_fd);
net_addrp net_ntop(sa_family_t family, const void *src, bool v6addition);
/* Takes ownership of both socket descriptors and closes them on every return path. */
net_relay_status net_relay(int socket_in, int socket_out, const void *pending_out, size_t pending_size);
int net_socket(net_socket_action action, sa_family_t family, const void *address, in_port_t port, bool reuseaddr);

#endif
