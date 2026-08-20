/*
 * network.h: Header file of network.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_NETWORK_H_INCLUDED_

#define _MRS_NETWORK_H_INCLUDED_

/* section: headers (library) */
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

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
	NETSOCK_BIND,
	NETSOCK_CONN
} net_socket_action;

/* section: functions (exported) */
net_addr net_addr_parse(const char *address);
net_connect_status net_connect_nonblocking(const net_addr *address, in_port_t port, int *socket_fd);
net_connect_status net_connect_nonblocking_complete(int socket_fd);
net_addrp net_ntop(sa_family_t family, const void *src, bool v6addition);
int net_relay(int socket_in, int socket_out);
net_addr net_resolve_dual(const char *hostname, sa_family_t primary_family, bool dual);
int net_socket(net_socket_action action, sa_family_t family, const void *address, in_port_t port, bool reuseaddr);

#endif
