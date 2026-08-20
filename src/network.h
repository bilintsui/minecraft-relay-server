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

/* section: defines */
/* socket create mode */
#define NETSOCK_BIND	0
#define NETSOCK_CONN	1

/* error code */
#define NET_EARGFAMILY	1
#define NET_EMALLOC	2
#define NET_ENORECORD	3
#define NET_EARGACTION	4
#define NET_EARGADDR	5
#define NET_ESOCKET	6
#define NET_EREUSEADDR	7
#define NET_EBIND	8
#define NET_ELISTEN	9
#define NET_ECONNECT	10

/* section: types */
typedef struct {
	sa_family_t family;
	int err;
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
typedef struct {
	char target[128];
	in_port_t port;
} net_srvrecord;

/* section: functions (exported) */
net_addr net_addr_parse(const char *address);
net_addrp net_ntop(sa_family_t family, const void *src, bool v6addition);
int net_relay(int socket_in, int socket_out);
net_addr net_resolve_dual(const char *hostname, sa_family_t primary_family, bool dual);
int net_socket(short action, sa_family_t family, const void *address, in_port_t port, bool reuseaddr);
int net_srvresolve(char *query_name, net_srvrecord *target);

#endif
