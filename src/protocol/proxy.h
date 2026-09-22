/*
 * protocol/proxy.h: Header file of protocol/proxy.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_PROTOCOLS_PROXY_H_INCLUDED_

#define _MRS_PROTOCOLS_PROXY_H_INCLUDED_

/* section: headers (library) */
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

/* section: headers (project) */
#include "../network.h"

/* section: defines */
/* limit */
#define PROTOPROXY_PACKETMAXLEN	128

/* section: types */
typedef struct {
	sa_family_t family;
	net_addr srcaddr, dstaddr;
	in_port_t srcport, dstport;
} p_proxy;

/* section: functions (exported) */
/* Retained for planned inbound PROXY v1 support; currently exercised only by tests. */
p_proxy protocol_proxy_read(const void *src, size_t n);
bool protocol_proxy_socket_read(int socket_fd, p_proxy *result);
size_t protocol_proxy_write(void *dst, p_proxy src);

#endif
