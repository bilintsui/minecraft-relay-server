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
#define PROTOPROXY_PACKETMAXLEN	107U

/* section: types */
typedef struct {
	sa_family_t family;
	net_addr srcaddr, dstaddr;
	in_port_t srcport, dstport;
} p_proxy;
/* Positive values match the PROXY version numbers in listener configuration. */
typedef enum {
	PROXY_PREFIX_PARTIAL = -1,
	PROXY_PREFIX_OTHER = 0,
	PROXY_PREFIX_V1 = 1,
	PROXY_PREFIX_V2 = 2
} proxy_prefix;
typedef enum {
	PROXY_READ_INCOMPLETE,
	PROXY_READ_COMPLETE,
	PROXY_READ_MALFORMED,
	PROXY_READ_TOO_LONG
} proxy_read_status;

/* section: functions (exported) */
proxy_prefix protocol_proxy_detect(const void *src, size_t n);
/* COMPLETE consumes one header, with AF_UNSPEC for UNKNOWN. All other results consume zero bytes. */
proxy_read_status protocol_proxy_read(const void *src, size_t n, p_proxy *result, size_t *consumed);
bool protocol_proxy_socket_read(int socket_fd, p_proxy *result);
size_t protocol_proxy_write(void *dst, p_proxy src);

#endif
