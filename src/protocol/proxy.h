/*
 * protocol/proxy.h: Header file of protocol/proxy.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_PROTOCOLS_PROXY_H_INCLUDED_

#define _MRS_PROTOCOLS_PROXY_H_INCLUDED_

#define PROTOPROXY_PACKETMAXLEN	128

#include "../network.h"

typedef struct {
	sa_family_t family;
	net_addr srcaddr, dstaddr;
	in_port_t srcport, dstport;
} p_proxy;

sa_family_t protocol_proxy_getfamily(const void *src, size_t n);
p_proxy protocol_proxy_read(const void *src, size_t n);
size_t protocol_proxy_write(void *dst, p_proxy src);
size_t protocol_proxy_write_plain(void *dst, sa_family_t family, net_addr srcaddr, net_addr dstaddr, in_port_t srcport, in_port_t dstport);

#endif
