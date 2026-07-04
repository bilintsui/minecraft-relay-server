/*
 * protocol/proxy.c: Functions for PROXY protocol (v1, ASCII)
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#include <stdio.h>
#include <string.h>

#include "proxy.h"

sa_family_t protocol_proxy_getfamily(const void *src, size_t n) {
	if (src == NULL) {
		return AF_UNSPEC;
	}
	if (n > PROTOPROXY_PACKETMAXLEN) {
		return AF_UNSPEC;
	}
	if (memcmp(src, "PROXY TCP", 9)) {
		return AF_UNSPEC;
	}
	const void *src_endptr = memchr(src, '\r', n);
	if (src_endptr == NULL) {
		return AF_UNSPEC;
	}
	if (n != src_endptr - src + 2) {
		return AF_UNSPEC;
	}
	if (memcmp(src_endptr, "\r\n", 2)) {
		return AF_UNSPEC;
	}
	switch (*((char *)(src + 9))) {
		case '4':
			return AF_INET;
		case '6':
			return AF_INET6;
		default:
			return AF_UNSPEC;
	}
}

p_proxy protocol_proxy_read(const void *src, size_t n) {
	p_proxy result;
	result.family = AF_UNSPEC;
	if (src == NULL) {
		return result;
	}
	result.family = protocol_proxy_getfamily(src, n);
	if (result.family == AF_UNSPEC) {
		return result;
	}
	net_addrp srcaddrp, dstaddrp;
	sscanf(src + 11, "%s %s %hu %hu\r\n", (char *)&srcaddrp, (char *)&dstaddrp, &(result.srcport), &(result.dstport));
	result.srcaddr = net_resolve_dual((char *)&srcaddrp, result.family, 0);
	result.dstaddr = net_resolve_dual((char *)&dstaddrp, result.family, 0);
	if (result.srcaddr.err || result.dstaddr.err) {
		result.family = AF_UNSPEC;
	}
	return result;
}

size_t protocol_proxy_write(void *dst, p_proxy src) {
	net_addrp srcaddrp = net_ntop(src.family, &(src.srcaddr.addr), 0);
	net_addrp dstaddrp = net_ntop(src.family, &(src.dstaddr.addr), 0);
	switch (src.family) {
		case AF_INET:
			return snprintf(dst, PROTOPROXY_PACKETMAXLEN + 1, "PROXY TCP4 %s %s %hu %hu\r\n", (char *)&srcaddrp, (char *)&dstaddrp, src.srcport, src.dstport);
		case AF_INET6:
			return snprintf(dst, PROTOPROXY_PACKETMAXLEN + 1, "PROXY TCP6 %s %s %hu %hu\r\n", (char *)&srcaddrp, (char *)&dstaddrp, src.srcport, src.dstport);
		default:
			return 0;
	}
}

size_t protocol_proxy_write_plain(void *dst, sa_family_t family, net_addr srcaddr, net_addr dstaddr, in_port_t srcport, in_port_t dstport) {
	p_proxy data;
	data.family = family;
	data.srcaddr = srcaddr;
	data.dstaddr = dstaddr;
	data.srcport = srcport;
	data.dstport = dstport;
	return protocol_proxy_write(dst, data);
}
