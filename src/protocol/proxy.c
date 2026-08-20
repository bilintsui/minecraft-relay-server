/*
 * protocol/proxy.c: Functions for PROXY protocol (v1, ASCII)
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

/* section: headers (project) */
#include "../network.h"

/* section: headers (self) */
#include "proxy.h"

/* section: functions (local) */
static bool protocol_proxy_endpoint_read(const struct sockaddr_storage *source, net_addr *address, in_port_t *port) {
	memset(address, 0, sizeof(*address));
	switch (source->ss_family) {
		case AF_INET: {
			const struct sockaddr_in *source_v4 = (const struct sockaddr_in *)source;
			address->family = AF_INET;
			address->addr.v4 = source_v4->sin_addr.s_addr;
			*port = ntohs(source_v4->sin_port);
			return true;
		}
		case AF_INET6: {
			const struct sockaddr_in6 *source_v6 = (const struct sockaddr_in6 *)source;
			if (IN6_IS_ADDR_V4MAPPED(&source_v6->sin6_addr)) {
				address->family = AF_INET;
				memcpy(&address->addr.v4, &source_v6->sin6_addr.s6_addr[12], sizeof(address->addr.v4));
			} else {
				address->family = AF_INET6;
				memcpy(address->addr.v6, &source_v6->sin6_addr, sizeof(address->addr.v6));
			}
			*port = ntohs(source_v6->sin6_port);
			return true;
		}
		default:
			return false;
	}
}

/* section: functions (exported) */
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
	if (n != (size_t)((const uint8_t *)src_endptr - (const uint8_t *)src) + 2) {
		return AF_UNSPEC;
	}
	if (memcmp(src_endptr, "\r\n", 2)) {
		return AF_UNSPEC;
	}
	switch (*((const char *)src + 9)) {
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
	memset(&result, 0, sizeof(result));
	result.family = AF_UNSPEC;
	if (src == NULL) {
		return result;
	}
	result.family = protocol_proxy_getfamily(src, n);
	if (result.family == AF_UNSPEC) {
		return result;
	}
	net_addrp srcaddrp, dstaddrp;
	sscanf((const char *)src + 11, "%s %s %hu %hu\r\n", (char *)&srcaddrp, (char *)&dstaddrp, &(result.srcport), &(result.dstport));
	result.srcaddr = net_resolve_dual((char *)&srcaddrp, result.family, false);
	result.dstaddr = net_resolve_dual((char *)&dstaddrp, result.family, false);
	if (result.srcaddr.err || result.dstaddr.err) {
		result.family = AF_UNSPEC;
	}
	return result;
}

bool protocol_proxy_socket_read(int socket_fd, p_proxy *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (socket_fd < 0 || result == NULL) {
		return false;
	}
	struct sockaddr_storage destination_socket;
	struct sockaddr_storage source_socket;
	socklen_t destination_socket_size = sizeof(destination_socket);
	socklen_t source_socket_size = sizeof(source_socket);
	memset(&destination_socket, 0, sizeof(destination_socket));
	memset(&source_socket, 0, sizeof(source_socket));
	if (getpeername(socket_fd, (struct sockaddr *)&source_socket, &source_socket_size) == -1
		|| getsockname(socket_fd, (struct sockaddr *)&destination_socket, &destination_socket_size) == -1
		|| !protocol_proxy_endpoint_read(&source_socket, &result->srcaddr, &result->srcport)
		|| !protocol_proxy_endpoint_read(&destination_socket, &result->dstaddr, &result->dstport)
		|| result->srcaddr.family != result->dstaddr.family) {
		memset(result, 0, sizeof(*result));
		return false;
	}
	result->family = result->srcaddr.family;
	return true;
}

size_t protocol_proxy_write(void *dst, p_proxy src) {
	net_addrp srcaddrp = net_ntop(src.family, &(src.srcaddr.addr), false);
	net_addrp dstaddrp = net_ntop(src.family, &(src.dstaddr.addr), false);
	int result;
	switch (src.family) {
		case AF_INET:
			result = snprintf(dst, PROTOPROXY_PACKETMAXLEN + 1, "PROXY TCP4 %s %s %hu %hu\r\n", (char *)&srcaddrp, (char *)&dstaddrp, src.srcport, src.dstport);
			break;
		case AF_INET6:
			result = snprintf(dst, PROTOPROXY_PACKETMAXLEN + 1, "PROXY TCP6 %s %s %hu %hu\r\n", (char *)&srcaddrp, (char *)&dstaddrp, src.srcport, src.dstport);
			break;
		default:
			return 0;
	}
	return result > 0 ? (size_t)result : 0;
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

size_t protocol_proxy_write_socket(void *dst, int socket_fd) {
	p_proxy source;
	if (dst == NULL || !protocol_proxy_socket_read(socket_fd, &source)) {
		return 0;
	}
	return protocol_proxy_write(dst, source);
}
