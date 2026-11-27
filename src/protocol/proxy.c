/*
 * protocol/proxy.c: Functions for PROXY protocol (v1, ASCII)
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
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
static bool protocol_proxy_field_address(const char **cursor, const char *end, sa_family_t family, net_addr *address) {
	char text[INET6_ADDRSTRLEN];
	const char *space = memchr(*cursor, ' ', (size_t)(end - *cursor));
	size_t length = (space != NULL) ? (size_t)(space - *cursor) : (size_t)(end - *cursor);
	if ((space == NULL) || (length == 0) || (length >= sizeof(text)) || (memchr(*cursor, '\0', length) != NULL)) {
		return false;
	}
	memcpy(text, *cursor, length);
	text[length] = '\0';
	*cursor += length;
	*address = net_addr_parse(text);
	/* Dual-stack senders can use a dotted IPv4 tail for mapped TCP6 endpoints. */
	return address->family == family && (family != AF_INET6 || strchr(text, '.') == NULL || net_addr_is_v4mapped(address));
}

static bool protocol_proxy_field_port(const char **cursor, const char *end, in_port_t *dst) {
	unsigned int value = 0;
	size_t length = 0;
	while (((*cursor + length) < end) && ((*cursor)[length] >= '0') && ((*cursor)[length] <= '9')) {
		value *= 10U;
		value += (unsigned int)((*cursor)[length] - '0');
		if (value > 65535U) {
			return false;
		}
		length++;
	}
	if (length == 0 || (length > 1 && **cursor == '0')) {
		return false;
	}
	*dst = (in_port_t)value;
	*cursor += length;
	return true;
}

static bool protocol_proxy_field_space(const char **cursor, const char *end) {
	if ((*cursor >= end) || (**cursor != ' ')) {
		return false;
	}
	(*cursor)++;
	return true;
}

/* inet_ntop can use a dotted tail for IPv6. The v1 wire representation uses hexadecimal groups. */
static net_addrp protocol_proxy_format_address(const net_addr *address) {
	net_addrp text = net_ntop(address->family, &address->addr, false);
	if (address->family == AF_INET6 && strchr(text.v6, '.') != NULL) {
		const uint8_t *bytes = address->addr.v6;
		const char *prefix = net_addr_is_v4mapped(address) ? "::ffff:" : "::";
		snprintf(text.v6, sizeof(text.v6), "%s%x:%x", prefix, (bytes[12] << 8) | bytes[13], (bytes[14] << 8) | bytes[15]);
	}
	return text;
}

static void protocol_proxy_normalize(p_proxy *pair) {
	net_addr source = pair->srcaddr, destination = pair->dstaddr;
	if (net_addr_unmap(&source) && net_addr_unmap(&destination)) {
		pair->family = AF_INET;
		pair->srcaddr = source;
		pair->dstaddr = destination;
	}
}

static bool protocol_proxy_tcp_read(const char *cursor, const char *end, sa_family_t family, p_proxy *result) {
	p_proxy pair = { .family = family };
	if (!protocol_proxy_field_address(&cursor, end, family, &pair.srcaddr) || !protocol_proxy_field_space(&cursor, end)
		|| !protocol_proxy_field_address(&cursor, end, family, &pair.dstaddr) || !protocol_proxy_field_space(&cursor, end)
		|| !protocol_proxy_field_port(&cursor, end, &pair.srcport) || !protocol_proxy_field_space(&cursor, end) || !protocol_proxy_field_port(&cursor, end, &pair.dstport) || cursor != end) {
		return false;
	}
	protocol_proxy_normalize(&pair);
	*result = pair;
	return true;
}

/* section: functions (exported) */
proxy_prefix protocol_proxy_detect(const void *src, size_t n) {
	static const char v1[] = "PROXY ";
	static const char v2[] = "\r\n\r\n\0\r\nQUIT\n";
	if (n == 0) {
		return PROXY_PREFIX_PARTIAL;
	}
	if (src != NULL && memcmp(src, v1, n < sizeof(v1) - 1U ? n : sizeof(v1) - 1U) == 0) {
		return n < sizeof(v1) - 1U ? PROXY_PREFIX_PARTIAL : PROXY_PREFIX_V1;
	}
	if (src != NULL && memcmp(src, v2, n < sizeof(v2) - 1U ? n : sizeof(v2) - 1U) == 0) {
		return n < sizeof(v2) - 1U ? PROXY_PREFIX_PARTIAL : PROXY_PREFIX_V2;
	}
	return PROXY_PREFIX_OTHER;
}

proxy_read_status protocol_proxy_read(const void *src, size_t n, p_proxy *result, size_t *consumed) {
	const char *line = src;
	if (result == NULL || consumed == NULL) {
		return PROXY_READ_MALFORMED;
	}
	*result = (p_proxy){ 0 };
	*consumed = 0;
	proxy_prefix prefix = protocol_proxy_detect(src, n);
	if (prefix != PROXY_PREFIX_V1) {
		return prefix == PROXY_PREFIX_PARTIAL ? PROXY_READ_INCOMPLETE : PROXY_READ_MALFORMED;
	}
	size_t limit = n < PROTOPROXY_PACKETMAXLEN ? n : PROTOPROXY_PACKETMAXLEN;
	size_t i = 6;
	while (i < limit && line[i] != '\r' && line[i] != '\n') {
		i++;
	}
	if (i < limit && (line[i] == '\n' || (i + 1 < limit && line[i + 1] != '\n'))) {
		return PROXY_READ_MALFORMED;
	}
	if (i + 1 >= limit) {
		return limit == PROTOPROXY_PACKETMAXLEN ? PROXY_READ_TOO_LONG : PROXY_READ_INCOMPLETE;
	}
	const char *fields = line + 6;
	size_t length = i - 6;
	if (length >= 7 && memcmp(fields, "UNKNOWN", 7) == 0 && (length == 7 || fields[7] == ' ')) {
		/* Optional UNKNOWN fields are opaque. */
	} else if (length >= 5 && (memcmp(fields, "TCP4 ", 5) == 0 || memcmp(fields, "TCP6 ", 5) == 0)) {
		if (!protocol_proxy_tcp_read(fields + 5, line + i, fields[3] == '4' ? AF_INET : AF_INET6, result)) {
			return PROXY_READ_MALFORMED;
		}
	} else {
		return PROXY_READ_MALFORMED;
	}
	*consumed = i + 2;
	return PROXY_READ_COMPLETE;
}

bool protocol_proxy_socket_read(int socket_fd, p_proxy *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (socket_fd < 0 || result == NULL) {
		errno = EINVAL;
		return false;
	}
	struct sockaddr_storage destination_socket;
	struct sockaddr_storage source_socket;
	socklen_t destination_socket_size = sizeof(destination_socket);
	socklen_t source_socket_size = sizeof(source_socket);
	memset(&destination_socket, 0, sizeof(destination_socket));
	memset(&source_socket, 0, sizeof(source_socket));
	if (getpeername(socket_fd, (struct sockaddr *)&source_socket, &source_socket_size) == -1
		|| getsockname(socket_fd, (struct sockaddr *)&destination_socket, &destination_socket_size) == -1) {
		return false;
	}
	if (!net_addr_from_socket(&source_socket, &result->srcaddr, &result->srcport)
		|| !net_addr_from_socket(&destination_socket, &result->dstaddr, &result->dstport)
		|| result->srcaddr.family != result->dstaddr.family) {
		memset(result, 0, sizeof(*result));
		errno = EAFNOSUPPORT;
		return false;
	}
	result->family = result->srcaddr.family;
	protocol_proxy_normalize(result);
	return true;
}

size_t protocol_proxy_write(void *dst, p_proxy src) {
	net_addrp srcaddrp = protocol_proxy_format_address(&src.srcaddr);
	net_addrp dstaddrp = protocol_proxy_format_address(&src.dstaddr);
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
