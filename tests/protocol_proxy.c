/*
 * protocol_proxy.c: Tests for PROXY protocol connection headers
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* section: headers (project) */
#include "protocol/proxy.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* section: types */
typedef struct {
	int accepted_fd;
	int client_fd;
	in_port_t client_port;
	int listener_fd;
	in_port_t listener_port;
} proxy_connection;

/* section: functions (local) */
static void proxy_connection_close(proxy_connection *connection) {
	if (connection->accepted_fd != -1) {
		close(connection->accepted_fd);
	}
	if (connection->client_fd != -1) {
		close(connection->client_fd);
	}
	if (connection->listener_fd != -1) {
		close(connection->listener_fd);
	}
	memset(connection, 0, sizeof(*connection));
	connection->accepted_fd = -1;
	connection->client_fd = -1;
	connection->listener_fd = -1;
}

static bool proxy_connection_open(proxy_connection *connection, sa_family_t listener_family, sa_family_t client_family, bool dual_stack) {
	memset(connection, 0, sizeof(*connection));
	connection->accepted_fd = -1;
	connection->client_fd = -1;
	connection->listener_fd = -1;
	connection->listener_fd = socket(listener_family, SOCK_STREAM, 0);
	if (connection->listener_fd == -1) {
		goto fail;
	}
	int reuse_address = 1;
	if (setsockopt(connection->listener_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address)) == -1) {
		goto fail;
	}
	if (listener_family == AF_INET6) {
		int ipv6_only = dual_stack ? 0 : 1;
		if (setsockopt(connection->listener_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, sizeof(ipv6_only)) == -1) {
			goto fail;
		}
		struct sockaddr_in6 listener_address = {
			.sin6_family = AF_INET6,
			.sin6_addr = IN6ADDR_ANY_INIT
		};
		if (!dual_stack) {
			listener_address.sin6_addr = in6addr_loopback;
		}
		if (bind(connection->listener_fd, (struct sockaddr *)&listener_address, sizeof(listener_address)) == -1) {
			goto fail;
		}
		socklen_t listener_address_size = sizeof(listener_address);
		if (getsockname(connection->listener_fd, (struct sockaddr *)&listener_address, &listener_address_size) == -1) {
			goto fail;
		}
		connection->listener_port = ntohs(listener_address.sin6_port);
	} else if (listener_family == AF_INET) {
		struct sockaddr_in listener_address = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
		};
		if (bind(connection->listener_fd, (struct sockaddr *)&listener_address, sizeof(listener_address)) == -1) {
			goto fail;
		}
		socklen_t listener_address_size = sizeof(listener_address);
		if (getsockname(connection->listener_fd, (struct sockaddr *)&listener_address, &listener_address_size) == -1) {
			goto fail;
		}
		connection->listener_port = ntohs(listener_address.sin_port);
	} else {
		errno = EAFNOSUPPORT;
		goto fail;
	}
	if (listen(connection->listener_fd, 1) == -1) {
		goto fail;
	}
	connection->client_fd = socket(client_family, SOCK_STREAM, 0);
	if (connection->client_fd == -1) {
		goto fail;
	}
	if (client_family == AF_INET6) {
		struct sockaddr_in6 server_address = {
			.sin6_family = AF_INET6,
			.sin6_addr = IN6ADDR_LOOPBACK_INIT,
			.sin6_port = htons(connection->listener_port)
		};
		if (connect(connection->client_fd, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) {
			goto fail;
		}
		struct sockaddr_in6 client_address;
		socklen_t client_address_size = sizeof(client_address);
		if (getsockname(connection->client_fd, (struct sockaddr *)&client_address, &client_address_size) == -1) {
			goto fail;
		}
		connection->client_port = ntohs(client_address.sin6_port);
	} else if (client_family == AF_INET) {
		struct sockaddr_in server_address = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = htons(connection->listener_port)
		};
		if (connect(connection->client_fd, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) {
			goto fail;
		}
		struct sockaddr_in client_address;
		socklen_t client_address_size = sizeof(client_address);
		if (getsockname(connection->client_fd, (struct sockaddr *)&client_address, &client_address_size) == -1) {
			goto fail;
		}
		connection->client_port = ntohs(client_address.sin_port);
	} else {
		errno = EAFNOSUPPORT;
		goto fail;
	}
	connection->accepted_fd = accept(connection->listener_fd, NULL, NULL);
	if (connection->accepted_fd == -1) {
		goto fail;
	}
	return true;

fail:
	proxy_connection_close(connection);
	return false;
}

static size_t proxy_socket_write(void *dst, int socket_fd) {
	p_proxy source;
	if (dst == NULL || !protocol_proxy_socket_read(socket_fd, &source)) {
		return 0;
	}
	return protocol_proxy_write(dst, source, PROXY_PREFIX_V1);
}

static bool proxy_header_test(sa_family_t listener_family, sa_family_t client_family, bool dual_stack, const char *protocol, const char *source, const char *destination) {
	bool test_result = false;
	proxy_connection connection;
	memset(&connection, 0, sizeof(connection));
	connection.accepted_fd = -1;
	connection.client_fd = -1;
	connection.listener_fd = -1;
	CHECK(proxy_connection_open(&connection, listener_family, client_family, dual_stack), "cannot open test connection");
	char expected[PROTOPROXY_PACKETMAXLEN + 1];
	char header[PROTOPROXY_PACKETMAXLEN + 1];
	int expected_size = snprintf(expected, sizeof(expected), "PROXY %s %s %s %hu %hu\r\n", protocol, source, destination, connection.client_port, connection.listener_port);
	CHECK(expected_size > 0 && (size_t)expected_size < sizeof(expected), "cannot format expected PROXY header");
	p_proxy endpoints;
	CHECK(protocol_proxy_socket_read(connection.accepted_fd, &endpoints) && endpoints.family == client_family && endpoints.srcport == connection.client_port
		&& endpoints.dstport == connection.listener_port && protocol_proxy_write(header, endpoints, PROXY_PREFIX_V1) == (size_t)expected_size
		&& memcmp(header, expected, (size_t)expected_size + 1U) == 0, "accepted connection endpoints were not captured as a reusable value");
	size_t header_size = proxy_socket_write(header, connection.accepted_fd);
	CHECK(header_size == (size_t)expected_size && memcmp(header, expected, header_size + 1) == 0, "PROXY header did not describe the accepted connection");
	p_proxy parsed;
	size_t consumed;
	CHECK(protocol_proxy_read(header, header_size, &parsed, &consumed) == PROXY_READ_COMPLETE && consumed == header_size, "incorrect header boundary");
	CHECK(parsed.family == client_family && parsed.srcport == connection.client_port && parsed.dstport == connection.listener_port, "PROXY header did not round-trip");
	test_result = true;

cleanup:
	proxy_connection_close(&connection);
	return test_result;
}

static bool proxy_test_arguments(void) {
	char header[PROTOPROXY_PACKETMAXLEN + 1];
	p_proxy endpoints;
	memset(&endpoints, 0xFF, sizeof(endpoints));
	return !protocol_proxy_socket_read(-1, &endpoints) && endpoints.family == AF_UNSPEC && endpoints.srcaddr.family == AF_UNSPEC
		&& !protocol_proxy_socket_read(-1, NULL) && proxy_socket_write(NULL, -1) == 0 && proxy_socket_write(header, -1) == 0;
}

static bool proxy_test_framing(void) {
	static const char *const invalid[] = {
		"PROXY TCP4 ::1 ::1 1 2\r\n", "PROXY TCP6 127.0.0.1 127.0.0.1 1 2\r\n", "PROXY TCP4 \r\n", "PROXY TCP4 127.0.0.1 127.0.0.1\r\n",
		"PROXY TCP4 127.0.0.01 127.0.0.1 1 2\r\n", "PROXY TCP4 127.0.0.1 127.0.0.1 1 2 x\r\n", "PROXY TCP4 127.0.0.1 127.0.0.1 x 2\r\n",
		"PROXY TCP4 127.0.0.1 127.0.0.1 70000 2\r\n", "PROXY TCP4 127.0.0.1 127.0.0.1 01 2\r\n", "PROXY TCP4 127.0.0.1 127.0.0.1 0 00\r\n",
		"PROXY TCP4 127.0.0.1 127.0.0.1 1 2 \r\n", "PROXY TCP4  127.0.0.1 127.0.0.1 1 2\r\n", "PROXY TCP4X127.0.0.1 127.0.0.1 1 2\r\n",
		"PROXY TCP4 11111111111111111111111111111111111111111111111111 127.0.0.1 1 2\r\n", "PROXY TCP6 ::192.0.2.1 ::1 1 2\r\n",
		"PROXY TCP6 ::ffff:192.0.2.1 64:ff9b::198.51.100.2 1 2\r\n", "PROXY TCP6 2001:db8::ffff:192.0.2.1 ::1 1 2\r\n",
		"PROXY TCP6 ::1 ::ffff:192.0.2.256 1 2\r\n", "PROXY TCP6 ::ffff:192.0.2.01 ::1 1 2\r\n",
		"PROXY UNKNOWN\n", "PROXY UNKNOWN\rX", "PROXY UNKNOWNX\r\n", "PROXY UDP4\r\n"
	};
	static const char nul[] = "PROXY TCP4 127.0.0.1\0extra 127.0.0.1 1 2\r\n";
	static const char tcp[] = "PROXY TCP4 127.0.0.1 192.0.2.4 0 65535\r\n";
	static const char v2[] = "\r\n\r\n\0\r\nQUIT\n";
	p_proxy pair;
	size_t consumed;
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		if (protocol_proxy_read(invalid[i], strlen(invalid[i]), &pair, &consumed) != PROXY_READ_MALFORMED || consumed != 0 || pair.family != AF_UNSPEC) {
			fprintf(stderr, "invalid header %zu was not rejected\n", i);
			return false;
		}
	}
	for (size_t i = 0; i < sizeof(tcp) - 1; i++) {
		if (protocol_proxy_read(tcp, i, &pair, &consumed) != PROXY_READ_INCOMPLETE || consumed != 0) {
			return false;
		}
	}
	for (size_t i = 0; i < sizeof(v2) - 1; i++) {
		if (protocol_proxy_detect(v2, i) != PROXY_PREFIX_PARTIAL) {
			return false;
		}
	}
	char limit[PROTOPROXY_PACKETMAXLEN + 2];
	memset(limit, 'x', sizeof(limit));
	memcpy(limit, "PROXY UNKNOWN ", 14);
	limit[20] = 0;
	if (protocol_proxy_read(limit, sizeof(limit), &pair, &consumed) != PROXY_READ_TOO_LONG) {
		return false;
	}
	memcpy(limit + PROTOPROXY_PACKETMAXLEN - 2, "\r\n", 2);
	return protocol_proxy_read(limit, sizeof(limit), &pair, &consumed) == PROXY_READ_COMPLETE && pair.family == AF_UNSPEC && consumed == PROTOPROXY_PACKETMAXLEN
		&& protocol_proxy_detect(v2, sizeof(v2) - 1) == PROXY_PREFIX_V2 && protocol_proxy_detect("Piano", 5) == PROXY_PREFIX_OTHER
		&& protocol_proxy_read(nul, sizeof(nul) - 1, &pair, &consumed) == PROXY_READ_MALFORMED
		&& protocol_proxy_read(tcp, sizeof(tcp), &pair, &consumed) == PROXY_READ_COMPLETE && consumed == sizeof(tcp) - 1 && pair.family == AF_INET && pair.srcport == 0 && pair.dstport == 65535;
}

static bool proxy_test_ipv4(void) {
	return proxy_header_test(AF_INET, AF_INET, false, "TCP4", "127.0.0.1", "127.0.0.1");
}

static bool proxy_test_ipv4_mapped(void) {
	return proxy_header_test(AF_INET6, AF_INET, true, "TCP4", "127.0.0.1", "127.0.0.1");
}

static bool proxy_test_ipv6(void) {
	return proxy_header_test(AF_INET6, AF_INET6, false, "TCP6", "::1", "::1");
}

static bool proxy_test_mapped_pair(void) {
	static const struct {
		const char *input, *output;
		sa_family_t family;
	} cases[] = {
		{ "PROXY TCP6 ::ffff:c000:0201 ::ffff:c633:6402 1 2\r\n", "PROXY TCP4 192.0.2.1 198.51.100.2 1 2\r\n", AF_INET },
		{ "PROXY TCP6 ::ffff:192.0.2.1 ::ffff:198.51.100.2 1 2\r\n", "PROXY TCP4 192.0.2.1 198.51.100.2 1 2\r\n", AF_INET },
		{ "PROXY TCP6 ::ffff:192.0.2.1 ::ffff:c633:6402 1 2\r\n", "PROXY TCP4 192.0.2.1 198.51.100.2 1 2\r\n", AF_INET },
		{ "PROXY TCP6 ::ffff:c000:0201 2001:db8::1 1 2\r\n", "PROXY TCP6 ::ffff:c000:201 2001:db8::1 1 2\r\n", AF_INET6 },
		{ "PROXY TCP6 0:0:0:0:0:FFFF:192.0.2.1 2001:db8::1 1 2\r\n", "PROXY TCP6 ::ffff:c000:201 2001:db8::1 1 2\r\n", AF_INET6 },
		{ "PROXY TCP6 2001:db8::1 ::ffff:c000:0201 1 2\r\n", "PROXY TCP6 2001:db8::1 ::ffff:c000:201 1 2\r\n", AF_INET6 },
		{ "PROXY TCP6 2001:db8::1 ::ffff:192.0.2.1 1 2\r\n", "PROXY TCP6 2001:db8::1 ::ffff:c000:201 1 2\r\n", AF_INET6 }
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		char output[PROTOPROXY_PACKETMAXLEN + 1];
		p_proxy pair;
		size_t consumed;
		size_t length = strlen(cases[i].input);
		if (protocol_proxy_read(cases[i].input, length, &pair, &consumed) != PROXY_READ_COMPLETE || consumed != length || pair.family != cases[i].family || pair.srcaddr.family != pair.dstaddr.family
			|| protocol_proxy_write(output, pair, PROXY_PREFIX_V1) != strlen(cases[i].output) || strcmp(output, cases[i].output) != 0) {
			fprintf(stderr, "mapped address case %zu failed: %s", i, cases[i].input);
			return false;
		}
	}
	return true;
}

static bool proxy_test_v2(void) {
	static const uint8_t wire[] = {
		13, 10, 13, 10, 0, 13, 10, 'Q', 'U', 'I', 'T', 10, 0x21, 0x11, 0, 16,
		192, 0, 2, 1, 198, 51, 100, 2, 0, 0, 0xff, 0xff, 0xe1, 0, 1, 0xaa, 0xfe
	};
	uint8_t input[sizeof(wire)], output[PROTOPROXY_PACKETMAXLEN + 1];
	p_proxy pair;
	size_t consumed;
	uint16_t remaining;
	for (size_t n = 0; n < 28; n++) {
		if (protocol_proxy_v2_prefix_read(wire, n, &pair, &consumed, &remaining) != PROXY_READ_INCOMPLETE || consumed != 0 || remaining != 0 || pair.family != AF_UNSPEC) {
			return false;
		}
	}
	if (protocol_proxy_v2_prefix_read(wire, sizeof(wire), &pair, &consumed, &remaining) != PROXY_READ_COMPLETE || consumed != 28 || remaining != 4
		|| pair.family != AF_INET || pair.srcport != 0 || pair.dstport != 65535 || protocol_proxy_write(output, pair, PROXY_PREFIX_V2) != 28) {
		return false;
	}
	memcpy(input, wire, sizeof(wire));
	input[15] = 12;
	if (memcmp(output, input, 28) != 0 || protocol_proxy_write(output, pair, PROXY_PREFIX_OTHER) != 0) {
		return false;
	}
	static const struct {
		uint8_t command, family;
		uint16_t length;
		proxy_read_status status;
	} cases[] = {
		{ 0x20, 0xff, 7, PROXY_READ_COMPLETE }, { 0x20, 0x31, 0, PROXY_READ_COMPLETE }, { 0x21, 0x00, 0, PROXY_READ_COMPLETE },
		{ 0x21, 0x12, 11, PROXY_READ_MALFORMED }, { 0x21, 0x12, 12, PROXY_READ_COMPLETE }, { 0x21, 0x12, 13, PROXY_READ_COMPLETE },
		{ 0x21, 0x22, 35, PROXY_READ_MALFORMED }, { 0x21, 0x22, 36, PROXY_READ_COMPLETE }, { 0x21, 0x22, 37, PROXY_READ_COMPLETE },
		{ 0x21, 0x31, 215, PROXY_READ_MALFORMED }, { 0x21, 0x31, 216, PROXY_READ_COMPLETE }, { 0x21, 0x31, 217, PROXY_READ_COMPLETE },
		{ 0x21, 0x32, 215, PROXY_READ_MALFORMED }, { 0x21, 0x32, 216, PROXY_READ_COMPLETE }, { 0x21, 0x32, 217, PROXY_READ_COMPLETE },
		{ 0x21, 0x31, UINT16_MAX, PROXY_READ_COMPLETE },
		{ 0x11, 0x11, 12, PROXY_READ_MALFORMED }, { 0x22, 0x00, 0, PROXY_READ_MALFORMED }, { 0x21, 0x13, 12, PROXY_READ_MALFORMED },
		{ 0x21, 0x41, 12, PROXY_READ_MALFORMED }, { 0x21, 0x11, 11, PROXY_READ_MALFORMED }, { 0x21, 0x21, 35, PROXY_READ_MALFORMED }
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		input[12] = cases[i].command;
		input[13] = cases[i].family;
		uint16_t length = htons(cases[i].length);
		memcpy(input + 14, &length, sizeof(length));
		if (protocol_proxy_v2_prefix_read(input, 16, &pair, &consumed, &remaining) != cases[i].status || pair.family != AF_UNSPEC
			|| (cases[i].status == PROXY_READ_COMPLETE ? consumed != 16 || remaining != cases[i].length : consumed != 0 || remaining != 0)) {
			fprintf(stderr, "unexpected v2 prefix result for command %#x, family %#x, length %u\n", (unsigned)cases[i].command, (unsigned)cases[i].family, (unsigned)cases[i].length);
			return false;
		}
	}
	return true;
}

/* section: functions (entry point) */
int main(void) {
	return proxy_test_arguments() && proxy_test_framing() && proxy_test_ipv4() && proxy_test_ipv4_mapped() && proxy_test_ipv6() && proxy_test_mapped_pair() && proxy_test_v2() ? EXIT_SUCCESS : EXIT_FAILURE;
}
