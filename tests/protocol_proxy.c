/*
 * protocol_proxy.c: Tests for PROXY protocol v1 connection headers
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
		&& endpoints.dstport == connection.listener_port && protocol_proxy_write(header, endpoints) == (size_t)expected_size
		&& memcmp(header, expected, (size_t)expected_size + 1U) == 0, "accepted connection endpoints were not captured as a reusable value");
	size_t header_size = protocol_proxy_write_socket(header, connection.accepted_fd);
	CHECK(header_size == (size_t)expected_size && memcmp(header, expected, header_size + 1) == 0, "PROXY header did not describe the accepted connection");
	p_proxy parsed = protocol_proxy_read(header, header_size);
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
		&& !protocol_proxy_socket_read(-1, NULL) && protocol_proxy_write_socket(NULL, -1) == 0 && protocol_proxy_write_socket(header, -1) == 0;
}

static bool proxy_test_declared_family(void) {
	static const char tcp4[] = "PROXY TCP4 ::1 ::1 1 2\r\n";
	static const char tcp6[] = "PROXY TCP6 127.0.0.1 127.0.0.1 1 2\r\n";
	p_proxy parsed = protocol_proxy_read(tcp4, sizeof(tcp4) - 1U);
	if (parsed.family != AF_UNSPEC) {
		return false;
	}
	parsed = protocol_proxy_read(tcp6, sizeof(tcp6) - 1U);
	return parsed.family == AF_UNSPEC;
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

/* section: functions (entry point) */
int main(void) {
	if (!proxy_test_arguments() || !proxy_test_declared_family() || !proxy_test_ipv4() || !proxy_test_ipv4_mapped() || !proxy_test_ipv6()) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
