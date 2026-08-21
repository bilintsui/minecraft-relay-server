/*
 * network_resolve.c: Tests for numeric address parsing
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* section: headers (project) */
#include "network.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* section: functions (local) */
static bool net_address_equal(const net_addr *address, sa_family_t family, const void *expected) {
	if (address == NULL || address->family != family || expected == NULL) {
		return false;
	}
	size_t address_size = family == AF_INET ? sizeof(uint32_t) : sizeof(uint8_t) * 16;
	return memcmp(&address->addr, expected, address_size) == 0;
}

static bool net_address_zero(const net_addr *address) {
	static const uint8_t zero[16];
	return address != NULL && address->family == 0 && memcmp(&address->addr, zero, sizeof(zero)) == 0;
}

static bool resolver_test_address_parse(void) {
	int test_result = false;
	uint8_t address_v4[4];
	uint8_t address_v6[16];
	CHECK(inet_pton(AF_INET, "192.0.2.40", address_v4) == 1 && inet_pton(AF_INET6, "2001:db8::40", address_v6) == 1, "cannot create numeric address references");
	net_addr result = net_addr_parse("192.0.2.40");
	CHECK(result.err == NET_OK && net_address_equal(&result, AF_INET, address_v4), "IPv4 literal was not parsed");
	result = net_addr_parse("2001:db8::40");
	CHECK(result.err == NET_OK && net_address_equal(&result, AF_INET6, address_v6), "IPv6 literal was not parsed");
	result = net_addr_parse("0.0.0.0");
	CHECK(result.err == NET_OK && result.family == AF_INET && result.addr.v4 == INADDR_ANY, "IPv4 wildcard was not parsed");
	result = net_addr_parse("::");
	CHECK(result.err == NET_OK && result.family == AF_INET6 && memcmp(result.addr.v6, &in6addr_any, sizeof(result.addr.v6)) == 0, "IPv6 wildcard was not parsed");

	static const char *invalid_addresses[] = { NULL, "", "localhost", "127.1", "192.0.2.1 ", "300.0.2.1", "fe80::1%lo" };
	for (size_t address_index = 0; address_index < sizeof(invalid_addresses) / sizeof(invalid_addresses[0]); address_index++) {
		result = net_addr_parse(invalid_addresses[address_index]);
		CHECK(result.err == NET_EARGADDR && net_address_zero(&result), "invalid numeric address was accepted");
	}
	test_result = true;

cleanup:
	return test_result;
}

/* section: functions (entry point) */
int main(void) {
	if (!resolver_test_address_parse()) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
