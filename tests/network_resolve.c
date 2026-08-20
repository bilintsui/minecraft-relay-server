/*
 * network_resolve.c: Tests for compatible address selection
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
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

/* section: global variables */
static uint8_t mock_address_first[16];
static char *mock_address_list[3];
static uint8_t mock_address_second[16];
static size_t mock_call_count;
static sa_family_t mock_call_families[2];
static sa_family_t mock_success_family;

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

static void resolver_mock_reset(sa_family_t success_family, const char *first, const char *second) {
	memset(mock_address_first, 0, sizeof(mock_address_first));
	memset(mock_address_second, 0, sizeof(mock_address_second));
	mock_address_list[0] = (char *)mock_address_first;
	mock_address_list[1] = second == NULL ? NULL : (char *)mock_address_second;
	mock_address_list[2] = NULL;
	mock_call_count = 0;
	memset(mock_call_families, 0, sizeof(mock_call_families));
	mock_success_family = success_family;
	if (first != NULL) {
		inet_pton(success_family, first, mock_address_first);
	}
	if (second != NULL) {
		inet_pton(success_family, second, mock_address_second);
	}
}

static bool resolver_test_dual(void) {
	int test_result = false;
	resolver_mock_reset(AF_INET, "192.0.2.10", "192.0.2.11");
	net_addr result = net_resolve_dual("primary.example", AF_INET, true);
	CHECK(result.err == 0 && net_address_equal(&result, AF_INET, mock_address_first), "primary NSS result was not selected");
	CHECK(mock_call_count == 1 && mock_call_families[0] == AF_INET, "successful primary lookup queried another family");

	resolver_mock_reset(AF_INET, "192.0.2.20", NULL);
	result = net_resolve_dual("fallback.example", AF_INET6, true);
	CHECK(result.err == 0 && net_address_equal(&result, AF_INET, mock_address_first), "alternate NSS result was not selected");
	CHECK(mock_call_count == 2 && mock_call_families[0] == AF_INET6 && mock_call_families[1] == AF_INET, "dual lookup used the wrong family order");

	resolver_mock_reset(AF_INET, "192.0.2.30", NULL);
	result = net_resolve_dual("single.example", AF_INET6, false);
	CHECK(result.err == NET_ENORECORD && net_address_zero(&result), "single-family failure returned the wrong result");
	CHECK(mock_call_count == 1 && mock_call_families[0] == AF_INET6, "single-family lookup attempted a fallback");

	resolver_mock_reset(AF_UNSPEC, NULL, NULL);
	result = net_resolve_dual("missing.example", AF_INET, true);
	CHECK(result.err == NET_ENORECORD && net_address_zero(&result), "dual-family failure returned the wrong result");
	CHECK(mock_call_count == 2 && mock_call_families[0] == AF_INET && mock_call_families[1] == AF_INET6, "failed dual lookup used the wrong family order");

	test_result = true;

cleanup:
	return test_result;
}

static bool resolver_test_invalid(void) {
	int test_result = false;
	resolver_mock_reset(AF_INET, "192.0.2.1", NULL);
	errno = EDOM;
	net_addr result = net_resolve_dual("invalid.example", AF_UNSPEC, true);
	CHECK(result.err == NET_EARGFAMILY && net_address_zero(&result), "invalid family returned the wrong result");
	CHECK(errno == EDOM, "invalid family unexpectedly changed errno");
	CHECK(mock_call_count == 0, "invalid family reached NSS");
	test_result = true;

cleanup:
	return test_result;
}

static bool resolver_test_literals(void) {
	int test_result = false;
	uint8_t address_v4[4];
	uint8_t address_v6[16];
	CHECK(inet_pton(AF_INET, "192.0.2.40", address_v4) == 1 && inet_pton(AF_INET6, "2001:db8::40", address_v6) == 1, "cannot create literal reference addresses");
	resolver_mock_reset(AF_UNSPEC, NULL, NULL);
	net_addr result = net_resolve_dual("192.0.2.40", AF_INET, false);
	CHECK(result.err == 0 && net_address_equal(&result, AF_INET, address_v4), "IPv4 literal was not resolved directly");
	CHECK(mock_call_count == 0, "IPv4 literal reached NSS");

	result = net_resolve_dual("2001:db8::40", AF_INET6, false);
	CHECK(result.err == 0 && net_address_equal(&result, AF_INET6, address_v6), "IPv6 literal was not resolved directly");
	CHECK(mock_call_count == 0, "IPv6 literal reached NSS");

	resolver_mock_reset(AF_UNSPEC, NULL, NULL);
	result = net_resolve_dual("192.0.2.40", AF_INET6, true);
	CHECK(result.err == 0 && net_address_equal(&result, AF_INET, address_v4), "wrong-family literal did not use dual fallback");
	CHECK(mock_call_count == 1 && mock_call_families[0] == AF_INET6, "wrong-family literal did not preserve the primary NSS attempt");

	test_result = true;

cleanup:
	return test_result;
}

/* section: functions (exported) */
struct hostent *__wrap_gethostbyname2(const char *name, int family) {
	static struct hostent response;
	if (mock_call_count < sizeof(mock_call_families) / sizeof(mock_call_families[0])) {
		mock_call_families[mock_call_count] = (sa_family_t)family;
	}
	mock_call_count++;
	if (name == NULL || family != mock_success_family || (family != AF_INET && family != AF_INET6)) {
		h_errno = HOST_NOT_FOUND;
		return NULL;
	}
	memset(&response, 0, sizeof(response));
	response.h_addr_list = mock_address_list;
	response.h_addrtype = family;
	response.h_length = family == AF_INET ? (int)sizeof(uint32_t) : (int)(sizeof(uint8_t) * 16);
	response.h_name = (char *)name;
	return &response;
}

/* section: functions (entry point) */
int main(void) {
	if (!resolver_test_dual() || !resolver_test_invalid() || !resolver_test_literals()) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
