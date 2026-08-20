/*
 * network_resolve_system.c: Tests for system NSS address resolution
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
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
			fprintf(stderr, "%s\n", message); \
			goto cleanup; \
		} \
	} while (0)

/* section: functions (local) */
static bool resolver_system_family(sa_family_t family, bool *tested) {
	if (tested == NULL || (family != AF_INET && family != AF_INET6)) {
		return false;
	}
	struct hostent *reference = gethostbyname2("localhost", family);
	if (reference == NULL) {
		return true;
	}
	size_t address_size = family == AF_INET ? sizeof(uint32_t) : sizeof(uint8_t) * 16;
	int test_result = false;
	uint8_t expected[16] = { 0 };
	CHECK(reference->h_addrtype == family && reference->h_length == (int)address_size && reference->h_addr_list != NULL && reference->h_addr_list[0] != NULL, "system NSS returned an invalid localhost address");
	memcpy(expected, reference->h_addr_list[0], address_size);
	net_addr result = net_resolve_dual("localhost", family, false);
	CHECK(result.err == 0 && result.family == family && memcmp(&result.addr, expected, address_size) == 0, "net_resolve_dual did not preserve the system NSS localhost result");
	*tested = true;
	test_result = true;

cleanup:
	return test_result;
}

/* section: functions (entry point) */
int main(void) {
	bool tested = false;
	if (!resolver_system_family(AF_INET, &tested) || !resolver_system_family(AF_INET6, &tested) || !tested) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
