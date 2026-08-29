/*
 * dns_pending.c: Deterministic pending-DNS injection for listener integration tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdlib.h>
#include <unistd.h>

/* section: headers (project) */
#include "resolver/dns.h"

/* section: functions (exported) */
dns_address_lookup_status __real_dns_address_lookup(const char *hostname, sa_family_t family, dns_address_result *result);

dns_address_lookup_status __wrap_dns_address_lookup(const char *hostname, sa_family_t family, dns_address_result *result) {
	if (getenv("MCRELAY_TEST_DNS_PENDING") == NULL) {
		return __real_dns_address_lookup(hostname, family, result);
	}
	for (;;) {
		pause();
	}
}
