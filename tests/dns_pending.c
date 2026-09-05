/*
 * dns_pending.c: Deterministic pending-DNS injection for listener integration tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "resolver/dns.h"

/* section: functions (local) */
static dns_address_lookup_status dns_pending_fixed(const char *hostname, sa_family_t family, dns_address_result *result) {
	if (hostname == NULL || result == NULL || (family != AF_INET && family != AF_INET6)) {
		return DNS_ADDRESS_LOOKUP_BAD_ARGUMENT;
	}
	result->addresses = calloc(1, sizeof(*result->addresses));
	if (result->addresses == NULL) {
		return DNS_ADDRESS_LOOKUP_MEMORY;
	}
	result->address_count = 1;
	result->addresses[0].address = net_addr_parse(family == AF_INET ? "127.0.0.1" : "::1");
	result->addresses[0].effective_ttl = 0;
	result->addresses[0].record_ttl = 0;
	result->rcode = ns_r_noerror;
	if (snprintf(result->canonical_name, sizeof(result->canonical_name), "%s", hostname) <= 0
		|| snprintf(result->question_name, sizeof(result->question_name), "%s", hostname) <= 0) {
		dns_address_result_destroy(result);
		return DNS_ADDRESS_LOOKUP_MALFORMED;
	}
	const char *delay_text = getenv("MCRELAY_TEST_DNS_FIXED_DELAY_MS");
	if (delay_text != NULL) {
		char *end = NULL;
		unsigned long delay_ms = strtoul(delay_text, &end, 10);
		if (end == delay_text || *end != '\0' || delay_ms > 60000UL) {
			dns_address_result_destroy(result);
			return DNS_ADDRESS_LOOKUP_BAD_ARGUMENT;
		}
		struct timespec delay = { .tv_sec = (time_t)(delay_ms / 1000UL), .tv_nsec = (long)(delay_ms % 1000UL) * 1000000L };
		while (family == AF_INET6 && nanosleep(&delay, &delay) == -1 && errno == EINTR) {
		}
	}
	return DNS_ADDRESS_LOOKUP_OK;
}

/* section: functions (exported) */
dns_address_lookup_status __real_dns_address_lookup(const char *hostname, sa_family_t family, dns_address_result *result);

dns_address_lookup_status __wrap_dns_address_lookup(const char *hostname, sa_family_t family, dns_address_result *result) {
	if (getenv("MCRELAY_TEST_DNS_FIXED") != NULL) {
		return dns_pending_fixed(hostname, family, result);
	}
	if (getenv("MCRELAY_TEST_DNS_PENDING") == NULL) {
		return __real_dns_address_lookup(hostname, family, result);
	}
	for (;;) {
		pause();
	}
}
