/*
 * resolver_cache.c: Tests for the listener-owned DNS result cache
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

/* section: headers (project) */
#include "dns.h"
#include "resolver_cache.h"

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
static bool cache_address_result_create(dns_address_result *result, const char *question_name, sa_family_t family, size_t address_count, uint32_t effective_ttl, bool with_cname) {
	if (result == NULL || question_name == NULL || (family != AF_INET && family != AF_INET6) || address_count == 0) {
		return false;
	}
	memset(result, 0, sizeof(*result));
	if (snprintf(result->question_name, sizeof(result->question_name), "%s", question_name) < 0) {
		return false;
	}
	const char *canonical_name = with_cname ? "target.cache.test" : question_name;
	if (snprintf(result->canonical_name, sizeof(result->canonical_name), "%s", canonical_name) < 0) {
		return false;
	}
	result->addresses = calloc(address_count, sizeof(*result->addresses));
	if (result->addresses == NULL) {
		return false;
	}
	result->address_count = address_count;
	result->rcode = ns_r_noerror;
	for (size_t index = 0; index < address_count; index++) {
		result->addresses[index].address.family = family;
		if (family == AF_INET) {
			result->addresses[index].address.addr.v4 = htonl(UINT32_C(0xC0000201) + (uint32_t)index);
		} else {
			result->addresses[index].address.addr.v6[15] = (uint8_t)(index + 1);
		}
		result->addresses[index].effective_ttl = effective_ttl;
		result->addresses[index].record_ttl = effective_ttl + 20;
	}
	if (with_cname) {
		result->cnames = calloc(DNS_CNAME_DEPTH_LIMIT, sizeof(*result->cnames));
		if (result->cnames == NULL) {
			dns_address_result_destroy(result);
			return false;
		}
		result->cname_count = 1;
		if (snprintf(result->cnames[0].owner, sizeof(result->cnames[0].owner), "%s", question_name) < 0
			|| snprintf(result->cnames[0].target, sizeof(result->cnames[0].target), "%s", canonical_name) < 0) {
			dns_address_result_destroy(result);
			return false;
		}
		result->cnames[0].ttl = effective_ttl;
	}
	return true;
}

static bool cache_negative_set(dns_negative_record *negative, const char *owner, uint32_t effective_ttl, bool valid) {
	if (negative == NULL) {
		return false;
	}
	memset(negative, 0, sizeof(*negative));
	if (!valid) {
		return true;
	}
	if (owner == NULL || snprintf(negative->owner, sizeof(negative->owner), "%s", owner) < 0) {
		return false;
	}
	negative->effective_ttl = effective_ttl;
	negative->minimum = effective_ttl + 10;
	negative->record_ttl = effective_ttl + 20;
	negative->valid = true;
	return true;
}

static bool cache_srv_result_create(dns_srv_result *result, const char *question_name, size_t record_count, uint32_t effective_ttl, bool with_cname) {
	if (result == NULL || question_name == NULL || record_count == 0) {
		return false;
	}
	memset(result, 0, sizeof(*result));
	if (snprintf(result->question_name, sizeof(result->question_name), "%s", question_name) < 0) {
		return false;
	}
	const char *canonical_name = with_cname ? "_minecraft._tcp.target.cache.test" : question_name;
	if (snprintf(result->canonical_name, sizeof(result->canonical_name), "%s", canonical_name) < 0) {
		return false;
	}
	result->records = calloc(record_count, sizeof(*result->records));
	if (result->records == NULL) {
		return false;
	}
	result->record_count = record_count;
	result->rcode = ns_r_noerror;
	for (size_t index = 0; index < record_count; index++) {
		result->records[index].effective_ttl = effective_ttl;
		result->records[index].port = (in_port_t)(25565 + index);
		result->records[index].priority = (uint16_t)index;
		result->records[index].record_ttl = effective_ttl + 20;
		result->records[index].weight = (uint16_t)(record_count - index);
		if (snprintf(result->records[index].target, sizeof(result->records[index].target), "target%zu.cache.test", index) < 0) {
			dns_srv_result_destroy(result);
			return false;
		}
	}
	if (with_cname) {
		result->cnames = calloc(DNS_CNAME_DEPTH_LIMIT, sizeof(*result->cnames));
		if (result->cnames == NULL) {
			dns_srv_result_destroy(result);
			return false;
		}
		result->cname_count = 1;
		if (snprintf(result->cnames[0].owner, sizeof(result->cnames[0].owner), "%s", question_name) < 0
			|| snprintf(result->cnames[0].target, sizeof(result->cnames[0].target), "%s", canonical_name) < 0) {
			dns_srv_result_destroy(result);
			return false;
		}
		result->cnames[0].ttl = effective_ttl;
	}
	return true;
}

static bool cache_time_equal(const struct timespec *left, const struct timespec *right) {
	return left != NULL && right != NULL && left->tv_sec == right->tv_sec && left->tv_nsec == right->tv_nsec;
}

static time_t cache_time_max(void) {
	uintmax_t maximum = UINTMAX_MAX;
	maximum >>= (sizeof(uintmax_t) - sizeof(time_t)) * CHAR_BIT;
	if ((time_t)-1 < 0) {
		maximum >>= 1;
	}
	return (time_t)maximum;
}

static bool cache_test_arguments(void) {
	int test_result = false;
	dns_address_result address_result = { 0 };
	dns_srv_result srv_result = { 0 };
	resolver_cache *cache = resolver_cache_create();
	resolver_cache_entry *entry = NULL;
	resolver_cache_view view = { 0 };
	const struct timespec now = { .tv_sec = 1 };
	char oversized_name[NS_MAXDNAME + 1];
	memset(oversized_name, 'a', sizeof(oversized_name));
	oversized_name[sizeof(oversized_name) - 1] = '\0';
	CHECK(cache != NULL, "cache could not be created");
	CHECK(resolver_cache_entry_acquire(NULL, "example.test", ns_t_a, &entry) == RESOLVER_CACHE_ACQUIRE_BAD_ARGUMENT && entry == NULL, "NULL cache was accepted");
	CHECK(resolver_cache_entry_acquire(cache, NULL, ns_t_a, &entry) == RESOLVER_CACHE_ACQUIRE_BAD_ARGUMENT && entry == NULL, "NULL query name was accepted");
	CHECK(resolver_cache_entry_acquire(cache, "", ns_t_a, &entry) == RESOLVER_CACHE_ACQUIRE_BAD_ARGUMENT && entry == NULL, "empty query name was accepted");
	CHECK(resolver_cache_entry_acquire(cache, "..", ns_t_a, &entry) == RESOLVER_CACHE_ACQUIRE_BAD_ARGUMENT && entry == NULL, "invalid double-root query name was accepted");
	CHECK(resolver_cache_entry_acquire(cache, oversized_name, ns_t_a, &entry) == RESOLVER_CACHE_ACQUIRE_BAD_ARGUMENT && entry == NULL, "oversized query name was accepted");
	CHECK(resolver_cache_entry_acquire(cache, "example.test", ns_t_txt, &entry) == RESOLVER_CACHE_ACQUIRE_BAD_ARGUMENT && entry == NULL, "unsupported query type was accepted");
	CHECK(resolver_cache_entry_acquire(cache, "example.test", ns_t_a, NULL) == RESOLVER_CACHE_ACQUIRE_BAD_ARGUMENT, "NULL entry result was accepted");
	CHECK(resolver_cache_entry_count(NULL) == 0 && resolver_cache_owned_bytes(NULL) == 0, "NULL cache getters returned data");
	CHECK(resolver_cache_entry_id(NULL) == 0 && resolver_cache_entry_name(NULL) == NULL && resolver_cache_entry_query_type(NULL) == 0, "NULL entry getters returned data");
	CHECK(!resolver_cache_entry_retain(NULL), "NULL entry was retained");
	CHECK(resolver_cache_result_fits(ns_t_a, 0, 1) && resolver_cache_result_fits(ns_t_aaaa, 1, 1) && resolver_cache_result_fits(ns_t_srv, 0, 1),
		"bounded cache result was rejected");
	CHECK(!resolver_cache_result_fits(ns_t_txt, 0, 1) && !resolver_cache_result_fits(ns_t_a, DNS_CNAME_DEPTH_LIMIT + 1, 1)
		&& !resolver_cache_result_fits(ns_t_srv, 0, DNS_SRV_RECORD_LIMIT), "invalid or oversized cache result was accepted");
	CHECK(!resolver_cache_entry_view(NULL, &now, &view), "NULL entry view was accepted");
	CHECK(!resolver_cache_entry_view(entry, &now, NULL), "NULL view result was accepted");
	CHECK(resolver_cache_entry_publish_address(NULL, DNS_ADDRESS_LOOKUP_OK, &now, &address_result) == RESOLVER_CACHE_PUBLISH_BAD_ARGUMENT, "NULL address entry was accepted");
	CHECK(resolver_cache_entry_publish_srv(NULL, DNS_SRV_LOOKUP_OK, &now, &srv_result) == RESOLVER_CACHE_PUBLISH_BAD_ARGUMENT, "NULL SRV entry was accepted");
	CHECK(resolver_cache_entry_acquire(cache, "view.cache.test", ns_t_a, &entry) == RESOLVER_CACHE_ACQUIRE_OK, "view argument entry could not be acquired");
	memset(&view, 0xFF, sizeof(view));
	const struct timespec invalid_now = { .tv_sec = 1, .tv_nsec = 1000000000L };
	CHECK(!resolver_cache_entry_view(entry, &invalid_now, &view) && view.status == RESOLVER_CACHE_VIEW_EMPTY && view.addresses == NULL && view.srv_records == NULL,
		"invalid view time was accepted or left output data behind");
	resolver_cache_entry_release(NULL);
	resolver_cache_destroy(NULL);
	test_result = true;

cleanup:
	dns_address_result_destroy(&address_result);
	dns_srv_result_destroy(&srv_result);
	resolver_cache_entry_release(entry);
	resolver_cache_destroy(cache);
	return test_result;
}

static bool cache_test_capacity(void) {
	int test_result = false;
	resolver_cache *byte_cache = NULL;
	resolver_cache_entry *byte_entries[2] = { NULL, NULL };
	dns_address_result byte_results[2] = { 0 };
	resolver_cache *entry_cache = resolver_cache_create();
	resolver_cache_entry *entries[RESOLVER_CACHE_ENTRY_LIMIT] = { NULL };
	resolver_cache_entry *extra_entry = NULL;
	resolver_cache *result_cache = NULL;
	resolver_cache_entry *result_entry = NULL;
	dns_srv_result large_result = { 0 };
	dns_srv_result small_result = { 0 };
	resolver_cache_view view = { 0 };
	const struct timespec completed_at = { .tv_sec = 100 };
	CHECK(entry_cache != NULL, "entry-limit cache could not be created");
	for (size_t index = 0; index < RESOLVER_CACHE_ENTRY_LIMIT; index++) {
		char name[64];
		CHECK(snprintf(name, sizeof(name), "entry%zu.cache.test", index) > 0, "entry-limit name could not be formatted");
		CHECK(resolver_cache_entry_acquire(entry_cache, name, ns_t_a, &entries[index]) == RESOLVER_CACHE_ACQUIRE_OK, "entry below the entry limit was rejected");
	}
	CHECK(resolver_cache_entry_acquire(entry_cache, "overflow.cache.test", ns_t_a, &extra_entry) == RESOLVER_CACHE_ACQUIRE_LIMIT && extra_entry == NULL,
		"entry above the entry limit was accepted");

	result_cache = resolver_cache_create();
	CHECK(result_cache != NULL, "result-limit cache could not be created");
	CHECK(resolver_cache_entry_acquire(result_cache, "_minecraft._tcp.large.cache.test", ns_t_srv, &result_entry) == RESOLVER_CACHE_ACQUIRE_OK, "result-limit entry could not be acquired");
	CHECK(cache_srv_result_create(&small_result, "_minecraft._tcp.large.cache.test", 1, 30, false), "small SRV result could not be created");
	CHECK(resolver_cache_entry_publish_srv(result_entry, DNS_SRV_LOOKUP_OK, &completed_at, &small_result) == RESOLVER_CACHE_PUBLISH_STORED, "baseline SRV result was not stored");
	CHECK(cache_srv_result_create(&large_result, "_minecraft._tcp.large.cache.test", DNS_SRV_RECORD_LIMIT, 30, false), "large SRV result could not be created");
	CHECK(resolver_cache_entry_publish_srv(result_entry, DNS_SRV_LOOKUP_OK, &completed_at, &large_result) == RESOLVER_CACHE_PUBLISH_LIMIT && large_result.records != NULL,
		"oversized SRV result was consumed or accepted");
	CHECK(resolver_cache_entry_view(result_entry, &completed_at, &view) && view.status == RESOLVER_CACHE_VIEW_FRESH_POSITIVE && view.srv_record_count == 1,
		"oversized replacement discarded the old SRV payload");

	byte_cache = resolver_cache_create();
	CHECK(byte_cache != NULL, "byte-limit cache could not be created");
	CHECK(resolver_cache_entry_acquire(byte_cache, "first.bytes.cache.test", ns_t_a, &byte_entries[0]) == RESOLVER_CACHE_ACQUIRE_OK
		&& resolver_cache_entry_acquire(byte_cache, "second.bytes.cache.test", ns_t_a, &byte_entries[1]) == RESOLVER_CACHE_ACQUIRE_OK, "byte-limit entries could not be acquired");
	CHECK(cache_address_result_create(&byte_results[0], "first.bytes.cache.test", AF_INET, 1, 30, true)
		&& cache_address_result_create(&byte_results[1], "second.bytes.cache.test", AF_INET, 1, 30, true), "byte-limit results could not be created");
	CHECK(resolver_cache_entry_publish_address(byte_entries[0], DNS_ADDRESS_LOOKUP_OK, &completed_at, &byte_results[0]) == RESOLVER_CACHE_PUBLISH_STORED,
		"first result below the owned-byte limit was rejected");
	CHECK(resolver_cache_entry_publish_address(byte_entries[1], DNS_ADDRESS_LOOKUP_OK, &completed_at, &byte_results[1]) == RESOLVER_CACHE_PUBLISH_LIMIT && byte_results[1].addresses != NULL,
		"result above the owned-byte limit was consumed or accepted");
	CHECK(cache_address_result_create(&byte_results[0], "first.bytes.cache.test", AF_INET, 1, 25, true), "same-size replacement result could not be created");
	CHECK(resolver_cache_entry_publish_address(byte_entries[0], DNS_ADDRESS_LOOKUP_OK, &completed_at, &byte_results[0]) == RESOLVER_CACHE_PUBLISH_STORED,
		"same-size payload replacement did not discount the old payload from steady-state accounting");
	CHECK(resolver_cache_owned_bytes(byte_cache) <= RESOLVER_CACHE_OWNED_BYTE_LIMIT, "cache exceeded its owned-byte limit");
	test_result = true;

cleanup:
	for (size_t index = 0; index < RESOLVER_CACHE_ENTRY_LIMIT; index++) {
		resolver_cache_entry_release(entries[index]);
	}
	resolver_cache_entry_release(extra_entry);
	resolver_cache_entry_release(result_entry);
	for (size_t index = 0; index < 2; index++) {
		resolver_cache_entry_release(byte_entries[index]);
		dns_address_result_destroy(&byte_results[index]);
	}
	dns_srv_result_destroy(&large_result);
	dns_srv_result_destroy(&small_result);
	resolver_cache_destroy(byte_cache);
	resolver_cache_destroy(entry_cache);
	resolver_cache_destroy(result_cache);
	return test_result;
}

static bool cache_test_key_lifetime(void) {
	int test_result = false;
	resolver_cache *cache = resolver_cache_create();
	resolver_cache_entry *address = NULL;
	resolver_cache_entry *address_again = NULL;
	resolver_cache_entry *address_new = NULL;
	resolver_cache_entry *address_v6 = NULL;
	resolver_cache_entry *root = NULL;
	resolver_cache_entry *srv = NULL;
	uint64_t old_id = 0;
	CHECK(cache != NULL, "key cache could not be created");
	CHECK(resolver_cache_entry_acquire(cache, "Example.COM.", ns_t_a, &address) == RESOLVER_CACHE_ACQUIRE_OK, "address entry could not be acquired");
	old_id = resolver_cache_entry_id(address);
	CHECK(old_id != 0 && strcmp(resolver_cache_entry_name(address), "example.com") == 0 && resolver_cache_entry_query_type(address) == ns_t_a, "address key was not normalized");
	CHECK(resolver_cache_entry_acquire(cache, "example.com", ns_t_a, &address_again) == RESOLVER_CACHE_ACQUIRE_OK && address_again == address, "equivalent address key was not deduplicated");
	CHECK(resolver_cache_entry_acquire(cache, "example.com", ns_t_aaaa, &address_v6) == RESOLVER_CACHE_ACQUIRE_OK && address_v6 != address, "address query types shared an entry");
	CHECK(resolver_cache_entry_acquire(cache, "example.com", ns_t_srv, &srv) == RESOLVER_CACHE_ACQUIRE_OK && srv != address && srv != address_v6, "SRV query shared an address entry");
	CHECK(resolver_cache_entry_acquire(cache, ".", ns_t_a, &root) == RESOLVER_CACHE_ACQUIRE_OK && strcmp(resolver_cache_entry_name(root), ".") == 0, "root query name was not preserved");
	CHECK(resolver_cache_entry_retain(root), "entry could not be explicitly retained");
	resolver_cache_entry_release(root);
	CHECK(resolver_cache_entry_count(cache) == 4, "cache returned the wrong deduplicated entry count");
	resolver_cache_entry_release(address);
	address = NULL;
	CHECK(resolver_cache_entry_count(cache) == 4, "entry was removed while another reference remained");
	resolver_cache_entry_release(address_again);
	address_again = NULL;
	CHECK(resolver_cache_entry_count(cache) == 3, "zero-reference entry was not removed");
	CHECK(resolver_cache_entry_acquire(cache, "EXAMPLE.COM.", ns_t_a, &address_new) == RESOLVER_CACHE_ACQUIRE_OK && resolver_cache_entry_id(address_new) > old_id,
		"recreated entry reused its listener-local ID");
	test_result = true;

cleanup:
	resolver_cache_entry_release(address);
	resolver_cache_entry_release(address_again);
	resolver_cache_entry_release(address_new);
	resolver_cache_entry_release(address_v6);
	resolver_cache_entry_release(root);
	resolver_cache_entry_release(srv);
	resolver_cache_destroy(cache);
	return test_result;
}

static bool cache_test_negative(void) {
	int test_result = false;
	resolver_cache *cache = resolver_cache_create();
	resolver_cache_entry *entry = NULL;
	dns_address_result result = { 0 };
	resolver_cache_view view = { 0 };
	const struct timespec completed_at = { .tv_sec = 50, .tv_nsec = 42 };
	CHECK(cache != NULL, "negative cache could not be created");
	CHECK(resolver_cache_entry_acquire(cache, "negative.cache.test", ns_t_a, &entry) == RESOLVER_CACHE_ACQUIRE_OK, "negative entry could not be acquired");
	CHECK(snprintf(result.question_name, sizeof(result.question_name), "%s", "negative.cache.test") > 0
		&& snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", "negative.cache.test") > 0 && cache_negative_set(&result.negative, "cache.test", 15, true),
		"negative NODATA result could not be created");
	result.rcode = ns_r_noerror;
	CHECK(resolver_cache_entry_publish_address(entry, DNS_ADDRESS_LOOKUP_NODATA, &completed_at, &result) == RESOLVER_CACHE_PUBLISH_STORED, "authoritative NODATA result was not stored");
	const struct timespec nodata_now = { .tv_sec = 64, .tv_nsec = 42 };
	CHECK(resolver_cache_entry_view(entry, &nodata_now, &view) && view.status == RESOLVER_CACHE_VIEW_FRESH_NODATA && view.addresses == NULL && view.srv_records == NULL,
		"authoritative NODATA view was invalid");
	CHECK(snprintf(result.question_name, sizeof(result.question_name), "%s", "negative.cache.test") > 0
		&& snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", "negative.cache.test") > 0 && cache_negative_set(&result.negative, "cache.test", 7, true),
		"negative NXDOMAIN result could not be created");
	result.rcode = ns_r_nxdomain;
	CHECK(resolver_cache_entry_publish_address(entry, DNS_ADDRESS_LOOKUP_NOT_FOUND, &completed_at, &result) == RESOLVER_CACHE_PUBLISH_STORED, "authoritative NXDOMAIN result was not stored");
	CHECK(resolver_cache_entry_view(entry, &completed_at, &view) && view.status == RESOLVER_CACHE_VIEW_FRESH_NXDOMAIN && view.expires_at.tv_sec == 57,
		"authoritative NXDOMAIN view was invalid");
	CHECK(snprintf(result.question_name, sizeof(result.question_name), "%s", "negative.cache.test") > 0
		&& snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", "negative.cache.test") > 0 && cache_negative_set(&result.negative, NULL, 0, false),
		"non-authoritative NODATA result could not be created");
	result.rcode = ns_r_noerror;
	CHECK(resolver_cache_entry_publish_address(entry, DNS_ADDRESS_LOOKUP_NODATA, &completed_at, &result) == RESOLVER_CACHE_PUBLISH_TRANSIENT,
		"NODATA without SOA was persisted");
	CHECK(result.question_name[0] != '\0' && resolver_cache_entry_view(entry, &completed_at, &view) && view.status == RESOLVER_CACHE_VIEW_EMPTY,
		"transient NODATA did not preserve caller ownership and clear the old payload");
	dns_address_result_destroy(&result);
	CHECK(snprintf(result.question_name, sizeof(result.question_name), "%s", "negative.cache.test") > 0
		&& snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", "negative.cache.test") > 0 && cache_negative_set(&result.negative, "cache.test", 0, true),
		"zero-TTL NXDOMAIN result could not be created");
	result.rcode = ns_r_nxdomain;
	CHECK(resolver_cache_entry_publish_address(entry, DNS_ADDRESS_LOOKUP_NOT_FOUND, &completed_at, &result) == RESOLVER_CACHE_PUBLISH_TRANSIENT && result.negative.valid,
		"zero-TTL NXDOMAIN result was consumed or persisted");
	test_result = true;

cleanup:
	dns_address_result_destroy(&result);
	resolver_cache_entry_release(entry);
	resolver_cache_destroy(cache);
	return test_result;
}

static bool cache_test_negative_srv(void) {
	int test_result = false;
	resolver_cache *cache = resolver_cache_create();
	resolver_cache_entry *entry = NULL;
	dns_srv_result result = { 0 };
	resolver_cache_view view = { 0 };
	const struct timespec completed_at = { .tv_sec = 75 };
	CHECK(cache != NULL, "negative SRV cache could not be created");
	CHECK(resolver_cache_entry_acquire(cache, "_minecraft._tcp.negative.cache.test", ns_t_srv, &entry) == RESOLVER_CACHE_ACQUIRE_OK, "negative SRV entry could not be acquired");
	CHECK(snprintf(result.question_name, sizeof(result.question_name), "%s", "_minecraft._tcp.negative.cache.test") > 0
		&& snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", "_minecraft._tcp.negative.cache.test") > 0 && cache_negative_set(&result.negative, "cache.test", 9, true),
		"negative SRV result could not be created");
	result.rcode = ns_r_nxdomain;
	CHECK(resolver_cache_entry_publish_srv(entry, DNS_SRV_LOOKUP_NOT_FOUND, &completed_at, &result) == RESOLVER_CACHE_PUBLISH_STORED, "authoritative SRV NXDOMAIN result was not stored");
	CHECK(resolver_cache_entry_view(entry, &completed_at, &view) && view.status == RESOLVER_CACHE_VIEW_FRESH_NXDOMAIN && view.addresses == NULL && view.srv_records == NULL,
		"authoritative SRV NXDOMAIN view was invalid");
	CHECK(snprintf(result.question_name, sizeof(result.question_name), "%s", "_minecraft._tcp.negative.cache.test") > 0
		&& snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", "_minecraft._tcp.negative.cache.test") > 0 && cache_negative_set(&result.negative, NULL, 0, false),
		"non-authoritative SRV NODATA result could not be created");
	result.rcode = ns_r_noerror;
	CHECK(resolver_cache_entry_publish_srv(entry, DNS_SRV_LOOKUP_NODATA, &completed_at, &result) == RESOLVER_CACHE_PUBLISH_TRANSIENT && result.question_name[0] != '\0',
		"SRV NODATA without SOA was consumed or persisted");
	CHECK(resolver_cache_entry_view(entry, &completed_at, &view) && view.status == RESOLVER_CACHE_VIEW_EMPTY, "transient SRV NODATA did not clear the old payload");
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	resolver_cache_entry_release(entry);
	resolver_cache_destroy(cache);
	return test_result;
}

static bool cache_test_positive_address(void) {
	int test_result = false;
	resolver_cache *cache = resolver_cache_create();
	resolver_cache_entry *entry = NULL;
	dns_address_result result = { 0 };
	resolver_cache_view view = { 0 };
	const struct timespec completed_at = { .tv_sec = 100, .tv_nsec = 321 };
	size_t empty_bytes = 0;
	CHECK(cache != NULL, "address cache could not be created");
	CHECK(resolver_cache_entry_acquire(cache, "address.cache.test", ns_t_a, &entry) == RESOLVER_CACHE_ACQUIRE_OK, "address entry could not be acquired");
	empty_bytes = resolver_cache_owned_bytes(cache);
	CHECK(cache_address_result_create(&result, "ADDRESS.CACHE.TEST.", AF_INET, 2, 30, true), "address result could not be created");
	result.addresses[1].effective_ttl = 12;
	CHECK(resolver_cache_entry_publish_address(entry, DNS_ADDRESS_LOOKUP_OK, &completed_at, &result) == RESOLVER_CACHE_PUBLISH_STORED, "address result was not stored");
	CHECK(result.addresses == NULL && result.cnames == NULL && result.question_name[0] == '\0', "stored address result ownership was not transferred");
	CHECK(resolver_cache_owned_bytes(cache) > empty_bytes, "stored address payload was not counted");
	const struct timespec fresh_now = { .tv_sec = 112, .tv_nsec = 320 };
	const struct timespec expected_expiry = { .tv_sec = 112, .tv_nsec = 321 };
	CHECK(resolver_cache_entry_view(entry, &fresh_now, &view) && view.status == RESOLVER_CACHE_VIEW_FRESH_POSITIVE && view.address_count == 2 && view.addresses != NULL,
		"fresh address view was invalid");
	CHECK(view.srv_records == NULL && view.srv_record_count == 0 && cache_time_equal(&view.completed_at, &completed_at) && cache_time_equal(&view.expires_at, &expected_expiry),
		"fresh address metadata was invalid");
	CHECK(view.addresses[0].address.family == AF_INET && view.addresses[1].effective_ttl == 12, "address record order or data was not preserved");
	CHECK(resolver_cache_entry_view(entry, &expected_expiry, &view) && view.status == RESOLVER_CACHE_VIEW_EMPTY && view.addresses == NULL,
		"address payload remained visible at its exact expiry");
	CHECK(resolver_cache_owned_bytes(cache) == empty_bytes, "expired address payload was not removed from the byte budget");
	test_result = true;

cleanup:
	dns_address_result_destroy(&result);
	resolver_cache_entry_release(entry);
	resolver_cache_destroy(cache);
	return test_result;
}

static bool cache_test_positive_srv(void) {
	int test_result = false;
	resolver_cache *cache = resolver_cache_create();
	resolver_cache_entry *entry = NULL;
	dns_srv_result result = { 0 };
	resolver_cache_view view = { 0 };
	const struct timespec completed_at = { .tv_sec = 200, .tv_nsec = 500 };
	CHECK(cache != NULL, "SRV cache could not be created");
	CHECK(resolver_cache_entry_acquire(cache, "_minecraft._tcp.cache.test", ns_t_srv, &entry) == RESOLVER_CACHE_ACQUIRE_OK, "SRV entry could not be acquired");
	CHECK(cache_srv_result_create(&result, "_MINECRAFT._TCP.CACHE.TEST.", 2, 20, true), "SRV result could not be created");
	result.records[0].effective_ttl = 8;
	CHECK(resolver_cache_entry_publish_srv(entry, DNS_SRV_LOOKUP_OK, &completed_at, &result) == RESOLVER_CACHE_PUBLISH_STORED, "SRV result was not stored");
	CHECK(result.records == NULL && result.cnames == NULL && result.question_name[0] == '\0', "stored SRV result ownership was not transferred");
	const struct timespec fresh_now = { .tv_sec = 208, .tv_nsec = 499 };
	CHECK(resolver_cache_entry_view(entry, &fresh_now, &view) && view.status == RESOLVER_CACHE_VIEW_FRESH_POSITIVE && view.srv_record_count == 2 && view.srv_records != NULL,
		"fresh SRV view was invalid");
	CHECK(view.addresses == NULL && view.address_count == 0 && view.srv_records[0].port == 25565 && strcmp(view.srv_records[1].target, "target1.cache.test") == 0,
		"SRV record order or data was not preserved");
	const struct timespec expired_now = { .tv_sec = 208, .tv_nsec = 500 };
	CHECK(resolver_cache_entry_view(entry, &expired_now, &view) && view.status == RESOLVER_CACHE_VIEW_EMPTY, "SRV payload remained visible at its exact expiry");
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	resolver_cache_entry_release(entry);
	resolver_cache_destroy(cache);
	return test_result;
}

static bool cache_test_publication_failures(void) {
	int test_result = false;
	resolver_cache *cache = resolver_cache_create();
	resolver_cache_entry *address_entry = NULL;
	resolver_cache_entry *srv_entry = NULL;
	dns_address_result candidate = { 0 };
	dns_address_result stored = { 0 };
	resolver_cache_view view = { 0 };
	const struct timespec completed_at = { .tv_sec = 1000 };
	CHECK(cache != NULL, "publication cache could not be created");
	CHECK(resolver_cache_entry_acquire(cache, "publish.cache.test", ns_t_a, &address_entry) == RESOLVER_CACHE_ACQUIRE_OK
		&& resolver_cache_entry_acquire(cache, "_minecraft._tcp.publish.cache.test", ns_t_srv, &srv_entry) == RESOLVER_CACHE_ACQUIRE_OK, "publication entries could not be acquired");
	CHECK(cache_address_result_create(&stored, "publish.cache.test", AF_INET, 1, 100, false), "stored publication result could not be created");
	CHECK(resolver_cache_entry_publish_address(address_entry, DNS_ADDRESS_LOOKUP_OK, &completed_at, &stored) == RESOLVER_CACHE_PUBLISH_STORED, "baseline publication failed");
	CHECK(cache_address_result_create(&candidate, "mismatch.cache.test", AF_INET, 1, 10, false), "mismatched publication result could not be created");
	CHECK(resolver_cache_entry_publish_address(address_entry, DNS_ADDRESS_LOOKUP_OK, &completed_at, &candidate) == RESOLVER_CACHE_PUBLISH_INVALID && candidate.addresses != NULL,
		"mismatched result was consumed or accepted");
	CHECK(resolver_cache_entry_view(address_entry, &completed_at, &view) && view.status == RESOLVER_CACHE_VIEW_FRESH_POSITIVE && view.addresses[0].effective_ttl == 100,
		"invalid publication replaced the old payload");
	dns_address_result_destroy(&candidate);
	CHECK(cache_address_result_create(&candidate, "publish.cache.test", AF_INET, 1, 10, false), "timed publication result could not be created");
	const struct timespec invalid_time = { .tv_sec = 1001, .tv_nsec = 1000000000L };
	CHECK(resolver_cache_entry_publish_address(address_entry, DNS_ADDRESS_LOOKUP_OK, &invalid_time, &candidate) == RESOLVER_CACHE_PUBLISH_TIME && candidate.addresses != NULL,
		"invalid completion time consumed or replaced a result");
	struct timespec overflow_time = { .tv_sec = cache_time_max() };
	CHECK(resolver_cache_entry_publish_address(address_entry, DNS_ADDRESS_LOOKUP_OK, &overflow_time, &candidate) == RESOLVER_CACHE_PUBLISH_TIME && candidate.addresses != NULL,
		"expiry overflow consumed or replaced a result");
	CHECK(resolver_cache_entry_publish_address(address_entry, DNS_ADDRESS_LOOKUP_TEMPORARY_ERROR, &completed_at, &candidate) == RESOLVER_CACHE_PUBLISH_INVALID && candidate.addresses != NULL,
		"temporary resolver failure was accepted by the cache");
	CHECK(resolver_cache_entry_publish_address(srv_entry, DNS_ADDRESS_LOOKUP_OK, &completed_at, &candidate) == RESOLVER_CACHE_PUBLISH_INVALID && candidate.addresses != NULL,
		"address result was accepted by an SRV entry");
	dns_address_result_destroy(&candidate);
	CHECK(cache_address_result_create(&candidate, "publish.cache.test", AF_INET, 1, 0, false), "zero-TTL address result could not be created");
	CHECK(resolver_cache_entry_publish_address(address_entry, DNS_ADDRESS_LOOKUP_OK, &completed_at, &candidate) == RESOLVER_CACHE_PUBLISH_TRANSIENT && candidate.addresses != NULL,
		"zero-TTL address result was consumed or persisted");
	CHECK(resolver_cache_entry_view(address_entry, &completed_at, &view) && view.status == RESOLVER_CACHE_VIEW_EMPTY, "zero-TTL authoritative result did not clear the old payload");
	test_result = true;

cleanup:
	dns_address_result_destroy(&candidate);
	dns_address_result_destroy(&stored);
	resolver_cache_entry_release(address_entry);
	resolver_cache_entry_release(srv_entry);
	resolver_cache_destroy(cache);
	return test_result;
}

/* section: functions (entry point) */
int main(void) {
	int test_result = EXIT_FAILURE;
	CHECK(cache_test_arguments(), "cache argument tests failed");
	CHECK(cache_test_capacity(), "cache capacity tests failed");
	CHECK(cache_test_key_lifetime(), "cache key-lifetime tests failed");
	CHECK(cache_test_negative(), "cache negative-result tests failed");
	CHECK(cache_test_negative_srv(), "cache negative-SRV tests failed");
	CHECK(cache_test_positive_address(), "cache positive-address tests failed");
	CHECK(cache_test_positive_srv(), "cache positive-SRV tests failed");
	CHECK(cache_test_publication_failures(), "cache publication-failure tests failed");
	test_result = EXIT_SUCCESS;

cleanup:
	return test_result;
}
