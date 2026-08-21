/*
 * resolver/cache.c: Listener-owned DNS result cache
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "util.h"

/* section: headers (self) */
#include "cache.h"

/* section: defines */
/* hash */
#define RESOLVER_CACHE_HASH_OFFSET	UINT64_C(14695981039346656037)
#define RESOLVER_CACHE_HASH_PRIME	UINT64_C(1099511628211)

/* section: types */
typedef enum {
	RESOLVER_CACHE_PAYLOAD_ADDRESS,
	RESOLVER_CACHE_PAYLOAD_SRV
} resolver_cache_payload_type;
typedef struct {
	struct timespec completed_at;
	struct timespec expires_at;
	size_t owned_bytes;
	union {
		dns_address_result address;
		dns_srv_result srv;
	} result;
	resolver_cache_view_status status;
	resolver_cache_payload_type type;
} resolver_cache_payload;
struct resolver_cache_entry {
	resolver_cache *cache;
	uint64_t hash;
	uint64_t id;
	char name[NS_MAXDNAME];
	struct resolver_cache_entry *next;
	resolver_cache_payload *payload;
	uint16_t query_type;
	size_t reference_count;
};
struct resolver_cache {
	resolver_cache_entry **buckets;
	size_t bucket_count;
	size_t entry_count;
	uint64_t next_entry_id;
	size_t owned_bytes;
};

/* section: functions (local) */
static resolver_cache_entry *resolver_cache_entry_find(const resolver_cache *cache, const char *name, uint16_t query_type, uint64_t hash) {
	size_t bucket_index = (size_t)(hash % cache->bucket_count);
	for (resolver_cache_entry *entry = cache->buckets[bucket_index]; entry != NULL; entry = entry->next) {
		if (entry->hash == hash && entry->query_type == query_type && strcmp(entry->name, name) == 0) {
			return entry;
		}
	}
	return NULL;
}

static void resolver_cache_entry_payload_clear(resolver_cache_entry *entry) {
	if (entry->payload == NULL) {
		return;
	}
	resolver_cache_payload *payload = entry->payload;
	entry->payload = NULL;
	if (payload->type == RESOLVER_CACHE_PAYLOAD_ADDRESS) {
		dns_address_result_destroy(&payload->result.address);
	} else {
		dns_srv_result_destroy(&payload->result.srv);
	}
	if (entry->cache->owned_bytes >= payload->owned_bytes) {
		entry->cache->owned_bytes -= payload->owned_bytes;
	} else {
		entry->cache->owned_bytes = 0;
	}
	free(payload);
}

static uint64_t resolver_cache_hash(const char *name, uint16_t query_type) {
	uint64_t result = RESOLVER_CACHE_HASH_OFFSET;
	for (size_t index = 0; name[index] != '\0'; index++) {
		result ^= (uint8_t)name[index];
		result *= RESOLVER_CACHE_HASH_PRIME;
	}
	result ^= (uint8_t)(query_type >> 8);
	result *= RESOLVER_CACHE_HASH_PRIME;
	result ^= (uint8_t)query_type;
	result *= RESOLVER_CACHE_HASH_PRIME;
	return result;
}

static bool resolver_cache_name_valid(const char *source) {
	char normalized[NS_MAXDNAME];
	return resolver_name_normalize(source, normalized);
}

static bool resolver_cache_cnames_valid(const dns_cname_record *cnames, size_t cname_count) {
	if (cname_count > DNS_CNAME_DEPTH_LIMIT || (cname_count == 0) != (cnames == NULL)) {
		return false;
	}
	for (size_t index = 0; index < cname_count; index++) {
		if (!resolver_cache_name_valid(cnames[index].owner) || !resolver_cache_name_valid(cnames[index].target)) {
			return false;
		}
	}
	return true;
}

static bool resolver_cache_negative_valid(const dns_negative_record *negative) {
	if (!negative->valid) {
		return negative->effective_ttl == 0 && negative->minimum == 0 && negative->owner[0] == '\0' && negative->record_ttl == 0;
	}
	return resolver_cache_name_valid(negative->owner) && negative->effective_ttl <= negative->minimum && negative->effective_ttl <= negative->record_ttl;
}

static bool resolver_cache_query_type_valid(uint16_t query_type) {
	return query_type == ns_t_a || query_type == ns_t_aaaa || query_type == ns_t_srv;
}

static bool resolver_cache_question_matches(const resolver_cache_entry *entry, const char *question_name) {
	char normalized[NS_MAXDNAME];
	return resolver_name_normalize(question_name, normalized) && strcmp(entry->name, normalized) == 0;
}

static bool resolver_cache_address_result_size(const dns_address_result *result, size_t *result_size) {
	size_t size = sizeof(resolver_cache_payload);
	size_t array_size;
	if (!resolver_size_multiply(result->address_count, sizeof(*result->addresses), &array_size) || !resolver_size_add(&size, array_size)) {
		return false;
	}
	if (result->cnames != NULL
		&& (!resolver_size_multiply(DNS_CNAME_DEPTH_LIMIT, sizeof(*result->cnames), &array_size) || !resolver_size_add(&size, array_size))) {
		return false;
	}
	*result_size = size;
	return true;
}

static bool resolver_cache_address_result_validate(const resolver_cache_entry *entry, dns_address_lookup_status lookup_status, const dns_address_result *result, uint32_t *ttl,
	resolver_cache_view_status *view_status) {
	if ((entry->query_type != ns_t_a && entry->query_type != ns_t_aaaa) || result == NULL || ttl == NULL || view_status == NULL
		|| !resolver_cache_question_matches(entry, result->question_name) || !resolver_cache_name_valid(result->canonical_name)
		|| !resolver_cache_cnames_valid(result->cnames, result->cname_count) || !resolver_cache_negative_valid(&result->negative)) {
		return false;
	}
	if (lookup_status == DNS_ADDRESS_LOOKUP_OK) {
		if (result->rcode != ns_r_noerror || result->addresses == NULL || result->address_count == 0 || result->address_count > DNS_ADDRESS_RECORD_LIMIT || result->negative.valid) {
			return false;
		}
		*ttl = UINT32_MAX;
		sa_family_t expected_family = entry->query_type == ns_t_a ? AF_INET : AF_INET6;
		for (size_t index = 0; index < result->address_count; index++) {
			if (result->addresses[index].address.family != expected_family || result->addresses[index].effective_ttl > result->addresses[index].record_ttl) {
				return false;
			}
			if (result->addresses[index].effective_ttl < *ttl) {
				*ttl = result->addresses[index].effective_ttl;
			}
		}
		*view_status = RESOLVER_CACHE_VIEW_FRESH_POSITIVE;
		return true;
	}
	if (result->addresses != NULL || result->address_count != 0 || (lookup_status != DNS_ADDRESS_LOOKUP_NODATA && lookup_status != DNS_ADDRESS_LOOKUP_NOT_FOUND)) {
		return false;
	}
	if ((lookup_status == DNS_ADDRESS_LOOKUP_NODATA && result->rcode != ns_r_noerror) || (lookup_status == DNS_ADDRESS_LOOKUP_NOT_FOUND && result->rcode != ns_r_nxdomain)) {
		return false;
	}
	*ttl = result->negative.valid ? result->negative.effective_ttl : 0;
	*view_status = lookup_status == DNS_ADDRESS_LOOKUP_NODATA ? RESOLVER_CACHE_VIEW_FRESH_NODATA : RESOLVER_CACHE_VIEW_FRESH_NXDOMAIN;
	return true;
}

static bool resolver_cache_srv_result_size(const dns_srv_result *result, size_t *result_size) {
	size_t size = sizeof(resolver_cache_payload);
	size_t array_size;
	if (!resolver_size_multiply(result->record_count, sizeof(*result->records), &array_size) || !resolver_size_add(&size, array_size)) {
		return false;
	}
	if (result->cnames != NULL
		&& (!resolver_size_multiply(DNS_CNAME_DEPTH_LIMIT, sizeof(*result->cnames), &array_size) || !resolver_size_add(&size, array_size))) {
		return false;
	}
	*result_size = size;
	return true;
}

static bool resolver_cache_srv_result_validate(const resolver_cache_entry *entry, dns_srv_lookup_status lookup_status, const dns_srv_result *result, uint32_t *ttl,
	resolver_cache_view_status *view_status) {
	if (entry->query_type != ns_t_srv || result == NULL || ttl == NULL || view_status == NULL || !resolver_cache_question_matches(entry, result->question_name)
		|| !resolver_cache_name_valid(result->canonical_name) || !resolver_cache_cnames_valid(result->cnames, result->cname_count) || !resolver_cache_negative_valid(&result->negative)) {
		return false;
	}
	if (lookup_status == DNS_SRV_LOOKUP_OK) {
		if (result->rcode != ns_r_noerror || result->records == NULL || result->record_count == 0 || result->record_count > DNS_SRV_RECORD_LIMIT || result->negative.valid) {
			return false;
		}
		*ttl = UINT32_MAX;
		for (size_t index = 0; index < result->record_count; index++) {
			if (!resolver_cache_name_valid(result->records[index].target) || result->records[index].effective_ttl > result->records[index].record_ttl) {
				return false;
			}
			if (result->records[index].effective_ttl < *ttl) {
				*ttl = result->records[index].effective_ttl;
			}
		}
		*view_status = RESOLVER_CACHE_VIEW_FRESH_POSITIVE;
		return true;
	}
	if (result->records != NULL || result->record_count != 0 || (lookup_status != DNS_SRV_LOOKUP_NODATA && lookup_status != DNS_SRV_LOOKUP_NOT_FOUND)) {
		return false;
	}
	if ((lookup_status == DNS_SRV_LOOKUP_NODATA && result->rcode != ns_r_noerror) || (lookup_status == DNS_SRV_LOOKUP_NOT_FOUND && result->rcode != ns_r_nxdomain)) {
		return false;
	}
	*ttl = result->negative.valid ? result->negative.effective_ttl : 0;
	*view_status = lookup_status == DNS_SRV_LOOKUP_NODATA ? RESOLVER_CACHE_VIEW_FRESH_NODATA : RESOLVER_CACHE_VIEW_FRESH_NXDOMAIN;
	return true;
}

static int resolver_cache_time_compare(const struct timespec *left, const struct timespec *right) {
	if (left->tv_sec < right->tv_sec) {
		return -1;
	}
	if (left->tv_sec > right->tv_sec) {
		return 1;
	}
	if (left->tv_nsec < right->tv_nsec) {
		return -1;
	}
	return left->tv_nsec > right->tv_nsec ? 1 : 0;
}

static bool resolver_cache_time_valid(const struct timespec *timestamp) {
	return timestamp != NULL && timestamp->tv_sec >= 0 && timestamp->tv_nsec >= 0 && timestamp->tv_nsec < 1000000000L;
}

static bool resolver_cache_expiry_calculate(const struct timespec *completed_at, uint32_t ttl, struct timespec *expires_at) {
	if (!resolver_cache_time_valid(completed_at) || expires_at == NULL) {
		return false;
	}
	uintmax_t completed_seconds = (uintmax_t)completed_at->tv_sec;
	if (completed_seconds > UINTMAX_MAX - ttl) {
		return false;
	}
	uintmax_t expiry_seconds = completed_seconds + ttl;
	time_t converted_seconds = (time_t)expiry_seconds;
	if (converted_seconds < 0 || (uintmax_t)converted_seconds != expiry_seconds) {
		return false;
	}
	*expires_at = *completed_at;
	expires_at->tv_sec = converted_seconds;
	return true;
}

static resolver_cache_publish_status resolver_cache_entry_payload_publish(resolver_cache_entry *entry, resolver_cache_payload_type payload_type, resolver_cache_view_status view_status,
	const struct timespec *completed_at, uint32_t ttl, size_t result_size, void *result) {
	if (!resolver_cache_time_valid(completed_at)) {
		return RESOLVER_CACHE_PUBLISH_TIME;
	}
	if (result_size > (size_t)RESOLVER_CACHE_RESULT_BYTE_LIMIT) {
		return RESOLVER_CACHE_PUBLISH_LIMIT;
	}
	if (ttl == 0) {
		resolver_cache_entry_payload_clear(entry);
		return RESOLVER_CACHE_PUBLISH_TRANSIENT;
	}
	struct timespec expires_at;
	if (!resolver_cache_expiry_calculate(completed_at, ttl, &expires_at)) {
		return RESOLVER_CACHE_PUBLISH_TIME;
	}
	resolver_cache *cache = entry->cache;
	size_t old_payload_size = entry->payload == NULL ? 0 : entry->payload->owned_bytes;
	size_t retained_size = cache->owned_bytes - old_payload_size;
	if (result_size > (size_t)RESOLVER_CACHE_OWNED_BYTE_LIMIT || retained_size > (size_t)RESOLVER_CACHE_OWNED_BYTE_LIMIT - result_size) {
		return RESOLVER_CACHE_PUBLISH_LIMIT;
	}
	resolver_cache_payload *payload = calloc(1, sizeof(*payload));
	if (payload == NULL) {
		return RESOLVER_CACHE_PUBLISH_MEMORY;
	}
	payload->completed_at = *completed_at;
	payload->expires_at = expires_at;
	payload->owned_bytes = result_size;
	payload->status = view_status;
	payload->type = payload_type;
	if (payload_type == RESOLVER_CACHE_PAYLOAD_ADDRESS) {
		payload->result.address = *((dns_address_result *)result);
		memset(result, 0, sizeof(dns_address_result));
	} else {
		payload->result.srv = *((dns_srv_result *)result);
		memset(result, 0, sizeof(dns_srv_result));
	}
	resolver_cache_entry_payload_clear(entry);
	entry->payload = payload;
	cache->owned_bytes += result_size;
	return RESOLVER_CACHE_PUBLISH_STORED;
}

/* section: functions (exported) */
resolver_cache *resolver_cache_create(void) {
	if (RESOLVER_CACHE_ENTRY_LIMIT == 0 || RESOLVER_CACHE_OWNED_BYTE_LIMIT == 0 || RESOLVER_CACHE_RESULT_BYTE_LIMIT == 0) {
		return NULL;
	}
	size_t bucket_bytes;
	if (!resolver_size_multiply((size_t)RESOLVER_CACHE_ENTRY_LIMIT, sizeof(resolver_cache_entry *), &bucket_bytes)
		|| sizeof(resolver_cache) > (size_t)RESOLVER_CACHE_OWNED_BYTE_LIMIT || bucket_bytes > (size_t)RESOLVER_CACHE_OWNED_BYTE_LIMIT - sizeof(resolver_cache)) {
		return NULL;
	}
	resolver_cache *cache = calloc(1, sizeof(*cache));
	if (cache == NULL) {
		return NULL;
	}
	cache->buckets = calloc((size_t)RESOLVER_CACHE_ENTRY_LIMIT, sizeof(*cache->buckets));
	if (cache->buckets == NULL) {
		free(cache);
		return NULL;
	}
	cache->bucket_count = (size_t)RESOLVER_CACHE_ENTRY_LIMIT;
	cache->next_entry_id = 1;
	cache->owned_bytes = sizeof(*cache) + bucket_bytes;
	return cache;
}

void resolver_cache_destroy(resolver_cache *cache) {
	if (cache == NULL) {
		return;
	}
	for (size_t bucket_index = 0; bucket_index < cache->bucket_count; bucket_index++) {
		resolver_cache_entry *entry = cache->buckets[bucket_index];
		while (entry != NULL) {
			resolver_cache_entry *next = entry->next;
			resolver_cache_entry_payload_clear(entry);
			free(entry);
			entry = next;
		}
	}
	free(cache->buckets);
	free(cache);
}

resolver_cache_acquire_status resolver_cache_entry_acquire(resolver_cache *cache, const char *query_name, uint16_t query_type, resolver_cache_entry **result) {
	if (result != NULL) {
		*result = NULL;
	}
	char normalized[NS_MAXDNAME];
	if (cache == NULL || result == NULL || !resolver_cache_query_type_valid(query_type) || !resolver_name_normalize(query_name, normalized)) {
		return RESOLVER_CACHE_ACQUIRE_BAD_ARGUMENT;
	}
	uint64_t hash = resolver_cache_hash(normalized, query_type);
	resolver_cache_entry *entry = resolver_cache_entry_find(cache, normalized, query_type, hash);
	if (entry != NULL) {
		if (!resolver_cache_entry_retain(entry)) {
			return RESOLVER_CACHE_ACQUIRE_LIMIT;
		}
		*result = entry;
		return RESOLVER_CACHE_ACQUIRE_OK;
	}
	if (cache->entry_count == (size_t)RESOLVER_CACHE_ENTRY_LIMIT || cache->next_entry_id == 0 || sizeof(*entry) > (size_t)RESOLVER_CACHE_OWNED_BYTE_LIMIT
		|| cache->owned_bytes > (size_t)RESOLVER_CACHE_OWNED_BYTE_LIMIT - sizeof(*entry)) {
		return RESOLVER_CACHE_ACQUIRE_LIMIT;
	}
	entry = calloc(1, sizeof(*entry));
	if (entry == NULL) {
		return RESOLVER_CACHE_ACQUIRE_MEMORY;
	}
	entry->cache = cache;
	entry->hash = hash;
	entry->id = cache->next_entry_id;
	memcpy(entry->name, normalized, strlen(normalized) + 1);
	entry->query_type = query_type;
	entry->reference_count = 1;
	size_t bucket_index = (size_t)(hash % cache->bucket_count);
	entry->next = cache->buckets[bucket_index];
	cache->buckets[bucket_index] = entry;
	cache->entry_count++;
	cache->owned_bytes += sizeof(*entry);
	cache->next_entry_id = cache->next_entry_id == UINT64_MAX ? 0 : cache->next_entry_id + 1;
	*result = entry;
	return RESOLVER_CACHE_ACQUIRE_OK;
}

size_t resolver_cache_entry_count(const resolver_cache *cache) {
	return cache == NULL ? 0 : cache->entry_count;
}

uint64_t resolver_cache_entry_id(const resolver_cache_entry *entry) {
	return entry == NULL ? 0 : entry->id;
}

const char *resolver_cache_entry_name(const resolver_cache_entry *entry) {
	return entry == NULL ? NULL : entry->name;
}

resolver_cache_publish_status resolver_cache_entry_publish_address(resolver_cache_entry *entry, dns_address_lookup_status lookup_status, const struct timespec *completed_at,
	dns_address_result *result) {
	if (entry == NULL || result == NULL || completed_at == NULL) {
		return RESOLVER_CACHE_PUBLISH_BAD_ARGUMENT;
	}
	uint32_t ttl;
	resolver_cache_view_status view_status;
	if (!resolver_cache_address_result_validate(entry, lookup_status, result, &ttl, &view_status)) {
		return RESOLVER_CACHE_PUBLISH_INVALID;
	}
	size_t result_size;
	if (!resolver_cache_address_result_size(result, &result_size)) {
		return RESOLVER_CACHE_PUBLISH_LIMIT;
	}
	return resolver_cache_entry_payload_publish(entry, RESOLVER_CACHE_PAYLOAD_ADDRESS, view_status, completed_at, ttl, result_size, result);
}

resolver_cache_publish_status resolver_cache_entry_publish_srv(resolver_cache_entry *entry, dns_srv_lookup_status lookup_status, const struct timespec *completed_at,
	dns_srv_result *result) {
	if (entry == NULL || result == NULL || completed_at == NULL) {
		return RESOLVER_CACHE_PUBLISH_BAD_ARGUMENT;
	}
	uint32_t ttl;
	resolver_cache_view_status view_status;
	if (!resolver_cache_srv_result_validate(entry, lookup_status, result, &ttl, &view_status)) {
		return RESOLVER_CACHE_PUBLISH_INVALID;
	}
	size_t result_size;
	if (!resolver_cache_srv_result_size(result, &result_size)) {
		return RESOLVER_CACHE_PUBLISH_LIMIT;
	}
	return resolver_cache_entry_payload_publish(entry, RESOLVER_CACHE_PAYLOAD_SRV, view_status, completed_at, ttl, result_size, result);
}

uint16_t resolver_cache_entry_query_type(const resolver_cache_entry *entry) {
	return entry == NULL ? 0 : entry->query_type;
}

void resolver_cache_entry_release(resolver_cache_entry *entry) {
	if (entry == NULL || entry->reference_count == 0) {
		return;
	}
	entry->reference_count--;
	if (entry->reference_count != 0) {
		return;
	}
	resolver_cache *cache = entry->cache;
	size_t bucket_index = (size_t)(entry->hash % cache->bucket_count);
	resolver_cache_entry **link = &cache->buckets[bucket_index];
	while (*link != NULL && *link != entry) {
		link = &(*link)->next;
	}
	if (*link == entry) {
		*link = entry->next;
	}
	resolver_cache_entry_payload_clear(entry);
	if (cache->owned_bytes >= sizeof(*entry)) {
		cache->owned_bytes -= sizeof(*entry);
	} else {
		cache->owned_bytes = 0;
	}
	if (cache->entry_count > 0) {
		cache->entry_count--;
	}
	free(entry);
}

bool resolver_cache_entry_retain(resolver_cache_entry *entry) {
	if (entry == NULL || entry->reference_count == SIZE_MAX) {
		return false;
	}
	entry->reference_count++;
	return true;
}

bool resolver_cache_entry_view(resolver_cache_entry *entry, const struct timespec *now, resolver_cache_view *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (entry == NULL || result == NULL || !resolver_cache_time_valid(now)) {
		return false;
	}
	if (entry->payload != NULL && resolver_cache_time_compare(now, &entry->payload->expires_at) >= 0) {
		resolver_cache_entry_payload_clear(entry);
	}
	if (entry->payload == NULL) {
		result->status = RESOLVER_CACHE_VIEW_EMPTY;
		return true;
	}
	result->completed_at = entry->payload->completed_at;
	result->expires_at = entry->payload->expires_at;
	result->status = entry->payload->status;
	if (entry->payload->type == RESOLVER_CACHE_PAYLOAD_ADDRESS) {
		result->addresses = entry->payload->result.address.addresses;
		result->address_count = entry->payload->result.address.address_count;
	} else {
		result->srv_records = entry->payload->result.srv.records;
		result->srv_record_count = entry->payload->result.srv.record_count;
	}
	return true;
}

size_t resolver_cache_owned_bytes(const resolver_cache *cache) {
	return cache == NULL ? 0 : cache->owned_bytes;
}

bool resolver_cache_result_fits(uint16_t query_type, size_t cname_count, size_t record_count) {
	if (cname_count > DNS_CNAME_DEPTH_LIMIT || (query_type != ns_t_a && query_type != ns_t_aaaa && query_type != ns_t_srv)
		|| ((query_type == ns_t_a || query_type == ns_t_aaaa) && record_count > DNS_ADDRESS_RECORD_LIMIT) || (query_type == ns_t_srv && record_count > DNS_SRV_RECORD_LIMIT)) {
		return false;
	}
	size_t size = sizeof(resolver_cache_payload);
	size_t array_size;
	if (cname_count > 0
		&& (!resolver_size_multiply(DNS_CNAME_DEPTH_LIMIT, sizeof(dns_cname_record), &array_size) || !resolver_size_add(&size, array_size))) {
		return false;
	}
	size_t record_size = query_type == ns_t_srv ? sizeof(dns_srv_record) : sizeof(dns_address_record);
	return resolver_size_multiply(record_count, record_size, &array_size) && resolver_size_add(&size, array_size) && size <= (size_t)RESOLVER_CACHE_RESULT_BYTE_LIMIT;
}
