/*
 * resolver/cache.h: Header file of resolver/cache.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_RESOLVER_CACHE_H_INCLUDED_

#define _MRS_RESOLVER_CACHE_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* section: headers (project) */
#include "../metrics.h"
#include "dns.h"

/* section: defines */
/* capacity */
#ifndef RESOLVER_CACHE_ENTRY_LIMIT
#define RESOLVER_CACHE_ENTRY_LIMIT	16384
#endif
#ifndef RESOLVER_CACHE_OWNED_BYTE_LIMIT
#define RESOLVER_CACHE_OWNED_BYTE_LIMIT	(64U * 1024U * 1024U)
#endif
#ifndef RESOLVER_CACHE_RESULT_BYTE_LIMIT
#define RESOLVER_CACHE_RESULT_BYTE_LIMIT	(256U * 1024U)
#endif

/* section: types */
typedef struct resolver_cache resolver_cache;
typedef enum {
	RESOLVER_CACHE_ACQUIRE_OK,
	RESOLVER_CACHE_ACQUIRE_BAD_ARGUMENT,
	RESOLVER_CACHE_ACQUIRE_LIMIT,
	RESOLVER_CACHE_ACQUIRE_MEMORY
} resolver_cache_acquire_status;
typedef struct resolver_cache_entry resolver_cache_entry;
typedef struct {
	uint64_t acquire_created;
	uint64_t acquire_reused;
	uint64_t acquire_bad_argument;
	uint64_t acquire_reference_limit;
	uint64_t acquire_entry_limit;
	uint64_t acquire_id_limit;
	uint64_t acquire_owned_byte_limit;
	uint64_t acquire_memory;
	uint64_t publish_stored;
	uint64_t publish_transient;
	uint64_t publish_bad_argument;
	uint64_t publish_invalid;
	uint64_t publish_limit;
	uint64_t publish_memory;
	uint64_t publish_time;
	uint64_t publish_limit_result_bytes;
	uint64_t publish_limit_owned_bytes;
	uint64_t value_positive;
	uint64_t value_nxdomain;
	uint64_t value_nodata;
	uint64_t expiry_positive;
	uint64_t expiry_nxdomain;
	uint64_t expiry_nodata;
	uint64_t resident_positive;
	uint64_t resident_nxdomain;
	uint64_t resident_nodata;
} resolver_cache_metrics_query;
typedef struct {
	uint64_t entries_current;
	uint64_t entries_high_water;
	uint64_t owned_bytes_current;
	uint64_t owned_bytes_high_water;
	resolver_cache_metrics_query query[METRICS_QUERY_TYPE_COUNT];
	uint64_t saturation_total;
	metrics_histogram_snapshot ttl[METRICS_RESOLVER_QUERY_TYPE_COUNT][METRICS_PAYLOAD_KIND_COUNT];
} resolver_cache_metrics_snapshot;
typedef enum {
	RESOLVER_CACHE_PUBLISH_STORED,
	RESOLVER_CACHE_PUBLISH_TRANSIENT,
	RESOLVER_CACHE_PUBLISH_BAD_ARGUMENT,
	RESOLVER_CACHE_PUBLISH_INVALID,
	RESOLVER_CACHE_PUBLISH_LIMIT,
	RESOLVER_CACHE_PUBLISH_MEMORY,
	RESOLVER_CACHE_PUBLISH_TIME
} resolver_cache_publish_status;
typedef enum {
	RESOLVER_CACHE_RESULT_FIT_OK,
	RESOLVER_CACHE_RESULT_FIT_SHAPE,
	RESOLVER_CACHE_RESULT_FIT_BYTES
} resolver_cache_result_fit;
typedef enum {
	RESOLVER_CACHE_VIEW_EMPTY,
	RESOLVER_CACHE_VIEW_FRESH_POSITIVE,
	RESOLVER_CACHE_VIEW_FRESH_NXDOMAIN,
	RESOLVER_CACHE_VIEW_FRESH_NODATA
} resolver_cache_view_status;
typedef struct {
	const dns_address_record *addresses;
	size_t address_count;
	struct timespec completed_at;
	struct timespec expires_at;
	const dns_srv_record *srv_records;
	size_t srv_record_count;
	resolver_cache_view_status status;
} resolver_cache_view;

/* section: functions (exported) */
resolver_cache *resolver_cache_create(void);
void resolver_cache_destroy(resolver_cache *cache);
/* Acquiring or retaining an entry creates one caller-owned reference. Zero references remove the entry immediately. */
resolver_cache_acquire_status resolver_cache_entry_acquire(resolver_cache *cache, const char *query_name, uint16_t query_type, resolver_cache_entry **result);
size_t resolver_cache_entry_count(const resolver_cache *cache);
uint64_t resolver_cache_entry_id(const resolver_cache_entry *entry);
const char *resolver_cache_entry_name(const resolver_cache_entry *entry);
/* A stored publication moves result ownership. A transient publication clears the old payload but leaves result ownership with the caller. Other failures change neither. */
resolver_cache_publish_status resolver_cache_entry_publish_address(resolver_cache_entry *entry, dns_address_lookup_status lookup_status, const struct timespec *completed_at, dns_address_result *result);
resolver_cache_publish_status resolver_cache_entry_publish_srv(resolver_cache_entry *entry, dns_srv_lookup_status lookup_status, const struct timespec *completed_at, dns_srv_result *result);
uint16_t resolver_cache_entry_query_type(const resolver_cache_entry *entry);
void resolver_cache_entry_release(resolver_cache_entry *entry);
bool resolver_cache_entry_retain(resolver_cache_entry *entry);
/* Views and their record pointers are borrowed until the next publication, expiry check, or final entry release. */
bool resolver_cache_entry_view(resolver_cache_entry *entry, const struct timespec *now, resolver_cache_view *result);
bool resolver_cache_metrics_get(const resolver_cache *cache, resolver_cache_metrics_snapshot *result);
size_t resolver_cache_owned_bytes(const resolver_cache *cache);
resolver_cache_result_fit resolver_cache_result_classify(uint16_t query_type, size_t cname_count, size_t record_count);

#endif
