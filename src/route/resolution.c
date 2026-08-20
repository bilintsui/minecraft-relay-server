/*
 * route/resolution.c: Per-generation route DNS resolution coordination
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
#include "../network.h"
#include "../resolver/cache.h"
#include "../resolver/dns.h"
#include "../resolver/hosts.h"
#include "../resolver/supervisor.h"
#include "bindings.h"
#include "prewarmer.h"

/* section: headers (self) */
#include "resolution.h"

/* section: defines */
/* hashing */
#define ROUTE_RESOLUTION_HASH_OFFSET	UINT64_C(14695981039346656037)
#define ROUTE_RESOLUTION_HASH_PRIME	UINT64_C(1099511628211)

/* section: types */
typedef struct route_resolution_dependency route_resolution_dependency;
typedef struct route_resolution_destination route_resolution_destination;
typedef struct route_resolution_entry route_resolution_entry;
typedef struct route_resolution_target {
	uint64_t hash;
	struct route_resolution_target *hash_next;
	hosts_address_result hosts;
	route_resolution_entry *ipv4_entry;
	route_resolution_entry *ipv6_entry;
	char name[NS_MAXDNAME];
	net_addr numeric_address;
	route_resolution_target_source source;
	size_t use_count;
} route_resolution_target;
typedef struct {
	route_resolution_dependency *dependencies;
	size_t dependency_count;
	size_t immediate_positive_count;
	size_t pending_count;
	size_t positive_count;
	dns_srv_record *records;
	size_t record_count;
	route_resolution_target **targets;
	size_t target_count;
} route_resolution_target_set;
struct route_resolution {
	size_t bucket_count;
	route_resolution_entry **buckets;
	resolver_cache *cache;
	route_resolution_destination *destinations;
	size_t destination_count;
	route_resolution_entry *dynamic_queue_head;
	route_resolution_entry *dynamic_queue_tail;
	const hosts_table *hosts;
	route_prewarmer prewarmer;
	const route_bindings *bindings;
	route_resolution_target **target_buckets;
	size_t terminal_destination_count;
};
struct route_resolution_dependency {
	bool address_source;
	route_resolution_destination *destination;
	route_resolution_entry *entry;
	route_resolution_dependency *entry_next;
	route_resolution_dependency *entry_previous;
	bool pending;
	bool positive;
};
struct route_resolution_destination {
	bool expanded;
	bool first_terminal;
	route_resolution_dependency owner_dependencies[2];
	size_t owner_dependency_count;
	size_t pending_entry_count;
	size_t positive_source_count;
	route_resolution_destination_result result;
	bool srv;
	route_resolution_target_set targets;
};
struct route_resolution_entry {
	resolver_cache_entry *cache_entry;
	route_resolution_dependency *dependencies;
	route_resolution_entry *hash_next;
	bool owned;
	bool positive;
	bool queued;
	route_resolution_entry *queue_next;
	route_resolution_entry *queue_previous;
	bool terminal;
	size_t use_count;
};

/* section: functions (local) */
static void route_resolution_dependency_link(route_resolution_entry *entry, route_resolution_dependency *dependency) {
	dependency->entry = entry;
	dependency->entry_next = entry->dependencies;
	if (entry->dependencies != NULL) {
		entry->dependencies->entry_previous = dependency;
	}
	entry->dependencies = dependency;
	entry->use_count++;
	dependency->pending = !entry->terminal;
	dependency->positive = entry->terminal && entry->positive && dependency->address_source;
}

static void route_resolution_destination_update(route_resolution *resolution, route_resolution_destination *destination) {
	if (!destination->expanded || destination->pending_entry_count != 0) {
		return;
	}
	if (destination->result == ROUTE_RESOLUTION_DESTINATION_PENDING) {
		destination->result = destination->positive_source_count > 0 ? ROUTE_RESOLUTION_DESTINATION_AVAILABLE : ROUTE_RESOLUTION_DESTINATION_UNAVAILABLE;
	}
	if (!destination->first_terminal) {
		destination->first_terminal = true;
		resolution->terminal_destination_count++;
	}
}

static size_t route_resolution_entry_bucket(const route_resolution *resolution, const resolver_cache_entry *entry) {
	return (size_t)(resolver_cache_entry_id(entry) % (uint64_t)resolution->bucket_count);
}

static route_resolution_entry *route_resolution_entry_find(const route_resolution *resolution, const resolver_cache_entry *entry) {
	if (resolution == NULL || entry == NULL) {
		return NULL;
	}
	for (route_resolution_entry *candidate = resolution->buckets[route_resolution_entry_bucket(resolution, entry)]; candidate != NULL; candidate = candidate->hash_next) {
		if (candidate->cache_entry == entry) {
			return candidate;
		}
	}
	return NULL;
}

static void route_resolution_entry_queue_append(route_resolution *resolution, route_resolution_entry *entry) {
	entry->queue_previous = resolution->dynamic_queue_tail;
	if (resolution->dynamic_queue_tail == NULL) {
		resolution->dynamic_queue_head = entry;
	} else {
		resolution->dynamic_queue_tail->queue_next = entry;
	}
	resolution->dynamic_queue_tail = entry;
	entry->queued = true;
}

static route_resolution_entry *route_resolution_entry_create(route_resolution *resolution, resolver_cache_entry *cache_entry, bool owned) {
	route_resolution_entry *entry = calloc(1, sizeof(*entry));
	if (entry == NULL) {
		return NULL;
	}
	entry->cache_entry = cache_entry;
	entry->owned = owned;
	size_t bucket = route_resolution_entry_bucket(resolution, cache_entry);
	entry->hash_next = resolution->buckets[bucket];
	resolution->buckets[bucket] = entry;
	if (owned) {
		route_resolution_entry_queue_append(resolution, entry);
	}
	return entry;
}

static route_resolution_entry *route_resolution_dynamic_entry_acquire(route_resolution *resolution, const char *name, uint16_t query_type, bool *created) {
	resolver_cache_entry *cache_entry = NULL;
	resolver_cache_acquire_status status = resolver_cache_entry_acquire(resolution->cache, name, query_type, &cache_entry);
	if (status != RESOLVER_CACHE_ACQUIRE_OK) {
		return NULL;
	}
	route_resolution_entry *entry = route_resolution_entry_find(resolution, cache_entry);
	if (entry != NULL) {
		resolver_cache_entry_release(cache_entry);
		*created = false;
		return entry;
	}
	entry = route_resolution_entry_create(resolution, cache_entry, true);
	if (entry == NULL) {
		resolver_cache_entry_release(cache_entry);
		return NULL;
	}
	*created = true;
	return entry;
}

static void route_resolution_entry_queue_remove(route_resolution *resolution, route_resolution_entry *entry) {
	if (!entry->queued) {
		return;
	}
	if (entry->queue_previous == NULL) {
		resolution->dynamic_queue_head = entry->queue_next;
	} else {
		entry->queue_previous->queue_next = entry->queue_next;
	}
	if (entry->queue_next == NULL) {
		resolution->dynamic_queue_tail = entry->queue_previous;
	} else {
		entry->queue_next->queue_previous = entry->queue_previous;
	}
	entry->queue_next = NULL;
	entry->queue_previous = NULL;
	entry->queued = false;
}

static void route_resolution_entry_remove(route_resolution *resolution, route_resolution_entry *entry) {
	if (entry == NULL || entry->use_count != 0 || entry->dependencies != NULL) {
		return;
	}
	size_t bucket = route_resolution_entry_bucket(resolution, entry->cache_entry);
	route_resolution_entry **cursor = &resolution->buckets[bucket];
	while (*cursor != NULL && *cursor != entry) {
		cursor = &(*cursor)->hash_next;
	}
	if (*cursor == entry) {
		*cursor = entry->hash_next;
	}
	route_resolution_entry_queue_remove(resolution, entry);
	if (entry->owned) {
		resolver_cache_entry_release(entry->cache_entry);
	}
	free(entry);
}

static void route_resolution_dependency_unlink(route_resolution *resolution, route_resolution_dependency *dependency) {
	route_resolution_entry *entry = dependency->entry;
	if (entry == NULL) {
		return;
	}
	if (dependency->entry_previous == NULL) {
		entry->dependencies = dependency->entry_next;
	} else {
		dependency->entry_previous->entry_next = dependency->entry_next;
	}
	if (dependency->entry_next != NULL) {
		dependency->entry_next->entry_previous = dependency->entry_previous;
	}
	if (entry->use_count > 0) {
		entry->use_count--;
	}
	memset(dependency, 0, sizeof(*dependency));
	if (entry->owned && entry->use_count == 0) {
		route_resolution_entry_remove(resolution, entry);
	}
}

static uint64_t route_resolution_name_hash(const char *name) {
	uint64_t hash = ROUTE_RESOLUTION_HASH_OFFSET;
	for (const unsigned char *character = (const unsigned char *)name; *character != '\0'; character++) {
		hash ^= *character;
		hash *= ROUTE_RESOLUTION_HASH_PRIME;
	}
	return hash;
}

static route_prewarm_status route_resolution_schedule_status(resolver_supervisor_schedule_status status) {
	switch (status) {
		case RESOLVER_SUPERVISOR_SCHEDULE_STARTED:
		case RESOLVER_SUPERVISOR_SCHEDULE_COALESCED:
		case RESOLVER_SUPERVISOR_SCHEDULE_COMPLETE:
		case RESOLVER_SUPERVISOR_SCHEDULE_FRESH:
			return ROUTE_PREWARM_MORE;
		case RESOLVER_SUPERVISOR_SCHEDULE_LIMIT:
			return ROUTE_PREWARM_CAPACITY;
		case RESOLVER_SUPERVISOR_SCHEDULE_IO:
			return ROUTE_PREWARM_IO;
		case RESOLVER_SUPERVISOR_SCHEDULE_MEMORY:
			return ROUTE_PREWARM_MEMORY;
		case RESOLVER_SUPERVISOR_SCHEDULE_TIME:
			return ROUTE_PREWARM_TIME;
		case RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT:
		default:
			return ROUTE_PREWARM_BAD_ARGUMENT;
	}
}

static size_t route_resolution_target_bucket(const route_resolution *resolution, uint64_t hash) {
	return (size_t)(hash % (uint64_t)resolution->bucket_count);
}

static bool route_resolution_target_dns_prepare(route_resolution *resolution, route_resolution_target *target) {
	bool ipv4_created = false;
	target->ipv4_entry = route_resolution_dynamic_entry_acquire(resolution, target->name, ns_t_a, &ipv4_created);
	if (target->ipv4_entry == NULL) {
		return false;
	}
	bool ipv6_created = false;
	target->ipv6_entry = route_resolution_dynamic_entry_acquire(resolution, target->name, ns_t_aaaa, &ipv6_created);
	if (target->ipv6_entry == NULL) {
		if (ipv4_created) {
			route_resolution_entry_remove(resolution, target->ipv4_entry);
		}
		target->ipv4_entry = NULL;
		return false;
	}
	(void)ipv6_created;
	target->ipv4_entry->use_count++;
	target->ipv6_entry->use_count++;
	target->source = ROUTE_RESOLUTION_TARGET_DNS;
	return true;
}

static bool route_resolution_target_name_equal(const route_resolution_target *target, const char *name) {
	return strcmp(target->name, name) == 0;
}

static route_resolution_target *route_resolution_target_find(const route_resolution *resolution, const char *name, uint64_t hash) {
	for (route_resolution_target *target = resolution->target_buckets[route_resolution_target_bucket(resolution, hash)]; target != NULL; target = target->hash_next) {
		if (target->hash == hash && route_resolution_target_name_equal(target, name)) {
			return target;
		}
	}
	return NULL;
}

static bool route_resolution_target_prepare(route_resolution *resolution, route_resolution_target *target) {
	target->numeric_address = net_addr_parse(target->name);
	if (target->numeric_address.family != 0) {
		target->source = ROUTE_RESOLUTION_TARGET_NUMERIC;
		return true;
	}
	memset(&target->numeric_address, 0, sizeof(target->numeric_address));
	hosts_lookup_status hosts_status = hosts_table_lookup(resolution->hosts, target->name, &target->hosts);
	if (hosts_status == HOSTS_LOOKUP_OK) {
		target->source = ROUTE_RESOLUTION_TARGET_HOSTS;
		return true;
	}
	hosts_address_result_destroy(&target->hosts);
	if (hosts_status != HOSTS_LOOKUP_NOT_FOUND) {
		return false;
	}
	return route_resolution_target_dns_prepare(resolution, target);
}

static route_resolution_target *route_resolution_target_create(route_resolution *resolution, const char *name, bool *created) {
	uint64_t hash = route_resolution_name_hash(name);
	route_resolution_target *target = route_resolution_target_find(resolution, name, hash);
	if (target != NULL) {
		*created = false;
		return target;
	}
	target = calloc(1, sizeof(*target));
	if (target == NULL) {
		return NULL;
	}
	if (strlen(name) >= sizeof(target->name)) {
		free(target);
		return NULL;
	}
	strcpy(target->name, name);
	target->hash = hash;
	if (!route_resolution_target_prepare(resolution, target)) {
		hosts_address_result_destroy(&target->hosts);
		free(target);
		return NULL;
	}
	size_t bucket = route_resolution_target_bucket(resolution, target->hash);
	target->hash_next = resolution->target_buckets[bucket];
	resolution->target_buckets[bucket] = target;
	*created = true;
	return target;
}

static void route_resolution_target_remove(route_resolution *resolution, route_resolution_target *target) {
	if (target == NULL || target->use_count != 0) {
		return;
	}
	size_t bucket = route_resolution_target_bucket(resolution, target->hash);
	route_resolution_target **cursor = &resolution->target_buckets[bucket];
	while (*cursor != NULL && *cursor != target) {
		cursor = &(*cursor)->hash_next;
	}
	if (*cursor == target) {
		*cursor = target->hash_next;
	}
	if (target->ipv4_entry != NULL) {
		if (target->ipv4_entry->use_count > 0) {
			target->ipv4_entry->use_count--;
		}
		if (target->ipv4_entry->owned) {
			route_resolution_entry_remove(resolution, target->ipv4_entry);
		}
	}
	if (target->ipv6_entry != NULL) {
		if (target->ipv6_entry->use_count > 0) {
			target->ipv6_entry->use_count--;
		}
		if (target->ipv6_entry->owned) {
			route_resolution_entry_remove(resolution, target->ipv6_entry);
		}
	}
	hosts_address_result_destroy(&target->hosts);
	free(target);
}

static void route_resolution_target_set_destroy_data(route_resolution_target_set *targets) {
	if (targets == NULL) {
		return;
	}
	free(targets->dependencies);
	free(targets->records);
	free(targets->targets);
	memset(targets, 0, sizeof(*targets));
}

static bool route_resolution_target_set_name_add(route_resolution *resolution, route_resolution_target_set *targets, const char *name, route_resolution_target **result,
	bool *created) {
	route_resolution_target *target = route_resolution_target_create(resolution, name, created);
	if (target == NULL) {
		return false;
	}
	for (size_t target_index = 0; target_index < targets->target_count; target_index++) {
		if (targets->targets[target_index] == target) {
			*result = NULL;
			return true;
		}
	}
	targets->targets[targets->target_count++] = target;
	if (target->source == ROUTE_RESOLUTION_TARGET_DNS) {
		route_resolution_dependency *ipv4_dependency = &targets->dependencies[targets->dependency_count++];
		ipv4_dependency->entry = target->ipv4_entry;
		route_resolution_dependency *ipv6_dependency = &targets->dependencies[targets->dependency_count++];
		ipv6_dependency->entry = target->ipv6_entry;
	} else {
		targets->immediate_positive_count++;
	}
	*result = target;
	return true;
}

static bool route_resolution_target_set_build(route_resolution *resolution, const dns_srv_record *records, size_t record_count, bool retain_records,
	route_resolution_target_set *result, route_resolution_target ***new_targets_result, size_t *new_target_count_result,
	route_resolution_destination_result *failure_result) {
	bool root_target = false;
	bool ordinary_target = false;
	for (size_t record_index = 0; record_index < record_count; record_index++) {
		root_target = root_target || strcmp(records[record_index].target, ".") == 0;
		ordinary_target = ordinary_target || strcmp(records[record_index].target, ".") != 0;
	}
	if (root_target) {
		*failure_result = ordinary_target ? ROUTE_RESOLUTION_DESTINATION_CONTRADICTORY : ROUTE_RESOLUTION_DESTINATION_SERVICE_UNAVAILABLE;
		return false;
	}
	if (record_count == 0 || record_count > DNS_SRV_RECORD_LIMIT || record_count > SIZE_MAX / sizeof(*result->targets)
		|| record_count > SIZE_MAX / 2U || record_count * 2U > SIZE_MAX / sizeof(*result->dependencies)
		|| record_count > SIZE_MAX / sizeof(*result->records) || record_count > SIZE_MAX / sizeof(route_resolution_target *)) {
		*failure_result = ROUTE_RESOLUTION_DESTINATION_UNAVAILABLE;
		return false;
	}
	result->targets = calloc(record_count, sizeof(*result->targets));
	result->dependencies = calloc(record_count * 2U, sizeof(*result->dependencies));
	route_resolution_target **new_targets = calloc(record_count, sizeof(*new_targets));
	if (retain_records) {
		result->records = calloc(record_count, sizeof(*result->records));
	}
	if (result->targets == NULL || result->dependencies == NULL || new_targets == NULL || (retain_records && result->records == NULL)) {
		free(new_targets);
		route_resolution_target_set_destroy_data(result);
		*failure_result = ROUTE_RESOLUTION_DESTINATION_UNAVAILABLE;
		return false;
	}
	if (retain_records) {
		memcpy(result->records, records, record_count * sizeof(*result->records));
		result->record_count = record_count;
	}
	size_t new_target_count = 0;
	for (size_t record_index = 0; record_index < record_count; record_index++) {
		route_resolution_target *target = NULL;
		bool created = false;
		if (!route_resolution_target_set_name_add(resolution, result, records[record_index].target, &target, &created)) {
			goto fail;
		}
		if (created) {
			new_targets[new_target_count++] = target;
		}
	}
	*new_targets_result = new_targets;
	*new_target_count_result = new_target_count;
	return true;

fail:
	for (size_t target_index = 0; target_index < new_target_count; target_index++) {
		route_resolution_target_remove(resolution, new_targets[target_index]);
	}
	free(new_targets);
	route_resolution_target_set_destroy_data(result);
	*failure_result = ROUTE_RESOLUTION_DESTINATION_UNAVAILABLE;
	return false;
}

static void route_resolution_target_set_unlink(route_resolution *resolution, route_resolution_target_set *targets) {
	if (targets == NULL) {
		return;
	}
	for (size_t dependency_index = 0; dependency_index < targets->dependency_count; dependency_index++) {
		route_resolution_dependency_unlink(resolution, &targets->dependencies[dependency_index]);
	}
	for (size_t target_index = 0; target_index < targets->target_count; target_index++) {
		route_resolution_target *target = targets->targets[target_index];
		if (target->use_count > 0) {
			target->use_count--;
		}
		route_resolution_target_remove(resolution, target);
	}
	route_resolution_target_set_destroy_data(targets);
}

static void route_resolution_destination_fail(route_resolution *resolution, route_resolution_destination *destination, route_resolution_destination_result result) {
	route_resolution_target_set_unlink(resolution, &destination->targets);
	destination->expanded = true;
	destination->pending_entry_count = 0;
	destination->positive_source_count = 0;
	destination->result = result;
	route_resolution_destination_update(resolution, destination);
}

static void route_resolution_destination_targets_replace(route_resolution *resolution, route_resolution_destination *destination, route_resolution_target_set *candidate) {
	/* Link the candidate first so shared cache entries cannot reach zero references during a generation-local SRV target-set replacement. */
	for (size_t target_index = 0; target_index < candidate->target_count; target_index++) {
		candidate->targets[target_index]->use_count++;
	}
	for (size_t dependency_index = 0; dependency_index < candidate->dependency_count; dependency_index++) {
		route_resolution_dependency *dependency = &candidate->dependencies[dependency_index];
		dependency->destination = destination;
		dependency->address_source = true;
		route_resolution_dependency_link(dependency->entry, dependency);
		candidate->pending_count += dependency->pending ? 1U : 0U;
		candidate->positive_count += dependency->positive ? 1U : 0U;
	}
	route_resolution_target_set_unlink(resolution, &destination->targets);
	destination->targets = *candidate;
	memset(candidate, 0, sizeof(*candidate));
	destination->expanded = true;
	destination->pending_entry_count = (destination->owner_dependencies[0].pending ? 1U : 0U) + destination->targets.pending_count;
	destination->positive_source_count = destination->targets.immediate_positive_count + destination->targets.positive_count;
	destination->result = ROUTE_RESOLUTION_DESTINATION_PENDING;
	route_resolution_destination_update(resolution, destination);
}

static void route_resolution_destination_expand(route_resolution *resolution, route_resolution_destination *destination, const dns_srv_record *records, size_t record_count,
	bool retain_records) {
	route_resolution_target_set candidate;
	memset(&candidate, 0, sizeof(candidate));
	route_resolution_target **new_targets = NULL;
	size_t new_target_count = 0;
	route_resolution_destination_result failure_result = ROUTE_RESOLUTION_DESTINATION_UNAVAILABLE;
	if (!route_resolution_target_set_build(resolution, records, record_count, retain_records, &candidate, &new_targets, &new_target_count, &failure_result)) {
		route_resolution_destination_fail(resolution, destination, failure_result);
		return;
	}
	route_resolution_destination_targets_replace(resolution, destination, &candidate);
	free(new_targets);
}

static void route_resolution_entry_terminal_observe(route_resolution *resolution, route_resolution_entry *entry, bool positive, const dns_srv_record *srv_records,
	size_t srv_record_count, bool retain_srv_records) {
	route_resolution_entry_queue_remove(resolution, entry);
	/* The first terminal observation satisfies every existing dependency once. Later SRV observations may still replace the current target set. */
	bool first_terminal = !entry->terminal;
	if (first_terminal) {
		entry->terminal = true;
		entry->positive = positive;
		for (route_resolution_dependency *dependency = entry->dependencies; dependency != NULL; dependency = dependency->entry_next) {
			if (dependency->pending) {
				dependency->pending = false;
				if (dependency->destination->pending_entry_count > 0) {
					dependency->destination->pending_entry_count--;
				}
			}
			if (positive && dependency->address_source && !dependency->positive) {
				dependency->positive = true;
				dependency->destination->positive_source_count++;
			}
		}
	}
	if (resolver_cache_entry_query_type(entry->cache_entry) == ns_t_srv) {
		for (route_resolution_dependency *dependency = entry->dependencies; dependency != NULL;) {
			route_resolution_dependency *next = dependency->entry_next;
			if (dependency->destination->srv && !dependency->address_source) {
				if (positive && srv_records != NULL) {
					route_resolution_destination_expand(resolution, dependency->destination, srv_records, srv_record_count, retain_srv_records);
				} else {
					route_resolution_destination_fail(resolution, dependency->destination, ROUTE_RESOLUTION_DESTINATION_UNAVAILABLE);
				}
			}
			dependency = next;
		}
	}
	if (first_terminal) {
		for (route_resolution_dependency *dependency = entry->dependencies; dependency != NULL; dependency = dependency->entry_next) {
			route_resolution_destination_update(resolution, dependency->destination);
		}
	}
}

static bool route_resolution_entry_fresh_observe(route_resolution *resolution, route_resolution_entry *entry, const struct timespec *now) {
	resolver_cache_view view;
	if (!resolver_cache_entry_view(entry->cache_entry, now, &view)) {
		return false;
	}
	if (view.status == RESOLVER_CACHE_VIEW_EMPTY) {
		return true;
	}
	bool positive = view.status == RESOLVER_CACHE_VIEW_FRESH_POSITIVE;
	const dns_srv_record *srv_records = resolver_cache_entry_query_type(entry->cache_entry) == ns_t_srv && positive ? view.srv_records : NULL;
	size_t srv_record_count = srv_records == NULL ? 0 : view.srv_record_count;
	route_resolution_entry_terminal_observe(resolution, entry, positive, srv_records, srv_record_count, true);
	return true;
}

static bool route_resolution_time_valid(const struct timespec *timestamp) {
	return timestamp != NULL && timestamp->tv_sec >= 0 && timestamp->tv_nsec >= 0 && timestamp->tv_nsec < 1000000000L;
}

/* section: functions (exported) */
route_resolution_build_status route_resolution_build(const route_bindings *bindings, const hosts_table *hosts, resolver_cache *cache, const struct timespec *now,
	route_resolution **result) {
	if (bindings == NULL || hosts == NULL || cache == NULL || !route_resolution_time_valid(now) || result == NULL || *result != NULL || RESOLVER_CACHE_ENTRY_LIMIT == 0) {
		return ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT;
	}
	size_t destination_count = route_bindings_destination_count(bindings);
	if (destination_count > 0 && destination_count > SIZE_MAX / sizeof(route_resolution_destination)) {
		return ROUTE_RESOLUTION_BUILD_MEMORY;
	}
	route_resolution *resolution = calloc(1, sizeof(*resolution));
	if (resolution == NULL) {
		return ROUTE_RESOLUTION_BUILD_MEMORY;
	}
	resolution->bindings = bindings;
	resolution->bucket_count = (size_t)RESOLVER_CACHE_ENTRY_LIMIT;
	resolution->cache = cache;
	resolution->destination_count = destination_count;
	resolution->hosts = hosts;
	resolution->buckets = calloc(resolution->bucket_count, sizeof(*resolution->buckets));
	resolution->destinations = calloc(destination_count == 0 ? 1U : destination_count, sizeof(*resolution->destinations));
	resolution->target_buckets = calloc(resolution->bucket_count, sizeof(*resolution->target_buckets));
	if (resolution->buckets == NULL || resolution->destinations == NULL || resolution->target_buckets == NULL) {
		route_resolution_destroy(resolution);
		return ROUTE_RESOLUTION_BUILD_MEMORY;
	}
	for (size_t entry_index = 0; entry_index < route_bindings_entry_count(bindings); entry_index++) {
		resolver_cache_entry *cache_entry = NULL;
		if (!route_bindings_entry_get(bindings, entry_index, &cache_entry) || route_resolution_entry_find(resolution, cache_entry) != NULL
			|| route_resolution_entry_create(resolution, cache_entry, false) == NULL) {
			route_resolution_destroy(resolution);
			return ROUTE_RESOLUTION_BUILD_MEMORY;
		}
	}
	for (size_t destination_index = 0; destination_index < destination_count; destination_index++) {
		route_binding_view binding;
		if (!route_bindings_destination_get(bindings, destination_index, &binding)) {
			route_resolution_destroy(resolution);
			return ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT;
		}
		route_resolution_destination *destination = &resolution->destinations[destination_index];
		if (binding.source == ROUTE_BINDING_SOURCE_NUMERIC || binding.source == ROUTE_BINDING_SOURCE_HOSTS) {
			destination->expanded = true;
			destination->positive_source_count = 1;
			destination->result = ROUTE_RESOLUTION_DESTINATION_PENDING;
			route_resolution_destination_update(resolution, destination);
			continue;
		}
		if (binding.source == ROUTE_BINDING_SOURCE_UNAVAILABLE) {
			destination->expanded = true;
			destination->result = ROUTE_RESOLUTION_DESTINATION_UNAVAILABLE;
			route_resolution_destination_update(resolution, destination);
			continue;
		}
		if (binding.source == ROUTE_BINDING_SOURCE_DNS_ADDRESS) {
			resolver_cache_entry *entries[] = { binding.ipv4_entry, binding.ipv6_entry };
			destination->expanded = true;
			destination->owner_dependency_count = 2;
			destination->pending_entry_count = 2;
			for (size_t dependency_index = 0; dependency_index < 2; dependency_index++) {
				route_resolution_entry *entry = route_resolution_entry_find(resolution, entries[dependency_index]);
				if (entry == NULL) {
					route_resolution_destroy(resolution);
					return ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT;
				}
				route_resolution_dependency *dependency = &destination->owner_dependencies[dependency_index];
				dependency->address_source = true;
				dependency->destination = destination;
				route_resolution_dependency_link(entry, dependency);
			}
			continue;
		}
		if (binding.source != ROUTE_BINDING_SOURCE_DNS_SRV) {
			route_resolution_destroy(resolution);
			return ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT;
		}
		route_resolution_entry *entry = route_resolution_entry_find(resolution, binding.srv_entry);
		if (entry == NULL) {
			route_resolution_destroy(resolution);
			return ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT;
		}
		destination->owner_dependency_count = 1;
		destination->pending_entry_count = 1;
		destination->srv = true;
		destination->owner_dependencies[0].destination = destination;
		route_resolution_dependency_link(entry, &destination->owner_dependencies[0]);
	}
	route_prewarmer_reset(&resolution->prewarmer, bindings);
	for (size_t entry_index = 0; entry_index < route_bindings_entry_count(bindings); entry_index++) {
		resolver_cache_entry *cache_entry = NULL;
		if (!route_bindings_entry_get(bindings, entry_index, &cache_entry)) {
			route_resolution_destroy(resolution);
			return ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT;
		}
		route_resolution_entry *entry = route_resolution_entry_find(resolution, cache_entry);
		if (entry == NULL || !route_resolution_entry_fresh_observe(resolution, entry, now)) {
			route_resolution_destroy(resolution);
			return ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT;
		}
	}
	*result = resolution;
	return ROUTE_RESOLUTION_BUILD_OK;
}

route_resolution_completion_status route_resolution_completion_observe(route_resolution *resolution, const resolver_supervisor_completion *completion, const struct timespec *now) {
	if (resolution == NULL || completion == NULL || completion->entry == NULL || !route_resolution_time_valid(now)) {
		return ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT;
	}
	route_resolution_entry *entry = route_resolution_entry_find(resolution, completion->entry);
	if (entry == NULL) {
		return ROUTE_RESOLUTION_COMPLETION_IGNORED;
	}
	if (completion->response.query_type != resolver_cache_entry_query_type(entry->cache_entry) || completion->response.status < RESOLVER_IPC_LOOKUP_OK
		|| completion->response.status > RESOLVER_IPC_LOOKUP_TRUNCATED || completion->response.status == RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR) {
		return ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT;
	}
	switch (completion->publication) {
		case RESOLVER_CACHE_PUBLISH_STORED:
		case RESOLVER_CACHE_PUBLISH_TRANSIENT:
		case RESOLVER_CACHE_PUBLISH_BAD_ARGUMENT:
		case RESOLVER_CACHE_PUBLISH_INVALID:
		case RESOLVER_CACHE_PUBLISH_LIMIT:
		case RESOLVER_CACHE_PUBLISH_MEMORY:
		case RESOLVER_CACHE_PUBLISH_TIME:
			break;
		default:
			return ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT;
	}
	if (completion->publication == RESOLVER_CACHE_PUBLISH_STORED) {
		resolver_cache_view view;
		if (!resolver_cache_entry_view(entry->cache_entry, now, &view)) {
			return ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT;
		}
		if (view.status != RESOLVER_CACHE_VIEW_EMPTY) {
			bool positive = view.status == RESOLVER_CACHE_VIEW_FRESH_POSITIVE;
			const dns_srv_record *srv_records = resolver_cache_entry_query_type(entry->cache_entry) == ns_t_srv && positive ? view.srv_records : NULL;
			route_resolution_entry_terminal_observe(resolution, entry, positive, srv_records, srv_records == NULL ? 0 : view.srv_record_count, true);
			return ROUTE_RESOLUTION_COMPLETION_OK;
		}
	}
	bool positive = completion->publication == RESOLVER_CACHE_PUBLISH_TRANSIENT && completion->response.status == RESOLVER_IPC_LOOKUP_OK;
	const dns_srv_record *srv_records = NULL;
	size_t srv_record_count = 0;
	if (positive && resolver_cache_entry_query_type(entry->cache_entry) == ns_t_srv) {
		srv_records = completion->response.payload.srv.records;
		srv_record_count = completion->response.payload.srv.record_count;
	}
	route_resolution_entry_terminal_observe(resolution, entry, positive, srv_records, srv_record_count, false);
	return ROUTE_RESOLUTION_COMPLETION_OK;
}

void route_resolution_destroy(route_resolution *resolution) {
	if (resolution == NULL) {
		return;
	}
	for (size_t destination_index = 0; destination_index < resolution->destination_count; destination_index++) {
		route_resolution_destination *destination = &resolution->destinations[destination_index];
		route_resolution_target_set_unlink(resolution, &destination->targets);
		for (size_t dependency_index = 0; dependency_index < destination->owner_dependency_count; dependency_index++) {
			route_resolution_dependency_unlink(resolution, &destination->owner_dependencies[dependency_index]);
		}
	}
	if (resolution->buckets != NULL) {
		for (size_t bucket = 0; bucket < resolution->bucket_count; bucket++) {
			route_resolution_entry *entry = resolution->buckets[bucket];
			while (entry != NULL) {
				route_resolution_entry *next = entry->hash_next;
				if (entry->owned) {
					resolver_cache_entry_release(entry->cache_entry);
				}
				free(entry);
				entry = next;
			}
		}
	}
	free(resolution->buckets);
	free(resolution->destinations);
	free(resolution->target_buckets);
	free(resolution);
}

size_t route_resolution_destination_count(const route_resolution *resolution) {
	return resolution == NULL ? 0 : resolution->destination_count;
}

bool route_resolution_destination_get(const route_resolution *resolution, size_t destination_index, route_resolution_destination_view *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (resolution == NULL || destination_index >= resolution->destination_count || result == NULL) {
		return false;
	}
	const route_resolution_destination *destination = &resolution->destinations[destination_index];
	result->first_terminal = destination->first_terminal;
	result->pending_entry_count = destination->pending_entry_count;
	result->result = destination->result;
	result->srv_records = destination->targets.records;
	result->srv_record_count = destination->targets.record_count;
	result->target_count = destination->targets.target_count;
	return true;
}

bool route_resolution_destination_target_get(const route_resolution *resolution, size_t destination_index, size_t target_index, route_resolution_target_view *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (resolution == NULL || destination_index >= resolution->destination_count || result == NULL
		|| target_index >= resolution->destinations[destination_index].targets.target_count) {
		return false;
	}
	const route_resolution_target *target = resolution->destinations[destination_index].targets.targets[target_index];
	result->addresses = target->hosts.addresses;
	result->address_count = target->hosts.address_count;
	result->ipv4_entry = target->ipv4_entry == NULL ? NULL : target->ipv4_entry->cache_entry;
	result->ipv6_entry = target->ipv6_entry == NULL ? NULL : target->ipv6_entry->cache_entry;
	result->name = target->name;
	result->numeric_address = target->numeric_address;
	result->source = target->source;
	return true;
}

route_prewarm_status route_resolution_schedule(route_resolution *resolution, resolver_supervisor *supervisor, const struct timespec *now, size_t batch_limit) {
	if (resolution == NULL || supervisor == NULL || !route_resolution_time_valid(now) || batch_limit == 0) {
		return ROUTE_PREWARM_BAD_ARGUMENT;
	}
	size_t calls = 0;
	while (calls < batch_limit && !route_prewarmer_complete(&resolution->prewarmer)) {
		resolver_cache_entry *cache_entry = NULL;
		if (!route_bindings_entry_get(resolution->bindings, resolution->prewarmer.next_entry_index, &cache_entry)) {
			return ROUTE_PREWARM_BAD_ARGUMENT;
		}
		route_resolution_entry *entry = route_resolution_entry_find(resolution, cache_entry);
		if (entry == NULL) {
			return ROUTE_PREWARM_BAD_ARGUMENT;
		}
		if (entry->terminal) {
			resolution->prewarmer.next_entry_index++;
			continue;
		}
		route_prewarm_step step = { 0 };
		route_prewarm_status status = route_prewarmer_step(&resolution->prewarmer, supervisor, now, &step);
		calls++;
		if (status != ROUTE_PREWARM_COMPLETE && status != ROUTE_PREWARM_MORE) {
			return status;
		}
		if (step.schedule_status == RESOLVER_SUPERVISOR_SCHEDULE_FRESH) {
			if (!route_resolution_entry_fresh_observe(resolution, entry, now)) {
				return ROUTE_PREWARM_BAD_ARGUMENT;
			}
		}
	}
	while (calls < batch_limit && resolution->dynamic_queue_head != NULL) {
		route_resolution_entry *entry = resolution->dynamic_queue_head;
		resolver_supervisor_schedule_status schedule_status = resolver_supervisor_entry_schedule(supervisor, entry->cache_entry, now);
		route_prewarm_status mapped = route_resolution_schedule_status(schedule_status);
		calls++;
		if (mapped != ROUTE_PREWARM_MORE) {
			return mapped;
		}
		route_resolution_entry_queue_remove(resolution, entry);
		if (schedule_status == RESOLVER_SUPERVISOR_SCHEDULE_FRESH && !route_resolution_entry_fresh_observe(resolution, entry, now)) {
			return ROUTE_PREWARM_BAD_ARGUMENT;
		}
	}
	return route_resolution_scheduling_complete(resolution) ? ROUTE_PREWARM_COMPLETE : ROUTE_PREWARM_MORE;
}

bool route_resolution_scheduling_complete(const route_resolution *resolution) {
	return resolution != NULL && route_prewarmer_complete(&resolution->prewarmer) && resolution->dynamic_queue_head == NULL;
}

bool route_resolution_warmup_complete(const route_resolution *resolution) {
	return resolution != NULL && resolution->terminal_destination_count == resolution->destination_count;
}
