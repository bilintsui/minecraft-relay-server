/*
 * route_bindings.c: Per-generation proxy destination resolver bindings
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

/* section: headers (project) */
#include "hosts.h"
#include "resolver_cache.h"
#include "route_table.h"

/* section: headers (self) */
#include "route_bindings.h"

/* section: types */
typedef struct {
	resolver_cache_entry *ipv4_entry;
	resolver_cache_entry *ipv6_entry;
	hosts_address_result hosts;
	net_addr numeric_address;
	in_port_t port;
	resolver_cache_entry *srv_entry;
	route_binding_source source;
} route_binding;
struct route_bindings {
	route_binding *destinations;
	size_t destination_count;
	resolver_cache_entry **entries;
	size_t entry_count;
};
typedef enum {
	ROUTE_BINDINGS_ENTRY_OK,
	ROUTE_BINDINGS_ENTRY_UNAVAILABLE,
	ROUTE_BINDINGS_ENTRY_LIMIT,
	ROUTE_BINDINGS_ENTRY_MEMORY
} route_bindings_entry_status;

/* section: functions (local) */
static route_bindings_entry_status route_bindings_cache_entry_acquire(route_bindings *bindings, resolver_cache *cache, const char *query_name, uint16_t query_type,
	resolver_cache_entry **result) {
	resolver_cache_entry *entry = NULL;
	resolver_cache_acquire_status status = resolver_cache_entry_acquire(cache, query_name, query_type, &entry);
	switch (status) {
		case RESOLVER_CACHE_ACQUIRE_OK:
			break;
		case RESOLVER_CACHE_ACQUIRE_BAD_ARGUMENT:
			return ROUTE_BINDINGS_ENTRY_UNAVAILABLE;
		case RESOLVER_CACHE_ACQUIRE_LIMIT:
			return ROUTE_BINDINGS_ENTRY_LIMIT;
		case RESOLVER_CACHE_ACQUIRE_MEMORY:
		default:
			return ROUTE_BINDINGS_ENTRY_MEMORY;
	}
	for (size_t entry_index = 0; entry_index < bindings->entry_count; entry_index++) {
		if (bindings->entries[entry_index] == entry) {
			resolver_cache_entry_release(entry);
			*result = bindings->entries[entry_index];
			return ROUTE_BINDINGS_ENTRY_OK;
		}
	}
	bindings->entries[bindings->entry_count++] = entry;
	*result = entry;
	return ROUTE_BINDINGS_ENTRY_OK;
}

static void route_bindings_cache_entries_rollback(route_bindings *bindings, size_t retained_count) {
	while (bindings->entry_count > retained_count) {
		resolver_cache_entry_release(bindings->entries[--bindings->entry_count]);
		bindings->entries[bindings->entry_count] = NULL;
	}
}

static route_bindings_build_status route_bindings_destination_prepare(route_bindings *bindings, route_binding *binding, const route_destination_view *destination,
	const hosts_table *hosts, resolver_cache *cache) {
	binding->port = destination->port;
	if (destination->numeric) {
		binding->numeric_address = destination->numeric_address;
		binding->source = ROUTE_BINDING_SOURCE_NUMERIC;
		return ROUTE_BINDINGS_BUILD_OK;
	}
	if (destination->srv) {
		route_bindings_entry_status entry_status = route_bindings_cache_entry_acquire(bindings, cache, destination->query_name, ns_t_srv, &binding->srv_entry);
		if (entry_status == ROUTE_BINDINGS_ENTRY_UNAVAILABLE) {
			binding->source = ROUTE_BINDING_SOURCE_UNAVAILABLE;
			return ROUTE_BINDINGS_BUILD_OK;
		}
		if (entry_status != ROUTE_BINDINGS_ENTRY_OK) {
			return entry_status == ROUTE_BINDINGS_ENTRY_LIMIT ? ROUTE_BINDINGS_BUILD_LIMIT : ROUTE_BINDINGS_BUILD_MEMORY;
		}
		binding->source = ROUTE_BINDING_SOURCE_DNS_SRV;
		return ROUTE_BINDINGS_BUILD_OK;
	}
	hosts_lookup_status hosts_status = hosts_table_lookup(hosts, destination->query_name, &binding->hosts);
	if (hosts_status == HOSTS_LOOKUP_OK) {
		binding->source = ROUTE_BINDING_SOURCE_HOSTS;
		return ROUTE_BINDINGS_BUILD_OK;
	}
	if (hosts_status == HOSTS_LOOKUP_MEMORY) {
		return ROUTE_BINDINGS_BUILD_MEMORY;
	}
	hosts_address_result_destroy(&binding->hosts);
	size_t retained_entry_count = bindings->entry_count;
	route_bindings_entry_status ipv4_status = route_bindings_cache_entry_acquire(bindings, cache, destination->query_name, ns_t_a, &binding->ipv4_entry);
	if (ipv4_status == ROUTE_BINDINGS_ENTRY_UNAVAILABLE) {
		binding->source = ROUTE_BINDING_SOURCE_UNAVAILABLE;
		return ROUTE_BINDINGS_BUILD_OK;
	}
	if (ipv4_status != ROUTE_BINDINGS_ENTRY_OK) {
		return ipv4_status == ROUTE_BINDINGS_ENTRY_LIMIT ? ROUTE_BINDINGS_BUILD_LIMIT : ROUTE_BINDINGS_BUILD_MEMORY;
	}
	route_bindings_entry_status ipv6_status = route_bindings_cache_entry_acquire(bindings, cache, destination->query_name, ns_t_aaaa, &binding->ipv6_entry);
	if (ipv6_status == ROUTE_BINDINGS_ENTRY_UNAVAILABLE) {
		route_bindings_cache_entries_rollback(bindings, retained_entry_count);
		binding->ipv4_entry = NULL;
		binding->source = ROUTE_BINDING_SOURCE_UNAVAILABLE;
		return ROUTE_BINDINGS_BUILD_OK;
	}
	if (ipv6_status != ROUTE_BINDINGS_ENTRY_OK) {
		return ipv6_status == ROUTE_BINDINGS_ENTRY_LIMIT ? ROUTE_BINDINGS_BUILD_LIMIT : ROUTE_BINDINGS_BUILD_MEMORY;
	}
	binding->source = ROUTE_BINDING_SOURCE_DNS_ADDRESS;
	return ROUTE_BINDINGS_BUILD_OK;
}

/* section: functions (exported) */
route_bindings_build_status route_bindings_build(const route_table *routes, const hosts_table *hosts, resolver_cache *cache, route_bindings **result) {
	if (routes == NULL || hosts == NULL || cache == NULL || result == NULL || *result != NULL) {
		return ROUTE_BINDINGS_BUILD_BAD_ARGUMENT;
	}
	size_t destination_count = route_table_destination_count(routes);
	if ((destination_count > 0 && destination_count > SIZE_MAX / sizeof(route_binding)) || destination_count > SIZE_MAX / 2U
		|| (destination_count > 0 && destination_count * 2U > SIZE_MAX / sizeof(resolver_cache_entry *))) {
		return ROUTE_BINDINGS_BUILD_MEMORY;
	}
	route_bindings *bindings = calloc(1, sizeof(*bindings));
	if (bindings == NULL) {
		return ROUTE_BINDINGS_BUILD_MEMORY;
	}
	bindings->destination_count = destination_count;
	if (destination_count > 0) {
		bindings->destinations = calloc(destination_count, sizeof(*bindings->destinations));
		bindings->entries = calloc(destination_count * 2U, sizeof(*bindings->entries));
		if (bindings->destinations == NULL || bindings->entries == NULL) {
			route_bindings_destroy(bindings);
			return ROUTE_BINDINGS_BUILD_MEMORY;
		}
	}
	for (size_t destination_index = 0; destination_index < destination_count; destination_index++) {
		route_destination_view destination;
		if (!route_table_destination_get(routes, destination_index, &destination)) {
			route_bindings_destroy(bindings);
			return ROUTE_BINDINGS_BUILD_INVALID;
		}
		route_bindings_build_status status = route_bindings_destination_prepare(bindings, &bindings->destinations[destination_index], &destination, hosts, cache);
		if (status != ROUTE_BINDINGS_BUILD_OK) {
			route_bindings_destroy(bindings);
			return status;
		}
	}
	*result = bindings;
	return ROUTE_BINDINGS_BUILD_OK;
}

void route_bindings_destroy(route_bindings *bindings) {
	if (bindings == NULL) {
		return;
	}
	for (size_t destination_index = 0; destination_index < bindings->destination_count; destination_index++) {
		hosts_address_result_destroy(&bindings->destinations[destination_index].hosts);
	}
	for (size_t entry_index = 0; entry_index < bindings->entry_count; entry_index++) {
		resolver_cache_entry_release(bindings->entries[entry_index]);
	}
	free(bindings->destinations);
	free(bindings->entries);
	free(bindings);
}

size_t route_bindings_destination_count(const route_bindings *bindings) {
	return bindings == NULL ? 0 : bindings->destination_count;
}

bool route_bindings_destination_get(const route_bindings *bindings, size_t destination_index, route_binding_view *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (bindings == NULL || destination_index >= bindings->destination_count || result == NULL) {
		return false;
	}
	const route_binding *binding = &bindings->destinations[destination_index];
	result->addresses = binding->hosts.addresses;
	result->address_count = binding->hosts.address_count;
	result->ipv4_entry = binding->ipv4_entry;
	result->ipv6_entry = binding->ipv6_entry;
	result->numeric_address = binding->numeric_address;
	result->port = binding->port;
	result->srv_entry = binding->srv_entry;
	result->source = binding->source;
	return true;
}

size_t route_bindings_entry_count(const route_bindings *bindings) {
	return bindings == NULL ? 0 : bindings->entry_count;
}

bool route_bindings_entry_get(const route_bindings *bindings, size_t entry_index, resolver_cache_entry **result) {
	if (result != NULL) {
		*result = NULL;
	}
	if (bindings == NULL || entry_index >= bindings->entry_count || result == NULL) {
		return false;
	}
	*result = bindings->entries[entry_index];
	return true;
}
