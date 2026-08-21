/*
 * route/endpoint.c: Fresh route endpoint selection and worker snapshots
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "../define/global.h"
#include "../network.h"
#include "../protocol/proxy.h"
#include "../resolver/cache.h"
#include "../resolver/dns.h"
#include "../timeutil.h"
#include "bindings.h"
#include "generation.h"
#include "resolution.h"
#include "table.h"

/* section: headers (self) */
#include "endpoint.h"

/* section: types */
typedef enum {
	ROUTE_ENDPOINT_ADDRESS_OK,
	ROUTE_ENDPOINT_ADDRESS_BAD_ARGUMENT,
	ROUTE_ENDPOINT_ADDRESS_LIMIT,
	ROUTE_ENDPOINT_ADDRESS_PENDING,
	ROUTE_ENDPOINT_ADDRESS_UNAVAILABLE
} route_endpoint_address_status;

/* section: functions (local) */
static route_endpoint_address_status route_endpoint_address_family_select(const net_addr *addresses, size_t address_count, sa_family_t family, net_addr *result) {
	if (result == NULL || (address_count > 0 && addresses == NULL) || (family != AF_INET && family != AF_INET6)) {
		return ROUTE_ENDPOINT_ADDRESS_BAD_ARGUMENT;
	}
	for (size_t address_index = 0; address_index < address_count; address_index++) {
		if (addresses[address_index].family == family && addresses[address_index].err == NET_OK) {
			*result = addresses[address_index];
			return ROUTE_ENDPOINT_ADDRESS_OK;
		}
	}
	return ROUTE_ENDPOINT_ADDRESS_UNAVAILABLE;
}

static route_endpoint_address_status route_endpoint_addresses_select(const net_addr *addresses, size_t address_count, sa_family_t preferred_family, net_addr *result) {
	route_endpoint_address_status status = route_endpoint_address_family_select(addresses, address_count, preferred_family, result);
	if (status != ROUTE_ENDPOINT_ADDRESS_UNAVAILABLE) {
		return status;
	}
	sa_family_t alternate_family = preferred_family == AF_INET ? AF_INET6 : AF_INET;
	return route_endpoint_address_family_select(addresses, address_count, alternate_family, result);
}

static bool route_endpoint_entry_view(resolver_cache_entry *entry, const struct timespec *now, const route_endpoint_overlay *overlays, resolver_cache_view *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (entry == NULL || now == NULL || result == NULL) {
		return false;
	}
	const route_endpoint_overlay *match = NULL;
	const route_endpoint_overlay *overlay = overlays;
	for (size_t overlay_index = 0; overlay != NULL && overlay_index < ROUTE_ENDPOINT_REQUIREMENT_LIMIT; overlay_index++) {
		if (overlay->entry == NULL || overlay->status > ROUTE_ENDPOINT_OVERLAY_UNAVAILABLE) {
			return false;
		}
		if (overlay->entry == entry && match == NULL) {
			match = overlay;
		}
		overlay = overlay->next;
	}
	if (overlay != NULL) {
		return false;
	}
	if (match == NULL || match->status == ROUTE_ENDPOINT_OVERLAY_NONE) {
		return resolver_cache_entry_view(entry, now, result);
	}
	if (match->status == ROUTE_ENDPOINT_OVERLAY_UNAVAILABLE) {
		result->status = RESOLVER_CACHE_VIEW_FRESH_NODATA;
		return true;
	}
	result->addresses = match->addresses;
	result->address_count = match->address_count;
	result->srv_records = match->srv_records;
	result->srv_record_count = match->srv_record_count;
	result->status = RESOLVER_CACHE_VIEW_FRESH_POSITIVE;
	return true;
}

static bool route_endpoint_requirement_add(route_endpoint_requirements *requirements, resolver_cache_entry *entry, bool pending) {
	if (requirements == NULL || entry == NULL) {
		return false;
	}
	for (size_t requirement_index = 0; requirement_index < requirements->count; requirement_index++) {
		if (requirements->items[requirement_index].entry == entry) {
			requirements->items[requirement_index].pending = requirements->items[requirement_index].pending || pending;
			return true;
		}
	}
	if (requirements->count >= ROUTE_ENDPOINT_REQUIREMENT_LIMIT) {
		return false;
	}
	requirements->items[requirements->count].entry = entry;
	requirements->items[requirements->count].pending = pending;
	requirements->count++;
	return true;
}

static route_endpoint_address_status route_endpoint_cache_family_select(resolver_cache_entry *entry, sa_family_t family, const struct timespec *now,
	const route_endpoint_overlay *overlays, route_endpoint_requirements *requirements, net_addr *result) {
	if (entry == NULL) {
		return ROUTE_ENDPOINT_ADDRESS_UNAVAILABLE;
	}
	uint16_t expected_query_type = family == AF_INET ? ns_t_a : family == AF_INET6 ? ns_t_aaaa : 0;
	if (expected_query_type == 0 || resolver_cache_entry_query_type(entry) != expected_query_type || result == NULL) {
		return ROUTE_ENDPOINT_ADDRESS_BAD_ARGUMENT;
	}
	resolver_cache_view view;
	if (!route_endpoint_entry_view(entry, now, overlays, &view)) {
		return ROUTE_ENDPOINT_ADDRESS_BAD_ARGUMENT;
	}
	if (!route_endpoint_requirement_add(requirements, entry, view.status == RESOLVER_CACHE_VIEW_EMPTY)) {
		return ROUTE_ENDPOINT_ADDRESS_LIMIT;
	}
	if (view.status == RESOLVER_CACHE_VIEW_EMPTY) {
		return ROUTE_ENDPOINT_ADDRESS_PENDING;
	}
	if (view.status != RESOLVER_CACHE_VIEW_FRESH_POSITIVE) {
		return ROUTE_ENDPOINT_ADDRESS_UNAVAILABLE;
	}
	for (size_t address_index = 0; address_index < view.address_count; address_index++) {
		if (view.addresses[address_index].address.family == family && view.addresses[address_index].address.err == NET_OK) {
			*result = view.addresses[address_index].address;
			return ROUTE_ENDPOINT_ADDRESS_OK;
		}
	}
	return ROUTE_ENDPOINT_ADDRESS_BAD_ARGUMENT;
}

static route_endpoint_address_status route_endpoint_cache_select(resolver_cache_entry *ipv4_entry, resolver_cache_entry *ipv6_entry, sa_family_t preferred_family,
	const struct timespec *now, const route_endpoint_overlay *overlays, route_endpoint_requirements *requirements, net_addr *result) {
	resolver_cache_entry *preferred_entry = preferred_family == AF_INET ? ipv4_entry : preferred_family == AF_INET6 ? ipv6_entry : NULL;
	resolver_cache_entry *alternate_entry = preferred_family == AF_INET ? ipv6_entry : preferred_family == AF_INET6 ? ipv4_entry : NULL;
	if (preferred_entry == NULL && alternate_entry == NULL) {
		return ROUTE_ENDPOINT_ADDRESS_UNAVAILABLE;
	}
	route_endpoint_address_status preferred_status = route_endpoint_cache_family_select(preferred_entry, preferred_family, now, overlays, requirements, result);
	if (preferred_status == ROUTE_ENDPOINT_ADDRESS_OK || preferred_status == ROUTE_ENDPOINT_ADDRESS_BAD_ARGUMENT || preferred_status == ROUTE_ENDPOINT_ADDRESS_LIMIT) {
		return preferred_status;
	}
	sa_family_t alternate_family = preferred_family == AF_INET ? AF_INET6 : preferred_family == AF_INET6 ? AF_INET : AF_UNSPEC;
	route_endpoint_address_status alternate_status = route_endpoint_cache_family_select(alternate_entry, alternate_family, now, overlays, requirements, result);
	if (alternate_status == ROUTE_ENDPOINT_ADDRESS_OK || alternate_status == ROUTE_ENDPOINT_ADDRESS_BAD_ARGUMENT || alternate_status == ROUTE_ENDPOINT_ADDRESS_LIMIT) {
		return alternate_status;
	}
	return preferred_status == ROUTE_ENDPOINT_ADDRESS_PENDING || alternate_status == ROUTE_ENDPOINT_ADDRESS_PENDING ? ROUTE_ENDPOINT_ADDRESS_PENDING
		: ROUTE_ENDPOINT_ADDRESS_UNAVAILABLE;
}

static route_endpoint_select_status route_endpoint_select_status_from_address(route_endpoint_address_status status) {
	switch (status) {
		case ROUTE_ENDPOINT_ADDRESS_OK:
			return ROUTE_ENDPOINT_SELECT_OK;
		case ROUTE_ENDPOINT_ADDRESS_PENDING:
			return ROUTE_ENDPOINT_SELECT_PENDING;
		case ROUTE_ENDPOINT_ADDRESS_LIMIT:
			return ROUTE_ENDPOINT_SELECT_LIMIT;
		case ROUTE_ENDPOINT_ADDRESS_UNAVAILABLE:
			return ROUTE_ENDPOINT_SELECT_UNAVAILABLE;
		case ROUTE_ENDPOINT_ADDRESS_BAD_ARGUMENT:
		default:
			return ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT;
	}
}

static route_endpoint_select_status route_endpoint_srv_record_select(const dns_srv_record *records, size_t record_count, const dns_srv_record **result) {
	if (result != NULL) {
		*result = NULL;
	}
	if (records == NULL || record_count == 0 || record_count > DNS_SRV_RECORD_LIMIT || result == NULL) {
		return ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT;
	}
	bool named_target = false;
	bool root_target = false;
	for (size_t record_index = 0; record_index < record_count; record_index++) {
		if (strcmp(records[record_index].target, ".") == 0) {
			root_target = true;
		} else {
			named_target = true;
		}
	}
	if (root_target) {
		return named_target ? ROUTE_ENDPOINT_SELECT_CONTRADICTORY : ROUTE_ENDPOINT_SELECT_SERVICE_UNAVAILABLE;
	}
	uint16_t minimum_priority = UINT16_MAX;
	for (size_t record_index = 0; record_index < record_count; record_index++) {
		if (records[record_index].target[0] == '\0') {
			return ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT;
		}
		if (records[record_index].priority < minimum_priority) {
			minimum_priority = records[record_index].priority;
		}
	}
	uint16_t maximum_weight = 0;
	for (size_t record_index = 0; record_index < record_count; record_index++) {
		if (records[record_index].priority == minimum_priority && records[record_index].weight > maximum_weight) {
			maximum_weight = records[record_index].weight;
		}
	}
	for (size_t record_index = 0; record_index < record_count; record_index++) {
		if (records[record_index].priority == minimum_priority && records[record_index].weight == maximum_weight) {
			*result = &records[record_index];
			return ROUTE_ENDPOINT_SELECT_OK;
		}
	}
	return ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT;
}

static bool route_endpoint_string_copy(char *destination, size_t destination_size, const char *source) {
	if (destination == NULL || destination_size == 0 || source == NULL) {
		return false;
	}
	size_t source_size = strlen(source);
	if (source_size >= destination_size) {
		return false;
	}
	memcpy(destination, source, source_size + 1U);
	return true;
}

static bool route_endpoint_target_find(const route_resolution *resolution, size_t destination_index, size_t target_count, const char *name,
	route_resolution_target_view *result) {
	for (size_t target_index = 0; target_index < target_count; target_index++) {
		route_resolution_target_view candidate;
		if (!route_resolution_destination_target_get(resolution, destination_index, target_index, &candidate)) {
			return false;
		}
		if (candidate.name != NULL && strcmp(candidate.name, name) == 0) {
			*result = candidate;
			return true;
		}
	}
	return false;
}

static route_endpoint_address_status route_endpoint_target_select(const route_resolution_target_view *target, sa_family_t preferred_family, const struct timespec *now,
	const route_endpoint_overlay *overlays, route_endpoint_requirements *requirements, net_addr *result) {
	if (target == NULL) {
		return ROUTE_ENDPOINT_ADDRESS_BAD_ARGUMENT;
	}
	switch (target->source) {
		case ROUTE_RESOLUTION_TARGET_NUMERIC:
			if (target->numeric_address.err != NET_OK || (target->numeric_address.family != AF_INET && target->numeric_address.family != AF_INET6)) {
				return ROUTE_ENDPOINT_ADDRESS_UNAVAILABLE;
			}
			*result = target->numeric_address;
			return ROUTE_ENDPOINT_ADDRESS_OK;
		case ROUTE_RESOLUTION_TARGET_HOSTS:
			return route_endpoint_addresses_select(target->addresses, target->address_count, preferred_family, result);
		case ROUTE_RESOLUTION_TARGET_DNS:
			return route_endpoint_cache_select(target->ipv4_entry, target->ipv6_entry, preferred_family, now, overlays, requirements, result);
		default:
			return ROUTE_ENDPOINT_ADDRESS_BAD_ARGUMENT;
	}
}

/* section: functions (exported) */
route_endpoint_select_status route_endpoint_evaluate(route_generation *generation, const char *vhost, const struct timespec *now, const p_proxy *inbound_proxy,
	const route_endpoint_overlay *overlays, route_endpoint_requirements *requirements, route_endpoint_snapshot *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (requirements != NULL) {
		memset(requirements, 0, sizeof(*requirements));
	}
	if (generation == NULL || vhost == NULL || inbound_proxy == NULL || requirements == NULL || result == NULL || route_generation_identity(generation) == 0
		|| !timeutil_valid(now)
		|| (inbound_proxy->family != AF_INET && inbound_proxy->family != AF_INET6) || inbound_proxy->srcaddr.family != inbound_proxy->family
		|| inbound_proxy->dstaddr.family != inbound_proxy->family || inbound_proxy->srcaddr.err != NET_OK || inbound_proxy->dstaddr.err != NET_OK) {
		return ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT;
	}
	const route_table *routes = route_generation_routes(generation);
	const route_bindings *bindings = route_generation_bindings(generation);
	const route_resolution *resolution = route_generation_resolution(generation);
	if (routes == NULL || bindings == NULL || resolution == NULL) {
		return ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT;
	}
	route_view route;
	if (!route_table_find(routes, vhost, &route)) {
		return ROUTE_ENDPOINT_SELECT_NO_ROUTE;
	}
	route_binding_view binding;
	if (!route_bindings_destination_get(bindings, route.destination_index, &binding)) {
		return ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT;
	}
	net_addr selected_address;
	memset(&selected_address, 0, sizeof(selected_address));
	const char *target_name = route.configured_address;
	in_port_t selected_port = binding.port;
	route_endpoint_address_status address_status;
	switch (binding.source) {
		case ROUTE_BINDING_SOURCE_NUMERIC:
			if (binding.numeric_address.err != NET_OK || (binding.numeric_address.family != AF_INET && binding.numeric_address.family != AF_INET6)) {
				return ROUTE_ENDPOINT_SELECT_UNAVAILABLE;
			}
			selected_address = binding.numeric_address;
			break;
		case ROUTE_BINDING_SOURCE_HOSTS:
			address_status = route_endpoint_addresses_select(binding.addresses, binding.address_count, inbound_proxy->family, &selected_address);
			if (address_status != ROUTE_ENDPOINT_ADDRESS_OK) {
				return route_endpoint_select_status_from_address(address_status);
			}
			break;
		case ROUTE_BINDING_SOURCE_DNS_ADDRESS:
			address_status = route_endpoint_cache_select(binding.ipv4_entry, binding.ipv6_entry, inbound_proxy->family, now, overlays, requirements, &selected_address);
			if (address_status != ROUTE_ENDPOINT_ADDRESS_OK) {
				return route_endpoint_select_status_from_address(address_status);
			}
			break;
		case ROUTE_BINDING_SOURCE_DNS_SRV: {
			resolver_cache_view srv_view;
			if (binding.srv_entry == NULL || resolver_cache_entry_query_type(binding.srv_entry) != ns_t_srv
				|| !route_endpoint_entry_view(binding.srv_entry, now, overlays, &srv_view)) {
				return ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT;
			}
			if (!route_endpoint_requirement_add(requirements, binding.srv_entry, srv_view.status == RESOLVER_CACHE_VIEW_EMPTY)) {
				return ROUTE_ENDPOINT_SELECT_LIMIT;
			}
			if (srv_view.status == RESOLVER_CACHE_VIEW_EMPTY) {
				return ROUTE_ENDPOINT_SELECT_PENDING;
			}
			if (srv_view.status != RESOLVER_CACHE_VIEW_FRESH_POSITIVE) {
				return ROUTE_ENDPOINT_SELECT_UNAVAILABLE;
			}
			const dns_srv_record *selected_record = NULL;
			route_endpoint_select_status srv_status = route_endpoint_srv_record_select(srv_view.srv_records, srv_view.srv_record_count, &selected_record);
			if (srv_status != ROUTE_ENDPOINT_SELECT_OK) {
				return srv_status;
			}
			route_resolution_destination_view destination;
			route_resolution_target_view target;
			if (!route_resolution_destination_get(resolution, route.destination_index, &destination)
				|| !route_endpoint_target_find(resolution, route.destination_index, destination.target_count, selected_record->target, &target)) {
				return ROUTE_ENDPOINT_SELECT_UNAVAILABLE;
			}
			address_status = route_endpoint_target_select(&target, inbound_proxy->family, now, overlays, requirements, &selected_address);
			if (address_status != ROUTE_ENDPOINT_ADDRESS_OK) {
				return route_endpoint_select_status_from_address(address_status);
			}
			selected_port = selected_record->port;
			target_name = selected_record->target;
			break;
		}
		case ROUTE_BINDING_SOURCE_UNAVAILABLE:
			return ROUTE_ENDPOINT_SELECT_UNAVAILABLE;
		default:
			return ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT;
	}
	if (!route_endpoint_string_copy(result->configured_address, sizeof(result->configured_address), route.configured_address)
		|| !route_endpoint_string_copy(result->target_name, sizeof(result->target_name), target_name)
		|| !route_endpoint_string_copy(result->vhost, sizeof(result->vhost), route.vhost)) {
		memset(result, 0, sizeof(*result));
		return ROUTE_ENDPOINT_SELECT_LIMIT;
	}
	result->address = selected_address;
	result->destination_index = route.destination_index;
	result->generation_identity = route_generation_identity(generation);
	result->inbound_proxy = *inbound_proxy;
	result->pheader = route.pheader;
	result->port = selected_port;
	result->rewrite = route.rewrite;
	return ROUTE_ENDPOINT_SELECT_OK;
}

route_endpoint_select_status route_endpoint_select(route_generation *generation, const char *vhost, const struct timespec *now, const p_proxy *inbound_proxy,
	route_endpoint_snapshot *result) {
	route_endpoint_requirements requirements;
	return route_endpoint_evaluate(generation, vhost, now, inbound_proxy, NULL, &requirements, result);
}
