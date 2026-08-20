/*
 * route/bindings.h: Per-generation proxy destination resolver bindings
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_ROUTE_BINDINGS_H_INCLUDED_

#define _MRS_ROUTE_BINDINGS_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>

/* section: headers (project) */
#include "../resolver/cache.h"
#include "../resolver/hosts.h"
#include "table.h"

/* section: types */
typedef enum {
	ROUTE_BINDING_SOURCE_UNAVAILABLE,
	ROUTE_BINDING_SOURCE_NUMERIC,
	ROUTE_BINDING_SOURCE_HOSTS,
	ROUTE_BINDING_SOURCE_DNS_ADDRESS,
	ROUTE_BINDING_SOURCE_DNS_SRV
} route_binding_source;
typedef struct {
	const net_addr *addresses;
	size_t address_count;
	resolver_cache_entry *ipv4_entry;
	resolver_cache_entry *ipv6_entry;
	net_addr numeric_address;
	in_port_t port;
	resolver_cache_entry *srv_entry;
	route_binding_source source;
} route_binding_view;
typedef struct route_bindings route_bindings;
typedef enum {
	ROUTE_BINDINGS_BUILD_OK,
	ROUTE_BINDINGS_BUILD_BAD_ARGUMENT,
	ROUTE_BINDINGS_BUILD_INVALID,
	ROUTE_BINDINGS_BUILD_LIMIT,
	ROUTE_BINDINGS_BUILD_MEMORY
} route_bindings_build_status;

/* section: functions (exported) */
route_bindings_build_status route_bindings_build(const route_table *routes, const hosts_table *hosts, resolver_cache *cache, route_bindings **result);
void route_bindings_destroy(route_bindings *bindings);
size_t route_bindings_destination_count(const route_bindings *bindings);
bool route_bindings_destination_get(const route_bindings *bindings, size_t destination_index, route_binding_view *result);
size_t route_bindings_entry_count(const route_bindings *bindings);
/* Returned entries are borrowed from the generation and must not be released by the caller. */
bool route_bindings_entry_get(const route_bindings *bindings, size_t entry_index, resolver_cache_entry **result);

#endif
