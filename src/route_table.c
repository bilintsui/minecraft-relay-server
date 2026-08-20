/*
 * route_table.c: Immutable prepared proxy route table
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <cjson/cJSON.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* section: headers (project) */
#include "config.h"
#include "network.h"

/* section: headers (self) */
#include "route_table.h"

/* section: defines */
/* hash */
#define ROUTE_TABLE_FNV_OFFSET	UINT64_C(14695981039346656037)
#define ROUTE_TABLE_FNV_PRIME	UINT64_C(1099511628211)

/* service */
#define ROUTE_TABLE_SRV_PREFIX	"_minecraft._tcp."

/* section: types */
typedef struct {
	size_t hash_next;
	bool numeric;
	net_addr numeric_address;
	in_port_t port;
	char *query_name;
	bool srv;
} route_destination;
typedef struct {
	char *configured_address;
	size_t destination_index;
	bool pheader;
	bool rewrite;
	char *vhost;
} route_entry;
struct route_table {
	route_destination *destinations;
	size_t destination_count;
	route_entry *routes;
	size_t route_count;
};

/* section: functions (local) */
static bool route_bool_read(const cJSON *value) {
	if (cJSON_IsBool(value)) {
		return cJSON_IsTrue(value);
	}
	return cJSON_IsNumber(value) && value->valueint != 0;
}

static bool route_destination_equal(const route_destination *left, const route_destination *right) {
	if (left->numeric != right->numeric || left->port != right->port || left->srv != right->srv) {
		return false;
	}
	if (!left->numeric) {
		return strcmp(left->query_name, right->query_name) == 0;
	}
	if (left->numeric_address.family != right->numeric_address.family) {
		return false;
	}
	if (left->numeric_address.family == AF_INET) {
		return left->numeric_address.addr.v4 == right->numeric_address.addr.v4;
	}
	return left->numeric_address.family == AF_INET6 && memcmp(left->numeric_address.addr.v6, right->numeric_address.addr.v6, sizeof(left->numeric_address.addr.v6)) == 0;
}

static uint64_t route_hash_byte(uint64_t hash, uint8_t value) {
	return (hash ^ value) * ROUTE_TABLE_FNV_PRIME;
}

static uint64_t route_hash_destination(const route_destination *destination) {
	uint64_t hash = ROUTE_TABLE_FNV_OFFSET;
	hash = route_hash_byte(hash, destination->numeric ? UINT8_C(1) : UINT8_C(0));
	hash = route_hash_byte(hash, destination->srv ? UINT8_C(1) : UINT8_C(0));
	hash = route_hash_byte(hash, (uint8_t)(destination->port >> 8));
	hash = route_hash_byte(hash, (uint8_t)destination->port);
	if (!destination->numeric) {
		for (size_t index = 0; destination->query_name[index] != '\0'; index++) {
			hash = route_hash_byte(hash, (uint8_t)destination->query_name[index]);
		}
		return hash;
	}
	hash = route_hash_byte(hash, destination->numeric_address.family == AF_INET ? UINT8_C(4) : UINT8_C(6));
	const uint8_t *address = destination->numeric_address.family == AF_INET ? (const uint8_t *)&destination->numeric_address.addr.v4 : destination->numeric_address.addr.v6;
	size_t address_size = destination->numeric_address.family == AF_INET ? sizeof(destination->numeric_address.addr.v4) : sizeof(destination->numeric_address.addr.v6);
	for (size_t index = 0; index < address_size; index++) {
		hash = route_hash_byte(hash, address[index]);
	}
	return hash;
}

static char *route_name_create(const char *source, bool srv) {
	if (source == NULL) {
		return NULL;
	}
	size_t source_size = strlen(source);
	bool root_name = source_size == 1 && source[0] == '.';
	if (source_size > 1 && source[source_size - 1] == '.' && source[source_size - 2] != '.') {
		source_size--;
	}
	size_t prefix_size = srv ? sizeof(ROUTE_TABLE_SRV_PREFIX) - 1U : 0;
	if (srv && (root_name || source_size == 0)) {
		source_size = 0;
		prefix_size--;
	}
	if (source_size > SIZE_MAX - prefix_size - 1U) {
		return NULL;
	}
	char *result = malloc(prefix_size + source_size + 1U);
	if (result == NULL) {
		return NULL;
	}
	if (prefix_size > 0) {
		memcpy(result, ROUTE_TABLE_SRV_PREFIX, prefix_size);
	}
	for (size_t index = 0; index < source_size; index++) {
		unsigned char character = (unsigned char)source[index];
		result[prefix_size + index] = character >= 'A' && character <= 'Z' ? (char)(character - 'A' + 'a') : (char)character;
	}
	result[prefix_size + source_size] = '\0';
	return result;
}

static bool route_proxy_count(const cJSON *proxy, size_t *destination_capacity, size_t *route_count) {
	if (!cJSON_IsArray(proxy) || destination_capacity == NULL || route_count == NULL) {
		return false;
	}
	*destination_capacity = 0;
	*route_count = 0;
	const cJSON *item = NULL;
	cJSON_ArrayForEach(item, proxy) {
		const cJSON *address = cJSON_GetObjectItemCaseSensitive(item, "address");
		const cJSON *port = cJSON_GetObjectItemCaseSensitive(item, "port");
		const cJSON *vhosts = cJSON_GetObjectItemCaseSensitive(item, "vhost");
		if (!cJSON_IsString(address) || !cJSON_IsArray(vhosts) || (port != NULL && (!cJSON_IsNumber(port) || port->valueint < 0 || port->valueint > UINT16_MAX))) {
			return false;
		}
		size_t item_route_count = 0;
		const cJSON *vhost = NULL;
		cJSON_ArrayForEach(vhost, vhosts) {
			if (cJSON_IsString(vhost)) {
				if (*route_count == SIZE_MAX || item_route_count == SIZE_MAX) {
					return false;
				}
				(*route_count)++;
				item_route_count++;
			}
		}
		if (item_route_count > 0) {
			if (*destination_capacity == SIZE_MAX) {
				return false;
			}
			(*destination_capacity)++;
		}
	}
	return true;
}

static bool route_proxy_destination_prepare(const cJSON *proxy, route_destination *destination) {
	const char *address = cJSON_GetObjectItemCaseSensitive(proxy, "address")->valuestring;
	const cJSON *port = cJSON_GetObjectItemCaseSensitive(proxy, "port");
	destination->hash_next = SIZE_MAX;
	destination->srv = port == NULL;
	if (port != NULL) {
		destination->port = (in_port_t)port->valueint;
		int saved_errno = errno;
		destination->numeric_address = net_addr_parse(address);
		errno = saved_errno;
		destination->numeric = destination->numeric_address.family != 0;
		if (!destination->numeric) {
			memset(&destination->numeric_address, 0, sizeof(destination->numeric_address));
		}
	}
	if (!destination->numeric) {
		destination->query_name = route_name_create(address, destination->srv);
		if (destination->query_name == NULL) {
			return false;
		}
	}
	return true;
}

static void route_table_destination_add(route_table *table, size_t *buckets, size_t bucket_count, route_destination *candidate, size_t *result) {
	size_t bucket = (size_t)(route_hash_destination(candidate) % (uint64_t)bucket_count);
	for (size_t destination_index = buckets[bucket]; destination_index != SIZE_MAX; destination_index = table->destinations[destination_index].hash_next) {
		if (route_destination_equal(&table->destinations[destination_index], candidate)) {
			free(candidate->query_name);
			memset(candidate, 0, sizeof(*candidate));
			*result = destination_index;
			return;
		}
	}
	candidate->hash_next = buckets[bucket];
	buckets[bucket] = table->destination_count;
	table->destinations[table->destination_count] = *candidate;
	memset(candidate, 0, sizeof(*candidate));
	*result = table->destination_count++;
}

static bool route_vhost_matches(const char *configured, const char *received) {
	size_t configured_size = strlen(configured);
	size_t received_size = strlen(received);
	if (received_size > 0 && received[received_size - 1] == '.') {
		received_size--;
	}
	return configured_size == received_size && strncasecmp(configured, received, received_size) == 0;
}

/* section: functions (exported) */
route_table_build_status route_table_build(const conf *source, route_table **result) {
	if (source == NULL || result == NULL || *result != NULL) {
		return ROUTE_TABLE_BUILD_BAD_ARGUMENT;
	}
	size_t destination_capacity;
	size_t route_count;
	if (!route_proxy_count(source->proxy, &destination_capacity, &route_count)) {
		return ROUTE_TABLE_BUILD_INVALID;
	}
	if ((destination_capacity > 0 && (destination_capacity > SIZE_MAX / sizeof(route_destination) || destination_capacity > SIZE_MAX / sizeof(size_t)))
		|| (route_count > 0 && route_count > SIZE_MAX / sizeof(route_entry))) {
		return ROUTE_TABLE_BUILD_MEMORY;
	}
	route_table *table = calloc(1, sizeof(*table));
	size_t *buckets = NULL;
	if (table == NULL) {
		return ROUTE_TABLE_BUILD_MEMORY;
	}
	if (destination_capacity > 0) {
		table->destinations = calloc(destination_capacity, sizeof(*table->destinations));
		buckets = malloc(destination_capacity * sizeof(*buckets));
		if (table->destinations == NULL || buckets == NULL) {
			route_table_destroy(table);
			free(buckets);
			return ROUTE_TABLE_BUILD_MEMORY;
		}
		for (size_t bucket = 0; bucket < destination_capacity; bucket++) {
			buckets[bucket] = SIZE_MAX;
		}
	}
	if (route_count > 0) {
		table->routes = calloc(route_count, sizeof(*table->routes));
		if (table->routes == NULL) {
			route_table_destroy(table);
			free(buckets);
			return ROUTE_TABLE_BUILD_MEMORY;
		}
	}
	const cJSON *proxy = NULL;
	cJSON_ArrayForEach(proxy, source->proxy) {
		const cJSON *vhosts = cJSON_GetObjectItemCaseSensitive(proxy, "vhost");
		bool has_routes = false;
		const cJSON *vhost = NULL;
		cJSON_ArrayForEach(vhost, vhosts) {
			has_routes = has_routes || cJSON_IsString(vhost);
		}
		if (!has_routes) {
			continue;
		}
		route_destination candidate;
		memset(&candidate, 0, sizeof(candidate));
		if (!route_proxy_destination_prepare(proxy, &candidate)) {
			route_table_destroy(table);
			free(buckets);
			return ROUTE_TABLE_BUILD_MEMORY;
		}
		size_t destination_index;
		route_table_destination_add(table, buckets, destination_capacity, &candidate, &destination_index);
		cJSON_ArrayForEach(vhost, vhosts) {
			if (!cJSON_IsString(vhost)) {
				continue;
			}
			route_entry *route = &table->routes[table->route_count];
			route->configured_address = strdup(cJSON_GetObjectItemCaseSensitive(proxy, "address")->valuestring);
			route->vhost = strdup(vhost->valuestring);
			if (route->configured_address == NULL || route->vhost == NULL) {
				free(route->configured_address);
				free(route->vhost);
				memset(route, 0, sizeof(*route));
				route_table_destroy(table);
				free(buckets);
				return ROUTE_TABLE_BUILD_MEMORY;
			}
			route->destination_index = destination_index;
			route->pheader = route_bool_read(cJSON_GetObjectItemCaseSensitive(proxy, "pheader"));
			route->rewrite = route_bool_read(cJSON_GetObjectItemCaseSensitive(proxy, "rewrite"));
			table->route_count++;
		}
	}
	free(buckets);
	*result = table;
	return ROUTE_TABLE_BUILD_OK;
}

size_t route_table_destination_count(const route_table *table) {
	return table == NULL ? 0 : table->destination_count;
}

bool route_table_destination_get(const route_table *table, size_t destination_index, route_destination_view *result) {
	if (table == NULL || destination_index >= table->destination_count || result == NULL) {
		return false;
	}
	const route_destination *destination = &table->destinations[destination_index];
	result->numeric = destination->numeric;
	result->numeric_address = destination->numeric_address;
	result->port = destination->port;
	result->query_name = destination->query_name;
	result->srv = destination->srv;
	return true;
}

void route_table_destroy(route_table *table) {
	if (table == NULL) {
		return;
	}
	for (size_t destination_index = 0; destination_index < table->destination_count; destination_index++) {
		free(table->destinations[destination_index].query_name);
	}
	for (size_t route_index = 0; route_index < table->route_count; route_index++) {
		free(table->routes[route_index].configured_address);
		free(table->routes[route_index].vhost);
	}
	free(table->destinations);
	free(table->routes);
	free(table);
}

bool route_table_find(const route_table *table, const char *vhost, route_view *result) {
	if (table == NULL || vhost == NULL || result == NULL) {
		return false;
	}
	for (size_t route_index = 0; route_index < table->route_count; route_index++) {
		if (route_vhost_matches(table->routes[route_index].vhost, vhost)) {
			return route_table_route_get(table, route_index, result);
		}
	}
	return false;
}

size_t route_table_route_count(const route_table *table) {
	return table == NULL ? 0 : table->route_count;
}

bool route_table_route_get(const route_table *table, size_t route_index, route_view *result) {
	if (table == NULL || route_index >= table->route_count || result == NULL) {
		return false;
	}
	const route_entry *route = &table->routes[route_index];
	result->configured_address = route->configured_address;
	result->destination_index = route->destination_index;
	result->pheader = route->pheader;
	result->rewrite = route->rewrite;
	result->vhost = route->vhost;
	return true;
}
