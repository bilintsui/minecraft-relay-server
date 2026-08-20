/*
 * route_table.h: Immutable prepared proxy route table
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_ROUTE_TABLE_H_INCLUDED_

#define _MRS_ROUTE_TABLE_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>

/* section: headers (project) */
#include "config.h"
#include "network.h"

/* section: types */
typedef struct {
	bool numeric;
	net_addr numeric_address;
	in_port_t port;
	const char *query_name;
	bool srv;
} route_destination_view;
typedef struct route_table route_table;
typedef enum {
	ROUTE_TABLE_BUILD_OK,
	ROUTE_TABLE_BUILD_BAD_ARGUMENT,
	ROUTE_TABLE_BUILD_INVALID,
	ROUTE_TABLE_BUILD_MEMORY
} route_table_build_status;
typedef struct {
	const char *configured_address;
	size_t destination_index;
	bool pheader;
	bool rewrite;
	const char *vhost;
} route_view;

/* section: functions (exported) */
route_table_build_status route_table_build(const conf *source, route_table **result);
size_t route_table_destination_count(const route_table *table);
bool route_table_destination_get(const route_table *table, size_t destination_index, route_destination_view *result);
void route_table_destroy(route_table *table);
bool route_table_find(const route_table *table, const char *vhost, route_view *result);
size_t route_table_route_count(const route_table *table);
bool route_table_route_get(const route_table *table, size_t route_index, route_view *result);

#endif
