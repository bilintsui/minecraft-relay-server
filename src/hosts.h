/*
 * hosts.h: Local static host-name table
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_HOSTS_H_INCLUDED_

#define _MRS_HOSTS_H_INCLUDED_

/* section: headers (library) */
#include <stddef.h>

/* section: headers (project) */
#include "network.h"

/* section: types */
typedef struct {
	net_addr *addresses;
	size_t address_count;
} hosts_address_result;
typedef enum {
	HOSTS_LOAD_OK,
	HOSTS_LOAD_FILE_ERROR,
	HOSTS_LOAD_LIMIT,
	HOSTS_LOAD_MEMORY,
	HOSTS_LOAD_BAD_ARGUMENT
} hosts_load_status;
typedef enum {
	HOSTS_LOOKUP_OK,
	HOSTS_LOOKUP_NOT_FOUND,
	HOSTS_LOOKUP_MEMORY,
	HOSTS_LOOKUP_BAD_ARGUMENT
} hosts_lookup_status;
typedef struct hosts_table hosts_table;

/* section: functions (exported) */
void hosts_address_result_destroy(hosts_address_result *result);
void hosts_table_destroy(hosts_table *table);
/* HOSTS_LOAD_FILE_ERROR returns a usable table containing guaranteed localhost fallbacks. */
hosts_load_status hosts_table_load(const char *filename, hosts_table **result, size_t *malformed_line_count);
hosts_lookup_status hosts_table_lookup(const hosts_table *table, const char *hostname, hosts_address_result *result);

#endif
