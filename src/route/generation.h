/*
 * route/generation.h: Header file of route/generation.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_ROUTE_GENERATION_H_INCLUDED_

#define _MRS_ROUTE_GENERATION_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "../config.h"
#include "../resolver/hosts.h"
#include "bindings.h"
#include "resolution.h"
#include "table.h"

/* section: types */
typedef struct route_generation route_generation;
typedef enum {
	ROUTE_GENERATION_CREATE_OK,
	ROUTE_GENERATION_CREATE_BAD_ARGUMENT,
	ROUTE_GENERATION_CREATE_MEMORY
} route_generation_create_status;

/* section: functions (exported) */
const route_bindings *route_generation_bindings(const route_generation *generation);
const conf *route_generation_config(const route_generation *generation);
/* Ownership of every component transfers only when creation succeeds. The listener-owned resolver cache must outlive the returned generation. */
route_generation_create_status route_generation_create(uint64_t identity, conf *config, hosts_table *hosts, route_table *routes, route_bindings *bindings,
	route_resolution *resolution, route_generation **result);
/* Use only in a forked non-listener child. This destroys the child's private COW copy regardless of its inherited reference count. */
void route_generation_dispose_in_child(route_generation *generation);
const hosts_table *route_generation_hosts(const route_generation *generation);
uint64_t route_generation_identity(const route_generation *generation);
size_t route_generation_reference_count(const route_generation *generation);
/* Returns the remaining reference count. A zero return means the generation was destroyed or the argument was invalid. */
size_t route_generation_release(route_generation *generation);
route_resolution *route_generation_resolution(route_generation *generation);
bool route_generation_retain(route_generation *generation);
const route_table *route_generation_routes(const route_generation *generation);

#endif
