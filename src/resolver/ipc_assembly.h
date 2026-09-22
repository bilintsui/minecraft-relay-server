/*
 * resolver/ipc_assembly.h: Header file of resolver/ipc_assembly.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_RESOLVER_IPC_ASSEMBLY_H_INCLUDED_

#define _MRS_RESOLVER_IPC_ASSEMBLY_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* section: headers (project) */
#include "../metrics.h"
#include "dns.h"
#include "ipc.h"

/* section: defines */
/* capacity */
#ifndef RESOLVER_REPLY_ASSEMBLY_BYTE_LIMIT
#define RESOLVER_REPLY_ASSEMBLY_BYTE_LIMIT	(1024U * 1024U)
#endif

/* section: types */
typedef struct resolver_ipc_assembly resolver_ipc_assembly;
typedef struct resolver_ipc_assembly_budget resolver_ipc_assembly_budget;
typedef struct {
	uint64_t create_ok;
	uint64_t create_bad_argument;
	uint64_t create_limit;
	uint64_t create_memory;
	uint64_t limit_result_shape;
	uint64_t limit_result_bytes;
	uint64_t limit_budget_bytes;
	uint64_t terminal_complete;
	uint64_t terminal_bad_argument;
	uint64_t terminal_limit;
	uint64_t terminal_memory;
	uint64_t terminal_protocol;
	uint64_t abandoned;
	uint64_t nonterminal_current;
} resolver_ipc_assembly_metrics_query;
typedef struct {
	uint64_t nonterminal_current;
	uint64_t owned_bytes_current;
	uint64_t owned_bytes_high_water;
	resolver_ipc_assembly_metrics_query query[METRICS_RESOLVER_QUERY_TYPE_COUNT];
	metrics_histogram_snapshot result_size[METRICS_RESOLVER_QUERY_TYPE_COUNT];
	uint64_t saturation_total;
} resolver_ipc_assembly_metrics_snapshot;
typedef union {
	dns_address_result address;
	dns_srv_result srv;
} resolver_ipc_assembly_payload;
typedef struct {
	resolver_ipc_assembly_budget *budget;
	struct timespec completed_at;
	size_t dynamic_bytes;
	resolver_ipc_assembly_payload payload;
	uint64_t query_id;
	uint16_t query_type;
	resolver_ipc_lookup_status status;
} resolver_ipc_assembly_result;
typedef enum {
	RESOLVER_IPC_ASSEMBLY_OK,
	RESOLVER_IPC_ASSEMBLY_COMPLETE,
	RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT,
	RESOLVER_IPC_ASSEMBLY_LIMIT,
	RESOLVER_IPC_ASSEMBLY_MEMORY,
	RESOLVER_IPC_ASSEMBLY_PROTOCOL
} resolver_ipc_assembly_status;

/* section: functions (exported) */
resolver_ipc_assembly_budget *resolver_ipc_assembly_budget_create(void);
void resolver_ipc_assembly_budget_destroy(resolver_ipc_assembly_budget *budget);
resolver_ipc_assembly_status resolver_ipc_assembly_create(resolver_ipc_assembly_budget *budget, const char *query_name, uint16_t query_class, uint16_t query_type, uint64_t query_id,
	resolver_ipc_assembly **result);
void resolver_ipc_assembly_destroy(resolver_ipc_assembly *assembly);
bool resolver_ipc_assembly_metrics_get(const resolver_ipc_assembly_budget *budget, resolver_ipc_assembly_metrics_snapshot *result);
resolver_ipc_assembly_status resolver_ipc_assembly_packet_consume(resolver_ipc_assembly *assembly, const void *packet, size_t packet_size);
/* Destroy transferred results before their assembly budget. The result object owns both its payload and its remaining assembly-budget charge. */
void resolver_ipc_assembly_result_destroy(resolver_ipc_assembly_result *result);
/* Results passed to result_take must be zero-initialized or previously destroyed. */
bool resolver_ipc_assembly_result_take(resolver_ipc_assembly *assembly, resolver_ipc_assembly_result *result);

#endif
