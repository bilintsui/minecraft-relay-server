/*
 * listener/context.h: Shared state for listener runtime coordination
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_CONTEXT_H_INCLUDED_

#define _MRS_LISTENER_CONTEXT_H_INCLUDED_

/* section: headers (library) */
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/* section: headers (project) */
#include "../config.h"
#include "../log.h"
#include "../resolver/cache.h"
#include "../resolver/hosts.h"
#include "../resolver/supervisor.h"
#include "../route/bindings.h"
#include "../route/generation_registry.h"
#include "../route/resolution.h"
#include "../route/table.h"
#include "metrics.h"

/* section: defines */
#ifndef LISTENER_WORKER_LIMIT
#define LISTENER_WORKER_LIMIT	256
#endif
#if LISTENER_WORKER_LIMIT < 1
#error "LISTENER_WORKER_LIMIT must be positive"
#endif

/* logging macro */
#define LISTENER_LOG(ctx, lvl, ...)	MKSYS_LOG((ctx)->log_filename, (ctx)->config->log.level, lvl, __VA_ARGS__)
#define LISTENER_LOG_TERMINAL(ctx, lvl, ...)	MKSYS_LOG(MKSYS_NOLOGFILE, (ctx)->config->log.level, lvl, __VA_ARGS__)

/* section: types */
typedef struct {
	size_t count;
	bool refusal_logged;
	struct timespec refusal_logged_at;
	pid_t pids[LISTENER_WORKER_LIMIT];
} listener_workers;
typedef struct listener_context {
	conf *config;
	conf_cache *config_cache;
	const char *config_filename;
	const char *config_filename_full;
	resolver_cache *dns_cache;
	uint64_t generation_next_identity;
	route_generation_registry *generations;
	hosts_table *hosts;
	char log_filename[PATH_MAX];
	listener_metrics_state metrics;
	listener_metrics_runtime metrics_runtime;
	resolver_supervisor *resolver;
	route_bindings *route_bindings;
	route_resolution *route_resolution;
	route_table *routes;
	const char *working_directory;
	listener_workers workers;
} listener_context;

#endif
