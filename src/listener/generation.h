/*
 * listener/generation.h: Listener route generation preparation, publication and ownership
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_GENERATION_H_INCLUDED_

#define _MRS_LISTENER_GENERATION_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <time.h>

/* section: headers (project) */
#include "../config.h"
#include "../log.h"
#include "../resolver/hosts.h"
#include "../route/generation.h"
#include "../route/generation_registry.h"

/* section: defines */
#ifndef LISTENER_HOSTS_FILENAME
#define LISTENER_HOSTS_FILENAME	"/etc/hosts"
#endif

/* section: types */
struct listener_context;
typedef enum {
	LISTENER_ROUTE_PREPARE_OK,
	LISTENER_ROUTE_PREPARE_CANDIDATE_ERROR,
	LISTENER_ROUTE_PREPARE_TIME_ERROR
} listener_route_prepare_status;

/* section: functions (exported) */
bool listener_generation_collect(struct listener_context *context, const struct timespec *now);
void listener_generation_destroy(struct listener_context *context);
void listener_generation_dispose_in_child(struct listener_context *context);
bool listener_generation_initial_publish(struct listener_context *context);
listener_route_prepare_status listener_generation_prepare(struct listener_context *context, conf **config, hosts_table **hosts, mksys_level failure_level,
	const char *failure_action, route_generation **result);
route_generation_registry_publish_status listener_generation_publish(struct listener_context *context, route_generation **candidate);
const char *listener_generation_publish_error(route_generation_registry_publish_status status);
bool listener_hosts_prepare(struct listener_context *context, mksys_level failure_level, const char *failure_action, hosts_table **result);

#endif
