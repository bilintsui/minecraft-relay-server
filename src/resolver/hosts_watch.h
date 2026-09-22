/*
 * resolver/hosts_watch.h: Local static host-name table file monitoring
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_RESOLVER_HOSTS_WATCH_H_INCLUDED_

#define _MRS_RESOLVER_HOSTS_WATCH_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>

/* section: types */
typedef struct hosts_watch hosts_watch;
typedef enum {
	HOSTS_WATCH_CREATE_OK,
	HOSTS_WATCH_CREATE_IO,
	HOSTS_WATCH_CREATE_MEMORY,
	HOSTS_WATCH_CREATE_BAD_ARGUMENT
} hosts_watch_create_status;
typedef struct {
	bool changed;
	bool refresh;
} hosts_watch_events;
typedef enum {
	HOSTS_WATCH_READ_OK,
	HOSTS_WATCH_READ_IO,
	HOSTS_WATCH_READ_BAD_ARGUMENT
} hosts_watch_read_status;

/* section: functions (exported) */
hosts_watch_create_status hosts_watch_create(const char *filename, hosts_watch **result);
int hosts_watch_descriptor(const hosts_watch *watch);
void hosts_watch_destroy(hosts_watch *watch);
hosts_watch_read_status hosts_watch_read(hosts_watch *watch, hosts_watch_events *events);

#endif
