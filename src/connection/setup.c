/*
 * connection/setup.c: Shared connection setup types and helpers
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* section: headers (self) */
#include "setup.h"

/* section: functions (exported) */
bool connection_setup_address_valid(const net_addr *address) {
	return address != NULL && address->err == NET_OK && (address->family == AF_INET || address->family == AF_INET6);
}

bool connection_setup_bundle_valid(const net_addrbundle *address) {
	if (address == NULL || (address->family != AF_INET && address->family != AF_INET6) || address->port == 0
		|| memchr(&address->address, '\0', sizeof(address->address)) == NULL || memchr(&address->address_clean, '\0', sizeof(address->address_clean)) == NULL) {
		return false;
	}
	return true;
}

const char *connection_setup_destination(const route_endpoint_snapshot *endpoint) {
	if (endpoint == NULL) {
		return NULL;
	}
	return endpoint->target_name[0] == '\0' ? endpoint->configured_address : endpoint->target_name;
}

bool connection_setup_snapshot_valid(const connection_setup_snapshot *snapshot) {
	return snapshot != NULL && memchr(snapshot->icon_b64, '\0', sizeof(snapshot->icon_b64)) != NULL
		&& memchr(snapshot->log_filename, '\0', sizeof(snapshot->log_filename)) != NULL
		&& snapshot->route_status >= CONNECTION_SETUP_ROUTE_BYPASS && snapshot->route_status <= CONNECTION_SETUP_ROUTE_UNAVAILABLE;
}
