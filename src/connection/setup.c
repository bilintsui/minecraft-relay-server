/*
 * connection/setup.c: Shared connection setup types and helpers
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* section: headers (self) */
#include "setup.h"

/* section: functions (local) */
static bool connection_proxy_provenance_valid(const connection_proxy_provenance *proxy) {
	return proxy != NULL && proxy->origin >= CONNECTION_PROXY_DIRECT && proxy->origin <= CONNECTION_PROXY_UNKNOWN && memchr(&proxy->peer, '\0', sizeof(proxy->peer)) != NULL;
}

/* section: functions (exported) */
bool connection_setup_address_valid(const net_addr *address) {
	return address != NULL && address->err == NET_OK && (address->family == AF_INET || address->family == AF_INET6);
}

bool connection_setup_bundle_valid(const net_addrbundle *address) {
	if (address == NULL || (address->family != AF_INET && address->family != AF_INET6)
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

void connection_setup_log_access(const connection_setup_snapshot *snapshot, mksys_level level, const net_addrbundle *source, const char *format, ...) {
	if (snapshot == NULL || level > snapshot->log_level || format == NULL || memchr(snapshot->log_filename, '\0', sizeof(snapshot->log_filename)) == NULL) {
		return;
	}
	char details[BUFSIZ];
	va_list args;
	va_start(args, format);
	int size = vsnprintf(details, sizeof(details), format, args);
	va_end(args);
	if (size >= 0) {
		connection_setup_log_record(snapshot->log_filename, snapshot->log_level, level, &snapshot->proxy, source, details);
	}
}

void connection_setup_log_record(const char *filename, uint8_t maxlevel, mksys_level level, const connection_proxy_provenance *proxy, const net_addrbundle *source, const char *details) {
	static const char *const outcomes[] = {
		[CONNECTION_PROXY_TRUSTED] = "accepted_trusted",
		[CONNECTION_PROXY_UNTRUSTED_ACCEPT] = "accepted_untrusted",
		[CONNECTION_PROXY_UNTRUSTED_IGNORE] = "ignored_untrusted",
		[CONNECTION_PROXY_UNKNOWN] = "unknown"
	};
	if (filename == NULL || level > maxlevel || !connection_proxy_provenance_valid(proxy) || !connection_setup_bundle_valid(source) || details == NULL) {
		return;
	}
	if (proxy->origin == CONNECTION_PROXY_DIRECT) {
		MKSYS_LOG(filename, maxlevel, level, "src: %s:%u, %s", source->address.v6, source->port, details);
	} else {
		MKSYS_LOG(filename, maxlevel, level, "peer: %s:%u, proxy: %s, src: %s:%u, %s", proxy->peer.v6, proxy->peer_port, outcomes[proxy->origin], source->address.v6, source->port, details);
	}
}

bool connection_setup_snapshot_valid(const connection_setup_snapshot *snapshot) {
	return snapshot != NULL && memchr(snapshot->icon_b64, '\0', sizeof(snapshot->icon_b64)) != NULL
		&& memchr(snapshot->log_filename, '\0', sizeof(snapshot->log_filename)) != NULL
		&& connection_proxy_provenance_valid(&snapshot->proxy)
		&& snapshot->route_status >= CONNECTION_SETUP_ROUTE_BYPASS && snapshot->route_status <= CONNECTION_SETUP_ROUTE_UNAVAILABLE;
}
