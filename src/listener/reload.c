/*
 * listener/reload.c: Configuration and local hosts reloads
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "../basic.h"
#include "../config.h"
#include "../log.h"
#include "../network.h"
#include "../resolver/hosts.h"
#include "../resolver/hosts_watch.h"
#include "context.h"
#include "events.h"
#include "generation.h"
#include "metrics.h"
#include "metrics_runtime.h"
#include "socket.h"

/* section: headers (self) */
#include "reload.h"

/* section: functions (local) */
static int listener_hosts_watch_establish(listener_context *context, listener_events *events, bool *overlap_changed) {
	int status = listener_events_hosts_watch_establish(events, LISTENER_HOSTS_FILENAME, overlap_changed);
	if (status == 1) {
		LISTENER_LOG(context, MKSYS_LEVEL_INFORMATION, "Automatic monitoring for local static host table %s restored.", LISTENER_HOSTS_FILENAME);
	}
	return status;
}

static void listener_reload_config_error(const char *config_filename, const char *log_filename, uint8_t log_level) {
	switch (errno) {
		case CONF_ECFIELD:
			/* The field diagnostic was written to the active log during validation. */
			break;
		case CONF_EROPENFAIL:
		case CONF_EROPENEMPTY:
		case CONF_EROPENLARGE:
		case CONF_ERMEMORY:
		case CONF_ERPARSE:
		case CONF_ECMEMORY:
		case CONF_ECLISTENPORT:
		case CONF_ECMETRICS:
		case CONF_ECPROXY:
			MKSYS_LOG(log_filename, log_level, MKSYS_LEVEL_WARNING,
				"%s%s%s",
				config_errmsg((conf_error)errno),
				(errno == CONF_EROPENFAIL || errno == CONF_EROPENEMPTY) ? config_filename : "", ", will keep your old configurations"
			);
			break;
		case CONF_ECPROXYDUP:
			config_log_duplicate_error(log_filename, log_level, MKSYS_LEVEL_WARNING, ", will keep your old configurations");
			break;
		default:
			MKSYS_LOG(log_filename, log_level, MKSYS_LEVEL_WARNING,
				"Error in processing configurations: Unknown error occurred, code: %d, will keep your old configurations",
				errno
			);
			break;
	}
}

static listener_socket_replace_status listener_reload_endpoint_activate(listener_socket *listener, const listener_endpoint *candidate, listener_events *events, const char *log_filename, uint8_t log_level) {
	if (listener_endpoint_equal(&listener->endpoint, candidate)) {
		return LISTENER_SOCKET_REPLACE_OK;
	}
	net_addrp candidate_address = net_ntop(candidate->address.family, &(candidate->address.addr), true);
	listener_socket_replace_status replace_status = listener_socket_replace(listener, candidate, events);
	if (replace_status == LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR) {
		MKSYS_LOG(log_filename, log_level, MKSYS_LEVEL_WARNING,
			"Cannot activate candidate listening endpoint %s:%d, will keep your old configurations.",
			(char *)&candidate_address, candidate->port
		);
		return replace_status;
	}
	if (replace_status == LISTENER_SOCKET_REPLACE_ACTIVE_ERROR) {
		MKSYS_LOG(log_filename, log_level, MKSYS_LEVEL_CRITICAL,
			"Cannot replace active listening socket: %s",
			strerror(errno)
		);
		return replace_status;
	}
	if (replace_status == LISTENER_SOCKET_REPLACE_ROLLBACK_ERROR) {
		MKSYS_LOG(log_filename, log_level, MKSYS_LEVEL_CRITICAL,
			"Cannot activate candidate listening endpoint %s:%d or restore the active listening socket.",
			(char *)&candidate_address, candidate->port
		);
		return replace_status;
	}
	MKSYS_LOG(log_filename, log_level, MKSYS_LEVEL_INFORMATION,
		"Listening endpoint changed to %s:%d.",
		(char *)&candidate_address, candidate->port
	);
	return replace_status;
}

static void listener_reload_metrics_snapshot(listener_context *context, listener_metrics_output_reason reason, const char *log_filename, uint8_t log_level) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
		listener_metrics_snapshot_output(context, reason, log_filename, log_level, &now);
	} else {
		listener_metrics_format_drop_record(&context->metrics_runtime);
	}
}

/* section: functions (exported) */
int listener_hosts_reload(listener_context *context) {
	conf *config_candidate = NULL;
	hosts_table *hosts_candidate = NULL;
	route_generation *generation_candidate = NULL;
	int result = 0;
	if (!listener_hosts_prepare(context, MKSYS_LEVEL_WARNING, ", keeping the existing table", &hosts_candidate)) {
		return 0;
	}
	if (!config_clone(context->config, &config_candidate)) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
			"Cannot clone the active configuration for an automatic local static host table reload, keeping the existing generation."
		);
		goto cleanup;
	}
	listener_route_prepare_status prepare_status = listener_generation_prepare(context, &config_candidate, &hosts_candidate, MKSYS_LEVEL_WARNING,
		", keeping the existing generation", &generation_candidate);
	if (prepare_status == LISTENER_ROUTE_PREPARE_TIME_ERROR) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
			"Cannot sample the monotonic clock while preparing automatic local static host route resolution: %s",
			strerror(errno)
		);
		result = -1;
		goto cleanup;
	}
	if (prepare_status != LISTENER_ROUTE_PREPARE_OK) {
		goto cleanup;
	}
	route_generation_registry_publish_status publish_status = listener_generation_publish(context, &generation_candidate);
	if (publish_status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL,
			"Cannot publish the automatically reloaded local static host route generation: %s.",
			listener_generation_publish_error(publish_status)
		);
		result = -1;
		goto cleanup;
	}
	LISTENER_LOG(context, MKSYS_LEVEL_INFORMATION,
		"Local static host table reloaded automatically."
	);

cleanup:
	config_destroy(config_candidate);
	hosts_table_destroy(hosts_candidate);
	route_generation_release(generation_candidate);
	return result;
}

bool listener_hosts_watch_process(listener_context *context, listener_events *events, bool failed, bool ready) {
	bool changed = failed;
	bool refresh = failed;
	if (ready) {
		hosts_watch_events watch_events;
		hosts_watch_read_status status = listener_events_hosts_watch_read(events, &watch_events);
		if (status == HOSTS_WATCH_READ_OK) {
			changed = changed || watch_events.changed;
			refresh = refresh || watch_events.refresh;
		} else {
			int saved_errno = errno;
			changed = true;
			refresh = true;
			LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
				"Cannot consume local static host table monitor events: %s; the latest table will still be reloaded.",
				strerror(saved_errno)
			);
		}
	}
	if (refresh) {
		bool overlap_changed = false;
		int status = listener_hosts_watch_establish(context, events, &overlap_changed);
		if (status == -1) {
			int saved_errno = errno;
			listener_events_hosts_watch_disable(events);
			LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
				"Cannot refresh automatic monitoring for local static host table %s: %s; SIGUSR1 reload remains available.",
				LISTENER_HOSTS_FILENAME, strerror(saved_errno)
			);
		}
		changed = changed || overlap_changed;
	}
	return changed;
}

void listener_hosts_watch_retry(listener_context *context, listener_events *events) {
	int status = listener_hosts_watch_establish(context, events, NULL);
	if (status == -1) {
		int saved_errno = errno;
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
			"Cannot monitor local static host table %s automatically: %s; SIGUSR1 reload remains available.",
			LISTENER_HOSTS_FILENAME, strerror(saved_errno)
		);
	}
}

int listener_reload(listener_context *context, listener_socket *listener, listener_events *events, bool *metrics_readiness_invalidated) {
	uint8_t config_maxlevel = context->config->log.level;
	bool metrics_effective_old = listener_metrics_effectively_enabled(context->config);
	uint32_t metrics_interval_old = context->config->metrics.interval;
	int result = 0;
	*metrics_readiness_invalidated = false;
	char config_logfull_old[PATH_MAX];
	snprintf(config_logfull_old, sizeof(config_logfull_old), "%s", context->log_filename);
	MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
		"Reloading config from file: %s",
		context->config_filename
	);
	hosts_table *hosts_candidate = NULL;
	bool hosts_prepared = listener_hosts_prepare(context, MKSYS_LEVEL_WARNING, ", keeping the existing table", &hosts_candidate);
	conf_cache config_cache_candidate = { 0 };
	conf *config_candidate = NULL;
	route_generation *generation_candidate = NULL;
	bool primary_published = false;
	conf_read_status read_status = config_read_with_log(context->config_filename_full, context->config_cache, &config_cache_candidate, &config_candidate, config_logfull_old, config_maxlevel);
	switch (read_status) {
		case CONF_READ_CHANGED: {
			listener_endpoint candidate_endpoint;
			listener_endpoint_status endpoint_status = listener_endpoint_prepare(config_candidate, &candidate_endpoint);
			if (endpoint_status == LISTENER_ENDPOINT_BAD_ADDRESS) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Error in configurations: Invalid candidate bind address, will keep your old configurations."
				);
				break;
			}
			if (endpoint_status == LISTENER_ENDPOINT_BAD_PORT) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Error in configurations: Invalid candidate bind port, will keep your old configurations."
				);
				break;
			}
			char config_logfull_candidate[PATH_MAX];
			resolve_path(config_candidate->log.filename, context->working_directory, config_logfull_candidate, sizeof(config_logfull_candidate));
			if (log_file_validate(config_logfull_candidate) == -1) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Cannot write candidate log to \"%s\", will keep your old configurations.",
					config_candidate->log.filename
				);
				break;
			}
			if (!config_icon_load(config_candidate, config_logfull_old, config_maxlevel, "will keep your old configurations")) {
				break;
			}
			if (hosts_candidate == NULL && !hosts_table_clone(context->hosts, &hosts_candidate)) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Cannot clone the existing local static host table for the candidate generation, will keep your old configurations."
				);
				break;
			}
			listener_route_prepare_status prepare_status = listener_generation_prepare(context, &config_candidate, &hosts_candidate, MKSYS_LEVEL_WARNING,
				", will keep your old configurations", &generation_candidate);
			if (prepare_status == LISTENER_ROUTE_PREPARE_TIME_ERROR) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
					"Cannot sample the monotonic clock while preparing candidate proxy route resolution: %s",
					strerror(errno)
				);
				result = -1;
				break;
			}
			if (prepare_status != LISTENER_ROUTE_PREPARE_OK) {
				break;
			}
			listener_socket_replace_status replace_status = listener_reload_endpoint_activate(listener, &candidate_endpoint, events, config_logfull_old, config_maxlevel);
			if (replace_status != LISTENER_SOCKET_REPLACE_OK) {
				result = replace_status == LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR ? 0 : -1;
				break;
			}
			route_generation_registry_publish_status publish_status = listener_generation_publish(context, &generation_candidate);
			if (publish_status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
					"Cannot publish the prepared proxy route generation: %s.",
					listener_generation_publish_error(publish_status)
				);
				result = -1;
				break;
			}
			bool metrics_effective_new = listener_metrics_effectively_enabled(context->config);
			bool metrics_transition = metrics_effective_old != metrics_effective_new
				|| (metrics_effective_new && metrics_interval_old != context->config->metrics.interval);
			*metrics_readiness_invalidated = metrics_transition;
			if (metrics_effective_old && !metrics_effective_new) {
				listener_reload_metrics_snapshot(context, LISTENER_METRICS_OUTPUT_DISABLE, config_logfull_old, config_maxlevel);
				listener_metrics_timer_set(context, events, 0, config_logfull_old, config_maxlevel);
			}
			snprintf(context->log_filename, sizeof(context->log_filename), "%s", config_logfull_candidate);
			config_cache_commit(context->config_cache, &config_cache_candidate);
			primary_published = true;
			if (metrics_effective_new && metrics_transition) {
				listener_metrics_timer_set(context, events, context->config->metrics.interval, context->log_filename, context->config->log.level);
				listener_reload_metrics_snapshot(context, LISTENER_METRICS_OUTPUT_RECONFIGURE, context->log_filename, context->config->log.level);
			} else if (metrics_effective_new && listener_events_metrics_timer_needs_retry(events)) {
				listener_metrics_timer_set(context, events, context->config->metrics.interval, context->log_filename, context->config->log.level);
			}
			MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
				"Configuration reloaded."
			);
			break;
		}
		case CONF_READ_UNCHANGED:
			MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
				"Configuration file unchanged."
			);
			break;
		case CONF_READ_ERROR:
			listener_reload_config_error(context->config_filename, config_logfull_old, config_maxlevel);
			break;
	}
	if (generation_candidate != NULL) {
		if (result == 0 && hosts_prepared && hosts_candidate == NULL && !hosts_table_clone(route_generation_hosts(generation_candidate), &hosts_candidate)) {
			MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Cannot preserve the candidate local static host table after route-generation activation failed."
			);
		}
		route_generation_release(generation_candidate);
		generation_candidate = NULL;
	}
	config_destroy(config_candidate);
	config_candidate = NULL;
	if (result == 0 && !primary_published && ((hosts_prepared && hosts_candidate != NULL) || read_status == CONF_READ_UNCHANGED)) {
		bool publish_hosts = hosts_prepared && hosts_candidate != NULL;
		if (!config_clone(context->config, &config_candidate)) {
			MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Cannot clone the active configuration for a replacement route generation, keeping the existing generation."
			);
		} else if (hosts_candidate == NULL && !hosts_table_clone(context->hosts, &hosts_candidate)) {
			MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Cannot clone the active local static host table for a replacement route generation, keeping the existing generation."
			);
		} else {
			if (read_status == CONF_READ_UNCHANGED) {
				config_icon_load(config_candidate, config_logfull_old, config_maxlevel, "keeping existing icon");
			}
			listener_route_prepare_status prepare_status = listener_generation_prepare(context, &config_candidate, &hosts_candidate, MKSYS_LEVEL_WARNING,
				", keeping the existing generation", &generation_candidate);
			if (prepare_status == LISTENER_ROUTE_PREPARE_TIME_ERROR) {
				MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
					"Cannot sample the monotonic clock while preparing local static host route resolution: %s",
					strerror(errno)
				);
				result = -1;
			} else if (prepare_status == LISTENER_ROUTE_PREPARE_OK) {
				route_generation_registry_publish_status publish_status = listener_generation_publish(context, &generation_candidate);
				if (publish_status != ROUTE_GENERATION_REGISTRY_PUBLISH_OK) {
					MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
						"Cannot publish the replacement proxy route generation: %s.",
						listener_generation_publish_error(publish_status)
					);
					result = -1;
				} else if (publish_hosts) {
					MKSYS_LOG(config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
						"Local static host table reloaded."
					);
				}
			}
		}
	}
	if (result == 0 && read_status == CONF_READ_UNCHANGED && metrics_effective_old && listener_events_metrics_timer_needs_retry(events)) {
		listener_metrics_timer_set(context, events, metrics_interval_old, config_logfull_old, config_maxlevel);
	}
	route_generation_release(generation_candidate);
	config_destroy(config_candidate);
	config_cache_destroy(&config_cache_candidate);
	hosts_table_destroy(hosts_candidate);
	return result;
}
