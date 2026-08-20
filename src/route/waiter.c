/*
 * route/waiter.c: Per-connection asynchronous route resolution waiters
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "../define/global.h"
#include "../protocol/proxy.h"
#include "../resolver/cache.h"
#include "../resolver/dns.h"
#include "../resolver/ipc.h"
#include "../resolver/supervisor.h"
#include "endpoint.h"
#include "generation.h"

/* section: headers (self) */
#include "waiter.h"

/* section: defines */
/* bounded synchronous reevaluation */
#define ROUTE_WAITER_PROGRESS_ITERATION_LIMIT	8

/* section: types */
typedef struct {
	bool completion_pending;
	resolver_cache_entry *entry;
	bool interest;
	route_endpoint_overlay overlay;
} route_waiter_entry;
struct route_waiter {
	struct timespec deadline;
	route_waiter_entry entries[ROUTE_ENDPOINT_REQUIREMENT_LIMIT];
	route_generation *generation;
	p_proxy inbound_proxy;
	route_endpoint_snapshot snapshot;
	bool snapshot_taken;
	route_waiter_status status;
	char vhost[ROUTE_ENDPOINT_TEXT_SIZE];
};

/* section: functions (local) */
static int route_waiter_time_compare(const struct timespec *left, const struct timespec *right) {
	if (left->tv_sec != right->tv_sec) {
		return left->tv_sec < right->tv_sec ? -1 : 1;
	}
	if (left->tv_nsec != right->tv_nsec) {
		return left->tv_nsec < right->tv_nsec ? -1 : 1;
	}
	return 0;
}

static bool route_waiter_time_valid(const struct timespec *value) {
	return value != NULL && value->tv_sec >= 0 && value->tv_nsec >= 0 && value->tv_nsec < 1000000000L;
}

static bool route_waiter_time_add_seconds(const struct timespec *source, uint64_t seconds, struct timespec *result) {
	if (!route_waiter_time_valid(source) || result == NULL || (uintmax_t)source->tv_sec > UINTMAX_MAX - seconds) {
		return false;
	}
	uintmax_t combined = (uintmax_t)source->tv_sec + seconds;
	result->tv_sec = (time_t)combined;
	if ((uintmax_t)result->tv_sec != combined) {
		return false;
	}
	result->tv_nsec = source->tv_nsec;
	return true;
}

static void route_waiter_entry_overlay_clear(route_waiter_entry *entry) {
	free((void *)entry->overlay.addresses);
	free((void *)entry->overlay.srv_records);
	memset(&entry->overlay, 0, sizeof(entry->overlay));
	entry->overlay.entry = entry->entry;
}

static bool route_waiter_entry_clear(route_waiter_entry *entry, resolver_supervisor *supervisor, const struct timespec *now) {
	bool result = true;
	if (entry->interest) {
		result = supervisor != NULL && route_waiter_time_valid(now) && resolver_supervisor_entry_interactive_release(supervisor, entry->entry, now);
		entry->interest = false;
	}
	route_waiter_entry_overlay_clear(entry);
	resolver_cache_entry_release(entry->entry);
	memset(entry, 0, sizeof(*entry));
	return result;
}

static route_waiter_entry *route_waiter_entry_find(route_waiter *waiter, const resolver_cache_entry *entry) {
	for (size_t entry_index = 0; entry_index < ROUTE_ENDPOINT_REQUIREMENT_LIMIT; entry_index++) {
		if (waiter->entries[entry_index].entry == entry) {
			return &waiter->entries[entry_index];
		}
	}
	return NULL;
}

static const route_endpoint_overlay *route_waiter_entry_overlays_link(route_waiter *waiter) {
	const route_endpoint_overlay *head = NULL;
	for (size_t entry_index = ROUTE_ENDPOINT_REQUIREMENT_LIMIT; entry_index > 0; entry_index--) {
		route_waiter_entry *entry = &waiter->entries[entry_index - 1U];
		if (entry->entry == NULL) {
			continue;
		}
		entry->overlay.entry = entry->entry;
		entry->overlay.next = head;
		head = &entry->overlay;
	}
	return head;
}

static bool route_waiter_entries_interests_release(route_waiter *waiter, resolver_supervisor *supervisor, const struct timespec *now) {
	bool result = true;
	for (size_t entry_index = 0; entry_index < ROUTE_ENDPOINT_REQUIREMENT_LIMIT; entry_index++) {
		route_waiter_entry *entry = &waiter->entries[entry_index];
		if (entry->interest) {
			bool released = supervisor != NULL && route_waiter_time_valid(now) && resolver_supervisor_entry_interactive_release(supervisor, entry->entry, now);
			entry->interest = false;
			result = released && result;
		}
	}
	return result;
}

static route_waiter_status route_waiter_entries_reconcile(route_waiter *waiter, const route_endpoint_requirements *requirements, resolver_supervisor *supervisor,
	const struct timespec *now) {
	bool needed[ROUTE_ENDPOINT_REQUIREMENT_LIMIT] = { false };
	for (size_t requirement_index = 0; requirement_index < requirements->count; requirement_index++) {
		route_waiter_entry *existing = route_waiter_entry_find(waiter, requirements->items[requirement_index].entry);
		if (existing != NULL) {
			needed[(size_t)(existing - waiter->entries)] = true;
		}
	}
	for (size_t entry_index = 0; entry_index < ROUTE_ENDPOINT_REQUIREMENT_LIMIT; entry_index++) {
		if (waiter->entries[entry_index].entry != NULL && !needed[entry_index]
			&& !route_waiter_entry_clear(&waiter->entries[entry_index], supervisor, now)) {
			return ROUTE_WAITER_BAD_ARGUMENT;
		}
	}
	for (size_t requirement_index = 0; requirement_index < requirements->count; requirement_index++) {
		resolver_cache_entry *cache_entry = requirements->items[requirement_index].entry;
		if (route_waiter_entry_find(waiter, cache_entry) != NULL) {
			continue;
		}
		route_waiter_entry *available = route_waiter_entry_find(waiter, NULL);
		if (available == NULL || !resolver_cache_entry_retain(cache_entry)) {
			return ROUTE_WAITER_LIMIT;
		}
		available->entry = cache_entry;
		available->overlay.entry = cache_entry;
	}
	return ROUTE_WAITER_PENDING;
}

static route_waiter_status route_waiter_status_from_endpoint(route_endpoint_select_status status) {
	switch (status) {
		case ROUTE_ENDPOINT_SELECT_OK:
			return ROUTE_WAITER_READY;
		case ROUTE_ENDPOINT_SELECT_CONTRADICTORY:
			return ROUTE_WAITER_CONTRADICTORY;
		case ROUTE_ENDPOINT_SELECT_LIMIT:
			return ROUTE_WAITER_LIMIT;
		case ROUTE_ENDPOINT_SELECT_NO_ROUTE:
			return ROUTE_WAITER_NO_ROUTE;
		case ROUTE_ENDPOINT_SELECT_PENDING:
			return ROUTE_WAITER_PENDING;
		case ROUTE_ENDPOINT_SELECT_SERVICE_UNAVAILABLE:
			return ROUTE_WAITER_SERVICE_UNAVAILABLE;
		case ROUTE_ENDPOINT_SELECT_UNAVAILABLE:
			return ROUTE_WAITER_UNAVAILABLE;
		case ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT:
		default:
			return ROUTE_WAITER_BAD_ARGUMENT;
	}
}

static route_waiter_status route_waiter_terminal_set(route_waiter *waiter, route_waiter_status status, resolver_supervisor *supervisor, const struct timespec *now) {
	if (!route_waiter_entries_interests_release(waiter, supervisor, now)) {
		waiter->status = ROUTE_WAITER_BAD_ARGUMENT;
		return waiter->status;
	}
	waiter->status = status;
	return status;
}

/* section: functions (exported) */
route_waiter_completion_status route_waiter_completion_observe(route_waiter *waiter, const resolver_supervisor_completion *completion) {
	if (waiter == NULL || completion == NULL || completion->entry == NULL || !route_waiter_time_valid(&completion->response.completed_at)
		|| completion->response.query_type != resolver_cache_entry_query_type(completion->entry) || completion->response.status < RESOLVER_IPC_LOOKUP_OK
		|| completion->response.status > RESOLVER_IPC_LOOKUP_TRUNCATED || completion->response.status == RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR) {
		return ROUTE_WAITER_COMPLETION_BAD_ARGUMENT;
	}
	switch (completion->publication) {
		case RESOLVER_CACHE_PUBLISH_STORED:
		case RESOLVER_CACHE_PUBLISH_TRANSIENT:
		case RESOLVER_CACHE_PUBLISH_BAD_ARGUMENT:
		case RESOLVER_CACHE_PUBLISH_INVALID:
		case RESOLVER_CACHE_PUBLISH_LIMIT:
		case RESOLVER_CACHE_PUBLISH_MEMORY:
		case RESOLVER_CACHE_PUBLISH_TIME:
			break;
		default:
			return ROUTE_WAITER_COMPLETION_BAD_ARGUMENT;
	}
	route_waiter_entry *entry = route_waiter_entry_find(waiter, completion->entry);
	if (entry == NULL) {
		return ROUTE_WAITER_COMPLETION_IGNORED;
	}
	entry->completion_pending = false;
	entry->interest = false;
	route_waiter_entry_overlay_clear(entry);
	if (route_waiter_time_compare(&completion->response.completed_at, &waiter->deadline) > 0 || completion->publication != RESOLVER_CACHE_PUBLISH_TRANSIENT
		|| completion->response.status != RESOLVER_IPC_LOOKUP_OK) {
		entry->overlay.status = completion->publication == RESOLVER_CACHE_PUBLISH_STORED
			&& route_waiter_time_compare(&completion->response.completed_at, &waiter->deadline) <= 0 ? ROUTE_ENDPOINT_OVERLAY_NONE : ROUTE_ENDPOINT_OVERLAY_UNAVAILABLE;
		return ROUTE_WAITER_COMPLETION_OK;
	}
	uint16_t query_type = completion->response.query_type;
	if (query_type == ns_t_a || query_type == ns_t_aaaa) {
		size_t record_count = completion->response.payload.address.address_count;
		if (record_count == 0 || record_count > DNS_ADDRESS_RECORD_LIMIT || completion->response.payload.address.addresses == NULL
			|| record_count > SIZE_MAX / sizeof(*completion->response.payload.address.addresses)) {
			entry->overlay.status = ROUTE_ENDPOINT_OVERLAY_UNAVAILABLE;
			return ROUTE_WAITER_COMPLETION_BAD_ARGUMENT;
		}
		dns_address_record *records = malloc(record_count * sizeof(*records));
		if (records == NULL) {
			entry->overlay.status = ROUTE_ENDPOINT_OVERLAY_UNAVAILABLE;
			return ROUTE_WAITER_COMPLETION_MEMORY;
		}
		memcpy(records, completion->response.payload.address.addresses, record_count * sizeof(*records));
		entry->overlay.addresses = records;
		entry->overlay.address_count = record_count;
	} else if (query_type == ns_t_srv) {
		size_t record_count = completion->response.payload.srv.record_count;
		if (record_count == 0 || record_count > DNS_SRV_RECORD_LIMIT || completion->response.payload.srv.records == NULL
			|| record_count > SIZE_MAX / sizeof(*completion->response.payload.srv.records)) {
			entry->overlay.status = ROUTE_ENDPOINT_OVERLAY_UNAVAILABLE;
			return ROUTE_WAITER_COMPLETION_BAD_ARGUMENT;
		}
		dns_srv_record *records = malloc(record_count * sizeof(*records));
		if (records == NULL) {
			entry->overlay.status = ROUTE_ENDPOINT_OVERLAY_UNAVAILABLE;
			return ROUTE_WAITER_COMPLETION_MEMORY;
		}
		memcpy(records, completion->response.payload.srv.records, record_count * sizeof(*records));
		entry->overlay.srv_records = records;
		entry->overlay.srv_record_count = record_count;
	} else {
		entry->overlay.status = ROUTE_ENDPOINT_OVERLAY_UNAVAILABLE;
		return ROUTE_WAITER_COMPLETION_BAD_ARGUMENT;
	}
	entry->overlay.status = ROUTE_ENDPOINT_OVERLAY_POSITIVE;
	return ROUTE_WAITER_COMPLETION_OK;
}

route_waiter_create_status route_waiter_create(route_generation *generation, const char *vhost, const p_proxy *inbound_proxy, const struct timespec *now,
	route_waiter **result) {
	if (generation == NULL || vhost == NULL || inbound_proxy == NULL || !route_waiter_time_valid(now) || result == NULL || *result != NULL
		|| LISTENER_ROUTE_WAIT_TIMEOUT_SEC == 0 || (inbound_proxy->family != AF_INET && inbound_proxy->family != AF_INET6)
		|| inbound_proxy->srcaddr.family != inbound_proxy->family || inbound_proxy->dstaddr.family != inbound_proxy->family
		|| inbound_proxy->srcaddr.err != NET_OK || inbound_proxy->dstaddr.err != NET_OK) {
		return ROUTE_WAITER_CREATE_BAD_ARGUMENT;
	}
	size_t vhost_size = strlen(vhost);
	if (vhost_size >= ROUTE_ENDPOINT_TEXT_SIZE) {
		return ROUTE_WAITER_CREATE_LIMIT;
	}
	struct timespec deadline;
	if (!route_waiter_time_add_seconds(now, LISTENER_ROUTE_WAIT_TIMEOUT_SEC, &deadline)) {
		return ROUTE_WAITER_CREATE_TIME;
	}
	route_waiter *waiter = calloc(1, sizeof(*waiter));
	if (waiter == NULL) {
		return ROUTE_WAITER_CREATE_MEMORY;
	}
	if (!route_generation_retain(generation)) {
		free(waiter);
		return ROUTE_WAITER_CREATE_LIMIT;
	}
	waiter->deadline = deadline;
	waiter->generation = generation;
	waiter->inbound_proxy = *inbound_proxy;
	waiter->status = ROUTE_WAITER_PENDING;
	memcpy(waiter->vhost, vhost, vhost_size + 1U);
	*result = waiter;
	return ROUTE_WAITER_CREATE_OK;
}

bool route_waiter_deadline(const route_waiter *waiter, struct timespec *result) {
	if (waiter == NULL || result == NULL) {
		return false;
	}
	*result = waiter->deadline;
	return true;
}

bool route_waiter_destroy(route_waiter *waiter, resolver_supervisor *supervisor, const struct timespec *now) {
	if (waiter == NULL) {
		return true;
	}
	bool result = true;
	for (size_t entry_index = 0; entry_index < ROUTE_ENDPOINT_REQUIREMENT_LIMIT; entry_index++) {
		result = route_waiter_entry_clear(&waiter->entries[entry_index], supervisor, now) && result;
	}
	route_generation_release(waiter->generation);
	free(waiter);
	return result;
}

route_waiter_status route_waiter_progress(route_waiter *waiter, resolver_supervisor *supervisor, const struct timespec *now) {
	if (waiter == NULL || supervisor == NULL || !route_waiter_time_valid(now)) {
		return ROUTE_WAITER_BAD_ARGUMENT;
	}
	if (waiter->status != ROUTE_WAITER_PENDING) {
		return waiter->status;
	}
	for (size_t iteration = 0; iteration < ROUTE_WAITER_PROGRESS_ITERATION_LIMIT; iteration++) {
		route_endpoint_requirements requirements;
		const route_endpoint_overlay *overlays = route_waiter_entry_overlays_link(waiter);
		route_endpoint_select_status endpoint_status = route_endpoint_evaluate(waiter->generation, waiter->vhost, now, &waiter->inbound_proxy, overlays, &requirements,
			&waiter->snapshot);
		route_waiter_status status = route_waiter_status_from_endpoint(endpoint_status);
		if (status != ROUTE_WAITER_PENDING) {
			return route_waiter_terminal_set(waiter, status, supervisor, now);
		}
		status = route_waiter_entries_reconcile(waiter, &requirements, supervisor, now);
		if (status != ROUTE_WAITER_PENDING) {
			return route_waiter_terminal_set(waiter, status, supervisor, now);
		}
		if (route_waiter_time_compare(now, &waiter->deadline) >= 0) {
			return route_waiter_terminal_set(waiter, ROUTE_WAITER_TIMEOUT, supervisor, now);
		}
		bool reevaluate = false;
		for (size_t requirement_index = 0; requirement_index < requirements.count; requirement_index++) {
			if (!requirements.items[requirement_index].pending) {
				continue;
			}
			route_waiter_entry *entry = route_waiter_entry_find(waiter, requirements.items[requirement_index].entry);
			if (entry == NULL) {
				return route_waiter_terminal_set(waiter, ROUTE_WAITER_BAD_ARGUMENT, supervisor, now);
			}
			if (entry->overlay.status != ROUTE_ENDPOINT_OVERLAY_NONE || entry->interest || entry->completion_pending) {
				continue;
			}
			resolver_supervisor_schedule_status schedule_status = resolver_supervisor_entry_schedule_interactive(supervisor, entry->entry, now);
			switch (schedule_status) {
				case RESOLVER_SUPERVISOR_SCHEDULE_STARTED:
				case RESOLVER_SUPERVISOR_SCHEDULE_COALESCED:
					entry->interest = true;
					break;
				case RESOLVER_SUPERVISOR_SCHEDULE_COMPLETE:
					entry->completion_pending = true;
					break;
				case RESOLVER_SUPERVISOR_SCHEDULE_FRESH:
					reevaluate = true;
					break;
				case RESOLVER_SUPERVISOR_SCHEDULE_LIMIT:
				case RESOLVER_SUPERVISOR_SCHEDULE_MEMORY:
					entry->overlay.status = ROUTE_ENDPOINT_OVERLAY_UNAVAILABLE;
					reevaluate = true;
					break;
				case RESOLVER_SUPERVISOR_SCHEDULE_IO:
					return route_waiter_terminal_set(waiter, ROUTE_WAITER_IO, supervisor, now);
				case RESOLVER_SUPERVISOR_SCHEDULE_TIME:
					return route_waiter_terminal_set(waiter, ROUTE_WAITER_TIME, supervisor, now);
				case RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT:
				default:
					return route_waiter_terminal_set(waiter, ROUTE_WAITER_BAD_ARGUMENT, supervisor, now);
			}
		}
		if (!reevaluate) {
			return ROUTE_WAITER_PENDING;
		}
	}
	return route_waiter_terminal_set(waiter, ROUTE_WAITER_BAD_ARGUMENT, supervisor, now);
}

bool route_waiter_snapshot_take(route_waiter *waiter, route_endpoint_snapshot *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (waiter == NULL || result == NULL || waiter->status != ROUTE_WAITER_READY || waiter->snapshot_taken) {
		return false;
	}
	*result = waiter->snapshot;
	memset(&waiter->snapshot, 0, sizeof(waiter->snapshot));
	waiter->snapshot_taken = true;
	return true;
}
