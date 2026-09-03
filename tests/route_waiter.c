/*
 * route_waiter.c: Tests for per-connection asynchronous route resolution waiters
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <cjson/cJSON.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "config.h"
#include "network.h"
#include "protocol/proxy.h"
#include "resolver/cache.h"
#include "resolver/dns.h"
#include "resolver/hosts.h"
#include "resolver/supervisor.h"
#include "route/bindings.h"
#include "route/endpoint.h"
#include "route/generation.h"
#include "route/prewarmer.h"
#include "route/resolution.h"
#include "route/table.h"
#include "route/waiter.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* section: types */
typedef struct {
	route_bindings *bindings;
	resolver_cache *cache;
	conf config;
	uint64_t identity;
	size_t reference_count;
	route_resolution *resolution;
	route_table *routes;
} waiter_fixture;
typedef struct {
	resolver_supervisor_release_status default_release_status;
	resolver_supervisor_schedule_status default_status;
	resolver_cache_entry *released[32];
	size_t release_count;
	resolver_supervisor_release_status release_statuses[32];
	size_t release_status_count;
	resolver_cache_entry *scheduled[32];
	size_t schedule_count;
} waiter_supervisor_mock;

/* section: global variables */
static waiter_supervisor_mock supervisor_mock;

/* section: functions (local) */
static bool waiter_address_equal(const net_addr *address, sa_family_t family, const char *expected) {
	if (address == NULL || address->family != family || expected == NULL) {
		return false;
	}
	uint8_t expected_address[16] = { 0 };
	if (inet_pton(family, expected, expected_address) != 1) {
		return false;
	}
	size_t address_size = family == AF_INET ? sizeof(uint32_t) : sizeof(expected_address);
	return memcmp(&address->addr, expected_address, address_size) == 0;
}

static bool waiter_address_publish(resolver_cache_entry *entry, const char *address, uint32_t ttl, const struct timespec *completed_at,
	resolver_cache_publish_status *publication) {
	if (entry == NULL || address == NULL || completed_at == NULL || publication == NULL) {
		return false;
	}
	uint16_t query_type = resolver_cache_entry_query_type(entry);
	sa_family_t family = query_type == ns_t_a ? AF_INET : query_type == ns_t_aaaa ? AF_INET6 : AF_UNSPEC;
	if (family == AF_UNSPEC) {
		return false;
	}
	dns_address_result result = { 0 };
	result.addresses = calloc(1, sizeof(*result.addresses));
	if (result.addresses == NULL) {
		return false;
	}
	result.address_count = 1;
	result.addresses[0].address = net_addr_parse(address);
	result.addresses[0].effective_ttl = ttl;
	result.addresses[0].record_ttl = ttl;
	result.rcode = ns_r_noerror;
	const char *name = resolver_cache_entry_name(entry);
	bool valid = result.addresses[0].address.family == family && snprintf(result.question_name, sizeof(result.question_name), "%s", name) > 0
		&& snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", name) > 0;
	if (valid) {
		*publication = resolver_cache_entry_publish_address(entry, DNS_ADDRESS_LOOKUP_OK, completed_at, &result);
	}
	dns_address_result_destroy(&result);
	return valid;
}

static bool waiter_binding_get(const waiter_fixture *fixture, const char *vhost, route_binding_view *result, size_t *destination_index) {
	route_view route;
	if (fixture == NULL || vhost == NULL || result == NULL || !route_table_find(fixture->routes, vhost, &route)
		|| !route_bindings_destination_get(fixture->bindings, route.destination_index, result)) {
		return false;
	}
	if (destination_index != NULL) {
		*destination_index = route.destination_index;
	}
	return true;
}

static bool waiter_completion_address(resolver_cache_entry *entry, resolver_cache_publish_status publication, resolver_ipc_lookup_status status,
	const struct timespec *completed_at, const char *address, dns_address_record *record, resolver_supervisor_completion *result) {
	if (entry == NULL || completed_at == NULL || record == NULL || result == NULL) {
		return false;
	}
	memset(record, 0, sizeof(*record));
	memset(result, 0, sizeof(*result));
	result->entry = entry;
	result->publication = publication;
	result->response.completed_at = *completed_at;
	result->response.query_type = resolver_cache_entry_query_type(entry);
	result->response.status = status;
	if (status == RESOLVER_IPC_LOOKUP_OK && address != NULL) {
		record->address = net_addr_parse(address);
		record->effective_ttl = 0;
		record->record_ttl = 0;
		result->response.payload.address.address_count = 1;
		result->response.payload.address.addresses = record;
	} else if (status == RESOLVER_IPC_LOOKUP_OK && publication == RESOLVER_CACHE_PUBLISH_TRANSIENT) {
		return false;
	}
	return true;
}

static bool waiter_completion_observe(waiter_fixture *fixture, route_waiter *waiter, const resolver_supervisor_completion *completion,
	const struct timespec *processed_at) {
	return route_resolution_completion_observe(fixture->resolution, completion, processed_at) == ROUTE_RESOLUTION_COMPLETION_OK
		&& route_waiter_completion_observe(waiter, completion) == ROUTE_WAITER_COMPLETION_OK;
}

static bool waiter_completion_srv(resolver_cache_entry *entry, const struct timespec *completed_at, dns_srv_record *records, size_t record_count,
	resolver_supervisor_completion *result) {
	if (entry == NULL || completed_at == NULL || records == NULL || record_count == 0 || result == NULL) {
		return false;
	}
	memset(result, 0, sizeof(*result));
	result->entry = entry;
	result->publication = RESOLVER_CACHE_PUBLISH_TRANSIENT;
	result->response.completed_at = *completed_at;
	result->response.payload.srv.record_count = record_count;
	result->response.payload.srv.records = records;
	result->response.query_type = ns_t_srv;
	result->response.status = RESOLVER_IPC_LOOKUP_OK;
	return true;
}

static bool waiter_fixture_build(waiter_fixture *fixture, const hosts_table *hosts, const struct timespec *now) {
	static const char json[] = "["
		"{\"vhost\":[\"numeric\"],\"address\":\"192.0.2.10\",\"port\":25560,\"rewrite\":true,\"pheader\":true},"
		"{\"vhost\":[\"dns\"],\"address\":\"dns.example\",\"port\":25562,\"rewrite\":true},"
		"{\"vhost\":[\"srv\"],\"address\":\"service.example\",\"rewrite\":true}"
	"]";
	if (fixture == NULL || hosts == NULL || now == NULL) {
		return false;
	}
	memset(fixture, 0, sizeof(*fixture));
	fixture->cache = resolver_cache_create();
	fixture->config.proxy = cJSON_Parse(json);
	fixture->identity = 71;
	fixture->reference_count = 1;
	return fixture->cache != NULL && fixture->config.proxy != NULL && route_table_build(&fixture->config, &fixture->routes) == ROUTE_TABLE_BUILD_OK
		&& route_bindings_build(fixture->routes, hosts, fixture->cache, &fixture->bindings) == ROUTE_BINDINGS_BUILD_OK
		&& route_resolution_build(fixture->bindings, hosts, fixture->cache, now, &fixture->resolution) == ROUTE_RESOLUTION_BUILD_OK;
}

static void waiter_fixture_destroy(waiter_fixture *fixture) {
	if (fixture == NULL) {
		return;
	}
	route_resolution_destroy(fixture->resolution);
	route_bindings_destroy(fixture->bindings);
	route_table_destroy(fixture->routes);
	cJSON_Delete(fixture->config.proxy);
	resolver_cache_destroy(fixture->cache);
	memset(fixture, 0, sizeof(*fixture));
}

static int waiter_fixture_write(const char *filename) {
	static const char fixture[] = "192.0.2.20 unrelated.example\n";
	int fd = open(filename, O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (fd == -1) {
		return -1;
	}
	ssize_t fixture_size = (ssize_t)(sizeof(fixture) - 1U);
	ssize_t written = write(fd, fixture, (size_t)fixture_size);
	int saved_errno = errno;
	if (close(fd) == -1 && written == fixture_size) {
		return -1;
	}
	errno = saved_errno;
	return written == fixture_size ? 0 : -1;
}

static void waiter_mock_reset(resolver_supervisor_schedule_status status) {
	memset(&supervisor_mock, 0, sizeof(supervisor_mock));
	supervisor_mock.default_release_status = RESOLVER_SUPERVISOR_RELEASE_OK;
	supervisor_mock.default_status = status;
}

static void waiter_mock_release_reset(resolver_supervisor_release_status status) {
	supervisor_mock.default_release_status = status;
	supervisor_mock.release_status_count = 0;
}

static p_proxy waiter_proxy(sa_family_t family) {
	p_proxy result;
	memset(&result, 0, sizeof(result));
	result.family = family;
	result.srcaddr = net_addr_parse(family == AF_INET ? "198.51.100.10" : "2001:db8::10");
	result.dstaddr = net_addr_parse(family == AF_INET ? "192.0.2.1" : "2001:db8::1");
	result.srcport = 40000;
	result.dstport = 25565;
	return result;
}

static bool waiter_target_get(const waiter_fixture *fixture, size_t destination_index, const char *name, route_resolution_target_view *result) {
	route_resolution_destination_view destination;
	if (fixture == NULL || name == NULL || result == NULL || !route_resolution_destination_get(fixture->resolution, destination_index, &destination)) {
		return false;
	}
	for (size_t target_index = 0; target_index < destination.target_count; target_index++) {
		if (!route_resolution_destination_target_get(fixture->resolution, destination_index, target_index, result)) {
			return false;
		}
		if (result->name != NULL && strcmp(result->name, name) == 0) {
			return true;
		}
	}
	return false;
}

static bool waiter_test_arguments(const hosts_table *hosts) {
	bool test_result = false;
	waiter_fixture fixture;
	const struct timespec now = { .tv_sec = 100 };
	const struct timespec invalid_now = { .tv_sec = 100, .tv_nsec = 1000000000L };
	p_proxy inbound = waiter_proxy(AF_INET);
	route_waiter *waiter = NULL;
	CHECK(waiter_fixture_build(&fixture, hosts, &now), "waiter argument fixture could not be built");
	CHECK(route_waiter_create(NULL, "numeric", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_BAD_ARGUMENT
		&& route_waiter_create((route_generation *)&fixture, NULL, &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_BAD_ARGUMENT
		&& route_waiter_create((route_generation *)&fixture, "numeric", NULL, &now, &waiter) == ROUTE_WAITER_CREATE_BAD_ARGUMENT
		&& route_waiter_create((route_generation *)&fixture, "numeric", &inbound, &invalid_now, &waiter) == ROUTE_WAITER_CREATE_BAD_ARGUMENT,
		"invalid waiter-create arguments were accepted");
	char long_vhost[ROUTE_ENDPOINT_TEXT_SIZE + 1U];
	memset(long_vhost, 'a', sizeof(long_vhost));
	long_vhost[sizeof(long_vhost) - 1U] = '\0';
	CHECK(route_waiter_create((route_generation *)&fixture, long_vhost, &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_LIMIT,
		"oversized waiter virtual host was accepted");
	CHECK(route_waiter_create((route_generation *)&fixture, "numeric", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK && waiter != NULL
		&& fixture.reference_count == 2, "valid waiter was not created or did not retain its generation");
	struct timespec deadline;
	CHECK(route_waiter_deadline(waiter, &deadline) && deadline.tv_sec == now.tv_sec + LISTENER_ROUTE_WAIT_TIMEOUT_SEC && deadline.tv_nsec == now.tv_nsec,
		"waiter absolute deadline was incorrect");
	route_endpoint_snapshot snapshot;
	memset(&snapshot, 0xA5, sizeof(snapshot));
	CHECK(!route_waiter_snapshot_take(waiter, &snapshot) && snapshot.generation_identity == 0, "pending waiter exposed a snapshot");
	CHECK(route_waiter_completion_observe(NULL, NULL) == ROUTE_WAITER_COMPLETION_BAD_ARGUMENT,
		"invalid completion-observe arguments were accepted");
	CHECK(route_waiter_destroy(waiter, NULL, NULL) == ROUTE_WAITER_DESTROY_OK && fixture.reference_count == 1
		&& route_waiter_destroy(NULL, NULL, NULL) == ROUTE_WAITER_DESTROY_OK,
		"idle waiter destruction or generation release failed");
	waiter = NULL;
	test_result = true;

cleanup:
	route_waiter_destroy(waiter, NULL, NULL);
	waiter_fixture_destroy(&fixture);
	return test_result;
}

static bool waiter_test_complete(const hosts_table *hosts) {
	bool test_result = false;
	waiter_fixture fixture;
	const struct timespec now = { .tv_sec = 100 };
	p_proxy inbound = waiter_proxy(AF_INET6);
	route_waiter *waiter = NULL;
	resolver_supervisor *supervisor = (resolver_supervisor *)&supervisor_mock;
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_COMPLETE);
	CHECK(waiter_fixture_build(&fixture, hosts, &now) && route_waiter_create((route_generation *)&fixture, "dns", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK,
		"complete-state waiter fixture could not be built");
	CHECK(route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 2
		&& route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 2,
		"queued completions were rescheduled or treated as terminal");
	route_binding_view binding;
	CHECK(waiter_binding_get(&fixture, "dns", &binding, NULL), "complete-state binding was unavailable");
	dns_address_record record;
	resolver_supervisor_completion completion;
	const struct timespec completed_at = { .tv_sec = 101 };
	CHECK(waiter_completion_address(binding.ipv6_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_OK, &completed_at, "2001:db8::31", &record, &completion)
		&& waiter_completion_observe(&fixture, waiter, &completion, &completed_at)
		&& route_waiter_progress(waiter, supervisor, &completed_at) == ROUTE_WAITER_READY,
		"queued transient completion did not make the waiter ready");
	test_result = true;

cleanup:
	route_waiter_destroy(waiter, supervisor, &now);
	waiter_fixture_destroy(&fixture);
	return test_result;
}

static bool waiter_test_completion_clears_interest(const hosts_table *hosts) {
	bool test_result = false;
	waiter_fixture fixture;
	const struct timespec now = { .tv_sec = 100 };
	const struct timespec completed_at = { .tv_sec = 101 };
	p_proxy inbound = waiter_proxy(AF_INET6);
	route_waiter *waiter = NULL;
	resolver_supervisor *supervisor = (resolver_supervisor *)&supervisor_mock;
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
	CHECK(waiter_fixture_build(&fixture, hosts, &now) && route_waiter_create((route_generation *)&fixture, "dns", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 2,
		"completion-interest waiter could not acquire both interests");
	route_binding_view binding;
	CHECK(waiter_binding_get(&fixture, "dns", &binding, NULL), "completion-interest binding was unavailable");
	dns_address_record record;
	resolver_supervisor_completion completion;
	CHECK(waiter_completion_address(binding.ipv4_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_OK, &completed_at, "192.0.2.81", &record,
		&completion), "completion-interest payload could not be prepared");
	completion.response.payload.address.address_count = DNS_ADDRESS_RECORD_LIMIT + 1U;
	CHECK(route_waiter_completion_observe(waiter, &completion) == ROUTE_WAITER_COMPLETION_BAD_ARGUMENT,
		"malformed transient completion was accepted");
	route_waiter_destroy_status destroy_status = route_waiter_destroy(waiter, supervisor, &completed_at);
	waiter = NULL;
	CHECK(destroy_status == ROUTE_WAITER_DESTROY_OK && supervisor_mock.release_count == 1 && supervisor_mock.released[0] == binding.ipv6_entry,
		"completion observation did not clear interest before transient-payload processing");
	test_result = true;

cleanup:
	route_waiter_destroy(waiter, supervisor, &completed_at);
	waiter_fixture_destroy(&fixture);
	return test_result;
}

static bool waiter_test_dns(const hosts_table *hosts) {
	bool test_result = false;
	waiter_fixture fixture;
	const struct timespec now = { .tv_sec = 100 };
	p_proxy inbound = waiter_proxy(AF_INET6);
	route_waiter *waiter = NULL;
	resolver_supervisor *supervisor = (resolver_supervisor *)&supervisor_mock;
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
	CHECK(waiter_fixture_build(&fixture, hosts, &now) && route_waiter_create((route_generation *)&fixture, "dns", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK,
		"DNS waiter fixture could not be built");
	CHECK(route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 2,
		"DNS waiter did not schedule both address families interactively");
	route_binding_view binding;
	CHECK(waiter_binding_get(&fixture, "dns", &binding, NULL), "DNS waiter binding was unavailable");
	dns_address_record record;
	resolver_supervisor_completion completion;
	const struct timespec completed_at = { .tv_sec = 101 };
	CHECK(waiter_completion_address(binding.ipv4_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_OK, &completed_at, "192.0.2.41", &record, &completion)
		&& waiter_completion_observe(&fixture, waiter, &completion, &completed_at), "transient alternate-family completion was not observed");
	memset(&record, 0, sizeof(record));
	CHECK(route_waiter_progress(waiter, supervisor, &completed_at) == ROUTE_WAITER_READY && supervisor_mock.release_count == 1
		&& supervisor_mock.released[0] == binding.ipv6_entry, "alternate-family success did not release the pending preferred-family interest");
	route_endpoint_snapshot snapshot;
	route_endpoint_snapshot duplicate;
	CHECK(route_waiter_snapshot_take(waiter, &snapshot) && !route_waiter_snapshot_take(waiter, &duplicate)
		&& duplicate.generation_identity == 0 && waiter_address_equal(&snapshot.address, AF_INET, "192.0.2.41"),
		"waiter transient overlay was not copied into a one-shot endpoint snapshot");
	resolver_cache_view view;
	CHECK(resolver_cache_entry_view(binding.ipv4_entry, &completed_at, &view) && view.status == RESOLVER_CACHE_VIEW_EMPTY,
		"TTL-zero waiter result leaked into the shared cache");
	CHECK(route_waiter_destroy(waiter, supervisor, &completed_at) == ROUTE_WAITER_DESTROY_OK && supervisor_mock.release_count == 1 && fixture.reference_count == 1,
		"ready waiter released an interactive interest twice or retained its generation");
	waiter = NULL;
	test_result = true;

cleanup:
	route_waiter_destroy(waiter, supervisor, &now);
	waiter_fixture_destroy(&fixture);
	return test_result;
}

static bool waiter_test_errors(const hosts_table *hosts) {
	bool test_result = false;
	waiter_fixture fixture;
	const struct timespec now = { .tv_sec = 100 };
	p_proxy inbound = waiter_proxy(AF_INET);
	route_waiter *waiter = NULL;
	resolver_supervisor *supervisor = (resolver_supervisor *)&supervisor_mock;
	CHECK(waiter_fixture_build(&fixture, hosts, &now), "waiter error fixture could not be built");
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_LIMIT);
	CHECK(route_waiter_create((route_generation *)&fixture, "dns", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_UNAVAILABLE
		&& route_waiter_destroy(waiter, supervisor, &now) == ROUTE_WAITER_DESTROY_OK,
		"local interactive capacity failure did not make only the route unavailable");
	waiter = NULL;
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_MEMORY);
	CHECK(route_waiter_create((route_generation *)&fixture, "dns", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_UNAVAILABLE
		&& route_waiter_destroy(waiter, supervisor, &now) == ROUTE_WAITER_DESTROY_OK,
		"local interactive memory failure did not make only the route unavailable");
	waiter = NULL;
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_IO);
	CHECK(route_waiter_create((route_generation *)&fixture, "dns", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_IO
		&& route_waiter_destroy(waiter, supervisor, &now) == ROUTE_WAITER_DESTROY_OK,
		"shared resolver IO failure was not propagated");
	waiter = NULL;
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_TIME);
	CHECK(route_waiter_create((route_generation *)&fixture, "dns", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_TIME
		&& route_waiter_destroy(waiter, supervisor, &now) == ROUTE_WAITER_DESTROY_OK,
		"shared resolver time failure was not propagated");
	waiter = NULL;
	CHECK(fixture.reference_count == 1, "error waiters leaked generation references");
	test_result = true;

cleanup:
	route_waiter_destroy(waiter, supervisor, &now);
	waiter_fixture_destroy(&fixture);
	return test_result;
}

static bool waiter_test_late(const hosts_table *hosts) {
	bool test_result = false;
	waiter_fixture fixture;
	const struct timespec accepted_at = { .tv_sec = 100 };
	const struct timespec completed_at = { .tv_sec = 111 };
	p_proxy inbound = waiter_proxy(AF_INET6);
	route_waiter *waiter = NULL;
	resolver_supervisor *supervisor = (resolver_supervisor *)&supervisor_mock;
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
	CHECK(waiter_fixture_build(&fixture, hosts, &accepted_at) && route_waiter_create((route_generation *)&fixture, "dns", &inbound, &accepted_at, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &accepted_at) == ROUTE_WAITER_PENDING, "late-completion waiter could not be started");
	route_binding_view binding;
	CHECK(waiter_binding_get(&fixture, "dns", &binding, NULL), "late-completion binding was unavailable");
	resolver_cache_publish_status publication;
	CHECK(waiter_address_publish(binding.ipv6_entry, "2001:db8::51", 30, &completed_at, &publication) && publication == RESOLVER_CACHE_PUBLISH_STORED,
		"late stored completion could not be published");
	dns_address_record record;
	resolver_supervisor_completion completion;
	CHECK(waiter_completion_address(binding.ipv6_entry, publication, RESOLVER_IPC_LOOKUP_OK, &completed_at, NULL, &record, &completion)
		&& waiter_completion_observe(&fixture, waiter, &completion, &completed_at), "late stored completion was not observed");
	route_endpoint_snapshot direct_snapshot;
	CHECK(route_endpoint_select((route_generation *)&fixture, "dns", &completed_at, &inbound, &direct_snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& waiter_address_equal(&direct_snapshot.address, AF_INET6, "2001:db8::51"), "late stored result was not available to unrelated future selectors");
	CHECK(route_waiter_progress(waiter, supervisor, &completed_at) == ROUTE_WAITER_TIMEOUT && supervisor_mock.release_count == 1
		&& supervisor_mock.released[0] == binding.ipv4_entry, "late completion crossed the waiter deadline or did not release the remaining interest");
	test_result = true;

cleanup:
	route_waiter_destroy(waiter, supervisor, &completed_at);
	waiter_fixture_destroy(&fixture);
	return test_result;
}

static bool waiter_test_negative(const hosts_table *hosts) {
	bool test_result = false;
	waiter_fixture fixture;
	const struct timespec accepted_at = { .tv_sec = 100 };
	const struct timespec completed_at = { .tv_sec = 101 };
	p_proxy inbound = waiter_proxy(AF_INET6);
	route_waiter *waiter = NULL;
	resolver_supervisor *supervisor = (resolver_supervisor *)&supervisor_mock;
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
	CHECK(waiter_fixture_build(&fixture, hosts, &accepted_at) && route_waiter_create((route_generation *)&fixture, "dns", &inbound, &accepted_at, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &accepted_at) == ROUTE_WAITER_PENDING, "negative-family waiter could not be started");
	route_binding_view binding;
	CHECK(waiter_binding_get(&fixture, "dns", &binding, NULL), "negative-family binding was unavailable");
	dns_address_record negative_record;
	resolver_supervisor_completion negative_completion;
	CHECK(waiter_completion_address(binding.ipv6_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_NODATA, &completed_at, NULL, &negative_record,
		&negative_completion) && waiter_completion_observe(&fixture, waiter, &negative_completion, &completed_at)
		&& route_waiter_progress(waiter, supervisor, &completed_at) == ROUTE_WAITER_PENDING,
		"terminally negative preferred family ended the waiter while the alternate family remained pending");
	dns_address_record positive_record;
	resolver_supervisor_completion positive_completion;
	CHECK(waiter_completion_address(binding.ipv4_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_OK, &completed_at, "192.0.2.62", &positive_record,
		&positive_completion) && waiter_completion_observe(&fixture, waiter, &positive_completion, &completed_at)
		&& route_waiter_progress(waiter, supervisor, &completed_at) == ROUTE_WAITER_READY,
		"alternate-family positive result did not finish a waiter after the preferred family resolved negatively");
	route_endpoint_snapshot snapshot;
	CHECK(route_waiter_snapshot_take(waiter, &snapshot) && waiter_address_equal(&snapshot.address, AF_INET, "192.0.2.62"),
		"negative preferred-family fallback selected the wrong endpoint");
	test_result = true;

cleanup:
	route_waiter_destroy(waiter, supervisor, &completed_at);
	waiter_fixture_destroy(&fixture);
	return test_result;
}

static bool waiter_test_numeric(const hosts_table *hosts) {
	bool test_result = false;
	waiter_fixture fixture;
	const struct timespec now = { .tv_sec = 100 };
	p_proxy inbound = waiter_proxy(AF_INET6);
	route_waiter *waiter = NULL;
	resolver_supervisor *supervisor = (resolver_supervisor *)&supervisor_mock;
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
	CHECK(waiter_fixture_build(&fixture, hosts, &now) && route_waiter_create((route_generation *)&fixture, "numeric", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK,
		"numeric waiter fixture could not be built");
	CHECK(route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_READY && supervisor_mock.schedule_count == 0,
		"numeric waiter did not become ready without DNS work");
	route_endpoint_snapshot snapshot;
	CHECK(route_waiter_snapshot_take(waiter, &snapshot) && snapshot.generation_identity == fixture.identity && snapshot.pheader && snapshot.rewrite
		&& waiter_address_equal(&snapshot.address, AF_INET, "192.0.2.10") && snapshot.port == 25560, "numeric waiter snapshot was incorrect");
	test_result = true;

cleanup:
	route_waiter_destroy(waiter, supervisor, &now);
	waiter_fixture_destroy(&fixture);
	return test_result;
}

static bool waiter_test_processing_delay(const hosts_table *hosts) {
	bool test_result = false;
	waiter_fixture fixture;
	const struct timespec accepted_at = { .tv_sec = 100 };
	const struct timespec completed_at = { .tv_sec = 110 };
	const struct timespec processed_at = { .tv_sec = 111 };
	p_proxy inbound = waiter_proxy(AF_INET6);
	route_waiter *waiter = NULL;
	resolver_supervisor *supervisor = (resolver_supervisor *)&supervisor_mock;
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
	CHECK(waiter_fixture_build(&fixture, hosts, &accepted_at) && route_waiter_create((route_generation *)&fixture, "dns", &inbound, &accepted_at, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &accepted_at) == ROUTE_WAITER_PENDING, "processing-delay waiter could not be started");
	route_binding_view binding;
	CHECK(waiter_binding_get(&fixture, "dns", &binding, NULL), "processing-delay binding was unavailable");
	dns_address_record record;
	resolver_supervisor_completion completion;
	CHECK(waiter_completion_address(binding.ipv6_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_OK, &completed_at, "2001:db8::61", &record, &completion)
		&& waiter_completion_observe(&fixture, waiter, &completion, &processed_at)
		&& route_waiter_progress(waiter, supervisor, &processed_at) == ROUTE_WAITER_READY,
		"on-time helper completion was rejected using listener processing time");
	route_endpoint_snapshot snapshot;
	CHECK(route_waiter_snapshot_take(waiter, &snapshot) && waiter_address_equal(&snapshot.address, AF_INET6, "2001:db8::61"),
		"delayed processing lost the accepted transient payload");
	test_result = true;

cleanup:
	route_waiter_destroy(waiter, supervisor, &processed_at);
	waiter_fixture_destroy(&fixture);
	return test_result;
}

static bool waiter_test_release_statuses(const hosts_table *hosts) {
	static const resolver_supervisor_release_status release_statuses[] = {
		RESOLVER_SUPERVISOR_RELEASE_OK,
		RESOLVER_SUPERVISOR_RELEASE_SATISFIED,
		RESOLVER_SUPERVISOR_RELEASE_BAD_ARGUMENT,
		RESOLVER_SUPERVISOR_RELEASE_IO,
		RESOLVER_SUPERVISOR_RELEASE_TIME
	};
	static const route_waiter_destroy_status destroy_statuses[] = {
		ROUTE_WAITER_DESTROY_OK,
		ROUTE_WAITER_DESTROY_OK,
		ROUTE_WAITER_DESTROY_BAD_ARGUMENT,
		ROUTE_WAITER_DESTROY_IO,
		ROUTE_WAITER_DESTROY_TIME
	};
	bool test_result = false;
	waiter_fixture fixture;
	const struct timespec now = { .tv_sec = 100 };
	p_proxy inbound = waiter_proxy(AF_INET6);
	resolver_supervisor *supervisor = (resolver_supervisor *)&supervisor_mock;
	route_waiter *waiter = NULL;
	route_waiter_destroy_status result;
	for (size_t status_index = 0; status_index < sizeof(release_statuses) / sizeof(release_statuses[0]); status_index++) {
		waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
		waiter_mock_release_reset(release_statuses[status_index]);
		CHECK(waiter_fixture_build(&fixture, hosts, &now) && route_waiter_create((route_generation *)&fixture, "dns", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK
			&& route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 2,
			"release-status waiter could not acquire both interests");
		result = route_waiter_destroy(waiter, supervisor, &now);
		waiter = NULL;
		CHECK(result == destroy_statuses[status_index] && supervisor_mock.release_count == 2 && fixture.reference_count == 1,
			"waiter destroy did not preserve the supervisor release status");
		waiter_fixture_destroy(&fixture);
	}
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
	CHECK(waiter_fixture_build(&fixture, hosts, &now), "completion-take fixture could not be built");
	CHECK(route_waiter_create((route_generation *)&fixture, "dns", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 2,
		"completion-take waiter could not acquire both interests");
	/* The first release models a completion-take that removed its job before waiter destruction. */
	supervisor_mock.release_statuses[0] = RESOLVER_SUPERVISOR_RELEASE_SATISFIED;
	supervisor_mock.release_status_count = 1;
	result = route_waiter_destroy(waiter, supervisor, &now);
	waiter = NULL;
	CHECK(result == ROUTE_WAITER_DESTROY_OK && supervisor_mock.release_count == 2 && fixture.reference_count == 1,
		"completion-take SATISFIED release was not treated as normal destruction");
	waiter_fixture_destroy(&fixture);

	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
	CHECK(waiter_fixture_build(&fixture, hosts, &now), "batch-release fixture could not be built");
	CHECK(route_waiter_create((route_generation *)&fixture, "dns", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 2,
		"batch-release waiter could not acquire both interests");
	supervisor_mock.release_statuses[0] = RESOLVER_SUPERVISOR_RELEASE_IO;
	supervisor_mock.release_statuses[1] = RESOLVER_SUPERVISOR_RELEASE_TIME;
	supervisor_mock.release_status_count = 2;
	result = route_waiter_destroy(waiter, supervisor, &now);
	waiter = NULL;
	CHECK(result == ROUTE_WAITER_DESTROY_IO && supervisor_mock.release_count == 2 && fixture.reference_count == 1,
		"waiter destroy stopped after the first release error");
	waiter_fixture_destroy(&fixture);

	const struct timespec invalid_now = { .tv_sec = 100, .tv_nsec = 1000000000L };
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
	CHECK(waiter_fixture_build(&fixture, hosts, &now), "invalid-time fixture could not be built");
	CHECK(route_waiter_create((route_generation *)&fixture, "dns", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 2,
		"invalid-time waiter could not acquire both interests");
	result = route_waiter_destroy(waiter, supervisor, &invalid_now);
	waiter = NULL;
	CHECK(result == ROUTE_WAITER_DESTROY_TIME && supervisor_mock.release_count == 0 && fixture.reference_count == 1,
		"invalid destruction time was not propagated without retrying release");
	waiter_fixture_destroy(&fixture);

	CHECK(waiter_fixture_build(&fixture, hosts, &now), "local-dispose fixture could not be built");
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
	CHECK(route_waiter_create((route_generation *)&fixture, "dns", &inbound, &now, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &now) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 2,
		"local-dispose waiter could not acquire both interests");
	route_waiter_dispose(waiter);
	waiter = NULL;
	CHECK(supervisor_mock.release_count == 0 && fixture.reference_count == 1, "local waiter disposal called the supervisor or leaked its generation");
	waiter_fixture_destroy(&fixture);
	test_result = true;

cleanup:
	route_waiter_destroy(waiter, supervisor, &now);
	waiter_fixture_destroy(&fixture);
	return test_result;
}

static bool waiter_test_release_progress(const hosts_table *hosts) {
	static const resolver_supervisor_release_status release_statuses[] = {
		RESOLVER_SUPERVISOR_RELEASE_BAD_ARGUMENT,
		RESOLVER_SUPERVISOR_RELEASE_IO,
		RESOLVER_SUPERVISOR_RELEASE_TIME
	};
	static const route_waiter_status waiter_statuses[] = {
		ROUTE_WAITER_BAD_ARGUMENT,
		ROUTE_WAITER_IO,
		ROUTE_WAITER_TIME
	};
	bool test_result = false;
	waiter_fixture fixture;
	const struct timespec accepted_at = { .tv_sec = 100 };
	const struct timespec expired_at = { .tv_sec = 110 };
	p_proxy inbound = waiter_proxy(AF_INET6);
	resolver_supervisor *supervisor = (resolver_supervisor *)&supervisor_mock;
	route_waiter *waiter = NULL;
	for (size_t status_index = 0; status_index < sizeof(release_statuses) / sizeof(release_statuses[0]); status_index++) {
		waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
		waiter_mock_release_reset(release_statuses[status_index]);
		CHECK(waiter_fixture_build(&fixture, hosts, &accepted_at) && route_waiter_create((route_generation *)&fixture, "dns", &inbound, &accepted_at, &waiter) == ROUTE_WAITER_CREATE_OK
			&& route_waiter_progress(waiter, supervisor, &accepted_at) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 2,
			"release-progress waiter could not acquire both interests");
		route_waiter_status progress_status = route_waiter_progress(waiter, supervisor, &expired_at);
		route_waiter_destroy_status destroy_status = route_waiter_destroy(waiter, supervisor, &expired_at);
		waiter = NULL;
		CHECK(progress_status == waiter_statuses[status_index] && destroy_status == ROUTE_WAITER_DESTROY_OK && supervisor_mock.release_count == 2
			&& fixture.reference_count == 1, "waiter progress did not propagate every release status");
		waiter_fixture_destroy(&fixture);
	}
	const struct timespec completed_at = { .tv_sec = 101 };
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
	CHECK(waiter_fixture_build(&fixture, hosts, &accepted_at) && route_waiter_create((route_generation *)&fixture, "dns", &inbound, &accepted_at, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &accepted_at) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 2,
		"terminal-entry waiter could not acquire both interests");
	CHECK(route_waiter_progress(waiter, supervisor, &expired_at) == ROUTE_WAITER_TIMEOUT, "terminal-entry waiter did not become terminal");
	route_binding_view binding;
	CHECK(waiter_binding_get(&fixture, "dns", &binding, NULL), "terminal-entry binding was unavailable");
	dns_address_record record;
	resolver_supervisor_completion completion;
	CHECK(waiter_completion_address(binding.ipv6_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_OK, &completed_at, "2001:db8::64", &record,
		&completion) && route_waiter_completion_observe(waiter, &completion) == ROUTE_WAITER_COMPLETION_OK,
		"terminal waiter released its local entry before destruction");
	CHECK(route_waiter_destroy(waiter, supervisor, &expired_at) == ROUTE_WAITER_DESTROY_OK && supervisor_mock.release_count == 2 && fixture.reference_count == 1,
		"terminal waiter did not preserve local entries until destruction");
	waiter = NULL;
	waiter_fixture_destroy(&fixture);
	test_result = true;

cleanup:
	route_waiter_destroy(waiter, supervisor, &expired_at);
	waiter_fixture_destroy(&fixture);
	return test_result;
}

static bool waiter_test_srv(const hosts_table *hosts) {
	bool test_result = false;
	waiter_fixture fixture;
	const struct timespec accepted_at = { .tv_sec = 100 };
	const struct timespec srv_at = { .tv_sec = 101 };
	const struct timespec target_at = { .tv_sec = 102 };
	p_proxy inbound = waiter_proxy(AF_INET6);
	route_waiter *waiter = NULL;
	resolver_supervisor *supervisor = (resolver_supervisor *)&supervisor_mock;
	waiter_mock_reset(RESOLVER_SUPERVISOR_SCHEDULE_STARTED);
	CHECK(waiter_fixture_build(&fixture, hosts, &accepted_at) && route_waiter_create((route_generation *)&fixture, "srv", &inbound, &accepted_at, &waiter) == ROUTE_WAITER_CREATE_OK
		&& route_waiter_progress(waiter, supervisor, &accepted_at) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 1,
		"SRV waiter did not schedule only its owner first");
	route_binding_view binding;
	size_t destination_index = 0;
	CHECK(waiter_binding_get(&fixture, "srv", &binding, &destination_index), "SRV waiter binding was unavailable");
	dns_srv_record srv_record;
	memset(&srv_record, 0, sizeof(srv_record));
	srv_record.port = 25572;
	CHECK(snprintf(srv_record.target, sizeof(srv_record.target), "%s", "target.example") > 0, "SRV waiter target could not be prepared");
	resolver_supervisor_completion srv_completion;
	CHECK(waiter_completion_srv(binding.srv_entry, &srv_at, &srv_record, 1, &srv_completion)
		&& waiter_completion_observe(&fixture, waiter, &srv_completion, &srv_at), "transient SRV completion was not observed in coordinator-first order");
	memset(&srv_record, 0, sizeof(srv_record));
	CHECK(route_waiter_progress(waiter, supervisor, &srv_at) == ROUTE_WAITER_PENDING && supervisor_mock.schedule_count == 3,
		"transient SRV payload was not copied before dynamic target scheduling");
	route_resolution_target_view target;
	CHECK(waiter_target_get(&fixture, destination_index, "target.example", &target) && target.source == ROUTE_RESOLUTION_TARGET_DNS,
		"SRV coordinator did not retain the dynamically discovered target entries");
	dns_address_record ipv6_record;
	resolver_supervisor_completion ipv6_completion;
	CHECK(waiter_completion_address(target.ipv6_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_NODATA, &target_at, NULL, &ipv6_record, &ipv6_completion)
		&& waiter_completion_observe(&fixture, waiter, &ipv6_completion, &target_at), "transient target IPv6 negative completion was not observed");
	dns_address_record ipv4_record;
	resolver_supervisor_completion ipv4_completion;
	CHECK(waiter_completion_address(target.ipv4_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_OK, &target_at, "192.0.2.72", &ipv4_record, &ipv4_completion)
		&& waiter_completion_observe(&fixture, waiter, &ipv4_completion, &target_at)
		&& route_waiter_progress(waiter, supervisor, &target_at) == ROUTE_WAITER_READY,
		"transient SRV target address completions did not finish the waiter");
	memset(&ipv4_record, 0, sizeof(ipv4_record));
	route_endpoint_snapshot snapshot;
	CHECK(route_waiter_snapshot_take(waiter, &snapshot) && waiter_address_equal(&snapshot.address, AF_INET, "192.0.2.72") && snapshot.port == 25572
		&& strcmp(snapshot.target_name, "target.example") == 0, "SRV waiter snapshot lost its event-scoped owner or target payload");
	resolver_cache_view view;
	CHECK(resolver_cache_entry_view(binding.srv_entry, &target_at, &view) && view.status == RESOLVER_CACHE_VIEW_EMPTY
		&& resolver_cache_entry_view(target.ipv4_entry, &target_at, &view) && view.status == RESOLVER_CACHE_VIEW_EMPTY,
		"TTL-zero SRV chain leaked into shared cache state");
	test_result = true;

cleanup:
	route_waiter_destroy(waiter, supervisor, &target_at);
	waiter_fixture_destroy(&fixture);
	return test_result;
}

/* section: functions (exported) */
resolver_supervisor_release_status __wrap_resolver_supervisor_entry_background_release(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now) {
	(void)supervisor;
	(void)entry;
	(void)now;
	return RESOLVER_SUPERVISOR_RELEASE_BAD_ARGUMENT;
}

resolver_supervisor_release_status __wrap_resolver_supervisor_entry_interactive_release(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now) {
	if (supervisor == NULL || entry == NULL || now == NULL || supervisor_mock.release_count >= sizeof(supervisor_mock.released) / sizeof(supervisor_mock.released[0])) {
		return RESOLVER_SUPERVISOR_RELEASE_BAD_ARGUMENT;
	}
	size_t release_index = supervisor_mock.release_count++;
	supervisor_mock.released[release_index] = entry;
	return release_index < supervisor_mock.release_status_count ? supervisor_mock.release_statuses[release_index] : supervisor_mock.default_release_status;
}

resolver_supervisor_schedule_status __wrap_resolver_supervisor_entry_schedule(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now) {
	(void)supervisor;
	(void)entry;
	(void)now;
	return RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT;
}

resolver_supervisor_schedule_status __wrap_resolver_supervisor_entry_schedule_interactive(resolver_supervisor *supervisor, resolver_cache_entry *entry,
	const struct timespec *now) {
	if (supervisor == NULL || entry == NULL || now == NULL || supervisor_mock.schedule_count >= sizeof(supervisor_mock.scheduled) / sizeof(supervisor_mock.scheduled[0])) {
		return RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT;
	}
	supervisor_mock.scheduled[supervisor_mock.schedule_count++] = entry;
	return supervisor_mock.default_status;
}

const route_bindings *__wrap_route_generation_bindings(const route_generation *generation) {
	const waiter_fixture *fixture = (const waiter_fixture *)generation;
	return fixture == NULL ? NULL : fixture->bindings;
}

uint64_t __wrap_route_generation_identity(const route_generation *generation) {
	const waiter_fixture *fixture = (const waiter_fixture *)generation;
	return fixture == NULL ? 0 : fixture->identity;
}

size_t __wrap_route_generation_release(route_generation *generation) {
	waiter_fixture *fixture = (waiter_fixture *)generation;
	if (fixture == NULL || fixture->reference_count == 0) {
		return 0;
	}
	fixture->reference_count--;
	return fixture->reference_count;
}

route_resolution *__wrap_route_generation_resolution(route_generation *generation) {
	waiter_fixture *fixture = (waiter_fixture *)generation;
	return fixture == NULL ? NULL : fixture->resolution;
}

bool __wrap_route_generation_retain(route_generation *generation) {
	waiter_fixture *fixture = (waiter_fixture *)generation;
	if (fixture == NULL || fixture->reference_count == SIZE_MAX) {
		return false;
	}
	fixture->reference_count++;
	return true;
}

const route_table *__wrap_route_generation_routes(const route_generation *generation) {
	const waiter_fixture *fixture = (const waiter_fixture *)generation;
	return fixture == NULL ? NULL : fixture->routes;
}

/* section: functions (entry point) */
int main(void) {
	int test_result = EXIT_FAILURE;
	char directory[] = "/tmp/mcrelay-route-waiter-XXXXXX";
	char filename[256] = { 0 };
	hosts_table *hosts = NULL;
	size_t malformed_line_count = 0;
	CHECK(mkdtemp(directory) != NULL, "cannot create route-waiter test directory");
	CHECK(snprintf(filename, sizeof(filename), "%s/hosts", directory) > 0, "cannot create route-waiter hosts path");
	CHECK(waiter_fixture_write(filename) == 0, "cannot write route-waiter hosts fixture");
	CHECK(hosts_table_load(filename, &hosts, &malformed_line_count) == HOSTS_LOAD_OK && hosts != NULL && malformed_line_count == 0,
		"cannot load route-waiter hosts fixture");
	CHECK(waiter_test_arguments(hosts), "route-waiter argument tests failed");
	CHECK(waiter_test_complete(hosts), "route-waiter queued-completion tests failed");
	CHECK(waiter_test_completion_clears_interest(hosts), "route-waiter completion-interest tests failed");
	CHECK(waiter_test_dns(hosts), "route-waiter DNS tests failed");
	CHECK(waiter_test_errors(hosts), "route-waiter error tests failed");
	CHECK(waiter_test_late(hosts), "route-waiter late-completion tests failed");
	CHECK(waiter_test_negative(hosts), "route-waiter negative-family tests failed");
	CHECK(waiter_test_numeric(hosts), "route-waiter numeric tests failed");
	CHECK(waiter_test_processing_delay(hosts), "route-waiter processing-delay tests failed");
	CHECK(waiter_test_release_statuses(hosts), "route-waiter release-status tests failed");
	CHECK(waiter_test_release_progress(hosts), "route-waiter release-progress tests failed");
	CHECK(waiter_test_srv(hosts), "route-waiter SRV tests failed");
	test_result = EXIT_SUCCESS;

cleanup:
	hosts_table_destroy(hosts);
	if (filename[0] != '\0') {
		unlink(filename);
	}
	rmdir(directory);
	return test_result;
}
