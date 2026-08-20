/*
 * route_resolution.c: Tests for per-generation route DNS resolution coordination
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
#include "resolver/cache.h"
#include "resolver/dns.h"
#include "resolver/hosts.h"
#include "resolver/supervisor.h"
#include "route/bindings.h"
#include "route/prewarmer.h"
#include "route/resolution.h"
#include "route/table.h"

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
	resolver_cache_entry *entry;
	resolver_supervisor_schedule_status status;
} resolution_schedule_fixture;

/* section: global variables */
static size_t resolution_schedule_fixture_count;
static size_t resolution_schedule_fixture_index;
static resolution_schedule_fixture resolution_schedule_fixtures[16];
static resolver_supervisor *resolution_schedule_supervisor;
static struct timespec resolution_schedule_time;

/* section: functions (local) */
static bool resolution_address_equal(const net_addr *address, sa_family_t family, const char *expected) {
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

static bool resolution_address_publish(resolver_cache_entry *entry, sa_family_t family, const char *address, uint32_t ttl, const struct timespec *completed_at) {
	dns_address_result result = { 0 };
	result.addresses = calloc(1, sizeof(*result.addresses));
	if (result.addresses == NULL) {
		return false;
	}
	result.address_count = 1;
	result.addresses[0].address = net_addr_parse(address);
	result.addresses[0].effective_ttl = ttl;
	result.addresses[0].record_ttl = ttl;
	const char *name = resolver_cache_entry_name(entry);
	if (result.addresses[0].address.family != family || snprintf(result.question_name, sizeof(result.question_name), "%s", name) <= 0
		|| snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", name) <= 0) {
		dns_address_result_destroy(&result);
		return false;
	}
	resolver_cache_publish_status status = resolver_cache_entry_publish_address(entry, DNS_ADDRESS_LOOKUP_OK, completed_at, &result);
	dns_address_result_destroy(&result);
	return status == (ttl == 0 ? RESOLVER_CACHE_PUBLISH_TRANSIENT : RESOLVER_CACHE_PUBLISH_STORED);
}

static bool resolution_bindings_build(const char *json, const hosts_table *hosts, resolver_cache *cache, conf *config, route_table **routes, route_bindings **bindings) {
	memset(config, 0, sizeof(*config));
	config->proxy = cJSON_Parse(json);
	return config->proxy != NULL && route_table_build(config, routes) == ROUTE_TABLE_BUILD_OK && *routes != NULL
		&& route_bindings_build(*routes, hosts, cache, bindings) == ROUTE_BINDINGS_BUILD_OK && *bindings != NULL;
}

static resolver_supervisor_completion resolution_completion(resolver_cache_entry *entry, resolver_cache_publish_status publication, resolver_ipc_lookup_status status) {
	resolver_supervisor_completion completion = { 0 };
	completion.entry = entry;
	completion.publication = publication;
	completion.response.query_type = resolver_cache_entry_query_type(entry);
	completion.response.status = status;
	return completion;
}

static int resolution_fixture_write(const char *filename) {
	static const char fixture[] =
		"192.0.2.10 local.example\n"
		"192.0.2.50 host.target\n"
		"2001:db8::50 HOST.TARGET.\n";
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

static void resolution_schedule_reset(resolver_supervisor *supervisor, const struct timespec *now) {
	memset(resolution_schedule_fixtures, 0, sizeof(resolution_schedule_fixtures));
	resolution_schedule_fixture_count = 0;
	resolution_schedule_fixture_index = 0;
	resolution_schedule_supervisor = supervisor;
	resolution_schedule_time = *now;
}

static bool resolution_srv_publish(resolver_cache_entry *entry, const char *const *targets, size_t target_count, uint32_t ttl, const struct timespec *completed_at) {
	dns_srv_result result = { 0 };
	result.records = calloc(target_count, sizeof(*result.records));
	if (result.records == NULL) {
		return false;
	}
	result.record_count = target_count;
	const char *name = resolver_cache_entry_name(entry);
	if (snprintf(result.question_name, sizeof(result.question_name), "%s", name) <= 0 || snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", name) <= 0) {
		dns_srv_result_destroy(&result);
		return false;
	}
	for (size_t target_index = 0; target_index < target_count; target_index++) {
		result.records[target_index].effective_ttl = ttl;
		result.records[target_index].port = (in_port_t)(25565U + target_index);
		result.records[target_index].priority = (uint16_t)(target_index % 2U);
		result.records[target_index].record_ttl = ttl;
		result.records[target_index].weight = (uint16_t)(target_index + 1U);
		if (snprintf(result.records[target_index].target, sizeof(result.records[target_index].target), "%s", targets[target_index]) <= 0) {
			dns_srv_result_destroy(&result);
			return false;
		}
	}
	resolver_cache_publish_status status = resolver_cache_entry_publish_srv(entry, DNS_SRV_LOOKUP_OK, completed_at, &result);
	dns_srv_result_destroy(&result);
	return status == (ttl == 0 ? RESOLVER_CACHE_PUBLISH_TRANSIENT : RESOLVER_CACHE_PUBLISH_STORED);
}

static bool resolution_test_arguments(const hosts_table *hosts) {
	static const char json[] = "[{\"vhost\":[\"route\"],\"address\":\"dns.example\",\"port\":25565}]";
	bool test_result = false;
	conf config = { 0 };
	resolver_cache *cache = resolver_cache_create();
	route_bindings *bindings = NULL;
	route_resolution *resolution = NULL;
	route_table *routes = NULL;
	const struct timespec now = { .tv_sec = 100 };
	struct timespec invalid_time = { .tv_sec = -1 };
	CHECK(cache != NULL && resolution_bindings_build(json, hosts, cache, &config, &routes, &bindings), "argument fixtures could not be prepared");
	CHECK(route_resolution_build(NULL, hosts, cache, &now, &resolution) == ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT, "NULL bindings were accepted");
	CHECK(route_resolution_build(bindings, NULL, cache, &now, &resolution) == ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT, "NULL hosts were accepted");
	CHECK(route_resolution_build(bindings, hosts, NULL, &now, &resolution) == ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT, "NULL cache was accepted");
	CHECK(route_resolution_build(bindings, hosts, cache, NULL, &resolution) == ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT, "NULL build time was accepted");
	CHECK(route_resolution_build(bindings, hosts, cache, &invalid_time, &resolution) == ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT, "invalid build time was accepted");
	CHECK(route_resolution_build(bindings, hosts, cache, &now, NULL) == ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT, "NULL build output was accepted");
	CHECK(route_resolution_build(bindings, hosts, cache, &now, &resolution) == ROUTE_RESOLUTION_BUILD_OK && resolution != NULL, "valid coordinator could not be built");
	CHECK(route_resolution_build(bindings, hosts, cache, &now, &resolution) == ROUTE_RESOLUTION_BUILD_BAD_ARGUMENT, "nonempty build output was accepted");
	CHECK(route_resolution_destination_count(NULL) == 0 && route_resolution_destination_count(resolution) == 1, "destination count argument handling was incorrect");
	route_resolution_destination_view destination;
	memset(&destination, 0xFF, sizeof(destination));
	CHECK(!route_resolution_destination_get(NULL, 0, &destination) && !destination.first_terminal && destination.target_count == 0,
		"invalid destination access did not clear its output");
	CHECK(!route_resolution_destination_get(resolution, 1, &destination), "out-of-range destination was accepted");
	route_resolution_target_view target;
	memset(&target, 0xFF, sizeof(target));
	CHECK(!route_resolution_destination_target_get(resolution, 0, 0, &target) && target.name == NULL && target.addresses == NULL,
		"invalid target access did not clear its output");
	resolver_supervisor_completion completion = { 0 };
	CHECK(route_resolution_completion_observe(NULL, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT
		&& route_resolution_completion_observe(resolution, NULL, &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT
		&& route_resolution_completion_observe(resolution, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT,
		"invalid completion arguments were accepted");
	CHECK(route_resolution_schedule(NULL, (resolver_supervisor *)(uintptr_t)1, &now, 1) == ROUTE_PREWARM_BAD_ARGUMENT
		&& route_resolution_schedule(resolution, NULL, &now, 1) == ROUTE_PREWARM_BAD_ARGUMENT
		&& route_resolution_schedule(resolution, (resolver_supervisor *)(uintptr_t)1, NULL, 1) == ROUTE_PREWARM_BAD_ARGUMENT
		&& route_resolution_schedule(resolution, (resolver_supervisor *)(uintptr_t)1, &now, 0) == ROUTE_PREWARM_BAD_ARGUMENT,
		"invalid schedule arguments were accepted");
	CHECK(!route_resolution_scheduling_complete(NULL) && !route_resolution_warmup_complete(NULL), "NULL coordinator appeared complete");
	route_resolution_destroy(NULL);
	test_result = true;

cleanup:
	route_resolution_destroy(resolution);
	route_bindings_destroy(bindings);
	resolver_cache_destroy(cache);
	route_table_destroy(routes);
	cJSON_Delete(config.proxy);
	return test_result;
}

static bool resolution_test_generation(const hosts_table *hosts) {
	static const char json[] = "["
		"{\"vhost\":[\"numeric\"],\"address\":\"192.0.2.20\",\"port\":25565},"
		"{\"vhost\":[\"hosts\"],\"address\":\"local.example\",\"port\":25565},"
		"{\"vhost\":[\"address\"],\"address\":\"address.example\",\"port\":25565},"
		"{\"vhost\":[\"srv\"],\"address\":\"service.example\"}"
	"]";
	static const char *const srv_targets[] = { "192.0.2.60", "host.target", "dns.target", "dns.target" };
	bool test_result = false;
	conf config = { 0 };
	resolver_cache *cache = resolver_cache_create();
	route_bindings *bindings = NULL;
	route_bindings *bindings_second = NULL;
	route_resolution *resolution = NULL;
	route_resolution *resolution_second = NULL;
	route_table *routes = NULL;
	const struct timespec now = { .tv_sec = 200, .tv_nsec = 300 };
	resolver_supervisor *supervisor = (resolver_supervisor *)(uintptr_t)1;
	CHECK(cache != NULL && resolution_bindings_build(json, hosts, cache, &config, &routes, &bindings), "generation fixtures could not be prepared");
	CHECK(route_resolution_build(bindings, hosts, cache, &now, &resolution) == ROUTE_RESOLUTION_BUILD_OK && resolution != NULL, "generation coordinator could not be built");
	CHECK(route_resolution_destination_count(resolution) == 4 && !route_resolution_warmup_complete(resolution), "initial generation terminal state was incorrect");
	route_resolution_destination_view numeric;
	route_resolution_destination_view local;
	route_resolution_destination_view address;
	route_resolution_destination_view srv;
	CHECK(route_resolution_destination_get(resolution, 0, &numeric) && numeric.first_terminal && numeric.result == ROUTE_RESOLUTION_DESTINATION_AVAILABLE
		&& route_resolution_destination_get(resolution, 1, &local) && local.first_terminal && local.result == ROUTE_RESOLUTION_DESTINATION_AVAILABLE,
		"immediate route sources were not terminal");
	CHECK(route_resolution_destination_get(resolution, 2, &address) && !address.first_terminal && address.pending_entry_count == 2
		&& route_resolution_destination_get(resolution, 3, &srv) && !srv.first_terminal && srv.pending_entry_count == 1,
		"DNS route sources did not begin pending");
	route_binding_view address_binding;
	route_binding_view srv_binding;
	CHECK(route_bindings_destination_get(bindings, 2, &address_binding) && address_binding.source == ROUTE_BINDING_SOURCE_DNS_ADDRESS
		&& route_bindings_destination_get(bindings, 3, &srv_binding) && srv_binding.source == ROUTE_BINDING_SOURCE_DNS_SRV,
		"DNS binding fixtures were incorrect");
	resolver_supervisor_completion malformed = resolution_completion(address_binding.ipv4_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_NODATA);
	malformed.response.query_type = ns_t_srv;
	CHECK(route_resolution_completion_observe(resolution, &malformed, &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT,
		"mismatched completion query type was accepted");
	malformed = resolution_completion(address_binding.ipv4_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR);
	CHECK(route_resolution_completion_observe(resolution, &malformed, &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT,
		"nonterminal temporary completion was accepted");
	malformed = resolution_completion(address_binding.ipv4_entry, (resolver_cache_publish_status)UINT8_MAX, RESOLVER_IPC_LOOKUP_NODATA);
	CHECK(route_resolution_completion_observe(resolution, &malformed, &now) == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT,
		"unknown completion publication was accepted");
	CHECK(resolution_address_publish(address_binding.ipv4_entry, AF_INET, "192.0.2.30", 30, &now), "stored address fixture could not be published");
	CHECK(resolution_srv_publish(srv_binding.srv_entry, srv_targets, sizeof(srv_targets) / sizeof(srv_targets[0]), 30, &now), "stored SRV fixture could not be published");
	resolution_schedule_reset(supervisor, &now);
	for (size_t entry_index = 0; entry_index < route_bindings_entry_count(bindings); entry_index++) {
		resolver_cache_entry *entry = NULL;
		CHECK(route_bindings_entry_get(bindings, entry_index, &entry), "static schedule entry could not be read");
		resolution_schedule_fixtures[entry_index].entry = entry;
		uint16_t query_type = resolver_cache_entry_query_type(entry);
		resolution_schedule_fixtures[entry_index].status = query_type == ns_t_a ? RESOLVER_SUPERVISOR_SCHEDULE_COMPLETE
			: query_type == ns_t_aaaa ? RESOLVER_SUPERVISOR_SCHEDULE_STARTED : RESOLVER_SUPERVISOR_SCHEDULE_FRESH;
	}
	resolution_schedule_fixture_count = route_bindings_entry_count(bindings);
	CHECK(route_resolution_schedule(resolution, supervisor, &now, 3) == ROUTE_PREWARM_MORE && resolution_schedule_fixture_index == 3,
		"static prewarm wave was incorrect");
	CHECK(route_resolution_destination_get(resolution, 2, &address) && !address.first_terminal && address.pending_entry_count == 2,
		"SCHEDULE_COMPLETE was counted before its completion was consumed");
	CHECK(route_resolution_destination_get(resolution, 3, &srv) && !srv.first_terminal && srv.pending_entry_count == 2 && srv.target_count == 3,
		"fresh SRV entry did not expand unique targets");
	CHECK(srv.srv_record_count == 4 && srv.srv_records != NULL && strcmp(srv.srv_records[0].target, "192.0.2.60") == 0
		&& strcmp(srv.srv_records[3].target, "dns.target") == 0 && srv.srv_records[2].priority == 0 && srv.srv_records[2].weight == 3
		&& srv.srv_records[2].port == 25567, "stored SRV metadata or DNS order was not retained");
	route_resolution_target_view numeric_target;
	route_resolution_target_view hosts_target;
	route_resolution_target_view dns_target;
	CHECK(route_resolution_destination_target_get(resolution, 3, 0, &numeric_target) && numeric_target.source == ROUTE_RESOLUTION_TARGET_NUMERIC
		&& resolution_address_equal(&numeric_target.numeric_address, AF_INET, "192.0.2.60"), "numeric SRV target was incorrect");
	CHECK(route_resolution_destination_target_get(resolution, 3, 1, &hosts_target) && hosts_target.source == ROUTE_RESOLUTION_TARGET_HOSTS && hosts_target.address_count == 2
		&& resolution_address_equal(&hosts_target.addresses[0], AF_INET, "192.0.2.50") && resolution_address_equal(&hosts_target.addresses[1], AF_INET6, "2001:db8::50"),
		"hosts SRV target was incorrect");
	CHECK(route_resolution_destination_target_get(resolution, 3, 2, &dns_target) && dns_target.source == ROUTE_RESOLUTION_TARGET_DNS
		&& strcmp(dns_target.name, "dns.target") == 0 && dns_target.ipv4_entry != NULL && dns_target.ipv6_entry != NULL,
		"DNS SRV target was incorrect");
	CHECK(resolver_cache_entry_count(cache) == 5, "dynamic SRV target entries were not generation-owned or deduplicated");
	resolution_schedule_reset(supervisor, &now);
	resolution_schedule_fixtures[0] = (resolution_schedule_fixture){ .entry = dns_target.ipv4_entry, .status = RESOLVER_SUPERVISOR_SCHEDULE_LIMIT };
	resolution_schedule_fixture_count = 1;
	CHECK(route_resolution_schedule(resolution, supervisor, &now, 2) == ROUTE_PREWARM_CAPACITY && !route_resolution_scheduling_complete(resolution),
		"dynamic capacity failure consumed its queued entry");
	resolution_schedule_reset(supervisor, &now);
	resolution_schedule_fixtures[0] = (resolution_schedule_fixture){ .entry = dns_target.ipv4_entry, .status = RESOLVER_SUPERVISOR_SCHEDULE_STARTED };
	resolution_schedule_fixtures[1] = (resolution_schedule_fixture){ .entry = dns_target.ipv6_entry, .status = RESOLVER_SUPERVISOR_SCHEDULE_MEMORY };
	resolution_schedule_fixture_count = 2;
	CHECK(route_resolution_schedule(resolution, supervisor, &now, 2) == ROUTE_PREWARM_MEMORY && !route_resolution_scheduling_complete(resolution),
		"dynamic memory failure did not preserve the rejected entry");
	resolution_schedule_reset(supervisor, &now);
	resolution_schedule_fixtures[0] = (resolution_schedule_fixture){ .entry = dns_target.ipv6_entry, .status = RESOLVER_SUPERVISOR_SCHEDULE_STARTED };
	resolution_schedule_fixture_count = 1;
	CHECK(route_resolution_schedule(resolution, supervisor, &now, 1) == ROUTE_PREWARM_COMPLETE && route_resolution_scheduling_complete(resolution),
		"dynamic scheduling did not resume to completion");
	resolver_supervisor_completion completion = resolution_completion(address_binding.ipv4_entry, RESOLVER_CACHE_PUBLISH_STORED, RESOLVER_IPC_LOOKUP_OK);
	CHECK(route_resolution_completion_observe(resolution, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_OK
		&& route_resolution_destination_get(resolution, 2, &address) && address.pending_entry_count == 1 && !address.first_terminal,
		"stored address completion was not observed");
	CHECK(route_resolution_completion_observe(resolution, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_OK
		&& route_resolution_destination_get(resolution, 2, &address) && address.pending_entry_count == 1,
		"duplicate address completion changed terminal accounting");
	completion = resolution_completion(address_binding.ipv6_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_NODATA);
	CHECK(route_resolution_completion_observe(resolution, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_OK
		&& route_resolution_destination_get(resolution, 2, &address) && address.first_terminal && address.result == ROUTE_RESOLUTION_DESTINATION_AVAILABLE,
		"dual-family address route did not complete after both terminal results");
	completion = resolution_completion(dns_target.ipv4_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_NODATA);
	CHECK(route_resolution_completion_observe(resolution, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_OK
		&& route_resolution_destination_get(resolution, 3, &srv) && srv.pending_entry_count == 1 && !srv.first_terminal,
		"first dynamic target completion ended the SRV route early");
	completion = resolution_completion(dns_target.ipv6_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_NODATA);
	CHECK(route_resolution_completion_observe(resolution, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_OK
		&& route_resolution_destination_get(resolution, 3, &srv) && srv.first_terminal && srv.result == ROUTE_RESOLUTION_DESTINATION_AVAILABLE
		&& route_resolution_warmup_complete(resolution), "SRV route did not complete after every target source reached a terminal result");
	CHECK(route_bindings_build(routes, hosts, cache, &bindings_second) == ROUTE_BINDINGS_BUILD_OK && bindings_second != NULL,
		"replacement bindings generation could not be built");
	CHECK(route_resolution_build(bindings_second, hosts, cache, &now, &resolution_second) == ROUTE_RESOLUTION_BUILD_OK && resolution_second != NULL
		&& resolver_cache_entry_count(cache) == 5, "replacement coordinator did not retain fresh SRV target entries before handoff");
	route_resolution_destroy(resolution);
	resolution = NULL;
	route_bindings_destroy(bindings);
	bindings = NULL;
	CHECK(resolver_cache_entry_count(cache) == 5, "old generation destruction dropped target entries still used by its replacement");
	route_resolution_destroy(resolution_second);
	resolution_second = NULL;
	route_bindings_destroy(bindings_second);
	bindings_second = NULL;
	CHECK(resolver_cache_entry_count(cache) == 0, "final generation destruction leaked cache entries");
	test_result = true;

cleanup:
	route_resolution_destroy(resolution_second);
	route_resolution_destroy(resolution);
	route_bindings_destroy(bindings_second);
	route_bindings_destroy(bindings);
	resolver_cache_destroy(cache);
	route_table_destroy(routes);
	cJSON_Delete(config.proxy);
	return test_result;
}

static bool resolution_test_shared_targets(const hosts_table *hosts) {
	static const char json[] = "["
		"{\"vhost\":[\"one\"],\"address\":\"one.example\"},"
		"{\"vhost\":[\"two\"],\"address\":\"two.example\"}"
	"]";
	static const char *const targets[] = { "shared.target" };
	bool test_result = false;
	conf config = { 0 };
	resolver_cache *cache = resolver_cache_create();
	route_bindings *bindings = NULL;
	route_resolution *resolution = NULL;
	route_table *routes = NULL;
	const struct timespec now = { .tv_sec = 250, .tv_nsec = 350 };
	CHECK(cache != NULL && resolution_bindings_build(json, hosts, cache, &config, &routes, &bindings), "shared-target fixtures could not be prepared");
	for (size_t destination_index = 0; destination_index < 2; destination_index++) {
		route_binding_view binding;
		CHECK(route_bindings_destination_get(bindings, destination_index, &binding) && binding.source == ROUTE_BINDING_SOURCE_DNS_SRV
			&& resolution_srv_publish(binding.srv_entry, targets, 1, 30, &now), "shared-target SRV fixture could not be published");
	}
	CHECK(route_resolution_build(bindings, hosts, cache, &now, &resolution) == ROUTE_RESOLUTION_BUILD_OK && resolution != NULL
		&& resolver_cache_entry_count(cache) == 4, "shared-target coordinator did not deduplicate dynamic cache entries generation-wide");
	route_resolution_destination_view first_destination;
	route_resolution_destination_view second_destination;
	route_resolution_target_view first_target;
	route_resolution_target_view second_target;
	CHECK(route_resolution_destination_get(resolution, 0, &first_destination) && !first_destination.first_terminal && first_destination.pending_entry_count == 2
		&& route_resolution_destination_get(resolution, 1, &second_destination) && !second_destination.first_terminal && second_destination.pending_entry_count == 2,
		"shared-target destinations did not begin with the same two pending address sources");
	CHECK(route_resolution_destination_target_get(resolution, 0, 0, &first_target) && route_resolution_destination_target_get(resolution, 1, 0, &second_target)
		&& first_target.source == ROUTE_RESOLUTION_TARGET_DNS && second_target.source == ROUTE_RESOLUTION_TARGET_DNS
		&& first_target.ipv4_entry == second_target.ipv4_entry && first_target.ipv6_entry == second_target.ipv6_entry,
		"identical SRV targets did not share generation-owned address entries");
	resolver_supervisor_completion completion = resolution_completion(first_target.ipv4_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_OK);
	CHECK(route_resolution_completion_observe(resolution, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_OK, "shared IPv4 completion was not observed");
	completion = resolution_completion(first_target.ipv6_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_OK);
	CHECK(route_resolution_completion_observe(resolution, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_OK
		&& route_resolution_destination_get(resolution, 0, &first_destination) && first_destination.first_terminal
		&& first_destination.result == ROUTE_RESOLUTION_DESTINATION_AVAILABLE
		&& route_resolution_destination_get(resolution, 1, &second_destination) && second_destination.first_terminal
		&& second_destination.result == ROUTE_RESOLUTION_DESTINATION_AVAILABLE && route_resolution_warmup_complete(resolution),
		"one shared target completion did not finish every dependent destination exactly once");
	test_result = true;

cleanup:
	route_resolution_destroy(resolution);
	route_bindings_destroy(bindings);
	resolver_cache_destroy(cache);
	route_table_destroy(routes);
	cJSON_Delete(config.proxy);
	return test_result;
}

static bool resolution_test_srv_terminals(const hosts_table *hosts) {
	static const char json[] = "["
		"{\"vhost\":[\"root\"],\"address\":\"root.example\"},"
		"{\"vhost\":[\"mixed\"],\"address\":\"mixed.example\"},"
		"{\"vhost\":[\"negative\"],\"address\":\"negative.example\"}"
	"]";
	bool test_result = false;
	conf config = { 0 };
	resolver_cache *cache = resolver_cache_create();
	resolver_cache_entry *unrelated = NULL;
	route_bindings *bindings = NULL;
	route_resolution *resolution = NULL;
	route_table *routes = NULL;
	const struct timespec now = { .tv_sec = 300, .tv_nsec = 400 };
	CHECK(cache != NULL && resolution_bindings_build(json, hosts, cache, &config, &routes, &bindings), "SRV terminal fixtures could not be prepared");
	CHECK(route_resolution_build(bindings, hosts, cache, &now, &resolution) == ROUTE_RESOLUTION_BUILD_OK && resolution != NULL, "SRV terminal coordinator could not be built");
	for (size_t destination_index = 0; destination_index < 2; destination_index++) {
		route_binding_view binding;
		CHECK(route_bindings_destination_get(bindings, destination_index, &binding) && binding.source == ROUTE_BINDING_SOURCE_DNS_SRV,
			"SRV terminal binding was incorrect");
		resolver_supervisor_completion completion = resolution_completion(binding.srv_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_OK);
		size_t record_count = destination_index == 0 ? 1U : 2U;
		completion.response.payload.srv.records = calloc(record_count, sizeof(*completion.response.payload.srv.records));
		CHECK(completion.response.payload.srv.records != NULL, "transient SRV completion could not be allocated");
		completion.response.payload.srv.record_count = record_count;
		CHECK(snprintf(completion.response.payload.srv.records[0].target, sizeof(completion.response.payload.srv.records[0].target), "%s", ".") > 0,
			"root SRV target could not be prepared");
		if (destination_index == 1) {
			CHECK(snprintf(completion.response.payload.srv.records[1].target, sizeof(completion.response.payload.srv.records[1].target), "%s", "dns.target") > 0,
				"ordinary mixed SRV target could not be prepared");
		}
		CHECK(route_resolution_completion_observe(resolution, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_OK,
			"transient SRV terminal completion was not observed");
		free(completion.response.payload.srv.records);
	}
	route_binding_view negative_binding;
	CHECK(route_bindings_destination_get(bindings, 2, &negative_binding), "negative SRV binding could not be read");
	resolver_supervisor_completion completion = resolution_completion(negative_binding.srv_entry, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_NOT_FOUND);
	CHECK(route_resolution_completion_observe(resolution, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_OK, "negative SRV completion was not observed");
	route_resolution_destination_view root;
	route_resolution_destination_view mixed;
	route_resolution_destination_view negative;
	CHECK(route_resolution_destination_get(resolution, 0, &root) && root.first_terminal && root.result == ROUTE_RESOLUTION_DESTINATION_SERVICE_UNAVAILABLE && root.target_count == 0,
		"root-only SRV RRset was not service-unavailable");
	CHECK(route_resolution_destination_get(resolution, 1, &mixed) && mixed.first_terminal && mixed.result == ROUTE_RESOLUTION_DESTINATION_CONTRADICTORY && mixed.target_count == 0,
		"mixed root and ordinary SRV RRset was not contradictory");
	CHECK(root.srv_records == NULL && root.srv_record_count == 0 && mixed.srv_records == NULL && mixed.srv_record_count == 0,
		"transient SRV metadata was retained after completion observation");
	CHECK(route_resolution_destination_get(resolution, 2, &negative) && negative.first_terminal && negative.result == ROUTE_RESOLUTION_DESTINATION_UNAVAILABLE
		&& route_resolution_warmup_complete(resolution), "negative SRV route was not terminal unavailable");
	CHECK(resolver_cache_entry_acquire(cache, "unrelated.example", ns_t_a, &unrelated) == RESOLVER_CACHE_ACQUIRE_OK, "unrelated completion entry could not be acquired");
	completion = resolution_completion(unrelated, RESOLVER_CACHE_PUBLISH_TRANSIENT, RESOLVER_IPC_LOOKUP_NODATA);
	CHECK(route_resolution_completion_observe(resolution, &completion, &now) == ROUTE_RESOLUTION_COMPLETION_IGNORED,
		"unrelated generation completion was not ignored");
	test_result = true;

cleanup:
	resolver_cache_entry_release(unrelated);
	route_resolution_destroy(resolution);
	route_bindings_destroy(bindings);
	resolver_cache_destroy(cache);
	route_table_destroy(routes);
	cJSON_Delete(config.proxy);
	return test_result;
}

/* section: functions (exported) */
resolver_supervisor_schedule_status __wrap_resolver_supervisor_entry_schedule(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now) {
	if (resolution_schedule_fixture_index >= resolution_schedule_fixture_count || supervisor != resolution_schedule_supervisor || now == NULL
		|| now->tv_sec != resolution_schedule_time.tv_sec || now->tv_nsec != resolution_schedule_time.tv_nsec
		|| entry != resolution_schedule_fixtures[resolution_schedule_fixture_index].entry) {
		return RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT;
	}
	return resolution_schedule_fixtures[resolution_schedule_fixture_index++].status;
}

/* section: functions (entry point) */
int main(void) {
	int test_result = EXIT_FAILURE;
	char directory[] = "/tmp/mcrelay-route-resolution-XXXXXX";
	char filename[256] = { 0 };
	hosts_table *hosts = NULL;
	size_t malformed_line_count = 0;
	CHECK(mkdtemp(directory) != NULL, "cannot create route-resolution test directory");
	CHECK(snprintf(filename, sizeof(filename), "%s/hosts", directory) > 0, "cannot create route-resolution hosts path");
	CHECK(resolution_fixture_write(filename) == 0, "cannot write route-resolution hosts fixture");
	CHECK(hosts_table_load(filename, &hosts, &malformed_line_count) == HOSTS_LOAD_OK && hosts != NULL && malformed_line_count == 0,
		"cannot load route-resolution hosts fixture");
	CHECK(resolution_test_arguments(hosts), "route-resolution argument tests failed");
	CHECK(resolution_test_generation(hosts), "route-resolution generation tests failed");
	CHECK(resolution_test_shared_targets(hosts), "route-resolution shared-target tests failed");
	CHECK(resolution_test_srv_terminals(hosts), "route-resolution SRV terminal tests failed");
	test_result = EXIT_SUCCESS;

cleanup:
	hosts_table_destroy(hosts);
	if (filename[0] != '\0') {
		unlink(filename);
	}
	rmdir(directory);
	return test_result;
}
