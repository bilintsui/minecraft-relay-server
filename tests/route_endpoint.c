/*
 * route_endpoint.c: Tests for fresh route endpoint selection and worker snapshots
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
	route_resolution *resolution;
	route_table *routes;
} endpoint_fixture;

/* section: functions (local) */
static bool endpoint_address_equal(const net_addr *address, sa_family_t family, const char *expected) {
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

static bool endpoint_address_publish(resolver_cache_entry *entry, const char *const *addresses, size_t address_count, uint32_t ttl, const struct timespec *completed_at) {
	if (entry == NULL || addresses == NULL || address_count == 0 || completed_at == NULL) {
		return false;
	}
	uint16_t query_type = resolver_cache_entry_query_type(entry);
	sa_family_t family = query_type == ns_t_a ? AF_INET : query_type == ns_t_aaaa ? AF_INET6 : AF_UNSPEC;
	if (family == AF_UNSPEC) {
		return false;
	}
	dns_address_result result = { 0 };
	result.addresses = calloc(address_count, sizeof(*result.addresses));
	if (result.addresses == NULL) {
		return false;
	}
	result.address_count = address_count;
	result.rcode = ns_r_noerror;
	const char *name = resolver_cache_entry_name(entry);
	if (snprintf(result.question_name, sizeof(result.question_name), "%s", name) <= 0
		|| snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", name) <= 0) {
		dns_address_result_destroy(&result);
		return false;
	}
	for (size_t address_index = 0; address_index < address_count; address_index++) {
		result.addresses[address_index].address = net_addr_parse(addresses[address_index]);
		result.addresses[address_index].effective_ttl = ttl;
		result.addresses[address_index].record_ttl = ttl;
		if (result.addresses[address_index].address.family != family) {
			dns_address_result_destroy(&result);
			return false;
		}
	}
	resolver_cache_publish_status status = resolver_cache_entry_publish_address(entry, DNS_ADDRESS_LOOKUP_OK, completed_at, &result);
	dns_address_result_destroy(&result);
	return status == (ttl == 0 ? RESOLVER_CACHE_PUBLISH_TRANSIENT : RESOLVER_CACHE_PUBLISH_STORED);
}

static bool endpoint_binding_get(const endpoint_fixture *fixture, const char *vhost, route_binding_view *result, size_t *destination_index) {
	route_view route;
	if (fixture == NULL || !route_table_find(fixture->routes, vhost, &route) || !route_bindings_destination_get(fixture->bindings, route.destination_index, result)) {
		return false;
	}
	if (destination_index != NULL) {
		*destination_index = route.destination_index;
	}
	return true;
}

static bool endpoint_fixture_build(endpoint_fixture *fixture, const hosts_table *hosts, const struct timespec *now) {
	static const char json[] = "["
		"{\"vhost\":[\"numeric\"],\"address\":\"192.0.2.10\",\"port\":25560,\"rewrite\":true,\"pheader\":true},"
		"{\"vhost\":[\"hosts\"],\"address\":\"hosts.example\",\"port\":25561},"
		"{\"vhost\":[\"dns\"],\"address\":\"dns.example\",\"port\":25562,\"rewrite\":true},"
		"{\"vhost\":[\"srv\"],\"address\":\"service.example\",\"rewrite\":true},"
		"{\"vhost\":[\"invalid\"],\"address\":\"invalid.example..\",\"port\":25563}"
	"]";
	if (fixture == NULL || hosts == NULL || now == NULL) {
		return false;
	}
	memset(fixture, 0, sizeof(*fixture));
	fixture->cache = resolver_cache_create();
	fixture->config.proxy = cJSON_Parse(json);
	fixture->identity = 42;
	return fixture->cache != NULL && fixture->config.proxy != NULL && route_table_build(&fixture->config, &fixture->routes) == ROUTE_TABLE_BUILD_OK
		&& route_bindings_build(fixture->routes, hosts, fixture->cache, &fixture->bindings) == ROUTE_BINDINGS_BUILD_OK
		&& route_resolution_build(fixture->bindings, hosts, fixture->cache, now, &fixture->resolution) == ROUTE_RESOLUTION_BUILD_OK;
}

static void endpoint_fixture_destroy(endpoint_fixture *fixture) {
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

static int endpoint_fixture_write(const char *filename) {
	static const char fixture[] =
		"192.0.2.20 hosts.example host.target\n"
		"2001:db8::20 hosts.example host.target\n";
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

static bool endpoint_negative_publish(resolver_cache_entry *entry, const struct timespec *completed_at) {
	if (entry == NULL || completed_at == NULL) {
		return false;
	}
	dns_address_result result = { 0 };
	const char *name = resolver_cache_entry_name(entry);
	if (snprintf(result.question_name, sizeof(result.question_name), "%s", name) <= 0
		|| snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", name) <= 0
		|| snprintf(result.negative.owner, sizeof(result.negative.owner), "%s", name) <= 0) {
		return false;
	}
	result.negative.effective_ttl = 30;
	result.negative.minimum = 30;
	result.negative.record_ttl = 30;
	result.negative.valid = true;
	result.rcode = ns_r_noerror;
	resolver_cache_publish_status status = resolver_cache_entry_publish_address(entry, DNS_ADDRESS_LOOKUP_NODATA, completed_at, &result);
	dns_address_result_destroy(&result);
	return status == RESOLVER_CACHE_PUBLISH_STORED;
}

static p_proxy endpoint_proxy(sa_family_t family) {
	p_proxy result;
	memset(&result, 0, sizeof(result));
	result.family = family;
	result.srcaddr = net_addr_parse(family == AF_INET ? "198.51.100.10" : "2001:db8::10");
	result.dstaddr = net_addr_parse(family == AF_INET ? "192.0.2.1" : "2001:db8::1");
	result.srcport = 40000;
	result.dstport = 25565;
	return result;
}

static bool endpoint_srv_publish(endpoint_fixture *fixture, resolver_cache_entry *entry, size_t destination_index, const dns_srv_record *records, size_t record_count,
	uint32_t ttl, const struct timespec *completed_at) {
	if (fixture == NULL || entry == NULL || records == NULL || record_count == 0 || completed_at == NULL) {
		return false;
	}
	dns_srv_result result = { 0 };
	result.records = calloc(record_count, sizeof(*result.records));
	if (result.records == NULL) {
		return false;
	}
	result.record_count = record_count;
	result.rcode = ns_r_noerror;
	const char *name = resolver_cache_entry_name(entry);
	if (snprintf(result.question_name, sizeof(result.question_name), "%s", name) <= 0
		|| snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", name) <= 0) {
		dns_srv_result_destroy(&result);
		return false;
	}
	for (size_t record_index = 0; record_index < record_count; record_index++) {
		result.records[record_index] = records[record_index];
		result.records[record_index].effective_ttl = ttl;
		result.records[record_index].record_ttl = ttl;
	}
	resolver_cache_publish_status publication = resolver_cache_entry_publish_srv(entry, DNS_SRV_LOOKUP_OK, completed_at, &result);
	dns_srv_result_destroy(&result);
	if (publication != RESOLVER_CACHE_PUBLISH_STORED) {
		return false;
	}
	resolver_supervisor_completion completion = { 0 };
	completion.entry = entry;
	completion.publication = publication;
	completion.response.query_type = ns_t_srv;
	completion.response.status = RESOLVER_IPC_LOOKUP_OK;
	if (route_resolution_completion_observe(fixture->resolution, &completion, completed_at) != ROUTE_RESOLUTION_COMPLETION_OK) {
		return false;
	}
	route_resolution_destination_view destination;
	return route_resolution_destination_get(fixture->resolution, destination_index, &destination);
}

static bool endpoint_target_get(const endpoint_fixture *fixture, size_t destination_index, const char *name, route_resolution_target_view *result) {
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

static bool endpoint_test_arguments(const hosts_table *hosts) {
	bool test_result = false;
	endpoint_fixture fixture;
	const struct timespec now = { .tv_sec = 100 };
	const struct timespec invalid_now = { .tv_sec = 100, .tv_nsec = 1000000000L };
	p_proxy inbound = endpoint_proxy(AF_INET6);
	route_endpoint_snapshot snapshot;
	CHECK(endpoint_fixture_build(&fixture, hosts, &now), "endpoint argument fixture could not be built");
	CHECK(route_endpoint_select(NULL, "numeric", &now, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT
		&& route_endpoint_select((route_generation *)&fixture, NULL, &now, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT
		&& route_endpoint_select((route_generation *)&fixture, "numeric", NULL, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT
		&& route_endpoint_select((route_generation *)&fixture, "numeric", &invalid_now, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT
		&& route_endpoint_select((route_generation *)&fixture, "numeric", &now, NULL, &snapshot) == ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT
		&& route_endpoint_select((route_generation *)&fixture, "numeric", &now, &inbound, NULL) == ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT,
		"invalid endpoint-selection arguments were accepted");
	p_proxy invalid_proxy = inbound;
	invalid_proxy.dstaddr.family = AF_INET;
	CHECK(route_endpoint_select((route_generation *)&fixture, "numeric", &now, &invalid_proxy, &snapshot) == ROUTE_ENDPOINT_SELECT_BAD_ARGUMENT,
		"inconsistent inbound endpoints were accepted");
	CHECK(route_endpoint_select((route_generation *)&fixture, "missing", &now, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_NO_ROUTE,
		"unknown virtual host was not distinguished");
	CHECK(route_endpoint_select((route_generation *)&fixture, "invalid", &now, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_UNAVAILABLE,
		"locally unavailable route was accepted");
	CHECK(route_endpoint_select((route_generation *)&fixture, "NUMERIC.", &now, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& endpoint_address_equal(&snapshot.address, AF_INET, "192.0.2.10") && snapshot.port == 25560 && snapshot.generation_identity == 42
		&& snapshot.destination_index == 0 && snapshot.pheader && snapshot.rewrite && strcmp(snapshot.configured_address, "192.0.2.10") == 0
		&& strcmp(snapshot.target_name, "192.0.2.10") == 0 && strcmp(snapshot.vhost, "numeric") == 0 && snapshot.inbound_proxy.family == AF_INET6,
		"numeric endpoint or pointer-free metadata snapshot was incorrect");
	CHECK(route_endpoint_select((route_generation *)&fixture, "hosts", &now, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& endpoint_address_equal(&snapshot.address, AF_INET6, "2001:db8::20"), "hosts selection did not prefer the inbound IPv6 family");
	inbound = endpoint_proxy(AF_INET);
	CHECK(route_endpoint_select((route_generation *)&fixture, "hosts", &now, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& endpoint_address_equal(&snapshot.address, AF_INET, "192.0.2.20"), "hosts selection did not prefer the inbound IPv4 family");
	test_result = true;

cleanup:
	endpoint_fixture_destroy(&fixture);
	return test_result;
}

static bool endpoint_test_dns(const hosts_table *hosts) {
	bool test_result = false;
	endpoint_fixture fixture;
	const struct timespec built_at = { .tv_sec = 100 };
	p_proxy inbound = endpoint_proxy(AF_INET6);
	route_endpoint_snapshot snapshot;
	route_binding_view binding;
	CHECK(endpoint_fixture_build(&fixture, hosts, &built_at) && endpoint_binding_get(&fixture, "dns", &binding, NULL), "DNS endpoint fixture could not be built");
	CHECK(route_endpoint_select((route_generation *)&fixture, "dns", &built_at, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_PENDING,
		"empty dual-family DNS route was not pending");
	static const char *const ipv4_addresses[] = { "192.0.2.40", "192.0.2.41" };
	CHECK(endpoint_address_publish(binding.ipv4_entry, ipv4_addresses, 2, 30, &built_at)
		&& route_endpoint_select((route_generation *)&fixture, "dns", &built_at, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& endpoint_address_equal(&snapshot.address, AF_INET, "192.0.2.40"), "fresh alternate family did not bypass a pending preferred query");
	CHECK(endpoint_negative_publish(binding.ipv6_entry, &built_at)
		&& route_endpoint_select((route_generation *)&fixture, "dns", &built_at, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& endpoint_address_equal(&snapshot.address, AF_INET, "192.0.2.40"), "fresh alternate family did not bypass a terminally negative preferred family");
	static const char *const ipv6_addresses[] = { "2001:db8::40" };
	CHECK(endpoint_address_publish(binding.ipv6_entry, ipv6_addresses, 1, 5, &built_at)
		&& route_endpoint_select((route_generation *)&fixture, "dns", &built_at, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& endpoint_address_equal(&snapshot.address, AF_INET6, "2001:db8::40"), "fresh preferred family did not win");
	const struct timespec ipv6_expired = { .tv_sec = 105 };
	CHECK(route_endpoint_select((route_generation *)&fixture, "dns", &ipv6_expired, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& endpoint_address_equal(&snapshot.address, AF_INET, "192.0.2.40"), "expired preferred payload did not fall back to the fresh alternate");
	const struct timespec all_expired = { .tv_sec = 130 };
	CHECK(route_endpoint_select((route_generation *)&fixture, "dns", &all_expired, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_PENDING,
		"strictly expired address payload remained selectable through warm-up state");
	const struct timespec negative_at = { .tv_sec = 140 };
	CHECK(endpoint_negative_publish(binding.ipv4_entry, &negative_at) && endpoint_negative_publish(binding.ipv6_entry, &negative_at)
		&& route_endpoint_select((route_generation *)&fixture, "dns", &negative_at, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_UNAVAILABLE,
		"two terminally negative address families did not make the route unavailable");
	test_result = true;

cleanup:
	endpoint_fixture_destroy(&fixture);
	return test_result;
}

static bool endpoint_test_snapshot(const hosts_table *hosts) {
	bool test_result = false;
	endpoint_fixture fixture;
	const struct timespec now = { .tv_sec = 100 };
	p_proxy inbound = endpoint_proxy(AF_INET);
	route_endpoint_snapshot snapshot;
	CHECK(endpoint_fixture_build(&fixture, hosts, &now), "snapshot fixture could not be built");
	CHECK(route_endpoint_select((route_generation *)&fixture, "numeric", &now, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK,
		"snapshot endpoint could not be selected");
	endpoint_fixture_destroy(&fixture);
	char proxy_header[PROTOPROXY_PACKETMAXLEN + 1] = { 0 };
	CHECK(snapshot.generation_identity == 42 && endpoint_address_equal(&snapshot.address, AF_INET, "192.0.2.10") && snapshot.port == 25560
		&& strcmp(snapshot.configured_address, "192.0.2.10") == 0 && strcmp(snapshot.target_name, "192.0.2.10") == 0 && strcmp(snapshot.vhost, "numeric") == 0
		&& protocol_proxy_write(proxy_header, snapshot.inbound_proxy) > 0 && strstr(proxy_header, "198.51.100.10 192.0.2.1 40000 25565") != NULL,
		"snapshot retained generation pointers or lost copied connection metadata");
	test_result = true;

cleanup:
	endpoint_fixture_destroy(&fixture);
	return test_result;
}

static bool endpoint_test_srv(const hosts_table *hosts) {
	bool test_result = false;
	endpoint_fixture fixture;
	const struct timespec built_at = { .tv_sec = 200 };
	p_proxy inbound = endpoint_proxy(AF_INET6);
	route_endpoint_snapshot snapshot;
	route_binding_view binding;
	size_t destination_index = 0;
	CHECK(endpoint_fixture_build(&fixture, hosts, &built_at) && endpoint_binding_get(&fixture, "srv", &binding, &destination_index), "SRV endpoint fixture could not be built");
	CHECK(route_endpoint_select((route_generation *)&fixture, "srv", &built_at, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_PENDING,
		"empty SRV owner was not pending");
	dns_srv_record records[4];
	memset(records, 0, sizeof(records));
	records[0].priority = 10;
	records[0].weight = 100;
	records[0].port = 25570;
	records[1].priority = 1;
	records[1].weight = 20;
	records[1].port = 25571;
	records[2].priority = 1;
	records[2].weight = 30;
	records[2].port = 25572;
	records[3].priority = 1;
	records[3].weight = 30;
	records[3].port = 25573;
	CHECK(snprintf(records[0].target, sizeof(records[0].target), "%s", "ignored.target") > 0
		&& snprintf(records[1].target, sizeof(records[1].target), "%s", "lower-weight.target") > 0
		&& snprintf(records[2].target, sizeof(records[2].target), "%s", "chosen.target") > 0
		&& snprintf(records[3].target, sizeof(records[3].target), "%s", "later.target") > 0
		&& endpoint_srv_publish(&fixture, binding.srv_entry, destination_index, records, 4, 30, &built_at), "deterministic SRV RRset could not be published");
	route_resolution_target_view target;
	CHECK(endpoint_target_get(&fixture, destination_index, "chosen.target", &target) && target.source == ROUTE_RESOLUTION_TARGET_DNS,
		"selected SRV target was not expanded as DNS work");
	static const char *const target_ipv4[] = { "192.0.2.72", "192.0.2.73" };
	static const char *const target_ipv6[] = { "2001:db8::72" };
	CHECK(endpoint_address_publish(target.ipv4_entry, target_ipv4, 2, 30, &built_at) && endpoint_address_publish(target.ipv6_entry, target_ipv6, 1, 5, &built_at),
		"selected SRV target addresses could not be published");
	CHECK(route_endpoint_select((route_generation *)&fixture, "srv", &built_at, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& endpoint_address_equal(&snapshot.address, AF_INET6, "2001:db8::72") && snapshot.port == 25572 && strcmp(snapshot.target_name, "chosen.target") == 0,
		"SRV selector did not apply priority, weight, record order, and preferred family");
	inbound = endpoint_proxy(AF_INET);
	CHECK(route_endpoint_select((route_generation *)&fixture, "srv", &built_at, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& endpoint_address_equal(&snapshot.address, AF_INET, "192.0.2.72"), "SRV address selection did not preserve DNS order");
	inbound = endpoint_proxy(AF_INET6);
	const struct timespec ipv6_expired = { .tv_sec = 205 };
	CHECK(route_endpoint_select((route_generation *)&fixture, "srv", &ipv6_expired, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& endpoint_address_equal(&snapshot.address, AF_INET, "192.0.2.72"), "expired SRV target family remained selectable");
	dns_srv_record host_record;
	memset(&host_record, 0, sizeof(host_record));
	host_record.port = 25580;
	CHECK(snprintf(host_record.target, sizeof(host_record.target), "%s", "host.target") > 0
		&& endpoint_srv_publish(&fixture, binding.srv_entry, destination_index, &host_record, 1, 30, &ipv6_expired)
		&& route_endpoint_select((route_generation *)&fixture, "srv", &ipv6_expired, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& endpoint_address_equal(&snapshot.address, AF_INET6, "2001:db8::20") && snapshot.port == 25580,
		"SRV target did not use the generation hosts source before DNS");
	dns_srv_record numeric_record;
	memset(&numeric_record, 0, sizeof(numeric_record));
	numeric_record.port = 25581;
	CHECK(snprintf(numeric_record.target, sizeof(numeric_record.target), "%s", "192.0.2.81") > 0
		&& endpoint_srv_publish(&fixture, binding.srv_entry, destination_index, &numeric_record, 1, 30, &ipv6_expired)
		&& route_endpoint_select((route_generation *)&fixture, "srv", &ipv6_expired, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_OK
		&& endpoint_address_equal(&snapshot.address, AF_INET, "192.0.2.81") && snapshot.port == 25581,
		"numeric SRV target did not retain its fixed family");
	dns_srv_record root_records[2];
	memset(root_records, 0, sizeof(root_records));
	root_records[0].port = 25565;
	CHECK(snprintf(root_records[0].target, sizeof(root_records[0].target), "%s", ".") > 0
		&& endpoint_srv_publish(&fixture, binding.srv_entry, destination_index, root_records, 1, 30, &ipv6_expired)
		&& route_endpoint_select((route_generation *)&fixture, "srv", &ipv6_expired, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_SERVICE_UNAVAILABLE,
		"root-only SRV RRset was not service-unavailable");
	root_records[1].port = 25565;
	CHECK(snprintf(root_records[1].target, sizeof(root_records[1].target), "%s", "host.target") > 0
		&& endpoint_srv_publish(&fixture, binding.srv_entry, destination_index, root_records, 2, 30, &ipv6_expired)
		&& route_endpoint_select((route_generation *)&fixture, "srv", &ipv6_expired, &inbound, &snapshot) == ROUTE_ENDPOINT_SELECT_CONTRADICTORY,
		"mixed root and named SRV RRset was not contradictory");
	test_result = true;

cleanup:
	endpoint_fixture_destroy(&fixture);
	return test_result;
}

/* section: functions (exported) */
const route_bindings *__wrap_route_generation_bindings(const route_generation *generation) {
	const endpoint_fixture *fixture = (const endpoint_fixture *)generation;
	return fixture == NULL ? NULL : fixture->bindings;
}

uint64_t __wrap_route_generation_identity(const route_generation *generation) {
	const endpoint_fixture *fixture = (const endpoint_fixture *)generation;
	return fixture == NULL ? 0 : fixture->identity;
}

route_resolution *__wrap_route_generation_resolution(route_generation *generation) {
	const endpoint_fixture *fixture = (const endpoint_fixture *)generation;
	return fixture == NULL ? NULL : fixture->resolution;
}

const route_table *__wrap_route_generation_routes(const route_generation *generation) {
	const endpoint_fixture *fixture = (const endpoint_fixture *)generation;
	return fixture == NULL ? NULL : fixture->routes;
}

resolver_supervisor_schedule_status __wrap_resolver_supervisor_entry_schedule(resolver_supervisor *supervisor, resolver_cache_entry *entry, const struct timespec *now) {
	(void)supervisor;
	(void)entry;
	(void)now;
	return RESOLVER_SUPERVISOR_SCHEDULE_BAD_ARGUMENT;
}

/* section: functions (entry point) */
int main(void) {
	int test_result = EXIT_FAILURE;
	char directory[] = "/tmp/mcrelay-route-endpoint-XXXXXX";
	char filename[256] = { 0 };
	hosts_table *hosts = NULL;
	size_t malformed_line_count = 0;
	CHECK(mkdtemp(directory) != NULL, "cannot create route-endpoint test directory");
	CHECK(snprintf(filename, sizeof(filename), "%s/hosts", directory) > 0, "cannot create route-endpoint hosts path");
	CHECK(endpoint_fixture_write(filename) == 0, "cannot write route-endpoint hosts fixture");
	CHECK(hosts_table_load(filename, &hosts, &malformed_line_count) == HOSTS_LOAD_OK && hosts != NULL && malformed_line_count == 0,
		"cannot load route-endpoint hosts fixture");
	CHECK(endpoint_test_arguments(hosts), "route-endpoint argument tests failed");
	CHECK(endpoint_test_dns(hosts), "route-endpoint DNS tests failed");
	CHECK(endpoint_test_snapshot(hosts), "route-endpoint snapshot tests failed");
	CHECK(endpoint_test_srv(hosts), "route-endpoint SRV tests failed");
	test_result = EXIT_SUCCESS;

cleanup:
	hosts_table_destroy(hosts);
	if (filename[0] != '\0') {
		unlink(filename);
	}
	rmdir(directory);
	return test_result;
}
