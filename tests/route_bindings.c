/*
 * route_bindings.c: Tests for per-generation proxy destination resolver bindings
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* section: headers (project) */
#include "config.h"
#include "network.h"
#include "resolver/cache.h"
#include "resolver/hosts.h"
#include "route/bindings.h"
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

/* section: functions (local) */
static bool route_test_address_equal(const net_addr *address, sa_family_t family, const char *expected) {
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

static int route_test_fixture_write(const char *filename) {
	static const char fixture[] =
		"192.0.2.10 local.example local-alias\n"
		"2001:db8::10 LOCAL.EXAMPLE.\n";
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

static bool route_test_table_build(const char *json, conf *config, route_table **routes) {
	memset(config, 0, sizeof(*config));
	config->proxy = cJSON_Parse(json);
	return config->proxy != NULL && route_table_build(config, routes) == ROUTE_TABLE_BUILD_OK && *routes != NULL;
}

static bool route_test_arguments(const hosts_table *hosts) {
	bool test_result = false;
	conf config = { 0 };
	resolver_cache *cache = resolver_cache_create();
	route_bindings *bindings = NULL;
	route_table *routes = NULL;
	CHECK(cache != NULL && route_test_table_build("[]", &config, &routes), "empty route inputs could not be prepared");
	CHECK(route_bindings_build(NULL, hosts, cache, &bindings) == ROUTE_BINDINGS_BUILD_BAD_ARGUMENT, "NULL route table was accepted");
	CHECK(route_bindings_build(routes, NULL, cache, &bindings) == ROUTE_BINDINGS_BUILD_BAD_ARGUMENT, "NULL hosts table was accepted");
	CHECK(route_bindings_build(routes, hosts, NULL, &bindings) == ROUTE_BINDINGS_BUILD_BAD_ARGUMENT, "NULL cache was accepted");
	CHECK(route_bindings_build(routes, hosts, cache, NULL) == ROUTE_BINDINGS_BUILD_BAD_ARGUMENT, "NULL output was accepted");
	CHECK(route_bindings_build(routes, hosts, cache, &bindings) == ROUTE_BINDINGS_BUILD_OK && bindings != NULL, "empty route bindings could not be built");
	CHECK(route_bindings_destination_count(bindings) == 0 && route_bindings_entry_count(bindings) == 0, "empty route bindings retained state");
	route_binding_view binding;
	memset(&binding, 0xFF, sizeof(binding));
	CHECK(!route_bindings_destination_get(bindings, 0, &binding) && binding.source == ROUTE_BINDING_SOURCE_UNAVAILABLE && binding.addresses == NULL,
		"invalid destination access did not clear its result");
	resolver_cache_entry *entry = (resolver_cache_entry *)(uintptr_t)1;
	CHECK(!route_bindings_entry_get(bindings, 0, &entry) && entry == NULL, "invalid cache-entry access did not clear its result");
	CHECK(route_bindings_build(routes, hosts, cache, &bindings) == ROUTE_BINDINGS_BUILD_BAD_ARGUMENT, "non-empty binding output was accepted");
	route_bindings_destroy(NULL);
	test_result = true;

cleanup:
	route_bindings_destroy(bindings);
	resolver_cache_destroy(cache);
	route_table_destroy(routes);
	cJSON_Delete(config.proxy);
	return test_result;
}

static bool route_test_bindings(const hosts_table *hosts) {
	static const char json[] = "["
		"{\"vhost\":[\"numeric\"],\"address\":\"192.0.2.20\",\"port\":25565},"
		"{\"vhost\":[\"hosts-a\"],\"address\":\"local.example\",\"port\":25565},"
		"{\"vhost\":[\"hosts-b\"],\"address\":\"LOCAL.EXAMPLE.\",\"port\":25566},"
		"{\"vhost\":[\"dns-a\"],\"address\":\"dns.example\",\"port\":25565},"
		"{\"vhost\":[\"dns-b\"],\"address\":\"DNS.EXAMPLE.\",\"port\":25566},"
		"{\"vhost\":[\"srv\"],\"address\":\"service.example\"},"
		"{\"vhost\":[\"invalid\"],\"address\":\"\",\"port\":25565},"
		"{\"vhost\":[\"localhost\"],\"address\":\"localhost\",\"port\":25565},"
		"{\"vhost\":[\"double-address\"],\"address\":\"dns.example..\",\"port\":25565},"
		"{\"vhost\":[\"double-srv\"],\"address\":\"service.example..\"}"
	"]";
	bool test_result = false;
	conf config = { 0 };
	resolver_cache *cache = resolver_cache_create();
	route_bindings *bindings = NULL;
	route_bindings *bindings_second = NULL;
	route_table *routes = NULL;
	CHECK(cache != NULL && route_test_table_build(json, &config, &routes), "route binding inputs could not be prepared");
	CHECK(route_bindings_build(routes, hosts, cache, &bindings) == ROUTE_BINDINGS_BUILD_OK && bindings != NULL, "route bindings could not be built");
	CHECK(route_bindings_destination_count(bindings) == 10 && route_bindings_entry_count(bindings) == 3 && resolver_cache_entry_count(cache) == 3,
		"route binding or unique cache-entry count was incorrect");
	route_binding_view binding;
	CHECK(route_bindings_destination_get(bindings, 0, &binding) && binding.source == ROUTE_BINDING_SOURCE_NUMERIC && binding.port == 25565
		&& route_test_address_equal(&binding.numeric_address, AF_INET, "192.0.2.20"), "numeric route binding was incorrect");
	CHECK(route_bindings_destination_get(bindings, 1, &binding) && binding.source == ROUTE_BINDING_SOURCE_HOSTS && binding.port == 25565 && binding.address_count == 2
		&& route_test_address_equal(&binding.addresses[0], AF_INET, "192.0.2.10") && route_test_address_equal(&binding.addresses[1], AF_INET6, "2001:db8::10"),
		"hosts route binding did not preserve all file-order addresses");
	CHECK(binding.ipv4_entry == NULL && binding.ipv6_entry == NULL && binding.srv_entry == NULL, "hosts route binding retained DNS entries");
	CHECK(route_bindings_destination_get(bindings, 2, &binding) && binding.source == ROUTE_BINDING_SOURCE_HOSTS && binding.port == 25566,
		"terminal-dot hosts route binding failed");
	route_binding_view dns_first;
	route_binding_view dns_second;
	CHECK(route_bindings_destination_get(bindings, 3, &dns_first) && route_bindings_destination_get(bindings, 4, &dns_second)
		&& dns_first.source == ROUTE_BINDING_SOURCE_DNS_ADDRESS && dns_second.source == ROUTE_BINDING_SOURCE_DNS_ADDRESS && dns_first.port == 25565 && dns_second.port == 25566,
		"explicit-port DNS route bindings were incorrect");
	CHECK(dns_first.ipv4_entry != NULL && dns_first.ipv6_entry != NULL && dns_first.ipv4_entry == dns_second.ipv4_entry && dns_first.ipv6_entry == dns_second.ipv6_entry,
		"identical DNS keys were not shared across destination ports");
	CHECK(route_bindings_destination_get(bindings, 5, &binding) && binding.source == ROUTE_BINDING_SOURCE_DNS_SRV && binding.port == 0 && binding.srv_entry != NULL,
		"SRV route binding was incorrect");
	CHECK(route_bindings_destination_get(bindings, 6, &binding) && binding.source == ROUTE_BINDING_SOURCE_UNAVAILABLE && binding.ipv4_entry == NULL
		&& binding.ipv6_entry == NULL && binding.srv_entry == NULL, "invalid route name did not remain locally unavailable");
	CHECK(route_bindings_destination_get(bindings, 7, &binding) && binding.source == ROUTE_BINDING_SOURCE_HOSTS && binding.address_count == 2
		&& route_test_address_equal(&binding.addresses[0], AF_INET, "127.0.0.1") && route_test_address_equal(&binding.addresses[1], AF_INET6, "::1"),
		"guaranteed localhost records were not bound");
	CHECK(route_bindings_destination_get(bindings, 8, &binding) && binding.source == ROUTE_BINDING_SOURCE_UNAVAILABLE
		&& route_bindings_destination_get(bindings, 9, &binding) && binding.source == ROUTE_BINDING_SOURCE_UNAVAILABLE,
		"double-dot route names were accepted as DNS cache keys");
	resolver_cache_entry *entry_a = NULL;
	resolver_cache_entry *entry_aaaa = NULL;
	resolver_cache_entry *entry_srv = NULL;
	CHECK(route_bindings_entry_get(bindings, 0, &entry_a) && route_bindings_entry_get(bindings, 1, &entry_aaaa) && route_bindings_entry_get(bindings, 2, &entry_srv),
		"unique cache-entry enumeration failed");
	CHECK(strcmp(resolver_cache_entry_name(entry_a), "dns.example") == 0 && resolver_cache_entry_query_type(entry_a) == ns_t_a
		&& strcmp(resolver_cache_entry_name(entry_aaaa), "dns.example") == 0 && resolver_cache_entry_query_type(entry_aaaa) == ns_t_aaaa
		&& strcmp(resolver_cache_entry_name(entry_srv), "_minecraft._tcp.service.example") == 0 && resolver_cache_entry_query_type(entry_srv) == ns_t_srv,
		"unique cache-entry enumeration order or identity was incorrect");
	CHECK(route_bindings_build(routes, hosts, cache, &bindings_second) == ROUTE_BINDINGS_BUILD_OK && bindings_second != NULL && resolver_cache_entry_count(cache) == 3,
		"second generation did not reuse existing cache entries");
	resolver_cache_entry *second_entry = NULL;
	CHECK(route_bindings_entry_get(bindings_second, 0, &second_entry) && second_entry == entry_a, "cache entry was not shared across generations");
	route_bindings_destroy(bindings_second);
	bindings_second = NULL;
	CHECK(resolver_cache_entry_count(cache) == 3, "destroying one generation released shared cache entries too early");
	route_bindings_destroy(bindings);
	bindings = NULL;
	CHECK(resolver_cache_entry_count(cache) == 0, "destroying the final generation did not release cache entries");
	test_result = true;

cleanup:
	route_bindings_destroy(bindings_second);
	route_bindings_destroy(bindings);
	resolver_cache_destroy(cache);
	route_table_destroy(routes);
	cJSON_Delete(config.proxy);
	return test_result;
}

static bool route_test_capacity(const hosts_table *hosts) {
	static const char json[] = "["
		"{\"vhost\":[\"a\"],\"address\":\"a.example\",\"port\":25565},"
		"{\"vhost\":[\"b\"],\"address\":\"b.example\",\"port\":25565},"
		"{\"vhost\":[\"c\"],\"address\":\"c.example\"}"
	"]";
	bool test_result = false;
	conf config = { 0 };
	resolver_cache *cache = resolver_cache_create();
	route_bindings *bindings = NULL;
	route_table *routes = NULL;
	CHECK(cache != NULL && route_test_table_build(json, &config, &routes), "capacity route inputs could not be prepared");
	CHECK(route_bindings_build(routes, hosts, cache, &bindings) == ROUTE_BINDINGS_BUILD_LIMIT && bindings == NULL, "static cache-entry capacity overflow was accepted");
	CHECK(resolver_cache_entry_count(cache) == 0 && resolver_cache_owned_bytes(cache) > 0, "failed generation leaked cache entries or destroyed cache metadata");
	test_result = true;

cleanup:
	route_bindings_destroy(bindings);
	resolver_cache_destroy(cache);
	route_table_destroy(routes);
	cJSON_Delete(config.proxy);
	return test_result;
}

/* section: functions (entry point) */
int main(void) {
	int test_result = EXIT_FAILURE;
	char directory[] = "/tmp/mcrelay-route-bindings-XXXXXX";
	char filename[256] = { 0 };
	hosts_table *hosts = NULL;
	size_t malformed_line_count = 0;
	CHECK(mkdtemp(directory) != NULL, "cannot create route-binding test directory");
	CHECK(snprintf(filename, sizeof(filename), "%s/hosts", directory) > 0, "cannot create hosts fixture path");
	CHECK(route_test_fixture_write(filename) == 0, "cannot write route-binding hosts fixture");
	CHECK(hosts_table_load(filename, &hosts, &malformed_line_count) == HOSTS_LOAD_OK && hosts != NULL && malformed_line_count == 0, "cannot load route-binding hosts fixture");
	CHECK(route_test_arguments(hosts), "route-binding argument tests failed");
	CHECK(route_test_bindings(hosts), "route-binding source tests failed");
	CHECK(route_test_capacity(hosts), "route-binding capacity tests failed");
	test_result = EXIT_SUCCESS;

cleanup:
	hosts_table_destroy(hosts);
	if (filename[0] != '\0') {
		unlink(filename);
	}
	rmdir(directory);
	return test_result;
}
