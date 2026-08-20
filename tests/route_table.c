/*
 * route_table.c: Tests for immutable prepared proxy routes
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* section: headers (project) */
#include "config.h"
#include "network.h"
#include "route/table.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s\n", message); \
			goto cleanup; \
		} \
	} while (0)

/* section: functions (local) */
static bool route_test_arguments(void) {
	bool test_result = false;
	conf config;
	memset(&config, 0, sizeof(config));
	route_table *table = NULL;
	CHECK(route_table_build(NULL, &table) == ROUTE_TABLE_BUILD_BAD_ARGUMENT && route_table_build(&config, NULL) == ROUTE_TABLE_BUILD_BAD_ARGUMENT,
		"invalid route-table build arguments were accepted");
	config.proxy = cJSON_Parse("[]");
	CHECK(config.proxy != NULL && route_table_build(&config, &table) == ROUTE_TABLE_BUILD_OK && table != NULL, "empty route table could not be built");
	CHECK(route_table_route_count(table) == 0 && route_table_destination_count(table) == 0, "empty route table retained entries");
	CHECK(route_table_build(&config, &table) == ROUTE_TABLE_BUILD_BAD_ARGUMENT, "non-empty route-table result was accepted");
	CHECK(!route_table_find(NULL, "example", &(route_view){ 0 }) && !route_table_find(table, NULL, &(route_view){ 0 }) && !route_table_find(table, "example", NULL),
		"invalid route lookup succeeded");
	CHECK(!route_table_route_get(table, 0, &(route_view){ 0 }) && !route_table_destination_get(table, 0, &(route_destination_view){ 0 }), "out-of-range route access succeeded");
	test_result = true;

cleanup:
	route_table_destroy(table);
	cJSON_Delete(config.proxy);
	return test_result;
}

static bool route_test_invalid(void) {
	static const char *fixtures[] = {
		"{}",
		"[{}]",
		"[{\"vhost\":[],\"address\":1}]",
		"[{\"vhost\":\"example\",\"address\":\"target\"}]",
		"[{\"vhost\":[],\"address\":\"target\",\"port\":-1}]",
		"[{\"vhost\":[],\"address\":\"target\",\"port\":65536}]"
	};
	bool test_result = false;
	conf config;
	memset(&config, 0, sizeof(config));
	route_table *table = NULL;
	for (size_t index = 0; index < sizeof(fixtures) / sizeof(fixtures[0]); index++) {
		config.proxy = cJSON_Parse(fixtures[index]);
		CHECK(config.proxy != NULL && route_table_build(&config, &table) == ROUTE_TABLE_BUILD_INVALID && table == NULL, "malformed proxy table was accepted");
		cJSON_Delete(config.proxy);
		config.proxy = NULL;
	}
	test_result = true;

cleanup:
	route_table_destroy(table);
	cJSON_Delete(config.proxy);
	return test_result;
}

static bool route_test_names(void) {
	static const char json[] = "["
		"{\"vhost\":[\"address\"],\"address\":\"Example.COM..\",\"port\":25565},"
		"{\"vhost\":[\"srv\"],\"address\":\"Example.COM..\"}"
	"]";
	bool test_result = false;
	conf config;
	memset(&config, 0, sizeof(config));
	route_table *table = NULL;
	config.proxy = cJSON_Parse(json);
	CHECK(config.proxy != NULL && route_table_build(&config, &table) == ROUTE_TABLE_BUILD_OK && table != NULL, "double-dot route table could not be built");
	CHECK(route_table_destination_count(table) == 2, "double-dot destinations were incorrectly deduplicated");
	route_destination_view destination;
	CHECK(route_table_destination_get(table, 0, &destination) && !destination.srv && strcmp(destination.query_name, "example.com..") == 0,
		"explicit-port double-dot name was silently normalized");
	CHECK(route_table_destination_get(table, 1, &destination) && destination.srv && strcmp(destination.query_name, "_minecraft._tcp.example.com..") == 0,
		"SRV double-dot name was silently normalized");
	test_result = true;

cleanup:
	route_table_destroy(table);
	cJSON_Delete(config.proxy);
	return test_result;
}

static bool route_test_routes(void) {
	static const char json[] = "["
		"{\"vhost\":[\"Alpha.Example\",\"beta.example\",9],\"address\":\"192.0.2.1\",\"port\":25565,\"rewrite\":true},"
		"{\"vhost\":[\"gamma.example\"],\"address\":\"192.0.2.1\",\"port\":25565,\"pheader\":1},"
		"{\"vhost\":[\"v6-a.example\"],\"address\":\"2001:0db8::1\",\"port\":25565},"
		"{\"vhost\":[\"v6-b.example\"],\"address\":\"2001:db8::1\",\"port\":25565},"
		"{\"vhost\":[\"name-a.example\"],\"address\":\"Example.COM.\",\"port\":25566},"
		"{\"vhost\":[\"name-b.example\"],\"address\":\"example.com\",\"port\":25566},"
		"{\"vhost\":[\"srv-a.example\"],\"address\":\"Example.COM.\"},"
		"{\"vhost\":[\"srv-b.example\"],\"address\":\"example.com\"},"
		"{\"vhost\":[\"other-port.example\"],\"address\":\"example.com\",\"port\":25567},"
		"{\"vhost\":[\"odd.\"],\"address\":\"bad name\",\"port\":25565},"
		"{\"vhost\":[],\"address\":\"unused.example\",\"port\":25565}"
	"]";
	bool test_result = false;
	conf config;
	memset(&config, 0, sizeof(config));
	route_table *table = NULL;
	config.proxy = cJSON_Parse(json);
	CHECK(config.proxy != NULL && route_table_build(&config, &table) == ROUTE_TABLE_BUILD_OK && table != NULL, "route table could not be built");
	CHECK(route_table_route_count(table) == 11 && route_table_destination_count(table) == 6, "route or deduplicated destination count was incorrect");
	route_view route;
	CHECK(route_table_find(table, "alpha.example.", &route) && strcmp(route.vhost, "Alpha.Example") == 0 && strcmp(route.configured_address, "192.0.2.1") == 0
		&& route.destination_index == 0 && route.rewrite && !route.pheader, "case-insensitive route lookup or flags were incorrect");
	CHECK(route_table_find(table, "gamma.example", &route) && route.destination_index == 0 && route.pheader && !route.rewrite, "shared numeric destination was not reused");
	CHECK(!route_table_find(table, "odd.", &route) && route_table_find(table, "odd..", &route), "legacy configured-vhost terminal-dot behavior changed");
	route_destination_view destination;
	CHECK(route_table_destination_get(table, 0, &destination) && destination.numeric && destination.numeric_address.family == AF_INET && destination.port == 25565
		&& destination.query_name == NULL && !destination.srv, "IPv4 destination was invalid");
	CHECK(route_table_destination_get(table, 1, &destination) && destination.numeric && destination.numeric_address.family == AF_INET6 && destination.port == 25565,
		"equivalent IPv6 literals were not deduplicated");
	CHECK(route_table_destination_get(table, 2, &destination) && !destination.numeric && strcmp(destination.query_name, "example.com") == 0 && destination.port == 25566 && !destination.srv,
		"explicit-port DNS destination was not normalized");
	CHECK(destination.numeric_address.family == 0 && destination.numeric_address.err == NET_OK, "name destination retained numeric-parser error state");
	CHECK(route_table_destination_get(table, 3, &destination) && !destination.numeric && strcmp(destination.query_name, "_minecraft._tcp.example.com") == 0 && destination.port == 0 && destination.srv,
		"SRV owner was not prepared exactly");
	CHECK(route_table_destination_get(table, 4, &destination) && !destination.numeric && strcmp(destination.query_name, "example.com") == 0 && destination.port == 25567,
		"different explicit ports were incorrectly deduplicated");
	CHECK(route_table_destination_get(table, 5, &destination) && !destination.numeric && strcmp(destination.query_name, "bad name") == 0,
		"unresolvable destination was not retained for route-local failure");
	test_result = true;

cleanup:
	route_table_destroy(table);
	cJSON_Delete(config.proxy);
	return test_result;
}

/* section: functions (entry point) */
int main(void) {
	int result = EXIT_FAILURE;
	CHECK(route_test_arguments(), "route argument tests failed");
	CHECK(route_test_invalid(), "route invalid-input tests failed");
	CHECK(route_test_names(), "route name tests failed");
	CHECK(route_test_routes(), "route preparation tests failed");
	result = EXIT_SUCCESS;

cleanup:
	return result;
}
