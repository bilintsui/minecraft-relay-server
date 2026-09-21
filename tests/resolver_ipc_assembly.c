/*
 * resolver_ipc_assembly.c: Tests for listener-side resolver IPC response assembly
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

/* section: headers (project) */
#include "resolver/cache.h"
#include "resolver/dns.h"
#include "resolver/ipc.h"
#include "resolver/ipc_assembly.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* section: global variables */
static size_t assembly_calloc_failures;

void *__real_calloc(size_t count, size_t size);

/* section: functions (local) */
static resolver_ipc_assembly_status assembly_address_send(resolver_ipc_assembly *assembly, const resolver_ipc_response_address *response) {
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_address_encode(response, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK) {
		return RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT;
	}
	return resolver_ipc_assembly_packet_consume(assembly, packet, packet_size);
}

static resolver_ipc_assembly_status assembly_begin_send(resolver_ipc_assembly *assembly, const resolver_ipc_response_begin *response) {
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_begin_encode(response, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK) {
		return RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT;
	}
	return resolver_ipc_assembly_packet_consume(assembly, packet, packet_size);
}

static resolver_ipc_assembly_status assembly_cname_send(resolver_ipc_assembly *assembly, const resolver_ipc_response_cname *response) {
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_cname_encode(response, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK) {
		return RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT;
	}
	return resolver_ipc_assembly_packet_consume(assembly, packet, packet_size);
}

static resolver_ipc_assembly_status assembly_end_send(resolver_ipc_assembly *assembly, const resolver_ipc_response_end *response) {
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_end_encode(response, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK) {
		return RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT;
	}
	return resolver_ipc_assembly_packet_consume(assembly, packet, packet_size);
}

static resolver_ipc_assembly *assembly_new(resolver_ipc_assembly_budget *budget, const char *query_name, uint16_t query_type, uint64_t query_id) {
	resolver_ipc_assembly *assembly = NULL;
	return resolver_ipc_assembly_create(budget, query_name, ns_c_in, query_type, query_id, &assembly) == RESOLVER_IPC_ASSEMBLY_OK ? assembly : NULL;
}

static bool assembly_reset(resolver_ipc_assembly_budget *budget, resolver_ipc_assembly **assembly, const char *query_name, uint16_t query_type, uint64_t query_id) {
	resolver_ipc_assembly_destroy(*assembly);
	*assembly = assembly_new(budget, query_name, query_type, query_id);
	return *assembly != NULL;
}

static resolver_ipc_assembly_status assembly_srv_send(resolver_ipc_assembly *assembly, const resolver_ipc_response_srv *response) {
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT];
	size_t packet_size;
	if (resolver_ipc_response_srv_encode(response, packet, sizeof(packet), &packet_size) != RESOLVER_IPC_CODEC_OK) {
		return RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT;
	}
	return resolver_ipc_assembly_packet_consume(assembly, packet, packet_size);
}

static bool assembly_test_address(void) {
	int test_result = false;
	resolver_ipc_assembly_budget *budget = resolver_ipc_assembly_budget_create();
	resolver_ipc_assembly *assembly = assembly_new(budget, "Alias.Address.Test.", ns_t_a, 11);
	resolver_cache *cache = resolver_cache_create();
	resolver_cache_entry *entry = NULL;
	resolver_ipc_assembly_result result = { 0 };
	CHECK(budget != NULL && assembly != NULL && cache != NULL, "address assembly could not be created");
	CHECK(resolver_cache_entry_acquire(cache, "alias.address.test", ns_t_a, &entry) == RESOLVER_CACHE_ACQUIRE_OK, "address cache entry could not be created");
	resolver_ipc_response_begin begin = {
		.canonical_name = "backend.address.test",
		.cname_count = 1,
		.completed_at = { .tv_sec = 100, .tv_nsec = 200 },
		.question_name = "alias.address.test",
		.query_class = ns_c_in,
		.query_id = 11,
		.query_type = ns_t_a,
		.rcode = ns_r_noerror,
		.record_count = 2,
		.status = RESOLVER_IPC_LOOKUP_OK
	};
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK, "address response BEGIN was rejected");
	CHECK(!resolver_ipc_assembly_result_take(assembly, &result), "incomplete address result was transferred");
	resolver_ipc_response_cname cname = { .record = { .owner = "alias.address.test", .target = "backend.address.test", .ttl = 40 }, .index = 0, .query_id = 11 };
	CHECK(assembly_cname_send(assembly, &cname) == RESOLVER_IPC_ASSEMBLY_OK, "address response CNAME was rejected");
	resolver_ipc_response_address address = { .index = 0, .query_id = 11, .record = { .address = { .family = AF_INET }, .effective_ttl = 40, .record_ttl = 100 } };
	address.record.address.addr.v4 = htonl(UINT32_C(0xC0000201));
	CHECK(assembly_address_send(assembly, &address) == RESOLVER_IPC_ASSEMBLY_OK, "first address response record was rejected");
	address.index = 1;
	address.record.address.addr.v4 = htonl(UINT32_C(0xC0000202));
	address.record.effective_ttl = 20;
	address.record.record_ttl = 20;
	CHECK(assembly_address_send(assembly, &address) == RESOLVER_IPC_ASSEMBLY_OK, "second address response record was rejected");
	resolver_ipc_response_end end = { .cname_count = 1, .query_id = 11, .record_count = 2 };
	CHECK(assembly_end_send(assembly, &end) == RESOLVER_IPC_ASSEMBLY_COMPLETE, "address response END did not complete the assembly");
	size_t owned_before_take = resolver_ipc_assembly_budget_owned_bytes(budget);
	CHECK(resolver_ipc_assembly_result_take(assembly, &result), "complete address result could not be transferred");
	CHECK(resolver_ipc_assembly_budget_owned_bytes(budget) == owned_before_take, "transferred address arrays escaped the assembly budget");
	CHECK(result.query_id == 11 && result.query_type == ns_t_a && result.status == RESOLVER_IPC_LOOKUP_OK && result.completed_at.tv_sec == 100 && result.completed_at.tv_nsec == 200,
		"address result metadata was not preserved");
	CHECK(result.payload.address.address_count == 2 && result.payload.address.cname_count == 1 && strcmp(result.payload.address.question_name, "alias.address.test") == 0
		&& strcmp(result.payload.address.canonical_name, "backend.address.test") == 0, "address result shape was not preserved");
	CHECK(result.payload.address.addresses[0].address.addr.v4 == htonl(UINT32_C(0xC0000201))
		&& result.payload.address.addresses[1].address.addr.v4 == htonl(UINT32_C(0xC0000202)), "address result records were not preserved");
	CHECK(!resolver_ipc_assembly_result_take(assembly, &(resolver_ipc_assembly_result){ 0 }), "address result was transferred twice");
	CHECK(assembly_end_send(assembly, &end) == RESOLVER_IPC_ASSEMBLY_PROTOCOL, "packet after transferred response was accepted");
	dns_address_lookup_status lookup_status;
	CHECK(resolver_ipc_lookup_status_to_address(result.status, &lookup_status), "address result status could not be converted");
	CHECK(resolver_cache_entry_publish_address(entry, lookup_status, &result.completed_at, &result.payload.address) == RESOLVER_CACHE_PUBLISH_STORED,
		"assembled address result could not be published");
	resolver_ipc_assembly_result_destroy(&result);
	CHECK(resolver_ipc_assembly_budget_owned_bytes(budget) < owned_before_take, "destroyed address result remained charged to the assembly budget");
	resolver_cache_view view;
	struct timespec now = { .tv_sec = 119 };
	CHECK(resolver_cache_entry_view(entry, &now, &view) && view.status == RESOLVER_CACHE_VIEW_FRESH_POSITIVE && view.address_count == 2,
		"published address result was not available from the cache");
	test_result = true;

cleanup:
	resolver_ipc_assembly_result_destroy(&result);
	resolver_ipc_assembly_destroy(assembly);
	resolver_ipc_assembly_budget_destroy(budget);
	resolver_cache_entry_release(entry);
	resolver_cache_destroy(cache);
	return test_result;
}

static bool assembly_test_arguments(void) {
	int test_result = false;
	resolver_ipc_assembly_budget *budget = resolver_ipc_assembly_budget_create();
	resolver_ipc_assembly *assembly = NULL;
	resolver_ipc_assembly_result result = { 0 };
	uint8_t packet[1] = { 0 };
	CHECK(budget != NULL, "assembly budget could not be created");
	CHECK(resolver_ipc_assembly_create(NULL, "argument.test", ns_c_in, ns_t_a, 1, &assembly) == RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT && assembly == NULL,
		"NULL assembly budget was accepted");
	CHECK(resolver_ipc_assembly_create(budget, NULL, ns_c_in, ns_t_a, 1, &assembly) == RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT && assembly == NULL, "NULL assembly name was accepted");
	CHECK(resolver_ipc_assembly_create(budget, "", ns_c_in, ns_t_a, 1, &assembly) == RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT && assembly == NULL, "empty assembly name was accepted");
	CHECK(resolver_ipc_assembly_create(budget, "argument.test", ns_c_chaos, ns_t_a, 1, &assembly) == RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT && assembly == NULL,
		"unsupported assembly class was accepted");
	CHECK(resolver_ipc_assembly_create(budget, "argument.test", ns_c_in, ns_t_txt, 1, &assembly) == RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT && assembly == NULL,
		"unsupported assembly type was accepted");
	CHECK(resolver_ipc_assembly_create(budget, "argument.test", ns_c_in, ns_t_a, 0, &assembly) == RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT && assembly == NULL,
		"zero assembly query ID was accepted");
	CHECK(resolver_ipc_assembly_create(budget, "argument.test", ns_c_in, ns_t_a, 1, NULL) == RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT, "NULL assembly result was accepted");
	assembly = assembly_new(budget, "argument.test", ns_t_a, 1);
	CHECK(assembly != NULL, "argument assembly could not be created");
	CHECK(resolver_ipc_assembly_packet_consume(NULL, packet, sizeof(packet)) == RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT, "NULL assembly consumed a packet");
	CHECK(resolver_ipc_assembly_packet_consume(assembly, NULL, 0) == RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT, "NULL packet was consumed");
	CHECK(!resolver_ipc_assembly_result_take(NULL, &result) && !resolver_ipc_assembly_result_take(assembly, NULL), "NULL result-transfer argument was accepted");
	CHECK(resolver_ipc_assembly_budget_owned_bytes(NULL) == 0, "NULL assembly budget reported owned bytes");
	resolver_ipc_assembly_destroy(NULL);
	resolver_ipc_assembly_result_destroy(NULL);
	resolver_ipc_assembly_budget_destroy(NULL);
	test_result = true;

cleanup:
	resolver_ipc_assembly_result_destroy(&result);
	resolver_ipc_assembly_destroy(assembly);
	resolver_ipc_assembly_budget_destroy(budget);
	return test_result;
}

static bool assembly_test_budget(void) {
	int test_result = false;
	resolver_ipc_assembly_budget *budget = resolver_ipc_assembly_budget_create();
	resolver_ipc_assembly *assembly = NULL;
	resolver_ipc_assembly *assemblies[64] = { NULL };
	size_t assembly_count = 0;
	CHECK(budget != NULL, "assembly budget could not be created");
	while (assembly_count < sizeof(assemblies) / sizeof(assemblies[0])) {
		resolver_ipc_assembly_status status = resolver_ipc_assembly_create(budget, "capacity.test", ns_c_in, ns_t_a, assembly_count + 1, &assemblies[assembly_count]);
		if (status == RESOLVER_IPC_ASSEMBLY_LIMIT) {
			break;
		}
		CHECK(status == RESOLVER_IPC_ASSEMBLY_OK && assemblies[assembly_count] != NULL, "assembly capacity failed unexpectedly");
		assembly_count++;
	}
	CHECK(assembly_count > 0 && assembly_count < sizeof(assemblies) / sizeof(assemblies[0]), "assembly metadata limit was not enforced");
	CHECK(resolver_ipc_assembly_budget_owned_bytes(budget) <= RESOLVER_REPLY_ASSEMBLY_BYTE_LIMIT, "assembly metadata exceeded its budget");
	resolver_ipc_assembly_destroy(assemblies[--assembly_count]);
	assemblies[assembly_count] = NULL;
	CHECK(resolver_ipc_assembly_create(budget, "capacity.test", ns_c_in, ns_t_a, 1000, &assembly) == RESOLVER_IPC_ASSEMBLY_OK && assembly != NULL,
		"released assembly capacity was not reusable");
	resolver_ipc_response_begin begin = {
		.canonical_name = "target.capacity.test",
		.cname_count = 1,
		.completed_at = { .tv_sec = 1 },
		.question_name = "capacity.test",
		.query_class = ns_c_in,
		.query_id = 1000,
		.query_type = ns_t_a,
		.rcode = ns_r_noerror,
		.record_count = 1,
		.status = RESOLVER_IPC_LOOKUP_OK
	};
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_LIMIT, "oversized aggregate reply allocation was accepted");
	CHECK(resolver_ipc_assembly_budget_owned_bytes(budget) <= RESOLVER_REPLY_ASSEMBLY_BYTE_LIMIT, "failed reply allocation changed the budget incorrectly");
	resolver_ipc_assembly_destroy(assembly);
	assembly = NULL;
	for (size_t index = 0; index < assembly_count; index++) {
		resolver_ipc_assembly_destroy(assemblies[index]);
		assemblies[index] = NULL;
	}
	assembly_count = 0;
	assembly = assembly_new(budget, "capacity.test", ns_t_a, 1001);
	begin.query_id = 1001;
	CHECK(assembly != NULL && assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK, "reply allocation did not fit after aggregate capacity was released");
	resolver_ipc_assembly_metrics_snapshot metrics;
	CHECK(resolver_ipc_assembly_metrics_get(budget, &metrics) && metrics.query[METRICS_QUERY_TYPE_A].create_limit == 1
		&& metrics.query[METRICS_QUERY_TYPE_A].limit_budget_bytes == 2 && metrics.query[METRICS_QUERY_TYPE_A].terminal_limit == 1,
		"assembly budget-limit metrics were incorrect");
	test_result = true;

cleanup:
	resolver_ipc_assembly_destroy(assembly);
	for (size_t index = 0; index < assembly_count; index++) {
		resolver_ipc_assembly_destroy(assemblies[index]);
	}
	resolver_ipc_assembly_budget_destroy(budget);
	return test_result;
}

static bool assembly_test_metrics(void) {
	int test_result = false;
	resolver_ipc_assembly_budget *budget = resolver_ipc_assembly_budget_create();
	resolver_ipc_assembly *assembly = NULL;
	resolver_ipc_assembly_result result = { 0 };
	resolver_ipc_assembly_metrics_snapshot metrics;
	memset(&metrics, 0xFF, sizeof(metrics));
	CHECK(!resolver_ipc_assembly_metrics_get(NULL, &metrics) && metrics.nonterminal_current == 0
		&& metrics.query[METRICS_QUERY_TYPE_A].create_ok == 0, "NULL assembly metrics input was accepted or left output data behind");
	CHECK(budget != NULL && resolver_ipc_assembly_metrics_get(budget, &metrics), "assembly metrics budget could not be created or read");
	uint64_t baseline_bytes = metrics.owned_bytes_current;
	CHECK(baseline_bytes > 0 && metrics.owned_bytes_high_water == baseline_bytes, "initial assembly metrics gauges were incorrect");
	CHECK(resolver_ipc_assembly_create(budget, NULL, ns_c_in, ns_t_a, 1, &assembly) == RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT && assembly == NULL,
		"attributable bad assembly create was accepted");
	CHECK(resolver_ipc_assembly_create(budget, "invalid.metrics.test", ns_c_in, ns_t_txt, 1, &assembly) == RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT && assembly == NULL,
		"unattributable assembly create was accepted");
	assembly_calloc_failures = 1;
	CHECK(resolver_ipc_assembly_create(budget, "memory.metrics.test", ns_c_in, ns_t_aaaa, 2, &assembly) == RESOLVER_IPC_ASSEMBLY_MEMORY && assembly == NULL,
		"assembly create allocation failure was not reported");
	assembly = assembly_new(budget, "abandoned.metrics.test", ns_t_a, 3);
	CHECK(assembly != NULL && resolver_ipc_assembly_metrics_get(budget, &metrics) && metrics.nonterminal_current == 1
		&& metrics.query[METRICS_QUERY_TYPE_A].nonterminal_current == 1, "live assembly metrics were incorrect");
	resolver_ipc_assembly_destroy(assembly);
	assembly = assembly_new(budget, "complete.metrics.test", ns_t_aaaa, 4);
	CHECK(assembly != NULL, "complete metrics assembly could not be created");
	resolver_ipc_response_begin begin = {
		.canonical_name = "complete.metrics.test",
		.completed_at = { .tv_sec = 1 },
		.question_name = "complete.metrics.test",
		.query_class = ns_c_in,
		.query_id = 4,
		.query_type = ns_t_aaaa,
		.rcode = ns_r_noerror,
		.status = RESOLVER_IPC_LOOKUP_NODATA
	};
	resolver_ipc_response_end end = { .query_id = 4 };
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK && assembly_end_send(assembly, &end) == RESOLVER_IPC_ASSEMBLY_COMPLETE
		&& resolver_ipc_assembly_result_take(assembly, &result), "complete assembly metrics result did not finish");
	resolver_ipc_assembly_destroy(assembly);
	assembly = NULL;
	resolver_ipc_assembly_result_destroy(&result);
	assembly = assembly_new(budget, "memory.metrics.test", ns_t_a, 5);
	CHECK(assembly != NULL, "terminal-memory metrics assembly could not be created");
	begin = (resolver_ipc_response_begin){
		.canonical_name = "memory.metrics.test",
		.completed_at = { .tv_sec = 1 },
		.question_name = "memory.metrics.test",
		.query_class = ns_c_in,
		.query_id = 5,
		.query_type = ns_t_a,
		.rcode = ns_r_noerror,
		.record_count = 1,
		.status = RESOLVER_IPC_LOOKUP_OK
	};
	assembly_calloc_failures = 1;
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_MEMORY, "assembly terminal allocation failure was not reported");
	resolver_ipc_assembly_destroy(assembly);
	assembly = assembly_new(budget, "_minecraft._tcp.bytes.metrics.test", ns_t_srv, 7);
	CHECK(assembly != NULL, "result-byte metrics assembly could not be created");
	begin = (resolver_ipc_response_begin){
		.canonical_name = "_minecraft._tcp.bytes.metrics.test",
		.completed_at = { .tv_sec = 1 },
		.question_name = "_minecraft._tcp.bytes.metrics.test",
		.query_class = ns_c_in,
		.query_id = 7,
		.query_type = ns_t_srv,
		.rcode = ns_r_noerror,
		.record_count = DNS_SRV_RECORD_LIMIT,
		.status = RESOLVER_IPC_LOOKUP_OK
	};
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_LIMIT, "assembly result-byte limit was not reported");
	resolver_ipc_assembly_destroy(assembly);
	assembly = NULL;
	CHECK(resolver_ipc_assembly_metrics_get(budget, &metrics), "final assembly metrics could not be read");
	const resolver_ipc_assembly_metrics_query *a = &metrics.query[METRICS_QUERY_TYPE_A];
	const resolver_ipc_assembly_metrics_query *aaaa = &metrics.query[METRICS_QUERY_TYPE_AAAA];
	const resolver_ipc_assembly_metrics_query *srv = &metrics.query[METRICS_QUERY_TYPE_SRV];
	CHECK(a->create_ok == 2 && a->create_bad_argument == 1 && a->limit_result_shape == 0 && a->terminal_memory == 1
		&& a->abandoned == 1 && a->nonterminal_current == 0, "A assembly metrics were incorrect");
	CHECK(aaaa->create_ok == 1 && aaaa->create_memory == 1 && aaaa->terminal_complete == 1 && aaaa->nonterminal_current == 0
		&& metrics.result_size[METRICS_QUERY_TYPE_AAAA].count == 1 && metrics.result_size[METRICS_QUERY_TYPE_AAAA].sum == 0,
		"AAAA assembly metrics were incorrect");
	CHECK(srv->create_ok == 1 && srv->limit_result_bytes == 1 && srv->terminal_limit == 1 && srv->nonterminal_current == 0,
		"SRV assembly metrics were incorrect");
	CHECK(metrics.nonterminal_current == 0 && metrics.owned_bytes_current == baseline_bytes && metrics.owned_bytes_high_water > baseline_bytes
		&& metrics.saturation_total == 0, "assembly aggregate metrics were incorrect");
	CHECK(a->create_ok == a->terminal_memory + a->abandoned + a->nonterminal_current
		&& aaaa->create_ok == aaaa->terminal_complete + aaaa->nonterminal_current
		&& srv->create_ok == srv->terminal_limit + srv->nonterminal_current, "assembly conservation identities did not hold");
	test_result = true;

cleanup:
	assembly_calloc_failures = 0;
	resolver_ipc_assembly_result_destroy(&result);
	resolver_ipc_assembly_destroy(assembly);
	resolver_ipc_assembly_budget_destroy(budget);
	return test_result;
}

static bool assembly_test_negative(void) {
	int test_result = false;
	resolver_ipc_assembly_budget *budget = resolver_ipc_assembly_budget_create();
	resolver_ipc_assembly *assembly = assembly_new(budget, "alias.negative.test", ns_t_aaaa, 21);
	resolver_ipc_assembly_result result = { 0 };
	CHECK(budget != NULL && assembly != NULL, "negative assembly could not be created");
	resolver_ipc_response_begin begin = {
		.canonical_name = "target.negative.test",
		.cname_count = 1,
		.completed_at = { .tv_sec = 300, .tv_nsec = 400 },
		.negative = { .effective_ttl = 20, .minimum = 30, .owner = "negative.test", .record_ttl = 40, .valid = true },
		.question_name = "alias.negative.test",
		.query_class = ns_c_in,
		.query_id = 21,
		.query_type = ns_t_aaaa,
		.rcode = ns_r_noerror,
		.status = RESOLVER_IPC_LOOKUP_NODATA
	};
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK, "negative response BEGIN was rejected");
	resolver_ipc_response_cname cname = { .record = { .owner = "alias.negative.test", .target = "target.negative.test", .ttl = 20 }, .index = 0, .query_id = 21 };
	CHECK(assembly_cname_send(assembly, &cname) == RESOLVER_IPC_ASSEMBLY_OK, "negative response CNAME was rejected");
	resolver_ipc_response_end end = { .cname_count = 1, .query_id = 21 };
	CHECK(assembly_end_send(assembly, &end) == RESOLVER_IPC_ASSEMBLY_COMPLETE && resolver_ipc_assembly_result_take(assembly, &result), "negative response did not complete");
	CHECK(result.status == RESOLVER_IPC_LOOKUP_NODATA && result.payload.address.addresses == NULL && result.payload.address.address_count == 0
		&& result.payload.address.negative.valid && result.payload.address.negative.effective_ttl == 20, "negative result was not preserved");
	resolver_ipc_assembly_result_destroy(&result);
	CHECK(assembly_reset(budget, &assembly, "missing.negative.test", ns_t_srv, 22), "NXDOMAIN assembly could not be created");
	begin = (resolver_ipc_response_begin){
		.canonical_name = "missing.negative.test",
		.completed_at = { .tv_sec = 500 },
		.question_name = "missing.negative.test",
		.query_class = ns_c_in,
		.query_id = 22,
		.query_type = ns_t_srv,
		.rcode = ns_r_nxdomain,
		.status = RESOLVER_IPC_LOOKUP_NOT_FOUND
	};
	end = (resolver_ipc_response_end){ .query_id = 22 };
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK && assembly_end_send(assembly, &end) == RESOLVER_IPC_ASSEMBLY_COMPLETE
		&& resolver_ipc_assembly_result_take(assembly, &result), "NXDOMAIN response without SOA did not complete");
	CHECK(result.status == RESOLVER_IPC_LOOKUP_NOT_FOUND && !result.payload.srv.negative.valid, "NXDOMAIN response metadata was not preserved");
	resolver_ipc_assembly_result_destroy(&result);
	CHECK(assembly_reset(budget, &assembly, "resolver.missing.test", ns_t_srv, 23), "resolver-level negative assembly could not be created");
	begin = (resolver_ipc_response_begin){ .completed_at = { .tv_sec = 550 }, .query_class = ns_c_in, .query_id = 23, .query_type = ns_t_srv,
		.status = RESOLVER_IPC_LOOKUP_NOT_FOUND };
	end = (resolver_ipc_response_end){ .query_id = 23 };
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK && assembly_end_send(assembly, &end) == RESOLVER_IPC_ASSEMBLY_COMPLETE
		&& resolver_ipc_assembly_result_take(assembly, &result), "resolver-level negative response did not complete");
	CHECK(result.status == RESOLVER_IPC_LOOKUP_NOT_FOUND && result.payload.srv.question_name[0] == '\0' && !result.payload.srv.negative.valid,
		"resolver-level negative result was not preserved");
	resolver_ipc_assembly_result_destroy(&result);
	CHECK(assembly_reset(budget, &assembly, "temporary.error.test", ns_t_a, 24), "temporary-error assembly could not be created");
	begin = (resolver_ipc_response_begin){ .completed_at = { .tv_sec = 600 }, .query_class = ns_c_in, .query_id = 24, .query_type = ns_t_a,
		.status = RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR };
	end = (resolver_ipc_response_end){ .query_id = 24 };
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK && assembly_end_send(assembly, &end) == RESOLVER_IPC_ASSEMBLY_COMPLETE
		&& resolver_ipc_assembly_result_take(assembly, &result), "temporary-error response did not complete");
	CHECK(result.status == RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR && result.payload.address.question_name[0] == '\0', "temporary-error result was not preserved");
	test_result = true;

cleanup:
	resolver_ipc_assembly_result_destroy(&result);
	resolver_ipc_assembly_destroy(assembly);
	resolver_ipc_assembly_budget_destroy(budget);
	return test_result;
}

static bool assembly_test_protocol(void) {
	int test_result = false;
	resolver_ipc_assembly_budget *budget = resolver_ipc_assembly_budget_create();
	resolver_ipc_assembly *assembly = assembly_new(budget, "protocol.test", ns_t_a, 31);
	CHECK(budget != NULL && assembly != NULL, "protocol assembly could not be created");
	resolver_ipc_response_address address = { .query_id = 31, .record = { .address = { .family = AF_INET }, .effective_ttl = 10, .record_ttl = 10 } };
	CHECK(assembly_address_send(assembly, &address) == RESOLVER_IPC_ASSEMBLY_PROTOCOL, "record before BEGIN was accepted");
	CHECK(assembly_reset(budget, &assembly, "protocol.test", ns_t_a, 32), "protocol assembly could not be reset");
	resolver_ipc_response_begin begin = {
		.canonical_name = "canonical.protocol.test",
		.cname_count = 1,
		.completed_at = { .tv_sec = 1 },
		.question_name = "protocol.test",
		.query_class = ns_c_in,
		.query_id = 999,
		.query_type = ns_t_a,
		.rcode = ns_r_noerror,
		.record_count = 1,
		.status = RESOLVER_IPC_LOOKUP_OK
	};
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_PROTOCOL, "mismatched BEGIN query ID was accepted");
	CHECK(assembly_reset(budget, &assembly, "protocol.test", ns_t_a, 33), "protocol assembly could not be reset");
	begin.query_id = 33;
	begin.question_name[0] = 'x';
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_PROTOCOL, "mismatched BEGIN question was accepted");
	CHECK(assembly_reset(budget, &assembly, "protocol.test", ns_t_a, 34), "protocol assembly could not be reset");
	memcpy(begin.question_name, "protocol.test", sizeof("protocol.test"));
	begin.query_id = 34;
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK, "valid protocol BEGIN was rejected");
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_PROTOCOL, "duplicate BEGIN was accepted");
	CHECK(assembly_reset(budget, &assembly, "protocol.test", ns_t_a, 35), "protocol assembly could not be reset");
	begin.query_id = 35;
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK, "valid protocol BEGIN was rejected");
	address.query_id = 35;
	CHECK(assembly_address_send(assembly, &address) == RESOLVER_IPC_ASSEMBLY_PROTOCOL, "address before declared CNAME was accepted");
	CHECK(assembly_reset(budget, &assembly, "protocol.test", ns_t_a, 36), "protocol assembly could not be reset");
	begin.query_id = 36;
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK, "valid protocol BEGIN was rejected");
	resolver_ipc_response_cname cname = { .record = { .owner = "protocol.test", .target = "protocol.test", .ttl = 10 }, .index = 0, .query_id = 36 };
	CHECK(assembly_cname_send(assembly, &cname) == RESOLVER_IPC_ASSEMBLY_PROTOCOL, "CNAME loop was accepted");
	CHECK(assembly_reset(budget, &assembly, "protocol.test", ns_t_a, 37), "protocol assembly could not be reset");
	begin.query_id = 37;
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK, "valid protocol BEGIN was rejected");
	cname.query_id = 37;
	memcpy(cname.record.target, "canonical.protocol.test", sizeof("canonical.protocol.test"));
	CHECK(assembly_cname_send(assembly, &cname) == RESOLVER_IPC_ASSEMBLY_OK, "valid protocol CNAME was rejected");
	address.query_id = 37;
	address.record.effective_ttl = 11;
	address.record.record_ttl = 20;
	CHECK(assembly_address_send(assembly, &address) == RESOLVER_IPC_ASSEMBLY_PROTOCOL, "address with an invalid chain TTL was accepted");
	CHECK(assembly_reset(budget, &assembly, "protocol.test", ns_t_a, 38), "protocol assembly could not be reset");
	begin.query_id = 38;
	begin.canonical_name[0] = 'x';
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK, "canonical-mismatch BEGIN was rejected too early");
	cname.query_id = 38;
	CHECK(assembly_cname_send(assembly, &cname) == RESOLVER_IPC_ASSEMBLY_OK, "canonical-mismatch CNAME was rejected");
	address.query_id = 38;
	address.record.effective_ttl = 10;
	address.record.record_ttl = 20;
	CHECK(assembly_address_send(assembly, &address) == RESOLVER_IPC_ASSEMBLY_OK, "canonical-mismatch address was rejected");
	resolver_ipc_response_end end = { .cname_count = 1, .query_id = 38, .record_count = 1 };
	CHECK(assembly_end_send(assembly, &end) == RESOLVER_IPC_ASSEMBLY_PROTOCOL, "mismatched canonical chain was completed");
	CHECK(assembly_reset(budget, &assembly, "protocol.test", ns_t_a, 39), "protocol assembly could not be reset");
	memcpy(begin.canonical_name, "protocol.test", sizeof("protocol.test"));
	begin.cname_count = 0;
	begin.query_id = 39;
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK, "post-END protocol BEGIN was rejected");
	address.query_id = 39;
	address.record.effective_ttl = 10;
	address.record.record_ttl = 10;
	CHECK(assembly_address_send(assembly, &address) == RESOLVER_IPC_ASSEMBLY_OK, "post-END protocol address was rejected");
	end = (resolver_ipc_response_end){ .query_id = 39, .record_count = 1 };
	CHECK(assembly_end_send(assembly, &end) == RESOLVER_IPC_ASSEMBLY_COMPLETE, "post-END protocol result did not complete");
	resolver_ipc_assembly_metrics_snapshot metrics_before;
	resolver_ipc_assembly_metrics_snapshot metrics_after;
	CHECK(resolver_ipc_assembly_metrics_get(budget, &metrics_before), "pre-duplicate-END metrics could not be read");
	CHECK(assembly_end_send(assembly, &end) == RESOLVER_IPC_ASSEMBLY_PROTOCOL, "duplicate END was accepted");
	CHECK(resolver_ipc_assembly_metrics_get(budget, &metrics_after)
		&& metrics_after.query[METRICS_QUERY_TYPE_A].terminal_complete == metrics_before.query[METRICS_QUERY_TYPE_A].terminal_complete
		&& metrics_after.query[METRICS_QUERY_TYPE_A].terminal_protocol == metrics_before.query[METRICS_QUERY_TYPE_A].terminal_protocol,
		"duplicate END produced a second assembly terminal");
	CHECK(!resolver_ipc_assembly_result_take(assembly, &(resolver_ipc_assembly_result){ 0 }), "result remained transferable after duplicate END");
	CHECK(assembly_reset(budget, &assembly, "protocol.test", ns_t_a, 40), "protocol assembly could not be reset");
	begin = (resolver_ipc_response_begin){
		.canonical_name = "protocol.test",
		.completed_at = { .tv_sec = 1 },
		.negative = { .effective_ttl = 10, .minimum = 10, .owner = "other.test", .record_ttl = 10, .valid = true },
		.question_name = "protocol.test",
		.query_class = ns_c_in,
		.query_id = 40,
		.query_type = ns_t_a,
		.rcode = ns_r_noerror,
		.status = RESOLVER_IPC_LOOKUP_NODATA
	};
	end = (resolver_ipc_response_end){ .query_id = 40 };
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK, "negative-owner protocol BEGIN was rejected too early");
	CHECK(assembly_end_send(assembly, &end) == RESOLVER_IPC_ASSEMBLY_PROTOCOL, "negative owner outside the canonical name was accepted");
	CHECK(assembly_reset(budget, &assembly, "protocol.test", ns_t_a, 41), "protocol assembly could not be reset");
	begin = (resolver_ipc_response_begin){
		.completed_at = { .tv_sec = 1 },
		.question_name = "protocol.test",
		.query_class = ns_c_in,
		.query_id = 41,
		.query_type = ns_t_a,
		.rcode = ns_r_refused,
		.status = RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR
	};
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_PROTOCOL, "temporary status accepted a non-SERVFAIL RCODE");
	test_result = true;

cleanup:
	resolver_ipc_assembly_destroy(assembly);
	resolver_ipc_assembly_budget_destroy(budget);
	return test_result;
}

static bool assembly_test_srv(void) {
	int test_result = false;
	resolver_ipc_assembly_budget *budget = resolver_ipc_assembly_budget_create();
	resolver_ipc_assembly *assembly = assembly_new(budget, "_minecraft._tcp.srv.test", ns_t_srv, 41);
	resolver_ipc_assembly_result result = { 0 };
	CHECK(budget != NULL && assembly != NULL, "SRV assembly could not be created");
	resolver_ipc_response_begin begin = {
		.canonical_name = "_minecraft._tcp.srv.test",
		.completed_at = { .tv_sec = 700, .tv_nsec = 800 },
		.question_name = "_minecraft._tcp.srv.test",
		.query_class = ns_c_in,
		.query_id = 41,
		.query_type = ns_t_srv,
		.rcode = ns_r_noerror,
		.record_count = 2,
		.status = RESOLVER_IPC_LOOKUP_OK
	};
	CHECK(assembly_begin_send(assembly, &begin) == RESOLVER_IPC_ASSEMBLY_OK, "SRV response BEGIN was rejected");
	resolver_ipc_response_srv srv = { .index = 0, .query_id = 41, .record = { .effective_ttl = 60, .port = 25565, .priority = 10, .record_ttl = 60,
		.target = "backend.srv.test", .weight = 20 } };
	CHECK(assembly_srv_send(assembly, &srv) == RESOLVER_IPC_ASSEMBLY_OK, "first SRV response record was rejected");
	srv.index = 1;
	srv.record.effective_ttl = 30;
	srv.record.port = 0;
	srv.record.priority = 0;
	srv.record.record_ttl = 30;
	memcpy(srv.record.target, ".", sizeof("."));
	srv.record.weight = 0;
	CHECK(assembly_srv_send(assembly, &srv) == RESOLVER_IPC_ASSEMBLY_OK, "second SRV response record was rejected");
	resolver_ipc_response_end end = { .query_id = 41, .record_count = 2 };
	CHECK(assembly_end_send(assembly, &end) == RESOLVER_IPC_ASSEMBLY_COMPLETE && resolver_ipc_assembly_result_take(assembly, &result), "SRV response did not complete");
	CHECK(result.query_type == ns_t_srv && result.status == RESOLVER_IPC_LOOKUP_OK && result.payload.srv.record_count == 2
		&& strcmp(result.payload.srv.records[0].target, "backend.srv.test") == 0 && strcmp(result.payload.srv.records[1].target, ".") == 0, "SRV result was not preserved");
	test_result = true;

cleanup:
	resolver_ipc_assembly_result_destroy(&result);
	resolver_ipc_assembly_destroy(assembly);
	resolver_ipc_assembly_budget_destroy(budget);
	return test_result;
}

/* section: functions (exported) */
void *__wrap_calloc(size_t count, size_t size) {
	if (assembly_calloc_failures > 0) {
		assembly_calloc_failures--;
		errno = ENOMEM;
		return NULL;
	}
	return __real_calloc(count, size);
}

/* section: functions (entry point) */
int main(void) {
	int test_result = EXIT_FAILURE;
	CHECK(assembly_test_address(), "address assembly tests failed");
	CHECK(assembly_test_arguments(), "assembly argument tests failed");
	CHECK(assembly_test_budget(), "assembly budget tests failed");
	CHECK(assembly_test_metrics(), "assembly metrics tests failed");
	CHECK(assembly_test_negative(), "negative assembly tests failed");
	CHECK(assembly_test_protocol(), "assembly protocol tests failed");
	CHECK(assembly_test_srv(), "SRV assembly tests failed");
	test_result = EXIT_SUCCESS;

cleanup:
	return test_result;
}
