/*
 * dns_srv_records.c: Tests for DNS SRV response parsing
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* section: headers (project) */
#include "resolver/dns.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* DNS message */
#define DNS_TEST_MESSAGE_CAPACITY	32768
#define DNS_TEST_NO_POINTER	SIZE_MAX

/* DNS query */
#define DNS_TEST_QUERY_SIZE	4
#define DNS_TEST_QUERY_TOKEN_FIRST	0x4D
#define DNS_TEST_QUERY_TOKEN_SECOND	0x52
#define DNS_TEST_QUERY_ID	((DNS_TEST_QUERY_TOKEN_FIRST << 8) | DNS_TEST_QUERY_TOKEN_SECOND)

/* section: types */
typedef struct {
	size_t answer_count;
	size_t authority_count;
	uint8_t data[DNS_TEST_MESSAGE_CAPACITY];
	size_t question_class_offset;
	size_t question_name_offset;
	size_t question_type_offset;
	char question_name[NS_MAXDNAME];
	size_t size;
} dns_message_builder;
typedef struct {
	bool fail;
	int failure_errno;
	int failure_return;
	const char *name;
	const dns_message_builder *response;
} dns_query_fixture;
typedef struct {
	size_t close_count;
	int expected_retrans;
	int expected_retry;
	size_t init_count;
	int initial_retrans;
	int initial_retry;
} dns_resolver_fixture;

/* section: global variables */
static size_t dns_query_fixture_count;
static size_t dns_query_fixture_index;
static dns_query_fixture dns_query_fixtures[DNS_CNAME_DEPTH_LIMIT + 1];
static bool dns_query_mismatch;
static bool dns_query_pending;
static dns_resolver_fixture dns_resolver = {
	.expected_retrans = DNS_QUERY_RETRANSMIT_TIMEOUT_SEC,
	.expected_retry = DNS_QUERY_ATTEMPT_LIMIT,
	.initial_retrans = DNS_QUERY_RETRANSMIT_TIMEOUT_SEC + 1,
	.initial_retry = DNS_QUERY_ATTEMPT_LIMIT + 1
};

/* section: functions (local) */
static bool dns_builder_bytes_write(dns_message_builder *builder, const void *source, size_t size) {
	if (builder == NULL || source == NULL || size > sizeof(builder->data) - builder->size) {
		return false;
	}
	memcpy(builder->data + builder->size, source, size);
	builder->size += size;
	return true;
}

static bool dns_builder_name_write(dns_message_builder *builder, const char *name, size_t *name_offset) {
	if (builder == NULL || name == NULL) {
		return false;
	}
	if (name_offset != NULL) {
		*name_offset = builder->size;
	}
	if (strcmp(name, ".") == 0) {
		const uint8_t root = 0;
		return dns_builder_bytes_write(builder, &root, sizeof(root));
	}
	const char *label = name;
	while (*label != '\0') {
		const char *separator = strchr(label, '.');
		size_t label_size = separator == NULL ? strlen(label) : (size_t)(separator - label);
		if (label_size == 0) {
			if (separator != NULL && separator[1] == '\0') {
				break;
			}
			return false;
		}
		if (label_size > 63) {
			return false;
		}
		uint8_t wire_size = (uint8_t)label_size;
		if (!dns_builder_bytes_write(builder, &wire_size, sizeof(wire_size)) || !dns_builder_bytes_write(builder, label, label_size)) {
			return false;
		}
		if (separator == NULL) {
			break;
		}
		label = separator + 1;
	}
	const uint8_t root = 0;
	return dns_builder_bytes_write(builder, &root, sizeof(root));
}

static bool dns_builder_pointer_write(dns_message_builder *builder, size_t offset) {
	if (builder == NULL || offset > 0x3FFF) {
		return false;
	}
	uint8_t pointer[2] = { (uint8_t)(0xC0 | (offset >> 8)), (uint8_t)offset };
	return dns_builder_bytes_write(builder, pointer, sizeof(pointer));
}

static bool dns_builder_record_add(dns_message_builder *builder, const char *owner, size_t owner_pointer, uint16_t type, uint16_t record_class, uint32_t ttl, const void *rdata, size_t rdata_size) {
	if (builder == NULL || rdata_size > UINT16_MAX || (rdata == NULL && rdata_size != 0)) {
		return false;
	}
	if (owner_pointer == DNS_TEST_NO_POINTER) {
		if (!dns_builder_name_write(builder, owner, NULL)) {
			return false;
		}
	} else if (!dns_builder_pointer_write(builder, owner_pointer)) {
		return false;
	}
	uint8_t metadata[10];
	metadata[0] = (uint8_t)(type >> 8);
	metadata[1] = (uint8_t)type;
	metadata[2] = (uint8_t)(record_class >> 8);
	metadata[3] = (uint8_t)record_class;
	metadata[4] = (uint8_t)(ttl >> 24);
	metadata[5] = (uint8_t)(ttl >> 16);
	metadata[6] = (uint8_t)(ttl >> 8);
	metadata[7] = (uint8_t)ttl;
	metadata[8] = (uint8_t)(rdata_size >> 8);
	metadata[9] = (uint8_t)rdata_size;
	if (!dns_builder_bytes_write(builder, metadata, sizeof(metadata)) || (rdata_size != 0 && !dns_builder_bytes_write(builder, rdata, rdata_size))) {
		return false;
	}
	builder->answer_count++;
	builder->data[6] = (uint8_t)(builder->answer_count >> 8);
	builder->data[7] = (uint8_t)builder->answer_count;
	return true;
}

static bool dns_builder_authority_add(dns_message_builder *builder, const char *owner, size_t owner_pointer, uint16_t type, uint16_t record_class, uint32_t ttl, const void *rdata,
	size_t rdata_size) {
	if (!dns_builder_record_add(builder, owner, owner_pointer, type, record_class, ttl, rdata, rdata_size)) {
		return false;
	}
	builder->answer_count--;
	builder->data[6] = (uint8_t)(builder->answer_count >> 8);
	builder->data[7] = (uint8_t)builder->answer_count;
	builder->authority_count++;
	builder->data[8] = (uint8_t)(builder->authority_count >> 8);
	builder->data[9] = (uint8_t)builder->authority_count;
	return true;
}

static bool dns_builder_response_start(dns_message_builder *builder, const char *question_name, uint16_t question_type) {
	if (builder == NULL || question_name == NULL) {
		return false;
	}
	memset(builder, 0, sizeof(*builder));
	builder->size = NS_HFIXEDSZ;
	builder->data[0] = (uint8_t)(DNS_TEST_QUERY_ID >> 8);
	builder->data[1] = (uint8_t)DNS_TEST_QUERY_ID;
	builder->data[2] = 0x81;
	builder->data[3] = 0x80;
	builder->data[5] = 1;
	if (!dns_builder_name_write(builder, question_name, &builder->question_name_offset)) {
		return false;
	}
	builder->question_type_offset = builder->size;
	uint8_t question_tail[4] = { (uint8_t)(question_type >> 8), (uint8_t)question_type, 0, ns_c_in };
	if (!dns_builder_bytes_write(builder, question_tail, sizeof(question_tail))) {
		return false;
	}
	builder->question_class_offset = builder->question_type_offset + 2;
	if (snprintf(builder->question_name, sizeof(builder->question_name), "%s", question_name) < 0) {
		return false;
	}
	return true;
}

static bool dns_builder_wire_name_create(const char *name, uint8_t *target, size_t target_size, size_t *result_size) {
	if (name == NULL || target == NULL || result_size == NULL) {
		return false;
	}
	dns_message_builder builder;
	memset(&builder, 0, sizeof(builder));
	if (!dns_builder_name_write(&builder, name, NULL) || builder.size > target_size) {
		return false;
	}
	memcpy(target, builder.data, builder.size);
	*result_size = builder.size;
	return true;
}

static bool dns_builder_wire_soa_create(const char *mname, const char *rname, uint32_t minimum, uint8_t *target, size_t target_size, size_t *result_size) {
	if (mname == NULL || rname == NULL || target == NULL || result_size == NULL) {
		return false;
	}
	dns_message_builder builder;
	memset(&builder, 0, sizeof(builder));
	if (!dns_builder_name_write(&builder, mname, NULL) || !dns_builder_name_write(&builder, rname, NULL)) {
		return false;
	}
	const uint32_t values[5] = { 1, 2, 3, 4, minimum };
	for (size_t value_index = 0; value_index < sizeof(values) / sizeof(values[0]); value_index++) {
		uint8_t wire_value[4] = {
			(uint8_t)(values[value_index] >> 24),
			(uint8_t)(values[value_index] >> 16),
			(uint8_t)(values[value_index] >> 8),
			(uint8_t)values[value_index]
		};
		if (!dns_builder_bytes_write(&builder, wire_value, sizeof(wire_value))) {
			return false;
		}
	}
	if (builder.size > target_size) {
		return false;
	}
	memcpy(target, builder.data, builder.size);
	*result_size = builder.size;
	return true;
}

static bool dns_builder_wire_srv_create(uint16_t priority, uint16_t weight, in_port_t port, const char *target_name, uint8_t *target, size_t target_size, size_t *result_size) {
	if (target == NULL || target_size < 7 || result_size == NULL) {
		return false;
	}
	target[0] = (uint8_t)(priority >> 8);
	target[1] = (uint8_t)priority;
	target[2] = (uint8_t)(weight >> 8);
	target[3] = (uint8_t)weight;
	target[4] = (uint8_t)(port >> 8);
	target[5] = (uint8_t)port;
	size_t name_size;
	if (!dns_builder_wire_name_create(target_name, target + 6, target_size - 6, &name_size)) {
		return false;
	}
	*result_size = name_size + 6;
	return true;
}

static bool dns_srv_status_complete(dns_srv_parse_status status) {
	return status == DNS_SRV_PARSE_OK || status == DNS_SRV_PARSE_ALIAS_ONLY || status == DNS_SRV_PARSE_NODATA || status == DNS_SRV_PARSE_NXDOMAIN || status == DNS_SRV_PARSE_RCODE_ERROR;
}

static bool dns_test_aliases(void) {
	dns_message_builder builder;
	dns_srv_result result = { 0 };
	uint8_t wire_name[NS_MAXCDNAME];
	uint8_t wire_srv[NS_MAXCDNAME + 6];
	size_t wire_name_size;
	size_t wire_srv_size;
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.Alias.Example.", ns_t_srv), "cannot start aliased SRV response");
	CHECK(dns_builder_wire_srv_create(10, 20, 25565, "Node.Example.", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode aliased SRV record");
	CHECK(dns_builder_record_add(&builder, "final.example", DNS_TEST_NO_POINTER, ns_t_srv, ns_c_in, 600, wire_srv, wire_srv_size), "cannot add aliased SRV record");
	CHECK(dns_builder_wire_name_create("final.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode final SRV alias");
	CHECK(dns_builder_record_add(&builder, "middle.example", DNS_TEST_NO_POINTER, ns_t_cname, ns_c_in, 120, wire_name, wire_name_size), "cannot add final SRV alias");
	CHECK(dns_builder_wire_name_create("middle.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode initial SRV alias");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 300, wire_name, wire_name_size), "cannot add initial SRV alias");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 250, wire_name, wire_name_size), "cannot add duplicate initial SRV alias");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_OK, "cannot parse aliased SRV response");
	CHECK(strcmp(result.question_name, "_minecraft._tcp.alias.example") == 0 && strcmp(result.canonical_name, "final.example") == 0, "aliased SRV names were normalized incorrectly");
	CHECK(result.cname_count == 2 && result.record_count == 1, "aliased SRV response returned the wrong record counts");
	CHECK(strcmp(result.cnames[0].owner, "_minecraft._tcp.alias.example") == 0 && strcmp(result.cnames[0].target, "middle.example") == 0 && result.cnames[0].ttl == 250,
		"initial SRV alias was parsed incorrectly");
	CHECK(strcmp(result.cnames[1].owner, "middle.example") == 0 && strcmp(result.cnames[1].target, "final.example") == 0 && result.cnames[1].ttl == 120, "final SRV alias was parsed incorrectly");
	CHECK(result.records[0].priority == 10 && result.records[0].weight == 20 && result.records[0].port == 25565 && strcmp(result.records[0].target, "node.example") == 0,
		"aliased SRV record fields were parsed incorrectly");
	CHECK(result.records[0].record_ttl == 600 && result.records[0].effective_ttl == 120, "aliased SRV record did not use the CNAME TTL");
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	return test_result;
}

static bool dns_test_arguments(void) {
	dns_message_builder builder;
	dns_srv_result result = { 0 };
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.arguments.example", ns_t_srv), "cannot start SRV argument response");
	CHECK(dns_srv_response_parse(NULL, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_BAD_ARGUMENT, "NULL SRV message was accepted");
	CHECK(dns_srv_response_parse(builder.data, (size_t)INT_MAX + 1, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_BAD_ARGUMENT, "oversized SRV message was accepted");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, NULL) == DNS_SRV_PARSE_BAD_ARGUMENT, "NULL SRV result was accepted");
	CHECK(dns_srv_response_parse(builder.data, builder.size, NULL, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_BAD_ARGUMENT, "NULL expected name was accepted");
	result.question_name[0] = 'x';
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_BAD_ARGUMENT, "non-empty SRV result was accepted");
	dns_srv_result_destroy(&result);
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_NODATA, "destroyed SRV result could not be reused");
	dns_srv_result_destroy(&result);
	dns_srv_result_destroy(&result);
	dns_srv_result_destroy(NULL);
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	return test_result;
}

static void dns_test_query_reset(void) {
	memset(dns_query_fixtures, 0, sizeof(dns_query_fixtures));
	dns_query_fixture_count = 0;
	dns_query_fixture_index = 0;
	dns_query_mismatch = false;
	dns_query_pending = false;
}

static bool dns_test_lookup(void) {
	dns_message_builder alias_response;
	dns_message_builder record_response;
	dns_srv_result result = { 0 };
	uint8_t wire_name[NS_MAXCDNAME];
	uint8_t wire_soa[NS_MAXCDNAME * 2 + 20];
	uint8_t wire_srv[NS_MAXCDNAME + 6];
	size_t wire_name_size;
	size_t wire_soa_size;
	size_t wire_srv_size;
	int test_result = false;
	CHECK(dns_builder_response_start(&record_response, "_minecraft._tcp.lookup.example", ns_t_srv), "cannot start SRV lookup response");
	CHECK(dns_builder_wire_srv_create(10, 20, 25565, "first.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode first lookup SRV record");
	CHECK(dns_builder_record_add(&record_response, NULL, record_response.question_name_offset, ns_t_srv, ns_c_in, 90, wire_srv, wire_srv_size), "cannot add first lookup SRV record");
	CHECK(dns_builder_wire_srv_create(30, 40, 25566, "second.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode second lookup SRV record");
	CHECK(dns_builder_record_add(&record_response, NULL, record_response.question_name_offset, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add second lookup SRV record");
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ .name = "_minecraft._tcp.lookup.example.", .response = &record_response };
	dns_query_fixture_count = 1;
	CHECK(dns_srv_lookup("_minecraft._tcp.lookup.example.", &result) == DNS_SRV_LOOKUP_OK, "cannot look up SRV RRset");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "SRV lookup issued the wrong query");
	CHECK(result.record_count == 2 && strcmp(result.records[0].target, "first.example") == 0 && strcmp(result.records[1].target, "second.example") == 0,
		"SRV lookup lost records or DNS ordering");
	CHECK(result.records[0].effective_ttl == 90 && result.records[1].effective_ttl == 30, "SRV lookup lost record TTLs");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&record_response, "_minecraft._tcp.unexpected.lookup", ns_t_srv), "cannot start mismatched-question SRV lookup response");
	CHECK(dns_builder_wire_srv_create(0, 0, 25565, "target.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode mismatched-question SRV lookup record");
	CHECK(dns_builder_record_add(&record_response, NULL, record_response.question_name_offset, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add mismatched-question SRV lookup record");
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ .name = "_minecraft._tcp.expected.lookup", .response = &record_response };
	dns_query_fixture_count = 1;
	CHECK(dns_srv_lookup("_minecraft._tcp.expected.lookup", &result) == DNS_SRV_LOOKUP_MALFORMED, "SRV lookup accepted a response for a different question");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "mismatched-question SRV lookup issued the wrong exact query");

	CHECK(dns_builder_response_start(&alias_response, "_minecraft._tcp.alias.lookup", ns_t_srv), "cannot start SRV lookup alias response");
	CHECK(dns_builder_wire_name_create("_minecraft._tcp.target.lookup", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode SRV lookup alias target");
	CHECK(dns_builder_record_add(&alias_response, NULL, alias_response.question_name_offset, ns_t_cname, ns_c_in, 15, wire_name, wire_name_size), "cannot add SRV lookup alias");
	CHECK(dns_builder_response_start(&record_response, "_minecraft._tcp.target.lookup", ns_t_srv), "cannot start aliased SRV lookup response");
	CHECK(dns_builder_wire_srv_create(0, 1, 25565, "target.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode aliased lookup SRV record");
	CHECK(dns_builder_record_add(&record_response, NULL, record_response.question_name_offset, ns_t_srv, ns_c_in, 60, wire_srv, wire_srv_size), "cannot add aliased lookup SRV record");
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ .name = "_minecraft._tcp.alias.lookup", .response = &alias_response };
	dns_query_fixtures[1] = (dns_query_fixture){ .name = "_minecraft._tcp.target.lookup", .response = &record_response };
	dns_query_fixture_count = 2;
	CHECK(dns_srv_lookup("_minecraft._tcp.alias.lookup", &result) == DNS_SRV_LOOKUP_OK, "cannot follow CNAME-only SRV lookup response");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "aliased SRV lookup issued the wrong queries");
	bool alias_names_match = strcmp(result.question_name, "_minecraft._tcp.alias.lookup") == 0 && strcmp(result.canonical_name, "_minecraft._tcp.target.lookup") == 0;
	CHECK(result.cname_count == 1 && result.record_count == 1 && alias_names_match, "aliased SRV lookup returned the wrong chain");
	CHECK(result.records[0].record_ttl == 60 && result.records[0].effective_ttl == 15, "aliased SRV lookup did not combine TTLs across responses");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&alias_response, "_minecraft._tcp.negative.alias.lookup", ns_t_srv), "cannot start negative SRV lookup alias response");
	CHECK(dns_builder_wire_name_create("_minecraft._tcp.negative.target.lookup", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode negative SRV lookup alias target");
	CHECK(dns_builder_record_add(&alias_response, NULL, alias_response.question_name_offset, ns_t_cname, ns_c_in, 25, wire_name, wire_name_size), "cannot add negative SRV lookup alias");
	CHECK(dns_builder_response_start(&record_response, "_minecraft._tcp.negative.target.lookup", ns_t_srv), "cannot start raw SRV NXDOMAIN lookup response");
	CHECK(dns_builder_wire_soa_create("ns.lookup", "hostmaster.lookup", 60, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode raw SRV NXDOMAIN lookup SOA");
	CHECK(dns_builder_authority_add(&record_response, "lookup", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 90, wire_soa, wire_soa_size), "cannot add raw SRV NXDOMAIN lookup SOA");
	record_response.data[3] = (uint8_t)((record_response.data[3] & 0xF0) | ns_r_nxdomain);
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ .name = "_minecraft._tcp.negative.alias.lookup", .response = &alias_response };
	dns_query_fixtures[1] = (dns_query_fixture){ .name = "_minecraft._tcp.negative.target.lookup", .response = &record_response };
	dns_query_fixture_count = 2;
	CHECK(dns_srv_lookup("_minecraft._tcp.negative.alias.lookup", &result) == DNS_SRV_LOOKUP_NOT_FOUND, "cannot retain raw SRV NXDOMAIN lookup response");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "negative SRV lookup issued the wrong exact queries");
	CHECK(result.cname_count == 1 && strcmp(result.canonical_name, "_minecraft._tcp.negative.target.lookup") == 0, "negative SRV lookup lost its cross-response CNAME chain");
	CHECK(result.negative.valid && strcmp(result.negative.owner, "lookup") == 0 && result.negative.record_ttl == 90 && result.negative.minimum == 60 && result.negative.effective_ttl == 25,
		"negative SRV lookup did not preserve or fold authoritative metadata");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&record_response, "_minecraft._tcp.nodata.lookup", ns_t_srv), "cannot start raw SRV NODATA lookup response");
	CHECK(dns_builder_wire_soa_create("ns.lookup", "hostmaster.lookup", 40, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode raw SRV NODATA lookup SOA");
	CHECK(dns_builder_authority_add(&record_response, "lookup", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 80, wire_soa, wire_soa_size), "cannot add raw SRV NODATA lookup SOA");
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ .name = "_minecraft._tcp.nodata.lookup", .response = &record_response };
	dns_query_fixture_count = 1;
	CHECK(dns_srv_lookup("_minecraft._tcp.nodata.lookup", &result) == DNS_SRV_LOOKUP_NODATA, "cannot retain raw SRV NODATA lookup response");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count && result.negative.valid && result.negative.effective_ttl == 40,
		"SRV NODATA lookup lost its query or authoritative negative TTL");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&alias_response, "_minecraft._tcp.a.lookup", ns_t_srv), "cannot start cross-response SRV loop a");
	CHECK(dns_builder_wire_name_create("_minecraft._tcp.b.lookup", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode cross-response SRV loop b");
	CHECK(dns_builder_record_add(&alias_response, NULL, alias_response.question_name_offset, ns_t_cname, ns_c_in, 15, wire_name, wire_name_size), "cannot add cross-response SRV loop a");
	CHECK(dns_builder_response_start(&record_response, "_minecraft._tcp.b.lookup", ns_t_srv), "cannot start cross-response SRV loop b");
	CHECK(dns_builder_wire_name_create("_minecraft._tcp.a.lookup", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode cross-response SRV loop a");
	CHECK(dns_builder_record_add(&record_response, NULL, record_response.question_name_offset, ns_t_cname, ns_c_in, 15, wire_name, wire_name_size), "cannot add cross-response SRV loop b");
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ .name = "_minecraft._tcp.a.lookup", .response = &alias_response };
	dns_query_fixtures[1] = (dns_query_fixture){ .name = "_minecraft._tcp.b.lookup", .response = &record_response };
	dns_query_fixture_count = 2;
	CHECK(dns_srv_lookup("_minecraft._tcp.a.lookup", &result) == DNS_SRV_LOOKUP_MALFORMED, "cross-response SRV CNAME loop was accepted");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "looping SRV lookup issued the wrong queries");
	CHECK(result.records == NULL && result.cnames == NULL, "failed SRV lookup returned partial records");

	static const struct {
		int failure_errno;
		int failure_return;
		dns_srv_lookup_status status;
	} transport_failures[] = {
		{ ETIMEDOUT, -1, DNS_SRV_LOOKUP_TEMPORARY_ERROR },
		{ ECONNREFUSED, -1, DNS_SRV_LOOKUP_TEMPORARY_ERROR },
		{ ECONNRESET, -1, DNS_SRV_LOOKUP_TEMPORARY_ERROR },
		{ ENETUNREACH, -1, DNS_SRV_LOOKUP_TEMPORARY_ERROR },
		{ EHOSTUNREACH, -1, DNS_SRV_LOOKUP_TEMPORARY_ERROR },
		{ EPIPE, -1, DNS_SRV_LOOKUP_TEMPORARY_ERROR },
		{ 999, -1, DNS_SRV_LOOKUP_TEMPORARY_ERROR },
		{ 0, 0, DNS_SRV_LOOKUP_TEMPORARY_ERROR },
		{ ENOMEM, -1, DNS_SRV_LOOKUP_MEMORY },
		{ EMSGSIZE, -1, DNS_SRV_LOOKUP_MALFORMED },
		{ ESRCH, -1, DNS_SRV_LOOKUP_PERMANENT_ERROR },
		{ EINVAL, -1, DNS_SRV_LOOKUP_PERMANENT_ERROR },
		{ EACCES, -1, DNS_SRV_LOOKUP_PERMANENT_ERROR }
	};
	for (size_t index = 0; index < sizeof(transport_failures) / sizeof(transport_failures[0]); index++) {
		dns_test_query_reset();
		dns_query_fixtures[0] = (dns_query_fixture){ .fail = true, .failure_errno = transport_failures[index].failure_errno,
			.failure_return = transport_failures[index].failure_return, .name = "_minecraft._tcp.error.lookup", .response = NULL };
		dns_query_fixture_count = 1;
		CHECK(dns_srv_lookup("_minecraft._tcp.error.lookup", &result) == transport_failures[index].status, "SRV transport failure returned the wrong status");
		CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "SRV transport failure issued the wrong query");
		dns_srv_result_destroy(&result);
	}

	CHECK(dns_builder_response_start(&record_response, "_minecraft._tcp.error.lookup", ns_t_srv), "cannot start SRV DNS error response");
	record_response.data[3] = (uint8_t)((record_response.data[3] & 0xF0) | ns_r_servfail);
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ .name = "_minecraft._tcp.error.lookup", .response = &record_response };
	dns_query_fixture_count = 1;
	CHECK(dns_srv_lookup("_minecraft._tcp.error.lookup", &result) == DNS_SRV_LOOKUP_TEMPORARY_ERROR, "SRV SERVFAIL response was not treated as temporary");
	CHECK(result.rcode == ns_r_servfail, "SRV lookup did not retain SERVFAIL rcode");
	dns_srv_result_destroy(&result);

	dns_test_query_reset();
	CHECK(dns_srv_lookup(NULL, &result) == DNS_SRV_LOOKUP_BAD_ARGUMENT, "SRV lookup accepted a NULL query name");
	CHECK(dns_srv_lookup("", &result) == DNS_SRV_LOOKUP_BAD_ARGUMENT, "SRV lookup accepted an empty query name");
	result.question_name[0] = 'x';
	CHECK(dns_srv_lookup("_minecraft._tcp.lookup.example", &result) == DNS_SRV_LOOKUP_BAD_ARGUMENT, "SRV lookup accepted a non-empty result");
	dns_srv_result_destroy(&result);
	CHECK(dns_query_fixture_index == 0, "invalid SRV lookup issued a resolver query");
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	dns_test_query_reset();
	return test_result;
}

static bool dns_test_lookup_depth(void) {
	dns_message_builder *responses = NULL;
	dns_srv_result result = { 0 };
	char query_names[DNS_CNAME_DEPTH_LIMIT + 2][NS_MAXDNAME];
	uint8_t wire_name[NS_MAXCDNAME];
	size_t wire_name_size;
	int test_result = false;
	responses = calloc(DNS_CNAME_DEPTH_LIMIT + 1, sizeof(*responses));
	CHECK(responses != NULL, "cannot allocate cross-response SRV depth fixtures");
	for (size_t index = 0; index < DNS_CNAME_DEPTH_LIMIT + 2; index++) {
		int name_size = snprintf(query_names[index], sizeof(query_names[index]), "_minecraft._tcp.depth%zu.lookup", index);
		CHECK(name_size > 0 && (size_t)name_size < sizeof(query_names[index]), "cannot format cross-response SRV depth name");
	}
	dns_test_query_reset();
	for (size_t index = 0; index < DNS_CNAME_DEPTH_LIMIT + 1; index++) {
		CHECK(dns_builder_response_start(&responses[index], query_names[index], ns_t_srv), "cannot start cross-response SRV depth fixture");
		CHECK(dns_builder_wire_name_create(query_names[index + 1], wire_name, sizeof(wire_name), &wire_name_size), "cannot encode cross-response SRV depth target");
		CHECK(dns_builder_record_add(&responses[index], NULL, responses[index].question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size), "cannot add cross-response SRV depth alias");
		dns_query_fixtures[index] = (dns_query_fixture){ .name = query_names[index], .response = &responses[index] };
	}
	dns_query_fixture_count = DNS_CNAME_DEPTH_LIMIT + 1;
	CHECK(dns_srv_lookup(query_names[0], &result) == DNS_SRV_LOOKUP_LIMIT, "cross-response SRV CNAME depth limit was not enforced");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "depth-limited SRV lookup issued the wrong queries");
	CHECK(result.records == NULL && result.record_count == 0 && result.cnames == NULL && result.cname_count == 0, "depth-limited SRV lookup returned partial records");
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	dns_test_query_reset();
	free(responses);
	return test_result;
}

static bool dns_test_malformed(void) {
	dns_message_builder builder;
	dns_srv_result result = { 0 };
	uint8_t wire_name[NS_MAXCDNAME];
	uint8_t wire_srv[NS_MAXCDNAME + 7];
	size_t wire_name_size;
	size_t wire_srv_size;
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.bad.example", ns_t_srv), "cannot start malformed SRV response");
	uint8_t short_rdata[6] = { 0 };
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 30, short_rdata, sizeof(short_rdata)), "cannot add short SRV record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "short SRV record was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.bad.example", ns_t_srv), "cannot restart malformed SRV response");
	CHECK(dns_builder_wire_srv_create(0, 0, 25565, "target.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode malformed SRV target");
	wire_srv[wire_srv_size++] = 0;
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add SRV record with trailing data");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "SRV target with trailing data was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.bad.example", ns_t_srv), "cannot restart invalid-pointer SRV response");
	uint8_t bad_pointer_rdata[8] = { 0, 0, 0, 0, 0x63, 0xDD, 0xFF, 0xFF };
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 30, bad_pointer_rdata, sizeof(bad_pointer_rdata)), "cannot add invalid SRV target pointer");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "invalid SRV target pointer was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.bad.example", ns_t_srv), "cannot restart conflicting SRV response");
	CHECK(dns_builder_wire_name_create("target.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode conflicting SRV alias");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size), "cannot add conflicting SRV alias");
	CHECK(dns_builder_wire_srv_create(0, 0, 25565, "node.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode conflicting SRV record");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add conflicting SRV record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "CNAME and SRV record at the same owner were accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.bad.example", ns_t_srv), "cannot restart conflicting-alias SRV response");
	CHECK(dns_builder_wire_name_create("first.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode first conflicting SRV alias");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size), "cannot add first conflicting SRV alias");
	CHECK(dns_builder_wire_name_create("second.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode second conflicting SRV alias");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size), "cannot add second conflicting SRV alias");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "conflicting SRV alias targets were accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.loop.example", ns_t_srv), "cannot start looping SRV response");
	CHECK(dns_builder_wire_name_create("middle.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode forward SRV loop alias");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size), "cannot add forward SRV loop alias");
	CHECK(dns_builder_wire_name_create("_minecraft._tcp.loop.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode reverse SRV loop alias");
	CHECK(dns_builder_record_add(&builder, "middle.example", DNS_TEST_NO_POINTER, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size), "cannot add reverse SRV loop alias");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "looping SRV alias chain was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.limit.example", ns_t_srv), "cannot start excessive SRV response");
	CHECK(dns_builder_wire_srv_create(0, 0, 25565, ".", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode excessive SRV record");
	for (size_t index = 0; index < DNS_SRV_RECORD_LIMIT + 1; index++) {
		CHECK(dns_builder_record_add(&builder, "unrelated.example", DNS_TEST_NO_POINTER, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add excessive SRV record");
	}
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_LIMIT, "excessive SRV answer count was accepted");

	CHECK(dns_builder_response_start(&builder, "depth0.example", ns_t_srv), "cannot start excessive SRV alias chain");
	for (size_t index = 0; index < DNS_CNAME_DEPTH_LIMIT + 1; index++) {
		char owner[32];
		char target[32];
		int owner_size = snprintf(owner, sizeof(owner), "depth%zu.example", index);
		int target_size = snprintf(target, sizeof(target), "depth%zu.example", index + 1);
		CHECK(owner_size > 0 && (size_t)owner_size < sizeof(owner) && target_size > 0 && (size_t)target_size < sizeof(target), "cannot format SRV alias depth names");
		CHECK(dns_builder_wire_name_create(target, wire_name, sizeof(wire_name), &wire_name_size), "cannot encode SRV alias depth target");
		CHECK(dns_builder_record_add(&builder, owner, DNS_TEST_NO_POINTER, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size), "cannot add SRV alias depth record");
	}
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_LIMIT, "excessive SRV CNAME depth was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.negative.example", ns_t_srv), "cannot start short SRV SOA response");
	uint8_t short_soa[19] = { 0 };
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 30, short_soa, sizeof(short_soa)), "cannot add short SRV SOA record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "short SRV SOA record was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.negative.example", ns_t_srv), "cannot start invalid-pointer SRV SOA response");
	uint8_t invalid_soa[24] = { 0xFF, 0xFF };
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 30, invalid_soa, sizeof(invalid_soa)), "cannot add invalid-pointer SRV SOA record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "invalid SRV SOA compression pointer was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.negative.example", ns_t_srv), "cannot start trailing-data SRV SOA response");
	uint8_t trailing_soa[NS_MAXCDNAME * 2 + 21];
	size_t trailing_soa_size;
	CHECK(dns_builder_wire_soa_create("ns.example", "hostmaster.example", 30, trailing_soa, sizeof(trailing_soa), &trailing_soa_size), "cannot encode trailing-data SRV SOA record");
	trailing_soa[trailing_soa_size++] = 0;
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 30, trailing_soa, trailing_soa_size), "cannot add trailing-data SRV SOA record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "SRV SOA record with trailing data was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.negative.example", ns_t_srv), "cannot start excessive SRV authority response");
	for (size_t index = 0; index <= DNS_AUTHORITY_RECORD_LIMIT; index++) {
		CHECK(dns_builder_authority_add(&builder, NULL, builder.question_name_offset, ns_t_txt, ns_c_in, 1, NULL, 0), "cannot add excessive SRV authority record");
	}
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_LIMIT, "excessive SRV authority count was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.contradictory.example", ns_t_srv), "cannot start contradictory SRV NXDOMAIN response");
	CHECK(dns_builder_wire_srv_create(0, 0, 25565, "target.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode contradictory NXDOMAIN SRV record");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add contradictory NXDOMAIN SRV record");
	builder.data[3] = (uint8_t)((builder.data[3] & 0xF0) | ns_r_nxdomain);
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "NXDOMAIN response with terminal SRV data was accepted");

	dns_srv_result_destroy(&result);
	/* Responses are bound to their queries: TXID, question name, and question count must match exactly. */
	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.bad.example", ns_t_srv), "cannot start TXID response");
	CHECK(dns_builder_wire_srv_create(0, 0, 25565, "target.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode TXID response record");
	CHECK(dns_builder_record_add(&builder, "_minecraft._tcp.bad.example", builder.question_name_offset, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add TXID response record");
	builder.data[1] ^= 0xFF;
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "wrong TXID was accepted");
	builder.data[1] ^= 0xFF;
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_OK, "correct TXID response failed");
	dns_srv_result_destroy(&result);
	CHECK(dns_srv_response_parse(builder.data, builder.size, "_minecraft._tcp.other.example", DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "wrong question name was accepted");
	CHECK(dns_srv_response_parse(builder.data, builder.size, "_minecraft._tcp.bad.example.", DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_OK, "trailing-dot question name failed");
	dns_srv_result_destroy(&result);
	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.bad.example", ns_t_srv), "cannot restart qdcount response");
	builder.data[5] = 0;
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "zero question count was accepted");
	builder.data[5] = 2;
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "two question count was accepted");

	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	return test_result;
}

static bool dns_test_negative(void) {
	dns_message_builder builder;
	dns_srv_result result = { 0 };
	uint8_t wire_name[NS_MAXCDNAME];
	uint8_t wire_soa[NS_MAXCDNAME * 2 + 20];
	size_t wire_name_size;
	size_t wire_soa_size;
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.nodata.example", ns_t_srv), "cannot start authoritative SRV NODATA response");
	CHECK(dns_builder_wire_soa_create("ns.example", "hostmaster.example", 120, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode SRV NODATA SOA record");
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 300, wire_soa, wire_soa_size), "cannot add SRV NODATA SOA record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_NODATA, "cannot parse authoritative SRV NODATA response");
	CHECK(result.negative.valid && strcmp(result.negative.owner, "example") == 0 && result.negative.record_ttl == 300 && result.negative.minimum == 120 && result.negative.effective_ttl == 120,
		"SRV NODATA negative metadata was parsed incorrectly");
	dns_srv_result_destroy(&result);
	for (size_t prefix_size = 0; prefix_size < builder.size; prefix_size++) {
		dns_srv_parse_status status = dns_srv_response_parse(builder.data, prefix_size, builder.question_name, DNS_TEST_QUERY_ID, &result);
		CHECK(!dns_srv_status_complete(status), "truncated authoritative SRV NODATA response was accepted");
		dns_srv_result_destroy(&result);
	}

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.absent.example", ns_t_srv), "cannot start SRV NODATA response without SOA");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_NODATA, "cannot parse SRV NODATA response without SOA");
	CHECK(!result.negative.valid, "SRV NODATA response without SOA produced authoritative negative metadata");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.missing.example", ns_t_srv), "cannot start SRV NODATA response with unrelated SOA");
	CHECK(dns_builder_wire_soa_create("ns.other.example", "hostmaster.other.example", 1, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode unrelated-only SRV SOA record");
	CHECK(dns_builder_authority_add(&builder, "other.example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 1, wire_soa, wire_soa_size), "cannot add unrelated-only SRV SOA record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_NODATA, "cannot parse SRV NODATA response with unrelated SOA");
	CHECK(!result.negative.valid, "unrelated SOA produced authoritative SRV negative metadata");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.alias.negative.example", ns_t_srv), "cannot start aliased SRV NXDOMAIN response");
	CHECK(dns_builder_wire_name_create("_minecraft._tcp.missing.sub.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode negative SRV alias target");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 20, wire_name, wire_name_size), "cannot add negative SRV alias");
	CHECK(dns_builder_wire_soa_create("ns.example", "hostmaster.example", 120, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode SRV NXDOMAIN SOA record");
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 300, wire_soa, wire_soa_size), "cannot add SRV NXDOMAIN SOA record");
	builder.data[3] = (uint8_t)((builder.data[3] & 0xF0) | ns_r_nxdomain);
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_NXDOMAIN, "cannot parse aliased SRV NXDOMAIN response");
	CHECK(result.cname_count == 1 && strcmp(result.canonical_name, "_minecraft._tcp.missing.sub.example") == 0, "SRV NXDOMAIN response lost its CNAME chain");
	CHECK(result.negative.valid && result.negative.effective_ttl == 20, "SRV NXDOMAIN negative TTL did not include the CNAME TTL");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.missing.sub.example", ns_t_srv), "cannot start closest-zone SRV NODATA response");
	CHECK(dns_builder_wire_soa_create("ns.example", "hostmaster.example", 5, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode root SRV SOA record");
	CHECK(dns_builder_authority_add(&builder, ".", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 5, wire_soa, wire_soa_size), "cannot add root SRV SOA record");
	CHECK(dns_builder_wire_soa_create("ns.example", "hostmaster.example", 150, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode parent SRV SOA record");
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 200, wire_soa, wire_soa_size), "cannot add parent SRV SOA record");
	CHECK(dns_builder_wire_soa_create("ns.sub.example", "hostmaster.sub.example", 80, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode closest SRV SOA record");
	CHECK(dns_builder_authority_add(&builder, "sub.example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 100, wire_soa, wire_soa_size), "cannot add closest SRV SOA record");
	CHECK(dns_builder_wire_soa_create("ns.sub.example", "hostmaster.sub.example", 200, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode duplicate SRV SOA record");
	CHECK(dns_builder_authority_add(&builder, "SUB.EXAMPLE.", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 30, wire_soa, wire_soa_size), "cannot add duplicate SRV SOA record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_NODATA, "cannot parse closest-zone SRV NODATA response");
	CHECK(result.negative.valid && strcmp(result.negative.owner, "sub.example") == 0 && result.negative.record_ttl == 30 && result.negative.minimum == 80 && result.negative.effective_ttl == 30,
		"closest or duplicate SRV SOA selection was incorrect");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.zero.example", ns_t_srv), "cannot start zero-TTL SRV NODATA response");
	CHECK(dns_builder_wire_soa_create("ns.example", "hostmaster.example", 0, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode zero-TTL SRV SOA record");
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 300, wire_soa, wire_soa_size), "cannot add zero-TTL SRV SOA record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_NODATA, "cannot parse zero-TTL SRV NODATA response");
	CHECK(result.negative.valid && result.negative.effective_ttl == 0, "valid zero SRV negative TTL was not distinguished from absent metadata");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.compressed.example", ns_t_srv), "cannot start compressed SRV SOA response");
	wire_soa[0] = (uint8_t)(0xC0 | (builder.question_name_offset >> 8));
	wire_soa[1] = (uint8_t)builder.question_name_offset;
	wire_soa[2] = wire_soa[0];
	wire_soa[3] = wire_soa[1];
	memset(wire_soa + 4, 0, 20);
	wire_soa[23] = 40;
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 50, wire_soa, 24), "cannot add compressed SRV SOA record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_NODATA, "cannot parse compressed SRV SOA response");
	CHECK(result.negative.valid && result.negative.minimum == 40 && result.negative.effective_ttl == 40, "compressed SRV SOA names or fields were parsed incorrectly");
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	return test_result;
}

static int dns_test_query_response(res_state resolver, const unsigned char *query, int query_size, unsigned char *answer, int answer_size) {
	if (!dns_query_pending || dns_query_fixture_index >= dns_query_fixture_count || resolver == NULL || query == NULL || query_size != DNS_TEST_QUERY_SIZE || answer == NULL || answer_size < 0
		|| resolver->retrans != dns_resolver.expected_retrans || resolver->retry != dns_resolver.expected_retry || query[0] != DNS_TEST_QUERY_TOKEN_FIRST || query[1] != DNS_TEST_QUERY_TOKEN_SECOND
		|| query[2] != (uint8_t)(dns_query_fixture_index >> 8) || query[3] != (uint8_t)dns_query_fixture_index) {
		dns_query_mismatch = true;
		dns_query_pending = false;
		if (resolver != NULL) {
			resolver->res_h_errno = NO_RECOVERY;
		}
		return -1;
	}
	dns_query_pending = false;
	const dns_query_fixture *fixture = &dns_query_fixtures[dns_query_fixture_index++];
	if (fixture->fail) {
		errno = fixture->failure_errno;
		return fixture->failure_return;
	}
	if (fixture->response == NULL || fixture->response->size > (size_t)answer_size) {
		dns_query_mismatch = true;
		resolver->res_h_errno = NO_RECOVERY;
		return -1;
	}
	memcpy(answer, fixture->response->data, fixture->response->size);
	return (int)fixture->response->size;
}

static bool dns_test_records(void) {
	dns_message_builder builder;
	dns_srv_result result = { 0 };
	uint8_t wire_srv[NS_MAXCDNAME + 6];
	size_t wire_srv_size;
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.Example.", ns_t_srv), "cannot start SRV response");
	CHECK(dns_builder_wire_srv_create(100, 1, 1, "unrelated.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode unrelated SRV record");
	CHECK(dns_builder_record_add(&builder, "_minecraft._tcp.unrelated.example", DNS_TEST_NO_POINTER, ns_t_srv, ns_c_in, 1, wire_srv, wire_srv_size), "cannot add unrelated SRV record");
	CHECK(dns_builder_wire_srv_create(10, 20, 25565, "First.Example.", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode first SRV record");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 300, wire_srv, wire_srv_size), "cannot add first SRV record");
	CHECK(dns_builder_wire_srv_create(5, 0, 25566, "second.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode second SRV record");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add second SRV record");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_chaos, 1, NULL, 0), "cannot add ignored non-IN SRV record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_OK, "cannot parse SRV RRset");
	CHECK(strcmp(result.question_name, "_minecraft._tcp.example") == 0 && strcmp(result.canonical_name, "_minecraft._tcp.example") == 0, "SRV owner was normalized incorrectly");
	CHECK(result.cname_count == 0 && result.record_count == 2, "SRV response returned the wrong record counts");
	CHECK(result.records[0].priority == 10 && result.records[0].weight == 20 && result.records[0].port == 25565 && strcmp(result.records[0].target, "first.example") == 0,
		"first SRV record was parsed incorrectly");
	CHECK(result.records[0].record_ttl == 300 && result.records[0].effective_ttl == 300, "first SRV TTL was parsed incorrectly");
	CHECK(result.records[1].priority == 5 && result.records[1].weight == 0 && result.records[1].port == 25566 && strcmp(result.records[1].target, "second.example") == 0,
		"second SRV record was parsed incorrectly");
	CHECK(result.records[1].record_ttl == 30 && result.records[1].effective_ttl == 30, "second SRV TTL was parsed incorrectly");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.unavailable.example", ns_t_srv), "cannot start unavailable SRV response");
	CHECK(dns_builder_wire_srv_create(0, 0, 0, ".", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode unavailable SRV record");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 15, wire_srv, wire_srv_size), "cannot add unavailable SRV record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_OK, "cannot parse unavailable SRV response");
	CHECK(result.record_count == 1 && strcmp(result.records[0].target, ".") == 0 && result.records[0].port == 0, "unavailable SRV target was not preserved");
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	return test_result;
}

static bool dns_test_resolver_limits(void) {
	dns_message_builder builder;
	dns_srv_result result = { 0 };
	uint8_t wire_srv[NS_MAXCDNAME + 6];
	size_t wire_srv_size;
	const int expected_retrans[] = { DNS_QUERY_RETRANSMIT_TIMEOUT_SEC, 1 };
	const int expected_retry[] = { DNS_QUERY_ATTEMPT_LIMIT, 0 };
	const int initial_retrans[] = { DNS_QUERY_RETRANSMIT_TIMEOUT_SEC + 8, 1 };
	const int initial_retry[] = { DNS_QUERY_ATTEMPT_LIMIT + 4, 0 };
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.limits.example", ns_t_srv), "cannot start SRV resolver-limit response");
	CHECK(dns_builder_wire_srv_create(0, 0, 25565, "target.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode SRV resolver-limit record");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add SRV resolver-limit record");
	for (size_t limit_index = 0; limit_index < sizeof(initial_retry) / sizeof(initial_retry[0]); limit_index++) {
		dns_resolver.expected_retrans = expected_retrans[limit_index];
		dns_resolver.expected_retry = expected_retry[limit_index];
		dns_resolver.initial_retrans = initial_retrans[limit_index];
		dns_resolver.initial_retry = initial_retry[limit_index];
		size_t close_count = dns_resolver.close_count;
		size_t init_count = dns_resolver.init_count;
		dns_test_query_reset();
		dns_query_fixtures[0] = (dns_query_fixture){ .name = "_minecraft._tcp.limits.example", .response = &builder };
		dns_query_fixture_count = 1;
		CHECK(dns_srv_lookup("_minecraft._tcp.limits.example", &result) == DNS_SRV_LOOKUP_OK, "resolver limits broke SRV lookup");
		CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "SRV lookup applied the wrong resolver limits");
		CHECK(dns_resolver.init_count == init_count + 1 && dns_resolver.close_count == close_count + 1, "SRV lookup did not close its initialized resolver state");
		dns_srv_result_destroy(&result);
	}
	test_result = true;

cleanup:
	dns_resolver.expected_retrans = DNS_QUERY_RETRANSMIT_TIMEOUT_SEC;
	dns_resolver.expected_retry = DNS_QUERY_ATTEMPT_LIMIT;
	dns_resolver.initial_retrans = DNS_QUERY_RETRANSMIT_TIMEOUT_SEC + 1;
	dns_resolver.initial_retry = DNS_QUERY_ATTEMPT_LIMIT + 1;
	dns_srv_result_destroy(&result);
	return test_result;
}

static bool dns_test_statuses(void) {
	dns_message_builder builder;
	dns_srv_result result = { 0 };
	uint8_t wire_name[NS_MAXCDNAME];
	size_t wire_name_size;
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start SRV NODATA response");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_NODATA, "SRV NODATA response was not identified");
	CHECK(strcmp(result.question_name, "_minecraft._tcp.status.example") == 0 && strcmp(result.canonical_name, "_minecraft._tcp.status.example") == 0, "SRV NODATA names were not retained");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start SRV alias-only response");
	CHECK(dns_builder_wire_name_create("_minecraft._tcp.target.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode SRV alias-only target");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 50, wire_name, wire_name_size), "cannot add SRV alias-only record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_ALIAS_ONLY, "SRV alias-only response was not identified");
	CHECK(result.cname_count == 1 && result.record_count == 0 && strcmp(result.canonical_name, "_minecraft._tcp.target.example") == 0, "SRV alias-only result was incomplete");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start SRV NXDOMAIN response");
	builder.data[3] = (uint8_t)((builder.data[3] & 0xF0) | ns_r_nxdomain);
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_NXDOMAIN, "SRV NXDOMAIN response was not identified");
	CHECK(result.rcode == ns_r_nxdomain && strcmp(result.question_name, "_minecraft._tcp.status.example") == 0, "SRV NXDOMAIN metadata was not retained");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start SRV SERVFAIL response");
	builder.data[3] = (uint8_t)((builder.data[3] & 0xF0) | ns_r_servfail);
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_RCODE_ERROR, "SRV SERVFAIL response was not identified");
	CHECK(result.rcode == ns_r_servfail, "SRV SERVFAIL rcode was not retained");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start truncated SRV response");
	builder.data[2] |= 0x02;
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_TRUNCATED, "SRV truncated flag was ignored");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start request-shaped SRV response");
	builder.data[2] &= 0x7F;
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "request-shaped SRV message was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start SRV opcode response");
	builder.data[2] |= 0x08;
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "non-query SRV opcode was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start wrong-type SRV response");
	builder.data[builder.question_type_offset + 1] = ns_t_a;
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "wrong SRV question type was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start wrong-class SRV response");
	builder.data[builder.question_class_offset + 1] = ns_c_chaos;
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_MALFORMED, "wrong SRV question class was accepted");
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	return test_result;
}

static bool dns_test_truncation(void) {
	dns_message_builder builder;
	dns_srv_result result = { 0 };
	uint8_t wire_srv[NS_MAXCDNAME + 6];
	size_t wire_srv_size;
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.truncate.example", ns_t_srv), "cannot start SRV truncation response");
	CHECK(dns_builder_wire_srv_create(0, 0, 25565, "target.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode SRV truncation record");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add SRV truncation record");
	for (size_t prefix_size = 0; prefix_size < builder.size; prefix_size++) {
		dns_srv_parse_status status = dns_srv_response_parse(builder.data, prefix_size, builder.question_name, DNS_TEST_QUERY_ID, &result);
		CHECK(!dns_srv_status_complete(status), "truncated SRV prefix was accepted as a complete response");
		dns_srv_result_destroy(&result);
	}
	CHECK(dns_srv_response_parse(builder.data, builder.size, builder.question_name, DNS_TEST_QUERY_ID, &result) == DNS_SRV_PARSE_OK, "complete SRV response failed after truncation checks");
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	return test_result;
}

/* section: functions (exported) */
void __wrap___res_nclose(res_state resolver) {
	if (resolver == NULL) {
		dns_query_mismatch = true;
		return;
	}
	dns_resolver.close_count++;
	memset(resolver, 0, sizeof(*resolver));
}

int __wrap___res_ninit(res_state resolver) {
	if (resolver == NULL) {
		dns_query_mismatch = true;
		return -1;
	}
	memset(resolver, 0, sizeof(*resolver));
	resolver->retrans = dns_resolver.initial_retrans;
	resolver->retry = dns_resolver.initial_retry;
	dns_resolver.init_count++;
	return 0;
}

int __wrap_res_nmkquery(res_state resolver, int operation, const char *name, int record_class, int type, const unsigned char *data, int data_size, const unsigned char *new_record,
	unsigned char *query, int query_size) {
	if (dns_query_pending || dns_query_fixture_index >= dns_query_fixture_count || resolver == NULL || operation != ns_o_query || name == NULL || record_class != ns_c_in || type != ns_t_srv
		|| data != NULL || data_size != 0 || new_record != NULL || query == NULL || query_size < DNS_TEST_QUERY_SIZE) {
		dns_query_mismatch = true;
		if (resolver != NULL) {
			resolver->res_h_errno = NO_RECOVERY;
		}
		return -1;
	}
	const dns_query_fixture *fixture = &dns_query_fixtures[dns_query_fixture_index];
	if (fixture->name == NULL || strcmp(fixture->name, name) != 0) {
		dns_query_mismatch = true;
		resolver->res_h_errno = NO_RECOVERY;
		return -1;
	}
	query[0] = DNS_TEST_QUERY_TOKEN_FIRST;
	query[1] = DNS_TEST_QUERY_TOKEN_SECOND;
	query[2] = (uint8_t)(dns_query_fixture_index >> 8);
	query[3] = (uint8_t)dns_query_fixture_index;
	dns_query_pending = true;
	return DNS_TEST_QUERY_SIZE;
}

int __wrap_res_nquery(res_state resolver, const char *name, int record_class, int type, unsigned char *answer, int answer_size) {
	(void)name;
	(void)record_class;
	(void)type;
	(void)answer;
	(void)answer_size;
	dns_query_mismatch = true;
	if (resolver != NULL) {
		resolver->res_h_errno = NO_RECOVERY;
	}
	return -1;
}

int __wrap_res_nsearch(res_state resolver, const char *name, int record_class, int type, unsigned char *answer, int answer_size) {
	(void)name;
	(void)record_class;
	(void)type;
	(void)answer;
	(void)answer_size;
	dns_query_mismatch = true;
	if (resolver != NULL) {
		resolver->res_h_errno = NO_RECOVERY;
	}
	return -1;
}

int __wrap_res_nsend(res_state resolver, const unsigned char *query, int query_size, unsigned char *answer, int answer_size) {
	return dns_test_query_response(resolver, query, query_size, answer, answer_size);
}

/* section: functions (entry point) */
int main(void) {
	if (!dns_test_aliases() || !dns_test_arguments() || !dns_test_lookup() || !dns_test_lookup_depth() || !dns_test_malformed() || !dns_test_negative() || !dns_test_records()
		|| !dns_test_resolver_limits() || !dns_test_statuses() || !dns_test_truncation()) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
