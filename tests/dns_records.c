/*
 * dns_records.c: Tests for DNS address response parsing
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
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
#include "dns.h"

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

/* section: types */
typedef struct {
	size_t answer_count;
	size_t authority_count;
	uint8_t data[DNS_TEST_MESSAGE_CAPACITY];
	size_t question_class_offset;
	size_t question_name_offset;
	size_t question_type_offset;
	size_t size;
} dns_message_builder;
typedef struct {
	int error;
	const char *name;
	const dns_message_builder *response;
	int type;
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

static bool dns_builder_record_add(dns_message_builder *builder, const char *owner, size_t owner_pointer, uint16_t type, uint16_t record_class, uint32_t ttl, const void *rdata, size_t rdata_size,
	size_t *rdata_offset) {
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
	if (!dns_builder_bytes_write(builder, metadata, sizeof(metadata))) {
		return false;
	}
	if (rdata_offset != NULL) {
		*rdata_offset = builder->size;
	}
	if (rdata_size != 0 && !dns_builder_bytes_write(builder, rdata, rdata_size)) {
		return false;
	}
	builder->answer_count++;
	builder->data[6] = (uint8_t)(builder->answer_count >> 8);
	builder->data[7] = (uint8_t)builder->answer_count;
	return true;
}

static bool dns_builder_authority_add(dns_message_builder *builder, const char *owner, size_t owner_pointer, uint16_t type, uint16_t record_class, uint32_t ttl, const void *rdata,
	size_t rdata_size) {
	if (!dns_builder_record_add(builder, owner, owner_pointer, type, record_class, ttl, rdata, rdata_size, NULL)) {
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
	builder->data[0] = 0x12;
	builder->data[1] = 0x34;
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

static bool dns_result_address_equal(const dns_address_record *record, const char *expected) {
	if (record == NULL || expected == NULL) {
		return false;
	}
	uint8_t address[16] = { 0 };
	size_t address_size = record->address.family == AF_INET ? sizeof(uint32_t) : sizeof(address);
	return inet_pton(record->address.family, expected, address) == 1 && memcmp(&record->address.addr, address, address_size) == 0;
}

static bool dns_status_complete(dns_address_parse_status status) {
	return status == DNS_ADDRESS_PARSE_OK || status == DNS_ADDRESS_PARSE_ALIAS_ONLY || status == DNS_ADDRESS_PARSE_NODATA || status == DNS_ADDRESS_PARSE_NXDOMAIN || status == DNS_ADDRESS_PARSE_RCODE_ERROR;
}

static bool dns_test_aliases(void) {
	dns_message_builder builder;
	dns_address_result result = { 0 };
	uint8_t wire_name[NS_MAXCDNAME];
	size_t wire_name_size;
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "Alias.Example.", ns_t_a), "cannot start alias response");
	uint8_t address_first[4] = { 192, 0, 2, 10 };
	uint8_t address_second[4] = { 192, 0, 2, 11 };
	CHECK(dns_builder_record_add(&builder, "final.example", DNS_TEST_NO_POINTER, ns_t_a, ns_c_in, 600, address_first, sizeof(address_first), NULL), "cannot add first aliased address");
	CHECK(dns_builder_record_add(&builder, "unrelated.example", DNS_TEST_NO_POINTER, ns_t_a, ns_c_in, 1, address_second, sizeof(address_second), NULL), "cannot add unrelated address");
	CHECK(dns_builder_record_add(&builder, "final.example", DNS_TEST_NO_POINTER, ns_t_a, ns_c_in, 30, address_second, sizeof(address_second), NULL), "cannot add second aliased address");
	CHECK(dns_builder_wire_name_create("final.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode final alias name");
	CHECK(dns_builder_record_add(&builder, "middle.example", DNS_TEST_NO_POINTER, ns_t_cname, ns_c_in, 120, wire_name, wire_name_size, NULL), "cannot add final alias");
	CHECK(dns_builder_wire_name_create("middle.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode middle alias name");
	CHECK(dns_builder_record_add(&builder, "alias.example", DNS_TEST_NO_POINTER, ns_t_cname, ns_c_in, 300, wire_name, wire_name_size, NULL), "cannot add initial alias");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_OK, "cannot parse multi-level alias response");
	CHECK(strcmp(result.question_name, "alias.example") == 0 && strcmp(result.canonical_name, "final.example") == 0, "alias names were normalized incorrectly");
	CHECK(result.cname_count == 2 && result.address_count == 2, "alias response returned the wrong record counts");
	CHECK(strcmp(result.cnames[0].owner, "alias.example") == 0 && strcmp(result.cnames[0].target, "middle.example") == 0 && result.cnames[0].ttl == 300, "initial alias was parsed incorrectly");
	CHECK(strcmp(result.cnames[1].owner, "middle.example") == 0 && strcmp(result.cnames[1].target, "final.example") == 0 && result.cnames[1].ttl == 120, "final alias was parsed incorrectly");
	CHECK(dns_result_address_equal(&result.addresses[0], "192.0.2.10") && result.addresses[0].record_ttl == 600 && result.addresses[0].effective_ttl == 120, "first aliased address was parsed incorrectly");
	CHECK(dns_result_address_equal(&result.addresses[1], "192.0.2.11") && result.addresses[1].record_ttl == 30 && result.addresses[1].effective_ttl == 30, "second aliased address was parsed incorrectly");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "compressed.example", ns_t_a), "cannot start compressed response");
	CHECK(dns_builder_wire_name_create("target.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode compressed target");
	size_t target_offset;
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 45, wire_name, wire_name_size, &target_offset), "cannot add compressed alias");
	CHECK(dns_builder_record_add(&builder, NULL, target_offset, ns_t_a, ns_c_in, 90, address_first, sizeof(address_first), NULL), "cannot add compressed-owner address");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_OK, "cannot parse compressed alias response");
	CHECK(result.cname_count == 1 && result.address_count == 1 && result.addresses[0].effective_ttl == 45, "compressed alias response was parsed incorrectly");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "duplicate.example", ns_t_a), "cannot start duplicate alias response");
	CHECK(dns_builder_wire_name_create("target.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode duplicate target");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 80, wire_name, wire_name_size, NULL), "cannot add first duplicate alias");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 20, wire_name, wire_name_size, NULL), "cannot add second duplicate alias");
	CHECK(dns_builder_record_add(&builder, "target.example", DNS_TEST_NO_POINTER, ns_t_a, ns_c_in, 100, address_first, sizeof(address_first), NULL), "cannot add duplicate-alias address");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_OK, "cannot parse duplicate alias response");
	CHECK(result.cname_count == 1 && result.cnames[0].ttl == 20 && result.addresses[0].effective_ttl == 20, "duplicate aliases did not use the minimum TTL");

	test_result = true;

cleanup:
	dns_address_result_destroy(&result);
	return test_result;
}

static bool dns_test_arguments(void) {
	dns_message_builder builder;
	dns_address_result result = { 0 };
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "arguments.example", ns_t_a), "cannot start argument response");
	CHECK(dns_address_response_parse(NULL, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_BAD_ARGUMENT, "NULL message was accepted");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_UNSPEC, &result) == DNS_ADDRESS_PARSE_BAD_ARGUMENT, "invalid family was accepted");
	CHECK(dns_address_response_parse(builder.data, (size_t)INT_MAX + 1, AF_INET, &result) == DNS_ADDRESS_PARSE_BAD_ARGUMENT, "oversized message was accepted");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, NULL) == DNS_ADDRESS_PARSE_BAD_ARGUMENT, "NULL result was accepted");
	result.question_name[0] = 'x';
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_BAD_ARGUMENT, "non-empty result was accepted");
	dns_address_result_destroy(&result);
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_NODATA, "destroyed result could not be reused");
	dns_address_result_destroy(&result);
	dns_address_result_destroy(&result);
	dns_address_result_destroy(NULL);
	test_result = true;

cleanup:
	dns_address_result_destroy(&result);
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
	dns_message_builder address_response;
	dns_address_result result = { 0 };
	uint8_t wire_name[NS_MAXCDNAME];
	uint8_t wire_soa[NS_MAXCDNAME * 2 + 20];
	size_t wire_name_size;
	size_t wire_soa_size;
	int test_result = false;
	CHECK(dns_builder_response_start(&address_response, "lookup.example", ns_t_a), "cannot start lookup response");
	uint8_t address_first[4] = { 192, 0, 2, 20 };
	uint8_t address_second[4] = { 192, 0, 2, 21 };
	CHECK(dns_builder_record_add(&address_response, NULL, address_response.question_name_offset, ns_t_a, ns_c_in, 90, address_first, sizeof(address_first), NULL), "cannot add first lookup address");
	CHECK(dns_builder_record_add(&address_response, NULL, address_response.question_name_offset, ns_t_a, ns_c_in, 30, address_second, sizeof(address_second), NULL), "cannot add second lookup address");
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ 0, "lookup.example", &address_response, ns_t_a };
	dns_query_fixture_count = 1;
	CHECK(dns_address_lookup("lookup.example", AF_INET, &result) == DNS_ADDRESS_LOOKUP_OK, "cannot look up IPv4 RRset");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "IPv4 lookup issued the wrong query");
	CHECK(result.address_count == 2 && dns_result_address_equal(&result.addresses[0], "192.0.2.20") && dns_result_address_equal(&result.addresses[1], "192.0.2.21"), "IPv4 lookup lost address records");
	CHECK(result.addresses[0].effective_ttl == 90 && result.addresses[1].effective_ttl == 30, "IPv4 lookup lost record TTLs");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&address_response, "unexpected.lookup", ns_t_a), "cannot start mismatched-question lookup response");
	CHECK(dns_builder_record_add(&address_response, NULL, address_response.question_name_offset, ns_t_a, ns_c_in, 30, address_first, sizeof(address_first), NULL), "cannot add mismatched-question lookup address");
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ 0, "expected.lookup", &address_response, ns_t_a };
	dns_query_fixture_count = 1;
	CHECK(dns_address_lookup("expected.lookup", AF_INET, &result) == DNS_ADDRESS_LOOKUP_MALFORMED, "lookup accepted a response for a different question");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "mismatched-question lookup issued the wrong exact query");

	CHECK(dns_builder_response_start(&alias_response, "alias.lookup", ns_t_a), "cannot start lookup alias response");
	CHECK(dns_builder_wire_name_create("target.lookup", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode lookup alias target");
	CHECK(dns_builder_record_add(&alias_response, NULL, alias_response.question_name_offset, ns_t_cname, ns_c_in, 15, wire_name, wire_name_size, NULL), "cannot add lookup alias");
	CHECK(dns_builder_response_start(&address_response, "target.lookup", ns_t_a), "cannot start aliased lookup response");
	CHECK(dns_builder_record_add(&address_response, NULL, address_response.question_name_offset, ns_t_a, ns_c_in, 60, address_first, sizeof(address_first), NULL), "cannot add aliased lookup address");
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ 0, "alias.lookup", &alias_response, ns_t_a };
	dns_query_fixtures[1] = (dns_query_fixture){ 0, "target.lookup", &address_response, ns_t_a };
	dns_query_fixture_count = 2;
	CHECK(dns_address_lookup("alias.lookup", AF_INET, &result) == DNS_ADDRESS_LOOKUP_OK, "cannot follow CNAME-only lookup response");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "aliased lookup issued the wrong queries");
	bool alias_names_match = strcmp(result.question_name, "alias.lookup") == 0 && strcmp(result.canonical_name, "target.lookup") == 0;
	CHECK(result.cname_count == 1 && result.address_count == 1 && alias_names_match, "aliased lookup returned the wrong chain");
	CHECK(result.addresses[0].record_ttl == 60 && result.addresses[0].effective_ttl == 15, "aliased lookup did not combine TTLs across responses");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&alias_response, "negative.alias.lookup", ns_t_a), "cannot start negative lookup alias response");
	CHECK(dns_builder_wire_name_create("negative.target.lookup", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode negative lookup alias target");
	CHECK(dns_builder_record_add(&alias_response, NULL, alias_response.question_name_offset, ns_t_cname, ns_c_in, 25, wire_name, wire_name_size, NULL), "cannot add negative lookup alias");
	CHECK(dns_builder_response_start(&address_response, "negative.target.lookup", ns_t_a), "cannot start raw NXDOMAIN lookup response");
	CHECK(dns_builder_wire_soa_create("ns.lookup", "hostmaster.lookup", 60, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode raw NXDOMAIN lookup SOA");
	CHECK(dns_builder_authority_add(&address_response, "lookup", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 90, wire_soa, wire_soa_size), "cannot add raw NXDOMAIN lookup SOA");
	address_response.data[3] = (uint8_t)((address_response.data[3] & 0xF0) | ns_r_nxdomain);
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ 0, "negative.alias.lookup", &alias_response, ns_t_a };
	dns_query_fixtures[1] = (dns_query_fixture){ 0, "negative.target.lookup", &address_response, ns_t_a };
	dns_query_fixture_count = 2;
	CHECK(dns_address_lookup("negative.alias.lookup", AF_INET, &result) == DNS_ADDRESS_LOOKUP_NOT_FOUND, "cannot retain raw NXDOMAIN lookup response");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "negative lookup issued the wrong exact queries");
	CHECK(result.cname_count == 1 && strcmp(result.canonical_name, "negative.target.lookup") == 0, "negative lookup lost its cross-response CNAME chain");
	CHECK(result.negative.valid && strcmp(result.negative.owner, "lookup") == 0 && result.negative.record_ttl == 90 && result.negative.minimum == 60 && result.negative.effective_ttl == 25,
		"negative lookup did not preserve or fold authoritative metadata");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&address_response, "nodata.lookup", ns_t_a), "cannot start raw NODATA lookup response");
	CHECK(dns_builder_wire_soa_create("ns.lookup", "hostmaster.lookup", 40, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode raw NODATA lookup SOA");
	CHECK(dns_builder_authority_add(&address_response, "lookup", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 80, wire_soa, wire_soa_size), "cannot add raw NODATA lookup SOA");
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ 0, "nodata.lookup", &address_response, ns_t_a };
	dns_query_fixture_count = 1;
	CHECK(dns_address_lookup("nodata.lookup", AF_INET, &result) == DNS_ADDRESS_LOOKUP_NODATA, "cannot retain raw NODATA lookup response");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count && result.negative.valid && result.negative.effective_ttl == 40,
		"NODATA lookup lost its query or authoritative negative TTL");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&alias_response, "a.lookup", ns_t_a), "cannot start cross-response loop a");
	CHECK(dns_builder_wire_name_create("b.lookup", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode cross-response loop b");
	CHECK(dns_builder_record_add(&alias_response, NULL, alias_response.question_name_offset, ns_t_cname, ns_c_in, 15, wire_name, wire_name_size, NULL), "cannot add cross-response loop a");
	CHECK(dns_builder_response_start(&address_response, "b.lookup", ns_t_a), "cannot start cross-response loop b");
	CHECK(dns_builder_wire_name_create("a.lookup", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode cross-response loop a");
	CHECK(dns_builder_record_add(&address_response, NULL, address_response.question_name_offset, ns_t_cname, ns_c_in, 15, wire_name, wire_name_size, NULL), "cannot add cross-response loop b");
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ 0, "a.lookup", &alias_response, ns_t_a };
	dns_query_fixtures[1] = (dns_query_fixture){ 0, "b.lookup", &address_response, ns_t_a };
	dns_query_fixture_count = 2;
	CHECK(dns_address_lookup("a.lookup", AF_INET, &result) == DNS_ADDRESS_LOOKUP_MALFORMED, "cross-response CNAME loop was accepted");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "looping lookup issued the wrong queries");
	CHECK(result.addresses == NULL && result.cnames == NULL, "failed lookup returned partial records");

	static const struct {
		int resolver_error;
		dns_address_lookup_status status;
	} resolver_errors[] = {
		{ HOST_NOT_FOUND, DNS_ADDRESS_LOOKUP_NOT_FOUND },
		{ NO_DATA, DNS_ADDRESS_LOOKUP_NODATA },
		{ NO_RECOVERY, DNS_ADDRESS_LOOKUP_PERMANENT_ERROR },
		{ TRY_AGAIN, DNS_ADDRESS_LOOKUP_TEMPORARY_ERROR }
	};
	for (size_t index = 0; index < sizeof(resolver_errors) / sizeof(resolver_errors[0]); index++) {
		dns_test_query_reset();
		dns_query_fixtures[0] = (dns_query_fixture){ resolver_errors[index].resolver_error, "error.lookup", NULL, ns_t_a };
		dns_query_fixture_count = 1;
		CHECK(dns_address_lookup("error.lookup", AF_INET, &result) == resolver_errors[index].status, "resolver failure returned the wrong status");
		CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "resolver failure issued the wrong query");
		dns_address_result_destroy(&result);
	}

	CHECK(dns_builder_response_start(&address_response, "error.lookup", ns_t_a), "cannot start DNS error response");
	address_response.data[3] = (uint8_t)((address_response.data[3] & 0xF0) | ns_r_servfail);
	dns_test_query_reset();
	dns_query_fixtures[0] = (dns_query_fixture){ 0, "error.lookup", &address_response, ns_t_a };
	dns_query_fixture_count = 1;
	CHECK(dns_address_lookup("error.lookup", AF_INET, &result) == DNS_ADDRESS_LOOKUP_TEMPORARY_ERROR, "SERVFAIL response was not treated as temporary");
	CHECK(result.rcode == ns_r_servfail, "lookup did not retain SERVFAIL rcode");
	dns_address_result_destroy(&result);

	dns_test_query_reset();
	CHECK(dns_address_lookup(NULL, AF_INET, &result) == DNS_ADDRESS_LOOKUP_BAD_ARGUMENT, "lookup accepted a NULL hostname");
	CHECK(dns_address_lookup("", AF_INET, &result) == DNS_ADDRESS_LOOKUP_BAD_ARGUMENT, "lookup accepted an empty hostname");
	CHECK(dns_address_lookup("lookup.example", AF_UNSPEC, &result) == DNS_ADDRESS_LOOKUP_BAD_ARGUMENT, "lookup accepted an invalid family");
	CHECK(dns_query_fixture_index == 0, "invalid lookup issued a resolver query");

	test_result = true;

cleanup:
	dns_address_result_destroy(&result);
	dns_test_query_reset();
	return test_result;
}

static bool dns_test_lookup_depth(void) {
	dns_message_builder *responses = NULL;
	dns_address_result result = { 0 };
	char query_names[DNS_CNAME_DEPTH_LIMIT + 2][NS_MAXDNAME];
	uint8_t wire_name[NS_MAXCDNAME];
	size_t wire_name_size;
	int test_result = false;
	responses = calloc(DNS_CNAME_DEPTH_LIMIT + 1, sizeof(*responses));
	CHECK(responses != NULL, "cannot allocate cross-response depth fixtures");
	for (size_t index = 0; index < DNS_CNAME_DEPTH_LIMIT + 2; index++) {
		int name_size = snprintf(query_names[index], sizeof(query_names[index]), "depth%zu.lookup", index);
		CHECK(name_size > 0 && (size_t)name_size < sizeof(query_names[index]), "cannot format cross-response depth name");
	}
	dns_test_query_reset();
	for (size_t index = 0; index < DNS_CNAME_DEPTH_LIMIT + 1; index++) {
		CHECK(dns_builder_response_start(&responses[index], query_names[index], ns_t_a), "cannot start cross-response depth fixture");
		CHECK(dns_builder_wire_name_create(query_names[index + 1], wire_name, sizeof(wire_name), &wire_name_size), "cannot encode cross-response depth target");
		CHECK(dns_builder_record_add(&responses[index], NULL, responses[index].question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size, NULL),
			"cannot add cross-response depth alias");
		dns_query_fixtures[index] = (dns_query_fixture){ 0, query_names[index], &responses[index], ns_t_a };
	}
	dns_query_fixture_count = DNS_CNAME_DEPTH_LIMIT + 1;
	CHECK(dns_address_lookup(query_names[0], AF_INET, &result) == DNS_ADDRESS_LOOKUP_LIMIT, "cross-response CNAME depth limit was not enforced");
	CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "depth-limited lookup issued the wrong queries");
	CHECK(result.addresses == NULL && result.address_count == 0 && result.cnames == NULL && result.cname_count == 0, "depth-limited lookup returned partial records");
	test_result = true;

cleanup:
	dns_address_result_destroy(&result);
	dns_test_query_reset();
	free(responses);
	return test_result;
}

static bool dns_test_malformed(void) {
	dns_message_builder builder;
	dns_address_result result = { 0 };
	uint8_t address[16] = { 192, 0, 2, 1 };
	uint8_t wire_name[NS_MAXCDNAME];
	size_t wire_name_size;
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "bad.example", ns_t_a), "cannot start malformed address response");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_a, ns_c_in, 30, address, 3, NULL), "cannot add malformed address");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "short A record was accepted");

	CHECK(dns_builder_response_start(&builder, "bad.example", ns_t_aaaa), "cannot start malformed IPv6 response");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_aaaa, ns_c_in, 30, address, 15, NULL), "cannot add malformed IPv6 address");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET6, &result) == DNS_ADDRESS_PARSE_MALFORMED, "short AAAA record was accepted");

	CHECK(dns_builder_response_start(&builder, "bad.example", ns_t_a), "cannot restart malformed alias response");
	CHECK(dns_builder_wire_name_create("target.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode malformed alias target");
	wire_name[wire_name_size++] = 0;
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size, NULL), "cannot add alias with trailing data");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "CNAME with trailing data was accepted");

	CHECK(dns_builder_response_start(&builder, "bad.example", ns_t_a), "cannot restart malformed pointer response");
	uint8_t bad_pointer[2] = { 0xFF, 0xFF };
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, bad_pointer, sizeof(bad_pointer), NULL), "cannot add invalid compression pointer");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "out-of-range compression pointer was accepted");

	CHECK(dns_builder_response_start(&builder, "bad.example", ns_t_a), "cannot restart self-pointer response");
	size_t self_pointer_offset = builder.size + 2 + 10;
	uint8_t self_pointer[2] = { (uint8_t)(0xC0 | (self_pointer_offset >> 8)), (uint8_t)self_pointer_offset };
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, self_pointer, sizeof(self_pointer), NULL), "cannot add self compression pointer");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "self compression pointer was accepted");

	CHECK(dns_builder_response_start(&builder, "a.example", ns_t_a), "cannot start semantic alias loop");
	CHECK(dns_builder_wire_name_create("b.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode loop target b");
	CHECK(dns_builder_record_add(&builder, "a.example", DNS_TEST_NO_POINTER, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size, NULL), "cannot add loop alias a");
	CHECK(dns_builder_wire_name_create("a.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode loop target a");
	CHECK(dns_builder_record_add(&builder, "b.example", DNS_TEST_NO_POINTER, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size, NULL), "cannot add loop alias b");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "semantic CNAME loop was accepted");

	CHECK(dns_builder_response_start(&builder, "conflict.example", ns_t_a), "cannot start conflicting alias response");
	CHECK(dns_builder_wire_name_create("first.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode first conflicting target");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size, NULL), "cannot add first conflicting alias");
	CHECK(dns_builder_wire_name_create("second.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode second conflicting target");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size, NULL), "cannot add second conflicting alias");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "conflicting CNAME targets were accepted");

	CHECK(dns_builder_response_start(&builder, "mixed.example", ns_t_a), "cannot start mixed alias response");
	CHECK(dns_builder_wire_name_create("target.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode mixed alias target");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size, NULL), "cannot add mixed alias");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_a, ns_c_in, 30, address, sizeof(uint32_t), NULL), "cannot add mixed address");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "CNAME and address at the same owner were accepted");

	CHECK(dns_builder_response_start(&builder, "n0.example", ns_t_a), "cannot start excessive alias chain");
	for (size_t index = 0; index <= DNS_CNAME_DEPTH_LIMIT; index++) {
		char owner[32];
		char target[32];
		CHECK(snprintf(owner, sizeof(owner), "n%zu.example", index) > 0, "cannot format excessive alias owner");
		CHECK(snprintf(target, sizeof(target), "n%zu.example", index + 1) > 0, "cannot format excessive alias target");
		CHECK(dns_builder_wire_name_create(target, wire_name, sizeof(wire_name), &wire_name_size), "cannot encode excessive alias target");
		CHECK(dns_builder_record_add(&builder, owner, DNS_TEST_NO_POINTER, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size, NULL), "cannot add excessive alias");
	}
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_LIMIT, "excessive CNAME chain was accepted");

	CHECK(dns_builder_response_start(&builder, "limit.example", ns_t_a), "cannot start excessive answer response");
	for (size_t index = 0; index <= DNS_ADDRESS_RECORD_LIMIT; index++) {
		CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_txt, ns_c_in, 1, NULL, 0, NULL), "cannot add excessive answer");
	}
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_LIMIT, "excessive answer count was accepted");

	CHECK(dns_builder_response_start(&builder, "negative.example", ns_t_a), "cannot start short SOA response");
	uint8_t short_soa[19] = { 0 };
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 30, short_soa, sizeof(short_soa)), "cannot add short SOA record");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "short SOA record was accepted");

	CHECK(dns_builder_response_start(&builder, "negative.example", ns_t_a), "cannot start invalid-pointer SOA response");
	uint8_t invalid_soa[24] = { 0xFF, 0xFF };
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 30, invalid_soa, sizeof(invalid_soa)), "cannot add invalid-pointer SOA record");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "invalid SOA compression pointer was accepted");

	CHECK(dns_builder_response_start(&builder, "negative.example", ns_t_a), "cannot start trailing-data SOA response");
	uint8_t trailing_soa[NS_MAXCDNAME * 2 + 21];
	size_t trailing_soa_size;
	CHECK(dns_builder_wire_soa_create("ns.example", "hostmaster.example", 30, trailing_soa, sizeof(trailing_soa), &trailing_soa_size), "cannot encode trailing-data SOA record");
	trailing_soa[trailing_soa_size++] = 0;
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 30, trailing_soa, trailing_soa_size), "cannot add trailing-data SOA record");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "SOA record with trailing data was accepted");

	CHECK(dns_builder_response_start(&builder, "negative.example", ns_t_a), "cannot start excessive-authority response");
	for (size_t index = 0; index <= DNS_AUTHORITY_RECORD_LIMIT; index++) {
		CHECK(dns_builder_authority_add(&builder, NULL, builder.question_name_offset, ns_t_txt, ns_c_in, 1, NULL, 0), "cannot add excessive authority record");
	}
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_LIMIT, "excessive authority count was accepted");

	CHECK(dns_builder_response_start(&builder, "contradictory.example", ns_t_a), "cannot start contradictory NXDOMAIN response");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_a, ns_c_in, 30, address, sizeof(uint32_t), NULL), "cannot add contradictory NXDOMAIN address");
	builder.data[3] = (uint8_t)((builder.data[3] & 0xF0) | ns_r_nxdomain);
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "NXDOMAIN response with terminal address data was accepted");

	test_result = true;

cleanup:
	dns_address_result_destroy(&result);
	return test_result;
}

static bool dns_test_negative(void) {
	dns_message_builder builder;
	dns_address_result result = { 0 };
	uint8_t wire_name[NS_MAXCDNAME];
	uint8_t wire_soa[NS_MAXCDNAME * 2 + 20];
	size_t wire_name_size;
	size_t wire_soa_size;
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "nodata.example", ns_t_a), "cannot start NODATA SOA response");
	CHECK(dns_builder_wire_soa_create("ns.example", "hostmaster.example", 120, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode NODATA SOA record");
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 300, wire_soa, wire_soa_size), "cannot add NODATA SOA record");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_NODATA, "cannot parse authoritative NODATA response");
	CHECK(result.negative.valid && strcmp(result.negative.owner, "example") == 0 && result.negative.record_ttl == 300 && result.negative.minimum == 120 && result.negative.effective_ttl == 120,
		"NODATA negative metadata was parsed incorrectly");
	dns_address_result_destroy(&result);
	for (size_t prefix_size = 0; prefix_size < builder.size; prefix_size++) {
		dns_address_parse_status status = dns_address_response_parse(builder.data, prefix_size, AF_INET, &result);
		CHECK(!dns_status_complete(status), "truncated authoritative NODATA response was accepted");
		dns_address_result_destroy(&result);
	}

	CHECK(dns_builder_response_start(&builder, "absent.example", ns_t_a), "cannot start NODATA response without SOA");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_NODATA, "cannot parse NODATA response without SOA");
	CHECK(!result.negative.valid, "NODATA response without SOA produced authoritative negative metadata");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "missing.example", ns_t_a), "cannot start NODATA response with unrelated SOA");
	CHECK(dns_builder_wire_soa_create("ns.other.example", "hostmaster.other.example", 1, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode unrelated-only SOA record");
	CHECK(dns_builder_authority_add(&builder, "other.example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 1, wire_soa, wire_soa_size), "cannot add unrelated-only SOA record");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_NODATA, "cannot parse NODATA response with unrelated SOA");
	CHECK(!result.negative.valid, "unrelated SOA produced authoritative negative metadata");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "alias.negative.example", ns_t_a), "cannot start aliased NXDOMAIN response");
	CHECK(dns_builder_wire_name_create("missing.sub.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode negative alias target");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 20, wire_name, wire_name_size, NULL), "cannot add negative alias");
	CHECK(dns_builder_wire_soa_create("ns.example", "hostmaster.example", 120, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode NXDOMAIN SOA record");
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 300, wire_soa, wire_soa_size), "cannot add NXDOMAIN SOA record");
	builder.data[3] = (uint8_t)((builder.data[3] & 0xF0) | ns_r_nxdomain);
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_NXDOMAIN, "cannot parse aliased NXDOMAIN response");
	CHECK(result.cname_count == 1 && strcmp(result.canonical_name, "missing.sub.example") == 0, "NXDOMAIN response lost its CNAME chain");
	CHECK(result.negative.valid && result.negative.effective_ttl == 20, "NXDOMAIN negative TTL did not include the CNAME TTL");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "missing.sub.example", ns_t_a), "cannot start closest-zone NODATA response");
	CHECK(dns_builder_wire_soa_create("ns.example", "hostmaster.example", 5, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode root SOA record");
	CHECK(dns_builder_authority_add(&builder, ".", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 5, wire_soa, wire_soa_size), "cannot add root SOA record");
	CHECK(dns_builder_wire_soa_create("ns.example", "hostmaster.example", 150, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode parent SOA record");
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 200, wire_soa, wire_soa_size), "cannot add parent SOA record");
	CHECK(dns_builder_wire_soa_create("ns.sub.example", "hostmaster.sub.example", 80, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode closest SOA record");
	CHECK(dns_builder_authority_add(&builder, "sub.example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 100, wire_soa, wire_soa_size), "cannot add closest SOA record");
	CHECK(dns_builder_wire_soa_create("ns.sub.example", "hostmaster.sub.example", 200, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode duplicate SOA record");
	CHECK(dns_builder_authority_add(&builder, "SUB.EXAMPLE.", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 30, wire_soa, wire_soa_size), "cannot add duplicate SOA record");
	CHECK(dns_builder_wire_soa_create("ns.other.example", "hostmaster.other.example", 1, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode unrelated SOA record");
	CHECK(dns_builder_authority_add(&builder, "other.example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 1, wire_soa, wire_soa_size), "cannot add unrelated SOA record");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_NODATA, "cannot parse closest-zone NODATA response");
	CHECK(result.negative.valid && strcmp(result.negative.owner, "sub.example") == 0 && result.negative.record_ttl == 30 && result.negative.minimum == 80 && result.negative.effective_ttl == 30,
		"closest or duplicate SOA selection was incorrect");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "zero.example", ns_t_a), "cannot start zero-TTL NODATA response");
	CHECK(dns_builder_wire_soa_create("ns.example", "hostmaster.example", 0, wire_soa, sizeof(wire_soa), &wire_soa_size), "cannot encode zero-TTL SOA record");
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 300, wire_soa, wire_soa_size), "cannot add zero-TTL SOA record");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_NODATA, "cannot parse zero-TTL NODATA response");
	CHECK(result.negative.valid && result.negative.effective_ttl == 0, "valid zero negative TTL was not distinguished from absent metadata");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "compressed.example", ns_t_a), "cannot start compressed SOA response");
	wire_soa[0] = (uint8_t)(0xC0 | (builder.question_name_offset >> 8));
	wire_soa[1] = (uint8_t)builder.question_name_offset;
	wire_soa[2] = wire_soa[0];
	wire_soa[3] = wire_soa[1];
	memset(wire_soa + 4, 0, 20);
	wire_soa[23] = 40;
	CHECK(dns_builder_authority_add(&builder, "example", DNS_TEST_NO_POINTER, ns_t_soa, ns_c_in, 50, wire_soa, 24), "cannot add compressed SOA record");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_NODATA, "cannot parse compressed SOA response");
	CHECK(result.negative.valid && result.negative.minimum == 40 && result.negative.effective_ttl == 40, "compressed SOA names or fields were parsed incorrectly");
	test_result = true;

cleanup:
	dns_address_result_destroy(&result);
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
	if (fixture->error != 0) {
		resolver->res_h_errno = fixture->error;
		return -1;
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
	dns_address_result result = { 0 };
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "multi.example", ns_t_a), "cannot start IPv4 response");
	uint8_t address_first[4] = { 192, 0, 2, 1 };
	uint8_t address_second[4] = { 198, 51, 100, 2 };
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_a, ns_c_in, 300, address_first, sizeof(address_first), NULL), "cannot add first IPv4 address");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_a, ns_c_in, 30, address_second, sizeof(address_second), NULL), "cannot add second IPv4 address");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_OK, "cannot parse IPv4 RRset");
	CHECK(result.address_count == 2 && result.cname_count == 0, "IPv4 RRset returned the wrong record counts");
	CHECK(strcmp(result.question_name, "multi.example") == 0 && strcmp(result.canonical_name, "multi.example") == 0, "direct IPv4 names were parsed incorrectly");
	CHECK(dns_result_address_equal(&result.addresses[0], "192.0.2.1") && result.addresses[0].record_ttl == 300 && result.addresses[0].effective_ttl == 300, "first IPv4 address was parsed incorrectly");
	CHECK(dns_result_address_equal(&result.addresses[1], "198.51.100.2") && result.addresses[1].record_ttl == 30 && result.addresses[1].effective_ttl == 30, "second IPv4 address was parsed incorrectly");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "multi.example", ns_t_aaaa), "cannot start IPv6 response");
	uint8_t address_v6_first[16];
	uint8_t address_v6_second[16];
	CHECK(inet_pton(AF_INET6, "2001:db8::1", address_v6_first) == 1 && inet_pton(AF_INET6, "2001:db8::2", address_v6_second) == 1, "cannot create IPv6 test addresses");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_aaaa, ns_c_in, 400, address_v6_first, sizeof(address_v6_first), NULL), "cannot add first IPv6 address");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_aaaa, ns_c_in, 40, address_v6_second, sizeof(address_v6_second), NULL), "cannot add second IPv6 address");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET6, &result) == DNS_ADDRESS_PARSE_OK, "cannot parse IPv6 RRset");
	CHECK(result.address_count == 2 && dns_result_address_equal(&result.addresses[0], "2001:db8::1") && dns_result_address_equal(&result.addresses[1], "2001:db8::2"), "IPv6 addresses did not preserve DNS order");
	CHECK(result.addresses[0].effective_ttl == 400 && result.addresses[1].effective_ttl == 40, "IPv6 TTLs were parsed incorrectly");

	test_result = true;

cleanup:
	dns_address_result_destroy(&result);
	return test_result;
}

static bool dns_test_resolver_limits(void) {
	dns_message_builder builder;
	dns_address_result result = { 0 };
	uint8_t address[4] = { 192, 0, 2, 50 };
	const int expected_retrans[] = { DNS_QUERY_RETRANSMIT_TIMEOUT_SEC, 1 };
	const int expected_retry[] = { DNS_QUERY_ATTEMPT_LIMIT, 0 };
	const int initial_retrans[] = { DNS_QUERY_RETRANSMIT_TIMEOUT_SEC + 8, 1 };
	const int initial_retry[] = { DNS_QUERY_ATTEMPT_LIMIT + 4, 0 };
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "limits.example", ns_t_a), "cannot start resolver-limit response");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_a, ns_c_in, 30, address, sizeof(address), NULL), "cannot add resolver-limit address");
	for (size_t limit_index = 0; limit_index < sizeof(initial_retry) / sizeof(initial_retry[0]); limit_index++) {
		dns_resolver.expected_retrans = expected_retrans[limit_index];
		dns_resolver.expected_retry = expected_retry[limit_index];
		dns_resolver.initial_retrans = initial_retrans[limit_index];
		dns_resolver.initial_retry = initial_retry[limit_index];
		size_t close_count = dns_resolver.close_count;
		size_t init_count = dns_resolver.init_count;
		dns_test_query_reset();
		dns_query_fixtures[0] = (dns_query_fixture){ 0, "limits.example", &builder, ns_t_a };
		dns_query_fixture_count = 1;
		CHECK(dns_address_lookup("limits.example", AF_INET, &result) == DNS_ADDRESS_LOOKUP_OK, "resolver limits broke address lookup");
		CHECK(!dns_query_mismatch && dns_query_fixture_index == dns_query_fixture_count, "address lookup applied the wrong resolver limits");
		CHECK(dns_resolver.init_count == init_count + 1 && dns_resolver.close_count == close_count + 1, "address lookup did not close its initialized resolver state");
		dns_address_result_destroy(&result);
	}
	test_result = true;

cleanup:
	dns_resolver.expected_retrans = DNS_QUERY_RETRANSMIT_TIMEOUT_SEC;
	dns_resolver.expected_retry = DNS_QUERY_ATTEMPT_LIMIT;
	dns_resolver.initial_retrans = DNS_QUERY_RETRANSMIT_TIMEOUT_SEC + 1;
	dns_resolver.initial_retry = DNS_QUERY_ATTEMPT_LIMIT + 1;
	dns_address_result_destroy(&result);
	return test_result;
}

static bool dns_test_statuses(void) {
	dns_message_builder builder;
	dns_address_result result = { 0 };
	uint8_t wire_name[NS_MAXCDNAME];
	size_t wire_name_size;
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "status.example", ns_t_a), "cannot start NODATA response");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_NODATA, "NODATA response was not identified");
	CHECK(strcmp(result.question_name, "status.example") == 0 && strcmp(result.canonical_name, "status.example") == 0, "NODATA names were not retained");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "status.example", ns_t_a), "cannot start alias-only response");
	CHECK(dns_builder_wire_name_create("target.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode alias-only target");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 50, wire_name, wire_name_size, NULL), "cannot add alias-only record");
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_ALIAS_ONLY, "alias-only response was not identified");
	CHECK(result.cname_count == 1 && result.address_count == 0 && strcmp(result.canonical_name, "target.example") == 0, "alias-only result was incomplete");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "status.example", ns_t_a), "cannot start NXDOMAIN response");
	builder.data[3] = (uint8_t)((builder.data[3] & 0xF0) | ns_r_nxdomain);
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_NXDOMAIN, "NXDOMAIN response was not identified");
	CHECK(result.rcode == ns_r_nxdomain && strcmp(result.question_name, "status.example") == 0, "NXDOMAIN metadata was not retained");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "status.example", ns_t_a), "cannot start SERVFAIL response");
	builder.data[3] = (uint8_t)((builder.data[3] & 0xF0) | ns_r_servfail);
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_RCODE_ERROR, "SERVFAIL response was not identified");
	CHECK(result.rcode == ns_r_servfail, "SERVFAIL rcode was not retained");
	dns_address_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "status.example", ns_t_a), "cannot start truncated response");
	builder.data[2] |= 0x02;
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_TRUNCATED, "truncated flag was ignored");

	CHECK(dns_builder_response_start(&builder, "status.example", ns_t_a), "cannot start request-shaped response");
	builder.data[2] &= 0x7F;
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "request-shaped message was accepted as a response");

	CHECK(dns_builder_response_start(&builder, "status.example", ns_t_a), "cannot start opcode response");
	builder.data[2] |= 0x08;
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "non-query opcode was accepted");

	CHECK(dns_builder_response_start(&builder, "status.example", ns_t_a), "cannot start wrong-type response");
	builder.data[builder.question_type_offset + 1] = ns_t_aaaa;
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "wrong question type was accepted");

	CHECK(dns_builder_response_start(&builder, "status.example", ns_t_a), "cannot start wrong-class response");
	builder.data[builder.question_class_offset + 1] = ns_c_chaos;
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_MALFORMED, "wrong question class was accepted");

	test_result = true;

cleanup:
	dns_address_result_destroy(&result);
	return test_result;
}

static bool dns_test_truncation(void) {
	dns_message_builder builder;
	dns_address_result result = { 0 };
	int test_result = false;
	CHECK(dns_builder_response_start(&builder, "truncate.example", ns_t_a), "cannot start truncation response");
	uint8_t address[4] = { 203, 0, 113, 1 };
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_a, ns_c_in, 30, address, sizeof(address), NULL), "cannot add truncation address");
	for (size_t prefix_size = 0; prefix_size < builder.size; prefix_size++) {
		dns_address_parse_status status = dns_address_response_parse(builder.data, prefix_size, AF_INET, &result);
		CHECK(!dns_status_complete(status), "truncated prefix was accepted as a complete response");
		dns_address_result_destroy(&result);
	}
	CHECK(dns_address_response_parse(builder.data, builder.size, AF_INET, &result) == DNS_ADDRESS_PARSE_OK, "complete response failed after truncation checks");
	test_result = true;

cleanup:
	dns_address_result_destroy(&result);
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
	if (dns_query_pending || dns_query_fixture_index >= dns_query_fixture_count || resolver == NULL || operation != ns_o_query || name == NULL || record_class != ns_c_in || data != NULL
		|| data_size != 0 || new_record != NULL || query == NULL || query_size < DNS_TEST_QUERY_SIZE) {
		dns_query_mismatch = true;
		if (resolver != NULL) {
			resolver->res_h_errno = NO_RECOVERY;
		}
		return -1;
	}
	const dns_query_fixture *fixture = &dns_query_fixtures[dns_query_fixture_index];
	if (fixture->name == NULL || strcmp(fixture->name, name) != 0 || fixture->type != type) {
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
