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
#include <netinet/in.h>
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

/* section: types */
typedef struct {
	size_t answer_count;
	uint8_t data[DNS_TEST_MESSAGE_CAPACITY];
	size_t question_class_offset;
	size_t question_name_offset;
	size_t question_type_offset;
	size_t size;
} dns_message_builder;

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
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_OK, "cannot parse aliased SRV response");
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
	CHECK(dns_srv_response_parse(NULL, builder.size, &result) == DNS_SRV_PARSE_BAD_ARGUMENT, "NULL SRV message was accepted");
	CHECK(dns_srv_response_parse(builder.data, (size_t)INT_MAX + 1, &result) == DNS_SRV_PARSE_BAD_ARGUMENT, "oversized SRV message was accepted");
	CHECK(dns_srv_response_parse(builder.data, builder.size, NULL) == DNS_SRV_PARSE_BAD_ARGUMENT, "NULL SRV result was accepted");
	result.question_name[0] = 'x';
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_BAD_ARGUMENT, "non-empty SRV result was accepted");
	dns_srv_result_destroy(&result);
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_NODATA, "destroyed SRV result could not be reused");
	dns_srv_result_destroy(&result);
	dns_srv_result_destroy(&result);
	dns_srv_result_destroy(NULL);
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
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
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_MALFORMED, "short SRV record was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.bad.example", ns_t_srv), "cannot restart malformed SRV response");
	CHECK(dns_builder_wire_srv_create(0, 0, 25565, "target.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode malformed SRV target");
	wire_srv[wire_srv_size++] = 0;
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add SRV record with trailing data");
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_MALFORMED, "SRV target with trailing data was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.bad.example", ns_t_srv), "cannot restart invalid-pointer SRV response");
	uint8_t bad_pointer_rdata[8] = { 0, 0, 0, 0, 0x63, 0xDD, 0xFF, 0xFF };
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 30, bad_pointer_rdata, sizeof(bad_pointer_rdata)), "cannot add invalid SRV target pointer");
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_MALFORMED, "invalid SRV target pointer was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.bad.example", ns_t_srv), "cannot restart conflicting SRV response");
	CHECK(dns_builder_wire_name_create("target.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode conflicting SRV alias");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size), "cannot add conflicting SRV alias");
	CHECK(dns_builder_wire_srv_create(0, 0, 25565, "node.example", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode conflicting SRV record");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add conflicting SRV record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_MALFORMED, "CNAME and SRV record at the same owner were accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.bad.example", ns_t_srv), "cannot restart conflicting-alias SRV response");
	CHECK(dns_builder_wire_name_create("first.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode first conflicting SRV alias");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size), "cannot add first conflicting SRV alias");
	CHECK(dns_builder_wire_name_create("second.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode second conflicting SRV alias");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size), "cannot add second conflicting SRV alias");
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_MALFORMED, "conflicting SRV alias targets were accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.loop.example", ns_t_srv), "cannot start looping SRV response");
	CHECK(dns_builder_wire_name_create("middle.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode forward SRV loop alias");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size), "cannot add forward SRV loop alias");
	CHECK(dns_builder_wire_name_create("_minecraft._tcp.loop.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode reverse SRV loop alias");
	CHECK(dns_builder_record_add(&builder, "middle.example", DNS_TEST_NO_POINTER, ns_t_cname, ns_c_in, 30, wire_name, wire_name_size), "cannot add reverse SRV loop alias");
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_MALFORMED, "looping SRV alias chain was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.limit.example", ns_t_srv), "cannot start excessive SRV response");
	CHECK(dns_builder_wire_srv_create(0, 0, 25565, ".", wire_srv, sizeof(wire_srv), &wire_srv_size), "cannot encode excessive SRV record");
	for (size_t index = 0; index < DNS_SRV_RECORD_LIMIT + 1; index++) {
		CHECK(dns_builder_record_add(&builder, "unrelated.example", DNS_TEST_NO_POINTER, ns_t_srv, ns_c_in, 30, wire_srv, wire_srv_size), "cannot add excessive SRV record");
	}
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_LIMIT, "excessive SRV answer count was accepted");

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
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_LIMIT, "excessive SRV CNAME depth was accepted");
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	return test_result;
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
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_OK, "cannot parse SRV RRset");
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
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_OK, "cannot parse unavailable SRV response");
	CHECK(result.record_count == 1 && strcmp(result.records[0].target, ".") == 0 && result.records[0].port == 0, "unavailable SRV target was not preserved");
	test_result = true;

cleanup:
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
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_NODATA, "SRV NODATA response was not identified");
	CHECK(strcmp(result.question_name, "_minecraft._tcp.status.example") == 0 && strcmp(result.canonical_name, "_minecraft._tcp.status.example") == 0, "SRV NODATA names were not retained");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start SRV alias-only response");
	CHECK(dns_builder_wire_name_create("_minecraft._tcp.target.example", wire_name, sizeof(wire_name), &wire_name_size), "cannot encode SRV alias-only target");
	CHECK(dns_builder_record_add(&builder, NULL, builder.question_name_offset, ns_t_cname, ns_c_in, 50, wire_name, wire_name_size), "cannot add SRV alias-only record");
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_ALIAS_ONLY, "SRV alias-only response was not identified");
	CHECK(result.cname_count == 1 && result.record_count == 0 && strcmp(result.canonical_name, "_minecraft._tcp.target.example") == 0, "SRV alias-only result was incomplete");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start SRV NXDOMAIN response");
	builder.data[3] = (uint8_t)((builder.data[3] & 0xF0) | ns_r_nxdomain);
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_NXDOMAIN, "SRV NXDOMAIN response was not identified");
	CHECK(result.rcode == ns_r_nxdomain && strcmp(result.question_name, "_minecraft._tcp.status.example") == 0, "SRV NXDOMAIN metadata was not retained");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start SRV SERVFAIL response");
	builder.data[3] = (uint8_t)((builder.data[3] & 0xF0) | ns_r_servfail);
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_RCODE_ERROR, "SRV SERVFAIL response was not identified");
	CHECK(result.rcode == ns_r_servfail, "SRV SERVFAIL rcode was not retained");
	dns_srv_result_destroy(&result);

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start truncated SRV response");
	builder.data[2] |= 0x02;
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_TRUNCATED, "SRV truncated flag was ignored");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start request-shaped SRV response");
	builder.data[2] &= 0x7F;
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_MALFORMED, "request-shaped SRV message was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start SRV opcode response");
	builder.data[2] |= 0x08;
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_MALFORMED, "non-query SRV opcode was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start wrong-type SRV response");
	builder.data[builder.question_type_offset + 1] = ns_t_a;
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_MALFORMED, "wrong SRV question type was accepted");

	CHECK(dns_builder_response_start(&builder, "_minecraft._tcp.status.example", ns_t_srv), "cannot start wrong-class SRV response");
	builder.data[builder.question_class_offset + 1] = ns_c_chaos;
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_MALFORMED, "wrong SRV question class was accepted");
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
		dns_srv_parse_status status = dns_srv_response_parse(builder.data, prefix_size, &result);
		CHECK(!dns_srv_status_complete(status), "truncated SRV prefix was accepted as a complete response");
		dns_srv_result_destroy(&result);
	}
	CHECK(dns_srv_response_parse(builder.data, builder.size, &result) == DNS_SRV_PARSE_OK, "complete SRV response failed after truncation checks");
	test_result = true;

cleanup:
	dns_srv_result_destroy(&result);
	return test_result;
}

/* section: functions (entry point) */
int main(void) {
	if (!dns_test_aliases() || !dns_test_arguments() || !dns_test_malformed() || !dns_test_records() || !dns_test_statuses() || !dns_test_truncation()) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
