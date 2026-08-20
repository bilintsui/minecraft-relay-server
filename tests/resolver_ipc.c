/*
 * resolver_ipc.c: Tests for the resolver helper IPC packet codec
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
#include "dns.h"
#include "resolver_ipc.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* packet */
#define IPC_TEST_HEADER_KIND_OFFSET	6
#define IPC_TEST_HEADER_QUERY_ID_OFFSET	12
#define IPC_TEST_HEADER_RESERVED_OFFSET	10
#define IPC_TEST_HEADER_SIZE_OFFSET	8
#define IPC_TEST_HEADER_VERSION_OFFSET	4
#define IPC_TEST_PAYLOAD_OFFSET	20

/* section: types */
typedef resolver_ipc_codec_status (*ipc_decoder)(const void *packet, size_t packet_size, void *result);
typedef union {
	resolver_ipc_request request;
	resolver_ipc_response_address address;
	resolver_ipc_response_begin begin;
	resolver_ipc_response_cname cname;
	resolver_ipc_response_end end;
	resolver_ipc_response_srv srv;
} ipc_result;

/* section: functions (local) */
static resolver_ipc_codec_status ipc_decode_address(const void *packet, size_t packet_size, void *result) {
	return resolver_ipc_response_address_decode(packet, packet_size, result);
}

static resolver_ipc_codec_status ipc_decode_begin(const void *packet, size_t packet_size, void *result) {
	return resolver_ipc_response_begin_decode(packet, packet_size, result);
}

static resolver_ipc_codec_status ipc_decode_cname(const void *packet, size_t packet_size, void *result) {
	return resolver_ipc_response_cname_decode(packet, packet_size, result);
}

static resolver_ipc_codec_status ipc_decode_end(const void *packet, size_t packet_size, void *result) {
	return resolver_ipc_response_end_decode(packet, packet_size, result);
}

static resolver_ipc_codec_status ipc_decode_request(const void *packet, size_t packet_size, void *result) {
	return resolver_ipc_request_decode(packet, packet_size, result);
}

static resolver_ipc_codec_status ipc_decode_srv(const void *packet, size_t packet_size, void *result) {
	return resolver_ipc_response_srv_decode(packet, packet_size, result);
}

static bool ipc_packet_identifies(const uint8_t *packet, size_t packet_size, resolver_ipc_packet_kind kind, uint64_t query_id) {
	resolver_ipc_packet_header header = { 0 };
	return resolver_ipc_packet_inspect(packet, packet_size, &header) == RESOLVER_IPC_CODEC_OK && header.kind == kind && header.query_id == query_id;
}

static bool ipc_packet_prefixes_rejected(const uint8_t *packet, size_t packet_size, ipc_decoder decoder) {
	if (packet == NULL || decoder == NULL) {
		return false;
	}
	for (size_t prefix_size = 0; prefix_size < packet_size; prefix_size++) {
		ipc_result result;
		memset(&result, 0xFF, sizeof(result));
		if (decoder(packet, prefix_size, &result) == RESOLVER_IPC_CODEC_OK) {
			return false;
		}
	}
	return true;
}

static void ipc_u16_write(uint8_t *target, uint16_t value) {
	target[0] = (uint8_t)(value >> 8);
	target[1] = (uint8_t)value;
}

static void ipc_u32_write(uint8_t *target, uint32_t value) {
	target[0] = (uint8_t)(value >> 24);
	target[1] = (uint8_t)(value >> 16);
	target[2] = (uint8_t)(value >> 8);
	target[3] = (uint8_t)value;
}

static bool ipc_test_arguments(void) {
	int test_result = false;
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT] = { 0 };
	size_t packet_size = 1;
	resolver_ipc_packet_header header = { 0 };
	resolver_ipc_request request = { .query_class = ns_c_in, .query_id = 1, .query_type = ns_t_a };
	CHECK(resolver_ipc_packet_inspect(NULL, 0, &header) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "NULL packet inspection was accepted");
	CHECK(resolver_ipc_packet_inspect(packet, 0, NULL) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "NULL packet header result was accepted");
	CHECK(resolver_ipc_request_encode(NULL, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT && packet_size == 0, "NULL request was accepted");
	CHECK(resolver_ipc_request_encode(&request, NULL, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT && packet_size == 0, "NULL packet buffer was accepted");
	CHECK(resolver_ipc_request_encode(&request, packet, sizeof(packet), NULL) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "NULL packet-size result was accepted");
	CHECK(resolver_ipc_request_decode(NULL, 0, &request) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "NULL request packet was accepted");
	CHECK(resolver_ipc_request_decode(packet, 0, NULL) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "NULL decoded request was accepted");
	CHECK(!resolver_ipc_lookup_status_from_address(DNS_ADDRESS_LOOKUP_OK, NULL), "NULL address status result was accepted");
	CHECK(!resolver_ipc_lookup_status_from_srv(DNS_SRV_LOOKUP_OK, NULL), "NULL SRV status result was accepted");
	CHECK(!resolver_ipc_lookup_status_to_address(RESOLVER_IPC_LOOKUP_OK, NULL), "NULL decoded address status was accepted");
	CHECK(!resolver_ipc_lookup_status_to_srv(RESOLVER_IPC_LOOKUP_OK, NULL), "NULL decoded SRV status was accepted");
	test_result = true;

cleanup:
	return test_result;
}

static bool ipc_test_begin(void) {
	int test_result = false;
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT] = { 0 };
	uint8_t original[RESOLVER_IPC_PACKET_BYTE_LIMIT] = { 0 };
	size_t packet_size = 0;
	resolver_ipc_response_begin decoded = { 0 };
	resolver_ipc_response_begin response = {
		.canonical_name = "canonical.begin.test",
		.cname_count = 1,
		.completed_at = { .tv_sec = 1234, .tv_nsec = 567890123 },
		.negative = { .effective_ttl = 20, .minimum = 30, .owner = "begin.test", .record_ttl = 40, .valid = true },
		.question_name = "question.begin.test",
		.query_class = ns_c_in,
		.query_id = UINT64_C(0x1122334455667788),
		.query_type = ns_t_srv,
		.rcode = ns_r_nxdomain,
		.record_count = 2,
		.status = RESOLVER_IPC_LOOKUP_NOT_FOUND
	};
	CHECK(resolver_ipc_response_begin_encode(&response, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "response begin could not be encoded");
	CHECK(ipc_packet_identifies(packet, packet_size, RESOLVER_IPC_PACKET_RESPONSE_BEGIN, response.query_id), "response begin header was incorrect");
	memcpy(original, packet, packet_size);
	CHECK(packet_size < RESOLVER_IPC_PACKET_BYTE_LIMIT && ipc_packet_prefixes_rejected(packet, packet_size, ipc_decode_begin), "truncated response begin was accepted");
	CHECK(resolver_ipc_response_begin_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_OK, "response begin could not be decoded");
	CHECK(decoded.query_id == response.query_id && decoded.query_class == ns_c_in && decoded.query_type == ns_t_srv && decoded.status == RESOLVER_IPC_LOOKUP_NOT_FOUND,
		"response begin identity was not preserved");
	CHECK(decoded.completed_at.tv_sec == response.completed_at.tv_sec && decoded.completed_at.tv_nsec == response.completed_at.tv_nsec && decoded.rcode == ns_r_nxdomain,
		"response begin completion metadata was not preserved");
	CHECK(decoded.cname_count == 1 && decoded.record_count == 2 && strcmp(decoded.question_name, response.question_name) == 0
		&& strcmp(decoded.canonical_name, response.canonical_name) == 0, "response begin names or counts were not preserved");
	CHECK(decoded.negative.valid && decoded.negative.effective_ttl == 20 && decoded.negative.minimum == 30 && decoded.negative.record_ttl == 40
		&& strcmp(decoded.negative.owner, "begin.test") == 0, "response begin negative metadata was not preserved");
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET + 4, 0);
	CHECK(resolver_ipc_response_begin_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_MALFORMED, "invalid response status was accepted");
	memcpy(packet, original, packet_size);
	packet[IPC_TEST_PAYLOAD_OFFSET + 6] = 16;
	CHECK(resolver_ipc_response_begin_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_MALFORMED, "invalid DNS rcode was accepted");
	memcpy(packet, original, packet_size);
	ipc_u32_write(packet + IPC_TEST_PAYLOAD_OFFSET + 16, 1000000000U);
	CHECK(resolver_ipc_response_begin_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_MALFORMED, "invalid response nanoseconds were accepted");
	memcpy(packet, original, packet_size);
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET + 20, DNS_CNAME_DEPTH_LIMIT + 1);
	CHECK(resolver_ipc_response_begin_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_MALFORMED, "oversized response CNAME count was accepted");
	memcpy(packet, original, packet_size);
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET + 22, DNS_SRV_RECORD_LIMIT + 1);
	CHECK(resolver_ipc_response_begin_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_MALFORMED, "oversized response record count was accepted");
	memcpy(packet, original, packet_size);
	packet[IPC_TEST_PAYLOAD_OFFSET + 7] = 0;
	CHECK(resolver_ipc_response_begin_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_MALFORMED, "inconsistent response negative metadata was accepted");
	memcpy(packet, original, packet_size);
	packet[IPC_TEST_PAYLOAD_OFFSET + 42] = '\0';
	CHECK(resolver_ipc_response_begin_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_MALFORMED, "embedded response-name NUL was accepted");
	memcpy(packet, original, packet_size);
	CHECK(resolver_ipc_response_begin_encode(&response, packet, packet_size - 1, &packet_size) == RESOLVER_IPC_CODEC_LIMIT && packet_size == 0,
		"undersized response-begin buffer was accepted");
	response.completed_at.tv_nsec = 1000000000L;
	CHECK(resolver_ipc_response_begin_encode(&response, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "invalid response completion time was accepted");
	response.completed_at.tv_nsec = 0;
	response.negative.effective_ttl = response.negative.minimum + 1;
	CHECK(resolver_ipc_response_begin_encode(&response, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "invalid negative TTL relation was accepted");
	response.negative.effective_ttl = 20;
	response.cname_count = DNS_CNAME_DEPTH_LIMIT + 1;
	CHECK(resolver_ipc_response_begin_encode(&response, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "oversized CNAME count was accepted");
	test_result = true;

cleanup:
	return test_result;
}

static bool ipc_test_corruption(void) {
	int test_result = false;
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT + 1] = { 0 };
	uint8_t original[RESOLVER_IPC_PACKET_BYTE_LIMIT] = { 0 };
	size_t packet_size = 0;
	resolver_ipc_packet_header header = { 0 };
	resolver_ipc_request decoded = { 0 };
	resolver_ipc_request request = { .query_name = "corruption.test", .query_class = ns_c_in, .query_id = 9, .query_type = ns_t_a };
	CHECK(resolver_ipc_request_encode(&request, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "corruption request could not be encoded");
	memcpy(original, packet, packet_size);
	packet[0] ^= 0xFF;
	CHECK(resolver_ipc_packet_inspect(packet, packet_size, &header) == RESOLVER_IPC_CODEC_MALFORMED, "invalid packet magic was accepted");
	memcpy(packet, original, packet_size);
	ipc_u16_write(packet + IPC_TEST_HEADER_VERSION_OFFSET, RESOLVER_IPC_PROTOCOL_VERSION + 1);
	header.kind = RESOLVER_IPC_PACKET_RESPONSE_END;
	header.query_id = UINT64_MAX;
	CHECK(resolver_ipc_packet_inspect(packet, packet_size, &header) == RESOLVER_IPC_CODEC_UNSUPPORTED && header.kind == 0 && header.query_id == 0,
		"unsupported protocol version was accepted or left a partial header");
	memcpy(packet, original, packet_size);
	ipc_u16_write(packet + IPC_TEST_HEADER_KIND_OFFSET, UINT16_MAX);
	CHECK(resolver_ipc_packet_inspect(packet, packet_size, &header) == RESOLVER_IPC_CODEC_UNSUPPORTED, "unknown packet kind was accepted");
	memcpy(packet, original, packet_size);
	ipc_u16_write(packet + IPC_TEST_HEADER_SIZE_OFFSET, (uint16_t)(packet_size - 1));
	CHECK(resolver_ipc_packet_inspect(packet, packet_size, &header) == RESOLVER_IPC_CODEC_MALFORMED, "mismatched packet size was accepted");
	memcpy(packet, original, packet_size);
	packet[IPC_TEST_HEADER_RESERVED_OFFSET] = 1;
	CHECK(resolver_ipc_packet_inspect(packet, packet_size, &header) == RESOLVER_IPC_CODEC_MALFORMED, "nonzero reserved field was accepted");
	memcpy(packet, original, packet_size);
	memset(packet + IPC_TEST_HEADER_QUERY_ID_OFFSET, 0, sizeof(uint64_t));
	CHECK(resolver_ipc_packet_inspect(packet, packet_size, &header) == RESOLVER_IPC_CODEC_MALFORMED, "zero query ID was accepted");
	memcpy(packet, original, packet_size);
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET, ns_c_chaos);
	CHECK(resolver_ipc_request_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_MALFORMED && decoded.query_id == 0, "unsupported request class was accepted");
	memcpy(packet, original, packet_size);
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET + sizeof(uint16_t), ns_t_txt);
	CHECK(resolver_ipc_request_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_MALFORMED && decoded.query_id == 0, "unsupported request type was accepted");
	memcpy(packet, original, packet_size);
	packet[IPC_TEST_PAYLOAD_OFFSET + sizeof(uint16_t) * 3] = '\0';
	CHECK(resolver_ipc_request_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_MALFORMED && decoded.query_id == 0, "embedded request-name NUL was accepted");
	memcpy(packet, original, packet_size);
	packet[packet_size] = 0;
	ipc_u16_write(packet + IPC_TEST_HEADER_SIZE_OFFSET, (uint16_t)(packet_size + 1));
	CHECK(resolver_ipc_request_decode(packet, packet_size + 1, &decoded) == RESOLVER_IPC_CODEC_MALFORMED, "request trailing data was accepted");
	CHECK(resolver_ipc_response_end_decode(original, packet_size, &(resolver_ipc_response_end){ 0 }) == RESOLVER_IPC_CODEC_MALFORMED, "request packet was decoded as a response end");
	CHECK(resolver_ipc_packet_inspect(packet, RESOLVER_IPC_PACKET_BYTE_LIMIT + 1, &header) == RESOLVER_IPC_CODEC_LIMIT, "oversized packet was accepted");
	test_result = true;

cleanup:
	return test_result;
}

static bool ipc_test_records(void) {
	int test_result = false;
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT] = { 0 };
	size_t packet_size = 0;
	resolver_ipc_response_address address = { .index = 3, .query_id = 101, .record = { .address = { .family = AF_INET }, .effective_ttl = 40, .record_ttl = 60 } };
	address.record.address.addr.v4 = htonl(UINT32_C(0xC0000201));
	resolver_ipc_response_address address_decoded = { 0 };
	CHECK(resolver_ipc_response_address_encode(&address, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "IPv4 response record could not be encoded");
	CHECK(ipc_packet_identifies(packet, packet_size, RESOLVER_IPC_PACKET_RESPONSE_ADDRESS, 101), "IPv4 response record header was incorrect");
	CHECK(packet[IPC_TEST_PAYLOAD_OFFSET + 2] == 0 && packet[IPC_TEST_PAYLOAD_OFFSET + 3] == RESOLVER_IPC_ADDRESS_IPV4, "IPv4 response used an unstable address-family value");
	CHECK(ipc_packet_prefixes_rejected(packet, packet_size, ipc_decode_address), "truncated IPv4 response record was accepted");
	CHECK(resolver_ipc_response_address_decode(packet, packet_size, &address_decoded) == RESOLVER_IPC_CODEC_OK && address_decoded.query_id == 101 && address_decoded.index == 3,
		"IPv4 response record identity was not preserved");
	CHECK(address_decoded.record.address.family == AF_INET && address_decoded.record.address.addr.v4 == address.record.address.addr.v4
		&& address_decoded.record.effective_ttl == 40 && address_decoded.record.record_ttl == 60, "IPv4 response record data was not preserved");
	address.record.address.family = AF_INET6;
	for (size_t index = 0; index < sizeof(address.record.address.addr.v6); index++) {
		address.record.address.addr.v6[index] = (uint8_t)index;
	}
	CHECK(resolver_ipc_response_address_encode(&address, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK
		&& resolver_ipc_response_address_decode(packet, packet_size, &address_decoded) == RESOLVER_IPC_CODEC_OK, "IPv6 response record did not round-trip");
	CHECK(packet[IPC_TEST_PAYLOAD_OFFSET + 2] == 0 && packet[IPC_TEST_PAYLOAD_OFFSET + 3] == RESOLVER_IPC_ADDRESS_IPV6, "IPv6 response used an unstable address-family value");
	CHECK(address_decoded.record.address.family == AF_INET6 && memcmp(address_decoded.record.address.addr.v6, address.record.address.addr.v6, sizeof(address.record.address.addr.v6)) == 0,
		"IPv6 response address was not preserved");
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET + 12, sizeof(uint32_t));
	CHECK(resolver_ipc_response_address_decode(packet, packet_size, &address_decoded) == RESOLVER_IPC_CODEC_MALFORMED, "mismatched IPv6 address length was accepted");
	CHECK(resolver_ipc_response_address_encode(&address, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "IPv6 response record could not be restored");
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET + 2, AF_UNSPEC);
	CHECK(resolver_ipc_response_address_decode(packet, packet_size, &address_decoded) == RESOLVER_IPC_CODEC_MALFORMED, "unsupported response address family was accepted");
	CHECK(resolver_ipc_response_address_encode(&address, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "IPv6 response record could not be restored");
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET, DNS_ADDRESS_RECORD_LIMIT);
	CHECK(resolver_ipc_response_address_decode(packet, packet_size, &address_decoded) == RESOLVER_IPC_CODEC_MALFORMED, "oversized response address index was accepted");
	CHECK(resolver_ipc_response_address_encode(&address, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "IPv6 response record could not be restored");
	ipc_u32_write(packet + IPC_TEST_PAYLOAD_OFFSET + 8, address.record.record_ttl + 1);
	CHECK(resolver_ipc_response_address_decode(packet, packet_size, &address_decoded) == RESOLVER_IPC_CODEC_MALFORMED, "invalid response address TTL relation was accepted");
	address.record.address.err = 1;
	CHECK(resolver_ipc_response_address_encode(&address, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "address record with an error was accepted");
	address.record.address.err = 0;
	address.record.effective_ttl = address.record.record_ttl + 1;
	CHECK(resolver_ipc_response_address_encode(&address, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "address record with an invalid TTL relation was accepted");
	address.record.effective_ttl = 40;
	address.index = DNS_ADDRESS_RECORD_LIMIT;
	CHECK(resolver_ipc_response_address_encode(&address, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "address record with an oversized index was accepted");

	resolver_ipc_response_cname cname = { .record = { .owner = "alias.records.test", .target = "target.records.test", .ttl = 25 }, .index = 2, .query_id = 102 };
	resolver_ipc_response_cname cname_decoded = { 0 };
	CHECK(resolver_ipc_response_cname_encode(&cname, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "CNAME response record could not be encoded");
	CHECK(ipc_packet_identifies(packet, packet_size, RESOLVER_IPC_PACKET_RESPONSE_CNAME, 102), "CNAME response record header was incorrect");
	CHECK(ipc_packet_prefixes_rejected(packet, packet_size, ipc_decode_cname) && resolver_ipc_response_cname_decode(packet, packet_size, &cname_decoded) == RESOLVER_IPC_CODEC_OK,
		"CNAME response record did not round-trip or accepted a prefix");
	CHECK(cname_decoded.query_id == 102 && cname_decoded.index == 2 && cname_decoded.record.ttl == 25 && strcmp(cname_decoded.record.owner, cname.record.owner) == 0
		&& strcmp(cname_decoded.record.target, cname.record.target) == 0, "CNAME response record data was not preserved");
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET, DNS_CNAME_DEPTH_LIMIT);
	CHECK(resolver_ipc_response_cname_decode(packet, packet_size, &cname_decoded) == RESOLVER_IPC_CODEC_MALFORMED, "oversized CNAME response index was accepted");
	CHECK(resolver_ipc_response_cname_encode(&cname, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "CNAME response record could not be restored");
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET + 8, 0);
	CHECK(resolver_ipc_response_cname_decode(packet, packet_size, &cname_decoded) == RESOLVER_IPC_CODEC_MALFORMED, "empty CNAME response target was accepted");
	cname.index = DNS_CNAME_DEPTH_LIMIT;
	CHECK(resolver_ipc_response_cname_encode(&cname, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "CNAME response with an oversized index was accepted");
	cname.index = 2;
	cname.record.target[0] = '\0';
	CHECK(resolver_ipc_response_cname_encode(&cname, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "CNAME response with an empty target was accepted");

	resolver_ipc_response_srv srv = { .index = 4, .query_id = 103, .record = { .priority = 10, .weight = 20, .port = 25565, .target = ".", .record_ttl = 90, .effective_ttl = 30 } };
	resolver_ipc_response_srv srv_decoded = { 0 };
	CHECK(resolver_ipc_response_srv_encode(&srv, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "SRV response record could not be encoded");
	CHECK(ipc_packet_identifies(packet, packet_size, RESOLVER_IPC_PACKET_RESPONSE_SRV, 103), "SRV response record header was incorrect");
	CHECK(ipc_packet_prefixes_rejected(packet, packet_size, ipc_decode_srv) && resolver_ipc_response_srv_decode(packet, packet_size, &srv_decoded) == RESOLVER_IPC_CODEC_OK,
		"SRV response record did not round-trip or accepted a prefix");
	CHECK(srv_decoded.query_id == 103 && srv_decoded.index == 4 && srv_decoded.record.priority == 10 && srv_decoded.record.weight == 20 && srv_decoded.record.port == 25565
		&& strcmp(srv_decoded.record.target, ".") == 0 && srv_decoded.record.effective_ttl == 30 && srv_decoded.record.record_ttl == 90,
		"SRV response record data was not preserved");
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET, DNS_SRV_RECORD_LIMIT);
	CHECK(resolver_ipc_response_srv_decode(packet, packet_size, &srv_decoded) == RESOLVER_IPC_CODEC_MALFORMED, "oversized SRV response index was accepted");
	CHECK(resolver_ipc_response_srv_encode(&srv, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "SRV response record could not be restored");
	ipc_u32_write(packet + IPC_TEST_PAYLOAD_OFFSET + 12, srv.record.record_ttl + 1);
	CHECK(resolver_ipc_response_srv_decode(packet, packet_size, &srv_decoded) == RESOLVER_IPC_CODEC_MALFORMED, "invalid SRV response TTL relation was accepted");
	CHECK(resolver_ipc_response_srv_encode(&srv, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "SRV response record could not be restored");
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET + 16, 0);
	CHECK(resolver_ipc_response_srv_decode(packet, packet_size, &srv_decoded) == RESOLVER_IPC_CODEC_MALFORMED, "empty SRV response target was accepted");
	srv.index = DNS_SRV_RECORD_LIMIT;
	CHECK(resolver_ipc_response_srv_encode(&srv, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "SRV response with an oversized index was accepted");
	srv.index = 4;
	srv.record.effective_ttl = srv.record.record_ttl + 1;
	CHECK(resolver_ipc_response_srv_encode(&srv, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "SRV response with an invalid TTL relation was accepted");

	resolver_ipc_response_end end = { .cname_count = 3, .query_id = 104, .record_count = 7 };
	resolver_ipc_response_end end_decoded = { 0 };
	CHECK(resolver_ipc_response_end_encode(&end, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "response end could not be encoded");
	CHECK(ipc_packet_identifies(packet, packet_size, RESOLVER_IPC_PACKET_RESPONSE_END, 104), "response end header was incorrect");
	CHECK(ipc_packet_prefixes_rejected(packet, packet_size, ipc_decode_end) && resolver_ipc_response_end_decode(packet, packet_size, &end_decoded) == RESOLVER_IPC_CODEC_OK,
		"response end did not round-trip or accepted a prefix");
	CHECK(end_decoded.query_id == 104 && end_decoded.cname_count == 3 && end_decoded.record_count == 7, "response end counts were not preserved");
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET, DNS_CNAME_DEPTH_LIMIT + 1);
	CHECK(resolver_ipc_response_end_decode(packet, packet_size, &end_decoded) == RESOLVER_IPC_CODEC_MALFORMED, "oversized response-end CNAME count was accepted");
	CHECK(resolver_ipc_response_end_encode(&end, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "response end could not be restored");
	ipc_u16_write(packet + IPC_TEST_PAYLOAD_OFFSET + 2, DNS_ADDRESS_RECORD_LIMIT + 1);
	CHECK(resolver_ipc_response_end_decode(packet, packet_size, &end_decoded) == RESOLVER_IPC_CODEC_MALFORMED, "oversized response-end record count was accepted");
	end.cname_count = DNS_CNAME_DEPTH_LIMIT + 1;
	CHECK(resolver_ipc_response_end_encode(&end, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "response end with an oversized CNAME count was accepted");
	end.cname_count = 3;
	end.record_count = DNS_ADDRESS_RECORD_LIMIT + 1;
	CHECK(resolver_ipc_response_end_encode(&end, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "response end with an oversized record count was accepted");
	test_result = true;

cleanup:
	return test_result;
}

static bool ipc_test_request(void) {
	static const uint8_t expected[] = {
		0x4D, 0x52, 0x53, 0x50, 0x00, 0x01, 0x00, 0x01, 0x00, 0x26, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00, 0x01, 0x00, 0x01, 0x00, 0x0C, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 't', 'e', 's', 't'
	};
	int test_result = false;
	uint8_t packet[RESOLVER_IPC_PACKET_BYTE_LIMIT] = { 0 };
	size_t packet_size = 0;
	resolver_ipc_packet_header header = { 0 };
	resolver_ipc_request decoded = { 0 };
	resolver_ipc_request request = { .query_name = "example.test", .query_class = ns_c_in, .query_id = UINT64_C(0x0102030405060708), .query_type = ns_t_a };
	CHECK(resolver_ipc_request_encode(&request, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK, "request could not be encoded");
	CHECK(packet_size == sizeof(expected) && memcmp(packet, expected, sizeof(expected)) == 0, "request wire encoding is not stable");
	CHECK(resolver_ipc_packet_inspect(packet, packet_size, &header) == RESOLVER_IPC_CODEC_OK && header.kind == RESOLVER_IPC_PACKET_REQUEST && header.query_id == request.query_id,
		"request header inspection failed");
	CHECK(ipc_packet_prefixes_rejected(packet, packet_size, ipc_decode_request), "truncated request packet was accepted");
	CHECK(resolver_ipc_request_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_OK && decoded.query_id == request.query_id && decoded.query_class == ns_c_in
		&& decoded.query_type == ns_t_a && strcmp(decoded.query_name, "example.test") == 0, "request did not round-trip");
	CHECK(resolver_ipc_request_encode(&request, packet, packet_size - 1, &packet_size) == RESOLVER_IPC_CODEC_LIMIT && packet_size == 0, "undersized request buffer was accepted");
	request.query_id = 0;
	CHECK(resolver_ipc_request_encode(&request, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "zero request query ID was accepted");
	request.query_id = 1;
	request.query_type = ns_t_txt;
	CHECK(resolver_ipc_request_encode(&request, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "unsupported request query type was accepted");
	request.query_type = ns_t_a;
	memset(request.query_name, 'a', sizeof(request.query_name));
	request.query_name[sizeof(request.query_name) - 1] = '\0';
	CHECK(resolver_ipc_request_encode(&request, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_OK
		&& resolver_ipc_request_decode(packet, packet_size, &decoded) == RESOLVER_IPC_CODEC_OK && strcmp(decoded.query_name, request.query_name) == 0,
		"maximum-sized request name did not round-trip");
	memset(request.query_name, 'a', sizeof(request.query_name));
	CHECK(resolver_ipc_request_encode(&request, packet, sizeof(packet), &packet_size) == RESOLVER_IPC_CODEC_BAD_ARGUMENT, "unterminated request name was accepted");
	test_result = true;

cleanup:
	return test_result;
}

static bool ipc_test_statuses(void) {
	static const dns_address_lookup_status address_statuses[] = {
		DNS_ADDRESS_LOOKUP_OK, DNS_ADDRESS_LOOKUP_BAD_ARGUMENT, DNS_ADDRESS_LOOKUP_LIMIT, DNS_ADDRESS_LOOKUP_MALFORMED, DNS_ADDRESS_LOOKUP_MEMORY,
		DNS_ADDRESS_LOOKUP_NODATA, DNS_ADDRESS_LOOKUP_NOT_FOUND, DNS_ADDRESS_LOOKUP_PERMANENT_ERROR, DNS_ADDRESS_LOOKUP_TEMPORARY_ERROR, DNS_ADDRESS_LOOKUP_TRUNCATED
	};
	static const resolver_ipc_lookup_status ipc_statuses[] = {
		RESOLVER_IPC_LOOKUP_OK, RESOLVER_IPC_LOOKUP_BAD_ARGUMENT, RESOLVER_IPC_LOOKUP_LIMIT, RESOLVER_IPC_LOOKUP_MALFORMED, RESOLVER_IPC_LOOKUP_MEMORY,
		RESOLVER_IPC_LOOKUP_NODATA, RESOLVER_IPC_LOOKUP_NOT_FOUND, RESOLVER_IPC_LOOKUP_PERMANENT_ERROR, RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR, RESOLVER_IPC_LOOKUP_TRUNCATED
	};
	static const dns_srv_lookup_status srv_statuses[] = {
		DNS_SRV_LOOKUP_OK, DNS_SRV_LOOKUP_BAD_ARGUMENT, DNS_SRV_LOOKUP_LIMIT, DNS_SRV_LOOKUP_MALFORMED, DNS_SRV_LOOKUP_MEMORY,
		DNS_SRV_LOOKUP_NODATA, DNS_SRV_LOOKUP_NOT_FOUND, DNS_SRV_LOOKUP_PERMANENT_ERROR, DNS_SRV_LOOKUP_TEMPORARY_ERROR, DNS_SRV_LOOKUP_TRUNCATED
	};
	int test_result = false;
	CHECK(sizeof(address_statuses) / sizeof(address_statuses[0]) == sizeof(ipc_statuses) / sizeof(ipc_statuses[0])
		&& sizeof(srv_statuses) / sizeof(srv_statuses[0]) == sizeof(ipc_statuses) / sizeof(ipc_statuses[0]), "status test tables have different sizes");
	for (size_t index = 0; index < sizeof(ipc_statuses) / sizeof(ipc_statuses[0]); index++) {
		resolver_ipc_lookup_status encoded_address = 0;
		resolver_ipc_lookup_status encoded_srv = 0;
		dns_address_lookup_status decoded_address = 0;
		dns_srv_lookup_status decoded_srv = 0;
		CHECK(resolver_ipc_lookup_status_from_address(address_statuses[index], &encoded_address) && encoded_address == ipc_statuses[index], "address lookup status encoded incorrectly");
		CHECK(resolver_ipc_lookup_status_from_srv(srv_statuses[index], &encoded_srv) && encoded_srv == ipc_statuses[index], "SRV lookup status encoded incorrectly");
		CHECK(resolver_ipc_lookup_status_to_address(ipc_statuses[index], &decoded_address) && decoded_address == address_statuses[index], "address lookup status decoded incorrectly");
		CHECK(resolver_ipc_lookup_status_to_srv(ipc_statuses[index], &decoded_srv) && decoded_srv == srv_statuses[index], "SRV lookup status decoded incorrectly");
	}
	resolver_ipc_lookup_status encoded = 0;
	dns_address_lookup_status decoded_address = 0;
	dns_srv_lookup_status decoded_srv = 0;
	CHECK(!resolver_ipc_lookup_status_from_address((dns_address_lookup_status)-1, &encoded), "invalid address lookup status was encoded");
	CHECK(!resolver_ipc_lookup_status_from_srv((dns_srv_lookup_status)-1, &encoded), "invalid SRV lookup status was encoded");
	CHECK(!resolver_ipc_lookup_status_to_address((resolver_ipc_lookup_status)0, &decoded_address), "invalid address IPC status was decoded");
	CHECK(!resolver_ipc_lookup_status_to_srv((resolver_ipc_lookup_status)0, &decoded_srv), "invalid SRV IPC status was decoded");
	test_result = true;

cleanup:
	return test_result;
}

/* section: functions (entry point) */
int main(void) {
	int test_result = EXIT_FAILURE;
	CHECK(ipc_test_arguments(), "IPC argument tests failed");
	CHECK(ipc_test_begin(), "IPC response-begin tests failed");
	CHECK(ipc_test_corruption(), "IPC corruption tests failed");
	CHECK(ipc_test_records(), "IPC record tests failed");
	CHECK(ipc_test_request(), "IPC request tests failed");
	CHECK(ipc_test_statuses(), "IPC status tests failed");
	test_result = EXIT_SUCCESS;

cleanup:
	return test_result;
}
