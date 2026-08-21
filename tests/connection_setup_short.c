/*
 * connection_setup_short.c: Tests for listener-owned short connection setup plans
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* section: headers (project) */
#include "connection/setup_short.h"
#include "protocol/handshake.h"
#include "protocol/handshake_legacy.h"

/* section: defines */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s\n", message); \
			return false; \
		} \
	} while (0)

/* section: functions (local) */
static net_addrbundle connection_setup_short_test_client(void) {
	net_addrbundle result;
	memset(&result, 0, sizeof(result));
	result.family = AF_INET;
	result.port = 40000;
	snprintf((char *)&result.address, sizeof(result.address), "%s", "198.51.100.10");
	snprintf((char *)&result.address_clean, sizeof(result.address_clean), "%s", "198.51.100.10");
	return result;
}

static connection_setup_snapshot connection_setup_short_test_snapshot(connection_setup_route_status route_status, bool rewrite, bool pheader) {
	connection_setup_snapshot result;
	memset(&result, 0, sizeof(result));
	result.endpoint.address = net_addr_parse("192.0.2.20");
	snprintf(result.endpoint.configured_address, sizeof(result.endpoint.configured_address), "%s", "configured.example");
	result.endpoint.destination_index = 3;
	result.endpoint.generation_identity = 42;
	result.endpoint.inbound_proxy.family = AF_INET;
	result.endpoint.inbound_proxy.srcaddr = net_addr_parse("198.51.100.10");
	result.endpoint.inbound_proxy.dstaddr = net_addr_parse("192.0.2.1");
	result.endpoint.inbound_proxy.srcport = 40000;
	result.endpoint.inbound_proxy.dstport = 25565;
	result.endpoint.port = 25570;
	result.endpoint.pheader = pheader;
	result.endpoint.rewrite = rewrite;
	snprintf(result.endpoint.target_name, sizeof(result.endpoint.target_name), "%s", "backend.example");
	snprintf(result.endpoint.vhost, sizeof(result.endpoint.vhost), "%s", "status.example");
	snprintf(result.icon_b64, sizeof(result.icon_b64), "%s", "ICON");
	snprintf(result.log_filename, sizeof(result.log_filename), "%s", "/tmp/mcrelay.log");
	result.log_level = 3;
	result.route_status = route_status;
	return result;
}

static size_t connection_setup_short_test_legacy_packet(uint8_t *destination, const char *address, uint8_t version) {
	p_motd_legacy packet;
	packet.address = (void *)address;
	packet.port = 25565;
	packet.version = version;
	return packet_write_legacy_motd(destination, packet);
}

static size_t connection_setup_short_test_modern_packet(uint8_t *destination, intent_t intent, varint_t version) {
	p_handshake packet;
	memset(&packet, 0, sizeof(packet));
	packet.address = (void *)"status.example";
	packet.nextstate = intent;
	packet.port = 25565;
	packet.version = version;
	packet.username = (void *)"player";
	return packet_write(destination, packet);
}

static bool connection_setup_short_test_classification(void) {
	static const uint8_t original[] = { 0x01 };
	static const uint8_t legacy_l1[] = { 0x02, 0x00, 0x00, 0x01 };
	static const uint8_t legacy_l2[] = { 0x02, 0x00, 0x03, 'a', ';', ':' };
	static const uint8_t legacy_l3[] = { 0x02, 0x1F, 0x00, 0x00 };
	static const uint8_t legacy_l4[] = { 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	static const uint8_t legacy_m1[] = { 0xFE };
	static const uint8_t legacy_m2[] = { 0xFE, 0x01 };
	connection_setup_snapshot snapshot = connection_setup_short_test_snapshot(CONNECTION_SETUP_ROUTE_READY, false, false);
	net_addrbundle client = connection_setup_short_test_client();
	connection_setup_short_plan plan;
	uint8_t modern[BUFSIZ];
	size_t modern_size;

	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, original, sizeof(original)) == CONNECTION_SETUP_SHORT_ABORT, "ORIGPRO accepted as short");
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, legacy_l1, sizeof(legacy_l1)) == CONNECTION_SETUP_SHORT_ABORT, "LEGACYL1 accepted as short");
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, legacy_l2, sizeof(legacy_l2)) == CONNECTION_SETUP_SHORT_ABORT, "LEGACYL2 accepted as short");
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, legacy_l3, sizeof(legacy_l3)) == CONNECTION_SETUP_SHORT_ABORT, "LEGACYL3 accepted as short");
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, legacy_l4, sizeof(legacy_l4)) == CONNECTION_SETUP_SHORT_ABORT, "LEGACYL4 accepted as short");
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, legacy_m1, sizeof(legacy_m1)) == CONNECTION_SETUP_SHORT_RESPOND, "LEGACYM1 was not answered locally");
	connection_setup_short_destroy(&plan);
	CHECK(plan.request == NULL && plan.response == NULL, "destroy did not clear LEGACYM1 plan");
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, legacy_m2, sizeof(legacy_m2)) == CONNECTION_SETUP_SHORT_RESPOND, "LEGACYM2 was not answered locally");
	connection_setup_short_destroy(&plan);
	modern_size = connection_setup_short_test_modern_packet(modern, CLIENT_INTENT_LOGIN, PVERDB_R_1_20_1 + 1U);
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, modern, modern_size) == CONNECTION_SETUP_SHORT_ABORT, "modern LOGIN accepted as short");
	modern_size = connection_setup_short_test_modern_packet(modern, CLIENT_INTENT_TRANSFER, PVERDB_R_1_20_1 + 1U);
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, modern, modern_size) == CONNECTION_SETUP_SHORT_ABORT, "modern TRANSFER accepted as short");
	modern_size = connection_setup_short_test_modern_packet(modern, CLIENT_INTENT_STATUS, 0);
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, modern, modern_size) == CONNECTION_SETUP_SHORT_RESPOND, "modern1 STATUS was not answered locally");
	connection_setup_short_destroy(&plan);
	return true;
}

static bool connection_setup_short_test_legacy_connect(void) {
	uint8_t initial[BUFSIZ];
	size_t initial_size = connection_setup_short_test_legacy_packet(initial, "status.example", 74);
	size_t initial_packet_size = initial_size;
	initial[initial_size++] = 0x01;
	initial[initial_size++] = 0x02;
	connection_setup_snapshot snapshot = connection_setup_short_test_snapshot(CONNECTION_SETUP_ROUTE_READY, true, true);
	net_addrbundle client = connection_setup_short_test_client();
	connection_setup_short_plan plan;
	size_t request_packet_size;
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, initial, initial_size) == CONNECTION_SETUP_SHORT_CONNECT, "LEGACYM3 did not produce CONNECT");
	CHECK(plan.request != NULL && plan.request_size > plan.pheader_size && plan.response != NULL && plan.response_size > 0, "LEGACYM3 plan buffers missing");
	CHECK(plan.pheader_size > 0 && memcmp(plan.request, "PROXY TCP4 ", 11) == 0, "LEGACYM3 PROXY header missing");
	CHECK(protocol_packet_length(plan.request + plan.pheader_size, plan.request_size - plan.pheader_size, &request_packet_size) == PROTOCOL_PACKET_COMPLETE
		&& request_packet_size < plan.request_size - plan.pheader_size && memcmp(plan.request + plan.pheader_size + request_packet_size, initial + initial_packet_size, 2) == 0,
		"LEGACYM3 trailing bytes changed");
	p_motd_legacy request = packet_read_legacy_motd(plan.request + plan.pheader_size);
	CHECK(request.address != NULL && strcmp(request.address, "backend.example") == 0 && request.port == 25570, "LEGACYM3 request was not rewritten");
	packet_destroy_legacy_motd(request);
	snprintf(snapshot.endpoint.target_name, sizeof(snapshot.endpoint.target_name), "%s", "changed.example");
	CHECK(strcmp(plan.snapshot.endpoint.target_name, "backend.example") == 0, "LEGACYM3 plan retained snapshot pointer");
	connection_setup_short_destroy(&plan);
	return true;
}

static bool connection_setup_short_test_modern_connect(void) {
	uint8_t initial[BUFSIZ];
	size_t initial_size = connection_setup_short_test_modern_packet(initial, CLIENT_INTENT_STATUS, PVERDB_R_1_20_1 + 1U);
	connection_setup_snapshot snapshot = connection_setup_short_test_snapshot(CONNECTION_SETUP_ROUTE_READY, true, false);
	net_addrbundle client = connection_setup_short_test_client();
	connection_setup_short_plan plan;
	size_t initial_packet_size;
	size_t request_packet_size;
	CHECK(protocol_packet_length(initial, initial_size, &initial_packet_size) == PROTOCOL_PACKET_COMPLETE && initial_packet_size < initial_size,
		"modern STATUS fixture did not contain trailing request bytes");
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, initial, initial_size) == CONNECTION_SETUP_SHORT_CONNECT, "modern STATUS did not produce CONNECT");
	CHECK(plan.request != NULL && plan.request_size > 0 && plan.response != NULL && plan.response_size > 0, "modern STATUS plan buffers missing");
	CHECK(protocol_packet_length(plan.request, plan.request_size, &request_packet_size) == PROTOCOL_PACKET_COMPLETE && request_packet_size < plan.request_size,
		"modern STATUS trailing request bytes were lost");
	CHECK(memcmp(plan.request + request_packet_size, initial + initial_packet_size, initial_size - initial_packet_size) == 0,
		"modern STATUS trailing request bytes changed");
	p_handshake request = packet_read(plan.request, plan.request + request_packet_size);
	CHECK(request.address != NULL && strcmp(request.address, "backend.example") == 0 && request.port == 25570 && request.nextstate == CLIENT_INTENT_STATUS,
		"modern STATUS request was not rewritten");
	packet_destroy(request);
	connection_setup_short_destroy(&plan);
	return true;
}

static bool connection_setup_short_test_responses(void) {
	uint8_t initial[BUFSIZ];
	uint8_t expected[BUFSIZ];
	size_t initial_size = connection_setup_short_test_legacy_packet(initial, "status.example", 74);
	connection_setup_snapshot snapshot = connection_setup_short_test_snapshot(CONNECTION_SETUP_ROUTE_UNAVAILABLE, false, false);
	net_addrbundle client = connection_setup_short_test_client();
	connection_setup_short_plan plan;
	size_t expected_size = make_motd_legacy(expected, "[Proxy] Server Temporarily Unavailable.", PVER_LEGACYM3, 74);
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, initial, initial_size) == CONNECTION_SETUP_SHORT_RESPOND, "legacy unavailable route did not respond");
	CHECK(plan.request == NULL && plan.response_size == expected_size && memcmp(plan.response, expected, expected_size) == 0, "legacy unavailable response mismatch");
	connection_setup_short_destroy(&plan);
	initial_size = connection_setup_short_test_modern_packet(initial, CLIENT_INTENT_STATUS, PVERDB_R_1_20_1 + 1U);
	expected_size = make_motd(expected, "[Proxy] Server Temporarily Unavailable.", PVERDB_R_1_20_1 + 1U, snapshot.icon_b64);
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, initial, initial_size) == CONNECTION_SETUP_SHORT_RESPOND, "modern unavailable route did not respond");
	CHECK(plan.request == NULL && plan.response_size == expected_size && memcmp(plan.response, expected, expected_size) == 0, "modern unavailable response mismatch");
	connection_setup_short_destroy(&plan);
	return true;
}

static bool connection_setup_short_test_arguments(void) {
	uint8_t initial[] = { 0xFE };
	connection_setup_snapshot snapshot = connection_setup_short_test_snapshot(CONNECTION_SETUP_ROUTE_READY, false, false);
	net_addrbundle client = connection_setup_short_test_client();
	connection_setup_short_plan plan;
	CHECK(connection_setup_short_prepare(NULL, &snapshot, client, initial, sizeof(initial)) == CONNECTION_SETUP_SHORT_ABORT, "NULL plan accepted");
	CHECK(connection_setup_short_prepare(&plan, NULL, client, initial, sizeof(initial)) == CONNECTION_SETUP_SHORT_ABORT, "NULL snapshot accepted");
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, NULL, 0) == CONNECTION_SETUP_SHORT_ABORT, "empty packet accepted");
	snapshot.endpoint.address.err = NET_EARGADDR;
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, initial, sizeof(initial)) == CONNECTION_SETUP_SHORT_RESPOND, "legacy local response required route validation");
	connection_setup_short_destroy(&plan);
	uint8_t modern[BUFSIZ];
	size_t modern_size = connection_setup_short_test_modern_packet(modern, CLIENT_INTENT_STATUS, PVERDB_R_1_20_1 + 1U);
	CHECK(connection_setup_short_prepare(&plan, &snapshot, client, modern, modern_size) == CONNECTION_SETUP_SHORT_ABORT, "invalid ready endpoint accepted");
	return true;
}

/* section: functions (entry point) */
int main(void) {
	if (!connection_setup_short_test_arguments() || !connection_setup_short_test_classification() || !connection_setup_short_test_legacy_connect()
		|| !connection_setup_short_test_modern_connect() || !connection_setup_short_test_responses()) {
		return 1;
	}
	return 0;
}
