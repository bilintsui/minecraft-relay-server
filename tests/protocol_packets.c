/*
 * protocol_packets.c: Tests for captured protocol packet parsing and construction
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <cjson/cJSON.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* section: headers (project) */
#include "../src/protocol/common.h"
#include "../src/protocol/handshake.h"
#include "../src/protocol/handshake_legacy.h"

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
enum client_fixture_kind {
	CLIENT_FIXTURE_IDENTIFY_ONLY,
	CLIENT_FIXTURE_LEGACY_LOGIN,
	CLIENT_FIXTURE_LEGACY_STATUS,
	CLIENT_FIXTURE_MODERN
};

typedef struct {
	const char *filename;
	enum client_fixture_kind kind;
	uint8_t protocol;
	bool roundtrip;
} client_fixture;

typedef union {
	uint32_t alignment;
	uint8_t bytes[BUFSIZ + 1];
} packet_storage;

/* section: functions (local) */
static ssize_t file_read(const char *filename, void *data, size_t capacity) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		return -1;
	}
	size_t size = fread(data, 1, capacity, file);
	if (ferror(file)) {
		int saved_errno = errno;
		fclose(file);
		errno = saved_errno;
		return -1;
	}
	if (fclose(file) != 0) {
		return -1;
	}
	return (ssize_t)size;
}

static bool legacy_message_validate(const uint8_t *data, size_t size, size_t *field_count) {
	if (data == NULL || field_count == NULL || size < 3 || data[0] != 0xFF) {
		return false;
	}
	size_t character_count = (size_t)data[1] * 256 + data[2];
	if (size != character_count * 2 + 3) {
		return false;
	}
	*field_count = 1;
	for (size_t index = 0; index < character_count; index++) {
		if (data[index * 2 + 3] != 0) {
			return false;
		}
		if (data[index * 2 + 4] == 0) {
			(*field_count)++;
		}
	}
	return true;
}

static bool modern_varint_read(const uint8_t **cursor, const uint8_t *end, uint32_t *value) {
	if (cursor == NULL || *cursor == NULL || end == NULL || value == NULL) {
		return false;
	}
	*value = 0;
	for (unsigned int index = 0; index < 5; index++) {
		if (*cursor == end) {
			return false;
		}
		uint8_t byte = *(*cursor)++;
		*value |= (uint32_t)(byte & 0x7F) << (index * 7);
		if (!(byte & 0x80)) {
			return true;
		}
	}
	return false;
}

static bool modern_message_validate(const uint8_t *data, size_t size) {
	if (data == NULL) {
		return false;
	}
	const uint8_t *cursor = data;
	const uint8_t *end = data + size;
	uint32_t frame_size, packet_id, string_size;
	if (!modern_varint_read(&cursor, end, &frame_size) || frame_size != (uint32_t)(end - cursor)) {
		return false;
	}
	if (!modern_varint_read(&cursor, end, &packet_id) || packet_id != 0) {
		return false;
	}
	if (!modern_varint_read(&cursor, end, &string_size) || string_size != (uint32_t)(end - cursor)) {
		return false;
	}
	char *json = malloc((size_t)string_size + 1);
	if (json == NULL) {
		return false;
	}
	memcpy(json, cursor, string_size);
	json[string_size] = '\0';
	cJSON *parsed = cJSON_Parse(json);
	free(json);
	if (parsed == NULL) {
		return false;
	}
	cJSON_Delete(parsed);
	return true;
}

static bool packet_roundtrip(enum client_fixture_kind kind, uint8_t protocol, const uint8_t *source, size_t source_size, uint8_t *target) {
	size_t target_size;
	if (kind == CLIENT_FIXTURE_LEGACY_LOGIN) {
		p_login_legacy packet = packet_read_legacy_login(source, source_size, protocol);
		target_size = packet_write_legacy_login(packet, target);
	} else if (kind == CLIENT_FIXTURE_LEGACY_STATUS) {
		p_motd_legacy packet = packet_read_legacy_motd(source);
		target_size = packet_write_legacy_motd(target, packet);
		packet_destroy_legacy_motd(packet);
	} else if (kind == CLIENT_FIXTURE_MODERN) {
		p_handshake packet = packet_read((void *)source, (void *)(source + source_size));
		if (packet.address == NULL) {
			return false;
		}
		target_size = packet_write(target, packet);
		packet_destroy(packet);
	} else {
		return false;
	}
	return target_size == source_size && memcmp(source, target, source_size) == 0;
}

static int path_format(char *target, size_t target_size, const char *directory, const char *filename) {
	int length = snprintf(target, target_size, "%s/%s", directory, filename);
	if (length < 0 || (size_t)length >= target_size) {
		errno = EOVERFLOW;
		return -1;
	}
	return 0;
}

/* section: functions (entry point) */
int main(int argc, char **argv) {
	/* Some excluded protocol versions remain structurally round-trippable even though workers reject them by policy. */
	static const client_fixture client_fixtures[] = {
		{ "login/login_1-a1.0.15.bin", CLIENT_FIXTURE_IDENTIFY_ONLY, PVER_ORIGPRO, false },
		{ "login/login_2-12w03a.bin", CLIENT_FIXTURE_LEGACY_LOGIN, PVER_LEGACYL1, true },
		{ "login/login_2-a1.0.16.bin", CLIENT_FIXTURE_IDENTIFY_ONLY, PVER_LEGACYL1, false },
		{ "login/login_2-b1.4_01.bin", CLIENT_FIXTURE_IDENTIFY_ONLY, PVER_LEGACYL1, false },
		{ "login/login_2-b1.5.bin", CLIENT_FIXTURE_LEGACY_LOGIN, PVER_LEGACYL1, true },
		{ "login/login_3-12w04a.bin", CLIENT_FIXTURE_LEGACY_LOGIN, PVER_LEGACYL2, true },
		{ "login/login_3-12w16a.bin", CLIENT_FIXTURE_LEGACY_LOGIN, PVER_LEGACYL2, true },
		{ "login/login_4-12w17a.bin", CLIENT_FIXTURE_LEGACY_LOGIN, PVER_LEGACYL3, true },
		{ "login/login_5-12w18a.bin", CLIENT_FIXTURE_LEGACY_LOGIN, PVER_LEGACYL4, true },
		{ "login/login_5-13w39b.bin", CLIENT_FIXTURE_LEGACY_LOGIN, PVER_LEGACYL4, true },
		{ "modern/login_1-13w41a.bin", CLIENT_FIXTURE_IDENTIFY_ONLY, PVER_MODERN1, false },
		{ "modern/login_2-13w41b.bin", CLIENT_FIXTURE_MODERN, PVER_MODERN1, true },
		{ "modern/status_1-13w41a.bin", CLIENT_FIXTURE_IDENTIFY_ONLY, PVER_MODERN1, false },
		{ "modern/status_2-13w41b.bin", CLIENT_FIXTURE_MODERN, PVER_MODERN1, true },
		{ "status/status_1-12w42a.bin", CLIENT_FIXTURE_IDENTIFY_ONLY, PVER_LEGACYM1, false },
		{ "status/status_1-b1.8-pre1.bin", CLIENT_FIXTURE_IDENTIFY_ONLY, PVER_LEGACYM1, false },
		{ "status/status_2-1.6.bin", CLIENT_FIXTURE_IDENTIFY_ONLY, PVER_LEGACYM2, false },
		{ "status/status_2-12w42b.bin", CLIENT_FIXTURE_IDENTIFY_ONLY, PVER_LEGACYM2, false },
		{ "status/status_3-1.6.1.bin", CLIENT_FIXTURE_LEGACY_STATUS, PVER_LEGACYM3, true },
		{ "status/status_3-13w39b.bin", CLIENT_FIXTURE_LEGACY_STATUS, PVER_LEGACYM3, true }
	};
	static const char *legacy_login_responses[] = {
		"login/login_5-12w18a.bin2",
		"login/login_5-13w39b.bin2"
	};
	static const struct {
		const char *filename;
		uint8_t version;
	} legacy_status_responses[] = {
		{ "status/status_3-1.6.1.bin2", 73 },
		{ "status/status_3-13w39b.bin2", 80 }
	};
	packet_storage source_storage = { 0 };
	packet_storage target_storage = { 0 };
	uint8_t *source = source_storage.bytes + 1;
	uint8_t *target = target_storage.bytes + 1;
	uint8_t legacy_m3_long_address[548] = { 0xFE, 0x01, 0xFA };
	uint8_t modern_multibyte_frame[131] = { 0x81, 0x01, 0x00, 0x01, 0x7B };
	char filename[BUFSIZ];
	int result = EXIT_FAILURE;
	CHECK(argc == 2, "raw packet directory is required");

	for (size_t index = 0; index < sizeof(client_fixtures) / sizeof(client_fixtures[0]); index++) {
		memset(source, 0, BUFSIZ);
		memset(target, 0, BUFSIZ);
		CHECK(path_format(filename, sizeof(filename), argv[1], client_fixtures[index].filename) == 0, "cannot format client fixture filename");
		ssize_t source_size = file_read(filename, source, BUFSIZ);
		CHECK(source_size > 0, "cannot read client fixture");
		CHECK(protocol_identify(source, (size_t)source_size, NULL) == client_fixtures[index].protocol, "client fixture protocol was identified incorrectly");
		if (client_fixtures[index].roundtrip) {
			CHECK(packet_roundtrip(client_fixtures[index].kind, client_fixtures[index].protocol, source, (size_t)source_size, target), "client fixture did not survive an exact round trip");
		}
	}
	memset(modern_multibyte_frame + 5, 'a', 123);
	modern_multibyte_frame[128] = 0x63;
	modern_multibyte_frame[129] = 0xDD;
	modern_multibyte_frame[130] = CLIENT_INTENT_STATUS;
	intent_t modern_intent;
	for (size_t prefix_size = 1; prefix_size < sizeof(modern_multibyte_frame); prefix_size++) {
		size_t packet_size;
		CHECK(protocol_packet_length(modern_multibyte_frame, prefix_size, &packet_size) == PROTOCOL_PACKET_INCOMPLETE, "truncated multi-byte modern frame was considered complete");
		CHECK(packet_size > prefix_size, "truncated multi-byte modern frame did not request more data");
		CHECK(protocol_identify(modern_multibyte_frame, prefix_size, &modern_intent) == PVER_UNIDENT, "truncated multi-byte modern frame was identified");
	}
	size_t packet_size;
	CHECK(protocol_packet_length(modern_multibyte_frame, sizeof(modern_multibyte_frame), &packet_size) == PROTOCOL_PACKET_COMPLETE, "complete multi-byte modern frame was considered incomplete");
	CHECK(packet_size == sizeof(modern_multibyte_frame), "multi-byte modern frame length was decoded incorrectly");
	CHECK(protocol_identify(modern_multibyte_frame, sizeof(modern_multibyte_frame), &modern_intent) == PVER_MODERN2, "multi-byte modern frame was identified incorrectly");
	CHECK(modern_intent == CLIENT_INTENT_STATUS, "multi-byte modern frame intent was identified incorrectly");
	legacy_m3_long_address[0x1E] = 0x01;
	legacy_m3_long_address[0x1F] = 0x00;
	for (size_t prefix_size = 1; prefix_size < sizeof(legacy_m3_long_address); prefix_size++) {
		enum protocol_packet_status packet_status = protocol_packet_length(legacy_m3_long_address, prefix_size, &packet_size);
		if (prefix_size < 3) {
			CHECK(packet_status == PROTOCOL_PACKET_AMBIGUOUS, "ambiguous legacy M3 prefix was classified incorrectly");
		} else {
			CHECK(packet_status == PROTOCOL_PACKET_INCOMPLETE, "truncated legacy M3 packet was considered complete");
		}
		CHECK(packet_size > prefix_size, "truncated legacy M3 packet did not request more data");
	}
	CHECK(protocol_packet_length(legacy_m3_long_address, sizeof(legacy_m3_long_address), &packet_size) == PROTOCOL_PACKET_COMPLETE, "complete legacy M3 packet was considered incomplete");
	CHECK(packet_size == sizeof(legacy_m3_long_address), "legacy M3 packet length was decoded incorrectly");

	for (size_t index = 0; index < sizeof(legacy_login_responses) / sizeof(legacy_login_responses[0]); index++) {
		memset(source, 0, BUFSIZ);
		memset(target, 0, BUFSIZ);
		CHECK(path_format(filename, sizeof(filename), argv[1], legacy_login_responses[index]) == 0, "cannot format legacy login response filename");
		ssize_t source_size = file_read(filename, source, BUFSIZ);
		CHECK(source_size > 0, "cannot read legacy login response");
		size_t source_fields, target_fields;
		CHECK(legacy_message_validate(source, (size_t)source_size, &source_fields), "captured legacy login response is malformed");
		size_t target_size = make_kickreason_legacy(target, "Outdated server!");
		CHECK(legacy_message_validate(target, target_size, &target_fields), "constructed legacy login response is malformed");
		CHECK(source_fields == target_fields && target_size == (size_t)source_size && memcmp(source, target, target_size) == 0, "constructed legacy login response differs from capture");
	}

	memset(source, 0, BUFSIZ);
	memset(target, 0, BUFSIZ);
	CHECK(path_format(filename, sizeof(filename), argv[1], "modern/login_2-13w41b.bin2") == 0, "cannot format modern login response filename");
	ssize_t source_size = file_read(filename, source, BUFSIZ);
	CHECK(source_size > 0, "cannot read modern login response");
	CHECK(modern_message_validate(source, (size_t)source_size), "captured modern login response is malformed");
	size_t target_size = make_kickreason(target, "Outdated server! I'm still on 13w41b");
	CHECK(modern_message_validate(target, target_size), "constructed modern login response is malformed");

	memset(source, 0, BUFSIZ);
	memset(target, 0, BUFSIZ);
	CHECK(path_format(filename, sizeof(filename), argv[1], "modern/status_2-13w41b.bin2") == 0, "cannot format modern status response filename");
	source_size = file_read(filename, source, BUFSIZ);
	CHECK(source_size > 0, "cannot read modern status response");
	CHECK(modern_message_validate(source, (size_t)source_size), "captured modern status response is malformed");
	target_size = make_motd(target, "A Minecraft Server", 0, NULL);
	CHECK(modern_message_validate(target, target_size), "constructed modern status response is malformed");

	for (size_t index = 0; index < sizeof(legacy_status_responses) / sizeof(legacy_status_responses[0]); index++) {
		memset(source, 0, BUFSIZ);
		memset(target, 0, BUFSIZ);
		CHECK(path_format(filename, sizeof(filename), argv[1], legacy_status_responses[index].filename) == 0, "cannot format legacy status response filename");
		source_size = file_read(filename, source, BUFSIZ);
		CHECK(source_size > 0, "cannot read legacy status response");
		size_t source_fields, target_fields;
		CHECK(legacy_message_validate(source, (size_t)source_size, &source_fields), "captured legacy status response is malformed");
		target_size = make_motd_legacy(target, "A Minecraft Server", PVER_LEGACYM3, legacy_status_responses[index].version);
		CHECK(legacy_message_validate(target, target_size, &target_fields), "constructed legacy status response is malformed");
		CHECK(source_fields == 6 && target_fields == source_fields, "constructed legacy status response has an incompatible field structure");
	}

	result = EXIT_SUCCESS;

cleanup:
	return result;
}
