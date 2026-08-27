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
#include "../src/basic.h"
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
typedef enum {
	CLIENT_FIXTURE_IDENTIFY_ONLY,
	CLIENT_FIXTURE_LEGACY_LOGIN,
	CLIENT_FIXTURE_LEGACY_STATUS,
	CLIENT_FIXTURE_MODERN
} client_fixture_kind;

typedef struct {
	const char *filename;
	client_fixture_kind kind;
	protocol_version protocol;
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

static bool kickreason_bounds_test(void) {
	static const char message[] = "Capacity test";
	uint8_t output[256];
	memset(output, 0xA5, sizeof(output));
	size_t modern_size = make_kickreason(output, sizeof(output), message);
	if (modern_size == 0 || modern_size > sizeof(output)) {
		return false;
	}
	memset(output, 0xA5, sizeof(output));
	if (make_kickreason(output, modern_size - 1U, message) != 0) {
		return false;
	}
	for (size_t index = 0; index < sizeof(output); index++) {
		if (output[index] != 0xA5) {
			return false;
		}
	}
	if (make_kickreason(output, modern_size, message) != modern_size || make_kickreason(NULL, modern_size, message) != 0
		|| make_kickreason(output, sizeof(output), NULL) != 0) {
		return false;
	}
	memset(output, 0xA5, sizeof(output));
	size_t legacy_size = make_kickreason_legacy(output, sizeof(output), message);
	if (legacy_size == 0 || legacy_size > sizeof(output)) {
		return false;
	}
	memset(output, 0xA5, sizeof(output));
	if (make_kickreason_legacy(output, legacy_size - 1U, message) != 0) {
		return false;
	}
	for (size_t index = 0; index < sizeof(output); index++) {
		if (output[index] != 0xA5) {
			return false;
		}
	}
	return make_kickreason_legacy(output, legacy_size, message) == legacy_size && make_kickreason_legacy(NULL, legacy_size, message) == 0
		&& make_kickreason_legacy(output, sizeof(output), NULL) == 0;
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

static int path_format(char *target, size_t target_size, const char *directory, const char *filename) {
	int length = snprintf(target, target_size, "%s/%s", directory, filename);
	if (length < 0 || (size_t)length >= target_size) {
		errno = EOVERFLOW;
		return -1;
	}
	return 0;
}

static bool legacy_motd_bounds_test(const char *directory) {
	char filename[BUFSIZ];
	uint8_t data[BUFSIZ];
	static const uint8_t short_packet[] = { '\xFE', '\x01', '\xFA' };
	uint8_t saved_length[2];
	p_motd_legacy packet;
	size_t declared_length, needed_size;
	ssize_t source_size;
	if (directory == NULL || path_format(filename, sizeof(filename), directory, "status/status_3-1.6.1.bin") != 0) {
		return false;
	}
	source_size = file_read(filename, data, sizeof(data));
	if (source_size <= 0x24 || protocol_identify(data, (size_t)source_size, NULL) != PVER_LEGACYM3) {
		return false;
	}
	declared_length = protocol_uint16_read(data + 0x1E);
	if ((size_t)source_size < 0x24U + declared_length * 2U) {
		return false;
	}
	packet = packet_read_legacy_motd(data, (size_t)source_size);
	if (packet.address == NULL) {
		return false;
	}
	packet_destroy_legacy_motd(packet);
	/* One byte short of the declared field layout is rejected instead of over-read. */
	needed_size = 0x24U + declared_length * 2U;
	packet = packet_read_legacy_motd(data, needed_size - 1U);
	if (packet.address != NULL) {
		packet_destroy_legacy_motd(packet);
		return false;
	}
	/* An oversized declared length is rejected without touching bytes beyond the buffer. */
	saved_length[0] = data[0x1E];
	saved_length[1] = data[0x1F];
	data[0x1E] = 0xFF;
	data[0x1F] = 0xFF;
	packet = packet_read_legacy_motd(data, (size_t)source_size);
	if (packet.address != NULL) {
		packet_destroy_legacy_motd(packet);
		return false;
	}
	data[0x1E] = saved_length[0];
	data[0x1F] = saved_length[1];
	/* Buffers shorter than the fixed framing are rejected before any field is read. */
	packet = packet_read_legacy_motd(short_packet, sizeof(short_packet));
	if (packet.address != NULL) {
		packet_destroy_legacy_motd(packet);
		return false;
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

static bool packet_read_bounds_test(void) {
	/* Both flush cases end at an ASan-protected object boundary; the cross-field case keeps bytes available but outside the declared address. */
	static const uint8_t fml_cross_field[] = { 0x0C, 0x00, 0x2F, 0x02, 'x', '\0', 'F', 'M', 'L', '\0', 0x63, 0xDD, 0x01 };
	static const uint8_t fml_flush[] = { 0x0A, 0x00, 0x2F, 0x03, 't', 'e', '\0' };
	static const uint8_t signature[] = { 0xA5, 0x5A };
	static const uint8_t signature_flush[] = { 0x10, 0x00, 0x2F, 0x04, 't', 'e', 's', 't', 0x63, 0xDD, 0x02, 0x06, 0x00, 0x03, 'a', 'b', 'c' };
	uint8_t packet_buffer[64];
	p_handshake packet;
	size_t offset;
	packet = packet_read((void *)fml_cross_field, (void *)(fml_cross_field + sizeof(fml_cross_field)));
	if (packet.address != NULL) {
		packet_destroy(packet);
		return false;
	}
	packet = packet_read((void *)fml_flush, (void *)(fml_flush + sizeof(fml_flush)));
	if (packet.address != NULL) {
		packet_destroy(packet);
		return false;
	}
	packet = packet_read((void *)signature_flush, (void *)(signature_flush + sizeof(signature_flush)));
	if (packet.address != NULL) {
		packet_destroy(packet);
		return false;
	}
	offset = 0;
	packet_buffer[offset++] = 15U;
	packet_buffer[offset++] = 0x00;
	packet_buffer[offset++] = 0x2F;
	packet_buffer[offset++] = 0x09;
	memcpy(packet_buffer + offset, "host\0FML\0", 9U);
	offset += 9U;
	packet_buffer[offset++] = 0x63;
	packet_buffer[offset++] = 0xDD;
	packet_buffer[offset++] = 0x01;
	packet = packet_read((void *)packet_buffer, (void *)(packet_buffer + offset));
	if (packet.address == NULL || packet.version_fml != 1 || strcmp(packet.address, "host") != 0 || packet.port != 25565 || packet.nextstate != CLIENT_INTENT_STATUS) {
		packet_destroy(packet);
		return false;
	}
	packet_destroy(packet);
	offset = 0;
	packet_buffer[offset++] = 16U;
	packet_buffer[offset++] = 0x00;
	packet_buffer[offset++] = 0x2F;
	packet_buffer[offset++] = 0x0A;
	memcpy(packet_buffer + offset, "host\0FML2\0", 10U);
	offset += 10U;
	packet_buffer[offset++] = 0x63;
	packet_buffer[offset++] = 0xDD;
	packet_buffer[offset++] = 0x01;
	packet = packet_read((void *)packet_buffer, (void *)(packet_buffer + offset));
	if (packet.address == NULL || packet.version_fml != 2 || strcmp(packet.address, "host") != 0 || packet.port != 25565 || packet.nextstate != CLIENT_INTENT_STATUS) {
		packet_destroy(packet);
		return false;
	}
	packet_destroy(packet);
	p_handshake source = { 0 };
	source.address = (void *)"host";
	source.nextstate = CLIENT_INTENT_LOGIN;
	source.port = 25565;
	source.signature_data = (void *)signature;
	source.signature_data_length = sizeof(signature);
	source.username = (void *)"player";
	source.version = PVERDB_R_1_20_1;
	size_t packet_size = packet_write(packet_buffer, sizeof(packet_buffer), source);
	packet = packet_read(packet_buffer, packet_buffer + packet_size);
	if (packet_size == 0 || packet.address == NULL || packet.username == NULL || strcmp(packet.address, "host") != 0 || strcmp(packet.username, "player") != 0
		|| packet.signature_data_length != sizeof(signature) || packet.signature_data == NULL || memcmp(packet.signature_data, signature, sizeof(signature)) != 0) {
		packet_destroy(packet);
		return false;
	}
	packet_destroy(packet);
	return true;
}

static bool packet_roundtrip(client_fixture_kind kind, protocol_version protocol, const uint8_t *source, size_t source_size, uint8_t *target, size_t target_capacity) {
	size_t target_size;
	if (kind == CLIENT_FIXTURE_LEGACY_LOGIN) {
		p_login_legacy packet = packet_read_legacy_login(source, source_size, protocol);
		target_size = packet_write_legacy_login(packet, target);
	} else if (kind == CLIENT_FIXTURE_LEGACY_STATUS) {
		p_motd_legacy packet = packet_read_legacy_motd(source, source_size);
		target_size = packet_write_legacy_motd(target, packet);
		packet_destroy_legacy_motd(packet);
	} else if (kind == CLIENT_FIXTURE_MODERN) {
		p_handshake packet = packet_read((void *)source, (void *)(source + source_size));
		if (packet.address == NULL) {
			return false;
		}
		target_size = packet_write(target, target_capacity, packet);
		packet_destroy(packet);
	} else {
		return false;
	}
	return target_size == source_size && memcmp(source, target, source_size) == 0;
}

static bool packet_write_bounds_test(void) {
	uint8_t scratch[BUFSIZ * 2];
	uint8_t *signature = malloc(BUFSIZ);
	char *long_address = malloc(PROTOHANDSHAKE_ADDRESSMAXLEN + 2U);
	char *long_username = malloc(PROTOHANDSHAKE_USERNAMEMAXLEN + 2U);
	p_handshake packet;
	bool result = false;
	size_t encoded_size;
	if (signature == NULL || long_address == NULL || long_username == NULL) {
		goto cleanup;
	}
	memset(signature, 's', BUFSIZ);
	memset(long_address, 'a', PROTOHANDSHAKE_ADDRESSMAXLEN + 1U);
	long_address[PROTOHANDSHAKE_ADDRESSMAXLEN + 1U] = '\0';
	memset(long_username, 'u', PROTOHANDSHAKE_USERNAMEMAXLEN + 1U);
	long_username[PROTOHANDSHAKE_USERNAMEMAXLEN + 1U] = '\0';
	memset(&packet, 0, sizeof(packet));
	packet.address = (void *)"status.example";
	packet.nextstate = CLIENT_INTENT_LOGIN;
	packet.port = 25565;
	packet.version = PVERDB_R_1_20_1 + 1U;
	packet.username = (void *)"player";
	packet.signature_data = signature;
	packet.signature_data_length = 1024;
	/* An exact destination capacity succeeds while one byte less is rejected. */
	encoded_size = packet_write(scratch, sizeof(scratch), packet);
	if (encoded_size == 0 || packet_write(scratch, encoded_size, packet) != encoded_size || packet_write(scratch, encoded_size - 1U, packet) != 0) {
		goto cleanup;
	}
	/* Field limits mirror packet_read: an address beyond PROTOHANDSHAKE_ADDRESSMAXLEN is rejected, one at the limit is not. */
	packet.address = long_address;
	if (packet_write(scratch, sizeof(scratch), packet) != 0) {
		goto cleanup;
	}
	long_address[PROTOHANDSHAKE_ADDRESSMAXLEN] = '\0';
	if (packet_write(scratch, sizeof(scratch), packet) == 0) {
		goto cleanup;
	}
	/* A username beyond PROTOHANDSHAKE_USERNAMEMAXLEN is rejected. */
	packet.username = long_username;
	if (packet_write(scratch, sizeof(scratch), packet) != 0) {
		goto cleanup;
	}
	packet.username = (void *)"player";
	/* The signature bound keeps the second staging buffer within BUFSIZ: the bound itself is accepted, one byte more is rejected. */
	packet.signature_data_length = BUFSIZ - 6U - 8U;
	encoded_size = packet_write(scratch, sizeof(scratch), packet);
	/* Maximum envelope: the largest address plus the largest signature encodes to 9222 bytes and fits the worker rewrite buffer. */
	if (encoded_size != 9222 || packet_write(scratch, 9222, packet) != 9222 || packet_write(scratch, 9221, packet) != 0) {
		goto cleanup;
	}
	packet.signature_data_length = BUFSIZ - 6U - 8U + 1U;
	if (packet_write(scratch, sizeof(scratch), packet) != 0) {
		goto cleanup;
	}
	packet.signature_data_length = 1024;
	/* Missing address or username fields are rejected instead of dereferenced. */
	packet.address = NULL;
	if (packet_write(scratch, sizeof(scratch), packet) != 0) {
		goto cleanup;
	}
	packet.address = (void *)"status.example";
	packet.username = NULL;
	if (packet_write(scratch, sizeof(scratch), packet) != 0) {
		goto cleanup;
	}
	result = true;
cleanup:
	free(signature);
	free(long_address);
	free(long_username);
	return result;
}

static bool packetshrink_bounds_test(void) {
	static const uint8_t mixed[] = { 0x00, 'a', 0x00, 'b', 'c' };
	static const uint8_t zeros[] = { 0x00, 0x00 };
	uint8_t target[8];
	memset(target, 0xA5, sizeof(target));
	if (packetshrink(mixed, sizeof(mixed), target, sizeof(target)) != 3 || memcmp(target, "abc", 3) != 0 || target[3] != 0xA5) {
		return false;
	}
	/* An exact destination capacity succeeds while one byte less is rejected without touching the target. */
	if (packetshrink(mixed, sizeof(mixed), target, 3U) != 3 || target[2] != 'c' || target[3] != 0xA5) {
		return false;
	}
	memset(target, 0xA5, sizeof(target));
	if (packetshrink(mixed, sizeof(mixed), target, 2U) != 0) {
		return false;
	}
	for (size_t index = 0; index < sizeof(target); index++) {
		if (target[index] != 0xA5) {
			return false;
		}
	}
	if (packetshrink(zeros, sizeof(zeros), target, sizeof(target)) != 0) {
		return false;
	}
	if (packetshrink(NULL, 1U, target, sizeof(target)) != 0 || packetshrink(mixed, sizeof(mixed), NULL, sizeof(target)) != 0) {
		return false;
	}
	return true;
}

static bool varint_bounds_test(void) {
	static const uint8_t complete[] = { 0xAC, 0x02, 0x7F };
	static const uint8_t truncated[] = { 0x80, 0x80, 0x80, 0x80 };
	static const uint8_t continuation_overflow[] = { 0x80, 0x80, 0x80, 0x80, 0x80 };
	static const uint8_t value_overflow[] = { 0x80, 0x80, 0x80, 0x80, 0x10 };
	varint_status status;
	varint_t value = 0;
	void *next = varint2int((void *)complete, (void *)(complete + sizeof(complete)), &value, &status);
	if (next != (void *)(complete + 2) || value != 300 || status != VARINT_COMPLETE) {
		return false;
	}
	next = varint2int((void *)complete, (void *)(complete + sizeof(complete)), NULL, NULL);
	if (next != (void *)(complete + 2)) {
		return false;
	}
	value = UINT32_MAX;
	next = varint2int((void *)truncated, (void *)(truncated + sizeof(truncated)), &value, &status);
	if (next != NULL || value != UINT32_MAX || status != VARINT_INCOMPLETE) {
		return false;
	}
	value = UINT32_MAX;
	next = varint2int((void *)continuation_overflow, (void *)(continuation_overflow + sizeof(continuation_overflow)), &value, &status);
	if (next != NULL || value != UINT32_MAX || status != VARINT_INVALID) {
		return false;
	}
	value = UINT32_MAX;
	next = varint2int((void *)value_overflow, (void *)(value_overflow + sizeof(value_overflow)), &value, &status);
	return next == NULL && value == UINT32_MAX && status == VARINT_INVALID;
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
	CHECK(kickreason_bounds_test(), "bounded kick response construction failed");
	CHECK(legacy_motd_bounds_test(argv[1]), "bounded legacy M3 parsing failed");
	CHECK(packet_read_bounds_test(), "bounded handshake packet reading failed");
	CHECK(varint_bounds_test(), "bounded varint decoding failed");
	CHECK(packet_write_bounds_test(), "bounded packet construction failed");
	CHECK(packetshrink_bounds_test(), "bounded packet shrinking failed");

	for (size_t index = 0; index < sizeof(client_fixtures) / sizeof(client_fixtures[0]); index++) {
		memset(source, 0, BUFSIZ);
		memset(target, 0, BUFSIZ);
		CHECK(path_format(filename, sizeof(filename), argv[1], client_fixtures[index].filename) == 0, "cannot format client fixture filename");
		ssize_t source_size = file_read(filename, source, BUFSIZ);
		CHECK(source_size > 0, "cannot read client fixture");
		CHECK(protocol_identify(source, (size_t)source_size, NULL) == client_fixtures[index].protocol, "client fixture protocol was identified incorrectly");
		if (client_fixtures[index].roundtrip) {
			CHECK(packet_roundtrip(client_fixtures[index].kind, client_fixtures[index].protocol, source, (size_t)source_size, target, sizeof(target_storage.bytes) - 1), "client fixture did not survive an exact round trip");
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
		protocol_packet_status packet_status = protocol_packet_length(legacy_m3_long_address, prefix_size, &packet_size);
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
		size_t target_size = make_kickreason_legacy(target, sizeof(target_storage.bytes) - 1U, "Outdated server!");
		CHECK(legacy_message_validate(target, target_size, &target_fields), "constructed legacy login response is malformed");
		CHECK(source_fields == target_fields && target_size == (size_t)source_size && memcmp(source, target, target_size) == 0, "constructed legacy login response differs from capture");
	}

	memset(source, 0, BUFSIZ);
	memset(target, 0, BUFSIZ);
	CHECK(path_format(filename, sizeof(filename), argv[1], "modern/login_2-13w41b.bin2") == 0, "cannot format modern login response filename");
	ssize_t source_size = file_read(filename, source, BUFSIZ);
	CHECK(source_size > 0, "cannot read modern login response");
	CHECK(modern_message_validate(source, (size_t)source_size), "captured modern login response is malformed");
	size_t target_size = make_kickreason(target, sizeof(target_storage.bytes) - 1U, "Outdated server! I'm still on 13w41b");
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
