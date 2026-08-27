/*
 * protocol/handshake.c: Functions for modern protocol handshake (13w41a and later)
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* section: headers (project) */
#include "../basic.h"
#include "../define/global.h"
#include "common.h"

/* section: headers (self) */
#include "handshake.h"

/* section: functions (local) */
static size_t varint_size(varint_t value) {
	size_t result = 1;
	while ((value >>= 7) != 0) {
		result++;
	}
	return result;
}

static bool handshake_varint_write(uint8_t **destination, size_t *remaining, varint_t value) {
	if (destination == NULL || *destination == NULL || remaining == NULL) {
		return false;
	}
	size_t encoded_size = varint_size(value);
	if (*remaining < encoded_size) {
		return false;
	}
	uint8_t *cursor = *destination;
	size_t index = 0;
	do {
		uint8_t byte = (uint8_t)(value & 0x7FU);
		value >>= 7;
		if (value != 0) {
			byte |= 0x80U;
		}
		cursor[index++] = byte;
	} while (value != 0);
	*destination += encoded_size;
	*remaining -= encoded_size;
	return true;
}

static size_t make_message(void *dst, const void *src) {
	uint8_t *tmp, *ptr_dst, *ptr_tmp;
	size_t dst_length, payload_length, src_length;
	tmp = calloc(1, BUFSIZ);
	ptr_tmp = int2varint(0, tmp);
	src_length = strlen(src);
	ptr_tmp = int2varint(src_length, ptr_tmp);
	memcpy(ptr_tmp, src, src_length);
	ptr_tmp += src_length;
	dst_length = ptr_tmp - tmp;
	ptr_dst = int2varint(dst_length, dst);
	memcpy(ptr_dst, tmp, dst_length);
	ptr_dst += dst_length;
	payload_length = ptr_dst - (uint8_t *)dst;
	free(tmp);
	return payload_length;
}

/* section: functions (exported) */
size_t make_kickreason(void *dst, size_t dst_capacity, const void *src) {
	static const char json_prefix[] = "{\"extra\":[{\"text\":\"";
	static const char json_suffix[] = "\"}],\"text\":\"\"}";
	if (dst == NULL || dst_capacity == 0 || src == NULL) {
		return 0;
	}
	size_t prefix_size = sizeof(json_prefix) - 1U;
	size_t suffix_size = sizeof(json_suffix) - 1U;
	size_t source_size = strlen(src);
	if (source_size > SIZE_MAX - prefix_size || source_size + prefix_size > SIZE_MAX - suffix_size) {
		return 0;
	}
	size_t json_size = prefix_size + source_size + suffix_size;
	if (json_size > UINT32_MAX) {
		return 0;
	}
	size_t string_length_size = varint_size((varint_t)json_size);
	if (json_size > SIZE_MAX - string_length_size - 1U) {
		return 0;
	}
	size_t frame_size = 1U + string_length_size + json_size;
	if (frame_size > UINT32_MAX) {
		return 0;
	}
	size_t frame_length_size = varint_size((varint_t)frame_size);
	if (frame_size > SIZE_MAX - frame_length_size || dst_capacity < frame_length_size + frame_size) {
		return 0;
	}
	uint8_t *cursor = dst;
	size_t remaining = dst_capacity;
	if (!handshake_varint_write(&cursor, &remaining, (varint_t)frame_size) || !handshake_varint_write(&cursor, &remaining, 0)
		|| !handshake_varint_write(&cursor, &remaining, (varint_t)json_size) || remaining < json_size) {
		return 0;
	}
	memcpy(cursor, json_prefix, prefix_size);
	cursor += prefix_size;
	memcpy(cursor, src, source_size);
	cursor += source_size;
	memcpy(cursor, json_suffix, suffix_size);
	return frame_length_size + frame_size;
}

size_t make_motd(void *dst, const void *src, varint_t ver, const char *favicon_b64) {
	void *input;
	size_t payload_length;
	const char *icon = favicon_b64 ? favicon_b64 : FAVICON_BASE64;
	input = calloc(1, BUFSIZ);
	sprintf(input,
		"{\"version\":{\"name\":\"\",\"protocol\":%u},\"players\":{\"max\":0,\"online\":0,\"sample\":[]},\"description\":{\"text\":\"%s\"},\"favicon\":\"data:image/png;base64,%s\"}",
		ver, (const char *)src, icon
	);
	payload_length = make_message(dst, input);
	free(input);
	return payload_length;
}

void packet_destroy(p_handshake object) {
	if (object.address != NULL) {
		free(object.address);
		object.address = NULL;
	}
	if (object.signature_data != NULL) {
		free(object.signature_data);
		object.signature_data = NULL;
	}
	if (object.username != NULL) {
		free(object.username);
		object.username = NULL;
	}
}

p_handshake packet_read(void *src, void *end) {
	p_handshake result;
	const char *address_end;
	void *part2_start;
	varint_t address_length, size_part1, size_part2, username_length;
	memset(&result, 0, sizeof(result));
	src = varint2int(src, end, &size_part1, NULL);
	if (src == NULL) {
		goto cleanup;
	}
	src = varint2int(src, end, &result.id_part1, NULL);
	if (src == NULL) {
		goto cleanup;
	}
	src = varint2int(src, end, &result.version, NULL);
	if (src == NULL) {
		goto cleanup;
	}
	src = varint2int(src, end, &address_length, NULL);
	if (src == NULL) {
		goto cleanup;
	}
	if (address_length > PROTOHANDSHAKE_ADDRESSMAXLEN) {
		goto cleanup;
	}
	if (address_length == 0) {
		goto cleanup;
	}
	if ((size_t)((const char *)end - (const char *)src) < address_length) {
		goto cleanup;
	}
	address_end = (const char *)src + address_length;
	if (address_end[-1] == '\0') {
		result.address = malloc(strlen(src) + 1);
		if (result.address == NULL) {
			goto cleanup;
		}
		strcpy(result.address, src);
		src = (char *)src + strlen(src);
		size_t suffix_size = (size_t)(address_end - (const char *)src);
		if (suffix_size == 5U && memcmp(src, "\0FML\0", 5) == 0) {
			result.version_fml = 1;
			src = (char *)src + 5;
		} else if (suffix_size == 6U && memcmp(src, "\0FML2\0", 6) == 0) {
			result.version_fml = 2;
			src = (char *)src + 6;
		} else {
			goto cleanup;
		}
	} else {
		result.version_fml = 0;
		result.address = calloc(1, address_length + 1);
		if (result.address == NULL) {
			goto cleanup;
		}
		memcpy(result.address, src, address_length);
		src = (void *)address_end;
	}
	if ((char *)src + sizeof(in_port_t) > (char *)end) {
		goto cleanup;
	}
	result.port = protocol_uint16_read(src);
	src = (uint8_t *)src + sizeof(uint16_t);
	src = varint2int(src, end, &result.nextstate, NULL);
	if (src == NULL) {
		goto cleanup;
	}
	if ((result.nextstate == CLIENT_INTENT_LOGIN) || (result.nextstate == CLIENT_INTENT_TRANSFER)) {
		part2_start = src = varint2int(src, end, &size_part2, NULL);
		if (src == NULL) {
			goto cleanup;
		}
		src = varint2int(src, end, &result.id_part2, NULL);
		if (src == NULL) {
			goto cleanup;
		}
		src = varint2int(src, end, &username_length, NULL);
		if (src == NULL) {
			goto cleanup;
		}
		if (username_length > PROTOHANDSHAKE_USERNAMEMAXLEN) {
			goto cleanup;
		}
		if ((char *)src + username_length > (char *)end) {
			goto cleanup;
		}
		result.username = calloc(1, username_length + 1);
		if (result.username == NULL) {
			goto cleanup;
		}
		memcpy(result.username, src, username_length);
		src = (char *)src + username_length;
		if ((size_t)((char *)src - (char *)part2_start) > size_part2) {
			goto cleanup;
		}
		result.signature_data_length = size_part2 - ((char *)src - (char *)part2_start);
		if (result.signature_data_length) {
			if (((result.version <= PVERDB_R_1_20_1) || ((result.version & PVERDB_SNAPMASK) <= PVERDB_S_1_20_1_RC1)) && (char *)src < (char *)end && (*((char *)src) == 1)) {
				result.signature_data_length--;
				src = (char *)src + 1;
			}
			if ((char *)src + result.signature_data_length > (char *)end) {
				goto cleanup;
			}
			result.signature_data = malloc(result.signature_data_length);
			if (result.signature_data == NULL) {
				goto cleanup;
			}
			memcpy(result.signature_data, src, result.signature_data_length);
			src = (char *)src + result.signature_data_length;
		} else {
			result.signature_data_length = 0;
		}
	}
	return result;
cleanup:
	packet_destroy(result);
	memset(&result, 0, sizeof(result));
	return result;
}

size_t packet_write(void *dst, size_t dst_capacity, const p_handshake src) {
	uint8_t *part1, *part2, *ptr_dst, *ptr_part1, *ptr_part2;
	size_t address_length, address_length_pure, size, size_part1, size_part2, username_length;
	if (dst == NULL || src.address == NULL) {
		return 0;
	}
	address_length = address_length_pure = strlen(src.address);
	if (address_length_pure > PROTOHANDSHAKE_ADDRESSMAXLEN) {
		return 0;
	}
	if (src.version_fml == 1) {
		address_length += 5;
	} else if (src.version_fml == 2) {
		address_length += 6;
	}
	username_length = 0;
	if ((src.nextstate == CLIENT_INTENT_LOGIN) || (src.nextstate == CLIENT_INTENT_TRANSFER)) {
		if (src.username == NULL) {
			return 0;
		}
		username_length = strlen(src.username);
		/* The 8-byte reserve covers the id, username-length, and legacy placeholder varints, keeping both staging buffers within BUFSIZ. */
		if (username_length > PROTOHANDSHAKE_USERNAMEMAXLEN || (src.signature_data_length > 0 && src.signature_data == NULL)
			|| src.signature_data_length > BUFSIZ - username_length - 8U) {
			return 0;
		}
	}
	ptr_part1 = part1 = calloc(1, BUFSIZ);
	ptr_part2 = part2 = calloc(1, BUFSIZ);
	if (part1 == NULL || part2 == NULL) {
		free(part1);
		free(part2);
		return 0;
	}
	ptr_dst = dst;
	ptr_part1 = int2varint(src.id_part1, ptr_part1);
	ptr_part1 = int2varint(src.version, ptr_part1);
	ptr_part1 = int2varint(address_length, ptr_part1);
	memcpy(ptr_part1, src.address, address_length_pure);
	if (src.version_fml == 1) {
		memcpy(ptr_part1 + address_length_pure, "\0FML\0", 5);
	} else if (src.version_fml == 2) {
		memcpy(ptr_part1 + address_length_pure, "\0FML2\0", 6);
	}
	ptr_part1 += address_length;
	protocol_uint16_write(ptr_part1, src.port);
	ptr_part1 += sizeof(uint16_t);
	ptr_part1 = int2varint(src.nextstate, ptr_part1);
	size_part1 = ptr_part1 - part1;
	ptr_part2 = int2varint(src.id_part2, ptr_part2);
	if ((src.nextstate == CLIENT_INTENT_LOGIN) || (src.nextstate == CLIENT_INTENT_TRANSFER)) {
		ptr_part2 = int2varint(username_length, ptr_part2);
		memcpy(ptr_part2, src.username, username_length);
		ptr_part2 += username_length;
		if (src.signature_data_length) {
			if ((src.version <= PVERDB_R_1_20_1) || ((src.version & PVERDB_SNAPMASK) <= PVERDB_S_1_20_1_RC1)) {
				ptr_part2 = int2varint(1, ptr_part2);
			}
			memcpy(ptr_part2, src.signature_data, src.signature_data_length);
			ptr_part2 += src.signature_data_length;
		}
	}
	size_part2 = ptr_part2 - part2;
	if (dst_capacity < varint_size(size_part1) + size_part1 + varint_size(size_part2) + size_part2) {
		free(part1);
		free(part2);
		return 0;
	}
	ptr_dst = int2varint(size_part1, ptr_dst);
	memcpy(ptr_dst, part1, size_part1);
	ptr_dst += size_part1;
	ptr_dst = int2varint(size_part2, ptr_dst);
	memcpy(ptr_dst, part2, size_part2);
	ptr_dst += size_part2;
	size = ptr_dst - (uint8_t *)dst;
	free(part1);
	free(part2);
	return size;
}
