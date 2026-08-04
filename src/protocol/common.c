/*
 * protocol/common.c: Functions for common protocol operations
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* section: headers (project) */
#include "../define/global.h"
#include "handshake.h"

/* section: headers (self) */
#include "common.h"

/* section: functions (local) */
static const uint8_t *protocol_varint_read(const uint8_t *src, const uint8_t *end, varint_t *value) {
	if (src == NULL || end == NULL || value == NULL) {
		return NULL;
	}
	varint_t result = 0;
	for (size_t index = 0; index <= VARINT_T_MAXIDX; index++) {
		if (src == end) {
			return NULL;
		}
		uint8_t byte = *src++;
		varint_t result_single = byte & 0x7F;
		if (index == VARINT_T_MAXIDX && ((byte & 0x80) || result_single > VARINT_T_LAST_MASK)) {
			return NULL;
		}
		result |= result_single << (index * 7);
		if (!(byte & 0x80)) {
			*value = result;
			return src;
		}
	}
	return NULL;
}

/* section: functions (exported) */
uint8_t protocol_identify(const void *src, size_t src_size, intent_t *intent) {
	if (intent != NULL) {
		*intent = 0;
	}
	if (src == NULL || src_size == 0) {
		return PVER_UNIDENT;
	}
	const uint8_t *source = src;
	switch (source[0]) {
		case 0x01:
			return PVER_ORIGPRO;
		case 0x02:
			if (src_size < 2) {
				return PVER_UNIDENT;
			}
			switch (source[1]) {
				case 0x00:
					if (src_size < 3) {
						return PVER_UNIDENT;
					}
					size_t field_size = src_size - 3;
					if (memchr(source + 3, ';', field_size) != NULL && memchr(source + 3, ':', field_size) != NULL) {
						return PVER_LEGACYL2;
					} else {
						return PVER_LEGACYL1;
					}
				case 0x1F:
					return PVER_LEGACYL3;
				default:
					return PVER_LEGACYL4;
			}
		case 0xFE:
			if (src_size == 1) {
				return PVER_LEGACYM1;
			}
			switch (source[1]) {
				case 0x00:
					return PVER_LEGACYM1;
				case 0x01:
					if (src_size == 2) {
						return PVER_LEGACYM2;
					}
					switch (source[2]) {
						case 0x00:
							return PVER_LEGACYM2;
						case 0xFA:
							return PVER_LEGACYM3;
						default:
							return PVER_UNIDENT;
					}
				default:
					return PVER_UNIDENT;
			}
		default: {
			const uint8_t *end = source + src_size;
			varint_t frame_size, packet_id, version;
			const uint8_t *frame_start = protocol_varint_read(source, end, &frame_size);
			if (frame_start == NULL || frame_size == 0 || (size_t)frame_size > (size_t)(end - frame_start)) {
				return PVER_UNIDENT;
			}
			const uint8_t *frame_end = frame_start + frame_size;
			const uint8_t *cursor = protocol_varint_read(frame_start, frame_end, &packet_id);
			if (cursor == NULL || packet_id != 0) {
				return PVER_UNIDENT;
			}
			cursor = protocol_varint_read(cursor, frame_end, &version);
			if (cursor == NULL || cursor == frame_end) {
				return PVER_UNIDENT;
			}
			intent_t frame_intent = frame_end[-1];
			if ((frame_intent == CLIENT_INTENT_STATUS) || (frame_intent == CLIENT_INTENT_LOGIN) || (frame_intent == CLIENT_INTENT_TRANSFER)) {
				if (intent != NULL) {
					*intent = frame_intent;
				}
				if (version != 0) {
					return PVER_MODERN2;
				} else {
					return PVER_MODERN1;
				}
			} else {
				return PVER_UNIDENT;
			}
		}
	}
}

uint16_t protocol_uint16_read(const void *src) {
	uint16_t value;
	memcpy(&value, src, sizeof(value));
	return ntohs(value);
}

void protocol_uint16_write(void *dst, uint16_t value) {
	value = htons(value);
	memcpy(dst, &value, sizeof(value));
}

uint32_t protocol_uint32_read(const void *src) {
	uint32_t value;
	memcpy(&value, src, sizeof(value));
	return ntohl(value);
}

void protocol_uint32_write(void *dst, uint32_t value) {
	value = htonl(value);
	memcpy(dst, &value, sizeof(value));
}
