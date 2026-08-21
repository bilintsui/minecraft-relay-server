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
#include "../basic.h"
#include "../define/global.h"
#include "handshake.h"

/* section: headers (self) */
#include "common.h"

/* section: functions (local) */
static protocol_packet_status protocol_varint_read(const uint8_t **cursor, const uint8_t *end, varint_t *value) {
	if (cursor == NULL || *cursor == NULL || end == NULL || value == NULL) {
		return PROTOCOL_PACKET_INVALID;
	}
	varint_status status;
	void *result = varint2int((void *)*cursor, (void *)end, value, &status);
	if (result == NULL) {
		return status == VARINT_INCOMPLETE ? PROTOCOL_PACKET_INCOMPLETE : PROTOCOL_PACKET_INVALID;
	}
	*cursor = result;
	return PROTOCOL_PACKET_COMPLETE;
}

/* section: functions (exported) */
protocol_version protocol_identify(const void *src, size_t src_size, intent_t *intent) {
	if (intent != NULL) {
		*intent = CLIENT_INTENT_UNSPECIFIED;
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
			const uint8_t *frame_start = source;
			if (protocol_varint_read(&frame_start, end, &frame_size) != PROTOCOL_PACKET_COMPLETE || frame_size == 0 || (size_t)frame_size > (size_t)(end - frame_start)) {
				return PVER_UNIDENT;
			}
			const uint8_t *frame_end = frame_start + frame_size;
			const uint8_t *cursor = frame_start;
			if (protocol_varint_read(&cursor, frame_end, &packet_id) != PROTOCOL_PACKET_COMPLETE || packet_id != 0) {
				return PVER_UNIDENT;
			}
			if (protocol_varint_read(&cursor, frame_end, &version) != PROTOCOL_PACKET_COMPLETE || cursor == frame_end) {
				return PVER_UNIDENT;
			}
			uint8_t frame_intent = frame_end[-1];
			if ((frame_intent == CLIENT_INTENT_STATUS) || (frame_intent == CLIENT_INTENT_LOGIN) || (frame_intent == CLIENT_INTENT_TRANSFER)) {
				if (intent != NULL) {
					*intent = (intent_t)frame_intent;
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

protocol_packet_status protocol_packet_length(const void *src, size_t src_size, size_t *packet_size) {
	if (src == NULL || packet_size == NULL) {
		return PROTOCOL_PACKET_INVALID;
	}
	*packet_size = 0;
	if (src_size == 0) {
		*packet_size = 1;
		return PROTOCOL_PACKET_INCOMPLETE;
	}
	const uint8_t *source = src;
	switch (source[0]) {
		case 0x01:
			*packet_size = 1;
			return PROTOCOL_PACKET_COMPLETE;
		case 0x02: {
			if (src_size < 2) {
				*packet_size = 2;
				return PROTOCOL_PACKET_INCOMPLETE;
			}
			if (source[1] == 0) {
				if (src_size < 4) {
					*packet_size = 4;
					return PROTOCOL_PACKET_INCOMPLETE;
				}
				size_t character_size = (source[3] == 0) ? sizeof(uint16_t) : sizeof(uint8_t);
				*packet_size = 3 + (size_t)source[2] * character_size;
			} else {
				if (src_size < 4) {
					*packet_size = 4;
					return PROTOCOL_PACKET_INCOMPLETE;
				}
				size_t username_end = 4 + (size_t)protocol_uint16_read(source + 2) * sizeof(uint16_t);
				if (source[1] == 0x1F) {
					*packet_size = username_end;
				} else {
					if (src_size < username_end + sizeof(uint16_t)) {
						*packet_size = username_end + sizeof(uint16_t);
						return PROTOCOL_PACKET_INCOMPLETE;
					}
					size_t address_length = protocol_uint16_read(source + username_end);
					*packet_size = username_end + sizeof(uint16_t) + address_length * sizeof(uint16_t) + sizeof(uint32_t);
				}
			}
			return (src_size < *packet_size) ? PROTOCOL_PACKET_INCOMPLETE : PROTOCOL_PACKET_COMPLETE;
		}
		case 0xFE:
			if (src_size == 1 || (src_size == 2 && source[1] == 0x01)) {
				*packet_size = 3;
				return PROTOCOL_PACKET_AMBIGUOUS;
			}
			if (source[1] != 0x01 || source[2] != 0xFA) {
				*packet_size = src_size;
				return PROTOCOL_PACKET_COMPLETE;
			}
			if (src_size < 0x20) {
				*packet_size = 0x20;
				return PROTOCOL_PACKET_INCOMPLETE;
			}
			*packet_size = 0x20 + (size_t)protocol_uint16_read(source + 0x1E) * sizeof(uint16_t) + sizeof(uint32_t);
			return (src_size < *packet_size) ? PROTOCOL_PACKET_INCOMPLETE : PROTOCOL_PACKET_COMPLETE;
		default: {
			const uint8_t *cursor = source;
			const uint8_t *end = source + src_size;
			varint_t frame_size;
			protocol_packet_status status = protocol_varint_read(&cursor, end, &frame_size);
			if (status != PROTOCOL_PACKET_COMPLETE) {
				*packet_size = (status == PROTOCOL_PACKET_INCOMPLETE && src_size < SIZE_MAX) ? src_size + 1 : 0;
				return status;
			}
			size_t frame_prefix_size = (size_t)(cursor - source);
			if (frame_size == 0 || (size_t)frame_size > SIZE_MAX - frame_prefix_size) {
				return PROTOCOL_PACKET_INVALID;
			}
			size_t first_frame_size = frame_prefix_size + (size_t)frame_size;
			*packet_size = first_frame_size;
			if (src_size < first_frame_size) {
				return PROTOCOL_PACKET_INCOMPLETE;
			}
			intent_t intent;
			protocol_version protocol = protocol_identify(source, first_frame_size, &intent);
			if (protocol == PVER_UNIDENT) {
				return PROTOCOL_PACKET_INVALID;
			}
			if (protocol == PVER_MODERN1 || intent == CLIENT_INTENT_STATUS) {
				return PROTOCOL_PACKET_COMPLETE;
			}
			cursor = source + first_frame_size;
			status = protocol_varint_read(&cursor, end, &frame_size);
			if (status != PROTOCOL_PACKET_COMPLETE) {
				*packet_size = (status == PROTOCOL_PACKET_INCOMPLETE && src_size < SIZE_MAX) ? src_size + 1 : 0;
				return status;
			}
			frame_prefix_size = (size_t)(cursor - (source + first_frame_size));
			if (frame_size == 0 || frame_prefix_size > SIZE_MAX - first_frame_size || (size_t)frame_size > SIZE_MAX - first_frame_size - frame_prefix_size) {
				return PROTOCOL_PACKET_INVALID;
			}
			*packet_size = first_frame_size + frame_prefix_size + (size_t)frame_size;
			return (src_size < *packet_size) ? PROTOCOL_PACKET_INCOMPLETE : PROTOCOL_PACKET_COMPLETE;
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
