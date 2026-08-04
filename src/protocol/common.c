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

/* section: functions (exported) */
uint8_t protocol_identify(const void *src) {
	if (src == NULL) {
		return PVER_UNIDENT;
	}
	const uint8_t *source = src;
	switch (source[0]) {
		case 0x01:
			return PVER_ORIGPRO;
		case 0x02:
			switch (source[1]) {
				case 0x00:
					if (memchr(source + 3, ';', source[2] * 2) && memchr(source + 3, ':', source[2] * 2)) {
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
			switch (source[1]) {
				case 0x00:
					return PVER_LEGACYM1;
				case 0x01:
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
			intent_t intent = source[source[0]];
			if ((intent == CLIENT_INTENT_STATUS) || (intent == CLIENT_INTENT_LOGIN) || (intent == CLIENT_INTENT_TRANSFER)) {
				if (source[2]) {
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
