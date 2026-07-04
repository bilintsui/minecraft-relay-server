/*
 * protocol/common.c: Functions for common protocol operations
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#include <string.h>

#include "common.h"

int protocol_identify(const char *src) {
	if (src == NULL) {
		return PVER_UNIDENT;
	}
	const unsigned char *source = (unsigned char *)src;
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
		default:
			if ((source[source[0]] == 1) || (source[source[0]] == 2)) {
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
