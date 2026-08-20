/*
 * protocol/common.h: Header file of protocol/common.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_PROTOCOLS_COMMON_H_INCLUDED_

#define _MRS_PROTOCOLS_COMMON_H_INCLUDED_

/* section: headers (library) */
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "../define/global.h"

/* section: types */
typedef enum {
	PROTOCOL_PACKET_AMBIGUOUS,
	PROTOCOL_PACKET_COMPLETE,
	PROTOCOL_PACKET_INCOMPLETE,
	PROTOCOL_PACKET_INVALID
} protocol_packet_status;
typedef enum {
	PVER_UNIDENT,
	PVER_ORIGPRO,
	PVER_LEGACYL1,
	PVER_LEGACYL2,
	PVER_LEGACYL3,
	PVER_LEGACYL4,
	PVER_LEGACYM1,
	PVER_LEGACYM2,
	PVER_LEGACYM3,
	PVER_MODERN1,
	PVER_MODERN2
} protocol_version;

/* section: functions (exported) */
protocol_version protocol_identify(const void *src, size_t src_size, intent_t *intent);
protocol_packet_status protocol_packet_length(const void *src, size_t src_size, size_t *packet_size);
uint16_t protocol_uint16_read(const void *src);
void protocol_uint16_write(void *dst, uint16_t value);
uint32_t protocol_uint32_read(const void *src);
void protocol_uint32_write(void *dst, uint32_t value);

#endif
