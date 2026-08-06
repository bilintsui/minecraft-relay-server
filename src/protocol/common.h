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

/* section: defines */
/* protocol type */
#define PVER_UNIDENT	0
#define PVER_ORIGPRO	1
#define PVER_LEGACYL1	2
#define PVER_LEGACYL2	3
#define PVER_LEGACYL3	4
#define PVER_LEGACYL4	5
#define PVER_LEGACYM1	6
#define PVER_LEGACYM2	7
#define PVER_LEGACYM3	8
#define PVER_MODERN1	9
#define PVER_MODERN2	10

/* section: types */
enum protocol_packet_status {
	PROTOCOL_PACKET_AMBIGUOUS,
	PROTOCOL_PACKET_COMPLETE,
	PROTOCOL_PACKET_INCOMPLETE,
	PROTOCOL_PACKET_INVALID
};

/* section: functions (exported) */
uint8_t protocol_identify(const void *src, size_t src_size, intent_t *intent);
enum protocol_packet_status protocol_packet_length(const void *src, size_t src_size, size_t *packet_size);
uint16_t protocol_uint16_read(const void *src);
void protocol_uint16_write(void *dst, uint16_t value);
uint32_t protocol_uint32_read(const void *src);
void protocol_uint32_write(void *dst, uint32_t value);

#endif
