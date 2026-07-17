/*
 * protocol/common.h: Header file of protocol/common.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_PROTOCOLS_COMMON_H_INCLUDED_

#define _MRS_PROTOCOLS_COMMON_H_INCLUDED_

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

uint8_t protocol_identify(const void *src);

#endif
