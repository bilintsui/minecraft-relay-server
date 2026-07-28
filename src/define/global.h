/*
 * define/global.h: Header file for global/general defines
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_DEFINES_H_INCLUDED_

#define _MRS_DEFINES_H_INCLUDED_

#include <stdint.h>

#define MCRELAY_VERSION_DISPLAY	"1.2-beta6"
#define MCRELAY_VERSION_INTERNAL	"68"
#define MCRELAY_COPYYEAR	"2020-2026"

#define PVERDB_SNAPMASK	0xBFFFFFFF
#define PVERDB_R_1_20_1	763
#define PVERDB_S_1_20_1_RC1	0x8E

#define VARINT_T_MAXIDX	(sizeof(varint_t) * 8 / 7)
#define VARINT_T_LAST_MASK	((varint_t)((1u << ((sizeof(varint_t) * 8) % 7)) - 1))

#ifndef DEBUG_MODE
#define DEBUG_MODE	false
#endif

#define ADDRESS_MAXLEN	1024

#define RUNMODE_CONSOLE	0
#define RUNMODE_SIMPLE	1
#define RUNMODE_FORKING	2

typedef uint8_t intent_t;
typedef uint32_t varint_t;

#endif
