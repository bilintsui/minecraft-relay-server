/*
 * define/global.h: Header file of global definitions
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_DEFINES_H_INCLUDED_

#define _MRS_DEFINES_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stdint.h>

/* section: defines */
/* limit */
#define ADDRESS_MAXLEN	1024

/* debug mode toggle */
#ifndef DEBUG_MODE
#define DEBUG_MODE	false
#endif

/* program metadata */
#define MCRELAY_VERSION_DISPLAY	"1.2-rc1"
#define MCRELAY_VERSION_INTERNAL	"73"
#define MCRELAY_COPYYEAR	"2020-2026"

/* protocol version constant */
#define PVERDB_SNAPMASK	0xBFFFFFFF
#define PVERDB_R_1_20_1	763
#define PVERDB_S_1_20_1_RC1	0x8E

/* varint */
#define VARINT_T_MAXIDX	(sizeof(varint_t) * 8 / 7)
#define VARINT_T_LAST_MASK	((varint_t)((1u << ((sizeof(varint_t) * 8) % 7)) - 1))

/* section: types */
/* Minecraft handshake intent values; keep this declaration in wire-value order. */
typedef enum {
	CLIENT_INTENT_UNSPECIFIED,
	CLIENT_INTENT_STATUS,
	CLIENT_INTENT_LOGIN,
	CLIENT_INTENT_TRANSFER
} intent_t;
typedef uint32_t varint_t;

#endif
