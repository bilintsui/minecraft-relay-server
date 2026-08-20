/*
 * connection/setup_short.h: Header file of setup_short.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_CONNECTION_SETUP_SHORT_H_INCLUDED_

#define _MRS_CONNECTION_SETUP_SHORT_H_INCLUDED_

/* section: headers (library) */
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "../protocol/common.h"
#include "../protocol/proxy.h"
#include "setup.h"

/* section: types */
typedef enum {
	CONNSETUP_SHORT_ABORT,
	CONNSETUP_SHORT_CONNECT,
	CONNSETUP_SHORT_RESPOND
} connsetup_short_action;
typedef struct {
	connsetup_snapshot snapshot;
	net_addrbundle inbound_address;
	protocol_version protocol;
	intent_t intent;
	uint8_t pheader[PROTOPROXY_PACKETMAXLEN + 1U];
	size_t pheader_size;
	uint8_t *request;
	size_t request_size;
	uint8_t *response;
	size_t response_size;
	connsetup_status result;
} connsetup_short_plan;

/* section: functions (exported) */
/* The plan owns its request and response buffers and contains no borrowed snapshot or configuration pointer. */
void connsetup_short_destroy(connsetup_short_plan *plan);
/* The initial packet is copied into an exact-size request allocation when the action is CONNECT. */
connsetup_short_action connsetup_short_prepare(connsetup_short_plan *plan, const connsetup_snapshot *snapshot, net_addrbundle inbound_address,
	const uint8_t *initial, size_t initial_size);

#endif
