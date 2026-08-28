/*
 * protocol/handshake_legacy.h: Header file of protocol/handshake_legacy.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_PROTOCOLS_HANDSHAKE_LEGACY_H_INCLUDED_

#define _MRS_PROTOCOLS_HANDSHAKE_LEGACY_H_INCLUDED_

/* section: headers (library) */
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "common.h"

/* section: types */
typedef struct {
	protocol_version proto_ver;
	char username[128], address[128];
	in_port_t port;
	uint8_t version;
} p_login_legacy;
typedef struct {
	void *address;
	in_port_t port;
	uint8_t version;
} p_motd_legacy;

/* section: functions (exported) */
/* Encodes a legacy login disconnect packet containing src. Returns zero when the arguments or capacity are invalid. */
size_t make_kickreason_legacy(void *dst, size_t dst_capacity, const void *src);
/*
 * Encodes a legacy status MOTD response containing src for M1/M2/M3. Returns zero when the arguments, protocol version,
 * or capacity are invalid; dst is written only on success and no heap allocation is performed.
 */
size_t make_motd_legacy(void *dst, size_t dst_capacity, const void *src, protocol_version motd_version, uint8_t version);
void packet_destroy_legacy_motd(p_motd_legacy object);
p_login_legacy packet_read_legacy_login(const void *sourcepacket, size_t sourcepacket_length, protocol_version login_version);
/*
 * Parses an M3 ping from src[0 .. src_size) into version, address, and port.  Returns a zeroed structure with a
 * NULL address when the arguments are invalid, the declared fields exceed src_size, or allocation fails.
 */
p_motd_legacy packet_read_legacy_motd(const void *src, size_t src_size);
size_t packet_write_legacy_login(p_login_legacy source, void *target);
size_t packet_write_legacy_motd(void *dst, p_motd_legacy src);

#endif
