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
#include <stdint.h>

/* section: types */
typedef struct {
	int proto_ver;
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
size_t make_kickreason_legacy(void *dst, const void *src);
size_t make_motd_legacy(void *dst, const void *src, uint8_t motd_version, uint8_t version);
void packet_destroy_legacy_motd(p_motd_legacy object);
p_login_legacy packet_read_legacy_login(const void *sourcepacket, size_t sourcepacket_length, uint8_t login_version);
p_motd_legacy packet_read_legacy_motd(const void *src);
size_t packet_write_legacy_login(p_login_legacy source, void *target);
size_t packet_write_legacy_motd(void *dst, p_motd_legacy src);

#endif
