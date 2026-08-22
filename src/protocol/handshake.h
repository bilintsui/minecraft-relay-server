/*
 * protocol/handshake.h: Header file of protocol/handshake.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_PROTOCOLS_HANDSHAKE_H_INCLUDED_

#define _MRS_PROTOCOLS_HANDSHAKE_H_INCLUDED_

/* section: headers (library) */
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "../define/global.h"

/* section: defines */
/* server icon */
#define FAVICON_BASE64 \
	"iVBORw0KGgoAAAANSUhEUgAAAEAAAABABAMAAABYR2ztAAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6UTwAAAAPUExURQAAAL4BAeMAALEAAP///y4OgmUAAAABdFJOUwBA5thmAAAA" \
	"AWJLR0QEj2jZUQAAAAd0SU1FB+oHEA8dAoMMU8YAAAAldEVYdGRhdGU6Y3JlYXRlADIwMjYtMDctMTZUMTU6Mjk6MDIrMDA6MDBTosTZAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDI2LTA3LTE2VDE1OjI5OjAyKzAw" \
	"OjAwIv98ZQAAACh0RVh0ZGF0ZTp0aW1lc3RhbXAAMjAyNi0wNy0xNlQxNToyOTowMiswMDowMHXqXboAAABySURBVEjHY2AYBfQGjIJKSEBQgPoKlNCAsjGVFYAdgLCXCaTE2ICqCoAiioLI7hEUooECBVTFTDRU" \
	"APUv7RTA/UszBYgoo5EC5CijjQK0VEd9BUroqY7KCuiQ9RgYjI0IlA+UK2BgNkYBBgzUVzAKaA0AxA9JzNErf4IAAAAASUVORK5CYII="

/* limit */
#define PROTOHANDSHAKE_ADDRESSMAXLEN	ADDRESS_MAXLEN
#define PROTOHANDSHAKE_USERNAMEMAXLEN	128

/* section: types */
typedef struct {
	varint_t id_part1, id_part2, nextstate, version;
	void *address, *signature_data, *username;
	size_t signature_data_length;
	uint8_t version_fml;
	in_port_t port;
} p_handshake;

/* section: functions (exported) */
size_t make_kickreason(void *dst, const void *src);
size_t make_motd(void *dst, const void *src, varint_t ver, const char *favicon_b64);
void packet_destroy(p_handshake object);
p_handshake packet_read(void *src, void *end);
/* Returns the total bytes written and 0 when dst is NULL, src fields are missing or exceed the packet_read limits, memory allocation fails, or the encoded packet does not fit dst_capacity. */
size_t packet_write(void *dst, size_t dst_capacity, const p_handshake src);

#endif
