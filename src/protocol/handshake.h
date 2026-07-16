/*
 * protocol/handshake.h: Header file of protocol/handshake.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_PROTOCOLS_HANDSHAKE_H_INCLUDED_

#define _MRS_PROTOCOLS_HANDSHAKE_H_INCLUDED_

#include <netinet/in.h>

#include "../define/global.h"

#define CLIENT_INTENT_STATUS	1
#define CLIENT_INTENT_LOGIN	2
#define CLIENT_INTENT_TRANSFER	3

#define PROTOHANDSHAKE_ADDRESSMAXLEN	ADDRESS_MAXLEN
#define PROTOHANDSHAKE_USERNAMEMAXLEN	128

#define FAVICON_BASE64 "iVBORw0KGgoAAAANSUhEUgAAAEAAAABABAMAAABYR2ztAAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6UTwAAAAPUExURQAAAL4BAeMAALEAAP///y4OgmUAAAABdFJOUwBA5thmAAAAAWJLR0QEj2jZUQAAAAd0SU1FB+oHEA8dAoMMU8YAAAAldEVYdGRhdGU6Y3JlYXRlADIwMjYtMDctMTZUMTU6Mjk6MDIrMDA6MDBTosTZAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDI2LTA3LTE2VDE1OjI5OjAyKzAwOjAwIv98ZQAAACh0RVh0ZGF0ZTp0aW1lc3RhbXAAMjAyNi0wNy0xNlQxNToyOTowMiswMDowMHXqXboAAABySURBVEjHY2AYBfQGjIJKSEBQgPoKlNCAsjGVFYAdgLCXCaTE2ICqCoAiioLI7hEUooECBVTFTDRUAPUv7RTA/UszBYgoo5EC5CijjQK0VEd9BUroqY7KCuiQ9RgYjI0IlA+UK2BgNkYBBgzUVzAKaA0AxA9JzNErf4IAAAAASUVORK5CYII="

typedef struct {
	varint_t id_part1, id_part2, nextstate, version;
	void *address, *signature_data, *username;
	size_t signature_data_length;
	unsigned short version_fml;
	in_port_t port;
} p_handshake;

size_t make_message(void *dst, const void *src);
size_t make_kickreason(void *dst, const void *src);
size_t make_motd(void *dst, const void *src, varint_t ver, const char *favicon_b64);
p_handshake packet_read(void *src, void *end);
size_t packet_write(void *dst, const p_handshake src);
void packet_destroy(p_handshake object);

#endif
