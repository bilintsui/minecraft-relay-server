/*
 * handshake_origin_fixtures.h: Query-origin filtering regression fixtures
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

#ifndef _MRS_TESTS_HANDSHAKE_ORIGIN_FIXTURES_H_INCLUDED_

#define _MRS_TESTS_HANDSHAKE_ORIGIN_FIXTURES_H_INCLUDED_

/* section: headers (library) */
#include <stddef.h>

/* section: defines */
#define HANDSHAKE_ORIGIN_FIXTURE(input, output) { input, sizeof(input) - 1U, output, sizeof(output) - 1U }

/* section: types */
typedef struct {
	const char *input;
	size_t input_size;
	const char *output;
	size_t output_size;
} handshake_origin_fixture;

/* section: global variables */
static const handshake_origin_fixture handshake_origin_fixtures[] = {
	HANDSHAKE_ORIGIN_FIXTURE("", ""),
	HANDSHAKE_ORIGIN_FIXTURE("?", "?"),
	HANDSHAKE_ORIGIN_FIXTURE("?_id=public&key=a%2Fb+%20&flag&empty=&key=second", "?_id=public&key=a%2Fb+%20&flag&empty=&key=second"),
	HANDSHAKE_ORIGIN_FIXTURE("?_o=join.example%3A25565", ""),
	HANDSHAKE_ORIGIN_FIXTURE("?_o", ""),
	HANDSHAKE_ORIGIN_FIXTURE("?_o=", ""),
	HANDSHAKE_ORIGIN_FIXTURE("?_o=%&keep=x", "?keep=x"),
	HANDSHAKE_ORIGIN_FIXTURE("?_o=x&_id=keep", "?_id=keep"),
	HANDSHAKE_ORIGIN_FIXTURE("?a=1&_o=x&b=2", "?a=1&b=2"),
	HANDSHAKE_ORIGIN_FIXTURE("?a=1&_o=x", "?a=1"),
	HANDSHAKE_ORIGIN_FIXTURE("?_o=x&_o=y&%5Fo=z&_%6f=a&%5f%6F=b", ""),
	HANDSHAKE_ORIGIN_FIXTURE("?%5Fo=x&_%6F=y&%5F%6f=z&_id=keep", "?_id=keep"),
	HANDSHAKE_ORIGIN_FIXTURE("?%5f%6F&%5F%6F=&keep=x", "?keep=x"),
	HANDSHAKE_ORIGIN_FIXTURE("?_origin=x&_o_extra=y&_O=z&%5F%4F=w&key=_o=stay&_id=x", "?_origin=x&_o_extra=y&_O=z&%5F%4F=w&key=_o=stay&_id=x"),
	HANDSHAKE_ORIGIN_FIXTURE("?%255Fo=x&%5F%256f=y&+_o=z&_o+=w&_o%00=x&%00_o=y", "?%255Fo=x&%5F%256f=y&+_o=z&_o+=w&_o%00=x&%00_o=y"),
	HANDSHAKE_ORIGIN_FIXTURE("?%=x&%5=x&%GG=x&%5G=x&_%6=x&%5F%6=x&_%6g=x&_o=remove", "?%=x&%5=x&%GG=x&%5G=x&_%6=x&%5F%6=x&_%6g=x"),
	HANDSHAKE_ORIGIN_FIXTURE("?a=%26_o%3Dkeep&b=x=y&%61=+&_o=remove", "?a=%26_o%3Dkeep&b=x=y&%61=+"),
	HANDSHAKE_ORIGIN_FIXTURE("?&_o=x&&flag&_o=y&", "?&&flag&"),
	HANDSHAKE_ORIGIN_FIXTURE("?_o=x&", "?"),
	HANDSHAKE_ORIGIN_FIXTURE("?&_o=x", "?"),
	HANDSHAKE_ORIGIN_FIXTURE("?_o=x&&_o=y", "?"),
	HANDSHAKE_ORIGIN_FIXTURE("?\0FORGE?_o=opaque", "?\0FORGE?_o=opaque"),
	HANDSHAKE_ORIGIN_FIXTURE("\0FML\0", "\0FML\0"),
	HANDSHAKE_ORIGIN_FIXTURE("\0FORGE?_o=opaque&%5Fo=opaque", "\0FORGE?_o=opaque&%5Fo=opaque"),
	HANDSHAKE_ORIGIN_FIXTURE("?_o=x\0FORGE", "\0FORGE"),
	HANDSHAKE_ORIGIN_FIXTURE("?_o=x&_id=keep\0FML\0?_o=opaque&%5Fo=opaque", "?_id=keep\0FML\0?_o=opaque&%5Fo=opaque"),
	HANDSHAKE_ORIGIN_FIXTURE("?a=1&_o=x\0_o=opaque\0\xA5", "?a=1\0_o=opaque\0\xA5"),
	HANDSHAKE_ORIGIN_FIXTURE("?_id=keep\0FORGE?_o=opaque", "?_id=keep\0FORGE?_o=opaque"),
	HANDSHAKE_ORIGIN_FIXTURE("?_o=x&%5Fo=y\0", "\0"),
	HANDSHAKE_ORIGIN_FIXTURE("?_o=x?keep=value&keep=1", "?keep=1"),
	HANDSHAKE_ORIGIN_FIXTURE("?keep?_o=x&keep=2", "?keep?_o=x&keep=2"),
	HANDSHAKE_ORIGIN_FIXTURE("?_o%26x=y&%5Fo%3Dx=z", "?_o%26x=y&%5Fo%3Dx=z"),
	/* Removing this long origin crosses both host-length and frame-length VarInt boundaries. */
	HANDSHAKE_ORIGIN_FIXTURE(
		"?_o=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.example%3A25565&_id=keep",
		"?_id=keep"
	)
};

#endif
