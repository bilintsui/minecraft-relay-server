/*
 * define/exitcode.h: Header file of exit code definitions
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_EXITCODE_H_INCLUDED_

#define _MRS_EXITCODE_H_INCLUDED_

/* section: headers (library) */
#include <errno.h>
#include <sysexits.h>

/* section: types */
typedef enum {
	EXITCODE_OK = EX_OK,			/* successful termination */
	EXITCODE_NOMEM = ENOMEM,		/* memory allocation failed */
	EXITCODE_BADARG = EINVAL,		/* invalid arguments or config */
	EXITCODE_FILELARGE = EFBIG,		/* configuration file too large */
	EXITCODE_CANTCREAT = EX_CANTCREAT,	/* cannot create output file */
	EXITCODE_BADPORT = EX_CONFIG,		/* invalid bind port */
	EXITCODE_INTERNAL = EX_SOFTWARE,		/* unknown internal error */
	EXITCODE_BADJSON = EX__MAX + 1,		/* JSON parse error */
	EXITCODE_BINDFAIL = EX__MAX + 2,		/* socket bind failed */
	EXITCODE_NOCONFFILE = EX__MAX + 3	/* config file not found */
} exit_code;

#endif
