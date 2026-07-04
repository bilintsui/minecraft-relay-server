/*
 * exitcode.h: Header file for exit codes
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_EXITCODE_H_INCLUDED_

#define _MRS_EXITCODE_H_INCLUDED_

#include <errno.h>
#include <sysexits.h>

#define EXITCODE_OK		EX_OK	/* successful termination */

/* errno aliases */
#define EXITCODE_NOPIDFILE	ENOENT	/* PID file not found */
#define EXITCODE_NOSIGNAL	ESRCH	/* target process not running */
#define EXITCODE_NOMEM		ENOMEM	/* memory allocation failed */
#define EXITCODE_BADARG		EINVAL	/* invalid arguments or config */
#define EXITCODE_FILELARGE	EFBIG	/* configuration file too large */

/* sysexits aliases */
#define EXITCODE_FORKFAIL	EX_OSERR	/* fork() system call failed */
#define EXITCODE_CANTCREAT	EX_CANTCREAT	/* cannot create output file */
#define EXITCODE_BADPORT	EX_CONFIG	/* invalid bind port */
#define EXITCODE_INTERNAL	EX_SOFTWARE	/* unknown internal error */

/* custom */
#define EXITCODE_BADJSON	(EX__MAX + 1)	/* JSON parse error */
#define EXITCODE_BINDFAIL	(EX__MAX + 2)	/* socket bind failed */
#define EXITCODE_NOCONFFILE	(EX__MAX + 3)	/* config file not found */
#define EXITCODE_MULTIINSTANCE	(EX__MAX + 4)	/* another instance is already running */

#endif
