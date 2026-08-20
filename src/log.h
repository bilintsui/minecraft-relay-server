/*
 * log.h: Header file of log.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LOG_H_INCLUDED_

#define _MRS_LOG_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stdint.h>

/* section: defines */
/* log file alias */
#define MKSYS_NOLOGFILE	""

/* prefixed logging */
#define MKSYS_PREFIX_ON	false
#define MKSYS_PREFIX_OFF	true

/* section: types */
/* Ordered by verbosity; keep the configured levels in this order. */
typedef enum {
	MKSYS_LEVEL_CRITICAL,
	MKSYS_LEVEL_WARNING,
	MKSYS_LEVEL_INFORMATION,
	MKSYS_LEVEL_ALL
} mksys_level;

/* section: functions (exported) */
int log_file_validate(const char *filename);
int mksysmsg(bool noprefix, const char *logfile, uint8_t maxlevel, mksys_level msglevel, const char *format, ...);

#endif
