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

/* common logging shortcut */
#define MKSYS_LOG(logfile, maxlevel, lvl, ...)	mksysmsg(MKSYS_PREFIX_ON, logfile, maxlevel, lvl, MKSYS_LINE_END, __VA_ARGS__)

/* section: types */
/* Ordered by verbosity; keep the configured levels in this order. */
typedef enum {
	MKSYS_LEVEL_CRITICAL,
	MKSYS_LEVEL_WARNING,
	MKSYS_LEVEL_INFORMATION,
	MKSYS_LEVEL_ALL
} mksys_level;
typedef enum {
	MKSYS_LINE_END,
	MKSYS_PARAGRAPH_END
} mksys_line_end;

/* section: functions (exported) */
int log_file_validate(const char *filename);
/* Every logged message is escaped through escape_default, so the output contains only visible ASCII characters; the line end is appended by the logger, not by the format string. */
int mksysmsg(bool noprefix, const char *logfile, uint8_t maxlevel, mksys_level msglevel, mksys_line_end line_end, const char *format, ...);

#endif
