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
/* logging level */
#define MKSYS_LEVEL_CRITICAL	0
#define MKSYS_LEVEL_WARNING	1
#define MKSYS_LEVEL_INFORMATION	2
#define MKSYS_LEVEL_ALL	255

/* log file alias */
#define MKSYS_NOLOGFILE	""

/* prefixed logging */
#define MKSYS_PREFIX_ON	false
#define MKSYS_PREFIX_OFF	true

/* section: functions (exported) */
int log_file_validate(const char *filename);
int mksysmsg(bool noprefix, const char *logfile, uint8_t maxlevel, uint8_t msglevel, const char *format, ...);

#endif
