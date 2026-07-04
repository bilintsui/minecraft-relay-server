/*
 * log.h: Header file of log.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LOG_H_INCLUDED_

#define _MRS_LOG_H_INCLUDED_

#define MKSYS_LEVEL_CRITICAL	0
#define MKSYS_LEVEL_WARNING	1
#define MKSYS_LEVEL_INFORMATION	2
#define MKSYS_LEVEL_ALL	255

#define MKSYS_PREFIX_ON	0
#define MKSYS_PREFIX_OFF	1

#define MKSYS_NOLOGFILE	""

void gettime(unsigned char *target);
int mksysmsg(unsigned short noprefix, char *logfile, unsigned short runmode, unsigned short maxlevel, unsigned short msglevel, const char *format, ...);

#endif
