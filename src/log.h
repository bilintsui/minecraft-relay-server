/*
 * log.h: Header file of log.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LOG_H_INCLUDED_

#define _MRS_LOG_H_INCLUDED_

void gettime(unsigned char *target);
int mksysmsg(unsigned short noprefix, char *logfile, unsigned short runmode, unsigned short maxlevel, unsigned short msglevel, const char *format, ...);

#endif
