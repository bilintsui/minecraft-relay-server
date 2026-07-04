/*
 * log.c: Functions for logging
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

void gettime(unsigned char *target) {
	time_t timestamp = time(NULL);
	struct tm tm_local;
	localtime_r(&timestamp, &tm_local);
	int tzdiff = -timezone + tm_local.tm_isdst * 3600;
	short tzdiff_hour = tzdiff / 3600;
	short tzdiff_min = tzdiff / 60 - tzdiff_hour * 60;
	sprintf(target,
		"%04d-%02d-%02d "	/* format: date */
		"%02d:%02d:%02d "	/* format: time */
		"UTC%+03d:%02d",	/* format: timezone */
		tm_local.tm_year + 1900, tm_local.tm_mon + 1, tm_local.tm_mday,	/* data: date */
		tm_local.tm_hour, tm_local.tm_min, tm_local.tm_sec,	/* data: time */
		tzdiff_hour, tzdiff_min	/* data: timezone */
	);
}

int mksysmsg(unsigned short noprefix, char *logfile, unsigned short runmode, unsigned short maxlevel, unsigned short msglevel, const char *format, ...) {
	char level_str[8];
	int status;
	va_list varlist;
	if (msglevel > maxlevel) {
		return 0;
	}
	memset(level_str, 0, 8);
	switch (msglevel) {
		case 0:
			strcpy(level_str, "CRIT");
			break;
		case 1:
			strcpy(level_str, "WARN");
			break;
		default:
			strcpy(level_str, "INFO");
			break;
	}
	va_start(varlist, format);
	if (strcmp(logfile, "") != 0) {
		char time_str[32];
		memset(time_str, 0, 32);
		gettime(time_str);
		FILE *logfd = fopen(logfile, "a");
		if (logfd != NULL) {
			if (noprefix == 0) {
				fprintf(logfd, "[%s] [%s] ", time_str, level_str);
			}
			char format_output[BUFSIZ];
			memset(format_output, 0, BUFSIZ);
			for (int recidx = 0; recidx < strlen(format); recidx++) {
				format_output[recidx] = format[recidx];
				if (format[recidx] == '\n') {
					break;
				}
			}
			status = vfprintf(logfd, format_output, varlist);
			fclose(logfd);
		}
	}
	va_end(varlist);
	va_start(varlist, format);
	if (runmode != 2) {
		if (noprefix && !isatty(STDOUT_FILENO)) {
			status = 0;
		} else if (msglevel == 0) {
			if (noprefix == 0) {
				fprintf(stderr, "[%s] ", level_str);
			}
			status = vfprintf(stderr, format, varlist);
		} else {
			if (noprefix == 0) {
				fprintf(stdout, "[%s] ", level_str);
			}
			status = vfprintf(stdout, format, varlist);
		}
	}
	va_end(varlist);
	if (status < 0) {
		return 1;
	} else {
		return 0;
	}
}
