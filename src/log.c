/*
 * log.c: Functions for logging
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* section: headers (self) */
#include "log.h"

/* section: functions (local) */
static void gettime(char *target) {
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

/* section: functions (exported) */
int mksysmsg(bool noprefix, const char *logfile, uint8_t maxlevel, uint8_t msglevel, const char *format, ...) {
	char level_str[8];
	int status;
	va_list varlist;
	if (msglevel > maxlevel) {
		return 0;
	}
	memset(level_str, 0, 8);
	switch (msglevel) {
		case MKSYS_LEVEL_CRITICAL:
			strcpy(level_str, "CRIT");
			break;
		case MKSYS_LEVEL_WARNING:
			strcpy(level_str, "WARN");
			break;
		default:
			strcpy(level_str, "INFO");
			break;
	}
	va_start(varlist, format);
	if (strcmp(logfile, MKSYS_NOLOGFILE) != 0) {
		char time_str[32];
		memset(time_str, 0, 32);
		gettime(time_str);
		FILE *logfd = fopen(logfile, "a");
		if (logfd != NULL) {
			if (noprefix == MKSYS_PREFIX_ON) {
				fprintf(logfd, "[%s] [%s] ", time_str, level_str);
			}
			char format_output[BUFSIZ];
			memset(format_output, 0, BUFSIZ);
			for (size_t recidx = 0; recidx < strlen(format); recidx++) {
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
	if (noprefix == MKSYS_PREFIX_OFF && !isatty(STDOUT_FILENO)) {
		status = 0;
	} else if (msglevel == MKSYS_LEVEL_CRITICAL) {
		if (noprefix == MKSYS_PREFIX_ON) {
			fprintf(stderr, "[%s] ", level_str);
		}
		status = vfprintf(stderr, format, varlist);
	} else {
		if (noprefix == MKSYS_PREFIX_ON) {
			fprintf(stdout, "[%s] ", level_str);
		}
		status = vfprintf(stdout, format, varlist);
	}
	va_end(varlist);
	if (status < 0) {
		return 1;
	} else {
		return 0;
	}
}
