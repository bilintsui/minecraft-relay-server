/*
 * log.c: Functions for logging
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
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
static void gettime(char *target, size_t target_size) {
	time_t timestamp = time(NULL);
	struct tm tm_local;
	target[0] = '\0';
	if (localtime_r(&timestamp, &tm_local) == NULL) {
		return;
	}
	size_t target_length = strftime(target, target_size, "%Y-%m-%d %H:%M:%S UTC%z", &tm_local);
	if (target_length < 5 || target_length + 1 >= target_size || (target[target_length - 5] != '+' && target[target_length - 5] != '-')) {
		target[0] = '\0';
		return;
	}
	/* strftime formats %z as +hhmm; insert the colon used by the log format. */
	memmove(target + target_length - 1, target + target_length - 2, 3);
	target[target_length - 2] = ':';
}

/* section: functions (exported) */
int log_file_validate(const char *filename) {
	bool created = false;
	int fd = open(filename, O_WRONLY | O_APPEND);
	if (fd == -1 && errno == ENOENT) {
		fd = open(filename, O_WRONLY | O_APPEND | O_CREAT | O_EXCL, 0666);
		if (fd != -1) {
			created = true;
		} else if (errno == EEXIST) {
			fd = open(filename, O_WRONLY | O_APPEND);
		}
	}
	if (fd == -1) {
		return -1;
	}
	if (created && unlink(filename) == -1) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	return close(fd);
}

int mksysmsg(bool noprefix, const char *logfile, uint8_t maxlevel, mksys_level msglevel, const char *format, ...) {
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
		gettime(time_str, sizeof(time_str));
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
