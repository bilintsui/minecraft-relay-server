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

/* section: headers (project) */
#include "basic.h"

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

static int log_write(bool noprefix, const char *logfile, uint8_t maxlevel, mksys_level msglevel, mksys_line_end line_end, const char *message) {
	if (message == NULL) {
		message = "";
	}
	char level_str[8];
	int status = 0;
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
	if (strcmp(logfile, MKSYS_NOLOGFILE) != 0) {
		char time_str[32];
		gettime(time_str, sizeof(time_str));
		FILE *logfd = fopen(logfile, "a");
		if (logfd != NULL) {
			if (noprefix == MKSYS_PREFIX_ON) {
				fprintf(logfd, "[%s] [%s] ", time_str, level_str);
			}
			status = fprintf(logfd, "%s\n", message);
			fclose(logfd);
		}
	}
	if (noprefix == MKSYS_PREFIX_OFF && !isatty(STDOUT_FILENO)) {
		return 0;
	}
	if (msglevel == MKSYS_LEVEL_CRITICAL) {
		if (noprefix == MKSYS_PREFIX_ON) {
			fprintf(stderr, "[%s] ", level_str);
		}
		status = fprintf(stderr, line_end == MKSYS_PARAGRAPH_END ? "%s\n\n" : "%s\n", message);
	} else {
		if (noprefix == MKSYS_PREFIX_ON) {
			fprintf(stdout, "[%s] ", level_str);
		}
		status = fprintf(stdout, line_end == MKSYS_PARAGRAPH_END ? "%s\n\n" : "%s\n", message);
	}
	if (status < 0) {
		return 1;
	}
	return 0;
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

int mksysmsg(bool noprefix, const char *logfile, uint8_t maxlevel, mksys_level msglevel, mksys_line_end line_end, const char *format, ...) {
	char format_line[BUFSIZ];
	char rendered[BUFSIZ];
	char escaped[BUFSIZ * 4 + 1];
	va_list varlist;
	size_t format_length = 0;
	if (format == NULL) {
		format = "";
	}
	/* A newline in a format never reaches the output; the line end comes from line_end instead. */
	while (format_length + 1 < sizeof(format_line) && format[format_length] != '\0' && format[format_length] != '\n') {
		format_line[format_length] = format[format_length];
		format_length++;
	}
	format_line[format_length] = '\0';
	va_start(varlist, format);
	int rendered_length = vsnprintf(rendered, sizeof(rendered), format_line, varlist);
	va_end(varlist);
	if (rendered_length < 0) {
		rendered_length = 0;
	}
	size_t rendered_size = (size_t)rendered_length;
	if (rendered_size >= sizeof(rendered)) {
		rendered_size = sizeof(rendered) - 1;
	}
	return log_write(noprefix, logfile, maxlevel, msglevel, line_end, escape_default(escaped, sizeof(escaped), rendered, rendered_size));
}
