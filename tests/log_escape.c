/*
 * log_escape.c: Tests for visible-ASCII log escaping
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* section: headers (project) */
#include "basic.h"
#include "log.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s\n", message); \
			return false; \
		} \
	} while (0)

/* section: functions (local) */
static bool escape_check(const char *source, const char *expected) {
	char buffer[64];
	return strcmp(escape_default(buffer, sizeof(buffer), source, strlen(source)), expected) == 0;
}

static bool log_escape_test_arguments(void) {
	char buffer[64];
	char small[8];
	CHECK(strcmp(escape_default(buffer, sizeof(buffer), NULL, 4), "") == 0, "NULL source was not turned into an empty string");
	CHECK(strcmp(escape_default(NULL, sizeof(buffer), "text", 4), "") == 0, "NULL destination was accepted");
	CHECK(strcmp(escape_default(small, 0, "text", 4), "") == 0, "zero-size destination was accepted");
	CHECK(strcmp(escape_default(small, sizeof(small), "aaaaaaaa\x01", 9), "aaaaaaa") == 0, "truncation did not stop at an escape boundary");
	/* The explicit length is authoritative: an embedded NUL inside the window is escaped, not treated as a terminator. */
	CHECK(strcmp(escape_default(buffer, sizeof(buffer), "a" "\x00" "b", 3), "a\\x00b") == 0, "embedded NUL inside the length window was not escaped");
	CHECK(strcmp(escape_default(buffer, sizeof(buffer), "abcdef", 3), "abc") == 0, "bytes beyond the length window were read");
	CHECK(strcmp(escape_default(buffer, sizeof(buffer), "abcdef", 0), "") == 0, "zero length did not produce an empty string");
	return true;
}

static bool log_escape_test_control_characters(void) {
	CHECK(escape_check("status.example", "status.example"), "plain text was modified");
	CHECK(escape_check("", ""), "empty text was modified");
	CHECK(escape_check("a\nb\rc\td", "a\\nb\\rc\\td"), "named control escapes were incorrect");
	CHECK(escape_check("a\\b", "a\\\\b"), "backslash was not escaped");
	CHECK(escape_check("a\x1b[31mb", "a\\x1b[31mb"), "escape character was not hex-escaped");
	CHECK(escape_check("a\x01\x7f", "a\\x01\\x7f"), "C0 and DEL were not hex-escaped");
	CHECK(escape_check("a\x80\x9f\xff", "a\\x80\\x9f\\xff"), "non-ASCII bytes were not hex-escaped");
	CHECK(escape_check("\xc3\xa4\xe4\xb8\xad", "\\xc3\\xa4\\xe4\\xb8\\xad"), "UTF-8 bytes were not hex-escaped");
	CHECK(escape_check("a~b", "a~b"), "upper visible ASCII bound was modified");
	return true;
}

static bool log_escape_test_message_line(void) {
	char filename[] = "/tmp/mcrelay-log-escape-XXXXXX";
	char content[512];
	size_t content_size = 0;
	size_t newline_count = 0;
	int fd = mkstemp(filename);
	if (fd == -1) {
		return false;
	}
	close(fd);
	mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "Binding on %s:%d...", "127.0.0.1", 25565);
	mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "Bind Successful.");
	mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_WARNING, MKSYS_LINE_END, "vhost: %s, status: reject", "evil\n[CRIT]");
	mksysmsg(MKSYS_PREFIX_ON, filename, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_PARAGRAPH_END, "For more information, see log file: %s", "/var/log");
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		remove(filename);
		return false;
	}
	content_size = fread(content, 1, sizeof(content) - 1, file);
	fclose(file);
	remove(filename);
	content[content_size] = '\0';
	for (size_t index = 0; index < content_size; index++) {
		newline_count += content[index] == '\n' ? 1 : 0;
	}
	CHECK(strstr(content, "Binding on 127.0.0.1:25565...\n") != NULL, "format line terminator was not a single real newline");
	CHECK(strstr(content, "Bind Successful.\n") != NULL && strstr(content, "Bind Successful.\n\n") == NULL, "message output produced a blank line in the log file");
	CHECK(strstr(content, "vhost: evil\\n[CRIT], status: reject\n") != NULL, "untrusted newline was not escaped in message output");
	CHECK(strstr(content, "For more information, see log file: /var/log\n") != NULL, "paragraph end did not produce a single file newline");
	CHECK(newline_count == 4, "message output did not produce exactly one newline per message");
	return true;
}

static bool log_escape_test_terminal_line(void) {
	char filename[] = "/tmp/mcrelay-log-terminal-XXXXXX";
	char content[256];
	size_t content_size = 0;
	size_t newline_count = 0;
	bool restored = true;
	int capture_fd = mkstemp(filename);
	int saved_stdout;
	FILE *file;
	if (capture_fd == -1) {
		return false;
	}
	fflush(stdout);
	saved_stdout = dup(STDOUT_FILENO);
	if (saved_stdout == -1 || dup2(capture_fd, STDOUT_FILENO) == -1) {
		if (saved_stdout != -1) {
			close(saved_stdout);
		}
		close(capture_fd);
		remove(filename);
		return false;
	}
	mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_LINE_END, "single line end");
	mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION, MKSYS_PARAGRAPH_END, "paragraph end");
	fflush(stdout);
	restored = dup2(saved_stdout, STDOUT_FILENO) != -1;
	close(saved_stdout);
	close(capture_fd);
	file = fopen(filename, "r");
	if (file == NULL) {
		remove(filename);
		return false;
	}
	content_size = fread(content, 1, sizeof(content) - 1, file);
	fclose(file);
	remove(filename);
	content[content_size] = '\0';
	CHECK(restored, "cannot restore the original standard output");
	for (size_t index = 0; index < content_size; index++) {
		newline_count += content[index] == '\n' ? 1 : 0;
	}
	CHECK(strstr(content, "[INFO] single line end\n") != NULL, "terminal line end did not append exactly one newline");
	CHECK(strstr(content, "[INFO] paragraph end\n\n") != NULL, "terminal paragraph end did not append two newlines");
	CHECK(newline_count == 3, "terminal output did not match the requested line endings");
	return true;
}

/* section: functions (entry point) */
int main(void) {
	return log_escape_test_arguments() && log_escape_test_control_characters() && log_escape_test_message_line() && log_escape_test_terminal_line() ? 0 : 1;
}
