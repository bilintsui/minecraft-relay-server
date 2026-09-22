/*
 * hosts_reload_fault.c: Deterministic local-hosts monitor recovery race for listener runtime tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

/* section: headers (project) */
#include "resolver/hosts.h"

/* section: global variables */
static bool hosts_reload_fault_init_failed;
static size_t hosts_reload_fault_load_count;

/* section: functions (local) */
static void hosts_reload_fault_write(const char *filename) {
	const char content[] = "127.0.0.1 localhost\n127.0.0.2 hosts-reload.test\n";
	int fd = open(filename, O_WRONLY | O_TRUNC | O_CLOEXEC);
	if (fd == -1 || write(fd, content, sizeof(content) - 1U) != (ssize_t)(sizeof(content) - 1U) || close(fd) == -1) {
		_exit(EXIT_FAILURE);
	}
}

/* section: functions (exported) */
hosts_load_status __real_hosts_table_load(const char *filename, hosts_table **result, size_t *malformed_line_count);
int __real_inotify_init1(int flags);

hosts_load_status __wrap_hosts_table_load(const char *filename, hosts_table **result, size_t *malformed_line_count) {
	hosts_load_status status = __real_hosts_table_load(filename, result, malformed_line_count);
	if (getenv("MCRELAY_TEST_HOSTS_RECOVERY") != NULL && ++hosts_reload_fault_load_count == 2U && status == HOSTS_LOAD_OK) {
		/* The reload has read A; write B before it publishes, while a recovered watch must already be armed. */
		hosts_reload_fault_write(filename);
	}
	return status;
}

int __wrap_inotify_init1(int flags) {
	if (getenv("MCRELAY_TEST_HOSTS_RECOVERY") != NULL && !hosts_reload_fault_init_failed) {
		hosts_reload_fault_init_failed = true;
		errno = EMFILE;
		return -1;
	}
	return __real_inotify_init1(flags);
}
