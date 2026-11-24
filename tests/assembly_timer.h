/*
 * assembly_timer.h: Test-only initial-assembly timer observations
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

#ifndef _MRS_TESTS_ASSEMBLY_TIMER_H_INCLUDED_

#define _MRS_TESTS_ASSEMBLY_TIMER_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

/* section: defines */
#define ASSEMBLY_TIMER_CHANNEL_ENV "MCRELAY_TEST_ASSEMBLY_CHANNEL"
#define ASSEMBLY_TIMER_FAULT_ENV "MCRELAY_TEST_ASSEMBLY_FAULT"
#define ASSEMBLY_TIMER_LOG_ENV "MCRELAY_TEST_ASSEMBLY_LOG"

#define ASSEMBLY_TIMER_LOG_DELAY_MS 3000
#define ASSEMBLY_TIMER_MAGIC 0x41534D42U
#define ASSEMBLY_TIMER_TIMEOUT_SEC 10

/* section: types */
typedef enum {
	ASSEMBLY_TIMER_ARMED,
	ASSEMBLY_TIMER_EXPIRED,
	ASSEMBLY_TIMER_CLOSED,
	ASSEMBLY_TIMER_CLOSE_SUPPRESSED,
	ASSEMBLY_TIMER_LOG_BEGIN,
	ASSEMBLY_TIMER_LOG_END
} assembly_timer_event_kind;

typedef enum {
	ASSEMBLY_TIMER_NORMAL,
	ASSEMBLY_TIMER_RELATIVE,
	ASSEMBLY_TIMER_SLIDING,
	ASSEMBLY_TIMER_DROP_CLOSE,
	ASSEMBLY_TIMER_WRONG_INITIAL,
	ASSEMBLY_TIMER_LOG_DELAY
} assembly_timer_fault;

typedef enum {
	ASSEMBLY_TIMER_CHANNEL_FAILURE = 99
} assembly_timer_exit_code;

typedef struct {
	uint32_t magic;
	assembly_timer_event_kind kind;
	pid_t pid;
	int fd, socket_fd, flags, result, error, clock_id;
	bool initial_clock_valid;
	uint64_t input_bytes, expirations;
	struct timespec initial_clock, observed_at;
	struct itimerspec setting;
} assembly_timer_event;

/* section: functions (exported) */
int __real_accept4(int socket_fd, struct sockaddr *address, socklen_t *address_size, int flags);
int __real_clock_gettime(clockid_t clock_id, struct timespec *value);
int __real_close(int fd);
int __real_fclose(FILE *stream);
ssize_t __real_read(int fd, void *buffer, size_t size);
ssize_t __real_recv(int fd, void *buffer, size_t size, int flags);
int __real_timerfd_create(int clock_id, int flags);
int __real_timerfd_settime(int fd, int flags, const struct itimerspec *value, struct itimerspec *old_value);

#endif
