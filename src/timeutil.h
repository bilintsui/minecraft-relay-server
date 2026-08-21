/*
 * timeutil.h: Header file of timeutil.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_TIMEUTIL_H_INCLUDED_

#define _MRS_TIMEUTIL_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* section: functions (exported) */
bool timeutil_add_milliseconds(const struct timespec *source, uint64_t milliseconds, struct timespec *result);
bool timeutil_add_seconds(const struct timespec *source, uint64_t seconds, struct timespec *result);
int timeutil_compare(const struct timespec *left, const struct timespec *right);
bool timeutil_valid(const struct timespec *value);

#endif
