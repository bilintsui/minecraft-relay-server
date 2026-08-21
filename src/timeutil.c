/*
 * timeutil.c: Shared timespec utilities
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* section: headers (self) */
#include "timeutil.h"

/* section: functions (exported) */
bool timeutil_add_milliseconds(const struct timespec *source, uint64_t milliseconds, struct timespec *result) {
	if (!timeutil_valid(source) || result == NULL) {
		return false;
	}
	uintmax_t added_seconds = milliseconds / UINT64_C(1000);
	uintmax_t added_nanoseconds = (milliseconds % UINT64_C(1000)) * UINT64_C(1000000) + (uintmax_t)source->tv_nsec;
	added_seconds += added_nanoseconds / UINT64_C(1000000000);
	added_nanoseconds %= UINT64_C(1000000000);
	if ((uintmax_t)source->tv_sec > UINTMAX_MAX - added_seconds) {
		return false;
	}
	uintmax_t combined = (uintmax_t)source->tv_sec + added_seconds;
	time_t converted = (time_t)combined;
	if (converted < 0 || (uintmax_t)converted != combined) {
		return false;
	}
	result->tv_sec = converted;
	result->tv_nsec = (long)added_nanoseconds;
	return true;
}

bool timeutil_add_seconds(const struct timespec *source, uint64_t seconds, struct timespec *result) {
	if (!timeutil_valid(source) || result == NULL || (uintmax_t)source->tv_sec > UINTMAX_MAX - seconds) {
		return false;
	}
	uintmax_t combined = (uintmax_t)source->tv_sec + seconds;
	time_t converted = (time_t)combined;
	if (converted < 0 || (uintmax_t)converted != combined) {
		return false;
	}
	result->tv_sec = converted;
	result->tv_nsec = source->tv_nsec;
	return true;
}

int timeutil_compare(const struct timespec *left, const struct timespec *right) {
	if (left->tv_sec != right->tv_sec) {
		return left->tv_sec < right->tv_sec ? -1 : 1;
	}
	if (left->tv_nsec != right->tv_nsec) {
		return left->tv_nsec < right->tv_nsec ? -1 : 1;
	}
	return 0;
}

bool timeutil_valid(const struct timespec *value) {
	return value != NULL && value->tv_sec >= 0 && value->tv_nsec >= 0 && value->tv_nsec < 1000000000L;
}
