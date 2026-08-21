/*
 * timeutil.c: Tests for shared timespec utilities
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

/* section: headers (project) */
#include "timeutil.h"

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
static bool timeutil_test_add_milliseconds(void) {
	struct timespec result = { .tv_sec = 0, .tv_nsec = 0 };
	struct timespec source = { .tv_sec = 10, .tv_nsec = 999500000 };
	CHECK(timeutil_add_milliseconds(&source, UINT64_C(1), &result), "millisecond addition failed");
	CHECK(result.tv_sec == 11 && result.tv_nsec == 500000, "millisecond carry was incorrect");
	CHECK(timeutil_add_milliseconds(&result, UINT64_C(500), &result), "in-place millisecond addition failed");
	CHECK(result.tv_sec == 11 && result.tv_nsec == 500500000, "in-place millisecond addition was incorrect");
	CHECK(!timeutil_add_milliseconds(NULL, 1, &result), "NULL millisecond source was accepted");
	CHECK(!timeutil_add_milliseconds(&source, 1, NULL), "NULL millisecond result was accepted");
	time_t maximum = (time_t)(UINTMAX_MAX / UINTMAX_C(2));
	if ((time_t)-1 < 0 && maximum > 0) {
		CHECK(!timeutil_add_milliseconds(&(struct timespec){ maximum, 999999999 }, 1, &result), "overflowing milliseconds were accepted");
	}
	return true;
}

static bool timeutil_test_add_seconds(void) {
	struct timespec result = { .tv_sec = 0, .tv_nsec = 0 };
	struct timespec source = { .tv_sec = 10, .tv_nsec = 20 };
	CHECK(timeutil_add_seconds(&source, UINT64_C(5), &result), "second addition failed");
	CHECK(result.tv_sec == 15 && result.tv_nsec == 20, "second addition was incorrect");
	CHECK(timeutil_add_seconds(&result, UINT64_C(5), &result), "in-place second addition failed");
	CHECK(result.tv_sec == 20 && result.tv_nsec == 20, "in-place second addition was incorrect");
	CHECK(!timeutil_add_seconds(&(struct timespec){ -1, 0 }, 1, &result), "negative second source was accepted");
	CHECK(!timeutil_add_seconds(&source, 1, NULL), "NULL second result was accepted");
	time_t maximum = (time_t)(UINTMAX_MAX / UINTMAX_C(2));
	if ((time_t)-1 < 0 && maximum > 0) {
		CHECK(!timeutil_add_seconds(&(struct timespec){ maximum, 0 }, 1, &result), "overflowing seconds were accepted");
	}
	return true;
}

static bool timeutil_test_compare(void) {
	const struct timespec equal_left = { .tv_sec = 1, .tv_nsec = 2 };
	const struct timespec equal_right = { .tv_sec = 1, .tv_nsec = 2 };
	const struct timespec lower_seconds = { .tv_sec = 0, .tv_nsec = 999999999 };
	const struct timespec higher_seconds = { .tv_sec = 1, .tv_nsec = 0 };
	const struct timespec lower_nanoseconds = { .tv_sec = 1, .tv_nsec = 1 };
	const struct timespec higher_nanoseconds = { .tv_sec = 1, .tv_nsec = 2 };
	CHECK(timeutil_compare(&equal_left, &equal_right) == 0, "equal timespecs did not compare equal");
	CHECK(timeutil_compare(&lower_seconds, &higher_seconds) < 0, "lower seconds did not compare lower");
	CHECK(timeutil_compare(&higher_seconds, &lower_seconds) > 0, "higher seconds did not compare higher");
	CHECK(timeutil_compare(&lower_nanoseconds, &higher_nanoseconds) < 0, "lower nanoseconds did not compare lower");
	CHECK(timeutil_compare(&higher_nanoseconds, &lower_nanoseconds) > 0, "higher nanoseconds did not compare higher");
	return true;
}

static bool timeutil_test_valid(void) {
	const struct timespec valid = { .tv_sec = 0, .tv_nsec = 999999999 };
	const struct timespec negative_seconds = { .tv_sec = -1, .tv_nsec = 0 };
	const struct timespec negative_nanoseconds = { .tv_sec = 0, .tv_nsec = -1 };
	const struct timespec excessive_nanoseconds = { .tv_sec = 0, .tv_nsec = 1000000000L };
	CHECK(timeutil_valid(&valid), "valid timespec was rejected");
	CHECK(!timeutil_valid(NULL), "NULL timespec was accepted");
	CHECK(!timeutil_valid(&negative_seconds), "negative seconds were accepted");
	CHECK(!timeutil_valid(&negative_nanoseconds), "negative nanoseconds were accepted");
	CHECK(!timeutil_valid(&excessive_nanoseconds), "excessive nanoseconds were accepted");
	return true;
}

/* section: functions (entry point) */
int main(void) {
	return timeutil_test_add_milliseconds() && timeutil_test_add_seconds() && timeutil_test_compare() && timeutil_test_valid() ? 0 : 1;
}
