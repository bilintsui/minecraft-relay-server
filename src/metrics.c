/*
 * metrics.c: Shared bounded metrics primitives
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "timeutil.h"

/* section: headers (self) */
#include "metrics.h"

/* section: global variables */
static const uint64_t metrics_duration_bounds[] = {
	UINT64_C(1) * UINT64_C(1000000),
	UINT64_C(5) * UINT64_C(1000000),
	UINT64_C(10) * UINT64_C(1000000),
	UINT64_C(25) * UINT64_C(1000000),
	UINT64_C(50) * UINT64_C(1000000),
	UINT64_C(100) * UINT64_C(1000000),
	UINT64_C(250) * UINT64_C(1000000),
	UINT64_C(500) * UINT64_C(1000000),
	UINT64_C(1000) * UINT64_C(1000000),
	UINT64_C(2000) * UINT64_C(1000000),
	UINT64_C(5000) * UINT64_C(1000000),
	UINT64_C(10000) * UINT64_C(1000000),
	UINT64_C(30000) * UINT64_C(1000000)
};
static const uint64_t metrics_size_bounds[] = {
	UINT64_C(0), UINT64_C(64), UINT64_C(256), UINT64_C(1024), UINT64_C(4096), UINT64_C(16384), UINT64_C(65536), UINT64_C(262144), UINT64_C(1048576)
};
static const uint64_t metrics_ttl_bounds[] = {
	UINT64_C(0), UINT64_C(1), UINT64_C(5), UINT64_C(30), UINT64_C(60), UINT64_C(300), UINT64_C(1800), UINT64_C(3600), UINT64_C(21600), UINT64_C(86400),
	UINT64_C(604800), UINT64_C(2592000)
};

/* section: functions (local) */
static void metrics_histogram_get(const metrics_histogram *histogram, size_t bucket_count, metrics_histogram_snapshot *result) {
	memset(result, 0, sizeof(*result));
	uint64_t cumulative = 0;
	for (size_t index = 0; index + 1U < bucket_count; index++) {
		if (UINT64_MAX - cumulative < histogram->buckets[index]) {
			cumulative = UINT64_MAX;
		} else {
			cumulative += histogram->buckets[index];
		}
		result->cumulative[index] = cumulative;
	}
	result->cumulative[bucket_count - 1U] = histogram->count;
	result->count = histogram->count;
	result->sample_errors = histogram->sample_errors;
	result->sum = histogram->sum;
}

static void metrics_saturation_record(uint64_t *saturation_total) {
	if (*saturation_total < UINT64_MAX) {
		(*saturation_total)++;
	}
}

static bool metrics_value_add(uint64_t *value, uint64_t amount) {
	if (UINT64_MAX - *value < amount) {
		*value = UINT64_MAX;
		return false;
	}
	*value += amount;
	return true;
}

static void metrics_histogram_observe(metrics_histogram *histogram, const uint64_t *bounds, size_t bound_count, uint64_t bucket_sample, uint64_t sum_sample, uint64_t *saturation_total) {
	size_t bucket = 0;
	while (bucket < bound_count && bucket_sample > bounds[bucket]) {
		bucket++;
	}
	bool exact = metrics_value_add(&histogram->buckets[bucket], 1);
	exact = metrics_value_add(&histogram->count, 1) && exact;
	exact = metrics_value_add(&histogram->sum, sum_sample) && exact;
	if (!exact) {
		metrics_saturation_record(saturation_total);
	}
}

static bool metrics_timespec_subtract(const struct timespec *start, const struct timespec *end, uint64_t *nanoseconds) {
	if (!timeutil_valid(start) || !timeutil_valid(end) || timeutil_compare(end, start) < 0) {
		return false;
	}
	uintmax_t seconds = (uintmax_t)end->tv_sec - (uintmax_t)start->tv_sec;
	uintmax_t remainder;
	if (end->tv_nsec < start->tv_nsec) {
		seconds--;
		remainder = UINTMAX_C(1000000000) + (uintmax_t)end->tv_nsec - (uintmax_t)start->tv_nsec;
	} else {
		remainder = (uintmax_t)end->tv_nsec - (uintmax_t)start->tv_nsec;
	}
	if (seconds > (UINT64_MAX - remainder) / UINT64_C(1000000000)) {
		return false;
	}
	*nanoseconds = (uint64_t)(seconds * UINTMAX_C(1000000000) + remainder);
	return true;
}

/* section: functions (exported) */
bool metrics_counter_add(uint64_t *counter, uint64_t amount, uint64_t *saturation_total) {
	if (metrics_value_add(counter, amount)) {
		return true;
	}
	metrics_saturation_record(saturation_total);
	return false;
}

void metrics_duration_histogram_get(const metrics_histogram *histogram, metrics_histogram_snapshot *result) {
	metrics_histogram_get(histogram, METRICS_DURATION_BUCKET_COUNT, result);
}

bool metrics_duration_histogram_observe(metrics_histogram *histogram, const struct timespec *start, const struct timespec *end, uint64_t *saturation_total) {
	uint64_t nanoseconds;
	if (!metrics_timespec_subtract(start, end, &nanoseconds)) {
		if (!metrics_value_add(&histogram->sample_errors, 1)) {
			metrics_saturation_record(saturation_total);
		}
		return false;
	}
	metrics_histogram_observe(histogram, metrics_duration_bounds, sizeof(metrics_duration_bounds) / sizeof(metrics_duration_bounds[0]), nanoseconds, nanoseconds / UINT64_C(1000), saturation_total);
	return true;
}

void metrics_high_water_update(uint64_t *high_water, uint64_t current) {
	if (current > *high_water) {
		*high_water = current;
	}
}

void metrics_size_histogram_get(const metrics_histogram *histogram, metrics_histogram_snapshot *result) {
	metrics_histogram_get(histogram, METRICS_SIZE_BUCKET_COUNT, result);
}

void metrics_size_histogram_observe(metrics_histogram *histogram, uint64_t bytes, uint64_t *saturation_total) {
	metrics_histogram_observe(histogram, metrics_size_bounds, sizeof(metrics_size_bounds) / sizeof(metrics_size_bounds[0]), bytes, bytes, saturation_total);
}

void metrics_ttl_histogram_get(const metrics_histogram *histogram, metrics_histogram_snapshot *result) {
	metrics_histogram_get(histogram, METRICS_TTL_BUCKET_COUNT, result);
}

void metrics_ttl_histogram_observe(metrics_histogram *histogram, uint64_t seconds, uint64_t *saturation_total) {
	metrics_histogram_observe(histogram, metrics_ttl_bounds, sizeof(metrics_ttl_bounds) / sizeof(metrics_ttl_bounds[0]), seconds, seconds, saturation_total);
}
