/*
 * metrics.h: Shared bounded metrics primitives
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

#ifndef _MRS_METRICS_H_INCLUDED_

#define _MRS_METRICS_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* section: defines */
#define METRICS_DURATION_BUCKET_COUNT	14
#define METRICS_HISTOGRAM_BUCKET_COUNT	METRICS_DURATION_BUCKET_COUNT
#define METRICS_SIZE_BUCKET_COUNT	10
#define METRICS_TTL_BUCKET_COUNT	13

/* section: types */
typedef struct {
	uint64_t buckets[METRICS_HISTOGRAM_BUCKET_COUNT];
	uint64_t count;
	uint64_t sample_errors;
	uint64_t sum;
} metrics_histogram;
typedef struct {
	uint64_t cumulative[METRICS_HISTOGRAM_BUCKET_COUNT];
	uint64_t count;
	uint64_t sample_errors;
	uint64_t sum;
} metrics_histogram_snapshot;

/* section: functions (exported) */
bool metrics_counter_add(uint64_t *counter, uint64_t amount, uint64_t *saturation_total);
void metrics_duration_histogram_get(const metrics_histogram *histogram, metrics_histogram_snapshot *result);
bool metrics_duration_histogram_observe(metrics_histogram *histogram, const struct timespec *start, const struct timespec *end, uint64_t *saturation_total);
void metrics_high_water_update(uint64_t *high_water, uint64_t current);
void metrics_size_histogram_get(const metrics_histogram *histogram, metrics_histogram_snapshot *result);
void metrics_size_histogram_observe(metrics_histogram *histogram, uint64_t bytes, uint64_t *saturation_total);
void metrics_ttl_histogram_get(const metrics_histogram *histogram, metrics_histogram_snapshot *result);
void metrics_ttl_histogram_observe(metrics_histogram *histogram, uint64_t seconds, uint64_t *saturation_total);

#endif
