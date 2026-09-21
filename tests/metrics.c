/*
 * metrics.c: Tests for shared bounded metrics primitives
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* section: headers (project) */
#include "metrics.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s\n", message); \
			return false; \
		} \
	} while (0)

/* section: global variables */
static const uint64_t duration_bounds[] = {
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
static const uint64_t size_bounds[] = {
	UINT64_C(0), UINT64_C(64), UINT64_C(256), UINT64_C(1024), UINT64_C(4096), UINT64_C(16384), UINT64_C(65536), UINT64_C(262144), UINT64_C(1048576)
};
static const uint64_t ttl_bounds[] = {
	UINT64_C(0), UINT64_C(1), UINT64_C(5), UINT64_C(30), UINT64_C(60), UINT64_C(300), UINT64_C(1800), UINT64_C(3600), UINT64_C(21600), UINT64_C(86400),
	UINT64_C(604800), UINT64_C(2592000)
};

/* section: functions (local) */
static size_t expected_bucket(const uint64_t *bounds, size_t bound_count, uint64_t sample) {
	size_t bucket = 0;
	while (bucket < bound_count && sample > bounds[bucket]) {
		bucket++;
	}
	return bucket;
}

static bool histogram_has_only_bucket(const metrics_histogram *histogram, size_t bucket, size_t bucket_count) {
	for (size_t index = 0; index < bucket_count; index++) {
		if (histogram->buckets[index] != (index == bucket ? 1U : 0U)) {
			return false;
		}
	}
	return histogram->count == 1;
}

static bool metrics_test_counter(void) {
	uint64_t counter = 1;
	uint64_t saturation = 0;
	CHECK(metrics_counter_add(&counter, 2, &saturation), "ordinary counter addition saturated");
	CHECK(counter == 3 && saturation == 0, "ordinary counter addition was incorrect");
	counter = UINT64_MAX - 1U;
	CHECK(metrics_counter_add(&counter, 1, &saturation), "exact counter maximum was treated as saturation");
	CHECK(counter == UINT64_MAX && saturation == 0, "exact counter maximum was incorrect");
	CHECK(metrics_counter_add(&counter, 0, &saturation), "zero addition at maximum saturated");
	CHECK(!metrics_counter_add(&counter, 1, &saturation), "counter overflow was accepted");
	CHECK(counter == UINT64_MAX && saturation == 1, "counter overflow did not saturate and record loss");
	counter = UINT64_MAX - 1U;
	CHECK(!metrics_counter_add(&counter, 2, &saturation), "multi-unit counter overflow was accepted");
	CHECK(counter == UINT64_MAX && saturation == 2, "multi-unit counter overflow was incorrect");
	saturation = UINT64_MAX;
	CHECK(!metrics_counter_add(&counter, 1, &saturation), "saturated counter accepted another increment");
	CHECK(counter == UINT64_MAX && saturation == UINT64_MAX, "saturation counter wrapped");
	return true;
}

static bool metrics_test_duration(void) {
	for (size_t index = 0; index < sizeof(duration_bounds) / sizeof(duration_bounds[0]); index++) {
		uint64_t samples[] = { duration_bounds[index] - 1U, duration_bounds[index], duration_bounds[index] + 1U };
		for (size_t sample_index = 0; sample_index < sizeof(samples) / sizeof(samples[0]); sample_index++) {
			metrics_histogram histogram = { 0 };
			uint64_t saturation = 0;
			struct timespec start = { .tv_sec = 0, .tv_nsec = 0 };
			struct timespec end = { .tv_sec = (time_t)(samples[sample_index] / UINT64_C(1000000000)),
				.tv_nsec = (long)(samples[sample_index] % UINT64_C(1000000000)) };
			CHECK(metrics_duration_histogram_observe(&histogram, &start, &end, &saturation), "valid duration was rejected");
			CHECK(histogram_has_only_bucket(&histogram,
				expected_bucket(duration_bounds, sizeof(duration_bounds) / sizeof(duration_bounds[0]), samples[sample_index]), METRICS_DURATION_BUCKET_COUNT),
				"duration boundary selected the wrong bucket");
			CHECK(histogram.sum == samples[sample_index] / UINT64_C(1000) && saturation == 0, "duration sum was incorrect");
		}
	}
	metrics_histogram histogram = { 0 };
	uint64_t saturation = 0;
	const struct timespec borrowed_start = { .tv_sec = 1, .tv_nsec = 900000000 };
	const struct timespec borrowed_end = { .tv_sec = 2, .tv_nsec = 100001999 };
	CHECK(metrics_duration_histogram_observe(&histogram, &borrowed_start, &borrowed_end, &saturation), "borrowed duration was rejected");
	CHECK(histogram.buckets[6] == 1 && histogram.sum == 200001, "borrowed duration or microsecond floor was incorrect");
	const struct timespec inf_end = { .tv_sec = 31, .tv_nsec = 0 };
	CHECK(metrics_duration_histogram_observe(&histogram, &(struct timespec){ 0, 0 }, &inf_end, &saturation), "infinite-bucket duration was rejected");
	CHECK(histogram.buckets[METRICS_DURATION_BUCKET_COUNT - 1U] == 1, "duration infinity bucket was not selected");
	return true;
}

static bool metrics_test_duration_invalid(void) {
	metrics_histogram histogram = { 0 };
	uint64_t saturation = 0;
	const struct timespec valid = { .tv_sec = 1, .tv_nsec = 0 };
	const struct timespec reverse = { .tv_sec = 0, .tv_nsec = 999999999 };
	const struct timespec invalid = { .tv_sec = 1, .tv_nsec = 1000000000L };
	errno = EDOM;
	CHECK(!metrics_duration_histogram_observe(&histogram, NULL, &valid, &saturation), "NULL duration start was accepted");
	CHECK(!metrics_duration_histogram_observe(&histogram, &valid, NULL, &saturation), "NULL duration end was accepted");
	CHECK(!metrics_duration_histogram_observe(&histogram, &valid, &reverse, &saturation), "reversed duration was accepted");
	CHECK(!metrics_duration_histogram_observe(&histogram, &valid, &invalid, &saturation), "invalid timespec was accepted");
	uint64_t overflow_seconds = UINT64_MAX / UINT64_C(1000000000) + 1U;
	time_t converted = (time_t)overflow_seconds;
	if (converted >= 0 && (uintmax_t)converted == overflow_seconds) {
		struct timespec overflow = { .tv_sec = converted, .tv_nsec = 0 };
		CHECK(!metrics_duration_histogram_observe(&histogram, &(struct timespec){ 0, 0 }, &overflow, &saturation), "overflowing duration was accepted");
	}
	CHECK(histogram.count == 0 && histogram.sum == 0 && histogram.sample_errors >= 4, "invalid durations changed samples or missed errors");
	CHECK(saturation == 0 && errno == EDOM, "invalid duration changed saturation or errno");
	histogram.sample_errors = UINT64_MAX;
	CHECK(!metrics_duration_histogram_observe(&histogram, &valid, &reverse, &saturation), "reversed duration was accepted after error saturation");
	CHECK(histogram.sample_errors == UINT64_MAX && saturation == 1, "duration error saturation was not recorded");
	return true;
}

static bool metrics_test_high_water(void) {
	uint64_t high_water = 5;
	metrics_high_water_update(&high_water, 4);
	CHECK(high_water == 5, "high-water mark decreased");
	metrics_high_water_update(&high_water, 5);
	CHECK(high_water == 5, "equal high-water update changed value");
	metrics_high_water_update(&high_water, 6);
	CHECK(high_water == 6, "high-water mark did not increase");
	metrics_high_water_update(&high_water, UINT64_MAX);
	CHECK(high_water == UINT64_MAX, "high-water mark did not accept maximum");
	return true;
}

static bool metrics_test_saturation(void) {
	metrics_histogram histogram = { 0 };
	histogram.buckets[0] = UINT64_MAX;
	histogram.count = UINT64_MAX;
	histogram.sum = UINT64_MAX;
	uint64_t saturation = 0;
	metrics_ttl_histogram_observe(&histogram, 0, &saturation);
	CHECK(histogram.buckets[0] == UINT64_MAX && histogram.count == UINT64_MAX && histogram.sum == UINT64_MAX,
		"histogram fields wrapped after saturation");
	CHECK(saturation == 1, "one histogram update did not produce exactly one saturation event");
	histogram = (metrics_histogram){ 0 };
	histogram.sum = UINT64_MAX - 1U;
	metrics_size_histogram_observe(&histogram, 2, &saturation);
	CHECK(histogram.count == 1 && histogram.sum == UINT64_MAX && saturation == 2, "histogram sum saturation was incorrect");
	return true;
}

static bool metrics_test_size(void) {
	for (size_t index = 0; index < sizeof(size_bounds) / sizeof(size_bounds[0]); index++) {
		uint64_t samples[3];
		size_t sample_count = 0;
		if (size_bounds[index] > 0) {
			samples[sample_count++] = size_bounds[index] - 1U;
		}
		samples[sample_count++] = size_bounds[index];
		samples[sample_count++] = size_bounds[index] + 1U;
		for (size_t sample_index = 0; sample_index < sample_count; sample_index++) {
			metrics_histogram histogram = { 0 };
			uint64_t saturation = 0;
			metrics_size_histogram_observe(&histogram, samples[sample_index], &saturation);
			CHECK(histogram_has_only_bucket(&histogram, expected_bucket(size_bounds, sizeof(size_bounds) / sizeof(size_bounds[0]), samples[sample_index]),
				METRICS_SIZE_BUCKET_COUNT), "size boundary selected the wrong bucket");
			CHECK(histogram.sum == samples[sample_index] && saturation == 0, "size histogram sum was incorrect");
		}
	}
	metrics_histogram histogram = { 0 };
	uint64_t saturation = 0;
	metrics_size_histogram_observe(&histogram, UINT64_MAX, &saturation);
	CHECK(histogram.buckets[METRICS_SIZE_BUCKET_COUNT - 1U] == 1 && histogram.sum == UINT64_MAX, "size infinity bucket was incorrect");
	return true;
}

static bool metrics_test_snapshot(void) {
	metrics_histogram histogram = { .buckets = { 1, 2, 3 }, .count = 10, .sample_errors = 4, .sum = 20 };
	metrics_histogram original = histogram;
	metrics_histogram_snapshot snapshot;
	metrics_duration_histogram_get(&histogram, &snapshot);
	CHECK(snapshot.cumulative[0] == 1 && snapshot.cumulative[1] == 3 && snapshot.cumulative[2] == 6, "duration cumulative buckets were incorrect");
	CHECK(snapshot.cumulative[METRICS_DURATION_BUCKET_COUNT - 1U] == 10 && snapshot.count == 10 && snapshot.sample_errors == 4 && snapshot.sum == 20,
		"duration histogram totals were incorrect");
	CHECK(memcmp(&histogram, &original, sizeof(histogram)) == 0, "histogram snapshot changed its source");
	histogram = (metrics_histogram){ .buckets = { UINT64_MAX, 1 }, .count = UINT64_MAX, .sum = UINT64_MAX };
	metrics_size_histogram_get(&histogram, &snapshot);
	CHECK(snapshot.cumulative[0] == UINT64_MAX && snapshot.cumulative[1] == UINT64_MAX, "cumulative snapshot wrapped");
	CHECK(snapshot.cumulative[METRICS_SIZE_BUCKET_COUNT - 1U] == UINT64_MAX && snapshot.cumulative[METRICS_SIZE_BUCKET_COUNT] == 0,
		"size snapshot bounds were incorrect");
	metrics_ttl_histogram_get(&histogram, &snapshot);
	CHECK(snapshot.cumulative[METRICS_TTL_BUCKET_COUNT - 1U] == UINT64_MAX && snapshot.cumulative[METRICS_TTL_BUCKET_COUNT] == 0,
		"TTL snapshot bounds were incorrect");
	return true;
}

static bool metrics_test_ttl(void) {
	for (size_t index = 0; index < sizeof(ttl_bounds) / sizeof(ttl_bounds[0]); index++) {
		uint64_t samples[3];
		size_t sample_count = 0;
		if (ttl_bounds[index] > 0) {
			samples[sample_count++] = ttl_bounds[index] - 1U;
		}
		samples[sample_count++] = ttl_bounds[index];
		samples[sample_count++] = ttl_bounds[index] + 1U;
		for (size_t sample_index = 0; sample_index < sample_count; sample_index++) {
			metrics_histogram histogram = { 0 };
			uint64_t saturation = 0;
			metrics_ttl_histogram_observe(&histogram, samples[sample_index], &saturation);
			CHECK(histogram_has_only_bucket(&histogram, expected_bucket(ttl_bounds, sizeof(ttl_bounds) / sizeof(ttl_bounds[0]), samples[sample_index]),
				METRICS_TTL_BUCKET_COUNT), "TTL boundary selected the wrong bucket");
			CHECK(histogram.sum == samples[sample_index] && saturation == 0, "TTL histogram sum was incorrect");
		}
	}
	metrics_histogram histogram = { 0 };
	uint64_t saturation = 0;
	metrics_ttl_histogram_observe(&histogram, UINT64_MAX, &saturation);
	CHECK(histogram.buckets[METRICS_TTL_BUCKET_COUNT - 1U] == 1 && histogram.sum == UINT64_MAX, "TTL infinity bucket was incorrect");
	return true;
}

/* section: functions (entry point) */
int main(void) {
	return metrics_test_counter() && metrics_test_duration() && metrics_test_duration_invalid() && metrics_test_high_water() && metrics_test_saturation()
		&& metrics_test_size() && metrics_test_snapshot() && metrics_test_ttl() ? 0 : 1;
}
