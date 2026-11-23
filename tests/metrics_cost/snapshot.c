/* Full owner snapshot collection plus the unchanged production 48-line emitter. */

/* section: headers (library) */
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "listener_metrics.h"

/* section: functions (local) */
static uint64_t nanoseconds(clockid_t clock) {
	struct timespec now;
	if (clock_gettime(clock, &now) != 0) {
		exit(2);
	}
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static resolver_cache_publish_status publish(resolver_cache_entry *entry, const struct timespec *now) {
	dns_address_result result = { 0 };
	const char *name = resolver_cache_entry_name(entry);
	snprintf(result.canonical_name, sizeof(result.canonical_name), "%s", name);
	snprintf(result.question_name, sizeof(result.question_name), "%s", name);
	result.addresses = calloc(1, sizeof(*result.addresses));
	if (result.addresses == NULL) {
		return RESOLVER_CACHE_PUBLISH_MEMORY;
	}
	result.address_count = 1;
	result.addresses[0].address.family = AF_INET;
	result.addresses[0].address.addr.v4 = htonl(INADDR_LOOPBACK);
	result.addresses[0].effective_ttl = 3600;
	result.addresses[0].record_ttl = 3600;
	resolver_cache_publish_status status = resolver_cache_entry_publish_address(entry, DNS_ADDRESS_LOOKUP_OK, now, &result);
	dns_address_result_destroy(&result);
	return status;
}

/* section: functions (entry point) */
int main(int argc, char **argv) {
	if (argc < 5 || argc > 7) {
		fprintf(stderr, "usage: snapshot_cost LOG CSV ITERATIONS CACHE_ENTRIES [PUBLISHED_ENTRIES] [JOBS]\n");
		return 2;
	}
	size_t iterations = (size_t)strtoul(argv[3], NULL, 10);
	size_t entries = (size_t)strtoul(argv[4], NULL, 10);
	size_t requested_published = argc > 5 ? (size_t)strtoul(argv[5], NULL, 10) : 0;
	size_t jobs = argc > 6 ? (size_t)strtoul(argv[6], NULL, 10) : 0;
	if (iterations < 1 || iterations > 100000 || entries > RESOLVER_CACHE_ENTRY_LIMIT || requested_published > entries || jobs > RESOLVER_SUPERVISOR_JOB_LIMIT || jobs > entries - requested_published) {
		return 2;
	}
	if (jobs > 0 && (getenv("MCRELAY_BENCH_DNS_PORT") == NULL || getenv("LD_PRELOAD") == NULL)) {
		fprintf(stderr, "job fixtures require the test-only loopback DNS redirect\n");
		return 2;
	}
	int exit_status = 2;
	FILE *output = NULL;
	bool publish_limited = false;
	size_t published = 0;
	uint64_t *cpu = calloc(iterations, sizeof(*cpu));
	uint64_t *wall = calloc(iterations, sizeof(*wall));
	resolver_cache *cache = resolver_cache_create();
	resolver_cache_entry **owned_entries = calloc(entries == 0 ? 1 : entries, sizeof(*owned_entries));
	resolver_supervisor *supervisor = NULL;
	sigset_t mask;
	sigemptyset(&mask);
	struct timespec now;
	if (cpu == NULL || wall == NULL || cache == NULL || owned_entries == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		goto cleanup;
	}
	supervisor = resolver_supervisor_create(&mask, &now);
	if (supervisor == NULL) {
		goto cleanup;
	}
	for (size_t index = 0; index < entries; index++) {
		char name[64];
		snprintf(name, sizeof(name), "entry-%zu.benchmark.invalid", index);
		if (resolver_cache_entry_acquire(cache, name, ns_t_a, &owned_entries[index]) != RESOLVER_CACHE_ACQUIRE_OK) {
			goto cleanup;
		}
	}
	for (; published < requested_published; published++) {
		resolver_cache_publish_status status = publish(owned_entries[published], &now);
		if (status == RESOLVER_CACHE_PUBLISH_LIMIT) {
			publish_limited = true;
			break;
		}
		if (status != RESOLVER_CACHE_PUBLISH_STORED) {
			goto cleanup;
		}
	}
	for (size_t index = 0; index < jobs; index++) {
		if (resolver_supervisor_entry_schedule_interactive(supervisor, owned_entries[published + index], &now) != RESOLVER_SUPERVISOR_SCHEDULE_STARTED) {
			goto cleanup;
		}
	}
	listener_metrics_aggregate_snapshot snapshot;
	if (!resolver_cache_metrics_get(cache, &snapshot.cache) || !resolver_supervisor_metrics_get(supervisor, &snapshot.supervisor)) {
		goto cleanup;
	}
	size_t dispatched = jobs < RESOLVER_SUPERVISOR_HELPER_COUNT ? jobs : RESOLVER_SUPERVISOR_HELPER_COUNT;
	if (snapshot.cache.entries_current != entries || snapshot.supervisor.jobs_current != jobs
		|| snapshot.supervisor.attempt[METRICS_QUERY_TYPE_A].jobs_dispatched_current != dispatched
		|| snapshot.supervisor.queue_current[RESOLVER_SUPERVISOR_PRIORITY_INTERACTIVE] != jobs - dispatched) {
		goto cleanup;
	}
	fprintf(stderr,
		"{\"entries\":%zu,\"requested_published\":%zu,\"published\":%zu,\"publish_limited\":%s,\"cache_owned_bytes\":%" PRIu64 ",\"cache_byte_limit\":%u,"
		"\"entry_limit\":%u,\"jobs\":%zu,\"dispatched\":%zu,\"queued\":%zu,\"job_limit\":%u}\n",
		entries, requested_published, published, publish_limited ? "true" : "false", snapshot.cache.owned_bytes_current, (unsigned int)RESOLVER_CACHE_OWNED_BYTE_LIMIT,
		(unsigned int)RESOLVER_CACHE_ENTRY_LIMIT, jobs, dispatched, jobs - dispatched, (unsigned int)RESOLVER_SUPERVISOR_JOB_LIMIT
	);
	listener_metrics_state listener = { 0 };
	listener_metrics_limits_set(&listener, 4096, 256);
	listener_metrics_runtime runtime;
	if (!listener_metrics_runtime_init(&runtime, getpid(), &now)) {
		goto cleanup;
	}
	for (size_t index = 0; index < iterations + 10; index++) {
		uint64_t cpu_start = nanoseconds(CLOCK_PROCESS_CPUTIME_ID);
		uint64_t wall_start = nanoseconds(CLOCK_MONOTONIC);
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || !listener_metrics_snapshot_get(&listener, &snapshot.listener)
			|| !resolver_cache_metrics_get(cache, &snapshot.cache) || !resolver_supervisor_metrics_assembly_get(supervisor, &snapshot.assembly)
			|| !resolver_supervisor_metrics_get(supervisor, &snapshot.supervisor)) {
			goto cleanup;
		}
		listener_metrics_output(&runtime, LISTENER_METRICS_OUTPUT_PERIODIC, &snapshot, argv[1], 2, &now);
		uint64_t elapsed_wall = nanoseconds(CLOCK_MONOTONIC) - wall_start;
		uint64_t elapsed_cpu = nanoseconds(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
		if (index >= 10) {
			cpu[index - 10] = elapsed_cpu;
			wall[index - 10] = elapsed_wall;
		}
	}
	if (runtime.logger_errors != 0 || runtime.format_drops != 0 || runtime.sequence != iterations + 10) {
		exit_status = 1;
		goto cleanup;
	}
	output = fopen(argv[2], "w");
	if (output == NULL) {
		goto cleanup;
	}
	fputs("sample,cpu_ns,wall_ns\n", output);
	for (size_t index = 0; index < iterations; index++) {
		fprintf(output, "%zu,%" PRIu64 ",%" PRIu64 "\n", index, cpu[index], wall[index]);
	}
	exit_status = fclose(output) == 0 ? 0 : 2;
	output = NULL;

cleanup:
	if (output != NULL) {
		fclose(output);
	}
	resolver_supervisor_destroy(supervisor);
	if (owned_entries != NULL) {
		for (size_t index = 0; index < entries; index++) {
			resolver_cache_entry_release(owned_entries[index]);
		}
	}
	resolver_cache_destroy(cache);
	free(cpu);
	free(owned_entries);
	free(wall);
	return exit_status;
}
