/* Full owner snapshot collection plus the unchanged production 48-line emitter. */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

/* section: functions (entry point) */
int main(int argc, char **argv) {
	if (argc != 5) {
		fprintf(stderr, "usage: snapshot_cost LOG CSV ITERATIONS CACHE_ENTRIES\n");
		return 2;
	}
	size_t iterations = (size_t)strtoul(argv[3], NULL, 10);
	size_t entries = (size_t)strtoul(argv[4], NULL, 10);
	if (iterations < 1 || iterations > 100000 || entries > 4096) {
		return 2;
	}
	uint64_t *cpu = calloc(iterations, sizeof(*cpu));
	uint64_t *wall = calloc(iterations, sizeof(*wall));
	resolver_cache *cache = resolver_cache_create();
	sigset_t mask;
	sigemptyset(&mask);
	struct timespec now;
	if (cpu == NULL || wall == NULL || cache == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		return 2;
	}
	resolver_supervisor *supervisor = resolver_supervisor_create(&mask, &now);
	if (supervisor == NULL) {
		return 2;
	}
	for (size_t index = 0; index < entries; index++) {
		char name[64];
		snprintf(name, sizeof(name), "entry-%zu.benchmark.invalid", index);
		resolver_cache_entry *entry;
		if (resolver_cache_entry_acquire(cache, name, ns_t_a, &entry) != RESOLVER_CACHE_ACQUIRE_OK) {
			return 2;
		}
	}
	listener_metrics_state listener = { 0 };
	listener_metrics_limits_set(&listener, 4096, 256);
	listener_metrics_runtime runtime;
	if (!listener_metrics_runtime_init(&runtime, getpid(), &now)) {
		return 2;
	}
	for (size_t index = 0; index < iterations + 10; index++) {
		uint64_t cpu_start = nanoseconds(CLOCK_PROCESS_CPUTIME_ID);
		uint64_t wall_start = nanoseconds(CLOCK_MONOTONIC);
		listener_metrics_aggregate_snapshot snapshot;
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || !listener_metrics_snapshot_get(&listener, &snapshot.listener)
			|| !resolver_cache_metrics_get(cache, &snapshot.cache) || !resolver_supervisor_metrics_assembly_get(supervisor, &snapshot.assembly)
			|| !resolver_supervisor_metrics_get(supervisor, &snapshot.supervisor)) {
			return 2;
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
		return 1;
	}
	FILE *output = fopen(argv[2], "w");
	if (output == NULL) {
		return 2;
	}
	fputs("sample,cpu_ns,wall_ns\n", output);
	for (size_t index = 0; index < iterations; index++) {
		fprintf(output, "%zu,%" PRIu64 ",%" PRIu64 "\n", index, cpu[index], wall[index]);
	}
	int status = fclose(output) == 0 ? 0 : 2;
	resolver_supervisor_destroy(supervisor);
	resolver_cache_destroy(cache);
	free(cpu);
	free(wall);
	return status;
}
