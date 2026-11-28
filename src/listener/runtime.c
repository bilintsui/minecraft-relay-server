/*
 * listener/runtime.c: Listener startup, event loop and shutdown
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <systemd/sd-daemon.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "../config.h"
#include "../define/exitcode.h"
#include "../log.h"
#include "../network.h"
#include "../resolver/cache.h"
#include "../resolver/supervisor.h"
#include "../route/generation_registry.h"
#include "../route/resolution.h"
#include "../route/table.h"
#include "../route/waiter.h"
#include "../timeutil.h"
#include "../version_info.h"
#include "admission.h"
#include "connection.h"
#include "context.h"
#include "dispatch.h"
#include "events.h"
#include "generation.h"
#include "metrics.h"
#include "metrics_runtime.h"
#include "reload.h"
#if defined(LISTENER_EARLY_COLLECT_TEST) || defined(LISTENER_READY_FLIP_TEST) || defined(LISTENER_ROUTE_TIMER_ARMED_TEST)
#include "runtime_hooks.h"
#endif
#include "socket.h"
#include "workers.h"

/* section: headers (self) */
#include "runtime.h"

/* section: defines */
/* listener */
#ifndef LISTENER_ROUTE_PREWARM_BATCH_LIMIT
#define LISTENER_ROUTE_PREWARM_BATCH_LIMIT	64
#endif
#ifndef LISTENER_ROUTE_WARMUP_TIMEOUT_SEC
#define LISTENER_ROUTE_WARMUP_TIMEOUT_SEC	10
#endif

/* process name */
#define LISTENER_PROCESS_NAME	"mrs-listener"

/* section: types */
typedef struct {
	struct timespec deadline;
	bool pressure_logged;
	bool ready;
} listener_route_runtime;

/* section: functions (local) */
static void listener_bind_success_msg(const listener_context *context) {
	mksysmsg(MKSYS_PREFIX_ON, context->log_filename, context->config->log.level, MKSYS_LEVEL_INFORMATION, MKSYS_PARAGRAPH_END, "Bind Successful.");
	mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, context->config->log.level, MKSYS_LEVEL_INFORMATION, MKSYS_PARAGRAPH_END, "For more information, see log file: %s", context->config->log.filename);
}

static void listener_notify_ready(void) {
	sd_notify(0, "READY=1");
}

static int listener_notify_reloading(void) {
	struct timespec timestamp;
	if (clock_gettime(CLOCK_MONOTONIC, &timestamp) == -1) {
		return -1;
	}
	if (!timeutil_valid(&timestamp)) {
		errno = EINVAL;
		return -1;
	}
	uint64_t timestamp_subsecond_usec = (uint64_t)timestamp.tv_nsec / 1000;
	if ((uint64_t)timestamp.tv_sec > (UINT64_MAX - timestamp_subsecond_usec) / 1000000) {
		errno = EOVERFLOW;
		return -1;
	}
	uint64_t timestamp_usec = (uint64_t)timestamp.tv_sec * 1000000 + timestamp_subsecond_usec;
	sd_notifyf(0, "RELOADING=1\nMONOTONIC_USEC=%" PRIu64, timestamp_usec);
	return 0;
}

static void listener_resolver_destroy(listener_context *context) {
	resolver_supervisor_destroy(context->resolver);
	context->resolver = NULL;
}

static int listener_resolver_events_process(listener_context *context, listener_connection *connections, const struct timespec *now) {
	resolver_supervisor_event_status status = resolver_supervisor_events_process(context->resolver, now);
	if (status != RESOLVER_SUPERVISOR_EVENT_OK) {
		errno = status == RESOLVER_SUPERVISOR_EVENT_TIME ? EOVERFLOW : status == RESOLVER_SUPERVISOR_EVENT_IO ? EIO : EINVAL;
		return -1;
	}
	resolver_supervisor_completion completion = { 0 };
	while (resolver_supervisor_completion_take(context->resolver, &completion)) {
		route_resolution_completion_status completion_status = route_generation_registry_completion_observe(context->generations, &completion, context->resolver, now);
		bool waiter_invalid = false;
		for (listener_connection *connection = connections; connection != NULL; connection = connection->next) {
			if (connection->waiter == NULL || connection->closing) {
				continue;
			}
			route_waiter_completion_status waiter_status = route_waiter_completion_observe(connection->waiter, &completion);
			if (waiter_status == ROUTE_WAITER_COMPLETION_BAD_ARGUMENT) {
				waiter_invalid = true;
			}
		}
		resolver_supervisor_completion_destroy(&completion);
		if (completion_status == ROUTE_RESOLUTION_COMPLETION_BAD_ARGUMENT || completion_status == ROUTE_RESOLUTION_COMPLETION_IO
			|| completion_status == ROUTE_RESOLUTION_COMPLETION_TIME || waiter_invalid) {
			errno = completion_status == ROUTE_RESOLUTION_COMPLETION_IO ? EIO : completion_status == ROUTE_RESOLUTION_COMPLETION_TIME ? EOVERFLOW : EINVAL;
			return -1;
		}
	}
	return 0;
}

static int listener_resolver_init(listener_context *context, listener_events *events) {
	struct timespec now;
	context->dns_cache = resolver_cache_create();
	if (context->dns_cache == NULL || clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return -1;
	}
	context->resolver = resolver_supervisor_create(&events->previous_signal_mask, &now);
	if (context->resolver == NULL || listener_events_resolver_add(events, resolver_supervisor_event_fd(context->resolver)) == -1) {
		return -1;
	}
	return 0;
}

static int listener_route_runtime_ready(listener_context *context, listener_route_runtime *runtime, listener_events *events, const listener_socket *listener, bool warmup_complete, const struct timespec *now) {
	if (listener_events_socket_add(events, listener->fd) == -1) {
		return -1;
	}
	runtime->ready = true;
	listener_notify_ready();
	if (!isatty(STDOUT_FILENO)) {
		fflush(stdout);
		fflush(stderr);
		int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
		if (null_fd != -1) {
			dup2(null_fd, STDOUT_FILENO);
			if (dup2(null_fd, STDERR_FILENO) != -1) {
				log_stderr_prepare();
			}
			if (null_fd != STDOUT_FILENO && null_fd != STDERR_FILENO) {
				close(null_fd);
			}
		}
	}
	if (warmup_complete) {
		mksysmsg(MKSYS_PREFIX_ON, context->log_filename, context->config->log.level, MKSYS_LEVEL_INFORMATION, MKSYS_PARAGRAPH_END,
			"Initial proxy route warm-up finished; accepting connections."
		);
	} else {
		mksysmsg(MKSYS_PREFIX_ON, context->log_filename, context->config->log.level, MKSYS_LEVEL_WARNING, MKSYS_PARAGRAPH_END,
			"Initial proxy route warm-up deadline reached; accepting connections while prewarming continues."
		);
	}
	if (listener_metrics_effectively_enabled(context->config)) {
		listener_metrics_timer_set(context, events, context->config->metrics.interval, context->log_filename, context->config->log.level);
		listener_metrics_snapshot_output(context, LISTENER_METRICS_OUTPUT_STARTUP, context->log_filename, context->config->log.level, now);
	}
	return 0;
}

static int listener_route_timer_set(const listener_events *events, const struct timespec *deadline) {
	struct itimerspec timer = { 0 };
#ifdef LISTENER_ROUTE_TIMER_ARMED_TEST
	if (deadline == NULL) {
		return listener_test_route_timer_disarm(events);
	}
#endif
	if (deadline != NULL) {
		timer.it_value = *deadline;
	}
	return listener_events_route_timer_set(events, &timer);
}

#ifdef LISTENER_READY_FLIP_TEST
static int listener_ready_flip_test_timer_disarm(const void *context) {
	return listener_route_timer_set(context, NULL);
}
#endif

static int listener_route_runtime_schedule(listener_context *context, listener_route_runtime *runtime, listener_events *events, const listener_socket *listener, const struct timespec *now) {
	route_prewarm_status status = route_resolution_schedule(context->route_resolution, context->resolver, now, LISTENER_ROUTE_PREWARM_BATCH_LIMIT);
	if (status == ROUTE_PREWARM_BAD_ARGUMENT || status == ROUTE_PREWARM_IO || status == ROUTE_PREWARM_TIME) {
		errno = status == ROUTE_PREWARM_TIME ? EOVERFLOW : status == ROUTE_PREWARM_IO ? EIO : EINVAL;
		return -1;
	}
	if (status == ROUTE_PREWARM_CAPACITY || status == ROUTE_PREWARM_MEMORY) {
		if (!runtime->pressure_logged) {
			LISTENER_LOG(context, MKSYS_LEVEL_WARNING,
				"Proxy route prewarming paused by local resolver %s pressure; it will resume after later resolver activity.",
				status == ROUTE_PREWARM_CAPACITY ? "capacity" : "memory"
			);
			runtime->pressure_logged = true;
		}
	} else if (runtime->pressure_logged) {
		LISTENER_LOG(context, MKSYS_LEVEL_INFORMATION,
			"Proxy route prewarming resumed after local resolver pressure."
		);
		runtime->pressure_logged = false;
	}
	bool deadline_reached = timeutil_compare(now, &runtime->deadline) >= 0;
	bool warmup_complete = route_resolution_warmup_complete(context->route_resolution);
#ifdef LISTENER_READY_FLIP_TEST
	int ready_flip_hold = listener_test_ready_flip_hold(runtime->ready, warmup_complete, listener_ready_flip_test_timer_disarm, events);
	if (ready_flip_hold == -1) {
		return -1;
	}
	if (ready_flip_hold == 1) {
		return 0;
	}
#endif
	if (!runtime->ready && (warmup_complete || deadline_reached) && listener_route_runtime_ready(context, runtime, events, listener, warmup_complete, now) == -1) {
		return -1;
	}
	if (status == ROUTE_PREWARM_MORE) {
		return listener_route_timer_set(events, now);
	}
	if (!runtime->ready) {
		return listener_route_timer_set(events, &runtime->deadline);
	}
	return listener_route_timer_set(events, NULL);
}

static int listener_route_runtime_start(listener_route_runtime *runtime, const listener_events *events, const struct timespec *now) {
	memset(runtime, 0, sizeof(*runtime));
	if (LISTENER_ROUTE_PREWARM_BATCH_LIMIT == 0 || LISTENER_ROUTE_WARMUP_TIMEOUT_SEC == 0 || !timeutil_add_seconds(now, LISTENER_ROUTE_WARMUP_TIMEOUT_SEC, &runtime->deadline)) {
		errno = EINVAL;
		return -1;
	}
	return listener_route_timer_set(events, &runtime->deadline);
}

static int listener_shutdown_begin(listener_context *context, listener_events *events, listener_connection **connections) {
	resolver_supervisor_shutdown_prepare(context->resolver);
	listener_metrics_timer_set(context, events, 0, context->log_filename, context->config->log.level);
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot sample the monotonic clock while closing listener connections: %s", strerror(errno));
		return -1;
	}
	int connection_destroy_errno = 0;
	while (*connections != NULL) {
		if (!listener_connection_destroy(connections, *connections, events, &context->metrics, LISTENER_METRICS_OUTCOME_SHUTDOWN, context->resolver, &now) && connection_destroy_errno == 0) {
			connection_destroy_errno = errno;
		}
	}
	if (connection_destroy_errno != 0) {
		errno = connection_destroy_errno;
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot release connection route interests during shutdown: %s", strerror(errno));
		return -1;
	}
	if (listener_route_timer_set(events, NULL) == -1 || clock_gettime(CLOCK_MONOTONIC, &now) == -1 || !resolver_supervisor_shutdown(context->resolver, &now)) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot shut down resolver runtime: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static bool listener_shutdown_drain(listener_context *context) {
	struct timespec now;
	bool time_valid = clock_gettime(CLOCK_MONOTONIC, &now) == 0;
	if (time_valid) {
		listener_metrics_observations_drain(context, &now);
	}
	if (!resolver_supervisor_shutdown_complete(context->resolver)) {
		return false;
	}
	if (listener_metrics_effectively_enabled(context->config) && time_valid) {
		listener_metrics_snapshot_output(context, LISTENER_METRICS_OUTPUT_SHUTDOWN, context->log_filename, context->config->log.level, &now);
	}
	return true;
}

static exit_code listener_loop(listener_context *context, listener_socket *listener) {
	exit_code exitcode = EXITCODE_INTERNAL;
	listener_events events;
	if (listener_events_init(&events) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot initialize listener event loop: %s", strerror(errno));
		goto release_resources;
	}
	listener_hosts_watch_retry(context, &events);
	context->generations = route_generation_registry_create();
	if (context->generations == NULL) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot initialize proxy route generation ownership: memory allocation failed.");
		goto release_resources;
	}
	if (!listener_hosts_prepare(context, MKSYS_LEVEL_CRITICAL, "", &context->hosts)) {
		goto release_resources;
	}
	if (listener_resolver_init(context, &events) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot initialize resolver runtime: %s", strerror(errno));
		goto release_resources;
	}
	if (!listener_generation_initial_publish(context)) {
		goto release_resources;
	}
	const size_t connection_limit = listener_connection_limit();
	listener_metrics_limits_set(&context->metrics, connection_limit, LISTENER_WORKER_LIMIT);
	listener_bind_success_msg(context);
	struct timespec route_now;
	listener_route_runtime route_runtime;
	pid_t listener_pid = getpid();
	if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1 || !listener_metrics_runtime_init(&context->metrics_runtime, listener_pid, &route_now)
		|| listener_route_runtime_start(&route_runtime, &events, &route_now) == -1
		|| listener_route_runtime_schedule(context, &route_runtime, &events, listener, &route_now) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot start proxy route prewarming: %s", strerror(errno));
		goto release_resources;
	}
	exitcode = EXITCODE_OK;
	size_t connection_count = 0;
	listener_connection *connections = NULL;
	bool hosts_reload_pending = false;
	bool reload_pending = false;
	bool shutting_down = false;
	while (1) {
		listener_requests requests;
		if (listener_events_wait(&events, &requests) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Listener event loop failed: %s", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (requests.hosts_watch_failed || requests.hosts_watch_ready) {
			hosts_reload_pending = listener_hosts_watch_process(context, &events, requests.hosts_watch_failed, requests.hosts_watch_ready) || hosts_reload_pending;
		}
		/* Client cancellation wins when route completion and peer shutdown are ready in the same epoll batch. */
		listener_dispatch_mark_cancelled(&requests);
		/* Release connection interests and enter supervisor shutdown before processing helper exits from the same stop batch. */
		if ((!requests.stop || shutting_down) && (requests.resolver_ready || requests.route_timer_ready)) {
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot sample the monotonic clock for route resolution: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			if (requests.resolver_ready && listener_resolver_events_process(context, connections, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Resolver event processing failed: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			if (requests.route_timer_ready && listener_events_route_timer_drain(&events) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot consume the route warm-up timer: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#ifdef LISTENER_READY_FLIP_TEST
			if (requests.route_timer_ready && listener_test_ready_flip_timer_event() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot notify the ready-flip timer test: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#endif
		}
		if (requests.child_ready && listener_workers_reap(context) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot reap a worker process: %s", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (requests.stop && !shutting_down) {
			if (listener_shutdown_begin(context, &events, &connections) == -1) {
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			connection_count = 0;
			shutting_down = true;
		}
		if (shutting_down) {
			if (listener_shutdown_drain(context)) {
				break;
			}
			continue;
		}
		if (requests.reload) {
			reload_pending = true;
#ifdef LISTENER_READY_FLIP_TEST
			if (listener_test_ready_flip_release() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot notify the ready-flip reload test: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#endif
#ifdef LISTENER_EARLY_COLLECT_TEST
			if (listener_test_early_collect_reload_ack() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot notify the early-collect reload test: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#endif
		}
		if (requests.resolver_ready && listener_dispatch_route_waiters(connections, listener, &events, listener_pid, context, &route_now) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Connection route resolution failed: %s", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
#ifdef LISTENER_EARLY_COLLECT_TEST
		bool retired_before_collect = route_generation_registry_retired(context->generations) != NULL;
#endif
		if (!listener_generation_collect(context, &route_now)) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot collect a retired proxy route generation: %s", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		bool reload_processed = false;
		bool metrics_readiness_invalidated = false;
#ifdef LISTENER_READY_FLIP_TEST
		/* Exclude unrelated test-daemon events: this scenario may reload only after the late-arm timer actually fires. */
		bool ready_flip_timer_ready = listener_test_ready_flip_timer_ready();
		if (!route_runtime.ready && reload_pending) {
			if (listener_test_ready_flip_reload_blocked() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot notify the ready-flip reload test: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
		}
#endif
		if (route_runtime.ready && reload_pending && route_generation_registry_retired(context->generations) == NULL
#ifdef LISTENER_READY_FLIP_TEST
			&& ready_flip_timer_ready
#endif
		) {
#ifdef LISTENER_EARLY_COLLECT_TEST
			if (listener_test_early_collect_observe(requests.resolver_ready, retired_before_collect) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot notify the early-collect test: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#endif
			if (listener_notify_reloading() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot create systemd reload timestamp: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			if (!listener_events_hosts_watch_active(&events)) {
				listener_hosts_watch_retry(context, &events);
			}
			/* Arm monitoring before the manual hosts read so changes during that read remain observable. */
			int reload_result = listener_reload(context, listener, &events, &metrics_readiness_invalidated);
			/* Complete the reload handshake before acting on a fatal result; systemd observes the subsequent listener exit separately. */
			listener_notify_ready();
			hosts_reload_pending = false;
			reload_pending = false;
			if (reload_result == -1) {
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			reload_processed = true;
			route_runtime.pressure_logged = false;
		}
		if (route_runtime.ready && !reload_pending && hosts_reload_pending && route_generation_registry_retired(context->generations) == NULL) {
			hosts_reload_pending = false;
			if (listener_hosts_reload(context) == -1) {
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			reload_processed = true;
			route_runtime.pressure_logged = false;
		}
		bool route_activity = requests.accept_ready || requests.ready_count > 0 || requests.reload || requests.resolver_ready || requests.route_timer_ready || reload_processed;
		if (route_activity) {
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1 || listener_route_runtime_schedule(context, &route_runtime, &events, listener, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Proxy route prewarming failed: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
		}
		if (listener_dispatch_batch(&requests, connections, listener, &events, listener_pid, context, &route_now) == -1) {
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		size_t destroyed_count;
		if (!listener_connections_destroy_closed(&connections, &events, &context->metrics, context->resolver, &route_now, &destroyed_count)) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot release closed connection route interests: %s", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (destroyed_count > connection_count) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Listener connection accounting failed.");
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		connection_count -= destroyed_count;
		if (!listener_generation_collect(context, &route_now)) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot collect a retired proxy route generation after connection processing: %s", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (route_runtime.ready && (hosts_reload_pending || reload_pending) && route_generation_registry_retired(context->generations) == NULL) {
			if (clock_gettime(CLOCK_MONOTONIC, &route_now) == -1 || listener_route_timer_set(&events, &route_now) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot resume a deferred route-generation reload: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#ifdef LISTENER_READY_FLIP_TEST
			if (listener_test_ready_flip_timer_arm() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot notify the ready-flip late-wake test: %s", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
#endif
		}
		listener_metrics_observations_drain(context, &route_now);
		if (!metrics_readiness_invalidated && (requests.metrics_timer_ready || requests.metrics_timer_failed)) {
			uint64_t expirations = 0;
			listener_metrics_timer_read_status metrics_status = listener_metrics_timer_read(context, &events, requests.metrics_timer_failed, &expirations);
			if (metrics_status == LISTENER_METRICS_TIMER_EXPIRED && listener_metrics_effectively_enabled(context->config)) {
				if (expirations > 1) {
					listener_metrics_missed_intervals_record(&context->metrics_runtime, expirations - 1U);
				}
				listener_metrics_snapshot_output(context, LISTENER_METRICS_OUTPUT_PERIODIC, context->log_filename, context->config->log.level, &route_now);
			}
		}
		if (route_runtime.ready && requests.accept_ready && listener_admission_accept_batch(context, listener->fd, &events, &connections, &connection_count, connection_limit) == -1) {
			exitcode = EXITCODE_INTERNAL;
			break;
		}
	}
	struct timespec cleanup_now;
	const struct timespec *cleanup_now_ptr = clock_gettime(CLOCK_MONOTONIC, &cleanup_now) == 0 ? &cleanup_now : NULL;
	if (cleanup_now_ptr != NULL && context->resolver != NULL) {
		listener_metrics_observations_drain(context, cleanup_now_ptr);
	}
	while (connections != NULL) {
		listener_connection_destroy(&connections, connections, &events, &context->metrics, LISTENER_METRICS_OUTCOME_INTERNAL_ERROR, NULL, cleanup_now_ptr);
	}
release_resources:
	listener_resolver_destroy(context);
	listener_events_destroy(&events);
	listener_socket_close(listener);
	return exitcode;
}

/* section: functions (exported) */
void listener_backoff(void) {
	struct timespec backoff = { .tv_sec = 0, .tv_nsec = 100000000 };
	nanosleep(&backoff, NULL);
}

exit_code listener_run(conf *config, conf_cache *config_cache, const char *config_filename, const char *config_filename_full, const char *working_directory, const char *log_filename) {
	listener_context context = {
		.config = config,
		.config_cache = config_cache,
		.config_filename = config_filename,
		.config_filename_full = config_filename_full,
		.generation_next_identity = 1,
		.working_directory = working_directory
	};
	snprintf(context.log_filename, sizeof(context.log_filename), "%s", log_filename);
	log_stderr_prepare();
	LISTENER_LOG(&context, MKSYS_LEVEL_INFORMATION, "Starting mcrelay %s on PID %jd...", version_info_get(), (intmax_t)getpid());
	if (prctl(PR_SET_NAME, LISTENER_PROCESS_NAME) == -1) {
		LISTENER_LOG(&context, MKSYS_LEVEL_WARNING, "Cannot set listener process name: %s", strerror(errno));
	}
	exit_code exitcode;
	listener_socket listener = { .fd = -1 };
	listener_endpoint_status endpoint_status = listener_endpoint_prepare(context.config, &listener.endpoint);
	if (endpoint_status == LISTENER_ENDPOINT_BAD_ADDRESS) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Error: Invalid bind address!");
		exitcode = EXITCODE_BINDFAIL;
		goto cleanup;
	}
	if (endpoint_status == LISTENER_ENDPOINT_BAD_PORT) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Error: Invalid bind port!");
		exitcode = EXITCODE_BADPORT;
		goto cleanup;
	}
	route_table_build_status route_status = route_table_build(context.config, &context.routes);
	if (route_status != ROUTE_TABLE_BUILD_OK) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Cannot prepare proxy routes: %s.", route_status == ROUTE_TABLE_BUILD_MEMORY ? "memory allocation failed" : "invalid internal route state");
		exitcode = EXITCODE_INTERNAL;
		goto cleanup;
	}
	net_addrp bindaddrp = net_ntop(listener.endpoint.address.family, &(listener.endpoint.address.addr), true);
	LISTENER_LOG(&context, MKSYS_LEVEL_INFORMATION, "Binding on %s:%d...", (char *)&bindaddrp, listener.endpoint.port);
	if (listener_socket_bind(&listener) == -1) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Bind Failed!");
		exitcode = EXITCODE_BINDFAIL;
		goto cleanup;
	}
	exitcode = listener_loop(&context, &listener);
cleanup:
	listener_generation_destroy(&context);
	config_cache_destroy(context.config_cache);
	resolver_cache_destroy(context.dns_cache);
	return exitcode;
}
