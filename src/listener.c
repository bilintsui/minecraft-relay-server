/*
 * listener.c: Listener and worker process runtime
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <systemd/sd-daemon.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "basic.h"
#include "config.h"
#include "connsetup.h"
#include "define/exitcode.h"
#include "hosts.h"
#include "log.h"
#include "network.h"
#include "resolver_cache.h"
#include "resolver_supervisor.h"

/* section: headers (self) */
#include "listener.h"

/* section: defines */
/* listener */
#define LISTENER_ACCEPT_BATCH	128
#ifndef LISTENER_HOSTS_FILENAME
#define LISTENER_HOSTS_FILENAME	"/etc/hosts"
#endif

/* logging macro */
#define LISTENER_LOG(ctx, lvl, ...)	mksysmsg(MKSYS_PREFIX_ON, (ctx)->log_filename, (ctx)->config->log.level, lvl, __VA_ARGS__)
#define LISTENER_LOG_TERMINAL(ctx, lvl, ...)	mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, (ctx)->config->log.level, lvl, __VA_ARGS__)

/* section: types */
enum listener_endpoint_status {
	LISTENER_ENDPOINT_OK,
	LISTENER_ENDPOINT_BAD_ADDRESS,
	LISTENER_ENDPOINT_BAD_PORT
};
enum listener_socket_open_status {
	LISTENER_SOCKET_OPEN_OK,
	LISTENER_SOCKET_OPEN_BIND_ERROR,
	LISTENER_SOCKET_OPEN_EVENTS_ERROR
};
enum listener_socket_replace_status {
	LISTENER_SOCKET_REPLACE_OK,
	LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR,
	LISTENER_SOCKET_REPLACE_ACTIVE_ERROR,
	LISTENER_SOCKET_REPLACE_ROLLBACK_ERROR
};
typedef union {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
} listener_client_address;
typedef struct {
	conf *config;
	conf_cache *config_cache;
	const char *config_filename;
	const char *config_filename_full;
	resolver_cache *dns_cache;
	hosts_table *hosts;
	char log_filename[PATH_MAX];
	resolver_supervisor *resolver;
	const char *working_directory;
} listener_context;
typedef struct {
	net_addr address;
	in_port_t port;
} listener_endpoint;
typedef struct {
	int epoll_fd;
	bool mask_blocked;
	sigset_t previous_signal_mask;
	int resolver_fd;
	int signal_fd;
} listener_events;
typedef struct {
	bool accept_ready;
	bool reload;
	bool resolver_ready;
	bool stop;
} listener_requests;
typedef struct {
	listener_endpoint endpoint;
	int fd;
} listener_socket;

/* section: functions (local) */
static bool listener_accept_error_retryable(int error) {
	switch (error) {
		case ECONNABORTED:
		case EHOSTDOWN:
		case EHOSTUNREACH:
		case ENETDOWN:
		case ENETUNREACH:
		case ENONET:
		case ENOPROTOOPT:
		case EOPNOTSUPP:
		case EPROTO:
			return true;
		default:
			return false;
	}
}

static void listener_backoff(void) {
	struct timespec backoff = { .tv_sec = 0, .tv_nsec = 100000000 };
	nanosleep(&backoff, NULL);
}

static void listener_bind_success_msg(const listener_context *context) {
	LISTENER_LOG(context, MKSYS_LEVEL_INFORMATION, "Bind Successful.\n\n");
	LISTENER_LOG_TERMINAL(context, MKSYS_LEVEL_INFORMATION, "For more information, see log file: %s\n\n", context->config->log.filename);
}

static net_addrbundle listener_client_address_parse(const listener_client_address *addr) {
	net_addrbundle result;
	memset(&result, 0, sizeof(result));
	result.family = addr->v4.sin_family;
	const void *addroffset = NULL;
	switch (result.family) {
		case AF_INET:
			result.address = net_ntop(AF_INET, &(addr->v4.sin_addr), true);
			result.address_clean = net_ntop(AF_INET, &(addr->v4.sin_addr), false);
			result.port = ntohs(addr->v4.sin_port);
			break;
		case AF_INET6:
			addroffset = &(addr->v6.sin6_addr);
			if (memcmp(addroffset, "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\xFF\xFF", 12) == 0) {
				result.family = AF_INET;
				addroffset = (const uint8_t *)addroffset + 12;
			}
			result.address = net_ntop(result.family, addroffset, true);
			result.address_clean = net_ntop(result.family, addroffset, false);
			result.port = ntohs(addr->v6.sin6_port);
			break;
		default:
			result.family = 0;
			break;
	}
	return result;
}

static bool listener_endpoint_equal(const listener_endpoint *left, const listener_endpoint *right) {
	if (left->address.family != right->address.family || left->port != right->port) {
		return false;
	}
	switch (left->address.family) {
		case AF_INET:
			return left->address.addr.v4 == right->address.addr.v4;
		case AF_INET6:
			return memcmp(left->address.addr.v6, right->address.addr.v6, sizeof(left->address.addr.v6)) == 0;
		default:
			return false;
	}
}

static bool listener_endpoint_is_wildcard(const listener_endpoint *target) {
	switch (target->address.family) {
		case AF_INET:
			return target->address.addr.v4 == INADDR_ANY;
		case AF_INET6:
			return memcmp(target->address.addr.v6, &in6addr_any, sizeof(target->address.addr.v6)) == 0;
		default:
			return false;
	}
}

static bool listener_endpoint_may_conflict(const listener_endpoint *left, const listener_endpoint *right) {
	if (left->port != right->port) {
		return false;
	}
	if (left->address.family != right->address.family) {
		return true;
	}
	return listener_endpoint_is_wildcard(left) || listener_endpoint_is_wildcard(right);
}

static enum listener_endpoint_status listener_endpoint_prepare(const conf *source, listener_endpoint *target) {
	target->address = net_addr_parse(source->listen.address);
	target->port = source->listen.port;
	if (target->address.family == 0) {
		return LISTENER_ENDPOINT_BAD_ADDRESS;
	}
	if (target->port == 0) {
		return LISTENER_ENDPOINT_BAD_PORT;
	}
	return LISTENER_ENDPOINT_OK;
}

static void listener_events_destroy(listener_events *events) {
	if (events->epoll_fd != -1) {
		close(events->epoll_fd);
	}
	if (events->signal_fd != -1) {
		close(events->signal_fd);
	}
	if (events->mask_blocked) {
		sigprocmask(SIG_SETMASK, &events->previous_signal_mask, NULL);
	}
}

static int listener_events_socket_add(const listener_events *events, int socket_fd) {
	int socket_flags = fcntl(socket_fd, F_GETFL);
	if (socket_flags == -1 || fcntl(socket_fd, F_SETFL, socket_flags | O_NONBLOCK) == -1) {
		return -1;
	}
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.fd = socket_fd;
	return epoll_ctl(events->epoll_fd, EPOLL_CTL_ADD, socket_fd, &event);
}

static int listener_events_init(int socket_fd, listener_events *events) {
	int saved_errno;
	memset(events, 0, sizeof(*events));
	events->epoll_fd = -1;
	events->resolver_fd = -1;
	events->signal_fd = -1;
	struct sigaction child_action;
	memset(&child_action, 0, sizeof(child_action));
	sigemptyset(&child_action.sa_mask);
	child_action.sa_handler = SIG_IGN;
	if (sigaction(SIGCHLD, &child_action, NULL) == -1) {
		return -1;
	}
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	sigaddset(&signal_mask, SIGUSR1);
	if (sigprocmask(SIG_BLOCK, &signal_mask, &events->previous_signal_mask) == -1) {
		return -1;
	}
	events->mask_blocked = true;
	events->signal_fd = signalfd(-1, &signal_mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (events->signal_fd == -1) {
		goto fail;
	}
	events->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (events->epoll_fd == -1) {
		goto fail;
	}
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.fd = events->signal_fd;
	if (epoll_ctl(events->epoll_fd, EPOLL_CTL_ADD, events->signal_fd, &event) == -1) {
		goto fail;
	}
	if (listener_events_socket_add(events, socket_fd) == -1) {
		goto fail;
	}
	return 0;
fail:
	saved_errno = errno;
	listener_events_destroy(events);
	errno = saved_errno;
	return -1;
}

static int listener_events_resolver_add(listener_events *events, int resolver_fd) {
	if (events == NULL || resolver_fd < 0 || events->resolver_fd != -1) {
		errno = EINVAL;
		return -1;
	}
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.fd = resolver_fd;
	if (epoll_ctl(events->epoll_fd, EPOLL_CTL_ADD, resolver_fd, &event) == -1) {
		return -1;
	}
	events->resolver_fd = resolver_fd;
	return 0;
}

static int listener_events_socket_remove(const listener_events *events, int socket_fd) {
	return epoll_ctl(events->epoll_fd, EPOLL_CTL_DEL, socket_fd, NULL);
}

static int listener_signals_read(int signal_fd, listener_requests *requests) {
	while (1) {
		struct signalfd_siginfo signal_info;
		ssize_t bytes = read(signal_fd, &signal_info, sizeof(signal_info));
		if (bytes == (ssize_t)sizeof(signal_info)) {
			switch (signal_info.ssi_signo) {
				case SIGINT:
				case SIGTERM:
					requests->stop = true;
					break;
				case SIGUSR1:
					requests->reload = true;
					break;
			}
			continue;
		}
		if (bytes == -1 && errno == EINTR) {
			continue;
		}
		if (bytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return 0;
		}
		if (bytes != -1) {
			errno = EIO;
		}
		return -1;
	}
}

static int listener_events_wait(int socket_fd, const listener_events *events, listener_requests *requests) {
	struct epoll_event ready_events[3];
	memset(requests, 0, sizeof(*requests));
	int ready_count;
	do {
		ready_count = epoll_wait(events->epoll_fd, ready_events, 3, -1);
	} while (ready_count == -1 && errno == EINTR);
	if (ready_count == -1) {
		return -1;
	}
	for (int i = 0; i < ready_count; i++) {
		uint32_t event_flags = ready_events[i].events;
		int event_fd = ready_events[i].data.fd;
		if (event_fd == events->signal_fd) {
			if ((event_flags & EPOLLIN) && listener_signals_read(events->signal_fd, requests) == -1) {
				return -1;
			}
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				errno = EIO;
				return -1;
			}
		} else if (event_fd == socket_fd) {
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				errno = EIO;
				return -1;
			}
			if (event_flags & EPOLLIN) {
				requests->accept_ready = true;
			}
		} else if (event_fd == events->resolver_fd) {
			if (event_flags & (EPOLLERR | EPOLLHUP)) {
				errno = EIO;
				return -1;
			}
			if (event_flags & EPOLLIN) {
				requests->resolver_ready = true;
			}
		} else {
			errno = EIO;
			return -1;
		}
	}
	return 0;
}

static void listener_hosts_dispose_in_child(listener_context *context) {
	hosts_table_destroy(context->hosts);
	context->hosts = NULL;
}

static const char *listener_hosts_load_error(hosts_load_status status) {
	switch (status) {
		case HOSTS_LOAD_LIMIT:
			return "entry limit reached";
		case HOSTS_LOAD_MEMORY:
			return "memory allocation failed";
		case HOSTS_LOAD_BAD_ARGUMENT:
		default:
			return "invalid loader state";
	}
}

static bool listener_hosts_replace(listener_context *context, uint8_t failure_level, const char *failure_action) {
	hosts_table *candidate = NULL;
	size_t malformed_line_count = 0;
	hosts_load_status status = hosts_table_load(LISTENER_HOSTS_FILENAME, &candidate, &malformed_line_count);
	if (status != HOSTS_LOAD_OK && status != HOSTS_LOAD_FILE_ERROR) {
		LISTENER_LOG(context, failure_level, "Cannot prepare local static host table from %s: %s%s.\n", LISTENER_HOSTS_FILENAME, listener_hosts_load_error(status), failure_action);
		return false;
	}
	if (candidate == NULL) {
		LISTENER_LOG(context, failure_level, "Cannot prepare local static host table from %s: loader returned no table%s.\n", LISTENER_HOSTS_FILENAME, failure_action);
		return false;
	}
	if (status == HOSTS_LOAD_FILE_ERROR) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot read local static host table from %s; using guaranteed localhost entries.\n", LISTENER_HOSTS_FILENAME);
	}
	if (malformed_line_count > 0) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Ignored %zu malformed line%s while loading local static host table from %s.\n", malformed_line_count,
			malformed_line_count == 1 ? "" : "s", LISTENER_HOSTS_FILENAME);
	}
	hosts_table *previous = context->hosts;
	context->hosts = candidate;
	hosts_table_destroy(previous);
	return true;
}

static void listener_notify_ready(void) {
	sd_notify(0, "READY=1");
}

static int listener_notify_reloading(void) {
	struct timespec timestamp;
	if (clock_gettime(CLOCK_MONOTONIC, &timestamp) == -1) {
		return -1;
	}
	if (timestamp.tv_sec < 0 || timestamp.tv_nsec < 0) {
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

static int listener_socket_bind(listener_socket *target) {
	target->fd = net_socket(NETSOCK_BIND, target->endpoint.address.family, &(target->endpoint.address.addr), target->endpoint.port, true);
	return target->fd;
}

static void listener_socket_close(listener_socket *target) {
	if (target->fd != -1) {
		close(target->fd);
		target->fd = -1;
	}
}

static enum listener_socket_open_status listener_socket_open(listener_socket *target, const listener_events *events) {
	if (listener_socket_bind(target) == -1) {
		return LISTENER_SOCKET_OPEN_BIND_ERROR;
	}
	if (listener_events_socket_add(events, target->fd) == -1) {
		int saved_errno = errno;
		listener_socket_close(target);
		errno = saved_errno;
		return LISTENER_SOCKET_OPEN_EVENTS_ERROR;
	}
	return LISTENER_SOCKET_OPEN_OK;
}

static enum listener_socket_replace_status listener_socket_replace_conflicting(listener_socket *target, listener_socket *candidate, const listener_events *events) {
	if (listener_events_socket_remove(events, target->fd) == -1) {
		return LISTENER_SOCKET_REPLACE_ACTIVE_ERROR;
	}
	listener_socket_close(target);
	if (listener_socket_open(candidate, events) == LISTENER_SOCKET_OPEN_OK) {
		*target = *candidate;
		return LISTENER_SOCKET_REPLACE_OK;
	}
	int candidate_errno = errno;
	if (listener_socket_open(target, events) != LISTENER_SOCKET_OPEN_OK) {
		return LISTENER_SOCKET_REPLACE_ROLLBACK_ERROR;
	}
	errno = candidate_errno;
	return LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR;
}

static enum listener_socket_replace_status listener_socket_replace(listener_socket *target, const listener_endpoint *endpoint, const listener_events *events) {
	listener_socket candidate = {
		.endpoint = *endpoint,
		.fd = -1
	};
	enum listener_socket_open_status open_status = listener_socket_open(&candidate, events);
	if (open_status != LISTENER_SOCKET_OPEN_OK) {
		/* Same-port address transitions may require closing the active socket before binding the candidate. */
		if (open_status == LISTENER_SOCKET_OPEN_BIND_ERROR && listener_endpoint_may_conflict(&target->endpoint, &candidate.endpoint) && errno == NET_EBIND) {
			return listener_socket_replace_conflicting(target, &candidate, events);
		}
		return LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR;
	}
	if (listener_events_socket_remove(events, target->fd) == -1) {
		int saved_errno = errno;
		listener_events_socket_remove(events, candidate.fd);
		listener_socket_close(&candidate);
		errno = saved_errno;
		return LISTENER_SOCKET_REPLACE_ACTIVE_ERROR;
	}
	listener_socket_close(target);
	*target = candidate;
	return LISTENER_SOCKET_REPLACE_OK;
}

static int listener_reload(listener_context *context, listener_socket *listener, const listener_events *events) {
	uint8_t config_maxlevel = context->config->log.level;
	int result = 0;
	char config_logfull_old[PATH_MAX];
	snprintf(config_logfull_old, sizeof(config_logfull_old), "%s", context->log_filename);
	mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
		"Reloading config from file: %s\n",
		context->config_filename
	);
	listener_hosts_replace(context, MKSYS_LEVEL_WARNING, ", keeping the existing table");
	conf_cache config_cache_candidate = { 0 };
	conf *config_candidate = NULL;
	conf_read_status read_status = config_read(context->config_filename_full, context->config_cache, &config_cache_candidate, &config_candidate);
	switch (read_status) {
		case CONF_READ_CHANGED: {
			listener_endpoint candidate_endpoint;
			enum listener_endpoint_status endpoint_status = listener_endpoint_prepare(config_candidate, &candidate_endpoint);
			if (endpoint_status == LISTENER_ENDPOINT_BAD_ADDRESS) {
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Error in configurations: Invalid candidate bind address, will keep your old configurations.\n"
				);
				break;
			}
			if (endpoint_status == LISTENER_ENDPOINT_BAD_PORT) {
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Error in configurations: Invalid candidate bind port, will keep your old configurations.\n"
				);
				break;
			}
			char config_logfull_candidate[PATH_MAX];
			resolve_path(config_candidate->log.filename, context->working_directory, config_logfull_candidate, sizeof(config_logfull_candidate));
			if (log_file_validate(config_logfull_candidate) == -1) {
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Cannot write candidate log to \"%s\", will keep your old configurations.\n",
					config_candidate->log.filename
				);
				break;
			}
			if (!config_icon_load(config_candidate, config_logfull_old, config_maxlevel, "will keep your old configurations")) {
				break;
			}
			if (!listener_endpoint_equal(&listener->endpoint, &candidate_endpoint)) {
				net_addrp candidate_address = net_ntop(candidate_endpoint.address.family, &(candidate_endpoint.address.addr), true);
				enum listener_socket_replace_status replace_status = listener_socket_replace(listener, &candidate_endpoint, events);
				if (replace_status == LISTENER_SOCKET_REPLACE_CANDIDATE_ERROR) {
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
						"Cannot activate candidate listening endpoint %s:%d, will keep your old configurations.\n",
						(char *)&candidate_address, candidate_endpoint.port
					);
					break;
				}
				if (replace_status == LISTENER_SOCKET_REPLACE_ACTIVE_ERROR) {
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
						"Cannot replace active listening socket: %s\n",
						strerror(errno)
					);
					result = -1;
					break;
				}
				if (replace_status == LISTENER_SOCKET_REPLACE_ROLLBACK_ERROR) {
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_CRITICAL,
						"Cannot activate candidate listening endpoint %s:%d or restore the active listening socket.\n",
						(char *)&candidate_address, candidate_endpoint.port
					);
					result = -1;
					break;
				}
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
					"Listening endpoint changed to %s:%d.\n",
					(char *)&candidate_address, candidate_endpoint.port
				);
			}
			config_destroy(context->config);
			context->config = config_candidate;
			config_candidate = NULL;
			snprintf(context->log_filename, sizeof(context->log_filename), "%s", config_logfull_candidate);
			config_cache_commit(context->config_cache, &config_cache_candidate);
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
				"Configuration reloaded.\n"
			);
			break;
		}
		case CONF_READ_UNCHANGED:
			config_icon_load(context->config, config_logfull_old, config_maxlevel, "keeping existing icon");
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
				"Configuration file unchanged.\n"
			);
			break;
		case CONF_READ_ERROR:
			switch (errno) {
				case CONF_EROPENFAIL:
				case CONF_EROPENEMPTY:
				case CONF_EROPENLARGE:
				case CONF_ERMEMORY:
				case CONF_ERPARSE:
				case CONF_ECMEMORY:
				case CONF_ECNETPRIORITYPROTOCOL:
				case CONF_ECLISTENPORT:
				case CONF_ECPROXY:
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
						"%s%s%s\n",
						config_errmsg(errno),
						(errno == CONF_EROPENFAIL || errno == CONF_EROPENEMPTY) ? context->config_filename : "",
						", will keep your old configurations"
					);
					break;
				case CONF_ECPROXYDUP:
					config_log_duplicate_error(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING, ", will keep your old configurations");
					break;
				default:
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
						"Error in processing configurations: Unknown error occurred, code: %d, will keep your old configurations\n",
						errno
					);
					break;
			}
	}
	config_destroy(config_candidate);
	config_cache_destroy(&config_cache_candidate);
	return result;
}

static void listener_resolver_completions_discard(listener_context *context) {
	resolver_supervisor_completion completion = { 0 };
	while (resolver_supervisor_completion_take(context->resolver, &completion)) {
		resolver_supervisor_completion_destroy(&completion);
	}
}

static void listener_resolver_destroy(listener_context *context) {
	resolver_supervisor_destroy(context->resolver);
	context->resolver = NULL;
	resolver_cache_destroy(context->dns_cache);
	context->dns_cache = NULL;
}

static void listener_resolver_dispose_in_child(listener_context *context) {
	resolver_supervisor_dispose_in_child(context->resolver);
	context->resolver = NULL;
	resolver_cache_destroy(context->dns_cache);
	context->dns_cache = NULL;
}

static int listener_resolver_events_process(listener_context *context) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return -1;
	}
	resolver_supervisor_event_status status = resolver_supervisor_events_process(context->resolver, &now);
	if (status != RESOLVER_SUPERVISOR_EVENT_OK) {
		errno = status == RESOLVER_SUPERVISOR_EVENT_TIME ? EINVAL : EIO;
		return -1;
	}
	listener_resolver_completions_discard(context);
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

static int listener_resolver_shutdown(listener_context *context) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1 || !resolver_supervisor_shutdown(context->resolver, &now)) {
		return -1;
	}
	return 0;
}

static int listener_worker_signals_restore(const sigset_t *signal_mask) {
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);
	action.sa_handler = SIG_IGN;
	if (sigaction(SIGUSR1, &action, NULL) == -1) {
		return -1;
	}
	action.sa_handler = SIG_DFL;
	if (sigaction(SIGINT, &action, NULL) == -1 || sigaction(SIGTERM, &action, NULL) == -1) {
		return -1;
	}
	return sigprocmask(SIG_SETMASK, signal_mask, NULL);
}

static int listener_worker_run(int client_fd, const listener_client_address *client_address, listener_socket *listener, const listener_events *events, pid_t listener_pid,
	listener_context *context) {
	close(events->epoll_fd);
	close(events->signal_fd);
	listener_socket_close(listener);
	listener_hosts_dispose_in_child(context);
	listener_resolver_dispose_in_child(context);
	if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot configure worker parent-death signal: %s\n", strerror(errno));
		return EXITCODE_INTERNAL;
	}
	if (getppid() != listener_pid) {
		return EXITCODE_OK;
	}
	if (listener_worker_signals_restore(&events->previous_signal_mask) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot restore worker signal state: %s\n", strerror(errno));
		return EXITCODE_INTERNAL;
	}
	net_addrbundle addrbundle_inbound_client = listener_client_address_parse(client_address);
	int socket_outbound;
	if (!connsetup(client_fd, &socket_outbound, context->log_filename, context->config, addrbundle_inbound_client, context->config->netpriority.enabled)) {
		net_relay(client_fd, socket_outbound);
	}
	return EXITCODE_OK;
}

static int listener_loop(listener_context *context, listener_socket *listener) {
	listener_events events;
	if (listener_events_init(listener->fd, &events) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot initialize listener event loop: %s\n", strerror(errno));
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	if (!listener_hosts_replace(context, MKSYS_LEVEL_CRITICAL, "")) {
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	if (listener_resolver_init(context, &events) == -1) {
		LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot initialize resolver runtime: %s\n", strerror(errno));
		listener_resolver_destroy(context);
		listener_events_destroy(&events);
		listener_socket_close(listener);
		return EXITCODE_INTERNAL;
	}
	listener_bind_success_msg(context);
	listener_notify_ready();
	if (!isatty(STDOUT_FILENO)) {
		fclose(stdout);
		fclose(stderr);
	}
	int exitcode = EXITCODE_OK;
	pid_t listener_pid = getpid();
	bool shutting_down = false;
	while (1) {
		listener_requests requests;
		if (listener_events_wait(listener->fd, &events, &requests) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Listener event loop failed: %s\n", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (requests.resolver_ready && listener_resolver_events_process(context) == -1) {
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Resolver event processing failed: %s\n", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (requests.stop && !shutting_down) {
			if (listener_resolver_shutdown(context) == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot shut down resolver runtime: %s\n", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			shutting_down = true;
		}
		if (shutting_down) {
			if (resolver_supervisor_shutdown_complete(context->resolver)) {
				break;
			}
			continue;
		}
		if (requests.reload) {
			if (listener_notify_reloading() == -1) {
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot create systemd reload timestamp: %s\n", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				break;
			}
			int reload_result = listener_reload(context, listener, &events);
			/* Complete the reload handshake before acting on a fatal result; systemd observes the subsequent listener exit separately. */
			listener_notify_ready();
			if (reload_result == -1) {
				exitcode = EXITCODE_INTERNAL;
				break;
			}
		}
		if (!requests.accept_ready) {
			continue;
		}
		for (size_t accept_attempt = 0; accept_attempt < LISTENER_ACCEPT_BATCH; accept_attempt++) {
			listener_client_address client_address;
			socklen_t address_length = sizeof(client_address);
			/* On Linux, accepted sockets do not inherit O_NONBLOCK from the listening socket. */
			int client_fd = accept(listener->fd, (struct sockaddr *)&client_address, &address_length);
			if (client_fd == -1) {
				if (errno == EINTR) {
					continue;
				}
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					break;
				}
				if (listener_accept_error_retryable(errno)) {
					continue;
				}
				if (errno == EMFILE || errno == ENFILE) {
					LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot accept client connection: %s\n", strerror(errno));
					listener_backoff();
					break;
				}
				LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot accept client connection: %s\n", strerror(errno));
				exitcode = EXITCODE_INTERNAL;
				goto cleanup;
			}
			pid_t worker_pid = fork();
			if (worker_pid > 0) {
				close(client_fd);
				continue;
			}
			if (worker_pid < 0) {
				int saved_errno = errno;
				close(client_fd);
				LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot create worker process: %s\n", strerror(saved_errno));
				listener_backoff();
				break;
			}
			_exit(listener_worker_run(client_fd, &client_address, listener, &events, listener_pid, context));
		}
	}
cleanup:
	listener_resolver_destroy(context);
	listener_events_destroy(&events);
	listener_socket_close(listener);
	return exitcode;
}

/* section: functions (exported) */
int listener_run(conf *config, conf_cache *config_cache, const char *config_filename, const char *config_filename_full, const char *working_directory, const char *log_filename) {
	listener_context context = {
		.config = config,
		.config_cache = config_cache,
		.config_filename = config_filename,
		.config_filename_full = config_filename_full,
		.working_directory = working_directory
	};
	snprintf(context.log_filename, sizeof(context.log_filename), "%s", log_filename);
	int exitcode;
	listener_socket listener = { .fd = -1 };
	enum listener_endpoint_status endpoint_status = listener_endpoint_prepare(context.config, &listener.endpoint);
	if (endpoint_status == LISTENER_ENDPOINT_BAD_ADDRESS) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Error: Invalid bind address!\n");
		exitcode = EXITCODE_BINDFAIL;
		goto cleanup;
	}
	if (endpoint_status == LISTENER_ENDPOINT_BAD_PORT) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Error: Invalid bind port!\n");
		exitcode = EXITCODE_BADPORT;
		goto cleanup;
	}
	net_addrp bindaddrp = net_ntop(listener.endpoint.address.family, &(listener.endpoint.address.addr), true);
	LISTENER_LOG(&context, MKSYS_LEVEL_INFORMATION, "Binding on %s:%d...\n", (char *)&bindaddrp, listener.endpoint.port);
	if (listener_socket_bind(&listener) == -1) {
		LISTENER_LOG(&context, MKSYS_LEVEL_CRITICAL, "Bind Failed!\n");
		exitcode = EXITCODE_BINDFAIL;
		goto cleanup;
	}
	exitcode = listener_loop(&context, &listener);
cleanup:
	config_destroy(context.config);
	config_cache_destroy(context.config_cache);
	hosts_table_destroy(context.hosts);
	return exitcode;
}
