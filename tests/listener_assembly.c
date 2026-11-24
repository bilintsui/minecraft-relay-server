/*
 * listener_assembly.c: Absolute assembly deadlines and independent EOF checks
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "assembly_timer.h"

/* section: defines */
/* This budget bounds real EOF observation; every programmed deadline is checked separately for exact equality. */
#define ASSEMBLY_CLOSE_GRACE_SEC 60
#define ASSEMBLY_CONTROL_GRACE_SEC 1
#define ASSEMBLY_EVENT_LIMIT 16
#define ASSEMBLY_INIT_DELAY_SEC 3
#define ASSEMBLY_REFRESH_DELAY_SEC 1
#define ASSEMBLY_SETUP_TIMEOUT_SEC 60
#define ASSEMBLY_STOP_TIMEOUT_SEC 5

/* section: types */
typedef enum {
	ASSEMBLY_CASE_OK,
	ASSEMBLY_CASE_SETUP,
	ASSEMBLY_CASE_CHANNEL,
	ASSEMBLY_CASE_FLAGS,
	ASSEMBLY_CASE_INITIAL_DEADLINE,
	ASSEMBLY_CASE_MOVED_DEADLINE,
	ASSEMBLY_CASE_PHASE,
	ASSEMBLY_CASE_CLOSE_TIMEOUT,
	ASSEMBLY_CASE_PROTOCOL,
	ASSEMBLY_CASE_UPSTREAM,
	ASSEMBLY_CASE_CHILD
} assembly_case_result;

typedef struct {
	bool initialized, expired, closed, eof, log_started, log_finished, close_suppressed;
	unsigned int arm_mask, event_count;
	int socket_fd, timer_fd;
	struct timespec initial_clock, deadline, log_begin;
	assembly_timer_event last;
} assembly_case_state;

typedef struct {
	char directory[64], config[128], log[128], notify[128];
	int backend_fd, client_fd, notify_fd, channel_read, channel_write;
	pid_t child;
	in_port_t listen_port;
	assembly_case_state state;
} assembly_case_fixture;

/* section: functions (local) */
static int assembly_socket_open(in_port_t *port, bool listening) {
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t size = sizeof(address);
	if (fd == -1) {
		return -1;
	}
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == -1 || getsockname(fd, (struct sockaddr *)&address, &size) == -1 || (listening && listen(fd, 1) == -1)) {
		close(fd);
		return -1;
	}
	*port = ntohs(address.sin_port);
	return fd;
}

static bool assembly_fixture_prepare(assembly_case_fixture *fixture) {
	in_port_t backend_port;
	snprintf(fixture->directory, sizeof(fixture->directory), "%s", "/tmp/mcrelay-assembly-XXXXXX");
	if (mkdtemp(fixture->directory) == NULL) {
		return false;
	}
	snprintf(fixture->config, sizeof(fixture->config), "%s/config.json", fixture->directory);
	snprintf(fixture->log, sizeof(fixture->log), "%s/access.log", fixture->directory);
	snprintf(fixture->notify, sizeof(fixture->notify), "%s/notify.sock", fixture->directory);
	fixture->backend_fd = assembly_socket_open(&backend_port, true);
	int reservation = assembly_socket_open(&fixture->listen_port, false);
	if (reservation >= 0) {
		close(reservation);
	}
	if (fixture->backend_fd == -1 || reservation == -1) {
		return false;
	}
	fixture->notify_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	if (fixture->notify_fd == -1 || strlen(fixture->notify) >= sizeof(address.sun_path)) {
		return false;
	}
	strcpy(address.sun_path, fixture->notify);
	int channel[2];
	if (bind(fixture->notify_fd, (struct sockaddr *)&address, sizeof(address)) == -1 || pipe2(channel, O_CLOEXEC | O_NONBLOCK) == -1) {
		return false;
	}
	fixture->channel_read = channel[0];
	fixture->channel_write = channel[1];
	FILE *config = fopen(fixture->config, "w");
	if (config == NULL) {
		return false;
	}
	int written = fprintf(config,
		"{\"log\":{\"filename\":\"%s\",\"level\":4},\"listen\":{\"address\":\"127.0.0.1\",\"port\":%u},\"icon\":\"\","
		"\"proxy\":[{\"vhost\":[\"assembly.example\"],\"address\":\"127.0.0.1\",\"port\":%u}]}\n",
		fixture->log, (unsigned int)fixture->listen_port, (unsigned int)backend_port
	);
	int closed = fclose(config);
	return written > 0 && closed == 0;
}

static int assembly_time_compare(const struct timespec *left, const struct timespec *right) {
	if (left->tv_sec != right->tv_sec) {
		return left->tv_sec < right->tv_sec ? -1 : 1;
	}
	return left->tv_nsec == right->tv_nsec ? 0 : (left->tv_nsec < right->tv_nsec ? -1 : 1);
}

static assembly_case_result assembly_event_apply(assembly_case_fixture *fixture, const assembly_timer_event *event) {
	assembly_case_state *state = &fixture->state;
	state->last = *event;
	if (event->magic != ASSEMBLY_TIMER_MAGIC || event->pid != fixture->child || ++state->event_count > ASSEMBLY_EVENT_LIMIT) {
		return ASSEMBLY_CASE_CHANNEL;
	}
	if (event->kind == ASSEMBLY_TIMER_ARMED) {
		if (event->result != 0 || event->flags != TFD_TIMER_ABSTIME || event->clock_id != CLOCK_MONOTONIC
			|| event->setting.it_interval.tv_sec != 0 || event->setting.it_interval.tv_nsec != 0) {
			return ASSEMBLY_CASE_FLAGS;
		}
		if (!state->initialized) {
			struct timespec expected = event->initial_clock;
			expected.tv_sec += ASSEMBLY_TIMER_TIMEOUT_SEC;
			if (!event->initial_clock_valid || event->input_bytes != 0 || assembly_time_compare(&expected, &event->setting.it_value) != 0) {
				return ASSEMBLY_CASE_INITIAL_DEADLINE;
			}
			state->initialized = true;
			state->initial_clock = event->initial_clock;
			state->deadline = event->setting.it_value;
			state->socket_fd = event->socket_fd;
			state->timer_fd = event->fd;
		} else if (event->fd != state->timer_fd || event->socket_fd != state->socket_fd || assembly_time_compare(&event->setting.it_value, &state->deadline) != 0) {
			return ASSEMBLY_CASE_MOVED_DEADLINE;
		}
		if (event->input_bytes > 2) {
			return ASSEMBLY_CASE_PROTOCOL;
		}
		state->arm_mask |= 1U << event->input_bytes;
	} else {
		if (!state->initialized || event->socket_fd != state->socket_fd) {
			return ASSEMBLY_CASE_CHANNEL;
		}
		switch (event->kind) {
			case ASSEMBLY_TIMER_EXPIRED:
				if (event->fd != state->timer_fd || event->result != (int)sizeof(uint64_t) || event->expirations == 0 || assembly_time_compare(&event->observed_at, &state->deadline) < 0) {
					return ASSEMBLY_CASE_PROTOCOL;
				}
				state->expired = true;
				break;
			case ASSEMBLY_TIMER_CLOSED:
				if (!state->expired || event->fd != state->socket_fd || event->result != 0) {
					return ASSEMBLY_CASE_CHANNEL;
				}
				state->closed = true;
				break;
			case ASSEMBLY_TIMER_CLOSE_SUPPRESSED:
				if (!state->expired || event->fd != state->socket_fd || event->result != 0) {
					return ASSEMBLY_CASE_CHANNEL;
				}
				state->close_suppressed = true;
				break;
			case ASSEMBLY_TIMER_LOG_BEGIN:
				if (!state->expired || state->log_started) {
					return ASSEMBLY_CASE_PROTOCOL;
				}
				state->log_started = true;
				state->log_begin = event->observed_at;
				break;
			case ASSEMBLY_TIMER_LOG_END: {
				struct timespec minimum = state->log_begin;
				minimum.tv_sec += ASSEMBLY_TIMER_LOG_DELAY_MS / 1000;
				minimum.tv_nsec += (ASSEMBLY_TIMER_LOG_DELAY_MS % 1000) * 1000000L;
				if (minimum.tv_nsec >= 1000000000L) {
					minimum.tv_nsec -= 1000000000L;
					minimum.tv_sec++;
				}
				if (!state->log_started || state->log_finished || assembly_time_compare(&event->observed_at, &minimum) < 0) {
					return ASSEMBLY_CASE_PROTOCOL;
				}
				state->log_finished = true;
				break;
			}
			default:
				return ASSEMBLY_CASE_CHANNEL;
		}
	}
	return ASSEMBLY_CASE_OK;
}

static bool assembly_time_deadline(struct timespec *deadline, time_t seconds) {
	if (clock_gettime(CLOCK_MONOTONIC, deadline) == -1) {
		return false;
	}
	deadline->tv_sec += seconds;
	return true;
}

static bool assembly_sleep(time_t seconds) {
	struct timespec deadline;
	if (!assembly_time_deadline(&deadline, seconds)) {
		return false;
	}
	int result;
	do {
		result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
	} while (result == EINTR);
	return result == 0;
}

static int assembly_time_remaining(const struct timespec *deadline) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return -1;
	}
	if (assembly_time_compare(&now, deadline) >= 0) {
		return 0;
	}
	int64_t milliseconds = (int64_t)(deadline->tv_sec - now.tv_sec) * 1000 + (deadline->tv_nsec - now.tv_nsec + 999999L) / 1000000L;
	return milliseconds > INT_MAX ? INT_MAX : (int)(milliseconds > 0 ? milliseconds : 1);
}

static bool assembly_child_wait(pid_t child, int options, int *status) {
	struct timespec deadline;
	if (!assembly_time_deadline(&deadline, ASSEMBLY_STOP_TIMEOUT_SEC)) {
		return false;
	}
	const struct timespec pause = { .tv_nsec = 10000000 };
	while (true) {
		pid_t result = waitpid(child, status, options | WNOHANG);
		if (result == child) {
			return true;
		}
		if ((result == -1 && errno != EINTR) || assembly_time_remaining(&deadline) <= 0) {
			return false;
		}
		nanosleep(&pause, NULL);
	}
}

static assembly_case_result assembly_events_poll(assembly_case_fixture *fixture, const struct timespec *deadline, assembly_case_result timeout_result) {
	struct pollfd events[2] = {
		{ .fd = fixture->state.eof ? -1 : fixture->client_fd, .events = POLLIN },
		{ .fd = fixture->channel_read, .events = POLLIN }
	};
	int remaining = assembly_time_remaining(deadline);
	if (remaining <= 0) {
		return remaining == 0 ? timeout_result : ASSEMBLY_CASE_SETUP;
	}
	int result = poll(events, 2, remaining);
	if (result == -1 && errno == EINTR) {
		return ASSEMBLY_CASE_OK;
	}
	if (result <= 0) {
		return result == 0 ? timeout_result : ASSEMBLY_CASE_SETUP;
	}
	if (events[0].revents != 0 && !fixture->state.eof) {
		uint8_t byte;
		ssize_t size = recv(fixture->client_fd, &byte, sizeof(byte), MSG_DONTWAIT);
		if (size == 0) {
			fixture->state.eof = true;
		} else if (size > 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
			return ASSEMBLY_CASE_PROTOCOL;
		}
	}
	/* Drain observations after checking EOF: all observations preceding close must then already be available. */
	while (true) {
		assembly_timer_event event;
		ssize_t size = read(fixture->channel_read, &event, sizeof(event));
		if (size == -1 && errno == EINTR) {
			continue;
		}
		if (size == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			break;
		}
		if (size != (ssize_t)sizeof(event)) {
			return ASSEMBLY_CASE_CHANNEL;
		}
		assembly_case_result observed = assembly_event_apply(fixture, &event);
		if (observed != ASSEMBLY_CASE_OK) {
			return observed;
		}
	}
	return ASSEMBLY_CASE_OK;
}

static bool assembly_fixture_connect(assembly_case_fixture *fixture) {
	fixture->client_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(fixture->listen_port) };
	if (fixture->client_fd == -1) {
		return false;
	}
	if (connect(fixture->client_fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
		return true;
	}
	if (errno != EINPROGRESS) {
		return false;
	}
	struct pollfd event = { .fd = fixture->client_fd, .events = POLLOUT };
	struct timespec deadline;
	if (!assembly_time_deadline(&deadline, ASSEMBLY_SETUP_TIMEOUT_SEC)) {
		return false;
	}
	while (true) {
		int remaining = assembly_time_remaining(&deadline);
		if (remaining <= 0) {
			return false;
		}
		int result = poll(&event, 1, remaining);
		if (result == -1 && errno == EINTR) continue;
		int error = 0;
		socklen_t size = sizeof(error);
		return result > 0 && getsockopt(fixture->client_fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0;
	}
}

static bool assembly_fixture_destroy(assembly_case_fixture *fixture) {
	bool result = true;
	if (fixture->child > 0) {
		int status;
		kill(fixture->child, SIGCONT);
		kill(fixture->child, SIGTERM);
		if (!assembly_child_wait(fixture->child, 0, &status)) {
			kill(fixture->child, SIGKILL);
			assembly_child_wait(fixture->child, 0, &status);
			result = false;
		} else {
			result = WIFEXITED(status) && WEXITSTATUS(status) == 0;
		}
	}
	int descriptors[] = { fixture->backend_fd, fixture->client_fd, fixture->notify_fd, fixture->channel_read, fixture->channel_write };
	for (size_t index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]); index++) {
		if (descriptors[index] >= 0) close(descriptors[index]);
	}
	if (result) {
		unlink(fixture->config);
		unlink(fixture->log);
		unlink(fixture->notify);
		if (fixture->directory[0] != '\0') rmdir(fixture->directory);
	}
	return result;
}

static assembly_case_result assembly_wait_arm(assembly_case_fixture *fixture, uint64_t input_bytes) {
	struct timespec deadline;
	if (!assembly_time_deadline(&deadline, ASSEMBLY_SETUP_TIMEOUT_SEC)) {
		return ASSEMBLY_CASE_SETUP;
	}
	while (!(fixture->state.arm_mask & (1U << input_bytes))) {
		assembly_case_result result = assembly_events_poll(fixture, &deadline, ASSEMBLY_CASE_PHASE);
		if (result != ASSEMBLY_CASE_OK) {
			return result;
		}
		if (!(fixture->state.arm_mask & (1U << input_bytes)) && (fixture->state.eof || fixture->state.closed || fixture->state.expired)) {
			return ASSEMBLY_CASE_PHASE;
		}
	}
	return ASSEMBLY_CASE_OK;
}

static bool assembly_wait_ready(const assembly_case_fixture *fixture) {
	struct timespec deadline;
	if (!assembly_time_deadline(&deadline, ASSEMBLY_SETUP_TIMEOUT_SEC)) {
		return false;
	}
	while (true) {
		int remaining = assembly_time_remaining(&deadline);
		struct pollfd events[2] = {
			{ .fd = fixture->notify_fd, .events = POLLIN },
			{ .fd = fixture->channel_read, .events = POLLIN }
		};
		if (remaining <= 0) {
			return false;
		}
		int result = poll(events, 2, remaining);
		if (result == -1 && errno == EINTR) {
			continue;
		}
		if (result <= 0 || events[1].revents != 0) {
			return false;
		}
		if (events[0].revents & POLLIN) {
			char message[64];
			ssize_t size = recv(fixture->notify_fd, message, sizeof(message), 0);
			return size == 7 && memcmp(message, "READY=1", 7) == 0;
		}
	}
}

static bool assembly_fixture_start(assembly_case_fixture *fixture, const char *binary, assembly_timer_fault fault) {
	pid_t parent = getpid();
	fixture->child = fork();
	if (fixture->child == 0) {
		char channel[32], mode[32];
		snprintf(channel, sizeof(channel), "%d", fixture->channel_write);
		snprintf(mode, sizeof(mode), "%d", (int)fault);
		int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (null_fd == -1 || prctl(PR_SET_PDEATHSIG, SIGKILL) == -1 || getppid() != parent
			|| dup2(null_fd, STDIN_FILENO) == -1 || dup2(null_fd, STDOUT_FILENO) == -1 || dup2(null_fd, STDERR_FILENO) == -1
			|| fcntl(fixture->channel_write, F_SETFD, 0) == -1 || setenv("NOTIFY_SOCKET", fixture->notify, 1) == -1
			|| setenv(ASSEMBLY_TIMER_CHANNEL_ENV, channel, 1) == -1 || setenv(ASSEMBLY_TIMER_FAULT_ENV, mode, 1) == -1
			|| setenv(ASSEMBLY_TIMER_LOG_ENV, fixture->log, 1) == -1) {
			_exit(EXIT_FAILURE);
		}
		if (null_fd > STDERR_FILENO) close(null_fd);
		close(fixture->backend_fd);
		close(fixture->notify_fd);
		close(fixture->channel_read);
		execl(binary, binary, "run", "-c", fixture->config, (char *)NULL);
		_exit(EXIT_FAILURE);
	}
	close(fixture->channel_write);
	fixture->channel_write = -1;
	return fixture->child > 0 && assembly_wait_ready(fixture);
}

static bool assembly_case_run(const char *binary, const char *name, assembly_timer_fault fault, bool delayed_accept, assembly_case_result expected) {
	assembly_case_fixture fixture;
	memset(&fixture, 0, sizeof(fixture));
	fixture.backend_fd = fixture.client_fd = fixture.notify_fd = fixture.channel_read = fixture.channel_write = -1;
	fixture.child = -1;
	assembly_case_result result = ASSEMBLY_CASE_SETUP;
	const char *phase = "prepare";
	if (!assembly_fixture_prepare(&fixture) || !assembly_fixture_start(&fixture, binary, fault)) goto cleanup;
	if (delayed_accept) {
		int status;
		phase = "stop-before-accept";
		if (kill(fixture.child, SIGSTOP) == -1 || !assembly_child_wait(fixture.child, WUNTRACED, &status) || !WIFSTOPPED(status)) goto cleanup;
	}
	phase = "connect";
	if (!assembly_fixture_connect(&fixture)) goto cleanup;
	if (delayed_accept && (!assembly_sleep(ASSEMBLY_INIT_DELAY_SEC) || kill(fixture.child, SIGCONT) == -1)) goto cleanup;
	phase = "initial-arm";
	result = assembly_wait_arm(&fixture, 0);
	if (result != ASSEMBLY_CASE_OK) goto cleanup;
	phase = "first-fragment";
	uint8_t byte = 0x7F;
	if (send(fixture.client_fd, &byte, 1, MSG_NOSIGNAL) != 1) {
		result = ASSEMBLY_CASE_PROTOCOL;
		goto cleanup;
	}
	result = assembly_wait_arm(&fixture, 1);
	if (result != ASSEMBLY_CASE_OK) goto cleanup;
	phase = "second-fragment";
	if (!assembly_sleep(ASSEMBLY_REFRESH_DELAY_SEC)) {
		result = ASSEMBLY_CASE_SETUP;
		goto cleanup;
	}
	byte = 0;
	if (send(fixture.client_fd, &byte, 1, MSG_NOSIGNAL) != 1) {
		result = ASSEMBLY_CASE_PROTOCOL;
		goto cleanup;
	}
	result = assembly_wait_arm(&fixture, 2);
	if (result != ASSEMBLY_CASE_OK) goto cleanup;
	phase = "expiry-and-eof";
	struct timespec deadline = fixture.state.deadline;
	deadline.tv_sec += ASSEMBLY_CLOSE_GRACE_SEC;
	if (fault == ASSEMBLY_TIMER_DROP_CLOSE) {
		while (!fixture.state.close_suppressed) {
			result = assembly_events_poll(&fixture, &deadline, ASSEMBLY_CASE_PHASE);
			if (result != ASSEMBLY_CASE_OK) goto cleanup;
		}
		if (!assembly_time_deadline(&deadline, ASSEMBLY_CONTROL_GRACE_SEC)) {
			result = ASSEMBLY_CASE_SETUP;
			goto cleanup;
		}
	}
	while (!fixture.state.expired || !fixture.state.closed || !fixture.state.eof || (fault == ASSEMBLY_TIMER_LOG_DELAY && !fixture.state.log_finished)) {
		result = assembly_events_poll(&fixture, &deadline, ASSEMBLY_CASE_CLOSE_TIMEOUT);
		if (result != ASSEMBLY_CASE_OK) {
			if (fault == ASSEMBLY_TIMER_DROP_CLOSE && (fixture.state.eof || fixture.state.closed)) result = ASSEMBLY_CASE_PROTOCOL;
			goto cleanup;
		}
	}
	phase = "no-upstream";
	struct pollfd upstream = { .fd = fixture.backend_fd, .events = POLLIN };
	result = poll(&upstream, 1, 0) == 0 ? ASSEMBLY_CASE_OK : ASSEMBLY_CASE_UPSTREAM;
	if (kill(fixture.child, 0) == -1) result = ASSEMBLY_CASE_CHILD;
cleanup:
	if (!assembly_fixture_destroy(&fixture)) result = ASSEMBLY_CASE_CHILD;
	fprintf(stderr,
		"assembly case=%s phase=%s result=%u expected=%u arms=%u expired=%u closed=%u eof=%u io=%u/%u deadline=%lld.%09ld last=%u bytes=%llu errno=%d root=%s\n",
		name, phase, (unsigned int)result, (unsigned int)expected, fixture.state.arm_mask, fixture.state.expired, fixture.state.closed, fixture.state.eof,
		fixture.state.log_started, fixture.state.log_finished, (long long)fixture.state.deadline.tv_sec, fixture.state.deadline.tv_nsec,
		(unsigned int)fixture.state.last.kind, (unsigned long long)fixture.state.last.input_bytes, fixture.state.last.error, fixture.directory
	);
	return result == expected;
}

/* section: functions (entry point) */
int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "assembly daemon and case name are required\n");
		return EXIT_FAILURE;
	}
	bool result;
	if (strcmp(argv[2], "accept-delay") == 0) {
		result = assembly_case_run(argv[1], argv[2], ASSEMBLY_TIMER_NORMAL, true, ASSEMBLY_CASE_OK);
	} else if (strcmp(argv[2], "log-delay") == 0) {
		result = assembly_case_run(argv[1], argv[2], ASSEMBLY_TIMER_LOG_DELAY, false, ASSEMBLY_CASE_OK);
	} else if (strcmp(argv[2], "controls") == 0) {
		result = assembly_case_run(argv[1], "relative", ASSEMBLY_TIMER_RELATIVE, false, ASSEMBLY_CASE_FLAGS)
			&& assembly_case_run(argv[1], "wrong-initial", ASSEMBLY_TIMER_WRONG_INITIAL, false, ASSEMBLY_CASE_INITIAL_DEADLINE)
			&& assembly_case_run(argv[1], "sliding", ASSEMBLY_TIMER_SLIDING, false, ASSEMBLY_CASE_MOVED_DEADLINE)
			&& assembly_case_run(argv[1], "unclosed", ASSEMBLY_TIMER_DROP_CLOSE, false, ASSEMBLY_CASE_CLOSE_TIMEOUT);
	} else {
		fprintf(stderr, "unknown assembly test case: %s\n", argv[2]);
		return EXIT_FAILURE;
	}
	return result ? EXIT_SUCCESS : EXIT_FAILURE;
}
