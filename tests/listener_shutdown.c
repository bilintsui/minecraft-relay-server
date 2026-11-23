/*
 * listener_shutdown.c: Stop-priority and resolver-helper recovery integration tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s: %s (errno=%d)\n", name, message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* bounds */
#define SHUTDOWN_HELPER_LIMIT	128
#define SHUTDOWN_POLL_MS	10
#define SHUTDOWN_TIMEOUT_MS	5000

/* section: types */
typedef struct {
	uint64_t spawn_attempt;
	uint64_t spawn_success;
	uint64_t failure_exit;
	uint64_t failure_io;
	uint64_t failure_protocol;
	uint64_t failure_spawn;
	uint64_t failure_timeout;
	uint64_t observation_dropped;
	uint64_t state_stopped;
} helper_metrics;

/* section: functions (local) */
static pid_t daemon_start(const char *binary, const char *config_filename) {
	pid_t process = fork();
	if (process != 0) {
		return process;
	}
	int null_fd = open("/dev/null", O_RDWR);
	if (setpgid(0, 0) == -1 || null_fd == -1 || dup2(null_fd, STDIN_FILENO) == -1 || dup2(null_fd, STDOUT_FILENO) == -1 || dup2(null_fd, STDERR_FILENO) == -1
		|| unsetenv("NOTIFY_SOCKET") == -1) {
		_exit(EXIT_FAILURE);
	}
	if (null_fd > STDERR_FILENO) {
		close(null_fd);
	}
	execl(binary, binary, "run", "-c", config_filename, (char *)NULL);
	_exit(EXIT_FAILURE);
}

static bool delay(void) {
	struct timespec interval = { .tv_nsec = SHUTDOWN_POLL_MS * 1000000L };
	while (nanosleep(&interval, &interval) == -1) {
		if (errno != EINTR) {
			return false;
		}
	}
	return true;
}

static bool helpers_read(pid_t parent, pid_t *helpers, size_t *count) {
	char filename[128];
	int length = snprintf(filename, sizeof(filename), "/proc/%ld/task/%ld/children", (long)parent, (long)parent);
	if (length < 0 || (size_t)length >= sizeof(filename)) {
		return false;
	}
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		return false;
	}
	*count = 0;
	long process;
	while (fscanf(file, "%ld", &process) == 1) {
		if (process <= 0 || process > INT_MAX || *count == SHUTDOWN_HELPER_LIMIT) {
			fclose(file);
			errno = EOVERFLOW;
			return false;
		}
		helpers[(*count)++] = (pid_t)process;
	}
	bool valid = feof(file) && !ferror(file);
	return fclose(file) == 0 && valid;
}

static bool helpers_replaced(pid_t parent, pid_t replaced, size_t expected) {
	for (int elapsed = 0; elapsed < SHUTDOWN_TIMEOUT_MS; elapsed += SHUTDOWN_POLL_MS) {
		pid_t helpers[SHUTDOWN_HELPER_LIMIT];
		size_t count;
		if (!helpers_read(parent, helpers, &count)) {
			return false;
		}
		bool found = false;
		for (size_t index = 0; index < count; index++) {
			found = found || helpers[index] == replaced;
		}
		if (!found && count == expected) {
			return true;
		}
		if (!delay()) {
			return false;
		}
	}
	errno = ETIMEDOUT;
	return false;
}

static bool metric_read(const char *line, const char *key, uint64_t *result) {
	char pattern[64];
	int length = snprintf(pattern, sizeof(pattern), " %s=", key);
	if (length < 0 || (size_t)length >= sizeof(pattern)) {
		return false;
	}
	const char *value = strstr(line, pattern);
	if (value == NULL) {
		return false;
	}
	value += (size_t)length;
	char *end;
	errno = 0;
	unsigned long long parsed = strtoull(value, &end, 10);
	if (errno != 0 || end == value || (*end != ' ' && *end != '\n') || parsed > UINT64_MAX) {
		return false;
	}
	*result = (uint64_t)parsed;
	return true;
}

static bool metrics_read(const char *filename, helper_metrics *first, helper_metrics *last, size_t *snapshots, size_t *events, bool *shutdown_seen) {
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		return false;
	}
	char line[4096];
	bool valid = true;
	*snapshots = 0;
	*events = 0;
	*shutdown_seen = false;
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strstr(line, "] [WARN] resolver_helper ") != NULL || strstr(line, "] [INFO] resolver_helper ") != NULL) {
			(*events)++;
		}
		if (strstr(line, " family=meta ") != NULL && strstr(line, " reason=shutdown lines=48 ") != NULL) {
			*shutdown_seen = true;
		}
		if (strstr(line, "] [INFO] metrics schema=1 ") == NULL || strstr(line, " family=helper ") == NULL) {
			continue;
		}
		helper_metrics current;
		if (!metric_read(line, "spawn_attempt", &current.spawn_attempt) || !metric_read(line, "spawn_success", &current.spawn_success)
			|| !metric_read(line, "failure_exit", &current.failure_exit) || !metric_read(line, "failure_io", &current.failure_io)
			|| !metric_read(line, "failure_protocol", &current.failure_protocol) || !metric_read(line, "failure_spawn", &current.failure_spawn)
			|| !metric_read(line, "failure_timeout", &current.failure_timeout) || !metric_read(line, "observation_dropped", &current.observation_dropped)
			|| !metric_read(line, "state_stopped", &current.state_stopped)) {
			valid = false;
			break;
		}
		if ((*snapshots)++ == 0) {
			*first = current;
		}
		*last = current;
	}
	valid = valid && !ferror(file);
	return fclose(file) == 0 && valid;
}

static bool process_wait(pid_t *process, int options, int *status) {
	for (int elapsed = 0; elapsed < SHUTDOWN_TIMEOUT_MS; elapsed += SHUTDOWN_POLL_MS) {
		pid_t result = waitpid(*process, status, WNOHANG | options);
		if (result == *process) {
			if (WIFEXITED(*status) || WIFSIGNALED(*status)) {
				*process = -1;
			}
			return true;
		}
		if ((result == -1 && errno != EINTR) || !delay()) {
			return false;
		}
	}
	errno = ETIMEDOUT;
	return false;
}

static bool process_zombie(pid_t process) {
	char filename[64];
	int length = snprintf(filename, sizeof(filename), "/proc/%ld/status", (long)process);
	if (length < 0 || (size_t)length >= sizeof(filename)) {
		return false;
	}
	for (int elapsed = 0; elapsed < SHUTDOWN_TIMEOUT_MS; elapsed += SHUTDOWN_POLL_MS) {
		FILE *file = fopen(filename, "r");
		if (file == NULL) {
			return false;
		}
		char line[256];
		char state = '\0';
		while (fgets(line, sizeof(line), file) != NULL && sscanf(line, "State: %c", &state) != 1) {
		}
		if (fclose(file) == EOF) {
			return false;
		}
		if (state == 'Z') {
			return true;
		}
		if (!delay()) {
			return false;
		}
	}
	errno = ETIMEDOUT;
	return false;
}

static bool run_case(const char *binary, const char *name, int stop_signal, size_t stop_helpers, bool recovery) {
	bool passed = false;
	char directory[] = "/tmp/mcrelay-shutdown-XXXXXX";
	char config_filename[PATH_MAX] = "";
	char log_filename[PATH_MAX] = "";
	pid_t listener = -1;
	int reservation = -1;
	FILE *config = NULL;
	bool directory_created = false;
	CHECK(mkdtemp(directory) != NULL, "cannot create fixture directory");
	directory_created = true;
	CHECK(snprintf(config_filename, sizeof(config_filename), "%s/config.json", directory) > 0
		&& snprintf(log_filename, sizeof(log_filename), "%s/access.log", directory) > 0, "cannot format fixture paths");
	reservation = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(reservation >= 0, "cannot reserve a loopback port");
	struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t address_size = sizeof(address);
	CHECK(bind(reservation, (const struct sockaddr *)&address, sizeof(address)) == 0
		&& getsockname(reservation, (struct sockaddr *)&address, &address_size) == 0, "cannot obtain a loopback port");
	CHECK(close(reservation) == 0, "cannot release reserved port");
	reservation = -1;
	config = fopen(config_filename, "w");
	CHECK(config != NULL, "cannot create configuration");
	int written = fprintf(config,
		"{\"log\":{\"filename\":\"%s\",\"level\":2},\"metrics\":{\"interval\":900},\"listen\":{\"address\":\"127.0.0.1\",\"port\":%u},"
		"\"proxy\":[{\"vhost\":\"shutdown.example\",\"address\":\"127.0.0.1\",\"port\":9}]}\n",
		log_filename, (unsigned int)ntohs(address.sin_port)
	);
	CHECK(written > 0, "cannot write configuration");
	int close_result = fclose(config);
	config = NULL;
	CHECK(close_result == 0, "cannot close configuration");
	listener = daemon_start(binary, config_filename);
	CHECK(listener > 0, "cannot start listener");
	helper_metrics first = { 0 };
	helper_metrics last = { 0 };
	size_t snapshots = 0;
	size_t events = 0;
	bool shutdown_seen = false;
	for (int elapsed = 0; elapsed < SHUTDOWN_TIMEOUT_MS; elapsed += SHUTDOWN_POLL_MS) {
		if (metrics_read(log_filename, &first, &last, &snapshots, &events, &shutdown_seen) && snapshots == 1) {
			break;
		}
		CHECK(delay(), "cannot wait for startup metrics");
	}
	CHECK(snapshots == 1 && first.spawn_success > 0 && first.spawn_attempt == first.spawn_success, "startup helper metrics missing or invalid");
	pid_t helpers[SHUTDOWN_HELPER_LIMIT];
	size_t helper_count;
	CHECK(helpers_read(listener, helpers, &helper_count) && helper_count == first.spawn_success, "startup helper child count disagrees with metrics");
	if (recovery) {
		CHECK(kill(helpers[0], SIGTERM) == 0 && helpers_replaced(listener, helpers[0], helper_count), "running helper was not replaced");
	}
	CHECK(kill(listener, SIGSTOP) == 0, "cannot stop listener to assemble one event batch");
	int status;
	CHECK(process_wait(&listener, WUNTRACED, &status) && WIFSTOPPED(status), "listener did not stop");
	CHECK(helpers_read(listener, helpers, &helper_count) && helper_count == first.spawn_success, "stopped listener lost its helper children");
	CHECK(kill(listener, stop_signal) == 0, "cannot queue listener stop signal");
	size_t stopped = stop_helpers < helper_count ? stop_helpers : helper_count;
	for (size_t index = 0; index < stopped; index++) {
		CHECK(kill(helpers[index], stop_signal) == 0, "cannot terminate helper during group stop");
	}
	/* The stopped parent cannot reap these PIDs: zombie state proves channel closure is ready before SIGCONT. */
	for (size_t index = 0; index < stopped; index++) {
		CHECK(process_zombie(helpers[index]), "helper did not exit before the stop batch");
	}
	CHECK(kill(listener, SIGCONT) == 0, "cannot resume listener");
	CHECK(process_wait(&listener, 0, &status) && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS, "listener did not shut down successfully");
	CHECK(metrics_read(log_filename, &first, &last, &snapshots, &events, &shutdown_seen) && snapshots == 2 && shutdown_seen, "final shutdown metrics missing");
	uint64_t expected_recovery = recovery ? 1U : 0U;
	CHECK(last.spawn_attempt == first.spawn_attempt + expected_recovery && last.spawn_success == first.spawn_success + expected_recovery,
		"shutdown respawned resolver helpers");
	CHECK(last.failure_exit == expected_recovery && last.failure_io == 0 && last.failure_protocol == 0 && last.failure_spawn == 0 && last.failure_timeout == 0,
		"shutdown counted an expected helper exit as a failure");
	CHECK(events == expected_recovery && last.observation_dropped == 0, "shutdown emitted unexpected helper observations");
	CHECK(last.state_stopped == first.spawn_success, "shutdown did not stop every helper");
	passed = true;

cleanup:
	if (listener > 0) {
		(void)kill(-listener, SIGKILL);
		while (waitpid(listener, NULL, 0) == -1 && errno == EINTR) {
		}
	}
	if (config != NULL) {
		fclose(config);
	}
	if (reservation >= 0) {
		close(reservation);
	}
	unlink(config_filename);
	unlink(log_filename);
	if (directory_created && rmdir(directory) == -1 && errno != ENOENT) {
		passed = false;
	}
	return passed;
}

/* section: functions (entry point) */
int main(int argc, char **argv) {
	if (argc != 2 && argc != 3) {
		fprintf(stderr, "usage: %s DAEMON [CASE]\n", argv[0]);
		return EXIT_FAILURE;
	}
	const struct {
		const char *name;
		int signal;
		size_t helpers;
		bool recovery;
	} cases[] = {
		{ "term-main", SIGTERM, 0, false },
		{ "term-one-helper", SIGTERM, 1, false },
		{ "term-all-helpers", SIGTERM, SIZE_MAX, false },
		{ "int-all-helpers", SIGINT, SIZE_MAX, false },
		{ "helper-recovery", SIGTERM, 0, true }
	};
	bool selected = false;
	for (size_t index = 0; index < sizeof(cases) / sizeof(*cases); index++) {
		if (argc == 3 && strcmp(argv[2], cases[index].name) != 0) {
			continue;
		}
		selected = true;
		if (!run_case(argv[1], cases[index].name, cases[index].signal, cases[index].helpers, cases[index].recovery)) {
			return EXIT_FAILURE;
		}
	}
	return selected ? EXIT_SUCCESS : EXIT_FAILURE;
}
