/*
 * worker_cap.c: Tests for the live worker process limit and reliable reaping
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d: %s)\n", message, errno, strerror(errno)); \
			goto cleanup; \
		} \
	} while (0)

/* timeout */
#define WORKER_CAP_CLOSE_TIMEOUT_MS	2000
#define WORKER_CAP_LOG_TIMEOUT_MS	2000
#define WORKER_CAP_QUIET_TIMEOUT_MS	250
#define WORKER_CAP_TEST_TIMEOUT_MS	5000
#define WORKER_CAP_WAIT_INTERVAL_MS	10
#define WORKER_CAP_PENDING_MIN_MS	500
#define WORKER_CAP_PENDING_MAX_MS	3500

/* section: types */
typedef struct {
	size_t direct;
	size_t workers;
} child_snapshot;

/* section: functions (local) */
static int backend_accept(int server_fd, int timeout_ms);
static int backend_quiet(int server_fd, int timeout_ms);
static int child_snapshot_read(pid_t parent, child_snapshot *result);
static int child_snapshot_wait(pid_t parent, size_t expected_workers, int timeout_ms, child_snapshot *result);
static int client_connect(in_port_t port);
static void client_drop(int *socket_fd);
static int connection_cap_probe(in_port_t port);
static pid_t daemon_start(const char *binary, const char *config_filename, const char *notify_filename, bool pending_connect, const char *refusal_marker_filename);
static void daemon_stop(pid_t *process);
static bool deadline_create(struct timespec *deadline, int timeout_ms);
static int deadline_remaining_ms(const struct timespec *deadline);
static int file_message_count(const char *filename, const char *message);
static size_t handshake_build(uint8_t *destination, const char *vhost, in_port_t port, uint32_t next_state);
static int log_count_wait(const char *filename, const char *message, int minimum, int timeout_ms);
static void log_dump(const char *filename);
static ssize_t message_receive(int socket_fd, void *data, size_t capacity, int timeout_ms);
static ssize_t notification_receive(int notify_fd, char *message, size_t capacity, int timeout_ms);
static int notification_reload(int notify_fd, int timeout_ms);
static int pending_connect_test(const char *binary);
static int process_wait(pid_t process, int timeout_ms);
static int refusal_probe(in_port_t port, const uint8_t *packet, size_t packet_size, bool legacy);
static bool refusal_response_validate(const uint8_t *response, size_t response_size, bool legacy);
static int run_cap_test(const char *binary);
static int server_open(in_port_t *port);
static int socket_expect_close(int socket_fd, int timeout_ms);
static int socket_send_all(int socket_fd, const void *data, size_t size);
static size_t status_response_build(uint8_t *destination, size_t destination_capacity);
static size_t varint_encode(uint8_t *destination, uint32_t value);
static size_t varint_size(uint32_t value);

static int backend_accept(int server_fd, int timeout_ms) {
	struct pollfd event = { .fd = server_fd, .events = POLLIN };
	int poll_result;
	do {
		poll_result = poll(&event, 1, timeout_ms);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result == 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	if (poll_result == -1) {
		return -1;
	}
	if (!(event.revents & POLLIN)) {
		errno = EIO;
		return -1;
	}
	return accept(server_fd, NULL, NULL);
}

static int backend_quiet(int server_fd, int timeout_ms) {
	struct pollfd event = { .fd = server_fd, .events = POLLIN };
	int poll_result;
	do {
		poll_result = poll(&event, 1, timeout_ms);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result == 0) {
		return 0;
	}
	if (poll_result == -1) {
		return -1;
	}
	errno = event.revents & POLLIN ? EBUSY : EIO;
	return -1;
}

static int child_snapshot_read(pid_t parent, child_snapshot *result) {
	DIR *processes;
	struct dirent *entry;
	child_snapshot snapshot = { 0 };
	if (parent <= 0 || result == NULL) {
		errno = EINVAL;
		return -1;
	}
	processes = opendir("/proc");
	if (processes == NULL) {
		return -1;
	}
	while ((entry = readdir(processes)) != NULL) {
		char *end = NULL;
		char status_filename[PATH_MAX];
		char process_name[64];
		char line[256];
		FILE *status;
		long process_number;
		long process_parent = -1;
		bool parent_found = false;
		errno = 0;
		process_number = strtol(entry->d_name, &end, 10);
		if (errno != 0 || end == entry->d_name || *end != '\0' || process_number <= 0) {
			continue;
		}
		int filename_length = snprintf(status_filename, sizeof(status_filename), "/proc/%ld/status", process_number);
		if (filename_length < 0 || (size_t)filename_length >= sizeof(status_filename)) {
			continue;
		}
		status = fopen(status_filename, "r");
		if (status == NULL) {
			continue;
		}
		while (fgets(line, sizeof(line), status) != NULL) {
			if (sscanf(line, "PPid:\t%ld", &process_parent) == 1) {
				parent_found = true;
				break;
			}
		}
		fclose(status);
		if (!parent_found || process_parent != (long)parent) {
			continue;
		}
		snapshot.direct++;
		filename_length = snprintf(status_filename, sizeof(status_filename), "/proc/%ld/comm", process_number);
		if (filename_length < 0 || (size_t)filename_length >= sizeof(status_filename)) {
			continue;
		}
		FILE *name_file = fopen(status_filename, "r");
		if (name_file == NULL) {
			continue;
		}
		bool name_read = fgets(process_name, sizeof(process_name), name_file) != NULL;
		fclose(name_file);
		if (name_read) {
			process_name[strcspn(process_name, "\n")] = '\0';
			if (strcmp(process_name, "worker") == 0) {
				snapshot.workers++;
			}
		}
	}
	closedir(processes);
	*result = snapshot;
	return 0;
}

static int child_snapshot_wait(pid_t parent, size_t expected_workers, int timeout_ms, child_snapshot *result) {
	const struct timespec interval = { .tv_nsec = WORKER_CAP_WAIT_INTERVAL_MS * 1000000L };
	for (int elapsed_ms = 0; elapsed_ms <= timeout_ms; elapsed_ms += WORKER_CAP_WAIT_INTERVAL_MS) {
		child_snapshot snapshot;
		if (child_snapshot_read(parent, &snapshot) == 0 && snapshot.workers == expected_workers) {
			if (result != NULL) {
				*result = snapshot;
			}
			return 0;
		}
		nanosleep(&interval, NULL);
	}
	errno = ETIMEDOUT;
	return -1;
}

static int client_connect(in_port_t port) {
	int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_fd == -1) {
		return -1;
	}
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port)
	};
	if (connect(socket_fd, (const struct sockaddr *)&address, sizeof(address)) == -1) {
		int saved_errno = errno;
		close(socket_fd);
		errno = saved_errno;
		return -1;
	}
	return socket_fd;
}

static void client_drop(int *socket_fd) {
	if (socket_fd != NULL && *socket_fd >= 0) {
		shutdown(*socket_fd, SHUT_RDWR);
		close(*socket_fd);
		*socket_fd = -1;
	}
}

static int connection_cap_probe(in_port_t port) {
	static const uint8_t incomplete_packet = 0x80;
	int socket_fd = client_connect(port);
	if (socket_fd == -1) {
		return -1;
	}
	if (socket_send_all(socket_fd, &incomplete_packet, sizeof(incomplete_packet)) == -1 && errno != EPIPE && errno != ECONNRESET && errno != ENOTCONN) {
		int saved_errno = errno;
		close(socket_fd);
		errno = saved_errno;
		return -1;
	}
	int result = socket_expect_close(socket_fd, WORKER_CAP_CLOSE_TIMEOUT_MS);
	int saved_errno = errno;
	close(socket_fd);
	errno = saved_errno;
	return result;
}

static pid_t daemon_start(const char *binary, const char *config_filename, const char *notify_filename, bool pending_connect, const char *refusal_marker_filename) {
	struct sigaction ignored_action = { 0 };
	struct sigaction previous_action;
	ignored_action.sa_handler = SIG_IGN;
	sigemptyset(&ignored_action.sa_mask);
	if (sigaction(SIGCHLD, &ignored_action, &previous_action) == -1) {
		return -1;
	}
	pid_t process = fork();
	if (process == 0) {
		int devnull_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (devnull_fd == -1 || dup2(devnull_fd, STDOUT_FILENO) == -1 || dup2(devnull_fd, STDERR_FILENO) == -1
			|| setenv("NOTIFY_SOCKET", notify_filename, 1) == -1
			|| (pending_connect && setenv("MCRELAY_TEST_CONNECT_PENDING", "1", 1) == -1)
			|| (refusal_marker_filename != NULL && setenv("MCRELAY_TEST_REFUSAL_PARTIAL", refusal_marker_filename, 1) == -1)) {
			_exit(EXIT_FAILURE);
		}
		if (devnull_fd > STDERR_FILENO) {
			close(devnull_fd);
		}
		execl(binary, binary, "run", "-c", config_filename, (char *)NULL);
		_exit(EXIT_FAILURE);
	}
	int saved_errno = errno;
	if (sigaction(SIGCHLD, &previous_action, NULL) == -1 && process > 0) {
		int restore_errno = errno;
		kill(process, SIGKILL);
		waitpid(process, NULL, 0);
		errno = restore_errno;
		return -1;
	}
	errno = saved_errno;
	return process;
}

static void daemon_stop(pid_t *process) {
	if (process == NULL || *process <= 0) {
		return;
	}
	if (kill(*process, SIGTERM) == -1 && errno != ESRCH) {
		kill(*process, SIGKILL);
	}
	if (process_wait(*process, WORKER_CAP_TEST_TIMEOUT_MS) == -1) {
		kill(*process, SIGKILL);
		waitpid(*process, NULL, 0);
	}
	*process = -1;
}

static bool deadline_create(struct timespec *deadline, int timeout_ms) {
	if (deadline == NULL || timeout_ms < 1 || clock_gettime(CLOCK_MONOTONIC, deadline) == -1) {
		return false;
	}
	deadline->tv_sec += timeout_ms / 1000;
	deadline->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
	if (deadline->tv_nsec >= 1000000000L) {
		deadline->tv_sec++;
		deadline->tv_nsec -= 1000000000L;
	}
	return true;
}

static int deadline_remaining_ms(const struct timespec *deadline) {
	struct timespec now;
	if (deadline == NULL || clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		return -1;
	}
	int64_t seconds = (int64_t)deadline->tv_sec - (int64_t)now.tv_sec;
	int64_t nanoseconds = (int64_t)deadline->tv_nsec - (int64_t)now.tv_nsec;
	if (nanoseconds < 0) {
		seconds--;
		nanoseconds += INT64_C(1000000000);
	}
	if (seconds < 0 || (seconds == 0 && nanoseconds == 0)) {
		return 0;
	}
	if (seconds > INT_MAX / 1000) {
		return INT_MAX;
	}
	int64_t milliseconds = seconds * INT64_C(1000) + (nanoseconds + INT64_C(999999)) / INT64_C(1000000);
	return milliseconds > INT_MAX ? INT_MAX : (int)milliseconds;
}

static int file_message_count(const char *filename, const char *message) {
	FILE *file;
	char line[BUFSIZ];
	int count = 0;
	if (filename == NULL || message == NULL) {
		errno = EINVAL;
		return -1;
	}
	file = fopen(filename, "r");
	if (file == NULL) {
		return errno == ENOENT ? 0 : -1;
	}
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strstr(line, message) != NULL) {
			count++;
		}
	}
	if (ferror(file)) {
		int saved_errno = errno == 0 ? EIO : errno;
		fclose(file);
		errno = saved_errno;
		return -1;
	}
	if (fclose(file) == EOF) {
		return -1;
	}
	return count;
}

static size_t handshake_build(uint8_t *destination, const char *vhost, in_port_t port, uint32_t next_state) {
	size_t vhost_size = strlen(vhost);
	size_t payload_size = varint_size(0) + varint_size(47) + varint_size((uint32_t)vhost_size) + vhost_size + sizeof(uint16_t) + varint_size(next_state);
	size_t offset = varint_encode(destination, (uint32_t)payload_size);
	destination[offset++] = 0x00;
	destination[offset++] = 0x2F;
	offset += varint_encode(destination + offset, (uint32_t)vhost_size);
	memcpy(destination + offset, vhost, vhost_size);
	offset += vhost_size;
	destination[offset++] = (uint8_t)(port >> 8);
	destination[offset++] = (uint8_t)port;
	offset += varint_encode(destination + offset, next_state);
	return offset;
}

static int log_count_wait(const char *filename, const char *message, int minimum, int timeout_ms) {
	const struct timespec interval = { .tv_nsec = WORKER_CAP_WAIT_INTERVAL_MS * 1000000L };
	for (int elapsed_ms = 0; elapsed_ms <= timeout_ms; elapsed_ms += WORKER_CAP_WAIT_INTERVAL_MS) {
		int count = file_message_count(filename, message);
		if (count >= minimum) {
			return count;
		}
		if (count == -1) {
			return -1;
		}
		nanosleep(&interval, NULL);
	}
	errno = ETIMEDOUT;
	return -1;
}

static void log_dump(const char *filename) {
	FILE *file;
	char line[BUFSIZ];
	if (filename == NULL) {
		return;
	}
	file = fopen(filename, "r");
	if (file == NULL) {
		fprintf(stderr, "cannot read daemon log %s: %s\n", filename, strerror(errno));
		return;
	}
	fputs("=== daemon log ===\n", stderr);
	while (fgets(line, sizeof(line), file) != NULL) {
		fputs(line, stderr);
	}
	fputs("=== end daemon log ===\n", stderr);
	fclose(file);
}

static ssize_t message_receive(int socket_fd, void *data, size_t capacity, int timeout_ms) {
	struct pollfd event = { .fd = socket_fd, .events = POLLIN };
	int poll_result;
	if (data == NULL || capacity == 0) {
		errno = EINVAL;
		return -1;
	}
	do {
		poll_result = poll(&event, 1, timeout_ms);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result == 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	if (poll_result == -1) {
		return -1;
	}
	if (!(event.revents & (POLLIN | POLLHUP | POLLERR))) {
		errno = EIO;
		return -1;
	}
	return recv(socket_fd, data, capacity, 0);
}

static ssize_t notification_receive(int notify_fd, char *message, size_t capacity, int timeout_ms) {
	struct pollfd event = { .fd = notify_fd, .events = POLLIN };
	int poll_result;
	if (message == NULL || capacity < 2U) {
		errno = EINVAL;
		return -1;
	}
	do {
		poll_result = poll(&event, 1, timeout_ms);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result == 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	if (poll_result == -1) {
		return -1;
	}
	if (!(event.revents & POLLIN)) {
		errno = EIO;
		return -1;
	}
	ssize_t message_size = recv(notify_fd, message, capacity - 1U, 0);
	if (message_size <= 0) {
		return -1;
	}
	message[message_size] = '\0';
	return message_size;
}

static int notification_reload(int notify_fd, int timeout_ms) {
	char message[256];
	if (notification_receive(notify_fd, message, sizeof(message), timeout_ms) <= 0 || strncmp(message, "RELOADING=1\n", 12) != 0) {
		errno = EPROTO;
		return -1;
	}
	if (notification_receive(notify_fd, message, sizeof(message), timeout_ms) <= 0 || strcmp(message, "READY=1") != 0) {
		errno = EPROTO;
		return -1;
	}
	return 0;
}

static int pending_connect_test(const char *binary) {
	char temporary_directory[] = "/tmp/mcrelay-worker-pending-XXXXXX";
	char config_filename[PATH_MAX] = { 0 };
	char log_filename[PATH_MAX] = { 0 };
	char notify_filename[PATH_MAX] = { 0 };
	uint8_t login_packet[BUFSIZ];
	int notify_fd = -1;
	int client_fd = -1;
	int result = -1;
	pid_t listener_pid = -1;
	in_port_t listener_port = 0;
	child_snapshot baseline;
	struct timespec start_time;
	struct timespec end_time;
	CHECK(binary != NULL, "pending daemon path is missing");
	CHECK(mkdtemp(temporary_directory) != NULL, "cannot create pending-connect temporary directory");
	int filename_length = snprintf(config_filename, sizeof(config_filename), "%s/config.json", temporary_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(config_filename), "cannot format pending configuration path");
	filename_length = snprintf(log_filename, sizeof(log_filename), "%s/access.log", temporary_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(log_filename), "cannot format pending log path");
	filename_length = snprintf(notify_filename, sizeof(notify_filename), "%s/notify.sock", temporary_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(notify_filename), "cannot format pending notification path");
	int reservation_fd = server_open(&listener_port);
	CHECK(reservation_fd >= 0, "cannot reserve pending listener port");
	CHECK(close(reservation_fd) == 0, "cannot release pending listener port");
	FILE *config = fopen(config_filename, "w");
	CHECK(config != NULL, "cannot open pending configuration");
	int written = fprintf(config,
		"{\"log\":{\"filename\":\"%s\",\"level\":4},\"listen\":{\"address\":\"127.0.0.1\",\"port\":%u},\"icon\":\"\",\"proxy\":[{\"vhost\":[\"test.example\"],\"address\":\"127.0.0.1\",\"port\":1}]}\n",
		log_filename, (unsigned int)listener_port);
	CHECK(fclose(config) == 0 && written > 0, "cannot write pending configuration");
	notify_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	CHECK(notify_fd >= 0, "cannot create pending notification socket");
	struct sockaddr_un notify_address = { 0 };
	notify_address.sun_family = AF_UNIX;
	CHECK(strlen(notify_filename) < sizeof(notify_address.sun_path), "pending notification path is too long");
	strcpy(notify_address.sun_path, notify_filename);
	CHECK(bind(notify_fd, (const struct sockaddr *)&notify_address, sizeof(notify_address)) == 0, "cannot bind pending notification socket");
	listener_pid = daemon_start(binary, config_filename, notify_filename, true, NULL);
	CHECK(listener_pid > 0, "cannot start pending-connect daemon");
	char message[256];
	CHECK(notification_receive(notify_fd, message, sizeof(message), WORKER_CAP_TEST_TIMEOUT_MS) > 0 && strcmp(message, "READY=1") == 0,
		"pending daemon READY notification is missing");
	CHECK(child_snapshot_read(listener_pid, &baseline) == 0, "cannot read pending daemon child baseline");
	static const char username[] = "pending01";
	size_t packet_size = handshake_build(login_packet, "test.example", 25565, 2);
	login_packet[packet_size++] = (uint8_t)(2U + strlen(username));
	login_packet[packet_size++] = 0x00;
	login_packet[packet_size++] = (uint8_t)strlen(username);
	memcpy(login_packet + packet_size, username, strlen(username));
	packet_size += strlen(username);
	CHECK(clock_gettime(CLOCK_MONOTONIC, &start_time) == 0, "cannot sample pending-connect start time");
	client_fd = client_connect(listener_port);
	CHECK(client_fd >= 0, "cannot connect pending-connect client");
	CHECK(socket_send_all(client_fd, login_packet, packet_size) == 0, "cannot send pending-connect login");
	CHECK(child_snapshot_wait(listener_pid, baseline.workers + 1U, WORKER_CAP_TEST_TIMEOUT_MS, NULL) == 0, "pending worker was not created");
	CHECK(socket_expect_close(client_fd, WORKER_CAP_TEST_TIMEOUT_MS) == 0, "pending-connect worker did not close its client on deadline");
	CHECK(clock_gettime(CLOCK_MONOTONIC, &end_time) == 0, "cannot sample pending-connect end time");
	client_drop(&client_fd);
	int64_t elapsed_ms = ((int64_t)end_time.tv_sec - (int64_t)start_time.tv_sec) * INT64_C(1000)
		+ ((int64_t)end_time.tv_nsec - (int64_t)start_time.tv_nsec) / INT64_C(1000000);
	CHECK(elapsed_ms >= WORKER_CAP_PENDING_MIN_MS && elapsed_ms <= WORKER_CAP_PENDING_MAX_MS, "pending-connect deadline was not close to one second");
	CHECK(child_snapshot_wait(listener_pid, baseline.workers, WORKER_CAP_TEST_TIMEOUT_MS, NULL) == 0, "pending worker slot was not reaped");
	CHECK(kill(listener_pid, 0) == 0, "listener died after pending-connect timeout");
	result = 0;

cleanup:
	if (result != 0) {
		log_dump(log_filename);
	}
	client_drop(&client_fd);
	daemon_stop(&listener_pid);
	if (notify_fd >= 0) {
		close(notify_fd);
	}
	unlink(config_filename);
	unlink(log_filename);
	unlink(notify_filename);
	rmdir(temporary_directory);
	return result;
}

static int process_wait(pid_t process, int timeout_ms) {
	const struct timespec interval = { .tv_nsec = WORKER_CAP_WAIT_INTERVAL_MS * 1000000L };
	for (int elapsed_ms = 0; elapsed_ms <= timeout_ms; elapsed_ms += WORKER_CAP_WAIT_INTERVAL_MS) {
		int status;
		pid_t wait_result = waitpid(process, &status, WNOHANG);
		if (wait_result == process) {
			return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
		}
		if (wait_result == -1) {
			return -1;
		}
		nanosleep(&interval, NULL);
	}
	errno = ETIMEDOUT;
	return -1;
}

static int refusal_probe(in_port_t port, const uint8_t *packet, size_t packet_size, bool legacy) {
	int socket_fd = client_connect(port);
	if (socket_fd == -1) {
		return -1;
	}
	if (socket_send_all(socket_fd, packet, packet_size) == -1) {
		if (errno != EPIPE && errno != ECONNRESET && errno != ENOTCONN) {
			int saved_errno = errno;
			close(socket_fd);
			errno = saved_errno;
			return -1;
		}
	}
	uint8_t received[BUFSIZ];
	size_t total = 0;
	bool closed = false;
	struct timespec deadline;
	if (!deadline_create(&deadline, WORKER_CAP_CLOSE_TIMEOUT_MS)) {
		int saved_errno = errno;
		close(socket_fd);
		errno = saved_errno;
		return -1;
	}
	while (!closed) {
		int remaining_ms = deadline_remaining_ms(&deadline);
		if (remaining_ms <= 0) {
			errno = remaining_ms == 0 ? ETIMEDOUT : errno;
			break;
		}
		struct pollfd event = { .fd = socket_fd, .events = POLLIN | POLLRDHUP };
		int poll_result = poll(&event, 1, remaining_ms);
		if (poll_result == -1 && errno == EINTR) {
			continue;
		}
		if (poll_result == -1) {
			break;
		}
		if (poll_result == 0) {
			errno = ETIMEDOUT;
			break;
		}
		if (total >= sizeof(received)) {
			errno = EMSGSIZE;
			break;
		}
		ssize_t received_size = recv(socket_fd, received + total, sizeof(received) - total, MSG_DONTWAIT);
		if (received_size == 0 || (received_size == -1 && (errno == ECONNRESET || errno == ENOTCONN))) {
			closed = true;
			break;
		}
		if (received_size > 0) {
			total += (size_t)received_size;
			continue;
		}
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
			break;
		}
	}
	bool response_valid = closed && refusal_response_validate(received, total, legacy);
	int result = response_valid ? 0 : -1;
	if (closed && !response_valid) {
		errno = EPROTO;
	} else if (!closed && errno == 0) {
		errno = ETIMEDOUT;
	}
	int saved_errno = errno;
	close(socket_fd);
	errno = saved_errno;
	return result;
}

static bool refusal_response_validate(const uint8_t *response, size_t response_size, bool legacy) {
	static const char notice[] = "[Proxy] Proxy is full, try again later.";
	static const char modern_json[] = "{\"extra\":[{\"text\":\"[Proxy] Proxy is full, try again later.\"}],\"text\":\"\"}";
	if (response == NULL) {
		return false;
	}
	if (legacy) {
		size_t notice_size = sizeof(notice) - 1U;
		if (response_size != 3U + notice_size * sizeof(uint16_t) || response[0] != 0xFF
			|| response[1] != (uint8_t)(notice_size >> 8) || response[2] != (uint8_t)notice_size) {
			return false;
		}
		for (size_t index = 0; index < notice_size; index++) {
			if (response[3U + index * 2U] != 0 || response[4U + index * 2U] != (uint8_t)notice[index]) {
				return false;
			}
		}
		return true;
	}
	size_t message_size = sizeof(modern_json) - 1U;
	return message_size + 2U <= 0x7FU && response_size == message_size + 3U && response[0] == (uint8_t)(message_size + 2U) && response[1] == 0
		&& response[2] == (uint8_t)message_size && memcmp(response + 3U, modern_json, message_size) == 0;
}

static int run_cap_test(const char *binary) {
	static const uint8_t legacy_login_packet[] = {
		0x02, 0x00, 0x09, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x75, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x31
	};
	static const char vhost[] = "test.example";
	static const char username[] = "captest01";
	static const char worker_limit_message[] = "Worker process limit reached";
	char temporary_directory[] = "/tmp/mcrelay-worker-cap-XXXXXX";
	char config_filename[PATH_MAX] = { 0 };
	char log_filename[PATH_MAX] = { 0 };
	char notify_filename[PATH_MAX] = { 0 };
	char refusal_marker_filename[PATH_MAX] = { 0 };
	uint8_t login_packet[BUFSIZ];
	uint8_t transfer_packet[BUFSIZ];
	uint8_t status_packet[BUFSIZ];
	uint8_t status_response[BUFSIZ];
	int notify_fd = -1;
	int upstream_server_fd = -1;
	int upstream_a_fd = -1;
	int upstream_b_fd = -1;
	int upstream_status_fd = -1;
	int upstream_replacement_fd = -1;
	int client_a_fd = -1;
	int client_b_fd = -1;
	int client_status_fd = -1;
	int client_replacement_fd = -1;
	int result = -1;
	pid_t listener_pid = -1;
	in_port_t listener_port = 0;
	in_port_t upstream_port = 0;
	child_snapshot baseline;
	CHECK(binary != NULL, "mcrelay executable path is required");
	CHECK(mkdtemp(temporary_directory) != NULL, "cannot create worker-cap temporary directory");
	int filename_length = snprintf(config_filename, sizeof(config_filename), "%s/config.json", temporary_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(config_filename), "cannot format configuration path");
	filename_length = snprintf(log_filename, sizeof(log_filename), "%s/access.log", temporary_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(log_filename), "cannot format log path");
	filename_length = snprintf(notify_filename, sizeof(notify_filename), "%s/notify.sock", temporary_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(notify_filename), "cannot format notification path");
	filename_length = snprintf(refusal_marker_filename, sizeof(refusal_marker_filename), "%s/refusal-partial.marker", temporary_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(refusal_marker_filename), "cannot format refusal marker path");
	upstream_server_fd = server_open(&upstream_port);
	CHECK(upstream_server_fd >= 0, "cannot open fake upstream server");
	int reservation_fd = server_open(&listener_port);
	CHECK(reservation_fd >= 0, "cannot reserve listener port");
	CHECK(close(reservation_fd) == 0, "cannot release listener port");
	FILE *config = fopen(config_filename, "w");
	CHECK(config != NULL, "cannot open worker-cap configuration");
	int written = fprintf(config,
		"{\"log\":{\"filename\":\"%s\",\"level\":4},\"listen\":{\"address\":\"127.0.0.1\",\"port\":%u},\"icon\":\"\",\"proxy\":[{\"vhost\":[\"%s\"],\"address\":\"127.0.0.1\",\"port\":%u}]}\n",
		log_filename, (unsigned int)listener_port, vhost, (unsigned int)upstream_port);
	CHECK(fclose(config) == 0 && written > 0, "cannot write worker-cap configuration");
	notify_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	CHECK(notify_fd >= 0, "cannot create notification socket");
	struct sockaddr_un notify_address = { 0 };
	notify_address.sun_family = AF_UNIX;
	CHECK(strlen(notify_filename) < sizeof(notify_address.sun_path), "notification path is too long");
	strcpy(notify_address.sun_path, notify_filename);
	CHECK(bind(notify_fd, (const struct sockaddr *)&notify_address, sizeof(notify_address)) == 0, "cannot bind notification socket");
	listener_pid = daemon_start(binary, config_filename, notify_filename, false, refusal_marker_filename);
	CHECK(listener_pid > 0, "cannot start worker-cap daemon");
	char message[256];
	CHECK(notification_receive(notify_fd, message, sizeof(message), WORKER_CAP_TEST_TIMEOUT_MS) > 0 && strcmp(message, "READY=1") == 0,
		"listener READY notification is missing");
	CHECK(child_snapshot_read(listener_pid, &baseline) == 0, "cannot read resolver child baseline");
	CHECK(baseline.direct >= baseline.workers, "invalid child baseline");
	uint8_t login_base[BUFSIZ];
	size_t login_size = handshake_build(login_base, vhost, upstream_port, 2);
	login_base[login_size++] = (uint8_t)(2U + strlen(username));
	login_base[login_size++] = 0x00;
	login_base[login_size++] = (uint8_t)strlen(username);
	memcpy(login_base + login_size, username, strlen(username));
	login_size += strlen(username);
	CHECK(login_size <= sizeof(login_packet), "login packet is too large");
	memcpy(login_packet, login_base, login_size);
	/* Rebuild the transfer packet so its handshake intent is 3 while preserving Login Start. */
	size_t transfer_size = handshake_build(transfer_packet, vhost, upstream_port, 3);
	transfer_packet[transfer_size++] = (uint8_t)(2U + strlen(username));
	transfer_packet[transfer_size++] = 0x00;
	transfer_packet[transfer_size++] = (uint8_t)strlen(username);
	memcpy(transfer_packet + transfer_size, username, strlen(username));
	transfer_size += strlen(username);
	CHECK(transfer_size <= sizeof(transfer_packet), "transfer packet is too large");
	size_t status_size = handshake_build(status_packet, vhost, upstream_port, 1);
	status_packet[status_size++] = 0x01;
	status_packet[status_size++] = 0x00;

	client_a_fd = client_connect(listener_port);
	CHECK(client_a_fd >= 0 && socket_send_all(client_a_fd, login_packet, login_size) == 0, "cannot start first LOGIN worker");
	upstream_a_fd = backend_accept(upstream_server_fd, WORKER_CAP_TEST_TIMEOUT_MS);
	CHECK(upstream_a_fd >= 0, "first LOGIN worker did not connect to backend");
	CHECK(child_snapshot_wait(listener_pid, baseline.workers + 1U, WORKER_CAP_TEST_TIMEOUT_MS, NULL) == 0, "first worker was not observed");
	client_b_fd = client_connect(listener_port);
	CHECK(client_b_fd >= 0 && socket_send_all(client_b_fd, login_packet, login_size) == 0, "cannot start second LOGIN worker");
	upstream_b_fd = backend_accept(upstream_server_fd, WORKER_CAP_TEST_TIMEOUT_MS);
	CHECK(upstream_b_fd >= 0, "second LOGIN worker did not connect to backend");
	CHECK(child_snapshot_wait(listener_pid, baseline.workers + 2U, WORKER_CAP_TEST_TIMEOUT_MS, NULL) == 0, "second worker was not observed");

	int initial_refusals = file_message_count(log_filename, worker_limit_message);
	CHECK(initial_refusals >= 0, "cannot count initial worker-cap log entries");
	CHECK(refusal_probe(listener_port, login_packet, login_size, false) == 0, "third LOGIN did not receive a complete refusal");
	CHECK(access(refusal_marker_filename, F_OK) == 0, "partial-send/EAGAIN refusal injection was not consumed");
	CHECK(refusal_probe(listener_port, transfer_packet, transfer_size, false) == 0, "TRANSFER did not receive a complete refusal");
	CHECK(refusal_probe(listener_port, legacy_login_packet, sizeof(legacy_login_packet), true) == 0, "legacy LOGIN did not receive a complete refusal");
	CHECK(log_count_wait(log_filename, worker_limit_message, initial_refusals + 1, WORKER_CAP_LOG_TIMEOUT_MS) >= initial_refusals + 1,
		"worker-cap refusal was not logged");
	for (int refusal_index = 0; refusal_index < 4; refusal_index++) {
		CHECK(refusal_probe(listener_port, refusal_index % 2 == 0 ? login_packet : transfer_packet,
			refusal_index % 2 == 0 ? login_size : transfer_size, false) == 0, "repeated worker-cap refusal was incomplete");
	}
	int refusal_count = file_message_count(log_filename, worker_limit_message);
	CHECK(refusal_count == initial_refusals + 1, "worker-cap refusal log was not rate limited");
	CHECK(backend_quiet(upstream_server_fd, WORKER_CAP_QUIET_TIMEOUT_MS) == 0, "refused worker reached backend");
	child_snapshot snapshot;
	CHECK(child_snapshot_read(listener_pid, &snapshot) == 0 && snapshot.workers == baseline.workers + 2U, "refused connections changed worker population");

	client_status_fd = client_connect(listener_port);
	CHECK(client_status_fd >= 0 && socket_send_all(client_status_fd, status_packet, status_size) == 0, "cannot start STATUS connection at worker cap");
	upstream_status_fd = backend_accept(upstream_server_fd, WORKER_CAP_TEST_TIMEOUT_MS);
	CHECK(upstream_status_fd >= 0, "STATUS did not remain serviceable at worker cap");
	size_t status_response_size = status_response_build(status_response, sizeof(status_response));
	CHECK(status_response_size > 0 && socket_send_all(upstream_status_fd, status_response, status_response_size) == 0, "cannot send STATUS response");
	uint8_t received_status[BUFSIZ];
	CHECK(message_receive(client_status_fd, received_status, sizeof(received_status), WORKER_CAP_TEST_TIMEOUT_MS) > 0, "STATUS response did not reach client");
	CHECK(child_snapshot_read(listener_pid, &snapshot) == 0 && snapshot.workers == baseline.workers + 2U, "STATUS unexpectedly forked a worker");

	CHECK(connection_cap_probe(listener_port) == 0, "shared connection-cap refusal did not occur before initial-packet assembly");
	CHECK(backend_quiet(upstream_server_fd, WORKER_CAP_QUIET_TIMEOUT_MS) == 0, "connection-cap refusal reached backend");
	CHECK(child_snapshot_read(listener_pid, &snapshot) == 0 && snapshot.workers == baseline.workers + 2U, "connection-cap refusal changed worker population");

	client_drop(&client_a_fd);
	client_drop(&upstream_a_fd);
	CHECK(child_snapshot_wait(listener_pid, baseline.workers + 1U, WORKER_CAP_TEST_TIMEOUT_MS, NULL) == 0, "first worker slot was not released");
	client_replacement_fd = client_connect(listener_port);
	CHECK(client_replacement_fd >= 0 && socket_send_all(client_replacement_fd, login_packet, login_size) == 0, "cannot reuse released worker slot");
	upstream_replacement_fd = backend_accept(upstream_server_fd, WORKER_CAP_TEST_TIMEOUT_MS);
	CHECK(upstream_replacement_fd >= 0, "replacement worker did not reach backend");
	CHECK(child_snapshot_wait(listener_pid, baseline.workers + 2U, WORKER_CAP_TEST_TIMEOUT_MS, NULL) == 0, "replacement worker was not observed");

	client_drop(&client_b_fd);
	client_drop(&upstream_b_fd);
	client_drop(&client_replacement_fd);
	client_drop(&upstream_replacement_fd);
	CHECK(child_snapshot_wait(listener_pid, baseline.workers, WORKER_CAP_TEST_TIMEOUT_MS, &snapshot) == 0, "coalesced worker exits were not fully reaped");
	CHECK(snapshot.direct >= baseline.direct, "resolver supervisor/helper baseline was lost while reaping workers");
	CHECK(kill(listener_pid, 0) == 0, "listener terminated after worker reaping");
	client_replacement_fd = client_connect(listener_port);
	CHECK(client_replacement_fd >= 0 && socket_send_all(client_replacement_fd, login_packet, login_size) == 0, "cannot reuse the worker table after coalesced exits");
	upstream_replacement_fd = backend_accept(upstream_server_fd, WORKER_CAP_TEST_TIMEOUT_MS);
	CHECK(upstream_replacement_fd >= 0, "post-reap worker did not reach backend");
	CHECK(child_snapshot_wait(listener_pid, baseline.workers + 1U, WORKER_CAP_TEST_TIMEOUT_MS, NULL) == 0, "post-reap worker was not observed");
	client_drop(&client_replacement_fd);
	client_drop(&upstream_replacement_fd);
	CHECK(child_snapshot_wait(listener_pid, baseline.workers, WORKER_CAP_TEST_TIMEOUT_MS, &snapshot) == 0, "post-reap worker slot was not released");
	CHECK(kill(listener_pid, SIGUSR1) == 0, "cannot request reload after worker reaping");
	CHECK(notification_reload(notify_fd, WORKER_CAP_TEST_TIMEOUT_MS) == 0, "reload did not complete after worker reaping");
	CHECK(child_snapshot_read(listener_pid, &snapshot) == 0 && snapshot.workers == baseline.workers, "reload left a worker process behind");

	client_drop(&client_status_fd);
	client_drop(&upstream_status_fd);
	CHECK(child_snapshot_wait(listener_pid, baseline.workers, WORKER_CAP_TEST_TIMEOUT_MS, &snapshot) == 0, "listener-held STATUS connection did not drain");
	CHECK(snapshot.direct >= baseline.direct, "resolver baseline changed after STATUS close");
	result = 0;

cleanup:
	if (result != 0) {
		log_dump(log_filename);
	}
	client_drop(&client_a_fd);
	client_drop(&client_b_fd);
	client_drop(&client_status_fd);
	client_drop(&client_replacement_fd);
	client_drop(&upstream_a_fd);
	client_drop(&upstream_b_fd);
	client_drop(&upstream_status_fd);
	client_drop(&upstream_replacement_fd);
	daemon_stop(&listener_pid);
	if (notify_fd >= 0) {
		close(notify_fd);
	}
	if (upstream_server_fd >= 0) {
		close(upstream_server_fd);
	}
	unlink(config_filename);
	unlink(log_filename);
	unlink(notify_filename);
	unlink(refusal_marker_filename);
	rmdir(temporary_directory);
	return result;
}

static int server_open(in_port_t *port) {
	int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_fd == -1) {
		return -1;
	}
	int reuse_address = 1;
	if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address)) == -1) {
		int saved_errno = errno;
		close(socket_fd);
		errno = saved_errno;
		return -1;
	}
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0
	};
	if (bind(socket_fd, (const struct sockaddr *)&address, sizeof(address)) == -1) {
		int saved_errno = errno;
		close(socket_fd);
		errno = saved_errno;
		return -1;
	}
	socklen_t address_size = sizeof(address);
	if (getsockname(socket_fd, (struct sockaddr *)&address, &address_size) == -1 || listen(socket_fd, 8) == -1) {
		int saved_errno = errno;
		close(socket_fd);
		errno = saved_errno;
		return -1;
	}
	if (port != NULL) {
		*port = ntohs(address.sin_port);
	}
	return socket_fd;
}

static int socket_expect_close(int socket_fd, int timeout_ms) {
	for (int elapsed_ms = 0; elapsed_ms <= timeout_ms; elapsed_ms += WORKER_CAP_WAIT_INTERVAL_MS) {
		struct pollfd event = { .fd = socket_fd, .events = POLLIN | POLLRDHUP };
		int poll_result;
		do {
			poll_result = poll(&event, 1, WORKER_CAP_WAIT_INTERVAL_MS);
		} while (poll_result == -1 && errno == EINTR);
		if (poll_result == -1) {
			return -1;
		}
		if (poll_result == 0) {
			continue;
		}
		if (!(event.revents & (POLLIN | POLLRDHUP | POLLERR | POLLHUP))) {
			errno = EIO;
			return -1;
		}
		uint8_t bytes[BUFSIZ];
		ssize_t received = recv(socket_fd, bytes, sizeof(bytes), MSG_DONTWAIT);
		if (received == 0 || (received == -1 && (errno == ECONNRESET || errno == ENOTCONN))) {
			return 0;
		}
		if (received > 0) {
			continue;
		}
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
			return -1;
		}
	}
	errno = ETIMEDOUT;
	return -1;
}

static int socket_send_all(int socket_fd, const void *data, size_t size) {
	const uint8_t *bytes = data;
	size_t sent = 0;
	if (socket_fd < 0 || (data == NULL && size > 0)) {
		errno = EINVAL;
		return -1;
	}
	while (sent < size) {
		ssize_t send_size = send(socket_fd, bytes + sent, size - sent, MSG_NOSIGNAL);
		if (send_size == -1 && errno == EINTR) {
			continue;
		}
		if (send_size <= 0) {
			return -1;
		}
		sent += (size_t)send_size;
	}
	return 0;
}

static size_t status_response_build(uint8_t *destination, size_t destination_capacity) {
	static const char json[] = "{\"version\":{\"name\":\"cap\",\"protocol\":47},\"players\":{\"max\":1,\"online\":0,\"sample\":[]},\"description\":{\"text\":\"ok\"}}";
	size_t json_size = strlen(json);
	size_t payload_size = 1U + varint_size((uint32_t)json_size) + json_size;
	if (destination == NULL || payload_size > UINT32_MAX || varint_size((uint32_t)payload_size) + payload_size > destination_capacity) {
		return 0;
	}
	size_t offset = varint_encode(destination, (uint32_t)payload_size);
	destination[offset++] = 0x00;
	offset += varint_encode(destination + offset, (uint32_t)json_size);
	memcpy(destination + offset, json, json_size);
	return offset + json_size;
}

static size_t varint_encode(uint8_t *destination, uint32_t value) {
	size_t size = 0;
	while (value >= 0x80U) {
		destination[size++] = (uint8_t)((value & 0x7FU) | 0x80U);
		value >>= 7;
	}
	destination[size++] = (uint8_t)value;
	return size;
}

static size_t varint_size(uint32_t value) {
	size_t size = 1;
	while (value >= 0x80U) {
		value >>= 7;
		size++;
	}
	return size;
}

/* section: functions (entry point) */
int main(int argc, char **argv) {
	if (argc != 2 && argc != 3) {
		fprintf(stderr, "usage: %s DAEMON [PENDING_CONNECT_DAEMON]\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (run_cap_test(argv[1]) != 0) {
		return EXIT_FAILURE;
	}
	if (argc == 3 && pending_connect_test(argv[2]) != 0) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
