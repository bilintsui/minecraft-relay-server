/*
 * listener_short_runtime.c: Listener-owned short connection integration tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
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
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* timeout */
#define LISTENER_RELOAD_LATE_TEST_DEFERRED_MS	500
#define LISTENER_RELOAD_LATE_TEST_RELEASE_MS	2000
#define LISTENER_ROUTE_CANCEL_TEST_TIMEOUT_MS	2000
#define LISTENER_SHORT_TEST_TIMEOUT_MS	5000
#define LISTENER_SHORT_TEST_POLL_MS	100

/* section: types */
typedef struct {
	char config_filename[PATH_MAX];
	char log_filename[PATH_MAX];
	char notify_filename[PATH_MAX];
	char release_trigger_filename[PATH_MAX];
	int notify_fd;
	in_port_t listener_port;
	pid_t listener;
} short_fixture;

/* section: global variables */
static const uint8_t short_login_request[] = {
	0x12, 0x00, 0x2F, 0x0C,
	't', 'e', 's', 't', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x63, 0xDD, 0x02,
	0x03, 0x00, 0x01, 'x'
};
static const uint8_t short_status_request[] = {
	0x12, 0x00, 0x2F, 0x0C,
	't', 'e', 's', 't', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x63, 0xDD, 0x01,
	0x01, 0x00
};

/* section: functions (local) */
static bool short_test_bytes_contain(const uint8_t *data, size_t data_size, const char *needle) {
	if (data == NULL || needle == NULL) {
		return false;
	}
	size_t needle_size = strlen(needle);
	if (needle_size > data_size) {
		return false;
	}
	for (size_t offset = 0; offset + needle_size <= data_size; offset++) {
		if (memcmp(data + offset, needle, needle_size) == 0) {
			return true;
		}
	}
	return false;
}

static bool short_test_client_alive(int socket_fd) {
	uint8_t byte;
	ssize_t result;
	if (socket_fd < 0) {
		errno = EINVAL;
		return false;
	}
	do {
		result = recv(socket_fd, &byte, sizeof(byte), MSG_DONTWAIT | MSG_PEEK);
	} while (result == -1 && errno == EINTR);
	return result > 0 || (result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
}

static int short_test_client_connect(in_port_t port) {
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port)
	};
	int result = socket(AF_INET, SOCK_STREAM, 0);
	if (result == -1) {
		return -1;
	}
	if (connect(result, (const struct sockaddr *)&address, sizeof(address)) == -1) {
		int saved_errno = errno;
		close(result);
		errno = saved_errno;
		return -1;
	}
	return result;
}

static int short_test_config_write(const short_fixture *fixture, const char *address, in_port_t upstream_port) {
	char content[PATH_MAX + 512];
	int content_length;
	int fd;
	if (fixture == NULL || address == NULL) {
		errno = EINVAL;
		return -1;
	}
	content_length = snprintf(content, sizeof(content),
		"{\"log\":{\"filename\":\"%s\",\"level\":4},\"listen\":{\"address\":\"127.0.0.1\",\"port\":%u},\"icon\":\"\",\"proxy\":[{\"vhost\":[\"test.example\"],\"address\":\"%s\",\"port\":%u}]}\n",
		fixture->log_filename, (unsigned int)fixture->listener_port, address, (unsigned int)upstream_port);
	if (content_length < 0 || (size_t)content_length >= sizeof(content)) {
		errno = EOVERFLOW;
		return -1;
	}
	fd = open(fixture->config_filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1) {
		return -1;
	}
	size_t written = 0;
	while (written < (size_t)content_length) {
		ssize_t write_size = write(fd, content + written, (size_t)content_length - written);
		if (write_size <= 0) {
			int saved_errno = errno;
			close(fd);
			errno = saved_errno;
			return -1;
		}
		written += (size_t)write_size;
	}
	return close(fd);
}

static bool short_test_file_contains(const char *filename, const char *needle) {
	if (filename == NULL || needle == NULL) {
		errno = EINVAL;
		return false;
	}
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		return false;
	}
	char line[BUFSIZ];
	bool result = false;
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strstr(line, needle) != NULL) {
			result = true;
			break;
		}
	}
	if (fclose(file) == EOF && !result) {
		return false;
	}
	return result;
}

static ssize_t short_test_fixture_notification_timeout(short_fixture *fixture, char *message, size_t capacity, int timeout_ms) {
	if (fixture == NULL || fixture->notify_fd < 0 || message == NULL || capacity < 2U || timeout_ms < 0) {
		errno = EINVAL;
		return -1;
	}
	struct pollfd event = { .fd = fixture->notify_fd, .events = POLLIN };
	int poll_result;
	do {
		poll_result = poll(&event, 1, timeout_ms);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result != 1 || !(event.revents & POLLIN)) {
		errno = poll_result == 0 ? ETIMEDOUT : EIO;
		return -1;
	}
	ssize_t message_size = recv(fixture->notify_fd, message, capacity - 1U, 0);
	if (message_size <= 0) {
		return -1;
	}
	message[message_size] = '\0';
	return message_size;
}

static ssize_t short_test_fixture_notification(short_fixture *fixture, char *message, size_t capacity) {
	return short_test_fixture_notification_timeout(fixture, message, capacity, LISTENER_SHORT_TEST_TIMEOUT_MS);
}

static int short_test_fixture_release_environment(const short_fixture *fixture, const char *suffix) {
	if (suffix == NULL || strncmp(suffix, "release-", strlen("release-")) != 0) {
		return 0;
	}
	const char *status = strstr(suffix, "-bad") != NULL ? "BAD_ARGUMENT" : strstr(suffix, "-time") != NULL ? "TIME" : "IO";
	if (fixture == NULL || setenv("MCRELAY_TEST_DNS_FIXED", "1", 1) == -1 || setenv("MCRELAY_TEST_DNS_FIXED_DELAY_MS", "500", 1) == -1
		|| setenv("MCRELAY_TEST_ROUTE_DESTROY_FAULT_TRIGGER", fixture->release_trigger_filename, 1) == -1
		|| setenv("MCRELAY_TEST_ROUTE_DESTROY_FAULT_STATUS", status, 1) == -1) {
		return -1;
	}
	return 0;
}

static int short_test_fixture_release_trigger(const short_fixture *fixture) {
	if (fixture == NULL || fixture->release_trigger_filename[0] == '\0') {
		errno = EINVAL;
		return -1;
	}
	int fd = open(fixture->release_trigger_filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1) {
		return -1;
	}
	return close(fd);
}

static int short_test_fixture_start(short_fixture *fixture, const char *binary, const char *directory, const char *suffix,
	const char *upstream_address, in_port_t upstream_port) {
	struct sockaddr_un notify_address;
	int filename_length;
	if (fixture == NULL || binary == NULL || directory == NULL || suffix == NULL || upstream_address == NULL) {
		errno = EINVAL;
		return -1;
	}
	memset(fixture, 0, sizeof(*fixture));
	fixture->notify_fd = -1;
	fixture->listener = -1;
	filename_length = snprintf(fixture->config_filename, sizeof(fixture->config_filename), "%s/%s-config.json", directory, suffix);
	if (filename_length < 0 || (size_t)filename_length >= sizeof(fixture->config_filename)) {
		errno = EOVERFLOW;
		return -1;
	}
	filename_length = snprintf(fixture->log_filename, sizeof(fixture->log_filename), "%s/%s.log", directory, suffix);
	if (filename_length < 0 || (size_t)filename_length >= sizeof(fixture->log_filename)) {
		errno = EOVERFLOW;
		return -1;
	}
	filename_length = snprintf(fixture->notify_filename, sizeof(fixture->notify_filename), "%s/%s.sock", directory, suffix);
	if (filename_length < 0 || (size_t)filename_length >= sizeof(fixture->notify_filename)) {
		errno = EOVERFLOW;
		return -1;
	}
	filename_length = snprintf(fixture->release_trigger_filename, sizeof(fixture->release_trigger_filename), "%s/%s-release.trigger", directory, suffix);
	if (filename_length < 0 || (size_t)filename_length >= sizeof(fixture->release_trigger_filename)) {
		errno = EOVERFLOW;
		return -1;
	}
	int reservation_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (reservation_fd == -1) {
		return -1;
	}
	struct sockaddr_in reservation_address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(0)
	};
	socklen_t reservation_size = sizeof(reservation_address);
	if (bind(reservation_fd, (const struct sockaddr *)&reservation_address, sizeof(reservation_address)) == -1
		|| getsockname(reservation_fd, (struct sockaddr *)&reservation_address, &reservation_size) == -1) {
		int saved_errno = errno;
		close(reservation_fd);
		errno = saved_errno;
		return -1;
	}
	fixture->listener_port = ntohs(reservation_address.sin_port);
	close(reservation_fd);
	if (short_test_config_write(fixture, upstream_address, upstream_port) == -1) {
		return -1;
	}
	fixture->notify_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fixture->notify_fd == -1) {
		return -1;
	}
	memset(&notify_address, 0, sizeof(notify_address));
	notify_address.sun_family = AF_UNIX;
	if (strlen(fixture->notify_filename) >= sizeof(notify_address.sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	strcpy(notify_address.sun_path, fixture->notify_filename);
	if (bind(fixture->notify_fd, (const struct sockaddr *)&notify_address, sizeof(notify_address)) == -1) {
		return -1;
	}
	fixture->listener = fork();
	if (fixture->listener == -1) {
		return -1;
	}
	if (fixture->listener == 0) {
		int devnull_fd = open("/dev/null", O_WRONLY);
		if (devnull_fd == -1 || dup2(devnull_fd, STDOUT_FILENO) == -1 || dup2(devnull_fd, STDERR_FILENO) == -1
			|| setenv("NOTIFY_SOCKET", fixture->notify_filename, 1) == -1
			|| ((strcmp(suffix, "route-cancel") == 0 || strcmp(suffix, "reload-late") == 0)
				&& setenv("MCRELAY_TEST_DNS_PENDING", "1", 1) == -1)
			|| (strcmp(suffix, "reload-late-short") == 0 && setenv("MCRELAY_TEST_CONNECT_PENDING", "1", 1) == -1)
			|| (strcmp(suffix, "deadline") == 0 && (setenv("MCRELAY_TEST_CONNECT_PENDING", "1", 1) == -1
				|| setenv("MCRELAY_TEST_TIMER_REARM_RACE", "1", 1) == -1))
			|| short_test_fixture_release_environment(fixture, suffix) == -1) {
			_exit(EXIT_FAILURE);
		}
		close(devnull_fd);
		execl(binary, binary, "run", "-c", fixture->config_filename, (char *)NULL);
		_exit(EXIT_FAILURE);
	}
	struct pollfd event = { .fd = fixture->notify_fd, .events = POLLIN };
	int poll_result;
	do {
		poll_result = poll(&event, 1, LISTENER_SHORT_TEST_TIMEOUT_MS);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result != 1 || !(event.revents & POLLIN)) {
		errno = poll_result == 0 ? ETIMEDOUT : EIO;
		return -1;
	}
	char message[128];
	ssize_t message_size = recv(fixture->notify_fd, message, sizeof(message) - 1, 0);
	if (message_size <= 0) {
		return -1;
	}
	message[message_size] = '\0';
	if (strcmp(message, "READY=1") != 0) {
		errno = EPROTO;
		return -1;
	}
	return 0;
}

static int short_test_fixture_stop(short_fixture *fixture) {
	int result = 0;
	if (fixture == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (fixture->listener > 0) {
		if (kill(fixture->listener, SIGTERM) == -1 && errno != ESRCH) {
			result = -1;
		}
		for (int elapsed = 0; elapsed < LISTENER_SHORT_TEST_TIMEOUT_MS; elapsed += LISTENER_SHORT_TEST_POLL_MS) {
			int status;
			pid_t wait_result = waitpid(fixture->listener, &status, WNOHANG);
			if (wait_result == fixture->listener) {
				fixture->listener = -1;
				break;
			}
			if (wait_result == -1) {
				result = -1;
				break;
			}
			struct timespec delay = { .tv_nsec = LISTENER_SHORT_TEST_POLL_MS * 1000000L };
			nanosleep(&delay, NULL);
		}
		if (fixture->listener > 0) {
			kill(fixture->listener, SIGKILL);
			waitpid(fixture->listener, NULL, 0);
			fixture->listener = -1;
			result = -1;
		}
	}
	if (fixture->notify_fd >= 0) {
		close(fixture->notify_fd);
		fixture->notify_fd = -1;
	}
	unlink(fixture->config_filename);
	unlink(fixture->log_filename);
	unlink(fixture->notify_filename);
	unlink(fixture->release_trigger_filename);
	return result;
}

static int short_test_fixture_wait_exit(short_fixture *fixture, int *status, int timeout_ms) {
	if (fixture == NULL || fixture->listener <= 0 || status == NULL || timeout_ms < 1) {
		errno = EINVAL;
		return -1;
	}
	for (int elapsed = 0; elapsed <= timeout_ms; elapsed += LISTENER_SHORT_TEST_POLL_MS) {
		pid_t result = waitpid(fixture->listener, status, WNOHANG);
		if (result == fixture->listener) {
			fixture->listener = -1;
			return 0;
		}
		if (result == -1) {
			return -1;
		}
		struct timespec delay = { .tv_nsec = LISTENER_SHORT_TEST_POLL_MS * 1000000L };
		nanosleep(&delay, NULL);
	}
	errno = ETIMEDOUT;
	return -1;
}

static int short_test_listener_accept(int listener_fd) {
	struct pollfd event = { .fd = listener_fd, .events = POLLIN };
	int poll_result;
	do {
		poll_result = poll(&event, 1, LISTENER_SHORT_TEST_TIMEOUT_MS);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result != 1 || !(event.revents & POLLIN)) {
		errno = poll_result == 0 ? ETIMEDOUT : EIO;
		return -1;
	}
	return accept(listener_fd, NULL, NULL);
}

static int short_test_listener_open(in_port_t *port) {
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(0)
	};
	socklen_t address_size = sizeof(address);
	int result = socket(AF_INET, SOCK_STREAM, 0);
	if (result == -1) {
		return -1;
	}
	if (bind(result, (const struct sockaddr *)&address, sizeof(address)) == -1 || listen(result, 8) == -1
		|| getsockname(result, (struct sockaddr *)&address, &address_size) == -1) {
		int saved_errno = errno;
		close(result);
		errno = saved_errno;
		return -1;
	}
	if (port != NULL) {
		*port = ntohs(address.sin_port);
	}
	return result;
}

static int short_test_receive_exact(int socket_fd, uint8_t *data, size_t data_size) {
	size_t offset = 0;
	while (offset < data_size) {
		struct pollfd event = { .fd = socket_fd, .events = POLLIN };
		int poll_result;
		do {
			poll_result = poll(&event, 1, LISTENER_SHORT_TEST_TIMEOUT_MS);
		} while (poll_result == -1 && errno == EINTR);
		if (poll_result != 1 || !(event.revents & (POLLIN | POLLHUP))) {
			errno = poll_result == 0 ? ETIMEDOUT : EIO;
			return -1;
		}
		ssize_t receive_size = recv(socket_fd, data + offset, data_size - offset, 0);
		if (receive_size <= 0) {
			errno = receive_size == 0 ? ECONNRESET : errno;
			return -1;
		}
		offset += (size_t)receive_size;
	}
	return 0;
}

static int short_test_receive_until_close(int socket_fd, uint8_t *data, size_t capacity, size_t *result_size, int timeout_ms) {
	struct timespec start;
	struct timespec now;
	size_t received_size = 0;
	if (data == NULL || result_size == NULL || capacity == 0 || clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
		errno = EINVAL;
		return -1;
	}
	while (1) {
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			return -1;
		}
		int elapsed = (int)((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000L);
		int remaining = timeout_ms - elapsed;
		if (remaining <= 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		struct pollfd event = { .fd = socket_fd, .events = POLLIN };
		int poll_result;
		do {
			poll_result = poll(&event, 1, remaining);
		} while (poll_result == -1 && errno == EINTR);
		if (poll_result == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		if (poll_result == -1) {
			return -1;
		}
		uint8_t buffer[BUFSIZ];
		ssize_t receive_size = recv(socket_fd, buffer, sizeof(buffer), MSG_DONTWAIT);
		if (receive_size == 0) {
			*result_size = received_size;
			return 0;
		}
		if (receive_size < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
				continue;
			}
			return -1;
		}
		if (received_size > capacity - (size_t)receive_size) {
			errno = EOVERFLOW;
			return -1;
		}
		memcpy(data + received_size, buffer, (size_t)receive_size);
		received_size += (size_t)receive_size;
	}
}

static int short_test_send_all(int socket_fd, const uint8_t *data, size_t data_size) {
	size_t offset = 0;
	while (offset < data_size) {
		ssize_t send_size = send(socket_fd, data + offset, data_size - offset, MSG_NOSIGNAL);
		if (send_size < 0 && errno == EINTR) {
			continue;
		}
		if (send_size <= 0) {
			return -1;
		}
		offset += (size_t)send_size;
	}
	return 0;
}

static bool short_test_admission(const char *binary, const char *directory) {
	bool test_result = false;
	short_fixture fixture = { .notify_fd = -1, .listener = -1 };
	int client_fds[3] = { -1, -1, -1 };
	int upstream_fd = -1;
	in_port_t upstream_port = 0;
	upstream_fd = short_test_listener_open(&upstream_port);
	CHECK(upstream_fd >= 0, "could not open admission upstream");
	CHECK(short_test_fixture_start(&fixture, binary, directory, "admission", "127.0.0.1", upstream_port) == 0,
		"could not start admission listener");
	struct pollfd events[3];
	for (size_t connection_index = 0; connection_index < sizeof(client_fds) / sizeof(client_fds[0]); connection_index++) {
		client_fds[connection_index] = short_test_client_connect(fixture.listener_port);
		CHECK(client_fds[connection_index] >= 0, "could not connect admission client");
		events[connection_index].fd = client_fds[connection_index];
		events[connection_index].events = POLLIN;
		events[connection_index].revents = 0;
	}
	int poll_result;
	do {
		poll_result = poll(events, sizeof(events) / sizeof(events[0]), 1000);
	} while (poll_result == -1 && errno == EINTR);
	CHECK(poll_result > 0, "listener did not reject a connection beyond its configured limit");
	size_t closed_count = 0;
	for (size_t connection_index = 0; connection_index < sizeof(client_fds) / sizeof(client_fds[0]); connection_index++) {
		if (events[connection_index].revents & (POLLERR | POLLHUP)) {
			closed_count++;
		} else if (events[connection_index].revents & POLLIN) {
			uint8_t byte;
			if (recv(client_fds[connection_index], &byte, sizeof(byte), MSG_DONTWAIT) == 0) {
				closed_count++;
			}
		}
	}
	CHECK(closed_count == 1U, "listener connection admission did not enforce the exact hard limit");
	test_result = true;

cleanup:
	for (size_t connection_index = 0; connection_index < sizeof(client_fds) / sizeof(client_fds[0]); connection_index++) {
		if (client_fds[connection_index] >= 0) {
			close(client_fds[connection_index]);
		}
	}
	if (upstream_fd >= 0) {
		close(upstream_fd);
	}
	if (fixture.listener > 0 || fixture.notify_fd >= 0) {
		short_test_fixture_stop(&fixture);
	}
	return test_result;
}

static bool short_test_deadline(const char *binary, const char *directory) {
	bool test_result = false;
	short_fixture fixture = { .notify_fd = -1, .listener = -1 };
	int client_fd = -1;
	CHECK(short_test_fixture_start(&fixture, binary, directory, "deadline", "127.0.0.1", 9) == 0,
		"could not start deadline listener");
	client_fd = short_test_client_connect(fixture.listener_port);
	CHECK(client_fd >= 0, "could not connect deadline client");
	CHECK(short_test_send_all(client_fd, short_status_request, 1) == 0, "could not send deadline request prefix");
	struct timespec delay = { .tv_sec = 3, .tv_nsec = 200000000L };
	while (nanosleep(&delay, &delay) == -1) {
		CHECK(errno == EINTR, "could not wait before completing deadline request");
	}
	CHECK(short_test_send_all(client_fd, short_status_request + 1, sizeof(short_status_request) - 1U) == 0,
		"could not finish deadline request");
	char notification[128];
	ssize_t notification_size = short_test_fixture_notification(&fixture, notification, sizeof(notification));
	CHECK(notification_size > 0 && strcmp(notification, "MCRELAY_TEST_TIMER_REARM=1") == 0,
		"timer rearm regression hook did not run");
	uint8_t response[BUFSIZ];
	size_t response_size = 0;
	CHECK(short_test_receive_until_close(client_fd, response, sizeof(response), &response_size, 3000) == 0,
		"absolute lifetime did not close the pending connection");
	CHECK(response_size == 0, "absolute lifetime synthesized a connect-timeout response");
	CHECK(kill(fixture.listener, 0) == 0, "deadline connection terminated listener");
	test_result = true;

cleanup:
	if (client_fd >= 0) {
		close(client_fd);
	}
	if (fixture.listener > 0 || fixture.notify_fd >= 0) {
		short_test_fixture_stop(&fixture);
	}
	return test_result;
}

static bool short_test_lifetime(const char *binary, const char *directory) {
	bool test_result = false;
	short_fixture fixture = { .notify_fd = -1, .listener = -1 };
	int client_fd = -1;
	int upstream_fd = -1;
	int upstream_client_fd = -1;
	in_port_t upstream_port = 0;
	uint8_t request[sizeof(short_status_request) + 4U];
	uint8_t received[BUFSIZ];
	size_t received_size = 0;
	memcpy(request, short_status_request, sizeof(short_status_request));
	memcpy(request + sizeof(short_status_request), "tail", 4);
	upstream_fd = short_test_listener_open(&upstream_port);
	CHECK(upstream_fd >= 0, "could not open lifetime upstream");
	CHECK(short_test_fixture_start(&fixture, binary, directory, "lifetime", "127.0.0.1", upstream_port) == 0,
		"could not start lifetime listener");
	client_fd = short_test_client_connect(fixture.listener_port);
	CHECK(client_fd >= 0, "could not connect lifetime client");
	CHECK(short_test_send_all(client_fd, request, sizeof(request)) == 0, "could not send lifetime request");
	upstream_client_fd = short_test_listener_accept(upstream_fd);
	CHECK(upstream_client_fd >= 0, "lifetime request did not reach upstream");
	uint8_t forwarded[sizeof(request)];
	CHECK(short_test_receive_exact(upstream_client_fd, forwarded, sizeof(forwarded)) == 0 && memcmp(forwarded, request, sizeof(request)) == 0,
		"lifetime request was not forwarded in order");
	struct timespec delay = { .tv_sec = 2, .tv_nsec = 600000000L };
	nanosleep(&delay, NULL);
	static const uint8_t activity[] = "upstream-activity";
	CHECK(short_test_send_all(upstream_client_fd, activity, sizeof(activity) - 1U) == 0, "could not send upstream activity");
	CHECK(short_test_receive_until_close(client_fd, received, sizeof(received), &received_size, 4000) == 0,
		"lifetime did not close the client connection");
	CHECK(received_size == sizeof(activity) - 1U && memcmp(received, activity, sizeof(activity) - 1U) == 0,
		"lifetime response contained unexpected or synthesized data");
	test_result = true;

cleanup:
	if (client_fd >= 0) {
		close(client_fd);
	}
	if (upstream_client_fd >= 0) {
		close(upstream_client_fd);
	}
	if (upstream_fd >= 0) {
		close(upstream_fd);
	}
	if (fixture.listener > 0 || fixture.notify_fd >= 0) {
		short_test_fixture_stop(&fixture);
	}
	return test_result;
}

static bool short_test_refusal(const char *binary, const char *directory) {
	bool test_result = false;
	short_fixture fixture = { .notify_fd = -1, .listener = -1 };
	int client_fd = -1;
	int reservation_fd = -1;
	in_port_t refused_port = 0;
	uint8_t response[BUFSIZ];
	size_t response_size = 0;
	reservation_fd = short_test_listener_open(&refused_port);
	CHECK(reservation_fd >= 0, "could not reserve refused upstream port");
	CHECK(close(reservation_fd) == 0, "could not release refused upstream port");
	reservation_fd = -1;
	CHECK(short_test_fixture_start(&fixture, binary, directory, "refusal", "127.0.0.1", refused_port) == 0,
		"could not start refusal listener");
	client_fd = short_test_client_connect(fixture.listener_port);
	CHECK(client_fd >= 0, "could not connect refusal client");
	CHECK(short_test_send_all(client_fd, short_status_request, sizeof(short_status_request)) == 0, "could not send refusal request");
	CHECK(short_test_receive_until_close(client_fd, response, sizeof(response), &response_size, LISTENER_SHORT_TEST_TIMEOUT_MS) == 0,
		"refused connection did not close after response");
	CHECK(short_test_bytes_contain(response, response_size, "Server Temporarily Unavailable."), "refused connection response was not temporary-unavailable");
	test_result = true;

cleanup:
	if (client_fd >= 0) {
		close(client_fd);
	}
	if (reservation_fd >= 0) {
		close(reservation_fd);
	}
	if (fixture.listener > 0 || fixture.notify_fd >= 0) {
		short_test_fixture_stop(&fixture);
	}
	return test_result;
}

static bool short_test_release_fault_dispatch(const char *binary, const char *directory) {
	bool test_result = false;
	short_fixture fixture = { .notify_fd = -1, .listener = -1 };
	int client_fd = -1;
	int status = 0;
	CHECK(short_test_fixture_start(&fixture, binary, directory, "release-dispatch-io", "release-fault.example", 25565) == 0,
		"could not start dispatch release-failure listener");
	CHECK(short_test_fixture_release_trigger(&fixture) == 0, "could not arm dispatch release-failure injection");
	client_fd = short_test_client_connect(fixture.listener_port);
	CHECK(client_fd >= 0, "could not connect dispatch release-failure client");
	CHECK(short_test_send_all(client_fd, short_login_request, sizeof(short_login_request)) == 0,
		"could not send dispatch release-failure request");
	CHECK(short_test_fixture_wait_exit(&fixture, &status, LISTENER_SHORT_TEST_TIMEOUT_MS) == 0
		&& WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS, "dispatch release failure did not terminate the listener");
	CHECK(short_test_file_contains(fixture.log_filename, "Input/output error"), "dispatch release failure was not listener-fatal");
	test_result = true;

cleanup:
	if (client_fd >= 0) {
		close(client_fd);
	}
	if (fixture.listener > 0 || fixture.notify_fd >= 0) {
		short_test_fixture_stop(&fixture);
	}
	return test_result;
}

static bool short_test_release_fault_refusal(const char *binary, const char *directory) {
	bool test_result = false;
	short_fixture fixture = { .notify_fd = -1, .listener = -1 };
	int upstream_fd = -1;
	int upstream_a_fd = -1;
	int client_a_fd = -1;
	int client_refusal_fd = -1;
	int status = 0;
	in_port_t upstream_port = 0;
	upstream_fd = short_test_listener_open(&upstream_port);
	CHECK(upstream_fd >= 0, "could not open release-failure upstream");
	CHECK(short_test_fixture_start(&fixture, binary, directory, "release-refusal-io", "release-fault.example", upstream_port) == 0,
		"could not start refusal release-failure listener");
	client_a_fd = short_test_client_connect(fixture.listener_port);
	CHECK(client_a_fd >= 0 && short_test_send_all(client_a_fd, short_login_request, sizeof(short_login_request)) == 0,
		"could not start first release-failure worker");
	upstream_a_fd = short_test_listener_accept(upstream_fd);
	CHECK(upstream_a_fd >= 0, "first release-failure worker did not reach upstream");
	CHECK(short_test_fixture_release_trigger(&fixture) == 0, "could not arm refusal release-failure injection");
	client_refusal_fd = short_test_client_connect(fixture.listener_port);
	CHECK(client_refusal_fd >= 0 && short_test_send_all(client_refusal_fd, short_login_request, sizeof(short_login_request)) == 0,
		"could not start refusal release-failure client");
	CHECK(short_test_fixture_wait_exit(&fixture, &status, LISTENER_SHORT_TEST_TIMEOUT_MS) == 0
		&& WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS, "refusal release failure did not terminate the listener");
	CHECK(short_test_file_contains(fixture.log_filename, "Input/output error"), "refusal release failure was not listener-fatal");
	test_result = true;

cleanup:
	if (client_a_fd >= 0) {
		close(client_a_fd);
	}
	if (client_refusal_fd >= 0) {
		close(client_refusal_fd);
	}
	if (upstream_a_fd >= 0) {
		close(upstream_a_fd);
	}
	if (upstream_fd >= 0) {
		close(upstream_fd);
	}
	if (fixture.listener > 0 || fixture.notify_fd >= 0) {
		short_test_fixture_stop(&fixture);
	}
	return test_result;
}

static bool short_test_release_fault_short_case(const char *binary, const char *directory, const char *suffix, const char *expected_error) {
	bool test_result = false;
	short_fixture fixture = { .notify_fd = -1, .listener = -1 };
	int client_fd = -1;
	int status = 0;
	CHECK(short_test_fixture_start(&fixture, binary, directory, suffix, "release-fault.example", 25565) == 0,
		"could not start short release-failure listener");
	CHECK(short_test_fixture_release_trigger(&fixture) == 0, "could not arm short release-failure injection");
	client_fd = short_test_client_connect(fixture.listener_port);
	CHECK(client_fd >= 0, "could not connect short release-failure client");
	CHECK(short_test_send_all(client_fd, short_status_request, sizeof(short_status_request)) == 0,
		"could not send short release-failure request");
	CHECK(short_test_fixture_wait_exit(&fixture, &status, LISTENER_SHORT_TEST_TIMEOUT_MS) == 0
		&& WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS, "short release failure did not terminate the listener");
	CHECK(short_test_file_contains(fixture.log_filename, expected_error), "short release failure errno was not preserved in the fatal log");
	test_result = true;

cleanup:
	if (client_fd >= 0) {
		close(client_fd);
	}
	if (fixture.listener > 0 || fixture.notify_fd >= 0) {
		short_test_fixture_stop(&fixture);
	}
	return test_result;
}

static bool short_test_release_fault_short(const char *binary, const char *directory) {
	return short_test_release_fault_short_case(binary, directory, "release-short-bad", "Invalid argument")
		&& short_test_release_fault_short_case(binary, directory, "release-short-io", "Input/output error")
		&& short_test_release_fault_short_case(binary, directory, "release-short-time", "Value too large for defined data type");
}

static bool short_test_relay(const char *binary, const char *directory) {
	bool test_result = false;
	short_fixture fixture = { .notify_fd = -1, .listener = -1 };
	int client_fd = -1;
	int upstream_fd = -1;
	int upstream_client_fd = -1;
	in_port_t upstream_port = 0;
	uint8_t request[sizeof(short_status_request) + 4U];
	uint8_t marker[32768];
	uint8_t received[32768];
	uint8_t response[32768];
	size_t received_size = 0;
	for (size_t byte_index = 0; byte_index < sizeof(marker); byte_index++) {
		marker[byte_index] = (uint8_t)(byte_index * 29U + 3U);
		response[byte_index] = (uint8_t)(byte_index * 31U + 7U);
	}
	memcpy(request, short_status_request, sizeof(short_status_request));
	memcpy(request + sizeof(short_status_request), "tail", 4);
	upstream_fd = short_test_listener_open(&upstream_port);
	CHECK(upstream_fd >= 0, "could not open relay upstream");
	CHECK(short_test_fixture_start(&fixture, binary, directory, "relay", "127.0.0.1", upstream_port) == 0,
		"could not start relay listener");
	client_fd = short_test_client_connect(fixture.listener_port);
	CHECK(client_fd >= 0, "could not connect relay client");
	CHECK(short_test_send_all(client_fd, request, sizeof(request)) == 0, "could not send relay request");
	upstream_client_fd = short_test_listener_accept(upstream_fd);
	CHECK(upstream_client_fd >= 0, "relay request did not reach upstream");
	uint8_t forwarded[sizeof(request)];
	CHECK(short_test_receive_exact(upstream_client_fd, forwarded, sizeof(forwarded)) == 0 && memcmp(forwarded, request, sizeof(request)) == 0,
		"relay request ordering was not preserved");
	CHECK(short_test_config_write(&fixture, "127.0.0.1", upstream_port) == 0, "could not rewrite relay configuration");
	CHECK(kill(fixture.listener, SIGUSR1) == 0, "could not reload listener during short relay");
	char notification[128];
	ssize_t notification_size = short_test_fixture_notification(&fixture, notification, sizeof(notification));
	CHECK(notification_size > 0 && strncmp(notification, "RELOADING=1\nMONOTONIC_USEC=", strlen("RELOADING=1\nMONOTONIC_USEC=")) == 0,
		"short-relay reload notification was invalid");
	notification_size = short_test_fixture_notification(&fixture, notification, sizeof(notification));
	CHECK(notification_size > 0 && strcmp(notification, "READY=1") == 0, "short-relay reload completion was invalid");
	CHECK(short_test_send_all(client_fd, marker, sizeof(marker)) == 0, "could not send relay data after reload");
	CHECK(short_test_receive_exact(upstream_client_fd, received, sizeof(marker)) == 0 && memcmp(received, marker, sizeof(marker)) == 0,
		"relay data changed or stalled across reload");
	CHECK(shutdown(client_fd, SHUT_WR) == 0, "could not half-close client request");
	uint8_t upstream_end;
	size_t upstream_received_size = 0;
	CHECK(short_test_receive_until_close(upstream_client_fd, &upstream_end, sizeof(upstream_end), &upstream_received_size, LISTENER_SHORT_TEST_TIMEOUT_MS) == 0
		&& upstream_received_size == 0, "relay did not propagate client half-close");
	CHECK(short_test_send_all(upstream_client_fd, response, sizeof(response)) == 0, "could not send relay response");
	CHECK(shutdown(upstream_client_fd, SHUT_WR) == 0, "could not half-close upstream response");
	CHECK(short_test_receive_exact(client_fd, received, sizeof(received)) == 0 && memcmp(received, response, sizeof(response)) == 0,
		"relay response ordering was not preserved");
	uint8_t end_byte;
	CHECK(short_test_receive_until_close(client_fd, &end_byte, sizeof(end_byte), &received_size, LISTENER_SHORT_TEST_TIMEOUT_MS) == 0 && received_size == 0,
		"relay did not propagate upstream half-close");
	test_result = true;

cleanup:
	if (client_fd >= 0) {
		close(client_fd);
	}
	if (upstream_client_fd >= 0) {
		close(upstream_client_fd);
	}
	if (upstream_fd >= 0) {
		close(upstream_fd);
	}
	if (fixture.listener > 0 || fixture.notify_fd >= 0) {
		short_test_fixture_stop(&fixture);
	}
	return test_result;
}

static bool short_test_relay_upstream_first(const char *binary, const char *directory) {
	bool test_result = false;
	short_fixture fixture = { .notify_fd = -1, .listener = -1 };
	int client_fd = -1;
	int upstream_fd = -1;
	int upstream_client_fd = -1;
	in_port_t upstream_port = 0;
	static const uint8_t marker[] = "client-after-upstream-fin";
	static const uint8_t response[] = "upstream-before-client-fin";
	upstream_fd = short_test_listener_open(&upstream_port);
	CHECK(upstream_fd >= 0, "could not open reverse-half-close upstream");
	CHECK(short_test_fixture_start(&fixture, binary, directory, "reverse", "127.0.0.1", upstream_port) == 0,
		"could not start reverse-half-close listener");
	client_fd = short_test_client_connect(fixture.listener_port);
	CHECK(client_fd >= 0, "could not connect reverse-half-close client");
	CHECK(short_test_send_all(client_fd, short_status_request, sizeof(short_status_request)) == 0,
		"could not send reverse-half-close request");
	upstream_client_fd = short_test_listener_accept(upstream_fd);
	CHECK(upstream_client_fd >= 0, "reverse-half-close request did not reach upstream");
	uint8_t forwarded[sizeof(short_status_request)];
	CHECK(short_test_receive_exact(upstream_client_fd, forwarded, sizeof(forwarded)) == 0
		&& memcmp(forwarded, short_status_request, sizeof(forwarded)) == 0, "reverse-half-close request was not forwarded");
	CHECK(short_test_send_all(upstream_client_fd, response, sizeof(response) - 1U) == 0, "could not send reverse-half-close response");
	CHECK(shutdown(upstream_client_fd, SHUT_WR) == 0, "could not half-close upstream first");
	uint8_t received[sizeof(response) - 1U];
	CHECK(short_test_receive_exact(client_fd, received, sizeof(received)) == 0 && memcmp(received, response, sizeof(received)) == 0,
		"reverse-half-close response was not forwarded");
	uint8_t end_byte;
	size_t end_size = 0;
	CHECK(short_test_receive_until_close(client_fd, &end_byte, sizeof(end_byte), &end_size, LISTENER_SHORT_TEST_TIMEOUT_MS) == 0 && end_size == 0,
		"upstream half-close was not propagated to client");
	CHECK(short_test_send_all(client_fd, marker, sizeof(marker) - 1U) == 0, "client could not write after upstream half-close");
	CHECK(shutdown(client_fd, SHUT_WR) == 0, "could not half-close client second");
	uint8_t forwarded_marker[sizeof(marker) - 1U];
	CHECK(short_test_receive_exact(upstream_client_fd, forwarded_marker, sizeof(forwarded_marker)) == 0
		&& memcmp(forwarded_marker, marker, sizeof(forwarded_marker)) == 0, "client data after upstream half-close was not forwarded");
	end_size = 0;
	CHECK(short_test_receive_until_close(upstream_client_fd, &end_byte, sizeof(end_byte), &end_size, LISTENER_SHORT_TEST_TIMEOUT_MS) == 0 && end_size == 0,
		"client half-close was not propagated to upstream");
	test_result = true;

cleanup:
	if (client_fd >= 0) {
		close(client_fd);
	}
	if (upstream_client_fd >= 0) {
		close(upstream_client_fd);
	}
	if (upstream_fd >= 0) {
		close(upstream_fd);
	}
	if (fixture.listener > 0 || fixture.notify_fd >= 0) {
		short_test_fixture_stop(&fixture);
	}
	return test_result;
}

static bool short_test_reload_late_case(const char *binary, const char *directory, const char *suffix, const char *address, in_port_t port,
	bool release_with_short_start) {
	bool test_result = false;
	short_fixture fixture = { .notify_fd = -1, .listener = -1 };
	int client_fd = -1;
	CHECK(short_test_fixture_start(&fixture, binary, directory, suffix, address, port) == 0,
		"could not start late-reload listener");
	client_fd = short_test_client_connect(fixture.listener_port);
	CHECK(client_fd >= 0, "could not connect late-reload client");
	if (!release_with_short_start) {
		CHECK(short_test_send_all(client_fd, short_status_request, sizeof(short_status_request)) == 0, "could not send late-reload request");
	}
	struct timespec delay = { .tv_nsec = 100000000L };
	while (nanosleep(&delay, &delay) == -1) {
		CHECK(errno == EINTR, "could not wait for late-reload client state");
	}
	CHECK(short_test_config_write(&fixture, address, port) == 0, "could not rewrite configuration for first reload");
	CHECK(kill(fixture.listener, SIGUSR1) == 0, "could not request first late-reload reload");
	char notification[128];
	ssize_t notification_size = short_test_fixture_notification(&fixture, notification, sizeof(notification));
	CHECK(notification_size > 0 && strncmp(notification, "RELOADING=1\nMONOTONIC_USEC=", strlen("RELOADING=1\nMONOTONIC_USEC=")) == 0,
		"first late-reload notification was invalid");
	notification_size = short_test_fixture_notification(&fixture, notification, sizeof(notification));
	CHECK(notification_size > 0 && strcmp(notification, "READY=1") == 0, "first late-reload completion was invalid");
	CHECK(short_test_config_write(&fixture, address, port) == 0, "could not rewrite configuration for deferred reload");
	CHECK(kill(fixture.listener, SIGUSR1) == 0, "could not request deferred late-reload reload");
	errno = 0;
	CHECK(short_test_fixture_notification_timeout(&fixture, notification, sizeof(notification), LISTENER_RELOAD_LATE_TEST_DEFERRED_MS) == -1
		&& errno == ETIMEDOUT, "deferred late-reload unexpectedly completed while the generation was pinned");
	if (release_with_short_start) {
		CHECK(short_test_send_all(client_fd, short_status_request, sizeof(short_status_request)) == 0, "could not send late-reload request");
	} else {
		CHECK(close(client_fd) == 0, "could not close late-reload client to release the generation");
		client_fd = -1;
	}
	notification_size = short_test_fixture_notification_timeout(&fixture, notification, sizeof(notification), LISTENER_RELOAD_LATE_TEST_RELEASE_MS);
	CHECK(notification_size > 0 && strncmp(notification, "RELOADING=1\nMONOTONIC_USEC=", strlen("RELOADING=1\nMONOTONIC_USEC=")) == 0,
		"deferred late-reload notification was missing");
	notification_size = short_test_fixture_notification(&fixture, notification, sizeof(notification));
	CHECK(notification_size > 0 && strcmp(notification, "READY=1") == 0, "deferred late-reload completion was invalid");
	if (release_with_short_start) {
		CHECK(short_test_client_alive(client_fd), "short-start late-reload client was destroyed before upstream connect completed");
	}
	errno = 0;
	CHECK(short_test_fixture_notification_timeout(&fixture, notification, sizeof(notification), LISTENER_RELOAD_LATE_TEST_DEFERRED_MS) == -1
		&& errno == ETIMEDOUT, "deferred late-reload executed more than once");
	CHECK(kill(fixture.listener, 0) == 0, "late-reload release terminated listener");
	CHECK(short_test_fixture_stop(&fixture) == 0, "late-reload listener did not stop cleanly");
	test_result = true;

cleanup:
	if (client_fd >= 0) {
		close(client_fd);
	}
	if (fixture.listener > 0 || fixture.notify_fd >= 0) {
		short_test_fixture_stop(&fixture);
	}
	return test_result;
}

static bool short_test_reload_late_release(const char *binary, const char *directory) {
	return short_test_reload_late_case(binary, directory, "reload-late", "route-wait.example", 25565, false);
}

static bool short_test_reload_late_release_short_start(const char *binary, const char *directory) {
	return short_test_reload_late_case(binary, directory, "reload-late-short", "127.0.0.1", 9, true);
}

static bool short_test_route_cancel(const char *binary, const char *directory) {
	bool test_result = false;
	short_fixture fixture = { .notify_fd = -1, .listener = -1 };
	int client_fd = -1;
	CHECK(short_test_fixture_start(&fixture, binary, directory, "route-cancel", "route-wait.example", 25565) == 0,
		"could not start route-cancellation listener");
	client_fd = short_test_client_connect(fixture.listener_port);
	CHECK(client_fd >= 0, "could not connect route-cancellation client");
	CHECK(short_test_send_all(client_fd, short_status_request, sizeof(short_status_request)) == 0, "could not send route-cancellation request");
	struct timespec delay = { .tv_nsec = 100000000L };
	while (nanosleep(&delay, &delay) == -1) {
		CHECK(errno == EINTR, "could not wait for pending route resolution");
	}
	CHECK(shutdown(client_fd, SHUT_WR) == 0, "could not half-close route-cancellation client");
	uint8_t response;
	size_t response_size = 0;
	CHECK(short_test_receive_until_close(client_fd, &response, sizeof(response), &response_size, LISTENER_ROUTE_CANCEL_TEST_TIMEOUT_MS) == 0
		&& response_size == 0, "route wait did not treat client half-close as cancellation");
	CHECK(kill(fixture.listener, 0) == 0, "route cancellation terminated listener");
	test_result = true;

cleanup:
	if (client_fd >= 0) {
		close(client_fd);
	}
	if (fixture.listener > 0 || fixture.notify_fd >= 0) {
		short_test_fixture_stop(&fixture);
	}
	return test_result;
}

static bool short_test_stop(const char *binary, const char *directory) {
	bool test_result = false;
	short_fixture fixture = { .notify_fd = -1, .listener = -1 };
	int client_fd = -1;
	int upstream_fd = -1;
	int upstream_client_fd = -1;
	in_port_t upstream_port = 0;
	upstream_fd = short_test_listener_open(&upstream_port);
	CHECK(upstream_fd >= 0, "could not open stop upstream");
	CHECK(short_test_fixture_start(&fixture, binary, directory, "stop", "127.0.0.1", upstream_port) == 0,
		"could not start stop listener");
	client_fd = short_test_client_connect(fixture.listener_port);
	CHECK(client_fd >= 0, "could not connect stop client");
	CHECK(short_test_send_all(client_fd, short_status_request, sizeof(short_status_request)) == 0, "could not send stop request");
	upstream_client_fd = short_test_listener_accept(upstream_fd);
	CHECK(upstream_client_fd >= 0, "stop request did not reach upstream");
	uint8_t forwarded[sizeof(short_status_request)];
	CHECK(short_test_receive_exact(upstream_client_fd, forwarded, sizeof(forwarded)) == 0, "could not receive stop request");
	CHECK(kill(fixture.listener, SIGTERM) == 0, "could not stop listener with an active short relay");
	uint8_t end_byte;
	size_t end_size = 0;
	CHECK(short_test_receive_until_close(client_fd, &end_byte, sizeof(end_byte), &end_size, LISTENER_SHORT_TEST_TIMEOUT_MS) == 0 && end_size == 0,
		"listener stop did not close short client");
	end_size = 0;
	CHECK(short_test_receive_until_close(upstream_client_fd, &end_byte, sizeof(end_byte), &end_size, LISTENER_SHORT_TEST_TIMEOUT_MS) == 0 && end_size == 0,
		"listener stop did not close short upstream");
	CHECK(short_test_fixture_stop(&fixture) == 0, "listener did not finish orderly resolver shutdown after closing short relay");
	test_result = true;

cleanup:
	if (client_fd >= 0) {
		close(client_fd);
	}
	if (upstream_client_fd >= 0) {
		close(upstream_client_fd);
	}
	if (upstream_fd >= 0) {
		close(upstream_fd);
	}
	if (fixture.listener > 0 || fixture.notify_fd >= 0) {
		short_test_fixture_stop(&fixture);
	}
	return test_result;
}

/* section: functions (entry point) */
int main(int argc, char **argv) {
	bool test_result = false;
	char temp_directory[] = "/tmp/mcrelay-listener-short-XXXXXX";
	if (argc != 2) {
		fprintf(stderr, "usage: %s <listener-short-daemon>\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (mkdtemp(temp_directory) == NULL) {
		fprintf(stderr, "cannot create temporary directory (errno=%d)\n", errno);
		return EXIT_FAILURE;
	}
	test_result = short_test_admission(argv[1], temp_directory) && short_test_deadline(argv[1], temp_directory)
		&& short_test_lifetime(argv[1], temp_directory) && short_test_refusal(argv[1], temp_directory)
		&& short_test_release_fault_short(argv[1], temp_directory) && short_test_release_fault_dispatch(argv[1], temp_directory)
		&& short_test_release_fault_refusal(argv[1], temp_directory)
		&& short_test_relay(argv[1], temp_directory) && short_test_relay_upstream_first(argv[1], temp_directory)
		&& short_test_reload_late_release(argv[1], temp_directory) && short_test_reload_late_release_short_start(argv[1], temp_directory)
		&& short_test_route_cancel(argv[1], temp_directory)
		&& short_test_stop(argv[1], temp_directory);
	if (rmdir(temp_directory) == -1 && errno != ENOENT) {
		test_result = false;
	}
	return test_result ? EXIT_SUCCESS : EXIT_FAILURE;
}
