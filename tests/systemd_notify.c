/*
 * systemd_notify.c: Tests for systemd notification protocol
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
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
#include <sys/stat.h>
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
#define MESSAGE_TIMEOUT_MS	5000
#define QUIET_TIMEOUT_MS	500

/* section: functions (local) */
static pid_t child_start(const char *binary, const char *config_filename, const char *notify_socket) {
	pid_t child = fork();
	if (child != 0) {
		return child;
	}
	int devnull_fd = open("/dev/null", O_WRONLY);
	if (devnull_fd == -1 || dup2(devnull_fd, STDOUT_FILENO) == -1 || dup2(devnull_fd, STDERR_FILENO) == -1 || setenv("NOTIFY_SOCKET", notify_socket, 1) == -1) {
		_exit(EXIT_FAILURE);
	}
	close(devnull_fd);
	execl(binary, binary, "run", "-c", config_filename, (char *)NULL);
	_exit(EXIT_FAILURE);
}

static int child_wait(pid_t child, int timeout_ms) {
	const struct timespec interval = {
		.tv_nsec = 10000000
	};
	for (int elapsed_ms = 0; elapsed_ms < timeout_ms; elapsed_ms += 10) {
		int status;
		pid_t wait_result = waitpid(child, &status, WNOHANG);
		if (wait_result == child) {
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

static ssize_t message_receive(int socket_fd, char *message, size_t message_size, int timeout_ms) {
	struct pollfd poll_fd = {
		.fd = socket_fd,
		.events = POLLIN
	};
	int poll_result;
	do {
		poll_result = poll(&poll_fd, 1, timeout_ms);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result <= 0) {
		return poll_result;
	}
	if (!(poll_fd.revents & POLLIN)) {
		errno = EIO;
		return -1;
	}
	ssize_t message_length = recv(socket_fd, message, message_size - 1, 0);
	if (message_length >= 0) {
		message[message_length] = '\0';
	}
	return message_length;
}

static bool message_reloading_valid(const char *message, uint64_t earliest_usec, uint64_t latest_usec) {
	static const char prefix[] = "RELOADING=1\nMONOTONIC_USEC=";
	if (strncmp(message, prefix, sizeof(prefix) - 1) != 0) {
		return false;
	}
	char *end = NULL;
	errno = 0;
	uintmax_t timestamp_usec = strtoumax(message + sizeof(prefix) - 1, &end, 10);
	return errno == 0 && end != NULL && *end == '\0' && timestamp_usec >= earliest_usec && timestamp_usec <= latest_usec;
}

static int monotonic_usec(uint64_t *result) {
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
	*result = (uint64_t)timestamp.tv_sec * 1000000 + timestamp_subsecond_usec;
	return 0;
}

static int port_find(in_port_t *result) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	socklen_t address_length = sizeof(address);
	if (getsockname(fd, (struct sockaddr *)&address, &address_length) == -1) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	*result = ntohs(address.sin_port);
	return close(fd);
}

static int write_config(const char *filename, const char *log_filename, in_port_t port) {
	char content[PATH_MAX + 512];
	int content_length = snprintf(content, sizeof(content),
		"{\"log\":{\"filename\":\"%s\",\"level\":4},\"listen\":{\"address\":\"127.0.0.1\",\"port\":%u},\"icon\":\"\",\"proxy\":[{\"vhost\":\"test.example\",\"address\":\"127.0.0.1\",\"port\":25565}]}\n",
		log_filename, (unsigned int)port
	);
	if (content_length < 0 || (size_t)content_length >= sizeof(content)) {
		errno = EOVERFLOW;
		return -1;
	}
	int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1) {
		return -1;
	}
	size_t written = 0;
	while (written < (size_t)content_length) {
		ssize_t write_result = write(fd, content + written, (size_t)content_length - written);
		if (write_result <= 0) {
			int saved_errno = errno;
			close(fd);
			errno = saved_errno;
			return -1;
		}
		written += (size_t)write_result;
	}
	return close(fd);
}

/* section: functions (entry point) */
int main(int argc, char **argv) {
	char temp_directory[] = "/tmp/mcrelay-systemd-notify-XXXXXX";
	char config_filename[PATH_MAX] = { 0 };
	char log_filename[PATH_MAX] = { 0 };
	char notify_filename[PATH_MAX] = { 0 };
	char reload_fifo_filename[PATH_MAX] = { 0 };
	char message[256];
	int fifo_fd = -1;
	int result = EXIT_FAILURE;
	int socket_fd = -1;
	pid_t child = -1;
	CHECK(argc == 2, "mcrelay executable path is required");
	CHECK(mkdtemp(temp_directory) != NULL, "cannot create temporary directory");
	int filename_length = snprintf(config_filename, sizeof(config_filename), "%s/config.json", temp_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(config_filename), "cannot format configuration filename");
	filename_length = snprintf(log_filename, sizeof(log_filename), "%s/access.log", temp_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(log_filename), "cannot format log filename");
	filename_length = snprintf(notify_filename, sizeof(notify_filename), "%s/notify.sock", temp_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(notify_filename), "cannot format notification socket filename");
	filename_length = snprintf(reload_fifo_filename, sizeof(reload_fifo_filename), "%s/reload.fifo", temp_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(reload_fifo_filename), "cannot format reload FIFO filename");
	in_port_t port;
	CHECK(port_find(&port) == 0, "cannot find a free listener port");
	CHECK(write_config(config_filename, log_filename, port) == 0, "cannot write configuration");

	socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	CHECK(socket_fd != -1, "cannot create notification socket");
	struct sockaddr_un notify_address;
	memset(&notify_address, 0, sizeof(notify_address));
	notify_address.sun_family = AF_UNIX;
	CHECK(strlen(notify_filename) < sizeof(notify_address.sun_path), "notification socket filename is too long");
	strcpy(notify_address.sun_path, notify_filename);
	CHECK(bind(socket_fd, (struct sockaddr *)&notify_address, sizeof(notify_address)) == 0, "cannot bind notification socket");

	child = child_start(argv[1], config_filename, notify_filename);
	CHECK(child > 0, "cannot start mcrelay");
	CHECK(message_receive(socket_fd, message, sizeof(message), MESSAGE_TIMEOUT_MS) > 0 && strcmp(message, "READY=1") == 0, "startup READY notification is missing");

	uint64_t earliest_usec, latest_usec;
	CHECK(monotonic_usec(&earliest_usec) == 0 && kill(child, SIGUSR1) == 0, "cannot request successful reload");
	CHECK(message_receive(socket_fd, message, sizeof(message), MESSAGE_TIMEOUT_MS) > 0, "successful RELOADING notification is missing");
	CHECK(monotonic_usec(&latest_usec) == 0 && message_reloading_valid(message, earliest_usec, latest_usec), "successful RELOADING notification is invalid");
	CHECK(message_receive(socket_fd, message, sizeof(message), MESSAGE_TIMEOUT_MS) > 0 && strcmp(message, "READY=1") == 0, "successful reload READY notification is missing");

	CHECK(unlink(config_filename) == 0, "cannot remove configuration for failure test");
	CHECK(monotonic_usec(&earliest_usec) == 0 && kill(child, SIGUSR1) == 0, "cannot request failed reload");
	CHECK(message_receive(socket_fd, message, sizeof(message), MESSAGE_TIMEOUT_MS) > 0, "failed RELOADING notification is missing");
	CHECK(monotonic_usec(&latest_usec) == 0 && message_reloading_valid(message, earliest_usec, latest_usec), "failed RELOADING notification is invalid");
	CHECK(message_receive(socket_fd, message, sizeof(message), MESSAGE_TIMEOUT_MS) > 0 && strcmp(message, "READY=1") == 0, "failed reload READY notification is missing");

	CHECK(monotonic_usec(&earliest_usec) == 0, "cannot read timestamp before repeated reloads");
	for (int signal_count = 0; signal_count < 8; signal_count++) {
		CHECK(kill(child, SIGUSR1) == 0, "cannot request repeated reload");
	}
	bool expect_reloading = true;
	int reload_count = 0;
	while (1) {
		ssize_t message_length = message_receive(socket_fd, message, sizeof(message), reload_count == 0 ? MESSAGE_TIMEOUT_MS : QUIET_TIMEOUT_MS);
		CHECK(message_length >= 0, "cannot receive repeated reload notification");
		if (message_length == 0) {
			break;
		}
		if (expect_reloading) {
			CHECK(monotonic_usec(&latest_usec) == 0 && message_reloading_valid(message, earliest_usec, latest_usec), "repeated reload notification is invalid");
		} else {
			CHECK(strcmp(message, "READY=1") == 0, "repeated reload READY notification is missing");
			reload_count++;
		}
		expect_reloading = !expect_reloading;
	}
	CHECK(expect_reloading && reload_count > 0, "repeated reload notifications are not paired");

	/* The FIFO blocks candidate log validation until its read side is opened, pinning do_reload() after RELOADING=1 while reload messages keep using the active log. */
	CHECK(mkfifo(reload_fifo_filename, 0600) == 0, "cannot create reload FIFO");
	CHECK(write_config(config_filename, reload_fifo_filename, port) == 0, "cannot write blocking reload configuration");
	CHECK(monotonic_usec(&earliest_usec) == 0 && kill(child, SIGUSR1) == 0, "cannot request blocking reload");
	CHECK(message_receive(socket_fd, message, sizeof(message), MESSAGE_TIMEOUT_MS) > 0, "blocking RELOADING notification is missing");
	CHECK(monotonic_usec(&latest_usec) == 0 && message_reloading_valid(message, earliest_usec, latest_usec), "blocking RELOADING notification is invalid");
	CHECK(kill(child, SIGTERM) == 0, "cannot request stop during reload");
	fifo_fd = open(reload_fifo_filename, O_RDONLY | O_NONBLOCK);
	CHECK(fifo_fd != -1, "cannot unblock reload FIFO");
	CHECK(message_receive(socket_fd, message, sizeof(message), MESSAGE_TIMEOUT_MS) > 0 && strcmp(message, "READY=1") == 0, "reload READY notification is missing before stop");
	CHECK(child_wait(child, MESSAGE_TIMEOUT_MS) == 0, "listener did not exit after stop during reload");
	child = -1;
	CHECK(message_receive(socket_fd, message, sizeof(message), QUIET_TIMEOUT_MS) == 0, "unexpected notification was sent after stop during reload");
	CHECK(close(fifo_fd) == 0, "cannot close reload FIFO");
	fifo_fd = -1;
	CHECK(unlink(reload_fifo_filename) == 0, "cannot remove reload FIFO");
	CHECK(write_config(config_filename, log_filename, port) == 0, "cannot restore configuration for signal-priority test");
	child = child_start(argv[1], config_filename, notify_filename);
	CHECK(child > 0, "cannot restart mcrelay for signal-priority test");
	CHECK(message_receive(socket_fd, message, sizeof(message), MESSAGE_TIMEOUT_MS) > 0 && strcmp(message, "READY=1") == 0, "restart READY notification is missing");

	CHECK(kill(child, SIGSTOP) == 0, "cannot stop listener for signal-priority test");
	int child_status;
	CHECK(waitpid(child, &child_status, WUNTRACED) == child && WIFSTOPPED(child_status), "listener did not stop for signal-priority test");
	CHECK(kill(child, SIGUSR1) == 0 && kill(child, SIGTERM) == 0 && kill(child, SIGCONT) == 0, "cannot send simultaneous stop and reload requests");
	CHECK(child_wait(child, MESSAGE_TIMEOUT_MS) == 0, "listener did not exit after simultaneous stop and reload requests");
	child = -1;
	CHECK(message_receive(socket_fd, message, sizeof(message), QUIET_TIMEOUT_MS) == 0, "reload notification was sent despite a pending stop request");

	result = EXIT_SUCCESS;

cleanup:
	if (child > 0) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
	}
	if (socket_fd != -1) {
		close(socket_fd);
	}
	if (fifo_fd != -1) {
		close(fifo_fd);
	}
	unlink(notify_filename);
	unlink(config_filename);
	unlink(log_filename);
	unlink(reload_fifo_filename);
	rmdir(temp_directory);
	return result;
}
