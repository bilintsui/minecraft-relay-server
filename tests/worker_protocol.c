/*
 * worker_protocol.c: Tests for worker protocol input handling
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
#define INITIAL_PACKET_CLOSE_TIMEOUT_MS	12000
#define INITIAL_PACKET_REFRESH_DELAY_SEC	5
#define INITIAL_PACKET_TIMEOUT_WAIT_MS	7000
#define QUIET_TIMEOUT_MS	100
#define SPLIT_DELAY_NS	10000000
#define TEST_TIMEOUT_MS	5000

/* section: types */
typedef struct {
	const char *filename;
	size_t required_size;
	bool update_modern_version;
} worker_fragment_fixture;

typedef struct {
	const char *filename;
	bool forwarded;
	bool response;
} worker_packet_fixture;

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
	const struct timespec interval = { .tv_nsec = 10000000 };
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

static int client_connect(in_port_t port) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port)
	};
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	return fd;
}

static ssize_t file_read(const char *filename, void *data, size_t capacity) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		return -1;
	}
	size_t size = fread(data, 1, capacity, file);
	if (ferror(file)) {
		int saved_errno = errno;
		fclose(file);
		errno = saved_errno;
		return -1;
	}
	if (fclose(file) != 0) {
		return -1;
	}
	return (ssize_t)size;
}

static ssize_t message_receive(int socket_fd, void *message, size_t message_size, int timeout_ms) {
	struct pollfd poll_fd = {
		.fd = socket_fd,
		.events = POLLIN
	};
	int poll_result;
	do {
		poll_result = poll(&poll_fd, 1, timeout_ms);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result == 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	if (poll_result == -1) {
		return poll_result;
	}
	if (!(poll_fd.revents & (POLLIN | POLLHUP))) {
		errno = EIO;
		return -1;
	}
	return recv(socket_fd, message, message_size, 0);
}

static int server_accept(int server_fd, int timeout_ms) {
	struct pollfd poll_fd = {
		.fd = server_fd,
		.events = POLLIN
	};
	int poll_result;
	do {
		poll_result = poll(&poll_fd, 1, timeout_ms);
	} while (poll_result == -1 && errno == EINTR);
	if (poll_result == 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	if (poll_result == -1) {
		return -1;
	}
	if (!(poll_fd.revents & POLLIN)) {
		errno = EIO;
		return -1;
	}
	return accept(server_fd, NULL, NULL);
}

static int server_open(in_port_t *port) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}
	int reuse_address = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address)) == -1) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
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
	if (getsockname(fd, (struct sockaddr *)&address, &address_length) == -1 || listen(fd, 1) == -1) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	*port = ntohs(address.sin_port);
	return fd;
}

static int server_open_ipv6(in_port_t *port) {
	int fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}
	int reuse_address = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address)) == -1) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	struct sockaddr_in6 address = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT
	};
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	socklen_t address_length = sizeof(address);
	if (getsockname(fd, (struct sockaddr *)&address, &address_length) == -1 || listen(fd, 1) == -1) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	*port = ntohs(address.sin6_port);
	return fd;
}

static ssize_t socket_receive_all(int socket_fd, void *data, size_t capacity, int timeout_ms) {
	size_t size = 0;
	while (size < capacity) {
		ssize_t receive_result = message_receive(socket_fd, (uint8_t *)data + size, capacity - size, timeout_ms);
		if (receive_result == 0) {
			return (ssize_t)size;
		}
		if (receive_result == -1) {
			return -1;
		}
		size += (size_t)receive_result;
	}
	errno = EMSGSIZE;
	return -1;
}

static int socket_send_all(int socket_fd, const void *data, size_t size) {
	const uint8_t *bytes = data;
	size_t sent = 0;
	while (sent < size) {
		ssize_t send_result = send(socket_fd, bytes + sent, size - sent, MSG_NOSIGNAL);
		if (send_result == -1 && errno == EINTR) {
			continue;
		}
		if (send_result <= 0) {
			return -1;
		}
		sent += (size_t)send_result;
	}
	return 0;
}

static int worker_packet_forward_split(in_port_t listener_port, int upstream_server_fd, const uint8_t *packet, size_t packet_size, size_t split_size) {
	int client_fd = -1;
	int result = -1;
	int upstream_client_fd = -1;
	if (packet == NULL || packet_size > BUFSIZ || split_size == 0 || split_size >= packet_size) {
		errno = EINVAL;
		return -1;
	}
	client_fd = client_connect(listener_port);
	if (client_fd == -1 || socket_send_all(client_fd, packet, split_size) == -1) {
		goto cleanup;
	}
	struct timespec delay = { .tv_nsec = SPLIT_DELAY_NS };
	while (nanosleep(&delay, &delay) == -1) {
		if (errno != EINTR) {
			goto cleanup;
		}
	}
	if (socket_send_all(client_fd, packet + split_size, packet_size - split_size) == -1 || shutdown(client_fd, SHUT_WR) == -1) {
		goto cleanup;
	}
	upstream_client_fd = server_accept(upstream_server_fd, TEST_TIMEOUT_MS);
	if (upstream_client_fd == -1) {
		goto cleanup;
	}
	uint8_t received[BUFSIZ];
	size_t received_size = 0;
	while (received_size < packet_size) {
		ssize_t receive_size = message_receive(upstream_client_fd, received + received_size, packet_size - received_size, TEST_TIMEOUT_MS);
		if (receive_size <= 0) {
			goto cleanup;
		}
		received_size += (size_t)receive_size;
	}
	if (memcmp(received, packet, packet_size) != 0) {
		errno = EPROTO;
		goto cleanup;
	}
	result = 0;
cleanup: {
		int saved_errno = errno;
		if (upstream_client_fd != -1) {
			close(upstream_client_fd);
		}
		if (client_fd != -1) {
			close(client_fd);
		}
		errno = saved_errno;
		return result;
	}
}

static int worker_packet_timeout(in_port_t listener_port, int upstream_server_fd) {
	static const uint8_t incomplete_packet[] = { 0x7F, 0x00 };
	int client_fd = -1;
	int result = -1;
	int upstream_client_fd = -1;
	client_fd = client_connect(listener_port);
	if (client_fd == -1 || socket_send_all(client_fd, incomplete_packet, 1) == -1) {
		goto cleanup;
	}
	uint8_t response;
	ssize_t receive_result = message_receive(client_fd, &response, sizeof(response), QUIET_TIMEOUT_MS);
	if (receive_result != -1 || errno != ETIMEDOUT) {
		errno = EPROTO;
		goto cleanup;
	}
	/* Refresh an incomplete packet midway through the assembly window; the absolute deadline must not move. */
	struct timespec refresh_delay = { .tv_sec = INITIAL_PACKET_REFRESH_DELAY_SEC };
	while (nanosleep(&refresh_delay, &refresh_delay) == -1) {
		if (errno != EINTR) {
			goto cleanup;
		}
	}
	if (socket_send_all(client_fd, incomplete_packet + 1, 1) == -1) {
		goto cleanup;
	}
	receive_result = message_receive(client_fd, &response, sizeof(response), INITIAL_PACKET_TIMEOUT_WAIT_MS);
	if (receive_result != 0) {
		if (receive_result > 0) {
			errno = EPROTO;
		}
		goto cleanup;
	}
	upstream_client_fd = server_accept(upstream_server_fd, 0);
	if (upstream_client_fd != -1 || errno != ETIMEDOUT) {
		errno = EPROTO;
		goto cleanup;
	}
	result = 0;
cleanup: {
		int saved_errno = errno;
		if (upstream_client_fd != -1) {
			close(upstream_client_fd);
		}
		if (client_fd != -1) {
			close(client_fd);
		}
		errno = saved_errno;
		return result;
	}
}

static int worker_packet_truncate(in_port_t listener_port, int upstream_server_fd, const uint8_t *packet, size_t prefix_size) {
	int client_fd = -1;
	int result = -1;
	int upstream_client_fd = -1;
	if (packet == NULL || prefix_size == 0 || prefix_size >= BUFSIZ) {
		errno = EINVAL;
		return -1;
	}
	client_fd = client_connect(listener_port);
	if (client_fd == -1 || socket_send_all(client_fd, packet, prefix_size) == -1 || shutdown(client_fd, SHUT_WR) == -1) {
		goto cleanup;
	}
	uint8_t response[BUFSIZ];
	/* Allow the production assembly deadline and a two-second processing margin to close a permanently truncated connection. */
	if (socket_receive_all(client_fd, response, sizeof(response), INITIAL_PACKET_CLOSE_TIMEOUT_MS) == -1) {
		goto cleanup;
	}
	upstream_client_fd = server_accept(upstream_server_fd, 0);
	if (upstream_client_fd != -1 || errno != ETIMEDOUT) {
		errno = EPROTO;
		goto cleanup;
	}
	result = 0;
cleanup: {
		int saved_errno = errno;
		if (upstream_client_fd != -1) {
			close(upstream_client_fd);
		}
		if (client_fd != -1) {
			close(client_fd);
		}
		errno = saved_errno;
		return result;
	}
}

static int write_config(const char *filename, const char *log_filename, in_port_t listener_port, in_port_t upstream_port) {
	char content[PATH_MAX + 512];
	int content_length = snprintf(content, sizeof(content),
		"{\"log\":{\"filename\":\"%s\",\"level\":4},\"listen\":{\"address\":\"127.0.0.1\",\"port\":%u},\"icon\":\"\",\"proxy\":["
		"{\"vhost\":[\"localhost\",\"test.example\"],\"address\":\"127.0.0.1\",\"port\":%u}]}\n",
		log_filename, (unsigned int)listener_port, (unsigned int)upstream_port
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

static int write_proxy_config(const char *filename, const char *log_filename, in_port_t listener_port, in_port_t upstream_port) {
	char content[PATH_MAX + 512];
	int content_length = snprintf(content, sizeof(content),
		"{\"log\":{\"filename\":\"%s\",\"level\":4},\"listen\":{\"address\":\"127.0.0.1\",\"port\":%u},\"icon\":\"\",\"proxy\":["
		"{\"vhost\":[\"test.example\"],\"address\":\"::1\",\"port\":%u,\"pheader\":true}]}\n",
		log_filename, (unsigned int)listener_port, (unsigned int)upstream_port
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
	static const worker_fragment_fixture fragment_fixtures[] = {
		{ "login/login_3-12w04a.bin", 0, false },
		{ "login/login_5-13w39b.bin", 0, false },
		{ "modern/login_2-13w41b.bin", 0, true },
		{ "modern/status_2-13w41b.bin", 16, true },
		{ "status/status_3-1.6.1.bin", 0, false }
	};
	/* Forward only versions with a routable virtual host that are included in the documented support policy. */
	static const worker_packet_fixture packet_fixtures[] = {
		{ "login/login_1-a1.0.15.bin", false, false },
		{ "login/login_2-12w03a.bin", false, true },
		{ "login/login_2-a1.0.16.bin", false, true },
		{ "login/login_2-b1.4_01.bin", false, true },
		{ "login/login_2-b1.5.bin", false, true },
		{ "login/login_3-12w04a.bin", true, false },
		{ "login/login_3-12w16a.bin", true, false },
		{ "login/login_4-12w17a.bin", false, true },
		{ "login/login_5-12w18a.bin", true, false },
		{ "login/login_5-13w39b.bin", true, false },
		{ "modern/login_1-13w41a.bin", false, true },
		{ "modern/login_2-13w41b.bin", false, true },
		{ "modern/status_1-13w41a.bin", false, true },
		{ "modern/status_2-13w41b.bin", false, true },
		{ "status/status_1-12w42a.bin", false, true },
		{ "status/status_1-b1.8-pre1.bin", false, true },
		{ "status/status_2-1.6.bin", false, true },
		{ "status/status_2-12w42b.bin", false, true },
		{ "status/status_3-1.6.1.bin", true, false },
		{ "status/status_3-13w39b.bin", true, false }
	};
	/* Modern status handshake declaring a 12-byte address while only three bytes remain. */
	static const uint8_t malformed_handshake[] = { 0x05, 0x00, 0x2F, 0x0C, 't', 0x01, 0xFF };
	/* Modern status handshake for test.example followed by an empty status request packet. */
	static const uint8_t valid_request[] = {
		0x12, 0x00, 0x2F, 0x0C,
		't', 'e', 's', 't', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x63, 0xDD, 0x01,
		0x01, 0x00
	};
	char temp_directory[] = "/tmp/mcrelay-worker-protocol-XXXXXX";
	char config_filename[PATH_MAX] = { 0 };
	char fixture_filename[PATH_MAX] = { 0 };
	char log_filename[PATH_MAX] = { 0 };
	char notify_filename[PATH_MAX] = { 0 };
	uint8_t received[BUFSIZ];
	int client_fd = -1;
	pid_t listener = -1;
	int listener_reservation_fd = -1;
	int notify_fd = -1;
	int result = EXIT_FAILURE;
	int upstream_client_fd = -1;
	int upstream_server_fd = -1;
	CHECK(argc == 3, "mcrelay executable path and raw packet directory are required");
	CHECK(mkdtemp(temp_directory) != NULL, "cannot create temporary directory");
	int filename_length = snprintf(config_filename, sizeof(config_filename), "%s/config.json", temp_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(config_filename), "cannot format configuration filename");
	filename_length = snprintf(log_filename, sizeof(log_filename), "%s/access.log", temp_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(log_filename), "cannot format log filename");
	filename_length = snprintf(notify_filename, sizeof(notify_filename), "%s/notify.sock", temp_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(notify_filename), "cannot format notification socket filename");
	in_port_t listener_port, upstream_port;
	upstream_server_fd = server_open(&upstream_port);
	CHECK(upstream_server_fd != -1, "cannot open fake upstream server");
	listener_reservation_fd = server_open(&listener_port);
	CHECK(listener_reservation_fd != -1, "cannot reserve listener port");
	CHECK(close(listener_reservation_fd) == 0, "cannot release listener port reservation");
	listener_reservation_fd = -1;
	CHECK(write_config(config_filename, log_filename, listener_port, upstream_port) == 0, "cannot write configuration");

	notify_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	CHECK(notify_fd != -1, "cannot create notification socket");
	struct sockaddr_un notify_address;
	memset(&notify_address, 0, sizeof(notify_address));
	notify_address.sun_family = AF_UNIX;
	CHECK(strlen(notify_filename) < sizeof(notify_address.sun_path), "notification socket filename is too long");
	strcpy(notify_address.sun_path, notify_filename);
	CHECK(bind(notify_fd, (struct sockaddr *)&notify_address, sizeof(notify_address)) == 0, "cannot bind notification socket");

	listener = child_start(argv[1], config_filename, notify_filename);
	CHECK(listener > 0, "cannot start mcrelay listener");
	char ready_message[64];
	ssize_t ready_length = message_receive(notify_fd, ready_message, sizeof(ready_message) - 1, TEST_TIMEOUT_MS);
	CHECK(ready_length > 0, "listener READY notification is missing");
	ready_message[ready_length] = '\0';
	CHECK(strcmp(ready_message, "READY=1") == 0, "listener READY notification is invalid");

	client_fd = client_connect(listener_port);
	CHECK(client_fd != -1, "cannot connect malformed test client");
	CHECK(socket_send_all(client_fd, malformed_handshake, sizeof(malformed_handshake)) == 0, "cannot send malformed handshake");
	CHECK(shutdown(client_fd, SHUT_WR) == 0, "cannot finish malformed handshake");
	uint8_t rejection[4096];
	CHECK(message_receive(client_fd, rejection, sizeof(rejection), TEST_TIMEOUT_MS) == 0, "malformed handshake connection remained open");
	CHECK(close(client_fd) == 0, "cannot close malformed test client");
	client_fd = -1;
	upstream_client_fd = server_accept(upstream_server_fd, QUIET_TIMEOUT_MS);
	CHECK(upstream_client_fd == -1 && errno == ETIMEDOUT, "malformed handshake reached upstream server");
	CHECK(kill(listener, 0) == 0, "malformed handshake terminated listener");

	client_fd = client_connect(listener_port);
	CHECK(client_fd != -1, "cannot connect valid test client");
	CHECK(socket_send_all(client_fd, valid_request, sizeof(valid_request)) == 0, "cannot send valid handshake");
	upstream_client_fd = server_accept(upstream_server_fd, TEST_TIMEOUT_MS);
	CHECK(upstream_client_fd >= 0, "valid handshake did not reach upstream server");
	size_t received_size = 0;
	while (received_size < sizeof(valid_request)) {
		ssize_t receive_result = message_receive(upstream_client_fd, received + received_size, sizeof(valid_request) - received_size, TEST_TIMEOUT_MS);
		CHECK(receive_result > 0, "cannot receive forwarded handshake");
		received_size += (size_t)receive_result;
	}
	CHECK(memcmp(received, valid_request, sizeof(valid_request)) == 0, "forwarded handshake differs from client input");
	CHECK(kill(listener, 0) == 0, "valid handshake terminated listener");

	CHECK(close(upstream_client_fd) == 0, "cannot close upstream connection");
	upstream_client_fd = -1;
	CHECK(close(client_fd) == 0, "cannot close valid test client");
	client_fd = -1;
	CHECK(worker_packet_timeout(listener_port, upstream_server_fd) == 0, "incomplete packet did not observe the absolute assembly timeout");
	CHECK(kill(listener, 0) == 0, "incomplete packet timeout terminated listener");

	for (size_t fixture_index = 0; fixture_index < sizeof(packet_fixtures) / sizeof(packet_fixtures[0]); fixture_index++) {
		filename_length = snprintf(fixture_filename, sizeof(fixture_filename), "%s/%s", argv[2], packet_fixtures[fixture_index].filename);
		CHECK(filename_length > 0 && (size_t)filename_length < sizeof(fixture_filename), "cannot format raw packet fixture filename");
		uint8_t fixture[BUFSIZ];
		ssize_t fixture_size = file_read(fixture_filename, fixture, sizeof(fixture));
		CHECK(fixture_size > 0, "cannot read raw packet fixture");
		client_fd = client_connect(listener_port);
		CHECK(client_fd != -1, "cannot connect raw packet test client");
		CHECK(socket_send_all(client_fd, fixture, (size_t)fixture_size) == 0, "cannot send raw packet fixture");
		CHECK(shutdown(client_fd, SHUT_WR) == 0, "cannot finish raw packet fixture");
		if (packet_fixtures[fixture_index].forwarded) {
			upstream_client_fd = server_accept(upstream_server_fd, TEST_TIMEOUT_MS);
			CHECK(upstream_client_fd >= 0, "supported raw packet did not reach upstream server");
			size_t fixture_received = 0;
			while (fixture_received < (size_t)fixture_size) {
				ssize_t receive_result = message_receive(upstream_client_fd, received + fixture_received, (size_t)fixture_size - fixture_received, TEST_TIMEOUT_MS);
				CHECK(receive_result > 0, "cannot receive forwarded raw packet");
				fixture_received += (size_t)receive_result;
			}
			CHECK(memcmp(received, fixture, (size_t)fixture_size) == 0, "forwarded raw packet differs from capture");
			CHECK(close(upstream_client_fd) == 0, "cannot close raw packet upstream connection");
			upstream_client_fd = -1;
		} else {
			uint8_t response[BUFSIZ];
			ssize_t response_size = socket_receive_all(client_fd, response, sizeof(response), TEST_TIMEOUT_MS);
			CHECK(response_size >= 0, "cannot receive raw packet rejection");
			CHECK((response_size > 0) == packet_fixtures[fixture_index].response, "raw packet rejection response does not match version policy");
			upstream_client_fd = server_accept(upstream_server_fd, QUIET_TIMEOUT_MS);
			CHECK(upstream_client_fd == -1 && errno == ETIMEDOUT, "unsupported raw packet reached upstream server");
		}
		CHECK(close(client_fd) == 0, "cannot close raw packet test client");
		client_fd = -1;
		CHECK(kill(listener, 0) == 0, "raw packet fixture terminated listener");
	}

	for (size_t fixture_index = 0; fixture_index < sizeof(fragment_fixtures) / sizeof(fragment_fixtures[0]); fixture_index++) {
		filename_length = snprintf(fixture_filename, sizeof(fixture_filename), "%s/%s", argv[2], fragment_fixtures[fixture_index].filename);
		CHECK(filename_length > 0 && (size_t)filename_length < sizeof(fixture_filename), "cannot format fragmented packet fixture filename");
		uint8_t fixture[BUFSIZ];
		ssize_t fixture_size = file_read(fixture_filename, fixture, sizeof(fixture));
		CHECK(fixture_size > 1, "cannot read fragmented packet fixture");
		if (fragment_fixtures[fixture_index].update_modern_version) {
			CHECK(fixture_size > 2, "modern fragmented packet fixture is too short");
			fixture[2] = 1;
		}
		for (size_t split_size = 1; split_size < (size_t)fixture_size; split_size++) {
			int fragment_result = worker_packet_forward_split(listener_port, upstream_server_fd, fixture, (size_t)fixture_size, split_size);
			if (fragment_result == -1) {
				fprintf(stderr, "fragmented fixture %s failed at split %zu\n", fragment_fixtures[fixture_index].filename, split_size);
			}
			CHECK(fragment_result == 0, "fragmented packet was not forwarded intact");
			CHECK(kill(listener, 0) == 0, "fragmented packet terminated listener");
		}
		size_t required_size = fragment_fixtures[fixture_index].required_size ? fragment_fixtures[fixture_index].required_size : (size_t)fixture_size;
		CHECK(required_size <= (size_t)fixture_size, "fragmented packet required size is invalid");
		for (size_t prefix_size = 1; prefix_size < required_size; prefix_size++) {
			int truncate_result = worker_packet_truncate(listener_port, upstream_server_fd, fixture, prefix_size);
			if (truncate_result == -1) {
				fprintf(stderr, "truncated fixture %s failed at prefix %zu\n", fragment_fixtures[fixture_index].filename, prefix_size);
			}
			CHECK(truncate_result == 0, "permanently truncated packet reached upstream");
			CHECK(kill(listener, 0) == 0, "permanently truncated packet terminated listener");
		}
	}

	CHECK(kill(listener, SIGTERM) == 0, "cannot stop listener");
	CHECK(child_wait(listener, TEST_TIMEOUT_MS) == 0, "listener did not exit successfully");
	listener = -1;
	CHECK(close(upstream_server_fd) == 0, "cannot close IPv4 upstream server");
	upstream_server_fd = server_open_ipv6(&upstream_port);
	CHECK(upstream_server_fd != -1, "cannot open IPv6 fake upstream server");
	CHECK(write_proxy_config(config_filename, log_filename, listener_port, upstream_port) == 0, "cannot write PROXY-header configuration");
	listener = child_start(argv[1], config_filename, notify_filename);
	CHECK(listener > 0, "cannot restart mcrelay listener for PROXY-header test");
	ready_length = message_receive(notify_fd, ready_message, sizeof(ready_message) - 1, TEST_TIMEOUT_MS);
	CHECK(ready_length > 0, "restarted listener READY notification is missing");
	ready_message[ready_length] = '\0';
	CHECK(strcmp(ready_message, "READY=1") == 0, "restarted listener READY notification is invalid");
	client_fd = client_connect(listener_port);
	CHECK(client_fd != -1, "cannot connect PROXY-header test client");
	struct sockaddr_in client_address;
	socklen_t client_address_size = sizeof(client_address);
	CHECK(getsockname(client_fd, (struct sockaddr *)&client_address, &client_address_size) == 0, "cannot read PROXY-header client endpoint");
	CHECK(socket_send_all(client_fd, valid_request, sizeof(valid_request)) == 0, "cannot send PROXY-header test handshake");
	upstream_client_fd = server_accept(upstream_server_fd, TEST_TIMEOUT_MS);
	CHECK(upstream_client_fd >= 0, "cross-family handshake did not reach IPv6 upstream server");
	char expected_header[128];
	int expected_header_size = snprintf(expected_header, sizeof(expected_header), "PROXY TCP4 127.0.0.1 127.0.0.1 %hu %hu\r\n", ntohs(client_address.sin_port), listener_port);
	CHECK(expected_header_size > 0 && (size_t)expected_header_size < sizeof(expected_header), "cannot format expected PROXY header");
	size_t expected_size = (size_t)expected_header_size + sizeof(valid_request);
	size_t proxy_received_size = 0;
	while (proxy_received_size < expected_size) {
		ssize_t receive_result = message_receive(upstream_client_fd, received + proxy_received_size, expected_size - proxy_received_size, TEST_TIMEOUT_MS);
		CHECK(receive_result > 0, "cannot receive PROXY header and forwarded handshake");
		proxy_received_size += (size_t)receive_result;
	}
	CHECK(memcmp(received, expected_header, (size_t)expected_header_size) == 0, "PROXY header did not describe the original inbound connection");
	CHECK(memcmp(received + expected_header_size, valid_request, sizeof(valid_request)) == 0, "handshake following PROXY header was corrupted");
	CHECK(close(upstream_client_fd) == 0, "cannot close PROXY-header upstream connection");
	upstream_client_fd = -1;
	CHECK(close(client_fd) == 0, "cannot close PROXY-header client connection");
	client_fd = -1;
	CHECK(kill(listener, SIGTERM) == 0, "cannot stop restarted listener");
	CHECK(child_wait(listener, TEST_TIMEOUT_MS) == 0, "restarted listener did not exit successfully");
	listener = -1;

	result = EXIT_SUCCESS;

cleanup:
	if (listener > 0) {
		kill(listener, SIGKILL);
		waitpid(listener, NULL, 0);
	}
	if (client_fd != -1) {
		close(client_fd);
	}
	if (listener_reservation_fd != -1) {
		close(listener_reservation_fd);
	}
	if (notify_fd != -1) {
		close(notify_fd);
	}
	if (upstream_client_fd != -1) {
		close(upstream_client_fd);
	}
	if (upstream_server_fd != -1) {
		close(upstream_server_fd);
	}
	unlink(config_filename);
	unlink(log_filename);
	unlink(notify_filename);
	rmdir(temp_directory);
	return result;
}
