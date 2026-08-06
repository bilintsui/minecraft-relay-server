/*
 * worker_lifecycle.c: Tests for worker process lifecycle
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <dirent.h>
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
#include <sys/prctl.h>
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
#define TEST_TIMEOUT_MS	5000
#define WAIT_INTERVAL_MS	10
#define WAIT_INTERVAL_NS	10000000

/* section: types */
typedef struct {
	uint64_t blocked;
	uint64_t caught;
	uint64_t ignored;
} process_signal_state;

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

static int listener_socket_probe(in_port_t port) {
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
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port)
	};
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == -1 || listen(fd, 1) == -1) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	return fd;
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

static int process_signals_read(pid_t process, process_signal_state *result) {
	char filename[64];
	int filename_length = snprintf(filename, sizeof(filename), "/proc/%ld/status", (long)process);
	if (filename_length < 0 || (size_t)filename_length >= sizeof(filename)) {
		errno = EOVERFLOW;
		return -1;
	}
	FILE *status = fopen(filename, "r");
	if (status == NULL) {
		return -1;
	}
	bool blocked_found = false;
	bool caught_found = false;
	bool ignored_found = false;
	char line[256];
	memset(result, 0, sizeof(*result));
	while (fgets(line, sizeof(line), status) != NULL) {
		if (sscanf(line, "SigBlk:\t%" SCNx64, &result->blocked) == 1) {
			blocked_found = true;
		} else if (sscanf(line, "SigCgt:\t%" SCNx64, &result->caught) == 1) {
			caught_found = true;
		} else if (sscanf(line, "SigIgn:\t%" SCNx64, &result->ignored) == 1) {
			ignored_found = true;
		}
	}
	if (ferror(status)) {
		int saved_errno = errno == 0 ? EIO : errno;
		fclose(status);
		errno = saved_errno;
		return -1;
	}
	if (fclose(status) == EOF) {
		return -1;
	}
	if (!blocked_found || !caught_found || !ignored_found) {
		errno = EIO;
		return -1;
	}
	return 0;
}

static int process_state_read(pid_t process, char *result) {
	char filename[64];
	int filename_length = snprintf(filename, sizeof(filename), "/proc/%ld/status", (long)process);
	if (filename_length < 0 || (size_t)filename_length >= sizeof(filename)) {
		errno = EOVERFLOW;
		return -1;
	}
	FILE *status = fopen(filename, "r");
	if (status == NULL) {
		return -1;
	}
	char line[256];
	int read_result = -1;
	while (fgets(line, sizeof(line), status) != NULL) {
		if (sscanf(line, "State:\t%c", result) == 1) {
			read_result = 0;
			break;
		}
	}
	if (fclose(status) == EOF && read_result == 0) {
		return -1;
	}
	if (read_result == -1) {
		errno = EIO;
	}
	return read_result;
}

static int process_stopped_wait(pid_t process, int timeout_ms) {
	const struct timespec interval = { .tv_nsec = WAIT_INTERVAL_NS };
	for (int elapsed_ms = 0; elapsed_ms < timeout_ms; elapsed_ms += WAIT_INTERVAL_MS) {
		char state;
		if (process_state_read(process, &state) == 0 && state == 'T') {
			return 0;
		}
		nanosleep(&interval, NULL);
	}
	errno = ETIMEDOUT;
	return -1;
}

static pid_t process_wait(pid_t process, int *status, int timeout_ms) {
	const struct timespec interval = { .tv_nsec = WAIT_INTERVAL_NS };
	for (int elapsed_ms = 0; elapsed_ms < timeout_ms; elapsed_ms += WAIT_INTERVAL_MS) {
		pid_t wait_result = waitpid(process, status, WNOHANG);
		if (wait_result != 0) {
			return wait_result;
		}
		nanosleep(&interval, NULL);
	}
	errno = ETIMEDOUT;
	return -1;
}

static bool worker_descriptors_valid(pid_t worker) {
	char directory_name[64];
	int directory_length = snprintf(directory_name, sizeof(directory_name), "/proc/%ld/fd", (long)worker);
	if (directory_length < 0 || (size_t)directory_length >= sizeof(directory_name)) {
		return false;
	}
	DIR *directory = opendir(directory_name);
	if (directory == NULL) {
		return false;
	}
	size_t eventpoll_count = 0;
	bool result = true;
	struct dirent *entry;
	while ((entry = readdir(directory)) != NULL) {
		if (entry->d_name[0] == '.') {
			continue;
		}
		char descriptor_name[96];
		int descriptor_length = snprintf(descriptor_name, sizeof(descriptor_name), "%s/%s", directory_name, entry->d_name);
		if (descriptor_length < 0 || (size_t)descriptor_length >= sizeof(descriptor_name)) {
			result = false;
			break;
		}
		char target[128];
		ssize_t target_length = readlink(descriptor_name, target, sizeof(target) - 1);
		if (target_length == -1) {
			result = false;
			break;
		}
		target[target_length] = '\0';
		if (strcmp(target, "anon_inode:[eventpoll]") == 0) {
			eventpoll_count++;
		} else if (strcmp(target, "anon_inode:[signalfd]") == 0) {
			result = false;
			break;
		}
	}
	closedir(directory);
	return result && eventpoll_count == 1;
}

static pid_t worker_find(pid_t listener, int timeout_ms) {
	const struct timespec interval = { .tv_nsec = WAIT_INTERVAL_NS };
	for (int elapsed_ms = 0; elapsed_ms < timeout_ms; elapsed_ms += WAIT_INTERVAL_MS) {
		DIR *processes = opendir("/proc");
		if (processes == NULL) {
			return -1;
		}
		struct dirent *entry;
		while ((entry = readdir(processes)) != NULL) {
			char *end = NULL;
			errno = 0;
			long process = strtol(entry->d_name, &end, 10);
			if (errno != 0 || end == entry->d_name || *end != '\0' || process <= 0 || process > INT_MAX) {
				continue;
			}
			char status_filename[64];
			int filename_length = snprintf(status_filename, sizeof(status_filename), "/proc/%ld/status", process);
			if (filename_length < 0 || (size_t)filename_length >= sizeof(status_filename)) {
				continue;
			}
			FILE *status = fopen(status_filename, "r");
			if (status == NULL) {
				continue;
			}
			char line[256];
			long parent = -1;
			while (fgets(line, sizeof(line), status) != NULL) {
				if (sscanf(line, "PPid:\t%ld", &parent) == 1) {
					break;
				}
			}
			fclose(status);
			if (parent == (long)listener) {
				closedir(processes);
				return (pid_t)process;
			}
		}
		closedir(processes);
		nanosleep(&interval, NULL);
	}
	errno = ETIMEDOUT;
	return -1;
}

static int worker_ready_wait(pid_t worker, int timeout_ms) {
	const uint64_t sigint_mask = UINT64_C(1) << (SIGINT - 1);
	const uint64_t sigterm_mask = UINT64_C(1) << (SIGTERM - 1);
	const uint64_t sigusr1_mask = UINT64_C(1) << (SIGUSR1 - 1);
	const uint64_t relevant_mask = sigint_mask | sigterm_mask | sigusr1_mask;
	const struct timespec interval = { .tv_nsec = WAIT_INTERVAL_NS };
	for (int elapsed_ms = 0; elapsed_ms < timeout_ms; elapsed_ms += WAIT_INTERVAL_MS) {
		process_signal_state signal_state;
		if (process_signals_read(worker, &signal_state) == 0 && (signal_state.blocked & relevant_mask) == 0 && worker_descriptors_valid(worker)) {
			return 0;
		}
		nanosleep(&interval, NULL);
	}
	process_signal_state signal_state;
	if (process_signals_read(worker, &signal_state) == 0) {
		fprintf(stderr, "worker state: SigBlk=%016" PRIx64 " SigCgt=%016" PRIx64 " SigIgn=%016" PRIx64 " descriptors_valid=%d\n",
			signal_state.blocked, signal_state.caught, signal_state.ignored, worker_descriptors_valid(worker)
		);
	}
	errno = ETIMEDOUT;
	return -1;
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
	char temp_directory[] = "/tmp/mcrelay-worker-lifecycle-XXXXXX";
	char config_filename[PATH_MAX] = { 0 };
	char log_filename[PATH_MAX] = { 0 };
	char notify_filename[PATH_MAX] = { 0 };
	char message[64];
	int client_fd = -1;
	pid_t listener = -1;
	int notify_fd = -1;
	int probe_fd = -1;
	int result = EXIT_FAILURE;
	pid_t worker = -1;
	CHECK(argc == 2, "mcrelay executable path is required");
	CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0, "cannot become a child subreaper");
	sigset_t listener_signals;
	sigemptyset(&listener_signals);
	sigaddset(&listener_signals, SIGINT);
	sigaddset(&listener_signals, SIGTERM);
	sigaddset(&listener_signals, SIGUSR1);
	CHECK(sigprocmask(SIG_UNBLOCK, &listener_signals, NULL) == 0, "cannot prepare listener signal mask");
	CHECK(mkdtemp(temp_directory) != NULL, "cannot create temporary directory");
	int filename_length = snprintf(config_filename, sizeof(config_filename), "%s/config.json", temp_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(config_filename), "cannot format configuration filename");
	filename_length = snprintf(log_filename, sizeof(log_filename), "%s/access.log", temp_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(log_filename), "cannot format log filename");
	filename_length = snprintf(notify_filename, sizeof(notify_filename), "%s/notify.sock", temp_directory);
	CHECK(filename_length > 0 && (size_t)filename_length < sizeof(notify_filename), "cannot format notification socket filename");
	in_port_t port;
	CHECK(port_find(&port) == 0, "cannot find a free listener port");
	CHECK(write_config(config_filename, log_filename, port) == 0, "cannot write configuration");

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
	CHECK(message_receive(notify_fd, message, sizeof(message), TEST_TIMEOUT_MS) > 0 && strcmp(message, "READY=1") == 0, "listener READY notification is missing");
	client_fd = client_connect(port);
	CHECK(client_fd != -1, "cannot connect test client");
	worker = worker_find(listener, TEST_TIMEOUT_MS);
	CHECK(worker > 0, "cannot find worker process");
	CHECK(worker_ready_wait(worker, TEST_TIMEOUT_MS) == 0, "worker initialization did not complete");

	process_signal_state signal_state;
	CHECK(process_signals_read(worker, &signal_state) == 0, "cannot read worker signal state");
	const uint64_t sigint_mask = UINT64_C(1) << (SIGINT - 1);
	const uint64_t sigterm_mask = UINT64_C(1) << (SIGTERM - 1);
	const uint64_t sigusr1_mask = UINT64_C(1) << (SIGUSR1 - 1);
	const uint64_t relevant_mask = sigint_mask | sigterm_mask | sigusr1_mask;
	CHECK((signal_state.blocked & relevant_mask) == 0, "worker retained blocked listener signals");
	CHECK((signal_state.caught & relevant_mask) == 0, "worker retained caught listener signals");
	CHECK((signal_state.ignored & (sigint_mask | sigterm_mask)) == 0, "worker ignores a termination signal");
	CHECK(worker_descriptors_valid(worker), "worker event descriptors are invalid");
	/* WSL1 reports SigIgn as zero, so verify the SIGUSR1 disposition behaviorally. */
	CHECK(kill(worker, SIGUSR1) == 0, "cannot send SIGUSR1 to worker");
	const struct timespec signal_delivery = { .tv_nsec = 100000000 };
	nanosleep(&signal_delivery, NULL);
	CHECK(kill(worker, 0) == 0, "SIGUSR1 terminated worker");

	CHECK(kill(worker, SIGSTOP) == 0, "cannot stop worker before listener exit");
	CHECK(process_stopped_wait(worker, TEST_TIMEOUT_MS) == 0, "worker did not stop before listener exit");
	CHECK(kill(listener, SIGTERM) == 0, "cannot stop listener");
	int listener_status;
	CHECK(process_wait(listener, &listener_status, TEST_TIMEOUT_MS) == listener, "listener did not exit");
	CHECK(WIFEXITED(listener_status) && WEXITSTATUS(listener_status) == 0, "listener exited unsuccessfully");
	listener = -1;
	probe_fd = listener_socket_probe(port);
	CHECK(probe_fd != -1, "worker retained the listening socket");
	CHECK(close(probe_fd) == 0, "cannot close listening socket probe");
	probe_fd = -1;
	CHECK(kill(worker, SIGCONT) == 0, "cannot resume worker after listener exit");
	int worker_status;
	CHECK(process_wait(worker, &worker_status, TEST_TIMEOUT_MS) == worker, "worker survived listener exit");
	CHECK(WIFSIGNALED(worker_status) && WTERMSIG(worker_status) == SIGTERM, "worker did not receive its parent-death signal");
	worker = -1;

	result = EXIT_SUCCESS;

cleanup:
	if (listener > 0) {
		kill(listener, SIGKILL);
	}
	if (worker > 0) {
		kill(worker, SIGKILL);
	}
	if (listener > 0) {
		waitpid(listener, NULL, 0);
	}
	if (worker > 0) {
		waitpid(worker, NULL, 0);
	}
	if (client_fd != -1) {
		close(client_fd);
	}
	if (notify_fd != -1) {
		close(notify_fd);
	}
	if (probe_fd != -1) {
		close(probe_fd);
	}
	unlink(config_filename);
	unlink(log_filename);
	unlink(notify_filename);
	rmdir(temp_directory);
	return result;
}
