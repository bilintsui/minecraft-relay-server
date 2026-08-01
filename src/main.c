/*
 * main.c: Entry point
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "basic.h"
#include "config.h"
#include "connsetup.h"
#include "define/exitcode.h"
#include "define/global.h"
#include "log.h"
#include "network.h"

/* section: defines */
/* default */
#define DEFAULT_CONFIG_FILE	"/etc/mcrelay/config.json"

/* logging macro */
#define LOG(lvl, ...)	mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL, lvl, __VA_ARGS__)
#define LOG_CFG(lvl, ...)	mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, config->log.level, lvl, __VA_ARGS__)
#define LOG_FILE(lvl, ...)	mksysmsg(MKSYS_PREFIX_ON, config_logfull, config->log.level, lvl, __VA_ARGS__)

/* listener */
#define LISTENER_ACCEPT_BATCH	128

/* section: types */
enum arg_error {
	ARG_OK,
	ARG_ERR_UNKNOWN_COMMAND,
	ARG_ERR_UNKNOWN_HELP_TOPIC,
	ARG_ERR_EMPTY_CONFIG,
	ARG_ERR_MISSING_VALUE,
	ARG_ERR_INVALID_ARGUMENT,
	ARG_ERR_INVALID
};
enum command {
	COMMAND_INVALID,
	COMMAND_DUMPCONFIG,
	COMMAND_HELP,
	COMMAND_RUN,
	COMMAND_VERSION
};
enum help_topic {
	HELP_GENERAL,
	HELP_DUMPCONFIG,
	HELP_HELP,
	HELP_RUN,
	HELP_VERSION
};
typedef struct {
	enum command command;
	const char *configfile;
	enum help_topic help_topic;
	enum arg_error error;
	const char *error_arg;
} arguments;
typedef struct {
	int epoll_fd;
	bool mask_blocked;
	sigset_t previous_signal_mask;
	int signal_fd;
} listener_events;
typedef struct {
	bool accept_ready;
	bool reload;
	bool stop;
} listener_requests;

/* section: global variables */
conf *config = NULL;
static conf_cache config_cache_state = { 0 };
char config_logfull[PATH_MAX];
bool config_netpriority_enabled = true;
sa_family_t config_netpriority_protocol = AF_INET6;
char configfile[PATH_MAX];
char configfile_full[PATH_MAX];
char cwd[PATH_MAX];

/* section: functions (local) */
static void bind_success_msg(void) {
	LOG_FILE(MKSYS_LEVEL_INFORMATION, "Bind Successful.\n\n");
	LOG_CFG(MKSYS_LEVEL_INFORMATION, "For more information, see log file: %s\n\n", config->log.filename);
}

static int config_exitcode(int err) {
	switch (err) {
		case CONF_EROPENLARGE:
			return EXITCODE_FILELARGE;
		case CONF_ERMEMORY:
		case CONF_ECMEMORY:
			return EXITCODE_NOMEM;
		case CONF_ERPARSE:
			return EXITCODE_BADJSON;
		case CONF_ECNETPRIORITYPROTOCOL:
		case CONF_ECLISTENPORT:
		case CONF_ECPROXY:
		case CONF_ECPROXYDUP:
			return EXITCODE_BADARG;
		default:
			return EXITCODE_INTERNAL;
	}
}

static void log_config_duperr(const char *logfile, uint8_t maxlevel, uint8_t msglevel, const char *suffix) {
	const char *base = config_errmsg(CONF_ECPROXYDUP);
	if (config_duperr[0] != '\0') {
		mksysmsg(MKSYS_PREFIX_ON, logfile, maxlevel, msglevel, "%s. Affected: \"%s\"%s\n", base, config_duperr, suffix);
		config_duperr[0] = '\0';
	} else {
		mksysmsg(MKSYS_PREFIX_ON, logfile, maxlevel, msglevel, "%s%s\n", base, suffix);
	}
}

static void do_reload(void) {
	uint8_t config_maxlevel = config->log.level;
	char config_logfull_old[PATH_MAX];
	snprintf(config_logfull_old, sizeof(config_logfull_old), "%s", config_logfull);
	mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
		"Reloading config from file: %s\n",
		configfile
	);
	conf *config_new = NULL;
	conf_read_status read_status = config_read(configfile_full, &config_cache_state, &config_new);
	switch (read_status) {
		case CONF_READ_CHANGED:
			config_destroy(config);
			config = config_new;
			config_icon_load(config, config_logfull, config_maxlevel);
			resolve_path(config->log.filename, cwd, config_logfull, sizeof(config_logfull));
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_INFORMATION,
				"Configuration reloaded.\n"
			);
			break;
		case CONF_READ_UNCHANGED:
			config_icon_load(config, config_logfull_old, config_maxlevel);
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
						(errno == CONF_EROPENFAIL || errno == CONF_EROPENEMPTY) ? configfile : "",
						", will keep your old configurations"
					);
					break;
				case CONF_ECPROXYDUP:
					log_config_duperr(config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING, ", will keep your old configurations");
					break;
				default:
					mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_maxlevel, MKSYS_LEVEL_WARNING,
						"Error in processing configurations: Unknown error occurred, code: %d, will keep your old configurations\n",
						errno
					);
					break;
			}
	}
	return;
}

static int load_config(const char *filename, const char *filename_full, conf_cache *cache, conf **target) {
	conf_read_status read_status = config_read(filename_full, cache, target);
	switch (read_status) {
		case CONF_READ_CHANGED:
			return EXITCODE_OK;
		case CONF_READ_UNCHANGED:
			LOG(MKSYS_LEVEL_CRITICAL, "Error in processing configurations: Initial config load unexpectedly reported no change.\n");
			return EXITCODE_INTERNAL;
		case CONF_READ_ERROR:
			break;
	}
	int config_error = errno;
	switch (config_error) {
		case CONF_EROPENFAIL:
		case CONF_EROPENEMPTY:
			LOG(MKSYS_LEVEL_CRITICAL, "%s%s\n", config_errmsg(config_error), filename);
			return EXITCODE_NOCONFFILE;
		case CONF_EROPENLARGE:
		case CONF_ERMEMORY:
		case CONF_ECMEMORY:
		case CONF_ERPARSE:
		case CONF_ECNETPRIORITYPROTOCOL:
		case CONF_ECLISTENPORT:
		case CONF_ECPROXY:
			LOG(MKSYS_LEVEL_CRITICAL, "%s\n", config_errmsg(config_error));
			return config_exitcode(config_error);
		case CONF_ECPROXYDUP:
			log_config_duperr(MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL, "");
			return config_exitcode(config_error);
		default:
			LOG(MKSYS_LEVEL_CRITICAL, "Error in processing configurations: Unknown error occurred, code: %d\n", config_error);
			return EXITCODE_INTERNAL;
	}
}

static int dump_config(const char *filename) {
	char current_directory[PATH_MAX];
	char filename_full[PATH_MAX];
	conf_cache cache = { 0 };
	conf *parsed = NULL;
	if (getcwd(current_directory, sizeof(current_directory)) == NULL) {
		LOG(MKSYS_LEVEL_CRITICAL, "Error: Cannot determine current working directory.\n");
		return EXITCODE_INTERNAL;
	}
	resolve_path(filename, current_directory, filename_full, sizeof(filename_full));
	int exitcode = load_config(filename, filename_full, &cache, &parsed);
	if (exitcode == EXITCODE_OK) {
		config_dumper(parsed);
	}
	config_destroy(parsed);
	config_cache_destroy(&cache);
	return exitcode;
}

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

static int listener_events_init(int socket_fd, listener_events *events) {
	int saved_errno;
	memset(events, 0, sizeof(*events));
	events->epoll_fd = -1;
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
	int socket_flags = fcntl(socket_fd, F_GETFL);
	if (socket_flags == -1 || fcntl(socket_fd, F_SETFL, socket_flags | O_NONBLOCK) == -1) {
		goto fail;
	}
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.fd = events->signal_fd;
	if (epoll_ctl(events->epoll_fd, EPOLL_CTL_ADD, events->signal_fd, &event) == -1) {
		goto fail;
	}
	event.data.fd = socket_fd;
	if (epoll_ctl(events->epoll_fd, EPOLL_CTL_ADD, socket_fd, &event) == -1) {
		goto fail;
	}
	return 0;
fail:
	saved_errno = errno;
	listener_events_destroy(events);
	errno = saved_errno;
	return -1;
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
	struct epoll_event ready_events[2];
	memset(requests, 0, sizeof(*requests));
	int ready_count;
	do {
		ready_count = epoll_wait(events->epoll_fd, ready_events, 2, -1);
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
		} else {
			errno = EIO;
			return -1;
		}
	}
	return 0;
}

static arguments parse_arguments(int argc, char **argv) {
	arguments result = {
		.command = COMMAND_INVALID,
		.configfile = NULL,
		.help_topic = HELP_GENERAL,
		.error = ARG_ERR_INVALID,
		.error_arg = NULL
	};
	if (argc < 2) {
		return result;
	}
	if (strcmp(argv[1], "help") == 0) {
		if (argc == 2) {
			result.command = COMMAND_HELP;
			result.error = ARG_OK;
		} else if (argc == 3) {
			if (strcmp(argv[2], "dumpconfig") == 0) {
				result.help_topic = HELP_DUMPCONFIG;
			} else if (strcmp(argv[2], "help") == 0) {
				result.help_topic = HELP_HELP;
			} else if (strcmp(argv[2], "run") == 0) {
				result.help_topic = HELP_RUN;
			} else if (strcmp(argv[2], "version") == 0) {
				result.help_topic = HELP_VERSION;
			} else {
				result.error = ARG_ERR_UNKNOWN_HELP_TOPIC;
				result.error_arg = argv[2];
				return result;
			}
			result.command = COMMAND_HELP;
			result.error = ARG_OK;
		} else {
			result.error = ARG_ERR_INVALID_ARGUMENT;
			result.error_arg = argv[3];
		}
	} else if (strcmp(argv[1], "version") == 0) {
		if (argc == 2) {
			result.command = COMMAND_VERSION;
			result.error = ARG_OK;
		} else {
			result.error = ARG_ERR_INVALID_ARGUMENT;
			result.error_arg = argv[2];
		}
	} else if (strcmp(argv[1], "dumpconfig") == 0 || strcmp(argv[1], "run") == 0) {
		enum command config_command = strcmp(argv[1], "dumpconfig") == 0 ? COMMAND_DUMPCONFIG : COMMAND_RUN;
		if (argc == 2) {
			result.command = config_command;
			result.configfile = DEFAULT_CONFIG_FILE;
			result.error = ARG_OK;
		} else if (strcmp(argv[2], "-c") == 0 || strcmp(argv[2], "--config") == 0) {
			if (argc == 3) {
				result.error = ARG_ERR_MISSING_VALUE;
				result.error_arg = argv[2];
				return result;
			}
			if (argc == 4) {
				if (argv[3][0] == '\0') {
					result.error = ARG_ERR_EMPTY_CONFIG;
					return result;
				}
				result.command = config_command;
				result.configfile = argv[3];
				result.error = ARG_OK;
			} else {
				result.error = ARG_ERR_INVALID_ARGUMENT;
				result.error_arg = argv[4];
			}
		} else {
			result.error = ARG_ERR_INVALID_ARGUMENT;
			result.error_arg = argv[2];
		}
	} else {
		result.error = ARG_ERR_UNKNOWN_COMMAND;
		result.error_arg = argv[1];
	}
	return result;
}

static net_addrbundle parse_client_address(void *addr) {
	net_addrbundle result;
	memset(&result, 0, sizeof(result));
	result.family = *((sa_family_t *)addr);
	void *addroffset = NULL;
	switch (result.family) {
		case AF_INET:
			result.address = net_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr), true);
			result.address_clean = net_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr), false);
			result.port = ntohs(((struct sockaddr_in *)addr)->sin_port);
			break;
		case AF_INET6:
			addroffset = &(((struct sockaddr_in6 *)addr)->sin6_addr);
			if (memcmp(addroffset, "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\xFF\xFF", 12) == 0) {
				result.family = AF_INET;
				addroffset = (uint8_t *)addroffset + 12;
			}
			result.address = net_ntop(result.family, addroffset, true);
			result.address_clean = net_ntop(result.family, addroffset, false);
			result.port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
			break;
		default:
			result.family = 0;
			break;
	}
	return result;
}

static void print_help(enum help_topic topic, const char *progname) {
	fputs(
		"Minecraft Relay Server [Version " MCRELAY_VERSION_DISPLAY "/"
		MCRELAY_VERSION_INTERNAL "]\n"
		"(c) " MCRELAY_COPYYEAR " Bilin Tsui\n\n",
		stdout
	);
	switch (topic) {
		case HELP_DUMPCONFIG:
			fprintf(stdout,
				"Display parsed configuration\n\n"
				"Usage: %s dumpconfig [options]\n\n"
				"\t-c, --config <config_file>\n"
				"\t\tOptional, specify a configuration to read. Default: " DEFAULT_CONFIG_FILE "\n",
				progname
			);
			break;
		case HELP_HELP:
			fprintf(stdout,
				"Get help for specific command\n\n"
				"Usage: %s help [<command>]\n",
				progname
			);
			break;
		case HELP_RUN:
			fprintf(stdout,
				"Create a server instance\n\n"
				"Usage: %s run [options]\n\n"
				"\t-c, --config <config_file>\n"
				"\t\tOptional, specify a configuration to read. Default: " DEFAULT_CONFIG_FILE "\n",
				progname
			);
			break;
		case HELP_VERSION:
			fprintf(stdout,
				"Get version in single line\n\n"
				"Usage: %s version\n",
				progname
			);
			break;
		case HELP_GENERAL:
		default:
			fprintf(stdout,
				"Usage: %s <command> ...\n\n"
				"\tdumpconfig\tDisplay parsed configuration\n"
				"\trun\t\tCreate a server instance\n"
				"\tversion\t\tGet version in single line\n\n"
				"Use \"%s help <command>\" to get help for specific command.\n",
				progname, progname
			);
			break;
	}
	fputs(
		"\nSee more: https://github.com/bilintsui/minecraft-relay-server\n",
		stdout
	);
}

static int restore_worker_signals(const sigset_t *signal_mask) {
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

static int run_listener(int socket_fd) {
	listener_events events;
	if (listener_events_init(socket_fd, &events) == -1) {
		LOG_FILE(MKSYS_LEVEL_CRITICAL, "Cannot initialize listener event loop: %s\n", strerror(errno));
		close(socket_fd);
		return EXITCODE_INTERNAL;
	}
	bind_success_msg();
	if (!isatty(STDOUT_FILENO)) {
		fclose(stdout);
		fclose(stderr);
	}
	int exitcode = EXITCODE_OK;
	pid_t listener_pid = getpid();
	while (1) {
		listener_requests requests;
		if (listener_events_wait(socket_fd, &events, &requests) == -1) {
			LOG_FILE(MKSYS_LEVEL_CRITICAL, "Listener event loop failed: %s\n", strerror(errno));
			exitcode = EXITCODE_INTERNAL;
			break;
		}
		if (requests.stop) {
			break;
		}
		if (requests.reload) {
			do_reload();
		}
		if (!requests.accept_ready) {
			continue;
		}
		for (size_t accept_attempt = 0; accept_attempt < LISTENER_ACCEPT_BATCH; accept_attempt++) {
			union {
				struct sockaddr_in v4;
				struct sockaddr_in6 v6;
			} client_address;
			socklen_t address_length = sizeof(client_address);
			/* On Linux, accepted sockets do not inherit O_NONBLOCK from the listening socket. */
			int client_fd = accept(socket_fd, (struct sockaddr *)&client_address, &address_length);
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
					LOG_FILE(MKSYS_LEVEL_WARNING, "Cannot accept client connection: %s\n", strerror(errno));
					listener_backoff();
					break;
				}
				LOG_FILE(MKSYS_LEVEL_CRITICAL, "Cannot accept client connection: %s\n", strerror(errno));
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
				LOG_FILE(MKSYS_LEVEL_WARNING, "Cannot create worker process: %s\n", strerror(saved_errno));
				listener_backoff();
				break;
			}
			close(events.epoll_fd);
			close(events.signal_fd);
			close(socket_fd);
			if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
				LOG_FILE(MKSYS_LEVEL_WARNING, "Cannot configure worker parent-death signal: %s\n", strerror(errno));
				_exit(EXITCODE_INTERNAL);
			}
			if (getppid() != listener_pid) {
				_exit(EXITCODE_OK);
			}
			if (restore_worker_signals(&events.previous_signal_mask) == -1) {
				LOG_FILE(MKSYS_LEVEL_WARNING, "Cannot restore worker signal state: %s\n", strerror(errno));
				_exit(EXITCODE_INTERNAL);
			}
			net_addrbundle addrbundle_inbound_client = parse_client_address(&client_address);
			int socket_outbound;
			if (!connsetup(client_fd, &socket_outbound, config_logfull, config, addrbundle_inbound_client, config_netpriority_enabled)) {
				net_relay(client_fd, socket_outbound);
			}
			_exit(EXITCODE_OK);
		}
	}
cleanup:
	listener_events_destroy(&events);
	close(socket_fd);
	return exitcode;
}

/* section: functions (entry point) */
int main(int argc, char **argv) {
	const char *progname = strrchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0];
	arguments args = parse_arguments(argc, argv);
	switch (args.command) {
		case COMMAND_DUMPCONFIG:
			return dump_config(args.configfile);
		case COMMAND_HELP:
			print_help(args.help_topic, progname);
			return EXITCODE_OK;
		case COMMAND_VERSION:
			fprintf(stdout, "v%s(%s)\n", MCRELAY_VERSION_DISPLAY, MCRELAY_VERSION_INTERNAL);
			return EXITCODE_OK;
		case COMMAND_RUN:
			break;
		case COMMAND_INVALID:
		default:
			if (argc > 1) {
				switch (args.error) {
					case ARG_ERR_UNKNOWN_COMMAND:
						fprintf(stderr, "Error: Unknown command \"%s\".\n", args.error_arg);
						break;
					case ARG_ERR_UNKNOWN_HELP_TOPIC:
						fprintf(stderr, "Error: Unknown help topic \"%s\".\n", args.error_arg);
						break;
					case ARG_ERR_EMPTY_CONFIG:
						fprintf(stderr, "Error: Configuration file path cannot be empty.\n");
						break;
					case ARG_ERR_MISSING_VALUE:
						fprintf(stderr, "Error: Option %s requires a value.\n", args.error_arg);
						break;
					case ARG_ERR_INVALID_ARGUMENT:
						fprintf(stderr, "Error: Invalid argument \"%s\".\n", args.error_arg);
						break;
					case ARG_ERR_INVALID:
					default:
						fprintf(stderr, "Error: Invalid arguments.\n");
						break;
				}
			}
			fprintf(stderr, "Try '%s help' for more information.\n", progname);
			return EXITCODE_BADARG;
	}
	int socket_inbound_server;
	getcwd(cwd, PATH_MAX);
	snprintf(configfile, sizeof(configfile), "%s", args.configfile);
	resolve_path(configfile, cwd, configfile_full, sizeof(configfile_full));
	LOG(MKSYS_LEVEL_INFORMATION, "Loading configurations from file: %s\n", configfile);
	int config_load_status = load_config(configfile, configfile_full, &config_cache_state, &config);
	if (config_load_status != EXITCODE_OK) {
		return config_load_status;
	}
	resolve_path(config->log.filename, cwd, config_logfull, sizeof(config_logfull));
	config_netpriority_enabled = config->netpriority.enabled;
	config_netpriority_protocol = config->netpriority.protocol;
	config_icon_load(config, config_logfull, config->log.level);
	FILE *tmpfd = fopen(config_logfull, "a");
	if (tmpfd == NULL) {
		LOG(MKSYS_LEVEL_CRITICAL, "Error: Cannot write log to \"%s\".\n", config->log.filename);
		return EXITCODE_CANTCREAT;
	} else {
		fclose(tmpfd);
	}
	net_addr bindaddr = net_resolve_dual(config->listen.address, config_netpriority_protocol, config_netpriority_enabled);
	if (bindaddr.family == 0) {
		LOG_FILE(MKSYS_LEVEL_CRITICAL, "Error: Invalid bind address!\n");
	}
	if (config->listen.port == 0) {
		LOG_FILE(MKSYS_LEVEL_CRITICAL, "Error: Invalid bind port!\n");
		return EXITCODE_BADPORT;
	}
	net_addrp bindaddrp = net_ntop(bindaddr.family, &(bindaddr.addr), true);
	LOG_FILE(MKSYS_LEVEL_INFORMATION, "Binding on %s:%d...\n", (char *)&bindaddrp, config->listen.port);
	socket_inbound_server = net_socket(NETSOCK_BIND, bindaddr.family, &(bindaddr.addr), config->listen.port, true);
	if (socket_inbound_server == -1) {
		LOG_FILE(MKSYS_LEVEL_CRITICAL, "Bind Failed!\n");
		return EXITCODE_BINDFAIL;
	}
	return run_listener(socket_inbound_server);
}
