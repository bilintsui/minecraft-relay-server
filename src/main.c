/*
 * main.c: Entry point
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
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
	COMMAND_HELP,
	COMMAND_RUN,
	COMMAND_VERSION
};
enum help_topic {
	HELP_GENERAL,
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

/* section: global variables */
conf *config = NULL;
static conf_cache config_cache_state = { 0 };
char config_logfull[PATH_MAX];
bool config_netpriority_enabled = true;
sa_family_t config_netpriority_protocol = AF_INET6;
char configfile[PATH_MAX];
char configfile_full[PATH_MAX];
char cwd[PATH_MAX];
volatile sig_atomic_t reload_flag = 0;

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

static void deal_signal(int signum) {
	switch (signum) {
		case SIGTERM:
		case SIGINT:
			exit(0);
		case SIGUSR1:
			reload_flag = 1;
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
			if (strcmp(argv[2], "help") == 0) {
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
	} else if (strcmp(argv[1], "run") == 0) {
		if (argc == 2) {
			result.command = COMMAND_RUN;
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
				result.command = COMMAND_RUN;
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
				"\trun\tCreate a server instance\n"
				"\tversion\tGet version in single line\n\n"
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

static void setup_signals(void) {
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = deal_signal;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	signal(SIGCHLD, SIG_IGN);
}

/* section: functions (entry point) */
int main(int argc, char **argv) {
	const char *progname = strrchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0];
	arguments args = parse_arguments(argc, argv);
	switch (args.command) {
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
	int socket_inbound_server, socket_inbound_client;
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} addr_inbound_client;
	socklen_t strulen = sizeof(addr_inbound_client);
	getcwd(cwd, PATH_MAX);
	snprintf(configfile, sizeof(configfile), "%s", args.configfile);
	resolve_path(configfile, cwd, configfile_full, sizeof(configfile_full));
	LOG(MKSYS_LEVEL_INFORMATION, "Loading configurations from file: %s\n", configfile);
	conf_read_status read_status = config_read(configfile_full, &config_cache_state, &config);
	switch (read_status) {
		case CONF_READ_CHANGED:
			resolve_path(config->log.filename, cwd, config_logfull, sizeof(config_logfull));
			config_netpriority_enabled = config->netpriority.enabled;
			config_netpriority_protocol = config->netpriority.protocol;
			config_icon_load(config, config_logfull, config->log.level);
			break;
		case CONF_READ_UNCHANGED:
			LOG(MKSYS_LEVEL_CRITICAL, "Error in processing configurations: Initial config load unexpectedly reported no change.\n");
			return EXITCODE_INTERNAL;
		case CONF_READ_ERROR:
			switch (errno) {
				case CONF_EROPENFAIL:
				case CONF_EROPENEMPTY:
					LOG(MKSYS_LEVEL_CRITICAL, "%s%s\n", config_errmsg(errno), configfile);
					return EXITCODE_NOCONFFILE;
				case CONF_EROPENLARGE:
				case CONF_ERMEMORY:
				case CONF_ECMEMORY:
				case CONF_ERPARSE:
				case CONF_ECNETPRIORITYPROTOCOL:
				case CONF_ECLISTENPORT:
				case CONF_ECPROXY:
					LOG(MKSYS_LEVEL_CRITICAL, "%s\n", config_errmsg(errno));
					return config_exitcode(errno);
				case CONF_ECPROXYDUP:
					log_config_duperr(MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL, "");
					return config_exitcode(errno);
				default:
					LOG(MKSYS_LEVEL_CRITICAL, "Error in processing configurations: Unknown error occurred, code: %d\n", errno);
					return EXITCODE_INTERNAL;
			}
	}
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
	bind_success_msg();
	setup_signals();
	if (!isatty(STDOUT_FILENO)) {
		fclose(stdout);
		fclose(stderr);
	}
	while (1) {
		if (reload_flag) {
			/*
			 * Clear before reloading: a SIGUSR1 arriving during
			 * do_reload() must remain pending for the next loop
			 * iteration instead of being clobbered here.
			 */
			reload_flag = 0;
			do_reload();
		}
		socket_inbound_client = accept(socket_inbound_server, (struct sockaddr *)&addr_inbound_client, &strulen);
		if (socket_inbound_client == -1) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		pid_t pid = fork();
		if (pid > 0) {
			close(socket_inbound_client);
		} else if (pid < 0) {
			break;
		} else {
			signal(SIGUSR1, SIG_DFL);
			close(socket_inbound_server);
			net_addrbundle addrbundle_inbound_client = parse_client_address(&addr_inbound_client);
			int socket_outbound;
			if (connsetup(socket_inbound_client, &socket_outbound, config_logfull, config, addrbundle_inbound_client, config_netpriority_enabled)) {
				return EXITCODE_OK;
			}
			net_relay(socket_inbound_client, socket_outbound);
			return EXITCODE_OK;
		}
	}
}
