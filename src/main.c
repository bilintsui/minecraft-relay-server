/*
 * main.c: Entry point
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "basic.h"
#include "connsetup.h"
#include "define/exitcode.h"
#include "define/global.h"
#include "log.h"

#define PIDFILE_PATH "/run/mcrelay/mcrelay.pid"

#define LOG(lvl, ...)	mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, lvl, __VA_ARGS__)
#define LOG_CFG(lvl, ...)	mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, config_runmode, config->log.level, lvl, __VA_ARGS__)
#define LOG_NOPFX(lvl, ...)	mksysmsg(MKSYS_PREFIX_OFF, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, lvl, __VA_ARGS__)
#define LOG_FILE(lvl, ...)	mksysmsg(MKSYS_PREFIX_ON, config_logfull, config_runmode, config->log.level, lvl, __VA_ARGS__)

char cwd[PATH_MAX];
char *argoffset_configfile = NULL;
char configfile[PATH_MAX];
char configfile_full[PATH_MAX];
char config_logfull[PATH_MAX];
conf *config = NULL;
bool config_netpriority_enabled = true;
sa_family_t config_netpriority_protocol = AF_INET6;
uint8_t config_runmode = RUNMODE_SIMPLE;
volatile sig_atomic_t reload_flag = 0;

static void deal_signal(int signum) {
	switch (signum) {
		case SIGTERM:
		case SIGINT:
			unlink(PIDFILE_PATH);
			exit(0);
		case SIGUSR1:
			reload_flag = 1;
	}
}

static void log_config_duperr(const char *logfile, uint8_t runmode, uint8_t maxlevel, uint8_t msglevel, const char *suffix) {
	const char *base = config_errmsg(CONF_ECPROXYDUP);
	if (config_duperr[0] != '\0') {
		mksysmsg(MKSYS_PREFIX_ON, logfile, runmode, maxlevel, msglevel, "%s. Affected: \"%s\"%s\n", base, config_duperr, suffix);
		config_duperr[0] = '\0';
	} else {
		mksysmsg(MKSYS_PREFIX_ON, logfile, runmode, maxlevel, msglevel, "%s%s\n", base, suffix);
	}
}

static void do_reload(void) {
	uint8_t config_maxlevel = config->log.level;
	char config_logfull_old[PATH_MAX];
	snprintf(config_logfull_old, sizeof(config_logfull_old), "%s", config_logfull);
	mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_INFORMATION,
		"Reloading config from file: %s\n",
		configfile
	);
	conf *config_new = config_read(configfile_full);
	switch (errno) {
		case 0:
			config_destroy(config);
			config = config_new;
			config_icon_load(config, config_logfull, config_runmode, config_maxlevel);
			resolve_path(config->log.filename, cwd, config_logfull, sizeof(config_logfull));
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_INFORMATION,
				"Configuration reloaded.\n"
			);
			break;
		case CONF_EROPENFAIL:
		case CONF_EROPENEMPTY:
		case CONF_EROPENLARGE:
		case CONF_ERMEMORY:
		case CONF_ERPARSE:
		case CONF_ECMEMORY:
		case CONF_ECNETPRIORITYPROTOCOL:
		case CONF_ECLISTENPORT:
		case CONF_ECPROXY:
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING,
				"%s%s%s\n",
				config_errmsg(errno),
				(errno == CONF_EROPENFAIL || errno == CONF_EROPENEMPTY) ? configfile : "",
				", will keep your old configurations"
			);
			break;
		case CONF_ECPROXYDUP:
			log_config_duperr(config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING, ", will keep your old configurations");
			break;
		default:
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Error in processing configurations: Unknown error occurred, code: %d, will keep your old configurations\n",
				errno
			);
			break;
	}
	return;
}

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

static void detach_process(void) {
	setsid();
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	chdir("/");
	umask(0);
}

static net_addrbundle parse_client_address(void *addr) {
	net_addrbundle result;
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
	}
	return result;
}

static int pidfile_read(int *pid_out) {
	FILE *f = fopen(PIDFILE_PATH, "r");
	if (f == NULL) {
		return -1;
	}
	fscanf(f, "%d", pid_out);
	fclose(f);
	return 0;
}

static int pidfile_write(pid_t pid) {
	FILE *f = fopen(PIDFILE_PATH, "w");
	if (f == NULL) {
		mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, config->log.level, MKSYS_LEVEL_CRITICAL, "Cannot write PID file " PIDFILE_PATH "\n");
		return -1;
	}
	fprintf(f, "%d", pid);
	fclose(f);
	return 0;
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

static const char *headmsg =
	"Minecraft Relay Server [Version " MCRELAY_VERSION_DISPLAY "/"
	MCRELAY_VERSION_INTERNAL "]\n"
	"(c) " MCRELAY_COPYYEAR " Bilin Tsui\n\n";
static const char *helpmsg =
	"<arguments|config_file>\n\n"
	"Arguments\n\t-r / --reload:\tReload config on the running instance\n"
	"\t-t / --stop:\tTerminate the running instance\n"
	"\t-f / --forking:\tMakes the process become daemonized\n"
	"\t-v / --version:\tShow current mcrelay version\n\n"
	"See more: https://github.com/bilintsui/minecraft-relay-server";

int main(int argc, char **argv) {
	int socket_inbound_server, socket_inbound_client;
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} addr_inbound_client;
	socklen_t strulen = sizeof(addr_inbound_client);
	getcwd(cwd, PATH_MAX);
	const char *progname = strrchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0];
	if (argc < 2) {
		LOG_NOPFX(MKSYS_LEVEL_CRITICAL, headmsg);
		fprintf(stderr, "Usage: %s %s\n", progname, helpmsg);
		return EXITCODE_BADARG;
	}
	argoffset_configfile = argv[1];
	int prevpid = 0;
	char *ptr_argv1 = argv[1];
	if (*ptr_argv1 == '-') {
		ptr_argv1++;
		if ((strcmp(ptr_argv1, "r") == 0) || (strcmp(ptr_argv1, "-reload") == 0)) {
			if (pidfile_read(&prevpid) != 0) {
				LOG_NOPFX(MKSYS_LEVEL_CRITICAL, headmsg);
				LOG(MKSYS_LEVEL_CRITICAL, "Cannot read " PIDFILE_PATH ".\n");
				return EXITCODE_NOPIDFILE;
			}
			if (kill(prevpid, SIGUSR1) == 0) {
				LOG_NOPFX(MKSYS_LEVEL_INFORMATION, headmsg);
				LOG(MKSYS_LEVEL_INFORMATION, "Successfully sent reload signal to currently running process.\n");
				return EXITCODE_OK;
			} else {
				LOG_NOPFX(MKSYS_LEVEL_CRITICAL, headmsg);
				LOG(MKSYS_LEVEL_CRITICAL, "Failed to send reload signal to currently running process.\n");
				return EXITCODE_NOSIGNAL;
			}
		} else if ((strcmp(ptr_argv1, "t") == 0) || (strcmp(ptr_argv1, "-stop") == 0)) {
			if (pidfile_read(&prevpid) != 0) {
				LOG_NOPFX(MKSYS_LEVEL_CRITICAL, headmsg);
				LOG(MKSYS_LEVEL_CRITICAL, "Cannot read " PIDFILE_PATH ".\n");
				return EXITCODE_NOPIDFILE;
			}
			if (kill(prevpid, SIGTERM) == 0) {
				LOG_NOPFX(MKSYS_LEVEL_INFORMATION, headmsg);
				LOG(MKSYS_LEVEL_INFORMATION, "Successfully sent terminate signal to currently running process.\n");
				return EXITCODE_OK;
			} else {
				LOG_NOPFX(MKSYS_LEVEL_CRITICAL, headmsg);
				LOG(MKSYS_LEVEL_CRITICAL, "Failed to send terminate signal to currently running process.\n");
				return EXITCODE_NOSIGNAL;
			}
		} else if ((strcmp(ptr_argv1, "f") == 0) || (strcmp(ptr_argv1, "-forking") == 0)) {
			config_runmode = RUNMODE_FORKING;
			argoffset_configfile = argv[2];
		} else if ((strcmp(ptr_argv1, "v") == 0) || (strcmp(ptr_argv1, "-version") == 0)) {
			fprintf(stdout, "v%s(%s)\n", MCRELAY_VERSION_DISPLAY, MCRELAY_VERSION_INTERNAL);
			return EXITCODE_OK;
		} else {
			LOG_NOPFX(MKSYS_LEVEL_CRITICAL, headmsg);
			fprintf(stderr, "Error: Invalid option \"-%s\"\n\nUsage: %s %s\n", ptr_argv1, progname, helpmsg);
			return EXITCODE_BADARG;
		}
	} else {
		if (pidfile_read(&prevpid) == 0) {
			if (kill(prevpid, 0) == 0) {
				LOG_NOPFX(MKSYS_LEVEL_CRITICAL, headmsg);
				LOG(MKSYS_LEVEL_CRITICAL, "You cannot run multiple instances at a time. Previous running process PID: %d.\n", prevpid);
				return EXITCODE_MULTIINSTANCE;
			}
		}
	}
	LOG_NOPFX(MKSYS_LEVEL_INFORMATION, headmsg);
	if (argoffset_configfile == NULL) {
		LOG(MKSYS_LEVEL_CRITICAL, "Config filename cannot be empty!\n", configfile);
		return EXITCODE_BADARG;
	}
	snprintf(configfile, sizeof(configfile), "%s", argoffset_configfile);
	resolve_path(configfile, cwd, configfile_full, sizeof(configfile_full));
	LOG(MKSYS_LEVEL_INFORMATION, "Loading configurations from file: %s\n\n", configfile);
	config = config_read(configfile_full);
	switch (errno) {
		case 0:
			resolve_path(config->log.filename, cwd, config_logfull, sizeof(config_logfull));
			config_netpriority_enabled = config->netpriority.enabled;
			config_netpriority_protocol = config->netpriority.protocol;
			config_icon_load(config, config_logfull, config_runmode, config->log.level);
			break;
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
			log_config_duperr(MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL, "");
			return config_exitcode(errno);
		default:
			LOG(MKSYS_LEVEL_CRITICAL, "Error in processing configurations: Unknown error occurred, code: %d\n", errno);
			return EXITCODE_INTERNAL;
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
	int pid;
	if (config_runmode == RUNMODE_FORKING) {
		pid = fork();
		if (pid > 0) {
			if (pidfile_write(pid) != 0) {
				return EXITCODE_CANTCREAT;
			}
			bind_success_msg();
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, config->log.level, MKSYS_LEVEL_INFORMATION, "Server running on PID: %d\n", pid);
			return EXITCODE_OK;
		} else if (pid < 0) {
			return EXITCODE_FORKFAIL;
		}
		detach_process();
	} else {
		pid = getpid();
		if (pidfile_write(pid) != 0) {
			return EXITCODE_CANTCREAT;
		}
	}
	if (config_runmode != RUNMODE_FORKING) {
		bind_success_msg();
	}
	setup_signals();
	if (config_runmode != RUNMODE_FORKING && !isatty(STDOUT_FILENO)) {
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
		pid = fork();
		if (pid > 0) {
			close(socket_inbound_client);
		} else if (pid < 0) {
			break;
		} else {
			signal(SIGUSR1, SIG_DFL);
			close(socket_inbound_server);
			net_addrbundle addrbundle_inbound_client = parse_client_address(&addr_inbound_client);
			int socket_outbound;
			if (connsetup(socket_inbound_client, &socket_outbound, config_logfull, config_runmode, config, addrbundle_inbound_client, config_netpriority_enabled)) {
				return EXITCODE_OK;
			}
			net_relay(socket_inbound_client, socket_outbound);
			return EXITCODE_OK;
		}
	}
}
