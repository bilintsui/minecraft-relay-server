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

#include "define/exitcode.h"
#include "define/global.h"
#include "log.h"
#include "misc.h"

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

void deal_signal(int signum) {
	switch (signum) {
		case SIGTERM:
		case SIGINT:
			unlink("/run/mcrelay/mcrelay.pid");
			exit(0);
		case SIGUSR1:
			reload_flag = 1;
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
			if (config->log.filename[0] != '/') {
				snprintf(config_logfull, sizeof(config_logfull), "%s/%s", cwd, config->log.filename);
			} else {
				snprintf(config_logfull, sizeof(config_logfull), "%s", config->log.filename);
			}
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_INFORMATION,
				"Configuration reloaded.\n"
			);
			break;
		case CONF_EROPENFAIL:
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Cannot read config file: %s\n",
				configfile
			);
			break;
		case CONF_EROPENLARGE:
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Error in configurations: File too large (5MB), will keep your old configurations.\n"
			);
			break;
		case CONF_ERMEMORY:
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Error in configurations: Failed to allocate memory when reading file, will keep your old configurations.\n"
			);
			break;
		case CONF_ERPARSE:
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Error in configurations: Not a valid JSON format, will keep your old configurations.\n"
			);
			break;
		case CONF_ECMEMORY:
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Error in processing configurations: Failed to allocate memory during internal processing, will keep your old configurations.\n"
			);
			break;
		case CONF_ECNETPRIORITYPROTOCOL:
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Error in configurations: Entry \"netpriority.protocol\" must be IPv4 or IPv6 (case sensitive), will keep your old configurations.\n"
			);
			break;
		case CONF_ECLISTENPORT:
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Error in configurations: Entry \"listen.port\" must be an unsigned short integer (0-65535), will keep your old configurations.\n"
			);
			break;
		case CONF_ECPROXY:
			mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING,
				"Error in configurations: Entry \"proxy\" is missing, will keep your old configurations.\n"
			);
			break;
		case CONF_ECPROXYDUP:
			if (config_duperr[0] != '\0') {
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Error in configurations: Duplication found in proxy virtual hostnames. "
					"Affected: \"%s\", will keep your old configurations.\n",
					config_duperr
				);
				config_duperr[0] = '\0';
			} else {
				mksysmsg(MKSYS_PREFIX_ON, config_logfull_old, config_runmode, config_maxlevel, MKSYS_LEVEL_WARNING,
					"Error in configurations: Duplication found in proxy virtual hostnames, will keep your old configurations.\n"
				);
			}
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

int main(int argc, char **argv) {
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
	int socket_inbound_server, socket_inbound_client;
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} addr_inbound_client;
	socklen_t strulen = sizeof(addr_inbound_client);
	getcwd(cwd, PATH_MAX);
	if (argc < 2) {
		mksysmsg(
			MKSYS_PREFIX_OFF, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
			headmsg
		);
		fprintf(stderr, "Usage: %s %s\n", strrchr(argv[0], '/') ? strrchr(argv[0],'/') + 1 : argv[0], helpmsg);
		return EXITCODE_BADARG;
	}
	argoffset_configfile = argv[1];
	FILE *pidfd = NULL;
	int prevpid = 0;
	char *ptr_argv1 = argv[1];
	if (*ptr_argv1 == '-') {
		ptr_argv1++;
		if ((strcmp(ptr_argv1, "r") == 0) || (strcmp(ptr_argv1, "-reload") == 0)) {
			pidfd = fopen("/run/mcrelay/mcrelay.pid", "r");
			if (pidfd == NULL) {
				mksysmsg(MKSYS_PREFIX_OFF, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
					headmsg
				);
				mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
					"Cannot read /run/mcrelay/mcrelay.pid.\n"
				);
				return EXITCODE_NOPIDFILE;
			}
			fscanf(pidfd, "%d", &prevpid);
			fclose(pidfd);
			if (kill(prevpid, SIGUSR1) == 0) {
				mksysmsg(MKSYS_PREFIX_OFF, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION,
					headmsg
				);
				mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION,
					"Successfully sent reload signal to currently running process.\n"
				);
				return EXITCODE_OK;
			} else {
				mksysmsg(MKSYS_PREFIX_OFF, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
					headmsg
				);
				mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
					"Failed to send reload signal to currently running process.\n"
				);
				return EXITCODE_NOSIGNAL;
			}
		} else if ((strcmp(ptr_argv1, "t") == 0) || (strcmp(ptr_argv1, "-stop") == 0)) {
			pidfd = fopen("/run/mcrelay/mcrelay.pid", "r");
			if (pidfd == NULL) {
				mksysmsg(MKSYS_PREFIX_OFF, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
					headmsg
				);
				mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
					"Cannot read /run/mcrelay/mcrelay.pid.\n"
				);
				return EXITCODE_NOPIDFILE;
			}
			fscanf(pidfd, "%d", &prevpid);
			fclose(pidfd);
			if (kill(prevpid, SIGTERM) == 0) {
				mksysmsg(MKSYS_PREFIX_OFF, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION,
					headmsg
				);
				mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION,
					"Successfully sent terminate signal to currently running process.\n"
				);
				return EXITCODE_OK;
			} else {
				mksysmsg(MKSYS_PREFIX_OFF, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
					headmsg
				);
				mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
					"Failed to send terminate signal to currently running process.\n"
				);
				return EXITCODE_NOSIGNAL;
			}
		} else if ((strcmp(ptr_argv1, "f") == 0) || (strcmp(ptr_argv1, "-forking") == 0)) {
			config_runmode = RUNMODE_FORKING;
			argoffset_configfile = argv[2];
		} else if ((strcmp(ptr_argv1, "v") == 0) || (strcmp(ptr_argv1, "-version") == 0)) {
			fprintf(stdout, "v%s(%s)\n", MCRELAY_VERSION_DISPLAY, MCRELAY_VERSION_INTERNAL);
			return EXITCODE_OK;
		} else {
			mksysmsg(MKSYS_PREFIX_OFF, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
				headmsg
			);
			fprintf(stderr, "Error: Invalid option \"-%s\"\n\nUsage: %s %s\n", ptr_argv1, strrchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0], helpmsg);
			return EXITCODE_BADARG;
		}
	} else {
		pidfd = fopen("/run/mcrelay/mcrelay.pid", "r");
		if (pidfd != NULL) {
			fscanf(pidfd, "%d", &prevpid);
			fclose(pidfd);
			if (kill(prevpid, 0) == 0) {
				mksysmsg(MKSYS_PREFIX_OFF, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
					headmsg
				);
				mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
					"You cannot run multiple instances at a time. Previous running process PID: %d.\n",
					prevpid
				);
				return EXITCODE_MULTIINSTANCE;
			}
		}
	}
	mksysmsg(MKSYS_PREFIX_OFF, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION,
		headmsg
	);
	if (argoffset_configfile == NULL) {
		mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
			"Config filename cannot be empty!\n",
			configfile
		);
		return EXITCODE_BADARG;
	}
	snprintf(configfile, sizeof(configfile), "%s", argoffset_configfile);
	if (configfile[0] != '/') {
		snprintf(configfile_full, sizeof(configfile_full), "%s/%s", cwd, configfile);
	} else {
		snprintf(configfile_full, sizeof(configfile_full), "%s", configfile);
	}
	mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_INFORMATION,
		"Loading configurations from file: %s\n\n",
		configfile
	);
	config = config_read(configfile_full);
	switch (errno) {
		case 0:
			if (config->log.filename[0] != '/') {
				snprintf(config_logfull, sizeof(config_logfull), "%s/%s", cwd, config->log.filename);
			} else {
				snprintf(config_logfull, sizeof(config_logfull), "%s", config->log.filename);
			}
			config_netpriority_enabled = config->netpriority.enabled;
			config_netpriority_protocol = config->netpriority.protocol;
			config_icon_load(config, config_logfull, config_runmode, config->log.level);
			break;
		case CONF_EROPENFAIL:
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
				"Cannot read config file: %s\n",
				configfile
			);
			return EXITCODE_NOCONFFILE;
		case CONF_EROPENLARGE:
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
				"Error in configurations: File too large (5MB).\n"
			);
			return EXITCODE_FILELARGE;
		case CONF_ERMEMORY:
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
				"Error in configurations: Failed to allocate memory when reading file.\n"
			);
			return EXITCODE_NOMEM;
		case CONF_ERPARSE:
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
				"Error in configurations: Not a valid JSON format.\n"
			);
			return EXITCODE_BADJSON;
		case CONF_ECMEMORY:
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
				"Error in processing configurations: Failed to allocate memory during internal processing.\n"
			);
			return EXITCODE_NOMEM;
		case CONF_ECNETPRIORITYPROTOCOL:
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
				"Error in configurations: Entry \"netpriority.protocol\" must be IPv4 or IPv6 (case sensitive).\n"
			);
			return EXITCODE_BADARG;
		case CONF_ECLISTENPORT:
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
				"Error in configurations: Entry \"listen.port\" must be an unsigned short integer (0-65535).\n"
			);
			return EXITCODE_BADARG;
		case CONF_ECPROXY:
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
				"Error in configurations: Entry \"proxy\" is missing!\n"
			);
			return EXITCODE_BADARG;
		case CONF_ECPROXYDUP:
			if (config_duperr[0] != '\0') {
				mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
					"Error in configurations: Duplication found in proxy virtual hostnames. Affected: \"%s\".\n",
					config_duperr
				);
				config_duperr[0] = '\0';
			} else {
				mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
					"Error in configurations: Duplication found in proxy virtual hostnames.\n"
				);
			}
			return EXITCODE_BADARG;
		default:
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
				"Error in processing configurations: Unknown error occurred, code: %d\n",
				errno
			);
			return EXITCODE_INTERNAL;
	}
	FILE *tmpfd = fopen(config_logfull, "a");
	if (tmpfd == NULL) {
		mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL,
			"Error: Cannot write log to \"%s\".\n",
			config->log.filename
		);
		return EXITCODE_CANTCREAT;
	} else {
		fclose(tmpfd);
	}
	net_addr bindaddr = net_resolve_dual(config->listen.address, config_netpriority_protocol, config_netpriority_enabled);
	if (bindaddr.family == 0) {
		mksysmsg(MKSYS_PREFIX_ON, config_logfull, config_runmode, config->log.level, MKSYS_LEVEL_CRITICAL,
			"Error: Invalid bind address!\n"
		);
	}
	if (config->listen.port == 0) {
		mksysmsg(MKSYS_PREFIX_ON, config_logfull, config_runmode, config->log.level, MKSYS_LEVEL_CRITICAL,
			"Error: Invalid bind port!\n"
		);
		return EXITCODE_BADPORT;
	}
	net_addrp bindaddrp = net_ntop(bindaddr.family, &(bindaddr.addr), true);
	mksysmsg(MKSYS_PREFIX_ON, config_logfull, config_runmode, config->log.level, MKSYS_LEVEL_INFORMATION,
		"Binding on %s:%d...\n",
		(char *)&bindaddrp, config->listen.port
	);
	socket_inbound_server = net_socket(NETSOCK_BIND, bindaddr.family, &(bindaddr.addr), config->listen.port, true);
	if (socket_inbound_server == -1) {
		mksysmsg(MKSYS_PREFIX_ON, config_logfull, config_runmode, config->log.level, MKSYS_LEVEL_CRITICAL,
			"Bind Failed!\n"
		);
		return EXITCODE_BINDFAIL;
	}
	int pid;
	if (config_runmode == RUNMODE_FORKING) {
		pid = fork();
		if (pid > 0) {
			FILE *pidfd = fopen("/run/mcrelay/mcrelay.pid", "w");
			if (pidfd == NULL) {
				mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, config->log.level, MKSYS_LEVEL_CRITICAL,
					"Cannot write PID file /run/mcrelay/mcrelay.pid\n"
				);
				return EXITCODE_CANTCREAT;
			}
			fprintf(pidfd, "%d", pid);
			fclose(pidfd);
			mksysmsg(MKSYS_PREFIX_ON, config_logfull, config_runmode, config->log.level, MKSYS_LEVEL_INFORMATION,
				"Bind Successful.\n\n"
			);
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, config_runmode, config->log.level, MKSYS_LEVEL_INFORMATION,
				"For more information, see log file: %s\n\n",
				config->log.filename
			);
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, config->log.level, MKSYS_LEVEL_INFORMATION,
				"Server running on PID: %d\n",
				pid
			);
			return EXITCODE_OK;
		} else if (pid < 0) {
			return EXITCODE_FORKFAIL;
		}
		setsid();
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);
		chdir("/");
		umask(0);
	} else {
		pid = getpid();
		FILE *pidfd = fopen("/run/mcrelay/mcrelay.pid", "w");
		if (pidfd == NULL) {
			mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, RUNMODE_CONSOLE, config->log.level, MKSYS_LEVEL_CRITICAL,
				"Cannot write PID file /run/mcrelay/mcrelay.pid\n"
			);
			return EXITCODE_CANTCREAT;
		}
		fprintf(pidfd, "%d", pid);
		fclose(pidfd);
	}
	if (config_runmode != RUNMODE_FORKING) {
		mksysmsg(MKSYS_PREFIX_ON, config_logfull, config_runmode, config->log.level, MKSYS_LEVEL_INFORMATION,
			"Bind Successful.\n\n"
		);
		mksysmsg(MKSYS_PREFIX_ON, MKSYS_NOLOGFILE, config_runmode, config->log.level, MKSYS_LEVEL_INFORMATION,
			"For more information, see log file: %s\n\n",
			config->log.filename
		);
	}
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = deal_signal;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	signal(SIGCHLD, SIG_IGN);
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
			net_addrbundle addrbundle_inbound_client;
			addrbundle_inbound_client.family = *((sa_family_t *)&addr_inbound_client);
			void *addr_inbound_client_addroffset = NULL;
			switch (addrbundle_inbound_client.family) {
				case AF_INET:
					addrbundle_inbound_client.address = net_ntop(AF_INET, &(((struct sockaddr_in *)&addr_inbound_client)->sin_addr), true);
					addrbundle_inbound_client.address_clean = net_ntop(AF_INET, &(((struct sockaddr_in *)&addr_inbound_client)->sin_addr), false);
					addrbundle_inbound_client.port = ntohs(((struct sockaddr_in *)&addr_inbound_client)->sin_port);
					break;
				case AF_INET6:
					addr_inbound_client_addroffset = &(((struct sockaddr_in6 *)&addr_inbound_client)->sin6_addr);
					if (memcmp(addr_inbound_client_addroffset, "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\xFF\xFF", 12) == 0) {
						addrbundle_inbound_client.family = AF_INET;
						addr_inbound_client_addroffset = (uint8_t *)addr_inbound_client_addroffset + 12;
					}
					addrbundle_inbound_client.address = net_ntop(addrbundle_inbound_client.family, addr_inbound_client_addroffset, true);
					addrbundle_inbound_client.address_clean = net_ntop(addrbundle_inbound_client.family, addr_inbound_client_addroffset, false);
					addrbundle_inbound_client.port = ntohs(((struct sockaddr_in6 *)&addr_inbound_client)->sin6_port);
					break;
			}
			int socket_outbound;
			if (backbone(socket_inbound_client, &socket_outbound, config_logfull, config_runmode, config, addrbundle_inbound_client, config_netpriority_enabled)) {
				return EXITCODE_OK;
			}
			net_relay(socket_inbound_client, socket_outbound);
			return EXITCODE_OK;
		}
	}
}
