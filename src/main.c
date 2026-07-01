/*
	main.c: Main source code for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta4
	(c) 2020-2026 Bilin Tsui.
	This is a Free Software, absolutely no warranty.

	Licensed under GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, see: https://www.gnu.org/licenses/gpl-3.0.html
*/

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "defines.h"
#include "exitcode.h"
#include "log.h"
#include "misc.h"

char cwd[PATH_MAX];
char *argoffset_configfile = NULL;
char configfile[PATH_MAX];
char configfile_full[PATH_MAX];
char config_logfull[PATH_MAX];
conf *config = NULL;
short config_netpriority_enabled = 1;
sa_family_t config_netpriority_protocol = AF_INET6;
unsigned short config_runmode = 1;
volatile sig_atomic_t reload_flag = 0;
void deal_signal(int signum)
{
	switch (signum) {
	case SIGTERM:
	case SIGINT:
		unlink("/run/mcrelay/mcrelay.pid");
		exit(0);
	case SIGUSR1:
		reload_flag = 1;
	}
}

static void do_reload(void)
{
	unsigned short config_maxlevel = config->log.level;
	char config_logfull_old[PATH_MAX];
	strncpy(config_logfull_old, config_logfull, PATH_MAX - 1);
	config_logfull_old[PATH_MAX - 1] = '\0';
	mksysmsg(0, config_logfull_old, config_runmode, config_maxlevel, 2,
		 "Reloading config from file: %s\n", configfile);
	conf *config_new = config_read(configfile_full);
	switch (errno) {
	case 0:
		config_destroy(config);
		config = config_new;
		if (config->log.filename[0] != '/') {
			snprintf(config_logfull, PATH_MAX, "%s/%s", cwd,
				 config->log.filename);
		} else {
			strncpy(config_logfull, config->log.filename,
				PATH_MAX - 1);
			config_logfull[PATH_MAX - 1] = '\0';
		}
		mksysmsg(0, config_logfull_old, config_runmode, config_maxlevel,
			 2, "Configuration reloaded.\n");
		break;
	case CONF_EROPENFAIL:
		mksysmsg(0, config_logfull_old, config_runmode, config_maxlevel,
			 1, "Cannot read config file: %s\n", configfile);
		break;
	case CONF_EROPENLARGE:
		mksysmsg(0, config_logfull_old, config_runmode, config_maxlevel,
			 1,
			 "Error in configurations: File too large (5MB), will keep your old configurations.\n");
		break;
	case CONF_ERMEMORY:
		mksysmsg(0, config_logfull_old, config_runmode, config_maxlevel,
			 1,
			 "Error in configurations: Failed to allocate memory when reading file, will keep your old configurations.\n");
		break;
	case CONF_ERPARSE:
		mksysmsg(0, config_logfull_old, config_runmode, config_maxlevel,
			 1,
			 "Error in configurations: Not a valid JSON format, will keep your old configurations.\n");
		break;
	case CONF_ECMEMORY:
		mksysmsg(0, config_logfull_old, config_runmode, config_maxlevel,
			 1,
			 "Error in processing configurations: Failed to allocate memory during internal processing, will keep your old configurations.\n");
		break;
	case CONF_ECNETPRIORITYPROTOCOL:
		mksysmsg(0, config_logfull_old, config_runmode, config_maxlevel,
			 1,
			 "Error in configurations: Entry \"netpriority.protocol\" must be IPv4 or IPv6 (case sensitive), will keep your old configurations.\n");
		break;
	case CONF_ECLISTENPORT:
		mksysmsg(0, config_logfull_old, config_runmode, config_maxlevel,
			 1,
			 "Error in configurations: Entry \"listen.port\" must be an unsigned short integer (0-65535), will keep your old configurations.\n");
		break;
	case CONF_ECPROXY:
		mksysmsg(0, config_logfull_old, config_runmode, config_maxlevel,
			 1,
			 "Error in configurations: Entry \"proxy\" is missing, will keep your old configurations.\n");
		break;
	case CONF_ECPROXYDUP:
		if (config_duperr[0] != '\0') {
			mksysmsg(0, config_logfull_old, config_runmode,
				 config_maxlevel, 1,
				 "Error in configurations: Duplication found in proxy virtual hostnames. Affected: \"%s\", will keep your old configurations.\n",
				 config_duperr);
			config_duperr[0] = '\0';
		} else {
			mksysmsg(0, config_logfull_old, config_runmode,
				 config_maxlevel, 1,
				 "Error in configurations: Duplication found in proxy virtual hostnames, will keep your old configurations.\n");
		}
		break;
	default:
		mksysmsg(0, config_logfull_old, config_runmode, config_maxlevel,
			 1,
			 "Error in processing configurations: Unknown error occurred, code: %d, will keep your old configurations\n",
			 errno);
		break;
	}
	return;
}

int main(int argc, char **argv)
{
	static const char *headmsg =
	    "Minecraft Relay Server [Version " MCRELAY_VERSION_DISPLAY "/"
	    MCRELAY_VERSION_INTERNAL "]\n"
	    "(c) " MCRELAY_COPYYEAR " Bilin Tsui\n\n";
	char *helpmsg =
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
	int strulen = sizeof(addr_inbound_client);
	getcwd(cwd, PATH_MAX);
	if (argc < 2) {
		mksysmsg(1, "", 0, 255, 0, headmsg);
		fprintf(stderr, "Usage: %s %s\n",
			strrchr(argv[0], '/') ? strrchr(argv[0],
							'/') + 1 : argv[0],
			helpmsg);
		return EXITCODE_BADARG;
	}
	argoffset_configfile = argv[1];
	FILE *pidfd = NULL;
	int prevpid = 0;
	char *ptr_argv1 = argv[1];
	if (*ptr_argv1 == '-') {
		ptr_argv1++;
		if ((strcmp(ptr_argv1, "r") == 0)
		    || (strcmp(ptr_argv1, "-reload") == 0)) {
			pidfd = fopen("/run/mcrelay/mcrelay.pid", "r");
			if (pidfd == NULL) {
				mksysmsg(1, "", 0, 255, 0, headmsg);
				mksysmsg(0, "", 0, 255, 0,
					 "Cannot read /run/mcrelay/mcrelay.pid.\n");
				return EXITCODE_NOPIDFILE;
			}
			fscanf(pidfd, "%d", &prevpid);
			fclose(pidfd);
			if (kill(prevpid, SIGUSR1) == 0) {
				mksysmsg(1, "", 0, 255, 2, headmsg);
				mksysmsg(0, "", 0, 255, 2,
					 "Successfully sent reload signal to currently running process.\n");
				return EXITCODE_OK;
			} else {
				mksysmsg(1, "", 0, 255, 0, headmsg);
				mksysmsg(0, "", 0, 255, 0,
					 "Failed to send reload signal to currently running process.\n");
				return EXITCODE_NOSIGNAL;
			}
		} else if ((strcmp(ptr_argv1, "t") == 0)
			   || (strcmp(ptr_argv1, "-stop") == 0)) {
			pidfd = fopen("/run/mcrelay/mcrelay.pid", "r");
			if (pidfd == NULL) {
				mksysmsg(1, "", 0, 255, 0, headmsg);
				mksysmsg(0, "", 0, 255, 0,
					 "Cannot read /run/mcrelay/mcrelay.pid.\n");
				return EXITCODE_NOPIDFILE;
			}
			fscanf(pidfd, "%d", &prevpid);
			fclose(pidfd);
			if (kill(prevpid, SIGTERM) == 0) {
				mksysmsg(1, "", 0, 255, 2, headmsg);
				mksysmsg(0, "", 0, 255, 2,
					 "Successfully sent terminate signal to currently running process.\n");
				return EXITCODE_OK;
			} else {
				mksysmsg(1, "", 0, 255, 0, headmsg);
				mksysmsg(0, "", 0, 255, 0,
					 "Failed to send terminate signal to currently running process.\n");
				return EXITCODE_NOSIGNAL;
			}
		} else if ((strcmp(ptr_argv1, "f") == 0)
			   || (strcmp(ptr_argv1, "-forking") == 0)) {
			config_runmode = 2;
			argoffset_configfile = argv[2];
		} else if ((strcmp(ptr_argv1, "v") == 0)
			   || (strcmp(ptr_argv1, "-version") == 0)) {
			fprintf(stdout, "v%s(%s)\n", MCRELAY_VERSION_DISPLAY,
				MCRELAY_VERSION_INTERNAL);
			return EXITCODE_OK;
		} else {
			mksysmsg(1, "", 0, 255, 0, headmsg);
			fprintf(stderr,
				"Error: Invalid option \"-%s\"\n\nUsage: %s %s\n",
				ptr_argv1,
				strrchr(argv[0], '/') ? strrchr(argv[0],
								'/') +
				1 : argv[0], helpmsg);
			return EXITCODE_BADARG;
		}
	} else {
		pidfd = fopen("/run/mcrelay/mcrelay.pid", "r");
		if (pidfd != NULL) {
			fscanf(pidfd, "%d", &prevpid);
			fclose(pidfd);
			if (kill(prevpid, 0) == 0) {
				mksysmsg(1, "", 0, 255, 0, headmsg);
				mksysmsg(0, "", 0, 255, 0,
					 "You cannot run multiple instances at a time. Previous running process PID: %d.\n",
					 prevpid);
				return EXITCODE_MULTIINSTANCE;
			}
		}
	}
	mksysmsg(1, "", 0, 255, 2, headmsg);
	if (argoffset_configfile == NULL) {
		mksysmsg(0, "", 0, 255, 0, "Config filename cannot be empty!\n",
			 configfile);
		return EXITCODE_BADARG;
	}
	strncpy(configfile, argoffset_configfile, PATH_MAX - 1);
	configfile[PATH_MAX - 1] = '\0';
	if (configfile[0] != '/') {
		snprintf(configfile_full, PATH_MAX, "%s/%s", cwd, configfile);
	} else {
		strncpy(configfile_full, configfile, PATH_MAX - 1);
		configfile_full[PATH_MAX - 1] = '\0';
	}
	mksysmsg(0, "", 0, 255, 2, "Loading configurations from file: %s\n\n",
		 configfile);
	config = config_read(configfile_full);
	switch (errno) {
	case 0:
		if (config->log.filename[0] != '/') {
			snprintf(config_logfull, PATH_MAX, "%s/%s", cwd,
				 config->log.filename);
		} else {
			strncpy(config_logfull, config->log.filename,
				PATH_MAX - 1);
			config_logfull[PATH_MAX - 1] = '\0';
		}
		config_netpriority_enabled = config->netpriority.enabled;
		config_netpriority_protocol = config->netpriority.protocol;
		break;
	case CONF_EROPENFAIL:
		mksysmsg(0, "", 0, 255, 0, "Cannot read config file: %s\n",
			 configfile);
		return EXITCODE_NOCONFFILE;
	case CONF_EROPENLARGE:
		mksysmsg(0, "", 0, 255, 0,
			 "Error in configurations: File too large (5MB).\n");
		return EXITCODE_FILELARGE;
	case CONF_ERMEMORY:
		mksysmsg(0, "", 0, 255, 0,
			 "Error in configurations: Failed to allocate memory when reading file.\n");
		return EXITCODE_NOMEM;
	case CONF_ERPARSE:
		mksysmsg(0, "", 0, 255, 0,
			 "Error in configurations: Not a valid JSON format.\n");
		return EXITCODE_BADJSON;
	case CONF_ECMEMORY:
		mksysmsg(0, "", 0, 255, 0,
			 "Error in processing configurations: Failed to allocate memory during internal processing.\n");
		return EXITCODE_NOMEM;
	case CONF_ECNETPRIORITYPROTOCOL:
		mksysmsg(0, "", 0, 255, 0,
			 "Error in configurations: Entry \"netpriority.protocol\" must be IPv4 or IPv6 (case sensitive).\n");
		return EXITCODE_BADARG;
	case CONF_ECLISTENPORT:
		mksysmsg(0, "", 0, 255, 0,
			 "Error in configurations: Entry \"listen.port\" must be an unsigned short integer (0-65535).\n");
		return EXITCODE_BADARG;
	case CONF_ECPROXY:
		mksysmsg(0, "", 0, 255, 0,
			 "Error in configurations: Entry \"proxy\" is missing!\n");
		return EXITCODE_BADARG;
	case CONF_ECPROXYDUP:
		if (config_duperr[0] != '\0') {
			mksysmsg(0, "", 0, 255, 0,
				 "Error in configurations: Duplication found in proxy virtual hostnames. Affected: \"%s\".\n",
				 config_duperr);
			config_duperr[0] = '\0';
		} else {
			mksysmsg(0, "", 0, 255, 0,
				 "Error in configurations: Duplication found in proxy virtual hostnames.\n");
		}
		return EXITCODE_BADARG;
	default:
		mksysmsg(0, "", 0, 255, 0,
			 "Error in processing configurations: Unknown error occurred, code: %d\n",
			 errno);
		return EXITCODE_INTERNAL;
	}
	FILE *tmpfd = fopen(config_logfull, "a");
	if (tmpfd == NULL) {
		mksysmsg(0, "", 0, 255, 0,
			 "Error: Cannot write log to \"%s\".\n",
			 config->log.filename);
		return EXITCODE_CANTCREAT;
	} else {
		fclose(tmpfd);
	}
	net_addr bindaddr = net_resolve_dual(config->listen.address,
					     config_netpriority_protocol,
					     config_netpriority_enabled);
	if (bindaddr.family == 0) {
		mksysmsg(0, config_logfull, config_runmode, config->log.level,
			 0, "Error: Invalid bind address!\n");
	}
	if (config->listen.port == 0) {
		mksysmsg(0, config_logfull, config_runmode, config->log.level,
			 0, "Error: Invalid bind port!\n");
		return EXITCODE_BADPORT;
	}
	net_addrp bindaddrp = net_ntop(bindaddr.family, &(bindaddr.addr), 1);
	mksysmsg(0, config_logfull, config_runmode, config->log.level, 2,
		 "Binding on %s:%d...\n", (char *)&bindaddrp,
		 config->listen.port);
	socket_inbound_server =
	    net_socket(NETSOCK_BIND, bindaddr.family, &(bindaddr.addr),
		       config->listen.port, 1);
	if (socket_inbound_server == -1) {
		mksysmsg(0, config_logfull, config_runmode, config->log.level,
			 0, "Bind Failed!\n");
		return EXITCODE_BINDFAIL;
	}

	int pid;
	if (config_runmode == 2) {
		pid = fork();
		if (pid > 0) {
			FILE *pidfd = fopen("/run/mcrelay/mcrelay.pid", "w");
			if (pidfd == NULL) {
				mksysmsg(0, "", 0, config->log.level, 0,
					 "Cannot write PID file /run/mcrelay/mcrelay.pid\n");
				return EXITCODE_CANTCREAT;
			}
			fprintf(pidfd, "%d", pid);
			fclose(pidfd);
			mksysmsg(0, config_logfull, config_runmode,
				 config->log.level, 2, "Bind Successful.\n\n");
			mksysmsg(0, "", config_runmode, config->log.level, 2,
				 "For more information, see log file: %s\n\n",
				 config->log.filename);
			mksysmsg(0, "", 0, config->log.level, 2,
				 "Server running on PID: %d\n", pid);
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
			mksysmsg(0, "", 0, config->log.level, 0,
				 "Cannot write PID file /run/mcrelay/mcrelay.pid\n");
			return EXITCODE_CANTCREAT;
		}
		fprintf(pidfd, "%d", pid);
		fclose(pidfd);
	}
	mksysmsg(0, config_logfull, config_runmode, config->log.level, 2,
		 "Bind Successful.\n\n");
	mksysmsg(0, "", config_runmode, config->log.level, 2,
		 "For more information, see log file: %s\n\n",
		 config->log.filename);
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = deal_signal;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	signal(SIGCHLD, SIG_IGN);
	if (!isatty(STDOUT_FILENO)) {
		fclose(stdout);
		fclose(stderr);
	}
	while (1) {
		if (reload_flag) {
			do_reload();
			reload_flag = 0;
		}
		socket_inbound_client =
		    accept(socket_inbound_server,
			   (struct sockaddr *)&addr_inbound_client, &strulen);
		if (socket_inbound_client == -1) {
			if (errno == EINTR)
				continue;
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
			addrbundle_inbound_client.family =
			    *((sa_family_t *) & addr_inbound_client);
			void *addr_inbound_client_addroffset = NULL;
			switch (addrbundle_inbound_client.family) {
			case AF_INET:
				addrbundle_inbound_client.address =
				    net_ntop(AF_INET, &(((struct sockaddr_in *)
							 &addr_inbound_client)->sin_addr), 1);
				addrbundle_inbound_client.address_clean =
				    net_ntop(AF_INET, &(((struct sockaddr_in *)
							 &addr_inbound_client)->sin_addr), 0);
				addrbundle_inbound_client.port =
				    ntohs(((struct sockaddr_in *)
					   &addr_inbound_client)->sin_port);
				break;
			case AF_INET6:
				addr_inbound_client_addroffset =
				    (unsigned char *)
				    &(((struct sockaddr_in6 *)
				       &addr_inbound_client)->sin6_addr);
				if (memcmp
				    (addr_inbound_client_addroffset,
				     "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\xFF\xFF",
				     12) == 0) {
					addrbundle_inbound_client.family =
					    AF_INET;
					addr_inbound_client_addroffset =
					    addr_inbound_client_addroffset + 12;
				}
				addrbundle_inbound_client.address =
				    net_ntop(addrbundle_inbound_client.family,
					     addr_inbound_client_addroffset, 1);
				addrbundle_inbound_client.address_clean =
				    net_ntop(addrbundle_inbound_client.family,
					     addr_inbound_client_addroffset, 0);
				addrbundle_inbound_client.port =
				    ntohs(((struct sockaddr_in6 *)
					   &addr_inbound_client)->sin6_port);
				break;
			}
			int socket_outbound;
			if (backbone
			    (socket_inbound_client, &socket_outbound,
			     config_logfull, config_runmode, config,
			     addrbundle_inbound_client,
			     config_netpriority_enabled)) {
				return EXITCODE_OK;
			}
			net_relay(socket_inbound_client, socket_outbound);
			return EXITCODE_OK;
		}
	}
}
