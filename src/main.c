/*
 * main.c: Entry point
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* section: headers (project) */
#include "basic.h"
#include "config.h"
#include "define/exitcode.h"
#include "define/global.h"
#include "listener.h"
#include "log.h"
#include "version.h"

/* section: defines */
/* default */
#define DEFAULT_CONFIG_FILE	"/etc/mcrelay/config.json"

/* logging macro */
#define LOG(lvl, ...)	MKSYS_LOG(MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL, lvl, __VA_ARGS__)

/* section: types */
typedef enum {
	ARG_OK,
	ARG_ERR_UNKNOWN_COMMAND,
	ARG_ERR_UNKNOWN_HELP_TOPIC,
	ARG_ERR_EMPTY_CONFIG,
	ARG_ERR_MISSING_VALUE,
	ARG_ERR_INVALID_ARGUMENT,
	ARG_ERR_INVALID
} arg_error;
typedef enum {
	COMMAND_INVALID,
	COMMAND_DUMPCONFIG,
	COMMAND_HELP,
	COMMAND_RUN,
	COMMAND_VERSION
} command;
typedef enum {
	HELP_GENERAL,
	HELP_DUMPCONFIG,
	HELP_HELP,
	HELP_RUN,
	HELP_VERSION
} help_topic;
typedef struct {
	command command;
	const char *configfile;
	help_topic help_topic;
	arg_error error;
	const char *error_arg;
} arguments;

/* section: functions (local) */
static exit_code config_exitcode(conf_error err) {
	switch (err) {
		case CONF_EROPENLARGE:
			return EXITCODE_FILELARGE;
		case CONF_ERMEMORY:
		case CONF_ECMEMORY:
			return EXITCODE_NOMEM;
		case CONF_ERPARSE:
			return EXITCODE_BADJSON;
		case CONF_ECLISTENPORT:
		case CONF_ECPROXY:
		case CONF_ECPROXYDUP:
			return EXITCODE_BADARG;
		default:
			return EXITCODE_INTERNAL;
	}
}

static exit_code load_config(const char *filename, const char *filename_full, const conf_cache *active_cache, conf_cache *candidate_cache, conf **target) {
	conf_read_status read_status = config_read(filename_full, active_cache, candidate_cache, target);
	switch (read_status) {
		case CONF_READ_CHANGED:
			return EXITCODE_OK;
		case CONF_READ_UNCHANGED:
			LOG(MKSYS_LEVEL_CRITICAL, "Error in processing configurations: Initial config load unexpectedly reported no change.");
			return EXITCODE_INTERNAL;
		case CONF_READ_ERROR:
			break;
	}
	conf_error config_error = (conf_error)errno;
	switch (config_error) {
		case CONF_EROPENFAIL:
		case CONF_EROPENEMPTY:
			LOG(MKSYS_LEVEL_CRITICAL, "%s%s", config_errmsg(config_error), filename);
			return EXITCODE_NOCONFFILE;
		case CONF_EROPENLARGE:
		case CONF_ERMEMORY:
		case CONF_ECMEMORY:
		case CONF_ERPARSE:
		case CONF_ECLISTENPORT:
		case CONF_ECPROXY:
			LOG(MKSYS_LEVEL_CRITICAL, "%s", config_errmsg(config_error));
			return config_exitcode(config_error);
		case CONF_ECPROXYDUP:
			config_log_duplicate_error(MKSYS_NOLOGFILE, MKSYS_LEVEL_ALL, MKSYS_LEVEL_CRITICAL, "");
			return config_exitcode(config_error);
		default:
			LOG(MKSYS_LEVEL_CRITICAL, "Error in processing configurations: Unknown error occurred, code: %d", config_error);
			return EXITCODE_INTERNAL;
	}
}

static exit_code dump_config(const char *filename) {
	char current_directory[PATH_MAX];
	char filename_full[PATH_MAX];
	conf_cache active_cache = { 0 };
	conf_cache candidate_cache = { 0 };
	conf *parsed = NULL;
	if (getcwd(current_directory, sizeof(current_directory)) == NULL) {
		LOG(MKSYS_LEVEL_CRITICAL, "Error: Cannot determine current working directory.");
		return EXITCODE_INTERNAL;
	}
	resolve_path(filename, current_directory, filename_full, sizeof(filename_full));
	exit_code exitcode = load_config(filename, filename_full, &active_cache, &candidate_cache, &parsed);
	if (exitcode == EXITCODE_OK) {
		config_dumper(parsed);
	}
	config_destroy(parsed);
	config_cache_destroy(&active_cache);
	config_cache_destroy(&candidate_cache);
	return exitcode;
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
		command config_command = strcmp(argv[1], "dumpconfig") == 0 ? COMMAND_DUMPCONFIG : COMMAND_RUN;
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

static void print_help(help_topic topic, const char *progname) {
	bool internal_assigned = MCRELAY_VERSION_INTERNAL[0] != '\0';
	fprintf(stdout,
		"Minecraft Relay Server [Version %s%s%s%s]\n"
		"(c) %s Bilin Tsui\n\n",
		MCRELAY_VERSION_DISPLAY, MCRELAY_VERSION_SUFFIX, internal_assigned ? "/" : "", MCRELAY_VERSION_INTERNAL, MCRELAY_COPYYEAR
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
		case COMMAND_VERSION: {
			bool internal_assigned = MCRELAY_VERSION_INTERNAL[0] != '\0';
			if (internal_assigned) {
				fprintf(stdout, "v%s%s(%s)\n", MCRELAY_VERSION_DISPLAY, MCRELAY_VERSION_SUFFIX, MCRELAY_VERSION_INTERNAL);
			} else {
				fprintf(stdout, "v%s%s\n", MCRELAY_VERSION_DISPLAY, MCRELAY_VERSION_SUFFIX);
			}
			return EXITCODE_OK;
		}
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
	if (geteuid() == 0) {
		LOG(MKSYS_LEVEL_WARNING, "Running as root is unsafe and entirely at your own risk; use an unprivileged account instead.");
	}
	char config_filename[PATH_MAX] = { 0 };
	char config_filename_full[PATH_MAX] = { 0 };
	char log_filename[PATH_MAX] = { 0 };
	char working_directory[PATH_MAX] = { 0 };
	if (getcwd(working_directory, sizeof(working_directory)) == NULL) {
		LOG(MKSYS_LEVEL_CRITICAL, "Error: Cannot determine current working directory.");
		return EXITCODE_INTERNAL;
	}
	snprintf(config_filename, sizeof(config_filename), "%s", args.configfile);
	resolve_path(config_filename, working_directory, config_filename_full, sizeof(config_filename_full));
	LOG(MKSYS_LEVEL_INFORMATION, "Loading configurations from file: %s", config_filename);
	conf *config = NULL;
	conf_cache config_cache_state = { 0 };
	conf_cache config_cache_candidate = { 0 };
	exit_code config_load_status = load_config(config_filename, config_filename_full, &config_cache_state, &config_cache_candidate, &config);
	if (config_load_status != EXITCODE_OK) {
		config_destroy(config);
		config_cache_destroy(&config_cache_candidate);
		return config_load_status;
	}
	resolve_path(config->log.filename, working_directory, log_filename, sizeof(log_filename));
	if (log_file_validate(log_filename) == -1) {
		LOG(MKSYS_LEVEL_CRITICAL, "Error: Cannot write log to \"%s\".", config->log.filename);
		config_destroy(config);
		config_cache_destroy(&config_cache_candidate);
		return EXITCODE_CANTCREAT;
	}
	config_icon_load(config, log_filename, config->log.level, "using default");
	config_cache_commit(&config_cache_state, &config_cache_candidate);
	return listener_run(config, &config_cache_state, config_filename, config_filename_full, working_directory, log_filename);
}
