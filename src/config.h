/*
 * config.h: Header file of config.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_CONFIG_H_INCLUDED_

#define _MRS_CONFIG_H_INCLUDED_

/* section: headers (library) */
#include <cjson/cJSON.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "define/global.h"
#include "log.h"

/* section: defines */
/* limit */
#define CONF_ADDRESSMAXLEN	ADDRESS_MAXLEN
/*
 * Max base64-encoded icon length: 7000 bytes leaves ≥1192 for JSON
 * framework + motd text + varint overhead within BUFSIZ (8192).
 */
#define CONF_ICON_B64MAX	7000

/* section: types */
typedef struct {
	void *data;
	size_t size;
} conf_cache;
typedef struct {
	struct {
		char *filename;
		uint8_t level;
	} log;
	struct {
		char *address;
		in_port_t port;
	} listen;
	char *icon_path, *icon_b64;
	conf_cache icon_cache;
	cJSON *proxy;
} conf;
typedef enum {
	CONF_ERROR_NONE,
	CONF_EARGUMENT,
	CONF_EROPENFAIL,
	CONF_EROPENEMPTY,
	CONF_EROPENLARGE,
	CONF_ERMEMORY,
	CONF_ERPARSE,
	CONF_ECMEMORY,
	CONF_ECLISTENPORT,
	CONF_ECPROXY,
	CONF_ECPROXYDUP
} conf_error;
typedef enum {
	CONF_READ_ERROR = -1,
	CONF_READ_UNCHANGED,
	CONF_READ_CHANGED
} conf_read_status;

/* section: functions (exported) */
void config_cache_commit(conf_cache *target, conf_cache *candidate);
void config_cache_destroy(conf_cache *target);
bool config_clone(const conf *source, conf **result);
void config_destroy(conf *target);
void config_dumper(conf *src);
const char *config_errmsg(conf_error err);
bool config_icon_load(conf *cfg, const char *logfile, uint8_t loglevel, const char *failure_action);
void config_log_duplicate_error(const char *logfile, uint8_t maxlevel, mksys_level msglevel, const char *suffix);
conf_read_status config_read(const char *filename, const conf_cache *active_cache, conf_cache *candidate_cache, conf **result);

#endif
