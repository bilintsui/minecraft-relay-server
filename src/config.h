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
#include <sys/socket.h>

/* section: headers (project) */
#include "define/global.h"

/* section: defines */
/* limit */
#define CONF_ADDRESSMAXLEN	ADDRESS_MAXLEN
/*
 * Max base64-encoded icon length: 7000 bytes leaves ≥1192 for JSON
 * framework + motd text + varint overhead within BUFSIZ (8192).
 */
#define CONF_ICON_B64MAX	7000

/* error code */
#define CONF_EARGUMENT	1
#define CONF_EROPENFAIL	2
#define CONF_EROPENEMPTY	3
#define CONF_EROPENLARGE	4
#define CONF_ERMEMORY	5
#define CONF_ERPARSE	6
#define CONF_ECMEMORY	7
#define CONF_ECNETPRIORITYPROTOCOL	8
#define CONF_ECLISTENPORT	9
#define CONF_ECPROXY	10
#define CONF_ECPROXYDUP	11

/* section: types */
typedef struct {
	void *data;
	size_t size;
} conf_cache;
typedef struct {
	struct {
		bool enabled;
		sa_family_t protocol;
	} netpriority;
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
typedef struct {
	char *address;
	in_port_t port;
	bool valid, srvenabled, rewrite, pheader;
} conf_proxy;
typedef enum {
	CONF_READ_ERROR = -1,
	CONF_READ_UNCHANGED,
	CONF_READ_CHANGED
} conf_read_status;

/* section: global variables */
extern char config_duperr[CONF_ADDRESSMAXLEN];

/* section: functions (exported) */
void config_cache_commit(conf_cache *target, conf_cache *candidate);
void config_cache_destroy(conf_cache *target);
void config_destroy(conf *target);
void config_dumper(conf *src);
const char *config_errmsg(int err);
bool config_icon_load(conf *cfg, const char *logfile, uint8_t loglevel, const char *failure_action);
conf_proxy config_proxy_search(conf *src, const char *targetvhost);
void config_proxy_search_destroy(conf_proxy *target);
conf_read_status config_read(const char *filename, const conf_cache *active_cache, conf_cache *candidate_cache, conf **result);

#endif
