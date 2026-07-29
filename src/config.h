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
#define CONF_EARGNULL	1
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
	struct {
		bool enabled;
		sa_family_t protocol;
	} netpriority;
	struct {
		char *filename;
		uint8_t level;
		bool binary;
	} log;
	struct {
		char *address;
		in_port_t port;
	} listen;
	char *icon_path, *icon_b64;
	cJSON *proxy;
} conf;
typedef struct {
	char *address;
	in_port_t port;
	bool valid, srvenabled, rewrite, pheader;
} conf_proxy;

/* section: global variables */
extern char config_duperr[CONF_ADDRESSMAXLEN];

/* section: functions (exported) */
void config_destroy(conf *target);
void config_dumper(conf *src);
const char *config_errmsg(int err);
void config_icon_load(conf *cfg, const char *logfile, uint8_t loglevel);
conf_proxy config_proxy_search(conf *src, const char *targetvhost);
void config_proxy_search_destroy(conf_proxy *target);
conf *config_read(char *filename);

#endif
