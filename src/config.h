/*
 * config.h: Header file of config.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_CONFIG_H_INCLUDED_

#define _MRS_CONFIG_H_INCLUDED_

#include <cjson/cJSON.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define CONF_ADDRESSMAXLEN	ADDRESS_MAXLEN

/*
 * Max base64-encoded icon length: 7000 bytes leaves ≥1192 for JSON
 * framework + motd text + varint overhead within BUFSIZ (8192).
 */
#define CONF_ICON_B64MAX	7000

#define CONF_EARGNULL	1
#define CONF_EROPENFAIL	2
#define CONF_EROPENLARGE	3
#define CONF_ERMEMORY	4
#define CONF_ERPARSE	5
#define CONF_ECMEMORY	6
#define CONF_ECNETPRIORITYPROTOCOL	7
#define CONF_ECLISTENPORT	8
#define CONF_ECPROXY	9
#define CONF_ECPROXYDUP	10

typedef struct {
	struct {
		short enabled;
		sa_family_t protocol;
	} netpriority;
	struct {
		char *filename;
		short level, binary;
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
	short valid, srvenabled, rewrite, pheader;
} conf_proxy;

extern char config_duperr[CONF_ADDRESSMAXLEN];
void config_destroy(conf * target);
short config_jsonbool(cJSON * src, short defaultvalue);
void config_dumper(conf * src);
void config_icon_load(conf *cfg, char *logfile, unsigned short runmode, unsigned short loglevel);
cJSON *config_proxy_parse(cJSON * src);
conf_proxy config_proxy_search(conf * src, const char *targetvhost);
void config_proxy_search_destroy(conf_proxy * target);
conf *config_read(char *filename);

#endif
