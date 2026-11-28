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
#include "network.h"
#include "protocol/proxy.h"

/* section: defines */
/* limit */
#define CONF_ADDRESSMAXLEN	ADDRESS_MAXLEN
/*
 * Max base64-encoded icon length: 7000 bytes leaves ≥1192 for JSON
 * framework + motd text + varint overhead within BUFSIZ (8192).
 */
#define CONF_ICON_B64MAX	7000

/* metrics */
#ifndef CONF_METRICS_MINIMUM_INTERVAL
#define CONF_METRICS_MINIMUM_INTERVAL	300U
#endif
#define CONF_METRICS_MAXIMUM_INTERVAL	86400U

/* section: types */
typedef struct {
	void *data;
	size_t size;
} conf_cache;
typedef enum {
	CONF_UNTRUSTED_REJECT,
	CONF_UNTRUSTED_IGNORE,
	CONF_UNTRUSTED_ACCEPT
} conf_untrusted_policy;
typedef struct {
	net_addr address;
	uint8_t host_bits; /* Zero for an individual address, including after IPv4-mapped normalization. */
	char text[INET6_ADDRSTRLEN + sizeof("/128") - 1];
} conf_trusted_source;
typedef struct {
	struct {
		char *filename;
		uint8_t level;
	} log;
	struct {
		char *address;
		in_port_t port;
		bool allow_proxy;
		proxy_prefix proxy_version;
		conf_untrusted_policy untrusted_policy;
		conf_trusted_source *trusted_sources;
		size_t trusted_count;
	} listen;
	struct {
		uint32_t interval;
	} metrics;
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
	CONF_ECFIELD,
	CONF_ECMETRICS,
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
bool config_peer_trusted(const conf *config, net_addr address);
/* An omitted field selects v1. OTHER flags an invalid explicit value. */
static inline proxy_prefix config_proxy_version(const cJSON *value) {
	if (value == NULL) {
		return PROXY_PREFIX_V1;
	}
	if (cJSON_IsNumber(value) && (value->valuedouble == PROXY_PREFIX_V1 || value->valuedouble == PROXY_PREFIX_V2)) {
		return (proxy_prefix)value->valueint;
	}
	return PROXY_PREFIX_OTHER;
}
conf_read_status config_read(const char *filename, const conf_cache *active_cache, conf_cache *candidate_cache, conf **result);
/* Report reload field diagnostics at WARN using the active log path and level. */
conf_read_status config_read_with_log(const char *filename, const conf_cache *active_cache, conf_cache *candidate_cache, conf **result, const char *active_log, uint8_t maxlevel);

#endif
