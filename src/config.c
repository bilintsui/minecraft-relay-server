/*
 * config.c: Functions for config reading
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "basic.h"
#include "log.h"

#include "config.h"

char config_duperr[CONF_ADDRESSMAXLEN] = { 0 };

void config_destroy(conf *target) {
	if (target != NULL) {
		free(target->log.filename);
		free(target->listen.address);
		free(target->icon_path);
		free(target->icon_b64);
		if (target->proxy != NULL) {
			cJSON_Delete(target->proxy);
		}
		free(target);
	}
}

bool config_jsonbool(cJSON *src, bool defaultvalue) {
	if (src == NULL) {
		return defaultvalue;
	}
	if (cJSON_IsBool(src)) {
		return cJSON_IsTrue(src);
	} else if (cJSON_IsNumber(src)) {
		return (src->valueint != 0);
	} else {
		return defaultvalue;
	}
}

void config_dumper(conf *src) {
	printf("Config Detail:\n");
	printf("\n[NETPRIORITY]\n");
	if (src->netpriority.enabled) {
		printf("Enabled\t\ttrue\n");
	} else {
		printf("Enabled\t\tfalse\n");
	}
	if (src->netpriority.protocol == AF_INET) {
		printf("Protocol\tIPv4\n");
	} else if (src->netpriority.protocol == AF_INET6) {
		printf("Protocol\tIPv6\n");
	}
	printf("\n[LOG]\n");
	printf("Filename\t%s\n", src->log.filename);
	printf("Level\t\t%d\n", src->log.level);
	if (src->log.binary) {
		printf("Binary\t\ttrue\n");
	} else {
		printf("Binary\t\tfalse\n");
	}
	printf("\n[LISTEN]\n");
	printf("Address\t\t%s\n", src->listen.address);
	printf("Port\t\t%d\n", src->listen.port);
	if (src->icon_path != NULL && src->icon_path[0] != '\0') {
		printf("Icon\t\t%s\n", src->icon_path);
	} else {
		printf("Icon\t\t<default>\n");
	}
	cJSON *proxy = src->proxy;
	cJSON *single = NULL;
	int proxy_count = 1;
	cJSON_ArrayForEach(single, proxy) {
		printf("\n[PROXY #%d]\n", proxy_count);
		cJSON *single_vhost = cJSON_GetObjectItemCaseSensitive(single, "vhost");
		cJSON *recvhost = NULL;
		int vhost_count = 1;
		cJSON_ArrayForEach(recvhost, single_vhost) {
			if (cJSON_IsString(recvhost)) {
				printf("vHost #%d\t%s\n", vhost_count, recvhost->valuestring);
				vhost_count++;
			}
		}
		printf("Address\t\t%s\n", cJSON_GetObjectItemCaseSensitive(single, "address")->valuestring);
		cJSON *single_port = cJSON_GetObjectItemCaseSensitive(single, "port");
		if (single_port == NULL) {
			printf("Port\t\t<SRV>\n");
		} else {
			printf("Port\t\t%d\n", single_port->valueint);
		}
		if (config_jsonbool(cJSON_GetObjectItemCaseSensitive(single, "rewrite"), false)) {
			printf("Rewrite\t\ttrue\n");
		} else {
			printf("Rewrite\t\tfalse\n");
		}
		if (config_jsonbool(cJSON_GetObjectItemCaseSensitive(single, "pheader"), false)) {
			printf("PHeader\t\ttrue\n");
		} else {
			printf("PHeader\t\tfalse\n");
		}
		proxy_count++;
	}
}

/*
 * Load and base64-encode the icon file specified in cfg->icon_path.
 * If the encoded result exceeds CONF_ICON_B64MAX or any step fails,
 * cfg->icon_b64 stays NULL (caller falls back to FAVICON_BASE64).
 */
void config_icon_load(conf *cfg, const char *logfile, uint8_t runmode, uint8_t loglevel) {
	if (cfg->icon_path == NULL) {
		return;
	}
	void *icon_raw = NULL;
	ssize_t icon_size = freadall(cfg->icon_path, &icon_raw, false);
	if (icon_size > 0) {
		size_t blocks = icon_size / 3;
		size_t b64_size = (blocks + (icon_size % 3 > 0)) * 4;
		if (b64_size > CONF_ICON_B64MAX) {
			mksysmsg(MKSYS_PREFIX_ON, logfile, runmode, loglevel, MKSYS_LEVEL_WARNING,
				"Icon too large (base64: %zu > %u bytes), using default.\n",
				b64_size, CONF_ICON_B64MAX
			);
		} else {
			cfg->icon_b64 = (char *)malloc(b64_size + 1);
			if (cfg->icon_b64 != NULL) {
				base64_encode(cfg->icon_b64, b64_size, icon_raw, icon_size);
				cfg->icon_b64[b64_size] = '\0';
			} else {
				mksysmsg(MKSYS_PREFIX_ON, logfile, runmode, loglevel, MKSYS_LEVEL_WARNING,
					"No memory for icon, using default.\n"
				);
			}
		}
		free(icon_raw);
	} else {
		if (icon_raw != NULL) {
			free(icon_raw);
		}
		if (icon_size == 0) {
			mksysmsg(MKSYS_PREFIX_ON, logfile, runmode, loglevel, MKSYS_LEVEL_WARNING,
				"Icon file %s is empty, using default.\n",
				cfg->icon_path
			);
		} else if (icon_size == -1) {
			switch (errno) {
				case FREADALL_ERFAIL:
					mksysmsg(MKSYS_PREFIX_ON, logfile, runmode, loglevel, MKSYS_LEVEL_WARNING,
						"Cannot open icon file %s, using default.\n",
						cfg->icon_path
					);
					break;
				case FREADALL_ELARGE:
					mksysmsg(MKSYS_PREFIX_ON, logfile, runmode, loglevel, MKSYS_LEVEL_WARNING,
						"Icon file %s too large, using default.\n",
						cfg->icon_path
					);
					break;
				case FREADALL_ENOMEM:
					mksysmsg(MKSYS_PREFIX_ON, logfile, runmode, loglevel, MKSYS_LEVEL_WARNING,
						"No memory to read icon file %s, using default.\n",
						cfg->icon_path
					);
					break;
				default:
					mksysmsg(MKSYS_PREFIX_ON, logfile, runmode, loglevel, MKSYS_LEVEL_WARNING,
						"Cannot read icon file %s, using default.\n",
						cfg->icon_path
					);
					break;
			}
		}
	}
}

cJSON *config_proxy_parse(cJSON *src) {
	cJSON *single = NULL;
	cJSON_ArrayForEach(single, src) {
		cJSON *single_vhost = cJSON_GetObjectItemCaseSensitive(single, "vhost");
		if (single_vhost == NULL) {
			cJSON_DetachItemViaPointer(src, single);
			continue;
		}
		if (!cJSON_IsArray(single_vhost)) {
			if (!cJSON_IsString(single_vhost)) {
				cJSON_DetachItemViaPointer(src, single);
				continue;
			}
			char *vhost = (char *)malloc(strlen(single_vhost->valuestring) + 1);
			if (vhost == NULL) {
				errno = CONF_ECMEMORY;
				return NULL;
			}
			strcpy(vhost, single_vhost->valuestring);
			cJSON_DeleteItemFromObjectCaseSensitive(single, "vhost");
			single_vhost = cJSON_AddArrayToObject(single, "vhost");
			cJSON *item_vhost = cJSON_CreateString(vhost);
			free(vhost);
			cJSON_AddItemToArray(single_vhost, item_vhost);
		}
		cJSON *single_address = cJSON_GetObjectItemCaseSensitive(single, "address");
		if (single_address == NULL) {
			cJSON_DetachItemViaPointer(src, single);
			continue;
		}
		if (!cJSON_IsString(single_address)) {
			cJSON_DetachItemViaPointer(src, single);
			continue;
		}
		cJSON *single_port = cJSON_GetObjectItemCaseSensitive(single, "port");
		if (single_port != NULL) {
			if (!cJSON_IsNumber(single_port)) {
				cJSON_DetachItemViaPointer(src, single);
				continue;
			}
			int port = single_port->valueint;
			if ((port < 0) || (port > 65535)) {
				cJSON_DetachItemViaPointer(src, single);
				continue;
			}
		}
	}
	cJSON *result = cJSON_Duplicate(src, 1);
	int dupdet_count = 0;
	char **vhost_namelist = NULL;
	cJSON *rec_result = NULL;
	cJSON_ArrayForEach(rec_result, result) {
		cJSON *result_vhostname = cJSON_GetObjectItemCaseSensitive(rec_result, "vhost");
		cJSON *rec_result_vhostname = NULL;
		cJSON_ArrayForEach(rec_result_vhostname, result_vhostname) {
			if (dupdet_count == 0) {
				vhost_namelist = (char **)calloc(1, sizeof(char **));
				if (vhost_namelist == NULL) {
					cJSON_Delete(result);
					errno = CONF_ECMEMORY;
					return NULL;
				}
				vhost_namelist[dupdet_count] = (char *)malloc(strlen(rec_result_vhostname->valuestring) + 1);
				if (vhost_namelist[dupdet_count] == NULL) {
					free(vhost_namelist);
					cJSON_Delete(result);
					errno = CONF_ECMEMORY;
					return NULL;
				}
				strcpy(vhost_namelist[dupdet_count], rec_result_vhostname->valuestring);
				dupdet_count++;
				continue;
			}
			for (int i = 0; i < dupdet_count; i++) {
				if (strcasecmp(vhost_namelist[i], rec_result_vhostname->valuestring) == 0) {
					snprintf(config_duperr, sizeof(config_duperr), "%s", rec_result_vhostname->valuestring);
					for (int j = 0; j < dupdet_count; j++) {
						free(vhost_namelist[j]);
					}
					free(vhost_namelist);
					cJSON_Delete(result);
					errno = CONF_ECPROXYDUP;
					return NULL;
				}
				if (i == (dupdet_count - 1)) {
					char **vhost_namelist_new = (char **)realloc(vhost_namelist, (dupdet_count + 1) * sizeof(char **));
					if (vhost_namelist_new == NULL) {
						for (int j = 0; j < dupdet_count; j++) {
							free(vhost_namelist[j]);
						}
						free(vhost_namelist);
						cJSON_Delete(result);
						errno = CONF_ECMEMORY;
						return NULL;
					}
					vhost_namelist = vhost_namelist_new;
					vhost_namelist[dupdet_count] = (char *)malloc(strlen(rec_result_vhostname->valuestring) + 1);
					if (vhost_namelist[dupdet_count] == NULL) {
						for (int j = 0; j < dupdet_count; j++) {
							free(vhost_namelist[j]);
						}
						free(vhost_namelist);
						cJSON_Delete(result);
						errno = CONF_ECMEMORY;
						return NULL;
					}
					strcpy(vhost_namelist[dupdet_count], rec_result_vhostname->valuestring);
					dupdet_count++;
					break;
				}
			}
		}
	}
	for (int i = 0; i < dupdet_count; i++) {
		free(vhost_namelist[i]);
	}
	free(vhost_namelist);
	cJSON_Delete(src);
	errno = 0;
	return result;
}

conf_proxy config_proxy_search(conf *src, const char *targetvhost) {
	conf_proxy result;
	memset(&result, 0, sizeof(result));
	if ((src == NULL) || (targetvhost == NULL)) {
		return result;
	}
	cJSON *proxylist = src->proxy;
	if (proxylist == NULL) {
		return result;
	}
	cJSON *rec_proxylist = NULL;
	cJSON_ArrayForEach(rec_proxylist, proxylist) {
		cJSON *vhostnames = cJSON_GetObjectItemCaseSensitive(rec_proxylist, "vhost");
		if (vhostnames == NULL) {
			return result;
		}
		cJSON *rec_vhostname = NULL;
		cJSON_ArrayForEach(rec_vhostname, vhostnames) {
			if (cJSON_IsString(rec_vhostname)) {
				if (strcmp_notail(rec_vhostname->valuestring, targetvhost, '.', true) == 0) {
					result.address = (char *)malloc(strlen(cJSON_GetObjectItemCaseSensitive(rec_proxylist, "address")->valuestring) + 1);
					if (result.address == NULL) {
						return result;
					}
					result.valid = true;
					strcpy(result.address, cJSON_GetObjectItemCaseSensitive(rec_proxylist, "address")->valuestring);
					cJSON *target_port = cJSON_GetObjectItemCaseSensitive(rec_proxylist, "port");
					if (target_port == NULL) {
						result.srvenabled = true;
					} else {
						result.port = target_port->valueint;
					}
					result.rewrite = config_jsonbool(cJSON_GetObjectItemCaseSensitive(rec_proxylist, "rewrite"), false);
					result.pheader = config_jsonbool(cJSON_GetObjectItemCaseSensitive(rec_proxylist, "pheader"), false);
					return result;
				}
			}
		}
	}
	return result;
}

void config_proxy_search_destroy(conf_proxy *target) {
	if (target->address != NULL) {
		free(target->address);
		target->address = NULL;
	}
	memset(target, 0, sizeof(conf_proxy));
}

conf *config_read(char *filename) {
	if (filename == NULL) {
		errno = CONF_EARGNULL;
		return NULL;
	}
	void *config_raw = NULL;
	ssize_t config_size = freadall(filename, &config_raw, DEBUG_MODE);
	if (config_size <= 0) {
		if (config_size == 0) {
			errno = CONF_EROPENEMPTY;
		} else if (config_size == -1) {
			switch (errno) {
				case FREADALL_ERFAIL:
					errno = CONF_EROPENFAIL;
					break;
				case FREADALL_ELARGE:
					errno = CONF_EROPENLARGE;
					break;
				case FREADALL_ENOMEM:
					errno = CONF_ERMEMORY;
					break;
			}
		}
		return NULL;
	}
	cJSON *config_json = cJSON_ParseWithLength(config_raw, config_size);
	free(config_raw);
	if (config_json == NULL) {
		errno = CONF_ERPARSE;
		return NULL;
	}
	conf *result = (conf *)calloc(1, sizeof(conf));
	if (result == NULL) {
		cJSON_Delete(config_json);
		errno = CONF_ECMEMORY;
		return NULL;
	}
	result->netpriority.enabled = true;
	result->netpriority.protocol = AF_INET6;
	cJSON *config_json_netpriority = cJSON_GetObjectItemCaseSensitive(config_json, "netpriority");
	if (config_json_netpriority != NULL) {
		result->netpriority.enabled = config_jsonbool(cJSON_GetObjectItemCaseSensitive(config_json_netpriority, "enabled"), true);
		cJSON *config_json_netpriority_protocol = cJSON_GetObjectItemCaseSensitive(config_json_netpriority, "protocol");
		if (cJSON_IsString(config_json_netpriority_protocol)) {
			if (strcmp(config_json_netpriority_protocol->valuestring, "IPv4") == 0) {
				result->netpriority.protocol = AF_INET;
			} else if (strcmp(config_json_netpriority_protocol->valuestring, "IPv6") == 0) {
				result->netpriority.protocol = AF_INET6;
			} else {
				cJSON_Delete(config_json);
				config_destroy(result);
				errno = CONF_ECNETPRIORITYPROTOCOL;
				return NULL;
			}
		}
	}
	const char *config_default_log_filename = "/var/log/mcrelay/access.log";
	result->log.filename = (char *)malloc(strlen(config_default_log_filename) + 1);
	if (result->log.filename == NULL) {
		cJSON_Delete(config_json);
		config_destroy(result);
		errno = CONF_ECMEMORY;
		return NULL;
	}
	strcpy(result->log.filename, config_default_log_filename);
	result->log.level = MKSYS_LEVEL_INFORMATION;
	result->log.binary = false;
	cJSON *config_json_log = cJSON_GetObjectItemCaseSensitive(config_json, "log");
	if (config_json_log != NULL) {
		cJSON *config_json_log_filename = cJSON_GetObjectItemCaseSensitive(config_json_log, "filename");
		if (config_json_log_filename != NULL) {
			if (cJSON_IsString(config_json_log_filename)) {
				if (config_json_log_filename->valuestring != NULL) {
					char *result_log_filename_new = (char *)realloc(result->log.filename, strlen(config_json_log_filename->valuestring) + 1);
					if (result_log_filename_new == NULL) {
						cJSON_Delete(config_json);
						config_destroy(result);
						errno = CONF_ECMEMORY;
						return NULL;
					}
					result->log.filename = result_log_filename_new;
					strcpy(result->log.filename, config_json_log_filename->valuestring);
				}
			}
		}
		cJSON *config_json_log_level = cJSON_GetObjectItemCaseSensitive(config_json_log, "level");
		if (config_json_log_level != NULL) {
			if (cJSON_IsNumber(config_json_log_level)) {
				result->log.level = config_json_log_level->valueint;
			}
		}
		result->log.binary = config_jsonbool(cJSON_GetObjectItemCaseSensitive(config_json_log, "binary"), false);
	}
	const char *config_default_listen_address = "::";
	result->listen.address = (char *)malloc(strlen(config_default_listen_address) + 1);
	if (result->listen.address == NULL) {
		cJSON_Delete(config_json);
		config_destroy(result);
		errno = CONF_ECMEMORY;
		return NULL;
	}
	strcpy(result->listen.address, config_default_listen_address);
	result->listen.port = 25565;
	cJSON *config_json_listen = cJSON_GetObjectItemCaseSensitive(config_json, "listen");
	if (config_json_listen != NULL) {
		cJSON *config_json_listen_address = cJSON_GetObjectItemCaseSensitive(config_json_listen, "address");
		if (config_json_listen_address != NULL) {
			if (cJSON_IsString(config_json_listen_address)) {
				if (config_json_listen_address->valuestring != NULL) {
					char *result_listen_address_new = (char *)realloc(result->listen.address, strlen(config_json_listen_address->valuestring) + 1);
					if (result_listen_address_new == NULL) {
						cJSON_Delete(config_json);
						config_destroy(result);
						errno = CONF_ECMEMORY;
						return NULL;
					}
					result->listen.address = result_listen_address_new;
					strcpy(result->listen.address, config_json_listen_address->valuestring);
				}
			}
		}
		cJSON *config_json_listen_port = cJSON_GetObjectItemCaseSensitive(config_json_listen, "port");
		if (config_json_listen_port != NULL) {
			if (cJSON_IsNumber(config_json_listen_port)) {
				int port = config_json_listen_port->valueint;
				if ((port < 0) || (port > 65535)) {
					cJSON_Delete(config_json);
					config_destroy(result);
					errno = CONF_ECLISTENPORT;
					return NULL;
				}
				result->listen.port = port;
			}
		}
	}
	cJSON *config_json_icon = cJSON_GetObjectItemCaseSensitive(config_json, "icon");
	if (cJSON_IsString(config_json_icon) && config_json_icon->valuestring != NULL
		&& config_json_icon->valuestring[0] != '\0') {
		result->icon_path = (char *)malloc(strlen(config_json_icon->valuestring) + 1);
		if (result->icon_path == NULL) {
			cJSON_Delete(config_json);
			config_destroy(result);
			errno = CONF_ECMEMORY;
			return NULL;
		}
		strcpy(result->icon_path, config_json_icon->valuestring);
	} else {
		result->icon_path = NULL;
	}
	result->icon_b64 = NULL;
	cJSON *config_json_proxy = cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(config_json, "proxy"), 1);
	if (config_json_proxy == NULL) {
		cJSON_Delete(config_json);
		config_destroy(result);
		errno = CONF_ECPROXY;
		return NULL;
	}
	cJSON_Delete(config_json);
	if (!cJSON_IsArray(config_json_proxy)) {
		cJSON_Delete(config_json_proxy);
		config_destroy(result);
		errno = CONF_ECPROXY;
		return NULL;
	}
	if (!cJSON_GetArraySize(config_json_proxy)) {
		cJSON_Delete(config_json_proxy);
		config_destroy(result);
		errno = CONF_ECPROXY;
		return NULL;
	}
	cJSON *config_json_proxy_parsed = config_proxy_parse(config_json_proxy);
	if (errno) {
		cJSON_Delete(config_json_proxy);
		config_destroy(result);
		return NULL;
	}
	result->proxy = config_json_proxy_parsed;
	errno = 0;
	return result;
}
