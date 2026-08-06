/*
 * listener.h: Header file of listener.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_H_INCLUDED_

#define _MRS_LISTENER_H_INCLUDED_

/* section: headers (project) */
#include "config.h"

/* section: functions (exported) */
/* Takes ownership of config and the contents of config_cache. */
int listener_run(conf *config, conf_cache *config_cache, const char *config_filename, const char *config_filename_full, const char *working_directory, const char *log_filename);

#endif
