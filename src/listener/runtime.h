/*
 * listener/runtime.h: Listener runtime entry point
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_RUNTIME_H_INCLUDED_

#define _MRS_LISTENER_RUNTIME_H_INCLUDED_

/* section: headers (project) */
#include "../config.h"
#include "../define/exitcode.h"

/* section: functions (exported) */
/* Takes ownership of config and the contents of config_cache. */
exit_code listener_run(conf *config, conf_cache *config_cache, const char *config_filename, const char *config_filename_full, const char *working_directory, const char *log_filename);

#endif
