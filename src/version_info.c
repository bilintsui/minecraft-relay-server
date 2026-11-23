/*
 * version_info.c: Shared build-version identification
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (project) */
#include "define/global.h"
#include "version.h"

/* section: headers (self) */
#include "version_info.h"

/* section: defines */
#if DEBUG_MODE
#define VERSION_DEBUG_SUFFIX "-debug"
#else
#define VERSION_DEBUG_SUFFIX ""
#endif

/* section: functions (exported) */
const char *version_info_get(void) {
	return MCRELAY_VERSION_INTERNAL[0] != '\0'
		? "v" MCRELAY_VERSION_DISPLAY MCRELAY_VERSION_SUFFIX VERSION_DEBUG_SUFFIX "(" MCRELAY_VERSION_INTERNAL ")"
		: "v" MCRELAY_VERSION_DISPLAY MCRELAY_VERSION_SUFFIX VERSION_DEBUG_SUFFIX;
}
