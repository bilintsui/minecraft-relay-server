/*
 * resolver/util.h: Header file of resolver/util.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_RESOLVER_UTIL_H_INCLUDED_

#define _MRS_RESOLVER_UTIL_H_INCLUDED_

/* section: headers (library) */
#include <arpa/nameser.h>
#include <stdbool.h>
#include <stddef.h>

/* section: functions (exported) */
bool resolver_name_encloses(const char *zone, const char *name);
bool resolver_name_normalize(const char *source, char target[NS_MAXDNAME]);
bool resolver_size_add(size_t *target, size_t value);
bool resolver_size_multiply(size_t left, size_t right, size_t *result);

#endif
