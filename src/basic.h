/*
 * basic.h: Header file of basic.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_BASIC_H_INCLUDED_

#define _MRS_BASIC_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <sys/types.h>

/* section: headers (project) */
#include "define/global.h"

/* section: defines */
/* freadall() limit */
#define FREADALL_SLIMIT	5242880

/* section: types */
typedef enum {
	FREADALL_ERROR_NONE,
	FREADALL_EINVAL,
	FREADALL_ERFAIL,
	FREADALL_ELARGE,
	FREADALL_ENOMEM
} freadall_error;

/* section: functions (exported) */
size_t base64_encode(void *dst, size_t dst_cap, const void *src, size_t src_len);
ssize_t freadall(const char *filename, void **dst, bool allow_fifo);
void *int2varint(varint_t src, void *dst);
size_t memcat(void *dst, size_t dst_size, const void *src, size_t src_size);
size_t packetexpand(const void *source, size_t source_length, void *target);
size_t packetshrink(const void *source, size_t source_length, void *target);
void resolve_path(const char *path, const char *cwd, char *out, size_t out_size);
int strcmp_notail(const char *str1, const char *str2, char exemptchr, bool case_insensitive);
char *strtok_head(char *dst, size_t dst_size, char *src, char delim);
size_t strtok_tail(char *dst, size_t dst_size, const char *src, size_t src_size, char delim);
void *varint2int(void *src, varint_t *dst);

#endif
