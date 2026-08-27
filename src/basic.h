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
typedef enum {
	VARINT_COMPLETE,
	VARINT_INCOMPLETE,
	VARINT_INVALID
} varint_status;

/* section: functions (exported) */
size_t base64_encode(void *dst, size_t dst_cap, const void *src, size_t src_len);
/* Returns NULL when dst or src is NULL or dst_size is zero; otherwise returns dst containing an always NUL-terminated visible-ASCII rendering of the first src_size bytes of src. */
const char *escape_default(char *dst, size_t dst_size, const char *src, size_t src_size);
ssize_t freadall(const char *filename, void **dst, bool allow_fifo);
void *int2varint(varint_t src, void *dst);
size_t memcat(void *dst, size_t dst_size, const void *src, size_t src_size);
size_t packetexpand(const void *source, size_t source_length, void *target);
/*
 * Copies every non-zero source byte into target, writing at most target_capacity bytes.  Returns the copied
 * byte count; zero is returned when the arguments are invalid or nothing fits, and an all-zero source also
 * produces zero.
 */
size_t packetshrink(const void *source, size_t source_length, void *target, size_t target_capacity);
void resolve_path(const char *path, const char *cwd, char *out, size_t out_size);
char *strtok_head(char *dst, size_t dst_size, char *src, char delim);
size_t strtok_tail(char *dst, size_t dst_size, const char *src, size_t src_size, char delim);
/* Returns the first unconsumed byte on success and NULL otherwise. dst is written only on success; status may be NULL. */
void *varint2int(void *src, void *end, varint_t *dst, varint_status *status);

#endif
