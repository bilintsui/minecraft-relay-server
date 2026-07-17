/*
 * basic.h: Header file of basic.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_BASIC_H_INCLUDED_

#define _MRS_BASIC_H_INCLUDED_

#include <stdbool.h>
#include <stddef.h>

#include "define/global.h"

#define FREADALL_SLIMIT	5242880
#define FREADALL_EINVAL	1
#define FREADALL_ERFAIL	2
#define FREADALL_ELARGE	3
#define FREADALL_ENOMEM	4

size_t base64_encode(void *dst, size_t dst_cap, const void *src, size_t src_len);
size_t freadall(const char *filename, void **dst);
void *int2varint(varint_t src, void *dst);
size_t memcat(void *dst, size_t dst_size, const void *src, size_t src_size);
size_t packetexpand(const void *source, size_t source_length, void *target);
size_t packetshrink(const void *source, size_t source_length, void *target);
size_t strlen_notail(const char *src, char exemptchr);
int strcmp_notail(const char *str1, const char *str2, char exemptchr, bool case_insensitive);
char *strtok_head(char *dst, size_t dst_size, char *src, char delim);
size_t strtok_tail(char *dst, size_t dst_size, const char *src, size_t src_size, char delim);
void *varint2int(void *src, varint_t *dst);

#endif
