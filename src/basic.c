/*
 * basic.c: Basic functions used across the project
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* section: headers (project) */
#include "define/global.h"

/* section: headers (self) */
#include "basic.h"

/* section: functions (exported) */
size_t base64_encode(void *dst, size_t dst_cap, const void *src, size_t src_len) {
	if ((dst == NULL) || (src == NULL) || (dst_cap == 0) || (src_len == 0)) {
		return 0;
	}

	const char *map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	uint8_t *dst_ptr = dst;
	const uint8_t *src_ptr = src;

	size_t full_blocks = src_len / 3;
	size_t remainder = src_len % 3;
	size_t total_blocks = full_blocks + (remainder > 0);

	if (dst_cap < total_blocks * 4) {
		total_blocks = full_blocks = dst_cap / 4;
		remainder = 0;
	}

	for (size_t i = 0; i < total_blocks; i++) {
		size_t s = i * 3;
		uint8_t b0 = src_ptr[s];
		uint8_t b1 = (i < full_blocks || remainder > 1) ? src_ptr[s + 1] : 0;
		uint8_t b2 = (i < full_blocks) ? src_ptr[s + 2] : 0;

		size_t d = i * 4;
		dst_ptr[d] = map[(b0 & 0xFC) >> 2];
		dst_ptr[d + 1] = map[((b0 & 0x03) << 4) | ((b1 & 0xF0) >> 4)];
		dst_ptr[d + 2] = (i < full_blocks || remainder > 1) ? map[((b1 & 0x0F) << 2) | ((b2 & 0xC0) >> 6)] : '=';
		dst_ptr[d + 3] = (i < full_blocks) ? map[b2 & 0x3F] : '=';
	}

	return total_blocks * 4;
}

ssize_t freadall(const char *filename, void **dst, bool allow_fifo) {
	freadall_error error_code = FREADALL_ERROR_NONE;
	FILE *srcfd = NULL;
	void *result = NULL;
	if ((filename == NULL) || (dst == NULL)) {
		error_code = FREADALL_EINVAL;
		goto cleanup;
	}
	struct stat st;
	if ((stat(filename, &st) != 0) || !(S_ISREG(st.st_mode) || (allow_fifo && S_ISFIFO(st.st_mode)))) {
		error_code = FREADALL_ERFAIL;
		goto cleanup;
	}
	srcfd = fopen(filename, "rb");
	if (srcfd == NULL) {
		error_code = FREADALL_ERFAIL;
		goto cleanup;
	}
	if ((fstat(fileno(srcfd), &st) != 0) || !(S_ISREG(st.st_mode) || (allow_fifo && S_ISFIFO(st.st_mode)))) {
		error_code = FREADALL_ERFAIL;
		goto cleanup;
	}
	result = malloc(FREADALL_SLIMIT);
	if (result == NULL) {
		error_code = FREADALL_ENOMEM;
		goto cleanup;
	}
	size_t bytes_read = 0, bytes_total = 0;
	while (bytes_total < FREADALL_SLIMIT) {
		bytes_read = fread((uint8_t *)result + bytes_total, 1, FREADALL_SLIMIT - bytes_total, srcfd);
		if (bytes_read == 0) {
			break;
		}
		bytes_total += bytes_read;
	}
	if (bytes_total == FREADALL_SLIMIT) {
		uint8_t extrabyte;
		if (fread(&extrabyte, 1, sizeof(extrabyte), srcfd)) {
			error_code = FREADALL_ELARGE;
			goto cleanup;
		}
	}
	if (ferror(srcfd)) {
		error_code = FREADALL_ERFAIL;
		goto cleanup;
	}
	fclose(srcfd);
	srcfd = NULL;
	if (bytes_total > 0) {
		void *result_final = realloc(result, bytes_total);
		if (result_final != NULL) {
			result = result_final;
		}
	} else {
		free(result);
		result = NULL;
	}
	*dst = result;
	errno = 0;
	return bytes_total;
cleanup:
	if (srcfd != NULL) {
		fclose(srcfd);
		srcfd = NULL;
	}
	if (result != NULL) {
		free(result);
		result = NULL;
	}
	errno = error_code;
	return -1;
}

void *int2varint(varint_t src, void *dst) {
	if (dst == NULL) {
		return NULL;
	}
	uint8_t *base = dst;
	size_t i = 0;
	do {
		base[i] = (src & 0x7F) | 0x80;
		src = src >> 7;
		i++;
	} while (src > 0);
	base[i - 1] = base[i - 1] & 0x7F;
	return base + i;
}

size_t memcat(void *dst, size_t dst_size, const void *src, size_t src_size) {
	memcpy((uint8_t *)dst + dst_size, src, src_size);
	return dst_size + src_size;
}

size_t packetexpand(const void *source, size_t source_length, void *target) {
	size_t size, recidx;
	const uint8_t *ptr_source = source;
	uint8_t *ptr_target = target;
	for (recidx = 0; recidx < source_length; recidx++) {
		*ptr_target = 0;
		ptr_target++;
		*ptr_target = ptr_source[recidx];
		ptr_target++;
	}
	size = ptr_target - (uint8_t *)target;
	return size;
}

size_t packetshrink(const void *source, size_t source_length, void *target) {
	size_t size, recidx;
	const uint8_t *ptr_source = source;
	uint8_t *ptr_target = target;
	for (recidx = 0; recidx < source_length; recidx++) {
		if (ptr_source[recidx] != 0) {
			*ptr_target = ptr_source[recidx];
			ptr_target++;
		}
	}
	size = ptr_target - (uint8_t *)target;
	return size;
}

void resolve_path(const char *path, const char *cwd, char *out, size_t out_size) {
	if ((path == NULL) || (cwd == NULL) || (out == NULL) || (out_size == 0)) {
		return;
	}
	if (path[0] != '/') {
		snprintf(out, out_size, "%s/%s", cwd, path);
	} else {
		snprintf(out, out_size, "%s", path);
	}
}

char *strtok_head(char *dst, size_t dst_size, char *src, char delim) {
	if ((src == NULL) || (dst_size == 0)) {
		return NULL;
	}
	if (*src == '\0') {
		if (dst != NULL) {
			*dst = '\0';
		}
		return NULL;
	}
	char *ptr_delim = strchr(src, delim);
	if (ptr_delim == NULL) {
		if (dst != NULL) {
			snprintf(dst, dst_size, "%s", src);
		}
		return NULL;
	}
	size_t length = ptr_delim - src;
	if (length >= dst_size) {
		length = dst_size - 1;
	}
	if (dst != NULL) {
		memcpy(dst, src, length);
		dst[length] = '\0';
	}
	return ptr_delim + 1;
}

size_t strtok_tail(char *dst, size_t dst_size, const char *src, size_t src_size, char delim) {
	if (src == NULL) {
		return 0;
	}
	if (src_size == 0) {
		if (dst != NULL) {
			*dst = '\0';
		}
		return 0;
	}
	char *buffer = (char *)malloc(src_size + 1);
	if (buffer == NULL) {
		return src_size;
	}
	memcpy(buffer, src, src_size);
	buffer[src_size] = '\0';
	char *ptr_delim = strrchr(buffer, delim);
	if (ptr_delim == NULL) {
		if (dst != NULL) {
			snprintf(dst, dst_size, "%s", buffer);
		}
		free(buffer);
		return 0;
	}
	ptrdiff_t offset = ptr_delim - buffer;
	if (dst != NULL) {
		snprintf(dst, dst_size, "%s", ptr_delim + 1);
	}
	free(buffer);
	return offset;
}

void *varint2int(void *src, void *end, varint_t *dst, varint_status *status) {
	if (status != NULL) {
		*status = VARINT_INVALID;
	}
	if (src == NULL || end == NULL || (uintptr_t)src > (uintptr_t)end) {
		return NULL;
	}
	uint8_t *base = src;
	uint8_t *limit = end;
	varint_t result = 0;
	varint_t result_single = 0;
	for (size_t i = 0; i <= VARINT_T_MAXIDX; i++) {
		if (base >= limit) {
			if (status != NULL) {
				*status = VARINT_INCOMPLETE;
			}
			return NULL;
		}
		uint8_t byte = *base++;
		result_single = byte & 0x7F;
		if (i == VARINT_T_MAXIDX) {
			if ((byte & 0x80) || result_single > VARINT_T_LAST_MASK) {
				return NULL;
			}
		}
		result = result | (result_single << (i * 7));
		if (!(byte & 0x80)) {
			if (dst != NULL) {
				*dst = result;
			}
			if (status != NULL) {
				*status = VARINT_COMPLETE;
			}
			return base;
		}
	}
	return NULL;
}
