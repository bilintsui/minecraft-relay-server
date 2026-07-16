/*
 * basic.c: Basic functions used across the project
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "basic.h"

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
		dst_ptr[d] = map[(b0 & 0b11111100) >> 2];
		dst_ptr[d + 1] = map[((b0 & 0b00000011) << 4) | ((b1 & 0b11110000) >> 4)];
		dst_ptr[d + 2] = (i < full_blocks || remainder > 1) ? map[((b1 & 0b00001111) << 2) | ((b2 & 0b11000000) >> 6)] : '=';
		dst_ptr[d + 3] = (i < full_blocks) ? map[b2 & 0b00111111] : '=';
	}

	return total_blocks * 4;
}

size_t freadall(const char *filename, char **dst) {
	if ((filename == NULL) || (dst == NULL)) {
		errno = FREADALL_EINVAL;
		return 0;
	}
	FILE *srcfd = fopen(filename, "rb");
	if (srcfd == NULL) {
		errno = FREADALL_ERFAIL;
		return 0;
	}
	fseek(srcfd, 0, SEEK_END);
	size_t filesize = ftell(srcfd);
	fseek(srcfd, 0, SEEK_SET);
	if (filesize > FREADALL_SLIMIT) {
		fclose(srcfd);
		errno = FREADALL_ELARGE;
		return 0;
	}
	char *result = (char *)malloc(filesize + 1);
	if (result == NULL) {
		fclose(srcfd);
		errno = FREADALL_ENOMEM;
		return 0;
	}
	fread(result, filesize, 1, srcfd);
	result[filesize] = '\0';
	fclose(srcfd);
	*dst = result;
	return filesize;
}

void *int2varint(varint_t src, void *dst) {
	if (dst == NULL) {
		return NULL;
	}
	unsigned char *base = dst;
	int i = 0;
	do {
		base[i] = (src & 0x7F) | 0x80;
		src = src >> 7;
		i++;
	} while (src > 0);
	base[i - 1] = base[i - 1] & 0x7F;
	return dst + i;
}

size_t memcat(void *dst, size_t dst_size, void *src, size_t src_size) {
	memcpy(dst + dst_size, src, src_size);
	return dst_size + src_size;
}

int packetexpand(unsigned char *source, int source_length, unsigned char *target) {
	int size, recidx;
	unsigned char *ptr_target = target;
	for (recidx = 0; recidx < source_length; recidx++) {
		*ptr_target = 0;
		ptr_target++;
		*ptr_target = source[recidx];
		ptr_target++;
	}
	size = ptr_target - target;
	return size;
}

int packetshrink(unsigned char *source, int source_length, unsigned char *target) {
	int size, recidx;
	unsigned char *ptr_target = target;
	for (recidx = 0; recidx < source_length; recidx++) {
		if (source[recidx] != 0) {
			*ptr_target = source[recidx];
			ptr_target++;
		}
	}
	size = ptr_target - target;
	return size;
}

size_t strlen_notail(const char *src, char exemptchr) {
	if (src == NULL) {
		return 0;
	}
	size_t result = strlen(src);
	while (result > 0) {
		if (src[result - 1] != exemptchr) {
			break;
		}
		result--;
	}
	return result;
}

int strcmp_notail(const char *str1, const char *str2, char exemptchr, short case_insensitive) {
	size_t str1_length = strlen(str1);
	size_t str2_length = strlen_notail(str2, exemptchr);
	if (str1_length < str2_length) {
		return -1;
	} else if (str1_length > str2_length) {
		return 1;
	} else {
		if (case_insensitive) {
			return strncasecmp(str1, str2, str2_length);
		} else {
			return strncmp(str1, str2, str2_length);
		}
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

size_t strtok_tail(char *dst, size_t dst_size, char *src, char delim, size_t length) {
	if (src == NULL) {
		return 0;
	}
	if (length == 0) {
		if (dst != NULL) {
			*dst = '\0';
		}
		return 0;
	}
	char *buffer = (char *)malloc(length + 1);
	if (buffer == NULL) {
		return length;
	}
	memcpy(buffer, src, length);
	buffer[length] = '\0';
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

void *varint2int(void *src, varint_t *dst) {
	if (src == NULL) {
		return NULL;
	}
	unsigned char *base = src;
	varint_t result = 0;
	varint_t result_single = 0;
	for (size_t i = 0; i <= VARINT_T_MAXIDX; i++) {
		result_single = base[i] & 0x7F;
		if (i == VARINT_T_MAXIDX) {
			if ((base[i] & 0x80) || result_single > VARINT_T_LAST_MASK) {
				return NULL;
			}
		}
		result = result | (result_single << (i * 7));
		if (!(base[i] & 0x80)) {
			if (dst != NULL) {
				*dst = result;
			}
			return src + i + 1;
		}
	}
	return NULL;
}
